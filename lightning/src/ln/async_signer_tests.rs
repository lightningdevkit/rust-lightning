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

use bitcoin::secp256k1::PublicKey;
use crate::events::{Event, MessageSendEvent, MessageSendEventsProvider};
use crate::ln::ChannelId;
use crate::ln::functional_test_utils::*;
use crate::ln::msgs;
use crate::ln::msgs::ChannelMessageHandler;
use crate::ln::channelmanager::{PaymentId, RAACommitmentOrder, RecipientOnionFields};
use crate::util::ser::Writeable;
use crate::util::test_channel_signer::ops;
use crate::util::test_utils;

/// Helper to run operations with a simulated asynchronous signer.
///
/// Disables the signer for the specified channel and then runs `do_fn`, then re-enables the signer
/// and calls `signer_unblocked`.
#[cfg(test)]
pub fn with_async_signer<'a, DoFn, T>(node: &Node, peer_id: &PublicKey, channel_id: &ChannelId, masks: &Vec<u32>, do_fn: &'a DoFn) -> T
	where DoFn: Fn() -> T
{
	let mask = masks.iter().fold(0, |acc, m| (acc | m));
	eprintln!("disabling {}", ops::string_from(mask));
	node.set_channel_signer_ops_available(peer_id, channel_id, mask, false);
	let res = do_fn();

	// Recompute the channel ID just in case the original ID was temporary.
	let new_channel_id = {
		let channels = node.node.list_channels();
		assert_eq!(channels.len(), 1, "expected one channel, not {}", channels.len());
		channels[0].channel_id
	};

	for mask in masks {
		eprintln!("enabling {} and calling signer_unblocked", ops::string_from(*mask));
		node.set_channel_signer_ops_available(peer_id, &new_channel_id, *mask, true);
		node.node.signer_unblocked(Some((*peer_id, new_channel_id)));
	}
	res
}

#[cfg(test)]
fn do_test_funding_created(masks: &Vec<u32>) {
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
	with_async_signer(&nodes[0], &nodes[1].node.get_our_node_id(), &temporary_channel_id, masks, &|| {
		nodes[0].node.funding_transaction_generated(&temporary_channel_id, &nodes[1].node.get_our_node_id(), tx.clone()).unwrap();
		check_added_monitors(&nodes[0], 0);
		assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	});

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
fn test_funding_created_grs() {
	do_test_funding_created(&vec![ops::GET_PER_COMMITMENT_POINT, ops::RELEASE_COMMITMENT_SECRET, ops::SIGN_COUNTERPARTY_COMMITMENT]);
}

#[test]
fn test_funding_created_gsr() {
	do_test_funding_created(&vec![ops::GET_PER_COMMITMENT_POINT, ops::SIGN_COUNTERPARTY_COMMITMENT, ops::RELEASE_COMMITMENT_SECRET]);
}

#[test]
fn test_funding_created_rsg() {
	do_test_funding_created(&vec![ops::RELEASE_COMMITMENT_SECRET, ops::SIGN_COUNTERPARTY_COMMITMENT, ops::GET_PER_COMMITMENT_POINT]);
}

#[test]
fn test_funding_created_rgs() {
	do_test_funding_created(&vec![ops::RELEASE_COMMITMENT_SECRET, ops::GET_PER_COMMITMENT_POINT, ops::SIGN_COUNTERPARTY_COMMITMENT]);
}

#[test]
fn test_funding_created_srg() {
	do_test_funding_created(&vec![ops::SIGN_COUNTERPARTY_COMMITMENT, ops::RELEASE_COMMITMENT_SECRET, ops::GET_PER_COMMITMENT_POINT]);
}

#[test]
fn test_funding_created_sgr() {
	do_test_funding_created(&vec![ops::SIGN_COUNTERPARTY_COMMITMENT, ops::GET_PER_COMMITMENT_POINT, ops::RELEASE_COMMITMENT_SECRET]);
}


#[cfg(test)]
fn do_test_funding_signed(masks: &Vec<u32>) {
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
	with_async_signer(&nodes[1], &nodes[0].node.get_our_node_id(), &temporary_channel_id, masks, &|| {
		nodes[1].node.handle_funding_created(&nodes[0].node.get_our_node_id(), &funding_created_msg);
		check_added_monitors(&nodes[1], 1);
		assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	});

	expect_channel_pending_event(&nodes[1], &nodes[0].node.get_our_node_id());

	// nodes[0] <-- funding_signed --- nodes[1]
	let funding_signed_msg = get_event_msg!(nodes[1], MessageSendEvent::SendFundingSigned, nodes[0].node.get_our_node_id());
	nodes[0].node.handle_funding_signed(&nodes[1].node.get_our_node_id(), &funding_signed_msg);
	check_added_monitors(&nodes[0], 1);
	expect_channel_pending_event(&nodes[0], &nodes[1].node.get_our_node_id());
}

#[test]
fn test_funding_signed_grs() {
	do_test_funding_signed(&vec![ops::GET_PER_COMMITMENT_POINT, ops::RELEASE_COMMITMENT_SECRET, ops::SIGN_COUNTERPARTY_COMMITMENT]);
}

#[test]
fn test_funding_signed_gsr() {
	do_test_funding_signed(&vec![ops::GET_PER_COMMITMENT_POINT, ops::SIGN_COUNTERPARTY_COMMITMENT, ops::RELEASE_COMMITMENT_SECRET]);
}

#[test]
fn test_funding_signed_rsg() {
	do_test_funding_signed(&vec![ops::RELEASE_COMMITMENT_SECRET, ops::SIGN_COUNTERPARTY_COMMITMENT, ops::GET_PER_COMMITMENT_POINT]);
}

#[test]
fn test_funding_signed_rgs() {
	do_test_funding_signed(&vec![ops::RELEASE_COMMITMENT_SECRET, ops::GET_PER_COMMITMENT_POINT, ops::SIGN_COUNTERPARTY_COMMITMENT]);
}

#[test]
fn test_funding_signed_srg() {
	do_test_funding_signed(&vec![ops::SIGN_COUNTERPARTY_COMMITMENT, ops::RELEASE_COMMITMENT_SECRET, ops::GET_PER_COMMITMENT_POINT]);
}

#[test]
fn test_funding_signed_sgr() {
	do_test_funding_signed(&vec![ops::SIGN_COUNTERPARTY_COMMITMENT, ops::GET_PER_COMMITMENT_POINT, ops::RELEASE_COMMITMENT_SECRET]);
}


#[cfg(test)]
fn do_test_commitment_signed(masks: &Vec<u32>) {
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

	// Mark dst's signer as unavailable and handle src's commitment_signed. If dst's signer is
	// offline, it oughtn't yet respond with any updates.
	with_async_signer(dst, &src.node.get_our_node_id(), &chan_id, masks, &|| {
		dst.node.handle_commitment_signed(&src.node.get_our_node_id(), &payment_event.commitment_msg);
		check_added_monitors(dst, 1);
		assert!(dst.node.get_and_clear_pending_msg_events().is_empty());
	});

	get_revoke_commit_msgs(&dst, &src.node.get_our_node_id());
}

#[test]
fn test_commitment_signed_grs() {
	do_test_commitment_signed(&vec![ops::GET_PER_COMMITMENT_POINT, ops::RELEASE_COMMITMENT_SECRET, ops::SIGN_COUNTERPARTY_COMMITMENT]);
}

#[test]
fn test_commitment_signed_gsr() {
	do_test_commitment_signed(&vec![ops::GET_PER_COMMITMENT_POINT, ops::SIGN_COUNTERPARTY_COMMITMENT, ops::RELEASE_COMMITMENT_SECRET]);
}

#[test]
fn test_commitment_signed_rsg() {
	do_test_commitment_signed(&vec![ops::RELEASE_COMMITMENT_SECRET, ops::SIGN_COUNTERPARTY_COMMITMENT, ops::GET_PER_COMMITMENT_POINT]);
}

#[test]
fn test_commitment_signed_rgs() {
	do_test_commitment_signed(&vec![ops::RELEASE_COMMITMENT_SECRET, ops::GET_PER_COMMITMENT_POINT, ops::SIGN_COUNTERPARTY_COMMITMENT]);
}

#[test]
fn test_commitment_signed_srg() {
	do_test_commitment_signed(&vec![ops::SIGN_COUNTERPARTY_COMMITMENT, ops::RELEASE_COMMITMENT_SECRET, ops::GET_PER_COMMITMENT_POINT]);
}

#[test]
fn test_commitment_signed_sgr() {
	do_test_commitment_signed(&vec![ops::SIGN_COUNTERPARTY_COMMITMENT, ops::GET_PER_COMMITMENT_POINT, ops::RELEASE_COMMITMENT_SECRET]);
}


#[cfg(test)]
fn do_test_funding_signed_0conf(masks: &Vec<u32>) {
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
		match &events[0] {
			Event::OpenChannelRequest { temporary_channel_id, .. } => {
				nodes[1].node.accept_inbound_channel_from_trusted_peer_0conf(
					temporary_channel_id, &nodes[0].node.get_our_node_id(), 0)
					.expect("Unable to accept inbound zero-conf channel");
			},
			ev => panic!("Expected OpenChannelRequest, not {:?}", ev)
		}
		assert_eq!(events.len(), 1, "Expected one event, got {}", events.len());
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
	with_async_signer(&nodes[1], &nodes[0].node.get_our_node_id(), &temporary_channel_id, masks, &|| {
		nodes[1].node.handle_funding_created(&nodes[0].node.get_our_node_id(), &funding_created_msg);
		check_added_monitors(&nodes[1], 1);
		assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	});

	// At this point, we basically expect the channel to open like a normal zero-conf channel.
	let (funding_signed, channel_ready_1) = {
		let events = nodes[1].node.get_and_clear_pending_msg_events();
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
fn test_funding_signed_0conf_grs() {
	do_test_funding_signed_0conf(&vec![ops::GET_PER_COMMITMENT_POINT, ops::RELEASE_COMMITMENT_SECRET, ops::SIGN_COUNTERPARTY_COMMITMENT]);
}

#[test]
fn test_funding_signed_0conf_gsr() {
	do_test_funding_signed_0conf(&vec![ops::GET_PER_COMMITMENT_POINT, ops::SIGN_COUNTERPARTY_COMMITMENT, ops::RELEASE_COMMITMENT_SECRET]);
}

#[test]
fn test_funding_signed_0conf_rsg() {
	do_test_funding_signed_0conf(&vec![ops::RELEASE_COMMITMENT_SECRET, ops::SIGN_COUNTERPARTY_COMMITMENT, ops::GET_PER_COMMITMENT_POINT]);
}

#[test]
fn test_funding_signed_0conf_rgs() {
	do_test_funding_signed_0conf(&vec![ops::RELEASE_COMMITMENT_SECRET, ops::GET_PER_COMMITMENT_POINT, ops::SIGN_COUNTERPARTY_COMMITMENT]);
}

#[test]
fn test_funding_signed_0conf_srg() {
	do_test_funding_signed_0conf(&vec![ops::SIGN_COUNTERPARTY_COMMITMENT, ops::RELEASE_COMMITMENT_SECRET, ops::GET_PER_COMMITMENT_POINT]);
}

#[test]
fn test_funding_signed_0conf_sgr() {
	do_test_funding_signed_0conf(&vec![ops::SIGN_COUNTERPARTY_COMMITMENT, ops::GET_PER_COMMITMENT_POINT, ops::RELEASE_COMMITMENT_SECRET]);
}


#[cfg(test)]
fn do_test_payment(masks: &Vec<u32>) {
	// This runs through a one-hop payment from start to finish, simulating an asynchronous signer at
	// each step.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let (_up1, _up2, channel_id, _tx) = create_announced_chan_between_nodes(&nodes, 0, 1);

	let alice = &nodes[0];
	let bob = &nodes[1];

	let (route, payment_hash, payment_preimage, payment_secret) = get_route_and_payment_hash!(alice, bob, 8_000_000);

	with_async_signer(&alice, &bob.node.get_our_node_id(), &channel_id, masks, &|| {
		alice.node.send_payment_with_route(&route, payment_hash,
			RecipientOnionFields::secret_only(payment_secret), PaymentId(payment_hash.0)).unwrap();
		check_added_monitors!(alice, 1);
		let events = alice.node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 0, "expected 0 events, got {}", events.len());
	});

	let payment_event = {
		let mut events = alice.node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		SendEvent::from_event(events.remove(0))
	};
	assert_eq!(payment_event.node_id, bob.node.get_our_node_id());
	assert_eq!(payment_event.msgs.len(), 1);

	// alice --[update_add_htlc]--> bob
	// alice --[commitment_signed]--> bob
	with_async_signer(&bob, &alice.node.get_our_node_id(), &channel_id, masks, &|| {
		bob.node.handle_update_add_htlc(&alice.node.get_our_node_id(), &payment_event.msgs[0]);
		bob.node.handle_commitment_signed(&alice.node.get_our_node_id(), &payment_event.commitment_msg);
		check_added_monitors(bob, 1);
	});

	// alice <--[revoke_and_ack]-- bob
	// alice <--[commitment_signed]-- bob
	{
		let (raa, cu) = {
			let events = bob.node.get_and_clear_pending_msg_events();
			assert_eq!(events.len(), 2, "expected 2 messages, got {}", events.len());
			match (&events[0], &events[1]) {
				(MessageSendEvent::SendRevokeAndACK { msg: raa, .. }, MessageSendEvent::UpdateHTLCs { updates: cu, .. }) => {
					assert_eq!(cu.update_add_htlcs.len(), 0, "expected 0 update_add_htlcs, got {}", cu.update_add_htlcs.len());
					(raa.clone(), cu.clone())
				}
				(a, b) => panic!("expected SendRevokeAndAck and UpdateHTLCs, not {:?} and {:?}", a, b)
			}
		};

		// TODO: run this with_async_signer once validate_counterparty_revocation supports it.
		alice.node.handle_revoke_and_ack(&bob.node.get_our_node_id(), &raa);
		check_added_monitors(alice, 1);

		with_async_signer(&alice, &bob.node.get_our_node_id(), &channel_id, masks, &|| {
			alice.node.handle_commitment_signed(&bob.node.get_our_node_id(), &cu.commitment_signed);
			check_added_monitors(alice, 1);
		});
	}

	// alice --[revoke_and_ack]--> bob
	// TODO: run this with_async_signer once validate_counterparty_revocation supports it.
	let raa = get_event_msg!(alice, MessageSendEvent::SendRevokeAndACK, bob.node.get_our_node_id());
	bob.node.handle_revoke_and_ack(&alice.node.get_our_node_id(), &raa);
	check_added_monitors(bob, 1);

	expect_pending_htlcs_forwardable!(bob);

	// Bob generates a PaymentClaimable to user code.
	{
		let events = bob.node.get_and_clear_pending_events();
		assert_eq!(events.len(), 1, "expected 1 event, got {}", events.len());
		match &events[0] {
			Event::PaymentClaimable { .. } => {
				bob.node.claim_funds(payment_preimage);
			}
			ev => panic!("Expected PaymentClaimable, got {:?}", ev)
		}
		check_added_monitors(bob, 1);
	}

	// Bob generates a PaymentClaimed event to user code.
	{
		let events = bob.node.get_and_clear_pending_events();
		assert_eq!(events.len(), 1, "expected 1 event, got {}", events.len());
		match &events[0] {
			Event::PaymentClaimed { .. } => (),
			ev => panic!("Expected PaymentClaimed, got {:?}", ev),
		}
	}

	// alice <--[update_fulfill_htlcs]-- bob
	// alice <--[commitment_signed]-- bob
	{
		let cu = {
			let events = bob.node.get_and_clear_pending_msg_events();
			assert_eq!(events.len(), 1, "expected 1 events, got {}", events.len());
			match &events[0] {
				MessageSendEvent::UpdateHTLCs { updates, .. } => {
					assert_eq!(updates.update_fulfill_htlcs.len(), 1, "expected 1 update_fulfill_htlcs, got {}", updates.update_fulfill_htlcs.len());
					updates.clone()
				}
				ev => panic!("Expected UpdateHTLCs, got {:?}", ev)
			}
		};

		with_async_signer(&alice, &bob.node.get_our_node_id(), &channel_id, masks, &|| {
			alice.node.handle_update_fulfill_htlc(&bob.node.get_our_node_id(), &cu.update_fulfill_htlcs[0]);
			alice.node.handle_commitment_signed(&bob.node.get_our_node_id(), &cu.commitment_signed);
			check_added_monitors(alice, 1);
		});
	}

	// alice --[revoke_and_ack]--> bob
	// alice --[commitment_signed]--> bob
	{
		let (raa, cu) = {
			let events = alice.node.get_and_clear_pending_msg_events();
			assert_eq!(events.len(), 2, "expected 2 messages, got {}", events.len());
			match (&events[0], &events[1]) {
				(MessageSendEvent::SendRevokeAndACK { msg: raa, .. }, MessageSendEvent::UpdateHTLCs { updates: cu, .. }) => {
					assert_eq!(cu.update_fulfill_htlcs.len(), 0, "expected 0 update_fulfill_htlcs, got {}", cu.update_fulfill_htlcs.len());
					(raa.clone(), cu.clone())
				}
				(a, b) => panic!("expected SendRevokeAndAck and UpdateHTLCs, not {:?} and {:?}", a, b)
			}
		};

		// TODO: run with async once validate_counterparty_revocation supports it.
		bob.node.handle_revoke_and_ack(&alice.node.get_our_node_id(), &raa);
		check_added_monitors(bob, 1);

		with_async_signer(&bob, &alice.node.get_our_node_id(), &channel_id, masks, &|| {
			bob.node.handle_commitment_signed(&alice.node.get_our_node_id(), &cu.commitment_signed);
			check_added_monitors(bob, 1);
		});
	}

	// alice <--[revoke_and_ack]-- bob
	// TODO: run with async once validate_counterparty_revocation supports it.
	let raa = get_event_msg!(bob, MessageSendEvent::SendRevokeAndACK, alice.node.get_our_node_id());
	alice.node.handle_revoke_and_ack(&bob.node.get_our_node_id(), &raa);
	check_added_monitors(alice, 0);

	// Alice generates PaymentSent and PaymentPathSuccessful events to user code.
	{
		let events = alice.node.get_and_clear_pending_events();
		assert_eq!(events.len(), 2, "expected 2 event, got {}", events.len());
		match (&events[0], &events[1]) {
			(Event::PaymentSent { .. }, Event::PaymentPathSuccessful { .. }) => (),
			(a, b) => panic!("Expected PaymentSent and PaymentPathSuccessful, got {:?} and {:?}", a, b)
		}

		check_added_monitors(alice, 1);  // why? would have expected this after handling RAA...
	}
}

#[test]
fn test_payment_grs() {
	do_test_payment(&vec![ops::GET_PER_COMMITMENT_POINT, ops::RELEASE_COMMITMENT_SECRET, ops::SIGN_COUNTERPARTY_COMMITMENT]);
}

#[test]
fn test_payment_gsr() {
	do_test_payment(&vec![ops::GET_PER_COMMITMENT_POINT, ops::SIGN_COUNTERPARTY_COMMITMENT, ops::RELEASE_COMMITMENT_SECRET]);
}

#[test]
fn test_payment_rsg() {
	do_test_payment(&vec![ops::RELEASE_COMMITMENT_SECRET, ops::SIGN_COUNTERPARTY_COMMITMENT, ops::GET_PER_COMMITMENT_POINT]);
}

#[test]
fn test_payment_rgs() {
	do_test_payment(&vec![ops::RELEASE_COMMITMENT_SECRET, ops::GET_PER_COMMITMENT_POINT, ops::SIGN_COUNTERPARTY_COMMITMENT]);
}

#[test]
fn test_payment_srg() {
	do_test_payment(&vec![ops::SIGN_COUNTERPARTY_COMMITMENT, ops::RELEASE_COMMITMENT_SECRET, ops::GET_PER_COMMITMENT_POINT]);
}

#[test]
fn test_payment_sgr() {
	do_test_payment(&vec![ops::SIGN_COUNTERPARTY_COMMITMENT, ops::GET_PER_COMMITMENT_POINT, ops::RELEASE_COMMITMENT_SECRET]);
}

#[cfg(test)]
fn do_test_peer_reconnect(masks: &Vec<u32>) {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let (_, _, chan_id, _) = create_announced_chan_between_nodes(&nodes, 0, 1);

	// Send a payment.
	let alice = &nodes[0];
	let bob = &nodes[1];
	let (route, payment_hash, payment_preimage, payment_secret) = get_route_and_payment_hash!(alice, bob, 8_000_000);

	with_async_signer(&alice, &bob.node.get_our_node_id(), &chan_id, masks, &|| {
		alice.node.send_payment_with_route(&route, payment_hash,
			RecipientOnionFields::secret_only(payment_secret), PaymentId(payment_hash.0)).unwrap();
		check_added_monitors!(alice, 1);
		let events = alice.node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 0, "expected 0 events, got {}", events.len());

		alice.node.peer_disconnected(&bob.node.get_our_node_id());
		bob.node.peer_disconnected(&alice.node.get_our_node_id());
	});

	with_async_signer(&alice, &bob.node.get_our_node_id(), &chan_id, masks, &|| {
		let mut reconnect_args = ReconnectArgs::new(alice, bob);
		reconnect_args.send_channel_ready = (true, true);  // ...since this will be state 1.
		reconnect_nodes(reconnect_args);
	});

	let payment_event = {
		let mut events = alice.node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		SendEvent::from_event(events.remove(0))
	};
	assert_eq!(payment_event.node_id, bob.node.get_our_node_id());
	assert_eq!(payment_event.msgs.len(), 1);

	// alice --[update_add_htlc]--> bob
	// alice --[commitment_signed]--> bob
	with_async_signer(&bob, &alice.node.get_our_node_id(), &chan_id, masks, &|| {
		bob.node.handle_update_add_htlc(&alice.node.get_our_node_id(), &payment_event.msgs[0]);
		bob.node.handle_commitment_signed(&alice.node.get_our_node_id(), &payment_event.commitment_msg);
		check_added_monitors(bob, 1);

		alice.node.peer_disconnected(&bob.node.get_our_node_id());
		bob.node.peer_disconnected(&alice.node.get_our_node_id());
	});

	let (alice_reestablish, bob_reestablish) = with_async_signer(&alice, &bob.node.get_our_node_id(), &chan_id, masks, &|| {
		alice.node.peer_connected(&bob.node.get_our_node_id(), &msgs::Init {
			features: bob.node.init_features(), networks: None, remote_network_address: None
		}, true).expect("peer_connected failed for alice");
		let alice_msgs = get_chan_reestablish_msgs!(alice, bob);
		assert_eq!(alice_msgs.len(), 1, "expected 1 message, got {}", alice_msgs.len());
		bob.node.peer_connected(&alice.node.get_our_node_id(), &msgs::Init {
			features: alice.node.init_features(), networks: None, remote_network_address: None
		}, false).expect("peer_connected failed for bob");
		let bob_msgs = get_chan_reestablish_msgs!(bob, alice);
		assert_eq!(bob_msgs.len(), 1, "expected 1 message, got {}", bob_msgs.len());
		(alice_msgs[0].clone(), bob_msgs[0].clone())
	});

	with_async_signer(&bob, &alice.node.get_our_node_id(), &chan_id, masks, &|| {
		bob.node.handle_channel_reestablish(&alice.node.get_our_node_id(), &alice_reestablish);
	});

	let (raa, cu) = match handle_chan_reestablish_msgs!(bob, alice) {
		(None, Some(raa), Some(cu), RAACommitmentOrder::RevokeAndACKFirst) => (raa, cu),
		(channel_ready, raa, cu, order) => {
			panic!("bob: channel_ready={:?} raa={:?} cu={:?} order={:?}", channel_ready, raa, cu, order);
		}
	};

	with_async_signer(&alice, &bob.node.get_our_node_id(), &chan_id, masks, &|| {
		alice.node.handle_channel_reestablish(&bob.node.get_our_node_id(), &bob_reestablish);
	});

	match handle_chan_reestablish_msgs!(alice, bob) {
		(None, None, None, _) => (),
		(channel_ready, raa, cu, order) => {
			panic!("alice: channel_ready={:?} raa={:?} cu={:?} order={:?}", channel_ready, raa, cu, order);
		}
	};

	with_async_signer(&alice, &bob.node.get_our_node_id(), &chan_id, masks, &|| {
		alice.node.handle_revoke_and_ack(&bob.node.get_our_node_id(), &raa);
		check_added_monitors(alice, 1);
	});

	// Disconnect?

	with_async_signer(&alice, &bob.node.get_our_node_id(), &chan_id, masks, &|| {
		alice.node.handle_commitment_signed(&bob.node.get_our_node_id(), &cu.commitment_signed);
		check_added_monitors(alice, 1);
	});

	// Disconnect?

	let raa = get_event_msg!(alice, MessageSendEvent::SendRevokeAndACK, bob.node.get_our_node_id());
	with_async_signer(&bob, &alice.node.get_our_node_id(), &chan_id, masks, &|| {
		bob.node.handle_revoke_and_ack(&alice.node.get_our_node_id(), &raa);
		check_added_monitors(bob, 1);
	});

	expect_pending_htlcs_forwardable!(bob);

	{
		let events = bob.node.get_and_clear_pending_events();
		assert_eq!(events.len(), 1, "expected 1 event, got {}", events.len());
		match &events[0] {
			Event::PaymentClaimable { .. } => (),
			ev => panic!("Expected PaymentClaimable, got {:?}", ev),
		}
	}

	with_async_signer(&bob, &alice.node.get_our_node_id(), &chan_id, masks, &|| {
		bob.node.claim_funds(payment_preimage);
		check_added_monitors(bob, 1);
	});

	let _cu = {
		let events = bob.node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1, "expected 1 message, got {}", events.len());
		match &events[0] {
			MessageSendEvent::UpdateHTLCs { ref updates, .. } => updates.clone(),
			ev => panic!("expected UpdateHTLCs, got {:?}", ev),
		}
	};

	{
		let events = bob.node.get_and_clear_pending_events();
		assert_eq!(events.len(), 1, "expected 1 event, got {}", events.len());
		match &events[0] {
			Event::PaymentClaimed { .. } => (),
			ev => panic!("Expected PaymentClaimed, got {:?}", ev),
		}
	}

	// Blah blah blah... send cu to alice, probably sprinkle some reconnects above.
}

#[test]
fn test_peer_reconnect_grs() {
	do_test_peer_reconnect(&vec![ops::GET_PER_COMMITMENT_POINT, ops::RELEASE_COMMITMENT_SECRET, ops::SIGN_COUNTERPARTY_COMMITMENT]);
}

#[test]
fn test_peer_reconnect_gsr() {
	do_test_peer_reconnect(&vec![ops::GET_PER_COMMITMENT_POINT, ops::SIGN_COUNTERPARTY_COMMITMENT, ops::RELEASE_COMMITMENT_SECRET]);
}

#[test]
fn test_peer_reconnect_rsg() {
	do_test_peer_reconnect(&vec![ops::RELEASE_COMMITMENT_SECRET, ops::SIGN_COUNTERPARTY_COMMITMENT, ops::GET_PER_COMMITMENT_POINT]);
}

#[test]
fn test_peer_reconnect_rgs() {
	do_test_peer_reconnect(&vec![ops::RELEASE_COMMITMENT_SECRET, ops::GET_PER_COMMITMENT_POINT, ops::SIGN_COUNTERPARTY_COMMITMENT]);
}

#[test]
fn test_peer_reconnect_srg() {
	do_test_peer_reconnect(&vec![ops::SIGN_COUNTERPARTY_COMMITMENT, ops::RELEASE_COMMITMENT_SECRET, ops::GET_PER_COMMITMENT_POINT]);
}

#[test]
fn test_peer_reconnect_sgr() {
	do_test_payment(&vec![ops::SIGN_COUNTERPARTY_COMMITMENT, ops::GET_PER_COMMITMENT_POINT, ops::RELEASE_COMMITMENT_SECRET]);
}

#[test]
fn channel_update_fee_test() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let (_, _, chan_id, _) = create_announced_chan_between_nodes(&nodes, 0, 1);

	let alice = &nodes[0];
	let bob = &nodes[1];

	// Balance
	send_payment(alice, &vec!(bob)[..], 8_000_000);

	// Send a payment from Bob to Alice: this requires Alice to acquire a new commitment point from
	// the signer. Make the signer be unavailable, and then trigger a situation that requires Alice to
	// request fee update. Alice should be able to generate the fee update without crashing: she needs
	// to be able to get the statistics about the new transaction, but doesn't actually need the
	// signed transaction itself.
	let (route, payment_hash, _payment_preimage, payment_secret) = get_route_and_payment_hash!(bob, alice, 2_000_000);
	bob.node.send_payment_with_route(
		&route, payment_hash,
		RecipientOnionFields::secret_only(payment_secret), PaymentId(payment_hash.0)).unwrap();
	check_added_monitors!(bob, 1);

	let payment_event = {
		let mut events = bob.node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		SendEvent::from_event(events.remove(0))
	};

	alice.set_channel_signer_ops_available(
		&bob.node.get_our_node_id(), &chan_id, ops::GET_PER_COMMITMENT_POINT, false);

	alice.node.handle_update_add_htlc(&bob.node.get_our_node_id(), &payment_event.msgs[0]);
	alice.node.handle_commitment_signed(&bob.node.get_our_node_id(), &payment_event.commitment_msg);
	check_added_monitors!(alice, 1);

	// Force alice to generate an update_fee
	{
		let mut feerate_lock = chanmon_cfgs[0].fee_estimator.sat_per_kw.lock().unwrap();
		*feerate_lock += 20;
	}

	alice.node.timer_tick_occurred();

	assert!(alice.node.get_and_clear_pending_msg_events().is_empty());

	alice.set_channel_signer_ops_available(
		&bob.node.get_our_node_id(), &chan_id, ops::GET_PER_COMMITMENT_POINT, true);
	alice.node.signer_unblocked(None);

	let events = alice.node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 2);
	match (&events[0], &events[1]) {
		(MessageSendEvent::SendRevokeAndACK { .. }, MessageSendEvent::UpdateHTLCs { .. }) => {
			// TODO(waterson) we'd kind of expect to see an update_fee here, but we actually don't because
			// signer_maybe_unblocked doesn't create that. It probably should.
		}
		(a, b) => {
			panic!("Expected SendRevokeAndACK and UpdateHTLCs, got {:?} and {:?}", a, b);
		}
	}
}

#[test]
fn monitor_honors_commitment_raa_order() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let (_, _, chan_id, _) = create_announced_chan_between_nodes(&nodes, 0, 1);

	let alice = &nodes[0];
	let bob = &nodes[1];

	let (route, payment_hash, _, payment_secret) = get_route_and_payment_hash!(alice, bob, 8_000_000);

	alice.node.send_payment_with_route(&route, payment_hash,
		RecipientOnionFields::secret_only(payment_secret), PaymentId(payment_hash.0)).unwrap();
	check_added_monitors!(alice, 1);

	let payment_event = {
		let mut events = alice.node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		SendEvent::from_event(events.remove(0))
	};

	// Make the commitment secret be unavailable. The expectation here is that Bob should send the
	// revoke-and-ack first. So even though he can generate a commitment update, he should hold onto
	// that until he's ready to revoke.
	bob.set_channel_signer_ops_available(&alice.node.get_our_node_id(),  &chan_id, ops::RELEASE_COMMITMENT_SECRET, false);

	bob.node.handle_update_add_htlc(&alice.node.get_our_node_id(), &payment_event.msgs[0]);
	bob.node.handle_commitment_signed(&alice.node.get_our_node_id(), &payment_event.commitment_msg);
	check_added_monitors(bob, 1);

	assert!(bob.node.get_and_clear_pending_msg_events().is_empty());

	// Now make the commitment secret available and restart the channel.
	bob.set_channel_signer_ops_available(&alice.node.get_our_node_id(),  &chan_id, ops::RELEASE_COMMITMENT_SECRET, true);
	bob.node.signer_unblocked(None);

	get_revoke_commit_msgs(bob, &alice.node.get_our_node_id());
}

#[test]
fn reconnect_while_awaiting_commitment_point() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let (_, _, channel_id, _) = create_announced_chan_between_nodes(&nodes, 0, 1);

	let alice = &nodes[0];
	let bob = &nodes[1];

	let (route, payment_hash, _payment_preimage, payment_secret) = get_route_and_payment_hash!(alice, bob, 8_000_000);
	alice.node.send_payment_with_route(&route, payment_hash,
		RecipientOnionFields::secret_only(payment_secret), PaymentId(payment_hash.0)).unwrap();
	check_added_monitors!(alice, 1);
	let payment_event = {
		let mut events = alice.node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		SendEvent::from_event(events.remove(0))
	};
	assert_eq!(payment_event.node_id, bob.node.get_our_node_id());
	assert_eq!(payment_event.msgs.len(), 1);

	// Don't let Bob fetch the commitment point right now.
	bob.set_channel_signer_ops_available(
		&alice.node.get_our_node_id(), &channel_id, ops::GET_PER_COMMITMENT_POINT, false);

	// alice --[update_add_htlc]--> bob
	// alice --[commitment_signed]--> bob
	bob.node.handle_update_add_htlc(&alice.node.get_our_node_id(), &payment_event.msgs[0]);
	bob.node.handle_commitment_signed(&alice.node.get_our_node_id(), &payment_event.commitment_msg);
	check_added_monitors(bob, 1);

	// Bob should not have responded with any messages since he's blocked on the signer yielding the
	// commitment point.
	assert!(bob.node.get_and_clear_pending_msg_events().is_empty());

	// Disconnect Alice and Bob...
	nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id());
	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id());

	// ...and now reconnect them. Bob still should not have the commitment point, and so we'll unpack
	// the sequence by hand here.
	alice.node.peer_connected(&bob.node.get_our_node_id(), &msgs::Init {
		features: bob.node.init_features(), networks: None, remote_network_address: None
	}, true).unwrap();
	let reestablish_1 = get_chan_reestablish_msgs!(alice, bob);

	// Alice should have sent Bob a channel_reestablish.
	assert_eq!(reestablish_1.len(), 1);

	bob.node.peer_connected(&alice.node.get_our_node_id(), &msgs::Init {
		features: alice.node.init_features(), networks: None, remote_network_address: None
	}, false).unwrap();

	// But Bob should _not_ have sent Alice one, since he's waiting on the signer to provide the
	// commitment point.
	assert!(get_chan_reestablish_msgs!(bob, alice).is_empty());

	// Make Bob handle Alice's channel_reestablish. This should cause Bob to generate a
	// channel_announcement and a channel_update, but nothing more.
	{
		bob.node.handle_channel_reestablish(&alice.node.get_our_node_id(), &reestablish_1[0]);
		match handle_chan_reestablish_msgs!(bob, alice) {
			(None, None, None, _) => (),
			(channel_ready, revoke_and_ack, commitment_update, order) => {
				panic!("got channel_ready={:?} revoke_and_ack={:?} commitment_update={:?} order={:?}",
					channel_ready, revoke_and_ack, commitment_update, order);
			}
		}
	}

	// Provide the commitment points and unblock Bob's signer. This should result in Bob sending a
	// channel_reestablish, an RAA and a new commitment_update.
	bob.set_channel_signer_ops_available(
		&alice.node.get_our_node_id(), &channel_id, ops::GET_PER_COMMITMENT_POINT, true);
	bob.node.signer_unblocked(None);

	let events = bob.node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 3, "Expected 3 events, got {:?}", events);
	let reestablish_2 = match (&events[0], &events[1], &events[2]) {
		(MessageSendEvent::SendChannelReestablish { msg: channel_reestablish, .. },
		 MessageSendEvent::SendRevokeAndACK { msg: revoke_and_ack, .. },
		 MessageSendEvent::UpdateHTLCs { updates, .. }) => {
			(channel_reestablish, revoke_and_ack, updates)
		}
		(a, b, c) => panic!("Expected SendChannelReestablish, SendRevokeAndACK, UpdateHTLCs; got {:?} {:?} {:?}", a, b, c)
	};

	{
		alice.node.handle_channel_reestablish(&bob.node.get_our_node_id(), &reestablish_2.0);
		match handle_chan_reestablish_msgs!(alice, bob) {
			(None, None, None, _) => (),
			(channel_ready, revoke_and_ack, commitment_update, order) => {
				panic!("got channel_ready={:?} revoke_and_ack={:?} commitment_update={:?} order={:?}",
					channel_ready, revoke_and_ack, commitment_update, order);
			}
		}
	}
}

#[test]
fn peer_restart_with_blocked_signer() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let persister;
	let new_chain_monitor;

	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let alice_deserialized;

	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let (_, _, channel_id, _) = create_announced_chan_between_nodes(&nodes, 0, 1);

	// Disconnect Bob and restart Alice
	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id());

	{
		let alice_serialized = nodes[0].node.encode();
		let alice_monitor_serialized = get_monitor!(nodes[0], channel_id).encode();
		reload_node!(nodes[0], *nodes[0].node.get_current_default_configuration(), &alice_serialized, &[&alice_monitor_serialized], persister, new_chain_monitor, alice_deserialized);
	}

	assert!(nodes[0].node.get_and_clear_pending_events().is_empty());
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	assert!(nodes[1].node.get_and_clear_pending_events().is_empty());
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	// Turn off Alice's signer.
	nodes[0].set_channel_signer_ops_available(
		&nodes[1].node.get_our_node_id(), &channel_id,
		ops::GET_PER_COMMITMENT_POINT | ops::RELEASE_COMMITMENT_SECRET | ops::SIGN_COUNTERPARTY_COMMITMENT,
		false);

	let node1_id = nodes[1].node.get_our_node_id();
	nodes[0].forget_signer_material(&node1_id, &channel_id);

	// Reconnect Alice and Bob.
	nodes[0].node.peer_connected(&nodes[1].node.get_our_node_id(), &msgs::Init {
		features: nodes[1].node.init_features(), networks: None, remote_network_address: None
	}, false).unwrap();

	nodes[1].node.peer_connected(&nodes[0].node.get_our_node_id(), &msgs::Init {
		features: nodes[0].node.init_features(), networks: None, remote_network_address: None
	}, false).unwrap();

	// Bob should have sent a channel_reestablish, but Alice should not have since her signer is
	// offline.
	assert!(get_chan_reestablish_msgs!(nodes[0], nodes[1]).is_empty());
	let reestablish_2 = get_chan_reestablish_msgs!(nodes[1], nodes[0]);
	assert_eq!(reestablish_2.len(), 1);

	nodes[0].node.handle_channel_reestablish(&nodes[1].node.get_our_node_id(), &reestablish_2[0]);
	match handle_chan_reestablish_msgs!(nodes[0], nodes[1]) {
		(None, None, None, _) => (),
		(channel_ready, revoke_and_ack, commitment_update, order) => {
			panic!("got channel_ready={:?} revoke_and_ack={:?} commitment_update={:?} order={:?}",
						 channel_ready, revoke_and_ack, commitment_update, order);
		}
	};

	// Re-enable and unblock Alice's signer.
	nodes[0].set_channel_signer_ops_available(
		&nodes[1].node.get_our_node_id(), &channel_id,
		ops::GET_PER_COMMITMENT_POINT | ops::RELEASE_COMMITMENT_SECRET | ops::SIGN_COUNTERPARTY_COMMITMENT,
		true);

	nodes[0].node.signer_unblocked(None);

	// N.B. that we can't just use `get_chan_reestablish_msgs` here, because we'll be expecting _both_
	// the channel_reestablish and the channel_ready that will have been generated from being sent the
	// channel_reestablish from our counterparty.
	let events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 2, "Expected two events, got {:?}", events);
	match (&events[0], &events[1]) {
		(MessageSendEvent::SendChannelReestablish { .. }, MessageSendEvent::SendChannelReady { .. }) => (),
		(a, b) => panic!("Expected channel_reestablish and channel_ready, got {:?} and {:?}", a, b),
	};
}

#[test]
fn peer_restart_with_blocked_signer_and_pending_payment() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let persister;
	let new_chain_monitor;

	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let alice_deserialized;

	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let (_, _, channel_id, _) = create_announced_chan_between_nodes(&nodes, 0, 1);

	let (route, payment_hash, _payment_preimage, payment_secret) = get_route_and_payment_hash!(nodes[0], nodes[1], 1_000_000);
	nodes[0].node.send_payment_with_route(&route, payment_hash,
		RecipientOnionFields::secret_only(payment_secret), PaymentId(payment_hash.0)).unwrap();

	check_added_monitors!(nodes[0], 1);
	assert!(nodes[0].node.get_and_clear_pending_events().is_empty());

	// Deliver the update_add_htlc and commitment_signed to Bob.
	{
		let mut events = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		let payment_event = SendEvent::from_event(events.remove(0));
		assert_eq!(payment_event.node_id, nodes[1].node.get_our_node_id());
		assert_eq!(payment_event.msgs.len(), 1);
		nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &payment_event.msgs[0]);
		nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &payment_event.commitment_msg);
	}

	// Disconnect Bob and restart Alice
	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id());

	{
		let alice_serialized = nodes[0].node.encode();
		let alice_monitor_serialized = get_monitor!(nodes[0], channel_id).encode();
		reload_node!(nodes[0], *nodes[0].node.get_current_default_configuration(), &alice_serialized, &[&alice_monitor_serialized], persister, new_chain_monitor, alice_deserialized);
	}

	assert!(nodes[0].node.get_and_clear_pending_events().is_empty());
	assert!(nodes[1].node.get_and_clear_pending_events().is_empty());

	// Turn off Bob's signer.
	nodes[1].set_channel_signer_ops_available(
		&nodes[0].node.get_our_node_id(), &channel_id,
		ops::GET_PER_COMMITMENT_POINT | ops::RELEASE_COMMITMENT_SECRET | ops::SIGN_COUNTERPARTY_COMMITMENT,
		false);

	// Reconnect Alice and Bob.
	nodes[0].node.peer_connected(&nodes[1].node.get_our_node_id(), &msgs::Init {
		features: nodes[1].node.init_features(), networks: None, remote_network_address: None
	}, false).unwrap();

	nodes[1].node.peer_connected(&nodes[0].node.get_our_node_id(), &msgs::Init {
		features: nodes[0].node.init_features(), networks: None, remote_network_address: None
	}, false).unwrap();

	// Alice should have sent Bob a channel_reestablish and vice versa.
	let reestablish_1 = get_chan_reestablish_msgs!(nodes[0], nodes[1]);
	assert_eq!(reestablish_1.len(), 1);
	let reestablish_2 = get_chan_reestablish_msgs!(nodes[1], nodes[0]);
	assert_eq!(reestablish_2.len(), 1);

	{
		nodes[1].node.handle_channel_reestablish(&nodes[0].node.get_our_node_id(), &reestablish_1[0]);
		match handle_chan_reestablish_msgs!(nodes[1], nodes[0]) {
			(None, None, None, _) => (),
			(channel_ready, revoke_and_ack, commitment_update, order) => {
				panic!("got channel_ready={:?} revoke_and_ack={:?} commitment_update={:?} order={:?}",
					channel_ready, revoke_and_ack, commitment_update, order);
			}
		}
	}

	{
		nodes[0].node.handle_channel_reestablish(&nodes[1].node.get_our_node_id(), &reestablish_2[0]);
		match handle_chan_reestablish_msgs!(nodes[0], nodes[1]) {
			(None, None, None, _) => (),
			(channel_ready, revoke_and_ack, commitment_update, order) => {
				panic!("got channel_ready={:?} revoke_and_ack={:?} commitment_update={:?} order={:?}",
					channel_ready, revoke_and_ack, commitment_update, order);
			}
		}
	};

	// Re-enable and unblock Bob's signer.
	nodes[1].set_channel_signer_ops_available(
		&nodes[0].node.get_our_node_id(), &channel_id,
		ops::GET_PER_COMMITMENT_POINT | ops::RELEASE_COMMITMENT_SECRET | ops::SIGN_COUNTERPARTY_COMMITMENT,
		true);

	nodes[1].node.signer_unblocked(None);

	// At this point we should provide Alice with the revoke_and_ack and commitment_signed.
	get_revoke_commit_msgs(&nodes[1], &nodes[0].node.get_our_node_id());
	check_added_monitors!(nodes[1], 1);
}

#[test]
fn peer_restart_with_blocked_signer_before_pending_payment() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let persister;
	let new_chain_monitor;

	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let alice_deserialized;

	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let (_, _, channel_id, _) = create_announced_chan_between_nodes(&nodes, 0, 1);

	let (route, payment_hash, _payment_preimage, payment_secret) = get_route_and_payment_hash!(nodes[0], nodes[1], 1_000_000);
	nodes[0].node.send_payment_with_route(&route, payment_hash,
		RecipientOnionFields::secret_only(payment_secret), PaymentId(payment_hash.0)).unwrap();

	check_added_monitors!(nodes[0], 1);
	assert!(nodes[0].node.get_and_clear_pending_events().is_empty());

	// Turn off Bob's signer.
	nodes[1].set_channel_signer_ops_available(
		&nodes[0].node.get_our_node_id(), &channel_id,
		ops::GET_PER_COMMITMENT_POINT | ops::RELEASE_COMMITMENT_SECRET | ops::SIGN_COUNTERPARTY_COMMITMENT,
		false);

	// Deliver the update_add_htlc and commitment_signed to Bob.
	{
		let mut events = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		let payment_event = SendEvent::from_event(events.remove(0));
		assert_eq!(payment_event.node_id, nodes[1].node.get_our_node_id());
		assert_eq!(payment_event.msgs.len(), 1);
		nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &payment_event.msgs[0]);
		nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &payment_event.commitment_msg);
	}

	// Disconnect Bob and restart Alice
	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id());

	{
		let alice_serialized = nodes[0].node.encode();
		let alice_monitor_serialized = get_monitor!(nodes[0], channel_id).encode();
		reload_node!(nodes[0], *nodes[0].node.get_current_default_configuration(), &alice_serialized, &[&alice_monitor_serialized], persister, new_chain_monitor, alice_deserialized);
	}

	assert!(nodes[0].node.get_and_clear_pending_events().is_empty());
	assert!(nodes[1].node.get_and_clear_pending_events().is_empty());

	// Reconnect Alice and Bob.
	nodes[0].node.peer_connected(&nodes[1].node.get_our_node_id(), &msgs::Init {
		features: nodes[1].node.init_features(), networks: None, remote_network_address: None
	}, false).unwrap();

	nodes[1].node.peer_connected(&nodes[0].node.get_our_node_id(), &msgs::Init {
		features: nodes[0].node.init_features(), networks: None, remote_network_address: None
	}, false).unwrap();

	// Re-enable and unblock Bob's signer.
	nodes[1].set_channel_signer_ops_available(
		&nodes[0].node.get_our_node_id(), &channel_id,
		ops::GET_PER_COMMITMENT_POINT | ops::RELEASE_COMMITMENT_SECRET | ops::SIGN_COUNTERPARTY_COMMITMENT,
		true);

	nodes[1].node.signer_unblocked(None);

	// Alice should have sent Bob a channel_reestablish and vice versa. We explicitly do _not_ expect
	// to see a RevokeAndACK and CommitmentUpdate yet!
	let reestablish_1 = get_chan_reestablish_msgs!(nodes[0], nodes[1]);
	assert_eq!(reestablish_1.len(), 1);
	let reestablish_2 = get_chan_reestablish_msgs!(nodes[1], nodes[0]);
	assert_eq!(reestablish_2.len(), 1);

	let (raa, cu) = {
		nodes[1].node.handle_channel_reestablish(&nodes[0].node.get_our_node_id(), &reestablish_1[0]);
		match handle_chan_reestablish_msgs!(nodes[1], nodes[0]) {
			(None, Some(raa), Some(cu), RAACommitmentOrder::RevokeAndACKFirst) => (raa, cu),
			(channel_ready, revoke_and_ack, commitment_update, order) => {
				panic!("got channel_ready={:?} revoke_and_ack={:?} commitment_update={:?} order={:?}",
					channel_ready, revoke_and_ack, commitment_update, order);
			}
		}
	};

	{
		nodes[0].node.handle_channel_reestablish(&nodes[1].node.get_our_node_id(), &reestablish_2[0]);
		match handle_chan_reestablish_msgs!(nodes[0], nodes[1]) {
			(None, None, None, _) => (),
			(channel_ready, revoke_and_ack, commitment_update, order) => {
				panic!("got channel_ready={:?} revoke_and_ack={:?} commitment_update={:?} order={:?}",
					channel_ready, revoke_and_ack, commitment_update, order);
			}
		}
	};

	nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &raa);
	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &cu.commitment_signed);
	check_added_monitors!(nodes[0], 2);

	// At this point Alice should provide Bob with the revoke_and_ack.
	let raa = {
		let events = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1, "Expected 1 event, got {}: {:?}", events.len(), events);
		match &events[0] {
			MessageSendEvent::SendRevokeAndACK { msg: raa, .. } => raa.clone(),
			ev => panic!("Expected SendRevokeAndACK, got {:?}", ev)
		}
	};

	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &raa);
	check_added_monitors!(nodes[1], 2);

	expect_pending_htlcs_forwardable!(nodes[1]);
	expect_payment_claimable!(nodes[1], payment_hash, payment_secret, 1_000_000);
}

#[test]
fn no_stray_channel_reestablish() {
	// Original fuzz trace.
	// a0 Disable A’s signer.
	// 2c Disconnect A and B, then restart A.
	// 0e Reconnect A and B.
	// 2d Disconnect A and B (and C), then restart B.
	// a1 Unblock A’s signer get_per_commitment_point
	// ff Reset.

	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let alice_persister;
	let bob_persister;
	let alice_new_chain_monitor;
	let bob_new_chain_monitor;

	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let alice_deserialized;
	let bob_deserialized;

	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let (_, _, channel_id, _) = create_announced_chan_between_nodes(&nodes, 0, 1);

	// Turn off Alice's signer.
	eprintln!("disabling alice's signer");
	nodes[0].set_channel_signer_ops_available(
		&nodes[1].node.get_our_node_id(), &channel_id,
		ops::GET_PER_COMMITMENT_POINT | ops::RELEASE_COMMITMENT_SECRET | ops::SIGN_COUNTERPARTY_COMMITMENT,
		false);

	// Disconnect Bob and restart Alice
	eprintln!("disconnecting bob");
	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id());

	eprintln!("restarting alice");
	{
		let alice_serialized = nodes[0].node.encode();
		let alice_monitor_serialized = get_monitor!(nodes[0], channel_id).encode();
		reload_node!(nodes[0], *nodes[0].node.get_current_default_configuration(), &alice_serialized, &[&alice_monitor_serialized], alice_persister, alice_new_chain_monitor, alice_deserialized);
	}

	// Reconnect Alice and Bob.
	eprintln!("reconnecting alice and bob");
	nodes[0].node.peer_connected(&nodes[1].node.get_our_node_id(), &msgs::Init {
		features: nodes[1].node.init_features(), networks: None, remote_network_address: None
	}, false).unwrap();

	// Disconnect Alice and restart Bob
	eprintln!("disconnecting alice");
	nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id());

	eprintln!("restarting bob");
	{
		let bob_serialized = nodes[1].node.encode();
		let bob_monitor_serialized = get_monitor!(nodes[1], channel_id).encode();
		reload_node!(nodes[1], *nodes[1].node.get_current_default_configuration(), &bob_serialized, &[&bob_monitor_serialized], bob_persister, bob_new_chain_monitor, bob_deserialized);
	}

	eprintln!("unblocking alice's signer for get_per_commitment_point");
	nodes[0].set_channel_signer_ops_available(&nodes[1].node.get_our_node_id(), &channel_id, ops::GET_PER_COMMITMENT_POINT, true);
	nodes[0].node.signer_unblocked(None);

	let events = nodes[0].node.get_and_clear_pending_msg_events();
	assert!(events.is_empty(), "Expected no events from Alice, got {:?}", events);
}

#[test]
fn dont_elide_channely_ready_from_state_1() {
	// 1. Disable Alice's signer.
	// 2. Send a payment from Alice to Bob.
	// 3. Disconnect Alice and Bob. Reload Alice.
	// 4. Reconnect Alice and Bob.
	// 5. Process messages on Bob, which should generate a `channel_reestablish`.
	// 6. Process messages on Alice, which should *not* send anything, in particular an
	//    `update_add_htlc` because Alice must send a `channel_ready` (that she can't create
	//    without her signer) first.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let persister;
	let new_chain_monitor;

	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let alice_deserialized;

	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let (_, _, channel_id, _) = create_announced_chan_between_nodes(&nodes, 0, 1);

	// Turn off Alice's signer.
	eprintln!("disabling alice's signer");
	nodes[0].set_channel_signer_ops_available(
		&nodes[1].node.get_our_node_id(), &channel_id,
		ops::GET_PER_COMMITMENT_POINT | ops::RELEASE_COMMITMENT_SECRET | ops::SIGN_COUNTERPARTY_COMMITMENT,
		false);

	eprintln!("sending payment from alice to bob");
	let (route, payment_hash, _payment_preimage, payment_secret) = get_route_and_payment_hash!(nodes[0], nodes[1], 1_000_000);
	nodes[0].node.send_payment_with_route(&route, payment_hash,
		RecipientOnionFields::secret_only(payment_secret), PaymentId(payment_hash.0)).unwrap();

	check_added_monitors!(nodes[0], 1);
	assert!(nodes[0].node.get_and_clear_pending_events().is_empty());
	assert!(nodes[1].node.get_and_clear_pending_events().is_empty());

	// Disconnect Bob and restart Alice
	eprintln!("disconnecting bob");
	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id());

	eprintln!("restarting alice");
	{
		let alice_serialized = nodes[0].node.encode();
		let alice_monitor_serialized = get_monitor!(nodes[0], channel_id).encode();
		reload_node!(nodes[0], *nodes[0].node.get_current_default_configuration(), &alice_serialized, &[&alice_monitor_serialized], persister, new_chain_monitor, alice_deserialized);
	}

	assert!(nodes[0].node.get_and_clear_pending_events().is_empty());
	assert!(nodes[1].node.get_and_clear_pending_events().is_empty());

	eprintln!("unblocking alice's signer with commmitment signed");
	nodes[0].set_channel_signer_ops_available(
		&nodes[1].node.get_our_node_id(), &channel_id,
		ops::SIGN_COUNTERPARTY_COMMITMENT,
		true);
	nodes[0].node.signer_unblocked(None);

	assert!(nodes[0].node.get_and_clear_pending_events().is_empty());
	assert!(nodes[1].node.get_and_clear_pending_events().is_empty());

	// Reconnect Alice and Bob.
	eprintln!("reconnecting alice and bob");
	nodes[0].node.peer_connected(&nodes[1].node.get_our_node_id(), &msgs::Init {
		features: nodes[1].node.init_features(), networks: None, remote_network_address: None
	}, false).unwrap();

	nodes[1].node.peer_connected(&nodes[0].node.get_our_node_id(), &msgs::Init {
		features: nodes[0].node.init_features(), networks: None, remote_network_address: None
	}, false).unwrap();

	// Bob should have sent Alice a channel_reestablish. Alice should not have done anything.
	assert!(get_chan_reestablish_msgs!(nodes[0], nodes[1]).is_empty());
	let reestablish_2 = get_chan_reestablish_msgs!(nodes[1], nodes[0]);
	assert_eq!(reestablish_2.len(), 1);

	// When Alice handle's the channel_reestablish, she should _still_ do nothing, in particular,
	// because she doesn't have the channel ready available.
	nodes[0].node.handle_channel_reestablish(&nodes[1].node.get_our_node_id(), &reestablish_2[0]);
	match handle_chan_reestablish_msgs!(nodes[0], nodes[1]) {
		(None, None, None, _) => (),
		(channel_ready, revoke_and_ack, commitment_update, order) => {
			panic!("got channel_ready={:?} revoke_and_ack={:?} commitment_update={:?} order={:?}",
						 channel_ready, revoke_and_ack, commitment_update, order);
		}
	};

	// Now provide the commitment point and Alice should send her channel_reestablish.
	nodes[0].set_channel_signer_ops_available(
		&nodes[1].node.get_our_node_id(), &channel_id,
		ops::GET_PER_COMMITMENT_POINT,
		true);
	nodes[0].node.signer_unblocked(None);

	let events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 3, "Expected 2 events, got {}: {:?}", events.len(), events);
	match (&events[0], &events[1], &events[2]) {
		(MessageSendEvent::SendChannelReestablish { .. },
		 MessageSendEvent::SendChannelReady { .. },
		 MessageSendEvent::UpdateHTLCs { .. }) => (),
		(a, b, c) => panic!("Expected SendChannelReestablish SendChannelReady UpdateHTLCs, not {:?} {:?} {:?}", a, b, c)
	};
}

#[test]
fn dont_lose_commitment_update() {
	// 1. Send a payment from Alice to Bob.
	// 2. Disable signing on Alice.
	// 3. Disconnect Alice and Bob. Reload Alice.
	// 4. Reconnect Alice and Bob.
	// 5. Process messages on Bob, which should generate a `channel_reestablish`.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let persister;
	let new_chain_monitor;

	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let alice_deserialized;

	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let (_, _, channel_id, _) = create_announced_chan_between_nodes(&nodes, 0, 1);

	eprintln!("sending payment from alice to bob");
	let (route, payment_hash, _payment_preimage, payment_secret) = get_route_and_payment_hash!(nodes[0], nodes[1], 1_000_000);
	nodes[0].node.send_payment_with_route(&route, payment_hash,
		RecipientOnionFields::secret_only(payment_secret), PaymentId(payment_hash.0)).unwrap();

	// Turn off Alice's signer.
	eprintln!("disabling alice's signer");
	nodes[0].set_channel_signer_ops_available(
		&nodes[1].node.get_our_node_id(), &channel_id,
		ops::GET_PER_COMMITMENT_POINT | ops::RELEASE_COMMITMENT_SECRET | ops::SIGN_COUNTERPARTY_COMMITMENT,
		false);

	check_added_monitors!(nodes[0], 1);
	assert!(nodes[0].node.get_and_clear_pending_events().is_empty());
	assert!(nodes[1].node.get_and_clear_pending_events().is_empty());

	// Disconnect Bob and restart Alice
	eprintln!("disconnecting bob");
	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id());

	eprintln!("restarting alice");
	{
		let alice_serialized = nodes[0].node.encode();
		let alice_monitor_serialized = get_monitor!(nodes[0], channel_id).encode();
		reload_node!(nodes[0], *nodes[0].node.get_current_default_configuration(), &alice_serialized, &[&alice_monitor_serialized], persister, new_chain_monitor, alice_deserialized);
	}

	// Reconnect Alice and Bob.
	eprintln!("reconnecting alice and bob");
	nodes[0].node.peer_connected(&nodes[1].node.get_our_node_id(), &msgs::Init {
		features: nodes[1].node.init_features(), networks: None, remote_network_address: None
	}, false).unwrap();

	nodes[1].node.peer_connected(&nodes[0].node.get_our_node_id(), &msgs::Init {
		features: nodes[0].node.init_features(), networks: None, remote_network_address: None
	}, false).unwrap();

	// Bob should have sent Alice a channel_reestablish. Alice should not have done anything.
	assert!(get_chan_reestablish_msgs!(nodes[0], nodes[1]).is_empty());
	let reestablish_2 = get_chan_reestablish_msgs!(nodes[1], nodes[0]);
	assert_eq!(reestablish_2.len(), 1);

	// When Alice handle's the channel_reestablish, she should _still_ do nothing, in particular,
	// because she doesn't have the channel ready available.
	nodes[0].node.handle_channel_reestablish(&nodes[1].node.get_our_node_id(), &reestablish_2[0]);
	match handle_chan_reestablish_msgs!(nodes[0], nodes[1]) {
		(None, None, None, _) => (),
		(channel_ready, revoke_and_ack, commitment_update, order) => {
			panic!("got channel_ready={:?} revoke_and_ack={:?} commitment_update={:?} order={:?}",
						 channel_ready, revoke_and_ack, commitment_update, order);
		}
	};

	{
		let events = nodes[0].node.get_and_clear_pending_msg_events();
		assert!(events.is_empty(), "expected no events, got {:?}", events);
	}

	{
		let events = nodes[1].node.get_and_clear_pending_msg_events();
		assert!(events.is_empty(), "expected no events, got {:?}", events);
	}

	eprintln!("unblocking alice's signer");
	nodes[0].set_channel_signer_ops_available(
		&nodes[1].node.get_our_node_id(), &channel_id,
		ops::GET_PER_COMMITMENT_POINT | ops::RELEASE_COMMITMENT_SECRET | ops::SIGN_COUNTERPARTY_COMMITMENT,
		true);
	nodes[0].node.signer_unblocked(None);

	let events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 3, "Expected 3 events, got {}: {:?}", events.len(), events);
	match (&events[0], &events[1], &events[2]) {
		(MessageSendEvent::SendChannelReestablish { .. },
		 MessageSendEvent::SendChannelReady { .. },
		 MessageSendEvent::UpdateHTLCs { .. }) => (),
		(a, b, c) => panic!("Expected SendChannelReestablish SendChannelReady UpdateHTLCs; not {:?} {:?} {:?}", a, b, c)
	}
}

#[test]
fn dont_lose_commitment_update_redux() {
	// - ~a0~ Disable A's signer.
	// - ~60~ Send a payment from A to B for 1,000 msats.
	// - ~2c~ Disconnect A and B, then restart A.
	// - ~0e~ Reconnect A and B.
	// - ~a3~ Unblock A's signer ~sign_counterparty_commitment~.
	// - ~19~ Process all messages on B.
	// - ~ff~ Reset.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let persister;
	let new_chain_monitor;

	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let alice_deserialized;

	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let (_, _, channel_id, _) = create_announced_chan_between_nodes(&nodes, 0, 1);

	// Turn off Alice's signer.
	eprintln!("disabling alice's signer");
	nodes[0].set_channel_signer_ops_available(
		&nodes[1].node.get_our_node_id(), &channel_id,
		ops::GET_PER_COMMITMENT_POINT | ops::RELEASE_COMMITMENT_SECRET | ops::SIGN_COUNTERPARTY_COMMITMENT,
		false);

	eprintln!("sending payment from alice to bob");
	let (route, payment_hash, _payment_preimage, payment_secret) = get_route_and_payment_hash!(nodes[0], nodes[1], 1_000_000);
	nodes[0].node.send_payment_with_route(&route, payment_hash,
		RecipientOnionFields::secret_only(payment_secret), PaymentId(payment_hash.0)).unwrap();

	check_added_monitors!(nodes[0], 1);
	assert!(nodes[0].node.get_and_clear_pending_events().is_empty());
	assert!(nodes[1].node.get_and_clear_pending_events().is_empty());

	// Disconnect Bob and restart Alice
	eprintln!("disconnecting bob");
	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id());

	eprintln!("restarting alice");
	{
		let alice_serialized = nodes[0].node.encode();
		let alice_monitor_serialized = get_monitor!(nodes[0], channel_id).encode();
		reload_node!(nodes[0], *nodes[0].node.get_current_default_configuration(), &alice_serialized, &[&alice_monitor_serialized], persister, new_chain_monitor, alice_deserialized);
	}

	// Reconnect Alice and Bob.
	eprintln!("reconnecting alice and bob");
	nodes[0].node.peer_connected(&nodes[1].node.get_our_node_id(), &msgs::Init {
		features: nodes[1].node.init_features(), networks: None, remote_network_address: None
	}, false).unwrap();

	nodes[1].node.peer_connected(&nodes[0].node.get_our_node_id(), &msgs::Init {
		features: nodes[0].node.init_features(), networks: None, remote_network_address: None
	}, false).unwrap();

	// Bob should have sent Alice a channel_reestablish. Alice should not have done anything.
	assert!(get_chan_reestablish_msgs!(nodes[0], nodes[1]).is_empty());
	let reestablish_2 = get_chan_reestablish_msgs!(nodes[1], nodes[0]);
	assert_eq!(reestablish_2.len(), 1);

	// Unblock alice for sign_counterparty_commitment.
	eprintln!("unblocking alice's signer for sign_counterparty_commitment");
	nodes[0].set_channel_signer_ops_available(&nodes[1].node.get_our_node_id(), &channel_id, ops::SIGN_COUNTERPARTY_COMMITMENT, true);
	nodes[0].node.signer_unblocked(None);
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());

	nodes[0].node.handle_channel_reestablish(&nodes[1].node.get_our_node_id(), &reestablish_2[0]);
	match handle_chan_reestablish_msgs!(nodes[0], nodes[1]) {
		(None, None, None, _) => (),
		(channel_ready, revoke_and_ack, commitment_update, order) => {
			panic!("got channel_ready={:?} revoke_and_ack={:?} commitment_update={:?} order={:?}",
						 channel_ready, revoke_and_ack, commitment_update, order);
		}
	};

	// Unblock alice for get_per_commitment_point and release_commitment_secret
	eprintln!("unblocking alice's signer for get_per_commitment_point and release_commitment_secret");
	nodes[0].set_channel_signer_ops_available(&nodes[1].node.get_our_node_id(), &channel_id, ops::GET_PER_COMMITMENT_POINT | ops::RELEASE_COMMITMENT_SECRET, true);
	nodes[0].node.signer_unblocked(None);

	let events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 3, "Expected 3 events, got {}: {:?}", events.len(), events);
	match (&events[0], &events[1], &events[2]) {
		(MessageSendEvent::SendChannelReestablish { .. },
		 MessageSendEvent::SendChannelReady { .. },
		 MessageSendEvent::UpdateHTLCs { .. }) => (),
		(a, b, c) => panic!("Expected SendChannelReestablish SendChannelReady UpdateHTLCs; not {:?} {:?} {:?}", a, b, c)
	}
}
