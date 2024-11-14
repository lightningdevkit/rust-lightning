// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

use crate::blinded_path::message::{MessageContext, OffersContext};
use crate::events::{Event, MessageSendEventsProvider, PaymentFailureReason};
use crate::ln::channelmanager::PaymentId;
use crate::ln::functional_test_utils::*;
use crate::ln::msgs::OnionMessageHandler;
use crate::ln::offers_tests;
use crate::ln::outbound_payment::Retry;
use crate::offers::nonce::Nonce;
use crate::onion_message::async_payments::{
	AsyncPaymentsMessage, AsyncPaymentsMessageHandler, ReleaseHeldHtlc,
};
use crate::onion_message::messenger::{Destination, MessageRouter, MessageSendInstructions};
use crate::onion_message::offers::OffersMessage;
use crate::onion_message::packet::ParsedOnionMessageContents;
use crate::prelude::*;
use crate::types::features::Bolt12InvoiceFeatures;
use bitcoin::secp256k1::Secp256k1;

use core::convert::Infallible;
use core::time::Duration;

#[test]
#[cfg(async_payments)]
fn static_invoice_unknown_required_features() {
	// Test that we will fail to pay a static invoice with unsupported required features.
	let secp_ctx = Secp256k1::new();
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 0);
	create_unannounced_chan_between_nodes_with_value(&nodes, 1, 2, 1_000_000, 0);

	let blinded_paths_to_always_online_node = nodes[1]
		.message_router
		.create_blinded_paths(
			nodes[1].node.get_our_node_id(),
			MessageContext::Offers(OffersContext::InvoiceRequest { nonce: Nonce([42; 16]) }),
			Vec::new(),
			&secp_ctx,
		)
		.unwrap();
	let (offer_builder, nonce) = nodes[2]
		.node
		.create_async_receive_offer_builder(blinded_paths_to_always_online_node)
		.unwrap();
	let offer = offer_builder.build().unwrap();
	let static_invoice_unknown_req_features = nodes[2]
		.node
		.create_static_invoice_builder(&offer, nonce, None)
		.unwrap()
		.features_unchecked(Bolt12InvoiceFeatures::unknown())
		.build_and_sign(&secp_ctx)
		.unwrap();

	let amt_msat = 5000;
	let payment_id = PaymentId([1; 32]);
	nodes[0]
		.node
		.pay_for_offer(&offer, None, Some(amt_msat), None, payment_id, Retry::Attempts(0), None)
		.unwrap();

	// Don't forward the invreq since we don't support retrieving the static invoice from the
	// recipient's LSP yet, instead manually construct the response.
	let invreq_om = nodes[0]
		.onion_messenger
		.next_onion_message_for_peer(nodes[1].node.get_our_node_id())
		.unwrap();
	let invreq_reply_path = offers_tests::extract_invoice_request(&nodes[1], &invreq_om).1;
	nodes[1]
		.onion_messenger
		.send_onion_message(
			ParsedOnionMessageContents::<Infallible>::Offers(OffersMessage::StaticInvoice(
				static_invoice_unknown_req_features,
			)),
			MessageSendInstructions::WithoutReplyPath {
				destination: Destination::BlindedPath(invreq_reply_path),
			},
		)
		.unwrap();

	let static_invoice_om = nodes[1]
		.onion_messenger
		.next_onion_message_for_peer(nodes[0].node.get_our_node_id())
		.unwrap();
	nodes[0]
		.onion_messenger
		.handle_onion_message(nodes[1].node.get_our_node_id(), &static_invoice_om);
	let events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		Event::PaymentFailed { payment_hash, payment_id: ev_payment_id, reason } => {
			assert_eq!(payment_hash, None);
			assert_eq!(payment_id, ev_payment_id);
			assert_eq!(reason, Some(PaymentFailureReason::UnknownRequiredFeatures));
		},
		_ => panic!(),
	}
}

#[test]
fn ignore_unexpected_static_invoice() {
	// Test that we'll ignore unexpected static invoices, invoices that don't match our invoice
	// request, and duplicate invoices.
	let secp_ctx = Secp256k1::new();
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 0);
	create_unannounced_chan_between_nodes_with_value(&nodes, 1, 2, 1_000_000, 0);

	// Initiate payment to the sender's intended offer.
	let blinded_paths_to_always_online_node = nodes[1]
		.message_router
		.create_blinded_paths(
			nodes[1].node.get_our_node_id(),
			MessageContext::Offers(OffersContext::InvoiceRequest { nonce: Nonce([42; 16]) }),
			Vec::new(),
			&secp_ctx,
		)
		.unwrap();
	let (offer_builder, offer_nonce) = nodes[2]
		.node
		.create_async_receive_offer_builder(blinded_paths_to_always_online_node.clone())
		.unwrap();
	let offer = offer_builder.build().unwrap();
	let amt_msat = 5000;
	let payment_id = PaymentId([1; 32]);
	nodes[0]
		.node
		.pay_for_offer(&offer, None, Some(amt_msat), None, payment_id, Retry::Attempts(0), None)
		.unwrap();

	// Don't forward the invreq since we don't support retrieving the static invoice from the
	// recipient's LSP yet, instead manually construct the responses below.
	let invreq_om = nodes[0]
		.onion_messenger
		.next_onion_message_for_peer(nodes[1].node.get_our_node_id())
		.unwrap();
	let invreq_reply_path = offers_tests::extract_invoice_request(&nodes[1], &invreq_om).1;

	// Create a static invoice to be sent over the reply path containing the original payment_id, but
	// the static invoice corresponds to a different offer than was originally paid.
	let unexpected_static_invoice = {
		let (offer_builder, nonce) = nodes[2]
			.node
			.create_async_receive_offer_builder(blinded_paths_to_always_online_node)
			.unwrap();
		let sender_unintended_offer = offer_builder.build().unwrap();

		nodes[2]
			.node
			.create_static_invoice_builder(&sender_unintended_offer, nonce, None)
			.unwrap()
			.build_and_sign(&secp_ctx)
			.unwrap()
	};

	// Check that we'll ignore the unexpected static invoice.
	nodes[1]
		.onion_messenger
		.send_onion_message(
			ParsedOnionMessageContents::<Infallible>::Offers(OffersMessage::StaticInvoice(
				unexpected_static_invoice,
			)),
			MessageSendInstructions::WithoutReplyPath {
				destination: Destination::BlindedPath(invreq_reply_path.clone()),
			},
		)
		.unwrap();
	let unexpected_static_invoice_om = nodes[1]
		.onion_messenger
		.next_onion_message_for_peer(nodes[0].node.get_our_node_id())
		.unwrap();
	nodes[0]
		.onion_messenger
		.handle_onion_message(nodes[1].node.get_our_node_id(), &unexpected_static_invoice_om);
	let async_pmts_msgs = AsyncPaymentsMessageHandler::release_pending_messages(nodes[0].node);
	assert!(async_pmts_msgs.is_empty());
	assert!(nodes[0].node.get_and_clear_pending_events().is_empty());

	// A valid static invoice corresponding to the correct offer will succeed and cause us to send a
	// held_htlc_available onion message.
	let valid_static_invoice = nodes[2]
		.node
		.create_static_invoice_builder(&offer, offer_nonce, None)
		.unwrap()
		.build_and_sign(&secp_ctx)
		.unwrap();

	nodes[1]
		.onion_messenger
		.send_onion_message(
			ParsedOnionMessageContents::<Infallible>::Offers(OffersMessage::StaticInvoice(
				valid_static_invoice.clone(),
			)),
			MessageSendInstructions::WithoutReplyPath {
				destination: Destination::BlindedPath(invreq_reply_path.clone()),
			},
		)
		.unwrap();
	let static_invoice_om = nodes[1]
		.onion_messenger
		.next_onion_message_for_peer(nodes[0].node.get_our_node_id())
		.unwrap();
	nodes[0]
		.onion_messenger
		.handle_onion_message(nodes[1].node.get_our_node_id(), &static_invoice_om);
	let async_pmts_msgs = AsyncPaymentsMessageHandler::release_pending_messages(nodes[0].node);
	assert!(!async_pmts_msgs.is_empty());
	assert!(async_pmts_msgs
		.into_iter()
		.all(|(msg, _)| matches!(msg, AsyncPaymentsMessage::HeldHtlcAvailable(_))));

	// Receiving a duplicate invoice will have no effect.
	nodes[1]
		.onion_messenger
		.send_onion_message(
			ParsedOnionMessageContents::<Infallible>::Offers(OffersMessage::StaticInvoice(
				valid_static_invoice,
			)),
			MessageSendInstructions::WithoutReplyPath {
				destination: Destination::BlindedPath(invreq_reply_path),
			},
		)
		.unwrap();
	let dup_static_invoice_om = nodes[1]
		.onion_messenger
		.next_onion_message_for_peer(nodes[0].node.get_our_node_id())
		.unwrap();
	nodes[0]
		.onion_messenger
		.handle_onion_message(nodes[1].node.get_our_node_id(), &dup_static_invoice_om);
	let async_pmts_msgs = AsyncPaymentsMessageHandler::release_pending_messages(nodes[0].node);
	assert!(async_pmts_msgs.is_empty());
}

#[test]
fn pays_static_invoice() {
	// Test that we support the async payments flow up to and including sending the actual payment.
	// Async receive is not yet supported so we don't complete the payment yet.
	let secp_ctx = Secp256k1::new();
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 0);
	create_unannounced_chan_between_nodes_with_value(&nodes, 1, 2, 1_000_000, 0);

	let blinded_paths_to_always_online_node = nodes[1]
		.message_router
		.create_blinded_paths(
			nodes[1].node.get_our_node_id(),
			MessageContext::Offers(OffersContext::InvoiceRequest { nonce: Nonce([42; 16]) }),
			Vec::new(),
			&secp_ctx,
		)
		.unwrap();
	let (offer_builder, offer_nonce) = nodes[2]
		.node
		.create_async_receive_offer_builder(blinded_paths_to_always_online_node)
		.unwrap();
	let offer = offer_builder.build().unwrap();
	let amt_msat = 5000;
	let payment_id = PaymentId([1; 32]);
	let relative_expiry = Duration::from_secs(1000);
	let static_invoice = nodes[2]
		.node
		.create_static_invoice_builder(&offer, offer_nonce, Some(relative_expiry))
		.unwrap()
		.build_and_sign(&secp_ctx)
		.unwrap();
	assert!(static_invoice.invoice_features().supports_basic_mpp());
	assert_eq!(static_invoice.relative_expiry(), relative_expiry);

	nodes[0]
		.node
		.pay_for_offer(&offer, None, Some(amt_msat), None, payment_id, Retry::Attempts(0), None)
		.unwrap();

	// Don't forward the invreq since we don't support retrieving the static invoice from the
	// recipient's LSP yet, instead manually construct the response.
	let invreq_om = nodes[0]
		.onion_messenger
		.next_onion_message_for_peer(nodes[1].node.get_our_node_id())
		.unwrap();
	let invreq_reply_path = offers_tests::extract_invoice_request(&nodes[1], &invreq_om).1;

	nodes[1]
		.onion_messenger
		.send_onion_message(
			ParsedOnionMessageContents::<Infallible>::Offers(OffersMessage::StaticInvoice(
				static_invoice,
			)),
			MessageSendInstructions::WithoutReplyPath {
				destination: Destination::BlindedPath(invreq_reply_path),
			},
		)
		.unwrap();
	let static_invoice_om = nodes[1]
		.onion_messenger
		.next_onion_message_for_peer(nodes[0].node.get_our_node_id())
		.unwrap();
	nodes[0]
		.onion_messenger
		.handle_onion_message(nodes[1].node.get_our_node_id(), &static_invoice_om);
	let mut async_pmts_msgs = AsyncPaymentsMessageHandler::release_pending_messages(nodes[0].node);
	assert!(!async_pmts_msgs.is_empty());
	assert!(async_pmts_msgs
		.iter()
		.all(|(msg, _)| matches!(msg, AsyncPaymentsMessage::HeldHtlcAvailable(_))));

	// Manually send the message and context releasing the HTLC since the recipient doesn't support
	// responding themselves yet.
	let held_htlc_avail_reply_path = match async_pmts_msgs.pop().unwrap().1 {
		MessageSendInstructions::WithSpecifiedReplyPath { reply_path, .. } => reply_path,
		_ => panic!(),
	};
	nodes[2]
		.onion_messenger
		.send_onion_message(
			ParsedOnionMessageContents::<Infallible>::AsyncPayments(
				AsyncPaymentsMessage::ReleaseHeldHtlc(ReleaseHeldHtlc {}),
			),
			MessageSendInstructions::WithoutReplyPath {
				destination: Destination::BlindedPath(held_htlc_avail_reply_path),
			},
		)
		.unwrap();

	let release_held_htlc_om = nodes[2]
		.onion_messenger
		.next_onion_message_for_peer(nodes[0].node.get_our_node_id())
		.unwrap();
	nodes[0]
		.onion_messenger
		.handle_onion_message(nodes[2].node.get_our_node_id(), &release_held_htlc_om);

	// Check that we've queued the HTLCs of the async keysend payment.
	let htlc_updates = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	assert_eq!(htlc_updates.update_add_htlcs.len(), 1);
	check_added_monitors!(nodes[0], 1);

	// Receiving a duplicate release_htlc message doesn't result in duplicate payment.
	nodes[0]
		.onion_messenger
		.handle_onion_message(nodes[2].node.get_our_node_id(), &release_held_htlc_om);
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
}
