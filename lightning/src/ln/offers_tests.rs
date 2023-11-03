// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Functional tests for the BOLT 12 Offers payment flow.
//!
//! [`ChannelManager`] provides utilities to create [`Offer`]s and [`Refund`]s along with utilities
//! to initiate and request payment for them, respectively. It also manages the payment flow via
//! implementing [`OffersMessageHandler`]. This module tests that functionality, including the
//! resulting [`Event`] generation.

use core::time::Duration;
use crate::blinded_path::BlindedPath;
use crate::events::{Event, MessageSendEventsProvider, PaymentPurpose};
use crate::ln::channelmanager::{PaymentId, RecentPaymentDetails, Retry};
use crate::ln::functional_test_utils::*;
use crate::ln::msgs::{OnionMessage, OnionMessageHandler};
use crate::offers::invoice::Bolt12Invoice;
use crate::offers::invoice_request::InvoiceRequest;
use crate::onion_message::messenger::PeeledOnion;
use crate::onion_message::offers::OffersMessage;
use crate::onion_message::packet::ParsedOnionMessageContents;

use crate::prelude::*;

macro_rules! expect_recent_payment {
	($node: expr, $payment_state: path, $payment_id: expr) => {
		match $node.node.list_recent_payments().first() {
			Some(&$payment_state { payment_id: actual_payment_id, .. }) => {
				assert_eq!($payment_id, actual_payment_id);
			},
			Some(_) => panic!("Unexpected recent payment state"),
			None => panic!("No recent payments"),
		}
	}
}

fn route_bolt12_payment<'a, 'b, 'c>(
	node: &Node<'a, 'b, 'c>, path: &[&Node<'a, 'b, 'c>], invoice: &Bolt12Invoice
) {
	// Monitor added when handling the invoice onion message.
	check_added_monitors(node, 1);

	let mut events = node.node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let ev = remove_first_msg_event_to_node(&path[0].node.get_our_node_id(), &mut events);

	// Use a fake payment_hash and bypass checking for the PaymentClaimable event since the
	// invoice contains the payment_hash but it was encrypted inside an onion message.
	let amount_msats = invoice.amount_msats();
	let payment_hash = invoice.payment_hash();
	do_pass_along_path(
		node, path, amount_msats, payment_hash, None, ev, false, false, None, false
	);
}

fn claim_bolt12_payment<'a, 'b, 'c>(node: &Node<'a, 'b, 'c>, path: &[&Node<'a, 'b, 'c>]) {
	let recipient = &path[path.len() - 1];
	match get_event!(recipient, Event::PaymentClaimable) {
		Event::PaymentClaimable {
			purpose: PaymentPurpose::InvoicePayment {
				payment_preimage: Some(payment_preimage), ..
			}, ..
		} => claim_payment(node, path, payment_preimage),
		_ => panic!(),
	};
}

fn extract_invoice_request<'a, 'b, 'c>(
	node: &Node<'a, 'b, 'c>, message: &OnionMessage
) -> (InvoiceRequest, Option<BlindedPath>) {
	match node.onion_messenger.peel_onion_message(message) {
		Ok(PeeledOnion::Receive(message, _, reply_path)) => match message {
			ParsedOnionMessageContents::Offers(offers_message) => match offers_message {
				OffersMessage::InvoiceRequest(invoice_request) => (invoice_request, reply_path),
				OffersMessage::Invoice(invoice) => panic!("Unexpected invoice: {:?}", invoice),
				OffersMessage::InvoiceError(error) => panic!("Unexpected invoice_error: {:?}", error),
			},
			ParsedOnionMessageContents::Custom(message) => panic!("Unexpected custom message: {:?}", message),
		},
		Ok(PeeledOnion::Forward(_, _)) => panic!("Unexpected onion message forward"),
		Err(e) => panic!("Failed to process onion message {:?}", e),
	}
}

fn extract_invoice<'a, 'b, 'c>(node: &Node<'a, 'b, 'c>, message: &OnionMessage) -> Bolt12Invoice {
	match node.onion_messenger.peel_onion_message(message) {
		Ok(PeeledOnion::Receive(message, _, _)) => match message {
			ParsedOnionMessageContents::Offers(offers_message) => match offers_message {
				OffersMessage::InvoiceRequest(invoice_request) => panic!("Unexpected invoice_request: {:?}", invoice_request),
				OffersMessage::Invoice(invoice) => invoice,
				OffersMessage::InvoiceError(error) => panic!("Unexpected invoice_error: {:?}", error),
			},
			ParsedOnionMessageContents::Custom(message) => panic!("Unexpected custom message: {:?}", message),
		},
		Ok(PeeledOnion::Forward(_, _)) => panic!("Unexpected onion message forward"),
		Err(e) => panic!("Failed to process onion message {:?}", e),
	}
}

/// Checks that an offer can be paid through a one-hop blinded path and that ephemeral pubkeys are
/// used rather than exposing a node's pubkey. However, the node's pubkey is still used as the
/// introduction node of the blinded path.
#[test]
fn creates_and_pays_for_offer_using_one_hop_blinded_path() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 10_000_000, 1_000_000_000);

	let alice = &nodes[0];
	let alice_id = alice.node.get_our_node_id();
	let bob = &nodes[1];
	let bob_id = bob.node.get_our_node_id();

	let offer = alice.node
		.create_offer_builder("coffee".to_string()).unwrap()
		.amount_msats(10_000_000)
		.build().unwrap();
	assert_ne!(offer.signing_pubkey(), alice_id);
	assert!(!offer.paths().is_empty());
	for path in offer.paths() {
		assert_eq!(path.introduction_node_id, alice_id);
	}

	let payment_id = PaymentId([1; 32]);
	bob.node.pay_for_offer(&offer, None, None, None, payment_id, Retry::Attempts(0), None).unwrap();
	expect_recent_payment!(bob, RecentPaymentDetails::AwaitingInvoice, payment_id);

	let onion_message = bob.onion_messenger.next_onion_message_for_peer(alice_id).unwrap();
	alice.onion_messenger.handle_onion_message(&bob_id, &onion_message);

	let (invoice_request, reply_path) = extract_invoice_request(alice, &onion_message);
	assert_eq!(invoice_request.amount_msats(), None);
	assert_ne!(invoice_request.payer_id(), bob_id);
	assert_eq!(reply_path.unwrap().introduction_node_id, bob_id);

	let onion_message = alice.onion_messenger.next_onion_message_for_peer(bob_id).unwrap();
	bob.onion_messenger.handle_onion_message(&alice_id, &onion_message);

	let invoice = extract_invoice(bob, &onion_message);
	assert_eq!(invoice.amount_msats(), 10_000_000);
	assert_ne!(invoice.signing_pubkey(), alice_id);
	assert!(!invoice.payment_paths().is_empty());
	for (_, path) in invoice.payment_paths() {
		assert_eq!(path.introduction_node_id, alice_id);
	}

	route_bolt12_payment(bob, &[alice], &invoice);
	expect_recent_payment!(bob, RecentPaymentDetails::Pending, payment_id);

	claim_bolt12_payment(bob, &[alice]);
	expect_recent_payment!(bob, RecentPaymentDetails::Fulfilled, payment_id);
}

/// Checks that a refund can be paid through a one-hop blinded path and that ephemeral pubkeys are
/// used rather than exposing a node's pubkey. However, the node's pubkey is still used as the
/// introduction node of the blinded path.
#[test]
fn creates_and_pays_for_refund_using_one_hop_blinded_path() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 10_000_000, 1_000_000_000);

	let alice = &nodes[0];
	let alice_id = alice.node.get_our_node_id();
	let bob = &nodes[1];
	let bob_id = bob.node.get_our_node_id();

	let absolute_expiry = Duration::from_secs(u64::MAX);
	let payment_id = PaymentId([1; 32]);
	let refund = bob.node
		.create_refund_builder(
			"refund".to_string(), 10_000_000, absolute_expiry, payment_id, Retry::Attempts(0), None
		)
		.unwrap()
		.build().unwrap();
	assert_eq!(refund.amount_msats(), 10_000_000);
	assert_eq!(refund.absolute_expiry(), Some(absolute_expiry));
	assert_ne!(refund.payer_id(), bob_id);
	assert!(!refund.paths().is_empty());
	for path in refund.paths() {
		assert_eq!(path.introduction_node_id, bob_id);
	}
	expect_recent_payment!(bob, RecentPaymentDetails::AwaitingInvoice, payment_id);

	alice.node.request_refund_payment(&refund).unwrap();

	let onion_message = alice.onion_messenger.next_onion_message_for_peer(bob_id).unwrap();
	bob.onion_messenger.handle_onion_message(&alice_id, &onion_message);

	let invoice = extract_invoice(bob, &onion_message);
	assert_eq!(invoice.amount_msats(), 10_000_000);
	assert_ne!(invoice.signing_pubkey(), alice_id);
	assert!(!invoice.payment_paths().is_empty());
	for (_, path) in invoice.payment_paths() {
		assert_eq!(path.introduction_node_id, alice_id);
	}

	route_bolt12_payment(bob, &[alice], &invoice);
	expect_recent_payment!(bob, RecentPaymentDetails::Pending, payment_id);

	claim_bolt12_payment(bob, &[alice]);
	expect_recent_payment!(bob, RecentPaymentDetails::Fulfilled, payment_id);
}

/// Checks that an invoice for an offer without any blinded paths can be requested. Note that while
/// the requested is sent directly using the node's pubkey, the response and the payment still use
/// blinded paths as required by the spec.
#[test]
fn pays_for_offer_without_blinded_paths() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 10_000_000, 1_000_000_000);

	let alice = &nodes[0];
	let alice_id = alice.node.get_our_node_id();
	let bob = &nodes[1];
	let bob_id = bob.node.get_our_node_id();

	let offer = alice.node
		.create_offer_builder("coffee".to_string()).unwrap()
		.clear_paths()
		.amount_msats(10_000_000)
		.build().unwrap();
	assert_eq!(offer.signing_pubkey(), alice_id);
	assert!(offer.paths().is_empty());

	let payment_id = PaymentId([1; 32]);
	bob.node.pay_for_offer(&offer, None, None, None, payment_id, Retry::Attempts(0), None).unwrap();
	expect_recent_payment!(bob, RecentPaymentDetails::AwaitingInvoice, payment_id);

	let onion_message = bob.onion_messenger.next_onion_message_for_peer(alice_id).unwrap();
	alice.onion_messenger.handle_onion_message(&bob_id, &onion_message);

	let onion_message = alice.onion_messenger.next_onion_message_for_peer(bob_id).unwrap();
	bob.onion_messenger.handle_onion_message(&alice_id, &onion_message);

	let invoice = extract_invoice(bob, &onion_message);
	route_bolt12_payment(bob, &[alice], &invoice);
	expect_recent_payment!(bob, RecentPaymentDetails::Pending, payment_id);

	claim_bolt12_payment(bob, &[alice]);
	expect_recent_payment!(bob, RecentPaymentDetails::Fulfilled, payment_id);
}

/// Checks that a refund without any blinded paths can be paid. Note that while the invoice is sent
/// directly using the node's pubkey, the payment still use blinded paths as required by the spec.
#[test]
fn pays_for_refund_without_blinded_paths() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 10_000_000, 1_000_000_000);

	let alice = &nodes[0];
	let alice_id = alice.node.get_our_node_id();
	let bob = &nodes[1];
	let bob_id = bob.node.get_our_node_id();

	let absolute_expiry = Duration::from_secs(u64::MAX);
	let payment_id = PaymentId([1; 32]);
	let refund = bob.node
		.create_refund_builder(
			"refund".to_string(), 10_000_000, absolute_expiry, payment_id, Retry::Attempts(0), None
		)
		.unwrap()
		.clear_paths()
		.build().unwrap();
	assert_eq!(refund.payer_id(), bob_id);
	assert!(refund.paths().is_empty());
	expect_recent_payment!(bob, RecentPaymentDetails::AwaitingInvoice, payment_id);

	alice.node.request_refund_payment(&refund).unwrap();

	let onion_message = alice.onion_messenger.next_onion_message_for_peer(bob_id).unwrap();
	bob.onion_messenger.handle_onion_message(&alice_id, &onion_message);

	let invoice = extract_invoice(bob, &onion_message);
	route_bolt12_payment(bob, &[alice], &invoice);
	expect_recent_payment!(bob, RecentPaymentDetails::Pending, payment_id);

	claim_bolt12_payment(bob, &[alice]);
	expect_recent_payment!(bob, RecentPaymentDetails::Fulfilled, payment_id);
}
