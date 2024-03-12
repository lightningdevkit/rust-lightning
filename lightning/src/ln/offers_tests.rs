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
//!
//! Two-node success tests use an announced channel:
//!
//! Alice --- Bob
//!
//! While two-node failure tests use an unannounced channel:
//!
//! Alice ... Bob
//!
//! Six-node tests use unannounced channels for the sender and recipient and announced channels for
//! the rest of the network.
//!
//!               nodes[4]
//!              /        \
//!             /          \
//!            /            \
//! Alice ... Bob -------- Charlie ... David
//!            \            /
//!             \          /
//!              \        /
//!               nodes[5]
//!
//! Unnamed nodes are needed to ensure unannounced nodes can create two-hop blinded paths.
//!
//! Nodes without channels are disconnected and connected as needed to ensure that deterministic
//! blinded paths are used.

use bitcoin::network::constants::Network;
use core::time::Duration;
use crate::blinded_path::{BlindedPath, IntroductionNode};
use crate::events::{Event, MessageSendEventsProvider, PaymentPurpose};
use crate::ln::channelmanager::{PaymentId, RecentPaymentDetails, Retry, self};
use crate::ln::functional_test_utils::*;
use crate::ln::msgs::{ChannelMessageHandler, Init, NodeAnnouncement, OnionMessage, OnionMessageHandler, RoutingMessageHandler, SocketAddress, UnsignedGossipMessage, UnsignedNodeAnnouncement};
use crate::offers::invoice::Bolt12Invoice;
use crate::offers::invoice_error::InvoiceError;
use crate::offers::invoice_request::InvoiceRequest;
use crate::offers::parse::Bolt12SemanticError;
use crate::onion_message::messenger::PeeledOnion;
use crate::onion_message::offers::OffersMessage;
use crate::onion_message::packet::ParsedOnionMessageContents;
use crate::routing::gossip::{NodeAlias, NodeId};
use crate::sign::{NodeSigner, Recipient};

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

fn connect_peers<'a, 'b, 'c>(node_a: &Node<'a, 'b, 'c>, node_b: &Node<'a, 'b, 'c>) {
	let node_id_a = node_a.node.get_our_node_id();
	let node_id_b = node_b.node.get_our_node_id();

	let init_a = Init {
		features: node_a.init_features(&node_id_b),
		networks: None,
		remote_network_address: None,
	};
	let init_b = Init {
		features: node_b.init_features(&node_id_a),
		networks: None,
		remote_network_address: None,
	};

	node_a.node.peer_connected(&node_id_b, &init_b, true).unwrap();
	node_b.node.peer_connected(&node_id_a, &init_a, false).unwrap();
	node_a.onion_messenger.peer_connected(&node_id_b, &init_b, true).unwrap();
	node_b.onion_messenger.peer_connected(&node_id_a, &init_a, false).unwrap();
}

fn disconnect_peers<'a, 'b, 'c>(node_a: &Node<'a, 'b, 'c>, peers: &[&Node<'a, 'b, 'c>]) {
	for node_b in peers {
		node_a.node.peer_disconnected(&node_b.node.get_our_node_id());
		node_b.node.peer_disconnected(&node_a.node.get_our_node_id());
		node_a.onion_messenger.peer_disconnected(&node_b.node.get_our_node_id());
		node_b.onion_messenger.peer_disconnected(&node_a.node.get_our_node_id());
	}
}

fn announce_node_address<'a, 'b, 'c>(
	node: &Node<'a, 'b, 'c>, peers: &[&Node<'a, 'b, 'c>], address: SocketAddress,
) {
	let features = node.onion_messenger.provided_node_features()
		| node.gossip_sync.provided_node_features();
	let rgb = [0u8; 3];
	let announcement = UnsignedNodeAnnouncement {
		features,
		timestamp: 1000,
		node_id: NodeId::from_pubkey(&node.keys_manager.get_node_id(Recipient::Node).unwrap()),
		rgb,
		alias: NodeAlias([0u8; 32]),
		addresses: vec![address],
		excess_address_data: Vec::new(),
		excess_data: Vec::new(),
	};
	let signature = node.keys_manager.sign_gossip_message(
		UnsignedGossipMessage::NodeAnnouncement(&announcement)
	).unwrap();

	let msg = NodeAnnouncement {
		signature,
		contents: announcement
	};

	node.gossip_sync.handle_node_announcement(&msg).unwrap();
	for peer in peers {
		peer.gossip_sync.handle_node_announcement(&msg).unwrap();
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
	let args = PassAlongPathArgs::new(node, path, amount_msats, payment_hash, ev)
		.without_clearing_recipient_events();
	do_pass_along_path(args);
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

fn extract_invoice_error<'a, 'b, 'c>(
	node: &Node<'a, 'b, 'c>, message: &OnionMessage
) -> InvoiceError {
	match node.onion_messenger.peel_onion_message(message) {
		Ok(PeeledOnion::Receive(message, _, _)) => match message {
			ParsedOnionMessageContents::Offers(offers_message) => match offers_message {
				OffersMessage::InvoiceRequest(invoice_request) => panic!("Unexpected invoice_request: {:?}", invoice_request),
				OffersMessage::Invoice(invoice) => panic!("Unexpected invoice: {:?}", invoice),
				OffersMessage::InvoiceError(error) => error,
			},
			ParsedOnionMessageContents::Custom(message) => panic!("Unexpected custom message: {:?}", message),
		},
		Ok(PeeledOnion::Forward(_, _)) => panic!("Unexpected onion message forward"),
		Err(e) => panic!("Failed to process onion message {:?}", e),
	}
}

/// Checks that blinded paths without Tor-only nodes are preferred when constructing an offer.
#[test]
fn prefers_non_tor_nodes_in_blinded_paths() {
	let mut accept_forward_cfg = test_default_channel_config();
	accept_forward_cfg.accept_forwards_to_priv_channels = true;

	let mut features = channelmanager::provided_init_features(&accept_forward_cfg);
	features.set_onion_messages_optional();
	features.set_route_blinding_optional();

	let chanmon_cfgs = create_chanmon_cfgs(6);
	let node_cfgs = create_node_cfgs(6, &chanmon_cfgs);

	*node_cfgs[1].override_init_features.borrow_mut() = Some(features);

	let node_chanmgrs = create_node_chanmgrs(
		6, &node_cfgs, &[None, Some(accept_forward_cfg), None, None, None, None]
	);
	let nodes = create_network(6, &node_cfgs, &node_chanmgrs);

	create_unannounced_chan_between_nodes_with_value(&nodes, 0, 1, 10_000_000, 1_000_000_000);
	create_unannounced_chan_between_nodes_with_value(&nodes, 2, 3, 10_000_000, 1_000_000_000);
	create_announced_chan_between_nodes_with_value(&nodes, 1, 2, 10_000_000, 1_000_000_000);
	create_announced_chan_between_nodes_with_value(&nodes, 1, 4, 10_000_000, 1_000_000_000);
	create_announced_chan_between_nodes_with_value(&nodes, 1, 5, 10_000_000, 1_000_000_000);
	create_announced_chan_between_nodes_with_value(&nodes, 2, 4, 10_000_000, 1_000_000_000);
	create_announced_chan_between_nodes_with_value(&nodes, 2, 5, 10_000_000, 1_000_000_000);

	// Add an extra channel so that more than one of Bob's peers have MIN_PEER_CHANNELS.
	create_announced_chan_between_nodes_with_value(&nodes, 4, 5, 10_000_000, 1_000_000_000);

	let (alice, bob, charlie, david) = (&nodes[0], &nodes[1], &nodes[2], &nodes[3]);
	let bob_id = bob.node.get_our_node_id();
	let charlie_id = charlie.node.get_our_node_id();

	disconnect_peers(alice, &[charlie, david, &nodes[4], &nodes[5]]);
	disconnect_peers(david, &[bob, &nodes[4], &nodes[5]]);

	let tor = SocketAddress::OnionV2([255, 254, 253, 252, 251, 250, 249, 248, 247, 246, 38, 7]);
	announce_node_address(charlie, &[alice, bob, david, &nodes[4], &nodes[5]], tor.clone());

	let offer = bob.node
		.create_offer_builder("coffee".to_string()).unwrap()
		.amount_msats(10_000_000)
		.build().unwrap();
	assert_ne!(offer.signing_pubkey(), bob_id);
	assert!(!offer.paths().is_empty());
	for path in offer.paths() {
		assert_ne!(path.introduction_node, IntroductionNode::NodeId(bob_id));
		assert_ne!(path.introduction_node, IntroductionNode::NodeId(charlie_id));
	}

	// Use a one-hop blinded path when Bob is announced and all his peers are Tor-only.
	announce_node_address(&nodes[4], &[alice, bob, charlie, david, &nodes[5]], tor.clone());
	announce_node_address(&nodes[5], &[alice, bob, charlie, david, &nodes[4]], tor.clone());

	let offer = bob.node
		.create_offer_builder("coffee".to_string()).unwrap()
		.amount_msats(10_000_000)
		.build().unwrap();
	assert_ne!(offer.signing_pubkey(), bob_id);
	assert!(!offer.paths().is_empty());
	for path in offer.paths() {
		assert_eq!(path.introduction_node, IntroductionNode::NodeId(bob_id));
	}
}

/// Checks that blinded paths prefer an introduction node that is the most connected.
#[test]
fn prefers_more_connected_nodes_in_blinded_paths() {
	let mut accept_forward_cfg = test_default_channel_config();
	accept_forward_cfg.accept_forwards_to_priv_channels = true;

	let mut features = channelmanager::provided_init_features(&accept_forward_cfg);
	features.set_onion_messages_optional();
	features.set_route_blinding_optional();

	let chanmon_cfgs = create_chanmon_cfgs(6);
	let node_cfgs = create_node_cfgs(6, &chanmon_cfgs);

	*node_cfgs[1].override_init_features.borrow_mut() = Some(features);

	let node_chanmgrs = create_node_chanmgrs(
		6, &node_cfgs, &[None, Some(accept_forward_cfg), None, None, None, None]
	);
	let nodes = create_network(6, &node_cfgs, &node_chanmgrs);

	create_unannounced_chan_between_nodes_with_value(&nodes, 0, 1, 10_000_000, 1_000_000_000);
	create_unannounced_chan_between_nodes_with_value(&nodes, 2, 3, 10_000_000, 1_000_000_000);
	create_announced_chan_between_nodes_with_value(&nodes, 1, 2, 10_000_000, 1_000_000_000);
	create_announced_chan_between_nodes_with_value(&nodes, 1, 4, 10_000_000, 1_000_000_000);
	create_announced_chan_between_nodes_with_value(&nodes, 1, 5, 10_000_000, 1_000_000_000);
	create_announced_chan_between_nodes_with_value(&nodes, 2, 4, 10_000_000, 1_000_000_000);
	create_announced_chan_between_nodes_with_value(&nodes, 2, 5, 10_000_000, 1_000_000_000);

	// Add extra channels so that more than one of Bob's peers have MIN_PEER_CHANNELS and one has
	// more than the others.
	create_announced_chan_between_nodes_with_value(&nodes, 0, 4, 10_000_000, 1_000_000_000);
	create_announced_chan_between_nodes_with_value(&nodes, 3, 4, 10_000_000, 1_000_000_000);

	let (alice, bob, charlie, david) = (&nodes[0], &nodes[1], &nodes[2], &nodes[3]);
	let bob_id = bob.node.get_our_node_id();

	disconnect_peers(alice, &[charlie, david, &nodes[4], &nodes[5]]);
	disconnect_peers(david, &[bob, &nodes[4], &nodes[5]]);

	let offer = bob.node
		.create_offer_builder("coffee".to_string()).unwrap()
		.amount_msats(10_000_000)
		.build().unwrap();
	assert_ne!(offer.signing_pubkey(), bob_id);
	assert!(!offer.paths().is_empty());
	for path in offer.paths() {
		assert_eq!(path.introduction_node, IntroductionNode::NodeId(nodes[4].node.get_our_node_id()));
	}
}

/// Checks that an offer can be paid through blinded paths and that ephemeral pubkeys are used
/// rather than exposing a node's pubkey.
#[test]
fn creates_and_pays_for_offer_using_two_hop_blinded_path() {
	let mut accept_forward_cfg = test_default_channel_config();
	accept_forward_cfg.accept_forwards_to_priv_channels = true;

	let mut features = channelmanager::provided_init_features(&accept_forward_cfg);
	features.set_onion_messages_optional();
	features.set_route_blinding_optional();

	let chanmon_cfgs = create_chanmon_cfgs(6);
	let node_cfgs = create_node_cfgs(6, &chanmon_cfgs);

	*node_cfgs[1].override_init_features.borrow_mut() = Some(features);

	let node_chanmgrs = create_node_chanmgrs(
		6, &node_cfgs, &[None, Some(accept_forward_cfg), None, None, None, None]
	);
	let nodes = create_network(6, &node_cfgs, &node_chanmgrs);

	create_unannounced_chan_between_nodes_with_value(&nodes, 0, 1, 10_000_000, 1_000_000_000);
	create_unannounced_chan_between_nodes_with_value(&nodes, 2, 3, 10_000_000, 1_000_000_000);
	create_announced_chan_between_nodes_with_value(&nodes, 1, 2, 10_000_000, 1_000_000_000);
	create_announced_chan_between_nodes_with_value(&nodes, 1, 4, 10_000_000, 1_000_000_000);
	create_announced_chan_between_nodes_with_value(&nodes, 1, 5, 10_000_000, 1_000_000_000);
	create_announced_chan_between_nodes_with_value(&nodes, 2, 4, 10_000_000, 1_000_000_000);
	create_announced_chan_between_nodes_with_value(&nodes, 2, 5, 10_000_000, 1_000_000_000);

	let (alice, bob, charlie, david) = (&nodes[0], &nodes[1], &nodes[2], &nodes[3]);
	let alice_id = alice.node.get_our_node_id();
	let bob_id = bob.node.get_our_node_id();
	let charlie_id = charlie.node.get_our_node_id();
	let david_id = david.node.get_our_node_id();

	disconnect_peers(alice, &[charlie, david, &nodes[4], &nodes[5]]);
	disconnect_peers(david, &[bob, &nodes[4], &nodes[5]]);

	let offer = alice.node
		.create_offer_builder("coffee".to_string()).unwrap()
		.amount_msats(10_000_000)
		.build().unwrap();
	assert_ne!(offer.signing_pubkey(), alice_id);
	assert!(!offer.paths().is_empty());
	for path in offer.paths() {
		assert_eq!(path.introduction_node, IntroductionNode::NodeId(bob_id));
	}

	let payment_id = PaymentId([1; 32]);
	david.node.pay_for_offer(&offer, None, None, None, payment_id, Retry::Attempts(0), None)
		.unwrap();
	expect_recent_payment!(david, RecentPaymentDetails::AwaitingInvoice, payment_id);

	connect_peers(david, bob);

	let onion_message = david.onion_messenger.next_onion_message_for_peer(bob_id).unwrap();
	bob.onion_messenger.handle_onion_message(&david_id, &onion_message);

	connect_peers(alice, charlie);

	let onion_message = bob.onion_messenger.next_onion_message_for_peer(alice_id).unwrap();
	alice.onion_messenger.handle_onion_message(&bob_id, &onion_message);

	let (invoice_request, reply_path) = extract_invoice_request(alice, &onion_message);
	assert_eq!(invoice_request.amount_msats(), None);
	assert_ne!(invoice_request.payer_id(), david_id);
	assert_eq!(reply_path.unwrap().introduction_node, IntroductionNode::NodeId(charlie_id));

	let onion_message = alice.onion_messenger.next_onion_message_for_peer(charlie_id).unwrap();
	charlie.onion_messenger.handle_onion_message(&alice_id, &onion_message);

	let onion_message = charlie.onion_messenger.next_onion_message_for_peer(david_id).unwrap();
	david.onion_messenger.handle_onion_message(&charlie_id, &onion_message);

	let invoice = extract_invoice(david, &onion_message);
	assert_eq!(invoice.amount_msats(), 10_000_000);
	assert_ne!(invoice.signing_pubkey(), alice_id);
	assert!(!invoice.payment_paths().is_empty());
	for (_, path) in invoice.payment_paths() {
		assert_eq!(path.introduction_node, IntroductionNode::NodeId(bob_id));
	}

	route_bolt12_payment(david, &[charlie, bob, alice], &invoice);
	expect_recent_payment!(david, RecentPaymentDetails::Pending, payment_id);

	claim_bolt12_payment(david, &[charlie, bob, alice]);
	expect_recent_payment!(david, RecentPaymentDetails::Fulfilled, payment_id);
}

/// Checks that a refund can be paid through blinded paths and that ephemeral pubkeys are used
/// rather than exposing a node's pubkey.
#[test]
fn creates_and_pays_for_refund_using_two_hop_blinded_path() {
	let mut accept_forward_cfg = test_default_channel_config();
	accept_forward_cfg.accept_forwards_to_priv_channels = true;

	let mut features = channelmanager::provided_init_features(&accept_forward_cfg);
	features.set_onion_messages_optional();
	features.set_route_blinding_optional();

	let chanmon_cfgs = create_chanmon_cfgs(6);
	let node_cfgs = create_node_cfgs(6, &chanmon_cfgs);

	*node_cfgs[1].override_init_features.borrow_mut() = Some(features);

	let node_chanmgrs = create_node_chanmgrs(
		6, &node_cfgs, &[None, Some(accept_forward_cfg), None, None, None, None]
	);
	let nodes = create_network(6, &node_cfgs, &node_chanmgrs);

	create_unannounced_chan_between_nodes_with_value(&nodes, 0, 1, 10_000_000, 1_000_000_000);
	create_unannounced_chan_between_nodes_with_value(&nodes, 2, 3, 10_000_000, 1_000_000_000);
	create_announced_chan_between_nodes_with_value(&nodes, 1, 2, 10_000_000, 1_000_000_000);
	create_announced_chan_between_nodes_with_value(&nodes, 1, 4, 10_000_000, 1_000_000_000);
	create_announced_chan_between_nodes_with_value(&nodes, 1, 5, 10_000_000, 1_000_000_000);
	create_announced_chan_between_nodes_with_value(&nodes, 2, 4, 10_000_000, 1_000_000_000);
	create_announced_chan_between_nodes_with_value(&nodes, 2, 5, 10_000_000, 1_000_000_000);

	let (alice, bob, charlie, david) = (&nodes[0], &nodes[1], &nodes[2], &nodes[3]);
	let alice_id = alice.node.get_our_node_id();
	let bob_id = bob.node.get_our_node_id();
	let charlie_id = charlie.node.get_our_node_id();
	let david_id = david.node.get_our_node_id();

	disconnect_peers(alice, &[charlie, david, &nodes[4], &nodes[5]]);
	disconnect_peers(david, &[bob, &nodes[4], &nodes[5]]);

	let absolute_expiry = Duration::from_secs(u64::MAX);
	let payment_id = PaymentId([1; 32]);
	let refund = david.node
		.create_refund_builder(
			"refund".to_string(), 10_000_000, absolute_expiry, payment_id, Retry::Attempts(0), None
		)
		.unwrap()
		.build().unwrap();
	assert_eq!(refund.amount_msats(), 10_000_000);
	assert_eq!(refund.absolute_expiry(), Some(absolute_expiry));
	assert_ne!(refund.payer_id(), david_id);
	assert!(!refund.paths().is_empty());
	for path in refund.paths() {
		assert_eq!(path.introduction_node, IntroductionNode::NodeId(charlie_id));
	}
	expect_recent_payment!(david, RecentPaymentDetails::AwaitingInvoice, payment_id);

	let expected_invoice = alice.node.request_refund_payment(&refund).unwrap();

	connect_peers(alice, charlie);

	let onion_message = alice.onion_messenger.next_onion_message_for_peer(charlie_id).unwrap();
	charlie.onion_messenger.handle_onion_message(&alice_id, &onion_message);

	let onion_message = charlie.onion_messenger.next_onion_message_for_peer(david_id).unwrap();
	david.onion_messenger.handle_onion_message(&charlie_id, &onion_message);

	let invoice = extract_invoice(david, &onion_message);
	assert_eq!(invoice, expected_invoice);

	assert_eq!(invoice.amount_msats(), 10_000_000);
	assert_ne!(invoice.signing_pubkey(), alice_id);
	assert!(!invoice.payment_paths().is_empty());
	for (_, path) in invoice.payment_paths() {
		assert_eq!(path.introduction_node, IntroductionNode::NodeId(bob_id));
	}

	route_bolt12_payment(david, &[charlie, bob, alice], &invoice);
	expect_recent_payment!(david, RecentPaymentDetails::Pending, payment_id);

	claim_bolt12_payment(david, &[charlie, bob, alice]);
	expect_recent_payment!(david, RecentPaymentDetails::Fulfilled, payment_id);
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
		assert_eq!(path.introduction_node, IntroductionNode::NodeId(alice_id));
	}

	let payment_id = PaymentId([1; 32]);
	bob.node.pay_for_offer(&offer, None, None, None, payment_id, Retry::Attempts(0), None).unwrap();
	expect_recent_payment!(bob, RecentPaymentDetails::AwaitingInvoice, payment_id);

	let onion_message = bob.onion_messenger.next_onion_message_for_peer(alice_id).unwrap();
	alice.onion_messenger.handle_onion_message(&bob_id, &onion_message);

	let (invoice_request, reply_path) = extract_invoice_request(alice, &onion_message);
	assert_eq!(invoice_request.amount_msats(), None);
	assert_ne!(invoice_request.payer_id(), bob_id);
	assert_eq!(reply_path.unwrap().introduction_node, IntroductionNode::NodeId(bob_id));

	let onion_message = alice.onion_messenger.next_onion_message_for_peer(bob_id).unwrap();
	bob.onion_messenger.handle_onion_message(&alice_id, &onion_message);

	let invoice = extract_invoice(bob, &onion_message);
	assert_eq!(invoice.amount_msats(), 10_000_000);
	assert_ne!(invoice.signing_pubkey(), alice_id);
	assert!(!invoice.payment_paths().is_empty());
	for (_, path) in invoice.payment_paths() {
		assert_eq!(path.introduction_node, IntroductionNode::NodeId(alice_id));
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
		assert_eq!(path.introduction_node, IntroductionNode::NodeId(bob_id));
	}
	expect_recent_payment!(bob, RecentPaymentDetails::AwaitingInvoice, payment_id);

	let expected_invoice = alice.node.request_refund_payment(&refund).unwrap();

	let onion_message = alice.onion_messenger.next_onion_message_for_peer(bob_id).unwrap();
	bob.onion_messenger.handle_onion_message(&alice_id, &onion_message);

	let invoice = extract_invoice(bob, &onion_message);
	assert_eq!(invoice, expected_invoice);

	assert_eq!(invoice.amount_msats(), 10_000_000);
	assert_ne!(invoice.signing_pubkey(), alice_id);
	assert!(!invoice.payment_paths().is_empty());
	for (_, path) in invoice.payment_paths() {
		assert_eq!(path.introduction_node, IntroductionNode::NodeId(alice_id));
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

	let expected_invoice = alice.node.request_refund_payment(&refund).unwrap();

	let onion_message = alice.onion_messenger.next_onion_message_for_peer(bob_id).unwrap();
	bob.onion_messenger.handle_onion_message(&alice_id, &onion_message);

	let invoice = extract_invoice(bob, &onion_message);
	assert_eq!(invoice, expected_invoice);

	route_bolt12_payment(bob, &[alice], &invoice);
	expect_recent_payment!(bob, RecentPaymentDetails::Pending, payment_id);

	claim_bolt12_payment(bob, &[alice]);
	expect_recent_payment!(bob, RecentPaymentDetails::Fulfilled, payment_id);
}

/// Fails creating an offer when a blinded path cannot be created without exposing the node's id.
#[test]
fn fails_creating_offer_without_blinded_paths() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	create_unannounced_chan_between_nodes_with_value(&nodes, 0, 1, 10_000_000, 1_000_000_000);

	match nodes[0].node.create_offer_builder("coffee".to_string()) {
		Ok(_) => panic!("Expected error"),
		Err(e) => assert_eq!(e, Bolt12SemanticError::MissingPaths),
	}
}

/// Fails creating a refund when a blinded path cannot be created without exposing the node's id.
#[test]
fn fails_creating_refund_without_blinded_paths() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	create_unannounced_chan_between_nodes_with_value(&nodes, 0, 1, 10_000_000, 1_000_000_000);

	let absolute_expiry = Duration::from_secs(u64::MAX);
	let payment_id = PaymentId([1; 32]);

	match nodes[0].node.create_refund_builder(
		"refund".to_string(), 10_000, absolute_expiry, payment_id, Retry::Attempts(0), None
	) {
		Ok(_) => panic!("Expected error"),
		Err(e) => assert_eq!(e, Bolt12SemanticError::MissingPaths),
	}

	assert!(nodes[0].node.list_recent_payments().is_empty());
}

/// Fails creating an invoice request when the offer contains an unsupported chain.
#[test]
fn fails_creating_invoice_request_for_unsupported_chain() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 10_000_000, 1_000_000_000);

	let alice = &nodes[0];
	let bob = &nodes[1];

	let offer = alice.node
		.create_offer_builder("coffee".to_string()).unwrap()
		.clear_chains()
		.chain(Network::Signet)
		.build().unwrap();

	let payment_id = PaymentId([1; 32]);
	match bob.node.pay_for_offer(&offer, None, None, None, payment_id, Retry::Attempts(0), None) {
		Ok(_) => panic!("Expected error"),
		Err(e) => assert_eq!(e, Bolt12SemanticError::UnsupportedChain),
	}
}

/// Fails requesting a payment when the refund contains an unsupported chain.
#[test]
fn fails_sending_invoice_with_unsupported_chain_for_refund() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 10_000_000, 1_000_000_000);

	let alice = &nodes[0];
	let bob = &nodes[1];

	let absolute_expiry = Duration::from_secs(u64::MAX);
	let payment_id = PaymentId([1; 32]);
	let refund = bob.node
		.create_refund_builder(
			"refund".to_string(), 10_000_000, absolute_expiry, payment_id, Retry::Attempts(0), None
		)
		.unwrap()
		.chain(Network::Signet)
		.build().unwrap();

	match alice.node.request_refund_payment(&refund) {
		Ok(_) => panic!("Expected error"),
		Err(e) => assert_eq!(e, Bolt12SemanticError::UnsupportedChain),
	}
}

/// Fails creating an invoice request when a blinded reply path cannot be created without exposing
/// the node's id.
#[test]
fn fails_creating_invoice_request_without_blinded_reply_path() {
	let chanmon_cfgs = create_chanmon_cfgs(6);
	let node_cfgs = create_node_cfgs(6, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(6, &node_cfgs, &[None, None, None, None, None, None]);
	let nodes = create_network(6, &node_cfgs, &node_chanmgrs);

	create_unannounced_chan_between_nodes_with_value(&nodes, 0, 1, 10_000_000, 1_000_000_000);
	create_unannounced_chan_between_nodes_with_value(&nodes, 2, 3, 10_000_000, 1_000_000_000);
	create_announced_chan_between_nodes_with_value(&nodes, 1, 2, 10_000_000, 1_000_000_000);
	create_announced_chan_between_nodes_with_value(&nodes, 1, 4, 10_000_000, 1_000_000_000);
	create_announced_chan_between_nodes_with_value(&nodes, 1, 5, 10_000_000, 1_000_000_000);

	let (alice, bob, charlie, david) = (&nodes[0], &nodes[1], &nodes[2], &nodes[3]);

	disconnect_peers(alice, &[charlie, david, &nodes[4], &nodes[5]]);
	disconnect_peers(david, &[bob, &nodes[4], &nodes[5]]);

	let offer = alice.node
		.create_offer_builder("coffee".to_string()).unwrap()
		.amount_msats(10_000_000)
		.build().unwrap();

	let payment_id = PaymentId([1; 32]);

	match david.node.pay_for_offer(&offer, None, None, None, payment_id, Retry::Attempts(0), None) {
		Ok(_) => panic!("Expected error"),
		Err(e) => assert_eq!(e, Bolt12SemanticError::MissingPaths),
	}

	assert!(nodes[0].node.list_recent_payments().is_empty());
}

#[test]
fn fails_creating_invoice_request_with_duplicate_payment_id() {
	let chanmon_cfgs = create_chanmon_cfgs(6);
	let node_cfgs = create_node_cfgs(6, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(6, &node_cfgs, &[None, None, None, None, None, None]);
	let nodes = create_network(6, &node_cfgs, &node_chanmgrs);

	create_unannounced_chan_between_nodes_with_value(&nodes, 0, 1, 10_000_000, 1_000_000_000);
	create_unannounced_chan_between_nodes_with_value(&nodes, 2, 3, 10_000_000, 1_000_000_000);
	create_announced_chan_between_nodes_with_value(&nodes, 1, 2, 10_000_000, 1_000_000_000);
	create_announced_chan_between_nodes_with_value(&nodes, 1, 4, 10_000_000, 1_000_000_000);
	create_announced_chan_between_nodes_with_value(&nodes, 1, 5, 10_000_000, 1_000_000_000);
	create_announced_chan_between_nodes_with_value(&nodes, 2, 4, 10_000_000, 1_000_000_000);
	create_announced_chan_between_nodes_with_value(&nodes, 2, 5, 10_000_000, 1_000_000_000);

	let (alice, _bob, charlie, david) = (&nodes[0], &nodes[1], &nodes[2], &nodes[3]);

	disconnect_peers(alice, &[charlie, david, &nodes[4], &nodes[5]]);

	let offer = alice.node
		.create_offer_builder("coffee".to_string()).unwrap()
		.amount_msats(10_000_000)
		.build().unwrap();

	let payment_id = PaymentId([1; 32]);
	assert!(
		david.node.pay_for_offer(
			&offer, None, None, None, payment_id, Retry::Attempts(0), None
		).is_ok()
	);
	expect_recent_payment!(david, RecentPaymentDetails::AwaitingInvoice, payment_id);

	match david.node.pay_for_offer(&offer, None, None, None, payment_id, Retry::Attempts(0), None) {
		Ok(_) => panic!("Expected error"),
		Err(e) => assert_eq!(e, Bolt12SemanticError::DuplicatePaymentId),
	}

	expect_recent_payment!(david, RecentPaymentDetails::AwaitingInvoice, payment_id);
}

#[test]
fn fails_creating_refund_with_duplicate_payment_id() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 10_000_000, 1_000_000_000);

	let absolute_expiry = Duration::from_secs(u64::MAX);
	let payment_id = PaymentId([1; 32]);
	assert!(
		nodes[0].node.create_refund_builder(
			"refund".to_string(), 10_000, absolute_expiry, payment_id, Retry::Attempts(0), None
		).is_ok()
	);
	expect_recent_payment!(nodes[0], RecentPaymentDetails::AwaitingInvoice, payment_id);

	match nodes[0].node.create_refund_builder(
		"refund".to_string(), 10_000, absolute_expiry, payment_id, Retry::Attempts(0), None
	) {
		Ok(_) => panic!("Expected error"),
		Err(e) => assert_eq!(e, Bolt12SemanticError::DuplicatePaymentId),
	}

	expect_recent_payment!(nodes[0], RecentPaymentDetails::AwaitingInvoice, payment_id);
}

#[test]
fn fails_sending_invoice_without_blinded_payment_paths_for_offer() {
	let mut accept_forward_cfg = test_default_channel_config();
	accept_forward_cfg.accept_forwards_to_priv_channels = true;

	// Clearing route_blinding prevents forming any payment paths since the node is unannounced.
	let mut features = channelmanager::provided_init_features(&accept_forward_cfg);
	features.set_onion_messages_optional();
	features.clear_route_blinding();

	let chanmon_cfgs = create_chanmon_cfgs(6);
	let node_cfgs = create_node_cfgs(6, &chanmon_cfgs);

	*node_cfgs[1].override_init_features.borrow_mut() = Some(features);

	let node_chanmgrs = create_node_chanmgrs(
		6, &node_cfgs, &[None, Some(accept_forward_cfg), None, None, None, None]
	);
	let nodes = create_network(6, &node_cfgs, &node_chanmgrs);

	create_unannounced_chan_between_nodes_with_value(&nodes, 0, 1, 10_000_000, 1_000_000_000);
	create_unannounced_chan_between_nodes_with_value(&nodes, 2, 3, 10_000_000, 1_000_000_000);
	create_announced_chan_between_nodes_with_value(&nodes, 1, 2, 10_000_000, 1_000_000_000);
	create_announced_chan_between_nodes_with_value(&nodes, 1, 4, 10_000_000, 1_000_000_000);
	create_announced_chan_between_nodes_with_value(&nodes, 1, 5, 10_000_000, 1_000_000_000);
	create_announced_chan_between_nodes_with_value(&nodes, 2, 4, 10_000_000, 1_000_000_000);
	create_announced_chan_between_nodes_with_value(&nodes, 2, 5, 10_000_000, 1_000_000_000);

	let (alice, bob, charlie, david) = (&nodes[0], &nodes[1], &nodes[2], &nodes[3]);
	let alice_id = alice.node.get_our_node_id();
	let bob_id = bob.node.get_our_node_id();
	let charlie_id = charlie.node.get_our_node_id();
	let david_id = david.node.get_our_node_id();

	disconnect_peers(alice, &[charlie, david, &nodes[4], &nodes[5]]);
	disconnect_peers(david, &[bob, &nodes[4], &nodes[5]]);

	let offer = alice.node
		.create_offer_builder("coffee".to_string()).unwrap()
		.amount_msats(10_000_000)
		.build().unwrap();

	let payment_id = PaymentId([1; 32]);
	david.node.pay_for_offer(&offer, None, None, None, payment_id, Retry::Attempts(0), None)
		.unwrap();

	connect_peers(david, bob);

	let onion_message = david.onion_messenger.next_onion_message_for_peer(bob_id).unwrap();
	bob.onion_messenger.handle_onion_message(&david_id, &onion_message);

	connect_peers(alice, charlie);

	let onion_message = bob.onion_messenger.next_onion_message_for_peer(alice_id).unwrap();
	alice.onion_messenger.handle_onion_message(&bob_id, &onion_message);

	let onion_message = alice.onion_messenger.next_onion_message_for_peer(charlie_id).unwrap();
	charlie.onion_messenger.handle_onion_message(&alice_id, &onion_message);

	let onion_message = charlie.onion_messenger.next_onion_message_for_peer(david_id).unwrap();
	david.onion_messenger.handle_onion_message(&charlie_id, &onion_message);

	let invoice_error = extract_invoice_error(david, &onion_message);
	assert_eq!(invoice_error, InvoiceError::from(Bolt12SemanticError::MissingPaths));
}

#[test]
fn fails_sending_invoice_without_blinded_payment_paths_for_refund() {
	let mut accept_forward_cfg = test_default_channel_config();
	accept_forward_cfg.accept_forwards_to_priv_channels = true;

	// Clearing route_blinding prevents forming any payment paths since the node is unannounced.
	let mut features = channelmanager::provided_init_features(&accept_forward_cfg);
	features.set_onion_messages_optional();
	features.clear_route_blinding();

	let chanmon_cfgs = create_chanmon_cfgs(6);
	let node_cfgs = create_node_cfgs(6, &chanmon_cfgs);

	*node_cfgs[1].override_init_features.borrow_mut() = Some(features);

	let node_chanmgrs = create_node_chanmgrs(
		6, &node_cfgs, &[None, Some(accept_forward_cfg), None, None, None, None]
	);
	let nodes = create_network(6, &node_cfgs, &node_chanmgrs);

	create_unannounced_chan_between_nodes_with_value(&nodes, 0, 1, 10_000_000, 1_000_000_000);
	create_unannounced_chan_between_nodes_with_value(&nodes, 2, 3, 10_000_000, 1_000_000_000);
	create_announced_chan_between_nodes_with_value(&nodes, 1, 2, 10_000_000, 1_000_000_000);
	create_announced_chan_between_nodes_with_value(&nodes, 1, 4, 10_000_000, 1_000_000_000);
	create_announced_chan_between_nodes_with_value(&nodes, 1, 5, 10_000_000, 1_000_000_000);
	create_announced_chan_between_nodes_with_value(&nodes, 2, 4, 10_000_000, 1_000_000_000);
	create_announced_chan_between_nodes_with_value(&nodes, 2, 5, 10_000_000, 1_000_000_000);

	let (alice, bob, charlie, david) = (&nodes[0], &nodes[1], &nodes[2], &nodes[3]);

	disconnect_peers(alice, &[charlie, david, &nodes[4], &nodes[5]]);
	disconnect_peers(david, &[bob, &nodes[4], &nodes[5]]);

	let absolute_expiry = Duration::from_secs(u64::MAX);
	let payment_id = PaymentId([1; 32]);
	let refund = david.node
		.create_refund_builder(
			"refund".to_string(), 10_000_000, absolute_expiry, payment_id, Retry::Attempts(0), None
		)
		.unwrap()
		.build().unwrap();

	match alice.node.request_refund_payment(&refund) {
		Ok(_) => panic!("Expected error"),
		Err(e) => assert_eq!(e, Bolt12SemanticError::MissingPaths),
	}
}

#[test]
fn fails_paying_invoice_more_than_once() {
	let mut accept_forward_cfg = test_default_channel_config();
	accept_forward_cfg.accept_forwards_to_priv_channels = true;

	let mut features = channelmanager::provided_init_features(&accept_forward_cfg);
	features.set_onion_messages_optional();
	features.set_route_blinding_optional();

	let chanmon_cfgs = create_chanmon_cfgs(6);
	let node_cfgs = create_node_cfgs(6, &chanmon_cfgs);

	*node_cfgs[1].override_init_features.borrow_mut() = Some(features);

	let node_chanmgrs = create_node_chanmgrs(
		6, &node_cfgs, &[None, Some(accept_forward_cfg), None, None, None, None]
	);
	let nodes = create_network(6, &node_cfgs, &node_chanmgrs);

	create_unannounced_chan_between_nodes_with_value(&nodes, 0, 1, 10_000_000, 1_000_000_000);
	create_unannounced_chan_between_nodes_with_value(&nodes, 2, 3, 10_000_000, 1_000_000_000);
	create_announced_chan_between_nodes_with_value(&nodes, 1, 2, 10_000_000, 1_000_000_000);
	create_announced_chan_between_nodes_with_value(&nodes, 1, 4, 10_000_000, 1_000_000_000);
	create_announced_chan_between_nodes_with_value(&nodes, 1, 5, 10_000_000, 1_000_000_000);
	create_announced_chan_between_nodes_with_value(&nodes, 2, 4, 10_000_000, 1_000_000_000);
	create_announced_chan_between_nodes_with_value(&nodes, 2, 5, 10_000_000, 1_000_000_000);

	let (alice, bob, charlie, david) = (&nodes[0], &nodes[1], &nodes[2], &nodes[3]);
	let alice_id = alice.node.get_our_node_id();
	let bob_id = bob.node.get_our_node_id();
	let charlie_id = charlie.node.get_our_node_id();
	let david_id = david.node.get_our_node_id();

	disconnect_peers(alice, &[charlie, david, &nodes[4], &nodes[5]]);
	disconnect_peers(david, &[bob, &nodes[4], &nodes[5]]);

	let absolute_expiry = Duration::from_secs(u64::MAX);
	let payment_id = PaymentId([1; 32]);
	let refund = david.node
		.create_refund_builder(
			"refund".to_string(), 10_000_000, absolute_expiry, payment_id, Retry::Attempts(0), None
		)
		.unwrap()
		.build().unwrap();
	expect_recent_payment!(david, RecentPaymentDetails::AwaitingInvoice, payment_id);

	// Alice sends the first invoice
	alice.node.request_refund_payment(&refund).unwrap();

	connect_peers(alice, charlie);

	let onion_message = alice.onion_messenger.next_onion_message_for_peer(charlie_id).unwrap();
	charlie.onion_messenger.handle_onion_message(&alice_id, &onion_message);

	let onion_message = charlie.onion_messenger.next_onion_message_for_peer(david_id).unwrap();
	david.onion_messenger.handle_onion_message(&charlie_id, &onion_message);

	// David pays the first invoice
	let invoice1 = extract_invoice(david, &onion_message);

	route_bolt12_payment(david, &[charlie, bob, alice], &invoice1);
	expect_recent_payment!(david, RecentPaymentDetails::Pending, payment_id);

	claim_bolt12_payment(david, &[charlie, bob, alice]);
	expect_recent_payment!(david, RecentPaymentDetails::Fulfilled, payment_id);

	disconnect_peers(alice, &[charlie]);

	// Alice sends the second invoice
	alice.node.request_refund_payment(&refund).unwrap();

	connect_peers(alice, charlie);
	connect_peers(david, bob);

	let onion_message = alice.onion_messenger.next_onion_message_for_peer(charlie_id).unwrap();
	charlie.onion_messenger.handle_onion_message(&alice_id, &onion_message);

	let onion_message = charlie.onion_messenger.next_onion_message_for_peer(david_id).unwrap();
	david.onion_messenger.handle_onion_message(&charlie_id, &onion_message);

	let invoice2 = extract_invoice(david, &onion_message);
	assert_eq!(invoice1.payer_metadata(), invoice2.payer_metadata());

	// David sends an error instead of paying the second invoice
	let onion_message = david.onion_messenger.next_onion_message_for_peer(bob_id).unwrap();
	bob.onion_messenger.handle_onion_message(&david_id, &onion_message);

	let onion_message = bob.onion_messenger.next_onion_message_for_peer(alice_id).unwrap();
	alice.onion_messenger.handle_onion_message(&bob_id, &onion_message);

	let invoice_error = extract_invoice_error(alice, &onion_message);
	assert_eq!(invoice_error, InvoiceError::from_string("DuplicateInvoice".to_string()));
}
