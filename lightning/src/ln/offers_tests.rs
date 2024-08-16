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

use bitcoin::network::Network;
use bitcoin::secp256k1::{PublicKey, Secp256k1};
use core::time::Duration;
use crate::blinded_path::IntroductionNode;
use crate::blinded_path::message::BlindedMessagePath;
use crate::blinded_path::payment::{Bolt12OfferContext, Bolt12RefundContext, PaymentContext};
use crate::blinded_path::message::{MessageContext, OffersContext};
use crate::events::{Event, MessageSendEventsProvider, PaymentFailureReason, PaymentPurpose};
use crate::ln::channelmanager::{Bolt12PaymentError, MAX_SHORT_LIVED_RELATIVE_EXPIRY, PaymentId, RecentPaymentDetails, Retry, self};
use crate::ln::features::Bolt12InvoiceFeatures;
use crate::ln::functional_test_utils::*;
use crate::ln::inbound_payment::ExpandedKey;
use crate::ln::msgs::{ChannelMessageHandler, Init, NodeAnnouncement, OnionMessage, OnionMessageHandler, RoutingMessageHandler, SocketAddress, UnsignedGossipMessage, UnsignedNodeAnnouncement};
use crate::ln::outbound_payment::IDEMPOTENCY_TIMEOUT_TICKS;
use crate::offers::invoice::Bolt12Invoice;
use crate::offers::invoice_error::InvoiceError;
use crate::offers::invoice_request::{InvoiceRequest, InvoiceRequestFields};
use crate::offers::nonce::Nonce;
use crate::offers::parse::Bolt12SemanticError;
use crate::onion_message::messenger::{Destination, PeeledOnion, new_pending_onion_message};
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

fn resolve_introduction_node<'a, 'b, 'c>(node: &Node<'a, 'b, 'c>, path: &BlindedMessagePath) -> PublicKey {
	path.public_introduction_node_id(&node.network_graph.read_only())
		.and_then(|node_id| node_id.as_pubkey().ok())
		.unwrap()
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

fn claim_bolt12_payment<'a, 'b, 'c>(
	node: &Node<'a, 'b, 'c>, path: &[&Node<'a, 'b, 'c>], expected_payment_context: PaymentContext
) {
	let recipient = &path[path.len() - 1];
	let payment_purpose = match get_event!(recipient, Event::PaymentClaimable) {
		Event::PaymentClaimable { purpose, .. } => purpose,
		_ => panic!("No Event::PaymentClaimable"),
	};
	let payment_preimage = match payment_purpose.preimage() {
		Some(preimage) => preimage,
		None => panic!("No preimage in Event::PaymentClaimable"),
	};
	match payment_purpose {
		PaymentPurpose::Bolt12OfferPayment { payment_context, .. } => {
			assert_eq!(PaymentContext::Bolt12Offer(payment_context), expected_payment_context);
		},
		PaymentPurpose::Bolt12RefundPayment { payment_context, .. } => {
			assert_eq!(PaymentContext::Bolt12Refund(payment_context), expected_payment_context);
		},
		_ => panic!("Unexpected payment purpose: {:?}", payment_purpose),
	}
	claim_payment(node, path, payment_preimage);
}

fn extract_offer_nonce<'a, 'b, 'c>(node: &Node<'a, 'b, 'c>, message: &OnionMessage) -> Nonce {
	match node.onion_messenger.peel_onion_message(message) {
		Ok(PeeledOnion::Receive(_, Some(MessageContext::Offers(OffersContext::InvoiceRequest { nonce })), _)) => nonce,
		Ok(PeeledOnion::Receive(_, context, _)) => panic!("Unexpected onion message context: {:?}", context),
		Ok(PeeledOnion::Forward(_, _)) => panic!("Unexpected onion message forward"),
		Err(e) => panic!("Failed to process onion message {:?}", e),
	}
}

fn extract_invoice_request<'a, 'b, 'c>(
	node: &Node<'a, 'b, 'c>, message: &OnionMessage
) -> (InvoiceRequest, BlindedMessagePath) {
	match node.onion_messenger.peel_onion_message(message) {
		Ok(PeeledOnion::Receive(message, _, reply_path)) => match message {
			ParsedOnionMessageContents::Offers(offers_message) => match offers_message {
				OffersMessage::InvoiceRequest(invoice_request) => (invoice_request, reply_path.unwrap()),
				OffersMessage::Invoice(invoice) => panic!("Unexpected invoice: {:?}", invoice),
				#[cfg(async_payments)]
				OffersMessage::StaticInvoice(invoice) => panic!("Unexpected static invoice: {:?}", invoice),
				OffersMessage::InvoiceError(error) => panic!("Unexpected invoice_error: {:?}", error),
			},
			#[cfg(async_payments)]
			ParsedOnionMessageContents::AsyncPayments(message) => panic!("Unexpected async payments message: {:?}", message),
			ParsedOnionMessageContents::Custom(message) => panic!("Unexpected custom message: {:?}", message),
		},
		Ok(PeeledOnion::Forward(_, _)) => panic!("Unexpected onion message forward"),
		Err(e) => panic!("Failed to process onion message {:?}", e),
	}
}

fn extract_invoice<'a, 'b, 'c>(node: &Node<'a, 'b, 'c>, message: &OnionMessage) -> (Bolt12Invoice, Option<BlindedMessagePath>) {
	match node.onion_messenger.peel_onion_message(message) {
		Ok(PeeledOnion::Receive(message, _, reply_path)) => match message {
			ParsedOnionMessageContents::Offers(offers_message) => match offers_message {
				OffersMessage::InvoiceRequest(invoice_request) => panic!("Unexpected invoice_request: {:?}", invoice_request),
				OffersMessage::Invoice(invoice) => (invoice, reply_path),
				#[cfg(async_payments)]
				OffersMessage::StaticInvoice(invoice) => panic!("Unexpected static invoice: {:?}", invoice),
				OffersMessage::InvoiceError(error) => panic!("Unexpected invoice_error: {:?}", error),
			},
			#[cfg(async_payments)]
			ParsedOnionMessageContents::AsyncPayments(message) => panic!("Unexpected async payments message: {:?}", message),
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
				#[cfg(async_payments)]
				OffersMessage::StaticInvoice(invoice) => panic!("Unexpected invoice: {:?}", invoice),
				OffersMessage::InvoiceError(error) => error,
			},
			#[cfg(async_payments)]
			ParsedOnionMessageContents::AsyncPayments(message) => panic!("Unexpected async payments message: {:?}", message),
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
		.create_offer_builder(None).unwrap()
		.amount_msats(10_000_000)
		.build().unwrap();
	assert_ne!(offer.signing_pubkey(), Some(bob_id));
	assert!(!offer.paths().is_empty());
	for path in offer.paths() {
		let introduction_node_id = resolve_introduction_node(david, &path);
		assert_ne!(introduction_node_id, bob_id);
		assert_ne!(introduction_node_id, charlie_id);
	}

	// Use a one-hop blinded path when Bob is announced and all his peers are Tor-only.
	announce_node_address(&nodes[4], &[alice, bob, charlie, david, &nodes[5]], tor.clone());
	announce_node_address(&nodes[5], &[alice, bob, charlie, david, &nodes[4]], tor.clone());

	let offer = bob.node
		.create_offer_builder(None).unwrap()
		.amount_msats(10_000_000)
		.build().unwrap();
	assert_ne!(offer.signing_pubkey(), Some(bob_id));
	assert!(!offer.paths().is_empty());
	for path in offer.paths() {
		let introduction_node_id = resolve_introduction_node(david, &path);
		assert_eq!(introduction_node_id, bob_id);
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
		.create_offer_builder(None).unwrap()
		.amount_msats(10_000_000)
		.build().unwrap();
	assert_ne!(offer.signing_pubkey(), Some(bob_id));
	assert!(!offer.paths().is_empty());
	for path in offer.paths() {
		let introduction_node_id = resolve_introduction_node(david, &path);
		assert_eq!(introduction_node_id, nodes[4].node.get_our_node_id());
	}
}

/// Checks that blinded paths are compact for short-lived offers.
#[test]
fn creates_short_lived_offer() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 10_000_000, 1_000_000_000);

	let alice = &nodes[0];
	let alice_id = alice.node.get_our_node_id();
	let bob = &nodes[1];

	let absolute_expiry = alice.node.duration_since_epoch() + MAX_SHORT_LIVED_RELATIVE_EXPIRY;
	let offer = alice.node
		.create_offer_builder(Some(absolute_expiry)).unwrap()
		.build().unwrap();
	assert_eq!(offer.absolute_expiry(), Some(absolute_expiry));
	assert!(!offer.paths().is_empty());
	for path in offer.paths() {
		let introduction_node_id = resolve_introduction_node(bob, &path);
		assert_eq!(introduction_node_id, alice_id);
		assert!(matches!(path.introduction_node(), &IntroductionNode::DirectedShortChannelId(..)));
	}
}

/// Checks that blinded paths are not compact for long-lived offers.
#[test]
fn creates_long_lived_offer() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 10_000_000, 1_000_000_000);

	let alice = &nodes[0];
	let alice_id = alice.node.get_our_node_id();

	let absolute_expiry = alice.node.duration_since_epoch() + MAX_SHORT_LIVED_RELATIVE_EXPIRY
		+ Duration::from_secs(1);
	let offer = alice.node
		.create_offer_builder(Some(absolute_expiry))
		.unwrap()
		.build().unwrap();
	assert_eq!(offer.absolute_expiry(), Some(absolute_expiry));
	assert!(!offer.paths().is_empty());
	for path in offer.paths() {
		assert_eq!(path.introduction_node(), &IntroductionNode::NodeId(alice_id));
	}

	let offer = alice.node
		.create_offer_builder(None).unwrap()
		.build().unwrap();
	assert_eq!(offer.absolute_expiry(), None);
	assert!(!offer.paths().is_empty());
	for path in offer.paths() {
		assert_eq!(path.introduction_node(), &IntroductionNode::NodeId(alice_id));
	}
}

/// Checks that blinded paths are compact for short-lived refunds.
#[test]
fn creates_short_lived_refund() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 10_000_000, 1_000_000_000);

	let alice = &nodes[0];
	let bob = &nodes[1];
	let bob_id = bob.node.get_our_node_id();

	let absolute_expiry = bob.node.duration_since_epoch() + MAX_SHORT_LIVED_RELATIVE_EXPIRY;
	let payment_id = PaymentId([1; 32]);
	let refund = bob.node
		.create_refund_builder(10_000_000, absolute_expiry, payment_id, Retry::Attempts(0), None)
		.unwrap()
		.build().unwrap();
	assert_eq!(refund.absolute_expiry(), Some(absolute_expiry));
	assert!(!refund.paths().is_empty());
	for path in refund.paths() {
		let introduction_node_id = resolve_introduction_node(alice, &path);
		assert_eq!(introduction_node_id, bob_id);
		assert!(matches!(path.introduction_node(), &IntroductionNode::DirectedShortChannelId(..)));
	}
}

/// Checks that blinded paths are not compact for long-lived refunds.
#[test]
fn creates_long_lived_refund() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 10_000_000, 1_000_000_000);

	let bob = &nodes[1];
	let bob_id = bob.node.get_our_node_id();

	let absolute_expiry = bob.node.duration_since_epoch() + MAX_SHORT_LIVED_RELATIVE_EXPIRY
		+ Duration::from_secs(1);
	let payment_id = PaymentId([1; 32]);
	let refund = bob.node
		.create_refund_builder(10_000_000, absolute_expiry, payment_id, Retry::Attempts(0), None)
		.unwrap()
		.build().unwrap();
	assert_eq!(refund.absolute_expiry(), Some(absolute_expiry));
	assert!(!refund.paths().is_empty());
	for path in refund.paths() {
		assert_eq!(path.introduction_node(), &IntroductionNode::NodeId(bob_id));
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
		.create_offer_builder(None)
		.unwrap()
		.amount_msats(10_000_000)
		.build().unwrap();
	assert_ne!(offer.signing_pubkey(), Some(alice_id));
	assert!(!offer.paths().is_empty());
	for path in offer.paths() {
		assert_eq!(path.introduction_node(), &IntroductionNode::NodeId(bob_id));
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
	let payment_context = PaymentContext::Bolt12Offer(Bolt12OfferContext {
		offer_id: offer.id(),
		invoice_request: InvoiceRequestFields {
			payer_id: invoice_request.payer_id(),
			quantity: None,
			payer_note_truncated: None,
		},
	});
	assert_eq!(invoice_request.amount_msats(), None);
	assert_ne!(invoice_request.payer_id(), david_id);
	assert_eq!(reply_path.introduction_node(), &IntroductionNode::NodeId(charlie_id));

	let onion_message = alice.onion_messenger.next_onion_message_for_peer(charlie_id).unwrap();
	charlie.onion_messenger.handle_onion_message(&alice_id, &onion_message);

	let onion_message = charlie.onion_messenger.next_onion_message_for_peer(david_id).unwrap();
	david.onion_messenger.handle_onion_message(&charlie_id, &onion_message);

	let (invoice, _) = extract_invoice(david, &onion_message);
	assert_eq!(invoice.amount_msats(), 10_000_000);
	assert_ne!(invoice.signing_pubkey(), alice_id);
	assert!(!invoice.payment_paths().is_empty());
	for (_, path) in invoice.payment_paths() {
		assert_eq!(path.introduction_node(), &IntroductionNode::NodeId(bob_id));
	}

	route_bolt12_payment(david, &[charlie, bob, alice], &invoice);
	expect_recent_payment!(david, RecentPaymentDetails::Pending, payment_id);

	claim_bolt12_payment(david, &[charlie, bob, alice], payment_context);
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
		.create_refund_builder(10_000_000, absolute_expiry, payment_id, Retry::Attempts(0), None)
		.unwrap()
		.build().unwrap();
	assert_eq!(refund.amount_msats(), 10_000_000);
	assert_eq!(refund.absolute_expiry(), Some(absolute_expiry));
	assert_ne!(refund.payer_id(), david_id);
	assert!(!refund.paths().is_empty());
	for path in refund.paths() {
		assert_eq!(path.introduction_node(), &IntroductionNode::NodeId(charlie_id));
	}
	expect_recent_payment!(david, RecentPaymentDetails::AwaitingInvoice, payment_id);

	let payment_context = PaymentContext::Bolt12Refund(Bolt12RefundContext {});
	let expected_invoice = alice.node.request_refund_payment(&refund).unwrap();

	connect_peers(alice, charlie);

	let onion_message = alice.onion_messenger.next_onion_message_for_peer(charlie_id).unwrap();
	charlie.onion_messenger.handle_onion_message(&alice_id, &onion_message);

	let onion_message = charlie.onion_messenger.next_onion_message_for_peer(david_id).unwrap();
	david.onion_messenger.handle_onion_message(&charlie_id, &onion_message);

	let (invoice, _) = extract_invoice(david, &onion_message);
	assert_eq!(invoice, expected_invoice);

	assert_eq!(invoice.amount_msats(), 10_000_000);
	assert_ne!(invoice.signing_pubkey(), alice_id);
	assert!(!invoice.payment_paths().is_empty());
	for (_, path) in invoice.payment_paths() {
		assert_eq!(path.introduction_node(), &IntroductionNode::NodeId(bob_id));
	}

	route_bolt12_payment(david, &[charlie, bob, alice], &invoice);
	expect_recent_payment!(david, RecentPaymentDetails::Pending, payment_id);

	claim_bolt12_payment(david, &[charlie, bob, alice], payment_context);
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
		.create_offer_builder(None).unwrap()
		.amount_msats(10_000_000)
		.build().unwrap();
	assert_ne!(offer.signing_pubkey(), Some(alice_id));
	assert!(!offer.paths().is_empty());
	for path in offer.paths() {
		assert_eq!(path.introduction_node(), &IntroductionNode::NodeId(alice_id));
	}

	let payment_id = PaymentId([1; 32]);
	bob.node.pay_for_offer(&offer, None, None, None, payment_id, Retry::Attempts(0), None).unwrap();
	expect_recent_payment!(bob, RecentPaymentDetails::AwaitingInvoice, payment_id);

	let onion_message = bob.onion_messenger.next_onion_message_for_peer(alice_id).unwrap();
	alice.onion_messenger.handle_onion_message(&bob_id, &onion_message);

	let (invoice_request, reply_path) = extract_invoice_request(alice, &onion_message);
	let payment_context = PaymentContext::Bolt12Offer(Bolt12OfferContext {
		offer_id: offer.id(),
		invoice_request: InvoiceRequestFields {
			payer_id: invoice_request.payer_id(),
			quantity: None,
			payer_note_truncated: None,
		},
	});
	assert_eq!(invoice_request.amount_msats(), None);
	assert_ne!(invoice_request.payer_id(), bob_id);
	assert_eq!(reply_path.introduction_node(), &IntroductionNode::NodeId(bob_id));

	let onion_message = alice.onion_messenger.next_onion_message_for_peer(bob_id).unwrap();
	bob.onion_messenger.handle_onion_message(&alice_id, &onion_message);

	let (invoice, _) = extract_invoice(bob, &onion_message);
	assert_eq!(invoice.amount_msats(), 10_000_000);
	assert_ne!(invoice.signing_pubkey(), alice_id);
	assert!(!invoice.payment_paths().is_empty());
	for (_, path) in invoice.payment_paths() {
		assert_eq!(path.introduction_node(), &IntroductionNode::NodeId(alice_id));
	}

	route_bolt12_payment(bob, &[alice], &invoice);
	expect_recent_payment!(bob, RecentPaymentDetails::Pending, payment_id);

	claim_bolt12_payment(bob, &[alice], payment_context);
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
		.create_refund_builder(10_000_000, absolute_expiry, payment_id, Retry::Attempts(0), None)
		.unwrap()
		.build().unwrap();
	assert_eq!(refund.amount_msats(), 10_000_000);
	assert_eq!(refund.absolute_expiry(), Some(absolute_expiry));
	assert_ne!(refund.payer_id(), bob_id);
	assert!(!refund.paths().is_empty());
	for path in refund.paths() {
		assert_eq!(path.introduction_node(), &IntroductionNode::NodeId(bob_id));
	}
	expect_recent_payment!(bob, RecentPaymentDetails::AwaitingInvoice, payment_id);

	let payment_context = PaymentContext::Bolt12Refund(Bolt12RefundContext {});
	let expected_invoice = alice.node.request_refund_payment(&refund).unwrap();

	let onion_message = alice.onion_messenger.next_onion_message_for_peer(bob_id).unwrap();
	bob.onion_messenger.handle_onion_message(&alice_id, &onion_message);

	let (invoice, _) = extract_invoice(bob, &onion_message);
	assert_eq!(invoice, expected_invoice);

	assert_eq!(invoice.amount_msats(), 10_000_000);
	assert_ne!(invoice.signing_pubkey(), alice_id);
	assert!(!invoice.payment_paths().is_empty());
	for (_, path) in invoice.payment_paths() {
		assert_eq!(path.introduction_node(), &IntroductionNode::NodeId(alice_id));
	}

	route_bolt12_payment(bob, &[alice], &invoice);
	expect_recent_payment!(bob, RecentPaymentDetails::Pending, payment_id);

	claim_bolt12_payment(bob, &[alice], payment_context);
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
		.create_offer_builder(None).unwrap()
		.clear_paths()
		.amount_msats(10_000_000)
		.build().unwrap();
	assert_eq!(offer.signing_pubkey(), Some(alice_id));
	assert!(offer.paths().is_empty());

	let payment_id = PaymentId([1; 32]);
	bob.node.pay_for_offer(&offer, None, None, None, payment_id, Retry::Attempts(0), None).unwrap();
	expect_recent_payment!(bob, RecentPaymentDetails::AwaitingInvoice, payment_id);

	let onion_message = bob.onion_messenger.next_onion_message_for_peer(alice_id).unwrap();
	alice.onion_messenger.handle_onion_message(&bob_id, &onion_message);

	let (invoice_request, _) = extract_invoice_request(alice, &onion_message);
	let payment_context = PaymentContext::Bolt12Offer(Bolt12OfferContext {
		offer_id: offer.id(),
		invoice_request: InvoiceRequestFields {
			payer_id: invoice_request.payer_id(),
			quantity: None,
			payer_note_truncated: None,
		},
	});

	let onion_message = alice.onion_messenger.next_onion_message_for_peer(bob_id).unwrap();
	bob.onion_messenger.handle_onion_message(&alice_id, &onion_message);

	let (invoice, _) = extract_invoice(bob, &onion_message);
	route_bolt12_payment(bob, &[alice], &invoice);
	expect_recent_payment!(bob, RecentPaymentDetails::Pending, payment_id);

	claim_bolt12_payment(bob, &[alice], payment_context);
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
		.create_refund_builder(10_000_000, absolute_expiry, payment_id, Retry::Attempts(0), None)
		.unwrap()
		.clear_paths()
		.build().unwrap();
	assert_eq!(refund.payer_id(), bob_id);
	assert!(refund.paths().is_empty());
	expect_recent_payment!(bob, RecentPaymentDetails::AwaitingInvoice, payment_id);

	let payment_context = PaymentContext::Bolt12Refund(Bolt12RefundContext {});
	let expected_invoice = alice.node.request_refund_payment(&refund).unwrap();

	let onion_message = alice.onion_messenger.next_onion_message_for_peer(bob_id).unwrap();
	bob.onion_messenger.handle_onion_message(&alice_id, &onion_message);

	let (invoice, _) = extract_invoice(bob, &onion_message);
	assert_eq!(invoice, expected_invoice);

	route_bolt12_payment(bob, &[alice], &invoice);
	expect_recent_payment!(bob, RecentPaymentDetails::Pending, payment_id);

	claim_bolt12_payment(bob, &[alice], payment_context);
	expect_recent_payment!(bob, RecentPaymentDetails::Fulfilled, payment_id);
}

/// This test checks that when multiple potential introduction nodes are available for the payer,
/// multiple `invoice_request` messages are sent for the offer, each with a different `reply_path`.
#[test]
fn send_invoice_requests_with_distinct_reply_path() {
	let mut accept_forward_cfg = test_default_channel_config();
	accept_forward_cfg.accept_forwards_to_priv_channels = true;

	let mut features = channelmanager::provided_init_features(&accept_forward_cfg);
	features.set_onion_messages_optional();
	features.set_route_blinding_optional();

	let chanmon_cfgs = create_chanmon_cfgs(7);
	let node_cfgs = create_node_cfgs(7, &chanmon_cfgs);

	*node_cfgs[1].override_init_features.borrow_mut() = Some(features);

	let node_chanmgrs = create_node_chanmgrs(
		7, &node_cfgs, &[None, Some(accept_forward_cfg), None, None, None, None, None]
	);
	let nodes = create_network(7, &node_cfgs, &node_chanmgrs);

	create_unannounced_chan_between_nodes_with_value(&nodes, 0, 1, 10_000_000, 1_000_000_000);
	create_unannounced_chan_between_nodes_with_value(&nodes, 2, 3, 10_000_000, 1_000_000_000);
	create_announced_chan_between_nodes_with_value(&nodes, 1, 2, 10_000_000, 1_000_000_000);
	create_announced_chan_between_nodes_with_value(&nodes, 1, 4, 10_000_000, 1_000_000_000);
	create_announced_chan_between_nodes_with_value(&nodes, 1, 5, 10_000_000, 1_000_000_000);
	create_announced_chan_between_nodes_with_value(&nodes, 2, 4, 10_000_000, 1_000_000_000);
	create_announced_chan_between_nodes_with_value(&nodes, 2, 5, 10_000_000, 1_000_000_000);

	// Introduce another potential introduction node, node[6], as a candidate
	create_unannounced_chan_between_nodes_with_value(&nodes, 3, 6, 10_000_000, 1_000_000_000);
	create_announced_chan_between_nodes_with_value(&nodes, 2, 6, 10_000_000, 1_000_000_000);
	create_announced_chan_between_nodes_with_value(&nodes, 4, 6, 10_000_000, 1_000_000_000);
	create_announced_chan_between_nodes_with_value(&nodes, 5, 6, 10_000_000, 1_000_000_000);

	let (alice, bob, charlie, david) = (&nodes[0], &nodes[1], &nodes[2], &nodes[3]);
	let alice_id = alice.node.get_our_node_id();
	let bob_id = bob.node.get_our_node_id();
	let charlie_id = charlie.node.get_our_node_id();
	let david_id = david.node.get_our_node_id();

	disconnect_peers(alice, &[charlie, david, &nodes[4], &nodes[5], &nodes[6]]);
	disconnect_peers(david, &[bob, &nodes[4], &nodes[5]]);

	let offer = alice.node
		.create_offer_builder(None)
		.unwrap()
		.amount_msats(10_000_000)
		.build().unwrap();
	assert_ne!(offer.signing_pubkey(), Some(alice_id));
	assert!(!offer.paths().is_empty());
	for path in offer.paths() {
		assert_eq!(path.introduction_node(), &IntroductionNode::NodeId(bob_id));
	}

	let payment_id = PaymentId([1; 32]);
	david.node.pay_for_offer(&offer, None, None, None, payment_id, Retry::Attempts(0), None)
		.unwrap();
	expect_recent_payment!(david, RecentPaymentDetails::AwaitingInvoice, payment_id);
	connect_peers(david, bob);

	// Send, extract and verify the first Invoice Request message
	let onion_message = david.onion_messenger.next_onion_message_for_peer(bob_id).unwrap();
	bob.onion_messenger.handle_onion_message(&david_id, &onion_message);

	connect_peers(alice, charlie);

	let onion_message = bob.onion_messenger.next_onion_message_for_peer(alice_id).unwrap();
	alice.onion_messenger.handle_onion_message(&bob_id, &onion_message);

	let (_, reply_path) = extract_invoice_request(alice, &onion_message);
	assert_eq!(reply_path.introduction_node(), &IntroductionNode::NodeId(charlie_id));

	// Send, extract and verify the second Invoice Request message
	let onion_message = david.onion_messenger.next_onion_message_for_peer(bob_id).unwrap();
	bob.onion_messenger.handle_onion_message(&david_id, &onion_message);

	let onion_message = bob.onion_messenger.next_onion_message_for_peer(alice_id).unwrap();
	alice.onion_messenger.handle_onion_message(&bob_id, &onion_message);

	let (_, reply_path) = extract_invoice_request(alice, &onion_message);
	assert_eq!(reply_path.introduction_node(), &IntroductionNode::NodeId(nodes[6].node.get_our_node_id()));
}

/// This test checks that when multiple potential introduction nodes are available for the payee,
/// multiple `Invoice` messages are sent for the Refund, each with a different `reply_path`.
#[test]
fn send_invoice_for_refund_with_distinct_reply_path() {
	let mut accept_forward_cfg = test_default_channel_config();
	accept_forward_cfg.accept_forwards_to_priv_channels = true;

	let mut features = channelmanager::provided_init_features(&accept_forward_cfg);
	features.set_onion_messages_optional();
	features.set_route_blinding_optional();

	let chanmon_cfgs = create_chanmon_cfgs(7);
	let node_cfgs = create_node_cfgs(7, &chanmon_cfgs);

	*node_cfgs[1].override_init_features.borrow_mut() = Some(features);

	let node_chanmgrs = create_node_chanmgrs(
		7, &node_cfgs, &[None, Some(accept_forward_cfg), None, None, None, None, None]
	);
	let nodes = create_network(7, &node_cfgs, &node_chanmgrs);

	create_unannounced_chan_between_nodes_with_value(&nodes, 0, 1, 10_000_000, 1_000_000_000);
	create_unannounced_chan_between_nodes_with_value(&nodes, 2, 3, 10_000_000, 1_000_000_000);
	create_announced_chan_between_nodes_with_value(&nodes, 1, 2, 10_000_000, 1_000_000_000);
	create_announced_chan_between_nodes_with_value(&nodes, 1, 4, 10_000_000, 1_000_000_000);
	create_announced_chan_between_nodes_with_value(&nodes, 1, 5, 10_000_000, 1_000_000_000);
	create_announced_chan_between_nodes_with_value(&nodes, 2, 4, 10_000_000, 1_000_000_000);
	create_announced_chan_between_nodes_with_value(&nodes, 2, 5, 10_000_000, 1_000_000_000);

	// Introduce another potential introduction node, node[6], as a candidate
	create_unannounced_chan_between_nodes_with_value(&nodes, 3, 6, 10_000_000, 1_000_000_000);
	create_announced_chan_between_nodes_with_value(&nodes, 2, 6, 10_000_000, 1_000_000_000);
	create_announced_chan_between_nodes_with_value(&nodes, 4, 6, 10_000_000, 1_000_000_000);
	create_announced_chan_between_nodes_with_value(&nodes, 5, 6, 10_000_000, 1_000_000_000);

	let (alice, bob, charlie, david) = (&nodes[0], &nodes[1], &nodes[2], &nodes[3]);
	let alice_id = alice.node.get_our_node_id();
	let bob_id = bob.node.get_our_node_id();
	let charlie_id = charlie.node.get_our_node_id();
	let david_id = david.node.get_our_node_id();

	disconnect_peers(alice, &[charlie, david, &nodes[4], &nodes[5], &nodes[6]]);
	disconnect_peers(david, &[bob, &nodes[4], &nodes[5]]);

	let absolute_expiry = Duration::from_secs(u64::MAX);
	let payment_id = PaymentId([1; 32]);
	let refund = alice.node
		.create_refund_builder(10_000_000, absolute_expiry, payment_id, Retry::Attempts(0), None)
		.unwrap()
		.build().unwrap();
	assert_ne!(refund.payer_id(), alice_id);
	for path in refund.paths() {
		assert_eq!(path.introduction_node(), &IntroductionNode::NodeId(bob_id));
	}
	expect_recent_payment!(alice, RecentPaymentDetails::AwaitingInvoice, payment_id);

	let _expected_invoice = david.node.request_refund_payment(&refund).unwrap();

	connect_peers(david, bob);

	let onion_message = david.onion_messenger.next_onion_message_for_peer(bob_id).unwrap();
	bob.onion_messenger.handle_onion_message(&david_id, &onion_message);

	connect_peers(alice, charlie);

	let onion_message = bob.onion_messenger.next_onion_message_for_peer(alice_id).unwrap();

	let (_, reply_path) = extract_invoice(alice, &onion_message);
	assert_eq!(reply_path.unwrap().introduction_node(), &IntroductionNode::NodeId(charlie_id));

	// Send, extract and verify the second Invoice Request message
	let onion_message = david.onion_messenger.next_onion_message_for_peer(bob_id).unwrap();
	bob.onion_messenger.handle_onion_message(&david_id, &onion_message);

	let onion_message = bob.onion_messenger.next_onion_message_for_peer(alice_id).unwrap();

	let (_, reply_path) = extract_invoice(alice, &onion_message);
	assert_eq!(reply_path.unwrap().introduction_node(), &IntroductionNode::NodeId(nodes[6].node.get_our_node_id()));
}

/// Checks that a deferred invoice can be paid asynchronously from an Event::InvoiceReceived.
#[test]
fn pays_bolt12_invoice_asynchronously() {
	let mut manually_pay_cfg = test_default_channel_config();
	manually_pay_cfg.manually_handle_bolt12_invoices = true;

	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, Some(manually_pay_cfg)]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 10_000_000, 1_000_000_000);

	let alice = &nodes[0];
	let alice_id = alice.node.get_our_node_id();
	let bob = &nodes[1];
	let bob_id = bob.node.get_our_node_id();

	let offer = alice.node
		.create_offer_builder(None).unwrap()
		.amount_msats(10_000_000)
		.build().unwrap();

	let payment_id = PaymentId([1; 32]);
	bob.node.pay_for_offer(&offer, None, None, None, payment_id, Retry::Attempts(0), None).unwrap();
	expect_recent_payment!(bob, RecentPaymentDetails::AwaitingInvoice, payment_id);

	let onion_message = bob.onion_messenger.next_onion_message_for_peer(alice_id).unwrap();
	alice.onion_messenger.handle_onion_message(&bob_id, &onion_message);

	let (invoice_request, _) = extract_invoice_request(alice, &onion_message);
	let payment_context = PaymentContext::Bolt12Offer(Bolt12OfferContext {
		offer_id: offer.id(),
		invoice_request: InvoiceRequestFields {
			payer_id: invoice_request.payer_id(),
			quantity: None,
			payer_note_truncated: None,
		},
	});

	let onion_message = alice.onion_messenger.next_onion_message_for_peer(bob_id).unwrap();
	bob.onion_messenger.handle_onion_message(&alice_id, &onion_message);

	let (invoice, context) = match get_event!(bob, Event::InvoiceReceived) {
		Event::InvoiceReceived { payment_id: actual_payment_id, invoice, context, .. } => {
			assert_eq!(actual_payment_id, payment_id);
			(invoice, context)
		},
		_ => panic!("No Event::InvoiceReceived"),
	};
	assert_eq!(invoice.amount_msats(), 10_000_000);
	assert_ne!(invoice.signing_pubkey(), alice_id);
	assert!(!invoice.payment_paths().is_empty());
	for (_, path) in invoice.payment_paths() {
		assert_eq!(path.introduction_node(), &IntroductionNode::NodeId(alice_id));
	}

	assert!(bob.node.send_payment_for_bolt12_invoice(&invoice, context.as_ref()).is_ok());
	assert_eq!(
		bob.node.send_payment_for_bolt12_invoice(&invoice, context.as_ref()),
		Err(Bolt12PaymentError::DuplicateInvoice),
	);

	route_bolt12_payment(bob, &[alice], &invoice);
	expect_recent_payment!(bob, RecentPaymentDetails::Pending, payment_id);

	claim_bolt12_payment(bob, &[alice], payment_context);
	expect_recent_payment!(bob, RecentPaymentDetails::Fulfilled, payment_id);

	assert_eq!(
		bob.node.send_payment_for_bolt12_invoice(&invoice, context.as_ref()),
		Err(Bolt12PaymentError::DuplicateInvoice),
	);

	for _ in 0..=IDEMPOTENCY_TIMEOUT_TICKS {
		bob.node.timer_tick_occurred();
	}

	assert_eq!(
		bob.node.send_payment_for_bolt12_invoice(&invoice, context.as_ref()),
		Err(Bolt12PaymentError::UnexpectedInvoice),
	);
}

/// Checks that an offer can be created using an unannounced node as a blinded path's introduction
/// node. This is only preferred if there are no other options which may indicated either the offer
/// is intended for the unannounced node or that the node is actually announced (e.g., an LSP) but
/// the recipient doesn't have a network graph.
#[test]
fn creates_offer_with_blinded_path_using_unannounced_introduction_node() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	create_unannounced_chan_between_nodes_with_value(&nodes, 0, 1, 10_000_000, 1_000_000_000);

	let alice = &nodes[0];
	let alice_id = alice.node.get_our_node_id();
	let bob = &nodes[1];
	let bob_id = bob.node.get_our_node_id();

	let offer = alice.node
		.create_offer_builder(None).unwrap()
		.amount_msats(10_000_000)
		.build().unwrap();
	assert_ne!(offer.signing_pubkey(), Some(alice_id));
	assert!(!offer.paths().is_empty());
	for path in offer.paths() {
		assert_eq!(path.introduction_node(), &IntroductionNode::NodeId(bob_id));
	}

	let payment_id = PaymentId([1; 32]);
	bob.node.pay_for_offer(&offer, None, None, None, payment_id, Retry::Attempts(0), None).unwrap();
	expect_recent_payment!(bob, RecentPaymentDetails::AwaitingInvoice, payment_id);

	let onion_message = bob.onion_messenger.next_onion_message_for_peer(alice_id).unwrap();
	alice.onion_messenger.handle_onion_message(&bob_id, &onion_message);

	let (invoice_request, reply_path) = extract_invoice_request(alice, &onion_message);
	let payment_context = PaymentContext::Bolt12Offer(Bolt12OfferContext {
		offer_id: offer.id(),
		invoice_request: InvoiceRequestFields {
			payer_id: invoice_request.payer_id(),
			quantity: None,
			payer_note_truncated: None,
		},
	});
	assert_ne!(invoice_request.payer_id(), bob_id);
	assert_eq!(reply_path.introduction_node(), &IntroductionNode::NodeId(alice_id));

	let onion_message = alice.onion_messenger.next_onion_message_for_peer(bob_id).unwrap();
	bob.onion_messenger.handle_onion_message(&alice_id, &onion_message);

	let (invoice, _) = extract_invoice(bob, &onion_message);
	assert_ne!(invoice.signing_pubkey(), alice_id);
	assert!(!invoice.payment_paths().is_empty());
	for (_, path) in invoice.payment_paths() {
		assert_eq!(path.introduction_node(), &IntroductionNode::NodeId(bob_id));
	}

	route_bolt12_payment(bob, &[alice], &invoice);
	expect_recent_payment!(bob, RecentPaymentDetails::Pending, payment_id);

	claim_bolt12_payment(bob, &[alice], payment_context);
	expect_recent_payment!(bob, RecentPaymentDetails::Fulfilled, payment_id);
}

/// Checks that a refund can be created using an unannounced node as a blinded path's introduction
/// node. This is only preferred if there are no other options which may indicated either the refund
/// is intended for the unannounced node or that the node is actually announced (e.g., an LSP) but
/// the sender doesn't have a network graph.
#[test]
fn creates_refund_with_blinded_path_using_unannounced_introduction_node() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	create_unannounced_chan_between_nodes_with_value(&nodes, 0, 1, 10_000_000, 1_000_000_000);

	let alice = &nodes[0];
	let alice_id = alice.node.get_our_node_id();
	let bob = &nodes[1];
	let bob_id = bob.node.get_our_node_id();

	let absolute_expiry = Duration::from_secs(u64::MAX);
	let payment_id = PaymentId([1; 32]);
	let refund = bob.node
		.create_refund_builder(10_000_000, absolute_expiry, payment_id, Retry::Attempts(0), None)
		.unwrap()
		.build().unwrap();
	assert_ne!(refund.payer_id(), bob_id);
	assert!(!refund.paths().is_empty());
	for path in refund.paths() {
		assert_eq!(path.introduction_node(), &IntroductionNode::NodeId(alice_id));
	}
	expect_recent_payment!(bob, RecentPaymentDetails::AwaitingInvoice, payment_id);

	let expected_invoice = alice.node.request_refund_payment(&refund).unwrap();

	let onion_message = alice.onion_messenger.next_onion_message_for_peer(bob_id).unwrap();

	let (invoice, _) = extract_invoice(bob, &onion_message);
	assert_eq!(invoice, expected_invoice);
	assert_ne!(invoice.signing_pubkey(), alice_id);
	assert!(!invoice.payment_paths().is_empty());
	for (_, path) in invoice.payment_paths() {
		assert_eq!(path.introduction_node(), &IntroductionNode::NodeId(bob_id));
	}
}

/// Check that authentication fails when an invoice request is handled using the wrong context
/// (i.e., was sent directly or over an unexpected blinded path).
#[test]
fn fails_authentication_when_handling_invoice_request() {
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
		.create_offer_builder(None)
		.unwrap()
		.amount_msats(10_000_000)
		.build().unwrap();
	assert_eq!(offer.metadata(), None);
	assert_ne!(offer.signing_pubkey(), Some(alice_id));
	assert!(!offer.paths().is_empty());
	for path in offer.paths() {
		assert_eq!(path.introduction_node(), &IntroductionNode::NodeId(bob_id));
	}

	let invalid_path = alice.node
		.create_offer_builder(None)
		.unwrap()
		.build().unwrap()
		.paths().first().unwrap()
		.clone();
	assert_eq!(invalid_path.introduction_node(), &IntroductionNode::NodeId(bob_id));

	// Send the invoice request directly to Alice instead of using a blinded path.
	let payment_id = PaymentId([1; 32]);
	david.node.pay_for_offer(&offer, None, None, None, payment_id, Retry::Attempts(0), None)
		.unwrap();
	expect_recent_payment!(david, RecentPaymentDetails::AwaitingInvoice, payment_id);

	connect_peers(david, alice);
	#[cfg(not(c_bindings))] {
		david.node.pending_offers_messages.lock().unwrap().first_mut().unwrap().destination =
			Destination::Node(alice_id);
	}
	#[cfg(c_bindings)] {
		david.node.pending_offers_messages.lock().unwrap().first_mut().unwrap().1 =
			Destination::Node(alice_id);
	}

	let onion_message = david.onion_messenger.next_onion_message_for_peer(alice_id).unwrap();
	alice.onion_messenger.handle_onion_message(&david_id, &onion_message);

	let (invoice_request, reply_path) = extract_invoice_request(alice, &onion_message);
	assert_eq!(invoice_request.amount_msats(), None);
	assert_ne!(invoice_request.payer_id(), david_id);
	assert_eq!(reply_path.introduction_node(), &IntroductionNode::NodeId(charlie_id));

	assert_eq!(alice.onion_messenger.next_onion_message_for_peer(charlie_id), None);

	david.node.abandon_payment(payment_id);
	get_event!(david, Event::PaymentFailed);

	// Send the invoice request to Alice using an invalid blinded path.
	let payment_id = PaymentId([2; 32]);
	david.node.pay_for_offer(&offer, None, None, None, payment_id, Retry::Attempts(0), None)
		.unwrap();
	expect_recent_payment!(david, RecentPaymentDetails::AwaitingInvoice, payment_id);

	#[cfg(not(c_bindings))] {
		david.node.pending_offers_messages.lock().unwrap().first_mut().unwrap().destination =
			Destination::BlindedPath(invalid_path);
	}
	#[cfg(c_bindings)] {
		david.node.pending_offers_messages.lock().unwrap().first_mut().unwrap().1 =
			Destination::BlindedPath(invalid_path);
	}

	connect_peers(david, bob);

	let onion_message = david.onion_messenger.next_onion_message_for_peer(bob_id).unwrap();
	bob.onion_messenger.handle_onion_message(&david_id, &onion_message);

	let onion_message = bob.onion_messenger.next_onion_message_for_peer(alice_id).unwrap();
	alice.onion_messenger.handle_onion_message(&bob_id, &onion_message);

	let (invoice_request, reply_path) = extract_invoice_request(alice, &onion_message);
	assert_eq!(invoice_request.amount_msats(), None);
	assert_ne!(invoice_request.payer_id(), david_id);
	assert_eq!(reply_path.introduction_node(), &IntroductionNode::NodeId(charlie_id));

	assert_eq!(alice.onion_messenger.next_onion_message_for_peer(charlie_id), None);
}

/// Check that authentication fails when an invoice is handled using the wrong context (i.e., was
/// sent over an unexpected blinded path).
#[test]
fn fails_authentication_when_handling_invoice_for_offer() {
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
		.create_offer_builder(None)
		.unwrap()
		.amount_msats(10_000_000)
		.build().unwrap();
	assert_ne!(offer.signing_pubkey(), Some(alice_id));
	assert!(!offer.paths().is_empty());
	for path in offer.paths() {
		assert_eq!(path.introduction_node(), &IntroductionNode::NodeId(bob_id));
	}

	// Initiate an invoice request, but abandon tracking it.
	let payment_id = PaymentId([1; 32]);
	david.node.pay_for_offer(&offer, None, None, None, payment_id, Retry::Attempts(0), None)
		.unwrap();
	david.node.abandon_payment(payment_id);
	get_event!(david, Event::PaymentFailed);

	// Don't send the invoice request, but grab its reply path to use with a different request.
	let invalid_reply_path = {
		let mut pending_offers_messages = david.node.pending_offers_messages.lock().unwrap();
		let pending_invoice_request = pending_offers_messages.pop().unwrap();
		pending_offers_messages.clear();
		#[cfg(not(c_bindings))] {
			pending_invoice_request.reply_path
		}
		#[cfg(c_bindings)] {
			pending_invoice_request.2
		}
	};

	let payment_id = PaymentId([2; 32]);
	david.node.pay_for_offer(&offer, None, None, None, payment_id, Retry::Attempts(0), None)
		.unwrap();
	expect_recent_payment!(david, RecentPaymentDetails::AwaitingInvoice, payment_id);

	// Swap out the reply path to force authentication to fail when handling the invoice since it
	// will be sent over the wrong blinded path.
	{
		let mut pending_offers_messages = david.node.pending_offers_messages.lock().unwrap();
		let mut pending_invoice_request = pending_offers_messages.first_mut().unwrap();
		#[cfg(not(c_bindings))] {
			pending_invoice_request.reply_path = invalid_reply_path;
		}
		#[cfg(c_bindings)] {
			pending_invoice_request.2 = invalid_reply_path;
		}
	}

	connect_peers(david, bob);

	let onion_message = david.onion_messenger.next_onion_message_for_peer(bob_id).unwrap();
	bob.onion_messenger.handle_onion_message(&david_id, &onion_message);

	connect_peers(alice, charlie);

	let onion_message = bob.onion_messenger.next_onion_message_for_peer(alice_id).unwrap();
	alice.onion_messenger.handle_onion_message(&bob_id, &onion_message);

	let (invoice_request, reply_path) = extract_invoice_request(alice, &onion_message);
	assert_eq!(invoice_request.amount_msats(), None);
	assert_ne!(invoice_request.payer_id(), david_id);
	assert_eq!(reply_path.introduction_node(), &IntroductionNode::NodeId(charlie_id));

	let onion_message = alice.onion_messenger.next_onion_message_for_peer(charlie_id).unwrap();
	charlie.onion_messenger.handle_onion_message(&alice_id, &onion_message);

	let onion_message = charlie.onion_messenger.next_onion_message_for_peer(david_id).unwrap();
	david.onion_messenger.handle_onion_message(&charlie_id, &onion_message);

	expect_recent_payment!(david, RecentPaymentDetails::AwaitingInvoice, payment_id);
}

/// Check that authentication fails when an invoice is handled using the wrong context (i.e., was
/// sent directly or over an unexpected blinded path).
#[test]
fn fails_authentication_when_handling_invoice_for_refund() {
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
	let charlie_id = charlie.node.get_our_node_id();
	let david_id = david.node.get_our_node_id();

	disconnect_peers(alice, &[charlie, david, &nodes[4], &nodes[5]]);
	disconnect_peers(david, &[bob, &nodes[4], &nodes[5]]);

	let absolute_expiry = Duration::from_secs(u64::MAX);
	let payment_id = PaymentId([1; 32]);
	let refund = david.node
		.create_refund_builder(10_000_000, absolute_expiry, payment_id, Retry::Attempts(0), None)
		.unwrap()
		.build().unwrap();
	assert_ne!(refund.payer_id(), david_id);
	assert!(!refund.paths().is_empty());
	for path in refund.paths() {
		assert_eq!(path.introduction_node(), &IntroductionNode::NodeId(charlie_id));
	}
	expect_recent_payment!(david, RecentPaymentDetails::AwaitingInvoice, payment_id);

	// Send the invoice directly to David instead of using a blinded path.
	let expected_invoice = alice.node.request_refund_payment(&refund).unwrap();

	connect_peers(david, alice);
	#[cfg(not(c_bindings))] {
		alice.node.pending_offers_messages.lock().unwrap().first_mut().unwrap().destination =
			Destination::Node(david_id);
	}
	#[cfg(c_bindings)] {
		alice.node.pending_offers_messages.lock().unwrap().first_mut().unwrap().1 =
			Destination::Node(david_id);
	}

	let onion_message = alice.onion_messenger.next_onion_message_for_peer(david_id).unwrap();
	david.onion_messenger.handle_onion_message(&alice_id, &onion_message);

	let (invoice, _) = extract_invoice(david, &onion_message);
	assert_eq!(invoice, expected_invoice);

	expect_recent_payment!(david, RecentPaymentDetails::AwaitingInvoice, payment_id);
	david.node.abandon_payment(payment_id);
	get_event!(david, Event::PaymentFailed);

	// Send the invoice to David using an invalid blinded path.
	let invalid_path = refund.paths().first().unwrap().clone();
	let payment_id = PaymentId([2; 32]);
	let refund = david.node
		.create_refund_builder(10_000_000, absolute_expiry, payment_id, Retry::Attempts(0), None)
		.unwrap()
		.build().unwrap();
	assert_ne!(refund.payer_id(), david_id);
	assert!(!refund.paths().is_empty());
	for path in refund.paths() {
		assert_eq!(path.introduction_node(), &IntroductionNode::NodeId(charlie_id));
	}

	let expected_invoice = alice.node.request_refund_payment(&refund).unwrap();

	#[cfg(not(c_bindings))] {
		alice.node.pending_offers_messages.lock().unwrap().first_mut().unwrap().destination =
			Destination::BlindedPath(invalid_path);
	}
	#[cfg(c_bindings)] {
		alice.node.pending_offers_messages.lock().unwrap().first_mut().unwrap().1 =
			Destination::BlindedPath(invalid_path);
	}

	connect_peers(alice, charlie);

	let onion_message = alice.onion_messenger.next_onion_message_for_peer(charlie_id).unwrap();
	charlie.onion_messenger.handle_onion_message(&alice_id, &onion_message);

	let onion_message = charlie.onion_messenger.next_onion_message_for_peer(david_id).unwrap();
	david.onion_messenger.handle_onion_message(&charlie_id, &onion_message);

	let (invoice, _) = extract_invoice(david, &onion_message);
	assert_eq!(invoice, expected_invoice);

	expect_recent_payment!(david, RecentPaymentDetails::AwaitingInvoice, payment_id);
}

/// Fails creating or paying an offer when a blinded path cannot be created because no peers are
/// connected.
#[test]
fn fails_creating_or_paying_for_offer_without_connected_peers() {
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

	let (alice, bob, charlie, david) = (&nodes[0], &nodes[1], &nodes[2], &nodes[3]);

	disconnect_peers(alice, &[bob, charlie, david, &nodes[4], &nodes[5]]);
	disconnect_peers(david, &[bob, charlie, &nodes[4], &nodes[5]]);

	let absolute_expiry = alice.node.duration_since_epoch() + MAX_SHORT_LIVED_RELATIVE_EXPIRY;
	match alice.node.create_offer_builder(Some(absolute_expiry)) {
		Ok(_) => panic!("Expected error"),
		Err(e) => assert_eq!(e, Bolt12SemanticError::MissingPaths),
	}

	let mut args = ReconnectArgs::new(alice, bob);
	args.send_channel_ready = (true, true);
	reconnect_nodes(args);

	let offer = alice.node
		.create_offer_builder(Some(absolute_expiry)).unwrap()
		.amount_msats(10_000_000)
		.build().unwrap();

	let payment_id = PaymentId([1; 32]);

	match david.node.pay_for_offer(&offer, None, None, None, payment_id, Retry::Attempts(0), None) {
		Ok(_) => panic!("Expected error"),
		Err(e) => assert_eq!(e, Bolt12SemanticError::MissingPaths),
	}

	assert!(nodes[0].node.list_recent_payments().is_empty());

	let mut args = ReconnectArgs::new(charlie, david);
	args.send_channel_ready = (true, true);
	reconnect_nodes(args);

	assert!(
		david.node.pay_for_offer(
			&offer, None, None, None, payment_id, Retry::Attempts(0), None
		).is_ok()
	);

	expect_recent_payment!(david, RecentPaymentDetails::AwaitingInvoice, payment_id);
}

/// Fails creating or sending an invoice for a refund when a blinded path cannot be created because
/// no peers are connected.
#[test]
fn fails_creating_refund_or_sending_invoice_without_connected_peers() {
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

	disconnect_peers(alice, &[bob, charlie, david, &nodes[4], &nodes[5]]);
	disconnect_peers(david, &[bob, charlie, &nodes[4], &nodes[5]]);

	let absolute_expiry = david.node.duration_since_epoch() + MAX_SHORT_LIVED_RELATIVE_EXPIRY;
	let payment_id = PaymentId([1; 32]);
	match david.node.create_refund_builder(
		10_000_000, absolute_expiry, payment_id, Retry::Attempts(0), None
	) {
		Ok(_) => panic!("Expected error"),
		Err(e) => assert_eq!(e, Bolt12SemanticError::MissingPaths),
	}

	let mut args = ReconnectArgs::new(charlie, david);
	args.send_channel_ready = (true, true);
	reconnect_nodes(args);

	let refund = david.node
		.create_refund_builder(10_000_000, absolute_expiry, payment_id, Retry::Attempts(0), None)
		.unwrap()
		.build().unwrap();

	match alice.node.request_refund_payment(&refund) {
		Ok(_) => panic!("Expected error"),
		Err(e) => assert_eq!(e, Bolt12SemanticError::MissingPaths),
	}

	let mut args = ReconnectArgs::new(alice, bob);
	args.send_channel_ready = (true, true);
	reconnect_nodes(args);

	assert!(alice.node.request_refund_payment(&refund).is_ok());
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
		.create_offer_builder(None).unwrap()
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
		.create_refund_builder(10_000_000, absolute_expiry, payment_id, Retry::Attempts(0), None)
		.unwrap()
		.chain(Network::Signet)
		.build().unwrap();

	match alice.node.request_refund_payment(&refund) {
		Ok(_) => panic!("Expected error"),
		Err(e) => assert_eq!(e, Bolt12SemanticError::UnsupportedChain),
	}
}

/// Fails creating an invoice request when a blinded reply path cannot be created.
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
	disconnect_peers(david, &[bob, charlie, &nodes[4], &nodes[5]]);

	let offer = alice.node
		.create_offer_builder(None).unwrap()
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
		.create_offer_builder(None).unwrap()
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
			10_000, absolute_expiry, payment_id, Retry::Attempts(0), None
		).is_ok()
	);
	expect_recent_payment!(nodes[0], RecentPaymentDetails::AwaitingInvoice, payment_id);

	match nodes[0].node.create_refund_builder(
		10_000, absolute_expiry, payment_id, Retry::Attempts(0), None
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
		.create_offer_builder(None).unwrap()
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

	// Confirm that david drops this failed payment from his pending outbound payments.
	match get_event!(david, Event::PaymentFailed) {
		Event::PaymentFailed { payment_id: actual_payment_id, reason, .. } => {
			assert_eq!(payment_id, actual_payment_id);
			assert_eq!(reason, Some(PaymentFailureReason::InvoiceRequestRejected));
		},
		_ => panic!("No Event::PaymentFailed"),
	}
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
		.create_refund_builder(10_000_000, absolute_expiry, payment_id, Retry::Attempts(0), None)
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
		.create_refund_builder(10_000_000, absolute_expiry, payment_id, Retry::Attempts(0), None)
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

	// David initiates paying the first invoice
	let payment_context = PaymentContext::Bolt12Refund(Bolt12RefundContext {});
	let (invoice1, _) = extract_invoice(david, &onion_message);

	route_bolt12_payment(david, &[charlie, bob, alice], &invoice1);
	expect_recent_payment!(david, RecentPaymentDetails::Pending, payment_id);

	disconnect_peers(alice, &[charlie]);

	// Alice sends the second invoice
	alice.node.request_refund_payment(&refund).unwrap();

	connect_peers(alice, charlie);
	connect_peers(david, bob);

	let onion_message = alice.onion_messenger.next_onion_message_for_peer(charlie_id).unwrap();
	charlie.onion_messenger.handle_onion_message(&alice_id, &onion_message);

	let onion_message = charlie.onion_messenger.next_onion_message_for_peer(david_id).unwrap();
	david.onion_messenger.handle_onion_message(&charlie_id, &onion_message);

	let (invoice2, _) = extract_invoice(david, &onion_message);
	assert_eq!(invoice1.payer_metadata(), invoice2.payer_metadata());

	// David doesn't initiate paying the second invoice
	assert!(david.onion_messenger.next_onion_message_for_peer(bob_id).is_none());
	assert!(david.node.get_and_clear_pending_msg_events().is_empty());

	// Complete paying the first invoice
	claim_bolt12_payment(david, &[charlie, bob, alice], payment_context);
	expect_recent_payment!(david, RecentPaymentDetails::Fulfilled, payment_id);
}

#[test]
fn fails_paying_invoice_with_unknown_required_features() {
	let mut accept_forward_cfg = test_default_channel_config();
	accept_forward_cfg.accept_forwards_to_priv_channels = true;

	// Clearing route_blinding prevents forming any payment paths since the node is unannounced.
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
		.create_offer_builder(None).unwrap()
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

	let (invoice_request, reply_path) = extract_invoice_request(alice, &onion_message);
	let nonce = extract_offer_nonce(alice, &onion_message);

	let onion_message = alice.onion_messenger.next_onion_message_for_peer(charlie_id).unwrap();
	charlie.onion_messenger.handle_onion_message(&alice_id, &onion_message);

	// Drop the invoice in favor for one with unknown required features.
	let onion_message = charlie.onion_messenger.next_onion_message_for_peer(david_id).unwrap();
	let (invoice, _) = extract_invoice(david, &onion_message);

	let payment_paths = invoice.payment_paths().to_vec();
	let payment_hash = invoice.payment_hash();

	let expanded_key = ExpandedKey::new(&alice.keys_manager.get_inbound_payment_key_material());
	let secp_ctx = Secp256k1::new();

	let created_at = alice.node.duration_since_epoch();
	let invoice = invoice_request
		.verify_using_recipient_data(nonce, &expanded_key, &secp_ctx).unwrap()
		.respond_using_derived_keys_no_std(payment_paths, payment_hash, created_at).unwrap()
		.features_unchecked(Bolt12InvoiceFeatures::unknown())
		.build_and_sign(&secp_ctx).unwrap();

	// Enqueue an onion message containing the new invoice.
	let pending_message = new_pending_onion_message(
		OffersMessage::Invoice(invoice), Destination::BlindedPath(reply_path), None
	);
	alice.node.pending_offers_messages.lock().unwrap().push(pending_message);

	let onion_message = alice.onion_messenger.next_onion_message_for_peer(charlie_id).unwrap();
	charlie.onion_messenger.handle_onion_message(&alice_id, &onion_message);

	let onion_message = charlie.onion_messenger.next_onion_message_for_peer(david_id).unwrap();
	david.onion_messenger.handle_onion_message(&charlie_id, &onion_message);

	// Confirm that david drops this failed payment from his pending outbound payments.
	match get_event!(david, Event::PaymentFailed) {
		Event::PaymentFailed {
			payment_id: event_payment_id,
			payment_hash: Some(event_payment_hash),
			reason: Some(event_reason),
		} => {
			assert_eq!(event_payment_id, payment_id);
			assert_eq!(event_payment_hash, payment_hash);
			assert_eq!(event_reason, PaymentFailureReason::UnknownRequiredFeatures);
		},
		_ => panic!("Expected Event::PaymentFailed with reason"),
	}
}
