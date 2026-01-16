// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

use crate::blinded_path::message::{
	BlindedMessagePath, MessageContext, NextMessageHop, OffersContext,
};
use crate::blinded_path::payment::PaymentContext;
use crate::blinded_path::payment::{AsyncBolt12OfferContext, BlindedPaymentTlvs};
use crate::chain::channelmonitor::{HTLC_FAIL_BACK_BUFFER, LATENCY_GRACE_PERIOD_BLOCKS};
use crate::events::{
	Event, EventsProvider, HTLCHandlingFailureReason, HTLCHandlingFailureType, PaidBolt12Invoice,
	PaymentFailureReason, PaymentPurpose,
};
use crate::ln::blinded_payment_tests::{fail_blinded_htlc_backwards, get_blinded_route_parameters};
use crate::ln::channelmanager::{
	Bolt12PaymentError, OptionalOfferPaymentParams, PaymentId, RecipientOnionFields,
	MIN_CLTV_EXPIRY_DELTA,
};
use crate::ln::functional_test_utils::*;
use crate::ln::inbound_payment;
use crate::ln::msgs;
use crate::ln::msgs::{
	BaseMessageHandler, ChannelMessageHandler, MessageSendEvent, OnionMessageHandler,
};
use crate::ln::offers_tests;
use crate::ln::onion_utils::LocalHTLCFailureReason;
use crate::ln::outbound_payment::{
	PendingOutboundPayment, Retry, TEST_ASYNC_PAYMENT_TIMEOUT_RELATIVE_EXPIRY,
};
use crate::offers::async_receive_offer_cache::{
	TEST_INVOICE_REFRESH_THRESHOLD, TEST_MAX_CACHED_OFFERS_TARGET, TEST_MAX_UPDATE_ATTEMPTS,
	TEST_MIN_OFFER_PATHS_RELATIVE_EXPIRY_SECS, TEST_OFFER_REFRESH_THRESHOLD,
};
use crate::offers::flow::{
	TEST_DEFAULT_ASYNC_RECEIVE_OFFER_EXPIRY, TEST_OFFERS_MESSAGE_REQUEST_LIMIT,
	TEST_TEMP_REPLY_PATH_RELATIVE_EXPIRY,
};
use crate::offers::invoice_request::InvoiceRequest;
use crate::offers::nonce::Nonce;
use crate::offers::offer::{Amount, Offer};
use crate::offers::static_invoice::{
	StaticInvoice, StaticInvoiceBuilder,
	DEFAULT_RELATIVE_EXPIRY as STATIC_INVOICE_DEFAULT_RELATIVE_EXPIRY,
};
use crate::onion_message::async_payments::{AsyncPaymentsMessage, AsyncPaymentsMessageHandler};
use crate::onion_message::messenger::{
	Destination, MessageRouter, MessageSendInstructions, PeeledOnion,
};
use crate::onion_message::offers::OffersMessage;
use crate::onion_message::packet::ParsedOnionMessageContents;
use crate::prelude::*;
use crate::routing::router::{Payee, PaymentParameters};
use crate::sign::NodeSigner;
use crate::sync::Mutex;
use crate::types::features::Bolt12InvoiceFeatures;
use crate::types::payment::{PaymentHash, PaymentPreimage, PaymentSecret};
use crate::util::config::{HTLCInterceptionFlags, UserConfig};
use crate::util::ser::Writeable;
use bitcoin::constants::ChainHash;
use bitcoin::network::Network;
use bitcoin::secp256k1;
use bitcoin::secp256k1::{PublicKey, Secp256k1};

use core::convert::Infallible;
use core::time::Duration;

struct StaticInvoiceServerFlowResult {
	invoice: StaticInvoice,
	invoice_slot: u16,
	invoice_request_path: BlindedMessagePath,

	// Returning messages that were sent along the way allows us to test handling duplicate messages.
	offer_paths_request: msgs::OnionMessage,
	static_invoice_persisted_message: msgs::OnionMessage,
}

// Go through the flow of interactively building a `StaticInvoice`, returning the
// AsyncPaymentsMessage::ServeStaticInvoice that has yet to be provided to the server node.
// Assumes that the sender and recipient are only peers with each other.
//
// Returns (offer_paths_req, serve_static_invoice)
fn invoice_flow_up_to_send_serve_static_invoice(
	server: &Node, recipient: &Node,
) -> (msgs::OnionMessage, msgs::OnionMessage) {
	// First provide an OfferPathsRequest from the recipient to the server.
	recipient.node.timer_tick_occurred();
	let offer_paths_req = loop {
		let msg = recipient
			.onion_messenger
			.next_onion_message_for_peer(server.node.get_our_node_id())
			.unwrap();
		// Ignore any messages that are updating the static invoice stored with the server here
		if matches!(
			server.onion_messenger.peel_onion_message(&msg).unwrap(),
			PeeledOnion::AsyncPayments(AsyncPaymentsMessage::OfferPathsRequest(_), _, _)
		) {
			break msg;
		}
	};
	server.onion_messenger.handle_onion_message(recipient.node.get_our_node_id(), &offer_paths_req);

	// Check that the right number of requests were queued and that they were only queued for the
	// server node.
	let mut pending_oms = recipient.onion_messenger.release_pending_msgs();
	let mut offer_paths_req_msgs = pending_oms.remove(&server.node.get_our_node_id()).unwrap();
	assert!(offer_paths_req_msgs.len() <= TEST_OFFERS_MESSAGE_REQUEST_LIMIT);
	for (_, msgs) in pending_oms {
		assert!(msgs.is_empty());
	}

	// The server responds with OfferPaths.
	let offer_paths = server
		.onion_messenger
		.next_onion_message_for_peer(recipient.node.get_our_node_id())
		.unwrap();
	recipient.onion_messenger.handle_onion_message(server.node.get_our_node_id(), &offer_paths);

	// Only one OfferPaths response should be queued.
	let mut pending_oms = server.onion_messenger.release_pending_msgs();
	for (_, msgs) in pending_oms {
		assert!(msgs.is_empty());
	}

	// After receiving the offer paths, the recipient constructs the static invoice and sends
	// ServeStaticInvoice to the server.
	let serve_static_invoice_om = recipient
		.onion_messenger
		.next_onion_message_for_peer(server.node.get_our_node_id())
		.unwrap();
	(offer_paths_req, serve_static_invoice_om)
}

// Go through the flow of interactively building a `StaticInvoice` and storing it with the static
// invoice server, returning the invoice and messages that were exchanged along the way at the end.
fn pass_static_invoice_server_messages(
	server: &Node, recipient: &Node, recipient_id: Vec<u8>,
) -> StaticInvoiceServerFlowResult {
	// Force the server and recipient to send OMs directly to each other for testing simplicity.
	server.message_router.peers_override.lock().unwrap().push(recipient.node.get_our_node_id());
	recipient.message_router.peers_override.lock().unwrap().push(server.node.get_our_node_id());

	let (offer_paths_req, serve_static_invoice_om) =
		invoice_flow_up_to_send_serve_static_invoice(server, recipient);
	server
		.onion_messenger
		.handle_onion_message(recipient.node.get_our_node_id(), &serve_static_invoice_om);

	// Upon handling the ServeStaticInvoice message, the server's node surfaces an event indicating
	// that the static invoice should be persisted.
	let mut events = server.node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	let (invoice, invoice_slot, ack_path, invoice_request_path) = match events.pop().unwrap() {
		Event::PersistStaticInvoice {
			invoice,
			invoice_persisted_path,
			recipient_id: ev_id,
			invoice_slot,
			invoice_request_path,
		} => {
			assert_eq!(recipient_id, ev_id);
			(invoice, invoice_slot, invoice_persisted_path, invoice_request_path)
		},
		_ => panic!(),
	};

	// Once the static invoice is persisted, the server needs to call `static_invoice_persisted` with
	// the reply path to the ServeStaticInvoice message, to tell the recipient that their offer is
	// ready to be used for async payments.
	server.node.static_invoice_persisted(ack_path);
	let invoice_persisted_om = server
		.onion_messenger
		.next_onion_message_for_peer(recipient.node.get_our_node_id())
		.unwrap();
	recipient
		.onion_messenger
		.handle_onion_message(server.node.get_our_node_id(), &invoice_persisted_om);

	// Remove the peer restriction added above.
	server.message_router.peers_override.lock().unwrap().clear();
	recipient.message_router.peers_override.lock().unwrap().clear();

	StaticInvoiceServerFlowResult {
		offer_paths_request: offer_paths_req,
		static_invoice_persisted_message: invoice_persisted_om,
		invoice_request_path,
		invoice,
		invoice_slot,
	}
}

// Goes through the async receive onion message flow, returning the final release_held_htlc OM.
//
// Assumes the held_htlc_available message will be sent:
// 	 sender -> always_online_recipient_counterparty -> recipient.
//
// Returns: (held_htlc_available_om, release_held_htlc_om)
fn pass_async_payments_oms(
	static_invoice: StaticInvoice, sender: &Node, always_online_recipient_counterparty: &Node,
	recipient: &Node, recipient_id: Vec<u8>, invoice_request_path: BlindedMessagePath,
) -> (msgs::OnionMessage, msgs::OnionMessage) {
	let sender_node_id = sender.node.get_our_node_id();
	let always_online_node_id = always_online_recipient_counterparty.node.get_our_node_id();

	let invreq_om =
		sender.onion_messenger.next_onion_message_for_peer(always_online_node_id).unwrap();
	always_online_recipient_counterparty
		.onion_messenger
		.handle_onion_message(sender_node_id, &invreq_om);

	let mut events = always_online_recipient_counterparty.node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	let (reply_path, invoice_request) = match events.pop().unwrap() {
		Event::StaticInvoiceRequested {
			recipient_id: ev_id,
			invoice_slot: _,
			reply_path,
			invoice_request,
		} => {
			assert_eq!(recipient_id, ev_id);
			(reply_path, invoice_request)
		},
		_ => panic!(),
	};

	always_online_recipient_counterparty
		.node
		.respond_to_static_invoice_request(
			static_invoice,
			reply_path,
			invoice_request,
			invoice_request_path,
		)
		.unwrap();

	let _invreq_om = always_online_recipient_counterparty
		.onion_messenger
		.next_onion_message_for_peer(recipient.node.get_our_node_id())
		.unwrap();
	let static_invoice_om = always_online_recipient_counterparty
		.onion_messenger
		.next_onion_message_for_peer(sender_node_id)
		.unwrap();
	sender.onion_messenger.handle_onion_message(always_online_node_id, &static_invoice_om);
	// Check that the node will not lock in HTLCs yet.
	sender.node.process_pending_htlc_forwards();
	assert!(sender.node.get_and_clear_pending_msg_events().is_empty());

	let held_htlc_available_om_0_1 =
		sender.onion_messenger.next_onion_message_for_peer(always_online_node_id).unwrap();
	always_online_recipient_counterparty
		.onion_messenger
		.handle_onion_message(sender_node_id, &held_htlc_available_om_0_1);
	let held_htlc_available_om_1_2 = always_online_recipient_counterparty
		.onion_messenger
		.next_onion_message_for_peer(recipient.node.get_our_node_id())
		.unwrap();
	recipient
		.onion_messenger
		.handle_onion_message(always_online_node_id, &held_htlc_available_om_1_2);

	let release_held_htlc =
		recipient.onion_messenger.next_onion_message_for_peer(sender_node_id).unwrap();
	(held_htlc_available_om_1_2, release_held_htlc)
}

fn create_static_invoice_builder<'a>(
	recipient: &Node, offer: &'a Offer, offer_nonce: Nonce, relative_expiry: Option<Duration>,
) -> StaticInvoiceBuilder<'a> {
	let amount_msat = offer.amount().and_then(|amount| match amount {
		Amount::Bitcoin { amount_msats } => Some(amount_msats),
		Amount::Currency { .. } => None,
	});

	let relative_expiry = relative_expiry.unwrap_or(STATIC_INVOICE_DEFAULT_RELATIVE_EXPIRY);
	let relative_expiry_secs: u32 = relative_expiry.as_secs().try_into().unwrap_or(u32::MAX);

	let created_at = recipient.node.duration_since_epoch();
	let payment_secret = inbound_payment::create_for_spontaneous_payment(
		&recipient.keys_manager.get_expanded_key(),
		amount_msat,
		relative_expiry_secs,
		created_at.as_secs(),
		None,
	)
	.unwrap();

	recipient
		.node
		.flow
		.create_static_invoice_builder(
			&recipient.router,
			offer,
			offer_nonce,
			payment_secret,
			relative_expiry_secs,
			recipient.node.list_usable_channels(),
			recipient.node.test_get_peers_for_blinded_path(),
		)
		.unwrap()
}

fn create_static_invoice<T: secp256k1::Signing + secp256k1::Verification>(
	always_online_counterparty: &Node, recipient: &Node, relative_expiry: Option<Duration>,
	secp_ctx: &Secp256k1<T>,
) -> (Offer, StaticInvoice) {
	let entropy_source = recipient.keys_manager;

	let blinded_paths_to_always_online_node = always_online_counterparty
		.message_router
		.create_blinded_paths(
			always_online_counterparty.node.get_our_node_id(),
			always_online_counterparty.keys_manager.get_receive_auth_key(),
			MessageContext::Offers(OffersContext::InvoiceRequest { nonce: Nonce([42; 16]) }),
			Vec::new(),
			&secp_ctx,
		)
		.unwrap();
	let (offer_builder, offer_nonce) = recipient
		.node
		.flow
		.create_async_receive_offer_builder(entropy_source, blinded_paths_to_always_online_node)
		.unwrap();
	let offer = offer_builder.build().unwrap();
	let static_invoice =
		create_static_invoice_builder(recipient, &offer, offer_nonce, relative_expiry)
			.build_and_sign(&secp_ctx)
			.unwrap();
	(offer, static_invoice)
}

fn extract_payment_hash(event: &MessageSendEvent) -> PaymentHash {
	match event {
		MessageSendEvent::UpdateHTLCs { ref updates, .. } => {
			updates.update_add_htlcs[0].payment_hash
		},
		_ => panic!(),
	}
}

fn extract_payment_preimage(event: &Event) -> PaymentPreimage {
	match event {
		Event::PaymentClaimable {
			purpose: PaymentPurpose::Bolt12OfferPayment { payment_preimage, .. },
			..
		} => payment_preimage.unwrap(),
		_ => panic!(),
	}
}

fn expect_offer_paths_requests(recipient: &Node, next_hop_nodes: &[&Node]) {
	// We want to check that the async recipient has enqueued at least one `OfferPathsRequest` and no
	// other message types. Check this by iterating through all their outbound onion messages, peeling
	// multiple times if the messages are forwarded through other nodes.
	let offer_paths_reqs = extract_expected_om(
		recipient,
		next_hop_nodes,
		|peeled_onion| {
			matches!(
				peeled_onion,
				PeeledOnion::AsyncPayments(AsyncPaymentsMessage::OfferPathsRequest(_), _, _)
			)
		},
		|_| false,
	);
	assert!(!offer_paths_reqs.is_empty());
}

fn extract_invoice_request_om<'a>(
	payer: &'a Node, next_hop_nodes: &[&'a Node],
) -> (PublicKey, msgs::OnionMessage) {
	extract_expected_om(
		payer,
		next_hop_nodes,
		|peeled_onion| {
			matches!(peeled_onion, &PeeledOnion::Offers(OffersMessage::InvoiceRequest(_), _, _))
		},
		|_| false,
	)
	.pop()
	.unwrap()
}

fn extract_static_invoice_om<'a>(
	invoice_server: &'a Node, next_hop_nodes: &[&'a Node],
) -> (PublicKey, msgs::OnionMessage, StaticInvoice) {
	let mut static_invoice = None;
	let mut expected_msg_type = |peeled_onion: &_| {
		if let PeeledOnion::Offers(OffersMessage::StaticInvoice(inv), _, _) = peeled_onion {
			static_invoice = Some(inv.clone());
			true
		} else {
			false
		}
	};
	let expected_msg_type_to_ignore = |peeled_onion: &_| {
		matches!(peeled_onion, &PeeledOnion::Offers(OffersMessage::InvoiceRequest(_), _, _))
	};
	let (peer_id, om) = extract_expected_om(
		invoice_server,
		next_hop_nodes,
		expected_msg_type,
		expected_msg_type_to_ignore,
	)
	.pop()
	.unwrap();
	(peer_id, om, static_invoice.unwrap())
}

fn extract_held_htlc_available_oms<'a>(
	payer: &'a Node, next_hop_nodes: &[&'a Node],
) -> Vec<(PublicKey, msgs::OnionMessage)> {
	extract_expected_om(
		payer,
		next_hop_nodes,
		|peeled_onion| {
			matches!(
				peeled_onion,
				&PeeledOnion::AsyncPayments(AsyncPaymentsMessage::HeldHtlcAvailable(_), _, _)
			)
		},
		|_| false,
	)
}

fn extract_release_htlc_oms<'a>(
	recipient: &'a Node, next_hop_nodes: &[&'a Node],
) -> Vec<(PublicKey, msgs::OnionMessage)> {
	extract_expected_om(
		recipient,
		next_hop_nodes,
		|peeled_onion| {
			matches!(
				peeled_onion,
				&PeeledOnion::AsyncPayments(AsyncPaymentsMessage::ReleaseHeldHtlc(_), _, _)
			)
		},
		|_| false,
	)
}

fn extract_expected_om<F1, F2>(
	msg_sender: &Node, next_hop_nodes: &[&Node], mut expected_msg_type: F1,
	expected_msg_type_to_ignore: F2,
) -> Vec<(PublicKey, msgs::OnionMessage)>
where
	F1: FnMut(&PeeledOnion<Infallible>) -> bool,
	F2: Fn(&PeeledOnion<Infallible>) -> bool,
{
	let per_msg_recipient_msgs = msg_sender.onion_messenger.release_pending_msgs();
	let mut pk_to_msg = Vec::new();
	for (pk, msgs) in per_msg_recipient_msgs {
		for msg in msgs {
			pk_to_msg.push((pk, msg));
		}
	}
	let mut msgs = Vec::new();
	while let Some((pk, msg)) = pk_to_msg.pop() {
		let node = next_hop_nodes.iter().find(|node| node.node.get_our_node_id() == pk).unwrap();
		let peeled_msg = node.onion_messenger.peel_onion_message(&msg).unwrap();
		match peeled_msg {
			PeeledOnion::Forward(next_hop, msg) => {
				let next_pk = match next_hop {
					NextMessageHop::NodeId(pk) => pk,
					NextMessageHop::ShortChannelId(scid) => {
						let mut next_pk = None;
						for node in next_hop_nodes {
							if node.node.get_our_node_id() == pk {
								continue;
							}
							for channel in node.node.list_channels() {
								if channel.short_channel_id.unwrap() == scid
									|| channel.inbound_scid_alias.unwrap_or(0) == scid
								{
									next_pk = Some(node.node.get_our_node_id());
								}
							}
						}
						next_pk.unwrap()
					},
				};
				pk_to_msg.push((next_pk, msg));
			},
			peeled_onion if expected_msg_type(&peeled_onion) => msgs.push((pk, msg)),
			peeled_onion if expected_msg_type_to_ignore(&peeled_onion) => {},
			peeled_onion => panic!("Unexpected message: {:?}", peeled_onion),
		}
	}
	assert!(!msgs.is_empty());
	msgs
}

fn advance_time_by(duration: Duration, node: &Node) {
	let target_time = (node.node.duration_since_epoch() + duration).as_secs() as u32;
	let block = create_dummy_block(node.best_block_hash(), target_time, Vec::new());
	connect_block(node, &block);
}

fn often_offline_node_cfg() -> UserConfig {
	let mut cfg = test_default_channel_config();
	cfg.channel_handshake_config.announce_for_forwarding = false;
	cfg.channel_handshake_limits.force_announced_channel_preference = true;
	cfg.hold_outbound_htlcs_at_next_hop = true;
	cfg
}

fn unify_blockheight_across_nodes(nodes: &[Node]) {
	// Make sure all nodes are at the same block height
	let node_max_height =
		nodes.iter().map(|node| node.blocks.lock().unwrap().len()).max().unwrap() as u32;
	for node in nodes.iter() {
		connect_blocks(node, node_max_height - node.best_block_info().1);
	}
}

// Interactively builds an async offer and initiates payment to it from an often-offline sender,
// up to but not including providing the static invoice to the sender.
//
// Assumes that the first node is the async sender and the last hop is the async recipient, with the
// middle node(s) being announced nodes acting as LSP and/or invoice server. At least 1 middle node
// must be present.
//
// Returns the `StaticInvoice` and the onion message containing it, as well as the direct peer
// sending the static invoice OM to the sender.
fn build_async_offer_and_init_payment(
	amt_msat: u64, nodes: &[Node],
) -> (StaticInvoice, PublicKey, msgs::OnionMessage) {
	let sender = &nodes[0];
	let sender_lsp = &nodes[1];
	let invoice_server = &nodes[nodes.len() - 2];
	let recipient = nodes.last().unwrap();

	let recipient_id = vec![42; 32];
	let inv_server_paths =
		invoice_server.node.blinded_paths_for_async_recipient(recipient_id.clone(), None).unwrap();
	recipient.node.set_paths_to_static_invoice_server(inv_server_paths).unwrap();
	expect_offer_paths_requests(recipient, &[sender, sender_lsp, invoice_server]);
	let invoice_flow_res =
		pass_static_invoice_server_messages(invoice_server, recipient, recipient_id.clone());
	let invoice = invoice_flow_res.invoice;
	let invreq_path = invoice_flow_res.invoice_request_path;

	let offer = recipient.node.get_async_receive_offer().unwrap();
	let payment_id = PaymentId([1; 32]);
	sender.node.pay_for_offer(&offer, Some(amt_msat), payment_id, Default::default()).unwrap();

	// Forward invreq to server, pass static invoice back
	let (peer_id, invreq_om) = extract_invoice_request_om(sender, &[sender_lsp, invoice_server]);
	invoice_server.onion_messenger.handle_onion_message(peer_id, &invreq_om);

	let mut events = invoice_server.node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	let (reply_path, invreq) = match events.pop().unwrap() {
		Event::StaticInvoiceRequested {
			recipient_id: ev_id, reply_path, invoice_request, ..
		} => {
			assert_eq!(recipient_id, ev_id);
			(reply_path, invoice_request)
		},
		_ => panic!(),
	};
	invoice_server
		.node
		.respond_to_static_invoice_request(invoice.clone(), reply_path, invreq, invreq_path)
		.unwrap();
	let (peer_node_id, static_invoice_om, _) =
		extract_static_invoice_om(invoice_server, &[sender_lsp, sender, recipient]);

	(invoice, peer_node_id, static_invoice_om)
}

fn lock_in_htlc_for_static_invoice(
	static_invoice_om: &msgs::OnionMessage, om_peer: PublicKey, sender: &Node, sender_lsp: &Node,
) -> PaymentHash {
	// The sender should lock in the held HTLC with their LSP right after receiving the static invoice.
	sender.onion_messenger.handle_onion_message(om_peer, &static_invoice_om);
	check_added_monitors(sender, 1);
	let commitment_update = get_htlc_update_msgs(&sender, &sender_lsp.node.get_our_node_id());
	let update_add = commitment_update.update_add_htlcs[0].clone();
	let payment_hash = update_add.payment_hash;
	assert!(update_add.hold_htlc.is_some());
	sender_lsp.node.handle_update_add_htlc(sender.node.get_our_node_id(), &update_add);
	let commitment = &commitment_update.commitment_signed;
	do_commitment_signed_dance(sender_lsp, sender, commitment, false, true);
	payment_hash
}

#[test]
fn invalid_keysend_payment_secret() {
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 0);
	let chan_upd_1_2 =
		create_announced_chan_between_nodes_with_value(&nodes, 1, 2, 1_000_000, 0).0.contents;

	let invalid_payment_secret = PaymentSecret([42; 32]);
	let amt_msat = 5000;
	let keysend_preimage = PaymentPreimage([42; 32]);
	let route_params = get_blinded_route_parameters(
		amt_msat,
		invalid_payment_secret,
		1,
		1_0000_0000,
		nodes.iter().skip(1).map(|n| n.node.get_our_node_id()).collect(),
		&[&chan_upd_1_2],
		&chanmon_cfgs[2].keys_manager,
	);

	let payment_hash = nodes[0]
		.node
		.send_spontaneous_payment(
			Some(keysend_preimage),
			RecipientOnionFields::spontaneous_empty(),
			PaymentId(keysend_preimage.0),
			route_params,
			Retry::Attempts(0),
		)
		.unwrap();
	check_added_monitors(&nodes[0], 1);

	let expected_route: &[&[&Node]] = &[&[&nodes[1], &nodes[2]]];
	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);

	let ev = remove_first_msg_event_to_node(&nodes[1].node.get_our_node_id(), &mut events);
	let args =
		PassAlongPathArgs::new(&nodes[0], &expected_route[0], amt_msat, payment_hash, ev.clone())
			.with_payment_secret(invalid_payment_secret)
			.with_payment_preimage(keysend_preimage)
			.expect_failure(HTLCHandlingFailureType::Receive { payment_hash });
	do_pass_along_path(args);

	let updates_2_1 = get_htlc_update_msgs(&nodes[2], &nodes[1].node.get_our_node_id());
	assert_eq!(updates_2_1.update_fail_malformed_htlcs.len(), 1);
	let update_malformed = &updates_2_1.update_fail_malformed_htlcs[0];
	assert_eq!(update_malformed.sha256_of_onion, [0; 32]);
	assert_eq!(
		update_malformed.failure_code,
		LocalHTLCFailureReason::InvalidOnionBlinding.failure_code()
	);
	nodes[1]
		.node
		.handle_update_fail_malformed_htlc(nodes[2].node.get_our_node_id(), update_malformed);
	do_commitment_signed_dance(&nodes[1], &nodes[2], &updates_2_1.commitment_signed, true, false);

	let updates_1_0 = get_htlc_update_msgs(&nodes[1], &nodes[0].node.get_our_node_id());
	assert_eq!(updates_1_0.update_fail_htlcs.len(), 1);
	nodes[0].node.handle_update_fail_htlc(
		nodes[1].node.get_our_node_id(),
		&updates_1_0.update_fail_htlcs[0],
	);
	do_commitment_signed_dance(&nodes[0], &nodes[1], &updates_1_0.commitment_signed, false, false);
	expect_payment_failed_conditions(
		&nodes[0],
		payment_hash,
		false,
		PaymentFailedConditions::new()
			.expected_htlc_error_data(LocalHTLCFailureReason::InvalidOnionBlinding, &[0; 32]),
	);
}

#[test]
fn static_invoice_unknown_required_features() {
	// Test that we will fail to pay a static invoice with unsupported required features.
	let secp_ctx = Secp256k1::new();
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	let entropy_source = nodes[2].keys_manager;
	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 0);
	create_unannounced_chan_between_nodes_with_value(&nodes, 1, 2, 1_000_000, 0);

	// Manually construct a static invoice so we can set unknown required features.
	let blinded_paths_to_always_online_node = nodes[1]
		.message_router
		.create_blinded_paths(
			nodes[1].node.get_our_node_id(),
			nodes[1].keys_manager.get_receive_auth_key(),
			MessageContext::Offers(OffersContext::InvoiceRequest { nonce: Nonce([42; 16]) }),
			Vec::new(),
			&secp_ctx,
		)
		.unwrap();
	let (offer_builder, nonce) = nodes[2]
		.node
		.flow
		.create_async_receive_offer_builder(entropy_source, blinded_paths_to_always_online_node)
		.unwrap();
	let offer = offer_builder.build().unwrap();
	let static_invoice_unknown_req_features =
		create_static_invoice_builder(&nodes[2], &offer, nonce, None)
			.features_unchecked(Bolt12InvoiceFeatures::unknown())
			.build_and_sign(&secp_ctx)
			.unwrap();

	// Initiate payment to the offer corresponding to the manually-constructed invoice that has
	// unknown required features.
	let amt_msat = 5000;
	let payment_id = PaymentId([1; 32]);
	nodes[0].node.pay_for_offer(&offer, Some(amt_msat), payment_id, Default::default()).unwrap();

	// Don't forward the invreq since the invoice was created outside of the normal flow, instead
	// manually construct the response.
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

	// Check that paying the static invoice fails as expected with
	// `PaymentFailureReason::UnknownRequiredFeatures`.
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
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 0);
	create_unannounced_chan_between_nodes_with_value(&nodes, 1, 2, 1_000_000, 0);

	let recipient_id = vec![42; 32];
	let inv_server_paths =
		nodes[1].node.blinded_paths_for_async_recipient(recipient_id.clone(), None).unwrap();
	nodes[2].node.set_paths_to_static_invoice_server(inv_server_paths).unwrap();
	expect_offer_paths_requests(&nodes[2], &[&nodes[0], &nodes[1]]);

	// Initiate payment to the sender's intended offer.
	let valid_static_invoice =
		pass_static_invoice_server_messages(&nodes[1], &nodes[2], recipient_id.clone()).invoice;
	let offer = nodes[2].node.get_async_receive_offer().unwrap();

	// Create a static invoice to be sent over the reply path containing the original payment_id, but
	// the static invoice corresponds to a different offer than was originally paid.
	let invoice_flow_res =
		pass_static_invoice_server_messages(&nodes[1], &nodes[2], recipient_id.clone());
	let unexpected_static_invoice = invoice_flow_res.invoice;

	let amt_msat = 5000;
	let payment_id = PaymentId([1; 32]);
	nodes[0].node.pay_for_offer(&offer, Some(amt_msat), payment_id, Default::default()).unwrap();

	let invreq_om = nodes[0]
		.onion_messenger
		.next_onion_message_for_peer(nodes[1].node.get_our_node_id())
		.unwrap();
	nodes[1].onion_messenger.handle_onion_message(nodes[0].node.get_our_node_id(), &invreq_om);

	let mut events = nodes[1].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	let (reply_path, invoice_request) = match events.pop().unwrap() {
		Event::StaticInvoiceRequested {
			recipient_id: ev_id,
			invoice_slot: _,
			reply_path,
			invoice_request,
		} => {
			assert_eq!(recipient_id, ev_id);
			(reply_path, invoice_request)
		},
		_ => panic!(),
	};

	// Check that the sender will ignore the unexpected static invoice.
	nodes[1]
		.node
		.respond_to_static_invoice_request(
			unexpected_static_invoice,
			reply_path.clone(),
			invoice_request.clone(),
			invoice_flow_res.invoice_request_path.clone(),
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
	nodes[1]
		.node
		.respond_to_static_invoice_request(
			valid_static_invoice.clone(),
			reply_path.clone(),
			invoice_request.clone(),
			invoice_flow_res.invoice_request_path.clone(),
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
		.node
		.respond_to_static_invoice_request(
			valid_static_invoice,
			reply_path,
			invoice_request,
			invoice_flow_res.invoice_request_path,
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
fn ignore_duplicate_invoice() {
	// When a sender tries to pay an async recipient it could potentially end up receiving two
	// invoices: one static invoice that it received from always-online node and a fresh invoice
	// received from async recipient in case it was online to reply to request. Test that it
	// will only pay one of the two invoices.
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);

	let mut allow_priv_chan_fwds_cfg = test_default_channel_config();
	allow_priv_chan_fwds_cfg.accept_forwards_to_priv_channels = true;
	let node_chanmgrs =
		create_node_chanmgrs(3, &node_cfgs, &[None, Some(allow_priv_chan_fwds_cfg), None]);

	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 0);
	create_unannounced_chan_between_nodes_with_value(&nodes, 1, 2, 1_000_000, 0);

	let sender = &nodes[0];
	let always_online_node = &nodes[1];
	let async_recipient = &nodes[2];

	let recipient_id = vec![42; 32];
	let inv_server_paths = always_online_node
		.node
		.blinded_paths_for_async_recipient(recipient_id.clone(), None)
		.unwrap();
	async_recipient.node.set_paths_to_static_invoice_server(inv_server_paths).unwrap();
	expect_offer_paths_requests(async_recipient, &[sender, always_online_node]);

	let invoice_flow_res = pass_static_invoice_server_messages(
		always_online_node,
		async_recipient,
		recipient_id.clone(),
	);
	let static_invoice = invoice_flow_res.invoice;
	assert!(static_invoice.invoice_features().supports_basic_mpp());
	let offer = async_recipient.node.get_async_receive_offer().unwrap();
	let amt_msat = 5000;
	let payment_id = PaymentId([1; 32]);
	sender.node.pay_for_offer(&offer, Some(amt_msat), payment_id, Default::default()).unwrap();

	let sender_node_id = sender.node.get_our_node_id();
	let always_online_node_id = always_online_node.node.get_our_node_id();
	let async_recipient_id = async_recipient.node.get_our_node_id();

	let invreq_om =
		sender.onion_messenger.next_onion_message_for_peer(always_online_node_id).unwrap();
	always_online_node.onion_messenger.handle_onion_message(sender_node_id, &invreq_om);

	let mut events = always_online_node.node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	let (reply_path, invoice_request) = match events.pop().unwrap() {
		Event::StaticInvoiceRequested {
			recipient_id: ev_id,
			invoice_slot: _,
			reply_path,
			invoice_request,
		} => {
			assert_eq!(recipient_id, ev_id);
			(reply_path, invoice_request)
		},
		_ => panic!(),
	};

	always_online_node
		.node
		.respond_to_static_invoice_request(
			static_invoice.clone(),
			reply_path,
			invoice_request,
			invoice_flow_res.invoice_request_path.clone(),
		)
		.unwrap();

	// After calling `respond_to_static_invoice_request` the next two messages should be the
	// invoice request to the intended for the async recipient and the static invoice to the
	// payer.
	let invreq_om =
		always_online_node.onion_messenger.next_onion_message_for_peer(async_recipient_id).unwrap();
	let peeled_msg = async_recipient.onion_messenger.peel_onion_message(&invreq_om).unwrap();
	assert!(matches!(peeled_msg, PeeledOnion::Offers(OffersMessage::InvoiceRequest(_), _, _)));

	let static_invoice_om =
		always_online_node.onion_messenger.next_onion_message_for_peer(sender_node_id).unwrap();
	let peeled_msg = sender.onion_messenger.peel_onion_message(&static_invoice_om).unwrap();
	assert!(matches!(peeled_msg, PeeledOnion::Offers(OffersMessage::StaticInvoice(_), _, _)));

	// Handling the `invoice_request` from the async recipient we should get back an invoice.
	async_recipient.onion_messenger.handle_onion_message(always_online_node_id, &invreq_om);
	let invoice_om =
		async_recipient.onion_messenger.next_onion_message_for_peer(sender_node_id).unwrap();

	// First pay the static invoice.
	sender.onion_messenger.handle_onion_message(always_online_node_id, &static_invoice_om);

	let held_htlc_available_om_0_1 =
		sender.onion_messenger.next_onion_message_for_peer(always_online_node_id).unwrap();
	always_online_node
		.onion_messenger
		.handle_onion_message(sender_node_id, &held_htlc_available_om_0_1);
	let held_htlc_available_om_1_2 =
		always_online_node.onion_messenger.next_onion_message_for_peer(async_recipient_id).unwrap();
	async_recipient
		.onion_messenger
		.handle_onion_message(always_online_node_id, &held_htlc_available_om_1_2);

	let release_held_htlc_om =
		async_recipient.onion_messenger.next_onion_message_for_peer(sender_node_id).unwrap();
	sender.onion_messenger.handle_onion_message(async_recipient_id, &release_held_htlc_om);

	let mut events = sender.node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let ev = remove_first_msg_event_to_node(&always_online_node_id, &mut events);
	let payment_hash = extract_payment_hash(&ev);
	check_added_monitors(&sender, 1);

	let route: &[&[&Node]] = &[&[always_online_node, async_recipient]];
	let args = PassAlongPathArgs::new(sender, route[0], amt_msat, payment_hash, ev);
	let claimable_ev = do_pass_along_path(args).unwrap();
	let keysend_preimage = extract_payment_preimage(&claimable_ev);
	let (res, _) =
		claim_payment_along_route(ClaimAlongRouteArgs::new(sender, route, keysend_preimage));
	assert_eq!(res, Some(PaidBolt12Invoice::StaticInvoice(static_invoice.clone())));

	// After paying the static invoice, check that regular invoice received from async recipient is ignored.
	match sender.onion_messenger.peel_onion_message(&invoice_om) {
		Ok(PeeledOnion::Offers(OffersMessage::Invoice(invoice), context, _)) => {
			assert!(matches!(
				sender.node.send_payment_for_bolt12_invoice(&invoice, context.as_ref()),
				Err(Bolt12PaymentError::DuplicateInvoice)
			))
		},
		_ => panic!(),
	}

	// Now handle case where the sender pays regular invoice and ignores static invoice.
	let payment_id = PaymentId([2; 32]);
	sender.node.pay_for_offer(&offer, Some(amt_msat), payment_id, Default::default()).unwrap();

	let invreq_om =
		sender.onion_messenger.next_onion_message_for_peer(always_online_node_id).unwrap();
	always_online_node.onion_messenger.handle_onion_message(sender_node_id, &invreq_om);

	let mut events = always_online_node.node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	let (reply_path, invoice_request) = match events.pop().unwrap() {
		Event::StaticInvoiceRequested {
			recipient_id: ev_id,
			invoice_slot: _,
			reply_path,
			invoice_request,
		} => {
			assert_eq!(recipient_id, ev_id);
			(reply_path, invoice_request)
		},
		_ => panic!(),
	};

	always_online_node
		.node
		.respond_to_static_invoice_request(
			static_invoice.clone(),
			reply_path,
			invoice_request,
			invoice_flow_res.invoice_request_path,
		)
		.unwrap();

	let invreq_om =
		always_online_node.onion_messenger.next_onion_message_for_peer(async_recipient_id).unwrap();
	let peeled_msg = async_recipient.onion_messenger.peel_onion_message(&invreq_om).unwrap();
	assert!(matches!(peeled_msg, PeeledOnion::Offers(OffersMessage::InvoiceRequest(_), _, _)));

	let static_invoice_om =
		always_online_node.onion_messenger.next_onion_message_for_peer(sender_node_id).unwrap();
	let peeled_msg = sender.onion_messenger.peel_onion_message(&static_invoice_om).unwrap();
	assert!(matches!(peeled_msg, PeeledOnion::Offers(OffersMessage::StaticInvoice(_), _, _)));

	async_recipient.onion_messenger.handle_onion_message(always_online_node_id, &invreq_om);
	let invoice_om =
		async_recipient.onion_messenger.next_onion_message_for_peer(sender_node_id).unwrap();

	let invoice = match sender.onion_messenger.peel_onion_message(&invoice_om) {
		Ok(PeeledOnion::Offers(OffersMessage::Invoice(invoice), _, _)) => invoice,
		_ => panic!(),
	};

	sender.onion_messenger.handle_onion_message(async_recipient_id, &invoice_om);

	let mut events = sender.node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let ev = remove_first_msg_event_to_node(&always_online_node_id, &mut events);
	let payment_hash = extract_payment_hash(&ev);
	check_added_monitors(&sender, 1);

	let args = PassAlongPathArgs::new(sender, route[0], amt_msat, payment_hash, ev)
		.without_clearing_recipient_events();
	do_pass_along_path(args);

	let payment_preimage = match get_event!(async_recipient, Event::PaymentClaimable) {
		Event::PaymentClaimable { purpose, .. } => purpose.preimage().unwrap(),
		_ => panic!("No Event::PaymentClaimable"),
	};

	// After paying invoice, check that static invoice is ignored.
	let res = claim_payment(sender, route[0], payment_preimage);
	assert_eq!(res, Some(PaidBolt12Invoice::Bolt12Invoice(invoice)));

	sender.onion_messenger.handle_onion_message(always_online_node_id, &static_invoice_om);
	let async_pmts_msgs = AsyncPaymentsMessageHandler::release_pending_messages(sender.node);
	assert!(async_pmts_msgs.is_empty());
	assert!(nodes[0].node.get_and_clear_pending_events().is_empty());
}

#[test]
fn async_receive_flow_success() {
	// Test that an always-online sender can successfully pay an async receiver.

	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);

	let mut allow_priv_chan_fwds_cfg = test_default_channel_config();
	allow_priv_chan_fwds_cfg.accept_forwards_to_priv_channels = true;
	let node_chanmgrs =
		create_node_chanmgrs(3, &node_cfgs, &[None, Some(allow_priv_chan_fwds_cfg), None]);

	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 0);
	create_unannounced_chan_between_nodes_with_value(&nodes, 1, 2, 1_000_000, 0);

	let recipient_id = vec![42; 32];
	let inv_server_paths =
		nodes[1].node.blinded_paths_for_async_recipient(recipient_id.clone(), None).unwrap();
	nodes[2].node.set_paths_to_static_invoice_server(inv_server_paths).unwrap();
	expect_offer_paths_requests(&nodes[2], &[&nodes[0], &nodes[1]]);

	let invoice_flow_res =
		pass_static_invoice_server_messages(&nodes[1], &nodes[2], recipient_id.clone());
	let static_invoice = invoice_flow_res.invoice;
	assert!(static_invoice.invoice_features().supports_basic_mpp());
	let offer = nodes[2].node.get_async_receive_offer().unwrap();
	let amt_msat = 5000;
	let payment_id = PaymentId([1; 32]);
	nodes[0].node.pay_for_offer(&offer, Some(amt_msat), payment_id, Default::default()).unwrap();
	let release_held_htlc_om = pass_async_payments_oms(
		static_invoice.clone(),
		&nodes[0],
		&nodes[1],
		&nodes[2],
		recipient_id,
		invoice_flow_res.invoice_request_path,
	)
	.1;
	nodes[0]
		.onion_messenger
		.handle_onion_message(nodes[2].node.get_our_node_id(), &release_held_htlc_om);

	// Check that we've queued the HTLCs of the async keysend payment.
	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let ev = remove_first_msg_event_to_node(&nodes[1].node.get_our_node_id(), &mut events);
	let payment_hash = extract_payment_hash(&ev);
	check_added_monitors(&nodes[0], 1);

	// Receiving a duplicate release_htlc message doesn't result in duplicate payment.
	nodes[0]
		.onion_messenger
		.handle_onion_message(nodes[2].node.get_our_node_id(), &release_held_htlc_om);
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());

	let route: &[&[&Node]] = &[&[&nodes[1], &nodes[2]]];
	let args = PassAlongPathArgs::new(&nodes[0], route[0], amt_msat, payment_hash, ev);
	let claimable_ev = do_pass_along_path(args).unwrap();
	let keysend_preimage = extract_payment_preimage(&claimable_ev);
	let (res, _) =
		claim_payment_along_route(ClaimAlongRouteArgs::new(&nodes[0], route, keysend_preimage));
	assert_eq!(res, Some(PaidBolt12Invoice::StaticInvoice(static_invoice)));
}

#[cfg_attr(feature = "std", ignore)]
#[test]
fn expired_static_invoice_fail() {
	// Test that if we receive an expired static invoice we'll fail the payment.
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 0);
	create_unannounced_chan_between_nodes_with_value(&nodes, 1, 2, 1_000_000, 0);

	let recipient_id = vec![42; 32];
	let inv_server_paths =
		nodes[1].node.blinded_paths_for_async_recipient(recipient_id.clone(), None).unwrap();
	nodes[2].node.set_paths_to_static_invoice_server(inv_server_paths).unwrap();
	expect_offer_paths_requests(&nodes[2], &[&nodes[0], &nodes[1]]);

	let invoice_flow_res =
		pass_static_invoice_server_messages(&nodes[1], &nodes[2], recipient_id.clone());
	let static_invoice = invoice_flow_res.invoice;
	let offer = nodes[2].node.get_async_receive_offer().unwrap();

	let amt_msat = 5000;
	let payment_id = PaymentId([1; 32]);
	nodes[0].node.pay_for_offer(&offer, Some(amt_msat), payment_id, Default::default()).unwrap();

	let invreq_om = nodes[0]
		.onion_messenger
		.next_onion_message_for_peer(nodes[1].node.get_our_node_id())
		.unwrap();
	nodes[1].onion_messenger.handle_onion_message(nodes[0].node.get_our_node_id(), &invreq_om);

	let mut events = nodes[1].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	let (reply_path, invoice_request) = match events.pop().unwrap() {
		Event::StaticInvoiceRequested { reply_path, invoice_request, .. } => {
			(reply_path, invoice_request)
		},
		_ => panic!(),
	};

	nodes[1]
		.node
		.respond_to_static_invoice_request(
			static_invoice.clone(),
			reply_path,
			invoice_request,
			invoice_flow_res.invoice_request_path,
		)
		.unwrap();
	let static_invoice_om = nodes[1]
		.onion_messenger
		.next_onion_message_for_peer(nodes[0].node.get_our_node_id())
		.unwrap();

	// Wait until the static invoice expires before providing it to the sender.
	let block = create_dummy_block(
		nodes[0].best_block_hash(),
		(static_invoice.created_at() + static_invoice.relative_expiry()).as_secs() as u32 + 1u32,
		Vec::new(),
	);
	connect_block(&nodes[0], &block);
	nodes[0]
		.onion_messenger
		.handle_onion_message(nodes[1].node.get_our_node_id(), &static_invoice_om);

	let events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		Event::PaymentFailed { payment_id: ev_payment_id, reason, .. } => {
			assert_eq!(reason.unwrap(), PaymentFailureReason::PaymentExpired);
			assert_eq!(ev_payment_id, payment_id);
		},
		_ => panic!(),
	}
	// TODO: the sender doesn't reply with InvoiceError right now because the always-online node
	// doesn't currently provide them with a reply path to do so.
}

#[cfg_attr(feature = "std", ignore)]
#[test]
fn timeout_unreleased_payment() {
	// If a server holds a pending HTLC for too long, payment is considered expired.
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 0);
	create_unannounced_chan_between_nodes_with_value(&nodes, 1, 2, 1_000_000, 0);

	let sender = &nodes[0];
	let server = &nodes[1];
	let recipient = &nodes[2];

	let recipient_id = vec![42; 32];
	let inv_server_paths =
		server.node.blinded_paths_for_async_recipient(recipient_id.clone(), None).unwrap();
	recipient.node.set_paths_to_static_invoice_server(inv_server_paths).unwrap();
	expect_offer_paths_requests(&nodes[2], &[&nodes[0], &nodes[1]]);

	let invoice_flow_res =
		pass_static_invoice_server_messages(server, recipient, recipient_id.clone());
	let static_invoice = invoice_flow_res.invoice;
	let offer = recipient.node.get_async_receive_offer().unwrap();

	let amt_msat = 5000;
	let payment_id = PaymentId([1; 32]);
	sender.node.pay_for_offer(&offer, Some(amt_msat), payment_id, Default::default()).unwrap();

	let invreq_om =
		sender.onion_messenger.next_onion_message_for_peer(server.node.get_our_node_id()).unwrap();
	server.onion_messenger.handle_onion_message(sender.node.get_our_node_id(), &invreq_om);

	let mut events = server.node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	let (reply_path, invoice_request) = match events.pop().unwrap() {
		Event::StaticInvoiceRequested { reply_path, invoice_request, .. } => {
			(reply_path, invoice_request)
		},
		_ => panic!(),
	};

	server
		.node
		.respond_to_static_invoice_request(
			static_invoice.clone(),
			reply_path,
			invoice_request,
			invoice_flow_res.invoice_request_path,
		)
		.unwrap();
	let static_invoice_om =
		server.onion_messenger.next_onion_message_for_peer(sender.node.get_our_node_id()).unwrap();

	// We handle the static invoice to held the pending HTLC
	sender.onion_messenger.handle_onion_message(server.node.get_our_node_id(), &static_invoice_om);

	// We advance enough time to expire the payment.
	// We add 2 hours as is the margin added to remove stale payments in non-std implementation.
	let timeout_time_expiry = TEST_ASYNC_PAYMENT_TIMEOUT_RELATIVE_EXPIRY
		+ Duration::from_secs(7200)
		+ Duration::from_secs(1);
	advance_time_by(timeout_time_expiry, sender);
	sender.node.timer_tick_occurred();
	let events = sender.node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		Event::PaymentFailed { payment_id: ev_payment_id, reason, .. } => {
			assert_eq!(reason.unwrap(), PaymentFailureReason::PaymentExpired);
			assert_eq!(ev_payment_id, payment_id);
		},
		_ => panic!(),
	}
}

#[test]
fn async_receive_mpp() {
	// An MPP payment from an always-online sender to an often-offline recipient.
	let chanmon_cfgs = create_chanmon_cfgs(4);
	let node_cfgs = create_node_cfgs(4, &chanmon_cfgs);

	let mut allow_priv_chan_fwds_cfg = test_default_channel_config();
	allow_priv_chan_fwds_cfg.accept_forwards_to_priv_channels = true;

	let node_chanmgrs = create_node_chanmgrs(
		4,
		&node_cfgs,
		&[None, Some(allow_priv_chan_fwds_cfg.clone()), Some(allow_priv_chan_fwds_cfg), None],
	);
	let nodes = create_network(4, &node_cfgs, &node_chanmgrs);

	// Create this network topology:
	//      n1
	//    /    \
	// n0       n3
	//    \    /
	//      n2
	create_announced_chan_between_nodes(&nodes, 0, 1);
	create_announced_chan_between_nodes(&nodes, 0, 2);
	create_unannounced_chan_between_nodes_with_value(&nodes, 1, 3, 1_000_000, 0);
	create_unannounced_chan_between_nodes_with_value(&nodes, 2, 3, 1_000_000, 0);

	// Ensure all nodes start at the same height.
	connect_blocks(&nodes[0], 4 * CHAN_CONFIRM_DEPTH + 1 - nodes[0].best_block_info().1);
	connect_blocks(&nodes[1], 4 * CHAN_CONFIRM_DEPTH + 1 - nodes[1].best_block_info().1);
	connect_blocks(&nodes[2], 4 * CHAN_CONFIRM_DEPTH + 1 - nodes[2].best_block_info().1);
	connect_blocks(&nodes[3], 4 * CHAN_CONFIRM_DEPTH + 1 - nodes[3].best_block_info().1);

	let recipient_id = vec![42; 32];
	let inv_server_paths =
		nodes[1].node.blinded_paths_for_async_recipient(recipient_id.clone(), None).unwrap();
	nodes[3].node.set_paths_to_static_invoice_server(inv_server_paths).unwrap();
	expect_offer_paths_requests(&nodes[3], &[&nodes[0], &nodes[1], &nodes[2]]);

	let invoice_flow_res =
		pass_static_invoice_server_messages(&nodes[1], &nodes[3], recipient_id.clone());
	let static_invoice = invoice_flow_res.invoice;
	let offer = nodes[3].node.get_async_receive_offer().unwrap();

	let amt_msat = 15_000_000;
	let payment_id = PaymentId([1; 32]);
	nodes[0].node.pay_for_offer(&offer, Some(amt_msat), payment_id, Default::default()).unwrap();
	let release_held_htlc_om_3_0 = pass_async_payments_oms(
		static_invoice,
		&nodes[0],
		&nodes[1],
		&nodes[3],
		recipient_id,
		invoice_flow_res.invoice_request_path,
	)
	.1;
	nodes[0]
		.onion_messenger
		.handle_onion_message(nodes[3].node.get_our_node_id(), &release_held_htlc_om_3_0);
	check_added_monitors(&nodes[0], 2);

	let expected_route: &[&[&Node]] = &[&[&nodes[1], &nodes[3]], &[&nodes[2], &nodes[3]]];
	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 2);

	let ev = remove_first_msg_event_to_node(&nodes[1].node.get_our_node_id(), &mut events);
	let payment_hash = match ev {
		MessageSendEvent::UpdateHTLCs { ref updates, .. } => {
			updates.update_add_htlcs[0].payment_hash
		},
		_ => panic!(),
	};

	let args = PassAlongPathArgs::new(&nodes[0], expected_route[0], amt_msat, payment_hash, ev)
		.without_claimable_event();
	do_pass_along_path(args);

	let ev = remove_first_msg_event_to_node(&nodes[2].node.get_our_node_id(), &mut events);
	let args = PassAlongPathArgs::new(&nodes[0], expected_route[1], amt_msat, payment_hash, ev);
	let claimable_ev = do_pass_along_path(args).unwrap();
	let keysend_preimage = match claimable_ev {
		Event::PaymentClaimable {
			purpose: PaymentPurpose::Bolt12OfferPayment { payment_preimage, .. },
			..
		} => payment_preimage.unwrap(),
		_ => panic!(),
	};
	claim_payment_along_route(ClaimAlongRouteArgs::new(
		&nodes[0],
		expected_route,
		keysend_preimage,
	));
}

#[test]
fn amount_doesnt_match_invreq() {
	// Ensure that we'll fail an async payment backwards if the amount in the HTLC is lower than the
	// amount from the original invoice request.
	let secp_ctx = Secp256k1::new();
	let chanmon_cfgs = create_chanmon_cfgs(4);
	let node_cfgs = create_node_cfgs(4, &chanmon_cfgs);

	let mut allow_priv_chan_fwds_cfg = test_default_channel_config();
	allow_priv_chan_fwds_cfg.accept_forwards_to_priv_channels = true;
	// Make one blinded path's fees slightly higher so they are tried in a deterministic order.
	let mut higher_fee_chan_cfg = allow_priv_chan_fwds_cfg.clone();
	higher_fee_chan_cfg.channel_config.forwarding_fee_base_msat += 5000;
	let node_chanmgrs = create_node_chanmgrs(
		4,
		&node_cfgs,
		&[None, Some(allow_priv_chan_fwds_cfg), Some(higher_fee_chan_cfg), None],
	);
	let nodes = create_network(4, &node_cfgs, &node_chanmgrs);

	// Create this network topology so nodes[0] has a blinded route hint to retry over.
	//      n1
	//    /    \
	// n0       n3
	//    \    /
	//      n2
	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 0);
	create_announced_chan_between_nodes_with_value(&nodes, 0, 2, 1_000_000, 0);
	create_unannounced_chan_between_nodes_with_value(&nodes, 1, 3, 1_000_000, 0);
	create_unannounced_chan_between_nodes_with_value(&nodes, 2, 3, 1_000_000, 0);

	// Ensure all nodes start at the same height.
	connect_blocks(&nodes[0], 4 * CHAN_CONFIRM_DEPTH + 1 - nodes[0].best_block_info().1);
	connect_blocks(&nodes[1], 4 * CHAN_CONFIRM_DEPTH + 1 - nodes[1].best_block_info().1);
	connect_blocks(&nodes[2], 4 * CHAN_CONFIRM_DEPTH + 1 - nodes[2].best_block_info().1);
	connect_blocks(&nodes[3], 4 * CHAN_CONFIRM_DEPTH + 1 - nodes[3].best_block_info().1);

	let recipient_id = vec![42; 32];
	let inv_server_paths =
		nodes[1].node.blinded_paths_for_async_recipient(recipient_id.clone(), None).unwrap();
	nodes[3].node.set_paths_to_static_invoice_server(inv_server_paths).unwrap();
	expect_offer_paths_requests(&nodes[3], &[&nodes[0], &nodes[1], &nodes[2]]);

	let invoice_flow_res =
		pass_static_invoice_server_messages(&nodes[1], &nodes[3], recipient_id.clone());
	let static_invoice = invoice_flow_res.invoice;
	let offer = nodes[3].node.get_async_receive_offer().unwrap();

	let amt_msat = 5000;
	let payment_id = PaymentId([1; 32]);
	nodes[0].node.pay_for_offer(&offer, Some(amt_msat), payment_id, Default::default()).unwrap();
	let release_held_htlc_om_3_0 = pass_async_payments_oms(
		static_invoice,
		&nodes[0],
		&nodes[1],
		&nodes[3],
		recipient_id,
		invoice_flow_res.invoice_request_path,
	)
	.1;

	// Replace the invoice request contained within outbound_payments before sending so the invreq
	// amount doesn't match the onion amount when the HTLC gets to the recipient.
	let mut valid_invreq = None;
	nodes[0].node.test_modify_pending_payment(&payment_id, |pmt| {
		if let PendingOutboundPayment::StaticInvoiceReceived { invoice_request, .. } = pmt {
			valid_invreq = Some(invoice_request.clone());
			*invoice_request = offer
				.request_invoice(
					&nodes[0].keys_manager.get_expanded_key(),
					Nonce::from_entropy_source(nodes[0].keys_manager),
					&secp_ctx,
					payment_id,
				)
				.unwrap()
				.amount_msats(amt_msat + 1)
				.unwrap()
				.chain_hash(ChainHash::using_genesis_block(Network::Testnet))
				.unwrap()
				.build_and_sign()
				.unwrap();
		} else {
			panic!()
		}
	});

	nodes[0]
		.onion_messenger
		.handle_onion_message(nodes[3].node.get_our_node_id(), &release_held_htlc_om_3_0);
	check_added_monitors(&nodes[0], 1);

	// Check that we've queued the HTLCs of the async keysend payment.
	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let mut ev = remove_first_msg_event_to_node(&nodes[1].node.get_our_node_id(), &mut events);
	assert!(matches!(
			ev, MessageSendEvent::UpdateHTLCs { ref updates, .. } if updates.update_add_htlcs.len() == 1));
	let payment_hash = extract_payment_hash(&ev);

	let route: &[&[&Node]] = &[&[&nodes[1], &nodes[3]]];
	let args = PassAlongPathArgs::new(&nodes[0], route[0], amt_msat, payment_hash, ev)
		.without_claimable_event()
		.expect_failure(HTLCHandlingFailureType::Receive { payment_hash });
	do_pass_along_path(args);

	// Modify the invoice request stored in our outbounds to be the correct one, to make sure the
	// payment retry will succeed after we finish failing the invalid HTLC back.
	nodes[0].node.test_modify_pending_payment(&payment_id, |pmt| {
		if let PendingOutboundPayment::Retryable { invoice_request, .. } = pmt {
			*invoice_request = valid_invreq.take();
		} else {
			panic!()
		}
	});

	fail_blinded_htlc_backwards(payment_hash, 1, &[&nodes[0], &nodes[1], &nodes[3]], true);

	// The retry with the correct invoice request should succeed.
	nodes[0].node.process_pending_htlc_forwards();
	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let mut ev = remove_first_msg_event_to_node(&nodes[2].node.get_our_node_id(), &mut events);
	assert!(matches!(
				ev, MessageSendEvent::UpdateHTLCs { ref updates, .. } if updates.update_add_htlcs.len() == 1));
	check_added_monitors(&nodes[0], 1);
	let route: &[&[&Node]] = &[&[&nodes[2], &nodes[3]]];
	let args = PassAlongPathArgs::new(&nodes[0], route[0], amt_msat, payment_hash, ev);
	let claimable_ev = do_pass_along_path(args).unwrap();
	let keysend_preimage = extract_payment_preimage(&claimable_ev);
	claim_payment_along_route(ClaimAlongRouteArgs::new(&nodes[0], route, keysend_preimage));
}

#[test]
fn reject_missing_invreq() {
	// Ensure we'll fail an async payment backwards if the HTLC onion doesn't contain the sender's
	// original invoice request.
	let mut valid_invreq: Mutex<Option<InvoiceRequest>> = Mutex::new(None);

	invalid_async_receive_with_retry(
		|sender, _, payment_id| {
			// Remove the invoice request from our Retryable payment so we don't include it in the onion on
			// retry.
			sender.node.test_modify_pending_payment(&payment_id, |pmt| {
				if let PendingOutboundPayment::Retryable { invoice_request, .. } = pmt {
					assert!(invoice_request.is_some());
					*valid_invreq.lock().unwrap() = invoice_request.take();
				} else {
					panic!()
				}
			});
		},
		|sender, payment_id| {
			// Re-add the invoice request so we include it in the onion on the next retry.
			sender.node.test_modify_pending_payment(&payment_id, |pmt| {
				if let PendingOutboundPayment::Retryable { invoice_request, .. } = pmt {
					*invoice_request = valid_invreq.lock().unwrap().take();
				} else {
					panic!()
				}
			});
		},
	);
}

#[test]
fn reject_bad_payment_secret() {
	// Ensure we'll fail an async payment backwards if the payment secret in the onion is invalid.

	let mut valid_payment_params: Mutex<Option<PaymentParameters>> = Mutex::new(None);
	invalid_async_receive_with_retry(
		|sender, recipient, payment_id| {
			// Store invalid payment paths in the sender's outbound Retryable payment to induce the failure
			// on the recipient's end. Store multiple paths so the sender still thinks they can retry after
			// the failure we're about to cause below.
			let mut invalid_blinded_payment_paths = Vec::new();
			for i in 0..2 {
				let mut paths = recipient
					.node
					.test_create_blinded_payment_paths(
						None,
						PaymentSecret([42; 32]), // invalid payment secret
						PaymentContext::AsyncBolt12Offer(AsyncBolt12OfferContext {
							// We don't reach the point of checking the invreq nonce due to the invalid payment secret
							offer_nonce: Nonce([i; Nonce::LENGTH]),
						}),
						u32::MAX,
					)
					.unwrap();
				invalid_blinded_payment_paths.append(&mut paths);
			}

			// Modify the outbound payment parameters to use payment paths with an invalid payment secret.
			sender.node.test_modify_pending_payment(&payment_id, |pmt| {
				if let PendingOutboundPayment::Retryable { ref mut payment_params, .. } = pmt {
					assert!(payment_params.is_some());
					let valid_params = payment_params.clone();
					if let Payee::Blinded { ref mut route_hints, .. } =
						&mut payment_params.as_mut().unwrap().payee
					{
						core::mem::swap(route_hints, &mut invalid_blinded_payment_paths);
					} else {
						panic!()
					}
					*valid_payment_params.lock().unwrap() = valid_params;
				} else {
					panic!()
				}
			});
		},
		|sender, payment_id| {
			// Re-add the valid payment params so we use the right payment secret on the next retry.
			sender.node.test_modify_pending_payment(&payment_id, |pmt| {
				if let PendingOutboundPayment::Retryable { payment_params, .. } = pmt {
					*payment_params = valid_payment_params.lock().unwrap().take();
				} else {
					panic!()
				}
			});
		},
	);
}

fn invalid_async_receive_with_retry<F1, F2>(
	mut modify_outbounds_for_failure: F1, mut modify_outbounds_for_success: F2,
) where
	F1: FnMut(&Node, &Node, PaymentId),
	F2: FnMut(&Node, PaymentId),
{
	let secp_ctx = Secp256k1::new();
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);

	let mut allow_priv_chan_fwds_cfg = test_default_channel_config();
	allow_priv_chan_fwds_cfg.accept_forwards_to_priv_channels = true;
	let node_chanmgrs =
		create_node_chanmgrs(3, &node_cfgs, &[None, Some(allow_priv_chan_fwds_cfg), None]);

	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	let entropy_source = nodes[2].keys_manager;
	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 0);
	create_unannounced_chan_between_nodes_with_value(&nodes, 1, 2, 1_000_000, 0);

	let recipient_id = vec![42; 32];
	let inv_server_paths =
		nodes[1].node.blinded_paths_for_async_recipient(recipient_id.clone(), None).unwrap();
	nodes[2].node.set_paths_to_static_invoice_server(inv_server_paths).unwrap();
	expect_offer_paths_requests(&nodes[2], &[&nodes[0], &nodes[1]]);

	// Set the random bytes so we can predict the offer nonce.
	let hardcoded_random_bytes = [42; 32];
	*nodes[2].keys_manager.override_random_bytes.lock().unwrap() = Some(hardcoded_random_bytes);

	// Ensure all nodes start at the same height.
	connect_blocks(&nodes[0], 2 * CHAN_CONFIRM_DEPTH + 1 - nodes[0].best_block_info().1);
	connect_blocks(&nodes[1], 2 * CHAN_CONFIRM_DEPTH + 1 - nodes[1].best_block_info().1);
	connect_blocks(&nodes[2], 2 * CHAN_CONFIRM_DEPTH + 1 - nodes[2].best_block_info().1);

	let blinded_paths_to_always_online_node = nodes[1]
		.message_router
		.create_blinded_paths(
			nodes[1].node.get_our_node_id(),
			nodes[1].keys_manager.get_receive_auth_key(),
			MessageContext::Offers(OffersContext::InvoiceRequest { nonce: Nonce([42; 16]) }),
			Vec::new(),
			&secp_ctx,
		)
		.unwrap();
	let (offer_builder, offer_nonce) = nodes[2]
		.node
		.flow
		.create_async_receive_offer_builder(entropy_source, blinded_paths_to_always_online_node)
		.unwrap();
	let offer = offer_builder.build().unwrap();
	let amt_msat = 5000;
	let payment_id = PaymentId([1; 32]);

	// Hardcode the payment paths so nodes[0] has something to retry over. Set all of these paths to
	// use the same nodes to avoid complicating the test with a bunch of extra nodes.
	let mut static_invoice_paths = Vec::new();
	for _ in 0..3 {
		let static_inv_for_path =
			create_static_invoice_builder(&nodes[2], &offer, offer_nonce, None)
				.build_and_sign(&secp_ctx)
				.unwrap();
		static_invoice_paths.push(static_inv_for_path.payment_paths()[0].clone());
	}
	nodes[2].router.expect_blinded_payment_paths(static_invoice_paths);

	let invoice_flow_res =
		pass_static_invoice_server_messages(&nodes[1], &nodes[2], recipient_id.clone());
	let static_invoice = invoice_flow_res.invoice;
	let offer = nodes[2].node.get_async_receive_offer().unwrap();

	nodes[0].node.pay_for_offer(&offer, Some(amt_msat), payment_id, Default::default()).unwrap();
	let release_held_htlc_om_2_0 = pass_async_payments_oms(
		static_invoice,
		&nodes[0],
		&nodes[1],
		&nodes[2],
		recipient_id,
		invoice_flow_res.invoice_request_path,
	)
	.1;
	nodes[0]
		.onion_messenger
		.handle_onion_message(nodes[2].node.get_our_node_id(), &release_held_htlc_om_2_0);
	check_added_monitors(&nodes[0], 1);

	// Check that we've queued the HTLCs of the async keysend payment.
	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let mut ev = remove_first_msg_event_to_node(&nodes[1].node.get_our_node_id(), &mut events);
	assert!(matches!(
					ev, MessageSendEvent::UpdateHTLCs { ref updates, .. } if updates.update_add_htlcs.len() == 1));
	let payment_hash = extract_payment_hash(&ev);

	let route: &[&[&Node]] = &[&[&nodes[1], &nodes[2]]];
	let args = PassAlongPathArgs::new(&nodes[0], route[0], amt_msat, payment_hash, ev);
	do_pass_along_path(args);

	// Fail the HTLC backwards to enable us to more easily modify the now-Retryable outbound to test
	// failures on the recipient's end.
	nodes[2].node.fail_htlc_backwards(&payment_hash);
	expect_htlc_failure_conditions(
		nodes[2].node.get_and_clear_pending_events(),
		&[HTLCHandlingFailureType::Receive { payment_hash }],
	);
	nodes[2].node.process_pending_htlc_forwards();
	check_added_monitors(&nodes[2], 1);
	fail_blinded_htlc_backwards(payment_hash, 1, &[&nodes[0], &nodes[1], &nodes[2]], true);

	// Trigger a retry and make sure it fails after calling the closure that induces recipient
	// failure.
	modify_outbounds_for_failure(&nodes[0], &nodes[2], payment_id);
	nodes[0].node.process_pending_htlc_forwards();
	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let mut ev = remove_first_msg_event_to_node(&nodes[1].node.get_our_node_id(), &mut events);
	assert!(matches!(
						ev, MessageSendEvent::UpdateHTLCs { ref updates, .. } if updates.update_add_htlcs.len() == 1));
	check_added_monitors(&nodes[0], 1);
	let route: &[&[&Node]] = &[&[&nodes[1], &nodes[2]]];
	let args = PassAlongPathArgs::new(&nodes[0], route[0], amt_msat, payment_hash, ev)
		.without_claimable_event()
		.expect_failure(HTLCHandlingFailureType::Receive { payment_hash });
	do_pass_along_path(args);
	fail_blinded_htlc_backwards(payment_hash, 1, &[&nodes[0], &nodes[1], &nodes[2]], true);

	// The retry after calling the 2nd closure should succeed.
	modify_outbounds_for_success(&nodes[0], payment_id);
	nodes[0].node.process_pending_htlc_forwards();
	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let mut ev = remove_first_msg_event_to_node(&nodes[1].node.get_our_node_id(), &mut events);
	check_added_monitors(&nodes[0], 1);
	let route: &[&[&Node]] = &[&[&nodes[1], &nodes[2]]];
	let args = PassAlongPathArgs::new(&nodes[0], route[0], amt_msat, payment_hash, ev);
	let claimable_ev = do_pass_along_path(args).unwrap();
	let keysend_preimage = extract_payment_preimage(&claimable_ev);
	claim_payment_along_route(ClaimAlongRouteArgs::new(&nodes[0], route, keysend_preimage));
}

#[cfg_attr(feature = "std", ignore)]
#[test]
fn expired_static_invoice_message_path() {
	// Test that if we receive a held_htlc_available message over an expired blinded path, we'll
	// ignore it.
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 0);
	create_unannounced_chan_between_nodes_with_value(&nodes, 1, 2, 1_000_000, 0);

	let recipient_id = vec![42; 32];
	let inv_server_paths =
		nodes[1].node.blinded_paths_for_async_recipient(recipient_id.clone(), None).unwrap();
	nodes[2].node.set_paths_to_static_invoice_server(inv_server_paths).unwrap();
	expect_offer_paths_requests(&nodes[2], &[&nodes[0], &nodes[1]]);

	let invoice_flow_res =
		pass_static_invoice_server_messages(&nodes[1], &nodes[2], recipient_id.clone());
	let static_invoice = invoice_flow_res.invoice;
	let offer = nodes[2].node.get_async_receive_offer().unwrap();

	let amt_msat = 5000;
	let payment_id = PaymentId([1; 32]);
	nodes[0].node.pay_for_offer(&offer, Some(amt_msat), payment_id, Default::default()).unwrap();

	// While the invoice is unexpired, respond with release_held_htlc.
	let (held_htlc_available_om, _release_held_htlc_om) = pass_async_payments_oms(
		static_invoice.clone(),
		&nodes[0],
		&nodes[1],
		&nodes[2],
		recipient_id,
		invoice_flow_res.invoice_request_path,
	);

	// After the invoice is expired, ignore inbound held_htlc_available messages over the path.
	let path_absolute_expiry = crate::ln::inbound_payment::calculate_absolute_expiry(
		nodes[2].node.duration_since_epoch().as_secs(),
		static_invoice.relative_expiry().as_secs() as u32,
	);
	let block = create_dummy_block(
		nodes[2].best_block_hash(),
		(path_absolute_expiry + 1) as u32,
		Vec::new(),
	);
	connect_block(&nodes[2], &block);
	nodes[2]
		.onion_messenger
		.handle_onion_message(nodes[1].node.get_our_node_id(), &held_htlc_available_om);
	for i in 0..2 {
		assert!(nodes[2]
			.onion_messenger
			.next_onion_message_for_peer(nodes[i].node.get_our_node_id())
			.is_none());
	}
}

#[test]
fn expired_static_invoice_payment_path() {
	// Test that we'll reject inbound payments to expired payment paths.
	let secp_ctx = Secp256k1::new();
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);

	let mut allow_priv_chan_fwds_cfg = test_default_channel_config();
	allow_priv_chan_fwds_cfg.accept_forwards_to_priv_channels = true;
	let node_chanmgrs =
		create_node_chanmgrs(3, &node_cfgs, &[None, Some(allow_priv_chan_fwds_cfg), None]);

	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 0);
	create_unannounced_chan_between_nodes_with_value(&nodes, 1, 2, 1_000_000, 0);

	let recipient_id = vec![42; 32];
	let inv_server_paths =
		nodes[1].node.blinded_paths_for_async_recipient(recipient_id.clone(), None).unwrap();
	nodes[2].node.set_paths_to_static_invoice_server(inv_server_paths).unwrap();
	expect_offer_paths_requests(&nodes[2], &[&nodes[0], &nodes[1]]);

	// Make sure all nodes are at the same block height in preparation for CLTV timeout things.
	let node_max_height =
		nodes.iter().map(|node| node.blocks.lock().unwrap().len()).max().unwrap() as u32;
	connect_blocks(&nodes[0], node_max_height - nodes[0].best_block_info().1);
	connect_blocks(&nodes[1], node_max_height - nodes[1].best_block_info().1);
	connect_blocks(&nodes[2], node_max_height - nodes[2].best_block_info().1);

	// Hardcode the blinded payment path returned by the router so we can expire it via mining blocks.
	let (_, static_invoice_expired_paths) =
		create_static_invoice(&nodes[1], &nodes[2], None, &secp_ctx);
	nodes[2]
		.router
		.expect_blinded_payment_paths(static_invoice_expired_paths.payment_paths().to_vec());

	// Extract the expiry height from the to-be-expired blinded payment path.
	let final_max_cltv_expiry = {
		let mut blinded_path = static_invoice_expired_paths.payment_paths().to_vec().pop().unwrap();
		blinded_path
			.advance_path_by_one(&nodes[1].keys_manager, &nodes[1].node, &secp_ctx)
			.unwrap();
		match blinded_path.decrypt_intro_payload(&nodes[2].keys_manager).unwrap().0 {
			BlindedPaymentTlvs::Receive(tlvs) => tlvs.payment_constraints.max_cltv_expiry,
			_ => panic!(),
		}
	};

	// Mine a bunch of blocks so the hardcoded path's `max_cltv_expiry` is expired at the recipient's
	// end by the time the payment arrives.
	let min_cltv_expiry_delta = test_default_channel_config().channel_config.cltv_expiry_delta;
	connect_blocks(
		&nodes[0],
		final_max_cltv_expiry
			- nodes[0].best_block_info().1
			- min_cltv_expiry_delta as u32
			- HTLC_FAIL_BACK_BUFFER
			- LATENCY_GRACE_PERIOD_BLOCKS
			- 1,
	);
	connect_blocks(
		&nodes[1],
		final_max_cltv_expiry
			- nodes[1].best_block_info().1
			// Don't expire the path for nodes[1]
			- min_cltv_expiry_delta as u32
			- HTLC_FAIL_BACK_BUFFER
			- LATENCY_GRACE_PERIOD_BLOCKS
			- 1,
	);
	connect_blocks(&nodes[2], final_max_cltv_expiry - nodes[2].best_block_info().1);

	let invoice_flow_res =
		pass_static_invoice_server_messages(&nodes[1], &nodes[2], recipient_id.clone());
	let static_invoice = invoice_flow_res.invoice;
	let offer = nodes[2].node.get_async_receive_offer().unwrap();

	let amt_msat = 5000;
	let payment_id = PaymentId([1; 32]);
	let mut params: OptionalOfferPaymentParams = Default::default();
	params.retry_strategy = Retry::Attempts(0);
	nodes[0].node.pay_for_offer(&offer, Some(amt_msat), payment_id, params).unwrap();
	let release_held_htlc_om = pass_async_payments_oms(
		static_invoice,
		&nodes[0],
		&nodes[1],
		&nodes[2],
		recipient_id,
		invoice_flow_res.invoice_request_path,
	)
	.1;
	nodes[0]
		.onion_messenger
		.handle_onion_message(nodes[2].node.get_our_node_id(), &release_held_htlc_om);

	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let ev = remove_first_msg_event_to_node(&nodes[1].node.get_our_node_id(), &mut events);
	let payment_hash = extract_payment_hash(&ev);
	check_added_monitors(&nodes[0], 1);

	let route: &[&[&Node]] = &[&[&nodes[1], &nodes[2]]];
	let args = PassAlongPathArgs::new(&nodes[0], route[0], amt_msat, payment_hash, ev)
		.without_claimable_event()
		.expect_failure(HTLCHandlingFailureType::Receive { payment_hash });
	do_pass_along_path(args);
	fail_blinded_htlc_backwards(payment_hash, 1, &[&nodes[0], &nodes[1], &nodes[2]], false);
	nodes[2].logger.assert_log_contains(
		"lightning::ln::channelmanager",
		"violated blinded payment constraints",
		1,
	);
}

#[cfg_attr(feature = "std", ignore)]
#[test]
fn ignore_expired_offer_paths_request() {
	// Ignore an incoming `OfferPathsRequest` if it is sent over a blinded path that is expired.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	create_unannounced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 0);
	let server = &nodes[0];
	let recipient = &nodes[1];

	const OFFER_PATHS_REQ_RELATIVE_EXPIRY: Duration = Duration::from_secs(60 * 60);
	let recipient_id = vec![42; 32];
	let inv_server_paths = server
		.node
		.blinded_paths_for_async_recipient(recipient_id, Some(OFFER_PATHS_REQ_RELATIVE_EXPIRY))
		.unwrap();
	recipient.node.set_paths_to_static_invoice_server(inv_server_paths).unwrap();

	// Retrieve the offer paths request, and check that before the path that the recipient was
	// configured with expires the server will respond to it, and after the config path expires they
	// won't.
	recipient.node.timer_tick_occurred();
	let offer_paths_req = recipient
		.onion_messenger
		.next_onion_message_for_peer(server.node.get_our_node_id())
		.unwrap();
	assert!(matches!(
		server.onion_messenger.peel_onion_message(&offer_paths_req).unwrap(),
		PeeledOnion::AsyncPayments(AsyncPaymentsMessage::OfferPathsRequest(_), _, _)
	));
	recipient.onion_messenger.release_pending_msgs(); // Ignore redundant paths requests

	// Prior to the config path expiry the server will respond with offer_paths:
	server.onion_messenger.handle_onion_message(recipient.node.get_our_node_id(), &offer_paths_req);
	let offer_paths = server
		.onion_messenger
		.next_onion_message_for_peer(recipient.node.get_our_node_id())
		.unwrap();
	assert!(matches!(
		recipient.onion_messenger.peel_onion_message(&offer_paths).unwrap(),
		PeeledOnion::AsyncPayments(AsyncPaymentsMessage::OfferPaths(_), _, _)
	));
	server.onion_messenger.release_pending_msgs(); // Ignore redundant offer_paths

	// After the config path expiry the offer paths request will be ignored:
	advance_time_by(OFFER_PATHS_REQ_RELATIVE_EXPIRY + Duration::from_secs(1), server);
	server.onion_messenger.handle_onion_message(recipient.node.get_our_node_id(), &offer_paths_req);
	assert!(server
		.onion_messenger
		.next_onion_message_for_peer(recipient.node.get_our_node_id())
		.is_none());
}

#[cfg_attr(feature = "std", ignore)]
#[test]
fn ignore_expired_offer_paths_message() {
	// If the recipient receives an offer_paths message over an expired reply path, it should be ignored.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	create_unannounced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 0);
	let server = &nodes[0];
	let recipient = &nodes[1];

	let recipient_id = vec![42; 32];
	let inv_server_paths =
		server.node.blinded_paths_for_async_recipient(recipient_id, None).unwrap();
	recipient.node.set_paths_to_static_invoice_server(inv_server_paths).unwrap();

	// First retrieve the offer_paths_request and corresponding offer_paths response from the server.
	recipient.node.timer_tick_occurred();
	let offer_paths_req = recipient
		.onion_messenger
		.next_onion_message_for_peer(server.node.get_our_node_id())
		.unwrap();
	recipient.onion_messenger.release_pending_msgs(); // Ignore redundant paths requests
	server.onion_messenger.handle_onion_message(recipient.node.get_our_node_id(), &offer_paths_req);
	let offer_paths = server
		.onion_messenger
		.next_onion_message_for_peer(recipient.node.get_our_node_id())
		.unwrap();
	assert!(matches!(
		recipient.onion_messenger.peel_onion_message(&offer_paths).unwrap(),
		PeeledOnion::AsyncPayments(AsyncPaymentsMessage::OfferPaths(_), _, _)
	));

	// Prior to expiry of the offer_paths_request reply path, the recipient will respond to
	// offer_paths with serve_static_invoice.
	recipient.onion_messenger.handle_onion_message(server.node.get_our_node_id(), &offer_paths);
	let serve_static_invoice = recipient
		.onion_messenger
		.next_onion_message_for_peer(server.node.get_our_node_id())
		.unwrap();
	assert!(matches!(
		server.onion_messenger.peel_onion_message(&serve_static_invoice).unwrap(),
		PeeledOnion::AsyncPayments(AsyncPaymentsMessage::ServeStaticInvoice(_), _, _)
	));

	// Manually advance time for the recipient so they will perceive the offer_paths message as being
	// sent over an expired reply path, and not respond with serve_static_invoice.
	advance_time_by(TEST_TEMP_REPLY_PATH_RELATIVE_EXPIRY + Duration::from_secs(1), recipient);
	recipient.onion_messenger.handle_onion_message(server.node.get_our_node_id(), &offer_paths);
	assert!(recipient
		.onion_messenger
		.next_onion_message_for_peer(server.node.get_our_node_id())
		.is_none());
}

#[test]
fn limit_offer_paths_requests() {
	// Limit the number of offer_paths_requests sent to the server if they aren't responding.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	create_unannounced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 0);
	let server = &nodes[0];
	let recipient = &nodes[1];

	let recipient_id = vec![42; 32];
	let inv_server_paths =
		server.node.blinded_paths_for_async_recipient(recipient_id, None).unwrap();
	recipient.node.set_paths_to_static_invoice_server(inv_server_paths).unwrap();
	expect_offer_paths_requests(&nodes[1], &[&nodes[0]]);

	// Up to TEST_MAX_UPDATE_ATTEMPTS offer_paths_requests are allowed to be sent out before the async
	// recipient should give up.
	// Subtract 1 because we sent the first request when invoice server paths were set above.
	for _ in 0..TEST_MAX_UPDATE_ATTEMPTS - 1 {
		recipient.node.test_check_refresh_async_receive_offers();
		let offer_paths_req = recipient
			.onion_messenger
			.next_onion_message_for_peer(server.node.get_our_node_id())
			.unwrap();
		assert!(matches!(
			server.onion_messenger.peel_onion_message(&offer_paths_req).unwrap(),
			PeeledOnion::AsyncPayments(AsyncPaymentsMessage::OfferPathsRequest(_), _, _)
		));
		recipient.onion_messenger.release_pending_msgs(); // Ignore redundant paths requests
	}

	// After the recipient runs out of attempts to request offer paths, they will give up until the
	// next timer tick.
	recipient.node.test_check_refresh_async_receive_offers();
	assert!(recipient
		.onion_messenger
		.next_onion_message_for_peer(server.node.get_our_node_id())
		.is_none());

	// On the next timer tick, more offer paths requests should be allowed to go through.
	recipient.node.timer_tick_occurred();
	let offer_paths_req = recipient
		.onion_messenger
		.next_onion_message_for_peer(server.node.get_our_node_id())
		.unwrap();
	assert!(matches!(
		server.onion_messenger.peel_onion_message(&offer_paths_req).unwrap(),
		PeeledOnion::AsyncPayments(AsyncPaymentsMessage::OfferPathsRequest(_), _, _)
	));
}

#[test]
fn limit_serve_static_invoice_requests() {
	// If we have enough async receive offers cached already, the recipient should stop sending out
	// offer_paths_requests.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	create_unannounced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 0);
	let server = &nodes[0];
	let recipient = &nodes[1];

	let recipient_id = vec![42; 32];
	let inv_server_paths =
		server.node.blinded_paths_for_async_recipient(recipient_id.clone(), None).unwrap();
	recipient.node.set_paths_to_static_invoice_server(inv_server_paths).unwrap();

	// Build the target number of offers interactively with the static invoice server.
	let mut offer_paths_req = None;
	let mut invoice_slots = new_hash_set();
	for expected_inv_slot in 0..TEST_MAX_CACHED_OFFERS_TARGET {
		let flow_res = pass_static_invoice_server_messages(server, recipient, recipient_id.clone());
		assert_eq!(flow_res.invoice_slot, expected_inv_slot as u16);

		offer_paths_req = Some(flow_res.offer_paths_request);
		invoice_slots.insert(flow_res.invoice_slot);

		// Trigger a cache refresh
		recipient.node.timer_tick_occurred();
	}
	assert_eq!(
		recipient.node.flow.test_get_async_receive_offers().len(),
		TEST_MAX_CACHED_OFFERS_TARGET
	);
	// Check that all invoice slot numbers are unique.
	assert_eq!(invoice_slots.len(), TEST_MAX_CACHED_OFFERS_TARGET);

	// Force allowing more offer paths request attempts so we can check that the recipient will not
	// attempt to build any further offers.
	recipient.node.timer_tick_occurred();
	assert!(recipient
		.onion_messenger
		.next_onion_message_for_peer(server.node.get_our_node_id())
		.is_none());

	// If the recipient now receives new offer_paths, they should not attempt to build new offers as
	// they already have enough.
	server
		.onion_messenger
		.handle_onion_message(recipient.node.get_our_node_id(), &offer_paths_req.unwrap());
	let offer_paths = server
		.onion_messenger
		.next_onion_message_for_peer(recipient.node.get_our_node_id())
		.unwrap();
	recipient.onion_messenger.handle_onion_message(server.node.get_our_node_id(), &offer_paths);
	assert!(recipient
		.onion_messenger
		.next_onion_message_for_peer(server.node.get_our_node_id())
		.is_none());
}

#[test]
fn offer_cache_round_trip_ser() {
	// Check that the async payments offer cache survives round trip serialization within the
	// `ChannelManager`.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let persister;
	let chain_monitor;
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let payee_node_deserialized;
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let chan_id =
		create_unannounced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 0).0.channel_id;
	let server = &nodes[0];
	let recipient = &nodes[1];

	let recipient_id = vec![42; 32];
	let inv_server_paths =
		server.node.blinded_paths_for_async_recipient(recipient_id.clone(), None).unwrap();
	recipient.node.set_paths_to_static_invoice_server(inv_server_paths).unwrap();

	// Build the target number of offers interactively with the static invoice server.
	for _ in 0..TEST_MAX_CACHED_OFFERS_TARGET {
		pass_static_invoice_server_messages(server, recipient, recipient_id.clone());
		// Trigger a cache refresh
		recipient.node.timer_tick_occurred();
	}

	// Check that round trip serialization of the ChannelManager will result in identical stored
	// offers.
	let cached_offers_pre_ser = recipient.node.flow.test_get_async_receive_offers();
	let config = test_default_channel_config();
	let serialized_monitor = get_monitor!(recipient, chan_id).encode();
	reload_node!(
		nodes[1],
		config,
		recipient.node.encode(),
		&[&serialized_monitor],
		persister,
		chain_monitor,
		payee_node_deserialized
	);
	let recipient = &nodes[1];
	let cached_offers_post_ser = recipient.node.flow.test_get_async_receive_offers();
	assert_eq!(cached_offers_pre_ser, cached_offers_post_ser);
}

#[test]
fn refresh_static_invoices_for_pending_offers() {
	// Check that an invoice for an  offer that is pending persistence with the server will be updated
	// every timer tick.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	create_unannounced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 0);
	let server = &nodes[0];
	let recipient = &nodes[1];

	let recipient_id = vec![42; 32];
	let inv_server_paths =
		server.node.blinded_paths_for_async_recipient(recipient_id.clone(), None).unwrap();
	recipient.node.set_paths_to_static_invoice_server(inv_server_paths).unwrap();
	expect_offer_paths_requests(&nodes[1], &[&nodes[0]]);

	// Set up the recipient to have one offer pending with the static invoice server.
	invoice_flow_up_to_send_serve_static_invoice(server, recipient);

	// Every timer tick, we'll send a fresh invoice to the server.
	for _ in 0..10 {
		recipient.node.timer_tick_occurred();
		let pending_oms = recipient.onion_messenger.release_pending_msgs();
		pending_oms
			.get(&server.node.get_our_node_id())
			.unwrap()
			.iter()
			.find(|msg| match server.onion_messenger.peel_onion_message(&msg).unwrap() {
				PeeledOnion::AsyncPayments(AsyncPaymentsMessage::ServeStaticInvoice(_), _, _) => {
					true
				},
				PeeledOnion::AsyncPayments(AsyncPaymentsMessage::OfferPathsRequest(_), _, _) => {
					false
				},
				_ => panic!("Unexpected message"),
			})
			.unwrap();
	}
}

#[cfg_attr(feature = "std", ignore)]
#[test]
fn refresh_static_invoices_for_used_offers() {
	// Check that an invoice for a used offer stored with the server will be updated every
	// INVOICE_REFRESH_THRESHOLD.
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);

	let mut allow_priv_chan_fwds_cfg = test_default_channel_config();
	allow_priv_chan_fwds_cfg.accept_forwards_to_priv_channels = true;
	let node_chanmgrs =
		create_node_chanmgrs(3, &node_cfgs, &[None, Some(allow_priv_chan_fwds_cfg), None]);

	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 0);
	create_unannounced_chan_between_nodes_with_value(&nodes, 1, 2, 1_000_000, 0);
	let sender = &nodes[0];
	let server = &nodes[1];
	let recipient = &nodes[2];

	let recipient_id = vec![42; 32];
	let inv_server_paths =
		server.node.blinded_paths_for_async_recipient(recipient_id.clone(), None).unwrap();
	recipient.node.set_paths_to_static_invoice_server(inv_server_paths).unwrap();
	expect_offer_paths_requests(&nodes[2], &[&nodes[0], &nodes[1]]);

	// Set up the recipient to have one offer and an invoice with the static invoice server.
	let flow_res = pass_static_invoice_server_messages(server, recipient, recipient_id.clone());
	let original_invoice = flow_res.invoice;
	// Mark the offer as used so we'll update the invoice after INVOICE_REFRESH_THRESHOLD.
	let _offer = recipient.node.get_async_receive_offer().unwrap();

	// Force the server and recipient to send OMs directly to each other for testing simplicity.
	server.message_router.peers_override.lock().unwrap().push(recipient.node.get_our_node_id());
	recipient.message_router.peers_override.lock().unwrap().push(server.node.get_our_node_id());

	// Prior to INVOICE_REFRESH_THRESHOLD, we won't refresh the invoice.
	advance_time_by(TEST_INVOICE_REFRESH_THRESHOLD, recipient);
	recipient.node.timer_tick_occurred();
	expect_offer_paths_requests(&nodes[2], &[&nodes[0], &nodes[1]]);

	// After INVOICE_REFRESH_THRESHOLD, we will refresh the invoice.
	advance_time_by(Duration::from_secs(1), recipient);
	recipient.node.timer_tick_occurred();
	let pending_oms = recipient.onion_messenger.release_pending_msgs();
	let serve_static_invoice_om = pending_oms
		.get(&server.node.get_our_node_id())
		.unwrap()
		.iter()
		.find(|msg| match server.onion_messenger.peel_onion_message(&msg).unwrap() {
			PeeledOnion::AsyncPayments(AsyncPaymentsMessage::ServeStaticInvoice(_), _, _) => true,
			PeeledOnion::AsyncPayments(AsyncPaymentsMessage::OfferPathsRequest(_), _, _) => false,
			_ => panic!("Unexpected message"),
		})
		.unwrap();

	server
		.onion_messenger
		.handle_onion_message(recipient.node.get_our_node_id(), &serve_static_invoice_om);
	let mut events = server.node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	let (updated_invoice, ack_path, invoice_request_path) = match events.pop().unwrap() {
		Event::PersistStaticInvoice {
			invoice,
			invoice_slot,
			invoice_persisted_path,
			recipient_id: ev_id,
			invoice_request_path,
		} => {
			assert_ne!(original_invoice, invoice);
			assert_eq!(recipient_id, ev_id);
			assert_eq!(invoice_slot, flow_res.invoice_slot);
			// When we update the invoice corresponding to a specific offer, the invoice_slot stays the
			// same.
			assert_eq!(invoice_slot, flow_res.invoice_slot);
			(invoice, invoice_persisted_path, invoice_request_path)
		},
		_ => panic!(),
	};
	server.node.static_invoice_persisted(ack_path);
	let invoice_persisted_om = server
		.onion_messenger
		.next_onion_message_for_peer(recipient.node.get_our_node_id())
		.unwrap();
	recipient
		.onion_messenger
		.handle_onion_message(server.node.get_our_node_id(), &invoice_persisted_om);
	assert_eq!(recipient.node.flow.test_get_async_receive_offers().len(), 1);

	// Remove the peer restriction added above.
	server.message_router.peers_override.lock().unwrap().clear();
	recipient.message_router.peers_override.lock().unwrap().clear();

	// Complete a payment to the new invoice.
	let offer = recipient.node.get_async_receive_offer().unwrap();
	let amt_msat = 5000;
	let payment_id = PaymentId([1; 32]);
	sender.node.pay_for_offer(&offer, Some(amt_msat), payment_id, Default::default()).unwrap();

	let release_held_htlc_om = pass_async_payments_oms(
		updated_invoice.clone(),
		sender,
		server,
		recipient,
		recipient_id,
		invoice_request_path,
	)
	.1;
	sender
		.onion_messenger
		.handle_onion_message(recipient.node.get_our_node_id(), &release_held_htlc_om);

	let mut events = sender.node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let ev = remove_first_msg_event_to_node(&server.node.get_our_node_id(), &mut events);
	let payment_hash = extract_payment_hash(&ev);
	check_added_monitors(&sender, 1);

	let route: &[&[&Node]] = &[&[server, recipient]];
	let args = PassAlongPathArgs::new(sender, route[0], amt_msat, payment_hash, ev);
	let claimable_ev = do_pass_along_path(args).unwrap();
	let keysend_preimage = extract_payment_preimage(&claimable_ev);
	let res = claim_payment_along_route(ClaimAlongRouteArgs::new(sender, route, keysend_preimage));
	assert_eq!(res.0, Some(PaidBolt12Invoice::StaticInvoice(updated_invoice)));
}

#[cfg_attr(feature = "std", ignore)]
#[test]
fn ignore_expired_static_invoice() {
	// If a server receives an expired static invoice to persist, they should ignore it and not
	// generate an event.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	create_unannounced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 0);
	let server = &nodes[0];
	let recipient = &nodes[1];
	let recipient_id = vec![42; 32];
	let inv_server_paths =
		server.node.blinded_paths_for_async_recipient(recipient_id, None).unwrap();
	recipient.node.set_paths_to_static_invoice_server(inv_server_paths).unwrap();

	let (_, serve_static_invoice_om) =
		invoice_flow_up_to_send_serve_static_invoice(server, recipient);

	// Advance time for the server so that by the time it receives the serve_static_invoice message,
	// the invoice within has expired.
	advance_time_by(TEST_DEFAULT_ASYNC_RECEIVE_OFFER_EXPIRY + Duration::from_secs(1), server);

	// Check that no Event::PersistStaticInvoice is generated.
	server
		.onion_messenger
		.handle_onion_message(recipient.node.get_our_node_id(), &serve_static_invoice_om);
	let mut events = server.node.get_and_clear_pending_events();
	assert!(events.is_empty());
}

#[test]
fn ignore_offer_paths_expiry_too_soon() {
	// Recipents should ignore received offer_paths that expire too soon.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	create_unannounced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 0);
	let server = &nodes[0];
	let recipient = &nodes[1];
	let recipient_id = vec![42; 32];
	let inv_server_paths =
		server.node.blinded_paths_for_async_recipient(recipient_id, None).unwrap();
	recipient.node.set_paths_to_static_invoice_server(inv_server_paths).unwrap();

	// Get a legit offer_paths message from the server.
	recipient.node.timer_tick_occurred();
	let offer_paths_req = recipient
		.onion_messenger
		.next_onion_message_for_peer(server.node.get_our_node_id())
		.unwrap();
	recipient.onion_messenger.release_pending_msgs();
	server.onion_messenger.handle_onion_message(recipient.node.get_our_node_id(), &offer_paths_req);
	let offer_paths = server
		.onion_messenger
		.next_onion_message_for_peer(recipient.node.get_our_node_id())
		.unwrap();

	// Get the blinded path use when manually sending the modified offer_paths message to the
	// recipient.
	let offer_paths_req_reply_path =
		match server.onion_messenger.peel_onion_message(&offer_paths_req) {
			Ok(PeeledOnion::AsyncPayments(
				AsyncPaymentsMessage::OfferPathsRequest(_),
				_,
				reply_path,
			)) => reply_path.unwrap(),
			_ => panic!(),
		};

	// Modify the offer_paths message from the server to indicate that the offer paths expire too
	// soon.
	let (mut offer_paths_unwrapped, ctx) = match recipient
		.onion_messenger
		.peel_onion_message(&offer_paths)
	{
		Ok(PeeledOnion::AsyncPayments(AsyncPaymentsMessage::OfferPaths(msg), ctx, _)) => (msg, ctx),
		_ => panic!(),
	};
	let too_soon_expiry_secs = recipient
		.node
		.duration_since_epoch()
		.as_secs()
		.saturating_add(TEST_MIN_OFFER_PATHS_RELATIVE_EXPIRY_SECS - 1);
	offer_paths_unwrapped.paths_absolute_expiry = Some(too_soon_expiry_secs);

	// Deliver the expired paths to the recipient and make sure they don't construct a
	// serve_static_invoice message in response.
	server
		.onion_messenger
		.send_onion_message(
			ParsedOnionMessageContents::<Infallible>::AsyncPayments(
				AsyncPaymentsMessage::OfferPaths(offer_paths_unwrapped),
			),
			MessageSendInstructions::WithReplyPath {
				destination: Destination::BlindedPath(offer_paths_req_reply_path),
				// This context isn't used because the recipient doesn't reply to the message
				context: MessageContext::AsyncPayments(ctx),
			},
		)
		.unwrap();
	let offer_paths_expiry_too_soon = server
		.onion_messenger
		.next_onion_message_for_peer(recipient.node.get_our_node_id())
		.unwrap();
	recipient
		.onion_messenger
		.handle_onion_message(server.node.get_our_node_id(), &offer_paths_expiry_too_soon);
	assert!(recipient
		.onion_messenger
		.next_onion_message_for_peer(server.node.get_our_node_id())
		.is_none());
}

#[test]
fn ignore_duplicate_offer() {
	// Test that if an async receiver gets notified that the invoice for an offer was persisted twice,
	// they won't cache the offer twice.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	create_unannounced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 0);

	let recipient_id = vec![42; 32];
	let inv_server_paths =
		nodes[0].node.blinded_paths_for_async_recipient(recipient_id.clone(), None).unwrap();
	nodes[1].node.set_paths_to_static_invoice_server(inv_server_paths).unwrap();

	let invoice_flow_res =
		pass_static_invoice_server_messages(&nodes[0], &nodes[1], recipient_id.clone());
	let static_invoice = invoice_flow_res.invoice;
	assert!(static_invoice.invoice_features().supports_basic_mpp());
	assert!(nodes[1].node.get_async_receive_offer().is_ok());

	// Check that the recipient will ignore duplicate offers received.
	nodes[1].onion_messenger.handle_onion_message(
		nodes[1].node.get_our_node_id(),
		&invoice_flow_res.static_invoice_persisted_message,
	);
	assert_eq!(nodes[1].node.flow.test_get_async_receive_offers().len(), 1);
}

#[cfg_attr(feature = "std", ignore)]
#[test]
fn remove_expired_offer_from_cache() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	create_unannounced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 0);
	let recipient = &nodes[1];

	let recipient_id = vec![42; 32];
	let inv_server_paths =
		nodes[0].node.blinded_paths_for_async_recipient(recipient_id.clone(), None).unwrap();
	nodes[1].node.set_paths_to_static_invoice_server(inv_server_paths).unwrap();
	pass_static_invoice_server_messages(&nodes[0], &nodes[1], recipient_id.clone());

	// We'll be able to retrieve the offer before it expires.
	assert!(nodes[1].node.get_async_receive_offer().is_ok());

	// After the offer expires we'll no longer return it from the API.
	advance_time_by(TEST_DEFAULT_ASYNC_RECEIVE_OFFER_EXPIRY + Duration::from_secs(1), recipient);
	assert!(nodes[1].node.get_async_receive_offer().is_err());
}

#[cfg_attr(feature = "std", ignore)]
#[test]
fn refresh_unused_offers() {
	// Check that if a user has an unused offer older than TEST_OFFER_REFRESH_THRESHOLD, they will
	// replace it with a fresh offer.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	create_unannounced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 0);
	let server = &nodes[0];
	let recipient = &nodes[1];

	let recipient_id = vec![42; 32];
	let inv_server_paths =
		server.node.blinded_paths_for_async_recipient(recipient_id.clone(), None).unwrap();
	recipient.node.set_paths_to_static_invoice_server(inv_server_paths).unwrap();

	// First fill up the offer cache.
	for _ in 0..(TEST_MAX_CACHED_OFFERS_TARGET - 1) {
		// Trigger a cache refresh
		recipient.node.timer_tick_occurred();

		pass_static_invoice_server_messages(server, recipient, recipient_id.clone());
	}

	// Have the last offer expire later than the others.
	advance_time_by(Duration::from_secs(1), recipient);
	pass_static_invoice_server_messages(server, recipient, recipient_id.clone());

	// Before the threshold, the recipient will not attempt to update any offers.
	advance_time_by(TEST_OFFER_REFRESH_THRESHOLD - Duration::from_secs(2), recipient);
	assert!(recipient
		.onion_messenger
		.release_pending_msgs()
		.get(&server.node.get_our_node_id())
		.unwrap()
		.is_empty());

	// After the threshold time passes, the recipient will attempt to replace all of their offers
	// (which are all unused) except the last.
	advance_time_by(Duration::from_secs(2), recipient);
	for expected_invoice_slot in 0..(TEST_MAX_CACHED_OFFERS_TARGET - 1) {
		// Trigger a cache refresh
		recipient.node.timer_tick_occurred();

		let flow_res = pass_static_invoice_server_messages(server, recipient, recipient_id.clone());
		assert_eq!(flow_res.invoice_slot, expected_invoice_slot as u16);
	}
	recipient.node.timer_tick_occurred();
	assert!(recipient
		.onion_messenger
		.release_pending_msgs()
		.get(&server.node.get_our_node_id())
		.unwrap()
		.is_empty());

	// The recipient will update the last offer after the threshold time has passed.
	advance_time_by(Duration::from_secs(1), recipient);
	recipient.node.timer_tick_occurred();
	let flow_res = pass_static_invoice_server_messages(server, recipient, recipient_id.clone());
	assert_eq!(flow_res.invoice_slot, TEST_MAX_CACHED_OFFERS_TARGET as u16 - 1);

	// If an offer is used, we shouldn't replace it after the threshold time.
	let offer = recipient.node.get_async_receive_offer().unwrap();
	advance_time_by(TEST_OFFER_REFRESH_THRESHOLD + Duration::from_secs(100), recipient);

	// All offers besides the used one should be successfully replaced.
	for _ in 0..(TEST_MAX_CACHED_OFFERS_TARGET - 1) {
		recipient.node.timer_tick_occurred();
		pass_static_invoice_server_messages(server, recipient, recipient_id.clone());
	}

	// The used offer should only get an invoice update.
	recipient.node.timer_tick_occurred();
	let mut pending_oms = recipient
		.onion_messenger
		.release_pending_msgs()
		.remove(&server.node.get_our_node_id())
		.unwrap();
	assert_eq!(pending_oms.len(), 1);
	let peeled_om = server.onion_messenger.peel_onion_message(&pending_oms[0]).unwrap();
	match peeled_om {
		PeeledOnion::AsyncPayments(AsyncPaymentsMessage::ServeStaticInvoice(msg), _, _) => {
			assert_eq!(msg.invoice.offer_message_paths(), offer.paths());
		},
		_ => panic!(),
	}

	// Check that the used offer is still in the cache
	assert!(recipient.node.flow.test_get_async_receive_offers().contains(&offer));
}

#[test]
fn invoice_server_is_not_channel_peer() {
	// Test that the async recipient's static invoice server does not need to be a channel peer for an
	// async payment to successfully complete.
	let chanmon_cfgs = create_chanmon_cfgs(4);
	let node_cfgs = create_node_cfgs(4, &chanmon_cfgs);

	let mut allow_priv_chan_fwds_cfg = test_default_channel_config();
	allow_priv_chan_fwds_cfg.accept_forwards_to_priv_channels = true;
	let node_chanmgrs =
		create_node_chanmgrs(4, &node_cfgs, &[None, Some(allow_priv_chan_fwds_cfg), None, None]);

	// Set up a network:
	//
	//         static_invoice_server
	//        /
	// sender -- forwarding_node ---- recipient
	//
	// So the static invoice server has no channels with the recipient.

	let nodes = create_network(4, &node_cfgs, &node_chanmgrs);
	let sender = &nodes[0];
	let forwarding_node = &nodes[1];
	let recipient = &nodes[2];
	let invoice_server = &nodes[3];
	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 0);
	create_announced_chan_between_nodes_with_value(&nodes, 0, 3, 1_000_000, 0);
	create_unannounced_chan_between_nodes_with_value(&nodes, 1, 2, 1_000_000, 0);

	let recipient_id = vec![42; 32];
	let inv_server_paths =
		invoice_server.node.blinded_paths_for_async_recipient(recipient_id.clone(), None).unwrap();
	recipient.node.set_paths_to_static_invoice_server(inv_server_paths).unwrap();
	expect_offer_paths_requests(&nodes[2], &[&nodes[0], &nodes[1], &nodes[3]]);
	let flow_res =
		pass_static_invoice_server_messages(invoice_server, recipient, recipient_id.clone());
	let invoice = flow_res.invoice;

	let offer = recipient.node.get_async_receive_offer().unwrap();
	let amt_msat = 5000;
	let payment_id = PaymentId([1; 32]);
	sender.node.pay_for_offer(&offer, Some(amt_msat), payment_id, Default::default()).unwrap();

	// Do the held_htlc_available --> release_held_htlc dance.
	let release_held_htlc_om = pass_async_payments_oms(
		invoice.clone(),
		sender,
		invoice_server,
		recipient,
		recipient_id,
		flow_res.invoice_request_path,
	)
	.1;
	sender
		.onion_messenger
		.handle_onion_message(recipient.node.get_our_node_id(), &release_held_htlc_om);

	// Check that the sender has queued the HTLCs of the async keysend payment.
	let mut events = sender.node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let ev = remove_first_msg_event_to_node(&forwarding_node.node.get_our_node_id(), &mut events);
	let payment_hash = extract_payment_hash(&ev);
	check_added_monitors(&sender, 1);

	let route: &[&[&Node]] = &[&[forwarding_node, recipient]];
	let args = PassAlongPathArgs::new(sender, route[0], amt_msat, payment_hash, ev);
	let claimable_ev = do_pass_along_path(args).unwrap();
	let keysend_preimage = extract_payment_preimage(&claimable_ev);
	let res = claim_payment_along_route(ClaimAlongRouteArgs::new(sender, route, keysend_preimage));
	assert_eq!(res.0, Some(PaidBolt12Invoice::StaticInvoice(invoice)));
}

#[test]
fn invoice_request_forwarded_to_async_recipient() {
	// Test that when an always-online node receives a static invoice request on behalf of an async
	// recipient it forwards the invoice request to the async recipient and also sends back the
	// static invoice to the payer.
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 0);
	create_unannounced_chan_between_nodes_with_value(&nodes, 1, 2, 1_000_000, 0);

	let sender = &nodes[0];
	let always_online_node = &nodes[1];
	let async_recipient = &nodes[2];

	let recipient_id = vec![42; 32];
	let inv_server_paths = always_online_node
		.node
		.blinded_paths_for_async_recipient(recipient_id.clone(), None)
		.unwrap();
	async_recipient.node.set_paths_to_static_invoice_server(inv_server_paths).unwrap();
	expect_offer_paths_requests(&nodes[2], &[&nodes[0], &nodes[1]]);

	let invoice_flow_res =
		pass_static_invoice_server_messages(&nodes[1], &nodes[2], recipient_id.clone());
	let static_invoice = invoice_flow_res.invoice;

	let offer = async_recipient.node.get_async_receive_offer().unwrap();
	let amt_msat = 5000;
	let payment_id = PaymentId([1; 32]);
	sender.node.pay_for_offer(&offer, Some(amt_msat), payment_id, Default::default()).unwrap();

	let sender_node_id = sender.node.get_our_node_id();

	// `invoice_request` message intended for the always-online node that receives requests on
	// behalf of async recipient.
	let invreq_om = sender
		.onion_messenger
		.next_onion_message_for_peer(always_online_node.node.get_our_node_id())
		.unwrap();

	always_online_node.onion_messenger.handle_onion_message(sender_node_id, &invreq_om);

	let mut events = always_online_node.node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	let (reply_path, invoice_request) = match events.pop().unwrap() {
		Event::StaticInvoiceRequested {
			recipient_id: ev_id,
			invoice_slot: _,
			reply_path,
			invoice_request,
		} => {
			assert_eq!(recipient_id, ev_id);
			(reply_path, invoice_request)
		},
		_ => panic!(),
	};

	always_online_node
		.node
		.respond_to_static_invoice_request(
			static_invoice,
			reply_path,
			invoice_request,
			invoice_flow_res.invoice_request_path,
		)
		.unwrap();

	// Check that the next onion messages are the invoice request that will be forwarded to the async
	// recipient and the static invoice to the payer.
	let invreq_om = always_online_node
		.onion_messenger
		.next_onion_message_for_peer(async_recipient.node.get_our_node_id())
		.unwrap();

	let static_invoice_om =
		always_online_node.onion_messenger.next_onion_message_for_peer(sender_node_id).unwrap();

	let peeled_msg = async_recipient.onion_messenger.peel_onion_message(&invreq_om).unwrap();
	assert!(matches!(peeled_msg, PeeledOnion::Offers(OffersMessage::InvoiceRequest(_), _, _)));

	let peeled_msg = sender.onion_messenger.peel_onion_message(&static_invoice_om).unwrap();
	assert!(matches!(peeled_msg, PeeledOnion::Offers(OffersMessage::StaticInvoice(_), _, _)));
}

#[test]
fn async_payment_e2e() {
	// Test the end-to-end flow of an async sender paying an async recipient.
	let chanmon_cfgs = create_chanmon_cfgs(4);
	let node_cfgs = create_node_cfgs(4, &chanmon_cfgs);

	let (sender_cfg, recipient_cfg) = (often_offline_node_cfg(), often_offline_node_cfg());
	let mut sender_lsp_cfg = test_default_channel_config();
	sender_lsp_cfg.enable_htlc_hold = true;
	let mut invoice_server_cfg = test_default_channel_config();
	invoice_server_cfg.accept_forwards_to_priv_channels = true;

	let node_chanmgrs = create_node_chanmgrs(
		4,
		&node_cfgs,
		&[Some(sender_cfg), Some(sender_lsp_cfg), Some(invoice_server_cfg), Some(recipient_cfg)],
	);
	let nodes = create_network(4, &node_cfgs, &node_chanmgrs);
	create_unannounced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 0);
	create_announced_chan_between_nodes_with_value(&nodes, 1, 2, 1_000_000, 0);
	create_unannounced_chan_between_nodes_with_value(&nodes, 2, 3, 1_000_000, 0);
	unify_blockheight_across_nodes(&nodes);
	let sender = &nodes[0];
	let sender_lsp = &nodes[1];
	let invoice_server = &nodes[2];
	let recipient = &nodes[3];

	// Retrieve the offer then disconnect the recipient from their LSP to simulate them going offline.
	let recipient_id = vec![42; 32];
	let inv_server_paths =
		invoice_server.node.blinded_paths_for_async_recipient(recipient_id.clone(), None).unwrap();
	recipient.node.set_paths_to_static_invoice_server(inv_server_paths).unwrap();
	expect_offer_paths_requests(recipient, &[invoice_server, sender_lsp]);
	let invoice_flow_res =
		pass_static_invoice_server_messages(invoice_server, recipient, recipient_id.clone());
	let invoice = invoice_flow_res.invoice;
	let invreq_path = invoice_flow_res.invoice_request_path;

	let offer = recipient.node.get_async_receive_offer().unwrap();
	recipient.node.peer_disconnected(invoice_server.node.get_our_node_id());
	recipient.onion_messenger.peer_disconnected(invoice_server.node.get_our_node_id());
	invoice_server.node.peer_disconnected(recipient.node.get_our_node_id());
	invoice_server.onion_messenger.peer_disconnected(recipient.node.get_our_node_id());

	let amt_msat = 5000;
	let payment_id = PaymentId([1; 32]);
	sender.node.pay_for_offer(&offer, Some(amt_msat), payment_id, Default::default()).unwrap();

	// Forward invreq to server, pass static invoice back, check that htlc was locked in/monitor was
	// added
	let (peer_id, invreq_om) = extract_invoice_request_om(sender, &[sender_lsp, invoice_server]);
	invoice_server.onion_messenger.handle_onion_message(peer_id, &invreq_om);

	let mut events = invoice_server.node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	let (reply_path, invreq) = match events.pop().unwrap() {
		Event::StaticInvoiceRequested {
			recipient_id: ev_id, reply_path, invoice_request, ..
		} => {
			assert_eq!(recipient_id, ev_id);
			(reply_path, invoice_request)
		},
		_ => panic!(),
	};

	invoice_server
		.node
		.respond_to_static_invoice_request(invoice, reply_path, invreq, invreq_path)
		.unwrap();
	let (peer_node_id, static_invoice_om, static_invoice) =
		extract_static_invoice_om(invoice_server, &[sender_lsp, sender]);
	let payment_hash =
		lock_in_htlc_for_static_invoice(&static_invoice_om, peer_node_id, sender, sender_lsp);

	// Ensure that after the held HTLC is locked in, the sender's lsp does not forward it immediately.
	sender_lsp.node.process_pending_htlc_forwards();
	assert!(sender_lsp.node.get_and_clear_pending_msg_events().is_empty());

	// Forward the held_htlc OM through to the invoice_server node, who should generate an
	// OnionMessageIntercepted event since the recipient is disconnected.
	let held_htlc_om_to_inv_server = sender
		.onion_messenger
		.next_onion_message_for_peer(invoice_server.node.get_our_node_id())
		.unwrap();
	invoice_server
		.onion_messenger
		.handle_onion_message(sender_lsp.node.get_our_node_id(), &held_htlc_om_to_inv_server);

	// Get the held_htlc OM from the interception event.
	let mut events_rc = core::cell::RefCell::new(Vec::new());
	invoice_server.onion_messenger.process_pending_events(&|e| Ok(events_rc.borrow_mut().push(e)));
	let events = events_rc.into_inner();
	let held_htlc_om = events
		.into_iter()
		.find_map(|ev| {
			if let Event::OnionMessageIntercepted { message, .. } = ev {
				// At least one of the intercepted onion messages will be an invoice request that the
				// invoice server is attempting to forward to the recipient, ignore that as we're testing
				// the static invoice flow
				let peeled_onion = recipient.onion_messenger.peel_onion_message(&message).unwrap();
				if matches!(
					peeled_onion,
					PeeledOnion::Offers(OffersMessage::InvoiceRequest { .. }, _, _)
				) {
					return None;
				}

				assert!(matches!(
					peeled_onion,
					PeeledOnion::AsyncPayments(AsyncPaymentsMessage::HeldHtlcAvailable(_), _, _)
				));
				Some(message)
			} else {
				None
			}
		})
		.unwrap();

	// Reconnect the recipient to the invoice_server so the held_htlc OM can be delivered.
	let mut reconnect_args = ReconnectArgs::new(invoice_server, recipient);
	reconnect_args.send_channel_ready = (true, true);
	reconnect_nodes(reconnect_args);

	// On reconnect, the invoice server should get an `OnionMessagePeerConnected` event and the
	// recipient should generate more offer_paths_requests.
	let events = core::cell::RefCell::new(Vec::new());
	invoice_server.onion_messenger.process_pending_events(&|e| Ok(events.borrow_mut().push(e)));
	assert_eq!(events.borrow().len(), 1);
	assert!(matches!(events.into_inner().pop().unwrap(), Event::OnionMessagePeerConnected { .. }));
	expect_offer_paths_requests(recipient, &[invoice_server]);

	// Now that the recipient is online, the payment can complete.
	recipient
		.onion_messenger
		.handle_onion_message(invoice_server.node.get_our_node_id(), &held_htlc_om);
	let (peer_id, release_htlc_om) =
		extract_release_htlc_oms(recipient, &[sender, sender_lsp, invoice_server]).pop().unwrap();
	sender_lsp.onion_messenger.handle_onion_message(peer_id, &release_htlc_om);

	sender_lsp.node.process_pending_htlc_forwards();
	let mut events = sender_lsp.node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let ev = remove_first_msg_event_to_node(&invoice_server.node.get_our_node_id(), &mut events);
	check_added_monitors(&sender_lsp, 1);

	let path: &[&Node] = &[invoice_server, recipient];
	let args = PassAlongPathArgs::new(sender_lsp, path, amt_msat, payment_hash, ev);
	let claimable_ev = do_pass_along_path(args).unwrap();

	let route: &[&[&Node]] = &[&[sender_lsp, invoice_server, recipient]];
	let keysend_preimage = extract_payment_preimage(&claimable_ev);
	let (res, _) =
		claim_payment_along_route(ClaimAlongRouteArgs::new(sender, route, keysend_preimage));
	assert_eq!(res, Some(PaidBolt12Invoice::StaticInvoice(static_invoice)));
}

#[test]
fn held_htlc_timeout() {
	// Test that if a held HTLC doesn't get released for a long time, it will eventually time out and
	// be failed backwards by the sender's LSP.
	let chanmon_cfgs = create_chanmon_cfgs(4);
	let node_cfgs = create_node_cfgs(4, &chanmon_cfgs);

	let (sender_cfg, recipient_cfg) = (often_offline_node_cfg(), often_offline_node_cfg());
	let mut sender_lsp_cfg = test_default_channel_config();
	sender_lsp_cfg.enable_htlc_hold = true;
	let mut invoice_server_cfg = test_default_channel_config();
	invoice_server_cfg.accept_forwards_to_priv_channels = true;

	let node_chanmgrs = create_node_chanmgrs(
		4,
		&node_cfgs,
		&[Some(sender_cfg), Some(sender_lsp_cfg), Some(invoice_server_cfg), Some(recipient_cfg)],
	);
	let nodes = create_network(4, &node_cfgs, &node_chanmgrs);
	create_unannounced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 0);
	create_announced_chan_between_nodes_with_value(&nodes, 1, 2, 1_000_000, 0);
	create_unannounced_chan_between_nodes_with_value(&nodes, 2, 3, 1_000_000, 0);
	unify_blockheight_across_nodes(&nodes);
	let sender = &nodes[0];
	let sender_lsp = &nodes[1];
	let invoice_server = &nodes[2];
	let recipient = &nodes[3];

	let amt_msat = 5000;
	let (_, peer_node_id, static_invoice_om) = build_async_offer_and_init_payment(amt_msat, &nodes);
	let payment_hash =
		lock_in_htlc_for_static_invoice(&static_invoice_om, peer_node_id, sender, sender_lsp);

	// Ensure that after the held HTLC is locked in, the sender's lsp does not forward it immediately.
	sender_lsp.node.process_pending_htlc_forwards();
	assert!(sender_lsp.node.get_and_clear_pending_msg_events().is_empty());

	let (peer_id, held_htlc_om) =
		extract_held_htlc_available_oms(sender, &[sender_lsp, invoice_server, recipient])
			.pop()
			.unwrap();
	recipient.onion_messenger.handle_onion_message(peer_id, &held_htlc_om);

	// Extract the release_htlc_om, but don't deliver it to the sender's LSP.
	let _ = extract_release_htlc_oms(recipient, &[sender, sender_lsp, invoice_server]);

	// Connect blocks to the sender's LSP until they timeout the HTLC.
	connect_blocks(
		sender_lsp,
		MIN_CLTV_EXPIRY_DELTA as u32
			+ TEST_FINAL_CLTV
			+ HTLC_FAIL_BACK_BUFFER
			+ LATENCY_GRACE_PERIOD_BLOCKS,
	);
	sender_lsp.node.process_pending_htlc_forwards();

	let expected_path = &[sender_lsp];
	let expected_route = &[&expected_path[..]];
	let mut evs = sender_lsp.node.get_and_clear_pending_events();
	assert_eq!(evs.len(), 1);
	match evs.pop().unwrap() {
		Event::HTLCHandlingFailed { failure_type, failure_reason, .. } => {
			assert!(matches!(failure_type, HTLCHandlingFailureType::InvalidForward { .. }));
			assert!(matches!(
				failure_reason,
				Some(HTLCHandlingFailureReason::Local {
					reason: LocalHTLCFailureReason::ForwardExpiryBuffer
				})
			));
		},
		_ => panic!(),
	}
	// Note that we won't retry the failed HTLC even though we originally allowed 1 retry attempt,
	// because held_htlc payments to static invoices aren't going to be retried ever until we support
	// trampoline.
	pass_failed_payment_back(
		sender,
		&expected_route[..],
		false,
		payment_hash,
		PaymentFailureReason::RetriesExhausted,
	);
}

#[test]
fn intercepted_hold_htlc() {
	// Test a payment `sender --> LSP --> recipient` such that the HTLC is both a hold htlc and an
	// intercept htlc, i.e. the HTLC needs be held until the recipient comes online *and* the LSP
	// needs to open a JIT channel to the recipient for the payment to complete.
	let chanmon_cfgs = create_chanmon_cfgs(4);
	let node_cfgs = create_node_cfgs(4, &chanmon_cfgs);
	let (sender_cfg, mut recipient_cfg) = (often_offline_node_cfg(), often_offline_node_cfg());
	recipient_cfg.manually_accept_inbound_channels = true;
	recipient_cfg.channel_handshake_limits.force_announced_channel_preference = false;

	let mut lsp_cfg = test_default_channel_config();
	lsp_cfg.htlc_interception_flags = HTLCInterceptionFlags::ToInterceptSCIDs as u8;
	lsp_cfg.accept_forwards_to_priv_channels = true;
	lsp_cfg.enable_htlc_hold = true;

	let node_chanmgrs = create_node_chanmgrs(
		4,
		&node_cfgs,
		&[Some(sender_cfg), Some(lsp_cfg), None, Some(recipient_cfg)],
	);
	let nodes = create_network(4, &node_cfgs, &node_chanmgrs);

	let sender = &nodes[0];
	let lsp = &nodes[1];
	let recipient = &nodes[3];

	// Only open a channel from sender <> LSP, not recipient <> LSP. The recipient <> LSP channel will
	// be a JIT channel created in response to an `HTLCIntercepted` event below.
	create_unannounced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 0);

	// Create an unused announced channel for the LSP node so it is an announced node for the purposes
	// of blinded pathfinding, etc. nodes[2] will never be used otherwise.
	create_announced_chan_between_nodes_with_value(&nodes, 1, 2, 1_000_000, 0);
	unify_blockheight_across_nodes(&nodes);

	// Typically, JIT channels are created by an LSP providing the recipient with special "intercept"
	// scids out-of-band, to be put in the recipient's BOLT 11 invoice route hints. The intercept
	// scids signal to the LSP to open a JIT channel.
	//
	// Below we hardcode blinded payment paths containing intercept scids, to be used in the
	// recipient's eventual static invoice, because we don't yet support intercept scids in the normal
	// static invoice server flow.

	// We need to be able to predict the offer_nonce in order to hardcode acceptable blinded payment
	// paths containing a JIT channel scid for the recipient below.
	// Without the offer_nonce used below in the `AsyncBolt12OfferContext` matching the eventual offer
	// that gets generated, the payment will be rejected.
	let hardcoded_random_bytes = [42; 32];
	*recipient.keys_manager.override_random_bytes.lock().unwrap() = Some(hardcoded_random_bytes);

	// Pass a dummy `ChannelDetails` when creating a blinded payment path, with an scid that indicates
	// to the LSP that they should open a 0-conf JIT channel to the recipient.
	let mut first_hops = sender.node.list_channels();
	let intercept_scid = lsp.node.get_intercept_scid();
	first_hops[0].short_channel_id = Some(intercept_scid);
	first_hops[0].inbound_scid_alias = Some(intercept_scid);

	let created_at = recipient.node.duration_since_epoch();
	let payment_secret = inbound_payment::create_for_spontaneous_payment(
		&recipient.keys_manager.get_expanded_key(),
		None,
		STATIC_INVOICE_DEFAULT_RELATIVE_EXPIRY.as_secs() as u32,
		created_at.as_secs(),
		None,
	)
	.unwrap();
	let mut offer_nonce = Nonce([0; Nonce::LENGTH]);
	offer_nonce.0.copy_from_slice(&hardcoded_random_bytes[..Nonce::LENGTH]);
	let payment_context = PaymentContext::AsyncBolt12Offer(AsyncBolt12OfferContext { offer_nonce });
	let blinded_payment_path_with_jit_channel_scid = recipient
		.node
		.flow
		.test_create_blinded_payment_paths(
			&recipient.router,
			first_hops,
			None,
			payment_secret,
			payment_context,
			u32::MAX,
		)
		.unwrap();
	recipient.router.expect_blinded_payment_paths(blinded_payment_path_with_jit_channel_scid);

	let amt_msat = 5000;
	let (static_invoice, peer_node_id, static_invoice_om) =
		build_async_offer_and_init_payment(amt_msat, &nodes);
	let payment_hash =
		lock_in_htlc_for_static_invoice(&static_invoice_om, peer_node_id, sender, lsp);

	// Ensure that after the held HTLC is locked in, the sender's lsp does not forward it immediately.
	lsp.node.process_pending_htlc_forwards();
	assert!(lsp.node.get_and_clear_pending_msg_events().is_empty());

	// Ensure we don't generate an `HTLCIntercepted` for the HTLC until the recipient sends
	// release_held_htlc.
	assert!(lsp.node.get_and_clear_pending_events().is_empty());

	let (peer_id, held_htlc_om) =
		extract_held_htlc_available_oms(sender, &[lsp, recipient, &nodes[2]]).pop().unwrap();
	recipient.onion_messenger.handle_onion_message(peer_id, &held_htlc_om);
	let (peer_id, release_htlc_om) =
		extract_release_htlc_oms(recipient, &[sender, lsp]).pop().unwrap();
	lsp.onion_messenger.handle_onion_message(peer_id, &release_htlc_om);
	lsp.node.process_pending_htlc_forwards();

	// After the sender's LSP receives release_held_htlc from the recipient, the HTLC will be
	// transitioned from a held HTLC to an intercept HTLC and we will generate an `HTLCIntercepted`
	// event.
	assert!(lsp.node.get_and_clear_pending_msg_events().is_empty());
	let evs = lsp.node.get_and_clear_pending_events();
	assert_eq!(evs.len(), 1);
	let (intercept_id, outbound_amt) = match evs[0] {
		Event::HTLCIntercepted {
			intercept_id,
			requested_next_hop_scid,
			expected_outbound_amount_msat,
			..
		} => {
			assert_eq!(requested_next_hop_scid, intercept_scid);
			(intercept_id, expected_outbound_amount_msat)
		},
		_ => panic!(),
	};

	// Open the just-in-time channel so the payment can then be forwarded.
	let (_, chan_id) = open_zero_conf_channel(&lsp, &recipient, None);
	lsp.node
		.forward_intercepted_htlc(
			intercept_id,
			&chan_id,
			recipient.node.get_our_node_id(),
			outbound_amt,
		)
		.unwrap();
	lsp.node.process_pending_htlc_forwards();

	let mut events = lsp.node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let ev = remove_first_msg_event_to_node(&recipient.node.get_our_node_id(), &mut events);
	check_added_monitors(&lsp, 1);

	let path: &[&Node] = &[recipient];
	let args = PassAlongPathArgs::new(lsp, path, amt_msat, payment_hash, ev);
	let claimable_ev = do_pass_along_path(args).unwrap();

	let route: &[&[&Node]] = &[&[lsp, recipient]];
	let keysend_preimage = extract_payment_preimage(&claimable_ev);
	let (res, _) =
		claim_payment_along_route(ClaimAlongRouteArgs::new(sender, route, keysend_preimage));
	assert_eq!(res, Some(PaidBolt12Invoice::StaticInvoice(static_invoice)));
}

#[test]
fn async_payment_mpp() {
	// An MPP payment from an often-offline sender to an often-offline recipient.
	let chanmon_cfgs = create_chanmon_cfgs(4);
	let node_cfgs = create_node_cfgs(4, &chanmon_cfgs);

	let (sender_cfg, recipient_cfg) = (often_offline_node_cfg(), often_offline_node_cfg());
	let mut lsp_cfg = test_default_channel_config();
	lsp_cfg.enable_htlc_hold = true;
	lsp_cfg.accept_forwards_to_priv_channels = true;

	let node_chanmgrs = create_node_chanmgrs(
		4,
		&node_cfgs,
		&[Some(sender_cfg), Some(lsp_cfg.clone()), Some(lsp_cfg), Some(recipient_cfg)],
	);
	let nodes = create_network(4, &node_cfgs, &node_chanmgrs);

	// Create this network topology:
	//         LSP1
	//        / |  \
	// sender   |   recipient
	//        \ |  /
	//      	LSP2
	// We open a public channel between LSP1 and LSP2 to ensure they are announced nodes.
	create_unannounced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 0);
	create_unannounced_chan_between_nodes_with_value(&nodes, 0, 2, 1_000_000, 0);
	create_announced_chan_between_nodes_with_value(&nodes, 1, 2, 1_000_000, 0);
	create_unannounced_chan_between_nodes_with_value(&nodes, 1, 3, 1_000_000, 0);
	create_unannounced_chan_between_nodes_with_value(&nodes, 2, 3, 1_000_000, 0);
	unify_blockheight_across_nodes(&nodes);
	let sender = &nodes[0];
	let lsp_a = &nodes[1];
	let lsp_b = &nodes[2];
	let recipient = &nodes[3];

	let amt_msat = 120_000_000;
	let (_, peer_id, static_invoice_om) = build_async_offer_and_init_payment(amt_msat, &nodes);

	// The sender should lock in the held HTLCs with their LSPs right after receiving the static invoice.
	sender.onion_messenger.handle_onion_message(peer_id, &static_invoice_om);
	check_added_monitors(sender, 2);
	let mut events = sender.node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 2);

	// HTLC 1
	let ev = remove_first_msg_event_to_node(&lsp_a.node.get_our_node_id(), &mut events);
	let commitment_update = match ev {
		MessageSendEvent::UpdateHTLCs { ref updates, .. } => updates,
		_ => panic!(),
	};
	let update_add = commitment_update.update_add_htlcs[0].clone();
	let payment_hash = update_add.payment_hash;
	assert!(update_add.hold_htlc.is_some());
	lsp_a.node.handle_update_add_htlc(sender.node.get_our_node_id(), &update_add);
	do_commitment_signed_dance(lsp_a, sender, &commitment_update.commitment_signed, false, true);
	lsp_a.node.process_pending_htlc_forwards();

	// HTLC 2
	let ev = remove_first_msg_event_to_node(&lsp_b.node.get_our_node_id(), &mut events);
	let commitment_update = match ev {
		MessageSendEvent::UpdateHTLCs { ref updates, .. } => updates,
		_ => panic!(),
	};
	let update_add = commitment_update.update_add_htlcs[0].clone();
	assert!(update_add.hold_htlc.is_some());
	lsp_b.node.handle_update_add_htlc(sender.node.get_our_node_id(), &update_add);
	do_commitment_signed_dance(lsp_b, sender, &commitment_update.commitment_signed, false, true);
	lsp_b.node.process_pending_htlc_forwards();

	// held htlc <> release_htlc dance
	let held_htlc_oms = extract_held_htlc_available_oms(sender, &[lsp_a, lsp_b, recipient]);
	// Expect at least 1 held_htlc OM per HTLC
	assert!(held_htlc_oms.len() >= 2);
	for (peer_id, held_htlc_om) in held_htlc_oms {
		recipient.onion_messenger.handle_onion_message(peer_id, &held_htlc_om);
	}
	let release_htlc_oms = extract_release_htlc_oms(recipient, &[sender, lsp_a, lsp_b]);
	assert!(release_htlc_oms.len() >= 2);
	for (peer_id, release_htlc_om) in release_htlc_oms {
		// Just give the OM to both LSPs for testing simplicity, only the correct one will successfully
		// parse it
		lsp_a.onion_messenger.handle_onion_message(peer_id, &release_htlc_om);
		lsp_b.onion_messenger.handle_onion_message(peer_id, &release_htlc_om);
	}

	let expected_path: &[&Node] = &[recipient];
	lsp_a.node.process_pending_htlc_forwards();
	check_added_monitors(&lsp_a, 1);
	let mut events = lsp_a.node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let ev = remove_first_msg_event_to_node(&recipient.node.get_our_node_id(), &mut events);
	let args = PassAlongPathArgs::new(lsp_a, expected_path, amt_msat, payment_hash, ev)
		.without_claimable_event();
	do_pass_along_path(args);

	lsp_b.node.process_pending_htlc_forwards();
	check_added_monitors(&lsp_b, 1);
	let mut events = lsp_b.node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let ev = remove_first_msg_event_to_node(&recipient.node.get_our_node_id(), &mut events);
	let args = PassAlongPathArgs::new(lsp_b, expected_path, amt_msat, payment_hash, ev);
	let claimable_ev = do_pass_along_path(args).unwrap();

	let keysend_preimage = match claimable_ev {
		Event::PaymentClaimable {
			purpose: PaymentPurpose::Bolt12OfferPayment { payment_preimage, .. },
			..
		} => payment_preimage.unwrap(),
		_ => panic!(),
	};

	let expected_route: &[&[&Node]] = &[&[&nodes[1], &nodes[3]], &[&nodes[2], &nodes[3]]];
	claim_payment_along_route(ClaimAlongRouteArgs::new(sender, expected_route, keysend_preimage));
}

#[test]
fn fail_held_htlcs_when_cfg_unset() {
	// Test that if we receive a held HTLC but `UserConfig::enable_htlc_hold` is unset, we will fail
	// it backwards.
	let chanmon_cfgs = create_chanmon_cfgs(4);
	let node_cfgs = create_node_cfgs(4, &chanmon_cfgs);

	let (sender_cfg, recipient_cfg) = (often_offline_node_cfg(), often_offline_node_cfg());
	let mut sender_lsp_cfg = test_default_channel_config();
	sender_lsp_cfg.enable_htlc_hold = true;
	let mut inv_server_cfg = test_default_channel_config();
	inv_server_cfg.accept_forwards_to_priv_channels = true;

	let cfgs = &[
		Some(sender_cfg),
		Some(sender_lsp_cfg.clone()),
		Some(inv_server_cfg),
		Some(recipient_cfg),
	];
	let node_chanmgrs = create_node_chanmgrs(4, &node_cfgs, cfgs);
	let nodes = create_network(4, &node_cfgs, &node_chanmgrs);
	create_unannounced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 0);
	create_announced_chan_between_nodes_with_value(&nodes, 1, 2, 1_000_000, 0);
	create_unannounced_chan_between_nodes_with_value(&nodes, 2, 3, 1_000_000, 0);
	unify_blockheight_across_nodes(&nodes);
	let sender = &nodes[0];
	let sender_lsp = &nodes[1];

	let (_, peer_node_id, static_invoice_om) = build_async_offer_and_init_payment(5000, &nodes);

	// Just before the sender sends the HTLC to their LSP, their LSP disables support for the feature.
	sender_lsp_cfg.enable_htlc_hold = false;
	sender_lsp.node.set_current_config(sender_lsp_cfg);

	let payment_hash =
		lock_in_htlc_for_static_invoice(&static_invoice_om, peer_node_id, sender, sender_lsp);

	// The LSP will then fail the HTLC back to the sender.
	sender_lsp.node.process_pending_htlc_forwards();
	let expected_path = &[sender_lsp];
	let expected_route = &[&expected_path[..]];
	let mut evs = sender_lsp.node.get_and_clear_pending_events();
	assert_eq!(evs.len(), 1);
	match evs.pop().unwrap() {
		Event::HTLCHandlingFailed { failure_type, failure_reason, .. } => {
			assert!(matches!(failure_type, HTLCHandlingFailureType::Forward { .. }));
			assert!(matches!(
				failure_reason,
				Some(HTLCHandlingFailureReason::Local {
					reason: LocalHTLCFailureReason::TemporaryNodeFailure
				})
			));
		},
		_ => panic!(),
	}
	pass_failed_payment_back(
		sender,
		&expected_route[..],
		false,
		payment_hash,
		PaymentFailureReason::RetriesExhausted,
	);
}

#[test]
fn release_htlc_races_htlc_onion_decode() {
	// Test that an async sender's LSP will release held HTLCs even if they receive the
	// release_held_htlc message before they have a chance to process the held HTLC's onion. This was
	// previously broken.
	let chanmon_cfgs = create_chanmon_cfgs(4);
	let node_cfgs = create_node_cfgs(4, &chanmon_cfgs);

	let (sender_cfg, recipient_cfg) = (often_offline_node_cfg(), often_offline_node_cfg());
	let mut sender_lsp_cfg = test_default_channel_config();
	sender_lsp_cfg.enable_htlc_hold = true;
	let mut invoice_server_cfg = test_default_channel_config();
	invoice_server_cfg.accept_forwards_to_priv_channels = true;

	let node_chanmgrs = create_node_chanmgrs(
		4,
		&node_cfgs,
		&[Some(sender_cfg), Some(sender_lsp_cfg), Some(invoice_server_cfg), Some(recipient_cfg)],
	);
	let nodes = create_network(4, &node_cfgs, &node_chanmgrs);
	create_unannounced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 0);
	create_announced_chan_between_nodes_with_value(&nodes, 1, 2, 1_000_000, 0);
	create_unannounced_chan_between_nodes_with_value(&nodes, 2, 3, 1_000_000, 0);
	unify_blockheight_across_nodes(&nodes);
	let sender = &nodes[0];
	let sender_lsp = &nodes[1];
	let invoice_server = &nodes[2];
	let recipient = &nodes[3];

	let amt_msat = 5000;
	let (static_invoice, peer_id, static_invoice_om) =
		build_async_offer_and_init_payment(amt_msat, &nodes);
	let payment_hash =
		lock_in_htlc_for_static_invoice(&static_invoice_om, peer_id, sender, sender_lsp);

	// The LSP has not transitioned the HTLC to the intercepts map internally because
	// process_pending_htlc_forwards has not been called.
	let (peer_id, held_htlc_om) =
		extract_held_htlc_available_oms(sender, &[sender_lsp, invoice_server, recipient])
			.pop()
			.unwrap();
	recipient.onion_messenger.handle_onion_message(peer_id, &held_htlc_om);

	// Extract the release_htlc_om and ensure the sender's LSP will release the HTLC on the next call
	// to process_pending_htlc_forwards, even though the HTLC was not yet officially intercepted when
	// the release message arrived.
	let (peer_id, release_htlc_om) =
		extract_release_htlc_oms(recipient, &[sender, sender_lsp, invoice_server]).pop().unwrap();
	sender_lsp.onion_messenger.handle_onion_message(peer_id, &release_htlc_om);

	sender_lsp.node.process_pending_htlc_forwards();
	let mut events = sender_lsp.node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let ev = remove_first_msg_event_to_node(&invoice_server.node.get_our_node_id(), &mut events);
	check_added_monitors(&sender_lsp, 1);

	let path: &[&Node] = &[invoice_server, recipient];
	let args = PassAlongPathArgs::new(sender_lsp, path, amt_msat, payment_hash, ev);
	let claimable_ev = do_pass_along_path(args).unwrap();

	let route: &[&[&Node]] = &[&[sender_lsp, invoice_server, recipient]];
	let keysend_preimage = extract_payment_preimage(&claimable_ev);
	let (res, _) =
		claim_payment_along_route(ClaimAlongRouteArgs::new(sender, route, keysend_preimage));
	assert_eq!(res, Some(PaidBolt12Invoice::StaticInvoice(static_invoice)));
}
