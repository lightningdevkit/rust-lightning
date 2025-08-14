// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

use crate::blinded_path::message::{MessageContext, OffersContext};
use crate::blinded_path::payment::PaymentContext;
use crate::blinded_path::payment::{AsyncBolt12OfferContext, BlindedPaymentTlvs};
use crate::chain::channelmonitor::{HTLC_FAIL_BACK_BUFFER, LATENCY_GRACE_PERIOD_BLOCKS};
use crate::events::{
	Event, HTLCHandlingFailureType, PaidBolt12Invoice, PaymentFailureReason, PaymentPurpose,
};
use crate::ln::blinded_payment_tests::{fail_blinded_htlc_backwards, get_blinded_route_parameters};
use crate::ln::channelmanager::{PaymentId, RecipientOnionFields};
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
use crate::routing::router::{Payee, PaymentParameters, RouteParametersConfig};
use crate::sign::NodeSigner;
use crate::sync::Mutex;
use crate::types::features::Bolt12InvoiceFeatures;
use crate::types::payment::{PaymentHash, PaymentPreimage, PaymentSecret};
use crate::util::ser::Writeable;
use bitcoin::constants::ChainHash;
use bitcoin::network::Network;
use bitcoin::secp256k1;
use bitcoin::secp256k1::Secp256k1;

use core::convert::Infallible;
use core::time::Duration;

struct StaticInvoiceServerFlowResult {
	invoice: StaticInvoice,
	invoice_slot: u16,

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
	let (invoice, invoice_slot, ack_path) = match events.pop().unwrap() {
		Event::PersistStaticInvoice {
			invoice,
			invoice_persisted_path,
			recipient_id: ev_id,
			invoice_slot,
		} => {
			assert_eq!(recipient_id, ev_id);
			(invoice, invoice_slot, invoice_persisted_path)
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
	recipient: &Node, recipient_id: Vec<u8>,
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
	let reply_path = match events.pop().unwrap() {
		Event::StaticInvoiceRequested { recipient_id: ev_id, invoice_slot: _, reply_path } => {
			assert_eq!(recipient_id, ev_id);
			reply_path
		},
		_ => panic!(),
	};

	always_online_recipient_counterparty
		.node
		.send_static_invoice(static_invoice, reply_path)
		.unwrap();
	let static_invoice_om = always_online_recipient_counterparty
		.onion_messenger
		.next_onion_message_for_peer(sender_node_id)
		.unwrap();
	sender.onion_messenger.handle_onion_message(always_online_node_id, &static_invoice_om);

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
	let entropy = recipient.keys_manager;
	let amount_msat = offer.amount().and_then(|amount| match amount {
		Amount::Bitcoin { amount_msats } => Some(amount_msats),
		Amount::Currency { .. } => None,
	});

	let relative_expiry = relative_expiry.unwrap_or(STATIC_INVOICE_DEFAULT_RELATIVE_EXPIRY);
	let relative_expiry_secs: u32 = relative_expiry.as_secs().try_into().unwrap_or(u32::MAX);

	let created_at = recipient.node.duration_since_epoch();
	let payment_secret = inbound_payment::create_for_spontaneous_payment(
		&recipient.keys_manager.get_inbound_payment_key(),
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
			entropy,
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
	let per_msg_recipient_msgs = recipient.onion_messenger.release_pending_msgs();
	let mut pk_to_msg = Vec::new();
	for (pk, msgs) in per_msg_recipient_msgs {
		for msg in msgs {
			pk_to_msg.push((pk, msg));
		}
	}
	let mut num_offer_paths_reqs: u8 = 0;
	while let Some((pk, msg)) = pk_to_msg.pop() {
		let node = next_hop_nodes.iter().find(|node| node.node.get_our_node_id() == pk).unwrap();
		let peeled_msg = node.onion_messenger.peel_onion_message(&msg).unwrap();
		match peeled_msg {
			PeeledOnion::AsyncPayments(AsyncPaymentsMessage::OfferPathsRequest(_), _, _) => {
				num_offer_paths_reqs += 1;
			},
			PeeledOnion::Forward(next_hop, msg) => {
				let next_pk = match next_hop {
					crate::blinded_path::message::NextMessageHop::NodeId(pk) => pk,
					_ => panic!(),
				};
				pk_to_msg.push((next_pk, msg));
			},
			_ => panic!("Unexpected message"),
		}
	}
	assert!(num_offer_paths_reqs > 0);
}

fn advance_time_by(duration: Duration, node: &Node) {
	let target_time = (node.node.duration_since_epoch() + duration).as_secs() as u32;
	let block = create_dummy_block(node.best_block_hash(), target_time, Vec::new());
	connect_block(node, &block);
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

	let updates_2_1 = get_htlc_update_msgs!(nodes[2], nodes[1].node.get_our_node_id());
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

	let updates_1_0 = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
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
	let params = RouteParametersConfig::default();
	nodes[0]
		.node
		.pay_for_offer(&offer, None, Some(amt_msat), None, payment_id, Retry::Attempts(0), params)
		.unwrap();

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
	let unexpected_static_invoice =
		pass_static_invoice_server_messages(&nodes[1], &nodes[2], recipient_id.clone()).invoice;

	let amt_msat = 5000;
	let payment_id = PaymentId([1; 32]);
	let params = RouteParametersConfig::default();
	nodes[0]
		.node
		.pay_for_offer(&offer, None, Some(amt_msat), None, payment_id, Retry::Attempts(0), params)
		.unwrap();

	let invreq_om = nodes[0]
		.onion_messenger
		.next_onion_message_for_peer(nodes[1].node.get_our_node_id())
		.unwrap();
	nodes[1].onion_messenger.handle_onion_message(nodes[0].node.get_our_node_id(), &invreq_om);

	let mut events = nodes[1].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	let reply_path = match events.pop().unwrap() {
		Event::StaticInvoiceRequested { recipient_id: ev_id, invoice_slot: _, reply_path } => {
			assert_eq!(recipient_id, ev_id);
			reply_path
		},
		_ => panic!(),
	};

	// Check that the sender will ignore the unexpected static invoice.
	nodes[1].node.send_static_invoice(unexpected_static_invoice, reply_path.clone()).unwrap();
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
	nodes[1].node.send_static_invoice(valid_static_invoice.clone(), reply_path.clone()).unwrap();
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
	nodes[1].node.send_static_invoice(valid_static_invoice, reply_path).unwrap();
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
	let params = RouteParametersConfig::default();
	nodes[0]
		.node
		.pay_for_offer(&offer, None, Some(amt_msat), None, payment_id, Retry::Attempts(0), params)
		.unwrap();
	let release_held_htlc_om = pass_async_payments_oms(
		static_invoice.clone(),
		&nodes[0],
		&nodes[1],
		&nodes[2],
		recipient_id,
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
	check_added_monitors!(nodes[0], 1);

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

	let static_invoice =
		pass_static_invoice_server_messages(&nodes[1], &nodes[2], recipient_id.clone()).invoice;
	let offer = nodes[2].node.get_async_receive_offer().unwrap();

	let amt_msat = 5000;
	let payment_id = PaymentId([1; 32]);
	let params = RouteParametersConfig::default();
	nodes[0]
		.node
		.pay_for_offer(&offer, None, Some(amt_msat), None, payment_id, Retry::Attempts(0), params)
		.unwrap();

	let invreq_om = nodes[0]
		.onion_messenger
		.next_onion_message_for_peer(nodes[1].node.get_our_node_id())
		.unwrap();
	nodes[1].onion_messenger.handle_onion_message(nodes[0].node.get_our_node_id(), &invreq_om);

	let mut events = nodes[1].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	let reply_path = match events.pop().unwrap() {
		Event::StaticInvoiceRequested { reply_path, .. } => reply_path,
		_ => panic!(),
	};

	nodes[1].node.send_static_invoice(static_invoice.clone(), reply_path).unwrap();
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

	let static_invoice =
		pass_static_invoice_server_messages(server, recipient, recipient_id.clone()).invoice;
	let offer = recipient.node.get_async_receive_offer().unwrap();

	let amt_msat = 5000;
	let payment_id = PaymentId([1; 32]);
	let params = RouteParametersConfig::default();
	sender
		.node
		.pay_for_offer(&offer, None, Some(amt_msat), None, payment_id, Retry::Attempts(0), params)
		.unwrap();

	let invreq_om =
		sender.onion_messenger.next_onion_message_for_peer(server.node.get_our_node_id()).unwrap();
	server.onion_messenger.handle_onion_message(sender.node.get_our_node_id(), &invreq_om);

	let mut events = server.node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	let reply_path = match events.pop().unwrap() {
		Event::StaticInvoiceRequested { reply_path, .. } => reply_path,
		_ => panic!(),
	};

	server.node.send_static_invoice(static_invoice.clone(), reply_path).unwrap();
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

	let static_invoice =
		pass_static_invoice_server_messages(&nodes[1], &nodes[3], recipient_id.clone()).invoice;
	let offer = nodes[3].node.get_async_receive_offer().unwrap();

	let amt_msat = 15_000_000;
	let payment_id = PaymentId([1; 32]);
	let params = RouteParametersConfig::default();
	nodes[0]
		.node
		.pay_for_offer(&offer, None, Some(amt_msat), None, payment_id, Retry::Attempts(1), params)
		.unwrap();
	let release_held_htlc_om_3_0 =
		pass_async_payments_oms(static_invoice, &nodes[0], &nodes[1], &nodes[3], recipient_id).1;
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

	let static_invoice =
		pass_static_invoice_server_messages(&nodes[1], &nodes[3], recipient_id.clone()).invoice;
	let offer = nodes[3].node.get_async_receive_offer().unwrap();

	let amt_msat = 5000;
	let payment_id = PaymentId([1; 32]);
	let params = RouteParametersConfig::default();
	nodes[0]
		.node
		.pay_for_offer(&offer, None, Some(amt_msat), None, payment_id, Retry::Attempts(1), params)
		.unwrap();
	let release_held_htlc_om_3_0 =
		pass_async_payments_oms(static_invoice, &nodes[0], &nodes[1], &nodes[3], recipient_id).1;

	// Replace the invoice request contained within outbound_payments before sending so the invreq
	// amount doesn't match the onion amount when the HTLC gets to the recipient.
	let mut valid_invreq = None;
	nodes[0].node.test_modify_pending_payment(&payment_id, |pmt| {
		if let PendingOutboundPayment::StaticInvoiceReceived { invoice_request, .. } = pmt {
			valid_invreq = Some(invoice_request.clone());
			*invoice_request = offer
				.request_invoice(
					&nodes[0].keys_manager.get_inbound_payment_key(),
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
	check_added_monitors!(nodes[0], 1);
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

	let static_invoice =
		pass_static_invoice_server_messages(&nodes[1], &nodes[2], recipient_id.clone()).invoice;
	let offer = nodes[2].node.get_async_receive_offer().unwrap();

	let params = RouteParametersConfig::default();
	nodes[0]
		.node
		.pay_for_offer(&offer, None, Some(amt_msat), None, payment_id, Retry::Attempts(2), params)
		.unwrap();
	let release_held_htlc_om_2_0 =
		pass_async_payments_oms(static_invoice, &nodes[0], &nodes[1], &nodes[2], recipient_id).1;
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
	check_added_monitors!(nodes[2], 1);
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
	check_added_monitors!(nodes[0], 1);
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
	check_added_monitors!(nodes[0], 1);
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

	let static_invoice =
		pass_static_invoice_server_messages(&nodes[1], &nodes[2], recipient_id.clone()).invoice;
	let offer = nodes[2].node.get_async_receive_offer().unwrap();

	let amt_msat = 5000;
	let payment_id = PaymentId([1; 32]);
	let params = RouteParametersConfig::default();
	nodes[0]
		.node
		.pay_for_offer(&offer, None, Some(amt_msat), None, payment_id, Retry::Attempts(1), params)
		.unwrap();

	// While the invoice is unexpired, respond with release_held_htlc.
	let (held_htlc_available_om, _release_held_htlc_om) = pass_async_payments_oms(
		static_invoice.clone(),
		&nodes[0],
		&nodes[1],
		&nodes[2],
		recipient_id,
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
			BlindedPaymentTlvs::Receive(tlvs) => tlvs.tlvs.payment_constraints.max_cltv_expiry,
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

	let static_invoice =
		pass_static_invoice_server_messages(&nodes[1], &nodes[2], recipient_id.clone()).invoice;
	let offer = nodes[2].node.get_async_receive_offer().unwrap();

	let amt_msat = 5000;
	let payment_id = PaymentId([1; 32]);
	let params = RouteParametersConfig::default();
	nodes[0]
		.node
		.pay_for_offer(&offer, None, Some(amt_msat), None, payment_id, Retry::Attempts(0), params)
		.unwrap();
	let release_held_htlc_om =
		pass_async_payments_oms(static_invoice, &nodes[0], &nodes[1], &nodes[2], recipient_id).1;
	nodes[0]
		.onion_messenger
		.handle_onion_message(nodes[2].node.get_our_node_id(), &release_held_htlc_om);

	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let ev = remove_first_msg_event_to_node(&nodes[1].node.get_our_node_id(), &mut events);
	let payment_hash = extract_payment_hash(&ev);
	check_added_monitors!(nodes[0], 1);

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
	let (updated_invoice, ack_path) = match events.pop().unwrap() {
		Event::PersistStaticInvoice {
			invoice,
			invoice_slot,
			invoice_persisted_path,
			recipient_id: ev_id,
		} => {
			assert_ne!(original_invoice, invoice);
			assert_eq!(recipient_id, ev_id);
			assert_eq!(invoice_slot, flow_res.invoice_slot);
			// When we update the invoice corresponding to a specific offer, the invoice_slot stays the
			// same.
			assert_eq!(invoice_slot, flow_res.invoice_slot);
			(invoice, invoice_persisted_path)
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
	let params = RouteParametersConfig::default();
	sender
		.node
		.pay_for_offer(&offer, None, Some(amt_msat), None, payment_id, Retry::Attempts(0), params)
		.unwrap();

	let release_held_htlc_om =
		pass_async_payments_oms(updated_invoice.clone(), sender, server, recipient, recipient_id).1;
	sender
		.onion_messenger
		.handle_onion_message(recipient.node.get_our_node_id(), &release_held_htlc_om);

	let mut events = sender.node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let ev = remove_first_msg_event_to_node(&server.node.get_our_node_id(), &mut events);
	let payment_hash = extract_payment_hash(&ev);
	check_added_monitors!(sender, 1);

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
	let invoice =
		pass_static_invoice_server_messages(invoice_server, recipient, recipient_id.clone())
			.invoice;

	let offer = recipient.node.get_async_receive_offer().unwrap();
	let amt_msat = 5000;
	let payment_id = PaymentId([1; 32]);
	let params = RouteParametersConfig::default();
	sender
		.node
		.pay_for_offer(&offer, None, Some(amt_msat), None, payment_id, Retry::Attempts(0), params)
		.unwrap();

	// Do the held_htlc_available --> release_held_htlc dance.
	let release_held_htlc_om =
		pass_async_payments_oms(invoice.clone(), sender, invoice_server, recipient, recipient_id).1;
	sender
		.onion_messenger
		.handle_onion_message(recipient.node.get_our_node_id(), &release_held_htlc_om);

	// Check that the sender has queued the HTLCs of the async keysend payment.
	let mut events = sender.node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let ev = remove_first_msg_event_to_node(&forwarding_node.node.get_our_node_id(), &mut events);
	let payment_hash = extract_payment_hash(&ev);
	check_added_monitors!(sender, 1);

	let route: &[&[&Node]] = &[&[forwarding_node, recipient]];
	let args = PassAlongPathArgs::new(sender, route[0], amt_msat, payment_hash, ev);
	let claimable_ev = do_pass_along_path(args).unwrap();
	let keysend_preimage = extract_payment_preimage(&claimable_ev);
	let res = claim_payment_along_route(ClaimAlongRouteArgs::new(sender, route, keysend_preimage));
	assert_eq!(res.0, Some(PaidBolt12Invoice::StaticInvoice(invoice)));
}
