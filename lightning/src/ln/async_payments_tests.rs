// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

use crate::blinded_path::message::{MessageContext, OffersContext};
use crate::events::{Event, HTLCDestination, MessageSendEventsProvider, PaymentFailureReason};
use crate::ln::blinded_payment_tests::{blinded_payment_path, get_blinded_route_parameters};
use crate::ln::channelmanager;
use crate::ln::channelmanager::{PaymentId, RecipientOnionFields};
use crate::ln::functional_test_utils::*;
use crate::ln::inbound_payment;
use crate::ln::msgs::ChannelMessageHandler;
use crate::ln::msgs::OnionMessageHandler;
use crate::ln::offers_tests;
use crate::ln::onion_utils::INVALID_ONION_BLINDING;
use crate::ln::outbound_payment::Retry;
use crate::offers::nonce::Nonce;
use crate::offers::offer::Offer;
use crate::offers::static_invoice::StaticInvoice;
use crate::onion_message::async_payments::{
	AsyncPaymentsMessage, AsyncPaymentsMessageHandler, ReleaseHeldHtlc,
};
use crate::onion_message::messenger::{Destination, MessageRouter, MessageSendInstructions};
use crate::onion_message::offers::OffersMessage;
use crate::onion_message::packet::ParsedOnionMessageContents;
use crate::prelude::*;
use crate::routing::router::{PaymentParameters, RouteParameters};
use crate::sign::NodeSigner;
use crate::types::features::Bolt12InvoiceFeatures;
use crate::types::payment::{PaymentPreimage, PaymentSecret};
use crate::util::config::UserConfig;
use bitcoin::secp256k1;
use bitcoin::secp256k1::Secp256k1;

use core::convert::Infallible;
use core::time::Duration;

fn create_static_invoice<T: secp256k1::Signing + secp256k1::Verification>(
	always_online_counterparty: &Node, recipient: &Node, relative_expiry: Option<Duration>,
	secp_ctx: &Secp256k1<T>,
) -> (Offer, StaticInvoice) {
	let blinded_paths_to_always_online_node = always_online_counterparty
		.message_router
		.create_blinded_paths(
			always_online_counterparty.node.get_our_node_id(),
			MessageContext::Offers(OffersContext::InvoiceRequest { nonce: Nonce([42; 16]) }),
			Vec::new(),
			&secp_ctx,
		)
		.unwrap();
	let (offer_builder, offer_nonce) = recipient
		.node
		.create_async_receive_offer_builder(blinded_paths_to_always_online_node)
		.unwrap();
	let offer = offer_builder.build().unwrap();
	let static_invoice = recipient
		.node
		.create_static_invoice_builder(&offer, offer_nonce, relative_expiry)
		.unwrap()
		.build_and_sign(&secp_ctx)
		.unwrap();
	(offer, static_invoice)
}

#[test]
fn blinded_keysend() {
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 0);
	let chan_upd_1_2 =
		create_announced_chan_between_nodes_with_value(&nodes, 1, 2, 1_000_000, 0).0.contents;

	let inbound_payment_key = nodes[2].keys_manager.get_inbound_payment_key();
	let payment_secret = inbound_payment::create_for_spontaneous_payment(
		&inbound_payment_key,
		None,
		u32::MAX,
		nodes[2].node.duration_since_epoch().as_secs(),
		None,
	)
	.unwrap();

	let amt_msat = 5000;
	let keysend_preimage = PaymentPreimage([42; 32]);
	let route_params = get_blinded_route_parameters(
		amt_msat,
		payment_secret,
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
	pass_along_path(
		&nodes[0],
		expected_route[0],
		amt_msat,
		payment_hash,
		Some(payment_secret),
		ev.clone(),
		true,
		Some(keysend_preimage),
	);
	claim_payment_along_route(ClaimAlongRouteArgs::new(
		&nodes[0],
		expected_route,
		keysend_preimage,
	));
}

#[test]
fn blinded_mpp_keysend() {
	let chanmon_cfgs = create_chanmon_cfgs(4);
	let node_cfgs = create_node_cfgs(4, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(4, &node_cfgs, &[None, None, None, None]);
	let nodes = create_network(4, &node_cfgs, &node_chanmgrs);

	create_announced_chan_between_nodes(&nodes, 0, 1);
	create_announced_chan_between_nodes(&nodes, 0, 2);
	let chan_1_3 = create_announced_chan_between_nodes(&nodes, 1, 3);
	let chan_2_3 = create_announced_chan_between_nodes(&nodes, 2, 3);

	let inbound_payment_key = nodes[3].keys_manager.get_inbound_payment_key();
	let payment_secret = inbound_payment::create_for_spontaneous_payment(
		&inbound_payment_key,
		None,
		u32::MAX,
		nodes[3].node.duration_since_epoch().as_secs(),
		None,
	)
	.unwrap();

	let amt_msat = 15_000_000;
	let keysend_preimage = PaymentPreimage([42; 32]);
	let route_params = {
		let pay_params = PaymentParameters::blinded(vec![
			blinded_payment_path(
				payment_secret,
				1,
				1_0000_0000,
				vec![nodes[1].node.get_our_node_id(), nodes[3].node.get_our_node_id()],
				&[&chan_1_3.0.contents],
				&chanmon_cfgs[3].keys_manager,
			),
			blinded_payment_path(
				payment_secret,
				1,
				1_0000_0000,
				vec![nodes[2].node.get_our_node_id(), nodes[3].node.get_our_node_id()],
				&[&chan_2_3.0.contents],
				&chanmon_cfgs[3].keys_manager,
			),
		])
		.with_bolt12_features(channelmanager::provided_bolt12_invoice_features(
			&UserConfig::default(),
		))
		.unwrap();
		RouteParameters::from_payment_params_and_value(pay_params, amt_msat)
	};

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
	check_added_monitors!(nodes[0], 2);

	let expected_route: &[&[&Node]] = &[&[&nodes[1], &nodes[3]], &[&nodes[2], &nodes[3]]];
	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 2);

	let ev = remove_first_msg_event_to_node(&nodes[1].node.get_our_node_id(), &mut events);
	pass_along_path(
		&nodes[0],
		expected_route[0],
		amt_msat,
		payment_hash.clone(),
		Some(payment_secret),
		ev.clone(),
		false,
		Some(keysend_preimage),
	);

	let ev = remove_first_msg_event_to_node(&nodes[2].node.get_our_node_id(), &mut events);
	pass_along_path(
		&nodes[0],
		expected_route[1],
		amt_msat,
		payment_hash.clone(),
		Some(payment_secret),
		ev.clone(),
		true,
		Some(keysend_preimage),
	);
	claim_payment_along_route(ClaimAlongRouteArgs::new(
		&nodes[0],
		expected_route,
		keysend_preimage,
	));
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
			.expect_failure(HTLCDestination::FailedPayment { payment_hash });
	do_pass_along_path(args);

	let updates_2_1 = get_htlc_update_msgs!(nodes[2], nodes[1].node.get_our_node_id());
	assert_eq!(updates_2_1.update_fail_malformed_htlcs.len(), 1);
	let update_malformed = &updates_2_1.update_fail_malformed_htlcs[0];
	assert_eq!(update_malformed.sha256_of_onion, [0; 32]);
	assert_eq!(update_malformed.failure_code, INVALID_ONION_BLINDING);
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
		PaymentFailedConditions::new().expected_htlc_error_data(INVALID_ONION_BLINDING, &[0; 32]),
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
	let (offer, valid_static_invoice) =
		create_static_invoice(&nodes[1], &nodes[2], None, &secp_ctx);
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
	let unexpected_static_invoice = create_static_invoice(&nodes[1], &nodes[2], None, &secp_ctx).1;

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

	let relative_expiry = Duration::from_secs(1000);
	let (offer, static_invoice) =
		create_static_invoice(&nodes[1], &nodes[2], Some(relative_expiry), &secp_ctx);
	assert!(static_invoice.invoice_features().supports_basic_mpp());
	assert_eq!(static_invoice.relative_expiry(), relative_expiry);

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
