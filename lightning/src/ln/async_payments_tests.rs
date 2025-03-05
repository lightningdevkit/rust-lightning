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
use crate::events::{Event, HTLCDestination, PaymentFailureReason};
use crate::ln::blinded_payment_tests::{fail_blinded_htlc_backwards, get_blinded_route_parameters};
use crate::ln::channelmanager::{PaymentId, RecipientOnionFields};
use crate::ln::functional_test_utils::*;
use crate::ln::msgs;
use crate::ln::msgs::{
	BaseMessageHandler, ChannelMessageHandler, MessageSendEvent, OnionMessageHandler,
};
use crate::ln::offers_tests;
use crate::ln::onion_utils::INVALID_ONION_BLINDING;
use crate::ln::outbound_payment::PendingOutboundPayment;
use crate::ln::outbound_payment::Retry;
use crate::offers::invoice_request::InvoiceRequest;
use crate::offers::nonce::Nonce;
use crate::offers::offer::Offer;
use crate::offers::static_invoice::StaticInvoice;
use crate::onion_message::async_payments::{AsyncPaymentsMessage, AsyncPaymentsMessageHandler};
use crate::onion_message::messenger::{Destination, MessageRouter, MessageSendInstructions};
use crate::onion_message::offers::OffersMessage;
use crate::onion_message::packet::ParsedOnionMessageContents;
use crate::prelude::*;
use crate::routing::router::{Payee, PaymentParameters, RouteParametersConfig};
use crate::sign::NodeSigner;
use crate::sync::Mutex;
use crate::types::features::Bolt12InvoiceFeatures;
use crate::types::payment::{PaymentHash, PaymentPreimage, PaymentSecret};
use bitcoin::constants::ChainHash;
use bitcoin::network::Network;
use bitcoin::secp256k1;
use bitcoin::secp256k1::Secp256k1;

use core::convert::Infallible;
use core::time::Duration;

// Goes through the async receive onion message flow, returning the final release_held_htlc OM.
//
// Assumes the held_htlc_available message will be sent:
// 	 sender -> always_online_recipient_counterparty -> recipient.
//
// Returns: (held_htlc_available_om, release_held_htlc_om)
fn pass_async_payments_oms(
	static_invoice: StaticInvoice, sender: &Node, always_online_recipient_counterparty: &Node,
	recipient: &Node,
) -> (msgs::OnionMessage, msgs::OnionMessage) {
	let sender_node_id = sender.node.get_our_node_id();
	let always_online_node_id = always_online_recipient_counterparty.node.get_our_node_id();

	// Don't forward the invreq since we don't support retrieving the static invoice from the
	// recipient's LSP yet, instead manually construct the response.
	let invreq_om =
		sender.onion_messenger.next_onion_message_for_peer(always_online_node_id).unwrap();
	let invreq_reply_path =
		offers_tests::extract_invoice_request(always_online_recipient_counterparty, &invreq_om).1;

	always_online_recipient_counterparty
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

	(
		held_htlc_available_om_1_2,
		recipient.onion_messenger.next_onion_message_for_peer(sender_node_id).unwrap(),
	)
}

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
	let params = RouteParametersConfig::default();
	nodes[0]
		.node
		.pay_for_offer(&offer, None, Some(amt_msat), None, payment_id, Retry::Attempts(0), params)
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
	let params = RouteParametersConfig::default();
	nodes[0]
		.node
		.pay_for_offer(&offer, None, Some(amt_msat), None, payment_id, Retry::Attempts(0), params)
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
fn async_receive_flow_success() {
	// Test that an always-online sender can successfully pay an async receiver.
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

	// Set the random bytes so we can predict the payment preimage and hash.
	let hardcoded_random_bytes = [42; 32];
	let keysend_preimage = PaymentPreimage(hardcoded_random_bytes);
	let payment_hash: PaymentHash = keysend_preimage.into();
	*nodes[0].keys_manager.override_random_bytes.lock().unwrap() = Some(hardcoded_random_bytes);

	let relative_expiry = Duration::from_secs(1000);
	let (offer, static_invoice) =
		create_static_invoice(&nodes[1], &nodes[2], Some(relative_expiry), &secp_ctx);
	assert!(static_invoice.invoice_features().supports_basic_mpp());
	assert_eq!(static_invoice.relative_expiry(), relative_expiry);

	let amt_msat = 5000;
	let payment_id = PaymentId([1; 32]);
	let params = RouteParametersConfig::default();
	nodes[0]
		.node
		.pay_for_offer(&offer, None, Some(amt_msat), None, payment_id, Retry::Attempts(0), params)
		.unwrap();
	let release_held_htlc_om =
		pass_async_payments_oms(static_invoice, &nodes[0], &nodes[1], &nodes[2]).1;
	nodes[0]
		.onion_messenger
		.handle_onion_message(nodes[2].node.get_our_node_id(), &release_held_htlc_om);

	// Check that we've queued the HTLCs of the async keysend payment.
	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let ev = remove_first_msg_event_to_node(&nodes[1].node.get_our_node_id(), &mut events);
	check_added_monitors!(nodes[0], 1);

	// Receiving a duplicate release_htlc message doesn't result in duplicate payment.
	nodes[0]
		.onion_messenger
		.handle_onion_message(nodes[2].node.get_our_node_id(), &release_held_htlc_om);
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());

	let route: &[&[&Node]] = &[&[&nodes[1], &nodes[2]]];
	let args = PassAlongPathArgs::new(&nodes[0], route[0], amt_msat, payment_hash, ev)
		.with_payment_preimage(keysend_preimage);
	do_pass_along_path(args);
	claim_payment_along_route(ClaimAlongRouteArgs::new(&nodes[0], route, keysend_preimage));
}

#[cfg_attr(feature = "std", ignore)]
#[test]
fn expired_static_invoice_fail() {
	// Test that if we receive an expired static invoice we'll fail the payment.
	let secp_ctx = Secp256k1::new();
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 0);
	create_unannounced_chan_between_nodes_with_value(&nodes, 1, 2, 1_000_000, 0);

	const INVOICE_EXPIRY_SECS: u32 = 10;
	let relative_expiry = Duration::from_secs(INVOICE_EXPIRY_SECS as u64);
	let (offer, static_invoice) =
		create_static_invoice(&nodes[1], &nodes[2], Some(relative_expiry), &secp_ctx);

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
	let invreq_reply_path = offers_tests::extract_invoice_request(&nodes[1], &invreq_om).1;
	// TODO: update to not manually send here when we add support for being the recipient's
	// always-online counterparty
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

	// Wait until the static invoice expires before providing it to the sender.
	let block = create_dummy_block(
		nodes[0].best_block_hash(),
		nodes[0].node.duration_since_epoch().as_secs() as u32 + INVOICE_EXPIRY_SECS + 1,
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
	// The sender doesn't reply with InvoiceError right now because the always-online node doesn't
	// currently provide them with a reply path to do so.
}

#[test]
fn async_receive_mpp() {
	let secp_ctx = Secp256k1::new();
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
	let (offer, static_invoice) = create_static_invoice(&nodes[1], &nodes[3], None, &secp_ctx);

	// In other tests we hardcode the sender's random bytes so we can predict the keysend preimage to
	// check later in the test, but that doesn't work for MPP because it causes the session_privs for
	// the different MPP parts to not be unique.
	let amt_msat = 15_000_000;
	let payment_id = PaymentId([1; 32]);
	let params = RouteParametersConfig::default();
	nodes[0]
		.node
		.pay_for_offer(&offer, None, Some(amt_msat), None, payment_id, Retry::Attempts(1), params)
		.unwrap();
	let release_held_htlc_om_3_0 =
		pass_async_payments_oms(static_invoice, &nodes[0], &nodes[1], &nodes[3]).1;
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
		crate::events::Event::PaymentClaimable {
			purpose: crate::events::PaymentPurpose::Bolt12OfferPayment { payment_preimage, .. },
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

	let (offer, static_invoice) = create_static_invoice(&nodes[1], &nodes[3], None, &secp_ctx);

	// Set the random bytes so we can predict the payment preimage and hash.
	let hardcoded_random_bytes = [42; 32];
	let keysend_preimage = PaymentPreimage(hardcoded_random_bytes);
	let payment_hash: PaymentHash = keysend_preimage.into();
	*nodes[0].keys_manager.override_random_bytes.lock().unwrap() = Some(hardcoded_random_bytes);

	let amt_msat = 5000;
	let payment_id = PaymentId([1; 32]);
	let params = RouteParametersConfig::default();
	nodes[0]
		.node
		.pay_for_offer(&offer, None, Some(amt_msat), None, payment_id, Retry::Attempts(1), params)
		.unwrap();
	let release_held_htlc_om_3_0 =
		pass_async_payments_oms(static_invoice, &nodes[0], &nodes[1], &nodes[3]).1;

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

	let route: &[&[&Node]] = &[&[&nodes[1], &nodes[3]]];
	let args = PassAlongPathArgs::new(&nodes[0], route[0], amt_msat, payment_hash, ev)
		.with_payment_preimage(keysend_preimage)
		.without_claimable_event()
		.expect_failure(HTLCDestination::FailedPayment { payment_hash });
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
	let args = PassAlongPathArgs::new(&nodes[0], route[0], amt_msat, payment_hash, ev)
		.with_payment_preimage(keysend_preimage);
	do_pass_along_path(args);
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

	// Hardcode the payment paths so nodes[0] has something to retry over. Set all of these paths to
	// use the same nodes to avoid complicating the test with a bunch of extra nodes.
	let mut static_invoice_paths = Vec::new();
	for _ in 0..3 {
		let static_inv_for_path = nodes[2]
			.node
			.create_static_invoice_builder(&offer, offer_nonce, None)
			.unwrap()
			.build_and_sign(&secp_ctx)
			.unwrap();
		static_invoice_paths.push(static_inv_for_path.payment_paths()[0].clone());
	}
	nodes[2].router.expect_blinded_payment_paths(static_invoice_paths);

	let static_invoice = nodes[2]
		.node
		.create_static_invoice_builder(&offer, offer_nonce, None)
		.unwrap()
		.build_and_sign(&secp_ctx)
		.unwrap();

	// Set the random bytes so we can predict the payment preimage and hash.
	let hardcoded_random_bytes = [42; 32];
	let keysend_preimage = PaymentPreimage(hardcoded_random_bytes);
	let payment_hash: PaymentHash = keysend_preimage.into();
	*nodes[0].keys_manager.override_random_bytes.lock().unwrap() = Some(hardcoded_random_bytes);

	let params = RouteParametersConfig::default();
	nodes[0]
		.node
		.pay_for_offer(&offer, None, Some(amt_msat), None, payment_id, Retry::Attempts(2), params)
		.unwrap();
	let release_held_htlc_om_2_0 =
		pass_async_payments_oms(static_invoice, &nodes[0], &nodes[1], &nodes[2]).1;
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

	let route: &[&[&Node]] = &[&[&nodes[1], &nodes[2]]];
	let args = PassAlongPathArgs::new(&nodes[0], route[0], amt_msat, payment_hash, ev)
		.with_payment_preimage(keysend_preimage);
	do_pass_along_path(args);

	// Fail the HTLC backwards to enable us to more easily modify the now-Retryable outbound to test
	// failures on the recipient's end.
	nodes[2].node.fail_htlc_backwards(&payment_hash);
	expect_pending_htlcs_forwardable_conditions(
		nodes[2].node.get_and_clear_pending_events(),
		&[HTLCDestination::FailedPayment { payment_hash }],
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
		.with_payment_preimage(keysend_preimage)
		.without_claimable_event()
		.expect_failure(HTLCDestination::FailedPayment { payment_hash });
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
	let args = PassAlongPathArgs::new(&nodes[0], route[0], amt_msat, payment_hash, ev)
		.with_payment_preimage(keysend_preimage);
	do_pass_along_path(args);
	claim_payment_along_route(ClaimAlongRouteArgs::new(&nodes[0], route, keysend_preimage));
}

#[cfg(not(feature = "std"))]
#[test]
fn expired_static_invoice_message_path() {
	// Test that if we receive a held_htlc_available message over an expired blinded path, we'll
	// ignore it.
	let secp_ctx = Secp256k1::new();
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 0);
	create_unannounced_chan_between_nodes_with_value(&nodes, 1, 2, 1_000_000, 0);

	const INVOICE_EXPIRY_SECS: u32 = 10;
	let (offer, static_invoice) = create_static_invoice(
		&nodes[1],
		&nodes[2],
		Some(Duration::from_secs(INVOICE_EXPIRY_SECS as u64)),
		&secp_ctx,
	);

	let amt_msat = 5000;
	let payment_id = PaymentId([1; 32]);
	let params = RouteParametersConfig::default();
	nodes[0]
		.node
		.pay_for_offer(&offer, None, Some(amt_msat), None, payment_id, Retry::Attempts(1), params)
		.unwrap();

	// While the invoice is unexpired, respond with release_held_htlc.
	let (held_htlc_available_om, _release_held_htlc_om) =
		pass_async_payments_oms(static_invoice, &nodes[0], &nodes[1], &nodes[2]);

	// After the invoice is expired, ignore inbound held_htlc_available messages over the path.
	let path_absolute_expiry = crate::ln::inbound_payment::calculate_absolute_expiry(
		nodes[2].node.duration_since_epoch().as_secs(),
		INVOICE_EXPIRY_SECS,
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

	// Make sure all nodes are at the same block height in preparation for CLTV timeout things.
	let node_max_height =
		nodes.iter().map(|node| node.blocks.lock().unwrap().len()).max().unwrap() as u32;
	connect_blocks(&nodes[0], node_max_height - nodes[0].best_block_info().1);
	connect_blocks(&nodes[1], node_max_height - nodes[1].best_block_info().1);
	connect_blocks(&nodes[2], node_max_height - nodes[2].best_block_info().1);

	// Set the random bytes so we can predict the payment preimage and hash.
	let hardcoded_random_bytes = [42; 32];
	let keysend_preimage = PaymentPreimage(hardcoded_random_bytes);
	let payment_hash: PaymentHash = keysend_preimage.into();
	*nodes[0].keys_manager.override_random_bytes.lock().unwrap() = Some(hardcoded_random_bytes);

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

	let (offer, static_invoice) = create_static_invoice(&nodes[1], &nodes[2], None, &secp_ctx);
	let amt_msat = 5000;
	let payment_id = PaymentId([1; 32]);
	let params = RouteParametersConfig::default();
	nodes[0]
		.node
		.pay_for_offer(&offer, None, Some(amt_msat), None, payment_id, Retry::Attempts(0), params)
		.unwrap();
	let release_held_htlc_om =
		pass_async_payments_oms(static_invoice, &nodes[0], &nodes[1], &nodes[2]).1;
	nodes[0]
		.onion_messenger
		.handle_onion_message(nodes[2].node.get_our_node_id(), &release_held_htlc_om);

	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let ev = remove_first_msg_event_to_node(&nodes[1].node.get_our_node_id(), &mut events);
	check_added_monitors!(nodes[0], 1);

	let route: &[&[&Node]] = &[&[&nodes[1], &nodes[2]]];
	let args = PassAlongPathArgs::new(&nodes[0], route[0], amt_msat, payment_hash, ev)
		.with_payment_preimage(keysend_preimage)
		.without_claimable_event()
		.expect_failure(HTLCDestination::FailedPayment { payment_hash });
	do_pass_along_path(args);
	fail_blinded_htlc_backwards(payment_hash, 1, &[&nodes[0], &nodes[1], &nodes[2]], false);
	nodes[2].logger.assert_log_contains(
		"lightning::ln::channelmanager",
		"violated blinded payment constraints",
		1,
	);
}
