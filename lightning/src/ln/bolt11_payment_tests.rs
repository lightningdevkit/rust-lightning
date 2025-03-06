// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Tests for verifying the correct end-to-end handling of BOLT11 payments, including metadata propagation.

use crate::events::Event;
use crate::ln::channelmanager::{PaymentId, Retry};
use crate::ln::functional_test_utils::*;
use crate::ln::msgs::ChannelMessageHandler;
use crate::ln::outbound_payment::Bolt11PaymentError;
use crate::routing::router::RouteParametersConfig;
use crate::sign::{NodeSigner, Recipient};
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::Hash;
use lightning_invoice::{Bolt11Invoice, Currency, InvoiceBuilder};
use std::time::SystemTime;

#[test]
fn payment_metadata_end_to_end_for_invoice_with_amount() {
	// Test that a payment metadata read from an invoice passed to `pay_invoice` makes it all
	// the way out through the `PaymentClaimable` event.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	create_announced_chan_between_nodes(&nodes, 0, 1);

	let payment_metadata = vec![42, 43, 44, 45, 46, 47, 48, 49, 42];

	let (payment_hash, payment_secret) =
		nodes[1].node.create_inbound_payment(None, 7200, None).unwrap();

	let timestamp = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap();
	let invoice = InvoiceBuilder::new(Currency::Bitcoin)
		.description("test".into())
		.payment_hash(Sha256::from_slice(&payment_hash.0).unwrap())
		.payment_secret(payment_secret)
		.duration_since_epoch(timestamp)
		.min_final_cltv_expiry_delta(144)
		.amount_milli_satoshis(50_000)
		.payment_metadata(payment_metadata.clone())
		.build_raw()
		.unwrap();
	let sig = nodes[1].keys_manager.backing.sign_invoice(&invoice, Recipient::Node).unwrap();
	let invoice = invoice.sign::<_, ()>(|_| Ok(sig)).unwrap();
	let invoice = Bolt11Invoice::from_signed(invoice).unwrap();

	match nodes[0].node.pay_for_bolt11_invoice(
		&invoice,
		PaymentId(payment_hash.0),
		Some(100),
		RouteParametersConfig::default(),
		Retry::Attempts(0),
	) {
		Err(Bolt11PaymentError::InvalidAmount) => (),
		_ => panic!("Unexpected result"),
	};

	nodes[0]
		.node
		.pay_for_bolt11_invoice(
			&invoice,
			PaymentId(payment_hash.0),
			None,
			RouteParametersConfig::default(),
			Retry::Attempts(0),
		)
		.unwrap();

	check_added_monitors(&nodes[0], 1);
	let send_event = SendEvent::from_node(&nodes[0]);
	nodes[1].node.handle_update_add_htlc(nodes[0].node.get_our_node_id(), &send_event.msgs[0]);
	commitment_signed_dance!(nodes[1], nodes[0], &send_event.commitment_msg, false);

	expect_pending_htlcs_forwardable!(nodes[1]);

	let mut events = nodes[1].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	match events.pop().unwrap() {
		Event::PaymentClaimable { onion_fields, .. } => {
			assert_eq!(Some(payment_metadata), onion_fields.unwrap().payment_metadata);
		},
		_ => panic!("Unexpected event"),
	}
}

#[test]
fn payment_metadata_end_to_end_for_invoice_with_no_amount() {
	// Test that a payment metadata read from an invoice passed to `pay_invoice` makes it all
	// the way out through the `PaymentClaimable` event.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	create_announced_chan_between_nodes(&nodes, 0, 1);

	let payment_metadata = vec![42, 43, 44, 45, 46, 47, 48, 49, 42];

	let (payment_hash, payment_secret) =
		nodes[1].node.create_inbound_payment(None, 7200, None).unwrap();

	let timestamp = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap();
	let invoice = InvoiceBuilder::new(Currency::Bitcoin)
		.description("test".into())
		.payment_hash(Sha256::from_slice(&payment_hash.0).unwrap())
		.payment_secret(payment_secret)
		.duration_since_epoch(timestamp)
		.min_final_cltv_expiry_delta(144)
		.payment_metadata(payment_metadata.clone())
		.build_raw()
		.unwrap();
	let sig = nodes[1].keys_manager.backing.sign_invoice(&invoice, Recipient::Node).unwrap();
	let invoice = invoice.sign::<_, ()>(|_| Ok(sig)).unwrap();
	let invoice = Bolt11Invoice::from_signed(invoice).unwrap();

	match nodes[0].node.pay_for_bolt11_invoice(
		&invoice,
		PaymentId(payment_hash.0),
		None,
		RouteParametersConfig::default(),
		Retry::Attempts(0),
	) {
		Err(Bolt11PaymentError::InvalidAmount) => (),
		_ => panic!("Unexpected result"),
	};

	nodes[0]
		.node
		.pay_for_bolt11_invoice(
			&invoice,
			PaymentId(payment_hash.0),
			Some(50_000),
			RouteParametersConfig::default(),
			Retry::Attempts(0),
		)
		.unwrap();

	check_added_monitors(&nodes[0], 1);
	let send_event = SendEvent::from_node(&nodes[0]);
	nodes[1].node.handle_update_add_htlc(nodes[0].node.get_our_node_id(), &send_event.msgs[0]);
	commitment_signed_dance!(nodes[1], nodes[0], &send_event.commitment_msg, false);

	expect_pending_htlcs_forwardable!(nodes[1]);

	let mut events = nodes[1].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	match events.pop().unwrap() {
		Event::PaymentClaimable { onion_fields, .. } => {
			assert_eq!(Some(payment_metadata), onion_fields.unwrap().payment_metadata);
		},
		_ => panic!("Unexpected event"),
	}
}
