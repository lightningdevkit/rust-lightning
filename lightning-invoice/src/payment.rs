// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Convenient utilities for paying Lightning invoices.

use crate::Bolt11Invoice;
use bitcoin::hashes::Hash;

use lightning::ln::PaymentHash;
use lightning::ln::channelmanager::RecipientOnionFields;
use lightning::routing::router::{PaymentParameters, RouteParameters};

/// Builds the necessary parameters to pay or pre-flight probe the given zero-amount
/// [`Bolt11Invoice`] using [`ChannelManager::send_payment`] or
/// [`ChannelManager::send_preflight_probes`].
///
/// Prior to paying, you must ensure that the [`Bolt11Invoice::payment_hash`] is unique and the
/// same [`PaymentHash`] has never been paid before.
///
/// Will always succeed unless the invoice has an amount specified, in which case
/// [`payment_parameters_from_invoice`] should be used.
///
/// [`ChannelManager::send_payment`]: lightning::ln::channelmanager::ChannelManager::send_payment
/// [`ChannelManager::send_preflight_probes`]: lightning::ln::channelmanager::ChannelManager::send_preflight_probes
pub fn payment_parameters_from_zero_amount_invoice(invoice: &Bolt11Invoice, amount_msat: u64)
-> Result<(PaymentHash, RecipientOnionFields, RouteParameters), ()> {
	if invoice.amount_milli_satoshis().is_some() {
		Err(())
	} else {
		Ok(params_from_invoice(invoice, amount_msat))
	}
}

/// Builds the necessary parameters to pay or pre-flight probe the given [`Bolt11Invoice`] using
/// [`ChannelManager::send_payment`] or [`ChannelManager::send_preflight_probes`].
///
/// Prior to paying, you must ensure that the [`Bolt11Invoice::payment_hash`] is unique and the
/// same [`PaymentHash`] has never been paid before.
///
/// Will always succeed unless the invoice has no amount specified, in which case
/// [`payment_parameters_from_zero_amount_invoice`] should be used.
///
/// [`ChannelManager::send_payment`]: lightning::ln::channelmanager::ChannelManager::send_payment
/// [`ChannelManager::send_preflight_probes`]: lightning::ln::channelmanager::ChannelManager::send_preflight_probes
pub fn payment_parameters_from_invoice(invoice: &Bolt11Invoice)
-> Result<(PaymentHash, RecipientOnionFields, RouteParameters), ()> {
	if let Some(amount_msat) = invoice.amount_milli_satoshis() {
		Ok(params_from_invoice(invoice, amount_msat))
	} else {
		Err(())
	}
}

fn params_from_invoice(invoice: &Bolt11Invoice, amount_msat: u64)
-> (PaymentHash, RecipientOnionFields, RouteParameters) {
	let payment_hash = PaymentHash((*invoice.payment_hash()).to_byte_array());

	let mut recipient_onion = RecipientOnionFields::secret_only(*invoice.payment_secret());
	recipient_onion.payment_metadata = invoice.payment_metadata().map(|v| v.clone());

	let mut payment_params = PaymentParameters::from_node_id(
			invoice.recover_payee_pub_key(),
			invoice.min_final_cltv_expiry_delta() as u32
		)
		.with_route_hints(invoice.route_hints()).unwrap();
	if let Some(expiry) = invoice.expires_at() {
		payment_params = payment_params.with_expiry_time(expiry.as_secs());
	}
	if let Some(features) = invoice.features() {
		payment_params = payment_params.with_bolt11_features(features.clone()).unwrap();
	}

	let route_params = RouteParameters::from_payment_params_and_value(payment_params, amount_msat);
	(payment_hash, recipient_onion, route_params)
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::{InvoiceBuilder, Currency};
	use bitcoin::hashes::sha256::Hash as Sha256;
	use lightning::events::Event;
	use lightning::ln::channelmanager::{Retry, PaymentId};
	use lightning::ln::msgs::ChannelMessageHandler;
	use lightning::ln::PaymentSecret;
	use lightning::ln::functional_test_utils::*;
	use lightning::routing::router::Payee;
	use secp256k1::{SecretKey, PublicKey, Secp256k1};
	use std::time::{SystemTime, Duration};

	fn duration_since_epoch() -> Duration {
		#[cfg(feature = "std")]
		let duration_since_epoch =
			SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap();
		#[cfg(not(feature = "std"))]
		let duration_since_epoch = Duration::from_secs(1234567);
		duration_since_epoch
	}

	#[test]
	fn invoice_test() {
		let payment_hash = Sha256::hash(&[0; 32]);
		let private_key = SecretKey::from_slice(&[42; 32]).unwrap();
		let secp_ctx = Secp256k1::new();
		let public_key = PublicKey::from_secret_key(&secp_ctx, &private_key);

		let invoice = InvoiceBuilder::new(Currency::Bitcoin)
			.description("test".into())
			.payment_hash(payment_hash)
			.payment_secret(PaymentSecret([0; 32]))
			.duration_since_epoch(duration_since_epoch())
			.min_final_cltv_expiry_delta(144)
			.amount_milli_satoshis(128)
			.build_signed(|hash| {
				secp_ctx.sign_ecdsa_recoverable(hash, &private_key)
			})
			.unwrap();

		assert!(payment_parameters_from_zero_amount_invoice(&invoice, 42).is_err());

		let (hash, onion, params) = payment_parameters_from_invoice(&invoice).unwrap();
		assert_eq!(&hash.0[..], &payment_hash[..]);
		assert_eq!(onion.payment_secret, Some(PaymentSecret([0; 32])));
		assert_eq!(params.final_value_msat, 128);
		match params.payment_params.payee {
			Payee::Clear { node_id, .. } => {
				assert_eq!(node_id, public_key);
			},
			_ => panic!(),
		}
	}

	#[test]
	fn zero_value_invoice_test() {
		let payment_hash = Sha256::hash(&[0; 32]);
		let private_key = SecretKey::from_slice(&[42; 32]).unwrap();
		let secp_ctx = Secp256k1::new();
		let public_key = PublicKey::from_secret_key(&secp_ctx, &private_key);

		let invoice = InvoiceBuilder::new(Currency::Bitcoin)
			.description("test".into())
			.payment_hash(payment_hash)
			.payment_secret(PaymentSecret([0; 32]))
			.duration_since_epoch(duration_since_epoch())
			.min_final_cltv_expiry_delta(144)
			.build_signed(|hash| {
				secp_ctx.sign_ecdsa_recoverable(hash, &private_key)
			})
		.unwrap();

		assert!(payment_parameters_from_invoice(&invoice).is_err());

		let (hash, onion, params) = payment_parameters_from_zero_amount_invoice(&invoice, 42).unwrap();
		assert_eq!(&hash.0[..], &payment_hash[..]);
		assert_eq!(onion.payment_secret, Some(PaymentSecret([0; 32])));
		assert_eq!(params.final_value_msat, 42);
		match params.payment_params.payee {
			Payee::Clear { node_id, .. } => {
				assert_eq!(node_id, public_key);
			},
			_ => panic!(),
		}
	}

	#[test]
	#[cfg(feature = "std")]
	fn payment_metadata_end_to_end() {
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

		let invoice = InvoiceBuilder::new(Currency::Bitcoin)
			.description("test".into())
			.payment_hash(Sha256::from_slice(&payment_hash.0).unwrap())
			.payment_secret(payment_secret)
			.current_timestamp()
			.min_final_cltv_expiry_delta(144)
			.amount_milli_satoshis(50_000)
			.payment_metadata(payment_metadata.clone())
			.build_signed(|hash| {
				Secp256k1::new().sign_ecdsa_recoverable(hash,
					&nodes[1].keys_manager.backing.get_node_secret_key())
			})
			.unwrap();

		let (hash, onion, params) = payment_parameters_from_invoice(&invoice).unwrap();
		nodes[0].node.send_payment(hash, onion, PaymentId(hash.0), params, Retry::Attempts(0)).unwrap();
		check_added_monitors(&nodes[0], 1);
		let send_event = SendEvent::from_node(&nodes[0]);
		nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &send_event.msgs[0]);
		commitment_signed_dance!(nodes[1], nodes[0], &send_event.commitment_msg, false);

		expect_pending_htlcs_forwardable!(nodes[1]);

		let mut events = nodes[1].node.get_and_clear_pending_events();
		assert_eq!(events.len(), 1);
		match events.pop().unwrap() {
			Event::PaymentClaimable { onion_fields, .. } => {
				assert_eq!(Some(payment_metadata), onion_fields.unwrap().payment_metadata);
			},
			_ => panic!("Unexpected event")
		}
	}
}
