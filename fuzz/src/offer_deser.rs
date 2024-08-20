// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

use crate::utils::test_logger;
use bitcoin::secp256k1::Secp256k1;
use core::convert::TryFrom;
use lightning::ln::channelmanager::PaymentId;
use lightning::ln::inbound_payment::ExpandedKey;
use lightning::offers::invoice_request::InvoiceRequest;
use lightning::offers::nonce::Nonce;
use lightning::offers::offer::{Amount, Offer, Quantity};
use lightning::offers::parse::Bolt12SemanticError;
use lightning::sign::{EntropySource, KeyMaterial};
use lightning::util::ser::Writeable;

#[inline]
pub fn do_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	if let Ok(offer) = Offer::try_from(data.to_vec()) {
		let mut bytes = Vec::with_capacity(data.len());
		offer.write(&mut bytes).unwrap();
		assert_eq!(data, bytes);

		let mut buffer = Vec::new();

		if let Ok(invoice_request) = build_request(&offer) {
			invoice_request.write(&mut buffer).unwrap();
		}
	}
}

struct FixedEntropy;

impl EntropySource for FixedEntropy {
	fn get_secure_random_bytes(&self) -> [u8; 32] {
		[42; 32]
	}
}

fn build_request(offer: &Offer) -> Result<InvoiceRequest, Bolt12SemanticError> {
	let expanded_key = ExpandedKey::new(&KeyMaterial([42; 32]));
	let entropy = FixedEntropy {};
	let nonce = Nonce::from_entropy_source(&entropy);
	let secp_ctx = Secp256k1::new();
	let payment_id = PaymentId([1; 32]);

	let mut builder = offer.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)?;

	builder = match offer.amount() {
		None => builder.amount_msats(1000).unwrap(),
		Some(Amount::Bitcoin { amount_msats }) => builder.amount_msats(amount_msats + 1)?,
		Some(Amount::Currency { .. }) => return Err(Bolt12SemanticError::UnsupportedCurrency),
	};

	builder = match offer.supported_quantity() {
		Quantity::Bounded(n) => builder.quantity(n.get()).unwrap(),
		Quantity::Unbounded => builder.quantity(10).unwrap(),
		Quantity::One => builder,
	};

	builder.build_and_sign()
}

pub fn offer_deser_test<Out: test_logger::Output>(data: &[u8], out: Out) {
	do_test(data, out);
}

#[no_mangle]
pub extern "C" fn offer_deser_run(data: *const u8, datalen: usize) {
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) }, test_logger::DevNull {});
}
