// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

use bitcoin::secp256k1::{KeyPair, PublicKey, Secp256k1, SecretKey};
use crate::utils::test_logger;
use core::convert::{Infallible, TryFrom};
use lightning::offers::invoice_request::UnsignedInvoiceRequest;
use lightning::offers::offer::{Amount, Offer, Quantity};
use lightning::offers::parse::SemanticError;
use lightning::util::ser::Writeable;

#[inline]
pub fn do_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	if let Ok(offer) = Offer::try_from(data.to_vec()) {
		let mut bytes = Vec::with_capacity(data.len());
		offer.write(&mut bytes).unwrap();
		assert_eq!(data, bytes);

		let secp_ctx = Secp256k1::new();
		let keys = KeyPair::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[42; 32]).unwrap());
		let pubkey = PublicKey::from(keys);
		let mut buffer = Vec::new();

		if let Ok(invoice_request) = build_response(&offer, pubkey) {
			invoice_request
				.sign::<_, Infallible>(
					|digest| Ok(secp_ctx.sign_schnorr_no_aux_rand(digest, &keys))
				)
				.unwrap()
				.write(&mut buffer)
				.unwrap();
		}
	}
}

fn build_response<'a>(
	offer: &'a Offer, pubkey: PublicKey
) -> Result<UnsignedInvoiceRequest<'a>, SemanticError> {
	let mut builder = offer.request_invoice(vec![42; 64], pubkey)?;

	builder = match offer.amount() {
		None => builder.amount_msats(1000).unwrap(),
		Some(Amount::Bitcoin { amount_msats }) => builder.amount_msats(amount_msats + 1)?,
		Some(Amount::Currency { .. }) => return Err(SemanticError::UnsupportedCurrency),
	};

	builder = match offer.supported_quantity() {
		Quantity::Bounded(n) => builder.quantity(n.get()).unwrap(),
		Quantity::Unbounded => builder.quantity(10).unwrap(),
		Quantity::One => builder,
	};

	builder.build()
}

pub fn offer_deser_test<Out: test_logger::Output>(data: &[u8], out: Out) {
	do_test(data, out);
}

#[no_mangle]
pub extern "C" fn offer_deser_run(data: *const u8, datalen: usize) {
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) }, test_logger::DevNull {});
}
