// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

use crate::utils::test_logger;
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use lightning::util::bech32::{u5, FromBase32, ToBase32};
use lightning_invoice::{
	Bolt11Invoice, RawBolt11Invoice, RawDataPart, RawHrp, RawTaggedField, TaggedField,
};
use std::str::FromStr;

#[inline]
pub fn do_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	// Read a fake HRP length byte
	let hrp_len = std::cmp::min(*data.get(0).unwrap_or(&0) as usize, data.len());
	if let Ok(s) = std::str::from_utf8(&data[..hrp_len]) {
		let hrp = match RawHrp::from_str(s) {
			Ok(hrp) => hrp,
			Err(_) => return,
		};
		let bech32 =
			data.iter().skip(hrp_len).map(|x| u5::try_from_u8(x % 32).unwrap()).collect::<Vec<_>>();
		let invoice_data = match RawDataPart::from_base32(&bech32) {
			Ok(invoice) => invoice,
			Err(_) => return,
		};

		// Our data encoding is not worse than the input
		assert!(invoice_data.to_base32().len() <= bech32.len());

		// Our data serialization is loss-less
		assert_eq!(
			RawDataPart::from_base32(&invoice_data.to_base32())
				.expect("faild parsing out own encoding"),
			invoice_data
		);

		if invoice_data.tagged_fields.iter().any(|field| {
			matches!(field, RawTaggedField::KnownSemantics(TaggedField::PayeePubKey(_)))
		}) {
			// We could forge a signature using the fact that signing is insecure in fuzz mode, but
			// easier to just skip and rely on the fact that no-PayeePubKey invoices do pubkey
			// recovery
			return;
		}

		let raw_invoice = RawBolt11Invoice { hrp, data: invoice_data };
		let signed_raw_invoice = match raw_invoice.sign(|hash| {
			let private_key = SecretKey::from_slice(&[42; 32]).unwrap();
			Ok::<_, ()>(Secp256k1::new().sign_ecdsa_recoverable(hash, &private_key))
		}) {
			Ok(inv) => inv,
			Err(_) => return,
		};

		if let Ok(invoice) = Bolt11Invoice::from_signed(signed_raw_invoice) {
			invoice.amount_milli_satoshis();
		}
	}
}

pub fn bolt11_deser_test<Out: test_logger::Output>(data: &[u8], out: Out) {
	do_test(data, out);
}

#[no_mangle]
pub extern "C" fn bolt11_deser_run(data: *const u8, datalen: usize) {
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) }, test_logger::DevNull {});
}
