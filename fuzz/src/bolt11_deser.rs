// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

use bitcoin::bech32::{u5, FromBase32, ToBase32};
use crate::utils::test_logger;
use lightning_invoice::RawDataPart;

#[inline]
pub fn do_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	let bech32 = data.iter().map(|x| u5::try_from_u8(x % 32).unwrap()).collect::<Vec<_>>();
	let invoice = match RawDataPart::from_base32(&bech32) {
		Ok(invoice) => invoice,
		Err(_) => return,
	};

	// Our encoding is not worse than the input
	assert!(invoice.to_base32().len() <= bech32.len());

	// Our serialization is loss-less
	assert_eq!(
		RawDataPart::from_base32(&invoice.to_base32()).expect("faild parsing out own encoding"),
		invoice
	);
}

pub fn bolt11_deser_test<Out: test_logger::Output>(data: &[u8], out: Out) {
	do_test(data, out);
}

#[no_mangle]
pub extern "C" fn bolt11_deser_run(data: *const u8, datalen: usize) {
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) }, test_logger::DevNull {});
}
