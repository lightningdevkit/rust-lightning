// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

use crate::utils::test_logger;
use core::convert::TryFrom;
use lightning::offers::static_invoice::StaticInvoice;
use lightning::util::ser::Writeable;

#[inline]
pub fn do_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	if let Ok(static_invoice) = StaticInvoice::try_from(data.to_vec()) {
		let mut bytes = Vec::with_capacity(data.len());
		static_invoice.write(&mut bytes).unwrap();
		assert_eq!(data, bytes);
	}
}

pub fn static_invoice_deser_test<Out: test_logger::Output>(data: &[u8], out: Out) {
	do_test(data, out);
}

#[no_mangle]
pub extern "C" fn static_invoice_deser_run(data: *const u8, datalen: usize) {
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) }, test_logger::DevNull {});
}
