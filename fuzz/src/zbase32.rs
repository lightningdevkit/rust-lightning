// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

use lightning::util::zbase32;

use crate::utils::test_logger;

#[inline]
pub fn do_test(data: &[u8]) {
	let res = zbase32::encode(data);
	assert_eq!(&zbase32::decode(&res).unwrap()[..], data);

	if let Ok(s) = std::str::from_utf8(data) {
		if let Ok(decoded) = zbase32::decode(s) {
			assert_eq!(&zbase32::encode(&decoded), &s.to_ascii_lowercase());
		}
	}
}

pub fn zbase32_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	do_test(data);
}

#[no_mangle]
pub extern "C" fn zbase32_run(data: *const u8, datalen: usize) {
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) });
}
