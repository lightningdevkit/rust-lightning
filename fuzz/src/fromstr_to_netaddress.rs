// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

use lightning::ln::msgs::SocketAddress;
use core::str::FromStr;

use crate::utils::test_logger;

#[inline]
pub fn do_test(data: &[u8]) {
	if let Ok(s) = std::str::from_utf8(data) {
		let _ = SocketAddress::from_str(s);
	}

}

pub fn fromstr_to_netaddress_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	do_test(data);
}

#[no_mangle]
pub extern "C" fn fromstr_to_netaddress_run(data: *const u8, datalen: usize) {
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) });
}

