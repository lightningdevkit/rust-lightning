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
use lightning::offers::parse::{Bech32Encode, ParseError};

#[inline]
pub fn do_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	if let Ok(bech32_encoded) = std::str::from_utf8(data) {
		if let Ok(bytes) = Bytes::from_bech32_str(bech32_encoded) {
			let bech32_encoded = bytes.to_string();
			assert_eq!(bytes, Bytes::from_bech32_str(&bech32_encoded).unwrap());
		}
	}
}

#[derive(Debug, PartialEq)]
struct Bytes(Vec<u8>);

impl Bech32Encode for Bytes {
	const BECH32_HRP: &'static str = "lno";
}

impl AsRef<[u8]> for Bytes {
	fn as_ref(&self) -> &[u8] {
		&self.0
	}
}

impl TryFrom<Vec<u8>> for Bytes {
	type Error = ParseError;
	fn try_from(data: Vec<u8>) -> Result<Self, ParseError> {
		Ok(Bytes(data))
	}
}

impl core::fmt::Display for Bytes {
	fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
		self.fmt_bech32_str(f)
	}
}

pub fn bech32_parse_test<Out: test_logger::Output>(data: &[u8], out: Out) {
	do_test(data, out);
}

#[no_mangle]
pub extern "C" fn bech32_parse_run(data: *const u8, datalen: usize) {
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) }, test_logger::DevNull {});
}
