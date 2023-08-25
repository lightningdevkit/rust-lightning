// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

use lightning::util::base32;

use crate::utils::test_logger;

#[inline]
pub fn do_test(data: &[u8]) {
	if let Ok(s) = std::str::from_utf8(data) {
		let first_decoding = base32::Alphabet::RFC4648 { padding: true }.decode(s);
		if let Ok(first_decoding) = first_decoding {
			let encoding_response = base32::Alphabet::RFC4648 { padding: true }.encode(&first_decoding);
			assert_eq!(encoding_response, s.to_ascii_uppercase());
			let second_decoding = base32::Alphabet::RFC4648 { padding: true }.decode(&encoding_response).unwrap();
			assert_eq!(first_decoding, second_decoding);
		}
	}

	if let Ok(s) = std::str::from_utf8(data) {
		let first_decoding = base32::Alphabet::RFC4648 { padding: false }.decode(s);
		if let Ok(first_decoding) = first_decoding {
			let encoding_response = base32::Alphabet::RFC4648 { padding: false }.encode(&first_decoding);
			assert_eq!(encoding_response, s.to_ascii_uppercase());
			let second_decoding = base32::Alphabet::RFC4648 { padding: false }.decode(&encoding_response).unwrap();
			assert_eq!(first_decoding, second_decoding);
		}
	}
	
	let encode_response = base32::Alphabet::RFC4648 { padding: false }.encode(&data);
	let decode_response = base32::Alphabet::RFC4648 { padding: false }.decode(&encode_response).unwrap();
	assert_eq!(data, decode_response);

	let encode_response = base32::Alphabet::RFC4648 { padding: true }.encode(&data);
	let decode_response = base32::Alphabet::RFC4648 { padding: true }.decode(&encode_response).unwrap();
	assert_eq!(data, decode_response);
}

pub fn base32_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	do_test(data);
}

#[no_mangle]
pub extern "C" fn base32_run(data: *const u8, datalen: usize) {
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) });
}
