// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

macro_rules! hash_to_message {
	($slice: expr) => {{
		#[cfg(not(fuzzing))]
		{
			::bitcoin::secp256k1::Message::from_digest_slice($slice).unwrap()
		}
		#[cfg(fuzzing)]
		{
			match ::bitcoin::secp256k1::Message::from_digest_slice($slice) {
				Ok(msg) => msg,
				Err(_) => ::bitcoin::secp256k1::Message::from_digest([1; 32]),
			}
		}
	}};
}
