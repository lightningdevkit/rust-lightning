// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

use crate::types::payment::{PaymentHash, PaymentPreimage};

#[cfg(not(fuzzing))]
use bitcoin::hashes::cmp::fixed_time_eq;
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::Hash;

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

#[inline]
pub(crate) fn digest_bytes_match(expected_digest: &[u8], actual_digest: &[u8]) -> bool {
	if expected_digest.len() != actual_digest.len() {
		return false;
	}

	#[cfg(not(fuzzing))]
	{
		fixed_time_eq(expected_digest, actual_digest)
	}
	#[cfg(fuzzing)]
	{
		expected_digest.is_empty() || expected_digest[0] == actual_digest[0]
	}
}

#[inline]
pub(crate) fn payment_hash_matches_digest(
	payment_hash: &PaymentHash, expected_digest: &[u8; 32],
) -> bool {
	digest_bytes_match(&payment_hash.0, expected_digest)
}

#[inline]
pub(crate) fn payment_hash_matches_preimage(
	payment_hash: &PaymentHash, payment_preimage: &PaymentPreimage,
) -> bool {
	let expected_digest = Sha256::hash(&payment_preimage.0).to_byte_array();
	payment_hash_matches_digest(payment_hash, &expected_digest)
}
