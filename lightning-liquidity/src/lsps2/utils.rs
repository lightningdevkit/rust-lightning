// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these licenses.

//! Utilities for implementing the bLIP-52 / LSPS2 standard.

use crate::lsps2::msgs::LSPS2OpeningFeeParams;
use crate::utils;

use bitcoin::hashes::hmac::{Hmac, HmacEngine};
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::{Hash, HashEngine};
use bitcoin::secp256k1::PublicKey;

/// Determines if the given parameters are valid given the secret used to generate the promise.
pub fn is_valid_opening_fee_params(
	fee_params: &LSPS2OpeningFeeParams, promise_secret: &[u8; 32], counterparty_node_id: &PublicKey,
) -> bool {
	if is_expired_opening_fee_params(fee_params) {
		return false;
	}
	let mut hmac = HmacEngine::<Sha256>::new(promise_secret);
	hmac.input(&counterparty_node_id.serialize());
	hmac.input(&fee_params.min_fee_msat.to_be_bytes());
	hmac.input(&fee_params.proportional.to_be_bytes());
	hmac.input(fee_params.valid_until.to_rfc3339().as_bytes());
	hmac.input(&fee_params.min_lifetime.to_be_bytes());
	hmac.input(&fee_params.max_client_to_self_delay.to_be_bytes());
	hmac.input(&fee_params.min_payment_size_msat.to_be_bytes());
	hmac.input(&fee_params.max_payment_size_msat.to_be_bytes());
	let promise_bytes = Hmac::from_engine(hmac).to_byte_array();
	let promise = utils::hex_str(&promise_bytes[..]);
	promise == fee_params.promise
}

/// Determines if the given parameters are expired, or still valid.
#[cfg_attr(not(feature = "time"), allow(unused_variables))]
pub fn is_expired_opening_fee_params(fee_params: &LSPS2OpeningFeeParams) -> bool {
	#[cfg(feature = "time")]
	{
		fee_params.valid_until.is_past()
	}
	#[cfg(not(feature = "time"))]
	{
		// TODO: We need to find a way to check expiry times in no-std builds.
		false
	}
}

/// Computes the opening fee given a payment size and the fee parameters.
///
/// Returns [`Option::None`] when the computation overflows.
///
/// See the [`specification`](https://github.com/lightning/blips/blob/master/blip-0052.md#computing-the-opening_fee) for more details.
pub fn compute_opening_fee(
	payment_size_msat: u64, opening_fee_min_fee_msat: u64, opening_fee_proportional: u64,
) -> Option<u64> {
	payment_size_msat
		.checked_mul(opening_fee_proportional)
		.map(|f| f.div_ceil(1_000_000))
		.map(|f| core::cmp::max(f, opening_fee_min_fee_msat))
}
