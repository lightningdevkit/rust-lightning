//! Utilities for implementing the bLIP-52 / LSPS2 standard.

use crate::lsps2::msgs::LSPS2OpeningFeeParams;
use crate::utils;

use bitcoin::hashes::hmac::{Hmac, HmacEngine};
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::{Hash, HashEngine};

/// Determines if the given parameters are valid given the secret used to generate the promise.
pub fn is_valid_opening_fee_params(
	fee_params: &LSPS2OpeningFeeParams, promise_secret: &[u8; 32],
) -> bool {
	if is_expired_opening_fee_params(fee_params) {
		return false;
	}
	let mut hmac = HmacEngine::<Sha256>::new(promise_secret);
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
		.and_then(|f| f.checked_add(999999))
		.and_then(|f| f.checked_div(1000000))
		.map(|f| core::cmp::max(f, opening_fee_min_fee_msat))
}

#[cfg(test)]
mod tests {
	use super::*;
	use proptest::prelude::*;

	const MAX_VALUE_MSAT: u64 = 21_000_000_0000_0000_000;

	fn arb_opening_fee_params() -> impl Strategy<Value = (u64, u64, u64)> {
		(0u64..MAX_VALUE_MSAT, 0u64..MAX_VALUE_MSAT, 0u64..MAX_VALUE_MSAT)
	}

	proptest! {
		#[test]
		fn test_compute_opening_fee((payment_size_msat, opening_fee_min_fee_msat, opening_fee_proportional) in arb_opening_fee_params()) {
			if let Some(res) = compute_opening_fee(payment_size_msat, opening_fee_min_fee_msat, opening_fee_proportional) {
				assert!(res >= opening_fee_min_fee_msat);
				assert_eq!(res as f32, (payment_size_msat as f32 * opening_fee_proportional as f32));
			} else {
				// Check we actually overflowed.
				let max_value = u64::MAX as u128;
				assert!((payment_size_msat as u128 * opening_fee_proportional as u128) > max_value);
			}
		}
	}
}
