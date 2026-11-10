//! Utilities for implementing the LSPS2 standard.

use crate::lsps2::msgs::OpeningFeeParams;
use crate::utils;

use bitcoin::hashes::hmac::{Hmac, HmacEngine};
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::{Hash, HashEngine};

#[cfg(feature = "std")]
use std::time::{SystemTime, UNIX_EPOCH};

/// Determines if the given parameters are valid given the secret used to generate the promise.
pub fn is_valid_opening_fee_params(
	fee_params: &OpeningFeeParams, promise_secret: &[u8; 32],
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
#[cfg_attr(not(feature = "std"), allow(unused_variables))]
pub fn is_expired_opening_fee_params(fee_params: &OpeningFeeParams) -> bool {
	#[cfg(feature = "std")]
	{
		let seconds_since_epoch = SystemTime::now()
			.duration_since(UNIX_EPOCH)
			.expect("system clock to be ahead of the unix epoch")
			.as_secs();
		let valid_until_seconds_since_epoch = fee_params
			.valid_until
			.timestamp()
			.try_into()
			.expect("expiration to be ahead of unix epoch");
		seconds_since_epoch > valid_until_seconds_since_epoch
	}
	#[cfg(not(feature = "std"))]
	{
		// TODO: We need to find a way to check expiry times in no-std builds.
		false
	}
}

/// Computes the opening fee given a payment size and the fee parameters.
///
/// Returns [`Option::None`] when the computation overflows.
///
/// See the [`specification`](https://github.com/BitcoinAndLightningLayerSpecs/lsp/tree/main/LSPS2#computing-the-opening_fee) for more details.
pub fn compute_opening_fee(
	payment_size_msat: u64, opening_fee_min_fee_msat: u64, opening_fee_proportional: u64,
) -> Option<u64> {
	payment_size_msat
		.checked_mul(opening_fee_proportional)
		.and_then(|f| f.checked_add(999999))
		.and_then(|f| f.checked_div(1000000))
		.map(|f| core::cmp::max(f, opening_fee_min_fee_msat))
}
