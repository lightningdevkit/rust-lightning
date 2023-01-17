// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Traits and utility impls which allow other parts of rust-lightning to interact with the
//! blockchain.
//!
//! Includes traits for monitoring and receiving notifications of new blocks and block
//! disconnections, transaction broadcasting, and feerate information requests.

use core::{cmp, ops::Deref};

use bitcoin::blockdata::transaction::Transaction;

/// An interface to send a transaction to the Bitcoin network.
pub trait BroadcasterInterface {
	/// Sends a transaction out to (hopefully) be mined.
	fn broadcast_transaction(&self, tx: &Transaction);
}

/// An enum that represents the speed at which we want a transaction to confirm used for feerate
/// estimation.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub enum ConfirmationTarget {
	/// We are happy with this transaction confirming slowly when feerate drops some.
	Background,
	/// We'd like this transaction to confirm without major delay, but 12-18 blocks is fine.
	Normal,
	/// We'd like this transaction to confirm in the next few blocks.
	HighPriority,
}

/// A trait which should be implemented to provide feerate information on a number of time
/// horizons.
///
/// Note that all of the functions implemented here *must* be reentrant-safe (obviously - they're
/// called from inside the library in response to chain events, P2P events, or timer events).
pub trait FeeEstimator {
	/// Gets estimated satoshis of fee required per 1000 Weight-Units.
	///
	/// LDK will wrap this method and ensure that the value returned is no smaller than 253
	/// (ie 1 satoshi-per-byte rounded up to ensure later round-downs don't put us below 1 satoshi-per-byte).
	///
	/// The following unit conversions can be used to convert to sats/KW:
	///  * satoshis-per-byte * 250
	///  * satoshis-per-kbyte / 4
	fn get_est_sat_per_1000_weight(&self, confirmation_target: ConfirmationTarget) -> u32;
}

/// Minimum relay fee as required by bitcoin network mempool policy.
pub const MIN_RELAY_FEE_SAT_PER_1000_WEIGHT: u64 = 4000;
/// Minimum feerate that takes a sane approach to bitcoind weight-to-vbytes rounding.
/// See the following Core Lightning commit for an explanation:
/// <https://github.com/ElementsProject/lightning/commit/2e687b9b352c9092b5e8bd4a688916ac50b44af0>
pub const FEERATE_FLOOR_SATS_PER_KW: u32 = 253;

/// Wraps a `Deref` to a `FeeEstimator` so that any fee estimations provided by it
/// are bounded below by `FEERATE_FLOOR_SATS_PER_KW` (253 sats/KW).
///
/// Note that this does *not* implement [`FeeEstimator`] to make it harder to accidentally mix the
/// two.
pub(crate) struct LowerBoundedFeeEstimator<F: Deref>(pub F) where F::Target: FeeEstimator;

impl<F: Deref> LowerBoundedFeeEstimator<F> where F::Target: FeeEstimator {
	/// Creates a new `LowerBoundedFeeEstimator` which wraps the provided fee_estimator
	pub fn new(fee_estimator: F) -> Self {
		LowerBoundedFeeEstimator(fee_estimator)
	}

	pub fn bounded_sat_per_1000_weight(&self, confirmation_target: ConfirmationTarget) -> u32 {
		cmp::max(
			self.0.get_est_sat_per_1000_weight(confirmation_target),
			FEERATE_FLOOR_SATS_PER_KW,
		)
	}
}

#[cfg(test)]
mod tests {
	use super::{FEERATE_FLOOR_SATS_PER_KW, LowerBoundedFeeEstimator, ConfirmationTarget, FeeEstimator};

	struct TestFeeEstimator {
		sat_per_kw: u32,
	}

	impl FeeEstimator for TestFeeEstimator {
		fn get_est_sat_per_1000_weight(&self, _: ConfirmationTarget) -> u32 {
			self.sat_per_kw
		}
	}

	#[test]
	fn test_fee_estimator_less_than_floor() {
		let sat_per_kw = FEERATE_FLOOR_SATS_PER_KW - 1;
		let test_fee_estimator = &TestFeeEstimator { sat_per_kw };
		let fee_estimator = LowerBoundedFeeEstimator::new(test_fee_estimator);

		assert_eq!(fee_estimator.bounded_sat_per_1000_weight(ConfirmationTarget::Background), FEERATE_FLOOR_SATS_PER_KW);
	}

	#[test]
	fn test_fee_estimator_greater_than_floor() {
		let sat_per_kw = FEERATE_FLOOR_SATS_PER_KW + 1;
		let test_fee_estimator = &TestFeeEstimator { sat_per_kw };
		let fee_estimator = LowerBoundedFeeEstimator::new(test_fee_estimator);

		assert_eq!(fee_estimator.bounded_sat_per_1000_weight(ConfirmationTarget::Background), sat_per_kw);
	}
}
