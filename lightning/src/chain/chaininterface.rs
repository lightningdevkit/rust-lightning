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
use core::convert::TryInto;

use bitcoin::blockdata::transaction::Transaction;

// TODO: Define typed abstraction over feerates to handle their conversions.
pub(crate) fn compute_feerate_sat_per_1000_weight(fee_sat: u64, weight: u64) -> u32 {
	(fee_sat * 1000 / weight).try_into().unwrap_or(u32::max_value())
}
pub(crate) const fn fee_for_weight(feerate_sat_per_1000_weight: u32, weight: u64) -> u64 {
	((feerate_sat_per_1000_weight as u64 * weight) + 1000 - 1) / 1000
}

/// An interface to send a transaction to the Bitcoin network.
pub trait BroadcasterInterface {
	/// Sends a list of transactions out to (hopefully) be mined.
	/// This only needs to handle the actual broadcasting of transactions, LDK will automatically
	/// rebroadcast transactions that haven't made it into a block.
	///
	/// In some cases LDK may attempt to broadcast a transaction which double-spends another
	/// and this isn't a bug and can be safely ignored.
	///
	/// If more than one transaction is given, these transactions should be considered to be a
	/// package and broadcast together. Some of the transactions may or may not depend on each other,
	/// be sure to manage both cases correctly.
	///
	/// Bitcoin transaction packages are defined in BIP 331 and here:
	/// https://github.com/bitcoin/bitcoin/blob/master/doc/policy/packages.md
	fn broadcast_transactions(&self, txs: &[&Transaction]);
}

/// An enum that represents the priority at which we want a transaction to confirm used for feerate
/// estimation.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub enum ConfirmationTarget {
	/// We'd like a transaction to confirm in the future, but don't want to commit most of the fees
	/// required to do so yet. The remaining fees will come via a Child-Pays-For-Parent (CPFP) fee
	/// bump of the transaction.
	///
	/// The feerate returned should be the absolute minimum feerate required to enter most node
	/// mempools across the network. Note that if you are not able to obtain this feerate estimate,
	/// you should likely use the furthest-out estimate allowed by your fee estimator.
	MempoolMinimum,
	/// We are happy with a transaction confirming slowly, at least within a day or so worth of
	/// blocks.
	Background,
	/// We'd like a transaction to confirm without major delayed, i.e., within the next 12-24 blocks.
	Normal,
	/// We'd like a transaction to confirm in the next few blocks.
	HighPriority,
}

/// A trait which should be implemented to provide feerate information on a number of time
/// horizons.
///
/// If access to a local mempool is not feasible, feerate estimates should be fetched from a set of
/// third-parties hosting them. Note that this enables them to affect the propagation of your
/// pre-signed transactions at any time and therefore endangers the safety of channels funds. It
/// should be considered carefully as a deployment.
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
