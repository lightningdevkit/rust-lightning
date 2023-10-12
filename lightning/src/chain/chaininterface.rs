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
	/// We have some funds available on chain which we need to spend prior to some expiry time at
	/// which point our counterparty may be able to steal them. Generally we have in the high tens
	/// to low hundreds of blocks to get our transaction on-chain, but we shouldn't risk too low a
	/// fee - this should be a relatively high priority feerate.
	OnChainSweep,
	/// The highest feerate we will allow our channel counterparty to have in a non-anchor channel.
	///
	/// This is the feerate on the transaction which we (or our counterparty) will broadcast in
	/// order to close the channel unilaterally. Because our counterparty must ensure they can
	/// always broadcast the latest state, this value being too low will cause immediate
	/// force-closures.
	///
	/// Allowing this value to be too high can allow our counterparty to burn our HTLC outputs to
	/// dust, which can result in HTLCs failing or force-closures (when the dust HTLCs exceed
	/// [`ChannelConfig::max_dust_htlc_exposure`]).
	///
	/// Because most nodes use a feerate estimate which is based on a relatively high priority
	/// transaction entering the current mempool, setting this to a small multiple of your current
	/// high priority feerate estimate should suffice.
	///
	/// [`ChannelConfig::max_dust_htlc_exposure`]: crate::util::config::ChannelConfig::max_dust_htlc_exposure
	MaxAllowedNonAnchorChannelRemoteFee,
	/// This is the lowest feerate we will allow our channel counterparty to have in an anchor
	/// channel in order to close the channel if a channel party goes away. Because our counterparty
	/// must ensure they can always broadcast the latest state, this value being too high will cause
	/// immediate force-closures.
	///
	/// This needs to be sufficient to get into the mempool when the channel needs to
	/// be force-closed. Setting too low may result in force-closures. Because this is for anchor
	/// channels, we can always bump the feerate later, the feerate here only needs to suffice to
	/// enter the mempool.
	///
	/// A good estimate is the expected mempool minimum at the time of force-closure. Obviously this
	/// is not an estimate which is very easy to calculate because we do not know the future. Using
	/// a simple long-term fee estimate or tracking of the mempool minimum is a good approach to
	/// ensure you can always close the channel. A future change to Bitcoin's P2P network
	/// (package relay) may obviate the need for this entirely.
	MinAllowedAnchorChannelRemoteFee,
	/// The lowest feerate we will allow our channel counterparty to have in a non-anchor channel.
	/// This needs to be sufficient to get confirmed when the channel needs to be force-closed.
	/// Setting too low may result in force-closures.
	///
	/// This is the feerate on the transaction which we (or our counterparty) will broadcast in
	/// order to close the channel if a channel party goes away. Because our counterparty must
	/// ensure they can always broadcast the latest state, this value being too high will cause
	/// immediate force-closures.
	///
	/// This feerate represents the fee we pick now, which must be sufficient to enter a block at an
	/// arbitrary time in the future. Obviously this is not an estimate which is very easy to
	/// calculate. This can leave channels subject to being unable to close if feerates rise, and in
	/// general you should prefer anchor channels to ensure you can increase the feerate when the
	/// transactions need broadcasting.
	///
	/// Do note some fee estimators round up to the next full sat/vbyte (ie 250 sats per kw),
	/// causing occasional issues with feerate disagreements between an initiator that wants a
	/// feerate of 1.1 sat/vbyte and a receiver that wants 1.1 rounded up to 2. If your fee
	/// estimator rounds subtracting 250 to your desired feerate here can help avoid this issue.
	///
	/// [`ChannelConfig::max_dust_htlc_exposure`]: crate::util::config::ChannelConfig::max_dust_htlc_exposure
	MinAllowedNonAnchorChannelRemoteFee,
	/// This is the feerate on the transaction which we (or our counterparty) will broadcast in
	/// order to close the channel if a channel party goes away.
	///
	/// This needs to be sufficient to get into the mempool when the channel needs to
	/// be force-closed. Setting too low may result in force-closures. Because this is for anchor
	/// channels, it can be a low value as we can always bump the feerate later.
	///
	/// A good estimate is the expected mempool minimum at the time of force-closure. Obviously this
	/// is not an estimate which is very easy to calculate because we do not know the future. Using
	/// a simple long-term fee estimate or tracking of the mempool minimum is a good approach to
	/// ensure you can always close the channel. A future change to Bitcoin's P2P network
	/// (package relay) may obviate the need for this entirely.
	AnchorChannelFee,
	/// Lightning is built around the ability to broadcast a transaction in the future to close our
	/// channel and claim all pending funds. In order to do so, non-anchor channels are built with
	/// transactions which we need to be able to broadcast at some point in the future.
	///
	/// This feerate represents the fee we pick now, which must be sufficient to enter a block at an
	/// arbitrary time in the future. Obviously this is not an estimate which is very easy to
	/// calculate, so most lightning nodes use some relatively high-priority feerate using the
	/// current mempool. This leaves channels subject to being unable to close if feerates rise, and
	/// in general you should prefer anchor channels to ensure you can increase the feerate when the
	/// transactions need broadcasting.
	///
	/// Since this should represent the feerate of a channel close that does not need fee
	/// bumping, this is also used as an upper bound for our attempted feerate when doing cooperative
	/// closure of any channel.
	NonAnchorChannelFee,
	/// When cooperatively closing a channel, this is the minimum feerate we will accept.
	/// Recommended at least within a day or so worth of blocks.
	///
	/// This will also be used when initiating a cooperative close of a channel. When closing a
	/// channel you can override this fee by using
	/// [`ChannelManager::close_channel_with_feerate_and_script`].
	///
	/// [`ChannelManager::close_channel_with_feerate_and_script`]: crate::ln::channelmanager::ChannelManager::close_channel_with_feerate_and_script
	ChannelCloseMinimum,
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

		assert_eq!(fee_estimator.bounded_sat_per_1000_weight(ConfirmationTarget::AnchorChannelFee), FEERATE_FLOOR_SATS_PER_KW);
	}

	#[test]
	fn test_fee_estimator_greater_than_floor() {
		let sat_per_kw = FEERATE_FLOOR_SATS_PER_KW + 1;
		let test_fee_estimator = &TestFeeEstimator { sat_per_kw };
		let fee_estimator = LowerBoundedFeeEstimator::new(test_fee_estimator);

		assert_eq!(fee_estimator.bounded_sat_per_1000_weight(ConfirmationTarget::AnchorChannelFee), sat_per_kw);
	}
}
