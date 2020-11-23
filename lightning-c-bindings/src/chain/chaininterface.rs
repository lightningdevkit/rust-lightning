//! Traits and utility impls which allow other parts of rust-lightning to interact with the
//! blockchain.
//!
//! Includes traits for monitoring and receiving notifications of new blocks and block
//! disconnections, transaction broadcasting, and feerate information requests.

use std::ffi::c_void;
use bitcoin::hashes::Hash;
use crate::c_types::*;

/// An interface to send a transaction to the Bitcoin network.
#[repr(C)]
pub struct BroadcasterInterface {
	pub this_arg: *mut c_void,
	/// Sends a transaction out to (hopefully) be mined.
	pub broadcast_transaction: extern "C" fn (this_arg: *const c_void, tx: crate::c_types::Transaction),
	pub free: Option<extern "C" fn(this_arg: *mut c_void)>,
}
unsafe impl Sync for BroadcasterInterface {}
unsafe impl Send for BroadcasterInterface {}

use lightning::chain::chaininterface::BroadcasterInterface as rustBroadcasterInterface;
impl rustBroadcasterInterface for BroadcasterInterface {
	fn broadcast_transaction(&self, tx: &bitcoin::blockdata::transaction::Transaction) {
		let mut local_tx = ::bitcoin::consensus::encode::serialize(tx);
		(self.broadcast_transaction)(self.this_arg, crate::c_types::Transaction::from_vec(local_tx))
	}
}

// We're essentially a pointer already, or at least a set of pointers, so allow us to be used
// directly as a Deref trait in higher-level structs:
impl std::ops::Deref for BroadcasterInterface {
	type Target = Self;
	fn deref(&self) -> &Self {
		self
	}
}
/// Calls the free function if one is set
#[no_mangle]
pub extern "C" fn BroadcasterInterface_free(this_ptr: BroadcasterInterface) { }
impl Drop for BroadcasterInterface {
	fn drop(&mut self) {
		if let Some(f) = self.free {
			f(self.this_arg);
		}
	}
}
/// An enum that represents the speed at which we want a transaction to confirm used for feerate
/// estimation.
#[must_use]
#[derive(Clone)]
#[repr(C)]
pub enum ConfirmationTarget {
	/// We are happy with this transaction confirming slowly when feerate drops some.
	Background,
	/// We'd like this transaction to confirm without major delay, but 12-18 blocks is fine.
	Normal,
	/// We'd like this transaction to confirm in the next few blocks.
	HighPriority,
}
use lightning::chain::chaininterface::ConfirmationTarget as nativeConfirmationTarget;
impl ConfirmationTarget {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeConfirmationTarget {
		match self {
			ConfirmationTarget::Background => nativeConfirmationTarget::Background,
			ConfirmationTarget::Normal => nativeConfirmationTarget::Normal,
			ConfirmationTarget::HighPriority => nativeConfirmationTarget::HighPriority,
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeConfirmationTarget {
		match self {
			ConfirmationTarget::Background => nativeConfirmationTarget::Background,
			ConfirmationTarget::Normal => nativeConfirmationTarget::Normal,
			ConfirmationTarget::HighPriority => nativeConfirmationTarget::HighPriority,
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &nativeConfirmationTarget) -> Self {
		match native {
			nativeConfirmationTarget::Background => ConfirmationTarget::Background,
			nativeConfirmationTarget::Normal => ConfirmationTarget::Normal,
			nativeConfirmationTarget::HighPriority => ConfirmationTarget::HighPriority,
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeConfirmationTarget) -> Self {
		match native {
			nativeConfirmationTarget::Background => ConfirmationTarget::Background,
			nativeConfirmationTarget::Normal => ConfirmationTarget::Normal,
			nativeConfirmationTarget::HighPriority => ConfirmationTarget::HighPriority,
		}
	}
}
#[no_mangle]
pub extern "C" fn ConfirmationTarget_clone(orig: &ConfirmationTarget) -> ConfirmationTarget {
	orig.clone()
}
/// A trait which should be implemented to provide feerate information on a number of time
/// horizons.
///
/// Note that all of the functions implemented here *must* be reentrant-safe (obviously - they're
/// called from inside the library in response to chain events, P2P events, or timer events).
#[repr(C)]
pub struct FeeEstimator {
	pub this_arg: *mut c_void,
	/// Gets estimated satoshis of fee required per 1000 Weight-Units.
	///
	/// Must be no smaller than 253 (ie 1 satoshi-per-byte rounded up to ensure later round-downs
	/// don't put us below 1 satoshi-per-byte).
	///
	/// This translates to:
	///  * satoshis-per-byte * 250
	///  * ceil(satoshis-per-kbyte / 4)
	#[must_use]
	pub get_est_sat_per_1000_weight: extern "C" fn (this_arg: *const c_void, confirmation_target: crate::chain::chaininterface::ConfirmationTarget) -> u32,
	pub free: Option<extern "C" fn(this_arg: *mut c_void)>,
}
unsafe impl Sync for FeeEstimator {}
unsafe impl Send for FeeEstimator {}

use lightning::chain::chaininterface::FeeEstimator as rustFeeEstimator;
impl rustFeeEstimator for FeeEstimator {
	fn get_est_sat_per_1000_weight(&self, confirmation_target: lightning::chain::chaininterface::ConfirmationTarget) -> u32 {
		let mut ret = (self.get_est_sat_per_1000_weight)(self.this_arg, crate::chain::chaininterface::ConfirmationTarget::native_into(confirmation_target));
		ret
	}
}

// We're essentially a pointer already, or at least a set of pointers, so allow us to be used
// directly as a Deref trait in higher-level structs:
impl std::ops::Deref for FeeEstimator {
	type Target = Self;
	fn deref(&self) -> &Self {
		self
	}
}
/// Calls the free function if one is set
#[no_mangle]
pub extern "C" fn FeeEstimator_free(this_ptr: FeeEstimator) { }
impl Drop for FeeEstimator {
	fn drop(&mut self) {
		if let Some(f) = self.free {
			f(self.this_arg);
		}
	}
}

#[no_mangle]
pub static MIN_RELAY_FEE_SAT_PER_1000_WEIGHT: u64 = lightning::chain::chaininterface::MIN_RELAY_FEE_SAT_PER_1000_WEIGHT;
