// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Utilities to send payments and manage outbound payment information.

use crate::ln::{PaymentHash, PaymentSecret};
use crate::ln::msgs::DecodeError;
use crate::routing::router::{RouteHop, RoutePath};
use crate::prelude::*;

/// Stores the session_priv for each part of a payment that is still pending. For versions 0.0.102
/// and later, also stores information for retrying the payment.
pub(crate) enum PendingOutboundPayment {
	Legacy {
		session_privs: HashSet<[u8; 32]>,
	},
	Retryable {
		session_privs: HashSet<[u8; 32]>,
		payment_hash: PaymentHash,
		payment_secret: Option<PaymentSecret>,
		pending_amt_msat: u64,
		/// Used to track the fee paid. Only present if the payment was serialized on 0.0.103+.
		pending_fee_msat: Option<u64>,
		/// The total payment amount across all paths, used to verify that a retry is not overpaying.
		total_msat: u64,
		/// Our best known block height at the time this payment was initiated.
		starting_block_height: u32,
	},
	/// When a pending payment is fulfilled, we continue tracking it until all pending HTLCs have
	/// been resolved. This ensures we don't look up pending payments in ChannelMonitors on restart
	/// and add a pending payment that was already fulfilled.
	Fulfilled {
		session_privs: HashSet<[u8; 32]>,
		payment_hash: Option<PaymentHash>,
		timer_ticks_without_htlcs: u8,
	},
	/// When a payer gives up trying to retry a payment, they inform us, letting us generate a
	/// `PaymentFailed` event when all HTLCs have irrevocably failed. This avoids a number of race
	/// conditions in MPP-aware payment retriers (1), where the possibility of multiple
	/// `PaymentPathFailed` events with `all_paths_failed` can be pending at once, confusing a
	/// downstream event handler as to when a payment has actually failed.
	///
	/// (1) https://github.com/lightningdevkit/rust-lightning/issues/1164
	Abandoned {
		session_privs: HashSet<[u8; 32]>,
		payment_hash: PaymentHash,
	},
}

impl PendingOutboundPayment {
	pub(super) fn is_fulfilled(&self) -> bool {
		match self {
			PendingOutboundPayment::Fulfilled { .. } => true,
			_ => false,
		}
	}
	pub(super) fn abandoned(&self) -> bool {
		match self {
			PendingOutboundPayment::Abandoned { .. } => true,
			_ => false,
		}
	}
	pub(super) fn get_pending_fee_msat(&self) -> Option<u64> {
		match self {
			PendingOutboundPayment::Retryable { pending_fee_msat, .. } => pending_fee_msat.clone(),
			_ => None,
		}
	}

	pub(super) fn payment_hash(&self) -> Option<PaymentHash> {
		match self {
			PendingOutboundPayment::Legacy { .. } => None,
			PendingOutboundPayment::Retryable { payment_hash, .. } => Some(*payment_hash),
			PendingOutboundPayment::Fulfilled { payment_hash, .. } => *payment_hash,
			PendingOutboundPayment::Abandoned { payment_hash, .. } => Some(*payment_hash),
		}
	}

	pub(super) fn mark_fulfilled(&mut self) {
		let mut session_privs = HashSet::new();
		core::mem::swap(&mut session_privs, match self {
			PendingOutboundPayment::Legacy { session_privs } |
				PendingOutboundPayment::Retryable { session_privs, .. } |
				PendingOutboundPayment::Fulfilled { session_privs, .. } |
				PendingOutboundPayment::Abandoned { session_privs, .. }
			=> session_privs,
		});
		let payment_hash = self.payment_hash();
		*self = PendingOutboundPayment::Fulfilled { session_privs, payment_hash, timer_ticks_without_htlcs: 0 };
	}

	pub(super) fn mark_abandoned(&mut self) -> Result<(), ()> {
		let mut session_privs = HashSet::new();
		let our_payment_hash;
		core::mem::swap(&mut session_privs, match self {
			PendingOutboundPayment::Legacy { .. } |
				PendingOutboundPayment::Fulfilled { .. } =>
				return Err(()),
				PendingOutboundPayment::Retryable { session_privs, payment_hash, .. } |
					PendingOutboundPayment::Abandoned { session_privs, payment_hash, .. } => {
						our_payment_hash = *payment_hash;
						session_privs
					},
		});
		*self = PendingOutboundPayment::Abandoned { session_privs, payment_hash: our_payment_hash };
		Ok(())
	}

	/// panics if path is None and !self.is_fulfilled
	pub(super) fn remove(&mut self, session_priv: &[u8; 32], path: Option<&Vec<RouteHop>>) -> bool {
		let remove_res = match self {
			PendingOutboundPayment::Legacy { session_privs } |
				PendingOutboundPayment::Retryable { session_privs, .. } |
				PendingOutboundPayment::Fulfilled { session_privs, .. } |
				PendingOutboundPayment::Abandoned { session_privs, .. } => {
					session_privs.remove(session_priv)
				}
		};
		if remove_res {
			if let PendingOutboundPayment::Retryable { ref mut pending_amt_msat, ref mut pending_fee_msat, .. } = self {
				let path = path.expect("Fulfilling a payment should always come with a path");
				let path_last_hop = path.last().expect("Outbound payments must have had a valid path");
				*pending_amt_msat -= path_last_hop.fee_msat;
				if let Some(fee_msat) = pending_fee_msat.as_mut() {
					*fee_msat -= path.get_path_fees();
				}
			}
		}
		remove_res
	}

	pub(super) fn insert(&mut self, session_priv: [u8; 32], path: &Vec<RouteHop>) -> bool {
		let insert_res = match self {
			PendingOutboundPayment::Legacy { session_privs } |
				PendingOutboundPayment::Retryable { session_privs, .. } => {
					session_privs.insert(session_priv)
				}
			PendingOutboundPayment::Fulfilled { .. } => false,
			PendingOutboundPayment::Abandoned { .. } => false,
		};
		if insert_res {
			if let PendingOutboundPayment::Retryable { ref mut pending_amt_msat, ref mut pending_fee_msat, .. } = self {
				let path_last_hop = path.last().expect("Outbound payments must have had a valid path");
				*pending_amt_msat += path_last_hop.fee_msat;
				if let Some(fee_msat) = pending_fee_msat.as_mut() {
					*fee_msat += path.get_path_fees();
				}
			}
		}
		insert_res
	}

	pub(super) fn remaining_parts(&self) -> usize {
		match self {
			PendingOutboundPayment::Legacy { session_privs } |
				PendingOutboundPayment::Retryable { session_privs, .. } |
				PendingOutboundPayment::Fulfilled { session_privs, .. } |
				PendingOutboundPayment::Abandoned { session_privs, .. } => {
					session_privs.len()
				}
		}
	}
}

impl_writeable_tlv_based_enum_upgradable!(PendingOutboundPayment,
	(0, Legacy) => {
		(0, session_privs, required),
	},
	(1, Fulfilled) => {
		(0, session_privs, required),
		(1, payment_hash, option),
		(3, timer_ticks_without_htlcs, (default_value, 0)),
	},
	(2, Retryable) => {
		(0, session_privs, required),
		(1, pending_fee_msat, option),
		(2, payment_hash, required),
		(4, payment_secret, option),
		(6, total_msat, required),
		(8, pending_amt_msat, required),
		(10, starting_block_height, required),
	},
	(3, Abandoned) => {
		(0, session_privs, required),
		(2, payment_hash, required),
	},
);
