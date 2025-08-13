// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

use alloc::vec::Vec;

use lightning::ln::channelmanager::InterceptId;
use lightning_types::payment::PaymentHash;

/// Holds payments with the corresponding HTLCs until it is possible to pay the fee.
/// When the fee is successfully paid with a forwarded payment, the queue should be consumed and the
/// remaining payments forwarded.
#[derive(Clone, Default, PartialEq, Eq, Debug)]
pub(crate) struct PaymentQueue {
	payments: Vec<PaymentQueueEntry>,
}

impl PaymentQueue {
	pub(crate) fn new() -> PaymentQueue {
		PaymentQueue { payments: Vec::new() }
	}

	pub(crate) fn add_htlc(&mut self, new_htlc: InterceptedHTLC) -> (u64, usize) {
		let payment =
			self.payments.iter_mut().find(|entry| entry.payment_hash == new_htlc.payment_hash);
		if let Some(entry) = payment {
			// HTLCs within a payment should have the same payment hash.
			debug_assert!(entry.htlcs.iter().all(|htlc| htlc.payment_hash == entry.payment_hash));
			// The given HTLC should not already be present.
			debug_assert!(entry
				.htlcs
				.iter()
				.all(|htlc| htlc.intercept_id != new_htlc.intercept_id));
			entry.htlcs.push(new_htlc);
			let total_expected_outbound_amount_msat =
				entry.htlcs.iter().map(|htlc| htlc.expected_outbound_amount_msat).sum();
			(total_expected_outbound_amount_msat, entry.htlcs.len())
		} else {
			let expected_outbound_amount_msat = new_htlc.expected_outbound_amount_msat;
			let entry =
				PaymentQueueEntry { payment_hash: new_htlc.payment_hash, htlcs: vec![new_htlc] };
			self.payments.push(entry);
			(expected_outbound_amount_msat, 1)
		}
	}

	pub(crate) fn pop_greater_than_msat(&mut self, amount_msat: u64) -> Option<PaymentQueueEntry> {
		let position = self.payments.iter().position(|entry| {
			entry.htlcs.iter().map(|htlc| htlc.expected_outbound_amount_msat).sum::<u64>()
				>= amount_msat
		});
		position.map(|position| self.payments.remove(position))
	}

	pub(crate) fn clear(&mut self) -> Vec<InterceptedHTLC> {
		self.payments.drain(..).map(|entry| entry.htlcs).flatten().collect()
	}
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) struct PaymentQueueEntry {
	pub(crate) payment_hash: PaymentHash,
	pub(crate) htlcs: Vec<InterceptedHTLC>,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub(crate) struct InterceptedHTLC {
	pub(crate) intercept_id: InterceptId,
	pub(crate) expected_outbound_amount_msat: u64,
	pub(crate) payment_hash: PaymentHash,
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_payment_queue() {
		let mut payment_queue = PaymentQueue::new();
		assert_eq!(
			payment_queue.add_htlc(InterceptedHTLC {
				intercept_id: InterceptId([0; 32]),
				expected_outbound_amount_msat: 200_000_000,
				payment_hash: PaymentHash([100; 32]),
			}),
			(200_000_000, 1),
		);
		assert_eq!(payment_queue.pop_greater_than_msat(500_000_000), None);

		assert_eq!(
			payment_queue.add_htlc(InterceptedHTLC {
				intercept_id: InterceptId([1; 32]),
				expected_outbound_amount_msat: 300_000_000,
				payment_hash: PaymentHash([101; 32]),
			}),
			(300_000_000, 1),
		);
		assert_eq!(payment_queue.pop_greater_than_msat(500_000_000), None);

		assert_eq!(
			payment_queue.add_htlc(InterceptedHTLC {
				intercept_id: InterceptId([2; 32]),
				expected_outbound_amount_msat: 300_000_000,
				payment_hash: PaymentHash([100; 32]),
			}),
			(500_000_000, 2),
		);

		let expected_entry = PaymentQueueEntry {
			payment_hash: PaymentHash([100; 32]),
			htlcs: vec![
				InterceptedHTLC {
					intercept_id: InterceptId([0; 32]),
					expected_outbound_amount_msat: 200_000_000,
					payment_hash: PaymentHash([100; 32]),
				},
				InterceptedHTLC {
					intercept_id: InterceptId([2; 32]),
					expected_outbound_amount_msat: 300_000_000,
					payment_hash: PaymentHash([100; 32]),
				},
			],
		};
		assert_eq!(payment_queue.pop_greater_than_msat(500_000_000), Some(expected_entry),);
		assert_eq!(
			payment_queue.clear(),
			vec![InterceptedHTLC {
				intercept_id: InterceptId([1; 32]),
				expected_outbound_amount_msat: 300_000_000,
				payment_hash: PaymentHash([101; 32]),
			}]
		);
	}
}
