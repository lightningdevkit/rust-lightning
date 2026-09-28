// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

use alloc::vec::Vec;

use lightning::impl_ser_tlv_based;
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

	fn payment_status(entry: &PaymentQueueEntry) -> (u64, usize) {
		let total_expected_outbound_amount_msat =
			entry.htlcs.iter().map(|htlc| htlc.expected_outbound_amount_msat).sum();
		(total_expected_outbound_amount_msat, entry.htlcs.len())
	}

	pub(crate) fn add_htlc(&mut self, new_htlc: InterceptedHTLC) -> (u64, usize) {
		if let Some(entry) = self
			.payments
			.iter()
			.find(|entry| entry.htlcs.iter().any(|htlc| htlc.intercept_id == new_htlc.intercept_id))
		{
			debug_assert_eq!(entry.payment_hash, new_htlc.payment_hash);
			return Self::payment_status(entry);
		}

		let payment =
			self.payments.iter_mut().find(|entry| entry.payment_hash == new_htlc.payment_hash);
		if let Some(entry) = payment {
			// HTLCs within a payment should have the same payment hash.
			debug_assert!(entry.htlcs.iter().all(|htlc| htlc.payment_hash == entry.payment_hash));
			entry.htlcs.push(new_htlc);
			Self::payment_status(entry)
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

	/// Drops the HTLCs for which `keep` returns `false`, discarding any payment left without
	/// HTLCs. Returns whether anything was dropped.
	pub(crate) fn retain_htlcs(&mut self, mut keep: impl FnMut(&InterceptedHTLC) -> bool) -> bool {
		let mut changed = false;
		self.payments.retain_mut(|entry| {
			let previous_len = entry.htlcs.len();
			entry.htlcs.retain(|htlc| keep(htlc));
			changed |= entry.htlcs.len() != previous_len;
			!entry.htlcs.is_empty()
		});
		changed
	}
}

impl_ser_tlv_based!(PaymentQueue, {
	(0, payments, optional_vec),
});

#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) struct PaymentQueueEntry {
	pub(crate) payment_hash: PaymentHash,
	pub(crate) htlcs: Vec<InterceptedHTLC>,
}

impl_ser_tlv_based!(PaymentQueueEntry, {
	(0, payment_hash, required),
	(2, htlcs, optional_vec),
});

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub(crate) struct InterceptedHTLC {
	pub(crate) intercept_id: InterceptId,
	pub(crate) expected_outbound_amount_msat: u64,
	pub(crate) payment_hash: PaymentHash,
}

impl_ser_tlv_based!(InterceptedHTLC, {
	(0, intercept_id, required),
	(2, expected_outbound_amount_msat, required),
	(4, payment_hash, required),
});

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

	#[test]
	fn test_retain_htlcs() {
		let htlc = |id, hash| InterceptedHTLC {
			intercept_id: InterceptId([id; 32]),
			expected_outbound_amount_msat: 100_000_000,
			payment_hash: PaymentHash([hash; 32]),
		};
		let mut payment_queue = PaymentQueue::new();
		payment_queue.add_htlc(htlc(0, 100));
		payment_queue.add_htlc(htlc(1, 100));
		payment_queue.add_htlc(htlc(2, 101));

		// Dropping one part of a payment leaves its siblings and other payments alone.
		assert!(payment_queue.retain_htlcs(|htlc| htlc.intercept_id != InterceptId([0; 32])));
		assert_eq!(payment_queue.pop_greater_than_msat(0).unwrap().htlcs, vec![htlc(1, 100)]);
		assert_eq!(payment_queue.pop_greater_than_msat(0).unwrap().htlcs, vec![htlc(2, 101)]);
		assert_eq!(payment_queue.pop_greater_than_msat(0), None);

		// A pass that drops nothing reports no change.
		let mut payment_queue = PaymentQueue::new();
		payment_queue.add_htlc(htlc(0, 100));
		assert!(!payment_queue.retain_htlcs(|htlc| htlc.intercept_id != InterceptId([1; 32])));
		assert_eq!(payment_queue.pop_greater_than_msat(0).unwrap().htlcs, vec![htlc(0, 100)]);

		// A payment left without HTLCs is discarded entirely.
		let mut payment_queue = PaymentQueue::new();
		payment_queue.add_htlc(htlc(0, 100));
		payment_queue.add_htlc(htlc(1, 101));
		assert!(payment_queue.retain_htlcs(|htlc| htlc.intercept_id != InterceptId([0; 32])));
		assert_eq!(payment_queue.pop_greater_than_msat(0).unwrap().htlcs, vec![htlc(1, 101)]);
		assert_eq!(payment_queue.pop_greater_than_msat(0), None);
	}
}
