use crate::prelude::Vec;
use lightning::ln::channelmanager::InterceptId;
use lightning::ln::PaymentHash;

/// Holds payments with the corresponding HTLCs until it is possible to pay the fee.
/// When the fee is successfully paid with a forwarded payment, the queue should be consumed and the
/// remaining payments forwarded.
#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) struct PaymentQueue {
	payments: Vec<(PaymentHash, Vec<InterceptedHTLC>)>,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub(crate) struct InterceptedHTLC {
	pub(crate) intercept_id: InterceptId,
	pub(crate) expected_outbound_amount_msat: u64,
	pub(crate) payment_hash: PaymentHash,
}

impl PaymentQueue {
	pub(crate) fn new() -> PaymentQueue {
		PaymentQueue { payments: Vec::new() }
	}

	pub(crate) fn add_htlc(&mut self, new_htlc: InterceptedHTLC) -> (u64, usize) {
		let payment = self.payments.iter_mut().find(|(p, _)| p == &new_htlc.payment_hash);
		if let Some((payment_hash, htlcs)) = payment {
			// HTLCs within a payment should have the same payment hash.
			debug_assert!(htlcs.iter().all(|htlc| htlc.payment_hash == *payment_hash));
			// The given HTLC should not already be present.
			debug_assert!(htlcs.iter().all(|htlc| htlc.intercept_id != new_htlc.intercept_id));
			htlcs.push(new_htlc);
			let total_expected_outbound_amount_msat =
				htlcs.iter().map(|htlc| htlc.expected_outbound_amount_msat).sum();
			(total_expected_outbound_amount_msat, htlcs.len())
		} else {
			let expected_outbound_amount_msat = new_htlc.expected_outbound_amount_msat;
			self.payments.push((new_htlc.payment_hash, vec![new_htlc]));
			(expected_outbound_amount_msat, 1)
		}
	}

	pub(crate) fn pop_greater_than_msat(
		&mut self, amount_msat: u64,
	) -> Option<(PaymentHash, Vec<InterceptedHTLC>)> {
		let position = self.payments.iter().position(|(_payment_hash, htlcs)| {
			htlcs.iter().map(|htlc| htlc.expected_outbound_amount_msat).sum::<u64>() >= amount_msat
		});
		position.map(|position| self.payments.remove(position))
	}

	pub(crate) fn clear(&mut self) -> Vec<InterceptedHTLC> {
		self.payments.drain(..).map(|(_k, v)| v).flatten().collect()
	}
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
		assert_eq!(
			payment_queue.pop_greater_than_msat(500_000_000),
			Some((
				PaymentHash([100; 32]),
				vec![
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
				]
			))
		);
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
