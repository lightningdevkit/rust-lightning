// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Contains peer state objects that are used by `LSPS1ServiceHandler`.

use super::msgs::{
	LSPS1ChannelInfo, LSPS1OrderId, LSPS1OrderParams, LSPS1OrderState, LSPS1PaymentInfo,
	LSPS1PaymentState, LSPS1Request,
};

use crate::lsps0::ser::{LSPSDateTime, LSPSRequestId};
use crate::prelude::HashMap;

use lightning::util::hash_tables::new_hash_map;
use lightning::{impl_writeable_tlv_based, impl_writeable_tlv_based_enum};

use core::fmt;

/// Indicates which payment method was used for the order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaymentMethod {
	/// A Lightning payment using BOLT 11.
	Bolt11,
	/// A Lightning payment using BOLT 12.
	Bolt12,
	/// An onchain payment.
	Onchain,
}

/// Error type for invalid state transitions.
#[derive(Debug, Clone)]
pub(super) enum ChannelOrderStateError {
	/// Attempted an invalid state transition.
	InvalidStateTransition {
		/// The state from which the transition was attempted.
		from: LSPS1OrderState,
		/// The action that was attempted.
		action: &'static str,
	},
	/// The specified payment method was not configured for this order.
	PaymentMethodNotConfigured,
}

impl fmt::Display for ChannelOrderStateError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::InvalidStateTransition { from, action } => {
				write!(f, "invalid state transition: cannot {} from {:?}", action, from)
			},
			Self::PaymentMethodNotConfigured => {
				write!(f, "payment method not configured for this order")
			},
		}
	}
}

/// Internal state machine for tracking channel order progress.
///
/// This combines the wire `order_state` (CREATED/COMPLETED/FAILED) with internal
/// payment tracking to provide type-safe state transitions.
#[derive(Debug, Clone)]
pub(super) enum ChannelOrderState {
	/// Initial state - awaiting payment from client.
	/// Payment states within payment_details should be EXPECT_PAYMENT.
	ExpectingPayment {
		/// Details about how to pay for the order.
		payment_details: LSPS1PaymentInfo,
	},
	/// Payment received, awaiting channel open.
	/// The paid method's state should be PAID.
	OrderPaid {
		/// Details about how to pay for the order (with paid method updated).
		payment_details: LSPS1PaymentInfo,
	},
	/// Channel successfully funded and opened (terminal).
	/// Payment states should be PAID.
	CompletedAndChannelOpened {
		/// Details about how to pay for the order.
		payment_details: LSPS1PaymentInfo,
		/// Information about the opened channel.
		channel_info: LSPS1ChannelInfo,
	},
	/// Order failed, payment refunded (terminal).
	/// Payment states should be REFUNDED.
	FailedAndRefunded {
		/// Details about how to pay for the order (with states set to REFUNDED).
		payment_details: LSPS1PaymentInfo,
	},
}

impl ChannelOrderState {
	/// Creates a new state in the ExpectingPayment state.
	pub(super) fn new(payment_details: LSPS1PaymentInfo) -> Self {
		ChannelOrderState::ExpectingPayment { payment_details }
	}

	/// Transition: ExpectingPayment -> OrderPaid
	///
	/// Updates the specified payment method's state to HOLD.
	pub(super) fn payment_received(
		&mut self, method: PaymentMethod,
	) -> Result<(), ChannelOrderStateError> {
		match self {
			ChannelOrderState::ExpectingPayment { payment_details } => {
				// Update the payment state for the specified method to HOLD
				let method_exists = match method {
					PaymentMethod::Bolt11 => {
						if let Some(ref mut bolt11) = payment_details.bolt11 {
							bolt11.state = LSPS1PaymentState::Hold;
							true
						} else {
							false
						}
					},
					PaymentMethod::Bolt12 => {
						if let Some(ref mut bolt12) = payment_details.bolt12 {
							bolt12.state = LSPS1PaymentState::Hold;
							true
						} else {
							false
						}
					},
					PaymentMethod::Onchain => {
						if let Some(ref mut onchain) = payment_details.onchain {
							onchain.state = LSPS1PaymentState::Hold;
							true
						} else {
							false
						}
					},
				};

				if !method_exists {
					return Err(ChannelOrderStateError::PaymentMethodNotConfigured);
				}

				// Move to OrderPaid state
				*self = ChannelOrderState::OrderPaid { payment_details: payment_details.clone() };
				Ok(())
			},
			_ => Err(ChannelOrderStateError::InvalidStateTransition {
				from: self.order_state(),
				action: "payment_received",
			}),
		}
	}

	/// Transition: OrderPaid -> CompletedAndChannelOpened
	///
	/// Updates payment states from HOLD to PAID.
	pub(super) fn channel_opened(
		&mut self, channel_info: LSPS1ChannelInfo,
	) -> Result<(), ChannelOrderStateError> {
		match self {
			ChannelOrderState::OrderPaid { payment_details } => {
				// Update payment states from HOLD to PAID
				let mut paid_details = payment_details.clone();
				if let Some(ref mut bolt11) = paid_details.bolt11 {
					if bolt11.state == LSPS1PaymentState::Hold {
						bolt11.state = LSPS1PaymentState::Paid;
					}
				}
				if let Some(ref mut bolt12) = paid_details.bolt12 {
					if bolt12.state == LSPS1PaymentState::Hold {
						bolt12.state = LSPS1PaymentState::Paid;
					}
				}
				if let Some(ref mut onchain) = paid_details.onchain {
					if onchain.state == LSPS1PaymentState::Hold {
						onchain.state = LSPS1PaymentState::Paid;
					}
				}

				*self = ChannelOrderState::CompletedAndChannelOpened {
					payment_details: paid_details,
					channel_info,
				};
				Ok(())
			},
			_ => Err(ChannelOrderStateError::InvalidStateTransition {
				from: self.order_state(),
				action: "channel_opened",
			}),
		}
	}

	/// Transition: ExpectingPayment|OrderPaid -> FailedAndRefunded
	///
	/// Updates all payment states to REFUNDED.
	pub(super) fn mark_failed_and_refunded(&mut self) -> Result<(), ChannelOrderStateError> {
		match self {
			ChannelOrderState::ExpectingPayment { payment_details }
			| ChannelOrderState::OrderPaid { payment_details } => {
				// Mark all payment methods as refunded
				let mut refunded_details = payment_details.clone();
				if let Some(ref mut bolt11) = refunded_details.bolt11 {
					bolt11.state = LSPS1PaymentState::Refunded;
				}
				if let Some(ref mut bolt12) = refunded_details.bolt12 {
					bolt12.state = LSPS1PaymentState::Refunded;
				}
				if let Some(ref mut onchain) = refunded_details.onchain {
					onchain.state = LSPS1PaymentState::Refunded;
				}

				*self = ChannelOrderState::FailedAndRefunded { payment_details: refunded_details };
				Ok(())
			},
			_ => Err(ChannelOrderStateError::InvalidStateTransition {
				from: self.order_state(),
				action: "mark_failed_and_refunded",
			}),
		}
	}

	/// Get payment_details (available in all states).
	pub(super) fn payment_details(&self) -> &LSPS1PaymentInfo {
		match self {
			ChannelOrderState::ExpectingPayment { payment_details }
			| ChannelOrderState::OrderPaid { payment_details }
			| ChannelOrderState::CompletedAndChannelOpened { payment_details, .. }
			| ChannelOrderState::FailedAndRefunded { payment_details } => payment_details,
		}
	}

	/// Get channel_info if in CompletedAndChannelOpened state.
	pub(super) fn channel_info(&self) -> Option<&LSPS1ChannelInfo> {
		match self {
			ChannelOrderState::CompletedAndChannelOpened { channel_info, .. } => Some(channel_info),
			_ => None,
		}
	}

	/// Convert to wire format LSPS1OrderState.
	pub(super) fn order_state(&self) -> LSPS1OrderState {
		match self {
			ChannelOrderState::ExpectingPayment { .. } | ChannelOrderState::OrderPaid { .. } => {
				LSPS1OrderState::Created
			},
			ChannelOrderState::CompletedAndChannelOpened { .. } => LSPS1OrderState::Completed,
			ChannelOrderState::FailedAndRefunded { .. } => LSPS1OrderState::Failed,
		}
	}
}

impl_writeable_tlv_based_enum!(ChannelOrderState,
	(0, ExpectingPayment) => {
		(0, payment_details, required),
	},
	(2, OrderPaid) => {
		(0, payment_details, required),
	},
	(4, CompletedAndChannelOpened) => {
		(0, payment_details, required),
		(2, channel_info, required),
	},
	(6, FailedAndRefunded) => {
		(0, payment_details, required),
	}
);

#[derive(Default)]
pub(crate) struct PeerState {
	outbound_channels_by_order_id: HashMap<LSPS1OrderId, ChannelOrder>,
	pending_requests: HashMap<LSPSRequestId, LSPS1Request>,
	needs_persist: bool,
}

impl PeerState {
	pub(super) fn new_order(
		&mut self, order_id: LSPS1OrderId, order_params: LSPS1OrderParams,
		created_at: LSPSDateTime, payment_details: LSPS1PaymentInfo,
	) -> ChannelOrder {
		let state = ChannelOrderState::new(payment_details);
		let channel_order = ChannelOrder { order_params, state, created_at };
		self.outbound_channels_by_order_id.insert(order_id, channel_order.clone());
		self.needs_persist |= true;
		channel_order
	}

	pub(super) fn get_order<'a>(
		&'a self, order_id: &LSPS1OrderId,
	) -> Result<&'a ChannelOrder, PeerStateError> {
		let order = self
			.outbound_channels_by_order_id
			.get(order_id)
			.ok_or(PeerStateError::UnknownOrderId)?;
		Ok(order)
	}

	/// Transition: ExpectingPayment -> OrderPaid
	///
	/// Updates the specified payment method's state to PAID.
	pub(super) fn order_payment_received(
		&mut self, order_id: &LSPS1OrderId, method: PaymentMethod,
	) -> Result<(), PeerStateError> {
		let order = self
			.outbound_channels_by_order_id
			.get_mut(order_id)
			.ok_or(PeerStateError::UnknownOrderId)?;
		order.state.payment_received(method).map_err(PeerStateError::InvalidStateTransition)?;
		self.needs_persist |= true;
		Ok(())
	}

	/// Transition: OrderPaid -> CompletedAndChannelOpened
	pub(super) fn order_channel_opened(
		&mut self, order_id: &LSPS1OrderId, channel_info: LSPS1ChannelInfo,
	) -> Result<(), PeerStateError> {
		let order = self
			.outbound_channels_by_order_id
			.get_mut(order_id)
			.ok_or(PeerStateError::UnknownOrderId)?;
		order.state.channel_opened(channel_info).map_err(PeerStateError::InvalidStateTransition)?;
		self.needs_persist |= true;
		Ok(())
	}

	/// Transition: ExpectingPayment|OrderPaid -> FailedAndRefunded
	///
	/// Updates all payment states to REFUNDED.
	pub(super) fn order_failed_and_refunded(
		&mut self, order_id: &LSPS1OrderId,
	) -> Result<(), PeerStateError> {
		let order = self
			.outbound_channels_by_order_id
			.get_mut(order_id)
			.ok_or(PeerStateError::UnknownOrderId)?;
		order.state.mark_failed_and_refunded().map_err(PeerStateError::InvalidStateTransition)?;
		self.needs_persist |= true;
		Ok(())
	}

	pub(super) fn register_request(
		&mut self, request_id: LSPSRequestId, request: LSPS1Request,
	) -> Result<(), PeerStateError> {
		if self.pending_requests.contains_key(&request_id) {
			return Err(PeerStateError::DuplicateRequestId);
		}
		self.pending_requests.insert(request_id, request);
		Ok(())
	}

	pub(super) fn remove_request(
		&mut self, request_id: &LSPSRequestId,
	) -> Result<LSPS1Request, PeerStateError> {
		self.pending_requests.remove(request_id).ok_or(PeerStateError::UnknownRequestId)
	}

	pub(super) fn pending_request_count(&self) -> usize {
		self.pending_requests.len()
	}

	pub(super) fn pending_requests_and_unpaid_orders(&self) -> usize {
		let pending_requests = self.pending_requests.len();
		// We exclude paid and completed orders.
		let unpaid_orders = self
			.outbound_channels_by_order_id
			.iter()
			.filter(|(_, v)| {
				!matches!(
					v.state,
					ChannelOrderState::OrderPaid { .. }
						| ChannelOrderState::CompletedAndChannelOpened { .. }
				)
			})
			.count();
		pending_requests + unpaid_orders
	}

	pub(super) fn has_active_requests(&self) -> bool {
		!self.outbound_channels_by_order_id.is_empty()
	}

	pub(super) fn needs_persist(&self) -> bool {
		self.needs_persist
	}

	pub(super) fn set_needs_persist(&mut self, needs_persist: bool) {
		self.needs_persist = needs_persist;
	}

	pub(super) fn is_prunable(&self) -> bool {
		// Return whether the entire state is empty.
		self.pending_requests.is_empty() && self.outbound_channels_by_order_id.is_empty()
	}

	pub(super) fn prune_pending_requests(&mut self) -> usize {
		let num_pruned = self.pending_requests.len();
		self.pending_requests.clear();
		num_pruned
	}

	pub(super) fn prune_expired_request_state(&mut self) {
		self.outbound_channels_by_order_id.retain(|_order_id, entry| {
			if entry.is_prunable() {
				self.needs_persist |= true;
				return false;
			}
			true
		});
	}
}

impl_writeable_tlv_based!(PeerState, {
	(0, outbound_channels_by_order_id, required),
	(_unused, pending_requests, (static_value, new_hash_map())),
	(_unused, needs_persist, (static_value, false)),
});

#[derive(Debug, Clone)]
pub(super) enum PeerStateError {
	UnknownRequestId,
	DuplicateRequestId,
	UnknownOrderId,
	InvalidStateTransition(ChannelOrderStateError),
}

impl fmt::Display for PeerStateError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::UnknownRequestId => write!(f, "unknown request id"),
			Self::DuplicateRequestId => write!(f, "duplicate request id"),
			Self::UnknownOrderId => write!(f, "unknown order id"),
			Self::InvalidStateTransition(e) => write!(f, "{}", e),
		}
	}
}

#[derive(Debug, Clone)]
pub(super) struct ChannelOrder {
	pub(super) order_params: LSPS1OrderParams,
	pub(super) state: ChannelOrderState,
	pub(super) created_at: LSPSDateTime,
}

impl ChannelOrder {
	/// Returns the order state.
	pub(super) fn order_state(&self) -> LSPS1OrderState {
		self.state.order_state()
	}

	/// Returns the payment details.
	pub(super) fn payment_details(&self) -> &LSPS1PaymentInfo {
		self.state.payment_details()
	}

	/// Returns the channel details if the channel has been opened.
	pub(super) fn channel_details(&self) -> Option<&LSPS1ChannelInfo> {
		self.state.channel_info()
	}

	fn is_prunable(&self) -> bool {
		let all_payment_details_expired;
		#[cfg(feature = "time")]
		{
			let details = self.state.payment_details();
			all_payment_details_expired =
				details.bolt11.as_ref().map_or(true, |d| d.expires_at.is_past())
					&& details.bolt12.as_ref().map_or(true, |d| d.expires_at.is_past())
					&& details.onchain.as_ref().map_or(true, |d| d.expires_at.is_past());
		}
		#[cfg(not(feature = "time"))]
		{
			// TODO: We need to find a way to check expiry times in no-std builds.
			all_payment_details_expired = false;
		}

		let created_or_failed = matches!(
			self.state,
			ChannelOrderState::ExpectingPayment { .. }
				| ChannelOrderState::FailedAndRefunded { .. }
		);

		all_payment_details_expired && created_or_failed
	}
}

impl_writeable_tlv_based!(ChannelOrder, {
	(0, order_params, required),
	(2, state, required),
	(4, created_at, required),
});

#[cfg(test)]
mod tests {
	use super::*;
	use crate::lsps0::ser::LSPSDateTime;
	use crate::lsps1::msgs::{LSPS1Bolt11PaymentInfo, LSPS1OnchainPaymentInfo, LSPS1PaymentState};

	use bitcoin::{Address, FeeRate, OutPoint};
	use lightning_invoice::Bolt11Invoice;

	use core::str::FromStr;

	fn create_test_bolt11_payment_info() -> LSPS1Bolt11PaymentInfo {
		let invoice_str = "lnbc252u1p3aht9ysp580g4633gd2x9lc5al0wd8wx0mpn9748jeyz46kqjrpxn52uhfpjqpp5qgf67tcqmuqehzgjm8mzya90h73deafvr4m5705l5u5l4r05l8cqdpud3h8ymm4w3jhytnpwpczqmt0de6xsmre2pkxzm3qydmkzdjrdev9s7zhgfaqxqyjw5qcqpjrzjqt6xptnd85lpqnu2lefq4cx070v5cdwzh2xlvmdgnu7gqp4zvkus5zapryqqx9qqqyqqqqqqqqqqqcsq9q9qyysgqen77vu8xqjelum24hgjpgfdgfgx4q0nehhalcmuggt32japhjuksq9jv6eksjfnppm4hrzsgyxt8y8xacxut9qv3fpyetz8t7tsymygq8yzn05";
		LSPS1Bolt11PaymentInfo {
			state: LSPS1PaymentState::ExpectPayment,
			expires_at: LSPSDateTime::from_str("2035-01-01T00:00:00Z").unwrap(),
			fee_total_sat: 9999,
			order_total_sat: 200999,
			invoice: Bolt11Invoice::from_str(invoice_str).unwrap(),
		}
	}

	fn create_test_onchain_payment_info() -> LSPS1OnchainPaymentInfo {
		LSPS1OnchainPaymentInfo {
			state: LSPS1PaymentState::ExpectPayment,
			expires_at: LSPSDateTime::from_str("2035-01-01T00:00:00Z").unwrap(),
			fee_total_sat: 9999,
			order_total_sat: 200999,
			address: Address::from_str(
				"bc1p5uvtaxzkjwvey2tfy49k5vtqfpjmrgm09cvs88ezyy8h2zv7jhas9tu4yr",
			)
			.unwrap()
			.assume_checked(),
			min_onchain_payment_confirmations: Some(1),
			min_fee_for_0conf: FeeRate::from_sat_per_vb(253).unwrap(),
			refund_onchain_address: None,
		}
	}

	fn create_test_payment_info_bolt11_only() -> LSPS1PaymentInfo {
		LSPS1PaymentInfo {
			bolt11: Some(create_test_bolt11_payment_info()),
			bolt12: None,
			onchain: None,
		}
	}

	fn create_test_payment_info_onchain_only() -> LSPS1PaymentInfo {
		LSPS1PaymentInfo {
			bolt11: None,
			bolt12: None,
			onchain: Some(create_test_onchain_payment_info()),
		}
	}

	fn create_test_channel_info() -> LSPS1ChannelInfo {
		LSPS1ChannelInfo {
			funded_at: LSPSDateTime::from_str("2035-01-01T00:00:00Z").unwrap(),
			funding_outpoint: OutPoint::from_str(
				"0301e0480b374b32851a9462db29dc19fe830a7f7d7a88b81612b9d42099c0ae:0",
			)
			.unwrap(),
			expires_at: LSPSDateTime::from_str("2036-01-01T00:00:00Z").unwrap(),
		}
	}

	// Test valid transition: ExpectingPayment -> OrderPaid via payment_received (Bolt11)
	#[test]
	fn test_payment_received_bolt11() {
		let payment_info = create_test_payment_info_bolt11_only();
		let mut state = ChannelOrderState::new(payment_info);

		assert!(matches!(state, ChannelOrderState::ExpectingPayment { .. }));
		assert_eq!(state.order_state(), LSPS1OrderState::Created);

		state.payment_received(PaymentMethod::Bolt11).unwrap();

		assert!(matches!(state, ChannelOrderState::OrderPaid { .. }));
		assert_eq!(state.order_state(), LSPS1OrderState::Created);
		// Payment state should be HOLD (not PAID) until channel is opened
		assert_eq!(state.payment_details().bolt11.as_ref().unwrap().state, LSPS1PaymentState::Hold);
	}

	// Test valid transition: ExpectingPayment -> OrderPaid via payment_received (Onchain)
	#[test]
	fn test_payment_received_onchain() {
		let payment_info = create_test_payment_info_onchain_only();
		let mut state = ChannelOrderState::new(payment_info);

		state.payment_received(PaymentMethod::Onchain).unwrap();

		assert!(matches!(state, ChannelOrderState::OrderPaid { .. }));
		// Payment state should be HOLD (not PAID) until channel is opened
		assert_eq!(
			state.payment_details().onchain.as_ref().unwrap().state,
			LSPS1PaymentState::Hold
		);
	}

	// Test valid transition: OrderPaid -> CompletedAndChannelOpened via channel_opened
	#[test]
	fn test_channel_opened() {
		let payment_info = create_test_payment_info_bolt11_only();
		let mut state = ChannelOrderState::new(payment_info);
		state.payment_received(PaymentMethod::Bolt11).unwrap();

		// Verify payment state is HOLD before channel opens
		assert_eq!(state.payment_details().bolt11.as_ref().unwrap().state, LSPS1PaymentState::Hold);

		let channel_info = create_test_channel_info();
		state.channel_opened(channel_info.clone()).unwrap();

		assert!(matches!(state, ChannelOrderState::CompletedAndChannelOpened { .. }));
		assert_eq!(state.order_state(), LSPS1OrderState::Completed);
		assert_eq!(state.channel_info(), Some(&channel_info));
		// Payment state should now be PAID after channel is opened
		assert_eq!(state.payment_details().bolt11.as_ref().unwrap().state, LSPS1PaymentState::Paid);
	}

	// Test valid transition: ExpectingPayment -> FailedAndRefunded
	#[test]
	fn test_mark_failed_from_expecting_payment() {
		let payment_info = create_test_payment_info_bolt11_only();
		let mut state = ChannelOrderState::new(payment_info);

		state.mark_failed_and_refunded().unwrap();

		assert!(matches!(state, ChannelOrderState::FailedAndRefunded { .. }));
		assert_eq!(state.order_state(), LSPS1OrderState::Failed);
		assert_eq!(
			state.payment_details().bolt11.as_ref().unwrap().state,
			LSPS1PaymentState::Refunded
		);
	}

	// Test valid transition: OrderPaid -> FailedAndRefunded
	#[test]
	fn test_mark_failed_from_order_paid() {
		let payment_info = create_test_payment_info_bolt11_only();
		let mut state = ChannelOrderState::new(payment_info);
		state.payment_received(PaymentMethod::Bolt11).unwrap();

		// Verify payment state is HOLD before failure
		assert_eq!(state.payment_details().bolt11.as_ref().unwrap().state, LSPS1PaymentState::Hold);

		state.mark_failed_and_refunded().unwrap();

		assert!(matches!(state, ChannelOrderState::FailedAndRefunded { .. }));
		assert_eq!(state.order_state(), LSPS1OrderState::Failed);
		// Payment state should now be REFUNDED
		assert_eq!(
			state.payment_details().bolt11.as_ref().unwrap().state,
			LSPS1PaymentState::Refunded
		);
	}

	// Test invalid transition: payment_received from OrderPaid
	#[test]
	fn test_payment_received_from_order_paid_fails() {
		let payment_info = create_test_payment_info_bolt11_only();
		let mut state = ChannelOrderState::new(payment_info);
		state.payment_received(PaymentMethod::Bolt11).unwrap();

		let result = state.payment_received(PaymentMethod::Bolt11);
		assert!(matches!(result, Err(ChannelOrderStateError::InvalidStateTransition { .. })));
	}

	// Test invalid transition: payment_received from CompletedAndChannelOpened
	#[test]
	fn test_payment_received_from_completed_fails() {
		let payment_info = create_test_payment_info_bolt11_only();
		let mut state = ChannelOrderState::new(payment_info);
		state.payment_received(PaymentMethod::Bolt11).unwrap();
		state.channel_opened(create_test_channel_info()).unwrap();

		let result = state.payment_received(PaymentMethod::Bolt11);
		assert!(matches!(result, Err(ChannelOrderStateError::InvalidStateTransition { .. })));
	}

	// Test invalid transition: payment_received from FailedAndRefunded
	#[test]
	fn test_payment_received_from_failed_fails() {
		let payment_info = create_test_payment_info_bolt11_only();
		let mut state = ChannelOrderState::new(payment_info);
		state.mark_failed_and_refunded().unwrap();

		let result = state.payment_received(PaymentMethod::Bolt11);
		assert!(matches!(result, Err(ChannelOrderStateError::InvalidStateTransition { .. })));
	}

	// Test invalid transition: channel_opened from ExpectingPayment
	#[test]
	fn test_channel_opened_from_expecting_payment_fails() {
		let payment_info = create_test_payment_info_bolt11_only();
		let mut state = ChannelOrderState::new(payment_info);

		let result = state.channel_opened(create_test_channel_info());
		assert!(matches!(result, Err(ChannelOrderStateError::InvalidStateTransition { .. })));
	}

	// Test invalid transition: channel_opened from CompletedAndChannelOpened
	#[test]
	fn test_channel_opened_from_completed_fails() {
		let payment_info = create_test_payment_info_bolt11_only();
		let mut state = ChannelOrderState::new(payment_info);
		state.payment_received(PaymentMethod::Bolt11).unwrap();
		state.channel_opened(create_test_channel_info()).unwrap();

		let result = state.channel_opened(create_test_channel_info());
		assert!(matches!(result, Err(ChannelOrderStateError::InvalidStateTransition { .. })));
	}

	// Test invalid transition: channel_opened from FailedAndRefunded
	#[test]
	fn test_channel_opened_from_failed_fails() {
		let payment_info = create_test_payment_info_bolt11_only();
		let mut state = ChannelOrderState::new(payment_info);
		state.mark_failed_and_refunded().unwrap();

		let result = state.channel_opened(create_test_channel_info());
		assert!(matches!(result, Err(ChannelOrderStateError::InvalidStateTransition { .. })));
	}

	// Test invalid transition: mark_failed_and_refunded from CompletedAndChannelOpened
	#[test]
	fn test_mark_failed_from_completed_fails() {
		let payment_info = create_test_payment_info_bolt11_only();
		let mut state = ChannelOrderState::new(payment_info);
		state.payment_received(PaymentMethod::Bolt11).unwrap();
		state.channel_opened(create_test_channel_info()).unwrap();

		let result = state.mark_failed_and_refunded();
		assert!(matches!(result, Err(ChannelOrderStateError::InvalidStateTransition { .. })));
	}

	// Test invalid transition: mark_failed_and_refunded from FailedAndRefunded
	#[test]
	fn test_mark_failed_from_failed_fails() {
		let payment_info = create_test_payment_info_bolt11_only();
		let mut state = ChannelOrderState::new(payment_info);
		state.mark_failed_and_refunded().unwrap();

		let result = state.mark_failed_and_refunded();
		assert!(matches!(result, Err(ChannelOrderStateError::InvalidStateTransition { .. })));
	}

	// Test error: payment_received with unconfigured payment method
	#[test]
	fn test_payment_received_unconfigured_method_fails() {
		// Create payment info with only onchain configured
		let payment_info = create_test_payment_info_onchain_only();
		let mut state = ChannelOrderState::new(payment_info);

		// Try to mark bolt11 as paid, which is not configured
		let result = state.payment_received(PaymentMethod::Bolt11);
		assert!(matches!(result, Err(ChannelOrderStateError::PaymentMethodNotConfigured)));

		// State should remain unchanged
		assert!(matches!(state, ChannelOrderState::ExpectingPayment { .. }));
	}

	// Test that channel_info is only available in CompletedAndChannelOpened state
	#[test]
	fn test_channel_info_availability() {
		let payment_info = create_test_payment_info_bolt11_only();
		let mut state = ChannelOrderState::new(payment_info);

		// Not available in ExpectingPayment
		assert!(state.channel_info().is_none());

		state.payment_received(PaymentMethod::Bolt11).unwrap();

		// Not available in OrderPaid
		assert!(state.channel_info().is_none());

		let channel_info = create_test_channel_info();
		state.channel_opened(channel_info.clone()).unwrap();

		// Available in CompletedAndChannelOpened
		assert_eq!(state.channel_info(), Some(&channel_info));
	}
}
