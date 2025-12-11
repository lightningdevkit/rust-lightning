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
	LSPS1Request,
};

use crate::lsps0::ser::{LSPSDateTime, LSPSRequestId};
use crate::prelude::HashMap;

use lightning::impl_writeable_tlv_based;
use lightning::util::hash_tables::new_hash_map;

use core::fmt;

#[derive(Default)]
pub(super) struct PeerState {
	outbound_channels_by_order_id: HashMap<LSPS1OrderId, ChannelOrder>,
	pending_requests: HashMap<LSPSRequestId, LSPS1Request>,
}

impl PeerState {
	pub(super) fn new_order(
		&mut self, order_id: LSPS1OrderId, order_params: LSPS1OrderParams,
		created_at: LSPSDateTime, payment_details: LSPS1PaymentInfo,
	) -> ChannelOrder {
		let order_state = LSPS1OrderState::Created;
		let channel_details = None;
		let channel_order = ChannelOrder {
			order_params,
			order_state,
			created_at,
			payment_details,
			channel_details,
		};
		self.outbound_channels_by_order_id.insert(order_id, channel_order.clone());
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

	pub(super) fn update_order<'a>(
		&'a mut self, order_id: &LSPS1OrderId, order_state: LSPS1OrderState,
		channel_details: Option<LSPS1ChannelInfo>,
	) -> Result<(), PeerStateError> {
		let order = self
			.outbound_channels_by_order_id
			.get_mut(order_id)
			.ok_or(PeerStateError::UnknownOrderId)?;
		order.order_state = order_state;
		order.channel_details = channel_details;
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

	pub(super) fn has_active_requests(&self) -> bool {
		!self.outbound_channels_by_order_id.is_empty()
	}
}

impl_writeable_tlv_based!(PeerState, {
	(0, outbound_channels_by_order_id, required),
	(_unused, pending_requests, (static_value, new_hash_map())),
});

#[derive(Debug, Copy, Clone)]
pub(super) enum PeerStateError {
	UnknownRequestId,
	DuplicateRequestId,
	UnknownOrderId,
}

impl fmt::Display for PeerStateError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::UnknownRequestId => write!(f, "unknown request id"),
			Self::DuplicateRequestId => write!(f, "duplicate request id"),
			Self::UnknownOrderId => write!(f, "unknown order id"),
		}
	}
}

#[derive(Debug, Clone)]
pub(super) struct ChannelOrder {
	pub(super) order_params: LSPS1OrderParams,
	pub(super) order_state: LSPS1OrderState,
	pub(super) created_at: LSPSDateTime,
	pub(super) payment_details: LSPS1PaymentInfo,
	pub(super) channel_details: Option<LSPS1ChannelInfo>,
}

impl_writeable_tlv_based!(ChannelOrder, {
	(0, order_params, required),
	(2, order_state, required),
	(4, created_at, required),
	(6, payment_details, required),
	(8, channel_details, option),
});
