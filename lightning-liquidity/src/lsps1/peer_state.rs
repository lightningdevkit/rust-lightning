// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Contains peer state objects that are used by `LSPS1ServiceHandler`.

use super::msgs::{LSPS1OrderId, LSPS1OrderParams, LSPS1PaymentInfo, LSPS1Request};

use crate::lsps0::ser::{LSPSDateTime, LSPSRequestId};
use crate::prelude::HashMap;

use core::fmt;

#[derive(Default)]
pub(super) struct PeerState {
	outbound_channels_by_order_id: HashMap<LSPS1OrderId, OutboundCRChannel>,
	pending_requests: HashMap<LSPSRequestId, LSPS1Request>,
}

impl PeerState {
	pub(super) fn new_order(
		&mut self, order_id: LSPS1OrderId, order_params: LSPS1OrderParams,
		created_at: LSPSDateTime, payment_details: LSPS1PaymentInfo,
	) {
		let channel = OutboundCRChannel::new(order_params, created_at, payment_details);
		self.outbound_channels_by_order_id.insert(order_id, channel);
	}

	pub(super) fn get_order<'a>(&'a self, order_id: &LSPS1OrderId) -> Option<&'a ChannelOrder> {
		self.outbound_channels_by_order_id.get(order_id).map(|channel| &channel.order)
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

#[derive(Debug, Copy, Clone)]
pub(super) enum PeerStateError {
	UnknownRequestId,
	DuplicateRequestId,
}

impl fmt::Display for PeerStateError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::UnknownRequestId => write!(f, "unknown request id"),
			Self::DuplicateRequestId => write!(f, "duplicate request id"),
		}
	}
}

pub(super) struct ChannelOrder {
	pub(super) order_params: LSPS1OrderParams,
	pub(super) created_at: LSPSDateTime,
	pub(super) payment_details: LSPS1PaymentInfo,
}

struct OutboundCRChannel {
	order: ChannelOrder,
}

impl OutboundCRChannel {
	fn new(
		order_params: LSPS1OrderParams, created_at: LSPSDateTime, payment_details: LSPS1PaymentInfo,
	) -> Self {
		Self { order: ChannelOrder { order_params, created_at, payment_details } }
	}
}
