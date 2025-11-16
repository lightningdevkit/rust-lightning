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

#[derive(Default)]
pub(super) struct PeerState {
	outbound_channels_by_order_id: HashMap<LSPS1OrderId, OutboundCRChannel>,
	pub(super) pending_requests: HashMap<LSPSRequestId, LSPS1Request>,
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

	pub(super) fn has_active_requests(&self) -> bool {
		!self.outbound_channels_by_order_id.is_empty()
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
