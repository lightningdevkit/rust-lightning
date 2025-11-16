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

use lightning::ln::msgs::{ErrorAction, LightningError};
use lightning::util::logger::Level;

#[derive(Default)]
pub(super) struct PeerState {
	pub(super) outbound_channels_by_order_id: HashMap<LSPS1OrderId, OutboundCRChannel>,
	pub(super) pending_requests: HashMap<LSPSRequestId, LSPS1Request>,
}

impl PeerState {
	pub(super) fn insert_outbound_channel(
		&mut self, order_id: LSPS1OrderId, channel: OutboundCRChannel,
	) {
		self.outbound_channels_by_order_id.insert(order_id, channel);
	}
}

struct ChannelStateError(String);

impl From<ChannelStateError> for LightningError {
	fn from(value: ChannelStateError) -> Self {
		LightningError { err: value.0, action: ErrorAction::IgnoreAndLog(Level::Info) }
	}
}

#[derive(PartialEq, Debug)]
pub(super) enum OutboundRequestState {
	OrderCreated { order_id: LSPS1OrderId },
	WaitingPayment { order_id: LSPS1OrderId },
}

impl OutboundRequestState {
	fn awaiting_payment(&self) -> Result<Self, ChannelStateError> {
		match self {
			OutboundRequestState::OrderCreated { order_id } => {
				Ok(OutboundRequestState::WaitingPayment { order_id: order_id.clone() })
			},
			state => Err(ChannelStateError(format!("TODO. JIT Channel was in state: {:?}", state))),
		}
	}
}

pub(super) struct OutboundLSPS1Config {
	pub(super) order: LSPS1OrderParams,
	pub(super) created_at: LSPSDateTime,
	pub(super) payment: LSPS1PaymentInfo,
}

pub(super) struct OutboundCRChannel {
	pub(super) state: OutboundRequestState,
	pub(super) config: OutboundLSPS1Config,
}

impl OutboundCRChannel {
	pub(super) fn new(
		order: LSPS1OrderParams, created_at: LSPSDateTime, order_id: LSPS1OrderId,
		payment: LSPS1PaymentInfo,
	) -> Self {
		Self {
			state: OutboundRequestState::OrderCreated { order_id },
			config: OutboundLSPS1Config { order, created_at, payment },
		}
	}
	pub(super) fn awaiting_payment(&mut self) -> Result<(), LightningError> {
		self.state = self.state.awaiting_payment()?;
		Ok(())
	}
}
