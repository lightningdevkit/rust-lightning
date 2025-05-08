// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Events are surfaced by the library to indicate some action must be taken
//! by the end-user.
//!
//! Because we don't have a built-in runtime, it's up to the end-user to poll
//! [`LiquidityManager::get_and_clear_pending_events`] to receive events.
//!
//! [`LiquidityManager::get_and_clear_pending_events`]: crate::LiquidityManager::get_and_clear_pending_events

mod event_queue;

pub(crate) use event_queue::EventQueue;
pub use event_queue::MAX_EVENT_QUEUE_SIZE;

use crate::lsps0;
use crate::lsps1;
use crate::lsps2;
use crate::lsps5;

/// An event which you should probably take some action in response to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LiquidityEvent {
	/// An LSPS0 client event.
	LSPS0Client(lsps0::event::LSPS0ClientEvent),
	/// An LSPS1 (Channel Request) client event.
	LSPS1Client(lsps1::event::LSPS1ClientEvent),
	/// An LSPS1 (Channel Request) server event.
	#[cfg(lsps1_service)]
	LSPS1Service(lsps1::event::LSPS1ServiceEvent),
	/// An LSPS2 (JIT Channel) client event.
	LSPS2Client(lsps2::event::LSPS2ClientEvent),
	/// An LSPS2 (JIT Channel) server event.
	LSPS2Service(lsps2::event::LSPS2ServiceEvent),
	/// An LSPS5 (Webhook) client event.
	LSPS5Client(lsps5::event::LSPS5ClientEvent),
	/// An LSPS5 (Webhook) server event.
	LSPS5Service(lsps5::event::LSPS5ServiceEvent),
}

impl From<lsps0::event::LSPS0ClientEvent> for LiquidityEvent {
	fn from(event: lsps0::event::LSPS0ClientEvent) -> Self {
		Self::LSPS0Client(event)
	}
}

impl From<lsps1::event::LSPS1ClientEvent> for LiquidityEvent {
	fn from(event: lsps1::event::LSPS1ClientEvent) -> Self {
		Self::LSPS1Client(event)
	}
}

#[cfg(lsps1_service)]
impl From<lsps1::event::LSPS1ServiceEvent> for LiquidityEvent {
	fn from(event: lsps1::event::LSPS1ServiceEvent) -> Self {
		Self::LSPS1Service(event)
	}
}

impl From<lsps2::event::LSPS2ClientEvent> for LiquidityEvent {
	fn from(event: lsps2::event::LSPS2ClientEvent) -> Self {
		Self::LSPS2Client(event)
	}
}

impl From<lsps2::event::LSPS2ServiceEvent> for LiquidityEvent {
	fn from(event: lsps2::event::LSPS2ServiceEvent) -> Self {
		Self::LSPS2Service(event)
	}
}

impl From<lsps5::event::LSPS5ClientEvent> for LiquidityEvent {
	fn from(event: lsps5::event::LSPS5ClientEvent) -> Self {
		Self::LSPS5Client(event)
	}
}

impl From<lsps5::event::LSPS5ServiceEvent> for LiquidityEvent {
	fn from(event: lsps5::event::LSPS5ServiceEvent) -> Self {
		Self::LSPS5Service(event)
	}
}
