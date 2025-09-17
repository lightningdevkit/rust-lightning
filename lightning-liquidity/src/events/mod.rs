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

use lightning::io;
use lightning::ln::msgs::DecodeError;
use lightning::util::ser::{
	BigSize, FixedLengthReader, MaybeReadable, Readable, Writeable, Writer,
};

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

impl Writeable for LiquidityEvent {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		match self {
			Self::LSPS0Client(_) => {
				// We'll always need to write something for `MaybeReadable`.
				0u8.write(writer)?;
			},
			Self::LSPS1Client(_) => {
				// We'll always need to write something for `MaybeReadable`.
				1u8.write(writer)?;
			},
			#[cfg(lsps1_service)]
			Self::LSPS1Service(_) => {
				// We'll always need to write something for `MaybeReadable`.
				2u8.write(writer)?;
			},
			Self::LSPS2Client(_) => {
				// We'll always need to write something for `MaybeReadable`.
				3u8.write(writer)?;
			},
			Self::LSPS2Service(event) => {
				4u8.write(writer)?;
				event.write(writer)?;
			},
			Self::LSPS5Client(_) => {
				// We'll always need to write something for `MaybeReadable`.
				5u8.write(writer)?;
			},
			Self::LSPS5Service(event) => {
				6u8.write(writer)?;
				event.write(writer)?;
			},
		}
		Ok(())
	}
}

impl MaybeReadable for LiquidityEvent {
	fn read<R: io::Read>(reader: &mut R) -> Result<Option<Self>, DecodeError> {
		match Readable::read(reader)? {
			0u8 => {
				// LSPS0ClientEvents are not persisted.
				Ok(None)
			},
			1u8 => {
				// LSPS1ClientEvents are not persisted.
				Ok(None)
			},
			2u8 => {
				// LSPS1ServiceEvents are not persisted.
				Ok(None)
			},
			3u8 => {
				// LSPS2ClientEvents are not persisted.
				Ok(None)
			},
			4u8 => {
				let event = Readable::read(reader)?;
				Ok(Some(LiquidityEvent::LSPS2Service(event)))
			},
			5u8 => {
				// LSPS5ClientEvents are not persisted.
				Ok(None)
			},
			6u8 => {
				let event = Readable::read(reader)?;
				Ok(Some(LiquidityEvent::LSPS5Service(event)))
			},
			x if x % 2 == 1 => {
				// If the event is of unknown type, assume it was written with `write_tlv_fields`,
				// which prefixes the whole thing with a length BigSize. Because the event is
				// odd-type unknown, we should treat it as `Ok(None)` even if it has some TLV
				// fields that are even. Thus, we avoid using `read_tlv_fields` and simply read
				// exactly the number of bytes specified, ignoring them entirely.
				let tlv_len: BigSize = Readable::read(reader)?;
				FixedLengthReader::new(reader, tlv_len.0)
					.eat_remaining()
					.map_err(|_| DecodeError::ShortRead)?;
				Ok(None)
			},
			_ => Err(DecodeError::InvalidValue),
		}
	}
}
