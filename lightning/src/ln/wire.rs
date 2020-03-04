//! Wire encoding/decoding for Lightning messages according to [BOLT #1].
//!
//! Messages known by this module can be read from the wire using [`read`].
//! The [`Message`] enum returned by [`read`] wraps the decoded message or the message type (if
//! unknown) to use with pattern matching.
//!
//! Messages implementing the [`Encode`] trait define a message type and can be sent over the wire
//! using [`write`].
//!
//! [BOLT #1]: https://github.com/lightningnetwork/lightning-rfc/blob/master/01-messaging.md
//! [`read`]: fn.read.html
//! [`write`]: fn.write.html
//! [`Encode`]: trait.Encode.html
//! [`Message`]: enum.Message.html

use ln::msgs;
use util::ser::{Readable, Writeable, Writer};

/// A Lightning message returned by [`read`] when decoding bytes received over the wire. Each
/// variant contains a message from [`ln::msgs`] or otherwise the message type if unknown.
///
/// [`read`]: fn.read.html
/// [`ln::msgs`]: ../msgs/index.html
#[allow(missing_docs)]
pub enum Message {
	Init(msgs::Init),
	Error(msgs::ErrorMessage),
	Ping(msgs::Ping),
	Pong(msgs::Pong),
	OpenChannel(msgs::OpenChannel),
	AcceptChannel(msgs::AcceptChannel),
	FundingCreated(msgs::FundingCreated),
	FundingSigned(msgs::FundingSigned),
	FundingLocked(msgs::FundingLocked),
	Shutdown(msgs::Shutdown),
	ClosingSigned(msgs::ClosingSigned),
	UpdateAddHTLC(msgs::UpdateAddHTLC),
	UpdateFulfillHTLC(msgs::UpdateFulfillHTLC),
	UpdateFailHTLC(msgs::UpdateFailHTLC),
	UpdateFailMalformedHTLC(msgs::UpdateFailMalformedHTLC),
	CommitmentSigned(msgs::CommitmentSigned),
	RevokeAndACK(msgs::RevokeAndACK),
	UpdateFee(msgs::UpdateFee),
	ChannelReestablish(msgs::ChannelReestablish),
	AnnouncementSignatures(msgs::AnnouncementSignatures),
	ChannelAnnouncement(msgs::ChannelAnnouncement),
	NodeAnnouncement(msgs::NodeAnnouncement),
	ChannelUpdate(msgs::ChannelUpdate),
	/// A message that could not be decoded because its type is unknown.
	Unknown(MessageType),
}

/// A number identifying a message to determine how it is encoded on the wire.
#[derive(Clone, Copy)]
pub struct MessageType(u16);

impl Message {
	/// Returns the type that was used to decode the message payload.
	pub fn type_id(&self) -> MessageType {
		match self {
			&Message::Init(ref msg) => msg.type_id(),
			&Message::Error(ref msg) => msg.type_id(),
			&Message::Ping(ref msg) => msg.type_id(),
			&Message::Pong(ref msg) => msg.type_id(),
			&Message::OpenChannel(ref msg) => msg.type_id(),
			&Message::AcceptChannel(ref msg) => msg.type_id(),
			&Message::FundingCreated(ref msg) => msg.type_id(),
			&Message::FundingSigned(ref msg) => msg.type_id(),
			&Message::FundingLocked(ref msg) => msg.type_id(),
			&Message::Shutdown(ref msg) => msg.type_id(),
			&Message::ClosingSigned(ref msg) => msg.type_id(),
			&Message::UpdateAddHTLC(ref msg) => msg.type_id(),
			&Message::UpdateFulfillHTLC(ref msg) => msg.type_id(),
			&Message::UpdateFailHTLC(ref msg) => msg.type_id(),
			&Message::UpdateFailMalformedHTLC(ref msg) => msg.type_id(),
			&Message::CommitmentSigned(ref msg) => msg.type_id(),
			&Message::RevokeAndACK(ref msg) => msg.type_id(),
			&Message::UpdateFee(ref msg) => msg.type_id(),
			&Message::ChannelReestablish(ref msg) => msg.type_id(),
			&Message::AnnouncementSignatures(ref msg) => msg.type_id(),
			&Message::ChannelAnnouncement(ref msg) => msg.type_id(),
			&Message::NodeAnnouncement(ref msg) => msg.type_id(),
			&Message::ChannelUpdate(ref msg) => msg.type_id(),
			&Message::Unknown(type_id) => type_id,
		}
	}
}

impl MessageType {
	/// Returns whether the message type is even, indicating both endpoints must support it.
	pub fn is_even(&self) -> bool {
		(self.0 & 1) == 0
	}
}

impl ::std::fmt::Display for MessageType {
	fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
		write!(f, "{}", self.0)
	}
}

/// Reads a message from the data buffer consisting of a 2-byte big-endian type and a
/// variable-length payload conforming to the type.
///
/// # Errors
///
/// Returns an error if the message payload code not be decoded as the specified type.
pub fn read<R: ::std::io::Read>(buffer: &mut R) -> Result<Message, msgs::DecodeError> {
	let message_type = <u16 as Readable>::read(buffer)?;
	match message_type {
		msgs::Init::TYPE => {
			Ok(Message::Init(Readable::read(buffer)?))
		},
		msgs::ErrorMessage::TYPE => {
			Ok(Message::Error(Readable::read(buffer)?))
		},
		msgs::Ping::TYPE => {
			Ok(Message::Ping(Readable::read(buffer)?))
		},
		msgs::Pong::TYPE => {
			Ok(Message::Pong(Readable::read(buffer)?))
		},
		msgs::OpenChannel::TYPE => {
			Ok(Message::OpenChannel(Readable::read(buffer)?))
		},
		msgs::AcceptChannel::TYPE => {
			Ok(Message::AcceptChannel(Readable::read(buffer)?))
		},
		msgs::FundingCreated::TYPE => {
			Ok(Message::FundingCreated(Readable::read(buffer)?))
		},
		msgs::FundingSigned::TYPE => {
			Ok(Message::FundingSigned(Readable::read(buffer)?))
		},
		msgs::FundingLocked::TYPE => {
			Ok(Message::FundingLocked(Readable::read(buffer)?))
		},
		msgs::Shutdown::TYPE => {
			Ok(Message::Shutdown(Readable::read(buffer)?))
		},
		msgs::ClosingSigned::TYPE => {
			Ok(Message::ClosingSigned(Readable::read(buffer)?))
		},
		msgs::UpdateAddHTLC::TYPE => {
			Ok(Message::UpdateAddHTLC(Readable::read(buffer)?))
		},
		msgs::UpdateFulfillHTLC::TYPE => {
			Ok(Message::UpdateFulfillHTLC(Readable::read(buffer)?))
		},
		msgs::UpdateFailHTLC::TYPE => {
			Ok(Message::UpdateFailHTLC(Readable::read(buffer)?))
		},
		msgs::UpdateFailMalformedHTLC::TYPE => {
			Ok(Message::UpdateFailMalformedHTLC(Readable::read(buffer)?))
		},
		msgs::CommitmentSigned::TYPE => {
			Ok(Message::CommitmentSigned(Readable::read(buffer)?))
		},
		msgs::RevokeAndACK::TYPE => {
			Ok(Message::RevokeAndACK(Readable::read(buffer)?))
		},
		msgs::UpdateFee::TYPE => {
			Ok(Message::UpdateFee(Readable::read(buffer)?))
		},
		msgs::ChannelReestablish::TYPE => {
			Ok(Message::ChannelReestablish(Readable::read(buffer)?))
		},
		msgs::AnnouncementSignatures::TYPE => {
			Ok(Message::AnnouncementSignatures(Readable::read(buffer)?))
		},
		msgs::ChannelAnnouncement::TYPE => {
			Ok(Message::ChannelAnnouncement(Readable::read(buffer)?))
		},
		msgs::NodeAnnouncement::TYPE => {
			Ok(Message::NodeAnnouncement(Readable::read(buffer)?))
		},
		msgs::ChannelUpdate::TYPE => {
			Ok(Message::ChannelUpdate(Readable::read(buffer)?))
		},
		_ => {
			Ok(Message::Unknown(MessageType(message_type)))
		},
	}
}

/// Writes a message to the data buffer encoded as a 2-byte big-endian type and a variable-length
/// payload.
///
/// # Errors
///
/// Returns an I/O error if the write could not be completed.
pub fn write<M: Encode + Writeable, W: Writer>(message: &M, buffer: &mut W) -> Result<(), ::std::io::Error> {
	M::TYPE.write(buffer)?;
	message.write(buffer)
}

/// Defines a type-identified encoding for sending messages over the wire.
///
/// Messages implementing this trait specify a type and must be [`Writeable`] to use with [`write`].
///
/// [`Writeable`]: ../../util/ser/trait.Writeable.html
/// [`write`]: fn.write.html
pub trait Encode {
	/// The type identifying the message payload.
	const TYPE: u16;

	/// Returns the type identifying the message payload. Convenience method for accessing
	/// [`TYPE`](TYPE).
	fn type_id(&self) -> MessageType {
		MessageType(Self::TYPE)
	}
}

impl Encode for msgs::Init {
	const TYPE: u16 = 16;
}

impl Encode for msgs::ErrorMessage {
	const TYPE: u16 = 17;
}

impl Encode for msgs::Ping {
	const TYPE: u16 = 18;
}

impl Encode for msgs::Pong {
	const TYPE: u16 = 19;
}

impl Encode for msgs::OpenChannel {
	const TYPE: u16 = 32;
}

impl Encode for msgs::AcceptChannel {
	const TYPE: u16 = 33;
}

impl Encode for msgs::FundingCreated {
	const TYPE: u16 = 34;
}

impl Encode for msgs::FundingSigned {
	const TYPE: u16 = 35;
}

impl Encode for msgs::FundingLocked {
	const TYPE: u16 = 36;
}

impl Encode for msgs::Shutdown {
	const TYPE: u16 = 38;
}

impl Encode for msgs::ClosingSigned {
	const TYPE: u16 = 39;
}

impl Encode for msgs::UpdateAddHTLC {
	const TYPE: u16 = 128;
}

impl Encode for msgs::UpdateFulfillHTLC {
	const TYPE: u16 = 130;
}

impl Encode for msgs::UpdateFailHTLC {
	const TYPE: u16 = 131;
}

impl Encode for msgs::UpdateFailMalformedHTLC {
	const TYPE: u16 = 135;
}

impl Encode for msgs::CommitmentSigned {
	const TYPE: u16 = 132;
}

impl Encode for msgs::RevokeAndACK {
	const TYPE: u16 = 133;
}

impl Encode for msgs::UpdateFee {
	const TYPE: u16 = 134;
}

impl Encode for msgs::ChannelReestablish {
	const TYPE: u16 = 136;
}

impl Encode for msgs::AnnouncementSignatures {
	const TYPE: u16 = 259;
}

impl Encode for msgs::ChannelAnnouncement {
	const TYPE: u16 = 256;
}

impl Encode for msgs::NodeAnnouncement {
	const TYPE: u16 = 257;
}

impl Encode for msgs::ChannelUpdate {
	const TYPE: u16 = 258;
}

#[cfg(test)]
mod tests {
	use super::*;
	use util::byte_utils;

	// Big-endian wire encoding of Pong message (type = 19, byteslen = 2).
	const ENCODED_PONG: [u8; 6] = [0u8, 19u8, 0u8, 2u8, 0u8, 0u8];

	#[test]
	fn read_empty_buffer() {
		let buffer = [];
		let mut reader = ::std::io::Cursor::new(buffer);
		assert!(read(&mut reader).is_err());
	}

	#[test]
	fn read_incomplete_type() {
		let buffer = &ENCODED_PONG[..1];
		let mut reader = ::std::io::Cursor::new(buffer);
		assert!(read(&mut reader).is_err());
	}

	#[test]
	fn read_empty_payload() {
		let buffer = &ENCODED_PONG[..2];
		let mut reader = ::std::io::Cursor::new(buffer);
		assert!(read(&mut reader).is_err());
	}

	#[test]
	fn read_invalid_message() {
		let buffer = &ENCODED_PONG[..4];
		let mut reader = ::std::io::Cursor::new(buffer);
		assert!(read(&mut reader).is_err());
	}

	#[test]
	fn read_known_message() {
		let buffer = &ENCODED_PONG[..];
		let mut reader = ::std::io::Cursor::new(buffer);
		let message = read(&mut reader).unwrap();
		match message {
			Message::Pong(_) => (),
			_ => panic!("Expected pong message; found message type: {}", message.type_id()),
		}
	}

	#[test]
	fn read_unknown_message() {
		let buffer = &byte_utils::be16_to_array(::std::u16::MAX);
		let mut reader = ::std::io::Cursor::new(buffer);
		let message = read(&mut reader).unwrap();
		match message {
			Message::Unknown(MessageType(::std::u16::MAX)) => (),
			_ => panic!("Expected message type {}; found: {}", ::std::u16::MAX, message.type_id()),
		}
	}

	#[test]
	fn write_message_with_type() {
		let message = msgs::Pong { byteslen: 2u16 };
		let mut buffer = Vec::new();
		assert!(write(&message, &mut buffer).is_ok());

		let type_length = ::std::mem::size_of::<u16>();
		let (type_bytes, payload_bytes) = buffer.split_at(type_length);
		assert_eq!(byte_utils::slice_to_be16(type_bytes), msgs::Pong::TYPE);
		assert_eq!(payload_bytes, &ENCODED_PONG[type_length..]);
	}

	#[test]
	fn read_message_encoded_with_write() {
		let message = msgs::Pong { byteslen: 2u16 };
		let mut buffer = Vec::new();
		assert!(write(&message, &mut buffer).is_ok());

		let mut reader = ::std::io::Cursor::new(buffer);
		let decoded_message = read(&mut reader).unwrap();
		match decoded_message {
			Message::Pong(msgs::Pong { byteslen: 2u16 }) => (),
			Message::Pong(msgs::Pong { byteslen }) => {
				panic!("Expected byteslen {}; found: {}", message.byteslen, byteslen);
			},
			_ => panic!("Expected pong message; found message type: {}", decoded_message.type_id()),
		}
	}

	#[test]
	fn is_even_message_type() {
		let message = Message::Unknown(MessageType(42));
		assert!(message.type_id().is_even());
	}

	#[test]
	fn is_odd_message_type() {
		let message = Message::Unknown(MessageType(43));
		assert!(!message.type_id().is_even());
	}
}
