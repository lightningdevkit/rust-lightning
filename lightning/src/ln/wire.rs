// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Wire encoding/decoding for Lightning messages according to [BOLT #1], and for
//! custom message through the [`CustomMessageReader`] trait.
//!
//! [BOLT #1]: https://github.com/lightning/bolts/blob/master/01-messaging.md

use crate::io;
use crate::ln::msgs;
use crate::util::ser::{Readable, Writeable, Writer};

/// Trait to be implemented by custom message (unrelated to the channel/gossip LN layers)
/// decoders.
pub trait CustomMessageReader {
	/// The type of the message decoded by the implementation.
	type CustomMessage: Type;
	/// Decodes a custom message to `CustomMessageType`. If the given message type is known to the
	/// implementation and the message could be decoded, must return `Ok(Some(message))`. If the
	/// message type is unknown to the implementation, must return `Ok(None)`. If a decoding error
	/// occur, must return `Err(DecodeError::X)` where `X` details the encountered error.
	fn read<R: io::Read>(&self, message_type: u16, buffer: &mut R) -> Result<Option<Self::CustomMessage>, msgs::DecodeError>;
}

// TestEq is a dummy trait which requires PartialEq when built in testing, and otherwise is
// blanket-implemented for all types.

#[cfg(test)]
pub trait TestEq : PartialEq {}
#[cfg(test)]
impl<T: PartialEq> TestEq for T {}

#[cfg(not(test))]
pub(crate) trait TestEq {}
#[cfg(not(test))]
impl<T> TestEq for T {}


/// A Lightning message returned by [`read`] when decoding bytes received over the wire. Each
/// variant contains a message from [`msgs`] or otherwise the message type if unknown.
#[allow(missing_docs)]
#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub(crate) enum Message<T> where T: core::fmt::Debug + Type + TestEq {
	Init(msgs::Init),
	Error(msgs::ErrorMessage),
	Warning(msgs::WarningMessage),
	Ping(msgs::Ping),
	Pong(msgs::Pong),
	PeerStorageMessage(msgs::PeerStorageMessage),
	YourPeerStorageMessage(msgs::YourPeerStorageMessage),
	OpenChannel(msgs::OpenChannel),
	OpenChannelV2(msgs::OpenChannelV2),
	AcceptChannel(msgs::AcceptChannel),
	AcceptChannelV2(msgs::AcceptChannelV2),
	FundingCreated(msgs::FundingCreated),
	FundingSigned(msgs::FundingSigned),
	Stfu(msgs::Stfu),
	#[cfg(splicing)]
	SpliceInit(msgs::SpliceInit),
	#[cfg(splicing)]
	SpliceAck(msgs::SpliceAck),
	#[cfg(splicing)]
	SpliceLocked(msgs::SpliceLocked),
	TxAddInput(msgs::TxAddInput),
	TxAddOutput(msgs::TxAddOutput),
	TxRemoveInput(msgs::TxRemoveInput),
	TxRemoveOutput(msgs::TxRemoveOutput),
	TxComplete(msgs::TxComplete),
	TxSignatures(msgs::TxSignatures),
	TxInitRbf(msgs::TxInitRbf),
	TxAckRbf(msgs::TxAckRbf),
	TxAbort(msgs::TxAbort),
	ChannelReady(msgs::ChannelReady),
	Shutdown(msgs::Shutdown),
	ClosingSigned(msgs::ClosingSigned),
	OnionMessage(msgs::OnionMessage),
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
	QueryShortChannelIds(msgs::QueryShortChannelIds),
	ReplyShortChannelIdsEnd(msgs::ReplyShortChannelIdsEnd),
	QueryChannelRange(msgs::QueryChannelRange),
	ReplyChannelRange(msgs::ReplyChannelRange),
	GossipTimestampFilter(msgs::GossipTimestampFilter),
	/// A message that could not be decoded because its type is unknown.
	Unknown(u16),
	/// A message that was produced by a [`CustomMessageReader`] and is to be handled by a
	/// [`crate::ln::peer_handler::CustomMessageHandler`].
	Custom(T),
}

impl<T> Writeable for Message<T> where T: core::fmt::Debug + Type + TestEq {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		match self {
			&Message::Init(ref msg) => msg.write(writer),
			&Message::Error(ref msg) => msg.write(writer),
			&Message::Warning(ref msg) => msg.write(writer),
			&Message::Ping(ref msg) => msg.write(writer),
			&Message::Pong(ref msg) => msg.write(writer),
			&Message::PeerStorageMessage(ref msg) => msg.write(writer),
			&Message::YourPeerStorageMessage(ref msg) => msg.write(writer),
			&Message::OpenChannel(ref msg) => msg.write(writer),
			&Message::OpenChannelV2(ref msg) => msg.write(writer),
			&Message::AcceptChannel(ref msg) => msg.write(writer),
			&Message::AcceptChannelV2(ref msg) => msg.write(writer),
			&Message::FundingCreated(ref msg) => msg.write(writer),
			&Message::FundingSigned(ref msg) => msg.write(writer),
			&Message::Stfu(ref msg) => msg.write(writer),
			#[cfg(splicing)]
			&Message::SpliceInit(ref msg) => msg.write(writer),
			#[cfg(splicing)]
			&Message::SpliceAck(ref msg) => msg.write(writer),
			#[cfg(splicing)]
			&Message::SpliceLocked(ref msg) => msg.write(writer),
			&Message::TxAddInput(ref msg) => msg.write(writer),
			&Message::TxAddOutput(ref msg) => msg.write(writer),
			&Message::TxRemoveInput(ref msg) => msg.write(writer),
			&Message::TxRemoveOutput(ref msg) => msg.write(writer),
			&Message::TxComplete(ref msg) => msg.write(writer),
			&Message::TxSignatures(ref msg) => msg.write(writer),
			&Message::TxInitRbf(ref msg) => msg.write(writer),
			&Message::TxAckRbf(ref msg) => msg.write(writer),
			&Message::TxAbort(ref msg) => msg.write(writer),
			&Message::ChannelReady(ref msg) => msg.write(writer),
			&Message::Shutdown(ref msg) => msg.write(writer),
			&Message::ClosingSigned(ref msg) => msg.write(writer),
			&Message::OnionMessage(ref msg) => msg.write(writer),
			&Message::UpdateAddHTLC(ref msg) => msg.write(writer),
			&Message::UpdateFulfillHTLC(ref msg) => msg.write(writer),
			&Message::UpdateFailHTLC(ref msg) => msg.write(writer),
			&Message::UpdateFailMalformedHTLC(ref msg) => msg.write(writer),
			&Message::CommitmentSigned(ref msg) => msg.write(writer),
			&Message::RevokeAndACK(ref msg) => msg.write(writer),
			&Message::UpdateFee(ref msg) => msg.write(writer),
			&Message::ChannelReestablish(ref msg) => msg.write(writer),
			&Message::AnnouncementSignatures(ref msg) => msg.write(writer),
			&Message::ChannelAnnouncement(ref msg) => msg.write(writer),
			&Message::NodeAnnouncement(ref msg) => msg.write(writer),
			&Message::ChannelUpdate(ref msg) => msg.write(writer),
			&Message::QueryShortChannelIds(ref msg) => msg.write(writer),
			&Message::ReplyShortChannelIdsEnd(ref msg) => msg.write(writer),
			&Message::QueryChannelRange(ref msg) => msg.write(writer),
			&Message::ReplyChannelRange(ref msg) => msg.write(writer),
			&Message::GossipTimestampFilter(ref msg) => msg.write(writer),
			&Message::Unknown(_) => { Ok(()) },
			&Message::Custom(ref msg) => msg.write(writer),
		}
	}
}

impl<T> Type for Message<T> where T: core::fmt::Debug + Type + TestEq {
	/// Returns the type that was used to decode the message payload.
	fn type_id(&self) -> u16 {
		match self {
			&Message::Init(ref msg) => msg.type_id(),
			&Message::Error(ref msg) => msg.type_id(),
			&Message::Warning(ref msg) => msg.type_id(),
			&Message::Ping(ref msg) => msg.type_id(),
			&Message::Pong(ref msg) => msg.type_id(),
			&Message::PeerStorageMessage(ref msg) => msg.type_id(),
			&Message::YourPeerStorageMessage(ref msg) => msg.type_id(),
			&Message::OpenChannel(ref msg) => msg.type_id(),
			&Message::OpenChannelV2(ref msg) => msg.type_id(),
			&Message::AcceptChannel(ref msg) => msg.type_id(),
			&Message::AcceptChannelV2(ref msg) => msg.type_id(),
			&Message::FundingCreated(ref msg) => msg.type_id(),
			&Message::FundingSigned(ref msg) => msg.type_id(),
			&Message::Stfu(ref msg) => msg.type_id(),
			#[cfg(splicing)]
			&Message::SpliceInit(ref msg) => msg.type_id(),
			#[cfg(splicing)]
			&Message::SpliceAck(ref msg) => msg.type_id(),
			#[cfg(splicing)]
			&Message::SpliceLocked(ref msg) => msg.type_id(),
			&Message::TxAddInput(ref msg) => msg.type_id(),
			&Message::TxAddOutput(ref msg) => msg.type_id(),
			&Message::TxRemoveInput(ref msg) => msg.type_id(),
			&Message::TxRemoveOutput(ref msg) => msg.type_id(),
			&Message::TxComplete(ref msg) => msg.type_id(),
			&Message::TxSignatures(ref msg) => msg.type_id(),
			&Message::TxInitRbf(ref msg) => msg.type_id(),
			&Message::TxAckRbf(ref msg) => msg.type_id(),
			&Message::TxAbort(ref msg) => msg.type_id(),
			&Message::ChannelReady(ref msg) => msg.type_id(),
			&Message::Shutdown(ref msg) => msg.type_id(),
			&Message::ClosingSigned(ref msg) => msg.type_id(),
			&Message::OnionMessage(ref msg) => msg.type_id(),
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
			&Message::QueryShortChannelIds(ref msg) => msg.type_id(),
			&Message::ReplyShortChannelIdsEnd(ref msg) => msg.type_id(),
			&Message::QueryChannelRange(ref msg) => msg.type_id(),
			&Message::ReplyChannelRange(ref msg) => msg.type_id(),
			&Message::GossipTimestampFilter(ref msg) => msg.type_id(),
			&Message::Unknown(type_id) => type_id,
			&Message::Custom(ref msg) => msg.type_id(),
		}
	}
}

impl<T> Message<T> where T: core::fmt::Debug + Type + TestEq {
	/// Returns whether the message's type is even, indicating both endpoints must support it.
	pub fn is_even(&self) -> bool {
		(self.type_id() & 1) == 0
	}
}

/// Reads a message from the data buffer consisting of a 2-byte big-endian type and a
/// variable-length payload conforming to the type.
///
/// # Errors
///
/// Returns an error if the message payload could not be decoded as the specified type.
pub(crate) fn read<R: io::Read, T, H: core::ops::Deref>(buffer: &mut R, custom_reader: H)
-> Result<Message<T>, (msgs::DecodeError, Option<u16>)> where
	T: core::fmt::Debug + Type + Writeable,
	H::Target: CustomMessageReader<CustomMessage = T>,
{
	let message_type = <u16 as Readable>::read(buffer).map_err(|e| (e, None))?;
	do_read(buffer, message_type, custom_reader).map_err(|e| (e, Some(message_type)))
}

fn do_read<R: io::Read, T, H: core::ops::Deref>(buffer: &mut R, message_type: u16, custom_reader: H)
-> Result<Message<T>, msgs::DecodeError> where
	T: core::fmt::Debug + Type + Writeable,
	H::Target: CustomMessageReader<CustomMessage = T>,
{
	match message_type {
		msgs::Init::TYPE => {
			Ok(Message::Init(Readable::read(buffer)?))
		},
		msgs::ErrorMessage::TYPE => {
			Ok(Message::Error(Readable::read(buffer)?))
		},
		msgs::WarningMessage::TYPE => {
			Ok(Message::Warning(Readable::read(buffer)?))
		},
		msgs::Ping::TYPE => {
			Ok(Message::Ping(Readable::read(buffer)?))
		},
		msgs::Pong::TYPE => {
			Ok(Message::Pong(Readable::read(buffer)?))
		},
		msgs::PeerStorageMessage::TYPE => {
			Ok(Message::PeerStorageMessage(Readable::read(buffer)?))
		},
		msgs::YourPeerStorageMessage::TYPE => {
			Ok(Message::YourPeerStorageMessage(Readable::read(buffer)?))
		},
		msgs::OpenChannel::TYPE => {
			Ok(Message::OpenChannel(Readable::read(buffer)?))
		},
		msgs::OpenChannelV2::TYPE => {
			Ok(Message::OpenChannelV2(Readable::read(buffer)?))
		},
		msgs::AcceptChannel::TYPE => {
			Ok(Message::AcceptChannel(Readable::read(buffer)?))
		},
		msgs::AcceptChannelV2::TYPE => {
			Ok(Message::AcceptChannelV2(Readable::read(buffer)?))
		},
		msgs::FundingCreated::TYPE => {
			Ok(Message::FundingCreated(Readable::read(buffer)?))
		},
		msgs::FundingSigned::TYPE => {
			Ok(Message::FundingSigned(Readable::read(buffer)?))
		},
		#[cfg(splicing)]
		msgs::SpliceInit::TYPE => {
			Ok(Message::SpliceInit(Readable::read(buffer)?))
		},
		msgs::Stfu::TYPE => {
			Ok(Message::Stfu(Readable::read(buffer)?))
		},
		#[cfg(splicing)]
		msgs::SpliceAck::TYPE => {
			Ok(Message::SpliceAck(Readable::read(buffer)?))
		},
		#[cfg(splicing)]
		msgs::SpliceLocked::TYPE => {
			Ok(Message::SpliceLocked(Readable::read(buffer)?))
		},
		msgs::TxAddInput::TYPE => {
			Ok(Message::TxAddInput(Readable::read(buffer)?))
		},
		msgs::TxAddOutput::TYPE => {
			Ok(Message::TxAddOutput(Readable::read(buffer)?))
		},
		msgs::TxRemoveInput::TYPE => {
			Ok(Message::TxRemoveInput(Readable::read(buffer)?))
		},
		msgs::TxRemoveOutput::TYPE => {
			Ok(Message::TxRemoveOutput(Readable::read(buffer)?))
		},
		msgs::TxComplete::TYPE => {
			Ok(Message::TxComplete(Readable::read(buffer)?))
		},
		msgs::TxSignatures::TYPE => {
			Ok(Message::TxSignatures(Readable::read(buffer)?))
		},
		msgs::TxInitRbf::TYPE => {
			Ok(Message::TxInitRbf(Readable::read(buffer)?))
		},
		msgs::TxAckRbf::TYPE => {
			Ok(Message::TxAckRbf(Readable::read(buffer)?))
		},
		msgs::TxAbort::TYPE => {
			Ok(Message::TxAbort(Readable::read(buffer)?))
		},
		msgs::ChannelReady::TYPE => {
			Ok(Message::ChannelReady(Readable::read(buffer)?))
		},
		msgs::Shutdown::TYPE => {
			Ok(Message::Shutdown(Readable::read(buffer)?))
		},
		msgs::ClosingSigned::TYPE => {
			Ok(Message::ClosingSigned(Readable::read(buffer)?))
		},
		msgs::OnionMessage::TYPE => {
			Ok(Message::OnionMessage(Readable::read(buffer)?))
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
		msgs::QueryShortChannelIds::TYPE => {
			Ok(Message::QueryShortChannelIds(Readable::read(buffer)?))
		},
		msgs::ReplyShortChannelIdsEnd::TYPE => {
			Ok(Message::ReplyShortChannelIdsEnd(Readable::read(buffer)?))
		},
		msgs::QueryChannelRange::TYPE => {
			Ok(Message::QueryChannelRange(Readable::read(buffer)?))
		},
		msgs::ReplyChannelRange::TYPE => {
			Ok(Message::ReplyChannelRange(Readable::read(buffer)?))
		}
		msgs::GossipTimestampFilter::TYPE => {
			Ok(Message::GossipTimestampFilter(Readable::read(buffer)?))
		},
		_ => {
			if let Some(custom) = custom_reader.read(message_type, buffer)? {
				Ok(Message::Custom(custom))
			} else {
				Ok(Message::Unknown(message_type))
			}
		},
	}
}

/// Writes a message to the data buffer encoded as a 2-byte big-endian type and a variable-length
/// payload.
///
/// # Errors
///
/// Returns an I/O error if the write could not be completed.
pub(crate) fn write<M: Type + Writeable, W: Writer>(message: &M, buffer: &mut W) -> Result<(), io::Error> {
	message.type_id().write(buffer)?;
	message.write(buffer)
}

mod encode {
	/// Defines a constant type identifier for reading messages from the wire.
	pub trait Encode {
		/// The type identifying the message payload.
		const TYPE: u16;
	}
}

pub(crate) use self::encode::Encode;

#[cfg(not(test))]
/// Defines a type identifier for sending messages over the wire.
///
/// Messages implementing this trait specify a type and must be [`Writeable`].
pub trait Type: core::fmt::Debug + Writeable {
	/// Returns the type identifying the message payload.
	fn type_id(&self) -> u16;
}

#[cfg(test)]
pub trait Type: core::fmt::Debug + Writeable + PartialEq {
	fn type_id(&self) -> u16;
}

#[cfg(any(feature = "_test_utils", fuzzing, test))]
impl Type for () {
	fn type_id(&self) -> u16 { unreachable!(); }
}

#[cfg(test)]
impl<T: core::fmt::Debug + Writeable + PartialEq> Type for T where T: Encode {
	fn type_id(&self) -> u16 { T::TYPE }
}

#[cfg(not(test))]
impl<T: core::fmt::Debug + Writeable> Type for T where T: Encode {
	fn type_id(&self) -> u16 { T::TYPE }
}

impl Encode for msgs::Stfu {
	const TYPE: u16 = 2;
}

impl Encode for msgs::Init {
	const TYPE: u16 = 16;
}

impl Encode for msgs::ErrorMessage {
	const TYPE: u16 = 17;
}

impl Encode for msgs::WarningMessage {
	const TYPE: u16 = 1;
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

impl Encode for msgs::ChannelReady {
	const TYPE: u16 = 36;
}

impl Encode for msgs::Shutdown {
	const TYPE: u16 = 38;
}

impl Encode for msgs::ClosingSigned {
	const TYPE: u16 = 39;
}

impl Encode for msgs::OpenChannelV2 {
	const TYPE: u16 = 64;
}

impl Encode for msgs::AcceptChannelV2 {
	const TYPE: u16 = 65;
}

impl Encode for msgs::SpliceInit {
	// TODO(splicing) Double check with finalized spec; draft spec contains 80; previously it was 74 (conflict with tx_abort); CLN used 75
	const TYPE: u16 = 80;
}

impl Encode for msgs::SpliceAck {
	const TYPE: u16 = 81;
}

impl Encode for msgs::SpliceLocked {
	const TYPE: u16 = 77;
}

impl Encode for msgs::TxAddInput {
	const TYPE: u16 = 66;
}

impl Encode for msgs::TxAddOutput {
	const TYPE: u16 = 67;
}

impl Encode for msgs::TxRemoveInput {
	const TYPE: u16 = 68;
}

impl Encode for msgs::TxRemoveOutput {
	const TYPE: u16 = 69;
}

impl Encode for msgs::TxComplete {
	const TYPE: u16 = 70;
}

impl Encode for msgs::TxSignatures {
	const TYPE: u16 = 71;
}

impl Encode for msgs::TxInitRbf {
	const TYPE: u16 = 72;
}

impl Encode for msgs::TxAckRbf {
	const TYPE: u16 = 73;
}

impl Encode for msgs::TxAbort {
	const TYPE: u16 = 74;
}

impl Encode for msgs::OnionMessage {
	const TYPE: u16 = 513;
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

impl Encode for msgs::QueryShortChannelIds {
	const TYPE: u16 = 261;
}

impl Encode for msgs::ReplyShortChannelIdsEnd {
	const TYPE: u16 = 262;
}

impl Encode for msgs::QueryChannelRange {
	const TYPE: u16 = 263;
}

impl Encode for msgs::ReplyChannelRange {
	const TYPE: u16 = 264;
}

impl Encode for msgs::GossipTimestampFilter {
	const TYPE: u16 = 265;
}

impl Encode for msgs::PeerStorageMessage {
	const TYPE: u16 = 7;
}

impl Encode for msgs::YourPeerStorageMessage {
	const TYPE: u16 = 9;
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::prelude::*;
	use crate::ln::peer_handler::IgnoringMessageHandler;

	// Big-endian wire encoding of Pong message (type = 19, byteslen = 2).
	const ENCODED_PONG: [u8; 6] = [0u8, 19u8, 0u8, 2u8, 0u8, 0u8];

	#[test]
	fn read_empty_buffer() {
		let buffer = [];
		let mut reader = io::Cursor::new(buffer);
		assert!(read(&mut reader, &IgnoringMessageHandler{}).is_err());
	}

	#[test]
	fn read_incomplete_type() {
		let buffer = &ENCODED_PONG[..1];
		let mut reader = io::Cursor::new(buffer);
		assert!(read(&mut reader, &IgnoringMessageHandler{}).is_err());
	}

	#[test]
	fn read_empty_payload() {
		let buffer = &ENCODED_PONG[..2];
		let mut reader = io::Cursor::new(buffer);
		assert!(read(&mut reader, &IgnoringMessageHandler{}).is_err());
	}

	#[test]
	fn read_invalid_message() {
		let buffer = &ENCODED_PONG[..4];
		let mut reader = io::Cursor::new(buffer);
		assert!(read(&mut reader, &IgnoringMessageHandler{}).is_err());
	}

	#[test]
	fn read_known_message() {
		let buffer = &ENCODED_PONG[..];
		let mut reader = io::Cursor::new(buffer);
		let message = read(&mut reader, &IgnoringMessageHandler{}).unwrap();
		match message {
			Message::Pong(_) => (),
			_ => panic!("Expected pong message; found message type: {}", message.type_id()),
		}
	}

	#[test]
	fn read_unknown_message() {
		let buffer = &::core::u16::MAX.to_be_bytes();
		let mut reader = io::Cursor::new(buffer);
		let message = read(&mut reader, &IgnoringMessageHandler{}).unwrap();
		match message {
			Message::Unknown(::core::u16::MAX) => (),
			_ => panic!("Expected message type {}; found: {}", ::core::u16::MAX, message.type_id()),
		}
	}

	#[test]
	fn write_message_with_type() {
		let message = msgs::Pong { byteslen: 2u16 };
		let mut buffer = Vec::new();
		assert!(write(&message, &mut buffer).is_ok());

		let type_length = ::core::mem::size_of::<u16>();
		let (type_bytes, payload_bytes) = buffer.split_at(type_length);
		assert_eq!(u16::from_be_bytes(type_bytes.try_into().unwrap()), msgs::Pong::TYPE);
		assert_eq!(payload_bytes, &ENCODED_PONG[type_length..]);
	}

	#[test]
	fn read_message_encoded_with_write() {
		let message = msgs::Pong { byteslen: 2u16 };
		let mut buffer = Vec::new();
		assert!(write(&message, &mut buffer).is_ok());

		let mut reader = io::Cursor::new(buffer);
		let decoded_message = read(&mut reader, &IgnoringMessageHandler{}).unwrap();
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
		let message = Message::<()>::Unknown(42);
		assert!(message.is_even());
	}

	#[test]
	fn is_odd_message_type() {
		let message = Message::<()>::Unknown(43);
		assert!(!message.is_even());
	}

	#[test]
	fn read_lnd_init_msg() {
		// Taken from lnd v0.9.0-beta.
		let buffer = vec![0, 16, 0, 2, 34, 0, 0, 3, 2, 162, 161];
		check_init_msg(buffer, false);
	}

	#[test]
	fn read_clightning_init_msg() {
		// Taken from c-lightning v0.8.0.
		let buffer = vec![0, 16, 0, 2, 34, 0, 0, 3, 2, 170, 162, 1, 32, 6, 34, 110, 70, 17, 26, 11, 89, 202, 175, 18, 96, 67, 235, 91, 191, 40, 195, 79, 58, 94, 51, 42, 31, 199, 178, 183, 60, 241, 136, 145, 15];
		check_init_msg(buffer, true);
	}

	fn check_init_msg(buffer: Vec<u8>, expect_unknown: bool) {
		let mut reader = io::Cursor::new(buffer);
		let decoded_msg = read(&mut reader, &IgnoringMessageHandler{}).unwrap();
		match decoded_msg {
			Message::Init(msgs::Init { features, .. }) => {
				assert!(features.supports_variable_length_onion());
				assert!(features.supports_upfront_shutdown_script());
				assert!(features.supports_gossip_queries());
				assert_eq!(expect_unknown, features.supports_unknown_bits());
				assert!(!features.requires_unknown_bits());
				assert!(!features.initial_routing_sync());
			},
			_ => panic!("Expected init message, found message type: {}", decoded_msg.type_id())
		}
	}

	#[test]
	fn read_lnd_node_announcement() {
		// Taken from lnd v0.9.0-beta.
		let buffer = vec![1, 1, 91, 164, 146, 213, 213, 165, 21, 227, 102, 33, 105, 179, 214, 21, 221, 175, 228, 93, 57, 177, 191, 127, 107, 229, 31, 50, 21, 81, 179, 71, 39, 18, 35, 2, 89, 224, 110, 123, 66, 39, 148, 246, 177, 85, 12, 19, 70, 226, 173, 132, 156, 26, 122, 146, 71, 213, 247, 48, 93, 190, 185, 177, 12, 172, 0, 3, 2, 162, 161, 94, 103, 195, 37, 2, 37, 242, 97, 140, 2, 111, 69, 85, 39, 118, 30, 221, 99, 254, 120, 49, 103, 22, 170, 227, 111, 172, 164, 160, 49, 68, 138, 116, 16, 22, 206, 107, 51, 153, 255, 97, 108, 105, 99, 101, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7, 1, 172, 21, 0, 2, 38, 7];
		let mut reader = io::Cursor::new(buffer);
		let decoded_msg = read(&mut reader, &IgnoringMessageHandler{}).unwrap();
		match decoded_msg {
			Message::NodeAnnouncement(msgs::NodeAnnouncement { contents: msgs::UnsignedNodeAnnouncement { features, ..}, ..}) => {
				assert!(features.supports_variable_length_onion());
				assert!(features.supports_upfront_shutdown_script());
				assert!(features.supports_gossip_queries());
				assert!(!features.requires_unknown_bits());
			},
			_ => panic!("Expected node announcement, found message type: {}", decoded_msg.type_id())
		}
	}

	#[test]
	fn read_lnd_chan_announcement() {
		// Taken from lnd v0.9.0-beta.
		let buffer = vec![1, 0, 82, 238, 153, 33, 128, 87, 215, 2, 28, 241, 140, 250, 98, 255, 56, 5, 79, 240, 214, 231, 172, 35, 240, 171, 44, 9, 78, 91, 8, 193, 102, 5, 17, 178, 142, 106, 180, 183, 46, 38, 217, 212, 25, 236, 69, 47, 92, 217, 181, 221, 161, 205, 121, 201, 99, 38, 158, 216, 186, 193, 230, 86, 222, 6, 206, 67, 22, 255, 137, 212, 141, 161, 62, 134, 76, 48, 241, 54, 50, 167, 187, 247, 73, 27, 74, 1, 129, 185, 197, 153, 38, 90, 255, 138, 39, 161, 102, 172, 213, 74, 107, 88, 150, 90, 0, 49, 104, 7, 182, 184, 194, 219, 181, 172, 8, 245, 65, 226, 19, 228, 101, 145, 25, 159, 52, 31, 58, 93, 53, 59, 218, 91, 37, 84, 103, 17, 74, 133, 33, 35, 2, 203, 101, 73, 19, 94, 175, 122, 46, 224, 47, 168, 128, 128, 25, 26, 25, 214, 52, 247, 43, 241, 117, 52, 206, 94, 135, 156, 52, 164, 143, 234, 58, 185, 50, 185, 140, 198, 174, 71, 65, 18, 105, 70, 131, 172, 137, 0, 164, 51, 215, 143, 117, 119, 217, 241, 197, 177, 227, 227, 170, 199, 114, 7, 218, 12, 107, 30, 191, 236, 203, 21, 61, 242, 48, 192, 90, 233, 200, 199, 111, 162, 68, 234, 54, 219, 1, 233, 66, 5, 82, 74, 84, 211, 95, 199, 245, 202, 89, 223, 102, 124, 62, 166, 253, 253, 90, 180, 118, 21, 61, 110, 37, 5, 96, 167, 0, 0, 6, 34, 110, 70, 17, 26, 11, 89, 202, 175, 18, 96, 67, 235, 91, 191, 40, 195, 79, 58, 94, 51, 42, 31, 199, 178, 183, 60, 241, 136, 145, 15, 0, 2, 65, 0, 0, 1, 0, 0, 2, 37, 242, 97, 140, 2, 111, 69, 85, 39, 118, 30, 221, 99, 254, 120, 49, 103, 22, 170, 227, 111, 172, 164, 160, 49, 68, 138, 116, 16, 22, 206, 107, 3, 54, 61, 144, 88, 171, 247, 136, 208, 99, 9, 135, 37, 201, 178, 253, 136, 0, 185, 235, 68, 160, 106, 110, 12, 46, 21, 125, 204, 18, 75, 234, 16, 3, 42, 171, 28, 52, 224, 11, 30, 30, 253, 156, 148, 175, 203, 121, 250, 111, 122, 195, 84, 122, 77, 183, 56, 135, 101, 88, 41, 60, 191, 99, 232, 85, 2, 36, 17, 156, 11, 8, 12, 189, 177, 68, 88, 28, 15, 207, 21, 179, 151, 56, 226, 158, 148, 3, 120, 113, 177, 243, 184, 17, 173, 37, 46, 222, 16];
		let mut reader = io::Cursor::new(buffer);
		let decoded_msg = read(&mut reader, &IgnoringMessageHandler{}).unwrap();
		match decoded_msg {
			Message::ChannelAnnouncement(msgs::ChannelAnnouncement { contents: msgs::UnsignedChannelAnnouncement { features, ..}, ..}) => {
				assert!(!features.requires_unknown_bits());
			},
			_ => panic!("Expected node announcement, found message type: {}", decoded_msg.type_id())
		}
	}

	#[derive(Eq, PartialEq, Debug)]
	struct TestCustomMessage {}

	const CUSTOM_MESSAGE_TYPE : u16 = 9000;

	impl Type for TestCustomMessage {
		fn type_id(&self) -> u16 {
			CUSTOM_MESSAGE_TYPE
		}
	}

	impl Writeable for TestCustomMessage {
		fn write<W: Writer>(&self, _: &mut W) -> Result<(), io::Error> {
			Ok(())
		}
	}

	struct TestCustomMessageReader {}

	impl CustomMessageReader for TestCustomMessageReader {
		type CustomMessage = TestCustomMessage;
		fn read<R: io::Read>(
			&self,
			message_type: u16,
			_: &mut R
		) -> Result<Option<Self::CustomMessage>, msgs::DecodeError> {
			if message_type == CUSTOM_MESSAGE_TYPE {
				return Ok(Some(TestCustomMessage{}));
			}

			Ok(None)
		}
	}

	#[test]
	fn read_custom_message() {
		let buffer = vec![35, 40];
		let mut reader = io::Cursor::new(buffer);
		let decoded_msg = read(&mut reader, &TestCustomMessageReader{}).unwrap();
		match decoded_msg {
			Message::Custom(custom) => {
				assert_eq!(custom.type_id(), CUSTOM_MESSAGE_TYPE);
				assert_eq!(custom, TestCustomMessage {});
			},
			_ => panic!("Expected custom message, found message type: {}", decoded_msg.type_id()),
		}
	}

	#[test]
	fn read_with_custom_reader_unknown_message_type() {
		let buffer = vec![35, 42];
		let mut reader = io::Cursor::new(buffer);
		let decoded_msg = read(&mut reader, &TestCustomMessageReader{}).unwrap();
		match decoded_msg {
			Message::Unknown(_) => {},
			_ => panic!("Expected unknown message, found message type: {}", decoded_msg.type_id()),
		}
	}

	#[test]
	fn custom_reader_unknown_message_type() {
		let buffer = Vec::new();
		let mut reader = io::Cursor::new(buffer);
		let res = TestCustomMessageReader{}.read(CUSTOM_MESSAGE_TYPE + 1, &mut reader).unwrap();
		assert!(res.is_none());
	}
}
