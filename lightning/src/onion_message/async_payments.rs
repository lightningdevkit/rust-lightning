// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Message handling for async payments.

use crate::io;
use crate::ln::msgs::DecodeError;
use crate::onion_message::messenger::{MessageSendInstructions, Responder, ResponseInstruction};
use crate::onion_message::packet::OnionMessageContents;
use crate::prelude::*;
use crate::util::ser::{Readable, ReadableArgs, Writeable, Writer};

// TLV record types for the `onionmsg_tlv` TLV stream as defined in BOLT 4.
const HELD_HTLC_AVAILABLE_TLV_TYPE: u64 = 72;
const RELEASE_HELD_HTLC_TLV_TYPE: u64 = 74;

/// A handler for an [`OnionMessage`] containing an async payments message as its payload.
///
/// [`OnionMessage`]: crate::ln::msgs::OnionMessage
pub trait AsyncPaymentsMessageHandler {
	/// Handle a [`HeldHtlcAvailable`] message. A [`ReleaseHeldHtlc`] should be returned to release
	/// the held funds.
	fn held_htlc_available(
		&self, message: HeldHtlcAvailable, responder: Option<Responder>,
	) -> Option<(ReleaseHeldHtlc, ResponseInstruction)>;

	/// Handle a [`ReleaseHeldHtlc`] message. If authentication of the message succeeds, an HTLC
	/// should be released to the corresponding payee.
	fn release_held_htlc(&self, message: ReleaseHeldHtlc);

	/// Release any [`AsyncPaymentsMessage`]s that need to be sent.
	///
	/// Typically, this is used for messages initiating an async payment flow rather than in response
	/// to another message.
	fn release_pending_messages(&self) -> Vec<(AsyncPaymentsMessage, MessageSendInstructions)> {
		vec![]
	}
}

/// Possible async payment messages sent and received via an [`OnionMessage`].
///
/// [`OnionMessage`]: crate::ln::msgs::OnionMessage
#[derive(Clone, Debug)]
pub enum AsyncPaymentsMessage {
	/// An HTLC is being held upstream for the often-offline recipient, to be released via
	/// [`ReleaseHeldHtlc`].
	HeldHtlcAvailable(HeldHtlcAvailable),

	/// Releases the HTLC corresponding to an inbound [`HeldHtlcAvailable`] message.
	ReleaseHeldHtlc(ReleaseHeldHtlc),
}

/// An HTLC destined for the recipient of this message is being held upstream. The reply path
/// accompanying this onion message should be used to send a [`ReleaseHeldHtlc`] response, which
/// will cause the upstream HTLC to be released.
#[derive(Clone, Debug)]
pub struct HeldHtlcAvailable {
	/// The secret that will be used by the recipient of this message to release the held HTLC.
	pub payment_release_secret: [u8; 32],
}

/// Releases the HTLC corresponding to an inbound [`HeldHtlcAvailable`] message.
#[derive(Clone, Debug)]
pub struct ReleaseHeldHtlc {
	/// Used to release the HTLC held upstream if it matches the corresponding
	/// [`HeldHtlcAvailable::payment_release_secret`].
	pub payment_release_secret: [u8; 32],
}

impl OnionMessageContents for ReleaseHeldHtlc {
	fn tlv_type(&self) -> u64 {
		RELEASE_HELD_HTLC_TLV_TYPE
	}
	fn msg_type(&self) -> &'static str {
		"Release Held HTLC"
	}
}

impl_writeable_tlv_based!(HeldHtlcAvailable, {
	(0, payment_release_secret, required),
});

impl_writeable_tlv_based!(ReleaseHeldHtlc, {
	(0, payment_release_secret, required),
});

impl AsyncPaymentsMessage {
	/// Returns whether `tlv_type` corresponds to a TLV record for async payment messages.
	pub fn is_known_type(tlv_type: u64) -> bool {
		match tlv_type {
			HELD_HTLC_AVAILABLE_TLV_TYPE | RELEASE_HELD_HTLC_TLV_TYPE => true,
			_ => false,
		}
	}
}

impl OnionMessageContents for AsyncPaymentsMessage {
	fn tlv_type(&self) -> u64 {
		match self {
			Self::HeldHtlcAvailable(_) => HELD_HTLC_AVAILABLE_TLV_TYPE,
			Self::ReleaseHeldHtlc(msg) => msg.tlv_type(),
		}
	}
	fn msg_type(&self) -> &'static str {
		match &self {
			Self::HeldHtlcAvailable(_) => "Held HTLC Available",
			Self::ReleaseHeldHtlc(msg) => msg.msg_type(),
		}
	}
}

impl Writeable for AsyncPaymentsMessage {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		match self {
			Self::HeldHtlcAvailable(message) => message.write(w),
			Self::ReleaseHeldHtlc(message) => message.write(w),
		}
	}
}

impl ReadableArgs<u64> for AsyncPaymentsMessage {
	fn read<R: io::Read>(r: &mut R, tlv_type: u64) -> Result<Self, DecodeError> {
		match tlv_type {
			HELD_HTLC_AVAILABLE_TLV_TYPE => Ok(Self::HeldHtlcAvailable(Readable::read(r)?)),
			RELEASE_HELD_HTLC_TLV_TYPE => Ok(Self::ReleaseHeldHtlc(Readable::read(r)?)),
			_ => Err(DecodeError::InvalidValue),
		}
	}
}
