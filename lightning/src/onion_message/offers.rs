// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Message handling for BOLT 12 Offers.

use core::convert::TryFrom;
use core::fmt;
use crate::io::{self, Read};
use crate::ln::msgs::DecodeError;
use crate::offers::invoice_error::InvoiceError;
use crate::offers::invoice_request::InvoiceRequest;
use crate::offers::invoice::Bolt12Invoice;
use crate::offers::parse::Bolt12ParseError;
use crate::onion_message::OnionMessageContents;
use crate::util::logger::Logger;
use crate::util::ser::{Readable, ReadableArgs, Writeable, Writer};
#[cfg(not(c_bindings))]
use crate::onion_message::messenger::PendingOnionMessage;

use crate::prelude::*;

// TLV record types for the `onionmsg_tlv` TLV stream as defined in BOLT 4.
const INVOICE_REQUEST_TLV_TYPE: u64 = 64;
const INVOICE_TLV_TYPE: u64 = 66;
const INVOICE_ERROR_TLV_TYPE: u64 = 68;

/// A handler for an [`OnionMessage`] containing a BOLT 12 Offers message as its payload.
///
/// [`OnionMessage`]: crate::ln::msgs::OnionMessage
pub trait OffersMessageHandler {
	/// Handles the given message by either responding with an [`Bolt12Invoice`], sending a payment,
	/// or replying with an error.
	///
	/// The returned [`OffersMessage`], if any, is enqueued to be sent by [`OnionMessenger`].
	///
	/// [`OnionMessenger`]: crate::onion_message::OnionMessenger
	fn handle_message(&self, message: OffersMessage) -> Option<OffersMessage>;

	/// Releases any [`OffersMessage`]s that need to be sent.
	///
	/// Typically, this is used for messages initiating a payment flow rather than in response to
	/// another message. The latter should use the return value of [`Self::handle_message`].
	#[cfg(not(c_bindings))]
	fn release_pending_messages(&self) -> Vec<PendingOnionMessage<OffersMessage>> { vec![] }

	/// Releases any [`OffersMessage`]s that need to be sent.
	///
	/// Typically, this is used for messages initiating a payment flow rather than in response to
	/// another message. The latter should use the return value of [`Self::handle_message`].
	#[cfg(c_bindings)]
	fn release_pending_messages(&self) -> Vec<(OffersMessage, crate::onion_message::Destination, Option<crate::blinded_path::BlindedPath>)> { vec![] }
}

/// Possible BOLT 12 Offers messages sent and received via an [`OnionMessage`].
///
/// [`OnionMessage`]: crate::ln::msgs::OnionMessage
#[derive(Clone)]
pub enum OffersMessage {
	/// A request for a [`Bolt12Invoice`] for a particular [`Offer`].
	///
	/// [`Offer`]: crate::offers::offer::Offer
	InvoiceRequest(InvoiceRequest),

	/// A [`Bolt12Invoice`] sent in response to an [`InvoiceRequest`] or a [`Refund`].
	///
	/// [`Refund`]: crate::offers::refund::Refund
	Invoice(Bolt12Invoice),

	/// An error from handling an [`OffersMessage`].
	InvoiceError(InvoiceError),
}

impl OffersMessage {
	/// Returns whether `tlv_type` corresponds to a TLV record for Offers.
	pub fn is_known_type(tlv_type: u64) -> bool {
		match tlv_type {
			INVOICE_REQUEST_TLV_TYPE | INVOICE_TLV_TYPE | INVOICE_ERROR_TLV_TYPE => true,
			_ => false,
		}
	}

	fn parse(tlv_type: u64, bytes: Vec<u8>) -> Result<Self, Bolt12ParseError> {
		match tlv_type {
			INVOICE_REQUEST_TLV_TYPE => Ok(Self::InvoiceRequest(InvoiceRequest::try_from(bytes)?)),
			INVOICE_TLV_TYPE => Ok(Self::Invoice(Bolt12Invoice::try_from(bytes)?)),
			_ => Err(Bolt12ParseError::Decode(DecodeError::InvalidValue)),
		}
	}
}

impl fmt::Debug for OffersMessage {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			OffersMessage::InvoiceRequest(message) => {
				write!(f, "{:?}", message.as_tlv_stream())
			}
			OffersMessage::Invoice(message) => {
				write!(f, "{:?}", message.as_tlv_stream())
			}
			OffersMessage::InvoiceError(message) => {
				write!(f, "{:?}", message)
			}
		}
	}
}

impl OnionMessageContents for OffersMessage {
	fn tlv_type(&self) -> u64 {
		match self {
			OffersMessage::InvoiceRequest(_) => INVOICE_REQUEST_TLV_TYPE,
			OffersMessage::Invoice(_) => INVOICE_TLV_TYPE,
			OffersMessage::InvoiceError(_) => INVOICE_ERROR_TLV_TYPE,
		}
	}
}

impl Writeable for OffersMessage {
	fn write(&self, w: &mut impl Writer) -> Result<(), io::Error> {
		match self {
			OffersMessage::InvoiceRequest(message) => message.write(w),
			OffersMessage::Invoice(message) => message.write(w),
			OffersMessage::InvoiceError(message) => message.write(w),
		}
	}
}

impl<L: Logger + ?Sized> ReadableArgs<(u64, &L)> for OffersMessage {
	fn read<R: Read>(r: &mut R, read_args: (u64, &L)) -> Result<Self, DecodeError> {
		let (tlv_type, logger) = read_args;
		if tlv_type == INVOICE_ERROR_TLV_TYPE {
			return Ok(Self::InvoiceError(InvoiceError::read(r)?));
		}

		let mut bytes = Vec::new();
		r.read_to_end(&mut bytes).unwrap();

		match Self::parse(tlv_type, bytes) {
			Ok(message) => Ok(message),
			Err(Bolt12ParseError::Decode(e)) => Err(e),
			Err(Bolt12ParseError::InvalidSemantics(e)) => {
				log_trace!(logger, "Invalid semantics for TLV type {}: {:?}", tlv_type, e);
				Err(DecodeError::InvalidValue)
			},
			Err(Bolt12ParseError::InvalidSignature(e)) => {
				log_trace!(logger, "Invalid signature for TLV type {}: {:?}", tlv_type, e);
				Err(DecodeError::InvalidValue)
			},
			Err(_) => Err(DecodeError::InvalidValue),
		}
	}
}
