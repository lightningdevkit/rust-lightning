// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Message handling for BOLT 12 Offers.

use crate::blinded_path::message::OffersContext;
use crate::io::{self, Read};
use crate::ln::msgs::DecodeError;
use crate::offers::invoice::Bolt12Invoice;
use crate::offers::invoice_error::InvoiceError;
use crate::offers::invoice_request::InvoiceRequest;
use crate::offers::parse::Bolt12ParseError;
#[cfg(async_payments)]
use crate::offers::static_invoice::StaticInvoice;
use crate::onion_message::messenger::{MessageSendInstructions, Responder, ResponseInstruction};
use crate::onion_message::packet::OnionMessageContents;
use crate::util::logger::Logger;
use crate::util::ser::{Readable, ReadableArgs, Writeable, Writer};
use core::fmt;

use crate::prelude::*;

// TLV record types for the `onionmsg_tlv` TLV stream as defined in BOLT 4.
const INVOICE_REQUEST_TLV_TYPE: u64 = 64;
const INVOICE_TLV_TYPE: u64 = 66;
const INVOICE_ERROR_TLV_TYPE: u64 = 68;
#[cfg(async_payments)]
const STATIC_INVOICE_TLV_TYPE: u64 = 70;

/// A handler for an [`OnionMessage`] containing a BOLT 12 Offers message as its payload.
///
/// [`OnionMessage`]: crate::ln::msgs::OnionMessage
pub trait OffersMessageHandler {
	/// Handles the given message by either responding with an [`Bolt12Invoice`], sending a payment,
	/// or replying with an error.
	///
	/// The returned [`OffersMessage`], if any, is enqueued to be sent by [`OnionMessenger`].
	///
	/// [`OnionMessenger`]: crate::onion_message::messenger::OnionMessenger
	fn handle_message(
		&self, message: OffersMessage, context: Option<OffersContext>, responder: Option<Responder>,
	) -> Option<(OffersMessage, ResponseInstruction)>;

	/// Releases any [`OffersMessage`]s that need to be sent.
	///
	/// Typically, this is used for messages initiating a payment flow rather than in response to
	/// another message. The latter should use the return value of [`Self::handle_message`].
	fn release_pending_messages(&self) -> Vec<(OffersMessage, MessageSendInstructions)> {
		vec![]
	}
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

	#[cfg(async_payments)]
	/// A [`StaticInvoice`] sent in response to an [`InvoiceRequest`].
	StaticInvoice(StaticInvoice),

	/// An error from handling an [`OffersMessage`].
	InvoiceError(InvoiceError),
}

impl OffersMessage {
	/// Returns whether `tlv_type` corresponds to a TLV record for Offers.
	pub fn is_known_type(tlv_type: u64) -> bool {
		match tlv_type {
			INVOICE_REQUEST_TLV_TYPE | INVOICE_TLV_TYPE | INVOICE_ERROR_TLV_TYPE => true,
			#[cfg(async_payments)]
			STATIC_INVOICE_TLV_TYPE => true,
			_ => false,
		}
	}

	fn parse(tlv_type: u64, bytes: Vec<u8>) -> Result<Self, Bolt12ParseError> {
		match tlv_type {
			INVOICE_REQUEST_TLV_TYPE => Ok(Self::InvoiceRequest(InvoiceRequest::try_from(bytes)?)),
			INVOICE_TLV_TYPE => Ok(Self::Invoice(Bolt12Invoice::try_from(bytes)?)),
			#[cfg(async_payments)]
			STATIC_INVOICE_TLV_TYPE => Ok(Self::StaticInvoice(StaticInvoice::try_from(bytes)?)),
			_ => Err(Bolt12ParseError::Decode(DecodeError::InvalidValue)),
		}
	}

	fn get_msg_type(&self) -> &'static str {
		match &self {
			OffersMessage::InvoiceRequest(_) => "Invoice Request",
			OffersMessage::Invoice(_) => "Invoice",
			#[cfg(async_payments)]
			OffersMessage::StaticInvoice(_) => "Static Invoice",
			OffersMessage::InvoiceError(_) => "Invoice Error",
		}
	}
}

impl fmt::Debug for OffersMessage {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			OffersMessage::InvoiceRequest(message) => {
				write!(f, "{:?}", message.as_tlv_stream())
			},
			OffersMessage::Invoice(message) => {
				write!(f, "{:?}", message.as_tlv_stream())
			},
			#[cfg(async_payments)]
			OffersMessage::StaticInvoice(message) => {
				write!(f, "{:?}", message)
			},
			OffersMessage::InvoiceError(message) => {
				write!(f, "{:?}", message)
			},
		}
	}
}

impl OnionMessageContents for OffersMessage {
	fn tlv_type(&self) -> u64 {
		match self {
			OffersMessage::InvoiceRequest(_) => INVOICE_REQUEST_TLV_TYPE,
			OffersMessage::Invoice(_) => INVOICE_TLV_TYPE,
			#[cfg(async_payments)]
			OffersMessage::StaticInvoice(_) => STATIC_INVOICE_TLV_TYPE,
			OffersMessage::InvoiceError(_) => INVOICE_ERROR_TLV_TYPE,
		}
	}
	#[cfg(c_bindings)]
	fn msg_type(&self) -> String {
		self.get_msg_type().to_string()
	}
	#[cfg(not(c_bindings))]
	fn msg_type(&self) -> &'static str {
		self.get_msg_type()
	}
}

impl Writeable for OffersMessage {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		match self {
			OffersMessage::InvoiceRequest(message) => message.write(w),
			OffersMessage::Invoice(message) => message.write(w),
			#[cfg(async_payments)]
			OffersMessage::StaticInvoice(message) => message.write(w),
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
		r.read_to_limit(&mut bytes, u64::MAX).unwrap();

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
