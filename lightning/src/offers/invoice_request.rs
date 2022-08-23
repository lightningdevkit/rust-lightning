// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Data structures and encoding for `invoice_request` messages.

use bitcoin::blockdata::constants::ChainHash;
use bitcoin::secp256k1::PublicKey;
use bitcoin::secp256k1::schnorr::Signature;
use core::convert::TryFrom;
use crate::io;
use crate::ln::features::OfferFeatures;
use crate::ln::msgs::DecodeError;
use crate::offers::merkle::{SignatureTlvStream, self};
use crate::offers::offer::{Amount, OfferContents, OfferTlvStream};
use crate::offers::parse::{ParseError, ParsedMessage, SemanticError};
use crate::offers::payer::{PayerContents, PayerTlvStream};
use crate::util::ser::{HighZeroBytesDroppedBigSize, SeekReadable, WithoutLength, Writeable, Writer};

use crate::prelude::*;

/// An `InvoiceRequest` is a request for an `Invoice` formulated from an [`Offer`].
///
/// An offer may provided choices such as quantity, amount, chain, features, etc. An invoice request
/// specifies these such that the recipient can send an invoice for payment.
///
/// [`Offer`]: crate::offers::offer::Offer
#[derive(Clone, Debug)]
pub struct InvoiceRequest {
	bytes: Vec<u8>,
	contents: InvoiceRequestContents,
	signature: Option<Signature>,
}

/// The contents of an [`InvoiceRequest`], which may be shared with an `Invoice`.
#[derive(Clone, Debug)]
pub(crate) struct InvoiceRequestContents {
	payer: PayerContents,
	offer: OfferContents,
	chain: Option<ChainHash>,
	amount_msats: Option<u64>,
	features: Option<OfferFeatures>,
	quantity: Option<u64>,
	payer_id: PublicKey,
	payer_note: Option<String>,
}

impl InvoiceRequest {
	/// An unpredictable series of bytes, typically containing information about the derivation of
	/// [`payer_id`].
	///
	/// [`payer_id`]: Self::payer_id
	pub fn metadata(&self) -> Option<&Vec<u8>> {
		self.contents.payer.0.as_ref()
	}

	/// A chain from [`Offer::chains`] that the offer is valid for.
	///
	/// [`Offer::chains`]: crate::offers::offer::Offer::chains
	pub fn chain(&self) -> ChainHash {
		self.contents.chain.unwrap_or_else(|| self.contents.offer.implied_chain())
	}

	/// The amount to pay in msats (i.e., the minimum lightning-payable unit for [`chain`]), which
	/// must be greater than or equal to [`Offer::amount`], converted if necessary.
	///
	/// [`chain`]: Self::chain
	/// [`Offer::amount`]: crate::offers::offer::Offer::amount
	pub fn amount_msats(&self) -> Option<u64> {
		self.contents.amount_msats
	}

	/// Features for paying the invoice.
	pub fn features(&self) -> Option<&OfferFeatures> {
		self.contents.features.as_ref()
	}

	/// The quantity of the offer's item conforming to [`Offer::is_valid_quantity`].
	///
	/// [`Offer::is_valid_quantity`]: crate::offers::offer::Offer::is_valid_quantity
	pub fn quantity(&self) -> Option<u64> {
		self.contents.quantity
	}

	/// A transient pubkey used to sign the invoice request.
	pub fn payer_id(&self) -> PublicKey {
		self.contents.payer_id
	}

	/// Payer provided note to include in the invoice.
	pub fn payer_note(&self) -> Option<&String> {
		self.contents.payer_note.as_ref()
	}

	/// Signature of the invoice request using [`payer_id`].
	///
	/// [`payer_id`]: Self::payer_id
	pub fn signature(&self) -> Option<Signature> {
		self.signature
	}
}

impl Writeable for InvoiceRequest {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		WithoutLength(&self.bytes).write(writer)
	}
}

impl TryFrom<Vec<u8>> for InvoiceRequest {
	type Error = ParseError;

	fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
		let parsed_invoice_request = ParsedMessage::<FullInvoiceRequestTlvStream>::try_from(bytes)?;
		InvoiceRequest::try_from(parsed_invoice_request)
	}
}

tlv_stream!(InvoiceRequestTlvStream, InvoiceRequestTlvStreamRef, 80..160, {
	(80, chain: ChainHash),
	(82, amount: (u64, HighZeroBytesDroppedBigSize)),
	(84, features: OfferFeatures),
	(86, quantity: (u64, HighZeroBytesDroppedBigSize)),
	(88, payer_id: PublicKey),
	(89, payer_note: (String, WithoutLength)),
});

type FullInvoiceRequestTlvStream =
	(PayerTlvStream, OfferTlvStream, InvoiceRequestTlvStream, SignatureTlvStream);

impl SeekReadable for FullInvoiceRequestTlvStream {
	fn read<R: io::Read + io::Seek>(r: &mut R) -> Result<Self, DecodeError> {
		let payer = SeekReadable::read(r)?;
		let offer = SeekReadable::read(r)?;
		let invoice_request = SeekReadable::read(r)?;
		let signature = SeekReadable::read(r)?;

		Ok((payer, offer, invoice_request, signature))
	}
}

type PartialInvoiceRequestTlvStream = (PayerTlvStream, OfferTlvStream, InvoiceRequestTlvStream);

impl TryFrom<ParsedMessage<FullInvoiceRequestTlvStream>> for InvoiceRequest {
	type Error = ParseError;

	fn try_from(invoice_request: ParsedMessage<FullInvoiceRequestTlvStream>)
		-> Result<Self, Self::Error>
	{
		let ParsedMessage {bytes, tlv_stream } = invoice_request;
		let (
			payer_tlv_stream, offer_tlv_stream, invoice_request_tlv_stream,
			SignatureTlvStream { signature },
		) = tlv_stream;
		let contents = InvoiceRequestContents::try_from(
			(payer_tlv_stream, offer_tlv_stream, invoice_request_tlv_stream)
		)?;

		if let Some(signature) = &signature {
			let tag = concat!("lightning", "invoice_request", "signature");
			merkle::verify_signature(signature, tag, &bytes, contents.payer_id)?;
		}

		Ok(InvoiceRequest { bytes, contents, signature })
	}
}

impl TryFrom<PartialInvoiceRequestTlvStream> for InvoiceRequestContents {
	type Error = SemanticError;

	fn try_from(tlv_stream: PartialInvoiceRequestTlvStream) -> Result<Self, Self::Error> {
		let (
			PayerTlvStream { metadata },
			offer_tlv_stream,
			InvoiceRequestTlvStream { chain, amount, features, quantity, payer_id, payer_note },
		) = tlv_stream;

		let payer = PayerContents(metadata);
		let offer = OfferContents::try_from(offer_tlv_stream)?;

		if !offer.supports_chain(chain.unwrap_or_else(|| offer.implied_chain())) {
			return Err(SemanticError::UnsupportedChain);
		}

		let amount_msats = match (offer.amount(), amount) {
			(Some(_), None) => return Err(SemanticError::MissingAmount),
			(Some(Amount::Currency { .. }), _) => return Err(SemanticError::UnsupportedCurrency),
			(_, amount_msats) => amount_msats,
		};

		if let Some(features) = &features {
			if features.requires_unknown_bits() {
				return Err(SemanticError::UnknownRequiredFeatures);
			}
		}

		let expects_quantity = offer.expects_quantity();
		let quantity = match quantity {
			None if expects_quantity => return Err(SemanticError::MissingQuantity),
			Some(_) if !expects_quantity => return Err(SemanticError::UnexpectedQuantity),
			Some(quantity) if !offer.is_valid_quantity(quantity) => {
				return Err(SemanticError::InvalidQuantity);
			}
			quantity => quantity,
		};

		{
			let amount_msats = amount_msats.unwrap_or(offer.amount_msats());
			let quantity = quantity.unwrap_or(1);
			if amount_msats < offer.expected_invoice_amount_msats(quantity) {
				return Err(SemanticError::InsufficientAmount);
			}
		}


		let payer_id = match payer_id {
			None => return Err(SemanticError::MissingPayerId),
			Some(payer_id) => payer_id,
		};

		Ok(InvoiceRequestContents {
			payer, offer, chain, amount_msats, features, quantity, payer_id, payer_note,
		})
	}
}
