// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Data structures and encoding for `invoice_request` messages.
//!
//! An [`InvoiceRequest`] can be either built from a parsed [`Offer`] as an "offer to be paid" or
//! built directly as an "offer for money" (e.g., refund, ATM withdrawal). In the former case, it is
//! typically constructed by a customer and sent to the merchant who had published the corresponding
//! offer. In the latter case, an offer doesn't exist as a precursor to the request. Rather the
//! merchant would typically construct the invoice request and present it to the customer.
//!
//! The recipient of the request responds with an `Invoice`.
//!
//! ```ignore
//! extern crate bitcoin;
//! extern crate lightning;
//!
//! use bitcoin::network::constants::Network;
//! use bitcoin::secp256k1::{KeyPair, PublicKey, Secp256k1, SecretKey};
//! use core::convert::Infallible;
//! use lightning::ln::features::OfferFeatures;
//! use lightning::offers::offer::Offer;
//! use lightning::util::ser::Writeable;
//!
//! # fn parse() -> Result<(), lightning::offers::parse::ParseError> {
//! let secp_ctx = Secp256k1::new();
//! let keys = KeyPair::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[42; 32])?);
//! let pubkey = PublicKey::from(keys);
//! let mut buffer = Vec::new();
//!
//! // "offer to be paid" flow
//! "lno1qcp4256ypq"
//!     .parse::<Offer>()?
//!     .request_invoice(vec![42; 64], pubkey)?
//!     .chain(Network::Testnet)?
//!     .amount_msats(1000)?
//!     .quantity(5)?
//!     .payer_note("foo".to_string())
//!     .build()?
//!     .sign::<_, Infallible>(|digest| Ok(secp_ctx.sign_schnorr_no_aux_rand(digest, &keys)))
//!     .expect("failed verifying signature")
//!     .write(&mut buffer)
//!     .unwrap();
//! # Ok(())
//! # }
//! ```

use bitcoin::blockdata::constants::ChainHash;
use bitcoin::network::constants::Network;
use bitcoin::secp256k1::{Message, PublicKey};
use bitcoin::secp256k1::schnorr::Signature;
use core::convert::TryFrom;
use crate::io;
use crate::ln::features::InvoiceRequestFeatures;
use crate::ln::msgs::DecodeError;
use crate::offers::merkle::{SignError, SignatureTlvStream, SignatureTlvStreamRef, self};
use crate::offers::offer::{Offer, OfferContents, OfferTlvStream, OfferTlvStreamRef};
use crate::offers::parse::{ParseError, ParsedMessage, SemanticError};
use crate::offers::payer::{PayerContents, PayerTlvStream, PayerTlvStreamRef};
use crate::util::ser::{HighZeroBytesDroppedBigSize, SeekReadable, WithoutLength, Writeable, Writer};
use crate::util::string::PrintableString;

use crate::prelude::*;

const SIGNATURE_TAG: &'static str = concat!("lightning", "invoice_request", "signature");

/// Builds an [`InvoiceRequest`] from an [`Offer`] for the "offer to be paid" flow.
///
/// See [module-level documentation] for usage.
///
/// [module-level documentation]: self
pub struct InvoiceRequestBuilder<'a> {
	offer: &'a Offer,
	invoice_request: InvoiceRequestContents,
}

impl<'a> InvoiceRequestBuilder<'a> {
	pub(super) fn new(offer: &'a Offer, metadata: Vec<u8>, payer_id: PublicKey) -> Self {
		Self {
			offer,
			invoice_request: InvoiceRequestContents {
				payer: PayerContents(metadata), offer: offer.contents.clone(), chain: None,
				amount_msats: None, features: InvoiceRequestFeatures::empty(), quantity: None,
				payer_id, payer_note: None,
			},
		}
	}

	/// Sets the [`InvoiceRequest::chain`] of the given [`Network`] for paying an invoice. If not
	/// called, [`Network::Bitcoin`] is assumed. Errors if the chain for `network` is not supported
	/// by the offer.
	///
	/// Successive calls to this method will override the previous setting.
	pub fn chain(mut self, network: Network) -> Result<Self, SemanticError> {
		let chain = ChainHash::using_genesis_block(network);
		if !self.offer.supports_chain(chain) {
			return Err(SemanticError::UnsupportedChain);
		}

		self.invoice_request.chain = Some(chain);
		Ok(self)
	}

	/// Sets the [`InvoiceRequest::amount_msats`] for paying an invoice. Errors if `amount_msats` is
	/// not at least the expected invoice amount (i.e., [`Offer::amount`] times [`quantity`]).
	///
	/// Successive calls to this method will override the previous setting.
	///
	/// [`quantity`]: Self::quantity
	pub fn amount_msats(mut self, amount_msats: u64) -> Result<Self, SemanticError> {
		self.invoice_request.offer.check_amount_msats_for_quantity(
			Some(amount_msats), self.invoice_request.quantity
		)?;
		self.invoice_request.amount_msats = Some(amount_msats);
		Ok(self)
	}

	/// Sets [`InvoiceRequest::quantity`] of items. If not set, `1` is assumed. Errors if `quantity`
	/// does not conform to [`Offer::is_valid_quantity`].
	///
	/// Successive calls to this method will override the previous setting.
	pub fn quantity(mut self, quantity: u64) -> Result<Self, SemanticError> {
		self.invoice_request.offer.check_quantity(Some(quantity))?;
		self.invoice_request.quantity = Some(quantity);
		Ok(self)
	}

	/// Sets the [`InvoiceRequest::payer_note`].
	///
	/// Successive calls to this method will override the previous setting.
	pub fn payer_note(mut self, payer_note: String) -> Self {
		self.invoice_request.payer_note = Some(payer_note);
		self
	}

	/// Builds an unsigned [`InvoiceRequest`] after checking for valid semantics. It can be signed
	/// by [`UnsignedInvoiceRequest::sign`].
	pub fn build(mut self) -> Result<UnsignedInvoiceRequest<'a>, SemanticError> {
		#[cfg(feature = "std")] {
			if self.offer.is_expired() {
				return Err(SemanticError::AlreadyExpired);
			}
		}

		let chain = self.invoice_request.chain();
		if !self.offer.supports_chain(chain) {
			return Err(SemanticError::UnsupportedChain);
		}

		if chain == self.offer.implied_chain() {
			self.invoice_request.chain = None;
		}

		if self.offer.amount().is_none() && self.invoice_request.amount_msats.is_none() {
			return Err(SemanticError::MissingAmount);
		}

		self.invoice_request.offer.check_quantity(self.invoice_request.quantity)?;
		self.invoice_request.offer.check_amount_msats_for_quantity(
			self.invoice_request.amount_msats, self.invoice_request.quantity
		)?;

		let InvoiceRequestBuilder { offer, invoice_request } = self;
		Ok(UnsignedInvoiceRequest { offer, invoice_request })
	}
}

/// A semantically valid [`InvoiceRequest`] that hasn't been signed.
pub struct UnsignedInvoiceRequest<'a> {
	offer: &'a Offer,
	invoice_request: InvoiceRequestContents,
}

impl<'a> UnsignedInvoiceRequest<'a> {
	/// Signs the invoice request using the given function.
	pub fn sign<F, E>(self, sign: F) -> Result<InvoiceRequest, SignError<E>>
	where
		F: FnOnce(&Message) -> Result<Signature, E>
	{
		// Use the offer bytes instead of the offer TLV stream as the offer may have contained
		// unknown TLV records, which are not stored in `OfferContents`.
		let (payer_tlv_stream, _offer_tlv_stream, invoice_request_tlv_stream) =
			self.invoice_request.as_tlv_stream();
		let offer_bytes = WithoutLength(&self.offer.bytes);
		let unsigned_tlv_stream = (payer_tlv_stream, offer_bytes, invoice_request_tlv_stream);

		let mut bytes = Vec::new();
		unsigned_tlv_stream.write(&mut bytes).unwrap();

		let pubkey = self.invoice_request.payer_id;
		let signature = Some(merkle::sign_message(sign, SIGNATURE_TAG, &bytes, pubkey)?);

		// Append the signature TLV record to the bytes.
		let signature_tlv_stream = SignatureTlvStreamRef {
			signature: signature.as_ref(),
		};
		signature_tlv_stream.write(&mut bytes).unwrap();

		Ok(InvoiceRequest {
			bytes,
			contents: self.invoice_request,
			signature,
		})
	}
}

/// An `InvoiceRequest` is a request for an `Invoice` formulated from an [`Offer`].
///
/// An offer may provide choices such as quantity, amount, chain, features, etc. An invoice request
/// specifies these such that its recipient can send an invoice for payment.
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
pub(super) struct InvoiceRequestContents {
	payer: PayerContents,
	offer: OfferContents,
	chain: Option<ChainHash>,
	amount_msats: Option<u64>,
	features: InvoiceRequestFeatures,
	quantity: Option<u64>,
	payer_id: PublicKey,
	payer_note: Option<String>,
}

impl InvoiceRequest {
	/// An unpredictable series of bytes, typically containing information about the derivation of
	/// [`payer_id`].
	///
	/// [`payer_id`]: Self::payer_id
	pub fn metadata(&self) -> &[u8] {
		&self.contents.payer.0[..]
	}

	/// A chain from [`Offer::chains`] that the offer is valid for.
	pub fn chain(&self) -> ChainHash {
		self.contents.chain()
	}

	/// The amount to pay in msats (i.e., the minimum lightning-payable unit for [`chain`]), which
	/// must be greater than or equal to [`Offer::amount`], converted if necessary.
	///
	/// [`chain`]: Self::chain
	pub fn amount_msats(&self) -> Option<u64> {
		self.contents.amount_msats
	}

	/// Features for paying the invoice.
	pub fn features(&self) -> &InvoiceRequestFeatures {
		&self.contents.features
	}

	/// The quantity of the offer's item conforming to [`Offer::is_valid_quantity`].
	pub fn quantity(&self) -> Option<u64> {
		self.contents.quantity
	}

	/// A possibly transient pubkey used to sign the invoice request.
	pub fn payer_id(&self) -> PublicKey {
		self.contents.payer_id
	}

	/// A payer-provided note which will be seen by the recipient and reflected back in the invoice
	/// response.
	pub fn payer_note(&self) -> Option<PrintableString> {
		self.contents.payer_note.as_ref().map(|payer_note| PrintableString(payer_note.as_str()))
	}

	/// Signature of the invoice request using [`payer_id`].
	///
	/// [`payer_id`]: Self::payer_id
	pub fn signature(&self) -> Option<Signature> {
		self.signature
	}
}

impl InvoiceRequestContents {
	fn chain(&self) -> ChainHash {
		self.chain.unwrap_or_else(|| self.offer.implied_chain())
	}

	pub(super) fn as_tlv_stream(&self) -> PartialInvoiceRequestTlvStreamRef {
		let payer = PayerTlvStreamRef {
			metadata: Some(&self.payer.0),
		};

		let offer = self.offer.as_tlv_stream();

		let features = {
			if self.features == InvoiceRequestFeatures::empty() { None }
			else { Some(&self.features) }
		};

		let invoice_request = InvoiceRequestTlvStreamRef {
			chain: self.chain.as_ref(),
			amount: self.amount_msats,
			features,
			quantity: self.quantity,
			payer_id: Some(&self.payer_id),
			payer_note: self.payer_note.as_ref(),
		};

		(payer, offer, invoice_request)
	}
}

impl Writeable for InvoiceRequest {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		WithoutLength(&self.bytes).write(writer)
	}
}

impl Writeable for InvoiceRequestContents {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		self.as_tlv_stream().write(writer)
	}
}

tlv_stream!(InvoiceRequestTlvStream, InvoiceRequestTlvStreamRef, 80..160, {
	(80, chain: ChainHash),
	(82, amount: (u64, HighZeroBytesDroppedBigSize)),
	(84, features: InvoiceRequestFeatures),
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

type PartialInvoiceRequestTlvStreamRef<'a> = (
	PayerTlvStreamRef<'a>,
	OfferTlvStreamRef<'a>,
	InvoiceRequestTlvStreamRef<'a>,
);

impl TryFrom<Vec<u8>> for InvoiceRequest {
	type Error = ParseError;

	fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
		let invoice_request = ParsedMessage::<FullInvoiceRequestTlvStream>::try_from(bytes)?;
		let ParsedMessage { bytes, tlv_stream } = invoice_request;
		let (
			payer_tlv_stream, offer_tlv_stream, invoice_request_tlv_stream,
			SignatureTlvStream { signature },
		) = tlv_stream;
		let contents = InvoiceRequestContents::try_from(
			(payer_tlv_stream, offer_tlv_stream, invoice_request_tlv_stream)
		)?;

		if let Some(signature) = &signature {
			merkle::verify_signature(signature, SIGNATURE_TAG, &bytes, contents.payer_id)?;
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

		let payer = match metadata {
			None => return Err(SemanticError::MissingPayerMetadata),
			Some(metadata) => PayerContents(metadata),
		};
		let offer = OfferContents::try_from(offer_tlv_stream)?;

		if !offer.supports_chain(chain.unwrap_or_else(|| offer.implied_chain())) {
			return Err(SemanticError::UnsupportedChain);
		}

		if offer.amount().is_none() && amount.is_none() {
			return Err(SemanticError::MissingAmount);
		}

		offer.check_quantity(quantity)?;
		offer.check_amount_msats_for_quantity(amount, quantity)?;

		let features = features.unwrap_or_else(InvoiceRequestFeatures::empty);

		let payer_id = match payer_id {
			None => return Err(SemanticError::MissingPayerId),
			Some(payer_id) => payer_id,
		};

		Ok(InvoiceRequestContents {
			payer, offer, chain, amount_msats: amount, features, quantity, payer_id, payer_note,
		})
	}
}

#[cfg(test)]
mod tests {
	use super::InvoiceRequest;

	use bitcoin::secp256k1::{KeyPair, Secp256k1, SecretKey};
	use core::convert::{Infallible, TryFrom};
	use crate::ln::msgs::DecodeError;
	use crate::offers::offer::OfferBuilder;
	use crate::offers::parse::ParseError;
	use crate::util::ser::{BigSize, Writeable};

	#[test]
	fn fails_parsing_invoice_request_with_extra_tlv_records() {
		let secp_ctx = Secp256k1::new();
		let keys = KeyPair::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[42; 32]).unwrap());
		let invoice_request = OfferBuilder::new("foo".into(), keys.public_key())
			.amount_msats(1000)
			.build().unwrap()
			.request_invoice(vec![1; 32], keys.public_key()).unwrap()
			.build().unwrap()
			.sign::<_, Infallible>(|digest| Ok(secp_ctx.sign_schnorr_no_aux_rand(digest, &keys)))
			.unwrap();

		let mut encoded_invoice_request = Vec::new();
		invoice_request.write(&mut encoded_invoice_request).unwrap();
		BigSize(1002).write(&mut encoded_invoice_request).unwrap();
		BigSize(32).write(&mut encoded_invoice_request).unwrap();
		[42u8; 32].write(&mut encoded_invoice_request).unwrap();

		match InvoiceRequest::try_from(encoded_invoice_request) {
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, ParseError::Decode(DecodeError::InvalidValue)),
		}
	}
}
