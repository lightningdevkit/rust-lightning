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
//! merchant would typically construct the invoice request and presents it to the customer.
//!
//! The recipient of the request responds with an `Invoice`.
//! ```
//! extern crate bitcoin;
//! extern crate lightning;
//!
//! use bitcoin::network::constants::Network;
//! use bitcoin::secp256k1::{KeyPair, PublicKey, Secp256k1, SecretKey};
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
//!     .request_invoice(pubkey)
//!     .metadata(vec![42; 64])
//!     .chain(Network::Testnet)?
//!     .amount_msats(1000)
//!     .quantity(5)?
//!     .payer_note("foo".to_string())
//!     .build()?
//!     .sign(|digest| secp_ctx.sign_schnorr_no_aux_rand(digest, &keys))?
//!     .write(&mut buffer)
//!     .unwrap();
//! # Ok(())
//! # }
//! ```

use bitcoin::blockdata::constants::ChainHash;
use bitcoin::network::constants::Network;
use bitcoin::secp256k1::{Message, PublicKey, self};
use bitcoin::secp256k1::schnorr::Signature;
use core::convert::TryFrom;
use core::str::FromStr;
use crate::io;
use crate::ln::features::OfferFeatures;
use crate::ln::msgs::DecodeError;
use crate::offers::merkle::{SignatureTlvStream, SignatureTlvStreamRef, self};
use crate::offers::offer::{Amount, Offer, OfferContents, OfferTlvStream, OfferTlvStreamRef, SendInvoiceOfferContents};
use crate::offers::parse::{Bech32Encode, ParseError, ParsedMessage, SemanticError};
use crate::offers::payer::{PayerContents, PayerTlvStream, PayerTlvStreamRef};
use crate::util::ser::{HighZeroBytesDroppedBigSize, SeekReadable, WithoutLength, Writeable, Writer};

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
	pub(super) fn new(offer: &'a Offer, payer_id: PublicKey) -> Self {
		Self {
			offer,
			invoice_request: InvoiceRequestContents {
				payer: PayerContents(None), offer: offer.contents.clone(), chain: None,
				amount_msats: None, features: None, quantity: None, payer_id, payer_note: None,
			},
		}
	}

	/// Sets the metadata for the invoice request. Useful for containing information about the
	/// derivation of [`InvoiceRequest::payer_id`]. This should not leak any information such as
	/// using a simple BIP-32 derivation path.
	///
	/// Successive calls to this method will override the previous setting.
	pub fn metadata(mut self, metadata: Vec<u8>) -> Self {
		self.invoice_request.payer = PayerContents(Some(metadata));
		self
	}

	/// Sets the chain hash of the given [`Network`] for paying an invoice. If not called,
	/// [`Network::Bitcoin`] is assumed. Must be supported by the offer.
	///
	/// Successive calls to this method will override the previous setting.
	pub fn chain(mut self, network: Network) -> Result<Self, SemanticError> {
		let chain = ChainHash::using_genesis_block(network);
		if !self.offer.supports_chain(chain) {
			return Err(SemanticError::UnsupportedChain)
		}

		self.invoice_request.chain = Some(chain);
		Ok(self)
	}

	/// Sets the amount for paying an invoice. Must be at least the base invoice amount (i.e.,
	/// [`Offer::amount`] times [`quantity`]).
	///
	/// Successive calls to this method will override the previous setting.
	///
	/// [`quantity`]: Self::quantity
	pub fn amount_msats(mut self, amount_msats: u64) -> Self {
		self.invoice_request.amount_msats = Some(amount_msats);
		self
	}

	/// Sets the features for the invoice request.
	///
	/// Successive calls to this method will override the previous setting.
	#[cfg(test)]
	pub fn features(mut self, features: OfferFeatures) -> Self {
		self.invoice_request.features = Some(features);
		self
	}

	/// Sets a quantity of items for the invoice request. If not set, `1` is assumed. Must conform
	/// to [`Offer::is_valid_quantity`].
	///
	/// Successive calls to this method will override the previous setting.
	pub fn quantity(mut self, quantity: u64) -> Result<Self, SemanticError> {
		if !self.offer.is_valid_quantity(quantity) {
			return Err(SemanticError::InvalidQuantity);
		}

		self.invoice_request.quantity = Some(quantity);
		Ok(self)
	}

	/// Sets a note for the invoice request.
	///
	/// Successive calls to this method will override the previous setting.
	pub fn payer_note(mut self, payer_note: String) -> Self {
		self.invoice_request.payer_note = Some(payer_note);
		self
	}

	/// Builds an [`InvoiceRequest`] after checking for valid semantics.
	pub fn build(self) -> Result<UnsignedInvoiceRequest<'a>, SemanticError> {
		if !self.offer.supports_chain(self.invoice_request.chain()) {
			return Err(SemanticError::UnsupportedChain);
		}

		if let Some(amount) = self.offer.amount() {
			if self.invoice_request.amount_msats.is_none() {
				return Err(SemanticError::MissingAmount);
			}

			if let Amount::Currency { .. } = amount {
				return Err(SemanticError::UnsupportedCurrency);
			}
		}

		if self.offer.expects_quantity() && self.invoice_request.quantity.is_none() {
			return Err(SemanticError::InvalidQuantity);
		}

		let amount_msats = self.invoice_request.amount_msats.unwrap_or(self.offer.amount_msats());
		let quantity = self.invoice_request.quantity.unwrap_or(1);
		if amount_msats < self.offer.expected_invoice_amount_msats(quantity) {
			return Err(SemanticError::InsufficientAmount);
		}

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
	pub fn sign<F>(self, sign: F) -> Result<InvoiceRequest, secp256k1::Error>
	where F: FnOnce(&Message) -> Signature
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
	pub fn features(&self) -> Option<&OfferFeatures> {
		self.contents.features.as_ref()
	}

	/// The quantity of the offer's item conforming to [`Offer::is_valid_quantity`].
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

impl InvoiceRequestContents {
	fn chain(&self) -> ChainHash {
		self.chain.unwrap_or_else(|| self.offer.implied_chain())
	}

	pub(super) fn as_tlv_stream(&self) -> PartialInvoiceRequestTlvStreamRef {
		let payer = PayerTlvStreamRef {
			metadata: self.payer.0.as_ref(),
		};

		let offer = self.offer.as_tlv_stream();

		let invoice_request = InvoiceRequestTlvStreamRef {
			chain: self.chain.as_ref(),
			amount: self.amount_msats,
			features: self.features.as_ref(),
			quantity: self.quantity,
			payer_id: Some(&self.payer_id),
			payer_note: self.payer_note.as_ref(),
		};

		(payer, offer, invoice_request)
	}
}

impl AsRef<[u8]> for InvoiceRequest {
	fn as_ref(&self) -> &[u8] {
		&self.bytes
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

impl Bech32Encode for InvoiceRequest {
	const BECH32_HRP: &'static str = "lnr";
}

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

impl FromStr for InvoiceRequest {
	type Err = ParseError;

	fn from_str(s: &str) -> Result<Self, <Self as FromStr>::Err> {
		InvoiceRequest::from_bech32_str(s)
	}
}

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

		let payer = PayerContents(metadata);
		let offer = match offer_tlv_stream.node_id {
			Some(_) => OfferContents::try_from(offer_tlv_stream)?,
			None => SendInvoiceOfferContents::try_from(offer_tlv_stream)?.0,
		};

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

impl core::fmt::Display for InvoiceRequest {
	fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
		self.fmt_bech32_str(f)
	}
}

#[cfg(test)]
mod tests {
	use super::InvoiceRequest;

	use bitcoin::secp256k1::{KeyPair, Secp256k1, SecretKey};
	use core::convert::TryFrom;
	use crate::ln::msgs::DecodeError;
	use crate::offers::offer::OfferBuilder;
	use crate::offers::parse::ParseError;
	use crate::util::ser::{BigSize, Writeable};

	#[test]
	fn fails_parsing_invoice_request_with_extra_tlv_records() {
		let secp_ctx = Secp256k1::new();
		let keys = KeyPair::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[42; 32]).unwrap());
		let invoice_request = OfferBuilder::new("foo".into(), keys.public_key())
			.build()
			.unwrap()
			.request_invoice(keys.public_key())
			.build()
			.unwrap()
			.sign(|digest| secp_ctx.sign_schnorr_no_aux_rand(digest, &keys))
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
