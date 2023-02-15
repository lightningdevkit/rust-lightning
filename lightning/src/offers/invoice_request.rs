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
//! An [`InvoiceRequest`] can be built from a parsed [`Offer`] as an "offer to be paid". It is
//! typically constructed by a customer and sent to the merchant who had published the corresponding
//! offer. The recipient of the request responds with an [`Invoice`].
//!
//! For an "offer for money" (e.g., refund, ATM withdrawal), where an offer doesn't exist as a
//! precursor, see [`Refund`].
//!
//! [`Invoice`]: crate::offers::invoice::Invoice
//! [`Refund`]: crate::offers::refund::Refund
//!
//! ```
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
use crate::ln::PaymentHash;
use crate::ln::features::InvoiceRequestFeatures;
use crate::ln::msgs::DecodeError;
use crate::offers::invoice::{BlindedPayInfo, InvoiceBuilder};
use crate::offers::merkle::{SignError, SignatureTlvStream, SignatureTlvStreamRef, self};
use crate::offers::offer::{Offer, OfferContents, OfferTlvStream, OfferTlvStreamRef};
use crate::offers::parse::{ParseError, ParsedMessage, SemanticError};
use crate::offers::payer::{PayerContents, PayerTlvStream, PayerTlvStreamRef};
use crate::onion_message::BlindedPath;
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

#[cfg(test)]
impl<'a> InvoiceRequestBuilder<'a> {
	fn chain_unchecked(mut self, network: Network) -> Self {
		let chain = ChainHash::using_genesis_block(network);
		self.invoice_request.chain = Some(chain);
		self
	}

	fn amount_msats_unchecked(mut self, amount_msats: u64) -> Self {
		self.invoice_request.amount_msats = Some(amount_msats);
		self
	}

	fn features_unchecked(mut self, features: InvoiceRequestFeatures) -> Self {
		self.invoice_request.features = features;
		self
	}

	fn quantity_unchecked(mut self, quantity: u64) -> Self {
		self.invoice_request.quantity = Some(quantity);
		self
	}

	pub(super) fn build_unchecked(self) -> UnsignedInvoiceRequest<'a> {
		let InvoiceRequestBuilder { offer, invoice_request } = self;
		UnsignedInvoiceRequest { offer, invoice_request }
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
		let signature = merkle::sign_message(sign, SIGNATURE_TAG, &bytes, pubkey)?;

		// Append the signature TLV record to the bytes.
		let signature_tlv_stream = SignatureTlvStreamRef {
			signature: Some(&signature),
		};
		signature_tlv_stream.write(&mut bytes).unwrap();

		Ok(InvoiceRequest {
			bytes,
			contents: self.invoice_request,
			signature,
		})
	}
}

/// An `InvoiceRequest` is a request for an [`Invoice`] formulated from an [`Offer`].
///
/// An offer may provide choices such as quantity, amount, chain, features, etc. An invoice request
/// specifies these such that its recipient can send an invoice for payment.
///
/// [`Invoice`]: crate::offers::invoice::Invoice
/// [`Offer`]: crate::offers::offer::Offer
#[derive(Clone, Debug, PartialEq)]
pub struct InvoiceRequest {
	pub(super) bytes: Vec<u8>,
	pub(super) contents: InvoiceRequestContents,
	signature: Signature,
}

/// The contents of an [`InvoiceRequest`], which may be shared with an [`Invoice`].
///
/// [`Invoice`]: crate::offers::invoice::Invoice
#[derive(Clone, Debug, PartialEq)]
pub(super) struct InvoiceRequestContents {
	payer: PayerContents,
	pub(super) offer: OfferContents,
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

	/// Features pertaining to requesting an invoice.
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
	pub fn signature(&self) -> Signature {
		self.signature
	}

	/// Creates an [`Invoice`] for the request with the given required fields and using the
	/// [`Duration`] since [`std::time::SystemTime::UNIX_EPOCH`] as the creation time.
	///
	/// See [`InvoiceRequest::respond_with_no_std`] for further details where the aforementioned
	/// creation time is used for the `created_at` parameter.
	///
	/// [`Invoice`]: crate::offers::invoice::Invoice
	/// [`Duration`]: core::time::Duration
	#[cfg(feature = "std")]
	pub fn respond_with(
		&self, payment_paths: Vec<(BlindedPath, BlindedPayInfo)>, payment_hash: PaymentHash
	) -> Result<InvoiceBuilder, SemanticError> {
		let created_at = std::time::SystemTime::now()
			.duration_since(std::time::SystemTime::UNIX_EPOCH)
			.expect("SystemTime::now() should come after SystemTime::UNIX_EPOCH");

		self.respond_with_no_std(payment_paths, payment_hash, created_at)
	}

	/// Creates an [`Invoice`] for the request with the given required fields.
	///
	/// Unless [`InvoiceBuilder::relative_expiry`] is set, the invoice will expire two hours after
	/// `created_at`, which is used to set [`Invoice::created_at`]. Useful for `no-std` builds where
	/// [`std::time::SystemTime`] is not available.
	///
	/// The caller is expected to remember the preimage of `payment_hash` in order to claim a payment
	/// for the invoice.
	///
	/// The `payment_paths` parameter is useful for maintaining the payment recipient's privacy. It
	/// must contain one or more elements ordered from most-preferred to least-preferred, if there's
	/// a preference. Note, however, that any privacy is lost if a public node id was used for
	/// [`Offer::signing_pubkey`].
	///
	/// Errors if the request contains unknown required features.
	///
	/// [`Invoice`]: crate::offers::invoice::Invoice
	/// [`Invoice::created_at`]: crate::offers::invoice::Invoice::created_at
	pub fn respond_with_no_std(
		&self, payment_paths: Vec<(BlindedPath, BlindedPayInfo)>, payment_hash: PaymentHash,
		created_at: core::time::Duration
	) -> Result<InvoiceBuilder, SemanticError> {
		if self.features().requires_unknown_bits() {
			return Err(SemanticError::UnknownRequiredFeatures);
		}

		InvoiceBuilder::for_offer(self, payment_paths, created_at, payment_hash)
	}

	#[cfg(test)]
	fn as_tlv_stream(&self) -> FullInvoiceRequestTlvStreamRef {
		let (payer_tlv_stream, offer_tlv_stream, invoice_request_tlv_stream) =
			self.contents.as_tlv_stream();
		let signature_tlv_stream = SignatureTlvStreamRef {
			signature: Some(&self.signature),
		};
		(payer_tlv_stream, offer_tlv_stream, invoice_request_tlv_stream, signature_tlv_stream)
	}
}

impl InvoiceRequestContents {
	pub(super) fn chain(&self) -> ChainHash {
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
	(84, features: (InvoiceRequestFeatures, WithoutLength)),
	(86, quantity: (u64, HighZeroBytesDroppedBigSize)),
	(88, payer_id: PublicKey),
	(89, payer_note: (String, WithoutLength)),
});

type FullInvoiceRequestTlvStream =
	(PayerTlvStream, OfferTlvStream, InvoiceRequestTlvStream, SignatureTlvStream);

#[cfg(test)]
type FullInvoiceRequestTlvStreamRef<'a> = (
	PayerTlvStreamRef<'a>,
	OfferTlvStreamRef<'a>,
	InvoiceRequestTlvStreamRef<'a>,
	SignatureTlvStreamRef<'a>,
);

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

		let signature = match signature {
			None => return Err(ParseError::InvalidSemantics(SemanticError::MissingSignature)),
			Some(signature) => signature,
		};
		merkle::verify_signature(&signature, SIGNATURE_TAG, &bytes, contents.payer_id)?;

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
	use super::{InvoiceRequest, InvoiceRequestTlvStreamRef, SIGNATURE_TAG};

	use bitcoin::blockdata::constants::ChainHash;
	use bitcoin::network::constants::Network;
	use bitcoin::secp256k1::{KeyPair, Message, PublicKey, Secp256k1, SecretKey, self};
	use bitcoin::secp256k1::schnorr::Signature;
	use core::convert::{Infallible, TryFrom};
	use core::num::NonZeroU64;
	#[cfg(feature = "std")]
	use core::time::Duration;
	use crate::ln::features::InvoiceRequestFeatures;
	use crate::ln::msgs::{DecodeError, MAX_VALUE_MSAT};
	use crate::offers::merkle::{SignError, SignatureTlvStreamRef, self};
	use crate::offers::offer::{Amount, OfferBuilder, OfferTlvStreamRef, Quantity};
	use crate::offers::parse::{ParseError, SemanticError};
	use crate::offers::payer::PayerTlvStreamRef;
	use crate::util::ser::{BigSize, Writeable};
	use crate::util::string::PrintableString;

	fn payer_keys() -> KeyPair {
		let secp_ctx = Secp256k1::new();
		KeyPair::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[42; 32]).unwrap())
	}

	fn payer_sign(digest: &Message) -> Result<Signature, Infallible> {
		let secp_ctx = Secp256k1::new();
		let keys = KeyPair::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[42; 32]).unwrap());
		Ok(secp_ctx.sign_schnorr_no_aux_rand(digest, &keys))
	}

	fn payer_pubkey() -> PublicKey {
		payer_keys().public_key()
	}

	fn recipient_sign(digest: &Message) -> Result<Signature, Infallible> {
		let secp_ctx = Secp256k1::new();
		let keys = KeyPair::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[43; 32]).unwrap());
		Ok(secp_ctx.sign_schnorr_no_aux_rand(digest, &keys))
	}

	fn recipient_pubkey() -> PublicKey {
		let secp_ctx = Secp256k1::new();
		KeyPair::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[43; 32]).unwrap()).public_key()
	}

	#[test]
	fn builds_invoice_request_with_defaults() {
		let invoice_request = OfferBuilder::new("foo".into(), recipient_pubkey())
			.amount_msats(1000)
			.build().unwrap()
			.request_invoice(vec![1; 32], payer_pubkey()).unwrap()
			.build().unwrap()
			.sign(payer_sign).unwrap();

		let mut buffer = Vec::new();
		invoice_request.write(&mut buffer).unwrap();

		assert_eq!(invoice_request.bytes, buffer.as_slice());
		assert_eq!(invoice_request.metadata(), &[1; 32]);
		assert_eq!(invoice_request.chain(), ChainHash::using_genesis_block(Network::Bitcoin));
		assert_eq!(invoice_request.amount_msats(), None);
		assert_eq!(invoice_request.features(), &InvoiceRequestFeatures::empty());
		assert_eq!(invoice_request.quantity(), None);
		assert_eq!(invoice_request.payer_id(), payer_pubkey());
		assert_eq!(invoice_request.payer_note(), None);
		assert!(
			merkle::verify_signature(
				&invoice_request.signature, SIGNATURE_TAG, &invoice_request.bytes, payer_pubkey()
			).is_ok()
		);

		assert_eq!(
			invoice_request.as_tlv_stream(),
			(
				PayerTlvStreamRef { metadata: Some(&vec![1; 32]) },
				OfferTlvStreamRef {
					chains: None,
					metadata: None,
					currency: None,
					amount: Some(1000),
					description: Some(&String::from("foo")),
					features: None,
					absolute_expiry: None,
					paths: None,
					issuer: None,
					quantity_max: None,
					node_id: Some(&recipient_pubkey()),
				},
				InvoiceRequestTlvStreamRef {
					chain: None,
					amount: None,
					features: None,
					quantity: None,
					payer_id: Some(&payer_pubkey()),
					payer_note: None,
				},
				SignatureTlvStreamRef { signature: Some(&invoice_request.signature()) },
			),
		);

		if let Err(e) = InvoiceRequest::try_from(buffer) {
			panic!("error parsing invoice request: {:?}", e);
		}
	}

	#[cfg(feature = "std")]
	#[test]
	fn builds_invoice_request_from_offer_with_expiration() {
		let future_expiry = Duration::from_secs(u64::max_value());
		let past_expiry = Duration::from_secs(0);

		if let Err(e) = OfferBuilder::new("foo".into(), recipient_pubkey())
			.amount_msats(1000)
			.absolute_expiry(future_expiry)
			.build().unwrap()
			.request_invoice(vec![1; 32], payer_pubkey()).unwrap()
			.build()
		{
			panic!("error building invoice_request: {:?}", e);
		}

		match OfferBuilder::new("foo".into(), recipient_pubkey())
			.amount_msats(1000)
			.absolute_expiry(past_expiry)
			.build().unwrap()
			.request_invoice(vec![1; 32], payer_pubkey()).unwrap()
			.build()
		{
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, SemanticError::AlreadyExpired),
		}
	}

	#[test]
	fn builds_invoice_request_with_chain() {
		let mainnet = ChainHash::using_genesis_block(Network::Bitcoin);
		let testnet = ChainHash::using_genesis_block(Network::Testnet);

		let invoice_request = OfferBuilder::new("foo".into(), recipient_pubkey())
			.amount_msats(1000)
			.build().unwrap()
			.request_invoice(vec![1; 32], payer_pubkey()).unwrap()
			.chain(Network::Bitcoin).unwrap()
			.build().unwrap()
			.sign(payer_sign).unwrap();
		let (_, _, tlv_stream, _) = invoice_request.as_tlv_stream();
		assert_eq!(invoice_request.chain(), mainnet);
		assert_eq!(tlv_stream.chain, None);

		let invoice_request = OfferBuilder::new("foo".into(), recipient_pubkey())
			.amount_msats(1000)
			.chain(Network::Testnet)
			.build().unwrap()
			.request_invoice(vec![1; 32], payer_pubkey()).unwrap()
			.chain(Network::Testnet).unwrap()
			.build().unwrap()
			.sign(payer_sign).unwrap();
		let (_, _, tlv_stream, _) = invoice_request.as_tlv_stream();
		assert_eq!(invoice_request.chain(), testnet);
		assert_eq!(tlv_stream.chain, Some(&testnet));

		let invoice_request = OfferBuilder::new("foo".into(), recipient_pubkey())
			.amount_msats(1000)
			.chain(Network::Bitcoin)
			.chain(Network::Testnet)
			.build().unwrap()
			.request_invoice(vec![1; 32], payer_pubkey()).unwrap()
			.chain(Network::Bitcoin).unwrap()
			.build().unwrap()
			.sign(payer_sign).unwrap();
		let (_, _, tlv_stream, _) = invoice_request.as_tlv_stream();
		assert_eq!(invoice_request.chain(), mainnet);
		assert_eq!(tlv_stream.chain, None);

		let invoice_request = OfferBuilder::new("foo".into(), recipient_pubkey())
			.amount_msats(1000)
			.chain(Network::Bitcoin)
			.chain(Network::Testnet)
			.build().unwrap()
			.request_invoice(vec![1; 32], payer_pubkey()).unwrap()
			.chain(Network::Bitcoin).unwrap()
			.chain(Network::Testnet).unwrap()
			.build().unwrap()
			.sign(payer_sign).unwrap();
		let (_, _, tlv_stream, _) = invoice_request.as_tlv_stream();
		assert_eq!(invoice_request.chain(), testnet);
		assert_eq!(tlv_stream.chain, Some(&testnet));

		match OfferBuilder::new("foo".into(), recipient_pubkey())
			.amount_msats(1000)
			.chain(Network::Testnet)
			.build().unwrap()
			.request_invoice(vec![1; 32], payer_pubkey()).unwrap()
			.chain(Network::Bitcoin)
		{
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, SemanticError::UnsupportedChain),
		}

		match OfferBuilder::new("foo".into(), recipient_pubkey())
			.amount_msats(1000)
			.chain(Network::Testnet)
			.build().unwrap()
			.request_invoice(vec![1; 32], payer_pubkey()).unwrap()
			.build()
		{
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, SemanticError::UnsupportedChain),
		}
	}

	#[test]
	fn builds_invoice_request_with_amount() {
		let invoice_request = OfferBuilder::new("foo".into(), recipient_pubkey())
			.amount_msats(1000)
			.build().unwrap()
			.request_invoice(vec![1; 32], payer_pubkey()).unwrap()
			.amount_msats(1000).unwrap()
			.build().unwrap()
			.sign(payer_sign).unwrap();
		let (_, _, tlv_stream, _) = invoice_request.as_tlv_stream();
		assert_eq!(invoice_request.amount_msats(), Some(1000));
		assert_eq!(tlv_stream.amount, Some(1000));

		let invoice_request = OfferBuilder::new("foo".into(), recipient_pubkey())
			.amount_msats(1000)
			.build().unwrap()
			.request_invoice(vec![1; 32], payer_pubkey()).unwrap()
			.amount_msats(1001).unwrap()
			.amount_msats(1000).unwrap()
			.build().unwrap()
			.sign(payer_sign).unwrap();
		let (_, _, tlv_stream, _) = invoice_request.as_tlv_stream();
		assert_eq!(invoice_request.amount_msats(), Some(1000));
		assert_eq!(tlv_stream.amount, Some(1000));

		let invoice_request = OfferBuilder::new("foo".into(), recipient_pubkey())
			.amount_msats(1000)
			.build().unwrap()
			.request_invoice(vec![1; 32], payer_pubkey()).unwrap()
			.amount_msats(1001).unwrap()
			.build().unwrap()
			.sign(payer_sign).unwrap();
		let (_, _, tlv_stream, _) = invoice_request.as_tlv_stream();
		assert_eq!(invoice_request.amount_msats(), Some(1001));
		assert_eq!(tlv_stream.amount, Some(1001));

		match OfferBuilder::new("foo".into(), recipient_pubkey())
			.amount_msats(1000)
			.build().unwrap()
			.request_invoice(vec![1; 32], payer_pubkey()).unwrap()
			.amount_msats(999)
		{
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, SemanticError::InsufficientAmount),
		}

		match OfferBuilder::new("foo".into(), recipient_pubkey())
			.amount_msats(1000)
			.supported_quantity(Quantity::Unbounded)
			.build().unwrap()
			.request_invoice(vec![1; 32], payer_pubkey()).unwrap()
			.quantity(2).unwrap()
			.amount_msats(1000)
		{
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, SemanticError::InsufficientAmount),
		}

		match OfferBuilder::new("foo".into(), recipient_pubkey())
			.amount_msats(1000)
			.build().unwrap()
			.request_invoice(vec![1; 32], payer_pubkey()).unwrap()
			.amount_msats(MAX_VALUE_MSAT + 1)
		{
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, SemanticError::InvalidAmount),
		}

		match OfferBuilder::new("foo".into(), recipient_pubkey())
			.amount_msats(1000)
			.supported_quantity(Quantity::Unbounded)
			.build().unwrap()
			.request_invoice(vec![1; 32], payer_pubkey()).unwrap()
			.amount_msats(1000).unwrap()
			.quantity(2).unwrap()
			.build()
		{
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, SemanticError::InsufficientAmount),
		}

		match OfferBuilder::new("foo".into(), recipient_pubkey())
			.build().unwrap()
			.request_invoice(vec![1; 32], payer_pubkey()).unwrap()
			.build()
		{
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, SemanticError::MissingAmount),
		}

		match OfferBuilder::new("foo".into(), recipient_pubkey())
			.amount_msats(1000)
			.supported_quantity(Quantity::Unbounded)
			.build().unwrap()
			.request_invoice(vec![1; 32], payer_pubkey()).unwrap()
			.quantity(u64::max_value()).unwrap()
			.build()
		{
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, SemanticError::InvalidAmount),
		}
	}

	#[test]
	fn builds_invoice_request_with_features() {
		let invoice_request = OfferBuilder::new("foo".into(), recipient_pubkey())
			.amount_msats(1000)
			.build().unwrap()
			.request_invoice(vec![1; 32], payer_pubkey()).unwrap()
			.features_unchecked(InvoiceRequestFeatures::unknown())
			.build().unwrap()
			.sign(payer_sign).unwrap();
		let (_, _, tlv_stream, _) = invoice_request.as_tlv_stream();
		assert_eq!(invoice_request.features(), &InvoiceRequestFeatures::unknown());
		assert_eq!(tlv_stream.features, Some(&InvoiceRequestFeatures::unknown()));

		let invoice_request = OfferBuilder::new("foo".into(), recipient_pubkey())
			.amount_msats(1000)
			.build().unwrap()
			.request_invoice(vec![1; 32], payer_pubkey()).unwrap()
			.features_unchecked(InvoiceRequestFeatures::unknown())
			.features_unchecked(InvoiceRequestFeatures::empty())
			.build().unwrap()
			.sign(payer_sign).unwrap();
		let (_, _, tlv_stream, _) = invoice_request.as_tlv_stream();
		assert_eq!(invoice_request.features(), &InvoiceRequestFeatures::empty());
		assert_eq!(tlv_stream.features, None);
	}

	#[test]
	fn builds_invoice_request_with_quantity() {
		let one = NonZeroU64::new(1).unwrap();
		let ten = NonZeroU64::new(10).unwrap();

		let invoice_request = OfferBuilder::new("foo".into(), recipient_pubkey())
			.amount_msats(1000)
			.supported_quantity(Quantity::One)
			.build().unwrap()
			.request_invoice(vec![1; 32], payer_pubkey()).unwrap()
			.build().unwrap()
			.sign(payer_sign).unwrap();
		let (_, _, tlv_stream, _) = invoice_request.as_tlv_stream();
		assert_eq!(invoice_request.quantity(), None);
		assert_eq!(tlv_stream.quantity, None);

		match OfferBuilder::new("foo".into(), recipient_pubkey())
			.amount_msats(1000)
			.supported_quantity(Quantity::One)
			.build().unwrap()
			.request_invoice(vec![1; 32], payer_pubkey()).unwrap()
			.amount_msats(2_000).unwrap()
			.quantity(2)
		{
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, SemanticError::UnexpectedQuantity),
		}

		let invoice_request = OfferBuilder::new("foo".into(), recipient_pubkey())
			.amount_msats(1000)
			.supported_quantity(Quantity::Bounded(ten))
			.build().unwrap()
			.request_invoice(vec![1; 32], payer_pubkey()).unwrap()
			.amount_msats(10_000).unwrap()
			.quantity(10).unwrap()
			.build().unwrap()
			.sign(payer_sign).unwrap();
		let (_, _, tlv_stream, _) = invoice_request.as_tlv_stream();
		assert_eq!(invoice_request.amount_msats(), Some(10_000));
		assert_eq!(tlv_stream.amount, Some(10_000));

		match OfferBuilder::new("foo".into(), recipient_pubkey())
			.amount_msats(1000)
			.supported_quantity(Quantity::Bounded(ten))
			.build().unwrap()
			.request_invoice(vec![1; 32], payer_pubkey()).unwrap()
			.amount_msats(11_000).unwrap()
			.quantity(11)
		{
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, SemanticError::InvalidQuantity),
		}

		let invoice_request = OfferBuilder::new("foo".into(), recipient_pubkey())
			.amount_msats(1000)
			.supported_quantity(Quantity::Unbounded)
			.build().unwrap()
			.request_invoice(vec![1; 32], payer_pubkey()).unwrap()
			.amount_msats(2_000).unwrap()
			.quantity(2).unwrap()
			.build().unwrap()
			.sign(payer_sign).unwrap();
		let (_, _, tlv_stream, _) = invoice_request.as_tlv_stream();
		assert_eq!(invoice_request.amount_msats(), Some(2_000));
		assert_eq!(tlv_stream.amount, Some(2_000));

		match OfferBuilder::new("foo".into(), recipient_pubkey())
			.amount_msats(1000)
			.supported_quantity(Quantity::Unbounded)
			.build().unwrap()
			.request_invoice(vec![1; 32], payer_pubkey()).unwrap()
			.build()
		{
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, SemanticError::MissingQuantity),
		}

		match OfferBuilder::new("foo".into(), recipient_pubkey())
			.amount_msats(1000)
			.supported_quantity(Quantity::Bounded(one))
			.build().unwrap()
			.request_invoice(vec![1; 32], payer_pubkey()).unwrap()
			.build()
		{
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, SemanticError::MissingQuantity),
		}
	}

	#[test]
	fn builds_invoice_request_with_payer_note() {
		let invoice_request = OfferBuilder::new("foo".into(), recipient_pubkey())
			.amount_msats(1000)
			.build().unwrap()
			.request_invoice(vec![1; 32], payer_pubkey()).unwrap()
			.payer_note("bar".into())
			.build().unwrap()
			.sign(payer_sign).unwrap();
		let (_, _, tlv_stream, _) = invoice_request.as_tlv_stream();
		assert_eq!(invoice_request.payer_note(), Some(PrintableString("bar")));
		assert_eq!(tlv_stream.payer_note, Some(&String::from("bar")));

		let invoice_request = OfferBuilder::new("foo".into(), recipient_pubkey())
			.amount_msats(1000)
			.build().unwrap()
			.request_invoice(vec![1; 32], payer_pubkey()).unwrap()
			.payer_note("bar".into())
			.payer_note("baz".into())
			.build().unwrap()
			.sign(payer_sign).unwrap();
		let (_, _, tlv_stream, _) = invoice_request.as_tlv_stream();
		assert_eq!(invoice_request.payer_note(), Some(PrintableString("baz")));
		assert_eq!(tlv_stream.payer_note, Some(&String::from("baz")));
	}

	#[test]
	fn fails_signing_invoice_request() {
		match OfferBuilder::new("foo".into(), recipient_pubkey())
			.amount_msats(1000)
			.build().unwrap()
			.request_invoice(vec![1; 32], payer_pubkey()).unwrap()
			.build().unwrap()
			.sign(|_| Err(()))
		{
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, SignError::Signing(())),
		}

		match OfferBuilder::new("foo".into(), recipient_pubkey())
			.amount_msats(1000)
			.build().unwrap()
			.request_invoice(vec![1; 32], payer_pubkey()).unwrap()
			.build().unwrap()
			.sign(recipient_sign)
		{
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, SignError::Verification(secp256k1::Error::InvalidSignature)),
		}
	}

	#[test]
	fn parses_invoice_request_with_metadata() {
		let invoice_request = OfferBuilder::new("foo".into(), recipient_pubkey())
			.amount_msats(1000)
			.build().unwrap()
			.request_invoice(vec![42; 32], payer_pubkey()).unwrap()
			.build().unwrap()
			.sign(payer_sign).unwrap();

		let mut buffer = Vec::new();
		invoice_request.write(&mut buffer).unwrap();

		if let Err(e) = InvoiceRequest::try_from(buffer) {
			panic!("error parsing invoice_request: {:?}", e);
		}
	}

	#[test]
	fn parses_invoice_request_with_chain() {
		let invoice_request = OfferBuilder::new("foo".into(), recipient_pubkey())
			.amount_msats(1000)
			.build().unwrap()
			.request_invoice(vec![1; 32], payer_pubkey()).unwrap()
			.chain(Network::Bitcoin).unwrap()
			.build().unwrap()
			.sign(payer_sign).unwrap();

		let mut buffer = Vec::new();
		invoice_request.write(&mut buffer).unwrap();

		if let Err(e) = InvoiceRequest::try_from(buffer) {
			panic!("error parsing invoice_request: {:?}", e);
		}

		let invoice_request = OfferBuilder::new("foo".into(), recipient_pubkey())
			.amount_msats(1000)
			.build().unwrap()
			.request_invoice(vec![1; 32], payer_pubkey()).unwrap()
			.chain_unchecked(Network::Testnet)
			.build_unchecked()
			.sign(payer_sign).unwrap();

		let mut buffer = Vec::new();
		invoice_request.write(&mut buffer).unwrap();

		match InvoiceRequest::try_from(buffer) {
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, ParseError::InvalidSemantics(SemanticError::UnsupportedChain)),
		}
	}

	#[test]
	fn parses_invoice_request_with_amount() {
		let invoice_request = OfferBuilder::new("foo".into(), recipient_pubkey())
			.amount_msats(1000)
			.build().unwrap()
			.request_invoice(vec![1; 32], payer_pubkey()).unwrap()
			.build().unwrap()
			.sign(payer_sign).unwrap();

		let mut buffer = Vec::new();
		invoice_request.write(&mut buffer).unwrap();

		if let Err(e) = InvoiceRequest::try_from(buffer) {
			panic!("error parsing invoice_request: {:?}", e);
		}

		let invoice_request = OfferBuilder::new("foo".into(), recipient_pubkey())
			.build().unwrap()
			.request_invoice(vec![1; 32], payer_pubkey()).unwrap()
			.amount_msats(1000).unwrap()
			.build().unwrap()
			.sign(payer_sign).unwrap();

		let mut buffer = Vec::new();
		invoice_request.write(&mut buffer).unwrap();

		if let Err(e) = InvoiceRequest::try_from(buffer) {
			panic!("error parsing invoice_request: {:?}", e);
		}

		let invoice_request = OfferBuilder::new("foo".into(), recipient_pubkey())
			.build().unwrap()
			.request_invoice(vec![1; 32], payer_pubkey()).unwrap()
			.build_unchecked()
			.sign(payer_sign).unwrap();

		let mut buffer = Vec::new();
		invoice_request.write(&mut buffer).unwrap();

		match InvoiceRequest::try_from(buffer) {
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, ParseError::InvalidSemantics(SemanticError::MissingAmount)),
		}

		let invoice_request = OfferBuilder::new("foo".into(), recipient_pubkey())
			.amount_msats(1000)
			.build().unwrap()
			.request_invoice(vec![1; 32], payer_pubkey()).unwrap()
			.amount_msats_unchecked(999)
			.build_unchecked()
			.sign(payer_sign).unwrap();

		let mut buffer = Vec::new();
		invoice_request.write(&mut buffer).unwrap();

		match InvoiceRequest::try_from(buffer) {
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, ParseError::InvalidSemantics(SemanticError::InsufficientAmount)),
		}

		let invoice_request = OfferBuilder::new("foo".into(), recipient_pubkey())
			.amount(Amount::Currency { iso4217_code: *b"USD", amount: 1000 })
			.build_unchecked()
			.request_invoice(vec![1; 32], payer_pubkey()).unwrap()
			.build_unchecked()
			.sign(payer_sign).unwrap();

		let mut buffer = Vec::new();
		invoice_request.write(&mut buffer).unwrap();

		match InvoiceRequest::try_from(buffer) {
			Ok(_) => panic!("expected error"),
			Err(e) => {
				assert_eq!(e, ParseError::InvalidSemantics(SemanticError::UnsupportedCurrency));
			},
		}

		let invoice_request = OfferBuilder::new("foo".into(), recipient_pubkey())
			.amount_msats(1000)
			.supported_quantity(Quantity::Unbounded)
			.build().unwrap()
			.request_invoice(vec![1; 32], payer_pubkey()).unwrap()
			.quantity(u64::max_value()).unwrap()
			.build_unchecked()
			.sign(payer_sign).unwrap();

		let mut buffer = Vec::new();
		invoice_request.write(&mut buffer).unwrap();

		match InvoiceRequest::try_from(buffer) {
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, ParseError::InvalidSemantics(SemanticError::InvalidAmount)),
		}
	}

	#[test]
	fn parses_invoice_request_with_quantity() {
		let one = NonZeroU64::new(1).unwrap();
		let ten = NonZeroU64::new(10).unwrap();

		let invoice_request = OfferBuilder::new("foo".into(), recipient_pubkey())
			.amount_msats(1000)
			.supported_quantity(Quantity::One)
			.build().unwrap()
			.request_invoice(vec![1; 32], payer_pubkey()).unwrap()
			.build().unwrap()
			.sign(payer_sign).unwrap();

		let mut buffer = Vec::new();
		invoice_request.write(&mut buffer).unwrap();

		if let Err(e) = InvoiceRequest::try_from(buffer) {
			panic!("error parsing invoice_request: {:?}", e);
		}

		let invoice_request = OfferBuilder::new("foo".into(), recipient_pubkey())
			.amount_msats(1000)
			.supported_quantity(Quantity::One)
			.build().unwrap()
			.request_invoice(vec![1; 32], payer_pubkey()).unwrap()
			.amount_msats(2_000).unwrap()
			.quantity_unchecked(2)
			.build_unchecked()
			.sign(payer_sign).unwrap();

		let mut buffer = Vec::new();
		invoice_request.write(&mut buffer).unwrap();

		match InvoiceRequest::try_from(buffer) {
			Ok(_) => panic!("expected error"),
			Err(e) => {
				assert_eq!(e, ParseError::InvalidSemantics(SemanticError::UnexpectedQuantity));
			},
		}

		let invoice_request = OfferBuilder::new("foo".into(), recipient_pubkey())
			.amount_msats(1000)
			.supported_quantity(Quantity::Bounded(ten))
			.build().unwrap()
			.request_invoice(vec![1; 32], payer_pubkey()).unwrap()
			.amount_msats(10_000).unwrap()
			.quantity(10).unwrap()
			.build().unwrap()
			.sign(payer_sign).unwrap();

		let mut buffer = Vec::new();
		invoice_request.write(&mut buffer).unwrap();

		if let Err(e) = InvoiceRequest::try_from(buffer) {
			panic!("error parsing invoice_request: {:?}", e);
		}

		let invoice_request = OfferBuilder::new("foo".into(), recipient_pubkey())
			.amount_msats(1000)
			.supported_quantity(Quantity::Bounded(ten))
			.build().unwrap()
			.request_invoice(vec![1; 32], payer_pubkey()).unwrap()
			.amount_msats(11_000).unwrap()
			.quantity_unchecked(11)
			.build_unchecked()
			.sign(payer_sign).unwrap();

		let mut buffer = Vec::new();
		invoice_request.write(&mut buffer).unwrap();

		match InvoiceRequest::try_from(buffer) {
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, ParseError::InvalidSemantics(SemanticError::InvalidQuantity)),
		}

		let invoice_request = OfferBuilder::new("foo".into(), recipient_pubkey())
			.amount_msats(1000)
			.supported_quantity(Quantity::Unbounded)
			.build().unwrap()
			.request_invoice(vec![1; 32], payer_pubkey()).unwrap()
			.amount_msats(2_000).unwrap()
			.quantity(2).unwrap()
			.build().unwrap()
			.sign(payer_sign).unwrap();

		let mut buffer = Vec::new();
		invoice_request.write(&mut buffer).unwrap();

		if let Err(e) = InvoiceRequest::try_from(buffer) {
			panic!("error parsing invoice_request: {:?}", e);
		}

		let invoice_request = OfferBuilder::new("foo".into(), recipient_pubkey())
			.amount_msats(1000)
			.supported_quantity(Quantity::Unbounded)
			.build().unwrap()
			.request_invoice(vec![1; 32], payer_pubkey()).unwrap()
			.build_unchecked()
			.sign(payer_sign).unwrap();

		let mut buffer = Vec::new();
		invoice_request.write(&mut buffer).unwrap();

		match InvoiceRequest::try_from(buffer) {
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, ParseError::InvalidSemantics(SemanticError::MissingQuantity)),
		}

		let invoice_request = OfferBuilder::new("foo".into(), recipient_pubkey())
			.amount_msats(1000)
			.supported_quantity(Quantity::Bounded(one))
			.build().unwrap()
			.request_invoice(vec![1; 32], payer_pubkey()).unwrap()
			.build_unchecked()
			.sign(payer_sign).unwrap();

		let mut buffer = Vec::new();
		invoice_request.write(&mut buffer).unwrap();

		match InvoiceRequest::try_from(buffer) {
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, ParseError::InvalidSemantics(SemanticError::MissingQuantity)),
		}
	}

	#[test]
	fn fails_parsing_invoice_request_without_metadata() {
		let offer = OfferBuilder::new("foo".into(), recipient_pubkey())
			.amount_msats(1000)
			.build().unwrap();
		let unsigned_invoice_request = offer.request_invoice(vec![1; 32], payer_pubkey()).unwrap()
			.build().unwrap();
		let mut tlv_stream = unsigned_invoice_request.invoice_request.as_tlv_stream();
		tlv_stream.0.metadata = None;

		let mut buffer = Vec::new();
		tlv_stream.write(&mut buffer).unwrap();

		match InvoiceRequest::try_from(buffer) {
			Ok(_) => panic!("expected error"),
			Err(e) => {
				assert_eq!(e, ParseError::InvalidSemantics(SemanticError::MissingPayerMetadata));
			},
		}
	}

	#[test]
	fn fails_parsing_invoice_request_without_payer_id() {
		let offer = OfferBuilder::new("foo".into(), recipient_pubkey())
			.amount_msats(1000)
			.build().unwrap();
		let unsigned_invoice_request = offer.request_invoice(vec![1; 32], payer_pubkey()).unwrap()
			.build().unwrap();
		let mut tlv_stream = unsigned_invoice_request.invoice_request.as_tlv_stream();
		tlv_stream.2.payer_id = None;

		let mut buffer = Vec::new();
		tlv_stream.write(&mut buffer).unwrap();

		match InvoiceRequest::try_from(buffer) {
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, ParseError::InvalidSemantics(SemanticError::MissingPayerId)),
		}
	}

	#[test]
	fn fails_parsing_invoice_request_without_node_id() {
		let offer = OfferBuilder::new("foo".into(), recipient_pubkey())
			.amount_msats(1000)
			.build().unwrap();
		let unsigned_invoice_request = offer.request_invoice(vec![1; 32], payer_pubkey()).unwrap()
			.build().unwrap();
		let mut tlv_stream = unsigned_invoice_request.invoice_request.as_tlv_stream();
		tlv_stream.1.node_id = None;

		let mut buffer = Vec::new();
		tlv_stream.write(&mut buffer).unwrap();

		match InvoiceRequest::try_from(buffer) {
			Ok(_) => panic!("expected error"),
			Err(e) => {
				assert_eq!(e, ParseError::InvalidSemantics(SemanticError::MissingSigningPubkey));
			},
		}
	}

	#[test]
	fn fails_parsing_invoice_request_without_signature() {
		let mut buffer = Vec::new();
		OfferBuilder::new("foo".into(), recipient_pubkey())
			.amount_msats(1000)
			.build().unwrap()
			.request_invoice(vec![1; 32], payer_pubkey()).unwrap()
			.build().unwrap()
			.invoice_request
			.write(&mut buffer).unwrap();

		match InvoiceRequest::try_from(buffer) {
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, ParseError::InvalidSemantics(SemanticError::MissingSignature)),
		}
	}

	#[test]
	fn fails_parsing_invoice_request_with_invalid_signature() {
		let mut invoice_request = OfferBuilder::new("foo".into(), recipient_pubkey())
			.amount_msats(1000)
			.build().unwrap()
			.request_invoice(vec![1; 32], payer_pubkey()).unwrap()
			.build().unwrap()
			.sign(payer_sign).unwrap();
		let last_signature_byte = invoice_request.bytes.last_mut().unwrap();
		*last_signature_byte = last_signature_byte.wrapping_add(1);

		let mut buffer = Vec::new();
		invoice_request.write(&mut buffer).unwrap();

		match InvoiceRequest::try_from(buffer) {
			Ok(_) => panic!("expected error"),
			Err(e) => {
				assert_eq!(e, ParseError::InvalidSignature(secp256k1::Error::InvalidSignature));
			},
		}
	}

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
