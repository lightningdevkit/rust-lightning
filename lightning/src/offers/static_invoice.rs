// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Data structures and encoding for static BOLT 12 invoices.

use crate::blinded_path::BlindedPath;
use crate::io;
use crate::ln::features::{Bolt12InvoiceFeatures, OfferFeatures};
use crate::ln::inbound_payment::ExpandedKey;
use crate::ln::msgs::DecodeError;
use crate::offers::invoice::{
	check_invoice_signing_pubkey, construct_payment_paths, filter_fallbacks, BlindedPathIter,
	BlindedPayInfo, BlindedPayInfoIter, FallbackAddress, InvoiceTlvStream, InvoiceTlvStreamRef,
};
use crate::offers::invoice_macros::{invoice_accessors_common, invoice_builder_methods_common};
use crate::offers::merkle::{
	self, SignError, SignFn, SignatureTlvStream, SignatureTlvStreamRef, TaggedHash,
};
use crate::offers::offer::{
	Amount, Offer, OfferContents, OfferTlvStream, OfferTlvStreamRef, Quantity,
};
use crate::offers::parse::{Bolt12ParseError, Bolt12SemanticError, ParsedMessage};
use crate::util::ser::{
	HighZeroBytesDroppedBigSize, Iterable, SeekReadable, WithoutLength, Writeable, Writer,
};
use crate::util::string::PrintableString;
use bitcoin::address::Address;
use bitcoin::blockdata::constants::ChainHash;
use bitcoin::secp256k1::schnorr::Signature;
use bitcoin::secp256k1::{self, Keypair, PublicKey, Secp256k1};
use core::time::Duration;

#[cfg(feature = "std")]
use crate::offers::invoice::is_expired;

#[allow(unused_imports)]
use crate::prelude::*;

/// Static invoices default to expiring after 2 weeks.
const DEFAULT_RELATIVE_EXPIRY: Duration = Duration::from_secs(3600 * 24 * 14);

/// Tag for the hash function used when signing a [`StaticInvoice`]'s merkle root.
pub const SIGNATURE_TAG: &'static str = concat!("lightning", "static_invoice", "signature");

/// A `StaticInvoice` is a reusable payment request corresponding to an [`Offer`].
///
/// A static invoice may be sent in response to an [`InvoiceRequest`] and includes all the
/// information needed to pay the recipient. However, unlike [`Bolt12Invoice`]s, static invoices do
/// not provide proof-of-payment. Therefore, [`Bolt12Invoice`]s should be preferred when the
/// recipient is online to provide one.
///
/// [`Offer`]: crate::offers::offer::Offer
/// [`InvoiceRequest`]: crate::offers::invoice_request::InvoiceRequest
/// [`Bolt12Invoice`]: crate::offers::invoice::Bolt12Invoice
#[derive(Clone, Debug)]
pub struct StaticInvoice {
	bytes: Vec<u8>,
	contents: InvoiceContents,
	signature: Signature,
}

/// The contents of a [`StaticInvoice`] for responding to an [`Offer`].
///
/// [`Offer`]: crate::offers::offer::Offer
#[derive(Clone, Debug)]
struct InvoiceContents {
	offer: OfferContents,
	payment_paths: Vec<(BlindedPayInfo, BlindedPath)>,
	created_at: Duration,
	relative_expiry: Option<Duration>,
	fallbacks: Option<Vec<FallbackAddress>>,
	features: Bolt12InvoiceFeatures,
	signing_pubkey: PublicKey,
	message_paths: Vec<BlindedPath>,
}

/// Builds a [`StaticInvoice`] from an [`Offer`].
///
/// [`Offer`]: crate::offers::offer::Offer
/// This is not exported to bindings users as builder patterns don't map outside of move semantics.
// TODO: add module-level docs and link here
pub struct StaticInvoiceBuilder<'a> {
	offer_bytes: &'a Vec<u8>,
	invoice: InvoiceContents,
	keys: Keypair,
}

impl<'a> StaticInvoiceBuilder<'a> {
	/// Initialize a [`StaticInvoiceBuilder`] from the given [`Offer`].
	///
	/// Unless [`StaticInvoiceBuilder::relative_expiry`] is set, the invoice will expire 24 hours
	/// after `created_at`.
	pub fn for_offer_using_derived_keys<T: secp256k1::Signing>(
		offer: &'a Offer, payment_paths: Vec<(BlindedPayInfo, BlindedPath)>,
		message_paths: Vec<BlindedPath>, created_at: Duration, expanded_key: &ExpandedKey,
		secp_ctx: &Secp256k1<T>,
	) -> Result<Self, Bolt12SemanticError> {
		if offer.chains().len() > 1 {
			return Err(Bolt12SemanticError::UnexpectedChain);
		}

		if payment_paths.is_empty() || message_paths.is_empty() || offer.paths().is_empty() {
			return Err(Bolt12SemanticError::MissingPaths);
		}

		let offer_signing_pubkey =
			offer.signing_pubkey().ok_or(Bolt12SemanticError::MissingSigningPubkey)?;

		let keys = offer
			.verify(&expanded_key, &secp_ctx)
			.map_err(|()| Bolt12SemanticError::InvalidMetadata)?
			.1
			.ok_or(Bolt12SemanticError::MissingSigningPubkey)?;

		let signing_pubkey = keys.public_key();
		if signing_pubkey != offer_signing_pubkey {
			return Err(Bolt12SemanticError::InvalidSigningPubkey);
		}

		let invoice =
			InvoiceContents::new(offer, payment_paths, message_paths, created_at, signing_pubkey);

		Ok(Self { offer_bytes: &offer.bytes, invoice, keys })
	}

	/// Builds a signed [`StaticInvoice`] after checking for valid semantics.
	pub fn build_and_sign<T: secp256k1::Signing>(
		self, secp_ctx: &Secp256k1<T>,
	) -> Result<StaticInvoice, Bolt12SemanticError> {
		#[cfg(feature = "std")]
		{
			if self.invoice.is_offer_expired() {
				return Err(Bolt12SemanticError::AlreadyExpired);
			}
		}

		#[cfg(not(feature = "std"))]
		{
			if self.invoice.is_offer_expired_no_std(self.invoice.created_at()) {
				return Err(Bolt12SemanticError::AlreadyExpired);
			}
		}

		let Self { offer_bytes, invoice, keys } = self;
		let unsigned_invoice = UnsignedStaticInvoice::new(&offer_bytes, invoice);
		let invoice = unsigned_invoice
			.sign(|message: &UnsignedStaticInvoice| {
				Ok(secp_ctx.sign_schnorr_no_aux_rand(message.tagged_hash.as_digest(), &keys))
			})
			.unwrap();
		Ok(invoice)
	}

	invoice_builder_methods_common!(self, Self, self.invoice, Self, self, S, StaticInvoice, mut);
}

/// A semantically valid [`StaticInvoice`] that hasn't been signed.
pub struct UnsignedStaticInvoice {
	bytes: Vec<u8>,
	contents: InvoiceContents,
	tagged_hash: TaggedHash,
}

macro_rules! invoice_accessors { ($self: ident, $contents: expr) => {
	/// The chain that must be used when paying the invoice. [`StaticInvoice`]s currently can only be
	/// created from offers that support a single chain.
	pub fn chain(&$self) -> ChainHash {
		$contents.chain()
	}

	/// Opaque bytes set by the originating [`Offer::metadata`].
	///
	/// [`Offer::metadata`]: crate::offers::offer::Offer::metadata
	pub fn metadata(&$self) -> Option<&Vec<u8>> {
		$contents.metadata()
	}

	/// The minimum amount required for a successful payment of a single item.
	///
	/// From [`Offer::amount`].
	///
	/// [`Offer::amount`]: crate::offers::offer::Offer::amount
	pub fn amount(&$self) -> Option<Amount> {
		$contents.amount()
	}

	/// Features pertaining to the originating [`Offer`], from [`Offer::offer_features`].
	///
	/// [`Offer`]: crate::offers::offer::Offer
	/// [`Offer::offer_features`]: crate::offers::offer::Offer::offer_features
	pub fn offer_features(&$self) -> &OfferFeatures {
		$contents.offer_features()
	}

	/// A complete description of the purpose of the originating offer, from [`Offer::description`].
	///
	/// [`Offer::description`]: crate::offers::offer::Offer::description
	pub fn description(&$self) -> Option<PrintableString> {
		$contents.description()
	}

	/// Duration since the Unix epoch when an invoice should no longer be requested, from
	/// [`Offer::absolute_expiry`].
	///
	/// [`Offer::absolute_expiry`]: crate::offers::offer::Offer::absolute_expiry
	pub fn absolute_expiry(&$self) -> Option<Duration> {
		$contents.absolute_expiry()
	}

	/// The issuer of the offer, from [`Offer::issuer`].
	///
	/// [`Offer::issuer`]: crate::offers::offer::Offer::issuer
	pub fn issuer(&$self) -> Option<PrintableString> {
		$contents.issuer()
	}

	/// Paths to the node that may supply the invoice on the recipient's behalf, originating from
	/// publicly reachable nodes. Taken from [`Offer::paths`].
	///
	/// [`Offer::paths`]: crate::offers::offer::Offer::paths
	pub fn offer_message_paths(&$self) -> &[BlindedPath] {
		$contents.offer_message_paths()
	}

	/// Paths to the recipient for indicating that a held HTLC is available to claim when they next
	/// come online.
	pub fn message_paths(&$self) -> &[BlindedPath] {
		$contents.message_paths()
	}

	/// The quantity of items supported, from [`Offer::supported_quantity`].
	///
	/// [`Offer::supported_quantity`]: crate::offers::offer::Offer::supported_quantity
	pub fn supported_quantity(&$self) -> Quantity {
		$contents.supported_quantity()
	}
} }

impl UnsignedStaticInvoice {
	fn new(offer_bytes: &Vec<u8>, contents: InvoiceContents) -> Self {
		let (_, invoice_tlv_stream) = contents.as_tlv_stream();
		let offer_bytes = WithoutLength(offer_bytes);
		let unsigned_tlv_stream = (offer_bytes, invoice_tlv_stream);

		let mut bytes = Vec::new();
		unsigned_tlv_stream.write(&mut bytes).unwrap();

		let tagged_hash = TaggedHash::from_valid_tlv_stream_bytes(SIGNATURE_TAG, &bytes);

		Self { contents, tagged_hash, bytes }
	}

	/// Signs the [`TaggedHash`] of the invoice using the given function.
	///
	/// Note: The hash computation may have included unknown, odd TLV records.
	pub fn sign<F: SignStaticInvoiceFn>(mut self, sign: F) -> Result<StaticInvoice, SignError> {
		let pubkey = self.contents.signing_pubkey;
		let signature = merkle::sign_message(sign, &self, pubkey)?;

		// Append the signature TLV record to the bytes.
		let signature_tlv_stream = SignatureTlvStreamRef { signature: Some(&signature) };
		signature_tlv_stream.write(&mut self.bytes).unwrap();

		Ok(StaticInvoice { bytes: self.bytes, contents: self.contents, signature })
	}

	invoice_accessors_common!(self, self.contents, StaticInvoice);
	invoice_accessors!(self, self.contents);
}

impl AsRef<TaggedHash> for UnsignedStaticInvoice {
	fn as_ref(&self) -> &TaggedHash {
		&self.tagged_hash
	}
}

/// A function for signing an [`UnsignedStaticInvoice`].
pub trait SignStaticInvoiceFn {
	/// Signs a [`TaggedHash`] computed over the merkle root of `message`'s TLV stream.
	fn sign_invoice(&self, message: &UnsignedStaticInvoice) -> Result<Signature, ()>;
}

impl<F> SignStaticInvoiceFn for F
where
	F: Fn(&UnsignedStaticInvoice) -> Result<Signature, ()>,
{
	fn sign_invoice(&self, message: &UnsignedStaticInvoice) -> Result<Signature, ()> {
		self(message)
	}
}

impl<F> SignFn<UnsignedStaticInvoice> for F
where
	F: SignStaticInvoiceFn,
{
	fn sign(&self, message: &UnsignedStaticInvoice) -> Result<Signature, ()> {
		self.sign_invoice(message)
	}
}

impl StaticInvoice {
	invoice_accessors_common!(self, self.contents, StaticInvoice);
	invoice_accessors!(self, self.contents);

	/// Signature of the invoice verified using [`StaticInvoice::signing_pubkey`].
	pub fn signature(&self) -> Signature {
		self.signature
	}
}

impl InvoiceContents {
	#[cfg(feature = "std")]
	fn is_offer_expired(&self) -> bool {
		self.offer.is_expired()
	}

	#[cfg(not(feature = "std"))]
	fn is_offer_expired_no_std(&self, duration_since_epoch: Duration) -> bool {
		self.offer.is_expired_no_std(duration_since_epoch)
	}

	fn new(
		offer: &Offer, payment_paths: Vec<(BlindedPayInfo, BlindedPath)>,
		message_paths: Vec<BlindedPath>, created_at: Duration, signing_pubkey: PublicKey,
	) -> Self {
		Self {
			offer: offer.contents.clone(),
			payment_paths,
			message_paths,
			created_at,
			relative_expiry: None,
			fallbacks: None,
			features: Bolt12InvoiceFeatures::empty(),
			signing_pubkey,
		}
	}

	fn as_tlv_stream(&self) -> PartialInvoiceTlvStreamRef {
		let features = {
			if self.features == Bolt12InvoiceFeatures::empty() {
				None
			} else {
				Some(&self.features)
			}
		};

		let invoice = InvoiceTlvStreamRef {
			paths: Some(Iterable(self.payment_paths.iter().map(|(_, path)| path))),
			message_paths: Some(self.message_paths.as_ref()),
			blindedpay: Some(Iterable(self.payment_paths.iter().map(|(payinfo, _)| payinfo))),
			created_at: Some(self.created_at.as_secs()),
			relative_expiry: self.relative_expiry.map(|duration| duration.as_secs() as u32),
			fallbacks: self.fallbacks.as_ref(),
			features,
			node_id: Some(&self.signing_pubkey),
			amount: None,
			payment_hash: None,
		};

		(self.offer.as_tlv_stream(), invoice)
	}

	fn chain(&self) -> ChainHash {
		debug_assert_eq!(self.offer.chains().len(), 1);
		self.offer.chains().first().cloned().unwrap_or_else(|| self.offer.implied_chain())
	}

	fn metadata(&self) -> Option<&Vec<u8>> {
		self.offer.metadata()
	}

	fn amount(&self) -> Option<Amount> {
		self.offer.amount()
	}

	fn offer_features(&self) -> &OfferFeatures {
		self.offer.features()
	}

	fn description(&self) -> Option<PrintableString> {
		self.offer.description()
	}

	fn absolute_expiry(&self) -> Option<Duration> {
		self.offer.absolute_expiry()
	}

	fn issuer(&self) -> Option<PrintableString> {
		self.offer.issuer()
	}

	fn offer_message_paths(&self) -> &[BlindedPath] {
		self.offer.paths()
	}

	fn message_paths(&self) -> &[BlindedPath] {
		&self.message_paths[..]
	}

	fn supported_quantity(&self) -> Quantity {
		self.offer.supported_quantity()
	}

	fn payment_paths(&self) -> &[(BlindedPayInfo, BlindedPath)] {
		&self.payment_paths[..]
	}

	fn created_at(&self) -> Duration {
		self.created_at
	}

	fn relative_expiry(&self) -> Duration {
		self.relative_expiry.unwrap_or(DEFAULT_RELATIVE_EXPIRY)
	}

	#[cfg(feature = "std")]
	fn is_expired(&self) -> bool {
		is_expired(self.created_at(), self.relative_expiry())
	}

	fn fallbacks(&self) -> Vec<Address> {
		let chain = self.chain();
		self.fallbacks
			.as_ref()
			.map(|fallbacks| filter_fallbacks(chain, fallbacks))
			.unwrap_or_else(Vec::new)
	}

	fn features(&self) -> &Bolt12InvoiceFeatures {
		&self.features
	}

	fn signing_pubkey(&self) -> PublicKey {
		self.signing_pubkey
	}
}

impl Writeable for StaticInvoice {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		WithoutLength(&self.bytes).write(writer)
	}
}

impl TryFrom<Vec<u8>> for StaticInvoice {
	type Error = Bolt12ParseError;

	fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
		let parsed_invoice = ParsedMessage::<FullInvoiceTlvStream>::try_from(bytes)?;
		StaticInvoice::try_from(parsed_invoice)
	}
}

type FullInvoiceTlvStream = (OfferTlvStream, InvoiceTlvStream, SignatureTlvStream);

impl SeekReadable for FullInvoiceTlvStream {
	fn read<R: io::Read + io::Seek>(r: &mut R) -> Result<Self, DecodeError> {
		let offer = SeekReadable::read(r)?;
		let invoice = SeekReadable::read(r)?;
		let signature = SeekReadable::read(r)?;

		Ok((offer, invoice, signature))
	}
}

type PartialInvoiceTlvStream = (OfferTlvStream, InvoiceTlvStream);

type PartialInvoiceTlvStreamRef<'a> = (OfferTlvStreamRef<'a>, InvoiceTlvStreamRef<'a>);

impl TryFrom<ParsedMessage<FullInvoiceTlvStream>> for StaticInvoice {
	type Error = Bolt12ParseError;

	fn try_from(invoice: ParsedMessage<FullInvoiceTlvStream>) -> Result<Self, Self::Error> {
		let ParsedMessage { bytes, tlv_stream } = invoice;
		let (offer_tlv_stream, invoice_tlv_stream, SignatureTlvStream { signature }) = tlv_stream;
		let contents = InvoiceContents::try_from((offer_tlv_stream, invoice_tlv_stream))?;

		let signature = match signature {
			None => {
				return Err(Bolt12ParseError::InvalidSemantics(
					Bolt12SemanticError::MissingSignature,
				))
			},
			Some(signature) => signature,
		};
		let tagged_hash = TaggedHash::from_valid_tlv_stream_bytes(SIGNATURE_TAG, &bytes);
		let pubkey = contents.signing_pubkey;
		merkle::verify_signature(&signature, &tagged_hash, pubkey)?;

		Ok(StaticInvoice { bytes, contents, signature })
	}
}

impl TryFrom<PartialInvoiceTlvStream> for InvoiceContents {
	type Error = Bolt12SemanticError;

	fn try_from(tlv_stream: PartialInvoiceTlvStream) -> Result<Self, Self::Error> {
		let (
			offer_tlv_stream,
			InvoiceTlvStream {
				paths,
				blindedpay,
				created_at,
				relative_expiry,
				fallbacks,
				features,
				node_id,
				message_paths,
				payment_hash,
				amount,
			},
		) = tlv_stream;

		if payment_hash.is_some() {
			return Err(Bolt12SemanticError::UnexpectedPaymentHash);
		}
		if amount.is_some() {
			return Err(Bolt12SemanticError::UnexpectedAmount);
		}

		let payment_paths = construct_payment_paths(blindedpay, paths)?;
		let message_paths = message_paths.ok_or(Bolt12SemanticError::MissingPaths)?;

		let created_at = match created_at {
			None => return Err(Bolt12SemanticError::MissingCreationTime),
			Some(timestamp) => Duration::from_secs(timestamp),
		};

		let relative_expiry = relative_expiry.map(Into::<u64>::into).map(Duration::from_secs);

		let features = features.unwrap_or_else(Bolt12InvoiceFeatures::empty);

		let signing_pubkey = node_id.ok_or(Bolt12SemanticError::MissingSigningPubkey)?;
		check_invoice_signing_pubkey(&signing_pubkey, &offer_tlv_stream)?;

		if offer_tlv_stream.paths.is_none() {
			return Err(Bolt12SemanticError::MissingPaths);
		}
		if offer_tlv_stream.chains.as_ref().map_or(0, |chains| chains.len()) > 1 {
			return Err(Bolt12SemanticError::UnexpectedChain);
		}

		Ok(InvoiceContents {
			offer: OfferContents::try_from(offer_tlv_stream)?,
			payment_paths,
			message_paths,
			created_at,
			relative_expiry,
			fallbacks,
			features,
			signing_pubkey,
		})
	}
}
