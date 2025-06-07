// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Data structures and encoding for static BOLT 12 invoices.

use crate::blinded_path::message::BlindedMessagePath;
use crate::blinded_path::payment::BlindedPaymentPath;
use crate::io;
use crate::ln::inbound_payment::ExpandedKey;
use crate::ln::msgs::DecodeError;
use crate::offers::invoice::{
	check_invoice_signing_pubkey, construct_payment_paths, filter_fallbacks,
	ExperimentalInvoiceTlvStream, ExperimentalInvoiceTlvStreamRef, FallbackAddress,
	InvoiceTlvStream, InvoiceTlvStreamRef,
};
#[cfg(test)]
use crate::offers::invoice_macros::invoice_builder_methods_test_common;
use crate::offers::invoice_macros::{invoice_accessors_common, invoice_builder_methods_common};
use crate::offers::invoice_request::InvoiceRequest;
use crate::offers::merkle::{
	self, SignError, SignFn, SignatureTlvStream, SignatureTlvStreamRef, TaggedHash, TlvStream,
};
use crate::offers::nonce::Nonce;
use crate::offers::offer::{
	Amount, ExperimentalOfferTlvStream, ExperimentalOfferTlvStreamRef, Offer, OfferContents,
	OfferTlvStream, OfferTlvStreamRef, Quantity, EXPERIMENTAL_OFFER_TYPES, OFFER_TYPES,
};
use crate::offers::parse::{Bolt12ParseError, Bolt12SemanticError, ParsedMessage};
use crate::types::features::{Bolt12InvoiceFeatures, OfferFeatures};
use crate::util::ser::{
	CursorReadable, Iterable, LengthLimitedRead, LengthReadable, WithoutLength, Writeable, Writer,
};
use crate::util::string::PrintableString;
use bitcoin::address::Address;
use bitcoin::constants::ChainHash;
use bitcoin::secp256k1::schnorr::Signature;
use bitcoin::secp256k1::{self, Keypair, PublicKey, Secp256k1};
use core::time::Duration;

#[cfg(feature = "std")]
use crate::offers::invoice::is_expired;

#[allow(unused_imports)]
use crate::prelude::*;

/// Static invoices default to expiring after 2 weeks.
pub const DEFAULT_RELATIVE_EXPIRY: Duration = Duration::from_secs(3600 * 24 * 14);

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
	contents: Box<InvoiceContents>,
	signature: Signature,
}

impl PartialEq for StaticInvoice {
	fn eq(&self, other: &Self) -> bool {
		self.bytes.eq(&other.bytes)
	}
}

impl Eq for StaticInvoice {}

impl core::hash::Hash for StaticInvoice {
	fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
		self.bytes.hash(state);
	}
}

/// The contents of a [`StaticInvoice`] for responding to an [`Offer`].
///
/// [`Offer`]: crate::offers::offer::Offer
#[derive(Clone, Debug)]
struct InvoiceContents {
	offer: OfferContents,
	payment_paths: Vec<BlindedPaymentPath>,
	created_at: Duration,
	relative_expiry: Option<Duration>,
	fallbacks: Option<Vec<FallbackAddress>>,
	features: Bolt12InvoiceFeatures,
	signing_pubkey: PublicKey,
	message_paths: Vec<BlindedMessagePath>,
	#[cfg(test)]
	experimental_baz: Option<u64>,
}

/// Builds a [`StaticInvoice`] from an [`Offer`].
///
/// [`Offer`]: crate::offers::offer::Offer
/// This is not exported to bindings users as builder patterns don't map outside of move semantics.
// TODO: add module-level docs and link here
pub struct StaticInvoiceBuilder<'a> {
	offer_bytes: &'a Vec<u8>,
	invoice: Box<InvoiceContents>,
	keys: Keypair,
}

impl<'a> StaticInvoiceBuilder<'a> {
	/// Initialize a [`StaticInvoiceBuilder`] from the given [`Offer`].
	///
	/// The invoice's expiration will default to [`DEFAULT_RELATIVE_EXPIRY`] after `created_at` unless
	/// overridden by [`StaticInvoiceBuilder::relative_expiry`].
	pub fn for_offer_using_derived_keys<T: secp256k1::Signing>(
		offer: &'a Offer, payment_paths: Vec<BlindedPaymentPath>,
		message_paths: Vec<BlindedMessagePath>, created_at: Duration, expanded_key: &ExpandedKey,
		nonce: Nonce, secp_ctx: &Secp256k1<T>,
	) -> Result<Self, Bolt12SemanticError> {
		if offer.chains().len() > 1 {
			return Err(Bolt12SemanticError::UnexpectedChain);
		}

		if payment_paths.is_empty() || message_paths.is_empty() || offer.paths().is_empty() {
			return Err(Bolt12SemanticError::MissingPaths);
		}

		let issuer_signing_pubkey =
			offer.issuer_signing_pubkey().ok_or(Bolt12SemanticError::MissingIssuerSigningPubkey)?;

		let keys = offer
			.verify(nonce, &expanded_key, &secp_ctx)
			.map_err(|()| Bolt12SemanticError::InvalidMetadata)?
			.1
			.ok_or(Bolt12SemanticError::MissingSigningPubkey)?;

		let signing_pubkey = keys.public_key();
		if signing_pubkey != issuer_signing_pubkey {
			return Err(Bolt12SemanticError::InvalidSigningPubkey);
		}

		let invoice = Box::new(InvoiceContents::new(
			offer,
			payment_paths,
			message_paths,
			created_at,
			signing_pubkey,
		));

		Ok(Self { offer_bytes: &offer.bytes, invoice, keys })
	}

	/// Builds an [`UnsignedStaticInvoice`] after checking for valid semantics, returning it along with
	/// the [`Keypair`] needed to sign it.
	pub fn build(self) -> Result<(UnsignedStaticInvoice, Keypair), Bolt12SemanticError> {
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
		Ok((UnsignedStaticInvoice::new(&offer_bytes, invoice), keys))
	}

	/// Builds a signed [`StaticInvoice`] after checking for valid semantics.
	pub fn build_and_sign<T: secp256k1::Signing>(
		self, secp_ctx: &Secp256k1<T>,
	) -> Result<StaticInvoice, Bolt12SemanticError> {
		let (unsigned_invoice, keys) = self.build()?;
		let invoice = unsigned_invoice
			.sign(|message: &UnsignedStaticInvoice| {
				Ok(secp_ctx.sign_schnorr_no_aux_rand(message.tagged_hash.as_digest(), &keys))
			})
			.unwrap();
		Ok(invoice)
	}

	invoice_builder_methods_common!(self, Self, self.invoice, Self, self, StaticInvoice, mut);

	#[cfg(test)]
	invoice_builder_methods_test_common!(self, Self, self.invoice, Self, self, mut);
}

/// A semantically valid [`StaticInvoice`] that hasn't been signed.
pub struct UnsignedStaticInvoice {
	bytes: Vec<u8>,
	experimental_bytes: Vec<u8>,
	contents: Box<InvoiceContents>,
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
	pub fn offer_message_paths(&$self) -> &[BlindedMessagePath] {
		$contents.offer_message_paths()
	}

	/// Paths to the recipient for indicating that a held HTLC is available to claim when they next
	/// come online.
	pub fn message_paths(&$self) -> &[BlindedMessagePath] {
		$contents.message_paths()
	}

	/// The quantity of items supported, from [`Offer::supported_quantity`].
	///
	/// [`Offer::supported_quantity`]: crate::offers::offer::Offer::supported_quantity
	pub fn supported_quantity(&$self) -> Quantity {
		$contents.supported_quantity()
	}

	/// The public key used by the recipient to sign invoices, from
	/// [`Offer::issuer_signing_pubkey`].
	///
	/// [`Offer::issuer_signing_pubkey`]: crate::offers::offer::Offer::issuer_signing_pubkey
	pub fn issuer_signing_pubkey(&$self) -> Option<PublicKey> {
		$contents.issuer_signing_pubkey()
	}
} }

macro_rules! invoice_accessors_signing_pubkey {
	($self: ident, $contents: expr, $invoice_type: ty) =>
{
	/// The public key corresponding to the key used to sign the invoice.
	///
	/// This will be:
	/// - [`Offer::issuer_signing_pubkey`] if it's `Some`, otherwise
	/// - the final blinded node id from a [`BlindedMessagePath`] in [`Offer::paths`] if `None`.
	///
	/// [`Offer::issuer_signing_pubkey`]: crate::offers::offer::Offer::issuer_signing_pubkey
	/// [`Offer::paths`]: crate::offers::offer::Offer::paths
	pub fn signing_pubkey(&$self) -> PublicKey {
		$contents.signing_pubkey()
	}
} }

impl UnsignedStaticInvoice {
	fn new(offer_bytes: &Vec<u8>, contents: Box<InvoiceContents>) -> Self {
		let (_, invoice_tlv_stream, _, experimental_invoice_tlv_stream) = contents.as_tlv_stream();

		const INVOICE_ALLOCATION_SIZE: usize = 1024;
		let mut bytes = Vec::with_capacity(INVOICE_ALLOCATION_SIZE);

		// Use the offer bytes instead of the offer TLV stream as the latter may have contained
		// unknown TLV records, which are not stored in `InvoiceContents`.
		for record in TlvStream::new(offer_bytes).range(OFFER_TYPES) {
			record.write(&mut bytes).unwrap();
		}

		let remaining_bytes = &offer_bytes[bytes.len()..];

		invoice_tlv_stream.write(&mut bytes).unwrap();

		const EXPERIMENTAL_TLV_ALLOCATION_SIZE: usize = 0;
		let mut experimental_bytes = Vec::with_capacity(EXPERIMENTAL_TLV_ALLOCATION_SIZE);

		let experimental_tlv_stream =
			TlvStream::new(remaining_bytes).range(EXPERIMENTAL_OFFER_TYPES);
		for record in experimental_tlv_stream {
			record.write(&mut experimental_bytes).unwrap();
		}

		experimental_invoice_tlv_stream.write(&mut experimental_bytes).unwrap();

		let tlv_stream = TlvStream::new(&bytes).chain(TlvStream::new(&experimental_bytes));
		let tagged_hash = TaggedHash::from_tlv_stream(SIGNATURE_TAG, tlv_stream);

		Self { bytes, experimental_bytes, contents, tagged_hash }
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

		// Append the experimental bytes after the signature.
		self.bytes.extend_from_slice(&self.experimental_bytes);

		Ok(StaticInvoice { bytes: self.bytes, contents: self.contents, signature })
	}

	invoice_accessors_common!(self, self.contents, UnsignedStaticInvoice);
	invoice_accessors_signing_pubkey!(self, self.contents, UnsignedStaticInvoice);
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
	invoice_accessors_signing_pubkey!(self, self.contents, StaticInvoice);
	invoice_accessors!(self, self.contents);

	/// Signature of the invoice verified using [`StaticInvoice::signing_pubkey`].
	pub fn signature(&self) -> Signature {
		self.signature
	}

	#[allow(unused)] // TODO: remove this once we remove the `async_payments` cfg flag
	pub(crate) fn is_from_same_offer(&self, invreq: &InvoiceRequest) -> bool {
		let invoice_offer_tlv_stream =
			Offer::tlv_stream_iter(&self.bytes).map(|tlv_record| tlv_record.record_bytes);
		let invreq_offer_tlv_stream =
			Offer::tlv_stream_iter(invreq.bytes()).map(|tlv_record| tlv_record.record_bytes);
		invoice_offer_tlv_stream.eq(invreq_offer_tlv_stream)
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
		offer: &Offer, payment_paths: Vec<BlindedPaymentPath>,
		message_paths: Vec<BlindedMessagePath>, created_at: Duration, signing_pubkey: PublicKey,
	) -> Self {
		Self {
			offer: *offer.contents.clone(),
			payment_paths,
			message_paths,
			created_at,
			relative_expiry: None,
			fallbacks: None,
			features: Bolt12InvoiceFeatures::empty(),
			signing_pubkey,
			#[cfg(test)]
			experimental_baz: None,
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
			paths: Some(Iterable(self.payment_paths.iter().map(|path| path.inner_blinded_path()))),
			message_paths: Some(self.message_paths.as_ref()),
			blindedpay: Some(Iterable(self.payment_paths.iter().map(|path| &path.payinfo))),
			created_at: Some(self.created_at.as_secs()),
			relative_expiry: self.relative_expiry.map(|duration| duration.as_secs() as u32),
			fallbacks: self.fallbacks.as_ref(),
			features,
			node_id: Some(&self.signing_pubkey),
			amount: None,
			payment_hash: None,
		};

		let experimental_invoice = ExperimentalInvoiceTlvStreamRef {
			#[cfg(test)]
			experimental_baz: self.experimental_baz,
		};

		let (offer, experimental_offer) = self.offer.as_tlv_stream();

		(offer, invoice, experimental_offer, experimental_invoice)
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

	fn offer_message_paths(&self) -> &[BlindedMessagePath] {
		self.offer.paths()
	}

	fn message_paths(&self) -> &[BlindedMessagePath] {
		&self.message_paths[..]
	}

	fn supported_quantity(&self) -> Quantity {
		self.offer.supported_quantity()
	}

	fn issuer_signing_pubkey(&self) -> Option<PublicKey> {
		self.offer.issuer_signing_pubkey()
	}

	fn payment_paths(&self) -> &[BlindedPaymentPath] {
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
impl LengthReadable for StaticInvoice {
	fn read_from_fixed_length_buffer<R: LengthLimitedRead>(r: &mut R) -> Result<Self, DecodeError> {
		let bytes: WithoutLength<Vec<u8>> = LengthReadable::read_from_fixed_length_buffer(r)?;
		Self::try_from(bytes.0).map_err(|_| DecodeError::InvalidValue)
	}
}

impl TryFrom<Vec<u8>> for StaticInvoice {
	type Error = Bolt12ParseError;

	fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
		let parsed_invoice = ParsedMessage::<FullInvoiceTlvStream>::try_from(bytes)?;
		StaticInvoice::try_from(parsed_invoice)
	}
}

type FullInvoiceTlvStream = (
	OfferTlvStream,
	InvoiceTlvStream,
	SignatureTlvStream,
	ExperimentalOfferTlvStream,
	ExperimentalInvoiceTlvStream,
);

impl CursorReadable for FullInvoiceTlvStream {
	fn read<R: AsRef<[u8]>>(r: &mut io::Cursor<R>) -> Result<Self, DecodeError> {
		let offer = CursorReadable::read(r)?;
		let invoice = CursorReadable::read(r)?;
		let signature = CursorReadable::read(r)?;
		let experimental_offer = CursorReadable::read(r)?;
		let experimental_invoice = CursorReadable::read(r)?;

		Ok((offer, invoice, signature, experimental_offer, experimental_invoice))
	}
}

type PartialInvoiceTlvStream =
	(OfferTlvStream, InvoiceTlvStream, ExperimentalOfferTlvStream, ExperimentalInvoiceTlvStream);

type PartialInvoiceTlvStreamRef<'a> = (
	OfferTlvStreamRef<'a>,
	InvoiceTlvStreamRef<'a>,
	ExperimentalOfferTlvStreamRef,
	ExperimentalInvoiceTlvStreamRef,
);

impl TryFrom<ParsedMessage<FullInvoiceTlvStream>> for StaticInvoice {
	type Error = Bolt12ParseError;

	fn try_from(invoice: ParsedMessage<FullInvoiceTlvStream>) -> Result<Self, Self::Error> {
		let ParsedMessage { bytes, tlv_stream } = invoice;
		let (
			offer_tlv_stream,
			invoice_tlv_stream,
			SignatureTlvStream { signature },
			experimental_offer_tlv_stream,
			experimental_invoice_tlv_stream,
		) = tlv_stream;
		let contents = Box::new(InvoiceContents::try_from((
			offer_tlv_stream,
			invoice_tlv_stream,
			experimental_offer_tlv_stream,
			experimental_invoice_tlv_stream,
		))?);

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
			experimental_offer_tlv_stream,
			ExperimentalInvoiceTlvStream {
				#[cfg(test)]
				experimental_baz,
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
			offer: OfferContents::try_from((offer_tlv_stream, experimental_offer_tlv_stream))?,
			payment_paths,
			message_paths,
			created_at,
			relative_expiry,
			fallbacks,
			features,
			signing_pubkey,
			#[cfg(test)]
			experimental_baz,
		})
	}
}

#[cfg(test)]
mod tests {
	use crate::blinded_path::message::BlindedMessagePath;
	use crate::blinded_path::BlindedHop;
	use crate::ln::inbound_payment::ExpandedKey;
	use crate::ln::msgs::DecodeError;
	use crate::offers::invoice::{
		ExperimentalInvoiceTlvStreamRef, InvoiceTlvStreamRef, EXPERIMENTAL_INVOICE_TYPES,
		INVOICE_TYPES,
	};
	use crate::offers::merkle;
	use crate::offers::merkle::{SignatureTlvStreamRef, TaggedHash, TlvStream};
	use crate::offers::nonce::Nonce;
	use crate::offers::offer::{
		ExperimentalOfferTlvStreamRef, Offer, OfferBuilder, OfferTlvStreamRef, Quantity,
	};
	use crate::offers::parse::{Bolt12ParseError, Bolt12SemanticError};
	use crate::offers::static_invoice::{
		StaticInvoice, StaticInvoiceBuilder, UnsignedStaticInvoice, DEFAULT_RELATIVE_EXPIRY,
		SIGNATURE_TAG,
	};
	use crate::offers::test_utils::*;
	use crate::types::features::{Bolt12InvoiceFeatures, OfferFeatures};
	use crate::util::ser::{BigSize, Iterable, Writeable};
	use bitcoin::constants::ChainHash;
	use bitcoin::secp256k1::{self, Secp256k1};
	use bitcoin::Network;
	use core::time::Duration;

	type FullInvoiceTlvStreamRef<'a> = (
		OfferTlvStreamRef<'a>,
		InvoiceTlvStreamRef<'a>,
		SignatureTlvStreamRef<'a>,
		ExperimentalOfferTlvStreamRef,
		ExperimentalInvoiceTlvStreamRef,
	);

	impl StaticInvoice {
		fn as_tlv_stream(&self) -> FullInvoiceTlvStreamRef {
			let (
				offer_tlv_stream,
				invoice_tlv_stream,
				experimental_offer_tlv_stream,
				experimental_invoice_tlv_stream,
			) = self.contents.as_tlv_stream();
			(
				offer_tlv_stream,
				invoice_tlv_stream,
				SignatureTlvStreamRef { signature: Some(&self.signature) },
				experimental_offer_tlv_stream,
				experimental_invoice_tlv_stream,
			)
		}
	}

	fn tlv_stream_to_bytes(
		tlv_stream: &(
			OfferTlvStreamRef,
			InvoiceTlvStreamRef,
			SignatureTlvStreamRef,
			ExperimentalOfferTlvStreamRef,
			ExperimentalInvoiceTlvStreamRef,
		),
	) -> Vec<u8> {
		let mut buffer = Vec::new();
		tlv_stream.0.write(&mut buffer).unwrap();
		tlv_stream.1.write(&mut buffer).unwrap();
		tlv_stream.2.write(&mut buffer).unwrap();
		tlv_stream.3.write(&mut buffer).unwrap();
		tlv_stream.4.write(&mut buffer).unwrap();
		buffer
	}

	fn invoice() -> StaticInvoice {
		let node_id = recipient_pubkey();
		let payment_paths = payment_paths();
		let now = now();
		let expanded_key = ExpandedKey::new([42; 32]);
		let entropy = FixedEntropy {};
		let nonce = Nonce::from_entropy_source(&entropy);
		let secp_ctx = Secp256k1::new();

		let offer = OfferBuilder::deriving_signing_pubkey(node_id, &expanded_key, nonce, &secp_ctx)
			.path(blinded_path())
			.build()
			.unwrap();

		StaticInvoiceBuilder::for_offer_using_derived_keys(
			&offer,
			payment_paths.clone(),
			vec![blinded_path()],
			now,
			&expanded_key,
			nonce,
			&secp_ctx,
		)
		.unwrap()
		.build_and_sign(&secp_ctx)
		.unwrap()
	}

	fn blinded_path() -> BlindedMessagePath {
		BlindedMessagePath::from_blinded_path(
			pubkey(40),
			pubkey(41),
			vec![
				BlindedHop { blinded_node_id: pubkey(42), encrypted_payload: vec![0; 43] },
				BlindedHop { blinded_node_id: pubkey(43), encrypted_payload: vec![0; 44] },
			],
		)
	}

	#[test]
	fn builds_invoice_for_offer_with_defaults() {
		let node_id = recipient_pubkey();
		let payment_paths = payment_paths();
		let now = now();
		let expanded_key = ExpandedKey::new([42; 32]);
		let entropy = FixedEntropy {};
		let nonce = Nonce::from_entropy_source(&entropy);
		let secp_ctx = Secp256k1::new();

		let offer = OfferBuilder::deriving_signing_pubkey(node_id, &expanded_key, nonce, &secp_ctx)
			.path(blinded_path())
			.build()
			.unwrap();

		let invoice = StaticInvoiceBuilder::for_offer_using_derived_keys(
			&offer,
			payment_paths.clone(),
			vec![blinded_path()],
			now,
			&expanded_key,
			nonce,
			&secp_ctx,
		)
		.unwrap()
		.build_and_sign(&secp_ctx)
		.unwrap();

		let mut buffer = Vec::new();
		invoice.write(&mut buffer).unwrap();

		assert_eq!(invoice.bytes, buffer.as_slice());
		assert_eq!(invoice.metadata(), None);
		assert_eq!(invoice.amount(), None);
		assert_eq!(invoice.description(), None);
		assert_eq!(invoice.offer_features(), &OfferFeatures::empty());
		assert_eq!(invoice.absolute_expiry(), None);
		assert_eq!(invoice.offer_message_paths(), &[blinded_path()]);
		assert_eq!(invoice.message_paths(), &[blinded_path()]);
		assert_eq!(invoice.issuer(), None);
		assert_eq!(invoice.supported_quantity(), Quantity::One);
		assert_ne!(invoice.signing_pubkey(), recipient_pubkey());
		assert_eq!(invoice.chain(), ChainHash::using_genesis_block(Network::Bitcoin));
		assert_eq!(invoice.payment_paths(), payment_paths.as_slice());
		assert_eq!(invoice.created_at(), now);
		assert_eq!(invoice.relative_expiry(), DEFAULT_RELATIVE_EXPIRY);
		#[cfg(feature = "std")]
		assert!(!invoice.is_expired());
		assert!(invoice.fallbacks().is_empty());
		assert_eq!(invoice.invoice_features(), &Bolt12InvoiceFeatures::empty());

		let signing_pubkey = offer.issuer_signing_pubkey().unwrap();
		let message = TaggedHash::from_valid_tlv_stream_bytes(SIGNATURE_TAG, &invoice.bytes);
		assert!(merkle::verify_signature(&invoice.signature, &message, signing_pubkey).is_ok());

		let paths = vec![blinded_path()];
		assert_eq!(
			invoice.as_tlv_stream(),
			(
				OfferTlvStreamRef {
					chains: None,
					metadata: None,
					currency: None,
					amount: None,
					description: None,
					features: None,
					absolute_expiry: None,
					paths: Some(&paths),
					issuer: None,
					quantity_max: None,
					issuer_id: Some(&signing_pubkey),
				},
				InvoiceTlvStreamRef {
					paths: Some(Iterable(
						payment_paths.iter().map(|path| path.inner_blinded_path())
					)),
					blindedpay: Some(Iterable(payment_paths.iter().map(|path| &path.payinfo))),
					created_at: Some(now.as_secs()),
					relative_expiry: None,
					payment_hash: None,
					amount: None,
					fallbacks: None,
					features: None,
					node_id: Some(&signing_pubkey),
					message_paths: Some(&paths),
				},
				SignatureTlvStreamRef { signature: Some(&invoice.signature()) },
				ExperimentalOfferTlvStreamRef { experimental_foo: None },
				ExperimentalInvoiceTlvStreamRef { experimental_baz: None },
			)
		);

		if let Err(e) = StaticInvoice::try_from(buffer) {
			panic!("error parsing invoice: {:?}", e);
		}
	}

	#[cfg(feature = "std")]
	#[test]
	fn builds_invoice_from_offer_with_expiration() {
		let node_id = recipient_pubkey();
		let now = now();
		let expanded_key = ExpandedKey::new([42; 32]);
		let entropy = FixedEntropy {};
		let nonce = Nonce::from_entropy_source(&entropy);
		let secp_ctx = Secp256k1::new();

		let future_expiry = Duration::from_secs(u64::max_value());
		let past_expiry = Duration::from_secs(0);

		let valid_offer =
			OfferBuilder::deriving_signing_pubkey(node_id, &expanded_key, nonce, &secp_ctx)
				.path(blinded_path())
				.absolute_expiry(future_expiry)
				.build()
				.unwrap();

		let invoice = StaticInvoiceBuilder::for_offer_using_derived_keys(
			&valid_offer,
			payment_paths(),
			vec![blinded_path()],
			now,
			&expanded_key,
			nonce,
			&secp_ctx,
		)
		.unwrap()
		.build_and_sign(&secp_ctx)
		.unwrap();
		assert!(!invoice.is_expired());
		assert_eq!(invoice.absolute_expiry(), Some(future_expiry));

		let expired_offer =
			OfferBuilder::deriving_signing_pubkey(node_id, &expanded_key, nonce, &secp_ctx)
				.path(blinded_path())
				.absolute_expiry(past_expiry)
				.build()
				.unwrap();
		if let Err(e) = StaticInvoiceBuilder::for_offer_using_derived_keys(
			&expired_offer,
			payment_paths(),
			vec![blinded_path()],
			now,
			&expanded_key,
			nonce,
			&secp_ctx,
		)
		.unwrap()
		.build_and_sign(&secp_ctx)
		{
			assert_eq!(e, Bolt12SemanticError::AlreadyExpired);
		} else {
			panic!("expected error")
		}
	}

	#[test]
	fn builds_invoice_from_offer_using_derived_key() {
		let node_id = recipient_pubkey();
		let now = now();
		let expanded_key = ExpandedKey::new([42; 32]);
		let entropy = FixedEntropy {};
		let nonce = Nonce::from_entropy_source(&entropy);
		let secp_ctx = Secp256k1::new();

		let offer = OfferBuilder::deriving_signing_pubkey(node_id, &expanded_key, nonce, &secp_ctx)
			.path(blinded_path())
			.experimental_foo(42)
			.build()
			.unwrap();

		if let Err(e) = StaticInvoiceBuilder::for_offer_using_derived_keys(
			&offer,
			payment_paths(),
			vec![blinded_path()],
			now,
			&expanded_key,
			nonce,
			&secp_ctx,
		)
		.unwrap()
		.build_and_sign(&secp_ctx)
		{
			panic!("error building invoice: {:?}", e);
		}

		let expanded_key = ExpandedKey::new([41; 32]);
		if let Err(e) = StaticInvoiceBuilder::for_offer_using_derived_keys(
			&offer,
			payment_paths(),
			vec![blinded_path()],
			now,
			&expanded_key,
			nonce,
			&secp_ctx,
		) {
			assert_eq!(e, Bolt12SemanticError::InvalidMetadata);
		} else {
			panic!("expected error")
		}
	}

	#[test]
	fn fails_build_with_missing_paths() {
		let node_id = recipient_pubkey();
		let now = now();
		let expanded_key = ExpandedKey::new([42; 32]);
		let entropy = FixedEntropy {};
		let nonce = Nonce::from_entropy_source(&entropy);
		let secp_ctx = Secp256k1::new();

		let valid_offer =
			OfferBuilder::deriving_signing_pubkey(node_id, &expanded_key, nonce, &secp_ctx)
				.path(blinded_path())
				.build()
				.unwrap();

		// Error if payment paths are missing.
		if let Err(e) = StaticInvoiceBuilder::for_offer_using_derived_keys(
			&valid_offer,
			Vec::new(),
			vec![blinded_path()],
			now,
			&expanded_key,
			nonce,
			&secp_ctx,
		) {
			assert_eq!(e, Bolt12SemanticError::MissingPaths);
		} else {
			panic!("expected error")
		}

		// Error if message paths are missing.
		if let Err(e) = StaticInvoiceBuilder::for_offer_using_derived_keys(
			&valid_offer,
			payment_paths(),
			Vec::new(),
			now,
			&expanded_key,
			nonce,
			&secp_ctx,
		) {
			assert_eq!(e, Bolt12SemanticError::MissingPaths);
		} else {
			panic!("expected error")
		}

		// Error if offer paths are missing.
		let mut offer_without_paths = valid_offer.clone();
		let (mut offer_tlv_stream, _) = offer_without_paths.as_tlv_stream();
		offer_tlv_stream.paths.take();
		let mut buffer = Vec::new();
		offer_tlv_stream.write(&mut buffer).unwrap();
		offer_without_paths = Offer::try_from(buffer).unwrap();
		if let Err(e) = StaticInvoiceBuilder::for_offer_using_derived_keys(
			&offer_without_paths,
			payment_paths(),
			vec![blinded_path()],
			now,
			&expanded_key,
			nonce,
			&secp_ctx,
		) {
			assert_eq!(e, Bolt12SemanticError::MissingPaths);
		} else {
			panic!("expected error")
		}
	}

	#[test]
	fn fails_building_with_missing_issuer_signing_pubkey() {
		let node_id = recipient_pubkey();
		let now = now();
		let expanded_key = ExpandedKey::new([42; 32]);
		let entropy = FixedEntropy {};
		let nonce = Nonce::from_entropy_source(&entropy);
		let secp_ctx = Secp256k1::new();

		let valid_offer =
			OfferBuilder::deriving_signing_pubkey(node_id, &expanded_key, nonce, &secp_ctx)
				.path(blinded_path())
				.build()
				.unwrap();

		let mut offer_missing_issuer_id = valid_offer.clone();
		let (mut offer_tlv_stream, _) = offer_missing_issuer_id.as_tlv_stream();
		offer_tlv_stream.issuer_id.take();
		let mut buffer = Vec::new();
		offer_tlv_stream.write(&mut buffer).unwrap();
		offer_missing_issuer_id = Offer::try_from(buffer).unwrap();

		if let Err(e) = StaticInvoiceBuilder::for_offer_using_derived_keys(
			&offer_missing_issuer_id,
			payment_paths(),
			vec![blinded_path()],
			now,
			&expanded_key,
			nonce,
			&secp_ctx,
		) {
			assert_eq!(e, Bolt12SemanticError::MissingIssuerSigningPubkey);
		} else {
			panic!("expected error")
		}
	}

	#[test]
	fn fails_building_with_invalid_metadata() {
		let now = now();
		let expanded_key = ExpandedKey::new([42; 32]);
		let entropy = FixedEntropy {};
		let nonce = Nonce::from_entropy_source(&entropy);
		let secp_ctx = Secp256k1::new();

		let offer = OfferBuilder::new(recipient_pubkey())
			.path(blinded_path())
			.metadata(vec![42; 32])
			.unwrap()
			.build()
			.unwrap();
		if let Err(e) = StaticInvoiceBuilder::for_offer_using_derived_keys(
			&offer,
			payment_paths(),
			vec![blinded_path()],
			now,
			&expanded_key,
			nonce,
			&secp_ctx,
		) {
			assert_eq!(e, Bolt12SemanticError::InvalidMetadata);
		} else {
			panic!("expected error")
		}
	}

	#[test]
	fn fails_building_with_extra_offer_chains() {
		let node_id = recipient_pubkey();
		let now = now();
		let expanded_key = ExpandedKey::new([42; 32]);
		let entropy = FixedEntropy {};
		let nonce = Nonce::from_entropy_source(&entropy);
		let secp_ctx = Secp256k1::new();

		let offer_with_extra_chain =
			OfferBuilder::deriving_signing_pubkey(node_id, &expanded_key, nonce, &secp_ctx)
				.path(blinded_path())
				.chain(Network::Bitcoin)
				.chain(Network::Testnet)
				.build()
				.unwrap();

		if let Err(e) = StaticInvoiceBuilder::for_offer_using_derived_keys(
			&offer_with_extra_chain,
			payment_paths(),
			vec![blinded_path()],
			now,
			&expanded_key,
			nonce,
			&secp_ctx,
		) {
			assert_eq!(e, Bolt12SemanticError::UnexpectedChain);
		} else {
			panic!("expected error")
		}
	}

	#[test]
	fn parses_invoice_with_relative_expiry() {
		let node_id = recipient_pubkey();
		let payment_paths = payment_paths();
		let now = now();
		let expanded_key = ExpandedKey::new([42; 32]);
		let entropy = FixedEntropy {};
		let nonce = Nonce::from_entropy_source(&entropy);
		let secp_ctx = Secp256k1::new();

		let offer = OfferBuilder::deriving_signing_pubkey(node_id, &expanded_key, nonce, &secp_ctx)
			.path(blinded_path())
			.build()
			.unwrap();

		const TEST_RELATIVE_EXPIRY: u32 = 3600;
		let invoice = StaticInvoiceBuilder::for_offer_using_derived_keys(
			&offer,
			payment_paths.clone(),
			vec![blinded_path()],
			now,
			&expanded_key,
			nonce,
			&secp_ctx,
		)
		.unwrap()
		.relative_expiry(TEST_RELATIVE_EXPIRY)
		.build_and_sign(&secp_ctx)
		.unwrap();

		let mut buffer = Vec::new();
		invoice.write(&mut buffer).unwrap();

		match StaticInvoice::try_from(buffer) {
			Ok(invoice) => assert_eq!(
				invoice.relative_expiry(),
				Duration::from_secs(TEST_RELATIVE_EXPIRY as u64)
			),
			Err(e) => panic!("error parsing invoice: {:?}", e),
		}
	}

	#[test]
	fn parses_invoice_with_allow_mpp() {
		let node_id = recipient_pubkey();
		let payment_paths = payment_paths();
		let now = now();
		let expanded_key = ExpandedKey::new([42; 32]);
		let entropy = FixedEntropy {};
		let nonce = Nonce::from_entropy_source(&entropy);
		let secp_ctx = Secp256k1::new();

		let offer = OfferBuilder::deriving_signing_pubkey(node_id, &expanded_key, nonce, &secp_ctx)
			.path(blinded_path())
			.build()
			.unwrap();

		let invoice = StaticInvoiceBuilder::for_offer_using_derived_keys(
			&offer,
			payment_paths.clone(),
			vec![blinded_path()],
			now,
			&expanded_key,
			nonce,
			&secp_ctx,
		)
		.unwrap()
		.allow_mpp()
		.build_and_sign(&secp_ctx)
		.unwrap();

		let mut buffer = Vec::new();
		invoice.write(&mut buffer).unwrap();

		match StaticInvoice::try_from(buffer) {
			Ok(invoice) => {
				let mut features = Bolt12InvoiceFeatures::empty();
				features.set_basic_mpp_optional();
				assert_eq!(invoice.invoice_features(), &features);
			},
			Err(e) => panic!("error parsing invoice: {:?}", e),
		}
	}

	#[test]
	fn fails_parsing_missing_invoice_fields() {
		// Error if `created_at` is missing.
		let missing_created_at_invoice = invoice();
		let mut tlv_stream = missing_created_at_invoice.as_tlv_stream();
		tlv_stream.1.created_at = None;
		match StaticInvoice::try_from(tlv_stream_to_bytes(&tlv_stream)) {
			Ok(_) => panic!("expected error"),
			Err(e) => {
				assert_eq!(
					e,
					Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::MissingCreationTime)
				);
			},
		}

		// Error if `node_id` is missing.
		let missing_node_id_invoice = invoice();
		let mut tlv_stream = missing_node_id_invoice.as_tlv_stream();
		tlv_stream.1.node_id = None;
		match StaticInvoice::try_from(tlv_stream_to_bytes(&tlv_stream)) {
			Ok(_) => panic!("expected error"),
			Err(e) => {
				assert_eq!(
					e,
					Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::MissingSigningPubkey)
				);
			},
		}

		// Error if message paths are missing.
		let missing_message_paths_invoice = invoice();
		let mut tlv_stream = missing_message_paths_invoice.as_tlv_stream();
		tlv_stream.1.message_paths = None;
		match StaticInvoice::try_from(tlv_stream_to_bytes(&tlv_stream)) {
			Ok(_) => panic!("expected error"),
			Err(e) => {
				assert_eq!(
					e,
					Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::MissingPaths)
				);
			},
		}

		// Error if signature is missing.
		let invoice = invoice();
		let mut buffer = Vec::new();
		invoice.contents.as_tlv_stream().write(&mut buffer).unwrap();
		match StaticInvoice::try_from(buffer) {
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(
				e,
				Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::MissingSignature)
			),
		}
	}

	#[test]
	fn fails_parsing_invalid_signing_pubkey() {
		let invoice = invoice();
		let invalid_pubkey = payer_pubkey();
		let mut tlv_stream = invoice.as_tlv_stream();
		tlv_stream.1.node_id = Some(&invalid_pubkey);

		match StaticInvoice::try_from(tlv_stream_to_bytes(&tlv_stream)) {
			Ok(_) => panic!("expected error"),
			Err(e) => {
				assert_eq!(
					e,
					Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::InvalidSigningPubkey)
				);
			},
		}
	}

	#[test]
	fn fails_parsing_invoice_with_invalid_signature() {
		let mut invoice = invoice();
		let last_signature_byte = invoice.bytes.last_mut().unwrap();
		*last_signature_byte = last_signature_byte.wrapping_add(1);

		let mut buffer = Vec::new();
		invoice.write(&mut buffer).unwrap();

		match StaticInvoice::try_from(buffer) {
			Ok(_) => panic!("expected error"),
			Err(e) => {
				assert_eq!(
					e,
					Bolt12ParseError::InvalidSignature(secp256k1::Error::IncorrectSignature)
				);
			},
		}
	}

	#[test]
	fn parses_invoice_with_unknown_tlv_records() {
		let node_id = recipient_pubkey();
		let payment_paths = payment_paths();
		let now = now();
		let expanded_key = ExpandedKey::new([42; 32]);
		let entropy = FixedEntropy {};
		let nonce = Nonce::from_entropy_source(&entropy);
		let secp_ctx = Secp256k1::new();

		let offer = OfferBuilder::deriving_signing_pubkey(node_id, &expanded_key, nonce, &secp_ctx)
			.path(blinded_path())
			.build()
			.unwrap();

		const UNKNOWN_ODD_TYPE: u64 = INVOICE_TYPES.end - 1;
		assert!(UNKNOWN_ODD_TYPE % 2 == 1);

		let (mut unsigned_invoice, keys) = StaticInvoiceBuilder::for_offer_using_derived_keys(
			&offer,
			payment_paths.clone(),
			vec![blinded_path()],
			now,
			&expanded_key,
			nonce,
			&secp_ctx,
		)
		.unwrap()
		.build()
		.unwrap();

		let mut unknown_bytes = Vec::new();
		BigSize(UNKNOWN_ODD_TYPE).write(&mut unknown_bytes).unwrap();
		BigSize(32).write(&mut unknown_bytes).unwrap();
		[42u8; 32].write(&mut unknown_bytes).unwrap();

		unsigned_invoice.bytes.extend_from_slice(&unknown_bytes);
		unsigned_invoice.tagged_hash =
			TaggedHash::from_valid_tlv_stream_bytes(SIGNATURE_TAG, &unsigned_invoice.bytes);

		let invoice = unsigned_invoice
			.sign(|message: &UnsignedStaticInvoice| {
				Ok(secp_ctx.sign_schnorr_no_aux_rand(message.as_ref().as_digest(), &keys))
			})
			.unwrap();

		let mut encoded_invoice = Vec::new();
		invoice.write(&mut encoded_invoice).unwrap();

		match StaticInvoice::try_from(encoded_invoice.clone()) {
			Ok(invoice) => assert_eq!(invoice.bytes, encoded_invoice),
			Err(e) => panic!("error parsing invoice: {:?}", e),
		}

		const UNKNOWN_EVEN_TYPE: u64 = INVOICE_TYPES.end - 2;
		assert!(UNKNOWN_EVEN_TYPE % 2 == 0);

		let (mut unsigned_invoice, keys) = StaticInvoiceBuilder::for_offer_using_derived_keys(
			&offer,
			payment_paths.clone(),
			vec![blinded_path()],
			now,
			&expanded_key,
			nonce,
			&secp_ctx,
		)
		.unwrap()
		.build()
		.unwrap();

		let mut unknown_bytes = Vec::new();
		BigSize(UNKNOWN_EVEN_TYPE).write(&mut unknown_bytes).unwrap();
		BigSize(32).write(&mut unknown_bytes).unwrap();
		[42u8; 32].write(&mut unknown_bytes).unwrap();

		unsigned_invoice.bytes.extend_from_slice(&unknown_bytes);
		unsigned_invoice.tagged_hash =
			TaggedHash::from_valid_tlv_stream_bytes(SIGNATURE_TAG, &unsigned_invoice.bytes);

		let invoice = unsigned_invoice
			.sign(|message: &UnsignedStaticInvoice| {
				Ok(secp_ctx.sign_schnorr_no_aux_rand(message.as_ref().as_digest(), &keys))
			})
			.unwrap();

		let mut encoded_invoice = Vec::new();
		invoice.write(&mut encoded_invoice).unwrap();

		match StaticInvoice::try_from(encoded_invoice) {
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, Bolt12ParseError::Decode(DecodeError::UnknownRequiredFeature)),
		}
	}

	#[test]
	fn parses_invoice_with_experimental_tlv_records() {
		let node_id = recipient_pubkey();
		let payment_paths = payment_paths();
		let now = now();
		let expanded_key = ExpandedKey::new([42; 32]);
		let entropy = FixedEntropy {};
		let nonce = Nonce::from_entropy_source(&entropy);
		let secp_ctx = Secp256k1::new();

		let offer = OfferBuilder::deriving_signing_pubkey(node_id, &expanded_key, nonce, &secp_ctx)
			.path(blinded_path())
			.build()
			.unwrap();

		let invoice = StaticInvoiceBuilder::for_offer_using_derived_keys(
			&offer,
			payment_paths.clone(),
			vec![blinded_path()],
			now,
			&expanded_key,
			nonce,
			&secp_ctx,
		)
		.unwrap()
		.experimental_baz(42)
		.build_and_sign(&secp_ctx)
		.unwrap();

		let mut encoded_invoice = Vec::new();
		invoice.write(&mut encoded_invoice).unwrap();

		assert!(StaticInvoice::try_from(encoded_invoice).is_ok());

		const UNKNOWN_ODD_TYPE: u64 = EXPERIMENTAL_INVOICE_TYPES.start + 1;
		assert!(UNKNOWN_ODD_TYPE % 2 == 1);

		let (mut unsigned_invoice, keys) = StaticInvoiceBuilder::for_offer_using_derived_keys(
			&offer,
			payment_paths.clone(),
			vec![blinded_path()],
			now,
			&expanded_key,
			nonce,
			&secp_ctx,
		)
		.unwrap()
		.build()
		.unwrap();

		let mut unknown_bytes = Vec::new();
		BigSize(UNKNOWN_ODD_TYPE).write(&mut unknown_bytes).unwrap();
		BigSize(32).write(&mut unknown_bytes).unwrap();
		[42u8; 32].write(&mut unknown_bytes).unwrap();

		unsigned_invoice.experimental_bytes.extend_from_slice(&unknown_bytes);

		let tlv_stream = TlvStream::new(&unsigned_invoice.bytes)
			.chain(TlvStream::new(&unsigned_invoice.experimental_bytes));
		unsigned_invoice.tagged_hash = TaggedHash::from_tlv_stream(SIGNATURE_TAG, tlv_stream);

		let invoice = unsigned_invoice
			.sign(|message: &UnsignedStaticInvoice| {
				Ok(secp_ctx.sign_schnorr_no_aux_rand(message.as_ref().as_digest(), &keys))
			})
			.unwrap();

		let mut encoded_invoice = Vec::new();
		invoice.write(&mut encoded_invoice).unwrap();

		match StaticInvoice::try_from(encoded_invoice.clone()) {
			Ok(invoice) => assert_eq!(invoice.bytes, encoded_invoice),
			Err(e) => panic!("error parsing invoice: {:?}", e),
		}

		const UNKNOWN_EVEN_TYPE: u64 = EXPERIMENTAL_INVOICE_TYPES.start;
		assert!(UNKNOWN_EVEN_TYPE % 2 == 0);

		let (mut unsigned_invoice, keys) = StaticInvoiceBuilder::for_offer_using_derived_keys(
			&offer,
			payment_paths.clone(),
			vec![blinded_path()],
			now,
			&expanded_key,
			nonce,
			&secp_ctx,
		)
		.unwrap()
		.build()
		.unwrap();

		let mut unknown_bytes = Vec::new();
		BigSize(UNKNOWN_EVEN_TYPE).write(&mut unknown_bytes).unwrap();
		BigSize(32).write(&mut unknown_bytes).unwrap();
		[42u8; 32].write(&mut unknown_bytes).unwrap();

		unsigned_invoice.experimental_bytes.extend_from_slice(&unknown_bytes);

		let tlv_stream = TlvStream::new(&unsigned_invoice.bytes)
			.chain(TlvStream::new(&unsigned_invoice.experimental_bytes));
		unsigned_invoice.tagged_hash = TaggedHash::from_tlv_stream(SIGNATURE_TAG, tlv_stream);

		let invoice = unsigned_invoice
			.sign(|message: &UnsignedStaticInvoice| {
				Ok(secp_ctx.sign_schnorr_no_aux_rand(message.as_ref().as_digest(), &keys))
			})
			.unwrap();

		let mut encoded_invoice = Vec::new();
		invoice.write(&mut encoded_invoice).unwrap();

		match StaticInvoice::try_from(encoded_invoice) {
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, Bolt12ParseError::Decode(DecodeError::UnknownRequiredFeature)),
		}

		let offer = OfferBuilder::deriving_signing_pubkey(node_id, &expanded_key, nonce, &secp_ctx)
			.path(blinded_path())
			.build()
			.unwrap();

		let invoice = StaticInvoiceBuilder::for_offer_using_derived_keys(
			&offer,
			payment_paths.clone(),
			vec![blinded_path()],
			now,
			&expanded_key,
			nonce,
			&secp_ctx,
		)
		.unwrap()
		.build_and_sign(&secp_ctx)
		.unwrap();

		let mut encoded_invoice = Vec::new();
		invoice.write(&mut encoded_invoice).unwrap();

		BigSize(UNKNOWN_ODD_TYPE).write(&mut encoded_invoice).unwrap();
		BigSize(32).write(&mut encoded_invoice).unwrap();
		[42u8; 32].write(&mut encoded_invoice).unwrap();

		match StaticInvoice::try_from(encoded_invoice) {
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(
				e,
				Bolt12ParseError::InvalidSignature(secp256k1::Error::IncorrectSignature)
			),
		}
	}

	#[test]
	fn fails_parsing_invoice_with_out_of_range_tlv_records() {
		let invoice = invoice();
		let mut encoded_invoice = Vec::new();
		invoice.write(&mut encoded_invoice).unwrap();
		BigSize(1002).write(&mut encoded_invoice).unwrap();
		BigSize(32).write(&mut encoded_invoice).unwrap();
		[42u8; 32].write(&mut encoded_invoice).unwrap();

		match StaticInvoice::try_from(encoded_invoice) {
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, Bolt12ParseError::Decode(DecodeError::InvalidValue)),
		}
	}

	#[test]
	fn fails_parsing_invoice_with_invalid_offer_fields() {
		// Error if the offer is missing paths.
		let missing_offer_paths_invoice = invoice();
		let mut tlv_stream = missing_offer_paths_invoice.as_tlv_stream();
		tlv_stream.0.paths = None;
		match StaticInvoice::try_from(tlv_stream_to_bytes(&tlv_stream)) {
			Ok(_) => panic!("expected error"),
			Err(e) => {
				assert_eq!(
					e,
					Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::MissingPaths)
				);
			},
		}

		// Error if the offer has more than one chain.
		let invalid_offer_chains_invoice = invoice();
		let mut tlv_stream = invalid_offer_chains_invoice.as_tlv_stream();
		let invalid_chains = vec![
			ChainHash::using_genesis_block(Network::Bitcoin),
			ChainHash::using_genesis_block(Network::Testnet),
		];
		tlv_stream.0.chains = Some(&invalid_chains);
		match StaticInvoice::try_from(tlv_stream_to_bytes(&tlv_stream)) {
			Ok(_) => panic!("expected error"),
			Err(e) => {
				assert_eq!(
					e,
					Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::UnexpectedChain)
				);
			},
		}
	}
}
