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
//! offer. The recipient of the request responds with a [`Bolt12Invoice`].
//!
//! For an "offer for money" (e.g., refund, ATM withdrawal), where an offer doesn't exist as a
//! precursor, see [`Refund`].
//!
//! [`Bolt12Invoice`]: crate::offers::invoice::Bolt12Invoice
//! [`Refund`]: crate::offers::refund::Refund
//!
//! ```
//! extern crate bitcoin;
//! extern crate lightning;
//!
//! use bitcoin::network::Network;
//! use bitcoin::secp256k1::{Keypair, PublicKey, Secp256k1, SecretKey};
//! use lightning::ln::channelmanager::PaymentId;
//! use lightning::ln::inbound_payment::ExpandedKey;
//! use lightning::types::features::OfferFeatures;
//! use lightning::offers::invoice_request::UnsignedInvoiceRequest;
//! # use lightning::offers::nonce::Nonce;
//! use lightning::offers::offer::Offer;
//! # use lightning::sign::EntropySource;
//! use lightning::util::ser::Writeable;
//!
//! # struct FixedEntropy;
//! # impl EntropySource for FixedEntropy {
//! #     fn get_secure_random_bytes(&self) -> [u8; 32] {
//! #         [42; 32]
//! #     }
//! # }
//! # fn parse() -> Result<(), lightning::offers::parse::Bolt12ParseError> {
//! let expanded_key = ExpandedKey::new([42; 32]);
//! # let entropy = FixedEntropy {};
//! # let nonce = Nonce::from_entropy_source(&entropy);
//! let secp_ctx = Secp256k1::new();
//! let payment_id = PaymentId([1; 32]);
//! let mut buffer = Vec::new();
//!
//! # use lightning::offers::invoice_request::InvoiceRequestBuilder;
//! # <InvoiceRequestBuilder<_>>::from(
//! "lno1qcp4256ypq"
//!     .parse::<Offer>()?
//!     .request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)?
//! # )
//!     .chain(Network::Testnet)?
//!     .amount_msats(1000)?
//!     .quantity(5)?
//!     .payer_note("foo".to_string())
//!     .build_and_sign()?
//!     .write(&mut buffer)
//!     .unwrap();
//! # Ok(())
//! # }
//! ```

use bitcoin::constants::ChainHash;
use bitcoin::network::Network;
use bitcoin::secp256k1::{Keypair, PublicKey, Secp256k1, self};
use bitcoin::secp256k1::schnorr::Signature;
use crate::io;
use crate::blinded_path::message::BlindedMessagePath;
use crate::blinded_path::payment::BlindedPaymentPath;
use crate::types::payment::PaymentHash;
use crate::ln::channelmanager::PaymentId;
use crate::types::features::InvoiceRequestFeatures;
use crate::ln::inbound_payment::{ExpandedKey, IV_LEN};
use crate::ln::msgs::DecodeError;
use crate::offers::merkle::{SignError, SignFn, SignatureTlvStream, SignatureTlvStreamRef, TaggedHash, TlvStream, self, SIGNATURE_TLV_RECORD_SIZE};
use crate::offers::nonce::Nonce;
use crate::offers::offer::{EXPERIMENTAL_OFFER_TYPES, ExperimentalOfferTlvStream, ExperimentalOfferTlvStreamRef, OFFER_TYPES, Offer, OfferContents, OfferId, OfferTlvStream, OfferTlvStreamRef};
use crate::offers::parse::{Bolt12ParseError, ParsedMessage, Bolt12SemanticError};
use crate::offers::payer::{PayerContents, PayerTlvStream, PayerTlvStreamRef};
use crate::offers::signer::{Metadata, MetadataMaterial};
use crate::onion_message::dns_resolution::HumanReadableName;
use crate::util::ser::{CursorReadable, HighZeroBytesDroppedBigSize, Readable, WithoutLength, Writeable, Writer};
use crate::util::string::{PrintableString, UntrustedString};

#[cfg(not(c_bindings))]
use {
	crate::offers::invoice::{DerivedSigningPubkey, ExplicitSigningPubkey, InvoiceBuilder},
};
#[cfg(c_bindings)]
use {
	crate::offers::invoice::{InvoiceWithDerivedSigningPubkeyBuilder, InvoiceWithExplicitSigningPubkeyBuilder},
};

#[allow(unused_imports)]
use crate::prelude::*;

/// Tag for the hash function used when signing an [`InvoiceRequest`]'s merkle root.
pub const SIGNATURE_TAG: &'static str = concat!("lightning", "invoice_request", "signature");

pub(super) const IV_BYTES: &[u8; IV_LEN] = b"LDK Invreq ~~~~~";

/// Builds an [`InvoiceRequest`] from an [`Offer`] for the "offer to be paid" flow.
///
/// See [module-level documentation] for usage.
///
/// This is not exported to bindings users as builder patterns don't map outside of move semantics.
///
/// [module-level documentation]: self
pub struct InvoiceRequestBuilder<'a, 'b, T: secp256k1::Signing> {
	offer: &'a Offer,
	invoice_request: InvoiceRequestContentsWithoutPayerSigningPubkey,
	payer_signing_pubkey: Option<PublicKey>,
	secp_ctx: Option<&'b Secp256k1<T>>,
}

/// Builds an [`InvoiceRequest`] from an [`Offer`] for the "offer to be paid" flow.
///
/// See [module-level documentation] for usage.
///
/// [module-level documentation]: self
#[cfg(c_bindings)]
pub struct InvoiceRequestWithDerivedPayerSigningPubkeyBuilder<'a, 'b> {
	offer: &'a Offer,
	invoice_request: InvoiceRequestContentsWithoutPayerSigningPubkey,
	payer_signing_pubkey: Option<PublicKey>,
	secp_ctx: Option<&'b Secp256k1<secp256k1::All>>,
}

macro_rules! invoice_request_derived_payer_signing_pubkey_builder_methods { (
	$self: ident, $self_type: ty, $secp_context: ty
) => {
	#[cfg_attr(c_bindings, allow(dead_code))]
	pub(super) fn deriving_signing_pubkey(
		offer: &'a Offer, expanded_key: &ExpandedKey, nonce: Nonce,
		secp_ctx: &'b Secp256k1<$secp_context>, payment_id: PaymentId
	) -> Self {
		let payment_id = Some(payment_id);
		let derivation_material = MetadataMaterial::new(nonce, expanded_key, payment_id);
		let metadata = Metadata::DerivedSigningPubkey(derivation_material);
		Self {
			offer,
			invoice_request: Self::create_contents(offer, metadata),
			payer_signing_pubkey: None,
			secp_ctx: Some(secp_ctx),
		}
	}

	/// Builds a signed [`InvoiceRequest`] after checking for valid semantics.
	pub fn build_and_sign($self: $self_type) -> Result<InvoiceRequest, Bolt12SemanticError> {
		let (unsigned_invoice_request, keys, secp_ctx) = $self.build_with_checks()?;
		#[cfg(c_bindings)]
		let mut unsigned_invoice_request = unsigned_invoice_request;
		debug_assert!(keys.is_some());

		let secp_ctx = secp_ctx.unwrap();
		let keys = keys.unwrap();
		let invoice_request = unsigned_invoice_request
			.sign(|message: &UnsignedInvoiceRequest|
				Ok(secp_ctx.sign_schnorr_no_aux_rand(message.as_ref().as_digest(), &keys))
			)
			.unwrap();
		Ok(invoice_request)
	}
} }

macro_rules! invoice_request_builder_methods { (
	$self: ident, $self_type: ty, $return_type: ty, $return_value: expr, $secp_context: ty $(, $self_mut: tt)?
) => {
	#[cfg_attr(c_bindings, allow(dead_code))]
	fn create_contents(offer: &Offer, metadata: Metadata) -> InvoiceRequestContentsWithoutPayerSigningPubkey {
		let offer = offer.contents.clone();
		InvoiceRequestContentsWithoutPayerSigningPubkey {
			payer: PayerContents(metadata), offer, chain: None, amount_msats: None,
			features: InvoiceRequestFeatures::empty(), quantity: None, payer_note: None,
			offer_from_hrn: None,
			#[cfg(test)]
			experimental_bar: None,
		}
	}

	/// Sets the [`InvoiceRequest::chain`] of the given [`Network`] for paying an invoice. If not
	/// called, [`Network::Bitcoin`] is assumed. Errors if the chain for `network` is not supported
	/// by the offer.
	///
	/// Successive calls to this method will override the previous setting.
	pub fn chain($self: $self_type, network: Network) -> Result<$return_type, Bolt12SemanticError> {
		$self.chain_hash(ChainHash::using_genesis_block(network))
	}

	/// Sets the [`InvoiceRequest::chain`] for paying an invoice. If not called, the chain hash of
	/// [`Network::Bitcoin`] is assumed. Errors if the chain for `network` is not supported by the
	/// offer.
	///
	/// Successive calls to this method will override the previous setting.
	pub(crate) fn chain_hash($($self_mut)* $self: $self_type, chain: ChainHash) -> Result<$return_type, Bolt12SemanticError> {
		if !$self.offer.supports_chain(chain) {
			return Err(Bolt12SemanticError::UnsupportedChain);
		}

		$self.invoice_request.chain = Some(chain);
		Ok($return_value)
	}

	/// Sets the [`InvoiceRequest::amount_msats`] for paying an invoice. Errors if `amount_msats` is
	/// not at least the expected invoice amount (i.e., [`Offer::amount`] times [`quantity`]).
	///
	/// Successive calls to this method will override the previous setting.
	///
	/// [`quantity`]: Self::quantity
	pub fn amount_msats($($self_mut)* $self: $self_type, amount_msats: u64) -> Result<$return_type, Bolt12SemanticError> {
		$self.invoice_request.offer.check_amount_msats_for_quantity(
			Some(amount_msats), $self.invoice_request.quantity
		)?;
		$self.invoice_request.amount_msats = Some(amount_msats);
		Ok($return_value)
	}

	/// Sets [`InvoiceRequest::quantity`] of items. If not set, `1` is assumed. Errors if `quantity`
	/// does not conform to [`Offer::is_valid_quantity`].
	///
	/// Successive calls to this method will override the previous setting.
	pub fn quantity($($self_mut)* $self: $self_type, quantity: u64) -> Result<$return_type, Bolt12SemanticError> {
		$self.invoice_request.offer.check_quantity(Some(quantity))?;
		$self.invoice_request.quantity = Some(quantity);
		Ok($return_value)
	}

	/// Sets the [`InvoiceRequest::payer_note`].
	///
	/// Successive calls to this method will override the previous setting.
	pub fn payer_note($($self_mut)* $self: $self_type, payer_note: String) -> $return_type {
		$self.invoice_request.payer_note = Some(payer_note);
		$return_value
	}

	/// Sets the [`InvoiceRequest::offer_from_hrn`].
	///
	/// Successive calls to this method will override the previous setting.
	pub fn sourced_from_human_readable_name($($self_mut)* $self: $self_type, hrn: HumanReadableName) -> $return_type {
		$self.invoice_request.offer_from_hrn = Some(hrn);
		$return_value
	}

	fn build_with_checks($($self_mut)* $self: $self_type) -> Result<
		(UnsignedInvoiceRequest, Option<Keypair>, Option<&'b Secp256k1<$secp_context>>),
		Bolt12SemanticError
	> {
		#[cfg(feature = "std")] {
			if $self.offer.is_expired() {
				return Err(Bolt12SemanticError::AlreadyExpired);
			}
		}

		let chain = $self.invoice_request.chain();
		if !$self.offer.supports_chain(chain) {
			return Err(Bolt12SemanticError::UnsupportedChain);
		}

		if chain == $self.offer.implied_chain() {
			$self.invoice_request.chain = None;
		}

		if $self.offer.amount().is_none() && $self.invoice_request.amount_msats.is_none() {
			return Err(Bolt12SemanticError::MissingAmount);
		}

		$self.invoice_request.offer.check_quantity($self.invoice_request.quantity)?;
		$self.invoice_request.offer.check_amount_msats_for_quantity(
			$self.invoice_request.amount_msats, $self.invoice_request.quantity
		)?;

		Ok($self.build_without_checks())
	}

	fn build_without_checks($($self_mut)* $self: $self_type) ->
		(UnsignedInvoiceRequest, Option<Keypair>, Option<&'b Secp256k1<$secp_context>>)
	{
		// Create the metadata for stateless verification of a Bolt12Invoice.
		let mut keys = None;
		let secp_ctx = $self.secp_ctx.clone();
		if $self.invoice_request.payer.0.has_derivation_material() {
			let mut metadata = core::mem::take(&mut $self.invoice_request.payer.0);

			let mut tlv_stream = $self.invoice_request.as_tlv_stream();
			debug_assert!(tlv_stream.2.payer_id.is_none());
			tlv_stream.0.metadata = None;
			if !metadata.derives_payer_keys() {
				tlv_stream.2.payer_id = $self.payer_signing_pubkey.as_ref();
			}

			let (derived_metadata, derived_keys) =
				metadata.derive_from(IV_BYTES, tlv_stream, $self.secp_ctx);
			metadata = derived_metadata;
			keys = derived_keys;
			if let Some(keys) = keys {
				debug_assert!($self.payer_signing_pubkey.is_none());
				$self.payer_signing_pubkey = Some(keys.public_key());
			}

			$self.invoice_request.payer.0 = metadata;
		}

		debug_assert!($self.invoice_request.payer.0.as_bytes().is_some());
		debug_assert!($self.payer_signing_pubkey.is_some());
		let payer_signing_pubkey = $self.payer_signing_pubkey.unwrap();

		let invoice_request = InvoiceRequestContents {
			#[cfg(not(c_bindings))]
			inner: $self.invoice_request,
			#[cfg(c_bindings)]
			inner: $self.invoice_request.clone(),
			payer_signing_pubkey,
		};
		let unsigned_invoice_request = UnsignedInvoiceRequest::new($self.offer, invoice_request);

		(unsigned_invoice_request, keys, secp_ctx)
	}
} }

#[cfg(test)]
macro_rules! invoice_request_builder_test_methods { (
	$self: ident, $self_type: ty, $return_type: ty, $return_value: expr $(, $self_mut: tt)?
) => {
	#[cfg_attr(c_bindings, allow(dead_code))]
	pub(super) fn payer_metadata($($self_mut)* $self: $self_type, metadata: Metadata) -> $return_type {
		$self.invoice_request.payer = PayerContents(metadata);
		$return_value
	}

	#[cfg_attr(c_bindings, allow(dead_code))]
	fn chain_unchecked($($self_mut)* $self: $self_type, network: Network) -> $return_type {
		let chain = ChainHash::using_genesis_block(network);
		$self.invoice_request.chain = Some(chain);
		$return_value
	}

	#[cfg_attr(c_bindings, allow(dead_code))]
	fn amount_msats_unchecked($($self_mut)* $self: $self_type, amount_msats: u64) -> $return_type {
		$self.invoice_request.amount_msats = Some(amount_msats);
		$return_value
	}

	#[cfg_attr(c_bindings, allow(dead_code))]
	fn features_unchecked($($self_mut)* $self: $self_type, features: InvoiceRequestFeatures) -> $return_type {
		$self.invoice_request.features = features;
		$return_value
	}

	#[cfg_attr(c_bindings, allow(dead_code))]
	fn quantity_unchecked($($self_mut)* $self: $self_type, quantity: u64) -> $return_type {
		$self.invoice_request.quantity = Some(quantity);
		$return_value
	}

	#[cfg_attr(c_bindings, allow(dead_code))]
	pub(super) fn payer_signing_pubkey($($self_mut)* $self: $self_type, signing_pubkey: PublicKey) -> $return_type {
		$self.payer_signing_pubkey = Some(signing_pubkey);
		$return_value
	}

	#[cfg_attr(c_bindings, allow(dead_code))]
	pub(super) fn experimental_bar($($self_mut)* $self: $self_type, experimental_bar: u64) -> $return_type {
		$self.invoice_request.experimental_bar = Some(experimental_bar);
		$return_value
	}

	#[cfg_attr(c_bindings, allow(dead_code))]
	pub(super) fn build_unchecked($self: $self_type) -> UnsignedInvoiceRequest {
		$self.build_without_checks().0
	}

	#[cfg_attr(c_bindings, allow(dead_code))]
	pub(super) fn build_unchecked_and_sign($self: $self_type) -> InvoiceRequest {
		let (unsigned_invoice_request, keys, secp_ctx) = $self.build_without_checks();
		#[cfg(c_bindings)]
		let mut unsigned_invoice_request = unsigned_invoice_request;
		debug_assert!(keys.is_some());

		let secp_ctx = secp_ctx.unwrap();
		let keys = keys.unwrap();
		unsigned_invoice_request
			.sign(|message: &UnsignedInvoiceRequest|
				Ok(secp_ctx.sign_schnorr_no_aux_rand(message.as_ref().as_digest(), &keys))
			)
			.unwrap()
	}
} }

impl<'a, 'b, T: secp256k1::Signing> InvoiceRequestBuilder<'a, 'b, T> {
	invoice_request_derived_payer_signing_pubkey_builder_methods!(self, Self, T);
	invoice_request_builder_methods!(self, Self, Self, self, T, mut);

	#[cfg(test)]
	invoice_request_builder_test_methods!(self, Self, Self, self, mut);
}

#[cfg(all(c_bindings, not(test)))]
impl<'a, 'b> InvoiceRequestWithDerivedPayerSigningPubkeyBuilder<'a, 'b> {
	invoice_request_derived_payer_signing_pubkey_builder_methods!(self, &mut Self, secp256k1::All);
	invoice_request_builder_methods!(self, &mut Self, (), (), secp256k1::All);
}

#[cfg(all(c_bindings, test))]
impl<'a, 'b> InvoiceRequestWithDerivedPayerSigningPubkeyBuilder<'a, 'b> {
	invoice_request_derived_payer_signing_pubkey_builder_methods!(self, &mut Self, secp256k1::All);
	invoice_request_builder_methods!(self, &mut Self, &mut Self, self, secp256k1::All);
	invoice_request_builder_test_methods!(self, &mut Self, &mut Self, self);
}

#[cfg(c_bindings)]
impl<'a, 'b> From<InvoiceRequestWithDerivedPayerSigningPubkeyBuilder<'a, 'b>>
for InvoiceRequestBuilder<'a, 'b, secp256k1::All> {
	fn from(builder: InvoiceRequestWithDerivedPayerSigningPubkeyBuilder<'a, 'b>) -> Self {
		let InvoiceRequestWithDerivedPayerSigningPubkeyBuilder {
			offer, invoice_request, payer_signing_pubkey, secp_ctx,
		} = builder;

		Self {
			offer, invoice_request, payer_signing_pubkey, secp_ctx,
		}
	}
}

/// A semantically valid [`InvoiceRequest`] that hasn't been signed.
///
/// # Serialization
///
/// This is serialized as a TLV stream, which includes TLV records from the originating message. As
/// such, it may include unknown, odd TLV records.
#[derive(Clone)]
pub struct UnsignedInvoiceRequest {
	bytes: Vec<u8>,
	experimental_bytes: Vec<u8>,
	contents: InvoiceRequestContents,
	tagged_hash: TaggedHash,
}

/// A function for signing an [`UnsignedInvoiceRequest`].
pub trait SignInvoiceRequestFn {
	/// Signs a [`TaggedHash`] computed over the merkle root of `message`'s TLV stream.
	fn sign_invoice_request(&self, message: &UnsignedInvoiceRequest) -> Result<Signature, ()>;
}

impl<F> SignInvoiceRequestFn for F
where
	F: Fn(&UnsignedInvoiceRequest) -> Result<Signature, ()>,
{
	fn sign_invoice_request(&self, message: &UnsignedInvoiceRequest) -> Result<Signature, ()> {
		self(message)
	}
}

impl<F> SignFn<UnsignedInvoiceRequest> for F
where
	F: SignInvoiceRequestFn,
{
	fn sign(&self, message: &UnsignedInvoiceRequest) -> Result<Signature, ()> {
		self.sign_invoice_request(message)
	}
}

impl UnsignedInvoiceRequest {
	fn new(offer: &Offer, contents: InvoiceRequestContents) -> Self {
		// Use the offer bytes instead of the offer TLV stream as the offer may have contained
		// unknown TLV records, which are not stored in `OfferContents`.
		let (
			payer_tlv_stream, _offer_tlv_stream, invoice_request_tlv_stream,
			_experimental_offer_tlv_stream, experimental_invoice_request_tlv_stream,
		) = contents.as_tlv_stream();

		// Allocate enough space for the invoice_request, which will include:
		// - all TLV records from `offer.bytes`,
		// - all invoice_request-specific TLV records, and
		// - a signature TLV record once the invoice_request is signed.
		let mut bytes = Vec::with_capacity(
			offer.bytes.len()
				+ payer_tlv_stream.serialized_length()
				+ invoice_request_tlv_stream.serialized_length()
				+ SIGNATURE_TLV_RECORD_SIZE
				+ experimental_invoice_request_tlv_stream.serialized_length(),
		);

		payer_tlv_stream.write(&mut bytes).unwrap();

		for record in TlvStream::new(&offer.bytes).range(OFFER_TYPES) {
			record.write(&mut bytes).unwrap();
		}

		let remaining_bytes = &offer.bytes[bytes.len() - payer_tlv_stream.serialized_length()..];

		invoice_request_tlv_stream.write(&mut bytes).unwrap();

		let mut experimental_tlv_stream = TlvStream::new(remaining_bytes)
			.range(EXPERIMENTAL_OFFER_TYPES)
			.peekable();
		let mut experimental_bytes = Vec::with_capacity(
			remaining_bytes.len()
				- experimental_tlv_stream
					.peek()
					.map_or(remaining_bytes.len(), |first_record| first_record.start)
				+ experimental_invoice_request_tlv_stream.serialized_length(),
		);

		for record in experimental_tlv_stream {
			record.write(&mut experimental_bytes).unwrap();
		}

		experimental_invoice_request_tlv_stream.write(&mut experimental_bytes).unwrap();
		debug_assert_eq!(experimental_bytes.len(), experimental_bytes.capacity());

		let tlv_stream = TlvStream::new(&bytes).chain(TlvStream::new(&experimental_bytes));
		let tagged_hash = TaggedHash::from_tlv_stream(SIGNATURE_TAG, tlv_stream);

		Self { bytes, experimental_bytes, contents, tagged_hash }
	}

	/// Returns the [`TaggedHash`] of the invoice to sign.
	pub fn tagged_hash(&self) -> &TaggedHash {
		&self.tagged_hash
	}
}

macro_rules! unsigned_invoice_request_sign_method { (
	$self: ident, $self_type: ty $(, $self_mut: tt)?
) => {
	/// Signs the [`TaggedHash`] of the invoice request using the given function.
	///
	/// Note: The hash computation may have included unknown, odd TLV records.
	pub fn sign<F: SignInvoiceRequestFn>(
		$($self_mut)* $self: $self_type, sign: F
	) -> Result<InvoiceRequest, SignError> {
		let pubkey = $self.contents.payer_signing_pubkey;
		let signature = merkle::sign_message(sign, &$self, pubkey)?;

		// Append the signature TLV record to the bytes.
		let signature_tlv_stream = SignatureTlvStreamRef {
			signature: Some(&signature),
		};
		signature_tlv_stream.write(&mut $self.bytes).unwrap();

		// Append the experimental bytes after the signature.
		debug_assert_eq!(
			// The two-byte overallocation results from SIGNATURE_TLV_RECORD_SIZE accommodating TLV
			// records with types >= 253.
			$self.bytes.len() + $self.experimental_bytes.len() + 2,
			$self.bytes.capacity(),
		);
		$self.bytes.extend_from_slice(&$self.experimental_bytes);

		Ok(InvoiceRequest {
			#[cfg(not(c_bindings))]
			bytes: $self.bytes,
			#[cfg(c_bindings)]
			bytes: $self.bytes.clone(),
			#[cfg(not(c_bindings))]
			contents: $self.contents,
			#[cfg(c_bindings)]
			contents: $self.contents.clone(),
			signature,
		})
	}
} }

#[cfg(not(c_bindings))]
impl UnsignedInvoiceRequest {
	unsigned_invoice_request_sign_method!(self, Self, mut);
}

#[cfg(c_bindings)]
impl UnsignedInvoiceRequest {
	unsigned_invoice_request_sign_method!(self, &mut Self);
}

impl AsRef<TaggedHash> for UnsignedInvoiceRequest {
	fn as_ref(&self) -> &TaggedHash {
		&self.tagged_hash
	}
}

/// An `InvoiceRequest` is a request for a [`Bolt12Invoice`] formulated from an [`Offer`].
///
/// An offer may provide choices such as quantity, amount, chain, features, etc. An invoice request
/// specifies these such that its recipient can send an invoice for payment.
///
/// [`Bolt12Invoice`]: crate::offers::invoice::Bolt12Invoice
/// [`Offer`]: crate::offers::offer::Offer
#[derive(Clone, Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct InvoiceRequest {
	pub(super) bytes: Vec<u8>,
	pub(super) contents: InvoiceRequestContents,
	signature: Signature,
}

/// An [`InvoiceRequest`] that has been verified by [`InvoiceRequest::verify_using_metadata`] or
/// [`InvoiceRequest::verify_using_recipient_data`] and exposes different ways to respond depending
/// on whether the signing keys were derived.
#[derive(Clone, Debug)]
pub struct VerifiedInvoiceRequest {
	/// The identifier of the [`Offer`] for which the [`InvoiceRequest`] was made.
	pub offer_id: OfferId,

	/// The verified request.
	pub(crate) inner: InvoiceRequest,

	/// Keys used for signing a [`Bolt12Invoice`] if they can be derived.
	///
	#[cfg_attr(feature = "std", doc = "If `Some`, must call [`respond_using_derived_keys`] when responding. Otherwise, call [`respond_with`].")]
	#[cfg_attr(feature = "std", doc = "")]
	/// [`Bolt12Invoice`]: crate::offers::invoice::Bolt12Invoice
	#[cfg_attr(feature = "std", doc = "[`respond_using_derived_keys`]: Self::respond_using_derived_keys")]
	#[cfg_attr(feature = "std", doc = "[`respond_with`]: Self::respond_with")]
	pub keys: Option<Keypair>,
}

/// The contents of an [`InvoiceRequest`], which may be shared with an [`Bolt12Invoice`].
///
/// [`Bolt12Invoice`]: crate::offers::invoice::Bolt12Invoice
#[derive(Clone, Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub(super) struct InvoiceRequestContents {
	pub(super) inner: InvoiceRequestContentsWithoutPayerSigningPubkey,
	payer_signing_pubkey: PublicKey,
}

#[derive(Clone, Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub(super) struct InvoiceRequestContentsWithoutPayerSigningPubkey {
	pub(super) payer: PayerContents,
	pub(super) offer: OfferContents,
	chain: Option<ChainHash>,
	amount_msats: Option<u64>,
	features: InvoiceRequestFeatures,
	quantity: Option<u64>,
	payer_note: Option<String>,
	offer_from_hrn: Option<HumanReadableName>,
	#[cfg(test)]
	experimental_bar: Option<u64>,
}

macro_rules! invoice_request_accessors { ($self: ident, $contents: expr) => {
	/// An unpredictable series of bytes, typically containing information about the derivation of
	/// [`payer_signing_pubkey`].
	///
	/// [`payer_signing_pubkey`]: Self::payer_signing_pubkey
	pub fn payer_metadata(&$self) -> &[u8] {
		$contents.metadata()
	}

	/// A chain from [`Offer::chains`] that the offer is valid for.
	pub fn chain(&$self) -> ChainHash {
		$contents.chain()
	}

	/// The amount to pay in msats (i.e., the minimum lightning-payable unit for [`chain`]), which
	/// must be greater than or equal to [`Offer::amount`], converted if necessary.
	///
	/// [`chain`]: Self::chain
	pub fn amount_msats(&$self) -> Option<u64> {
		$contents.amount_msats()
	}

	/// Features pertaining to requesting an invoice.
	pub fn invoice_request_features(&$self) -> &InvoiceRequestFeatures {
		&$contents.features()
	}

	/// The quantity of the offer's item conforming to [`Offer::is_valid_quantity`].
	pub fn quantity(&$self) -> Option<u64> {
		$contents.quantity()
	}

	/// A possibly transient pubkey used to sign the invoice request.
	pub fn payer_signing_pubkey(&$self) -> PublicKey {
		$contents.payer_signing_pubkey()
	}

	/// A payer-provided note which will be seen by the recipient and reflected back in the invoice
	/// response.
	pub fn payer_note(&$self) -> Option<PrintableString> {
		$contents.payer_note()
	}

	/// If the [`Offer`] was sourced from a BIP 353 Human Readable Name, this should be set by the
	/// builder to indicate the original [`HumanReadableName`] which was resolved.
	pub fn offer_from_hrn(&$self) -> &Option<HumanReadableName> {
		$contents.offer_from_hrn()
	}
} }

impl UnsignedInvoiceRequest {
	offer_accessors!(self, self.contents.inner.offer);
	invoice_request_accessors!(self, self.contents);
}

macro_rules! invoice_request_respond_with_explicit_signing_pubkey_methods { (
	$self: ident, $contents: expr, $builder: ty
) => {
	/// Creates an [`InvoiceBuilder`] for the request with the given required fields and using the
	/// [`Duration`] since [`std::time::SystemTime::UNIX_EPOCH`] as the creation time.
	///
	/// See [`InvoiceRequest::respond_with_no_std`] for further details where the aforementioned
	/// creation time is used for the `created_at` parameter.
	///
	/// [`Duration`]: core::time::Duration
	#[cfg(feature = "std")]
	pub fn respond_with(
		&$self, payment_paths: Vec<BlindedPaymentPath>, payment_hash: PaymentHash
	) -> Result<$builder, Bolt12SemanticError> {
		let created_at = std::time::SystemTime::now()
			.duration_since(std::time::SystemTime::UNIX_EPOCH)
			.expect("SystemTime::now() should come after SystemTime::UNIX_EPOCH");

		$contents.respond_with_no_std(payment_paths, payment_hash, created_at)
	}

	/// Creates an [`InvoiceBuilder`] for the request with the given required fields.
	///
	/// Unless [`InvoiceBuilder::relative_expiry`] is set, the invoice will expire two hours after
	/// `created_at`, which is used to set [`Bolt12Invoice::created_at`].
	#[cfg_attr(feature = "std", doc = "Useful for non-`std` builds where [`std::time::SystemTime`] is not available.")]
	///
	/// The caller is expected to remember the preimage of `payment_hash` in order to claim a payment
	/// for the invoice.
	///
	/// The `payment_paths` parameter is useful for maintaining the payment recipient's privacy. It
	/// must contain one or more elements ordered from most-preferred to least-preferred, if there's
	/// a preference. Note, however, that any privacy is lost if a public node id was used for
	/// [`Offer::issuer_signing_pubkey`].
	///
	/// Errors if the request contains unknown required features.
	///
	/// # Note
	///
	/// If the originating [`Offer`] was created using [`OfferBuilder::deriving_signing_pubkey`],
	/// then first use [`InvoiceRequest::verify_using_metadata`] or
	/// [`InvoiceRequest::verify_using_recipient_data`] and then [`VerifiedInvoiceRequest`] methods
	/// instead.
	///
	/// [`Bolt12Invoice::created_at`]: crate::offers::invoice::Bolt12Invoice::created_at
	/// [`OfferBuilder::deriving_signing_pubkey`]: crate::offers::offer::OfferBuilder::deriving_signing_pubkey
	pub fn respond_with_no_std(
		&$self, payment_paths: Vec<BlindedPaymentPath>, payment_hash: PaymentHash,
		created_at: core::time::Duration
	) -> Result<$builder, Bolt12SemanticError> {
		if $contents.invoice_request_features().requires_unknown_bits() {
			return Err(Bolt12SemanticError::UnknownRequiredFeatures);
		}

		let signing_pubkey = match $contents.contents.inner.offer.issuer_signing_pubkey() {
			Some(signing_pubkey) => signing_pubkey,
			None => return Err(Bolt12SemanticError::MissingIssuerSigningPubkey),
		};

		<$builder>::for_offer(&$contents, payment_paths, created_at, payment_hash, signing_pubkey)
	}

	#[cfg(test)]
	#[allow(dead_code)]
	pub(super) fn respond_with_no_std_using_signing_pubkey(
		&$self, payment_paths: Vec<BlindedPaymentPath>, payment_hash: PaymentHash,
		created_at: core::time::Duration, signing_pubkey: PublicKey
	) -> Result<$builder, Bolt12SemanticError> {
		debug_assert!($contents.contents.inner.offer.issuer_signing_pubkey().is_none());

		if $contents.invoice_request_features().requires_unknown_bits() {
			return Err(Bolt12SemanticError::UnknownRequiredFeatures);
		}

		<$builder>::for_offer(&$contents, payment_paths, created_at, payment_hash, signing_pubkey)
	}
} }

macro_rules! invoice_request_verify_method { ($self: ident, $self_type: ty) => {
	/// Verifies that the request was for an offer created using the given key by checking the
	/// metadata from the offer.
	///
	/// Returns the verified request which contains the derived keys needed to sign a
	/// [`Bolt12Invoice`] for the request if they could be extracted from the metadata.
	///
	/// [`Bolt12Invoice`]: crate::offers::invoice::Bolt12Invoice
	pub fn verify_using_metadata<
		#[cfg(not(c_bindings))]
		T: secp256k1::Signing
	>(
		$self: $self_type, key: &ExpandedKey,
		#[cfg(not(c_bindings))]
		secp_ctx: &Secp256k1<T>,
		#[cfg(c_bindings)]
		secp_ctx: &Secp256k1<secp256k1::All>,
	) -> Result<VerifiedInvoiceRequest, ()> {
		let (offer_id, keys) =
			$self.contents.inner.offer.verify_using_metadata(&$self.bytes, key, secp_ctx)?;
		Ok(VerifiedInvoiceRequest {
			offer_id,
			#[cfg(not(c_bindings))]
			inner: $self,
			#[cfg(c_bindings)]
			inner: $self.clone(),
			keys,
		})
	}

	/// Verifies that the request was for an offer created using the given key by checking a nonce
	/// included with the [`BlindedMessagePath`] for which the request was sent through.
	///
	/// Returns the verified request which contains the derived keys needed to sign a
	/// [`Bolt12Invoice`] for the request if they could be extracted from the metadata.
	///
	/// [`Bolt12Invoice`]: crate::offers::invoice::Bolt12Invoice
	pub fn verify_using_recipient_data<
		#[cfg(not(c_bindings))]
		T: secp256k1::Signing
	>(
		$self: $self_type, nonce: Nonce, key: &ExpandedKey,
		#[cfg(not(c_bindings))]
		secp_ctx: &Secp256k1<T>,
		#[cfg(c_bindings)]
		secp_ctx: &Secp256k1<secp256k1::All>,
	) -> Result<VerifiedInvoiceRequest, ()> {
		let (offer_id, keys) = $self.contents.inner.offer.verify_using_recipient_data(
			&$self.bytes, nonce, key, secp_ctx
		)?;
		Ok(VerifiedInvoiceRequest {
			offer_id,
			#[cfg(not(c_bindings))]
			inner: $self,
			#[cfg(c_bindings)]
			inner: $self.clone(),
			keys,
		})
	}
} }

#[cfg(not(c_bindings))]
impl InvoiceRequest {
	offer_accessors!(self, self.contents.inner.offer);
	invoice_request_accessors!(self, self.contents);
	invoice_request_respond_with_explicit_signing_pubkey_methods!(self, self, InvoiceBuilder<ExplicitSigningPubkey>);
	invoice_request_verify_method!(self, Self);

	#[cfg(async_payments)]
	pub(super) fn bytes(&self) -> &Vec<u8> {
		&self.bytes
	}
}

#[cfg(c_bindings)]
impl InvoiceRequest {
	offer_accessors!(self, self.contents.inner.offer);
	invoice_request_accessors!(self, self.contents);
	invoice_request_respond_with_explicit_signing_pubkey_methods!(self, self, InvoiceWithExplicitSigningPubkeyBuilder);
	invoice_request_verify_method!(self, &Self);
}

impl InvoiceRequest {
	/// Signature of the invoice request using [`payer_signing_pubkey`].
	///
	/// [`payer_signing_pubkey`]: Self::payer_signing_pubkey
	pub fn signature(&self) -> Signature {
		self.signature
	}

	pub(crate) fn as_tlv_stream(&self) -> FullInvoiceRequestTlvStreamRef {
		let (
			payer_tlv_stream, offer_tlv_stream, invoice_request_tlv_stream,
			experimental_offer_tlv_stream, experimental_invoice_request_tlv_stream,
		) = self.contents.as_tlv_stream();
		let signature_tlv_stream = SignatureTlvStreamRef {
			signature: Some(&self.signature),
		};
		(
			payer_tlv_stream, offer_tlv_stream, invoice_request_tlv_stream,
			signature_tlv_stream, experimental_offer_tlv_stream,
			experimental_invoice_request_tlv_stream,
		)
	}
}

macro_rules! invoice_request_respond_with_derived_signing_pubkey_methods { (
	$self: ident, $contents: expr, $builder: ty
) => {
	/// Creates an [`InvoiceBuilder`] for the request using the given required fields and that uses
	/// derived signing keys from the originating [`Offer`] to sign the [`Bolt12Invoice`]. Must use
	/// the same [`ExpandedKey`] as the one used to create the offer.
	///
	/// See [`InvoiceRequest::respond_with`] for further details.
	///
	/// [`Bolt12Invoice`]: crate::offers::invoice::Bolt12Invoice
	#[cfg(feature = "std")]
	pub fn respond_using_derived_keys(
		&$self, payment_paths: Vec<BlindedPaymentPath>, payment_hash: PaymentHash
	) -> Result<$builder, Bolt12SemanticError> {
		let created_at = std::time::SystemTime::now()
			.duration_since(std::time::SystemTime::UNIX_EPOCH)
			.expect("SystemTime::now() should come after SystemTime::UNIX_EPOCH");

		$self.respond_using_derived_keys_no_std(payment_paths, payment_hash, created_at)
	}

	/// Creates an [`InvoiceBuilder`] for the request using the given required fields and that uses
	/// derived signing keys from the originating [`Offer`] to sign the [`Bolt12Invoice`]. Must use
	/// the same [`ExpandedKey`] as the one used to create the offer.
	///
	/// See [`InvoiceRequest::respond_with_no_std`] for further details.
	///
	/// [`Bolt12Invoice`]: crate::offers::invoice::Bolt12Invoice
	pub fn respond_using_derived_keys_no_std(
		&$self, payment_paths: Vec<BlindedPaymentPath>, payment_hash: PaymentHash,
		created_at: core::time::Duration
	) -> Result<$builder, Bolt12SemanticError> {
		if $self.inner.invoice_request_features().requires_unknown_bits() {
			return Err(Bolt12SemanticError::UnknownRequiredFeatures);
		}

		let keys = match $self.keys {
			None => return Err(Bolt12SemanticError::InvalidMetadata),
			Some(keys) => keys,
		};

		match $contents.contents.inner.offer.issuer_signing_pubkey() {
			Some(signing_pubkey) => debug_assert_eq!(signing_pubkey, keys.public_key()),
			None => return Err(Bolt12SemanticError::MissingIssuerSigningPubkey),
		}

		<$builder>::for_offer_using_keys(
			&$self.inner, payment_paths, created_at, payment_hash, keys
		)
	}
} }

impl VerifiedInvoiceRequest {
	offer_accessors!(self, self.inner.contents.inner.offer);
	invoice_request_accessors!(self, self.inner.contents);
	#[cfg(not(c_bindings))]
	invoice_request_respond_with_explicit_signing_pubkey_methods!(self, self.inner, InvoiceBuilder<ExplicitSigningPubkey>);
	#[cfg(c_bindings)]
	invoice_request_respond_with_explicit_signing_pubkey_methods!(self, self.inner, InvoiceWithExplicitSigningPubkeyBuilder);
	#[cfg(not(c_bindings))]
	invoice_request_respond_with_derived_signing_pubkey_methods!(self, self.inner, InvoiceBuilder<DerivedSigningPubkey>);
	#[cfg(c_bindings)]
	invoice_request_respond_with_derived_signing_pubkey_methods!(self, self.inner, InvoiceWithDerivedSigningPubkeyBuilder);

	pub(crate) fn fields(&self) -> InvoiceRequestFields {
		let InvoiceRequestContents {
			payer_signing_pubkey,
			inner: InvoiceRequestContentsWithoutPayerSigningPubkey {
				quantity, payer_note, ..
			},
		} = &self.inner.contents;

		InvoiceRequestFields {
			payer_signing_pubkey: *payer_signing_pubkey,
			quantity: *quantity,
			payer_note_truncated: payer_note.clone()
				.map(|mut s| { s.truncate(PAYER_NOTE_LIMIT); UntrustedString(s) }),
			human_readable_name: self.offer_from_hrn().clone(),
		}
	}
}

impl InvoiceRequestContents {
	pub(super) fn metadata(&self) -> &[u8] {
		self.inner.metadata()
	}

	pub(super) fn chain(&self) -> ChainHash {
		self.inner.chain()
	}

	pub(super) fn amount_msats(&self) -> Option<u64> {
		self.inner.amount_msats
	}

	pub(super) fn features(&self) -> &InvoiceRequestFeatures {
		&self.inner.features
	}

	pub(super) fn quantity(&self) -> Option<u64> {
		self.inner.quantity
	}

	pub(super) fn payer_signing_pubkey(&self) -> PublicKey {
		self.payer_signing_pubkey
	}

	pub(super) fn payer_note(&self) -> Option<PrintableString> {
		self.inner.payer_note.as_ref()
			.map(|payer_note| PrintableString(payer_note.as_str()))
	}

	pub(super) fn offer_from_hrn(&self) -> &Option<HumanReadableName> {
		&self.inner.offer_from_hrn
	}

	pub(super) fn as_tlv_stream(&self) -> PartialInvoiceRequestTlvStreamRef {
		let (payer, offer, mut invoice_request, experimental_offer, experimental_invoice_request) =
			self.inner.as_tlv_stream();
		invoice_request.payer_id = Some(&self.payer_signing_pubkey);
		(payer, offer, invoice_request, experimental_offer, experimental_invoice_request)
	}
}

impl InvoiceRequestContentsWithoutPayerSigningPubkey {
	pub(super) fn metadata(&self) -> &[u8] {
		self.payer.0.as_bytes().map(|bytes| bytes.as_slice()).unwrap_or(&[])
	}

	pub(super) fn chain(&self) -> ChainHash {
		self.chain.unwrap_or_else(|| self.offer.implied_chain())
	}

	pub(super) fn as_tlv_stream(&self) -> PartialInvoiceRequestTlvStreamRef {
		let payer = PayerTlvStreamRef {
			metadata: self.payer.0.as_bytes(),
		};

		let (offer, experimental_offer) = self.offer.as_tlv_stream();

		let features = {
			if self.features == InvoiceRequestFeatures::empty() { None }
			else { Some(&self.features) }
		};

		let invoice_request = InvoiceRequestTlvStreamRef {
			chain: self.chain.as_ref(),
			amount: self.amount_msats,
			features,
			quantity: self.quantity,
			payer_id: None,
			payer_note: self.payer_note.as_ref(),
			offer_from_hrn: self.offer_from_hrn.as_ref(),
			paths: None,
		};

		let experimental_invoice_request = ExperimentalInvoiceRequestTlvStreamRef {
			#[cfg(test)]
			experimental_bar: self.experimental_bar,
		};

		(payer, offer, invoice_request, experimental_offer, experimental_invoice_request)
	}
}

impl Writeable for UnsignedInvoiceRequest {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		WithoutLength(&self.bytes).write(writer)
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

impl Readable for InvoiceRequest {
	fn read<R: io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
		let bytes: WithoutLength<Vec<u8>> = Readable::read(reader)?;
		Self::try_from(bytes.0).map_err(|_| DecodeError::InvalidValue)
	}
}

/// Valid type range for invoice_request TLV records.
pub(super) const INVOICE_REQUEST_TYPES: core::ops::Range<u64> = 80..160;

/// TLV record type for [`InvoiceRequest::payer_signing_pubkey`] and
/// [`Refund::payer_signing_pubkey`].
///
/// [`Refund::payer_signing_pubkey`]: crate::offers::refund::Refund::payer_signing_pubkey
pub(super) const INVOICE_REQUEST_PAYER_ID_TYPE: u64 = 88;

// This TLV stream is used for both InvoiceRequest and Refund, but not all TLV records are valid for
// InvoiceRequest as noted below.
tlv_stream!(InvoiceRequestTlvStream, InvoiceRequestTlvStreamRef<'a>, INVOICE_REQUEST_TYPES, {
	(80, chain: ChainHash),
	(82, amount: (u64, HighZeroBytesDroppedBigSize)),
	(84, features: (InvoiceRequestFeatures, WithoutLength)),
	(86, quantity: (u64, HighZeroBytesDroppedBigSize)),
	(INVOICE_REQUEST_PAYER_ID_TYPE, payer_id: PublicKey),
	(89, payer_note: (String, WithoutLength)),
	// Only used for Refund since the onion message of an InvoiceRequest has a reply path.
	(90, paths: (Vec<BlindedMessagePath>, WithoutLength)),
	(91, offer_from_hrn: HumanReadableName),
});

/// Valid type range for experimental invoice_request TLV records.
pub(super) const EXPERIMENTAL_INVOICE_REQUEST_TYPES: core::ops::Range<u64> =
	2_000_000_000..3_000_000_000;

#[cfg(not(test))]
tlv_stream!(
	ExperimentalInvoiceRequestTlvStream, ExperimentalInvoiceRequestTlvStreamRef,
	EXPERIMENTAL_INVOICE_REQUEST_TYPES, {}
);

#[cfg(test)]
tlv_stream!(
	ExperimentalInvoiceRequestTlvStream, ExperimentalInvoiceRequestTlvStreamRef,
	EXPERIMENTAL_INVOICE_REQUEST_TYPES, {
		(2_999_999_999, experimental_bar: (u64, HighZeroBytesDroppedBigSize)),
	}
);

type FullInvoiceRequestTlvStream = (
	PayerTlvStream, OfferTlvStream, InvoiceRequestTlvStream, SignatureTlvStream,
	ExperimentalOfferTlvStream, ExperimentalInvoiceRequestTlvStream,
);

type FullInvoiceRequestTlvStreamRef<'a> = (
	PayerTlvStreamRef<'a>,
	OfferTlvStreamRef<'a>,
	InvoiceRequestTlvStreamRef<'a>,
	SignatureTlvStreamRef<'a>,
	ExperimentalOfferTlvStreamRef,
	ExperimentalInvoiceRequestTlvStreamRef,
);

impl CursorReadable for FullInvoiceRequestTlvStream {
	fn read<R: AsRef<[u8]>>(r: &mut io::Cursor<R>) -> Result<Self, DecodeError> {
		let payer = CursorReadable::read(r)?;
		let offer = CursorReadable::read(r)?;
		let invoice_request = CursorReadable::read(r)?;
		let signature = CursorReadable::read(r)?;
		let experimental_offer = CursorReadable::read(r)?;
		let experimental_invoice_request = CursorReadable::read(r)?;

		Ok(
			(
				payer, offer, invoice_request, signature, experimental_offer,
				experimental_invoice_request,
			)
		)
	}
}

type PartialInvoiceRequestTlvStream = (
	PayerTlvStream, OfferTlvStream, InvoiceRequestTlvStream, ExperimentalOfferTlvStream,
	ExperimentalInvoiceRequestTlvStream,
);

type PartialInvoiceRequestTlvStreamRef<'a> = (
	PayerTlvStreamRef<'a>,
	OfferTlvStreamRef<'a>,
	InvoiceRequestTlvStreamRef<'a>,
	ExperimentalOfferTlvStreamRef,
	ExperimentalInvoiceRequestTlvStreamRef,
);

impl TryFrom<Vec<u8>> for UnsignedInvoiceRequest {
	type Error = Bolt12ParseError;

	fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
		let invoice_request = ParsedMessage::<PartialInvoiceRequestTlvStream>::try_from(bytes)?;
		let ParsedMessage { mut bytes, tlv_stream } = invoice_request;

		let contents = InvoiceRequestContents::try_from(tlv_stream)?;
		let tagged_hash = TaggedHash::from_valid_tlv_stream_bytes(SIGNATURE_TAG, &bytes);

		let offset = TlvStream::new(&bytes)
			.range(0..INVOICE_REQUEST_TYPES.end)
			.last()
			.map_or(0, |last_record| last_record.end);
		let experimental_bytes = bytes.split_off(offset);

		Ok(UnsignedInvoiceRequest { bytes, experimental_bytes, contents, tagged_hash })
	}
}

impl TryFrom<Vec<u8>> for InvoiceRequest {
	type Error = Bolt12ParseError;

	fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
		let invoice_request = ParsedMessage::<FullInvoiceRequestTlvStream>::try_from(bytes)?;
		let ParsedMessage { bytes, tlv_stream } = invoice_request;
		let (
			payer_tlv_stream, offer_tlv_stream, invoice_request_tlv_stream,
			SignatureTlvStream { signature },
			experimental_offer_tlv_stream,
			experimental_invoice_request_tlv_stream,
		) = tlv_stream;
		let contents = InvoiceRequestContents::try_from(
			(
				payer_tlv_stream, offer_tlv_stream, invoice_request_tlv_stream,
				experimental_offer_tlv_stream, experimental_invoice_request_tlv_stream,
			)
		)?;

		let signature = match signature {
			None => return Err(Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::MissingSignature)),
			Some(signature) => signature,
		};
		let message = TaggedHash::from_valid_tlv_stream_bytes(SIGNATURE_TAG, &bytes);
		merkle::verify_signature(&signature, &message, contents.payer_signing_pubkey)?;

		Ok(InvoiceRequest { bytes, contents, signature })
	}
}

impl TryFrom<PartialInvoiceRequestTlvStream> for InvoiceRequestContents {
	type Error = Bolt12SemanticError;

	fn try_from(tlv_stream: PartialInvoiceRequestTlvStream) -> Result<Self, Self::Error> {
		let (
			PayerTlvStream { metadata },
			offer_tlv_stream,
			InvoiceRequestTlvStream {
				chain, amount, features, quantity, payer_id, payer_note, paths,
				offer_from_hrn,
			},
			experimental_offer_tlv_stream,
			ExperimentalInvoiceRequestTlvStream {
				#[cfg(test)]
				experimental_bar,
			},
		) = tlv_stream;

		let payer = match metadata {
			None => return Err(Bolt12SemanticError::MissingPayerMetadata),
			Some(metadata) => PayerContents(Metadata::Bytes(metadata)),
		};
		let offer = OfferContents::try_from((offer_tlv_stream, experimental_offer_tlv_stream))?;

		if !offer.supports_chain(chain.unwrap_or_else(|| offer.implied_chain())) {
			return Err(Bolt12SemanticError::UnsupportedChain);
		}

		if offer.amount().is_none() && amount.is_none() {
			return Err(Bolt12SemanticError::MissingAmount);
		}

		offer.check_quantity(quantity)?;
		offer.check_amount_msats_for_quantity(amount, quantity)?;

		let features = features.unwrap_or_else(InvoiceRequestFeatures::empty);

		let payer_signing_pubkey = match payer_id {
			None => return Err(Bolt12SemanticError::MissingPayerSigningPubkey),
			Some(payer_id) => payer_id,
		};

		if paths.is_some() {
			return Err(Bolt12SemanticError::UnexpectedPaths);
		}

		Ok(InvoiceRequestContents {
			inner: InvoiceRequestContentsWithoutPayerSigningPubkey {
				payer, offer, chain, amount_msats: amount, features, quantity, payer_note,
				offer_from_hrn,
				#[cfg(test)]
				experimental_bar,
			},
			payer_signing_pubkey,
		})
	}
}

/// Fields sent in an [`InvoiceRequest`] message to include in [`PaymentContext::Bolt12Offer`].
///
/// [`PaymentContext::Bolt12Offer`]: crate::blinded_path::payment::PaymentContext::Bolt12Offer
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvoiceRequestFields {
	/// A possibly transient pubkey used to sign the invoice request.
	pub payer_signing_pubkey: PublicKey,

	/// The quantity of the offer's item conforming to [`Offer::is_valid_quantity`].
	pub quantity: Option<u64>,

	/// A payer-provided note which will be seen by the recipient and reflected back in the invoice
	/// response. Truncated to [`PAYER_NOTE_LIMIT`] characters.
	pub payer_note_truncated: Option<UntrustedString>,

	/// The Human Readable Name which the sender indicated they were paying to.
	pub human_readable_name: Option<HumanReadableName>,
}

/// The maximum number of characters included in [`InvoiceRequestFields::payer_note_truncated`].
pub const PAYER_NOTE_LIMIT: usize = 512;

impl Writeable for InvoiceRequestFields {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		write_tlv_fields!(writer, {
			(0, self.payer_signing_pubkey, required),
			(1, self.human_readable_name, option),
			(2, self.quantity.map(|v| HighZeroBytesDroppedBigSize(v)), option),
			(4, self.payer_note_truncated.as_ref().map(|s| WithoutLength(&s.0)), option),
		});
		Ok(())
	}
}

impl Readable for InvoiceRequestFields {
	fn read<R: io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
		_init_and_read_len_prefixed_tlv_fields!(reader, {
			(0, payer_signing_pubkey, required),
			(1, human_readable_name, option),
			(2, quantity, (option, encoding: (u64, HighZeroBytesDroppedBigSize))),
			(4, payer_note_truncated, (option, encoding: (String, WithoutLength))),
		});

		Ok(InvoiceRequestFields {
			payer_signing_pubkey: payer_signing_pubkey.0.unwrap(),
			quantity,
			payer_note_truncated: payer_note_truncated.map(|s| UntrustedString(s)),
			human_readable_name,
		})
	}
}

#[cfg(test)]
mod tests {
	use super::{EXPERIMENTAL_INVOICE_REQUEST_TYPES, ExperimentalInvoiceRequestTlvStreamRef, INVOICE_REQUEST_TYPES, InvoiceRequest, InvoiceRequestFields, InvoiceRequestTlvStreamRef, PAYER_NOTE_LIMIT, SIGNATURE_TAG, UnsignedInvoiceRequest};

	use bitcoin::constants::ChainHash;
	use bitcoin::network::Network;
	use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey, self};
	use core::num::NonZeroU64;
	#[cfg(feature = "std")]
	use core::time::Duration;
	use crate::ln::channelmanager::PaymentId;
	use crate::types::features::{InvoiceRequestFeatures, OfferFeatures};
	use crate::ln::inbound_payment::ExpandedKey;
	use crate::ln::msgs::{DecodeError, MAX_VALUE_MSAT};
	use crate::offers::invoice::{Bolt12Invoice, SIGNATURE_TAG as INVOICE_SIGNATURE_TAG};
	use crate::offers::merkle::{SignatureTlvStreamRef, TaggedHash, TlvStream, self};
	use crate::offers::nonce::Nonce;
	use crate::offers::offer::{Amount, Currency, ExperimentalOfferTlvStreamRef, OfferTlvStreamRef, Quantity};
	#[cfg(not(c_bindings))]
	use {
		crate::offers::offer::OfferBuilder,
	};
	#[cfg(c_bindings)]
	use {
		crate::offers::offer::OfferWithExplicitMetadataBuilder as OfferBuilder,
	};
	use crate::offers::parse::{Bolt12ParseError, Bolt12SemanticError};
	use crate::offers::payer::PayerTlvStreamRef;
	use crate::offers::test_utils::*;
	use crate::util::ser::{BigSize, Readable, Writeable};
	use crate::util::string::{PrintableString, UntrustedString};

	#[test]
	fn builds_invoice_request_with_defaults() {
		let expanded_key = ExpandedKey::new([42; 32]);
		let entropy = FixedEntropy {};
		let nonce = Nonce::from_entropy_source(&entropy);
		let secp_ctx = Secp256k1::new();
		let payment_id = PaymentId([1; 32]);
		let encrypted_payment_id = expanded_key.crypt_for_offer(payment_id.0, nonce);

		let invoice_request = OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.build().unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id).unwrap()
			.build_and_sign().unwrap();

		let mut buffer = Vec::new();
		invoice_request.write(&mut buffer).unwrap();

		assert_eq!(invoice_request.bytes, buffer.as_slice());
		assert_eq!(invoice_request.payer_metadata(), &encrypted_payment_id);
		assert_eq!(invoice_request.chains(), vec![ChainHash::using_genesis_block(Network::Bitcoin)]);
		assert_eq!(invoice_request.metadata(), None);
		assert_eq!(invoice_request.amount(), Some(Amount::Bitcoin { amount_msats: 1000 }));
		assert_eq!(invoice_request.description(), Some(PrintableString("")));
		assert_eq!(invoice_request.offer_features(), &OfferFeatures::empty());
		assert_eq!(invoice_request.absolute_expiry(), None);
		assert_eq!(invoice_request.paths(), &[]);
		assert_eq!(invoice_request.issuer(), None);
		assert_eq!(invoice_request.supported_quantity(), Quantity::One);
		assert_eq!(invoice_request.issuer_signing_pubkey(), Some(recipient_pubkey()));
		assert_eq!(invoice_request.chain(), ChainHash::using_genesis_block(Network::Bitcoin));
		assert_eq!(invoice_request.amount_msats(), None);
		assert_eq!(invoice_request.invoice_request_features(), &InvoiceRequestFeatures::empty());
		assert_eq!(invoice_request.quantity(), None);
		assert_eq!(invoice_request.payer_note(), None);

		let message = TaggedHash::from_valid_tlv_stream_bytes(SIGNATURE_TAG, &invoice_request.bytes);
		assert!(
			merkle::verify_signature(
				&invoice_request.signature, &message, invoice_request.payer_signing_pubkey(),
			).is_ok()
		);

		assert_eq!(
			invoice_request.as_tlv_stream(),
			(
				PayerTlvStreamRef { metadata: Some(&encrypted_payment_id.to_vec()) },
				OfferTlvStreamRef {
					chains: None,
					metadata: None,
					currency: None,
					amount: Some(1000),
					description: Some(&String::from("")),
					features: None,
					absolute_expiry: None,
					paths: None,
					issuer: None,
					quantity_max: None,
					issuer_id: Some(&recipient_pubkey()),
				},
				InvoiceRequestTlvStreamRef {
					chain: None,
					amount: None,
					features: None,
					quantity: None,
					payer_id: Some(&invoice_request.payer_signing_pubkey()),
					payer_note: None,
					paths: None,
					offer_from_hrn: None,
				},
				SignatureTlvStreamRef { signature: Some(&invoice_request.signature()) },
				ExperimentalOfferTlvStreamRef {
					experimental_foo: None,
				},
				ExperimentalInvoiceRequestTlvStreamRef {
					experimental_bar: None,
				},
			),
		);

		if let Err(e) = InvoiceRequest::try_from(buffer) {
			panic!("error parsing invoice request: {:?}", e);
		}
	}

	#[cfg(feature = "std")]
	#[test]
	fn builds_invoice_request_from_offer_with_expiration() {
		let expanded_key = ExpandedKey::new([42; 32]);
		let entropy = FixedEntropy {};
		let nonce = Nonce::from_entropy_source(&entropy);
		let secp_ctx = Secp256k1::new();
		let payment_id = PaymentId([1; 32]);

		let future_expiry = Duration::from_secs(u64::max_value());
		let past_expiry = Duration::from_secs(0);

		if let Err(e) = OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.absolute_expiry(future_expiry)
			.build().unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id).unwrap()
			.build_and_sign()
		{
			panic!("error building invoice_request: {:?}", e);
		}

		match OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.absolute_expiry(past_expiry)
			.build().unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id).unwrap()
			.build_and_sign()
		{
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, Bolt12SemanticError::AlreadyExpired),
		}
	}

	#[test]
	fn builds_invoice_request_with_derived_payer_signing_pubkey() {
		let expanded_key = ExpandedKey::new([42; 32]);
		let entropy = FixedEntropy {};
		let nonce = Nonce::from_entropy_source(&entropy);
		let secp_ctx = Secp256k1::new();
		let payment_id = PaymentId([1; 32]);

		let offer = OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.experimental_foo(42)
			.build().unwrap();
		let invoice_request = offer
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id).unwrap()
			.experimental_bar(42)
			.build_and_sign()
			.unwrap();

		let invoice = invoice_request.respond_with_no_std(payment_paths(), payment_hash(), now())
			.unwrap()
			.experimental_baz(42)
			.build().unwrap()
			.sign(recipient_sign).unwrap();
		assert!(invoice.verify_using_metadata(&expanded_key, &secp_ctx).is_err());
		assert!(
			invoice.verify_using_payer_data(payment_id, nonce, &expanded_key, &secp_ctx).is_ok()
		);

		// Fails verification with altered fields
		let (
			payer_tlv_stream, offer_tlv_stream, mut invoice_request_tlv_stream,
			mut invoice_tlv_stream, mut signature_tlv_stream, experimental_offer_tlv_stream,
			experimental_invoice_request_tlv_stream, experimental_invoice_tlv_stream,
		) = invoice.as_tlv_stream();
		invoice_request_tlv_stream.amount = Some(2000);
		invoice_tlv_stream.amount = Some(2000);

		let tlv_stream =
			(payer_tlv_stream, offer_tlv_stream, invoice_request_tlv_stream, invoice_tlv_stream);
		let experimental_tlv_stream = (
			experimental_offer_tlv_stream, experimental_invoice_request_tlv_stream,
			experimental_invoice_tlv_stream,
		);
		let mut bytes = Vec::new();
		(&tlv_stream, &experimental_tlv_stream).write(&mut bytes).unwrap();

		let message = TaggedHash::from_valid_tlv_stream_bytes(INVOICE_SIGNATURE_TAG, &bytes);
		let signature = merkle::sign_message(recipient_sign, &message, recipient_pubkey()).unwrap();
		signature_tlv_stream.signature = Some(&signature);

		let mut encoded_invoice = Vec::new();
		(tlv_stream, signature_tlv_stream, experimental_tlv_stream)
			.write(&mut encoded_invoice)
			.unwrap();

		let invoice = Bolt12Invoice::try_from(encoded_invoice).unwrap();
		assert!(
			invoice.verify_using_payer_data(payment_id, nonce, &expanded_key, &secp_ctx).is_err()
		);

		// Fails verification with altered payer id
		let (
			payer_tlv_stream, offer_tlv_stream, mut invoice_request_tlv_stream, invoice_tlv_stream,
			mut signature_tlv_stream, experimental_offer_tlv_stream,
			experimental_invoice_request_tlv_stream, experimental_invoice_tlv_stream,
		) = invoice.as_tlv_stream();
		let payer_id = pubkey(1);
		invoice_request_tlv_stream.payer_id = Some(&payer_id);

		let tlv_stream =
			(payer_tlv_stream, offer_tlv_stream, invoice_request_tlv_stream, invoice_tlv_stream);
		let experimental_tlv_stream = (
			experimental_offer_tlv_stream, experimental_invoice_request_tlv_stream,
			experimental_invoice_tlv_stream,
		);
		let mut bytes = Vec::new();
		(&tlv_stream, &experimental_tlv_stream).write(&mut bytes).unwrap();

		let message = TaggedHash::from_valid_tlv_stream_bytes(INVOICE_SIGNATURE_TAG, &bytes);
		let signature = merkle::sign_message(recipient_sign, &message, recipient_pubkey()).unwrap();
		signature_tlv_stream.signature = Some(&signature);

		let mut encoded_invoice = Vec::new();
		(tlv_stream, signature_tlv_stream, experimental_tlv_stream)
			.write(&mut encoded_invoice)
			.unwrap();

		let invoice = Bolt12Invoice::try_from(encoded_invoice).unwrap();
		assert!(
			invoice.verify_using_payer_data(payment_id, nonce, &expanded_key, &secp_ctx).is_err()
		);
	}

	#[test]
	fn builds_invoice_request_with_chain() {
		let expanded_key = ExpandedKey::new([42; 32]);
		let entropy = FixedEntropy {};
		let nonce = Nonce::from_entropy_source(&entropy);
		let secp_ctx = Secp256k1::new();
		let payment_id = PaymentId([1; 32]);

		let mainnet = ChainHash::using_genesis_block(Network::Bitcoin);
		let testnet = ChainHash::using_genesis_block(Network::Testnet);

		let invoice_request = OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.build().unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id).unwrap()
			.chain(Network::Bitcoin).unwrap()
			.build_and_sign().unwrap();
		let (_, _, tlv_stream, _, _, _) = invoice_request.as_tlv_stream();
		assert_eq!(invoice_request.chain(), mainnet);
		assert_eq!(tlv_stream.chain, None);

		let invoice_request = OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.chain(Network::Testnet)
			.build().unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id).unwrap()
			.chain(Network::Testnet).unwrap()
			.build_and_sign().unwrap();
		let (_, _, tlv_stream, _, _, _) = invoice_request.as_tlv_stream();
		assert_eq!(invoice_request.chain(), testnet);
		assert_eq!(tlv_stream.chain, Some(&testnet));

		let invoice_request = OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.chain(Network::Bitcoin)
			.chain(Network::Testnet)
			.build().unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id).unwrap()
			.chain(Network::Bitcoin).unwrap()
			.build_and_sign().unwrap();
		let (_, _, tlv_stream, _, _, _) = invoice_request.as_tlv_stream();
		assert_eq!(invoice_request.chain(), mainnet);
		assert_eq!(tlv_stream.chain, None);

		let invoice_request = OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.chain(Network::Bitcoin)
			.chain(Network::Testnet)
			.build().unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id).unwrap()
			.chain(Network::Bitcoin).unwrap()
			.chain(Network::Testnet).unwrap()
			.build_and_sign().unwrap();
		let (_, _, tlv_stream, _, _, _) = invoice_request.as_tlv_stream();
		assert_eq!(invoice_request.chain(), testnet);
		assert_eq!(tlv_stream.chain, Some(&testnet));

		match OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.chain(Network::Testnet)
			.build().unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id).unwrap()
			.chain(Network::Bitcoin)
		{
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, Bolt12SemanticError::UnsupportedChain),
		}

		match OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.chain(Network::Testnet)
			.build().unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id).unwrap()
			.build_and_sign()
		{
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, Bolt12SemanticError::UnsupportedChain),
		}
	}

	#[test]
	fn builds_invoice_request_with_amount() {
		let expanded_key = ExpandedKey::new([42; 32]);
		let entropy = FixedEntropy {};
		let nonce = Nonce::from_entropy_source(&entropy);
		let secp_ctx = Secp256k1::new();
		let payment_id = PaymentId([1; 32]);

		let invoice_request = OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.build().unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id).unwrap()
			.amount_msats(1000).unwrap()
			.build_and_sign().unwrap();
		let (_, _, tlv_stream, _, _, _) = invoice_request.as_tlv_stream();
		assert_eq!(invoice_request.amount_msats(), Some(1000));
		assert_eq!(tlv_stream.amount, Some(1000));

		let invoice_request = OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.build().unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id).unwrap()
			.amount_msats(1001).unwrap()
			.amount_msats(1000).unwrap()
			.build_and_sign().unwrap();
		let (_, _, tlv_stream, _, _, _) = invoice_request.as_tlv_stream();
		assert_eq!(invoice_request.amount_msats(), Some(1000));
		assert_eq!(tlv_stream.amount, Some(1000));

		let invoice_request = OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.build().unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id).unwrap()
			.amount_msats(1001).unwrap()
			.build_and_sign().unwrap();
		let (_, _, tlv_stream, _, _, _) = invoice_request.as_tlv_stream();
		assert_eq!(invoice_request.amount_msats(), Some(1001));
		assert_eq!(tlv_stream.amount, Some(1001));

		match OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.build().unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id).unwrap()
			.amount_msats(999)
		{
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, Bolt12SemanticError::InsufficientAmount),
		}

		match OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.supported_quantity(Quantity::Unbounded)
			.build().unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id).unwrap()
			.quantity(2).unwrap()
			.amount_msats(1000)
		{
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, Bolt12SemanticError::InsufficientAmount),
		}

		match OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.build().unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id).unwrap()
			.amount_msats(MAX_VALUE_MSAT + 1)
		{
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, Bolt12SemanticError::InvalidAmount),
		}

		match OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.supported_quantity(Quantity::Unbounded)
			.build().unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id).unwrap()
			.amount_msats(1000).unwrap()
			.quantity(2).unwrap()
			.build_and_sign()
		{
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, Bolt12SemanticError::InsufficientAmount),
		}

		match OfferBuilder::new(recipient_pubkey())
			.build().unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id).unwrap()
			.build_and_sign()
		{
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, Bolt12SemanticError::MissingAmount),
		}

		match OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.supported_quantity(Quantity::Unbounded)
			.build().unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id).unwrap()
			.quantity(u64::max_value()).unwrap()
			.build_and_sign()
		{
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, Bolt12SemanticError::InvalidAmount),
		}
	}

	#[test]
	fn builds_invoice_request_with_features() {
		let expanded_key = ExpandedKey::new([42; 32]);
		let entropy = FixedEntropy {};
		let nonce = Nonce::from_entropy_source(&entropy);
		let secp_ctx = Secp256k1::new();
		let payment_id = PaymentId([1; 32]);

		let invoice_request = OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.build().unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id).unwrap()
			.features_unchecked(InvoiceRequestFeatures::unknown())
			.build_and_sign().unwrap();
		let (_, _, tlv_stream, _, _, _) = invoice_request.as_tlv_stream();
		assert_eq!(invoice_request.invoice_request_features(), &InvoiceRequestFeatures::unknown());
		assert_eq!(tlv_stream.features, Some(&InvoiceRequestFeatures::unknown()));

		let invoice_request = OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.build().unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id).unwrap()
			.features_unchecked(InvoiceRequestFeatures::unknown())
			.features_unchecked(InvoiceRequestFeatures::empty())
			.build_and_sign().unwrap();
		let (_, _, tlv_stream, _, _, _) = invoice_request.as_tlv_stream();
		assert_eq!(invoice_request.invoice_request_features(), &InvoiceRequestFeatures::empty());
		assert_eq!(tlv_stream.features, None);
	}

	#[test]
	fn builds_invoice_request_with_quantity() {
		let expanded_key = ExpandedKey::new([42; 32]);
		let entropy = FixedEntropy {};
		let nonce = Nonce::from_entropy_source(&entropy);
		let secp_ctx = Secp256k1::new();
		let payment_id = PaymentId([1; 32]);

		let one = NonZeroU64::new(1).unwrap();
		let ten = NonZeroU64::new(10).unwrap();

		let invoice_request = OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.supported_quantity(Quantity::One)
			.build().unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id).unwrap()
			.build_and_sign().unwrap();
		let (_, _, tlv_stream, _, _, _) = invoice_request.as_tlv_stream();
		assert_eq!(invoice_request.quantity(), None);
		assert_eq!(tlv_stream.quantity, None);

		match OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.supported_quantity(Quantity::One)
			.build().unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id).unwrap()
			.amount_msats(2_000).unwrap()
			.quantity(2)
		{
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, Bolt12SemanticError::UnexpectedQuantity),
		}

		let invoice_request = OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.supported_quantity(Quantity::Bounded(ten))
			.build().unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id).unwrap()
			.amount_msats(10_000).unwrap()
			.quantity(10).unwrap()
			.build_and_sign().unwrap();
		let (_, _, tlv_stream, _, _, _) = invoice_request.as_tlv_stream();
		assert_eq!(invoice_request.amount_msats(), Some(10_000));
		assert_eq!(tlv_stream.amount, Some(10_000));

		match OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.supported_quantity(Quantity::Bounded(ten))
			.build().unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id).unwrap()
			.amount_msats(11_000).unwrap()
			.quantity(11)
		{
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, Bolt12SemanticError::InvalidQuantity),
		}

		let invoice_request = OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.supported_quantity(Quantity::Unbounded)
			.build().unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id).unwrap()
			.amount_msats(2_000).unwrap()
			.quantity(2).unwrap()
			.build_and_sign().unwrap();
		let (_, _, tlv_stream, _, _, _) = invoice_request.as_tlv_stream();
		assert_eq!(invoice_request.amount_msats(), Some(2_000));
		assert_eq!(tlv_stream.amount, Some(2_000));

		match OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.supported_quantity(Quantity::Unbounded)
			.build().unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id).unwrap()
			.build_and_sign()
		{
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, Bolt12SemanticError::MissingQuantity),
		}

		match OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.supported_quantity(Quantity::Bounded(one))
			.build().unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id).unwrap()
			.build_and_sign()
		{
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, Bolt12SemanticError::MissingQuantity),
		}
	}

	#[test]
	fn builds_invoice_request_with_payer_note() {
		let expanded_key = ExpandedKey::new([42; 32]);
		let entropy = FixedEntropy {};
		let nonce = Nonce::from_entropy_source(&entropy);
		let secp_ctx = Secp256k1::new();
		let payment_id = PaymentId([1; 32]);

		let invoice_request = OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.build().unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id).unwrap()
			.payer_note("bar".into())
			.build_and_sign().unwrap();
		let (_, _, tlv_stream, _, _, _) = invoice_request.as_tlv_stream();
		assert_eq!(invoice_request.payer_note(), Some(PrintableString("bar")));
		assert_eq!(tlv_stream.payer_note, Some(&String::from("bar")));

		let invoice_request = OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.build().unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id).unwrap()
			.payer_note("bar".into())
			.payer_note("baz".into())
			.build_and_sign().unwrap();
		let (_, _, tlv_stream, _, _, _) = invoice_request.as_tlv_stream();
		assert_eq!(invoice_request.payer_note(), Some(PrintableString("baz")));
		assert_eq!(tlv_stream.payer_note, Some(&String::from("baz")));
	}

	#[test]
	fn fails_responding_with_unknown_required_features() {
		let expanded_key = ExpandedKey::new([42; 32]);
		let entropy = FixedEntropy {};
		let nonce = Nonce::from_entropy_source(&entropy);
		let secp_ctx = Secp256k1::new();
		let payment_id = PaymentId([1; 32]);

		match OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.build().unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id).unwrap()
			.features_unchecked(InvoiceRequestFeatures::unknown())
			.build_and_sign().unwrap()
			.respond_with_no_std(payment_paths(), payment_hash(), now())
		{
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, Bolt12SemanticError::UnknownRequiredFeatures),
		}
	}

	#[test]
	fn parses_invoice_request_with_metadata() {
		let expanded_key = ExpandedKey::new([42; 32]);
		let entropy = FixedEntropy {};
		let nonce = Nonce::from_entropy_source(&entropy);
		let secp_ctx = Secp256k1::new();
		let payment_id = PaymentId([1; 32]);

		let invoice_request = OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.build().unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id).unwrap()
			.build_and_sign().unwrap();

		let mut buffer = Vec::new();
		invoice_request.write(&mut buffer).unwrap();

		if let Err(e) = InvoiceRequest::try_from(buffer) {
			panic!("error parsing invoice_request: {:?}", e);
		}
	}

	#[test]
	fn parses_invoice_request_with_chain() {
		let expanded_key = ExpandedKey::new([42; 32]);
		let entropy = FixedEntropy {};
		let nonce = Nonce::from_entropy_source(&entropy);
		let secp_ctx = Secp256k1::new();
		let payment_id = PaymentId([1; 32]);

		let invoice_request = OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.build().unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id).unwrap()
			.chain(Network::Bitcoin).unwrap()
			.build_and_sign().unwrap();

		let mut buffer = Vec::new();
		invoice_request.write(&mut buffer).unwrap();

		if let Err(e) = InvoiceRequest::try_from(buffer) {
			panic!("error parsing invoice_request: {:?}", e);
		}

		let invoice_request = OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.build().unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id).unwrap()
			.chain_unchecked(Network::Testnet)
			.build_unchecked_and_sign();

		let mut buffer = Vec::new();
		invoice_request.write(&mut buffer).unwrap();

		match InvoiceRequest::try_from(buffer) {
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::UnsupportedChain)),
		}
	}

	#[test]
	fn parses_invoice_request_with_amount() {
		let expanded_key = ExpandedKey::new([42; 32]);
		let entropy = FixedEntropy {};
		let nonce = Nonce::from_entropy_source(&entropy);
		let secp_ctx = Secp256k1::new();
		let payment_id = PaymentId([1; 32]);

		let invoice_request = OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.build().unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id).unwrap()
			.build_and_sign().unwrap();

		let mut buffer = Vec::new();
		invoice_request.write(&mut buffer).unwrap();

		if let Err(e) = InvoiceRequest::try_from(buffer) {
			panic!("error parsing invoice_request: {:?}", e);
		}

		let invoice_request = OfferBuilder::new(recipient_pubkey())
			.build().unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id).unwrap()
			.amount_msats(1000).unwrap()
			.build_and_sign().unwrap();

		let mut buffer = Vec::new();
		invoice_request.write(&mut buffer).unwrap();

		if let Err(e) = InvoiceRequest::try_from(buffer) {
			panic!("error parsing invoice_request: {:?}", e);
		}

		let invoice_request = OfferBuilder::new(recipient_pubkey())
			.build().unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id).unwrap()
			.build_unchecked_and_sign();

		let mut buffer = Vec::new();
		invoice_request.write(&mut buffer).unwrap();

		match InvoiceRequest::try_from(buffer) {
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::MissingAmount)),
		}

		let invoice_request = OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.build().unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id).unwrap()
			.amount_msats_unchecked(999)
			.build_unchecked_and_sign();

		let mut buffer = Vec::new();
		invoice_request.write(&mut buffer).unwrap();

		match InvoiceRequest::try_from(buffer) {
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::InsufficientAmount)),
		}

		let invoice_request = OfferBuilder::new(recipient_pubkey())
			.description("foo".to_string())
			.amount(Amount::Currency(Currency { iso4217_code: *b"USD", amount: 1000 }))
			.build_unchecked()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id).unwrap()
			.build_unchecked_and_sign();

		let mut buffer = Vec::new();
		invoice_request.write(&mut buffer).unwrap();

		match InvoiceRequest::try_from(buffer) {
			Ok(_) => panic!("expected error"),
			Err(e) => {
				assert_eq!(e, Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::UnsupportedCurrency));
			},
		}

		let invoice_request = OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.supported_quantity(Quantity::Unbounded)
			.build().unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id).unwrap()
			.quantity(u64::max_value()).unwrap()
			.build_unchecked_and_sign();

		let mut buffer = Vec::new();
		invoice_request.write(&mut buffer).unwrap();

		match InvoiceRequest::try_from(buffer) {
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::InvalidAmount)),
		}
	}

	#[test]
	fn parses_invoice_request_with_quantity() {
		let expanded_key = ExpandedKey::new([42; 32]);
		let entropy = FixedEntropy {};
		let nonce = Nonce::from_entropy_source(&entropy);
		let secp_ctx = Secp256k1::new();
		let payment_id = PaymentId([1; 32]);

		let one = NonZeroU64::new(1).unwrap();
		let ten = NonZeroU64::new(10).unwrap();

		let invoice_request = OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.supported_quantity(Quantity::One)
			.build().unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id).unwrap()
			.build_and_sign().unwrap();

		let mut buffer = Vec::new();
		invoice_request.write(&mut buffer).unwrap();

		if let Err(e) = InvoiceRequest::try_from(buffer) {
			panic!("error parsing invoice_request: {:?}", e);
		}

		let invoice_request = OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.supported_quantity(Quantity::One)
			.build().unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id).unwrap()
			.amount_msats(2_000).unwrap()
			.quantity_unchecked(2)
			.build_unchecked_and_sign();

		let mut buffer = Vec::new();
		invoice_request.write(&mut buffer).unwrap();

		match InvoiceRequest::try_from(buffer) {
			Ok(_) => panic!("expected error"),
			Err(e) => {
				assert_eq!(e, Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::UnexpectedQuantity));
			},
		}

		let invoice_request = OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.supported_quantity(Quantity::Bounded(ten))
			.build().unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id).unwrap()
			.amount_msats(10_000).unwrap()
			.quantity(10).unwrap()
			.build_and_sign().unwrap();

		let mut buffer = Vec::new();
		invoice_request.write(&mut buffer).unwrap();

		if let Err(e) = InvoiceRequest::try_from(buffer) {
			panic!("error parsing invoice_request: {:?}", e);
		}

		let invoice_request = OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.supported_quantity(Quantity::Bounded(ten))
			.build().unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id).unwrap()
			.amount_msats(11_000).unwrap()
			.quantity_unchecked(11)
			.build_unchecked_and_sign();

		let mut buffer = Vec::new();
		invoice_request.write(&mut buffer).unwrap();

		match InvoiceRequest::try_from(buffer) {
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::InvalidQuantity)),
		}

		let invoice_request = OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.supported_quantity(Quantity::Unbounded)
			.build().unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id).unwrap()
			.amount_msats(2_000).unwrap()
			.quantity(2).unwrap()
			.build_and_sign().unwrap();

		let mut buffer = Vec::new();
		invoice_request.write(&mut buffer).unwrap();

		if let Err(e) = InvoiceRequest::try_from(buffer) {
			panic!("error parsing invoice_request: {:?}", e);
		}

		let invoice_request = OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.supported_quantity(Quantity::Unbounded)
			.build().unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id).unwrap()
			.build_unchecked_and_sign();

		let mut buffer = Vec::new();
		invoice_request.write(&mut buffer).unwrap();

		match InvoiceRequest::try_from(buffer) {
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::MissingQuantity)),
		}

		let invoice_request = OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.supported_quantity(Quantity::Bounded(one))
			.build().unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id).unwrap()
			.build_unchecked_and_sign();

		let mut buffer = Vec::new();
		invoice_request.write(&mut buffer).unwrap();

		match InvoiceRequest::try_from(buffer) {
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::MissingQuantity)),
		}
	}

	#[test]
	fn fails_parsing_invoice_request_without_metadata() {
		let expanded_key = ExpandedKey::new([42; 32]);
		let entropy = FixedEntropy {};
		let nonce = Nonce::from_entropy_source(&entropy);
		let secp_ctx = Secp256k1::new();
		let payment_id = PaymentId([1; 32]);

		let unsigned_invoice_request = OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.build().unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id).unwrap()
			.build_unchecked();
		let mut tlv_stream = unsigned_invoice_request.contents.as_tlv_stream();
		tlv_stream.0.metadata = None;

		let mut buffer = Vec::new();
		tlv_stream.write(&mut buffer).unwrap();

		match InvoiceRequest::try_from(buffer) {
			Ok(_) => panic!("expected error"),
			Err(e) => {
				assert_eq!(e, Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::MissingPayerMetadata));
			},
		}
	}

	#[test]
	fn fails_parsing_invoice_request_without_payer_signing_pubkey() {
		let expanded_key = ExpandedKey::new([42; 32]);
		let entropy = FixedEntropy {};
		let nonce = Nonce::from_entropy_source(&entropy);
		let secp_ctx = Secp256k1::new();
		let payment_id = PaymentId([1; 32]);

		let unsigned_invoice_request = OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.build().unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id).unwrap()
			.build_unchecked();
		let mut tlv_stream = unsigned_invoice_request.contents.as_tlv_stream();
		tlv_stream.2.payer_id = None;

		let mut buffer = Vec::new();
		tlv_stream.write(&mut buffer).unwrap();

		match InvoiceRequest::try_from(buffer) {
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::MissingPayerSigningPubkey)),
		}
	}

	#[test]
	fn fails_parsing_invoice_request_without_issuer_id() {
		let expanded_key = ExpandedKey::new([42; 32]);
		let entropy = FixedEntropy {};
		let nonce = Nonce::from_entropy_source(&entropy);
		let secp_ctx = Secp256k1::new();
		let payment_id = PaymentId([1; 32]);

		let unsigned_invoice_request = OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.build().unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id).unwrap()
			.build_unchecked();
		let mut tlv_stream = unsigned_invoice_request.contents.as_tlv_stream();
		tlv_stream.1.issuer_id = None;

		let mut buffer = Vec::new();
		tlv_stream.write(&mut buffer).unwrap();

		match InvoiceRequest::try_from(buffer) {
			Ok(_) => panic!("expected error"),
			Err(e) => {
				assert_eq!(e, Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::MissingIssuerSigningPubkey));
			},
		}
	}

	#[test]
	fn fails_parsing_invoice_request_without_signature() {
		let expanded_key = ExpandedKey::new([42; 32]);
		let entropy = FixedEntropy {};
		let nonce = Nonce::from_entropy_source(&entropy);
		let secp_ctx = Secp256k1::new();
		let payment_id = PaymentId([1; 32]);

		let mut buffer = Vec::new();
		OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.build().unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id).unwrap()
			.build_unchecked()
			.contents
			.write(&mut buffer).unwrap();

		match InvoiceRequest::try_from(buffer) {
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::MissingSignature)),
		}
	}

	#[test]
	fn fails_parsing_invoice_request_with_invalid_signature() {
		let expanded_key = ExpandedKey::new([42; 32]);
		let entropy = FixedEntropy {};
		let nonce = Nonce::from_entropy_source(&entropy);
		let secp_ctx = Secp256k1::new();
		let payment_id = PaymentId([1; 32]);

		let mut invoice_request = OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.build().unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id).unwrap()
			.build_and_sign().unwrap();
		let last_signature_byte = invoice_request.bytes.last_mut().unwrap();
		*last_signature_byte = last_signature_byte.wrapping_add(1);

		let mut buffer = Vec::new();
		invoice_request.write(&mut buffer).unwrap();

		match InvoiceRequest::try_from(buffer) {
			Ok(_) => panic!("expected error"),
			Err(e) => {
				assert_eq!(e, Bolt12ParseError::InvalidSignature(secp256k1::Error::IncorrectSignature));
			},
		}
	}

	#[test]
	fn parses_invoice_request_with_unknown_tlv_records() {
		let expanded_key = ExpandedKey::new([42; 32]);
		let entropy = FixedEntropy {};
		let nonce = Nonce::from_entropy_source(&entropy);
		let payment_id = PaymentId([1; 32]);

		const UNKNOWN_ODD_TYPE: u64 = INVOICE_REQUEST_TYPES.end - 1;
		assert!(UNKNOWN_ODD_TYPE % 2 == 1);

		let secp_ctx = Secp256k1::new();
		let keys = Keypair::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[42; 32]).unwrap());
		let (mut unsigned_invoice_request, payer_keys, _) = OfferBuilder::new(keys.public_key())
			.amount_msats(1000)
			.build().unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id).unwrap()
			.build_without_checks();

		let mut unknown_bytes = Vec::new();
		BigSize(UNKNOWN_ODD_TYPE).write(&mut unknown_bytes).unwrap();
		BigSize(32).write(&mut unknown_bytes).unwrap();
		[42u8; 32].write(&mut unknown_bytes).unwrap();

		unsigned_invoice_request.bytes.reserve_exact(
			unsigned_invoice_request.bytes.capacity()
				- unsigned_invoice_request.bytes.len()
				+ unknown_bytes.len(),
		);
		unsigned_invoice_request.bytes.extend_from_slice(&unknown_bytes);
		unsigned_invoice_request.tagged_hash =
			TaggedHash::from_valid_tlv_stream_bytes(SIGNATURE_TAG, &unsigned_invoice_request.bytes);

		let keys = payer_keys.unwrap();
		let invoice_request = unsigned_invoice_request
			.sign(|message: &UnsignedInvoiceRequest|
				Ok(secp_ctx.sign_schnorr_no_aux_rand(message.as_ref().as_digest(), &keys))
			)
			.unwrap();

		let mut encoded_invoice_request = Vec::new();
		invoice_request.write(&mut encoded_invoice_request).unwrap();

		match InvoiceRequest::try_from(encoded_invoice_request.clone()) {
			Ok(invoice_request) => assert_eq!(invoice_request.bytes, encoded_invoice_request),
			Err(e) => panic!("error parsing invoice_request: {:?}", e),
		}

		const UNKNOWN_EVEN_TYPE: u64 = INVOICE_REQUEST_TYPES.end - 2;
		assert!(UNKNOWN_EVEN_TYPE % 2 == 0);

		let (mut unsigned_invoice_request, payer_keys, _) = OfferBuilder::new(keys.public_key())
			.amount_msats(1000)
			.build().unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id).unwrap()
			.build_without_checks();

		let mut unknown_bytes = Vec::new();
		BigSize(UNKNOWN_EVEN_TYPE).write(&mut unknown_bytes).unwrap();
		BigSize(32).write(&mut unknown_bytes).unwrap();
		[42u8; 32].write(&mut unknown_bytes).unwrap();

		unsigned_invoice_request.bytes.reserve_exact(
			unsigned_invoice_request.bytes.capacity()
				- unsigned_invoice_request.bytes.len()
				+ unknown_bytes.len(),
		);
		unsigned_invoice_request.bytes.extend_from_slice(&unknown_bytes);
		unsigned_invoice_request.tagged_hash =
			TaggedHash::from_valid_tlv_stream_bytes(SIGNATURE_TAG, &unsigned_invoice_request.bytes);

		let keys = payer_keys.unwrap();
		let invoice_request = unsigned_invoice_request
			.sign(|message: &UnsignedInvoiceRequest|
				Ok(secp_ctx.sign_schnorr_no_aux_rand(message.as_ref().as_digest(), &keys))
			)
			.unwrap();

		let mut encoded_invoice_request = Vec::new();
		invoice_request.write(&mut encoded_invoice_request).unwrap();

		match InvoiceRequest::try_from(encoded_invoice_request) {
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, Bolt12ParseError::Decode(DecodeError::UnknownRequiredFeature)),
		}
	}

	#[test]
	fn parses_invoice_request_with_experimental_tlv_records() {
		let expanded_key = ExpandedKey::new([42; 32]);
		let entropy = FixedEntropy {};
		let nonce = Nonce::from_entropy_source(&entropy);
		let payment_id = PaymentId([1; 32]);

		const UNKNOWN_ODD_TYPE: u64 = EXPERIMENTAL_INVOICE_REQUEST_TYPES.start + 1;
		assert!(UNKNOWN_ODD_TYPE % 2 == 1);

		let secp_ctx = Secp256k1::new();
		let keys = Keypair::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[42; 32]).unwrap());
		let (mut unsigned_invoice_request, payer_keys, _) = OfferBuilder::new(keys.public_key())
			.amount_msats(1000)
			.build().unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id).unwrap()
			.build_without_checks();

		let mut unknown_bytes = Vec::new();
		BigSize(UNKNOWN_ODD_TYPE).write(&mut unknown_bytes).unwrap();
		BigSize(32).write(&mut unknown_bytes).unwrap();
		[42u8; 32].write(&mut unknown_bytes).unwrap();

		unsigned_invoice_request.bytes.reserve_exact(
			unsigned_invoice_request.bytes.capacity()
				- unsigned_invoice_request.bytes.len()
				+ unknown_bytes.len(),
		);
		unsigned_invoice_request.experimental_bytes.extend_from_slice(&unknown_bytes);

		let tlv_stream = TlvStream::new(&unsigned_invoice_request.bytes)
			.chain(TlvStream::new(&unsigned_invoice_request.experimental_bytes));
		unsigned_invoice_request.tagged_hash =
			TaggedHash::from_tlv_stream(SIGNATURE_TAG, tlv_stream);

		let keys = payer_keys.unwrap();
		let invoice_request = unsigned_invoice_request
			.sign(|message: &UnsignedInvoiceRequest|
				Ok(secp_ctx.sign_schnorr_no_aux_rand(message.as_ref().as_digest(), &keys))
			)
			.unwrap();

		let mut encoded_invoice_request = Vec::new();
		invoice_request.write(&mut encoded_invoice_request).unwrap();

		match InvoiceRequest::try_from(encoded_invoice_request.clone()) {
			Ok(invoice_request) => assert_eq!(invoice_request.bytes, encoded_invoice_request),
			Err(e) => panic!("error parsing invoice_request: {:?}", e),
		}

		const UNKNOWN_EVEN_TYPE: u64 = EXPERIMENTAL_INVOICE_REQUEST_TYPES.start;
		assert!(UNKNOWN_EVEN_TYPE % 2 == 0);

		let (mut unsigned_invoice_request, payer_keys, _) = OfferBuilder::new(keys.public_key())
			.amount_msats(1000)
			.build().unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id).unwrap()
			.build_without_checks();

		let mut unknown_bytes = Vec::new();
		BigSize(UNKNOWN_EVEN_TYPE).write(&mut unknown_bytes).unwrap();
		BigSize(32).write(&mut unknown_bytes).unwrap();
		[42u8; 32].write(&mut unknown_bytes).unwrap();

		unsigned_invoice_request.bytes.reserve_exact(
			unsigned_invoice_request.bytes.capacity()
				- unsigned_invoice_request.bytes.len()
				+ unknown_bytes.len(),
		);
		unsigned_invoice_request.experimental_bytes.extend_from_slice(&unknown_bytes);

		let tlv_stream = TlvStream::new(&unsigned_invoice_request.bytes)
			.chain(TlvStream::new(&unsigned_invoice_request.experimental_bytes));
		unsigned_invoice_request.tagged_hash =
			TaggedHash::from_tlv_stream(SIGNATURE_TAG, tlv_stream);

		let keys = payer_keys.unwrap();
		let invoice_request = unsigned_invoice_request
			.sign(|message: &UnsignedInvoiceRequest|
				Ok(secp_ctx.sign_schnorr_no_aux_rand(message.as_ref().as_digest(), &keys))
			)
			.unwrap();

		let mut encoded_invoice_request = Vec::new();
		invoice_request.write(&mut encoded_invoice_request).unwrap();

		match InvoiceRequest::try_from(encoded_invoice_request) {
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, Bolt12ParseError::Decode(DecodeError::UnknownRequiredFeature)),
		}

		let invoice_request = OfferBuilder::new(keys.public_key())
			.amount_msats(1000)
			.build().unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id).unwrap()
			.build_and_sign().unwrap();

		let mut encoded_invoice_request = Vec::new();
		invoice_request.write(&mut encoded_invoice_request).unwrap();

		BigSize(UNKNOWN_ODD_TYPE).write(&mut encoded_invoice_request).unwrap();
		BigSize(32).write(&mut encoded_invoice_request).unwrap();
		[42u8; 32].write(&mut encoded_invoice_request).unwrap();

		match InvoiceRequest::try_from(encoded_invoice_request) {
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, Bolt12ParseError::InvalidSignature(secp256k1::Error::IncorrectSignature)),
		}
	}

	#[test]
	fn fails_parsing_invoice_request_with_out_of_range_tlv_records() {
		let expanded_key = ExpandedKey::new([42; 32]);
		let entropy = FixedEntropy {};
		let nonce = Nonce::from_entropy_source(&entropy);
		let secp_ctx = Secp256k1::new();
		let payment_id = PaymentId([1; 32]);

		let invoice_request = OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.build().unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id).unwrap()
			.build_and_sign().unwrap();

		let mut encoded_invoice_request = Vec::new();
		invoice_request.write(&mut encoded_invoice_request).unwrap();
		BigSize(1002).write(&mut encoded_invoice_request).unwrap();
		BigSize(32).write(&mut encoded_invoice_request).unwrap();
		[42u8; 32].write(&mut encoded_invoice_request).unwrap();

		match InvoiceRequest::try_from(encoded_invoice_request) {
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, Bolt12ParseError::Decode(DecodeError::InvalidValue)),
		}

		let mut encoded_invoice_request = Vec::new();
		invoice_request.write(&mut encoded_invoice_request).unwrap();
		BigSize(EXPERIMENTAL_INVOICE_REQUEST_TYPES.end).write(&mut encoded_invoice_request).unwrap();
		BigSize(32).write(&mut encoded_invoice_request).unwrap();
		[42u8; 32].write(&mut encoded_invoice_request).unwrap();

		match InvoiceRequest::try_from(encoded_invoice_request) {
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, Bolt12ParseError::Decode(DecodeError::InvalidValue)),
		}
	}

	#[test]
	fn copies_verified_invoice_request_fields() {
		let node_id = recipient_pubkey();
		let expanded_key = ExpandedKey::new([42; 32]);
		let entropy = FixedEntropy {};
		let nonce = Nonce::from_entropy_source(&entropy);
		let secp_ctx = Secp256k1::new();
		let payment_id = PaymentId([1; 32]);

		#[cfg(c_bindings)]
		use crate::offers::offer::OfferWithDerivedMetadataBuilder as OfferBuilder;
		let offer = OfferBuilder::deriving_signing_pubkey(node_id, &expanded_key, nonce, &secp_ctx)
			.chain(Network::Testnet)
			.amount_msats(1000)
			.supported_quantity(Quantity::Unbounded)
			.build().unwrap();
		assert_eq!(offer.issuer_signing_pubkey(), Some(node_id));

		let invoice_request = offer
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id).unwrap()
			.chain(Network::Testnet).unwrap()
			.quantity(1).unwrap()
			.payer_note("0".repeat(PAYER_NOTE_LIMIT * 2))
			.build_and_sign().unwrap();
		match invoice_request.verify_using_metadata(&expanded_key, &secp_ctx) {
			Ok(invoice_request) => {
				let fields = invoice_request.fields();
				assert_eq!(invoice_request.offer_id, offer.id());
				assert_eq!(
					fields,
					InvoiceRequestFields {
						payer_signing_pubkey: invoice_request.payer_signing_pubkey(),
						quantity: Some(1),
						payer_note_truncated: Some(UntrustedString("0".repeat(PAYER_NOTE_LIMIT))),
						human_readable_name: None,
					}
				);

				let mut buffer = Vec::new();
				fields.write(&mut buffer).unwrap();

				let deserialized_fields: InvoiceRequestFields =
					Readable::read(&mut buffer.as_slice()).unwrap();
				assert_eq!(deserialized_fields, fields);
			},
			Err(_) => panic!("unexpected error"),
		}
	}
}
