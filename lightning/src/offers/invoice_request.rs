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
//! use bitcoin::network::constants::Network;
//! use bitcoin::secp256k1::{KeyPair, PublicKey, Secp256k1, SecretKey};
//! use core::convert::Infallible;
//! use lightning::ln::features::OfferFeatures;
//! use lightning::offers::offer::Offer;
//! use lightning::util::ser::Writeable;
//!
//! # fn parse() -> Result<(), lightning::offers::parse::Bolt12ParseError> {
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
//!     .sign::<_, Infallible>(
//!         |message| Ok(secp_ctx.sign_schnorr_no_aux_rand(message.as_ref().as_digest(), &keys))
//!     )
//!     .expect("failed verifying signature")
//!     .write(&mut buffer)
//!     .unwrap();
//! # Ok(())
//! # }
//! ```

use bitcoin::blockdata::constants::ChainHash;
use bitcoin::network::constants::Network;
use bitcoin::secp256k1::{KeyPair, PublicKey, Secp256k1, self};
use bitcoin::secp256k1::schnorr::Signature;
use core::convert::{AsRef, Infallible, TryFrom};
use core::ops::Deref;
use crate::sign::EntropySource;
use crate::io;
use crate::blinded_path::BlindedPath;
use crate::ln::PaymentHash;
use crate::ln::channelmanager::PaymentId;
use crate::ln::features::InvoiceRequestFeatures;
use crate::ln::inbound_payment::{ExpandedKey, IV_LEN, Nonce};
use crate::ln::msgs::DecodeError;
use crate::offers::invoice::{BlindedPayInfo, DerivedSigningPubkey, ExplicitSigningPubkey, InvoiceBuilder};
use crate::offers::merkle::{SignError, SignatureTlvStream, SignatureTlvStreamRef, TaggedHash, self};
use crate::offers::offer::{Offer, OfferContents, OfferTlvStream, OfferTlvStreamRef};
use crate::offers::parse::{Bolt12ParseError, ParsedMessage, Bolt12SemanticError};
use crate::offers::payer::{PayerContents, PayerTlvStream, PayerTlvStreamRef};
use crate::offers::signer::{Metadata, MetadataMaterial};
use crate::util::ser::{HighZeroBytesDroppedBigSize, SeekReadable, WithoutLength, Writeable, Writer};
use crate::util::string::PrintableString;

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
pub struct InvoiceRequestBuilder<'a, 'b, P: PayerIdStrategy, T: secp256k1::Signing> {
	offer: &'a Offer,
	invoice_request: InvoiceRequestContentsWithoutPayerId,
	payer_id: Option<PublicKey>,
	payer_id_strategy: core::marker::PhantomData<P>,
	secp_ctx: Option<&'b Secp256k1<T>>,
}

/// Indicates how [`InvoiceRequest::payer_id`] will be set.
///
/// This is not exported to bindings users as builder patterns don't map outside of move semantics.
pub trait PayerIdStrategy {}

/// [`InvoiceRequest::payer_id`] will be explicitly set.
///
/// This is not exported to bindings users as builder patterns don't map outside of move semantics.
pub struct ExplicitPayerId {}

/// [`InvoiceRequest::payer_id`] will be derived.
///
/// This is not exported to bindings users as builder patterns don't map outside of move semantics.
pub struct DerivedPayerId {}

impl PayerIdStrategy for ExplicitPayerId {}
impl PayerIdStrategy for DerivedPayerId {}

impl<'a, 'b, T: secp256k1::Signing> InvoiceRequestBuilder<'a, 'b, ExplicitPayerId, T> {
	pub(super) fn new(offer: &'a Offer, metadata: Vec<u8>, payer_id: PublicKey) -> Self {
		Self {
			offer,
			invoice_request: Self::create_contents(offer, Metadata::Bytes(metadata)),
			payer_id: Some(payer_id),
			payer_id_strategy: core::marker::PhantomData,
			secp_ctx: None,
		}
	}

	pub(super) fn deriving_metadata<ES: Deref>(
		offer: &'a Offer, payer_id: PublicKey, expanded_key: &ExpandedKey, entropy_source: ES,
		payment_id: PaymentId,
	) -> Self where ES::Target: EntropySource {
		let nonce = Nonce::from_entropy_source(entropy_source);
		let payment_id = Some(payment_id);
		let derivation_material = MetadataMaterial::new(nonce, expanded_key, IV_BYTES, payment_id);
		let metadata = Metadata::Derived(derivation_material);
		Self {
			offer,
			invoice_request: Self::create_contents(offer, metadata),
			payer_id: Some(payer_id),
			payer_id_strategy: core::marker::PhantomData,
			secp_ctx: None,
		}
	}
}

impl<'a, 'b, T: secp256k1::Signing> InvoiceRequestBuilder<'a, 'b, DerivedPayerId, T> {
	pub(super) fn deriving_payer_id<ES: Deref>(
		offer: &'a Offer, expanded_key: &ExpandedKey, entropy_source: ES,
		secp_ctx: &'b Secp256k1<T>, payment_id: PaymentId
	) -> Self where ES::Target: EntropySource {
		let nonce = Nonce::from_entropy_source(entropy_source);
		let payment_id = Some(payment_id);
		let derivation_material = MetadataMaterial::new(nonce, expanded_key, IV_BYTES, payment_id);
		let metadata = Metadata::DerivedSigningPubkey(derivation_material);
		Self {
			offer,
			invoice_request: Self::create_contents(offer, metadata),
			payer_id: None,
			payer_id_strategy: core::marker::PhantomData,
			secp_ctx: Some(secp_ctx),
		}
	}
}

impl<'a, 'b, P: PayerIdStrategy, T: secp256k1::Signing> InvoiceRequestBuilder<'a, 'b, P, T> {
	fn create_contents(offer: &Offer, metadata: Metadata) -> InvoiceRequestContentsWithoutPayerId {
		let offer = offer.contents.clone();
		InvoiceRequestContentsWithoutPayerId {
			payer: PayerContents(metadata), offer, chain: None, amount_msats: None,
			features: InvoiceRequestFeatures::empty(), quantity: None, payer_note: None,
		}
	}

	/// Sets the [`InvoiceRequest::chain`] of the given [`Network`] for paying an invoice. If not
	/// called, [`Network::Bitcoin`] is assumed. Errors if the chain for `network` is not supported
	/// by the offer.
	///
	/// Successive calls to this method will override the previous setting.
	pub fn chain(self, network: Network) -> Result<Self, Bolt12SemanticError> {
		self.chain_hash(ChainHash::using_genesis_block(network))
	}

	/// Sets the [`InvoiceRequest::chain`] for paying an invoice. If not called, the chain hash of
	/// [`Network::Bitcoin`] is assumed. Errors if the chain for `network` is not supported by the
	/// offer.
	///
	/// Successive calls to this method will override the previous setting.
	pub(crate) fn chain_hash(mut self, chain: ChainHash) -> Result<Self, Bolt12SemanticError> {
		if !self.offer.supports_chain(chain) {
			return Err(Bolt12SemanticError::UnsupportedChain);
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
	pub fn amount_msats(mut self, amount_msats: u64) -> Result<Self, Bolt12SemanticError> {
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
	pub fn quantity(mut self, quantity: u64) -> Result<Self, Bolt12SemanticError> {
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

	fn build_with_checks(mut self) -> Result<
		(UnsignedInvoiceRequest, Option<KeyPair>, Option<&'b Secp256k1<T>>),
		Bolt12SemanticError
	> {
		#[cfg(feature = "std")] {
			if self.offer.is_expired() {
				return Err(Bolt12SemanticError::AlreadyExpired);
			}
		}

		let chain = self.invoice_request.chain();
		if !self.offer.supports_chain(chain) {
			return Err(Bolt12SemanticError::UnsupportedChain);
		}

		if chain == self.offer.implied_chain() {
			self.invoice_request.chain = None;
		}

		if self.offer.amount().is_none() && self.invoice_request.amount_msats.is_none() {
			return Err(Bolt12SemanticError::MissingAmount);
		}

		self.invoice_request.offer.check_quantity(self.invoice_request.quantity)?;
		self.invoice_request.offer.check_amount_msats_for_quantity(
			self.invoice_request.amount_msats, self.invoice_request.quantity
		)?;

		Ok(self.build_without_checks())
	}

	fn build_without_checks(mut self) ->
		(UnsignedInvoiceRequest, Option<KeyPair>, Option<&'b Secp256k1<T>>)
	{
		// Create the metadata for stateless verification of a Bolt12Invoice.
		let mut keys = None;
		let secp_ctx = self.secp_ctx.clone();
		if self.invoice_request.payer.0.has_derivation_material() {
			let mut metadata = core::mem::take(&mut self.invoice_request.payer.0);

			let mut tlv_stream = self.invoice_request.as_tlv_stream();
			debug_assert!(tlv_stream.2.payer_id.is_none());
			tlv_stream.0.metadata = None;
			if !metadata.derives_payer_keys() {
				tlv_stream.2.payer_id = self.payer_id.as_ref();
			}

			let (derived_metadata, derived_keys) = metadata.derive_from(tlv_stream, self.secp_ctx);
			metadata = derived_metadata;
			keys = derived_keys;
			if let Some(keys) = keys {
				debug_assert!(self.payer_id.is_none());
				self.payer_id = Some(keys.public_key());
			}

			self.invoice_request.payer.0 = metadata;
		}

		debug_assert!(self.invoice_request.payer.0.as_bytes().is_some());
		debug_assert!(self.payer_id.is_some());
		let payer_id = self.payer_id.unwrap();

		let invoice_request = InvoiceRequestContents {
			inner: self.invoice_request,
			payer_id,
		};
		let unsigned_invoice_request = UnsignedInvoiceRequest::new(self.offer, invoice_request);

		(unsigned_invoice_request, keys, secp_ctx)
	}
}

impl<'a, 'b, T: secp256k1::Signing> InvoiceRequestBuilder<'a, 'b, ExplicitPayerId, T> {
	/// Builds an unsigned [`InvoiceRequest`] after checking for valid semantics. It can be signed
	/// by [`UnsignedInvoiceRequest::sign`].
	pub fn build(self) -> Result<UnsignedInvoiceRequest, Bolt12SemanticError> {
		let (unsigned_invoice_request, keys, _) = self.build_with_checks()?;
		debug_assert!(keys.is_none());
		Ok(unsigned_invoice_request)
	}
}

impl<'a, 'b, T: secp256k1::Signing> InvoiceRequestBuilder<'a, 'b, DerivedPayerId, T> {
	/// Builds a signed [`InvoiceRequest`] after checking for valid semantics.
	pub fn build_and_sign(self) -> Result<InvoiceRequest, Bolt12SemanticError> {
		let (unsigned_invoice_request, keys, secp_ctx) = self.build_with_checks()?;
		debug_assert!(keys.is_some());

		let secp_ctx = secp_ctx.unwrap();
		let keys = keys.unwrap();
		let invoice_request = unsigned_invoice_request
			.sign::<_, Infallible>(
				|message| Ok(secp_ctx.sign_schnorr_no_aux_rand(message.as_ref().as_digest(), &keys))
			)
			.unwrap();
		Ok(invoice_request)
	}
}

#[cfg(test)]
impl<'a, 'b, P: PayerIdStrategy, T: secp256k1::Signing> InvoiceRequestBuilder<'a, 'b, P, T> {
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

	pub(super) fn build_unchecked(self) -> UnsignedInvoiceRequest {
		self.build_without_checks().0
	}
}

/// A semantically valid [`InvoiceRequest`] that hasn't been signed.
///
/// # Serialization
///
/// This is serialized as a TLV stream, which includes TLV records from the originating message. As
/// such, it may include unknown, odd TLV records.
pub struct UnsignedInvoiceRequest {
	bytes: Vec<u8>,
	contents: InvoiceRequestContents,
	tagged_hash: TaggedHash,
}

impl UnsignedInvoiceRequest {
	fn new(offer: &Offer, contents: InvoiceRequestContents) -> Self {
		// Use the offer bytes instead of the offer TLV stream as the offer may have contained
		// unknown TLV records, which are not stored in `OfferContents`.
		let (payer_tlv_stream, _offer_tlv_stream, invoice_request_tlv_stream) =
			contents.as_tlv_stream();
		let offer_bytes = WithoutLength(&offer.bytes);
		let unsigned_tlv_stream = (payer_tlv_stream, offer_bytes, invoice_request_tlv_stream);

		let mut bytes = Vec::new();
		unsigned_tlv_stream.write(&mut bytes).unwrap();

		let tagged_hash = TaggedHash::new(SIGNATURE_TAG, &bytes);

		Self { bytes, contents, tagged_hash }
	}

	/// Returns the [`TaggedHash`] of the invoice to sign.
	pub fn tagged_hash(&self) -> &TaggedHash {
		&self.tagged_hash
	}

	/// Signs the [`TaggedHash`] of the invoice request using the given function.
	///
	/// Note: The hash computation may have included unknown, odd TLV records.
	///
	/// This is not exported to bindings users as functions are not yet mapped.
	pub fn sign<F, E>(mut self, sign: F) -> Result<InvoiceRequest, SignError<E>>
	where
		F: FnOnce(&Self) -> Result<Signature, E>
	{
		let pubkey = self.contents.payer_id;
		let signature = merkle::sign_message(sign, &self, pubkey)?;

		// Append the signature TLV record to the bytes.
		let signature_tlv_stream = SignatureTlvStreamRef {
			signature: Some(&signature),
		};
		signature_tlv_stream.write(&mut self.bytes).unwrap();

		Ok(InvoiceRequest {
			bytes: self.bytes,
			contents: self.contents,
			signature,
		})
	}
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

/// An [`InvoiceRequest`] that has been verified by [`InvoiceRequest::verify`] and exposes different
/// ways to respond depending on whether the signing keys were derived.
#[derive(Clone, Debug)]
pub struct VerifiedInvoiceRequest {
	/// The verified request.
	inner: InvoiceRequest,

	/// Keys used for signing a [`Bolt12Invoice`] if they can be derived.
	///
	/// If `Some`, must call [`respond_using_derived_keys`] when responding. Otherwise, call
	/// [`respond_with`].
	///
	/// [`Bolt12Invoice`]: crate::offers::invoice::Bolt12Invoice
	/// [`respond_using_derived_keys`]: Self::respond_using_derived_keys
	/// [`respond_with`]: Self::respond_with
	pub keys: Option<KeyPair>,
}

/// The contents of an [`InvoiceRequest`], which may be shared with an [`Bolt12Invoice`].
///
/// [`Bolt12Invoice`]: crate::offers::invoice::Bolt12Invoice
#[derive(Clone, Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub(super) struct InvoiceRequestContents {
	pub(super) inner: InvoiceRequestContentsWithoutPayerId,
	payer_id: PublicKey,
}

#[derive(Clone, Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub(super) struct InvoiceRequestContentsWithoutPayerId {
	payer: PayerContents,
	pub(super) offer: OfferContents,
	chain: Option<ChainHash>,
	amount_msats: Option<u64>,
	features: InvoiceRequestFeatures,
	quantity: Option<u64>,
	payer_note: Option<String>,
}

macro_rules! invoice_request_accessors { ($self: ident, $contents: expr) => {
	/// An unpredictable series of bytes, typically containing information about the derivation of
	/// [`payer_id`].
	///
	/// [`payer_id`]: Self::payer_id
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
	pub fn payer_id(&$self) -> PublicKey {
		$contents.payer_id()
	}

	/// A payer-provided note which will be seen by the recipient and reflected back in the invoice
	/// response.
	pub fn payer_note(&$self) -> Option<PrintableString> {
		$contents.payer_note()
	}
} }

impl UnsignedInvoiceRequest {
	offer_accessors!(self, self.contents.inner.offer);
	invoice_request_accessors!(self, self.contents);
}

impl InvoiceRequest {
	offer_accessors!(self, self.contents.inner.offer);
	invoice_request_accessors!(self, self.contents);

	/// Signature of the invoice request using [`payer_id`].
	///
	/// [`payer_id`]: Self::payer_id
	pub fn signature(&self) -> Signature {
		self.signature
	}

	/// Creates an [`InvoiceBuilder`] for the request with the given required fields and using the
	/// [`Duration`] since [`std::time::SystemTime::UNIX_EPOCH`] as the creation time.
	///
	/// See [`InvoiceRequest::respond_with_no_std`] for further details where the aforementioned
	/// creation time is used for the `created_at` parameter.
	///
	/// This is not exported to bindings users as builder patterns don't map outside of move semantics.
	///
	/// [`Duration`]: core::time::Duration
	#[cfg(feature = "std")]
	pub fn respond_with(
		&self, payment_paths: Vec<(BlindedPayInfo, BlindedPath)>, payment_hash: PaymentHash
	) -> Result<InvoiceBuilder<ExplicitSigningPubkey>, Bolt12SemanticError> {
		let created_at = std::time::SystemTime::now()
			.duration_since(std::time::SystemTime::UNIX_EPOCH)
			.expect("SystemTime::now() should come after SystemTime::UNIX_EPOCH");

		self.respond_with_no_std(payment_paths, payment_hash, created_at)
	}

	/// Creates an [`InvoiceBuilder`] for the request with the given required fields.
	///
	/// Unless [`InvoiceBuilder::relative_expiry`] is set, the invoice will expire two hours after
	/// `created_at`, which is used to set [`Bolt12Invoice::created_at`]. Useful for `no-std` builds
	/// where [`std::time::SystemTime`] is not available.
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
	/// # Note
	///
	/// If the originating [`Offer`] was created using [`OfferBuilder::deriving_signing_pubkey`],
	/// then use [`InvoiceRequest::verify`] and [`VerifiedInvoiceRequest`] methods instead.
	///
	/// This is not exported to bindings users as builder patterns don't map outside of move semantics.
	///
	/// [`Bolt12Invoice::created_at`]: crate::offers::invoice::Bolt12Invoice::created_at
	/// [`OfferBuilder::deriving_signing_pubkey`]: crate::offers::offer::OfferBuilder::deriving_signing_pubkey
	pub fn respond_with_no_std(
		&self, payment_paths: Vec<(BlindedPayInfo, BlindedPath)>, payment_hash: PaymentHash,
		created_at: core::time::Duration
	) -> Result<InvoiceBuilder<ExplicitSigningPubkey>, Bolt12SemanticError> {
		if self.invoice_request_features().requires_unknown_bits() {
			return Err(Bolt12SemanticError::UnknownRequiredFeatures);
		}

		InvoiceBuilder::for_offer(self, payment_paths, created_at, payment_hash)
	}

	/// Verifies that the request was for an offer created using the given key. Returns the verified
	/// request which contains the derived keys needed to sign a [`Bolt12Invoice`] for the request
	/// if they could be extracted from the metadata.
	///
	/// [`Bolt12Invoice`]: crate::offers::invoice::Bolt12Invoice
	pub fn verify<T: secp256k1::Signing>(
		self, key: &ExpandedKey, secp_ctx: &Secp256k1<T>
	) -> Result<VerifiedInvoiceRequest, ()> {
		let keys = self.contents.inner.offer.verify(&self.bytes, key, secp_ctx)?;
		Ok(VerifiedInvoiceRequest {
			inner: self,
			keys,
		})
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

impl VerifiedInvoiceRequest {
	offer_accessors!(self, self.inner.contents.inner.offer);
	invoice_request_accessors!(self, self.inner.contents);

	/// Creates an [`InvoiceBuilder`] for the request with the given required fields and using the
	/// [`Duration`] since [`std::time::SystemTime::UNIX_EPOCH`] as the creation time.
	///
	/// See [`InvoiceRequest::respond_with_no_std`] for further details.
	///
	/// This is not exported to bindings users as builder patterns don't map outside of move semantics.
	///
	/// [`Duration`]: core::time::Duration
	#[cfg(feature = "std")]
	pub fn respond_with(
		&self, payment_paths: Vec<(BlindedPayInfo, BlindedPath)>, payment_hash: PaymentHash
	) -> Result<InvoiceBuilder<ExplicitSigningPubkey>, Bolt12SemanticError> {
		self.inner.respond_with(payment_paths, payment_hash)
	}

	/// Creates an [`InvoiceBuilder`] for the request with the given required fields.
	///
	/// See [`InvoiceRequest::respond_with_no_std`] for further details.
	///
	/// This is not exported to bindings users as builder patterns don't map outside of move semantics.
	pub fn respond_with_no_std(
		&self, payment_paths: Vec<(BlindedPayInfo, BlindedPath)>, payment_hash: PaymentHash,
		created_at: core::time::Duration
	) -> Result<InvoiceBuilder<ExplicitSigningPubkey>, Bolt12SemanticError> {
		self.inner.respond_with_no_std(payment_paths, payment_hash, created_at)
	}

	/// Creates an [`InvoiceBuilder`] for the request using the given required fields and that uses
	/// derived signing keys from the originating [`Offer`] to sign the [`Bolt12Invoice`]. Must use
	/// the same [`ExpandedKey`] as the one used to create the offer.
	///
	/// See [`InvoiceRequest::respond_with`] for further details.
	///
	/// This is not exported to bindings users as builder patterns don't map outside of move semantics.
	///
	/// [`Bolt12Invoice`]: crate::offers::invoice::Bolt12Invoice
	#[cfg(feature = "std")]
	pub fn respond_using_derived_keys(
		&self, payment_paths: Vec<(BlindedPayInfo, BlindedPath)>, payment_hash: PaymentHash
	) -> Result<InvoiceBuilder<DerivedSigningPubkey>, Bolt12SemanticError> {
		let created_at = std::time::SystemTime::now()
			.duration_since(std::time::SystemTime::UNIX_EPOCH)
			.expect("SystemTime::now() should come after SystemTime::UNIX_EPOCH");

		self.respond_using_derived_keys_no_std(payment_paths, payment_hash, created_at)
	}

	/// Creates an [`InvoiceBuilder`] for the request using the given required fields and that uses
	/// derived signing keys from the originating [`Offer`] to sign the [`Bolt12Invoice`]. Must use
	/// the same [`ExpandedKey`] as the one used to create the offer.
	///
	/// See [`InvoiceRequest::respond_with_no_std`] for further details.
	///
	/// This is not exported to bindings users as builder patterns don't map outside of move semantics.
	///
	/// [`Bolt12Invoice`]: crate::offers::invoice::Bolt12Invoice
	pub fn respond_using_derived_keys_no_std(
		&self, payment_paths: Vec<(BlindedPayInfo, BlindedPath)>, payment_hash: PaymentHash,
		created_at: core::time::Duration
	) -> Result<InvoiceBuilder<DerivedSigningPubkey>, Bolt12SemanticError> {
		if self.inner.invoice_request_features().requires_unknown_bits() {
			return Err(Bolt12SemanticError::UnknownRequiredFeatures);
		}

		let keys = match self.keys {
			None => return Err(Bolt12SemanticError::InvalidMetadata),
			Some(keys) => keys,
		};

		InvoiceBuilder::for_offer_using_keys(
			&self.inner, payment_paths, created_at, payment_hash, keys
		)
	}
}

impl InvoiceRequestContents {
	pub(super) fn metadata(&self) -> &[u8] {
		self.inner.metadata()
	}

	pub(super) fn derives_keys(&self) -> bool {
		self.inner.payer.0.derives_payer_keys()
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

	pub(super) fn payer_id(&self) -> PublicKey {
		self.payer_id
	}

	pub(super) fn payer_note(&self) -> Option<PrintableString> {
		self.inner.payer_note.as_ref()
			.map(|payer_note| PrintableString(payer_note.as_str()))
	}

	pub(super) fn as_tlv_stream(&self) -> PartialInvoiceRequestTlvStreamRef {
		let (payer, offer, mut invoice_request) = self.inner.as_tlv_stream();
		invoice_request.payer_id = Some(&self.payer_id);
		(payer, offer, invoice_request)
	}
}

impl InvoiceRequestContentsWithoutPayerId {
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
			payer_id: None,
			payer_note: self.payer_note.as_ref(),
		};

		(payer, offer, invoice_request)
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

/// Valid type range for invoice_request TLV records.
pub(super) const INVOICE_REQUEST_TYPES: core::ops::Range<u64> = 80..160;

/// TLV record type for [`InvoiceRequest::payer_id`] and [`Refund::payer_id`].
///
/// [`Refund::payer_id`]: crate::offers::refund::Refund::payer_id
pub(super) const INVOICE_REQUEST_PAYER_ID_TYPE: u64 = 88;

tlv_stream!(InvoiceRequestTlvStream, InvoiceRequestTlvStreamRef, INVOICE_REQUEST_TYPES, {
	(80, chain: ChainHash),
	(82, amount: (u64, HighZeroBytesDroppedBigSize)),
	(84, features: (InvoiceRequestFeatures, WithoutLength)),
	(86, quantity: (u64, HighZeroBytesDroppedBigSize)),
	(INVOICE_REQUEST_PAYER_ID_TYPE, payer_id: PublicKey),
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

impl TryFrom<Vec<u8>> for UnsignedInvoiceRequest {
	type Error = Bolt12ParseError;

	fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
		let invoice_request = ParsedMessage::<PartialInvoiceRequestTlvStream>::try_from(bytes)?;
		let ParsedMessage { bytes, tlv_stream } = invoice_request;
		let (
			payer_tlv_stream, offer_tlv_stream, invoice_request_tlv_stream,
		) = tlv_stream;
		let contents = InvoiceRequestContents::try_from(
			(payer_tlv_stream, offer_tlv_stream, invoice_request_tlv_stream)
		)?;

		let tagged_hash = TaggedHash::new(SIGNATURE_TAG, &bytes);

		Ok(UnsignedInvoiceRequest { bytes, contents, tagged_hash })
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
		) = tlv_stream;
		let contents = InvoiceRequestContents::try_from(
			(payer_tlv_stream, offer_tlv_stream, invoice_request_tlv_stream)
		)?;

		let signature = match signature {
			None => return Err(Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::MissingSignature)),
			Some(signature) => signature,
		};
		let message = TaggedHash::new(SIGNATURE_TAG, &bytes);
		merkle::verify_signature(&signature, message, contents.payer_id)?;

		Ok(InvoiceRequest { bytes, contents, signature })
	}
}

impl TryFrom<PartialInvoiceRequestTlvStream> for InvoiceRequestContents {
	type Error = Bolt12SemanticError;

	fn try_from(tlv_stream: PartialInvoiceRequestTlvStream) -> Result<Self, Self::Error> {
		let (
			PayerTlvStream { metadata },
			offer_tlv_stream,
			InvoiceRequestTlvStream { chain, amount, features, quantity, payer_id, payer_note },
		) = tlv_stream;

		let payer = match metadata {
			None => return Err(Bolt12SemanticError::MissingPayerMetadata),
			Some(metadata) => PayerContents(Metadata::Bytes(metadata)),
		};
		let offer = OfferContents::try_from(offer_tlv_stream)?;

		if !offer.supports_chain(chain.unwrap_or_else(|| offer.implied_chain())) {
			return Err(Bolt12SemanticError::UnsupportedChain);
		}

		if offer.amount().is_none() && amount.is_none() {
			return Err(Bolt12SemanticError::MissingAmount);
		}

		offer.check_quantity(quantity)?;
		offer.check_amount_msats_for_quantity(amount, quantity)?;

		let features = features.unwrap_or_else(InvoiceRequestFeatures::empty);

		let payer_id = match payer_id {
			None => return Err(Bolt12SemanticError::MissingPayerId),
			Some(payer_id) => payer_id,
		};

		Ok(InvoiceRequestContents {
			inner: InvoiceRequestContentsWithoutPayerId {
				payer, offer, chain, amount_msats: amount, features, quantity, payer_note,
			},
			payer_id,
		})
	}
}

#[cfg(test)]
mod tests {
	use super::{InvoiceRequest, InvoiceRequestTlvStreamRef, SIGNATURE_TAG, UnsignedInvoiceRequest};

	use bitcoin::blockdata::constants::ChainHash;
	use bitcoin::network::constants::Network;
	use bitcoin::secp256k1::{KeyPair, Secp256k1, SecretKey, self};
	use core::convert::{Infallible, TryFrom};
	use core::num::NonZeroU64;
	#[cfg(feature = "std")]
	use core::time::Duration;
	use crate::sign::KeyMaterial;
	use crate::ln::channelmanager::PaymentId;
	use crate::ln::features::{InvoiceRequestFeatures, OfferFeatures};
	use crate::ln::inbound_payment::ExpandedKey;
	use crate::ln::msgs::{DecodeError, MAX_VALUE_MSAT};
	use crate::offers::invoice::{Bolt12Invoice, SIGNATURE_TAG as INVOICE_SIGNATURE_TAG};
	use crate::offers::merkle::{SignError, SignatureTlvStreamRef, TaggedHash, self};
	use crate::offers::offer::{Amount, OfferBuilder, OfferTlvStreamRef, Quantity};
	use crate::offers::parse::{Bolt12ParseError, Bolt12SemanticError};
	use crate::offers::payer::PayerTlvStreamRef;
	use crate::offers::test_utils::*;
	use crate::util::ser::{BigSize, Writeable};
	use crate::util::string::PrintableString;

	#[test]
	fn builds_invoice_request_with_defaults() {
		let unsigned_invoice_request = OfferBuilder::new("foo".into(), recipient_pubkey())
			.amount_msats(1000)
			.build().unwrap()
			.request_invoice(vec![1; 32], payer_pubkey()).unwrap()
			.build().unwrap();

		let mut buffer = Vec::new();
		unsigned_invoice_request.write(&mut buffer).unwrap();

		assert_eq!(unsigned_invoice_request.bytes, buffer.as_slice());
		assert_eq!(unsigned_invoice_request.payer_metadata(), &[1; 32]);
		assert_eq!(unsigned_invoice_request.chains(), vec![ChainHash::using_genesis_block(Network::Bitcoin)]);
		assert_eq!(unsigned_invoice_request.metadata(), None);
		assert_eq!(unsigned_invoice_request.amount(), Some(&Amount::Bitcoin { amount_msats: 1000 }));
		assert_eq!(unsigned_invoice_request.description(), PrintableString("foo"));
		assert_eq!(unsigned_invoice_request.offer_features(), &OfferFeatures::empty());
		assert_eq!(unsigned_invoice_request.absolute_expiry(), None);
		assert_eq!(unsigned_invoice_request.paths(), &[]);
		assert_eq!(unsigned_invoice_request.issuer(), None);
		assert_eq!(unsigned_invoice_request.supported_quantity(), Quantity::One);
		assert_eq!(unsigned_invoice_request.signing_pubkey(), recipient_pubkey());
		assert_eq!(unsigned_invoice_request.chain(), ChainHash::using_genesis_block(Network::Bitcoin));
		assert_eq!(unsigned_invoice_request.amount_msats(), None);
		assert_eq!(unsigned_invoice_request.invoice_request_features(), &InvoiceRequestFeatures::empty());
		assert_eq!(unsigned_invoice_request.quantity(), None);
		assert_eq!(unsigned_invoice_request.payer_id(), payer_pubkey());
		assert_eq!(unsigned_invoice_request.payer_note(), None);

		match UnsignedInvoiceRequest::try_from(buffer) {
			Err(e) => panic!("error parsing unsigned invoice request: {:?}", e),
			Ok(parsed) => {
				assert_eq!(parsed.bytes, unsigned_invoice_request.bytes);
				assert_eq!(parsed.tagged_hash, unsigned_invoice_request.tagged_hash);
			},
		}

		let invoice_request = unsigned_invoice_request.sign(payer_sign).unwrap();

		let mut buffer = Vec::new();
		invoice_request.write(&mut buffer).unwrap();

		assert_eq!(invoice_request.bytes, buffer.as_slice());
		assert_eq!(invoice_request.payer_metadata(), &[1; 32]);
		assert_eq!(invoice_request.chains(), vec![ChainHash::using_genesis_block(Network::Bitcoin)]);
		assert_eq!(invoice_request.metadata(), None);
		assert_eq!(invoice_request.amount(), Some(&Amount::Bitcoin { amount_msats: 1000 }));
		assert_eq!(invoice_request.description(), PrintableString("foo"));
		assert_eq!(invoice_request.offer_features(), &OfferFeatures::empty());
		assert_eq!(invoice_request.absolute_expiry(), None);
		assert_eq!(invoice_request.paths(), &[]);
		assert_eq!(invoice_request.issuer(), None);
		assert_eq!(invoice_request.supported_quantity(), Quantity::One);
		assert_eq!(invoice_request.signing_pubkey(), recipient_pubkey());
		assert_eq!(invoice_request.chain(), ChainHash::using_genesis_block(Network::Bitcoin));
		assert_eq!(invoice_request.amount_msats(), None);
		assert_eq!(invoice_request.invoice_request_features(), &InvoiceRequestFeatures::empty());
		assert_eq!(invoice_request.quantity(), None);
		assert_eq!(invoice_request.payer_id(), payer_pubkey());
		assert_eq!(invoice_request.payer_note(), None);

		let message = TaggedHash::new(SIGNATURE_TAG, &invoice_request.bytes);
		assert!(merkle::verify_signature(&invoice_request.signature, message, payer_pubkey()).is_ok());

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
			Err(e) => assert_eq!(e, Bolt12SemanticError::AlreadyExpired),
		}
	}

	#[test]
	fn builds_invoice_request_with_derived_metadata() {
		let payer_id = payer_pubkey();
		let expanded_key = ExpandedKey::new(&KeyMaterial([42; 32]));
		let entropy = FixedEntropy {};
		let secp_ctx = Secp256k1::new();
		let payment_id = PaymentId([1; 32]);

		let offer = OfferBuilder::new("foo".into(), recipient_pubkey())
			.amount_msats(1000)
			.build().unwrap();
		let invoice_request = offer
			.request_invoice_deriving_metadata(payer_id, &expanded_key, &entropy, payment_id)
			.unwrap()
			.build().unwrap()
			.sign(payer_sign).unwrap();
		assert_eq!(invoice_request.payer_id(), payer_pubkey());

		let invoice = invoice_request.respond_with_no_std(payment_paths(), payment_hash(), now())
			.unwrap()
			.build().unwrap()
			.sign(recipient_sign).unwrap();
		match invoice.verify(&expanded_key, &secp_ctx) {
			Ok(payment_id) => assert_eq!(payment_id, PaymentId([1; 32])),
			Err(()) => panic!("verification failed"),
		}

		// Fails verification with altered fields
		let (
			payer_tlv_stream, offer_tlv_stream, mut invoice_request_tlv_stream,
			mut invoice_tlv_stream, mut signature_tlv_stream
		) = invoice.as_tlv_stream();
		invoice_request_tlv_stream.amount = Some(2000);
		invoice_tlv_stream.amount = Some(2000);

		let tlv_stream =
			(payer_tlv_stream, offer_tlv_stream, invoice_request_tlv_stream, invoice_tlv_stream);
		let mut bytes = Vec::new();
		tlv_stream.write(&mut bytes).unwrap();

		let message = TaggedHash::new(INVOICE_SIGNATURE_TAG, &bytes);
		let signature = merkle::sign_message(recipient_sign, &message, recipient_pubkey()).unwrap();
		signature_tlv_stream.signature = Some(&signature);

		let mut encoded_invoice = bytes;
		signature_tlv_stream.write(&mut encoded_invoice).unwrap();

		let invoice = Bolt12Invoice::try_from(encoded_invoice).unwrap();
		assert!(invoice.verify(&expanded_key, &secp_ctx).is_err());

		// Fails verification with altered metadata
		let (
			mut payer_tlv_stream, offer_tlv_stream, invoice_request_tlv_stream, invoice_tlv_stream,
			mut signature_tlv_stream
		) = invoice.as_tlv_stream();
		let metadata = payer_tlv_stream.metadata.unwrap().iter().copied().rev().collect();
		payer_tlv_stream.metadata = Some(&metadata);

		let tlv_stream =
			(payer_tlv_stream, offer_tlv_stream, invoice_request_tlv_stream, invoice_tlv_stream);
		let mut bytes = Vec::new();
		tlv_stream.write(&mut bytes).unwrap();

		let message = TaggedHash::new(INVOICE_SIGNATURE_TAG, &bytes);
		let signature = merkle::sign_message(recipient_sign, &message, recipient_pubkey()).unwrap();
		signature_tlv_stream.signature = Some(&signature);

		let mut encoded_invoice = bytes;
		signature_tlv_stream.write(&mut encoded_invoice).unwrap();

		let invoice = Bolt12Invoice::try_from(encoded_invoice).unwrap();
		assert!(invoice.verify(&expanded_key, &secp_ctx).is_err());
	}

	#[test]
	fn builds_invoice_request_with_derived_payer_id() {
		let expanded_key = ExpandedKey::new(&KeyMaterial([42; 32]));
		let entropy = FixedEntropy {};
		let secp_ctx = Secp256k1::new();
		let payment_id = PaymentId([1; 32]);

		let offer = OfferBuilder::new("foo".into(), recipient_pubkey())
			.amount_msats(1000)
			.build().unwrap();
		let invoice_request = offer
			.request_invoice_deriving_payer_id(&expanded_key, &entropy, &secp_ctx, payment_id)
			.unwrap()
			.build_and_sign()
			.unwrap();

		let invoice = invoice_request.respond_with_no_std(payment_paths(), payment_hash(), now())
			.unwrap()
			.build().unwrap()
			.sign(recipient_sign).unwrap();
		match invoice.verify(&expanded_key, &secp_ctx) {
			Ok(payment_id) => assert_eq!(payment_id, PaymentId([1; 32])),
			Err(()) => panic!("verification failed"),
		}

		// Fails verification with altered fields
		let (
			payer_tlv_stream, offer_tlv_stream, mut invoice_request_tlv_stream,
			mut invoice_tlv_stream, mut signature_tlv_stream
		) = invoice.as_tlv_stream();
		invoice_request_tlv_stream.amount = Some(2000);
		invoice_tlv_stream.amount = Some(2000);

		let tlv_stream =
			(payer_tlv_stream, offer_tlv_stream, invoice_request_tlv_stream, invoice_tlv_stream);
		let mut bytes = Vec::new();
		tlv_stream.write(&mut bytes).unwrap();

		let message = TaggedHash::new(INVOICE_SIGNATURE_TAG, &bytes);
		let signature = merkle::sign_message(recipient_sign, &message, recipient_pubkey()).unwrap();
		signature_tlv_stream.signature = Some(&signature);

		let mut encoded_invoice = bytes;
		signature_tlv_stream.write(&mut encoded_invoice).unwrap();

		let invoice = Bolt12Invoice::try_from(encoded_invoice).unwrap();
		assert!(invoice.verify(&expanded_key, &secp_ctx).is_err());

		// Fails verification with altered payer id
		let (
			payer_tlv_stream, offer_tlv_stream, mut invoice_request_tlv_stream, invoice_tlv_stream,
			mut signature_tlv_stream
		) = invoice.as_tlv_stream();
		let payer_id = pubkey(1);
		invoice_request_tlv_stream.payer_id = Some(&payer_id);

		let tlv_stream =
			(payer_tlv_stream, offer_tlv_stream, invoice_request_tlv_stream, invoice_tlv_stream);
		let mut bytes = Vec::new();
		tlv_stream.write(&mut bytes).unwrap();

		let message = TaggedHash::new(INVOICE_SIGNATURE_TAG, &bytes);
		let signature = merkle::sign_message(recipient_sign, &message, recipient_pubkey()).unwrap();
		signature_tlv_stream.signature = Some(&signature);

		let mut encoded_invoice = bytes;
		signature_tlv_stream.write(&mut encoded_invoice).unwrap();

		let invoice = Bolt12Invoice::try_from(encoded_invoice).unwrap();
		assert!(invoice.verify(&expanded_key, &secp_ctx).is_err());
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
			Err(e) => assert_eq!(e, Bolt12SemanticError::UnsupportedChain),
		}

		match OfferBuilder::new("foo".into(), recipient_pubkey())
			.amount_msats(1000)
			.chain(Network::Testnet)
			.build().unwrap()
			.request_invoice(vec![1; 32], payer_pubkey()).unwrap()
			.build()
		{
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, Bolt12SemanticError::UnsupportedChain),
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
			Err(e) => assert_eq!(e, Bolt12SemanticError::InsufficientAmount),
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
			Err(e) => assert_eq!(e, Bolt12SemanticError::InsufficientAmount),
		}

		match OfferBuilder::new("foo".into(), recipient_pubkey())
			.amount_msats(1000)
			.build().unwrap()
			.request_invoice(vec![1; 32], payer_pubkey()).unwrap()
			.amount_msats(MAX_VALUE_MSAT + 1)
		{
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, Bolt12SemanticError::InvalidAmount),
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
			Err(e) => assert_eq!(e, Bolt12SemanticError::InsufficientAmount),
		}

		match OfferBuilder::new("foo".into(), recipient_pubkey())
			.build().unwrap()
			.request_invoice(vec![1; 32], payer_pubkey()).unwrap()
			.build()
		{
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, Bolt12SemanticError::MissingAmount),
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
			Err(e) => assert_eq!(e, Bolt12SemanticError::InvalidAmount),
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
		assert_eq!(invoice_request.invoice_request_features(), &InvoiceRequestFeatures::unknown());
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
		assert_eq!(invoice_request.invoice_request_features(), &InvoiceRequestFeatures::empty());
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
			Err(e) => assert_eq!(e, Bolt12SemanticError::UnexpectedQuantity),
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
			Err(e) => assert_eq!(e, Bolt12SemanticError::InvalidQuantity),
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
			Err(e) => assert_eq!(e, Bolt12SemanticError::MissingQuantity),
		}

		match OfferBuilder::new("foo".into(), recipient_pubkey())
			.amount_msats(1000)
			.supported_quantity(Quantity::Bounded(one))
			.build().unwrap()
			.request_invoice(vec![1; 32], payer_pubkey()).unwrap()
			.build()
		{
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, Bolt12SemanticError::MissingQuantity),
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
	fn fails_responding_with_unknown_required_features() {
		match OfferBuilder::new("foo".into(), recipient_pubkey())
			.amount_msats(1000)
			.build().unwrap()
			.request_invoice(vec![42; 32], payer_pubkey()).unwrap()
			.features_unchecked(InvoiceRequestFeatures::unknown())
			.build().unwrap()
			.sign(payer_sign).unwrap()
			.respond_with_no_std(payment_paths(), payment_hash(), now())
		{
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, Bolt12SemanticError::UnknownRequiredFeatures),
		}
	}

	#[test]
	fn parses_invoice_request_with_metadata() {
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
			Err(e) => assert_eq!(e, Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::UnsupportedChain)),
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
			Err(e) => assert_eq!(e, Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::MissingAmount)),
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
			Err(e) => assert_eq!(e, Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::InsufficientAmount)),
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
				assert_eq!(e, Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::UnsupportedCurrency));
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
			Err(e) => assert_eq!(e, Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::InvalidAmount)),
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
				assert_eq!(e, Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::UnexpectedQuantity));
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
			Err(e) => assert_eq!(e, Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::InvalidQuantity)),
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
			Err(e) => assert_eq!(e, Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::MissingQuantity)),
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
			Err(e) => assert_eq!(e, Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::MissingQuantity)),
		}
	}

	#[test]
	fn fails_parsing_invoice_request_without_metadata() {
		let offer = OfferBuilder::new("foo".into(), recipient_pubkey())
			.amount_msats(1000)
			.build().unwrap();
		let unsigned_invoice_request = offer.request_invoice(vec![1; 32], payer_pubkey()).unwrap()
			.build().unwrap();
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
	fn fails_parsing_invoice_request_without_payer_id() {
		let offer = OfferBuilder::new("foo".into(), recipient_pubkey())
			.amount_msats(1000)
			.build().unwrap();
		let unsigned_invoice_request = offer.request_invoice(vec![1; 32], payer_pubkey()).unwrap()
			.build().unwrap();
		let mut tlv_stream = unsigned_invoice_request.contents.as_tlv_stream();
		tlv_stream.2.payer_id = None;

		let mut buffer = Vec::new();
		tlv_stream.write(&mut buffer).unwrap();

		match InvoiceRequest::try_from(buffer) {
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::MissingPayerId)),
		}
	}

	#[test]
	fn fails_parsing_invoice_request_without_node_id() {
		let offer = OfferBuilder::new("foo".into(), recipient_pubkey())
			.amount_msats(1000)
			.build().unwrap();
		let unsigned_invoice_request = offer.request_invoice(vec![1; 32], payer_pubkey()).unwrap()
			.build().unwrap();
		let mut tlv_stream = unsigned_invoice_request.contents.as_tlv_stream();
		tlv_stream.1.node_id = None;

		let mut buffer = Vec::new();
		tlv_stream.write(&mut buffer).unwrap();

		match InvoiceRequest::try_from(buffer) {
			Ok(_) => panic!("expected error"),
			Err(e) => {
				assert_eq!(e, Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::MissingSigningPubkey));
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
			.contents
			.write(&mut buffer).unwrap();

		match InvoiceRequest::try_from(buffer) {
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::MissingSignature)),
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
				assert_eq!(e, Bolt12ParseError::InvalidSignature(secp256k1::Error::InvalidSignature));
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
			.sign::<_, Infallible>(
				|message| Ok(secp_ctx.sign_schnorr_no_aux_rand(message.as_ref().as_digest(), &keys))
			)
			.unwrap();

		let mut encoded_invoice_request = Vec::new();
		invoice_request.write(&mut encoded_invoice_request).unwrap();
		BigSize(1002).write(&mut encoded_invoice_request).unwrap();
		BigSize(32).write(&mut encoded_invoice_request).unwrap();
		[42u8; 32].write(&mut encoded_invoice_request).unwrap();

		match InvoiceRequest::try_from(encoded_invoice_request) {
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, Bolt12ParseError::Decode(DecodeError::InvalidValue)),
		}
	}
}
