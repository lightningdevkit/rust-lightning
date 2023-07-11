// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Data structures and encoding for `invoice` messages.
//!
//! A [`Bolt12Invoice`] can be built from a parsed [`InvoiceRequest`] for the "offer to be paid"
//! flow or from a [`Refund`] as an "offer for money" flow. The expected recipient of the payment
//! then sends the invoice to the intended payer, who will then pay it.
//!
//! The payment recipient must include a [`PaymentHash`], so as to reveal the preimage upon payment
//! receipt, and one or more [`BlindedPath`]s for the payer to use when sending the payment.
//!
//! ```
//! extern crate bitcoin;
//! extern crate lightning;
//!
//! use bitcoin::hashes::Hash;
//! use bitcoin::secp256k1::{KeyPair, PublicKey, Secp256k1, SecretKey};
//! use core::convert::{Infallible, TryFrom};
//! use lightning::offers::invoice_request::InvoiceRequest;
//! use lightning::offers::refund::Refund;
//! use lightning::util::ser::Writeable;
//!
//! # use lightning::ln::PaymentHash;
//! # use lightning::offers::invoice::BlindedPayInfo;
//! # use lightning::blinded_path::BlindedPath;
//! #
//! # fn create_payment_paths() -> Vec<(BlindedPayInfo, BlindedPath)> { unimplemented!() }
//! # fn create_payment_hash() -> PaymentHash { unimplemented!() }
//! #
//! # fn parse_invoice_request(bytes: Vec<u8>) -> Result<(), lightning::offers::parse::Bolt12ParseError> {
//! let payment_paths = create_payment_paths();
//! let payment_hash = create_payment_hash();
//! let secp_ctx = Secp256k1::new();
//! let keys = KeyPair::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[42; 32])?);
//! let pubkey = PublicKey::from(keys);
//! let wpubkey_hash = bitcoin::util::key::PublicKey::new(pubkey).wpubkey_hash().unwrap();
//! let mut buffer = Vec::new();
//!
//! // Invoice for the "offer to be paid" flow.
//! InvoiceRequest::try_from(bytes)?
#![cfg_attr(feature = "std", doc = "
    .respond_with(payment_paths, payment_hash)?
")]
#![cfg_attr(not(feature = "std"), doc = "
    .respond_with_no_std(payment_paths, payment_hash, core::time::Duration::from_secs(0))?
")]
//!     .relative_expiry(3600)
//!     .allow_mpp()
//!     .fallback_v0_p2wpkh(&wpubkey_hash)
//!     .build()?
//!     .sign::<_, Infallible>(
//!         |message| Ok(secp_ctx.sign_schnorr_no_aux_rand(message.as_ref().as_digest(), &keys))
//!     )
//!     .expect("failed verifying signature")
//!     .write(&mut buffer)
//!     .unwrap();
//! # Ok(())
//! # }
//!
//! # fn parse_refund(bytes: Vec<u8>) -> Result<(), lightning::offers::parse::Bolt12ParseError> {
//! # let payment_paths = create_payment_paths();
//! # let payment_hash = create_payment_hash();
//! # let secp_ctx = Secp256k1::new();
//! # let keys = KeyPair::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[42; 32])?);
//! # let pubkey = PublicKey::from(keys);
//! # let wpubkey_hash = bitcoin::util::key::PublicKey::new(pubkey).wpubkey_hash().unwrap();
//! # let mut buffer = Vec::new();
//!
//! // Invoice for the "offer for money" flow.
//! "lnr1qcp4256ypq"
//!     .parse::<Refund>()?
#![cfg_attr(feature = "std", doc = "
    .respond_with(payment_paths, payment_hash, pubkey)?
")]
#![cfg_attr(not(feature = "std"), doc = "
    .respond_with_no_std(payment_paths, payment_hash, pubkey, core::time::Duration::from_secs(0))?
")]
//!     .relative_expiry(3600)
//!     .allow_mpp()
//!     .fallback_v0_p2wpkh(&wpubkey_hash)
//!     .build()?
//!     .sign::<_, Infallible>(
//!         |message| Ok(secp_ctx.sign_schnorr_no_aux_rand(message.as_ref().as_digest(), &keys))
//!     )
//!     .expect("failed verifying signature")
//!     .write(&mut buffer)
//!     .unwrap();
//! # Ok(())
//! # }
//!
//! ```

use bitcoin::blockdata::constants::ChainHash;
use bitcoin::hash_types::{WPubkeyHash, WScriptHash};
use bitcoin::hashes::Hash;
use bitcoin::network::constants::Network;
use bitcoin::secp256k1::{KeyPair, PublicKey, Secp256k1, self};
use bitcoin::secp256k1::schnorr::Signature;
use bitcoin::util::address::{Address, Payload, WitnessVersion};
use bitcoin::util::schnorr::TweakedPublicKey;
use core::convert::{AsRef, Infallible, TryFrom};
use core::time::Duration;
use crate::io;
use crate::blinded_path::BlindedPath;
use crate::ln::PaymentHash;
use crate::ln::features::{BlindedHopFeatures, Bolt12InvoiceFeatures, InvoiceRequestFeatures, OfferFeatures};
use crate::ln::inbound_payment::ExpandedKey;
use crate::ln::msgs::DecodeError;
use crate::offers::invoice_request::{INVOICE_REQUEST_PAYER_ID_TYPE, INVOICE_REQUEST_TYPES, IV_BYTES as INVOICE_REQUEST_IV_BYTES, InvoiceRequest, InvoiceRequestContents, InvoiceRequestTlvStream, InvoiceRequestTlvStreamRef};
use crate::offers::merkle::{SignError, SignatureTlvStream, SignatureTlvStreamRef, TaggedHash, TlvStream, WithoutSignatures, self};
use crate::offers::offer::{Amount, OFFER_TYPES, OfferTlvStream, OfferTlvStreamRef, Quantity};
use crate::offers::parse::{Bolt12ParseError, Bolt12SemanticError, ParsedMessage};
use crate::offers::payer::{PAYER_METADATA_TYPE, PayerTlvStream, PayerTlvStreamRef};
use crate::offers::refund::{IV_BYTES as REFUND_IV_BYTES, Refund, RefundContents};
use crate::offers::signer;
use crate::util::ser::{HighZeroBytesDroppedBigSize, Iterable, SeekReadable, WithoutLength, Writeable, Writer};
use crate::util::string::PrintableString;

use crate::prelude::*;

#[cfg(feature = "std")]
use std::time::SystemTime;

const DEFAULT_RELATIVE_EXPIRY: Duration = Duration::from_secs(7200);

/// Tag for the hash function used when signing a [`Bolt12Invoice`]'s merkle root.
pub const SIGNATURE_TAG: &'static str = concat!("lightning", "invoice", "signature");

/// Builds a [`Bolt12Invoice`] from either:
/// - an [`InvoiceRequest`] for the "offer to be paid" flow or
/// - a [`Refund`] for the "offer for money" flow.
///
/// See [module-level documentation] for usage.
///
/// This is not exported to bindings users as builder patterns don't map outside of move semantics.
///
/// [`InvoiceRequest`]: crate::offers::invoice_request::InvoiceRequest
/// [`Refund`]: crate::offers::refund::Refund
/// [module-level documentation]: self
pub struct InvoiceBuilder<'a, S: SigningPubkeyStrategy> {
	invreq_bytes: &'a Vec<u8>,
	invoice: InvoiceContents,
	signing_pubkey_strategy: S,
}

/// Indicates how [`Bolt12Invoice::signing_pubkey`] was set.
///
/// This is not exported to bindings users as builder patterns don't map outside of move semantics.
pub trait SigningPubkeyStrategy {}

/// [`Bolt12Invoice::signing_pubkey`] was explicitly set.
///
/// This is not exported to bindings users as builder patterns don't map outside of move semantics.
pub struct ExplicitSigningPubkey {}

/// [`Bolt12Invoice::signing_pubkey`] was derived.
///
/// This is not exported to bindings users as builder patterns don't map outside of move semantics.
pub struct DerivedSigningPubkey(KeyPair);

impl SigningPubkeyStrategy for ExplicitSigningPubkey {}
impl SigningPubkeyStrategy for DerivedSigningPubkey {}

impl<'a> InvoiceBuilder<'a, ExplicitSigningPubkey> {
	pub(super) fn for_offer(
		invoice_request: &'a InvoiceRequest, payment_paths: Vec<(BlindedPayInfo, BlindedPath)>,
		created_at: Duration, payment_hash: PaymentHash
	) -> Result<Self, Bolt12SemanticError> {
		let amount_msats = Self::check_amount_msats(invoice_request)?;
		let signing_pubkey = invoice_request.contents.inner.offer.signing_pubkey();
		let contents = InvoiceContents::ForOffer {
			invoice_request: invoice_request.contents.clone(),
			fields: Self::fields(
				payment_paths, created_at, payment_hash, amount_msats, signing_pubkey
			),
		};

		Self::new(&invoice_request.bytes, contents, ExplicitSigningPubkey {})
	}

	pub(super) fn for_refund(
		refund: &'a Refund, payment_paths: Vec<(BlindedPayInfo, BlindedPath)>, created_at: Duration,
		payment_hash: PaymentHash, signing_pubkey: PublicKey
	) -> Result<Self, Bolt12SemanticError> {
		let amount_msats = refund.amount_msats();
		let contents = InvoiceContents::ForRefund {
			refund: refund.contents.clone(),
			fields: Self::fields(
				payment_paths, created_at, payment_hash, amount_msats, signing_pubkey
			),
		};

		Self::new(&refund.bytes, contents, ExplicitSigningPubkey {})
	}
}

impl<'a> InvoiceBuilder<'a, DerivedSigningPubkey> {
	pub(super) fn for_offer_using_keys(
		invoice_request: &'a InvoiceRequest, payment_paths: Vec<(BlindedPayInfo, BlindedPath)>,
		created_at: Duration, payment_hash: PaymentHash, keys: KeyPair
	) -> Result<Self, Bolt12SemanticError> {
		let amount_msats = Self::check_amount_msats(invoice_request)?;
		let signing_pubkey = invoice_request.contents.inner.offer.signing_pubkey();
		let contents = InvoiceContents::ForOffer {
			invoice_request: invoice_request.contents.clone(),
			fields: Self::fields(
				payment_paths, created_at, payment_hash, amount_msats, signing_pubkey
			),
		};

		Self::new(&invoice_request.bytes, contents, DerivedSigningPubkey(keys))
	}

	pub(super) fn for_refund_using_keys(
		refund: &'a Refund, payment_paths: Vec<(BlindedPayInfo, BlindedPath)>, created_at: Duration,
		payment_hash: PaymentHash, keys: KeyPair,
	) -> Result<Self, Bolt12SemanticError> {
		let amount_msats = refund.amount_msats();
		let signing_pubkey = keys.public_key();
		let contents = InvoiceContents::ForRefund {
			refund: refund.contents.clone(),
			fields: Self::fields(
				payment_paths, created_at, payment_hash, amount_msats, signing_pubkey
			),
		};

		Self::new(&refund.bytes, contents, DerivedSigningPubkey(keys))
	}
}

impl<'a, S: SigningPubkeyStrategy> InvoiceBuilder<'a, S> {
	fn check_amount_msats(invoice_request: &InvoiceRequest) -> Result<u64, Bolt12SemanticError> {
		match invoice_request.amount_msats() {
			Some(amount_msats) => Ok(amount_msats),
			None => match invoice_request.contents.inner.offer.amount() {
				Some(Amount::Bitcoin { amount_msats }) => {
					amount_msats.checked_mul(invoice_request.quantity().unwrap_or(1))
						.ok_or(Bolt12SemanticError::InvalidAmount)
				},
				Some(Amount::Currency { .. }) => Err(Bolt12SemanticError::UnsupportedCurrency),
				None => Err(Bolt12SemanticError::MissingAmount),
			},
		}
	}

	fn fields(
		payment_paths: Vec<(BlindedPayInfo, BlindedPath)>, created_at: Duration,
		payment_hash: PaymentHash, amount_msats: u64, signing_pubkey: PublicKey
	) -> InvoiceFields {
		InvoiceFields {
			payment_paths, created_at, relative_expiry: None, payment_hash, amount_msats,
			fallbacks: None, features: Bolt12InvoiceFeatures::empty(), signing_pubkey,
		}
	}

	fn new(
		invreq_bytes: &'a Vec<u8>, contents: InvoiceContents, signing_pubkey_strategy: S
	) -> Result<Self, Bolt12SemanticError> {
		if contents.fields().payment_paths.is_empty() {
			return Err(Bolt12SemanticError::MissingPaths);
		}

		Ok(Self { invreq_bytes, invoice: contents, signing_pubkey_strategy })
	}

	/// Sets the [`Bolt12Invoice::relative_expiry`] as seconds since [`Bolt12Invoice::created_at`].
	/// Any expiry that has already passed is valid and can be checked for using
	/// [`Bolt12Invoice::is_expired`].
	///
	/// Successive calls to this method will override the previous setting.
	pub fn relative_expiry(mut self, relative_expiry_secs: u32) -> Self {
		let relative_expiry = Duration::from_secs(relative_expiry_secs as u64);
		self.invoice.fields_mut().relative_expiry = Some(relative_expiry);
		self
	}

	/// Adds a P2WSH address to [`Bolt12Invoice::fallbacks`].
	///
	/// Successive calls to this method will add another address. Caller is responsible for not
	/// adding duplicate addresses and only calling if capable of receiving to P2WSH addresses.
	pub fn fallback_v0_p2wsh(mut self, script_hash: &WScriptHash) -> Self {
		let address = FallbackAddress {
			version: WitnessVersion::V0.to_num(),
			program: Vec::from(&script_hash.into_inner()[..]),
		};
		self.invoice.fields_mut().fallbacks.get_or_insert_with(Vec::new).push(address);
		self
	}

	/// Adds a P2WPKH address to [`Bolt12Invoice::fallbacks`].
	///
	/// Successive calls to this method will add another address. Caller is responsible for not
	/// adding duplicate addresses and only calling if capable of receiving to P2WPKH addresses.
	pub fn fallback_v0_p2wpkh(mut self, pubkey_hash: &WPubkeyHash) -> Self {
		let address = FallbackAddress {
			version: WitnessVersion::V0.to_num(),
			program: Vec::from(&pubkey_hash.into_inner()[..]),
		};
		self.invoice.fields_mut().fallbacks.get_or_insert_with(Vec::new).push(address);
		self
	}

	/// Adds a P2TR address to [`Bolt12Invoice::fallbacks`].
	///
	/// Successive calls to this method will add another address. Caller is responsible for not
	/// adding duplicate addresses and only calling if capable of receiving to P2TR addresses.
	pub fn fallback_v1_p2tr_tweaked(mut self, output_key: &TweakedPublicKey) -> Self {
		let address = FallbackAddress {
			version: WitnessVersion::V1.to_num(),
			program: Vec::from(&output_key.serialize()[..]),
		};
		self.invoice.fields_mut().fallbacks.get_or_insert_with(Vec::new).push(address);
		self
	}

	/// Sets [`Bolt12Invoice::invoice_features`] to indicate MPP may be used. Otherwise, MPP is
	/// disallowed.
	pub fn allow_mpp(mut self) -> Self {
		self.invoice.fields_mut().features.set_basic_mpp_optional();
		self
	}
}

impl<'a> InvoiceBuilder<'a, ExplicitSigningPubkey> {
	/// Builds an unsigned [`Bolt12Invoice`] after checking for valid semantics. It can be signed by
	/// [`UnsignedBolt12Invoice::sign`].
	pub fn build(self) -> Result<UnsignedBolt12Invoice, Bolt12SemanticError> {
		#[cfg(feature = "std")] {
			if self.invoice.is_offer_or_refund_expired() {
				return Err(Bolt12SemanticError::AlreadyExpired);
			}
		}

		let InvoiceBuilder { invreq_bytes, invoice, .. } = self;
		Ok(UnsignedBolt12Invoice::new(invreq_bytes, invoice))
	}
}

impl<'a> InvoiceBuilder<'a, DerivedSigningPubkey> {
	/// Builds a signed [`Bolt12Invoice`] after checking for valid semantics.
	pub fn build_and_sign<T: secp256k1::Signing>(
		self, secp_ctx: &Secp256k1<T>
	) -> Result<Bolt12Invoice, Bolt12SemanticError> {
		#[cfg(feature = "std")] {
			if self.invoice.is_offer_or_refund_expired() {
				return Err(Bolt12SemanticError::AlreadyExpired);
			}
		}

		let InvoiceBuilder {
			invreq_bytes, invoice, signing_pubkey_strategy: DerivedSigningPubkey(keys)
		} = self;
		let unsigned_invoice = UnsignedBolt12Invoice::new(invreq_bytes, invoice);

		let invoice = unsigned_invoice
			.sign::<_, Infallible>(
				|message| Ok(secp_ctx.sign_schnorr_no_aux_rand(message.as_ref().as_digest(), &keys))
			)
			.unwrap();
		Ok(invoice)
	}
}

/// A semantically valid [`Bolt12Invoice`] that hasn't been signed.
///
/// # Serialization
///
/// This is serialized as a TLV stream, which includes TLV records from the originating message. As
/// such, it may include unknown, odd TLV records.
pub struct UnsignedBolt12Invoice {
	bytes: Vec<u8>,
	contents: InvoiceContents,
	tagged_hash: TaggedHash,
}

impl UnsignedBolt12Invoice {
	fn new(invreq_bytes: &[u8], contents: InvoiceContents) -> Self {
		// Use the invoice_request bytes instead of the invoice_request TLV stream as the latter may
		// have contained unknown TLV records, which are not stored in `InvoiceRequestContents` or
		// `RefundContents`.
		let (_, _, _, invoice_tlv_stream) = contents.as_tlv_stream();
		let invoice_request_bytes = WithoutSignatures(invreq_bytes);
		let unsigned_tlv_stream = (invoice_request_bytes, invoice_tlv_stream);

		let mut bytes = Vec::new();
		unsigned_tlv_stream.write(&mut bytes).unwrap();

		let tagged_hash = TaggedHash::new(SIGNATURE_TAG, &bytes);

		Self { bytes, contents, tagged_hash }
	}

	/// Signs the [`TaggedHash`] of the invoice using the given function.
	///
	/// Note: The hash computation may have included unknown, odd TLV records.
	///
	/// This is not exported to bindings users as functions aren't currently mapped.
	pub fn sign<F, E>(mut self, sign: F) -> Result<Bolt12Invoice, SignError<E>>
	where
		F: FnOnce(&Self) -> Result<Signature, E>
	{
		let pubkey = self.contents.fields().signing_pubkey;
		let signature = merkle::sign_message(sign, &self, pubkey)?;

		// Append the signature TLV record to the bytes.
		let signature_tlv_stream = SignatureTlvStreamRef {
			signature: Some(&signature),
		};
		signature_tlv_stream.write(&mut self.bytes).unwrap();

		Ok(Bolt12Invoice {
			bytes: self.bytes,
			contents: self.contents,
			signature,
		})
	}
}

impl AsRef<TaggedHash> for UnsignedBolt12Invoice {
	fn as_ref(&self) -> &TaggedHash {
		&self.tagged_hash
	}
}

/// A `Bolt12Invoice` is a payment request, typically corresponding to an [`Offer`] or a [`Refund`].
///
/// An invoice may be sent in response to an [`InvoiceRequest`] in the case of an offer or sent
/// directly after scanning a refund. It includes all the information needed to pay a recipient.
///
/// [`Offer`]: crate::offers::offer::Offer
/// [`Refund`]: crate::offers::refund::Refund
/// [`InvoiceRequest`]: crate::offers::invoice_request::InvoiceRequest
#[derive(Clone, Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct Bolt12Invoice {
	bytes: Vec<u8>,
	contents: InvoiceContents,
	signature: Signature,
}

/// The contents of an [`Bolt12Invoice`] for responding to either an [`Offer`] or a [`Refund`].
///
/// [`Offer`]: crate::offers::offer::Offer
/// [`Refund`]: crate::offers::refund::Refund
#[derive(Clone, Debug)]
#[cfg_attr(test, derive(PartialEq))]
enum InvoiceContents {
	/// Contents for an [`Bolt12Invoice`] corresponding to an [`Offer`].
	///
	/// [`Offer`]: crate::offers::offer::Offer
	ForOffer {
		invoice_request: InvoiceRequestContents,
		fields: InvoiceFields,
	},
	/// Contents for an [`Bolt12Invoice`] corresponding to a [`Refund`].
	///
	/// [`Refund`]: crate::offers::refund::Refund
	ForRefund {
		refund: RefundContents,
		fields: InvoiceFields,
	},
}

/// Invoice-specific fields for an `invoice` message.
#[derive(Clone, Debug, PartialEq)]
struct InvoiceFields {
	payment_paths: Vec<(BlindedPayInfo, BlindedPath)>,
	created_at: Duration,
	relative_expiry: Option<Duration>,
	payment_hash: PaymentHash,
	amount_msats: u64,
	fallbacks: Option<Vec<FallbackAddress>>,
	features: Bolt12InvoiceFeatures,
	signing_pubkey: PublicKey,
}

macro_rules! invoice_accessors { ($self: ident, $contents: expr) => {
	/// The chains that may be used when paying a requested invoice.
	///
	/// From [`Offer::chains`]; `None` if the invoice was created in response to a [`Refund`].
	///
	/// [`Offer::chains`]: crate::offers::offer::Offer::chains
	pub fn offer_chains(&$self) -> Option<Vec<ChainHash>> {
		$contents.offer_chains()
	}

	/// The chain that must be used when paying the invoice; selected from [`offer_chains`] if the
	/// invoice originated from an offer.
	///
	/// From [`InvoiceRequest::chain`] or [`Refund::chain`].
	///
	/// [`offer_chains`]: Self::offer_chains
	/// [`InvoiceRequest::chain`]: crate::offers::invoice_request::InvoiceRequest::chain
	pub fn chain(&$self) -> ChainHash {
		$contents.chain()
	}

	/// Opaque bytes set by the originating [`Offer`].
	///
	/// From [`Offer::metadata`]; `None` if the invoice was created in response to a [`Refund`] or
	/// if the [`Offer`] did not set it.
	///
	/// [`Offer`]: crate::offers::offer::Offer
	/// [`Offer::metadata`]: crate::offers::offer::Offer::metadata
	pub fn metadata(&$self) -> Option<&Vec<u8>> {
		$contents.metadata()
	}

	/// The minimum amount required for a successful payment of a single item.
	///
	/// From [`Offer::amount`]; `None` if the invoice was created in response to a [`Refund`] or if
	/// the [`Offer`] did not set it.
	///
	/// [`Offer`]: crate::offers::offer::Offer
	/// [`Offer::amount`]: crate::offers::offer::Offer::amount
	pub fn amount(&$self) -> Option<&Amount> {
		$contents.amount()
	}

	/// Features pertaining to the originating [`Offer`].
	///
	/// From [`Offer::offer_features`]; `None` if the invoice was created in response to a
	/// [`Refund`].
	///
	/// [`Offer`]: crate::offers::offer::Offer
	/// [`Offer::offer_features`]: crate::offers::offer::Offer::offer_features
	pub fn offer_features(&$self) -> Option<&OfferFeatures> {
		$contents.offer_features()
	}

	/// A complete description of the purpose of the originating offer or refund.
	///
	/// From [`Offer::description`] or [`Refund::description`].
	///
	/// [`Offer::description`]: crate::offers::offer::Offer::description
	pub fn description(&$self) -> PrintableString {
		$contents.description()
	}

	/// Duration since the Unix epoch when an invoice should no longer be requested.
	///
	/// From [`Offer::absolute_expiry`] or [`Refund::absolute_expiry`].
	///
	/// [`Offer::absolute_expiry`]: crate::offers::offer::Offer::absolute_expiry
	pub fn absolute_expiry(&$self) -> Option<Duration> {
		$contents.absolute_expiry()
	}

	/// The issuer of the offer or refund.
	///
	/// From [`Offer::issuer`] or [`Refund::issuer`].
	///
	/// [`Offer::issuer`]: crate::offers::offer::Offer::issuer
	pub fn issuer(&$self) -> Option<PrintableString> {
		$contents.issuer()
	}

	/// Paths to the recipient originating from publicly reachable nodes.
	///
	/// From [`Offer::paths`] or [`Refund::paths`].
	///
	/// [`Offer::paths`]: crate::offers::offer::Offer::paths
	pub fn message_paths(&$self) -> &[BlindedPath] {
		$contents.message_paths()
	}

	/// The quantity of items supported.
	///
	/// From [`Offer::supported_quantity`]; `None` if the invoice was created in response to a
	/// [`Refund`].
	///
	/// [`Offer::supported_quantity`]: crate::offers::offer::Offer::supported_quantity
	pub fn supported_quantity(&$self) -> Option<Quantity> {
		$contents.supported_quantity()
	}

	/// An unpredictable series of bytes from the payer.
	///
	/// From [`InvoiceRequest::payer_metadata`] or [`Refund::payer_metadata`].
	pub fn payer_metadata(&$self) -> &[u8] {
		$contents.payer_metadata()
	}

	/// Features pertaining to requesting an invoice.
	///
	/// From [`InvoiceRequest::invoice_request_features`] or [`Refund::features`].
	pub fn invoice_request_features(&$self) -> &InvoiceRequestFeatures {
		&$contents.invoice_request_features()
	}

	/// The quantity of items requested or refunded for.
	///
	/// From [`InvoiceRequest::quantity`] or [`Refund::quantity`].
	pub fn quantity(&$self) -> Option<u64> {
		$contents.quantity()
	}

	/// A possibly transient pubkey used to sign the invoice request or to send an invoice for a
	/// refund in case there are no [`message_paths`].
	///
	/// [`message_paths`]: Self::message_paths
	pub fn payer_id(&$self) -> PublicKey {
		$contents.payer_id()
	}

	/// A payer-provided note reflected back in the invoice.
	///
	/// From [`InvoiceRequest::payer_note`] or [`Refund::payer_note`].
	pub fn payer_note(&$self) -> Option<PrintableString> {
		$contents.payer_note()
	}

	/// Paths to the recipient originating from publicly reachable nodes, including information
	/// needed for routing payments across them.
	///
	/// Blinded paths provide recipient privacy by obfuscating its node id. Note, however, that this
	/// privacy is lost if a public node id is used for [`Bolt12Invoice::signing_pubkey`].
	///
	/// This is not exported to bindings users as slices with non-reference types cannot be ABI
	/// matched in another language.
	pub fn payment_paths(&$self) -> &[(BlindedPayInfo, BlindedPath)] {
		$contents.payment_paths()
	}

	/// Duration since the Unix epoch when the invoice was created.
	pub fn created_at(&$self) -> Duration {
		$contents.created_at()
	}

	/// Duration since [`Bolt12Invoice::created_at`] when the invoice has expired and therefore
	/// should no longer be paid.
	pub fn relative_expiry(&$self) -> Duration {
		$contents.relative_expiry()
	}

	/// Whether the invoice has expired.
	#[cfg(feature = "std")]
	pub fn is_expired(&$self) -> bool {
		$contents.is_expired()
	}

	/// SHA256 hash of the payment preimage that will be given in return for paying the invoice.
	pub fn payment_hash(&$self) -> PaymentHash {
		$contents.payment_hash()
	}

	/// The minimum amount required for a successful payment of the invoice.
	pub fn amount_msats(&$self) -> u64 {
		$contents.amount_msats()
	}

	/// Fallback addresses for paying the invoice on-chain, in order of most-preferred to
	/// least-preferred.
	pub fn fallbacks(&$self) -> Vec<Address> {
		$contents.fallbacks()
	}

	/// Features pertaining to paying an invoice.
	pub fn invoice_features(&$self) -> &Bolt12InvoiceFeatures {
		$contents.features()
	}

	/// The public key corresponding to the key used to sign the invoice.
	pub fn signing_pubkey(&$self) -> PublicKey {
		$contents.signing_pubkey()
	}
} }

impl UnsignedBolt12Invoice {
	invoice_accessors!(self, self.contents);
}

impl Bolt12Invoice {
	invoice_accessors!(self, self.contents);

	/// Signature of the invoice verified using [`Bolt12Invoice::signing_pubkey`].
	pub fn signature(&self) -> Signature {
		self.signature
	}

	/// Hash that was used for signing the invoice.
	pub fn signable_hash(&self) -> [u8; 32] {
		merkle::message_digest(SIGNATURE_TAG, &self.bytes).as_ref().clone()
	}

	/// Verifies that the invoice was for a request or refund created using the given key.
	pub fn verify<T: secp256k1::Signing>(
		&self, key: &ExpandedKey, secp_ctx: &Secp256k1<T>
	) -> bool {
		self.contents.verify(TlvStream::new(&self.bytes), key, secp_ctx)
	}

	#[cfg(test)]
	pub(super) fn as_tlv_stream(&self) -> FullInvoiceTlvStreamRef {
		let (payer_tlv_stream, offer_tlv_stream, invoice_request_tlv_stream, invoice_tlv_stream) =
			self.contents.as_tlv_stream();
		let signature_tlv_stream = SignatureTlvStreamRef {
			signature: Some(&self.signature),
		};
		(payer_tlv_stream, offer_tlv_stream, invoice_request_tlv_stream, invoice_tlv_stream,
		 signature_tlv_stream)
	}
}

impl InvoiceContents {
	/// Whether the original offer or refund has expired.
	#[cfg(feature = "std")]
	fn is_offer_or_refund_expired(&self) -> bool {
		match self {
			InvoiceContents::ForOffer { invoice_request, .. } =>
				invoice_request.inner.offer.is_expired(),
			InvoiceContents::ForRefund { refund, .. } => refund.is_expired(),
		}
	}

	fn offer_chains(&self) -> Option<Vec<ChainHash>> {
		match self {
			InvoiceContents::ForOffer { invoice_request, .. } =>
				Some(invoice_request.inner.offer.chains()),
			InvoiceContents::ForRefund { .. } => None,
		}
	}

	fn chain(&self) -> ChainHash {
		match self {
			InvoiceContents::ForOffer { invoice_request, .. } => invoice_request.chain(),
			InvoiceContents::ForRefund { refund, .. } => refund.chain(),
		}
	}

	fn metadata(&self) -> Option<&Vec<u8>> {
		match self {
			InvoiceContents::ForOffer { invoice_request, .. } =>
				invoice_request.inner.offer.metadata(),
			InvoiceContents::ForRefund { .. } => None,
		}
	}

	fn amount(&self) -> Option<&Amount> {
		match self {
			InvoiceContents::ForOffer { invoice_request, .. } =>
				invoice_request.inner.offer.amount(),
			InvoiceContents::ForRefund { .. } => None,
		}
	}

	fn description(&self) -> PrintableString {
		match self {
			InvoiceContents::ForOffer { invoice_request, .. } => {
				invoice_request.inner.offer.description()
			},
			InvoiceContents::ForRefund { refund, .. } => refund.description(),
		}
	}

	fn offer_features(&self) -> Option<&OfferFeatures> {
		match self {
			InvoiceContents::ForOffer { invoice_request, .. } => {
				Some(invoice_request.inner.offer.features())
			},
			InvoiceContents::ForRefund { .. } => None,
		}
	}

	fn absolute_expiry(&self) -> Option<Duration> {
		match self {
			InvoiceContents::ForOffer { invoice_request, .. } => {
				invoice_request.inner.offer.absolute_expiry()
			},
			InvoiceContents::ForRefund { refund, .. } => refund.absolute_expiry(),
		}
	}

	fn issuer(&self) -> Option<PrintableString> {
		match self {
			InvoiceContents::ForOffer { invoice_request, .. } => {
				invoice_request.inner.offer.issuer()
			},
			InvoiceContents::ForRefund { refund, .. } => refund.issuer(),
		}
	}

	fn message_paths(&self) -> &[BlindedPath] {
		match self {
			InvoiceContents::ForOffer { invoice_request, .. } => {
				invoice_request.inner.offer.paths()
			},
			InvoiceContents::ForRefund { refund, .. } => refund.paths(),
		}
	}

	fn supported_quantity(&self) -> Option<Quantity> {
		match self {
			InvoiceContents::ForOffer { invoice_request, .. } => {
				Some(invoice_request.inner.offer.supported_quantity())
			},
			InvoiceContents::ForRefund { .. } => None,
		}
	}

	fn payer_metadata(&self) -> &[u8] {
		match self {
			InvoiceContents::ForOffer { invoice_request, .. } => invoice_request.metadata(),
			InvoiceContents::ForRefund { refund, .. } => refund.metadata(),
		}
	}

	fn invoice_request_features(&self) -> &InvoiceRequestFeatures {
		match self {
			InvoiceContents::ForOffer { invoice_request, .. } => invoice_request.features(),
			InvoiceContents::ForRefund { refund, .. } => refund.features(),
		}
	}

	fn quantity(&self) -> Option<u64> {
		match self {
			InvoiceContents::ForOffer { invoice_request, .. } => invoice_request.quantity(),
			InvoiceContents::ForRefund { refund, .. } => refund.quantity(),
		}
	}

	fn payer_id(&self) -> PublicKey {
		match self {
			InvoiceContents::ForOffer { invoice_request, .. } => invoice_request.payer_id(),
			InvoiceContents::ForRefund { refund, .. } => refund.payer_id(),
		}
	}

	fn payer_note(&self) -> Option<PrintableString> {
		match self {
			InvoiceContents::ForOffer { invoice_request, .. } => invoice_request.payer_note(),
			InvoiceContents::ForRefund { refund, .. } => refund.payer_note(),
		}
	}

	fn payment_paths(&self) -> &[(BlindedPayInfo, BlindedPath)] {
		&self.fields().payment_paths[..]
	}

	fn created_at(&self) -> Duration {
		self.fields().created_at
	}

	fn relative_expiry(&self) -> Duration {
		self.fields().relative_expiry.unwrap_or(DEFAULT_RELATIVE_EXPIRY)
	}

	#[cfg(feature = "std")]
	fn is_expired(&self) -> bool {
		let absolute_expiry = self.created_at().checked_add(self.relative_expiry());
		match absolute_expiry {
			Some(seconds_from_epoch) => match SystemTime::UNIX_EPOCH.elapsed() {
				Ok(elapsed) => elapsed > seconds_from_epoch,
				Err(_) => false,
			},
			None => false,
		}
	}

	fn payment_hash(&self) -> PaymentHash {
		self.fields().payment_hash
	}

	fn amount_msats(&self) -> u64 {
		self.fields().amount_msats
	}

	fn fallbacks(&self) -> Vec<Address> {
		let chain = self.chain();
		let network = if chain == ChainHash::using_genesis_block(Network::Bitcoin) {
			Network::Bitcoin
		} else if chain == ChainHash::using_genesis_block(Network::Testnet) {
			Network::Testnet
		} else if chain == ChainHash::using_genesis_block(Network::Signet) {
			Network::Signet
		} else if chain == ChainHash::using_genesis_block(Network::Regtest) {
			Network::Regtest
		} else {
			return Vec::new()
		};

		let to_valid_address = |address: &FallbackAddress| {
			let version = match WitnessVersion::try_from(address.version) {
				Ok(version) => version,
				Err(_) => return None,
			};

			let program = &address.program;
			if program.len() < 2 || program.len() > 40 {
				return None;
			}

			let address = Address {
				payload: Payload::WitnessProgram {
					version,
					program: program.clone(),
				},
				network,
			};

			if !address.is_standard() && version == WitnessVersion::V0 {
				return None;
			}

			Some(address)
		};

		self.fields().fallbacks
			.as_ref()
			.map(|fallbacks| fallbacks.iter().filter_map(to_valid_address).collect())
			.unwrap_or_else(Vec::new)
	}

	fn features(&self) -> &Bolt12InvoiceFeatures {
		&self.fields().features
	}

	fn signing_pubkey(&self) -> PublicKey {
		self.fields().signing_pubkey
	}

	fn fields(&self) -> &InvoiceFields {
		match self {
			InvoiceContents::ForOffer { fields, .. } => fields,
			InvoiceContents::ForRefund { fields, .. } => fields,
		}
	}

	fn fields_mut(&mut self) -> &mut InvoiceFields {
		match self {
			InvoiceContents::ForOffer { fields, .. } => fields,
			InvoiceContents::ForRefund { fields, .. } => fields,
		}
	}

	fn verify<T: secp256k1::Signing>(
		&self, tlv_stream: TlvStream<'_>, key: &ExpandedKey, secp_ctx: &Secp256k1<T>
	) -> bool {
		let offer_records = tlv_stream.clone().range(OFFER_TYPES);
		let invreq_records = tlv_stream.range(INVOICE_REQUEST_TYPES).filter(|record| {
			match record.r#type {
				PAYER_METADATA_TYPE => false, // Should be outside range
				INVOICE_REQUEST_PAYER_ID_TYPE => !self.derives_keys(),
				_ => true,
			}
		});
		let tlv_stream = offer_records.chain(invreq_records);

		let (metadata, payer_id, iv_bytes) = match self {
			InvoiceContents::ForOffer { invoice_request, .. } => {
				(invoice_request.metadata(), invoice_request.payer_id(), INVOICE_REQUEST_IV_BYTES)
			},
			InvoiceContents::ForRefund { refund, .. } => {
				(refund.metadata(), refund.payer_id(), REFUND_IV_BYTES)
			},
		};

		match signer::verify_metadata(metadata, key, iv_bytes, payer_id, tlv_stream, secp_ctx) {
			Ok(_) => true,
			Err(()) => false,
		}
	}

	fn derives_keys(&self) -> bool {
		match self {
			InvoiceContents::ForOffer { invoice_request, .. } => invoice_request.derives_keys(),
			InvoiceContents::ForRefund { refund, .. } => refund.derives_keys(),
		}
	}

	fn as_tlv_stream(&self) -> PartialInvoiceTlvStreamRef {
		let (payer, offer, invoice_request) = match self {
			InvoiceContents::ForOffer { invoice_request, .. } => invoice_request.as_tlv_stream(),
			InvoiceContents::ForRefund { refund, .. } => refund.as_tlv_stream(),
		};
		let invoice = self.fields().as_tlv_stream();

		(payer, offer, invoice_request, invoice)
	}
}

impl InvoiceFields {
	fn as_tlv_stream(&self) -> InvoiceTlvStreamRef {
		let features = {
			if self.features == Bolt12InvoiceFeatures::empty() { None }
			else { Some(&self.features) }
		};

		InvoiceTlvStreamRef {
			paths: Some(Iterable(self.payment_paths.iter().map(|(_, path)| path))),
			blindedpay: Some(Iterable(self.payment_paths.iter().map(|(payinfo, _)| payinfo))),
			created_at: Some(self.created_at.as_secs()),
			relative_expiry: self.relative_expiry.map(|duration| duration.as_secs() as u32),
			payment_hash: Some(&self.payment_hash),
			amount: Some(self.amount_msats),
			fallbacks: self.fallbacks.as_ref(),
			features,
			node_id: Some(&self.signing_pubkey),
		}
	}
}

impl Writeable for UnsignedBolt12Invoice {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		WithoutLength(&self.bytes).write(writer)
	}
}

impl Writeable for Bolt12Invoice {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		WithoutLength(&self.bytes).write(writer)
	}
}

impl Writeable for InvoiceContents {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		self.as_tlv_stream().write(writer)
	}
}

impl TryFrom<Vec<u8>> for UnsignedBolt12Invoice {
	type Error = Bolt12ParseError;

	fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
		let invoice = ParsedMessage::<PartialInvoiceTlvStream>::try_from(bytes)?;
		let ParsedMessage { bytes, tlv_stream } = invoice;
		let (
			payer_tlv_stream, offer_tlv_stream, invoice_request_tlv_stream, invoice_tlv_stream,
		) = tlv_stream;
		let contents = InvoiceContents::try_from(
			(payer_tlv_stream, offer_tlv_stream, invoice_request_tlv_stream, invoice_tlv_stream)
		)?;

		let tagged_hash = TaggedHash::new(SIGNATURE_TAG, &bytes);

		Ok(UnsignedBolt12Invoice { bytes, contents, tagged_hash })
	}
}

impl TryFrom<Vec<u8>> for Bolt12Invoice {
	type Error = Bolt12ParseError;

	fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
		let parsed_invoice = ParsedMessage::<FullInvoiceTlvStream>::try_from(bytes)?;
		Bolt12Invoice::try_from(parsed_invoice)
	}
}

tlv_stream!(InvoiceTlvStream, InvoiceTlvStreamRef, 160..240, {
	(160, paths: (Vec<BlindedPath>, WithoutLength, Iterable<'a, BlindedPathIter<'a>, BlindedPath>)),
	(162, blindedpay: (Vec<BlindedPayInfo>, WithoutLength, Iterable<'a, BlindedPayInfoIter<'a>, BlindedPayInfo>)),
	(164, created_at: (u64, HighZeroBytesDroppedBigSize)),
	(166, relative_expiry: (u32, HighZeroBytesDroppedBigSize)),
	(168, payment_hash: PaymentHash),
	(170, amount: (u64, HighZeroBytesDroppedBigSize)),
	(172, fallbacks: (Vec<FallbackAddress>, WithoutLength)),
	(174, features: (Bolt12InvoiceFeatures, WithoutLength)),
	(176, node_id: PublicKey),
});

type BlindedPathIter<'a> = core::iter::Map<
	core::slice::Iter<'a, (BlindedPayInfo, BlindedPath)>,
	for<'r> fn(&'r (BlindedPayInfo, BlindedPath)) -> &'r BlindedPath,
>;

type BlindedPayInfoIter<'a> = core::iter::Map<
	core::slice::Iter<'a, (BlindedPayInfo, BlindedPath)>,
	for<'r> fn(&'r (BlindedPayInfo, BlindedPath)) -> &'r BlindedPayInfo,
>;

/// Information needed to route a payment across a [`BlindedPath`].
#[derive(Clone, Debug, Hash, Eq, PartialEq)]
pub struct BlindedPayInfo {
	/// Base fee charged (in millisatoshi) for the entire blinded path.
	pub fee_base_msat: u32,

	/// Liquidity fee charged (in millionths of the amount transferred) for the entire blinded path
	/// (i.e., 10,000 is 1%).
	pub fee_proportional_millionths: u32,

	/// Number of blocks subtracted from an incoming HTLC's `cltv_expiry` for the entire blinded
	/// path.
	pub cltv_expiry_delta: u16,

	/// The minimum HTLC value (in millisatoshi) that is acceptable to all channel peers on the
	/// blinded path from the introduction node to the recipient, accounting for any fees, i.e., as
	/// seen by the recipient.
	pub htlc_minimum_msat: u64,

	/// The maximum HTLC value (in millisatoshi) that is acceptable to all channel peers on the
	/// blinded path from the introduction node to the recipient, accounting for any fees, i.e., as
	/// seen by the recipient.
	pub htlc_maximum_msat: u64,

	/// Features set in `encrypted_data_tlv` for the `encrypted_recipient_data` TLV record in an
	/// onion payload.
	pub features: BlindedHopFeatures,
}

impl_writeable!(BlindedPayInfo, {
	fee_base_msat,
	fee_proportional_millionths,
	cltv_expiry_delta,
	htlc_minimum_msat,
	htlc_maximum_msat,
	features
});

/// Wire representation for an on-chain fallback address.
#[derive(Clone, Debug, PartialEq)]
pub(super) struct FallbackAddress {
	version: u8,
	program: Vec<u8>,
}

impl_writeable!(FallbackAddress, { version, program });

type FullInvoiceTlvStream =
	(PayerTlvStream, OfferTlvStream, InvoiceRequestTlvStream, InvoiceTlvStream, SignatureTlvStream);

#[cfg(test)]
type FullInvoiceTlvStreamRef<'a> = (
	PayerTlvStreamRef<'a>,
	OfferTlvStreamRef<'a>,
	InvoiceRequestTlvStreamRef<'a>,
	InvoiceTlvStreamRef<'a>,
	SignatureTlvStreamRef<'a>,
);

impl SeekReadable for FullInvoiceTlvStream {
	fn read<R: io::Read + io::Seek>(r: &mut R) -> Result<Self, DecodeError> {
		let payer = SeekReadable::read(r)?;
		let offer = SeekReadable::read(r)?;
		let invoice_request = SeekReadable::read(r)?;
		let invoice = SeekReadable::read(r)?;
		let signature = SeekReadable::read(r)?;

		Ok((payer, offer, invoice_request, invoice, signature))
	}
}

type PartialInvoiceTlvStream =
	(PayerTlvStream, OfferTlvStream, InvoiceRequestTlvStream, InvoiceTlvStream);

type PartialInvoiceTlvStreamRef<'a> = (
	PayerTlvStreamRef<'a>,
	OfferTlvStreamRef<'a>,
	InvoiceRequestTlvStreamRef<'a>,
	InvoiceTlvStreamRef<'a>,
);

impl SeekReadable for PartialInvoiceTlvStream {
	fn read<R: io::Read + io::Seek>(r: &mut R) -> Result<Self, DecodeError> {
		let payer = SeekReadable::read(r)?;
		let offer = SeekReadable::read(r)?;
		let invoice_request = SeekReadable::read(r)?;
		let invoice = SeekReadable::read(r)?;

		Ok((payer, offer, invoice_request, invoice))
	}
}

impl TryFrom<ParsedMessage<FullInvoiceTlvStream>> for Bolt12Invoice {
	type Error = Bolt12ParseError;

	fn try_from(invoice: ParsedMessage<FullInvoiceTlvStream>) -> Result<Self, Self::Error> {
		let ParsedMessage { bytes, tlv_stream } = invoice;
		let (
			payer_tlv_stream, offer_tlv_stream, invoice_request_tlv_stream, invoice_tlv_stream,
			SignatureTlvStream { signature },
		) = tlv_stream;
		let contents = InvoiceContents::try_from(
			(payer_tlv_stream, offer_tlv_stream, invoice_request_tlv_stream, invoice_tlv_stream)
		)?;

		let signature = match signature {
			None => return Err(Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::MissingSignature)),
			Some(signature) => signature,
		};
		let message = TaggedHash::new(SIGNATURE_TAG, &bytes);
		let pubkey = contents.fields().signing_pubkey;
		merkle::verify_signature(&signature, message, pubkey)?;

		Ok(Bolt12Invoice { bytes, contents, signature })
	}
}

impl TryFrom<PartialInvoiceTlvStream> for InvoiceContents {
	type Error = Bolt12SemanticError;

	fn try_from(tlv_stream: PartialInvoiceTlvStream) -> Result<Self, Self::Error> {
		let (
			payer_tlv_stream,
			offer_tlv_stream,
			invoice_request_tlv_stream,
			InvoiceTlvStream {
				paths, blindedpay, created_at, relative_expiry, payment_hash, amount, fallbacks,
				features, node_id,
			},
		) = tlv_stream;

		let payment_paths = match (blindedpay, paths) {
			(_, None) => return Err(Bolt12SemanticError::MissingPaths),
			(None, _) => return Err(Bolt12SemanticError::InvalidPayInfo),
			(_, Some(paths)) if paths.is_empty() => return Err(Bolt12SemanticError::MissingPaths),
			(Some(blindedpay), Some(paths)) if paths.len() != blindedpay.len() => {
				return Err(Bolt12SemanticError::InvalidPayInfo);
			},
			(Some(blindedpay), Some(paths)) => {
				blindedpay.into_iter().zip(paths.into_iter()).collect::<Vec<_>>()
			},
		};

		let created_at = match created_at {
			None => return Err(Bolt12SemanticError::MissingCreationTime),
			Some(timestamp) => Duration::from_secs(timestamp),
		};

		let relative_expiry = relative_expiry
			.map(Into::<u64>::into)
			.map(Duration::from_secs);

		let payment_hash = match payment_hash {
			None => return Err(Bolt12SemanticError::MissingPaymentHash),
			Some(payment_hash) => payment_hash,
		};

		let amount_msats = match amount {
			None => return Err(Bolt12SemanticError::MissingAmount),
			Some(amount) => amount,
		};

		let features = features.unwrap_or_else(Bolt12InvoiceFeatures::empty);

		let signing_pubkey = match node_id {
			None => return Err(Bolt12SemanticError::MissingSigningPubkey),
			Some(node_id) => node_id,
		};

		let fields = InvoiceFields {
			payment_paths, created_at, relative_expiry, payment_hash, amount_msats, fallbacks,
			features, signing_pubkey,
		};

		match offer_tlv_stream.node_id {
			Some(expected_signing_pubkey) => {
				if fields.signing_pubkey != expected_signing_pubkey {
					return Err(Bolt12SemanticError::InvalidSigningPubkey);
				}

				let invoice_request = InvoiceRequestContents::try_from(
					(payer_tlv_stream, offer_tlv_stream, invoice_request_tlv_stream)
				)?;
				Ok(InvoiceContents::ForOffer { invoice_request, fields })
			},
			None => {
				let refund = RefundContents::try_from(
					(payer_tlv_stream, offer_tlv_stream, invoice_request_tlv_stream)
				)?;
				Ok(InvoiceContents::ForRefund { refund, fields })
			},
		}
	}
}

#[cfg(test)]
mod tests {
	use super::{Bolt12Invoice, DEFAULT_RELATIVE_EXPIRY, FallbackAddress, FullInvoiceTlvStreamRef, InvoiceTlvStreamRef, SIGNATURE_TAG, UnsignedBolt12Invoice};

	use bitcoin::blockdata::constants::ChainHash;
	use bitcoin::blockdata::script::Script;
	use bitcoin::hashes::Hash;
	use bitcoin::network::constants::Network;
	use bitcoin::secp256k1::{Message, Secp256k1, XOnlyPublicKey, self};
	use bitcoin::util::address::{Address, Payload, WitnessVersion};
	use bitcoin::util::schnorr::TweakedPublicKey;
	use core::convert::TryFrom;
	use core::time::Duration;
	use crate::blinded_path::{BlindedHop, BlindedPath};
	use crate::sign::KeyMaterial;
	use crate::ln::features::{Bolt12InvoiceFeatures, InvoiceRequestFeatures, OfferFeatures};
	use crate::ln::inbound_payment::ExpandedKey;
	use crate::ln::msgs::DecodeError;
	use crate::offers::invoice_request::InvoiceRequestTlvStreamRef;
	use crate::offers::merkle::{SignError, SignatureTlvStreamRef, TaggedHash, self};
	use crate::offers::offer::{Amount, OfferBuilder, OfferTlvStreamRef, Quantity};
	use crate::offers::parse::{Bolt12ParseError, Bolt12SemanticError};
	use crate::offers::payer::PayerTlvStreamRef;
	use crate::offers::refund::RefundBuilder;
	use crate::offers::test_utils::*;
	use crate::util::ser::{BigSize, Iterable, Writeable};
	use crate::util::string::PrintableString;

	trait ToBytes {
		fn to_bytes(&self) -> Vec<u8>;
	}

	impl<'a> ToBytes for FullInvoiceTlvStreamRef<'a> {
		fn to_bytes(&self) -> Vec<u8> {
			let mut buffer = Vec::new();
			self.0.write(&mut buffer).unwrap();
			self.1.write(&mut buffer).unwrap();
			self.2.write(&mut buffer).unwrap();
			self.3.write(&mut buffer).unwrap();
			self.4.write(&mut buffer).unwrap();
			buffer
		}
	}

	#[test]
	fn builds_invoice_for_offer_with_defaults() {
		let payment_paths = payment_paths();
		let payment_hash = payment_hash();
		let now = now();
		let unsigned_invoice = OfferBuilder::new("foo".into(), recipient_pubkey())
			.amount_msats(1000)
			.build().unwrap()
			.request_invoice(vec![1; 32], payer_pubkey()).unwrap()
			.build().unwrap()
			.sign(payer_sign).unwrap()
			.respond_with_no_std(payment_paths.clone(), payment_hash, now).unwrap()
			.build().unwrap();

		let mut buffer = Vec::new();
		unsigned_invoice.write(&mut buffer).unwrap();

		assert_eq!(unsigned_invoice.bytes, buffer.as_slice());
		assert_eq!(unsigned_invoice.payer_metadata(), &[1; 32]);
		assert_eq!(unsigned_invoice.offer_chains(), Some(vec![ChainHash::using_genesis_block(Network::Bitcoin)]));
		assert_eq!(unsigned_invoice.metadata(), None);
		assert_eq!(unsigned_invoice.amount(), Some(&Amount::Bitcoin { amount_msats: 1000 }));
		assert_eq!(unsigned_invoice.description(), PrintableString("foo"));
		assert_eq!(unsigned_invoice.offer_features(), Some(&OfferFeatures::empty()));
		assert_eq!(unsigned_invoice.absolute_expiry(), None);
		assert_eq!(unsigned_invoice.message_paths(), &[]);
		assert_eq!(unsigned_invoice.issuer(), None);
		assert_eq!(unsigned_invoice.supported_quantity(), Some(Quantity::One));
		assert_eq!(unsigned_invoice.signing_pubkey(), recipient_pubkey());
		assert_eq!(unsigned_invoice.chain(), ChainHash::using_genesis_block(Network::Bitcoin));
		assert_eq!(unsigned_invoice.amount_msats(), 1000);
		assert_eq!(unsigned_invoice.invoice_request_features(), &InvoiceRequestFeatures::empty());
		assert_eq!(unsigned_invoice.quantity(), None);
		assert_eq!(unsigned_invoice.payer_id(), payer_pubkey());
		assert_eq!(unsigned_invoice.payer_note(), None);
		assert_eq!(unsigned_invoice.payment_paths(), payment_paths.as_slice());
		assert_eq!(unsigned_invoice.created_at(), now);
		assert_eq!(unsigned_invoice.relative_expiry(), DEFAULT_RELATIVE_EXPIRY);
		#[cfg(feature = "std")]
		assert!(!unsigned_invoice.is_expired());
		assert_eq!(unsigned_invoice.payment_hash(), payment_hash);
		assert_eq!(unsigned_invoice.amount_msats(), 1000);
		assert_eq!(unsigned_invoice.fallbacks(), vec![]);
		assert_eq!(unsigned_invoice.invoice_features(), &Bolt12InvoiceFeatures::empty());
		assert_eq!(unsigned_invoice.signing_pubkey(), recipient_pubkey());

		match UnsignedBolt12Invoice::try_from(buffer) {
			Err(e) => panic!("error parsing unsigned invoice: {:?}", e),
			Ok(parsed) => {
				assert_eq!(parsed.bytes, unsigned_invoice.bytes);
				assert_eq!(parsed.tagged_hash, unsigned_invoice.tagged_hash);
			},
		}

		let invoice = unsigned_invoice.sign(recipient_sign).unwrap();

		let mut buffer = Vec::new();
		invoice.write(&mut buffer).unwrap();

		assert_eq!(invoice.bytes, buffer.as_slice());
		assert_eq!(invoice.payer_metadata(), &[1; 32]);
		assert_eq!(invoice.offer_chains(), Some(vec![ChainHash::using_genesis_block(Network::Bitcoin)]));
		assert_eq!(invoice.metadata(), None);
		assert_eq!(invoice.amount(), Some(&Amount::Bitcoin { amount_msats: 1000 }));
		assert_eq!(invoice.description(), PrintableString("foo"));
		assert_eq!(invoice.offer_features(), Some(&OfferFeatures::empty()));
		assert_eq!(invoice.absolute_expiry(), None);
		assert_eq!(invoice.message_paths(), &[]);
		assert_eq!(invoice.issuer(), None);
		assert_eq!(invoice.supported_quantity(), Some(Quantity::One));
		assert_eq!(invoice.signing_pubkey(), recipient_pubkey());
		assert_eq!(invoice.chain(), ChainHash::using_genesis_block(Network::Bitcoin));
		assert_eq!(invoice.amount_msats(), 1000);
		assert_eq!(invoice.invoice_request_features(), &InvoiceRequestFeatures::empty());
		assert_eq!(invoice.quantity(), None);
		assert_eq!(invoice.payer_id(), payer_pubkey());
		assert_eq!(invoice.payer_note(), None);
		assert_eq!(invoice.payment_paths(), payment_paths.as_slice());
		assert_eq!(invoice.created_at(), now);
		assert_eq!(invoice.relative_expiry(), DEFAULT_RELATIVE_EXPIRY);
		#[cfg(feature = "std")]
		assert!(!invoice.is_expired());
		assert_eq!(invoice.payment_hash(), payment_hash);
		assert_eq!(invoice.amount_msats(), 1000);
		assert_eq!(invoice.fallbacks(), vec![]);
		assert_eq!(invoice.invoice_features(), &Bolt12InvoiceFeatures::empty());
		assert_eq!(invoice.signing_pubkey(), recipient_pubkey());

		let message = TaggedHash::new(SIGNATURE_TAG, &invoice.bytes);
		assert!(merkle::verify_signature(&invoice.signature, message, recipient_pubkey()).is_ok());

		let digest = Message::from_slice(&invoice.signable_hash()).unwrap();
		let pubkey = recipient_pubkey().into();
		let secp_ctx = Secp256k1::verification_only();
		assert!(secp_ctx.verify_schnorr(&invoice.signature, &digest, &pubkey).is_ok());

		assert_eq!(
			invoice.as_tlv_stream(),
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
				InvoiceTlvStreamRef {
					paths: Some(Iterable(payment_paths.iter().map(|(_, path)| path))),
					blindedpay: Some(Iterable(payment_paths.iter().map(|(payinfo, _)| payinfo))),
					created_at: Some(now.as_secs()),
					relative_expiry: None,
					payment_hash: Some(&payment_hash),
					amount: Some(1000),
					fallbacks: None,
					features: None,
					node_id: Some(&recipient_pubkey()),
				},
				SignatureTlvStreamRef { signature: Some(&invoice.signature()) },
			),
		);

		if let Err(e) = Bolt12Invoice::try_from(buffer) {
			panic!("error parsing invoice: {:?}", e);
		}
	}

	#[test]
	fn builds_invoice_for_refund_with_defaults() {
		let payment_paths = payment_paths();
		let payment_hash = payment_hash();
		let now = now();
		let invoice = RefundBuilder::new("foo".into(), vec![1; 32], payer_pubkey(), 1000).unwrap()
			.build().unwrap()
			.respond_with_no_std(payment_paths.clone(), payment_hash, recipient_pubkey(), now)
			.unwrap()
			.build().unwrap()
			.sign(recipient_sign).unwrap();

		let mut buffer = Vec::new();
		invoice.write(&mut buffer).unwrap();

		assert_eq!(invoice.bytes, buffer.as_slice());
		assert_eq!(invoice.payer_metadata(), &[1; 32]);
		assert_eq!(invoice.offer_chains(), None);
		assert_eq!(invoice.metadata(), None);
		assert_eq!(invoice.amount(), None);
		assert_eq!(invoice.description(), PrintableString("foo"));
		assert_eq!(invoice.offer_features(), None);
		assert_eq!(invoice.absolute_expiry(), None);
		assert_eq!(invoice.message_paths(), &[]);
		assert_eq!(invoice.issuer(), None);
		assert_eq!(invoice.supported_quantity(), None);
		assert_eq!(invoice.signing_pubkey(), recipient_pubkey());
		assert_eq!(invoice.chain(), ChainHash::using_genesis_block(Network::Bitcoin));
		assert_eq!(invoice.amount_msats(), 1000);
		assert_eq!(invoice.invoice_request_features(), &InvoiceRequestFeatures::empty());
		assert_eq!(invoice.quantity(), None);
		assert_eq!(invoice.payer_id(), payer_pubkey());
		assert_eq!(invoice.payer_note(), None);
		assert_eq!(invoice.payment_paths(), payment_paths.as_slice());
		assert_eq!(invoice.created_at(), now);
		assert_eq!(invoice.relative_expiry(), DEFAULT_RELATIVE_EXPIRY);
		#[cfg(feature = "std")]
		assert!(!invoice.is_expired());
		assert_eq!(invoice.payment_hash(), payment_hash);
		assert_eq!(invoice.amount_msats(), 1000);
		assert_eq!(invoice.fallbacks(), vec![]);
		assert_eq!(invoice.invoice_features(), &Bolt12InvoiceFeatures::empty());
		assert_eq!(invoice.signing_pubkey(), recipient_pubkey());

		let message = TaggedHash::new(SIGNATURE_TAG, &invoice.bytes);
		assert!(merkle::verify_signature(&invoice.signature, message, recipient_pubkey()).is_ok());

		assert_eq!(
			invoice.as_tlv_stream(),
			(
				PayerTlvStreamRef { metadata: Some(&vec![1; 32]) },
				OfferTlvStreamRef {
					chains: None,
					metadata: None,
					currency: None,
					amount: None,
					description: Some(&String::from("foo")),
					features: None,
					absolute_expiry: None,
					paths: None,
					issuer: None,
					quantity_max: None,
					node_id: None,
				},
				InvoiceRequestTlvStreamRef {
					chain: None,
					amount: Some(1000),
					features: None,
					quantity: None,
					payer_id: Some(&payer_pubkey()),
					payer_note: None,
				},
				InvoiceTlvStreamRef {
					paths: Some(Iterable(payment_paths.iter().map(|(_, path)| path))),
					blindedpay: Some(Iterable(payment_paths.iter().map(|(payinfo, _)| payinfo))),
					created_at: Some(now.as_secs()),
					relative_expiry: None,
					payment_hash: Some(&payment_hash),
					amount: Some(1000),
					fallbacks: None,
					features: None,
					node_id: Some(&recipient_pubkey()),
				},
				SignatureTlvStreamRef { signature: Some(&invoice.signature()) },
			),
		);

		if let Err(e) = Bolt12Invoice::try_from(buffer) {
			panic!("error parsing invoice: {:?}", e);
		}
	}

	#[cfg(feature = "std")]
	#[test]
	fn builds_invoice_from_offer_with_expiration() {
		let future_expiry = Duration::from_secs(u64::max_value());
		let past_expiry = Duration::from_secs(0);

		if let Err(e) = OfferBuilder::new("foo".into(), recipient_pubkey())
			.amount_msats(1000)
			.absolute_expiry(future_expiry)
			.build().unwrap()
			.request_invoice(vec![1; 32], payer_pubkey()).unwrap()
			.build().unwrap()
			.sign(payer_sign).unwrap()
			.respond_with(payment_paths(), payment_hash())
			.unwrap()
			.build()
		{
			panic!("error building invoice: {:?}", e);
		}

		match OfferBuilder::new("foo".into(), recipient_pubkey())
			.amount_msats(1000)
			.absolute_expiry(past_expiry)
			.build().unwrap()
			.request_invoice(vec![1; 32], payer_pubkey()).unwrap()
			.build_unchecked()
			.sign(payer_sign).unwrap()
			.respond_with(payment_paths(), payment_hash())
			.unwrap()
			.build()
		{
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, Bolt12SemanticError::AlreadyExpired),
		}
	}

	#[cfg(feature = "std")]
	#[test]
	fn builds_invoice_from_refund_with_expiration() {
		let future_expiry = Duration::from_secs(u64::max_value());
		let past_expiry = Duration::from_secs(0);

		if let Err(e) = RefundBuilder::new("foo".into(), vec![1; 32], payer_pubkey(), 1000).unwrap()
			.absolute_expiry(future_expiry)
			.build().unwrap()
			.respond_with(payment_paths(), payment_hash(), recipient_pubkey())
			.unwrap()
			.build()
		{
			panic!("error building invoice: {:?}", e);
		}

		match RefundBuilder::new("foo".into(), vec![1; 32], payer_pubkey(), 1000).unwrap()
			.absolute_expiry(past_expiry)
			.build().unwrap()
			.respond_with(payment_paths(), payment_hash(), recipient_pubkey())
			.unwrap()
			.build()
		{
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, Bolt12SemanticError::AlreadyExpired),
		}
	}

	#[test]
	fn builds_invoice_from_offer_using_derived_keys() {
		let desc = "foo".to_string();
		let node_id = recipient_pubkey();
		let expanded_key = ExpandedKey::new(&KeyMaterial([42; 32]));
		let entropy = FixedEntropy {};
		let secp_ctx = Secp256k1::new();

		let blinded_path = BlindedPath {
			introduction_node_id: pubkey(40),
			blinding_point: pubkey(41),
			blinded_hops: vec![
				BlindedHop { blinded_node_id: pubkey(42), encrypted_payload: vec![0; 43] },
				BlindedHop { blinded_node_id: node_id, encrypted_payload: vec![0; 44] },
			],
		};

		let offer = OfferBuilder
			::deriving_signing_pubkey(desc, node_id, &expanded_key, &entropy, &secp_ctx)
			.amount_msats(1000)
			.path(blinded_path)
			.build().unwrap();
		let invoice_request = offer.request_invoice(vec![1; 32], payer_pubkey()).unwrap()
			.build().unwrap()
			.sign(payer_sign).unwrap();

		if let Err(e) = invoice_request
			.verify_and_respond_using_derived_keys_no_std(
				payment_paths(), payment_hash(), now(), &expanded_key, &secp_ctx
			)
			.unwrap()
			.build_and_sign(&secp_ctx)
		{
			panic!("error building invoice: {:?}", e);
		}

		let expanded_key = ExpandedKey::new(&KeyMaterial([41; 32]));
		match invoice_request.verify_and_respond_using_derived_keys_no_std(
			payment_paths(), payment_hash(), now(), &expanded_key, &secp_ctx
		) {
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, Bolt12SemanticError::InvalidMetadata),
		}

		let desc = "foo".to_string();
		let offer = OfferBuilder
			::deriving_signing_pubkey(desc, node_id, &expanded_key, &entropy, &secp_ctx)
			.amount_msats(1000)
			.build().unwrap();
		let invoice_request = offer.request_invoice(vec![1; 32], payer_pubkey()).unwrap()
			.build().unwrap()
			.sign(payer_sign).unwrap();

		match invoice_request.verify_and_respond_using_derived_keys_no_std(
			payment_paths(), payment_hash(), now(), &expanded_key, &secp_ctx
		) {
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, Bolt12SemanticError::InvalidMetadata),
		}
	}

	#[test]
	fn builds_invoice_from_refund_using_derived_keys() {
		let expanded_key = ExpandedKey::new(&KeyMaterial([42; 32]));
		let entropy = FixedEntropy {};
		let secp_ctx = Secp256k1::new();

		let refund = RefundBuilder::new("foo".into(), vec![1; 32], payer_pubkey(), 1000).unwrap()
			.build().unwrap();

		if let Err(e) = refund
			.respond_using_derived_keys_no_std(
				payment_paths(), payment_hash(), now(), &expanded_key, &entropy
			)
			.unwrap()
			.build_and_sign(&secp_ctx)
		{
			panic!("error building invoice: {:?}", e);
		}
	}

	#[test]
	fn builds_invoice_with_relative_expiry() {
		let now = now();
		let one_hour = Duration::from_secs(3600);

		let invoice = OfferBuilder::new("foo".into(), recipient_pubkey())
			.amount_msats(1000)
			.build().unwrap()
			.request_invoice(vec![1; 32], payer_pubkey()).unwrap()
			.build().unwrap()
			.sign(payer_sign).unwrap()
			.respond_with_no_std(payment_paths(), payment_hash(), now).unwrap()
			.relative_expiry(one_hour.as_secs() as u32)
			.build().unwrap()
			.sign(recipient_sign).unwrap();
		let (_, _, _, tlv_stream, _) = invoice.as_tlv_stream();
		#[cfg(feature = "std")]
		assert!(!invoice.is_expired());
		assert_eq!(invoice.relative_expiry(), one_hour);
		assert_eq!(tlv_stream.relative_expiry, Some(one_hour.as_secs() as u32));

		let invoice = OfferBuilder::new("foo".into(), recipient_pubkey())
			.amount_msats(1000)
			.build().unwrap()
			.request_invoice(vec![1; 32], payer_pubkey()).unwrap()
			.build().unwrap()
			.sign(payer_sign).unwrap()
			.respond_with_no_std(payment_paths(), payment_hash(), now - one_hour).unwrap()
			.relative_expiry(one_hour.as_secs() as u32 - 1)
			.build().unwrap()
			.sign(recipient_sign).unwrap();
		let (_, _, _, tlv_stream, _) = invoice.as_tlv_stream();
		#[cfg(feature = "std")]
		assert!(invoice.is_expired());
		assert_eq!(invoice.relative_expiry(), one_hour - Duration::from_secs(1));
		assert_eq!(tlv_stream.relative_expiry, Some(one_hour.as_secs() as u32 - 1));
	}

	#[test]
	fn builds_invoice_with_amount_from_request() {
		let invoice = OfferBuilder::new("foo".into(), recipient_pubkey())
			.amount_msats(1000)
			.build().unwrap()
			.request_invoice(vec![1; 32], payer_pubkey()).unwrap()
			.amount_msats(1001).unwrap()
			.build().unwrap()
			.sign(payer_sign).unwrap()
			.respond_with_no_std(payment_paths(), payment_hash(), now()).unwrap()
			.build().unwrap()
			.sign(recipient_sign).unwrap();
		let (_, _, _, tlv_stream, _) = invoice.as_tlv_stream();
		assert_eq!(invoice.amount_msats(), 1001);
		assert_eq!(tlv_stream.amount, Some(1001));
	}

	#[test]
	fn builds_invoice_with_quantity_from_request() {
		let invoice = OfferBuilder::new("foo".into(), recipient_pubkey())
			.amount_msats(1000)
			.supported_quantity(Quantity::Unbounded)
			.build().unwrap()
			.request_invoice(vec![1; 32], payer_pubkey()).unwrap()
			.quantity(2).unwrap()
			.build().unwrap()
			.sign(payer_sign).unwrap()
			.respond_with_no_std(payment_paths(), payment_hash(), now()).unwrap()
			.build().unwrap()
			.sign(recipient_sign).unwrap();
		let (_, _, _, tlv_stream, _) = invoice.as_tlv_stream();
		assert_eq!(invoice.amount_msats(), 2000);
		assert_eq!(tlv_stream.amount, Some(2000));

		match OfferBuilder::new("foo".into(), recipient_pubkey())
			.amount_msats(1000)
			.supported_quantity(Quantity::Unbounded)
			.build().unwrap()
			.request_invoice(vec![1; 32], payer_pubkey()).unwrap()
			.quantity(u64::max_value()).unwrap()
			.build_unchecked()
			.sign(payer_sign).unwrap()
			.respond_with_no_std(payment_paths(), payment_hash(), now())
		{
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, Bolt12SemanticError::InvalidAmount),
		}
	}

	#[test]
	fn builds_invoice_with_fallback_address() {
		let script = Script::new();
		let pubkey = bitcoin::util::key::PublicKey::new(recipient_pubkey());
		let x_only_pubkey = XOnlyPublicKey::from_keypair(&recipient_keys()).0;
		let tweaked_pubkey = TweakedPublicKey::dangerous_assume_tweaked(x_only_pubkey);

		let invoice = OfferBuilder::new("foo".into(), recipient_pubkey())
			.amount_msats(1000)
			.build().unwrap()
			.request_invoice(vec![1; 32], payer_pubkey()).unwrap()
			.build().unwrap()
			.sign(payer_sign).unwrap()
			.respond_with_no_std(payment_paths(), payment_hash(), now()).unwrap()
			.fallback_v0_p2wsh(&script.wscript_hash())
			.fallback_v0_p2wpkh(&pubkey.wpubkey_hash().unwrap())
			.fallback_v1_p2tr_tweaked(&tweaked_pubkey)
			.build().unwrap()
			.sign(recipient_sign).unwrap();
		let (_, _, _, tlv_stream, _) = invoice.as_tlv_stream();
		assert_eq!(
			invoice.fallbacks(),
			vec![
				Address::p2wsh(&script, Network::Bitcoin),
				Address::p2wpkh(&pubkey, Network::Bitcoin).unwrap(),
				Address::p2tr_tweaked(tweaked_pubkey, Network::Bitcoin),
			],
		);
		assert_eq!(
			tlv_stream.fallbacks,
			Some(&vec![
				FallbackAddress {
					version: WitnessVersion::V0.to_num(),
					program: Vec::from(&script.wscript_hash().into_inner()[..]),
				},
				FallbackAddress {
					version: WitnessVersion::V0.to_num(),
					program: Vec::from(&pubkey.wpubkey_hash().unwrap().into_inner()[..]),
				},
				FallbackAddress {
					version: WitnessVersion::V1.to_num(),
					program: Vec::from(&tweaked_pubkey.serialize()[..]),
				},
			])
		);
	}

	#[test]
	fn builds_invoice_with_allow_mpp() {
		let mut features = Bolt12InvoiceFeatures::empty();
		features.set_basic_mpp_optional();

		let invoice = OfferBuilder::new("foo".into(), recipient_pubkey())
			.amount_msats(1000)
			.build().unwrap()
			.request_invoice(vec![1; 32], payer_pubkey()).unwrap()
			.build().unwrap()
			.sign(payer_sign).unwrap()
			.respond_with_no_std(payment_paths(), payment_hash(), now()).unwrap()
			.allow_mpp()
			.build().unwrap()
			.sign(recipient_sign).unwrap();
		let (_, _, _, tlv_stream, _) = invoice.as_tlv_stream();
		assert_eq!(invoice.invoice_features(), &features);
		assert_eq!(tlv_stream.features, Some(&features));
	}

	#[test]
	fn fails_signing_invoice() {
		match OfferBuilder::new("foo".into(), recipient_pubkey())
			.amount_msats(1000)
			.build().unwrap()
			.request_invoice(vec![1; 32], payer_pubkey()).unwrap()
			.build().unwrap()
			.sign(payer_sign).unwrap()
			.respond_with_no_std(payment_paths(), payment_hash(), now()).unwrap()
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
			.sign(payer_sign).unwrap()
			.respond_with_no_std(payment_paths(), payment_hash(), now()).unwrap()
			.build().unwrap()
			.sign(payer_sign)
		{
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, SignError::Verification(secp256k1::Error::InvalidSignature)),
		}
	}

	#[test]
	fn parses_invoice_with_payment_paths() {
		let invoice = OfferBuilder::new("foo".into(), recipient_pubkey())
			.amount_msats(1000)
			.build().unwrap()
			.request_invoice(vec![1; 32], payer_pubkey()).unwrap()
			.build().unwrap()
			.sign(payer_sign).unwrap()
			.respond_with_no_std(payment_paths(), payment_hash(), now()).unwrap()
			.build().unwrap()
			.sign(recipient_sign).unwrap();

		let mut buffer = Vec::new();
		invoice.write(&mut buffer).unwrap();

		if let Err(e) = Bolt12Invoice::try_from(buffer) {
			panic!("error parsing invoice: {:?}", e);
		}

		let mut tlv_stream = invoice.as_tlv_stream();
		tlv_stream.3.paths = None;

		match Bolt12Invoice::try_from(tlv_stream.to_bytes()) {
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::MissingPaths)),
		}

		let mut tlv_stream = invoice.as_tlv_stream();
		tlv_stream.3.blindedpay = None;

		match Bolt12Invoice::try_from(tlv_stream.to_bytes()) {
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::InvalidPayInfo)),
		}

		let empty_payment_paths = vec![];
		let mut tlv_stream = invoice.as_tlv_stream();
		tlv_stream.3.paths = Some(Iterable(empty_payment_paths.iter().map(|(_, path)| path)));

		match Bolt12Invoice::try_from(tlv_stream.to_bytes()) {
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::MissingPaths)),
		}

		let mut payment_paths = payment_paths();
		payment_paths.pop();
		let mut tlv_stream = invoice.as_tlv_stream();
		tlv_stream.3.blindedpay = Some(Iterable(payment_paths.iter().map(|(payinfo, _)| payinfo)));

		match Bolt12Invoice::try_from(tlv_stream.to_bytes()) {
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::InvalidPayInfo)),
		}
	}

	#[test]
	fn parses_invoice_with_created_at() {
		let invoice = OfferBuilder::new("foo".into(), recipient_pubkey())
			.amount_msats(1000)
			.build().unwrap()
			.request_invoice(vec![1; 32], payer_pubkey()).unwrap()
			.build().unwrap()
			.sign(payer_sign).unwrap()
			.respond_with_no_std(payment_paths(), payment_hash(), now()).unwrap()
			.build().unwrap()
			.sign(recipient_sign).unwrap();

		let mut buffer = Vec::new();
		invoice.write(&mut buffer).unwrap();

		if let Err(e) = Bolt12Invoice::try_from(buffer) {
			panic!("error parsing invoice: {:?}", e);
		}

		let mut tlv_stream = invoice.as_tlv_stream();
		tlv_stream.3.created_at = None;

		match Bolt12Invoice::try_from(tlv_stream.to_bytes()) {
			Ok(_) => panic!("expected error"),
			Err(e) => {
				assert_eq!(e, Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::MissingCreationTime));
			},
		}
	}

	#[test]
	fn parses_invoice_with_relative_expiry() {
		let invoice = OfferBuilder::new("foo".into(), recipient_pubkey())
			.amount_msats(1000)
			.build().unwrap()
			.request_invoice(vec![1; 32], payer_pubkey()).unwrap()
			.build().unwrap()
			.sign(payer_sign).unwrap()
			.respond_with_no_std(payment_paths(), payment_hash(), now()).unwrap()
			.relative_expiry(3600)
			.build().unwrap()
			.sign(recipient_sign).unwrap();

		let mut buffer = Vec::new();
		invoice.write(&mut buffer).unwrap();

		match Bolt12Invoice::try_from(buffer) {
			Ok(invoice) => assert_eq!(invoice.relative_expiry(), Duration::from_secs(3600)),
			Err(e) => panic!("error parsing invoice: {:?}", e),
		}
	}

	#[test]
	fn parses_invoice_with_payment_hash() {
		let invoice = OfferBuilder::new("foo".into(), recipient_pubkey())
			.amount_msats(1000)
			.build().unwrap()
			.request_invoice(vec![1; 32], payer_pubkey()).unwrap()
			.build().unwrap()
			.sign(payer_sign).unwrap()
			.respond_with_no_std(payment_paths(), payment_hash(), now()).unwrap()
			.build().unwrap()
			.sign(recipient_sign).unwrap();

		let mut buffer = Vec::new();
		invoice.write(&mut buffer).unwrap();

		if let Err(e) = Bolt12Invoice::try_from(buffer) {
			panic!("error parsing invoice: {:?}", e);
		}

		let mut tlv_stream = invoice.as_tlv_stream();
		tlv_stream.3.payment_hash = None;

		match Bolt12Invoice::try_from(tlv_stream.to_bytes()) {
			Ok(_) => panic!("expected error"),
			Err(e) => {
				assert_eq!(e, Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::MissingPaymentHash));
			},
		}
	}

	#[test]
	fn parses_invoice_with_amount() {
		let invoice = OfferBuilder::new("foo".into(), recipient_pubkey())
			.amount_msats(1000)
			.build().unwrap()
			.request_invoice(vec![1; 32], payer_pubkey()).unwrap()
			.build().unwrap()
			.sign(payer_sign).unwrap()
			.respond_with_no_std(payment_paths(), payment_hash(), now()).unwrap()
			.build().unwrap()
			.sign(recipient_sign).unwrap();

		let mut buffer = Vec::new();
		invoice.write(&mut buffer).unwrap();

		if let Err(e) = Bolt12Invoice::try_from(buffer) {
			panic!("error parsing invoice: {:?}", e);
		}

		let mut tlv_stream = invoice.as_tlv_stream();
		tlv_stream.3.amount = None;

		match Bolt12Invoice::try_from(tlv_stream.to_bytes()) {
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::MissingAmount)),
		}
	}

	#[test]
	fn parses_invoice_with_allow_mpp() {
		let invoice = OfferBuilder::new("foo".into(), recipient_pubkey())
			.amount_msats(1000)
			.build().unwrap()
			.request_invoice(vec![1; 32], payer_pubkey()).unwrap()
			.build().unwrap()
			.sign(payer_sign).unwrap()
			.respond_with_no_std(payment_paths(), payment_hash(), now()).unwrap()
			.allow_mpp()
			.build().unwrap()
			.sign(recipient_sign).unwrap();

		let mut buffer = Vec::new();
		invoice.write(&mut buffer).unwrap();

		match Bolt12Invoice::try_from(buffer) {
			Ok(invoice) => {
				let mut features = Bolt12InvoiceFeatures::empty();
				features.set_basic_mpp_optional();
				assert_eq!(invoice.invoice_features(), &features);
			},
			Err(e) => panic!("error parsing invoice: {:?}", e),
		}
	}

	#[test]
	fn parses_invoice_with_fallback_address() {
		let script = Script::new();
		let pubkey = bitcoin::util::key::PublicKey::new(recipient_pubkey());
		let x_only_pubkey = XOnlyPublicKey::from_keypair(&recipient_keys()).0;
		let tweaked_pubkey = TweakedPublicKey::dangerous_assume_tweaked(x_only_pubkey);

		let offer = OfferBuilder::new("foo".into(), recipient_pubkey())
			.amount_msats(1000)
			.build().unwrap();
		let invoice_request = offer
			.request_invoice(vec![1; 32], payer_pubkey()).unwrap()
			.build().unwrap()
			.sign(payer_sign).unwrap();
		let mut invoice_builder = invoice_request
			.respond_with_no_std(payment_paths(), payment_hash(), now()).unwrap()
			.fallback_v0_p2wsh(&script.wscript_hash())
			.fallback_v0_p2wpkh(&pubkey.wpubkey_hash().unwrap())
			.fallback_v1_p2tr_tweaked(&tweaked_pubkey);

		// Only standard addresses will be included.
		let fallbacks = invoice_builder.invoice.fields_mut().fallbacks.as_mut().unwrap();
		// Non-standard addresses
		fallbacks.push(FallbackAddress { version: 1, program: vec![0u8; 41] });
		fallbacks.push(FallbackAddress { version: 2, program: vec![0u8; 1] });
		fallbacks.push(FallbackAddress { version: 17, program: vec![0u8; 40] });
		// Standard address
		fallbacks.push(FallbackAddress { version: 1, program: vec![0u8; 33] });
		fallbacks.push(FallbackAddress { version: 2, program: vec![0u8; 40] });

		let invoice = invoice_builder.build().unwrap().sign(recipient_sign).unwrap();
		let mut buffer = Vec::new();
		invoice.write(&mut buffer).unwrap();

		match Bolt12Invoice::try_from(buffer) {
			Ok(invoice) => {
				assert_eq!(
					invoice.fallbacks(),
					vec![
						Address::p2wsh(&script, Network::Bitcoin),
						Address::p2wpkh(&pubkey, Network::Bitcoin).unwrap(),
						Address::p2tr_tweaked(tweaked_pubkey, Network::Bitcoin),
						Address {
							payload: Payload::WitnessProgram {
								version: WitnessVersion::V1,
								program: vec![0u8; 33],
							},
							network: Network::Bitcoin,
						},
						Address {
							payload: Payload::WitnessProgram {
								version: WitnessVersion::V2,
								program: vec![0u8; 40],
							},
							network: Network::Bitcoin,
						},
					],
				);
			},
			Err(e) => panic!("error parsing invoice: {:?}", e),
		}
	}

	#[test]
	fn parses_invoice_with_node_id() {
		let invoice = OfferBuilder::new("foo".into(), recipient_pubkey())
			.amount_msats(1000)
			.build().unwrap()
			.request_invoice(vec![1; 32], payer_pubkey()).unwrap()
			.build().unwrap()
			.sign(payer_sign).unwrap()
			.respond_with_no_std(payment_paths(), payment_hash(), now()).unwrap()
			.build().unwrap()
			.sign(recipient_sign).unwrap();

		let mut buffer = Vec::new();
		invoice.write(&mut buffer).unwrap();

		if let Err(e) = Bolt12Invoice::try_from(buffer) {
			panic!("error parsing invoice: {:?}", e);
		}

		let mut tlv_stream = invoice.as_tlv_stream();
		tlv_stream.3.node_id = None;

		match Bolt12Invoice::try_from(tlv_stream.to_bytes()) {
			Ok(_) => panic!("expected error"),
			Err(e) => {
				assert_eq!(e, Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::MissingSigningPubkey));
			},
		}

		let invalid_pubkey = payer_pubkey();
		let mut tlv_stream = invoice.as_tlv_stream();
		tlv_stream.3.node_id = Some(&invalid_pubkey);

		match Bolt12Invoice::try_from(tlv_stream.to_bytes()) {
			Ok(_) => panic!("expected error"),
			Err(e) => {
				assert_eq!(e, Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::InvalidSigningPubkey));
			},
		}
	}

	#[test]
	fn fails_parsing_invoice_without_signature() {
		let mut buffer = Vec::new();
		OfferBuilder::new("foo".into(), recipient_pubkey())
			.amount_msats(1000)
			.build().unwrap()
			.request_invoice(vec![1; 32], payer_pubkey()).unwrap()
			.build().unwrap()
			.sign(payer_sign).unwrap()
			.respond_with_no_std(payment_paths(), payment_hash(), now()).unwrap()
			.build().unwrap()
			.contents
			.write(&mut buffer).unwrap();

		match Bolt12Invoice::try_from(buffer) {
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::MissingSignature)),
		}
	}

	#[test]
	fn fails_parsing_invoice_with_invalid_signature() {
		let mut invoice = OfferBuilder::new("foo".into(), recipient_pubkey())
			.amount_msats(1000)
			.build().unwrap()
			.request_invoice(vec![1; 32], payer_pubkey()).unwrap()
			.build().unwrap()
			.sign(payer_sign).unwrap()
			.respond_with_no_std(payment_paths(), payment_hash(), now()).unwrap()
			.build().unwrap()
			.sign(recipient_sign).unwrap();
		let last_signature_byte = invoice.bytes.last_mut().unwrap();
		*last_signature_byte = last_signature_byte.wrapping_add(1);

		let mut buffer = Vec::new();
		invoice.write(&mut buffer).unwrap();

		match Bolt12Invoice::try_from(buffer) {
			Ok(_) => panic!("expected error"),
			Err(e) => {
				assert_eq!(e, Bolt12ParseError::InvalidSignature(secp256k1::Error::InvalidSignature));
			},
		}
	}

	#[test]
	fn fails_parsing_invoice_with_extra_tlv_records() {
		let invoice = OfferBuilder::new("foo".into(), recipient_pubkey())
			.amount_msats(1000)
			.build().unwrap()
			.request_invoice(vec![1; 32], payer_pubkey()).unwrap()
			.build().unwrap()
			.sign(payer_sign).unwrap()
			.respond_with_no_std(payment_paths(), payment_hash(), now()).unwrap()
			.build().unwrap()
			.sign(recipient_sign).unwrap();

		let mut encoded_invoice = Vec::new();
		invoice.write(&mut encoded_invoice).unwrap();
		BigSize(1002).write(&mut encoded_invoice).unwrap();
		BigSize(32).write(&mut encoded_invoice).unwrap();
		[42u8; 32].write(&mut encoded_invoice).unwrap();

		match Bolt12Invoice::try_from(encoded_invoice) {
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, Bolt12ParseError::Decode(DecodeError::InvalidValue)),
		}
	}
}
