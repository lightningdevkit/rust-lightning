// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Data structures and encoding for refunds.
//!
//! A [`Refund`] is an "offer for money" and is typically constructed by a merchant and presented
//! directly to the customer. The recipient responds with a [`Bolt12Invoice`] to be paid.
//!
//! This is an [`InvoiceRequest`] produced *not* in response to an [`Offer`].
//!
//! [`Bolt12Invoice`]: crate::offers::invoice::Bolt12Invoice
//! [`InvoiceRequest`]: crate::offers::invoice_request::InvoiceRequest
//! [`Offer`]: crate::offers::offer::Offer
//!
//! # Example
//!
//! ```
//! extern crate bitcoin;
//! extern crate core;
//! extern crate lightning;
//!
//! use core::convert::TryFrom;
//! use core::time::Duration;
//!
//! use bitcoin::network::Network;
//! use bitcoin::secp256k1::{Keypair, PublicKey, Secp256k1, SecretKey};
//! use lightning::offers::parse::Bolt12ParseError;
//! use lightning::offers::refund::{Refund, RefundBuilder};
//! use lightning::util::ser::{Readable, Writeable};
//!
//! # use lightning::blinded_path::BlindedPath;
//! # #[cfg(feature = "std")]
//! # use std::time::SystemTime;
//! #
//! # fn create_blinded_path() -> BlindedPath { unimplemented!() }
//! # fn create_another_blinded_path() -> BlindedPath { unimplemented!() }
//! #
//! # #[cfg(feature = "std")]
//! # fn build() -> Result<(), Bolt12ParseError> {
//! let secp_ctx = Secp256k1::new();
//! let keys = Keypair::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[42; 32]).unwrap());
//! let pubkey = PublicKey::from(keys);
//!
//! let expiration = SystemTime::now() + Duration::from_secs(24 * 60 * 60);
//! let refund = RefundBuilder::new(vec![1; 32], pubkey, 20_000)?
//!     .description("coffee, large".to_string())
//!     .absolute_expiry(expiration.duration_since(SystemTime::UNIX_EPOCH).unwrap())
//!     .issuer("Foo Bar".to_string())
//!     .path(create_blinded_path())
//!     .path(create_another_blinded_path())
//!     .chain(Network::Bitcoin)
//!     .payer_note("refund for order #12345".to_string())
//!     .build()?;
//!
//! // Encode as a bech32 string for use in a QR code.
//! let encoded_refund = refund.to_string();
//!
//! // Parse from a bech32 string after scanning from a QR code.
//! let refund = encoded_refund.parse::<Refund>()?;
//!
//! // Encode refund as raw bytes.
//! let mut bytes = Vec::new();
//! refund.write(&mut bytes).unwrap();
//!
//! // Decode raw bytes into an refund.
//! let refund = Refund::try_from(bytes)?;
//! # Ok(())
//! # }
//! ```
//!
//! # Note
//!
//! If constructing a [`Refund`] for use with a [`ChannelManager`], use
//! [`ChannelManager::create_refund_builder`] instead of [`RefundBuilder::new`].
//!
//! [`ChannelManager`]: crate::ln::channelmanager::ChannelManager
//! [`ChannelManager::create_refund_builder`]: crate::ln::channelmanager::ChannelManager::create_refund_builder

use bitcoin::constants::ChainHash;
use bitcoin::network::Network;
use bitcoin::secp256k1::{PublicKey, Secp256k1, self};
use core::hash::{Hash, Hasher};
use core::ops::Deref;
use core::str::FromStr;
use core::time::Duration;
use crate::sign::EntropySource;
use crate::io;
use crate::blinded_path::BlindedPath;
use crate::ln::types::PaymentHash;
use crate::ln::channelmanager::PaymentId;
use crate::ln::features::InvoiceRequestFeatures;
use crate::ln::inbound_payment::{ExpandedKey, IV_LEN};
use crate::ln::msgs::{DecodeError, MAX_VALUE_MSAT};
use crate::offers::invoice::BlindedPayInfo;
use crate::offers::invoice_request::{InvoiceRequestTlvStream, InvoiceRequestTlvStreamRef};
use crate::offers::nonce::Nonce;
use crate::offers::offer::{OfferTlvStream, OfferTlvStreamRef};
use crate::offers::parse::{Bech32Encode, Bolt12ParseError, Bolt12SemanticError, ParsedMessage};
use crate::offers::payer::{PayerContents, PayerTlvStream, PayerTlvStreamRef};
use crate::offers::signer::{Metadata, MetadataMaterial, self};
use crate::util::ser::{SeekReadable, Readable, WithoutLength, Writeable, Writer};
use crate::util::string::PrintableString;

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

#[cfg(feature = "std")]
use std::time::SystemTime;

pub(super) const IV_BYTES_WITH_METADATA: &[u8; IV_LEN] = b"LDK Refund ~~~~~";
pub(super) const IV_BYTES_WITHOUT_METADATA: &[u8; IV_LEN] = b"LDK Refund v2~~~";

/// Builds a [`Refund`] for the "offer for money" flow.
///
/// See [module-level documentation] for usage.
///
/// This is not exported to bindings users as builder patterns don't map outside of move semantics.
///
/// [module-level documentation]: self
pub struct RefundBuilder<'a, T: secp256k1::Signing> {
	refund: RefundContents,
	secp_ctx: Option<&'a Secp256k1<T>>,
}

/// Builds a [`Refund`] for the "offer for money" flow.
///
/// See [module-level documentation] for usage.
///
/// [module-level documentation]: self
#[cfg(c_bindings)]
#[derive(Clone)]
pub struct RefundMaybeWithDerivedMetadataBuilder<'a> {
	refund: RefundContents,
	secp_ctx: Option<&'a Secp256k1<secp256k1::All>>,
}

macro_rules! refund_explicit_metadata_builder_methods { () => {
	/// Creates a new builder for a refund using the [`Refund::payer_id`] for the public node id to
	/// send to if no [`Refund::paths`] are set. Otherwise, it may be a transient pubkey.
	///
	/// Additionally, sets the required (empty) [`Refund::description`], [`Refund::payer_metadata`],
	/// and [`Refund::amount_msats`].
	///
	/// # Note
	///
	/// If constructing a [`Refund`] for use with a [`ChannelManager`], use
	/// [`ChannelManager::create_refund_builder`] instead of [`RefundBuilder::new`].
	///
	/// [`ChannelManager`]: crate::ln::channelmanager::ChannelManager
	/// [`ChannelManager::create_refund_builder`]: crate::ln::channelmanager::ChannelManager::create_refund_builder
	pub fn new(
		metadata: Vec<u8>, payer_id: PublicKey, amount_msats: u64
	) -> Result<Self, Bolt12SemanticError> {
		if amount_msats > MAX_VALUE_MSAT {
			return Err(Bolt12SemanticError::InvalidAmount);
		}

		let metadata = Metadata::Bytes(metadata);
		Ok(Self {
			refund: RefundContents {
				payer: PayerContents(metadata), description: String::new(), absolute_expiry: None,
				issuer: None, chain: None, amount_msats, features: InvoiceRequestFeatures::empty(),
				quantity: None, payer_id, payer_note: None, paths: None,
			},
			secp_ctx: None,
		})
	}
} }

macro_rules! refund_builder_methods { (
	$self: ident, $self_type: ty, $return_type: ty, $return_value: expr, $secp_context: ty $(, $self_mut: tt)?
) => {
	/// Similar to [`RefundBuilder::new`] except, if [`RefundBuilder::path`] is called, the payer id
	/// is derived from the given [`ExpandedKey`] and nonce. This provides sender privacy by using a
	/// different payer id for each refund, assuming a different nonce is used.  Otherwise, the
	/// provided `node_id` is used for the payer id.
	///
	/// Also, sets the metadata when [`RefundBuilder::build`] is called such that it can be used by
	/// [`Bolt12Invoice::verify_using_metadata`] to determine if the invoice was produced for the
	/// refund given an [`ExpandedKey`]. However, if [`RefundBuilder::path`] is called, then the
	/// metadata must be included in each [`BlindedPath`] instead. In this case, use
	/// [`Bolt12Invoice::verify_using_payer_data`].
	///
	/// The `payment_id` is encrypted in the metadata and should be unique. This ensures that only
	/// one invoice will be paid for the refund and that payments can be uniquely identified.
	///
	/// [`Bolt12Invoice::verify_using_metadata`]: crate::offers::invoice::Bolt12Invoice::verify_using_metadata
	/// [`Bolt12Invoice::verify_using_payer_data`]: crate::offers::invoice::Bolt12Invoice::verify_using_payer_data
	/// [`ExpandedKey`]: crate::ln::inbound_payment::ExpandedKey
	pub fn deriving_payer_id(
		node_id: PublicKey, expanded_key: &ExpandedKey, nonce: Nonce,
		secp_ctx: &'a Secp256k1<$secp_context>, amount_msats: u64, payment_id: PaymentId
	) -> Result<Self, Bolt12SemanticError> {
		if amount_msats > MAX_VALUE_MSAT {
			return Err(Bolt12SemanticError::InvalidAmount);
		}

		let payment_id = Some(payment_id);
		let derivation_material = MetadataMaterial::new(nonce, expanded_key, payment_id);
		let metadata = Metadata::DerivedSigningPubkey(derivation_material);
		Ok(Self {
			refund: RefundContents {
				payer: PayerContents(metadata), description: String::new(), absolute_expiry: None,
				issuer: None, chain: None, amount_msats, features: InvoiceRequestFeatures::empty(),
				quantity: None, payer_id: node_id, payer_note: None, paths: None,
			},
			secp_ctx: Some(secp_ctx),
		})
	}

	/// Sets the [`Refund::description`].
	///
	/// Successive calls to this method will override the previous setting.
	pub fn description($($self_mut)* $self: $self_type, description: String) -> $return_type {
		$self.refund.description = description;
		$return_value
	}

	/// Sets the [`Refund::absolute_expiry`] as seconds since the Unix epoch. Any expiry that has
	/// already passed is valid and can be checked for using [`Refund::is_expired`].
	///
	/// Successive calls to this method will override the previous setting.
	pub fn absolute_expiry($($self_mut)* $self: $self_type, absolute_expiry: Duration) -> $return_type {
		$self.refund.absolute_expiry = Some(absolute_expiry);
		$return_value
	}

	/// Sets the [`Refund::issuer`].
	///
	/// Successive calls to this method will override the previous setting.
	pub fn issuer($($self_mut)* $self: $self_type, issuer: String) -> $return_type {
		$self.refund.issuer = Some(issuer);
		$return_value
	}

	/// Adds a blinded path to [`Refund::paths`]. Must include at least one path if only connected
	/// by private channels or if [`Refund::payer_id`] is not a public node id.
	///
	/// Successive calls to this method will add another blinded path. Caller is responsible for not
	/// adding duplicate paths.
	pub fn path($($self_mut)* $self: $self_type, path: BlindedPath) -> $return_type {
		$self.refund.paths.get_or_insert_with(Vec::new).push(path);
		$return_value
	}

	/// Sets the [`Refund::chain`] of the given [`Network`] for paying an invoice. If not
	/// called, [`Network::Bitcoin`] is assumed.
	///
	/// Successive calls to this method will override the previous setting.
	pub fn chain($self: $self_type, network: Network) -> $return_type {
		$self.chain_hash(ChainHash::using_genesis_block(network))
	}

	/// Sets the [`Refund::chain`] of the given [`ChainHash`] for paying an invoice. If not called,
	/// [`Network::Bitcoin`] is assumed.
	///
	/// Successive calls to this method will override the previous setting.
	pub(crate) fn chain_hash($($self_mut)* $self: $self_type, chain: ChainHash) -> $return_type {
		$self.refund.chain = Some(chain);
		$return_value
	}

	/// Sets [`Refund::quantity`] of items. This is purely for informational purposes. It is useful
	/// when the refund pertains to a [`Bolt12Invoice`] that paid for more than one item from an
	/// [`Offer`] as specified by [`InvoiceRequest::quantity`].
	///
	/// Successive calls to this method will override the previous setting.
	///
	/// [`Bolt12Invoice`]: crate::offers::invoice::Bolt12Invoice
	/// [`InvoiceRequest::quantity`]: crate::offers::invoice_request::InvoiceRequest::quantity
	/// [`Offer`]: crate::offers::offer::Offer
	pub fn quantity($($self_mut)* $self: $self_type, quantity: u64) -> $return_type {
		$self.refund.quantity = Some(quantity);
		$return_value
	}

	/// Sets the [`Refund::payer_note`].
	///
	/// Successive calls to this method will override the previous setting.
	pub fn payer_note($($self_mut)* $self: $self_type, payer_note: String) -> $return_type {
		$self.refund.payer_note = Some(payer_note);
		$return_value
	}

	/// Builds a [`Refund`] after checking for valid semantics.
	pub fn build($($self_mut)* $self: $self_type) -> Result<Refund, Bolt12SemanticError> {
		if $self.refund.chain() == $self.refund.implied_chain() {
			$self.refund.chain = None;
		}

		// Create the metadata for stateless verification of a Bolt12Invoice.
		if $self.refund.payer.0.has_derivation_material() {
			let mut metadata = core::mem::take(&mut $self.refund.payer.0);

			let iv_bytes = if $self.refund.paths.is_none() {
				metadata = metadata.without_keys();
				IV_BYTES_WITH_METADATA
			} else {
				IV_BYTES_WITHOUT_METADATA
			};

			let mut tlv_stream = $self.refund.as_tlv_stream();
			tlv_stream.0.metadata = None;
			if metadata.derives_payer_keys() {
				tlv_stream.2.payer_id = None;
			}

			let (derived_metadata, keys) =
				metadata.derive_from(iv_bytes, tlv_stream, $self.secp_ctx);
			metadata = derived_metadata;
			if let Some(keys) = keys {
				$self.refund.payer_id = keys.public_key();
			}

			$self.refund.payer.0 = metadata;
		}

		let mut bytes = Vec::new();
		$self.refund.write(&mut bytes).unwrap();

		Ok(Refund {
			bytes,
			#[cfg(not(c_bindings))]
			contents: $self.refund,
			#[cfg(c_bindings)]
			contents: $self.refund.clone(),
		})
	}
} }

#[cfg(test)]
macro_rules! refund_builder_test_methods { (
	$self: ident, $self_type: ty, $return_type: ty, $return_value: expr $(, $self_mut: tt)?
) => {
	#[cfg_attr(c_bindings, allow(dead_code))]
	pub(crate) fn clear_paths($($self_mut)* $self: $self_type) -> $return_type {
		$self.refund.paths = None;
		$return_value
	}

	#[cfg_attr(c_bindings, allow(dead_code))]
	fn features_unchecked($($self_mut)* $self: $self_type, features: InvoiceRequestFeatures) -> $return_type {
		$self.refund.features = features;
		$return_value
	}
} }

impl<'a> RefundBuilder<'a, secp256k1::SignOnly> {
	refund_explicit_metadata_builder_methods!();
}

impl<'a, T: secp256k1::Signing> RefundBuilder<'a, T> {
	refund_builder_methods!(self, Self, Self, self, T, mut);

	#[cfg(test)]
	refund_builder_test_methods!(self, Self, Self, self, mut);
}

#[cfg(all(c_bindings, not(test)))]
impl<'a> RefundMaybeWithDerivedMetadataBuilder<'a> {
	refund_explicit_metadata_builder_methods!();
	refund_builder_methods!(self, &mut Self, (), (), secp256k1::All);
}

#[cfg(all(c_bindings, test))]
impl<'a> RefundMaybeWithDerivedMetadataBuilder<'a> {
	refund_explicit_metadata_builder_methods!();
	refund_builder_methods!(self, &mut Self, &mut Self, self, secp256k1::All);
	refund_builder_test_methods!(self, &mut Self, &mut Self, self);
}

#[cfg(c_bindings)]
impl<'a> From<RefundBuilder<'a, secp256k1::All>>
for RefundMaybeWithDerivedMetadataBuilder<'a> {
	fn from(builder: RefundBuilder<'a, secp256k1::All>) -> Self {
		let RefundBuilder { refund, secp_ctx } = builder;

		Self { refund, secp_ctx }
	}
}

#[cfg(c_bindings)]
impl<'a> From<RefundMaybeWithDerivedMetadataBuilder<'a>>
for RefundBuilder<'a, secp256k1::All> {
	fn from(builder: RefundMaybeWithDerivedMetadataBuilder<'a>) -> Self {
		let RefundMaybeWithDerivedMetadataBuilder { refund, secp_ctx } = builder;

		Self { refund, secp_ctx }
	}
}

/// A `Refund` is a request to send an [`Bolt12Invoice`] without a preceding [`Offer`].
///
/// Typically, after an invoice is paid, the recipient may publish a refund allowing the sender to
/// recoup their funds. A refund may be used more generally as an "offer for money", such as with a
/// bitcoin ATM.
///
/// [`Bolt12Invoice`]: crate::offers::invoice::Bolt12Invoice
/// [`Offer`]: crate::offers::offer::Offer
#[derive(Clone, Debug)]
pub struct Refund {
	pub(super) bytes: Vec<u8>,
	pub(super) contents: RefundContents,
}

/// The contents of a [`Refund`], which may be shared with an [`Bolt12Invoice`].
///
/// [`Bolt12Invoice`]: crate::offers::invoice::Bolt12Invoice
#[derive(Clone, Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub(super) struct RefundContents {
	pub(super) payer: PayerContents,
	// offer fields
	description: String,
	absolute_expiry: Option<Duration>,
	issuer: Option<String>,
	// invoice_request fields
	chain: Option<ChainHash>,
	amount_msats: u64,
	features: InvoiceRequestFeatures,
	quantity: Option<u64>,
	payer_id: PublicKey,
	payer_note: Option<String>,
	paths: Option<Vec<BlindedPath>>,
}

impl Refund {
	/// A complete description of the purpose of the refund. Intended to be displayed to the user
	/// but with the caveat that it has not been verified in any way.
	pub fn description(&self) -> PrintableString {
		self.contents.description()
	}

	/// Duration since the Unix epoch when an invoice should no longer be sent.
	///
	/// If `None`, the refund does not expire.
	pub fn absolute_expiry(&self) -> Option<Duration> {
		self.contents.absolute_expiry()
	}

	/// Whether the refund has expired.
	#[cfg(feature = "std")]
	pub fn is_expired(&self) -> bool {
		self.contents.is_expired()
	}

	/// Whether the refund has expired given the duration since the Unix epoch.
	pub fn is_expired_no_std(&self, duration_since_epoch: Duration) -> bool {
		self.contents.is_expired_no_std(duration_since_epoch)
	}

	/// The issuer of the refund, possibly beginning with `user@domain` or `domain`. Intended to be
	/// displayed to the user but with the caveat that it has not been verified in any way.
	pub fn issuer(&self) -> Option<PrintableString> {
		self.contents.issuer()
	}

	/// Paths to the sender originating from publicly reachable nodes. Blinded paths provide sender
	/// privacy by obfuscating its node id.
	pub fn paths(&self) -> &[BlindedPath] {
		self.contents.paths()
	}

	/// An unpredictable series of bytes, typically containing information about the derivation of
	/// [`payer_id`].
	///
	/// [`payer_id`]: Self::payer_id
	pub fn payer_metadata(&self) -> &[u8] {
		self.contents.metadata()
	}

	/// A chain that the refund is valid for.
	pub fn chain(&self) -> ChainHash {
		self.contents.chain()
	}

	/// The amount to refund in msats (i.e., the minimum lightning-payable unit for [`chain`]).
	///
	/// [`chain`]: Self::chain
	pub fn amount_msats(&self) -> u64 {
		self.contents.amount_msats()
	}

	/// Features pertaining to requesting an invoice.
	pub fn features(&self) -> &InvoiceRequestFeatures {
		&self.contents.features()
	}

	/// The quantity of an item that refund is for.
	pub fn quantity(&self) -> Option<u64> {
		self.contents.quantity()
	}

	/// A public node id to send to in the case where there are no [`paths`]. Otherwise, a possibly
	/// transient pubkey.
	///
	/// [`paths`]: Self::paths
	pub fn payer_id(&self) -> PublicKey {
		self.contents.payer_id()
	}

	/// Payer provided note to include in the invoice.
	pub fn payer_note(&self) -> Option<PrintableString> {
		self.contents.payer_note()
	}
}

macro_rules! respond_with_explicit_signing_pubkey_methods { ($self: ident, $builder: ty) => {
	/// Creates an [`InvoiceBuilder`] for the refund with the given required fields and using the
	/// [`Duration`] since [`std::time::SystemTime::UNIX_EPOCH`] as the creation time.
	///
	/// See [`Refund::respond_with_no_std`] for further details where the aforementioned creation
	/// time is used for the `created_at` parameter.
	///
	/// This is not exported to bindings users as builder patterns don't map outside of move semantics.
	///
	/// [`Duration`]: core::time::Duration
	#[cfg(feature = "std")]
	pub fn respond_with(
		&$self, payment_paths: Vec<(BlindedPayInfo, BlindedPath)>, payment_hash: PaymentHash,
		signing_pubkey: PublicKey,
	) -> Result<$builder, Bolt12SemanticError> {
		let created_at = std::time::SystemTime::now()
			.duration_since(std::time::SystemTime::UNIX_EPOCH)
			.expect("SystemTime::now() should come after SystemTime::UNIX_EPOCH");

		$self.respond_with_no_std(payment_paths, payment_hash, signing_pubkey, created_at)
	}

	/// Creates an [`InvoiceBuilder`] for the refund with the given required fields.
	///
	/// Unless [`InvoiceBuilder::relative_expiry`] is set, the invoice will expire two hours after
	/// `created_at`, which is used to set [`Bolt12Invoice::created_at`]. Useful for `no-std` builds
	/// where [`std::time::SystemTime`] is not available.
	///
	/// The caller is expected to remember the preimage of `payment_hash` in order to
	/// claim a payment for the invoice.
	///
	/// The `signing_pubkey` is required to sign the invoice since refunds are not in response to an
	/// offer, which does have a `signing_pubkey`.
	///
	/// The `payment_paths` parameter is useful for maintaining the payment recipient's privacy. It
	/// must contain one or more elements ordered from most-preferred to least-preferred, if there's
	/// a preference. Note, however, that any privacy is lost if a public node id is used for
	/// `signing_pubkey`.
	///
	/// Errors if the request contains unknown required features.
	///
	/// This is not exported to bindings users as builder patterns don't map outside of move semantics.
	///
	/// [`Bolt12Invoice::created_at`]: crate::offers::invoice::Bolt12Invoice::created_at
	pub fn respond_with_no_std(
		&$self, payment_paths: Vec<(BlindedPayInfo, BlindedPath)>, payment_hash: PaymentHash,
		signing_pubkey: PublicKey, created_at: Duration
	) -> Result<$builder, Bolt12SemanticError> {
		if $self.features().requires_unknown_bits() {
			return Err(Bolt12SemanticError::UnknownRequiredFeatures);
		}

		<$builder>::for_refund($self, payment_paths, created_at, payment_hash, signing_pubkey)
	}
} }

macro_rules! respond_with_derived_signing_pubkey_methods { ($self: ident, $builder: ty) => {
	/// Creates an [`InvoiceBuilder`] for the refund using the given required fields and that uses
	/// derived signing keys to sign the [`Bolt12Invoice`].
	///
	/// See [`Refund::respond_with`] for further details.
	///
	/// This is not exported to bindings users as builder patterns don't map outside of move semantics.
	///
	/// [`Bolt12Invoice`]: crate::offers::invoice::Bolt12Invoice
	#[cfg(feature = "std")]
	pub fn respond_using_derived_keys<ES: Deref>(
		&$self, payment_paths: Vec<(BlindedPayInfo, BlindedPath)>, payment_hash: PaymentHash,
		expanded_key: &ExpandedKey, entropy_source: ES
	) -> Result<$builder, Bolt12SemanticError>
	where
		ES::Target: EntropySource,
	{
		let created_at = std::time::SystemTime::now()
			.duration_since(std::time::SystemTime::UNIX_EPOCH)
			.expect("SystemTime::now() should come after SystemTime::UNIX_EPOCH");

		$self.respond_using_derived_keys_no_std(
			payment_paths, payment_hash, created_at, expanded_key, entropy_source
		)
	}

	/// Creates an [`InvoiceBuilder`] for the refund using the given required fields and that uses
	/// derived signing keys to sign the [`Bolt12Invoice`].
	///
	/// See [`Refund::respond_with_no_std`] for further details.
	///
	/// This is not exported to bindings users as builder patterns don't map outside of move semantics.
	///
	/// [`Bolt12Invoice`]: crate::offers::invoice::Bolt12Invoice
	pub fn respond_using_derived_keys_no_std<ES: Deref>(
		&$self, payment_paths: Vec<(BlindedPayInfo, BlindedPath)>, payment_hash: PaymentHash,
		created_at: core::time::Duration, expanded_key: &ExpandedKey, entropy_source: ES
	) -> Result<$builder, Bolt12SemanticError>
	where
		ES::Target: EntropySource,
	{
		if $self.features().requires_unknown_bits() {
			return Err(Bolt12SemanticError::UnknownRequiredFeatures);
		}

		let nonce = Nonce::from_entropy_source(entropy_source);
		let keys = signer::derive_keys(nonce, expanded_key);
		<$builder>::for_refund_using_keys($self, payment_paths, created_at, payment_hash, keys)
	}
} }

#[cfg(not(c_bindings))]
impl Refund {
	respond_with_explicit_signing_pubkey_methods!(self, InvoiceBuilder<ExplicitSigningPubkey>);
	respond_with_derived_signing_pubkey_methods!(self, InvoiceBuilder<DerivedSigningPubkey>);
}

#[cfg(c_bindings)]
impl Refund {
	respond_with_explicit_signing_pubkey_methods!(self, InvoiceWithExplicitSigningPubkeyBuilder);
	respond_with_derived_signing_pubkey_methods!(self, InvoiceWithDerivedSigningPubkeyBuilder);
}

#[cfg(test)]
impl Refund {
	fn as_tlv_stream(&self) -> RefundTlvStreamRef {
		self.contents.as_tlv_stream()
	}
}

impl AsRef<[u8]> for Refund {
	fn as_ref(&self) -> &[u8] {
		&self.bytes
	}
}

impl PartialEq for Refund {
	fn eq(&self, other: &Self) -> bool {
		self.bytes.eq(&other.bytes)
	}
}

impl Eq for Refund {}

impl Hash for Refund {
	fn hash<H: Hasher>(&self, state: &mut H) {
		self.bytes.hash(state);
	}
}

impl RefundContents {
	pub fn description(&self) -> PrintableString {
		PrintableString(&self.description)
	}

	pub fn absolute_expiry(&self) -> Option<Duration> {
		self.absolute_expiry
	}

	#[cfg(feature = "std")]
	pub(super) fn is_expired(&self) -> bool {
		SystemTime::UNIX_EPOCH
			.elapsed()
			.map(|duration_since_epoch| self.is_expired_no_std(duration_since_epoch))
			.unwrap_or(false)
	}

	pub(super) fn is_expired_no_std(&self, duration_since_epoch: Duration) -> bool {
		self.absolute_expiry
			.map(|absolute_expiry| duration_since_epoch > absolute_expiry)
			.unwrap_or(false)
	}

	pub fn issuer(&self) -> Option<PrintableString> {
		self.issuer.as_ref().map(|issuer| PrintableString(issuer.as_str()))
	}

	pub fn paths(&self) -> &[BlindedPath] {
		self.paths.as_ref().map(|paths| paths.as_slice()).unwrap_or(&[])
	}

	pub(super) fn metadata(&self) -> &[u8] {
		self.payer.0.as_bytes().map(|bytes| bytes.as_slice()).unwrap_or(&[])
	}

	pub(super) fn chain(&self) -> ChainHash {
		self.chain.unwrap_or_else(|| self.implied_chain())
	}

	pub fn implied_chain(&self) -> ChainHash {
		ChainHash::using_genesis_block(Network::Bitcoin)
	}

	pub fn amount_msats(&self) -> u64 {
		self.amount_msats
	}

	/// Features pertaining to requesting an invoice.
	pub fn features(&self) -> &InvoiceRequestFeatures {
		&self.features
	}

	/// The quantity of an item that refund is for.
	pub fn quantity(&self) -> Option<u64> {
		self.quantity
	}

	/// A public node id to send to in the case where there are no [`paths`]. Otherwise, a possibly
	/// transient pubkey.
	///
	/// [`paths`]: Self::paths
	pub fn payer_id(&self) -> PublicKey {
		self.payer_id
	}

	/// Payer provided note to include in the invoice.
	pub fn payer_note(&self) -> Option<PrintableString> {
		self.payer_note.as_ref().map(|payer_note| PrintableString(payer_note.as_str()))
	}

	pub(super) fn as_tlv_stream(&self) -> RefundTlvStreamRef {
		let payer = PayerTlvStreamRef {
			metadata: self.payer.0.as_bytes(),
		};

		let offer = OfferTlvStreamRef {
			chains: None,
			metadata: None,
			currency: None,
			amount: None,
			description: Some(&self.description),
			features: None,
			absolute_expiry: self.absolute_expiry.map(|duration| duration.as_secs()),
			paths: None,
			issuer: self.issuer.as_ref(),
			quantity_max: None,
			node_id: None,
		};

		let features = {
			if self.features == InvoiceRequestFeatures::empty() { None }
			else { Some(&self.features) }
		};

		let invoice_request = InvoiceRequestTlvStreamRef {
			chain: self.chain.as_ref(),
			amount: Some(self.amount_msats),
			features,
			quantity: self.quantity,
			payer_id: Some(&self.payer_id),
			payer_note: self.payer_note.as_ref(),
			paths: self.paths.as_ref(),
		};

		(payer, offer, invoice_request)
	}
}

impl Readable for Refund {
	fn read<R: io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
		let bytes: WithoutLength<Vec<u8>> = Readable::read(reader)?;
		Self::try_from(bytes.0).map_err(|_| DecodeError::InvalidValue)
	}
}

impl Writeable for Refund {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		WithoutLength(&self.bytes).write(writer)
	}
}

impl Writeable for RefundContents {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		self.as_tlv_stream().write(writer)
	}
}

type RefundTlvStream = (PayerTlvStream, OfferTlvStream, InvoiceRequestTlvStream);

type RefundTlvStreamRef<'a> = (
	PayerTlvStreamRef<'a>,
	OfferTlvStreamRef<'a>,
	InvoiceRequestTlvStreamRef<'a>,
);

impl SeekReadable for RefundTlvStream {
	fn read<R: io::Read + io::Seek>(r: &mut R) -> Result<Self, DecodeError> {
		let payer = SeekReadable::read(r)?;
		let offer = SeekReadable::read(r)?;
		let invoice_request = SeekReadable::read(r)?;

		Ok((payer, offer, invoice_request))
	}
}

impl Bech32Encode for Refund {
	const BECH32_HRP: &'static str = "lnr";
}

impl FromStr for Refund {
	type Err = Bolt12ParseError;

	fn from_str(s: &str) -> Result<Self, <Self as FromStr>::Err> {
		Refund::from_bech32_str(s)
	}
}

impl TryFrom<Vec<u8>> for Refund {
	type Error = Bolt12ParseError;

	fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
		let refund = ParsedMessage::<RefundTlvStream>::try_from(bytes)?;
		let ParsedMessage { bytes, tlv_stream } = refund;
		let contents = RefundContents::try_from(tlv_stream)?;

		Ok(Refund { bytes, contents })
	}
}

impl TryFrom<RefundTlvStream> for RefundContents {
	type Error = Bolt12SemanticError;

	fn try_from(tlv_stream: RefundTlvStream) -> Result<Self, Self::Error> {
		let (
			PayerTlvStream { metadata: payer_metadata },
			OfferTlvStream {
				chains, metadata, currency, amount: offer_amount, description,
				features: offer_features, absolute_expiry, paths: offer_paths, issuer, quantity_max,
				node_id,
			},
			InvoiceRequestTlvStream {
				chain, amount, features, quantity, payer_id, payer_note, paths
			},
		) = tlv_stream;

		let payer = match payer_metadata {
			None => return Err(Bolt12SemanticError::MissingPayerMetadata),
			Some(metadata) => PayerContents(Metadata::Bytes(metadata)),
		};

		if metadata.is_some() {
			return Err(Bolt12SemanticError::UnexpectedMetadata);
		}

		if chains.is_some() {
			return Err(Bolt12SemanticError::UnexpectedChain);
		}

		if currency.is_some() || offer_amount.is_some() {
			return Err(Bolt12SemanticError::UnexpectedAmount);
		}

		let description = match description {
			None => return Err(Bolt12SemanticError::MissingDescription),
			Some(description) => description,
		};

		if offer_features.is_some() {
			return Err(Bolt12SemanticError::UnexpectedFeatures);
		}

		let absolute_expiry = absolute_expiry.map(Duration::from_secs);

		if offer_paths.is_some() {
			return Err(Bolt12SemanticError::UnexpectedPaths);
		}

		if quantity_max.is_some() {
			return Err(Bolt12SemanticError::UnexpectedQuantity);
		}

		if node_id.is_some() {
			return Err(Bolt12SemanticError::UnexpectedSigningPubkey);
		}

		let amount_msats = match amount {
			None => return Err(Bolt12SemanticError::MissingAmount),
			Some(amount_msats) if amount_msats > MAX_VALUE_MSAT => {
				return Err(Bolt12SemanticError::InvalidAmount);
			},
			Some(amount_msats) => amount_msats,
		};

		let features = features.unwrap_or_else(InvoiceRequestFeatures::empty);

		let payer_id = match payer_id {
			None => return Err(Bolt12SemanticError::MissingPayerId),
			Some(payer_id) => payer_id,
		};

		Ok(RefundContents {
			payer, description, absolute_expiry, issuer, chain, amount_msats, features, quantity,
			payer_id, payer_note, paths,
		})
	}
}

impl core::fmt::Display for Refund {
	fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
		self.fmt_bech32_str(f)
	}
}

#[cfg(test)]
mod tests {
	use super::{Refund, RefundTlvStreamRef};
	#[cfg(not(c_bindings))]
	use {
		super::RefundBuilder,
	};
	#[cfg(c_bindings)]
	use {
		super::RefundMaybeWithDerivedMetadataBuilder as RefundBuilder,
	};

	use bitcoin::constants::ChainHash;
	use bitcoin::network::Network;
	use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};

	use core::time::Duration;

	use crate::blinded_path::{BlindedHop, BlindedPath, IntroductionNode};
	use crate::sign::KeyMaterial;
	use crate::ln::channelmanager::PaymentId;
	use crate::ln::features::{InvoiceRequestFeatures, OfferFeatures};
	use crate::ln::inbound_payment::ExpandedKey;
	use crate::ln::msgs::{DecodeError, MAX_VALUE_MSAT};
	use crate::offers::invoice_request::InvoiceRequestTlvStreamRef;
	use crate::offers::nonce::Nonce;
	use crate::offers::offer::OfferTlvStreamRef;
	use crate::offers::parse::{Bolt12ParseError, Bolt12SemanticError};
	use crate::offers::payer::PayerTlvStreamRef;
	use crate::offers::test_utils::*;
	use crate::util::ser::{BigSize, Writeable};
	use crate::util::string::PrintableString;
	use crate::prelude::*;

	trait ToBytes {
		fn to_bytes(&self) -> Vec<u8>;
	}

	impl<'a> ToBytes for RefundTlvStreamRef<'a> {
		fn to_bytes(&self) -> Vec<u8> {
			let mut buffer = Vec::new();
			self.write(&mut buffer).unwrap();
			buffer
		}
	}

	#[test]
	fn builds_refund_with_defaults() {
		let refund = RefundBuilder::new(vec![1; 32], payer_pubkey(), 1000).unwrap()
			.build().unwrap();

		let mut buffer = Vec::new();
		refund.write(&mut buffer).unwrap();

		assert_eq!(refund.bytes, buffer.as_slice());
		assert_eq!(refund.payer_metadata(), &[1; 32]);
		assert_eq!(refund.description(), PrintableString(""));
		assert_eq!(refund.absolute_expiry(), None);
		#[cfg(feature = "std")]
		assert!(!refund.is_expired());
		assert_eq!(refund.paths(), &[]);
		assert_eq!(refund.issuer(), None);
		assert_eq!(refund.chain(), ChainHash::using_genesis_block(Network::Bitcoin));
		assert_eq!(refund.amount_msats(), 1000);
		assert_eq!(refund.features(), &InvoiceRequestFeatures::empty());
		assert_eq!(refund.payer_id(), payer_pubkey());
		assert_eq!(refund.payer_note(), None);

		assert_eq!(
			refund.as_tlv_stream(),
			(
				PayerTlvStreamRef { metadata: Some(&vec![1; 32]) },
				OfferTlvStreamRef {
					chains: None,
					metadata: None,
					currency: None,
					amount: None,
					description: Some(&String::from("")),
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
					paths: None,
				},
			),
		);

		if let Err(e) = Refund::try_from(buffer) {
			panic!("error parsing refund: {:?}", e);
		}
	}

	#[test]
	fn fails_building_refund_with_invalid_amount() {
		match RefundBuilder::new(vec![1; 32], payer_pubkey(), MAX_VALUE_MSAT + 1) {
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, Bolt12SemanticError::InvalidAmount),
		}
	}

	#[test]
	fn builds_refund_with_metadata_derived() {
		let node_id = payer_pubkey();
		let expanded_key = ExpandedKey::new(&KeyMaterial([42; 32]));
		let entropy = FixedEntropy {};
		let nonce = Nonce::from_entropy_source(&entropy);
		let secp_ctx = Secp256k1::new();
		let payment_id = PaymentId([1; 32]);

		let refund = RefundBuilder
			::deriving_payer_id(node_id, &expanded_key, nonce, &secp_ctx, 1000, payment_id)
			.unwrap()
			.build().unwrap();
		assert_eq!(refund.payer_id(), node_id);

		// Fails verification with altered fields
		let invoice = refund
			.respond_with_no_std(payment_paths(), payment_hash(), recipient_pubkey(), now())
			.unwrap()
			.build().unwrap()
			.sign(recipient_sign).unwrap();
		match invoice.verify_using_metadata(&expanded_key, &secp_ctx) {
			Ok(payment_id) => assert_eq!(payment_id, PaymentId([1; 32])),
			Err(()) => panic!("verification failed"),
		}
		assert!(
			invoice.verify_using_payer_data(payment_id, nonce, &expanded_key, &secp_ctx).is_err()
		);

		let mut tlv_stream = refund.as_tlv_stream();
		tlv_stream.2.amount = Some(2000);

		let mut encoded_refund = Vec::new();
		tlv_stream.write(&mut encoded_refund).unwrap();

		let invoice = Refund::try_from(encoded_refund).unwrap()
			.respond_with_no_std(payment_paths(), payment_hash(), recipient_pubkey(), now())
			.unwrap()
			.build().unwrap()
			.sign(recipient_sign).unwrap();
		assert!(invoice.verify_using_metadata(&expanded_key, &secp_ctx).is_err());

		// Fails verification with altered metadata
		let mut tlv_stream = refund.as_tlv_stream();
		let metadata = tlv_stream.0.metadata.unwrap().iter().copied().rev().collect();
		tlv_stream.0.metadata = Some(&metadata);

		let mut encoded_refund = Vec::new();
		tlv_stream.write(&mut encoded_refund).unwrap();

		let invoice = Refund::try_from(encoded_refund).unwrap()
			.respond_with_no_std(payment_paths(), payment_hash(), recipient_pubkey(), now())
			.unwrap()
			.build().unwrap()
			.sign(recipient_sign).unwrap();
		assert!(invoice.verify_using_metadata(&expanded_key, &secp_ctx).is_err());
	}

	#[test]
	fn builds_refund_with_derived_payer_id() {
		let node_id = payer_pubkey();
		let expanded_key = ExpandedKey::new(&KeyMaterial([42; 32]));
		let entropy = FixedEntropy {};
		let nonce = Nonce::from_entropy_source(&entropy);
		let secp_ctx = Secp256k1::new();
		let payment_id = PaymentId([1; 32]);

		let blinded_path = BlindedPath {
			introduction_node: IntroductionNode::NodeId(pubkey(40)),
			blinding_point: pubkey(41),
			blinded_hops: vec![
				BlindedHop { blinded_node_id: pubkey(43), encrypted_payload: vec![0; 43] },
				BlindedHop { blinded_node_id: node_id, encrypted_payload: vec![0; 44] },
			],
		};

		let refund = RefundBuilder
			::deriving_payer_id(node_id, &expanded_key, nonce, &secp_ctx, 1000, payment_id)
			.unwrap()
			.path(blinded_path)
			.build().unwrap();
		assert_ne!(refund.payer_id(), node_id);

		let invoice = refund
			.respond_with_no_std(payment_paths(), payment_hash(), recipient_pubkey(), now())
			.unwrap()
			.build().unwrap()
			.sign(recipient_sign).unwrap();
		assert!(invoice.verify_using_metadata(&expanded_key, &secp_ctx).is_err());
		assert!(
			invoice.verify_using_payer_data(payment_id, nonce, &expanded_key, &secp_ctx).is_ok()
		);

		// Fails verification with altered fields
		let mut tlv_stream = refund.as_tlv_stream();
		tlv_stream.2.amount = Some(2000);

		let mut encoded_refund = Vec::new();
		tlv_stream.write(&mut encoded_refund).unwrap();

		let invoice = Refund::try_from(encoded_refund).unwrap()
			.respond_with_no_std(payment_paths(), payment_hash(), recipient_pubkey(), now())
			.unwrap()
			.build().unwrap()
			.sign(recipient_sign).unwrap();
		assert!(
			invoice.verify_using_payer_data(payment_id, nonce, &expanded_key, &secp_ctx).is_err()
		);

		// Fails verification with altered payer_id
		let mut tlv_stream = refund.as_tlv_stream();
		let payer_id = pubkey(1);
		tlv_stream.2.payer_id = Some(&payer_id);

		let mut encoded_refund = Vec::new();
		tlv_stream.write(&mut encoded_refund).unwrap();

		let invoice = Refund::try_from(encoded_refund).unwrap()
			.respond_with_no_std(payment_paths(), payment_hash(), recipient_pubkey(), now())
			.unwrap()
			.build().unwrap()
			.sign(recipient_sign).unwrap();
		assert!(
			invoice.verify_using_payer_data(payment_id, nonce, &expanded_key, &secp_ctx).is_err()
		);
	}

	#[test]
	fn builds_refund_with_absolute_expiry() {
		let future_expiry = Duration::from_secs(u64::max_value());
		let past_expiry = Duration::from_secs(0);
		let now = future_expiry - Duration::from_secs(1_000);

		let refund = RefundBuilder::new(vec![1; 32], payer_pubkey(), 1000).unwrap()
			.absolute_expiry(future_expiry)
			.build()
			.unwrap();
		let (_, tlv_stream, _) = refund.as_tlv_stream();
		#[cfg(feature = "std")]
		assert!(!refund.is_expired());
		assert!(!refund.is_expired_no_std(now));
		assert_eq!(refund.absolute_expiry(), Some(future_expiry));
		assert_eq!(tlv_stream.absolute_expiry, Some(future_expiry.as_secs()));

		let refund = RefundBuilder::new(vec![1; 32], payer_pubkey(), 1000).unwrap()
			.absolute_expiry(future_expiry)
			.absolute_expiry(past_expiry)
			.build()
			.unwrap();
		let (_, tlv_stream, _) = refund.as_tlv_stream();
		#[cfg(feature = "std")]
		assert!(refund.is_expired());
		assert!(refund.is_expired_no_std(now));
		assert_eq!(refund.absolute_expiry(), Some(past_expiry));
		assert_eq!(tlv_stream.absolute_expiry, Some(past_expiry.as_secs()));
	}

	#[test]
	fn builds_refund_with_paths() {
		let paths = vec![
			BlindedPath {
				introduction_node: IntroductionNode::NodeId(pubkey(40)),
				blinding_point: pubkey(41),
				blinded_hops: vec![
					BlindedHop { blinded_node_id: pubkey(43), encrypted_payload: vec![0; 43] },
					BlindedHop { blinded_node_id: pubkey(44), encrypted_payload: vec![0; 44] },
				],
			},
			BlindedPath {
				introduction_node: IntroductionNode::NodeId(pubkey(40)),
				blinding_point: pubkey(41),
				blinded_hops: vec![
					BlindedHop { blinded_node_id: pubkey(45), encrypted_payload: vec![0; 45] },
					BlindedHop { blinded_node_id: pubkey(46), encrypted_payload: vec![0; 46] },
				],
			},
		];

		let refund = RefundBuilder::new(vec![1; 32], payer_pubkey(), 1000).unwrap()
			.path(paths[0].clone())
			.path(paths[1].clone())
			.build()
			.unwrap();
		let (_, _, invoice_request_tlv_stream) = refund.as_tlv_stream();
		assert_eq!(refund.payer_id(), pubkey(42));
		assert_eq!(refund.paths(), paths.as_slice());
		assert_ne!(pubkey(42), pubkey(44));
		assert_eq!(invoice_request_tlv_stream.payer_id, Some(&pubkey(42)));
		assert_eq!(invoice_request_tlv_stream.paths, Some(&paths));
	}

	#[test]
	fn builds_refund_with_issuer() {
		let refund = RefundBuilder::new(vec![1; 32], payer_pubkey(), 1000).unwrap()
			.issuer("bar".into())
			.build()
			.unwrap();
		let (_, tlv_stream, _) = refund.as_tlv_stream();
		assert_eq!(refund.issuer(), Some(PrintableString("bar")));
		assert_eq!(tlv_stream.issuer, Some(&String::from("bar")));

		let refund = RefundBuilder::new(vec![1; 32], payer_pubkey(), 1000).unwrap()
			.issuer("bar".into())
			.issuer("baz".into())
			.build()
			.unwrap();
		let (_, tlv_stream, _) = refund.as_tlv_stream();
		assert_eq!(refund.issuer(), Some(PrintableString("baz")));
		assert_eq!(tlv_stream.issuer, Some(&String::from("baz")));
	}

	#[test]
	fn builds_refund_with_chain() {
		let mainnet = ChainHash::using_genesis_block(Network::Bitcoin);
		let testnet = ChainHash::using_genesis_block(Network::Testnet);

		let refund = RefundBuilder::new(vec![1; 32], payer_pubkey(), 1000).unwrap()
			.chain(Network::Bitcoin)
			.build().unwrap();
		let (_, _, tlv_stream) = refund.as_tlv_stream();
		assert_eq!(refund.chain(), mainnet);
		assert_eq!(tlv_stream.chain, None);

		let refund = RefundBuilder::new(vec![1; 32], payer_pubkey(), 1000).unwrap()
			.chain(Network::Testnet)
			.build().unwrap();
		let (_, _, tlv_stream) = refund.as_tlv_stream();
		assert_eq!(refund.chain(), testnet);
		assert_eq!(tlv_stream.chain, Some(&testnet));

		let refund = RefundBuilder::new(vec![1; 32], payer_pubkey(), 1000).unwrap()
			.chain(Network::Regtest)
			.chain(Network::Testnet)
			.build().unwrap();
		let (_, _, tlv_stream) = refund.as_tlv_stream();
		assert_eq!(refund.chain(), testnet);
		assert_eq!(tlv_stream.chain, Some(&testnet));
	}

	#[test]
	fn builds_refund_with_quantity() {
		let refund = RefundBuilder::new(vec![1; 32], payer_pubkey(), 1000).unwrap()
			.quantity(10)
			.build().unwrap();
		let (_, _, tlv_stream) = refund.as_tlv_stream();
		assert_eq!(refund.quantity(), Some(10));
		assert_eq!(tlv_stream.quantity, Some(10));

		let refund = RefundBuilder::new(vec![1; 32], payer_pubkey(), 1000).unwrap()
			.quantity(10)
			.quantity(1)
			.build().unwrap();
		let (_, _, tlv_stream) = refund.as_tlv_stream();
		assert_eq!(refund.quantity(), Some(1));
		assert_eq!(tlv_stream.quantity, Some(1));
	}

	#[test]
	fn builds_refund_with_payer_note() {
		let refund = RefundBuilder::new(vec![1; 32], payer_pubkey(), 1000).unwrap()
			.payer_note("bar".into())
			.build().unwrap();
		let (_, _, tlv_stream) = refund.as_tlv_stream();
		assert_eq!(refund.payer_note(), Some(PrintableString("bar")));
		assert_eq!(tlv_stream.payer_note, Some(&String::from("bar")));

		let refund = RefundBuilder::new(vec![1; 32], payer_pubkey(), 1000).unwrap()
			.payer_note("bar".into())
			.payer_note("baz".into())
			.build().unwrap();
		let (_, _, tlv_stream) = refund.as_tlv_stream();
		assert_eq!(refund.payer_note(), Some(PrintableString("baz")));
		assert_eq!(tlv_stream.payer_note, Some(&String::from("baz")));
	}

	#[test]
	fn fails_responding_with_unknown_required_features() {
		match RefundBuilder::new(vec![1; 32], payer_pubkey(), 1000).unwrap()
			.features_unchecked(InvoiceRequestFeatures::unknown())
			.build().unwrap()
			.respond_with_no_std(payment_paths(), payment_hash(), recipient_pubkey(), now())
		{
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, Bolt12SemanticError::UnknownRequiredFeatures),
		}
	}

	#[test]
	fn parses_refund_with_metadata() {
		let refund = RefundBuilder::new(vec![1; 32], payer_pubkey(), 1000).unwrap()
			.build().unwrap();
		if let Err(e) = refund.to_string().parse::<Refund>() {
			panic!("error parsing refund: {:?}", e);
		}

		let mut tlv_stream = refund.as_tlv_stream();
		tlv_stream.0.metadata = None;

		match Refund::try_from(tlv_stream.to_bytes()) {
			Ok(_) => panic!("expected error"),
			Err(e) => {
				assert_eq!(e, Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::MissingPayerMetadata));
			},
		}
	}

	#[test]
	fn parses_refund_with_description() {
		let refund = RefundBuilder::new(vec![1; 32], payer_pubkey(), 1000).unwrap()
			.build().unwrap();
		if let Err(e) = refund.to_string().parse::<Refund>() {
			panic!("error parsing refund: {:?}", e);
		}

		let mut tlv_stream = refund.as_tlv_stream();
		tlv_stream.1.description = None;

		match Refund::try_from(tlv_stream.to_bytes()) {
			Ok(_) => panic!("expected error"),
			Err(e) => {
				assert_eq!(e, Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::MissingDescription));
			},
		}
	}

	#[test]
	fn parses_refund_with_amount() {
		let refund = RefundBuilder::new(vec![1; 32], payer_pubkey(), 1000).unwrap()
			.build().unwrap();
		if let Err(e) = refund.to_string().parse::<Refund>() {
			panic!("error parsing refund: {:?}", e);
		}

		let mut tlv_stream = refund.as_tlv_stream();
		tlv_stream.2.amount = None;

		match Refund::try_from(tlv_stream.to_bytes()) {
			Ok(_) => panic!("expected error"),
			Err(e) => {
				assert_eq!(e, Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::MissingAmount));
			},
		}

		let mut tlv_stream = refund.as_tlv_stream();
		tlv_stream.2.amount = Some(MAX_VALUE_MSAT + 1);

		match Refund::try_from(tlv_stream.to_bytes()) {
			Ok(_) => panic!("expected error"),
			Err(e) => {
				assert_eq!(e, Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::InvalidAmount));
			},
		}
	}

	#[test]
	fn parses_refund_with_payer_id() {
		let refund = RefundBuilder::new(vec![1; 32], payer_pubkey(), 1000).unwrap()
			.build().unwrap();
		if let Err(e) = refund.to_string().parse::<Refund>() {
			panic!("error parsing refund: {:?}", e);
		}

		let mut tlv_stream = refund.as_tlv_stream();
		tlv_stream.2.payer_id = None;

		match Refund::try_from(tlv_stream.to_bytes()) {
			Ok(_) => panic!("expected error"),
			Err(e) => {
				assert_eq!(e, Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::MissingPayerId));
			},
		}
	}

	#[test]
	fn parses_refund_with_optional_fields() {
		let past_expiry = Duration::from_secs(0);
		let paths = vec![
			BlindedPath {
				introduction_node: IntroductionNode::NodeId(pubkey(40)),
				blinding_point: pubkey(41),
				blinded_hops: vec![
					BlindedHop { blinded_node_id: pubkey(43), encrypted_payload: vec![0; 43] },
					BlindedHop { blinded_node_id: pubkey(44), encrypted_payload: vec![0; 44] },
				],
			},
			BlindedPath {
				introduction_node: IntroductionNode::NodeId(pubkey(40)),
				blinding_point: pubkey(41),
				blinded_hops: vec![
					BlindedHop { blinded_node_id: pubkey(45), encrypted_payload: vec![0; 45] },
					BlindedHop { blinded_node_id: pubkey(46), encrypted_payload: vec![0; 46] },
				],
			},
		];

		let refund = RefundBuilder::new(vec![1; 32], payer_pubkey(), 1000).unwrap()
			.absolute_expiry(past_expiry)
			.issuer("bar".into())
			.path(paths[0].clone())
			.path(paths[1].clone())
			.chain(Network::Testnet)
			.features_unchecked(InvoiceRequestFeatures::unknown())
			.quantity(10)
			.payer_note("baz".into())
			.build()
			.unwrap();
		match refund.to_string().parse::<Refund>() {
			Ok(refund) => {
				assert_eq!(refund.absolute_expiry(), Some(past_expiry));
				#[cfg(feature = "std")]
				assert!(refund.is_expired());
				assert_eq!(refund.paths(), &paths[..]);
				assert_eq!(refund.issuer(), Some(PrintableString("bar")));
				assert_eq!(refund.chain(), ChainHash::using_genesis_block(Network::Testnet));
				assert_eq!(refund.features(), &InvoiceRequestFeatures::unknown());
				assert_eq!(refund.quantity(), Some(10));
				assert_eq!(refund.payer_note(), Some(PrintableString("baz")));
			},
			Err(e) => panic!("error parsing refund: {:?}", e),
		}
	}

	#[test]
	fn fails_parsing_refund_with_unexpected_fields() {
		let refund = RefundBuilder::new(vec![1; 32], payer_pubkey(), 1000).unwrap()
			.build().unwrap();
		if let Err(e) = refund.to_string().parse::<Refund>() {
			panic!("error parsing refund: {:?}", e);
		}

		let metadata = vec![42; 32];
		let mut tlv_stream = refund.as_tlv_stream();
		tlv_stream.1.metadata = Some(&metadata);

		match Refund::try_from(tlv_stream.to_bytes()) {
			Ok(_) => panic!("expected error"),
			Err(e) => {
				assert_eq!(e, Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::UnexpectedMetadata));
			},
		}

		let chains = vec![ChainHash::using_genesis_block(Network::Testnet)];
		let mut tlv_stream = refund.as_tlv_stream();
		tlv_stream.1.chains = Some(&chains);

		match Refund::try_from(tlv_stream.to_bytes()) {
			Ok(_) => panic!("expected error"),
			Err(e) => {
				assert_eq!(e, Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::UnexpectedChain));
			},
		}

		let mut tlv_stream = refund.as_tlv_stream();
		tlv_stream.1.currency = Some(&b"USD");
		tlv_stream.1.amount = Some(1000);

		match Refund::try_from(tlv_stream.to_bytes()) {
			Ok(_) => panic!("expected error"),
			Err(e) => {
				assert_eq!(e, Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::UnexpectedAmount));
			},
		}

		let features = OfferFeatures::unknown();
		let mut tlv_stream = refund.as_tlv_stream();
		tlv_stream.1.features = Some(&features);

		match Refund::try_from(tlv_stream.to_bytes()) {
			Ok(_) => panic!("expected error"),
			Err(e) => {
				assert_eq!(e, Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::UnexpectedFeatures));
			},
		}

		let mut tlv_stream = refund.as_tlv_stream();
		tlv_stream.1.quantity_max = Some(10);

		match Refund::try_from(tlv_stream.to_bytes()) {
			Ok(_) => panic!("expected error"),
			Err(e) => {
				assert_eq!(e, Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::UnexpectedQuantity));
			},
		}

		let node_id = payer_pubkey();
		let mut tlv_stream = refund.as_tlv_stream();
		tlv_stream.1.node_id = Some(&node_id);

		match Refund::try_from(tlv_stream.to_bytes()) {
			Ok(_) => panic!("expected error"),
			Err(e) => {
				assert_eq!(e, Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::UnexpectedSigningPubkey));
			},
		}
	}

	#[test]
	fn fails_parsing_refund_with_extra_tlv_records() {
		let secp_ctx = Secp256k1::new();
		let keys = Keypair::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[42; 32]).unwrap());
		let refund = RefundBuilder::new(vec![1; 32], keys.public_key(), 1000).unwrap()
			.build().unwrap();

		let mut encoded_refund = Vec::new();
		refund.write(&mut encoded_refund).unwrap();
		BigSize(1002).write(&mut encoded_refund).unwrap();
		BigSize(32).write(&mut encoded_refund).unwrap();
		[42u8; 32].write(&mut encoded_refund).unwrap();

		match Refund::try_from(encoded_refund) {
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, Bolt12ParseError::Decode(DecodeError::InvalidValue)),
		}
	}
}
