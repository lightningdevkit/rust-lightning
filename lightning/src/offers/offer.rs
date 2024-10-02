// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Data structures and encoding for `offer` messages.
//!
//! An [`Offer`] represents an "offer to be paid." It is typically constructed by a merchant and
//! published as a QR code to be scanned by a customer. The customer uses the offer to request an
//! invoice from the merchant to be paid.
//!
//! # Example
//!
//! ```
//! extern crate bitcoin;
//! extern crate core;
//! extern crate lightning;
//!
//! use core::convert::TryFrom;
//! use core::num::NonZeroU64;
//! use core::time::Duration;
//!
//! use bitcoin::secp256k1::{Keypair, PublicKey, Secp256k1, SecretKey};
//! use lightning::offers::offer::{Offer, OfferBuilder, Quantity};
//! use lightning::offers::parse::Bolt12ParseError;
//! use lightning::util::ser::{Readable, Writeable};
//!
//! # use lightning::blinded_path::message::BlindedMessagePath;
//! # #[cfg(feature = "std")]
//! # use std::time::SystemTime;
//! #
//! # fn create_blinded_path() -> BlindedMessagePath { unimplemented!() }
//! # fn create_another_blinded_path() -> BlindedMessagePath { unimplemented!() }
//! #
//! # #[cfg(feature = "std")]
//! # fn build() -> Result<(), Bolt12ParseError> {
//! let secp_ctx = Secp256k1::new();
//! let keys = Keypair::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[42; 32]).unwrap());
//! let pubkey = PublicKey::from(keys);
//!
//! let expiration = SystemTime::now() + Duration::from_secs(24 * 60 * 60);
//! let offer = OfferBuilder::new(pubkey)
//!     .description("coffee, large".to_string())
//!     .amount_msats(20_000)
//!     .supported_quantity(Quantity::Unbounded)
//!     .absolute_expiry(expiration.duration_since(SystemTime::UNIX_EPOCH).unwrap())
//!     .issuer("Foo Bar".to_string())
//!     .path(create_blinded_path())
//!     .path(create_another_blinded_path())
//!     .build()?;
//!
//! // Encode as a bech32 string for use in a QR code.
//! let encoded_offer = offer.to_string();
//!
//! // Parse from a bech32 string after scanning from a QR code.
//! let offer = encoded_offer.parse::<Offer>()?;
//!
//! // Encode offer as raw bytes.
//! let mut bytes = Vec::new();
//! offer.write(&mut bytes).unwrap();
//!
//! // Decode raw bytes into an offer.
//! let offer = Offer::try_from(bytes)?;
//! # Ok(())
//! # }
//! ```
//!
//! # Note
//!
//! If constructing an [`Offer`] for use with a [`ChannelManager`], use
//! [`ChannelManager::create_offer_builder`] instead of [`OfferBuilder::new`].
//!
//! [`ChannelManager`]: crate::ln::channelmanager::ChannelManager
//! [`ChannelManager::create_offer_builder`]: crate::ln::channelmanager::ChannelManager::create_offer_builder

use bitcoin::constants::ChainHash;
use bitcoin::network::Network;
use bitcoin::secp256k1::{Keypair, PublicKey, Secp256k1, self};
#[cfg(feature = "serde")]
use serde::{Serialize, Deserialize};
use core::hash::{Hash, Hasher};
use core::num::NonZeroU64;
use core::str::FromStr;
use core::time::Duration;
use crate::io;
use crate::blinded_path::message::BlindedMessagePath;
use crate::ln::channelmanager::PaymentId;
use crate::ln::features::OfferFeatures;
use crate::ln::inbound_payment::{ExpandedKey, IV_LEN};
use crate::ln::msgs::{DecodeError, MAX_VALUE_MSAT};
use crate::offers::merkle::{TaggedHash, TlvStream};
use crate::offers::nonce::Nonce;
use crate::offers::parse::{Bech32Encode, Bolt12ParseError, Bolt12SemanticError, ParsedMessage};
use crate::offers::signer::{Metadata, MetadataMaterial, self};
use crate::util::ser::{HighZeroBytesDroppedBigSize, Readable, WithoutLength, Writeable, Writer};
use crate::util::string::PrintableString;

#[cfg(not(c_bindings))]
use {
	crate::offers::invoice_request::{DerivedPayerSigningPubkey, ExplicitPayerSigningPubkey, InvoiceRequestBuilder},
};
#[cfg(c_bindings)]
use {
	crate::offers::invoice_request::{InvoiceRequestWithDerivedPayerSigningPubkeyBuilder, InvoiceRequestWithExplicitPayerSigningPubkeyBuilder},
};

#[allow(unused_imports)]
use crate::prelude::*;

#[cfg(feature = "std")]
use std::time::SystemTime;

pub(super) const IV_BYTES_WITH_METADATA: &[u8; IV_LEN] = b"LDK Offer ~~~~~~";
pub(super) const IV_BYTES_WITHOUT_METADATA: &[u8; IV_LEN] = b"LDK Offer v2~~~~";

/// An identifier for an [`Offer`] built using [`DerivedMetadata`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct OfferId(pub [u8; 32]);

impl OfferId {
	const ID_TAG: &'static str = "LDK Offer ID";

	fn from_valid_offer_tlv_stream(bytes: &[u8]) -> Self {
		let tagged_hash = TaggedHash::from_valid_tlv_stream_bytes(Self::ID_TAG, bytes);
		Self(tagged_hash.to_bytes())
	}

	fn from_valid_invreq_tlv_stream(bytes: &[u8]) -> Self {
		let tlv_stream = TlvStream::new(bytes).range(OFFER_TYPES);
		let tagged_hash = TaggedHash::from_tlv_stream(Self::ID_TAG, tlv_stream);
		Self(tagged_hash.to_bytes())
	}
}

impl Writeable for OfferId {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		self.0.write(w)
	}
}

impl Readable for OfferId {
	fn read<R: io::Read>(r: &mut R) -> Result<Self, DecodeError> {
		Ok(OfferId(Readable::read(r)?))
	}
}

/// Builds an [`Offer`] for the "offer to be paid" flow.
///
/// See [module-level documentation] for usage.
///
/// This is not exported to bindings users as builder patterns don't map outside of move semantics.
///
/// [module-level documentation]: self
pub struct OfferBuilder<'a, M: MetadataStrategy, T: secp256k1::Signing> {
	offer: OfferContents,
	metadata_strategy: core::marker::PhantomData<M>,
	secp_ctx: Option<&'a Secp256k1<T>>,
}

/// Builds an [`Offer`] for the "offer to be paid" flow.
///
/// See [module-level documentation] for usage.
///
/// [module-level documentation]: self
#[cfg(c_bindings)]
#[derive(Clone)]
pub struct OfferWithExplicitMetadataBuilder<'a> {
	offer: OfferContents,
	metadata_strategy: core::marker::PhantomData<ExplicitMetadata>,
	secp_ctx: Option<&'a Secp256k1<secp256k1::All>>,
}

/// Builds an [`Offer`] for the "offer to be paid" flow.
///
/// See [module-level documentation] for usage.
///
/// [module-level documentation]: self
#[cfg(c_bindings)]
#[derive(Clone)]
pub struct OfferWithDerivedMetadataBuilder<'a> {
	offer: OfferContents,
	metadata_strategy: core::marker::PhantomData<DerivedMetadata>,
	secp_ctx: Option<&'a Secp256k1<secp256k1::All>>,
}

/// Indicates how [`Offer::metadata`] may be set.
///
/// This is not exported to bindings users as builder patterns don't map outside of move semantics.
pub trait MetadataStrategy {}

/// [`Offer::metadata`] may be explicitly set or left empty.
///
/// This is not exported to bindings users as builder patterns don't map outside of move semantics.
pub struct ExplicitMetadata {}

/// [`Offer::metadata`] will be derived.
///
/// This is not exported to bindings users as builder patterns don't map outside of move semantics.
pub struct DerivedMetadata {}

impl MetadataStrategy for ExplicitMetadata {}

impl MetadataStrategy for DerivedMetadata {}

macro_rules! offer_explicit_metadata_builder_methods { (
	$self: ident, $self_type: ty, $return_type: ty, $return_value: expr
) => {
	/// Creates a new builder for an offer using the `signing_pubkey` for signing invoices. The
	/// associated secret key must be remembered while the offer is valid.
	///
	/// Use a different pubkey per offer to avoid correlating offers.
	///
	/// # Note
	///
	/// If constructing an [`Offer`] for use with a [`ChannelManager`], use
	/// [`ChannelManager::create_offer_builder`] instead of [`OfferBuilder::new`].
	///
	/// [`ChannelManager`]: crate::ln::channelmanager::ChannelManager
	/// [`ChannelManager::create_offer_builder`]: crate::ln::channelmanager::ChannelManager::create_offer_builder
	pub fn new(signing_pubkey: PublicKey) -> Self {
		Self {
			offer: OfferContents {
				chains: None, metadata: None, amount: None, description: None,
				features: OfferFeatures::empty(), absolute_expiry: None, issuer: None, paths: None,
				supported_quantity: Quantity::One, issuer_signing_pubkey: Some(signing_pubkey),
			},
			metadata_strategy: core::marker::PhantomData,
			secp_ctx: None,
		}
	}

	/// Sets the [`Offer::metadata`] to the given bytes.
	///
	/// Successive calls to this method will override the previous setting.
	pub fn metadata(mut $self: $self_type, metadata: Vec<u8>) -> Result<$return_type, Bolt12SemanticError> {
		$self.offer.metadata = Some(Metadata::Bytes(metadata));
		Ok($return_value)
	}
} }

macro_rules! offer_derived_metadata_builder_methods { ($secp_context: ty) => {
	/// Similar to [`OfferBuilder::new`] except, if [`OfferBuilder::path`] is called, the signing
	/// pubkey is derived from the given [`ExpandedKey`] and [`Nonce`]. This provides recipient
	/// privacy by using a different signing pubkey for each offer. Otherwise, the provided
	/// `node_id` is used for [`Offer::issuer_signing_pubkey`].
	///
	/// Also, sets the metadata when [`OfferBuilder::build`] is called such that it can be used by
	/// [`InvoiceRequest::verify_using_metadata`] to determine if the request was produced for the
	/// offer given an [`ExpandedKey`]. However, if [`OfferBuilder::path`] is called, then the
	/// metadata will not be set and must be included in each [`BlindedMessagePath`] instead. In this case,
	/// use [`InvoiceRequest::verify_using_recipient_data`].
	///
	/// [`InvoiceRequest::verify_using_metadata`]: crate::offers::invoice_request::InvoiceRequest::verify_using_metadata
	/// [`InvoiceRequest::verify_using_recipient_data`]: crate::offers::invoice_request::InvoiceRequest::verify_using_recipient_data
	/// [`ExpandedKey`]: crate::ln::inbound_payment::ExpandedKey
	pub fn deriving_signing_pubkey(
		node_id: PublicKey, expanded_key: &ExpandedKey, nonce: Nonce,
		secp_ctx: &'a Secp256k1<$secp_context>
	) -> Self {
		let derivation_material = MetadataMaterial::new(nonce, expanded_key, None);
		let metadata = Metadata::DerivedSigningPubkey(derivation_material);
		Self {
			offer: OfferContents {
				chains: None, metadata: Some(metadata), amount: None, description: None,
				features: OfferFeatures::empty(), absolute_expiry: None, issuer: None, paths: None,
				supported_quantity: Quantity::One, issuer_signing_pubkey: Some(node_id),
			},
			metadata_strategy: core::marker::PhantomData,
			secp_ctx: Some(secp_ctx),
		}
	}
} }

macro_rules! offer_builder_methods { (
	$self: ident, $self_type: ty, $return_type: ty, $return_value: expr $(, $self_mut: tt)?
) => {
	/// Adds the chain hash of the given [`Network`] to [`Offer::chains`]. If not called,
	/// the chain hash of [`Network::Bitcoin`] is assumed to be the only one supported.
	///
	/// See [`Offer::chains`] on how this relates to the payment currency.
	///
	/// Successive calls to this method will add another chain hash.
	pub fn chain($self: $self_type, network: Network) -> $return_type {
		$self.chain_hash(ChainHash::using_genesis_block(network))
	}

	/// Adds the [`ChainHash`] to [`Offer::chains`]. If not called, the chain hash of
	/// [`Network::Bitcoin`] is assumed to be the only one supported.
	///
	/// See [`Offer::chains`] on how this relates to the payment currency.
	///
	/// Successive calls to this method will add another chain hash.
	pub(crate) fn chain_hash($($self_mut)* $self: $self_type, chain: ChainHash) -> $return_type {
		let chains = $self.offer.chains.get_or_insert_with(Vec::new);
		if !chains.contains(&chain) {
			chains.push(chain);
		}

		$return_value
	}

	/// Sets the [`Offer::amount`] as an [`Amount::Bitcoin`].
	///
	/// Successive calls to this method will override the previous setting.
	pub fn amount_msats($self: $self_type, amount_msats: u64) -> $return_type {
		$self.amount(Amount::Bitcoin { amount_msats })
	}

	/// Sets the [`Offer::amount`].
	///
	/// Successive calls to this method will override the previous setting.
	pub(super) fn amount($($self_mut)* $self: $self_type, amount: Amount) -> $return_type {
		$self.offer.amount = Some(amount);
		$return_value
	}

	/// Sets the [`Offer::absolute_expiry`] as seconds since the Unix epoch.
	#[cfg_attr(feature = "std", doc = "Any expiry that has already passed is valid and can be checked for using [`Offer::is_expired`].")]
	///
	/// Successive calls to this method will override the previous setting.
	pub fn absolute_expiry($($self_mut)* $self: $self_type, absolute_expiry: Duration) -> $return_type {
		$self.offer.absolute_expiry = Some(absolute_expiry);
		$return_value
	}

	/// Sets the [`Offer::description`].
	///
	/// Successive calls to this method will override the previous setting.
	pub fn description($($self_mut)* $self: $self_type, description: String) -> $return_type {
		$self.offer.description = Some(description);
		$return_value
	}

	/// Sets the [`Offer::issuer`].
	///
	/// Successive calls to this method will override the previous setting.
	pub fn issuer($($self_mut)* $self: $self_type, issuer: String) -> $return_type {
		$self.offer.issuer = Some(issuer);
		$return_value
	}

	/// Adds a blinded path to [`Offer::paths`]. Must include at least one path if only connected by
	/// private channels or if [`Offer::issuer_signing_pubkey`] is not a public node id.
	///
	/// Successive calls to this method will add another blinded path. Caller is responsible for not
	/// adding duplicate paths.
	pub fn path($($self_mut)* $self: $self_type, path: BlindedMessagePath) -> $return_type {
		$self.offer.paths.get_or_insert_with(Vec::new).push(path);
		$return_value
	}

	/// Sets the quantity of items for [`Offer::supported_quantity`]. If not called, defaults to
	/// [`Quantity::One`].
	///
	/// Successive calls to this method will override the previous setting.
	pub fn supported_quantity($($self_mut)* $self: $self_type, quantity: Quantity) -> $return_type {
		$self.offer.supported_quantity = quantity;
		$return_value
	}

	/// Builds an [`Offer`] from the builder's settings.
	pub fn build($($self_mut)* $self: $self_type) -> Result<Offer, Bolt12SemanticError> {
		match $self.offer.amount {
			Some(Amount::Bitcoin { amount_msats }) => {
				if amount_msats > MAX_VALUE_MSAT {
					return Err(Bolt12SemanticError::InvalidAmount);
				}
			},
			Some(Amount::Currency { .. }) => return Err(Bolt12SemanticError::UnsupportedCurrency),
			None => {},
		}

		if $self.offer.amount.is_some() && $self.offer.description.is_none() {
			$self.offer.description = Some(String::new());
		}

		if let Some(chains) = &$self.offer.chains {
			if chains.len() == 1 && chains[0] == $self.offer.implied_chain() {
				$self.offer.chains = None;
			}
		}

		Ok($self.build_without_checks())
	}

	fn build_without_checks($($self_mut)* $self: $self_type) -> Offer {
		if let Some(mut metadata) = $self.offer.metadata.take() {
			// Create the metadata for stateless verification of an InvoiceRequest.
			if metadata.has_derivation_material() {

				// Don't derive keys if no blinded paths were given since this means the signing
				// pubkey must be the node id of an announced node.
				let iv_bytes = if $self.offer.paths.is_none() {
					metadata = metadata.without_keys();
					IV_BYTES_WITH_METADATA
				} else {
					IV_BYTES_WITHOUT_METADATA
				};

				let mut tlv_stream = $self.offer.as_tlv_stream();
				debug_assert_eq!(tlv_stream.metadata, None);
				tlv_stream.metadata = None;
				if metadata.derives_recipient_keys() {
					tlv_stream.issuer_id = None;
				}

				// Either replace the signing pubkey with the derived pubkey or include the metadata
				// for verification. In the former case, the blinded paths must include
				// `OffersContext::InvoiceRequest` instead.
				let (derived_metadata, keys) =
					metadata.derive_from(iv_bytes, tlv_stream, $self.secp_ctx);
				match keys {
					Some(keys) => $self.offer.issuer_signing_pubkey = Some(keys.public_key()),
					None => $self.offer.metadata = Some(derived_metadata),
				}
			} else {
				$self.offer.metadata = Some(metadata);
			}
		}

		let mut bytes = Vec::new();
		$self.offer.write(&mut bytes).unwrap();

		let id = OfferId::from_valid_offer_tlv_stream(&bytes);

		Offer {
			bytes,
			#[cfg(not(c_bindings))]
			contents: $self.offer,
			#[cfg(c_bindings)]
			contents: $self.offer.clone(),
			id,
		}
	}
} }

#[cfg(test)]
macro_rules! offer_builder_test_methods { (
	$self: ident, $self_type: ty, $return_type: ty, $return_value: expr $(, $self_mut: tt)?
) => {
	#[cfg_attr(c_bindings, allow(dead_code))]
	fn features_unchecked($($self_mut)* $self: $self_type, features: OfferFeatures) -> $return_type {
		$self.offer.features = features;
		$return_value
	}

	#[cfg_attr(c_bindings, allow(dead_code))]
	pub(crate) fn clear_chains($($self_mut)* $self: $self_type) -> $return_type {
		$self.offer.chains = None;
		$return_value
	}

	#[cfg_attr(c_bindings, allow(dead_code))]
	pub(crate) fn clear_paths($($self_mut)* $self: $self_type) -> $return_type {
		$self.offer.paths = None;
		$return_value
	}

	#[cfg_attr(c_bindings, allow(dead_code))]
	pub(crate) fn clear_issuer_signing_pubkey($($self_mut)* $self: $self_type) -> $return_type {
		$self.offer.issuer_signing_pubkey = None;
		$return_value
	}

	#[cfg_attr(c_bindings, allow(dead_code))]
	pub(super) fn build_unchecked($self: $self_type) -> Offer {
		$self.build_without_checks()
	}
} }

impl<'a, M: MetadataStrategy, T: secp256k1::Signing> OfferBuilder<'a, M, T> {
	offer_builder_methods!(self, Self, Self, self, mut);

	#[cfg(test)]
	offer_builder_test_methods!(self, Self, Self, self, mut);
}

impl<'a> OfferBuilder<'a, ExplicitMetadata, secp256k1::SignOnly> {
	offer_explicit_metadata_builder_methods!(self, Self, Self, self);
}

impl<'a, T: secp256k1::Signing> OfferBuilder<'a, DerivedMetadata, T> {
	offer_derived_metadata_builder_methods!(T);
}

#[cfg(all(c_bindings, not(test)))]
impl<'a> OfferWithExplicitMetadataBuilder<'a> {
	offer_explicit_metadata_builder_methods!(self, &mut Self, (), ());
	offer_builder_methods!(self, &mut Self, (), ());
}

#[cfg(all(c_bindings, test))]
impl<'a> OfferWithExplicitMetadataBuilder<'a> {
	offer_explicit_metadata_builder_methods!(self, &mut Self, &mut Self, self);
	offer_builder_methods!(self, &mut Self, &mut Self, self);
	offer_builder_test_methods!(self, &mut Self, &mut Self, self);
}

#[cfg(all(c_bindings, not(test)))]
impl<'a> OfferWithDerivedMetadataBuilder<'a> {
	offer_derived_metadata_builder_methods!(secp256k1::All);
	offer_builder_methods!(self, &mut Self, (), ());
}

#[cfg(all(c_bindings, test))]
impl<'a> OfferWithDerivedMetadataBuilder<'a> {
	offer_derived_metadata_builder_methods!(secp256k1::All);
	offer_builder_methods!(self, &mut Self, &mut Self, self);
	offer_builder_test_methods!(self, &mut Self, &mut Self, self);
}

#[cfg(c_bindings)]
impl<'a> From<OfferBuilder<'a, DerivedMetadata, secp256k1::All>>
for OfferWithDerivedMetadataBuilder<'a> {
	fn from(builder: OfferBuilder<'a, DerivedMetadata, secp256k1::All>) -> Self {
		let OfferBuilder { offer, metadata_strategy, secp_ctx } = builder;

		Self { offer, metadata_strategy, secp_ctx }
	}
}

#[cfg(c_bindings)]
impl<'a> From<OfferWithDerivedMetadataBuilder<'a>>
for OfferBuilder<'a, DerivedMetadata, secp256k1::All> {
	fn from(builder: OfferWithDerivedMetadataBuilder<'a>) -> Self {
		let OfferWithDerivedMetadataBuilder { offer, metadata_strategy, secp_ctx } = builder;

		Self { offer, metadata_strategy, secp_ctx }
	}
}

/// An `Offer` is a potentially long-lived proposal for payment of a good or service.
///
/// An offer is a precursor to an [`InvoiceRequest`]. A merchant publishes an offer from which a
/// customer may request an [`Bolt12Invoice`] for a specific quantity and using an amount sufficient
/// to cover that quantity (i.e., at least `quantity * amount`). See [`Offer::amount`].
///
/// Offers may be denominated in currency other than bitcoin but are ultimately paid using the
/// latter.
///
/// Through the use of [`BlindedMessagePath`]s, offers provide recipient privacy.
///
/// [`InvoiceRequest`]: crate::offers::invoice_request::InvoiceRequest
/// [`Bolt12Invoice`]: crate::offers::invoice::Bolt12Invoice
#[derive(Clone, Debug)]
pub struct Offer {
	// The serialized offer. Needed when creating an `InvoiceRequest` if the offer contains unknown
	// fields.
	pub(super) bytes: Vec<u8>,
	pub(super) contents: OfferContents,
	id: OfferId,
}

/// The contents of an [`Offer`], which may be shared with an [`InvoiceRequest`] or a
/// [`Bolt12Invoice`].
///
/// [`InvoiceRequest`]: crate::offers::invoice_request::InvoiceRequest
/// [`Bolt12Invoice`]: crate::offers::invoice::Bolt12Invoice
#[derive(Clone, Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub(super) struct OfferContents {
	chains: Option<Vec<ChainHash>>,
	metadata: Option<Metadata>,
	amount: Option<Amount>,
	description: Option<String>,
	features: OfferFeatures,
	absolute_expiry: Option<Duration>,
	issuer: Option<String>,
	paths: Option<Vec<BlindedMessagePath>>,
	supported_quantity: Quantity,
	issuer_signing_pubkey: Option<PublicKey>,
}

macro_rules! offer_accessors { ($self: ident, $contents: expr) => {
	// TODO: Return a slice once ChainHash has constants.
	// - https://github.com/rust-bitcoin/rust-bitcoin/pull/1283
	// - https://github.com/rust-bitcoin/rust-bitcoin/pull/1286
	/// The chains that may be used when paying a requested invoice (e.g., bitcoin mainnet).
	/// Payments must be denominated in units of the minimal lightning-payable unit (e.g., msats)
	/// for the selected chain.
	pub fn chains(&$self) -> Vec<bitcoin::constants::ChainHash> {
		$contents.chains()
	}

	// TODO: Link to corresponding method in `InvoiceRequest`.
	/// Opaque bytes set by the originator. Useful for authentication and validating fields since it
	/// is reflected in `invoice_request` messages along with all the other fields from the `offer`.
	pub fn metadata(&$self) -> Option<&Vec<u8>> {
		$contents.metadata()
	}

	/// The minimum amount required for a successful payment of a single item.
	pub fn amount(&$self) -> Option<$crate::offers::offer::Amount> {
		$contents.amount()
	}

	/// A complete description of the purpose of the payment. Intended to be displayed to the user
	/// but with the caveat that it has not been verified in any way.
	pub fn description(&$self) -> Option<$crate::util::string::PrintableString> {
		$contents.description()
	}

	/// Features pertaining to the offer.
	pub fn offer_features(&$self) -> &$crate::ln::features::OfferFeatures {
		&$contents.features()
	}

	/// Duration since the Unix epoch when an invoice should no longer be requested.
	///
	/// If `None`, the offer does not expire.
	pub fn absolute_expiry(&$self) -> Option<core::time::Duration> {
		$contents.absolute_expiry()
	}

	/// The issuer of the offer, possibly beginning with `user@domain` or `domain`. Intended to be
	/// displayed to the user but with the caveat that it has not been verified in any way.
	pub fn issuer(&$self) -> Option<$crate::util::string::PrintableString> {
		$contents.issuer()
	}

	/// Paths to the recipient originating from publicly reachable nodes. Blinded paths provide
	/// recipient privacy by obfuscating its node id.
	pub fn paths(&$self) -> &[$crate::blinded_path::message::BlindedMessagePath] {
		$contents.paths()
	}

	/// The quantity of items supported.
	pub fn supported_quantity(&$self) -> $crate::offers::offer::Quantity {
		$contents.supported_quantity()
	}

	/// The public key corresponding to the key used by the recipient to sign invoices.
	/// - If [`Offer::paths`] is empty, MUST be `Some` and contain the recipient's node id for
	///   sending an [`InvoiceRequest`].
	/// - If [`Offer::paths`] is not empty, MAY be `Some` and contain a transient id.
	/// - If `None`, the signing pubkey will be the final blinded node id from the
	///   [`BlindedMessagePath`] in [`Offer::paths`] used to send the [`InvoiceRequest`].
	///
	/// See also [`Bolt12Invoice::signing_pubkey`].
	///
	/// [`InvoiceRequest`]: crate::offers::invoice_request::InvoiceRequest
	/// [`Bolt12Invoice::signing_pubkey`]: crate::offers::invoice::Bolt12Invoice::signing_pubkey
	pub fn issuer_signing_pubkey(&$self) -> Option<bitcoin::secp256k1::PublicKey> {
		$contents.issuer_signing_pubkey()
	}
} }

impl Offer {
	offer_accessors!(self, self.contents);

	/// Returns the id of the offer.
	pub fn id(&self) -> OfferId {
		self.id
	}

	pub(super) fn implied_chain(&self) -> ChainHash {
		self.contents.implied_chain()
	}

	/// Returns whether the given chain is supported by the offer.
	pub fn supports_chain(&self, chain: ChainHash) -> bool {
		self.contents.supports_chain(chain)
	}

	/// Whether the offer has expired.
	#[cfg(feature = "std")]
	pub fn is_expired(&self) -> bool {
		self.contents.is_expired()
	}

	/// Whether the offer has expired given the duration since the Unix epoch.
	pub fn is_expired_no_std(&self, duration_since_epoch: Duration) -> bool {
		self.contents.is_expired_no_std(duration_since_epoch)
	}

	/// Returns whether the given quantity is valid for the offer.
	pub fn is_valid_quantity(&self, quantity: u64) -> bool {
		self.contents.is_valid_quantity(quantity)
	}

	/// Returns whether a quantity is expected in an [`InvoiceRequest`] for the offer.
	///
	/// [`InvoiceRequest`]: crate::offers::invoice_request::InvoiceRequest
	pub fn expects_quantity(&self) -> bool {
		self.contents.expects_quantity()
	}

	#[cfg(async_payments)]
	pub(super) fn verify<T: secp256k1::Signing>(
		&self, nonce: Nonce, key: &ExpandedKey, secp_ctx: &Secp256k1<T>
	) -> Result<(OfferId, Option<Keypair>), ()> {
		self.contents.verify_using_recipient_data(&self.bytes, nonce, key, secp_ctx)
	}
}

macro_rules! request_invoice_derived_signing_pubkey { ($self: ident, $builder: ty) => {
	/// Similar to [`Offer::request_invoice`] except it:
	/// - derives the [`InvoiceRequest::payer_signing_pubkey`] such that a different key can be used
	///   for each request,
	/// - sets [`InvoiceRequest::payer_metadata`] when [`InvoiceRequestBuilder::build`] is called
	///   such that it can be used by [`Bolt12Invoice::verify_using_metadata`] to determine if the
	///   invoice was requested using a base [`ExpandedKey`] from which the payer id was derived,
	///   and
	/// - includes the [`PaymentId`] encrypted in [`InvoiceRequest::payer_metadata`] so that it can
	///   be used when sending the payment for the requested invoice.
	///
	/// Useful to protect the sender's privacy.
	///
	/// [`InvoiceRequest::payer_signing_pubkey`]: crate::offers::invoice_request::InvoiceRequest::payer_signing_pubkey
	/// [`InvoiceRequest::payer_metadata`]: crate::offers::invoice_request::InvoiceRequest::payer_metadata
	/// [`Bolt12Invoice::verify_using_metadata`]: crate::offers::invoice::Bolt12Invoice::verify_using_metadata
	/// [`ExpandedKey`]: crate::ln::inbound_payment::ExpandedKey
	pub fn request_invoice_deriving_signing_pubkey<
		'a, 'b,
		#[cfg(not(c_bindings))]
		T: secp256k1::Signing
	>(
		&'a $self, expanded_key: &ExpandedKey, nonce: Nonce,
		#[cfg(not(c_bindings))]
		secp_ctx: &'b Secp256k1<T>,
		#[cfg(c_bindings)]
		secp_ctx: &'b Secp256k1<secp256k1::All>,
		payment_id: PaymentId
	) -> Result<$builder, Bolt12SemanticError> {
		if $self.offer_features().requires_unknown_bits() {
			return Err(Bolt12SemanticError::UnknownRequiredFeatures);
		}

		Ok(<$builder>::deriving_signing_pubkey($self, expanded_key, nonce, secp_ctx, payment_id))
	}
} }

macro_rules! request_invoice_explicit_signing_pubkey { ($self: ident, $builder: ty) => {
	/// Similar to [`Offer::request_invoice_deriving_signing_pubkey`] except uses `signing_pubkey`
	/// for the [`InvoiceRequest::payer_signing_pubkey`] instead of deriving a different key for
	/// each request.
	///
	/// Useful for recurring payments using the same `signing_pubkey` with different invoices.
	///
	/// [`InvoiceRequest::payer_signing_pubkey`]: crate::offers::invoice_request::InvoiceRequest::payer_signing_pubkey
	pub fn request_invoice_deriving_metadata(
		&$self, signing_pubkey: PublicKey, expanded_key: &ExpandedKey, nonce: Nonce,
		payment_id: PaymentId
	) -> Result<$builder, Bolt12SemanticError> {
		if $self.offer_features().requires_unknown_bits() {
			return Err(Bolt12SemanticError::UnknownRequiredFeatures);
		}

		Ok(<$builder>::deriving_metadata($self, signing_pubkey, expanded_key, nonce, payment_id))
	}

	/// Creates an [`InvoiceRequestBuilder`] for the offer with the given `metadata` and
	/// `signing_pubkey`, which will be reflected in the `Bolt12Invoice` response.
	///
	/// The `metadata` is useful for including information about the derivation of `signing_pubkey`
	/// such that invoice response handling can be stateless. Also serves as payer-provided entropy
	/// while hashing in the signature calculation.
	///
	/// This should not leak any information such as by using a simple BIP-32 derivation path.
	/// Otherwise, payments may be correlated.
	///
	/// Errors if the offer contains unknown required features.
	///
	/// [`InvoiceRequest`]: crate::offers::invoice_request::InvoiceRequest
	pub fn request_invoice(
		&$self, metadata: Vec<u8>, signing_pubkey: PublicKey
	) -> Result<$builder, Bolt12SemanticError> {
		if $self.offer_features().requires_unknown_bits() {
			return Err(Bolt12SemanticError::UnknownRequiredFeatures);
		}

		Ok(<$builder>::new($self, metadata, signing_pubkey))
	}
} }

#[cfg(not(c_bindings))]
impl Offer {
	request_invoice_derived_signing_pubkey!(self, InvoiceRequestBuilder<'a, 'b, DerivedPayerSigningPubkey, T>);
	request_invoice_explicit_signing_pubkey!(self, InvoiceRequestBuilder<ExplicitPayerSigningPubkey, secp256k1::SignOnly>);
}

#[cfg(c_bindings)]
impl Offer {
	request_invoice_derived_signing_pubkey!(self, InvoiceRequestWithDerivedPayerSigningPubkeyBuilder<'a, 'b>);
	request_invoice_explicit_signing_pubkey!(self, InvoiceRequestWithExplicitPayerSigningPubkeyBuilder);
}

#[cfg(test)]
impl Offer {
	pub(super) fn as_tlv_stream(&self) -> OfferTlvStreamRef {
		self.contents.as_tlv_stream()
	}
}

impl AsRef<[u8]> for Offer {
	fn as_ref(&self) -> &[u8] {
		&self.bytes
	}
}

impl PartialEq for Offer {
	fn eq(&self, other: &Self) -> bool {
		self.bytes.eq(&other.bytes)
	}
}

impl Eq for Offer {}

impl Hash for Offer {
	fn hash<H: Hasher>(&self, state: &mut H) {
		self.bytes.hash(state);
	}
}

impl OfferContents {
	pub fn chains(&self) -> Vec<ChainHash> {
		self.chains.as_ref().cloned().unwrap_or_else(|| vec![self.implied_chain()])
	}

	pub fn implied_chain(&self) -> ChainHash {
		ChainHash::using_genesis_block(Network::Bitcoin)
	}

	pub fn supports_chain(&self, chain: ChainHash) -> bool {
		self.chains().contains(&chain)
	}

	pub fn metadata(&self) -> Option<&Vec<u8>> {
		self.metadata.as_ref().and_then(|metadata| metadata.as_bytes())
	}

	pub fn amount(&self) -> Option<Amount> {
		self.amount
	}

	pub fn description(&self) -> Option<PrintableString> {
		self.description.as_ref().map(|description| PrintableString(description))
	}

	pub fn features(&self) -> &OfferFeatures {
		&self.features
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

	pub fn paths(&self) -> &[BlindedMessagePath] {
		self.paths.as_ref().map(|paths| paths.as_slice()).unwrap_or(&[])
	}

	pub(super) fn check_amount_msats_for_quantity(
		&self, amount_msats: Option<u64>, quantity: Option<u64>
	) -> Result<(), Bolt12SemanticError> {
		let offer_amount_msats = match self.amount {
			None => 0,
			Some(Amount::Bitcoin { amount_msats }) => amount_msats,
			Some(Amount::Currency { .. }) => return Err(Bolt12SemanticError::UnsupportedCurrency),
		};

		if !self.expects_quantity() || quantity.is_some() {
			let expected_amount_msats = offer_amount_msats.checked_mul(quantity.unwrap_or(1))
				.ok_or(Bolt12SemanticError::InvalidAmount)?;
			let amount_msats = amount_msats.unwrap_or(expected_amount_msats);

			if amount_msats < expected_amount_msats {
				return Err(Bolt12SemanticError::InsufficientAmount);
			}

			if amount_msats > MAX_VALUE_MSAT {
				return Err(Bolt12SemanticError::InvalidAmount);
			}
		}

		Ok(())
	}

	pub fn supported_quantity(&self) -> Quantity {
		self.supported_quantity
	}

	pub(super) fn check_quantity(&self, quantity: Option<u64>) -> Result<(), Bolt12SemanticError> {
		let expects_quantity = self.expects_quantity();
		match quantity {
			None if expects_quantity => Err(Bolt12SemanticError::MissingQuantity),
			Some(_) if !expects_quantity => Err(Bolt12SemanticError::UnexpectedQuantity),
			Some(quantity) if !self.is_valid_quantity(quantity) => {
				Err(Bolt12SemanticError::InvalidQuantity)
			},
			_ => Ok(()),
		}
	}

	fn is_valid_quantity(&self, quantity: u64) -> bool {
		match self.supported_quantity {
			Quantity::Bounded(n) => quantity <= n.get(),
			Quantity::Unbounded => quantity > 0,
			Quantity::One => quantity == 1,
		}
	}

	fn expects_quantity(&self) -> bool {
		match self.supported_quantity {
			Quantity::Bounded(_) => true,
			Quantity::Unbounded => true,
			Quantity::One => false,
		}
	}

	pub(super) fn issuer_signing_pubkey(&self) -> Option<PublicKey> {
		self.issuer_signing_pubkey
	}

	pub(super) fn verify_using_metadata<T: secp256k1::Signing>(
		&self, bytes: &[u8], key: &ExpandedKey, secp_ctx: &Secp256k1<T>
	) -> Result<(OfferId, Option<Keypair>), ()> {
		self.verify(bytes, self.metadata.as_ref(), key, IV_BYTES_WITH_METADATA, secp_ctx)
	}

	pub(super) fn verify_using_recipient_data<T: secp256k1::Signing>(
		&self, bytes: &[u8], nonce: Nonce, key: &ExpandedKey, secp_ctx: &Secp256k1<T>
	) -> Result<(OfferId, Option<Keypair>), ()> {
		let metadata = Metadata::RecipientData(nonce);
		self.verify(bytes, Some(&metadata), key, IV_BYTES_WITHOUT_METADATA, secp_ctx)
	}

	/// Verifies that the offer metadata was produced from the offer in the TLV stream.
	fn verify<T: secp256k1::Signing>(
		&self, bytes: &[u8], metadata: Option<&Metadata>, key: &ExpandedKey,
		iv_bytes: &[u8; IV_LEN], secp_ctx: &Secp256k1<T>
	) -> Result<(OfferId, Option<Keypair>), ()> {
		match metadata {
			Some(metadata) => {
				let tlv_stream = TlvStream::new(bytes).range(OFFER_TYPES).filter(|record| {
					match record.r#type {
						OFFER_METADATA_TYPE => false,
						OFFER_ISSUER_ID_TYPE => !metadata.derives_recipient_keys(),
						_ => true,
					}
				});
				let signing_pubkey = match self.issuer_signing_pubkey() {
					Some(signing_pubkey) => signing_pubkey,
					None => return Err(()),
				};
				let keys = signer::verify_recipient_metadata(
					metadata.as_ref(), key, iv_bytes, signing_pubkey, tlv_stream, secp_ctx
				)?;

				let offer_id = OfferId::from_valid_invreq_tlv_stream(bytes);

				Ok((offer_id, keys))
			},
			None => Err(()),
		}
	}

	pub(super) fn as_tlv_stream(&self) -> OfferTlvStreamRef {
		let (currency, amount) = match &self.amount {
			None => (None, None),
			Some(Amount::Bitcoin { amount_msats }) => (None, Some(*amount_msats)),
			Some(Amount::Currency { iso4217_code, amount }) => (
				Some(iso4217_code), Some(*amount)
			),
		};

		let features = {
			if self.features == OfferFeatures::empty() { None } else { Some(&self.features) }
		};

		OfferTlvStreamRef {
			chains: self.chains.as_ref(),
			metadata: self.metadata(),
			currency,
			amount,
			description: self.description.as_ref(),
			features,
			absolute_expiry: self.absolute_expiry.map(|duration| duration.as_secs()),
			paths: self.paths.as_ref(),
			issuer: self.issuer.as_ref(),
			quantity_max: self.supported_quantity.to_tlv_record(),
			issuer_id: self.issuer_signing_pubkey.as_ref(),
		}
	}
}

impl Readable for Offer {
	fn read<R: io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
		let bytes: WithoutLength<Vec<u8>> = Readable::read(reader)?;
		Self::try_from(bytes.0).map_err(|_| DecodeError::InvalidValue)
	}
}

impl Writeable for Offer {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		WithoutLength(&self.bytes).write(writer)
	}
}

impl Writeable for OfferContents {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		self.as_tlv_stream().write(writer)
	}
}

/// The minimum amount required for an item in an [`Offer`], denominated in either bitcoin or
/// another currency.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Amount {
	/// An amount of bitcoin.
	Bitcoin {
		/// The amount in millisatoshi.
		amount_msats: u64,
	},
	/// An amount of currency specified using ISO 4712.
	Currency {
		/// The currency that the amount is denominated in.
		iso4217_code: CurrencyCode,
		/// The amount in the currency unit adjusted by the ISO 4712 exponent (e.g., USD cents).
		amount: u64,
	},
}

/// An ISO 4712 three-letter currency code (e.g., USD).
pub type CurrencyCode = [u8; 3];

/// Quantity of items supported by an [`Offer`].
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Quantity {
	/// Up to a specific number of items (inclusive). Use when more than one item can be requested
	/// but is limited (e.g., because of per customer or inventory limits).
	///
	/// May be used with `NonZeroU64::new(1)` but prefer to use [`Quantity::One`] if only one item
	/// is supported.
	Bounded(NonZeroU64),
	/// One or more items. Use when more than one item can be requested without any limit.
	Unbounded,
	/// Only one item. Use when only a single item can be requested.
	One,
}

impl Quantity {
	fn to_tlv_record(self) -> Option<u64> {
		match self {
			Quantity::Bounded(n) => Some(n.get()),
			Quantity::Unbounded => Some(0),
			Quantity::One => None,
		}
	}
}

/// Valid type range for offer TLV records.
pub(super) const OFFER_TYPES: core::ops::Range<u64> = 1..80;

/// TLV record type for [`Offer::metadata`].
const OFFER_METADATA_TYPE: u64 = 4;

/// TLV record type for [`Offer::issuer_signing_pubkey`].
const OFFER_ISSUER_ID_TYPE: u64 = 22;

tlv_stream!(OfferTlvStream, OfferTlvStreamRef, OFFER_TYPES, {
	(2, chains: (Vec<ChainHash>, WithoutLength)),
	(OFFER_METADATA_TYPE, metadata: (Vec<u8>, WithoutLength)),
	(6, currency: CurrencyCode),
	(8, amount: (u64, HighZeroBytesDroppedBigSize)),
	(10, description: (String, WithoutLength)),
	(12, features: (OfferFeatures, WithoutLength)),
	(14, absolute_expiry: (u64, HighZeroBytesDroppedBigSize)),
	(16, paths: (Vec<BlindedMessagePath>, WithoutLength)),
	(18, issuer: (String, WithoutLength)),
	(20, quantity_max: (u64, HighZeroBytesDroppedBigSize)),
	(OFFER_ISSUER_ID_TYPE, issuer_id: PublicKey),
});

impl Bech32Encode for Offer {
	const BECH32_HRP: &'static str = "lno";
}

impl FromStr for Offer {
	type Err = Bolt12ParseError;

	fn from_str(s: &str) -> Result<Self, <Self as FromStr>::Err> {
		Self::from_bech32_str(s)
	}
}

impl TryFrom<Vec<u8>> for Offer {
	type Error = Bolt12ParseError;

	fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
		let offer = ParsedMessage::<OfferTlvStream>::try_from(bytes)?;
		let ParsedMessage { bytes, tlv_stream } = offer;
		let contents = OfferContents::try_from(tlv_stream)?;
		let id = OfferId::from_valid_offer_tlv_stream(&bytes);

		Ok(Offer { bytes, contents, id })
	}
}

impl TryFrom<OfferTlvStream> for OfferContents {
	type Error = Bolt12SemanticError;

	fn try_from(tlv_stream: OfferTlvStream) -> Result<Self, Self::Error> {
		let OfferTlvStream {
			chains, metadata, currency, amount, description, features, absolute_expiry, paths,
			issuer, quantity_max, issuer_id,
		} = tlv_stream;

		let metadata = metadata.map(|metadata| Metadata::Bytes(metadata));

		let amount = match (currency, amount) {
			(None, None) => None,
			(None, Some(amount_msats)) if amount_msats > MAX_VALUE_MSAT => {
				return Err(Bolt12SemanticError::InvalidAmount);
			},
			(None, Some(amount_msats)) => Some(Amount::Bitcoin { amount_msats }),
			(Some(_), None) => return Err(Bolt12SemanticError::MissingAmount),
			(Some(iso4217_code), Some(amount)) => Some(Amount::Currency { iso4217_code, amount }),
		};

		if amount.is_some() && description.is_none() {
			return Err(Bolt12SemanticError::MissingDescription);
		}

		let features = features.unwrap_or_else(OfferFeatures::empty);

		let absolute_expiry = absolute_expiry
			.map(|seconds_from_epoch| Duration::from_secs(seconds_from_epoch));

		let supported_quantity = match quantity_max {
			None => Quantity::One,
			Some(0) => Quantity::Unbounded,
			Some(n) => Quantity::Bounded(NonZeroU64::new(n).unwrap()),
		};

		let (issuer_signing_pubkey, paths) = match (issuer_id, paths) {
			(None, None) => return Err(Bolt12SemanticError::MissingIssuerSigningPubkey),
			(_, Some(paths)) if paths.is_empty() => return Err(Bolt12SemanticError::MissingPaths),
			(issuer_id, paths) => (issuer_id, paths),
		};

		Ok(OfferContents {
			chains, metadata, amount, description, features, absolute_expiry, issuer, paths,
			supported_quantity, issuer_signing_pubkey,
		})
	}
}

impl core::fmt::Display for Offer {
	fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
		self.fmt_bech32_str(f)
	}
}

#[cfg(test)]
mod tests {
	use super::{Amount, Offer, OfferTlvStreamRef, Quantity};
	#[cfg(not(c_bindings))]
	use {
		super::OfferBuilder,
	};
	#[cfg(c_bindings)]
	use {
		super::OfferWithExplicitMetadataBuilder as OfferBuilder,
	};

	use bitcoin::constants::ChainHash;
	use bitcoin::network::Network;
	use bitcoin::secp256k1::Secp256k1;
	use core::num::NonZeroU64;
	use core::time::Duration;
	use crate::blinded_path::BlindedHop;
	use crate::blinded_path::message::BlindedMessagePath;
	use crate::sign::KeyMaterial;
	use crate::ln::features::OfferFeatures;
	use crate::ln::inbound_payment::ExpandedKey;
	use crate::ln::msgs::{DecodeError, MAX_VALUE_MSAT};
	use crate::offers::nonce::Nonce;
	use crate::offers::parse::{Bolt12ParseError, Bolt12SemanticError};
	use crate::offers::test_utils::*;
	use crate::util::ser::{BigSize, Writeable};
	use crate::util::string::PrintableString;

	#[test]
	fn builds_offer_with_defaults() {
		let offer = OfferBuilder::new(pubkey(42)).build().unwrap();

		let mut buffer = Vec::new();
		offer.write(&mut buffer).unwrap();

		assert_eq!(offer.bytes, buffer.as_slice());
		assert_eq!(offer.chains(), vec![ChainHash::using_genesis_block(Network::Bitcoin)]);
		assert!(offer.supports_chain(ChainHash::using_genesis_block(Network::Bitcoin)));
		assert_eq!(offer.metadata(), None);
		assert_eq!(offer.amount(), None);
		assert_eq!(offer.description(), None);
		assert_eq!(offer.offer_features(), &OfferFeatures::empty());
		assert_eq!(offer.absolute_expiry(), None);
		#[cfg(feature = "std")]
		assert!(!offer.is_expired());
		assert_eq!(offer.paths(), &[]);
		assert_eq!(offer.issuer(), None);
		assert_eq!(offer.supported_quantity(), Quantity::One);
		assert!(!offer.expects_quantity());
		assert_eq!(offer.issuer_signing_pubkey(), Some(pubkey(42)));

		assert_eq!(
			offer.as_tlv_stream(),
			OfferTlvStreamRef {
				chains: None,
				metadata: None,
				currency: None,
				amount: None,
				description: None,
				features: None,
				absolute_expiry: None,
				paths: None,
				issuer: None,
				quantity_max: None,
				issuer_id: Some(&pubkey(42)),
			},
		);

		if let Err(e) = Offer::try_from(buffer) {
			panic!("error parsing offer: {:?}", e);
		}
	}

	#[test]
	fn builds_offer_with_chains() {
		let mainnet = ChainHash::using_genesis_block(Network::Bitcoin);
		let testnet = ChainHash::using_genesis_block(Network::Testnet);

		let offer = OfferBuilder::new(pubkey(42))
			.chain(Network::Bitcoin)
			.build()
			.unwrap();
		assert!(offer.supports_chain(mainnet));
		assert_eq!(offer.chains(), vec![mainnet]);
		assert_eq!(offer.as_tlv_stream().chains, None);

		let offer = OfferBuilder::new(pubkey(42))
			.chain(Network::Testnet)
			.build()
			.unwrap();
		assert!(offer.supports_chain(testnet));
		assert_eq!(offer.chains(), vec![testnet]);
		assert_eq!(offer.as_tlv_stream().chains, Some(&vec![testnet]));

		let offer = OfferBuilder::new(pubkey(42))
			.chain(Network::Testnet)
			.chain(Network::Testnet)
			.build()
			.unwrap();
		assert!(offer.supports_chain(testnet));
		assert_eq!(offer.chains(), vec![testnet]);
		assert_eq!(offer.as_tlv_stream().chains, Some(&vec![testnet]));

		let offer = OfferBuilder::new(pubkey(42))
			.chain(Network::Bitcoin)
			.chain(Network::Testnet)
			.build()
			.unwrap();
		assert!(offer.supports_chain(mainnet));
		assert!(offer.supports_chain(testnet));
		assert_eq!(offer.chains(), vec![mainnet, testnet]);
		assert_eq!(offer.as_tlv_stream().chains, Some(&vec![mainnet, testnet]));
	}

	#[test]
	fn builds_offer_with_metadata() {
		let offer = OfferBuilder::new(pubkey(42))
			.metadata(vec![42; 32]).unwrap()
			.build()
			.unwrap();
		assert_eq!(offer.metadata(), Some(&vec![42; 32]));
		assert_eq!(offer.as_tlv_stream().metadata, Some(&vec![42; 32]));

		let offer = OfferBuilder::new(pubkey(42))
			.metadata(vec![42; 32]).unwrap()
			.metadata(vec![43; 32]).unwrap()
			.build()
			.unwrap();
		assert_eq!(offer.metadata(), Some(&vec![43; 32]));
		assert_eq!(offer.as_tlv_stream().metadata, Some(&vec![43; 32]));
	}

	#[test]
	fn builds_offer_with_metadata_derived() {
		let node_id = recipient_pubkey();
		let expanded_key = ExpandedKey::new(&KeyMaterial([42; 32]));
		let entropy = FixedEntropy {};
		let nonce = Nonce::from_entropy_source(&entropy);
		let secp_ctx = Secp256k1::new();

		#[cfg(c_bindings)]
		use super::OfferWithDerivedMetadataBuilder as OfferBuilder;
		let offer = OfferBuilder::deriving_signing_pubkey(node_id, &expanded_key, nonce, &secp_ctx)
			.amount_msats(1000)
			.build().unwrap();
		assert!(offer.metadata().is_some());
		assert_eq!(offer.issuer_signing_pubkey(), Some(node_id));

		let invoice_request = offer.request_invoice(vec![1; 32], payer_pubkey()).unwrap()
			.build().unwrap()
			.sign(payer_sign).unwrap();
		match invoice_request.verify_using_metadata(&expanded_key, &secp_ctx) {
			Ok(invoice_request) => assert_eq!(invoice_request.offer_id, offer.id()),
			Err(_) => panic!("unexpected error"),
		}

		// Fails verification when using the wrong method
		let invoice_request = offer.request_invoice(vec![1; 32], payer_pubkey()).unwrap()
			.build().unwrap()
			.sign(payer_sign).unwrap();
		assert!(
			invoice_request.verify_using_recipient_data(nonce, &expanded_key, &secp_ctx).is_err()
		);

		// Fails verification with altered offer field
		let mut tlv_stream = offer.as_tlv_stream();
		tlv_stream.amount = Some(100);

		let mut encoded_offer = Vec::new();
		tlv_stream.write(&mut encoded_offer).unwrap();

		let invoice_request = Offer::try_from(encoded_offer).unwrap()
			.request_invoice(vec![1; 32], payer_pubkey()).unwrap()
			.build().unwrap()
			.sign(payer_sign).unwrap();
		assert!(invoice_request.verify_using_metadata(&expanded_key, &secp_ctx).is_err());

		// Fails verification with altered metadata
		let mut tlv_stream = offer.as_tlv_stream();
		let metadata = tlv_stream.metadata.unwrap().iter().copied().rev().collect();
		tlv_stream.metadata = Some(&metadata);

		let mut encoded_offer = Vec::new();
		tlv_stream.write(&mut encoded_offer).unwrap();

		let invoice_request = Offer::try_from(encoded_offer).unwrap()
			.request_invoice(vec![1; 32], payer_pubkey()).unwrap()
			.build().unwrap()
			.sign(payer_sign).unwrap();
		assert!(invoice_request.verify_using_metadata(&expanded_key, &secp_ctx).is_err());
	}

	#[test]
	fn builds_offer_with_derived_signing_pubkey() {
		let node_id = recipient_pubkey();
		let expanded_key = ExpandedKey::new(&KeyMaterial([42; 32]));
		let entropy = FixedEntropy {};
		let nonce = Nonce::from_entropy_source(&entropy);
		let secp_ctx = Secp256k1::new();

		let blinded_path = BlindedMessagePath::from_raw(
			pubkey(40), pubkey(41),
			vec![
				BlindedHop { blinded_node_id: pubkey(42), encrypted_payload: vec![0; 43] },
				BlindedHop { blinded_node_id: node_id, encrypted_payload: vec![0; 44] },
			]
		);

		#[cfg(c_bindings)]
		use super::OfferWithDerivedMetadataBuilder as OfferBuilder;
		let offer = OfferBuilder::deriving_signing_pubkey(node_id, &expanded_key, nonce, &secp_ctx)
			.amount_msats(1000)
			.path(blinded_path)
			.build().unwrap();
		assert!(offer.metadata().is_none());
		assert_ne!(offer.issuer_signing_pubkey(), Some(node_id));

		let invoice_request = offer.request_invoice(vec![1; 32], payer_pubkey()).unwrap()
			.build().unwrap()
			.sign(payer_sign).unwrap();
		match invoice_request.verify_using_recipient_data(nonce, &expanded_key, &secp_ctx) {
			Ok(invoice_request) => assert_eq!(invoice_request.offer_id, offer.id()),
			Err(_) => panic!("unexpected error"),
		}

		// Fails verification when using the wrong method
		let invoice_request = offer.request_invoice(vec![1; 32], payer_pubkey()).unwrap()
			.build().unwrap()
			.sign(payer_sign).unwrap();
		assert!(invoice_request.verify_using_metadata(&expanded_key, &secp_ctx).is_err());

		// Fails verification with altered offer field
		let mut tlv_stream = offer.as_tlv_stream();
		tlv_stream.amount = Some(100);

		let mut encoded_offer = Vec::new();
		tlv_stream.write(&mut encoded_offer).unwrap();

		let invoice_request = Offer::try_from(encoded_offer).unwrap()
			.request_invoice(vec![1; 32], payer_pubkey()).unwrap()
			.build().unwrap()
			.sign(payer_sign).unwrap();
		assert!(
			invoice_request.verify_using_recipient_data(nonce, &expanded_key, &secp_ctx).is_err()
		);

		// Fails verification with altered signing pubkey
		let mut tlv_stream = offer.as_tlv_stream();
		let issuer_id = pubkey(1);
		tlv_stream.issuer_id = Some(&issuer_id);

		let mut encoded_offer = Vec::new();
		tlv_stream.write(&mut encoded_offer).unwrap();

		let invoice_request = Offer::try_from(encoded_offer).unwrap()
			.request_invoice(vec![1; 32], payer_pubkey()).unwrap()
			.build().unwrap()
			.sign(payer_sign).unwrap();
		assert!(
			invoice_request.verify_using_recipient_data(nonce, &expanded_key, &secp_ctx).is_err()
		);
	}

	#[test]
	fn builds_offer_with_amount() {
		let bitcoin_amount = Amount::Bitcoin { amount_msats: 1000 };
		let currency_amount = Amount::Currency { iso4217_code: *b"USD", amount: 10 };

		let offer = OfferBuilder::new(pubkey(42))
			.amount_msats(1000)
			.build()
			.unwrap();
		let tlv_stream = offer.as_tlv_stream();
		assert_eq!(offer.amount(), Some(bitcoin_amount));
		assert_eq!(tlv_stream.amount, Some(1000));
		assert_eq!(tlv_stream.currency, None);

		#[cfg(not(c_bindings))]
		let builder = OfferBuilder::new(pubkey(42))
			.amount(currency_amount.clone());
		#[cfg(c_bindings)]
		let mut builder = OfferBuilder::new(pubkey(42));
		#[cfg(c_bindings)]
		builder.amount(currency_amount.clone());
		let tlv_stream = builder.offer.as_tlv_stream();
		assert_eq!(builder.offer.amount, Some(currency_amount.clone()));
		assert_eq!(tlv_stream.amount, Some(10));
		assert_eq!(tlv_stream.currency, Some(b"USD"));
		match builder.build() {
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, Bolt12SemanticError::UnsupportedCurrency),
		}

		let offer = OfferBuilder::new(pubkey(42))
			.amount(currency_amount.clone())
			.amount(bitcoin_amount.clone())
			.build()
			.unwrap();
		let tlv_stream = offer.as_tlv_stream();
		assert_eq!(tlv_stream.amount, Some(1000));
		assert_eq!(tlv_stream.currency, None);

		let invalid_amount = Amount::Bitcoin { amount_msats: MAX_VALUE_MSAT + 1 };
		match OfferBuilder::new(pubkey(42)).amount(invalid_amount).build() {
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, Bolt12SemanticError::InvalidAmount),
		}
	}

	#[test]
	fn builds_offer_with_description() {
		let offer = OfferBuilder::new(pubkey(42))
			.description("foo".into())
			.build()
			.unwrap();
		assert_eq!(offer.description(), Some(PrintableString("foo")));
		assert_eq!(offer.as_tlv_stream().description, Some(&String::from("foo")));

		let offer = OfferBuilder::new(pubkey(42))
			.description("foo".into())
			.description("bar".into())
			.build()
			.unwrap();
		assert_eq!(offer.description(), Some(PrintableString("bar")));
		assert_eq!(offer.as_tlv_stream().description, Some(&String::from("bar")));

		let offer = OfferBuilder::new(pubkey(42))
			.amount_msats(1000)
			.build()
			.unwrap();
		assert_eq!(offer.description(), Some(PrintableString("")));
		assert_eq!(offer.as_tlv_stream().description, Some(&String::from("")));
	}

	#[test]
	fn builds_offer_with_features() {
		let offer = OfferBuilder::new(pubkey(42))
			.features_unchecked(OfferFeatures::unknown())
			.build()
			.unwrap();
		assert_eq!(offer.offer_features(), &OfferFeatures::unknown());
		assert_eq!(offer.as_tlv_stream().features, Some(&OfferFeatures::unknown()));

		let offer = OfferBuilder::new(pubkey(42))
			.features_unchecked(OfferFeatures::unknown())
			.features_unchecked(OfferFeatures::empty())
			.build()
			.unwrap();
		assert_eq!(offer.offer_features(), &OfferFeatures::empty());
		assert_eq!(offer.as_tlv_stream().features, None);
	}

	#[test]
	fn builds_offer_with_absolute_expiry() {
		let future_expiry = Duration::from_secs(u64::max_value());
		let past_expiry = Duration::from_secs(0);
		let now = future_expiry - Duration::from_secs(1_000);

		let offer = OfferBuilder::new(pubkey(42))
			.absolute_expiry(future_expiry)
			.build()
			.unwrap();
		#[cfg(feature = "std")]
		assert!(!offer.is_expired());
		assert!(!offer.is_expired_no_std(now));
		assert_eq!(offer.absolute_expiry(), Some(future_expiry));
		assert_eq!(offer.as_tlv_stream().absolute_expiry, Some(future_expiry.as_secs()));

		let offer = OfferBuilder::new(pubkey(42))
			.absolute_expiry(future_expiry)
			.absolute_expiry(past_expiry)
			.build()
			.unwrap();
		#[cfg(feature = "std")]
		assert!(offer.is_expired());
		assert!(offer.is_expired_no_std(now));
		assert_eq!(offer.absolute_expiry(), Some(past_expiry));
		assert_eq!(offer.as_tlv_stream().absolute_expiry, Some(past_expiry.as_secs()));
	}

	#[test]
	fn builds_offer_with_paths() {
		let paths = vec![
			BlindedMessagePath::from_raw(
				pubkey(40), pubkey(41),
				vec![
					BlindedHop { blinded_node_id: pubkey(43), encrypted_payload: vec![0; 43] },
					BlindedHop { blinded_node_id: pubkey(44), encrypted_payload: vec![0; 44] },
				]
			),
			BlindedMessagePath::from_raw(
				pubkey(40), pubkey(41),
				vec![
					BlindedHop { blinded_node_id: pubkey(45), encrypted_payload: vec![0; 45] },
					BlindedHop { blinded_node_id: pubkey(46), encrypted_payload: vec![0; 46] },
				]
			),
		];

		let offer = OfferBuilder::new(pubkey(42))
			.path(paths[0].clone())
			.path(paths[1].clone())
			.build()
			.unwrap();
		let tlv_stream = offer.as_tlv_stream();
		assert_eq!(offer.paths(), paths.as_slice());
		assert_eq!(offer.issuer_signing_pubkey(), Some(pubkey(42)));
		assert_ne!(pubkey(42), pubkey(44));
		assert_eq!(tlv_stream.paths, Some(&paths));
		assert_eq!(tlv_stream.issuer_id, Some(&pubkey(42)));
	}

	#[test]
	fn builds_offer_with_issuer() {
		let offer = OfferBuilder::new(pubkey(42))
			.issuer("foo".into())
			.build()
			.unwrap();
		assert_eq!(offer.issuer(), Some(PrintableString("foo")));
		assert_eq!(offer.as_tlv_stream().issuer, Some(&String::from("foo")));

		let offer = OfferBuilder::new(pubkey(42))
			.issuer("foo".into())
			.issuer("bar".into())
			.build()
			.unwrap();
		assert_eq!(offer.issuer(), Some(PrintableString("bar")));
		assert_eq!(offer.as_tlv_stream().issuer, Some(&String::from("bar")));
	}

	#[test]
	fn builds_offer_with_supported_quantity() {
		let one = NonZeroU64::new(1).unwrap();
		let ten = NonZeroU64::new(10).unwrap();

		let offer = OfferBuilder::new(pubkey(42))
			.supported_quantity(Quantity::One)
			.build()
			.unwrap();
		let tlv_stream = offer.as_tlv_stream();
		assert!(!offer.expects_quantity());
		assert_eq!(offer.supported_quantity(), Quantity::One);
		assert_eq!(tlv_stream.quantity_max, None);

		let offer = OfferBuilder::new(pubkey(42))
			.supported_quantity(Quantity::Unbounded)
			.build()
			.unwrap();
		let tlv_stream = offer.as_tlv_stream();
		assert!(offer.expects_quantity());
		assert_eq!(offer.supported_quantity(), Quantity::Unbounded);
		assert_eq!(tlv_stream.quantity_max, Some(0));

		let offer = OfferBuilder::new(pubkey(42))
			.supported_quantity(Quantity::Bounded(ten))
			.build()
			.unwrap();
		let tlv_stream = offer.as_tlv_stream();
		assert!(offer.expects_quantity());
		assert_eq!(offer.supported_quantity(), Quantity::Bounded(ten));
		assert_eq!(tlv_stream.quantity_max, Some(10));

		let offer = OfferBuilder::new(pubkey(42))
			.supported_quantity(Quantity::Bounded(one))
			.build()
			.unwrap();
		let tlv_stream = offer.as_tlv_stream();
		assert!(offer.expects_quantity());
		assert_eq!(offer.supported_quantity(), Quantity::Bounded(one));
		assert_eq!(tlv_stream.quantity_max, Some(1));

		let offer = OfferBuilder::new(pubkey(42))
			.supported_quantity(Quantity::Bounded(ten))
			.supported_quantity(Quantity::One)
			.build()
			.unwrap();
		let tlv_stream = offer.as_tlv_stream();
		assert!(!offer.expects_quantity());
		assert_eq!(offer.supported_quantity(), Quantity::One);
		assert_eq!(tlv_stream.quantity_max, None);
	}

	#[test]
	fn fails_requesting_invoice_with_unknown_required_features() {
		match OfferBuilder::new(pubkey(42))
			.features_unchecked(OfferFeatures::unknown())
			.build().unwrap()
			.request_invoice(vec![1; 32], pubkey(43))
		{
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, Bolt12SemanticError::UnknownRequiredFeatures),
		}
	}

	#[test]
	fn parses_offer_with_chains() {
		let offer = OfferBuilder::new(pubkey(42))
			.chain(Network::Bitcoin)
			.chain(Network::Testnet)
			.build()
			.unwrap();
		if let Err(e) = offer.to_string().parse::<Offer>() {
			panic!("error parsing offer: {:?}", e);
		}
	}

	#[test]
	fn parses_offer_with_amount() {
		let offer = OfferBuilder::new(pubkey(42))
			.amount(Amount::Bitcoin { amount_msats: 1000 })
			.build()
			.unwrap();
		if let Err(e) = offer.to_string().parse::<Offer>() {
			panic!("error parsing offer: {:?}", e);
		}

		let mut tlv_stream = offer.as_tlv_stream();
		tlv_stream.amount = Some(1000);
		tlv_stream.currency = Some(b"USD");

		let mut encoded_offer = Vec::new();
		tlv_stream.write(&mut encoded_offer).unwrap();

		if let Err(e) = Offer::try_from(encoded_offer) {
			panic!("error parsing offer: {:?}", e);
		}

		let mut tlv_stream = offer.as_tlv_stream();
		tlv_stream.amount = None;
		tlv_stream.currency = Some(b"USD");

		let mut encoded_offer = Vec::new();
		tlv_stream.write(&mut encoded_offer).unwrap();

		match Offer::try_from(encoded_offer) {
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::MissingAmount)),
		}

		let mut tlv_stream = offer.as_tlv_stream();
		tlv_stream.amount = Some(MAX_VALUE_MSAT + 1);
		tlv_stream.currency = None;

		let mut encoded_offer = Vec::new();
		tlv_stream.write(&mut encoded_offer).unwrap();

		match Offer::try_from(encoded_offer) {
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::InvalidAmount)),
		}
	}

	#[test]
	fn parses_offer_with_description() {
		let offer = OfferBuilder::new(pubkey(42)).build().unwrap();
		if let Err(e) = offer.to_string().parse::<Offer>() {
			panic!("error parsing offer: {:?}", e);
		}

		let offer = OfferBuilder::new(pubkey(42))
			.description("foo".to_string())
			.amount_msats(1000)
			.build().unwrap();
		if let Err(e) = offer.to_string().parse::<Offer>() {
			panic!("error parsing offer: {:?}", e);
		}

		let mut tlv_stream = offer.as_tlv_stream();
		tlv_stream.description = None;

		let mut encoded_offer = Vec::new();
		tlv_stream.write(&mut encoded_offer).unwrap();

		match Offer::try_from(encoded_offer) {
			Ok(_) => panic!("expected error"),
			Err(e) => {
				assert_eq!(e, Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::MissingDescription));
			},
		}
	}

	#[test]
	fn parses_offer_with_paths() {
		let offer = OfferBuilder::new(pubkey(42))
			.path(BlindedMessagePath::from_raw(
				pubkey(40), pubkey(41),
				vec![
					BlindedHop { blinded_node_id: pubkey(43), encrypted_payload: vec![0; 43] },
					BlindedHop { blinded_node_id: pubkey(44), encrypted_payload: vec![0; 44] },
				]
			))
			.path(BlindedMessagePath::from_raw(
					pubkey(40), pubkey(41),
					vec![
						BlindedHop { blinded_node_id: pubkey(45), encrypted_payload: vec![0; 45] },
						BlindedHop { blinded_node_id: pubkey(46), encrypted_payload: vec![0; 46] },
					]
			))
			.build()
			.unwrap();
		if let Err(e) = offer.to_string().parse::<Offer>() {
			panic!("error parsing offer: {:?}", e);
		}

		let offer = OfferBuilder::new(pubkey(42))
			.path(BlindedMessagePath::from_raw(
					pubkey(40), pubkey(41),
					vec![
						BlindedHop { blinded_node_id: pubkey(43), encrypted_payload: vec![0; 43] },
						BlindedHop { blinded_node_id: pubkey(44), encrypted_payload: vec![0; 44] },
					]
			))
			.clear_issuer_signing_pubkey()
			.build()
			.unwrap();
		if let Err(e) = offer.to_string().parse::<Offer>() {
			panic!("error parsing offer: {:?}", e);
		}

		let mut builder = OfferBuilder::new(pubkey(42));
		builder.offer.paths = Some(vec![]);

		let offer = builder.build().unwrap();
		match offer.to_string().parse::<Offer>() {
			Ok(_) => panic!("expected error"),
			Err(e) => {
				assert_eq!(e, Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::MissingPaths));
			},
		}
	}

	#[test]
	fn parses_offer_with_quantity() {
		let offer = OfferBuilder::new(pubkey(42))
			.supported_quantity(Quantity::One)
			.build()
			.unwrap();
		if let Err(e) = offer.to_string().parse::<Offer>() {
			panic!("error parsing offer: {:?}", e);
		}

		let offer = OfferBuilder::new(pubkey(42))
			.supported_quantity(Quantity::Unbounded)
			.build()
			.unwrap();
		if let Err(e) = offer.to_string().parse::<Offer>() {
			panic!("error parsing offer: {:?}", e);
		}

		let offer = OfferBuilder::new(pubkey(42))
			.supported_quantity(Quantity::Bounded(NonZeroU64::new(10).unwrap()))
			.build()
			.unwrap();
		if let Err(e) = offer.to_string().parse::<Offer>() {
			panic!("error parsing offer: {:?}", e);
		}

		let offer = OfferBuilder::new(pubkey(42))
			.supported_quantity(Quantity::Bounded(NonZeroU64::new(1).unwrap()))
			.build()
			.unwrap();
		if let Err(e) = offer.to_string().parse::<Offer>() {
			panic!("error parsing offer: {:?}", e);
		}
	}

	#[test]
	fn parses_offer_with_issuer_id() {
		let offer = OfferBuilder::new(pubkey(42)).build().unwrap();
		if let Err(e) = offer.to_string().parse::<Offer>() {
			panic!("error parsing offer: {:?}", e);
		}

		let mut tlv_stream = offer.as_tlv_stream();
		tlv_stream.issuer_id = None;

		let mut encoded_offer = Vec::new();
		tlv_stream.write(&mut encoded_offer).unwrap();

		match Offer::try_from(encoded_offer) {
			Ok(_) => panic!("expected error"),
			Err(e) => {
				assert_eq!(e, Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::MissingIssuerSigningPubkey));
			},
		}
	}

	#[test]
	fn fails_parsing_offer_with_extra_tlv_records() {
		let offer = OfferBuilder::new(pubkey(42)).build().unwrap();

		let mut encoded_offer = Vec::new();
		offer.write(&mut encoded_offer).unwrap();
		BigSize(80).write(&mut encoded_offer).unwrap();
		BigSize(32).write(&mut encoded_offer).unwrap();
		[42u8; 32].write(&mut encoded_offer).unwrap();

		match Offer::try_from(encoded_offer) {
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, Bolt12ParseError::Decode(DecodeError::InvalidValue)),
		}
	}
}

#[cfg(test)]
mod bolt12_tests {
	use super::{Bolt12ParseError, Bolt12SemanticError, Offer};
	use crate::ln::msgs::DecodeError;

	#[test]
	fn parses_bech32_encoded_offers() {
		let offers = [
			// Minimal bolt12 offer
			"lno1zcss9mk8y3wkklfvevcrszlmu23kfrxh49px20665dqwmn4p72pksese",
			// with description (but no amount)
			"lno1pgx9getnwss8vetrw3hhyuckyypwa3eyt44h6txtxquqh7lz5djge4afgfjn7k4rgrkuag0jsd5xvxg",

			// for testnet
			"lno1qgsyxjtl6luzd9t3pr62xr7eemp6awnejusgf6gw45q75vcfqqqqqqq2p32x2um5ypmx2cm5dae8x93pqthvwfzadd7jejes8q9lhc4rvjxd022zv5l44g6qah82ru5rdpnpj",

			// for bitcoin (redundant)
			"lno1qgsxlc5vp2m0rvmjcxn2y34wv0m5lyc7sdj7zksgn35dvxgqqqqqqqq2p32x2um5ypmx2cm5dae8x93pqthvwfzadd7jejes8q9lhc4rvjxd022zv5l44g6qah82ru5rdpnpj",

			// for bitcoin or liquidv1
			"lno1qfqpge38tqmzyrdjj3x2qkdr5y80dlfw56ztq6yd9sme995g3gsxqqm0u2xq4dh3kdevrf4zg6hx8a60jv0gxe0ptgyfc6xkryqqqqqqqq9qc4r9wd6zqan9vd6x7unnzcss9mk8y3wkklfvevcrszlmu23kfrxh49px20665dqwmn4p72pksese",

			// with metadata
			"lno1qsgqqqqqqqqqqqqqqqqqqqqqqqqqqzsv23jhxapqwejkxar0wfe3vggzamrjghtt05kvkvpcp0a79gmy3nt6jsn98ad2xs8de6sl9qmgvcvs",

			// with amount
			"lno1pqpzwyq2p32x2um5ypmx2cm5dae8x93pqthvwfzadd7jejes8q9lhc4rvjxd022zv5l44g6qah82ru5rdpnpj",

			// with currency
			"lno1qcp4256ypqpzwyq2p32x2um5ypmx2cm5dae8x93pqthvwfzadd7jejes8q9lhc4rvjxd022zv5l44g6qah82ru5rdpnpj",

			// with expiry
			"lno1pgx9getnwss8vetrw3hhyucwq3ay997czcss9mk8y3wkklfvevcrszlmu23kfrxh49px20665dqwmn4p72pksese",

			// with issuer
			"lno1pgx9getnwss8vetrw3hhyucjy358garswvaz7tmzdak8gvfj9ehhyeeqgf85c4p3xgsxjmnyw4ehgunfv4e3vggzamrjghtt05kvkvpcp0a79gmy3nt6jsn98ad2xs8de6sl9qmgvcvs",

			// with quantity
			"lno1pgx9getnwss8vetrw3hhyuc5qyz3vggzamrjghtt05kvkvpcp0a79gmy3nt6jsn98ad2xs8de6sl9qmgvcvs",

			// with unlimited (or unknown) quantity
			"lno1pgx9getnwss8vetrw3hhyuc5qqtzzqhwcuj966ma9n9nqwqtl032xeyv6755yeflt235pmww58egx6rxry",

			// with single quantity (weird but valid)
			"lno1pgx9getnwss8vetrw3hhyuc5qyq3vggzamrjghtt05kvkvpcp0a79gmy3nt6jsn98ad2xs8de6sl9qmgvcvs",

			// with feature
			"lno1pgx9getnwss8vetrw3hhyucvp5yqqqqqqqqqqqqqqqqqqqqkyypwa3eyt44h6txtxquqh7lz5djge4afgfjn7k4rgrkuag0jsd5xvxg",

			// with blinded path via Bob (0x424242...), blinding 020202...
			"lno1pgx9getnwss8vetrw3hhyucs5ypjgef743p5fzqq9nqxh0ah7y87rzv3ud0eleps9kl2d5348hq2k8qzqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgqpqqqqqqqqqqqqqqqqqqqqqqqqqqqzqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqqzq3zyg3zyg3zyg3vggzamrjghtt05kvkvpcp0a79gmy3nt6jsn98ad2xs8de6sl9qmgvcvs",

			// ... and with sciddir introduction node
			"lno1pgx9getnwss8vetrw3hhyucs3yqqqqqqqqqqqqp2qgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqqyqqqqqqqqqqqqqqqqqqqqqqqqqqqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqqgzyg3zyg3zyg3z93pqthvwfzadd7jejes8q9lhc4rvjxd022zv5l44g6qah82ru5rdpnpj",

			// with no issuer_id and blinded path via Bob (0x424242...), blinding 020202...
			"lno1pgx9getnwss8vetrw3hhyucs5ypjgef743p5fzqq9nqxh0ah7y87rzv3ud0eleps9kl2d5348hq2k8qzqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgqpqqqqqqqqqqqqqqqqqqqqqqqqqqqzqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqqzq3zyg3zyg3zygs",

			//... and with second blinded path via 1x2x3 (direction 1), blinding 020202...
			"lno1pgx9getnwss8vetrw3hhyucsl5qj5qeyv5l2cs6y3qqzesrth7mlzrlp3xg7xhulusczm04x6g6nms9trspqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqqsqqqqqqqqqqqqqqqqqqqqqqqqqqpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqsqpqg3zyg3zyg3zygpqqqqzqqqqgqqxqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqqgqqqqqqqqqqqqqqqqqqqqqqqqqqqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgqqsg3zyg3zyg3zygtzzqhwcuj966ma9n9nqwqtl032xeyv6755yeflt235pmww58egx6rxry",

			// unknown odd field
			"lno1pgx9getnwss8vetrw3hhyuckyypwa3eyt44h6txtxquqh7lz5djge4afgfjn7k4rgrkuag0jsd5xvxfppf5x2mrvdamk7unvvs",
		];
		for encoded_offer in &offers {
			if let Err(e) = encoded_offer.parse::<Offer>() {
				panic!("Invalid offer ({:?}): {}", e, encoded_offer);
			}
		}
	}

	#[test]
	fn fails_parsing_bech32_encoded_offers() {
		// Malformed: fields out of order
		assert_eq!(
			"lno1zcssyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszpgz5znzfgdzs".parse::<Offer>(),
			Err(Bolt12ParseError::Decode(DecodeError::InvalidValue)),
		);

		// Malformed: unknown even TLV type 78
		assert_eq!(
			"lno1pgz5znzfgdz3vggzqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpysgr0u2xq4dh3kdevrf4zg6hx8a60jv0gxe0ptgyfc6xkryqqqqqqqq".parse::<Offer>(),
			Err(Bolt12ParseError::Decode(DecodeError::UnknownRequiredFeature)),
		);

		// Malformed: empty
		assert_eq!(
			"lno1".parse::<Offer>(),
			Err(Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::MissingIssuerSigningPubkey)),
		);

		// Malformed: truncated at type
		assert_eq!(
			"lno1pg".parse::<Offer>(),
			Err(Bolt12ParseError::Decode(DecodeError::ShortRead)),
		);

		// Malformed: truncated in length
		assert_eq!(
			"lno1pt7s".parse::<Offer>(),
			Err(Bolt12ParseError::Decode(DecodeError::ShortRead)),
		);

		// Malformed: truncated after length
		assert_eq!(
			"lno1pgpq".parse::<Offer>(),
			Err(Bolt12ParseError::Decode(DecodeError::ShortRead)),
		);

		// Malformed: truncated in description
		assert_eq!(
			"lno1pgpyz".parse::<Offer>(),
			Err(Bolt12ParseError::Decode(DecodeError::ShortRead)),
		);

		// Malformed: invalid offer_chains length
		assert_eq!(
			"lno1qgqszzs9g9xyjs69zcssyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqsz".parse::<Offer>(),
			Err(Bolt12ParseError::Decode(DecodeError::ShortRead)),
		);

		// Malformed: truncated currency UTF-8
		assert_eq!(
			"lno1qcqcqzs9g9xyjs69zcssyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqsz".parse::<Offer>(),
			Err(Bolt12ParseError::Decode(DecodeError::ShortRead)),
		);

		// Malformed: invalid currency UTF-8
		assert_eq!(
			"lno1qcpgqsg2q4q5cj2rg5tzzqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqg".parse::<Offer>(),
			Err(Bolt12ParseError::Decode(DecodeError::ShortRead)),
		);

		// Malformed: truncated description UTF-8
		assert_eq!(
			"lno1pgqcq93pqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqy".parse::<Offer>(),
			Err(Bolt12ParseError::Decode(DecodeError::InvalidValue)),
		);

		// Malformed: invalid description UTF-8
		assert_eq!(
			"lno1pgpgqsgkyypqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqs".parse::<Offer>(),
			Err(Bolt12ParseError::Decode(DecodeError::InvalidValue)),
		);

		// Malformed: truncated offer_paths
		assert_eq!(
			"lno1pgz5znzfgdz3qqgpzcssyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqsz".parse::<Offer>(),
			Err(Bolt12ParseError::Decode(DecodeError::ShortRead)),
		);

		// Malformed: zero num_hops in blinded_path
		assert_eq!(
			"lno1pgz5znzfgdz3qqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqsqzcssyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqsz".parse::<Offer>(),
			Err(Bolt12ParseError::Decode(DecodeError::ShortRead)),
		);

		// Malformed: truncated onionmsg_hop in blinded_path
		assert_eq!(
			"lno1pgz5znzfgdz3qqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqspqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqgkyypqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqs".parse::<Offer>(),
			Err(Bolt12ParseError::Decode(DecodeError::ShortRead)),
		);

		// Malformed: bad first_node_id in blinded_path
		assert_eq!(
			"lno1pgz5znzfgdz3qqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqspqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqgqzcssyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqsz".parse::<Offer>(),
			Err(Bolt12ParseError::Decode(DecodeError::ShortRead)),
		);

		// Malformed: bad blinding in blinded_path
		assert_eq!(
			"lno1pgz5znzfgdz3qqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcpqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqgqzcssyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqsz".parse::<Offer>(),
			Err(Bolt12ParseError::Decode(DecodeError::ShortRead)),
		);

		// Malformed: bad blinded_node_id in onionmsg_hop
		assert_eq!(
			"lno1pgz5znzfgdz3qqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqspqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqgqzcssyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqsz".parse::<Offer>(),
			Err(Bolt12ParseError::Decode(DecodeError::ShortRead)),
		);

		// Malformed: truncated issuer UTF-8
		assert_eq!(
			"lno1pgz5znzfgdz3yqvqzcssyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqsz".parse::<Offer>(),
			Err(Bolt12ParseError::Decode(DecodeError::InvalidValue)),
		);

		// Malformed: invalid issuer UTF-8
		assert_eq!(
			"lno1pgz5znzfgdz3yq5qgytzzqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqg".parse::<Offer>(),
			Err(Bolt12ParseError::Decode(DecodeError::InvalidValue)),
		);

		// Malformed: invalid offer_issuer_id
		assert_eq!(
			"lno1pgz5znzfgdz3vggzqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvps".parse::<Offer>(),
			Err(Bolt12ParseError::Decode(DecodeError::InvalidValue)),
		);

		// Contains type >= 80
		assert_eq!(
			"lno1pgz5znzfgdz3vggzqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgp9qgr0u2xq4dh3kdevrf4zg6hx8a60jv0gxe0ptgyfc6xkryqqqqqqqq".parse::<Offer>(),
			Err(Bolt12ParseError::Decode(DecodeError::InvalidValue)),
		);

		// TODO: Resolved in spec https://github.com/lightning/bolts/pull/798/files#r1334851959
		// Contains unknown feature 22
		assert!(
			"lno1pgx9getnwss8vetrw3hhyucvqdqqqqqkyypwa3eyt44h6txtxquqh7lz5djge4afgfjn7k4rgrkuag0jsd5xvxg".parse::<Offer>().is_ok()
		);

		// Missing offer_description
		assert_eq!(
			// TODO: Match the spec once it is updated.
			"lno1pqpq86qkyypwa3eyt44h6txtxquqh7lz5djge4afgfjn7k4rgrkuag0jsd5xvxg".parse::<Offer>(),
			Err(Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::MissingDescription)),
		);

		// Missing offer_issuer_id
		assert_eq!(
			"lno1pgx9getnwss8vetrw3hhyuc".parse::<Offer>(),
			Err(Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::MissingIssuerSigningPubkey)),
		);

		// Second offer_path is empty
		assert_eq!(
			"lno1pgx9getnwss8vetrw3hhyucsespjgef743p5fzqq9nqxh0ah7y87rzv3ud0eleps9kl2d5348hq2k8qzqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgqpqqqqqqqqqqqqqqqqqqqqqqqqqqqzqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqqzq3zyg3zyg3zygszqqqqyqqqqsqqvpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqsq".parse::<Offer>(),
			Err(Bolt12ParseError::Decode(DecodeError::InvalidValue)),
		);
	}
}
