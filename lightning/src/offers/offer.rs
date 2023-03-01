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
//! ```
//! extern crate bitcoin;
//! extern crate core;
//! extern crate lightning;
//!
//! use core::convert::TryFrom;
//! use core::num::NonZeroU64;
//! use core::time::Duration;
//!
//! use bitcoin::secp256k1::{KeyPair, PublicKey, Secp256k1, SecretKey};
//! use lightning::offers::offer::{Offer, OfferBuilder, Quantity};
//! use lightning::offers::parse::ParseError;
//! use lightning::util::ser::{Readable, Writeable};
//!
//! # use lightning::onion_message::BlindedPath;
//! # #[cfg(feature = "std")]
//! # use std::time::SystemTime;
//! #
//! # fn create_blinded_path() -> BlindedPath { unimplemented!() }
//! # fn create_another_blinded_path() -> BlindedPath { unimplemented!() }
//! #
//! # #[cfg(feature = "std")]
//! # fn build() -> Result<(), ParseError> {
//! let secp_ctx = Secp256k1::new();
//! let keys = KeyPair::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[42; 32]).unwrap());
//! let pubkey = PublicKey::from(keys);
//!
//! let expiration = SystemTime::now() + Duration::from_secs(24 * 60 * 60);
//! let offer = OfferBuilder::new("coffee, large".to_string(), pubkey)
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

use bitcoin::blockdata::constants::ChainHash;
use bitcoin::network::constants::Network;
use bitcoin::secp256k1::PublicKey;
use core::convert::TryFrom;
use core::num::NonZeroU64;
use core::str::FromStr;
use core::time::Duration;
use crate::io;
use crate::ln::features::OfferFeatures;
use crate::ln::msgs::MAX_VALUE_MSAT;
use crate::offers::invoice_request::InvoiceRequestBuilder;
use crate::offers::parse::{Bech32Encode, ParseError, ParsedMessage, SemanticError};
use crate::onion_message::BlindedPath;
use crate::util::ser::{HighZeroBytesDroppedBigSize, WithoutLength, Writeable, Writer};
use crate::util::string::PrintableString;

use crate::prelude::*;

#[cfg(feature = "std")]
use std::time::SystemTime;

/// Builds an [`Offer`] for the "offer to be paid" flow.
///
/// See [module-level documentation] for usage.
///
/// [module-level documentation]: self
pub struct OfferBuilder {
	offer: OfferContents,
}

impl OfferBuilder {
	/// Creates a new builder for an offer setting the [`Offer::description`] and using the
	/// [`Offer::signing_pubkey`] for signing invoices. The associated secret key must be remembered
	/// while the offer is valid.
	///
	/// Use a different pubkey per offer to avoid correlating offers.
	pub fn new(description: String, signing_pubkey: PublicKey) -> Self {
		let offer = OfferContents {
			chains: None, metadata: None, amount: None, description,
			features: OfferFeatures::empty(), absolute_expiry: None, issuer: None, paths: None,
			supported_quantity: Quantity::One, signing_pubkey,
		};
		OfferBuilder { offer }
	}

	/// Adds the chain hash of the given [`Network`] to [`Offer::chains`]. If not called,
	/// the chain hash of [`Network::Bitcoin`] is assumed to be the only one supported.
	///
	/// See [`Offer::chains`] on how this relates to the payment currency.
	///
	/// Successive calls to this method will add another chain hash.
	pub fn chain(mut self, network: Network) -> Self {
		let chains = self.offer.chains.get_or_insert_with(Vec::new);
		let chain = ChainHash::using_genesis_block(network);
		if !chains.contains(&chain) {
			chains.push(chain);
		}

		self
	}

	/// Sets the [`Offer::metadata`].
	///
	/// Successive calls to this method will override the previous setting.
	pub fn metadata(mut self, metadata: Vec<u8>) -> Self {
		self.offer.metadata = Some(metadata);
		self
	}

	/// Sets the [`Offer::amount`] as an [`Amount::Bitcoin`].
	///
	/// Successive calls to this method will override the previous setting.
	pub fn amount_msats(self, amount_msats: u64) -> Self {
		self.amount(Amount::Bitcoin { amount_msats })
	}

	/// Sets the [`Offer::amount`].
	///
	/// Successive calls to this method will override the previous setting.
	pub(super) fn amount(mut self, amount: Amount) -> Self {
		self.offer.amount = Some(amount);
		self
	}

	/// Sets the [`Offer::absolute_expiry`] as seconds since the Unix epoch. Any expiry that has
	/// already passed is valid and can be checked for using [`Offer::is_expired`].
	///
	/// Successive calls to this method will override the previous setting.
	pub fn absolute_expiry(mut self, absolute_expiry: Duration) -> Self {
		self.offer.absolute_expiry = Some(absolute_expiry);
		self
	}

	/// Sets the [`Offer::issuer`].
	///
	/// Successive calls to this method will override the previous setting.
	pub fn issuer(mut self, issuer: String) -> Self {
		self.offer.issuer = Some(issuer);
		self
	}

	/// Adds a blinded path to [`Offer::paths`]. Must include at least one path if only connected by
	/// private channels or if [`Offer::signing_pubkey`] is not a public node id.
	///
	/// Successive calls to this method will add another blinded path. Caller is responsible for not
	/// adding duplicate paths.
	pub fn path(mut self, path: BlindedPath) -> Self {
		self.offer.paths.get_or_insert_with(Vec::new).push(path);
		self
	}

	/// Sets the quantity of items for [`Offer::supported_quantity`]. If not called, defaults to
	/// [`Quantity::One`].
	///
	/// Successive calls to this method will override the previous setting.
	pub fn supported_quantity(mut self, quantity: Quantity) -> Self {
		self.offer.supported_quantity = quantity;
		self
	}

	/// Builds an [`Offer`] from the builder's settings.
	pub fn build(mut self) -> Result<Offer, SemanticError> {
		match self.offer.amount {
			Some(Amount::Bitcoin { amount_msats }) => {
				if amount_msats > MAX_VALUE_MSAT {
					return Err(SemanticError::InvalidAmount);
				}
			},
			Some(Amount::Currency { .. }) => return Err(SemanticError::UnsupportedCurrency),
			None => {},
		}

		if let Some(chains) = &self.offer.chains {
			if chains.len() == 1 && chains[0] == self.offer.implied_chain() {
				self.offer.chains = None;
			}
		}

		let mut bytes = Vec::new();
		self.offer.write(&mut bytes).unwrap();

		Ok(Offer {
			bytes,
			contents: self.offer,
		})
	}
}

#[cfg(test)]
impl OfferBuilder {
	fn features_unchecked(mut self, features: OfferFeatures) -> Self {
		self.offer.features = features;
		self
	}

	pub(super) fn build_unchecked(self) -> Offer {
		let mut bytes = Vec::new();
		self.offer.write(&mut bytes).unwrap();

		Offer { bytes, contents: self.offer }
	}
}

/// An `Offer` is a potentially long-lived proposal for payment of a good or service.
///
/// An offer is a precursor to an [`InvoiceRequest`]. A merchant publishes an offer from which a
/// customer may request an [`Invoice`] for a specific quantity and using an amount sufficient to
/// cover that quantity (i.e., at least `quantity * amount`). See [`Offer::amount`].
///
/// Offers may be denominated in currency other than bitcoin but are ultimately paid using the
/// latter.
///
/// Through the use of [`BlindedPath`]s, offers provide recipient privacy.
///
/// [`InvoiceRequest`]: crate::offers::invoice_request::InvoiceRequest
/// [`Invoice`]: crate::offers::invoice::Invoice
#[derive(Clone, Debug, PartialEq)]
pub struct Offer {
	// The serialized offer. Needed when creating an `InvoiceRequest` if the offer contains unknown
	// fields.
	pub(super) bytes: Vec<u8>,
	pub(super) contents: OfferContents,
}

/// The contents of an [`Offer`], which may be shared with an [`InvoiceRequest`] or an [`Invoice`].
///
/// [`InvoiceRequest`]: crate::offers::invoice_request::InvoiceRequest
/// [`Invoice`]: crate::offers::invoice::Invoice
#[derive(Clone, Debug, PartialEq)]
pub(super) struct OfferContents {
	chains: Option<Vec<ChainHash>>,
	metadata: Option<Vec<u8>>,
	amount: Option<Amount>,
	description: String,
	features: OfferFeatures,
	absolute_expiry: Option<Duration>,
	issuer: Option<String>,
	paths: Option<Vec<BlindedPath>>,
	supported_quantity: Quantity,
	signing_pubkey: PublicKey,
}

impl Offer {
	// TODO: Return a slice once ChainHash has constants.
	// - https://github.com/rust-bitcoin/rust-bitcoin/pull/1283
	// - https://github.com/rust-bitcoin/rust-bitcoin/pull/1286
	/// The chains that may be used when paying a requested invoice (e.g., bitcoin mainnet).
	/// Payments must be denominated in units of the minimal lightning-payable unit (e.g., msats)
	/// for the selected chain.
	pub fn chains(&self) -> Vec<ChainHash> {
		self.contents.chains()
	}

	pub(super) fn implied_chain(&self) -> ChainHash {
		self.contents.implied_chain()
	}

	/// Returns whether the given chain is supported by the offer.
	pub fn supports_chain(&self, chain: ChainHash) -> bool {
		self.contents.supports_chain(chain)
	}

	// TODO: Link to corresponding method in `InvoiceRequest`.
	/// Opaque bytes set by the originator. Useful for authentication and validating fields since it
	/// is reflected in `invoice_request` messages along with all the other fields from the `offer`.
	pub fn metadata(&self) -> Option<&Vec<u8>> {
		self.contents.metadata.as_ref()
	}

	/// The minimum amount required for a successful payment of a single item.
	pub fn amount(&self) -> Option<&Amount> {
		self.contents.amount()
	}

	/// A complete description of the purpose of the payment. Intended to be displayed to the user
	/// but with the caveat that it has not been verified in any way.
	pub fn description(&self) -> PrintableString {
		PrintableString(&self.contents.description)
	}

	/// Features pertaining to the offer.
	pub fn features(&self) -> &OfferFeatures {
		&self.contents.features
	}

	/// Duration since the Unix epoch when an invoice should no longer be requested.
	///
	/// If `None`, the offer does not expire.
	pub fn absolute_expiry(&self) -> Option<Duration> {
		self.contents.absolute_expiry
	}

	/// Whether the offer has expired.
	#[cfg(feature = "std")]
	pub fn is_expired(&self) -> bool {
		self.contents.is_expired()
	}

	/// The issuer of the offer, possibly beginning with `user@domain` or `domain`. Intended to be
	/// displayed to the user but with the caveat that it has not been verified in any way.
	pub fn issuer(&self) -> Option<PrintableString> {
		self.contents.issuer.as_ref().map(|issuer| PrintableString(issuer.as_str()))
	}

	/// Paths to the recipient originating from publicly reachable nodes. Blinded paths provide
	/// recipient privacy by obfuscating its node id.
	pub fn paths(&self) -> &[BlindedPath] {
		self.contents.paths.as_ref().map(|paths| paths.as_slice()).unwrap_or(&[])
	}

	/// The quantity of items supported.
	pub fn supported_quantity(&self) -> Quantity {
		self.contents.supported_quantity()
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

	/// The public key used by the recipient to sign invoices.
	pub fn signing_pubkey(&self) -> PublicKey {
		self.contents.signing_pubkey()
	}

	/// Creates an [`InvoiceRequest`] for the offer with the given `metadata` and `payer_id`, which
	/// will be reflected in the `Invoice` response.
	///
	/// The `metadata` is useful for including information about the derivation of `payer_id` such
	/// that invoice response handling can be stateless. Also serves as payer-provided entropy while
	/// hashing in the signature calculation.
	///
	/// This should not leak any information such as by using a simple BIP-32 derivation path.
	/// Otherwise, payments may be correlated.
	///
	/// Errors if the offer contains unknown required features.
	///
	/// [`InvoiceRequest`]: crate::offers::invoice_request::InvoiceRequest
	pub fn request_invoice(
		&self, metadata: Vec<u8>, payer_id: PublicKey
	) -> Result<InvoiceRequestBuilder, SemanticError> {
		if self.features().requires_unknown_bits() {
			return Err(SemanticError::UnknownRequiredFeatures);
		}

		Ok(InvoiceRequestBuilder::new(self, metadata, payer_id))
	}

	#[cfg(test)]
	pub(super) fn as_tlv_stream(&self) -> OfferTlvStreamRef {
		self.contents.as_tlv_stream()
	}
}

impl AsRef<[u8]> for Offer {
	fn as_ref(&self) -> &[u8] {
		&self.bytes
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

	#[cfg(feature = "std")]
	pub(super) fn is_expired(&self) -> bool {
		match self.absolute_expiry {
			Some(seconds_from_epoch) => match SystemTime::UNIX_EPOCH.elapsed() {
				Ok(elapsed) => elapsed > seconds_from_epoch,
				Err(_) => false,
			},
			None => false,
		}
	}

	pub fn amount(&self) -> Option<&Amount> {
		self.amount.as_ref()
	}

	pub(super) fn check_amount_msats_for_quantity(
		&self, amount_msats: Option<u64>, quantity: Option<u64>
	) -> Result<(), SemanticError> {
		let offer_amount_msats = match self.amount {
			None => 0,
			Some(Amount::Bitcoin { amount_msats }) => amount_msats,
			Some(Amount::Currency { .. }) => return Err(SemanticError::UnsupportedCurrency),
		};

		if !self.expects_quantity() || quantity.is_some() {
			let expected_amount_msats = offer_amount_msats.checked_mul(quantity.unwrap_or(1))
				.ok_or(SemanticError::InvalidAmount)?;
			let amount_msats = amount_msats.unwrap_or(expected_amount_msats);

			if amount_msats < expected_amount_msats {
				return Err(SemanticError::InsufficientAmount);
			}

			if amount_msats > MAX_VALUE_MSAT {
				return Err(SemanticError::InvalidAmount);
			}
		}

		Ok(())
	}

	pub fn supported_quantity(&self) -> Quantity {
		self.supported_quantity
	}

	pub(super) fn check_quantity(&self, quantity: Option<u64>) -> Result<(), SemanticError> {
		let expects_quantity = self.expects_quantity();
		match quantity {
			None if expects_quantity => Err(SemanticError::MissingQuantity),
			Some(_) if !expects_quantity => Err(SemanticError::UnexpectedQuantity),
			Some(quantity) if !self.is_valid_quantity(quantity) => {
				Err(SemanticError::InvalidQuantity)
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

	pub(super) fn signing_pubkey(&self) -> PublicKey {
		self.signing_pubkey
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
			metadata: self.metadata.as_ref(),
			currency,
			amount,
			description: Some(&self.description),
			features,
			absolute_expiry: self.absolute_expiry.map(|duration| duration.as_secs()),
			paths: self.paths.as_ref(),
			issuer: self.issuer.as_ref(),
			quantity_max: self.supported_quantity.to_tlv_record(),
			node_id: Some(&self.signing_pubkey),
		}
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
#[derive(Clone, Debug, PartialEq)]
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
	fn to_tlv_record(&self) -> Option<u64> {
		match self {
			Quantity::Bounded(n) => Some(n.get()),
			Quantity::Unbounded => Some(0),
			Quantity::One => None,
		}
	}
}

tlv_stream!(OfferTlvStream, OfferTlvStreamRef, 1..80, {
	(2, chains: (Vec<ChainHash>, WithoutLength)),
	(4, metadata: (Vec<u8>, WithoutLength)),
	(6, currency: CurrencyCode),
	(8, amount: (u64, HighZeroBytesDroppedBigSize)),
	(10, description: (String, WithoutLength)),
	(12, features: (OfferFeatures, WithoutLength)),
	(14, absolute_expiry: (u64, HighZeroBytesDroppedBigSize)),
	(16, paths: (Vec<BlindedPath>, WithoutLength)),
	(18, issuer: (String, WithoutLength)),
	(20, quantity_max: (u64, HighZeroBytesDroppedBigSize)),
	(22, node_id: PublicKey),
});

impl Bech32Encode for Offer {
	const BECH32_HRP: &'static str = "lno";
}

impl FromStr for Offer {
	type Err = ParseError;

	fn from_str(s: &str) -> Result<Self, <Self as FromStr>::Err> {
		Self::from_bech32_str(s)
	}
}

impl TryFrom<Vec<u8>> for Offer {
	type Error = ParseError;

	fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
		let offer = ParsedMessage::<OfferTlvStream>::try_from(bytes)?;
		let ParsedMessage { bytes, tlv_stream } = offer;
		let contents = OfferContents::try_from(tlv_stream)?;
		Ok(Offer { bytes, contents })
	}
}

impl TryFrom<OfferTlvStream> for OfferContents {
	type Error = SemanticError;

	fn try_from(tlv_stream: OfferTlvStream) -> Result<Self, Self::Error> {
		let OfferTlvStream {
			chains, metadata, currency, amount, description, features, absolute_expiry, paths,
			issuer, quantity_max, node_id,
		} = tlv_stream;

		let amount = match (currency, amount) {
			(None, None) => None,
			(None, Some(amount_msats)) if amount_msats > MAX_VALUE_MSAT => {
				return Err(SemanticError::InvalidAmount);
			},
			(None, Some(amount_msats)) => Some(Amount::Bitcoin { amount_msats }),
			(Some(_), None) => return Err(SemanticError::MissingAmount),
			(Some(iso4217_code), Some(amount)) => Some(Amount::Currency { iso4217_code, amount }),
		};

		let description = match description {
			None => return Err(SemanticError::MissingDescription),
			Some(description) => description,
		};

		let features = features.unwrap_or_else(OfferFeatures::empty);

		let absolute_expiry = absolute_expiry
			.map(|seconds_from_epoch| Duration::from_secs(seconds_from_epoch));

		let supported_quantity = match quantity_max {
			None => Quantity::One,
			Some(0) => Quantity::Unbounded,
			Some(n) => Quantity::Bounded(NonZeroU64::new(n).unwrap()),
		};

		let signing_pubkey = match node_id {
			None => return Err(SemanticError::MissingSigningPubkey),
			Some(node_id) => node_id,
		};

		Ok(OfferContents {
			chains, metadata, amount, description, features, absolute_expiry, issuer, paths,
			supported_quantity, signing_pubkey,
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
	use super::{Amount, Offer, OfferBuilder, OfferTlvStreamRef, Quantity};

	use bitcoin::blockdata::constants::ChainHash;
	use bitcoin::network::constants::Network;
	use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
	use core::convert::TryFrom;
	use core::num::NonZeroU64;
	use core::time::Duration;
	use crate::ln::features::OfferFeatures;
	use crate::ln::msgs::{DecodeError, MAX_VALUE_MSAT};
	use crate::offers::parse::{ParseError, SemanticError};
	use crate::onion_message::{BlindedHop, BlindedPath};
	use crate::util::ser::{BigSize, Writeable};
	use crate::util::string::PrintableString;

	fn pubkey(byte: u8) -> PublicKey {
		let secp_ctx = Secp256k1::new();
		PublicKey::from_secret_key(&secp_ctx, &privkey(byte))
	}

	fn privkey(byte: u8) -> SecretKey {
		SecretKey::from_slice(&[byte; 32]).unwrap()
	}

	#[test]
	fn builds_offer_with_defaults() {
		let offer = OfferBuilder::new("foo".into(), pubkey(42)).build().unwrap();

		let mut buffer = Vec::new();
		offer.write(&mut buffer).unwrap();

		assert_eq!(offer.bytes, buffer.as_slice());
		assert_eq!(offer.chains(), vec![ChainHash::using_genesis_block(Network::Bitcoin)]);
		assert!(offer.supports_chain(ChainHash::using_genesis_block(Network::Bitcoin)));
		assert_eq!(offer.metadata(), None);
		assert_eq!(offer.amount(), None);
		assert_eq!(offer.description(), PrintableString("foo"));
		assert_eq!(offer.features(), &OfferFeatures::empty());
		assert_eq!(offer.absolute_expiry(), None);
		#[cfg(feature = "std")]
		assert!(!offer.is_expired());
		assert_eq!(offer.paths(), &[]);
		assert_eq!(offer.issuer(), None);
		assert_eq!(offer.supported_quantity(), Quantity::One);
		assert_eq!(offer.signing_pubkey(), pubkey(42));

		assert_eq!(
			offer.as_tlv_stream(),
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
				node_id: Some(&pubkey(42)),
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

		let offer = OfferBuilder::new("foo".into(), pubkey(42))
			.chain(Network::Bitcoin)
			.build()
			.unwrap();
		assert!(offer.supports_chain(mainnet));
		assert_eq!(offer.chains(), vec![mainnet]);
		assert_eq!(offer.as_tlv_stream().chains, None);

		let offer = OfferBuilder::new("foo".into(), pubkey(42))
			.chain(Network::Testnet)
			.build()
			.unwrap();
		assert!(offer.supports_chain(testnet));
		assert_eq!(offer.chains(), vec![testnet]);
		assert_eq!(offer.as_tlv_stream().chains, Some(&vec![testnet]));

		let offer = OfferBuilder::new("foo".into(), pubkey(42))
			.chain(Network::Testnet)
			.chain(Network::Testnet)
			.build()
			.unwrap();
		assert!(offer.supports_chain(testnet));
		assert_eq!(offer.chains(), vec![testnet]);
		assert_eq!(offer.as_tlv_stream().chains, Some(&vec![testnet]));

		let offer = OfferBuilder::new("foo".into(), pubkey(42))
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
		let offer = OfferBuilder::new("foo".into(), pubkey(42))
			.metadata(vec![42; 32])
			.build()
			.unwrap();
		assert_eq!(offer.metadata(), Some(&vec![42; 32]));
		assert_eq!(offer.as_tlv_stream().metadata, Some(&vec![42; 32]));

		let offer = OfferBuilder::new("foo".into(), pubkey(42))
			.metadata(vec![42; 32])
			.metadata(vec![43; 32])
			.build()
			.unwrap();
		assert_eq!(offer.metadata(), Some(&vec![43; 32]));
		assert_eq!(offer.as_tlv_stream().metadata, Some(&vec![43; 32]));
	}

	#[test]
	fn builds_offer_with_amount() {
		let bitcoin_amount = Amount::Bitcoin { amount_msats: 1000 };
		let currency_amount = Amount::Currency { iso4217_code: *b"USD", amount: 10 };

		let offer = OfferBuilder::new("foo".into(), pubkey(42))
			.amount_msats(1000)
			.build()
			.unwrap();
		let tlv_stream = offer.as_tlv_stream();
		assert_eq!(offer.amount(), Some(&bitcoin_amount));
		assert_eq!(tlv_stream.amount, Some(1000));
		assert_eq!(tlv_stream.currency, None);

		let builder = OfferBuilder::new("foo".into(), pubkey(42))
			.amount(currency_amount.clone());
		let tlv_stream = builder.offer.as_tlv_stream();
		assert_eq!(builder.offer.amount, Some(currency_amount.clone()));
		assert_eq!(tlv_stream.amount, Some(10));
		assert_eq!(tlv_stream.currency, Some(b"USD"));
		match builder.build() {
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, SemanticError::UnsupportedCurrency),
		}

		let offer = OfferBuilder::new("foo".into(), pubkey(42))
			.amount(currency_amount.clone())
			.amount(bitcoin_amount.clone())
			.build()
			.unwrap();
		let tlv_stream = offer.as_tlv_stream();
		assert_eq!(tlv_stream.amount, Some(1000));
		assert_eq!(tlv_stream.currency, None);

		let invalid_amount = Amount::Bitcoin { amount_msats: MAX_VALUE_MSAT + 1 };
		match OfferBuilder::new("foo".into(), pubkey(42)).amount(invalid_amount).build() {
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, SemanticError::InvalidAmount),
		}
	}

	#[test]
	fn builds_offer_with_features() {
		let offer = OfferBuilder::new("foo".into(), pubkey(42))
			.features_unchecked(OfferFeatures::unknown())
			.build()
			.unwrap();
		assert_eq!(offer.features(), &OfferFeatures::unknown());
		assert_eq!(offer.as_tlv_stream().features, Some(&OfferFeatures::unknown()));

		let offer = OfferBuilder::new("foo".into(), pubkey(42))
			.features_unchecked(OfferFeatures::unknown())
			.features_unchecked(OfferFeatures::empty())
			.build()
			.unwrap();
		assert_eq!(offer.features(), &OfferFeatures::empty());
		assert_eq!(offer.as_tlv_stream().features, None);
	}

	#[test]
	fn builds_offer_with_absolute_expiry() {
		let future_expiry = Duration::from_secs(u64::max_value());
		let past_expiry = Duration::from_secs(0);

		let offer = OfferBuilder::new("foo".into(), pubkey(42))
			.absolute_expiry(future_expiry)
			.build()
			.unwrap();
		#[cfg(feature = "std")]
		assert!(!offer.is_expired());
		assert_eq!(offer.absolute_expiry(), Some(future_expiry));
		assert_eq!(offer.as_tlv_stream().absolute_expiry, Some(future_expiry.as_secs()));

		let offer = OfferBuilder::new("foo".into(), pubkey(42))
			.absolute_expiry(future_expiry)
			.absolute_expiry(past_expiry)
			.build()
			.unwrap();
		#[cfg(feature = "std")]
		assert!(offer.is_expired());
		assert_eq!(offer.absolute_expiry(), Some(past_expiry));
		assert_eq!(offer.as_tlv_stream().absolute_expiry, Some(past_expiry.as_secs()));
	}

	#[test]
	fn builds_offer_with_paths() {
		let paths = vec![
			BlindedPath {
				introduction_node_id: pubkey(40),
				blinding_point: pubkey(41),
				blinded_hops: vec![
					BlindedHop { blinded_node_id: pubkey(43), encrypted_payload: vec![0; 43] },
					BlindedHop { blinded_node_id: pubkey(44), encrypted_payload: vec![0; 44] },
				],
			},
			BlindedPath {
				introduction_node_id: pubkey(40),
				blinding_point: pubkey(41),
				blinded_hops: vec![
					BlindedHop { blinded_node_id: pubkey(45), encrypted_payload: vec![0; 45] },
					BlindedHop { blinded_node_id: pubkey(46), encrypted_payload: vec![0; 46] },
				],
			},
		];

		let offer = OfferBuilder::new("foo".into(), pubkey(42))
			.path(paths[0].clone())
			.path(paths[1].clone())
			.build()
			.unwrap();
		let tlv_stream = offer.as_tlv_stream();
		assert_eq!(offer.paths(), paths.as_slice());
		assert_eq!(offer.signing_pubkey(), pubkey(42));
		assert_ne!(pubkey(42), pubkey(44));
		assert_eq!(tlv_stream.paths, Some(&paths));
		assert_eq!(tlv_stream.node_id, Some(&pubkey(42)));
	}

	#[test]
	fn builds_offer_with_issuer() {
		let offer = OfferBuilder::new("foo".into(), pubkey(42))
			.issuer("bar".into())
			.build()
			.unwrap();
		assert_eq!(offer.issuer(), Some(PrintableString("bar")));
		assert_eq!(offer.as_tlv_stream().issuer, Some(&String::from("bar")));

		let offer = OfferBuilder::new("foo".into(), pubkey(42))
			.issuer("bar".into())
			.issuer("baz".into())
			.build()
			.unwrap();
		assert_eq!(offer.issuer(), Some(PrintableString("baz")));
		assert_eq!(offer.as_tlv_stream().issuer, Some(&String::from("baz")));
	}

	#[test]
	fn builds_offer_with_supported_quantity() {
		let one = NonZeroU64::new(1).unwrap();
		let ten = NonZeroU64::new(10).unwrap();

		let offer = OfferBuilder::new("foo".into(), pubkey(42))
			.supported_quantity(Quantity::One)
			.build()
			.unwrap();
		let tlv_stream = offer.as_tlv_stream();
		assert_eq!(offer.supported_quantity(), Quantity::One);
		assert_eq!(tlv_stream.quantity_max, None);

		let offer = OfferBuilder::new("foo".into(), pubkey(42))
			.supported_quantity(Quantity::Unbounded)
			.build()
			.unwrap();
		let tlv_stream = offer.as_tlv_stream();
		assert_eq!(offer.supported_quantity(), Quantity::Unbounded);
		assert_eq!(tlv_stream.quantity_max, Some(0));

		let offer = OfferBuilder::new("foo".into(), pubkey(42))
			.supported_quantity(Quantity::Bounded(ten))
			.build()
			.unwrap();
		let tlv_stream = offer.as_tlv_stream();
		assert_eq!(offer.supported_quantity(), Quantity::Bounded(ten));
		assert_eq!(tlv_stream.quantity_max, Some(10));

		let offer = OfferBuilder::new("foo".into(), pubkey(42))
			.supported_quantity(Quantity::Bounded(one))
			.build()
			.unwrap();
		let tlv_stream = offer.as_tlv_stream();
		assert_eq!(offer.supported_quantity(), Quantity::Bounded(one));
		assert_eq!(tlv_stream.quantity_max, Some(1));

		let offer = OfferBuilder::new("foo".into(), pubkey(42))
			.supported_quantity(Quantity::Bounded(ten))
			.supported_quantity(Quantity::One)
			.build()
			.unwrap();
		let tlv_stream = offer.as_tlv_stream();
		assert_eq!(offer.supported_quantity(), Quantity::One);
		assert_eq!(tlv_stream.quantity_max, None);
	}

	#[test]
	fn fails_requesting_invoice_with_unknown_required_features() {
		match OfferBuilder::new("foo".into(), pubkey(42))
			.features_unchecked(OfferFeatures::unknown())
			.build().unwrap()
			.request_invoice(vec![1; 32], pubkey(43))
		{
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, SemanticError::UnknownRequiredFeatures),
		}
	}

	#[test]
	fn parses_offer_with_chains() {
		let offer = OfferBuilder::new("foo".into(), pubkey(42))
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
		let offer = OfferBuilder::new("foo".into(), pubkey(42))
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
			Err(e) => assert_eq!(e, ParseError::InvalidSemantics(SemanticError::MissingAmount)),
		}

		let mut tlv_stream = offer.as_tlv_stream();
		tlv_stream.amount = Some(MAX_VALUE_MSAT + 1);
		tlv_stream.currency = None;

		let mut encoded_offer = Vec::new();
		tlv_stream.write(&mut encoded_offer).unwrap();

		match Offer::try_from(encoded_offer) {
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, ParseError::InvalidSemantics(SemanticError::InvalidAmount)),
		}
	}

	#[test]
	fn parses_offer_with_description() {
		let offer = OfferBuilder::new("foo".into(), pubkey(42)).build().unwrap();
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
				assert_eq!(e, ParseError::InvalidSemantics(SemanticError::MissingDescription));
			},
		}
	}

	#[test]
	fn parses_offer_with_paths() {
		let offer = OfferBuilder::new("foo".into(), pubkey(42))
			.path(BlindedPath {
				introduction_node_id: pubkey(40),
				blinding_point: pubkey(41),
				blinded_hops: vec![
					BlindedHop { blinded_node_id: pubkey(43), encrypted_payload: vec![0; 43] },
					BlindedHop { blinded_node_id: pubkey(44), encrypted_payload: vec![0; 44] },
				],
			})
			.path(BlindedPath {
				introduction_node_id: pubkey(40),
				blinding_point: pubkey(41),
				blinded_hops: vec![
					BlindedHop { blinded_node_id: pubkey(45), encrypted_payload: vec![0; 45] },
					BlindedHop { blinded_node_id: pubkey(46), encrypted_payload: vec![0; 46] },
				],
			})
			.build()
			.unwrap();
		if let Err(e) = offer.to_string().parse::<Offer>() {
			panic!("error parsing offer: {:?}", e);
		}

		let mut builder = OfferBuilder::new("foo".into(), pubkey(42));
		builder.offer.paths = Some(vec![]);

		let offer = builder.build().unwrap();
		if let Err(e) = offer.to_string().parse::<Offer>() {
			panic!("error parsing offer: {:?}", e);
		}
	}

	#[test]
	fn parses_offer_with_quantity() {
		let offer = OfferBuilder::new("foo".into(), pubkey(42))
			.supported_quantity(Quantity::One)
			.build()
			.unwrap();
		if let Err(e) = offer.to_string().parse::<Offer>() {
			panic!("error parsing offer: {:?}", e);
		}

		let offer = OfferBuilder::new("foo".into(), pubkey(42))
			.supported_quantity(Quantity::Unbounded)
			.build()
			.unwrap();
		if let Err(e) = offer.to_string().parse::<Offer>() {
			panic!("error parsing offer: {:?}", e);
		}

		let offer = OfferBuilder::new("foo".into(), pubkey(42))
			.supported_quantity(Quantity::Bounded(NonZeroU64::new(10).unwrap()))
			.build()
			.unwrap();
		if let Err(e) = offer.to_string().parse::<Offer>() {
			panic!("error parsing offer: {:?}", e);
		}

		let offer = OfferBuilder::new("foo".into(), pubkey(42))
			.supported_quantity(Quantity::Bounded(NonZeroU64::new(1).unwrap()))
			.build()
			.unwrap();
		if let Err(e) = offer.to_string().parse::<Offer>() {
			panic!("error parsing offer: {:?}", e);
		}
	}

	#[test]
	fn parses_offer_with_node_id() {
		let offer = OfferBuilder::new("foo".into(), pubkey(42)).build().unwrap();
		if let Err(e) = offer.to_string().parse::<Offer>() {
			panic!("error parsing offer: {:?}", e);
		}

		let mut tlv_stream = offer.as_tlv_stream();
		tlv_stream.node_id = None;

		let mut encoded_offer = Vec::new();
		tlv_stream.write(&mut encoded_offer).unwrap();

		match Offer::try_from(encoded_offer) {
			Ok(_) => panic!("expected error"),
			Err(e) => {
				assert_eq!(e, ParseError::InvalidSemantics(SemanticError::MissingSigningPubkey));
			},
		}
	}

	#[test]
	fn fails_parsing_offer_with_extra_tlv_records() {
		let offer = OfferBuilder::new("foo".into(), pubkey(42)).build().unwrap();

		let mut encoded_offer = Vec::new();
		offer.write(&mut encoded_offer).unwrap();
		BigSize(80).write(&mut encoded_offer).unwrap();
		BigSize(32).write(&mut encoded_offer).unwrap();
		[42u8; 32].write(&mut encoded_offer).unwrap();

		match Offer::try_from(encoded_offer) {
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, ParseError::Decode(DecodeError::InvalidValue)),
		}
	}
}

#[cfg(test)]
mod bech32_tests {
	use super::{Offer, ParseError};
	use bitcoin::bech32;
	use crate::ln::msgs::DecodeError;

	// TODO: Remove once test vectors are updated.
	#[ignore]
	#[test]
	fn encodes_offer_as_bech32_without_checksum() {
		let encoded_offer = "lno1qcp4256ypqpq86q2pucnq42ngssx2an9wfujqerp0y2pqun4wd68jtn00fkxzcnn9ehhyec6qgqsz83qfwdpl28qqmc78ymlvhmxcsywdk5wrjnj36jryg488qwlrnzyjczlqsp9nyu4phcg6dqhlhzgxagfu7zh3d9re0sqp9ts2yfugvnnm9gxkcnnnkdpa084a6t520h5zhkxsdnghvpukvd43lastpwuh73k29qsy";
		let offer = dbg!(encoded_offer.parse::<Offer>().unwrap());
		let reencoded_offer = offer.to_string();
		dbg!(reencoded_offer.parse::<Offer>().unwrap());
		assert_eq!(reencoded_offer, encoded_offer);
	}

	// TODO: Remove once test vectors are updated.
	#[ignore]
	#[test]
	fn parses_bech32_encoded_offers() {
		let offers = [
			// BOLT 12 test vectors
			"lno1qcp4256ypqpq86q2pucnq42ngssx2an9wfujqerp0y2pqun4wd68jtn00fkxzcnn9ehhyec6qgqsz83qfwdpl28qqmc78ymlvhmxcsywdk5wrjnj36jryg488qwlrnzyjczlqsp9nyu4phcg6dqhlhzgxagfu7zh3d9re0sqp9ts2yfugvnnm9gxkcnnnkdpa084a6t520h5zhkxsdnghvpukvd43lastpwuh73k29qsy",
			"l+no1qcp4256ypqpq86q2pucnq42ngssx2an9wfujqerp0y2pqun4wd68jtn00fkxzcnn9ehhyec6qgqsz83qfwdpl28qqmc78ymlvhmxcsywdk5wrjnj36jryg488qwlrnzyjczlqsp9nyu4phcg6dqhlhzgxagfu7zh3d9re0sqp9ts2yfugvnnm9gxkcnnnkdpa084a6t520h5zhkxsdnghvpukvd43lastpwuh73k29qsy",
			"l+no1qcp4256ypqpq86q2pucnq42ngssx2an9wfujqerp0y2pqun4wd68jtn00fkxzcnn9ehhyec6qgqsz83qfwdpl28qqmc78ymlvhmxcsywdk5wrjnj36jryg488qwlrnzyjczlqsp9nyu4phcg6dqhlhzgxagfu7zh3d9re0sqp9ts2yfugvnnm9gxkcnnnkdpa084a6t520h5zhkxsdnghvpukvd43lastpwuh73k29qsy",
			"lno1qcp4256ypqpq+86q2pucnq42ngssx2an9wfujqerp0y2pqun4wd68jtn0+0fkxzcnn9ehhyec6qgqsz83qfwdpl28qqmc78ymlvhmxcsywdk5wrjnj36jryg488qwlrnzyjczlqsp9nyu4phcg6dqhlhzgxagfu7zh3d9re0+sqp9ts2yfugvnnm9gxkcnnnkdpa084a6t520h5zhkxsdnghvpukvd43lastpwuh73k29qs+y",
			"lno1qcp4256ypqpq+ 86q2pucnq42ngssx2an9wfujqerp0y2pqun4wd68jtn0+  0fkxzcnn9ehhyec6qgqsz83qfwdpl28qqmc78ymlvhmxcsywdk5wrjnj36jryg488qwlrnzyjczlqsp9nyu4phcg6dqhlhzgxagfu7zh3d9re0+\nsqp9ts2yfugvnnm9gxkcnnnkdpa084a6t520h5zhkxsdnghvpukvd43l+\r\nastpwuh73k29qs+\r  y",
			// Two blinded paths
			"lno1qcp4256ypqpq86q2pucnq42ngssx2an9wfujqerp0yg06qg2qdd7t628sgykwj5kuc837qmlv9m9gr7sq8ap6erfgacv26nhp8zzcqgzhdvttlk22pw8fmwqqrvzst792mj35ypylj886ljkcmug03wg6heqqsqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq6muh550qsfva9fdes0ruph7ctk2s8aqq06r4jxj3msc448wzwy9sqs9w6ckhlv55zuwnkuqqxc9qhu24h9rggzflyw04l9d3hcslzu340jqpqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq2pqun4wd68jtn00fkxzcnn9ehhyec6qgqsz83qfwdpl28qqmc78ymlvhmxcsywdk5wrjnj36jryg488qwlrnzyjczlqsp9nyu4phcg6dqhlhzgxagfu7zh3d9re0sqp9ts2yfugvnnm9gxkcnnnkdpa084a6t520h5zhkxsdnghvpukvd43lastpwuh73k29qsy",
		];
		for encoded_offer in &offers {
			if let Err(e) = encoded_offer.parse::<Offer>() {
				panic!("Invalid offer ({:?}): {}", e, encoded_offer);
			}
		}
	}

	#[test]
	fn fails_parsing_bech32_encoded_offers_with_invalid_continuations() {
		let offers = [
			// BOLT 12 test vectors
			"lno1qcp4256ypqpq86q2pucnq42ngssx2an9wfujqerp0y2pqun4wd68jtn00fkxzcnn9ehhyec6qgqsz83qfwdpl28qqmc78ymlvhmxcsywdk5wrjnj36jryg488qwlrnzyjczlqsp9nyu4phcg6dqhlhzgxagfu7zh3d9re0sqp9ts2yfugvnnm9gxkcnnnkdpa084a6t520h5zhkxsdnghvpukvd43lastpwuh73k29qsy+",
			"lno1qcp4256ypqpq86q2pucnq42ngssx2an9wfujqerp0y2pqun4wd68jtn00fkxzcnn9ehhyec6qgqsz83qfwdpl28qqmc78ymlvhmxcsywdk5wrjnj36jryg488qwlrnzyjczlqsp9nyu4phcg6dqhlhzgxagfu7zh3d9re0sqp9ts2yfugvnnm9gxkcnnnkdpa084a6t520h5zhkxsdnghvpukvd43lastpwuh73k29qsy+ ",
			"+lno1qcp4256ypqpq86q2pucnq42ngssx2an9wfujqerp0y2pqun4wd68jtn00fkxzcnn9ehhyec6qgqsz83qfwdpl28qqmc78ymlvhmxcsywdk5wrjnj36jryg488qwlrnzyjczlqsp9nyu4phcg6dqhlhzgxagfu7zh3d9re0sqp9ts2yfugvnnm9gxkcnnnkdpa084a6t520h5zhkxsdnghvpukvd43lastpwuh73k29qsy",
			"+ lno1qcp4256ypqpq86q2pucnq42ngssx2an9wfujqerp0y2pqun4wd68jtn00fkxzcnn9ehhyec6qgqsz83qfwdpl28qqmc78ymlvhmxcsywdk5wrjnj36jryg488qwlrnzyjczlqsp9nyu4phcg6dqhlhzgxagfu7zh3d9re0sqp9ts2yfugvnnm9gxkcnnnkdpa084a6t520h5zhkxsdnghvpukvd43lastpwuh73k29qsy",
			"ln++o1qcp4256ypqpq86q2pucnq42ngssx2an9wfujqerp0y2pqun4wd68jtn00fkxzcnn9ehhyec6qgqsz83qfwdpl28qqmc78ymlvhmxcsywdk5wrjnj36jryg488qwlrnzyjczlqsp9nyu4phcg6dqhlhzgxagfu7zh3d9re0sqp9ts2yfugvnnm9gxkcnnnkdpa084a6t520h5zhkxsdnghvpukvd43lastpwuh73k29qsy",
		];
		for encoded_offer in &offers {
			match encoded_offer.parse::<Offer>() {
				Ok(_) => panic!("Valid offer: {}", encoded_offer),
				Err(e) => assert_eq!(e, ParseError::InvalidContinuation),
			}
		}

	}

	#[test]
	fn fails_parsing_bech32_encoded_offer_with_invalid_hrp() {
		let encoded_offer = "lni1qcp4256ypqpq86q2pucnq42ngssx2an9wfujqerp0y2pqun4wd68jtn00fkxzcnn9ehhyec6qgqsz83qfwdpl28qqmc78ymlvhmxcsywdk5wrjnj36jryg488qwlrnzyjczlqsp9nyu4phcg6dqhlhzgxagfu7zh3d9re0sqp9ts2yfugvnnm9gxkcnnnkdpa084a6t520h5zhkxsdnghvpukvd43lastpwuh73k29qsy";
		match encoded_offer.parse::<Offer>() {
			Ok(_) => panic!("Valid offer: {}", encoded_offer),
			Err(e) => assert_eq!(e, ParseError::InvalidBech32Hrp),
		}
	}

	#[test]
	fn fails_parsing_bech32_encoded_offer_with_invalid_bech32_data() {
		let encoded_offer = "lno1qcp4256ypqpq86q2pucnq42ngssx2an9wfujqerp0y2pqun4wd68jtn00fkxzcnn9ehhyec6qgqsz83qfwdpl28qqmc78ymlvhmxcsywdk5wrjnj36jryg488qwlrnzyjczlqsp9nyu4phcg6dqhlhzgxagfu7zh3d9re0sqp9ts2yfugvnnm9gxkcnnnkdpa084a6t520h5zhkxsdnghvpukvd43lastpwuh73k29qso";
		match encoded_offer.parse::<Offer>() {
			Ok(_) => panic!("Valid offer: {}", encoded_offer),
			Err(e) => assert_eq!(e, ParseError::Bech32(bech32::Error::InvalidChar('o'))),
		}
	}

	#[test]
	fn fails_parsing_bech32_encoded_offer_with_invalid_tlv_data() {
		let encoded_offer = "lno1qcp4256ypqpq86q2pucnq42ngssx2an9wfujqerp0y2pqun4wd68jtn00fkxzcnn9ehhyec6qgqsz83qfwdpl28qqmc78ymlvhmxcsywdk5wrjnj36jryg488qwlrnzyjczlqsp9nyu4phcg6dqhlhzgxagfu7zh3d9re0sqp9ts2yfugvnnm9gxkcnnnkdpa084a6t520h5zhkxsdnghvpukvd43lastpwuh73k29qsyqqqqq";
		match encoded_offer.parse::<Offer>() {
			Ok(_) => panic!("Valid offer: {}", encoded_offer),
			Err(e) => assert_eq!(e, ParseError::Decode(DecodeError::InvalidValue)),
		}
	}
}
