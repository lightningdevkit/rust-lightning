// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Data structures and encoding for `offer` messages.

use bitcoin::blockdata::constants::ChainHash;
use bitcoin::network::constants::Network;
use bitcoin::secp256k1::PublicKey;
use core::num::NonZeroU64;
use core::time::Duration;
use crate::ln::features::OfferFeatures;
use crate::onion_message::BlindedPath;
use crate::util::string::PrintableString;

use crate::prelude::*;

#[cfg(feature = "std")]
use std::time::SystemTime;

/// An `Offer` is a potentially long-lived proposal for payment of a good or service.
///
/// An offer is a precursor to an `InvoiceRequest`. A merchant publishes an offer from which a
/// customer may request an `Invoice` for a specific quantity and using an amount sufficient to
/// cover that quantity (i.e., at least `quantity * amount`). See [`Offer::amount`].
///
/// Offers may be denominated in currency other than bitcoin but are ultimately paid using the
/// latter.
///
/// Through the use of [`BlindedPath`]s, offers provide recipient privacy.
#[derive(Clone, Debug)]
pub struct Offer {
	// The serialized offer. Needed when creating an `InvoiceRequest` if the offer contains unknown
	// fields.
	bytes: Vec<u8>,
	contents: OfferContents,
}

/// The contents of an [`Offer`], which may be shared with an `InvoiceRequest` or an `Invoice`.
#[derive(Clone, Debug)]
pub(crate) struct OfferContents {
	chains: Option<Vec<ChainHash>>,
	metadata: Option<Vec<u8>>,
	amount: Option<Amount>,
	description: String,
	features: OfferFeatures,
	absolute_expiry: Option<Duration>,
	issuer: Option<String>,
	paths: Option<Vec<BlindedPath>>,
	quantity_max: Option<u64>,
	signing_pubkey: Option<PublicKey>,
}

impl Offer {
	// TODO: Return a slice once ChainHash has constants.
	// - https://github.com/rust-bitcoin/rust-bitcoin/pull/1283
	// - https://github.com/rust-bitcoin/rust-bitcoin/pull/1286
	/// The chains that may be used when paying a requested invoice (e.g., bitcoin mainnet).
	/// Payments must be denominated in units of the minimal lightning-payable unit (e.g., msats)
	/// for the selected chain.
	pub fn chains(&self) -> Vec<ChainHash> {
		self.contents.chains
			.as_ref()
			.cloned()
			.unwrap_or_else(|| vec![ChainHash::using_genesis_block(Network::Bitcoin)])
	}

	// TODO: Link to corresponding method in `InvoiceRequest`.
	/// Opaque bytes set by the originator. Useful for authentication and validating fields since it
	/// is reflected in `invoice_request` messages along with all the other fields from the `offer`.
	pub fn metadata(&self) -> Option<&Vec<u8>> {
		self.contents.metadata.as_ref()
	}

	/// The minimum amount required for a successful payment of a single item.
	pub fn amount(&self) -> Option<&Amount> {
		self.contents.amount.as_ref()
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
		match self.absolute_expiry() {
			Some(seconds_from_epoch) => match SystemTime::UNIX_EPOCH.elapsed() {
				Ok(elapsed) => elapsed > seconds_from_epoch,
				Err(_) => false,
			},
			None => false,
		}
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
		match self.contents.quantity_max {
			Some(0) => Quantity::Unbounded,
			Some(n) => Quantity::Bounded(NonZeroU64::new(n).unwrap()),
			None => Quantity::Bounded(NonZeroU64::new(1).unwrap()),
		}
	}

	/// The public key used by the recipient to sign invoices.
	pub fn signing_pubkey(&self) -> PublicKey {
		self.contents.signing_pubkey.unwrap()
	}
}

/// The minimum amount required for an item in an [`Offer`], denominated in either bitcoin or
/// another currency.
#[derive(Clone, Debug)]
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
pub enum Quantity {
	/// Up to a specific number of items (inclusive).
	Bounded(NonZeroU64),
	/// One or more items.
	Unbounded,
}
