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
//! directly to the customer. The recipient responds with an `Invoice` to be paid.
//!
//! This is an [`InvoiceRequest`] produced *not* in response to an [`Offer`].
//!
//! [`InvoiceRequest`]: crate::offers::invoice_request::InvoiceRequest
//! [`Offer`]: crate::offers::offer::Offer

use bitcoin::blockdata::constants::ChainHash;
use bitcoin::network::constants::Network;
use bitcoin::secp256k1::PublicKey;
use core::convert::TryFrom;
use core::str::FromStr;
use core::time::Duration;
use crate::io;
use crate::ln::features::InvoiceRequestFeatures;
use crate::ln::msgs::{DecodeError, MAX_VALUE_MSAT};
use crate::offers::invoice_request::InvoiceRequestTlvStream;
use crate::offers::offer::OfferTlvStream;
use crate::offers::parse::{Bech32Encode, ParseError, ParsedMessage, SemanticError};
use crate::offers::payer::{PayerContents, PayerTlvStream};
use crate::onion_message::BlindedPath;
use crate::util::ser::{SeekReadable, WithoutLength, Writeable, Writer};
use crate::util::string::PrintableString;

use crate::prelude::*;

#[cfg(feature = "std")]
use std::time::SystemTime;

/// A `Refund` is a request to send an `Invoice` without a preceding [`Offer`].
///
/// Typically, after an invoice is paid, the recipient may publish a refund allowing the sender to
/// recoup their funds. A refund may be used more generally as an "offer for money", such as with a
/// bitcoin ATM.
///
/// [`Offer`]: crate::offers::offer::Offer
#[derive(Clone, Debug)]
pub struct Refund {
	bytes: Vec<u8>,
	contents: RefundContents,
}

/// The contents of a [`Refund`], which may be shared with an `Invoice`.
#[derive(Clone, Debug)]
struct RefundContents {
	payer: PayerContents,
	// offer fields
	metadata: Option<Vec<u8>>,
	description: String,
	absolute_expiry: Option<Duration>,
	issuer: Option<String>,
	paths: Option<Vec<BlindedPath>>,
	// invoice_request fields
	chain: Option<ChainHash>,
	amount_msats: u64,
	features: InvoiceRequestFeatures,
	payer_id: PublicKey,
	payer_note: Option<String>,
}

impl Refund {
	/// A complete description of the purpose of the refund. Intended to be displayed to the user
	/// but with the caveat that it has not been verified in any way.
	pub fn description(&self) -> PrintableString {
		PrintableString(&self.contents.description)
	}

	/// Duration since the Unix epoch when an invoice should no longer be sent.
	///
	/// If `None`, the refund does not expire.
	pub fn absolute_expiry(&self) -> Option<Duration> {
		self.contents.absolute_expiry
	}

	/// Whether the refund has expired.
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

	/// The issuer of the refund, possibly beginning with `user@domain` or `domain`. Intended to be
	/// displayed to the user but with the caveat that it has not been verified in any way.
	pub fn issuer(&self) -> Option<PrintableString> {
		self.contents.issuer.as_ref().map(|issuer| PrintableString(issuer.as_str()))
	}

	/// Paths to the sender originating from publicly reachable nodes. Blinded paths provide sender
	/// privacy by obfuscating its node id.
	pub fn paths(&self) -> &[BlindedPath] {
		self.contents.paths.as_ref().map(|paths| paths.as_slice()).unwrap_or(&[])
	}

	/// An unpredictable series of bytes, typically containing information about the derivation of
	/// [`payer_id`].
	///
	/// [`payer_id`]: Self::payer_id
	pub fn metadata(&self) -> &[u8] {
		&self.contents.payer.0
	}

	/// A chain that the refund is valid for.
	pub fn chain(&self) -> ChainHash {
		self.contents.chain.unwrap_or_else(|| ChainHash::using_genesis_block(Network::Bitcoin))
	}

	/// The amount to refund in msats (i.e., the minimum lightning-payable unit for [`chain`]).
	///
	/// [`chain`]: Self::chain
	pub fn amount_msats(&self) -> u64 {
		self.contents.amount_msats
	}

	/// Features pertaining to requesting an invoice.
	pub fn features(&self) -> &InvoiceRequestFeatures {
		&self.contents.features
	}

	/// A possibly transient pubkey used to sign the refund.
	pub fn payer_id(&self) -> PublicKey {
		self.contents.payer_id
	}

	/// Payer provided note to include in the invoice.
	pub fn payer_note(&self) -> Option<PrintableString> {
		self.contents.payer_note.as_ref().map(|payer_note| PrintableString(payer_note.as_str()))
	}
}

impl AsRef<[u8]> for Refund {
	fn as_ref(&self) -> &[u8] {
		&self.bytes
	}
}

impl Writeable for Refund {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		WithoutLength(&self.bytes).write(writer)
	}
}

type RefundTlvStream = (PayerTlvStream, OfferTlvStream, InvoiceRequestTlvStream);

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
	type Err = ParseError;

	fn from_str(s: &str) -> Result<Self, <Self as FromStr>::Err> {
		Refund::from_bech32_str(s)
	}
}

impl TryFrom<Vec<u8>> for Refund {
	type Error = ParseError;

	fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
		let refund = ParsedMessage::<RefundTlvStream>::try_from(bytes)?;
		let ParsedMessage { bytes, tlv_stream } = refund;
		let contents = RefundContents::try_from(tlv_stream)?;

		Ok(Refund { bytes, contents })
	}
}

impl TryFrom<RefundTlvStream> for RefundContents {
	type Error = SemanticError;

	fn try_from(tlv_stream: RefundTlvStream) -> Result<Self, Self::Error> {
		let (
			PayerTlvStream { metadata: payer_metadata },
			OfferTlvStream {
				chains, metadata, currency, amount: offer_amount, description,
				features: offer_features, absolute_expiry, paths, issuer, quantity_max, node_id,
			},
			InvoiceRequestTlvStream { chain, amount, features, quantity, payer_id, payer_note },
		) = tlv_stream;

		let payer = match payer_metadata {
			None => return Err(SemanticError::MissingPayerMetadata),
			Some(metadata) => PayerContents(metadata),
		};

		if chains.is_some() {
			return Err(SemanticError::UnexpectedChain);
		}

		if currency.is_some() || offer_amount.is_some() {
			return Err(SemanticError::UnexpectedAmount);
		}

		let description = match description {
			None => return Err(SemanticError::MissingDescription),
			Some(description) => description,
		};

		if offer_features.is_some() {
			return Err(SemanticError::UnexpectedFeatures);
		}

		let absolute_expiry = absolute_expiry.map(Duration::from_secs);

		if quantity_max.is_some() {
			return Err(SemanticError::UnexpectedQuantity);
		}

		if node_id.is_some() {
			return Err(SemanticError::UnexpectedSigningPubkey);
		}

		let amount_msats = match amount {
			None => return Err(SemanticError::MissingAmount),
			Some(amount_msats) if amount_msats > MAX_VALUE_MSAT => {
				return Err(SemanticError::InvalidAmount);
			},
			Some(amount_msats) => amount_msats,
		};

		let features = features.unwrap_or_else(InvoiceRequestFeatures::empty);

		// TODO: Check why this isn't in the spec.
		if quantity.is_some() {
			return Err(SemanticError::UnexpectedQuantity);
		}

		let payer_id = match payer_id {
			None => return Err(SemanticError::MissingPayerId),
			Some(payer_id) => payer_id,
		};

		// TODO: Should metadata be included?
		Ok(RefundContents {
			payer, metadata, description, absolute_expiry, issuer, paths, chain, amount_msats,
			features, payer_id, payer_note,
		})
	}
}

impl core::fmt::Display for Refund {
	fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
		self.fmt_bech32_str(f)
	}
}
