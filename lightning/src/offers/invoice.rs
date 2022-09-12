// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Data structures and encoding for `invoice` messages.

use bitcoin::blockdata::constants::ChainHash;
use bitcoin::network::constants::Network;
use bitcoin::secp256k1::PublicKey;
use bitcoin::secp256k1::schnorr::Signature;
use bitcoin::util::address::{Address, Payload, WitnessVersion};
use core::convert::TryFrom;
use core::time::Duration;
use crate::io;
use crate::ln::PaymentHash;
use crate::ln::features::{BlindedHopFeatures, Bolt12InvoiceFeatures};
use crate::ln::msgs::DecodeError;
use crate::offers::invoice_request::{InvoiceRequestContents, InvoiceRequestTlvStream};
use crate::offers::merkle::{SignatureTlvStream, self};
use crate::offers::offer::OfferTlvStream;
use crate::offers::parse::{ParseError, ParsedMessage, SemanticError};
use crate::offers::payer::PayerTlvStream;
use crate::offers::refund::RefundContents;
use crate::onion_message::BlindedPath;
use crate::util::ser::{HighZeroBytesDroppedBigSize, SeekReadable, WithoutLength, Writeable, Writer};

use crate::prelude::*;

#[cfg(feature = "std")]
use std::time::SystemTime;

const DEFAULT_RELATIVE_EXPIRY: Duration = Duration::from_secs(7200);

const SIGNATURE_TAG: &'static str = concat!("lightning", "invoice", "signature");

/// An `Invoice` is a payment request, typically corresponding to an [`Offer`] or a [`Refund`].
///
/// An invoice may be sent in response to an [`InvoiceRequest`] in the case of an offer or sent
/// directly after scanning a refund. It includes all the information needed to pay a recipient.
///
/// [`Offer`]: crate::offers::offer::Offer
/// [`Refund`]: crate::offers::refund::Refund
/// [`InvoiceRequest`]: crate::offers::invoice_request::InvoiceRequest
pub struct Invoice {
	bytes: Vec<u8>,
	contents: InvoiceContents,
	signature: Signature,
}

/// The contents of an [`Invoice`] for responding to either an [`Offer`] or a [`Refund`].
///
/// [`Offer`]: crate::offers::offer::Offer
/// [`Refund`]: crate::offers::refund::Refund
enum InvoiceContents {
	/// Contents for an [`Invoice`] corresponding to an [`Offer`].
	///
	/// [`Offer`]: crate::offers::offer::Offer
	ForOffer {
		invoice_request: InvoiceRequestContents,
		fields: InvoiceFields,
	},
	/// Contents for an [`Invoice`] corresponding to a [`Refund`].
	///
	/// [`Refund`]: crate::offers::refund::Refund
	ForRefund {
		refund: RefundContents,
		fields: InvoiceFields,
	},
}

/// Invoice-specific fields for an `invoice` message.
struct InvoiceFields {
	payment_paths: Vec<(BlindedPath, BlindedPayInfo)>,
	created_at: Duration,
	relative_expiry: Option<Duration>,
	payment_hash: PaymentHash,
	amount_msats: u64,
	fallbacks: Option<Vec<FallbackAddress>>,
	features: Bolt12InvoiceFeatures,
	signing_pubkey: PublicKey,
}

impl Invoice {
	/// Paths to the recipient originating from publicly reachable nodes, including information
	/// needed for routing payments across them. Blinded paths provide recipient privacy by
	/// obfuscating its node id.
	pub fn payment_paths(&self) -> &[(BlindedPath, BlindedPayInfo)] {
		&self.contents.fields().payment_paths[..]
	}

	/// Duration since the Unix epoch when the invoice was created.
	pub fn created_at(&self) -> Duration {
		self.contents.fields().created_at
	}

	/// Duration since [`Invoice::created_at`] when the invoice has expired and therefore should no
	/// longer be paid.
	pub fn relative_expiry(&self) -> Duration {
		self.contents.fields().relative_expiry.unwrap_or(DEFAULT_RELATIVE_EXPIRY)
	}

	/// Whether the invoice has expired.
	#[cfg(feature = "std")]
	pub fn is_expired(&self) -> bool {
		let absolute_expiry = self.created_at().checked_add(self.relative_expiry());
		match absolute_expiry {
			Some(seconds_from_epoch) => match SystemTime::UNIX_EPOCH.elapsed() {
				Ok(elapsed) => elapsed > seconds_from_epoch,
				Err(_) => false,
			},
			None => false,
		}
	}

	/// SHA256 hash of the payment preimage that will be given in return for paying the invoice.
	pub fn payment_hash(&self) -> PaymentHash {
		self.contents.fields().payment_hash
	}

	/// The minimum amount required for a successful payment of the invoice.
	pub fn amount_msats(&self) -> u64 {
		self.contents.fields().amount_msats
	}

	/// Fallback addresses for paying the invoice on-chain, in order of most-preferred to
	/// least-preferred.
	pub fn fallbacks(&self) -> Vec<Address> {
		let network = match self.network() {
			None => return Vec::new(),
			Some(network) => network,
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
					program: address.program.clone(),
				},
				network,
			};

			if !address.is_standard() && version == WitnessVersion::V0 {
				return None;
			}

			Some(address)
		};

		self.contents.fields().fallbacks
			.as_ref()
			.map(|fallbacks| fallbacks.iter().filter_map(to_valid_address).collect())
			.unwrap_or_else(Vec::new)
	}

	fn network(&self) -> Option<Network> {
		let chain = self.contents.chain();
		if chain == ChainHash::using_genesis_block(Network::Bitcoin) {
			Some(Network::Bitcoin)
		} else if chain == ChainHash::using_genesis_block(Network::Testnet) {
			Some(Network::Testnet)
		} else if chain == ChainHash::using_genesis_block(Network::Signet) {
			Some(Network::Signet)
		} else if chain == ChainHash::using_genesis_block(Network::Regtest) {
			Some(Network::Regtest)
		} else {
			None
		}
	}

	/// Features pertaining to paying an invoice.
	pub fn features(&self) -> &Bolt12InvoiceFeatures {
		&self.contents.fields().features
	}

	/// The public key used to sign invoices.
	pub fn signing_pubkey(&self) -> PublicKey {
		self.contents.fields().signing_pubkey
	}

	/// Signature of the invoice using [`Invoice::signing_pubkey`].
	pub fn signature(&self) -> Signature {
		self.signature
	}
}

impl InvoiceContents {
	fn chain(&self) -> ChainHash {
		match self {
			InvoiceContents::ForOffer { invoice_request, .. } => invoice_request.chain(),
			InvoiceContents::ForRefund { refund, .. } => refund.chain(),
		}
	}

	fn fields(&self) -> &InvoiceFields {
		match self {
			InvoiceContents::ForOffer { fields, .. } => fields,
			InvoiceContents::ForRefund { fields, .. } => fields,
		}
	}
}

impl Writeable for Invoice {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		WithoutLength(&self.bytes).write(writer)
	}
}

impl TryFrom<Vec<u8>> for Invoice {
	type Error = ParseError;

	fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
		let parsed_invoice = ParsedMessage::<FullInvoiceTlvStream>::try_from(bytes)?;
		Invoice::try_from(parsed_invoice)
	}
}

tlv_stream!(InvoiceTlvStream, InvoiceTlvStreamRef, 160..240, {
	(160, paths: (Vec<BlindedPath>, WithoutLength)),
	(162, blindedpay: (Vec<BlindedPayInfo>, WithoutLength)),
	(164, created_at: (u64, HighZeroBytesDroppedBigSize)),
	(166, relative_expiry: (u32, HighZeroBytesDroppedBigSize)),
	(168, payment_hash: PaymentHash),
	(170, amount: (u64, HighZeroBytesDroppedBigSize)),
	(172, fallbacks: (Vec<FallbackAddress>, WithoutLength)),
	(174, features: (Bolt12InvoiceFeatures, WithoutLength)),
	(176, node_id: PublicKey),
});

/// Information needed to route a payment across a [`BlindedPath`] hop.
#[derive(Debug, PartialEq)]
pub struct BlindedPayInfo {
	fee_base_msat: u32,
	fee_proportional_millionths: u32,
	cltv_expiry_delta: u16,
	htlc_minimum_msat: u64,
	htlc_maximum_msat: u64,
	features: BlindedHopFeatures,
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
#[derive(Debug, PartialEq)]
pub(super) struct FallbackAddress {
	version: u8,
	program: Vec<u8>,
}

impl_writeable!(FallbackAddress, { version, program });

type FullInvoiceTlvStream =
	(PayerTlvStream, OfferTlvStream, InvoiceRequestTlvStream, InvoiceTlvStream, SignatureTlvStream);

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

impl TryFrom<ParsedMessage<FullInvoiceTlvStream>> for Invoice {
	type Error = ParseError;

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
			None => return Err(ParseError::InvalidSemantics(SemanticError::MissingSignature)),
			Some(signature) => signature,
		};
		let pubkey = contents.fields().signing_pubkey;
		merkle::verify_signature(&signature, SIGNATURE_TAG, &bytes, pubkey)?;

		Ok(Invoice { bytes, contents, signature })
	}
}

impl TryFrom<PartialInvoiceTlvStream> for InvoiceContents {
	type Error = SemanticError;

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

		let payment_paths = match (paths, blindedpay) {
			(None, _) => return Err(SemanticError::MissingPaths),
			(_, None) => return Err(SemanticError::InvalidPayInfo),
			(Some(paths), _) if paths.is_empty() => return Err(SemanticError::MissingPaths),
			(Some(paths), Some(blindedpay)) if paths.len() != blindedpay.len() => {
				return Err(SemanticError::InvalidPayInfo);
			},
			(Some(paths), Some(blindedpay)) => {
				paths.into_iter().zip(blindedpay.into_iter()).collect::<Vec<_>>()
			},
		};

		let created_at = match created_at {
			None => return Err(SemanticError::MissingCreationTime),
			Some(timestamp) => Duration::from_secs(timestamp),
		};

		let relative_expiry = relative_expiry
			.map(Into::<u64>::into)
			.map(Duration::from_secs);

		let payment_hash = match payment_hash {
			None => return Err(SemanticError::MissingPaymentHash),
			Some(payment_hash) => payment_hash,
		};

		let amount_msats = match amount {
			None => return Err(SemanticError::MissingAmount),
			Some(amount) => amount,
		};

		let features = features.unwrap_or_else(Bolt12InvoiceFeatures::empty);

		let signing_pubkey = match node_id {
			None => return Err(SemanticError::MissingSigningPubkey),
			Some(node_id) => node_id,
		};

		let fields = InvoiceFields {
			payment_paths, created_at, relative_expiry, payment_hash, amount_msats, fallbacks,
			features, signing_pubkey,
		};

		match offer_tlv_stream.node_id {
			Some(expected_signing_pubkey) => {
				if fields.signing_pubkey != expected_signing_pubkey {
					return Err(SemanticError::InvalidSigningPubkey);
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
