// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Data structures and encoding for `invoice_request` messages.

use bitcoin::secp256k1::schnorr::Signature;
use bitcoin::util::address::{Address, Payload, WitnessVersion};
use core::convert::TryFrom;
use core::time::Duration;
use crate::io;
use crate::ln::PaymentHash;
use crate::ln::features::OfferFeatures;
use crate::ln::msgs::DecodeError;
use crate::offers::merkle::{SignatureTlvStream, self};
use crate::offers::offer::OfferTlvStream;
use crate::offers::parse::{ParseError, ParsedMessage, SemanticError};
use crate::offers::payer::PayerTlvStream;
use crate::offers::invoice_request::{InvoiceRequestContents, InvoiceRequestTlvStream};
use crate::onion_message::BlindedPath;
use crate::util::ser::{HighZeroBytesDroppedBigSize, SeekReadable, WithoutLength, Writeable, Writer};

use crate::prelude::*;

///
const SIGNATURE_TAG: &'static str = concat!("lightning", "invoice", "signature");

///
pub struct Invoice {
	bytes: Vec<u8>,
	contents: InvoiceContents,
	signature: Option<Signature>,
}

///
pub(crate) struct InvoiceContents {
	invoice_request: InvoiceRequestContents,
	paths: Option<Vec<BlindedPath>>,
	payinfo: Option<Vec<BlindedPayInfo>>,
	created_at: Duration,
	relative_expiry: Option<Duration>,
	payment_hash: PaymentHash,
	amount_msats: u64,
	fallbacks: Option<Vec<Address>>,
	features: Option<OfferFeatures>,
	code: Option<String>,
}

impl Invoice {
	///
	pub fn fallbacks(&self) -> Vec<&Address> {
		let is_valid = |address: &&Address| {
			if let Address { payload: Payload::WitnessProgram { program, .. }, .. } = address {
				if address.is_standard() {
					return true;
				} else if program.len() < 2 || program.len() > 40 {
					return false;
				} else {
					return true;
				}
			}

			unreachable!()
		};
		self.contents.fallbacks
			.as_ref()
			.map(|fallbacks| fallbacks.iter().filter(is_valid).collect())
			.unwrap_or_else(Vec::new)
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
	(162, payinfo: (Vec<BlindedPayInfo>, WithoutLength)),
	(164, created_at: (u64, HighZeroBytesDroppedBigSize)),
	(166, relative_expiry: (u32, HighZeroBytesDroppedBigSize)),
	(168, payment_hash: PaymentHash),
	(170, amount: (u64, HighZeroBytesDroppedBigSize)),
	(172, fallbacks: (Vec<FallbackAddress>, WithoutLength)),
	(174, features: OfferFeatures),
	(176, code: (String, WithoutLength)),
});

///
#[derive(Debug)]
pub struct BlindedPayInfo {
	fee_base_msat: u32,
	fee_proportional_millionths: u32,
	cltv_expiry_delta: u16,
	htlc_minimum_msat: u64,
	htlc_maximum_msat: u64,
	features_len: u16,
	features: OfferFeatures,
}

impl_writeable!(BlindedPayInfo, {
	fee_base_msat,
	fee_proportional_millionths,
	cltv_expiry_delta,
	htlc_minimum_msat,
	htlc_maximum_msat,
	features_len,
	features
});

///
#[derive(Debug)]
pub struct FallbackAddress {
	version: WitnessVersion,
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

		if let Some(signature) = &signature {
			let pubkey = contents.invoice_request.offer.signing_pubkey();
			merkle::verify_signature(signature, SIGNATURE_TAG, &bytes, pubkey)?;
		}

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
				paths, payinfo, created_at, relative_expiry, payment_hash, amount, fallbacks,
				features, code,
			},
		) = tlv_stream;

		let invoice_request = InvoiceRequestContents::try_from(
			(payer_tlv_stream, offer_tlv_stream, invoice_request_tlv_stream)
		)?;

		let (paths, payinfo) = match (paths, payinfo) {
			(None, _) => return Err(SemanticError::MissingPaths),
			(_, None) => return Err(SemanticError::InvalidPayInfo),
			(Some(paths), _) if paths.is_empty() => return Err(SemanticError::MissingPaths),
			(Some(paths), Some(payinfo)) if paths.len() != payinfo.len() => {
				return Err(SemanticError::InvalidPayInfo);
			},
			(paths, payinfo) => (paths, payinfo),
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

		let fallbacks = match fallbacks {
			None => None,
			Some(fallbacks) => {
				let mut addresses = Vec::with_capacity(fallbacks.len());
				for FallbackAddress { version, program } in fallbacks {
					addresses.push(Address {
						payload: Payload::WitnessProgram { version, program },
						network: invoice_request.network(),
					});
				}
				Some(addresses)
			},
		};

		Ok(InvoiceContents {
			invoice_request, paths, payinfo, created_at, relative_expiry, payment_hash,
			amount_msats, fallbacks, features, code,
		})
	}
}
