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
use bitcoin::hash_types::{WPubkeyHash, WScriptHash};
use bitcoin::hashes::Hash;
use bitcoin::network::constants::Network;
use bitcoin::secp256k1::{Message, PublicKey};
use bitcoin::secp256k1::schnorr::Signature;
use bitcoin::util::address::{Address, Payload, WitnessVersion};
use bitcoin::util::schnorr::TweakedPublicKey;
use core::convert::TryFrom;
use core::time::Duration;
use crate::io;
use crate::ln::PaymentHash;
use crate::ln::features::{BlindedHopFeatures, Bolt12InvoiceFeatures};
use crate::ln::msgs::DecodeError;
use crate::offers::invoice_request::{InvoiceRequest, InvoiceRequestContents, InvoiceRequestTlvStream, InvoiceRequestTlvStreamRef};
use crate::offers::merkle::{SignError, SignatureTlvStream, SignatureTlvStreamRef, WithoutSignatures, self};
use crate::offers::offer::{Amount, OfferTlvStream, OfferTlvStreamRef};
use crate::offers::parse::{ParseError, ParsedMessage, SemanticError};
use crate::offers::payer::{PayerTlvStream, PayerTlvStreamRef};
use crate::offers::refund::RefundContents;
use crate::onion_message::BlindedPath;
use crate::util::ser::{HighZeroBytesDroppedBigSize, Iterable, SeekReadable, WithoutLength, Writeable, Writer};

use crate::prelude::*;

#[cfg(feature = "std")]
use std::time::SystemTime;

const DEFAULT_RELATIVE_EXPIRY: Duration = Duration::from_secs(7200);

const SIGNATURE_TAG: &'static str = concat!("lightning", "invoice", "signature");

/// Builds an [`Invoice`] from either:
/// - an [`InvoiceRequest`] for the "offer to be paid" flow or
/// - a [`Refund`] for the "offer for money" flow.
///
/// See [module-level documentation] for usage.
///
/// [`InvoiceRequest`]: crate::offers::invoice_request::InvoiceRequest
/// [`Refund`]: crate::offers::refund::Refund
/// [module-level documentation]: self
pub struct InvoiceBuilder<'a> {
	invreq_bytes: &'a Vec<u8>,
	invoice: InvoiceContents,
}

impl<'a> InvoiceBuilder<'a> {
	pub(super) fn for_offer(
		invoice_request: &'a InvoiceRequest, payment_paths: Vec<(BlindedPath, BlindedPayInfo)>,
		created_at: Duration, payment_hash: PaymentHash
	) -> Result<Self, SemanticError> {
		if payment_paths.is_empty() {
			return Err(SemanticError::MissingPaths);
		}

		let amount_msats = match invoice_request.amount_msats() {
			Some(amount_msats) => amount_msats,
			None => match invoice_request.contents.offer.amount() {
				Some(Amount::Bitcoin { amount_msats }) => {
					amount_msats * invoice_request.quantity().unwrap_or(1)
				},
				Some(Amount::Currency { .. }) => return Err(SemanticError::UnsupportedCurrency),
				None => return Err(SemanticError::MissingAmount),
			},
		};

		Ok(Self {
			invreq_bytes: &invoice_request.bytes,
			invoice: InvoiceContents::ForOffer {
				invoice_request: invoice_request.contents.clone(),
				fields: InvoiceFields {
					payment_paths, created_at, relative_expiry: None, payment_hash, amount_msats,
					fallbacks: None, features: Bolt12InvoiceFeatures::empty(),
					signing_pubkey: invoice_request.contents.offer.signing_pubkey(),
				},
			},
		})
	}

	/// Sets the [`Invoice::relative_expiry`] as seconds since [`Invoice::created_at`]. Any expiry
	/// that has already passed is valid and can be checked for using [`Invoice::is_expired`].
	///
	/// Successive calls to this method will override the previous setting.
	pub fn relative_expiry(mut self, relative_expiry_secs: u32) -> Self {
		let relative_expiry = Duration::from_secs(relative_expiry_secs as u64);
		self.invoice.fields_mut().relative_expiry = Some(relative_expiry);
		self
	}

	/// Adds a P2WSH address to [`Invoice::fallbacks`].
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

	/// Adds a P2WPKH address to [`Invoice::fallbacks`].
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

	/// Adds a P2TR address to [`Invoice::fallbacks`].
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

	/// Sets [`Invoice::features`] to indicate MPP may be used. Otherwise, MPP is disallowed.
	pub fn allow_mpp(mut self) -> Self {
		self.invoice.fields_mut().features.set_basic_mpp_optional();
		self
	}

	/// Builds an unsigned [`Invoice`] after checking for valid semantics. It can be signed by
	/// [`UnsignedInvoice::sign`].
	pub fn build(self) -> Result<UnsignedInvoice<'a>, SemanticError> {
		#[cfg(feature = "std")] {
			if self.invoice.is_offer_or_refund_expired() {
				return Err(SemanticError::AlreadyExpired);
			}
		}

		let InvoiceBuilder { invreq_bytes, invoice } = self;
		Ok(UnsignedInvoice { invreq_bytes, invoice })
	}
}

/// A semantically valid [`Invoice`] that hasn't been signed.
pub struct UnsignedInvoice<'a> {
	invreq_bytes: &'a Vec<u8>,
	invoice: InvoiceContents,
}

impl<'a> UnsignedInvoice<'a> {
	/// Signs the invoice using the given function.
	pub fn sign<F, E>(self, sign: F) -> Result<Invoice, SignError<E>>
	where
		F: FnOnce(&Message) -> Result<Signature, E>
	{
		// Use the invoice_request bytes instead of the invoice_request TLV stream as the latter may
		// have contained unknown TLV records, which are not stored in `InvoiceRequestContents` or
		// `RefundContents`.
		let (_, _, _, invoice_tlv_stream) = self.invoice.as_tlv_stream();
		let invoice_request_bytes = WithoutSignatures(self.invreq_bytes);
		let unsigned_tlv_stream = (invoice_request_bytes, invoice_tlv_stream);

		let mut bytes = Vec::new();
		unsigned_tlv_stream.write(&mut bytes).unwrap();

		let pubkey = self.invoice.fields().signing_pubkey;
		let signature = merkle::sign_message(sign, SIGNATURE_TAG, &bytes, pubkey)?;

		// Append the signature TLV record to the bytes.
		let signature_tlv_stream = SignatureTlvStreamRef {
			signature: Some(&signature),
		};
		signature_tlv_stream.write(&mut bytes).unwrap();

		Ok(Invoice {
			bytes,
			contents: self.invoice,
			signature,
		})
	}
}

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
	/// Whether the original offer or refund has expired.
	#[cfg(feature = "std")]
	fn is_offer_or_refund_expired(&self) -> bool {
		match self {
			InvoiceContents::ForOffer { invoice_request, .. } => invoice_request.offer.is_expired(),
			InvoiceContents::ForRefund { refund, .. } => refund.is_expired(),
		}
	}

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

	fn fields_mut(&mut self) -> &mut InvoiceFields {
		match self {
			InvoiceContents::ForOffer { fields, .. } => fields,
			InvoiceContents::ForRefund { fields, .. } => fields,
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
			paths: Some(Iterable(self.payment_paths.iter().map(|(path, _)| path))),
			blindedpay: Some(Iterable(self.payment_paths.iter().map(|(_, payinfo)| payinfo))),
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
	core::slice::Iter<'a, (BlindedPath, BlindedPayInfo)>,
	for<'r> fn(&'r (BlindedPath, BlindedPayInfo)) -> &'r BlindedPath,
>;

type BlindedPayInfoIter<'a> = core::iter::Map<
	core::slice::Iter<'a, (BlindedPath, BlindedPayInfo)>,
	for<'r> fn(&'r (BlindedPath, BlindedPayInfo)) -> &'r BlindedPayInfo,
>;

/// Information needed to route a payment across a [`BlindedPath`].
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

type PartialInvoiceTlvStreamRef<'a> = (
	PayerTlvStreamRef<'a>,
	OfferTlvStreamRef<'a>,
	InvoiceRequestTlvStreamRef<'a>,
	InvoiceTlvStreamRef<'a>,
);

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
