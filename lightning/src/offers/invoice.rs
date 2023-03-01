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
//! An [`Invoice`] can be built from a parsed [`InvoiceRequest`] for the "offer to be paid" flow or
//! from a [`Refund`] as an "offer for money" flow. The expected recipient of the payment then sends
//! the invoice to the intended payer, who will then pay it.
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
//! # use lightning::onion_message::BlindedPath;
//! #
//! # fn create_payment_paths() -> Vec<(BlindedPath, BlindedPayInfo)> { unimplemented!() }
//! # fn create_payment_hash() -> PaymentHash { unimplemented!() }
//! #
//! # fn parse_invoice_request(bytes: Vec<u8>) -> Result<(), lightning::offers::parse::ParseError> {
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
//!     .sign::<_, Infallible>(|digest| Ok(secp_ctx.sign_schnorr_no_aux_rand(digest, &keys)))
//!     .expect("failed verifying signature")
//!     .write(&mut buffer)
//!     .unwrap();
//! # Ok(())
//! # }
//!
//! # fn parse_refund(bytes: Vec<u8>) -> Result<(), lightning::offers::parse::ParseError> {
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
//!     .sign::<_, Infallible>(|digest| Ok(secp_ctx.sign_schnorr_no_aux_rand(digest, &keys)))
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
use crate::offers::refund::{Refund, RefundContents};
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
		let amount_msats = match invoice_request.amount_msats() {
			Some(amount_msats) => amount_msats,
			None => match invoice_request.contents.offer.amount() {
				Some(Amount::Bitcoin { amount_msats }) => {
					amount_msats.checked_mul(invoice_request.quantity().unwrap_or(1))
						.ok_or(SemanticError::InvalidAmount)?
				},
				Some(Amount::Currency { .. }) => return Err(SemanticError::UnsupportedCurrency),
				None => return Err(SemanticError::MissingAmount),
			},
		};

		let contents = InvoiceContents::ForOffer {
			invoice_request: invoice_request.contents.clone(),
			fields: InvoiceFields {
				payment_paths, created_at, relative_expiry: None, payment_hash, amount_msats,
				fallbacks: None, features: Bolt12InvoiceFeatures::empty(),
				signing_pubkey: invoice_request.contents.offer.signing_pubkey(),
			},
		};

		Self::new(&invoice_request.bytes, contents)
	}

	pub(super) fn for_refund(
		refund: &'a Refund, payment_paths: Vec<(BlindedPath, BlindedPayInfo)>, created_at: Duration,
		payment_hash: PaymentHash, signing_pubkey: PublicKey
	) -> Result<Self, SemanticError> {
		let contents = InvoiceContents::ForRefund {
			refund: refund.contents.clone(),
			fields: InvoiceFields {
				payment_paths, created_at, relative_expiry: None, payment_hash,
				amount_msats: refund.amount_msats(), fallbacks: None,
				features: Bolt12InvoiceFeatures::empty(), signing_pubkey,
			},
		};

		Self::new(&refund.bytes, contents)
	}

	fn new(invreq_bytes: &'a Vec<u8>, contents: InvoiceContents) -> Result<Self, SemanticError> {
		if contents.fields().payment_paths.is_empty() {
			return Err(SemanticError::MissingPaths);
		}

		Ok(Self { invreq_bytes, invoice: contents })
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
	/// The public key corresponding to the key needed to sign the invoice.
	pub fn signing_pubkey(&self) -> PublicKey {
		self.invoice.fields().signing_pubkey
	}

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
#[derive(Clone, Debug, PartialEq)]
pub struct Invoice {
	bytes: Vec<u8>,
	contents: InvoiceContents,
	signature: Signature,
}

/// The contents of an [`Invoice`] for responding to either an [`Offer`] or a [`Refund`].
///
/// [`Offer`]: crate::offers::offer::Offer
/// [`Refund`]: crate::offers::refund::Refund
#[derive(Clone, Debug, PartialEq)]
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
#[derive(Clone, Debug, PartialEq)]
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
	/// needed for routing payments across them.
	///
	/// Blinded paths provide recipient privacy by obfuscating its node id. Note, however, that this
	/// privacy is lost if a public node id is used for [`Invoice::signing_pubkey`].
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

	/// The public key corresponding to the key used to sign the invoice.
	pub fn signing_pubkey(&self) -> PublicKey {
		self.contents.fields().signing_pubkey
	}

	/// Signature of the invoice verified using [`Invoice::signing_pubkey`].
	pub fn signature(&self) -> Signature {
		self.signature
	}

	#[cfg(test)]
	fn as_tlv_stream(&self) -> FullInvoiceTlvStreamRef {
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

impl Writeable for InvoiceContents {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		self.as_tlv_stream().write(writer)
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
#[derive(Clone, Debug, PartialEq)]
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

#[cfg(test)]
mod tests {
	use super::{DEFAULT_RELATIVE_EXPIRY, BlindedPayInfo, FallbackAddress, FullInvoiceTlvStreamRef, Invoice, InvoiceTlvStreamRef, SIGNATURE_TAG};

	use bitcoin::blockdata::script::Script;
	use bitcoin::hashes::Hash;
	use bitcoin::network::constants::Network;
	use bitcoin::secp256k1::{KeyPair, Message, PublicKey, Secp256k1, SecretKey, XOnlyPublicKey, self};
	use bitcoin::secp256k1::schnorr::Signature;
	use bitcoin::util::address::{Address, Payload, WitnessVersion};
	use bitcoin::util::schnorr::TweakedPublicKey;
	use core::convert::{Infallible, TryFrom};
	use core::time::Duration;
	use crate::ln::PaymentHash;
	use crate::ln::msgs::DecodeError;
	use crate::ln::features::{BlindedHopFeatures, Bolt12InvoiceFeatures};
	use crate::offers::invoice_request::InvoiceRequestTlvStreamRef;
	use crate::offers::merkle::{SignError, SignatureTlvStreamRef, self};
	use crate::offers::offer::{OfferBuilder, OfferTlvStreamRef, Quantity};
	use crate::offers::parse::{ParseError, SemanticError};
	use crate::offers::payer::PayerTlvStreamRef;
	use crate::offers::refund::RefundBuilder;
	use crate::onion_message::{BlindedHop, BlindedPath};
	use crate::util::ser::{BigSize, Iterable, Writeable};

	fn payer_keys() -> KeyPair {
		let secp_ctx = Secp256k1::new();
		KeyPair::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[42; 32]).unwrap())
	}

	fn payer_sign(digest: &Message) -> Result<Signature, Infallible> {
		let secp_ctx = Secp256k1::new();
		let keys = KeyPair::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[42; 32]).unwrap());
		Ok(secp_ctx.sign_schnorr_no_aux_rand(digest, &keys))
	}

	fn payer_pubkey() -> PublicKey {
		payer_keys().public_key()
	}

	fn recipient_keys() -> KeyPair {
		let secp_ctx = Secp256k1::new();
		KeyPair::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[43; 32]).unwrap())
	}

	fn recipient_sign(digest: &Message) -> Result<Signature, Infallible> {
		let secp_ctx = Secp256k1::new();
		let keys = KeyPair::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[43; 32]).unwrap());
		Ok(secp_ctx.sign_schnorr_no_aux_rand(digest, &keys))
	}

	fn recipient_pubkey() -> PublicKey {
		recipient_keys().public_key()
	}

	fn pubkey(byte: u8) -> PublicKey {
		let secp_ctx = Secp256k1::new();
		PublicKey::from_secret_key(&secp_ctx, &privkey(byte))
	}

	fn privkey(byte: u8) -> SecretKey {
		SecretKey::from_slice(&[byte; 32]).unwrap()
	}

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

	fn payment_paths() -> Vec<(BlindedPath, BlindedPayInfo)> {
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

		let payinfo = vec![
			BlindedPayInfo {
				fee_base_msat: 1,
				fee_proportional_millionths: 1_000,
				cltv_expiry_delta: 42,
				htlc_minimum_msat: 100,
				htlc_maximum_msat: 1_000_000_000_000,
				features: BlindedHopFeatures::empty(),
			},
			BlindedPayInfo {
				fee_base_msat: 1,
				fee_proportional_millionths: 1_000,
				cltv_expiry_delta: 42,
				htlc_minimum_msat: 100,
				htlc_maximum_msat: 1_000_000_000_000,
				features: BlindedHopFeatures::empty(),
			},
		];

		paths.into_iter().zip(payinfo.into_iter()).collect()
	}

	fn payment_hash() -> PaymentHash {
		PaymentHash([42; 32])
	}

	fn now() -> Duration {
		std::time::SystemTime::now()
			.duration_since(std::time::SystemTime::UNIX_EPOCH)
			.expect("SystemTime::now() should come after SystemTime::UNIX_EPOCH")
	}

	#[test]
	fn builds_invoice_for_offer_with_defaults() {
		let payment_paths = payment_paths();
		let payment_hash = payment_hash();
		let now = now();
		let invoice = OfferBuilder::new("foo".into(), recipient_pubkey())
			.amount_msats(1000)
			.build().unwrap()
			.request_invoice(vec![1; 32], payer_pubkey()).unwrap()
			.build().unwrap()
			.sign(payer_sign).unwrap()
			.respond_with_no_std(payment_paths.clone(), payment_hash, now).unwrap()
			.build().unwrap()
			.sign(recipient_sign).unwrap();

		let mut buffer = Vec::new();
		invoice.write(&mut buffer).unwrap();

		assert_eq!(invoice.bytes, buffer.as_slice());
		assert_eq!(invoice.payment_paths(), payment_paths.as_slice());
		assert_eq!(invoice.created_at(), now);
		assert_eq!(invoice.relative_expiry(), DEFAULT_RELATIVE_EXPIRY);
		#[cfg(feature = "std")]
		assert!(!invoice.is_expired());
		assert_eq!(invoice.payment_hash(), payment_hash);
		assert_eq!(invoice.amount_msats(), 1000);
		assert_eq!(invoice.fallbacks(), vec![]);
		assert_eq!(invoice.features(), &Bolt12InvoiceFeatures::empty());
		assert_eq!(invoice.signing_pubkey(), recipient_pubkey());
		assert!(
			merkle::verify_signature(
				&invoice.signature, SIGNATURE_TAG, &invoice.bytes, recipient_pubkey()
			).is_ok()
		);

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
					paths: Some(Iterable(payment_paths.iter().map(|(path, _)| path))),
					blindedpay: Some(Iterable(payment_paths.iter().map(|(_, payinfo)| payinfo))),
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

		if let Err(e) = Invoice::try_from(buffer) {
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
		assert_eq!(invoice.payment_paths(), payment_paths.as_slice());
		assert_eq!(invoice.created_at(), now);
		assert_eq!(invoice.relative_expiry(), DEFAULT_RELATIVE_EXPIRY);
		#[cfg(feature = "std")]
		assert!(!invoice.is_expired());
		assert_eq!(invoice.payment_hash(), payment_hash);
		assert_eq!(invoice.amount_msats(), 1000);
		assert_eq!(invoice.fallbacks(), vec![]);
		assert_eq!(invoice.features(), &Bolt12InvoiceFeatures::empty());
		assert_eq!(invoice.signing_pubkey(), recipient_pubkey());
		assert!(
			merkle::verify_signature(
				&invoice.signature, SIGNATURE_TAG, &invoice.bytes, recipient_pubkey()
			).is_ok()
		);

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
					paths: Some(Iterable(payment_paths.iter().map(|(path, _)| path))),
					blindedpay: Some(Iterable(payment_paths.iter().map(|(_, payinfo)| payinfo))),
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

		if let Err(e) = Invoice::try_from(buffer) {
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
			Err(e) => assert_eq!(e, SemanticError::AlreadyExpired),
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
			Err(e) => assert_eq!(e, SemanticError::AlreadyExpired),
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
			Err(e) => assert_eq!(e, SemanticError::InvalidAmount),
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
		assert_eq!(invoice.features(), &features);
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

		if let Err(e) = Invoice::try_from(buffer) {
			panic!("error parsing invoice: {:?}", e);
		}

		let mut tlv_stream = invoice.as_tlv_stream();
		tlv_stream.3.paths = None;

		match Invoice::try_from(tlv_stream.to_bytes()) {
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, ParseError::InvalidSemantics(SemanticError::MissingPaths)),
		}

		let mut tlv_stream = invoice.as_tlv_stream();
		tlv_stream.3.blindedpay = None;

		match Invoice::try_from(tlv_stream.to_bytes()) {
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, ParseError::InvalidSemantics(SemanticError::InvalidPayInfo)),
		}

		let empty_payment_paths = vec![];
		let mut tlv_stream = invoice.as_tlv_stream();
		tlv_stream.3.paths = Some(Iterable(empty_payment_paths.iter().map(|(path, _)| path)));

		match Invoice::try_from(tlv_stream.to_bytes()) {
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, ParseError::InvalidSemantics(SemanticError::MissingPaths)),
		}

		let mut payment_paths = payment_paths();
		payment_paths.pop();
		let mut tlv_stream = invoice.as_tlv_stream();
		tlv_stream.3.blindedpay = Some(Iterable(payment_paths.iter().map(|(_, payinfo)| payinfo)));

		match Invoice::try_from(tlv_stream.to_bytes()) {
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, ParseError::InvalidSemantics(SemanticError::InvalidPayInfo)),
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

		if let Err(e) = Invoice::try_from(buffer) {
			panic!("error parsing invoice: {:?}", e);
		}

		let mut tlv_stream = invoice.as_tlv_stream();
		tlv_stream.3.created_at = None;

		match Invoice::try_from(tlv_stream.to_bytes()) {
			Ok(_) => panic!("expected error"),
			Err(e) => {
				assert_eq!(e, ParseError::InvalidSemantics(SemanticError::MissingCreationTime));
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

		match Invoice::try_from(buffer) {
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

		if let Err(e) = Invoice::try_from(buffer) {
			panic!("error parsing invoice: {:?}", e);
		}

		let mut tlv_stream = invoice.as_tlv_stream();
		tlv_stream.3.payment_hash = None;

		match Invoice::try_from(tlv_stream.to_bytes()) {
			Ok(_) => panic!("expected error"),
			Err(e) => {
				assert_eq!(e, ParseError::InvalidSemantics(SemanticError::MissingPaymentHash));
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

		if let Err(e) = Invoice::try_from(buffer) {
			panic!("error parsing invoice: {:?}", e);
		}

		let mut tlv_stream = invoice.as_tlv_stream();
		tlv_stream.3.amount = None;

		match Invoice::try_from(tlv_stream.to_bytes()) {
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, ParseError::InvalidSemantics(SemanticError::MissingAmount)),
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

		match Invoice::try_from(buffer) {
			Ok(invoice) => {
				let mut features = Bolt12InvoiceFeatures::empty();
				features.set_basic_mpp_optional();
				assert_eq!(invoice.features(), &features);
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
		let mut unsigned_invoice = invoice_request
			.respond_with_no_std(payment_paths(), payment_hash(), now()).unwrap()
			.fallback_v0_p2wsh(&script.wscript_hash())
			.fallback_v0_p2wpkh(&pubkey.wpubkey_hash().unwrap())
			.fallback_v1_p2tr_tweaked(&tweaked_pubkey)
			.build().unwrap();

		// Only standard addresses will be included.
		let fallbacks = unsigned_invoice.invoice.fields_mut().fallbacks.as_mut().unwrap();
		// Non-standard addresses
		fallbacks.push(FallbackAddress { version: 1, program: vec![0u8; 41] });
		fallbacks.push(FallbackAddress { version: 2, program: vec![0u8; 1] });
		fallbacks.push(FallbackAddress { version: 17, program: vec![0u8; 40] });
		// Standard address
		fallbacks.push(FallbackAddress { version: 1, program: vec![0u8; 33] });
		fallbacks.push(FallbackAddress { version: 2, program: vec![0u8; 40] });

		let invoice = unsigned_invoice.sign(recipient_sign).unwrap();
		let mut buffer = Vec::new();
		invoice.write(&mut buffer).unwrap();

		match Invoice::try_from(buffer) {
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

		if let Err(e) = Invoice::try_from(buffer) {
			panic!("error parsing invoice: {:?}", e);
		}

		let mut tlv_stream = invoice.as_tlv_stream();
		tlv_stream.3.node_id = None;

		match Invoice::try_from(tlv_stream.to_bytes()) {
			Ok(_) => panic!("expected error"),
			Err(e) => {
				assert_eq!(e, ParseError::InvalidSemantics(SemanticError::MissingSigningPubkey));
			},
		}

		let invalid_pubkey = payer_pubkey();
		let mut tlv_stream = invoice.as_tlv_stream();
		tlv_stream.3.node_id = Some(&invalid_pubkey);

		match Invoice::try_from(tlv_stream.to_bytes()) {
			Ok(_) => panic!("expected error"),
			Err(e) => {
				assert_eq!(e, ParseError::InvalidSemantics(SemanticError::InvalidSigningPubkey));
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
			.invoice
			.write(&mut buffer).unwrap();

		match Invoice::try_from(buffer) {
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, ParseError::InvalidSemantics(SemanticError::MissingSignature)),
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

		match Invoice::try_from(buffer) {
			Ok(_) => panic!("expected error"),
			Err(e) => {
				assert_eq!(e, ParseError::InvalidSignature(secp256k1::Error::InvalidSignature));
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

		match Invoice::try_from(encoded_invoice) {
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, ParseError::Decode(DecodeError::InvalidValue)),
		}
	}
}
