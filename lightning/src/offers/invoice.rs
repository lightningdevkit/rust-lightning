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
//! receipt, and one or more [`BlindedPaymentPath`]s for the payer to use when sending the payment.
//!
//! ```
//! extern crate bitcoin;
//! extern crate lightning;
//!
//! use bitcoin::hashes::Hash;
//! use bitcoin::secp256k1::{Keypair, PublicKey, Secp256k1, SecretKey};
//! use core::convert::TryFrom;
//! use lightning::offers::invoice::UnsignedBolt12Invoice;
//! use lightning::offers::invoice_request::InvoiceRequest;
//! use lightning::offers::refund::Refund;
//! use lightning::util::ser::Writeable;
//!
//! # use lightning::types::payment::PaymentHash;
//! # use lightning::offers::invoice::{ExplicitSigningPubkey, InvoiceBuilder};
//! # use lightning::blinded_path::payment::{BlindedPayInfo, BlindedPaymentPath};
//! #
//! # fn create_payment_paths() -> Vec<BlindedPaymentPath> { unimplemented!() }
//! # fn create_payment_hash() -> PaymentHash { unimplemented!() }
//! #
//! # fn parse_invoice_request(bytes: Vec<u8>) -> Result<(), lightning::offers::parse::Bolt12ParseError> {
//! let payment_paths = create_payment_paths();
//! let payment_hash = create_payment_hash();
//! let secp_ctx = Secp256k1::new();
//! let keys = Keypair::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[42; 32])?);
//! let pubkey = PublicKey::from(keys);
//! let wpubkey_hash = bitcoin::key::PublicKey::new(pubkey).wpubkey_hash().unwrap();
//! let mut buffer = Vec::new();
//!
//! // Invoice for the "offer to be paid" flow.
//! # <InvoiceBuilder<ExplicitSigningPubkey>>::from(
//! InvoiceRequest::try_from(bytes)?
#![cfg_attr(
	feature = "std",
	doc = "
    .respond_with(payment_paths, payment_hash)?
"
)]
#![cfg_attr(
	not(feature = "std"),
	doc = "
    .respond_with_no_std(payment_paths, payment_hash, core::time::Duration::from_secs(0))?
"
)]
//! # )
//!     .relative_expiry(3600)
//!     .allow_mpp()
//!     .fallback_v0_p2wpkh(&wpubkey_hash)
//!     .build()?
//!     .sign(|message: &UnsignedBolt12Invoice|
//!         Ok(secp_ctx.sign_schnorr_no_aux_rand(message.as_ref().as_digest(), &keys))
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
//! # let keys = Keypair::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[42; 32])?);
//! # let pubkey = PublicKey::from(keys);
//! # let wpubkey_hash = bitcoin::key::PublicKey::new(pubkey).wpubkey_hash().unwrap();
//! # let mut buffer = Vec::new();
//!
//! // Invoice for the "offer for money" flow.
//! # <InvoiceBuilder<ExplicitSigningPubkey>>::from(
//! "lnr1qcp4256ypq"
//!     .parse::<Refund>()?
#![cfg_attr(
	feature = "std",
	doc = "
    .respond_with(payment_paths, payment_hash, pubkey)?
"
)]
#![cfg_attr(
	not(feature = "std"),
	doc = "
    .respond_with_no_std(payment_paths, payment_hash, pubkey, core::time::Duration::from_secs(0))?
"
)]
//! # )
//!     .relative_expiry(3600)
//!     .allow_mpp()
//!     .fallback_v0_p2wpkh(&wpubkey_hash)
//!     .build()?
//!     .sign(|message: &UnsignedBolt12Invoice|
//!         Ok(secp_ctx.sign_schnorr_no_aux_rand(message.as_ref().as_digest(), &keys))
//!     )
//!     .expect("failed verifying signature")
//!     .write(&mut buffer)
//!     .unwrap();
//! # Ok(())
//! # }
//!
//! ```

use crate::blinded_path::message::BlindedMessagePath;
use crate::blinded_path::payment::{BlindedPayInfo, BlindedPaymentPath};
use crate::blinded_path::BlindedPath;
use crate::io;
use crate::ln::channelmanager::PaymentId;
use crate::ln::inbound_payment::{ExpandedKey, IV_LEN};
use crate::ln::msgs::DecodeError;
#[cfg(test)]
use crate::offers::invoice_macros::invoice_builder_methods_test_common;
use crate::offers::invoice_macros::{invoice_accessors_common, invoice_builder_methods_common};
use crate::offers::invoice_request::{
	ExperimentalInvoiceRequestTlvStream, ExperimentalInvoiceRequestTlvStreamRef, InvoiceRequest,
	InvoiceRequestContents, InvoiceRequestTlvStream, InvoiceRequestTlvStreamRef,
	EXPERIMENTAL_INVOICE_REQUEST_TYPES, INVOICE_REQUEST_PAYER_ID_TYPE, INVOICE_REQUEST_TYPES,
	IV_BYTES as INVOICE_REQUEST_IV_BYTES,
};
use crate::offers::merkle::{
	self, SignError, SignFn, SignatureTlvStream, SignatureTlvStreamRef, TaggedHash, TlvStream,
};
use crate::offers::nonce::Nonce;
use crate::offers::offer::{
	Amount, ExperimentalOfferTlvStream, ExperimentalOfferTlvStreamRef, OfferTlvStream,
	OfferTlvStreamRef, Quantity, EXPERIMENTAL_OFFER_TYPES, OFFER_TYPES,
};
use crate::offers::parse::{Bolt12ParseError, Bolt12SemanticError, ParsedMessage};
use crate::offers::payer::{PayerTlvStream, PayerTlvStreamRef, PAYER_METADATA_TYPE};
use crate::offers::refund::{
	Refund, RefundContents, IV_BYTES_WITHOUT_METADATA as REFUND_IV_BYTES_WITHOUT_METADATA,
	IV_BYTES_WITH_METADATA as REFUND_IV_BYTES_WITH_METADATA,
};
use crate::offers::signer::{self, Metadata};
use crate::types::features::{Bolt12InvoiceFeatures, InvoiceRequestFeatures, OfferFeatures};
use crate::types::payment::PaymentHash;
use crate::util::ser::{
	CursorReadable, HighZeroBytesDroppedBigSize, Iterable, LengthLimitedRead, LengthReadable,
	WithoutLength, Writeable, Writer,
};
use crate::util::string::PrintableString;
use bitcoin::address::Address;
use bitcoin::constants::ChainHash;
use bitcoin::secp256k1::schnorr::Signature;
use bitcoin::secp256k1::{self, Keypair, PublicKey, Secp256k1};
use bitcoin::{Network, WitnessProgram, WitnessVersion};
use core::hash::{Hash, Hasher};
use core::time::Duration;

#[allow(unused_imports)]
use crate::prelude::*;

#[cfg(feature = "std")]
use std::time::SystemTime;

pub(crate) const DEFAULT_RELATIVE_EXPIRY: Duration = Duration::from_secs(7200);

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
	invoice: Box<InvoiceContents>,
	signing_pubkey_strategy: S,
}

/// Builds a [`Bolt12Invoice`] from either:
/// - an [`InvoiceRequest`] for the "offer to be paid" flow or
/// - a [`Refund`] for the "offer for money" flow.
///
/// See [module-level documentation] for usage.
///
/// [`InvoiceRequest`]: crate::offers::invoice_request::InvoiceRequest
/// [`Refund`]: crate::offers::refund::Refund
/// [module-level documentation]: self
#[cfg(c_bindings)]
pub struct InvoiceWithExplicitSigningPubkeyBuilder<'a> {
	invreq_bytes: &'a Vec<u8>,
	invoice: Box<InvoiceContents>,
	signing_pubkey_strategy: ExplicitSigningPubkey,
}

/// Builds a [`Bolt12Invoice`] from either:
/// - an [`InvoiceRequest`] for the "offer to be paid" flow or
/// - a [`Refund`] for the "offer for money" flow.
///
/// See [module-level documentation] for usage.
///
/// [`InvoiceRequest`]: crate::offers::invoice_request::InvoiceRequest
/// [`Refund`]: crate::offers::refund::Refund
/// [module-level documentation]: self
#[cfg(c_bindings)]
pub struct InvoiceWithDerivedSigningPubkeyBuilder<'a> {
	invreq_bytes: &'a Vec<u8>,
	invoice: Box<InvoiceContents>,
	signing_pubkey_strategy: DerivedSigningPubkey,
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
pub struct DerivedSigningPubkey(pub(super) Keypair);

impl SigningPubkeyStrategy for ExplicitSigningPubkey {}
impl SigningPubkeyStrategy for DerivedSigningPubkey {}

macro_rules! invoice_explicit_signing_pubkey_builder_methods {
	($self: ident, $self_type: ty) => {
		#[cfg_attr(c_bindings, allow(dead_code))]
		pub(super) fn for_offer(
			invoice_request: &'a InvoiceRequest, payment_paths: Vec<BlindedPaymentPath>,
			created_at: Duration, payment_hash: PaymentHash, signing_pubkey: PublicKey,
		) -> Result<Self, Bolt12SemanticError> {
			let amount_msats = Self::amount_msats(invoice_request)?;
			let contents = Box::new(InvoiceContents::ForOffer {
				invoice_request: *invoice_request.contents.clone(),
				fields: Self::fields(
					payment_paths,
					created_at,
					payment_hash,
					amount_msats,
					signing_pubkey,
				),
			});

			Self::new(&invoice_request.bytes, contents, ExplicitSigningPubkey {})
		}

		#[cfg_attr(c_bindings, allow(dead_code))]
		pub(super) fn for_refund(
			refund: &'a Refund, payment_paths: Vec<BlindedPaymentPath>, created_at: Duration,
			payment_hash: PaymentHash, signing_pubkey: PublicKey,
		) -> Result<Self, Bolt12SemanticError> {
			let amount_msats = refund.amount_msats();
			let contents = Box::new(InvoiceContents::ForRefund {
				refund: *refund.contents.clone(),
				fields: Self::fields(
					payment_paths,
					created_at,
					payment_hash,
					amount_msats,
					signing_pubkey,
				),
			});

			Self::new(&refund.bytes, contents, ExplicitSigningPubkey {})
		}

		/// Builds an unsigned [`Bolt12Invoice`] after checking for valid semantics. It can be signed by
		/// [`UnsignedBolt12Invoice::sign`].
		pub fn build($self: $self_type) -> Result<UnsignedBolt12Invoice, Bolt12SemanticError> {
			#[cfg(feature = "std")]
			{
				if $self.invoice.is_offer_or_refund_expired() {
					return Err(Bolt12SemanticError::AlreadyExpired);
				}
			}

			#[cfg(not(feature = "std"))]
			{
				if $self.invoice.is_offer_or_refund_expired_no_std($self.invoice.created_at()) {
					return Err(Bolt12SemanticError::AlreadyExpired);
				}
			}

			let Self { invreq_bytes, invoice, .. } = $self;
			#[cfg(not(c_bindings))]
			{
				Ok(UnsignedBolt12Invoice::new(invreq_bytes, invoice))
			}
			#[cfg(c_bindings)]
			{
				Ok(UnsignedBolt12Invoice::new(invreq_bytes, invoice.clone()))
			}
		}
	};
}

macro_rules! invoice_derived_signing_pubkey_builder_methods {
	($self: ident, $self_type: ty) => {
		#[cfg_attr(c_bindings, allow(dead_code))]
		pub(super) fn for_offer_using_keys(
			invoice_request: &'a InvoiceRequest, payment_paths: Vec<BlindedPaymentPath>,
			created_at: Duration, payment_hash: PaymentHash, keys: Keypair,
		) -> Result<Self, Bolt12SemanticError> {
			let amount_msats = Self::amount_msats(invoice_request)?;
			let signing_pubkey = keys.public_key();
			let contents = Box::new(InvoiceContents::ForOffer {
				invoice_request: *invoice_request.contents.clone(),
				fields: Self::fields(
					payment_paths,
					created_at,
					payment_hash,
					amount_msats,
					signing_pubkey,
				),
			});

			Self::new(&invoice_request.bytes, contents, DerivedSigningPubkey(keys))
		}

		#[cfg_attr(c_bindings, allow(dead_code))]
		pub(super) fn for_refund_using_keys(
			refund: &'a Refund, payment_paths: Vec<BlindedPaymentPath>, created_at: Duration,
			payment_hash: PaymentHash, keys: Keypair,
		) -> Result<Self, Bolt12SemanticError> {
			let amount_msats = refund.amount_msats();
			let signing_pubkey = keys.public_key();
			let contents = Box::new(InvoiceContents::ForRefund {
				refund: *refund.contents.clone(),
				fields: Self::fields(
					payment_paths,
					created_at,
					payment_hash,
					amount_msats,
					signing_pubkey,
				),
			});

			Self::new(&refund.bytes, contents, DerivedSigningPubkey(keys))
		}

		/// Builds a signed [`Bolt12Invoice`] after checking for valid semantics.
		pub fn build_and_sign<T: secp256k1::Signing>(
			$self: $self_type, secp_ctx: &Secp256k1<T>,
		) -> Result<Bolt12Invoice, Bolt12SemanticError> {
			#[cfg(feature = "std")]
			{
				if $self.invoice.is_offer_or_refund_expired() {
					return Err(Bolt12SemanticError::AlreadyExpired);
				}
			}

			#[cfg(not(feature = "std"))]
			{
				if $self.invoice.is_offer_or_refund_expired_no_std($self.invoice.created_at()) {
					return Err(Bolt12SemanticError::AlreadyExpired);
				}
			}

			let Self { invreq_bytes, invoice, signing_pubkey_strategy: DerivedSigningPubkey(keys) } =
				$self;
			#[cfg(not(c_bindings))]
			let unsigned_invoice = UnsignedBolt12Invoice::new(invreq_bytes, invoice);
			#[cfg(c_bindings)]
			let mut unsigned_invoice = UnsignedBolt12Invoice::new(invreq_bytes, invoice.clone());

			let invoice = unsigned_invoice
				.sign(|message: &UnsignedBolt12Invoice| {
					Ok(secp_ctx.sign_schnorr_no_aux_rand(message.as_ref().as_digest(), &keys))
				})
				.unwrap();
			Ok(invoice)
		}
	};
}

macro_rules! invoice_builder_methods {
	(
	$self: ident, $self_type: ty, $return_type: ty, $return_value: expr, $type_param: ty $(, $self_mut: tt)?
) => {
		pub(crate) fn amount_msats(
			invoice_request: &InvoiceRequest,
		) -> Result<u64, Bolt12SemanticError> {
			match invoice_request.contents.inner.amount_msats() {
				Some(amount_msats) => Ok(amount_msats),
				None => match invoice_request.contents.inner.offer.amount() {
					Some(Amount::Bitcoin { amount_msats }) => amount_msats
						.checked_mul(invoice_request.quantity().unwrap_or(1))
						.ok_or(Bolt12SemanticError::InvalidAmount),
					Some(Amount::Currency { .. }) => Err(Bolt12SemanticError::UnsupportedCurrency),
					None => Err(Bolt12SemanticError::MissingAmount),
				},
			}
		}

		#[cfg_attr(c_bindings, allow(dead_code))]
		fn fields(
			payment_paths: Vec<BlindedPaymentPath>, created_at: Duration,
			payment_hash: PaymentHash, amount_msats: u64, signing_pubkey: PublicKey,
		) -> InvoiceFields {
			InvoiceFields {
				payment_paths,
				created_at,
				relative_expiry: None,
				payment_hash,
				amount_msats,
				fallbacks: None,
				features: Bolt12InvoiceFeatures::empty(),
				signing_pubkey,
				#[cfg(test)]
				experimental_baz: None,
			}
		}

		#[cfg_attr(c_bindings, allow(dead_code))]
		fn new(
			invreq_bytes: &'a Vec<u8>, contents: Box<InvoiceContents>,
			signing_pubkey_strategy: $type_param,
		) -> Result<Self, Bolt12SemanticError> {
			if contents.fields().payment_paths.is_empty() {
				return Err(Bolt12SemanticError::MissingPaths);
			}

			Ok(Self { invreq_bytes, invoice: contents, signing_pubkey_strategy })
		}
	};
}

#[cfg(test)]
macro_rules! invoice_builder_methods_test { (
	$self: ident, $self_type: ty, $return_type: ty, $return_value: expr
	$(, $self_mut: tt)?
) => {
	#[cfg_attr(c_bindings, allow(dead_code))]
	pub(crate) fn amount_msats_unchecked(
		$($self_mut)* $self: $self_type, amount_msats: u64,
	) -> $return_type {
		$self.invoice.fields_mut().amount_msats = amount_msats;
		$return_value
	}
} }

impl<'a> InvoiceBuilder<'a, ExplicitSigningPubkey> {
	invoice_explicit_signing_pubkey_builder_methods!(self, Self);
}

impl<'a> InvoiceBuilder<'a, DerivedSigningPubkey> {
	invoice_derived_signing_pubkey_builder_methods!(self, Self);
}

impl<'a, S: SigningPubkeyStrategy> InvoiceBuilder<'a, S> {
	invoice_builder_methods!(self, Self, Self, self, S, mut);
	invoice_builder_methods_common!(
		self,
		Self,
		self.invoice.fields_mut(),
		Self,
		self,
		Bolt12Invoice,
		mut
	);

	#[cfg(test)]
	invoice_builder_methods_test!(self, Self, Self, self, mut);
	#[cfg(test)]
	invoice_builder_methods_test_common!(self, Self, self.invoice.fields_mut(), Self, self, mut);
}

#[cfg(all(c_bindings, not(test)))]
impl<'a> InvoiceWithExplicitSigningPubkeyBuilder<'a> {
	invoice_explicit_signing_pubkey_builder_methods!(self, &mut Self);
	invoice_builder_methods!(self, &mut Self, (), (), ExplicitSigningPubkey);
	invoice_builder_methods_common!(
		self,
		&mut Self,
		self.invoice.fields_mut(),
		(),
		(),
		Bolt12Invoice
	);
}

#[cfg(all(c_bindings, test))]
impl<'a> InvoiceWithExplicitSigningPubkeyBuilder<'a> {
	invoice_explicit_signing_pubkey_builder_methods!(self, &mut Self);
	invoice_builder_methods!(self, &mut Self, &mut Self, self, ExplicitSigningPubkey);
	invoice_builder_methods_common!(
		self,
		&mut Self,
		self.invoice.fields_mut(),
		&mut Self,
		self,
		Bolt12Invoice
	);
	invoice_builder_methods_test!(self, &mut Self, &mut Self, self);
	invoice_builder_methods_test_common!(
		self,
		&mut Self,
		self.invoice.fields_mut(),
		&mut Self,
		self
	);
}

#[cfg(all(c_bindings, not(test)))]
impl<'a> InvoiceWithDerivedSigningPubkeyBuilder<'a> {
	invoice_derived_signing_pubkey_builder_methods!(self, &mut Self);
	invoice_builder_methods!(self, &mut Self, (), (), DerivedSigningPubkey);
	invoice_builder_methods_common!(
		self,
		&mut Self,
		self.invoice.fields_mut(),
		(),
		(),
		Bolt12Invoice
	);
}

#[cfg(all(c_bindings, test))]
impl<'a> InvoiceWithDerivedSigningPubkeyBuilder<'a> {
	invoice_derived_signing_pubkey_builder_methods!(self, &mut Self);
	invoice_builder_methods!(self, &mut Self, &mut Self, self, DerivedSigningPubkey);
	invoice_builder_methods_common!(
		self,
		&mut Self,
		self.invoice.fields_mut(),
		&mut Self,
		self,
		Bolt12Invoice
	);
	invoice_builder_methods_test!(self, &mut Self, &mut Self, self);
	invoice_builder_methods_test_common!(
		self,
		&mut Self,
		self.invoice.fields_mut(),
		&mut Self,
		self
	);
}

#[cfg(c_bindings)]
impl<'a> From<InvoiceWithExplicitSigningPubkeyBuilder<'a>>
	for InvoiceBuilder<'a, ExplicitSigningPubkey>
{
	fn from(builder: InvoiceWithExplicitSigningPubkeyBuilder<'a>) -> Self {
		let InvoiceWithExplicitSigningPubkeyBuilder {
			invreq_bytes,
			invoice,
			signing_pubkey_strategy,
		} = builder;

		Self { invreq_bytes, invoice, signing_pubkey_strategy }
	}
}

#[cfg(c_bindings)]
impl<'a> From<InvoiceWithDerivedSigningPubkeyBuilder<'a>>
	for InvoiceBuilder<'a, DerivedSigningPubkey>
{
	fn from(builder: InvoiceWithDerivedSigningPubkeyBuilder<'a>) -> Self {
		let InvoiceWithDerivedSigningPubkeyBuilder {
			invreq_bytes,
			invoice,
			signing_pubkey_strategy,
		} = builder;

		Self { invreq_bytes, invoice, signing_pubkey_strategy }
	}
}

/// A semantically valid [`Bolt12Invoice`] that hasn't been signed.
///
/// # Serialization
///
/// This is serialized as a TLV stream, which includes TLV records from the originating message. As
/// such, it may include unknown, odd TLV records.
#[derive(Clone)]
pub struct UnsignedBolt12Invoice {
	bytes: Vec<u8>,
	experimental_bytes: Vec<u8>,
	contents: Box<InvoiceContents>,
	tagged_hash: TaggedHash,
}

/// A function for signing an [`UnsignedBolt12Invoice`].
pub trait SignBolt12InvoiceFn {
	/// Signs a [`TaggedHash`] computed over the merkle root of `message`'s TLV stream.
	fn sign_invoice(&self, message: &UnsignedBolt12Invoice) -> Result<Signature, ()>;
}

impl<F> SignBolt12InvoiceFn for F
where
	F: Fn(&UnsignedBolt12Invoice) -> Result<Signature, ()>,
{
	fn sign_invoice(&self, message: &UnsignedBolt12Invoice) -> Result<Signature, ()> {
		self(message)
	}
}

impl<F> SignFn<UnsignedBolt12Invoice> for F
where
	F: SignBolt12InvoiceFn,
{
	fn sign(&self, message: &UnsignedBolt12Invoice) -> Result<Signature, ()> {
		self.sign_invoice(message)
	}
}

impl UnsignedBolt12Invoice {
	fn new(invreq_bytes: &[u8], contents: Box<InvoiceContents>) -> Self {
		// TLV record ranges applicable to invreq_bytes.
		const NON_EXPERIMENTAL_TYPES: core::ops::Range<u64> = 0..INVOICE_REQUEST_TYPES.end;
		const EXPERIMENTAL_TYPES: core::ops::Range<u64> =
			EXPERIMENTAL_OFFER_TYPES.start..EXPERIMENTAL_INVOICE_REQUEST_TYPES.end;

		let (_, _, _, invoice_tlv_stream, _, _, experimental_invoice_tlv_stream) =
			contents.as_tlv_stream();

		const INVOICE_ALLOCATION_SIZE: usize = 1024;
		let mut bytes = Vec::with_capacity(INVOICE_ALLOCATION_SIZE);

		// Use the invoice_request bytes instead of the invoice_request TLV stream as the latter may
		// have contained unknown TLV records, which are not stored in `InvoiceRequestContents` or
		// `RefundContents`.
		for record in TlvStream::new(invreq_bytes).range(NON_EXPERIMENTAL_TYPES) {
			record.write(&mut bytes).unwrap();
		}

		let remaining_bytes = &invreq_bytes[bytes.len()..];

		invoice_tlv_stream.write(&mut bytes).unwrap();

		const EXPERIMENTAL_TLV_ALLOCATION_SIZE: usize = 0;
		let mut experimental_bytes = Vec::with_capacity(EXPERIMENTAL_TLV_ALLOCATION_SIZE);

		let experimental_tlv_stream = TlvStream::new(remaining_bytes).range(EXPERIMENTAL_TYPES);
		for record in experimental_tlv_stream {
			record.write(&mut experimental_bytes).unwrap();
		}

		experimental_invoice_tlv_stream.write(&mut experimental_bytes).unwrap();

		let tlv_stream = TlvStream::new(&bytes).chain(TlvStream::new(&experimental_bytes));
		let tagged_hash = TaggedHash::from_tlv_stream(SIGNATURE_TAG, tlv_stream);

		Self { bytes, experimental_bytes, contents, tagged_hash }
	}

	/// Returns the [`TaggedHash`] of the invoice to sign.
	pub fn tagged_hash(&self) -> &TaggedHash {
		&self.tagged_hash
	}
}

macro_rules! unsigned_invoice_sign_method { ($self: ident, $self_type: ty $(, $self_mut: tt)?) => {
	/// Signs the [`TaggedHash`] of the invoice using the given function.
	///
	/// Note: The hash computation may have included unknown, odd TLV records.
	pub fn sign<F: SignBolt12InvoiceFn>(
		$($self_mut)* $self: $self_type, sign: F
	) -> Result<Bolt12Invoice, SignError> {
		let pubkey = $self.contents.fields().signing_pubkey;
		let signature = merkle::sign_message(sign, &$self, pubkey)?;

		// Append the signature TLV record to the bytes.
		let signature_tlv_stream = SignatureTlvStreamRef {
			signature: Some(&signature),
		};
		signature_tlv_stream.write(&mut $self.bytes).unwrap();

		// Append the experimental bytes after the signature.
		$self.bytes.extend_from_slice(&$self.experimental_bytes);

		Ok(Bolt12Invoice {
			#[cfg(not(c_bindings))]
			bytes: $self.bytes,
			#[cfg(c_bindings)]
			bytes: $self.bytes.clone(),
			#[cfg(not(c_bindings))]
			contents: $self.contents,
			#[cfg(c_bindings)]
			contents: $self.contents.clone(),
			signature,
			#[cfg(not(c_bindings))]
			tagged_hash: $self.tagged_hash,
			#[cfg(c_bindings)]
			tagged_hash: $self.tagged_hash.clone(),
		})
	}
} }

#[cfg(not(c_bindings))]
impl UnsignedBolt12Invoice {
	unsigned_invoice_sign_method!(self, Self, mut);
}

#[cfg(c_bindings)]
impl UnsignedBolt12Invoice {
	unsigned_invoice_sign_method!(self, &mut Self);
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
pub struct Bolt12Invoice {
	bytes: Vec<u8>,
	contents: Box<InvoiceContents>,
	signature: Signature,
	tagged_hash: TaggedHash,
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
	ForOffer { invoice_request: InvoiceRequestContents, fields: InvoiceFields },
	/// Contents for an [`Bolt12Invoice`] corresponding to a [`Refund`].
	///
	/// [`Refund`]: crate::offers::refund::Refund
	ForRefund { refund: RefundContents, fields: InvoiceFields },
}

/// Invoice-specific fields for an `invoice` message.
#[derive(Clone, Debug, PartialEq)]
struct InvoiceFields {
	payment_paths: Vec<BlindedPaymentPath>,
	created_at: Duration,
	relative_expiry: Option<Duration>,
	payment_hash: PaymentHash,
	amount_msats: u64,
	fallbacks: Option<Vec<FallbackAddress>>,
	features: Bolt12InvoiceFeatures,
	signing_pubkey: PublicKey,
	#[cfg(test)]
	experimental_baz: Option<u64>,
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
	pub fn amount(&$self) -> Option<Amount> {
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
	pub fn description(&$self) -> Option<PrintableString> {
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
	pub fn message_paths(&$self) -> &[BlindedMessagePath] {
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

	/// The public key used by the recipient to sign invoices.
	///
	/// From [`Offer::issuer_signing_pubkey`] and may be `None`; also `None` if the invoice was
	/// created in response to a [`Refund`].
	///
	/// [`Offer::issuer_signing_pubkey`]: crate::offers::offer::Offer::issuer_signing_pubkey
	pub fn issuer_signing_pubkey(&$self) -> Option<PublicKey> {
		$contents.issuer_signing_pubkey()
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
	pub fn payer_signing_pubkey(&$self) -> PublicKey {
		$contents.payer_signing_pubkey()
	}

	/// A payer-provided note reflected back in the invoice.
	///
	/// From [`InvoiceRequest::payer_note`] or [`Refund::payer_note`].
	pub fn payer_note(&$self) -> Option<PrintableString> {
		$contents.payer_note()
	}

	/// SHA256 hash of the payment preimage that will be given in return for paying the invoice.
	pub fn payment_hash(&$self) -> PaymentHash {
		$contents.payment_hash()
	}

	/// The minimum amount required for a successful payment of the invoice.
	pub fn amount_msats(&$self) -> u64 {
		$contents.amount_msats()
	}
} }

macro_rules! invoice_accessors_signing_pubkey {
	($self: ident, $contents: expr, $invoice_type: ty) =>
{
	/// A typically transient public key corresponding to the key used to sign the invoice.
	///
	/// If the invoices was created in response to an [`Offer`], then this will be:
	/// - [`Offer::issuer_signing_pubkey`] if it's `Some`, otherwise
	/// - the final blinded node id from a [`BlindedMessagePath`] in [`Offer::paths`] if `None`.
	///
	/// If the invoice was created in response to a [`Refund`], then it is a valid pubkey chosen by
	/// the recipient.
	///
	/// [`Offer`]: crate::offers::offer::Offer
	/// [`Offer::issuer_signing_pubkey`]: crate::offers::offer::Offer::issuer_signing_pubkey
	/// [`Offer::paths`]: crate::offers::offer::Offer::paths
	/// [`Refund`]: crate::offers::refund::Refund
	pub fn signing_pubkey(&$self) -> PublicKey {
		$contents.signing_pubkey()
	}
} }

impl UnsignedBolt12Invoice {
	invoice_accessors_common!(self, self.contents, UnsignedBolt12Invoice);
	invoice_accessors_signing_pubkey!(self, self.contents, UnsignedBolt12Invoice);
	invoice_accessors!(self, self.contents);
}

impl Bolt12Invoice {
	invoice_accessors_common!(self, self.contents, Bolt12Invoice);
	invoice_accessors_signing_pubkey!(self, self.contents, Bolt12Invoice);
	invoice_accessors!(self, self.contents);

	/// Signature of the invoice verified using [`Bolt12Invoice::signing_pubkey`].
	pub fn signature(&self) -> Signature {
		self.signature
	}

	/// Hash that was used for signing the invoice.
	pub fn signable_hash(&self) -> [u8; 32] {
		self.tagged_hash.as_digest().as_ref().clone()
	}

	/// Verifies that the invoice was for a request or refund created using the given key by
	/// checking the payer metadata from the invoice request.
	///
	/// Returns the associated [`PaymentId`] to use when sending the payment.
	pub fn verify_using_metadata<T: secp256k1::Signing>(
		&self, key: &ExpandedKey, secp_ctx: &Secp256k1<T>,
	) -> Result<PaymentId, ()> {
		let (metadata, iv_bytes) = match &*self.contents {
			InvoiceContents::ForOffer { invoice_request, .. } => {
				(&invoice_request.inner.payer.0, INVOICE_REQUEST_IV_BYTES)
			},
			InvoiceContents::ForRefund { refund, .. } => {
				(&refund.payer.0, REFUND_IV_BYTES_WITH_METADATA)
			},
		};
		self.contents.verify(&self.bytes, metadata, key, iv_bytes, secp_ctx)
	}

	/// Verifies that the invoice was for a request or refund created using the given key by
	/// checking a payment id and nonce included with the [`BlindedMessagePath`] for which the invoice was
	/// sent through.
	pub fn verify_using_payer_data<T: secp256k1::Signing>(
		&self, payment_id: PaymentId, nonce: Nonce, key: &ExpandedKey, secp_ctx: &Secp256k1<T>,
	) -> Result<PaymentId, ()> {
		let metadata = Metadata::payer_data(payment_id, nonce, key);
		let iv_bytes = match &*self.contents {
			InvoiceContents::ForOffer { .. } => INVOICE_REQUEST_IV_BYTES,
			InvoiceContents::ForRefund { .. } => REFUND_IV_BYTES_WITHOUT_METADATA,
		};
		self.contents.verify(&self.bytes, &metadata, key, iv_bytes, secp_ctx).and_then(
			|extracted_payment_id| {
				(payment_id == extracted_payment_id).then(|| payment_id).ok_or(())
			},
		)
	}

	pub(crate) fn as_tlv_stream(&self) -> FullInvoiceTlvStreamRef {
		let (
			payer_tlv_stream,
			offer_tlv_stream,
			invoice_request_tlv_stream,
			invoice_tlv_stream,
			experimental_offer_tlv_stream,
			experimental_invoice_request_tlv_stream,
			experimental_invoice_tlv_stream,
		) = self.contents.as_tlv_stream();
		let signature_tlv_stream = SignatureTlvStreamRef { signature: Some(&self.signature) };
		(
			payer_tlv_stream,
			offer_tlv_stream,
			invoice_request_tlv_stream,
			invoice_tlv_stream,
			signature_tlv_stream,
			experimental_offer_tlv_stream,
			experimental_invoice_request_tlv_stream,
			experimental_invoice_tlv_stream,
		)
	}

	pub(crate) fn is_for_refund_without_paths(&self) -> bool {
		match &*self.contents {
			InvoiceContents::ForOffer { .. } => false,
			InvoiceContents::ForRefund { .. } => self.message_paths().is_empty(),
		}
	}
}

impl PartialEq for Bolt12Invoice {
	fn eq(&self, other: &Self) -> bool {
		self.bytes.eq(&other.bytes)
	}
}

impl Eq for Bolt12Invoice {}

impl Hash for Bolt12Invoice {
	fn hash<H: Hasher>(&self, state: &mut H) {
		self.bytes.hash(state);
	}
}

impl InvoiceContents {
	/// Whether the original offer or refund has expired.
	#[cfg(feature = "std")]
	fn is_offer_or_refund_expired(&self) -> bool {
		match self {
			InvoiceContents::ForOffer { invoice_request, .. } => {
				invoice_request.inner.offer.is_expired()
			},
			InvoiceContents::ForRefund { refund, .. } => refund.is_expired(),
		}
	}

	#[cfg(not(feature = "std"))]
	fn is_offer_or_refund_expired_no_std(&self, duration_since_epoch: Duration) -> bool {
		match self {
			InvoiceContents::ForOffer { invoice_request, .. } => {
				invoice_request.inner.offer.is_expired_no_std(duration_since_epoch)
			},
			InvoiceContents::ForRefund { refund, .. } => {
				refund.is_expired_no_std(duration_since_epoch)
			},
		}
	}

	fn offer_chains(&self) -> Option<Vec<ChainHash>> {
		match self {
			InvoiceContents::ForOffer { invoice_request, .. } => {
				Some(invoice_request.inner.offer.chains())
			},
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
			InvoiceContents::ForOffer { invoice_request, .. } => {
				invoice_request.inner.offer.metadata()
			},
			InvoiceContents::ForRefund { .. } => None,
		}
	}

	fn amount(&self) -> Option<Amount> {
		match self {
			InvoiceContents::ForOffer { invoice_request, .. } => {
				invoice_request.inner.offer.amount()
			},
			InvoiceContents::ForRefund { .. } => None,
		}
	}

	fn description(&self) -> Option<PrintableString> {
		match self {
			InvoiceContents::ForOffer { invoice_request, .. } => {
				invoice_request.inner.offer.description()
			},
			InvoiceContents::ForRefund { refund, .. } => Some(refund.description()),
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

	fn message_paths(&self) -> &[BlindedMessagePath] {
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

	fn issuer_signing_pubkey(&self) -> Option<PublicKey> {
		match self {
			InvoiceContents::ForOffer { invoice_request, .. } => {
				invoice_request.inner.offer.issuer_signing_pubkey()
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

	fn payer_signing_pubkey(&self) -> PublicKey {
		match self {
			InvoiceContents::ForOffer { invoice_request, .. } => {
				invoice_request.payer_signing_pubkey()
			},
			InvoiceContents::ForRefund { refund, .. } => refund.payer_signing_pubkey(),
		}
	}

	fn payer_note(&self) -> Option<PrintableString> {
		match self {
			InvoiceContents::ForOffer { invoice_request, .. } => invoice_request.payer_note(),
			InvoiceContents::ForRefund { refund, .. } => refund.payer_note(),
		}
	}

	fn payment_paths(&self) -> &[BlindedPaymentPath] {
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
		is_expired(self.created_at(), self.relative_expiry())
	}

	fn payment_hash(&self) -> PaymentHash {
		self.fields().payment_hash
	}

	fn amount_msats(&self) -> u64 {
		self.fields().amount_msats
	}

	fn fallbacks(&self) -> Vec<Address> {
		self.fields()
			.fallbacks
			.as_ref()
			.map(|fallbacks| filter_fallbacks(self.chain(), fallbacks))
			.unwrap_or_default()
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
		&self, bytes: &[u8], metadata: &Metadata, key: &ExpandedKey, iv_bytes: &[u8; IV_LEN],
		secp_ctx: &Secp256k1<T>,
	) -> Result<PaymentId, ()> {
		const EXPERIMENTAL_TYPES: core::ops::Range<u64> =
			EXPERIMENTAL_OFFER_TYPES.start..EXPERIMENTAL_INVOICE_REQUEST_TYPES.end;

		let offer_records = TlvStream::new(bytes).range(OFFER_TYPES);
		let invreq_records = TlvStream::new(bytes).range(INVOICE_REQUEST_TYPES).filter(|record| {
			match record.r#type {
				PAYER_METADATA_TYPE => false, // Should be outside range
				INVOICE_REQUEST_PAYER_ID_TYPE => !metadata.derives_payer_keys(),
				_ => true,
			}
		});
		let experimental_records = TlvStream::new(bytes).range(EXPERIMENTAL_TYPES);
		let tlv_stream = offer_records.chain(invreq_records).chain(experimental_records);

		let signing_pubkey = self.payer_signing_pubkey();
		signer::verify_payer_metadata(
			metadata.as_ref(),
			key,
			iv_bytes,
			signing_pubkey,
			tlv_stream,
			secp_ctx,
		)
	}

	fn as_tlv_stream(&self) -> PartialInvoiceTlvStreamRef {
		let (payer, offer, invoice_request, experimental_offer, experimental_invoice_request) =
			match self {
				InvoiceContents::ForOffer { invoice_request, .. } => {
					invoice_request.as_tlv_stream()
				},
				InvoiceContents::ForRefund { refund, .. } => refund.as_tlv_stream(),
			};
		let (invoice, experimental_invoice) = self.fields().as_tlv_stream();

		(
			payer,
			offer,
			invoice_request,
			invoice,
			experimental_offer,
			experimental_invoice_request,
			experimental_invoice,
		)
	}
}

#[cfg(feature = "std")]
pub(super) fn is_expired(created_at: Duration, relative_expiry: Duration) -> bool {
	let absolute_expiry = created_at.checked_add(relative_expiry);
	match absolute_expiry {
		Some(seconds_from_epoch) => match SystemTime::UNIX_EPOCH.elapsed() {
			Ok(elapsed) => elapsed > seconds_from_epoch,
			Err(_) => false,
		},
		None => false,
	}
}

pub(super) fn filter_fallbacks(chain: ChainHash, fallbacks: &Vec<FallbackAddress>) -> Vec<Address> {
	let network = if chain == ChainHash::using_genesis_block(Network::Bitcoin) {
		Network::Bitcoin
	} else if chain == ChainHash::using_genesis_block(Network::Testnet) {
		Network::Testnet
	} else if chain == ChainHash::using_genesis_block(Network::Signet) {
		Network::Signet
	} else if chain == ChainHash::using_genesis_block(Network::Regtest) {
		Network::Regtest
	} else {
		return Vec::new();
	};

	let to_valid_address = |address: &FallbackAddress| {
		let version = match WitnessVersion::try_from(address.version) {
			Ok(version) => version,
			Err(_) => return None,
		};

		let witness_program = match WitnessProgram::new(version, &address.program) {
			Ok(witness_program) => witness_program,
			Err(_) => return None,
		};
		Some(Address::from_witness_program(witness_program, network))
	};

	fallbacks.iter().filter_map(to_valid_address).collect()
}

impl InvoiceFields {
	fn as_tlv_stream(&self) -> (InvoiceTlvStreamRef, ExperimentalInvoiceTlvStreamRef) {
		let features = {
			if self.features == Bolt12InvoiceFeatures::empty() {
				None
			} else {
				Some(&self.features)
			}
		};

		(
			InvoiceTlvStreamRef {
				paths: Some(Iterable(
					self.payment_paths.iter().map(|path| path.inner_blinded_path()),
				)),
				blindedpay: Some(Iterable(self.payment_paths.iter().map(|path| &path.payinfo))),
				created_at: Some(self.created_at.as_secs()),
				relative_expiry: self.relative_expiry.map(|duration| duration.as_secs() as u32),
				payment_hash: Some(&self.payment_hash),
				amount: Some(self.amount_msats),
				fallbacks: self.fallbacks.as_ref(),
				features,
				node_id: Some(&self.signing_pubkey),
				message_paths: None,
			},
			ExperimentalInvoiceTlvStreamRef {
				#[cfg(test)]
				experimental_baz: self.experimental_baz,
			},
		)
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

impl LengthReadable for Bolt12Invoice {
	fn read_from_fixed_length_buffer<R: LengthLimitedRead>(
		reader: &mut R,
	) -> Result<Self, DecodeError> {
		let bytes: WithoutLength<Vec<u8>> = LengthReadable::read_from_fixed_length_buffer(reader)?;
		Self::try_from(bytes.0).map_err(|e| match e {
			Bolt12ParseError::Decode(e) => e,
			_ => DecodeError::InvalidValue,
		})
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
		let ParsedMessage { mut bytes, tlv_stream } = invoice;
		let contents = Box::new(InvoiceContents::try_from(tlv_stream)?);

		let tagged_hash = TaggedHash::from_valid_tlv_stream_bytes(SIGNATURE_TAG, &bytes);

		let offset = TlvStream::new(&bytes)
			.range(0..INVOICE_TYPES.end)
			.last()
			.map_or(0, |last_record| last_record.end);
		let experimental_bytes = bytes.split_off(offset);

		Ok(UnsignedBolt12Invoice { bytes, experimental_bytes, contents, tagged_hash })
	}
}

impl TryFrom<Vec<u8>> for Bolt12Invoice {
	type Error = Bolt12ParseError;

	fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
		let parsed_invoice = ParsedMessage::<FullInvoiceTlvStream>::try_from(bytes)?;
		Bolt12Invoice::try_from(parsed_invoice)
	}
}

/// Valid type range for invoice TLV records.
pub(super) const INVOICE_TYPES: core::ops::Range<u64> = 160..240;

tlv_stream!(InvoiceTlvStream, InvoiceTlvStreamRef<'a>, INVOICE_TYPES, {
	(160, paths: (Vec<BlindedPath>, WithoutLength, Iterable<'a, BlindedPathIter<'a>, BlindedPath>)),
	(162, blindedpay: (Vec<BlindedPayInfo>, WithoutLength, Iterable<'a, BlindedPayInfoIter<'a>, BlindedPayInfo>)),
	(164, created_at: (u64, HighZeroBytesDroppedBigSize)),
	(166, relative_expiry: (u32, HighZeroBytesDroppedBigSize)),
	(168, payment_hash: PaymentHash),
	(170, amount: (u64, HighZeroBytesDroppedBigSize)),
	(172, fallbacks: (Vec<FallbackAddress>, WithoutLength)),
	(174, features: (Bolt12InvoiceFeatures, WithoutLength)),
	(176, node_id: PublicKey),
	// Only present in `StaticInvoice`s.
	(236, message_paths: (Vec<BlindedMessagePath>, WithoutLength)),
});

/// Valid type range for experimental invoice TLV records.
pub(super) const EXPERIMENTAL_INVOICE_TYPES: core::ops::RangeFrom<u64> = 3_000_000_000..;

#[cfg(not(test))]
tlv_stream!(
	ExperimentalInvoiceTlvStream,
	ExperimentalInvoiceTlvStreamRef,
	EXPERIMENTAL_INVOICE_TYPES,
	{
		// When adding experimental TLVs, update EXPERIMENTAL_TLV_ALLOCATION_SIZE accordingly in
		// both UnsignedBolt12Invoice:new and UnsignedStaticInvoice::new to avoid unnecessary
		// allocations.
	}
);

#[cfg(test)]
tlv_stream!(
	ExperimentalInvoiceTlvStream, ExperimentalInvoiceTlvStreamRef, EXPERIMENTAL_INVOICE_TYPES, {
		(3_999_999_999, experimental_baz: (u64, HighZeroBytesDroppedBigSize)),
	}
);

pub(super) type BlindedPathIter<'a> = core::iter::Map<
	core::slice::Iter<'a, BlindedPaymentPath>,
	for<'r> fn(&'r BlindedPaymentPath) -> &'r BlindedPath,
>;

pub(super) type BlindedPayInfoIter<'a> = core::iter::Map<
	core::slice::Iter<'a, BlindedPaymentPath>,
	for<'r> fn(&'r BlindedPaymentPath) -> &'r BlindedPayInfo,
>;

/// Wire representation for an on-chain fallback address.
#[derive(Clone, Debug, PartialEq)]
pub(super) struct FallbackAddress {
	pub(super) version: u8,
	pub(super) program: Vec<u8>,
}

impl_writeable!(FallbackAddress, { version, program });

type FullInvoiceTlvStream = (
	PayerTlvStream,
	OfferTlvStream,
	InvoiceRequestTlvStream,
	InvoiceTlvStream,
	SignatureTlvStream,
	ExperimentalOfferTlvStream,
	ExperimentalInvoiceRequestTlvStream,
	ExperimentalInvoiceTlvStream,
);

type FullInvoiceTlvStreamRef<'a> = (
	PayerTlvStreamRef<'a>,
	OfferTlvStreamRef<'a>,
	InvoiceRequestTlvStreamRef<'a>,
	InvoiceTlvStreamRef<'a>,
	SignatureTlvStreamRef<'a>,
	ExperimentalOfferTlvStreamRef,
	ExperimentalInvoiceRequestTlvStreamRef,
	ExperimentalInvoiceTlvStreamRef,
);

impl CursorReadable for FullInvoiceTlvStream {
	fn read<R: AsRef<[u8]>>(r: &mut io::Cursor<R>) -> Result<Self, DecodeError> {
		let payer = CursorReadable::read(r)?;
		let offer = CursorReadable::read(r)?;
		let invoice_request = CursorReadable::read(r)?;
		let invoice = CursorReadable::read(r)?;
		let signature = CursorReadable::read(r)?;
		let experimental_offer = CursorReadable::read(r)?;
		let experimental_invoice_request = CursorReadable::read(r)?;
		let experimental_invoice = CursorReadable::read(r)?;

		Ok((
			payer,
			offer,
			invoice_request,
			invoice,
			signature,
			experimental_offer,
			experimental_invoice_request,
			experimental_invoice,
		))
	}
}

type PartialInvoiceTlvStream = (
	PayerTlvStream,
	OfferTlvStream,
	InvoiceRequestTlvStream,
	InvoiceTlvStream,
	ExperimentalOfferTlvStream,
	ExperimentalInvoiceRequestTlvStream,
	ExperimentalInvoiceTlvStream,
);

type PartialInvoiceTlvStreamRef<'a> = (
	PayerTlvStreamRef<'a>,
	OfferTlvStreamRef<'a>,
	InvoiceRequestTlvStreamRef<'a>,
	InvoiceTlvStreamRef<'a>,
	ExperimentalOfferTlvStreamRef,
	ExperimentalInvoiceRequestTlvStreamRef,
	ExperimentalInvoiceTlvStreamRef,
);

impl CursorReadable for PartialInvoiceTlvStream {
	fn read<R: AsRef<[u8]>>(r: &mut io::Cursor<R>) -> Result<Self, DecodeError> {
		let payer = CursorReadable::read(r)?;
		let offer = CursorReadable::read(r)?;
		let invoice_request = CursorReadable::read(r)?;
		let invoice = CursorReadable::read(r)?;
		let experimental_offer = CursorReadable::read(r)?;
		let experimental_invoice_request = CursorReadable::read(r)?;
		let experimental_invoice = CursorReadable::read(r)?;

		Ok((
			payer,
			offer,
			invoice_request,
			invoice,
			experimental_offer,
			experimental_invoice_request,
			experimental_invoice,
		))
	}
}

impl TryFrom<ParsedMessage<FullInvoiceTlvStream>> for Bolt12Invoice {
	type Error = Bolt12ParseError;

	fn try_from(invoice: ParsedMessage<FullInvoiceTlvStream>) -> Result<Self, Self::Error> {
		let ParsedMessage { bytes, tlv_stream } = invoice;
		let (
			payer_tlv_stream,
			offer_tlv_stream,
			invoice_request_tlv_stream,
			invoice_tlv_stream,
			SignatureTlvStream { signature },
			experimental_offer_tlv_stream,
			experimental_invoice_request_tlv_stream,
			experimental_invoice_tlv_stream,
		) = tlv_stream;
		let contents = Box::new(InvoiceContents::try_from((
			payer_tlv_stream,
			offer_tlv_stream,
			invoice_request_tlv_stream,
			invoice_tlv_stream,
			experimental_offer_tlv_stream,
			experimental_invoice_request_tlv_stream,
			experimental_invoice_tlv_stream,
		))?);

		let signature = signature
			.ok_or(Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::MissingSignature))?;
		let tagged_hash = TaggedHash::from_valid_tlv_stream_bytes(SIGNATURE_TAG, &bytes);
		let pubkey = contents.fields().signing_pubkey;
		merkle::verify_signature(&signature, &tagged_hash, pubkey)?;

		Ok(Bolt12Invoice { bytes, contents, signature, tagged_hash })
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
				paths,
				blindedpay,
				created_at,
				relative_expiry,
				payment_hash,
				amount,
				fallbacks,
				features,
				node_id,
				message_paths,
			},
			experimental_offer_tlv_stream,
			experimental_invoice_request_tlv_stream,
			ExperimentalInvoiceTlvStream {
				#[cfg(test)]
				experimental_baz,
			},
		) = tlv_stream;

		if message_paths.is_some() {
			return Err(Bolt12SemanticError::UnexpectedPaths);
		}

		let payment_paths = construct_payment_paths(blindedpay, paths)?;

		let created_at = match created_at {
			None => return Err(Bolt12SemanticError::MissingCreationTime),
			Some(timestamp) => Duration::from_secs(timestamp),
		};

		let relative_expiry = relative_expiry.map(Into::<u64>::into).map(Duration::from_secs);

		let payment_hash = payment_hash.ok_or(Bolt12SemanticError::MissingPaymentHash)?;

		let amount_msats = amount.ok_or(Bolt12SemanticError::MissingAmount)?;

		let features = features.unwrap_or_else(Bolt12InvoiceFeatures::empty);

		let signing_pubkey = node_id.ok_or(Bolt12SemanticError::MissingSigningPubkey)?;

		let fields = InvoiceFields {
			payment_paths,
			created_at,
			relative_expiry,
			payment_hash,
			amount_msats,
			fallbacks,
			features,
			signing_pubkey,
			#[cfg(test)]
			experimental_baz,
		};

		check_invoice_signing_pubkey(&fields.signing_pubkey, &offer_tlv_stream)?;

		if offer_tlv_stream.issuer_id.is_none() && offer_tlv_stream.paths.is_none() {
			let refund = RefundContents::try_from((
				payer_tlv_stream,
				offer_tlv_stream,
				invoice_request_tlv_stream,
				experimental_offer_tlv_stream,
				experimental_invoice_request_tlv_stream,
			))?;

			if amount_msats != refund.amount_msats() {
				return Err(Bolt12SemanticError::InvalidAmount);
			}

			Ok(InvoiceContents::ForRefund { refund, fields })
		} else {
			let invoice_request = InvoiceRequestContents::try_from((
				payer_tlv_stream,
				offer_tlv_stream,
				invoice_request_tlv_stream,
				experimental_offer_tlv_stream,
				experimental_invoice_request_tlv_stream,
			))?;

			if let Some(requested_amount_msats) = invoice_request.amount_msats() {
				if amount_msats != requested_amount_msats {
					return Err(Bolt12SemanticError::InvalidAmount);
				}
			}

			Ok(InvoiceContents::ForOffer { invoice_request, fields })
		}
	}
}

pub(super) fn construct_payment_paths(
	blinded_payinfos: Option<Vec<BlindedPayInfo>>, blinded_paths: Option<Vec<BlindedPath>>,
) -> Result<Vec<BlindedPaymentPath>, Bolt12SemanticError> {
	match (blinded_payinfos, blinded_paths) {
		(_, None) => Err(Bolt12SemanticError::MissingPaths),
		(None, _) => Err(Bolt12SemanticError::InvalidPayInfo),
		(_, Some(paths)) if paths.is_empty() => Err(Bolt12SemanticError::MissingPaths),
		(Some(blindedpay), Some(paths)) if paths.len() != blindedpay.len() => {
			Err(Bolt12SemanticError::InvalidPayInfo)
		},
		(Some(blindedpay), Some(paths)) => Ok(blindedpay
			.into_iter()
			.zip(paths.into_iter())
			.map(|(payinfo, path)| BlindedPaymentPath::from_parts(path, payinfo))
			.collect::<Vec<_>>()),
	}
}

pub(super) fn check_invoice_signing_pubkey(
	invoice_signing_pubkey: &PublicKey, offer_tlv_stream: &OfferTlvStream,
) -> Result<(), Bolt12SemanticError> {
	match (&offer_tlv_stream.issuer_id, &offer_tlv_stream.paths) {
		(Some(issuer_signing_pubkey), _) => {
			if invoice_signing_pubkey != issuer_signing_pubkey {
				return Err(Bolt12SemanticError::InvalidSigningPubkey);
			}
		},
		(None, Some(paths)) => {
			if !paths
				.iter()
				.filter_map(|path| path.blinded_hops().last())
				.any(|last_hop| invoice_signing_pubkey == &last_hop.blinded_node_id)
			{
				return Err(Bolt12SemanticError::InvalidSigningPubkey);
			}
		},
		_ => {},
	}
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::{
		Bolt12Invoice, ExperimentalInvoiceTlvStreamRef, FallbackAddress, FullInvoiceTlvStreamRef,
		InvoiceTlvStreamRef, UnsignedBolt12Invoice, DEFAULT_RELATIVE_EXPIRY,
		EXPERIMENTAL_INVOICE_TYPES, INVOICE_TYPES, SIGNATURE_TAG,
	};

	use bitcoin::address::Address;
	use bitcoin::constants::ChainHash;
	use bitcoin::hashes::Hash;
	use bitcoin::key::TweakedPublicKey;
	use bitcoin::network::Network;
	use bitcoin::script::ScriptBuf;
	use bitcoin::secp256k1::{self, Keypair, Message, Secp256k1, SecretKey, XOnlyPublicKey};
	use bitcoin::{CompressedPublicKey, WitnessProgram, WitnessVersion};

	use core::time::Duration;

	use crate::blinded_path::message::BlindedMessagePath;
	use crate::blinded_path::BlindedHop;
	use crate::ln::channelmanager::PaymentId;
	use crate::ln::inbound_payment::ExpandedKey;
	use crate::ln::msgs::DecodeError;
	use crate::offers::invoice_request::{
		ExperimentalInvoiceRequestTlvStreamRef, InvoiceRequestTlvStreamRef,
	};
	use crate::offers::merkle::{self, SignError, SignatureTlvStreamRef, TaggedHash, TlvStream};
	use crate::offers::nonce::Nonce;
	use crate::offers::offer::{
		Amount, ExperimentalOfferTlvStreamRef, OfferTlvStreamRef, Quantity,
	};
	use crate::offers::parse::{Bolt12ParseError, Bolt12SemanticError};
	use crate::offers::payer::PayerTlvStreamRef;
	use crate::offers::test_utils::*;
	use crate::prelude::*;
	use crate::types::features::{Bolt12InvoiceFeatures, InvoiceRequestFeatures, OfferFeatures};
	use crate::util::ser::{BigSize, Iterable, Writeable};
	use crate::util::string::PrintableString;
	#[cfg(not(c_bindings))]
	use {crate::offers::offer::OfferBuilder, crate::offers::refund::RefundBuilder};
	#[cfg(c_bindings)]
	use {
		crate::offers::offer::OfferWithExplicitMetadataBuilder as OfferBuilder,
		crate::offers::refund::RefundMaybeWithDerivedMetadataBuilder as RefundBuilder,
	};

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
		let expanded_key = ExpandedKey::new([42; 32]);
		let entropy = FixedEntropy {};
		let nonce = Nonce::from_entropy_source(&entropy);
		let secp_ctx = Secp256k1::new();
		let payment_id = PaymentId([1; 32]);
		let encrypted_payment_id = expanded_key.crypt_for_offer(payment_id.0, nonce);

		let payment_paths = payment_paths();
		let payment_hash = payment_hash();
		let now = now();
		let unsigned_invoice = OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.build()
			.unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.build_and_sign()
			.unwrap()
			.respond_with_no_std(payment_paths.clone(), payment_hash, now)
			.unwrap()
			.build()
			.unwrap();

		let mut buffer = Vec::new();
		unsigned_invoice.write(&mut buffer).unwrap();

		assert_eq!(unsigned_invoice.bytes, buffer.as_slice());
		assert_eq!(unsigned_invoice.payer_metadata(), &encrypted_payment_id);
		assert_eq!(
			unsigned_invoice.offer_chains(),
			Some(vec![ChainHash::using_genesis_block(Network::Bitcoin)])
		);
		assert_eq!(unsigned_invoice.metadata(), None);
		assert_eq!(unsigned_invoice.amount(), Some(Amount::Bitcoin { amount_msats: 1000 }));
		assert_eq!(unsigned_invoice.description(), Some(PrintableString("")));
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
		assert_eq!(unsigned_invoice.payer_note(), None);
		assert_eq!(unsigned_invoice.payment_paths(), payment_paths.as_slice());
		assert_eq!(unsigned_invoice.created_at(), now);
		assert_eq!(unsigned_invoice.relative_expiry(), DEFAULT_RELATIVE_EXPIRY);
		#[cfg(feature = "std")]
		assert!(!unsigned_invoice.is_expired());
		assert_eq!(unsigned_invoice.payment_hash(), payment_hash);
		assert!(unsigned_invoice.fallbacks().is_empty());
		assert_eq!(unsigned_invoice.invoice_features(), &Bolt12InvoiceFeatures::empty());

		match UnsignedBolt12Invoice::try_from(buffer) {
			Err(e) => panic!("error parsing unsigned invoice: {:?}", e),
			Ok(parsed) => {
				assert_eq!(parsed.bytes, unsigned_invoice.bytes);
				assert_eq!(parsed.tagged_hash, unsigned_invoice.tagged_hash);
			},
		}

		#[cfg(c_bindings)]
		let mut unsigned_invoice = unsigned_invoice;
		let invoice = unsigned_invoice.sign(recipient_sign).unwrap();

		let mut buffer = Vec::new();
		invoice.write(&mut buffer).unwrap();

		assert_eq!(invoice.bytes, buffer.as_slice());
		assert_eq!(invoice.payer_metadata(), &encrypted_payment_id);
		assert_eq!(
			invoice.offer_chains(),
			Some(vec![ChainHash::using_genesis_block(Network::Bitcoin)])
		);
		assert_eq!(invoice.metadata(), None);
		assert_eq!(invoice.amount(), Some(Amount::Bitcoin { amount_msats: 1000 }));
		assert_eq!(invoice.description(), Some(PrintableString("")));
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
		assert_eq!(
			invoice.verify_using_payer_data(payment_id, nonce, &expanded_key, &secp_ctx),
			Ok(payment_id),
		);
		assert_eq!(invoice.payer_note(), None);
		assert_eq!(invoice.payment_paths(), payment_paths.as_slice());
		assert_eq!(invoice.created_at(), now);
		assert_eq!(invoice.relative_expiry(), DEFAULT_RELATIVE_EXPIRY);
		#[cfg(feature = "std")]
		assert!(!invoice.is_expired());
		assert_eq!(invoice.payment_hash(), payment_hash);
		assert!(invoice.fallbacks().is_empty());
		assert_eq!(invoice.invoice_features(), &Bolt12InvoiceFeatures::empty());
		assert!(!invoice.is_for_refund_without_paths());

		let message = TaggedHash::from_valid_tlv_stream_bytes(SIGNATURE_TAG, &invoice.bytes);
		assert!(merkle::verify_signature(&invoice.signature, &message, recipient_pubkey()).is_ok());

		let digest = Message::from_digest(invoice.signable_hash());
		let pubkey = recipient_pubkey().into();
		let secp_ctx = Secp256k1::verification_only();
		assert!(secp_ctx.verify_schnorr(&invoice.signature, &digest, &pubkey).is_ok());

		assert_eq!(
			invoice.as_tlv_stream(),
			(
				PayerTlvStreamRef { metadata: Some(&encrypted_payment_id.to_vec()) },
				OfferTlvStreamRef {
					chains: None,
					metadata: None,
					currency: None,
					amount: Some(1000),
					description: Some(&String::from("")),
					features: None,
					absolute_expiry: None,
					paths: None,
					issuer: None,
					quantity_max: None,
					issuer_id: Some(&recipient_pubkey()),
				},
				InvoiceRequestTlvStreamRef {
					chain: None,
					amount: None,
					features: None,
					quantity: None,
					payer_id: Some(&invoice.payer_signing_pubkey()),
					payer_note: None,
					paths: None,
					offer_from_hrn: None,
				},
				InvoiceTlvStreamRef {
					paths: Some(Iterable(
						payment_paths.iter().map(|path| path.inner_blinded_path())
					)),
					blindedpay: Some(Iterable(payment_paths.iter().map(|path| &path.payinfo))),
					created_at: Some(now.as_secs()),
					relative_expiry: None,
					payment_hash: Some(&payment_hash),
					amount: Some(1000),
					fallbacks: None,
					features: None,
					node_id: Some(&recipient_pubkey()),
					message_paths: None,
				},
				SignatureTlvStreamRef { signature: Some(&invoice.signature()) },
				ExperimentalOfferTlvStreamRef { experimental_foo: None },
				ExperimentalInvoiceRequestTlvStreamRef { experimental_bar: None },
				ExperimentalInvoiceTlvStreamRef { experimental_baz: None },
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
		let invoice = RefundBuilder::new(vec![1; 32], payer_pubkey(), 1000)
			.unwrap()
			.build()
			.unwrap()
			.respond_with_no_std(payment_paths.clone(), payment_hash, recipient_pubkey(), now)
			.unwrap()
			.build()
			.unwrap()
			.sign(recipient_sign)
			.unwrap();

		let mut buffer = Vec::new();
		invoice.write(&mut buffer).unwrap();

		assert_eq!(invoice.bytes, buffer.as_slice());
		assert_eq!(invoice.payer_metadata(), &[1; 32]);
		assert_eq!(invoice.offer_chains(), None);
		assert_eq!(invoice.metadata(), None);
		assert_eq!(invoice.amount(), None);
		assert_eq!(invoice.description(), Some(PrintableString("")));
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
		assert_eq!(invoice.payer_signing_pubkey(), payer_pubkey());
		assert_eq!(invoice.payer_note(), None);
		assert_eq!(invoice.payment_paths(), payment_paths.as_slice());
		assert_eq!(invoice.created_at(), now);
		assert_eq!(invoice.relative_expiry(), DEFAULT_RELATIVE_EXPIRY);
		#[cfg(feature = "std")]
		assert!(!invoice.is_expired());
		assert_eq!(invoice.payment_hash(), payment_hash);
		assert!(invoice.fallbacks().is_empty());
		assert_eq!(invoice.invoice_features(), &Bolt12InvoiceFeatures::empty());
		assert!(invoice.is_for_refund_without_paths());

		let message = TaggedHash::from_valid_tlv_stream_bytes(SIGNATURE_TAG, &invoice.bytes);
		assert!(merkle::verify_signature(&invoice.signature, &message, recipient_pubkey()).is_ok());

		assert_eq!(
			invoice.as_tlv_stream(),
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
					issuer_id: None,
				},
				InvoiceRequestTlvStreamRef {
					chain: None,
					amount: Some(1000),
					features: None,
					quantity: None,
					payer_id: Some(&payer_pubkey()),
					payer_note: None,
					paths: None,
					offer_from_hrn: None,
				},
				InvoiceTlvStreamRef {
					paths: Some(Iterable(
						payment_paths.iter().map(|path| path.inner_blinded_path())
					)),
					blindedpay: Some(Iterable(payment_paths.iter().map(|path| &path.payinfo))),
					created_at: Some(now.as_secs()),
					relative_expiry: None,
					payment_hash: Some(&payment_hash),
					amount: Some(1000),
					fallbacks: None,
					features: None,
					node_id: Some(&recipient_pubkey()),
					message_paths: None,
				},
				SignatureTlvStreamRef { signature: Some(&invoice.signature()) },
				ExperimentalOfferTlvStreamRef { experimental_foo: None },
				ExperimentalInvoiceRequestTlvStreamRef { experimental_bar: None },
				ExperimentalInvoiceTlvStreamRef { experimental_baz: None },
			),
		);

		if let Err(e) = Bolt12Invoice::try_from(buffer) {
			panic!("error parsing invoice: {:?}", e);
		}
	}

	#[cfg(feature = "std")]
	#[test]
	fn builds_invoice_from_offer_with_expiration() {
		let expanded_key = ExpandedKey::new([42; 32]);
		let entropy = FixedEntropy {};
		let nonce = Nonce::from_entropy_source(&entropy);
		let secp_ctx = Secp256k1::new();
		let payment_id = PaymentId([1; 32]);

		let future_expiry = Duration::from_secs(u64::max_value());
		let past_expiry = Duration::from_secs(0);

		if let Err(e) = OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.absolute_expiry(future_expiry)
			.build()
			.unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.build_and_sign()
			.unwrap()
			.respond_with(payment_paths(), payment_hash())
			.unwrap()
			.build()
		{
			panic!("error building invoice: {:?}", e);
		}

		match OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.absolute_expiry(past_expiry)
			.build()
			.unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.build_unchecked_and_sign()
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

		if let Err(e) = RefundBuilder::new(vec![1; 32], payer_pubkey(), 1000)
			.unwrap()
			.absolute_expiry(future_expiry)
			.build()
			.unwrap()
			.respond_with(payment_paths(), payment_hash(), recipient_pubkey())
			.unwrap()
			.build()
		{
			panic!("error building invoice: {:?}", e);
		}

		match RefundBuilder::new(vec![1; 32], payer_pubkey(), 1000)
			.unwrap()
			.absolute_expiry(past_expiry)
			.build()
			.unwrap()
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
		let node_id = recipient_pubkey();
		let expanded_key = ExpandedKey::new([42; 32]);
		let entropy = FixedEntropy {};
		let nonce = Nonce::from_entropy_source(&entropy);
		let secp_ctx = Secp256k1::new();
		let payment_id = PaymentId([1; 32]);

		let blinded_path = BlindedMessagePath::from_blinded_path(
			pubkey(40),
			pubkey(41),
			vec![
				BlindedHop { blinded_node_id: pubkey(42), encrypted_payload: vec![0; 43] },
				BlindedHop { blinded_node_id: node_id, encrypted_payload: vec![0; 44] },
			],
		);

		#[cfg(c_bindings)]
		use crate::offers::offer::OfferWithDerivedMetadataBuilder as OfferBuilder;
		let invoice_request =
			OfferBuilder::deriving_signing_pubkey(node_id, &expanded_key, nonce, &secp_ctx)
				.amount_msats(1000)
				.path(blinded_path)
				.experimental_foo(42)
				.build()
				.unwrap()
				.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
				.unwrap()
				.build_and_sign()
				.unwrap();

		if let Err(e) = invoice_request
			.clone()
			.verify_using_recipient_data(nonce, &expanded_key, &secp_ctx)
			.unwrap()
			.respond_using_derived_keys_no_std(payment_paths(), payment_hash(), now())
			.unwrap()
			.build_and_sign(&secp_ctx)
		{
			panic!("error building invoice: {:?}", e);
		}

		let expanded_key = ExpandedKey::new([41; 32]);
		assert!(invoice_request
			.verify_using_recipient_data(nonce, &expanded_key, &secp_ctx)
			.is_err());

		let invoice_request =
			OfferBuilder::deriving_signing_pubkey(node_id, &expanded_key, nonce, &secp_ctx)
				.amount_msats(1000)
				// Omit the path so that node_id is used for the signing pubkey instead of deriving it
				.experimental_foo(42)
				.build()
				.unwrap()
				.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
				.unwrap()
				.build_and_sign()
				.unwrap();

		match invoice_request
			.verify_using_metadata(&expanded_key, &secp_ctx)
			.unwrap()
			.respond_using_derived_keys_no_std(payment_paths(), payment_hash(), now())
		{
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, Bolt12SemanticError::InvalidMetadata),
		}
	}

	#[test]
	fn builds_invoice_from_refund_using_derived_keys() {
		let expanded_key = ExpandedKey::new([42; 32]);
		let entropy = FixedEntropy {};
		let secp_ctx = Secp256k1::new();

		let refund = RefundBuilder::new(vec![1; 32], payer_pubkey(), 1000)
			.unwrap()
			.experimental_foo(42)
			.build()
			.unwrap();

		if let Err(e) = refund
			.respond_using_derived_keys_no_std(
				payment_paths(),
				payment_hash(),
				now(),
				&expanded_key,
				&entropy,
			)
			.unwrap()
			.build_and_sign(&secp_ctx)
		{
			panic!("error building invoice: {:?}", e);
		}
	}

	#[test]
	fn builds_invoice_from_refund_with_path() {
		let node_id = payer_pubkey();
		let expanded_key = ExpandedKey::new([42; 32]);
		let entropy = FixedEntropy {};
		let secp_ctx = Secp256k1::new();

		let blinded_path = BlindedMessagePath::from_blinded_path(
			pubkey(40),
			pubkey(41),
			vec![
				BlindedHop { blinded_node_id: pubkey(42), encrypted_payload: vec![0; 43] },
				BlindedHop { blinded_node_id: node_id, encrypted_payload: vec![0; 44] },
			],
		);

		let refund = RefundBuilder::new(vec![1; 32], payer_pubkey(), 1000)
			.unwrap()
			.path(blinded_path)
			.build()
			.unwrap();

		let invoice = refund
			.respond_using_derived_keys_no_std(
				payment_paths(),
				payment_hash(),
				now(),
				&expanded_key,
				&entropy,
			)
			.unwrap()
			.build_and_sign(&secp_ctx)
			.unwrap();
		assert!(!invoice.message_paths().is_empty());
		assert!(!invoice.is_for_refund_without_paths());
	}

	#[test]
	fn builds_invoice_with_relative_expiry() {
		let expanded_key = ExpandedKey::new([42; 32]);
		let entropy = FixedEntropy {};
		let nonce = Nonce::from_entropy_source(&entropy);
		let secp_ctx = Secp256k1::new();
		let payment_id = PaymentId([1; 32]);

		let now = now();
		let one_hour = Duration::from_secs(3600);

		let invoice = OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.build()
			.unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.build_and_sign()
			.unwrap()
			.respond_with_no_std(payment_paths(), payment_hash(), now)
			.unwrap()
			.relative_expiry(one_hour.as_secs() as u32)
			.build()
			.unwrap()
			.sign(recipient_sign)
			.unwrap();
		let (_, _, _, tlv_stream, _, _, _, _) = invoice.as_tlv_stream();
		#[cfg(feature = "std")]
		assert!(!invoice.is_expired());
		assert_eq!(invoice.relative_expiry(), one_hour);
		assert_eq!(tlv_stream.relative_expiry, Some(one_hour.as_secs() as u32));

		let invoice = OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.build()
			.unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.build_and_sign()
			.unwrap()
			.respond_with_no_std(payment_paths(), payment_hash(), now - one_hour)
			.unwrap()
			.relative_expiry(one_hour.as_secs() as u32 - 1)
			.build()
			.unwrap()
			.sign(recipient_sign)
			.unwrap();
		let (_, _, _, tlv_stream, _, _, _, _) = invoice.as_tlv_stream();
		#[cfg(feature = "std")]
		assert!(invoice.is_expired());
		assert_eq!(invoice.relative_expiry(), one_hour - Duration::from_secs(1));
		assert_eq!(tlv_stream.relative_expiry, Some(one_hour.as_secs() as u32 - 1));
	}

	#[test]
	fn builds_invoice_with_amount_from_request() {
		let expanded_key = ExpandedKey::new([42; 32]);
		let entropy = FixedEntropy {};
		let nonce = Nonce::from_entropy_source(&entropy);
		let secp_ctx = Secp256k1::new();
		let payment_id = PaymentId([1; 32]);

		let invoice = OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.build()
			.unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.amount_msats(1001)
			.unwrap()
			.build_and_sign()
			.unwrap()
			.respond_with_no_std(payment_paths(), payment_hash(), now())
			.unwrap()
			.build()
			.unwrap()
			.sign(recipient_sign)
			.unwrap();
		let (_, _, _, tlv_stream, _, _, _, _) = invoice.as_tlv_stream();
		assert_eq!(invoice.amount_msats(), 1001);
		assert_eq!(tlv_stream.amount, Some(1001));
	}

	#[test]
	fn builds_invoice_with_quantity_from_request() {
		let expanded_key = ExpandedKey::new([42; 32]);
		let entropy = FixedEntropy {};
		let nonce = Nonce::from_entropy_source(&entropy);
		let secp_ctx = Secp256k1::new();
		let payment_id = PaymentId([1; 32]);

		let invoice = OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.supported_quantity(Quantity::Unbounded)
			.build()
			.unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.quantity(2)
			.unwrap()
			.build_and_sign()
			.unwrap()
			.respond_with_no_std(payment_paths(), payment_hash(), now())
			.unwrap()
			.build()
			.unwrap()
			.sign(recipient_sign)
			.unwrap();
		let (_, _, _, tlv_stream, _, _, _, _) = invoice.as_tlv_stream();
		assert_eq!(invoice.amount_msats(), 2000);
		assert_eq!(tlv_stream.amount, Some(2000));

		match OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.supported_quantity(Quantity::Unbounded)
			.build()
			.unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.quantity(u64::max_value())
			.unwrap()
			.build_unchecked_and_sign()
			.respond_with_no_std(payment_paths(), payment_hash(), now())
		{
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, Bolt12SemanticError::InvalidAmount),
		}
	}

	#[test]
	fn builds_invoice_with_fallback_address() {
		let expanded_key = ExpandedKey::new([42; 32]);
		let entropy = FixedEntropy {};
		let nonce = Nonce::from_entropy_source(&entropy);
		let secp_ctx = Secp256k1::new();
		let payment_id = PaymentId([1; 32]);

		let script = ScriptBuf::new();
		let pubkey = bitcoin::key::PublicKey::new(recipient_pubkey());
		let x_only_pubkey = XOnlyPublicKey::from_keypair(&recipient_keys()).0;
		let tweaked_pubkey = TweakedPublicKey::dangerous_assume_tweaked(x_only_pubkey);

		let invoice = OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.build()
			.unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.build_and_sign()
			.unwrap()
			.respond_with_no_std(payment_paths(), payment_hash(), now())
			.unwrap()
			.fallback_v0_p2wsh(&script.wscript_hash())
			.fallback_v0_p2wpkh(&pubkey.wpubkey_hash().unwrap())
			.fallback_v1_p2tr_tweaked(&tweaked_pubkey)
			.build()
			.unwrap()
			.sign(recipient_sign)
			.unwrap();
		let (_, _, _, tlv_stream, _, _, _, _) = invoice.as_tlv_stream();
		assert_eq!(
			invoice.fallbacks(),
			vec![
				Address::p2wsh(&script, Network::Bitcoin),
				Address::p2wpkh(&CompressedPublicKey(pubkey.inner), Network::Bitcoin),
				Address::p2tr_tweaked(tweaked_pubkey, Network::Bitcoin),
			],
		);
		assert_eq!(
			tlv_stream.fallbacks,
			Some(&vec![
				FallbackAddress {
					version: WitnessVersion::V0.to_num(),
					program: Vec::from(script.wscript_hash().to_byte_array()),
				},
				FallbackAddress {
					version: WitnessVersion::V0.to_num(),
					program: Vec::from(pubkey.wpubkey_hash().unwrap().to_byte_array()),
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
		let expanded_key = ExpandedKey::new([42; 32]);
		let entropy = FixedEntropy {};
		let nonce = Nonce::from_entropy_source(&entropy);
		let secp_ctx = Secp256k1::new();
		let payment_id = PaymentId([1; 32]);

		let mut features = Bolt12InvoiceFeatures::empty();
		features.set_basic_mpp_optional();

		let invoice = OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.build()
			.unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.build_and_sign()
			.unwrap()
			.respond_with_no_std(payment_paths(), payment_hash(), now())
			.unwrap()
			.allow_mpp()
			.build()
			.unwrap()
			.sign(recipient_sign)
			.unwrap();
		let (_, _, _, tlv_stream, _, _, _, _) = invoice.as_tlv_stream();
		assert_eq!(invoice.invoice_features(), &features);
		assert_eq!(tlv_stream.features, Some(&features));
	}

	#[test]
	fn fails_signing_invoice() {
		let expanded_key = ExpandedKey::new([42; 32]);
		let entropy = FixedEntropy {};
		let nonce = Nonce::from_entropy_source(&entropy);
		let secp_ctx = Secp256k1::new();
		let payment_id = PaymentId([1; 32]);

		match OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.build()
			.unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.build_and_sign()
			.unwrap()
			.respond_with_no_std(payment_paths(), payment_hash(), now())
			.unwrap()
			.build()
			.unwrap()
			.sign(fail_sign)
		{
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, SignError::Signing),
		}

		match OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.build()
			.unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.build_and_sign()
			.unwrap()
			.respond_with_no_std(payment_paths(), payment_hash(), now())
			.unwrap()
			.build()
			.unwrap()
			.sign(payer_sign)
		{
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, SignError::Verification(secp256k1::Error::IncorrectSignature)),
		}
	}

	#[test]
	fn parses_invoice_with_payment_paths() {
		let expanded_key = ExpandedKey::new([42; 32]);
		let entropy = FixedEntropy {};
		let nonce = Nonce::from_entropy_source(&entropy);
		let secp_ctx = Secp256k1::new();
		let payment_id = PaymentId([1; 32]);

		let invoice = OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.build()
			.unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.build_and_sign()
			.unwrap()
			.respond_with_no_std(payment_paths(), payment_hash(), now())
			.unwrap()
			.build()
			.unwrap()
			.sign(recipient_sign)
			.unwrap();

		let mut buffer = Vec::new();
		invoice.write(&mut buffer).unwrap();

		if let Err(e) = Bolt12Invoice::try_from(buffer) {
			panic!("error parsing invoice: {:?}", e);
		}

		let mut tlv_stream = invoice.as_tlv_stream();
		tlv_stream.3.paths = None;

		match Bolt12Invoice::try_from(tlv_stream.to_bytes()) {
			Ok(_) => panic!("expected error"),
			Err(e) => {
				assert_eq!(e, Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::MissingPaths))
			},
		}

		let mut tlv_stream = invoice.as_tlv_stream();
		tlv_stream.3.blindedpay = None;

		match Bolt12Invoice::try_from(tlv_stream.to_bytes()) {
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(
				e,
				Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::InvalidPayInfo)
			),
		}

		let empty_payment_paths = vec![];
		let mut tlv_stream = invoice.as_tlv_stream();
		tlv_stream.3.paths =
			Some(Iterable(empty_payment_paths.iter().map(|path| path.inner_blinded_path())));

		match Bolt12Invoice::try_from(tlv_stream.to_bytes()) {
			Ok(_) => panic!("expected error"),
			Err(e) => {
				assert_eq!(e, Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::MissingPaths))
			},
		}

		let mut payment_paths = payment_paths();
		payment_paths.pop();
		let mut tlv_stream = invoice.as_tlv_stream();
		tlv_stream.3.blindedpay = Some(Iterable(payment_paths.iter().map(|path| &path.payinfo)));

		match Bolt12Invoice::try_from(tlv_stream.to_bytes()) {
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(
				e,
				Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::InvalidPayInfo)
			),
		}
	}

	#[test]
	fn parses_invoice_with_created_at() {
		let expanded_key = ExpandedKey::new([42; 32]);
		let entropy = FixedEntropy {};
		let nonce = Nonce::from_entropy_source(&entropy);
		let secp_ctx = Secp256k1::new();
		let payment_id = PaymentId([1; 32]);

		let invoice = OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.build()
			.unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.build_and_sign()
			.unwrap()
			.respond_with_no_std(payment_paths(), payment_hash(), now())
			.unwrap()
			.build()
			.unwrap()
			.sign(recipient_sign)
			.unwrap();

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
				assert_eq!(
					e,
					Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::MissingCreationTime)
				);
			},
		}
	}

	#[test]
	fn parses_invoice_with_relative_expiry() {
		let expanded_key = ExpandedKey::new([42; 32]);
		let entropy = FixedEntropy {};
		let nonce = Nonce::from_entropy_source(&entropy);
		let secp_ctx = Secp256k1::new();
		let payment_id = PaymentId([1; 32]);

		let invoice = OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.build()
			.unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.build_and_sign()
			.unwrap()
			.respond_with_no_std(payment_paths(), payment_hash(), now())
			.unwrap()
			.relative_expiry(3600)
			.build()
			.unwrap()
			.sign(recipient_sign)
			.unwrap();

		let mut buffer = Vec::new();
		invoice.write(&mut buffer).unwrap();

		match Bolt12Invoice::try_from(buffer) {
			Ok(invoice) => assert_eq!(invoice.relative_expiry(), Duration::from_secs(3600)),
			Err(e) => panic!("error parsing invoice: {:?}", e),
		}
	}

	#[test]
	fn parses_invoice_with_payment_hash() {
		let expanded_key = ExpandedKey::new([42; 32]);
		let entropy = FixedEntropy {};
		let nonce = Nonce::from_entropy_source(&entropy);
		let secp_ctx = Secp256k1::new();
		let payment_id = PaymentId([1; 32]);

		let invoice = OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.build()
			.unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.build_and_sign()
			.unwrap()
			.respond_with_no_std(payment_paths(), payment_hash(), now())
			.unwrap()
			.build()
			.unwrap()
			.sign(recipient_sign)
			.unwrap();

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
				assert_eq!(
					e,
					Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::MissingPaymentHash)
				);
			},
		}
	}

	#[test]
	fn parses_invoice_with_amount() {
		let expanded_key = ExpandedKey::new([42; 32]);
		let entropy = FixedEntropy {};
		let nonce = Nonce::from_entropy_source(&entropy);
		let secp_ctx = Secp256k1::new();
		let payment_id = PaymentId([1; 32]);

		let invoice = OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.build()
			.unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.build_and_sign()
			.unwrap()
			.respond_with_no_std(payment_paths(), payment_hash(), now())
			.unwrap()
			.build()
			.unwrap()
			.sign(recipient_sign)
			.unwrap();

		let mut buffer = Vec::new();
		invoice.write(&mut buffer).unwrap();

		if let Err(e) = Bolt12Invoice::try_from(buffer) {
			panic!("error parsing invoice: {:?}", e);
		}

		let mut tlv_stream = invoice.as_tlv_stream();
		tlv_stream.3.amount = None;

		match Bolt12Invoice::try_from(tlv_stream.to_bytes()) {
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(
				e,
				Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::MissingAmount)
			),
		}
	}

	#[test]
	fn parses_invoice_with_allow_mpp() {
		let expanded_key = ExpandedKey::new([42; 32]);
		let entropy = FixedEntropy {};
		let nonce = Nonce::from_entropy_source(&entropy);
		let secp_ctx = Secp256k1::new();
		let payment_id = PaymentId([1; 32]);

		let invoice = OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.build()
			.unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.build_and_sign()
			.unwrap()
			.respond_with_no_std(payment_paths(), payment_hash(), now())
			.unwrap()
			.allow_mpp()
			.build()
			.unwrap()
			.sign(recipient_sign)
			.unwrap();

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
		let expanded_key = ExpandedKey::new([42; 32]);
		let entropy = FixedEntropy {};
		let nonce = Nonce::from_entropy_source(&entropy);
		let secp_ctx = Secp256k1::new();
		let payment_id = PaymentId([1; 32]);

		let script = ScriptBuf::new();
		let pubkey = bitcoin::key::PublicKey::new(recipient_pubkey());
		let x_only_pubkey = XOnlyPublicKey::from_keypair(&recipient_keys()).0;
		let tweaked_pubkey = TweakedPublicKey::dangerous_assume_tweaked(x_only_pubkey);

		let invoice_request = OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.build()
			.unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.build_and_sign()
			.unwrap();
		#[cfg(not(c_bindings))]
		let invoice_builder =
			invoice_request.respond_with_no_std(payment_paths(), payment_hash(), now()).unwrap();
		#[cfg(c_bindings)]
		let mut invoice_builder =
			invoice_request.respond_with_no_std(payment_paths(), payment_hash(), now()).unwrap();
		let invoice_builder = invoice_builder
			.fallback_v0_p2wsh(&script.wscript_hash())
			.fallback_v0_p2wpkh(&pubkey.wpubkey_hash().unwrap())
			.fallback_v1_p2tr_tweaked(&tweaked_pubkey);
		#[cfg(not(c_bindings))]
		let mut invoice_builder = invoice_builder;

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
				let v1_witness_program =
					WitnessProgram::new(WitnessVersion::V1, &[0u8; 33]).unwrap();
				let v2_witness_program =
					WitnessProgram::new(WitnessVersion::V2, &[0u8; 40]).unwrap();
				assert_eq!(
					invoice.fallbacks(),
					vec![
						Address::p2wsh(&script, Network::Bitcoin),
						Address::p2wpkh(&CompressedPublicKey(pubkey.inner), Network::Bitcoin),
						Address::p2tr_tweaked(tweaked_pubkey, Network::Bitcoin),
						Address::from_witness_program(v1_witness_program, Network::Bitcoin),
						Address::from_witness_program(v2_witness_program, Network::Bitcoin),
					],
				);
			},
			Err(e) => panic!("error parsing invoice: {:?}", e),
		}
	}

	#[test]
	fn parses_invoice_with_node_id() {
		let expanded_key = ExpandedKey::new([42; 32]);
		let entropy = FixedEntropy {};
		let nonce = Nonce::from_entropy_source(&entropy);
		let secp_ctx = Secp256k1::new();
		let payment_id = PaymentId([1; 32]);

		let invoice = OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.build()
			.unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.build_and_sign()
			.unwrap()
			.respond_with_no_std(payment_paths(), payment_hash(), now())
			.unwrap()
			.build()
			.unwrap()
			.sign(recipient_sign)
			.unwrap();

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
				assert_eq!(
					e,
					Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::MissingSigningPubkey)
				);
			},
		}

		let invalid_pubkey = payer_pubkey();
		let mut tlv_stream = invoice.as_tlv_stream();
		tlv_stream.3.node_id = Some(&invalid_pubkey);

		match Bolt12Invoice::try_from(tlv_stream.to_bytes()) {
			Ok(_) => panic!("expected error"),
			Err(e) => {
				assert_eq!(
					e,
					Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::InvalidSigningPubkey)
				);
			},
		}
	}

	#[test]
	fn parses_invoice_with_node_id_from_blinded_path() {
		let expanded_key = ExpandedKey::new([42; 32]);
		let entropy = FixedEntropy {};
		let nonce = Nonce::from_entropy_source(&entropy);
		let secp_ctx = Secp256k1::new();
		let payment_id = PaymentId([1; 32]);

		let paths = vec![
			BlindedMessagePath::from_blinded_path(
				pubkey(40),
				pubkey(41),
				vec![
					BlindedHop { blinded_node_id: pubkey(43), encrypted_payload: vec![0; 43] },
					BlindedHop { blinded_node_id: pubkey(44), encrypted_payload: vec![0; 44] },
				],
			),
			BlindedMessagePath::from_blinded_path(
				pubkey(40),
				pubkey(41),
				vec![
					BlindedHop { blinded_node_id: pubkey(45), encrypted_payload: vec![0; 45] },
					BlindedHop { blinded_node_id: pubkey(46), encrypted_payload: vec![0; 46] },
				],
			),
		];

		let blinded_node_id_sign = |message: &UnsignedBolt12Invoice| {
			let secp_ctx = Secp256k1::new();
			let keys =
				Keypair::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[46; 32]).unwrap());
			Ok(secp_ctx.sign_schnorr_no_aux_rand(message.as_ref().as_digest(), &keys))
		};

		let invoice = OfferBuilder::new(recipient_pubkey())
			.clear_issuer_signing_pubkey()
			.amount_msats(1000)
			.path(paths[0].clone())
			.path(paths[1].clone())
			.build()
			.unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.build_and_sign()
			.unwrap()
			.respond_with_no_std_using_signing_pubkey(
				payment_paths(),
				payment_hash(),
				now(),
				pubkey(46),
			)
			.unwrap()
			.build()
			.unwrap()
			.sign(blinded_node_id_sign)
			.unwrap();

		let mut buffer = Vec::new();
		invoice.write(&mut buffer).unwrap();

		if let Err(e) = Bolt12Invoice::try_from(buffer) {
			panic!("error parsing invoice: {:?}", e);
		}

		let invoice = OfferBuilder::new(recipient_pubkey())
			.clear_issuer_signing_pubkey()
			.amount_msats(1000)
			.path(paths[0].clone())
			.path(paths[1].clone())
			.build()
			.unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.build_and_sign()
			.unwrap()
			.respond_with_no_std_using_signing_pubkey(
				payment_paths(),
				payment_hash(),
				now(),
				recipient_pubkey(),
			)
			.unwrap()
			.build()
			.unwrap()
			.sign(recipient_sign)
			.unwrap();

		let mut buffer = Vec::new();
		invoice.write(&mut buffer).unwrap();

		match Bolt12Invoice::try_from(buffer) {
			Ok(_) => panic!("expected error"),
			Err(e) => {
				assert_eq!(
					e,
					Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::InvalidSigningPubkey)
				);
			},
		}
	}

	#[test]
	fn fails_parsing_invoice_with_wrong_amount() {
		let expanded_key = ExpandedKey::new([42; 32]);
		let entropy = FixedEntropy {};
		let nonce = Nonce::from_entropy_source(&entropy);
		let secp_ctx = Secp256k1::new();
		let payment_id = PaymentId([1; 32]);

		let invoice = OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.build()
			.unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.build_and_sign()
			.unwrap()
			.respond_with_no_std(payment_paths(), payment_hash(), now())
			.unwrap()
			.amount_msats_unchecked(2000)
			.build()
			.unwrap()
			.sign(recipient_sign)
			.unwrap();

		let mut buffer = Vec::new();
		invoice.write(&mut buffer).unwrap();

		match Bolt12Invoice::try_from(buffer) {
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(
				e,
				Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::InvalidAmount)
			),
		}

		let invoice = OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.build()
			.unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.amount_msats(1000)
			.unwrap()
			.build_and_sign()
			.unwrap()
			.respond_with_no_std(payment_paths(), payment_hash(), now())
			.unwrap()
			.amount_msats_unchecked(2000)
			.build()
			.unwrap()
			.sign(recipient_sign)
			.unwrap();

		let mut buffer = Vec::new();
		invoice.write(&mut buffer).unwrap();

		match Bolt12Invoice::try_from(buffer) {
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(
				e,
				Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::InvalidAmount)
			),
		}

		let invoice = RefundBuilder::new(vec![1; 32], payer_pubkey(), 1000)
			.unwrap()
			.build()
			.unwrap()
			.respond_using_derived_keys_no_std(
				payment_paths(),
				payment_hash(),
				now(),
				&expanded_key,
				&entropy,
			)
			.unwrap()
			.amount_msats_unchecked(2000)
			.build_and_sign(&secp_ctx)
			.unwrap();

		let mut buffer = Vec::new();
		invoice.write(&mut buffer).unwrap();

		match Bolt12Invoice::try_from(buffer) {
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(
				e,
				Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::InvalidAmount)
			),
		}
	}

	#[test]
	fn fails_parsing_invoice_without_signature() {
		let expanded_key = ExpandedKey::new([42; 32]);
		let entropy = FixedEntropy {};
		let nonce = Nonce::from_entropy_source(&entropy);
		let secp_ctx = Secp256k1::new();
		let payment_id = PaymentId([1; 32]);

		let mut buffer = Vec::new();
		OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.build()
			.unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.build_and_sign()
			.unwrap()
			.respond_with_no_std(payment_paths(), payment_hash(), now())
			.unwrap()
			.build()
			.unwrap()
			.contents
			.write(&mut buffer)
			.unwrap();

		match Bolt12Invoice::try_from(buffer) {
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(
				e,
				Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::MissingSignature)
			),
		}
	}

	#[test]
	fn fails_parsing_invoice_with_invalid_signature() {
		let expanded_key = ExpandedKey::new([42; 32]);
		let entropy = FixedEntropy {};
		let nonce = Nonce::from_entropy_source(&entropy);
		let secp_ctx = Secp256k1::new();
		let payment_id = PaymentId([1; 32]);

		let mut invoice = OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.build()
			.unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.build_and_sign()
			.unwrap()
			.respond_with_no_std(payment_paths(), payment_hash(), now())
			.unwrap()
			.build()
			.unwrap()
			.sign(recipient_sign)
			.unwrap();
		let last_signature_byte = invoice.bytes.last_mut().unwrap();
		*last_signature_byte = last_signature_byte.wrapping_add(1);

		let mut buffer = Vec::new();
		invoice.write(&mut buffer).unwrap();

		match Bolt12Invoice::try_from(buffer) {
			Ok(_) => panic!("expected error"),
			Err(e) => {
				assert_eq!(
					e,
					Bolt12ParseError::InvalidSignature(secp256k1::Error::IncorrectSignature)
				);
			},
		}
	}

	#[test]
	fn parses_invoice_with_unknown_tlv_records() {
		let expanded_key = ExpandedKey::new([42; 32]);
		let entropy = FixedEntropy {};
		let nonce = Nonce::from_entropy_source(&entropy);
		let payment_id = PaymentId([1; 32]);

		const UNKNOWN_ODD_TYPE: u64 = INVOICE_TYPES.end - 1;
		assert!(UNKNOWN_ODD_TYPE % 2 == 1);

		let secp_ctx = Secp256k1::new();
		let keys = Keypair::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[42; 32]).unwrap());
		let mut unsigned_invoice = OfferBuilder::new(keys.public_key())
			.amount_msats(1000)
			.build()
			.unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.build_and_sign()
			.unwrap()
			.respond_with_no_std(payment_paths(), payment_hash(), now())
			.unwrap()
			.build()
			.unwrap();

		let mut unknown_bytes = Vec::new();
		BigSize(UNKNOWN_ODD_TYPE).write(&mut unknown_bytes).unwrap();
		BigSize(32).write(&mut unknown_bytes).unwrap();
		[42u8; 32].write(&mut unknown_bytes).unwrap();

		unsigned_invoice.bytes.extend_from_slice(&unknown_bytes);
		unsigned_invoice.tagged_hash =
			TaggedHash::from_valid_tlv_stream_bytes(SIGNATURE_TAG, &unsigned_invoice.bytes);

		let invoice = unsigned_invoice
			.sign(|message: &UnsignedBolt12Invoice| {
				Ok(secp_ctx.sign_schnorr_no_aux_rand(message.as_ref().as_digest(), &keys))
			})
			.unwrap();

		let mut encoded_invoice = Vec::new();
		invoice.write(&mut encoded_invoice).unwrap();

		match Bolt12Invoice::try_from(encoded_invoice.clone()) {
			Ok(invoice) => assert_eq!(invoice.bytes, encoded_invoice),
			Err(e) => panic!("error parsing invoice: {:?}", e),
		}

		const UNKNOWN_EVEN_TYPE: u64 = INVOICE_TYPES.end - 2;
		assert!(UNKNOWN_EVEN_TYPE % 2 == 0);

		let mut unsigned_invoice = OfferBuilder::new(keys.public_key())
			.amount_msats(1000)
			.build()
			.unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.build_and_sign()
			.unwrap()
			.respond_with_no_std(payment_paths(), payment_hash(), now())
			.unwrap()
			.build()
			.unwrap();

		let mut unknown_bytes = Vec::new();
		BigSize(UNKNOWN_EVEN_TYPE).write(&mut unknown_bytes).unwrap();
		BigSize(32).write(&mut unknown_bytes).unwrap();
		[42u8; 32].write(&mut unknown_bytes).unwrap();

		unsigned_invoice.bytes.extend_from_slice(&unknown_bytes);
		unsigned_invoice.tagged_hash =
			TaggedHash::from_valid_tlv_stream_bytes(SIGNATURE_TAG, &unsigned_invoice.bytes);

		let invoice = unsigned_invoice
			.sign(|message: &UnsignedBolt12Invoice| {
				Ok(secp_ctx.sign_schnorr_no_aux_rand(message.as_ref().as_digest(), &keys))
			})
			.unwrap();

		let mut encoded_invoice = Vec::new();
		invoice.write(&mut encoded_invoice).unwrap();

		match Bolt12Invoice::try_from(encoded_invoice) {
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, Bolt12ParseError::Decode(DecodeError::UnknownRequiredFeature)),
		}
	}

	#[test]
	fn parses_invoice_with_experimental_tlv_records() {
		let expanded_key = ExpandedKey::new([42; 32]);
		let entropy = FixedEntropy {};
		let nonce = Nonce::from_entropy_source(&entropy);
		let payment_id = PaymentId([1; 32]);

		let secp_ctx = Secp256k1::new();
		let keys = Keypair::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[42; 32]).unwrap());
		let invoice = OfferBuilder::new(keys.public_key())
			.amount_msats(1000)
			.build()
			.unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.build_and_sign()
			.unwrap()
			.respond_with_no_std(payment_paths(), payment_hash(), now())
			.unwrap()
			.experimental_baz(42)
			.build()
			.unwrap()
			.sign(|message: &UnsignedBolt12Invoice| {
				Ok(secp_ctx.sign_schnorr_no_aux_rand(message.as_ref().as_digest(), &keys))
			})
			.unwrap();

		let mut encoded_invoice = Vec::new();
		invoice.write(&mut encoded_invoice).unwrap();

		assert!(Bolt12Invoice::try_from(encoded_invoice).is_ok());

		const UNKNOWN_ODD_TYPE: u64 = EXPERIMENTAL_INVOICE_TYPES.start + 1;
		assert!(UNKNOWN_ODD_TYPE % 2 == 1);

		let mut unsigned_invoice = OfferBuilder::new(keys.public_key())
			.amount_msats(1000)
			.build()
			.unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.build_and_sign()
			.unwrap()
			.respond_with_no_std(payment_paths(), payment_hash(), now())
			.unwrap()
			.build()
			.unwrap();

		let mut unknown_bytes = Vec::new();
		BigSize(UNKNOWN_ODD_TYPE).write(&mut unknown_bytes).unwrap();
		BigSize(32).write(&mut unknown_bytes).unwrap();
		[42u8; 32].write(&mut unknown_bytes).unwrap();

		unsigned_invoice.experimental_bytes.extend_from_slice(&unknown_bytes);

		let tlv_stream = TlvStream::new(&unsigned_invoice.bytes)
			.chain(TlvStream::new(&unsigned_invoice.experimental_bytes));
		unsigned_invoice.tagged_hash = TaggedHash::from_tlv_stream(SIGNATURE_TAG, tlv_stream);

		let invoice = unsigned_invoice
			.sign(|message: &UnsignedBolt12Invoice| {
				Ok(secp_ctx.sign_schnorr_no_aux_rand(message.as_ref().as_digest(), &keys))
			})
			.unwrap();

		let mut encoded_invoice = Vec::new();
		invoice.write(&mut encoded_invoice).unwrap();

		match Bolt12Invoice::try_from(encoded_invoice.clone()) {
			Ok(invoice) => assert_eq!(invoice.bytes, encoded_invoice),
			Err(e) => panic!("error parsing invoice: {:?}", e),
		}

		const UNKNOWN_EVEN_TYPE: u64 = EXPERIMENTAL_INVOICE_TYPES.start;
		assert!(UNKNOWN_EVEN_TYPE % 2 == 0);

		let mut unsigned_invoice = OfferBuilder::new(keys.public_key())
			.amount_msats(1000)
			.build()
			.unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.build_and_sign()
			.unwrap()
			.respond_with_no_std(payment_paths(), payment_hash(), now())
			.unwrap()
			.build()
			.unwrap();

		let mut unknown_bytes = Vec::new();
		BigSize(UNKNOWN_EVEN_TYPE).write(&mut unknown_bytes).unwrap();
		BigSize(32).write(&mut unknown_bytes).unwrap();
		[42u8; 32].write(&mut unknown_bytes).unwrap();

		unsigned_invoice.experimental_bytes.extend_from_slice(&unknown_bytes);

		let tlv_stream = TlvStream::new(&unsigned_invoice.bytes)
			.chain(TlvStream::new(&unsigned_invoice.experimental_bytes));
		unsigned_invoice.tagged_hash = TaggedHash::from_tlv_stream(SIGNATURE_TAG, tlv_stream);

		let invoice = unsigned_invoice
			.sign(|message: &UnsignedBolt12Invoice| {
				Ok(secp_ctx.sign_schnorr_no_aux_rand(message.as_ref().as_digest(), &keys))
			})
			.unwrap();

		let mut encoded_invoice = Vec::new();
		invoice.write(&mut encoded_invoice).unwrap();

		match Bolt12Invoice::try_from(encoded_invoice) {
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, Bolt12ParseError::Decode(DecodeError::UnknownRequiredFeature)),
		}

		let invoice = OfferBuilder::new(keys.public_key())
			.amount_msats(1000)
			.build()
			.unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.build_and_sign()
			.unwrap()
			.respond_with_no_std(payment_paths(), payment_hash(), now())
			.unwrap()
			.build()
			.unwrap()
			.sign(|message: &UnsignedBolt12Invoice| {
				Ok(secp_ctx.sign_schnorr_no_aux_rand(message.as_ref().as_digest(), &keys))
			})
			.unwrap();

		let mut encoded_invoice = Vec::new();
		invoice.write(&mut encoded_invoice).unwrap();

		BigSize(UNKNOWN_ODD_TYPE).write(&mut encoded_invoice).unwrap();
		BigSize(32).write(&mut encoded_invoice).unwrap();
		[42u8; 32].write(&mut encoded_invoice).unwrap();

		match Bolt12Invoice::try_from(encoded_invoice) {
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(
				e,
				Bolt12ParseError::InvalidSignature(secp256k1::Error::IncorrectSignature)
			),
		}
	}

	#[test]
	fn fails_parsing_invoice_with_out_of_range_tlv_records() {
		let expanded_key = ExpandedKey::new([42; 32]);
		let entropy = FixedEntropy {};
		let nonce = Nonce::from_entropy_source(&entropy);
		let secp_ctx = Secp256k1::new();
		let payment_id = PaymentId([1; 32]);

		let invoice = OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.build()
			.unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.build_and_sign()
			.unwrap()
			.respond_with_no_std(payment_paths(), payment_hash(), now())
			.unwrap()
			.build()
			.unwrap()
			.sign(recipient_sign)
			.unwrap();

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

	#[test]
	fn fails_parsing_invoice_with_message_paths() {
		let expanded_key = ExpandedKey::new([42; 32]);
		let entropy = FixedEntropy {};
		let nonce = Nonce::from_entropy_source(&entropy);
		let secp_ctx = Secp256k1::new();
		let payment_id = PaymentId([1; 32]);

		let invoice = OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.build()
			.unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.build_and_sign()
			.unwrap()
			.respond_with_no_std(payment_paths(), payment_hash(), now())
			.unwrap()
			.build()
			.unwrap()
			.sign(recipient_sign)
			.unwrap();

		let blinded_path = BlindedMessagePath::from_blinded_path(
			pubkey(40),
			pubkey(41),
			vec![
				BlindedHop { blinded_node_id: pubkey(42), encrypted_payload: vec![0; 43] },
				BlindedHop { blinded_node_id: pubkey(43), encrypted_payload: vec![0; 44] },
			],
		);

		let mut tlv_stream = invoice.as_tlv_stream();
		let message_paths = vec![blinded_path];
		tlv_stream.3.message_paths = Some(&message_paths);

		match Bolt12Invoice::try_from(tlv_stream.to_bytes()) {
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(
				e,
				Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::UnexpectedPaths)
			),
		}
	}
}
