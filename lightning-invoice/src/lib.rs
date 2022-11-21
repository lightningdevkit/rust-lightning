// Prefix these with `rustdoc::` when we update our MSRV to be >= 1.52 to remove warnings.
#![deny(broken_intra_doc_links)]
#![deny(private_intra_doc_links)]

#![deny(missing_docs)]
#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]

#![cfg_attr(docsrs, feature(doc_auto_cfg))]

#![cfg_attr(feature = "strict", deny(warnings))]
#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]

//! This crate provides data structures to represent
//! [lightning BOLT11](https://github.com/lightning/bolts/blob/master/11-payment-encoding.md)
//! invoices and functions to create, encode and decode these. If you just want to use the standard
//! en-/decoding functionality this should get you started:
//!
//!   * For parsing use `str::parse::<Invoice>(&self)` (see the docs of `impl FromStr for Invoice`)
//!   * For constructing invoices use the `InvoiceBuilder`
//!   * For serializing invoices use the `Display`/`ToString` traits

#[cfg(not(any(feature = "std", feature = "no-std")))]
compile_error!("at least one of the `std` or `no-std` features must be enabled");

pub mod payment;
pub mod utils;

pub(crate) mod time_utils;

extern crate bech32;
extern crate bitcoin_hashes;
#[macro_use] extern crate lightning;
extern crate num_traits;
extern crate secp256k1;
extern crate alloc;
#[cfg(any(test, feature = "std"))]
extern crate core;
#[cfg(feature = "serde")]
extern crate serde;

#[cfg(feature = "std")]
use std::time::SystemTime;

use bech32::u5;
use bitcoin_hashes::Hash;
use bitcoin_hashes::sha256;
use lightning::ln::PaymentSecret;
use lightning::ln::features::InvoiceFeatures;
#[cfg(any(doc, test))]
use lightning::routing::gossip::RoutingFees;
use lightning::routing::router::RouteHint;
use lightning::util::invoice::construct_invoice_preimage;

use secp256k1::PublicKey;
use secp256k1::{Message, Secp256k1};
use secp256k1::ecdsa::RecoverableSignature;

use core::fmt::{Display, Formatter, self};
use core::iter::FilterMap;
use core::num::ParseIntError;
use core::ops::Deref;
use core::slice::Iter;
use core::time::Duration;
use core::str;

#[cfg(feature = "serde")]
use serde::{Deserialize, Deserializer,Serialize, Serializer, de::Error};

mod de;
mod ser;
mod tb;

mod prelude {
	#[cfg(feature = "hashbrown")]
	extern crate hashbrown;

	pub use alloc::{vec, vec::Vec, string::String, collections::VecDeque, boxed::Box};
	#[cfg(not(feature = "hashbrown"))]
	pub use std::collections::{HashMap, HashSet, hash_map};
	#[cfg(feature = "hashbrown")]
	pub use self::hashbrown::{HashMap, HashSet, hash_map};

	pub use alloc::string::ToString;
}

use crate::prelude::*;

/// Sync compat for std/no_std
#[cfg(feature = "std")]
mod sync {
	pub use ::std::sync::{Mutex, MutexGuard};
}

/// Sync compat for std/no_std
#[cfg(not(feature = "std"))]
mod sync;

/// Errors that indicate what is wrong with the invoice. They have some granularity for debug
/// reasons, but should generally result in an "invalid BOLT11 invoice" message for the user.
#[allow(missing_docs)]
#[derive(PartialEq, Eq, Debug, Clone)]
pub enum ParseError {
	Bech32Error(bech32::Error),
	ParseAmountError(ParseIntError),
	MalformedSignature(secp256k1::Error),
	BadPrefix,
	UnknownCurrency,
	UnknownSiPrefix,
	MalformedHRP,
	TooShortDataPart,
	UnexpectedEndOfTaggedFields,
	DescriptionDecodeError(str::Utf8Error),
	PaddingError,
	IntegerOverflowError,
	InvalidSegWitProgramLength,
	InvalidPubKeyHashLength,
	InvalidScriptHashLength,
	InvalidRecoveryId,
	InvalidSliceLength(String),

	/// Not an error, but used internally to signal that a part of the invoice should be ignored
	/// according to BOLT11
	Skip,
}

/// Indicates that something went wrong while parsing or validating the invoice. Parsing errors
/// should be mostly seen as opaque and are only there for debugging reasons. Semantic errors
/// like wrong signatures, missing fields etc. could mean that someone tampered with the invoice.
#[derive(PartialEq, Eq, Debug, Clone)]
pub enum ParseOrSemanticError {
	/// The invoice couldn't be decoded
	ParseError(ParseError),

	/// The invoice could be decoded but violates the BOLT11 standard
	SemanticError(crate::SemanticError),
}

/// The number of bits used to represent timestamps as defined in BOLT 11.
const TIMESTAMP_BITS: usize = 35;

/// The maximum timestamp as [`Duration::as_secs`] since the Unix epoch allowed by [`BOLT 11`].
///
/// [BOLT 11]: https://github.com/lightning/bolts/blob/master/11-payment-encoding.md
pub const MAX_TIMESTAMP: u64 = (1 << TIMESTAMP_BITS) - 1;

/// Default expiry time as defined by [BOLT 11].
///
/// [BOLT 11]: https://github.com/lightning/bolts/blob/master/11-payment-encoding.md
pub const DEFAULT_EXPIRY_TIME: u64 = 3600;

/// Default minimum final CLTV expiry as defined by [BOLT 11].
///
/// Note that this is *not* the same value as rust-lightning's minimum CLTV expiry, which is
/// provided in [`MIN_FINAL_CLTV_EXPIRY_DELTA`].
///
/// [BOLT 11]: https://github.com/lightning/bolts/blob/master/11-payment-encoding.md
/// [`MIN_FINAL_CLTV_EXPIRY_DELTA`]: lightning::ln::channelmanager::MIN_FINAL_CLTV_EXPIRY_DELTA
pub const DEFAULT_MIN_FINAL_CLTV_EXPIRY_DELTA: u64 = 18;

/// Builder for `Invoice`s. It's the most convenient and advised way to use this library. It ensures
/// that only a semantically and syntactically correct Invoice can be built using it.
///
/// ```
/// extern crate secp256k1;
/// extern crate lightning;
/// extern crate lightning_invoice;
/// extern crate bitcoin_hashes;
///
/// use bitcoin_hashes::Hash;
/// use bitcoin_hashes::sha256;
///
/// use secp256k1::Secp256k1;
/// use secp256k1::SecretKey;
///
/// use lightning::ln::PaymentSecret;
///
/// use lightning_invoice::{Currency, InvoiceBuilder};
///
/// # #[cfg(not(feature = "std"))]
/// # fn main() {}
/// # #[cfg(feature = "std")]
/// # fn main() {
/// let private_key = SecretKey::from_slice(
///		&[
///			0xe1, 0x26, 0xf6, 0x8f, 0x7e, 0xaf, 0xcc, 0x8b, 0x74, 0xf5, 0x4d, 0x26, 0x9f,
///			0xe2, 0x06, 0xbe, 0x71, 0x50, 0x00, 0xf9, 0x4d, 0xac, 0x06, 0x7d, 0x1c, 0x04,
/// 		0xa8, 0xca, 0x3b, 0x2d, 0xb7, 0x34
/// 	][..]
///	).unwrap();
///
/// let payment_hash = sha256::Hash::from_slice(&[0; 32][..]).unwrap();
/// let payment_secret = PaymentSecret([42u8; 32]);
///
/// let invoice = InvoiceBuilder::new(Currency::Bitcoin)
/// 	.description("Coins pls!".into())
/// 	.payment_hash(payment_hash)
/// 	.payment_secret(payment_secret)
/// 	.current_timestamp()
/// 	.min_final_cltv_expiry_delta(144)
/// 	.build_signed(|hash| {
/// 		Secp256k1::new().sign_ecdsa_recoverable(hash, &private_key)
/// 	})
/// 	.unwrap();
///
/// assert!(invoice.to_string().starts_with("lnbc1"));
/// # }
/// ```
///
/// # Type parameters
/// The two parameters `D` and `H` signal if the builder already contains the correct amount of the
/// given field:
///  * `D`: exactly one `Description` or `DescriptionHash`
///  * `H`: exactly one `PaymentHash`
///  * `T`: the timestamp is set
///
/// (C-not exported) as we likely need to manually select one set of boolean type parameters.
#[derive(Eq, PartialEq, Debug, Clone)]
pub struct InvoiceBuilder<D: tb::Bool, H: tb::Bool, T: tb::Bool, C: tb::Bool, S: tb::Bool> {
	currency: Currency,
	amount: Option<u64>,
	si_prefix: Option<SiPrefix>,
	timestamp: Option<PositiveTimestamp>,
	tagged_fields: Vec<TaggedField>,
	error: Option<CreationError>,

	phantom_d: core::marker::PhantomData<D>,
	phantom_h: core::marker::PhantomData<H>,
	phantom_t: core::marker::PhantomData<T>,
	phantom_c: core::marker::PhantomData<C>,
	phantom_s: core::marker::PhantomData<S>,
}

/// Represents a syntactically and semantically correct lightning BOLT11 invoice.
///
/// There are three ways to construct an `Invoice`:
///  1. using `InvoiceBuilder`
///  2. using `Invoice::from_signed(SignedRawInvoice)`
///  3. using `str::parse::<Invoice>(&str)`
#[derive(Eq, PartialEq, Debug, Clone, Hash)]
pub struct Invoice {
	signed_invoice: SignedRawInvoice,
}

/// Represents the description of an invoice which has to be either a directly included string or
/// a hash of a description provided out of band.
///
/// (C-not exported) As we don't have a good way to map the reference lifetimes making this
/// practically impossible to use safely in languages like C.
#[derive(Eq, PartialEq, Debug, Clone)]
pub enum InvoiceDescription<'f> {
	/// Reference to the directly supplied description in the invoice
	Direct(&'f Description),

	/// Reference to the description's hash included in the invoice
	Hash(&'f Sha256),
}

/// Represents a signed `RawInvoice` with cached hash. The signature is not checked and may be
/// invalid.
///
/// # Invariants
/// The hash has to be either from the deserialized invoice or from the serialized `raw_invoice`.
#[derive(Eq, PartialEq, Debug, Clone, Hash)]
pub struct SignedRawInvoice {
	/// The rawInvoice that the signature belongs to
	raw_invoice: RawInvoice,

	/// Hash of the `RawInvoice` that will be used to check the signature.
	///
	/// * if the `SignedRawInvoice` was deserialized the hash is of from the original encoded form,
	/// since it's not guaranteed that encoding it again will lead to the same result since integers
	/// could have been encoded with leading zeroes etc.
	/// * if the `SignedRawInvoice` was constructed manually the hash will be the calculated hash
	/// from the `RawInvoice`
	hash: [u8; 32],

	/// signature of the payment request
	signature: InvoiceSignature,
}

/// Represents an syntactically correct Invoice for a payment on the lightning network,
/// but without the signature information.
/// De- and encoding should not lead to information loss but may lead to different hashes.
///
/// For methods without docs see the corresponding methods in `Invoice`.
#[derive(Eq, PartialEq, Debug, Clone, Hash)]
pub struct RawInvoice {
	/// human readable part
	pub hrp: RawHrp,

	/// data part
	pub data: RawDataPart,
}

/// Data of the `RawInvoice` that is encoded in the human readable part
///
/// (C-not exported) As we don't yet support `Option<Enum>`
#[derive(Eq, PartialEq, Debug, Clone, Hash)]
pub struct RawHrp {
	/// The currency deferred from the 3rd and 4th character of the bech32 transaction
	pub currency: Currency,

	/// The amount that, multiplied by the SI prefix, has to be payed
	pub raw_amount: Option<u64>,

	/// SI prefix that gets multiplied with the `raw_amount`
	pub si_prefix: Option<SiPrefix>,
}

/// Data of the `RawInvoice` that is encoded in the data part
#[derive(Eq, PartialEq, Debug, Clone, Hash)]
pub struct RawDataPart {
	/// generation time of the invoice
	pub timestamp: PositiveTimestamp,

	/// tagged fields of the payment request
	pub tagged_fields: Vec<RawTaggedField>,
}

/// A timestamp that refers to a date after 1 January 1970.
///
/// # Invariants
///
/// The Unix timestamp representing the stored time has to be positive and no greater than
/// [`MAX_TIMESTAMP`].
#[derive(Eq, PartialEq, Debug, Clone, Hash)]
pub struct PositiveTimestamp(Duration);

/// SI prefixes for the human readable part
#[derive(Eq, PartialEq, Debug, Clone, Copy, Hash)]
pub enum SiPrefix {
	/// 10^-3
	Milli,
	/// 10^-6
	Micro,
	/// 10^-9
	Nano,
	/// 10^-12
	Pico,
}

impl SiPrefix {
	/// Returns the multiplier to go from a BTC value to picoBTC implied by this SiPrefix.
	/// This is effectively 10^12 * the prefix multiplier
	pub fn multiplier(&self) -> u64 {
		match *self {
			SiPrefix::Milli => 1_000_000_000,
			SiPrefix::Micro => 1_000_000,
			SiPrefix::Nano => 1_000,
			SiPrefix::Pico => 1,
		}
	}

	/// Returns all enum variants of `SiPrefix` sorted in descending order of their associated
	/// multiplier.
	///
	/// (C-not exported) As we don't yet support a slice of enums, and also because this function
	/// isn't the most critical to expose.
	pub fn values_desc() -> &'static [SiPrefix] {
		use crate::SiPrefix::*;
		static VALUES: [SiPrefix; 4] = [Milli, Micro, Nano, Pico];
		&VALUES
	}
}

/// Enum representing the crypto currencies (or networks) supported by this library
#[derive(Clone, Debug, Hash, Eq, PartialEq)]
pub enum Currency {
	/// Bitcoin mainnet
	Bitcoin,

	/// Bitcoin testnet
	BitcoinTestnet,

	/// Bitcoin regtest
	Regtest,

	/// Bitcoin simnet
	Simnet,

	/// Bitcoin signet
	Signet,
}

/// Tagged field which may have an unknown tag
///
/// (C-not exported) as we don't currently support TaggedField
#[derive(Clone, Debug, Hash, Eq, PartialEq)]
pub enum RawTaggedField {
	/// Parsed tagged field with known tag
	KnownSemantics(TaggedField),
	/// tagged field which was not parsed due to an unknown tag or undefined field semantics
	UnknownSemantics(Vec<u5>),
}

/// Tagged field with known tag
///
/// For descriptions of the enum values please refer to the enclosed type's docs.
///
/// (C-not exported) As we don't yet support enum variants with the same name the struct contained
/// in the variant.
#[allow(missing_docs)]
#[derive(Clone, Debug, Hash, Eq, PartialEq)]
pub enum TaggedField {
	PaymentHash(Sha256),
	Description(Description),
	PayeePubKey(PayeePubKey),
	DescriptionHash(Sha256),
	ExpiryTime(ExpiryTime),
	MinFinalCltvExpiryDelta(MinFinalCltvExpiryDelta),
	Fallback(Fallback),
	PrivateRoute(PrivateRoute),
	PaymentSecret(PaymentSecret),
	Features(InvoiceFeatures),
}

/// SHA-256 hash
#[derive(Clone, Debug, Hash, Eq, PartialEq)]
pub struct Sha256(/// (C-not exported) as the native hash types are not currently mapped
	pub sha256::Hash);

/// Description string
///
/// # Invariants
/// The description can be at most 639 __bytes__ long
#[derive(Clone, Debug, Hash, Eq, PartialEq)]
pub struct Description(String);

/// Payee public key
#[derive(Clone, Debug, Hash, Eq, PartialEq)]
pub struct PayeePubKey(pub PublicKey);

/// Positive duration that defines when (relatively to the timestamp) in the future the invoice
/// expires
#[derive(Clone, Debug, Hash, Eq, PartialEq)]
pub struct ExpiryTime(Duration);

/// `min_final_cltv_expiry_delta` to use for the last HTLC in the route
#[derive(Clone, Debug, Hash, Eq, PartialEq)]
pub struct MinFinalCltvExpiryDelta(pub u64);

// TODO: better types instead onf byte arrays
/// Fallback address in case no LN payment is possible
#[allow(missing_docs)]
#[derive(Clone, Debug, Hash, Eq, PartialEq)]
pub enum Fallback {
	SegWitProgram {
		version: u5,
		program: Vec<u8>,
	},
	PubKeyHash([u8; 20]),
	ScriptHash([u8; 20]),
}

/// Recoverable signature
#[derive(Clone, Debug, Hash, Eq, PartialEq)]
pub struct InvoiceSignature(pub RecoverableSignature);

/// Private routing information
///
/// # Invariants
/// The encoded route has to be <1024 5bit characters long (<=639 bytes or <=12 hops)
///
#[derive(Clone, Debug, Hash, Eq, PartialEq)]
pub struct PrivateRoute(RouteHint);

/// Tag constants as specified in BOLT11
#[allow(missing_docs)]
pub mod constants {
	pub const TAG_PAYMENT_HASH: u8 = 1;
	pub const TAG_DESCRIPTION: u8 = 13;
	pub const TAG_PAYEE_PUB_KEY: u8 = 19;
	pub const TAG_DESCRIPTION_HASH: u8 = 23;
	pub const TAG_EXPIRY_TIME: u8 = 6;
	pub const TAG_MIN_FINAL_CLTV_EXPIRY_DELTA: u8 = 24;
	pub const TAG_FALLBACK: u8 = 9;
	pub const TAG_PRIVATE_ROUTE: u8 = 3;
	pub const TAG_PAYMENT_SECRET: u8 = 16;
	pub const TAG_FEATURES: u8 = 5;
}

impl InvoiceBuilder<tb::False, tb::False, tb::False, tb::False, tb::False> {
	/// Construct new, empty `InvoiceBuilder`. All necessary fields have to be filled first before
	/// `InvoiceBuilder::build(self)` becomes available.
	pub fn new(currrency: Currency) -> Self {
		InvoiceBuilder {
			currency: currrency,
			amount: None,
			si_prefix: None,
			timestamp: None,
			tagged_fields: Vec::new(),
			error: None,

			phantom_d: core::marker::PhantomData,
			phantom_h: core::marker::PhantomData,
			phantom_t: core::marker::PhantomData,
			phantom_c: core::marker::PhantomData,
			phantom_s: core::marker::PhantomData,
		}
	}
}

impl<D: tb::Bool, H: tb::Bool, T: tb::Bool, C: tb::Bool, S: tb::Bool> InvoiceBuilder<D, H, T, C, S> {
	/// Helper function to set the completeness flags.
	fn set_flags<DN: tb::Bool, HN: tb::Bool, TN: tb::Bool, CN: tb::Bool, SN: tb::Bool>(self) -> InvoiceBuilder<DN, HN, TN, CN, SN> {
		InvoiceBuilder::<DN, HN, TN, CN, SN> {
			currency: self.currency,
			amount: self.amount,
			si_prefix: self.si_prefix,
			timestamp: self.timestamp,
			tagged_fields: self.tagged_fields,
			error: self.error,

			phantom_d: core::marker::PhantomData,
			phantom_h: core::marker::PhantomData,
			phantom_t: core::marker::PhantomData,
			phantom_c: core::marker::PhantomData,
			phantom_s: core::marker::PhantomData,
		}
	}

	/// Sets the amount in millisatoshis. The optimal SI prefix is chosen automatically.
	pub fn amount_milli_satoshis(mut self, amount_msat: u64) -> Self {
		let amount = amount_msat * 10; // Invoices are denominated in "pico BTC"
		let biggest_possible_si_prefix = SiPrefix::values_desc()
			.iter()
			.find(|prefix| amount % prefix.multiplier() == 0)
			.expect("Pico should always match");
		self.amount = Some(amount / biggest_possible_si_prefix.multiplier());
		self.si_prefix = Some(*biggest_possible_si_prefix);
		self
	}

	/// Sets the payee's public key.
	pub fn payee_pub_key(mut self, pub_key: PublicKey) -> Self {
		self.tagged_fields.push(TaggedField::PayeePubKey(PayeePubKey(pub_key)));
		self
	}

	/// Sets the expiry time, dropping the subsecond part (which is not representable in BOLT 11
	/// invoices).
	pub fn expiry_time(mut self, expiry_time: Duration) -> Self {
		self.tagged_fields.push(TaggedField::ExpiryTime(ExpiryTime::from_duration(expiry_time)));
		self
	}

	/// Adds a fallback address.
	pub fn fallback(mut self, fallback: Fallback) -> Self {
		self.tagged_fields.push(TaggedField::Fallback(fallback));
		self
	}

	/// Adds a private route.
	pub fn private_route(mut self, hint: RouteHint) -> Self {
		match PrivateRoute::new(hint) {
			Ok(r) => self.tagged_fields.push(TaggedField::PrivateRoute(r)),
			Err(e) => self.error = Some(e),
		}
		self
	}
}

impl<D: tb::Bool, H: tb::Bool, C: tb::Bool, S: tb::Bool> InvoiceBuilder<D, H, tb::True, C, S> {
	/// Builds a `RawInvoice` if no `CreationError` occurred while construction any of the fields.
	pub fn build_raw(self) -> Result<RawInvoice, CreationError> {

		// If an error occurred at any time before, return it now
		if let Some(e) = self.error {
			return Err(e);
		}

		let hrp = RawHrp {
			currency: self.currency,
			raw_amount: self.amount,
			si_prefix: self.si_prefix,
		};

		let timestamp = self.timestamp.expect("ensured to be Some(t) by type T");

		let tagged_fields = self.tagged_fields.into_iter().map(|tf| {
			RawTaggedField::KnownSemantics(tf)
		}).collect::<Vec<_>>();

		let data = RawDataPart {
			timestamp: timestamp,
			tagged_fields: tagged_fields,
		};

		Ok(RawInvoice {
			hrp: hrp,
			data: data,
		})
	}
}

impl<H: tb::Bool, T: tb::Bool, C: tb::Bool, S: tb::Bool> InvoiceBuilder<tb::False, H, T, C, S> {
	/// Set the description. This function is only available if no description (hash) was set.
	pub fn description(mut self, description: String) -> InvoiceBuilder<tb::True, H, T, C, S> {
		match Description::new(description) {
			Ok(d) => self.tagged_fields.push(TaggedField::Description(d)),
			Err(e) => self.error = Some(e),
		}
		self.set_flags()
	}

	/// Set the description hash. This function is only available if no description (hash) was set.
	pub fn description_hash(mut self, description_hash: sha256::Hash) -> InvoiceBuilder<tb::True, H, T, C, S> {
		self.tagged_fields.push(TaggedField::DescriptionHash(Sha256(description_hash)));
		self.set_flags()
	}
}

impl<D: tb::Bool, T: tb::Bool, C: tb::Bool, S: tb::Bool> InvoiceBuilder<D, tb::False, T, C, S> {
	/// Set the payment hash. This function is only available if no payment hash was set.
	pub fn payment_hash(mut self, hash: sha256::Hash) -> InvoiceBuilder<D, tb::True, T, C, S> {
		self.tagged_fields.push(TaggedField::PaymentHash(Sha256(hash)));
		self.set_flags()
	}
}

impl<D: tb::Bool, H: tb::Bool, C: tb::Bool, S: tb::Bool> InvoiceBuilder<D, H, tb::False, C, S> {
	/// Sets the timestamp to a specific [`SystemTime`].
	#[cfg(feature = "std")]
	pub fn timestamp(mut self, time: SystemTime) -> InvoiceBuilder<D, H, tb::True, C, S> {
		match PositiveTimestamp::from_system_time(time) {
			Ok(t) => self.timestamp = Some(t),
			Err(e) => self.error = Some(e),
		}

		self.set_flags()
	}

	/// Sets the timestamp to a duration since the Unix epoch, dropping the subsecond part (which
	/// is not representable in BOLT 11 invoices).
	pub fn duration_since_epoch(mut self, time: Duration) -> InvoiceBuilder<D, H, tb::True, C, S> {
		match PositiveTimestamp::from_duration_since_epoch(time) {
			Ok(t) => self.timestamp = Some(t),
			Err(e) => self.error = Some(e),
		}

		self.set_flags()
	}

	/// Sets the timestamp to the current system time.
	#[cfg(feature = "std")]
	pub fn current_timestamp(mut self) -> InvoiceBuilder<D, H, tb::True, C, S> {
		let now = PositiveTimestamp::from_system_time(SystemTime::now());
		self.timestamp = Some(now.expect("for the foreseeable future this shouldn't happen"));
		self.set_flags()
	}
}

impl<D: tb::Bool, H: tb::Bool, T: tb::Bool, S: tb::Bool> InvoiceBuilder<D, H, T, tb::False, S> {
	/// Sets `min_final_cltv_expiry_delta`.
	pub fn min_final_cltv_expiry_delta(mut self, min_final_cltv_expiry_delta: u64) -> InvoiceBuilder<D, H, T, tb::True, S> {
		self.tagged_fields.push(TaggedField::MinFinalCltvExpiryDelta(MinFinalCltvExpiryDelta(min_final_cltv_expiry_delta)));
		self.set_flags()
	}
}

impl<D: tb::Bool, H: tb::Bool, T: tb::Bool, C: tb::Bool> InvoiceBuilder<D, H, T, C, tb::False> {
	/// Sets the payment secret and relevant features.
	pub fn payment_secret(mut self, payment_secret: PaymentSecret) -> InvoiceBuilder<D, H, T, C, tb::True> {
		let mut features = InvoiceFeatures::empty();
		features.set_variable_length_onion_required();
		features.set_payment_secret_required();
		self.tagged_fields.push(TaggedField::PaymentSecret(payment_secret));
		self.tagged_fields.push(TaggedField::Features(features));
		self.set_flags()
	}
}

impl<D: tb::Bool, H: tb::Bool, T: tb::Bool, C: tb::Bool> InvoiceBuilder<D, H, T, C, tb::True> {
	/// Sets the `basic_mpp` feature as optional.
	pub fn basic_mpp(mut self) -> Self {
		for field in self.tagged_fields.iter_mut() {
			if let TaggedField::Features(f) = field {
				f.set_basic_mpp_optional();
			}
		}
		self
	}
}

impl InvoiceBuilder<tb::True, tb::True, tb::True, tb::True, tb::True> {
	/// Builds and signs an invoice using the supplied `sign_function`. This function MAY NOT fail
	/// and MUST produce a recoverable signature valid for the given hash and if applicable also for
	/// the included payee public key.
	pub fn build_signed<F>(self, sign_function: F) -> Result<Invoice, CreationError>
		where F: FnOnce(&Message) -> RecoverableSignature
	{
		let invoice = self.try_build_signed::<_, ()>(|hash| {
			Ok(sign_function(hash))
		});

		match invoice {
			Ok(i) => Ok(i),
			Err(SignOrCreationError::CreationError(e)) => Err(e),
			Err(SignOrCreationError::SignError(())) => unreachable!(),
		}
	}

	/// Builds and signs an invoice using the supplied `sign_function`. This function MAY fail with
	/// an error of type `E` and MUST produce a recoverable signature valid for the given hash and
	/// if applicable also for the included payee public key.
	pub fn try_build_signed<F, E>(self, sign_function: F) -> Result<Invoice, SignOrCreationError<E>>
		where F: FnOnce(&Message) -> Result<RecoverableSignature, E>
	{
		let raw = match self.build_raw() {
			Ok(r) => r,
			Err(e) => return Err(SignOrCreationError::CreationError(e)),
		};

		let signed = match raw.sign(sign_function) {
			Ok(s) => s,
			Err(e) => return Err(SignOrCreationError::SignError(e)),
		};

		let invoice = Invoice {
			signed_invoice: signed,
		};

		invoice.check_field_counts().expect("should be ensured by type signature of builder");
		invoice.check_feature_bits().expect("should be ensured by type signature of builder");
		invoice.check_amount().expect("should be ensured by type signature of builder");

		Ok(invoice)
	}
}


impl SignedRawInvoice {
	/// Disassembles the `SignedRawInvoice` into its three parts:
	///  1. raw invoice
	///  2. hash of the raw invoice
	///  3. signature
	pub fn into_parts(self) -> (RawInvoice, [u8; 32], InvoiceSignature) {
		(self.raw_invoice, self.hash, self.signature)
	}

	/// The `RawInvoice` which was signed.
	pub fn raw_invoice(&self) -> &RawInvoice {
		&self.raw_invoice
	}

	/// The hash of the `RawInvoice` that was signed.
	pub fn signable_hash(&self) -> &[u8; 32] {
		&self.hash
	}

	/// InvoiceSignature for the invoice.
	pub fn signature(&self) -> &InvoiceSignature {
		&self.signature
	}

	/// Recovers the public key used for signing the invoice from the recoverable signature.
	pub fn recover_payee_pub_key(&self) -> Result<PayeePubKey, secp256k1::Error> {
		let hash = Message::from_slice(&self.hash[..])
			.expect("Hash is 32 bytes long, same as MESSAGE_SIZE");

		Ok(PayeePubKey(Secp256k1::new().recover_ecdsa(
			&hash,
			&self.signature
		)?))
	}

	/// Checks if the signature is valid for the included payee public key or if none exists if it's
	/// valid for the recovered signature (which should always be true?).
	pub fn check_signature(&self) -> bool {
		let included_pub_key = self.raw_invoice.payee_pub_key();

		let mut recovered_pub_key = Option::None;
		if recovered_pub_key.is_none() {
			let recovered = match self.recover_payee_pub_key() {
				Ok(pk) => pk,
				Err(_) => return false,
			};
			recovered_pub_key = Some(recovered);
		}

		let pub_key = included_pub_key.or_else(|| recovered_pub_key.as_ref())
			.expect("One is always present");

		let hash = Message::from_slice(&self.hash[..])
			.expect("Hash is 32 bytes long, same as MESSAGE_SIZE");

		let secp_context = Secp256k1::new();
		let verification_result = secp_context.verify_ecdsa(
			&hash,
			&self.signature.to_standard(),
			pub_key
		);

		match verification_result {
			Ok(()) => true,
			Err(_) => false,
		}
	}
}

/// Finds the first element of an enum stream of a given variant and extracts one member of the
/// variant. If no element was found `None` gets returned.
///
/// The following example would extract the first B.
///
/// ```ignore
/// enum Enum {
/// 	A(u8),
/// 	B(u16)
/// }
///
/// let elements = vec![Enum::A(1), Enum::A(2), Enum::B(3), Enum::A(4)];
///
/// assert_eq!(find_extract!(elements.iter(), Enum::B(x), x), Some(3u16));
/// ```
macro_rules! find_extract {
	($iter:expr, $enm:pat, $enm_var:ident) => {
		find_all_extract!($iter, $enm, $enm_var).next()
	};
}

/// Finds the all elements of an enum stream of a given variant and extracts one member of the
/// variant through an iterator.
///
/// The following example would extract all A.
///
/// ```ignore
/// enum Enum {
/// 	A(u8),
/// 	B(u16)
/// }
///
/// let elements = vec![Enum::A(1), Enum::A(2), Enum::B(3), Enum::A(4)];
///
/// assert_eq!(
/// 	find_all_extract!(elements.iter(), Enum::A(x), x).collect::<Vec<u8>>(),
/// 	vec![1u8, 2u8, 4u8]
/// );
/// ```
macro_rules! find_all_extract {
	($iter:expr, $enm:pat, $enm_var:ident) => {
		$iter.filter_map(|tf| match *tf {
			$enm => Some($enm_var),
			_ => None,
		})
	};
}

#[allow(missing_docs)]
impl RawInvoice {
	/// Hash the HRP as bytes and signatureless data part.
	fn hash_from_parts(hrp_bytes: &[u8], data_without_signature: &[u5]) -> [u8; 32] {
		let preimage = construct_invoice_preimage(hrp_bytes, data_without_signature);
		let mut hash: [u8; 32] = Default::default();
		hash.copy_from_slice(&sha256::Hash::hash(&preimage)[..]);
		hash
	}

	/// Calculate the hash of the encoded `RawInvoice` which should be signed.
	pub fn signable_hash(&self) -> [u8; 32] {
		use bech32::ToBase32;

		RawInvoice::hash_from_parts(
			self.hrp.to_string().as_bytes(),
			&self.data.to_base32()
		)
	}

	/// Signs the invoice using the supplied `sign_function`. This function MAY fail with an error
	/// of type `E`. Since the signature of a `SignedRawInvoice` is not required to be valid there
	/// are no constraints regarding the validity of the produced signature.
	///
	/// (C-not exported) As we don't currently support passing function pointers into methods
	/// explicitly.
	pub fn sign<F, E>(self, sign_method: F) -> Result<SignedRawInvoice, E>
		where F: FnOnce(&Message) -> Result<RecoverableSignature, E>
	{
		let raw_hash = self.signable_hash();
		let hash = Message::from_slice(&raw_hash[..])
			.expect("Hash is 32 bytes long, same as MESSAGE_SIZE");
		let signature = sign_method(&hash)?;

		Ok(SignedRawInvoice {
			raw_invoice: self,
			hash: raw_hash,
			signature: InvoiceSignature(signature),
		})
	}

	/// Returns an iterator over all tagged fields with known semantics.
	///
	/// (C-not exported) As there is not yet a manual mapping for a FilterMap
	pub fn known_tagged_fields(&self)
		-> FilterMap<Iter<RawTaggedField>, fn(&RawTaggedField) -> Option<&TaggedField>>
	{
		// For 1.14.0 compatibility: closures' types can't be written an fn()->() in the
		// function's type signature.
		// TODO: refactor once impl Trait is available
		fn match_raw(raw: &RawTaggedField) -> Option<&TaggedField> {
			match *raw {
				RawTaggedField::KnownSemantics(ref tf) => Some(tf),
				_ => None,
			}
		}

		self.data.tagged_fields.iter().filter_map(match_raw )
	}

	pub fn payment_hash(&self) -> Option<&Sha256> {
		find_extract!(self.known_tagged_fields(), TaggedField::PaymentHash(ref x), x)
	}

	pub fn description(&self) -> Option<&Description> {
		find_extract!(self.known_tagged_fields(), TaggedField::Description(ref x), x)
	}

	pub fn payee_pub_key(&self) -> Option<&PayeePubKey> {
		find_extract!(self.known_tagged_fields(), TaggedField::PayeePubKey(ref x), x)
	}

	pub fn description_hash(&self) -> Option<&Sha256> {
		find_extract!(self.known_tagged_fields(), TaggedField::DescriptionHash(ref x), x)
	}

	pub fn expiry_time(&self) -> Option<&ExpiryTime> {
		find_extract!(self.known_tagged_fields(), TaggedField::ExpiryTime(ref x), x)
	}

	pub fn min_final_cltv_expiry_delta(&self) -> Option<&MinFinalCltvExpiryDelta> {
		find_extract!(self.known_tagged_fields(), TaggedField::MinFinalCltvExpiryDelta(ref x), x)
	}

	pub fn payment_secret(&self) -> Option<&PaymentSecret> {
		find_extract!(self.known_tagged_fields(), TaggedField::PaymentSecret(ref x), x)
	}

	pub fn features(&self) -> Option<&InvoiceFeatures> {
		find_extract!(self.known_tagged_fields(), TaggedField::Features(ref x), x)
	}

	/// (C-not exported) as we don't support Vec<&NonOpaqueType>
	pub fn fallbacks(&self) -> Vec<&Fallback> {
		find_all_extract!(self.known_tagged_fields(), TaggedField::Fallback(ref x), x).collect()
	}

	pub fn private_routes(&self) -> Vec<&PrivateRoute> {
		find_all_extract!(self.known_tagged_fields(), TaggedField::PrivateRoute(ref x), x).collect()
	}

	pub fn amount_pico_btc(&self) -> Option<u64> {
		self.hrp.raw_amount.map(|v| {
			v * self.hrp.si_prefix.as_ref().map_or(1_000_000_000_000, |si| { si.multiplier() })
		})
	}

	pub fn currency(&self) -> Currency {
		self.hrp.currency.clone()
	}
}

impl PositiveTimestamp {
	/// Creates a `PositiveTimestamp` from a Unix timestamp in the range `0..=MAX_TIMESTAMP`.
	///
	/// Otherwise, returns a [`CreationError::TimestampOutOfBounds`].
	pub fn from_unix_timestamp(unix_seconds: u64) -> Result<Self, CreationError> {
		if unix_seconds <= MAX_TIMESTAMP {
			Ok(Self(Duration::from_secs(unix_seconds)))
		} else {
			Err(CreationError::TimestampOutOfBounds)
		}
	}

	/// Creates a `PositiveTimestamp` from a [`SystemTime`] with a corresponding Unix timestamp in
	/// the range `0..=MAX_TIMESTAMP`.
	///
	/// Note that the subsecond part is dropped as it is not representable in BOLT 11 invoices.
	///
	/// Otherwise, returns a [`CreationError::TimestampOutOfBounds`].
	#[cfg(feature = "std")]
	pub fn from_system_time(time: SystemTime) -> Result<Self, CreationError> {
		time.duration_since(SystemTime::UNIX_EPOCH)
			.map(Self::from_duration_since_epoch)
			.unwrap_or(Err(CreationError::TimestampOutOfBounds))
	}

	/// Creates a `PositiveTimestamp` from a [`Duration`] since the Unix epoch in the range
	/// `0..=MAX_TIMESTAMP`.
	///
	/// Note that the subsecond part is dropped as it is not representable in BOLT 11 invoices.
	///
	/// Otherwise, returns a [`CreationError::TimestampOutOfBounds`].
	pub fn from_duration_since_epoch(duration: Duration) -> Result<Self, CreationError> {
		Self::from_unix_timestamp(duration.as_secs())
	}

	/// Returns the Unix timestamp representing the stored time
	pub fn as_unix_timestamp(&self) -> u64 {
		self.0.as_secs()
	}

	/// Returns the duration of the stored time since the Unix epoch
	pub fn as_duration_since_epoch(&self) -> Duration {
		self.0
	}

	/// Returns the [`SystemTime`] representing the stored time
	#[cfg(feature = "std")]
	pub fn as_time(&self) -> SystemTime {
		SystemTime::UNIX_EPOCH + self.0
	}
}

#[cfg(feature = "std")]
impl Into<SystemTime> for PositiveTimestamp {
	fn into(self) -> SystemTime {
		SystemTime::UNIX_EPOCH + self.0
	}
}

impl Invoice {
	/// Transform the `Invoice` into it's unchecked version
	pub fn into_signed_raw(self) -> SignedRawInvoice {
		self.signed_invoice
	}

	/// Check that all mandatory fields are present
	fn check_field_counts(&self) -> Result<(), SemanticError> {
		// "A writer MUST include exactly one p field […]."
		let payment_hash_cnt = self.tagged_fields().filter(|&tf| match *tf {
			TaggedField::PaymentHash(_) => true,
			_ => false,
		}).count();
		if payment_hash_cnt < 1 {
			return Err(SemanticError::NoPaymentHash);
		} else if payment_hash_cnt > 1 {
			return Err(SemanticError::MultiplePaymentHashes);
		}

		// "A writer MUST include either exactly one d or exactly one h field."
		let description_cnt = self.tagged_fields().filter(|&tf| match *tf {
			TaggedField::Description(_) | TaggedField::DescriptionHash(_) => true,
			_ => false,
		}).count();
		if  description_cnt < 1 {
			return Err(SemanticError::NoDescription);
		} else if description_cnt > 1 {
			return  Err(SemanticError::MultipleDescriptions);
		}

		self.check_payment_secret()?;

		Ok(())
	}

	/// Checks that there is exactly one payment secret field
	fn check_payment_secret(&self) -> Result<(), SemanticError> {
		// "A writer MUST include exactly one `s` field."
		let payment_secret_count = self.tagged_fields().filter(|&tf| match *tf {
			TaggedField::PaymentSecret(_) => true,
			_ => false,
		}).count();
		if payment_secret_count < 1 {
			return Err(SemanticError::NoPaymentSecret);
		} else if payment_secret_count > 1 {
			return Err(SemanticError::MultiplePaymentSecrets);
		}

		Ok(())
	}

	/// Check that amount is a whole number of millisatoshis
	fn check_amount(&self) -> Result<(), SemanticError> {
		if let Some(amount_pico_btc) = self.amount_pico_btc() {
			if amount_pico_btc % 10 != 0 {
				return Err(SemanticError::ImpreciseAmount);
			}
		}
		Ok(())
	}

	/// Check that feature bits are set as required
	fn check_feature_bits(&self) -> Result<(), SemanticError> {
		self.check_payment_secret()?;

		// "A writer MUST set an s field if and only if the payment_secret feature is set."
		// (this requirement has been since removed, and we now require the payment secret
		// feature bit always).
		let features = self.tagged_fields().find(|&tf| match *tf {
			TaggedField::Features(_) => true,
			_ => false,
		});
		match features {
			None => Err(SemanticError::InvalidFeatures),
			Some(TaggedField::Features(features)) => {
				if features.requires_unknown_bits() {
					Err(SemanticError::InvalidFeatures)
				} else if !features.supports_payment_secret() {
					Err(SemanticError::InvalidFeatures)
				} else {
					Ok(())
				}
			},
			Some(_) => unreachable!(),
		}
	}

	/// Check that the invoice is signed correctly and that key recovery works
	pub fn check_signature(&self) -> Result<(), SemanticError> {
		match self.signed_invoice.recover_payee_pub_key() {
			Err(secp256k1::Error::InvalidRecoveryId) =>
				return Err(SemanticError::InvalidRecoveryId),
			Err(secp256k1::Error::InvalidSignature) =>
				return Err(SemanticError::InvalidSignature),
			Err(e) => panic!("no other error may occur, got {:?}", e),
			Ok(_) => {},
		}

		if !self.signed_invoice.check_signature() {
			return Err(SemanticError::InvalidSignature);
		}

		Ok(())
	}

	/// Constructs an `Invoice` from a `SignedRawInvoice` by checking all its invariants.
	/// ```
	/// use lightning_invoice::*;
	///
	/// let invoice = "lnbc100p1psj9jhxdqud3jxktt5w46x7unfv9kz6mn0v3jsnp4q0d3p2sfluzdx45tqcs\
	/// h2pu5qc7lgq0xs578ngs6s0s68ua4h7cvspp5q6rmq35js88zp5dvwrv9m459tnk2zunwj5jalqtyxqulh0l\
	/// 5gflssp5nf55ny5gcrfl30xuhzj3nphgj27rstekmr9fw3ny5989s300gyus9qyysgqcqpcrzjqw2sxwe993\
	/// h5pcm4dxzpvttgza8zhkqxpgffcrf5v25nwpr3cmfg7z54kuqq8rgqqqqqqqq2qqqqq9qq9qrzjqd0ylaqcl\
	/// j9424x9m8h2vcukcgnm6s56xfgu3j78zyqzhgs4hlpzvznlugqq9vsqqqqqqqlgqqqqqeqq9qrzjqwldmj9d\
	/// ha74df76zhx6l9we0vjdquygcdt3kssupehe64g6yyp5yz5rhuqqwccqqyqqqqlgqqqqjcqq9qrzjqf9e58a\
	/// guqr0rcun0ajlvmzq3ek63cw2w282gv3z5uupmuwvgjtq2z55qsqqg6qqqyqqqrtnqqqzq3cqygrzjqvphms\
	/// ywntrrhqjcraumvc4y6r8v4z5v593trte429v4hredj7ms5z52usqq9ngqqqqqqqlgqqqqqqgq9qrzjq2v0v\
	/// p62g49p7569ev48cmulecsxe59lvaw3wlxm7r982zxa9zzj7z5l0cqqxusqqyqqqqlgqqqqqzsqygarl9fh3\
	/// 8s0gyuxjjgux34w75dnc6xp2l35j7es3jd4ugt3lu0xzre26yg5m7ke54n2d5sym4xcmxtl8238xxvw5h5h5\
	/// j5r6drg6k6zcqj0fcwg";
	///
	/// let signed = invoice.parse::<SignedRawInvoice>().unwrap();
	///
	/// assert!(Invoice::from_signed(signed).is_ok());
	/// ```
	pub fn from_signed(signed_invoice: SignedRawInvoice) -> Result<Self, SemanticError> {
		let invoice = Invoice {
			signed_invoice: signed_invoice,
		};
		invoice.check_field_counts()?;
		invoice.check_feature_bits()?;
		invoice.check_signature()?;
		invoice.check_amount()?;

		Ok(invoice)
	}

	/// Returns the `Invoice`'s timestamp (should equal its creation time)
	#[cfg(feature = "std")]
	pub fn timestamp(&self) -> SystemTime {
		self.signed_invoice.raw_invoice().data.timestamp.as_time()
	}

	/// Returns the `Invoice`'s timestamp as a duration since the Unix epoch
	pub fn duration_since_epoch(&self) -> Duration {
		self.signed_invoice.raw_invoice().data.timestamp.0
	}

	/// Returns an iterator over all tagged fields of this Invoice.
	///
	/// (C-not exported) As there is not yet a manual mapping for a FilterMap
	pub fn tagged_fields(&self)
		-> FilterMap<Iter<RawTaggedField>, fn(&RawTaggedField) -> Option<&TaggedField>> {
		self.signed_invoice.raw_invoice().known_tagged_fields()
	}

	/// Returns the hash to which we will receive the preimage on completion of the payment
	pub fn payment_hash(&self) -> &sha256::Hash {
		&self.signed_invoice.payment_hash().expect("checked by constructor").0
	}

	/// Return the description or a hash of it for longer ones
	///
	/// (C-not exported) because we don't yet export InvoiceDescription
	pub fn description(&self) -> InvoiceDescription {
		if let Some(ref direct) = self.signed_invoice.description() {
			return InvoiceDescription::Direct(direct);
		} else if let Some(ref hash) = self.signed_invoice.description_hash() {
			return InvoiceDescription::Hash(hash);
		}
		unreachable!("ensured by constructor");
	}

	/// Get the payee's public key if one was included in the invoice
	pub fn payee_pub_key(&self) -> Option<&PublicKey> {
		self.signed_invoice.payee_pub_key().map(|x| &x.0)
	}

	/// Get the payment secret if one was included in the invoice
	pub fn payment_secret(&self) -> &PaymentSecret {
		self.signed_invoice.payment_secret().expect("was checked by constructor")
	}

	/// Get the invoice features if they were included in the invoice
	pub fn features(&self) -> Option<&InvoiceFeatures> {
		self.signed_invoice.features()
	}

	/// Recover the payee's public key (only to be used if none was included in the invoice)
	pub fn recover_payee_pub_key(&self) -> PublicKey {
		self.signed_invoice.recover_payee_pub_key().expect("was checked by constructor").0
	}

	/// Returns the invoice's expiry time, if present, otherwise [`DEFAULT_EXPIRY_TIME`].
	pub fn expiry_time(&self) -> Duration {
		self.signed_invoice.expiry_time()
			.map(|x| x.0)
			.unwrap_or(Duration::from_secs(DEFAULT_EXPIRY_TIME))
	}

	/// Returns whether the invoice has expired.
	#[cfg(feature = "std")]
	pub fn is_expired(&self) -> bool {
		Self::is_expired_from_epoch(&self.timestamp(), self.expiry_time())
	}

	/// Returns whether the expiry time from the given epoch has passed.
	#[cfg(feature = "std")]
	pub(crate) fn is_expired_from_epoch(epoch: &SystemTime, expiry_time: Duration) -> bool {
		match epoch.elapsed() {
			Ok(elapsed) => elapsed > expiry_time,
			Err(_) => false,
		}
	}

	/// Returns whether the expiry time would pass at the given point in time.
	/// `at_time` is the timestamp as a duration since the Unix epoch.
	pub fn would_expire(&self, at_time: Duration) -> bool {
		self.duration_since_epoch()
			.checked_add(self.expiry_time())
			.unwrap_or_else(|| Duration::new(u64::max_value(), 1_000_000_000 - 1)) < at_time
	}

	/// Returns the invoice's `min_final_cltv_expiry_delta` time, if present, otherwise
	/// [`DEFAULT_MIN_FINAL_CLTV_EXPIRY_DELTA`].
	pub fn min_final_cltv_expiry_delta(&self) -> u64 {
		self.signed_invoice.min_final_cltv_expiry_delta()
			.map(|x| x.0)
			.unwrap_or(DEFAULT_MIN_FINAL_CLTV_EXPIRY_DELTA)
	}

	/// Returns a list of all fallback addresses
	///
	/// (C-not exported) as we don't support Vec<&NonOpaqueType>
	pub fn fallbacks(&self) -> Vec<&Fallback> {
		self.signed_invoice.fallbacks()
	}

	/// Returns a list of all routes included in the invoice
	pub fn private_routes(&self) -> Vec<&PrivateRoute> {
		self.signed_invoice.private_routes()
	}

	/// Returns a list of all routes included in the invoice as the underlying hints
	pub fn route_hints(&self) -> Vec<RouteHint> {
		find_all_extract!(
			self.signed_invoice.known_tagged_fields(), TaggedField::PrivateRoute(ref x), x
		).map(|route| (**route).clone()).collect()
	}

	/// Returns the currency for which the invoice was issued
	pub fn currency(&self) -> Currency {
		self.signed_invoice.currency()
	}

	/// Returns the amount if specified in the invoice as millisatoshis.
	pub fn amount_milli_satoshis(&self) -> Option<u64> {
		self.signed_invoice.amount_pico_btc().map(|v| v / 10)
	}

	/// Returns the amount if specified in the invoice as pico BTC.
	fn amount_pico_btc(&self) -> Option<u64> {
		self.signed_invoice.amount_pico_btc()
	}
}

impl From<TaggedField> for RawTaggedField {
	fn from(tf: TaggedField) -> Self {
		RawTaggedField::KnownSemantics(tf)
	}
}

impl TaggedField {
	/// Numeric representation of the field's tag
	pub fn tag(&self) -> u5 {
		let tag = match *self {
			TaggedField::PaymentHash(_) => constants::TAG_PAYMENT_HASH,
			TaggedField::Description(_) => constants::TAG_DESCRIPTION,
			TaggedField::PayeePubKey(_) => constants::TAG_PAYEE_PUB_KEY,
			TaggedField::DescriptionHash(_) => constants::TAG_DESCRIPTION_HASH,
			TaggedField::ExpiryTime(_) => constants::TAG_EXPIRY_TIME,
			TaggedField::MinFinalCltvExpiryDelta(_) => constants::TAG_MIN_FINAL_CLTV_EXPIRY_DELTA,
			TaggedField::Fallback(_) => constants::TAG_FALLBACK,
			TaggedField::PrivateRoute(_) => constants::TAG_PRIVATE_ROUTE,
			TaggedField::PaymentSecret(_) => constants::TAG_PAYMENT_SECRET,
			TaggedField::Features(_) => constants::TAG_FEATURES,
		};

		u5::try_from_u8(tag).expect("all tags defined are <32")
	}
}

impl Description {

	/// Creates a new `Description` if `description` is at most 1023 __bytes__ long,
	/// returns `CreationError::DescriptionTooLong` otherwise
	///
	/// Please note that single characters may use more than one byte due to UTF8 encoding.
	pub fn new(description: String) -> Result<Description, CreationError> {
		if description.len() > 639 {
			Err(CreationError::DescriptionTooLong)
		} else {
			Ok(Description(description))
		}
	}

	/// Returns the underlying description `String`
	pub fn into_inner(self) -> String {
		self.0
	}
}

impl Into<String> for Description {
	fn into(self) -> String {
		self.into_inner()
	}
}

impl Deref for Description {
	type Target = str;

	fn deref(&self) -> &str {
		&self.0
	}
}

impl From<PublicKey> for PayeePubKey {
	fn from(pk: PublicKey) -> Self {
		PayeePubKey(pk)
	}
}

impl Deref for PayeePubKey {
	type Target = PublicKey;

	fn deref(&self) -> &PublicKey {
		&self.0
	}
}

impl ExpiryTime {
	/// Construct an `ExpiryTime` from seconds.
	pub fn from_seconds(seconds: u64) -> ExpiryTime {
		ExpiryTime(Duration::from_secs(seconds))
	}

	/// Construct an `ExpiryTime` from a `Duration`, dropping the sub-second part.
	pub fn from_duration(duration: Duration) -> ExpiryTime {
		Self::from_seconds(duration.as_secs())
	}

	/// Returns the expiry time in seconds
	pub fn as_seconds(&self) -> u64 {
		self.0.as_secs()
	}

	/// Returns a reference to the underlying `Duration` (=expiry time)
	pub fn as_duration(&self) -> &Duration {
		&self.0
	}
}

impl PrivateRoute {
	/// Creates a new (partial) route from a list of hops
	pub fn new(hops: RouteHint) -> Result<PrivateRoute, CreationError> {
		if hops.0.len() <= 12 {
			Ok(PrivateRoute(hops))
		} else {
			Err(CreationError::RouteTooLong)
		}
	}

	/// Returns the underlying list of hops
	pub fn into_inner(self) -> RouteHint {
		self.0
	}
}

impl Into<RouteHint> for PrivateRoute {
	fn into(self) -> RouteHint {
		self.into_inner()
	}
}

impl Deref for PrivateRoute {
	type Target = RouteHint;

	fn deref(&self) -> &RouteHint {
		&self.0
	}
}

impl Deref for InvoiceSignature {
	type Target = RecoverableSignature;

	fn deref(&self) -> &RecoverableSignature {
		&self.0
	}
}

impl Deref for SignedRawInvoice {
	type Target = RawInvoice;

	fn deref(&self) -> &RawInvoice {
		&self.raw_invoice
	}
}

/// Errors that may occur when constructing a new `RawInvoice` or `Invoice`
#[derive(Eq, PartialEq, Debug, Clone)]
pub enum CreationError {
	/// The supplied description string was longer than 639 __bytes__ (see [`Description::new(…)`](./struct.Description.html#method.new))
	DescriptionTooLong,

	/// The specified route has too many hops and can't be encoded
	RouteTooLong,

	/// The Unix timestamp of the supplied date is less than zero or greater than 35-bits
	TimestampOutOfBounds,

	/// The supplied millisatoshi amount was greater than the total bitcoin supply.
	InvalidAmount,

	/// Route hints were required for this invoice and were missing. Applies to
	/// [phantom invoices].
	///
	/// [phantom invoices]: crate::utils::create_phantom_invoice
	MissingRouteHints,

	/// The provided `min_final_cltv_expiry_delta` was less than [`MIN_FINAL_CLTV_EXPIRY_DELTA`].
	///
	/// [`MIN_FINAL_CLTV_EXPIRY_DELTA`]: lightning::ln::channelmanager::MIN_FINAL_CLTV_EXPIRY_DELTA
	MinFinalCltvExpiryDeltaTooShort,
}

impl Display for CreationError {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		match self {
			CreationError::DescriptionTooLong => f.write_str("The supplied description string was longer than 639 bytes"),
			CreationError::RouteTooLong => f.write_str("The specified route has too many hops and can't be encoded"),
			CreationError::TimestampOutOfBounds => f.write_str("The Unix timestamp of the supplied date is less than zero or greater than 35-bits"),
			CreationError::InvalidAmount => f.write_str("The supplied millisatoshi amount was greater than the total bitcoin supply"),
			CreationError::MissingRouteHints => f.write_str("The invoice required route hints and they weren't provided"),
			CreationError::MinFinalCltvExpiryDeltaTooShort => f.write_str(
				"The supplied final CLTV expiry delta was less than LDK's `MIN_FINAL_CLTV_EXPIRY_DELTA`"),
		}
	}
}

#[cfg(feature = "std")]
impl std::error::Error for CreationError { }

/// Errors that may occur when converting a `RawInvoice` to an `Invoice`. They relate to the
/// requirements sections in BOLT #11
#[derive(Eq, PartialEq, Debug, Clone)]
pub enum SemanticError {
	/// The invoice is missing the mandatory payment hash
	NoPaymentHash,

	/// The invoice has multiple payment hashes which isn't allowed
	MultiplePaymentHashes,

	/// No description or description hash are part of the invoice
	NoDescription,

	/// The invoice contains multiple descriptions and/or description hashes which isn't allowed
	MultipleDescriptions,

	/// The invoice is missing the mandatory payment secret, which all modern lightning nodes
	/// should provide.
	NoPaymentSecret,

	/// The invoice contains multiple payment secrets
	MultiplePaymentSecrets,

	/// The invoice's features are invalid
	InvalidFeatures,

	/// The recovery id doesn't fit the signature/pub key
	InvalidRecoveryId,

	/// The invoice's signature is invalid
	InvalidSignature,

	/// The invoice's amount was not a whole number of millisatoshis
	ImpreciseAmount,
}

impl Display for SemanticError {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		match self {
			SemanticError::NoPaymentHash => f.write_str("The invoice is missing the mandatory payment hash"),
			SemanticError::MultiplePaymentHashes => f.write_str("The invoice has multiple payment hashes which isn't allowed"),
			SemanticError::NoDescription => f.write_str("No description or description hash are part of the invoice"),
			SemanticError::MultipleDescriptions => f.write_str("The invoice contains multiple descriptions and/or description hashes which isn't allowed"),
			SemanticError::NoPaymentSecret => f.write_str("The invoice is missing the mandatory payment secret"),
			SemanticError::MultiplePaymentSecrets => f.write_str("The invoice contains multiple payment secrets"),
			SemanticError::InvalidFeatures => f.write_str("The invoice's features are invalid"),
			SemanticError::InvalidRecoveryId => f.write_str("The recovery id doesn't fit the signature/pub key"),
			SemanticError::InvalidSignature => f.write_str("The invoice's signature is invalid"),
			SemanticError::ImpreciseAmount => f.write_str("The invoice's amount was not a whole number of millisatoshis"),
		}
	}
}

#[cfg(feature = "std")]
impl std::error::Error for SemanticError { }

/// When signing using a fallible method either an user-supplied `SignError` or a `CreationError`
/// may occur.
#[derive(Eq, PartialEq, Debug, Clone)]
pub enum SignOrCreationError<S = ()> {
	/// An error occurred during signing
	SignError(S),

	/// An error occurred while building the transaction
	CreationError(CreationError),
}

impl<S> Display for SignOrCreationError<S> {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		match self {
			SignOrCreationError::SignError(_) => f.write_str("An error occurred during signing"),
			SignOrCreationError::CreationError(err) => err.fmt(f),
		}
	}
}

#[cfg(feature = "serde")]
impl Serialize for Invoice {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
		serializer.serialize_str(self.to_string().as_str())
	}
}
#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for Invoice {
	fn deserialize<D>(deserializer: D) -> Result<Invoice, D::Error> where D: Deserializer<'de> {
		let bolt11 = String::deserialize(deserializer)?
			.parse::<Invoice>()
			.map_err(|e| D::Error::custom(format!("{:?}", e)))?;

		Ok(bolt11)
	}
}

#[cfg(test)]
mod test {
	use bitcoin_hashes::hex::FromHex;
	use bitcoin_hashes::sha256;

	#[test]
	fn test_system_time_bounds_assumptions() {
		assert_eq!(
			crate::PositiveTimestamp::from_unix_timestamp(crate::MAX_TIMESTAMP + 1),
			Err(crate::CreationError::TimestampOutOfBounds)
		);
	}

	#[test]
	fn test_calc_invoice_hash() {
		use crate::{RawInvoice, RawHrp, RawDataPart, Currency, PositiveTimestamp};
		use crate::TaggedField::*;

		let invoice = RawInvoice {
			hrp: RawHrp {
				currency: Currency::Bitcoin,
				raw_amount: None,
				si_prefix: None,
			},
			data: RawDataPart {
				timestamp: PositiveTimestamp::from_unix_timestamp(1496314658).unwrap(),
				tagged_fields: vec![
					PaymentHash(crate::Sha256(sha256::Hash::from_hex(
						"0001020304050607080900010203040506070809000102030405060708090102"
					).unwrap())).into(),
					Description(crate::Description::new(
						"Please consider supporting this project".to_owned()
					).unwrap()).into(),
				],
			},
		};

		let expected_hash = [
			0xc3, 0xd4, 0xe8, 0x3f, 0x64, 0x6f, 0xa7, 0x9a, 0x39, 0x3d, 0x75, 0x27, 0x7b, 0x1d,
			0x85, 0x8d, 0xb1, 0xd1, 0xf7, 0xab, 0x71, 0x37, 0xdc, 0xb7, 0x83, 0x5d, 0xb2, 0xec,
			0xd5, 0x18, 0xe1, 0xc9
		];

		assert_eq!(invoice.signable_hash(), expected_hash)
	}

	#[test]
	fn test_check_signature() {
		use crate::TaggedField::*;
		use secp256k1::Secp256k1;
		use secp256k1::ecdsa::{RecoveryId, RecoverableSignature};
		use secp256k1::{SecretKey, PublicKey};
		use crate::{SignedRawInvoice, InvoiceSignature, RawInvoice, RawHrp, RawDataPart, Currency, Sha256,
			 PositiveTimestamp};

		let invoice = SignedRawInvoice {
			raw_invoice: RawInvoice {
				hrp: RawHrp {
					currency: Currency::Bitcoin,
					raw_amount: None,
					si_prefix: None,
				},
				data: RawDataPart {
					timestamp: PositiveTimestamp::from_unix_timestamp(1496314658).unwrap(),
					tagged_fields: vec ! [
						PaymentHash(Sha256(sha256::Hash::from_hex(
							"0001020304050607080900010203040506070809000102030405060708090102"
						).unwrap())).into(),
						Description(
							crate::Description::new(
								"Please consider supporting this project".to_owned()
							).unwrap()
						).into(),
					],
				},
			},
			hash: [
				0xc3, 0xd4, 0xe8, 0x3f, 0x64, 0x6f, 0xa7, 0x9a, 0x39, 0x3d, 0x75, 0x27,
				0x7b, 0x1d, 0x85, 0x8d, 0xb1, 0xd1, 0xf7, 0xab, 0x71, 0x37, 0xdc, 0xb7,
				0x83, 0x5d, 0xb2, 0xec, 0xd5, 0x18, 0xe1, 0xc9
			],
			signature: InvoiceSignature(RecoverableSignature::from_compact(
				& [
					0x38u8, 0xec, 0x68, 0x91, 0x34, 0x5e, 0x20, 0x41, 0x45, 0xbe, 0x8a,
					0x3a, 0x99, 0xde, 0x38, 0xe9, 0x8a, 0x39, 0xd6, 0xa5, 0x69, 0x43,
					0x4e, 0x18, 0x45, 0xc8, 0xaf, 0x72, 0x05, 0xaf, 0xcf, 0xcc, 0x7f,
					0x42, 0x5f, 0xcd, 0x14, 0x63, 0xe9, 0x3c, 0x32, 0x88, 0x1e, 0xad,
					0x0d, 0x6e, 0x35, 0x6d, 0x46, 0x7e, 0xc8, 0xc0, 0x25, 0x53, 0xf9,
					0xaa, 0xb1, 0x5e, 0x57, 0x38, 0xb1, 0x1f, 0x12, 0x7f
				],
				RecoveryId::from_i32(0).unwrap()
			).unwrap()),
		};

		assert!(invoice.check_signature());

		let private_key = SecretKey::from_slice(
			&[
				0xe1, 0x26, 0xf6, 0x8f, 0x7e, 0xaf, 0xcc, 0x8b, 0x74, 0xf5, 0x4d, 0x26, 0x9f, 0xe2,
				0x06, 0xbe, 0x71, 0x50, 0x00, 0xf9, 0x4d, 0xac, 0x06, 0x7d, 0x1c, 0x04, 0xa8, 0xca,
				0x3b, 0x2d, 0xb7, 0x34
			][..]
		).unwrap();
		let public_key = PublicKey::from_secret_key(&Secp256k1::new(), &private_key);

		assert_eq!(invoice.recover_payee_pub_key(), Ok(crate::PayeePubKey(public_key)));

		let (raw_invoice, _, _) = invoice.into_parts();
		let new_signed = raw_invoice.sign::<_, ()>(|hash| {
			Ok(Secp256k1::new().sign_ecdsa_recoverable(hash, &private_key))
		}).unwrap();

		assert!(new_signed.check_signature());
	}

	#[test]
	fn test_check_feature_bits() {
		use crate::TaggedField::*;
		use lightning::ln::features::InvoiceFeatures;
		use secp256k1::Secp256k1;
		use secp256k1::SecretKey;
		use crate::{RawInvoice, RawHrp, RawDataPart, Currency, Sha256, PositiveTimestamp, Invoice,
			 SemanticError};

		let private_key = SecretKey::from_slice(&[42; 32]).unwrap();
		let payment_secret = lightning::ln::PaymentSecret([21; 32]);
		let invoice_template = RawInvoice {
			hrp: RawHrp {
				currency: Currency::Bitcoin,
				raw_amount: None,
				si_prefix: None,
			},
			data: RawDataPart {
				timestamp: PositiveTimestamp::from_unix_timestamp(1496314658).unwrap(),
				tagged_fields: vec ! [
					PaymentHash(Sha256(sha256::Hash::from_hex(
						"0001020304050607080900010203040506070809000102030405060708090102"
					).unwrap())).into(),
					Description(
						crate::Description::new(
							"Please consider supporting this project".to_owned()
						).unwrap()
					).into(),
				],
			},
		};

		// Missing features
		let invoice = {
			let mut invoice = invoice_template.clone();
			invoice.data.tagged_fields.push(PaymentSecret(payment_secret).into());
			invoice.sign::<_, ()>(|hash| Ok(Secp256k1::new().sign_ecdsa_recoverable(hash, &private_key)))
		}.unwrap();
		assert_eq!(Invoice::from_signed(invoice), Err(SemanticError::InvalidFeatures));

		// Missing feature bits
		let invoice = {
			let mut invoice = invoice_template.clone();
			invoice.data.tagged_fields.push(PaymentSecret(payment_secret).into());
			invoice.data.tagged_fields.push(Features(InvoiceFeatures::empty()).into());
			invoice.sign::<_, ()>(|hash| Ok(Secp256k1::new().sign_ecdsa_recoverable(hash, &private_key)))
		}.unwrap();
		assert_eq!(Invoice::from_signed(invoice), Err(SemanticError::InvalidFeatures));

		let mut payment_secret_features = InvoiceFeatures::empty();
		payment_secret_features.set_payment_secret_required();

		// Including payment secret and feature bits
		let invoice = {
			let mut invoice = invoice_template.clone();
			invoice.data.tagged_fields.push(PaymentSecret(payment_secret).into());
			invoice.data.tagged_fields.push(Features(payment_secret_features.clone()).into());
			invoice.sign::<_, ()>(|hash| Ok(Secp256k1::new().sign_ecdsa_recoverable(hash, &private_key)))
		}.unwrap();
		assert!(Invoice::from_signed(invoice).is_ok());

		// No payment secret or features
		let invoice = {
			let invoice = invoice_template.clone();
			invoice.sign::<_, ()>(|hash| Ok(Secp256k1::new().sign_ecdsa_recoverable(hash, &private_key)))
		}.unwrap();
		assert_eq!(Invoice::from_signed(invoice), Err(SemanticError::NoPaymentSecret));

		// No payment secret or feature bits
		let invoice = {
			let mut invoice = invoice_template.clone();
			invoice.data.tagged_fields.push(Features(InvoiceFeatures::empty()).into());
			invoice.sign::<_, ()>(|hash| Ok(Secp256k1::new().sign_ecdsa_recoverable(hash, &private_key)))
		}.unwrap();
		assert_eq!(Invoice::from_signed(invoice), Err(SemanticError::NoPaymentSecret));

		// Missing payment secret
		let invoice = {
			let mut invoice = invoice_template.clone();
			invoice.data.tagged_fields.push(Features(payment_secret_features).into());
			invoice.sign::<_, ()>(|hash| Ok(Secp256k1::new().sign_ecdsa_recoverable(hash, &private_key)))
		}.unwrap();
		assert_eq!(Invoice::from_signed(invoice), Err(SemanticError::NoPaymentSecret));

		// Multiple payment secrets
		let invoice = {
			let mut invoice = invoice_template.clone();
			invoice.data.tagged_fields.push(PaymentSecret(payment_secret).into());
			invoice.data.tagged_fields.push(PaymentSecret(payment_secret).into());
			invoice.sign::<_, ()>(|hash| Ok(Secp256k1::new().sign_ecdsa_recoverable(hash, &private_key)))
		}.unwrap();
		assert_eq!(Invoice::from_signed(invoice), Err(SemanticError::MultiplePaymentSecrets));
	}

	#[test]
	fn test_builder_amount() {
		use crate::*;

		let builder = InvoiceBuilder::new(Currency::Bitcoin)
			.description("Test".into())
			.payment_hash(sha256::Hash::from_slice(&[0;32][..]).unwrap())
			.duration_since_epoch(Duration::from_secs(1234567));

		let invoice = builder.clone()
			.amount_milli_satoshis(1500)
			.build_raw()
			.unwrap();

		assert_eq!(invoice.hrp.si_prefix, Some(SiPrefix::Nano));
		assert_eq!(invoice.hrp.raw_amount, Some(15));


		let invoice = builder.clone()
			.amount_milli_satoshis(150)
			.build_raw()
			.unwrap();

		assert_eq!(invoice.hrp.si_prefix, Some(SiPrefix::Pico));
		assert_eq!(invoice.hrp.raw_amount, Some(1500));
	}

	#[test]
	fn test_builder_fail() {
		use crate::*;
		use lightning::routing::router::RouteHintHop;
		use std::iter::FromIterator;
		use secp256k1::PublicKey;

		let builder = InvoiceBuilder::new(Currency::Bitcoin)
			.payment_hash(sha256::Hash::from_slice(&[0;32][..]).unwrap())
			.duration_since_epoch(Duration::from_secs(1234567))
			.min_final_cltv_expiry_delta(144);

		let too_long_string = String::from_iter(
			(0..1024).map(|_| '?')
		);

		let long_desc_res = builder.clone()
			.description(too_long_string)
			.build_raw();
		assert_eq!(long_desc_res, Err(CreationError::DescriptionTooLong));

		let route_hop = RouteHintHop {
			src_node_id: PublicKey::from_slice(
					&[
						0x03, 0x9e, 0x03, 0xa9, 0x01, 0xb8, 0x55, 0x34, 0xff, 0x1e, 0x92, 0xc4,
						0x3c, 0x74, 0x43, 0x1f, 0x7c, 0xe7, 0x20, 0x46, 0x06, 0x0f, 0xcf, 0x7a,
						0x95, 0xc3, 0x7e, 0x14, 0x8f, 0x78, 0xc7, 0x72, 0x55
					][..]
				).unwrap(),
			short_channel_id: 0,
			fees: RoutingFees {
				base_msat: 0,
				proportional_millionths: 0,
			},
			cltv_expiry_delta: 0,
			htlc_minimum_msat: None,
			htlc_maximum_msat: None,
		};
		let too_long_route = RouteHint(vec![route_hop; 13]);
		let long_route_res = builder.clone()
			.description("Test".into())
			.private_route(too_long_route)
			.build_raw();
		assert_eq!(long_route_res, Err(CreationError::RouteTooLong));

		let sign_error_res = builder.clone()
			.description("Test".into())
			.payment_secret(PaymentSecret([0; 32]))
			.try_build_signed(|_| {
				Err("ImaginaryError")
			});
		assert_eq!(sign_error_res, Err(SignOrCreationError::SignError("ImaginaryError")));
	}

	#[test]
	fn test_builder_ok() {
		use crate::*;
		use lightning::routing::router::RouteHintHop;
		use secp256k1::Secp256k1;
		use secp256k1::{SecretKey, PublicKey};
		use std::time::{UNIX_EPOCH, Duration};

		let secp_ctx = Secp256k1::new();

		let private_key = SecretKey::from_slice(
			&[
				0xe1, 0x26, 0xf6, 0x8f, 0x7e, 0xaf, 0xcc, 0x8b, 0x74, 0xf5, 0x4d, 0x26, 0x9f, 0xe2,
				0x06, 0xbe, 0x71, 0x50, 0x00, 0xf9, 0x4d, 0xac, 0x06, 0x7d, 0x1c, 0x04, 0xa8, 0xca,
				0x3b, 0x2d, 0xb7, 0x34
			][..]
		).unwrap();
		let public_key = PublicKey::from_secret_key(&secp_ctx, &private_key);

		let route_1 = RouteHint(vec![
			RouteHintHop {
				src_node_id: public_key.clone(),
				short_channel_id: de::parse_int_be(&[123; 8], 256).expect("short chan ID slice too big?"),
				fees: RoutingFees {
					base_msat: 2,
					proportional_millionths: 1,
				},
				cltv_expiry_delta: 145,
				htlc_minimum_msat: None,
				htlc_maximum_msat: None,
			},
			RouteHintHop {
				src_node_id: public_key.clone(),
				short_channel_id: de::parse_int_be(&[42; 8], 256).expect("short chan ID slice too big?"),
				fees: RoutingFees {
					base_msat: 3,
					proportional_millionths: 2,
				},
				cltv_expiry_delta: 146,
				htlc_minimum_msat: None,
				htlc_maximum_msat: None,
			}
		]);

		let route_2 = RouteHint(vec![
			RouteHintHop {
				src_node_id: public_key.clone(),
				short_channel_id: 0,
				fees: RoutingFees {
					base_msat: 4,
					proportional_millionths: 3,
				},
				cltv_expiry_delta: 147,
				htlc_minimum_msat: None,
				htlc_maximum_msat: None,
			},
			RouteHintHop {
				src_node_id: public_key.clone(),
				short_channel_id: de::parse_int_be(&[1; 8], 256).expect("short chan ID slice too big?"),
				fees: RoutingFees {
					base_msat: 5,
					proportional_millionths: 4,
				},
				cltv_expiry_delta: 148,
				htlc_minimum_msat: None,
				htlc_maximum_msat: None,
			}
		]);

		let builder = InvoiceBuilder::new(Currency::BitcoinTestnet)
			.amount_milli_satoshis(123)
			.duration_since_epoch(Duration::from_secs(1234567))
			.payee_pub_key(public_key.clone())
			.expiry_time(Duration::from_secs(54321))
			.min_final_cltv_expiry_delta(144)
			.fallback(Fallback::PubKeyHash([0;20]))
			.private_route(route_1.clone())
			.private_route(route_2.clone())
			.description_hash(sha256::Hash::from_slice(&[3;32][..]).unwrap())
			.payment_hash(sha256::Hash::from_slice(&[21;32][..]).unwrap())
			.payment_secret(PaymentSecret([42; 32]))
			.basic_mpp();

		let invoice = builder.clone().build_signed(|hash| {
			secp_ctx.sign_ecdsa_recoverable(hash, &private_key)
		}).unwrap();

		assert!(invoice.check_signature().is_ok());
		assert_eq!(invoice.tagged_fields().count(), 10);

		assert_eq!(invoice.amount_milli_satoshis(), Some(123));
		assert_eq!(invoice.amount_pico_btc(), Some(1230));
		assert_eq!(invoice.currency(), Currency::BitcoinTestnet);
		#[cfg(feature = "std")]
		assert_eq!(
			invoice.timestamp().duration_since(UNIX_EPOCH).unwrap().as_secs(),
			1234567
		);
		assert_eq!(invoice.payee_pub_key(), Some(&public_key));
		assert_eq!(invoice.expiry_time(), Duration::from_secs(54321));
		assert_eq!(invoice.min_final_cltv_expiry_delta(), 144);
		assert_eq!(invoice.fallbacks(), vec![&Fallback::PubKeyHash([0;20])]);
		assert_eq!(invoice.private_routes(), vec![&PrivateRoute(route_1), &PrivateRoute(route_2)]);
		assert_eq!(
			invoice.description(),
			InvoiceDescription::Hash(&Sha256(sha256::Hash::from_slice(&[3;32][..]).unwrap()))
		);
		assert_eq!(invoice.payment_hash(), &sha256::Hash::from_slice(&[21;32][..]).unwrap());
		assert_eq!(invoice.payment_secret(), &PaymentSecret([42; 32]));

		let mut expected_features = InvoiceFeatures::empty();
		expected_features.set_variable_length_onion_required();
		expected_features.set_payment_secret_required();
		expected_features.set_basic_mpp_optional();
		assert_eq!(invoice.features(), Some(&expected_features));

		let raw_invoice = builder.build_raw().unwrap();
		assert_eq!(raw_invoice, *invoice.into_signed_raw().raw_invoice())
	}

	#[test]
	fn test_default_values() {
		use crate::*;
		use secp256k1::Secp256k1;
		use secp256k1::SecretKey;

		let signed_invoice = InvoiceBuilder::new(Currency::Bitcoin)
			.description("Test".into())
			.payment_hash(sha256::Hash::from_slice(&[0;32][..]).unwrap())
			.payment_secret(PaymentSecret([0; 32]))
			.duration_since_epoch(Duration::from_secs(1234567))
			.build_raw()
			.unwrap()
			.sign::<_, ()>(|hash| {
				let privkey = SecretKey::from_slice(&[41; 32]).unwrap();
				let secp_ctx = Secp256k1::new();
				Ok(secp_ctx.sign_ecdsa_recoverable(hash, &privkey))
			})
			.unwrap();
		let invoice = Invoice::from_signed(signed_invoice).unwrap();

		assert_eq!(invoice.min_final_cltv_expiry_delta(), DEFAULT_MIN_FINAL_CLTV_EXPIRY_DELTA);
		assert_eq!(invoice.expiry_time(), Duration::from_secs(DEFAULT_EXPIRY_TIME));
		assert!(!invoice.would_expire(Duration::from_secs(1234568)));
	}

	#[test]
	fn test_expiration() {
		use crate::*;
		use secp256k1::Secp256k1;
		use secp256k1::SecretKey;

		let signed_invoice = InvoiceBuilder::new(Currency::Bitcoin)
			.description("Test".into())
			.payment_hash(sha256::Hash::from_slice(&[0;32][..]).unwrap())
			.payment_secret(PaymentSecret([0; 32]))
			.duration_since_epoch(Duration::from_secs(1234567))
			.build_raw()
			.unwrap()
			.sign::<_, ()>(|hash| {
				let privkey = SecretKey::from_slice(&[41; 32]).unwrap();
				let secp_ctx = Secp256k1::new();
				Ok(secp_ctx.sign_ecdsa_recoverable(hash, &privkey))
			})
			.unwrap();
		let invoice = Invoice::from_signed(signed_invoice).unwrap();

		assert!(invoice.would_expire(Duration::from_secs(1234567 + DEFAULT_EXPIRY_TIME + 1)));
	}

	#[cfg(feature = "serde")]
	#[test]
	fn test_serde() {
		let invoice_str = "lnbc100p1psj9jhxdqud3jxktt5w46x7unfv9kz6mn0v3jsnp4q0d3p2sfluzdx45tqcs\
			h2pu5qc7lgq0xs578ngs6s0s68ua4h7cvspp5q6rmq35js88zp5dvwrv9m459tnk2zunwj5jalqtyxqulh0l\
			5gflssp5nf55ny5gcrfl30xuhzj3nphgj27rstekmr9fw3ny5989s300gyus9qyysgqcqpcrzjqw2sxwe993\
			h5pcm4dxzpvttgza8zhkqxpgffcrf5v25nwpr3cmfg7z54kuqq8rgqqqqqqqq2qqqqq9qq9qrzjqd0ylaqcl\
			j9424x9m8h2vcukcgnm6s56xfgu3j78zyqzhgs4hlpzvznlugqq9vsqqqqqqqlgqqqqqeqq9qrzjqwldmj9d\
			ha74df76zhx6l9we0vjdquygcdt3kssupehe64g6yyp5yz5rhuqqwccqqyqqqqlgqqqqjcqq9qrzjqf9e58a\
			guqr0rcun0ajlvmzq3ek63cw2w282gv3z5uupmuwvgjtq2z55qsqqg6qqqyqqqrtnqqqzq3cqygrzjqvphms\
			ywntrrhqjcraumvc4y6r8v4z5v593trte429v4hredj7ms5z52usqq9ngqqqqqqqlgqqqqqqgq9qrzjq2v0v\
			p62g49p7569ev48cmulecsxe59lvaw3wlxm7r982zxa9zzj7z5l0cqqxusqqyqqqqlgqqqqqzsqygarl9fh3\
			8s0gyuxjjgux34w75dnc6xp2l35j7es3jd4ugt3lu0xzre26yg5m7ke54n2d5sym4xcmxtl8238xxvw5h5h5\
			j5r6drg6k6zcqj0fcwg";
		let invoice = invoice_str.parse::<super::Invoice>().unwrap();
		let serialized_invoice = serde_json::to_string(&invoice).unwrap();
		let deserialized_invoice: super::Invoice = serde_json::from_str(serialized_invoice.as_str()).unwrap();
		assert_eq!(invoice, deserialized_invoice);
		assert_eq!(invoice_str, deserialized_invoice.to_string().as_str());
		assert_eq!(invoice_str, serialized_invoice.as_str().trim_matches('\"'));
	}
}
