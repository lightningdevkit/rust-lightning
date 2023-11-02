// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Utilities to generate inbound payment information in service of invoice creation.

use alloc::string::ToString;
use bitcoin::hashes::{Hash, HashEngine};
use bitcoin::hashes::cmp::fixed_time_eq;
use bitcoin::hashes::hmac::{Hmac, HmacEngine};
use bitcoin::hashes::sha256::Hash as Sha256;
use crate::sign::{KeyMaterial, EntropySource};
use crate::ln::{PaymentHash, PaymentPreimage, PaymentSecret};
use crate::ln::msgs;
use crate::ln::msgs::MAX_VALUE_MSAT;
use crate::util::chacha20::ChaCha20;
use crate::util::crypto::hkdf_extract_expand_5x;
use crate::util::errors::APIError;
use crate::util::logger::Logger;

use core::convert::{TryFrom, TryInto};
use core::ops::Deref;

pub(crate) const IV_LEN: usize = 16;
const METADATA_LEN: usize = 16;
const METADATA_KEY_LEN: usize = 32;
const AMT_MSAT_LEN: usize = 8;
// Used to shift the payment type bits to take up the top 3 bits of the metadata bytes, or to
// retrieve said payment type bits.
const METHOD_TYPE_OFFSET: usize = 5;

/// A set of keys that were HKDF-expanded from an initial call to
/// [`NodeSigner::get_inbound_payment_key_material`].
///
/// [`NodeSigner::get_inbound_payment_key_material`]: crate::sign::NodeSigner::get_inbound_payment_key_material
pub struct ExpandedKey {
	/// The key used to encrypt the bytes containing the payment metadata (i.e. the amount and
	/// expiry, included for payment verification on decryption).
	metadata_key: [u8; 32],
	/// The key used to authenticate an LDK-provided payment hash and metadata as previously
	/// registered with LDK.
	ldk_pmt_hash_key: [u8; 32],
	/// The key used to authenticate a user-provided payment hash and metadata as previously
	/// registered with LDK.
	user_pmt_hash_key: [u8; 32],
	/// The base key used to derive signing keys and authenticate messages for BOLT 12 Offers.
	offers_base_key: [u8; 32],
	/// The key used to encrypt message metadata for BOLT 12 Offers.
	offers_encryption_key: [u8; 32],
}

impl ExpandedKey {
	/// Create a  new [`ExpandedKey`] for generating an inbound payment hash and secret.
	///
	/// It is recommended to cache this value and not regenerate it for each new inbound payment.
	pub fn new(key_material: &KeyMaterial) -> ExpandedKey {
		let (
			metadata_key,
			ldk_pmt_hash_key,
			user_pmt_hash_key,
			offers_base_key,
			offers_encryption_key,
		) = hkdf_extract_expand_5x(b"LDK Inbound Payment Key Expansion", &key_material.0);
		Self {
			metadata_key,
			ldk_pmt_hash_key,
			user_pmt_hash_key,
			offers_base_key,
			offers_encryption_key,
		}
	}

	/// Returns an [`HmacEngine`] used to construct [`Offer::metadata`].
	///
	/// [`Offer::metadata`]: crate::offers::offer::Offer::metadata
	pub(crate) fn hmac_for_offer(
		&self, nonce: Nonce, iv_bytes: &[u8; IV_LEN]
	) -> HmacEngine<Sha256> {
		let mut hmac = HmacEngine::<Sha256>::new(&self.offers_base_key);
		hmac.input(iv_bytes);
		hmac.input(&nonce.0);
		hmac
	}

	/// Encrypts or decrypts the given `bytes`. Used for data included in an offer message's
	/// metadata (e.g., payment id).
	pub(crate) fn crypt_for_offer(&self, mut bytes: [u8; 32], nonce: Nonce) -> [u8; 32] {
		ChaCha20::encrypt_single_block_in_place(&self.offers_encryption_key, &nonce.0, &mut bytes);
		bytes
	}
}

/// A 128-bit number used only once.
///
/// Needed when constructing [`Offer::metadata`] and deriving [`Offer::signing_pubkey`] from
/// [`ExpandedKey`]. Must not be reused for any other derivation without first hashing.
///
/// [`Offer::metadata`]: crate::offers::offer::Offer::metadata
/// [`Offer::signing_pubkey`]: crate::offers::offer::Offer::signing_pubkey
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct Nonce(pub(crate) [u8; Self::LENGTH]);

impl Nonce {
	/// Number of bytes in the nonce.
	pub const LENGTH: usize = 16;

	/// Creates a `Nonce` from the given [`EntropySource`].
	pub fn from_entropy_source<ES: Deref>(entropy_source: ES) -> Self
	where
		ES::Target: EntropySource,
	{
		let mut bytes = [0u8; Self::LENGTH];
		let rand_bytes = entropy_source.get_secure_random_bytes();
		bytes.copy_from_slice(&rand_bytes[..Self::LENGTH]);

		Nonce(bytes)
	}

	/// Returns a slice of the underlying bytes of size [`Nonce::LENGTH`].
	pub fn as_slice(&self) -> &[u8] {
		&self.0
	}
}

impl TryFrom<&[u8]> for Nonce {
	type Error = ();

	fn try_from(bytes: &[u8]) -> Result<Self, ()> {
		if bytes.len() != Self::LENGTH {
			return Err(());
		}

		let mut copied_bytes = [0u8; Self::LENGTH];
		copied_bytes.copy_from_slice(bytes);

		Ok(Self(copied_bytes))
	}
}

enum Method {
	LdkPaymentHash = 0,
	UserPaymentHash = 1,
	LdkPaymentHashCustomFinalCltv = 2,
	UserPaymentHashCustomFinalCltv = 3,
}

impl Method {
	fn from_bits(bits: u8) -> Result<Method, u8> {
		match bits {
			bits if bits == Method::LdkPaymentHash as u8 => Ok(Method::LdkPaymentHash),
			bits if bits == Method::UserPaymentHash as u8 => Ok(Method::UserPaymentHash),
			bits if bits == Method::LdkPaymentHashCustomFinalCltv as u8 => Ok(Method::LdkPaymentHashCustomFinalCltv),
			bits if bits == Method::UserPaymentHashCustomFinalCltv as u8 => Ok(Method::UserPaymentHashCustomFinalCltv),
			unknown => Err(unknown),
		}
	}
}

fn min_final_cltv_expiry_delta_from_metadata(bytes: [u8; METADATA_LEN]) -> u16 {
	let expiry_bytes = &bytes[AMT_MSAT_LEN..];
	u16::from_be_bytes([expiry_bytes[0], expiry_bytes[1]])
}

/// Equivalent to [`crate::ln::channelmanager::ChannelManager::create_inbound_payment`], but no
/// `ChannelManager` is required. Useful for generating invoices for [phantom node payments] without
/// a `ChannelManager`.
///
/// `keys` is generated by calling [`NodeSigner::get_inbound_payment_key_material`] and then
/// calling [`ExpandedKey::new`] with its result. It is recommended to cache this value and not
/// regenerate it for each new inbound payment.
///
/// `current_time` is a Unix timestamp representing the current time.
///
/// Note that if `min_final_cltv_expiry_delta` is set to some value, then the payment will not be receivable
/// on versions of LDK prior to 0.0.114.
///
/// [phantom node payments]: crate::sign::PhantomKeysManager
/// [`NodeSigner::get_inbound_payment_key_material`]: crate::sign::NodeSigner::get_inbound_payment_key_material
pub fn create<ES: Deref>(keys: &ExpandedKey, min_value_msat: Option<u64>,
	invoice_expiry_delta_secs: u32, entropy_source: &ES, current_time: u64,
	min_final_cltv_expiry_delta: Option<u16>) -> Result<(PaymentHash, PaymentSecret), ()>
	where ES::Target: EntropySource
{
	let metadata_bytes = construct_metadata_bytes(min_value_msat, if min_final_cltv_expiry_delta.is_some() {
			Method::LdkPaymentHashCustomFinalCltv
		} else {
			Method::LdkPaymentHash
		}, invoice_expiry_delta_secs, current_time, min_final_cltv_expiry_delta)?;

	let mut iv_bytes = [0 as u8; IV_LEN];
	let rand_bytes = entropy_source.get_secure_random_bytes();
	iv_bytes.copy_from_slice(&rand_bytes[..IV_LEN]);

	let mut hmac = HmacEngine::<Sha256>::new(&keys.ldk_pmt_hash_key);
	hmac.input(&iv_bytes);
	hmac.input(&metadata_bytes);
	let payment_preimage_bytes = Hmac::from_engine(hmac).to_byte_array();

	let ldk_pmt_hash = PaymentHash(Sha256::hash(&payment_preimage_bytes).to_byte_array());
	let payment_secret = construct_payment_secret(&iv_bytes, &metadata_bytes, &keys.metadata_key);
	Ok((ldk_pmt_hash, payment_secret))
}

/// Equivalent to [`crate::ln::channelmanager::ChannelManager::create_inbound_payment_for_hash`],
/// but no `ChannelManager` is required. Useful for generating invoices for [phantom node payments]
/// without a `ChannelManager`.
///
/// See [`create`] for information on the `keys` and `current_time` parameters.
///
/// Note that if `min_final_cltv_expiry_delta` is set to some value, then the payment will not be receivable
/// on versions of LDK prior to 0.0.114.
///
/// [phantom node payments]: crate::sign::PhantomKeysManager
pub fn create_from_hash(keys: &ExpandedKey, min_value_msat: Option<u64>, payment_hash: PaymentHash,
	invoice_expiry_delta_secs: u32, current_time: u64, min_final_cltv_expiry_delta: Option<u16>) -> Result<PaymentSecret, ()> {
	let metadata_bytes = construct_metadata_bytes(min_value_msat, if min_final_cltv_expiry_delta.is_some() {
			Method::UserPaymentHashCustomFinalCltv
		} else {
			Method::UserPaymentHash
		}, invoice_expiry_delta_secs, current_time, min_final_cltv_expiry_delta)?;

	let mut hmac = HmacEngine::<Sha256>::new(&keys.user_pmt_hash_key);
	hmac.input(&metadata_bytes);
	hmac.input(&payment_hash.0);
	let hmac_bytes = Hmac::from_engine(hmac).to_byte_array();

	let mut iv_bytes = [0 as u8; IV_LEN];
	iv_bytes.copy_from_slice(&hmac_bytes[..IV_LEN]);

	Ok(construct_payment_secret(&iv_bytes, &metadata_bytes, &keys.metadata_key))
}

fn construct_metadata_bytes(min_value_msat: Option<u64>, payment_type: Method,
	invoice_expiry_delta_secs: u32, highest_seen_timestamp: u64, min_final_cltv_expiry_delta: Option<u16>) -> Result<[u8; METADATA_LEN], ()> {
	if min_value_msat.is_some() && min_value_msat.unwrap() > MAX_VALUE_MSAT {
		return Err(());
	}

	let mut min_amt_msat_bytes: [u8; AMT_MSAT_LEN] = match min_value_msat {
		Some(amt) => amt.to_be_bytes(),
		None => [0; AMT_MSAT_LEN],
	};
	min_amt_msat_bytes[0] |= (payment_type as u8) << METHOD_TYPE_OFFSET;

	// We assume that highest_seen_timestamp is pretty close to the current time - it's updated when
	// we receive a new block with the maximum time we've seen in a header. It should never be more
	// than two hours in the future.  Thus, we add two hours here as a buffer to ensure we
	// absolutely never fail a payment too early.
	// Note that we assume that received blocks have reasonably up-to-date timestamps.
	let expiry_timestamp = highest_seen_timestamp + invoice_expiry_delta_secs as u64 + 7200;
	let mut expiry_bytes = expiry_timestamp.to_be_bytes();

	// `min_value_msat` should fit in (64 bits - 3 payment type bits =) 61 bits as an unsigned integer.
	// This should leave us with a maximum value greater than the 21M BTC supply cap anyway.
	if min_value_msat.is_some() && min_value_msat.unwrap() > ((1u64 << 61) - 1) { return Err(()); }

	// `expiry_timestamp` should fit in (64 bits - 2 delta bytes =) 48 bits as an unsigned integer.
	// Bitcoin's block header timestamps are actually `u32`s, so we're technically already limited to
	// the much smaller maximum timestamp of `u32::MAX` for now, but we check the u64 `expiry_timestamp`
	// for future-proofing.
	if min_final_cltv_expiry_delta.is_some() && expiry_timestamp > ((1u64 << 48) - 1) { return Err(()); }

	if let Some(min_final_cltv_expiry_delta) = min_final_cltv_expiry_delta {
		let bytes = min_final_cltv_expiry_delta.to_be_bytes();
		expiry_bytes[0] |= bytes[0];
		expiry_bytes[1] |= bytes[1];
	}

	let mut metadata_bytes: [u8; METADATA_LEN] = [0; METADATA_LEN];

	metadata_bytes[..AMT_MSAT_LEN].copy_from_slice(&min_amt_msat_bytes);
	metadata_bytes[AMT_MSAT_LEN..].copy_from_slice(&expiry_bytes);

	Ok(metadata_bytes)
}

fn construct_payment_secret(iv_bytes: &[u8; IV_LEN], metadata_bytes: &[u8; METADATA_LEN], metadata_key: &[u8; METADATA_KEY_LEN]) -> PaymentSecret {
	let mut payment_secret_bytes: [u8; 32] = [0; 32];
	let (iv_slice, encrypted_metadata_slice) = payment_secret_bytes.split_at_mut(IV_LEN);
	iv_slice.copy_from_slice(iv_bytes);

	ChaCha20::encrypt_single_block(
		metadata_key, iv_bytes, encrypted_metadata_slice, metadata_bytes
	);
	PaymentSecret(payment_secret_bytes)
}

/// Check that an inbound payment's `payment_data` field is sane.
///
/// LDK does not store any data for pending inbound payments. Instead, we construct our payment
/// secret (and, if supplied by LDK, our payment preimage) to include encrypted metadata about the
/// payment.
///
/// For payments without a custom `min_final_cltv_expiry_delta`, the metadata is constructed as:
///   payment method (3 bits) || payment amount (8 bytes - 3 bits) || expiry (8 bytes)
///
/// For payments including a custom `min_final_cltv_expiry_delta`, the metadata is constructed as:
///   payment method (3 bits) || payment amount (8 bytes - 3 bits) || min_final_cltv_expiry_delta (2 bytes) || expiry (6 bytes)
///
/// In both cases the result is then encrypted using a key derived from [`NodeSigner::get_inbound_payment_key_material`].
///
/// Then on payment receipt, we verify in this method that the payment preimage and payment secret
/// match what was constructed.
///
/// [`create_inbound_payment`] and [`create_inbound_payment_for_hash`] are called by the user to
/// construct the payment secret and/or payment hash that this method is verifying. If the former
/// method is called, then the payment method bits mentioned above are represented internally as
/// [`Method::LdkPaymentHash`]. If the latter, [`Method::UserPaymentHash`].
///
/// For the former method, the payment preimage is constructed as an HMAC of payment metadata and
/// random bytes. Because the payment secret is also encoded with these random bytes and metadata
/// (with the metadata encrypted with a block cipher), we're able to authenticate the preimage on
/// payment receipt.
///
/// For the latter, the payment secret instead contains an HMAC of the user-provided payment hash
/// and payment metadata (encrypted with a block cipher), allowing us to authenticate the payment
/// hash and metadata on payment receipt.
///
/// See [`ExpandedKey`] docs for more info on the individual keys used.
///
/// [`NodeSigner::get_inbound_payment_key_material`]: crate::sign::NodeSigner::get_inbound_payment_key_material
/// [`create_inbound_payment`]: crate::ln::channelmanager::ChannelManager::create_inbound_payment
/// [`create_inbound_payment_for_hash`]: crate::ln::channelmanager::ChannelManager::create_inbound_payment_for_hash
pub(super) fn verify<L: Deref>(payment_hash: PaymentHash, payment_data: &msgs::FinalOnionHopData,
	highest_seen_timestamp: u64, keys: &ExpandedKey, logger: &L) -> Result<
	(Option<PaymentPreimage>, Option<u16>), ()>
	where L::Target: Logger
{
	let (iv_bytes, metadata_bytes) = decrypt_metadata(payment_data.payment_secret, keys);

	let payment_type_res = Method::from_bits((metadata_bytes[0] & 0b1110_0000) >> METHOD_TYPE_OFFSET);
	let mut amt_msat_bytes = [0; AMT_MSAT_LEN];
	let mut expiry_bytes = [0; METADATA_LEN - AMT_MSAT_LEN];
	amt_msat_bytes.copy_from_slice(&metadata_bytes[..AMT_MSAT_LEN]);
	expiry_bytes.copy_from_slice(&metadata_bytes[AMT_MSAT_LEN..]);
	// Zero out the bits reserved to indicate the payment type.
	amt_msat_bytes[0] &= 0b00011111;
	let mut min_final_cltv_expiry_delta = None;

	// Make sure to check the HMAC before doing the other checks below, to mitigate timing attacks.
	let mut payment_preimage = None;

	match payment_type_res {
		Ok(Method::UserPaymentHash) | Ok(Method::UserPaymentHashCustomFinalCltv) => {
			let mut hmac = HmacEngine::<Sha256>::new(&keys.user_pmt_hash_key);
			hmac.input(&metadata_bytes[..]);
			hmac.input(&payment_hash.0);
			if !fixed_time_eq(&iv_bytes, &Hmac::from_engine(hmac).to_byte_array().split_at_mut(IV_LEN).0) {
				log_trace!(logger, "Failing HTLC with user-generated payment_hash {}: unexpected payment_secret", &payment_hash);
				return Err(())
			}
		},
		Ok(Method::LdkPaymentHash) | Ok(Method::LdkPaymentHashCustomFinalCltv) => {
			match derive_ldk_payment_preimage(payment_hash, &iv_bytes, &metadata_bytes, keys) {
				Ok(preimage) => payment_preimage = Some(preimage),
				Err(bad_preimage_bytes) => {
					log_trace!(logger, "Failing HTLC with payment_hash {} due to mismatching preimage {}", &payment_hash, log_bytes!(bad_preimage_bytes));
					return Err(())
				}
			}
		},
		Err(unknown_bits) => {
			log_trace!(logger, "Failing HTLC with payment hash {} due to unknown payment type {}", &payment_hash, unknown_bits);
			return Err(());
		}
	}

	match payment_type_res {
		Ok(Method::UserPaymentHashCustomFinalCltv) | Ok(Method::LdkPaymentHashCustomFinalCltv) => {
			min_final_cltv_expiry_delta = Some(min_final_cltv_expiry_delta_from_metadata(metadata_bytes));
			// Zero out first two bytes of expiry reserved for `min_final_cltv_expiry_delta`.
			expiry_bytes[0] &= 0;
			expiry_bytes[1] &= 0;
		}
		_ => {}
	}

	let min_amt_msat: u64 = u64::from_be_bytes(amt_msat_bytes.into());
	let expiry = u64::from_be_bytes(expiry_bytes.try_into().unwrap());

	if payment_data.total_msat < min_amt_msat {
		log_trace!(logger, "Failing HTLC with payment_hash {} due to total_msat {} being less than the minimum amount of {} msat", &payment_hash, payment_data.total_msat, min_amt_msat);
		return Err(())
	}

	if expiry < highest_seen_timestamp {
		log_trace!(logger, "Failing HTLC with payment_hash {}: expired payment", &payment_hash);
		return Err(())
	}

	Ok((payment_preimage, min_final_cltv_expiry_delta))
}

pub(super) fn get_payment_preimage(payment_hash: PaymentHash, payment_secret: PaymentSecret, keys: &ExpandedKey) -> Result<PaymentPreimage, APIError> {
	let (iv_bytes, metadata_bytes) = decrypt_metadata(payment_secret, keys);

	match Method::from_bits((metadata_bytes[0] & 0b1110_0000) >> METHOD_TYPE_OFFSET) {
		Ok(Method::LdkPaymentHash) | Ok(Method::LdkPaymentHashCustomFinalCltv) => {
			derive_ldk_payment_preimage(payment_hash, &iv_bytes, &metadata_bytes, keys)
				.map_err(|bad_preimage_bytes| APIError::APIMisuseError {
					err: format!("Payment hash {} did not match decoded preimage {}", &payment_hash, log_bytes!(bad_preimage_bytes))
				})
		},
		Ok(Method::UserPaymentHash) | Ok(Method::UserPaymentHashCustomFinalCltv) => Err(APIError::APIMisuseError {
			err: "Expected payment type to be LdkPaymentHash, instead got UserPaymentHash".to_string()
		}),
		Err(other) => Err(APIError::APIMisuseError { err: format!("Unknown payment type: {}", other) }),
	}
}

fn decrypt_metadata(payment_secret: PaymentSecret, keys: &ExpandedKey) -> ([u8; IV_LEN], [u8; METADATA_LEN]) {
	let mut iv_bytes = [0; IV_LEN];
	let (iv_slice, encrypted_metadata_bytes) = payment_secret.0.split_at(IV_LEN);
	iv_bytes.copy_from_slice(iv_slice);

	let mut metadata_bytes: [u8; METADATA_LEN] = [0; METADATA_LEN];
	ChaCha20::encrypt_single_block(
		&keys.metadata_key, &iv_bytes, &mut metadata_bytes, encrypted_metadata_bytes
	);

	(iv_bytes, metadata_bytes)
}

// Errors if the payment preimage doesn't match `payment_hash`. Returns the bad preimage bytes in
// this case.
fn derive_ldk_payment_preimage(payment_hash: PaymentHash, iv_bytes: &[u8; IV_LEN], metadata_bytes: &[u8; METADATA_LEN], keys: &ExpandedKey) -> Result<PaymentPreimage, [u8; 32]> {
	let mut hmac = HmacEngine::<Sha256>::new(&keys.ldk_pmt_hash_key);
	hmac.input(iv_bytes);
	hmac.input(metadata_bytes);
	let decoded_payment_preimage = Hmac::from_engine(hmac).to_byte_array();
	if !fixed_time_eq(&payment_hash.0, &Sha256::hash(&decoded_payment_preimage).to_byte_array()) {
		return Err(decoded_payment_preimage);
	}
	return Ok(PaymentPreimage(decoded_payment_preimage))
}
