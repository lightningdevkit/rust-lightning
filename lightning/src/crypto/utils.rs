use bitcoin::hashes::hmac::{Hmac, HmacEngine};
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::{Hash, HashEngine};
use bitcoin::secp256k1::{ecdsa::Signature, Message, Secp256k1, SecretKey, Signing};

use crate::sign::EntropySource;

use core::ops::Deref;

macro_rules! hkdf_extract_expand {
	($salt: expr, $ikm: expr) => {{
		let mut hmac = HmacEngine::<Sha256>::new($salt);
		hmac.input($ikm);
		let prk = Hmac::from_engine(hmac).to_byte_array();
		let mut hmac = HmacEngine::<Sha256>::new(&prk[..]);
		hmac.input(&[1; 1]);
		let t1 = Hmac::from_engine(hmac).to_byte_array();
		let mut hmac = HmacEngine::<Sha256>::new(&prk[..]);
		hmac.input(&t1);
		hmac.input(&[2; 1]);
		(t1, Hmac::from_engine(hmac).to_byte_array(), prk)
	}};
	($salt: expr, $ikm: expr, 2) => {{
		let (k1, k2, _) = hkdf_extract_expand!($salt, $ikm);
		(k1, k2)
	}};
	($salt: expr, $ikm: expr, 5) => {{
		let (k1, k2, prk) = hkdf_extract_expand!($salt, $ikm);

		let mut hmac = HmacEngine::<Sha256>::new(&prk[..]);
		hmac.input(&k2);
		hmac.input(&[3; 1]);
		let k3 = Hmac::from_engine(hmac).to_byte_array();

		let mut hmac = HmacEngine::<Sha256>::new(&prk[..]);
		hmac.input(&k3);
		hmac.input(&[4; 1]);
		let k4 = Hmac::from_engine(hmac).to_byte_array();

		let mut hmac = HmacEngine::<Sha256>::new(&prk[..]);
		hmac.input(&k4);
		hmac.input(&[5; 1]);
		let k5 = Hmac::from_engine(hmac).to_byte_array();

		(k1, k2, k3, k4, k5)
	}};
}

pub fn hkdf_extract_expand_twice(salt: &[u8], ikm: &[u8]) -> ([u8; 32], [u8; 32]) {
	hkdf_extract_expand!(salt, ikm, 2)
}

pub fn hkdf_extract_expand_5x(
	salt: &[u8], ikm: &[u8],
) -> ([u8; 32], [u8; 32], [u8; 32], [u8; 32], [u8; 32]) {
	hkdf_extract_expand!(salt, ikm, 5)
}

#[inline]
pub fn sign<C: Signing>(ctx: &Secp256k1<C>, msg: &Message, sk: &SecretKey) -> Signature {
	#[cfg(feature = "grind_signatures")]
	let sig = ctx.sign_ecdsa_low_r(msg, sk);
	#[cfg(not(feature = "grind_signatures"))]
	let sig = ctx.sign_ecdsa(msg, sk);
	sig
}

#[inline]
#[allow(unused_variables)]
pub fn sign_with_aux_rand<C: Signing, ES: Deref>(
	ctx: &Secp256k1<C>, msg: &Message, sk: &SecretKey, entropy_source: &ES,
) -> Signature
where
	ES::Target: EntropySource,
{
	#[cfg(feature = "grind_signatures")]
	let sig = loop {
		let sig = ctx.sign_ecdsa_with_noncedata(msg, sk, &entropy_source.get_secure_random_bytes());
		if sig.serialize_compact()[0] < 0x80 {
			break sig;
		}
	};
	#[cfg(all(not(feature = "grind_signatures"), not(ldk_test_vectors)))]
	let sig = ctx.sign_ecdsa_with_noncedata(msg, sk, &entropy_source.get_secure_random_bytes());
	#[cfg(all(not(feature = "grind_signatures"), ldk_test_vectors))]
	let sig = sign(ctx, msg, sk);
	sig
}
