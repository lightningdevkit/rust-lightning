use bitcoin::hashes::{Hash, HashEngine};
use bitcoin::hashes::hmac::{Hmac, HmacEngine};
use bitcoin::hashes::sha256::Hash as Sha256;

macro_rules! hkdf_extract_expand {
	($salt: expr, $ikm: expr) => {{
		let mut hmac = HmacEngine::<Sha256>::new($salt);
		hmac.input($ikm);
		let prk = Hmac::from_engine(hmac).into_inner();
		let mut hmac = HmacEngine::<Sha256>::new(&prk[..]);
		hmac.input(&[1; 1]);
		let t1 = Hmac::from_engine(hmac).into_inner();
		let mut hmac = HmacEngine::<Sha256>::new(&prk[..]);
		hmac.input(&t1);
		hmac.input(&[2; 1]);
		(t1, Hmac::from_engine(hmac).into_inner(), prk)
	}};
	($salt: expr, $ikm: expr, 2) => {{
		let (k1, k2, _) = hkdf_extract_expand!($salt, $ikm);
		(k1, k2)
	}};
	($salt: expr, $ikm: expr, 3) => {{
		let (k1, k2, prk) = hkdf_extract_expand!($salt, $ikm);

		let mut hmac = HmacEngine::<Sha256>::new(&prk[..]);
		hmac.input(&k2);
		hmac.input(&[3; 1]);
		(k1, k2, Hmac::from_engine(hmac).into_inner())
	}}
}

pub fn hkdf_extract_expand_twice(salt: &[u8], ikm: &[u8]) -> ([u8; 32], [u8; 32]) {
	hkdf_extract_expand!(salt, ikm, 2)
}

pub fn hkdf_extract_expand_thrice(salt: &[u8], ikm: &[u8]) -> ([u8; 32], [u8; 32], [u8; 32]) {
	hkdf_extract_expand!(salt, ikm, 3)
}
