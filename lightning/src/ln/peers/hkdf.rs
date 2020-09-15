use bitcoin::hashes::{Hash, HashEngine, Hmac, HmacEngine};
use bitcoin::hashes::sha256::Hash as Sha256;

pub fn derive(salt: &[u8], master: &[u8]) -> ([u8; 32], [u8; 32]) {
	let mut hmac = HmacEngine::<Sha256>::new(salt);
	hmac.input(master);
	let prk = Hmac::from_engine(hmac).into_inner(); // prk = sha256(master)

	let mut hmac = HmacEngine::<Sha256>::new(&prk[..]);
	hmac.input(&[1; 1]);
	let t1 = Hmac::from_engine(hmac).into_inner(); // t1 = sha256(prk | 1)

	let mut hmac = HmacEngine::<Sha256>::new(&prk[..]);
	hmac.input(&t1);
	hmac.input(&[2; 1]);
	// sha256(prk | t1 | 2) = sha256(sha256(master) | sha256(sha256(sha256(master) | 1) | 2)
	(t1, Hmac::from_engine(hmac).into_inner())
}
