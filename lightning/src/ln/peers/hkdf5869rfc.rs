use bitcoin::hashes::{Hash, HashEngine, Hmac, HmacEngine};
use bitcoin::hashes::sha256::Hash as Sha256;

// Allows 1 or more inputs and "concatenates" them together using the input() function
// of HmacEngine::<Sha256>
macro_rules! hmac_sha256 {
	( $salt:expr, ($( $input:expr ),+ )) => {{
		let mut engine = HmacEngine::<Sha256>::new($salt);
		$(
			engine.input($input);
		)+
		Hmac::from_engine(engine).into_inner()
	}}
}

/// Implements HKDF defined in [BOLT #8](https://github.com/lightningnetwork/lightning-rfc/blob/master/08-transport.md#handshake-state)
/// [RFC 5869](https://tools.ietf.org/html/rfc5869pub)
/// Returns the first 64 octets as two 32 byte arrays
pub(super) fn derive(salt: &[u8], ikm: &[u8])  -> ([u8; 32], [u8; 32]) {
	// 2.1.  Notation
	//
	// HMAC-Hash denotes the HMAC function [HMAC] instantiated with hash
	// function 'Hash'.  HMAC always has two arguments: the first is a key
	// and the second an input (or message).  (Note that in the extract
	// step, 'IKM' is used as the HMAC input, not as the HMAC key.)
	//
	// When the message is composed of several elements we use concatenation
	// (denoted |) in the second argument; for example, HMAC(K, elem1 |
	// elem2 | elem3).

	// 2.2. Step 1: Extract
	// HKDF-Extract(salt, IKM) -> PRK
	// PRK = HMAC-Hash(salt, IKM)
	let prk = hmac_sha256!(salt, (ikm));

	// 2.3.  Step 2: Expand
	// HKDF-Expand(PRK, info, L) -> OKM
	// N = ceil(L/HashLen)
	// T = T(1) | T(2) | T(3) | ... | T(N)
	// OKM = first L octets of T
	//
	// where:
	// T(0) = empty string (zero length)
	// T(1) = HMAC-Hash(PRK, T(0) | info | 0x01)
	let t1 = hmac_sha256!(&prk, (&[1]));
	// T(2) = HMAC-Hash(PRK, T(1) | info | 0x02)
	let t2 = hmac_sha256!(&prk, (&t1, &[2]));

	return (t1, t2)
}

// Appendix A.  Test Vectors
#[cfg(test)]
mod test {
	use hex;
	use ln::peers::hkdf5869rfc::derive;

	// Test with SHA-256 and zero-length salt/info
	// Our implementation uses a zero-length info field and returns the first 64 octets. As a result,
	// this test will be a prefix match on the vector provided by the RFC which is 42 bytes.
	#[test]
	fn rfc_5869_test_vector_3() {
		let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
		let (t1, t2) = derive(&[], &ikm);

		let mut calculated_okm = t1.to_vec();
		calculated_okm.extend_from_slice(&t2);
		calculated_okm.truncate(42);
		assert_eq!(calculated_okm, hex::decode("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8").unwrap());
	}
}