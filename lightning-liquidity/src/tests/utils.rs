use crate::prelude::Vec;
use bitcoin::secp256k1::PublicKey;
use lightning::io;
use lightning::sign::EntropySource;

pub struct TestEntropy {}
impl EntropySource for TestEntropy {
	fn get_secure_random_bytes(&self) -> [u8; 32] {
		[0; 32]
	}
}

pub fn to_vec(hex: &str) -> Option<Vec<u8>> {
	let mut out = Vec::with_capacity(hex.len() / 2);

	let mut b = 0;
	for (idx, c) in hex.as_bytes().iter().enumerate() {
		b <<= 4;
		match *c {
			b'A'..=b'F' => b |= c - b'A' + 10,
			b'a'..=b'f' => b |= c - b'a' + 10,
			b'0'..=b'9' => b |= c - b'0',
			_ => return None,
		}
		if (idx & 1) == 1 {
			out.push(b);
			b = 0;
		}
	}

	Some(out)
}

pub fn to_compressed_pubkey(hex: &str) -> Option<PublicKey> {
	if hex.len() != 33 * 2 {
		return None;
	}
	let data = match to_vec(&hex[0..33 * 2]) {
		Some(bytes) => bytes,
		None => return None,
	};
	match PublicKey::from_slice(&data) {
		Ok(pk) => Some(pk),
		Err(_) => None,
	}
}

pub fn parse_pubkey(pubkey_str: &str) -> Result<PublicKey, io::Error> {
	let pubkey = to_compressed_pubkey(pubkey_str);
	if pubkey.is_none() {
		return Err(io::Error::new(
			io::ErrorKind::Other,
			"ERROR: unable to parse given pubkey for node",
		));
	}

	Ok(pubkey.unwrap())
}
