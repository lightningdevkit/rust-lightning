use bitcoin::hashes::hex::FromHex;
use bitcoin::util::uint::Uint256;

pub fn hex_to_uint256(hex: &str) -> Option<Uint256> {
	match <[u8; 32]>::from_hex(hex) {
		Err(_) => None,
		Ok(bytes) => Some(Uint256::from_be_bytes(bytes)),
	}
}

#[cfg(feature = "rpc-client")]
pub fn hex_to_vec(hex: &str) -> Option<Vec<u8>> {
	Vec::<u8>::from_hex(hex).ok()
}

#[cfg(test)]
mod tests {
	use super::*;
	use bitcoin::util::uint::Uint256;

	#[test]
	fn hex_to_uint256_empty_str() {
		assert!(hex_to_uint256("").is_none());
	}

	#[test]
	fn hex_to_uint256_too_short_str() {
		let hex = String::from_utf8(vec![b'0'; 63]).unwrap();
		assert!(hex_to_uint256(&hex).is_none());
	}

	#[test]
	fn hex_to_uint256_too_long_str() {
		let hex = String::from_utf8(vec![b'0'; 65]).unwrap();
		assert!(hex_to_uint256(&hex).is_none());
	}

	#[test]
	fn hex_to_uint256_invalid_char() {
		let hex = String::from_utf8(vec![b'G'; 64]).unwrap();
		assert!(hex_to_uint256(&hex).is_none());
	}

	#[test]
	fn hex_to_uint256_lowercase_str() {
		let hex: String = std::iter::repeat("0123456789abcdef").take(4).collect();
		assert_eq!(hex_to_uint256(&hex).unwrap(), Uint256([0x0123456789abcdefu64; 4]));
	}

	#[test]
	fn hex_to_uint256_uppercase_str() {
		let hex: String = std::iter::repeat("0123456789ABCDEF").take(4).collect();
		assert_eq!(hex_to_uint256(&hex).unwrap(), Uint256([0x0123456789abcdefu64; 4]));
	}

	#[test]
	fn hex_to_vec_empty_str() {
		assert_eq!(hex_to_vec("").unwrap(), Vec::<u8>::new());
	}

	#[test]
	fn hex_to_vec_odd_length_str() {
		let hex = "123456789";
		assert!(hex_to_vec(&hex).is_none());
	}

	#[test]
	fn hex_to_vec_even_length_str() {
		let hex = "0123456789";
		assert_eq!(hex_to_vec(&hex).unwrap(), vec![0x01u8, 0x23u8, 0x45u8, 0x67u8, 0x89u8]);
	}

	#[test]
	fn hex_to_vec_invalid_char() {
		let hex = String::from_utf8(vec![b'G'; 64]).unwrap();
		assert!(hex_to_vec(&hex).is_none());
	}

	#[test]
	fn hex_to_vec_lowercase_str() {
		let hex: String = std::iter::repeat("ef").take(32).collect();
		assert_eq!(hex_to_vec(&hex).unwrap(), vec![0xefu8; 32]);
	}

	#[test]
	fn hex_to_vec_uppercase_str() {
		let hex: String = std::iter::repeat("EF").take(32).collect();
		assert_eq!(hex_to_vec(&hex).unwrap(), vec![0xefu8; 32]);
	}
}
