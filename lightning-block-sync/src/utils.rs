use bitcoin::hashes::hex::FromHex;
use bitcoin::util::uint::Uint256;

pub fn hex_to_uint256(hex: &str) -> Result<Uint256, bitcoin::hashes::hex::Error> {
	let bytes = <[u8; 32]>::from_hex(hex)?;
	Ok(Uint256::from_be_bytes(bytes))
}

#[cfg(test)]
mod tests {
	use super::*;
	use bitcoin::util::uint::Uint256;

	#[test]
	fn hex_to_uint256_empty_str() {
		assert!(hex_to_uint256("").is_err());
	}

	#[test]
	fn hex_to_uint256_too_short_str() {
		let hex = String::from_utf8(vec![b'0'; 32]).unwrap();
		assert_eq!(hex_to_uint256(&hex), Err(bitcoin::hashes::hex::Error::InvalidLength(64, 32)));
	}

	#[test]
	fn hex_to_uint256_too_long_str() {
		let hex = String::from_utf8(vec![b'0'; 128]).unwrap();
		assert_eq!(hex_to_uint256(&hex), Err(bitcoin::hashes::hex::Error::InvalidLength(64, 128)));
	}

	#[test]
	fn hex_to_uint256_odd_length_str() {
		let hex = String::from_utf8(vec![b'0'; 65]).unwrap();
		assert_eq!(hex_to_uint256(&hex), Err(bitcoin::hashes::hex::Error::OddLengthString(65)));
	}

	#[test]
	fn hex_to_uint256_invalid_char() {
		let hex = String::from_utf8(vec![b'G'; 64]).unwrap();
		assert_eq!(hex_to_uint256(&hex), Err(bitcoin::hashes::hex::Error::InvalidChar(b'G')));
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
}
