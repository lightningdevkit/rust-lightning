// This is a modification of base32 encoding to support the zbase32 alphabet.
// The original piece of software can be found at https://crates.io/crates/base32(v0.4.0)
// The original portions of this software are Copyright (c) 2015 The base32 Developers

// This file is licensed under either of
// Apache License, Version 2.0, (LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0) or
// MIT license (LICENSE-MIT or http://opensource.org/licenses/MIT) at your option.

#[allow(unused)]
use crate::prelude::*;

/// RFC4648 encoding table
const RFC4648_ALPHABET: &'static [u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Zbase encoding alphabet
const ZBASE_ALPHABET: &'static [u8] = b"ybndrfg8ejkmcpqxot1uwisza345h769";

/// RFC4648 decoding table
const RFC4648_INV_ALPHABET: [i8; 43] = [
	-1, -1, 26, 27, 28, 29, 30, 31, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0, 1, 2, 3, 4, 5, 6, 7, 8,
	9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
];

/// Zbase decoding table
const ZBASE_INV_ALPHABET: [i8; 43] = [
	-1, 18, -1, 25, 26, 27, 30, 29, 7, 31, -1, -1, -1, -1, -1, -1, -1, 24, 1, 12, 3, 8, 5, 6, 28,
	21, 9, 10, -1, 11, 2, 16, 13, 14, 4, 22, 17, 19, -1, 20, 15, 0, 23,
];

/// Alphabet used for encoding and decoding.
#[derive(Copy, Clone)]
pub enum Alphabet {
	/// RFC4648 encoding.
	RFC4648 {
		/// Whether to use padding.
		padding: bool,
	},
	/// Zbase32 encoding.
	ZBase32,
}

impl Alphabet {
	/// Encode bytes into a base32 string.
	pub fn encode(&self, data: &[u8]) -> String {
		// output_length is calculated as follows:
		// / 5 divides the data length by the number of bits per chunk (5),
		// * 8 multiplies the result by the number of characters per chunk (8).
		// + 4 rounds up to the nearest character.
		let output_length = (data.len() * 8 + 4) / 5;
		let mut ret = match self {
			Self::RFC4648 { padding } => {
				let mut ret = Self::encode_data(data, RFC4648_ALPHABET);
				if *padding {
					let len = ret.len();
					for i in output_length..len {
						ret[i] = b'=';
					}

					return String::from_utf8(ret).expect("Invalid UTF-8");
				}
				ret
			},
			Self::ZBase32 => Self::encode_data(data, ZBASE_ALPHABET),
		};
		ret.truncate(output_length);

		#[cfg(fuzzing)]
		assert_eq!(ret.capacity(), (data.len() + 4) / 5 * 8);

		String::from_utf8(ret).expect("Invalid UTF-8")
	}

	/// Decode a base32 string into a byte vector.
	pub fn decode(&self, data: &str) -> Result<Vec<u8>, ()> {
		let data = data.as_bytes();
		let (data, alphabet) = match self {
			Self::RFC4648 { padding } => {
				let mut unpadded_data_length = data.len();
				if *padding {
					if data.len() % 8 != 0 {
						return Err(());
					}
					data.iter().rev().take(6).for_each(|&c| {
						if c == b'=' {
							unpadded_data_length -= 1;
						}
					});
				}
				(&data[..unpadded_data_length], RFC4648_INV_ALPHABET)
			},
			Self::ZBase32 => (data, ZBASE_INV_ALPHABET),
		};
		// If the string has more characters than are required to alphabet_encode the number of bytes
		// decodable, treat the string as invalid.
		match data.len() % 8 {
			1 | 3 | 6 => return Err(()),
			_ => {},
		}
		Ok(Self::decode_data(data, alphabet)?)
	}

	/// Encode a byte slice into a base32 string.
	fn encode_data(data: &[u8], alphabet: &'static [u8]) -> Vec<u8> {
		// cap is calculated as follows:
		// / 5 divides the data length by the number of bits per chunk (5),
		// * 8 multiplies the result by the number of characters per chunk (8).
		// + 4 rounds up to the nearest character.
		let cap = (data.len() + 4) / 5 * 8;
		let mut ret = Vec::with_capacity(cap);
		for chunk in data.chunks(5) {
			let mut buf = [0u8; 5];
			for (i, &b) in chunk.iter().enumerate() {
				buf[i] = b;
			}
			ret.push(alphabet[((buf[0] & 0xF8) >> 3) as usize]);
			ret.push(alphabet[(((buf[0] & 0x07) << 2) | ((buf[1] & 0xC0) >> 6)) as usize]);
			ret.push(alphabet[((buf[1] & 0x3E) >> 1) as usize]);
			ret.push(alphabet[(((buf[1] & 0x01) << 4) | ((buf[2] & 0xF0) >> 4)) as usize]);
			ret.push(alphabet[(((buf[2] & 0x0F) << 1) | (buf[3] >> 7)) as usize]);
			ret.push(alphabet[((buf[3] & 0x7C) >> 2) as usize]);
			ret.push(alphabet[(((buf[3] & 0x03) << 3) | ((buf[4] & 0xE0) >> 5)) as usize]);
			ret.push(alphabet[(buf[4] & 0x1F) as usize]);
		}
		#[cfg(fuzzing)]
		assert_eq!(ret.capacity(), cap);

		ret
	}

	fn decode_data(data: &[u8], alphabet: [i8; 43]) -> Result<Vec<u8>, ()> {
		// cap is calculated as follows:
		// / 8 divides the data length by the number of characters per chunk (8),
		// * 5 multiplies the result by the number of bits per chunk (5),
		// + 7 rounds up to the nearest byte.
		let cap = (data.len() + 7) / 8 * 5;
		let mut ret = Vec::with_capacity(cap);
		for chunk in data.chunks(8) {
			let mut buf = [0u8; 8];
			for (i, &c) in chunk.iter().enumerate() {
				match alphabet.get(c.to_ascii_uppercase().wrapping_sub(b'0') as usize) {
					Some(&-1) | None => return Err(()),
					Some(&value) => buf[i] = value as u8,
				};
			}
			ret.push((buf[0] << 3) | (buf[1] >> 2));
			ret.push((buf[1] << 6) | (buf[2] << 1) | (buf[3] >> 4));
			ret.push((buf[3] << 4) | (buf[4] >> 1));
			ret.push((buf[4] << 7) | (buf[5] << 2) | (buf[6] >> 3));
			ret.push((buf[6] << 5) | buf[7]);
		}
		let output_length = data.len() * 5 / 8;
		for c in ret.drain(output_length..) {
			if c != 0 {
				// If the original string had any bits set at positions outside of the encoded data,
				// treat the string as invalid.
				return Err(());
			}
		}

		// Check that our capacity calculation doesn't under-shoot in fuzzing
		#[cfg(fuzzing)]
		assert_eq!(ret.capacity(), cap);
		Ok(ret)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	const ZBASE32_TEST_DATA: &[(&str, &[u8])] = &[
		("", &[]),
		("yy", &[0x00]),
		("oy", &[0x80]),
		("tqrey", &[0x8b, 0x88, 0x80]),
		("6n9hq", &[0xf0, 0xbf, 0xc7]),
		("4t7ye", &[0xd4, 0x7a, 0x04]),
		("6im5sdy", &[0xf5, 0x57, 0xbb, 0x0c]),
		(
			"ybndrfg8ejkmcpqxot1uwisza345h769",
			&[
				0x00, 0x44, 0x32, 0x14, 0xc7, 0x42, 0x54, 0xb6, 0x35, 0xcf, 0x84, 0x65, 0x3a, 0x56,
				0xd7, 0xc6, 0x75, 0xbe, 0x77, 0xdf,
			],
		),
	];

	#[test]
	fn test_zbase32_encode() {
		for &(zbase32, data) in ZBASE32_TEST_DATA {
			assert_eq!(Alphabet::ZBase32.encode(data), zbase32);
		}
	}

	#[test]
	fn test_zbase32_decode() {
		for &(zbase32, data) in ZBASE32_TEST_DATA {
			assert_eq!(Alphabet::ZBase32.decode(zbase32).unwrap(), data);
		}
	}

	#[test]
	fn test_decode_wrong() {
		const WRONG_DATA: &[&str] = &["00", "l1", "?", "="];
		for &data in WRONG_DATA {
			match Alphabet::ZBase32.decode(data) {
				Ok(_) => assert!(false, "Data shouldn't be decodable"),
				Err(_) => assert!(true),
			}
		}
	}

	const RFC4648_NON_PADDED_TEST_VECTORS: &[(&[u8], &[u8])] = &[
		(&[0xF8, 0x3E, 0x7F, 0x83, 0xE7], b"7A7H7A7H"),
		(&[0x77, 0xC1, 0xF7, 0x7C, 0x1F], b"O7A7O7A7"),
		(&[0xF8, 0x3E, 0x7F, 0x83, 0xE7], b"7A7H7A7H"),
		(&[0x77, 0xC1, 0xF7, 0x7C, 0x1F], b"O7A7O7A7"),
	];

	const RFC4648_TEST_VECTORS: &[(&[u8], &str)] = &[
		(b"", ""),
		(b"f", "MY======"),
		(b"fo", "MZXQ===="),
		(b"foo", "MZXW6==="),
		(b"foob", "MZXW6YQ="),
		(b"fooba", "MZXW6YTB"),
		(b"foobar", "MZXW6YTBOI======"),
		(&[0xF8, 0x3E, 0x7F, 0x83], "7A7H7AY="),
	];

	#[test]
	fn test_rfc4648_encode() {
		for (input, encoded) in RFC4648_TEST_VECTORS {
			assert_eq!(&Alphabet::RFC4648 { padding: true }.encode(input), encoded);
		}

		for (input, encoded) in RFC4648_NON_PADDED_TEST_VECTORS {
			assert_eq!(&Alphabet::RFC4648 { padding: false }.encode(input).as_bytes(), encoded);
		}
	}

	#[test]
	fn test_rfc4648_decode() {
		for (input, encoded) in RFC4648_TEST_VECTORS {
			let res = &Alphabet::RFC4648 { padding: true }.decode(encoded).unwrap();
			assert_eq!(&res[..], &input[..]);
		}

		for (input, encoded) in RFC4648_NON_PADDED_TEST_VECTORS {
			let res = &Alphabet::RFC4648 { padding: false }
				.decode(std::str::from_utf8(encoded).unwrap())
				.unwrap();
			assert_eq!(&res[..], &input[..]);
		}
	}

	#[test]
	fn padding() {
		let num_padding = [0, 6, 4, 3, 1];
		for i in 1..6 {
			let encoded = Alphabet::RFC4648 { padding: true }
				.encode((0..(i as u8)).collect::<Vec<u8>>().as_ref());
			assert_eq!(encoded.len(), 8);
			for j in 0..(num_padding[i % 5]) {
				assert_eq!(encoded.as_bytes()[encoded.len() - j - 1], b'=');
			}
			for j in 0..(8 - num_padding[i % 5]) {
				assert!(encoded.as_bytes()[j] != b'=');
			}
		}
	}

	#[test]
	fn test_decode_rfc4648_errors() {
		assert!(Alphabet::RFC4648 { padding: false }.decode("abc2def===").is_err()); // Invalid char because padding is disabled
		assert!(Alphabet::RFC4648 { padding: true }.decode("abc2def===").is_err()); // Invalid length
		assert!(Alphabet::RFC4648 { padding: true }.decode("MZX=6YTB").is_err()); // Invalid char
	}
}
