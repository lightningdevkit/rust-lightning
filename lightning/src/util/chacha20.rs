// This file was stolen from rust-crypto.
// Copyright 2012-2013 The Rust Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution and at
// http://rust-lang.org/COPYRIGHT.

// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::io;

#[cfg(not(feature = "fuzztarget"))]
mod real_chacha {
	use std::cmp;
	use util::byte_utils::{le32_to_array, slice_to_le32};

	#[derive(Clone, Copy, PartialEq, Eq)]
	#[allow(non_camel_case_types)]
	struct u32x4(pub u32, pub u32, pub u32, pub u32);
	impl ::std::ops::Add for u32x4 {
		type Output = u32x4;
		fn add(self, rhs: u32x4) -> u32x4 {
			u32x4(
				self.0.wrapping_add(rhs.0),
				self.1.wrapping_add(rhs.1),
				self.2.wrapping_add(rhs.2),
				self.3.wrapping_add(rhs.3),
			)
		}
	}
	impl ::std::ops::Sub for u32x4 {
		type Output = u32x4;
		fn sub(self, rhs: u32x4) -> u32x4 {
			u32x4(
				self.0.wrapping_sub(rhs.0),
				self.1.wrapping_sub(rhs.1),
				self.2.wrapping_sub(rhs.2),
				self.3.wrapping_sub(rhs.3),
			)
		}
	}
	impl ::std::ops::BitXor for u32x4 {
		type Output = u32x4;
		fn bitxor(self, rhs: u32x4) -> u32x4 {
			u32x4(self.0 ^ rhs.0, self.1 ^ rhs.1, self.2 ^ rhs.2, self.3 ^ rhs.3)
		}
	}
	impl ::std::ops::Shr<u32x4> for u32x4 {
		type Output = u32x4;
		fn shr(self, rhs: u32x4) -> u32x4 {
			u32x4(self.0 >> rhs.0, self.1 >> rhs.1, self.2 >> rhs.2, self.3 >> rhs.3)
		}
	}
	impl ::std::ops::Shl<u32x4> for u32x4 {
		type Output = u32x4;
		fn shl(self, rhs: u32x4) -> u32x4 {
			u32x4(self.0 << rhs.0, self.1 << rhs.1, self.2 << rhs.2, self.3 << rhs.3)
		}
	}

	const BLOCK_SIZE: usize = 64;

	#[derive(Clone, Copy)]
	struct ChaChaState {
		a: u32x4,
		b: u32x4,
		c: u32x4,
		d: u32x4,
	}

	#[derive(Copy)]
	pub struct ChaCha20 {
		state: ChaChaState,
		output: [u8; BLOCK_SIZE],
		offset: usize,
	}

	impl Clone for ChaCha20 {
		fn clone(&self) -> ChaCha20 {
			*self
		}
	}

	#[cfg_attr(rustfmt, rustfmt_skip)]
	macro_rules! swizzle {
		($b: expr, $c: expr, $d: expr) => {{
			let u32x4(b10, b11, b12, b13) = $b;
			$b = u32x4(b11, b12, b13, b10);
			let u32x4(c10, c11, c12, c13) = $c;
			$c = u32x4(c12, c13,c10, c11);
			let u32x4(d10, d11, d12, d13) = $d;
			$d = u32x4(d13, d10, d11, d12);
		}}
	}

	#[cfg_attr(rustfmt, rustfmt_skip)]
	macro_rules! state_to_buffer {
		($state: expr, $output: expr) => {{
			let u32x4(a1, a2, a3, a4) = $state.a;
			let u32x4(b1, b2, b3, b4) = $state.b;
			let u32x4(c1, c2, c3, c4) = $state.c;
			let u32x4(d1, d2, d3, d4) = $state.d;
			let lens = [
				a1,a2,a3,a4,
				b1,b2,b3,b4,
				c1,c2,c3,c4,
				d1,d2,d3,d4
			];
			for i in 0..lens.len() {
				$output[i*4..(i+1)*4].copy_from_slice(&le32_to_array(lens[i]));
			}
		}}
	}

	#[cfg_attr(rustfmt, rustfmt_skip)]
	macro_rules! round{
		($state: expr) => {{
			$state.a = $state.a + $state.b;
			rotate!($state.d, $state.a, S16);
			$state.c = $state.c + $state.d;
			rotate!($state.b, $state.c, S12);
			$state.a = $state.a + $state.b;
			rotate!($state.d, $state.a, S8);
			$state.c = $state.c + $state.d;
			rotate!($state.b, $state.c, S7);
		}}
	}

	#[cfg_attr(rustfmt, rustfmt_skip)]
	macro_rules! rotate {
		($a: expr, $b: expr, $c:expr) => {{
			let v = $a ^ $b;
			let r = S32 - $c;
			let right = v >> r;
			$a = (v << $c) ^ right
		}}
	}

	const S32: u32x4 = u32x4(32, 32, 32, 32);
	const S16: u32x4 = u32x4(16, 16, 16, 16);
	const S12: u32x4 = u32x4(12, 12, 12, 12);
	const S8: u32x4 = u32x4(8, 8, 8, 8);
	const S7: u32x4 = u32x4(7, 7, 7, 7);

	impl ChaCha20 {
		pub fn new(key: &[u8], nonce: &[u8]) -> ChaCha20 {
			assert!(key.len() == 16 || key.len() == 32);
			assert!(nonce.len() == 8 || nonce.len() == 12);

			ChaCha20 { state: ChaCha20::expand(key, nonce), output: [0u8; BLOCK_SIZE], offset: 64 }
		}

		fn expand(key: &[u8], nonce: &[u8]) -> ChaChaState {
			let constant = match key.len() {
				16 => b"expand 16-byte k",
				32 => b"expand 32-byte k",
				_ => unreachable!(),
			};
			ChaChaState {
				a: u32x4(
					slice_to_le32(&constant[0..4]),
					slice_to_le32(&constant[4..8]),
					slice_to_le32(&constant[8..12]),
					slice_to_le32(&constant[12..16]),
				),
				b: u32x4(
					slice_to_le32(&key[0..4]),
					slice_to_le32(&key[4..8]),
					slice_to_le32(&key[8..12]),
					slice_to_le32(&key[12..16]),
				),
				c: if key.len() == 16 {
					u32x4(
						slice_to_le32(&key[0..4]),
						slice_to_le32(&key[4..8]),
						slice_to_le32(&key[8..12]),
						slice_to_le32(&key[12..16]),
					)
				} else {
					u32x4(
						slice_to_le32(&key[16..20]),
						slice_to_le32(&key[20..24]),
						slice_to_le32(&key[24..28]),
						slice_to_le32(&key[28..32]),
					)
				},
				d: if nonce.len() == 16 {
					u32x4(
						slice_to_le32(&nonce[0..4]),
						slice_to_le32(&nonce[4..8]),
						slice_to_le32(&nonce[8..12]),
						slice_to_le32(&nonce[12..16]),
					)
				} else if nonce.len() == 12 {
					u32x4(0, slice_to_le32(&nonce[0..4]), slice_to_le32(&nonce[4..8]), slice_to_le32(&nonce[8..12]))
				} else {
					u32x4(0, 0, slice_to_le32(&nonce[0..4]), slice_to_le32(&nonce[4..8]))
				},
			}
		}

		// put the the next BLOCK_SIZE keystream bytes into self.output
		fn update(&mut self) {
			let mut state = self.state;

			for _ in 0..10 {
				round!(state);
				swizzle!(state.b, state.c, state.d);
				round!(state);
				swizzle!(state.d, state.c, state.b);
			}
			state.a = state.a + self.state.a;
			state.b = state.b + self.state.b;
			state.c = state.c + self.state.c;
			state.d = state.d + self.state.d;

			state_to_buffer!(state, self.output);

			self.state.d = self.state.d + u32x4(1, 0, 0, 0);
			let u32x4(c12, _, _, _) = self.state.d;
			if c12 == 0 {
				// we could increment the other counter word with an 8 byte nonce
				// but other implementations like boringssl have this same
				// limitation
				panic!("counter is exhausted");
			}

			self.offset = 0;
		}

		#[inline] // Useful cause input may be 0s on stack that should be optimized out
		pub fn process(&mut self, input: &[u8], output: &mut [u8]) {
			assert!(input.len() == output.len());
			let len = input.len();
			let mut i = 0;
			while i < len {
				// If there is no keystream available in the output buffer,
				// generate the next block.
				if self.offset == BLOCK_SIZE {
					self.update();
				}

				// Process the min(available keystream, remaining input length).
				let count = cmp::min(BLOCK_SIZE - self.offset, len - i);
				// explicitly assert lengths to avoid bounds checks:
				assert!(output.len() >= i + count);
				assert!(input.len() >= i + count);
				assert!(self.output.len() >= self.offset + count);
				for j in 0..count {
					output[i + j] = input[i + j] ^ self.output[self.offset + j];
				}
				i += count;
				self.offset += count;
			}
		}

		pub fn process_in_place(&mut self, input_output: &mut [u8]) {
			let len = input_output.len();
			let mut i = 0;
			while i < len {
				// If there is no keystream available in the output buffer,
				// generate the next block.
				if self.offset == BLOCK_SIZE {
					self.update();
				}

				// Process the min(available keystream, remaining input length).
				let count = cmp::min(BLOCK_SIZE - self.offset, len - i);
				// explicitly assert lengths to avoid bounds checks:
				assert!(input_output.len() >= i + count);
				assert!(self.output.len() >= self.offset + count);
				for j in 0..count {
					input_output[i + j] ^= self.output[self.offset + j];
				}
				i += count;
				self.offset += count;
			}
		}
	}
}
#[cfg(not(feature = "fuzztarget"))]
pub use self::real_chacha::ChaCha20;

#[cfg(feature = "fuzztarget")]
mod fuzzy_chacha {
	pub struct ChaCha20 {}

	impl ChaCha20 {
		pub fn new(key: &[u8], nonce: &[u8]) -> ChaCha20 {
			assert!(key.len() == 16 || key.len() == 32);
			assert!(nonce.len() == 8 || nonce.len() == 12);
			Self {}
		}

		pub fn process(&mut self, input: &[u8], output: &mut [u8]) {
			output.copy_from_slice(input);
		}

		pub fn process_in_place(&mut self, _input_output: &mut [u8]) {}
	}
}
#[cfg(feature = "fuzztarget")]
pub use self::fuzzy_chacha::ChaCha20;

pub(crate) struct ChaChaReader<'a, R: io::Read> {
	pub chacha: &'a mut ChaCha20,
	pub read: R,
}
impl<'a, R: io::Read> io::Read for ChaChaReader<'a, R> {
	fn read(&mut self, dest: &mut [u8]) -> Result<usize, io::Error> {
		let res = self.read.read(dest)?;
		if res > 0 {
			self.chacha.process_in_place(&mut dest[0..res]);
		}
		Ok(res)
	}
}

#[cfg(test)]
mod test {
	use std::iter::repeat;

	use super::ChaCha20;

	#[test]
	fn test_chacha20_256_tls_vectors() {
		struct TestVector {
			key: [u8; 32],
			nonce: [u8; 8],
			keystream: Vec<u8>,
		};
		// taken from http://tools.ietf.org/html/draft-agl-tls-chacha20poly1305-04
		let test_vectors = vec![
			TestVector {
				key: [
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				],
				nonce: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
				keystream: vec![
					0x76, 0xb8, 0xe0, 0xad, 0xa0, 0xf1, 0x3d, 0x90, 0x40, 0x5d, 0x6a, 0xe5, 0x53, 0x86, 0xbd, 0x28,
					0xbd, 0xd2, 0x19, 0xb8, 0xa0, 0x8d, 0xed, 0x1a, 0xa8, 0x36, 0xef, 0xcc, 0x8b, 0x77, 0x0d, 0xc7,
					0xda, 0x41, 0x59, 0x7c, 0x51, 0x57, 0x48, 0x8d, 0x77, 0x24, 0xe0, 0x3f, 0xb8, 0xd8, 0x4a, 0x37,
					0x6a, 0x43, 0xb8, 0xf4, 0x15, 0x18, 0xa1, 0x1c, 0xc3, 0x87, 0xb6, 0x69, 0xb2, 0xee, 0x65, 0x86,
				],
			},
			TestVector {
				key: [
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
				],
				nonce: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
				keystream: vec![
					0x45, 0x40, 0xf0, 0x5a, 0x9f, 0x1f, 0xb2, 0x96, 0xd7, 0x73, 0x6e, 0x7b, 0x20, 0x8e, 0x3c, 0x96,
					0xeb, 0x4f, 0xe1, 0x83, 0x46, 0x88, 0xd2, 0x60, 0x4f, 0x45, 0x09, 0x52, 0xed, 0x43, 0x2d, 0x41,
					0xbb, 0xe2, 0xa0, 0xb6, 0xea, 0x75, 0x66, 0xd2, 0xa5, 0xd1, 0xe7, 0xe2, 0x0d, 0x42, 0xaf, 0x2c,
					0x53, 0xd7, 0x92, 0xb1, 0xc4, 0x3f, 0xea, 0x81, 0x7e, 0x9a, 0xd2, 0x75, 0xae, 0x54, 0x69, 0x63,
				],
			},
			TestVector {
				key: [
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				],
				nonce: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01],
				keystream: vec![
					0xde, 0x9c, 0xba, 0x7b, 0xf3, 0xd6, 0x9e, 0xf5, 0xe7, 0x86, 0xdc, 0x63, 0x97, 0x3f, 0x65, 0x3a,
					0x0b, 0x49, 0xe0, 0x15, 0xad, 0xbf, 0xf7, 0x13, 0x4f, 0xcb, 0x7d, 0xf1, 0x37, 0x82, 0x10, 0x31,
					0xe8, 0x5a, 0x05, 0x02, 0x78, 0xa7, 0x08, 0x45, 0x27, 0x21, 0x4f, 0x73, 0xef, 0xc7, 0xfa, 0x5b,
					0x52, 0x77, 0x06, 0x2e, 0xb7, 0xa0, 0x43, 0x3e, 0x44, 0x5f, 0x41, 0xe3,
				],
			},
			TestVector {
				key: [
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				],
				nonce: [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
				keystream: vec![
					0xef, 0x3f, 0xdf, 0xd6, 0xc6, 0x15, 0x78, 0xfb, 0xf5, 0xcf, 0x35, 0xbd, 0x3d, 0xd3, 0x3b, 0x80,
					0x09, 0x63, 0x16, 0x34, 0xd2, 0x1e, 0x42, 0xac, 0x33, 0x96, 0x0b, 0xd1, 0x38, 0xe5, 0x0d, 0x32,
					0x11, 0x1e, 0x4c, 0xaf, 0x23, 0x7e, 0xe5, 0x3c, 0xa8, 0xad, 0x64, 0x26, 0x19, 0x4a, 0x88, 0x54,
					0x5d, 0xdc, 0x49, 0x7a, 0x0b, 0x46, 0x6e, 0x7d, 0x6b, 0xbd, 0xb0, 0x04, 0x1b, 0x2f, 0x58, 0x6b,
				],
			},
			TestVector {
				key: [
					0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
					0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
				],
				nonce: [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07],
				keystream: vec![
					0xf7, 0x98, 0xa1, 0x89, 0xf1, 0x95, 0xe6, 0x69, 0x82, 0x10, 0x5f, 0xfb, 0x64, 0x0b, 0xb7, 0x75,
					0x7f, 0x57, 0x9d, 0xa3, 0x16, 0x02, 0xfc, 0x93, 0xec, 0x01, 0xac, 0x56, 0xf8, 0x5a, 0xc3, 0xc1,
					0x34, 0xa4, 0x54, 0x7b, 0x73, 0x3b, 0x46, 0x41, 0x30, 0x42, 0xc9, 0x44, 0x00, 0x49, 0x17, 0x69,
					0x05, 0xd3, 0xbe, 0x59, 0xea, 0x1c, 0x53, 0xf1, 0x59, 0x16, 0x15, 0x5c, 0x2b, 0xe8, 0x24, 0x1a,
					0x38, 0x00, 0x8b, 0x9a, 0x26, 0xbc, 0x35, 0x94, 0x1e, 0x24, 0x44, 0x17, 0x7c, 0x8a, 0xde, 0x66,
					0x89, 0xde, 0x95, 0x26, 0x49, 0x86, 0xd9, 0x58, 0x89, 0xfb, 0x60, 0xe8, 0x46, 0x29, 0xc9, 0xbd,
					0x9a, 0x5a, 0xcb, 0x1c, 0xc1, 0x18, 0xbe, 0x56, 0x3e, 0xb9, 0xb3, 0xa4, 0xa4, 0x72, 0xf8, 0x2e,
					0x09, 0xa7, 0xe7, 0x78, 0x49, 0x2b, 0x56, 0x2e, 0xf7, 0x13, 0x0e, 0x88, 0xdf, 0xe0, 0x31, 0xc7,
					0x9d, 0xb9, 0xd4, 0xf7, 0xc7, 0xa8, 0x99, 0x15, 0x1b, 0x9a, 0x47, 0x50, 0x32, 0xb6, 0x3f, 0xc3,
					0x85, 0x24, 0x5f, 0xe0, 0x54, 0xe3, 0xdd, 0x5a, 0x97, 0xa5, 0xf5, 0x76, 0xfe, 0x06, 0x40, 0x25,
					0xd3, 0xce, 0x04, 0x2c, 0x56, 0x6a, 0xb2, 0xc5, 0x07, 0xb1, 0x38, 0xdb, 0x85, 0x3e, 0x3d, 0x69,
					0x59, 0x66, 0x09, 0x96, 0x54, 0x6c, 0xc9, 0xc4, 0xa6, 0xea, 0xfd, 0xc7, 0x77, 0xc0, 0x40, 0xd7,
					0x0e, 0xaf, 0x46, 0xf7, 0x6d, 0xad, 0x39, 0x79, 0xe5, 0xc5, 0x36, 0x0c, 0x33, 0x17, 0x16, 0x6a,
					0x1c, 0x89, 0x4c, 0x94, 0xa3, 0x71, 0x87, 0x6a, 0x94, 0xdf, 0x76, 0x28, 0xfe, 0x4e, 0xaa, 0xf2,
					0xcc, 0xb2, 0x7d, 0x5a, 0xaa, 0xe0, 0xad, 0x7a, 0xd0, 0xf9, 0xd4, 0xb6, 0xad, 0x3b, 0x54, 0x09,
					0x87, 0x46, 0xd4, 0x52, 0x4d, 0x38, 0x40, 0x7a, 0x6d, 0xeb, 0x3a, 0xb7, 0x8f, 0xab, 0x78, 0xc9,
				],
			},
		];

		for tv in test_vectors.iter() {
			let mut c = ChaCha20::new(&tv.key, &tv.nonce);
			let input: Vec<u8> = repeat(0).take(tv.keystream.len()).collect();
			let mut output: Vec<u8> = repeat(0).take(input.len()).collect();
			c.process(&input[..], &mut output[..]);
			assert_eq!(output, tv.keystream);
		}
	}

	#[test]
	fn test_chacha20_256_tls_vectors_96_nonce() {
		struct TestVector {
			key: [u8; 32],
			nonce: [u8; 12],
			keystream: Vec<u8>,
		};
		// taken from http://tools.ietf.org/html/draft-agl-tls-chacha20poly1305-04
		let test_vectors = vec![
			TestVector {
				key: [
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				],
				nonce: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
				keystream: vec![
					0x76, 0xb8, 0xe0, 0xad, 0xa0, 0xf1, 0x3d, 0x90, 0x40, 0x5d, 0x6a, 0xe5, 0x53, 0x86, 0xbd, 0x28,
					0xbd, 0xd2, 0x19, 0xb8, 0xa0, 0x8d, 0xed, 0x1a, 0xa8, 0x36, 0xef, 0xcc, 0x8b, 0x77, 0x0d, 0xc7,
					0xda, 0x41, 0x59, 0x7c, 0x51, 0x57, 0x48, 0x8d, 0x77, 0x24, 0xe0, 0x3f, 0xb8, 0xd8, 0x4a, 0x37,
					0x6a, 0x43, 0xb8, 0xf4, 0x15, 0x18, 0xa1, 0x1c, 0xc3, 0x87, 0xb6, 0x69, 0xb2, 0xee, 0x65, 0x86,
				],
			},
			TestVector {
				key: [
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
				],
				nonce: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
				keystream: vec![
					0x45, 0x40, 0xf0, 0x5a, 0x9f, 0x1f, 0xb2, 0x96, 0xd7, 0x73, 0x6e, 0x7b, 0x20, 0x8e, 0x3c, 0x96,
					0xeb, 0x4f, 0xe1, 0x83, 0x46, 0x88, 0xd2, 0x60, 0x4f, 0x45, 0x09, 0x52, 0xed, 0x43, 0x2d, 0x41,
					0xbb, 0xe2, 0xa0, 0xb6, 0xea, 0x75, 0x66, 0xd2, 0xa5, 0xd1, 0xe7, 0xe2, 0x0d, 0x42, 0xaf, 0x2c,
					0x53, 0xd7, 0x92, 0xb1, 0xc4, 0x3f, 0xea, 0x81, 0x7e, 0x9a, 0xd2, 0x75, 0xae, 0x54, 0x69, 0x63,
				],
			},
			TestVector {
				key: [
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				],
				nonce: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01],
				keystream: vec![
					0xde, 0x9c, 0xba, 0x7b, 0xf3, 0xd6, 0x9e, 0xf5, 0xe7, 0x86, 0xdc, 0x63, 0x97, 0x3f, 0x65, 0x3a,
					0x0b, 0x49, 0xe0, 0x15, 0xad, 0xbf, 0xf7, 0x13, 0x4f, 0xcb, 0x7d, 0xf1, 0x37, 0x82, 0x10, 0x31,
					0xe8, 0x5a, 0x05, 0x02, 0x78, 0xa7, 0x08, 0x45, 0x27, 0x21, 0x4f, 0x73, 0xef, 0xc7, 0xfa, 0x5b,
					0x52, 0x77, 0x06, 0x2e, 0xb7, 0xa0, 0x43, 0x3e, 0x44, 0x5f, 0x41, 0xe3,
				],
			},
			TestVector {
				key: [
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				],
				nonce: [0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
				keystream: vec![
					0xef, 0x3f, 0xdf, 0xd6, 0xc6, 0x15, 0x78, 0xfb, 0xf5, 0xcf, 0x35, 0xbd, 0x3d, 0xd3, 0x3b, 0x80,
					0x09, 0x63, 0x16, 0x34, 0xd2, 0x1e, 0x42, 0xac, 0x33, 0x96, 0x0b, 0xd1, 0x38, 0xe5, 0x0d, 0x32,
					0x11, 0x1e, 0x4c, 0xaf, 0x23, 0x7e, 0xe5, 0x3c, 0xa8, 0xad, 0x64, 0x26, 0x19, 0x4a, 0x88, 0x54,
					0x5d, 0xdc, 0x49, 0x7a, 0x0b, 0x46, 0x6e, 0x7d, 0x6b, 0xbd, 0xb0, 0x04, 0x1b, 0x2f, 0x58, 0x6b,
				],
			},
			TestVector {
				key: [
					0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
					0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
				],
				nonce: [0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07],
				keystream: vec![
					0xf7, 0x98, 0xa1, 0x89, 0xf1, 0x95, 0xe6, 0x69, 0x82, 0x10, 0x5f, 0xfb, 0x64, 0x0b, 0xb7, 0x75,
					0x7f, 0x57, 0x9d, 0xa3, 0x16, 0x02, 0xfc, 0x93, 0xec, 0x01, 0xac, 0x56, 0xf8, 0x5a, 0xc3, 0xc1,
					0x34, 0xa4, 0x54, 0x7b, 0x73, 0x3b, 0x46, 0x41, 0x30, 0x42, 0xc9, 0x44, 0x00, 0x49, 0x17, 0x69,
					0x05, 0xd3, 0xbe, 0x59, 0xea, 0x1c, 0x53, 0xf1, 0x59, 0x16, 0x15, 0x5c, 0x2b, 0xe8, 0x24, 0x1a,
					0x38, 0x00, 0x8b, 0x9a, 0x26, 0xbc, 0x35, 0x94, 0x1e, 0x24, 0x44, 0x17, 0x7c, 0x8a, 0xde, 0x66,
					0x89, 0xde, 0x95, 0x26, 0x49, 0x86, 0xd9, 0x58, 0x89, 0xfb, 0x60, 0xe8, 0x46, 0x29, 0xc9, 0xbd,
					0x9a, 0x5a, 0xcb, 0x1c, 0xc1, 0x18, 0xbe, 0x56, 0x3e, 0xb9, 0xb3, 0xa4, 0xa4, 0x72, 0xf8, 0x2e,
					0x09, 0xa7, 0xe7, 0x78, 0x49, 0x2b, 0x56, 0x2e, 0xf7, 0x13, 0x0e, 0x88, 0xdf, 0xe0, 0x31, 0xc7,
					0x9d, 0xb9, 0xd4, 0xf7, 0xc7, 0xa8, 0x99, 0x15, 0x1b, 0x9a, 0x47, 0x50, 0x32, 0xb6, 0x3f, 0xc3,
					0x85, 0x24, 0x5f, 0xe0, 0x54, 0xe3, 0xdd, 0x5a, 0x97, 0xa5, 0xf5, 0x76, 0xfe, 0x06, 0x40, 0x25,
					0xd3, 0xce, 0x04, 0x2c, 0x56, 0x6a, 0xb2, 0xc5, 0x07, 0xb1, 0x38, 0xdb, 0x85, 0x3e, 0x3d, 0x69,
					0x59, 0x66, 0x09, 0x96, 0x54, 0x6c, 0xc9, 0xc4, 0xa6, 0xea, 0xfd, 0xc7, 0x77, 0xc0, 0x40, 0xd7,
					0x0e, 0xaf, 0x46, 0xf7, 0x6d, 0xad, 0x39, 0x79, 0xe5, 0xc5, 0x36, 0x0c, 0x33, 0x17, 0x16, 0x6a,
					0x1c, 0x89, 0x4c, 0x94, 0xa3, 0x71, 0x87, 0x6a, 0x94, 0xdf, 0x76, 0x28, 0xfe, 0x4e, 0xaa, 0xf2,
					0xcc, 0xb2, 0x7d, 0x5a, 0xaa, 0xe0, 0xad, 0x7a, 0xd0, 0xf9, 0xd4, 0xb6, 0xad, 0x3b, 0x54, 0x09,
					0x87, 0x46, 0xd4, 0x52, 0x4d, 0x38, 0x40, 0x7a, 0x6d, 0xeb, 0x3a, 0xb7, 0x8f, 0xab, 0x78, 0xc9,
				],
			},
		];

		for tv in test_vectors.iter() {
			let mut c = ChaCha20::new(&tv.key, &tv.nonce);
			let input: Vec<u8> = repeat(0).take(tv.keystream.len()).collect();
			let mut output: Vec<u8> = repeat(0).take(input.len()).collect();
			c.process(&input[..], &mut output[..]);
			assert_eq!(output, tv.keystream);
		}
	}
}
