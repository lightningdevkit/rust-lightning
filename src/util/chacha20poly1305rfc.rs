// ring has a garbage API so its use is avoided, but rust-crypto doesn't have RFC-variant poly1305
// Instead, we steal rust-crypto's implementation and tweak it to match the RFC.

// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// This is a port of Andrew Moons poly1305-donna
// https://github.com/floodyberry/poly1305-donna

#[cfg(not(feature = "fuzztarget"))]
mod real_chachapoly {
	use util::chacha20::ChaCha20;
	use util::poly1305::Poly1305;
	use bitcoin_hashes::cmp::fixed_time_eq;

	use util::byte_utils;

	#[derive(Clone, Copy)]
	pub struct ChaCha20Poly1305RFC {
		cipher: ChaCha20,
		mac: Poly1305,
		finished: bool,
		data_len: usize,
		aad_len: u64,
	}

	impl ChaCha20Poly1305RFC {
		#[inline]
		fn pad_mac_16(mac: &mut Poly1305, len: usize) {
			if len % 16 != 0 {
				mac.input(&[0; 16][0..16 - (len % 16)]);
			}
		}
		pub fn new(key: &[u8], nonce: &[u8], aad: &[u8]) -> ChaCha20Poly1305RFC {
			assert!(key.len() == 16 || key.len() == 32);
			assert!(nonce.len() == 12);

			// Ehh, I'm too lazy to *also* tweak ChaCha20 to make it RFC-compliant
			assert!(nonce[0] == 0 && nonce[1] == 0 && nonce[2] == 0 && nonce[3] == 0);

			let mut cipher = ChaCha20::new(key, &nonce[4..]);
			let mut mac_key = [0u8; 64];
			let zero_key = [0u8; 64];
			cipher.process(&zero_key, &mut mac_key);

			let mut mac = Poly1305::new(&mac_key[..32]);
			mac.input(aad);
			ChaCha20Poly1305RFC::pad_mac_16(&mut mac, aad.len());

			ChaCha20Poly1305RFC {
				cipher: cipher,
				mac: mac,
				finished: false,
				data_len: 0,
				aad_len: aad.len() as u64,
			}
		}

		pub fn encrypt(&mut self, input: &[u8], output: &mut [u8], out_tag: &mut [u8]) {
			assert!(input.len() == output.len());
			assert!(self.finished == false);
			self.cipher.process(input, output);
			self.data_len += input.len();
			self.mac.input(output);
			ChaCha20Poly1305RFC::pad_mac_16(&mut self.mac, self.data_len);
			self.finished = true;
			self.mac.input(&byte_utils::le64_to_array(self.aad_len));
			self.mac.input(&byte_utils::le64_to_array(self.data_len as u64));
			self.mac.raw_result(out_tag);
		}

		pub fn decrypt(&mut self, input: &[u8], output: &mut [u8], tag: &[u8]) -> bool {
			assert!(input.len() == output.len());
			assert!(self.finished == false);

			self.finished = true;

			self.mac.input(input);

			self.data_len += input.len();
			ChaCha20Poly1305RFC::pad_mac_16(&mut self.mac, self.data_len);
			self.mac.input(&byte_utils::le64_to_array(self.aad_len));
			self.mac.input(&byte_utils::le64_to_array(self.data_len as u64));

			let mut calc_tag =  [0u8; 16];
			self.mac.raw_result(&mut calc_tag);
			if fixed_time_eq(&calc_tag, tag) {
				self.cipher.process(input, output);
				true
			} else {
				false
			}
		}
	}
}
#[cfg(not(feature = "fuzztarget"))]
pub use self::real_chachapoly::ChaCha20Poly1305RFC;

#[cfg(feature = "fuzztarget")]
mod fuzzy_chachapoly {
	#[derive(Clone, Copy)]
	pub struct ChaCha20Poly1305RFC {
		tag: [u8; 16],
		finished: bool,
	}
	impl ChaCha20Poly1305RFC {
		pub fn new(key: &[u8], nonce: &[u8], _aad: &[u8]) -> ChaCha20Poly1305RFC {
			assert!(key.len() == 16 || key.len() == 32);
			assert!(nonce.len() == 12);

			// Ehh, I'm too lazy to *also* tweak ChaCha20 to make it RFC-compliant
			assert!(nonce[0] == 0 && nonce[1] == 0 && nonce[2] == 0 && nonce[3] == 0);

			let mut tag = [0; 16];
			tag.copy_from_slice(&key[0..16]);

			ChaCha20Poly1305RFC {
				tag,
				finished: false,
			}
		}

		pub fn encrypt(&mut self, input: &[u8], output: &mut [u8], out_tag: &mut [u8]) {
			assert!(input.len() == output.len());
			assert!(self.finished == false);

			output.copy_from_slice(&input);
			out_tag.copy_from_slice(&self.tag);
			self.finished = true;
		}

		pub fn decrypt(&mut self, input: &[u8], output: &mut [u8], tag: &[u8]) -> bool {
			assert!(input.len() == output.len());
			assert!(self.finished == false);

			if tag[..] != self.tag[..] { return false; }
			output.copy_from_slice(input);
			self.finished = true;
			true
		}
	}
}
#[cfg(feature = "fuzztarget")]
pub use self::fuzzy_chachapoly::ChaCha20Poly1305RFC;
