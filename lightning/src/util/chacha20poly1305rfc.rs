// ring has a garbage API so its use is avoided, but rust-crypto doesn't have RFC-variant poly1305
// Instead, we steal rust-crypto's implementation and tweak it to match the RFC.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.
//
// This is a port of Andrew Moons poly1305-donna
// https://github.com/floodyberry/poly1305-donna

use crate::ln::msgs::DecodeError;
use crate::util::ser::{FixedLengthReader, LengthRead, LengthReadableArgs, Readable, Writeable, Writer};
use crate::io::{self, Read, Write};

#[cfg(not(fuzzing))]
mod real_chachapoly {
	use crate::util::chacha20::ChaCha20;
	use crate::util::poly1305::Poly1305;
	use bitcoin::hashes::cmp::fixed_time_eq;

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
				cipher,
				mac,
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
			self.mac.input(&self.aad_len.to_le_bytes());
			self.mac.input(&(self.data_len as u64).to_le_bytes());
			self.mac.raw_result(out_tag);
		}

		pub fn encrypt_full_message_in_place(&mut self, input_output: &mut [u8], out_tag: &mut [u8]) {
			self.encrypt_in_place(input_output);
			self.finish_and_get_tag(out_tag);
		}

		// Encrypt `input_output` in-place. To finish and calculate the tag, use `finish_and_get_tag`
		// below.
		pub(super) fn encrypt_in_place(&mut self, input_output: &mut [u8]) {
			debug_assert!(self.finished == false);
			self.cipher.process_in_place(input_output);
			self.data_len += input_output.len();
			self.mac.input(input_output);
		}

		// If we were previously encrypting with `encrypt_in_place`, this method can be used to finish
		// encrypting and calculate the tag.
		pub(super) fn finish_and_get_tag(&mut self, out_tag: &mut [u8]) {
			debug_assert!(self.finished == false);
			ChaCha20Poly1305RFC::pad_mac_16(&mut self.mac, self.data_len);
			self.finished = true;
			self.mac.input(&self.aad_len.to_le_bytes());
			self.mac.input(&(self.data_len as u64).to_le_bytes());
			self.mac.raw_result(out_tag);
		}

		pub fn decrypt(&mut self, input: &[u8], output: &mut [u8], tag: &[u8]) -> bool {
			assert!(input.len() == output.len());
			assert!(self.finished == false);

			self.finished = true;

			self.mac.input(input);

			self.data_len += input.len();
			ChaCha20Poly1305RFC::pad_mac_16(&mut self.mac, self.data_len);
			self.mac.input(&self.aad_len.to_le_bytes());
			self.mac.input(&(self.data_len as u64).to_le_bytes());

			let mut calc_tag =  [0u8; 16];
			self.mac.raw_result(&mut calc_tag);
			if fixed_time_eq(&calc_tag, tag) {
				self.cipher.process(input, output);
				true
			} else {
				false
			}
		}

		pub fn check_decrypt_in_place(&mut self, input_output: &mut [u8], tag: &[u8]) -> Result<(), ()> {
			self.decrypt_in_place(input_output);
			if self.finish_and_check_tag(tag) { Ok(()) } else { Err(()) }
		}

		/// Decrypt in place, without checking the tag. Use `finish_and_check_tag` to check it
		/// later when decryption finishes.
		///
		/// Should never be `pub` because the public API should always enforce tag checking.
		pub(super) fn decrypt_in_place(&mut self, input_output: &mut [u8]) {
			debug_assert!(self.finished == false);
			self.mac.input(input_output);
			self.data_len += input_output.len();
			self.cipher.process_in_place(input_output);
		}

		/// If we were previously decrypting with `just_decrypt_in_place`, this method must be used
		/// to check the tag. Returns whether or not the tag is valid.
		pub(super) fn finish_and_check_tag(&mut self, tag: &[u8]) -> bool {
			debug_assert!(self.finished == false);
			self.finished = true;
			ChaCha20Poly1305RFC::pad_mac_16(&mut self.mac, self.data_len);
			self.mac.input(&self.aad_len.to_le_bytes());
			self.mac.input(&(self.data_len as u64).to_le_bytes());

			let mut calc_tag =  [0u8; 16];
			self.mac.raw_result(&mut calc_tag);
			if fixed_time_eq(&calc_tag, tag) {
				true
			} else {
				false
			}
		}
	}
}
#[cfg(not(fuzzing))]
pub use self::real_chachapoly::ChaCha20Poly1305RFC;

/// Enables simultaneously reading and decrypting a ChaCha20Poly1305RFC stream from a std::io::Read.
struct ChaChaPolyReader<'a, R: Read> {
	pub chacha: &'a mut ChaCha20Poly1305RFC,
	pub read: R,
}

impl<'a, R: Read> Read for ChaChaPolyReader<'a, R> {
	// Decrypt bytes from Self::read into `dest`.
	// `ChaCha20Poly1305RFC::finish_and_check_tag` must be called to check the tag after all reads
	// complete.
	fn read(&mut self, dest: &mut [u8]) -> Result<usize, io::Error> {
		let res = self.read.read(dest)?;
		if res > 0 {
			self.chacha.decrypt_in_place(&mut dest[0..res]);
		}
		Ok(res)
	}
}

/// Enables simultaneously writing and encrypting a byte stream into a Writer.
struct ChaChaPolyWriter<'a, W: Writer> {
	pub chacha: &'a mut ChaCha20Poly1305RFC,
	pub write: &'a mut W,
}

impl<'a, W: Writer> Writer for ChaChaPolyWriter<'a, W> {
	// Encrypt then write bytes from `src` into Self::write.
	// `ChaCha20Poly1305RFC::finish_and_get_tag` can be called to retrieve the tag after all writes
	// complete.
	fn write_all(&mut self, src: &[u8]) -> Result<(), io::Error> {
		let mut src_idx = 0;
		while src_idx < src.len() {
			let mut write_buffer = [0; 8192];
			let bytes_written = (&mut write_buffer[..]).write(&src[src_idx..]).expect("In-memory writes can't fail");
			self.chacha.encrypt_in_place(&mut write_buffer[..bytes_written]);
			self.write.write_all(&write_buffer[..bytes_written])?;
			src_idx += bytes_written;
		}
		Ok(())
	}
}

/// Enables the use of the serialization macros for objects that need to be simultaneously encrypted and
/// serialized. This allows us to avoid an intermediate Vec allocation.
pub(crate) struct ChaChaPolyWriteAdapter<'a, W: Writeable> {
	pub rho: [u8; 32],
	pub writeable: &'a W,
}

impl<'a, W: Writeable> ChaChaPolyWriteAdapter<'a, W> {
	#[allow(unused)] // This will be used for onion messages soon
	pub fn new(rho: [u8; 32], writeable: &'a W) -> ChaChaPolyWriteAdapter<'a, W> {
		Self { rho, writeable }
	}
}

impl<'a, T: Writeable> Writeable for ChaChaPolyWriteAdapter<'a, T> {
	// Simultaneously write and encrypt Self::writeable.
	fn write(&self, w: &mut impl Writer) -> Result<(), io::Error> {
		let mut chacha = ChaCha20Poly1305RFC::new(&self.rho, &[0; 12], &[]);
		let mut chacha_stream = ChaChaPolyWriter { chacha: &mut chacha, write: w };
		self.writeable.write(&mut chacha_stream)?;
		let mut tag = [0 as u8; 16];
		chacha.finish_and_get_tag(&mut tag);
		tag.write(w)?;

		Ok(())
	}
}

/// Enables the use of the serialization macros for objects that need to be simultaneously decrypted and
/// deserialized. This allows us to avoid an intermediate Vec allocation.
pub(crate) struct ChaChaPolyReadAdapter<R: Readable> {
	pub readable: R,
}

impl<T: Readable> LengthReadableArgs<[u8; 32]> for ChaChaPolyReadAdapter<T> {
	// Simultaneously read and decrypt an object from a LengthRead, storing it in Self::readable.
	// LengthRead must be used instead of std::io::Read because we need the total length to separate
	// out the tag at the end.
	fn read<R: LengthRead>(mut r: &mut R, secret: [u8; 32]) -> Result<Self, DecodeError> {
		if r.total_bytes() < 16 { return Err(DecodeError::InvalidValue) }

		let mut chacha = ChaCha20Poly1305RFC::new(&secret, &[0; 12], &[]);
		let decrypted_len = r.total_bytes() - 16;
		let s = FixedLengthReader::new(&mut r, decrypted_len);
		let mut chacha_stream = ChaChaPolyReader { chacha: &mut chacha, read: s };
		let readable: T = Readable::read(&mut chacha_stream)?;
		chacha_stream.read.eat_remaining()?;

		let mut tag = [0 as u8; 16];
		r.read_exact(&mut tag)?;
		if !chacha.finish_and_check_tag(&tag) {
			return Err(DecodeError::InvalidValue)
		}

		Ok(Self { readable })
	}
}

#[cfg(fuzzing)]
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

		pub fn encrypt_full_message_in_place(&mut self, input_output: &mut [u8], out_tag: &mut [u8]) {
			self.encrypt_in_place(input_output);
			self.finish_and_get_tag(out_tag);
		}

		pub(super) fn encrypt_in_place(&mut self, _input_output: &mut [u8]) {
			assert!(self.finished == false);
		}

		pub(super) fn finish_and_get_tag(&mut self, out_tag: &mut [u8]) {
			assert!(self.finished == false);
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

		pub fn check_decrypt_in_place(&mut self, input_output: &mut [u8], tag: &[u8]) -> Result<(), ()> {
			self.decrypt_in_place(input_output);
			if self.finish_and_check_tag(tag) { Ok(()) } else { Err(()) }
		}

		pub(super) fn decrypt_in_place(&mut self, _input: &mut [u8]) {
			assert!(self.finished == false);
		}

		pub(super) fn finish_and_check_tag(&mut self, tag: &[u8]) -> bool {
			if tag[..] != self.tag[..] { return false; }
			self.finished = true;
			true
		}
	}
}
#[cfg(fuzzing)]
pub use self::fuzzy_chachapoly::ChaCha20Poly1305RFC;

#[cfg(test)]
mod tests {
	use crate::ln::msgs::DecodeError;
	use super::{ChaChaPolyReadAdapter, ChaChaPolyWriteAdapter};
	use crate::util::ser::{self, FixedLengthReader, LengthReadableArgs, Writeable};

	// Used for for testing various lengths of serialization.
	#[derive(Debug, PartialEq, Eq)]
	struct TestWriteable {
		field1: Vec<u8>,
		field2: Vec<u8>,
		field3: Vec<u8>,
	}
	impl_writeable_tlv_based!(TestWriteable, {
		(1, field1, required_vec),
		(2, field2, required_vec),
		(3, field3, required_vec),
	});

	#[test]
	fn test_chacha_stream_adapters() {
		// Check that ChaChaPolyReadAdapter and ChaChaPolyWriteAdapter correctly encode and decode an
		// encrypted object.
		macro_rules! check_object_read_write {
			($obj: expr) => {
				// First, serialize the object, encrypted with ChaCha20Poly1305.
				let rho = [42; 32];
				let writeable_len = $obj.serialized_length() as u64 + 16;
				let write_adapter = ChaChaPolyWriteAdapter::new(rho, &$obj);
				let encrypted_writeable_bytes = write_adapter.encode();
				let encrypted_writeable = &encrypted_writeable_bytes[..];

				// Now deserialize the object back and make sure it matches the original.
				let mut rd = FixedLengthReader::new(encrypted_writeable, writeable_len);
				let read_adapter = <ChaChaPolyReadAdapter<TestWriteable>>::read(&mut rd, rho).unwrap();
				assert_eq!($obj, read_adapter.readable);
			};
		}

		// Try a big object that will require multiple write buffers.
		let big_writeable = TestWriteable {
			field1: vec![43],
			field2: vec![44; 4192],
			field3: vec![45; 4192 + 1],
		};
		check_object_read_write!(big_writeable);

		// Try a small object that fits into one write buffer.
		let small_writeable = TestWriteable {
			field1: vec![43],
			field2: vec![44],
			field3: vec![45],
		};
		check_object_read_write!(small_writeable);
	}

	fn do_chacha_stream_adapters_ser_macros() -> Result<(), DecodeError> {
		let writeable = TestWriteable {
			field1: vec![43],
			field2: vec![44; 4192],
			field3: vec![45; 4192 + 1],
		};

		// First, serialize the object into a TLV stream, encrypted with ChaCha20Poly1305.
		let rho = [42; 32];
		let write_adapter = ChaChaPolyWriteAdapter::new(rho, &writeable);
		let mut writer = ser::VecWriter(Vec::new());
		encode_tlv_stream!(&mut writer, {
			(1, write_adapter, required),
		});

		// Now deserialize the object back and make sure it matches the original.
		let mut read_adapter: Option<ChaChaPolyReadAdapter<TestWriteable>> = None;
		decode_tlv_stream!(&writer.0[..], {
			(1, read_adapter, (option: LengthReadableArgs, rho)),
		});
		assert_eq!(writeable, read_adapter.unwrap().readable);

		Ok(())
	}

	#[test]
	fn chacha_stream_adapters_ser_macros() {
		// Test that our stream adapters work as expected with the TLV macros.
		// This also serves to test the `option: $trait` variant of the `_decode_tlv` ser macro.
		do_chacha_stream_adapters_ser_macros().unwrap()
	}
}
