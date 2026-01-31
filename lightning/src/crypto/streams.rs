use crate::crypto::fixed_time_eq;

use crate::io::{self, Read, Write};
use crate::ln::msgs::DecodeError;
use crate::util::ser::{
	FixedLengthReader, LengthLimitedRead, LengthReadableArgs, Readable, Writeable, Writer,
};

use alloc::vec::Vec;
use chacha20_poly1305::{
	chacha20::{ChaCha20, Key, Nonce},
	poly1305::Poly1305,
};

pub(crate) struct ChaChaReader<'a, R: io::Read> {
	pub chacha: &'a mut ChaCha20,
	pub read: R,
}
impl<'a, R: io::Read> io::Read for ChaChaReader<'a, R> {
	fn read(&mut self, dest: &mut [u8]) -> Result<usize, io::Error> {
		let res = self.read.read(dest)?;
		if res > 0 {
			self.chacha.apply_keystream(&mut dest[..res]);
		}
		Ok(res)
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
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		let mut chacha = ChaCha20::new(Key::new(self.rho), Nonce::new([0; 12]), 0);
		let mut mac_key = [0u8; 64];
		chacha.apply_keystream(&mut mac_key);

		#[cfg(not(fuzzing))]
		let mac = Poly1305::new(mac_key[..32].try_into().unwrap());
		#[cfg(fuzzing)]
		let mac = Poly1305::new(self.rho);

		let mut chacha_stream =
			ChaChaPolyWriter { chacha: &mut chacha, poly: mac, write_len: 0, write: w };
		self.writeable.write(&mut chacha_stream)?;

		let tag = chacha_stream.finish_and_get_tag();
		tag.write(w)?;

		Ok(())
	}

	fn serialized_length(&self) -> usize {
		self.writeable.serialized_length() + 16
	}
}

/// Encrypts the provided plaintext with the given key using ChaCha20Poly1305 in the modified
/// with-AAD form used in [`ChaChaDualPolyReadAdapter`].
pub(crate) fn chachapoly_encrypt_with_swapped_aad(
	mut plaintext: Vec<u8>, key: [u8; 32], aad: [u8; 32],
) -> Vec<u8> {
	let mut chacha = ChaCha20::new(Key::new(key), Nonce::new([0; 12]), 0);
	let mut mac_key = [0u8; 64];
	chacha.apply_keystream(&mut mac_key);

	let mut mac = Poly1305::new(mac_key[..32].try_into().unwrap());
	chacha.apply_keystream(&mut plaintext[..]);
	mac.input(&plaintext[..]);

	if plaintext.len() % 16 != 0 {
		mac.input(&[0; 16][0..16 - (plaintext.len() % 16)]);
	}

	mac.input(&aad[..]);
	// Note that we don't need to pad the AAD since its a multiple of 16 bytes

	mac.input(&(plaintext.len() as u64).to_le_bytes());
	mac.input(&32u64.to_le_bytes());

	plaintext.extend_from_slice(&mac.tag());
	plaintext
}

/// Enables the use of the serialization macros for objects that need to be simultaneously decrypted
/// and deserialized. This allows us to avoid an intermediate Vec allocation.
///
/// This variant of [`ChaChaPolyReadAdapter`] calculates Poly1305 tags twice, once using the given
/// key and once with the given 32-byte AAD appended after the encrypted stream, accepting either
/// being correct as sufficient.
///
/// Note that we do *not* use the provided AAD as the standard ChaCha20Poly1305 AAD as that would
/// require placing it first and prevent us from avoiding redundant Poly1305 rounds. Instead, the
/// ChaCha20Poly1305 MAC check is tweaked to move the AAD to *after* the contents being
/// checked, effectively treating the contents as the AAD for the AAD-containing MAC but behaving
/// like classic ChaCha20Poly1305 for the non-AAD-containing MAC.
pub(crate) struct ChaChaDualPolyReadAdapter<R: Readable> {
	pub readable: R,
	pub used_aad: bool,
}

impl<T: Readable> LengthReadableArgs<([u8; 32], [u8; 32])> for ChaChaDualPolyReadAdapter<T> {
	// Simultaneously read and decrypt an object from a LengthLimitedRead storing it in
	// Self::readable. LengthLimitedRead must be used instead of std::io::Read because we need the
	// total length to separate out the tag at the end.
	fn read<R: LengthLimitedRead>(
		r: &mut R, params: ([u8; 32], [u8; 32]),
	) -> Result<Self, DecodeError> {
		if r.remaining_bytes() < 16 {
			return Err(DecodeError::InvalidValue);
		}
		let (key, aad) = params;

		let mut chacha = ChaCha20::new(Key::new(key), Nonce::new([0; 12]), 0);
		let mut mac_key = [0u8; 64];
		chacha.apply_keystream(&mut mac_key);

		#[cfg(not(fuzzing))]
		let mut mac = Poly1305::new(mac_key[..32].try_into().unwrap());
		#[cfg(not(fuzzing))]
		let mut mac_aad = Poly1305::new(mac_key[..32].try_into().unwrap());
		#[cfg(fuzzing)]
		let mut mac = Poly1305::new(key);
		#[cfg(fuzzing)]
		let mut mac_aad = Poly1305::new(key);

		let decrypted_len = r.remaining_bytes() - 16;
		let s = FixedLengthReader::new(r, decrypted_len);
		let mut chacha_stream = ChaChaDualPolyReader {
			chacha: &mut chacha,
			poly: &mut mac,
			poly_aad: &mut mac_aad,
			read_len: 0,
			read: s,
		};

		let readable: T = Readable::read(&mut chacha_stream)?;
		while chacha_stream.read.bytes_remain() {
			let mut buf = [0; 256];
			if chacha_stream.read(&mut buf)? == 0 {
				return Err(DecodeError::ShortRead);
			}
		}

		let read_len = chacha_stream.read_len;

		if read_len % 16 != 0 {
			let padding = &[0; 16][0..16 - (read_len % 16)];
			mac.input(padding);
			mac_aad.input(padding);
		}

		mac_aad.input(&aad[..]);
		// Note that we don't need to pad the AAD since its a multiple of 16 bytes

		// For the AAD-containing MAC, swap the AAD and the read data, effectively.
		mac_aad.input(&(read_len as u64).to_le_bytes());
		mac_aad.input(&32u64.to_le_bytes());

		// For the non-AAD-containing MAC, leave the data and AAD where they belong.
		mac.input(&0u64.to_le_bytes());
		mac.input(&(read_len as u64).to_le_bytes());

		let mut tag = [0u8; 16];
		r.read_exact(&mut tag)?;
		if fixed_time_eq(&mac.tag(), &tag) {
			Ok(Self { readable, used_aad: false })
		} else if fixed_time_eq(&mac_aad.tag(), &tag) {
			Ok(Self { readable, used_aad: true })
		} else {
			return Err(DecodeError::InvalidValue);
		}
	}
}

struct ChaChaDualPolyReader<'a, R: Read> {
	chacha: &'a mut ChaCha20,
	poly: &'a mut Poly1305,
	poly_aad: &'a mut Poly1305,
	read_len: usize,
	pub read: R,
}

impl<'a, R: Read> Read for ChaChaDualPolyReader<'a, R> {
	// Decrypts bytes from Self::read into `dest`.
	// After all reads complete, the caller must compare the expected tag with
	// the result of `Poly1305::tag()`
	fn read(&mut self, dest: &mut [u8]) -> Result<usize, io::Error> {
		let res = self.read.read(dest)?;
		if res > 0 {
			self.poly.input(&dest[..res]);
			self.poly_aad.input(&dest[..res]);
			self.chacha.apply_keystream(&mut dest[..res]);
			self.read_len += res;
		}
		Ok(res)
	}
}

/// Enables the use of the serialization macros for objects that need to be simultaneously decrypted and
/// deserialized. This allows us to avoid an intermediate Vec allocation.
pub(crate) struct ChaChaPolyReadAdapter<R: Readable> {
	pub readable: R,
}

impl<T: Readable> LengthReadableArgs<[u8; 32]> for ChaChaPolyReadAdapter<T> {
	// Simultaneously read and decrypt an object from a LengthLimitedRead storing it in
	// Self::readable. LengthLimitedRead must be used instead of std::io::Read because we need the
	// total length to separate out the tag at the end.
	fn read<R: LengthLimitedRead>(r: &mut R, secret: [u8; 32]) -> Result<Self, DecodeError> {
		if r.remaining_bytes() < 16 {
			return Err(DecodeError::InvalidValue);
		}

		let mut chacha = ChaCha20::new(Key::new(secret), Nonce::new([0; 12]), 0);
		let mut mac_key = [0u8; 64];
		chacha.apply_keystream(&mut mac_key);

		#[cfg(not(fuzzing))]
		let mut mac = Poly1305::new(mac_key[..32].try_into().unwrap());
		#[cfg(fuzzing)]
		let mut mac = Poly1305::new(secret);

		let decrypted_len = r.remaining_bytes() - 16;
		let s = FixedLengthReader::new(r, decrypted_len);
		let mut chacha_stream = ChaChaPolyReader::new(&mut chacha, &mut mac, s);
		let readable: T = Readable::read(&mut chacha_stream)?;
		while chacha_stream.read.bytes_remain() {
			let mut buf = [0; 256];
			chacha_stream.read(&mut buf)?;
		}

		let read_len = chacha_stream.read_len();
		drop(chacha_stream);

		if read_len % 16 != 0 {
			mac.input(&[0; 16][0..16 - (read_len % 16)]);
		}
		mac.input(&0u64.to_le_bytes());
		mac.input(&(read_len as u64).to_le_bytes());

		let mut tag = [0u8; 16];
		r.read_exact(&mut tag)?;
		if !fixed_time_eq(&mac.tag(), &tag) {
			return Err(DecodeError::InvalidValue);
		}

		Ok(Self { readable })
	}
}

/// Enables simultaneously reading and decrypting a ChaCha20Poly1305 stream from a std::io::Read.
struct ChaChaPolyReader<'a, R: Read> {
	chacha: &'a mut ChaCha20,
	poly: &'a mut Poly1305,
	read_len: usize,
	pub read: R,
}

impl<'a, R: Read> ChaChaPolyReader<'a, R> {
	fn new(chacha: &'a mut ChaCha20, poly: &'a mut Poly1305, read: R) -> Self {
		Self { chacha, poly, read_len: 0, read }
	}

	fn read_len(&self) -> usize {
		self.read_len
	}
}

impl<'a, R: Read> Read for ChaChaPolyReader<'a, R> {
	// Decrypt bytes from Self::read into `dest`.
	fn read(&mut self, dest: &mut [u8]) -> Result<usize, io::Error> {
		let res = self.read.read(dest)?;
		if res > 0 {
			self.poly.input(&dest[..res]);
			self.chacha.apply_keystream(&mut dest[..res]);
			self.read_len += res;
		}
		Ok(res)
	}
}

/// Enables simultaneously writing and encrypting a byte stream into a Writer.
struct ChaChaPolyWriter<'a, W: Writer> {
	chacha: &'a mut ChaCha20,
	poly: Poly1305,
	write_len: usize,
	pub write: &'a mut W,
}

impl<'a, W: Writer> ChaChaPolyWriter<'a, W> {
	/// Finish encrypting and return the 16-byte authentication tag.
	fn finish_and_get_tag(mut self) -> [u8; 16] {
		if self.write_len % 16 != 0 {
			self.poly.input(&[0; 16][0..16 - (self.write_len % 16)]);
		}
		self.poly.input(&0u64.to_le_bytes());
		self.poly.input(&(self.write_len as u64).to_le_bytes());
		self.poly.tag()
	}
}

impl<'a, W: Writer> Writer for ChaChaPolyWriter<'a, W> {
	// Encrypt then write bytes from `src` into Self::write.
	fn write_all(&mut self, src: &[u8]) -> Result<(), io::Error> {
		let mut src_idx = 0;
		while src_idx < src.len() {
			let mut write_buffer = [0; 8192];
			let bytes_written = (&mut write_buffer[..])
				.write(&src[src_idx..])
				.expect("In-memory writes can't fail");
			self.chacha.apply_keystream(&mut write_buffer[..bytes_written]);
			self.poly.input(&write_buffer[..bytes_written]);
			self.write.write_all(&write_buffer[..bytes_written])?;
			self.write_len += bytes_written;
			src_idx += bytes_written;
		}
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::{ChaChaPolyReadAdapter, ChaChaPolyWriteAdapter};
	use crate::ln::msgs::DecodeError;
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
				let encrypted_writeable = &mut &encrypted_writeable_bytes[..];

				// Now deserialize the object back and make sure it matches the original.
				let mut rd = FixedLengthReader::new(encrypted_writeable, writeable_len);
				let read_adapter =
					<ChaChaPolyReadAdapter<TestWriteable>>::read(&mut rd, rho).unwrap();
				assert_eq!($obj, read_adapter.readable);
			};
		}

		// Try a big object that will require multiple write buffers.
		let big_writeable =
			TestWriteable { field1: vec![43], field2: vec![44; 4192], field3: vec![45; 4192 + 1] };
		check_object_read_write!(big_writeable);

		// Try a small object that fits into one write buffer.
		let small_writeable =
			TestWriteable { field1: vec![43], field2: vec![44], field3: vec![45] };
		check_object_read_write!(small_writeable);
	}

	fn do_chacha_stream_adapters_ser_macros() -> Result<(), DecodeError> {
		let writeable =
			TestWriteable { field1: vec![43], field2: vec![44; 4192], field3: vec![45; 4192 + 1] };

		// First, serialize the object into a TLV stream, encrypted with ChaCha20Poly1305.
		let rho = [42; 32];
		let write_adapter = ChaChaPolyWriteAdapter::new(rho, &writeable);
		let mut writer = ser::VecWriter(Vec::new());
		encode_tlv_stream!(&mut writer, {
			(1, write_adapter, required),
		});

		// Now deserialize the object back and make sure it matches the original.
		let mut read_adapter: Option<ChaChaPolyReadAdapter<TestWriteable>> = None;
		decode_tlv_stream!(&mut &writer.0[..], {
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

	#[test]
	fn short_read_chacha_dual_read_adapter() {
		// Previously, if we attempted to read from a ChaChaDualPolyReadAdapter but the object
		// being read is shorter than the available buffer while the buffer passed to
		// ChaChaDualPolyReadAdapter itself always thinks it has room, we'd end up
		// infinite-looping as we didn't handle `Read::read`'s 0 return values at EOF.
		let mut stream = &[0; 1024][..];
		let mut too_long_stream = FixedLengthReader::new(&mut stream, 2048);
		let keys = ([42; 32], [99; 32]);
		let res = super::ChaChaDualPolyReadAdapter::<u8>::read(&mut too_long_stream, keys);
		match res {
			Ok(_) => panic!(),
			Err(e) => assert_eq!(e, DecodeError::ShortRead),
		}
	}
}
