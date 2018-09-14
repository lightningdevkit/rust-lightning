use std::result::Result;
use std::io::Read;
use std::collections::HashMap;
use std::hash::Hash;
use std::mem;

use secp256k1::{Secp256k1, Signature};
use secp256k1::key::PublicKey;
use bitcoin::util::hash::Sha256dHash;
use bitcoin::blockdata::script::Script;
use std::marker::Sized;
use ln::msgs::DecodeError;

use util::byte_utils::{be64_to_array, be32_to_array, be16_to_array, slice_to_be16, slice_to_be32, slice_to_be64};

const MAX_BUF_SIZE: usize = 64 * 1024;

/// A trait that is similar to std::io::Write.
/// An impl is provided for any type that also impls std::io::Write.
pub trait Writer {
	/// Writes the given buf out. See std::io::Write::write_all for more
	fn write_all(&mut self, buf: &[u8]) -> Result<(), ::std::io::Error>;
}

impl<W: ::std::io::Write> Writer for W {
	fn write_all(&mut self, buf: &[u8]) -> Result<(), ::std::io::Error> {
		<Self as ::std::io::Write>::write_all(self, buf)
	}
}

/// A trait that various rust-lightning types implement allowing them to be written out to a Writer
pub trait Writeable<W: Writer> {
	/// Writes self out to the given Writer
	fn write(&self, writer: &mut W) -> Result<(), DecodeError>;
}

/// A trait that various rust-lightning types implement allowing them to be read in from a Read
pub trait Readable<R>
	where Self: Sized,
	      R: Read
{
	/// Reads a Self in from the given Read
	fn read(reader: &mut R) -> Result<Self, DecodeError>;
}

macro_rules! impl_writeable_primitive {
	($val_type:ty, $meth_write:ident, $len: expr, $meth_read:ident) => {
		impl<W: Writer> Writeable<W> for $val_type {
			#[inline]
			fn write(&self, writer: &mut W) -> Result<(), DecodeError> {
				Ok(writer.write_all(&$meth_write(*self))?)
			}
		}
		impl<R: Read> Readable<R> for $val_type {
			#[inline]
			fn read(reader: &mut R) -> Result<$val_type, DecodeError> {
				let mut buf = [0; $len];
				reader.read_exact(&mut buf)?;
				Ok($meth_read(&buf))
			}
		}
	}
}

impl_writeable_primitive!(u64, be64_to_array, 8, slice_to_be64);
impl_writeable_primitive!(u32, be32_to_array, 4, slice_to_be32);
impl_writeable_primitive!(u16, be16_to_array, 2, slice_to_be16);

impl<W: Writer> Writeable<W> for u8 {
	#[inline]
	fn write(&self, writer: &mut W) -> Result<(), DecodeError> {
		Ok(writer.write_all(&[*self])?)
	}
}
impl<R: Read> Readable<R> for u8 {
	#[inline]
	fn read(reader: &mut R) -> Result<u8, DecodeError> {
		let mut buf = [0; 1];
		reader.read_exact(&mut buf)?;
		Ok(buf[0])
	}
}

impl<W: Writer> Writeable<W> for bool {
	#[inline]
	fn write(&self, writer: &mut W) -> Result<(), DecodeError> {
		Ok(writer.write_all(&[if *self {1} else {0}])?)
	}
}
impl<R: Read> Readable<R> for bool {
	#[inline]
	fn read(reader: &mut R) -> Result<bool, DecodeError> {
		let mut buf = [0; 1];
		reader.read_exact(&mut buf)?;
		if buf[0] != 0 && buf[0] != 1 {
			return Err(DecodeError::InvalidValue);
		}
		Ok(buf[0] == 1)
	}
}

// u8 arrays
macro_rules! impl_array {
	( $size:expr ) => (
		impl<W: Writer> Writeable<W> for [u8; $size]
		{
			#[inline]
			fn write(&self, w: &mut W) -> Result<(), DecodeError> {
				w.write_all(self)?;
				Ok(())
			}
		}

		impl<R: Read> Readable<R> for [u8; $size]
		{
			#[inline]
			fn read(r: &mut R) -> Result<Self, DecodeError> {
				let mut buf = [0u8; $size];
				r.read_exact(&mut buf)?;
				Ok(buf)
			}
		}
	);
}

//TODO: performance issue with [u8; size] with impl_array!()
impl_array!(32); // for channel id & hmac
impl_array!(33); // for PublicKey
impl_array!(64); // for Signature
impl_array!(1300); // for OnionPacket.hop_data

// HashMap
impl<W, K, V> Writeable<W> for HashMap<K, V>
	where W: Writer,
	      K: Writeable<W> + Eq + Hash,
	      V: Writeable<W>
{
	#[inline]
	fn write(&self, w: &mut W) -> Result<(), DecodeError> {
	(self.len() as u16).write(w)?;
		for (key, value) in self.iter() {
			key.write(w)?;
			value.write(w)?;
		}
		Ok(())
	}
}

impl<R, K, V> Readable<R> for HashMap<K, V>
	where R: Read,
	      K: Readable<R> + Eq + Hash,
	      V: Readable<R>
{
	#[inline]
	fn read(r: &mut R) -> Result<Self, DecodeError> {
		let len: u16 = Readable::read(r)?;
		let mut ret = HashMap::with_capacity(len as usize);
		for _ in 0..len {
			ret.insert(K::read(r)?, V::read(r)?);
		}
		Ok(ret)
	}
}

// Vectors
impl<W: Writer, T: Writeable<W>> Writeable<W> for Vec<T> {
	#[inline]
	fn write(&self, w: &mut W) -> Result<(), DecodeError> {
		let byte_size = (self.len() as usize)
		                .checked_mul(mem::size_of::<T>())
		                .ok_or(DecodeError::BadLengthDescriptor)?;
		if byte_size > MAX_BUF_SIZE {
			return Err(DecodeError::BadLengthDescriptor);
		}
		(self.len() as u16).write(w)?;
		// performance with Vec<u8>
		for e in self.iter() {
			e.write(w)?;
		}
		Ok(())
	}
}

impl<R: Read, T: Readable<R>> Readable<R> for Vec<T> {
	#[inline]
	fn read(r: &mut R) -> Result<Self, DecodeError> {
		let len: u16 = Readable::read(r)?;
		let byte_size = (len as usize)
		                .checked_mul(mem::size_of::<T>())
		                .ok_or(DecodeError::BadLengthDescriptor)?;
		if byte_size > MAX_BUF_SIZE {
			return Err(DecodeError::BadLengthDescriptor);
		}
		let mut ret = Vec::with_capacity(len as usize);
		for _ in 0..len { ret.push(T::read(r)?); }
		Ok(ret)
	}
}

impl<W: Writer> Writeable<W> for Script {
	fn write(&self, w: &mut W) -> Result<(), DecodeError> {
		self.to_bytes().to_vec().write(w)
	}
}

impl<R: Read> Readable<R> for Script {
	fn read(r: &mut R) -> Result<Self, DecodeError> {
		let len = <u16 as Readable<R>>::read(r)? as usize;
		let mut buf = vec![0; len];
		r.read_exact(&mut buf)?;
		Ok(Script::from(buf))
	}
}

impl<W: Writer> Writeable<W> for Option<Script> {
	fn write(&self, w: &mut W) -> Result<(), DecodeError> {
		if let &Some(ref script) = self {
			script.write(w)?;
		}
		Ok(())
	}
}

impl<R: Read> Readable<R> for Option<Script> {
	fn read(r: &mut R) -> Result<Self, DecodeError> {
		match <u16 as Readable<R>>::read(r) {
			Ok(len) => {
				let mut buf = vec![0; len as usize];
				r.read_exact(&mut buf)?;
				Ok(Some(Script::from(buf)))
			},
			Err(DecodeError::ShortRead) => Ok(None),
			Err(e) => Err(e)
		}
	}
}

impl<W: Writer> Writeable<W> for PublicKey {
	fn write(&self, w: &mut W) -> Result<(), DecodeError> {
		self.serialize().write(w)
	}
}

impl<R: Read> Readable<R> for PublicKey {
	fn read(r: &mut R) -> Result<Self, DecodeError> {
		let buf: [u8; 33] = Readable::read(r)?;
		match PublicKey::from_slice(&Secp256k1::without_caps(), &buf) {
			Ok(key) => Ok(key),
			Err(_) => return Err(DecodeError::BadPublicKey),
		}
	}
}

impl<W: Writer> Writeable<W> for Sha256dHash {
	fn write(&self, w: &mut W) -> Result<(), DecodeError> {
		self.as_bytes().write(w)
	}
}

impl<R: Read> Readable<R> for Sha256dHash {
	fn read(r: &mut R) -> Result<Self, DecodeError> {
		let buf: [u8; 32] = Readable::read(r)?;
		Ok(From::from(&buf[..]))
	}
}

impl<W: Writer> Writeable<W> for Signature {
	fn write(&self, w: &mut W) -> Result<(), DecodeError> {
		self.serialize_compact(&Secp256k1::without_caps()).write(w)
	}
}

impl<R: Read> Readable<R> for Signature {
	fn read(r: &mut R) -> Result<Self, DecodeError> {
		let buf: [u8; 64] = Readable::read(r)?;
		match Signature::from_compact(&Secp256k1::without_caps(), &buf) {
			Ok(sig) => Ok(sig),
			Err(_) => return Err(DecodeError::BadSignature),
		}
	}
}
