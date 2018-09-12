use std::result::Result;
use std::io::{Read, Write};
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

const MAX_BUF_SIZE: usize = 16 * 1024;

pub struct Writer<W> { writer: W }
pub struct Reader<R> { reader: R }

pub trait Writeable<W: Write> {
	fn write(&self, writer: &mut Writer<W>) -> Result<(), DecodeError>;
}

pub trait Readable<R>
	where Self: Sized,
	      R: Read
{
	fn read(reader: &mut Reader<R>) -> Result<Self, DecodeError>;
}

impl<W: Write> Writer<W> {
	pub fn new(writer: W) -> Writer<W> {
		return Writer { writer }
	}
	pub fn into_inner(self) -> W { self.writer }
	pub fn get_ref(&self) -> &W { &self.writer }
	fn write_u64(&mut self, v: u64) -> Result<(), DecodeError> {
		Ok(self.writer.write_all(&be64_to_array(v))?)
	}
	fn write_u32(&mut self, v: u32) -> Result<(), DecodeError> {
		Ok(self.writer.write_all(&be32_to_array(v))?)
	}
	fn write_u16(&mut self, v: u16) -> Result<(), DecodeError> {
		Ok(self.writer.write_all(&be16_to_array(v))?)
	}
	fn write_u8(&mut self, v: u8) -> Result<(), DecodeError> {
		Ok(self.writer.write_all(&[v])?)
	}
	fn write_bool(&mut self, v: bool) -> Result<(), DecodeError> {
		Ok(self.writer.write_all(&[if v {1} else {0}])?)
	}
	pub fn write_all(&mut self, v: &[u8]) -> Result<(), DecodeError> {
		Ok(self.writer.write_all(v)?)
	}
}

impl<R: Read> Reader<R> {
	pub fn new(reader: R) -> Reader<R> {
		return Reader { reader }
	}
	pub fn into_inner(self) -> R { self.reader }
	pub fn get_ref(&self) -> &R { &self.reader }

	fn read_u64(&mut self) -> Result<u64, DecodeError> {
		let mut buf = [0; 8];
		self.reader.read_exact(&mut buf)?;
		Ok(slice_to_be64(&buf))
	}

	fn read_u32(&mut self) -> Result<u32, DecodeError> {
		let mut buf = [0; 4];
		self.reader.read_exact(&mut buf)?;
		Ok(slice_to_be32(&buf))
	}

	fn read_u16(&mut self) -> Result<u16, DecodeError> {
		let mut buf = [0; 2];
		self.reader.read_exact(&mut buf)?;
		Ok(slice_to_be16(&buf))
	}

	fn read_u8(&mut self) -> Result<u8, DecodeError> {
		let mut buf = [0; 1];
		self.reader.read_exact(&mut buf)?;
		Ok(buf[0])
	}
	fn read_bool(&mut self) -> Result<bool, DecodeError> {
		let mut buf = [0; 1];
		self.reader.read_exact(&mut buf)?;
		if buf[0] != 0 && buf[0] != 1 {
			return Err(DecodeError::InvalidValue);
		}
		Ok(buf[0] == 1)
	}
	pub fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), DecodeError> {
		Ok(self.reader.read_exact(buf)?)
	}
	pub fn read_to_end(&mut self, buf: &mut Vec<u8>) -> Result<usize, DecodeError> {
		Ok(self.reader.read_to_end(buf)?)
	}
}

macro_rules! impl_writeable_primitive {
	($val_type:ty, $meth_write:ident, $meth_read:ident) => {
		impl<W:Write> Writeable<W> for $val_type {
			#[inline]
			fn write(&self, writer: &mut Writer<W>) -> Result<(), DecodeError> {
				writer.$meth_write(*self)
			}
		}
		impl<R:Read> Readable<R> for $val_type {
			#[inline]
			fn read(reader: &mut Reader<R>) -> Result<$val_type, DecodeError> {
				reader.$meth_read()
			}
		}
	}
}

impl_writeable_primitive!(u64, write_u64, read_u64);
impl_writeable_primitive!(u32, write_u32, read_u32);
impl_writeable_primitive!(u16, write_u16, read_u16);
impl_writeable_primitive!(u8, write_u8, read_u8);
impl_writeable_primitive!(bool, write_bool, read_bool);

// u8 arrays
macro_rules! impl_array {
	( $size:expr ) => (
		impl<W> Writeable<W> for [u8; $size]
			where W: Write
		{
			#[inline]
			fn write(&self, w: &mut Writer<W>) -> Result<(), DecodeError> {
				w.write_all(self)?;
				Ok(())
			}
		}

		impl<R> Readable<R> for [u8; $size]
			where R: Read
		{
			#[inline]
			fn read(r: &mut Reader<R>) -> Result<Self, DecodeError> {
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
	where W: Write,
	      K: Writeable<W> + Eq + Hash,
	      V: Writeable<W>
{
	#[inline]
	fn write(&self, w: &mut Writer<W>) -> Result<(), DecodeError> {
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
	fn read(r: &mut Reader<R>) -> Result<Self, DecodeError> {
		let len: u16 = Readable::read(r)?;
		let mut ret = HashMap::with_capacity(len as usize);
		for _ in 0..len {
			ret.insert(K::read(r)?, V::read(r)?);
		}
		Ok(ret)
	}
}

// Vectors
impl<W: Write, T: Writeable<W>> Writeable<W> for Vec<T> {
	#[inline]
	fn write(&self, w: &mut Writer<W>) -> Result<(), DecodeError> {
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
	fn read(r: &mut Reader<R>) -> Result<Self, DecodeError> {
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

impl<W: Write> Writeable<W> for Script {
	fn write(&self, w: &mut Writer<W>) -> Result<(), DecodeError> {
		self.to_bytes().to_vec().write(w)
	}
}

impl<R: Read> Readable<R> for Script {
	fn read(r: &mut Reader<R>) -> Result<Self, DecodeError> {
		let len = <u16 as Readable<R>>::read(r)? as usize;
		let mut buf = vec![0; len];
		r.read_exact(&mut buf)?;
		Ok(Script::from(buf))
	}
}

impl<W: Write> Writeable<W> for Option<Script> {
	fn write(&self, w: &mut Writer<W>) -> Result<(), DecodeError> {
		if let &Some(ref script) = self {
			script.write(w)?;
		}
		Ok(())
	}
}

impl<R: Read> Readable<R> for Option<Script> {
	fn read(r: &mut Reader<R>) -> Result<Self, DecodeError> {
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

impl<W: Write> Writeable<W> for PublicKey {
	fn write(&self, w: &mut Writer<W>) -> Result<(), DecodeError> {
		self.serialize().write(w)
	}
}

impl<R: Read> Readable<R> for PublicKey {
	fn read(r: &mut Reader<R>) -> Result<Self, DecodeError> {
		let buf: [u8; 33] = Readable::read(r)?;
		match PublicKey::from_slice(&Secp256k1::without_caps(), &buf) {
			Ok(key) => Ok(key),
			Err(_) => return Err(DecodeError::BadPublicKey),
		}
	}
}

impl<W: Write> Writeable<W> for Sha256dHash {
	fn write(&self, w: &mut Writer<W>) -> Result<(), DecodeError> {
		self.as_bytes().write(w)
	}
}

impl<R: Read> Readable<R> for Sha256dHash {
	fn read(r: &mut Reader<R>) -> Result<Self, DecodeError> {
		let buf: [u8; 32] = Readable::read(r)?;
		Ok(From::from(&buf[..]))
	}
}

impl<W: Write> Writeable<W> for Signature {
	fn write(&self, w: &mut Writer<W>) -> Result<(), DecodeError> {
		self.serialize_compact(&Secp256k1::without_caps()).write(w)
	}
}

impl<R: Read> Readable<R> for Signature {
	fn read(r: &mut Reader<R>) -> Result<Self, DecodeError> {
		let buf: [u8; 64] = Readable::read(r)?;
		match Signature::from_compact(&Secp256k1::without_caps(), &buf) {
			Ok(sig) => Ok(sig),
			Err(_) => return Err(DecodeError::BadSignature),
		}
	}
}

macro_rules! impl_writeable {
	($st:ident, {$($field:ident),*}) => {
		impl<W: ::std::io::Write> Writeable<W> for $st {
			fn write(&self, w: &mut Writer<W>) -> Result<(), DecodeError> {
				$( self.$field.write(w)?; )*
				Ok(())
			}
		}

		impl<R: ::std::io::Read> Readable<R> for $st {
			fn read(r: &mut Reader<R>) -> Result<Self, DecodeError> {
				Ok(Self {
					$($field: Readable::read(r)?),*
				})
			}
		}
	}
}
