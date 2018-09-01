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

macro_rules! writer_fn {
	($name:ident, $val_type:ty, $convfn:ident) => {
		#[inline]
		fn $name(&mut self, v: $val_type) -> Result<(), DecodeError> {
			Ok(self.writer.write_all(&$convfn(v))?)
		}
	}
}

macro_rules! reader_fn {
	($name:ident, $val_type:ty, $val_size: expr, $convfn:ident) => {
		#[inline]
		fn $name(&mut self) -> Result<$val_type, DecodeError> {
			let mut buf = [0; $val_size];
			self.reader.read_exact(&mut buf)?;
			Ok($convfn(&buf))
		}
	}
}

use util::byte_utils::{be64_to_array, be32_to_array, be16_to_array, slice_to_be16, slice_to_be32, slice_to_be64};

impl<W: Write> Writer<W> {
	#[cfg(feature = "fuzztarget")]
	pub fn new(writer: W) -> Writer<W> {
		return Writer { writer }
	}
	#[cfg(feature = "fuzztarget")]
	pub fn into_inner(self) -> W { self.writer }
	#[cfg(feature = "fuzztarget")]
	pub fn get_ref(&self) -> &W { &self.writer }
	writer_fn!(write_u64, u64, be64_to_array);
	writer_fn!(write_u32, u32, be32_to_array);
	writer_fn!(write_u16, u16, be16_to_array);
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
	#[cfg(feature = "fuzztarget")]
	pub fn new(reader: R) -> Reader<R> {
		return Reader { reader }
	}
	#[cfg(feature = "fuzztarget")]
  pub fn into_inner(self) -> R { self.reader }
	pub fn get_ref(&self) -> &R { &self.reader }

	reader_fn!(read_u16, u16, 2, slice_to_be16);
	reader_fn!(read_u32, u32, 4, slice_to_be32);
	reader_fn!(read_u64, u64, 8, slice_to_be64);

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

// Arrays
macro_rules! impl_array {
	( $size:expr ) => (
		impl<W, T> Writeable<W> for [T; $size]
			where W: Write,
						T: Writeable<W>,
		{
			#[inline]
			fn write(&self, w: &mut Writer<W>) -> Result<(), DecodeError> {
					for i in self.iter() { i.write(w)?; }
					Ok(())
			}
		}

		impl<R, T> Readable<R> for [T; $size]
			where R: Read,
						T: Readable<R> + Copy,
		{
			#[inline]
			fn read(r: &mut Reader<R>) -> Result<[T; $size], DecodeError> {
				let mut ret = [T::read(r)?; $size];
				for item in ret.iter_mut().take($size).skip(1) { *item = T::read(r)?; }
				Ok(ret)
			}
		}
	);
}

//TODO: performance issue with [u8; size] with impl_array!()
impl_array!(32); // for channel id & hmac
impl_array!(33); // for PublicKey
impl_array!(64); // for Signature

// Tuples
macro_rules! tuple_encode {
	($($x:ident),*) => (
		impl<W: Write, $($x: Writeable<W>),*> Writeable<W> for ($($x),*) {
			#[inline]
			#[allow(non_snake_case)]
			fn write(&self, w: &mut Writer<W>) -> Result<(), DecodeError> {
					let &($(ref $x),*) = self;
					$( $x.write(w)?; )*
					Ok(())
			}
		}
		impl<R: Read, $($x: Readable<R>),*> Readable<R> for ($($x),*) {
			#[inline]
			#[allow(non_snake_case)]
			fn read(r: &mut Reader<R>) -> Result<($($x),*), DecodeError> {
					Ok(($({let $x = $x::read(r)?; $x }),*))
			}
		}
	);
}

tuple_encode!(T0, T1);
tuple_encode!(T0, T1, T2, T3);
tuple_encode!(T0, T1, T2, T3, T4, T5);
tuple_encode!(T0, T1, T2, T3, T4, T5, T6, T7);

/*
// References
impl<W: Write, T: Writeable<W>> Writeable<W> for Box<T> {
	#[inline]
	fn write(&self, w: &mut Writer<W>) -> Result<(), DecodeError> { (**self).write(w) }
}

impl<R: Read, T: Readable<R>> Readable<R> for Box<T> {
	#[inline]
	fn read(r: &mut Reader<R>) -> Result<Box<T>, DecodeError> {
		Ok(Box::new(T::read(r)?))
	}
}
*/

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
	fn read(r: &mut Reader<R>) -> Result<HashMap<K, V>, DecodeError> {
		let len: u16 = Readable::read(r)?;
		let mut ret = HashMap::with_capacity(len as usize);
		for _ in 0..len {
				ret.insert(K::read(r)?, V::read(r)?);
		}
		Ok(ret)
	}
}


// don't want [u8; sz] be encoded thru this
// to dump slice with size-prefix use vec
/*
impl<W: Write, T: Writeable<W>> Writeable<W> for [T] {
	#[inline]
	fn write(&self, w: &mut Writer<W>) -> Result<(), DecodeError> {
		(self.len() as u16).write(w)?;
		for c in self.iter() { c.write(w)?; }
		Ok(())
	}
}
*/

// Vectors
impl<W: Write, T: Writeable<W>> Writeable<W> for Vec<T> {
	#[inline]
	fn write(&self, w: &mut Writer<W>) -> Result<(), DecodeError> {
		let byte_size = (self.len() as usize)
											.checked_mul(mem::size_of::<T>())
											.ok_or(DecodeError::InvalidLength)?;
		if byte_size > MAX_BUF_SIZE {
				return Err(DecodeError::InvalidLength);
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
	fn read(r: &mut Reader<R>) -> Result<Vec<T>, DecodeError> {
			let len: u16 = Readable::read(r)?;
			let byte_size = (len as usize)
												.checked_mul(mem::size_of::<T>())
												.ok_or(DecodeError::InvalidLength)?;
			if byte_size > MAX_BUF_SIZE {
					return Err(DecodeError::InvalidLength);
			}
			let mut ret = Vec::with_capacity(len as usize);
			for _ in 0..len { ret.push(T::read(r)?); }
			Ok(ret)
	}
}

impl<W, T> Writeable<W> for Option<T>
	where W: Write,
				T: ::std::ops::Index<::std::ops::RangeFull, Output=[u8]>
{
	#[inline]
	fn write(&self, w: &mut Writer<W>) -> Result<(), DecodeError> {
		if let &Some(ref data) = self {
			data[..].to_vec().write(w)?;
		} else {
			0u16.write(w)?;
		}
		Ok(())
	}
}

impl<R, T> Readable<R> for Option<T>
	where R: Read,
				T: From<Vec<u8>>,
{
	#[inline]
	fn read(r: &mut Reader<R>) -> Result<Option<T>, DecodeError> {
		match <u16 as Readable<R>>::read(r)? as usize {
			0 => {
				Ok(None)
			},
			len => {
				let mut buf = vec![0; len];
				r.read_exact(&mut buf)?;
				Ok(Some(T::from(buf)))
			}
		}
	}
}

impl<W: Write> Writeable<W> for Script {
	fn write(&self, w: &mut Writer<W>) -> Result<(), DecodeError> {
		self.to_bytes().to_vec().write(w)
	}
}

impl<R: Read> Readable<R> for Script {
	fn read(r: &mut Reader<R>) -> Result<Script, DecodeError> {
		let len = <u16 as Readable<R>>::read(r)? as usize;
		let mut buf = vec![0; len];
		r.read_exact(&mut buf)?;
		Ok(Script::from(buf))
	}
}

impl<W: Write> Writeable<W> for PublicKey {
	fn write(&self, w: &mut Writer<W>) -> Result<(), DecodeError> {
		self.serialize().write(w)
	}
}

impl<R: Read> Readable<R> for PublicKey {
	fn read(r: &mut Reader<R>) -> Result<PublicKey, DecodeError> {
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
	fn read(r: &mut Reader<R>) -> Result<Sha256dHash, DecodeError> {
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
	fn read(r: &mut Reader<R>) -> Result<Signature, DecodeError> {
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
