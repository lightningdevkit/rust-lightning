// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! A very simple serialization framework which is used to serialize/deserialize messages as well
//! as [`ChannelManager`]s and [`ChannelMonitor`]s.
//!
//! [`ChannelManager`]: crate::ln::channelmanager::ChannelManager
//! [`ChannelMonitor`]: crate::chain::channelmonitor::ChannelMonitor

use crate::prelude::*;
use crate::io::{self, Read, Seek, Write};
use crate::io_extras::{copy, sink};
use core::hash::Hash;
use crate::sync::Mutex;
use core::cmp;
use core::convert::TryFrom;
use core::ops::Deref;

use alloc::collections::BTreeMap;

use bitcoin::secp256k1::{PublicKey, SecretKey};
use bitcoin::secp256k1::constants::{PUBLIC_KEY_SIZE, SECRET_KEY_SIZE, COMPACT_SIGNATURE_SIZE, SCHNORR_SIGNATURE_SIZE};
use bitcoin::secp256k1::ecdsa;
use bitcoin::secp256k1::schnorr;
use bitcoin::blockdata::constants::ChainHash;
use bitcoin::blockdata::script::Script;
use bitcoin::blockdata::transaction::{OutPoint, Transaction, TxOut};
use bitcoin::consensus;
use bitcoin::consensus::Encodable;
use bitcoin::hashes::sha256d::Hash as Sha256dHash;
use bitcoin::hash_types::{Txid, BlockHash};
use core::marker::Sized;
use core::time::Duration;
use crate::ln::msgs::DecodeError;
use crate::ln::{PaymentPreimage, PaymentHash, PaymentSecret};

use crate::util::byte_utils::{be48_to_array, slice_to_be48};

/// serialization buffer size
pub const MAX_BUF_SIZE: usize = 64 * 1024;

/// A simplified version of [`std::io::Write`] that exists largely for backwards compatibility.
/// An impl is provided for any type that also impls [`std::io::Write`].
///
/// (C-not exported) as we only export serialization to/from byte arrays instead
pub trait Writer {
	/// Writes the given buf out. See std::io::Write::write_all for more
	fn write_all(&mut self, buf: &[u8]) -> Result<(), io::Error>;
}

impl<W: Write> Writer for W {
	#[inline]
	fn write_all(&mut self, buf: &[u8]) -> Result<(), io::Error> {
		<Self as io::Write>::write_all(self, buf)
	}
}

pub(crate) struct WriterWriteAdaptor<'a, W: Writer + 'a>(pub &'a mut W);
impl<'a, W: Writer + 'a> Write for WriterWriteAdaptor<'a, W> {
	#[inline]
	fn write_all(&mut self, buf: &[u8]) -> Result<(), io::Error> {
		self.0.write_all(buf)
	}
	#[inline]
	fn write(&mut self, buf: &[u8]) -> Result<usize, io::Error> {
		self.0.write_all(buf)?;
		Ok(buf.len())
	}
	#[inline]
	fn flush(&mut self) -> Result<(), io::Error> {
		Ok(())
	}
}

pub(crate) struct VecWriter(pub Vec<u8>);
impl Writer for VecWriter {
	#[inline]
	fn write_all(&mut self, buf: &[u8]) -> Result<(), io::Error> {
		self.0.extend_from_slice(buf);
		Ok(())
	}
}

/// Writer that only tracks the amount of data written - useful if you need to calculate the length
/// of some data when serialized but don't yet need the full data.
///
/// (C-not exported) as manual TLV building is not currently supported in bindings
pub struct LengthCalculatingWriter(pub usize);
impl Writer for LengthCalculatingWriter {
	#[inline]
	fn write_all(&mut self, buf: &[u8]) -> Result<(), io::Error> {
		self.0 += buf.len();
		Ok(())
	}
}

/// Essentially [`std::io::Take`] but a bit simpler and with a method to walk the underlying stream
/// forward to ensure we always consume exactly the fixed length specified.
///
/// (C-not exported) as manual TLV building is not currently supported in bindings
pub struct FixedLengthReader<R: Read> {
	read: R,
	bytes_read: u64,
	total_bytes: u64,
}
impl<R: Read> FixedLengthReader<R> {
	/// Returns a new [`FixedLengthReader`].
	pub fn new(read: R, total_bytes: u64) -> Self {
		Self { read, bytes_read: 0, total_bytes }
	}

	/// Returns whether some bytes are remaining or not.
	#[inline]
	pub fn bytes_remain(&mut self) -> bool {
		self.bytes_read != self.total_bytes
	}

	/// Consumes the remaining bytes.
	#[inline]
	pub fn eat_remaining(&mut self) -> Result<(), DecodeError> {
		copy(self, &mut sink()).unwrap();
		if self.bytes_read != self.total_bytes {
			Err(DecodeError::ShortRead)
		} else {
			Ok(())
		}
	}
}
impl<R: Read> Read for FixedLengthReader<R> {
	#[inline]
	fn read(&mut self, dest: &mut [u8]) -> Result<usize, io::Error> {
		if self.total_bytes == self.bytes_read {
			Ok(0)
		} else {
			let read_len = cmp::min(dest.len() as u64, self.total_bytes - self.bytes_read);
			match self.read.read(&mut dest[0..(read_len as usize)]) {
				Ok(v) => {
					self.bytes_read += v as u64;
					Ok(v)
				},
				Err(e) => Err(e),
			}
		}
	}
}

impl<R: Read> LengthRead for FixedLengthReader<R> {
	#[inline]
	fn total_bytes(&self) -> u64 {
		self.total_bytes
	}
}

/// A [`Read`] implementation which tracks whether any bytes have been read at all. This allows us to distinguish
/// between "EOF reached before we started" and "EOF reached mid-read".
///
/// (C-not exported) as manual TLV building is not currently supported in bindings
pub struct ReadTrackingReader<R: Read> {
	read: R,
	/// Returns whether we have read from this reader or not yet.
	pub have_read: bool,
}
impl<R: Read> ReadTrackingReader<R> {
	/// Returns a new [`ReadTrackingReader`].
	pub fn new(read: R) -> Self {
		Self { read, have_read: false }
	}
}
impl<R: Read> Read for ReadTrackingReader<R> {
	#[inline]
	fn read(&mut self, dest: &mut [u8]) -> Result<usize, io::Error> {
		match self.read.read(dest) {
			Ok(0) => Ok(0),
			Ok(len) => {
				self.have_read = true;
				Ok(len)
			},
			Err(e) => Err(e),
		}
	}
}

/// A trait that various LDK types implement allowing them to be written out to a [`Writer`].
///
/// (C-not exported) as we only export serialization to/from byte arrays instead
pub trait Writeable {
	/// Writes `self` out to the given [`Writer`].
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error>;

	/// Writes `self` out to a `Vec<u8>`.
	fn encode(&self) -> Vec<u8> {
		let mut msg = VecWriter(Vec::new());
		self.write(&mut msg).unwrap();
		msg.0
	}

	/// Writes `self` out to a `Vec<u8>`.
	#[cfg(test)]
	fn encode_with_len(&self) -> Vec<u8> {
		let mut msg = VecWriter(Vec::new());
		0u16.write(&mut msg).unwrap();
		self.write(&mut msg).unwrap();
		let len = msg.0.len();
		msg.0[..2].copy_from_slice(&(len as u16 - 2).to_be_bytes());
		msg.0
	}

	/// Gets the length of this object after it has been serialized. This can be overridden to
	/// optimize cases where we prepend an object with its length.
	// Note that LLVM optimizes this away in most cases! Check that it isn't before you override!
	#[inline]
	fn serialized_length(&self) -> usize {
		let mut len_calc = LengthCalculatingWriter(0);
		self.write(&mut len_calc).expect("No in-memory data may fail to serialize");
		len_calc.0
	}
}

impl<'a, T: Writeable> Writeable for &'a T {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> { (*self).write(writer) }
}

/// A trait that various LDK types implement allowing them to be read in from a [`Read`].
///
/// (C-not exported) as we only export serialization to/from byte arrays instead
pub trait Readable
	where Self: Sized
{
	/// Reads a `Self` in from the given [`Read`].
	fn read<R: Read>(reader: &mut R) -> Result<Self, DecodeError>;
}

/// A trait that various LDK types implement allowing them to be read in from a
/// [`Read`]` + `[`Seek`].
pub(crate) trait SeekReadable where Self: Sized {
	/// Reads a `Self` in from the given [`Read`].
	fn read<R: Read + Seek>(reader: &mut R) -> Result<Self, DecodeError>;
}

/// A trait that various higher-level LDK types implement allowing them to be read in
/// from a [`Read`] given some additional set of arguments which is required to deserialize.
///
/// (C-not exported) as we only export serialization to/from byte arrays instead
pub trait ReadableArgs<P>
	where Self: Sized
{
	/// Reads a `Self` in from the given [`Read`].
	fn read<R: Read>(reader: &mut R, params: P) -> Result<Self, DecodeError>;
}

/// A [`std::io::Read`] that also provides the total bytes available to be read.
pub(crate) trait LengthRead: Read {
	/// The total number of bytes available to be read.
	fn total_bytes(&self) -> u64;
}

/// A trait that various higher-level LDK types implement allowing them to be read in
/// from a Read given some additional set of arguments which is required to deserialize, requiring
/// the implementer to provide the total length of the read.
pub(crate) trait LengthReadableArgs<P> where Self: Sized
{
	/// Reads a `Self` in from the given [`LengthRead`].
	fn read<R: LengthRead>(reader: &mut R, params: P) -> Result<Self, DecodeError>;
}

/// A trait that various higher-level LDK types implement allowing them to be read in
/// from a [`Read`], requiring the implementer to provide the total length of the read.
pub(crate) trait LengthReadable where Self: Sized
{
	/// Reads a `Self` in from the given [`LengthRead`].
	fn read<R: LengthRead>(reader: &mut R) -> Result<Self, DecodeError>;
}

/// A trait that various LDK types implement allowing them to (maybe) be read in from a [`Read`].
///
/// (C-not exported) as we only export serialization to/from byte arrays instead
pub trait MaybeReadable
	where Self: Sized
{
	/// Reads a `Self` in from the given [`Read`].
	fn read<R: Read>(reader: &mut R) -> Result<Option<Self>, DecodeError>;
}

impl<T: Readable> MaybeReadable for T {
	#[inline]
	fn read<R: Read>(reader: &mut R) -> Result<Option<T>, DecodeError> {
		Ok(Some(Readable::read(reader)?))
	}
}

/// Wrapper to read a required (non-optional) TLV record.
///
/// (C-not exported) as manual TLV building is not currently supported in bindings
pub struct RequiredWrapper<T>(pub Option<T>);
impl<T: Readable> Readable for RequiredWrapper<T> {
	#[inline]
	fn read<R: Read>(reader: &mut R) -> Result<Self, DecodeError> {
		Ok(Self(Some(Readable::read(reader)?)))
	}
}
impl<A, T: ReadableArgs<A>> ReadableArgs<A> for RequiredWrapper<T> {
	#[inline]
	fn read<R: Read>(reader: &mut R, args: A) -> Result<Self, DecodeError> {
		Ok(Self(Some(ReadableArgs::read(reader, args)?)))
	}
}
/// When handling `default_values`, we want to map the default-value T directly
/// to a `RequiredWrapper<T>` in a way that works for `field: T = t;` as
/// well. Thus, we assume `Into<T> for T` does nothing and use that.
impl<T> From<T> for RequiredWrapper<T> {
	fn from(t: T) -> RequiredWrapper<T> { RequiredWrapper(Some(t)) }
}

/// Wrapper to read a required (non-optional) TLV record that may have been upgraded without
/// backwards compat.
///
/// (C-not exported) as manual TLV building is not currently supported in bindings
pub struct UpgradableRequired<T: MaybeReadable>(pub Option<T>);
impl<T: MaybeReadable> MaybeReadable for UpgradableRequired<T> {
	#[inline]
	fn read<R: Read>(reader: &mut R) -> Result<Option<Self>, DecodeError> {
		let tlv = MaybeReadable::read(reader)?;
		if let Some(tlv) = tlv { return Ok(Some(Self(Some(tlv)))) }
		Ok(None)
	}
}

pub(crate) struct U48(pub u64);
impl Writeable for U48 {
	#[inline]
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		writer.write_all(&be48_to_array(self.0))
	}
}
impl Readable for U48 {
	#[inline]
	fn read<R: Read>(reader: &mut R) -> Result<U48, DecodeError> {
		let mut buf = [0; 6];
		reader.read_exact(&mut buf)?;
		Ok(U48(slice_to_be48(&buf)))
	}
}

/// Lightning TLV uses a custom variable-length integer called `BigSize`. It is similar to Bitcoin's
/// variable-length integers except that it is serialized in big-endian instead of little-endian.
///
/// Like Bitcoin's variable-length integer, it exhibits ambiguity in that certain values can be
/// encoded in several different ways, which we must check for at deserialization-time. Thus, if
/// you're looking for an example of a variable-length integer to use for your own project, move
/// along, this is a rather poor design.
pub struct BigSize(pub u64);
impl Writeable for BigSize {
	#[inline]
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		match self.0 {
			0...0xFC => {
				(self.0 as u8).write(writer)
			},
			0xFD...0xFFFF => {
				0xFDu8.write(writer)?;
				(self.0 as u16).write(writer)
			},
			0x10000...0xFFFFFFFF => {
				0xFEu8.write(writer)?;
				(self.0 as u32).write(writer)
			},
			_ => {
				0xFFu8.write(writer)?;
				(self.0 as u64).write(writer)
			},
		}
	}
}
impl Readable for BigSize {
	#[inline]
	fn read<R: Read>(reader: &mut R) -> Result<BigSize, DecodeError> {
		let n: u8 = Readable::read(reader)?;
		match n {
			0xFF => {
				let x: u64 = Readable::read(reader)?;
				if x < 0x100000000 {
					Err(DecodeError::InvalidValue)
				} else {
					Ok(BigSize(x))
				}
			}
			0xFE => {
				let x: u32 = Readable::read(reader)?;
				if x < 0x10000 {
					Err(DecodeError::InvalidValue)
				} else {
					Ok(BigSize(x as u64))
				}
			}
			0xFD => {
				let x: u16 = Readable::read(reader)?;
				if x < 0xFD {
					Err(DecodeError::InvalidValue)
				} else {
					Ok(BigSize(x as u64))
				}
			}
			n => Ok(BigSize(n as u64))
		}
	}
}

/// The lightning protocol uses u16s for lengths in most cases. As our serialization framework
/// primarily targets that, we must as well. However, because we may serialize objects that have
/// more than 65K entries, we need to be able to store larger values. Thus, we define a variable
/// length integer here that is backwards-compatible for values < 0xffff. We treat 0xffff as
/// "read eight more bytes".
///
/// To ensure we only have one valid encoding per value, we add 0xffff to values written as eight
/// bytes. Thus, 0xfffe is serialized as 0xfffe, whereas 0xffff is serialized as
/// 0xffff0000000000000000 (i.e. read-eight-bytes then zero).
struct CollectionLength(pub u64);
impl Writeable for CollectionLength {
	#[inline]
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		if self.0 < 0xffff {
			(self.0 as u16).write(writer)
		} else {
			0xffffu16.write(writer)?;
			(self.0 - 0xffff).write(writer)
		}
	}
}

impl Readable for CollectionLength {
	#[inline]
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		let mut val: u64 = <u16 as Readable>::read(r)? as u64;
		if val == 0xffff {
			val = <u64 as Readable>::read(r)?
				.checked_add(0xffff).ok_or(DecodeError::InvalidValue)?;
		}
		Ok(CollectionLength(val))
	}
}

/// In TLV we occasionally send fields which only consist of, or potentially end with, a
/// variable-length integer which is simply truncated by skipping high zero bytes. This type
/// encapsulates such integers implementing [`Readable`]/[`Writeable`] for them.
#[cfg_attr(test, derive(PartialEq, Eq, Debug))]
pub(crate) struct HighZeroBytesDroppedBigSize<T>(pub T);

macro_rules! impl_writeable_primitive {
	($val_type:ty, $len: expr) => {
		impl Writeable for $val_type {
			#[inline]
			fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
				writer.write_all(&self.to_be_bytes())
			}
		}
		impl Writeable for HighZeroBytesDroppedBigSize<$val_type> {
			#[inline]
			fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
				// Skip any full leading 0 bytes when writing (in BE):
				writer.write_all(&self.0.to_be_bytes()[(self.0.leading_zeros()/8) as usize..$len])
			}
		}
		impl Readable for $val_type {
			#[inline]
			fn read<R: Read>(reader: &mut R) -> Result<$val_type, DecodeError> {
				let mut buf = [0; $len];
				reader.read_exact(&mut buf)?;
				Ok(<$val_type>::from_be_bytes(buf))
			}
		}
		impl Readable for HighZeroBytesDroppedBigSize<$val_type> {
			#[inline]
			fn read<R: Read>(reader: &mut R) -> Result<HighZeroBytesDroppedBigSize<$val_type>, DecodeError> {
				// We need to accept short reads (read_len == 0) as "EOF" and handle them as simply
				// the high bytes being dropped. To do so, we start reading into the middle of buf
				// and then convert the appropriate number of bytes with extra high bytes out of
				// buf.
				let mut buf = [0; $len*2];
				let mut read_len = reader.read(&mut buf[$len..])?;
				let mut total_read_len = read_len;
				while read_len != 0 && total_read_len != $len {
					read_len = reader.read(&mut buf[($len + total_read_len)..])?;
					total_read_len += read_len;
				}
				if total_read_len == 0 || buf[$len] != 0 {
					let first_byte = $len - ($len - total_read_len);
					let mut bytes = [0; $len];
					bytes.copy_from_slice(&buf[first_byte..first_byte + $len]);
					Ok(HighZeroBytesDroppedBigSize(<$val_type>::from_be_bytes(bytes)))
				} else {
					// If the encoding had extra zero bytes, return a failure even though we know
					// what they meant (as the TLV test vectors require this)
					Err(DecodeError::InvalidValue)
				}
			}
		}
		impl From<$val_type> for HighZeroBytesDroppedBigSize<$val_type> {
			fn from(val: $val_type) -> Self { Self(val) }
		}
	}
}

impl_writeable_primitive!(u128, 16);
impl_writeable_primitive!(u64, 8);
impl_writeable_primitive!(u32, 4);
impl_writeable_primitive!(u16, 2);

impl Writeable for u8 {
	#[inline]
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		writer.write_all(&[*self])
	}
}
impl Readable for u8 {
	#[inline]
	fn read<R: Read>(reader: &mut R) -> Result<u8, DecodeError> {
		let mut buf = [0; 1];
		reader.read_exact(&mut buf)?;
		Ok(buf[0])
	}
}

impl Writeable for bool {
	#[inline]
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		writer.write_all(&[if *self {1} else {0}])
	}
}
impl Readable for bool {
	#[inline]
	fn read<R: Read>(reader: &mut R) -> Result<bool, DecodeError> {
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
		impl Writeable for [u8; $size]
		{
			#[inline]
			fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
				w.write_all(self)
			}
		}

		impl Readable for [u8; $size]
		{
			#[inline]
			fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
				let mut buf = [0u8; $size];
				r.read_exact(&mut buf)?;
				Ok(buf)
			}
		}
	);
}

impl_array!(3); // for rgb, ISO 4712 code
impl_array!(4); // for IPv4
impl_array!(12); // for OnionV2
impl_array!(16); // for IPv6
impl_array!(32); // for channel id & hmac
impl_array!(PUBLIC_KEY_SIZE); // for PublicKey
impl_array!(64); // for ecdsa::Signature and schnorr::Signature
impl_array!(1300); // for OnionPacket.hop_data

impl Writeable for [u16; 8] {
	#[inline]
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		for v in self.iter() {
			w.write_all(&v.to_be_bytes())?
		}
		Ok(())
	}
}

impl Readable for [u16; 8] {
	#[inline]
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		let mut buf = [0u8; 16];
		r.read_exact(&mut buf)?;
		let mut res = [0u16; 8];
		for (idx, v) in res.iter_mut().enumerate() {
			*v = (buf[idx] as u16) << 8 | (buf[idx + 1] as u16)
		}
		Ok(res)
	}
}

/// A type for variable-length values within TLV record where the length is encoded as part of the record.
/// Used to prevent encoding the length twice.
///
/// (C-not exported) as manual TLV building is not currently supported in bindings
pub struct WithoutLength<T>(pub T);

impl Writeable for WithoutLength<&String> {
	#[inline]
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		w.write_all(self.0.as_bytes())
	}
}
impl Readable for WithoutLength<String> {
	#[inline]
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		let v: WithoutLength<Vec<u8>> = Readable::read(r)?;
		Ok(Self(String::from_utf8(v.0).map_err(|_| DecodeError::InvalidValue)?))
	}
}
impl<'a> From<&'a String> for WithoutLength<&'a String> {
	fn from(s: &'a String) -> Self { Self(s) }
}

impl<'a, T: Writeable> Writeable for WithoutLength<&'a Vec<T>> {
	#[inline]
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		for ref v in self.0.iter() {
			v.write(writer)?;
		}
		Ok(())
	}
}

impl<T: MaybeReadable> Readable for WithoutLength<Vec<T>> {
	#[inline]
	fn read<R: Read>(mut reader: &mut R) -> Result<Self, DecodeError> {
		let mut values = Vec::new();
		loop {
			let mut track_read = ReadTrackingReader::new(&mut reader);
			match MaybeReadable::read(&mut track_read) {
				Ok(Some(v)) => { values.push(v); },
				Ok(None) => { },
				// If we failed to read any bytes at all, we reached the end of our TLV
				// stream and have simply exhausted all entries.
				Err(ref e) if e == &DecodeError::ShortRead && !track_read.have_read => break,
				Err(e) => return Err(e),
			}
		}
		Ok(Self(values))
	}
}
impl<'a, T> From<&'a Vec<T>> for WithoutLength<&'a Vec<T>> {
	fn from(v: &'a Vec<T>) -> Self { Self(v) }
}

#[derive(Debug)]
pub(crate) struct Iterable<'a, I: Iterator<Item = &'a T> + Clone, T: 'a>(pub I);

impl<'a, I: Iterator<Item = &'a T> + Clone, T: 'a + Writeable> Writeable for Iterable<'a, I, T> {
	#[inline]
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		for ref v in self.0.clone() {
			v.write(writer)?;
		}
		Ok(())
	}
}

#[cfg(test)]
impl<'a, I: Iterator<Item = &'a T> + Clone, T: 'a + PartialEq> PartialEq for Iterable<'a, I, T> {
	fn eq(&self, other: &Self) -> bool {
		self.0.clone().collect::<Vec<_>>() == other.0.clone().collect::<Vec<_>>()
	}
}

macro_rules! impl_for_map {
	($ty: ident, $keybound: ident, $constr: expr) => {
		impl<K, V> Writeable for $ty<K, V>
			where K: Writeable + Eq + $keybound, V: Writeable
		{
			#[inline]
			fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
				CollectionLength(self.len() as u64).write(w)?;
				for (key, value) in self.iter() {
					key.write(w)?;
					value.write(w)?;
				}
				Ok(())
			}
		}

		impl<K, V> Readable for $ty<K, V>
			where K: Readable + Eq + $keybound, V: MaybeReadable
		{
			#[inline]
			fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
				let len: CollectionLength = Readable::read(r)?;
				let mut ret = $constr(len.0 as usize);
				for _ in 0..len.0 {
					let k = K::read(r)?;
					let v_opt = V::read(r)?;
					if let Some(v) = v_opt {
						if ret.insert(k, v).is_some() {
							return Err(DecodeError::InvalidValue);
						}
					}
				}
				Ok(ret)
			}
		}
	}
}

impl_for_map!(BTreeMap, Ord, |_| BTreeMap::new());
impl_for_map!(HashMap, Hash, |len| HashMap::with_capacity(len));

// HashSet
impl<T> Writeable for HashSet<T>
where T: Writeable + Eq + Hash
{
	#[inline]
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		CollectionLength(self.len() as u64).write(w)?;
		for item in self.iter() {
			item.write(w)?;
		}
		Ok(())
	}
}

impl<T> Readable for HashSet<T>
where T: Readable + Eq + Hash
{
	#[inline]
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		let len: CollectionLength = Readable::read(r)?;
		let mut ret = HashSet::with_capacity(cmp::min(len.0 as usize, MAX_BUF_SIZE / core::mem::size_of::<T>()));
		for _ in 0..len.0 {
			if !ret.insert(T::read(r)?) {
				return Err(DecodeError::InvalidValue)
			}
		}
		Ok(ret)
	}
}

// Vectors
macro_rules! impl_for_vec {
	($ty: ty $(, $name: ident)*) => {
		impl<$($name : Writeable),*> Writeable for Vec<$ty> {
			#[inline]
			fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
				CollectionLength(self.len() as u64).write(w)?;
				for elem in self.iter() {
					elem.write(w)?;
				}
				Ok(())
			}
		}

		impl<$($name : Readable),*> Readable for Vec<$ty> {
			#[inline]
			fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
				let len: CollectionLength = Readable::read(r)?;
				let mut ret = Vec::with_capacity(cmp::min(len.0 as usize, MAX_BUF_SIZE / core::mem::size_of::<$ty>()));
				for _ in 0..len.0 {
					if let Some(val) = MaybeReadable::read(r)? {
						ret.push(val);
					}
				}
				Ok(ret)
			}
		}
	}
}

impl Writeable for Vec<u8> {
	#[inline]
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		CollectionLength(self.len() as u64).write(w)?;
		w.write_all(&self)
	}
}

impl Readable for Vec<u8> {
	#[inline]
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		let mut len: CollectionLength = Readable::read(r)?;
		let mut ret = Vec::new();
		while len.0 > 0 {
			let readamt = cmp::min(len.0 as usize, MAX_BUF_SIZE);
			let readstart = ret.len();
			ret.resize(readstart + readamt, 0);
			r.read_exact(&mut ret[readstart..])?;
			len.0 -= readamt as u64;
		}
		Ok(ret)
	}
}

impl_for_vec!(ecdsa::Signature);
impl_for_vec!(crate::ln::channelmanager::MonitorUpdateCompletionAction);
impl_for_vec!((A, B), A, B);

impl Writeable for Script {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		(self.len() as u16).write(w)?;
		w.write_all(self.as_bytes())
	}
}

impl Readable for Script {
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		let len = <u16 as Readable>::read(r)? as usize;
		let mut buf = vec![0; len];
		r.read_exact(&mut buf)?;
		Ok(Script::from(buf))
	}
}

impl Writeable for PublicKey {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		self.serialize().write(w)
	}
	#[inline]
	fn serialized_length(&self) -> usize {
		PUBLIC_KEY_SIZE
	}
}

impl Readable for PublicKey {
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		let buf: [u8; PUBLIC_KEY_SIZE] = Readable::read(r)?;
		match PublicKey::from_slice(&buf) {
			Ok(key) => Ok(key),
			Err(_) => return Err(DecodeError::InvalidValue),
		}
	}
}

impl Writeable for SecretKey {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		let mut ser = [0; SECRET_KEY_SIZE];
		ser.copy_from_slice(&self[..]);
		ser.write(w)
	}
	#[inline]
	fn serialized_length(&self) -> usize {
		SECRET_KEY_SIZE
	}
}

impl Readable for SecretKey {
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		let buf: [u8; SECRET_KEY_SIZE] = Readable::read(r)?;
		match SecretKey::from_slice(&buf) {
			Ok(key) => Ok(key),
			Err(_) => return Err(DecodeError::InvalidValue),
		}
	}
}

impl Writeable for Sha256dHash {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		w.write_all(&self[..])
	}
}

impl Readable for Sha256dHash {
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		use bitcoin::hashes::Hash;

		let buf: [u8; 32] = Readable::read(r)?;
		Ok(Sha256dHash::from_slice(&buf[..]).unwrap())
	}
}

impl Writeable for ecdsa::Signature {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		self.serialize_compact().write(w)
	}
}

impl Readable for ecdsa::Signature {
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		let buf: [u8; COMPACT_SIGNATURE_SIZE] = Readable::read(r)?;
		match ecdsa::Signature::from_compact(&buf) {
			Ok(sig) => Ok(sig),
			Err(_) => return Err(DecodeError::InvalidValue),
		}
	}
}

impl Writeable for schnorr::Signature {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		self.as_ref().write(w)
	}
}

impl Readable for schnorr::Signature {
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		let buf: [u8; SCHNORR_SIGNATURE_SIZE] = Readable::read(r)?;
		match schnorr::Signature::from_slice(&buf) {
			Ok(sig) => Ok(sig),
			Err(_) => return Err(DecodeError::InvalidValue),
		}
	}
}

impl Writeable for PaymentPreimage {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		self.0.write(w)
	}
}

impl Readable for PaymentPreimage {
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		let buf: [u8; 32] = Readable::read(r)?;
		Ok(PaymentPreimage(buf))
	}
}

impl Writeable for PaymentHash {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		self.0.write(w)
	}
}

impl Readable for PaymentHash {
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		let buf: [u8; 32] = Readable::read(r)?;
		Ok(PaymentHash(buf))
	}
}

impl Writeable for PaymentSecret {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		self.0.write(w)
	}
}

impl Readable for PaymentSecret {
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		let buf: [u8; 32] = Readable::read(r)?;
		Ok(PaymentSecret(buf))
	}
}

impl<T: Writeable> Writeable for Box<T> {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		T::write(&**self, w)
	}
}

impl<T: Readable> Readable for Box<T> {
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		Ok(Box::new(Readable::read(r)?))
	}
}

impl<T: Writeable> Writeable for Option<T> {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		match *self {
			None => 0u8.write(w)?,
			Some(ref data) => {
				BigSize(data.serialized_length() as u64 + 1).write(w)?;
				data.write(w)?;
			}
		}
		Ok(())
	}
}

impl<T: Readable> Readable for Option<T>
{
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		let len: BigSize = Readable::read(r)?;
		match len.0 {
			0 => Ok(None),
			len => {
				let mut reader = FixedLengthReader::new(r, len - 1);
				Ok(Some(Readable::read(&mut reader)?))
			}
		}
	}
}

impl Writeable for Txid {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		w.write_all(&self[..])
	}
}

impl Readable for Txid {
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		use bitcoin::hashes::Hash;

		let buf: [u8; 32] = Readable::read(r)?;
		Ok(Txid::from_slice(&buf[..]).unwrap())
	}
}

impl Writeable for BlockHash {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		w.write_all(&self[..])
	}
}

impl Readable for BlockHash {
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		use bitcoin::hashes::Hash;

		let buf: [u8; 32] = Readable::read(r)?;
		Ok(BlockHash::from_slice(&buf[..]).unwrap())
	}
}

impl Writeable for ChainHash {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		w.write_all(self.as_bytes())
	}
}

impl Readable for ChainHash {
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		let buf: [u8; 32] = Readable::read(r)?;
		Ok(ChainHash::from(&buf[..]))
	}
}

impl Writeable for OutPoint {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		self.txid.write(w)?;
		self.vout.write(w)?;
		Ok(())
	}
}

impl Readable for OutPoint {
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		let txid = Readable::read(r)?;
		let vout = Readable::read(r)?;
		Ok(OutPoint {
			txid,
			vout,
		})
	}
}

macro_rules! impl_consensus_ser {
	($bitcoin_type: ty) => {
		impl Writeable for $bitcoin_type {
			fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
				match self.consensus_encode(&mut WriterWriteAdaptor(writer)) {
					Ok(_) => Ok(()),
					Err(e) => Err(e),
				}
			}
		}

		impl Readable for $bitcoin_type {
			fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
				match consensus::encode::Decodable::consensus_decode(r) {
					Ok(t) => Ok(t),
					Err(consensus::encode::Error::Io(ref e)) if e.kind() == io::ErrorKind::UnexpectedEof => Err(DecodeError::ShortRead),
					Err(consensus::encode::Error::Io(e)) => Err(DecodeError::Io(e.kind())),
					Err(_) => Err(DecodeError::InvalidValue),
				}
			}
		}
	}
}
impl_consensus_ser!(Transaction);
impl_consensus_ser!(TxOut);

impl<T: Readable> Readable for Mutex<T> {
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		let t: T = Readable::read(r)?;
		Ok(Mutex::new(t))
	}
}
impl<T: Writeable> Writeable for Mutex<T> {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		self.lock().unwrap().write(w)
	}
}

impl<A: Readable, B: Readable> Readable for (A, B) {
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		let a: A = Readable::read(r)?;
		let b: B = Readable::read(r)?;
		Ok((a, b))
	}
}
impl<A: Writeable, B: Writeable> Writeable for (A, B) {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		self.0.write(w)?;
		self.1.write(w)
	}
}

impl<A: Readable, B: Readable, C: Readable> Readable for (A, B, C) {
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		let a: A = Readable::read(r)?;
		let b: B = Readable::read(r)?;
		let c: C = Readable::read(r)?;
		Ok((a, b, c))
	}
}
impl<A: Writeable, B: Writeable, C: Writeable> Writeable for (A, B, C) {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		self.0.write(w)?;
		self.1.write(w)?;
		self.2.write(w)
	}
}

impl<A: Readable, B: Readable, C: Readable, D: Readable> Readable for (A, B, C, D) {
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		let a: A = Readable::read(r)?;
		let b: B = Readable::read(r)?;
		let c: C = Readable::read(r)?;
		let d: D = Readable::read(r)?;
		Ok((a, b, c, d))
	}
}
impl<A: Writeable, B: Writeable, C: Writeable, D: Writeable> Writeable for (A, B, C, D) {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		self.0.write(w)?;
		self.1.write(w)?;
		self.2.write(w)?;
		self.3.write(w)
	}
}

impl Writeable for () {
	fn write<W: Writer>(&self, _: &mut W) -> Result<(), io::Error> {
		Ok(())
	}
}
impl Readable for () {
	fn read<R: Read>(_r: &mut R) -> Result<Self, DecodeError> {
		Ok(())
	}
}

impl Writeable for String {
	#[inline]
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		CollectionLength(self.len() as u64).write(w)?;
		w.write_all(self.as_bytes())
	}
}
impl Readable for String {
	#[inline]
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		let v: Vec<u8> = Readable::read(r)?;
		let ret = String::from_utf8(v).map_err(|_| DecodeError::InvalidValue)?;
		Ok(ret)
	}
}

/// Represents a hostname for serialization purposes.
/// Only the character set and length will be validated.
/// The character set consists of ASCII alphanumeric characters, hyphens, and periods.
/// Its length is guaranteed to be representable by a single byte.
/// This serialization is used by [`BOLT 7`] hostnames.
///
/// [`BOLT 7`]: https://github.com/lightning/bolts/blob/master/07-routing-gossip.md
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hostname(String);
impl Hostname {
	/// Returns the length of the hostname.
	pub fn len(&self) -> u8 {
		(&self.0).len() as u8
	}
}
impl Deref for Hostname {
	type Target = String;

	fn deref(&self) -> &Self::Target {
		&self.0
	}
}
impl From<Hostname> for String {
	fn from(hostname: Hostname) -> Self {
		hostname.0
	}
}
impl TryFrom<Vec<u8>> for Hostname {
	type Error = ();

	fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
		if let Ok(s) = String::from_utf8(bytes) {
			Hostname::try_from(s)
		} else {
			Err(())
		}
	}
}
impl TryFrom<String> for Hostname {
	type Error = ();

	fn try_from(s: String) -> Result<Self, Self::Error> {
		if s.len() <= 255 && s.chars().all(|c|
			c.is_ascii_alphanumeric() ||
			c == '.' ||
			c == '-'
		) {
			Ok(Hostname(s))
		} else {
			Err(())
		}
	}
}
impl Writeable for Hostname {
	#[inline]
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		self.len().write(w)?;
		w.write_all(self.as_bytes())
	}
}
impl Readable for Hostname {
	#[inline]
	fn read<R: Read>(r: &mut R) -> Result<Hostname, DecodeError> {
		let len: u8 = Readable::read(r)?;
		let mut vec = Vec::with_capacity(len.into());
		vec.resize(len.into(), 0);
		r.read_exact(&mut vec)?;
		Hostname::try_from(vec).map_err(|_| DecodeError::InvalidValue)
	}
}

impl Writeable for Duration {
	#[inline]
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		self.as_secs().write(w)?;
		self.subsec_nanos().write(w)
	}
}
impl Readable for Duration {
	#[inline]
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		let secs = Readable::read(r)?;
		let nanos = Readable::read(r)?;
		Ok(Duration::new(secs, nanos))
	}
}

#[cfg(test)]
mod tests {
	use core::convert::TryFrom;
	use crate::util::ser::{Readable, Hostname, Writeable};

	#[test]
	fn hostname_conversion() {
		assert_eq!(Hostname::try_from(String::from("a-test.com")).unwrap().as_str(), "a-test.com");

		assert!(Hostname::try_from(String::from("\"")).is_err());
		assert!(Hostname::try_from(String::from("$")).is_err());
		assert!(Hostname::try_from(String::from("⚡")).is_err());
		let mut large_vec = Vec::with_capacity(256);
		large_vec.resize(256, b'A');
		assert!(Hostname::try_from(String::from_utf8(large_vec).unwrap()).is_err());
	}

	#[test]
	fn hostname_serialization() {
		let hostname = Hostname::try_from(String::from("test")).unwrap();
		let mut buf: Vec<u8> = Vec::new();
		hostname.write(&mut buf).unwrap();
		assert_eq!(Hostname::read(&mut buf.as_slice()).unwrap().as_str(), "test");
	}
}
