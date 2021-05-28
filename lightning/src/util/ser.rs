// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! A very simple serialization framework which is used to serialize/deserialize messages as well
//! as ChannelsManagers and ChannelMonitors.

use prelude::*;
use std::io::{Read, Write};
use std::collections::HashMap;
use core::hash::Hash;
use std::sync::Mutex;
use core::cmp;

use bitcoin::secp256k1::Signature;
use bitcoin::secp256k1::key::{PublicKey, SecretKey};
use bitcoin::secp256k1::constants::{PUBLIC_KEY_SIZE, COMPACT_SIGNATURE_SIZE};
use bitcoin::blockdata::script::Script;
use bitcoin::blockdata::transaction::{OutPoint, Transaction, TxOut};
use bitcoin::consensus;
use bitcoin::consensus::Encodable;
use bitcoin::hashes::sha256d::Hash as Sha256dHash;
use bitcoin::hash_types::{Txid, BlockHash};
use core::marker::Sized;
use ln::msgs::DecodeError;
use ln::{PaymentPreimage, PaymentHash, PaymentSecret};

use util::byte_utils::{be48_to_array, slice_to_be48};

/// serialization buffer size
pub const MAX_BUF_SIZE: usize = 64 * 1024;

/// A trait that is similar to std::io::Write but has one extra function which can be used to size
/// buffers being written into.
/// An impl is provided for any type that also impls std::io::Write which simply ignores size
/// hints.
///
/// (C-not exported) as we only export serialization to/from byte arrays instead
pub trait Writer {
	/// Writes the given buf out. See std::io::Write::write_all for more
	fn write_all(&mut self, buf: &[u8]) -> Result<(), ::std::io::Error>;
	/// Hints that data of the given size is about the be written. This may not always be called
	/// prior to data being written and may be safely ignored.
	fn size_hint(&mut self, size: usize);
}

impl<W: Write> Writer for W {
	#[inline]
	fn write_all(&mut self, buf: &[u8]) -> Result<(), ::std::io::Error> {
		<Self as ::std::io::Write>::write_all(self, buf)
	}
	#[inline]
	fn size_hint(&mut self, _size: usize) { }
}

pub(crate) struct WriterWriteAdaptor<'a, W: Writer + 'a>(pub &'a mut W);
impl<'a, W: Writer + 'a> Write for WriterWriteAdaptor<'a, W> {
	fn write_all(&mut self, buf: &[u8]) -> Result<(), ::std::io::Error> {
		self.0.write_all(buf)
	}
	fn write(&mut self, buf: &[u8]) -> Result<usize, ::std::io::Error> {
		self.0.write_all(buf)?;
		Ok(buf.len())
	}
	fn flush(&mut self) -> Result<(), ::std::io::Error> {
		Ok(())
	}
}

pub(crate) struct VecWriter(pub Vec<u8>);
impl Writer for VecWriter {
	fn write_all(&mut self, buf: &[u8]) -> Result<(), ::std::io::Error> {
		self.0.extend_from_slice(buf);
		Ok(())
	}
	fn size_hint(&mut self, size: usize) {
		self.0.reserve_exact(size);
	}
}

/// Writer that only tracks the amount of data written - useful if you need to calculate the length
/// of some data when serialized but don't yet need the full data.
pub(crate) struct LengthCalculatingWriter(pub usize);
impl Writer for LengthCalculatingWriter {
	#[inline]
	fn write_all(&mut self, buf: &[u8]) -> Result<(), ::std::io::Error> {
		self.0 += buf.len();
		Ok(())
	}
	#[inline]
	fn size_hint(&mut self, _size: usize) {}
}

/// Essentially std::io::Take but a bit simpler and with a method to walk the underlying stream
/// forward to ensure we always consume exactly the fixed length specified.
pub(crate) struct FixedLengthReader<R: Read> {
	read: R,
	bytes_read: u64,
	total_bytes: u64,
}
impl<R: Read> FixedLengthReader<R> {
	pub fn new(read: R, total_bytes: u64) -> Self {
		Self { read, bytes_read: 0, total_bytes }
	}

	pub fn bytes_remain(&mut self) -> bool {
		self.bytes_read != self.total_bytes
	}

	pub fn eat_remaining(&mut self) -> Result<(), DecodeError> {
		::std::io::copy(self, &mut ::std::io::sink()).unwrap();
		if self.bytes_read != self.total_bytes {
			Err(DecodeError::ShortRead)
		} else {
			Ok(())
		}
	}
}
impl<R: Read> Read for FixedLengthReader<R> {
	fn read(&mut self, dest: &mut [u8]) -> Result<usize, ::std::io::Error> {
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

/// A Read which tracks whether any bytes have been read at all. This allows us to distinguish
/// between "EOF reached before we started" and "EOF reached mid-read".
pub(crate) struct ReadTrackingReader<R: Read> {
	read: R,
	pub have_read: bool,
}
impl<R: Read> ReadTrackingReader<R> {
	pub fn new(read: R) -> Self {
		Self { read, have_read: false }
	}
}
impl<R: Read> Read for ReadTrackingReader<R> {
	fn read(&mut self, dest: &mut [u8]) -> Result<usize, ::std::io::Error> {
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

/// A trait that various rust-lightning types implement allowing them to be written out to a Writer
///
/// (C-not exported) as we only export serialization to/from byte arrays instead
pub trait Writeable {
	/// Writes self out to the given Writer
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error>;

	/// Writes self out to a Vec<u8>
	fn encode(&self) -> Vec<u8> {
		let mut msg = VecWriter(Vec::new());
		self.write(&mut msg).unwrap();
		msg.0
	}

	/// Writes self out to a Vec<u8>
	fn encode_with_len(&self) -> Vec<u8> {
		let mut msg = VecWriter(Vec::new());
		0u16.write(&mut msg).unwrap();
		self.write(&mut msg).unwrap();
		let len = msg.0.len();
		msg.0[..2].copy_from_slice(&(len as u16 - 2).to_be_bytes());
		msg.0
	}
}

impl<'a, T: Writeable> Writeable for &'a T {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> { (*self).write(writer) }
}

/// A trait that various rust-lightning types implement allowing them to be read in from a Read
///
/// (C-not exported) as we only export serialization to/from byte arrays instead
pub trait Readable
	where Self: Sized
{
	/// Reads a Self in from the given Read
	fn read<R: Read>(reader: &mut R) -> Result<Self, DecodeError>;
}

/// A trait that various higher-level rust-lightning types implement allowing them to be read in
/// from a Read given some additional set of arguments which is required to deserialize.
///
/// (C-not exported) as we only export serialization to/from byte arrays instead
pub trait ReadableArgs<P>
	where Self: Sized
{
	/// Reads a Self in from the given Read
	fn read<R: Read>(reader: &mut R, params: P) -> Result<Self, DecodeError>;
}

/// A trait that various rust-lightning types implement allowing them to (maybe) be read in from a Read
///
/// (C-not exported) as we only export serialization to/from byte arrays instead
pub trait MaybeReadable
	where Self: Sized
{
	/// Reads a Self in from the given Read
	fn read<R: Read>(reader: &mut R) -> Result<Option<Self>, DecodeError>;
}

pub(crate) struct OptionDeserWrapper<T: Readable>(pub Option<T>);
impl<T: Readable> Readable for OptionDeserWrapper<T> {
	fn read<R: Read>(reader: &mut R) -> Result<Self, DecodeError> {
		Ok(Self(Some(Readable::read(reader)?)))
	}
}

const MAX_ALLOC_SIZE: u64 = 64*1024;

pub(crate) struct VecWriteWrapper<'a, T: Writeable>(pub &'a Vec<T>);
impl<'a, T: Writeable> Writeable for VecWriteWrapper<'a, T> {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
		(self.0.len() as u64).write(writer)?;
		for ref v in self.0.iter() {
			v.write(writer)?;
		}
		Ok(())
	}
}
pub(crate) struct VecReadWrapper<T: Readable>(pub Vec<T>);
impl<T: Readable> Readable for VecReadWrapper<T> {
	fn read<R: Read>(reader: &mut R) -> Result<Self, DecodeError> {
		let count: u64 = Readable::read(reader)?;
		let mut values = Vec::with_capacity(cmp::min(count, MAX_ALLOC_SIZE / (core::mem::size_of::<T>() as u64)) as usize);
		for _ in 0..count {
			match Readable::read(reader) {
				Ok(v) => { values.push(v); },
				Err(e) => return Err(e),
			}
		}
		Ok(Self(values))
	}
}

pub(crate) struct U48(pub u64);
impl Writeable for U48 {
	#[inline]
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
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

/// Lightning TLV uses a custom variable-length integer called BigSize. It is similar to Bitcoin's
/// variable-length integers except that it is serialized in big-endian instead of little-endian.
///
/// Like Bitcoin's variable-length integer, it exhibits ambiguity in that certain values can be
/// encoded in several different ways, which we must check for at deserialization-time. Thus, if
/// you're looking for an example of a variable-length integer to use for your own project, move
/// along, this is a rather poor design.
pub(crate) struct BigSize(pub u64);
impl Writeable for BigSize {
	#[inline]
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
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

/// In TLV we occasionally send fields which only consist of, or potentially end with, a
/// variable-length integer which is simply truncated by skipping high zero bytes. This type
/// encapsulates such integers implementing Readable/Writeable for them.
#[cfg_attr(test, derive(PartialEq, Debug))]
pub(crate) struct HighZeroBytesDroppedVarInt<T>(pub T);

macro_rules! impl_writeable_primitive {
	($val_type:ty, $len: expr) => {
		impl Writeable for $val_type {
			#[inline]
			fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
				writer.write_all(&self.to_be_bytes())
			}
		}
		impl Writeable for HighZeroBytesDroppedVarInt<$val_type> {
			#[inline]
			fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
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
		impl Readable for HighZeroBytesDroppedVarInt<$val_type> {
			#[inline]
			fn read<R: Read>(reader: &mut R) -> Result<HighZeroBytesDroppedVarInt<$val_type>, DecodeError> {
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
					Ok(HighZeroBytesDroppedVarInt(<$val_type>::from_be_bytes(bytes)))
				} else {
					// If the encoding had extra zero bytes, return a failure even though we know
					// what they meant (as the TLV test vectors require this)
					Err(DecodeError::InvalidValue)
				}
			}
		}
	}
}

impl_writeable_primitive!(u64, 8);
impl_writeable_primitive!(u32, 4);
impl_writeable_primitive!(u16, 2);

impl Writeable for u8 {
	#[inline]
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
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
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
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
			fn write<W: Writer>(&self, w: &mut W) -> Result<(), ::std::io::Error> {
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

//TODO: performance issue with [u8; size] with impl_array!()
impl_array!(3); // for rgb
impl_array!(4); // for IPv4
impl_array!(10); // for OnionV2
impl_array!(16); // for IPv6
impl_array!(32); // for channel id & hmac
impl_array!(PUBLIC_KEY_SIZE); // for PublicKey
impl_array!(COMPACT_SIGNATURE_SIZE); // for Signature
impl_array!(1300); // for OnionPacket.hop_data

// HashMap
impl<K, V> Writeable for HashMap<K, V>
	where K: Writeable + Eq + Hash,
	      V: Writeable
{
	#[inline]
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), ::std::io::Error> {
	(self.len() as u16).write(w)?;
		for (key, value) in self.iter() {
			key.write(w)?;
			value.write(w)?;
		}
		Ok(())
	}
}

impl<K, V> Readable for HashMap<K, V>
	where K: Readable + Eq + Hash,
	      V: Readable
{
	#[inline]
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		let len: u16 = Readable::read(r)?;
		let mut ret = HashMap::with_capacity(len as usize);
		for _ in 0..len {
			ret.insert(K::read(r)?, V::read(r)?);
		}
		Ok(ret)
	}
}

// Vectors
impl Writeable for Vec<u8> {
	#[inline]
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), ::std::io::Error> {
		(self.len() as u16).write(w)?;
		w.write_all(&self)
	}
}

impl Readable for Vec<u8> {
	#[inline]
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		let len: u16 = Readable::read(r)?;
		let mut ret = Vec::with_capacity(len as usize);
		ret.resize(len as usize, 0);
		r.read_exact(&mut ret)?;
		Ok(ret)
	}
}
impl Writeable for Vec<Signature> {
	#[inline]
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), ::std::io::Error> {
		(self.len() as u16).write(w)?;
		for e in self.iter() {
			e.write(w)?;
		}
		Ok(())
	}
}

impl Readable for Vec<Signature> {
	#[inline]
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		let len: u16 = Readable::read(r)?;
		let byte_size = (len as usize)
		                .checked_mul(COMPACT_SIGNATURE_SIZE)
		                .ok_or(DecodeError::BadLengthDescriptor)?;
		if byte_size > MAX_BUF_SIZE {
			return Err(DecodeError::BadLengthDescriptor);
		}
		let mut ret = Vec::with_capacity(len as usize);
		for _ in 0..len { ret.push(Signature::read(r)?); }
		Ok(ret)
	}
}

impl Writeable for Script {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), ::std::io::Error> {
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
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), ::std::io::Error> {
		self.serialize().write(w)
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
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), ::std::io::Error> {
		let mut ser = [0; 32];
		ser.copy_from_slice(&self[..]);
		ser.write(w)
	}
}

impl Readable for SecretKey {
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		let buf: [u8; 32] = Readable::read(r)?;
		match SecretKey::from_slice(&buf) {
			Ok(key) => Ok(key),
			Err(_) => return Err(DecodeError::InvalidValue),
		}
	}
}

impl Writeable for Sha256dHash {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), ::std::io::Error> {
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

impl Writeable for Signature {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), ::std::io::Error> {
		self.serialize_compact().write(w)
	}
}

impl Readable for Signature {
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		let buf: [u8; COMPACT_SIGNATURE_SIZE] = Readable::read(r)?;
		match Signature::from_compact(&buf) {
			Ok(sig) => Ok(sig),
			Err(_) => return Err(DecodeError::InvalidValue),
		}
	}
}

impl Writeable for PaymentPreimage {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), ::std::io::Error> {
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
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), ::std::io::Error> {
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
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), ::std::io::Error> {
		self.0.write(w)
	}
}

impl Readable for PaymentSecret {
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		let buf: [u8; 32] = Readable::read(r)?;
		Ok(PaymentSecret(buf))
	}
}

impl<T: Writeable> Writeable for Option<T> {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), ::std::io::Error> {
		match *self {
			None => 0u8.write(w)?,
			Some(ref data) => {
				let mut len_calc = LengthCalculatingWriter(0);
				data.write(&mut len_calc).expect("No in-memory data may fail to serialize");
				BigSize(len_calc.0 as u64 + 1).write(w)?;
				data.write(w)?;
			}
		}
		Ok(())
	}
}

impl<T: Readable> Readable for Option<T>
{
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		match BigSize::read(r)?.0 {
			0 => Ok(None),
			len => {
				let mut reader = FixedLengthReader::new(r, len - 1);
				Ok(Some(Readable::read(&mut reader)?))
			}
		}
	}
}

impl Writeable for Txid {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), ::std::io::Error> {
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
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), ::std::io::Error> {
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

impl Writeable for OutPoint {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), ::std::io::Error> {
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
			fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
				match self.consensus_encode(WriterWriteAdaptor(writer)) {
					Ok(_) => Ok(()),
					Err(e) => Err(e),
				}
			}
		}

		impl Readable for $bitcoin_type {
			fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
				match consensus::encode::Decodable::consensus_decode(r) {
					Ok(t) => Ok(t),
					Err(consensus::encode::Error::Io(ref e)) if e.kind() == ::std::io::ErrorKind::UnexpectedEof => Err(DecodeError::ShortRead),
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
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), ::std::io::Error> {
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
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), ::std::io::Error> {
		self.0.write(w)?;
		self.1.write(w)
	}
}
