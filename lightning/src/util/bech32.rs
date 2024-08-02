//! Bech32 encoding/decoding for lightning invoices.

use core::fmt;

#[allow(unused_imports)]
use crate::prelude::*;

/// An unsigned 5-bit value, in the range 0 - 31, the basic data block in Bech32 encoding.
/// Internally a byte is stored, but value is always in the 0--31 range.
/// The `u5` name is analogoue to the `u8`, `u16` etc. base types.
/// Based on 'u5' from `bech32` crate v `0.9.1` `<https://github.com/rust-bitcoin/rust-bech32/blob/v0.9.1/src/lib.rs>`
#[derive(Copy, Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[allow(non_camel_case_types)]
pub struct u5(u8);

/// Potential errors during Bech32 encoding/decoding operations.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Bech32Error {
	/// Bech32 string of invalid length
	InvalidLength,
	/// A value out of range, larger than 31.
	ValueOutOfRange(u8),
	/// Invalid Bech32 character
	InvalidCharacter(char),
}

impl u5 {
	/// Create from a u8 value.
	pub fn try_from_u8(n: u8) -> Result<Self, Bech32Error> {
		if n > Self::INNER_MAX {
			Err(Bech32Error::ValueOutOfRange(n))
		} else {
			Ok(Self(n))
		}
	}

	/// Create from a u8 value, without check, the input should be in the 0 - -31 range.
	/// Higher bits are nulled.
	pub fn from_u8(n: u8) -> Self {
		Self(n % Self::INNER_COUNT)
	}

	/// Access as u8. The value is guaranteed to be in the 0 - 31 range,
	/// but once it is in an `u8`, there is no way to enforce that.
	#[inline]
	pub fn as_u8(&self) -> u8 {
		self.0
	}

	const INNER_MAX: u8 = 31;
	const INNER_COUNT: u8 = 32;

	/// The zero value (character 'q')
	pub const ZERO: u5 = u5(0);

	/// The one value (character 'p')
	pub const ONE: u5 = u5(1);

	/// The maximum allowed numerical value, 31
	pub const MAX: u5 = u5(Self::INNER_MAX);

	/// Decode from Bech32 character
	pub fn try_from_char(c: char) -> Result<u5, Bech32Error> {
		CharConverter::from_char(c).ok_or(Bech32Error::InvalidCharacter(c))
	}

	/// Convert to Bech32 character, lowercase.
	pub fn to_char(&self) -> char {
		CharConverter::to_char(self)
	}

	/// Utility to pack a u5 slice to u8 vector.
	/// It is assumed that the u5 elements were padded, if the total number of bits
	/// is not a multiple of 8, any trailing bits are simply dropped.
	pub fn pack_to_bytes(unpacked: &[u5]) -> Vec<u8> {
		unpacked.iter().copied().pack_to_bytes().collect()
	}

	/// Utility to unpack u5 elements from a u8 slice.
	/// If the total number of bits is not a multiple of 5, they are right-padded with 0 bits.
	pub fn unpack_from_bytes(packed: &[u8]) -> Vec<u5> {
		packed.iter().copied().unpack_from_bytes().collect()
	}
}

/// Iterator adaptor that packs `u5` elements to bytes.
///
/// It is assumed that the u5 elements were padded, if the total number of bits
/// is not a multiple of 8, any trailing bits are dropped.
///
/// Based on `FesToBytes` from `rust-bech32` crate.
#[derive(Clone, PartialEq, Eq)]
pub struct U5Packer<I: Iterator<Item = u5>> {
	remain_bits: usize,
	remain_u8: u8,
	iter: I,
}

impl<I> U5Packer<I>
where
	I: Iterator<Item = u5>,
{
	fn new(iter: I) -> Self {
		Self { remain_bits: 0, remain_u8: 0, iter }
	}
}

impl<I> Iterator for U5Packer<I>
where
	I: Iterator<Item = u5>,
{
	type Item = u8;

	/// Retrieve the next packed byte
	fn next(&mut self) -> Option<u8> {
		let mut next_out: Option<u8> = None;
		// We may need to read two inputs to produce an output
		while next_out.is_none() {
			// Next input element. If there is none, we just stop
			let curr_in = self.iter.next()?;
			if self.remain_bits >= 3 {
				// we have a new full byte -- 3 or 4 remain bits, plus 5 new ones
				next_out = Some(self.remain_u8 | (curr_in.0 >> (self.remain_bits - 3)));
				let to_remain_shift = (8 + 3) - self.remain_bits;
				self.remain_u8 = if to_remain_shift < 8 { curr_in.0 << to_remain_shift } else { 0 };
				self.remain_bits -= 3; // added 5, removed 8
			} else {
				// only 0, 1, or 2 remain bits,  plus 5 new ones
				self.remain_u8 = self.remain_u8 | (curr_in.0 << (3 - self.remain_bits));
				self.remain_bits += 5;
				next_out = None;
			}
		}
		// we have a next
		next_out
	}

	#[inline]
	fn size_hint(&self) -> (usize, Option<usize>) {
		// If the total number of bits is not a multiple of 8, any trailing bits are dropped.
		let unpacked_len_to_packed_len = |n| n * 5 / 8;

		let (unpacked_min, unpacked_max) = self.iter.size_hint();
		// +1 because we set last_fe with call to `next`.
		let min = unpacked_len_to_packed_len(unpacked_min + 1);
		let max = unpacked_max.map(|max| unpacked_len_to_packed_len(max + 1));
		(min, max)
	}
}

/// Extension trait for field element iterators.
pub trait PackU5IterExt: Sized + Iterator<Item = u5> {
	/// Adapts the `u5` iterator to output packed bytes.
	///
	/// It is assumed that the u5 elements were padded, if the total number of bits
	/// is not a multiple of 8, any trailing bits are simply dropped.
	#[inline]
	fn pack_to_bytes(self) -> U5Packer<Self> {
		U5Packer::new(self)
	}
}

impl<I> PackU5IterExt for I where I: Iterator<Item = u5> {}

/// Iterator adaptor that unpacks `u5` elements from a stream of packed bytes.
///
/// If the total number of bits is not a multiple of 5, they are right-padded with 0 bits.
///
/// Based on `BytesToFes` from `rust-bech32` crate.
#[derive(Clone, PartialEq, Eq)]
pub struct U5Unpacker<I: Iterator<Item = u8>> {
	remain_bits: usize,
	remain_u8: u8,
	iter: I,
}

impl<I> U5Unpacker<I>
where
	I: Iterator<Item = u8>,
{
	fn new(iter: I) -> Self {
		Self { remain_bits: 0, remain_u8: 0, iter }
	}
}

impl<I> Iterator for U5Unpacker<I>
where
	I: Iterator<Item = u8>,
{
	type Item = u5;

	#[inline]
	fn next(&mut self) -> Option<u5> {
		let next_out = if self.remain_bits >= 5 {
			// We have enough remained bits for an output, no need to read the input
			let next_out = self.remain_u8;
			self.remain_u8 = self.remain_u8 << 5;
			self.remain_bits -= 5;
			next_out
		} else {
			if let Some(curr_in) = self.iter.next() {
				// we have at least one u5 to output (maybe two)
				let next_out = self.remain_u8 | (curr_in >> self.remain_bits);
				let to_remain_shift = 5 - self.remain_bits;
				self.remain_u8 = curr_in << to_remain_shift;
				self.remain_bits += 3; // added 8, removed 5
				next_out
			} else {
				// No more inputs, output remaining (if any)
				if self.remain_bits > 0 {
					self.remain_bits = 0;
					self.remain_u8
				} else {
					return None;
				}
			}
		};
		// Isolate the 5 left bits
		Some(u5(next_out >> 3))
	}
}

/// Extension trait for byte iterators which provides an adaptor to GF32 elements.
pub trait UnpackU5IterExt: Sized + Iterator<Item = u8> {
	/// Adapts the u8 iterator to output unpacked u5 elements.
	///
	/// If the total number of bits is not a multiple of 5, they are right-padded with 0 bits.
	#[inline]
	fn unpack_from_bytes(self) -> U5Unpacker<Self> {
		U5Unpacker::new(self)
	}
}

impl<I> UnpackU5IterExt for I where I: Iterator<Item = u8> {}

impl fmt::Display for Bech32Error {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
		let s = match self {
			Bech32Error::InvalidLength => {
				format!("Invalid length")
			},
			Bech32Error::InvalidCharacter(c) => {
				format!("Invalid character ({})", c)
			},
			Bech32Error::ValueOutOfRange(v) => {
				format!("Out-of-range value ({})", v)
			},
		};
		f.write_str(&s)
	}
}

/// Interface to write `u5`s into a sink.
pub trait WriteBase32 {
	/// Write error
	type Err: fmt::Debug;

	/// Write a `u5` slice.
	fn write(&mut self, data: &[u5]) -> Result<(), Self::Err> {
		for b in data {
			self.write_u5(*b)?;
		}
		Ok(())
	}

	/// Write a single `u5`.
	fn write_u5(&mut self, data: u5) -> Result<(), Self::Err>;
}

/// A trait for converting a value to a `u5` vector.
pub trait ToBase32 {
	/// Convert `Self` to base32 vector
	fn to_base32(&self) -> Vec<u5> {
		let mut vec = Vec::new();
		self.write_base32(&mut vec).unwrap();
		vec
	}

	/// Encode as base32 and write it to the supplied writer
	/// Implementations shouldn't allocate.
	fn write_base32<W: WriteBase32>(&self, writer: &mut W) -> Result<(), <W as WriteBase32>::Err>;
}

/// Interface to calculate the length of the base32 representation before actually serializing
pub trait Base32Len: ToBase32 {
	/// Calculate the base32 serialized length
	fn base32_len(&self) -> usize;
}

/// Trait for paring/converting base32 slice. It is the reciprocal of `ToBase32`.
pub trait FromBase32: Sized {
	/// The associated error which can be returned from parsing (e.g. because of bad padding).
	type Err;

	/// Convert a base32 slice to `Self`.
	fn from_base32(b32: &[u5]) -> Result<Self, Self::Err>;
}

impl WriteBase32 for Vec<u5> {
	type Err = ();

	fn write(&mut self, data: &[u5]) -> Result<(), Self::Err> {
		self.extend_from_slice(data);
		Ok(())
	}

	fn write_u5(&mut self, data: u5) -> Result<(), Self::Err> {
		self.push(data);
		Ok(())
	}
}

impl ToBase32 for [u8] {
	/// Encode as base32 and write it to the supplied writer
	fn write_base32<W: WriteBase32>(&self, writer: &mut W) -> Result<(), <W as WriteBase32>::Err> {
		writer.write(&self.iter().copied().unpack_from_bytes().collect::<Vec<u5>>())
	}
}

impl ToBase32 for Vec<u8> {
	/// Encode as base32 and write it to the supplied writer
	fn write_base32<W: WriteBase32>(&self, writer: &mut W) -> Result<(), <W as WriteBase32>::Err> {
		self.as_slice().write_base32(writer)
	}
}

impl Base32Len for [u8] {
	/// Calculate the base32 serialized length
	fn base32_len(&self) -> usize {
		// rounded up
		(self.len() * 8 + (5 - 1)) / 5
	}
}

impl Base32Len for Vec<u8> {
	/// Calculate the base32 serialized length
	fn base32_len(&self) -> usize {
		self.as_slice().base32_len()
	}
}

impl FromBase32 for Vec<u8> {
	type Err = Bech32Error;

	fn from_base32(data: &[u5]) -> Result<Self, Self::Err> {
		Ok(data.iter().copied().pack_to_bytes().collect::<Self>())
	}
}

/// Bech32 character encoding/decoding logic (lookup tables).
/// Bsed on 'u5' from `bech32` crate v `0.9.1` `<https://github.com/rust-bitcoin/rust-bech32/blob/v0.9.1/src/lib.rs>`
struct CharConverter {}

impl CharConverter {
	/// Encode a u5 value to char.
	fn to_char(a: &u5) -> char {
		Self::CHARS_LOWER[(a.as_u8() % 32) as usize]
	}

	/// Decode a character to a u5 value.
	fn from_char(c: char) -> Option<u5> {
		let cascii = u32::from(c);
		if cascii <= 127 {
			let idx = Self::CHARS_INV[cascii as usize];
			if idx >= 0 && idx < 32 {
				return Some(u5::from_u8(idx as u8));
			}
		}
		None
	}

	/// Mapping from numeric value to bech32 character.
    #[rustfmt::skip]
	const CHARS_LOWER: [char; 32] = [
        'q', 'p', 'z', 'r', 'y', '9', 'x', '8', //  +0
        'g', 'f', '2', 't', 'v', 'd', 'w', '0', //  +8
        's', '3', 'j', 'n', '5', '4', 'k', 'h', // +16
        'c', 'e', '6', 'm', 'u', 'a', '7', 'l', // +24
    ];

	/// Mapping from bech32 character (either case) to numeric value.
	///
	/// E.g., 'z' is `CHARS_LOWER[2]` and is ASCII value `122` so `CHARS_INV[122] == 2`
    #[rustfmt::skip]
	const CHARS_INV: [i8; 128] = [
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        15, -1, 10, 17, 21, 20, 26, 30,  7,  5, -1, -1, -1, -1, -1, -1,
        -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
        1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1,
        -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
        1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1,
    ];
}

#[cfg(test)]
mod test {
	use super::{u5, Base32Len, Bech32Error, FromBase32, PackU5IterExt, ToBase32, UnpackU5IterExt};

	#[test]
	fn u5_from_u8() {
		for i in 0..31 {
			assert_eq!(u5::from_u8(i).as_u8(), i);
		}
		assert_eq!(u5::from_u8(32).as_u8(), 0);
		assert_eq!(u5::from_u8(100).as_u8(), 4);
	}

	#[test]
	fn u5_try_from_u8() {
		for i in 0..31 {
			assert_eq!(u5::try_from_u8(i).unwrap().as_u8(), i);
		}
		assert_eq!(u5::try_from_u8(32).err().unwrap(), Bech32Error::ValueOutOfRange(32));
		assert_eq!(u5::try_from_u8(100).err().unwrap(), Bech32Error::ValueOutOfRange(100));
	}

	#[test]
	fn u5_default() {
		assert_eq!(u5::default().as_u8(), 0);
	}

	#[test]
	fn u5_const() {
		assert_eq!(u5::ZERO.as_u8(), 0);
		assert_eq!(u5::ONE.as_u8(), 1);
		assert_eq!(u5::MAX.as_u8(), 31);
	}

	#[test]
	fn pack_to_bytes() {
		{
			let u5vec = [u5::ZERO];
			let u8vec = u5::pack_to_bytes(&u5vec);
			assert_eq!(u8vec.len(), 0);
		}
		{
			let u5vec: Vec<u5> = [0u8, 0].iter().map(|n| u5::from_u8(*n)).collect();
			let u8vec = u5::pack_to_bytes(&u5vec);
			let expectedu8 = vec![0];
			assert_eq!(u8vec.len(), 1);
			assert_eq!(u8vec, expectedu8);
		}
		{
			// 10101000 00
			let u5vec: Vec<u5> = [21u8, 0].iter().map(|n| u5::from_u8(*n)).collect();
			let u8vec = u5::pack_to_bytes(&u5vec);
			let expectedu8 = vec![21 << 3];
			assert_eq!(u8vec, expectedu8);
		}
		{
			// 10101101 01
			let u5vec: Vec<u5> = [21u8, 21].iter().map(|n| u5::from_u8(*n)).collect();
			let u8vec = u5::pack_to_bytes(&u5vec);
			let expectedu8 = vec![(21 << 3) + (21 >> 2)];
			assert_eq!(u8vec, expectedu8);
		}
		{
			// 00001000 10000110 0100
			let u5vec: Vec<u5> = [1u8, 2, 3, 4].iter().map(|n| u5::from_u8(*n)).collect();
			let u8vec = u5::pack_to_bytes(&u5vec);
			let expectedu8 = vec![8, 134];
			assert_eq!(u8vec, expectedu8);
		}
		{
			// 00001000 10000110 01000010 10011000 11101000
			let u5vec: Vec<u5> =
				[1u8, 2, 3, 4, 5, 6, 7, 8].iter().map(|n| u5::from_u8(*n)).collect();
			let u8vec = u5::pack_to_bytes(&u5vec);
			let expectedu8 = vec![8, 134, 66, 152, 232];
			assert_eq!(u8vec, expectedu8);
		}
	}

	#[test]
	fn unpack_from_bytes() {
		{
			// 00001 00010 00011 0
			let u8vec = vec![8, 134];
			let u5vec = u5::unpack_from_bytes(&u8vec);
			let expectedu5: Vec<u5> = [1u8, 2, 3, 0].iter().map(|n| u5::from_u8(*n)).collect();
			assert_eq!(u5vec, expectedu5);
		}
		{
			// 00001 00010 00011 00100 0000
			let u8vec = vec![8, 134, 64];
			let u5vec = u5::unpack_from_bytes(&u8vec);
			let expectedu5: Vec<u5> = [1u8, 2, 3, 4, 0].iter().map(|n| u5::from_u8(*n)).collect();
			assert_eq!(u5vec, expectedu5);
		}
		{
			// 00001 00010 00011 00100 00101 00110 00111 01000
			let u8vec = vec![8, 134, 66, 152, 232];
			let u5vec = u5::unpack_from_bytes(&u8vec);
			let expectedu5: Vec<u5> =
				[1, 2, 3, 4, 5, 6, 7, 8].iter().map(|n| u5::from_u8(*n)).collect();
			assert_eq!(u5vec, expectedu5);
		}
	}

	#[test]
	fn pack_methods() {
		// Different ways to invoke packing
		let u5vec: Vec<u5> = [1u8, 2, 3, 4].iter().map(|n| u5::from_u8(*n)).collect();
		let expectedu8 = vec![8, 134];
		{
			// iterator
			let u8vec: Vec<u8> = u5vec.iter().copied().pack_to_bytes().collect();
			assert_eq!(u8vec, expectedu8);
		}
		{
			// associated method on u5
			let u8vec = u5::pack_to_bytes(&u5vec);
			assert_eq!(u8vec, expectedu8);
		}
		{
			// trait on Vec<u8>
			let u8vec = Vec::<u8>::from_base32(&u5vec).unwrap();
			assert_eq!(u8vec, expectedu8);
		}
	}

	#[test]
	fn unpack_methods() {
		// Different ways to invoke unpacking
		let u8vec = vec![8, 134, 64];
		let expectedu5: Vec<u5> = [1u8, 2, 3, 4, 0].iter().map(|n| u5::from_u8(*n)).collect();
		{
			// iterator
			let u5vec: Vec<u5> = u8vec.iter().copied().unpack_from_bytes().collect();
			assert_eq!(u5vec, expectedu5);
		}
		{
			// associated method on u5
			let u5vec = u5::unpack_from_bytes(&u8vec);
			assert_eq!(u5vec, expectedu5);
		}
		{
			// trait on [u8]
			let u5vec = (&u8vec).to_base32();
			assert_eq!(u5vec, expectedu5);
			assert_eq!((&u8vec).base32_len(), expectedu5.len());
		}
		{
			// trait on Vec<u8>
			let u5vec = u8vec.to_base32();
			assert_eq!(u5vec, expectedu5);
			assert_eq!(u8vec.base32_len(), expectedu5.len());
		}
	}

	#[test]
	fn char_encode() {
		assert_eq!(u5::ZERO.to_char(), 'q');
		assert_eq!(u5::ONE.to_char(), 'p');
		assert_eq!(u5::from_u8(2).to_char(), 'z');
		assert_eq!(u5::from_u8(3).to_char(), 'r');
		assert_eq!(u5::from_u8(5).to_char(), '9');
		assert_eq!(u5::from_u8(10).to_char(), '2');
		assert_eq!(u5::from_u8(15).to_char(), '0');
		assert_eq!(u5::from_u8(24).to_char(), 'c');
		assert_eq!(u5::from_u8(29).to_char(), 'a');
		assert_eq!(u5::from_u8(31).to_char(), 'l');
	}

	#[test]
	fn char_decode() {
		assert_eq!(u5::try_from_char('a').unwrap(), u5::from_u8(29));
		assert_eq!(u5::try_from_char('c').unwrap(), u5::from_u8(24));
		assert_eq!(u5::try_from_char('l').unwrap(), u5::from_u8(31));
		assert_eq!(u5::try_from_char('p').unwrap(), u5::ONE);
		assert_eq!(u5::try_from_char('q').unwrap(), u5::ZERO);
		assert_eq!(u5::try_from_char('r').unwrap(), u5::from_u8(3));
		assert_eq!(u5::try_from_char('z').unwrap(), u5::from_u8(2));
		assert_eq!(u5::try_from_char('0').unwrap(), u5::from_u8(15));
		assert_eq!(u5::try_from_char('2').unwrap(), u5::from_u8(10));
		assert_eq!(u5::try_from_char('9').unwrap(), u5::from_u8(5));

		assert_eq!(u5::try_from_char('A').unwrap(), u5::from_u8(29));
		assert_eq!(u5::try_from_char('C').unwrap(), u5::from_u8(24));
		assert_eq!(u5::try_from_char('Z').unwrap(), u5::from_u8(2));

		assert_eq!(u5::try_from_char('b').err().unwrap(), Bech32Error::InvalidCharacter('b'));
		assert_eq!(u5::try_from_char('1').err().unwrap(), Bech32Error::InvalidCharacter('1'));
	}

	#[test]
	fn u8slice_base32_len() {
		assert_eq!([0u8; 0].base32_len(), 0);
		assert_eq!([0u8; 1].base32_len(), 2);
		assert_eq!([0u8; 2].base32_len(), 4);
		assert_eq!([0u8; 3].base32_len(), 5);
		assert_eq!([0u8; 4].base32_len(), 7);
		assert_eq!([0u8; 5].base32_len(), 8);
		assert_eq!([0u8; 6].base32_len(), 10);
		assert_eq!([0u8; 20].base32_len(), 32);
	}

	#[test]
	fn bech32_error() {
		assert_eq!(Bech32Error::InvalidLength.to_string(), "Invalid length");
		assert_eq!(format!("{}", Bech32Error::InvalidLength), "Invalid length");
		assert_eq!(format!("{:?}", Bech32Error::InvalidLength), "InvalidLength");
		assert_eq!(Bech32Error::ValueOutOfRange(3).to_string(), "Out-of-range value (3)");
	}
}
