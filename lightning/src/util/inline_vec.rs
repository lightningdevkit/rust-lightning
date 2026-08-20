// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Buffers which store short contents inline rather than on the heap. See [`InlineVec`] and
//! [`InlineStr`].

use alloc::vec::Vec;
use core::cmp;
use core::fmt;
use core::hash::{Hash, Hasher};
use core::ops::{Deref, DerefMut};

/// A byte buffer which holds up to `N` bytes inline, spilling onto the heap only if it grows
/// beyond that.
///
/// Note that a `Vec` is always three pointers long, so a buffer of this form is never shorter than
/// 24 bytes on 64-bit platforms no matter what `N` is.
///
/// Luckily, because `Vec` uses a `NonNull` pointer to its buffer, the two-variant enum is free
/// space-wise, but we only get the remaining 2 usizes in length available for our own stuff (as
/// any other value is interpreted as the `Heap` variant).
///
/// Thus, as long as `N` is no more than 15 (i.e. 15 bytes of data plus one byte of length on
/// 64-bit platforms), this is the same length as a `Vec` in memory.
#[derive(Clone, Eq)]
pub enum InlineVec<const N: usize> {
	/// Contents which fit inline, of which only the first `len` bytes are in use.
	// TODO: Once `generic_const_exprs` is available, bound this on the low end at
	// `size_of::<usize>() * 2 - 1` bytes, i.e. the space we get for free anyway.
	Held { bytes: [u8; N], len: u8 },
	/// Contents which did not fit inline and are thus held on the heap.
	Heap(Vec<u8>),
}

impl<const N: usize> InlineVec<N> {
	/// Checks, at compile time, that the inline length fits in the `u8` we track it with.
	///
	/// This is only checked for the `N`s we actually use, i.e. it must be read somewhere in each
	/// method which can construct a [`Self::Held`].
	const ASSERT_INLINE_LEN_FITS: () = assert!(N <= u8::MAX as usize);

	/// Constructs an empty [`InlineVec`]
	pub fn empty() -> Self {
		let () = Self::ASSERT_INLINE_LEN_FITS;
		Self::Held { bytes: [0; N], len: 0 }
	}

	/// Constructs an [`InlineVec`] from the given bytes
	pub fn from(vec: Vec<u8>) -> Self {
		let () = Self::ASSERT_INLINE_LEN_FITS;
		if vec.len() <= N {
			let mut bytes = [0; N];
			bytes[..vec.len()].copy_from_slice(&vec);
			Self::Held { bytes, len: vec.len() as u8 }
		} else {
			Self::Heap(vec)
		}
	}

	/// Resizes an [`InlineVec`] to the given length, padding with `default` if required.
	///
	/// See [`Vec::resize`] for more info.
	pub fn resize(&mut self, new_len: usize, default: u8) {
		let () = Self::ASSERT_INLINE_LEN_FITS;
		match self {
			Self::Held { bytes, len } => {
				let start_len = *len as usize;
				if new_len <= N {
					bytes[start_len..].copy_from_slice(&[default; N][start_len..]);
					*len = new_len as u8;
				} else {
					let mut vec = Vec::new();
					vec.resize(new_len, default);
					vec[..start_len].copy_from_slice(&bytes[..start_len]);
					*self = Self::Heap(vec);
				}
			},
			Self::Heap(vec) => {
				vec.resize(new_len, default);
				if new_len <= N {
					let mut bytes = [0; N];
					bytes[..new_len].copy_from_slice(&vec[..new_len]);
					*self = Self::Held { bytes, len: new_len as u8 };
				}
			},
		}
	}

	/// Appends the given bytes to this [`InlineVec`], moving it onto the heap if they no longer
	/// fit inline.
	pub fn extend_from_slice(&mut self, other: &[u8]) {
		let () = Self::ASSERT_INLINE_LEN_FITS;
		match self {
			Self::Held { bytes, len } => {
				let start_len = *len as usize;
				let new_len = start_len.saturating_add(other.len());
				if new_len <= N {
					bytes[start_len..new_len].copy_from_slice(other);
					*len = new_len as u8;
				} else {
					let mut vec = Vec::with_capacity(new_len);
					vec.extend_from_slice(&bytes[..start_len]);
					vec.extend_from_slice(other);
					*self = Self::Heap(vec);
				}
			},
			Self::Heap(vec) => vec.extend_from_slice(other),
		}
	}

	/// Fetches the length of the [`InlineVec`], in bytes.
	pub fn len(&self) -> usize {
		self.deref().len()
	}

	/// Fetches an iterator over the bytes of this [`InlineVec`]
	pub fn iter(
		&self,
	) -> impl Clone + ExactSizeIterator<Item = &u8> + DoubleEndedIterator<Item = &u8> {
		let slice = self.deref();
		slice.iter()
	}

	/// Fetches a mutable iterator over the bytes of this [`InlineVec`]
	pub fn iter_mut(
		&mut self,
	) -> impl ExactSizeIterator<Item = &mut u8> + DoubleEndedIterator<Item = &mut u8> {
		let slice = self.deref_mut();
		slice.iter_mut()
	}
}

impl<const N: usize> Deref for InlineVec<N> {
	type Target = [u8];
	fn deref(&self) -> &[u8] {
		match self {
			InlineVec::Held { bytes, len } => &bytes[..*len as usize],
			InlineVec::Heap(vec) => &vec,
		}
	}
}

impl<const N: usize> DerefMut for InlineVec<N> {
	fn deref_mut(&mut self) -> &mut [u8] {
		match self {
			InlineVec::Held { bytes, len } => &mut bytes[..*len as usize],
			InlineVec::Heap(vec) => &mut vec[..],
		}
	}
}

impl<const N: usize> PartialEq for InlineVec<N> {
	fn eq(&self, other: &Self) -> bool {
		self.deref() == other.deref()
	}
}
impl<const N: usize> PartialOrd for InlineVec<N> {
	fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
		Some(self.cmp(other))
	}
}
impl<const N: usize> Ord for InlineVec<N> {
	fn cmp(&self, other: &Self) -> cmp::Ordering {
		self.deref().cmp(other.deref())
	}
}
impl<const N: usize> Hash for InlineVec<N> {
	fn hash<H: Hasher>(&self, hasher: &mut H) {
		self.deref().hash(hasher);
	}
}
impl<const N: usize> fmt::Debug for InlineVec<N> {
	fn fmt(&self, fmt: &mut fmt::Formatter) -> Result<(), fmt::Error> {
		self.deref().fmt(fmt)
	}
}

/// A string which holds up to `N` bytes inline, spilling onto the heap only if it grows beyond
/// that.
///
/// Written to via its [`fmt::Write`] implementation, which, unlike the buffer's capacity, is not
/// limited to `N` bytes.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct InlineStr<const N: usize>(InlineVec<N>);

impl<const N: usize> InlineStr<N> {
	/// Constructs an empty [`InlineStr`]
	pub fn new() -> Self {
		Self(InlineVec::empty())
	}

	/// Fetches the contents of this [`InlineStr`] as a string.
	pub fn as_str(&self) -> &str {
		// Only whole `&str`s are ever appended, so the buffer always holds valid UTF-8.
		match core::str::from_utf8(&self.0) {
			Ok(s) => s,
			Err(_) => {
				debug_assert!(false, "An InlineStr should only ever contain valid UTF-8");
				""
			},
		}
	}
}

impl<const N: usize> fmt::Write for InlineStr<N> {
	fn write_str(&mut self, s: &str) -> fmt::Result {
		self.0.extend_from_slice(s.as_bytes());
		Ok(())
	}
}

impl<const N: usize> fmt::Display for InlineStr<N> {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		fmt::Display::fmt(self.as_str(), f)
	}
}

impl<const N: usize> fmt::Debug for InlineStr<N> {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		fmt::Debug::fmt(self.as_str(), f)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use core::fmt::Write as _;

	#[test]
	fn inline_vec_spills_to_the_heap_when_appended_past_its_capacity() {
		let mut vec = InlineVec::<4>::empty();
		vec.extend_from_slice(&[1, 2]);
		vec.extend_from_slice(&[3, 4]);
		assert!(matches!(vec, InlineVec::Held { .. }));
		assert_eq!(&vec[..], &[1, 2, 3, 4]);

		vec.extend_from_slice(&[5]);
		assert!(matches!(vec, InlineVec::Heap(_)));
		assert_eq!(&vec[..], &[1, 2, 3, 4, 5]);

		assert_eq!(vec, InlineVec::<4>::from(alloc::vec![1, 2, 3, 4, 5]));

		// The inline bytes past the length are not necessarily zeroed, but only the contents are
		// ever compared.
		let mut short = InlineVec::<4>::from(alloc::vec![1, 2, 3, 4]);
		short.resize(2, 0);
		assert_eq!(short, InlineVec::<4>::from(alloc::vec![1, 2]));
	}

	#[test]
	fn inline_vec_moves_between_inline_and_heap_storage_when_resized() {
		let mut vec = InlineVec::<4>::empty();
		assert!(matches!(vec, InlineVec::Held { .. }));

		vec.resize(4, 42);
		assert_eq!(vec.len(), 4);
		assert!(vec.iter().all(|b| *b == 42));
		assert!(matches!(vec, InlineVec::Held { .. }));

		vec.resize(8, 43);
		assert_eq!(vec.len(), 8);
		assert!(vec.iter().take(4).all(|b| *b == 42));
		assert!(vec.iter().skip(4).all(|b| *b == 43));
		assert!(matches!(vec, InlineVec::Heap(_)));

		vec.resize(4, 0);
		assert_eq!(vec.len(), 4);
		assert!(vec.iter().all(|b| *b == 42));
		assert!(matches!(vec, InlineVec::Held { .. }));
	}

	#[test]
	fn inline_str_writes_are_infallible() {
		let mut buf = InlineStr::<4>::new();
		assert_eq!(buf.as_str(), "");

		assert!(write!(&mut buf, "ab").is_ok());
		assert!(write!(&mut buf, "cd").is_ok());
		assert_eq!(buf.as_str(), "abcd");

		// A write which does not fit inline moves the contents to the heap rather than failing or
		// truncating, which would risk splitting a multi-byte character.
		assert!(write!(&mut buf, "é").is_ok());
		assert_eq!(buf.as_str(), "abcdé");
	}
}
