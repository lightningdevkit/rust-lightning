#[cfg(not(feature = "std"))]
/// Re-export of either `core2::io` or `std::io`, depending on the `std` feature flag.
pub use core2::io::*;
#[cfg(feature = "std")]
/// Re-export of either `core2::io` or `std::io`, depending on the `std` feature flag.
pub use std::io::*;

/// Emulation of std::io::Cursor
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Cursor<T> {
	inner: T,
	pos: u64,
}

impl<T> Cursor<T> {
	/// Creates a `Cursor` by wrapping `inner`.
	#[inline]
	pub fn new(inner: T) -> Cursor<T> {
		Cursor { pos: 0, inner }
	}

	/// Returns the position read up to thus far.
	#[inline]
	pub fn position(&self) -> u64 {
		self.pos
	}

	/// Returns the inner buffer.
	///
	/// This is the whole wrapped buffer, including the bytes already read.
	#[inline]
	pub fn into_inner(self) -> T {
		self.inner
	}

	/// Gets a reference to the underlying value in this cursor.
	pub fn get_ref(&self) -> &T {
		&self.inner
	}

	/// Gets a mutable reference to the underlying value in this cursor.
	///
	/// Care should be taken to avoid modifying the internal I/O state of the
	/// underlying value as it may corrupt this cursor's position.
	pub fn get_mut(&mut self) -> &mut T {
		&mut self.inner
	}

	/// Sets the position of this cursor.
	pub fn set_position(&mut self, pos: u64) {
		self.pos = pos;
	}
}

impl<T: AsRef<[u8]>> Read for Cursor<T> {
	fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
		let n = Read::read(&mut self.fill_buf()?, buf)?;
		self.pos += n as u64;
		Ok(n)
	}

	fn read_exact(&mut self, buf: &mut [u8]) -> Result<()> {
		let n = buf.len();
		Read::read_exact(&mut self.fill_buf()?, buf)?;
		self.pos += n as u64;
		Ok(())
	}
}

impl<T: AsRef<[u8]>> BufRead for Cursor<T> {
	fn fill_buf(&mut self) -> Result<&[u8]> {
		let amt = core::cmp::min(self.pos, self.inner.as_ref().len() as u64);
		Ok(&self.inner.as_ref()[(amt as usize)..])
	}
	fn consume(&mut self, amt: usize) {
		self.pos += amt as u64;
	}
}
