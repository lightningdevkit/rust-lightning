//! Lightning exposes sets of supported operations through "feature flags". This module includes
//! types to store those feature flags and query for specific flags.

use std::{cmp, fmt};
use std::result::Result;
use std::marker::PhantomData;

use ln::msgs::DecodeError;
use util::ser::{Readable, Writeable, Writer};

mod sealed { // You should just use the type aliases instead.
	pub struct InitContext {}
	pub struct NodeContext {}
	pub struct ChannelContext {}

	/// An internal trait capturing the various feature context types
	pub trait Context {}
	impl Context for InitContext {}
	impl Context for NodeContext {}
	impl Context for ChannelContext {}

	pub trait DataLossProtect: Context {}
	impl DataLossProtect for InitContext {}
	impl DataLossProtect for NodeContext {}

	pub trait InitialRoutingSync: Context {}
	impl InitialRoutingSync for InitContext {}

	pub trait UpfrontShutdownScript: Context {}
	impl UpfrontShutdownScript for InitContext {}
	impl UpfrontShutdownScript for NodeContext {}

	pub trait VariableLengthOnion: Context {}
	impl VariableLengthOnion for InitContext {}
	impl VariableLengthOnion for NodeContext {}
}

/// Tracks the set of features which a node implements, templated by the context in which it
/// appears.
pub struct Features<T: sealed::Context> {
	/// Note that, for convinience, flags is LITTLE endian (despite being big-endian on the wire)
	flags: Vec<u8>,
	mark: PhantomData<T>,
}

impl<T: sealed::Context> Clone for Features<T> {
	fn clone(&self) -> Self {
		Self {
			flags: self.flags.clone(),
			mark: PhantomData,
		}
	}
}
impl<T: sealed::Context> PartialEq for Features<T> {
	fn eq(&self, o: &Self) -> bool {
		self.flags.eq(&o.flags)
	}
}
impl<T: sealed::Context> fmt::Debug for Features<T> {
	fn fmt(&self, fmt: &mut fmt::Formatter) -> Result<(), fmt::Error> {
		self.flags.fmt(fmt)
	}
}

/// A feature message as it appears in an init message
pub type InitFeatures = Features<sealed::InitContext>;
/// A feature message as it appears in a node_announcement message
pub type NodeFeatures = Features<sealed::NodeContext>;
/// A feature message as it appears in a channel_announcement message
pub type ChannelFeatures = Features<sealed::ChannelContext>;

impl InitFeatures {
	/// Create a Features with the features we support
	pub fn supported() -> InitFeatures {
		InitFeatures {
			flags: vec![2 | 1 << 5, 1 << (9-8)],
			mark: PhantomData,
		}
	}

	/// Writes all features present up to, and including, 13.
	pub(crate) fn write_up_to_13<W: Writer>(&self, w: &mut W) -> Result<(), ::std::io::Error> {
		let len = cmp::min(2, self.flags.len());
		w.size_hint(len + 2);
		(len as u16).write(w)?;
		for i in (0..len).rev() {
			if i == 0 {
				self.flags[i].write(w)?;
			} else {
				// On byte 1, we want up-to-and-including-bit-13, 0-indexed, which is
				// up-to-and-including-bit-5, 0-indexed, on this byte:
				(self.flags[i] & 0b00_11_11_11).write(w)?;
			}
		}
		Ok(())
	}

	/// or's another InitFeatures into this one.
	pub(crate) fn or(mut self, o: InitFeatures) -> InitFeatures {
		let total_feature_len = cmp::max(self.flags.len(), o.flags.len());
		self.flags.resize(total_feature_len, 0u8);
		for (byte, o_byte) in self.flags.iter_mut().zip(o.flags.iter()) {
			*byte |= *o_byte;
		}
		self
	}
}

impl ChannelFeatures {
	/// Create a Features with the features we support
	#[cfg(not(feature = "fuzztarget"))]
	pub(crate) fn supported() -> ChannelFeatures {
		ChannelFeatures {
			flags: Vec::new(),
			mark: PhantomData,
		}
	}
	#[cfg(feature = "fuzztarget")]
	pub fn supported() -> ChannelFeatures {
		ChannelFeatures {
			flags: Vec::new(),
			mark: PhantomData,
		}
	}

	/// Takes the flags that we know how to interpret in an init-context features that are also
	/// relevant in a channel-context features and creates a channel-context features from them.
	pub(crate) fn with_known_relevant_init_flags(_init_ctx: &InitFeatures) -> Self {
		// There are currently no channel flags defined that we understand.
		Self { flags: Vec::new(), mark: PhantomData, }
	}
}

impl NodeFeatures {
	/// Create a Features with the features we support
	#[cfg(not(feature = "fuzztarget"))]
	pub(crate) fn supported() -> NodeFeatures {
		NodeFeatures {
			flags: vec![2 | 1 << 5, 1 << (9-8)],
			mark: PhantomData,
		}
	}
	#[cfg(feature = "fuzztarget")]
	pub fn supported() -> NodeFeatures {
		NodeFeatures {
			flags: vec![2 | 1 << 5, 1 << (9-8)],
			mark: PhantomData,
		}
	}

	/// Takes the flags that we know how to interpret in an init-context features that are also
	/// relevant in a node-context features and creates a node-context features from them.
	pub(crate) fn with_known_relevant_init_flags(init_ctx: &InitFeatures) -> Self {
		let mut flags = Vec::new();
		if init_ctx.flags.len() > 0 {
			// Pull out data_loss_protect and upfront_shutdown_script (bits 0, 1, 4, and 5)
			flags.push(init_ctx.flags.last().unwrap() & 0b00110011);
		}
		Self { flags, mark: PhantomData, }
	}
}

impl<T: sealed::Context> Features<T> {
	/// Create a blank Features with no features set
	pub fn empty() -> Features<T> {
		Features {
			flags: Vec::new(),
			mark: PhantomData,
		}
	}

	#[cfg(test)]
	/// Create a Features given a set of flags, in LE.
	pub fn from_le_bytes(flags: Vec<u8>) -> Features<T> {
		Features {
			flags,
			mark: PhantomData,
		}
	}

	#[cfg(test)]
	/// Gets the underlying flags set, in LE.
	pub fn le_flags(&self) -> &Vec<u8> {
		&self.flags
	}

	pub(crate) fn requires_unknown_bits(&self) -> bool {
		self.flags.iter().enumerate().any(|(idx, &byte)| {
			(match idx {
				0 => (byte & 0b00010100),
				1 => (byte & 0b01010100),
				_ => (byte & 0b01010101),
			}) != 0
		})
	}

	pub(crate) fn supports_unknown_bits(&self) -> bool {
		self.flags.iter().enumerate().any(|(idx, &byte)| {
			(match idx {
				0 => (byte & 0b11000100),
				1 => (byte & 0b11111100),
				_ => byte,
			}) != 0
		})
	}

	/// The number of bytes required to represent the feature flags present. This does not include
	/// the length bytes which are included in the serialized form.
	pub(crate) fn byte_count(&self) -> usize {
		self.flags.len()
	}

	#[cfg(test)]
	pub(crate) fn set_require_unknown_bits(&mut self) {
		let newlen = cmp::max(2, self.flags.len());
		self.flags.resize(newlen, 0u8);
		self.flags[1] |= 0x40;
	}

	#[cfg(test)]
	pub(crate) fn clear_require_unknown_bits(&mut self) {
		let newlen = cmp::max(2, self.flags.len());
		self.flags.resize(newlen, 0u8);
		self.flags[1] &= !0x40;
		if self.flags.len() == 2 && self.flags[1] == 0 {
			self.flags.resize(1, 0u8);
		}
	}
}

impl<T: sealed::DataLossProtect> Features<T> {
	pub(crate) fn supports_data_loss_protect(&self) -> bool {
		self.flags.len() > 0 && (self.flags[0] & 3) != 0
	}
}

impl<T: sealed::UpfrontShutdownScript> Features<T> {
	pub(crate) fn supports_upfront_shutdown_script(&self) -> bool {
		self.flags.len() > 0 && (self.flags[0] & (3 << 4)) != 0
	}
	#[cfg(test)]
	pub(crate) fn unset_upfront_shutdown_script(&mut self) {
		self.flags[0] ^= 1 << 5;
	}
}

impl<T: sealed::VariableLengthOnion> Features<T> {
	pub(crate) fn supports_variable_length_onion(&self) -> bool {
		self.flags.len() > 1 && (self.flags[1] & 3) != 0
	}
}

impl<T: sealed::InitialRoutingSync> Features<T> {
	pub(crate) fn initial_routing_sync(&self) -> bool {
		self.flags.len() > 0 && (self.flags[0] & (1 << 3)) != 0
	}
	pub(crate) fn set_initial_routing_sync(&mut self) {
		if self.flags.len() == 0 {
			self.flags.resize(1, 1 << 3);
		} else {
			self.flags[0] |= 1 << 3;
		}
	}
}

impl<T: sealed::Context> Writeable for Features<T> {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), ::std::io::Error> {
		w.size_hint(self.flags.len() + 2);
		(self.flags.len() as u16).write(w)?;
		for f in self.flags.iter().rev() { // Swap back to big-endian
			f.write(w)?;
		}
		Ok(())
	}
}

impl<R: ::std::io::Read, T: sealed::Context> Readable<R> for Features<T> {
	fn read(r: &mut R) -> Result<Self, DecodeError> {
		let mut flags: Vec<u8> = Readable::read(r)?;
		flags.reverse(); // Swap to little-endian
		Ok(Self {
			flags,
			mark: PhantomData,
		})
	}
}
