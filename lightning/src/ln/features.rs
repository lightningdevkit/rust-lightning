//! Lightning exposes sets of supported operations through "feature flags". This module includes
//! types to store those feature flags and query for specific flags.

use std::{cmp, fmt};
use std::result::Result;
use std::marker::PhantomData;

use ln::msgs::DecodeError;
use util::ser::{Readable, Writeable, Writer};

/// The context in which a Feature object appears determines which bits of features the node
/// supports will be set. We use this when creating our own Feature objects to select which bits to
/// set and when passing around Feature objects to ensure the bits we're checking for are
/// available.
///
/// This Context represents when the Feature appears in the init message, sent between peers and not
/// rumored around the P2P network.
pub struct FeatureContextInit {}
/// The context in which a Feature object appears determines which bits of features the node
/// supports will be set. We use this when creating our own Feature objects to select which bits to
/// set and when passing around Feature objects to ensure the bits we're checking for are
/// available.
///
/// This Context represents when the Feature appears in the node_announcement message, as it is
/// rumored around the P2P network.
pub struct FeatureContextNode {}
/// The context in which a Feature object appears determines which bits of features the node
/// supports will be set. We use this when creating our own Feature objects to select which bits to
/// set and when passing around Feature objects to ensure the bits we're checking for are
/// available.
///
/// This Context represents when the Feature appears in the ChannelAnnouncement message, as it is
/// rumored around the P2P network.
pub struct FeatureContextChannel {}
/// The context in which a Feature object appears determines which bits of features the node
/// supports will be set. We use this when creating our own Feature objects to select which bits to
/// set and when passing around Feature objects to ensure the bits we're checking for are
/// available.
///
/// This Context represents when the Feature appears in an invoice, used to determine the different
/// options available for routing a payment.
///
/// Note that this is currently unused as invoices come to us via a different crate and are not
/// native to rust-lightning directly.
pub struct FeatureContextInvoice {}

/// An internal trait capturing the various future context types
pub trait FeatureContext {}
impl FeatureContext for FeatureContextInit {}
impl FeatureContext for FeatureContextNode {}
impl FeatureContext for FeatureContextChannel {}
impl FeatureContext for FeatureContextInvoice {}

/// An internal trait capturing FeatureContextInit and FeatureContextNode
pub trait FeatureContextInitNode : FeatureContext {}
impl FeatureContextInitNode for FeatureContextInit {}
impl FeatureContextInitNode for FeatureContextNode {}

/// Tracks the set of features which a node implements, templated by the context in which it
/// appears.
pub struct Features<T: FeatureContext> {
	/// Note that, for convinience, flags is LITTLE endian (despite being big-endian on the wire)
	flags: Vec<u8>,
	mark: PhantomData<T>,
}

impl<T: FeatureContext> Clone for Features<T> {
	fn clone(&self) -> Self {
		Self {
			flags: self.flags.clone(),
			mark: PhantomData,
		}
	}
}
impl<T: FeatureContext> PartialEq for Features<T> {
	fn eq(&self, o: &Self) -> bool {
		self.flags.eq(&o.flags)
	}
}
impl<T: FeatureContext> fmt::Debug for Features<T> {
	fn fmt(&self, fmt: &mut fmt::Formatter) -> Result<(), fmt::Error> {
		self.flags.fmt(fmt)
	}
}

/// A feature message as it appears in an init message
pub type InitFeatures = Features<FeatureContextInit>;
/// A feature message as it appears in a node_announcement message
pub type NodeFeatures = Features<FeatureContextNode>;
/// A feature message as it appears in a channel_announcement message
pub type ChannelFeatures = Features<FeatureContextChannel>;

impl<T: FeatureContextInitNode> Features<T> {
	/// Create a Features with the features we support
	#[cfg(not(feature = "fuzztarget"))]
	pub(crate) fn supported() -> Features<T> {
		Features {
			flags: vec![2 | 1 << 5],
			mark: PhantomData,
		}
	}
	#[cfg(feature = "fuzztarget")]
	pub fn supported() -> Features<T> {
		Features {
			flags: vec![2 | 1 << 5],
			mark: PhantomData,
		}
	}
}

impl Features<FeatureContextChannel> {
	/// Create a Features with the features we support
	#[cfg(not(feature = "fuzztarget"))]
	pub(crate) fn supported() -> Features<FeatureContextChannel> {
		Features {
			flags: Vec::new(),
			mark: PhantomData,
		}
	}
	#[cfg(feature = "fuzztarget")]
	pub fn supported() -> Features<FeatureContextChannel> {
		Features {
			flags: Vec::new(),
			mark: PhantomData,
		}
	}
}

impl<T: FeatureContext> Features<T> {
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
			( idx != 0 && (byte & 0x55) != 0 ) || ( idx == 0 && (byte & 0x14) != 0 )
		})
	}

	pub(crate) fn supports_unknown_bits(&self) -> bool {
		self.flags.iter().enumerate().any(|(idx, &byte)| {
			( idx != 0 && byte != 0 ) || ( idx == 0 && (byte & 0xc4) != 0 )
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

impl<T: FeatureContextInitNode> Features<T> {
	pub(crate) fn supports_data_loss_protect(&self) -> bool {
		self.flags.len() > 0 && (self.flags[0] & 3) != 0
	}

	pub(crate) fn supports_upfront_shutdown_script(&self) -> bool {
		self.flags.len() > 0 && (self.flags[0] & (3 << 4)) != 0
	}
	#[cfg(test)]
	pub(crate) fn unset_upfront_shutdown_script(&mut self) {
		self.flags[0] ^= 1 << 5;
	}
}

impl Features<FeatureContextInit> {
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

	/// Writes all features present up to, and including, 13.
	pub(crate) fn write_up_to_13<W: Writer>(&self, w: &mut W) -> Result<(), ::std::io::Error> {
		let len = cmp::min(2, self.flags.len());
		w.size_hint(len + 2);
		(len as u16).write(w)?;
		for i in (0..len).rev() {
			if i == 0 {
				self.flags[i].write(w)?;
			} else {
				(self.flags[i] & ((1 << (14 - 8)) - 1)).write(w)?;
			}
		}
		Ok(())
	}

	/// or's another InitFeatures into this one.
	pub(crate) fn or(mut self, o: InitFeatures) -> InitFeatures {
		let total_feature_len = cmp::max(self.flags.len(), o.flags.len());
		self.flags.resize(total_feature_len, 0u8);
		for (feature, o_feature) in self.flags.iter_mut().zip(o.flags.iter()) {
			*feature |= *o_feature;
		}
		self
	}
}

impl<T: FeatureContext> Writeable for Features<T> {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), ::std::io::Error> {
		w.size_hint(self.flags.len() + 2);
		(self.flags.len() as u16).write(w)?;
		for f in self.flags.iter().rev() { // Swap back to big-endian
			f.write(w)?;
		}
		Ok(())
	}
}

impl<R: ::std::io::Read, T: FeatureContext> Readable<R> for Features<T> {
	fn read(r: &mut R) -> Result<Self, DecodeError> {
		let mut flags: Vec<u8> = Readable::read(r)?;
		flags.reverse(); // Swap to little-endian
		Ok(Self {
			flags,
			mark: PhantomData,
		})
	}
}
