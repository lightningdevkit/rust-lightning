// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Feature flag definitions for the Lightning protocol according to [BOLT #9].
//!
//! Lightning nodes advertise a supported set of operation through feature flags. Features are
//! applicable for a specific context as indicated in some [messages]. [`Features`] encapsulates
//! behavior for specifying and checking feature flags for a particular context. Each feature is
//! defined internally by a trait specifying the corresponding flags (i.e., even and odd bits). A
//! [`Context`] is used to parameterize [`Features`] and defines which features it can support.
//!
//! Whether a feature is considered "known" or "unknown" is relative to the implementation, whereas
//! the term "supports" is used in reference to a particular set of [`Features`]. That is, a node
//! supports a feature if it advertises the feature (as either required or optional) to its peers.
//! And the implementation can interpret a feature if the feature is known to it.
//!
//! [BOLT #9]: https://github.com/lightningnetwork/lightning-rfc/blob/master/09-features.md
//! [messages]: ../msgs/index.html
//! [`Features`]: struct.Features.html
//! [`Context`]: sealed/trait.Context.html

use std::{cmp, fmt};
use std::marker::PhantomData;

use ln::msgs::DecodeError;
use util::ser::{Readable, Writeable, Writer};

mod sealed {
	/// The context in which [`Features`] are applicable. Defines which features are required and
	/// which are optional for the context.
	///
	/// [`Features`]: ../struct.Features.html
	pub trait Context {
		/// Features that are known to the implementation, where a required feature is indicated by
		/// its even bit and an optional feature is indicated by its odd bit.
		const KNOWN_FEATURE_FLAGS: &'static [u8];

		/// Bitmask for selecting features that are known to the implementation, regardless of
		/// whether each feature is required or optional.
		const KNOWN_FEATURE_MASK: &'static [u8];
	}

	/// Defines a [`Context`] by stating which features it requires and which are optional. Features
	/// are specified as a comma-separated list of bytes where each byte is a pipe-delimited list of
	/// feature identifiers.
	///
	/// [`Context`]: trait.Context.html
	macro_rules! define_context {
		($context: ident {
			required_features: [$( $( $required_feature: ident )|*, )*],
			optional_features: [$( $( $optional_feature: ident )|*, )*],
		}) => {
			pub struct $context {}

			impl Context for $context {
				const KNOWN_FEATURE_FLAGS: &'static [u8] = &[
					// For each byte, use bitwise-OR to compute the applicable flags for known
					// required features `r_i` and optional features `o_j` for all `i` and `j` such
					// that the following slice is formed:
					//
					// [
					//  `r_0` | `r_1` | ... | `o_0` | `o_1` | ...,
					//  ...,
					// ]
					$(
						0b00_00_00_00 $(|
							<Self as $required_feature>::REQUIRED_MASK)*
						$(|
							<Self as $optional_feature>::OPTIONAL_MASK)*,
					)*
				];

				const KNOWN_FEATURE_MASK: &'static [u8] = &[
					// Similar as above, but set both flags for each feature regardless of whether
					// the feature is required or optional.
					$(
						0b00_00_00_00 $(|
							<Self as $required_feature>::REQUIRED_MASK |
							<Self as $required_feature>::OPTIONAL_MASK)*
						$(|
							<Self as $optional_feature>::REQUIRED_MASK |
							<Self as $optional_feature>::OPTIONAL_MASK)*,
					)*
				];
			}
		};
	}

	define_context!(InitContext {
		required_features: [
			// Byte 0
			,
			// Byte 1
			StaticRemoteKey,
			// Byte 2
			,
		],
		optional_features: [
			// Byte 0
			DataLossProtect | InitialRoutingSync | UpfrontShutdownScript | GossipQueries,
			// Byte 1
			VariableLengthOnion | PaymentSecret,
			// Byte 2
			BasicMPP,
		],
	});
	define_context!(NodeContext {
		required_features: [
			// Byte 0
			,
			// Byte 1
			StaticRemoteKey,
			// Byte 2
			,
		],
		optional_features: [
			// Byte 0
			DataLossProtect | UpfrontShutdownScript | GossipQueries,
			// Byte 1
			VariableLengthOnion | PaymentSecret,
			// Byte 2
			BasicMPP,
		],
	});
	define_context!(ChannelContext {
		required_features: [],
		optional_features: [],
	});

	/// Defines a feature with the given bits for the specified [`Context`]s. The generated trait is
	/// useful for manipulating feature flags.
	///
	/// [`Context`]: trait.Context.html
	macro_rules! define_feature {
		($odd_bit: expr, $feature: ident, [$($context: ty),+], $doc: expr) => {
			#[doc = $doc]
			///
			/// See [BOLT #9] for details.
			///
			/// [BOLT #9]: https://github.com/lightningnetwork/lightning-rfc/blob/master/09-features.md
			pub trait $feature: Context {
				/// The bit used to signify that the feature is required.
				const EVEN_BIT: usize = $odd_bit - 1;

				/// The bit used to signify that the feature is optional.
				const ODD_BIT: usize = $odd_bit;

				/// Assertion that [`EVEN_BIT`] is actually even.
				///
				/// [`EVEN_BIT`]: #associatedconstant.EVEN_BIT
				const ASSERT_EVEN_BIT_PARITY: usize;

				/// Assertion that [`ODD_BIT`] is actually odd.
				///
				/// [`ODD_BIT`]: #associatedconstant.ODD_BIT
				const ASSERT_ODD_BIT_PARITY: usize;

				/// The byte where the feature is set.
				const BYTE_OFFSET: usize = Self::EVEN_BIT / 8;

				/// The bitmask for the feature's required flag relative to the [`BYTE_OFFSET`].
				///
				/// [`BYTE_OFFSET`]: #associatedconstant.BYTE_OFFSET
				const REQUIRED_MASK: u8 = 1 << (Self::EVEN_BIT - 8 * Self::BYTE_OFFSET);

				/// The bitmask for the feature's optional flag relative to the [`BYTE_OFFSET`].
				///
				/// [`BYTE_OFFSET`]: #associatedconstant.BYTE_OFFSET
				const OPTIONAL_MASK: u8 = 1 << (Self::ODD_BIT - 8 * Self::BYTE_OFFSET);

				/// Returns whether the feature is required by the given flags.
				#[inline]
				fn requires_feature(flags: &Vec<u8>) -> bool {
					flags.len() > Self::BYTE_OFFSET &&
						(flags[Self::BYTE_OFFSET] & Self::REQUIRED_MASK) != 0
				}

				/// Returns whether the feature is supported by the given flags.
				#[inline]
				fn supports_feature(flags: &Vec<u8>) -> bool {
					flags.len() > Self::BYTE_OFFSET &&
						(flags[Self::BYTE_OFFSET] & (Self::REQUIRED_MASK | Self::OPTIONAL_MASK)) != 0
				}

				/// Sets the feature's required (even) bit in the given flags.
				#[inline]
				fn set_required_bit(flags: &mut Vec<u8>) {
					if flags.len() <= Self::BYTE_OFFSET {
						flags.resize(Self::BYTE_OFFSET + 1, 0u8);
					}

					flags[Self::BYTE_OFFSET] |= Self::REQUIRED_MASK;
				}

				/// Sets the feature's optional (odd) bit in the given flags.
				#[inline]
				fn set_optional_bit(flags: &mut Vec<u8>) {
					if flags.len() <= Self::BYTE_OFFSET {
						flags.resize(Self::BYTE_OFFSET + 1, 0u8);
					}

					flags[Self::BYTE_OFFSET] |= Self::OPTIONAL_MASK;
				}

				/// Clears the feature's required (even) and optional (odd) bits from the given
				/// flags.
				#[inline]
				fn clear_bits(flags: &mut Vec<u8>) {
					if flags.len() > Self::BYTE_OFFSET {
						flags[Self::BYTE_OFFSET] &= !Self::REQUIRED_MASK;
						flags[Self::BYTE_OFFSET] &= !Self::OPTIONAL_MASK;
					}

					let last_non_zero_byte = flags.iter().rposition(|&byte| byte != 0);
					let size = if let Some(offset) = last_non_zero_byte { offset + 1 } else { 0 };
					flags.resize(size, 0u8);
				}
			}

			$(
				impl $feature for $context {
					// EVEN_BIT % 2 == 0
					const ASSERT_EVEN_BIT_PARITY: usize = 0 - (<Self as $feature>::EVEN_BIT % 2);

					// ODD_BIT % 2 == 1
					const ASSERT_ODD_BIT_PARITY: usize = (<Self as $feature>::ODD_BIT % 2) - 1;
				}
			)*
		}
	}

	define_feature!(1, DataLossProtect, [InitContext, NodeContext],
		"Feature flags for `option_data_loss_protect`.");
	// NOTE: Per Bolt #9, initial_routing_sync has no even bit.
	define_feature!(3, InitialRoutingSync, [InitContext],
		"Feature flags for `initial_routing_sync`.");
	define_feature!(5, UpfrontShutdownScript, [InitContext, NodeContext],
		"Feature flags for `option_upfront_shutdown_script`.");
	define_feature!(7, GossipQueries, [InitContext, NodeContext],
		"Feature flags for `gossip_queries`.");
	define_feature!(9, VariableLengthOnion, [InitContext, NodeContext],
		"Feature flags for `var_onion_optin`.");
	define_feature!(13, StaticRemoteKey, [InitContext, NodeContext],
		"Feature flags for `option_static_remotekey`.");
	define_feature!(15, PaymentSecret, [InitContext, NodeContext],
		"Feature flags for `payment_secret`.");
	define_feature!(17, BasicMPP, [InitContext, NodeContext],
		"Feature flags for `basic_mpp`.");

	#[cfg(test)]
	define_context!(TestingContext {
		required_features: [
			// Byte 0
			,
			// Byte 1
			,
			// Byte 2
			UnknownFeature,
		],
		optional_features: [
			// Byte 0
			,
			// Byte 1
			,
			// Byte 2
			,
		],
	});

	#[cfg(test)]
	define_feature!(23, UnknownFeature, [TestingContext],
		"Feature flags for an unknown feature used in testing.");
}

/// Tracks the set of features which a node implements, templated by the context in which it
/// appears.
///
/// (C-not exported) as we map the concrete feature types below directly instead
pub struct Features<T: sealed::Context> {
	/// Note that, for convenience, flags is LITTLE endian (despite being big-endian on the wire)
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

/// Features used within an `init` message.
pub type InitFeatures = Features<sealed::InitContext>;
/// Features used within a `node_announcement` message.
pub type NodeFeatures = Features<sealed::NodeContext>;
/// Features used within a `channel_announcement` message.
pub type ChannelFeatures = Features<sealed::ChannelContext>;

impl InitFeatures {
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

	/// Converts `InitFeatures` to `Features<C>`. Only known `InitFeatures` relevant to context `C`
	/// are included in the result.
	pub(crate) fn to_context<C: sealed::Context>(&self) -> Features<C> {
		self.to_context_internal()
	}
}

impl<T: sealed::Context> Features<T> {
	/// Create a blank Features with no features set
	pub fn empty() -> Self {
		Features {
			flags: Vec::new(),
			mark: PhantomData,
		}
	}

	/// Creates features known by the implementation as defined by [`T::KNOWN_FEATURE_FLAGS`].
	///
	/// [`T::KNOWN_FEATURE_FLAGS`]: sealed/trait.Context.html#associatedconstant.KNOWN_FEATURE_FLAGS
	pub fn known() -> Self {
		Self {
			flags: T::KNOWN_FEATURE_FLAGS.to_vec(),
			mark: PhantomData,
		}
	}

	/// Converts `Features<T>` to `Features<C>`. Only known `T` features relevant to context `C` are
	/// included in the result.
	fn to_context_internal<C: sealed::Context>(&self) -> Features<C> {
		let byte_count = C::KNOWN_FEATURE_MASK.len();
		let mut flags = Vec::new();
		for (i, byte) in self.flags.iter().enumerate() {
			if i < byte_count {
				let known_source_features = T::KNOWN_FEATURE_MASK[i];
				let known_target_features = C::KNOWN_FEATURE_MASK[i];
				flags.push(byte & known_source_features & known_target_features);
			}
		}
		Features::<C> { flags, mark: PhantomData, }
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
		// Bitwise AND-ing with all even bits set except for known features will select required
		// unknown features.
		let byte_count = T::KNOWN_FEATURE_MASK.len();
		self.flags.iter().enumerate().any(|(i, &byte)| {
			let required_features = 0b01_01_01_01;
			let unknown_features = if i < byte_count {
				!T::KNOWN_FEATURE_MASK[i]
			} else {
				0b11_11_11_11
			};
			(byte & (required_features & unknown_features)) != 0
		})
	}

	pub(crate) fn supports_unknown_bits(&self) -> bool {
		// Bitwise AND-ing with all even and odd bits set except for known features will select
		// both required and optional unknown features.
		let byte_count = T::KNOWN_FEATURE_MASK.len();
		self.flags.iter().enumerate().any(|(i, &byte)| {
			let unknown_features = if i < byte_count {
				!T::KNOWN_FEATURE_MASK[i]
			} else {
				0b11_11_11_11
			};
			(byte & unknown_features) != 0
		})
	}

	/// The number of bytes required to represent the feature flags present. This does not include
	/// the length bytes which are included in the serialized form.
	pub(crate) fn byte_count(&self) -> usize {
		self.flags.len()
	}

	#[cfg(test)]
	pub(crate) fn set_required_unknown_bits(&mut self) {
		<sealed::TestingContext as sealed::UnknownFeature>::set_required_bit(&mut self.flags);
	}

	#[cfg(test)]
	pub(crate) fn set_optional_unknown_bits(&mut self) {
		<sealed::TestingContext as sealed::UnknownFeature>::set_optional_bit(&mut self.flags);
	}

	#[cfg(test)]
	pub(crate) fn clear_unknown_bits(&mut self) {
		<sealed::TestingContext as sealed::UnknownFeature>::clear_bits(&mut self.flags);
	}
}

impl<T: sealed::DataLossProtect> Features<T> {
	#[cfg(test)]
	pub(crate) fn requires_data_loss_protect(&self) -> bool {
		<T as sealed::DataLossProtect>::requires_feature(&self.flags)
	}
	pub(crate) fn supports_data_loss_protect(&self) -> bool {
		<T as sealed::DataLossProtect>::supports_feature(&self.flags)
	}
}

impl<T: sealed::UpfrontShutdownScript> Features<T> {
	#[cfg(test)]
	pub(crate) fn requires_upfront_shutdown_script(&self) -> bool {
		<T as sealed::UpfrontShutdownScript>::requires_feature(&self.flags)
	}
	pub(crate) fn supports_upfront_shutdown_script(&self) -> bool {
		<T as sealed::UpfrontShutdownScript>::supports_feature(&self.flags)
	}
	#[cfg(test)]
	pub(crate) fn clear_upfront_shutdown_script(mut self) -> Self {
		<T as sealed::UpfrontShutdownScript>::clear_bits(&mut self.flags);
		self
	}
}


impl<T: sealed::GossipQueries> Features<T> {
	#[cfg(test)]
	pub(crate) fn requires_gossip_queries(&self) -> bool {
		<T as sealed::GossipQueries>::requires_feature(&self.flags)
	}
	pub(crate) fn supports_gossip_queries(&self) -> bool {
		<T as sealed::GossipQueries>::supports_feature(&self.flags)
	}
	#[cfg(test)]
	pub(crate) fn clear_gossip_queries(mut self) -> Self {
		<T as sealed::GossipQueries>::clear_bits(&mut self.flags);
		self
	}
}

impl<T: sealed::VariableLengthOnion> Features<T> {
	#[cfg(test)]
	pub(crate) fn requires_variable_length_onion(&self) -> bool {
		<T as sealed::VariableLengthOnion>::requires_feature(&self.flags)
	}
	pub(crate) fn supports_variable_length_onion(&self) -> bool {
		<T as sealed::VariableLengthOnion>::supports_feature(&self.flags)
	}
}

impl<T: sealed::StaticRemoteKey> Features<T> {
	pub(crate) fn supports_static_remote_key(&self) -> bool {
		<T as sealed::StaticRemoteKey>::supports_feature(&self.flags)
	}
	#[cfg(test)]
	pub(crate) fn requires_static_remote_key(&self) -> bool {
		<T as sealed::StaticRemoteKey>::requires_feature(&self.flags)
	}
}

impl<T: sealed::InitialRoutingSync> Features<T> {
	pub(crate) fn initial_routing_sync(&self) -> bool {
		<T as sealed::InitialRoutingSync>::supports_feature(&self.flags)
	}
	// We are no longer setting initial_routing_sync now that gossip_queries
	// is enabled. This feature is ignored by a peer when gossip_queries has 
	// been negotiated.
	#[cfg(test)]
	pub(crate) fn clear_initial_routing_sync(&mut self) {
		<T as sealed::InitialRoutingSync>::clear_bits(&mut self.flags)
	}
}

impl<T: sealed::PaymentSecret> Features<T> {
	#[cfg(test)]
	pub(crate) fn requires_payment_secret(&self) -> bool {
		<T as sealed::PaymentSecret>::requires_feature(&self.flags)
	}
	// Note that we never need to test this since what really matters is the invoice - iff the
	// invoice provides a payment_secret, we assume that we can use it (ie that the recipient
	// supports payment_secret).
	#[allow(dead_code)]
	pub(crate) fn supports_payment_secret(&self) -> bool {
		<T as sealed::PaymentSecret>::supports_feature(&self.flags)
	}
}

impl<T: sealed::BasicMPP> Features<T> {
	#[cfg(test)]
	pub(crate) fn requires_basic_mpp(&self) -> bool {
		<T as sealed::BasicMPP>::requires_feature(&self.flags)
	}
	// We currently never test for this since we don't actually *generate* multipath routes.
	#[allow(dead_code)]
	pub(crate) fn supports_basic_mpp(&self) -> bool {
		<T as sealed::BasicMPP>::supports_feature(&self.flags)
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

impl<T: sealed::Context> Readable for Features<T> {
	fn read<R: ::std::io::Read>(r: &mut R) -> Result<Self, DecodeError> {
		let mut flags: Vec<u8> = Readable::read(r)?;
		flags.reverse(); // Swap to little-endian
		Ok(Self {
			flags,
			mark: PhantomData,
		})
	}
}

#[cfg(test)]
mod tests {
	use super::{ChannelFeatures, InitFeatures, NodeFeatures};

	#[test]
	fn sanity_test_known_features() {
		assert!(!ChannelFeatures::known().requires_unknown_bits());
		assert!(!ChannelFeatures::known().supports_unknown_bits());
		assert!(!InitFeatures::known().requires_unknown_bits());
		assert!(!InitFeatures::known().supports_unknown_bits());
		assert!(!NodeFeatures::known().requires_unknown_bits());
		assert!(!NodeFeatures::known().supports_unknown_bits());

		assert!(InitFeatures::known().supports_upfront_shutdown_script());
		assert!(NodeFeatures::known().supports_upfront_shutdown_script());
		assert!(!InitFeatures::known().requires_upfront_shutdown_script());
		assert!(!NodeFeatures::known().requires_upfront_shutdown_script());

		assert!(InitFeatures::known().supports_gossip_queries());
		assert!(NodeFeatures::known().supports_gossip_queries());
		assert!(!InitFeatures::known().requires_gossip_queries());
		assert!(!NodeFeatures::known().requires_gossip_queries());

		assert!(InitFeatures::known().supports_data_loss_protect());
		assert!(NodeFeatures::known().supports_data_loss_protect());
		assert!(!InitFeatures::known().requires_data_loss_protect());
		assert!(!NodeFeatures::known().requires_data_loss_protect());

		assert!(InitFeatures::known().supports_variable_length_onion());
		assert!(NodeFeatures::known().supports_variable_length_onion());
		assert!(!InitFeatures::known().requires_variable_length_onion());
		assert!(!NodeFeatures::known().requires_variable_length_onion());

		assert!(InitFeatures::known().supports_static_remote_key());
		assert!(NodeFeatures::known().supports_static_remote_key());
		assert!(InitFeatures::known().requires_static_remote_key());
		assert!(NodeFeatures::known().requires_static_remote_key());

		assert!(InitFeatures::known().supports_payment_secret());
		assert!(NodeFeatures::known().supports_payment_secret());
		assert!(!InitFeatures::known().requires_payment_secret());
		assert!(!NodeFeatures::known().requires_payment_secret());

		assert!(InitFeatures::known().supports_basic_mpp());
		assert!(NodeFeatures::known().supports_basic_mpp());
		assert!(!InitFeatures::known().requires_basic_mpp());
		assert!(!NodeFeatures::known().requires_basic_mpp());

		let mut init_features = InitFeatures::known();
		assert!(init_features.initial_routing_sync());
		init_features.clear_initial_routing_sync();
		assert!(!init_features.initial_routing_sync());
	}

	#[test]
	fn sanity_test_unknown_bits() {
		let mut features = ChannelFeatures::empty();
		assert!(!features.requires_unknown_bits());
		assert!(!features.supports_unknown_bits());

		features.set_required_unknown_bits();
		assert!(features.requires_unknown_bits());
		assert!(features.supports_unknown_bits());

		features.clear_unknown_bits();
		assert!(!features.requires_unknown_bits());
		assert!(!features.supports_unknown_bits());

		features.set_optional_unknown_bits();
		assert!(!features.requires_unknown_bits());
		assert!(features.supports_unknown_bits());
	}

	#[test]
	fn convert_to_context_with_relevant_flags() {
		let init_features = InitFeatures::known().clear_upfront_shutdown_script().clear_gossip_queries();
		assert!(init_features.initial_routing_sync());
		assert!(!init_features.supports_upfront_shutdown_script());
		assert!(!init_features.supports_gossip_queries());

		let node_features: NodeFeatures = init_features.to_context();
		{
			// Check that the flags are as expected:
			// - option_data_loss_protect
			// - var_onion_optin | static_remote_key (req) | payment_secret
			// - basic_mpp
			assert_eq!(node_features.flags.len(), 3);
			assert_eq!(node_features.flags[0], 0b00000010);
			assert_eq!(node_features.flags[1], 0b10010010);
			assert_eq!(node_features.flags[2], 0b00000010);
		}

		// Check that cleared flags are kept blank when converting back:
		// - initial_routing_sync was not applicable to NodeContext
		// - upfront_shutdown_script was cleared before converting
		// - gossip_queries was cleared before converting
		let features: InitFeatures = node_features.to_context_internal();
		assert!(!features.initial_routing_sync());
		assert!(!features.supports_upfront_shutdown_script());
		assert!(!init_features.supports_gossip_queries());
	}
}
