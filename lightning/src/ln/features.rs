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
//! defined internally by a trait specifying the corresponding flags (i.e., even and odd bits).
//!
//! Whether a feature is considered "known" or "unknown" is relative to the implementation, whereas
//! the term "supports" is used in reference to a particular set of [`Features`]. That is, a node
//! supports a feature if it advertises the feature (as either required or optional) to its peers.
//! And the implementation can interpret a feature if the feature is known to it.
//!
//! The following features are currently required in the LDK:
//! - `VariableLengthOnion` - requires/supports variable-length routing onion payloads
//!     (see [BOLT-4](https://github.com/lightning/bolts/blob/master/04-onion-routing.md) for more information).
//! - `StaticRemoteKey` - requires/supports static key for remote output
//!     (see [BOLT-3](https://github.com/lightning/bolts/blob/master/03-transactions.md) for more information).
//!
//! The following features are currently supported in the LDK:
//! - `DataLossProtect` - requires/supports that a node which has somehow fallen behind, e.g., has been restored from an old backup,
//!     can detect that it has fallen behind
//!     (see [BOLT-2](https://github.com/lightning/bolts/blob/master/02-peer-protocol.md) for more information).
//! - `InitialRoutingSync` - requires/supports that the sending node needs a complete routing information dump
//!     (see [BOLT-7](https://github.com/lightning/bolts/blob/master/07-routing-gossip.md#initial-sync) for more information).
//! - `UpfrontShutdownScript` - commits to a shutdown scriptpubkey when opening a channel
//!     (see [BOLT-2](https://github.com/lightning/bolts/blob/master/02-peer-protocol.md#the-open_channel-message) for more information).
//! - `GossipQueries` - requires/supports more sophisticated gossip control
//!     (see [BOLT-7](https://github.com/lightning/bolts/blob/master/07-routing-gossip.md) for more information).
//! - `PaymentSecret` - requires/supports that a node supports payment_secret field
//!     (see [BOLT-4](https://github.com/lightning/bolts/blob/master/04-onion-routing.md) for more information).
//! - `BasicMPP` - requires/supports that a node can receive basic multi-part payments
//!     (see [BOLT-4](https://github.com/lightning/bolts/blob/master/04-onion-routing.md#basic-multi-part-payments) for more information).
//! - `Wumbo` - requires/supports that a node create large channels. Called `option_support_large_channel` in the spec.
//!     (see [BOLT-2](https://github.com/lightning/bolts/blob/master/02-peer-protocol.md#the-open_channel-message) for more information).
//! - `ShutdownAnySegwit` - requires/supports that future segwit versions are allowed in `shutdown`
//!     (see [BOLT-2](https://github.com/lightning/bolts/blob/master/02-peer-protocol.md) for more information).
//! - `OnionMessages` - requires/supports forwarding onion messages
//!     (see [BOLT-7](https://github.com/lightning/bolts/pull/759/files) for more information).
//!     TODO: update link
//! - `ChannelType` - node supports the channel_type field in open/accept
//!     (see [BOLT-2](https://github.com/lightning/bolts/blob/master/02-peer-protocol.md) for more information).
//! - `SCIDPrivacy` - supply channel aliases for routing
//!     (see [BOLT-2](https://github.com/lightning/bolts/blob/master/02-peer-protocol.md) for more information).
//! - `Keysend` - send funds to a node without an invoice
//!     (see the [`Keysend` feature assignment proposal](https://github.com/lightning/bolts/issues/605#issuecomment-606679798) for more information).
//! - `AnchorsZeroFeeHtlcTx` - requires/supports that commitment transactions include anchor outputs
//!   and HTLC transactions are pre-signed with zero fee (see
//!   [BOLT-3](https://github.com/lightning/bolts/blob/master/03-transactions.md) for more
//!   information).
//!
//! [BOLT #9]: https://github.com/lightning/bolts/blob/master/09-features.md
//! [messages]: crate::ln::msgs

use crate::{io, io_extras};
use crate::prelude::*;
use core::{cmp, fmt};
use core::hash::{Hash, Hasher};
use core::marker::PhantomData;

use bitcoin::bech32;
use bitcoin::bech32::{Base32Len, FromBase32, ToBase32, u5, WriteBase32};
use crate::ln::msgs::DecodeError;
use crate::util::ser::{Readable, WithoutLength, Writeable, Writer};

mod sealed {
	use crate::prelude::*;
	use crate::ln::features::Features;

	/// The context in which [`Features`] are applicable. Defines which features are known to the
	/// implementation, though specification of them as required or optional is up to the code
	/// constructing a features object.
	pub trait Context {
		/// Bitmask for selecting features that are known to the implementation.
		const KNOWN_FEATURE_MASK: &'static [u8];
	}

	/// Defines a [`Context`] by stating which features it requires and which are optional. Features
	/// are specified as a comma-separated list of bytes where each byte is a pipe-delimited list of
	/// feature identifiers.
	macro_rules! define_context {
		($context: ident, [$( $( $known_feature: ident )|*, )*]) => {
			#[derive(Eq, PartialEq)]
			pub struct $context {}

			impl Context for $context {
				const KNOWN_FEATURE_MASK: &'static [u8] = &[
					$(
						0b00_00_00_00 $(|
							<Self as $known_feature>::REQUIRED_MASK |
							<Self as $known_feature>::OPTIONAL_MASK)*,
					)*
				];
			}

			impl alloc::fmt::Display for Features<$context> {
				fn fmt(&self, fmt: &mut alloc::fmt::Formatter) -> Result<(), alloc::fmt::Error> {
					$(
						$(
							fmt.write_fmt(format_args!("{}: {}, ", stringify!($known_feature),
								if <$context as $known_feature>::requires_feature(&self.flags) { "required" }
								else if <$context as $known_feature>::supports_feature(&self.flags) { "supported" }
								else { "not supported" }))?;
						)*
						{} // Rust gets mad if we only have a $()* block here, so add a dummy {}
					)*
					fmt.write_fmt(format_args!("unknown flags: {}",
						if self.requires_unknown_bits() { "required" }
						else if self.supports_unknown_bits() { "supported" } else { "none" }))
				}
			}
		};
	}

	define_context!(InitContext, [
		// Byte 0
		DataLossProtect | InitialRoutingSync | UpfrontShutdownScript | GossipQueries,
		// Byte 1
		VariableLengthOnion | StaticRemoteKey | PaymentSecret,
		// Byte 2
		BasicMPP | Wumbo | AnchorsZeroFeeHtlcTx,
		// Byte 3
		ShutdownAnySegwit,
		// Byte 4
		OnionMessages,
		// Byte 5
		ChannelType | SCIDPrivacy,
		// Byte 6
		ZeroConf,
	]);
	define_context!(NodeContext, [
		// Byte 0
		DataLossProtect | UpfrontShutdownScript | GossipQueries,
		// Byte 1
		VariableLengthOnion | StaticRemoteKey | PaymentSecret,
		// Byte 2
		BasicMPP | Wumbo | AnchorsZeroFeeHtlcTx,
		// Byte 3
		ShutdownAnySegwit,
		// Byte 4
		OnionMessages,
		// Byte 5
		ChannelType | SCIDPrivacy,
		// Byte 6
		ZeroConf | Keysend,
	]);
	define_context!(ChannelContext, []);
	define_context!(InvoiceContext, [
		// Byte 0
		,
		// Byte 1
		VariableLengthOnion | PaymentSecret,
		// Byte 2
		BasicMPP,
	]);
	define_context!(OfferContext, []);
	define_context!(InvoiceRequestContext, []);
	define_context!(Bolt12InvoiceContext, [
		// Byte 0
		,
		// Byte 1
		,
		// Byte 2
		BasicMPP,
	]);
	define_context!(BlindedHopContext, []);
	// This isn't a "real" feature context, and is only used in the channel_type field in an
	// `OpenChannel` message.
	define_context!(ChannelTypeContext, [
		// Byte 0
		,
		// Byte 1
		StaticRemoteKey,
		// Byte 2
		AnchorsZeroFeeHtlcTx,
		// Byte 3
		,
		// Byte 4
		,
		// Byte 5
		SCIDPrivacy,
		// Byte 6
		ZeroConf,
	]);

	/// Defines a feature with the given bits for the specified [`Context`]s. The generated trait is
	/// useful for manipulating feature flags.
	macro_rules! define_feature {
		($odd_bit: expr, $feature: ident, [$($context: ty),+], $doc: expr, $optional_setter: ident,
		 $required_setter: ident, $supported_getter: ident) => {
			#[doc = $doc]
			///
			/// See [BOLT #9] for details.
			///
			/// [BOLT #9]: https://github.com/lightning/bolts/blob/master/09-features.md
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

				/// Assertion that the bits are set in the context's [`KNOWN_FEATURE_MASK`].
				///
				/// [`KNOWN_FEATURE_MASK`]: Context::KNOWN_FEATURE_MASK
				#[cfg(not(test))] // We violate this constraint with `UnknownFeature`
				const ASSERT_BITS_IN_MASK: u8;

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

			impl <T: $feature> Features<T> {
				/// Set this feature as optional.
				pub fn $optional_setter(&mut self) {
					<T as $feature>::set_optional_bit(&mut self.flags);
				}

				/// Set this feature as required.
				pub fn $required_setter(&mut self) {
					<T as $feature>::set_required_bit(&mut self.flags);
				}

				/// Checks if this feature is supported.
				pub fn $supported_getter(&self) -> bool {
					<T as $feature>::supports_feature(&self.flags)
				}
			}

			$(
				impl $feature for $context {
					// EVEN_BIT % 2 == 0
					const ASSERT_EVEN_BIT_PARITY: usize = 0 - (<Self as $feature>::EVEN_BIT % 2);

					// ODD_BIT % 2 == 1
					const ASSERT_ODD_BIT_PARITY: usize = (<Self as $feature>::ODD_BIT % 2) - 1;

					// (byte & (REQUIRED_MASK | OPTIONAL_MASK)) >> (EVEN_BIT % 8) == 3
					#[cfg(not(test))] // We violate this constraint with `UnknownFeature`
					const ASSERT_BITS_IN_MASK: u8 =
						((<$context>::KNOWN_FEATURE_MASK[<Self as $feature>::BYTE_OFFSET] & (<Self as $feature>::REQUIRED_MASK | <Self as $feature>::OPTIONAL_MASK))
						 >> (<Self as $feature>::EVEN_BIT % 8)) - 3;
				}
			)*
		};
		($odd_bit: expr, $feature: ident, [$($context: ty),+], $doc: expr, $optional_setter: ident,
		 $required_setter: ident, $supported_getter: ident, $required_getter: ident) => {
			define_feature!($odd_bit, $feature, [$($context),+], $doc, $optional_setter, $required_setter, $supported_getter);
			impl <T: $feature> Features<T> {
				/// Checks if this feature is required.
				pub fn $required_getter(&self) -> bool {
					<T as $feature>::requires_feature(&self.flags)
				}
			}
		}
	}

	define_feature!(1, DataLossProtect, [InitContext, NodeContext],
		"Feature flags for `option_data_loss_protect`.", set_data_loss_protect_optional,
		set_data_loss_protect_required, supports_data_loss_protect, requires_data_loss_protect);
	// NOTE: Per Bolt #9, initial_routing_sync has no even bit.
	define_feature!(3, InitialRoutingSync, [InitContext], "Feature flags for `initial_routing_sync`.",
		set_initial_routing_sync_optional, set_initial_routing_sync_required,
		initial_routing_sync);
	define_feature!(5, UpfrontShutdownScript, [InitContext, NodeContext],
		"Feature flags for `option_upfront_shutdown_script`.", set_upfront_shutdown_script_optional,
		set_upfront_shutdown_script_required, supports_upfront_shutdown_script,
		requires_upfront_shutdown_script);
	define_feature!(7, GossipQueries, [InitContext, NodeContext],
		"Feature flags for `gossip_queries`.", set_gossip_queries_optional, set_gossip_queries_required,
		supports_gossip_queries, requires_gossip_queries);
	define_feature!(9, VariableLengthOnion, [InitContext, NodeContext, InvoiceContext],
		"Feature flags for `var_onion_optin`.", set_variable_length_onion_optional,
		set_variable_length_onion_required, supports_variable_length_onion,
		requires_variable_length_onion);
	define_feature!(13, StaticRemoteKey, [InitContext, NodeContext, ChannelTypeContext],
		"Feature flags for `option_static_remotekey`.", set_static_remote_key_optional,
		set_static_remote_key_required, supports_static_remote_key, requires_static_remote_key);
	define_feature!(15, PaymentSecret, [InitContext, NodeContext, InvoiceContext],
		"Feature flags for `payment_secret`.", set_payment_secret_optional, set_payment_secret_required,
		supports_payment_secret, requires_payment_secret);
	define_feature!(17, BasicMPP, [InitContext, NodeContext, InvoiceContext, Bolt12InvoiceContext],
		"Feature flags for `basic_mpp`.", set_basic_mpp_optional, set_basic_mpp_required,
		supports_basic_mpp, requires_basic_mpp);
	define_feature!(19, Wumbo, [InitContext, NodeContext],
		"Feature flags for `option_support_large_channel` (aka wumbo channels).", set_wumbo_optional, set_wumbo_required,
		supports_wumbo, requires_wumbo);
	define_feature!(23, AnchorsZeroFeeHtlcTx, [InitContext, NodeContext, ChannelTypeContext],
		"Feature flags for `option_anchors_zero_fee_htlc_tx`.", set_anchors_zero_fee_htlc_tx_optional,
		set_anchors_zero_fee_htlc_tx_required, supports_anchors_zero_fee_htlc_tx, requires_anchors_zero_fee_htlc_tx);
	define_feature!(27, ShutdownAnySegwit, [InitContext, NodeContext],
		"Feature flags for `opt_shutdown_anysegwit`.", set_shutdown_any_segwit_optional,
		set_shutdown_any_segwit_required, supports_shutdown_anysegwit, requires_shutdown_anysegwit);
	define_feature!(39, OnionMessages, [InitContext, NodeContext],
		"Feature flags for `option_onion_messages`.", set_onion_messages_optional,
		set_onion_messages_required, supports_onion_messages, requires_onion_messages);
	define_feature!(45, ChannelType, [InitContext, NodeContext],
		"Feature flags for `option_channel_type`.", set_channel_type_optional,
		set_channel_type_required, supports_channel_type, requires_channel_type);
	define_feature!(47, SCIDPrivacy, [InitContext, NodeContext, ChannelTypeContext],
		"Feature flags for only forwarding with SCID aliasing. Called `option_scid_alias` in the BOLTs",
		set_scid_privacy_optional, set_scid_privacy_required, supports_scid_privacy, requires_scid_privacy);
	define_feature!(51, ZeroConf, [InitContext, NodeContext, ChannelTypeContext],
		"Feature flags for accepting channels with zero confirmations. Called `option_zeroconf` in the BOLTs",
		set_zero_conf_optional, set_zero_conf_required, supports_zero_conf, requires_zero_conf);
	define_feature!(55, Keysend, [NodeContext],
		"Feature flags for keysend payments.", set_keysend_optional, set_keysend_required,
		supports_keysend, requires_keysend);

	#[cfg(test)]
	define_feature!(123456789, UnknownFeature,
		[NodeContext, ChannelContext, InvoiceContext, OfferContext, InvoiceRequestContext, Bolt12InvoiceContext, BlindedHopContext],
		"Feature flags for an unknown feature used in testing.", set_unknown_feature_optional,
		set_unknown_feature_required, supports_unknown_test_feature, requires_unknown_test_feature);
}

/// Tracks the set of features which a node implements, templated by the context in which it
/// appears.
///
/// (C-not exported) as we map the concrete feature types below directly instead
#[derive(Eq)]
pub struct Features<T: sealed::Context> {
	/// Note that, for convenience, flags is LITTLE endian (despite being big-endian on the wire)
	flags: Vec<u8>,
	mark: PhantomData<T>,
}

impl <T: sealed::Context> Features<T> {
	pub(crate) fn or(mut self, o: Self) -> Self {
		let total_feature_len = cmp::max(self.flags.len(), o.flags.len());
		self.flags.resize(total_feature_len, 0u8);
		for (byte, o_byte) in self.flags.iter_mut().zip(o.flags.iter()) {
			*byte |= *o_byte;
		}
		self
	}
}

impl<T: sealed::Context> Clone for Features<T> {
	fn clone(&self) -> Self {
		Self {
			flags: self.flags.clone(),
			mark: PhantomData,
		}
	}
}
impl<T: sealed::Context> Hash for Features<T> {
	fn hash<H: Hasher>(&self, hasher: &mut H) {
		self.flags.hash(hasher);
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
/// Features used within an invoice.
pub type InvoiceFeatures = Features<sealed::InvoiceContext>;
/// Features used within an `offer`.
pub type OfferFeatures = Features<sealed::OfferContext>;
/// Features used within an `invoice_request`.
pub type InvoiceRequestFeatures = Features<sealed::InvoiceRequestContext>;
/// Features used within an `invoice`.
pub type Bolt12InvoiceFeatures = Features<sealed::Bolt12InvoiceContext>;
/// Features used within BOLT 4 encrypted_data_tlv and BOLT 12 blinded_payinfo
pub type BlindedHopFeatures = Features<sealed::BlindedHopContext>;

/// Features used within the channel_type field in an OpenChannel message.
///
/// A channel is always of some known "type", describing the transaction formats used and the exact
/// semantics of our interaction with our peer.
///
/// Note that because a channel is a specific type which is proposed by the opener and accepted by
/// the counterparty, only required features are allowed here.
///
/// This is serialized differently from other feature types - it is not prefixed by a length, and
/// thus must only appear inside a TLV where its length is known in advance.
pub type ChannelTypeFeatures = Features<sealed::ChannelTypeContext>;

impl InitFeatures {
	/// Writes all features present up to, and including, 13.
	pub(crate) fn write_up_to_13<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		let len = cmp::min(2, self.flags.len());
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

	/// Converts `InitFeatures` to `Features<C>`. Only known `InitFeatures` relevant to context `C`
	/// are included in the result.
	pub(crate) fn to_context<C: sealed::Context>(&self) -> Features<C> {
		self.to_context_internal()
	}
}

impl InvoiceFeatures {
	/// Converts `InvoiceFeatures` to `Features<C>`. Only known `InvoiceFeatures` relevant to
	/// context `C` are included in the result.
	pub(crate) fn to_context<C: sealed::Context>(&self) -> Features<C> {
		self.to_context_internal()
	}

	/// Getting a route for a keysend payment to a private node requires providing the payee's
	/// features (since they were not announced in a node announcement). However, keysend payments
	/// don't have an invoice to pull the payee's features from, so this method is provided for use in
	/// [`PaymentParameters::for_keysend`], thus omitting the need for payers to manually construct an
	/// `InvoiceFeatures` for [`find_route`].
	///
	/// [`PaymentParameters::for_keysend`]: crate::routing::router::PaymentParameters::for_keysend
	/// [`find_route`]: crate::routing::router::find_route
	pub(crate) fn for_keysend() -> InvoiceFeatures {
		let mut res = InvoiceFeatures::empty();
		res.set_variable_length_onion_optional();
		res
	}
}

impl ChannelTypeFeatures {
	// Maps the relevant `InitFeatures` to `ChannelTypeFeatures`. Any unknown features to
	// `ChannelTypeFeatures` are not included in the result.
	pub(crate) fn from_init(init: &InitFeatures) -> Self {
		let mut ret = init.to_context_internal();
		// ChannelTypeFeatures must only contain required bits, so we OR the required forms of all
		// optional bits and then AND out the optional ones.
		for byte in ret.flags.iter_mut() {
			*byte |= (*byte & 0b10_10_10_10) >> 1;
			*byte &= 0b01_01_01_01;
		}
		ret
	}

	/// Constructs a ChannelTypeFeatures with only static_remotekey set
	pub(crate) fn only_static_remote_key() -> Self {
		let mut ret = Self::empty();
		<sealed::ChannelTypeContext as sealed::StaticRemoteKey>::set_required_bit(&mut ret.flags);
		ret
	}
}

impl ToBase32 for InvoiceFeatures {
	fn write_base32<W: WriteBase32>(&self, writer: &mut W) -> Result<(), <W as WriteBase32>::Err> {
		// Explanation for the "4": the normal way to round up when dividing is to add the divisor
		// minus one before dividing
		let length_u5s = (self.flags.len() * 8 + 4) / 5 as usize;
		let mut res_u5s: Vec<u5> = vec![u5::try_from_u8(0).unwrap(); length_u5s];
		for (byte_idx, byte) in self.flags.iter().enumerate() {
			let bit_pos_from_left_0_indexed = byte_idx * 8;
			let new_u5_idx = length_u5s - (bit_pos_from_left_0_indexed / 5) as usize - 1;
			let new_bit_pos = bit_pos_from_left_0_indexed % 5;
			let shifted_chunk_u16 = (*byte as u16) << new_bit_pos;
			let curr_u5_as_u8 = res_u5s[new_u5_idx].to_u8();
			res_u5s[new_u5_idx] = u5::try_from_u8(curr_u5_as_u8 | ((shifted_chunk_u16 & 0x001f) as u8)).unwrap();
			if new_u5_idx > 0 {
				let curr_u5_as_u8 = res_u5s[new_u5_idx - 1].to_u8();
				res_u5s[new_u5_idx - 1] = u5::try_from_u8(curr_u5_as_u8 | (((shifted_chunk_u16 >> 5) & 0x001f) as u8)).unwrap();
			}
			if new_u5_idx > 1 {
				let curr_u5_as_u8 = res_u5s[new_u5_idx - 2].to_u8();
				res_u5s[new_u5_idx - 2] = u5::try_from_u8(curr_u5_as_u8 | (((shifted_chunk_u16 >> 10) & 0x001f) as u8)).unwrap();
			}
		}
		// Trim the highest feature bits.
		while !res_u5s.is_empty() && res_u5s[0] == u5::try_from_u8(0).unwrap() {
			res_u5s.remove(0);
		}
		writer.write(&res_u5s)
	}
}

impl Base32Len for InvoiceFeatures {
	fn base32_len(&self) -> usize {
		self.to_base32().len()
	}
}

impl FromBase32 for InvoiceFeatures {
	type Err = bech32::Error;

	fn from_base32(field_data: &[u5]) -> Result<InvoiceFeatures, bech32::Error> {
		// Explanation for the "7": the normal way to round up when dividing is to add the divisor
		// minus one before dividing
		let length_bytes = (field_data.len() * 5 + 7) / 8 as usize;
		let mut res_bytes: Vec<u8> = vec![0; length_bytes];
		for (u5_idx, chunk) in field_data.iter().enumerate() {
			let bit_pos_from_right_0_indexed = (field_data.len() - u5_idx - 1) * 5;
			let new_byte_idx = (bit_pos_from_right_0_indexed / 8) as usize;
			let new_bit_pos = bit_pos_from_right_0_indexed % 8;
			let chunk_u16 = chunk.to_u8() as u16;
			res_bytes[new_byte_idx] |= ((chunk_u16 << new_bit_pos) & 0xff) as u8;
			if new_byte_idx != length_bytes - 1 {
				res_bytes[new_byte_idx + 1] |= ((chunk_u16 >> (8-new_bit_pos)) & 0xff) as u8;
			}
		}
		// Trim the highest feature bits.
		while !res_bytes.is_empty() && res_bytes[res_bytes.len() - 1] == 0 {
			res_bytes.pop();
		}
		Ok(InvoiceFeatures::from_le_bytes(res_bytes))
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

	/// Converts `Features<T>` to `Features<C>`. Only known `T` features relevant to context `C` are
	/// included in the result.
	fn to_context_internal<C: sealed::Context>(&self) -> Features<C> {
		let from_byte_count = T::KNOWN_FEATURE_MASK.len();
		let to_byte_count = C::KNOWN_FEATURE_MASK.len();
		let mut flags = Vec::new();
		for (i, byte) in self.flags.iter().enumerate() {
			if i < from_byte_count && i < to_byte_count {
				let from_known_features = T::KNOWN_FEATURE_MASK[i];
				let to_known_features = C::KNOWN_FEATURE_MASK[i];
				flags.push(byte & from_known_features & to_known_features);
			}
		}
		Features::<C> { flags, mark: PhantomData, }
	}

	/// Create a Features given a set of flags, in little-endian. This is in reverse byte order from
	/// most on-the-wire encodings.
	/// (C-not exported) as we don't support export across multiple T
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

	fn write_be<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		for f in self.flags.iter().rev() { // Swap back to big-endian
			f.write(w)?;
		}
		Ok(())
	}

	fn from_be_bytes(mut flags: Vec<u8>) -> Features<T> {
		flags.reverse(); // Swap to little-endian
		Self {
			flags,
			mark: PhantomData,
		}
	}

	pub(crate) fn supports_any_optional_bits(&self) -> bool {
		self.flags.iter().any(|&byte| (byte & 0b10_10_10_10) != 0)
	}

	/// Returns true if this `Features` object contains unknown feature flags which are set as
	/// "required".
	pub fn requires_unknown_bits(&self) -> bool {
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

	// Returns true if the features within `self` are a subset of the features within `other`.
	pub(crate) fn is_subset(&self, other: &Self) -> bool {
		for (idx, byte) in self.flags.iter().enumerate() {
			if let Some(other_byte) = other.flags.get(idx) {
				if byte & other_byte != *byte {
					// `self` has bits set that `other` doesn't.
					return false;
				}
			} else {
				if *byte > 0 {
					// `self` has a non-zero byte that `other` doesn't.
					return false;
				}
			}
		}
		true
	}
}

impl<T: sealed::UpfrontShutdownScript> Features<T> {
	#[cfg(test)]
	pub(crate) fn clear_upfront_shutdown_script(mut self) -> Self {
		<T as sealed::UpfrontShutdownScript>::clear_bits(&mut self.flags);
		self
	}
}

impl<T: sealed::ShutdownAnySegwit> Features<T> {
	#[cfg(test)]
	pub(crate) fn clear_shutdown_anysegwit(mut self) -> Self {
		<T as sealed::ShutdownAnySegwit>::clear_bits(&mut self.flags);
		self
	}
}

impl<T: sealed::Wumbo> Features<T> {
	#[cfg(test)]
	pub(crate) fn clear_wumbo(mut self) -> Self {
		<T as sealed::Wumbo>::clear_bits(&mut self.flags);
		self
	}
}

impl<T: sealed::SCIDPrivacy> Features<T> {
	pub(crate) fn clear_scid_privacy(&mut self) {
		<T as sealed::SCIDPrivacy>::clear_bits(&mut self.flags);
	}
}

impl<T: sealed::AnchorsZeroFeeHtlcTx> Features<T> {
	pub(crate) fn clear_anchors_zero_fee_htlc_tx(&mut self) {
		<T as sealed::AnchorsZeroFeeHtlcTx>::clear_bits(&mut self.flags);
	}
}

#[cfg(test)]
impl<T: sealed::UnknownFeature> Features<T> {
	pub(crate) fn unknown() -> Self {
		let mut features = Self::empty();
		features.set_unknown_feature_required();
		features
	}
}

macro_rules! impl_feature_len_prefixed_write {
	($features: ident) => {
		impl Writeable for $features {
			fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
				(self.flags.len() as u16).write(w)?;
				self.write_be(w)
			}
		}
		impl Readable for $features {
			fn read<R: io::Read>(r: &mut R) -> Result<Self, DecodeError> {
				Ok(Self::from_be_bytes(Vec::<u8>::read(r)?))
			}
		}
	}
}
impl_feature_len_prefixed_write!(InitFeatures);
impl_feature_len_prefixed_write!(ChannelFeatures);
impl_feature_len_prefixed_write!(NodeFeatures);
impl_feature_len_prefixed_write!(InvoiceFeatures);
impl_feature_len_prefixed_write!(BlindedHopFeatures);

// Some features only appear inside of TLVs, so they don't have a length prefix when serialized.
macro_rules! impl_feature_tlv_write {
	($features: ident) => {
		impl Writeable for $features {
			fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
				WithoutLength(self).write(w)
			}
		}
		impl Readable for $features {
			fn read<R: io::Read>(r: &mut R) -> Result<Self, DecodeError> {
				Ok(WithoutLength::<Self>::read(r)?.0)
			}
		}
	}
}

impl_feature_tlv_write!(ChannelTypeFeatures);

// Some features may appear both in a TLV record and as part of a TLV subtype sequence. The latter
// requires a length but the former does not.

impl<T: sealed::Context> Writeable for WithoutLength<&Features<T>> {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		self.0.write_be(w)
	}
}

impl<T: sealed::Context> Readable for WithoutLength<Features<T>> {
	fn read<R: io::Read>(r: &mut R) -> Result<Self, DecodeError> {
		let v = io_extras::read_to_end(r)?;
		Ok(WithoutLength(Features::<T>::from_be_bytes(v)))
	}
}

#[cfg(test)]
mod tests {
	use super::{ChannelFeatures, ChannelTypeFeatures, InitFeatures, InvoiceFeatures, NodeFeatures, OfferFeatures, sealed};
	use bitcoin::bech32::{Base32Len, FromBase32, ToBase32, u5};
	use crate::util::ser::{Readable, WithoutLength, Writeable};

	#[test]
	fn sanity_test_unknown_bits() {
		let features = ChannelFeatures::empty();
		assert!(!features.requires_unknown_bits());
		assert!(!features.supports_unknown_bits());

		let mut features = ChannelFeatures::empty();
		features.set_unknown_feature_required();
		assert!(features.requires_unknown_bits());
		assert!(features.supports_unknown_bits());

		let mut features = ChannelFeatures::empty();
		features.set_unknown_feature_optional();
		assert!(!features.requires_unknown_bits());
		assert!(features.supports_unknown_bits());
	}

	#[test]
	fn convert_to_context_with_relevant_flags() {
		let mut init_features = InitFeatures::empty();
		// Set a bunch of features we use, plus initial_routing_sync_required (which shouldn't get
		// converted as it's only relevant in an init context).
		init_features.set_initial_routing_sync_required();
		init_features.set_data_loss_protect_optional();
		init_features.set_variable_length_onion_required();
		init_features.set_static_remote_key_required();
		init_features.set_payment_secret_required();
		init_features.set_basic_mpp_optional();
		init_features.set_wumbo_optional();
		init_features.set_shutdown_any_segwit_optional();
		init_features.set_onion_messages_optional();
		init_features.set_channel_type_optional();
		init_features.set_scid_privacy_optional();
		init_features.set_zero_conf_optional();
		init_features.set_anchors_zero_fee_htlc_tx_optional();

		assert!(init_features.initial_routing_sync());
		assert!(!init_features.supports_upfront_shutdown_script());
		assert!(!init_features.supports_gossip_queries());

		let node_features: NodeFeatures = init_features.to_context();
		{
			// Check that the flags are as expected:
			// - option_data_loss_protect
			// - var_onion_optin (req) | static_remote_key (req) | payment_secret(req)
			// - basic_mpp | wumbo
			// - opt_shutdown_anysegwit
			// - onion_messages
			// - option_channel_type | option_scid_alias
			// - option_zeroconf
			assert_eq!(node_features.flags.len(), 7);
			assert_eq!(node_features.flags[0], 0b00000010);
			assert_eq!(node_features.flags[1], 0b01010001);
			assert_eq!(node_features.flags[2], 0b10001010);
			assert_eq!(node_features.flags[3], 0b00001000);
			assert_eq!(node_features.flags[4], 0b10000000);
			assert_eq!(node_features.flags[5], 0b10100000);
			assert_eq!(node_features.flags[6], 0b00001000);
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

	#[test]
	fn convert_to_context_with_unknown_flags() {
		// Ensure the `from` context has fewer known feature bytes than the `to` context.
		assert!(<sealed::InvoiceContext as sealed::Context>::KNOWN_FEATURE_MASK.len() <
			<sealed::NodeContext as sealed::Context>::KNOWN_FEATURE_MASK.len());
		let mut invoice_features = InvoiceFeatures::empty();
		invoice_features.set_unknown_feature_optional();
		assert!(invoice_features.supports_unknown_bits());
		let node_features: NodeFeatures = invoice_features.to_context();
		assert!(!node_features.supports_unknown_bits());
	}

	#[test]
	fn set_feature_bits() {
		let mut features = InvoiceFeatures::empty();
		features.set_basic_mpp_optional();
		features.set_payment_secret_required();
		assert!(features.supports_basic_mpp());
		assert!(!features.requires_basic_mpp());
		assert!(features.requires_payment_secret());
		assert!(features.supports_payment_secret());
	}

	#[test]
	fn encodes_features_without_length() {
		let features = OfferFeatures::from_le_bytes(vec![1, 2, 3, 4, 5, 42, 100, 101]);
		assert_eq!(features.flags.len(), 8);

		let mut serialized_features = Vec::new();
		WithoutLength(&features).write(&mut serialized_features).unwrap();
		assert_eq!(serialized_features.len(), 8);

		let deserialized_features =
			WithoutLength::<OfferFeatures>::read(&mut &serialized_features[..]).unwrap().0;
		assert_eq!(features, deserialized_features);
	}

	#[test]
	fn invoice_features_encoding() {
		let features_as_u5s = vec![
			u5::try_from_u8(6).unwrap(),
			u5::try_from_u8(10).unwrap(),
			u5::try_from_u8(25).unwrap(),
			u5::try_from_u8(1).unwrap(),
			u5::try_from_u8(10).unwrap(),
			u5::try_from_u8(0).unwrap(),
			u5::try_from_u8(20).unwrap(),
			u5::try_from_u8(2).unwrap(),
			u5::try_from_u8(0).unwrap(),
			u5::try_from_u8(6).unwrap(),
			u5::try_from_u8(0).unwrap(),
			u5::try_from_u8(16).unwrap(),
			u5::try_from_u8(1).unwrap(),
		];
		let features = InvoiceFeatures::from_le_bytes(vec![1, 2, 3, 4, 5, 42, 100, 101]);

		// Test length calculation.
		assert_eq!(features.base32_len(), 13);

		// Test serialization.
		let features_serialized = features.to_base32();
		assert_eq!(features_as_u5s, features_serialized);

		// Test deserialization.
		let features_deserialized = InvoiceFeatures::from_base32(&features_as_u5s).unwrap();
		assert_eq!(features, features_deserialized);
	}

	#[test]
	fn test_channel_type_mapping() {
		// If we map an InvoiceFeatures with StaticRemoteKey optional, it should map into a
		// required-StaticRemoteKey ChannelTypeFeatures.
		let mut init_features = InitFeatures::empty();
		init_features.set_static_remote_key_optional();
		let converted_features = ChannelTypeFeatures::from_init(&init_features);
		assert_eq!(converted_features, ChannelTypeFeatures::only_static_remote_key());
		assert!(!converted_features.supports_any_optional_bits());
		assert!(converted_features.requires_static_remote_key());
	}
}
