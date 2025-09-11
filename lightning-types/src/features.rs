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
//! applicable for a specific context. [`Features`] encapsulates behavior for specifying and
//! checking feature flags for a particular context. Each feature is defined internally by a trait
//! specifying the corresponding flags (i.e., even and odd bits).
//!
//! Whether a feature is considered "known" or "unknown" is relative to the implementation, whereas
//! the term "supports" is used in reference to a particular set of [`Features`]. That is, a node
//! supports a feature if it advertises the feature (as either required or optional) to its peers.
//! And the implementation can interpret a feature if the feature is known to it.
//!
//! The following features are currently required in the LDK:
//! - `VariableLengthOnion` - requires/supports variable-length routing onion payloads
//!   (see [BOLT-4](https://github.com/lightning/bolts/blob/master/04-onion-routing.md) for more information).
//! - `StaticRemoteKey` - requires/supports static key for remote output
//!   (see [BOLT-3](https://github.com/lightning/bolts/blob/master/03-transactions.md) for more information).
//!
//! The following features are currently supported in the LDK:
//! - `DataLossProtect` - requires/supports that a node which has somehow fallen behind, e.g., has been restored from an old backup,
//!   can detect that it has fallen behind
//!   (see [BOLT-2](https://github.com/lightning/bolts/blob/master/02-peer-protocol.md) for more information).
//! - `InitialRoutingSync` - requires/supports that the sending node needs a complete routing information dump
//!   (see [BOLT-7](https://github.com/lightning/bolts/blob/master/07-routing-gossip.md#initial-sync) for more information).
//! - `UpfrontShutdownScript` - commits to a shutdown scriptpubkey when opening a channel
//!   (see [BOLT-2](https://github.com/lightning/bolts/blob/master/02-peer-protocol.md#the-open_channel-message) for more information).
//! - `GossipQueries` - requires/supports more sophisticated gossip control
//!   (see [BOLT-7](https://github.com/lightning/bolts/blob/master/07-routing-gossip.md) for more information).
//! - `PaymentSecret` - requires/supports that a node supports payment_secret field
//!   (see [BOLT-4](https://github.com/lightning/bolts/blob/master/04-onion-routing.md) for more information).
//! - `BasicMPP` - requires/supports that a node can receive basic multi-part payments
//!   (see [BOLT-4](https://github.com/lightning/bolts/blob/master/04-onion-routing.md#basic-multi-part-payments) for more information).
//! - `Wumbo` - requires/supports that a node create large channels. Called `option_support_large_channel` in the spec.
//!   (see [BOLT-2](https://github.com/lightning/bolts/blob/master/02-peer-protocol.md#the-open_channel-message) for more information).
//! - `AnchorsZeroFeeHtlcTx` - requires/supports that commitment transactions include anchor outputs
//!   and HTLC transactions are pre-signed with zero fee (see
//!   [BOLT-3](https://github.com/lightning/bolts/blob/master/03-transactions.md) for more
//!   information).
//! - `RouteBlinding` - requires/supports that a node can relay payments over blinded paths
//!   (see [BOLT-4](https://github.com/lightning/bolts/blob/master/04-onion-routing.md#route-blinding) for more information).
//! - `ShutdownAnySegwit` - requires/supports that future segwit versions are allowed in `shutdown`
//!   (see [BOLT-2](https://github.com/lightning/bolts/blob/master/02-peer-protocol.md) for more information).
//! - `DualFund` - requires/supports V2 channel establishment
//!   (see [BOLT-2](https://github.com/lightning/bolts/blob/master/02-peer-protocol.md#channel-establishment-v2) for more information).
//! - `SimpleClose` - requires/supports simplified closing negotiation
//!   (see [BOLT-2](https://github.com/lightning/bolts/blob/master/02-peer-protocol.md#closing-negotiation-closing_complete-and-closing_sig) for more information).
//! - `OnionMessages` - requires/supports forwarding onion messages
//!   (see [BOLT-7](https://github.com/lightning/bolts/pull/759/files) for more information).
//     TODO: update link
//! - `ChannelType` - node supports the channel_type field in open/accept
//!   (see [BOLT-2](https://github.com/lightning/bolts/blob/master/02-peer-protocol.md) for more information).
//! - `SCIDPrivacy` - supply channel aliases for routing
//!   (see [BOLT-2](https://github.com/lightning/bolts/blob/master/02-peer-protocol.md) for more information).
//! - `PaymentMetadata` - include additional data in invoices which is passed to recipients in the
//!   onion.
//!   (see [BOLT-11](https://github.com/lightning/bolts/blob/master/11-payment-encoding.md) for
//!   more).
//! - `ZeroConf` - supports accepting HTLCs and using channels prior to funding confirmation
//!   (see
//!   [BOLT-2](https://github.com/lightning/bolts/blob/master/02-peer-protocol.md#the-channel_ready-message)
//!   for more info).
//! - `Keysend` - send funds to a node without an invoice
//!   (see the [`Keysend` feature assignment proposal](https://github.com/lightning/bolts/issues/605#issuecomment-606679798) for more information).
//! - `Trampoline` - supports receiving and forwarding Trampoline payments
//!   (see the [`Trampoline` feature proposal](https://github.com/lightning/bolts/pull/836) for more information).
//! - `DnsResolver` - supports resolving DNS names to TXT DNSSEC proofs for BIP 353 payments
//!   (see [bLIP 32](https://github.com/lightning/blips/blob/master/blip-0032.md) for more information).
//! - `ProvideStorage` - Indicates that we offer the capability to store data of our peers
//!   (see [BOLT PR #1110](https://github.com/lightning/bolts/pull/1110) for more info).
//! - `Quiescence` - protocol to quiesce a channel by indicating that "SomeThing Fundamental is Underway"
//!   (see [BOLT-2](https://github.com/lightning/bolts/blob/master/02-peer-protocol.md#channel-quiescence) for more information).
//! - `ZeroFeeCommitments` - A channel type which always uses zero transaction fee on commitment transactions.
//!   (see [BOLT PR #1228](https://github.com/lightning/bolts/pull/1228) for more info).
//! - `Splice` - Allows replacing the currently-locked funding transaction with a new one
//!   (see [BOLT PR #1160](https://github.com/lightning/bolts/pull/1160) for more information).
//! - `HtlcHold` - requires/supports holding HTLCs and forwarding on receipt of an onion message
//!   (see [BOLT-2](https://github.com/lightning/bolts/pull/989/files) for more information).
//!
//! LDK knows about the following features, but does not support them:
//! - `AnchorsNonzeroFeeHtlcTx` - the initial version of anchor outputs, which was later found to be
//!   vulnerable (see this
//!   [mailing list post](https://lists.linuxfoundation.org/pipermail/lightning-dev/2020-September/002796.html)
//!   for more information).
//!
//! [BOLT #9]: https://github.com/lightning/bolts/blob/master/09-features.md

use core::borrow::Borrow;
use core::hash::{Hash, Hasher};
use core::marker::PhantomData;
use core::ops::{Deref, DerefMut};
use core::{cmp, fmt};

use alloc::vec::Vec;

mod sealed {
	use super::Features;

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

	define_context!(
		InitContext,
		[
			// Byte 0
			DataLossProtect | InitialRoutingSync | UpfrontShutdownScript | GossipQueries,
			// Byte 1
			VariableLengthOnion | StaticRemoteKey | PaymentSecret,
			// Byte 2
			BasicMPP | Wumbo | AnchorsNonzeroFeeHtlcTx | AnchorsZeroFeeHtlcTx,
			// Byte 3
			RouteBlinding | ShutdownAnySegwit | DualFund | Taproot,
			// Byte 4
			Quiescence | OnionMessages,
			// Byte 5
			ProvideStorage | ChannelType | SCIDPrivacy | AnchorZeroFeeCommitments,
			// Byte 6
			ZeroConf,
			// Byte 7
			Trampoline | SimpleClose | Splice,
			// Byte 8 - 130
			,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,
			// Byte 131
			HtlcHold,
		]
	);
	define_context!(
		NodeContext,
		[
			// Byte 0
			DataLossProtect | UpfrontShutdownScript | GossipQueries,
			// Byte 1
			VariableLengthOnion | StaticRemoteKey | PaymentSecret,
			// Byte 2
			BasicMPP | Wumbo | AnchorsNonzeroFeeHtlcTx | AnchorsZeroFeeHtlcTx,
			// Byte 3
			RouteBlinding | ShutdownAnySegwit | DualFund | Taproot,
			// Byte 4
			Quiescence | OnionMessages,
			// Byte 5
			ProvideStorage | ChannelType | SCIDPrivacy | AnchorZeroFeeCommitments,
			// Byte 6
			ZeroConf | Keysend,
			// Byte 7
			Trampoline | SimpleClose | Splice,
			// Byte 8 - 31
			,,,,,,,,,,,,,,,,,,,,,,,,
			// Byte 32
			DnsResolver,
			// Byte 33 - 130
			,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,
			// Byte 131
			HtlcHold,
		]
	);
	define_context!(ChannelContext, []);
	define_context!(Bolt11InvoiceContext, [
		// Byte 0
		,
		// Byte 1
		VariableLengthOnion | PaymentSecret,
		// Byte 2
		BasicMPP,
		// Byte 3
		,
		// Byte 4
		,
		// Byte 5
		,
		// Byte 6
		PaymentMetadata,
		// Byte 7
		Trampoline,
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
		// Byte 3
		,
		// Byte 4
		,
		// Byte 5
		,
		// Byte 6
		,
		// Byte 7
		Trampoline,
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
		AnchorsNonzeroFeeHtlcTx | AnchorsZeroFeeHtlcTx,
		// Byte 3
		Taproot,
		// Byte 4
		,
		// Byte 5
		SCIDPrivacy | AnchorZeroFeeCommitments,
		// Byte 6
		ZeroConf,
	]);

	/// Defines a feature with the given bits for the specified [`Context`]s. The generated trait is
	/// useful for manipulating feature flags.
	macro_rules! define_feature {
		($odd_bit: expr, $feature: ident, [$($context: ty),+], $doc: expr, $optional_setter: ident,
		 $required_setter: ident, $clear: ident, $supported_getter: ident) => {
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
				#[cfg(not(any(test, feature = "_test_utils")))] // We violate this constraint with `UnknownFeature`
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
				fn requires_feature(flags: &[u8]) -> bool {
					flags.len() > Self::BYTE_OFFSET &&
						(flags[Self::BYTE_OFFSET] & Self::REQUIRED_MASK) != 0
				}

				/// Returns whether the feature is supported by the given flags.
				#[inline]
				fn supports_feature(flags: &[u8]) -> bool {
					flags.len() > Self::BYTE_OFFSET &&
						(flags[Self::BYTE_OFFSET] & (Self::REQUIRED_MASK | Self::OPTIONAL_MASK)) != 0
				}

				/// Sets the feature's required (even) bit in the given flags.
				#[inline]
				fn set_required_bit(obj: &mut Features<Self>) {
					if obj.flags.len() <= Self::BYTE_OFFSET {
						obj.flags.resize(Self::BYTE_OFFSET + 1, 0u8);
					}

					obj.flags[Self::BYTE_OFFSET] |= Self::REQUIRED_MASK;
					obj.flags[Self::BYTE_OFFSET] &= !Self::OPTIONAL_MASK;
				}

				/// Sets the feature's optional (odd) bit in the given flags.
				#[inline]
				fn set_optional_bit(obj: &mut Features<Self>) {
					if obj.flags.len() <= Self::BYTE_OFFSET {
						obj.flags.resize(Self::BYTE_OFFSET + 1, 0u8);
					}

					obj.flags[Self::BYTE_OFFSET] |= Self::OPTIONAL_MASK;
				}

				/// Clears the feature's required (even) and optional (odd) bits from the given
				/// flags.
				#[inline]
				fn clear_bits(obj: &mut Features<Self>) {
					if obj.flags.len() > Self::BYTE_OFFSET {
						obj.flags[Self::BYTE_OFFSET] &= !Self::REQUIRED_MASK;
						obj.flags[Self::BYTE_OFFSET] &= !Self::OPTIONAL_MASK;
					}

					let last_non_zero_byte = obj.flags.iter().rposition(|&byte| byte != 0);
					let size = if let Some(offset) = last_non_zero_byte { offset + 1 } else { 0 };
					obj.flags.resize(size, 0u8);
				}
			}

			impl <T: $feature> Features<T> {
				/// Set this feature as optional.
				pub fn $optional_setter(&mut self) {
					<T as $feature>::set_optional_bit(self);
				}

				/// Set this feature as required.
				pub fn $required_setter(&mut self) {
					<T as $feature>::set_required_bit(self);
				}

				/// Unsets this feature.
				pub fn $clear(&mut self) {
					<T as $feature>::clear_bits(self);
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
					#[cfg(not(any(test, feature = "_test_utils")))] // We violate this constraint with `UnknownFeature`
					const ASSERT_BITS_IN_MASK: u8 =
						((<$context>::KNOWN_FEATURE_MASK[<Self as $feature>::BYTE_OFFSET] & (<Self as $feature>::REQUIRED_MASK | <Self as $feature>::OPTIONAL_MASK))
						 >> (<Self as $feature>::EVEN_BIT % 8)) - 3;
				}
			)*
		};
		($odd_bit: expr, $feature: ident, [$($context: ty),+], $doc: expr, $optional_setter: ident,
		 $required_setter: ident, $clear: ident, $supported_getter: ident, $required_getter: ident) => {
			define_feature!($odd_bit, $feature, [$($context),+], $doc, $optional_setter, $required_setter, $clear, $supported_getter);
			impl <T: $feature> Features<T> {
				/// Checks if this feature is required.
				pub fn $required_getter(&self) -> bool {
					<T as $feature>::requires_feature(&self.flags)
				}
			}
		}
	}

	define_feature!(
		1,
		DataLossProtect,
		[InitContext, NodeContext],
		"Feature flags for `option_data_loss_protect`.",
		set_data_loss_protect_optional,
		set_data_loss_protect_required,
		clear_data_loss_protect,
		supports_data_loss_protect,
		requires_data_loss_protect
	);
	// NOTE: Per Bolt #9, initial_routing_sync has no even bit.
	define_feature!(
		3,
		InitialRoutingSync,
		[InitContext],
		"Feature flags for `initial_routing_sync`.",
		set_initial_routing_sync_optional,
		set_initial_routing_sync_required,
		clear_initial_routing_sync,
		initial_routing_sync
	);
	define_feature!(
		5,
		UpfrontShutdownScript,
		[InitContext, NodeContext],
		"Feature flags for `option_upfront_shutdown_script`.",
		set_upfront_shutdown_script_optional,
		set_upfront_shutdown_script_required,
		clear_upfront_shutdown_script,
		supports_upfront_shutdown_script,
		requires_upfront_shutdown_script
	);
	define_feature!(
		7,
		GossipQueries,
		[InitContext, NodeContext],
		"Feature flags for `gossip_queries`.",
		set_gossip_queries_optional,
		set_gossip_queries_required,
		clear_gossip_queries,
		supports_gossip_queries,
		requires_gossip_queries
	);
	define_feature!(
		9,
		VariableLengthOnion,
		[InitContext, NodeContext, Bolt11InvoiceContext],
		"Feature flags for `var_onion_optin`.",
		set_variable_length_onion_optional,
		set_variable_length_onion_required,
		clear_variable_length_onion,
		supports_variable_length_onion,
		requires_variable_length_onion
	);
	define_feature!(
		13,
		StaticRemoteKey,
		[InitContext, NodeContext, ChannelTypeContext],
		"Feature flags for `option_static_remotekey`.",
		set_static_remote_key_optional,
		set_static_remote_key_required,
		clear_static_remote_key,
		supports_static_remote_key,
		requires_static_remote_key
	);
	define_feature!(
		15,
		PaymentSecret,
		[InitContext, NodeContext, Bolt11InvoiceContext],
		"Feature flags for `payment_secret`.",
		set_payment_secret_optional,
		set_payment_secret_required,
		clear_payment_secret,
		supports_payment_secret,
		requires_payment_secret
	);
	define_feature!(
		17,
		BasicMPP,
		[InitContext, NodeContext, Bolt11InvoiceContext, Bolt12InvoiceContext],
		"Feature flags for `basic_mpp`.",
		set_basic_mpp_optional,
		set_basic_mpp_required,
		clear_basic_mpp,
		supports_basic_mpp,
		requires_basic_mpp
	);
	define_feature!(
		19,
		Wumbo,
		[InitContext, NodeContext],
		"Feature flags for `option_support_large_channel` (aka wumbo channels).",
		set_wumbo_optional,
		set_wumbo_required,
		clear_wumbo,
		supports_wumbo,
		requires_wumbo
	);
	define_feature!(
		21,
		AnchorsNonzeroFeeHtlcTx,
		[InitContext, NodeContext, ChannelTypeContext],
		"Feature flags for `option_anchors_nonzero_fee_htlc_tx`.",
		set_anchors_nonzero_fee_htlc_tx_optional,
		set_anchors_nonzero_fee_htlc_tx_required,
		clear_anchors_nonzero_fee_htlc_tx,
		supports_anchors_nonzero_fee_htlc_tx,
		requires_anchors_nonzero_fee_htlc_tx
	);
	define_feature!(
		23,
		AnchorsZeroFeeHtlcTx,
		[InitContext, NodeContext, ChannelTypeContext],
		"Feature flags for `option_anchors_zero_fee_htlc_tx`.",
		set_anchors_zero_fee_htlc_tx_optional,
		set_anchors_zero_fee_htlc_tx_required,
		clear_anchors_zero_fee_htlc_tx,
		supports_anchors_zero_fee_htlc_tx,
		requires_anchors_zero_fee_htlc_tx
	);
	define_feature!(
		25,
		RouteBlinding,
		[InitContext, NodeContext],
		"Feature flags for `option_route_blinding`.",
		set_route_blinding_optional,
		set_route_blinding_required,
		clear_route_blinding,
		supports_route_blinding,
		requires_route_blinding
	);
	define_feature!(
		27,
		ShutdownAnySegwit,
		[InitContext, NodeContext],
		"Feature flags for `opt_shutdown_anysegwit`.",
		set_shutdown_any_segwit_optional,
		set_shutdown_any_segwit_required,
		clear_shutdown_anysegwit,
		supports_shutdown_anysegwit,
		requires_shutdown_anysegwit
	);
	define_feature!(
		29,
		DualFund,
		[InitContext, NodeContext],
		"Feature flags for `option_dual_fund`.",
		set_dual_fund_optional,
		set_dual_fund_required,
		clear_dual_fund,
		supports_dual_fund,
		requires_dual_fund
	);
	define_feature!(
		31,
		Taproot,
		[InitContext, NodeContext, ChannelTypeContext],
		"Feature flags for `option_taproot`.",
		set_taproot_optional,
		set_taproot_required,
		clear_taproot,
		supports_taproot,
		requires_taproot
	);
	define_feature!(
		35,
		Quiescence,
		[InitContext, NodeContext],
		"Feature flags for `option_quiesce`.",
		set_quiescence_optional,
		set_quiescence_required,
		clear_quiescence,
		supports_quiescence,
		requires_quiescence
	);
	define_feature!(
		39,
		OnionMessages,
		[InitContext, NodeContext],
		"Feature flags for `option_onion_messages`.",
		set_onion_messages_optional,
		set_onion_messages_required,
		clear_onion_messages,
		supports_onion_messages,
		requires_onion_messages
	);
	define_feature!(
		41,
		AnchorZeroFeeCommitments,
		[InitContext, NodeContext, ChannelTypeContext],
		"Feature flags for `option_zero_fee_commitments`.",
		set_anchor_zero_fee_commitments_optional,
		set_anchor_zero_fee_commitments_required,
		clear_anchor_zero_fee_commitments,
		supports_anchor_zero_fee_commitments,
		requires_anchor_zero_fee_commitments
	);
	define_feature!(
		43,
		ProvideStorage,
		[InitContext, NodeContext],
		"Feature flags for `option_provide_storage`.",
		set_provide_storage_optional,
		set_provide_storage_required,
		clear_provide_storage,
		supports_provide_storage,
		requires_provide_storage
	);
	define_feature!(
		45,
		ChannelType,
		[InitContext, NodeContext],
		"Feature flags for `option_channel_type`.",
		set_channel_type_optional,
		set_channel_type_required,
		clear_channel_type,
		supports_channel_type,
		requires_channel_type
	);
	define_feature!(47,
		SCIDPrivacy,
		[InitContext, NodeContext, ChannelTypeContext],
		"Feature flags for only forwarding with SCID aliasing. Called `option_scid_alias` in the BOLTs",
		set_scid_privacy_optional,
		set_scid_privacy_required,
		clear_scid_privacy,
		supports_scid_privacy,
		requires_scid_privacy
	);
	define_feature!(
		49,
		PaymentMetadata,
		[Bolt11InvoiceContext],
		"Feature flags for payment metadata in invoices.",
		set_payment_metadata_optional,
		set_payment_metadata_required,
		clear_payment_metadata,
		supports_payment_metadata,
		requires_payment_metadata
	);
	define_feature!(51, ZeroConf, [InitContext, NodeContext, ChannelTypeContext],
		"Feature flags for accepting channels with zero confirmations. Called `option_zeroconf` in the BOLTs",
		set_zero_conf_optional, set_zero_conf_required, supports_zero_conf, requires_zero_conf);
	define_feature!(
		55,
		Keysend,
		[NodeContext],
		"Feature flags for keysend payments.",
		set_keysend_optional,
		set_keysend_required,
		clear_keysend,
		supports_keysend,
		requires_keysend
	);
	define_feature!(
		57,
		Trampoline,
		[InitContext, NodeContext, Bolt11InvoiceContext, Bolt12InvoiceContext],
		"Feature flags for Trampoline routing.",
		set_trampoline_routing_optional,
		set_trampoline_routing_required,
		clear_trampoline_routing,
		supports_trampoline_routing,
		requires_trampoline_routing
	);
	define_feature!(
		61,
		SimpleClose,
		[InitContext, NodeContext],
		"Feature flags for simplified closing negotiation.",
		set_simple_close_optional,
		set_simple_close_required,
		clear_simple_close,
		supports_simple_close,
		requires_simple_close
	);
	define_feature!(
		63,
		Splice,
		[InitContext, NodeContext],
		"Feature flags for channel splicing.",
		set_splicing_optional,
		set_splicing_required,
		clear_splicing,
		supports_splicing,
		requires_splicing
	);
	// By default, allocate enough bytes to cover up to Splice. Update this as new features are
	// added which we expect to appear commonly across contexts.
	pub(super) const MIN_FEATURES_ALLOCATION_BYTES: usize = (63 + 7) / 8;
	define_feature!(
		259,
		DnsResolver,
		[NodeContext],
		"Feature flags for DNS resolving.",
		set_dns_resolution_optional,
		set_dns_resolution_required,
		clear_dns_resolution,
		supports_dns_resolution,
		requires_dns_resolution
	);
	define_feature!(
		1053, // The BOLTs PR uses feature bit 52/53, so add +1000 for the experimental bit
		HtlcHold,
		[InitContext, NodeContext],
		"Feature flags for holding HTLCs and forwarding on receipt of an onion message",
		set_htlc_hold_optional,
		set_htlc_hold_required,
		clear_htlc_hold,
		supports_htlc_hold,
		requires_htlc_hold
	);

	// Note: update the module-level docs when a new feature bit is added!

	#[cfg(any(test, feature = "_test_utils"))]
	define_feature!(
		12345,
		UnknownFeature,
		[
			NodeContext,
			ChannelContext,
			Bolt11InvoiceContext,
			OfferContext,
			InvoiceRequestContext,
			Bolt12InvoiceContext,
			BlindedHopContext
		],
		"Feature flags for an unknown feature used in testing.",
		set_unknown_feature_optional,
		set_unknown_feature_required,
		clear_unknown_feature,
		supports_unknown_test_feature,
		requires_unknown_test_feature
	);
}

const ANY_REQUIRED_FEATURES_MASK: u8 = 0b01_01_01_01;
const ANY_OPTIONAL_FEATURES_MASK: u8 = 0b10_10_10_10;

// Vecs are always 3 pointers long, so `FeatureFlags` is never shorter than 24 bytes on 64-bit
// platforms no matter what we do.
//
// Luckily, because `Vec` uses a `NonNull` pointer to its buffer, the two-variant enum is free
// space-wise, but we only get the remaining 2 usizes in length available for our own stuff (as any
// other value is interpreted as the `Heap` variant).
//
// Thus, as long as we never use more than 16 bytes (15 bytes for the data and one byte for the
// length) for our Held variant `FeatureFlags` is the same length as a `Vec` in memory.
const DIRECT_ALLOC_BYTES: usize = if sealed::MIN_FEATURES_ALLOCATION_BYTES > 8 * 2 - 1 {
	sealed::MIN_FEATURES_ALLOCATION_BYTES
} else {
	8 * 2 - 1
};
const _ASSERT: () = assert!(DIRECT_ALLOC_BYTES <= u8::MAX as usize);

#[cfg(fuzzing)]
#[derive(Clone, PartialEq, Eq)]
pub enum FeatureFlags {
	Held { bytes: [u8; DIRECT_ALLOC_BYTES], len: u8 },
	Heap(Vec<u8>),
}

#[cfg(not(fuzzing))]
#[derive(Clone, PartialEq, Eq)]
enum FeatureFlags {
	Held { bytes: [u8; DIRECT_ALLOC_BYTES], len: u8 },
	Heap(Vec<u8>),
}

impl FeatureFlags {
	/// Constructs an empty [`FeatureFlags`]
	pub fn empty() -> Self {
		Self::Held { bytes: [0; DIRECT_ALLOC_BYTES], len: 0 }
	}

	/// Constructs a [`FeatureFlags`] from the given bytes
	pub fn from(vec: Vec<u8>) -> Self {
		if vec.len() <= DIRECT_ALLOC_BYTES {
			let mut bytes = [0; DIRECT_ALLOC_BYTES];
			bytes[..vec.len()].copy_from_slice(&vec);
			Self::Held { bytes, len: vec.len() as u8 }
		} else {
			Self::Heap(vec)
		}
	}

	/// Resizes a [`FeatureFlags`] to the given length, padding with `default` if required.
	///
	/// See [`Vec::resize`] for more info.
	pub fn resize(&mut self, new_len: usize, default: u8) {
		match self {
			Self::Held { bytes, len } => {
				let start_len = *len as usize;
				if new_len <= DIRECT_ALLOC_BYTES {
					bytes[start_len..].copy_from_slice(&[default; DIRECT_ALLOC_BYTES][start_len..]);
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
				if new_len <= DIRECT_ALLOC_BYTES {
					let mut bytes = [0; DIRECT_ALLOC_BYTES];
					bytes[..new_len].copy_from_slice(&vec[..new_len]);
					*self = Self::Held { bytes, len: new_len as u8 };
				}
			},
		}
	}

	/// Fetches the length of the [`FeatureFlags`], in bytes.
	pub fn len(&self) -> usize {
		self.deref().len()
	}

	/// Fetches an iterator over the bytes of this [`FeatureFlags`]
	pub fn iter(
		&self,
	) -> (impl Clone + ExactSizeIterator<Item = &u8> + DoubleEndedIterator<Item = &u8>) {
		let slice = self.deref();
		slice.iter()
	}

	/// Fetches a mutable iterator over the bytes of this [`FeatureFlags`]
	pub fn iter_mut(
		&mut self,
	) -> (impl ExactSizeIterator<Item = &mut u8> + DoubleEndedIterator<Item = &mut u8>) {
		let slice = self.deref_mut();
		slice.iter_mut()
	}
}

impl Deref for FeatureFlags {
	type Target = [u8];
	fn deref(&self) -> &[u8] {
		match self {
			FeatureFlags::Held { bytes, len } => &bytes[..*len as usize],
			FeatureFlags::Heap(vec) => &vec,
		}
	}
}

impl DerefMut for FeatureFlags {
	fn deref_mut(&mut self) -> &mut [u8] {
		match self {
			FeatureFlags::Held { bytes, len } => &mut bytes[..*len as usize],
			FeatureFlags::Heap(vec) => &mut vec[..],
		}
	}
}

impl PartialOrd for FeatureFlags {
	fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
		Some(self.cmp(other))
	}
}
impl Ord for FeatureFlags {
	fn cmp(&self, other: &Self) -> cmp::Ordering {
		self.deref().cmp(other.deref())
	}
}
impl fmt::Debug for FeatureFlags {
	fn fmt(&self, fmt: &mut fmt::Formatter) -> Result<(), fmt::Error> {
		self.deref().fmt(fmt)
	}
}

/// Tracks the set of features which a node implements, templated by the context in which it
/// appears.
///
/// This is not exported to bindings users as we map the concrete feature types below directly instead
#[derive(Eq)]
pub struct Features<T: sealed::Context + ?Sized> {
	/// Note that, for convenience, flags is LITTLE endian (despite being big-endian on the wire)
	flags: FeatureFlags,
	mark: PhantomData<T>,
}

impl<T: sealed::Context, Rhs: Borrow<Self>> core::ops::BitOrAssign<Rhs> for Features<T> {
	fn bitor_assign(&mut self, rhs: Rhs) {
		let total_feature_len = cmp::max(self.flags.len(), rhs.borrow().flags.len());
		self.flags.resize(total_feature_len, 0u8);
		for (byte, rhs_byte) in self.flags.iter_mut().zip(rhs.borrow().flags.iter()) {
			*byte |= *rhs_byte;
		}
	}
}

impl<T: sealed::Context> core::ops::BitOr for Features<T> {
	type Output = Self;

	fn bitor(mut self, o: Self) -> Self {
		self |= o;
		self
	}
}

impl<T: sealed::Context> Clone for Features<T> {
	fn clone(&self) -> Self {
		Self { flags: self.flags.clone(), mark: PhantomData }
	}
}
impl<T: sealed::Context> Hash for Features<T> {
	fn hash<H: Hasher>(&self, hasher: &mut H) {
		let mut nonzero_flags = &self.flags[..];
		while nonzero_flags.last() == Some(&0) {
			nonzero_flags = &nonzero_flags[..nonzero_flags.len() - 1];
		}
		nonzero_flags.hash(hasher);
	}
}
impl<T: sealed::Context + ?Sized> PartialEq for Features<T> {
	fn eq(&self, o: &Self) -> bool {
		let mut o_iter = o.flags.iter();
		let mut self_iter = self.flags.iter();
		loop {
			match (o_iter.next(), self_iter.next()) {
				(Some(o), Some(us)) => {
					if o != us {
						return false;
					}
				},
				(Some(b), None) | (None, Some(b)) => {
					if *b != 0 {
						return false;
					}
				},
				(None, None) => return true,
			}
		}
	}
}
impl<T: sealed::Context> PartialOrd for Features<T> {
	fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
		self.flags.partial_cmp(&other.flags)
	}
}
impl<T: sealed::Context + Eq> Ord for Features<T> {
	fn cmp(&self, other: &Self) -> cmp::Ordering {
		self.flags.cmp(&other.flags)
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
pub type Bolt11InvoiceFeatures = Features<sealed::Bolt11InvoiceContext>;
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
	#[doc(hidden)]
	/// Converts `InitFeatures` to `Features<C>`. Only known `InitFeatures` relevant to context `C`
	/// are included in the result.
	///
	/// This is not exported to bindings users as it shouldn't be used outside of LDK
	pub fn to_context<C: sealed::Context>(&self) -> Features<C> {
		self.to_context_internal()
	}
}

impl Bolt11InvoiceFeatures {
	#[doc(hidden)]
	/// Converts `Bolt11InvoiceFeatures` to `Features<C>`. Only known `Bolt11InvoiceFeatures` relevant to
	/// context `C` are included in the result.
	///
	/// This is not exported to bindings users as it shouldn't be used outside of LDK
	pub fn to_context<C: sealed::Context>(&self) -> Features<C> {
		self.to_context_internal()
	}

	/// Getting a route for a keysend payment to a private node requires providing the payee's
	/// features (since they were not announced in a node announcement). However, keysend payments
	/// don't have an invoice to pull the payee's features from, so this method is provided for use
	/// when a [`Bolt11InvoiceFeatures`] is required in a route.
	///
	/// MPP keysend is not widely supported yet, so we parameterize support to allow the user to
	/// choose whether their router should find multi-part routes.
	pub fn for_keysend(allow_mpp: bool) -> Bolt11InvoiceFeatures {
		let mut res = Bolt11InvoiceFeatures::empty();
		res.set_variable_length_onion_optional();
		if allow_mpp {
			res.set_basic_mpp_optional();
		}
		res
	}
}

impl Bolt12InvoiceFeatures {
	#[doc(hidden)]
	/// Converts [`Bolt12InvoiceFeatures`] to [`Features<C>`]. Only known [`Bolt12InvoiceFeatures`]
	/// relevant to context `C` are included in the result.
	///
	/// This is not exported to bindings users as it shouldn't be used outside of LDK
	pub fn to_context<C: sealed::Context>(&self) -> Features<C> {
		self.to_context_internal()
	}
}

impl ChannelTypeFeatures {
	#[doc(hidden)]
	/// Maps the relevant `InitFeatures` to `ChannelTypeFeatures`. Any unknown features to
	/// `ChannelTypeFeatures` are not included in the result.
	///
	/// This is not exported to bindings users as it shouldn't be used outside of LDK
	pub fn from_init(init: &InitFeatures) -> Self {
		let mut ret = init.to_context_internal();
		// ChannelTypeFeatures must only contain required bits, so we OR the required forms of all
		// optional bits and then AND out the optional ones.
		for byte in ret.flags.iter_mut() {
			*byte |= (*byte & ANY_OPTIONAL_FEATURES_MASK) >> 1;
			*byte &= ANY_REQUIRED_FEATURES_MASK;
		}
		ret
	}

	/// Constructs a ChannelTypeFeatures with only static_remotekey set
	pub fn only_static_remote_key() -> Self {
		let mut ret = Self::empty();
		<sealed::ChannelTypeContext as sealed::StaticRemoteKey>::set_required_bit(&mut ret);
		ret
	}

	/// Constructs a ChannelTypeFeatures with anchors support
	pub fn anchors_zero_htlc_fee_and_dependencies() -> Self {
		let mut ret = Self::empty();
		<sealed::ChannelTypeContext as sealed::StaticRemoteKey>::set_required_bit(&mut ret);
		<sealed::ChannelTypeContext as sealed::AnchorsZeroFeeHtlcTx>::set_required_bit(&mut ret);
		ret
	}

	/// Constructs a ChannelTypeFeatures with zero fee commitment anchors support.
	pub fn anchors_zero_fee_commitments() -> Self {
		let mut ret = Self::empty();
		<sealed::ChannelTypeContext as sealed::AnchorZeroFeeCommitments>::set_required_bit(
			&mut ret,
		);
		ret
	}
}

impl<T: sealed::Context> Features<T> {
	/// Create a blank Features with no features set
	pub fn empty() -> Self {
		Features { flags: FeatureFlags::empty(), mark: PhantomData }
	}

	/// Converts `Features<T>` to `Features<C>`. Only known `T` features relevant to context `C` are
	/// included in the result.
	fn to_context_internal<C: sealed::Context>(&self) -> Features<C> {
		let flag_iter = self.flags.iter().enumerate().filter_map(|(i, byte)| {
			if i < T::KNOWN_FEATURE_MASK.len() && i < C::KNOWN_FEATURE_MASK.len() {
				Some((i, *byte & T::KNOWN_FEATURE_MASK[i] & C::KNOWN_FEATURE_MASK[i]))
			} else {
				None
			}
		});
		let mut flags = FeatureFlags::empty();
		flags.resize(flag_iter.clone().count(), 0);
		for (i, byte) in flag_iter {
			flags[i] = byte;
		}
		Features::<C> { flags, mark: PhantomData }
	}

	/// Create a Features given a set of flags, in little-endian. This is in reverse byte order from
	/// most on-the-wire encodings.
	///
	/// This is not exported to bindings users as we don't support export across multiple T
	pub fn from_le_bytes(flags: Vec<u8>) -> Features<T> {
		Features { flags: FeatureFlags::from(flags), mark: PhantomData }
	}

	/// Returns the feature set as a list of bytes, in little-endian. This is in reverse byte order
	/// from most on-the-wire encodings.
	pub fn le_flags(&self) -> &[u8] {
		&self.flags
	}

	/// Create a [`Features`] given a set of flags, in big-endian. This is in byte order from
	/// most on-the-wire encodings.
	///
	/// This is not exported to bindings users as we don't support export across multiple T
	pub fn from_be_bytes(mut flags: Vec<u8>) -> Features<T> {
		flags.reverse(); // Swap to little-endian
		Self { flags: FeatureFlags::from(flags), mark: PhantomData }
	}

	/// Returns true if this `Features` has any optional flags set
	pub fn supports_any_optional_bits(&self) -> bool {
		self.flags.iter().any(|&byte| (byte & ANY_OPTIONAL_FEATURES_MASK) != 0)
	}

	/// Returns true if this `Features` object contains required features unknown by `other`.
	pub fn requires_unknown_bits_from(&self, other: &Self) -> bool {
		// Bitwise AND-ing with all even bits set except for known features will select required
		// unknown features.
		self.flags.iter().enumerate().any(|(i, &byte)| {
			let unknown_features = unset_features_mask_at_position(other, i);
			(byte & (ANY_REQUIRED_FEATURES_MASK & unknown_features)) != 0
		})
	}

	/// Returns the set of required features unknown by `other`, as their bit position.
	pub fn required_unknown_bits_from(&self, other: &Self) -> Vec<u64> {
		let mut unknown_bits = Vec::new();

		// Bitwise AND-ing with all even bits set except for known features will select required
		// unknown features.
		self.flags.iter().enumerate().for_each(|(i, &byte)| {
			let unknown_features = unset_features_mask_at_position(other, i);
			if byte & unknown_features != 0 {
				for bit in (0..8).step_by(2) {
					if ((byte & unknown_features) >> bit) & 1 == 1 {
						unknown_bits.push((i as u64) * 8 + bit);
					}
				}
			}
		});

		unknown_bits
	}

	/// Returns true if this `Features` object contains unknown feature flags which are set as
	/// "required".
	pub fn requires_unknown_bits(&self) -> bool {
		// Bitwise AND-ing with all even bits set except for known features will select required
		// unknown features.
		let mut known_chunks = T::KNOWN_FEATURE_MASK.chunks(8);
		for chunk in self.flags.chunks(8) {
			let mut flag_bytes = [0; 8];
			flag_bytes[..chunk.len()].copy_from_slice(&chunk);
			let flag_int = u64::from_le_bytes(flag_bytes);

			let known_chunk = known_chunks.next().unwrap_or(&[0; 0]);
			let mut known_bytes = [0; 8];
			known_bytes[..known_chunk.len()].copy_from_slice(&known_chunk);
			let known_int = u64::from_le_bytes(known_bytes);

			const REQ_MASK: u64 = u64::from_le_bytes([ANY_REQUIRED_FEATURES_MASK; 8]);
			if flag_int & (REQ_MASK & !known_int) != 0 {
				return true;
			}
		}
		false
	}

	/// Returns true if this `Features` supports any bits which we do not know of
	pub fn supports_unknown_bits(&self) -> bool {
		// Bitwise AND-ing with all even and odd bits set except for known features will select
		// both required and optional unknown features.
		let byte_count = T::KNOWN_FEATURE_MASK.len();
		self.flags.iter().enumerate().any(|(i, &byte)| {
			let unknown_features =
				if i < byte_count { !T::KNOWN_FEATURE_MASK[i] } else { 0b11_11_11_11 };
			(byte & unknown_features) != 0
		})
	}

	/// Sets a required feature bit. Errors if `bit` is outside the feature range as defined
	/// by [BOLT 9].
	///
	/// Note: Required bits are even. If an odd bit is given, then the corresponding even bit will
	/// be set instead (i.e., `bit - 1`).
	///
	/// [BOLT 9]: https://github.com/lightning/bolts/blob/master/09-features.md
	pub fn set_required_feature_bit(&mut self, bit: usize) -> Result<(), ()> {
		self.set_feature_bit(bit - (bit % 2))
	}

	/// Sets an optional feature bit. Errors if `bit` is outside the feature range as defined
	/// by [BOLT 9].
	///
	/// Note: Optional bits are odd. If an even bit is given, then the corresponding odd bit will be
	/// set instead (i.e., `bit + 1`).
	///
	/// [BOLT 9]: https://github.com/lightning/bolts/blob/master/09-features.md
	pub fn set_optional_feature_bit(&mut self, bit: usize) -> Result<(), ()> {
		self.set_feature_bit(bit + (1 - (bit % 2)))
	}

	fn set_feature_bit(&mut self, bit: usize) -> Result<(), ()> {
		if bit > 255 {
			return Err(());
		}
		self.set_bit(bit, false)
	}

	/// Sets a required custom feature bit. Errors if `bit` is outside the custom range as defined
	/// by [bLIP 2] or if it is a known `T` feature.
	///
	/// Note: Required bits are even. If an odd bit is given, then the corresponding even bit will
	/// be set instead (i.e., `bit - 1`).
	///
	/// [bLIP 2]: https://github.com/lightning/blips/blob/master/blip-0002.md#feature-bits
	pub fn set_required_custom_bit(&mut self, bit: usize) -> Result<(), ()> {
		self.set_custom_bit(bit - (bit % 2))
	}

	/// Sets an optional custom feature bit. Errors if `bit` is outside the custom range as defined
	/// by [bLIP 2] or if it is a known `T` feature.
	///
	/// Note: Optional bits are odd. If an even bit is given, then the corresponding odd bit will be
	/// set instead (i.e., `bit + 1`).
	///
	/// [bLIP 2]: https://github.com/lightning/blips/blob/master/blip-0002.md#feature-bits
	pub fn set_optional_custom_bit(&mut self, bit: usize) -> Result<(), ()> {
		self.set_custom_bit(bit + (1 - (bit % 2)))
	}

	fn set_custom_bit(&mut self, bit: usize) -> Result<(), ()> {
		if bit < 256 {
			return Err(());
		}
		self.set_bit(bit, true)
	}

	fn set_bit(&mut self, bit: usize, custom: bool) -> Result<(), ()> {
		let byte_offset = bit / 8;
		let mask = 1 << (bit - 8 * byte_offset);
		if byte_offset < T::KNOWN_FEATURE_MASK.len() && custom {
			if (T::KNOWN_FEATURE_MASK[byte_offset] & mask) != 0 {
				return Err(());
			}
		}

		if self.flags.len() <= byte_offset {
			self.flags.resize(byte_offset + 1, 0u8);
		}

		self.flags[byte_offset] |= mask;

		Ok(())
	}
}

#[cfg(any(test, feature = "_test_utils"))]
impl<T: sealed::UnknownFeature> Features<T> {
	/// Sets an unknown feature for testing
	pub fn unknown() -> Self {
		let mut features = Self::empty();
		features.set_unknown_feature_required();
		features
	}
}

pub(crate) fn unset_features_mask_at_position<T: sealed::Context>(
	other: &Features<T>, index: usize,
) -> u8 {
	if index < other.flags.len() {
		// Form a mask similar to !T::KNOWN_FEATURE_MASK only for `other`
		!(other.flags[index]
			| ((other.flags[index] >> 1) & ANY_REQUIRED_FEATURES_MASK)
			| ((other.flags[index] << 1) & ANY_OPTIONAL_FEATURES_MASK))
	} else {
		0b11_11_11_11
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn sanity_test_unknown_bits() {
		let features = ChannelFeatures::empty();
		assert!(!features.requires_unknown_bits());
		assert!(!features.supports_unknown_bits());

		let mut features = ChannelFeatures::empty();
		features.set_unknown_feature_required();
		assert!(features.requires_unknown_bits());
		assert!(features.supports_unknown_bits());
		assert_eq!(features.required_unknown_bits_from(&ChannelFeatures::empty()), vec![12344]);

		let mut features = ChannelFeatures::empty();
		features.set_unknown_feature_optional();
		assert!(!features.requires_unknown_bits());
		assert!(features.supports_unknown_bits());
		assert_eq!(features.required_unknown_bits_from(&ChannelFeatures::empty()), vec![]);

		let mut features = ChannelFeatures::empty();
		features.set_unknown_feature_required();
		features.set_custom_bit(12346).unwrap();
		assert!(features.requires_unknown_bits());
		assert!(features.supports_unknown_bits());
		assert_eq!(
			features.required_unknown_bits_from(&ChannelFeatures::empty()),
			vec![12344, 12346]
		);

		let mut limiter = ChannelFeatures::empty();
		limiter.set_unknown_feature_optional();
		assert_eq!(features.required_unknown_bits_from(&limiter), vec![12346]);
	}

	#[test]
	fn requires_unknown_bits_from() {
		let mut features1 = InitFeatures::empty();
		let mut features2 = InitFeatures::empty();
		assert!(!features1.requires_unknown_bits_from(&features2));
		assert!(!features2.requires_unknown_bits_from(&features1));

		features1.set_provide_storage_required();
		assert!(features1.requires_unknown_bits_from(&features2));
		assert!(!features2.requires_unknown_bits_from(&features1));

		features2.set_provide_storage_optional();
		assert!(!features1.requires_unknown_bits_from(&features2));
		assert!(!features2.requires_unknown_bits_from(&features1));

		features1.set_data_loss_protect_required();
		assert!(features1.requires_unknown_bits_from(&features2));
		assert!(!features2.requires_unknown_bits_from(&features1));

		features2.set_data_loss_protect_optional();
		assert!(!features1.requires_unknown_bits_from(&features2));
		assert!(!features2.requires_unknown_bits_from(&features1));

		features2.set_gossip_queries_required();
		assert!(!features1.requires_unknown_bits_from(&features2));
		assert!(features2.requires_unknown_bits_from(&features1));

		features1.set_gossip_queries_optional();
		assert!(!features1.requires_unknown_bits_from(&features2));
		assert!(!features2.requires_unknown_bits_from(&features1));

		features1.set_variable_length_onion_required();
		assert!(features1.requires_unknown_bits_from(&features2));
		assert!(!features2.requires_unknown_bits_from(&features1));

		features2.set_variable_length_onion_optional();
		assert!(!features1.requires_unknown_bits_from(&features2));
		assert!(!features2.requires_unknown_bits_from(&features1));

		features1.set_basic_mpp_required();
		features2.set_wumbo_required();
		assert!(features1.requires_unknown_bits_from(&features2));
		assert!(features2.requires_unknown_bits_from(&features1));
	}

	#[test]
	fn convert_to_context_with_relevant_flags() {
		let mut init_features = InitFeatures::empty();
		// Set a bunch of features we use, plus initial_routing_sync_required (which shouldn't get
		// converted as it's only relevant in an init context).
		init_features.set_initial_routing_sync_required();
		init_features.set_data_loss_protect_required();
		init_features.set_variable_length_onion_required();
		init_features.set_static_remote_key_required();
		init_features.set_payment_secret_required();
		init_features.set_basic_mpp_optional();
		init_features.set_wumbo_optional();
		init_features.set_anchors_zero_fee_htlc_tx_optional();
		init_features.set_route_blinding_optional();
		init_features.set_shutdown_any_segwit_optional();
		init_features.set_onion_messages_optional();
		init_features.set_channel_type_optional();
		init_features.set_scid_privacy_optional();
		init_features.set_zero_conf_optional();
		init_features.set_quiescence_optional();
		init_features.set_simple_close_optional();
		init_features.set_splicing_optional();

		assert!(init_features.initial_routing_sync());
		assert!(!init_features.supports_upfront_shutdown_script());
		assert!(!init_features.supports_gossip_queries());

		let node_features: NodeFeatures = init_features.to_context();
		{
			// Check that the flags are as expected:
			// - option_data_loss_protect (req)
			// - var_onion_optin (req) | static_remote_key (req) | payment_secret(req)
			// - basic_mpp | wumbo | option_anchors_zero_fee_htlc_tx
			// - option_route_blinding | opt_shutdown_anysegwit
			// - onion_messages
			// - option_channel_type | option_scid_alias
			// - option_zeroconf
			// - option_simple_close | option_splice
			assert_eq!(node_features.flags.len(), 8);
			assert_eq!(node_features.flags[0], 0b00000001);
			assert_eq!(node_features.flags[1], 0b01010001);
			assert_eq!(node_features.flags[2], 0b10001010);
			assert_eq!(node_features.flags[3], 0b00001010);
			assert_eq!(node_features.flags[4], 0b10001000);
			assert_eq!(node_features.flags[5], 0b10100000);
			assert_eq!(node_features.flags[6], 0b00001000);
			assert_eq!(node_features.flags[7], 0b10100000);
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
		assert!(
			<sealed::ChannelContext as sealed::Context>::KNOWN_FEATURE_MASK.len()
				< <sealed::Bolt11InvoiceContext as sealed::Context>::KNOWN_FEATURE_MASK.len()
		);
		let mut channel_features = ChannelFeatures::empty();
		channel_features.set_unknown_feature_optional();
		assert!(channel_features.supports_unknown_bits());
		let invoice_features: Bolt11InvoiceFeatures = channel_features.to_context_internal();
		assert!(!invoice_features.supports_unknown_bits());
	}

	#[test]
	fn set_feature_bits() {
		let mut features = Bolt11InvoiceFeatures::empty();
		features.set_basic_mpp_optional();
		features.set_payment_secret_required();
		assert!(features.supports_basic_mpp());
		assert!(!features.requires_basic_mpp());
		assert!(features.requires_payment_secret());
		assert!(features.supports_payment_secret());

		// Set flags manually
		let mut features = NodeFeatures::empty();
		assert!(features.set_optional_feature_bit(55).is_ok());
		assert!(features.supports_keysend());
		assert!(features.set_optional_feature_bit(255).is_ok());
		assert!(features.set_required_feature_bit(256).is_err());
	}

	#[test]
	fn set_custom_bits() {
		let mut features = Bolt11InvoiceFeatures::empty();
		features.set_variable_length_onion_optional();
		assert_eq!(features.flags[1], 0b00000010);

		assert!(features.set_optional_custom_bit(255).is_err());
		assert!(features.set_required_custom_bit(256).is_ok());
		assert!(features.set_required_custom_bit(258).is_ok());
		assert_eq!(features.flags[31], 0b00000000);
		assert_eq!(features.flags[32], 0b00000101);

		let known_bit = <sealed::Bolt11InvoiceContext as sealed::PaymentSecret>::EVEN_BIT;
		let byte_offset = <sealed::Bolt11InvoiceContext as sealed::PaymentSecret>::BYTE_OFFSET;
		assert_eq!(byte_offset, 1);
		assert_eq!(features.flags[byte_offset], 0b00000010);
		assert!(features.set_required_custom_bit(known_bit).is_err());
		assert_eq!(features.flags[byte_offset], 0b00000010);

		let mut features = Bolt11InvoiceFeatures::empty();
		assert!(features.set_optional_custom_bit(256).is_ok());
		assert!(features.set_optional_custom_bit(259).is_ok());
		assert_eq!(features.flags[32], 0b00001010);

		let mut features = Bolt11InvoiceFeatures::empty();
		assert!(features.set_required_custom_bit(257).is_ok());
		assert!(features.set_required_custom_bit(258).is_ok());
		assert_eq!(features.flags[32], 0b00000101);
	}

	#[test]
	fn test_channel_type_mapping() {
		// If we map an Bolt11InvoiceFeatures with StaticRemoteKey optional, it should map into a
		// required-StaticRemoteKey ChannelTypeFeatures.
		let mut init_features = InitFeatures::empty();
		init_features.set_static_remote_key_optional();
		let converted_features = ChannelTypeFeatures::from_init(&init_features);
		assert_eq!(converted_features, ChannelTypeFeatures::only_static_remote_key());
		assert!(!converted_features.supports_any_optional_bits());
		assert!(converted_features.requires_static_remote_key());
	}

	#[test]
	fn test_excess_zero_bytes_ignored() {
		// Checks that `Hash` and `PartialEq` ignore excess zero bytes, which may appear due to
		// feature conversion or because a peer serialized their feature poorly.
		use std::collections::hash_map::DefaultHasher;
		use std::hash::{Hash, Hasher};

		let mut zerod_features = InitFeatures::empty();
		zerod_features.flags = FeatureFlags::Heap(vec![0]);
		let empty_features = InitFeatures::empty();
		assert!(empty_features.flags.is_empty());

		assert_eq!(zerod_features, empty_features);

		let mut zerod_hash = DefaultHasher::new();
		zerod_features.hash(&mut zerod_hash);
		let mut empty_hash = DefaultHasher::new();
		empty_features.hash(&mut empty_hash);
		assert_eq!(zerod_hash.finish(), empty_hash.finish());
	}

	#[test]
	fn test_feature_flags_transitions() {
		// Tests transitions from stack to heap and back in `FeatureFlags`
		let mut flags = FeatureFlags::empty();
		assert!(matches!(flags, FeatureFlags::Held { .. }));

		flags.resize(DIRECT_ALLOC_BYTES, 42);
		assert_eq!(flags.len(), DIRECT_ALLOC_BYTES);
		assert!(flags.iter().take(DIRECT_ALLOC_BYTES).all(|b| *b == 42));
		assert!(matches!(flags, FeatureFlags::Held { .. }));

		flags.resize(DIRECT_ALLOC_BYTES * 2, 43);
		assert_eq!(flags.len(), DIRECT_ALLOC_BYTES * 2);
		assert!(flags.iter().take(DIRECT_ALLOC_BYTES).all(|b| *b == 42));
		assert!(flags.iter().skip(DIRECT_ALLOC_BYTES).all(|b| *b == 43));
		assert!(matches!(flags, FeatureFlags::Heap(_)));

		flags.resize(DIRECT_ALLOC_BYTES, 0);
		assert_eq!(flags.len(), DIRECT_ALLOC_BYTES);
		assert!(flags.iter().take(DIRECT_ALLOC_BYTES).all(|b| *b == 42));
		assert!(matches!(flags, FeatureFlags::Held { .. }));
	}
}
