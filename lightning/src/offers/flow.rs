// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Provides data structures and functions for creating and managing Offers messages,
//! facilitating communication, and handling Bolt12 invoice payments.

use bitcoin::secp256k1;
use bitcoin::{key::Secp256k1, PublicKey};

use crate::ln::inbound_payment;
use crate::prelude::*;
use crate::sign::EntropySource;
use core::ops::Deref;

use crate::onion_message::messenger::MessageRouter;
use crate::util::logger::Logger;

#[cfg(not(c_bindings))]
use {
	crate::ln::channelmanager::{SimpleArcChannelManager, SimpleRefChannelManager},
	crate::onion_message::messenger::DefaultMessageRouter,
	crate::routing::gossip::NetworkGraph,
	crate::sign::KeysManager,
	crate::sync::Arc,
};

/// Functions commonly shared in usage between [`ChannelManager`] & [`OffersMessageFlow`]
///
/// [`ChannelManager`]: crate::ln::channelmanager::ChannelManager
pub trait OffersMessageCommons {}

/// [`SimpleArcOffersMessageFlow`] is useful when you need a [`OffersMessageFlow`] with a static lifetime, e.g.
/// when you're using `lightning-net-tokio` (since `tokio::spawn` requires parameters with static
/// lifetimes). Other times you can afford a reference, which is more efficient, in which case
/// [`SimpleRefOffersMessageFlow`] is the more appropriate type. Defining these type aliases prevents
/// issues such as overly long function definitions. Note that the `OffersMessageFlow` can take any type
/// that implements [`EntropySource`], for its keys manager, [`MessageRouter`] for its message router, or
/// [`OffersMessageCommons`] for its shared core functionalities. But this type alias chooses the concrete types
/// of [`KeysManager`] and [`SimpleArcChannelManager`] and [`DefaultMessageRouter`].
///
/// This is not exported to bindings users as type aliases aren't supported in most languages.
#[cfg(not(c_bindings))]
pub type SimpleArcOffersMessageFlow<M, T, F, L> = OffersMessageFlow<
	Arc<KeysManager>,
	Arc<SimpleArcChannelManager<M, T, F, L>>,
	Arc<DefaultMessageRouter<Arc<NetworkGraph<Arc<L>>>, Arc<L>, Arc<KeysManager>>>,
	Arc<L>,
>;

/// [`SimpleRefOffersMessageFlow`] is a type alias for a OffersMessageFlow reference, and is the reference
/// counterpart to the [`SimpleArcOffersMessageFlow`] type alias. Use this type by default when you don't
/// need a OffersMessageFlow with a static lifetime. You'll need a static lifetime in cases such as
/// usage of lightning-net-tokio (since `tokio::spawn` requires parameters with static lifetimes).
/// But if this is not necessary, using a reference is more efficient. Defining these type aliases
/// issues such as overly long function definitions. Note that the `OffersMessageFlow` can take any type
/// that implements [`EntropySource`], for its keys manager, [`MessageRouter`] for its message router, or
/// [`OffersMessageCommons`] for its shared core functionalities. But this type alias chooses the concrete types
/// of [`KeysManager`] and [`SimpleArcChannelManager`] and [`DefaultMessageRouter`].
///
/// This is not exported to bindings users as type aliases aren't supported in most languages.
#[cfg(not(c_bindings))]
pub type SimpleRefOffersMessageFlow<'a, 'b, 'c, 'd, 'e, 'f, 'g, 'h, 'i, 'j, M, T, F, L> =
	OffersMessageFlow<
		&'a KeysManager,
		&'j SimpleRefChannelManager<'a, 'b, 'c, 'd, 'e, 'f, 'g, 'h, 'i, M, T, F, L>,
		&'i DefaultMessageRouter<&'g NetworkGraph<&'b L>, &'b L, &'a KeysManager>,
		&'g L,
	>;

/// A trivial trait which describes any [`OffersMessageFlow`].
///
/// This is not exported to bindings users as general cover traits aren't useful in other
/// languages.
pub trait AnOffersMessageFlow {
	/// A type implementing [`EntropySource`].
	type EntropySource: EntropySource + ?Sized;
	/// A type that may be dereferenced to [`Self::EntropySource`].
	type ES: Deref<Target = Self::EntropySource>;

	/// A type implementing [`OffersMessageCommons`].
	type OffersMessageCommons: OffersMessageCommons + ?Sized;
	/// A type that may be dereferenced to [`Self::OffersMessageCommons`].
	type OMC: Deref<Target = Self::OffersMessageCommons>;

	/// A type implementing [`MessageRouter`].
	type MessageRouter: MessageRouter + ?Sized;
	/// A type that may be dereferenced to [`Self::MessageRouter`].
	type MR: Deref<Target = Self::MessageRouter>;

	/// A type implementing [`Logger`].
	type Logger: Logger + ?Sized;
	/// A type that may be dereferenced to [`Self::Logger`].
	type L: Deref<Target = Self::Logger>;

	/// Returns a reference to the actual [`OffersMessageFlow`] object.
	fn get_omf(&self) -> &OffersMessageFlow<Self::ES, Self::OMC, Self::MR, Self::L>;
}

impl<ES: Deref, OMC: Deref, MR: Deref, L: Deref> AnOffersMessageFlow
	for OffersMessageFlow<ES, OMC, MR, L>
where
	ES::Target: EntropySource,
	OMC::Target: OffersMessageCommons,
	MR::Target: MessageRouter,
	L::Target: Logger,
{
	type EntropySource = ES::Target;
	type ES = ES;

	type OffersMessageCommons = OMC::Target;
	type OMC = OMC;

	type MessageRouter = MR::Target;
	type MR = MR;

	type Logger = L::Target;
	type L = L;

	fn get_omf(&self) -> &OffersMessageFlow<ES, OMC, MR, L> {
		self
	}
}

/// Facilitates the handling, communication, and management of Offers messages within a Lightning
/// node, enabling the creation, verification, and resolution of BOLT 12 invoices and related
/// payment flows.
///
/// The `OffersMessageFlow` struct integrates several components to manage the lifecycle of Offers
/// messages, ensuring robust communication and payment handling:
/// - EntropySource to provide cryptographic randomness essential for Offers message handling.
/// - [`Logger`] for detailed operational logging of Offers-related activity.
/// - OffersMessageCommons for core operations shared across Offers messages, such as metadata
///   verification and signature handling.
/// - MessageRouter for routing Offers messages to their appropriate destinations within the
///   Lightning network.
/// - Manages OffersMessage for creating and processing Offers-related messages.
/// - Handles [`DNSResolverMessage`] for resolving human-readable names in Offers messages
///   (when the `dnssec` feature is enabled).
///
/// Key Features:
/// - Supports creating BOLT 12 Offers, invoice requests, and refunds.
/// - Integrates with the Lightning node's broader message and payment infrastructure.
/// - Handles cryptographic operations and message validation to ensure compliance with BOLT 12.
/// - Supports DNS resolution for human-readable names (when enabled with `dnssec` feature).
///
/// This struct is essential for enabling BOLT12 payment workflows in the Lightning network,
/// providing the foundational mechanisms for Offers and related message exchanges.
///
/// [`DNSResolverMessage`]: crate::onion_message::dns_resolution::DNSResolverMessage
pub struct OffersMessageFlow<ES: Deref, OMC: Deref, MR: Deref, L: Deref>
where
	ES::Target: EntropySource,
	OMC::Target: OffersMessageCommons,
	MR::Target: MessageRouter,
	L::Target: Logger,
{
	secp_ctx: Secp256k1<secp256k1::All>,
	our_network_pubkey: PublicKey,
	inbound_payment_key: inbound_payment::ExpandedKey,

	/// Contains functions shared between OffersMessageHandler and ChannelManager.
	commons: OMC,

	message_router: MR,
	entropy_source: ES,

	/// The Logger for use in the OffersMessageFlow and which may be used to log
	/// information during deserialization.
	pub logger: L,
}

impl<ES: Deref, OMC: Deref, MR: Deref, L: Deref> OffersMessageFlow<ES, OMC, MR, L>
where
	ES::Target: EntropySource,
	OMC::Target: OffersMessageCommons,
	MR::Target: MessageRouter,
	L::Target: Logger,
{
	/// Creates a new [`OffersMessageFlow`]
	pub fn new(
		expanded_inbound_key: inbound_payment::ExpandedKey, our_network_pubkey: PublicKey,
		entropy_source: ES, commons: OMC, message_router: MR, logger: L,
	) -> Self {
		let mut secp_ctx = Secp256k1::new();
		secp_ctx.seeded_randomize(&entropy_source.get_secure_random_bytes());

		Self {
			secp_ctx,
			our_network_pubkey,
			inbound_payment_key: expanded_inbound_key,

			commons,

			message_router,
			entropy_source,

			logger,
		}
	}

	/// Gets the node_id held by this OffersMessageFlow
	pub fn get_our_node_id(&self) -> PublicKey {
		self.our_network_pubkey
	}
}
