// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Provides data structures and functions for creating and managing Offers messages,
//! facilitating communication, and handling BOLT12 messages and payments.

use core::ops::Deref;
use core::sync::atomic::{AtomicUsize, Ordering};
use core::time::Duration;

use crate::blinded_path::message::{
	BlindedMessagePath, MessageContext, MessageForwardNode, OffersContext,
};
use crate::blinded_path::payment::{
	BlindedPaymentPath, PaymentConstraints, PaymentContext, UnauthenticatedReceiveTlvs,
};
use crate::chain::channelmonitor::LATENCY_GRACE_PERIOD_BLOCKS;

#[allow(unused_imports)]
use crate::prelude::*;

use crate::chain::BestBlock;
use crate::ln::channel_state::ChannelDetails;
use crate::ln::channelmanager::{CLTV_FAR_FAR_AWAY, MAX_SHORT_LIVED_RELATIVE_EXPIRY};
use crate::ln::inbound_payment;
use crate::offers::nonce::Nonce;
use crate::onion_message::async_payments::AsyncPaymentsMessage;
use crate::onion_message::messenger::{MessageRouter, MessageSendInstructions};
use crate::onion_message::offers::OffersMessage;
use crate::routing::router::Router;
use crate::sign::EntropySource;
use crate::sync::{Mutex, RwLock};
use bitcoin::block::Header;
use bitcoin::constants::ChainHash;
use bitcoin::secp256k1::{self, PublicKey, Secp256k1};
use lightning_invoice::PaymentSecret;

#[cfg(feature = "dnssec")]
use crate::onion_message::dns_resolution::{DNSResolverMessage, OMNameResolver};

/// A BOLT12 offers code and flow utility provider, which facilitates
/// BOLT12 builder generation and onion message handling.
///
/// [`OffersMessageFlow`] is parameterized by a [`MessageRouter`], which is responsible
/// for finding message paths when initiating and retrying onion messages.
pub struct OffersMessageFlow<MR: Deref>
where
	MR::Target: MessageRouter,
{
	chain_hash: ChainHash,
	best_block: RwLock<BestBlock>,

	our_network_pubkey: PublicKey,
	highest_seen_timestamp: AtomicUsize,
	inbound_payment_key: inbound_payment::ExpandedKey,

	secp_ctx: Secp256k1<secp256k1::All>,
	message_router: MR,

	#[cfg(not(any(test, feature = "_test_utils")))]
	pending_offers_messages: Mutex<Vec<(OffersMessage, MessageSendInstructions)>>,
	#[cfg(any(test, feature = "_test_utils"))]
	pub(crate) pending_offers_messages: Mutex<Vec<(OffersMessage, MessageSendInstructions)>>,

	pending_async_payments_messages: Mutex<Vec<(AsyncPaymentsMessage, MessageSendInstructions)>>,

	#[cfg(feature = "dnssec")]
	pub(crate) hrn_resolver: OMNameResolver,
	#[cfg(feature = "dnssec")]
	pending_dns_onion_messages: Mutex<Vec<(DNSResolverMessage, MessageSendInstructions)>>,
}

impl<MR: Deref> OffersMessageFlow<MR>
where
	MR::Target: MessageRouter,
{
	/// Creates a new [`OffersMessageFlow`]
	pub fn new(
		chain_hash: ChainHash, best_block: BestBlock, our_network_pubkey: PublicKey,
		current_timestamp: u32, inbound_payment_key: inbound_payment::ExpandedKey,
		secp_ctx: Secp256k1<secp256k1::All>, message_router: MR,
	) -> Self {
		Self {
			chain_hash,
			best_block: RwLock::new(best_block),

			our_network_pubkey,
			highest_seen_timestamp: AtomicUsize::new(current_timestamp as usize),
			inbound_payment_key,

			secp_ctx,
			message_router,

			pending_offers_messages: Mutex::new(Vec::new()),
			pending_async_payments_messages: Mutex::new(Vec::new()),

			#[cfg(feature = "dnssec")]
			hrn_resolver: OMNameResolver::new(current_timestamp, best_block.height),
			#[cfg(feature = "dnssec")]
			pending_dns_onion_messages: Mutex::new(Vec::new()),
		}
	}

	/// Gets the node_id held by this [`OffersMessageFlow`]`
	fn get_our_node_id(&self) -> PublicKey {
		self.our_network_pubkey
	}

	fn duration_since_epoch(&self) -> Duration {
		#[cfg(not(feature = "std"))]
		let now = Duration::from_secs(self.highest_seen_timestamp.load(Ordering::Acquire) as u64);
		#[cfg(feature = "std")]
		let now = std::time::SystemTime::now()
			.duration_since(std::time::SystemTime::UNIX_EPOCH)
			.expect("SystemTime::now() should come after SystemTime::UNIX_EPOCH");
		now
	}

	/// Notifies the [`OffersMessageFlow`] that a new block has been observed.
	///
	/// This allows the flow to keep in sync with the latest block timestamp,
	/// which may be used for time-sensitive operations.
	///
	/// Must be called whenever a new chain tip becomes available. May be skipped
	/// for intermediary blocks.
	pub fn best_block_updated(&self, header: &Header, _height: u32) {
		let timestamp = &self.highest_seen_timestamp;
		let block_time = header.time as usize;

		loop {
			// Update timestamp to be the max of its current value and the block
			// timestamp. This should keep us close to the current time without relying on
			// having an explicit local time source.
			// Just in case we end up in a race, we loop until we either successfully
			// update timestamp or decide we don't need to.
			let old_serial = timestamp.load(Ordering::Acquire);
			if old_serial >= block_time {
				break;
			}
			if timestamp
				.compare_exchange(old_serial, block_time, Ordering::AcqRel, Ordering::Relaxed)
				.is_ok()
			{
				break;
			}
		}

		#[cfg(feature = "dnssec")]
		{
			let updated_time = timestamp.load(Ordering::Acquire) as u32;
			self.hrn_resolver.new_best_block(_height, updated_time);
		}
	}
}

impl<MR: Deref> OffersMessageFlow<MR>
where
	MR::Target: MessageRouter,
{
	/// Creates a collection of blinded paths by delegating to [`MessageRouter`] based on
	/// the path's intended lifetime.
	///
	/// Whether or not the path is compact depends on whether the path is short-lived or long-lived,
	/// respectively, based on the given `absolute_expiry` as seconds since the Unix epoch. See
	/// [`MAX_SHORT_LIVED_RELATIVE_EXPIRY`].
	fn create_blinded_paths_using_absolute_expiry(
		&self, context: OffersContext, absolute_expiry: Option<Duration>,
		peers: Vec<MessageForwardNode>,
	) -> Result<Vec<BlindedMessagePath>, ()> {
		let now = self.duration_since_epoch();
		let max_short_lived_absolute_expiry = now.saturating_add(MAX_SHORT_LIVED_RELATIVE_EXPIRY);

		if absolute_expiry.unwrap_or(Duration::MAX) <= max_short_lived_absolute_expiry {
			self.create_compact_blinded_paths(peers, context)
		} else {
			self.create_blinded_paths(peers, MessageContext::Offers(context))
		}
	}

	/// Creates a collection of blinded paths by delegating to
	/// [`MessageRouter::create_blinded_paths`].
	///
	/// Errors if the `MessageRouter` errors.
	fn create_blinded_paths(
		&self, peers: Vec<MessageForwardNode>, context: MessageContext,
	) -> Result<Vec<BlindedMessagePath>, ()> {
		let recipient = self.get_our_node_id();
		let secp_ctx = &self.secp_ctx;

		let peers = peers.into_iter().map(|node| node.node_id).collect();
		self.message_router
			.create_blinded_paths(recipient, context, peers, secp_ctx)
			.and_then(|paths| (!paths.is_empty()).then(|| paths).ok_or(()))
	}

	/// Creates a collection of blinded paths by delegating to
	/// [`MessageRouter::create_compact_blinded_paths`].
	///
	/// Errors if the `MessageRouter` errors.
	fn create_compact_blinded_paths(
		&self, peers: Vec<MessageForwardNode>, context: OffersContext,
	) -> Result<Vec<BlindedMessagePath>, ()> {
		let recipient = self.get_our_node_id();
		let secp_ctx = &self.secp_ctx;

		self.message_router
			.create_compact_blinded_paths(
				recipient,
				MessageContext::Offers(context),
				peers,
				secp_ctx,
			)
			.and_then(|paths| (!paths.is_empty()).then(|| paths).ok_or(()))
	}

	/// Creates multi-hop blinded payment paths for the given `amount_msats` by delegating to
	/// [`Router::create_blinded_payment_paths`].
	fn create_blinded_payment_paths<ES: Deref, R: Deref>(
		&self, router: &R, entropy_source: ES, usable_channels: Vec<ChannelDetails>,
		amount_msats: Option<u64>, payment_secret: PaymentSecret, payment_context: PaymentContext,
		relative_expiry_seconds: u32,
	) -> Result<Vec<BlindedPaymentPath>, ()>
	where
		ES::Target: EntropySource,
		R::Target: Router,
	{
		let expanded_key = &self.inbound_payment_key;
		let entropy = &*entropy_source;
		let secp_ctx = &self.secp_ctx;

		let payee_node_id = self.get_our_node_id();

		// Assume shorter than usual block times to avoid spuriously failing payments too early.
		const SECONDS_PER_BLOCK: u32 = 9 * 60;
		let relative_expiry_blocks = relative_expiry_seconds / SECONDS_PER_BLOCK;
		let max_cltv_expiry = core::cmp::max(relative_expiry_blocks, CLTV_FAR_FAR_AWAY)
			.saturating_add(LATENCY_GRACE_PERIOD_BLOCKS)
			.saturating_add(self.best_block.read().unwrap().height);

		let payee_tlvs = UnauthenticatedReceiveTlvs {
			payment_secret,
			payment_constraints: PaymentConstraints { max_cltv_expiry, htlc_minimum_msat: 1 },
			payment_context,
		};
		let nonce = Nonce::from_entropy_source(entropy);
		let payee_tlvs = payee_tlvs.authenticate(nonce, expanded_key);

		router.create_blinded_payment_paths(
			payee_node_id,
			usable_channels,
			payee_tlvs,
			amount_msats,
			secp_ctx,
		)
	}

	#[cfg(all(test, async_payments))]
	/// Creates multi-hop blinded payment paths for the given `amount_msats` by delegating to
	/// [`Router::create_blinded_payment_paths`].
	pub(crate) fn test_create_blinded_payment_paths<ES: Deref, R: Deref>(
		&self, router: &R, entropy_source: ES, usable_channels: Vec<ChannelDetails>,
		amount_msats: Option<u64>, payment_secret: PaymentSecret, payment_context: PaymentContext,
		relative_expiry_seconds: u32,
	) -> Result<Vec<BlindedPaymentPath>, ()>
	where
		ES::Target: EntropySource,
		R::Target: Router,
	{
		self.create_blinded_payment_paths(
			router,
			entropy_source,
			usable_channels,
			amount_msats,
			payment_secret,
			payment_context,
			relative_expiry_seconds,
		)
	}
}
