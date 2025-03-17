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

use bitcoin::block::Header;
use bitcoin::constants::ChainHash;
use bitcoin::secp256k1::{self, PublicKey, Secp256k1};

#[allow(unused_imports)]
use crate::prelude::*;

use crate::chain::BestBlock;
use crate::ln::inbound_payment;
use crate::onion_message::async_payments::AsyncPaymentsMessage;
use crate::onion_message::messenger::{MessageRouter, MessageSendInstructions};
use crate::onion_message::offers::OffersMessage;
use crate::sync::{Mutex, RwLock};

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
