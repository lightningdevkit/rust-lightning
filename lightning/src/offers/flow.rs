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

use crate::blinded_path::message::{
	AsyncPaymentsContext, BlindedMessagePath, MessageContext, MessageForwardNode, OffersContext,
};
use crate::blinded_path::payment::{
	AsyncBolt12OfferContext, BlindedPaymentPath, Bolt12OfferContext, Bolt12RefundContext,
	PaymentConstraints, PaymentContext, UnauthenticatedReceiveTlvs,
};
use crate::chain::channelmonitor::LATENCY_GRACE_PERIOD_BLOCKS;

#[allow(unused_imports)]
use crate::prelude::*;

use crate::chain::BestBlock;
use crate::ln::channel_state::ChannelDetails;
use crate::ln::channelmanager::{InterceptId, PaymentId, CLTV_FAR_FAR_AWAY};
use crate::ln::inbound_payment;
use crate::offers::async_receive_offer_cache::AsyncReceiveOfferCache;
use crate::offers::invoice::{
	Bolt12Invoice, DerivedSigningPubkey, ExplicitSigningPubkey, InvoiceBuilder,
	UnsignedBolt12Invoice, DEFAULT_RELATIVE_EXPIRY,
};
use crate::offers::invoice_error::InvoiceError;
use crate::offers::invoice_request::{
	InvoiceRequest, InvoiceRequestBuilder, VerifiedInvoiceRequest,
};
use crate::offers::nonce::Nonce;
use crate::offers::offer::{Amount, DerivedMetadata, Offer, OfferBuilder};
use crate::offers::parse::Bolt12SemanticError;
use crate::offers::refund::{Refund, RefundBuilder};
use crate::onion_message::async_payments::{
	AsyncPaymentsMessage, HeldHtlcAvailable, OfferPaths, OfferPathsRequest, ServeStaticInvoice,
	StaticInvoicePersisted,
};
use crate::onion_message::messenger::{
	Destination, MessageRouter, MessageSendInstructions, Responder, PADDED_PATH_LENGTH,
};
use crate::onion_message::offers::OffersMessage;
use crate::onion_message::packet::OnionMessageContents;
use crate::routing::router::Router;
use crate::sign::{EntropySource, NodeSigner, ReceiveAuthKey};

use crate::offers::static_invoice::{StaticInvoice, StaticInvoiceBuilder};
use crate::sync::{Mutex, RwLock};
use crate::types::payment::{PaymentHash, PaymentSecret};
use crate::util::logger::Logger;
use crate::util::ser::Writeable;

#[cfg(feature = "dnssec")]
use {
	crate::blinded_path::message::DNSResolverContext,
	crate::onion_message::dns_resolution::{DNSResolverMessage, DNSSECQuery, OMNameResolver},
};

/// A BOLT12 offers code and flow utility provider, which facilitates
/// BOLT12 builder generation and onion message handling.
///
/// [`OffersMessageFlow`] is parameterized by a [`MessageRouter`], which is responsible
/// for finding message paths when initiating and retrying onion messages.
pub struct OffersMessageFlow<MR: Deref, L: Deref>
where
	MR::Target: MessageRouter,
	L::Target: Logger,
{
	chain_hash: ChainHash,
	best_block: RwLock<BestBlock>,

	our_network_pubkey: PublicKey,
	highest_seen_timestamp: AtomicUsize,
	inbound_payment_key: inbound_payment::ExpandedKey,

	receive_auth_key: ReceiveAuthKey,

	secp_ctx: Secp256k1<secp256k1::All>,
	message_router: MR,

	#[cfg(not(any(test, feature = "_test_utils")))]
	pending_offers_messages: Mutex<Vec<(OffersMessage, MessageSendInstructions)>>,
	#[cfg(any(test, feature = "_test_utils"))]
	pub(crate) pending_offers_messages: Mutex<Vec<(OffersMessage, MessageSendInstructions)>>,

	pending_async_payments_messages: Mutex<Vec<(AsyncPaymentsMessage, MessageSendInstructions)>>,
	async_receive_offer_cache: Mutex<AsyncReceiveOfferCache>,

	#[cfg(feature = "dnssec")]
	pub(crate) hrn_resolver: OMNameResolver,
	#[cfg(feature = "dnssec")]
	pending_dns_onion_messages: Mutex<Vec<(DNSResolverMessage, MessageSendInstructions)>>,

	logger: L,
}

impl<MR: Deref, L: Deref> OffersMessageFlow<MR, L>
where
	MR::Target: MessageRouter,
	L::Target: Logger,
{
	/// Creates a new [`OffersMessageFlow`]
	pub fn new(
		chain_hash: ChainHash, best_block: BestBlock, our_network_pubkey: PublicKey,
		current_timestamp: u32, inbound_payment_key: inbound_payment::ExpandedKey,
		receive_auth_key: ReceiveAuthKey, secp_ctx: Secp256k1<secp256k1::All>, message_router: MR,
		logger: L,
	) -> Self {
		Self {
			chain_hash,
			best_block: RwLock::new(best_block),

			our_network_pubkey,
			highest_seen_timestamp: AtomicUsize::new(current_timestamp as usize),
			inbound_payment_key,

			receive_auth_key,

			secp_ctx,
			message_router,

			pending_offers_messages: Mutex::new(Vec::new()),
			pending_async_payments_messages: Mutex::new(Vec::new()),

			#[cfg(feature = "dnssec")]
			hrn_resolver: OMNameResolver::new(current_timestamp, best_block.height),
			#[cfg(feature = "dnssec")]
			pending_dns_onion_messages: Mutex::new(Vec::new()),

			async_receive_offer_cache: Mutex::new(AsyncReceiveOfferCache::new()),

			logger,
		}
	}

	/// If we are an async recipient, on startup we'll interactively build offers and static invoices
	/// with an always-online node that will serve static invoices on our behalf. Once the offer is
	/// built and the static invoice is confirmed as persisted by the server, the underlying
	/// [`AsyncReceiveOfferCache`] should be persisted using
	/// [`Self::writeable_async_receive_offer_cache`] so we remember the offers we've built.
	pub fn with_async_payments_offers_cache(
		mut self, async_receive_offer_cache: AsyncReceiveOfferCache,
	) -> Self {
		self.async_receive_offer_cache = Mutex::new(async_receive_offer_cache);
		self
	}

	/// Sets the [`BlindedMessagePath`]s that we will use as an async recipient to interactively build
	/// [`Offer`]s with a static invoice server, so the server can serve [`StaticInvoice`]s to payers
	/// on our behalf when we're offline.
	///
	/// This method will also send out messages initiating async offer creation to the static invoice
	/// server, if any peers are connected.
	///
	/// This method only needs to be called once when the server first takes on the recipient as a
	/// client, or when the paths change, e.g. if the paths are set to expire at a particular time.
	pub fn set_paths_to_static_invoice_server(
		&self, paths_to_static_invoice_server: Vec<BlindedMessagePath>,
		peers: Vec<MessageForwardNode>,
	) -> Result<(), ()> {
		let mut cache = self.async_receive_offer_cache.lock().unwrap();
		cache.set_paths_to_static_invoice_server(paths_to_static_invoice_server.clone())?;
		core::mem::drop(cache);

		// We'll only fail here if no peers are connected yet for us to create reply paths to outbound
		// offer_paths_requests, so ignore the error.
		let _ = self.check_refresh_async_offers(peers, false);

		Ok(())
	}

	/// Gets the node_id held by this [`OffersMessageFlow`]`
	fn get_our_node_id(&self) -> PublicKey {
		self.our_network_pubkey
	}

	fn get_receive_auth_key(&self) -> ReceiveAuthKey {
		self.receive_auth_key
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

/// The maximum size of a received [`StaticInvoice`] before we'll fail verification in
/// [`OffersMessageFlow::verify_serve_static_invoice_message].
pub const MAX_STATIC_INVOICE_SIZE_BYTES: usize = 5 * 1024;

/// Defines the maximum number of [`OffersMessage`] including different reply paths to be sent
/// along different paths.
/// Sending multiple requests increases the chances of successful delivery in case some
/// paths are unavailable. However, only one invoice for a given [`PaymentId`] will be paid,
/// even if multiple invoices are received.
const OFFERS_MESSAGE_REQUEST_LIMIT: usize = 10;

#[cfg(test)]
pub(crate) const TEST_OFFERS_MESSAGE_REQUEST_LIMIT: usize = OFFERS_MESSAGE_REQUEST_LIMIT;

/// The default relative expiry for reply paths where a quick response is expected and the reply
/// path is single-use.
const TEMP_REPLY_PATH_RELATIVE_EXPIRY: Duration = Duration::from_secs(2 * 60 * 60);

#[cfg(test)]
pub(crate) const TEST_TEMP_REPLY_PATH_RELATIVE_EXPIRY: Duration = TEMP_REPLY_PATH_RELATIVE_EXPIRY;

// Default to async receive offers and the paths used to update them lasting one year.
const DEFAULT_ASYNC_RECEIVE_OFFER_EXPIRY: Duration = Duration::from_secs(365 * 24 * 60 * 60);

#[cfg(test)]
pub(crate) const TEST_DEFAULT_ASYNC_RECEIVE_OFFER_EXPIRY: Duration =
	DEFAULT_ASYNC_RECEIVE_OFFER_EXPIRY;

impl<MR: Deref, L: Deref> OffersMessageFlow<MR, L>
where
	MR::Target: MessageRouter,
	L::Target: Logger,
{
	/// [`BlindedMessagePath`]s for an async recipient to communicate with this node and interactively
	/// build [`Offer`]s and [`StaticInvoice`]s for receiving async payments.
	///
	/// If `relative_expiry` is unset, the [`BlindedMessagePath`]s will never expire.
	///
	/// Returns the paths that the recipient should be configured with via
	/// [`Self::set_paths_to_static_invoice_server`].
	///
	/// Errors if blinded path creation fails or the provided `recipient_id` is larger than 1KiB.
	pub fn blinded_paths_for_async_recipient(
		&self, recipient_id: Vec<u8>, relative_expiry: Option<Duration>,
		peers: Vec<MessageForwardNode>,
	) -> Result<Vec<BlindedMessagePath>, ()> {
		if recipient_id.len() > 1024 {
			log_trace!(self.logger, "Async recipient ID exceeds 1024 bytes");
			return Err(());
		}

		let path_absolute_expiry =
			relative_expiry.map(|exp| exp.saturating_add(self.duration_since_epoch()));

		let context = MessageContext::AsyncPayments(AsyncPaymentsContext::OfferPathsRequest {
			recipient_id,
			path_absolute_expiry,
		});
		self.create_blinded_paths(peers, context)
	}

	/// Creates a collection of blinded paths by delegating to
	/// [`MessageRouter::create_blinded_paths`].
	///
	/// Errors if the `MessageRouter` errors.
	fn create_blinded_paths(
		&self, peers: Vec<MessageForwardNode>, context: MessageContext,
	) -> Result<Vec<BlindedMessagePath>, ()> {
		let recipient = self.get_our_node_id();
		let receive_key = self.get_receive_auth_key();
		let secp_ctx = &self.secp_ctx;

		self.message_router
			.create_blinded_paths(recipient, receive_key, context, peers, secp_ctx)
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

	#[cfg(test)]
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

fn enqueue_onion_message_with_reply_paths<T: OnionMessageContents + Clone>(
	message: T, message_paths: &[BlindedMessagePath], reply_paths: Vec<BlindedMessagePath>,
	queue: &mut Vec<(T, MessageSendInstructions)>,
) {
	reply_paths
		.iter()
		.flat_map(|reply_path| message_paths.iter().map(move |path| (path, reply_path)))
		.take(OFFERS_MESSAGE_REQUEST_LIMIT)
		.for_each(|(path, reply_path)| {
			let instructions = MessageSendInstructions::WithSpecifiedReplyPath {
				destination: Destination::BlindedPath(path.clone()),
				reply_path: reply_path.clone(),
			};
			queue.push((message.clone(), instructions));
		});
}

/// Instructions for how to respond to an `InvoiceRequest`.
pub enum InvreqResponseInstructions {
	/// We are the recipient of this payment, and a [`Bolt12Invoice`] should be sent in response to
	/// the invoice request since it is now verified.
	SendInvoice(VerifiedInvoiceRequest),
	/// We are a static invoice server and should respond to this invoice request by retrieving the
	/// [`StaticInvoice`] corresponding to the `recipient_id` and `invoice_slot` and calling
	/// `OffersMessageFlow::enqueue_static_invoice`.
	///
	/// [`StaticInvoice`]: crate::offers::static_invoice::StaticInvoice
	SendStaticInvoice {
		/// An identifier for the async recipient for whom we are serving [`StaticInvoice`]s.
		///
		/// [`StaticInvoice`]: crate::offers::static_invoice::StaticInvoice
		recipient_id: Vec<u8>,
		/// The slot number for the specific invoice being requested by the payer.
		invoice_slot: u16,
	},
}

impl<MR: Deref, L: Deref> OffersMessageFlow<MR, L>
where
	MR::Target: MessageRouter,
	L::Target: Logger,
{
	/// Verifies an [`InvoiceRequest`] using the provided [`OffersContext`] or the [`InvoiceRequest::metadata`].
	///
	/// - If an [`OffersContext::InvoiceRequest`] with a `nonce` is provided, verification is performed using recipient context data.
	/// - If no context is provided but the [`InvoiceRequest`] contains [`Offer`] metadata, verification is performed using that metadata.
	/// - If neither is available, verification fails.
	///
	/// # Errors
	///
	/// Returns an error if:
	/// - Both [`OffersContext`] and [`InvoiceRequest`] metadata are absent or invalid.
	/// - The verification process (via recipient context data or metadata) fails.
	pub fn verify_invoice_request(
		&self, invoice_request: InvoiceRequest, context: Option<OffersContext>,
	) -> Result<InvreqResponseInstructions, ()> {
		let secp_ctx = &self.secp_ctx;
		let expanded_key = &self.inbound_payment_key;

		let nonce = match context {
			None if invoice_request.metadata().is_some() => None,
			Some(OffersContext::InvoiceRequest { nonce }) => Some(nonce),
			Some(OffersContext::StaticInvoiceRequested {
				recipient_id,
				invoice_slot,
				path_absolute_expiry,
			}) => {
				if path_absolute_expiry < self.duration_since_epoch() {
					log_trace!(self.logger, "Static invoice request has expired");
					return Err(());
				}

				return Ok(InvreqResponseInstructions::SendStaticInvoice {
					recipient_id,
					invoice_slot,
				});
			},
			_ => return Err(()),
		};

		let invoice_request = match nonce {
			Some(nonce) => {
				invoice_request.verify_using_recipient_data(nonce, expanded_key, secp_ctx)
			},
			None => invoice_request.verify_using_metadata(expanded_key, secp_ctx),
		}?;

		Ok(InvreqResponseInstructions::SendInvoice(invoice_request))
	}

	/// Verifies a [`Bolt12Invoice`] using the provided [`OffersContext`] or the invoice's payer metadata,
	/// returning the corresponding [`PaymentId`] if successful.
	///
	/// - If an [`OffersContext::OutboundPayment`] with a `nonce` is provided, verification is performed
	///   using this to form the payer metadata.
	/// - If no context is provided and the invoice corresponds to a [`Refund`] without blinded paths,
	///   verification is performed using the [`Bolt12Invoice::payer_metadata`].
	/// - If neither condition is met, verification fails.
	pub fn verify_bolt12_invoice(
		&self, invoice: &Bolt12Invoice, context: Option<&OffersContext>,
	) -> Result<PaymentId, ()> {
		let secp_ctx = &self.secp_ctx;
		let expanded_key = &self.inbound_payment_key;

		match context {
			None if invoice.is_for_refund_without_paths() => {
				invoice.verify_using_metadata(expanded_key, secp_ctx)
			},
			Some(&OffersContext::OutboundPayment { payment_id, nonce, .. }) => {
				invoice.verify_using_payer_data(payment_id, nonce, expanded_key, secp_ctx)
			},
			_ => Err(()),
		}
	}

	/// Verifies the provided [`AsyncPaymentsContext`] for an inbound [`HeldHtlcAvailable`] message.
	///
	/// Because blinded path contexts are verified as a part of onion message processing, this only
	/// validates that the context is not yet expired based on `path_absolute_expiry`.
	///
	/// # Errors
	///
	/// Returns `Err(())` if:
	/// - The inbound payment context has expired.
	pub fn verify_inbound_async_payment_context(
		&self, context: AsyncPaymentsContext,
	) -> Result<(), ()> {
		match context {
			AsyncPaymentsContext::InboundPayment { path_absolute_expiry } => {
				if self.duration_since_epoch() > path_absolute_expiry {
					return Err(());
				}
				Ok(())
			},
			_ => Err(()),
		}
	}

	fn create_offer_builder_intern<ES: Deref, PF, I>(
		&self, entropy_source: ES, make_paths: PF,
	) -> Result<(OfferBuilder<'_, DerivedMetadata, secp256k1::All>, Nonce), Bolt12SemanticError>
	where
		ES::Target: EntropySource,
		PF: FnOnce(
			PublicKey,
			MessageContext,
			&secp256k1::Secp256k1<secp256k1::All>,
		) -> Result<I, Bolt12SemanticError>,
		I: IntoIterator<Item = BlindedMessagePath>,
	{
		let node_id = self.get_our_node_id();
		let expanded_key = &self.inbound_payment_key;
		let entropy = entropy_source;
		let secp_ctx = &self.secp_ctx;

		let nonce = Nonce::from_entropy_source(entropy);
		let context = MessageContext::Offers(OffersContext::InvoiceRequest { nonce });

		let mut builder =
			OfferBuilder::deriving_signing_pubkey(node_id, expanded_key, nonce, secp_ctx)
				.chain_hash(self.chain_hash);

		for path in make_paths(node_id, context, secp_ctx)? {
			builder = builder.path(path)
		}

		Ok((builder.into(), nonce))
	}

	/// Creates an [`OfferBuilder`] such that the [`Offer`] it builds is recognized by the
	/// [`OffersMessageFlow`], and any corresponding [`InvoiceRequest`] can be verified using
	/// [`Self::verify_invoice_request`]. The offer will expire at `absolute_expiry` if `Some`,
	/// or will not expire if `None`.
	///
	/// # Privacy
	///
	/// Uses [`MessageRouter`] provided at construction to construct a [`BlindedMessagePath`] for
	/// the offer. See the documentation of the selected [`MessageRouter`] for details on how it
	/// selects blinded paths including privacy implications and reliability tradeoffs.
	///
	/// Also uses a derived signing pubkey in the offer for recipient privacy.
	///
	/// # Limitations
	///
	/// If [`DefaultMessageRouter`] is used to parameterize the [`OffersMessageFlow`], a direct
	/// connection to the introduction node in the responding [`InvoiceRequest`]'s reply path is
	/// required. See the [`DefaultMessageRouter`] documentation for more details.
	///
	/// # Errors
	///
	/// Returns an error if the parameterized [`Router`] is unable to create a blinded path for the offer.
	///
	/// [`DefaultMessageRouter`]: crate::onion_message::messenger::DefaultMessageRouter
	pub fn create_offer_builder<ES: Deref>(
		&self, entropy_source: ES, peers: Vec<MessageForwardNode>,
	) -> Result<OfferBuilder<'_, DerivedMetadata, secp256k1::All>, Bolt12SemanticError>
	where
		ES::Target: EntropySource,
	{
		self.create_offer_builder_intern(&*entropy_source, |_, context, _| {
			self.create_blinded_paths(peers, context)
				.map(|paths| paths.into_iter().take(1))
				.map_err(|_| Bolt12SemanticError::MissingPaths)
		})
		.map(|(builder, _)| builder)
	}

	/// Same as [`Self::create_offer_builder`], but allows specifying a custom [`MessageRouter`]
	/// instead of using the one provided via the [`OffersMessageFlow`] parameterization.
	///
	/// This gives users full control over how the [`BlindedMessagePath`] is constructed,
	/// including the option to omit it entirely.
	///
	/// See [`Self::create_offer_builder`] for more details on usage.
	pub fn create_offer_builder_using_router<ME: Deref, ES: Deref>(
		&self, router: ME, entropy_source: ES, peers: Vec<MessageForwardNode>,
	) -> Result<OfferBuilder<'_, DerivedMetadata, secp256k1::All>, Bolt12SemanticError>
	where
		ME::Target: MessageRouter,
		ES::Target: EntropySource,
	{
		let receive_key = self.get_receive_auth_key();
		self.create_offer_builder_intern(&*entropy_source, |node_id, context, secp_ctx| {
			router
				.create_blinded_paths(node_id, receive_key, context, peers, secp_ctx)
				.map(|paths| paths.into_iter().take(1))
				.map_err(|_| Bolt12SemanticError::MissingPaths)
		})
		.map(|(builder, _)| builder)
	}

	/// Create an offer for receiving async payments as an often-offline recipient.
	///
	/// Because we may be offline when the payer attempts to request an invoice, you MUST:
	/// 1. Provide at least 1 [`BlindedMessagePath`] terminating at an always-online node that will
	///    serve the [`StaticInvoice`] created from this offer on our behalf.
	/// 2. Use [`Self::create_static_invoice_builder`] to create a [`StaticInvoice`] from this
	///    [`Offer`] plus the returned [`Nonce`], and provide the static invoice to the
	///    aforementioned always-online node.
	pub fn create_async_receive_offer_builder<ES: Deref>(
		&self, entropy_source: ES, message_paths_to_always_online_node: Vec<BlindedMessagePath>,
	) -> Result<(OfferBuilder<'_, DerivedMetadata, secp256k1::All>, Nonce), Bolt12SemanticError>
	where
		ES::Target: EntropySource,
	{
		self.create_offer_builder_intern(&*entropy_source, |_, _, _| {
			Ok(message_paths_to_always_online_node)
		})
	}

	fn create_refund_builder_intern<ES: Deref, PF, I>(
		&self, entropy_source: ES, make_paths: PF, amount_msats: u64, absolute_expiry: Duration,
		payment_id: PaymentId,
	) -> Result<RefundBuilder<'_, secp256k1::All>, Bolt12SemanticError>
	where
		ES::Target: EntropySource,
		PF: FnOnce(
			PublicKey,
			MessageContext,
			&secp256k1::Secp256k1<secp256k1::All>,
		) -> Result<I, Bolt12SemanticError>,
		I: IntoIterator<Item = BlindedMessagePath>,
	{
		let node_id = self.get_our_node_id();
		let expanded_key = &self.inbound_payment_key;
		let entropy = &*entropy_source;
		let secp_ctx = &self.secp_ctx;

		let nonce = Nonce::from_entropy_source(entropy);
		let context = MessageContext::Offers(OffersContext::OutboundPayment { payment_id, nonce });

		// Create the base builder with common properties
		let mut builder = RefundBuilder::deriving_signing_pubkey(
			node_id,
			expanded_key,
			nonce,
			secp_ctx,
			amount_msats,
			payment_id,
		)?
		.chain_hash(self.chain_hash)
		.absolute_expiry(absolute_expiry);

		for path in make_paths(node_id, context, secp_ctx)? {
			builder = builder.path(path);
		}

		Ok(builder.into())
	}

	/// Creates a [`RefundBuilder`] such that the [`Refund`] it builds is recognized by the
	/// [`OffersMessageFlow`], and any corresponding [`Bolt12Invoice`] received for the refund
	/// can be verified using [`Self::verify_bolt12_invoice`].
	///
	/// # Privacy
	///
	/// Uses [`MessageRouter`] provided at construction to construct a [`BlindedMessagePath`] for
	/// the refund. See the documentation of the selected [`MessageRouter`] for details on how it
	/// selects blinded paths including privacy implications and reliability tradeoffs.
	///
	/// The builder will have the provided expiration set. Any changes to the expiration on the
	/// returned builder will not be honored by [`OffersMessageFlow`]. For non-`std`, the highest seen
	/// block time minus two hours is used for the current time when determining if the refund has
	/// expired.
	///
	/// The refund can be revoked by the user prior to receiving the invoice.
	/// If abandoned, or if an invoice is not received before expiration, the payment will fail
	/// with an [`Event::PaymentFailed`].
	///
	/// If `max_total_routing_fee_msat` is not specified, the default from
	/// [`RouteParameters::from_payment_params_and_value`] is applied.
	///
	/// Also uses a derived payer id in the refund for payer privacy.
	///
	/// # Errors
	///
	/// Returns an error if:
	/// - A duplicate `payment_id` is provided, given the caveats in the aforementioned link.
	/// - `amount_msats` is invalid, or
	/// - The parameterized [`Router`] is unable to create a blinded path for the refund.
	///
	/// [`Event::PaymentFailed`]: crate::events::Event::PaymentFailed
	/// [`RouteParameters::from_payment_params_and_value`]: crate::routing::router::RouteParameters::from_payment_params_and_value
	pub fn create_refund_builder<ES: Deref>(
		&self, entropy_source: ES, amount_msats: u64, absolute_expiry: Duration,
		payment_id: PaymentId, peers: Vec<MessageForwardNode>,
	) -> Result<RefundBuilder<'_, secp256k1::All>, Bolt12SemanticError>
	where
		ES::Target: EntropySource,
	{
		self.create_refund_builder_intern(
			&*entropy_source,
			|_, context, _| {
				self.create_blinded_paths(peers, context)
					.map(|paths| paths.into_iter().take(1))
					.map_err(|_| Bolt12SemanticError::MissingPaths)
			},
			amount_msats,
			absolute_expiry,
			payment_id,
		)
	}

	/// Same as [`Self::create_refund_builder`] but allows specifying a custom [`MessageRouter`]
	/// instead of using the one provided via the [`OffersMessageFlow`] parameterization.
	///
	/// This gives users full control over how the [`BlindedMessagePath`] is constructed,
	/// including the option to omit it entirely.
	///
	/// See [`Self::create_refund_builder`] for more details on usage.
	///
	/// # Errors
	///
	/// In addition to the errors documented in [`Self::create_refund_builder`], this method will
	/// return an error if the provided [`MessageRouter`] fails to construct a valid
	/// [`BlindedMessagePath`] for the refund.
	///
	/// [`Refund`]: crate::offers::refund::Refund
	/// [`BlindedMessagePath`]: crate::blinded_path::message::BlindedMessagePath
	/// [`Bolt12Invoice`]: crate::offers::invoice::Bolt12Invoice
	/// [`Event::PaymentFailed`]: crate::events::Event::PaymentFailed
	/// [`RouteParameters::from_payment_params_and_value`]: crate::routing::router::RouteParameters::from_payment_params_and_value
	pub fn create_refund_builder_using_router<ES: Deref, ME: Deref>(
		&self, router: ME, entropy_source: ES, amount_msats: u64, absolute_expiry: Duration,
		payment_id: PaymentId, peers: Vec<MessageForwardNode>,
	) -> Result<RefundBuilder<'_, secp256k1::All>, Bolt12SemanticError>
	where
		ME::Target: MessageRouter,
		ES::Target: EntropySource,
	{
		let receive_key = self.get_receive_auth_key();
		self.create_refund_builder_intern(
			&*entropy_source,
			|node_id, context, secp_ctx| {
				router
					.create_blinded_paths(node_id, receive_key, context, peers, secp_ctx)
					.map(|paths| paths.into_iter().take(1))
					.map_err(|_| Bolt12SemanticError::MissingPaths)
			},
			amount_msats,
			absolute_expiry,
			payment_id,
		)
	}

	/// Creates an [`InvoiceRequestBuilder`] such that the [`InvoiceRequest`] it builds is recognized
	/// by the [`OffersMessageFlow`], and any corresponding [`Bolt12Invoice`] received in response
	/// can be verified using [`Self::verify_bolt12_invoice`].
	///
	/// # Nonce
	/// The nonce is used to create a unique [`InvoiceRequest::payer_metadata`] for the invoice request.
	/// These will be used to verify the corresponding [`Bolt12Invoice`] when it is received.
	pub fn create_invoice_request_builder<'a>(
		&'a self, offer: &'a Offer, nonce: Nonce, payment_id: PaymentId,
	) -> Result<InvoiceRequestBuilder<'a, 'a, secp256k1::All>, Bolt12SemanticError> {
		let expanded_key = &self.inbound_payment_key;
		let secp_ctx = &self.secp_ctx;

		let builder: InvoiceRequestBuilder<secp256k1::All> =
			offer.request_invoice(expanded_key, nonce, secp_ctx, payment_id)?.into();
		let builder = builder.chain_hash(self.chain_hash)?;

		Ok(builder)
	}

	/// Creates a [`StaticInvoiceBuilder`] from the corresponding [`Offer`] and [`Nonce`] that were
	/// created via [`Self::create_async_receive_offer_builder`].
	pub fn create_static_invoice_builder<'a, ES: Deref, R: Deref>(
		&self, router: &R, entropy_source: ES, offer: &'a Offer, offer_nonce: Nonce,
		payment_secret: PaymentSecret, relative_expiry_secs: u32,
		usable_channels: Vec<ChannelDetails>, peers: Vec<MessageForwardNode>,
	) -> Result<StaticInvoiceBuilder<'a>, Bolt12SemanticError>
	where
		ES::Target: EntropySource,
		R::Target: Router,
	{
		let expanded_key = &self.inbound_payment_key;
		let entropy = &*entropy_source;
		let secp_ctx = &self.secp_ctx;

		let payment_context =
			PaymentContext::AsyncBolt12Offer(AsyncBolt12OfferContext { offer_nonce });

		let amount_msat = offer.amount().and_then(|amount| match amount {
			Amount::Bitcoin { amount_msats } => Some(amount_msats),
			Amount::Currency { .. } => None,
		});

		let created_at = self.duration_since_epoch();

		let payment_paths = self
			.create_blinded_payment_paths(
				router,
				entropy,
				usable_channels,
				amount_msat,
				payment_secret,
				payment_context,
				relative_expiry_secs,
			)
			.map_err(|()| Bolt12SemanticError::MissingPaths)?;

		let path_absolute_expiry = Duration::from_secs(inbound_payment::calculate_absolute_expiry(
			created_at.as_secs(),
			relative_expiry_secs,
		));

		let context = MessageContext::AsyncPayments(AsyncPaymentsContext::InboundPayment {
			path_absolute_expiry,
		});

		let async_receive_message_paths = self
			.create_blinded_paths(peers, context)
			.map_err(|()| Bolt12SemanticError::MissingPaths)?;

		StaticInvoiceBuilder::for_offer_using_derived_keys(
			offer,
			payment_paths,
			async_receive_message_paths,
			created_at,
			expanded_key,
			offer_nonce,
			secp_ctx,
		)
		.map(|inv| inv.allow_mpp().relative_expiry(relative_expiry_secs))
	}

	/// Creates an [`InvoiceBuilder`] using the provided [`Refund`].
	///
	/// This method is used when a node wishes to construct an [`InvoiceBuilder`]
	/// in response to a [`Refund`] request as part of a BOLT 12 flow.
	///
	/// Returns an `InvoiceBuilder` configured with:
	/// - Blinded payment paths created using the parameterized [`Router`], with the provided
	///   `payment_secret` included in the path payloads.
	/// - The given `payment_hash` and `payment_secret`, enabling secure claim verification.
	///
	/// Returns an error if the refund targets a different chain or if no valid
	/// blinded path can be constructed.
	pub fn create_invoice_builder_from_refund<'a, ES: Deref, R: Deref>(
		&'a self, router: &R, entropy_source: ES, refund: &'a Refund, payment_hash: PaymentHash,
		payment_secret: PaymentSecret, usable_channels: Vec<ChannelDetails>,
	) -> Result<InvoiceBuilder<'a, DerivedSigningPubkey>, Bolt12SemanticError>
	where
		ES::Target: EntropySource,
		R::Target: Router,
	{
		if refund.chain() != self.chain_hash {
			return Err(Bolt12SemanticError::UnsupportedChain);
		}

		let expanded_key = &self.inbound_payment_key;
		let entropy = &*entropy_source;

		let amount_msats = refund.amount_msats();
		let relative_expiry = DEFAULT_RELATIVE_EXPIRY.as_secs() as u32;

		let payment_context = PaymentContext::Bolt12Refund(Bolt12RefundContext {});
		let payment_paths = self
			.create_blinded_payment_paths(
				router,
				entropy,
				usable_channels,
				Some(amount_msats),
				payment_secret,
				payment_context,
				relative_expiry,
			)
			.map_err(|_| Bolt12SemanticError::MissingPaths)?;

		#[cfg(feature = "std")]
		let builder = refund.respond_using_derived_keys(
			payment_paths,
			payment_hash,
			expanded_key,
			entropy,
		)?;

		#[cfg(not(feature = "std"))]
		let created_at = Duration::from_secs(self.highest_seen_timestamp.load(Ordering::Acquire) as u64);
		#[cfg(not(feature = "std"))]
		let builder = refund.respond_using_derived_keys_no_std(
			payment_paths,
			payment_hash,
			created_at,
			expanded_key,
			entropy,
		)?;

		Ok(builder.into())
	}

	/// Creates a response for the provided [`VerifiedInvoiceRequest`].
	///
	/// A response can be either an [`OffersMessage::Invoice`] with additional [`MessageContext`],
	/// or an [`OffersMessage::InvoiceError`], depending on the [`InvoiceRequest`].
	///
	/// An [`OffersMessage::InvoiceError`] will be generated if:
	/// - We fail to generate valid payment paths to include in the [`Bolt12Invoice`].
	/// - We fail to generate a valid signed [`Bolt12Invoice`] for the [`InvoiceRequest`].
	pub fn create_response_for_invoice_request<ES: Deref, NS: Deref, R: Deref>(
		&self, signer: &NS, router: &R, entropy_source: ES,
		invoice_request: VerifiedInvoiceRequest, amount_msats: u64, payment_hash: PaymentHash,
		payment_secret: PaymentSecret, usable_channels: Vec<ChannelDetails>,
	) -> (OffersMessage, Option<MessageContext>)
	where
		ES::Target: EntropySource,
		NS::Target: NodeSigner,
		R::Target: Router,
	{
		let entropy = &*entropy_source;
		let secp_ctx = &self.secp_ctx;

		let relative_expiry = DEFAULT_RELATIVE_EXPIRY.as_secs() as u32;

		let context = PaymentContext::Bolt12Offer(Bolt12OfferContext {
			offer_id: invoice_request.offer_id,
			invoice_request: invoice_request.fields(),
		});

		let payment_paths = match self.create_blinded_payment_paths(
			router,
			entropy,
			usable_channels,
			Some(amount_msats),
			payment_secret,
			context,
			relative_expiry,
		) {
			Ok(paths) => paths,
			Err(_) => {
				let error = InvoiceError::from(Bolt12SemanticError::MissingPaths);
				return (OffersMessage::InvoiceError(error.into()), None);
			},
		};

		#[cfg(not(feature = "std"))]
		let created_at = Duration::from_secs(self.highest_seen_timestamp.load(Ordering::Acquire) as u64);

		let response = if invoice_request.keys.is_some() {
			#[cfg(feature = "std")]
			let builder = invoice_request.respond_using_derived_keys(payment_paths, payment_hash);
			#[cfg(not(feature = "std"))]
			let builder = invoice_request.respond_using_derived_keys_no_std(
				payment_paths,
				payment_hash,
				created_at,
			);
			builder
				.map(InvoiceBuilder::<DerivedSigningPubkey>::from)
				.and_then(|builder| builder.allow_mpp().build_and_sign(secp_ctx))
				.map_err(InvoiceError::from)
		} else {
			#[cfg(feature = "std")]
			let builder = invoice_request.respond_with(payment_paths, payment_hash);
			#[cfg(not(feature = "std"))]
			let builder = invoice_request.respond_with_no_std(payment_paths, payment_hash, created_at);
			builder
				.map(InvoiceBuilder::<ExplicitSigningPubkey>::from)
				.and_then(|builder| builder.allow_mpp().build())
				.map_err(InvoiceError::from)
				.and_then(|invoice| {
					#[cfg(c_bindings)]
					let mut invoice = invoice;
					invoice
						.sign(|invoice: &UnsignedBolt12Invoice| signer.sign_bolt12_invoice(invoice))
						.map_err(InvoiceError::from)
				})
		};

		match response {
			Ok(invoice) => {
				let context =
					MessageContext::Offers(OffersContext::InboundPayment { payment_hash });

				(OffersMessage::Invoice(invoice), Some(context))
			},
			Err(error) => (OffersMessage::InvoiceError(error.into()), None),
		}
	}

	/// Enqueues the created [`InvoiceRequest`] to be sent to the counterparty.
	///
	/// # Payment
	///
	/// The provided `payment_id` is used to create a unique [`MessageContext`] for the
	/// blinded paths sent to the counterparty. This allows them to respond with an invoice,
	/// over those blinded paths, which can be verified against the intended outbound payment,
	/// ensuring the invoice corresponds to a payment we actually want to make.
	///
	/// # Nonce
	/// The nonce is used to create a unique [`MessageContext`] for the reply paths.
	/// These will be used to verify the corresponding [`Bolt12Invoice`] when it is received.
	///
	/// Note: The provided [`Nonce`] MUST be the same as the [`Nonce`] used for creating the
	/// [`InvoiceRequest`] to ensure correct verification of the corresponding [`Bolt12Invoice`].
	///
	/// See [`OffersMessageFlow::create_invoice_request_builder`] for more details.
	///
	/// # Peers
	///
	/// The user must provide a list of [`MessageForwardNode`] that will be used to generate
	/// valid reply paths for the counterparty to send back the corresponding [`Bolt12Invoice`]
	/// or [`InvoiceError`].
	///
	/// [`supports_onion_messages`]: crate::types::features::Features::supports_onion_messages
	pub fn enqueue_invoice_request(
		&self, invoice_request: InvoiceRequest, payment_id: PaymentId, nonce: Nonce,
		peers: Vec<MessageForwardNode>,
	) -> Result<(), Bolt12SemanticError> {
		let context = MessageContext::Offers(OffersContext::OutboundPayment { payment_id, nonce });
		let reply_paths = self
			.create_blinded_paths(peers, context)
			.map_err(|_| Bolt12SemanticError::MissingPaths)?;

		let mut pending_offers_messages = self.pending_offers_messages.lock().unwrap();
		if !invoice_request.paths().is_empty() {
			let message = OffersMessage::InvoiceRequest(invoice_request.clone());
			enqueue_onion_message_with_reply_paths(
				message,
				invoice_request.paths(),
				reply_paths,
				&mut pending_offers_messages,
			);
		} else if let Some(node_id) = invoice_request.issuer_signing_pubkey() {
			for reply_path in reply_paths {
				let instructions = MessageSendInstructions::WithSpecifiedReplyPath {
					destination: Destination::Node(node_id),
					reply_path,
				};
				let message = OffersMessage::InvoiceRequest(invoice_request.clone());
				pending_offers_messages.push((message, instructions));
			}
		} else {
			debug_assert!(false);
			return Err(Bolt12SemanticError::MissingIssuerSigningPubkey);
		}

		Ok(())
	}

	/// Enqueues the created [`Bolt12Invoice`] corresponding to a [`Refund`] to be sent
	/// to the counterparty.
	///
	/// # Peers
	///
	/// The user must provide a list of [`MessageForwardNode`] that will be used to generate valid
	/// reply paths for the counterparty to send back the corresponding [`InvoiceError`] if we fail
	/// to create blinded reply paths
	///
	/// [`supports_onion_messages`]: crate::types::features::Features::supports_onion_messages
	pub fn enqueue_invoice(
		&self, invoice: Bolt12Invoice, refund: &Refund, peers: Vec<MessageForwardNode>,
	) -> Result<(), Bolt12SemanticError> {
		let payment_hash = invoice.payment_hash();

		let context = MessageContext::Offers(OffersContext::InboundPayment { payment_hash });

		let reply_paths = self
			.create_blinded_paths(peers, context)
			.map_err(|_| Bolt12SemanticError::MissingPaths)?;

		let mut pending_offers_messages = self.pending_offers_messages.lock().unwrap();

		if refund.paths().is_empty() {
			for reply_path in reply_paths {
				let instructions = MessageSendInstructions::WithSpecifiedReplyPath {
					destination: Destination::Node(refund.payer_signing_pubkey()),
					reply_path,
				};
				let message = OffersMessage::Invoice(invoice.clone());
				pending_offers_messages.push((message, instructions));
			}
		} else {
			let message = OffersMessage::Invoice(invoice);
			enqueue_onion_message_with_reply_paths(
				message,
				refund.paths(),
				reply_paths,
				&mut pending_offers_messages,
			);
		}

		Ok(())
	}

	/// Forwards a [`StaticInvoice`] over the provided [`Responder`] in response to an
	/// [`InvoiceRequest`] that we as a static invoice server received on behalf of an often-offline
	/// recipient.
	pub fn enqueue_static_invoice(
		&self, invoice: StaticInvoice, responder: Responder,
	) -> Result<(), Bolt12SemanticError> {
		let duration_since_epoch = self.duration_since_epoch();
		if invoice.is_expired_no_std(duration_since_epoch) {
			return Err(Bolt12SemanticError::AlreadyExpired);
		}
		if invoice.is_offer_expired_no_std(duration_since_epoch) {
			return Err(Bolt12SemanticError::AlreadyExpired);
		}

		let mut pending_offers_messages = self.pending_offers_messages.lock().unwrap();
		let message = OffersMessage::StaticInvoice(invoice);
		pending_offers_messages.push((message, responder.respond().into_instructions()));

		Ok(())
	}

	/// Enqueues `held_htlc_available` onion messages to be sent to the payee via the reply paths
	/// contained within the provided [`StaticInvoice`].
	///
	/// # Peers
	///
	/// The user must provide a list of [`MessageForwardNode`] that will be used to generate valid
	/// reply paths for the recipient to send back the corresponding [`ReleaseHeldHtlc`] onion message.
	///
	/// [`ReleaseHeldHtlc`]: crate::onion_message::async_payments::ReleaseHeldHtlc
	/// [`supports_onion_messages`]: crate::types::features::Features::supports_onion_messages
	pub fn enqueue_held_htlc_available(
		&self, invoice: &StaticInvoice, payment_id: PaymentId, peers: Vec<MessageForwardNode>,
	) -> Result<(), Bolt12SemanticError> {
		let context =
			MessageContext::AsyncPayments(AsyncPaymentsContext::OutboundPayment { payment_id });

		let reply_paths = self
			.create_blinded_paths(peers, context)
			.map_err(|_| Bolt12SemanticError::MissingPaths)?;

		let mut pending_async_payments_messages =
			self.pending_async_payments_messages.lock().unwrap();

		let message = AsyncPaymentsMessage::HeldHtlcAvailable(HeldHtlcAvailable {});
		enqueue_onion_message_with_reply_paths(
			message,
			invoice.message_paths(),
			reply_paths,
			&mut pending_async_payments_messages,
		);

		Ok(())
	}

	/// If we are holding an HTLC on behalf of an often-offline sender, this method allows us to
	/// create a path for the sender to use as the reply path when they send the recipient a
	/// [`HeldHtlcAvailable`] onion message, so the recipient's [`ReleaseHeldHtlc`] response will be
	/// received to our node.
	///
	/// [`ReleaseHeldHtlc`]: crate::onion_message::async_payments::ReleaseHeldHtlc
	pub fn path_for_release_held_htlc<ES: Deref>(
		&self, intercept_id: InterceptId, entropy: ES,
	) -> BlindedMessagePath
	where
		ES::Target: EntropySource,
	{
		// In the future, we should support multi-hop paths here.
		let context =
			MessageContext::AsyncPayments(AsyncPaymentsContext::ReleaseHeldHtlc { intercept_id });
		let num_dummy_hops = PADDED_PATH_LENGTH.saturating_sub(1);
		BlindedMessagePath::new_with_dummy_hops(
			&[],
			self.get_our_node_id(),
			num_dummy_hops,
			self.receive_auth_key,
			context,
			&*entropy,
			&self.secp_ctx,
		)
	}

	/// Enqueues the created [`DNSSECQuery`] to be sent to the counterparty.
	///
	/// # Peers
	///
	/// The user must provide a list of [`MessageForwardNode`] that will be used to generate
	/// valid reply paths for the counterparty to send back the corresponding response for
	/// the [`DNSSECQuery`] message.
	///
	/// [`supports_onion_messages`]: crate::types::features::Features::supports_onion_messages
	#[cfg(feature = "dnssec")]
	pub fn enqueue_dns_onion_message(
		&self, message: DNSSECQuery, context: DNSResolverContext, dns_resolvers: Vec<Destination>,
		peers: Vec<MessageForwardNode>,
	) -> Result<(), Bolt12SemanticError> {
		let reply_paths = self
			.create_blinded_paths(peers, MessageContext::DNSResolver(context))
			.map_err(|_| Bolt12SemanticError::MissingPaths)?;

		let message_params = dns_resolvers
			.iter()
			.flat_map(|destination| reply_paths.iter().map(move |path| (path, destination)))
			.take(OFFERS_MESSAGE_REQUEST_LIMIT);
		for (reply_path, destination) in message_params {
			self.pending_dns_onion_messages.lock().unwrap().push((
				DNSResolverMessage::DNSSECQuery(message.clone()),
				MessageSendInstructions::WithSpecifiedReplyPath {
					destination: destination.clone(),
					reply_path: reply_path.clone(),
				},
			));
		}

		Ok(())
	}

	/// Gets the enqueued [`OffersMessage`] with their corresponding [`MessageSendInstructions`].
	pub fn release_pending_offers_messages(&self) -> Vec<(OffersMessage, MessageSendInstructions)> {
		core::mem::take(&mut self.pending_offers_messages.lock().unwrap())
	}

	/// Gets the enqueued [`AsyncPaymentsMessage`] with their corresponding [`MessageSendInstructions`].
	pub fn release_pending_async_messages(
		&self,
	) -> Vec<(AsyncPaymentsMessage, MessageSendInstructions)> {
		core::mem::take(&mut self.pending_async_payments_messages.lock().unwrap())
	}

	/// Gets the enqueued [`DNSResolverMessage`] with their corresponding [`MessageSendInstructions`].
	#[cfg(feature = "dnssec")]
	pub fn release_pending_dns_messages(
		&self,
	) -> Vec<(DNSResolverMessage, MessageSendInstructions)> {
		core::mem::take(&mut self.pending_dns_onion_messages.lock().unwrap())
	}

	/// Retrieve an [`Offer`] for receiving async payments as an often-offline recipient. Will only
	/// return an offer if [`Self::set_paths_to_static_invoice_server`] was called and we succeeded in
	/// interactively building a [`StaticInvoice`] with the static invoice server.
	///
	/// Returns the requested offer as well as a bool indicating whether the cache needs to be
	/// persisted using [`Self::writeable_async_receive_offer_cache`].
	pub fn get_async_receive_offer(&self) -> Result<(Offer, bool), ()> {
		let mut cache = self.async_receive_offer_cache.lock().unwrap();
		cache.get_async_receive_offer(self.duration_since_epoch())
	}

	#[cfg(test)]
	pub(crate) fn test_get_async_receive_offers(&self) -> Vec<Offer> {
		self.async_receive_offer_cache.lock().unwrap().test_get_payable_offers()
	}

	/// Sends out [`OfferPathsRequest`] and [`ServeStaticInvoice`] onion messages if we are an
	/// often-offline recipient and are configured to interactively build offers and static invoices
	/// with a static invoice server.
	///
	/// # Usage
	///
	/// This method should be called on peer connection and once per minute or so, to keep the offers
	/// cache updated. When calling this method once per minute, SHOULD set `timer_tick_occurred` so
	/// the cache can self-regulate the number of messages sent out.
	///
	/// Errors if we failed to create blinded reply paths when sending an [`OfferPathsRequest`] message.
	pub fn check_refresh_async_receive_offer_cache<ES: Deref, R: Deref>(
		&self, peers: Vec<MessageForwardNode>, usable_channels: Vec<ChannelDetails>, entropy: ES,
		router: R, timer_tick_occurred: bool,
	) -> Result<(), ()>
	where
		ES::Target: EntropySource,
		R::Target: Router,
	{
		// Terminate early if this node does not intend to receive async payments.
		{
			let cache = self.async_receive_offer_cache.lock().unwrap();
			if cache.paths_to_static_invoice_server().is_empty() {
				return Ok(());
			}
		}

		self.check_refresh_async_offers(peers.clone(), timer_tick_occurred)?;

		if timer_tick_occurred {
			self.check_refresh_static_invoices(peers, usable_channels, entropy, router);
		}

		Ok(())
	}

	fn check_refresh_async_offers(
		&self, peers: Vec<MessageForwardNode>, timer_tick_occurred: bool,
	) -> Result<(), ()> {
		let duration_since_epoch = self.duration_since_epoch();
		let mut cache = self.async_receive_offer_cache.lock().unwrap();

		// Update the cache to remove expired offers, and check to see whether we need new offers to be
		// interactively built with the static invoice server.
		let needs_new_offer_slot =
			match cache.prune_expired_offers(duration_since_epoch, timer_tick_occurred) {
				Some(idx) => idx,
				None => return Ok(()),
			};

		// If we need new offers, send out offer paths request messages to the static invoice server.
		let context = MessageContext::AsyncPayments(AsyncPaymentsContext::OfferPaths {
			path_absolute_expiry: duration_since_epoch
				.saturating_add(TEMP_REPLY_PATH_RELATIVE_EXPIRY),
			invoice_slot: needs_new_offer_slot,
		});
		let reply_paths = match self.create_blinded_paths(peers, context) {
			Ok(paths) => paths,
			Err(()) => {
				log_error!(
					self.logger,
					"Failed to create blinded paths for OfferPathsRequest message"
				);
				return Err(());
			},
		};

		// We can't fail past this point, so indicate to the cache that we've requested new offers.
		cache.new_offers_requested();

		let mut pending_async_payments_messages =
			self.pending_async_payments_messages.lock().unwrap();
		let message = AsyncPaymentsMessage::OfferPathsRequest(OfferPathsRequest {
			invoice_slot: needs_new_offer_slot,
		});
		enqueue_onion_message_with_reply_paths(
			message,
			cache.paths_to_static_invoice_server(),
			reply_paths,
			&mut pending_async_payments_messages,
		);

		Ok(())
	}

	/// Enqueue onion messages that will used to request invoice refresh from the static invoice
	/// server, based on the offers provided by the cache.
	fn check_refresh_static_invoices<ES: Deref, R: Deref>(
		&self, peers: Vec<MessageForwardNode>, usable_channels: Vec<ChannelDetails>, entropy: ES,
		router: R,
	) where
		ES::Target: EntropySource,
		R::Target: Router,
	{
		let mut serve_static_invoice_msgs = Vec::new();
		{
			let duration_since_epoch = self.duration_since_epoch();
			let cache = self.async_receive_offer_cache.lock().unwrap();
			for offer_and_metadata in cache.offers_needing_invoice_refresh(duration_since_epoch) {
				let (offer, offer_nonce, update_static_invoice_path) = offer_and_metadata;

				let (invoice, forward_invreq_path) = match self.create_static_invoice_for_server(
					offer,
					offer_nonce,
					peers.clone(),
					usable_channels.clone(),
					&*entropy,
					&*router,
				) {
					Ok((invoice, path)) => (invoice, path),
					Err(()) => continue,
				};

				let reply_path_context = {
					MessageContext::AsyncPayments(AsyncPaymentsContext::StaticInvoicePersisted {
						invoice_created_at: invoice.created_at(),
						offer_id: offer.id(),
					})
				};

				let serve_invoice_message = ServeStaticInvoice {
					invoice,
					forward_invoice_request_path: forward_invreq_path,
				};
				serve_static_invoice_msgs.push((
					serve_invoice_message,
					update_static_invoice_path.clone(),
					reply_path_context,
				));
			}
		}

		// Enqueue the new serve_static_invoice messages in a separate loop to avoid holding the offer
		// cache lock and the pending_async_payments_messages lock at the same time.
		for (serve_invoice_msg, serve_invoice_path, reply_path_ctx) in serve_static_invoice_msgs {
			let reply_paths = match self.create_blinded_paths(peers.clone(), reply_path_ctx) {
				Ok(paths) => paths,
				Err(()) => continue,
			};

			let message = AsyncPaymentsMessage::ServeStaticInvoice(serve_invoice_msg);
			enqueue_onion_message_with_reply_paths(
				message,
				&[serve_invoice_path.into_blinded_path()],
				reply_paths,
				&mut self.pending_async_payments_messages.lock().unwrap(),
			);
		}
	}

	/// Handles an incoming [`OfferPathsRequest`] onion message from an often-offline recipient who
	/// wants us (the static invoice server) to serve [`StaticInvoice`]s to payers on their behalf.
	/// Sends out [`OfferPaths`] onion messages in response.
	pub fn handle_offer_paths_request(
		&self, request: &OfferPathsRequest, context: AsyncPaymentsContext,
		peers: Vec<MessageForwardNode>,
	) -> Option<(OfferPaths, MessageContext)> {
		let duration_since_epoch = self.duration_since_epoch();

		let recipient_id = match context {
			AsyncPaymentsContext::OfferPathsRequest { recipient_id, path_absolute_expiry } => {
				if duration_since_epoch > path_absolute_expiry.unwrap_or(Duration::MAX) {
					return None;
				}
				recipient_id
			},
			_ => return None,
		};

		// Create the blinded paths that will be included in the async recipient's offer.
		let (offer_paths, paths_expiry) = {
			let path_absolute_expiry =
				duration_since_epoch.saturating_add(DEFAULT_ASYNC_RECEIVE_OFFER_EXPIRY);
			let context = MessageContext::Offers(OffersContext::StaticInvoiceRequested {
				recipient_id: recipient_id.clone(),
				path_absolute_expiry,
				invoice_slot: request.invoice_slot,
			});

			match self.create_blinded_paths(peers, context) {
				Ok(paths) => (paths, path_absolute_expiry),
				Err(()) => {
					log_error!(
						self.logger,
						"Failed to create blinded paths for OfferPaths message"
					);
					return None;
				},
			}
		};

		// Create a reply path so that the recipient can respond to our offer_paths message with the
		// static invoice that they create. This path will also be used by the recipient to update said
		// invoice.
		let reply_path_context = {
			let path_absolute_expiry =
				duration_since_epoch.saturating_add(DEFAULT_ASYNC_RECEIVE_OFFER_EXPIRY);
			MessageContext::AsyncPayments(AsyncPaymentsContext::ServeStaticInvoice {
				recipient_id,
				invoice_slot: request.invoice_slot,
				path_absolute_expiry,
			})
		};

		let offer_paths_om =
			OfferPaths { paths: offer_paths, paths_absolute_expiry: Some(paths_expiry.as_secs()) };
		return Some((offer_paths_om, reply_path_context));
	}

	/// Handles an incoming [`OfferPaths`] message from the static invoice server, sending out
	/// [`ServeStaticInvoice`] onion messages in response if we've built a new async receive offer and
	/// need the corresponding [`StaticInvoice`] to be persisted by the static invoice server.
	///
	/// Returns `None` if we have enough offers cached already, verification of `message` fails, or we
	/// fail to create blinded paths.
	pub fn handle_offer_paths<ES: Deref, R: Deref>(
		&self, message: OfferPaths, context: AsyncPaymentsContext, responder: Responder,
		peers: Vec<MessageForwardNode>, usable_channels: Vec<ChannelDetails>, entropy: ES,
		router: R,
	) -> Option<(ServeStaticInvoice, MessageContext)>
	where
		ES::Target: EntropySource,
		R::Target: Router,
	{
		let duration_since_epoch = self.duration_since_epoch();
		let invoice_slot = match context {
			AsyncPaymentsContext::OfferPaths { invoice_slot, path_absolute_expiry } => {
				if duration_since_epoch > path_absolute_expiry {
					return None;
				}
				invoice_slot
			},
			_ => return None,
		};

		{
			// Only respond with `ServeStaticInvoice` if we actually need a new offer built.
			let mut cache = self.async_receive_offer_cache.lock().unwrap();
			cache.prune_expired_offers(duration_since_epoch, false);
			if !cache.should_build_offer_with_paths(
				&message.paths[..],
				message.paths_absolute_expiry,
				invoice_slot,
				duration_since_epoch,
			) {
				return None;
			}
		}

		let (mut offer_builder, offer_nonce) =
			match self.create_async_receive_offer_builder(&*entropy, message.paths) {
				Ok((builder, nonce)) => (builder, nonce),
				Err(_) => return None, // Only reachable if OfferPaths::paths is empty
			};
		if let Some(paths_absolute_expiry) = message.paths_absolute_expiry {
			offer_builder =
				offer_builder.absolute_expiry(Duration::from_secs(paths_absolute_expiry));
		}
		let (offer_id, offer) = match offer_builder.build() {
			Ok(offer) => (offer.id(), offer),
			Err(_) => {
				log_error!(self.logger, "Failed to build async receive offer");
				debug_assert!(false);
				return None;
			},
		};

		let (invoice, forward_invoice_request_path) = match self.create_static_invoice_for_server(
			&offer,
			offer_nonce,
			peers,
			usable_channels,
			&*entropy,
			router,
		) {
			Ok(res) => res,
			Err(()) => {
				log_error!(self.logger, "Failed to create static invoice for server");
				return None;
			},
		};

		if let Err(()) = self.async_receive_offer_cache.lock().unwrap().cache_pending_offer(
			offer,
			message.paths_absolute_expiry,
			offer_nonce,
			responder,
			duration_since_epoch,
			invoice_slot,
		) {
			log_error!(self.logger, "Failed to cache pending offer");
			return None;
		}

		let reply_path_context = {
			MessageContext::AsyncPayments(AsyncPaymentsContext::StaticInvoicePersisted {
				offer_id,
				invoice_created_at: invoice.created_at(),
			})
		};

		let serve_invoice_message = ServeStaticInvoice { invoice, forward_invoice_request_path };
		Some((serve_invoice_message, reply_path_context))
	}

	/// Creates a [`StaticInvoice`] and a blinded path for the server to forward invoice requests from
	/// payers to our node.
	fn create_static_invoice_for_server<ES: Deref, R: Deref>(
		&self, offer: &Offer, offer_nonce: Nonce, peers: Vec<MessageForwardNode>,
		usable_channels: Vec<ChannelDetails>, entropy: ES, router: R,
	) -> Result<(StaticInvoice, BlindedMessagePath), ()>
	where
		ES::Target: EntropySource,
		R::Target: Router,
	{
		let expanded_key = &self.inbound_payment_key;
		let duration_since_epoch = self.duration_since_epoch();
		let secp_ctx = &self.secp_ctx;

		let offer_relative_expiry = offer
			.absolute_expiry()
			.map(|exp| exp.saturating_sub(duration_since_epoch).as_secs())
			.map(|exp_u64| exp_u64.try_into().unwrap_or(u32::MAX))
			.unwrap_or(u32::MAX);

		// Set the invoice to expire at the same time as the offer. We aim to update this invoice as
		// often as possible, so there shouldn't be any reason to have it expire earlier than the
		// offer.
		let payment_secret = inbound_payment::create_for_spontaneous_payment(
			expanded_key,
			None, // The async receive offers we create are always amount-less
			offer_relative_expiry,
			duration_since_epoch.as_secs(),
			None,
		)?;

		let invoice = self
			.create_static_invoice_builder(
				&router,
				&*entropy,
				&offer,
				offer_nonce,
				payment_secret,
				offer_relative_expiry,
				usable_channels,
				peers.clone(),
			)
			.and_then(|builder| builder.build_and_sign(secp_ctx))
			.map_err(|_| ())?;

		let nonce = Nonce::from_entropy_source(&*entropy);
		let context = MessageContext::Offers(OffersContext::InvoiceRequest { nonce });
		let forward_invoice_request_path = self
			.create_blinded_paths(peers, context)
			.and_then(|paths| paths.into_iter().next().ok_or(()))?;

		Ok((invoice, forward_invoice_request_path))
	}

	/// Verifies an incoming [`ServeStaticInvoice`] onion message from an often-offline recipient who
	/// wants us as a static invoice server to serve the [`ServeStaticInvoice::invoice`] to payers on
	/// their behalf.
	///
	/// On success, returns `(recipient_id, invoice_slot)` for use in persisting and later retrieving
	/// the static invoice from the database.
	///
	/// Errors if the [`ServeStaticInvoice::invoice`] is expired or larger than
	/// [`MAX_STATIC_INVOICE_SIZE_BYTES`].
	///
	/// [`ServeStaticInvoice::invoice`]: crate::onion_message::async_payments::ServeStaticInvoice::invoice
	pub fn verify_serve_static_invoice_message(
		&self, message: &ServeStaticInvoice, context: AsyncPaymentsContext,
	) -> Result<(Vec<u8>, u16), ()> {
		if message.invoice.is_expired_no_std(self.duration_since_epoch()) {
			log_trace!(self.logger, "Received expired StaticInvoice");
			return Err(());
		}
		if message.invoice.serialized_length() > MAX_STATIC_INVOICE_SIZE_BYTES {
			return Err(());
		}
		match context {
			AsyncPaymentsContext::ServeStaticInvoice {
				recipient_id,
				invoice_slot,
				path_absolute_expiry,
			} => {
				if self.duration_since_epoch() > path_absolute_expiry {
					log_trace!(self.logger, "Received expired StaticInvoice path");
					return Err(());
				}

				return Ok((recipient_id, invoice_slot));
			},
			_ => return Err(()),
		};
	}

	/// Indicates that a [`ServeStaticInvoice::invoice`] has been persisted and is ready to be served
	/// to payers on behalf of an often-offline recipient. This method must be called after persisting
	/// a [`StaticInvoice`] to confirm to the recipient that their corresponding [`Offer`] is ready to
	/// receive async payments.
	pub fn static_invoice_persisted(&self, responder: Responder) {
		let mut pending_async_payments_messages =
			self.pending_async_payments_messages.lock().unwrap();
		let message = AsyncPaymentsMessage::StaticInvoicePersisted(StaticInvoicePersisted {});
		pending_async_payments_messages.push((message, responder.respond().into_instructions()));
	}

	/// Handles an incoming [`StaticInvoicePersisted`] onion message from the static invoice server.
	/// Returns a bool indicating whether the async receive offer cache needs to be re-persisted using
	/// [`Self::writeable_async_receive_offer_cache`].
	///
	/// [`StaticInvoicePersisted`]: crate::onion_message::async_payments::StaticInvoicePersisted
	pub fn handle_static_invoice_persisted(&self, context: AsyncPaymentsContext) -> bool {
		let mut cache = self.async_receive_offer_cache.lock().unwrap();
		cache.static_invoice_persisted(context)
	}

	/// Get the encoded [`AsyncReceiveOfferCache`] for persistence.
	pub fn writeable_async_receive_offer_cache(&self) -> Vec<u8> {
		self.async_receive_offer_cache.encode()
	}
}
