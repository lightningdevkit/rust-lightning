// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Provides data structures and functions for creating and managing Offers messages,
//! facilitating communication, and handling Bolt12 messages and payments.

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
	BlindedPaymentPath, Bolt12OfferContext, Bolt12RefundContext, PaymentConstraints,
	PaymentContext, UnauthenticatedReceiveTlvs,
};
use crate::chain::channelmonitor::LATENCY_GRACE_PERIOD_BLOCKS;
use crate::chain::transaction::TransactionData;
use crate::chain::{self, BestBlock};
use crate::ln::channel_state::ChannelDetails;
use crate::ln::channelmanager::{
	Verification, OFFERS_MESSAGE_REQUEST_LIMIT,
	{PaymentId, CLTV_FAR_FAR_AWAY, MAX_SHORT_LIVED_RELATIVE_EXPIRY},
};
use crate::ln::inbound_payment;
use crate::offers::invoice::{
	Bolt12Invoice, DerivedSigningPubkey, ExplicitSigningPubkey, InvoiceBuilder,
	UnsignedBolt12Invoice, DEFAULT_RELATIVE_EXPIRY,
};
use crate::offers::invoice_error::InvoiceError;
use crate::offers::invoice_request::{
	InvoiceRequest, InvoiceRequestBuilder, VerifiedInvoiceRequest,
};
use crate::offers::nonce::Nonce;
use crate::offers::offer::{DerivedMetadata, Offer, OfferBuilder};
use crate::offers::parse::Bolt12SemanticError;
use crate::offers::refund::{Refund, RefundBuilder};
use crate::onion_message::async_payments::AsyncPaymentsMessage;
use crate::onion_message::dns_resolution::HumanReadableName;
use crate::onion_message::messenger::{Destination, MessageRouter, MessageSendInstructions};
use crate::onion_message::offers::OffersMessage;
use crate::onion_message::packet::OnionMessageContents;
use crate::routing::router::Router;
use crate::sign::{EntropySource, NodeSigner};
use crate::sync::{Mutex, RwLock};
use crate::types::payment::{PaymentHash, PaymentSecret};

#[cfg(async_payments)]
use {
	crate::blinded_path::payment::AsyncBolt12OfferContext,
	crate::offers::offer::Amount,
	crate::offers::signer,
	crate::offers::static_invoice::{
		StaticInvoice, StaticInvoiceBuilder,
		DEFAULT_RELATIVE_EXPIRY as STATIC_INVOICE_DEFAULT_RELATIVE_EXPIRY,
	},
	crate::onion_message::async_payments::HeldHtlcAvailable,
};

#[cfg(feature = "dnssec")]
use {
	crate::blinded_path::message::DNSResolverContext,
	crate::onion_message::dns_resolution::{DNSResolverMessage, DNSSECQuery},
};

pub struct OffersMessageFlow<ES: Deref, MR: Deref, R: Deref>
where
	ES::Target: EntropySource,
	MR::Target: MessageRouter,
	R::Target: Router,
{
	chain_hash: ChainHash,
	best_block: RwLock<BestBlock>,

	our_network_pubkey: PublicKey,
	highest_seen_timestamp: AtomicUsize,
	inbound_payment_key: inbound_payment::ExpandedKey,

	secp_ctx: Secp256k1<secp256k1::All>,
	entropy_source: ES,

	message_router: MR,
	router: R,

	#[cfg(not(any(test, feature = "_test_utils")))]
	pending_offers_messages: Mutex<Vec<(OffersMessage, MessageSendInstructions)>>,
	#[cfg(any(test, feature = "_test_utils"))]
	pub(crate) pending_offers_messages: Mutex<Vec<(OffersMessage, MessageSendInstructions)>>,

	pending_async_payments_messages: Mutex<Vec<(AsyncPaymentsMessage, MessageSendInstructions)>>,

	#[cfg(feature = "dnssec")]
	pending_dns_onion_messages: Mutex<Vec<(DNSResolverMessage, MessageSendInstructions)>>,
}

impl<ES: Deref, MR: Deref, R: Deref> OffersMessageFlow<ES, MR, R>
where
	ES::Target: EntropySource,
	MR::Target: MessageRouter,
	R::Target: Router,
{
	/// Creates a new [`OffersMessageFlow`]
	pub fn new(
		chain_hash: ChainHash, best_block: BestBlock, our_network_pubkey: PublicKey,
		current_timestamp: u32, inbound_payment_key: inbound_payment::ExpandedKey,
		entropy_source: ES, message_router: MR, router: R,
	) -> Self {
		let mut secp_ctx = Secp256k1::new();
		secp_ctx.seeded_randomize(&entropy_source.get_secure_random_bytes());

		Self {
			chain_hash,
			best_block: RwLock::new(best_block),

			our_network_pubkey,
			highest_seen_timestamp: AtomicUsize::new(current_timestamp as usize),
			inbound_payment_key,

			secp_ctx,
			entropy_source,

			message_router,
			router,

			pending_offers_messages: Mutex::new(Vec::new()),
			pending_async_payments_messages: Mutex::new(Vec::new()),
			#[cfg(feature = "dnssec")]
			pending_dns_onion_messages: Mutex::new(Vec::new()),
		}
	}

	/// Gets the node_id held by this OffersMessageFlow
	pub fn get_our_node_id(&self) -> PublicKey {
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

	fn best_block_updated(&self, header: &Header) {
		macro_rules! max_time {
			($timestamp: expr) => {
				loop {
					// Update $timestamp to be the max of its current value and the block
					// timestamp. This should keep us close to the current time without relying on
					// having an explicit local time source.
					// Just in case we end up in a race, we loop until we either successfully
					// update $timestamp or decide we don't need to.
					let old_serial = $timestamp.load(Ordering::Acquire);
					if old_serial >= header.time as usize {
						break;
					}
					if $timestamp
						.compare_exchange(
							old_serial,
							header.time as usize,
							Ordering::AcqRel,
							Ordering::Relaxed,
						)
						.is_ok()
					{
						break;
					}
				}
			};
		}

		max_time!(self.highest_seen_timestamp);
	}
}

impl<ES: Deref, MR: Deref, R: Deref> OffersMessageFlow<ES, MR, R>
where
	ES::Target: EntropySource,
	MR::Target: MessageRouter,
	R::Target: Router,
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

		let peers = peers;

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
	fn create_blinded_payment_paths(
		&self, usable_channels: Vec<ChannelDetails>, amount_msats: Option<u64>,
		payment_secret: PaymentSecret, payment_context: PaymentContext,
		relative_expiry_seconds: u32,
	) -> Result<Vec<BlindedPaymentPath>, ()> {
		let expanded_key = &self.inbound_payment_key;
		let entropy = &*self.entropy_source;
		let secp_ctx = &self.secp_ctx;

		let first_hops = usable_channels;
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

		self.router.create_blinded_payment_paths(
			payee_node_id,
			first_hops,
			payee_tlvs,
			amount_msats,
			secp_ctx,
		)
	}
}

impl<ES: Deref, MR: Deref, R: Deref> chain::Listen for OffersMessageFlow<ES, MR, R>
where
	ES::Target: EntropySource,
	MR::Target: MessageRouter,
	R::Target: Router,
{
	fn filtered_block_connected(&self, header: &Header, _txdata: &TransactionData, _height: u32) {
		self.best_block_updated(header);
	}

	fn block_disconnected(&self, _header: &Header, _height: u32) {}
}

fn enqueue_onion_message_with_reply_paths<T: OnionMessageContents + Clone>(
	message: T, message_paths: &[BlindedMessagePath], reply_paths: Vec<BlindedMessagePath>,
	queue: &mut Vec<(T, MessageSendInstructions)>
) {
	reply_paths
		.iter()
		.flat_map(|reply_path|
			message_paths
				.iter()
				.map(move |path| (path, reply_path))
		)
		.take(OFFERS_MESSAGE_REQUEST_LIMIT)
		.for_each(|(path, reply_path)| {
			let instructions = MessageSendInstructions::WithSpecifiedReplyPath {
				destination: Destination::BlindedPath(path.clone()),
				reply_path: reply_path.clone(),
			};
			queue.push((message.clone(), instructions));
		});
}

impl<ES: Deref, MR: Deref, R: Deref> OffersMessageFlow<ES, MR, R>
where
	ES::Target: EntropySource,
	MR::Target: MessageRouter,
	R::Target: Router,
{
	pub fn verify_invoice_request(
		&self, invoice_request: InvoiceRequest, context: Option<OffersContext>,
	) -> Result<VerifiedInvoiceRequest, ()> {
		let secp_ctx = &self.secp_ctx;
		let expanded_key = &self.inbound_payment_key;

		let nonce = match context {
			None if invoice_request.metadata().is_some() => None,
			Some(OffersContext::InvoiceRequest { nonce }) => Some(nonce),
			_ => return Err(()),
		};

		let invoice_request = match nonce {
			Some(nonce) => {
				match invoice_request.verify_using_recipient_data(nonce, expanded_key, secp_ctx) {
					Ok(invoice_request) => invoice_request,
					Err(()) => return Err(()),
				}
			},
			None => match invoice_request.verify_using_metadata(expanded_key, secp_ctx) {
				Ok(invoice_request) => invoice_request,
				Err(()) => return Err(()),
			},
		};

		Ok(invoice_request)
	}

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

	#[cfg(async_payments)]
	pub fn verify_async_context(
		&self, context: AsyncPaymentsContext,
	) -> Result<Option<PaymentId>, ()> {
		match context {
			AsyncPaymentsContext::InboundPayment { nonce, hmac, path_absolute_expiry } => {
				signer::verify_held_htlc_available_context(nonce, hmac, &self.inbound_payment_key)?;

				if self.duration_since_epoch() > path_absolute_expiry {
					return Err(());
				}
				Ok(None)
			},
			AsyncPaymentsContext::OutboundPayment { payment_id, hmac, nonce } => {
				payment_id.verify_for_async_payment(hmac, nonce, &self.inbound_payment_key)?;
				Ok(Some(payment_id))
			},
		}
	}

	pub fn create_offer_builder(
		&self, absolute_expiry: Option<Duration>, nonce: Option<Nonce>,
		peers: Vec<MessageForwardNode>,
	) -> Result<OfferBuilder<DerivedMetadata, secp256k1::All>, Bolt12SemanticError> {
		let node_id = self.get_our_node_id();
		let expanded_key = &self.inbound_payment_key;
		let entropy = &*self.entropy_source;
		let secp_ctx = &self.secp_ctx;

		let nonce = nonce.unwrap_or(Nonce::from_entropy_source(entropy));
		let context = OffersContext::InvoiceRequest { nonce };

		let path = self
			.create_blinded_paths_using_absolute_expiry(context, absolute_expiry, peers)
			.and_then(|paths| paths.into_iter().next().ok_or(()))
			.map_err(|_| Bolt12SemanticError::MissingPaths)?;

		let builder = OfferBuilder::deriving_signing_pubkey(node_id, expanded_key, nonce, secp_ctx)
			.chain_hash(self.chain_hash)
			.path(path);

		let builder = match absolute_expiry {
			None => builder,
			Some(absolute_expiry) => builder.absolute_expiry(absolute_expiry),
		};

		Ok(builder)
	}

	pub fn create_refund_builder(
		&self, amount_msats: u64, absolute_expiry: Duration, payment_id: PaymentId,
		peers: Vec<MessageForwardNode>,
	) -> Result<RefundBuilder<secp256k1::All>, Bolt12SemanticError> {
		let node_id = self.get_our_node_id();
		let expanded_key = &self.inbound_payment_key;
		let entropy = &*self.entropy_source;
		let secp_ctx = &self.secp_ctx;

		let nonce = Nonce::from_entropy_source(entropy);
		let context = OffersContext::OutboundPayment { payment_id, nonce, hmac: None };

		let path = self
			.create_blinded_paths_using_absolute_expiry(context, Some(absolute_expiry), peers)
			.and_then(|paths| paths.into_iter().next().ok_or(()))
			.map_err(|_| Bolt12SemanticError::MissingPaths)?;

		let builder = RefundBuilder::deriving_signing_pubkey(
			node_id,
			expanded_key,
			nonce,
			secp_ctx,
			amount_msats,
			payment_id,
		)?
		.chain_hash(self.chain_hash)
		.absolute_expiry(absolute_expiry)
		.path(path);

		Ok(builder)
	}

	pub fn create_invoice_request_builder<'a>(
		&'a self, offer: &'a Offer, nonce: Nonce, quantity: Option<u64>, amount_msats: Option<u64>,
		payer_note: Option<String>, human_readable_name: Option<HumanReadableName>,
		payment_id: PaymentId,
	) -> Result<InvoiceRequestBuilder<'a, 'a, secp256k1::All>, Bolt12SemanticError> {
		let expanded_key = &self.inbound_payment_key;
		let secp_ctx = &self.secp_ctx;

		let builder: InvoiceRequestBuilder<secp256k1::All> =
			offer.request_invoice(expanded_key, nonce, secp_ctx, payment_id)?.into();
		let builder = builder.chain_hash(self.chain_hash)?;

		let builder = match quantity {
			None => builder,
			Some(quantity) => builder.quantity(quantity)?,
		};
		let builder = match amount_msats {
			None => builder,
			Some(amount_msats) => builder.amount_msats(amount_msats)?,
		};
		let builder = match payer_note {
			None => builder,
			Some(payer_note) => builder.payer_note(payer_note),
		};
		let builder = match human_readable_name {
			None => builder,
			Some(hrn) => builder.sourced_from_human_readable_name(hrn),
		};

		Ok(builder)
	}

	#[cfg(async_payments)]
	pub fn create_static_invoice_builder<'a>(
		&'a self, offer: &'a Offer, offer_nonce: Nonce, relative_expiry: Option<Duration>,
		usable_channels: Vec<ChannelDetails>, peers: Vec<MessageForwardNode>,
	) -> Result<StaticInvoiceBuilder<'a>, Bolt12SemanticError> {
		let expanded_key = &self.inbound_payment_key;
		let entropy = &*self.entropy_source;
		let secp_ctx = &self.secp_ctx;

		let payment_context =
			PaymentContext::AsyncBolt12Offer(AsyncBolt12OfferContext { offer_nonce });
		let amount_msat = offer.amount().and_then(|amount| match amount {
			Amount::Bitcoin { amount_msats } => Some(amount_msats),
			Amount::Currency { .. } => None,
		});

		let relative_expiry = relative_expiry.unwrap_or(STATIC_INVOICE_DEFAULT_RELATIVE_EXPIRY);
		let relative_expiry_secs: u32 = relative_expiry.as_secs().try_into().unwrap_or(u32::MAX);

		let created_at = self.duration_since_epoch();
		let payment_secret = inbound_payment::create_for_spontaneous_payment(
			&self.inbound_payment_key,
			amount_msat,
			relative_expiry_secs,
			created_at.as_secs(),
			None,
		)
		.map_err(|()| Bolt12SemanticError::InvalidAmount)?;

		let payment_paths = self
			.create_blinded_payment_paths(
				usable_channels,
				amount_msat,
				payment_secret,
				payment_context,
				relative_expiry_secs,
			)
			.map_err(|()| Bolt12SemanticError::MissingPaths)?;

		let nonce = Nonce::from_entropy_source(entropy);
		let hmac = signer::hmac_for_held_htlc_available_context(nonce, expanded_key);
		let path_absolute_expiry = Duration::from_secs(inbound_payment::calculate_absolute_expiry(
			created_at.as_secs(),
			relative_expiry_secs,
		));

		let context = MessageContext::AsyncPayments(AsyncPaymentsContext::InboundPayment {
			nonce,
			hmac,
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

	pub fn create_invoice_builder_from_refund<'a>(
		&'a self, refund: &'a Refund, payment_hash: PaymentHash, payment_secret: PaymentSecret,
		usable_channels: Vec<ChannelDetails>,
	) -> Result<InvoiceBuilder<'a, DerivedSigningPubkey>, Bolt12SemanticError> {
		let expanded_key = &self.inbound_payment_key;
		let entropy = &*self.entropy_source;

		let amount_msats = refund.amount_msats();
		let relative_expiry = DEFAULT_RELATIVE_EXPIRY.as_secs() as u32;

		let payment_context = PaymentContext::Bolt12Refund(Bolt12RefundContext {});
		let payment_paths = self
			.create_blinded_payment_paths(
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

		Ok(builder)
	}

	pub fn create_response_for_invoice_request<NS: Deref>(
		&self, signer: &NS, invoice_request: VerifiedInvoiceRequest, amount_msats: u64,
		payment_hash: PaymentHash, payment_secret: PaymentSecret,
		usable_channels: Vec<ChannelDetails>,
	) -> (OffersMessage, Option<MessageContext>)
	where
		NS::Target: NodeSigner,
	{
		let expanded_key = &self.inbound_payment_key;
		let entropy = &*self.entropy_source;
		let secp_ctx = &self.secp_ctx;

		let relative_expiry = DEFAULT_RELATIVE_EXPIRY.as_secs() as u32;

		let context = PaymentContext::Bolt12Offer(Bolt12OfferContext {
			offer_id: invoice_request.offer_id,
			invoice_request: invoice_request.fields(),
		});

		let payment_paths = match self.create_blinded_payment_paths(
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
				let nonce = Nonce::from_entropy_source(entropy);
				let hmac = payment_hash.hmac_for_offer_payment(nonce, expanded_key);
				let context = MessageContext::Offers(OffersContext::InboundPayment {
					payment_hash,
					nonce,
					hmac,
				});

				(OffersMessage::Invoice(invoice), Some(context))
			},
			Err(error) => (OffersMessage::InvoiceError(error.into()), None),
		}
	}

	pub fn enqueue_invoice_request(
		&self, invoice_request: InvoiceRequest, payment_id: PaymentId, nonce: Option<Nonce>,
		peers: Vec<MessageForwardNode>,
	) -> Result<(), Bolt12SemanticError> {
		let expanded_key = &self.inbound_payment_key;
		let entropy = &*self.entropy_source;

		let nonce = nonce.unwrap_or(Nonce::from_entropy_source(entropy));

		let hmac = payment_id.hmac_for_offer_payment(nonce, expanded_key);
		let context = MessageContext::Offers(OffersContext::OutboundPayment {
			payment_id,
			nonce,
			hmac: Some(hmac),
		});
		let reply_paths = self
			.create_blinded_paths(peers, context)
			.map_err(|_| Bolt12SemanticError::MissingPaths)?;

		let mut pending_offers_messages = self.pending_offers_messages.lock().unwrap();
		if !invoice_request.paths().is_empty() {
			let message = OffersMessage::InvoiceRequest(invoice_request.clone());
			enqueue_onion_message_with_reply_paths(
				message, invoice_request.paths(), reply_paths, &mut pending_offers_messages
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

	pub fn enqueue_invoice(
		&self, invoice: Bolt12Invoice, refund: &Refund, payment_hash: PaymentHash,
		peers: Vec<MessageForwardNode>,
	) -> Result<(), Bolt12SemanticError> {
		let expanded_key = &self.inbound_payment_key;
		let entropy = &*self.entropy_source;

		let nonce = Nonce::from_entropy_source(entropy);
		let hmac = payment_hash.hmac_for_offer_payment(nonce, expanded_key);
		let context = MessageContext::Offers(OffersContext::InboundPayment {
			payment_hash: invoice.payment_hash(),
			nonce,
			hmac,
		});

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
			let message = OffersMessage::Invoice(invoice.clone());
			enqueue_onion_message_with_reply_paths(
				message, refund.paths(), reply_paths, &mut pending_offers_messages
			);
		}

		Ok(())
	}

	#[cfg(async_payments)]
	pub fn enqueue_async_payment_messages(
		&self, invoice: &StaticInvoice, payment_id: PaymentId, peers: Vec<MessageForwardNode>,
	) -> Result<(), Bolt12SemanticError> {
		let expanded_key = &self.inbound_payment_key;
		let entropy = &*self.entropy_source;

		let nonce = Nonce::from_entropy_source(entropy);
		let hmac = payment_id.hmac_for_async_payment(nonce, expanded_key);
		let context = MessageContext::AsyncPayments(AsyncPaymentsContext::OutboundPayment {
			payment_id,
			nonce,
			hmac,
		});

		let reply_paths = self
			.create_blinded_paths(peers, context)
			.map_err(|_| Bolt12SemanticError::MissingPaths)?;

		let mut pending_async_payments_messages =
			self.pending_async_payments_messages.lock().unwrap();

		let message = AsyncPaymentsMessage::HeldHtlcAvailable(HeldHtlcAvailable {});
		enqueue_onion_message_with_reply_paths(
			message, invoice.message_paths(), reply_paths, &mut pending_async_payments_messages
		);

		Ok(())
	}

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

	pub fn get_and_clear_pending_offers_messages(
		&self,
	) -> Vec<(OffersMessage, MessageSendInstructions)> {
		core::mem::take(&mut self.pending_offers_messages.lock().unwrap())
	}

	pub fn get_and_clear_pending_async_messages(
		&self,
	) -> Vec<(AsyncPaymentsMessage, MessageSendInstructions)> {
		core::mem::take(&mut self.pending_async_payments_messages.lock().unwrap())
	}

	#[cfg(feature = "dnssec")]
	pub fn get_and_clear_pending_dns_messages(
		&self,
	) -> Vec<(DNSResolverMessage, MessageSendInstructions)> {
		core::mem::take(&mut self.pending_dns_onion_messages.lock().unwrap())
	}
}
