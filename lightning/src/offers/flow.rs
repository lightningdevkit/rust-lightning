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

use crate::blinded_path::message::{
	BlindedMessagePath, MessageContext, MessageForwardNode, OffersContext,
};
use crate::blinded_path::payment::BlindedPaymentPath;
use crate::ln::channelmanager::{
	PaymentId, MAX_SHORT_LIVED_RELATIVE_EXPIRY, OFFERS_MESSAGE_REQUEST_LIMIT,
};
use crate::ln::inbound_payment;
use crate::offers::invoice::{Bolt12Invoice, DerivedSigningPubkey, InvoiceBuilder};
use crate::offers::invoice_request::{InvoiceRequest, InvoiceRequestBuilder};
use crate::offers::nonce::Nonce;
use crate::offers::offer::{DerivedMetadata, Offer, OfferBuilder};
use crate::offers::parse::Bolt12SemanticError;
use crate::offers::refund::{Refund, RefundBuilder};
use crate::onion_message::async_payments::AsyncPaymentsMessage;
use crate::onion_message::dns_resolution::{DNSSECQuery, HumanReadableName};
use crate::onion_message::messenger::{Destination, MessageRouter, MessageSendInstructions};
use crate::onion_message::offers::OffersMessage;
use crate::sign::EntropySource;
use crate::sync::Mutex;
use bitcoin::constants::ChainHash;
use bitcoin::secp256k1::{PublicKey, Secp256k1};
use bitcoin::{secp256k1, Network};
use types::payment::PaymentHash;

use core::ops::Deref;
use core::sync::atomic::AtomicUsize;
use core::time::Duration;

#[cfg(feature = "dnssec")]
use crate::onion_message::dns_resolution::DNSResolverMessage;

pub trait Flow {
	fn create_offer_builder(
		&self, nonce: Nonce,
	) -> Result<OfferBuilder<DerivedMetadata, secp256k1::All>, Bolt12SemanticError>;

	fn create_refund_builder(
		&self, amount_msats: u64, absolute_expiry: Duration, payment_id: PaymentId, nonce: Nonce,
	) -> Result<RefundBuilder<secp256k1::All>, Bolt12SemanticError>;

	fn create_invoice_request_builder<'a>(
		&'a self, offer: &'a Offer, nonce: Nonce, quantity: Option<u64>, amount_msats: Option<u64>,
		payer_note: Option<String>, human_readable_name: Option<HumanReadableName>,
		payment_id: PaymentId,
	) -> Result<InvoiceRequestBuilder<'a, 'a, secp256k1::All>, Bolt12SemanticError>;

	fn create_invoice_builder<'a>(
		&'a self, refund: &'a Refund, payment_paths: Vec<BlindedPaymentPath>,
		payment_hash: PaymentHash,
	) -> Result<InvoiceBuilder<'a, DerivedSigningPubkey>, Bolt12SemanticError>;

	fn create_blinded_paths(
		&self, peers: Vec<MessageForwardNode>, context: MessageContext,
	) -> Result<Vec<BlindedMessagePath>, ()>;

	fn create_compact_blinded_paths(
		&self, peers: Vec<MessageForwardNode>, context: OffersContext,
	) -> Result<Vec<BlindedMessagePath>, ()>;

	fn create_blinded_paths_using_absolute_expiry(
		&self, peers: Vec<MessageForwardNode>, context: OffersContext,
		absolute_expiry: Option<Duration>,
	) -> Result<Vec<BlindedMessagePath>, ()>;

	fn enqueue_invoice_request(
		&self, invoice_request: InvoiceRequest, reply_paths: Vec<BlindedMessagePath>,
	) -> Result<(), Bolt12SemanticError>;

	fn enqueue_invoice(
		&self, invoice: Bolt12Invoice, refund: &Refund, reply_paths: Vec<BlindedMessagePath>,
	) -> Result<(), Bolt12SemanticError>;

	#[cfg(feature = "dnssec")]
	fn enqueue_dns_onion_message(
		&self, message: DNSSECQuery, dns_resolvers: Vec<Destination>,
		reply_paths: Vec<BlindedMessagePath>,
	) -> Result<(), Bolt12SemanticError>;

	fn get_and_clear_pending_offers_messages(
		&self,
	) -> Vec<(OffersMessage, MessageSendInstructions)>;

	fn get_and_clear_pending_async_messages(
		&self,
	) -> Vec<(AsyncPaymentsMessage, MessageSendInstructions)>;

	#[cfg(feature = "dnssec")]
	fn get_and_clear_pending_dns_messages(
		&self,
	) -> Vec<(DNSResolverMessage, MessageSendInstructions)>;
}

pub struct OffersMessageFlow<ES: Deref, MR: Deref>
where
	ES::Target: EntropySource,
	MR::Target: MessageRouter,
{
	chain_hash: ChainHash,
	message_router: MR,

	our_network_pubkey: PublicKey,
	highest_seen_timestamp: AtomicUsize,
	inbound_payment_key: inbound_payment::ExpandedKey,

	secp_ctx: Secp256k1<secp256k1::All>,
	entropy_source: ES,

	#[cfg(not(any(test, feature = "_test_utils")))]
	pending_offers_messages: Mutex<Vec<(OffersMessage, MessageSendInstructions)>>,
	#[cfg(any(test, feature = "_test_utils"))]
	pub(crate) pending_offers_messages: Mutex<Vec<(OffersMessage, MessageSendInstructions)>>,

	pending_async_payments_messages: Mutex<Vec<(AsyncPaymentsMessage, MessageSendInstructions)>>,

	#[cfg(feature = "dnssec")]
	pending_dns_onion_messages: Mutex<Vec<(DNSResolverMessage, MessageSendInstructions)>>,
}

impl<ES: Deref, MR: Deref> OffersMessageFlow<ES, MR>
where
	ES::Target: EntropySource,
	MR::Target: MessageRouter,
{
	/// Creates a new [`OffersMessageFlow`]
	pub fn new(
		network: Network, message_router: MR, our_network_pubkey: PublicKey,
		current_timestamp: u32, inbound_payment_key: inbound_payment::ExpandedKey,
		entropy_source: ES,
	) -> Self {
		let mut secp_ctx = Secp256k1::new();
		secp_ctx.seeded_randomize(&entropy_source.get_secure_random_bytes());

		Self {
			chain_hash: ChainHash::using_genesis_block(network),
			message_router,

			our_network_pubkey,
			highest_seen_timestamp: AtomicUsize::new(current_timestamp as usize),
			inbound_payment_key,

			secp_ctx,
			entropy_source,

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
}

impl<ES: Deref, MR: Deref> Flow for OffersMessageFlow<ES, MR>
where
	ES::Target: EntropySource,
	MR::Target: MessageRouter,
{
	fn create_offer_builder(
		&self, nonce: Nonce,
	) -> Result<OfferBuilder<DerivedMetadata, secp256k1::All>, Bolt12SemanticError> {
		let node_id = self.get_our_node_id();
		let expanded_key = &self.inbound_payment_key;
		let secp_ctx = &self.secp_ctx;

		let builder = OfferBuilder::deriving_signing_pubkey(node_id, expanded_key, nonce, secp_ctx)
			.chain_hash(self.chain_hash);

		Ok(builder)
	}

	fn create_refund_builder(
		&self, amount_msats: u64, absolute_expiry: Duration, payment_id: PaymentId, nonce: Nonce,
	) -> Result<RefundBuilder<secp256k1::All>, Bolt12SemanticError> {
		let node_id = self.get_our_node_id();
		let expanded_key = &self.inbound_payment_key;
		let secp_ctx = &self.secp_ctx;

		let builder = RefundBuilder::deriving_signing_pubkey(
			node_id,
			expanded_key,
			nonce,
			secp_ctx,
			amount_msats,
			payment_id,
		)?
		.chain_hash(self.chain_hash)
		.absolute_expiry(absolute_expiry);

		Ok(builder)
	}

	fn create_invoice_request_builder<'a>(
		&'a self, offer: &'a Offer, nonce: Nonce, quantity: Option<u64>, amount_msats: Option<u64>,
		payer_note: Option<String>, human_readable_name: Option<HumanReadableName>,
		payment_id: PaymentId,
	) -> Result<InvoiceRequestBuilder<'a, 'a, secp256k1::All>, Bolt12SemanticError> {
		let expanded_key = &self.inbound_payment_key;
		let secp_ctx = &self.secp_ctx;

		let builder = offer
			.request_invoice(expanded_key, nonce, secp_ctx, payment_id)?
			.chain_hash(self.chain_hash)?;

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

		Ok(builder.into())
	}

	fn create_invoice_builder<'a>(
		&'a self, refund: &'a Refund, payment_paths: Vec<BlindedPaymentPath>,
		payment_hash: PaymentHash,
	) -> Result<InvoiceBuilder<'a, DerivedSigningPubkey>, Bolt12SemanticError> {
		let expanded_key = &self.inbound_payment_key;
		let entropy = &*self.entropy_source;

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
		let builder: InvoiceBuilder<DerivedSigningPubkey> = builder.into();

		Ok(builder)
	}

	fn create_blinded_paths(
		&self, peers: Vec<MessageForwardNode>, context: MessageContext,
	) -> Result<Vec<BlindedMessagePath>, ()> {
		let recipient = self.get_our_node_id();
		let secp_ctx = &self.secp_ctx;

		let peers = peers.iter().map(|node| node.node_id).collect::<Vec<_>>();

		self.message_router
			.create_blinded_paths(recipient, context, peers, secp_ctx)
			.and_then(|paths| (!paths.is_empty()).then(|| paths).ok_or(()))
	}

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

	fn create_blinded_paths_using_absolute_expiry(
		&self, peers: Vec<MessageForwardNode>, context: OffersContext,
		absolute_expiry: Option<Duration>,
	) -> Result<Vec<BlindedMessagePath>, ()> {
		let now = self.duration_since_epoch();
		let max_short_lived_absolute_expiry = now.saturating_add(MAX_SHORT_LIVED_RELATIVE_EXPIRY);

		if absolute_expiry.unwrap_or(Duration::MAX) <= max_short_lived_absolute_expiry {
			self.create_compact_blinded_paths(peers, context)
		} else {
			self.create_blinded_paths(peers, MessageContext::Offers(context))
		}
	}

	fn enqueue_invoice_request(
		&self, invoice_request: InvoiceRequest, reply_paths: Vec<BlindedMessagePath>,
	) -> Result<(), Bolt12SemanticError> {
		let mut pending_offers_messages = self.pending_offers_messages.lock().unwrap();
		if !invoice_request.paths().is_empty() {
			reply_paths
				.iter()
				.flat_map(|reply_path| {
					invoice_request.paths().iter().map(move |path| (path, reply_path))
				})
				.take(OFFERS_MESSAGE_REQUEST_LIMIT)
				.for_each(|(path, reply_path)| {
					let instructions = MessageSendInstructions::WithSpecifiedReplyPath {
						destination: Destination::BlindedPath(path.clone()),
						reply_path: reply_path.clone(),
					};
					let message = OffersMessage::InvoiceRequest(invoice_request.clone());
					pending_offers_messages.push((message, instructions));
				});
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

	fn enqueue_invoice(
		&self, invoice: Bolt12Invoice, refund: &Refund, reply_paths: Vec<BlindedMessagePath>,
	) -> Result<(), Bolt12SemanticError> {
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
			reply_paths
				.iter()
				.flat_map(|reply_path| refund.paths().iter().map(move |path| (path, reply_path)))
				.take(OFFERS_MESSAGE_REQUEST_LIMIT)
				.for_each(|(path, reply_path)| {
					let instructions = MessageSendInstructions::WithSpecifiedReplyPath {
						destination: Destination::BlindedPath(path.clone()),
						reply_path: reply_path.clone(),
					};
					let message = OffersMessage::Invoice(invoice.clone());
					pending_offers_messages.push((message, instructions));
				});
		}

		Ok(())
	}

	#[cfg(feature = "dnssec")]
	fn enqueue_dns_onion_message(
		&self, message: DNSSECQuery, dns_resolvers: Vec<Destination>,
		reply_paths: Vec<BlindedMessagePath>,
	) -> Result<(), Bolt12SemanticError> {
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

	fn get_and_clear_pending_offers_messages(
		&self,
	) -> Vec<(OffersMessage, MessageSendInstructions)> {
		core::mem::take(&mut self.pending_offers_messages.lock().unwrap())
	}

	fn get_and_clear_pending_async_messages(
		&self,
	) -> Vec<(AsyncPaymentsMessage, MessageSendInstructions)> {
		core::mem::take(&mut self.pending_async_payments_messages.lock().unwrap())
	}

	#[cfg(feature = "dnssec")]
	fn get_and_clear_pending_dns_messages(
		&self,
	) -> Vec<(DNSResolverMessage, MessageSendInstructions)> {
		core::mem::take(&mut self.pending_dns_onion_messages.lock().unwrap())
	}
}
