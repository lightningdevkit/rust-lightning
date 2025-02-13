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

use bitcoin::key::Secp256k1;
use bitcoin::secp256k1::{self, PublicKey};

use crate::ln::inbound_payment;
use crate::offers::invoice_error::InvoiceError;
use crate::offers::nonce::Nonce;
use crate::prelude::*;
use crate::sign::EntropySource;
use core::ops::Deref;
use core::time::Duration;

use bitcoin::secp256k1::schnorr;
use lightning_invoice::PaymentSecret;
use types::payment::PaymentHash;

use crate::blinded_path::message::{BlindedMessagePath, MessageContext, MessageForwardNode, OffersContext};
use crate::blinded_path::payment::{BlindedPaymentPath, Bolt12OfferContext, PaymentContext};
use crate::events::PaymentFailureReason;
use crate::ln::channelmanager::{Bolt12PaymentError, PaymentId, Verification};
use crate::ln::outbound_payment::RetryableInvoiceRequest;
use crate::offers::invoice::{Bolt12Invoice, DerivedSigningPubkey, ExplicitSigningPubkey, InvoiceBuilder, UnsignedBolt12Invoice, DEFAULT_RELATIVE_EXPIRY};
use crate::offers::invoice_request::InvoiceRequest;
use crate::offers::parse::Bolt12SemanticError;
use crate::onion_message::messenger::{MessageSendInstructions, Responder, ResponseInstruction};
use crate::onion_message::offers::{OffersMessage, OffersMessageHandler};
use crate::sync::MutexGuard;
use crate::onion_message::messenger::MessageRouter;
use crate::util::logger::{Logger, WithContext};

#[cfg(not(feature = "std"))]
use core::sync::atomic::Ordering;

#[cfg(async_payments)]
use crate::offers::static_invoice::StaticInvoice;

#[cfg(not(c_bindings))]
use {
	crate::ln::channelmanager::{SimpleArcChannelManager, SimpleRefChannelManager},
	crate::onion_message::messenger::DefaultMessageRouter,
	crate::routing::gossip::NetworkGraph,
	crate::sign::KeysManager,
	crate::sync::Arc,
};

/// Functions commonly shared in usage between [`ChannelManager`] & `OffersMessageFlow`
///
/// [`ChannelManager`]: crate::ln::channelmanager::ChannelManager
pub trait OffersMessageCommons {
	/// Get the current time determined by highest seen timestamp
	fn get_current_blocktime(&self) -> Duration;

	#[cfg(not(feature = "std"))]
	/// Get the approximate current time using the highest seen timestamp
	fn get_highest_seen_timestamp(&self) -> Duration;

	/// Get the vector of peers that can be used for a blinded path
	fn get_peer_for_blinded_path(&self) -> Vec<MessageForwardNode>;

	/// Creates multi-hop blinded payment paths for the given `amount_msats` by delegating to
	/// [`Router::create_blinded_payment_paths`].
	///
	/// [`Router::create_blinded_payment_paths`]: crate::routing::router::Router::create_blinded_payment_paths
	fn create_blinded_payment_paths(
		&self, amount_msats: Option<u64>, payment_secret: PaymentSecret, payment_context: PaymentContext, relative_expiry_time: u32,
	) -> Result<Vec<BlindedPaymentPath>, ()>;

	/// Gets a payment secret and payment hash for use in an invoice given to a third party wishing
	/// to pay us.
	///
	/// This differs from [`create_inbound_payment_for_hash`] only in that it generates the
	/// [`PaymentHash`] and [`PaymentPreimage`] for you.
	///
	/// The [`PaymentPreimage`] will ultimately be returned to you in the [`PaymentClaimable`] event, which
	/// will have the [`PaymentClaimable::purpose`] return `Some` for [`PaymentPurpose::preimage`]. That
	/// should then be passed directly to [`claim_funds`].
	///
	/// See [`create_inbound_payment_for_hash`] for detailed documentation on behavior and requirements.
	///
	/// Note that a malicious eavesdropper can intuit whether an inbound payment was created by
	/// `create_inbound_payment` or `create_inbound_payment_for_hash` based on runtime.
	///
	/// # Note
	///
	/// If you register an inbound payment with this method, then serialize the `ChannelManager`, then
	/// deserialize it with a node running 0.0.103 and earlier, the payment will fail to be received.
	///
	/// Errors if `min_value_msat` is greater than total bitcoin supply.
	///
	/// If `min_final_cltv_expiry_delta` is set to some value, then the payment will not be receivable
	/// on versions of LDK prior to 0.0.114.
	///
	/// [`claim_funds`]: crate::ln::channelmanager::ChannelManager::claim_funds
	/// [`PaymentClaimable`]: crate::events::Event::PaymentClaimable
	/// [`PaymentClaimable::purpose`]: crate::events::Event::PaymentClaimable::purpose
	/// [`PaymentPurpose::preimage`]: crate::events::PaymentPurpose::preimage
	/// [`create_inbound_payment_for_hash`]: crate::ln::channelmanager::ChannelManager::create_inbound_payment_for_hash
	/// [`PaymentPreimage`]: crate::types::payment::PaymentPreimage
	fn create_inbound_payment(&self, min_value_msat: Option<u64>, invoice_expiry_delta_secs: u32,
		min_final_cltv_expiry_delta: Option<u16>) -> Result<(PaymentHash, PaymentSecret), ()>;

	/// Release invoice requests awaiting invoice
	fn release_invoice_requests_awaiting_invoice(&self) -> Vec<(PaymentId, RetryableInvoiceRequest)>;

	/// Signs the [`TaggedHash`] of a BOLT 12 invoice.
	///
	/// May be called by a function passed to [`UnsignedBolt12Invoice::sign`] where `invoice` is the
	/// callee.
	///
	/// Implementors may check that the `invoice` is expected rather than blindly signing the tagged
	/// hash. An `Ok` result should sign `invoice.tagged_hash().as_digest()` with the node's signing
	/// key or an ephemeral key to preserve privacy, whichever is associated with
	/// [`UnsignedBolt12Invoice::signing_pubkey`].
	///
	/// [`TaggedHash`]: crate::offers::merkle::TaggedHash
	fn sign_bolt12_invoice(
		&self, invoice: &UnsignedBolt12Invoice,
	) -> Result<schnorr::Signature, ()>;

	/// Send payment for verified bolt12 invoice
	fn send_payment_for_verified_bolt12_invoice(&self, invoice: &Bolt12Invoice, payment_id: PaymentId) -> Result<(), Bolt12PaymentError>;

	/// Abandon Payment with Reason
	fn abandon_payment_with_reason(&self, payment_id: PaymentId, reason: PaymentFailureReason);

	// ----Temporary Functions----
	// Set of functions temporarily moved to OffersMessageCommons for easier
	// transition of code from ChannelManager to OffersMessageFlow

	/// Get pending offers messages
	fn get_pending_offers_messages(&self) -> MutexGuard<'_, Vec<(OffersMessage, MessageSendInstructions)>>;

	/// Enqueue invoice request
	fn enqueue_invoice_request(&self, invoice_request: InvoiceRequest, reply_paths: Vec<BlindedMessagePath>) -> Result<(), Bolt12SemanticError>;

	/// Initiate a new async payment
	#[cfg(async_payments)]
	fn initiate_async_payment(
		&self, invoice: &StaticInvoice, payment_id: PaymentId
	) -> Result<(), Bolt12PaymentError>;
}

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

impl<ES: Deref, OMC: Deref, MR: Deref, L: Deref> OffersMessageFlow<ES, OMC, MR, L>
where
	ES::Target: EntropySource,
	OMC::Target: OffersMessageCommons,
	MR::Target: MessageRouter,
	L::Target: Logger,
{
	fn verify_bolt12_invoice(
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

	/// Creates a collection of blinded paths by delegating to
	/// [`MessageRouter::create_blinded_paths`].
	///
	/// Errors if the `MessageRouter` errors.
	///
	/// [`MessageRouter::create_blinded_paths`]: crate::onion_message::messenger::MessageRouter::create_blinded_paths
	pub fn create_blinded_paths(
		&self, context: MessageContext,
	) -> Result<Vec<BlindedMessagePath>, ()> {
		let recipient = self.get_our_node_id();
		let secp_ctx = &self.secp_ctx;

		let peers = self.commons.get_peer_for_blinded_path()
			.into_iter()
			.map(|node| node.node_id)
			.collect();

		self.message_router
			.create_blinded_paths(recipient, context, peers, secp_ctx)
			.and_then(|paths| (!paths.is_empty()).then(|| paths).ok_or(()))
	}
}

impl<ES: Deref, OMC: Deref, M:Deref, L: Deref> OffersMessageHandler for OffersMessageFlow<ES, OMC, M, L>
where
	ES::Target: EntropySource,
	OMC::Target: OffersMessageCommons,
	M::Target: MessageRouter,
	L::Target: Logger,
{
	fn handle_message(
		&self, message: OffersMessage, context: Option<OffersContext>, responder: Option<Responder>,
	) -> Option<(OffersMessage, ResponseInstruction)> {
		let secp_ctx = &self.secp_ctx;
		let expanded_key = &self.inbound_payment_key;

		macro_rules! handle_pay_invoice_res {
			($res: expr, $invoice: expr, $logger: expr) => {{
				let error = match $res {
					Err(Bolt12PaymentError::UnknownRequiredFeatures) => {
						log_trace!(
							$logger, "Invoice requires unknown features: {:?}",
							$invoice.invoice_features()
						);
						InvoiceError::from(Bolt12SemanticError::UnknownRequiredFeatures)
					},
					Err(Bolt12PaymentError::SendingFailed(e)) => {
						log_trace!($logger, "Failed paying invoice: {:?}", e);
						InvoiceError::from_string(format!("{:?}", e))
					},
					#[cfg(async_payments)]
					Err(Bolt12PaymentError::BlindedPathCreationFailed) => {
						let err_msg = "Failed to create a blinded path back to ourselves";
						log_trace!($logger, "{}", err_msg);
						InvoiceError::from_string(err_msg.to_string())
					},
					Err(Bolt12PaymentError::UnexpectedInvoice)
						| Err(Bolt12PaymentError::DuplicateInvoice)
						| Ok(()) => return None,
				};

				match responder {
					Some(responder) => return Some((OffersMessage::InvoiceError(error), responder.respond())),
					None => {
						log_trace!($logger, "No reply path to send error: {:?}", error);
						return None
					},
				}
			}}
		}

		match message {
			OffersMessage::InvoiceRequest(invoice_request) => {
				let responder = match responder {
					Some(responder) => responder,
					None => return None,
				};

				let nonce = match context {
					None if invoice_request.metadata().is_some() => None,
					Some(OffersContext::InvoiceRequest { nonce }) => Some(nonce),
					_ => return None,
				};

				let invoice_request = match nonce {
					Some(nonce) => match invoice_request.verify_using_recipient_data(
						nonce, expanded_key, secp_ctx,
					) {
						Ok(invoice_request) => invoice_request,
						Err(()) => return None,
					},
					None => match invoice_request.verify_using_metadata(expanded_key, secp_ctx) {
						Ok(invoice_request) => invoice_request,
						Err(()) => return None,
					},
				};

				let amount_msats = match InvoiceBuilder::<DerivedSigningPubkey>::amount_msats(
					&invoice_request.inner
				) {
					Ok(amount_msats) => amount_msats,
					Err(error) => return Some((OffersMessage::InvoiceError(error.into()), responder.respond())),
				};

				let relative_expiry = DEFAULT_RELATIVE_EXPIRY.as_secs() as u32;
				let (payment_hash, payment_secret) = match self.commons.create_inbound_payment(
					Some(amount_msats), relative_expiry, None
				) {
					Ok((payment_hash, payment_secret)) => (payment_hash, payment_secret),
					Err(()) => {
						let error = Bolt12SemanticError::InvalidAmount;
						return Some((OffersMessage::InvoiceError(error.into()), responder.respond()));
					},
				};

				let payment_context = PaymentContext::Bolt12Offer(Bolt12OfferContext {
					offer_id: invoice_request.offer_id,
					invoice_request: invoice_request.fields(),
				});
				let payment_paths = match self.commons.create_blinded_payment_paths(
					Some(amount_msats), payment_secret, payment_context, relative_expiry
				) {
					Ok(payment_paths) => payment_paths,
					Err(()) => {
						let error = Bolt12SemanticError::MissingPaths;
						return Some((OffersMessage::InvoiceError(error.into()), responder.respond()));
					},
				};

				#[cfg(not(feature = "std"))]
				let created_at = self.commons.get_highest_seen_timestamp();

				let response = if invoice_request.keys.is_some() {
					#[cfg(feature = "std")]
					let builder = invoice_request.respond_using_derived_keys(
						payment_paths, payment_hash
					);
					#[cfg(not(feature = "std"))]
					let builder = invoice_request.respond_using_derived_keys_no_std(
						payment_paths, payment_hash, created_at
					);
					builder
						.map(InvoiceBuilder::<DerivedSigningPubkey>::from)
						.and_then(|builder| builder.allow_mpp().build_and_sign(secp_ctx))
						.map_err(InvoiceError::from)
				} else {
					#[cfg(feature = "std")]
					let builder = invoice_request.respond_with(payment_paths, payment_hash);
					#[cfg(not(feature = "std"))]
					let builder = invoice_request.respond_with_no_std(
						payment_paths, payment_hash, created_at
					);
					builder
						.map(InvoiceBuilder::<ExplicitSigningPubkey>::from)
						.and_then(|builder| builder.allow_mpp().build())
						.map_err(InvoiceError::from)
						.and_then(|invoice| {
							#[cfg(c_bindings)]
							let mut invoice = invoice;
							invoice
								.sign(|invoice: &UnsignedBolt12Invoice|
									self.commons.sign_bolt12_invoice(invoice)
								)
								.map_err(InvoiceError::from)
						})
				};

				match response {
					Ok(invoice) => {
						let nonce = Nonce::from_entropy_source(&*self.entropy_source);
						let hmac = payment_hash.hmac_for_offer_payment(nonce, expanded_key);
						let context = MessageContext::Offers(OffersContext::InboundPayment { payment_hash, nonce, hmac });
						Some((OffersMessage::Invoice(invoice), responder.respond_with_reply_path(context)))
					},
					Err(error) => Some((OffersMessage::InvoiceError(error.into()), responder.respond())),
				}
			},
			OffersMessage::Invoice(invoice) => {
				let payment_id = match self.verify_bolt12_invoice(&invoice, context.as_ref()) {
					Ok(payment_id) => payment_id,
					Err(()) => return None,
				};

				let logger = WithContext::from(
					&self.logger, None, None, Some(invoice.payment_hash()),
				);

				let res = self.commons.send_payment_for_verified_bolt12_invoice(&invoice, payment_id);
				handle_pay_invoice_res!(res, invoice, logger);
			},
			#[cfg(async_payments)]
			OffersMessage::StaticInvoice(invoice) => {
				let payment_id = match context {
					Some(OffersContext::OutboundPayment { payment_id, nonce, hmac: Some(hmac) }) => {
						if payment_id.verify_for_offer_payment(hmac, nonce, expanded_key).is_err() {
							return None
						}
						payment_id
					},
					_ => return None
				};
				let res = self.commons.initiate_async_payment(&invoice, payment_id);
				handle_pay_invoice_res!(res, invoice, self.logger);
			},
			OffersMessage::InvoiceError(invoice_error) => {
				let payment_hash = match context {
					Some(OffersContext::InboundPayment { payment_hash, nonce, hmac }) => {
						match payment_hash.verify_for_offer_payment(hmac, nonce, expanded_key) {
							Ok(_) => Some(payment_hash),
							Err(_) => None,
						}
					},
					_ => None,
				};

				let logger = WithContext::from(&self.logger, None, None, payment_hash);
				log_trace!(logger, "Received invoice_error: {}", invoice_error);

				match context {
					Some(OffersContext::OutboundPayment { payment_id, nonce, hmac: Some(hmac) }) => {
						if let Ok(()) = payment_id.verify_for_offer_payment(hmac, nonce, expanded_key) {
							self.commons.abandon_payment_with_reason(
								payment_id, PaymentFailureReason::InvoiceRequestRejected,
							);
						}
					},
					_ => {},
				}

				None
			},
		}
	}

	fn message_received(&self) {
		for (payment_id, retryable_invoice_request) in self
			.commons
			.release_invoice_requests_awaiting_invoice()
		{
			let RetryableInvoiceRequest { invoice_request, nonce, .. } = retryable_invoice_request;
			let hmac = payment_id.hmac_for_offer_payment(nonce, &self.inbound_payment_key);
			let context = MessageContext::Offers(OffersContext::OutboundPayment {
				payment_id,
				nonce,
				hmac: Some(hmac)
			});
			match self.create_blinded_paths(context) {
				Ok(reply_paths) => match self.commons.enqueue_invoice_request(invoice_request, reply_paths) {
					Ok(_) => {}
					Err(_) => {
						log_warn!(self.logger,
							"Retry failed for an invoice request with payment_id: {}",
							payment_id
						);
					}
				},
				Err(_) => {
					log_warn!(self.logger,
						"Retry failed for an invoice request with payment_id: {}. \
							Reason: router could not find a blinded path to include as the reply path",
						payment_id
					);
				}
			}
		}
	}

	fn release_pending_messages(&self) -> Vec<(OffersMessage, MessageSendInstructions)> {
		core::mem::take(&mut self.commons.get_pending_offers_messages())
	}
}

