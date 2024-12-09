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

use crate::prelude::*;
use core::ops::Deref;
#[cfg(not(feature = "std"))]
use core::sync::atomic::Ordering;
use core::time::Duration;

use bitcoin::constants::ChainHash;
use bitcoin::secp256k1::{self, schnorr, PublicKey, Secp256k1};
use lightning_invoice::PaymentSecret;
use types::payment::PaymentHash;

use crate::blinded_path::message::{
	BlindedMessagePath, MessageContext, MessageForwardNode, OffersContext,
};
use crate::blinded_path::payment::{
	BlindedPaymentPath, Bolt12OfferContext, Bolt12RefundContext, PaymentContext,
};
use crate::events::PaymentFailureReason;
use crate::ln::channelmanager::{Bolt12PaymentError, PaymentId, Verification};
use crate::ln::inbound_payment;
use crate::ln::outbound_payment::{Retry, RetryableInvoiceRequest, StaleExpiration};
use crate::offers::invoice::{
	Bolt12Invoice, DerivedSigningPubkey, ExplicitSigningPubkey, InvoiceBuilder,
	UnsignedBolt12Invoice, DEFAULT_RELATIVE_EXPIRY,
};
use crate::offers::invoice_request::{InvoiceRequest, InvoiceRequestBuilder};
use crate::offers::parse::Bolt12SemanticError;
use crate::onion_message::dns_resolution::HumanReadableName;
use crate::onion_message::messenger::{
	Destination, MessageRouter, MessageSendInstructions, Responder, ResponseInstruction,
};
use crate::onion_message::offers::{OffersMessage, OffersMessageHandler};

use crate::offers::invoice_error::InvoiceError;
use crate::offers::nonce::Nonce;
use crate::offers::offer::{DerivedMetadata, Offer, OfferBuilder};
use crate::offers::refund::{Refund, RefundBuilder};

use crate::sign::EntropySource;
use crate::sync::Mutex;
use crate::util::logger::{Logger, WithContext};

#[cfg(c_bindings)]
use {
	crate::offers::offer::OfferWithDerivedMetadataBuilder,
	crate::offers::refund::RefundMaybeWithDerivedMetadataBuilder,
};

#[cfg(feature = "dnssec")]
use {
	crate::blinded_path::message::DNSResolverContext,
	crate::onion_message::dns_resolution::{
		DNSResolverMessage, DNSResolverMessageHandler, DNSSECProof, DNSSECQuery, OMNameResolver,
	},
};

/// Functions commonly shared in usage between [`ChannelManager`] & `OffersMessageFlow`
///
/// [`ChannelManager`]: crate::ln::channelmanager::ChannelManager
pub trait OffersMessageCommons {
	#[cfg(feature = "dnssec")]
	/// Get hrn resolver
	fn get_hrn_resolver(&self) -> &OMNameResolver;

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
	fn create_inbound_payment(
		&self, min_value_msat: Option<u64>, invoice_expiry_delta_secs: u32,
		min_final_cltv_expiry_delta: Option<u16>,
	) -> Result<(PaymentHash, PaymentSecret), ()>;

	/// Creates multi-hop blinded payment paths for the given `amount_msats` by delegating to
	/// [`Router::create_blinded_payment_paths`].
	///
	/// [`Router::create_blinded_payment_paths`]: crate::routing::router::Router::create_blinded_payment_paths
	fn create_blinded_payment_paths(
		&self, amount_msats: u64, payment_secret: PaymentSecret, payment_context: PaymentContext,
	) -> Result<Vec<BlindedPaymentPath>, ()>;

	/// Get the vector of peers that can be used for a blinded path
	fn get_peer_for_blinded_path(&self) -> Vec<MessageForwardNode>;

	/// Send payment for verified bolt12 invoice
	fn send_payment_for_verified_bolt12_invoice(
		&self, invoice: &Bolt12Invoice, payment_id: PaymentId,
	) -> Result<(), Bolt12PaymentError>;

	/// Abandon Payment with Reason
	fn abandon_payment_with_reason(&self, payment_id: PaymentId, reason: PaymentFailureReason);

	/// Release invoice requests awaiting invoice
	fn release_invoice_requests_awaiting_invoice(
		&self,
	) -> Vec<(PaymentId, RetryableInvoiceRequest)>;

	/// Creates a collection of blinded paths by delegating to
	/// [`MessageRouter::create_blinded_paths`].
	///
	/// Errors if the `MessageRouter` errors.
	///
	/// [`MessageRouter::create_blinded_paths`]: crate::onion_message::messenger::MessageRouter::create_blinded_paths
	fn create_blinded_paths(&self, context: MessageContext) -> Result<Vec<BlindedMessagePath>, ()>;

	/// Get the current time determined by highest seen timestamp
	fn get_current_blocktime(&self) -> Duration;

	/// Get the [`ChainHash`] of the chain
	fn get_chain_hash(&self) -> ChainHash;

	/// Add new awaiting invoice
	fn add_new_awaiting_invoice(
		&self, payment_id: PaymentId, expiration: StaleExpiration, retry_strategy: Retry,
		max_total_routing_fee_msat: Option<u64>,
		retryable_invoice_request: Option<RetryableInvoiceRequest>,
	) -> Result<(), ()>;

	#[cfg(feature = "dnssec")]
	/// Add new awaiting offer
	fn add_new_awaiting_offer(
		&self, payment_id: PaymentId, expiration: StaleExpiration, retry_strategy: Retry,
		max_total_routing_fee_msat: Option<u64>, amount_msats: u64,
	) -> Result<(), ()>;

	#[cfg(feature = "dnssec")]
	/// Amount for payment awaiting offer
	fn amt_msats_for_payment_awaiting_offer(&self, payment_id: PaymentId) -> Result<u64, ()>;

	#[cfg(feature = "dnssec")]
	/// Received Offer
	fn received_offer(
		&self, payment_id: PaymentId, retryable_invoice_request: Option<RetryableInvoiceRequest>,
	) -> Result<(), ()>;

	#[cfg(not(feature = "std"))]
	/// Get the approximate current time using the highest seen timestamp
	fn get_highest_seen_timestamp(&self) -> Duration;
}

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
/// - [`EntropySource`] to provide cryptographic randomness essential for Offers message handling.
/// - [`Logger`] for detailed operational logging of Offers-related activity.
/// - [`OffersMessageCommons`] for core operations shared across Offers messages, such as metadata
///   verification and signature handling.
/// - [`MessageRouter`] for routing Offers messages to their appropriate destinations within the
///   Lightning network.
/// - Manages [`OffersMessage`] for creating and processing Offers-related messages.
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
/// ## Relationship with `ChannelManager`
///
/// [`OffersMessageFlow`] and [`ChannelManager`] work in tandem to facilitate BOLT 12 functionality within
/// a Lightning node:
/// - The `OffersMessageFlow` is responsible for creating, managing, and verifying Offers messages,
///   such as BOLT 12 invoices and refunds.
/// - The `ChannelManager` manages the lifecycle of payments tied to these Offers messages, handling
///   tasks like payment execution, tracking payment states, and processing related events.
///
/// The relationship is further reinforced through the [`OffersMessageCommons`] trait:
/// - `ChannelManager` implements the [`OffersMessageCommons`] trait, providing shared functionality
///   such as metadata verification and signature handling.
/// - `OffersMessageFlow` relies on this trait to perform common operations, enabling it to delegate
///   these tasks to `ChannelManager` by default.
///
/// Practical Use Case:
/// - A BOLT 12 Offer is created using `OffersMessageFlow`, which provides the necessary interface
///   for Offer creation and invoice generation.
/// - Once a payment is initiated for the Offer, `ChannelManager` takes over, managing the payment's
///   lifecycle, including retries, claims, and event handling.
/// - Events such as `Event::PaymentClaimable` or `Event::PaymentFailed` are processed by
///   `ChannelManager`, which may invoke functionality defined in `OffersMessageCommons` to support
///   Offers-related operations.
///
/// This modular and decoupled design ensures that `OffersMessageFlow` and `ChannelManager` can
/// operate independently while maintaining a seamless integration for handling Offers and payments
/// in the Lightning network.
///
/// ## BOLT 12 Offers
///
/// The [`offers`] module is useful for creating BOLT 12 offers. An [`Offer`] is a precursor to a
/// [`Bolt12Invoice`], which must first be requested by the payer. The interchange of these messages
/// as defined in the specification is handled by [`OffersMessageFlow`] and its implementation of
/// [`OffersMessageHandler`]. However, this only works with an [`Offer`] created using a builder
/// returned by [`create_offer_builder`]. With this approach, BOLT 12 offers and invoices are
/// stateless just as BOLT 11 invoices are.
///
/// ```
/// # use lightning::events::{Event, EventsProvider, PaymentPurpose};
/// # use lightning::ln::channelmanager::AChannelManager;
/// # use lightning::offers::flow::AnOffersMessageFlow;
/// # use lightning::offers::parse::Bolt12SemanticError;
///
/// #
/// # fn example<T: AnOffersMessageFlow, U: AChannelManager>(offers_flow: T, channel_manager: U) -> Result<(), Bolt12SemanticError> {
/// # let offers_flow = offers_flow.get_omf();
/// # let channel_manager = channel_manager.get_cm();
/// # let absolute_expiry = None;
/// # let offer = offers_flow
///     .create_offer_builder(absolute_expiry)?
/// # ;
/// # // Needed for compiling for c_bindings
/// # let builder: lightning::offers::offer::OfferBuilder<_, _> = offer.into();
/// # let offer = builder
///     .description("coffee".to_string())
///     .amount_msats(10_000_000)
///     .build()?;
/// let bech32_offer = offer.to_string();
///
/// // On the event processing thread
/// channel_manager.process_pending_events(&|event| {
///     match event {
///         Event::PaymentClaimable { payment_hash, purpose, .. } => match purpose {
///             PaymentPurpose::Bolt12OfferPayment { payment_preimage: Some(payment_preimage), .. } => {
///                 println!("Claiming payment {}", payment_hash);
///                 channel_manager.claim_funds(payment_preimage);
///             },
///             PaymentPurpose::Bolt12OfferPayment { payment_preimage: None, .. } => {
///                 println!("Unknown payment hash: {}", payment_hash);
///             }
/// #           _ => {},
///         },
///         Event::PaymentClaimed { payment_hash, amount_msat, .. } => {
///             println!("Claimed {} msats", amount_msat);
///         },
///         // ...
///     #     _ => {},
///     }
///     Ok(())
/// });
/// # Ok(())
/// # }
/// ```
///
/// A [`Refund`] is a request for an invoice to be paid. Like *paying* for an [`Offer`], *creating*
/// a [`Refund`] involves maintaining state since it represents a future outbound payment.
/// Therefore, use [`create_refund_builder`] when creating one, otherwise [`OffersMessageFlow`] will
/// refuse to pay any corresponding [`Bolt12Invoice`] that it receives.
///
/// ```
/// # use core::time::Duration;
/// # use lightning::events::{Event, EventsProvider};
/// # use lightning::ln::channelmanager::{AChannelManager, PaymentId, RecentPaymentDetails, Retry};
/// # use lightning::offers::flow::AnOffersMessageFlow;
/// # use lightning::offers::parse::Bolt12SemanticError;
/// #
/// # fn example<T: AnOffersMessageFlow, U: AChannelManager>(
/// #     offers_flow: T, channel_manager: U, amount_msats: u64, absolute_expiry: Duration, retry: Retry,
/// #     max_total_routing_fee_msat: Option<u64>
/// # ) -> Result<(), Bolt12SemanticError> {
/// # let offers_flow = offers_flow.get_omf();
/// # let channel_manager = channel_manager.get_cm();
/// # let payment_id = PaymentId([42; 32]);
/// # let refund = offers_flow
///     .create_refund_builder(
///         amount_msats, absolute_expiry, payment_id, retry, max_total_routing_fee_msat
///     )?
/// # ;
/// # // Needed for compiling for c_bindings
/// # let builder: lightning::offers::refund::RefundBuilder<_> = refund.into();
/// # let refund = builder
///     .description("coffee".to_string())
///     .payer_note("refund for order 1234".to_string())
///     .build()?;
/// let bech32_refund = refund.to_string();
///
/// // First the payment will be waiting on an invoice
/// let expected_payment_id = payment_id;
/// assert!(
///     channel_manager.list_recent_payments().iter().find(|details| matches!(
///         details,
///         RecentPaymentDetails::AwaitingInvoice { payment_id: expected_payment_id }
///     )).is_some()
/// );
///
/// // Once the invoice is received, a payment will be sent
/// assert!(
///     channel_manager.list_recent_payments().iter().find(|details| matches!(
///         details,
///         RecentPaymentDetails::Pending { payment_id: expected_payment_id, ..  }
///     )).is_some()
/// );
///
/// // On the event processing thread
/// channel_manager.process_pending_events(&|event| {
///     match event {
///         Event::PaymentSent { payment_id: Some(payment_id), .. } => println!("Paid {}", payment_id),
///         Event::PaymentFailed { payment_id, .. } => println!("Failed paying {}", payment_id),
///         // ...
///     #     _ => {},
///     }
///     Ok(())
/// });
/// # Ok(())
/// # }
/// ```
///
/// Use [`pay_for_offer`] to initiated payment, which sends an [`InvoiceRequest`] for an [`Offer`]
/// and pays the [`Bolt12Invoice`] response.
///
/// ```
/// # use lightning::events::{Event, EventsProvider};
/// # use lightning::ln::channelmanager::{AChannelManager, PaymentId, RecentPaymentDetails, Retry};
/// # use lightning::offers::flow::{AnOffersMessageFlow, OffersMessageCommons};
/// # use lightning::offers::offer::Offer;
/// #
/// # fn example<T: AnOffersMessageFlow, U: AChannelManager>(
/// #     offers_flow: T, channel_manager: U, offer: &Offer, quantity: Option<u64>, amount_msats: Option<u64>,
/// #     payer_note: Option<String>, retry: Retry, max_total_routing_fee_msat: Option<u64>
/// # ) {
/// # let offers_flow = offers_flow.get_omf();
/// # let channel_manager = channel_manager.get_cm();
/// let payment_id = PaymentId([42; 32]);
/// match offers_flow.pay_for_offer(
///     offer, quantity, amount_msats, payer_note, payment_id, retry, max_total_routing_fee_msat
/// ) {
///     Ok(()) => println!("Requesting invoice for offer"),
///     Err(e) => println!("Unable to request invoice for offer: {:?}", e),
/// }
///
/// // First the payment will be waiting on an invoice
/// let expected_payment_id = payment_id;
/// assert!(
///     channel_manager.list_recent_payments().iter().find(|details| matches!(
///         details,
///         RecentPaymentDetails::AwaitingInvoice { payment_id: expected_payment_id }
///     )).is_some()
/// );
///
/// // Once the invoice is received, a payment will be sent
/// assert!(
///     channel_manager.list_recent_payments().iter().find(|details| matches!(
///         details,
///         RecentPaymentDetails::Pending { payment_id: expected_payment_id, ..  }
///     )).is_some()
/// );
///
/// // On the event processing thread
/// channel_manager.process_pending_events(&|event| {
///     match event {
///         Event::PaymentSent { payment_id: Some(payment_id), .. } => println!("Paid {}", payment_id),
///         Event::PaymentFailed { payment_id, .. } => println!("Failed paying {}", payment_id),
///         // ...
///     #     _ => {},
///     }
///     Ok(())
/// });
/// # }
/// ```
///
/// ## BOLT 12 Refunds
///
/// Use [`request_refund_payment`] to send a [`Bolt12Invoice`] for receiving the refund. Similar to
/// *creating* an [`Offer`], this is stateless as it represents an inbound payment.
///
/// ```
/// # use lightning::events::{Event, EventsProvider, PaymentPurpose};
/// # use lightning::ln::channelmanager::AChannelManager;
/// # use lightning::offers::flow::{AnOffersMessageFlow, OffersMessageCommons};
/// # use lightning::offers::refund::Refund;
/// #
/// # fn example<T: AnOffersMessageFlow, U: AChannelManager>(offers_flow: T, channel_manager: U, refund: &Refund) {
/// # let offers_flow = offers_flow.get_omf();
/// # let channel_manager = channel_manager.get_cm();
/// let known_payment_hash = match offers_flow.request_refund_payment(refund) {
///     Ok(invoice) => {
///         let payment_hash = invoice.payment_hash();
///         println!("Requesting refund payment {}", payment_hash);
///         payment_hash
///     },
///     Err(e) => panic!("Unable to request payment for refund: {:?}", e),
/// };
///
/// // On the event processing thread
/// channel_manager.process_pending_events(&|event| {
///     match event {
///         Event::PaymentClaimable { payment_hash, purpose, .. } => match purpose {
///             PaymentPurpose::Bolt12RefundPayment { payment_preimage: Some(payment_preimage), .. } => {
///                 assert_eq!(payment_hash, known_payment_hash);
///                 println!("Claiming payment {}", payment_hash);
///                 channel_manager.claim_funds(payment_preimage);
///             },
///             PaymentPurpose::Bolt12RefundPayment { payment_preimage: None, .. } => {
///                 println!("Unknown payment hash: {}", payment_hash);
///             },
///             // ...
/// #           _ => {},
///     },
///     Event::PaymentClaimed { payment_hash, amount_msat, .. } => {
///         assert_eq!(payment_hash, known_payment_hash);
///         println!("Claimed {} msats", amount_msat);
///     },
///     // ...
/// #     _ => {},
///     }
///     Ok(())
/// });
/// # }
/// ```
///
/// [`DNSResolverMessage`]: crate::onion_message::dns_resolution::DNSResolverMessage
/// [`ChannelManager`]: crate::ln::channelmanager::ChannelManager
/// [`Bolt12Invoice`]: crate::offers::invoice
/// [`create_offer_builder`]: Self::create_offer_builder
/// [`create_refund_builder`]: Self::create_refund_builder
/// [`Refund`]: crate::offers::refund::Refund
/// [`InvoiceRequest`]: crate::offers::invoice_request
/// [`Offer`]: crate::offers::offer
/// [`offers`]: crate::offers
/// [`pay_for_offer`]: Self::pay_for_offer
/// [`request_refund_payment`]: Self::request_refund_payment
pub struct OffersMessageFlow<ES: Deref, OMC: Deref, MR: Deref, L: Deref>
where
	ES::Target: EntropySource,
	OMC::Target: OffersMessageCommons,
	MR::Target: MessageRouter,
	L::Target: Logger,
{
	inbound_payment_key: inbound_payment::ExpandedKey,
	our_network_pubkey: PublicKey,

	secp_ctx: Secp256k1<secp256k1::All>,

	entropy_source: ES,

	/// Contains functions shared between OffersMessageHandler and ChannelManager.
	commons: OMC,

	message_router: MR,

	#[cfg(not(any(test, feature = "_test_utils")))]
	pending_offers_messages: Mutex<Vec<(OffersMessage, MessageSendInstructions)>>,
	#[cfg(any(test, feature = "_test_utils"))]
	pub(crate) pending_offers_messages: Mutex<Vec<(OffersMessage, MessageSendInstructions)>>,

	#[cfg(feature = "dnssec")]
	pending_dns_onion_messages: Mutex<Vec<(DNSResolverMessage, MessageSendInstructions)>>,

	#[cfg(feature = "_test_utils")]
	/// In testing, it is useful be able to forge a name -> offer mapping so that we can pay an
	/// offer generated in the test.
	///
	/// This allows for doing so, validating proofs as normal, but, if they pass, replacing the
	/// offer they resolve to to the given one.
	pub testing_dnssec_proof_offer_resolution_override: Mutex<HashMap<HumanReadableName, Offer>>,

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
			inbound_payment_key: expanded_inbound_key,
			our_network_pubkey,
			secp_ctx,
			entropy_source,

			commons,

			message_router,

			pending_offers_messages: Mutex::new(Vec::new()),

			#[cfg(feature = "dnssec")]
			pending_dns_onion_messages: Mutex::new(Vec::new()),

			#[cfg(feature = "_test_utils")]
			testing_dnssec_proof_offer_resolution_override: Mutex::new(new_hash_map()),
			logger,
		}
	}

	/// Gets the node_id held by this OffersMessageFlow
	pub fn get_our_node_id(&self) -> PublicKey {
		self.our_network_pubkey
	}
}

/// The maximum expiration from the current time where an [`Offer`] or [`Refund`] is considered
/// short-lived, while anything with a greater expiration is considered long-lived.
///
/// Using [`OffersMessageFlow::create_offer_builder`] or [`OffersMessageFlow::create_refund_builder`],
/// will included a [`BlindedMessagePath`] created using:
/// - [`MessageRouter::create_compact_blinded_paths`] when short-lived, and
/// - [`MessageRouter::create_blinded_paths`] when long-lived.
///
/// [`OffersMessageFlow::create_offer_builder`]: crate::offers::flow::OffersMessageFlow::create_offer_builder
/// [`OffersMessageFlow::create_refund_builder`]: crate::offers::flow::OffersMessageFlow::create_refund_builder
///
///
/// Using compact [`BlindedMessagePath`]s may provide better privacy as the [`MessageRouter`] could select
/// more hops. However, since they use short channel ids instead of pubkeys, they are more likely to
/// become invalid over time as channels are closed. Thus, they are only suitable for short-term use.
///
/// [`Offer`]: crate::offers::offer
/// [`Refund`]: crate::offers::refund
pub const MAX_SHORT_LIVED_RELATIVE_EXPIRY: Duration = Duration::from_secs(60 * 60 * 24);

/// Defines the maximum number of [`OffersMessage`] including different reply paths to be sent
/// along different paths.
/// Sending multiple requests increases the chances of successful delivery in case some
/// paths are unavailable. However, only one invoice for a given [`PaymentId`] will be paid,
/// even if multiple invoices are received.
pub const OFFERS_MESSAGE_REQUEST_LIMIT: usize = 10;

impl<ES: Deref, OMC: Deref, MR: Deref, L: Deref> OffersMessageFlow<ES, OMC, MR, L>
where
	ES::Target: EntropySource,
	OMC::Target: OffersMessageCommons,
	MR::Target: MessageRouter,
	L::Target: Logger,
{
	/// Creates a collection of blinded paths by delegating to [`MessageRouter`] based on
	/// the path's intended lifetime.
	///
	/// Whether or not the path is compact depends on whether the path is short-lived or long-lived,
	/// respectively, based on the given `absolute_expiry` as seconds since the Unix epoch. See
	/// [`MAX_SHORT_LIVED_RELATIVE_EXPIRY`].
	pub fn create_blinded_paths_using_absolute_expiry(
		&self, context: OffersContext, absolute_expiry: Option<Duration>,
	) -> Result<Vec<BlindedMessagePath>, ()> {
		let now = self.duration_since_epoch();
		let max_short_lived_absolute_expiry = now.saturating_add(MAX_SHORT_LIVED_RELATIVE_EXPIRY);

		if absolute_expiry.unwrap_or(Duration::MAX) <= max_short_lived_absolute_expiry {
			self.create_compact_blinded_paths(context)
		} else {
			self.commons.create_blinded_paths(MessageContext::Offers(context))
		}
	}

	pub(crate) fn duration_since_epoch(&self) -> Duration {
		#[cfg(not(feature = "std"))]
		let now = self.commons.get_highest_seen_timestamp();
		#[cfg(feature = "std")]
		let now = std::time::SystemTime::now()
			.duration_since(std::time::SystemTime::UNIX_EPOCH)
			.expect("SystemTime::now() should come after SystemTime::UNIX_EPOCH");

		now
	}

	/// Creates a collection of blinded paths by delegating to
	/// [`MessageRouter::create_compact_blinded_paths`].
	///
	/// Errors if the `MessageRouter` errors.
	fn create_compact_blinded_paths(
		&self, context: OffersContext,
	) -> Result<Vec<BlindedMessagePath>, ()> {
		let recipient = self.get_our_node_id();
		let secp_ctx = &self.secp_ctx;

		let peers = self.commons.get_peer_for_blinded_path();

		self.message_router
			.create_compact_blinded_paths(
				recipient,
				MessageContext::Offers(context),
				peers,
				secp_ctx,
			)
			.and_then(|paths| (!paths.is_empty()).then(|| paths).ok_or(()))
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
}

impl<ES: Deref, OMC: Deref, MR: Deref, L: Deref> OffersMessageFlow<ES, OMC, MR, L>
where
	ES::Target: EntropySource,
	OMC::Target: OffersMessageCommons,
	MR::Target: MessageRouter,
	L::Target: Logger,
{
	fn pay_for_offer_intern<
		CPP: FnOnce(&InvoiceRequest, Nonce) -> Result<(), Bolt12SemanticError>,
	>(
		&self, offer: &Offer, quantity: Option<u64>, amount_msats: Option<u64>,
		payer_note: Option<String>, payment_id: PaymentId,
		human_readable_name: Option<HumanReadableName>, create_pending_payment: CPP,
	) -> Result<(), Bolt12SemanticError> {
		let expanded_key = &self.inbound_payment_key;
		let entropy = &*self.entropy_source;
		let secp_ctx = &self.secp_ctx;

		let nonce = Nonce::from_entropy_source(entropy);
		let builder: InvoiceRequestBuilder<secp256k1::All> =
			offer.request_invoice(expanded_key, nonce, secp_ctx, payment_id)?.into();
		let builder = builder.chain_hash(self.commons.get_chain_hash())?;

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
		let invoice_request = builder.build_and_sign()?;

		let hmac = payment_id.hmac_for_offer_payment(nonce, expanded_key);
		let context = MessageContext::Offers(OffersContext::OutboundPayment {
			payment_id,
			nonce,
			hmac: Some(hmac),
		});
		let reply_paths = self
			.commons
			.create_blinded_paths(context)
			.map_err(|_| Bolt12SemanticError::MissingPaths)?;

		create_pending_payment(&invoice_request, nonce)?;

		self.enqueue_invoice_request(invoice_request, reply_paths)
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

	/// Pays the [`Bolt12Invoice`] associated with the `payment_id` encoded in its `payer_metadata`.
	///
	/// The invoice's `payer_metadata` is used to authenticate that the invoice was indeed requested
	/// before attempting a payment. [`Bolt12PaymentError::UnexpectedInvoice`] is returned if this
	/// fails or if the encoded `payment_id` is not recognized. The latter may happen once the
	/// payment is no longer tracked because the payment was attempted after:
	/// - an invoice for the `payment_id` was already paid,
	/// - one full [timer tick] has elapsed since initially requesting the invoice when paying an
	///   offer, or
	/// - the refund corresponding to the invoice has already expired.
	///
	/// To retry the payment, request another invoice using a new `payment_id`.
	///
	/// Attempting to pay the same invoice twice while the first payment is still pending will
	/// result in a [`Bolt12PaymentError::DuplicateInvoice`].
	///
	/// Otherwise, either [`Event::PaymentSent`] or [`Event::PaymentFailed`] are used to indicate
	/// whether or not the payment was successful.
	///
	/// [`Event::PaymentSent`]: crate::events::Event::PaymentSent
	/// [`Event::PaymentFailed`]: crate::events::Event::PaymentFailed
	/// [timer tick]: crate::ln::channelmanager::ChannelManager::timer_tick_occurred
	pub fn send_payment_for_bolt12_invoice(
		&self, invoice: &Bolt12Invoice, context: Option<&OffersContext>,
	) -> Result<(), Bolt12PaymentError> {
		match self.verify_bolt12_invoice(invoice, context) {
			Ok(payment_id) => {
				self.commons.send_payment_for_verified_bolt12_invoice(invoice, payment_id)
			},
			Err(()) => Err(Bolt12PaymentError::UnexpectedInvoice),
		}
	}
}

impl<ES: Deref, OMC: Deref, MR: Deref, L: Deref> OffersMessageHandler
	for OffersMessageFlow<ES, OMC, MR, L>
where
	ES::Target: EntropySource,
	OMC::Target: OffersMessageCommons,
	MR::Target: MessageRouter,
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
							$logger,
							"Invoice requires unknown features: {:?}",
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
					Some(responder) => {
						return Some((OffersMessage::InvoiceError(error), responder.respond()))
					},
					None => {
						log_trace!($logger, "No reply path to send error: {:?}", error);
						return None;
					},
				}
			}};
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
						nonce,
						expanded_key,
						secp_ctx,
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
					&invoice_request.inner,
				) {
					Ok(amount_msats) => amount_msats,
					Err(error) => {
						return Some((
							OffersMessage::InvoiceError(error.into()),
							responder.respond(),
						))
					},
				};

				let relative_expiry = DEFAULT_RELATIVE_EXPIRY.as_secs() as u32;
				let (payment_hash, payment_secret) = match self.commons.create_inbound_payment(
					Some(amount_msats),
					relative_expiry,
					None,
				) {
					Ok((payment_hash, payment_secret)) => (payment_hash, payment_secret),
					Err(()) => {
						let error = Bolt12SemanticError::InvalidAmount;
						return Some((
							OffersMessage::InvoiceError(error.into()),
							responder.respond(),
						));
					},
				};

				let payment_context = PaymentContext::Bolt12Offer(Bolt12OfferContext {
					offer_id: invoice_request.offer_id,
					invoice_request: invoice_request.fields(),
				});
				let payment_paths = match self.commons.create_blinded_payment_paths(
					amount_msats,
					payment_secret,
					payment_context,
				) {
					Ok(payment_paths) => payment_paths,
					Err(()) => {
						let error = Bolt12SemanticError::MissingPaths;
						return Some((
							OffersMessage::InvoiceError(error.into()),
							responder.respond(),
						));
					},
				};

				#[cfg(not(feature = "std"))]
				let created_at = self.commons.get_current_blocktime();

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
								.sign(|invoice: &UnsignedBolt12Invoice| {
									self.commons.sign_bolt12_invoice(invoice)
								})
								.map_err(InvoiceError::from)
						})
				};

				match response {
					Ok(invoice) => {
						let nonce = Nonce::from_entropy_source(&*self.entropy_source);
						let hmac = payment_hash.hmac_for_offer_payment(nonce, expanded_key);
						let context = MessageContext::Offers(OffersContext::InboundPayment {
							payment_hash,
							nonce,
							hmac,
						});
						Some((
							OffersMessage::Invoice(invoice),
							responder.respond_with_reply_path(context),
						))
					},
					Err(error) => {
						Some((OffersMessage::InvoiceError(error.into()), responder.respond()))
					},
				}
			},
			OffersMessage::Invoice(invoice) => {
				let payment_id = match self.verify_bolt12_invoice(&invoice, context.as_ref()) {
					Ok(payment_id) => payment_id,
					Err(()) => return None,
				};

				let logger =
					WithContext::from(&self.logger, None, None, Some(invoice.payment_hash()));

				let res =
					self.commons.send_payment_for_verified_bolt12_invoice(&invoice, payment_id);
				handle_pay_invoice_res!(res, invoice, logger);
			},
			#[cfg(async_payments)]
			OffersMessage::StaticInvoice(invoice) => {
				let payment_id = match context {
					Some(OffersContext::OutboundPayment {
						payment_id,
						nonce,
						hmac: Some(hmac),
					}) => {
						if payment_id.verify_for_offer_payment(hmac, nonce, expanded_key).is_err() {
							return None;
						}
						payment_id
					},
					_ => return None,
				};
				let res = self.initiate_async_payment(&invoice, payment_id);
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
					Some(OffersContext::OutboundPayment {
						payment_id,
						nonce,
						hmac: Some(hmac),
					}) => {
						if let Ok(()) =
							payment_id.verify_for_offer_payment(hmac, nonce, expanded_key)
						{
							self.commons.abandon_payment_with_reason(
								payment_id,
								PaymentFailureReason::InvoiceRequestRejected,
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
		for (payment_id, retryable_invoice_request) in
			self.commons.release_invoice_requests_awaiting_invoice()
		{
			let RetryableInvoiceRequest { invoice_request, nonce } = retryable_invoice_request;
			let hmac = payment_id.hmac_for_offer_payment(nonce, &self.inbound_payment_key);
			let context = MessageContext::Offers(OffersContext::OutboundPayment {
				payment_id,
				nonce,
				hmac: Some(hmac),
			});
			match self.commons.create_blinded_paths(context) {
				Ok(reply_paths) => {
					match self.enqueue_invoice_request(invoice_request, reply_paths) {
						Ok(_) => {},
						Err(_) => {
							log_warn!(
								self.logger,
								"Retry failed for an invoice request with payment_id: {}",
								payment_id
							);
						},
					}
				},
				Err(_) => {
					log_warn!(
						self.logger,
						"Retry failed for an invoice request with payment_id: {}. \
							Reason: router could not find a blinded path to include as the reply path",
						payment_id
					);
				},
			}
		}
	}

	fn release_pending_messages(&self) -> Vec<(OffersMessage, MessageSendInstructions)> {
		core::mem::take(&mut self.pending_offers_messages.lock().unwrap())
	}
}

macro_rules! create_offer_builder { ($self: ident, $builder: ty) => {
	/// Creates an [`OfferBuilder`] such that the [`Offer`] it builds is recognized by the
	/// [`OffersMessageFlow`] when handling [`InvoiceRequest`] messages for the offer. The offer's
	/// expiration will be `absolute_expiry` if `Some`, otherwise it will not expire.
	///
	/// # Privacy
	///
	/// Uses [`MessageRouter`] to construct a [`BlindedMessagePath`] for the offer based on the given
	/// `absolute_expiry` according to [`MAX_SHORT_LIVED_RELATIVE_EXPIRY`]. See those docs for
	/// privacy implications as well as those of the parameterized [`Router`], which implements
	/// [`MessageRouter`].
	///
	/// Also, uses a derived signing pubkey in the offer for recipient privacy.
	///
	/// # Limitations
	///
	/// Requires a direct connection to the introduction node in the responding [`InvoiceRequest`]'s
	/// reply path.
	///
	/// # Errors
	///
	/// Errors if the parameterized [`Router`] is unable to create a blinded path for the offer.
	///
	/// [`BlindedMessagePath`]: crate::blinded_path::message::BlindedMessagePath
	/// [`InvoiceRequest`]: crate::offers::invoice_request::InvoiceRequest
	/// [`MessageRouter`]: crate::onion_message::messenger::MessageRouter
	/// [`Offer`]: crate::offers::offer
	/// [`Router`]: crate::routing::router::Router
	pub fn create_offer_builder(
		&$self, absolute_expiry: Option<Duration>
	) -> Result<$builder, Bolt12SemanticError> {
		let node_id = $self.get_our_node_id();
		let expanded_key = &$self.inbound_payment_key;
		let entropy = &*$self.entropy_source;
		let secp_ctx = &$self.secp_ctx;

		let nonce = Nonce::from_entropy_source(entropy);
		let context = OffersContext::InvoiceRequest { nonce };
		let path = $self.create_blinded_paths_using_absolute_expiry(context, absolute_expiry)
			.and_then(|paths| paths.into_iter().next().ok_or(()))
			.map_err(|_| Bolt12SemanticError::MissingPaths)?;
		let builder = OfferBuilder::deriving_signing_pubkey(node_id, expanded_key, nonce, secp_ctx)
			.chain_hash($self.commons.get_chain_hash())
			.path(path);

		let builder = match absolute_expiry {
			None => builder,
			Some(absolute_expiry) => builder.absolute_expiry(absolute_expiry),
		};

		Ok(builder.into())
	}
} }

macro_rules! create_refund_builder { ($self: ident, $builder: ty) => {
	/// Creates a [`RefundBuilder`] such that the [`Refund`] it builds is recognized by the
	/// [`OffersMessageFlow`] when handling [`Bolt12Invoice`] messages for the refund.
	///
	/// # Payment
	///
	/// The provided `payment_id` is used to ensure that only one invoice is paid for the refund.
	/// See [Avoiding Duplicate Payments] for other requirements once the payment has been sent.
	///
	/// The builder will have the provided expiration set. Any changes to the expiration on the
	/// returned builder will not be honored by [`OffersMessageFlow`]. For non-`std`, the highest seen
	/// block time minus two hours is used for the current time when determining if the refund has
	/// expired.
	///
	/// To revoke the refund, use [`ChannelManager::abandon_payment`] prior to receiving the
	/// invoice. If abandoned, or an invoice isn't received before expiration, the payment will fail
	/// with an [`Event::PaymentFailed`].
	///
	/// If `max_total_routing_fee_msat` is not specified, The default from
	/// [`RouteParameters::from_payment_params_and_value`] is applied.
	///
	/// # Privacy
	///
	/// Uses [`MessageRouter`] to construct a [`BlindedMessagePath`] for the refund based on the given
	/// `absolute_expiry` according to [`MAX_SHORT_LIVED_RELATIVE_EXPIRY`]. See those docs for
	/// privacy implications as well as those of the parameterized [`Router`], which implements
	/// [`MessageRouter`].
	///
	/// Also, uses a derived payer id in the refund for payer privacy.
	///
	/// # Limitations
	///
	/// Requires a direct connection to an introduction node in the responding
	/// [`Bolt12Invoice::payment_paths`].
	///
	/// # Errors
	///
	/// Errors if:
	/// - a duplicate `payment_id` is provided given the caveats in the aforementioned link,
	/// - `amount_msats` is invalid, or
	/// - the parameterized [`Router`] is unable to create a blinded path for the refund.
	///
	/// [`Refund`]: crate::offers::refund::Refund
	/// [`BlindedMessagePath`]: crate::blinded_path::message::BlindedMessagePath
	/// [`Bolt12Invoice`]: crate::offers::invoice::Bolt12Invoice
	/// [`Bolt12Invoice::payment_paths`]: crate::offers::invoice::Bolt12Invoice::payment_paths
	/// [`ChannelManager::abandon_payment`]: crate::ln::channelmanager::ChannelManager::abandon_payment
	/// [`MessageRouter`]: crate::onion_message::messenger::MessageRouter
	/// [`RouteParameters::from_payment_params_and_value`]: crate::routing::router::RouteParameters::from_payment_params_and_value
	/// [`Router`]: crate::routing::router::Router
	/// [`Event::PaymentFailed`]: crate::events::Event::PaymentFailed
	/// [Avoiding Duplicate Payments]: #avoiding-duplicate-payments
	pub fn create_refund_builder(
		&$self, amount_msats: u64, absolute_expiry: Duration, payment_id: PaymentId,
		retry_strategy: Retry, max_total_routing_fee_msat: Option<u64>
	) -> Result<$builder, Bolt12SemanticError> {
		let node_id = $self.get_our_node_id();
		let expanded_key = &$self.inbound_payment_key;
		let entropy = &*$self.entropy_source;
		let secp_ctx = &$self.secp_ctx;

		let nonce = Nonce::from_entropy_source(entropy);
		let context = OffersContext::OutboundPayment { payment_id, nonce, hmac: None };
		let path = $self.create_blinded_paths_using_absolute_expiry(context, Some(absolute_expiry))
			.and_then(|paths| paths.into_iter().next().ok_or(()))
			.map_err(|_| Bolt12SemanticError::MissingPaths)?;

		let builder = RefundBuilder::deriving_signing_pubkey(
			node_id, expanded_key, nonce, secp_ctx, amount_msats, payment_id
		)?
			.chain_hash($self.commons.get_chain_hash())
			.absolute_expiry(absolute_expiry)
			.path(path);

		let expiration = StaleExpiration::AbsoluteTimeout(absolute_expiry);

		$self.commons.add_new_awaiting_invoice(
			payment_id, expiration, retry_strategy, max_total_routing_fee_msat, None
		).map_err(|_| Bolt12SemanticError::DuplicatePaymentId)?;

		Ok(builder.into())
	}
} }

impl<ES: Deref, OMC: Deref, MR: Deref, L: Deref> OffersMessageFlow<ES, OMC, MR, L>
where
	ES::Target: EntropySource,
	OMC::Target: OffersMessageCommons,
	MR::Target: MessageRouter,
	L::Target: Logger,
{
	#[cfg(not(c_bindings))]
	create_offer_builder!(self, OfferBuilder<DerivedMetadata, secp256k1::All>);
	#[cfg(c_bindings)]
	create_offer_builder!(self, OfferWithDerivedMetadataBuilder);

	#[cfg(not(c_bindings))]
	create_refund_builder!(self, RefundBuilder<secp256k1::All>);

	#[cfg(c_bindings)]
	create_refund_builder!(self, RefundMaybeWithDerivedMetadataBuilder);

	/// Pays for an [`Offer`] using the given parameters by creating an [`InvoiceRequest`] and
	/// enqueuing it to be sent via an onion message. [`OffersMessageFlow`] will pay the actual
	/// [`Bolt12Invoice`] once it is received.
	///
	/// Uses [`InvoiceRequestBuilder`] such that the [`InvoiceRequest`] it builds is recognized by
	/// the [`OffersMessageFlow`] when handling a [`Bolt12Invoice`] message in response to the request.
	/// The optional parameters are used in the builder, if `Some`:
	/// - `quantity` for [`InvoiceRequest::quantity`] which must be set if
	///   [`Offer::expects_quantity`] is `true`.
	/// - `amount_msats` if overpaying what is required for the given `quantity` is desired, and
	/// - `payer_note` for [`InvoiceRequest::payer_note`].
	///
	/// If `max_total_routing_fee_msat` is not specified, The default from
	/// [`RouteParameters::from_payment_params_and_value`] is applied.
	///
	/// # Payment
	///
	/// The provided `payment_id` is used to ensure that only one invoice is paid for the request
	/// when received. See [Avoiding Duplicate Payments] for other requirements once the payment has
	/// been sent.
	///
	/// To revoke the request, use [`ChannelManager::abandon_payment`] prior to receiving the
	/// invoice. If abandoned, or an invoice isn't received in a reasonable amount of time, the
	/// payment will fail with an [`Event::PaymentFailed`].
	///
	/// # Privacy
	///
	/// For payer privacy, uses a derived payer id and uses [`MessageRouter::create_blinded_paths`]
	/// to construct a [`BlindedMessagePath`] for the reply path. For further privacy implications, see the
	/// docs of the parameterized [`Router`], which implements [`MessageRouter`].
	///
	/// # Limitations
	///
	/// Requires a direct connection to an introduction node in [`Offer::paths`] or to
	/// [`Offer::issuer_signing_pubkey`], if empty. A similar restriction applies to the responding
	/// [`Bolt12Invoice::payment_paths`].
	///
	/// # Errors
	///
	/// Errors if:
	/// - a duplicate `payment_id` is provided given the caveats in the aforementioned link,
	/// - the provided parameters are invalid for the offer,
	/// - the offer is for an unsupported chain, or
	/// - the parameterized [`Router`] is unable to create a blinded reply path for the invoice
	///   request.
	///
	/// [`BlindedMessagePath`]: crate::blinded_path::message::BlindedMessagePath
	/// [`Bolt12Invoice`]: crate::offers::invoice::Bolt12Invoice
	/// [`Bolt12Invoice::payment_paths`]: crate::offers::invoice::Bolt12Invoice::payment_paths
	/// [`ChannelManager::abandon_payment`]: crate::ln::channelmanager::ChannelManager::abandon_payment
	/// [`InvoiceRequest`]: crate::offers::invoice_request::InvoiceRequest
	/// [`InvoiceRequest::quantity`]: crate::offers::invoice_request::InvoiceRequest::quantity
	/// [`InvoiceRequest::payer_note`]: crate::offers::invoice_request::InvoiceRequest::payer_note
	/// [`InvoiceRequestBuilder`]: crate::offers::invoice_request::InvoiceRequestBuilder
	/// [`MessageRouter`]: crate::onion_message::messenger::MessageRouter
	/// [`MessageRouter::create_blinded_paths`]: crate::onion_message::messenger::MessageRouter::create_blinded_paths
	/// [`RouteParameters::from_payment_params_and_value`]: crate::routing::router::RouteParameters::from_payment_params_and_value
	/// [`Router`]: crate::routing::router::Router
	/// [`Event::PaymentFailed`]: crate::events::Event::PaymentFailed
	/// [Avoiding Duplicate Payments]: #avoiding-duplicate-payments
	pub fn pay_for_offer(
		&self, offer: &Offer, quantity: Option<u64>, amount_msats: Option<u64>,
		payer_note: Option<String>, payment_id: PaymentId, retry_strategy: Retry,
		max_total_routing_fee_msat: Option<u64>,
	) -> Result<(), Bolt12SemanticError> {
		self.pay_for_offer_intern(
			offer,
			quantity,
			amount_msats,
			payer_note,
			payment_id,
			None,
			|invoice_request, nonce| {
				let expiration = StaleExpiration::TimerTicks(1);
				let retryable_invoice_request =
					RetryableInvoiceRequest { invoice_request: invoice_request.clone(), nonce };
				self.commons
					.add_new_awaiting_invoice(
						payment_id,
						expiration,
						retry_strategy,
						max_total_routing_fee_msat,
						Some(retryable_invoice_request),
					)
					.map_err(|_| Bolt12SemanticError::DuplicatePaymentId)
			},
		)
	}

	/// Creates a [`Bolt12Invoice`] for a [`Refund`] and enqueues it to be sent via an onion
	/// message.
	///
	/// The resulting invoice uses a [`PaymentHash`] recognized by the [`ChannelManager`] and a
	/// [`BlindedPaymentPath`] containing the [`PaymentSecret`] needed to reconstruct the
	/// corresponding [`PaymentPreimage`]. It is returned purely for informational purposes.
	///
	/// [`PaymentPreimage`]: crate::types::payment::PaymentPreimage
	///
	/// # Limitations
	///
	/// Requires a direct connection to an introduction node in [`Refund::paths`] or to
	/// [`Refund::payer_signing_pubkey`], if empty. This request is best effort; an invoice will be
	/// sent to each node meeting the aforementioned criteria, but there's no guarantee that they
	/// will be received and no retries will be made.
	///
	/// # Errors
	///
	/// Errors if:
	/// - the refund is for an unsupported chain, or
	/// - the parameterized [`Router`] is unable to create a blinded payment path or reply path for
	///   the invoice.
	///
	/// [`BlindedPaymentPath`]: crate::blinded_path::payment::BlindedPaymentPath
	/// [`ChannelManager`]: crate::ln::channelmanager::ChannelManager
	/// [`PaymentHash`]: crate::types::payment::PaymentHash
	/// [`PaymentSecret`]: crate::types::payment::PaymentSecret
	/// [`Router`]: crate::routing::router::Router
	pub fn request_refund_payment(
		&self, refund: &Refund,
	) -> Result<Bolt12Invoice, Bolt12SemanticError> {
		let expanded_key = &self.inbound_payment_key;
		let entropy = &*self.entropy_source;
		let secp_ctx = &self.secp_ctx;

		let amount_msats = refund.amount_msats();
		let relative_expiry = DEFAULT_RELATIVE_EXPIRY.as_secs() as u32;

		if refund.chain() != self.commons.get_chain_hash() {
			return Err(Bolt12SemanticError::UnsupportedChain);
		}

		// TODO: Add persistance through `commons` internal function. Shouldn't be exposed here.
		// let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(&*self.commons);

		match self.commons.create_inbound_payment(Some(amount_msats), relative_expiry, None) {
			Ok((payment_hash, payment_secret)) => {
				let payment_context = PaymentContext::Bolt12Refund(Bolt12RefundContext {});
				let payment_paths = self
					.commons
					.create_blinded_payment_paths(amount_msats, payment_secret, payment_context)
					.map_err(|_| Bolt12SemanticError::MissingPaths)?;

				#[cfg(feature = "std")]
				let builder = refund.respond_using_derived_keys(
					payment_paths,
					payment_hash,
					expanded_key,
					entropy,
				)?;
				#[cfg(not(feature = "std"))]
				let created_at = self.commons.get_current_blocktime();
				#[cfg(not(feature = "std"))]
				let builder = refund.respond_using_derived_keys_no_std(
					payment_paths,
					payment_hash,
					created_at,
					expanded_key,
					entropy,
				)?;
				let builder: InvoiceBuilder<DerivedSigningPubkey> = builder.into();
				let invoice = builder.allow_mpp().build_and_sign(secp_ctx)?;

				let nonce = Nonce::from_entropy_source(entropy);
				let hmac = payment_hash.hmac_for_offer_payment(nonce, expanded_key);
				let context = MessageContext::Offers(OffersContext::InboundPayment {
					payment_hash: invoice.payment_hash(),
					nonce,
					hmac,
				});
				let reply_paths = self
					.commons
					.create_blinded_paths(context)
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
					reply_paths
						.iter()
						.flat_map(|reply_path| {
							refund.paths().iter().map(move |path| (path, reply_path))
						})
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

				Ok(invoice)
			},
			Err(()) => Err(Bolt12SemanticError::InvalidAmount),
		}
	}

	/// Pays for an [`Offer`] looked up using [BIP 353] Human Readable Names resolved by the DNS
	/// resolver(s) at `dns_resolvers` which resolve names according to bLIP 32.
	///
	/// If the wallet supports paying on-chain schemes, you should instead use
	/// [`OMNameResolver::resolve_name`] and [`OMNameResolver::handle_dnssec_proof_for_uri`] (by
	/// implementing [`DNSResolverMessageHandler`]) directly to look up a URI and then delegate to
	/// your normal URI handling.
	///
	/// If `max_total_routing_fee_msat` is not specified, the default from
	/// [`RouteParameters::from_payment_params_and_value`] is applied.
	///
	/// # Payment
	///
	/// The provided `payment_id` is used to ensure that only one invoice is paid for the request
	/// when received. See [Avoiding Duplicate Payments] for other requirements once the payment has
	/// been sent.
	///
	/// To revoke the request, use [`ChannelManager::abandon_payment`] prior to receiving the
	/// invoice. If abandoned, or an invoice isn't received in a reasonable amount of time, the
	/// payment will fail with an [`Event::InvoiceRequestFailed`].
	///
	/// # Privacy
	///
	/// For payer privacy, uses a derived payer id and uses [`MessageRouter::create_blinded_paths`]
	/// to construct a [`BlindedPath`] for the reply path. For further privacy implications, see the
	/// docs of the parameterized [`Router`], which implements [`MessageRouter`].
	///
	/// # Limitations
	///
	/// Requires a direct connection to the given [`Destination`] as well as an introduction node in
	/// [`Offer::paths`] or to [`Offer::signing_pubkey`], if empty. A similar restriction applies to
	/// the responding [`Bolt12Invoice::payment_paths`].
	///
	/// # Errors
	///
	/// Errors if:
	/// - a duplicate `payment_id` is provided given the caveats in the aforementioned link,
	///
	/// [`Bolt12Invoice::payment_paths`]: crate::offers::invoice::Bolt12Invoice::payment_paths
	/// [Avoiding Duplicate Payments]: #avoiding-duplicate-payments
	#[cfg(feature = "dnssec")]
	pub fn pay_for_offer_from_human_readable_name(
		&self, name: HumanReadableName, amount_msats: u64, payment_id: PaymentId,
		retry_strategy: Retry, max_total_routing_fee_msat: Option<u64>,
		dns_resolvers: Vec<Destination>,
	) -> Result<(), ()> {
		let (onion_message, context) = self.commons.get_hrn_resolver().resolve_name(
			payment_id,
			name,
			&*self.entropy_source,
		)?;
		let reply_paths =
			self.commons.create_blinded_paths(MessageContext::DNSResolver(context))?;
		let expiration = StaleExpiration::TimerTicks(1);
		self.commons.add_new_awaiting_offer(
			payment_id,
			expiration,
			retry_strategy,
			max_total_routing_fee_msat,
			amount_msats,
		)?;
		let message_params = dns_resolvers
			.iter()
			.flat_map(|destination| reply_paths.iter().map(move |path| (path, destination)))
			.take(OFFERS_MESSAGE_REQUEST_LIMIT);
		for (reply_path, destination) in message_params {
			self.pending_dns_onion_messages.lock().unwrap().push((
				DNSResolverMessage::DNSSECQuery(onion_message.clone()),
				MessageSendInstructions::WithSpecifiedReplyPath {
					destination: destination.clone(),
					reply_path: reply_path.clone(),
				},
			));
		}
		Ok(())
	}
}

#[cfg(feature = "dnssec")]
impl<ES: Deref, OMC: Deref, MR: Deref, L: Deref> DNSResolverMessageHandler
	for OffersMessageFlow<ES, OMC, MR, L>
where
	ES::Target: EntropySource,
	OMC::Target: OffersMessageCommons,
	MR::Target: MessageRouter,
	L::Target: Logger,
{
	fn handle_dnssec_query(
		&self, _message: DNSSECQuery, _responder: Option<Responder>,
	) -> Option<(DNSResolverMessage, ResponseInstruction)> {
		None
	}

	fn handle_dnssec_proof(&self, message: DNSSECProof, context: DNSResolverContext) {
		let offer_opt =
			self.commons.get_hrn_resolver().handle_dnssec_proof_for_offer(message, context);
		#[cfg_attr(not(feature = "_test_utils"), allow(unused_mut))]
		if let Some((completed_requests, mut offer)) = offer_opt {
			for (name, payment_id) in completed_requests {
				#[cfg(feature = "_test_utils")]
				if let Some(replacement_offer) = self
					.testing_dnssec_proof_offer_resolution_override
					.lock()
					.unwrap()
					.remove(&name)
				{
					// If we have multiple pending requests we may end up over-using the override
					// offer, but tests can deal with that.
					offer = replacement_offer;
				}
				if let Ok(amt_msats) = self.commons.amt_msats_for_payment_awaiting_offer(payment_id)
				{
					let offer_pay_res = self.pay_for_offer_intern(
						&offer,
						None,
						Some(amt_msats),
						None,
						payment_id,
						Some(name),
						|invoice_request, nonce| {
							let retryable_invoice_request = RetryableInvoiceRequest {
								invoice_request: invoice_request.clone(),
								nonce,
							};
							self.commons
								.received_offer(payment_id, Some(retryable_invoice_request))
								.map_err(|_| Bolt12SemanticError::DuplicatePaymentId)
						},
					);
					if offer_pay_res.is_err() {
						// The offer we tried to pay is the canonical current offer for the name we
						// wanted to pay. If we can't pay it, there's no way to recover so fail the
						// payment.
						// Note that the PaymentFailureReason should be ignored for an
						// AwaitingInvoice payment.
						self.commons.abandon_payment_with_reason(
							payment_id,
							PaymentFailureReason::RouteNotFound,
						);
					}
				}
			}
		}
	}

	fn release_pending_messages(&self) -> Vec<(DNSResolverMessage, MessageSendInstructions)> {
		core::mem::take(&mut self.pending_dns_onion_messages.lock().unwrap())
	}
}
