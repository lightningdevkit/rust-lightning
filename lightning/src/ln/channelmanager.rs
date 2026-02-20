// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! The top-level channel management and payment tracking stuff lives here.
//!
//! The [`ChannelManager`] is the main chunk of logic implementing the lightning protocol and is
//! responsible for tracking which channels are open, HTLCs are in flight and reestablishing those
//! upon reconnect to the relevant peer(s).
//!
//! It does not manage routing logic (see [`Router`] for that) nor does it manage constructing
//! on-chain transactions (it only monitors the chain to watch for any force-closes that might
//! imply it needs to fail HTLCs/payments/channels it manages).

use bitcoin::block::Header;
use bitcoin::constants::ChainHash;
use bitcoin::key::constants::SECRET_KEY_SIZE;
use bitcoin::network::Network;
use bitcoin::transaction::Transaction;

use bitcoin::hash_types::{BlockHash, Txid};
use bitcoin::hashes::hmac::Hmac;
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::{Hash, HashEngine, HmacEngine};

use bitcoin::secp256k1::Secp256k1;
use bitcoin::secp256k1::{PublicKey, SecretKey};
use bitcoin::{secp256k1, FeeRate, Sequence, SignedAmount};

use crate::blinded_path::message::{
	AsyncPaymentsContext, BlindedMessagePath, MessageForwardNode, OffersContext,
};
use crate::blinded_path::payment::{AsyncBolt12OfferContext, Bolt12OfferContext, PaymentContext};
use crate::blinded_path::NodeIdLookUp;
use crate::chain;
use crate::chain::chaininterface::{
	BroadcasterInterface, ConfirmationTarget, FeeEstimator, LowerBoundedFeeEstimator,
	TransactionType,
};
use crate::chain::channelmonitor::{
	Balance, ChannelMonitor, ChannelMonitorUpdate, ChannelMonitorUpdateStep, MonitorEvent,
	WithChannelMonitor, ANTI_REORG_DELAY, CLTV_CLAIM_BUFFER, HTLC_FAIL_BACK_BUFFER,
	LATENCY_GRACE_PERIOD_BLOCKS, MAX_BLOCKS_FOR_CONF,
};
use crate::chain::transaction::{OutPoint, TransactionData};
use crate::chain::{BestBlock, ChannelMonitorUpdateStatus, Confirm, Watch};
use crate::events::{
	self, ClosureReason, Event, EventHandler, EventsProvider, HTLCHandlingFailureType,
	InboundChannelFunds, PaymentFailureReason, ReplayEvent,
};
use crate::events::{FundingInfo, PaidBolt12Invoice};
use crate::ln::chan_utils::selected_commitment_sat_per_1000_weight;
#[cfg(any(test, fuzzing, feature = "_test_utils"))]
use crate::ln::channel::QuiescentAction;
use crate::ln::channel::{
	self, hold_time_since, Channel, ChannelError, ChannelUpdateStatus, DisconnectResult,
	FundedChannel, FundingTxSigned, InboundV1Channel, InteractiveTxMsgError, OutboundHop,
	OutboundV1Channel, PendingV2Channel, ReconnectionMsg, ShutdownResult, StfuResponse,
	UpdateFulfillCommitFetch, WithChannelContext,
};
use crate::ln::channel_state::ChannelDetails;
use crate::ln::funding::{FundingContribution, FundingTemplate};
use crate::ln::inbound_payment;
use crate::ln::interactivetxs::InteractiveTxMessageSend;
use crate::ln::msgs;
use crate::ln::msgs::{
	BaseMessageHandler, ChannelMessageHandler, CommitmentUpdate, DecodeError, LightningError,
	MessageSendEvent,
};
use crate::ln::onion_payment::{
	check_incoming_htlc_cltv, create_fwd_pending_htlc_info, create_recv_pending_htlc_info,
	decode_incoming_update_add_htlc_onion, invalid_payment_err_data, HopConnector, InboundHTLCErr,
	NextPacketDetails,
};
use crate::ln::onion_utils::{self};
use crate::ln::onion_utils::{
	decode_fulfill_attribution_data, HTLCFailReason, LocalHTLCFailureReason,
};
use crate::ln::onion_utils::{process_fulfill_attribution_data, AttributionData};
use crate::ln::our_peer_storage::{EncryptedOurPeerStorage, PeerStorageMonitorHolder};
#[cfg(test)]
use crate::ln::outbound_payment;
#[cfg(any(test, feature = "_externalize_tests"))]
use crate::ln::outbound_payment::PaymentSendFailure;
use crate::ln::outbound_payment::{
	Bolt11PaymentError, Bolt12PaymentError, OutboundPayments, PendingOutboundPayment,
	ProbeSendFailure, RecipientCustomTlvs, RecipientOnionFields, Retry, RetryableInvoiceRequest,
	RetryableSendFailure, SendAlongPathArgs, StaleExpiration,
};
use crate::ln::types::ChannelId;
use crate::offers::async_receive_offer_cache::AsyncReceiveOfferCache;
use crate::offers::flow::{HeldHtlcReplyPath, InvreqResponseInstructions, OffersMessageFlow};
use crate::offers::invoice::{Bolt12Invoice, UnsignedBolt12Invoice};
use crate::offers::invoice_error::InvoiceError;
use crate::offers::invoice_request::{InvoiceRequest, InvoiceRequestVerifiedFromOffer};
use crate::offers::nonce::Nonce;
use crate::offers::offer::{Offer, OfferFromHrn};
use crate::offers::parse::Bolt12SemanticError;
use crate::offers::refund::Refund;
use crate::offers::static_invoice::StaticInvoice;
use crate::onion_message::async_payments::{
	AsyncPaymentsMessage, AsyncPaymentsMessageHandler, HeldHtlcAvailable, OfferPaths,
	OfferPathsRequest, ReleaseHeldHtlc, ServeStaticInvoice, StaticInvoicePersisted,
};
use crate::onion_message::dns_resolution::HumanReadableName;
use crate::onion_message::messenger::{
	MessageRouter, MessageSendInstructions, Responder, ResponseInstruction,
};
use crate::onion_message::offers::{OffersMessage, OffersMessageHandler};
use crate::routing::gossip::NodeId;
use crate::routing::router::{
	BlindedTail, FixedRouter, InFlightHtlcs, Path, Payee, PaymentParameters, Route,
	RouteParameters, RouteParametersConfig, Router,
};
use crate::sign::ecdsa::EcdsaChannelSigner;
use crate::sign::{EntropySource, NodeSigner, Recipient, SignerProvider};
#[cfg(any(feature = "_test_utils", test))]
use crate::types::features::Bolt11InvoiceFeatures;
use crate::types::features::{
	Bolt12InvoiceFeatures, ChannelFeatures, ChannelTypeFeatures, InitFeatures, NodeFeatures,
};
use crate::types::payment::{PaymentHash, PaymentPreimage, PaymentSecret};
use crate::types::string::UntrustedString;
use crate::util::config::{
	ChannelConfig, ChannelConfigOverrides, ChannelConfigUpdate, HTLCInterceptionFlags, UserConfig,
};
use crate::util::errors::APIError;
use crate::util::logger::{Level, Logger, WithContext};
use crate::util::scid_utils::fake_scid;
use crate::util::ser::{
	BigSize, FixedLengthReader, LengthReadable, MaybeReadable, Readable, ReadableArgs, VecWriter,
	WithoutLength, Writeable, Writer,
};
use crate::util::wakers::{Future, Notifier};

#[cfg(test)]
use crate::blinded_path::payment::BlindedPaymentPath;

#[cfg(feature = "dnssec")]
use {
	crate::blinded_path::message::DNSResolverContext,
	crate::onion_message::dns_resolution::{
		DNSResolverMessage, DNSResolverMessageHandler, DNSSECProof, DNSSECQuery,
	},
	crate::onion_message::messenger::Destination,
};

#[cfg(c_bindings)]
use {
	crate::offers::offer::OfferWithDerivedMetadataBuilder,
	crate::offers::refund::RefundMaybeWithDerivedMetadataBuilder,
};
#[cfg(not(c_bindings))]
use {
	crate::offers::offer::{DerivedMetadata, OfferBuilder},
	crate::offers::refund::RefundBuilder,
	crate::onion_message::messenger::DefaultMessageRouter,
	crate::routing::gossip::NetworkGraph,
	crate::routing::router::DefaultRouter,
	crate::routing::scoring::{ProbabilisticScorer, ProbabilisticScoringFeeParameters},
	crate::sign::KeysManager,
};

use lightning_invoice::{
	Bolt11Invoice, Bolt11InvoiceDescription, CreationError, Currency, Description,
	InvoiceBuilder as Bolt11InvoiceBuilder, SignOrCreationError, DEFAULT_EXPIRY_TIME,
};

use alloc::collections::{btree_map, BTreeMap};

use crate::io;
use crate::io::Read;
use crate::prelude::*;
use crate::sync::{Arc, FairRwLock, LockHeldState, LockTestExt, Mutex, RwLock, RwLockReadGuard};
use bitcoin::hex::impl_fmt_traits;

use crate::ln::script::ShutdownScript;
use core::borrow::Borrow;
use core::cell::RefCell;
use core::convert::Infallible;
use core::ops::Deref;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use core::time::Duration;
use core::{cmp, mem};

// We hold various information about HTLC relay in the HTLC objects in Channel itself:
//
// Upon receipt of an HTLC from a peer, we'll give it a PendingHTLCStatus indicating if it should
// forward the HTLC with information it will give back to us when it does so, or if it should Fail
// the HTLC with the relevant message for the Channel to handle giving to the remote peer.
//
// Once said HTLC is committed in the Channel, if the PendingHTLCStatus indicated Forward, the
// Channel will return the PendingHTLCInfo back to us, and we will create an HTLCForwardInfo
// with it to track where it came from (in case of onwards-forward error), waiting a random delay
// before we forward it.
//
// We will then use HTLCForwardInfo's PendingHTLCInfo to construct an outbound HTLC, with a
// relevant HTLCSource::PreviousHopData filled in to indicate where it came from (which we can use
// to either fail-backwards or fulfill the HTLC backwards along the relevant path).
// Alternatively, we can fill an outbound HTLC with a HTLCSource::OutboundRoute indicating this is
// our payment, which we can use to decode errors or inform the user that the payment was sent.

/// Information about where a received HTLC('s onion) has indicated the HTLC should go.
#[derive(Clone)] // See FundedChannel::revoke_and_ack for why, tl;dr: Rust bug
#[cfg_attr(test, derive(Debug, PartialEq))]
pub enum PendingHTLCRouting {
	/// An HTLC which should be forwarded on to another node.
	Forward {
		/// The onion which should be included in the forwarded HTLC, telling the next hop what to
		/// do with the HTLC.
		onion_packet: msgs::OnionPacket,
		/// The short channel ID of the channel which we were instructed to forward this HTLC to.
		///
		/// This could be a real on-chain SCID, an SCID alias, or some other SCID which has meaning
		/// to the receiving node, such as one returned from
		/// [`ChannelManager::get_intercept_scid`] or [`ChannelManager::get_phantom_scid`].
		short_channel_id: u64, // This should be NonZero<u64> eventually when we bump MSRV
		/// Set if this HTLC is being forwarded within a blinded path.
		blinded: Option<BlindedForward>,
		/// The absolute CLTV of the inbound HTLC
		incoming_cltv_expiry: Option<u32>,
		/// Whether this HTLC should be held by our node until we receive a corresponding
		/// [`ReleaseHeldHtlc`] onion message.
		hold_htlc: Option<()>,
	},
	/// An HTLC which should be forwarded on to another Trampoline node.
	TrampolineForward {
		/// The onion shared secret we build with the sender (or the preceding Trampoline node) used
		/// to decrypt the onion.
		///
		/// This is later used to encrypt failure packets in the event that the HTLC is failed.
		incoming_shared_secret: [u8; 32],
		/// The onion which should be included in the forwarded HTLC, telling the next hop what to
		/// do with the HTLC.
		onion_packet: msgs::TrampolineOnionPacket,
		/// The node ID of the Trampoline node which we need to route this HTLC to.
		node_id: PublicKey,
		/// Set if this HTLC is being forwarded within a blinded path.
		blinded: Option<BlindedForward>,
		/// The absolute CLTV of the inbound HTLC
		incoming_cltv_expiry: u32,
	},
	/// The onion indicates that this is a payment for an invoice (supposedly) generated by us.
	///
	/// Note that at this point, we have not checked that the invoice being paid was actually
	/// generated by us, but rather it's claiming to pay an invoice of ours.
	Receive {
		/// Information about the amount the sender intended to pay and (potential) proof that this
		/// is a payment for an invoice we generated. This proof of payment is is also used for
		/// linking MPP parts of a larger payment.
		payment_data: msgs::FinalOnionHopData,
		/// Additional data which we (allegedly) instructed the sender to include in the onion.
		///
		/// For HTLCs received by LDK, this will ultimately be exposed in
		/// [`Event::PaymentClaimable::onion_fields`] as
		/// [`RecipientOnionFields::payment_metadata`].
		payment_metadata: Option<Vec<u8>>,
		/// The context of the payment included by the recipient in a blinded path, or `None` if a
		/// blinded path was not used.
		///
		/// Used in part to determine the [`events::PaymentPurpose`].
		payment_context: Option<PaymentContext>,
		/// CLTV expiry of the received HTLC.
		///
		/// Used to track when we should expire pending HTLCs that go unclaimed.
		incoming_cltv_expiry: u32,
		/// If the onion had forwarding instructions to one of our phantom node SCIDs, this will
		/// provide the onion shared secret used to decrypt the next level of forwarding
		/// instructions.
		phantom_shared_secret: Option<[u8; 32]>,
		/// If the onion had trampoline forwarding instruction to our node.
		/// This will provice the onion shared secret to encrypt error packets to the sender.
		trampoline_shared_secret: Option<[u8; 32]>,
		/// Custom TLVs which were set by the sender.
		///
		/// For HTLCs received by LDK, this will ultimately be exposed in
		/// [`Event::PaymentClaimable::onion_fields`] as
		/// [`RecipientOnionFields::custom_tlvs`].
		custom_tlvs: Vec<(u64, Vec<u8>)>,
		/// Set if this HTLC is the final hop in a multi-hop blinded path.
		requires_blinded_error: bool,
	},
	/// The onion indicates that this is for payment to us but which contains the preimage for
	/// claiming included, and is unrelated to any invoice we'd previously generated (aka a
	/// "keysend" or "spontaneous" payment).
	ReceiveKeysend {
		/// Information about the amount the sender intended to pay and possibly a token to
		/// associate MPP parts of a larger payment.
		///
		/// This will only be filled in if receiving MPP keysend payments is enabled, and it being
		/// present will cause deserialization to fail on versions of LDK prior to 0.0.116.
		payment_data: Option<msgs::FinalOnionHopData>,
		/// Preimage for this onion payment. This preimage is provided by the sender and will be
		/// used to settle the spontaneous payment.
		payment_preimage: PaymentPreimage,
		/// Additional data which we (allegedly) instructed the sender to include in the onion.
		///
		/// For HTLCs received by LDK, this will ultimately bubble back up as
		/// [`RecipientOnionFields::payment_metadata`].
		payment_metadata: Option<Vec<u8>>,
		/// CLTV expiry of the received HTLC.
		///
		/// Used to track when we should expire pending HTLCs that go unclaimed.
		incoming_cltv_expiry: u32,
		/// Custom TLVs which were set by the sender.
		///
		/// For HTLCs received by LDK, these will ultimately bubble back up as
		/// [`RecipientOnionFields::custom_tlvs`].
		custom_tlvs: Vec<(u64, Vec<u8>)>,
		/// Set if this HTLC is the final hop in a multi-hop blinded path.
		requires_blinded_error: bool,
		/// Set if we are receiving a keysend to a blinded path, meaning we created the
		/// [`PaymentSecret`] and should verify it using our
		/// [`NodeSigner::get_expanded_key`].
		has_recipient_created_payment_secret: bool,
		/// The [`InvoiceRequest`] associated with the [`Offer`] corresponding to this payment.
		invoice_request: Option<InvoiceRequest>,
		/// The context of the payment included by the recipient in a blinded path, or `None` if a
		/// blinded path was not used.
		///
		/// Used in part to determine the [`events::PaymentPurpose`].
		payment_context: Option<PaymentContext>,
	},
}

/// Information used to forward or fail this HTLC that is being forwarded within a blinded path.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct BlindedForward {
	/// The `blinding_point` that was set in the inbound [`msgs::UpdateAddHTLC`], or in the inbound
	/// onion payload if we're the introduction node. Useful for calculating the next hop's
	/// [`msgs::UpdateAddHTLC::blinding_point`].
	pub inbound_blinding_point: PublicKey,
	/// If needed, this determines how this HTLC should be failed backwards, based on whether we are
	/// the introduction node.
	pub failure: BlindedFailure,
	/// Overrides the next hop's [`msgs::UpdateAddHTLC::blinding_point`]. Set if this HTLC is being
	/// forwarded within a [`BlindedPaymentPath`] that was concatenated to another blinded path that
	/// starts at the next hop.
	///
	/// [`BlindedPaymentPath`]: crate::blinded_path::payment::BlindedPaymentPath
	pub next_blinding_override: Option<PublicKey>,
}

impl PendingHTLCRouting {
	// Used to override the onion failure code and data if the HTLC is blinded.
	fn blinded_failure(&self) -> Option<BlindedFailure> {
		match self {
			Self::Forward { blinded: Some(BlindedForward { failure, .. }), .. } => Some(*failure),
			Self::TrampolineForward { blinded: Some(BlindedForward { failure, .. }), .. } => {
				Some(*failure)
			},
			Self::Receive { requires_blinded_error: true, .. } => {
				Some(BlindedFailure::FromBlindedNode)
			},
			Self::ReceiveKeysend { requires_blinded_error: true, .. } => {
				Some(BlindedFailure::FromBlindedNode)
			},
			_ => None,
		}
	}

	fn incoming_cltv_expiry(&self) -> Option<u32> {
		match self {
			Self::Forward { incoming_cltv_expiry, .. } => *incoming_cltv_expiry,
			Self::TrampolineForward { incoming_cltv_expiry, .. } => Some(*incoming_cltv_expiry),
			Self::Receive { incoming_cltv_expiry, .. } => Some(*incoming_cltv_expiry),
			Self::ReceiveKeysend { incoming_cltv_expiry, .. } => Some(*incoming_cltv_expiry),
		}
	}

	/// Whether this HTLC should be held by our node until we receive a corresponding
	/// [`ReleaseHeldHtlc`] onion message.
	pub(super) fn should_hold_htlc(&self) -> bool {
		match self {
			Self::Forward { hold_htlc: Some(()), .. } => true,
			_ => false,
		}
	}
}

/// Information about an incoming HTLC, including the [`PendingHTLCRouting`] describing where it
/// should go next.
#[derive(Clone)] // See FundedChannel::revoke_and_ack for why, tl;dr: Rust bug
#[cfg_attr(test, derive(Debug, PartialEq))]
pub struct PendingHTLCInfo {
	/// Further routing details based on whether the HTLC is being forwarded or received.
	pub routing: PendingHTLCRouting,
	/// The onion shared secret we build with the sender used to decrypt the onion.
	///
	/// This is later used to encrypt failure packets in the event that the HTLC is failed.
	pub incoming_shared_secret: [u8; 32],
	/// Hash of the payment preimage, to lock the payment until the receiver releases the preimage.
	pub payment_hash: PaymentHash,
	/// Amount received in the incoming HTLC.
	///
	/// This field was added in LDK 0.0.113 and will be `None` for objects written by prior
	/// versions.
	pub incoming_amt_msat: Option<u64>,
	/// The amount the sender indicated should be forwarded on to the next hop or amount the sender
	/// intended for us to receive for received payments.
	///
	/// If the received amount is less than this for received payments, an intermediary hop has
	/// attempted to steal some of our funds and we should fail the HTLC (the sender should retry
	/// it along another path).
	///
	/// Because nodes can take less than their required fees, and because senders may wish to
	/// improve their own privacy, this amount may be less than [`Self::incoming_amt_msat`] for
	/// received payments. In such cases, recipients must handle this HTLC as if it had received
	/// [`Self::outgoing_amt_msat`].
	pub outgoing_amt_msat: u64,
	/// The CLTV the sender has indicated we should set on the forwarded HTLC (or has indicated
	/// should have been set on the received HTLC for received payments).
	pub outgoing_cltv_value: u32,
	/// The fee taken for this HTLC in addition to the standard protocol HTLC fees.
	///
	/// If this is a payment for forwarding, this is the fee we are taking before forwarding the
	/// HTLC.
	///
	/// If this is a received payment, this is the fee that our counterparty took.
	///
	/// This is used to allow LSPs to take fees as a part of payments, without the sender having to
	/// shoulder them.
	pub skimmed_fee_msat: Option<u64>,
	/// An experimental field indicating whether our node's reputation would be held accountable
	/// for the timely resolution of the received HTLC.
	pub incoming_accountable: bool,
}

#[derive(Clone, Debug)] // See FundedChannel::revoke_and_ack for why, tl;dr: Rust bug
pub(super) enum HTLCFailureMsg {
	Relay(msgs::UpdateFailHTLC),
	Malformed(msgs::UpdateFailMalformedHTLC),
}

/// Stores whether we can't forward an HTLC or relevant forwarding info
#[cfg_attr(test, derive(Debug))]
#[derive(Clone)] // See FundedChannel::revoke_and_ack for why, tl;dr: Rust bug
pub(super) enum PendingHTLCStatus {
	Forward(PendingHTLCInfo),
	Fail(HTLCFailureMsg),
}

#[cfg_attr(test, derive(Clone, Debug, PartialEq))]
pub(super) struct PendingAddHTLCInfo {
	pub(super) forward_info: PendingHTLCInfo,

	// These fields are set before calling `forward_htlcs()` and consumed in
	// `process_pending_htlc_forwards()` for constructing the
	// `HTLCSource::PreviousHopData` for failed and forwarded
	// HTLCs.
	//
	// Note that this may be an outbound SCID alias for the associated channel.
	prev_outbound_scid_alias: u64,
	prev_htlc_id: u64,
	prev_counterparty_node_id: PublicKey,
	prev_channel_id: ChannelId,
	prev_funding_outpoint: OutPoint,
	prev_user_channel_id: u128,
}

impl PendingAddHTLCInfo {
	fn htlc_previous_hop_data(&self) -> HTLCPreviousHopData {
		let phantom_shared_secret = match self.forward_info.routing {
			PendingHTLCRouting::Receive { phantom_shared_secret, .. } => phantom_shared_secret,
			_ => None,
		};
		let trampoline_shared_secret = match self.forward_info.routing {
			PendingHTLCRouting::Receive { trampoline_shared_secret, .. } => {
				trampoline_shared_secret
			},
			_ => None,
		};

		HTLCPreviousHopData {
			prev_outbound_scid_alias: self.prev_outbound_scid_alias,
			user_channel_id: Some(self.prev_user_channel_id),
			outpoint: self.prev_funding_outpoint,
			channel_id: self.prev_channel_id,
			counterparty_node_id: Some(self.prev_counterparty_node_id),
			htlc_id: self.prev_htlc_id,
			incoming_packet_shared_secret: self.forward_info.incoming_shared_secret,
			phantom_shared_secret,
			trampoline_shared_secret,
			blinded_failure: self.forward_info.routing.blinded_failure(),
			cltv_expiry: self.forward_info.routing.incoming_cltv_expiry(),
		}
	}
}

#[cfg_attr(test, derive(Clone, Debug, PartialEq))]
pub(super) enum HTLCForwardInfo {
	AddHTLC(PendingAddHTLCInfo),
	FailHTLC { htlc_id: u64, err_packet: msgs::OnionErrorPacket },
	FailMalformedHTLC { htlc_id: u64, failure_code: u16, sha256_of_onion: [u8; 32] },
}

/// Whether this blinded HTLC is being failed backwards by the introduction node or a blinded node,
/// which determines the failure message that should be used.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub enum BlindedFailure {
	/// This HTLC is being failed backwards by the introduction node, and thus should be failed with
	/// [`msgs::UpdateFailHTLC`] and error code [`LocalHTLCFailureReason::InvalidOnionBlinding`].
	FromIntroductionNode,
	/// This HTLC is being failed backwards by a blinded node within the path, and thus should be
	/// failed with [`msgs::UpdateFailMalformedHTLC`] and error code
	/// [`LocalHTLCFailureReason::InvalidOnionBlinding`].
	FromBlindedNode,
}

#[derive(PartialEq, Eq)]
enum OnionPayload {
	/// Indicates this incoming onion payload is for the purpose of paying an invoice.
	Invoice {
		/// This is only here for backwards-compatibility in serialization, in the future it can be
		/// removed, breaking clients running 0.0.106 and earlier.
		_legacy_hop_data: Option<msgs::FinalOnionHopData>,
	},
	/// Contains the payer-provided preimage.
	Spontaneous(PaymentPreimage),
}

/// HTLCs that are to us and can be failed/claimed by the user
#[derive(PartialEq, Eq)]
struct ClaimableHTLC {
	prev_hop: HTLCPreviousHopData,
	cltv_expiry: u32,
	/// The amount (in msats) of this MPP part
	value: u64,
	/// The amount (in msats) that the sender intended to be sent in this MPP
	/// part (used for validating total MPP amount)
	sender_intended_value: u64,
	onion_payload: OnionPayload,
	timer_ticks: u8,
	/// The total value received for a payment (sum of all MPP parts if the payment is a MPP).
	/// Gets set to the amount reported when pushing [`Event::PaymentClaimable`].
	total_value_received: Option<u64>,
	/// The sender intended sum total of all MPP parts specified in the onion
	total_msat: u64,
	/// The extra fee our counterparty skimmed off the top of this HTLC.
	counterparty_skimmed_fee_msat: Option<u64>,
}

impl From<&ClaimableHTLC> for events::ClaimedHTLC {
	fn from(val: &ClaimableHTLC) -> Self {
		events::ClaimedHTLC {
			counterparty_node_id: val.prev_hop.counterparty_node_id,
			channel_id: val.prev_hop.channel_id,
			user_channel_id: val.prev_hop.user_channel_id.unwrap_or(0),
			cltv_expiry: val.cltv_expiry,
			value_msat: val.value,
			counterparty_skimmed_fee_msat: val.counterparty_skimmed_fee_msat.unwrap_or(0),
		}
	}
}

impl PartialOrd for ClaimableHTLC {
	fn partial_cmp(&self, other: &ClaimableHTLC) -> Option<cmp::Ordering> {
		Some(self.cmp(other))
	}
}
impl Ord for ClaimableHTLC {
	fn cmp(&self, other: &ClaimableHTLC) -> cmp::Ordering {
		let res = (self.prev_hop.channel_id, self.prev_hop.htlc_id)
			.cmp(&(other.prev_hop.channel_id, other.prev_hop.htlc_id));
		if res.is_eq() {
			debug_assert!(self == other, "ClaimableHTLCs from the same source should be identical");
		}
		res
	}
}

/// A user-provided identifier in [`ChannelManager::send_payment`] used to uniquely identify
/// a payment and ensure idempotency in LDK.
///
/// This is not exported to bindings users as we just use [u8; 32] directly
#[derive(Hash, Copy, Clone, PartialEq, Eq)]
pub struct PaymentId(pub [u8; Self::LENGTH]);

impl PaymentId {
	/// Number of bytes in the id.
	pub const LENGTH: usize = 32;
}

impl PaymentId {
	fn for_inbound_from_htlcs<I: Iterator<Item = (ChannelId, u64)>>(
		key: &[u8; 32], htlcs: I,
	) -> PaymentId {
		let mut prev_pair = None;
		let mut hasher = HmacEngine::new(key);
		for (channel_id, htlc_id) in htlcs {
			hasher.input(&channel_id.0);
			hasher.input(&htlc_id.to_le_bytes());
			if let Some(prev) = prev_pair {
				debug_assert!(prev < (channel_id, htlc_id), "HTLCs should be sorted");
			}
			prev_pair = Some((channel_id, htlc_id));
		}
		PaymentId(Hmac::<Sha256>::from_engine(hasher).to_byte_array())
	}
}

impl Borrow<[u8]> for PaymentId {
	fn borrow(&self) -> &[u8] {
		&self.0[..]
	}
}

impl_fmt_traits! {
	impl fmt_traits for PaymentId {
		const LENGTH: usize = 32;
	}
}

impl Writeable for PaymentId {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		self.0.write(w)
	}
}

impl Readable for PaymentId {
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		let buf: [u8; 32] = Readable::read(r)?;
		Ok(PaymentId(buf))
	}
}

/// An identifier used to uniquely identify an intercepted HTLC to LDK.
///
/// This is not exported to bindings users as we just use [u8; 32] directly
#[derive(Hash, Copy, Clone, PartialEq, Eq)]
pub struct InterceptId(pub [u8; 32]);

impl InterceptId {
	fn from_htlc_id_and_chan_id(
		htlc_id: u64, channel_id: &ChannelId, counterparty_node_id: &PublicKey,
	) -> Self {
		let mut sha = Sha256::engine();
		sha.input(&htlc_id.to_be_bytes());
		sha.input(&channel_id.0);
		sha.input(&counterparty_node_id.serialize());
		Self(Sha256::from_engine(sha).to_byte_array())
	}
}

impl Borrow<[u8]> for InterceptId {
	fn borrow(&self) -> &[u8] {
		&self.0[..]
	}
}
impl_fmt_traits! {
	impl fmt_traits for InterceptId {
		const LENGTH: usize = 32;
	}
}

impl Writeable for InterceptId {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		self.0.write(w)
	}
}

impl Readable for InterceptId {
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		let buf: [u8; 32] = Readable::read(r)?;
		Ok(InterceptId(buf))
	}
}

/// Optional arguments to [`ChannelManager::pay_for_bolt11_invoice`]
///
/// These fields will often not need to be set, and the provided [`Self::default`] can be used.
pub struct OptionalBolt11PaymentParams {
	/// A set of custom tlvs, user can send along the payment.
	pub custom_tlvs: RecipientCustomTlvs,
	/// Pathfinding options which tweak how the path is constructed to the recipient.
	pub route_params_config: RouteParametersConfig,
	/// The number of tries or time during which we'll retry this payment if some paths to the
	/// recipient fail.
	///
	/// Once the retry limit is reached, further path failures will not be retried and the payment
	/// will ultimately fail once all pending paths have failed (generating an
	/// [`Event::PaymentFailed`]).
	pub retry_strategy: Retry,
}

impl Default for OptionalBolt11PaymentParams {
	fn default() -> Self {
		Self {
			custom_tlvs: RecipientCustomTlvs::new(vec![]).unwrap(),
			route_params_config: Default::default(),
			#[cfg(feature = "std")]
			retry_strategy: Retry::Timeout(core::time::Duration::from_secs(2)),
			#[cfg(not(feature = "std"))]
			retry_strategy: Retry::Attempts(3),
		}
	}
}

/// Optional arguments to [`ChannelManager::pay_for_offer`]
#[cfg_attr(
	feature = "dnssec",
	doc = "and [`ChannelManager::pay_for_offer_from_human_readable_name`]"
)]
/// .
///
/// These fields will often not need to be set, and the provided [`Self::default`] can be used.
pub struct OptionalOfferPaymentParams {
	/// A note that is communicated to the recipient about this payment via
	/// [`InvoiceRequest::payer_note`].
	pub payer_note: Option<String>,
	/// Pathfinding options which tweak how the path is constructed to the recipient.
	pub route_params_config: RouteParametersConfig,
	/// The number of tries or time during which we'll retry this payment if some paths to the
	/// recipient fail.
	///
	/// Once the retry limit is reached, further path failures will not be retried and the payment
	/// will ultimately fail once all pending paths have failed (generating an
	/// [`Event::PaymentFailed`]).
	pub retry_strategy: Retry,
}

impl Default for OptionalOfferPaymentParams {
	fn default() -> Self {
		Self {
			payer_note: None,
			route_params_config: Default::default(),
			#[cfg(feature = "std")]
			retry_strategy: Retry::Timeout(core::time::Duration::from_secs(2)),
			#[cfg(not(feature = "std"))]
			retry_strategy: Retry::Attempts(3),
		}
	}
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
/// Uniquely describes an HTLC by its source. Just the guaranteed-unique subset of [`HTLCSource`].
pub(crate) enum SentHTLCId {
	PreviousHopData { prev_outbound_scid_alias: u64, htlc_id: u64 },
	OutboundRoute { session_priv: [u8; SECRET_KEY_SIZE] },
}
impl SentHTLCId {
	pub(crate) fn from_source(source: &HTLCSource) -> Self {
		match source {
			HTLCSource::PreviousHopData(hop_data) => Self::PreviousHopData {
				prev_outbound_scid_alias: hop_data.prev_outbound_scid_alias,
				htlc_id: hop_data.htlc_id,
			},
			HTLCSource::OutboundRoute { session_priv, .. } => {
				Self::OutboundRoute { session_priv: session_priv.secret_bytes() }
			},
		}
	}
}
impl_writeable_tlv_based_enum!(SentHTLCId,
	(0, PreviousHopData) => {
		(0, prev_outbound_scid_alias, required),
		(2, htlc_id, required),
	},
	(2, OutboundRoute) => {
		(0, session_priv, required),
	},
);

type FailedHTLCForward = (HTLCSource, PaymentHash, HTLCFailReason, HTLCHandlingFailureType);

mod fuzzy_channelmanager {
	use super::*;

	/// Tracks the inbound corresponding to an outbound HTLC
	#[allow(clippy::derive_hash_xor_eq)] // Our Hash is faithful to the data, we just don't have SecretKey::hash
	#[derive(Clone, Debug, PartialEq, Eq)]
	pub enum HTLCSource {
		PreviousHopData(HTLCPreviousHopData),
		OutboundRoute {
			path: Path,
			session_priv: SecretKey,
			/// Technically we can recalculate this from the route, but we cache it here to avoid
			/// doing a double-pass on route when we get a failure back
			first_hop_htlc_msat: u64,
			payment_id: PaymentId,
			/// The BOLT12 invoice associated with this payment, if any. This is stored here to ensure
			/// we can provide proof-of-payment details in payment claim events even after a restart
			/// with a stale ChannelManager state.
			bolt12_invoice: Option<PaidBolt12Invoice>,
		},
	}

	/// Tracks the inbound corresponding to an outbound HTLC
	#[derive(Clone, Debug, Hash, PartialEq, Eq)]
	pub struct HTLCPreviousHopData {
		pub prev_outbound_scid_alias: u64,
		pub user_channel_id: Option<u128>,
		pub htlc_id: u64,
		pub incoming_packet_shared_secret: [u8; 32],
		pub phantom_shared_secret: Option<[u8; 32]>,
		pub trampoline_shared_secret: Option<[u8; 32]>,
		pub blinded_failure: Option<BlindedFailure>,
		pub channel_id: ChannelId,

		// These fields are consumed by `claim_funds_from_hop()` when updating a force-closed backwards
		// channel with a preimage provided by the forward channel.
		pub outpoint: OutPoint,
		pub counterparty_node_id: Option<PublicKey>,
		/// Used to preserve our backwards channel by failing back in case an HTLC claim in the forward
		/// channel remains unconfirmed for too long.
		pub cltv_expiry: Option<u32>,
	}
}
#[cfg(fuzzing)]
pub use self::fuzzy_channelmanager::*;
#[cfg(not(fuzzing))]
pub(crate) use self::fuzzy_channelmanager::*;

#[allow(clippy::derive_hash_xor_eq)] // Our Hash is faithful to the data, we just don't have SecretKey::hash
impl core::hash::Hash for HTLCSource {
	fn hash<H: core::hash::Hasher>(&self, hasher: &mut H) {
		match self {
			HTLCSource::PreviousHopData(prev_hop_data) => {
				0u8.hash(hasher);
				prev_hop_data.hash(hasher);
			},
			HTLCSource::OutboundRoute {
				path,
				session_priv,
				payment_id,
				first_hop_htlc_msat,
				bolt12_invoice,
			} => {
				1u8.hash(hasher);
				path.hash(hasher);
				session_priv[..].hash(hasher);
				payment_id.hash(hasher);
				first_hop_htlc_msat.hash(hasher);
				bolt12_invoice.hash(hasher);
			},
		}
	}
}
impl HTLCSource {
	#[cfg(any(test, all(ldk_test_vectors, feature = "grind_signatures")))]
	pub fn dummy() -> Self {
		HTLCSource::OutboundRoute {
			path: Path { hops: Vec::new(), blinded_tail: None },
			session_priv: SecretKey::from_slice(&[1; 32]).unwrap(),
			first_hop_htlc_msat: 0,
			payment_id: PaymentId([2; 32]),
			bolt12_invoice: None,
		}
	}

	/// Checks whether this HTLCSource could possibly match the given HTLC output in a commitment
	/// transaction. Useful to ensure different datastructures match up.
	pub(crate) fn possibly_matches_output(
		&self, htlc: &super::chan_utils::HTLCOutputInCommitment,
	) -> bool {
		if let HTLCSource::OutboundRoute { first_hop_htlc_msat, .. } = self {
			*first_hop_htlc_msat == htlc.amount_msat
		} else {
			// There's nothing we can check for forwarded HTLCs
			true
		}
	}

	/// Returns the CLTV expiry of the inbound HTLC (i.e. the source referred to by this object),
	/// if the source was a forwarded HTLC and the HTLC was first forwarded on LDK 0.1.1 or later.
	pub(crate) fn inbound_htlc_expiry(&self) -> Option<u32> {
		match self {
			Self::PreviousHopData(HTLCPreviousHopData { cltv_expiry, .. }) => *cltv_expiry,
			_ => None,
		}
	}

	pub(crate) fn static_invoice(&self) -> Option<StaticInvoice> {
		match self {
			Self::OutboundRoute {
				bolt12_invoice: Some(PaidBolt12Invoice::StaticInvoice(inv)),
				..
			} => Some(inv.clone()),
			_ => None,
		}
	}
}

/// This enum is used to specify which error data to send to peers when failing back an HTLC
/// using [`ChannelManager::fail_htlc_backwards_with_reason`].
///
/// For more info on failure codes, see <https://github.com/lightning/bolts/blob/master/04-onion-routing.md#failure-messages>.
#[derive(Clone, Copy)]
pub enum FailureCode {
	/// We had a temporary error processing the payment. Useful if no other error codes fit
	/// and you want to indicate that the payer may want to retry.
	TemporaryNodeFailure,
	/// We have a required feature which was not in this onion. For example, you may require
	/// some additional metadata that was not provided with this payment.
	RequiredNodeFeatureMissing,
	/// You may wish to use this when a `payment_preimage` is unknown, or the CLTV expiry of
	/// the HTLC is too close to the current block height for safe handling.
	/// Using this failure code in [`ChannelManager::fail_htlc_backwards_with_reason`] is
	/// equivalent to calling [`ChannelManager::fail_htlc_backwards`].
	IncorrectOrUnknownPaymentDetails,
	/// We failed to process the payload after the onion was decrypted. You may wish to
	/// use this when receiving custom HTLC TLVs with even type numbers that you don't recognize.
	///
	/// If available, the tuple data may include the type number and byte offset in the
	/// decrypted byte stream where the failure occurred.
	InvalidOnionPayload(Option<(u64, u16)>),
}

impl Into<LocalHTLCFailureReason> for FailureCode {
	fn into(self) -> LocalHTLCFailureReason {
		match self {
			FailureCode::TemporaryNodeFailure => LocalHTLCFailureReason::TemporaryNodeFailure,
			FailureCode::RequiredNodeFeatureMissing => LocalHTLCFailureReason::RequiredNodeFeature,
			FailureCode::IncorrectOrUnknownPaymentDetails => {
				LocalHTLCFailureReason::IncorrectPaymentDetails
			},
			FailureCode::InvalidOnionPayload(_) => LocalHTLCFailureReason::InvalidOnionPayload,
		}
	}
}

/// Error type returned across the peer_state mutex boundary. When an Err is generated for a
/// Channel, we generally end up with a ChannelError::Close for which we have to close the channel
/// immediately (ie with no further calls on it made). Thus, this step happens inside a
/// peer_state lock. We then return the set of things that need to be done outside the lock in
/// this struct and call handle_error!() on it.
struct MsgHandleErrInternal {
	err: msgs::LightningError,
	closes_channel: bool,
	shutdown_finish: Option<(ShutdownResult, Option<(msgs::ChannelUpdate, NodeId, NodeId)>)>,
	tx_abort: Option<msgs::TxAbort>,
	exited_quiescence: bool,
}

impl MsgHandleErrInternal {
	fn send_err_msg_no_close(err: String, channel_id: ChannelId) -> Self {
		Self {
			err: LightningError {
				err: err.clone(),
				action: msgs::ErrorAction::SendErrorMessage {
					msg: msgs::ErrorMessage { channel_id, data: err },
				},
			},
			closes_channel: false,
			shutdown_finish: None,
			tx_abort: None,
			exited_quiescence: false,
		}
	}

	fn unreachable_no_such_peer(counterparty_node_id: &PublicKey, channel_id: ChannelId) -> Self {
		debug_assert!(false);
		let err =
			format!("No such peer for the passed counterparty_node_id {counterparty_node_id}");
		Self::send_err_msg_no_close(err, channel_id)
	}

	fn no_such_channel_for_peer(counterparty_node_id: &PublicKey, channel_id: ChannelId) -> Self {
		let err = format!(
			"Got a message for a channel from the wrong node! No such channel_id {} for the passed counterparty_node_id {}",
			channel_id, counterparty_node_id
		);
		Self::send_err_msg_no_close(err, channel_id)
	}

	fn from_no_close(err: msgs::LightningError) -> Self {
		Self {
			err,
			closes_channel: false,
			shutdown_finish: None,
			tx_abort: None,
			exited_quiescence: false,
		}
	}

	fn from_finish_shutdown(
		err: String, channel_id: ChannelId, shutdown_res: ShutdownResult,
		channel_update: Option<(msgs::ChannelUpdate, NodeId, NodeId)>,
	) -> Self {
		let err_msg = msgs::ErrorMessage { channel_id, data: err.clone() };
		let action = if shutdown_res.monitor_update.is_some() {
			// We have a closing `ChannelMonitorUpdate`, which means the channel was funded and we
			// should disconnect our peer such that we force them to broadcast their latest
			// commitment upon reconnecting.
			msgs::ErrorAction::DisconnectPeer { msg: Some(err_msg) }
		} else {
			msgs::ErrorAction::SendErrorMessage { msg: err_msg }
		};
		Self {
			err: LightningError { err, action },
			closes_channel: true,
			shutdown_finish: Some((shutdown_res, channel_update)),
			tx_abort: None,
			exited_quiescence: false,
		}
	}

	fn from_chan_no_close(err: ChannelError, channel_id: ChannelId) -> Self {
		let tx_abort = match &err {
			&ChannelError::Abort(reason) => Some(reason.into_tx_abort_msg(channel_id)),
			_ => None,
		};
		let err = match err {
			ChannelError::Warn(msg) => LightningError {
				err: msg.clone(),
				action: msgs::ErrorAction::SendWarningMessage {
					msg: msgs::WarningMessage { channel_id, data: msg },
					log_level: Level::Warn,
				},
			},
			ChannelError::WarnAndDisconnect(msg) => LightningError {
				err: msg.clone(),
				action: msgs::ErrorAction::DisconnectPeerWithWarning {
					msg: msgs::WarningMessage { channel_id, data: msg },
				},
			},
			ChannelError::Ignore(msg) => {
				LightningError { err: msg, action: msgs::ErrorAction::IgnoreError }
			},
			ChannelError::Abort(reason) => {
				LightningError { err: reason.to_string(), action: msgs::ErrorAction::IgnoreError }
			},
			ChannelError::Close((msg, _)) | ChannelError::SendError(msg) => LightningError {
				err: msg.clone(),
				action: msgs::ErrorAction::SendErrorMessage {
					msg: msgs::ErrorMessage { channel_id, data: msg },
				},
			},
		};
		Self {
			err,
			closes_channel: false,
			shutdown_finish: None,
			tx_abort,
			exited_quiescence: false,
		}
	}

	fn dont_send_error_message(&mut self) {
		match &mut self.err.action {
			msgs::ErrorAction::DisconnectPeer { msg } => *msg = None,
			msgs::ErrorAction::SendErrorMessage { msg: _ } => {
				self.err.action = msgs::ErrorAction::IgnoreError;
			},
			_ => {},
		}
	}

	fn closes_channel(&self) -> bool {
		self.closes_channel
	}

	fn with_exited_quiescence(mut self, exited_quiescence: bool) -> Self {
		self.exited_quiescence = exited_quiescence;
		self
	}
}

/// For events which result in both a RevokeAndACK and a CommitmentUpdate, by default they should
/// be sent in the order they appear in the return value, however sometimes the order needs to be
/// variable at runtime (eg FundedChannel::channel_reestablish needs to re-send messages in the order
/// they were originally sent). In those cases, this enum is also returned.
#[derive(Clone, PartialEq, Debug)]
pub(super) enum RAACommitmentOrder {
	/// Send the CommitmentUpdate messages first
	CommitmentFirst,
	/// Send the RevokeAndACK message first
	RevokeAndACKFirst,
}

/// Similar to scenarios used by [`RAACommitmentOrder`], this determines whether a `channel_ready`
/// message should be sent first (i.e., prior to a `commitment_update`) or after the initial
/// `commitment_update` and `tx_signatures` for channel funding.
pub(super) enum ChannelReadyOrder {
	/// Send `channel_ready` message first.
	ChannelReadyFirst,
	/// Send initial `commitment_update` and `tx_signatures` first.
	SignaturesFirst,
}

/// Information about a payment which is currently being claimed.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ClaimingPayment {
	amount_msat: u64,
	payment_purpose: events::PaymentPurpose,
	receiver_node_id: PublicKey,
	htlcs: Vec<events::ClaimedHTLC>,
	sender_intended_value: Option<u64>,
	onion_fields: Option<RecipientOnionFields>,
	payment_id: Option<PaymentId>,
	/// When we claim and generate a [`Event::PaymentClaimed`], we want to block any
	/// payment-preimage-removing RAA [`ChannelMonitorUpdate`]s until the [`Event::PaymentClaimed`]
	/// is handled, ensuring we can regenerate the event on restart. We pick a random channel to
	/// block and store it here.
	///
	/// Note that once we disallow downgrades to 0.1 we should be able to simply use
	/// [`Self::htlcs`] to generate this rather than storing it here (as we won't need the funding
	/// outpoint), allowing us to remove this field.
	durable_preimage_channel: Option<(OutPoint, PublicKey, ChannelId)>,
}
impl_writeable_tlv_based!(ClaimingPayment, {
	(0, amount_msat, required),
	(1, durable_preimage_channel, option),
	(2, payment_purpose, required),
	(4, receiver_node_id, required),
	(5, htlcs, optional_vec),
	(7, sender_intended_value, option),
	(9, onion_fields, option),
	(11, payment_id, option),
});

struct ClaimablePayment {
	purpose: events::PaymentPurpose,
	onion_fields: Option<RecipientOnionFields>,
	htlcs: Vec<ClaimableHTLC>,
}

impl ClaimablePayment {
	fn inbound_payment_id(&self, secret: &[u8; 32]) -> PaymentId {
		PaymentId::for_inbound_from_htlcs(
			secret,
			self.htlcs.iter().map(|htlc| (htlc.prev_hop.channel_id, htlc.prev_hop.htlc_id)),
		)
	}

	/// Returns the inbound `(channel_id, user_channel_id)` pairs for all HTLCs associated with the payment.
	///
	/// Note: The `user_channel_id` will be `None` for HTLCs created using LDK version 0.0.117 or prior.
	fn receiving_channel_ids(&self) -> Vec<(ChannelId, Option<u128>)> {
		self.htlcs
			.iter()
			.map(|htlc| (htlc.prev_hop.channel_id, htlc.prev_hop.user_channel_id))
			.collect()
	}
}

/// Represent the channel funding transaction type.
enum FundingType {
	/// This variant is useful when we want LDK to validate the funding transaction and
	/// broadcast it automatically.
	///
	/// This is the normal flow.
	Checked(Transaction),
	/// This variant is useful when we want LDK to validate the funding transaction and
	/// broadcast it manually.
	///
	/// Used in LSPS2 on a client_trusts_lsp model
	CheckedManualBroadcast(Transaction),
	/// This variant is useful when we want to loosen the validation checks and allow to
	/// manually broadcast the funding transaction, leaving the responsibility to the caller.
	///
	/// This is useful in cases of constructing the funding transaction as part of another
	/// flow and the caller wants to perform the validation and broadcasting. An example of such
	/// scenario could be when constructing the funding transaction as part of a Payjoin
	/// transaction.
	Unchecked(OutPoint),
}

impl FundingType {
	fn txid(&self) -> Txid {
		match self {
			FundingType::Checked(tx) => tx.compute_txid(),
			FundingType::CheckedManualBroadcast(tx) => tx.compute_txid(),
			FundingType::Unchecked(outp) => outp.txid,
		}
	}

	fn transaction_or_dummy(&self) -> Transaction {
		match self {
			FundingType::Checked(tx) => tx.clone(),
			FundingType::CheckedManualBroadcast(tx) => tx.clone(),
			FundingType::Unchecked(_) => Transaction {
				version: bitcoin::transaction::Version::TWO,
				lock_time: bitcoin::absolute::LockTime::ZERO,
				input: Vec::new(),
				output: Vec::new(),
			},
		}
	}

	fn is_manual_broadcast(&self) -> bool {
		match self {
			FundingType::Checked(_) => false,
			FundingType::CheckedManualBroadcast(_) => true,
			FundingType::Unchecked(_) => true,
		}
	}
}

/// Information about claimable or being-claimed payments
struct ClaimablePayments {
	/// Map from payment hash to the payment data and any HTLCs which are to us and can be
	/// failed/claimed by the user.
	///
	/// Note that, no consistency guarantees are made about the channels given here actually
	/// existing anymore by the time you go to read them!
	///
	/// When adding to the map, [`Self::pending_claiming_payments`] must also be checked to ensure
	/// we don't get a duplicate payment.
	claimable_payments: HashMap<PaymentHash, ClaimablePayment>,

	/// Map from payment hash to the payment data for HTLCs which we have begun claiming, but which
	/// are waiting on a [`ChannelMonitorUpdate`] to complete in order to be surfaced to the user
	/// as an [`events::Event::PaymentClaimed`].
	pending_claiming_payments: HashMap<PaymentHash, ClaimingPayment>,
}

impl ClaimablePayments {
	/// Moves a payment from [`Self::claimable_payments`] to [`Self::pending_claiming_payments`].
	///
	/// If `custom_tlvs_known` is false and custom even TLVs are set by the sender, the set of
	/// pending HTLCs will be returned in the `Err` variant of this method. They MUST then be
	/// failed by the caller as they will not be in either [`Self::claimable_payments`] or
	/// [`Self::pending_claiming_payments`].
	///
	/// If `custom_tlvs_known` is true, and a matching payment is found, it will always be moved.
	///
	/// If no payment is found, `Err(Vec::new())` is returned.
	#[rustfmt::skip]
	fn begin_claiming_payment<L: Logger, S: NodeSigner>(
		&mut self, payment_hash: PaymentHash, node_signer: &S, logger: &L,
		inbound_payment_id_secret: &[u8; 32], custom_tlvs_known: bool,
	) -> Result<(Vec<ClaimableHTLC>, ClaimingPayment), Vec<ClaimableHTLC>> {
		match self.claimable_payments.remove(&payment_hash) {
			Some(payment) => {
				let mut receiver_node_id = node_signer.get_node_id(Recipient::Node)
					.expect("Failed to get node_id for node recipient");
				for htlc in payment.htlcs.iter() {
					if htlc.prev_hop.phantom_shared_secret.is_some() {
						let phantom_pubkey = node_signer.get_node_id(Recipient::PhantomNode)
							.expect("Failed to get node_id for phantom node recipient");
						receiver_node_id = phantom_pubkey;
						break;
					}
				}

				if let Some(RecipientOnionFields { custom_tlvs, .. }) = &payment.onion_fields {
					if !custom_tlvs_known && custom_tlvs.iter().any(|(typ, _)| typ % 2 == 0) {
						log_info!(logger, "Rejecting payment with payment hash {} as we cannot accept payment with unknown even TLVs: {}",
							&payment_hash, log_iter!(custom_tlvs.iter().map(|(typ, _)| typ).filter(|typ| *typ % 2 == 0)));
						return Err(payment.htlcs);
					}
				}

				let payment_id = payment.inbound_payment_id(inbound_payment_id_secret);
				let claiming_payment = self.pending_claiming_payments
					.entry(payment_hash)
					.and_modify(|_| {
						debug_assert!(false, "Shouldn't get a duplicate pending claim event ever");
						log_error!(logger, "Got a duplicate pending claimable event on payment hash {}! Please report this bug",
							&payment_hash);
					})
					.or_insert_with(|| {
						let htlcs = payment.htlcs.iter().map(events::ClaimedHTLC::from).collect();
						let sender_intended_value = payment.htlcs.first().map(|htlc| htlc.total_msat);
						// Pick an "arbitrary" channel to block RAAs on until the `PaymentSent`
						// event is processed, specifically the last channel to get claimed.
						let durable_preimage_channel = payment.htlcs.last().map_or(None, |htlc| {
							if let Some(node_id) = htlc.prev_hop.counterparty_node_id {
								Some((htlc.prev_hop.outpoint, node_id, htlc.prev_hop.channel_id))
							} else {
								None
							}
						});
						debug_assert!(durable_preimage_channel.is_some());
						ClaimingPayment {
							amount_msat: payment.htlcs.iter().map(|source| source.value).sum(),
							payment_purpose: payment.purpose,
							receiver_node_id,
							htlcs,
							sender_intended_value,
							onion_fields: payment.onion_fields,
							payment_id: Some(payment_id),
							durable_preimage_channel,
						}
					}).clone();

				Ok((payment.htlcs, claiming_payment))
			},
			None => Err(Vec::new())
		}
	}
}

/// Events which we process internally but cannot be processed immediately at the generation site
/// usually because we're running pre-full-init. They are handled immediately once we detect we are
/// running normally, and specifically must be processed before any other non-background
/// [`ChannelMonitorUpdate`]s are applied.
#[derive(Debug)]
enum BackgroundEvent {
	/// Handle a ChannelMonitorUpdate which may or may not close the channel and may unblock the
	/// channel to continue normal operation.
	///
	/// Any such events that exist in [`ChannelManager::pending_background_events`] will *also* be
	/// tracked in [`PeerState::in_flight_monitor_updates`].
	///
	/// Note that any such events are lost on shutdown, so in general they must be updates which
	/// are regenerated on startup.
	MonitorUpdateRegeneratedOnStartup {
		counterparty_node_id: PublicKey,
		funding_txo: OutPoint,
		channel_id: ChannelId,
		update: ChannelMonitorUpdate,
	},
	/// Some [`ChannelMonitorUpdate`] (s) completed before we were serialized but we still have
	/// them marked pending, thus we need to run any [`MonitorUpdateCompletionAction`] (s) pending
	/// on a channel.
	MonitorUpdatesComplete {
		counterparty_node_id: PublicKey,
		channel_id: ChannelId,
		highest_update_id_completed: u64,
	},
}

/// A pointer to a channel that is unblocked when an event is surfaced
#[derive(Debug)]
pub(crate) struct EventUnblockedChannel {
	counterparty_node_id: PublicKey,
	funding_txo: OutPoint,
	channel_id: ChannelId,
	blocking_action: RAAMonitorUpdateBlockingAction,
}

impl Writeable for EventUnblockedChannel {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		self.counterparty_node_id.write(writer)?;
		self.funding_txo.write(writer)?;
		self.channel_id.write(writer)?;
		self.blocking_action.write(writer)
	}
}

impl MaybeReadable for EventUnblockedChannel {
	fn read<R: Read>(reader: &mut R) -> Result<Option<Self>, DecodeError> {
		let counterparty_node_id = Readable::read(reader)?;
		let funding_txo = Readable::read(reader)?;
		let channel_id = Readable::read(reader)?;
		let blocking_action = match RAAMonitorUpdateBlockingAction::read(reader)? {
			Some(blocking_action) => blocking_action,
			None => return Ok(None),
		};
		Ok(Some(EventUnblockedChannel {
			counterparty_node_id,
			funding_txo,
			channel_id,
			blocking_action,
		}))
	}
}

#[derive(Debug)]
/// Note that these run after all *non-blocked* [`ChannelMonitorUpdate`]s have been persisted.
/// Thus, they're primarily useful for (and currently only used for) claims, where the
/// [`ChannelMonitorUpdate`] we care about is a preimage update, which bypass the monitor update
/// blocking logic entirely and can never be blocked.
pub(crate) enum MonitorUpdateCompletionAction {
	/// Indicates that a payment ultimately destined for us was claimed and we should emit an
	/// [`events::Event::PaymentClaimed`] to the user if we haven't yet generated such an event for
	/// this payment. Note that this is only best-effort. On restart it's possible such a duplicate
	/// event can be generated.
	PaymentClaimed {
		payment_hash: PaymentHash,
		/// A pending MPP claim which hasn't yet completed.
		///
		/// Not written to disk.
		pending_mpp_claim: Option<(PublicKey, ChannelId, PendingMPPClaimPointer)>,
	},
	/// Indicates an [`events::Event`] should be surfaced to the user and possibly resume the
	/// operation of another channel.
	///
	/// This is usually generated when we've forwarded an HTLC and want to block the outbound edge
	/// from completing a monitor update which removes the payment preimage until the inbound edge
	/// completes a monitor update containing the payment preimage. In that case, after the inbound
	/// edge completes, we will surface an [`Event::PaymentForwarded`] as well as unblock the
	/// outbound edge.
	EmitEventAndFreeOtherChannel {
		event: events::Event,
		downstream_counterparty_and_funding_outpoint: Option<EventUnblockedChannel>,
	},
	/// Indicates we should immediately resume the operation of another channel, unless there is
	/// some other reason why the channel is blocked. In practice this simply means immediately
	/// removing the [`RAAMonitorUpdateBlockingAction`] provided from the blocking set.
	///
	/// This is usually generated when we've forwarded an HTLC and want to block the outbound edge
	/// from completing a monitor update which removes the payment preimage until the inbound edge
	/// completes a monitor update containing the payment preimage. However, we use this variant
	/// instead of [`Self::EmitEventAndFreeOtherChannel`] when we discover that the claim was in
	/// fact duplicative and we simply want to resume the outbound edge channel immediately.
	///
	/// This variant should thus never be written to disk, as it is processed inline rather than
	/// stored for later processing.
	FreeOtherChannelImmediately {
		downstream_counterparty_node_id: PublicKey,
		blocking_action: RAAMonitorUpdateBlockingAction,
		downstream_channel_id: ChannelId,
	},
}

impl_writeable_tlv_based_enum_upgradable!(MonitorUpdateCompletionAction,
	(0, PaymentClaimed) => {
		(0, payment_hash, required),
		(9999999999, pending_mpp_claim, (static_value, None)),
	},
	// Note that FreeOtherChannelImmediately should never be written - we were supposed to free
	// *immediately*. However, for simplicity we implement read/write here.
	(1, FreeOtherChannelImmediately) => {
		(0, downstream_counterparty_node_id, required),
		(4, blocking_action, upgradable_required),
		(5, downstream_channel_id, required),
	},
	(2, EmitEventAndFreeOtherChannel) => {
		(0, event, upgradable_required),
		// LDK prior to 0.0.116 did not have this field as the monitor update application order was
		// required by clients. If we downgrade to something prior to 0.0.116 this may result in
		// monitor updates which aren't properly blocked or resumed, however that's fine - we don't
		// support async monitor updates even in LDK 0.0.116 and once we do we'll require no
		// downgrades to prior versions.
		(1, downstream_counterparty_and_funding_outpoint, upgradable_option),
	},
);

/// Result of attempting to resume a channel after a monitor update completes while locks are held.
/// Contains remaining work to be processed after locks are released.
#[must_use]
enum PostMonitorUpdateChanResume {
	/// Channel still has blocked monitor updates pending. Contains only update actions to process.
	Blocked { update_actions: Vec<MonitorUpdateCompletionAction> },
	/// Channel was fully unblocked and has been resumed. Contains remaining data to process.
	Unblocked {
		channel_id: ChannelId,
		counterparty_node_id: PublicKey,
		funding_txo: OutPoint,
		user_channel_id: u128,
		unbroadcasted_batch_funding_txid: Option<Txid>,
		update_actions: Vec<MonitorUpdateCompletionAction>,
		htlc_forwards: Vec<PendingAddHTLCInfo>,
		decode_update_add_htlcs: Option<(u64, Vec<msgs::UpdateAddHTLC>)>,
		finalized_claimed_htlcs: Vec<(HTLCSource, Option<AttributionData>)>,
		failed_htlcs: Vec<(HTLCSource, PaymentHash, HTLCFailReason)>,
		committed_outbound_htlc_sources: Vec<(HTLCPreviousHopData, u64)>,
	},
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PaymentCompleteUpdate {
	counterparty_node_id: PublicKey,
	channel_funding_outpoint: OutPoint,
	channel_id: ChannelId,
	htlc_id: SentHTLCId,
}

impl_writeable_tlv_based!(PaymentCompleteUpdate, {
	(1, channel_funding_outpoint, required),
	(3, counterparty_node_id, required),
	(5, channel_id, required),
	(7, htlc_id, required),
});

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum EventCompletionAction {
	ReleaseRAAChannelMonitorUpdate {
		counterparty_node_id: PublicKey,
		// Was required until LDK 0.2. Always filled in as `Some`.
		channel_funding_outpoint: Option<OutPoint>,
		channel_id: ChannelId,
	},

	/// When a payment's resolution is communicated to the downstream logic via
	/// [`Event::PaymentSent`] or [`Event::PaymentFailed`] we may want to mark the payment as
	/// fully-resolved in the [`ChannelMonitor`], which we do via this action.
	/// Note that this action will be dropped on downgrade to LDK prior to 0.2!
	ReleasePaymentCompleteChannelMonitorUpdate(PaymentCompleteUpdate),
}
impl_writeable_tlv_based_enum!(EventCompletionAction,
	(0, ReleaseRAAChannelMonitorUpdate) => {
		(0, channel_funding_outpoint, option),
		(2, counterparty_node_id, required),
		(3, channel_id, (default_value, {
			if channel_funding_outpoint.is_none() {
				Err(DecodeError::InvalidValue)?
			}
			ChannelId::v1_from_funding_outpoint(channel_funding_outpoint.unwrap())
		})),
	}
	{1, ReleasePaymentCompleteChannelMonitorUpdate} => (),
);

/// The source argument which is passed to [`ChannelManager::claim_mpp_part`].
///
/// This is identical to [`MPPClaimHTLCSource`] except that [`Self::counterparty_node_id`] is an
/// `Option`, whereas it is required in [`MPPClaimHTLCSource`]. In the future, we should ideally
/// drop this and merge the two, however doing so may break upgrades for nodes which have pending
/// forwarded payments.
struct HTLCClaimSource {
	counterparty_node_id: PublicKey,
	funding_txo: OutPoint,
	channel_id: ChannelId,
	htlc_id: u64,
}

impl From<&MPPClaimHTLCSource> for HTLCClaimSource {
	fn from(o: &MPPClaimHTLCSource) -> HTLCClaimSource {
		HTLCClaimSource {
			counterparty_node_id: o.counterparty_node_id,
			funding_txo: o.funding_txo,
			channel_id: o.channel_id,
			htlc_id: o.htlc_id,
		}
	}
}

#[derive(Debug)]
pub(crate) struct PendingMPPClaim {
	channels_without_preimage: Vec<(PublicKey, ChannelId)>,
	channels_with_preimage: Vec<(PublicKey, ChannelId)>,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
/// The source of an HTLC which is being claimed as a part of an incoming payment. Each part is
/// tracked in [`ChannelMonitor`]s, so that it can be converted to an [`HTLCClaimSource`] for claim
/// replays on startup.
struct MPPClaimHTLCSource {
	counterparty_node_id: PublicKey,
	funding_txo: OutPoint,
	channel_id: ChannelId,
	htlc_id: u64,
}

impl_writeable_tlv_based!(MPPClaimHTLCSource, {
	(0, counterparty_node_id, required),
	(2, funding_txo, required),
	(4, channel_id, required),
	(6, htlc_id, required),
});

#[derive(Clone, Debug, PartialEq, Eq)]
/// When we're claiming a(n MPP) payment, we want to store information about that payment in the
/// [`ChannelMonitor`] so that we can replay the claim without any information from the
/// [`ChannelManager`] at all. This struct stores that information with enough to replay claims
/// against all MPP parts as well as generate an [`Event::PaymentClaimed`].
pub(crate) struct PaymentClaimDetails {
	mpp_parts: Vec<MPPClaimHTLCSource>,
	/// Use [`ClaimingPayment`] as a stable source of all the fields we need to generate the
	/// [`Event::PaymentClaimed`].
	claiming_payment: ClaimingPayment,
}

impl_writeable_tlv_based!(PaymentClaimDetails, {
	(0, mpp_parts, required_vec),
	(2, claiming_payment, required),
});

#[derive(Clone)]
pub(crate) struct PendingMPPClaimPointer(Arc<Mutex<PendingMPPClaim>>);

impl PartialEq for PendingMPPClaimPointer {
	fn eq(&self, o: &Self) -> bool {
		Arc::ptr_eq(&self.0, &o.0)
	}
}
impl Eq for PendingMPPClaimPointer {}

impl core::fmt::Debug for PendingMPPClaimPointer {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
		self.0.lock().unwrap().fmt(f)
	}
}

#[derive(Clone, PartialEq, Eq, Debug)]
/// If something is blocked on the completion of an RAA-generated [`ChannelMonitorUpdate`] we track
/// the blocked action here. See enum variants for more info.
pub(crate) enum RAAMonitorUpdateBlockingAction {
	/// A forwarded payment was claimed. We block the downstream channel completing its monitor
	/// update which removes the HTLC preimage until the upstream channel has gotten the preimage
	/// durably to disk.
	ForwardedPaymentInboundClaim {
		/// The upstream channel ID (i.e. the inbound edge).
		channel_id: ChannelId,
		/// The HTLC ID on the inbound edge.
		htlc_id: u64,
	},
	/// We claimed an MPP payment across multiple channels. We have to block removing the payment
	/// preimage from any monitor until the last monitor is updated to contain the payment
	/// preimage. Otherwise we may not be able to replay the preimage on the monitor(s) that
	/// weren't updated on startup.
	///
	/// This variant is *not* written to disk, instead being inferred from [`ChannelMonitor`]
	/// state.
	ClaimedMPPPayment { pending_claim: PendingMPPClaimPointer },
}

impl RAAMonitorUpdateBlockingAction {
	fn from_prev_hop_data(prev_hop: &HTLCPreviousHopData) -> Self {
		Self::ForwardedPaymentInboundClaim {
			channel_id: prev_hop.channel_id,
			htlc_id: prev_hop.htlc_id,
		}
	}
}

impl_writeable_tlv_based_enum_upgradable!(RAAMonitorUpdateBlockingAction,
	(0, ForwardedPaymentInboundClaim) => { (0, channel_id, required), (2, htlc_id, required) },
	unread_variants: ClaimedMPPPayment
);

impl Readable for Option<RAAMonitorUpdateBlockingAction> {
	fn read<R: Read>(reader: &mut R) -> Result<Self, DecodeError> {
		Ok(RAAMonitorUpdateBlockingAction::read(reader)?)
	}
}

/// State we hold per-peer.
pub(super) struct PeerState<SP: SignerProvider> {
	/// `channel_id` -> `Channel`
	///
	/// Holds all channels where the peer is the counterparty.
	pub(super) channel_by_id: HashMap<ChannelId, Channel<SP>>,
	/// `temporary_channel_id` -> `InboundChannelRequest`.
	///
	/// Holds all unaccepted inbound channels where the peer is the counterparty.
	/// If the channel is accepted, then the entry in this table is removed and a Channel is
	/// created and placed in the `channel_by_id` table. If the channel is rejected, then
	/// the entry is simply removed.
	pub(super) inbound_channel_request_by_id: HashMap<ChannelId, InboundChannelRequest>,
	/// The latest `InitFeatures` we heard from the peer.
	latest_features: InitFeatures,
	/// Messages to send to the peer - pushed to in the same lock that they are generated in (except
	/// for broadcast messages, where ordering isn't as strict).
	pub(super) pending_msg_events: Vec<MessageSendEvent>,
	/// Map from Channel IDs to pending [`ChannelMonitorUpdate`]s which have been passed to the
	/// user but which have not yet completed. We still keep the funding outpoint around to backfill
	/// the legacy TLV field to support downgrading.
	///
	/// Note that the channel may no longer exist. For example if the channel was closed but we
	/// later needed to claim an HTLC which is pending on-chain, we may generate a monitor update
	/// for a missing channel.
	///
	/// Note that any pending [`BackgroundEvent::MonitorUpdateRegeneratedOnStartup`]s which are
	/// sitting in [`ChannelManager::pending_background_events`] will *also* be tracked here. This
	/// avoids a race condition during [`ChannelManager::pending_background_events`] processing
	/// where we complete one [`ChannelMonitorUpdate`] (but there are more pending as background
	/// events) but we conclude all pending [`ChannelMonitorUpdate`]s have completed and its safe
	/// to run post-completion actions.
	in_flight_monitor_updates: BTreeMap<ChannelId, (OutPoint, Vec<ChannelMonitorUpdate>)>,
	/// Map from a specific channel to some action(s) that should be taken when all pending
	/// [`ChannelMonitorUpdate`]s for the channel complete updating.
	///
	/// Note that because we generally only have one entry here a HashMap is pretty overkill. A
	/// BTreeMap currently stores more than ten elements per leaf node, so even up to a few
	/// channels with a peer this will just be one allocation and will amount to a linear list of
	/// channels to walk, avoiding the whole hashing rigmarole.
	///
	/// Note that the channel may no longer exist. For example, if a channel was closed but we
	/// later needed to claim an HTLC which is pending on-chain, we may generate a monitor update
	/// for a missing channel. While a malicious peer could construct a second channel with the
	/// same `temporary_channel_id` (or final `channel_id` in the case of 0conf channels or prior
	/// to funding appearing on-chain), the downstream `ChannelMonitor` set is required to ensure
	/// duplicates do not occur, so such channels should fail without a monitor update completing.
	///
	/// Note that these run after all *non-blocked* [`ChannelMonitorUpdate`]s have been persisted.
	/// Thus, they're primarily useful for (and currently only used for) claims, where the
	/// [`ChannelMonitorUpdate`] we care about is a preimage update, which bypass the monitor
	/// update blocking logic entirely and can never be blocked.
	monitor_update_blocked_actions: BTreeMap<ChannelId, Vec<MonitorUpdateCompletionAction>>,
	/// If another channel's [`ChannelMonitorUpdate`] needs to complete before a channel we have
	/// with this peer can complete an RAA [`ChannelMonitorUpdate`] (e.g. because the RAA update
	/// will remove a preimage that needs to be durably in an upstream channel first), we put an
	/// entry here to note that the channel with the key's ID is blocked on a set of actions.
	actions_blocking_raa_monitor_updates: BTreeMap<ChannelId, Vec<RAAMonitorUpdateBlockingAction>>,
	/// The latest [`ChannelMonitor::get_latest_update_id`] value for all closed channels as they
	/// exist on-disk/in our [`chain::Watch`].
	///
	/// If there are any updates pending in [`Self::in_flight_monitor_updates`] this will contain
	/// the highest `update_id` of all the pending in-flight updates (note that any pending updates
	/// not yet applied sitting in [`ChannelManager::pending_background_events`] will also be
	/// considered as they are also in [`Self::in_flight_monitor_updates`]).
	///
	/// Note that channels which were closed prior to LDK 0.1 may have a value here of `u64::MAX`.
	closed_channel_monitor_update_ids: BTreeMap<ChannelId, u64>,
	/// The peer is currently connected (i.e. we've seen a
	/// [`BaseMessageHandler::peer_connected`] and no corresponding
	/// [`BaseMessageHandler::peer_disconnected`].
	pub is_connected: bool,
	/// Holds the peer storage data for the channel partner on a per-peer basis.
	peer_storage: Vec<u8>,
}

impl<SP: SignerProvider> PeerState<SP> {
	/// Indicates that a peer meets the criteria where we're ok to remove it from our storage.
	/// If true is passed for `require_disconnected`, the function will return false if we haven't
	/// disconnected from the node already, ie. `PeerState::is_connected` is set to `true`.
	fn ok_to_remove(&self, require_disconnected: bool) -> bool {
		if require_disconnected && self.is_connected {
			return false;
		}
		for (_, updates) in self.in_flight_monitor_updates.values() {
			if !updates.is_empty() {
				return false;
			}
		}
		let chan_is_funded_or_outbound = |(_, channel): (_, &Channel<SP>)| {
			channel.is_funded() || channel.funding().is_outbound()
		};
		!self.channel_by_id.iter().any(chan_is_funded_or_outbound)
			&& self.monitor_update_blocked_actions.is_empty()
			&& self.closed_channel_monitor_update_ids.is_empty()
	}

	// Returns a count of all channels we have with this peer, including unfunded channels.
	fn total_channel_count(&self) -> usize {
		self.channel_by_id.len() + self.inbound_channel_request_by_id.len()
	}

	// Returns a bool indicating if the given `channel_id` matches a channel we have with this peer.
	fn has_channel(&self, channel_id: &ChannelId) -> bool {
		self.channel_by_id.contains_key(channel_id)
			|| self.inbound_channel_request_by_id.contains_key(channel_id)
	}
}

#[derive(Clone)]
pub(super) enum OpenChannelMessage {
	V1(msgs::OpenChannel),
	V2(msgs::OpenChannelV2),
}

pub(super) enum OpenChannelMessageRef<'a> {
	V1(&'a msgs::OpenChannel),
	V2(&'a msgs::OpenChannelV2),
}

/// A not-yet-accepted inbound (from counterparty) channel. Once
/// accepted, the parameters will be used to construct a channel.
pub(super) struct InboundChannelRequest {
	/// The original OpenChannel message.
	pub open_channel_msg: OpenChannelMessage,
	/// The number of ticks remaining before the request expires.
	pub ticks_remaining: i32,
}

/// The number of ticks that may elapse while we're waiting for an unaccepted inbound channel to be
/// accepted. An unaccepted channel that exceeds this limit will be abandoned.
const UNACCEPTED_INBOUND_CHANNEL_AGE_LIMIT_TICKS: i32 = 2;

/// The number of blocks of historical feerate estimates we keep around and consider when deciding
/// to force-close a channel for having too-low fees. Also the number of blocks we have to see
/// after startup before we consider force-closing channels for having too-low fees.
pub(super) const FEERATE_TRACKING_BLOCKS: usize = 144;

/// Stores a PaymentSecret and any other data we may need to validate an inbound payment is
/// actually ours and not some duplicate HTLC sent to us by a node along the route.
///
/// For users who don't want to bother doing their own payment preimage storage, we also store that
/// here.
///
/// Note that this struct will be removed entirely soon, in favor of storing no inbound payment data
/// and instead encoding it in the payment secret.
#[derive(Debug)]
struct PendingInboundPayment {
	/// The payment secret that the sender must use for us to accept this payment
	payment_secret: PaymentSecret,
	/// Time at which this HTLC expires - blocks with a header time above this value will result in
	/// this payment being removed.
	expiry_time: u64,
	/// Arbitrary identifier the user specifies (or not)
	user_payment_id: u64,
	// Other required attributes of the payment, optionally enforced:
	payment_preimage: Option<PaymentPreimage>,
	min_value_msat: Option<u64>,
}

/// [`SimpleArcChannelManager`] is useful when you need a [`ChannelManager`] with a static lifetime, e.g.
/// when you're using `lightning-net-tokio` (since `tokio::spawn` requires parameters with static
/// lifetimes). Other times you can afford a reference, which is more efficient, in which case
/// [`SimpleRefChannelManager`] is the more appropriate type. Defining these type aliases prevents
/// issues such as overly long function definitions. Note that the `ChannelManager` can take any type
/// that implements [`NodeSigner`], [`EntropySource`], and [`SignerProvider`] for its keys manager,
/// or, respectively, [`Router`] for its router, but this type alias chooses the concrete types
/// of [`KeysManager`] and [`DefaultRouter`].
///
/// This is not exported to bindings users as type aliases aren't supported in most languages.
#[cfg(not(c_bindings))]
pub type SimpleArcChannelManager<M, T, F, L> = ChannelManager<
	Arc<M>,
	Arc<T>,
	Arc<KeysManager>,
	Arc<KeysManager>,
	Arc<KeysManager>,
	Arc<F>,
	Arc<
		DefaultRouter<
			Arc<NetworkGraph<Arc<L>>>,
			Arc<L>,
			Arc<KeysManager>,
			Arc<RwLock<ProbabilisticScorer<Arc<NetworkGraph<Arc<L>>>, Arc<L>>>>,
			ProbabilisticScoringFeeParameters,
			ProbabilisticScorer<Arc<NetworkGraph<Arc<L>>>, Arc<L>>,
		>,
	>,
	Arc<DefaultMessageRouter<Arc<NetworkGraph<Arc<L>>>, Arc<L>, Arc<KeysManager>>>,
	Arc<L>,
>;

/// [`SimpleRefChannelManager`] is a type alias for a ChannelManager reference, and is the reference
/// counterpart to the [`SimpleArcChannelManager`] type alias. Use this type by default when you don't
/// need a ChannelManager with a static lifetime. You'll need a static lifetime in cases such as
/// usage of lightning-net-tokio (since `tokio::spawn` requires parameters with static lifetimes).
/// But if this is not necessary, using a reference is more efficient. Defining these type aliases
/// issues such as overly long function definitions. Note that the ChannelManager can take any type
/// that implements [`NodeSigner`], [`EntropySource`], and [`SignerProvider`] for its keys manager,
/// or, respectively, [`Router`]  for its router, but this type alias chooses the concrete types
/// of [`KeysManager`] and [`DefaultRouter`].
///
/// This is not exported to bindings users as type aliases aren't supported in most languages.
#[cfg(not(c_bindings))]
pub type SimpleRefChannelManager<'a, 'b, 'c, 'd, 'e, 'f, 'g, 'h, 'i, M, T, F, L> = ChannelManager<
	&'a M,
	&'b T,
	&'c KeysManager,
	&'c KeysManager,
	&'c KeysManager,
	&'d F,
	&'e DefaultRouter<
		&'f NetworkGraph<&'g L>,
		&'g L,
		&'c KeysManager,
		&'h RwLock<ProbabilisticScorer<&'f NetworkGraph<&'g L>, &'g L>>,
		ProbabilisticScoringFeeParameters,
		ProbabilisticScorer<&'f NetworkGraph<&'g L>, &'g L>,
	>,
	&'i DefaultMessageRouter<&'f NetworkGraph<&'g L>, &'g L, &'c KeysManager>,
	&'g L,
>;

/// A trivial trait which describes any [`ChannelManager`].
///
/// This is not exported to bindings users as general cover traits aren't useful in other
/// languages.
pub trait AChannelManager {
	/// A type implementing [`chain::Watch`].
	type Watch: chain::Watch<Self::Signer>;
	/// A type implementing [`BroadcasterInterface`].
	type Broadcaster: BroadcasterInterface;
	/// A type implementing [`EntropySource`].
	type EntropySource: EntropySource;
	/// A type implementing [`NodeSigner`].
	type NodeSigner: NodeSigner;
	/// A type implementing [`EcdsaChannelSigner`].
	type Signer: EcdsaChannelSigner + Sized;
	/// A type implementing [`SignerProvider`] for [`Self::Signer`].
	type SP: SignerProvider<EcdsaSigner = Self::Signer>;
	/// A type implementing [`FeeEstimator`].
	type FeeEstimator: FeeEstimator;
	/// A type implementing [`Router`].
	type Router: Router;
	/// A type implementing [`MessageRouter`].
	type MessageRouter: MessageRouter;
	/// A type implementing [`Logger`].
	type Logger: Logger;
	/// Returns a reference to the actual [`ChannelManager`] object.
	fn get_cm(
		&self,
	) -> &ChannelManager<
		Self::Watch,
		Self::Broadcaster,
		Self::EntropySource,
		Self::NodeSigner,
		Self::SP,
		Self::FeeEstimator,
		Self::Router,
		Self::MessageRouter,
		Self::Logger,
	>;
}

impl<
		M: chain::Watch<SP::EcdsaSigner>,
		T: BroadcasterInterface,
		ES: EntropySource,
		NS: NodeSigner,
		SP: SignerProvider,
		F: FeeEstimator,
		R: Router,
		MR: MessageRouter,
		L: Logger,
	> AChannelManager for ChannelManager<M, T, ES, NS, SP, F, R, MR, L>
{
	type Watch = M;
	type Broadcaster = T;
	type EntropySource = ES;
	type NodeSigner = NS;
	type Signer = SP::EcdsaSigner;
	type SP = SP;
	type FeeEstimator = F;
	type Router = R;
	type MessageRouter = MR;
	type Logger = L;
	fn get_cm(&self) -> &ChannelManager<M, T, ES, NS, SP, F, R, MR, L> {
		self
	}
}

/// A lightning node's channel state machine and payment management logic, which facilitates
/// sending, forwarding, and receiving payments through lightning channels.
///
/// [`ChannelManager`] is parameterized by a number of components to achieve this.
/// - [`chain::Watch`] (typically [`ChainMonitor`]) for on-chain monitoring and enforcement of each
///   channel
/// - [`BroadcasterInterface`] for broadcasting transactions related to opening, funding, and
///   closing channels
/// - [`EntropySource`] for providing random data needed for cryptographic operations
/// - [`NodeSigner`] for cryptographic operations scoped to the node
/// - [`SignerProvider`] for providing signers whose operations are scoped to individual channels
/// - [`FeeEstimator`] to determine transaction fee rates needed to have a transaction mined in a
///   timely manner
/// - [`Router`] for finding payment paths when initiating and retrying payments
/// - [`MessageRouter`] for finding message paths when initiating and retrying onion messages
/// - [`Logger`] for logging operational information of varying degrees
///
/// Additionally, it implements the following traits:
/// - [`ChannelMessageHandler`] to handle off-chain channel activity from peers
/// - [`BaseMessageHandler`] to handle peer dis/connection and send messages to peers
/// - [`OffersMessageHandler`] for BOLT 12 message handling and sending
/// - [`EventsProvider`] to generate user-actionable [`Event`]s
/// - [`chain::Listen`] and [`chain::Confirm`] for notification of on-chain activity
///
/// Thus, [`ChannelManager`] is typically used to parameterize a [`MessageHandler`] and an
/// [`OnionMessenger`]. The latter is required to support BOLT 12 functionality.
///
/// # `ChannelManager` vs `ChannelMonitor`
///
/// It's important to distinguish between the *off-chain* management and *on-chain* enforcement of
/// lightning channels. [`ChannelManager`] exchanges messages with peers to manage the off-chain
/// state of each channel. During this process, it generates a [`ChannelMonitor`] for each channel
/// and a [`ChannelMonitorUpdate`] for each relevant change, notifying its parameterized
/// [`chain::Watch`] of them.
///
/// An implementation of [`chain::Watch`], such as [`ChainMonitor`], is responsible for aggregating
/// these [`ChannelMonitor`]s and applying any [`ChannelMonitorUpdate`]s to them. It then monitors
/// for any pertinent on-chain activity, enforcing claims as needed.
///
/// This division of off-chain management and on-chain enforcement allows for interesting node
/// setups. For instance, on-chain enforcement could be moved to a separate host or have added
/// redundancy, possibly as a watchtower. See [`chain::Watch`] for the relevant interface.
///
/// # Initialization
///
/// Use [`ChannelManager::new`] with the most recent [`BlockHash`] when creating a fresh instance.
/// Otherwise, if restarting, construct [`ChannelManagerReadArgs`] with the necessary parameters and
/// references to any deserialized [`ChannelMonitor`]s that were previously persisted. Use this to
/// deserialize the [`ChannelManager`] and feed it any new chain data since it was last online, as
/// detailed in the [`ChannelManagerReadArgs`] documentation.
///
/// ```
/// use bitcoin::BlockHash;
/// use bitcoin::network::Network;
/// use lightning::chain::BestBlock;
/// # use lightning::chain::channelmonitor::ChannelMonitor;
/// use lightning::ln::channelmanager::{ChainParameters, ChannelManager, ChannelManagerReadArgs};
/// # use lightning::routing::gossip::NetworkGraph;
/// use lightning::util::config::UserConfig;
/// use lightning::util::ser::ReadableArgs;
///
/// # fn read_channel_monitors() -> Vec<ChannelMonitor<lightning::sign::InMemorySigner>> { vec![] }
/// # fn example<
/// #     'a,
/// #     L: lightning::util::logger::Logger,
/// #     ES: lightning::sign::EntropySource,
/// #     S: for <'b> lightning::routing::scoring::LockableScore<'b, ScoreLookUp = SL>,
/// #     SL: lightning::routing::scoring::ScoreLookUp<ScoreParams = SP>,
/// #     SP: Sized,
/// #     R: lightning::io::Read,
/// # >(
/// #     fee_estimator: &dyn lightning::chain::chaininterface::FeeEstimator,
/// #     chain_monitor: &dyn lightning::chain::Watch<lightning::sign::InMemorySigner>,
/// #     tx_broadcaster: &dyn lightning::chain::chaininterface::BroadcasterInterface,
/// #     router: &lightning::routing::router::DefaultRouter<&NetworkGraph<&'a L>, &'a L, &ES, &S, SP, SL>,
/// #     message_router: &lightning::onion_message::messenger::DefaultMessageRouter<&NetworkGraph<&'a L>, &'a L, &ES>,
/// #     logger: &L,
/// #     entropy_source: &ES,
/// #     node_signer: &dyn lightning::sign::NodeSigner,
/// #     signer_provider: &lightning::sign::DynSignerProvider,
/// #     best_block: lightning::chain::BestBlock,
/// #     current_timestamp: u32,
/// #     mut reader: R,
/// # ) -> Result<(), lightning::ln::msgs::DecodeError> {
/// // Fresh start with no channels
/// let params = ChainParameters {
///     network: Network::Bitcoin,
///     best_block,
/// };
/// let config = UserConfig::default();
/// let channel_manager = ChannelManager::new(
///     fee_estimator, chain_monitor, tx_broadcaster, router, message_router, logger,
///     entropy_source, node_signer, signer_provider, config.clone(), params, current_timestamp,
/// );
///
/// // Restart from deserialized data
/// let mut channel_monitors = read_channel_monitors();
/// let args = ChannelManagerReadArgs::new(
///     entropy_source, node_signer, signer_provider, fee_estimator, chain_monitor, tx_broadcaster,
///     router, message_router, logger, config, channel_monitors.iter().collect(),
/// );
/// let (block_hash, channel_manager) =
///     <(BlockHash, ChannelManager<_, _, _, _, _, _, _, _, _>)>::read(&mut reader, args)?;
///
/// // Update the ChannelManager and ChannelMonitors with the latest chain data
/// // ...
///
/// // Move the monitors to the ChannelManager's chain::Watch parameter
/// for monitor in channel_monitors {
///     chain_monitor.watch_channel(monitor.channel_id(), monitor);
/// }
/// # Ok(())
/// # }
/// ```
///
/// # Operation
///
/// The following is required for [`ChannelManager`] to function properly:
/// - Handle messages from peers using its [`ChannelMessageHandler`] implementation (typically
///   called by [`PeerManager::read_event`] when processing network I/O)
/// - Process peer connections and send messages to peers obtained via its [`BaseMessageHandler`]
///   implementation (typically initiated when [`PeerManager::process_events`] is called)
/// - Feed on-chain activity using either its [`chain::Listen`] or [`chain::Confirm`] implementation
///   as documented by those traits
/// - Perform any periodic channel and payment checks by calling [`timer_tick_occurred`] roughly
///   every minute
/// - Persist to disk whenever [`get_and_clear_needs_persistence`] returns `true` using a
///   [`KVStoreSync`] implementation
/// - Handle [`Event`]s obtained via its [`EventsProvider`] implementation
///
/// The [`Future`] returned by [`get_event_or_persistence_needed_future`] is useful in determining
/// when the last two requirements need to be checked.
///
/// The [`lightning-block-sync`] and [`lightning-transaction-sync`] crates provide utilities that
/// simplify feeding in on-chain activity using the [`chain::Listen`] and [`chain::Confirm`] traits,
/// respectively. The remaining requirements can be met using the [`lightning-background-processor`]
/// crate. For languages other than Rust, the availability of similar utilities may vary.
///
/// # Channels
///
/// [`ChannelManager`]'s primary function involves managing a channel state. Without channels,
/// payments can't be sent. Use [`list_channels`] or [`list_usable_channels`] for a snapshot of the
/// currently open channels.
///
/// ```
/// # use lightning::ln::channelmanager::AChannelManager;
/// #
/// # fn example<T: AChannelManager>(channel_manager: T) {
/// # let channel_manager = channel_manager.get_cm();
/// let channels = channel_manager.list_usable_channels();
/// for details in channels {
///     println!("{:?}", details);
/// }
/// # }
/// ```
///
/// Each channel is identified using a [`ChannelId`], which will change throughout the channel's
/// life cycle. Additionally, channels are assigned a `user_channel_id`, which is given in
/// [`Event`]s associated with the channel and serves as a fixed identifier but is otherwise unused
/// by [`ChannelManager`].
///
/// ## Opening Channels
///
/// To open a channel with a peer, call [`create_channel`]. This will initiate the process of
/// opening an outbound channel, which requires self-funding when handling
/// [`Event::FundingGenerationReady`].
///
/// ```
/// # use bitcoin::{ScriptBuf, Transaction};
/// # use bitcoin::secp256k1::PublicKey;
/// # use lightning::ln::channelmanager::AChannelManager;
/// # use lightning::events::{Event, EventsProvider};
/// #
/// # trait Wallet {
/// #     fn create_funding_transaction(
/// #         &self, _amount_sats: u64, _output_script: ScriptBuf
/// #     ) -> Transaction;
/// # }
/// #
/// # fn example<T: AChannelManager, W: Wallet>(channel_manager: T, wallet: W, peer_id: PublicKey) {
/// # let channel_manager = channel_manager.get_cm();
/// let value_sats = 1_000_000;
/// let push_msats = 10_000_000;
/// match channel_manager.create_channel(peer_id, value_sats, push_msats, 42, None, None) {
///     Ok(channel_id) => println!("Opening channel {}", channel_id),
///     Err(e) => println!("Error opening channel: {:?}", e),
/// }
///
/// // On the event processing thread once the peer has responded
/// channel_manager.process_pending_events(&|event| {
///     match event {
///         Event::FundingGenerationReady {
///             temporary_channel_id, counterparty_node_id, channel_value_satoshis, output_script,
///             user_channel_id, ..
///         } => {
///             assert_eq!(user_channel_id, 42);
///             let funding_transaction = wallet.create_funding_transaction(
///                 channel_value_satoshis, output_script
///             );
///             match channel_manager.funding_transaction_generated(
///                 temporary_channel_id, counterparty_node_id, funding_transaction
///             ) {
///                 Ok(()) => println!("Funding channel {}", temporary_channel_id),
///                 Err(e) => println!("Error funding channel {}: {:?}", temporary_channel_id, e),
///             }
///         },
///         Event::ChannelPending { channel_id, user_channel_id, former_temporary_channel_id, .. } => {
///             assert_eq!(user_channel_id, 42);
///             println!(
///                 "Channel {} now {} pending (funding transaction has been broadcasted)", channel_id,
///                 former_temporary_channel_id.unwrap()
///             );
///         },
///         Event::ChannelReady { channel_id, user_channel_id, .. } => {
///             assert_eq!(user_channel_id, 42);
///             println!("Channel {} ready", channel_id);
///         },
///         // ...
///     #     _ => {},
///     }
///     Ok(())
/// });
/// # }
/// ```
///
/// ## Accepting Channels
///
/// Inbound channels are initiated by peers and must be manually accepted or rejected when
/// handling [`Event::OpenChannelRequest`].
///
/// ```
/// # use bitcoin::secp256k1::PublicKey;
/// # use lightning::ln::channelmanager::AChannelManager;
/// # use lightning::events::{Event, EventsProvider};
/// #
/// # fn is_trusted(counterparty_node_id: PublicKey) -> bool {
/// #     // ...
/// #     unimplemented!()
/// # }
/// #
/// # fn example<T: AChannelManager>(channel_manager: T) {
/// # let channel_manager = channel_manager.get_cm();
/// # let error_message = "Channel force-closed";
/// channel_manager.process_pending_events(&|event| {
///     match event {
///         Event::OpenChannelRequest { temporary_channel_id, counterparty_node_id, ..  } => {
///             if !is_trusted(counterparty_node_id) {
///                 match channel_manager.force_close_broadcasting_latest_txn(
///                     &temporary_channel_id, &counterparty_node_id, error_message.to_string()
///                 ) {
///                     Ok(()) => println!("Rejecting channel {}", temporary_channel_id),
///                     Err(e) => println!("Error rejecting channel {}: {:?}", temporary_channel_id, e),
///                 }
///                 return Ok(());
///             }
///
///             let user_channel_id = 43;
///             match channel_manager.accept_inbound_channel(
///                 &temporary_channel_id, &counterparty_node_id, user_channel_id, None
///             ) {
///                 Ok(()) => println!("Accepting channel {}", temporary_channel_id),
///                 Err(e) => println!("Error accepting channel {}: {:?}", temporary_channel_id, e),
///             }
///         },
///         // ...
///     #     _ => {},
///     }
///     Ok(())
/// });
/// # }
/// ```
///
/// ## Closing Channels
///
/// There are two ways to close a channel: either cooperatively using [`close_channel`] or
/// unilaterally using [`force_close_broadcasting_latest_txn`]. The former is ideal as it makes for
/// lower fees and immediate access to funds. However, the latter may be necessary if the
/// counterparty isn't behaving properly or has gone offline. [`Event::ChannelClosed`] is generated
/// once the channel has been closed successfully.
///
/// ```
/// # use bitcoin::secp256k1::PublicKey;
/// # use lightning::ln::types::ChannelId;
/// # use lightning::ln::channelmanager::AChannelManager;
/// # use lightning::events::{Event, EventsProvider};
/// #
/// # fn example<T: AChannelManager>(
/// #     channel_manager: T, channel_id: ChannelId, counterparty_node_id: PublicKey
/// # ) {
/// # let channel_manager = channel_manager.get_cm();
/// match channel_manager.close_channel(&channel_id, &counterparty_node_id) {
///     Ok(()) => println!("Closing channel {}", channel_id),
///     Err(e) => println!("Error closing channel {}: {:?}", channel_id, e),
/// }
///
/// // On the event processing thread
/// channel_manager.process_pending_events(&|event| {
///     match event {
///         Event::ChannelClosed { channel_id, user_channel_id, ..  } => {
///             assert_eq!(user_channel_id, 42);
///             println!("Channel {} closed", channel_id);
///         },
///         // ...
///     #     _ => {},
///     }
///     Ok(())
/// });
/// # }
/// ```
///
/// # Payments
///
/// [`ChannelManager`] is responsible for sending, forwarding, and receiving payments through its
/// channels. A payment is typically initiated from a [BOLT 11] invoice or a [BOLT 12] offer, though
/// spontaneous (i.e., keysend) payments are also possible. Incoming payments don't require
/// maintaining any additional state as [`ChannelManager`] can reconstruct the [`PaymentPreimage`]
/// from the [`PaymentSecret`]. Sending payments, however, require tracking in order to retry failed
/// HTLCs.
///
/// After a payment is initiated, it will appear in [`list_recent_payments`] until a short time
/// after either an [`Event::PaymentSent`] or [`Event::PaymentFailed`] is handled. Failed HTLCs
/// for a payment will be retried according to the payment's [`Retry`] strategy or until
/// [`abandon_payment`] is called.
///
/// ## BOLT 11 Invoices
///
/// The [`lightning-invoice`] crate is useful for creating BOLT 11 invoices. However, in order to
/// construct a [`Bolt11Invoice`] that is compatible with [`ChannelManager`], use
/// [`create_bolt11_invoice`]. This method serves as a convenience for building invoices with the
/// [`PaymentHash`] and [`PaymentSecret`] returned from [`create_inbound_payment`]. To provide your
/// own [`PaymentHash`], override the appropriate [`Bolt11InvoiceParameters`], which is equivalent
/// to using [`create_inbound_payment_for_hash`].
///
/// [`ChannelManager`] generates an [`Event::PaymentClaimable`] once the full payment has been
/// received. Call [`claim_funds`] to release the [`PaymentPreimage`], which in turn will result in
/// an [`Event::PaymentClaimed`].
///
/// ```
/// # use lightning::events::{Event, EventsProvider, PaymentPurpose};
/// # use lightning::ln::channelmanager::{AChannelManager, Bolt11InvoiceParameters};
/// #
/// # fn example<T: AChannelManager>(channel_manager: T) {
/// # let channel_manager = channel_manager.get_cm();
/// let params = Bolt11InvoiceParameters {
///     amount_msats: Some(10_000_000),
///     invoice_expiry_delta_secs: Some(3600),
///     ..Default::default()
/// };
/// let invoice = match channel_manager.create_bolt11_invoice(params) {
///     Ok(invoice) => {
///         println!("Creating invoice with payment hash {}", invoice.payment_hash());
///         invoice
///     },
///     Err(e) => panic!("Error creating invoice: {}", e),
/// };
///
/// // On the event processing thread
/// channel_manager.process_pending_events(&|event| {
///     match event {
///         Event::PaymentClaimable { payment_hash, purpose, .. } => match purpose {
///             PaymentPurpose::Bolt11InvoicePayment { payment_preimage: Some(payment_preimage), .. } => {
///                 assert_eq!(payment_hash, invoice.payment_hash());
///                 println!("Claiming payment {}", payment_hash);
///                 channel_manager.claim_funds(payment_preimage);
///             },
///             PaymentPurpose::Bolt11InvoicePayment { payment_preimage: None, .. } => {
///                 println!("Unknown payment hash: {}", payment_hash);
///             },
///             PaymentPurpose::SpontaneousPayment(payment_preimage) => {
///                 assert_ne!(payment_hash, invoice.payment_hash());
///                 println!("Claiming spontaneous payment {}", payment_hash);
///                 channel_manager.claim_funds(payment_preimage);
///             },
///             // ...
/// #           _ => {},
///         },
///         Event::PaymentClaimed { payment_hash, amount_msat, .. } => {
///             assert_eq!(payment_hash, invoice.payment_hash());
///             println!("Claimed {} msats", amount_msat);
///         },
///         // ...
/// #       _ => {},
///     }
///     Ok(())
/// });
/// # }
/// ```
///
/// ```
/// # use bitcoin::hashes::Hash;
/// # use lightning::events::{Event, EventsProvider};
/// # use lightning::types::payment::PaymentHash;
/// # use lightning::ln::channelmanager::{AChannelManager, OptionalBolt11PaymentParams, PaymentId, RecentPaymentDetails};
/// # use lightning::ln::outbound_payment::Retry;
/// # use lightning_invoice::Bolt11Invoice;
/// #
/// # fn example<T: AChannelManager>(
/// #     channel_manager: T, invoice: &Bolt11Invoice, optional_params: OptionalBolt11PaymentParams,
/// #     retry: Retry
/// # ) {
/// # let channel_manager = channel_manager.get_cm();
/// # let payment_id = PaymentId([42; 32]);
/// # let payment_hash = invoice.payment_hash();
///
/// match channel_manager.pay_for_bolt11_invoice(
///     invoice, payment_id, None, optional_params
/// ) {
///     Ok(()) => println!("Sending payment with hash {}", payment_hash),
///     Err(e) => println!("Failed sending payment with hash {}: {:?}", payment_hash, e),
/// }
///
/// let expected_payment_id = payment_id;
/// let expected_payment_hash = payment_hash;
/// assert!(
///     channel_manager.list_recent_payments().iter().find(|details| matches!(
///         details,
///         RecentPaymentDetails::Pending {
///             payment_id: expected_payment_id,
///             payment_hash: expected_payment_hash,
///             ..
///         }
///     )).is_some()
/// );
///
/// // On the event processing thread
/// channel_manager.process_pending_events(&|event| {
///     match event {
///         Event::PaymentSent { payment_hash, .. } => println!("Paid {}", payment_hash),
///         Event::PaymentFailed { payment_hash: Some(payment_hash), .. } =>
///             println!("Failed paying {}", payment_hash),
///         // ...
///     #     _ => {},
///     }
///     Ok(())
/// });
/// # }
/// ```
///
/// ## BOLT 12 Offers
///
/// The [`offers`] module is useful for creating BOLT 12 offers. An [`Offer`] is a precursor to a
/// [`Bolt12Invoice`], which must first be requested by the payer. The interchange of these messages
/// as defined in the specification is handled by [`ChannelManager`] and its implementation of
/// [`OffersMessageHandler`]. However, this only works with an [`Offer`] created using a builder
/// returned by [`create_offer_builder`]. With this approach, BOLT 12 offers and invoices are
/// stateless just as BOLT 11 invoices are.
///
/// ```
/// # use lightning::events::{Event, EventsProvider, PaymentPurpose};
/// # use lightning::ln::channelmanager::AChannelManager;
/// # use lightning::offers::parse::Bolt12SemanticError;
/// # use lightning::routing::router::RouteParametersConfig;
/// #
/// # fn example<T: AChannelManager>(channel_manager: T) -> Result<(), Bolt12SemanticError> {
/// # let channel_manager = channel_manager.get_cm();
/// let offer = channel_manager
///     .create_offer_builder()?
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
/// Use [`pay_for_offer`] to initiated payment, which sends an [`InvoiceRequest`] for an [`Offer`]
/// and pays the [`Bolt12Invoice`] response.
///
/// ```
/// # use lightning::events::{Event, EventsProvider};
/// # use lightning::ln::channelmanager::{AChannelManager, PaymentId, RecentPaymentDetails};
/// # use lightning::offers::offer::Offer;
/// #
/// # fn example<T: AChannelManager>(
/// #     channel_manager: T, offer: &Offer, amount_msats: Option<u64>,
/// # ) {
/// # let channel_manager = channel_manager.get_cm();
/// let payment_id = PaymentId([42; 32]);
/// match channel_manager.pay_for_offer(
///     offer, amount_msats, payment_id, Default::default(),
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
/// A [`Refund`] is a request for an invoice to be paid. Like *paying* for an [`Offer`], *creating*
/// a [`Refund`] involves maintaining state since it represents a future outbound payment.
/// Therefore, use [`create_refund_builder`] when creating one, otherwise [`ChannelManager`] will
/// refuse to pay any corresponding [`Bolt12Invoice`] that it receives.
///
/// ```
/// # use core::time::Duration;
/// # use lightning::events::{Event, EventsProvider};
/// # use lightning::ln::channelmanager::{AChannelManager, PaymentId, RecentPaymentDetails};
/// # use lightning::ln::outbound_payment::Retry;
/// # use lightning::offers::parse::Bolt12SemanticError;
/// # use lightning::routing::router::RouteParametersConfig;
/// #
/// # fn example<T: AChannelManager>(
/// #     channel_manager: T, amount_msats: u64, absolute_expiry: Duration, retry: Retry,
/// #     route_params_config: RouteParametersConfig
/// # ) -> Result<(), Bolt12SemanticError> {
/// # let channel_manager = channel_manager.get_cm();
/// let payment_id = PaymentId([42; 32]);
/// let refund = channel_manager
///     .create_refund_builder(
///         amount_msats, absolute_expiry, payment_id, retry, route_params_config
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
/// Use [`request_refund_payment`] to send a [`Bolt12Invoice`] for receiving the refund. Similar to
/// *creating* an [`Offer`], this is stateless as it represents an inbound payment.
///
/// ```
/// # use lightning::events::{Event, EventsProvider, PaymentPurpose};
/// # use lightning::ln::channelmanager::AChannelManager;
/// # use lightning::offers::refund::Refund;
/// #
/// # fn example<T: AChannelManager>(channel_manager: T, refund: &Refund) {
/// # let channel_manager = channel_manager.get_cm();
/// let known_payment_hash = match channel_manager.request_refund_payment(refund) {
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
/// # Persistence
///
/// Implements [`Writeable`] to write out all channel state to disk. Implies [`peer_disconnected`] for
/// all peers during write/read (though does not modify this instance, only the instance being
/// serialized). This will result in any channels which have not yet exchanged [`funding_created`] (i.e.,
/// called [`funding_transaction_generated`] for outbound channels) being closed.
///
/// Note that you can be a bit lazier about writing out `ChannelManager` than you can be with
/// [`ChannelMonitor`]. With [`ChannelMonitor`] you MUST durably write each
/// [`ChannelMonitorUpdate`] before returning from
/// [`chain::Watch::watch_channel`]/[`update_channel`] or before completing async writes. With
/// `ChannelManager`s, writing updates happens out-of-band (and will prevent any other
/// `ChannelManager` operations from occurring during the serialization process). If the
/// deserialized version is out-of-date compared to the [`ChannelMonitor`] passed by reference to
/// [`read`], those channels will be force-closed based on the `ChannelMonitor` state and no funds
/// will be lost (modulo on-chain transaction fees).
///
/// Note that the deserializer is only implemented for `(`[`BlockHash`]`, `[`ChannelManager`]`)`, which
/// tells you the last block hash which was connected. You should get the best block tip before using the manager.
/// See [`chain::Listen`] and [`chain::Confirm`] for more details.
///
/// # `ChannelUpdate` Messages
///
/// Note that `ChannelManager` is responsible for tracking liveness of its channels and generating
/// [`ChannelUpdate`] messages informing peers that the channel is temporarily disabled. To avoid
/// spam due to quick disconnection/reconnection, updates are not sent until the channel has been
/// offline for a full minute. In order to track this, you must call
/// [`timer_tick_occurred`] roughly once per minute, though it doesn't have to be perfect.
///
/// # DoS Mitigation
///
/// To avoid trivial DoS issues, `ChannelManager` limits the number of inbound connections and
/// inbound channels without confirmed funding transactions. This may result in nodes which we do
/// not have a channel with being unable to connect to us or open new channels with us if we have
/// many peers with unfunded channels.
///
/// Because it is an indication of trust, inbound channels which we've accepted as 0conf are
/// exempted from the count of unfunded channels. Similarly, outbound channels and connections are
/// never limited. Please ensure you limit the count of such channels yourself.
///
/// # Type Aliases
///
/// Rather than using a plain `ChannelManager`, it is preferable to use either a [`SimpleArcChannelManager`]
/// a [`SimpleRefChannelManager`], for conciseness. See their documentation for more details, but
/// essentially you should default to using a [`SimpleRefChannelManager`], and use a
/// [`SimpleArcChannelManager`] when you require a `ChannelManager` with a static lifetime, such as when
/// you're using lightning-net-tokio.
///
/// [`ChainMonitor`]: crate::chain::chainmonitor::ChainMonitor
/// [`MessageHandler`]: crate::ln::peer_handler::MessageHandler
/// [`OnionMessenger`]: crate::onion_message::messenger::OnionMessenger
/// [`PeerManager::read_event`]: crate::ln::peer_handler::PeerManager::read_event
/// [`PeerManager::process_events`]: crate::ln::peer_handler::PeerManager::process_events
/// [`timer_tick_occurred`]: Self::timer_tick_occurred
/// [`get_and_clear_needs_persistence`]: Self::get_and_clear_needs_persistence
/// [`KVStoreSync`]: crate::util::persist::KVStoreSync
/// [`get_event_or_persistence_needed_future`]: Self::get_event_or_persistence_needed_future
/// [`lightning-block-sync`]: https://docs.rs/lightning_block_sync/latest/lightning_block_sync
/// [`lightning-transaction-sync`]: https://docs.rs/lightning_transaction_sync/latest/lightning_transaction_sync
/// [`lightning-background-processor`]: https://docs.rs/lightning-background-processor/latest/lightning_background_processor
/// [`list_channels`]: Self::list_channels
/// [`list_usable_channels`]: Self::list_usable_channels
/// [`create_channel`]: Self::create_channel
/// [`close_channel`]: Self::force_close_broadcasting_latest_txn
/// [`force_close_broadcasting_latest_txn`]: Self::force_close_broadcasting_latest_txn
/// [BOLT 11]: https://github.com/lightning/bolts/blob/master/11-payment-encoding.md
/// [BOLT 12]: https://github.com/rustyrussell/lightning-rfc/blob/guilt/offers/12-offer-encoding.md
/// [`list_recent_payments`]: Self::list_recent_payments
/// [`abandon_payment`]: Self::abandon_payment
/// [`lightning-invoice`]: https://docs.rs/lightning_invoice/latest/lightning_invoice
/// [`create_bolt11_invoice`]: Self::create_bolt11_invoice
/// [`create_inbound_payment`]: Self::create_inbound_payment
/// [`create_inbound_payment_for_hash`]: Self::create_inbound_payment_for_hash
/// [`claim_funds`]: Self::claim_funds
/// [`send_payment`]: Self::send_payment
/// [`offers`]: crate::offers
/// [`create_offer_builder`]: Self::create_offer_builder
/// [`pay_for_offer`]: Self::pay_for_offer
/// [`InvoiceRequest`]: crate::offers::invoice_request::InvoiceRequest
/// [`create_refund_builder`]: Self::create_refund_builder
/// [`request_refund_payment`]: Self::request_refund_payment
/// [`peer_disconnected`]: msgs::BaseMessageHandler::peer_disconnected
/// [`funding_created`]: msgs::FundingCreated
/// [`funding_transaction_generated`]: Self::funding_transaction_generated
/// [`BlockHash`]: bitcoin::hash_types::BlockHash
/// [`update_channel`]: chain::Watch::update_channel
/// [`ChannelUpdate`]: msgs::ChannelUpdate
/// [`read`]: ReadableArgs::read
pub struct ChannelManager<
	M: chain::Watch<SP::EcdsaSigner>,
	T: BroadcasterInterface,
	ES: EntropySource,
	NS: NodeSigner,
	SP: SignerProvider,
	F: FeeEstimator,
	R: Router,
	MR: MessageRouter,
	L: Logger,
> {
	config: RwLock<UserConfig>,
	chain_hash: ChainHash,
	fee_estimator: LowerBoundedFeeEstimator<F>,
	chain_monitor: M,
	tx_broadcaster: T,
	router: R,

	#[cfg(test)]
	pub(super) flow: OffersMessageFlow<MR, L>,
	#[cfg(not(test))]
	flow: OffersMessageFlow<MR, L>,

	#[cfg(any(test, feature = "_test_utils"))]
	pub(super) best_block: RwLock<BestBlock>,
	#[cfg(not(any(test, feature = "_test_utils")))]
	best_block: RwLock<BestBlock>,
	pub(super) secp_ctx: Secp256k1<secp256k1::All>,

	/// The session_priv bytes and retry metadata of outbound payments which are pending resolution.
	/// The authoritative state of these HTLCs resides either within Channels or ChannelMonitors
	/// (if the channel has been force-closed), however we track them here to prevent duplicative
	/// PaymentSent/PaymentPathFailed events. Specifically, in the case of a duplicative
	/// update_fulfill_htlc message after a reconnect, we may "claim" a payment twice.
	/// Additionally, because ChannelMonitors are often not re-serialized after connecting block(s)
	/// which may generate a claim event, we may receive similar duplicate claim/fail MonitorEvents
	/// after reloading from disk while replaying blocks against ChannelMonitors.
	///
	/// See `PendingOutboundPayment` documentation for more info.
	pending_outbound_payments: OutboundPayments,

	/// SCID/SCID Alias -> forward infos. Key of 0 means payments received.
	///
	/// Note that because we may have an SCID Alias as the key we can have two entries per channel,
	/// though in practice we probably won't be receiving HTLCs for a channel both via the alias
	/// and via the classic SCID.
	///
	/// Note that no consistency guarantees are made about the existence of a channel with the
	/// `short_channel_id` here, nor the `short_channel_id` in the `PendingHTLCInfo`!
	#[cfg(test)]
	pub(super) forward_htlcs: Mutex<HashMap<u64, Vec<HTLCForwardInfo>>>,
	#[cfg(not(test))]
	forward_htlcs: Mutex<HashMap<u64, Vec<HTLCForwardInfo>>>,
	/// Storage for HTLCs that have been intercepted.
	///
	/// These HTLCs fall into two categories:
	/// 1. HTLCs that are bubbled up to the user and held until the invocation of
	///    [`ChannelManager::forward_intercepted_htlc`] or [`ChannelManager::fail_intercepted_htlc`]
	///    (or timeout)
	/// 2. HTLCs that are being held on behalf of an often-offline sender until receipt of a
	///    [`ReleaseHeldHtlc`] onion message from an often-offline recipient
	pending_intercepted_htlcs: Mutex<HashMap<InterceptId, PendingAddHTLCInfo>>,

	/// Outbound SCID Alias -> pending `update_add_htlc`s to decode.
	/// We use the scid alias because regular scids may change if a splice occurs.
	///
	/// Note that no consistency guarantees are made about the existence of a channel with the
	/// `short_channel_id` here, nor the `channel_id` in `UpdateAddHTLC`!
	decode_update_add_htlcs: Mutex<HashMap<u64, Vec<msgs::UpdateAddHTLC>>>,

	/// The sets of payments which are claimable or currently being claimed. See
	/// [`ClaimablePayments`]' individual field docs for more info.
	claimable_payments: Mutex<ClaimablePayments>,

	/// The set of outbound SCID aliases across all our channels, including unconfirmed channels
	/// and some closed channels which reached a usable state prior to being closed. This is used
	/// only to avoid duplicates, and is not persisted explicitly to disk, but rebuilt from the
	/// active channel list on load.
	outbound_scid_aliases: Mutex<HashSet<u64>>,

	/// SCIDs (and outbound SCID aliases) -> `counterparty_node_id`s and `channel_id`s.
	///
	/// Outbound SCID aliases are added here once the channel is available for normal use, with
	/// SCIDs being added once the funding transaction is confirmed at the channel's required
	/// confirmation depth.
	///
	/// Note that while this holds `counterparty_node_id`s and `channel_id`s, no consistency
	/// guarantees are made about the existence of a peer with the `counterparty_node_id` nor a
	/// channel with the `channel_id` in our other maps.
	#[cfg(test)]
	pub(super) short_to_chan_info: FairRwLock<HashMap<u64, (PublicKey, ChannelId)>>,
	#[cfg(not(test))]
	short_to_chan_info: FairRwLock<HashMap<u64, (PublicKey, ChannelId)>>,

	our_network_pubkey: PublicKey,

	inbound_payment_key: inbound_payment::ExpandedKey,

	/// LDK puts the [fake scids] that it generates into namespaces, to identify the type of an
	/// incoming payment. To make it harder for a third-party to identify the type of a payment,
	/// we encrypt the namespace identifier using these bytes.
	///
	/// [fake scids]: crate::util::scid_utils::fake_scid
	fake_scid_rand_bytes: [u8; 32],

	/// When we send payment probes, we generate the [`PaymentHash`] based on this cookie secret
	/// and a random [`PaymentId`]. This allows us to discern probes from real payments, without
	/// keeping additional state.
	probing_cookie_secret: [u8; 32],

	/// When generating [`PaymentId`]s for inbound payments, we HMAC the HTLCs with this secret.
	inbound_payment_id_secret: [u8; 32],

	/// The highest block timestamp we've seen, which is usually a good guess at the current time.
	/// Assuming most miners are generating blocks with reasonable timestamps, this shouldn't be
	/// very far in the past, and can only ever be up to two hours in the future.
	highest_seen_timestamp: AtomicUsize,

	/// The bulk of our storage. Currently the `per_peer_state` stores our channels on a per-peer
	/// basis, as well as the peer's latest features.
	///
	/// If we are connected to a peer we always at least have an entry here, even if no channels
	/// are currently open with that peer.
	///
	/// Because adding or removing an entry is rare, we usually take an outer read lock and then
	/// operate on the inner value freely. This opens up for parallel per-peer operation for
	/// channels.
	///
	/// Note that the same thread must never acquire two inner `PeerState` locks at the same time.
	#[cfg(not(any(test, feature = "_test_utils")))]
	per_peer_state: FairRwLock<HashMap<PublicKey, Mutex<PeerState<SP>>>>,
	#[cfg(any(test, feature = "_test_utils"))]
	pub(super) per_peer_state: FairRwLock<HashMap<PublicKey, Mutex<PeerState<SP>>>>,

	/// We only support using one of [`ChannelMonitorUpdateStatus::InProgress`] and
	/// [`ChannelMonitorUpdateStatus::Completed`] without restarting. Because the API does not
	/// otherwise directly enforce this, we enforce it in non-test builds here by storing which one
	/// is in use.
	#[cfg(not(any(test, feature = "_externalize_tests")))]
	monitor_update_type: AtomicUsize,

	/// The set of events which we need to give to the user to handle. In some cases an event may
	/// require some further action after the user handles it (currently only blocking a monitor
	/// update from being handed to the user to ensure the included changes to the channel state
	/// are handled by the user before they're persisted durably to disk). In that case, the second
	/// element in the tuple is set to `Some` with further details of the action.
	///
	/// Note that events MUST NOT be removed from pending_events after deserialization, as they
	/// could be in the middle of being processed without the direct mutex held.
	#[cfg(not(any(test, feature = "_test_utils")))]
	pending_events: Mutex<VecDeque<(events::Event, Option<EventCompletionAction>)>>,
	#[cfg(any(test, feature = "_test_utils"))]
	pub(crate) pending_events: Mutex<VecDeque<(events::Event, Option<EventCompletionAction>)>>,

	/// A simple atomic flag to ensure only one task at a time can be processing events asynchronously.
	pending_events_processor: AtomicBool,

	/// A simple atomic flag to ensure only one task at a time can be processing HTLC forwards via
	/// [`Self::process_pending_htlc_forwards`].
	pending_htlc_forwards_processor: AtomicBool,

	/// If we are running during init (either directly during the deserialization method or in
	/// block connection methods which run after deserialization but before normal operation) we
	/// cannot provide the user with [`ChannelMonitorUpdate`]s through the normal update flow -
	/// prior to normal operation the user may not have loaded the [`ChannelMonitor`]s into their
	/// [`ChainMonitor`] and thus attempting to update it will fail or panic.
	///
	/// Thus, we place them here to be handled as soon as possible once we are running normally.
	///
	/// [`ChainMonitor`]: crate::chain::chainmonitor::ChainMonitor
	pending_background_events: Mutex<Vec<BackgroundEvent>>,
	/// Used when we have to take a BIG lock to make sure everything is self-consistent.
	/// Essentially just when we're serializing ourselves out.
	/// Taken first everywhere where we are making changes before any other locks.
	/// When acquiring this lock in read mode, rather than acquiring it directly, call
	/// `PersistenceNotifierGuard::notify_on_drop(..)` and pass the lock to it, to ensure the
	/// Notifier the lock contains sends out a notification when the lock is released.
	total_consistency_lock: RwLock<()>,
	/// Tracks the progress of channels going through batch funding by whether funding_signed was
	/// received and the monitor has been persisted.
	///
	/// This information does not need to be persisted as funding nodes can forget
	/// unfunded channels upon disconnection.
	funding_batch_states: Mutex<BTreeMap<Txid, Vec<(ChannelId, PublicKey, bool)>>>,

	background_events_processed_since_startup: AtomicBool,

	event_persist_notifier: Notifier,
	needs_persist_flag: AtomicBool,

	/// Tracks the message events that are to be broadcasted when we are connected to some peer.
	pending_broadcast_messages: Mutex<Vec<MessageSendEvent>>,

	/// We only want to force-close our channels on peers based on stale feerates when we're
	/// confident the feerate on the channel is *really* stale, not just became stale recently.
	/// Thus, we store the fee estimates we had as of the last [`FEERATE_TRACKING_BLOCKS`] blocks
	/// (after startup completed) here, and only force-close when channels have a lower feerate
	/// than we predicted any time in the last [`FEERATE_TRACKING_BLOCKS`] blocks.
	///
	/// We only keep this in memory as we assume any feerates we receive immediately after startup
	/// may be bunk (as they often are if Bitcoin Core crashes) and want to delay taking any
	/// actions for a day anyway.
	///
	/// The first element in the pair is the
	/// [`ConfirmationTarget::MinAllowedAnchorChannelRemoteFee`] estimate, the second the
	/// [`ConfirmationTarget::MinAllowedNonAnchorChannelRemoteFee`] estimate.
	last_days_feerates: Mutex<VecDeque<(u32, u32)>>,

	#[cfg(feature = "_test_utils")]
	/// In testing, it is useful be able to forge a name -> offer mapping so that we can pay an
	/// offer generated in the test.
	///
	/// This allows for doing so, validating proofs as normal, but, if they pass, replacing the
	/// offer they resolve to to the given one.
	pub testing_dnssec_proof_offer_resolution_override: Mutex<HashMap<HumanReadableName, Offer>>,

	#[cfg(test)]
	pub(super) entropy_source: ES,
	#[cfg(not(test))]
	entropy_source: ES,
	node_signer: NS,
	#[cfg(test)]
	pub(super) signer_provider: SP,
	#[cfg(not(test))]
	signer_provider: SP,

	logger: L,
}

/// Chain-related parameters used to construct a new `ChannelManager`.
///
/// Typically, the block-specific parameters are derived from the best block hash for the network,
/// as a newly constructed `ChannelManager` will not have created any channels yet. These parameters
/// are not needed when deserializing a previously constructed `ChannelManager`.
#[derive(Clone, Copy, PartialEq)]
pub struct ChainParameters {
	/// The network for determining the `chain_hash` in Lightning messages.
	pub network: Network,

	/// The hash and height of the latest block successfully connected.
	///
	/// Used to track on-chain channel funding outputs and send payments with reliable timelocks.
	pub best_block: BestBlock,
}

#[derive(Copy, Clone, PartialEq)]
#[must_use]
enum NotifyOption {
	DoPersist,
	SkipPersistHandleEvents,
	SkipPersistNoEvents,
}

/// Whenever we release the `ChannelManager`'s `total_consistency_lock`, from read mode, it is
/// desirable to notify any listeners on `await_persistable_update_timeout`/
/// `await_persistable_update` when new updates are available for persistence. Therefore, this
/// struct is responsible for locking the total consistency lock and, upon going out of scope,
/// sending the aforementioned notification (since the lock being released indicates that the
/// updates are ready for persistence).
///
/// We allow callers to either always notify by constructing with `notify_on_drop` or choose to
/// notify or not based on whether relevant changes have been made, providing a closure to
/// `optionally_notify` which returns a `NotifyOption`.
struct PersistenceNotifierGuard<'a, F: FnOnce() -> NotifyOption> {
	event_persist_notifier: &'a Notifier,
	needs_persist_flag: &'a AtomicBool,
	// Always `Some` once initialized, but tracked as an `Option` to obtain the closure by value in
	// [`PersistenceNotifierGuard::drop`].
	should_persist: Option<F>,
	// We hold onto this result so the lock doesn't get released immediately.
	_read_guard: RwLockReadGuard<'a, ()>,
}

// We don't care what the concrete F is here, it's unused
impl<'a> PersistenceNotifierGuard<'a, fn() -> NotifyOption> {
	/// Notifies any waiters and indicates that we need to persist, in addition to possibly having
	/// events to handle.
	///
	/// This must always be called if the changes included a `ChannelMonitorUpdate`, as well as in
	/// other cases where losing the changes on restart may result in a force-close or otherwise
	/// isn't ideal.
	fn notify_on_drop<C: AChannelManager>(
		cm: &'a C,
	) -> PersistenceNotifierGuard<'a, impl FnOnce() -> NotifyOption> {
		Self::optionally_notify(cm, || -> NotifyOption { NotifyOption::DoPersist })
	}

	fn manually_notify<F: FnOnce(), C: AChannelManager>(
		cm: &'a C, f: F,
	) -> PersistenceNotifierGuard<'a, impl FnOnce() -> NotifyOption> {
		let read_guard = cm.get_cm().total_consistency_lock.read().unwrap();
		let force_notify = cm.get_cm().process_background_events();

		PersistenceNotifierGuard {
			event_persist_notifier: &cm.get_cm().event_persist_notifier,
			needs_persist_flag: &cm.get_cm().needs_persist_flag,
			should_persist: Some(move || {
				f();
				force_notify
			}),
			_read_guard: read_guard,
		}
	}

	fn optionally_notify<F: FnOnce() -> NotifyOption, C: AChannelManager>(
		cm: &'a C, persist_check: F,
	) -> PersistenceNotifierGuard<'a, impl FnOnce() -> NotifyOption> {
		let read_guard = cm.get_cm().total_consistency_lock.read().unwrap();
		let force_notify = cm.get_cm().process_background_events();

		PersistenceNotifierGuard {
			event_persist_notifier: &cm.get_cm().event_persist_notifier,
			needs_persist_flag: &cm.get_cm().needs_persist_flag,
			should_persist: Some(move || {
				// Pick the "most" action between `persist_check` and the background events
				// processing and return that.
				let notify = persist_check();
				match (notify, force_notify) {
					(NotifyOption::DoPersist, _) => NotifyOption::DoPersist,
					(_, NotifyOption::DoPersist) => NotifyOption::DoPersist,
					(NotifyOption::SkipPersistHandleEvents, _) => {
						NotifyOption::SkipPersistHandleEvents
					},
					(_, NotifyOption::SkipPersistHandleEvents) => {
						NotifyOption::SkipPersistHandleEvents
					},
					_ => NotifyOption::SkipPersistNoEvents,
				}
			}),
			_read_guard: read_guard,
		}
	}

	/// Note that if any [`ChannelMonitorUpdate`]s are possibly generated,
	/// [`ChannelManager::process_background_events`] MUST be called first (or
	/// [`Self::optionally_notify`] used).
	fn optionally_notify_skipping_background_events<F: Fn() -> NotifyOption, C: AChannelManager>(
		cm: &'a C, persist_check: F,
	) -> PersistenceNotifierGuard<'a, F> {
		let read_guard = cm.get_cm().total_consistency_lock.read().unwrap();

		PersistenceNotifierGuard {
			event_persist_notifier: &cm.get_cm().event_persist_notifier,
			needs_persist_flag: &cm.get_cm().needs_persist_flag,
			should_persist: Some(persist_check),
			_read_guard: read_guard,
		}
	}
}

impl<'a, F: FnOnce() -> NotifyOption> Drop for PersistenceNotifierGuard<'a, F> {
	fn drop(&mut self) {
		let should_persist = match self.should_persist.take() {
			Some(should_persist) => should_persist,
			None => {
				debug_assert!(false);
				return;
			},
		};
		match should_persist() {
			NotifyOption::DoPersist => {
				self.needs_persist_flag.store(true, Ordering::Release);
				self.event_persist_notifier.notify()
			},
			NotifyOption::SkipPersistHandleEvents => self.event_persist_notifier.notify(),
			NotifyOption::SkipPersistNoEvents => {},
		}
	}
}

/// The amount of time in blocks we require our counterparty wait to claim their money (ie time
/// between when we, or our watchtower, must check for them having broadcast a theft transaction).
///
/// This can be increased (but not decreased) through [`ChannelHandshakeConfig::our_to_self_delay`]
///
/// [`ChannelHandshakeConfig::our_to_self_delay`]: crate::util::config::ChannelHandshakeConfig::our_to_self_delay
pub const BREAKDOWN_TIMEOUT: u16 = 6 * 24;
/// The amount of time in blocks we're willing to wait to claim money back to us. This matches
/// the maximum required amount in lnd as of March 2021.
pub(crate) const MAX_LOCAL_BREAKDOWN_TIMEOUT: u16 = 2 * 6 * 24 * 7;

/// The minimum number of blocks between an inbound HTLC's CLTV and the corresponding outbound
/// HTLC's CLTV. The current default represents roughly eight hours of blocks at six blocks/hour.
///
/// This can be increased (but not decreased) through [`ChannelConfig::cltv_expiry_delta`]
///
/// [`ChannelConfig::cltv_expiry_delta`]: crate::util::config::ChannelConfig::cltv_expiry_delta
// This should always be a few blocks greater than channelmonitor::CLTV_CLAIM_BUFFER,
// i.e. the node we forwarded the payment on to should always have enough room to reliably time out
// the HTLC via a full update_fail_htlc/commitment_signed dance before we hit the
// CLTV_CLAIM_BUFFER point (we static assert that it's at least 3 blocks more).
pub const MIN_CLTV_EXPIRY_DELTA: u16 = 6 * 8;
// This should be long enough to allow a payment path drawn across multiple routing hops with substantial
// `cltv_expiry_delta`. Indeed, the length of those values is the reaction delay offered to a routing node
// in case of HTLC on-chain settlement. While appearing less competitive, a node operator could decide to
// scale them up to suit its security policy. At the network-level, we shouldn't constrain them too much,
// while avoiding to introduce a DoS vector. Further, a low CTLV_FAR_FAR_AWAY could be a source of
// routing failure for any HTLC sender picking up an LDK node among the first hops.
pub(crate) const CLTV_FAR_FAR_AWAY: u32 = 14 * 24 * 6;

/// Minimum CLTV difference between the current block height and received inbound payments.
/// Invoices generated for payment to us must set their `min_final_cltv_expiry_delta` field to at least
/// this value.
// Note that we fail if exactly HTLC_FAIL_BACK_BUFFER + 1 was used, so we need to add one for
// any payments to succeed. Further, we don't want payments to fail if a block was found while
// a payment was being routed, so we add an extra block to be safe.
pub const MIN_FINAL_CLTV_EXPIRY_DELTA: u16 = HTLC_FAIL_BACK_BUFFER as u16 + 3;

// Check that our MIN_CLTV_EXPIRY_DELTA gives us enough time to get everything on chain and locked
// in with enough time left to fail the corresponding HTLC back to our inbound edge before they
// force-close on us.
// In other words, if the next-hop peer fails HTLC LATENCY_GRACE_PERIOD_BLOCKS after our
// CLTV_CLAIM_BUFFER (because that's how many blocks we allow them after expiry), we'll still have
// 2*MAX_BLOCKS_FOR_CONF + ANTI_REORG_DELAY left to get two transactions on chain and the second
// fully locked in before the peer force-closes on us (LATENCY_GRACE_PERIOD_BLOCKS before the
// expiry, i.e. assuming the peer force-closes right at the expiry and we're behind by
// LATENCY_GRACE_PERIOD_BLOCKS).
const _CHECK_CLTV_EXPIRY_SANITY: () = assert!(
	MIN_CLTV_EXPIRY_DELTA as u32
		>= 2 * LATENCY_GRACE_PERIOD_BLOCKS + 2 * MAX_BLOCKS_FOR_CONF + ANTI_REORG_DELAY
);

// Check that our MIN_CLTV_EXPIRY_DELTA gives us enough time to get the HTLC preimage back to our
// counterparty if the outbound edge gives us the preimage only one block before we'd force-close
// the channel.
// ie they provide the preimage LATENCY_GRACE_PERIOD_BLOCKS - 1 after the HTLC expires, then we
// pass the preimage back, which takes LATENCY_GRACE_PERIOD_BLOCKS to complete, and we want to make
// sure this all happens at least N blocks before the inbound HTLC expires (where N is the
// counterparty's CLTV_CLAIM_BUFFER or equivalent).
const _ASSUMED_COUNTERPARTY_CLTV_CLAIM_BUFFER: u32 = 6 * 6;

const _CHECK_COUNTERPARTY_REALISTIC: () =
	assert!(_ASSUMED_COUNTERPARTY_CLTV_CLAIM_BUFFER >= CLTV_CLAIM_BUFFER);

const _CHECK_CLTV_EXPIRY_OFFCHAIN: () = assert!(
	MIN_CLTV_EXPIRY_DELTA as u32
		>= 2 * LATENCY_GRACE_PERIOD_BLOCKS - 1 + _ASSUMED_COUNTERPARTY_CLTV_CLAIM_BUFFER
);

/// The number of ticks of [`ChannelManager::timer_tick_occurred`] until expiry of incomplete MPPs
#[cfg(not(any(fuzzing, test, feature = "_test_utils")))]
pub(crate) const MPP_TIMEOUT_TICKS: u8 = 3;
#[cfg(any(fuzzing, test, feature = "_test_utils"))]
pub(crate) const MPP_TIMEOUT_TICKS: u8 = 1;

/// The number of ticks of [`ChannelManager::timer_tick_occurred`] where a peer is disconnected
/// until we mark the channel disabled and gossip the update.
pub(crate) const DISABLE_GOSSIP_TICKS: u8 = 10;

/// The number of ticks of [`ChannelManager::timer_tick_occurred`] where a peer is connected until
/// we mark the channel enabled and gossip the update.
pub(crate) const ENABLE_GOSSIP_TICKS: u8 = 5;

/// The maximum number of unfunded channels we can have per-peer before we start rejecting new
/// (inbound) ones. The number of peers with unfunded channels is limited separately in
/// [`MAX_UNFUNDED_CHANNEL_PEERS`].
pub(super) const MAX_UNFUNDED_CHANS_PER_PEER: usize = 4;

/// The maximum number of peers from which we will allow pending unfunded channels. Once we reach
/// this many peers we reject new (inbound) channels from peers with which we don't have a channel.
pub(super) const MAX_UNFUNDED_CHANNEL_PEERS: usize = 50;

/// The maximum allowed size for peer storage, in bytes.
///
/// This constant defines the upper limit for the size of data
/// that can be stored for a peer. It is set to 1024 bytes (1 kilobyte)
/// to prevent excessive resource consumption.
#[cfg(not(test))]
const MAX_PEER_STORAGE_SIZE: usize = 1024;

/// The maximum number of peers which we do not have a (funded) channel with. Once we reach this
/// many peers we reject new (inbound) connections.
const MAX_NO_CHANNEL_PEERS: usize = 250;

/// Used by [`ChannelManager::list_recent_payments`] to express the status of recent payments.
/// These include payments that have yet to find a successful path, or have unresolved HTLCs.
#[derive(Debug, PartialEq)]
pub enum RecentPaymentDetails {
	/// When an invoice was requested and thus a payment has not yet been sent.
	AwaitingInvoice {
		/// A user-provided identifier in [`ChannelManager::pay_for_offer`] used to uniquely identify a
		/// payment and ensure idempotency in LDK.
		payment_id: PaymentId,
	},
	/// When a payment is still being sent and awaiting successful delivery.
	Pending {
		/// A user-provided identifier in [`send_payment`] or [`pay_for_offer`] used to uniquely
		/// identify a payment and ensure idempotency in LDK.
		///
		/// [`send_payment`]: crate::ln::channelmanager::ChannelManager::send_payment
		/// [`pay_for_offer`]: crate::ln::channelmanager::ChannelManager::pay_for_offer
		payment_id: PaymentId,
		/// Hash of the payment that is currently being sent but has yet to be fulfilled or
		/// abandoned.
		payment_hash: PaymentHash,
		/// Total amount (in msat, excluding fees) across all paths for this payment,
		/// not just the amount currently inflight.
		total_msat: u64,
	},
	/// When a pending payment is fulfilled, we continue tracking it until all pending HTLCs have
	/// been resolved. Upon receiving [`Event::PaymentSent`], we delay for a few minutes before the
	/// payment is removed from tracking.
	Fulfilled {
		/// A user-provided identifier in [`send_payment`] or [`pay_for_offer`] used to uniquely
		/// identify a payment and ensure idempotency in LDK.
		///
		/// [`send_payment`]: crate::ln::channelmanager::ChannelManager::send_payment
		/// [`pay_for_offer`]: crate::ln::channelmanager::ChannelManager::pay_for_offer
		payment_id: PaymentId,
		/// Hash of the payment that was claimed. `None` for serializations of [`ChannelManager`]
		/// made before LDK version 0.0.104.
		payment_hash: Option<PaymentHash>,
	},
	/// After a payment's retries are exhausted per the provided [`Retry`], or it is explicitly
	/// abandoned via [`ChannelManager::abandon_payment`], it is marked as abandoned until all
	/// pending HTLCs for this payment resolve and an [`Event::PaymentFailed`] is generated.
	Abandoned {
		/// A user-provided identifier in [`send_payment`] or [`pay_for_offer`] used to uniquely
		/// identify a payment and ensure idempotency in LDK.
		///
		/// [`send_payment`]: crate::ln::channelmanager::ChannelManager::send_payment
		/// [`pay_for_offer`]: crate::ln::channelmanager::ChannelManager::pay_for_offer
		payment_id: PaymentId,
		/// Hash of the payment that we have given up trying to send.
		payment_hash: PaymentHash,
	},
}

/// Route hints used in constructing invoices for [phantom node payents].
///
/// [phantom node payments]: crate::sign::PhantomKeysManager
#[derive(Clone)]
pub struct PhantomRouteHints {
	/// The list of channels to be included in the invoice route hints.
	pub channels: Vec<ChannelDetails>,
	/// A fake scid used for representing the phantom node's fake channel in generating the invoice
	/// route hints.
	pub phantom_scid: u64,
	/// The pubkey of the real backing node that would ultimately receive the payment.
	pub real_node_pubkey: PublicKey,
}

/// The return type of [`ChannelManager::check_free_peer_holding_cells`]
type FreeHoldingCellsResult = Vec<(
	ChannelId,
	PublicKey,
	Option<PostMonitorUpdateChanResume>,
	Vec<(HTLCSource, PaymentHash)>,
)>;

macro_rules! insert_short_channel_id {
	($short_to_chan_info: ident, $channel: expr) => {{
		if let Some(real_scid) = $channel.funding.get_short_channel_id() {
			let scid_insert = $short_to_chan_info.insert(real_scid, ($channel.context.get_counterparty_node_id(), $channel.context.channel_id()));
			assert!(scid_insert.is_none() || scid_insert.unwrap() == ($channel.context.get_counterparty_node_id(), $channel.context.channel_id()),
				"SCIDs should never collide - ensure you weren't behind the chain tip by a full month when creating channels");
		}
	}}
}

macro_rules! emit_funding_tx_broadcast_safe_event {
	($locked_events: expr, $channel: expr, $funding_txo: expr) => {
		if !$channel.context.funding_tx_broadcast_safe_event_emitted() {
			$locked_events.push_back((events::Event::FundingTxBroadcastSafe {
				channel_id: $channel.context.channel_id(),
				user_channel_id: $channel.context.get_user_id(),
				funding_txo: $funding_txo,
				counterparty_node_id: $channel.context.get_counterparty_node_id(),
				former_temporary_channel_id: $channel.context.temporary_channel_id()
					.expect("Unreachable: FundingTxBroadcastSafe event feature added to channel establishment process in LDK v0.0.124 where this should never be None."),
			}, None));
			$channel.context.set_funding_tx_broadcast_safe_event_emitted();
		}
	}
}

macro_rules! emit_channel_pending_event {
	($locked_events: expr, $channel: expr) => {
		if $channel.context.should_emit_channel_pending_event() {
			let funding_txo = $channel.funding.get_funding_txo().unwrap();
			let funding_redeem_script =
				Some($channel.funding.channel_transaction_parameters.make_funding_redeemscript());
			$locked_events.push_back((
				events::Event::ChannelPending {
					channel_id: $channel.context.channel_id(),
					former_temporary_channel_id: $channel.context.temporary_channel_id(),
					counterparty_node_id: $channel.context.get_counterparty_node_id(),
					user_channel_id: $channel.context.get_user_id(),
					funding_txo: funding_txo.into_bitcoin_outpoint(),
					channel_type: Some($channel.funding.get_channel_type().clone()),
					funding_redeem_script,
				},
				None,
			));
			$channel.context.set_channel_pending_event_emitted();
		}
	};
}

macro_rules! emit_initial_channel_ready_event {
	($locked_events: expr, $channel: expr) => {
		if $channel.context.should_emit_initial_channel_ready_event() {
			debug_assert!($channel.context.channel_pending_event_emitted());
			$locked_events.push_back((
				events::Event::ChannelReady {
					channel_id: $channel.context.channel_id(),
					user_channel_id: $channel.context.get_user_id(),
					counterparty_node_id: $channel.context.get_counterparty_node_id(),
					funding_txo: $channel
						.funding
						.get_funding_txo()
						.map(|outpoint| outpoint.into_bitcoin_outpoint()),
					channel_type: $channel.funding.get_channel_type().clone(),
				},
				None,
			));
			$channel.context.set_initial_channel_ready_event_emitted();
		}
	};
}

fn convert_channel_err_internal<
	Close: FnOnce(ClosureReason, &str) -> (ShutdownResult, Option<(msgs::ChannelUpdate, NodeId, NodeId)>),
>(
	err: ChannelError, chan_id: ChannelId, close: Close,
) -> (bool, MsgHandleErrInternal) {
	match err {
		ChannelError::Warn(msg) => {
			(false, MsgHandleErrInternal::from_chan_no_close(ChannelError::Warn(msg), chan_id))
		},
		ChannelError::WarnAndDisconnect(msg) => (
			false,
			MsgHandleErrInternal::from_chan_no_close(ChannelError::WarnAndDisconnect(msg), chan_id),
		),
		ChannelError::Ignore(msg) => {
			(false, MsgHandleErrInternal::from_chan_no_close(ChannelError::Ignore(msg), chan_id))
		},
		ChannelError::Abort(reason) => {
			(false, MsgHandleErrInternal::from_chan_no_close(ChannelError::Abort(reason), chan_id))
		},
		ChannelError::Close((msg, reason)) => {
			let (finish, chan_update) = close(reason, &msg);
			(true, MsgHandleErrInternal::from_finish_shutdown(msg, chan_id, finish, chan_update))
		},
		ChannelError::SendError(msg) => {
			(false, MsgHandleErrInternal::from_chan_no_close(ChannelError::SendError(msg), chan_id))
		},
	}
}

macro_rules! break_channel_entry {
	($self: ident, $peer_state: expr, $res: expr, $entry: expr) => {
		match $res {
			Ok(res) => res,
			Err(e) => {
				let (drop, res) = $self.locked_handle_force_close(
					&mut $peer_state.closed_channel_monitor_update_ids,
					&mut $peer_state.in_flight_monitor_updates,
					e,
					$entry.get_mut(),
				);
				if drop {
					$entry.remove_entry();
				}
				break Err(res);
			},
		}
	};
}

macro_rules! try_channel_entry {
	($self: ident, $peer_state: expr, $res: expr, $entry: expr) => {
		match $res {
			Ok(res) => res,
			Err(e) => {
				let (drop, res) = $self.locked_handle_force_close(
					&mut $peer_state.closed_channel_monitor_update_ids,
					&mut $peer_state.in_flight_monitor_updates,
					e,
					$entry.get_mut(),
				);
				if drop {
					$entry.remove_entry();
				}
				return Err(res);
			},
		}
	};
}

#[rustfmt::skip]
macro_rules! process_events_body {
	($self: expr, $event_to_handle: expr, $handle_event: expr) => {
		let mut handling_failed = false;
		let mut processed_all_events = false;
		while !handling_failed && !processed_all_events {
			if $self.pending_events_processor.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
				return;
			}

			let mut result;

			{
				// We'll acquire our total consistency lock so that we can be sure no other
				// persists happen while processing monitor events.
				let _read_guard = $self.total_consistency_lock.read().unwrap();

				// Because `handle_post_event_actions` may send `ChannelMonitorUpdate`s to the user we must
				// ensure any startup-generated background events are handled first.
				result = $self.process_background_events();

				// TODO: This behavior should be documented. It's unintuitive that we query
				// ChannelMonitors when clearing other events.
				if $self.process_pending_monitor_events() {
					result = NotifyOption::DoPersist;
				}
			}

			let pending_events = $self.pending_events.lock().unwrap().clone();
			if !pending_events.is_empty() {
				result = NotifyOption::DoPersist;
			}

			let mut post_event_actions = Vec::new();

			let mut num_handled_events = 0;
			for (event, action_opt) in pending_events {
				log_trace!($self.logger, "Handling event {:?}...", event);
				$event_to_handle = event;
				let event_handling_result = $handle_event;
				log_trace!($self.logger, "Done handling event, result: {:?}", event_handling_result);
				match event_handling_result {
					Ok(()) => {
						if let Some(action) = action_opt {
							post_event_actions.push(action);
						}
						num_handled_events += 1;
					}
					Err(_e) => {
						// If we encounter an error we stop handling events and make sure to replay
						// any unhandled events on the next invocation.
						handling_failed = true;
						break;
					}
				}
			}

			{
				let mut pending_events = $self.pending_events.lock().unwrap();
				pending_events.drain(..num_handled_events);
				processed_all_events = pending_events.is_empty();
				// Note that `push_pending_forwards_ev` relies on `pending_events_processor` being
				// updated here with the `pending_events` lock acquired.
				$self.pending_events_processor.store(false, Ordering::Release);
			}

			if !post_event_actions.is_empty() {
				// `handle_post_event_actions` may update channel state, so take the total
				// consistency lock now similarly to other callers of `handle_post_event_actions`.
				// Note that if it needs to wake the background processor for event handling or
				// persistence it will do so directly.
				let _read_guard = $self.total_consistency_lock.read().unwrap();
				$self.handle_post_event_actions(post_event_actions);
				// If we had some actions, go around again as we may have more events now
				processed_all_events = false;
			}

			match result {
				NotifyOption::DoPersist => {
					$self.needs_persist_flag.store(true, Ordering::Release);
					$self.event_persist_notifier.notify();
				},
				NotifyOption::SkipPersistHandleEvents =>
					$self.event_persist_notifier.notify(),
				NotifyOption::SkipPersistNoEvents => {},
			}
		}
	}
}

/// Creates an [`Event::HTLCIntercepted`] from a [`PendingAddHTLCInfo`]. We generate this event in a
/// few places so this DRYs the code.
fn create_htlc_intercepted_event(
	intercept_id: InterceptId, pending_add: &PendingAddHTLCInfo,
) -> Result<Event, ()> {
	let inbound_amount_msat = pending_add.forward_info.incoming_amt_msat.ok_or(())?;
	let requested_next_hop_scid = match pending_add.forward_info.routing {
		PendingHTLCRouting::Forward { short_channel_id, .. } => short_channel_id,
		_ => return Err(()),
	};
	Ok(Event::HTLCIntercepted {
		requested_next_hop_scid,
		payment_hash: pending_add.forward_info.payment_hash,
		inbound_amount_msat,
		expected_outbound_amount_msat: pending_add.forward_info.outgoing_amt_msat,
		intercept_id,
		outgoing_htlc_expiry_block_height: Some(pending_add.forward_info.outgoing_cltv_value),
	})
}

impl<
		M: chain::Watch<SP::EcdsaSigner>,
		T: BroadcasterInterface,
		ES: EntropySource,
		NS: NodeSigner,
		SP: SignerProvider,
		F: FeeEstimator,
		R: Router,
		MR: MessageRouter,
		L: Logger,
	> ChannelManager<M, T, ES, NS, SP, F, R, MR, L>
{
	/// Constructs a new `ChannelManager` to hold several channels and route between them.
	///
	/// The current time or latest block header time can be provided as the `current_timestamp`.
	///
	/// This is the main "logic hub" for all channel-related actions, and implements
	/// [`ChannelMessageHandler`].
	///
	/// Non-proportional fees are fixed according to our risk using the provided fee estimator.
	///
	/// Users need to notify the new `ChannelManager` when a new block is connected or
	/// disconnected using its [`block_connected`] and [`blocks_disconnected`] methods, starting
	/// from after [`params.best_block.block_hash`]. See [`chain::Listen`] and [`chain::Confirm`] for
	/// more details.
	///
	/// [`block_connected`]: chain::Listen::block_connected
	/// [`blocks_disconnected`]: chain::Listen::blocks_disconnected
	/// [`params.best_block.block_hash`]: chain::BestBlock::block_hash
	#[rustfmt::skip]
	pub fn new(
		fee_est: F, chain_monitor: M, tx_broadcaster: T, router: R, message_router: MR, logger: L,
		entropy_source: ES, node_signer: NS, signer_provider: SP, config: UserConfig,
		params: ChainParameters, current_timestamp: u32,
	) -> Self
	where
		L: Clone,
	{
		let mut secp_ctx = Secp256k1::new();
		secp_ctx.seeded_randomize(&entropy_source.get_secure_random_bytes());

		let expanded_inbound_key = node_signer.get_expanded_key();
		let our_network_pubkey = node_signer.get_node_id(Recipient::Node).unwrap();

		let flow = OffersMessageFlow::new(
			ChainHash::using_genesis_block(params.network), params.best_block,
			our_network_pubkey, current_timestamp, expanded_inbound_key,
			node_signer.get_receive_auth_key(), secp_ctx.clone(), message_router, logger.clone(),
		);

		ChannelManager {
			config: RwLock::new(config),
			chain_hash: ChainHash::using_genesis_block(params.network),
			fee_estimator: LowerBoundedFeeEstimator::new(fee_est),
			chain_monitor,
			tx_broadcaster,
			router,
			flow,

			best_block: RwLock::new(params.best_block),

			outbound_scid_aliases: Mutex::new(new_hash_set()),
			pending_outbound_payments: OutboundPayments::new(new_hash_map()),
			forward_htlcs: Mutex::new(new_hash_map()),
			decode_update_add_htlcs: Mutex::new(new_hash_map()),
			claimable_payments: Mutex::new(ClaimablePayments { claimable_payments: new_hash_map(), pending_claiming_payments: new_hash_map() }),
			pending_intercepted_htlcs: Mutex::new(new_hash_map()),
			short_to_chan_info: FairRwLock::new(new_hash_map()),

			our_network_pubkey,
			secp_ctx,

			inbound_payment_key: expanded_inbound_key,
			fake_scid_rand_bytes: entropy_source.get_secure_random_bytes(),

			probing_cookie_secret: entropy_source.get_secure_random_bytes(),
			inbound_payment_id_secret: entropy_source.get_secure_random_bytes(),

			highest_seen_timestamp: AtomicUsize::new(current_timestamp as usize),

			per_peer_state: FairRwLock::new(new_hash_map()),

			#[cfg(not(any(test, feature = "_externalize_tests")))]
			monitor_update_type: AtomicUsize::new(0),

			pending_events: Mutex::new(VecDeque::new()),
			pending_events_processor: AtomicBool::new(false),
			pending_htlc_forwards_processor: AtomicBool::new(false),
			pending_background_events: Mutex::new(Vec::new()),
			total_consistency_lock: RwLock::new(()),
			background_events_processed_since_startup: AtomicBool::new(false),
			event_persist_notifier: Notifier::new(),
			needs_persist_flag: AtomicBool::new(false),
			funding_batch_states: Mutex::new(BTreeMap::new()),

			pending_broadcast_messages: Mutex::new(Vec::new()),

			last_days_feerates: Mutex::new(VecDeque::new()),

			entropy_source,
			node_signer,
			signer_provider,

			logger,

			#[cfg(feature = "_test_utils")]
			testing_dnssec_proof_offer_resolution_override: Mutex::new(new_hash_map()),
		}
	}

	fn send_channel_ready(
		&self, pending_msg_events: &mut Vec<MessageSendEvent>, channel: &FundedChannel<SP>,
		channel_ready_msg: msgs::ChannelReady,
	) {
		let counterparty_node_id = channel.context.get_counterparty_node_id();
		if channel.context.is_connected() {
			pending_msg_events.push(MessageSendEvent::SendChannelReady {
				node_id: counterparty_node_id,
				msg: channel_ready_msg,
			});
		}
		// Note that we may send a `channel_ready` multiple times for a channel if we reconnect, so
		// we allow collisions, but we shouldn't ever be updating the channel ID pointed to.
		let mut short_to_chan_info = self.short_to_chan_info.write().unwrap();
		let outbound_alias_insert = short_to_chan_info.insert(
			channel.context.outbound_scid_alias(),
			(counterparty_node_id, channel.context.channel_id()),
		);
		assert!(outbound_alias_insert.is_none() || outbound_alias_insert.unwrap() == (counterparty_node_id, channel.context.channel_id()),
				"SCIDs should never collide - ensure you weren't behind the chain tip by a full month when creating channels");
		insert_short_channel_id!(short_to_chan_info, channel);
	}

	/// Gets the current [`UserConfig`] which controls some global behavior and includes the
	/// default configuration applied to all new channels.
	pub fn get_current_config(&self) -> UserConfig {
		self.config.read().unwrap().clone()
	}

	/// Updates the current [`UserConfig`] which controls some global behavior and includes the
	/// default configuration applied to all new channels.
	pub fn set_current_config(&self, new_config: UserConfig) {
		*self.config.write().unwrap() = new_config;
	}

	#[cfg(test)]
	pub fn create_and_insert_outbound_scid_alias_for_test(&self) -> u64 {
		self.create_and_insert_outbound_scid_alias()
	}

	fn create_and_insert_outbound_scid_alias(&self) -> u64 {
		let height = self.best_block.read().unwrap().height;
		let mut outbound_scid_alias = 0;
		let mut i = 0;
		loop {
			// fuzzing chacha20 doesn't use the key at all so we always get the same alias
			if cfg!(fuzzing) {
				outbound_scid_alias += 1;
			} else {
				outbound_scid_alias = fake_scid::Namespace::OutboundAlias.get_fake_scid(
					height,
					&self.chain_hash,
					&self.fake_scid_rand_bytes,
					&self.entropy_source,
				);
			}
			if outbound_scid_alias != 0
				&& self.outbound_scid_aliases.lock().unwrap().insert(outbound_scid_alias)
			{
				break;
			}
			i += 1;
			if i > 1_000_000 {
				panic!("Your RNG is busted or we ran out of possible outbound SCID aliases (which should never happen before we run out of memory to store channels");
			}
		}
		outbound_scid_alias
	}

	/// Creates a new outbound channel to the given remote node and with the given value.
	///
	/// `user_channel_id` will be provided back as in
	/// [`Event::FundingGenerationReady::user_channel_id`] to allow tracking of which events
	/// correspond with which `create_channel` call. Note that the `user_channel_id` defaults to a
	/// randomized value for inbound channels. `user_channel_id` has no meaning inside of LDK, it
	/// is simply copied to events and otherwise ignored.
	///
	/// Raises [`APIError::APIMisuseError`] when `channel_value_satoshis` > 2**24 or `push_msat` is
	/// greater than `channel_value_satoshis * 1k` or `channel_value_satoshis < 1000`.
	///
	/// Raises [`APIError::ChannelUnavailable`] if the channel cannot be opened due to failing to
	/// generate a shutdown scriptpubkey or destination script set by
	/// [`SignerProvider::get_shutdown_scriptpubkey`] or [`SignerProvider::get_destination_script`].
	///
	/// Note that we do not check if you are currently connected to the given peer. If no
	/// connection is available, the outbound `open_channel` message may fail to send, resulting in
	/// the channel eventually being silently forgotten (dropped on reload).
	///
	/// If `temporary_channel_id` is specified, it will be used as the temporary channel ID of the
	/// channel. Otherwise, a random one will be generated for you.
	///
	/// Returns the new Channel's temporary `channel_id`. This ID will appear as
	/// [`Event::FundingGenerationReady::temporary_channel_id`] and in
	/// [`ChannelDetails::channel_id`] until after
	/// [`ChannelManager::funding_transaction_generated`] is called, swapping the Channel's ID for
	/// one derived from the funding transaction's TXID. If the counterparty rejects the channel
	/// immediately, this temporary ID will appear in [`Event::ChannelClosed::channel_id`].
	///
	/// [`Event::FundingGenerationReady::user_channel_id`]: events::Event::FundingGenerationReady::user_channel_id
	/// [`Event::FundingGenerationReady::temporary_channel_id`]: events::Event::FundingGenerationReady::temporary_channel_id
	/// [`Event::ChannelClosed::channel_id`]: events::Event::ChannelClosed::channel_id
	#[rustfmt::skip]
	pub fn create_channel(&self, their_network_key: PublicKey, channel_value_satoshis: u64, push_msat: u64, user_channel_id: u128, temporary_channel_id: Option<ChannelId>, override_config: Option<UserConfig>) -> Result<ChannelId, APIError> {
		if channel_value_satoshis < 1000 {
			return Err(APIError::APIMisuseError { err: format!("Channel value must be at least 1000 satoshis. It was {}", channel_value_satoshis) });
		}

		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(self);
		// We want to make sure the lock is actually acquired by PersistenceNotifierGuard.
		debug_assert!(&self.total_consistency_lock.try_write().is_err());

		let per_peer_state = self.per_peer_state.read().unwrap();

		let peer_state_mutex = per_peer_state.get(&their_network_key)
			.ok_or_else(|| APIError::APIMisuseError{ err: format!("Not connected to node: {}", their_network_key) })?;

		let mut peer_state = peer_state_mutex.lock().unwrap();
		if !peer_state.is_connected {
			return Err(APIError::APIMisuseError{ err: format!("Not connected to node: {}", their_network_key) });
		}

		if let Some(temporary_channel_id) = temporary_channel_id {
			if peer_state.channel_by_id.contains_key(&temporary_channel_id) {
				return Err(APIError::APIMisuseError{ err: format!("Channel with temporary channel ID {} already exists!", temporary_channel_id)});
			}
		}

		let mut channel = {
			let outbound_scid_alias = self.create_and_insert_outbound_scid_alias();
			let their_features = &peer_state.latest_features;
			let config = self.config.read().unwrap();
			let config = if let Some(config) = &override_config {
				config
			} else {
				&*config
			};
			match OutboundV1Channel::new(&self.fee_estimator, &self.entropy_source, &self.signer_provider, their_network_key,
				their_features, channel_value_satoshis, push_msat, user_channel_id, config,
				self.best_block.read().unwrap().height, outbound_scid_alias, temporary_channel_id, &self.logger)
			{
				Ok(res) => res,
				Err(e) => {
					self.outbound_scid_aliases.lock().unwrap().remove(&outbound_scid_alias);
					return Err(e);
				},
			}
		};
		let logger = WithChannelContext::from(&self.logger, &channel.context, None);
		let res = channel.get_open_channel(self.chain_hash, &&logger);

		let temporary_channel_id = channel.context.channel_id();
		match peer_state.channel_by_id.entry(temporary_channel_id) {
			hash_map::Entry::Occupied(_) => {
				if cfg!(fuzzing) {
					return Err(APIError::APIMisuseError { err: "Fuzzy bad RNG".to_owned() });
				} else {
					panic!("RNG is bad???");
				}
			},
			hash_map::Entry::Vacant(entry) => { entry.insert(Channel::from(channel)); }
		}

		if let Some(msg) = res {
			peer_state.pending_msg_events.push(MessageSendEvent::SendOpenChannel {
				node_id: their_network_key,
				msg,
			});
		}
		Ok(temporary_channel_id)
	}

	fn list_funded_channels_with_filter<
		Fn: FnMut(&(&InitFeatures, &ChannelId, &Channel<SP>)) -> bool,
	>(
		&self, mut f: Fn,
	) -> Vec<ChannelDetails> {
		// Allocate our best estimate of the number of channels we have in the `res`
		// Vec. Sadly the `short_to_chan_info` map doesn't cover channels without
		// a scid or a scid alias. Therefore reallocations may still occur, but is
		// unlikely as the `short_to_chan_info` map often contains 2 entries for
		// the same channel.
		let mut res = Vec::with_capacity(self.short_to_chan_info.read().unwrap().len());
		{
			let best_block_height = self.best_block.read().unwrap().height;
			let per_peer_state = self.per_peer_state.read().unwrap();
			for (_cp_id, peer_state_mutex) in per_peer_state.iter() {
				let mut peer_state_lock = peer_state_mutex.lock().unwrap();
				let peer_state = &mut *peer_state_lock;
				// Only `Channels` in the `Channel::Funded` phase can be considered funded.
				let filtered_chan_by_id = peer_state
					.channel_by_id
					.iter()
					.map(|(cid, c)| (&peer_state.latest_features, cid, c))
					.filter(|(_, _, chan)| chan.is_funded())
					.filter(|v| f(v));
				res.extend(filtered_chan_by_id.map(|(_, _channel_id, channel)| {
					ChannelDetails::from_channel(
						channel,
						best_block_height,
						peer_state.latest_features.clone(),
						&self.fee_estimator,
					)
				}));
			}
		}
		res
	}

	/// Gets the list of open channels, in random order. See [`ChannelDetails`] field documentation for
	/// more information.
	pub fn list_channels(&self) -> Vec<ChannelDetails> {
		// Allocate our best estimate of the number of channels we have in the `res`
		// Vec. Sadly the `short_to_chan_info` map doesn't cover channels without
		// a scid or a scid alias. Therefore reallocations may still occur, but is
		// unlikely as the `short_to_chan_info` map often contains 2 entries for
		// the same channel.
		let mut res = Vec::with_capacity(self.short_to_chan_info.read().unwrap().len());
		{
			let best_block_height = self.best_block.read().unwrap().height;
			let per_peer_state = self.per_peer_state.read().unwrap();
			for (_cp_id, peer_state_mutex) in per_peer_state.iter() {
				let mut peer_state_lock = peer_state_mutex.lock().unwrap();
				let peer_state = &mut *peer_state_lock;
				for (_, channel) in peer_state.channel_by_id.iter() {
					let details = ChannelDetails::from_channel(
						channel,
						best_block_height,
						peer_state.latest_features.clone(),
						&self.fee_estimator,
					);
					res.push(details);
				}
			}
		}
		res
	}

	/// Gets the list of usable channels, in random order. Useful as an argument to
	/// [`Router::find_route`] to ensure non-announced channels are used.
	///
	/// These are guaranteed to have their [`ChannelDetails::is_usable`] value set to true, see the
	/// documentation for [`ChannelDetails::is_usable`] for more info on exactly what the criteria
	/// are.
	pub fn list_usable_channels(&self) -> Vec<ChannelDetails> {
		// Note we use is_live here instead of usable which leads to somewhat confused
		// internal/external nomenclature, but that's ok cause that's probably what the user
		// really wanted anyway.
		self.list_funded_channels_with_filter(|&(_, _, ref channel)| channel.context().is_live())
	}

	/// Gets the list of channels we have with a given counterparty, in random order.
	pub fn list_channels_with_counterparty(
		&self, counterparty_node_id: &PublicKey,
	) -> Vec<ChannelDetails> {
		let best_block_height = self.best_block.read().unwrap().height;
		let per_peer_state = self.per_peer_state.read().unwrap();

		if let Some(peer_state_mutex) = per_peer_state.get(counterparty_node_id) {
			let mut peer_state_lock = peer_state_mutex.lock().unwrap();
			let peer_state = &mut *peer_state_lock;
			let features = &peer_state.latest_features;
			let channel_to_details = |channel| {
				ChannelDetails::from_channel(
					channel,
					best_block_height,
					features.clone(),
					&self.fee_estimator,
				)
			};
			let chan_by_id = peer_state.channel_by_id.iter();
			return chan_by_id.map(|(_, chan)| chan).map(channel_to_details).collect();
		}
		vec![]
	}

	/// Returns in an undefined order recent payments that -- if not fulfilled -- have yet to find a
	/// successful path, or have unresolved HTLCs.
	///
	/// This can be useful for payments that may have been prepared, but ultimately not sent, as a
	/// result of a crash. If such a payment exists, is not listed here, and an
	/// [`Event::PaymentSent`] has not been received, you may consider resending the payment.
	///
	/// [`Event::PaymentSent`]: events::Event::PaymentSent
	#[rustfmt::skip]
	pub fn list_recent_payments(&self) -> Vec<RecentPaymentDetails> {
		self.pending_outbound_payments.pending_outbound_payments.lock().unwrap().iter()
			.filter_map(|(payment_id, pending_outbound_payment)| match pending_outbound_payment {
				PendingOutboundPayment::AwaitingInvoice { .. }
					| PendingOutboundPayment::AwaitingOffer { .. }
					// InvoiceReceived is an intermediate state and doesn't need to be exposed
					| PendingOutboundPayment::InvoiceReceived { .. } =>
				{
					Some(RecentPaymentDetails::AwaitingInvoice { payment_id: *payment_id })
				},
				PendingOutboundPayment::StaticInvoiceReceived { .. } => {
					Some(RecentPaymentDetails::AwaitingInvoice { payment_id: *payment_id })
				},
				PendingOutboundPayment::Retryable { payment_hash, total_msat, .. } => {
					Some(RecentPaymentDetails::Pending {
						payment_id: *payment_id,
						payment_hash: *payment_hash,
						total_msat: *total_msat,
					})
				},
				PendingOutboundPayment::Abandoned { payment_hash, .. } => {
					Some(RecentPaymentDetails::Abandoned { payment_id: *payment_id, payment_hash: *payment_hash })
				},
				PendingOutboundPayment::Fulfilled { payment_hash, .. } => {
					Some(RecentPaymentDetails::Fulfilled { payment_id: *payment_id, payment_hash: *payment_hash })
				},
				PendingOutboundPayment::Legacy { .. } => None
			})
			.collect()
	}

	fn close_channel_internal(
		&self, chan_id: &ChannelId, counterparty_node_id: &PublicKey,
		target_feerate_sats_per_1000_weight: Option<u32>,
		override_shutdown_script: Option<ShutdownScript>,
	) -> Result<(), APIError> {
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(self);

		let mut failed_htlcs: Vec<(HTLCSource, PaymentHash)> = Vec::new();
		let mut shutdown_result = Ok(());

		{
			let per_peer_state = self.per_peer_state.read().unwrap();

			let peer_state_mutex = per_peer_state
				.get(counterparty_node_id)
				.ok_or_else(|| APIError::no_such_peer(counterparty_node_id))?;

			let mut peer_state_lock = peer_state_mutex.lock().unwrap();
			let peer_state = &mut *peer_state_lock;

			match peer_state.channel_by_id.entry(*chan_id) {
				hash_map::Entry::Occupied(mut chan_entry) => {
					if !chan_entry.get().context().is_connected() {
						return Err(APIError::ChannelUnavailable {
							err: "Cannot begin shutdown while peer is disconnected, maybe force-close instead?".to_owned(),
						});
					}

					if let Some(chan) = chan_entry.get_mut().as_funded_mut() {
						let funding_txo_opt = chan.funding.get_funding_txo();
						let their_features = &peer_state.latest_features;
						let (shutdown_msg, mut monitor_update_opt, htlcs) = chan.get_shutdown(
							&self.signer_provider,
							their_features,
							target_feerate_sats_per_1000_weight,
							override_shutdown_script,
							&self.logger,
						)?;
						failed_htlcs = htlcs;

						// We can send the `shutdown` message before updating the `ChannelMonitor`
						// here as we don't need the monitor update to complete until we send a
						// `shutdown_signed`, which we'll delay if we're pending a monitor update.
						peer_state.pending_msg_events.push(MessageSendEvent::SendShutdown {
							node_id: *counterparty_node_id,
							msg: shutdown_msg,
						});

						debug_assert!(
							monitor_update_opt.is_none() || !chan.is_shutdown(),
							"We can't both complete shutdown and generate a monitor update"
						);

						// Update the monitor with the shutdown script if necessary.
						if let Some(monitor_update) = monitor_update_opt.take() {
							if let Some(data) = self.handle_new_monitor_update(
								&mut peer_state.in_flight_monitor_updates,
								&mut peer_state.monitor_update_blocked_actions,
								&mut peer_state.pending_msg_events,
								peer_state.is_connected,
								chan,
								funding_txo_opt.unwrap(),
								monitor_update,
							) {
								mem::drop(peer_state_lock);
								mem::drop(per_peer_state);
								self.handle_post_monitor_update_chan_resume(data);
							}
						}
					} else {
						let reason = ClosureReason::LocallyCoopClosedUnfundedChannel;
						let err = ChannelError::Close((reason.to_string(), reason));
						let mut chan = chan_entry.remove();
						let (_, mut e) = self.locked_handle_unfunded_close(err, &mut chan);
						e.dont_send_error_message();
						shutdown_result = Err(e);
					}
				},
				hash_map::Entry::Vacant(_) => {
					return Err(APIError::no_such_channel_for_peer(chan_id, counterparty_node_id));
				},
			}
		}

		for htlc_source in failed_htlcs.drain(..) {
			let failure_reason = LocalHTLCFailureReason::ChannelClosed;
			let reason = HTLCFailReason::from_failure_code(failure_reason);
			let receiver = HTLCHandlingFailureType::Forward {
				node_id: Some(*counterparty_node_id),
				channel_id: *chan_id,
			};
			let (source, hash) = htlc_source;
			self.fail_htlc_backwards_internal(&source, &hash, &reason, receiver, None);
		}

		let _ = self.handle_error(shutdown_result, *counterparty_node_id);

		Ok(())
	}

	/// Begins the process of closing a channel. After this call (plus some timeout), no new HTLCs
	/// will be accepted on the given channel, and after additional timeout/the closing of all
	/// pending HTLCs, the channel will be closed on chain.
	///
	///  * If we are the channel initiator, we will pay between our [`ChannelCloseMinimum`] and
	///    [`ChannelConfig::force_close_avoidance_max_fee_satoshis`] plus our [`NonAnchorChannelFee`]
	///    fee estimate.
	///  * If our counterparty is the channel initiator, we will require a channel closing
	///    transaction feerate of at least our [`ChannelCloseMinimum`] feerate or the feerate which
	///    would appear on a force-closure transaction, whichever is lower. We will allow our
	///    counterparty to pay as much fee as they'd like, however.
	///
	/// May generate a [`SendShutdown`] message event on success, which should be relayed.
	///
	/// Raises [`APIError::ChannelUnavailable`] if the channel cannot be closed due to failing to
	/// generate a shutdown scriptpubkey or destination script set by
	/// [`SignerProvider::get_shutdown_scriptpubkey`]. A force-closure may be needed to close the
	/// channel.
	///
	/// [`ChannelConfig::force_close_avoidance_max_fee_satoshis`]: crate::util::config::ChannelConfig::force_close_avoidance_max_fee_satoshis
	/// [`ChannelCloseMinimum`]: crate::chain::chaininterface::ConfirmationTarget::ChannelCloseMinimum
	/// [`NonAnchorChannelFee`]: crate::chain::chaininterface::ConfirmationTarget::NonAnchorChannelFee
	/// [`SendShutdown`]: MessageSendEvent::SendShutdown
	pub fn close_channel(
		&self, channel_id: &ChannelId, counterparty_node_id: &PublicKey,
	) -> Result<(), APIError> {
		self.close_channel_internal(channel_id, counterparty_node_id, None, None)
	}

	/// Begins the process of closing a channel. After this call (plus some timeout), no new HTLCs
	/// will be accepted on the given channel, and after additional timeout/the closing of all
	/// pending HTLCs, the channel will be closed on chain.
	///
	/// `target_feerate_sat_per_1000_weight` has different meanings depending on if we initiated
	/// the channel being closed or not:
	///  * If we are the channel initiator, we will pay at least this feerate on the closing
	///    transaction. The upper-bound is set by
	///    [`ChannelConfig::force_close_avoidance_max_fee_satoshis`] plus our [`NonAnchorChannelFee`]
	///    fee estimate (or `target_feerate_sat_per_1000_weight`, if it is greater).
	///  * If our counterparty is the channel initiator, we will refuse to accept a channel closure
	///    transaction feerate below `target_feerate_sat_per_1000_weight` (or the feerate which
	///    will appear on a force-closure transaction, whichever is lower).
	///
	/// The `shutdown_script` provided  will be used as the `scriptPubKey` for the closing transaction.
	/// Will fail if a shutdown script has already been set for this channel by
	/// [`ChannelHandshakeConfig::commit_upfront_shutdown_pubkey`]. The given shutdown script must
	/// also be compatible with our and the counterparty's features.
	///
	/// May generate a [`SendShutdown`] message event on success, which should be relayed.
	///
	/// Raises [`APIError::ChannelUnavailable`] if the channel cannot be closed due to failing to
	/// generate a shutdown scriptpubkey or destination script set by
	/// [`SignerProvider::get_shutdown_scriptpubkey`]. A force-closure may be needed to close the
	/// channel.
	///
	/// [`ChannelConfig::force_close_avoidance_max_fee_satoshis`]: crate::util::config::ChannelConfig::force_close_avoidance_max_fee_satoshis
	/// [`NonAnchorChannelFee`]: crate::chain::chaininterface::ConfirmationTarget::NonAnchorChannelFee
	/// [`ChannelHandshakeConfig::commit_upfront_shutdown_pubkey`]: crate::util::config::ChannelHandshakeConfig::commit_upfront_shutdown_pubkey
	/// [`SendShutdown`]: MessageSendEvent::SendShutdown
	pub fn close_channel_with_feerate_and_script(
		&self, channel_id: &ChannelId, counterparty_node_id: &PublicKey,
		target_feerate_sats_per_1000_weight: Option<u32>, shutdown_script: Option<ShutdownScript>,
	) -> Result<(), APIError> {
		self.close_channel_internal(
			channel_id,
			counterparty_node_id,
			target_feerate_sats_per_1000_weight,
			shutdown_script,
		)
	}

	/// Applies a [`ChannelMonitorUpdate`] which may or may not be for a channel which is closed.
	#[rustfmt::skip]
	fn apply_post_close_monitor_update(
		&self, counterparty_node_id: PublicKey, channel_id: ChannelId, funding_txo: OutPoint,
		monitor_update: ChannelMonitorUpdate,
	) {
		// Note that there may be some post-close updates which need to be well-ordered with
		// respect to the `update_id`, so we hold the `peer_state` lock here.
		let per_peer_state = self.per_peer_state.read().unwrap();
		let mut peer_state_lock = per_peer_state.get(&counterparty_node_id)
			.expect("We must always have a peer entry for a peer with which we have channels that have ChannelMonitors")
			.lock().unwrap();
		let peer_state = &mut *peer_state_lock;
		match peer_state.channel_by_id.entry(channel_id) {
			hash_map::Entry::Occupied(mut chan_entry) => {
				if let Some(chan) = chan_entry.get_mut().as_funded_mut() {
					if let Some(data) = self.handle_new_monitor_update(
						&mut peer_state.in_flight_monitor_updates,
						&mut peer_state.monitor_update_blocked_actions,
						&mut peer_state.pending_msg_events,
						peer_state.is_connected,
						chan,
						funding_txo,
						monitor_update,
					) {
						mem::drop(peer_state_lock);
						mem::drop(per_peer_state);
						self.handle_post_monitor_update_chan_resume(data);
					}
					return;
				} else {
					debug_assert!(false, "We shouldn't have an update for a non-funded channel");
				}
			},
			hash_map::Entry::Vacant(_) => {},
		}

		if let Some(actions) = self.handle_post_close_monitor_update(
			&mut peer_state.in_flight_monitor_updates,
			&mut peer_state.monitor_update_blocked_actions,
			funding_txo,
			monitor_update,
			counterparty_node_id,
			channel_id,
		) {
			mem::drop(peer_state_lock);
			mem::drop(per_peer_state);
			self.handle_monitor_update_completion_actions(actions);
		}
	}

	/// When a channel is removed, two things need to happen:
	/// (a) Handle the initial within-lock closure for the channel via one of the following methods:
	///     [`ChannelManager::locked_handle_unfunded_close`],
	/// 	[`ChannelManager::locked_handle_funded_coop_close`],
	/// 	[`ChannelManager::locked_handle_funded_force_close`] or
	/// 	[`ChannelManager::locked_handle_force_close`].
	/// (b) [`ChannelManager::handle_error`] needs to be called without holding any locks (except
	///     [`ChannelManager::total_consistency_lock`]), which then calls this.
	fn finish_close_channel(&self, mut shutdown_res: ShutdownResult) {
		debug_assert_ne!(self.per_peer_state.held_by_thread(), LockHeldState::HeldByThread);
		#[cfg(debug_assertions)]
		for (_, peer) in self.per_peer_state.read().unwrap().iter() {
			debug_assert_ne!(peer.held_by_thread(), LockHeldState::HeldByThread);
		}

		let logger = WithContext::from(
			&self.logger,
			Some(shutdown_res.counterparty_node_id),
			Some(shutdown_res.channel_id),
			None,
		);

		log_debug!(
			logger,
			"Finishing closure of channel due to {} with {} HTLCs to fail",
			shutdown_res.closure_reason,
			shutdown_res.dropped_outbound_htlcs.len()
		);
		for htlc_source in shutdown_res.dropped_outbound_htlcs.drain(..) {
			let (source, payment_hash, counterparty_node_id, channel_id) = htlc_source;
			let failure_reason = LocalHTLCFailureReason::ChannelClosed;
			let reason = HTLCFailReason::from_failure_code(failure_reason);
			let receiver = HTLCHandlingFailureType::Forward {
				node_id: Some(counterparty_node_id),
				channel_id,
			};
			self.fail_htlc_backwards_internal(&source, &payment_hash, &reason, receiver, None);
		}
		if let Some((_, funding_txo, _channel_id, monitor_update)) = shutdown_res.monitor_update {
			debug_assert!(false, "This should have been handled in `convert_channel_err`");
			self.apply_post_close_monitor_update(
				shutdown_res.counterparty_node_id,
				shutdown_res.channel_id,
				funding_txo,
				monitor_update,
			);
		}
		if self.background_events_processed_since_startup.load(Ordering::Acquire) {
			// If a `ChannelMonitorUpdate` was applied (i.e. any time we have a funding txo and are
			// not in the startup sequence) check if we need to handle any
			// `MonitorUpdateCompletionAction`s.
			// TODO: If we do the `in_flight_monitor_updates.is_empty()` check in
			// `convert_channel_err` we can skip the locks here.
			if shutdown_res.channel_funding_txo.is_some() {
				self.channel_monitor_updated(
					&shutdown_res.channel_id,
					None,
					&shutdown_res.counterparty_node_id,
				);
			}
		}
		let mut shutdown_results: Vec<(Result<Infallible, _>, _)> = Vec::new();
		if let Some(txid) = shutdown_res.unbroadcasted_batch_funding_txid {
			let mut funding_batch_states = self.funding_batch_states.lock().unwrap();
			let affected_channels = funding_batch_states.remove(&txid).into_iter().flatten();
			let per_peer_state = self.per_peer_state.read().unwrap();
			let mut has_uncompleted_channel = None;
			for (channel_id, counterparty_node_id, state) in affected_channels {
				if let Some(peer_state_mutex) = per_peer_state.get(&counterparty_node_id) {
					let mut peer_state_lock = peer_state_mutex.lock().unwrap();
					let peer_state = &mut *peer_state_lock;
					if let Some(mut chan) = peer_state.channel_by_id.remove(&channel_id) {
						let reason = ClosureReason::FundingBatchClosure;
						let err = ChannelError::Close((reason.to_string(), reason));
						let (_, e) = self.locked_handle_force_close(
							&mut peer_state.closed_channel_monitor_update_ids,
							&mut peer_state.in_flight_monitor_updates,
							err,
							&mut chan,
						);
						shutdown_results.push((Err(e), counterparty_node_id));
					}
				}
				has_uncompleted_channel =
					Some(has_uncompleted_channel.map_or(!state, |v| v || !state));
			}
			debug_assert!(
				has_uncompleted_channel.unwrap_or(true),
				"Closing a batch where all channels have completed initial monitor update",
			);
		}

		{
			let mut pending_events = self.pending_events.lock().unwrap();
			pending_events.push_back((
				events::Event::ChannelClosed {
					channel_id: shutdown_res.channel_id,
					user_channel_id: shutdown_res.user_channel_id,
					reason: shutdown_res.closure_reason,
					counterparty_node_id: Some(shutdown_res.counterparty_node_id),
					channel_capacity_sats: Some(shutdown_res.channel_capacity_satoshis),
					channel_funding_txo: shutdown_res.channel_funding_txo,
					last_local_balance_msat: Some(shutdown_res.last_local_balance_msat),
				},
				None,
			));

			if let Some(splice_funding_failed) = shutdown_res.splice_funding_failed.take() {
				pending_events.push_back((
					events::Event::SpliceFailed {
						channel_id: shutdown_res.channel_id,
						counterparty_node_id: shutdown_res.counterparty_node_id,
						user_channel_id: shutdown_res.user_channel_id,
						abandoned_funding_txo: splice_funding_failed.funding_txo,
						channel_type: splice_funding_failed.channel_type,
						contributed_inputs: splice_funding_failed.contributed_inputs,
						contributed_outputs: splice_funding_failed.contributed_outputs,
					},
					None,
				));
			}

			if let Some(transaction) = shutdown_res.unbroadcasted_funding_tx {
				let funding_info = if shutdown_res.is_manual_broadcast {
					FundingInfo::OutPoint {
						outpoint: shutdown_res.channel_funding_txo
							.expect("We had an unbroadcasted funding tx, so should also have had a funding outpoint"),
					}
				} else {
					FundingInfo::Tx { transaction }
				};
				pending_events.push_back((
					events::Event::DiscardFunding {
						channel_id: shutdown_res.channel_id,
						funding_info,
					},
					None,
				));
			}
		}
		for (err, counterparty_node_id) in shutdown_results.drain(..) {
			let _ = self.handle_error(err, counterparty_node_id);
		}
	}

	/// `peer_msg` should be set when we receive a message from a peer, but not set when the
	/// user closes, which will be re-exposed as the `ChannelClosed` reason.
	fn force_close_channel_with_peer(
		&self, channel_id: &ChannelId, peer_node_id: &PublicKey, reason: ClosureReason,
	) -> Result<(), APIError> {
		let per_peer_state = self.per_peer_state.read().unwrap();
		let peer_state_mutex =
			per_peer_state.get(peer_node_id).ok_or_else(|| APIError::no_such_peer(peer_node_id))?;
		let mut peer_state_lock = peer_state_mutex.lock().unwrap();
		let peer_state = &mut *peer_state_lock;
		let logger = WithContext::from(&self.logger, Some(*peer_node_id), Some(*channel_id), None);

		let is_from_counterparty = matches!(reason, ClosureReason::CounterpartyForceClosed { .. });
		let message = match &reason {
			ClosureReason::HolderForceClosed { message, .. } => message.clone(),
			_ => reason.to_string(),
		};

		if let Some(mut chan) = peer_state.channel_by_id.remove(channel_id) {
			log_error!(logger, "Force-closing channel");
			let err = ChannelError::Close((message, reason));
			let (_, mut e) = self.locked_handle_force_close(
				&mut peer_state.closed_channel_monitor_update_ids,
				&mut peer_state.in_flight_monitor_updates,
				err,
				&mut chan,
			);
			mem::drop(peer_state_lock);
			mem::drop(per_peer_state);
			if is_from_counterparty {
				// If the peer is the one who asked us to force-close, don't reply with a fresh
				// error message.
				e.dont_send_error_message();
			}
			let _ = self.handle_error(Err::<(), _>(e), *peer_node_id);
			Ok(())
		} else if peer_state.inbound_channel_request_by_id.remove(channel_id).is_some() {
			log_error!(logger, "Force-closing inbound channel request");
			if !is_from_counterparty && peer_state.is_connected {
				peer_state.pending_msg_events.push(MessageSendEvent::HandleError {
					node_id: *peer_node_id,
					action: msgs::ErrorAction::SendErrorMessage {
						msg: msgs::ErrorMessage { channel_id: *channel_id, data: message },
					},
				});
			}
			// N.B. that we don't send any channel close event here: we
			// don't have a user_channel_id, and we never sent any opening
			// events anyway.
			Ok(())
		} else {
			Err(APIError::no_such_channel_for_peer(channel_id, peer_node_id))
		}
	}

	#[rustfmt::skip]
	fn force_close_sending_error(&self, channel_id: &ChannelId, counterparty_node_id: &PublicKey, error_message: String)
	-> Result<(), APIError> {
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(self);
		log_debug!(self.logger,
			"Force-closing channel, The error message sent to the peer : {}", error_message);
		// No matter what value for `broadcast_latest_txn` we set here, `Channel` will override it
		// and set the appropriate value.
		let reason = ClosureReason::HolderForceClosed {
			broadcasted_latest_txn: Some(true),
			message: error_message,
		};
		self.force_close_channel_with_peer(channel_id, &counterparty_node_id, reason)
	}

	/// Force closes a channel, immediately broadcasting the latest local transaction(s),
	/// rejecting new HTLCs.
	///
	/// The provided `error_message` is sent to connected peers for closing
	/// channels and should be a human-readable description of what went wrong.
	///
	/// Fails if `channel_id` is unknown to the manager, or if the `counterparty_node_id`
	/// isn't the counterparty of the corresponding channel.
	pub fn force_close_broadcasting_latest_txn(
		&self, channel_id: &ChannelId, counterparty_node_id: &PublicKey, error_message: String,
	) -> Result<(), APIError> {
		self.force_close_sending_error(channel_id, counterparty_node_id, error_message)
	}

	/// Force close all channels, immediately broadcasting the latest local commitment transaction
	/// for each to the chain and rejecting new HTLCs on each.
	///
	/// The provided `error_message` is sent to connected peers for closing channels and should
	/// be a human-readable description of what went wrong.
	pub fn force_close_all_channels_broadcasting_latest_txn(&self, error_message: String) {
		for chan in self.list_channels() {
			let _ = self.force_close_broadcasting_latest_txn(
				&chan.channel_id,
				&chan.counterparty.node_id,
				error_message.clone(),
			);
		}
	}

	/// Handles an error by closing the channel if required and generating peer messages.
	fn handle_error<A>(
		&self, internal: Result<A, MsgHandleErrInternal>, counterparty_node_id: PublicKey,
	) -> Result<A, LightningError> {
		// In testing, ensure there are no deadlocks where the lock is already held upon
		// entering the macro.
		debug_assert_ne!(self.pending_events.held_by_thread(), LockHeldState::HeldByThread);
		debug_assert_ne!(self.per_peer_state.held_by_thread(), LockHeldState::HeldByThread);

		internal.map_err(|err_internal| {
			let mut msg_event = None;

			if let Some((shutdown_res, update_option)) = err_internal.shutdown_finish {
				let counterparty_node_id = shutdown_res.counterparty_node_id;
				let channel_id = shutdown_res.channel_id;
				let logger = WithContext::from(
					&self.logger,
					Some(counterparty_node_id),
					Some(channel_id),
					None,
				);
				log_error!(logger, "Closing channel: {}", err_internal.err.err);

				self.finish_close_channel(shutdown_res);
				if let Some((update, node_id_1, node_id_2)) = update_option {
					let mut pending_broadcast_messages =
						self.pending_broadcast_messages.lock().unwrap();
					pending_broadcast_messages.push(MessageSendEvent::BroadcastChannelUpdate {
						msg: update,
						node_id_1,
						node_id_2,
					});
				}
			} else {
				log_error!(self.logger, "Got non-closing error: {}", err_internal.err.err);
			}

			if let msgs::ErrorAction::IgnoreError = err_internal.err.action {
				if let Some(tx_abort) = err_internal.tx_abort {
					msg_event = Some(MessageSendEvent::SendTxAbort {
						node_id: counterparty_node_id,
						msg: tx_abort,
					});
				}
			} else {
				msg_event = Some(MessageSendEvent::HandleError {
					node_id: counterparty_node_id,
					action: err_internal.err.action.clone(),
				});
			}

			let mut holding_cell_res = None;
			if msg_event.is_some() || err_internal.exited_quiescence {
				let per_peer_state = self.per_peer_state.read().unwrap();
				if let Some(peer_state_mutex) = per_peer_state.get(&counterparty_node_id) {
					let mut peer_state = peer_state_mutex.lock().unwrap();
					if let Some(msg_event) = msg_event {
						if peer_state.is_connected {
							peer_state.pending_msg_events.push(msg_event);
						}
					}
					// We need to enqueue the `tx_abort` in `pending_msg_events` above before we
					// enqueue any commitment updates generated by freeing holding cell HTLCs.
					holding_cell_res = err_internal
						.exited_quiescence
						.then(|| self.check_free_peer_holding_cells(&mut peer_state));
				}
			}
			if let Some(res) = holding_cell_res {
				self.handle_holding_cell_free_result(res);
			}

			// Return error in case higher-API need one
			err_internal.err
		})
	}

	/// Handle the initial within-lock closure for a funded channel that is either force-closed or cooperatively
	/// closed (as indicated by `coop_close_shutdown_res`).
	///
	/// Returns `(boolean indicating if we should remove the Channel object from memory, a mapped
	/// error)`.
	fn locked_handle_funded_close_internal(
		&self, closed_channel_monitor_update_ids: &mut BTreeMap<ChannelId, u64>,
		in_flight_monitor_updates: &mut BTreeMap<ChannelId, (OutPoint, Vec<ChannelMonitorUpdate>)>,
		coop_close_shutdown_res: Option<ShutdownResult>, err: ChannelError,
		chan: &mut FundedChannel<SP>,
	) -> (bool, MsgHandleErrInternal) {
		let chan_id = chan.context.channel_id();
		convert_channel_err_internal(err, chan_id, |reason, msg| {
			let logger = WithChannelContext::from(&self.logger, &chan.context, None);

			let mut shutdown_res = if let Some(res) = coop_close_shutdown_res {
				res
			} else {
				chan.force_shutdown(reason)
			};
			let chan_update = self.get_channel_update_for_broadcast(chan).ok();

			log_error!(logger, "Closed channel due to close-required error: {}", msg);

			if let Some((_, funding_txo, _, update)) = shutdown_res.monitor_update.take() {
				self.handle_new_monitor_update_locked_actions_handled_by_caller(
					in_flight_monitor_updates,
					chan.context.channel_id(),
					funding_txo,
					chan.context.get_counterparty_node_id(),
					update,
				);
			}
			// If there's a possibility that we need to generate further monitor updates for this
			// channel, we need to store the last update_id of it. However, we don't want to insert
			// into the map (which prevents the `PeerState` from being cleaned up) for channels that
			// never even got confirmations (which would open us up to DoS attacks).
			let update_id = chan.context.get_latest_monitor_update_id();
			let funding_confirmed = chan.funding.get_funding_tx_confirmation_height().is_some();
			let chan_zero_conf = chan.context.minimum_depth(&chan.funding) == Some(0);
			if funding_confirmed || chan_zero_conf || update_id > 1 {
				closed_channel_monitor_update_ids.insert(chan_id, update_id);
			}
			let mut short_to_chan_info = self.short_to_chan_info.write().unwrap();
			if let Some(short_id) = chan.funding.get_short_channel_id() {
				short_to_chan_info.remove(&short_id);
			} else {
				// If the channel was never confirmed on-chain prior to its closure, remove the
				// outbound SCID alias we used for it from the collision-prevention set. While we
				// generally want to avoid ever re-using an outbound SCID alias across all channels, we
				// also don't want a counterparty to be able to trivially cause a memory leak by simply
				// opening a million channels with us which are closed before we ever reach the funding
				// stage.
				let outbound_alias = chan.context.outbound_scid_alias();
				let alias_removed =
					self.outbound_scid_aliases.lock().unwrap().remove(&outbound_alias);
				debug_assert!(alias_removed);
			}
			short_to_chan_info.remove(&chan.context.outbound_scid_alias());
			for scid in chan.context.historical_scids() {
				short_to_chan_info.remove(scid);
			}

			(shutdown_res, chan_update)
		})
	}

	/// Handle the initial within-lock closure for an unfunded channel.
	///
	/// Returns `(boolean indicating if we should remove the Channel object from memory, a mapped
	/// error)`.
	///
	/// The same closure semantics as described in [`ChannelManager::locked_handle_force_close`] apply.
	fn locked_handle_unfunded_close(
		&self, err: ChannelError, chan: &mut Channel<SP>,
	) -> (bool, MsgHandleErrInternal) {
		let chan_id = chan.context().channel_id();
		convert_channel_err_internal(err, chan_id, |reason, msg| {
			let logger = WithChannelContext::from(&self.logger, chan.context(), None);

			let shutdown_res = chan.force_shutdown(reason);
			log_error!(logger, "Closed channel due to close-required error: {}", msg);
			self.short_to_chan_info.write().unwrap().remove(&chan.context().outbound_scid_alias());
			// If the channel was never confirmed on-chain prior to its closure, remove the
			// outbound SCID alias we used for it from the collision-prevention set. While we
			// generally want to avoid ever re-using an outbound SCID alias across all channels, we
			// also don't want a counterparty to be able to trivially cause a memory leak by simply
			// opening a million channels with us which are closed before we ever reach the funding
			// stage.
			let outbound_alias = chan.context().outbound_scid_alias();
			let alias_removed = self.outbound_scid_aliases.lock().unwrap().remove(&outbound_alias);
			debug_assert!(alias_removed);
			(shutdown_res, None)
		})
	}

	/// Handle the initial within-lock closure for a channel that is cooperatively closed.
	///
	/// Returns a mapped error.
	///
	/// The same closure semantics as described in [`ChannelManager::locked_handle_force_close`] apply.
	fn locked_handle_funded_coop_close(
		&self, closed_update_ids: &mut BTreeMap<ChannelId, u64>,
		in_flight_updates: &mut BTreeMap<ChannelId, (OutPoint, Vec<ChannelMonitorUpdate>)>,
		shutdown_result: ShutdownResult, funded_channel: &mut FundedChannel<SP>,
	) -> MsgHandleErrInternal {
		let reason =
			ChannelError::Close(("Coop Closed".to_owned(), shutdown_result.closure_reason.clone()));
		let (close, mut err) = self.locked_handle_funded_close_internal(
			closed_update_ids,
			in_flight_updates,
			Some(shutdown_result),
			reason,
			funded_channel,
		);
		err.dont_send_error_message();
		debug_assert!(close);
		err
	}

	/// Handle the initial within-lock closure for a funded channel that is force-closed.
	///
	/// Returns `(boolean indicating if we should remove the Channel object from memory, a mapped
	/// error)`.
	///
	/// The same closure semantics as described in [`ChannelManager::locked_handle_force_close`] apply.
	fn locked_handle_funded_force_close(
		&self, closed_update_ids: &mut BTreeMap<ChannelId, u64>,
		in_flight_updates: &mut BTreeMap<ChannelId, (OutPoint, Vec<ChannelMonitorUpdate>)>,
		err: ChannelError, funded_channel: &mut FundedChannel<SP>,
	) -> (bool, MsgHandleErrInternal) {
		self.locked_handle_funded_close_internal(
			closed_update_ids,
			in_flight_updates,
			None,
			err,
			funded_channel,
		)
	}

	/// Handle the initial within-lock closure for a channel that is force-closed.
	///
	/// Returns `(boolean indicating if we should remove the Channel object from memory, a mapped
	/// error)`.
	///
	/// # Closure semantics
	///
	/// Two things need to happen:
	/// (a) This method must be called in the same `per_peer_state` lock as the channel-closing action,
	/// (b) [`ChannelManager::handle_error`] needs to be called without holding any locks (except
	///     [`ChannelManager::total_consistency_lock`]), which then calls
	///     [`ChannelManager::finish_close_channel`].
	fn locked_handle_force_close(
		&self, closed_update_ids: &mut BTreeMap<ChannelId, u64>,
		in_flight_updates: &mut BTreeMap<ChannelId, (OutPoint, Vec<ChannelMonitorUpdate>)>,
		err: ChannelError, channel: &mut Channel<SP>,
	) -> (bool, MsgHandleErrInternal) {
		match channel.as_funded_mut() {
			Some(funded_channel) => self.locked_handle_funded_close_internal(
				closed_update_ids,
				in_flight_updates,
				None,
				err,
				funded_channel,
			),
			None => self.locked_handle_unfunded_close(err, channel),
		}
	}

	/// Initiate a splice in order to add value to (splice-in) or remove value from (splice-out)
	/// the channel. This will spend the channel's funding transaction output, effectively replacing
	/// it with a new one.
	///
	/// # Required Feature Flags
	///
	/// Initiating a splice requires that the channel counterparty supports splicing. Any
	/// channel (no matter the type) can be spliced, as long as the counterparty is currently
	/// connected.
	///
	/// # Arguments
	///
	/// The splice initiator is responsible for paying fees for common fields, shared inputs, and
	/// shared outputs along with any contributed inputs and outputs. Fees are determined using
	/// `feerate` and must be covered by the supplied inputs for splice-in or the channel balance
	/// for splice-out.
	///
	/// Returns a [`FundingTemplate`] which should be used to build a [`FundingContribution`] via
	/// one of its splice methods (e.g., [`FundingTemplate::splice_in_sync`]). The resulting
	/// contribution must then be passed to [`ChannelManager::funding_contributed`].
	///
	/// # Events
	///
	/// Once the funding transaction has been constructed, an [`Event::SplicePending`] will be
	/// emitted. At this point, any inputs contributed to the splice can only be re-spent if an
	/// [`Event::DiscardFunding`] is seen.
	///
	/// After initial signatures have been exchanged, [`Event::FundingTransactionReadyForSigning`]
	/// will be generated and [`ChannelManager::funding_transaction_signed`] should be called.
	///
	/// If any failures occur while negotiating the funding transaction, an [`Event::SpliceFailed`]
	/// will be emitted. Any contributed inputs no longer used will be included here and thus can
	/// be re-spent.
	///
	/// Once the splice has been locked by both counterparties, an [`Event::ChannelReady`] will be
	/// emitted with the new funding output. At this point, a new splice can be negotiated by
	/// calling `splice_channel` again on this channel.
	///
	/// [`FundingContribution`]: crate::ln::funding::FundingContribution
	#[rustfmt::skip]
	pub fn splice_channel(
		&self, channel_id: &ChannelId, counterparty_node_id: &PublicKey, feerate: FeeRate,
	) -> Result<FundingTemplate, APIError> {
		let per_peer_state = self.per_peer_state.read().unwrap();

		let peer_state_mutex = match per_peer_state
			.get(counterparty_node_id)
			.ok_or_else(|| APIError::no_such_peer(counterparty_node_id))
		{
			Ok(p) => p,
			Err(e) => return Err(e),
		};

		let mut peer_state = peer_state_mutex.lock().unwrap();
		if !peer_state.latest_features.supports_splicing() {
			return Err(APIError::ChannelUnavailable {
				err: "Peer does not support splicing".to_owned(),
			});
		}
		if !peer_state.latest_features.supports_quiescence() {
			return Err(APIError::ChannelUnavailable {
				err: "Peer does not support quiescence, a splicing prerequisite".to_owned(),
			});
		}

		// Look for the channel
		match peer_state.channel_by_id.entry(*channel_id) {
			hash_map::Entry::Occupied(chan_phase_entry) => {
				if let Some(chan) = chan_phase_entry.get().as_funded() {
					chan.splice_channel(feerate)
				} else {
					Err(APIError::ChannelUnavailable {
						err: format!(
							"Channel with id {} is not funded, cannot splice it",
							channel_id
						),
					})
				}
			},
			hash_map::Entry::Vacant(_) => {
				Err(APIError::no_such_channel_for_peer(channel_id, counterparty_node_id))
			},
		}
	}

	#[cfg(test)]
	pub(crate) fn abandon_splice(
		&self, channel_id: &ChannelId, counterparty_node_id: &PublicKey,
	) -> Result<(), APIError> {
		let mut res = Ok(());
		PersistenceNotifierGuard::optionally_notify(self, || {
			let result = self.internal_abandon_splice(channel_id, counterparty_node_id);
			res = result;
			match res {
				Ok(_) => NotifyOption::SkipPersistHandleEvents,
				Err(_) => NotifyOption::SkipPersistNoEvents,
			}
		});
		res
	}

	#[cfg(test)]
	fn internal_abandon_splice(
		&self, channel_id: &ChannelId, counterparty_node_id: &PublicKey,
	) -> Result<(), APIError> {
		let per_peer_state = self.per_peer_state.read().unwrap();

		let peer_state_mutex = match per_peer_state
			.get(counterparty_node_id)
			.ok_or_else(|| APIError::no_such_peer(counterparty_node_id))
		{
			Ok(p) => p,
			Err(e) => return Err(e),
		};

		let mut peer_state_lock = peer_state_mutex.lock().unwrap();
		let peer_state = &mut *peer_state_lock;

		// Look for the channel
		match peer_state.channel_by_id.entry(*channel_id) {
			hash_map::Entry::Occupied(mut chan_phase_entry) => {
				if !chan_phase_entry.get().context().is_connected() {
					// TODO: We should probably support this, but right now `splice_channel` refuses when
					// the peer is disconnected, so we just check it here.
					return Err(APIError::ChannelUnavailable {
						err: "Cannot abandon splice while peer is disconnected".to_owned(),
					});
				}

				if let Some(chan) = chan_phase_entry.get_mut().as_funded_mut() {
					let (tx_abort, splice_funding_failed) = chan.abandon_splice()?;

					peer_state.pending_msg_events.push(MessageSendEvent::SendTxAbort {
						node_id: *counterparty_node_id,
						msg: tx_abort,
					});

					if let Some(splice_funding_failed) = splice_funding_failed {
						let pending_events = &mut self.pending_events.lock().unwrap();
						pending_events.push_back((
							events::Event::SpliceFailed {
								channel_id: *channel_id,
								counterparty_node_id: *counterparty_node_id,
								user_channel_id: chan.context.get_user_id(),
								abandoned_funding_txo: splice_funding_failed.funding_txo,
								channel_type: splice_funding_failed.channel_type,
								contributed_inputs: splice_funding_failed.contributed_inputs,
								contributed_outputs: splice_funding_failed.contributed_outputs,
							},
							None,
						));
					}

					Ok(())
				} else {
					Err(APIError::ChannelUnavailable {
						err: format!(
							"Channel with id {} is not funded, cannot abandon splice",
							channel_id
						),
					})
				}
			},
			hash_map::Entry::Vacant(_) => {
				Err(APIError::no_such_channel_for_peer(channel_id, counterparty_node_id))
			},
		}
	}

	fn forward_needs_intercept_to_known_chan(
		&self, prev_chan_public: bool, outbound_chan: &FundedChannel<SP>,
	) -> bool {
		let intercept_flags = self.config.read().unwrap().htlc_interception_flags;
		if !outbound_chan.context.should_announce() {
			if outbound_chan.context.is_connected() {
				if intercept_flags & (HTLCInterceptionFlags::ToOnlinePrivateChannels as u8) != 0 {
					return true;
				}
			} else {
				if intercept_flags & (HTLCInterceptionFlags::ToOfflinePrivateChannels as u8) != 0 {
					return true;
				}
			}
		} else {
			if intercept_flags & (HTLCInterceptionFlags::ToPublicChannels as u8) != 0 {
				return true;
			}
		}
		if prev_chan_public {
			if outbound_chan.context.should_announce() {
				if intercept_flags & (HTLCInterceptionFlags::FromPublicToPublicChannels as u8) != 0
				{
					return true;
				}
			} else {
				if intercept_flags & (HTLCInterceptionFlags::FromPublicToPrivateChannels as u8) != 0
				{
					return true;
				}
			}
		} else {
			if intercept_flags & (HTLCInterceptionFlags::FromPrivateChannels as u8) != 0 {
				return true;
			}
		}
		false
	}

	fn forward_needs_intercept_to_unknown_chan(&self, outgoing_scid: u64) -> bool {
		let intercept_flags = self.config.read().unwrap().htlc_interception_flags;
		if fake_scid::is_valid_intercept(
			&self.fake_scid_rand_bytes,
			outgoing_scid,
			&self.chain_hash,
		) {
			if intercept_flags & (HTLCInterceptionFlags::ToInterceptSCIDs as u8) != 0 {
				return true;
			}
		} else if fake_scid::is_valid_phantom(
			&self.fake_scid_rand_bytes,
			outgoing_scid,
			&self.chain_hash,
		) {
			// Handled as a normal forward
		} else if intercept_flags & (HTLCInterceptionFlags::ToUnknownSCIDs as u8) != 0 {
			return true;
		}
		false
	}

	#[rustfmt::skip]
	fn can_forward_htlc_to_outgoing_channel(
		&self, chan: &mut FundedChannel<SP>, msg: &msgs::UpdateAddHTLC,
		next_packet: &NextPacketDetails, will_intercept: bool,
	) -> Result<(), LocalHTLCFailureReason> {
		if !chan.context.should_announce()
			&& !self.config.read().unwrap().accept_forwards_to_priv_channels
		{
			// Note that the behavior here should be identical to the above block - we
			// should NOT reveal the existence or non-existence of a private channel if
			// we don't allow forwards outbound over them.
			return Err(LocalHTLCFailureReason::PrivateChannelForward);
		}
		if let HopConnector::ShortChannelId(outgoing_scid) = next_packet.outgoing_connector {
			if chan.funding.get_channel_type().supports_scid_privacy() && outgoing_scid != chan.context.outbound_scid_alias() {
				// `option_scid_alias` (referred to in LDK as `scid_privacy`) means
				// "refuse to forward unless the SCID alias was used", so we pretend
				// we don't have the channel here.
				return Err(LocalHTLCFailureReason::RealSCIDForward);
			}
		} else {
			return Err(LocalHTLCFailureReason::InvalidTrampolineForward);
		}

		// Note that we could technically not return an error yet here and just hope
		// that the connection is reestablished or monitor updated by the time we get
		// around to doing the actual forward, but better to fail early if we can and
		// hopefully an attacker trying to path-trace payments cannot make this occur
		// on a small/per-node/per-channel scale.
		if !will_intercept && !chan.context.is_live() {
			if !chan.context.is_enabled() {
				return Err(LocalHTLCFailureReason::ChannelDisabled);
			} else if !chan.context.is_connected() {
				return Err(LocalHTLCFailureReason::PeerOffline);
			} else {
				return Err(LocalHTLCFailureReason::ChannelNotReady);
			}
		}
		if next_packet.outgoing_amt_msat < chan.context.get_counterparty_htlc_minimum_msat() {
			return Err(LocalHTLCFailureReason::AmountBelowMinimum);
		}
		chan.htlc_satisfies_config(msg, next_packet.outgoing_amt_msat, next_packet.outgoing_cltv_value)
	}

	/// Executes a callback `C` that returns some value `X` on the channel found with the given
	/// `scid`. `None` is returned when the channel is not found.
	fn do_funded_channel_callback<X, C: Fn(&mut FundedChannel<SP>) -> X>(
		&self, scid: u64, callback: C,
	) -> Option<X> {
		let (counterparty_node_id, channel_id) =
			match self.short_to_chan_info.read().unwrap().get(&scid).cloned() {
				None => return None,
				Some((cp_id, id)) => (cp_id, id),
			};
		let per_peer_state = self.per_peer_state.read().unwrap();
		let peer_state_mutex_opt = per_peer_state.get(&counterparty_node_id);
		if peer_state_mutex_opt.is_none() {
			return None;
		}
		let mut peer_state_lock = peer_state_mutex_opt.unwrap().lock().unwrap();
		let peer_state = &mut *peer_state_lock;
		match peer_state.channel_by_id.get_mut(&channel_id).and_then(Channel::as_funded_mut) {
			None => None,
			Some(chan) => Some(callback(chan)),
		}
	}

	fn can_forward_htlc_should_intercept(
		&self, msg: &msgs::UpdateAddHTLC, prev_chan_public: bool, next_hop: &NextPacketDetails,
	) -> Result<bool, LocalHTLCFailureReason> {
		let outgoing_scid = match next_hop.outgoing_connector {
			HopConnector::ShortChannelId(scid) => scid,
			HopConnector::Dummy => {
				// Dummy hops are only used for path padding and must not reach HTLC processing.
				debug_assert!(false, "Dummy hop reached HTLC handling.");
				return Err(LocalHTLCFailureReason::InvalidOnionPayload);
			},
			HopConnector::Trampoline(_) => {
				return Err(LocalHTLCFailureReason::InvalidTrampolineForward);
			},
		};
		// TODO: We do the fake SCID namespace check a bunch of times here (and indirectly via
		// `forward_needs_intercept_*`, including as called in
		// `can_forward_htlc_to_outgoing_channel`), we should find a way to reduce the number of
		// times we do it.
		let intercept =
			match self.do_funded_channel_callback(outgoing_scid, |chan: &mut FundedChannel<SP>| {
				let intercept = self.forward_needs_intercept_to_known_chan(prev_chan_public, chan);
				self.can_forward_htlc_to_outgoing_channel(chan, msg, next_hop, intercept)?;
				Ok(intercept)
			}) {
				Some(Ok(intercept)) => intercept,
				Some(Err(e)) => return Err(e),
				None => {
					// Perform basic sanity checks on the amounts and CLTV being forwarded
					if next_hop.outgoing_amt_msat > msg.amount_msat {
						return Err(LocalHTLCFailureReason::FeeInsufficient);
					}
					let cltv_delta = msg.cltv_expiry.saturating_sub(next_hop.outgoing_cltv_value);
					if cltv_delta < MIN_CLTV_EXPIRY_DELTA.into() {
						return Err(LocalHTLCFailureReason::IncorrectCLTVExpiry);
					}

					if fake_scid::is_valid_phantom(
						&self.fake_scid_rand_bytes,
						outgoing_scid,
						&self.chain_hash,
					) {
						false
					} else if self.forward_needs_intercept_to_unknown_chan(outgoing_scid) {
						true
					} else {
						return Err(LocalHTLCFailureReason::UnknownNextPeer);
					}
				},
			};

		let cur_height = self.best_block.read().unwrap().height + 1;
		check_incoming_htlc_cltv(cur_height, next_hop.outgoing_cltv_value, msg.cltv_expiry)?;

		Ok(intercept)
	}

	#[rustfmt::skip]
	fn htlc_failure_from_update_add_err(
		&self, msg: &msgs::UpdateAddHTLC, counterparty_node_id: &PublicKey,
		reason: LocalHTLCFailureReason, is_intro_node_blinded_forward: bool,
		shared_secret: &[u8; 32]
	) -> HTLCFailureMsg {
		// at capacity, we write fields `htlc_msat` and `len`
		let mut res = VecWriter(Vec::with_capacity(8 + 2));
		if reason.is_temporary() {
			if reason == LocalHTLCFailureReason::AmountBelowMinimum ||
				reason == LocalHTLCFailureReason::FeeInsufficient {
				msg.amount_msat.write(&mut res).expect("Writes cannot fail");
			}
			else if reason == LocalHTLCFailureReason::IncorrectCLTVExpiry {
				msg.cltv_expiry.write(&mut res).expect("Writes cannot fail");
			}
			else if reason == LocalHTLCFailureReason::ChannelDisabled {
				// TODO: underspecified, follow https://github.com/lightning/bolts/issues/791
				0u16.write(&mut res).expect("Writes cannot fail");
			}
			// See https://github.com/lightning/bolts/blob/247e83d/04-onion-routing.md?plain=1#L1414-L1415
			(0u16).write(&mut res).expect("Writes cannot fail");
		}

		log_info!(
			WithContext::from(&self.logger, Some(*counterparty_node_id), Some(msg.channel_id), Some(msg.payment_hash)),
			"Failed to accept/forward incoming HTLC: {:?}", reason,
		);
		// If `msg.blinding_point` is set, we must always fail with malformed.
		if msg.blinding_point.is_some() {
			return HTLCFailureMsg::Malformed(msgs::UpdateFailMalformedHTLC {
				channel_id: msg.channel_id,
				htlc_id: msg.htlc_id,
				sha256_of_onion: [0; 32],
				failure_code: LocalHTLCFailureReason::InvalidOnionBlinding.failure_code(),
			});
		}

		let (reason, err_data) = if is_intro_node_blinded_forward {
			(LocalHTLCFailureReason::InvalidOnionBlinding, &[0; 32][..])
		} else {
			(reason, &res.0[..])
		};
		let failure = HTLCFailReason::reason(reason, err_data.to_vec())
		.get_encrypted_failure_packet(shared_secret, &None);
		HTLCFailureMsg::Relay(msgs::UpdateFailHTLC {
			channel_id: msg.channel_id,
			htlc_id: msg.htlc_id,
			reason: failure.data,
			attribution_data: failure.attribution_data,
		})
	}

	#[rustfmt::skip]
	fn construct_pending_htlc_fail_msg<'a>(
		&self, msg: &msgs::UpdateAddHTLC, counterparty_node_id: &PublicKey,
		shared_secret: [u8; 32], inbound_err: InboundHTLCErr
	) -> HTLCFailureMsg {
		let logger = WithContext::from(&self.logger, Some(*counterparty_node_id), Some(msg.channel_id), Some(msg.payment_hash));
		log_info!(logger, "Failed to accept/forward incoming HTLC: {}", inbound_err.msg);

		if msg.blinding_point.is_some() {
			return HTLCFailureMsg::Malformed(
				msgs::UpdateFailMalformedHTLC {
					channel_id: msg.channel_id,
					htlc_id: msg.htlc_id,
					sha256_of_onion: [0; 32],
					failure_code: LocalHTLCFailureReason::InvalidOnionBlinding.failure_code(),
				}
			)
		}

		let failure = HTLCFailReason::reason(inbound_err.reason, inbound_err.err_data.to_vec())
					.get_encrypted_failure_packet(&shared_secret, &None);
		return HTLCFailureMsg::Relay(msgs::UpdateFailHTLC {
			channel_id: msg.channel_id,
			htlc_id: msg.htlc_id,
			reason: failure.data,
			attribution_data: failure.attribution_data,
		});
	}

	#[rustfmt::skip]
	fn get_pending_htlc_info<'a>(
		&self, msg: &msgs::UpdateAddHTLC, shared_secret: [u8; 32],
		decoded_hop: onion_utils::Hop, allow_underpay: bool,
		next_packet_pubkey_opt: Option<Result<PublicKey, secp256k1::Error>>,
	) -> Result<PendingHTLCInfo, InboundHTLCErr> {
		match decoded_hop {
			onion_utils::Hop::Receive { .. } | onion_utils::Hop::BlindedReceive { .. } |
			onion_utils::Hop::TrampolineReceive { .. } | onion_utils::Hop::TrampolineBlindedReceive { .. } => {
				// OUR PAYMENT!
				// Note that we could obviously respond immediately with an update_fulfill_htlc
				// message, however that would leak that we are the recipient of this payment, so
				// instead we stay symmetric with the forwarding case, only responding (after a
				// delay) once they've send us a commitment_signed!
				let current_height: u32 = self.best_block.read().unwrap().height;
				create_recv_pending_htlc_info(decoded_hop, shared_secret, msg.payment_hash,
					msg.amount_msat, msg.cltv_expiry, None, allow_underpay, msg.skimmed_fee_msat,
					msg.accountable.unwrap_or(false), current_height)
			},
			onion_utils::Hop::Forward { .. } | onion_utils::Hop::BlindedForward { .. } => {
				create_fwd_pending_htlc_info(msg, decoded_hop, shared_secret, next_packet_pubkey_opt)
			},
			onion_utils::Hop::Dummy { .. } => {
				debug_assert!(
					false,
					"Reached unreachable dummy-hop HTLC. Dummy hops are peeled in \
					`process_pending_update_add_htlcs`, and the resulting HTLC is \
					re-enqueued for processing. Hitting this means the peel-and-requeue \
					step was missed."
				);
				return Err(InboundHTLCErr {
					msg: "Failed to decode update add htlc onion",
					reason: LocalHTLCFailureReason::InvalidOnionPayload,
					err_data: Vec::new(),
				})
			},
			onion_utils::Hop::TrampolineForward { .. } | onion_utils::Hop::TrampolineBlindedForward { .. } => {
				create_fwd_pending_htlc_info(msg, decoded_hop, shared_secret, next_packet_pubkey_opt)
			},
		}
	}

	/// Gets the current [`channel_update`] for the given channel (as well as our and our
	/// counterparty's [`NodeId`], which is needed for the
	/// [`MessageSendEvent::BroadcastChannelUpdate`]). This first checks if the channel is
	/// public, and thus should be called whenever the result is going to be passed out in a
	/// [`MessageSendEvent::BroadcastChannelUpdate`] event.
	///
	/// Note that in [`internal_closing_signed`], this function is called without the `peer_state`
	/// corresponding to the channel's counterparty locked, as the channel been removed from the
	/// storage and the `peer_state` lock has been dropped.
	///
	/// [`channel_update`]: msgs::ChannelUpdate
	/// [`internal_closing_signed`]: Self::internal_closing_signed
	fn get_channel_update_for_broadcast(
		&self, chan: &FundedChannel<SP>,
	) -> Result<(msgs::ChannelUpdate, NodeId, NodeId), LightningError> {
		if !chan.context.should_announce() {
			return Err(LightningError {
				err: "Cannot broadcast a channel_update for a private channel".to_owned(),
				action: msgs::ErrorAction::IgnoreError,
			});
		}
		if chan.funding.get_short_channel_id().is_none() {
			return Err(LightningError {
				err: "Channel not yet established".to_owned(),
				action: msgs::ErrorAction::IgnoreError,
			});
		}
		let logger = WithChannelContext::from(&self.logger, &chan.context, None);
		log_trace!(logger, "Attempting to generate broadcast channel update",);
		self.get_channel_update_for_unicast(chan)
	}

	/// Gets the current [`channel_update`] for the given channel (as well as our and our
	/// counterparty's [`NodeId`]). This does not check if the channel is public (only returning an
	/// `Err` if the channel does not yet have an assigned SCID), and thus MUST NOT be called
	/// unless the recipient of the resulting message has already provided evidence that they know
	/// about the existence of the channel.
	///
	/// Note that through [`internal_closing_signed`], this function is called without the
	/// `peer_state`  corresponding to the channel's counterparty locked, as the channel been
	/// removed from the storage and the `peer_state` lock has been dropped.
	///
	/// [`channel_update`]: msgs::ChannelUpdate
	/// [`internal_closing_signed`]: Self::internal_closing_signed
	#[rustfmt::skip]
	fn get_channel_update_for_unicast(
		&self, chan: &FundedChannel<SP>,
	) -> Result<(msgs::ChannelUpdate, NodeId, NodeId), LightningError> {
		let logger = WithChannelContext::from(&self.logger, &chan.context, None);
		log_trace!(logger, "Attempting to generate channel update");
		let short_channel_id = match chan.funding.get_short_channel_id().or(chan.context.latest_inbound_scid_alias()) {
			None => return Err(LightningError{err: "Channel not yet established".to_owned(), action: msgs::ErrorAction::IgnoreError}),
			Some(id) => id,
		};

		let logger = WithChannelContext::from(&self.logger, &chan.context, None);
		log_trace!(logger, "Generating channel update");
		let our_node_id = NodeId::from_pubkey(&self.our_network_pubkey);
		let their_node_id = NodeId::from_pubkey(&chan.context.get_counterparty_node_id());
		let were_node_one = our_node_id < their_node_id;
		let enabled = chan.context.is_enabled();

		let unsigned = msgs::UnsignedChannelUpdate {
			chain_hash: self.chain_hash,
			short_channel_id,
			timestamp: chan.context.get_update_time_counter(),
			message_flags: 1 | if !chan.context.should_announce() { 1 << 1 } else { 0 }, // must_be_one + dont_forward
			channel_flags: (!were_node_one) as u8 | ((!enabled as u8) << 1),
			cltv_expiry_delta: chan.context.get_cltv_expiry_delta(),
			htlc_minimum_msat: chan.context.get_counterparty_htlc_minimum_msat(),
			htlc_maximum_msat: chan.get_announced_htlc_max_msat(),
			fee_base_msat: chan.context.get_outbound_forwarding_fee_base_msat(),
			fee_proportional_millionths: chan.context.get_fee_proportional_millionths(),
			excess_data: Vec::new(),
		};
		// Panic on failure to signal LDK should be restarted to retry signing the `ChannelUpdate`.
		// If we returned an error and the `node_signer` cannot provide a signature for whatever
		// reason`, we wouldn't be able to receive inbound payments through the corresponding
		// channel.
		let sig = self.node_signer.sign_gossip_message(msgs::UnsignedGossipMessage::ChannelUpdate(&unsigned)).unwrap();

		Ok((
			msgs::ChannelUpdate {
				signature: sig,
				contents: unsigned
			},
			if were_node_one { our_node_id } else { their_node_id },
			if were_node_one { their_node_id } else { our_node_id },
		))
	}

	#[cfg(any(test, feature = "_externalize_tests"))]
	pub(crate) fn test_send_payment_along_path(
		&self, path: &Path, payment_hash: &PaymentHash, recipient_onion: RecipientOnionFields,
		total_value: u64, cur_height: u32, payment_id: PaymentId,
		keysend_preimage: &Option<PaymentPreimage>, session_priv_bytes: [u8; 32],
	) -> Result<(), APIError> {
		let _lck = self.total_consistency_lock.read().unwrap();
		self.send_payment_along_path(SendAlongPathArgs {
			path,
			payment_hash,
			recipient_onion: &recipient_onion,
			total_value,
			cur_height,
			payment_id,
			keysend_preimage,
			invoice_request: None,
			bolt12_invoice: None,
			session_priv_bytes,
			hold_htlc_at_next_hop: false,
		})
	}

	fn send_payment_along_path(&self, args: SendAlongPathArgs) -> Result<(), APIError> {
		let SendAlongPathArgs {
			path,
			payment_hash,
			recipient_onion,
			total_value,
			cur_height,
			payment_id,
			keysend_preimage,
			invoice_request,
			bolt12_invoice,
			session_priv_bytes,
			hold_htlc_at_next_hop,
		} = args;
		// The top-level caller should hold the total_consistency_lock read lock.
		debug_assert!(self.total_consistency_lock.try_write().is_err());
		let prng_seed = self.entropy_source.get_secure_random_bytes();
		let session_priv = SecretKey::from_slice(&session_priv_bytes[..]).expect("RNG is busted");

		let logger = WithContext::for_payment(
			&self.logger,
			path.hops.first().map(|hop| hop.pubkey),
			None,
			Some(*payment_hash),
			payment_id,
		);
		let (onion_packet, htlc_msat, htlc_cltv) = onion_utils::create_payment_onion(
			&self.secp_ctx,
			&path,
			&session_priv,
			total_value,
			recipient_onion,
			cur_height,
			payment_hash,
			keysend_preimage,
			invoice_request,
			prng_seed,
		)
		.map_err(|e| {
			log_error!(logger, "Failed to build an onion for path");
			e
		})?;

		let err: Result<(), _> = loop {
			let first_chan_scid = &path.hops.first().unwrap().short_channel_id;
			let first_chan = self.short_to_chan_info.read().unwrap().get(first_chan_scid).cloned();

			let (counterparty_node_id, id) = match first_chan {
				None => {
					log_error!(logger, "Failed to find first-hop for payment hash {payment_hash}");
					return Err(APIError::ChannelUnavailable {
						err: "No channel available with first hop!".to_owned(),
					});
				},
				Some((cp_id, chan_id)) => (cp_id, chan_id),
			};

			// Add the channel id to the logger that already has the rest filled in.
			let logger_ref = &logger;
			let logger = WithContext::from(&logger_ref, None, Some(id), None);
			log_trace!(
				logger,
				"Attempting to send payment along path with next hop {first_chan_scid}"
			);

			let per_peer_state = self.per_peer_state.read().unwrap();
			let peer_state_mutex = per_peer_state.get(&counterparty_node_id).ok_or_else(|| {
				APIError::ChannelUnavailable {
					err: "No peer matching the path's first hop found!".to_owned(),
				}
			})?;
			let mut peer_state_lock = peer_state_mutex.lock().unwrap();
			let peer_state = &mut *peer_state_lock;
			if let hash_map::Entry::Occupied(mut chan_entry) = peer_state.channel_by_id.entry(id) {
				match chan_entry.get_mut().as_funded_mut() {
					Some(chan) => {
						if !chan.context.is_live() {
							return Err(APIError::ChannelUnavailable {
								err: "Peer for first hop currently disconnected".to_owned(),
							});
						}
						let funding_txo = chan.funding.get_funding_txo().unwrap();
						let htlc_source = HTLCSource::OutboundRoute {
							path: path.clone(),
							session_priv: session_priv.clone(),
							first_hop_htlc_msat: htlc_msat,
							payment_id,
							bolt12_invoice: bolt12_invoice.cloned(),
						};
						let send_res = chan.send_htlc_and_commit(
							htlc_msat,
							*payment_hash,
							htlc_cltv,
							htlc_source,
							onion_packet,
							None,
							hold_htlc_at_next_hop,
							false, // Not accountable by default for sender.
							&self.fee_estimator,
							&&logger,
						);
						match break_channel_entry!(self, peer_state, send_res, chan_entry) {
							Some(monitor_update) => {
								let (update_completed, completion_data) = self
									.handle_new_monitor_update_with_status(
										&mut peer_state.in_flight_monitor_updates,
										&mut peer_state.monitor_update_blocked_actions,
										&mut peer_state.pending_msg_events,
										peer_state.is_connected,
										chan,
										funding_txo,
										monitor_update,
									);
								if let Some(data) = completion_data {
									mem::drop(peer_state_lock);
									mem::drop(per_peer_state);
									self.handle_post_monitor_update_chan_resume(data);
								}
								if !update_completed {
									// Note that MonitorUpdateInProgress here indicates (per function
									// docs) that we will resend the commitment update once monitor
									// updating completes. Therefore, we must return an error
									// indicating that it is unsafe to retry the payment wholesale,
									// which we do in the send_payment check for
									// MonitorUpdateInProgress, below.
									return Err(APIError::MonitorUpdateInProgress);
								}
							},
							None => {},
						}
					},
					None => {
						return Err(APIError::ChannelUnavailable {
							err: "Channel to first hop is unfunded".to_owned(),
						})
					},
				};
			} else {
				// The channel was likely removed after we fetched the id from the
				// `short_to_chan_info` map, but before we successfully locked the
				// `channel_by_id` map.
				// This can occur as no consistency guarantees exists between the two maps.
				return Err(APIError::ChannelUnavailable {
					err: "No channel available with first hop!".to_owned(),
				});
			}
			return Ok(());
		};
		match self.handle_error(err, path.hops.first().unwrap().pubkey) {
			Ok(_) => unreachable!(),
			Err(e) => Err(APIError::ChannelUnavailable { err: e.err }),
		}
	}

	/// Sends a payment along a given route. See [`Self::send_payment`] for more info.
	///
	/// LDK will not automatically retry this payment, though it may be manually re-sent after an
	/// [`Event::PaymentFailed`] is generated.
	#[rustfmt::skip]
	pub fn send_payment_with_route(
		&self, mut route: Route, payment_hash: PaymentHash, recipient_onion: RecipientOnionFields,
		payment_id: PaymentId
	) -> Result<(), RetryableSendFailure> {
		let best_block_height = self.best_block.read().unwrap().height;
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(self);
		let route_params = route.route_params.clone().unwrap_or_else(|| {
			// Create a dummy route params since they're a required parameter but unused in this case
			let (payee_node_id, cltv_delta) = route.paths.first()
				.and_then(|path| path.hops.last().map(|hop| (hop.pubkey, hop.cltv_expiry_delta as u32)))
				.unwrap_or_else(|| (PublicKey::from_slice(&[2; 32]).unwrap(), MIN_FINAL_CLTV_EXPIRY_DELTA as u32));
			let dummy_payment_params = PaymentParameters::from_node_id(payee_node_id, cltv_delta);
			RouteParameters::from_payment_params_and_value(dummy_payment_params, route.get_total_amount())
		});
		if route.route_params.is_none() { route.route_params = Some(route_params.clone()); }
		let router = FixedRouter::new(route);
		let logger =
			WithContext::for_payment(&self.logger, None, None, Some(payment_hash), payment_id);
		self.pending_outbound_payments
			.send_payment(payment_hash, recipient_onion, payment_id, Retry::Attempts(0),
				route_params, &&router, self.list_usable_channels(), || self.compute_inflight_htlcs(),
				&self.entropy_source, &self.node_signer, best_block_height,
				&self.pending_events, |args| self.send_payment_along_path(args), &logger)
	}

	/// Sends a payment to the route found using the provided [`RouteParameters`], retrying failed
	/// payment paths based on the provided `Retry`.
	///
	/// You should likely prefer [`Self::pay_for_bolt11_invoice`] or [`Self::pay_for_offer`] in
	/// general, however this method may allow for slightly more customization.
	///
	/// May generate [`UpdateHTLCs`] message(s) event on success, which should be relayed (e.g. via
	/// [`PeerManager::process_events`]).
	///
	/// # Avoiding Duplicate Payments
	///
	/// If a pending payment is currently in-flight with the same [`PaymentId`] provided, this
	/// method will error with [`RetryableSendFailure::DuplicatePayment`]. Note, however, that once a
	/// payment is no longer pending (either via [`ChannelManager::abandon_payment`], or handling of
	/// an [`Event::PaymentSent`] or [`Event::PaymentFailed`]) LDK will not stop you from sending a
	/// second payment with the same [`PaymentId`].
	///
	/// Thus, in order to ensure duplicate payments are not sent, you should implement your own
	/// tracking of payments, including state to indicate once a payment has completed. Because you
	/// should also ensure that [`PaymentHash`]es are not re-used, for simplicity, you should
	/// consider using the [`PaymentHash`] as the key for tracking payments. In that case, the
	/// [`PaymentId`] should be a copy of the [`PaymentHash`] bytes.
	///
	/// Additionally, in the scenario where we begin the process of sending a payment, but crash
	/// before `send_payment` returns (or prior to [`ChannelMonitorUpdate`] persistence if you're
	/// using [`ChannelMonitorUpdateStatus::InProgress`]), the payment may be lost on restart. See
	/// [`ChannelManager::list_recent_payments`] for more information.
	///
	/// Routes are automatically found using the [`Router`] provided on startup. To fix a route for a
	/// particular payment, use [`Self::send_payment_with_route`] or match the [`PaymentId`] passed to
	/// [`Router::find_route_with_id`].
	///
	/// [`Event::PaymentSent`]: events::Event::PaymentSent
	/// [`Event::PaymentFailed`]: events::Event::PaymentFailed
	/// [`UpdateHTLCs`]: MessageSendEvent::UpdateHTLCs
	/// [`PeerManager::process_events`]: crate::ln::peer_handler::PeerManager::process_events
	/// [`ChannelMonitorUpdateStatus::InProgress`]: crate::chain::ChannelMonitorUpdateStatus::InProgress
	pub fn send_payment(
		&self, payment_hash: PaymentHash, recipient_onion: RecipientOnionFields,
		payment_id: PaymentId, route_params: RouteParameters, retry_strategy: Retry,
	) -> Result<(), RetryableSendFailure> {
		let best_block_height = self.best_block.read().unwrap().height;
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(self);
		self.pending_outbound_payments.send_payment(
			payment_hash,
			recipient_onion,
			payment_id,
			retry_strategy,
			route_params,
			&self.router,
			self.list_usable_channels(),
			|| self.compute_inflight_htlcs(),
			&self.entropy_source,
			&self.node_signer,
			best_block_height,
			&self.pending_events,
			|args| self.send_payment_along_path(args),
			&WithContext::for_payment(&self.logger, None, None, Some(payment_hash), payment_id),
		)
	}

	#[cfg(any(test, feature = "_externalize_tests"))]
	pub(super) fn test_send_payment_internal(
		&self, route: &Route, payment_hash: PaymentHash, recipient_onion: RecipientOnionFields,
		keysend_preimage: Option<PaymentPreimage>, payment_id: PaymentId,
		recv_value_msat: Option<u64>, onion_session_privs: Vec<[u8; 32]>,
	) -> Result<(), PaymentSendFailure> {
		let best_block_height = self.best_block.read().unwrap().height;
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(self);
		self.pending_outbound_payments.test_send_payment_internal(
			route,
			payment_hash,
			recipient_onion,
			keysend_preimage,
			payment_id,
			recv_value_msat,
			onion_session_privs,
			&self.node_signer,
			best_block_height,
			|args| self.send_payment_along_path(args),
		)
	}

	#[cfg(any(test, feature = "_externalize_tests"))]
	pub(crate) fn test_add_new_pending_payment(
		&self, payment_hash: PaymentHash, recipient_onion: RecipientOnionFields,
		payment_id: PaymentId, route: &Route,
	) -> Result<Vec<[u8; 32]>, PaymentSendFailure> {
		let best_block_height = self.best_block.read().unwrap().height;
		self.pending_outbound_payments.test_add_new_pending_payment(
			payment_hash,
			recipient_onion,
			payment_id,
			route,
			None,
			&self.entropy_source,
			best_block_height,
		)
	}

	#[cfg(test)]
	pub(crate) fn test_modify_pending_payment<Fn>(&self, payment_id: &PaymentId, mut callback: Fn)
	where
		Fn: FnMut(&mut PendingOutboundPayment),
	{
		let mut outbounds =
			self.pending_outbound_payments.pending_outbound_payments.lock().unwrap();
		match outbounds.get_mut(payment_id) {
			Some(outb) => callback(outb),
			_ => panic!(),
		}
	}

	#[cfg(test)]
	pub(crate) fn test_set_payment_metadata(
		&self, payment_id: PaymentId, new_payment_metadata: Option<Vec<u8>>,
	) {
		self.pending_outbound_payments.test_set_payment_metadata(payment_id, new_payment_metadata);
	}

	/// Pays a [`Bolt11Invoice`] associated with the `payment_id`. See [`Self::send_payment`] for more info.
	///
	/// # Payment Id
	/// The invoice's `payment_hash().0` serves as a reliable choice for the `payment_id`.
	///
	/// # Handling Invoice Amounts
	/// Some invoices include a specific amount, while others require you to specify one.
	/// - If the invoice **includes** an amount, user may provide an amount greater or equal to it
	/// to allow for overpayments.
	/// - If the invoice **doesn't include** an amount, you'll need to specify `amount_msats`.
	///
	/// If these conditions aren’t met, the function will return [`Bolt11PaymentError::InvalidAmount`].
	///
	/// # Custom Routing Parameters
	/// Users can customize routing parameters via [`RouteParametersConfig`].
	/// To use default settings, call the function with [`RouteParametersConfig::default`].
	pub fn pay_for_bolt11_invoice(
		&self, invoice: &Bolt11Invoice, payment_id: PaymentId, amount_msats: Option<u64>,
		optional_params: OptionalBolt11PaymentParams,
	) -> Result<(), Bolt11PaymentError> {
		let best_block_height = self.best_block.read().unwrap().height;
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(self);
		let payment_hash = invoice.payment_hash();
		self.pending_outbound_payments.pay_for_bolt11_invoice(
			invoice,
			payment_id,
			amount_msats,
			optional_params,
			&self.router,
			self.list_usable_channels(),
			|| self.compute_inflight_htlcs(),
			&self.entropy_source,
			&self.node_signer,
			best_block_height,
			&self.pending_events,
			|args| self.send_payment_along_path(args),
			&WithContext::for_payment(&self.logger, None, None, Some(payment_hash), payment_id),
		)
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
	/// [timer tick]: Self::timer_tick_occurred
	pub fn send_payment_for_bolt12_invoice(
		&self, invoice: &Bolt12Invoice, context: Option<&OffersContext>,
	) -> Result<(), Bolt12PaymentError> {
		match self.flow.verify_bolt12_invoice(invoice, context) {
			Ok(payment_id) => self.send_payment_for_verified_bolt12_invoice(invoice, payment_id),
			Err(()) => Err(Bolt12PaymentError::UnexpectedInvoice),
		}
	}

	fn send_payment_for_verified_bolt12_invoice(
		&self, invoice: &Bolt12Invoice, payment_id: PaymentId,
	) -> Result<(), Bolt12PaymentError> {
		let best_block_height = self.best_block.read().unwrap().height;
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(self);
		let features = self.bolt12_invoice_features();
		self.pending_outbound_payments.send_payment_for_bolt12_invoice(
			invoice,
			payment_id,
			&self.router,
			self.list_usable_channels(),
			features,
			|| self.compute_inflight_htlcs(),
			&self.entropy_source,
			&self.node_signer,
			&self,
			&self.secp_ctx,
			best_block_height,
			&self.pending_events,
			|args| self.send_payment_along_path(args),
			&WithContext::for_payment(&self.logger, None, None, None, payment_id),
		)
	}

	fn check_refresh_async_receive_offer_cache(&self, timer_tick_occurred: bool) {
		let peers = self.get_peers_for_blinded_path();
		let channels = self.list_usable_channels();
		let router = &self.router;
		let refresh_res = self.flow.check_refresh_async_receive_offer_cache(
			peers,
			channels,
			router,
			timer_tick_occurred,
		);
		match refresh_res {
			Err(()) => {
				log_error!(
					self.logger,
					"Failed to create blinded paths when requesting async receive offer paths"
				);
			},
			Ok(()) => {},
		}
	}

	#[cfg(test)]
	pub(crate) fn test_check_refresh_async_receive_offers(&self) {
		self.check_refresh_async_receive_offer_cache(false);
	}

	/// Should be called after handling an [`Event::PersistStaticInvoice`], where the `Responder`
	/// comes from [`Event::PersistStaticInvoice::invoice_persisted_path`].
	pub fn static_invoice_persisted(&self, invoice_persisted_path: Responder) {
		self.flow.static_invoice_persisted(invoice_persisted_path);
	}

	/// Forwards a [`StaticInvoice`] to a payer in response to an
	/// [`Event::StaticInvoiceRequested`]. Also forwards the payer's [`InvoiceRequest`] to the
	/// async recipient, in case the recipient is online to provide the payer with a fresh
	/// [`Bolt12Invoice`].
	pub fn respond_to_static_invoice_request(
		&self, invoice: StaticInvoice, responder: Responder, invoice_request: InvoiceRequest,
		invoice_request_path: BlindedMessagePath,
	) -> Result<(), Bolt12SemanticError> {
		self.flow.enqueue_invoice_request_to_forward(
			invoice_request,
			invoice_request_path,
			responder.clone(),
		);
		self.flow.enqueue_static_invoice(invoice, responder)
	}

	fn initiate_async_payment(
		&self, invoice: &StaticInvoice, payment_id: PaymentId,
	) -> Result<(), Bolt12PaymentError> {
		let mut res = Ok(());
		PersistenceNotifierGuard::optionally_notify(self, || {
			let logger = WithContext::for_payment(&self.logger, None, None, None, payment_id);
			let best_block_height = self.best_block.read().unwrap().height;
			let features = self.bolt12_invoice_features();
			let outbound_pmts_res = self.pending_outbound_payments.static_invoice_received(
				invoice,
				payment_id,
				features,
				best_block_height,
				self.duration_since_epoch(),
				&self.entropy_source,
				&self.pending_events,
			);
			match outbound_pmts_res {
				Ok(()) => {},
				Err(Bolt12PaymentError::UnexpectedInvoice)
				| Err(Bolt12PaymentError::DuplicateInvoice) => {
					res = outbound_pmts_res.map(|_| ());
					return NotifyOption::SkipPersistNoEvents;
				},
				Err(e) => {
					res = Err(e);
					return NotifyOption::DoPersist;
				},
			};

			// If the call to `Self::hold_htlc_channels` succeeded, then we are a private node and can
			// hold the HTLCs for this payment at our next-hop channel counterparty until the recipient
			// comes online. This allows us to go offline after locking in the HTLCs.
			if let Ok(channels) = self.hold_htlc_channels() {
				if let Err(e) =
					self.send_payment_for_static_invoice_no_persist(payment_id, channels, true)
				{
					log_trace!(
						logger,
						"Failed to send held HTLC with payment id {}: {:?}",
						payment_id,
						e
					);
				}
			} else {
				let reply_path = HeldHtlcReplyPath::ToUs {
					payment_id,
					peers: self.get_peers_for_blinded_path(),
				};
				let enqueue_held_htlc_available_res =
					self.flow.enqueue_held_htlc_available(invoice, reply_path);
				if enqueue_held_htlc_available_res.is_err() {
					self.abandon_payment_with_reason(
						payment_id,
						PaymentFailureReason::BlindedPathCreationFailed,
					);
					res = Err(Bolt12PaymentError::BlindedPathCreationFailed);
					return NotifyOption::DoPersist;
				};
			}

			NotifyOption::DoPersist
		});

		res
	}

	/// Returns a list of channels where our counterparty supports
	/// [`InitFeatures::supports_htlc_hold`], or an error if there are none or we are configured not
	/// to hold HTLCs at our next-hop channel counterparty. Useful for sending async payments to
	/// [`StaticInvoice`]s.
	fn hold_htlc_channels(&self) -> Result<Vec<ChannelDetails>, ()> {
		let should_send_async = self.config.read().unwrap().hold_outbound_htlcs_at_next_hop;
		if !should_send_async {
			return Err(());
		}

		let hold_htlc_channels =
			self.list_funded_channels_with_filter(|&(init_features, _, ref channel)| {
				init_features.supports_htlc_hold() && channel.context().is_live()
			});

		if hold_htlc_channels.is_empty() {
			Err(())
		} else {
			Ok(hold_htlc_channels)
		}
	}

	fn send_payment_for_static_invoice(
		&self, payment_id: PaymentId,
	) -> Result<(), Bolt12PaymentError> {
		let mut res = Ok(());
		let first_hops = self.list_usable_channels();
		PersistenceNotifierGuard::optionally_notify(self, || {
			let outbound_pmts_res =
				self.send_payment_for_static_invoice_no_persist(payment_id, first_hops, false);
			match outbound_pmts_res {
				Err(Bolt12PaymentError::UnexpectedInvoice)
				| Err(Bolt12PaymentError::DuplicateInvoice) => {
					res = outbound_pmts_res.map(|_| ());
					NotifyOption::SkipPersistNoEvents
				},
				other_res => {
					res = other_res;
					NotifyOption::DoPersist
				},
			}
		});
		res
	}

	/// Useful if the caller is already triggering a persist of the `ChannelManager`.
	fn send_payment_for_static_invoice_no_persist(
		&self, payment_id: PaymentId, first_hops: Vec<ChannelDetails>, hold_htlcs_at_next_hop: bool,
	) -> Result<(), Bolt12PaymentError> {
		let best_block_height = self.best_block.read().unwrap().height;
		self.pending_outbound_payments.send_payment_for_static_invoice(
			payment_id,
			hold_htlcs_at_next_hop,
			&self.router,
			first_hops,
			|| self.compute_inflight_htlcs(),
			&self.entropy_source,
			&self.node_signer,
			&self,
			&self.secp_ctx,
			best_block_height,
			&self.pending_events,
			|args| self.send_payment_along_path(args),
			&WithContext::for_payment(&self.logger, None, None, None, payment_id),
		)
	}

	/// If we are holding an HTLC on behalf of an often-offline sender, this method allows us to
	/// create a path for the sender to use as the reply path when they send the recipient a
	/// [`HeldHtlcAvailable`] onion message, so the recipient's [`ReleaseHeldHtlc`] response will be
	/// received to our node.
	fn path_for_release_held_htlc(
		&self, htlc_id: u64, prev_outbound_scid_alias: u64, channel_id: &ChannelId,
		counterparty_node_id: &PublicKey,
	) -> BlindedMessagePath {
		let intercept_id =
			InterceptId::from_htlc_id_and_chan_id(htlc_id, channel_id, counterparty_node_id);
		self.flow.path_for_release_held_htlc(
			intercept_id,
			prev_outbound_scid_alias,
			htlc_id,
			&self.entropy_source,
		)
	}

	/// Signals that no further attempts for the given payment should occur. Useful if you have a
	/// pending outbound payment with retries remaining, but wish to stop retrying the payment before
	/// retries are exhausted.
	///
	/// # Event Generation
	///
	/// If no [`Event::PaymentFailed`] event had been generated before, one will be generated as soon
	/// as there are no remaining pending HTLCs for this payment.
	///
	/// Note that calling this method does *not* prevent a payment from succeeding. You must still
	/// wait until you receive either a [`Event::PaymentFailed`] or [`Event::PaymentSent`] event to
	/// determine the ultimate status of a payment.
	///
	/// # Requested Invoices
	///
	/// In the case of paying a [`Bolt12Invoice`] via [`ChannelManager::pay_for_offer`], abandoning
	/// the payment prior to receiving the invoice will result in an [`Event::PaymentFailed`] and
	/// prevent any attempts at paying it once received.
	///
	/// # Restart Behavior
	///
	/// If an [`Event::PaymentFailed`] is generated and we restart without first persisting the
	/// [`ChannelManager`], another [`Event::PaymentFailed`] may be generated.
	///
	/// [`Bolt12Invoice`]: crate::offers::invoice::Bolt12Invoice
	pub fn abandon_payment(&self, payment_id: PaymentId) {
		self.abandon_payment_with_reason(payment_id, PaymentFailureReason::UserAbandoned)
	}

	fn abandon_payment_with_reason(&self, payment_id: PaymentId, reason: PaymentFailureReason) {
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(self);
		self.pending_outbound_payments.abandon_payment(payment_id, reason, &self.pending_events);
	}

	/// Send a spontaneous payment, which is a payment that does not require the recipient to have
	/// generated an invoice. Optionally, you may specify the preimage. If you do choose to specify
	/// the preimage, it must be a cryptographically secure random value that no intermediate node
	/// would be able to guess -- otherwise, an intermediate node may claim the payment and it will
	/// never reach the recipient.
	///
	/// Similar to regular payments, you MUST NOT reuse a `payment_preimage` value. See
	/// [`send_payment`] for more information about the risks of duplicate preimage usage.
	///
	/// See [`send_payment`] documentation for more details on the idempotency guarantees provided by
	/// the [`PaymentId`] key.
	///
	/// See [`PaymentParameters::for_keysend`] for help in constructing `route_params` for spontaneous
	/// payments.
	///
	/// [`send_payment`]: Self::send_payment
	/// [`PaymentParameters::for_keysend`]: crate::routing::router::PaymentParameters::for_keysend
	pub fn send_spontaneous_payment(
		&self, payment_preimage: Option<PaymentPreimage>, recipient_onion: RecipientOnionFields,
		payment_id: PaymentId, route_params: RouteParameters, retry_strategy: Retry,
	) -> Result<PaymentHash, RetryableSendFailure> {
		let best_block_height = self.best_block.read().unwrap().height;
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(self);
		let payment_hash = payment_preimage.map(|preimage| preimage.into());
		self.pending_outbound_payments.send_spontaneous_payment(
			payment_preimage,
			recipient_onion,
			payment_id,
			retry_strategy,
			route_params,
			&self.router,
			self.list_usable_channels(),
			|| self.compute_inflight_htlcs(),
			&self.entropy_source,
			&self.node_signer,
			best_block_height,
			&self.pending_events,
			|args| self.send_payment_along_path(args),
			&WithContext::for_payment(&self.logger, None, None, payment_hash, payment_id),
		)
	}

	/// Send a payment that is probing the given route for liquidity. We calculate the
	/// [`PaymentHash`] of probes based on a static secret and a random [`PaymentId`], which allows
	/// us to easily discern them from real payments.
	pub fn send_probe(&self, path: Path) -> Result<(PaymentHash, PaymentId), ProbeSendFailure> {
		let best_block_height = self.best_block.read().unwrap().height;
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(self);
		self.pending_outbound_payments.send_probe(
			path,
			self.probing_cookie_secret,
			&self.entropy_source,
			&self.node_signer,
			best_block_height,
			|args| self.send_payment_along_path(args),
		)
	}

	/// Returns whether a payment with the given [`PaymentHash`] and [`PaymentId`] is, in fact, a
	/// payment probe.
	#[cfg(test)]
	pub(crate) fn payment_is_probe(
		&self, payment_hash: &PaymentHash, payment_id: &PaymentId,
	) -> bool {
		outbound_payment::payment_is_probe(payment_hash, payment_id, self.probing_cookie_secret)
	}

	/// Sends payment probes over all paths of a route that would be used to pay the given
	/// amount to the given `node_id`.
	///
	/// See [`ChannelManager::send_preflight_probes`] for more information.
	pub fn send_spontaneous_preflight_probes(
		&self, node_id: PublicKey, amount_msat: u64, final_cltv_expiry_delta: u32,
		liquidity_limit_multiplier: Option<u64>,
	) -> Result<Vec<(PaymentHash, PaymentId)>, ProbeSendFailure> {
		let payment_params = PaymentParameters::from_node_id(node_id, final_cltv_expiry_delta);

		let route_params =
			RouteParameters::from_payment_params_and_value(payment_params, amount_msat);

		self.send_preflight_probes(route_params, liquidity_limit_multiplier)
	}

	/// Sends payment probes over all paths of a route that would be used to pay a route found
	/// according to the given [`RouteParameters`].
	///
	/// This may be used to send "pre-flight" probes, i.e., to train our scorer before conducting
	/// the actual payment. Note this is only useful if there likely is sufficient time for the
	/// probe to settle before sending out the actual payment, e.g., when waiting for user
	/// confirmation in a wallet UI.
	///
	/// Otherwise, there is a chance the probe could take up some liquidity needed to complete the
	/// actual payment. Users should therefore be cautious and might avoid sending probes if
	/// liquidity is scarce and/or they don't expect the probe to return before they send the
	/// payment. To mitigate this issue, channels with available liquidity less than the required
	/// amount times the given `liquidity_limit_multiplier` won't be used to send pre-flight
	/// probes. If `None` is given as `liquidity_limit_multiplier`, it defaults to `3`.
	pub fn send_preflight_probes(
		&self, route_params: RouteParameters, liquidity_limit_multiplier: Option<u64>,
	) -> Result<Vec<(PaymentHash, PaymentId)>, ProbeSendFailure> {
		let liquidity_limit_multiplier = liquidity_limit_multiplier.unwrap_or(3);

		let payer = self.get_our_node_id();
		let usable_channels = self.list_usable_channels();
		let first_hops = usable_channels.iter().collect::<Vec<_>>();
		let inflight_htlcs = self.compute_inflight_htlcs();

		let route = self
			.router
			.find_route(&payer, &route_params, Some(&first_hops), inflight_htlcs)
			.map_err(|e| {
				log_error!(self.logger, "Failed to find path for payment probe: {:?}", e);
				ProbeSendFailure::RouteNotFound
			})?;

		let mut used_liquidity_map = hash_map_with_capacity(first_hops.len());

		let mut res = Vec::new();

		for mut path in route.paths {
			// If the last hop is probably an unannounced channel we refrain from probing all the
			// way through to the end and instead probe up to the second-to-last channel.
			while let Some(last_path_hop) = path.hops.last() {
				if last_path_hop.maybe_announced_channel {
					// We found a potentially announced last hop.
					break;
				} else {
					// Drop the last hop, as it's likely unannounced.
					log_debug!(
						self.logger,
						"Avoided sending payment probe all the way to last hop {} as it is likely unannounced.",
						last_path_hop.short_channel_id
					);
					let final_value_msat = path.final_value_msat();
					path.hops.pop();
					if let Some(new_last) = path.hops.last_mut() {
						new_last.fee_msat += final_value_msat;
					}
				}
			}

			if path.hops.len() < 2 {
				log_debug!(
					self.logger,
					"Skipped sending payment probe over path with less than two hops."
				);
				continue;
			}

			if let Some(first_path_hop) = path.hops.first() {
				if let Some(first_hop) = first_hops.iter().find(|h| {
					h.get_outbound_payment_scid() == Some(first_path_hop.short_channel_id)
				}) {
					let path_value = path.final_value_msat() + path.fee_msat();
					let used_liquidity =
						used_liquidity_map.entry(first_path_hop.short_channel_id).or_insert(0);

					if first_hop.next_outbound_htlc_limit_msat
						< (*used_liquidity + path_value) * liquidity_limit_multiplier
					{
						log_debug!(self.logger, "Skipped sending payment probe to avoid putting channel {} under the liquidity limit.", first_path_hop.short_channel_id);
						continue;
					} else {
						*used_liquidity += path_value;
					}
				}
			}

			res.push(self.send_probe(path).map_err(|e| {
				log_error!(self.logger, "Failed to send pre-flight probe: {:?}", e);
				e
			})?);
		}

		Ok(res)
	}

	/// Handles the generation of a funding transaction, optionally (for tests) with a function
	/// which checks the correctness of the funding transaction given the associated channel.
	#[rustfmt::skip]
	fn funding_transaction_generated_intern<FundingOutput: FnMut(&OutboundV1Channel<SP>) -> Result<OutPoint, &'static str>>(
			&self, temporary_channel_id: ChannelId, counterparty_node_id: PublicKey, funding_transaction: Transaction, is_batch_funding: bool,
			mut find_funding_output: FundingOutput, is_manual_broadcast: bool,
		) -> Result<(), APIError> {
		let per_peer_state = self.per_peer_state.read().unwrap();
		let peer_state_mutex = per_peer_state.get(&counterparty_node_id)
			.ok_or_else(|| APIError::no_such_peer(&counterparty_node_id))?;

		let mut peer_state_lock = peer_state_mutex.lock().unwrap();
		let peer_state = &mut *peer_state_lock;

		macro_rules! abandon_chan { ($err: expr, $api_err: expr, $chan: expr) => { {
			let counterparty;
			let err = if let ChannelError::Close((msg, reason)) = $err {
				let channel_id = $chan.context.channel_id();
				counterparty = $chan.context.get_counterparty_node_id();
				let shutdown_res = $chan.abandon_unfunded_chan(reason);
				MsgHandleErrInternal::from_finish_shutdown(msg, channel_id, shutdown_res, None)
			} else { unreachable!(); };

			mem::drop(peer_state_lock);
			mem::drop(per_peer_state);
			let _: Result<(), _> = self.handle_error(Err(err), counterparty);
			Err($api_err)
		} } }

		let mut chan = match peer_state.channel_by_id.entry(temporary_channel_id) {
			hash_map::Entry::Occupied(chan) => {
				if !chan.get().ready_to_fund() {
					return Err(APIError::APIMisuseError {
						err: format!("Channel {temporary_channel_id} with counterparty {counterparty_node_id} is not an unfunded, outbound channel ready to fund"),
					});
				}
				match chan.remove().into_unfunded_outbound_v1() {
					Ok(chan) => chan,
					Err(chan) => {
						debug_assert!(false, "ready_to_fund guarantees into_unfunded_outbound_v1 will succeed");
						peer_state.channel_by_id.insert(temporary_channel_id, chan);
						return Err(APIError::APIMisuseError {
							err: "Invalid state, please report this bug".to_owned(),
						});
					},
				}
			},
			hash_map::Entry::Vacant(_) => {
				return Err(APIError::ChannelUnavailable {
					err: format!("Channel {temporary_channel_id} with counterparty {counterparty_node_id} not found"),
				});
			},
		};

		let funding_txo = match find_funding_output(&chan) {
			Ok(found_funding_txo) => found_funding_txo,
			Err(err) => {
				let chan_err = ChannelError::close(err.to_owned());
				let api_err = APIError::APIMisuseError { err: err.to_owned() };
				return abandon_chan!(chan_err, api_err, chan);
			},
		};

		let logger = WithChannelContext::from(&self.logger, &chan.context, None);
		let funding_res = chan.get_funding_created(funding_transaction, funding_txo, is_batch_funding, &&logger);
		let (mut chan, msg_opt) = match funding_res {
			Ok(funding_msg) => (chan, funding_msg),
			Err((mut chan, chan_err)) => {
				let api_err = APIError::ChannelUnavailable { err: "Signer refused to sign the initial commitment transaction".to_owned() };
				return abandon_chan!(chan_err, api_err, chan);
			}
		};

		match peer_state.channel_by_id.entry(chan.context.channel_id()) {
			hash_map::Entry::Occupied(_) => {
				// We need to `unset_funding_info` to make sure we don't close the already open
				// channel and instead close the one pending.
				let err = format!(
					"An existing channel using ID {} is open with peer {}",
					chan.context.channel_id(), chan.context.get_counterparty_node_id(),
				);
				let chan_err = ChannelError::close(err.to_owned());
				let api_err = APIError::APIMisuseError { err: err.to_owned() };
				chan.unset_funding_info();
				return abandon_chan!(chan_err, api_err, chan);
			},
			hash_map::Entry::Vacant(e) => {
				if let Some(msg) = msg_opt {
					peer_state.pending_msg_events.push(MessageSendEvent::SendFundingCreated {
						node_id: chan.context.get_counterparty_node_id(),
						msg,
					});
				}
				if is_manual_broadcast {
					chan.context.set_manual_broadcast();
				}

				e.insert(Channel::from(chan));
				Ok(())
			}
		}
	}

	#[cfg(any(test, feature = "_externalize_tests"))]
	pub(crate) fn funding_transaction_generated_unchecked(
		&self, temporary_channel_id: ChannelId, counterparty_node_id: PublicKey,
		funding_transaction: Transaction, output_index: u16,
	) -> Result<(), APIError> {
		let txid = funding_transaction.compute_txid();
		self.funding_transaction_generated_intern(
			temporary_channel_id,
			counterparty_node_id,
			funding_transaction,
			false,
			|_| Ok(OutPoint { txid, index: output_index }),
			false,
		)
	}

	/// Call this upon creation of a funding transaction for the given channel.
	///
	/// Returns an [`APIError::APIMisuseError`] if the funding_transaction spent non-SegWit outputs
	/// or if no output was found which matches the parameters in [`Event::FundingGenerationReady`].
	///
	/// Returns [`APIError::APIMisuseError`] if the funding transaction is not final for propagation
	/// across the p2p network.
	///
	/// Returns [`APIError::ChannelUnavailable`] if a funding transaction has already been provided
	/// for the channel or if the channel has been closed as indicated by [`Event::ChannelClosed`].
	///
	/// May panic if the output found in the funding transaction is duplicative with some other
	/// channel (note that this should be trivially prevented by using unique funding transaction
	/// keys per-channel).
	///
	/// Do NOT broadcast the funding transaction yourself. When we have safely received our
	/// counterparty's signature the funding transaction will automatically be broadcast via the
	/// [`BroadcasterInterface`] provided when this `ChannelManager` was constructed.
	///
	/// Note that this includes RBF or similar transaction replacement strategies - lightning does
	/// not currently support replacing a funding transaction on an existing channel. Instead,
	/// create a new channel with a conflicting funding transaction.
	///
	/// Note to keep the miner incentives aligned in moving the blockchain forward, we recommend
	/// the wallet software generating the funding transaction to apply anti-fee sniping as
	/// implemented by Bitcoin Core wallet. See <https://bitcoinops.org/en/topics/fee-sniping/>
	/// for more details.
	///
	/// [`Event::FundingGenerationReady`]: crate::events::Event::FundingGenerationReady
	/// [`Event::ChannelClosed`]: crate::events::Event::ChannelClosed
	pub fn funding_transaction_generated(
		&self, temporary_channel_id: ChannelId, counterparty_node_id: PublicKey,
		funding_transaction: Transaction,
	) -> Result<(), APIError> {
		let temporary_chan = &[(&temporary_channel_id, &counterparty_node_id)];
		self.batch_funding_transaction_generated(temporary_chan, funding_transaction)
	}

	/// **Unsafe**: This method does not validate the spent output. It is the caller's
	/// responsibility to ensure the spent outputs are SegWit, as well as making sure the funding
	/// transaction has a final absolute locktime, i.e., its locktime is lower than the next block height.
	///
	/// For a safer method, please refer to [`ChannelManager::funding_transaction_generated`].
	///
	/// Call this in response to a [`Event::FundingGenerationReady`] event.
	///
	/// Note that if this method is called successfully, the funding transaction won't be
	/// broadcasted and you are expected to broadcast it manually when receiving the
	/// [`Event::FundingTxBroadcastSafe`] event.
	///
	/// Returns [`APIError::ChannelUnavailable`] if a funding transaction has already been provided
	/// for the channel or if the channel has been closed as indicated by [`Event::ChannelClosed`].
	///
	/// May panic if the funding output is duplicative with some other channel (note that this
	/// should be trivially prevented by using unique funding transaction keys per-channel).
	///
	/// Note to keep the miner incentives aligned in moving the blockchain forward, we recommend
	/// the wallet software generating the funding transaction to apply anti-fee sniping as
	/// implemented by Bitcoin Core wallet. See <https://bitcoinops.org/en/topics/fee-sniping/> for
	/// more details.
	///
	/// [`Event::FundingGenerationReady`]: crate::events::Event::FundingGenerationReady
	/// [`Event::FundingTxBroadcastSafe`]: crate::events::Event::FundingTxBroadcastSafe
	/// [`Event::ChannelClosed`]: crate::events::Event::ChannelClosed
	/// [`ChannelManager::funding_transaction_generated`]: crate::ln::channelmanager::ChannelManager::funding_transaction_generated
	pub fn unsafe_manual_funding_transaction_generated(
		&self, temporary_channel_id: ChannelId, counterparty_node_id: PublicKey, funding: OutPoint,
	) -> Result<(), APIError> {
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(self);

		let temporary_chans = &[(&temporary_channel_id, &counterparty_node_id)];
		let funding_type = FundingType::Unchecked(funding);
		self.batch_funding_transaction_generated_intern(temporary_chans, funding_type)
	}

	/// Call this upon creation of a funding transaction for the given channel.
	///
	/// This method executes the same checks as [`ChannelManager::funding_transaction_generated`],
	/// but it does not automatically broadcast the funding transaction.
	///
	/// Call this in response to a [`Event::FundingGenerationReady`] event, only in a context where you want to manually
	/// control the broadcast of the funding transaction.
	///
	/// The associated [`ChannelMonitor`] likewise avoids broadcasting holder commitment or CPFP
	/// transactions until the funding has been observed on chain. This
	/// prevents attempting to broadcast unconfirmable commitment transactions before the channel's
	/// funding exists in a block.
	///
	/// If HTLCs would otherwise approach timeout while the funding transaction has not yet appeared
	/// on chain, the monitor avoids broadcasting force-close transactions in manual-broadcast
	/// mode until the funding is seen. It may still close the channel off-chain (emitting a
	/// `ChannelClosed` event) to avoid accepting further updates. Ensure your application either
	/// broadcasts the funding transaction in a timely manner or avoids forwarding HTLCs that could
	/// approach timeout during this interim state.
	///
	/// See also [`ChannelMonitor::broadcast_latest_holder_commitment_txn`]. For channels using
	/// manual-broadcast, calling that method has no effect until the funding has been observed
	/// on-chain.
	///
	/// [`ChannelManager::funding_transaction_generated`]: crate::ln::channelmanager::ChannelManager::funding_transaction_generated
	/// [`Event::FundingGenerationReady`]: crate::events::Event::FundingGenerationReady
	pub fn funding_transaction_generated_manual_broadcast(
		&self, temporary_channel_id: ChannelId, counterparty_node_id: PublicKey,
		funding_transaction: Transaction,
	) -> Result<(), APIError> {
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(self);
		self.batch_funding_transaction_generated_intern(
			&[(&temporary_channel_id, &counterparty_node_id)],
			FundingType::CheckedManualBroadcast(funding_transaction),
		)
	}

	/// Call this upon creation of a batch funding transaction for the given channels.
	///
	/// Return values are identical to [`Self::funding_transaction_generated`], respective to
	/// each individual channel and transaction output.
	///
	/// Do NOT broadcast the funding transaction yourself. This batch funding transaction
	/// will only be broadcast when we have safely received and persisted the counterparty's
	/// signature for each channel.
	///
	/// If there is an error, all channels in the batch are to be considered closed.
	pub fn batch_funding_transaction_generated(
		&self, temporary_channels: &[(&ChannelId, &PublicKey)], funding_transaction: Transaction,
	) -> Result<(), APIError> {
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(self);
		let funding_type = FundingType::Checked(funding_transaction);
		self.batch_funding_transaction_generated_intern(temporary_channels, funding_type)
	}

	fn batch_funding_transaction_generated_intern(
		&self, temporary_channels: &[(&ChannelId, &PublicKey)], funding: FundingType,
	) -> Result<(), APIError> {
		let mut result = Ok(());
		if let FundingType::Checked(funding_transaction)
		| FundingType::CheckedManualBroadcast(funding_transaction) = &funding
		{
			if !funding_transaction.is_coinbase() {
				for inp in funding_transaction.input.iter() {
					if inp.witness.is_empty() {
						result = result.and(Err(APIError::APIMisuseError {
							err:
								"Funding transaction must be fully signed and spend Segwit outputs"
									.to_owned(),
						}));
					}
				}
			}

			if funding_transaction.output.len() > u16::max_value() as usize {
				result = result.and(Err(APIError::APIMisuseError {
					err: "Transaction had more than 2^16 outputs, which is not supported"
						.to_owned(),
				}));
			}
			let height = self.best_block.read().unwrap().height;
			// Transactions are evaluated as final by network mempools if their locktime is strictly
			// lower than the next block height. However, the modules constituting our Lightning
			// node might not have perfect sync about their blockchain views. Thus, if the wallet
			// module is ahead of LDK, only allow one more block of headroom.
			if !funding_transaction.input.iter().all(|input| input.sequence == Sequence::MAX)
				&& funding_transaction.lock_time.is_block_height()
				&& funding_transaction.lock_time.to_consensus_u32() > height + 1
			{
				result = result.and(Err(APIError::APIMisuseError {
					err: "Funding transaction absolute timelock is non-final".to_owned(),
				}));
			}
		}

		let txid = funding.txid();
		let is_batch_funding = temporary_channels.len() > 1;
		let mut funding_batch_states =
			if is_batch_funding { Some(self.funding_batch_states.lock().unwrap()) } else { None };
		let mut funding_batch_state = funding_batch_states.as_mut().and_then(|states| match states
			.entry(txid)
		{
			btree_map::Entry::Occupied(_) => {
				result = result.clone().and(Err(APIError::APIMisuseError {
					err: "Batch funding transaction with the same txid already exists".to_owned(),
				}));
				None
			},
			btree_map::Entry::Vacant(vacant) => Some(vacant.insert(Vec::new())),
		});
		let is_manual_broadcast = funding.is_manual_broadcast();
		for &(temporary_channel_id, counterparty_node_id) in temporary_channels {
			result = result.and_then(|_| {
				self.funding_transaction_generated_intern(
					*temporary_channel_id,
					*counterparty_node_id,
					funding.transaction_or_dummy(),
					is_batch_funding,
					|chan| {
						let mut output_index = None;
						let expected_spk = chan.funding.get_funding_redeemscript().to_p2wsh();
						let outpoint = match &funding {
							FundingType::Checked(tx) | FundingType::CheckedManualBroadcast(tx) => {
								for (idx, outp) in tx.output.iter().enumerate() {
									if outp.script_pubkey == expected_spk
										&& outp.value.to_sat() == chan.funding.get_value_satoshis()
									{
										if output_index.is_some() {
											return Err("Multiple outputs matched the expected script and value");
										}
										output_index = Some(idx as u16);
									}
								}
								if output_index.is_none() {
									return Err("No output matched the script_pubkey and value in the FundingGenerationReady event");
								}
								OutPoint { txid, index: output_index.unwrap() }
							},
							FundingType::Unchecked(outpoint) => outpoint.clone(),
						};
						if let Some(funding_batch_state) = funding_batch_state.as_mut() {
							// TODO(dual_funding): We only do batch funding for V1 channels at the moment, but we'll probably
							// need to fix this somehow to not rely on using the outpoint for the channel ID if we
							// want to support V2 batching here as well.
							funding_batch_state.push((
								ChannelId::v1_from_funding_outpoint(outpoint),
								*counterparty_node_id,
								false,
							));
						}
						Ok(outpoint)
					},
					is_manual_broadcast,
				)
			});
		}
		if let Err(ref e) = result {
			// Remaining channels need to be removed on any error.
			let e = format!("Error in transaction funding: {:?}", e);
			let mut channels_to_remove = Vec::new();
			channels_to_remove.extend(
				funding_batch_states
					.as_mut()
					.and_then(|states| states.remove(&txid))
					.into_iter()
					.flatten()
					.map(|(chan_id, node_id, _state)| (chan_id, node_id)),
			);
			channels_to_remove
				.extend(temporary_channels.iter().map(|(&chan_id, &node_id)| (chan_id, node_id)));
			let mut shutdown_results: Vec<(Result<Infallible, _>, _)> = Vec::new();
			{
				let per_peer_state = self.per_peer_state.read().unwrap();
				for (channel_id, counterparty_node_id) in channels_to_remove {
					per_peer_state
						.get(&counterparty_node_id)
						.map(|peer_state_mutex| peer_state_mutex.lock().unwrap())
						.and_then(|mut peer_state| {
							peer_state
								.channel_by_id
								.remove(&channel_id)
								.map(|chan| (chan, peer_state))
						})
						.map(|(mut chan, mut peer_state_lock)| {
							let reason = ClosureReason::ProcessingError { err: e.clone() };
							let err = ChannelError::Close((e.clone(), reason));
							let peer_state = &mut *peer_state_lock;
							let (_, e) = self.locked_handle_force_close(
								&mut peer_state.closed_channel_monitor_update_ids,
								&mut peer_state.in_flight_monitor_updates,
								err,
								&mut chan,
							);
							shutdown_results.push((Err(e), counterparty_node_id));
						});
				}
			}
			mem::drop(funding_batch_states);
			for (err, counterparty_node_id) in shutdown_results {
				let _ = self.handle_error(err, counterparty_node_id);
			}
		}
		result
	}

	/// Adds or removes funds from the given channel as specified by a [`FundingContribution`].
	///
	/// Used after [`ChannelManager::splice_channel`] by constructing a [`FundingContribution`]
	/// from the returned [`FundingTemplate`] and passing it here.
	///
	/// Calling this method will commence the process of creating a new funding transaction for the
	/// channel. An [`Event::FundingTransactionReadyForSigning`] will be generated once the
	/// transaction is successfully constructed interactively with the counterparty.
	/// If unsuccessful, an [`Event::SpliceFailed`] will be surfaced instead.
	///
	/// An optional `locktime` for the funding transaction may be specified. If not given, the
	/// current best block height is used.
	///
	/// Returns [`ChannelUnavailable`] when a channel is not found or an incorrect
	/// `counterparty_node_id` is provided.
	///
	/// Returns [`APIMisuseError`] when a channel is not in a state where it is expecting funding
	/// contribution.
	///
	/// [`ChannelUnavailable`]: APIError::ChannelUnavailable
	/// [`APIMisuseError`]: APIError::APIMisuseError
	pub fn funding_contributed(
		&self, channel_id: &ChannelId, counterparty_node_id: &PublicKey,
		contribution: FundingContribution, locktime: Option<u32>,
	) -> Result<(), APIError> {
		let mut result = Ok(());
		PersistenceNotifierGuard::optionally_notify(self, || {
			let per_peer_state = self.per_peer_state.read().unwrap();
			let peer_state_mutex_opt = per_peer_state.get(counterparty_node_id);
			if peer_state_mutex_opt.is_none() {
				result = Err(APIError::ChannelUnavailable {
					err: format!("Can't find a peer matching the passed counterparty node_id {counterparty_node_id}")
				});
				return NotifyOption::SkipPersistNoEvents;
			}

			let mut peer_state = peer_state_mutex_opt.unwrap().lock().unwrap();

			match peer_state.channel_by_id.get_mut(channel_id) {
				Some(channel) => match channel.as_funded_mut() {
					Some(chan) => {
						let locktime = bitcoin::absolute::LockTime::from_consensus(
							locktime.unwrap_or_else(|| self.current_best_block().height),
						);
						let logger = WithChannelContext::from(&self.logger, chan.context(), None);
						match chan.funding_contributed(contribution, locktime, &&logger) {
							Ok(msg_opt) => {
								if let Some(msg) = msg_opt {
									peer_state.pending_msg_events.push(
										MessageSendEvent::SendStfu {
											node_id: *counterparty_node_id,
											msg,
										},
									);
								}
							},
							Err(splice_funding_failed) => {
								let pending_events = &mut self.pending_events.lock().unwrap();
								pending_events.push_back((
									events::Event::SpliceFailed {
										channel_id: *channel_id,
										counterparty_node_id: *counterparty_node_id,
										user_channel_id: channel.context().get_user_id(),
										abandoned_funding_txo: splice_funding_failed.funding_txo,
										channel_type: splice_funding_failed.channel_type.clone(),
										contributed_inputs: splice_funding_failed
											.contributed_inputs,
										contributed_outputs: splice_funding_failed
											.contributed_outputs,
									},
									None,
								));
							},
						}

						return NotifyOption::DoPersist;
					},
					None => {
						result = Err(APIError::APIMisuseError {
							err: format!(
								"Channel with id {} not expecting funding contribution",
								channel_id
							),
						});
						return NotifyOption::SkipPersistNoEvents;
					},
				},
				None => {
					result = Err(APIError::ChannelUnavailable {
						err: format!(
							"Channel with id {} not found for the passed counterparty node_id {}",
							channel_id, counterparty_node_id
						),
					});
					return NotifyOption::SkipPersistNoEvents;
				},
			}
		});

		result
	}

	/// Handles a signed funding transaction generated by interactive transaction construction and
	/// provided by the client. Should only be called in response to a [`FundingTransactionReadyForSigning`]
	/// event.
	///
	/// Do NOT broadcast the funding transaction yourself. When we have safely received our
	/// counterparty's signature(s) the funding transaction will automatically be broadcast via the
	/// [`BroadcasterInterface`] provided when this `ChannelManager` was constructed.
	///
	/// `SIGHASH_ALL` MUST be used for all signatures when providing signatures, otherwise your
	/// funds can be held hostage!
	///
	/// LDK checks the following:
	///  * Each input spends an output that is one of P2WPKH, P2WSH, or P2TR.
	///    These were already checked by LDK when the inputs to be contributed were provided.
	///  * All signatures use the `SIGHASH_ALL` sighash type.
	///  * P2WPKH and P2TR key path spends are valid (verifies signatures)
	///
	/// NOTE:
	///  * When checking P2WSH spends, LDK tries to decode 70-72 byte witness elements as ECDSA
	///    signatures with a sighash flag. If the internal DER-decoding fails, then LDK just
	///    assumes it wasn't a signature and carries with checks. If the element can be decoded
	///    as an ECDSA signature, the the sighash flag must be `SIGHASH_ALL`.
	///  * When checking P2TR script-path spends, LDK assumes all elements of exactly 65 bytes
	///    with the last byte matching any valid sighash flag byte are schnorr signatures and checks
	///    that the sighash type is `SIGHASH_ALL`. If the last byte is not any valid sighash flag, the
	///    element is assumed not to be a signature and is ignored. Elements of 64 bytes are not
	///    checked because if they were schnorr signatures then they would implicitly be `SIGHASH_DEFAULT`
	///    which is an alias of `SIGHASH_ALL`.
	///
	/// Returns [`ChannelUnavailable`] when a channel is not found or an incorrect
	/// `counterparty_node_id` is provided.
	///
	/// Returns [`APIMisuseError`] when a channel is not in a state where it is expecting funding
	/// signatures or if any of the checks described above fail.
	///
	/// [`FundingTransactionReadyForSigning`]: events::Event::FundingTransactionReadyForSigning
	/// [`ChannelUnavailable`]: APIError::ChannelUnavailable
	/// [`APIMisuseError`]: APIError::APIMisuseError
	pub fn funding_transaction_signed(
		&self, channel_id: &ChannelId, counterparty_node_id: &PublicKey, transaction: Transaction,
	) -> Result<(), APIError> {
		let mut funding_tx_signed_result = Ok(());
		let mut monitor_update_result: Option<
			Result<PostMonitorUpdateChanResume, MsgHandleErrInternal>,
		> = None;

		PersistenceNotifierGuard::optionally_notify(self, || {
			let per_peer_state = self.per_peer_state.read().unwrap();
			let peer_state_mutex_opt = per_peer_state.get(counterparty_node_id);
			if peer_state_mutex_opt.is_none() {
				funding_tx_signed_result = Err(APIError::no_such_peer(counterparty_node_id));
				return NotifyOption::SkipPersistNoEvents;
			}

			let mut peer_state_lock = peer_state_mutex_opt.unwrap().lock().unwrap();
			let peer_state = &mut *peer_state_lock;

			match peer_state.channel_by_id.entry(*channel_id) {
				hash_map::Entry::Occupied(mut chan_entry) => {
					let txid = transaction.compute_txid();
					let witnesses: Vec<_> = transaction
						.input
						.into_iter()
						.map(|input| input.witness)
						.filter(|witness| !witness.is_empty())
						.collect();
					let best_block_height = self.best_block.read().unwrap().height;

					let chan = chan_entry.get_mut();
					match chan.funding_transaction_signed(
						txid,
						witnesses,
						best_block_height,
						&self.fee_estimator,
						&self.logger,
					) {
						Ok(FundingTxSigned {
							commitment_signed,
							counterparty_initial_commitment_signed_result,
							tx_signatures,
							funding_tx,
							splice_negotiated,
							splice_locked,
						}) => {
							if let Some((funding_tx, tx_type)) = funding_tx {
								let funded_chan = chan.as_funded_mut().expect(
									"Funding transactions ready for broadcast can only exist for funded channels",
								);
								self.broadcast_interactive_funding(
									funded_chan,
									&funding_tx,
									Some(tx_type),
									&self.logger,
								);
							}
							if let Some(splice_negotiated) = splice_negotiated {
								self.pending_events.lock().unwrap().push_back((
									events::Event::SplicePending {
										channel_id: *channel_id,
										counterparty_node_id: *counterparty_node_id,
										user_channel_id: chan.context().get_user_id(),
										new_funding_txo: splice_negotiated.funding_txo,
										channel_type: splice_negotiated.channel_type,
										new_funding_redeem_script: splice_negotiated
											.funding_redeem_script,
									},
									None,
								));
							}

							if chan.context().is_connected() {
								if let Some(commitment_signed) = commitment_signed {
									peer_state.pending_msg_events.push(
										MessageSendEvent::UpdateHTLCs {
											node_id: *counterparty_node_id,
											channel_id: *channel_id,
											updates: CommitmentUpdate {
												commitment_signed: vec![commitment_signed],
												update_add_htlcs: vec![],
												update_fulfill_htlcs: vec![],
												update_fail_htlcs: vec![],
												update_fail_malformed_htlcs: vec![],
												update_fee: None,
											},
										},
									);
								}
								if let Some(tx_signatures) = tx_signatures {
									peer_state.pending_msg_events.push(
										MessageSendEvent::SendTxSignatures {
											node_id: *counterparty_node_id,
											msg: tx_signatures,
										},
									);
								}
								if let Some(splice_locked) = splice_locked {
									peer_state.pending_msg_events.push(
										MessageSendEvent::SendSpliceLocked {
											node_id: *counterparty_node_id,
											msg: splice_locked,
										},
									);
								}
							}

							if let Some(funded_chan) = chan.as_funded_mut() {
								match counterparty_initial_commitment_signed_result {
									Some(Ok(Some(monitor_update))) => {
										let funding_txo = funded_chan.funding.get_funding_txo();
										if let Some(post_update_data) = self
											.handle_new_monitor_update(
												&mut peer_state.in_flight_monitor_updates,
												&mut peer_state.monitor_update_blocked_actions,
												&mut peer_state.pending_msg_events,
												peer_state.is_connected,
												funded_chan,
												funding_txo.unwrap(),
												monitor_update,
											) {
											monitor_update_result = Some(Ok(post_update_data));
										}
									},
									Some(Err(err)) => {
										let (drop, err) = self.locked_handle_funded_force_close(
											&mut peer_state.closed_channel_monitor_update_ids,
											&mut peer_state.in_flight_monitor_updates,
											err,
											funded_chan,
										);
										if drop {
											chan_entry.remove_entry();
										}

										monitor_update_result = Some(Err(err));
									},
									Some(Ok(None)) | None => {},
								}
							}

							funding_tx_signed_result = Ok(());
						},
						Err(err) => {
							funding_tx_signed_result = Err(err);
							return NotifyOption::SkipPersistNoEvents;
						},
					}
				},
				hash_map::Entry::Vacant(_) => {
					funding_tx_signed_result =
						Err(APIError::no_such_channel_for_peer(channel_id, counterparty_node_id));
					return NotifyOption::SkipPersistNoEvents;
				},
			}

			mem::drop(peer_state_lock);
			mem::drop(per_peer_state);

			if let Some(monitor_update_result) = monitor_update_result {
				match monitor_update_result {
					Ok(post_update_data) => {
						self.handle_post_monitor_update_chan_resume(post_update_data);
					},
					Err(_) => {
						let _ = self.handle_error(monitor_update_result, *counterparty_node_id);
					},
				}
			}

			NotifyOption::DoPersist
		});

		funding_tx_signed_result
	}

	fn broadcast_interactive_funding(
		&self, channel: &mut FundedChannel<SP>, funding_tx: &Transaction,
		transaction_type: Option<TransactionType>, logger: &L,
	) {
		let logger = WithChannelContext::from(logger, channel.context(), None);
		log_info!(
			logger,
			"Broadcasting signed interactive funding transaction {}",
			funding_tx.compute_txid()
		);
		let tx_type = transaction_type.unwrap_or_else(|| TransactionType::Funding {
			channels: vec![(
				channel.context().get_counterparty_node_id(),
				channel.context().channel_id(),
			)],
		});
		self.tx_broadcaster.broadcast_transactions(&[(funding_tx, tx_type)]);
		{
			let mut pending_events = self.pending_events.lock().unwrap();
			emit_channel_pending_event!(pending_events, channel);
		}
	}

	/// Atomically applies partial updates to the [`ChannelConfig`] of the given channels.
	///
	/// Once the updates are applied, each eligible channel (advertised with a known short channel
	/// ID and a change in [`forwarding_fee_proportional_millionths`], [`forwarding_fee_base_msat`],
	/// or [`cltv_expiry_delta`]) has a [`BroadcastChannelUpdate`] event message generated
	/// containing the new [`ChannelUpdate`] message which should be broadcast to the network.
	///
	/// Returns [`ChannelUnavailable`] when a channel is not found or an incorrect
	/// `counterparty_node_id` is provided.
	///
	/// Returns [`APIMisuseError`] when a [`cltv_expiry_delta`] update is to be applied with a value
	/// below [`MIN_CLTV_EXPIRY_DELTA`].
	///
	/// If an error is returned, none of the updates should be considered applied.
	///
	/// [`forwarding_fee_proportional_millionths`]: ChannelConfig::forwarding_fee_proportional_millionths
	/// [`forwarding_fee_base_msat`]: ChannelConfig::forwarding_fee_base_msat
	/// [`cltv_expiry_delta`]: ChannelConfig::cltv_expiry_delta
	/// [`BroadcastChannelUpdate`]: MessageSendEvent::BroadcastChannelUpdate
	/// [`ChannelUpdate`]: msgs::ChannelUpdate
	/// [`ChannelUnavailable`]: APIError::ChannelUnavailable
	/// [`APIMisuseError`]: APIError::APIMisuseError
	#[rustfmt::skip]
	pub fn update_partial_channel_config(
		&self, counterparty_node_id: &PublicKey, channel_ids: &[ChannelId], config_update: &ChannelConfigUpdate,
	) -> Result<(), APIError> {
		if config_update.cltv_expiry_delta.map(|delta| delta < MIN_CLTV_EXPIRY_DELTA).unwrap_or(false) {
			return Err(APIError::APIMisuseError {
				err: format!("The chosen CLTV expiry delta is below the minimum of {}", MIN_CLTV_EXPIRY_DELTA),
			});
		}

		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(self);
		let per_peer_state = self.per_peer_state.read().unwrap();
		let peer_state_mutex = per_peer_state.get(counterparty_node_id)
			.ok_or_else(|| APIError::no_such_peer(counterparty_node_id))?;
		let mut peer_state_lock = peer_state_mutex.lock().unwrap();
		let peer_state = &mut *peer_state_lock;

		for channel_id in channel_ids {
			if !peer_state.has_channel(channel_id) {
				return Err(APIError::no_such_channel_for_peer(
					channel_id,
					counterparty_node_id,
				));
			};
		}
		for channel_id in channel_ids {
			if let Some(channel) = peer_state.channel_by_id.get_mut(channel_id) {
				let mut config = channel.context().config();
				config.apply(config_update);
				if !channel.context_mut().update_config(&config) {
					continue;
				}
				if let Some(channel) = channel.as_funded() {
					if let Ok((msg, node_id_1, node_id_2)) = self.get_channel_update_for_broadcast(channel) {
						let mut pending_broadcast_messages = self.pending_broadcast_messages.lock().unwrap();
						pending_broadcast_messages.push(MessageSendEvent::BroadcastChannelUpdate { msg, node_id_1, node_id_2 });
					} else if peer_state.is_connected {
						if let Ok((msg, _, _)) = self.get_channel_update_for_unicast(channel) {
							peer_state.pending_msg_events.push(MessageSendEvent::SendChannelUpdate {
								node_id: channel.context.get_counterparty_node_id(),
								msg,
							});
						}
					}
				}
				continue;
			} else {
				// This should not be reachable as we've already checked for non-existence in the previous channel_id loop.
				debug_assert!(false);
				return Err(APIError::ChannelUnavailable {
					err: format!(
						"Channel with ID {} for passed counterparty_node_id {} disappeared after we confirmed its existence - this should not be reachable!",
						channel_id, counterparty_node_id),
				});
			};
		}
		Ok(())
	}

	/// Atomically updates the [`ChannelConfig`] for the given channels.
	///
	/// Once the updates are applied, each eligible channel (advertised with a known short channel
	/// ID and a change in [`forwarding_fee_proportional_millionths`], [`forwarding_fee_base_msat`],
	/// or [`cltv_expiry_delta`]) has a [`BroadcastChannelUpdate`] event message generated
	/// containing the new [`ChannelUpdate`] message which should be broadcast to the network.
	///
	/// Returns [`ChannelUnavailable`] when a channel is not found or an incorrect
	/// `counterparty_node_id` is provided.
	///
	/// Returns [`APIMisuseError`] when a [`cltv_expiry_delta`] update is to be applied with a value
	/// below [`MIN_CLTV_EXPIRY_DELTA`].
	///
	/// If an error is returned, none of the updates should be considered applied.
	///
	/// [`forwarding_fee_proportional_millionths`]: ChannelConfig::forwarding_fee_proportional_millionths
	/// [`forwarding_fee_base_msat`]: ChannelConfig::forwarding_fee_base_msat
	/// [`cltv_expiry_delta`]: ChannelConfig::cltv_expiry_delta
	/// [`BroadcastChannelUpdate`]: MessageSendEvent::BroadcastChannelUpdate
	/// [`ChannelUpdate`]: msgs::ChannelUpdate
	/// [`ChannelUnavailable`]: APIError::ChannelUnavailable
	/// [`APIMisuseError`]: APIError::APIMisuseError
	pub fn update_channel_config(
		&self, counterparty_node_id: &PublicKey, channel_ids: &[ChannelId], config: &ChannelConfig,
	) -> Result<(), APIError> {
		self.update_partial_channel_config(counterparty_node_id, channel_ids, &(*config).into())
	}

	/// Attempts to forward an intercepted HTLC over the provided channel id and with the provided
	/// amount to forward. Should only be called in response to an [`HTLCIntercepted`] event.
	///
	/// Intercepted HTLCs can be useful for Lightning Service Providers (LSPs) to open a just-in-time
	/// channel to a receiving node if the node lacks sufficient inbound liquidity.
	///
	/// To make use of intercepted HTLCs, set [`UserConfig::htlc_interception_flags`] must have a
	/// non-0 value.
	///
	/// Note that LDK does not enforce fee requirements in `amt_to_forward_msat`, and will not stop
	/// you from forwarding more than you received. See
	/// [`HTLCIntercepted::expected_outbound_amount_msat`] for more on forwarding a different amount
	/// than expected.
	///
	/// Errors if the event was not handled in time, in which case the HTLC was automatically failed
	/// backwards.
	///
	/// [`UserConfig::htlc_interception_flags`]: crate::util::config::UserConfig::htlc_interception_flags
	/// [`HTLCIntercepted`]: events::Event::HTLCIntercepted
	/// [`HTLCIntercepted::expected_outbound_amount_msat`]: events::Event::HTLCIntercepted::expected_outbound_amount_msat
	// TODO: when we move to deciding the best outbound channel at forward time, only take
	// `next_node_id` and not `next_hop_channel_id`
	pub fn forward_intercepted_htlc(
		&self, intercept_id: InterceptId, next_hop_channel_id: &ChannelId, next_node_id: PublicKey,
		amt_to_forward_msat: u64,
	) -> Result<(), APIError> {
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(self);

		let outbound_scid_alias = {
			let peer_state_lock = self.per_peer_state.read().unwrap();
			let peer_state_mutex = peer_state_lock
				.get(&next_node_id)
				.ok_or_else(|| APIError::no_such_peer(&next_node_id))?;
			let mut peer_state_lock = peer_state_mutex.lock().unwrap();
			let peer_state = &mut *peer_state_lock;
			match peer_state.channel_by_id.get(next_hop_channel_id) {
				Some(chan) => {
					if let Some(funded_chan) = chan.as_funded() {
						if !funded_chan.context.is_usable() {
							return Err(APIError::ChannelUnavailable {
								err: format!(
									"Channel with id {next_hop_channel_id} not fully established"
								),
							});
						}
						funded_chan.context.outbound_scid_alias()
					} else {
						return Err(APIError::ChannelUnavailable {
						err: format!(
							"Channel with id {next_hop_channel_id} for the passed counterparty node_id {next_node_id} is still opening."
						)
					});
					}
				},
				None => {
					let logger = WithContext::from(
						&self.logger,
						Some(next_node_id),
						Some(*next_hop_channel_id),
						None,
					);
					log_error!(
						logger,
						"Channel not found when attempting to forward intercepted HTLC"
					);
					return Err(APIError::no_such_channel_for_peer(
						next_hop_channel_id,
						&next_node_id,
					));
				},
			}
		};

		let payment = self
			.pending_intercepted_htlcs
			.lock()
			.unwrap()
			.remove(&intercept_id)
			.ok_or_else(|| APIError::APIMisuseError {
				err: format!("Payment with intercept id {} not found", log_bytes!(intercept_id.0)),
			})?;

		let routing = match payment.forward_info.routing {
			PendingHTLCRouting::Forward {
				onion_packet,
				blinded,
				incoming_cltv_expiry,
				hold_htlc,
				..
			} => {
				debug_assert!(hold_htlc.is_none(), "Held intercept HTLCs should not be surfaced in an event until the recipient comes online");
				PendingHTLCRouting::Forward {
					onion_packet,
					blinded,
					incoming_cltv_expiry,
					hold_htlc,
					short_channel_id: outbound_scid_alias,
				}
			},
			_ => unreachable!(), // Only `PendingHTLCRouting::Forward`s are intercepted
		};
		let skimmed_fee_msat =
			payment.forward_info.outgoing_amt_msat.saturating_sub(amt_to_forward_msat);
		let pending_htlc_info = PendingHTLCInfo {
			skimmed_fee_msat: if skimmed_fee_msat == 0 { None } else { Some(skimmed_fee_msat) },
			outgoing_amt_msat: amt_to_forward_msat,
			routing,
			..payment.forward_info
		};

		let forward = [PendingAddHTLCInfo {
			prev_outbound_scid_alias: payment.prev_outbound_scid_alias,
			prev_htlc_id: payment.prev_htlc_id,
			prev_counterparty_node_id: payment.prev_counterparty_node_id,
			prev_channel_id: payment.prev_channel_id,
			prev_funding_outpoint: payment.prev_funding_outpoint,
			prev_user_channel_id: payment.prev_user_channel_id,
			forward_info: pending_htlc_info,
		}];
		self.forward_htlcs(forward);
		Ok(())
	}

	/// Fails the intercepted HTLC indicated by intercept_id. Should only be called in response to
	/// an [`HTLCIntercepted`] event. See [`ChannelManager::forward_intercepted_htlc`].
	///
	/// Errors if the event was not handled in time, in which case the HTLC was automatically failed
	/// backwards.
	///
	/// [`HTLCIntercepted`]: events::Event::HTLCIntercepted
	#[rustfmt::skip]
	pub fn fail_intercepted_htlc(&self, intercept_id: InterceptId) -> Result<(), APIError> {
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(self);

		let payment = self.pending_intercepted_htlcs.lock().unwrap().remove(&intercept_id)
			.ok_or_else(|| APIError::APIMisuseError {
				err: format!("Payment with intercept id {} not found", log_bytes!(intercept_id.0))
			})?;

		if let PendingHTLCRouting::Forward { short_channel_id, .. } = payment.forward_info.routing {
			let htlc_source = HTLCSource::PreviousHopData(payment.htlc_previous_hop_data());
			let reason = HTLCFailReason::from_failure_code(LocalHTLCFailureReason::UnknownNextPeer);
			let destination = HTLCHandlingFailureType::InvalidForward { requested_forward_scid: short_channel_id };
			let hash = payment.forward_info.payment_hash;
			self.fail_htlc_backwards_internal(&htlc_source, &hash, &reason, destination, None);
		} else { unreachable!() } // Only `PendingHTLCRouting::Forward`s are intercepted

		Ok(())
	}

	#[cfg(any(test, feature = "_test_utils"))]
	/// Process any pending inbound [`msgs::UpdateAddHTLC`] messages, decoding the onion and placing
	/// the pending HTLC in `ChannelManager::forward_htlcs` or
	/// `ChannelManager::pending_intercepted_htlcs` as well as generating relevant [`Event`]s.
	pub fn test_process_pending_update_add_htlcs(&self) -> bool {
		self.process_pending_update_add_htlcs()
	}

	fn process_pending_update_add_htlcs(&self) -> bool {
		let mut should_persist = false;
		let mut decode_update_add_htlcs = new_hash_map();
		let mut dummy_update_add_htlcs = new_hash_map();
		mem::swap(&mut decode_update_add_htlcs, &mut self.decode_update_add_htlcs.lock().unwrap());

		let get_htlc_failure_type = |outgoing_scid_opt: Option<u64>, payment_hash: PaymentHash| {
			if let Some(outgoing_scid) = outgoing_scid_opt {
				match self.short_to_chan_info.read().unwrap().get(&outgoing_scid) {
					Some((outgoing_counterparty_node_id, outgoing_channel_id)) => {
						HTLCHandlingFailureType::Forward {
							node_id: Some(*outgoing_counterparty_node_id),
							channel_id: *outgoing_channel_id,
						}
					},
					None => HTLCHandlingFailureType::InvalidForward {
						requested_forward_scid: outgoing_scid,
					},
				}
			} else {
				HTLCHandlingFailureType::Receive { payment_hash }
			}
		};

		'outer_loop: for (incoming_scid_alias, update_add_htlcs) in decode_update_add_htlcs {
			// If any decoded update_add_htlcs were processed, we need to persist.
			should_persist = true;
			let (
				incoming_counterparty_node_id,
				incoming_channel_id,
				incoming_funding_txo,
				incoming_user_channel_id,
				incoming_accept_underpaying_htlcs,
				incoming_chan_is_public,
			) = match self.do_funded_channel_callback(
				incoming_scid_alias,
				|chan: &mut FundedChannel<SP>| {
					(
						chan.context.get_counterparty_node_id(),
						chan.context.channel_id(),
						chan.funding.get_funding_txo().unwrap(),
						chan.context.get_user_id(),
						chan.context.config().accept_underpaying_htlcs,
						chan.context.should_announce(),
					)
				},
			) {
				Some(incoming_channel_details) => incoming_channel_details,
				// The incoming channel no longer exists, HTLCs should be resolved onchain instead.
				None => continue,
			};

			let mut htlc_forwards = Vec::new();
			let mut htlc_fails = Vec::new();
			for update_add_htlc in &update_add_htlcs {
				let (next_hop, next_packet_details_opt) =
					match decode_incoming_update_add_htlc_onion(
						&update_add_htlc,
						&self.node_signer,
						&self.logger,
						&self.secp_ctx,
					) {
						Ok(decoded_onion) => match decoded_onion {
							(
								onion_utils::Hop::Dummy {
									dummy_hop_data,
									next_hop_hmac,
									new_packet_bytes,
									..
								},
								Some(next_packet_details),
							) => {
								let new_update_add_htlc =
									onion_utils::peel_dummy_hop_update_add_htlc(
										update_add_htlc,
										dummy_hop_data,
										next_hop_hmac,
										new_packet_bytes,
										next_packet_details,
										&self.node_signer,
										&self.secp_ctx,
									);

								dummy_update_add_htlcs
									.entry(incoming_scid_alias)
									.or_insert_with(Vec::new)
									.push(new_update_add_htlc);

								continue;
							},
							_ => decoded_onion,
						},

						Err((htlc_fail, reason)) => {
							let failure_type = HTLCHandlingFailureType::InvalidOnion;
							htlc_fails.push((htlc_fail, failure_type, reason.into()));
							continue;
						},
					};

				let is_intro_node_blinded_forward = next_hop.is_intro_node_blinded_forward();
				let outgoing_scid_opt =
					next_packet_details_opt.as_ref().and_then(|d| match d.outgoing_connector {
						HopConnector::ShortChannelId(scid) => Some(scid),
						HopConnector::Dummy => {
							debug_assert!(
								false,
								"Dummy hops must never be processed at this stage."
							);
							None
						},
						HopConnector::Trampoline(_) => None,
					});
				let shared_secret = next_hop.shared_secret().secret_bytes();

				macro_rules! fail_htlc_continue_to_next {
					($reason: expr) => {{
						let htlc_fail = self.htlc_failure_from_update_add_err(
							&update_add_htlc,
							&incoming_counterparty_node_id,
							$reason,
							is_intro_node_blinded_forward,
							&shared_secret,
						);
						let failure_type =
							get_htlc_failure_type(outgoing_scid_opt, update_add_htlc.payment_hash);
						htlc_fails.push((htlc_fail, failure_type, $reason.into()));
						continue;
					}};
				}

				// Nodes shouldn't expect us to hold HTLCs for them if we don't advertise htlc_hold feature
				// support.
				//
				// If we wanted to pretend to be a node that didn't understand the feature at all here, the
				// correct behavior would've been to disconnect the sender when we first received the
				// update_add message. However, this would make the `UserConfig::enable_htlc_hold` option
				// unsafe -- if our node switched the config option from on to off just after the sender
				// enqueued their update_add + CS, the sender would continue retransmitting those messages
				// and we would keep disconnecting them until the HTLC timed out.
				if update_add_htlc.hold_htlc.is_some()
					&& !BaseMessageHandler::provided_node_features(self).supports_htlc_hold()
				{
					fail_htlc_continue_to_next!(LocalHTLCFailureReason::TemporaryNodeFailure);
				}

				// Process the HTLC on the incoming channel.
				match self.do_funded_channel_callback(
					incoming_scid_alias,
					|chan: &mut FundedChannel<SP>| {
						let logger = WithChannelContext::from(
							&self.logger,
							&chan.context,
							Some(update_add_htlc.payment_hash),
						);
						chan.can_accept_incoming_htlc(&self.fee_estimator, &logger)
					},
				) {
					Some(Ok(_)) => {},
					Some(Err(reason)) => {
						fail_htlc_continue_to_next!(reason);
					},
					// The incoming channel no longer exists, HTLCs should be resolved onchain instead.
					None => continue 'outer_loop,
				}

				// Now process the HTLC on the outgoing channel if it's a forward.
				let mut intercept_forward = false;
				if let Some(next_packet_details) = next_packet_details_opt.as_ref() {
					match self.can_forward_htlc_should_intercept(
						&update_add_htlc,
						incoming_chan_is_public,
						next_packet_details,
					) {
						Err(reason) => {
							fail_htlc_continue_to_next!(reason);
						},
						Ok(intercept) => intercept_forward = intercept,
					}
				}

				match self.get_pending_htlc_info(
					&update_add_htlc,
					shared_secret,
					next_hop,
					incoming_accept_underpaying_htlcs,
					next_packet_details_opt.map(|d| d.next_packet_pubkey),
				) {
					Ok(info) => {
						let pending_add = PendingAddHTLCInfo {
							prev_outbound_scid_alias: incoming_scid_alias,
							prev_counterparty_node_id: incoming_counterparty_node_id,
							prev_funding_outpoint: incoming_funding_txo,
							prev_channel_id: incoming_channel_id,
							prev_htlc_id: update_add_htlc.htlc_id,
							prev_user_channel_id: incoming_user_channel_id,
							forward_info: info,
						};
						let intercept_id = || {
							InterceptId::from_htlc_id_and_chan_id(
								update_add_htlc.htlc_id,
								&incoming_channel_id,
								&incoming_counterparty_node_id,
							)
						};
						let logger = WithContext::from(
							&self.logger,
							None,
							Some(incoming_channel_id),
							Some(update_add_htlc.payment_hash),
						);
						if pending_add.forward_info.routing.should_hold_htlc() {
							let mut held_htlcs = self.pending_intercepted_htlcs.lock().unwrap();
							let intercept_id = intercept_id();
							match held_htlcs.entry(intercept_id) {
								hash_map::Entry::Vacant(entry) => {
									log_debug!(
										logger,
										"Intercepted held HTLC with id {intercept_id}, holding until the recipient is online"
									);
									entry.insert(pending_add);
								},
								hash_map::Entry::Occupied(_) => {
									debug_assert!(false, "Should never have two HTLCs with the same channel id and htlc id");
									log_error!(logger, "Duplicate intercept id for HTLC");
									fail_htlc_continue_to_next!(
										LocalHTLCFailureReason::TemporaryNodeFailure
									);
								},
							}
						} else if intercept_forward {
							let intercept_id = intercept_id();
							let mut pending_intercepts =
								self.pending_intercepted_htlcs.lock().unwrap();
							match pending_intercepts.entry(intercept_id) {
								hash_map::Entry::Vacant(entry) => {
									if let Ok(intercept_ev) =
										create_htlc_intercepted_event(intercept_id, &pending_add)
									{
										log_debug!(
											logger,
											"Intercepted HTLC, generating intercept event with ID {intercept_id}"
										);
										let ev_entry = (intercept_ev, None);
										// It's possible we processed this intercept forward,
										// generated an event, then re-processed it here after
										// restart, in which case the intercept event should not be
										// pushed redundantly.
										let mut events = self.pending_events.lock().unwrap();
										events.retain(|ev| *ev != ev_entry);
										events.push_back(ev_entry);
										entry.insert(pending_add);
									} else {
										debug_assert!(false);
										log_error!(
											logger,
											"Failed to generate an intercept event for HTLC"
										);
										fail_htlc_continue_to_next!(
											LocalHTLCFailureReason::TemporaryNodeFailure
										);
									}
								},
								hash_map::Entry::Occupied(_) => {
									log_error!(
										logger,
										"Failed to forward incoming HTLC: detected duplicate intercepted payment",
									);
									debug_assert!(false, "Should never have two HTLCs with the same channel id and htlc id");
									fail_htlc_continue_to_next!(
										LocalHTLCFailureReason::TemporaryNodeFailure
									);
								},
							}
						} else {
							htlc_forwards.push(pending_add);
						}
					},
					Err(inbound_err) => {
						let failure_type =
							get_htlc_failure_type(outgoing_scid_opt, update_add_htlc.payment_hash);
						let htlc_failure = inbound_err.reason.into();
						let htlc_fail = self.construct_pending_htlc_fail_msg(
							&update_add_htlc,
							&incoming_counterparty_node_id,
							shared_secret,
							inbound_err,
						);
						htlc_fails.push((htlc_fail, failure_type, htlc_failure));
					},
				}
			}

			// Process all of the forwards and failures for the channel in which the HTLCs were
			// proposed to as a batch.
			self.forward_htlcs(htlc_forwards);
			for (htlc_fail, failure_type, failure_reason) in htlc_fails.drain(..) {
				let failure = match htlc_fail {
					HTLCFailureMsg::Relay(fail_htlc) => HTLCForwardInfo::FailHTLC {
						htlc_id: fail_htlc.htlc_id,
						err_packet: fail_htlc.into(),
					},
					HTLCFailureMsg::Malformed(fail_malformed_htlc) => {
						HTLCForwardInfo::FailMalformedHTLC {
							htlc_id: fail_malformed_htlc.htlc_id,
							sha256_of_onion: fail_malformed_htlc.sha256_of_onion,
							failure_code: fail_malformed_htlc.failure_code.into(),
						}
					},
				};
				self.forward_htlcs
					.lock()
					.unwrap()
					.entry(incoming_scid_alias)
					.or_default()
					.push(failure);
				self.pending_events.lock().unwrap().push_back((
					events::Event::HTLCHandlingFailed {
						prev_channel_id: incoming_channel_id,
						failure_type,
						failure_reason: Some(failure_reason),
					},
					None,
				));
			}
		}

		// Merge peeled dummy HTLCs into the existing decode queue so they can be
		// processed in the next iteration. We avoid replacing the whole queue
		// (e.g. via mem::swap) because other threads may have enqueued new HTLCs
		// meanwhile; merging preserves everything safely.
		if !dummy_update_add_htlcs.is_empty() {
			let mut decode_update_add_htlc_source = self.decode_update_add_htlcs.lock().unwrap();

			for (incoming_scid_alias, htlcs) in dummy_update_add_htlcs.into_iter() {
				decode_update_add_htlc_source.entry(incoming_scid_alias).or_default().extend(htlcs);
			}
		}

		should_persist
	}

	/// Returns whether we have pending HTLC forwards that need to be processed via
	/// [`Self::process_pending_htlc_forwards`].
	pub fn needs_pending_htlc_processing(&self) -> bool {
		if !self.forward_htlcs.lock().unwrap().is_empty() {
			return true;
		}
		if !self.decode_update_add_htlcs.lock().unwrap().is_empty() {
			return true;
		}
		if self.pending_outbound_payments.needs_abandon_or_retry() {
			return true;
		}
		false
	}

	/// Processes HTLCs which are pending waiting on random forward delay.
	///
	/// Will be regularly called by LDK's background processor.
	///
	/// Users implementing their own background processing logic should call this in irregular,
	/// randomly-distributed intervals.
	pub fn process_pending_htlc_forwards(&self) {
		if self
			.pending_htlc_forwards_processor
			.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
			.is_err()
		{
			return;
		}

		let _persistence_guard = PersistenceNotifierGuard::optionally_notify(self, || {
			self.internal_process_pending_htlc_forwards()
		});

		self.pending_htlc_forwards_processor.store(false, Ordering::Release);
	}

	// Returns whether or not we need to re-persist.
	fn internal_process_pending_htlc_forwards(&self) -> NotifyOption {
		let mut should_persist = NotifyOption::SkipPersistNoEvents;

		if self.process_pending_update_add_htlcs() {
			should_persist = NotifyOption::DoPersist;
		}

		let mut new_events = VecDeque::new();
		let mut failed_forwards = Vec::new();
		let mut phantom_receives: Vec<PendingAddHTLCInfo> = Vec::new();
		let mut forward_htlcs = new_hash_map();
		mem::swap(&mut forward_htlcs, &mut self.forward_htlcs.lock().unwrap());

		for (short_chan_id, mut pending_forwards) in forward_htlcs {
			should_persist = NotifyOption::DoPersist;
			if short_chan_id != 0 {
				self.process_forward_htlcs(
					short_chan_id,
					&mut pending_forwards,
					&mut failed_forwards,
					&mut phantom_receives,
				);
			} else {
				self.process_receive_htlcs(
					&mut pending_forwards,
					&mut new_events,
					&mut failed_forwards,
				);
			}
		}

		let best_block_height = self.best_block.read().unwrap().height;
		let needs_persist = self.pending_outbound_payments.check_retry_payments(
			&self.router,
			|| self.list_usable_channels(),
			|| self.compute_inflight_htlcs(),
			&self.entropy_source,
			&self.node_signer,
			best_block_height,
			&self.pending_events,
			|args| self.send_payment_along_path(args),
			&WithContext::from(&self.logger, None, None, None),
		);
		if needs_persist {
			should_persist = NotifyOption::DoPersist;
		}

		for (htlc_source, payment_hash, failure_reason, destination) in failed_forwards.drain(..) {
			self.fail_htlc_backwards_internal(
				&htlc_source,
				&payment_hash,
				&failure_reason,
				destination,
				None,
			);
		}
		self.forward_htlcs(phantom_receives);

		if self.check_free_holding_cells() {
			should_persist = NotifyOption::DoPersist;
		}

		if new_events.is_empty() {
			return should_persist;
		}
		let mut events = self.pending_events.lock().unwrap();
		events.append(&mut new_events);
		should_persist = NotifyOption::DoPersist;

		should_persist
	}

	/// Fail the list of provided HTLC forwards because the channel they were to be forwarded over does no longer exist.
	fn forwarding_channel_not_found(
		&self, forward_infos: impl Iterator<Item = HTLCForwardInfo>, short_chan_id: u64,
		forwarding_counterparty: Option<PublicKey>, failed_forwards: &mut Vec<FailedHTLCForward>,
		phantom_receives: &mut Vec<PendingAddHTLCInfo>,
	) {
		for forward_info in forward_infos {
			match forward_info {
				HTLCForwardInfo::AddHTLC(payment) => {
					let PendingAddHTLCInfo {
						prev_outbound_scid_alias,
						prev_htlc_id,
						prev_channel_id,
						prev_funding_outpoint,
						prev_user_channel_id,
						prev_counterparty_node_id,
						forward_info:
							PendingHTLCInfo {
								ref routing,
								incoming_shared_secret,
								payment_hash,
								outgoing_amt_msat,
								outgoing_cltv_value,
								incoming_accountable,
								..
							},
					} = payment;
					let logger = WithContext::from(
						&self.logger,
						forwarding_counterparty,
						Some(prev_channel_id),
						Some(payment_hash),
					);
					let mut failure_handler =
						|msg, reason, err_data, phantom_ss, next_hop_unknown| {
							log_info!(logger, "Failed to accept/forward incoming HTLC: {}", msg);

							let mut prev_hop = payment.htlc_previous_hop_data();
							// Override the phantom shared secret because it wasn't set in the originating
							// `PendingAddHTLCInfo` above, it was calculated below after detecting this as a
							// phantom payment.
							prev_hop.phantom_shared_secret = phantom_ss;
							let failure_type = if next_hop_unknown {
								HTLCHandlingFailureType::InvalidForward {
									requested_forward_scid: short_chan_id,
								}
							} else {
								HTLCHandlingFailureType::Receive { payment_hash }
							};

							failed_forwards.push((
								HTLCSource::PreviousHopData(prev_hop),
								payment_hash,
								HTLCFailReason::reason(reason, err_data),
								failure_type,
							));
						};

					if let PendingHTLCRouting::Forward { ref onion_packet, .. } = routing {
						let phantom_pubkey_res =
							self.node_signer.get_node_id(Recipient::PhantomNode);
						if phantom_pubkey_res.is_ok()
							&& fake_scid::is_valid_phantom(
								&self.fake_scid_rand_bytes,
								short_chan_id,
								&self.chain_hash,
							) {
							let decode_res = onion_utils::decode_next_payment_hop(
								Recipient::PhantomNode,
								&onion_packet.public_key.unwrap(),
								&onion_packet.hop_data,
								onion_packet.hmac,
								payment_hash,
								None,
								&self.node_signer,
							);
							let next_hop = match decode_res {
								Ok(res) => res,
								Err(onion_utils::OnionDecodeErr::Malformed { err_msg, reason }) => {
									let sha256_of_onion =
										Sha256::hash(&onion_packet.hop_data).to_byte_array();
									// In this scenario, the phantom would have sent us an
									// `update_fail_malformed_htlc`, meaning here we encrypt the error as
									// if it came from us (the second-to-last hop) but contains the sha256
									// of the onion.
									failure_handler(
										err_msg,
										reason,
										sha256_of_onion.to_vec(),
										None,
										false,
									);
									continue;
								},
								Err(onion_utils::OnionDecodeErr::Relay {
									err_msg,
									reason,
									shared_secret,
									..
								}) => {
									let phantom_shared_secret = shared_secret.secret_bytes();
									failure_handler(
										err_msg,
										reason,
										Vec::new(),
										Some(phantom_shared_secret),
										false,
									);
									continue;
								},
							};
							let phantom_shared_secret = next_hop.shared_secret().secret_bytes();
							let current_height: u32 = self.best_block.read().unwrap().height;
							let create_res = create_recv_pending_htlc_info(
								next_hop,
								incoming_shared_secret,
								payment_hash,
								outgoing_amt_msat,
								outgoing_cltv_value,
								Some(phantom_shared_secret),
								false,
								None,
								incoming_accountable,
								current_height,
							);
							match create_res {
								Ok(info) => phantom_receives.push(PendingAddHTLCInfo {
									forward_info: info,
									prev_outbound_scid_alias,
									prev_htlc_id,
									prev_counterparty_node_id,
									prev_channel_id,
									prev_funding_outpoint,
									prev_user_channel_id,
								}),
								Err(InboundHTLCErr { reason, err_data, msg }) => {
									failure_handler(
										msg,
										reason,
										err_data,
										Some(phantom_shared_secret),
										false,
									);
									continue;
								},
							}
						} else {
							let msg = format!(
								"Unknown short channel id {} for forward HTLC",
								short_chan_id
							);
							failure_handler(
								&msg,
								LocalHTLCFailureReason::UnknownNextPeer,
								Vec::new(),
								None,
								true,
							);
							continue;
						}
					} else {
						let msg =
							format!("Unknown short channel id {} for forward HTLC", short_chan_id);
						failure_handler(
							&msg,
							LocalHTLCFailureReason::UnknownNextPeer,
							Vec::new(),
							None,
							true,
						);
						continue;
					}
				},
				HTLCForwardInfo::FailHTLC { .. } | HTLCForwardInfo::FailMalformedHTLC { .. } => {
					// Channel went away before we could fail it. This implies
					// the channel is now on chain and our counterparty is
					// trying to broadcast the HTLC-Timeout, but that's their
					// problem, not ours.
				},
			}
		}
	}

	fn process_forward_htlcs(
		&self, short_chan_id: u64, pending_forwards: &mut Vec<HTLCForwardInfo>,
		failed_forwards: &mut Vec<FailedHTLCForward>,
		phantom_receives: &mut Vec<PendingAddHTLCInfo>,
	) {
		let mut forwarding_counterparty = None;

		let chan_info_opt = self.short_to_chan_info.read().unwrap().get(&short_chan_id).cloned();
		let (counterparty_node_id, forward_chan_id) = match chan_info_opt {
			Some((cp_id, chan_id)) => (cp_id, chan_id),
			None => {
				self.forwarding_channel_not_found(
					pending_forwards.drain(..),
					short_chan_id,
					forwarding_counterparty,
					failed_forwards,
					phantom_receives,
				);
				return;
			},
		};
		forwarding_counterparty = Some(counterparty_node_id);
		let per_peer_state = self.per_peer_state.read().unwrap();
		let peer_state_mutex_opt = per_peer_state.get(&counterparty_node_id);
		if peer_state_mutex_opt.is_none() {
			self.forwarding_channel_not_found(
				pending_forwards.drain(..),
				short_chan_id,
				forwarding_counterparty,
				failed_forwards,
				phantom_receives,
			);
			return;
		}
		let mut peer_state_lock = peer_state_mutex_opt.unwrap().lock().unwrap();
		let peer_state = &mut *peer_state_lock;
		let mut draining_pending_forwards = pending_forwards.drain(..);
		while let Some(forward_info) = draining_pending_forwards.next() {
			let queue_fail_htlc_res = match forward_info {
				HTLCForwardInfo::AddHTLC(ref payment) => {
					let htlc_source = HTLCSource::PreviousHopData(payment.htlc_previous_hop_data());
					let PendingAddHTLCInfo {
						prev_outbound_scid_alias,
						forward_info:
							PendingHTLCInfo {
								payment_hash,
								outgoing_amt_msat,
								outgoing_cltv_value,
								routing,
								skimmed_fee_msat,
								incoming_accountable,
								..
							},
						..
					} = payment;
					let (onion_packet, blinded) = match routing {
						PendingHTLCRouting::Forward { ref onion_packet, blinded, .. } => {
							(onion_packet, blinded)
						},
						_ => {
							panic!("short_channel_id != 0 should imply any pending_forward entries are of type Forward");
						},
					};
					let next_blinding_point = blinded.and_then(|b| {
						b.next_blinding_override.or_else(|| {
							let encrypted_tlvs_ss = self
								.node_signer
								.ecdh(Recipient::Node, &b.inbound_blinding_point, None)
								.unwrap()
								.secret_bytes();
							onion_utils::next_hop_pubkey(
								&self.secp_ctx,
								b.inbound_blinding_point,
								&encrypted_tlvs_ss,
							)
							.ok()
						})
					});

					// Forward the HTLC over the most appropriate channel with the corresponding peer,
					// applying non-strict forwarding.
					// The channel with the least amount of outbound liquidity will be used to maximize the
					// probability of being able to successfully forward a subsequent HTLC.
					let maybe_optimal_channel = peer_state
						.channel_by_id
						.values_mut()
						.filter_map(Channel::as_funded_mut)
						.filter_map(|chan| {
							let balances = chan.get_available_balances(&self.fee_estimator);
							let is_in_range = (balances.next_outbound_htlc_minimum_msat
								..=balances.next_outbound_htlc_limit_msat)
								.contains(&outgoing_amt_msat);
							if is_in_range && chan.context.is_usable() {
								Some((chan, balances))
							} else {
								None
							}
						})
						.min_by_key(|(_, balances)| balances.next_outbound_htlc_limit_msat)
						.map(|(c, _)| c);
					let optimal_channel = match maybe_optimal_channel {
						Some(chan) => chan,
						None => {
							// Fall back to the specified channel to return an appropriate error.
							if let Some(chan) = peer_state
								.channel_by_id
								.get_mut(&forward_chan_id)
								.and_then(Channel::as_funded_mut)
							{
								chan
							} else {
								let fwd_iter =
									core::iter::once(forward_info).chain(draining_pending_forwards);
								self.forwarding_channel_not_found(
									fwd_iter,
									short_chan_id,
									forwarding_counterparty,
									failed_forwards,
									phantom_receives,
								);
								break;
							}
						},
					};

					let logger = WithChannelContext::from(
						&self.logger,
						&optimal_channel.context,
						Some(*payment_hash),
					);
					let channel_description =
						if optimal_channel.funding.get_short_channel_id() == Some(short_chan_id) {
							"specified"
						} else {
							"alternate"
						};
					log_trace!(
						logger,
						"Forwarding HTLC from SCID {} with next hop SCID {} over {}",
						prev_outbound_scid_alias,
						short_chan_id,
						channel_description
					);
					if let Err((reason, msg)) = optimal_channel.queue_add_htlc(
						*outgoing_amt_msat,
						*payment_hash,
						*outgoing_cltv_value,
						htlc_source.clone(),
						onion_packet.clone(),
						*skimmed_fee_msat,
						next_blinding_point,
						*incoming_accountable,
						&self.fee_estimator,
						&&logger,
					) {
						log_trace!(logger, "Failed to forward HTLC: {}", msg);

						if let Some(chan) = peer_state
							.channel_by_id
							.get_mut(&forward_chan_id)
							.and_then(Channel::as_funded_mut)
						{
							let data = self.get_htlc_inbound_temp_fail_data(reason);
							let failure_type = HTLCHandlingFailureType::Forward {
								node_id: Some(chan.context.get_counterparty_node_id()),
								channel_id: forward_chan_id,
							};
							failed_forwards.push((
								htlc_source,
								*payment_hash,
								HTLCFailReason::reason(reason, data),
								failure_type,
							));
						} else {
							self.forwarding_channel_not_found(
								core::iter::once(forward_info).chain(draining_pending_forwards),
								short_chan_id,
								forwarding_counterparty,
								failed_forwards,
								phantom_receives,
							);
							break;
						}
					}
					None
				},
				HTLCForwardInfo::FailHTLC { htlc_id, ref err_packet } => {
					if let Some(chan) = peer_state
						.channel_by_id
						.get_mut(&forward_chan_id)
						.and_then(Channel::as_funded_mut)
					{
						let logger = WithChannelContext::from(&self.logger, &chan.context, None);
						log_trace!(logger, "Failing HTLC back to channel with short id {} (backward HTLC ID {}) after delay", short_chan_id, htlc_id);
						Some((chan.queue_fail_htlc(htlc_id, err_packet.clone(), &&logger), htlc_id))
					} else {
						self.forwarding_channel_not_found(
							core::iter::once(forward_info).chain(draining_pending_forwards),
							short_chan_id,
							forwarding_counterparty,
							failed_forwards,
							phantom_receives,
						);
						break;
					}
				},
				HTLCForwardInfo::FailMalformedHTLC { htlc_id, failure_code, sha256_of_onion } => {
					if let Some(chan) = peer_state
						.channel_by_id
						.get_mut(&forward_chan_id)
						.and_then(Channel::as_funded_mut)
					{
						let logger = WithChannelContext::from(&self.logger, &chan.context, None);
						log_trace!(logger, "Failing malformed HTLC back to channel with short id {} (backward HTLC ID {}) after delay", short_chan_id, htlc_id);
						let res = chan.queue_fail_malformed_htlc(
							htlc_id,
							failure_code,
							sha256_of_onion,
							&&logger,
						);
						Some((res, htlc_id))
					} else {
						self.forwarding_channel_not_found(
							core::iter::once(forward_info).chain(draining_pending_forwards),
							short_chan_id,
							forwarding_counterparty,
							failed_forwards,
							phantom_receives,
						);
						break;
					}
				},
			};
			if let Some((queue_fail_htlc_res, htlc_id)) = queue_fail_htlc_res {
				if let Err(e) = queue_fail_htlc_res {
					if let ChannelError::Ignore(msg) = e {
						if let Some(chan) = peer_state
							.channel_by_id
							.get_mut(&forward_chan_id)
							.and_then(Channel::as_funded_mut)
						{
							let logger =
								WithChannelContext::from(&self.logger, &chan.context, None);
							log_trace!(
								logger,
								"Failed to fail HTLC with ID {} backwards to short_id {}: {}",
								htlc_id,
								short_chan_id,
								msg
							);
						}
					} else {
						panic!("Stated return value requirements in queue_fail_{{malformed_}}htlc() were not met");
					}
					// fail-backs are best-effort, we probably already have one
					// pending, and if not that's OK, if not, the channel is on
					// the chain and sending the HTLC-Timeout is their problem.
				}
			}
		}
	}

	fn process_receive_htlcs(
		&self, pending_forwards: &mut Vec<HTLCForwardInfo>,
		new_events: &mut VecDeque<(Event, Option<EventCompletionAction>)>,
		failed_forwards: &mut Vec<FailedHTLCForward>,
	) {
		'next_forwardable_htlc: for forward_info in pending_forwards.drain(..) {
			match forward_info {
				HTLCForwardInfo::AddHTLC(payment) => {
					let prev_hop = payment.htlc_previous_hop_data();
					let PendingAddHTLCInfo {
						prev_channel_id,
						prev_funding_outpoint,
						forward_info:
							PendingHTLCInfo {
								routing,
								payment_hash,
								incoming_amt_msat,
								outgoing_amt_msat,
								skimmed_fee_msat,
								..
							},
						..
					} = payment;
					let blinded_failure = routing.blinded_failure();
					let (
						cltv_expiry,
						onion_payload,
						payment_data,
						payment_context,
						phantom_shared_secret,
						mut onion_fields,
						has_recipient_created_payment_secret,
						invoice_request_opt,
						trampoline_shared_secret,
					) = match routing {
						PendingHTLCRouting::Receive {
							payment_data,
							payment_metadata,
							payment_context,
							incoming_cltv_expiry,
							phantom_shared_secret,
							trampoline_shared_secret,
							custom_tlvs,
							requires_blinded_error: _,
						} => {
							let _legacy_hop_data = Some(payment_data.clone());
							let onion_fields = RecipientOnionFields {
								payment_secret: Some(payment_data.payment_secret),
								payment_metadata,
								custom_tlvs,
							};
							(
								incoming_cltv_expiry,
								OnionPayload::Invoice { _legacy_hop_data },
								Some(payment_data),
								payment_context,
								phantom_shared_secret,
								onion_fields,
								true,
								None,
								trampoline_shared_secret,
							)
						},
						PendingHTLCRouting::ReceiveKeysend {
							payment_data,
							payment_preimage,
							payment_metadata,
							incoming_cltv_expiry,
							custom_tlvs,
							requires_blinded_error: _,
							has_recipient_created_payment_secret,
							payment_context,
							invoice_request,
						} => {
							let onion_fields = RecipientOnionFields {
								payment_secret: payment_data
									.as_ref()
									.map(|data| data.payment_secret),
								payment_metadata,
								custom_tlvs,
							};
							(
								incoming_cltv_expiry,
								OnionPayload::Spontaneous(payment_preimage),
								payment_data,
								payment_context,
								None,
								onion_fields,
								has_recipient_created_payment_secret,
								invoice_request,
								None,
							)
						},
						_ => {
							panic!("short_channel_id == 0 should imply any pending_forward entries are of type Receive");
						},
					};
					let claimable_htlc = ClaimableHTLC {
						prev_hop,
						// We differentiate the received value from the sender intended value
						// if possible so that we don't prematurely mark MPP payments complete
						// if routing nodes overpay
						value: incoming_amt_msat.unwrap_or(outgoing_amt_msat),
						sender_intended_value: outgoing_amt_msat,
						timer_ticks: 0,
						total_value_received: None,
						total_msat: if let Some(data) = &payment_data {
							data.total_msat
						} else {
							outgoing_amt_msat
						},
						cltv_expiry,
						onion_payload,
						counterparty_skimmed_fee_msat: skimmed_fee_msat,
					};

					let mut committed_to_claimable = false;

					macro_rules! fail_htlc {
						($htlc: expr, $payment_hash: expr) => {
							debug_assert!(!committed_to_claimable);
							let err_data = invalid_payment_err_data(
								$htlc.value,
								self.best_block.read().unwrap().height,
							);
							let counterparty_node_id = $htlc.prev_hop.counterparty_node_id;
							let incoming_packet_shared_secret =
								$htlc.prev_hop.incoming_packet_shared_secret;
							let prev_outbound_scid_alias = $htlc.prev_hop.prev_outbound_scid_alias;
							failed_forwards.push((
								HTLCSource::PreviousHopData(HTLCPreviousHopData {
									prev_outbound_scid_alias,
									user_channel_id: $htlc.prev_hop.user_channel_id,
									counterparty_node_id,
									channel_id: prev_channel_id,
									outpoint: prev_funding_outpoint,
									htlc_id: $htlc.prev_hop.htlc_id,
									incoming_packet_shared_secret,
									phantom_shared_secret,
									trampoline_shared_secret,
									blinded_failure,
									cltv_expiry: Some(cltv_expiry),
								}),
								payment_hash,
								HTLCFailReason::reason(
									LocalHTLCFailureReason::IncorrectPaymentDetails,
									err_data,
								),
								HTLCHandlingFailureType::Receive { payment_hash: $payment_hash },
							));
							continue 'next_forwardable_htlc;
						};
					}
					let phantom_shared_secret = claimable_htlc.prev_hop.phantom_shared_secret;
					let mut receiver_node_id = self.our_network_pubkey;
					if phantom_shared_secret.is_some() {
						receiver_node_id = self
							.node_signer
							.get_node_id(Recipient::PhantomNode)
							.expect("Failed to get node_id for phantom node recipient");
					}

					macro_rules! check_total_value {
						($purpose: expr) => {{
							let mut payment_claimable_generated = false;
							let is_keysend = $purpose.is_keysend();
							let mut claimable_payments = self.claimable_payments.lock().unwrap();
							if claimable_payments.pending_claiming_payments.contains_key(&payment_hash) {
								fail_htlc!(claimable_htlc, payment_hash);
							}
							let ref mut claimable_payment = claimable_payments.claimable_payments
								.entry(payment_hash)
								// Note that if we insert here we MUST NOT fail_htlc!()
								.or_insert_with(|| {
									committed_to_claimable = true;
									ClaimablePayment {
										purpose: $purpose.clone(), htlcs: Vec::new(), onion_fields: None,
									}
								});
							if $purpose != claimable_payment.purpose {
								let log_keysend = |keysend| if keysend { "keysend" } else { "non-keysend" };
								log_trace!(self.logger, "Failing new {} HTLC with payment_hash {} as we already had an existing {} HTLC with the same payment hash", log_keysend(is_keysend), &payment_hash, log_keysend(!is_keysend));
								fail_htlc!(claimable_htlc, payment_hash);
							}
							if let Some(earlier_fields) = &mut claimable_payment.onion_fields {
								if earlier_fields.check_merge(&mut onion_fields).is_err() {
									fail_htlc!(claimable_htlc, payment_hash);
								}
							} else {
								claimable_payment.onion_fields = Some(onion_fields);
							}
							let mut total_value = claimable_htlc.sender_intended_value;
							let mut earliest_expiry = claimable_htlc.cltv_expiry;
							for htlc in claimable_payment.htlcs.iter() {
								total_value += htlc.sender_intended_value;
								earliest_expiry = cmp::min(earliest_expiry, htlc.cltv_expiry);
								if htlc.total_msat != claimable_htlc.total_msat {
									log_trace!(self.logger, "Failing HTLCs with payment_hash {} as the HTLCs had inconsistent total values (eg {} and {})",
										&payment_hash, claimable_htlc.total_msat, htlc.total_msat);
									total_value = msgs::MAX_VALUE_MSAT;
								}
								if total_value >= msgs::MAX_VALUE_MSAT { break; }
							}
							// The condition determining whether an MPP is complete must
							// match exactly the condition used in `timer_tick_occurred`
							if total_value >= msgs::MAX_VALUE_MSAT {
								fail_htlc!(claimable_htlc, payment_hash);
							} else if total_value - claimable_htlc.sender_intended_value >= claimable_htlc.total_msat {
								log_trace!(self.logger, "Failing HTLC with payment_hash {} as payment is already claimable",
									&payment_hash);
								fail_htlc!(claimable_htlc, payment_hash);
							} else if total_value >= claimable_htlc.total_msat {
								#[allow(unused_assignments)] {
									committed_to_claimable = true;
								}
								claimable_payment.htlcs.push(claimable_htlc);
								let amount_msat =
									claimable_payment.htlcs.iter().map(|htlc| htlc.value).sum();
								claimable_payment.htlcs.iter_mut()
									.for_each(|htlc| htlc.total_value_received = Some(amount_msat));
								let counterparty_skimmed_fee_msat = claimable_payment.htlcs.iter()
									.map(|htlc| htlc.counterparty_skimmed_fee_msat.unwrap_or(0)).sum();
								debug_assert!(total_value.saturating_sub(amount_msat) <=
									counterparty_skimmed_fee_msat);
								claimable_payment.htlcs.sort();
								let payment_id =
									claimable_payment.inbound_payment_id(&self.inbound_payment_id_secret);
								new_events.push_back((events::Event::PaymentClaimable {
									receiver_node_id: Some(receiver_node_id),
									payment_hash,
									purpose: $purpose,
									amount_msat,
									counterparty_skimmed_fee_msat,
									receiving_channel_ids: claimable_payment.receiving_channel_ids(),
									claim_deadline: Some(earliest_expiry - HTLC_FAIL_BACK_BUFFER),
									onion_fields: claimable_payment.onion_fields.clone(),
									payment_id: Some(payment_id),
								}, None));
								payment_claimable_generated = true;
							} else {
								// Nothing to do - we haven't reached the total
								// payment value yet, wait until we receive more
								// MPP parts.
								claimable_payment.htlcs.push(claimable_htlc);
								#[allow(unused_assignments)] {
									committed_to_claimable = true;
								}
							}
							payment_claimable_generated
						}}
					}

					// Check that the payment hash and secret are known. Note that we
					// MUST take care to handle the "unknown payment hash" and
					// "incorrect payment secret" cases here identically or we'd expose
					// that we are the ultimate recipient of the given payment hash.
					// Further, we must not expose whether we have any other HTLCs
					// associated with the same payment_hash pending or not.
					let payment_preimage = if has_recipient_created_payment_secret {
						if let Some(ref payment_data) = payment_data {
							let verify_res = inbound_payment::verify(
								payment_hash,
								&payment_data,
								self.highest_seen_timestamp.load(Ordering::Acquire) as u64,
								&self.inbound_payment_key,
								&self.logger,
							);
							let (payment_preimage, min_final_cltv_expiry_delta) = match verify_res {
								Ok(result) => result,
								Err(()) => {
									log_trace!(self.logger, "Failing new HTLC with payment_hash {} as payment verification failed", &payment_hash);
									fail_htlc!(claimable_htlc, payment_hash);
								},
							};
							if let Some(min_final_cltv_expiry_delta) = min_final_cltv_expiry_delta {
								let expected_min_expiry_height = (self.current_best_block().height
									+ min_final_cltv_expiry_delta as u32)
									as u64;
								if (cltv_expiry as u64) < expected_min_expiry_height {
									log_trace!(self.logger, "Failing new HTLC with payment_hash {} as its CLTV expiry was too soon (had {}, earliest expected {})",
									&payment_hash, cltv_expiry, expected_min_expiry_height);
									fail_htlc!(claimable_htlc, payment_hash);
								}
							}
							payment_preimage
						} else {
							fail_htlc!(claimable_htlc, payment_hash);
						}
					} else {
						None
					};
					match claimable_htlc.onion_payload {
						OnionPayload::Invoice { .. } => {
							let payment_data = payment_data.unwrap();
							let from_parts_res = events::PaymentPurpose::from_parts(
								payment_preimage,
								payment_data.payment_secret,
								payment_context,
							);
							let purpose = match from_parts_res {
								Ok(purpose) => purpose,
								Err(()) => {
									fail_htlc!(claimable_htlc, payment_hash);
								},
							};
							check_total_value!(purpose);
						},
						OnionPayload::Spontaneous(keysend_preimage) => {
							let purpose = if let Some(PaymentContext::AsyncBolt12Offer(
								AsyncBolt12OfferContext { offer_nonce },
							)) = payment_context
							{
								let payment_data = match payment_data {
									Some(data) => data,
									None => {
										debug_assert!(
											false,
											"We checked that payment_data is Some above"
										);
										fail_htlc!(claimable_htlc, payment_hash);
									},
								};

								let verify_opt = invoice_request_opt.and_then(|invreq| {
									invreq
										.verify_using_recipient_data(
											offer_nonce,
											&self.inbound_payment_key,
											&self.secp_ctx,
										)
										.ok()
								});
								let verified_invreq = match verify_opt {
									Some(verified_invreq) => {
										if let Some(invreq_amt_msat) =
											verified_invreq.amount_msats()
										{
											if payment_data.total_msat < invreq_amt_msat {
												fail_htlc!(claimable_htlc, payment_hash);
											}
										}
										verified_invreq
									},
									None => {
										fail_htlc!(claimable_htlc, payment_hash);
									},
								};
								let payment_purpose_context =
									PaymentContext::Bolt12Offer(Bolt12OfferContext {
										offer_id: verified_invreq.offer_id(),
										invoice_request: verified_invreq.fields(),
									});
								let from_parts_res = events::PaymentPurpose::from_parts(
									Some(keysend_preimage),
									payment_data.payment_secret,
									Some(payment_purpose_context),
								);
								match from_parts_res {
									Ok(purpose) => purpose,
									Err(()) => {
										fail_htlc!(claimable_htlc, payment_hash);
									},
								}
							} else if payment_context.is_some() {
								log_trace!(self.logger, "Failing new HTLC with payment_hash {}: received a keysend payment to a non-async payments context {:#?}", payment_hash, payment_context);
								fail_htlc!(claimable_htlc, payment_hash);
							} else {
								events::PaymentPurpose::SpontaneousPayment(keysend_preimage)
							};
							check_total_value!(purpose);
						},
					}
				},
				HTLCForwardInfo::FailHTLC { .. } | HTLCForwardInfo::FailMalformedHTLC { .. } => {
					panic!("Got pending fail of our own HTLC");
				},
			}
		}
	}

	/// Free the background events, generally called from [`PersistenceNotifierGuard`] constructors.
	///
	/// Expects the caller to have a total_consistency_lock read lock.
	fn process_background_events(&self) -> NotifyOption {
		debug_assert_ne!(
			self.total_consistency_lock.held_by_thread(),
			LockHeldState::NotHeldByThread
		);

		self.background_events_processed_since_startup.store(true, Ordering::Release);

		let mut background_events = Vec::new();
		mem::swap(&mut *self.pending_background_events.lock().unwrap(), &mut background_events);
		if background_events.is_empty() {
			return NotifyOption::SkipPersistNoEvents;
		}

		for event in background_events.drain(..) {
			match event {
				BackgroundEvent::MonitorUpdateRegeneratedOnStartup {
					counterparty_node_id,
					funding_txo,
					channel_id,
					update,
				} => {
					self.apply_post_close_monitor_update(
						counterparty_node_id,
						channel_id,
						funding_txo,
						update,
					);
				},
				BackgroundEvent::MonitorUpdatesComplete {
					counterparty_node_id,
					channel_id,
					highest_update_id_completed,
				} => {
					// Now that we can finally handle the background event, remove all in-flight
					// monitor updates for this channel that we've known to complete, as they have
					// already been persisted to the monitor and can be applied to our internal
					// state such that the channel resumes operation if no new updates have been
					// made since.
					self.channel_monitor_updated(
						&channel_id,
						Some(highest_update_id_completed),
						&counterparty_node_id,
					);
				},
			}
		}
		NotifyOption::DoPersist
	}

	#[cfg(any(test, feature = "_test_utils"))]
	/// Process background events, for functional testing
	pub fn test_process_background_events(&self) {
		let _lck = self.total_consistency_lock.read().unwrap();
		let _ = self.process_background_events();
	}

	#[rustfmt::skip]
	fn update_channel_fee(&self, chan_id: &ChannelId, chan: &mut FundedChannel<SP>, new_feerate: u32) -> NotifyOption {
		if !chan.funding.is_outbound() { return NotifyOption::SkipPersistNoEvents; }

		let logger = WithChannelContext::from(&self.logger, &chan.context, None);

		let current_feerate = chan.context.get_feerate_sat_per_1000_weight();
		let update_fee_required = match new_feerate.cmp(&current_feerate) {
			cmp::Ordering::Greater => true,
			cmp::Ordering::Equal => false,
			// Only bother with a fee update if feerate has decreased at least half.
			cmp::Ordering::Less => new_feerate * 2 <= current_feerate,
		};
		if !update_fee_required {
			return NotifyOption::SkipPersistNoEvents
		}

		if !chan.context.is_live() {
			log_trace!(logger, "Channel {} does not qualify for a feerate change from {} to {} as it cannot currently be updated (probably the peer is disconnected).",
				chan_id, chan.context.get_feerate_sat_per_1000_weight(), new_feerate);
			return NotifyOption::SkipPersistNoEvents;
		}
		log_trace!(logger, "Channel qualifies for a feerate change from {} to {}.",
			chan.context.get_feerate_sat_per_1000_weight(), new_feerate);

		chan.queue_update_fee(new_feerate, &self.fee_estimator, &&logger);
		NotifyOption::DoPersist
	}

	/// Performs actions which should happen on startup and roughly once per minute thereafter.
	///
	/// This currently includes:
	///  * Increasing or decreasing the on-chain feerate estimates for our outbound channels,
	///  * Broadcasting [`ChannelUpdate`] messages if we've been disconnected from our peer for more
	///    than a minute, informing the network that they should no longer attempt to route over
	///    the channel.
	///  * Expiring a channel's previous [`ChannelConfig`] if necessary to only allow forwarding HTLCs
	///    with the current [`ChannelConfig`].
	///  * Removing peers which have disconnected but and no longer have any channels.
	///  * Force-closing and removing channels which have not completed establishment in a timely manner.
	///  * Forgetting about stale outbound payments, either those that have already been fulfilled
	///    or those awaiting an invoice that hasn't been delivered in the necessary amount of time.
	///    The latter is determined using the system clock in `std` and the highest seen block time
	///    minus two hours in non-`std`.
	///
	/// Note that this may cause reentrancy through [`chain::Watch::update_channel`] calls or feerate
	/// estimate fetches.
	///
	/// [`ChannelUpdate`]: msgs::ChannelUpdate
	/// [`ChannelConfig`]: crate::util::config::ChannelConfig
	pub fn timer_tick_occurred(&self) {
		PersistenceNotifierGuard::optionally_notify(self, || {
			let mut should_persist = NotifyOption::SkipPersistNoEvents;

			let mut handle_errors: Vec<(Result<(), _>, _)> = Vec::new();
			let mut timed_out_mpp_htlcs = Vec::new();
			let mut pending_peers_awaiting_removal = Vec::new();
			let mut feerate_cache = new_hash_map();

			{
				let per_peer_state = self.per_peer_state.read().unwrap();
				for (counterparty_node_id, peer_state_mutex) in per_peer_state.iter() {
					let mut peer_state_lock = peer_state_mutex.lock().unwrap();
					let peer_state = &mut *peer_state_lock;
					let pending_msg_events = &mut peer_state.pending_msg_events;
					let counterparty_node_id = *counterparty_node_id;
					peer_state.channel_by_id.retain(|chan_id, chan| {
						match chan.as_funded_mut() {
							Some(funded_chan) => {
								let channel_type = funded_chan.funding.get_channel_type();
								let new_feerate = feerate_cache.get(channel_type).copied().or_else(|| {
									let feerate = selected_commitment_sat_per_1000_weight(&self.fee_estimator, &channel_type);
									feerate_cache.insert(channel_type.clone(), feerate);
									Some(feerate)
								}).unwrap();
								let chan_needs_persist = self.update_channel_fee(chan_id, funded_chan, new_feerate);
								if chan_needs_persist == NotifyOption::DoPersist { should_persist = NotifyOption::DoPersist; }

								if let Err(e) = funded_chan.timer_check_closing_negotiation_progress() {
									let (needs_close, err) = self.locked_handle_funded_force_close(&mut peer_state.closed_channel_monitor_update_ids, &mut peer_state.in_flight_monitor_updates, e, funded_chan);
									handle_errors.push((Err(err), counterparty_node_id));
									if needs_close { return false; }
								}

								match funded_chan.channel_update_status() {
									ChannelUpdateStatus::Enabled if !funded_chan.context.is_live() => funded_chan.set_channel_update_status(ChannelUpdateStatus::DisabledStaged(0)),
									ChannelUpdateStatus::Disabled if funded_chan.context.is_live() => funded_chan.set_channel_update_status(ChannelUpdateStatus::EnabledStaged(0)),
									ChannelUpdateStatus::DisabledStaged(_) if funded_chan.context.is_live()
										=> funded_chan.set_channel_update_status(ChannelUpdateStatus::Enabled),
									ChannelUpdateStatus::EnabledStaged(_) if !funded_chan.context.is_live()
										=> funded_chan.set_channel_update_status(ChannelUpdateStatus::Disabled),
									ChannelUpdateStatus::DisabledStaged(mut n) if !funded_chan.context.is_live() => {
										n += 1;
										if n >= DISABLE_GOSSIP_TICKS {
											funded_chan.set_channel_update_status(ChannelUpdateStatus::Disabled);
											if let Ok((update, node_id_1, node_id_2)) = self.get_channel_update_for_broadcast(&funded_chan) {
												let mut pending_broadcast_messages = self.pending_broadcast_messages.lock().unwrap();
												pending_broadcast_messages.push(MessageSendEvent::BroadcastChannelUpdate {
													msg: update, node_id_1, node_id_2
												});
											}
											should_persist = NotifyOption::DoPersist;
										} else {
											funded_chan.set_channel_update_status(ChannelUpdateStatus::DisabledStaged(n));
										}
									},
									ChannelUpdateStatus::EnabledStaged(mut n) if funded_chan.context.is_live() => {
										n += 1;
										if n >= ENABLE_GOSSIP_TICKS {
											funded_chan.set_channel_update_status(ChannelUpdateStatus::Enabled);
											if let Ok((update, node_id_1, node_id_2)) = self.get_channel_update_for_broadcast(&funded_chan) {
												let mut pending_broadcast_messages = self.pending_broadcast_messages.lock().unwrap();
												pending_broadcast_messages.push(MessageSendEvent::BroadcastChannelUpdate {
													msg: update, node_id_1, node_id_2
												});
											}
											should_persist = NotifyOption::DoPersist;
										} else {
											funded_chan.set_channel_update_status(ChannelUpdateStatus::EnabledStaged(n));
										}
									},
									_ => {},
								}

								funded_chan.context.maybe_expire_prev_config();

								if peer_state.is_connected {
									if funded_chan.should_disconnect_peer_awaiting_response() {
										let logger = WithChannelContext::from(&self.logger, &funded_chan.context, None);
										log_debug!(logger, "Disconnecting peer due to not making any progress");
										pending_msg_events.push(MessageSendEvent::HandleError {
											node_id: counterparty_node_id,
											action: msgs::ErrorAction::DisconnectPeerWithWarning {
												msg: msgs::WarningMessage {
													channel_id: *chan_id,
													data: "Disconnecting due to timeout awaiting response".to_owned(),
												},
											},
										});
									}
								}

								true
							},
							None => {
								chan.context_mut().maybe_expire_prev_config();
								let unfunded_context = chan.unfunded_context_mut().expect("channel should be unfunded");
								if unfunded_context.should_expire_unfunded_channel() {
									let context = chan.context();
									let logger = WithChannelContext::from(&self.logger, context, None);
									log_error!(logger,
										"Force-closing pending channel for not establishing in a timely manner",
										);
									let reason = ClosureReason::FundingTimedOut;
									let msg = "Force-closing pending channel due to timeout awaiting establishment handshake".to_owned();
									let err = ChannelError::Close((msg, reason));
									let (_, e) = self.locked_handle_unfunded_close(
										err,
										chan,
									);
									handle_errors.push((Err(e), counterparty_node_id));
									false
								} else {
									true
								}
							},
						}
					});

					for (chan_id, req) in peer_state.inbound_channel_request_by_id.iter_mut() {
						if {
							req.ticks_remaining -= 1;
							req.ticks_remaining
						} <= 0
						{
							let logger = WithContext::from(
								&self.logger,
								Some(counterparty_node_id),
								Some(*chan_id),
								None,
							);
							log_error!(logger, "Force-closing unaccepted inbound channel {} for not accepting in a timely manner", &chan_id);
							if peer_state.is_connected {
								peer_state.pending_msg_events.push(MessageSendEvent::HandleError {
									node_id: counterparty_node_id,
									action: msgs::ErrorAction::SendErrorMessage {
										msg: msgs::ErrorMessage {
											channel_id: chan_id.clone(),
											data: "Channel force-closed".to_owned(),
										},
									},
								});
							}
						}
					}
					peer_state
						.inbound_channel_request_by_id
						.retain(|_, req| req.ticks_remaining > 0);

					if peer_state.ok_to_remove(true) {
						pending_peers_awaiting_removal.push(counterparty_node_id);
					}
				}
			}

			// When a peer disconnects but still has channels, the peer's `peer_state` entry in the
			// `per_peer_state` is not removed by the `peer_disconnected` function. If the channels
			// of to that peer is later closed while still being disconnected (i.e. force closed),
			// we therefore need to remove the peer from `peer_state` separately.
			// To avoid having to take the `per_peer_state` `write` lock once the channels are
			// closed, we instead remove such peers awaiting removal here on a timer, to limit the
			// negative effects on parallelism as much as possible.
			if pending_peers_awaiting_removal.len() > 0 {
				let mut per_peer_state = self.per_peer_state.write().unwrap();
				for counterparty_node_id in pending_peers_awaiting_removal {
					match per_peer_state.entry(counterparty_node_id) {
						hash_map::Entry::Occupied(entry) => {
							// Remove the entry if the peer is still disconnected and we still
							// have no channels to the peer.
							let remove_entry = {
								let peer_state = entry.get().lock().unwrap();
								peer_state.ok_to_remove(true)
							};
							if remove_entry {
								entry.remove_entry();
							}
						},
						hash_map::Entry::Vacant(_) => { /* The PeerState has already been removed */
						},
					}
				}
			}

			self.claimable_payments.lock().unwrap().claimable_payments.retain(
				|payment_hash, payment| {
					if payment.htlcs.is_empty() {
						// This should be unreachable
						debug_assert!(false);
						return false;
					}
					if let OnionPayload::Invoice { .. } = payment.htlcs[0].onion_payload {
						// Check if we've received all the parts we need for an MPP (the value of the parts adds to total_msat).
						// In this case we're not going to handle any timeouts of the parts here.
						// This condition determining whether the MPP is complete here must match
						// exactly the condition used in `process_pending_htlc_forwards`.
						let htlc_total_msat =
							payment.htlcs.iter().map(|h| h.sender_intended_value).sum();
						if payment.htlcs[0].total_msat <= htlc_total_msat {
							return true;
						} else if payment.htlcs.iter_mut().any(|htlc| {
							htlc.timer_ticks += 1;
							return htlc.timer_ticks >= MPP_TIMEOUT_TICKS;
						}) {
							let htlcs = payment
								.htlcs
								.drain(..)
								.map(|htlc: ClaimableHTLC| (htlc.prev_hop, *payment_hash));
							timed_out_mpp_htlcs.extend(htlcs);
							return false;
						}
					}
					true
				},
			);

			for htlc_source in timed_out_mpp_htlcs.drain(..) {
				let source = HTLCSource::PreviousHopData(htlc_source.0.clone());
				let failure_reason = LocalHTLCFailureReason::MPPTimeout;
				let reason = HTLCFailReason::from_failure_code(failure_reason);
				let receiver = HTLCHandlingFailureType::Receive { payment_hash: htlc_source.1 };
				self.fail_htlc_backwards_internal(&source, &htlc_source.1, &reason, receiver, None);
			}

			for (err, counterparty_node_id) in handle_errors {
				let _ = self.handle_error(err, counterparty_node_id);
			}

			#[cfg(feature = "std")]
			let duration_since_epoch = std::time::SystemTime::now()
				.duration_since(std::time::SystemTime::UNIX_EPOCH)
				.expect("SystemTime::now() should come after SystemTime::UNIX_EPOCH");
			#[cfg(not(feature = "std"))]
			let duration_since_epoch = Duration::from_secs(
				self.highest_seen_timestamp.load(Ordering::Acquire).saturating_sub(7200) as u64,
			);

			self.pending_outbound_payments
				.remove_stale_payments(duration_since_epoch, &self.pending_events);

			self.check_refresh_async_receive_offer_cache(true);

			if self.check_free_holding_cells() {
				// While we try to ensure we clear holding cells immediately, its possible we miss
				// one somewhere. Thus, its useful to try regularly to ensure even if something
				// gets stuck its only for a minute or so. Still, good to panic here in debug to
				// ensure we discover the missing free.
				// Note that in cases where we had a fee update in the loop above, we expect to
				// need to free holding cells now, thus we only report an error if `should_persist`
				// has not been updated to `DoPersist`.
				if should_persist != NotifyOption::DoPersist {
					debug_assert!(false, "Holding cells are cleared immediately");
					log_error!(
						self.logger,
						"Holding cells were freed in last-ditch cleanup. Please report this (performance) bug."
					);
				}
				should_persist = NotifyOption::DoPersist;
			}

			should_persist
		});
	}

	/// Indicates that the preimage for payment_hash is unknown or the received amount is incorrect
	/// after a PaymentClaimable event, failing the HTLC back to its origin and freeing resources
	/// along the path (including in our own channel on which we received it).
	///
	/// Note that in some cases around unclean shutdown, it is possible the payment may have
	/// already been claimed by you via [`ChannelManager::claim_funds`] prior to you seeing (a
	/// second copy of) the [`events::Event::PaymentClaimable`] event. Alternatively, the payment
	/// may have already been failed automatically by LDK if it was nearing its expiration time.
	///
	/// While LDK will never claim a payment automatically on your behalf (i.e. without you calling
	/// [`ChannelManager::claim_funds`]), you should still monitor for
	/// [`events::Event::PaymentClaimed`] events even for payments you intend to fail, especially on
	/// startup during which time claims that were in-progress at shutdown may be replayed.
	pub fn fail_htlc_backwards(&self, payment_hash: &PaymentHash) {
		let failure_code = FailureCode::IncorrectOrUnknownPaymentDetails;
		self.fail_htlc_backwards_with_reason(payment_hash, failure_code);
	}

	/// This is a variant of [`ChannelManager::fail_htlc_backwards`] that allows you to specify the
	/// reason for the failure.
	///
	/// See [`FailureCode`] for valid failure codes.
	pub fn fail_htlc_backwards_with_reason(
		&self, payment_hash: &PaymentHash, failure_code: FailureCode,
	) {
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(self);

		let removed_source =
			self.claimable_payments.lock().unwrap().claimable_payments.remove(payment_hash);
		if let Some(payment) = removed_source {
			for htlc in payment.htlcs {
				let reason = self.get_htlc_fail_reason_from_failure_code(failure_code, &htlc);
				let source = HTLCSource::PreviousHopData(htlc.prev_hop);
				let receiver = HTLCHandlingFailureType::Receive { payment_hash: *payment_hash };
				self.fail_htlc_backwards_internal(&source, &payment_hash, &reason, receiver, None);
			}
		}
	}

	/// Gets error data to form an [`HTLCFailReason`] given a [`FailureCode`] and [`ClaimableHTLC`].
	fn get_htlc_fail_reason_from_failure_code(
		&self, failure_code: FailureCode, htlc: &ClaimableHTLC,
	) -> HTLCFailReason {
		match failure_code {
			FailureCode::TemporaryNodeFailure => {
				HTLCFailReason::from_failure_code(failure_code.into())
			},
			FailureCode::RequiredNodeFeatureMissing => {
				HTLCFailReason::from_failure_code(failure_code.into())
			},
			FailureCode::IncorrectOrUnknownPaymentDetails => {
				let mut htlc_msat_height_data = htlc.value.to_be_bytes().to_vec();
				htlc_msat_height_data
					.extend_from_slice(&self.best_block.read().unwrap().height.to_be_bytes());
				HTLCFailReason::reason(failure_code.into(), htlc_msat_height_data)
			},
			FailureCode::InvalidOnionPayload(data) => {
				let fail_data = match data {
					Some((typ, offset)) => [BigSize(typ).encode(), offset.encode()].concat(),
					None => Vec::new(),
				};
				HTLCFailReason::reason(failure_code.into(), fail_data)
			},
		}
	}

	/// Gets an HTLC onion failure code and error data for an `UPDATE` error, given the error code
	/// that we want to return and a channel.
	///
	/// This is for failures on the channel on which the HTLC was *received*, not failures
	/// forwarding
	fn get_htlc_inbound_temp_fail_data(&self, reason: LocalHTLCFailureReason) -> Vec<u8> {
		debug_assert!(reason.is_temporary());
		debug_assert!(reason != LocalHTLCFailureReason::AmountBelowMinimum);
		debug_assert!(reason != LocalHTLCFailureReason::FeeInsufficient);
		debug_assert!(reason != LocalHTLCFailureReason::IncorrectCLTVExpiry);
		// at capacity, we write fields `disabled_flags` and `len`
		let mut enc = VecWriter(Vec::with_capacity(4));
		if reason == LocalHTLCFailureReason::ChannelDisabled {
			// No flags for `disabled_flags` are currently defined so they're always two zero bytes.
			// See https://github.com/lightning/bolts/blob/341ec84/04-onion-routing.md?plain=1#L1008
			0u16.write(&mut enc).expect("Writes cannot fail");
		}
		// See https://github.com/lightning/bolts/blob/247e83d/04-onion-routing.md?plain=1#L1414-L1415
		(0u16).write(&mut enc).expect("Writes cannot fail");
		enc.0
	}

	// Fail a list of HTLCs that were just freed from the holding cell. The HTLCs need to be
	// failed backwards or, if they were one of our outgoing HTLCs, then their failure needs to
	// be surfaced to the user.
	fn fail_holding_cell_htlcs(
		&self, mut htlcs_to_fail: Vec<(HTLCSource, PaymentHash)>, channel_id: ChannelId,
		counterparty_node_id: &PublicKey,
	) {
		let (failure_reason, onion_failure_data) = {
			let per_peer_state = self.per_peer_state.read().unwrap();
			if let Some(peer_state_mutex) = per_peer_state.get(counterparty_node_id) {
				let mut peer_state_lock = peer_state_mutex.lock().unwrap();
				let peer_state = &mut *peer_state_lock;
				match peer_state.channel_by_id.entry(channel_id) {
					hash_map::Entry::Occupied(chan_entry) => {
						if let Some(_chan) = chan_entry.get().as_funded() {
							let reason = LocalHTLCFailureReason::TemporaryChannelFailure;
							let data = self.get_htlc_inbound_temp_fail_data(reason);
							(reason, data)
						} else {
							// We shouldn't be trying to fail holding cell HTLCs on an unfunded channel.
							debug_assert!(false);
							(LocalHTLCFailureReason::UnknownNextPeer, Vec::new())
						}
					},
					hash_map::Entry::Vacant(_) => {
						(LocalHTLCFailureReason::UnknownNextPeer, Vec::new())
					},
				}
			} else {
				(LocalHTLCFailureReason::UnknownNextPeer, Vec::new())
			}
		};

		for (htlc_src, payment_hash) in htlcs_to_fail.drain(..) {
			let reason = HTLCFailReason::reason(failure_reason, onion_failure_data.clone());
			let receiver = HTLCHandlingFailureType::Forward {
				node_id: Some(counterparty_node_id.clone()),
				channel_id,
			};
			self.fail_htlc_backwards_internal(&htlc_src, &payment_hash, &reason, receiver, None);
		}
	}

	/// Fails an HTLC backwards to the sender of it to us.
	/// Note that we do not assume that channels corresponding to failed HTLCs are still available.
	fn fail_htlc_backwards_internal(
		&self, source: &HTLCSource, payment_hash: &PaymentHash, onion_error: &HTLCFailReason,
		failure_type: HTLCHandlingFailureType,
		mut from_monitor_update_completion: Option<PaymentCompleteUpdate>,
	) {
		// Ensure that no peer state channel storage lock is held when calling this function.
		// This ensures that future code doesn't introduce a lock-order requirement for
		// `forward_htlcs` to be locked after the `per_peer_state` peer locks, which calling
		// this function with any `per_peer_state` peer lock acquired would.
		#[cfg(debug_assertions)]
		for (_, peer) in self.per_peer_state.read().unwrap().iter() {
			debug_assert_ne!(peer.held_by_thread(), LockHeldState::HeldByThread);
		}

		//TODO: There is a timing attack here where if a node fails an HTLC back to us they can
		//identify whether we sent it or not based on the (I presume) very different runtime
		//between the branches here. We should make this async and move it into the forward HTLCs
		//timer handling.

		// Note that we MUST NOT end up calling methods on self.chain_monitor here - we're called
		// from block_connected which may run during initialization prior to the chain_monitor
		// being fully configured. See the docs for `ChannelManagerReadArgs` for more.
		match source {
			HTLCSource::OutboundRoute { ref path, ref session_priv, ref payment_id, .. } => {
				let logger = WithContext::for_payment(
					&self.logger,
					path.hops.first().map(|hop| hop.pubkey),
					None,
					Some(*payment_hash),
					*payment_id,
				);
				self.pending_outbound_payments.fail_htlc(
					source,
					payment_hash,
					onion_error,
					path,
					session_priv,
					payment_id,
					self.probing_cookie_secret,
					&self.secp_ctx,
					&self.pending_events,
					&mut from_monitor_update_completion,
					&logger,
				);
				if let Some(update) = from_monitor_update_completion {
					// If `fail_htlc` didn't `take` the post-event action, we should go ahead and
					// complete it here as the failure was duplicative - we've already handled it.
					// This can happen in rare cases where a MonitorUpdate is replayed after
					// restart because a ChannelMonitor wasn't persisted after it was applied (even
					// though the ChannelManager was).
					// For such cases, we also check that there's no existing pending event to
					// complete this action already, which we let finish instead.
					let action =
						EventCompletionAction::ReleasePaymentCompleteChannelMonitorUpdate(update);
					let have_action = {
						let pending_events = self.pending_events.lock().unwrap();
						pending_events.iter().any(|(_, act)| act.as_ref() == Some(&action))
					};
					if !have_action {
						self.handle_post_event_actions([action]);
					}
				}
			},
			HTLCSource::PreviousHopData(HTLCPreviousHopData {
				ref prev_outbound_scid_alias,
				ref htlc_id,
				ref incoming_packet_shared_secret,
				ref phantom_shared_secret,
				ref trampoline_shared_secret,
				outpoint: _,
				ref blinded_failure,
				ref channel_id,
				..
			}) => {
				log_trace!(
					WithContext::from(&self.logger, None, Some(*channel_id), Some(*payment_hash)),
					"Failing {}HTLC backwards from us: {:?}",
					if blinded_failure.is_some() { "blinded " } else { "" },
					onion_error
				);
				// In case of trampoline + phantom we prioritize the trampoline failure over the phantom failure.
				// TODO: Correctly wrap the error packet twice if failing back a trampoline + phantom HTLC.
				let secondary_shared_secret = trampoline_shared_secret.or(*phantom_shared_secret);
				let failure = match blinded_failure {
					Some(BlindedFailure::FromIntroductionNode) => {
						let blinded_onion_error = HTLCFailReason::reason(
							LocalHTLCFailureReason::InvalidOnionBlinding,
							vec![0; 32],
						);
						let err_packet = blinded_onion_error.get_encrypted_failure_packet(
							incoming_packet_shared_secret,
							&secondary_shared_secret,
						);
						HTLCForwardInfo::FailHTLC { htlc_id: *htlc_id, err_packet }
					},
					Some(BlindedFailure::FromBlindedNode) => HTLCForwardInfo::FailMalformedHTLC {
						htlc_id: *htlc_id,
						failure_code: LocalHTLCFailureReason::InvalidOnionBlinding.failure_code(),
						sha256_of_onion: [0; 32],
					},
					None => {
						let err_packet = onion_error.get_encrypted_failure_packet(
							incoming_packet_shared_secret,
							&secondary_shared_secret,
						);
						HTLCForwardInfo::FailHTLC { htlc_id: *htlc_id, err_packet }
					},
				};

				let mut forward_htlcs = self.forward_htlcs.lock().unwrap();
				match forward_htlcs.entry(*prev_outbound_scid_alias) {
					hash_map::Entry::Occupied(mut entry) => {
						entry.get_mut().push(failure);
					},
					hash_map::Entry::Vacant(entry) => {
						entry.insert(vec![failure]);
					},
				}
				mem::drop(forward_htlcs);
				let mut pending_events = self.pending_events.lock().unwrap();
				pending_events.push_back((
					events::Event::HTLCHandlingFailed {
						prev_channel_id: *channel_id,
						failure_type,
						failure_reason: Some(onion_error.into()),
					},
					None,
				));
			},
		}
	}

	/// Provides a payment preimage in response to [`Event::PaymentClaimable`], generating any
	/// [`MessageSendEvent`]s needed to claim the payment.
	///
	/// This method is guaranteed to ensure the payment has been claimed but only if the current
	/// height is strictly below [`Event::PaymentClaimable::claim_deadline`]. To avoid race
	/// conditions, you should wait for an [`Event::PaymentClaimed`] before considering the payment
	/// successful. It will generally be available in the next [`process_pending_events`] call.
	///
	/// Note that if you did not set an `amount_msat` when calling [`create_inbound_payment`] or
	/// [`create_inbound_payment_for_hash`] you must check that the amount in the `PaymentClaimable`
	/// event matches your expectation. If you fail to do so and call this method, you may provide
	/// the sender "proof-of-payment" when they did not fulfill the full expected payment.
	///
	/// This function will fail the payment if it has custom TLVs with even type numbers, as we
	/// will assume they are unknown. If you intend to accept even custom TLVs, you should use
	/// [`claim_funds_with_known_custom_tlvs`].
	///
	/// [`Event::PaymentClaimable`]: crate::events::Event::PaymentClaimable
	/// [`Event::PaymentClaimable::claim_deadline`]: crate::events::Event::PaymentClaimable::claim_deadline
	/// [`Event::PaymentClaimed`]: crate::events::Event::PaymentClaimed
	/// [`process_pending_events`]: EventsProvider::process_pending_events
	/// [`create_inbound_payment`]: Self::create_inbound_payment
	/// [`create_inbound_payment_for_hash`]: Self::create_inbound_payment_for_hash
	/// [`claim_funds_with_known_custom_tlvs`]: Self::claim_funds_with_known_custom_tlvs
	pub fn claim_funds(&self, payment_preimage: PaymentPreimage) {
		self.claim_payment_internal(payment_preimage, false);
	}

	/// This is a variant of [`claim_funds`] that allows accepting a payment with custom TLVs with
	/// even type numbers.
	///
	/// # Note
	///
	/// You MUST check you've understood all even TLVs before using this to
	/// claim, otherwise you may unintentionally agree to some protocol you do not understand.
	///
	/// [`claim_funds`]: Self::claim_funds
	pub fn claim_funds_with_known_custom_tlvs(&self, payment_preimage: PaymentPreimage) {
		self.claim_payment_internal(payment_preimage, true);
	}

	fn claim_payment_internal(&self, payment_preimage: PaymentPreimage, custom_tlvs_known: bool) {
		let payment_hash = PaymentHash(Sha256::hash(&payment_preimage.0).to_byte_array());

		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(self);

		let (sources, claiming_payment) = {
			let res = self.claimable_payments.lock().unwrap().begin_claiming_payment(
				payment_hash,
				&self.node_signer,
				&self.logger,
				&self.inbound_payment_id_secret,
				custom_tlvs_known,
			);

			match res {
				Ok((htlcs, payment_info)) => (htlcs, payment_info),
				Err(htlcs) => {
					for htlc in htlcs {
						let reason = self.get_htlc_fail_reason_from_failure_code(
							FailureCode::InvalidOnionPayload(None),
							&htlc,
						);
						let source = HTLCSource::PreviousHopData(htlc.prev_hop);
						let receiver = HTLCHandlingFailureType::Receive { payment_hash };
						self.fail_htlc_backwards_internal(
							&source,
							&payment_hash,
							&reason,
							receiver,
							None,
						);
					}
					return;
				},
			}
		};
		debug_assert!(!sources.is_empty());

		// Just in case one HTLC has been failed between when we generated the `PaymentClaimable`
		// and when we got here we need to check that the amount we're about to claim matches the
		// amount we told the user in the last `PaymentClaimable`. We also do a sanity-check that
		// the MPP parts all have the same `total_msat`.
		let mut claimable_amt_msat = 0;
		let mut prev_total_msat = None;
		let mut expected_amt_msat = None;
		let mut valid_mpp = true;
		let mut errs = Vec::new();
		let per_peer_state = self.per_peer_state.read().unwrap();
		for htlc in sources.iter() {
			if prev_total_msat.is_some() && prev_total_msat != Some(htlc.total_msat) {
				log_error!(self.logger, "Somehow ended up with an MPP payment with different expected total amounts - this should not be reachable!");
				debug_assert!(false);
				valid_mpp = false;
				break;
			}
			prev_total_msat = Some(htlc.total_msat);

			if expected_amt_msat.is_some() && expected_amt_msat != htlc.total_value_received {
				log_error!(self.logger, "Somehow ended up with an MPP payment with different received total amounts - this should not be reachable!");
				debug_assert!(false);
				valid_mpp = false;
				break;
			}
			expected_amt_msat = htlc.total_value_received;
			claimable_amt_msat += htlc.value;
		}
		mem::drop(per_peer_state);
		if sources.is_empty() || expected_amt_msat.is_none() {
			self.claimable_payments.lock().unwrap().pending_claiming_payments.remove(&payment_hash);
			log_info!(
				self.logger,
				"Attempted to claim an incomplete payment which no longer had any available HTLCs!"
			);
			return;
		}
		if claimable_amt_msat != expected_amt_msat.unwrap() {
			self.claimable_payments.lock().unwrap().pending_claiming_payments.remove(&payment_hash);
			log_info!(self.logger, "Attempted to claim an incomplete payment, expected {} msat, had {} available to claim.",
				expected_amt_msat.unwrap(), claimable_amt_msat);
			return;
		}
		if valid_mpp {
			let mpp_parts: Vec<_> = sources
				.iter()
				.filter_map(|htlc| {
					if let Some(cp_id) = htlc.prev_hop.counterparty_node_id {
						Some(MPPClaimHTLCSource {
							counterparty_node_id: cp_id,
							funding_txo: htlc.prev_hop.outpoint,
							channel_id: htlc.prev_hop.channel_id,
							htlc_id: htlc.prev_hop.htlc_id,
						})
					} else {
						None
					}
				})
				.collect();
			let pending_mpp_claim_ptr_opt = if sources.len() > 1 {
				let mut channels_without_preimage = Vec::with_capacity(mpp_parts.len());
				for part in mpp_parts.iter() {
					let chan = (part.counterparty_node_id, part.channel_id);
					if !channels_without_preimage.contains(&chan) {
						channels_without_preimage.push(chan);
					}
				}
				Some(Arc::new(Mutex::new(PendingMPPClaim {
					channels_without_preimage,
					channels_with_preimage: Vec::new(),
				})))
			} else {
				None
			};
			let payment_info = Some(PaymentClaimDetails { mpp_parts, claiming_payment });
			for htlc in sources {
				let this_mpp_claim =
					pending_mpp_claim_ptr_opt.as_ref().map(|pending_mpp_claim| {
						let counterparty_id = htlc.prev_hop.counterparty_node_id;
						let counterparty_id = counterparty_id
							.expect("Prior to upgrading to LDK 0.1, all pending HTLCs forwarded by LDK 0.0.123 or before must be resolved. It appears at least one claimable payment was not resolved. Please downgrade to LDK 0.0.125 and resolve the HTLC by claiming the payment prior to upgrading.");
						let claim_ptr = PendingMPPClaimPointer(Arc::clone(pending_mpp_claim));
						(counterparty_id, htlc.prev_hop.channel_id, claim_ptr)
					});
				let raa_blocker = pending_mpp_claim_ptr_opt.as_ref().map(|pending_claim| {
					RAAMonitorUpdateBlockingAction::ClaimedMPPPayment {
						pending_claim: PendingMPPClaimPointer(Arc::clone(pending_claim)),
					}
				});

				// Create new attribution data as the final hop. Always report a zero hold time, because reporting a
				// non-zero value will not make a difference in the penalty that may be applied by the sender. If there
				// is a phantom hop, we need to double-process.
				let attribution_data =
					if let Some(phantom_secret) = htlc.prev_hop.phantom_shared_secret {
						let attribution_data =
							process_fulfill_attribution_data(None, &phantom_secret, 0);
						Some(attribution_data)
					} else {
						None
					};

				let attribution_data = process_fulfill_attribution_data(
					attribution_data,
					&htlc.prev_hop.incoming_packet_shared_secret,
					0,
				);

				self.claim_funds_from_hop(
					htlc.prev_hop,
					payment_preimage,
					payment_info.clone(),
					Some(attribution_data),
					|_, definitely_duplicate| {
						debug_assert!(
							!definitely_duplicate,
							"We shouldn't claim duplicatively from a payment"
						);
						(
							Some(MonitorUpdateCompletionAction::PaymentClaimed {
								payment_hash,
								pending_mpp_claim: this_mpp_claim,
							}),
							raa_blocker,
						)
					},
				);
			}
		} else {
			for htlc in sources {
				let err_data =
					invalid_payment_err_data(htlc.value, self.best_block.read().unwrap().height);
				let source = HTLCSource::PreviousHopData(htlc.prev_hop);
				let reason = HTLCFailReason::reason(
					LocalHTLCFailureReason::IncorrectPaymentDetails,
					err_data,
				);
				let receiver = HTLCHandlingFailureType::Receive { payment_hash };
				self.fail_htlc_backwards_internal(&source, &payment_hash, &reason, receiver, None);
			}
			self.claimable_payments.lock().unwrap().pending_claiming_payments.remove(&payment_hash);
		}

		// Now we can handle any errors which were generated.
		for (counterparty_node_id, err) in errs.drain(..) {
			let res: Result<(), _> = Err(err);
			let _ = self.handle_error(res, counterparty_node_id);
		}
	}

	fn claim_funds_from_hop<
		ComplFunc: FnOnce(
			Option<u64>,
			bool,
		) -> (Option<MonitorUpdateCompletionAction>, Option<RAAMonitorUpdateBlockingAction>),
	>(
		&self, prev_hop: HTLCPreviousHopData, payment_preimage: PaymentPreimage,
		payment_info: Option<PaymentClaimDetails>, attribution_data: Option<AttributionData>,
		completion_action: ComplFunc,
	) {
		let counterparty_node_id = prev_hop.counterparty_node_id.or_else(|| {
			let short_to_chan_info = self.short_to_chan_info.read().unwrap();
			short_to_chan_info.get(&prev_hop.prev_outbound_scid_alias).map(|(cp_id, _)| *cp_id)
		});
		let counterparty_node_id = if let Some(node_id) = counterparty_node_id {
			node_id
		} else {
			let payment_hash: PaymentHash = payment_preimage.into();
			panic!(
				"Prior to upgrading to LDK 0.1, all pending HTLCs forwarded by LDK 0.0.123 or before must be resolved. It appears at least the HTLC with payment_hash {payment_hash} (preimage {payment_preimage}) was not resolved. Please downgrade to LDK 0.0.125 and resolve the HTLC prior to upgrading.",
			);
		};

		let htlc_source = HTLCClaimSource {
			counterparty_node_id,
			funding_txo: prev_hop.outpoint,
			channel_id: prev_hop.channel_id,
			htlc_id: prev_hop.htlc_id,
		};
		self.claim_mpp_part(
			htlc_source,
			payment_preimage,
			payment_info,
			attribution_data,
			completion_action,
		)
	}

	fn claim_mpp_part<
		ComplFunc: FnOnce(
			Option<u64>,
			bool,
		) -> (Option<MonitorUpdateCompletionAction>, Option<RAAMonitorUpdateBlockingAction>),
	>(
		&self, prev_hop: HTLCClaimSource, payment_preimage: PaymentPreimage,
		payment_info: Option<PaymentClaimDetails>, attribution_data: Option<AttributionData>,
		completion_action: ComplFunc,
	) {
		//TODO: Delay the claimed_funds relaying just like we do outbound relay!

		// If we haven't yet run background events assume we're still deserializing and shouldn't
		// actually pass `ChannelMonitorUpdate`s to users yet. Instead, queue them up as
		// `BackgroundEvent`s.
		let during_init = !self.background_events_processed_since_startup.load(Ordering::Acquire);

		// As we may call handle_monitor_update_completion_actions in rather rare cases, check that
		// the required mutexes are not held before we start.
		debug_assert_ne!(self.pending_events.held_by_thread(), LockHeldState::HeldByThread);
		debug_assert_ne!(self.claimable_payments.held_by_thread(), LockHeldState::HeldByThread);

		let per_peer_state = self.per_peer_state.read().unwrap();
		let chan_id = prev_hop.channel_id;

		const MISSING_MON_ERROR: &'static str =
			"If we're going to claim an HTLC against a channel, we should always have *some* state for the channel, even if just the latest ChannelMonitor update_id. This failure indicates we need to claim an HTLC from a channel for which we did not have a ChannelMonitor at startup and didn't create one while running.";

		let mut peer_state_lock = per_peer_state
			.get(&prev_hop.counterparty_node_id)
			.map(|peer_mutex| peer_mutex.lock().unwrap())
			.expect(MISSING_MON_ERROR);

		{
			let peer_state = &mut *peer_state_lock;
			if let hash_map::Entry::Occupied(mut chan_entry) =
				peer_state.channel_by_id.entry(chan_id)
			{
				if let Some(chan) = chan_entry.get_mut().as_funded_mut() {
					let logger = WithChannelContext::from(&self.logger, &chan.context, None);
					let fulfill_res = chan.get_update_fulfill_htlc_and_commit(
						prev_hop.htlc_id,
						payment_preimage,
						payment_info,
						attribution_data,
						&&logger,
					);

					match fulfill_res {
						UpdateFulfillCommitFetch::NewClaim { htlc_value_msat, monitor_update } => {
							let (action_opt, raa_blocker_opt) =
								completion_action(Some(htlc_value_msat), false);
							if let Some(action) = action_opt {
								log_trace!(
									logger,
									"Tracking monitor update completion action: {:?}",
									action
								);
								peer_state
									.monitor_update_blocked_actions
									.entry(chan_id)
									.or_insert(Vec::new())
									.push(action);
							}
							if let Some(raa_blocker) = raa_blocker_opt {
								peer_state
									.actions_blocking_raa_monitor_updates
									.entry(chan_id)
									.or_insert_with(Vec::new)
									.push(raa_blocker);
							}
							if let Some(data) = self.handle_new_monitor_update(
								&mut peer_state.in_flight_monitor_updates,
								&mut peer_state.monitor_update_blocked_actions,
								&mut peer_state.pending_msg_events,
								peer_state.is_connected,
								chan,
								prev_hop.funding_txo,
								monitor_update,
							) {
								mem::drop(peer_state_lock);
								mem::drop(per_peer_state);
								self.handle_post_monitor_update_chan_resume(data);
							}
						},
						UpdateFulfillCommitFetch::DuplicateClaim {} => {
							let (action_opt, raa_blocker_opt) = completion_action(None, true);
							if let Some(raa_blocker) = raa_blocker_opt {
								// If we're making a claim during startup, its a replay of a
								// payment claim from a `ChannelMonitor`. In some cases (MPP or
								// if the HTLC was only recently removed) we make such claims
								// after an HTLC has been removed from a channel entirely, and
								// thus the RAA blocker may have long since completed.
								//
								// However, its possible that the `ChannelMonitorUpdate` containing
								// the preimage never completed and is still pending. In that case,
								// we need to re-add the RAA blocker, which we do here. Handling
								// the post-update action, below, will remove it again.
								//
								// In any other case (i.e. not during startup), the RAA blocker
								// must still be present and blocking RAAs.
								let actions = &mut peer_state.actions_blocking_raa_monitor_updates;
								let actions_list = actions.entry(chan_id).or_insert_with(Vec::new);
								if !actions_list.contains(&raa_blocker) {
									debug_assert!(during_init);
									actions_list.push(raa_blocker);
								}
							}
							let action = if let Some(action) = action_opt {
								action
							} else {
								return;
							};

							// If there are monitor updates in flight, we may be in the case
							// described above, replaying a claim on startup which needs an RAA
							// blocker to remain blocked. Thus, in such a case we simply push the
							// post-update action to the blocked list and move on.
							// In any case, we should err on the side of caution and not process
							// the post-update action no matter the situation.
							let in_flight_mons = peer_state.in_flight_monitor_updates.get(&chan_id);
							if in_flight_mons.map(|(_, mons)| !mons.is_empty()).unwrap_or(false) {
								peer_state
									.monitor_update_blocked_actions
									.entry(chan_id)
									.or_insert_with(Vec::new)
									.push(action);
								return;
							}

							mem::drop(peer_state_lock);

							log_trace!(logger, "Completing monitor update completion action as claim was redundant: {:?}",
								action);
							if let MonitorUpdateCompletionAction::FreeOtherChannelImmediately {
								downstream_counterparty_node_id: node_id,
								blocking_action: blocker,
								downstream_channel_id: channel_id,
							} = action
							{
								if let Some(peer_state_mtx) = per_peer_state.get(&node_id) {
									let mut peer_state = peer_state_mtx.lock().unwrap();
									if let Some(blockers) = peer_state
										.actions_blocking_raa_monitor_updates
										.get_mut(&channel_id)
									{
										let mut found_blocker = false;
										blockers.retain(|iter| {
											// Note that we could actually be blocked, in
											// which case we need to only remove the one
											// blocker which was added duplicatively.
											let first_blocker = !found_blocker;
											if *iter == blocker {
												found_blocker = true;
											}
											*iter != blocker || !first_blocker
										});
										debug_assert!(found_blocker);
									}
								} else {
									debug_assert!(false);
								}
							} else if matches!(
								action,
								MonitorUpdateCompletionAction::PaymentClaimed { .. }
							) {
								debug_assert!(during_init,
									"Duplicate claims should always either be for forwarded payments(freeing another channel immediately) or during init (for claim replay)");
								mem::drop(per_peer_state);
								self.handle_monitor_update_completion_actions([action]);
							} else {
								debug_assert!(false,
									"Duplicate claims should always either be for forwarded payments(freeing another channel immediately) or during init (for claim replay)");
								return;
							};
						},
					}
				}
				return;
			}
		}

		let peer_state = &mut *peer_state_lock;

		let update_id = if let Some(latest_update_id) =
			peer_state.closed_channel_monitor_update_ids.get_mut(&chan_id)
		{
			*latest_update_id = latest_update_id.saturating_add(1);
			*latest_update_id
		} else {
			let err = "We need the latest ChannelMonitorUpdate ID to build a new update.
This should have been checked for availability on startup but somehow it is no longer available.
This indicates a bug inside LDK. Please report this error at https://github.com/lightningdevkit/rust-lightning/issues/new";
			log_error!(self.logger, "{}", err);
			panic!("{}", err);
		};

		let preimage_update = ChannelMonitorUpdate {
			update_id,
			updates: vec![ChannelMonitorUpdateStep::PaymentPreimage {
				payment_preimage,
				payment_info,
			}],
			channel_id: Some(prev_hop.channel_id),
		};

		// We don't have any idea if this is a duplicate claim without interrogating the
		// `ChannelMonitor`, so we just always queue up the completion action after the
		// `ChannelMonitorUpdate` we're about to generate. This may result in a duplicate `Event`,
		// but note that `Event`s are generally always allowed to be duplicative (and it's
		// specifically noted in `PaymentForwarded`).
		let (action_opt, raa_blocker_opt) = completion_action(None, false);

		if let Some(raa_blocker) = raa_blocker_opt {
			peer_state
				.actions_blocking_raa_monitor_updates
				.entry(prev_hop.channel_id)
				.or_default()
				.push(raa_blocker);
		}

		// Given the fact that we're in a bit of a weird edge case, its worth hashing the preimage
		// to include the `payment_hash` in the log metadata here.
		let payment_hash = payment_preimage.into();
		let logger = WithContext::from(
			&self.logger,
			Some(prev_hop.counterparty_node_id),
			Some(chan_id),
			Some(payment_hash),
		);

		if let Some(action) = action_opt {
			log_trace!(
				logger,
				"Tracking monitor update completion action for closed channel: {:?}",
				action
			);
			peer_state
				.monitor_update_blocked_actions
				.entry(chan_id)
				.or_insert(Vec::new())
				.push(action);
		}

		if let Some(actions) = self.handle_post_close_monitor_update(
			&mut peer_state.in_flight_monitor_updates,
			&mut peer_state.monitor_update_blocked_actions,
			prev_hop.funding_txo,
			preimage_update,
			prev_hop.counterparty_node_id,
			chan_id,
		) {
			mem::drop(peer_state_lock);
			mem::drop(per_peer_state);
			self.handle_monitor_update_completion_actions(actions);
		}
	}

	fn finalize_claims(&self, sources: Vec<(HTLCSource, Option<AttributionData>)>) {
		// Decode attribution data to hold times.
		let hold_times = sources.into_iter().filter_map(|(source, attribution_data)| {
			if let HTLCSource::OutboundRoute { ref session_priv, ref path, .. } = source {
				// If the path has trampoline hops, we need to hash the session private key to get the outer session key.
				let derived_key;
				let session_priv = if path.has_trampoline_hops() {
					let session_priv_hash =
						Sha256::hash(&session_priv.secret_bytes()).to_byte_array();
					derived_key = SecretKey::from_slice(&session_priv_hash[..]).unwrap();
					&derived_key
				} else {
					session_priv
				};

				let hold_times = attribution_data.map_or(Vec::new(), |attribution_data| {
					decode_fulfill_attribution_data(
						&self.secp_ctx,
						&self.logger,
						path,
						session_priv,
						attribution_data,
					)
				});

				Some((source, hold_times))
			} else {
				None
			}
		});

		self.pending_outbound_payments.finalize_claims(hold_times, &self.pending_events);
	}

	fn claim_funds_internal(
		&self, source: HTLCSource, payment_preimage: PaymentPreimage,
		forwarded_htlc_value_msat: Option<u64>, skimmed_fee_msat: Option<u64>, from_onchain: bool,
		next_channel_counterparty_node_id: PublicKey, next_channel_outpoint: OutPoint,
		next_channel_id: ChannelId, next_user_channel_id: Option<u128>,
		attribution_data: Option<AttributionData>, send_timestamp: Option<Duration>,
	) {
		let startup_replay =
			!self.background_events_processed_since_startup.load(Ordering::Acquire);
		let htlc_id = SentHTLCId::from_source(&source);
		match source {
			HTLCSource::OutboundRoute {
				session_priv, payment_id, path, bolt12_invoice, ..
			} => {
				debug_assert!(!startup_replay,
					"We don't support claim_htlc claims during startup - monitors may not be available yet");
				debug_assert_eq!(next_channel_counterparty_node_id, path.hops[0].pubkey);

				let mut ev_completion_action = if from_onchain {
					let release = PaymentCompleteUpdate {
						counterparty_node_id: next_channel_counterparty_node_id,
						channel_funding_outpoint: next_channel_outpoint,
						channel_id: next_channel_id,
						htlc_id,
					};
					Some(EventCompletionAction::ReleasePaymentCompleteChannelMonitorUpdate(release))
				} else {
					Some(EventCompletionAction::ReleaseRAAChannelMonitorUpdate {
						channel_funding_outpoint: Some(next_channel_outpoint),
						channel_id: next_channel_id,
						counterparty_node_id: path.hops[0].pubkey,
					})
				};
				let logger = WithContext::for_payment(
					&self.logger,
					path.hops.first().map(|hop| hop.pubkey),
					None,
					Some(payment_preimage.into()),
					payment_id,
				);
				self.pending_outbound_payments.claim_htlc(
					payment_id,
					payment_preimage,
					bolt12_invoice,
					session_priv,
					path,
					from_onchain,
					&mut ev_completion_action,
					&self.pending_events,
					&logger,
				);
				// If an event was generated, `claim_htlc` set `ev_completion_action` to None, if
				// not, we should go ahead and run it now (as the claim was duplicative), at least
				// if a PaymentClaimed event with the same action isn't already pending.
				let have_action = if ev_completion_action.is_some() {
					let pending_events = self.pending_events.lock().unwrap();
					pending_events.iter().any(|(_, act)| *act == ev_completion_action)
				} else {
					false
				};
				if !have_action {
					self.handle_post_event_actions(ev_completion_action);
				}
			},
			HTLCSource::PreviousHopData(hop_data) => {
				let prev_channel_id = hop_data.channel_id;
				let prev_user_channel_id = hop_data.user_channel_id;
				let prev_node_id = hop_data.counterparty_node_id;
				let completed_blocker =
					RAAMonitorUpdateBlockingAction::from_prev_hop_data(&hop_data);

				// Obtain hold time, if available.
				let hold_time = hold_time_since(send_timestamp).unwrap_or(0);

				// If attribution data was received from downstream, we shift it and get it ready for adding our hold
				// time. Note that fulfilled HTLCs take a fast path to the incoming side. We don't need to wait for RAA
				// to record the hold time like we do for failed HTLCs.
				let attribution_data = process_fulfill_attribution_data(
					attribution_data,
					&hop_data.incoming_packet_shared_secret,
					hold_time,
				);

				#[cfg(test)]
				let claiming_chan_funding_outpoint = hop_data.outpoint;
				self.claim_funds_from_hop(
					hop_data,
					payment_preimage,
					None,
					Some(attribution_data),
					|htlc_claim_value_msat, definitely_duplicate| {
						let chan_to_release = Some(EventUnblockedChannel {
							counterparty_node_id: next_channel_counterparty_node_id,
							funding_txo: next_channel_outpoint,
							channel_id: next_channel_id,
							blocking_action: completed_blocker,
						});

						if definitely_duplicate && startup_replay {
							// On startup we may get redundant claims which are related to
							// monitor updates still in flight. In that case, we shouldn't
							// immediately free, but instead let that monitor update complete
							// in the background.
							#[cfg(test)]
							{
								let per_peer_state = self.per_peer_state.deadlocking_read();
								// The channel we'd unblock should already be closed, or...
								let channel_closed = per_peer_state
									.get(&next_channel_counterparty_node_id)
									.map(|lck| lck.deadlocking_lock())
									.map(|peer| !peer.channel_by_id.contains_key(&next_channel_id))
									.unwrap_or(true);
								let background_events =
									self.pending_background_events.lock().unwrap();
								// there should be a `BackgroundEvent` pending...
								let matching_bg_event =
									background_events.iter().any(|ev| {
										match ev {
											// to apply a monitor update that blocked the claiming channel,
											BackgroundEvent::MonitorUpdateRegeneratedOnStartup {
												funding_txo, update, ..
											} => {
												if *funding_txo == claiming_chan_funding_outpoint {
													assert!(update.updates.iter().any(|upd|
														if let ChannelMonitorUpdateStep::PaymentPreimage {
															payment_preimage: update_preimage, ..
														} = upd {
															payment_preimage == *update_preimage
														} else { false }
													), "{:?}", update);
													true
												} else { false }
											},
											// or the monitor update has completed and will unblock
											// immediately once we get going.
											BackgroundEvent::MonitorUpdatesComplete {
												channel_id, ..
											} =>
												*channel_id == prev_channel_id,
										}
									});
								assert!(
									channel_closed || matching_bg_event,
									"{:?}",
									*background_events
								);
							}
							(None, None)
						} else if definitely_duplicate {
							if let Some(other_chan) = chan_to_release {
								(Some(MonitorUpdateCompletionAction::FreeOtherChannelImmediately {
									downstream_counterparty_node_id: other_chan.counterparty_node_id,
									downstream_channel_id: other_chan.channel_id,
									blocking_action: other_chan.blocking_action,
								}), None)
							} else {
								(None, None)
							}
						} else {
							let total_fee_earned_msat =
								if let Some(forwarded_htlc_value) = forwarded_htlc_value_msat {
									if let Some(claimed_htlc_value) = htlc_claim_value_msat {
										Some(claimed_htlc_value - forwarded_htlc_value)
									} else {
										None
									}
								} else {
									None
								};
							debug_assert!(
								skimmed_fee_msat <= total_fee_earned_msat,
								"skimmed_fee_msat must always be included in total_fee_earned_msat"
							);
							(
								Some(MonitorUpdateCompletionAction::EmitEventAndFreeOtherChannel {
									event: events::Event::PaymentForwarded {
										prev_channel_id: Some(prev_channel_id),
										next_channel_id: Some(next_channel_id),
										prev_user_channel_id,
										next_user_channel_id,
										prev_node_id,
										next_node_id: Some(next_channel_counterparty_node_id),
										total_fee_earned_msat,
										skimmed_fee_msat,
										claim_from_onchain_tx: from_onchain,
										outbound_amount_forwarded_msat: forwarded_htlc_value_msat,
									},
									downstream_counterparty_and_funding_outpoint: chan_to_release,
								}),
								None,
							)
						}
					},
				);
			},
		}
	}

	/// Gets the node_id held by this ChannelManager
	pub fn get_our_node_id(&self) -> PublicKey {
		self.our_network_pubkey
	}

	/// Handles actions which need to complete after a [`ChannelMonitorUpdate`] has been applied
	/// which can happen after the per-peer state lock has been dropped.
	fn post_monitor_update_unlock(
		&self, channel_id: ChannelId, counterparty_node_id: PublicKey, funding_txo: OutPoint,
		user_channel_id: u128, unbroadcasted_batch_funding_txid: Option<Txid>,
		update_actions: Vec<MonitorUpdateCompletionAction>, htlc_forwards: Vec<PendingAddHTLCInfo>,
		decode_update_add_htlcs: Option<(u64, Vec<msgs::UpdateAddHTLC>)>,
		finalized_claimed_htlcs: Vec<(HTLCSource, Option<AttributionData>)>,
		failed_htlcs: Vec<(HTLCSource, PaymentHash, HTLCFailReason)>,
		committed_outbound_htlc_sources: Vec<(HTLCPreviousHopData, u64)>,
	) {
		// If the channel belongs to a batch funding transaction, the progress of the batch
		// should be updated as we have received funding_signed and persisted the monitor.
		if let Some(txid) = unbroadcasted_batch_funding_txid {
			let mut funding_batch_states = self.funding_batch_states.lock().unwrap();
			let mut batch_completed = false;
			if let Some(batch_state) = funding_batch_states.get_mut(&txid) {
				let channel_state = batch_state.iter_mut().find(|(chan_id, pubkey, _)| {
					*chan_id == channel_id && *pubkey == counterparty_node_id
				});
				if let Some(channel_state) = channel_state {
					channel_state.2 = true;
				} else {
					debug_assert!(false, "Missing batch state after initial monitor update");
				}
				batch_completed = batch_state.iter().all(|(_, _, completed)| *completed);
			} else {
				debug_assert!(false, "Missing batch state after initial monitor update");
			}

			// When all channels in a batched funding transaction have become ready, it is not necessary
			// to track the progress of the batch anymore and the state of the channels can be updated.
			if batch_completed {
				let removed_batch_state = funding_batch_states.remove(&txid).into_iter().flatten();
				let per_peer_state = self.per_peer_state.read().unwrap();
				let mut batch_funding_tx = None;
				let mut batch_channels = Vec::new();
				for (channel_id, counterparty_node_id, _) in removed_batch_state {
					if let Some(peer_state_mutex) = per_peer_state.get(&counterparty_node_id) {
						let mut peer_state = peer_state_mutex.lock().unwrap();

						let chan = peer_state.channel_by_id.get_mut(&channel_id);
						if let Some(funded_chan) = chan.and_then(Channel::as_funded_mut) {
							batch_funding_tx = batch_funding_tx.or_else(|| {
								funded_chan.context.unbroadcasted_funding(&funded_chan.funding)
							});
							funded_chan.set_batch_ready();
							batch_channels.push((counterparty_node_id, channel_id));

							let mut pending_events = self.pending_events.lock().unwrap();
							emit_channel_pending_event!(pending_events, funded_chan);
						}
					}
				}
				if let Some(tx) = batch_funding_tx {
					log_info!(self.logger, "Broadcasting batch funding tx {}", tx.compute_txid());
					self.tx_broadcaster.broadcast_transactions(&[(
						&tx,
						TransactionType::Funding { channels: batch_channels },
					)]);
				}
			}
		}

		self.handle_monitor_update_completion_actions(update_actions);

		self.forward_htlcs(htlc_forwards);
		if let Some(decode) = decode_update_add_htlcs {
			self.push_decode_update_add_htlcs(decode);
		}
		self.finalize_claims(finalized_claimed_htlcs);
		for failure in failed_htlcs {
			let receiver = HTLCHandlingFailureType::Forward {
				node_id: Some(counterparty_node_id),
				channel_id,
			};
			self.fail_htlc_backwards_internal(&failure.0, &failure.1, &failure.2, receiver, None);
		}
		self.prune_persisted_inbound_htlc_onions(
			channel_id,
			counterparty_node_id,
			funding_txo,
			user_channel_id,
			committed_outbound_htlc_sources,
		);
	}

	fn handle_monitor_update_completion_actions<
		I: IntoIterator<Item = MonitorUpdateCompletionAction>,
	>(
		&self, actions: I,
	) {
		debug_assert_ne!(self.pending_events.held_by_thread(), LockHeldState::HeldByThread);
		debug_assert_ne!(self.claimable_payments.held_by_thread(), LockHeldState::HeldByThread);
		debug_assert_ne!(self.per_peer_state.held_by_thread(), LockHeldState::HeldByThread);

		let mut freed_channels = Vec::new();

		for action in actions.into_iter() {
			match action {
				MonitorUpdateCompletionAction::PaymentClaimed {
					payment_hash,
					pending_mpp_claim,
				} => {
					let (peer_id, chan_id) = pending_mpp_claim
						.as_ref()
						.map(|c| (Some(c.0), Some(c.1)))
						.unwrap_or_default();
					let logger =
						WithContext::from(&self.logger, peer_id, chan_id, Some(payment_hash));
					log_trace!(logger, "Handling PaymentClaimed monitor update completion action");

					if let Some((cp_node_id, chan_id, claim_ptr)) = pending_mpp_claim {
						let per_peer_state = self.per_peer_state.read().unwrap();
						per_peer_state.get(&cp_node_id).map(|peer_state_mutex| {
							let mut peer_state = peer_state_mutex.lock().unwrap();
							let blockers_entry =
								peer_state.actions_blocking_raa_monitor_updates.entry(chan_id);
							if let btree_map::Entry::Occupied(mut blockers) = blockers_entry {
								blockers.get_mut().retain(|blocker| {
									let pending_claim = match &blocker {
										RAAMonitorUpdateBlockingAction::ClaimedMPPPayment {
											pending_claim,
										} => pending_claim,
										_ => return true,
									};
									if *pending_claim != claim_ptr {
										return true;
									}
									let mut claim_state_lock = pending_claim.0.lock().unwrap();
									let claim_state = &mut *claim_state_lock;
									claim_state.channels_without_preimage.retain(|(cp, cid)| {
										let this_claim = *cp == cp_node_id && *cid == chan_id;
										if this_claim {
											claim_state.channels_with_preimage.push((*cp, *cid));
											false
										} else {
											true
										}
									});
									if claim_state.channels_without_preimage.is_empty() {
										for (cp, cid) in claim_state.channels_with_preimage.iter() {
											let freed_chan = (*cp, *cid, blocker.clone());
											freed_channels.push(freed_chan);
										}
									}
									!claim_state.channels_without_preimage.is_empty()
								});
								if blockers.get().is_empty() {
									blockers.remove();
								}
							}
						});
					}

					let payment = self
						.claimable_payments
						.lock()
						.unwrap()
						.pending_claiming_payments
						.remove(&payment_hash);
					if let Some(ClaimingPayment {
						amount_msat,
						payment_purpose: purpose,
						receiver_node_id,
						htlcs,
						sender_intended_value: sender_intended_total_msat,
						onion_fields,
						payment_id,
						durable_preimage_channel,
					}) = payment
					{
						let event = events::Event::PaymentClaimed {
							payment_hash,
							purpose,
							amount_msat,
							receiver_node_id: Some(receiver_node_id),
							htlcs,
							sender_intended_total_msat,
							onion_fields,
							payment_id,
						};
						let action = if let Some((outpoint, counterparty_node_id, channel_id)) =
							durable_preimage_channel
						{
							Some(EventCompletionAction::ReleaseRAAChannelMonitorUpdate {
								channel_funding_outpoint: Some(outpoint),
								counterparty_node_id,
								channel_id,
							})
						} else {
							None
						};
						let event_action = (event, action);
						let mut pending_events = self.pending_events.lock().unwrap();
						// If we're replaying a claim on startup we may end up duplicating an event
						// that's already in our queue, so check before we push another one. The
						// `payment_id` should suffice to ensure we never spuriously drop a second
						// event for a duplicate payment.
						if !pending_events.contains(&event_action) {
							log_trace!(
								logger,
								"Queuing PaymentClaimed event with event completion action {:?}",
								event_action.1
							);
							pending_events.push_back(event_action);
						}
					}
				},
				MonitorUpdateCompletionAction::EmitEventAndFreeOtherChannel {
					event,
					downstream_counterparty_and_funding_outpoint,
				} => {
					self.pending_events.lock().unwrap().push_back((event, None));
					if let Some(unblocked) = downstream_counterparty_and_funding_outpoint {
						self.handle_monitor_update_release(
							unblocked.counterparty_node_id,
							unblocked.channel_id,
							Some(unblocked.blocking_action),
						);
					}
				},
				MonitorUpdateCompletionAction::FreeOtherChannelImmediately {
					downstream_counterparty_node_id,
					downstream_channel_id,
					blocking_action,
				} => {
					self.handle_monitor_update_release(
						downstream_counterparty_node_id,
						downstream_channel_id,
						Some(blocking_action),
					);
				},
			}
		}

		for (node_id, channel_id, blocker) in freed_channels {
			self.handle_monitor_update_release(node_id, channel_id, Some(blocker));
		}
	}

	/// Applies a [`ChannelMonitorUpdate`] to the channel monitor.
	///
	/// Monitor updates must be applied while holding the same lock under which they were generated
	/// to ensure correct ordering. However, completion handling requires releasing those locks.
	/// This method applies the update immediately (while locks are held) and returns whether the
	/// update completed, allowing the caller to handle completion separately after releasing locks.
	///
	/// Returns a tuple of `(update_completed, all_updates_completed)`:
	/// - `update_completed`: whether this specific monitor update finished persisting
	/// - `all_updates_completed`: whether all in-flight updates for this channel are now complete
	fn handle_new_monitor_update_locked_actions_handled_by_caller(
		&self,
		in_flight_monitor_updates: &mut BTreeMap<ChannelId, (OutPoint, Vec<ChannelMonitorUpdate>)>,
		channel_id: ChannelId, funding_txo: OutPoint, counterparty_node_id: PublicKey,
		new_update: ChannelMonitorUpdate,
	) -> (bool, bool) {
		let in_flight_updates = &mut in_flight_monitor_updates
			.entry(channel_id)
			.or_insert_with(|| (funding_txo, Vec::new()))
			.1;
		// During startup, we push monitor updates as background events through to here in
		// order to replay updates that were in-flight when we shut down. Thus, we have to
		// filter for uniqueness here.
		let update_idx =
			in_flight_updates.iter().position(|upd| upd == &new_update).unwrap_or_else(|| {
				in_flight_updates.push(new_update);
				in_flight_updates.len() - 1
			});

		if self.background_events_processed_since_startup.load(Ordering::Acquire) {
			let update_res =
				self.chain_monitor.update_channel(channel_id, &in_flight_updates[update_idx]);
			let logger =
				WithContext::from(&self.logger, Some(counterparty_node_id), Some(channel_id), None);
			let update_completed = self.handle_monitor_update_res(update_res, logger);
			if update_completed {
				let _ = in_flight_updates.remove(update_idx);
			}
			(update_completed, update_completed && in_flight_updates.is_empty())
		} else {
			// We blindly assume that the ChannelMonitorUpdate will be regenerated on startup if we
			// fail to persist it. This is a fairly safe assumption, however, since anything we do
			// during the startup sequence should be replayed exactly if we immediately crash.
			let event = BackgroundEvent::MonitorUpdateRegeneratedOnStartup {
				counterparty_node_id,
				funding_txo,
				channel_id,
				update: in_flight_updates[update_idx].clone(),
			};
			// We want to track the in-flight update both in `in_flight_monitor_updates` and in
			// `pending_background_events` to avoid a race condition during
			// `pending_background_events` processing where we complete one
			// `ChannelMonitorUpdate` (but there are more pending as background events) but we
			// conclude that all pending `ChannelMonitorUpdate`s have completed and its safe to
			// run post-completion actions.
			// We could work around that with some effort, but its simpler to just track updates
			// twice.
			self.pending_background_events.lock().unwrap().push(event);
			(false, false)
		}
	}

	/// Handles a monitor update for a closed channel, returning optionally the completion actions
	/// to process after locks are released.
	///
	/// Returns `Some` if all in-flight updates are complete.
	fn handle_post_close_monitor_update(
		&self,
		in_flight_monitor_updates: &mut BTreeMap<ChannelId, (OutPoint, Vec<ChannelMonitorUpdate>)>,
		monitor_update_blocked_actions: &mut BTreeMap<
			ChannelId,
			Vec<MonitorUpdateCompletionAction>,
		>,
		funding_txo: OutPoint, update: ChannelMonitorUpdate, counterparty_node_id: PublicKey,
		channel_id: ChannelId,
	) -> Option<Vec<MonitorUpdateCompletionAction>> {
		let (_update_completed, all_updates_complete) = self
			.handle_new_monitor_update_locked_actions_handled_by_caller(
				in_flight_monitor_updates,
				channel_id,
				funding_txo,
				counterparty_node_id,
				update,
			);
		if all_updates_complete {
			Some(monitor_update_blocked_actions.remove(&channel_id).unwrap_or(Vec::new()))
		} else {
			None
		}
	}

	/// Returns whether the monitor update is completed, `false` if the update is in-progress.
	fn handle_monitor_update_res<LG: Logger>(
		&self, update_res: ChannelMonitorUpdateStatus, logger: LG,
	) -> bool {
		debug_assert!(self.background_events_processed_since_startup.load(Ordering::Acquire));
		match update_res {
			ChannelMonitorUpdateStatus::UnrecoverableError => {
				let err_str = "ChannelMonitor[Update] persistence failed unrecoverably. This indicates we cannot continue normal operation and must shut down.";
				log_error!(logger, "{}", err_str);
				panic!("{}", err_str);
			},
			ChannelMonitorUpdateStatus::InProgress => {
				#[cfg(not(any(test, feature = "_externalize_tests")))]
				if self.monitor_update_type.swap(1, Ordering::Relaxed) == 2 {
					panic!("Cannot use both ChannelMonitorUpdateStatus modes InProgress and Completed without restart");
				}
				log_debug!(
					logger,
					"ChannelMonitor update in flight, holding messages until the update completes.",
				);
				false
			},
			ChannelMonitorUpdateStatus::Completed => {
				#[cfg(not(any(test, feature = "_externalize_tests")))]
				if self.monitor_update_type.swap(2, Ordering::Relaxed) == 1 {
					panic!("Cannot use both ChannelMonitorUpdateStatus modes InProgress and Completed without restart");
				}
				true
			},
		}
	}

	/// Handles the initial monitor persistence, returning optionally data to process after locks
	/// are released.
	///
	/// Note: This method takes individual fields from `PeerState` rather than the whole struct
	/// to avoid borrow checker issues when the channel is borrowed from `peer_state.channel_by_id`.
	fn handle_initial_monitor(
		&self,
		in_flight_monitor_updates: &mut BTreeMap<ChannelId, (OutPoint, Vec<ChannelMonitorUpdate>)>,
		monitor_update_blocked_actions: &mut BTreeMap<
			ChannelId,
			Vec<MonitorUpdateCompletionAction>,
		>,
		pending_msg_events: &mut Vec<MessageSendEvent>, is_connected: bool,
		chan: &mut FundedChannel<SP>, update_res: ChannelMonitorUpdateStatus,
	) -> Option<PostMonitorUpdateChanResume> {
		let logger = WithChannelContext::from(&self.logger, &chan.context, None);
		let update_completed = self.handle_monitor_update_res(update_res, logger);
		if update_completed {
			Some(self.try_resume_channel_post_monitor_update(
				in_flight_monitor_updates,
				monitor_update_blocked_actions,
				pending_msg_events,
				is_connected,
				chan,
			))
		} else {
			None
		}
	}

	/// Applies a new monitor update and attempts to resume the channel if all updates are complete.
	///
	/// Returns [`PostMonitorUpdateChanResume`] if all in-flight updates are complete, which should
	/// be passed to [`Self::handle_post_monitor_update_chan_resume`] after releasing locks.
	///
	/// Note: This method takes individual fields from [`PeerState`] rather than the whole struct
	/// to avoid borrow checker issues when the channel is borrowed from `peer_state.channel_by_id`.
	fn handle_new_monitor_update(
		&self,
		in_flight_monitor_updates: &mut BTreeMap<ChannelId, (OutPoint, Vec<ChannelMonitorUpdate>)>,
		monitor_update_blocked_actions: &mut BTreeMap<
			ChannelId,
			Vec<MonitorUpdateCompletionAction>,
		>,
		pending_msg_events: &mut Vec<MessageSendEvent>, is_connected: bool,
		chan: &mut FundedChannel<SP>, funding_txo: OutPoint, update: ChannelMonitorUpdate,
	) -> Option<PostMonitorUpdateChanResume> {
		self.handle_new_monitor_update_with_status(
			in_flight_monitor_updates,
			monitor_update_blocked_actions,
			pending_msg_events,
			is_connected,
			chan,
			funding_txo,
			update,
		)
		.1
	}

	/// Like [`Self::handle_new_monitor_update`], but also returns whether this specific update
	/// completed (as opposed to being in-progress).
	fn handle_new_monitor_update_with_status(
		&self,
		in_flight_monitor_updates: &mut BTreeMap<ChannelId, (OutPoint, Vec<ChannelMonitorUpdate>)>,
		monitor_update_blocked_actions: &mut BTreeMap<
			ChannelId,
			Vec<MonitorUpdateCompletionAction>,
		>,
		pending_msg_events: &mut Vec<MessageSendEvent>, is_connected: bool,
		chan: &mut FundedChannel<SP>, funding_txo: OutPoint, update: ChannelMonitorUpdate,
	) -> (bool, Option<PostMonitorUpdateChanResume>) {
		let chan_id = chan.context.channel_id();
		let counterparty_node_id = chan.context.get_counterparty_node_id();

		let (update_completed, all_updates_complete) = self
			.handle_new_monitor_update_locked_actions_handled_by_caller(
				in_flight_monitor_updates,
				chan_id,
				funding_txo,
				counterparty_node_id,
				update,
			);

		let completion_data = if all_updates_complete {
			Some(self.try_resume_channel_post_monitor_update(
				in_flight_monitor_updates,
				monitor_update_blocked_actions,
				pending_msg_events,
				is_connected,
				chan,
			))
		} else {
			None
		};

		(update_completed, completion_data)
	}

	/// Attempts to resume a channel after a monitor update completes, while locks are still held.
	///
	/// If the channel has no more blocked monitor updates, this resumes normal operation by
	/// calling [`Self::handle_channel_resumption`] and returns the remaining work to process
	/// after locks are released. If blocked updates remain, only the update actions are returned.
	///
	/// Note: This method takes individual fields from [`PeerState`] rather than the whole struct
	/// to avoid borrow checker issues when the channel is borrowed from `peer_state.channel_by_id`.
	fn try_resume_channel_post_monitor_update(
		&self,
		in_flight_monitor_updates: &mut BTreeMap<ChannelId, (OutPoint, Vec<ChannelMonitorUpdate>)>,
		monitor_update_blocked_actions: &mut BTreeMap<
			ChannelId,
			Vec<MonitorUpdateCompletionAction>,
		>,
		pending_msg_events: &mut Vec<MessageSendEvent>, is_connected: bool,
		chan: &mut FundedChannel<SP>,
	) -> PostMonitorUpdateChanResume {
		let chan_id = chan.context.channel_id();
		let outbound_alias = chan.context.outbound_scid_alias();
		let counterparty_node_id = chan.context.get_counterparty_node_id();

		#[cfg(debug_assertions)]
		{
			let in_flight_updates = in_flight_monitor_updates.get(&chan_id);
			assert!(in_flight_updates.map(|(_, updates)| updates.is_empty()).unwrap_or(true));
			assert!(chan.is_awaiting_monitor_update());
		}

		let logger = WithChannelContext::from(&self.logger, &chan.context, None);

		let update_actions = monitor_update_blocked_actions.remove(&chan_id).unwrap_or(Vec::new());

		if chan.blocked_monitor_updates_pending() != 0 {
			log_debug!(logger, "Channel has blocked monitor updates, completing update actions but leaving channel blocked");
			PostMonitorUpdateChanResume::Blocked { update_actions }
		} else {
			log_debug!(logger, "Channel is open and awaiting update, resuming it");
			let updates = chan.monitor_updating_restored(
				&&logger,
				&self.node_signer,
				self.chain_hash,
				&*self.config.read().unwrap(),
				self.best_block.read().unwrap().height,
				|htlc_id| {
					self.path_for_release_held_htlc(
						htlc_id,
						outbound_alias,
						&chan_id,
						&counterparty_node_id,
					)
				},
			);
			let channel_update = if updates.channel_ready.is_some()
				&& chan.context.is_usable()
				&& is_connected
			{
				if let Ok((msg, _, _)) = self.get_channel_update_for_unicast(chan) {
					Some(MessageSendEvent::SendChannelUpdate { node_id: counterparty_node_id, msg })
				} else {
					None
				}
			} else {
				None
			};

			let (htlc_forwards, decode_update_add_htlcs) = self.handle_channel_resumption(
				pending_msg_events,
				chan,
				updates.raa,
				updates.commitment_update,
				updates.commitment_order,
				updates.accepted_htlcs,
				updates.pending_update_adds,
				updates.funding_broadcastable,
				updates.channel_ready,
				updates.announcement_sigs,
				updates.tx_signatures,
				None,
				updates.channel_ready_order,
			);
			if let Some(upd) = channel_update {
				pending_msg_events.push(upd);
			}

			let unbroadcasted_batch_funding_txid =
				chan.context.unbroadcasted_batch_funding_txid(&chan.funding);

			PostMonitorUpdateChanResume::Unblocked {
				channel_id: chan_id,
				counterparty_node_id,
				funding_txo: chan.funding_outpoint(),
				user_channel_id: chan.context.get_user_id(),
				unbroadcasted_batch_funding_txid,
				update_actions,
				htlc_forwards,
				decode_update_add_htlcs,
				finalized_claimed_htlcs: updates.finalized_claimed_htlcs,
				failed_htlcs: updates.failed_htlcs,
				committed_outbound_htlc_sources: updates.committed_outbound_htlc_sources,
			}
		}
	}

	/// We store inbound committed HTLCs' onions in `Channel`s for use in reconstructing the pending
	/// HTLC set on `ChannelManager` read. If an HTLC has been irrevocably forwarded to the outbound
	/// edge, we no longer need to persist the inbound edge's onion and can prune it here.
	fn prune_persisted_inbound_htlc_onions(
		&self, outbound_channel_id: ChannelId, outbound_node_id: PublicKey,
		outbound_funding_txo: OutPoint, outbound_user_channel_id: u128,
		committed_outbound_htlc_sources: Vec<(HTLCPreviousHopData, u64)>,
	) {
		let per_peer_state = self.per_peer_state.read().unwrap();
		for (source, outbound_amt_msat) in committed_outbound_htlc_sources {
			let counterparty_node_id = match source.counterparty_node_id.as_ref() {
				Some(id) => id,
				None => continue,
			};
			let mut peer_state =
				match per_peer_state.get(counterparty_node_id).map(|state| state.lock().unwrap()) {
					Some(peer_state) => peer_state,
					None => continue,
				};

			if let Some(chan) =
				peer_state.channel_by_id.get_mut(&source.channel_id).and_then(|c| c.as_funded_mut())
			{
				chan.prune_inbound_htlc_onion(
					source.htlc_id,
					&source,
					OutboundHop {
						amt_msat: outbound_amt_msat,
						channel_id: outbound_channel_id,
						node_id: outbound_node_id,
						funding_txo: outbound_funding_txo,
						user_channel_id: outbound_user_channel_id,
					},
				);
			}
		}
	}

	#[cfg(test)]
	pub(crate) fn test_holding_cell_outbound_htlc_forwards_count(
		&self, cp_id: PublicKey, chan_id: ChannelId,
	) -> usize {
		let per_peer_state = self.per_peer_state.read().unwrap();
		let peer_state = per_peer_state.get(&cp_id).map(|state| state.lock().unwrap()).unwrap();
		let chan = peer_state.channel_by_id.get(&chan_id).and_then(|c| c.as_funded()).unwrap();
		chan.test_holding_cell_outbound_htlc_forwards_count()
	}

	#[cfg(test)]
	/// Useful to check that we prune inbound HTLC onions once they are irrevocably forwarded to the
	/// outbound edge, see [`Self::prune_persisted_inbound_htlc_onions`].
	pub(crate) fn test_get_inbound_committed_htlcs_with_onion(
		&self, cp_id: PublicKey, chan_id: ChannelId,
	) -> usize {
		let per_peer_state = self.per_peer_state.read().unwrap();
		let peer_state = per_peer_state.get(&cp_id).map(|state| state.lock().unwrap()).unwrap();
		let chan = peer_state.channel_by_id.get(&chan_id).and_then(|c| c.as_funded()).unwrap();
		chan.inbound_htlcs_pending_decode().count()
	}

	#[cfg(test)]
	/// Useful for testing crash scenarios where the holding cell of a channel is not persisted.
	pub(crate) fn test_clear_channel_holding_cell(&self, cp_id: PublicKey, chan_id: ChannelId) {
		let per_peer_state = self.per_peer_state.read().unwrap();
		let mut peer_state = per_peer_state.get(&cp_id).map(|state| state.lock().unwrap()).unwrap();
		let chan =
			peer_state.channel_by_id.get_mut(&chan_id).and_then(|c| c.as_funded_mut()).unwrap();
		chan.test_clear_holding_cell();
	}

	/// Completes channel resumption after locks have been released.
	///
	/// Processes the [`PostMonitorUpdateChanResume`] returned by
	/// [`Self::try_resume_channel_post_monitor_update`], handling update actions and any
	/// remaining work that requires locks to be released (e.g., forwarding HTLCs, failing HTLCs).
	fn handle_post_monitor_update_chan_resume(&self, data: PostMonitorUpdateChanResume) {
		debug_assert_ne!(self.per_peer_state.held_by_thread(), LockHeldState::HeldByThread);
		#[cfg(debug_assertions)]
		for (_, peer) in self.per_peer_state.read().unwrap().iter() {
			debug_assert_ne!(peer.held_by_thread(), LockHeldState::HeldByThread);
		}

		match data {
			PostMonitorUpdateChanResume::Blocked { update_actions } => {
				self.handle_monitor_update_completion_actions(update_actions);
			},
			PostMonitorUpdateChanResume::Unblocked {
				channel_id,
				counterparty_node_id,
				funding_txo,
				user_channel_id,
				unbroadcasted_batch_funding_txid,
				update_actions,
				htlc_forwards,
				decode_update_add_htlcs,
				finalized_claimed_htlcs,
				failed_htlcs,
				committed_outbound_htlc_sources,
			} => {
				self.post_monitor_update_unlock(
					channel_id,
					counterparty_node_id,
					funding_txo,
					user_channel_id,
					unbroadcasted_batch_funding_txid,
					update_actions,
					htlc_forwards,
					decode_update_add_htlcs,
					finalized_claimed_htlcs,
					failed_htlcs,
					committed_outbound_htlc_sources,
				);
			},
		}
	}

	/// Handles a channel reentering a functional state, either due to reconnect or a monitor
	/// update completion.
	#[rustfmt::skip]
	fn handle_channel_resumption(&self, pending_msg_events: &mut Vec<MessageSendEvent>,
		channel: &mut FundedChannel<SP>, raa: Option<msgs::RevokeAndACK>,
		commitment_update: Option<msgs::CommitmentUpdate>, commitment_order: RAACommitmentOrder,
		pending_forwards: Vec<(PendingHTLCInfo, u64)>, pending_update_adds: Vec<msgs::UpdateAddHTLC>,
		funding_broadcastable: Option<Transaction>,
		channel_ready: Option<msgs::ChannelReady>, announcement_sigs: Option<msgs::AnnouncementSignatures>,
		tx_signatures: Option<msgs::TxSignatures>, tx_abort: Option<msgs::TxAbort>,
		channel_ready_order: ChannelReadyOrder,
	) -> (Vec<PendingAddHTLCInfo>, Option<(u64, Vec<msgs::UpdateAddHTLC>)>) {
		let logger = WithChannelContext::from(&self.logger, &channel.context, None);
		log_trace!(logger, "Handling channel resumption with {} RAA, {} commitment update, {} pending forwards, {} pending update_add_htlcs, {}broadcasting funding, {} channel ready, {} announcement, {} tx_signatures, {} tx_abort",
			if raa.is_some() { "an" } else { "no" },
			if commitment_update.is_some() { "a" } else { "no" },
			pending_forwards.len(), pending_update_adds.len(),
			if funding_broadcastable.is_some() { "" } else { "not " },
			if channel_ready.is_some() { "sending" } else { "without" },
			if announcement_sigs.is_some() { "sending" } else { "without" },
			if tx_signatures.is_some() { "sending" } else { "without" },
			if tx_abort.is_some() { "sending" } else { "without" },
		);

		let counterparty_node_id = channel.context.get_counterparty_node_id();
		let outbound_scid_alias = channel.context.outbound_scid_alias();

		let mut htlc_forwards = Vec::new();
		if !pending_forwards.is_empty() {
			htlc_forwards = pending_forwards.into_iter().map(|(forward_info, prev_htlc_id)| {
				PendingAddHTLCInfo {
					forward_info,
					prev_outbound_scid_alias: outbound_scid_alias,
					prev_htlc_id,
					prev_counterparty_node_id: counterparty_node_id,
					prev_channel_id: channel.context.channel_id(),
					prev_funding_outpoint: channel.funding.get_funding_txo().unwrap(),
					prev_user_channel_id: channel.context.get_user_id(),
				}
			}).collect();
		}
		let mut decode_update_add_htlcs = None;
		if !pending_update_adds.is_empty() {
			decode_update_add_htlcs = Some((outbound_scid_alias, pending_update_adds));
		}

		if channel.context.is_connected() {
			if let ChannelReadyOrder::ChannelReadyFirst = channel_ready_order {
				if let Some(msg) = &channel_ready {
					self.send_channel_ready(pending_msg_events, channel, msg.clone());
				}

				if let Some(msg) = &announcement_sigs {
					pending_msg_events.push(MessageSendEvent::SendAnnouncementSignatures {
						node_id: counterparty_node_id,
						msg: msg.clone(),
					});
				}
			}

			macro_rules! handle_cs { () => {
				if let Some(update) = commitment_update {
					pending_msg_events.push(MessageSendEvent::UpdateHTLCs {
						node_id: counterparty_node_id,
						channel_id: channel.context.channel_id(),
						updates: update,
					});
				}
			} }
			macro_rules! handle_raa { () => {
				if let Some(revoke_and_ack) = raa {
					pending_msg_events.push(MessageSendEvent::SendRevokeAndACK {
						node_id: counterparty_node_id,
						msg: revoke_and_ack,
					});
				}
			} }
			match commitment_order {
				RAACommitmentOrder::CommitmentFirst => {
					handle_cs!();
					handle_raa!();
				},
				RAACommitmentOrder::RevokeAndACKFirst => {
					handle_raa!();
					handle_cs!();
				},
			}

			if let Some(msg) = tx_signatures {
				pending_msg_events.push(MessageSendEvent::SendTxSignatures {
					node_id: counterparty_node_id,
					msg,
				});
			}
			if let Some(msg) = tx_abort {
				pending_msg_events.push(MessageSendEvent::SendTxAbort {
					node_id: counterparty_node_id,
					msg,
				});
			}

			if let ChannelReadyOrder::SignaturesFirst = channel_ready_order {
				if let Some(msg) = channel_ready {
					self.send_channel_ready(pending_msg_events, channel, msg);
				}

				if let Some(msg) = announcement_sigs {
					pending_msg_events.push(MessageSendEvent::SendAnnouncementSignatures {
						node_id: counterparty_node_id,
						msg,
					});
				}
			}
		} else if let Some(msg) = channel_ready {
			self.send_channel_ready(pending_msg_events, channel, msg);
		}

		if let Some(tx) = funding_broadcastable {
			if channel.context.is_manual_broadcast() {
				log_info!(logger, "Not broadcasting funding transaction with txid {} as it is manually managed", tx.compute_txid());
				let mut pending_events = self.pending_events.lock().unwrap();
				match channel.funding.get_funding_txo() {
					Some(funding_txo) => {
						emit_funding_tx_broadcast_safe_event!(pending_events, channel, funding_txo.into_bitcoin_outpoint())
					},
					None => {
						debug_assert!(false, "Channel resumed without a funding txo, this should never happen!");
						return (htlc_forwards, decode_update_add_htlcs);
					}
				};
			} else {
				log_info!(logger, "Broadcasting funding transaction with txid {}", tx.compute_txid());
				self.tx_broadcaster.broadcast_transactions(&[(
					&tx,
					TransactionType::Funding { channels: vec![(counterparty_node_id, channel.context.channel_id())] },
				)]);
			}
		}

		{
			let mut pending_events = self.pending_events.lock().unwrap();
			emit_channel_pending_event!(pending_events, channel);
			emit_initial_channel_ready_event!(pending_events, channel);
		}

		(htlc_forwards, decode_update_add_htlcs)
	}

	#[rustfmt::skip]
	fn channel_monitor_updated(&self, channel_id: &ChannelId, highest_applied_update_id: Option<u64>, counterparty_node_id: &PublicKey) {
		debug_assert!(self.total_consistency_lock.try_write().is_err()); // Caller holds read lock

		let per_peer_state = self.per_peer_state.read().unwrap();
		let mut peer_state_lock;
		let peer_state_mutex_opt = per_peer_state.get(counterparty_node_id);
		if peer_state_mutex_opt.is_none() { return }
		peer_state_lock = peer_state_mutex_opt.unwrap().lock().unwrap();
		let peer_state = &mut *peer_state_lock;

		let logger = WithContext::from(&self.logger, Some(*counterparty_node_id), Some(*channel_id), None);
		let remaining_in_flight =
			if let Some((_, pending)) = peer_state.in_flight_monitor_updates.get_mut(channel_id) {
				if let Some(highest_applied_update_id) = highest_applied_update_id {
					pending.retain(|upd| upd.update_id > highest_applied_update_id);
					log_trace!(
						logger,
						"ChannelMonitor updated to {highest_applied_update_id}. {} pending in-flight updates.",
						pending.len()
					);
				} else if let Some(update) = pending.get(0) {
					log_trace!(
						logger,
						"ChannelMonitor updated to {}. {} pending in-flight updates.",
						update.update_id - 1,
						pending.len()
					);
				} else {
					log_trace!(
						logger,
						"ChannelMonitor updated. {} pending in-flight updates.",
						pending.len()
					);
				}
				pending.len()
			} else { 0 };

		if remaining_in_flight != 0 {
			return;
		}

		if let Some(chan) = peer_state.channel_by_id
			.get_mut(channel_id)
			.and_then(Channel::as_funded_mut)
		{
			if chan.is_awaiting_monitor_update() {
				let completion_data = self.try_resume_channel_post_monitor_update(
					&mut peer_state.in_flight_monitor_updates,
					&mut peer_state.monitor_update_blocked_actions,
					&mut peer_state.pending_msg_events,
					peer_state.is_connected,
					chan,
				);

				let holding_cell_res = self.check_free_peer_holding_cells(peer_state);

				mem::drop(peer_state_lock);
				mem::drop(per_peer_state);

				self.handle_post_monitor_update_chan_resume(completion_data);
				self.handle_holding_cell_free_result(holding_cell_res);
			} else {
				log_trace!(logger, "Channel is open but not awaiting update");
			}
		} else {
			let update_actions = peer_state.monitor_update_blocked_actions
				.remove(channel_id).unwrap_or(Vec::new());
			log_trace!(logger, "Channel is closed, applying {} post-update actions", update_actions.len());
			mem::drop(peer_state_lock);
			mem::drop(per_peer_state);
			self.handle_monitor_update_completion_actions(update_actions);
		}
	}

	/// Accepts a request to open a channel after a [`Event::OpenChannelRequest`].
	///
	/// The `temporary_channel_id` parameter indicates which inbound channel should be accepted,
	/// and the `counterparty_node_id` parameter is the id of the peer which has requested to open
	/// the channel.
	///
	/// The `user_channel_id` parameter will be provided back in
	/// [`Event::ChannelClosed::user_channel_id`] to allow tracking of which events correspond
	/// with which `accept_inbound_channel`/`accept_inbound_channel_from_trusted_peer_0conf` call.
	///
	/// Note that this method will return an error and reject the channel, if it requires support
	/// for zero confirmations. Instead, `accept_inbound_channel_from_trusted_peer_0conf` must be
	/// used to accept such channels.
	///
	/// NOTE: LDK makes no attempt to prevent the counterparty from using non-standard inputs which
	/// will prevent the funding transaction from being relayed on the bitcoin network and hence being
	/// confirmed.
	///
	/// [`Event::OpenChannelRequest`]: events::Event::OpenChannelRequest
	/// [`Event::ChannelClosed::user_channel_id`]: events::Event::ChannelClosed::user_channel_id
	pub fn accept_inbound_channel(
		&self, temporary_channel_id: &ChannelId, counterparty_node_id: &PublicKey,
		user_channel_id: u128, config_overrides: Option<ChannelConfigOverrides>,
	) -> Result<(), APIError> {
		self.do_accept_inbound_channel(
			temporary_channel_id,
			counterparty_node_id,
			false,
			user_channel_id,
			config_overrides,
		)
	}

	/// Accepts a request to open a channel after a [`Event::OpenChannelRequest`], treating
	/// it as confirmed immediately.
	///
	/// The `user_channel_id` parameter will be provided back in
	/// [`Event::ChannelClosed::user_channel_id`] to allow tracking of which events correspond
	/// with which `accept_inbound_channel`/`accept_inbound_channel_from_trusted_peer_0conf` call.
	///
	/// Unlike [`ChannelManager::accept_inbound_channel`], this method accepts the incoming channel
	/// and (if the counterparty agrees), enables forwarding of payments immediately.
	///
	/// This fully trusts that the counterparty has honestly and correctly constructed the funding
	/// transaction and blindly assumes that it will eventually confirm.
	///
	/// If it does not confirm before we decide to close the channel, or if the funding transaction
	/// does not pay to the correct script the correct amount, *you will lose funds*.
	///
	/// [`Event::OpenChannelRequest`]: events::Event::OpenChannelRequest
	/// [`Event::ChannelClosed::user_channel_id`]: events::Event::ChannelClosed::user_channel_id
	pub fn accept_inbound_channel_from_trusted_peer_0conf(
		&self, temporary_channel_id: &ChannelId, counterparty_node_id: &PublicKey,
		user_channel_id: u128, config_overrides: Option<ChannelConfigOverrides>,
	) -> Result<(), APIError> {
		self.do_accept_inbound_channel(
			temporary_channel_id,
			counterparty_node_id,
			true,
			user_channel_id,
			config_overrides,
		)
	}

	/// TODO(dual_funding): Allow contributions, pass intended amount and inputs
	fn do_accept_inbound_channel(
		&self, temporary_channel_id: &ChannelId, counterparty_node_id: &PublicKey,
		accept_0conf: bool, user_channel_id: u128,
		config_overrides: Option<ChannelConfigOverrides>,
	) -> Result<(), APIError> {
		let mut config = self.config.read().unwrap().clone();

		// Apply configuration overrides.
		if let Some(overrides) = config_overrides {
			config.apply(&overrides);
		};

		let logger = WithContext::from(
			&self.logger,
			Some(*counterparty_node_id),
			Some(*temporary_channel_id),
			None,
		);
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(self);

		let peers_without_funded_channels =
			self.peers_without_funded_channels(|peer| peer.total_channel_count() > 0);
		let per_peer_state = self.per_peer_state.read().unwrap();
		let peer_state_mutex = per_peer_state.get(counterparty_node_id).ok_or_else(|| {
			log_error!(logger, "Can't find peer matching the passed counterparty node_id");
			APIError::no_such_peer(counterparty_node_id)
		})?;
		let mut peer_state_lock = peer_state_mutex.lock().unwrap();
		let peer_state = &mut *peer_state_lock;
		let is_only_peer_channel = peer_state.total_channel_count() == 1;

		// Find (and remove) the channel in the unaccepted table. If it's not there, something weird is
		// happening and return an error. N.B. that we create channel with an outbound SCID of zero so
		// that we can delay allocating the SCID until after we're sure that the checks below will
		// succeed.
		let res = match peer_state.inbound_channel_request_by_id.remove(temporary_channel_id) {
			Some(unaccepted_channel) => {
				let best_block_height = self.best_block.read().unwrap().height;
				match unaccepted_channel.open_channel_msg {
					OpenChannelMessage::V1(open_channel_msg) => InboundV1Channel::new(
						&self.fee_estimator,
						&self.entropy_source,
						&self.signer_provider,
						*counterparty_node_id,
						&self.channel_type_features(),
						&peer_state.latest_features,
						&open_channel_msg,
						user_channel_id,
						&config,
						best_block_height,
						&self.logger,
						accept_0conf,
					)
					.map_err(|err| {
						MsgHandleErrInternal::from_chan_no_close(err, *temporary_channel_id)
					})
					.map(|mut channel| {
						let logger = WithChannelContext::from(&self.logger, &channel.context, None);
						let message_send_event =
							channel.accept_inbound_channel(&&logger).map(|msg| {
								MessageSendEvent::SendAcceptChannel {
									node_id: *counterparty_node_id,
									msg,
								}
							});
						(*temporary_channel_id, Channel::from(channel), message_send_event)
					}),
					OpenChannelMessage::V2(open_channel_msg) => PendingV2Channel::new_inbound(
						&self.fee_estimator,
						&self.entropy_source,
						&self.signer_provider,
						self.get_our_node_id(),
						*counterparty_node_id,
						&self.channel_type_features(),
						&peer_state.latest_features,
						&open_channel_msg,
						user_channel_id,
						&config,
						best_block_height,
						&self.logger,
					)
					.map_err(|e| {
						let channel_id = open_channel_msg.common_fields.temporary_channel_id;
						MsgHandleErrInternal::from_chan_no_close(e, channel_id)
					})
					.map(|channel| {
						let message_send_event = MessageSendEvent::SendAcceptChannelV2 {
							node_id: channel.context.get_counterparty_node_id(),
							msg: channel.accept_inbound_dual_funded_channel(),
						};
						(
							channel.context.channel_id(),
							Channel::from(channel),
							Some(message_send_event),
						)
					}),
				}
			},
			None => {
				let err_str = "No such channel awaiting to be accepted.".to_owned();
				log_error!(logger, "{}", err_str);

				return Err(APIError::APIMisuseError { err: err_str });
			},
		};

		// We have to match below instead of map_err on the above as in the map_err closure the borrow checker
		// would consider peer_state moved even though we would bail out with the `?` operator.
		let (channel_id, mut channel, message_send_event) = match res {
			Ok(res) => res,
			Err(err) => {
				mem::drop(peer_state_lock);
				mem::drop(per_peer_state);
				// TODO(dunxen): Find/make less icky way to do this.
				match self.handle_error(
					Result::<(), MsgHandleErrInternal>::Err(err),
					*counterparty_node_id,
				) {
					Ok(_) => {
						unreachable!("`handle_error` only returns Err as we've passed in an Err")
					},
					Err(e) => {
						return Err(APIError::ChannelUnavailable { err: e.err });
					},
				}
			},
		};

		if accept_0conf {
			// This should have been correctly configured by the call to Inbound(V1/V2)Channel::new.
			debug_assert!(channel.minimum_depth().unwrap() == 0);
		} else if channel.funding().get_channel_type().requires_zero_conf() {
			let send_msg_err_event = MessageSendEvent::HandleError {
				node_id: channel.context().get_counterparty_node_id(),
				action: msgs::ErrorAction::SendErrorMessage {
					msg: msgs::ErrorMessage {
						channel_id: *temporary_channel_id,
						data: "No zero confirmation channels accepted".to_owned(),
					},
				},
			};
			debug_assert!(peer_state.is_connected);
			peer_state.pending_msg_events.push(send_msg_err_event);
			let err_str = "Please use accept_inbound_channel_from_trusted_peer_0conf to accept channels with zero confirmations.".to_owned();
			log_error!(logger, "{}", err_str);

			return Err(APIError::APIMisuseError { err: err_str });
		} else {
			// If this peer already has some channels, a new channel won't increase our number of peers
			// with unfunded channels, so as long as we aren't over the maximum number of unfunded
			// channels per-peer we can accept channels from a peer with existing ones.
			if is_only_peer_channel && peers_without_funded_channels > MAX_UNFUNDED_CHANNEL_PEERS {
				let send_msg_err_event = MessageSendEvent::HandleError {
					node_id: channel.context().get_counterparty_node_id(),
					action: msgs::ErrorAction::SendErrorMessage {
						msg: msgs::ErrorMessage {
							channel_id: *temporary_channel_id,
							data:
								"Have too many peers with unfunded channels, not accepting new ones"
									.to_owned(),
						},
					},
				};
				debug_assert!(peer_state.is_connected);
				peer_state.pending_msg_events.push(send_msg_err_event);
				let err_str =
					"Too many peers with unfunded channels, refusing to accept new ones".to_owned();
				log_error!(logger, "{}", err_str);

				return Err(APIError::APIMisuseError { err: err_str });
			}
		}

		// Now that we know we have a channel, assign an outbound SCID alias.
		let outbound_scid_alias = self.create_and_insert_outbound_scid_alias();
		channel.context_mut().set_outbound_scid_alias(outbound_scid_alias);

		if let Some(message_send_event) = message_send_event {
			debug_assert!(peer_state.is_connected);
			peer_state.pending_msg_events.push(message_send_event);
		}
		peer_state.channel_by_id.insert(channel_id, channel);

		Ok(())
	}

	/// Gets the number of peers which match the given filter and do not have any funded, outbound,
	/// or 0-conf channels.
	///
	/// The filter is called for each peer and provided with the number of unfunded, inbound, and
	/// non-0-conf channels we have with the peer.
	fn peers_without_funded_channels<Filter>(&self, maybe_count_peer: Filter) -> usize
	where
		Filter: Fn(&PeerState<SP>) -> bool,
	{
		let mut peers_without_funded_channels = 0;
		let best_block_height = self.best_block.read().unwrap().height;
		{
			let peer_state_lock = self.per_peer_state.read().unwrap();
			for (_, peer_mtx) in peer_state_lock.iter() {
				let peer = peer_mtx.lock().unwrap();
				if !maybe_count_peer(&*peer) {
					continue;
				}
				let num_unfunded_channels = Self::unfunded_channel_count(&peer, best_block_height);
				if num_unfunded_channels == peer.total_channel_count() {
					peers_without_funded_channels += 1;
				}
			}
		}
		return peers_without_funded_channels;
	}

	#[rustfmt::skip]
	fn unfunded_channel_count(
		peer: &PeerState<SP>, best_block_height: u32
	) -> usize {
		let mut num_unfunded_channels = 0;
		for (_, chan) in peer.channel_by_id.iter() {
			match chan.as_funded() {
				Some(funded_chan) => {
					// This covers non-zero-conf inbound `Channel`s that we are currently monitoring, but those
					// which have not yet had any confirmations on-chain.
					if !funded_chan.funding.is_outbound() && chan.minimum_depth().unwrap_or(1) != 0 &&
						funded_chan.funding.get_funding_tx_confirmations(best_block_height) == 0
					{
						num_unfunded_channels += 1;
					}
				},
				None => {
					// Outbound channels don't contribute to the unfunded count in the DoS context.
					if chan.funding().is_outbound() {
						continue;
					}

					// 0conf channels are not considered unfunded.
					if chan.minimum_depth().unwrap_or(1) == 0 {
						continue;
					}

					// Inbound V2 channels with contributed inputs are not considered unfunded.
					if let Some(unfunded_chan) = chan.as_unfunded_v2() {
						if unfunded_chan.funding_negotiation_context.our_funding_contribution > SignedAmount::ZERO {
							continue;
						}
					}

					num_unfunded_channels += 1;
				},
			}
		}
		num_unfunded_channels + peer.inbound_channel_request_by_id.len()
	}

	fn internal_open_channel(
		&self, counterparty_node_id: &PublicKey, msg: OpenChannelMessageRef<'_>,
	) -> Result<(), MsgHandleErrInternal> {
		let common_fields = match msg {
			OpenChannelMessageRef::V1(msg) => &msg.common_fields,
			OpenChannelMessageRef::V2(msg) => &msg.common_fields,
		};

		// Do common open_channel(2) checks

		// Note that the ChannelManager is NOT re-persisted on disk after this, so any changes are
		// likely to be lost on restart!
		if common_fields.chain_hash != self.chain_hash {
			return Err(MsgHandleErrInternal::send_err_msg_no_close(
				"Unknown genesis block hash".to_owned(),
				common_fields.temporary_channel_id,
			));
		}

		if !self.config.read().unwrap().accept_inbound_channels {
			return Err(MsgHandleErrInternal::send_err_msg_no_close(
				"No inbound channels accepted".to_owned(),
				common_fields.temporary_channel_id,
			));
		}

		let per_peer_state = self.per_peer_state.read().unwrap();
		let peer_state_mutex = per_peer_state.get(counterparty_node_id).ok_or_else(|| {
			MsgHandleErrInternal::unreachable_no_such_peer(
				counterparty_node_id,
				common_fields.temporary_channel_id,
			)
		})?;
		let mut peer_state_lock = peer_state_mutex.lock().unwrap();
		let peer_state = &mut *peer_state_lock;

		let best_block_height = self.best_block.read().unwrap().height;
		if Self::unfunded_channel_count(peer_state, best_block_height)
			>= MAX_UNFUNDED_CHANS_PER_PEER
		{
			return Err(MsgHandleErrInternal::send_err_msg_no_close(
				format!("Refusing more than {} unfunded channels.", MAX_UNFUNDED_CHANS_PER_PEER),
				common_fields.temporary_channel_id,
			));
		}

		let channel_id = common_fields.temporary_channel_id;
		let channel_exists = peer_state.has_channel(&channel_id);
		if channel_exists {
			return Err(MsgHandleErrInternal::send_err_msg_no_close(
				"temporary_channel_id collision for the same peer!".to_owned(),
				common_fields.temporary_channel_id,
			));
		}

		let channel_type =
			channel::channel_type_from_open_channel(common_fields, &self.channel_type_features())
				.map_err(|e| {
				MsgHandleErrInternal::from_chan_no_close(e, common_fields.temporary_channel_id)
			})?;

		let mut pending_events = self.pending_events.lock().unwrap();
		let is_announced = (common_fields.channel_flags & 1) == 1;
		pending_events.push_back((
			events::Event::OpenChannelRequest {
				temporary_channel_id: common_fields.temporary_channel_id,
				counterparty_node_id: *counterparty_node_id,
				funding_satoshis: common_fields.funding_satoshis,
				channel_negotiation_type: match msg {
					OpenChannelMessageRef::V1(msg) => InboundChannelFunds::PushMsat(msg.push_msat),
					OpenChannelMessageRef::V2(_) => InboundChannelFunds::DualFunded,
				},
				channel_type,
				is_announced,
				params: common_fields.channel_parameters(),
			},
			None,
		));
		peer_state.inbound_channel_request_by_id.insert(
			channel_id,
			InboundChannelRequest {
				open_channel_msg: match msg {
					OpenChannelMessageRef::V1(msg) => OpenChannelMessage::V1(msg.clone()),
					OpenChannelMessageRef::V2(msg) => OpenChannelMessage::V2(msg.clone()),
				},
				ticks_remaining: UNACCEPTED_INBOUND_CHANNEL_AGE_LIMIT_TICKS,
			},
		);

		Ok(())
	}

	#[rustfmt::skip]
	fn internal_accept_channel(&self, counterparty_node_id: &PublicKey, msg: &msgs::AcceptChannel) -> Result<(), MsgHandleErrInternal> {
		// Note that the ChannelManager is NOT re-persisted on disk after this, so any changes are
		// likely to be lost on restart!
		let (value, output_script, user_id) = {
			let per_peer_state = self.per_peer_state.read().unwrap();
			let peer_state_mutex = per_peer_state.get(counterparty_node_id).ok_or_else(|| {
				MsgHandleErrInternal::unreachable_no_such_peer(
					counterparty_node_id,
					msg.common_fields.temporary_channel_id,
				)
			})?;
			let mut peer_state_lock = peer_state_mutex.lock().unwrap();
			let peer_state = &mut *peer_state_lock;
			match peer_state.channel_by_id.entry(msg.common_fields.temporary_channel_id) {
				hash_map::Entry::Occupied(mut chan) => {
					match chan.get_mut().as_unfunded_outbound_v1_mut() {
						Some(unfunded_chan) => {
							let res = unfunded_chan.accept_channel(
								msg,
								&self.config.read().unwrap().channel_handshake_limits,
								&peer_state.latest_features,
							);
							try_channel_entry!(self, peer_state, res, chan);
							(unfunded_chan.funding.get_value_satoshis(), unfunded_chan.funding.get_funding_redeemscript().to_p2wsh(), unfunded_chan.context.get_user_id())
						},
						None => {
							return Err(MsgHandleErrInternal::send_err_msg_no_close(format!("Got an unexpected accept_channel message from peer with counterparty_node_id {}", counterparty_node_id), msg.common_fields.temporary_channel_id));
						}
					}
				},
				hash_map::Entry::Vacant(_) => return Err(MsgHandleErrInternal::no_such_channel_for_peer(counterparty_node_id, msg.common_fields.temporary_channel_id))
			}
		};
		let mut pending_events = self.pending_events.lock().unwrap();
		pending_events.push_back((events::Event::FundingGenerationReady {
			temporary_channel_id: msg.common_fields.temporary_channel_id,
			counterparty_node_id: *counterparty_node_id,
			channel_value_satoshis: value,
			output_script,
			user_channel_id: user_id,
		}, None));
		Ok(())
	}

	fn internal_funding_created(
		&self, counterparty_node_id: &PublicKey, msg: &msgs::FundingCreated,
	) -> Result<(), MsgHandleErrInternal> {
		let best_block = *self.best_block.read().unwrap();

		let per_peer_state = self.per_peer_state.read().unwrap();
		let peer_state_mutex = per_peer_state.get(counterparty_node_id).ok_or_else(|| {
			MsgHandleErrInternal::unreachable_no_such_peer(
				counterparty_node_id,
				msg.temporary_channel_id,
			)
		})?;

		let mut peer_state_lock = peer_state_mutex.lock().unwrap();
		let peer_state = &mut *peer_state_lock;
		let (mut chan, funding_msg_opt, monitor) = match peer_state
			.channel_by_id
			.remove(&msg.temporary_channel_id)
			.map(Channel::into_unfunded_inbound_v1)
		{
			Some(Ok(inbound_chan)) => {
				let logger = WithChannelContext::from(&self.logger, &inbound_chan.context, None);
				match inbound_chan.funding_created(msg, best_block, &self.signer_provider, &&logger)
				{
					Ok(res) => res,
					Err((inbound_chan, err)) => {
						// We've already removed this inbound channel from the map in `PeerState`
						// above so at this point we just need to clean up any lingering entries
						// concerning this channel as it is safe to do so.
						debug_assert!(matches!(err, ChannelError::Close(_)));
						let mut chan = Channel::from(inbound_chan);
						return Err(self
							.locked_handle_force_close(
								&mut peer_state.closed_channel_monitor_update_ids,
								&mut peer_state.in_flight_monitor_updates,
								err,
								&mut chan,
							)
							.1);
					},
				}
			},
			Some(Err(mut chan)) => {
				let err_msg = format!("Got an unexpected funding_created message from peer with counterparty_node_id {}", counterparty_node_id);
				let err = ChannelError::close(err_msg);
				return Err(self
					.locked_handle_force_close(
						&mut peer_state.closed_channel_monitor_update_ids,
						&mut peer_state.in_flight_monitor_updates,
						err,
						&mut chan,
					)
					.1);
			},
			None => {
				return Err(MsgHandleErrInternal::no_such_channel_for_peer(
					counterparty_node_id,
					msg.temporary_channel_id,
				))
			},
		};

		let funded_channel_id = chan.context.channel_id();

		macro_rules! fail_chan {
			($err: expr) => {{
				// Note that at this point we've filled in the funding outpoint on our channel, but its
				// actually in conflict with another channel. Thus, if we call `convert_channel_err`
				// immediately, we'll remove the existing channel from `outpoint_to_peer`.
				// Thus, we must first unset the funding outpoint on the channel.
				let err = ChannelError::close($err.to_owned());
				chan.unset_funding_info();
				let mut chan = Channel::from(chan);
				return Err(self.locked_handle_unfunded_close(err, &mut chan).1);
			}};
		}

		match peer_state.channel_by_id.entry(funded_channel_id) {
			hash_map::Entry::Occupied(_) => {
				fail_chan!("Already had channel with the new channel_id");
			},
			hash_map::Entry::Vacant(e) => {
				let monitor_res = self.chain_monitor.watch_channel(monitor.channel_id(), monitor);
				if let Ok(persist_state) = monitor_res {
					// There's no problem signing a counterparty's funding transaction if our monitor
					// hasn't persisted to disk yet - we can't lose money on a transaction that we haven't
					// accepted payment from yet. We do, however, need to wait to send our channel_ready
					// until we have persisted our monitor.
					if let Some(msg) = funding_msg_opt {
						peer_state.pending_msg_events.push(MessageSendEvent::SendFundingSigned {
							node_id: *counterparty_node_id,
							msg,
						});
					}

					if let Some(funded_chan) = e.insert(Channel::from(chan)).as_funded_mut() {
						if let Some(data) = self.handle_initial_monitor(
							&mut peer_state.in_flight_monitor_updates,
							&mut peer_state.monitor_update_blocked_actions,
							&mut peer_state.pending_msg_events,
							peer_state.is_connected,
							funded_chan,
							persist_state,
						) {
							mem::drop(peer_state_lock);
							mem::drop(per_peer_state);
							self.handle_post_monitor_update_chan_resume(data);
						}
					} else {
						unreachable!("This must be a funded channel as we just inserted it.");
					}
					Ok(())
				} else {
					let logger = WithChannelContext::from(&self.logger, &chan.context, None);
					log_error!(logger, "Persisting initial ChannelMonitor failed, implying the channel ID was duplicated");
					fail_chan!("Duplicate channel ID");
				}
			},
		}
	}

	fn internal_peer_storage_retrieval(
		&self, peer_node_id: PublicKey, msg: msgs::PeerStorageRetrieval,
	) -> Result<(), MsgHandleErrInternal> {
		// TODO: Check if have any stale or missing ChannelMonitor.
		let logger = WithContext::from(&self.logger, Some(peer_node_id), None, None);
		let err = || {
			MsgHandleErrInternal::from_chan_no_close(
				ChannelError::Ignore("Invalid PeerStorageRetrieval message received.".into()),
				ChannelId([0; 32]),
			)
		};

		let encrypted_ops = match EncryptedOurPeerStorage::new(msg.data) {
			Ok(encrypted_ops) => encrypted_ops,
			Err(()) => {
				log_debug!(logger, "Received a peer backup which wasn't long enough to be valid");
				return Err(err());
			},
		};

		let decrypted = match encrypted_ops.decrypt(&self.node_signer.get_peer_storage_key()) {
			Ok(decrypted_ops) => decrypted_ops.into_vec(),
			Err(()) => {
				log_debug!(logger, "Received a peer backup which was corrupted");
				return Err(err());
			},
		};

		log_trace!(logger, "Got valid {}-byte peer backup from {}", decrypted.len(), peer_node_id);
		let per_peer_state = self.per_peer_state.read().unwrap();

		let mut cursor = io::Cursor::new(decrypted);
		let mon_list = <Vec<PeerStorageMonitorHolder> as Readable>::read(&mut cursor)
			.unwrap_or_else(|e| {
				// This should NEVER happen.
				debug_assert!(false);
				log_debug!(self.logger, "Unable to unpack the retrieved peer storage {:?}", e);
				Vec::new()
			});

		for mon_holder in mon_list.iter() {
			let peer_state_mutex = match per_peer_state.get(&mon_holder.counterparty_node_id) {
				Some(mutex) => mutex,
				None => {
					log_debug!(
						logger,
						"Not able to find peer_state for the counterparty {}, channel_id {}",
						log_pubkey!(mon_holder.counterparty_node_id),
						mon_holder.channel_id
					);
					continue;
				},
			};

			let peer_state_lock = peer_state_mutex.lock().unwrap();
			let peer_state = &*peer_state_lock;

			match peer_state.channel_by_id.get(&mon_holder.channel_id) {
				Some(chan) => {
					if let Some(funded_chan) = chan.as_funded() {
						if funded_chan.get_revoked_counterparty_commitment_transaction_number()
							> mon_holder.min_seen_secret
						{
							panic!(
								"Lost channel state for channel {}.\n\
								Received peer storage with a more recent state than what our node had.\n\
								Use the FundRecoverer to initiate a force close and sweep the funds.",
								&mon_holder.channel_id
							);
						}
					}
				},
				None => {
					log_debug!(logger, "Found an unknown channel {}", &mon_holder.channel_id);
				},
			}
		}
		Ok(())
	}

	#[rustfmt::skip]
	fn internal_peer_storage(&self, counterparty_node_id: PublicKey, msg: msgs::PeerStorage) -> Result<(), MsgHandleErrInternal> {
		let per_peer_state = self.per_peer_state.read().unwrap();
		let peer_state_mutex = per_peer_state.get(&counterparty_node_id).ok_or_else(|| {
			MsgHandleErrInternal::unreachable_no_such_peer(&counterparty_node_id, ChannelId([0; 32]))
		})?;

		let mut peer_state_lock = peer_state_mutex.lock().unwrap();
		let peer_state = &mut *peer_state_lock;
		let logger = WithContext::from(&self.logger, Some(counterparty_node_id), None, None);

		// Check if we have any channels with the peer (Currently we only provide the service to peers we have a channel with).
		if !peer_state.channel_by_id.values().any(|phase| phase.is_funded()) {
			log_debug!(logger, "Ignoring peer storage request from {} as we don't have any funded channels with them.", log_pubkey!(counterparty_node_id));
			return Err(MsgHandleErrInternal::from_chan_no_close(ChannelError::Warn(
				"Ignoring peer_storage message, as peer storage is currently supported only for \
				peers with an active funded channel.".into(),
			), ChannelId([0; 32])));
		}

		#[cfg(not(test))]
		if msg.data.len() > MAX_PEER_STORAGE_SIZE {
			log_debug!(logger, "Sending warning to peer and ignoring peer storage request from {} as its over 1KiB", log_pubkey!(counterparty_node_id));

			return Err(MsgHandleErrInternal::from_chan_no_close(ChannelError::Warn(
				format!("Supports only data up to {} bytes in peer storage.", MAX_PEER_STORAGE_SIZE)
			), ChannelId([0; 32])));
		}

		log_trace!(logger, "Received peer_storage from {}", log_pubkey!(counterparty_node_id));
		peer_state.peer_storage = msg.data;

		Ok(())
	}

	#[rustfmt::skip]
	fn internal_funding_signed(&self, counterparty_node_id: &PublicKey, msg: &msgs::FundingSigned) -> Result<(), MsgHandleErrInternal> {
		let best_block = *self.best_block.read().unwrap();
		let per_peer_state = self.per_peer_state.read().unwrap();
		let peer_state_mutex = per_peer_state.get(counterparty_node_id).ok_or_else(|| {
			MsgHandleErrInternal::unreachable_no_such_peer(counterparty_node_id, msg.channel_id)
		})?;

		let mut peer_state_lock = peer_state_mutex.lock().unwrap();
		let peer_state = &mut *peer_state_lock;
		match peer_state.channel_by_id.entry(msg.channel_id) {
			hash_map::Entry::Occupied(mut chan_entry) => {
				let chan = chan_entry.get_mut();
				match chan
					.funding_signed(&msg, best_block, &self.signer_provider, &self.logger)
					.and_then(|(funded_chan, monitor)| {
						self.chain_monitor
							.watch_channel(funded_chan.context.channel_id(), monitor)
							.map_err(|()| {
								// We weren't able to watch the channel to begin with, so no
								// updates should be made on it. Previously, full_stack_target
								// found an (unreachable) panic when the monitor update contained
								// within `shutdown_finish` was applied.
								funded_chan.unset_funding_info();
								ChannelError::close("Channel ID was a duplicate".to_owned())
							})
							.map(|persist_status| (funded_chan, persist_status))
					})
				{
					Ok((funded_chan, persist_status)) => {
						if let Some(data) = self.handle_initial_monitor(
							&mut peer_state.in_flight_monitor_updates,
							&mut peer_state.monitor_update_blocked_actions,
							&mut peer_state.pending_msg_events,
							peer_state.is_connected,
							funded_chan,
							persist_status,
						) {
							mem::drop(peer_state_lock);
							mem::drop(per_peer_state);
							self.handle_post_monitor_update_chan_resume(data);
						}
						Ok(())
					},
					Err(e) => try_channel_entry!(self, peer_state, Err(e), chan_entry),
				}
			},
			hash_map::Entry::Vacant(_) => return Err(MsgHandleErrInternal::send_err_msg_no_close("Failed to find corresponding channel".to_owned(), msg.channel_id))
		}
	}

	fn internal_tx_msg<
		HandleTxMsgFn: Fn(&mut Channel<SP>) -> Result<InteractiveTxMessageSend, InteractiveTxMsgError>,
	>(
		&self, counterparty_node_id: &PublicKey, channel_id: ChannelId,
		tx_msg_handler: HandleTxMsgFn,
	) -> Result<(), MsgHandleErrInternal> {
		let per_peer_state = self.per_peer_state.read().unwrap();
		let peer_state_mutex = per_peer_state.get(counterparty_node_id).ok_or_else(|| {
			MsgHandleErrInternal::unreachable_no_such_peer(counterparty_node_id, channel_id)
		})?;
		let mut peer_state_lock = peer_state_mutex.lock().unwrap();
		let peer_state = &mut *peer_state_lock;
		match peer_state.channel_by_id.entry(channel_id) {
			hash_map::Entry::Occupied(mut chan_entry) => {
				let channel = chan_entry.get_mut();
				match tx_msg_handler(channel) {
					Ok(msg_send) => {
						let msg_send_event = msg_send.into_msg_send_event(*counterparty_node_id);
						peer_state.pending_msg_events.push(msg_send_event);
						Ok(())
					},
					Err(InteractiveTxMsgError {
						err,
						splice_funding_failed,
						exited_quiescence,
					}) => {
						if let Some(splice_funding_failed) = splice_funding_failed {
							let pending_events = &mut self.pending_events.lock().unwrap();
							pending_events.push_back((
								events::Event::SpliceFailed {
									channel_id,
									counterparty_node_id: *counterparty_node_id,
									user_channel_id: channel.context().get_user_id(),
									abandoned_funding_txo: splice_funding_failed.funding_txo,
									channel_type: splice_funding_failed.channel_type.clone(),
									contributed_inputs: splice_funding_failed.contributed_inputs,
									contributed_outputs: splice_funding_failed.contributed_outputs,
								},
								None,
							));
						}
						debug_assert!(!exited_quiescence || matches!(err, ChannelError::Abort(_)));

						Err(MsgHandleErrInternal::from_chan_no_close(err, channel_id)
							.with_exited_quiescence(exited_quiescence))
					},
				}
			},
			hash_map::Entry::Vacant(_) => Err(MsgHandleErrInternal::no_such_channel_for_peer(
				counterparty_node_id,
				channel_id,
			)),
		}
	}

	fn internal_tx_add_input(
		&self, counterparty_node_id: PublicKey, msg: &msgs::TxAddInput,
	) -> Result<(), MsgHandleErrInternal> {
		self.internal_tx_msg(&counterparty_node_id, msg.channel_id, |channel: &mut Channel<SP>| {
			channel.tx_add_input(msg, &self.logger)
		})
	}

	fn internal_tx_add_output(
		&self, counterparty_node_id: PublicKey, msg: &msgs::TxAddOutput,
	) -> Result<(), MsgHandleErrInternal> {
		self.internal_tx_msg(&counterparty_node_id, msg.channel_id, |channel: &mut Channel<SP>| {
			channel.tx_add_output(msg, &self.logger)
		})
	}

	fn internal_tx_remove_input(
		&self, counterparty_node_id: PublicKey, msg: &msgs::TxRemoveInput,
	) -> Result<(), MsgHandleErrInternal> {
		self.internal_tx_msg(&counterparty_node_id, msg.channel_id, |channel: &mut Channel<SP>| {
			channel.tx_remove_input(msg, &self.logger)
		})
	}

	fn internal_tx_remove_output(
		&self, counterparty_node_id: PublicKey, msg: &msgs::TxRemoveOutput,
	) -> Result<(), MsgHandleErrInternal> {
		self.internal_tx_msg(&counterparty_node_id, msg.channel_id, |channel: &mut Channel<SP>| {
			channel.tx_remove_output(msg, &self.logger)
		})
	}

	fn internal_tx_complete(
		&self, counterparty_node_id: PublicKey, msg: &msgs::TxComplete,
	) -> Result<(), MsgHandleErrInternal> {
		let per_peer_state = self.per_peer_state.read().unwrap();
		let peer_state_mutex = per_peer_state.get(&counterparty_node_id).ok_or_else(|| {
			MsgHandleErrInternal::unreachable_no_such_peer(&counterparty_node_id, msg.channel_id)
		})?;
		let mut peer_state_lock = peer_state_mutex.lock().unwrap();
		let peer_state = &mut *peer_state_lock;
		match peer_state.channel_by_id.entry(msg.channel_id) {
			hash_map::Entry::Occupied(mut chan_entry) => {
				let chan = chan_entry.get_mut();
				match chan.tx_complete(msg, &self.fee_estimator, &self.logger) {
					Ok(tx_complete_result) => {
						if let Some(interactive_tx_msg_send) =
							tx_complete_result.interactive_tx_msg_send
						{
							let msg_send_event =
								interactive_tx_msg_send.into_msg_send_event(counterparty_node_id);
							peer_state.pending_msg_events.push(msg_send_event);
						};

						if let Some(unsigned_transaction) = tx_complete_result.event_unsigned_tx {
							self.pending_events.lock().unwrap().push_back((
								events::Event::FundingTransactionReadyForSigning {
									unsigned_transaction,
									counterparty_node_id,
									channel_id: msg.channel_id,
									user_channel_id: chan.context().get_user_id(),
								},
								None,
							));
							// We have a successful signing session that we need to persist.
							self.needs_persist_flag.store(true, Ordering::Release);
							self.event_persist_notifier.notify()
						}

						if let Some(FundingTxSigned {
							commitment_signed,
							counterparty_initial_commitment_signed_result,
							tx_signatures,
							funding_tx,
							splice_negotiated,
							splice_locked,
						}) = tx_complete_result.funding_tx_signed
						{
							// We shouldn't expect to see the splice negotiated or locked yet as we
							// haven't exchanged `tx_signatures` at this point. Similarly, we
							// shouldn't have a result for the counterparty's initial commitment
							// signed as they haven't sent it yet.
							debug_assert!(funding_tx.is_none());
							debug_assert!(splice_negotiated.is_none());
							debug_assert!(splice_locked.is_none());
							debug_assert!(counterparty_initial_commitment_signed_result.is_none());

							if let Some(commitment_signed) = commitment_signed {
								peer_state.pending_msg_events.push(MessageSendEvent::UpdateHTLCs {
									node_id: counterparty_node_id,
									channel_id: msg.channel_id,
									updates: CommitmentUpdate {
										commitment_signed: vec![commitment_signed],
										update_add_htlcs: vec![],
										update_fulfill_htlcs: vec![],
										update_fail_htlcs: vec![],
										update_fail_malformed_htlcs: vec![],
										update_fee: None,
									},
								});
							}
							if let Some(tx_signatures) = tx_signatures {
								peer_state.pending_msg_events.push(
									MessageSendEvent::SendTxSignatures {
										node_id: counterparty_node_id,
										msg: tx_signatures,
									},
								);
							}

							// We have a successful signing session that we need to persist.
							self.needs_persist_flag.store(true, Ordering::Release);
							self.event_persist_notifier.notify()
						}

						Ok(())
					},
					Err(InteractiveTxMsgError {
						err,
						splice_funding_failed,
						exited_quiescence,
					}) => {
						if let Some(splice_funding_failed) = splice_funding_failed {
							let pending_events = &mut self.pending_events.lock().unwrap();
							pending_events.push_back((
								events::Event::SpliceFailed {
									channel_id: msg.channel_id,
									counterparty_node_id,
									user_channel_id: chan.context().get_user_id(),
									abandoned_funding_txo: splice_funding_failed.funding_txo,
									channel_type: splice_funding_failed.channel_type.clone(),
									contributed_inputs: splice_funding_failed.contributed_inputs,
									contributed_outputs: splice_funding_failed.contributed_outputs,
								},
								None,
							));
						}
						debug_assert!(!exited_quiescence || matches!(err, ChannelError::Abort(_)));

						Err(MsgHandleErrInternal::from_chan_no_close(err, msg.channel_id)
							.with_exited_quiescence(exited_quiescence))
					},
				}
			},
			hash_map::Entry::Vacant(_) => Err(MsgHandleErrInternal::no_such_channel_for_peer(
				&counterparty_node_id,
				msg.channel_id,
			)),
		}
	}

	fn internal_tx_signatures(
		&self, counterparty_node_id: &PublicKey, msg: &msgs::TxSignatures,
	) -> Result<(), MsgHandleErrInternal> {
		let (result, holding_cell_res) = {
			let per_peer_state = self.per_peer_state.read().unwrap();
			let peer_state_mutex = per_peer_state.get(counterparty_node_id).ok_or_else(|| {
				MsgHandleErrInternal::unreachable_no_such_peer(counterparty_node_id, msg.channel_id)
			})?;
			let mut peer_state_lock = peer_state_mutex.lock().unwrap();
			let peer_state = &mut *peer_state_lock;
			match peer_state.channel_by_id.entry(msg.channel_id) {
				hash_map::Entry::Occupied(mut chan_entry) => {
					match chan_entry.get_mut().as_funded_mut() {
						Some(chan) => {
							let best_block_height = self.best_block.read().unwrap().height;
							let FundingTxSigned {
								commitment_signed,
								counterparty_initial_commitment_signed_result,
								tx_signatures,
								funding_tx,
								splice_negotiated,
								splice_locked,
							} = try_channel_entry!(
								self,
								peer_state,
								chan.tx_signatures(msg, best_block_height, &self.logger),
								chan_entry
							);

							// We should never be sending a `commitment_signed` in response to their
							// `tx_signatures`.
							debug_assert!(commitment_signed.is_none());
							debug_assert!(counterparty_initial_commitment_signed_result.is_none());

							if let Some(tx_signatures) = tx_signatures {
								peer_state.pending_msg_events.push(
									MessageSendEvent::SendTxSignatures {
										node_id: *counterparty_node_id,
										msg: tx_signatures,
									},
								);
							}
							if let Some(splice_locked) = splice_locked {
								peer_state.pending_msg_events.push(
									MessageSendEvent::SendSpliceLocked {
										node_id: *counterparty_node_id,
										msg: splice_locked,
									},
								);
							}
							if let Some((ref funding_tx, ref tx_type)) = funding_tx {
								self.broadcast_interactive_funding(
									chan,
									funding_tx,
									Some(tx_type.clone()),
									&self.logger,
								);
							}
							// We consider a splice negotiated when we exchange `tx_signatures`,
							// which also terminates quiescence.
							let exited_quiescence = splice_negotiated.is_some();
							if let Some(splice_negotiated) = splice_negotiated {
								self.pending_events.lock().unwrap().push_back((
									events::Event::SplicePending {
										channel_id: msg.channel_id,
										counterparty_node_id: *counterparty_node_id,
										user_channel_id: chan.context.get_user_id(),
										new_funding_txo: splice_negotiated.funding_txo,
										channel_type: splice_negotiated.channel_type,
										new_funding_redeem_script: splice_negotiated
											.funding_redeem_script,
									},
									None,
								));
							}
							let holding_cell_res = if exited_quiescence {
								self.check_free_peer_holding_cells(peer_state)
							} else {
								Vec::new()
							};
							(Ok(()), holding_cell_res)
						},
						None => {
							let msg = "Got an unexpected tx_signatures message";
							let reason = ClosureReason::ProcessingError { err: msg.to_owned() };
							let err = ChannelError::Close((msg.to_owned(), reason));
							try_channel_entry!(self, peer_state, Err(err), chan_entry)
						},
					}
				},
				hash_map::Entry::Vacant(_) => (
					Err(MsgHandleErrInternal::no_such_channel_for_peer(
						counterparty_node_id,
						msg.channel_id,
					)),
					Vec::new(),
				),
			}
		};

		self.handle_holding_cell_free_result(holding_cell_res);
		result
	}

	fn internal_tx_abort(
		&self, counterparty_node_id: &PublicKey, msg: &msgs::TxAbort,
	) -> Result<NotifyOption, MsgHandleErrInternal> {
		let (result, holding_cell_res) = {
			let per_peer_state = self.per_peer_state.read().unwrap();
			let peer_state_mutex = per_peer_state.get(counterparty_node_id).ok_or_else(|| {
				MsgHandleErrInternal::unreachable_no_such_peer(counterparty_node_id, msg.channel_id)
			})?;
			let mut peer_state_lock = peer_state_mutex.lock().unwrap();
			let peer_state = &mut *peer_state_lock;
			match peer_state.channel_by_id.entry(msg.channel_id) {
				hash_map::Entry::Occupied(mut chan_entry) => {
					let res = chan_entry.get_mut().tx_abort(msg, &self.logger);
					let (tx_abort, splice_failed, exited_quiescence) =
						try_channel_entry!(self, peer_state, res, chan_entry);

					let persist = if tx_abort.is_some() || splice_failed.is_some() {
						NotifyOption::DoPersist
					} else {
						NotifyOption::SkipPersistNoEvents
					};

					if let Some(tx_abort_msg) = tx_abort {
						peer_state.pending_msg_events.push(MessageSendEvent::SendTxAbort {
							node_id: *counterparty_node_id,
							msg: tx_abort_msg,
						});
					}

					if let Some(splice_funding_failed) = splice_failed {
						let pending_events = &mut self.pending_events.lock().unwrap();
						pending_events.push_back((
							events::Event::SpliceFailed {
								channel_id: msg.channel_id,
								counterparty_node_id: *counterparty_node_id,
								user_channel_id: chan_entry.get().context().get_user_id(),
								abandoned_funding_txo: splice_funding_failed.funding_txo,
								channel_type: splice_funding_failed.channel_type,
								contributed_inputs: splice_funding_failed.contributed_inputs,
								contributed_outputs: splice_funding_failed.contributed_outputs,
							},
							None,
						));
					}

					let holding_cell_res = if exited_quiescence {
						self.check_free_peer_holding_cells(peer_state)
					} else {
						Vec::new()
					};
					(Ok(persist), holding_cell_res)
				},
				hash_map::Entry::Vacant(_) => (
					Err(MsgHandleErrInternal::no_such_channel_for_peer(
						counterparty_node_id,
						msg.channel_id,
					)),
					Vec::new(),
				),
			}
		};

		self.handle_holding_cell_free_result(holding_cell_res);
		result
	}

	#[rustfmt::skip]
	fn internal_channel_ready(&self, counterparty_node_id: &PublicKey, msg: &msgs::ChannelReady) -> Result<(), MsgHandleErrInternal> {
		// Note that the ChannelManager is NOT re-persisted on disk after this (unless we error
		// closing a channel), so any changes are likely to be lost on restart!
		let per_peer_state = self.per_peer_state.read().unwrap();
		let peer_state_mutex = per_peer_state.get(counterparty_node_id).ok_or_else(|| {
			MsgHandleErrInternal::unreachable_no_such_peer(counterparty_node_id, msg.channel_id)
		})?;
		let mut peer_state_lock = peer_state_mutex.lock().unwrap();
		let peer_state = &mut *peer_state_lock;
		match peer_state.channel_by_id.entry(msg.channel_id) {
			hash_map::Entry::Occupied(mut chan_entry) => {
				if let Some(chan) = chan_entry.get_mut().as_funded_mut() {
					let logger = WithChannelContext::from(&self.logger, &chan.context, None);
					let res = chan.channel_ready(
						&msg,
						&self.node_signer,
						self.chain_hash,
						&self.config.read().unwrap(),
						&self.best_block.read().unwrap(),
						&&logger
					);
					let announcement_sigs_opt =
						try_channel_entry!(self, peer_state, res, chan_entry);
					if let Some(announcement_sigs) = announcement_sigs_opt {
						log_trace!(logger, "Sending announcement_signatures");
						peer_state.pending_msg_events.push(MessageSendEvent::SendAnnouncementSignatures {
							node_id: counterparty_node_id.clone(),
							msg: announcement_sigs,
						});
					} else if chan.context.is_usable() {
						// If we're sending an announcement_signatures, we'll send the (public)
						// channel_update after sending a channel_announcement when we receive our
						// counterparty's announcement_signatures. Thus, we only bother to send a
						// channel_update here if the channel is not public, i.e. we're not sending an
						// announcement_signatures.
						log_trace!(logger, "Sending private initial channel_update for our counterparty");
						if let Ok((msg, _, _)) = self.get_channel_update_for_unicast(chan) {
							peer_state.pending_msg_events.push(MessageSendEvent::SendChannelUpdate {
								node_id: counterparty_node_id.clone(),
								msg,
							});
						}
					}

					{
						let mut pending_events = self.pending_events.lock().unwrap();
						emit_initial_channel_ready_event!(pending_events, chan);
					}

					Ok(())
				} else {
					try_channel_entry!(self, peer_state, Err(ChannelError::close(
						"Got a channel_ready message for an unfunded channel!".into())), chan_entry)
				}
			},
			hash_map::Entry::Vacant(_) => {
				Err(MsgHandleErrInternal::no_such_channel_for_peer(counterparty_node_id, msg.channel_id))
			}
		}
	}

	fn internal_shutdown(
		&self, counterparty_node_id: &PublicKey, msg: &msgs::Shutdown,
	) -> Result<(), MsgHandleErrInternal> {
		let mut dropped_htlcs: Vec<(HTLCSource, PaymentHash)>;
		{
			let per_peer_state = self.per_peer_state.read().unwrap();
			let peer_state_mutex = per_peer_state.get(counterparty_node_id).ok_or_else(|| {
				MsgHandleErrInternal::unreachable_no_such_peer(counterparty_node_id, msg.channel_id)
			})?;
			let mut peer_state_lock = peer_state_mutex.lock().unwrap();
			let peer_state = &mut *peer_state_lock;
			if let hash_map::Entry::Occupied(mut chan_entry) =
				peer_state.channel_by_id.entry(msg.channel_id.clone())
			{
				match chan_entry.get_mut().as_funded_mut() {
					Some(chan) => {
						if !chan.received_shutdown() {
							let logger =
								WithChannelContext::from(&self.logger, &chan.context, None);
							log_info!(
								logger,
								"Received a shutdown message from our counterparty{}.",
								if chan.sent_shutdown() {
									" after we initiated shutdown"
								} else {
									""
								}
							);
						}

						let funding_txo_opt = chan.funding.get_funding_txo();
						let (shutdown, monitor_update_opt, htlcs) = try_channel_entry!(
							self,
							peer_state,
							chan.shutdown(
								&self.logger,
								&self.signer_provider,
								&peer_state.latest_features,
								&msg
							),
							chan_entry
						);
						dropped_htlcs = htlcs;

						if let Some(msg) = shutdown {
							// We can send the `shutdown` message before updating the `ChannelMonitor`
							// here as we don't need the monitor update to complete until we send a
							// `shutdown_signed`, which we'll delay if we're pending a monitor update.
							peer_state.pending_msg_events.push(MessageSendEvent::SendShutdown {
								node_id: *counterparty_node_id,
								msg,
							});
						}
						// Update the monitor with the shutdown script if necessary.
						if let Some(monitor_update) = monitor_update_opt {
							if let Some(data) = self.handle_new_monitor_update(
								&mut peer_state.in_flight_monitor_updates,
								&mut peer_state.monitor_update_blocked_actions,
								&mut peer_state.pending_msg_events,
								peer_state.is_connected,
								chan,
								funding_txo_opt.unwrap(),
								monitor_update,
							) {
								mem::drop(peer_state_lock);
								mem::drop(per_peer_state);
								self.handle_post_monitor_update_chan_resume(data);
							}
						}
					},
					None => {
						let logger = WithChannelContext::from(
							&self.logger,
							chan_entry.get().context(),
							None,
						);
						log_error!(logger, "Immediately closing unfunded channel as peer asked to cooperatively shut it down (which is unnecessary)");
						let reason = ClosureReason::CounterpartyCoopClosedUnfundedChannel;
						let err = ChannelError::Close((reason.to_string(), reason));
						let mut chan = chan_entry.remove();
						let (_, mut e) = self.locked_handle_unfunded_close(err, &mut chan);
						e.dont_send_error_message();
						return Err(e);
					},
				}
			} else {
				return Err(MsgHandleErrInternal::no_such_channel_for_peer(
					counterparty_node_id,
					msg.channel_id,
				));
			}
		}
		for htlc_source in dropped_htlcs.drain(..) {
			let receiver = HTLCHandlingFailureType::Forward {
				node_id: Some(counterparty_node_id.clone()),
				channel_id: msg.channel_id,
			};
			let reason = HTLCFailReason::from_failure_code(LocalHTLCFailureReason::ChannelClosed);
			let (source, hash) = htlc_source;
			self.fail_htlc_backwards_internal(&source, &hash, &reason, receiver, None);
		}

		Ok(())
	}

	fn internal_closing_signed(
		&self, counterparty_node_id: &PublicKey, msg: &msgs::ClosingSigned,
	) -> Result<(), MsgHandleErrInternal> {
		let per_peer_state = self.per_peer_state.read().unwrap();
		let peer_state_mutex = per_peer_state.get(counterparty_node_id).ok_or_else(|| {
			MsgHandleErrInternal::unreachable_no_such_peer(counterparty_node_id, msg.channel_id)
		})?;
		let logger;
		let tx_err: Option<(_, Result<Infallible, _>)> = {
			let mut peer_state_lock = peer_state_mutex.lock().unwrap();
			let peer_state = &mut *peer_state_lock;
			match peer_state.channel_by_id.entry(msg.channel_id.clone()) {
				hash_map::Entry::Occupied(mut chan_entry) => {
					if let Some(chan) = chan_entry.get_mut().as_funded_mut() {
						logger = WithChannelContext::from(&self.logger, &chan.context, None);
						let res = chan.closing_signed(&self.fee_estimator, &msg, &&logger);
						let (closing_signed, tx_shutdown_result) =
							try_channel_entry!(self, peer_state, res, chan_entry);
						debug_assert_eq!(tx_shutdown_result.is_some(), chan.is_shutdown());
						if let Some(msg) = closing_signed {
							peer_state.pending_msg_events.push(
								MessageSendEvent::SendClosingSigned {
									node_id: counterparty_node_id.clone(),
									msg,
								},
							);
						}
						if let Some((tx, close_res)) = tx_shutdown_result {
							// We're done with this channel, we've got a signed closing transaction and
							// will send the closing_signed back to the remote peer upon return. This
							// also implies there are no pending HTLCs left on the channel, so we can
							// fully delete it from tracking (the channel monitor is still around to
							// watch for old state broadcasts)!
							let err = self.locked_handle_funded_coop_close(
								&mut peer_state.closed_channel_monitor_update_ids,
								&mut peer_state.in_flight_monitor_updates,
								close_res,
								chan,
							);
							chan_entry.remove();
							Some((tx, Err(err)))
						} else {
							None
						}
					} else {
						return try_channel_entry!(
							self,
							peer_state,
							Err(ChannelError::close(
								"Got a closing_signed message for an unfunded channel!".into()
							)),
							chan_entry
						);
					}
				},
				hash_map::Entry::Vacant(_) => {
					return Err(MsgHandleErrInternal::no_such_channel_for_peer(
						counterparty_node_id,
						msg.channel_id,
					))
				},
			}
		};
		mem::drop(per_peer_state);
		if let Some((broadcast_tx, err)) = tx_err {
			log_info!(logger, "Broadcasting {}", log_tx!(broadcast_tx));
			self.tx_broadcaster.broadcast_transactions(&[(
				&broadcast_tx,
				TransactionType::CooperativeClose {
					counterparty_node_id: *counterparty_node_id,
					channel_id: msg.channel_id,
				},
			)]);
			let _ = self.handle_error(err, *counterparty_node_id);
		}
		Ok(())
	}

	#[cfg(simple_close)]
	fn internal_closing_complete(
		&self, _counterparty_node_id: PublicKey, _msg: msgs::ClosingComplete,
	) -> Result<(), MsgHandleErrInternal> {
		unimplemented!("Handling ClosingComplete is not implemented");
	}

	#[cfg(simple_close)]
	fn internal_closing_sig(
		&self, _counterparty_node_id: PublicKey, _msg: msgs::ClosingSig,
	) -> Result<(), MsgHandleErrInternal> {
		unimplemented!("Handling ClosingSig is not implemented");
	}

	#[rustfmt::skip]
	fn internal_update_add_htlc(&self, counterparty_node_id: &PublicKey, msg: &msgs::UpdateAddHTLC) -> Result<(), MsgHandleErrInternal> {
		//TODO: BOLT 4 points out a specific attack where a peer may re-send an onion packet and
		//determine the state of the payment based on our response/if we forward anything/the time
		//we take to respond. We should take care to avoid allowing such an attack.
		//
		//TODO: There exists a further attack where a node may garble the onion data, forward it to
		//us repeatedly garbled in different ways, and compare our error messages, which are
		//encrypted with the same key. It's not immediately obvious how to usefully exploit that,
		//but we should prevent it anyway.

		// Note that the ChannelManager is NOT re-persisted on disk after this (unless we error
		// closing a channel), so any changes are likely to be lost on restart!

		let per_peer_state = self.per_peer_state.read().unwrap();
		let peer_state_mutex = per_peer_state.get(counterparty_node_id).ok_or_else(|| {
			MsgHandleErrInternal::unreachable_no_such_peer(counterparty_node_id, msg.channel_id)
		})?;
		let mut peer_state_lock = peer_state_mutex.lock().unwrap();
		let peer_state = &mut *peer_state_lock;
		match peer_state.channel_by_id.entry(msg.channel_id) {
			hash_map::Entry::Occupied(mut chan_entry) => {
				if let Some(chan) = chan_entry.get_mut().as_funded_mut() {
					try_channel_entry!(self, peer_state, chan.update_add_htlc(&msg, &self.fee_estimator), chan_entry);
				} else {
					return try_channel_entry!(self, peer_state, Err(ChannelError::close(
						"Got an update_add_htlc message for an unfunded channel!".into())), chan_entry);
				}
			},
			hash_map::Entry::Vacant(_) => return Err(MsgHandleErrInternal::no_such_channel_for_peer(counterparty_node_id, msg.channel_id))
		}
		Ok(())
	}

	fn internal_update_fulfill_htlc(
		&self, counterparty_node_id: &PublicKey, msg: msgs::UpdateFulfillHTLC,
	) -> Result<(), MsgHandleErrInternal> {
		let funding_txo;
		let next_user_channel_id;
		let (htlc_source, forwarded_htlc_value, skimmed_fee_msat, send_timestamp) = {
			let per_peer_state = self.per_peer_state.read().unwrap();
			let peer_state_mutex = per_peer_state.get(counterparty_node_id).ok_or_else(|| {
				MsgHandleErrInternal::unreachable_no_such_peer(counterparty_node_id, msg.channel_id)
			})?;
			let mut peer_state_lock = peer_state_mutex.lock().unwrap();
			let peer_state = &mut *peer_state_lock;
			match peer_state.channel_by_id.entry(msg.channel_id) {
				hash_map::Entry::Occupied(mut chan_entry) => {
					if let Some(chan) = chan_entry.get_mut().as_funded_mut() {
						let res = try_channel_entry!(
							self,
							peer_state,
							chan.update_fulfill_htlc(&msg),
							chan_entry
						);
						if let HTLCSource::PreviousHopData(prev_hop) = &res.0 {
							let logger =
								WithChannelContext::from(&self.logger, &chan.context, None);
							log_trace!(logger,
								"Holding the next revoke_and_ack until the preimage is durably persisted in the inbound edge's ChannelMonitor",
								);
							peer_state
								.actions_blocking_raa_monitor_updates
								.entry(msg.channel_id)
								.or_insert_with(Vec::new)
								.push(RAAMonitorUpdateBlockingAction::from_prev_hop_data(
									&prev_hop,
								));
						}
						// Note that we do not need to push an `actions_blocking_raa_monitor_updates`
						// entry here, even though we *do* need to block the next RAA monitor update.
						// We do this instead in the `claim_funds_internal` by attaching a
						// `ReleaseRAAChannelMonitorUpdate` action to the event generated when the
						// outbound HTLC is claimed. This is guaranteed to all complete before we
						// process the RAA as messages are processed from single peers serially.
						funding_txo = chan
							.funding
							.get_funding_txo()
							.expect("We won't accept a fulfill until funded");
						next_user_channel_id = chan.context.get_user_id();
						res
					} else {
						return try_channel_entry!(
							self,
							peer_state,
							Err(ChannelError::close(
								"Got an update_fulfill_htlc message for an unfunded channel!"
									.into()
							)),
							chan_entry
						);
					}
				},
				hash_map::Entry::Vacant(_) => {
					return Err(MsgHandleErrInternal::no_such_channel_for_peer(
						counterparty_node_id,
						msg.channel_id,
					))
				},
			}
		};
		self.claim_funds_internal(
			htlc_source,
			msg.payment_preimage.clone(),
			Some(forwarded_htlc_value),
			skimmed_fee_msat,
			false,
			*counterparty_node_id,
			funding_txo,
			msg.channel_id,
			Some(next_user_channel_id),
			msg.attribution_data,
			send_timestamp,
		);

		Ok(())
	}

	#[rustfmt::skip]
	fn internal_update_fail_htlc(&self, counterparty_node_id: &PublicKey, msg: &msgs::UpdateFailHTLC) -> Result<(), MsgHandleErrInternal> {
		// Note that the ChannelManager is NOT re-persisted on disk after this (unless we error
		// closing a channel), so any changes are likely to be lost on restart!
		let per_peer_state = self.per_peer_state.read().unwrap();
		let peer_state_mutex = per_peer_state.get(counterparty_node_id).ok_or_else(|| {
			MsgHandleErrInternal::unreachable_no_such_peer(counterparty_node_id, msg.channel_id)
		})?;
		let mut peer_state_lock = peer_state_mutex.lock().unwrap();
		let peer_state = &mut *peer_state_lock;
		match peer_state.channel_by_id.entry(msg.channel_id) {
			hash_map::Entry::Occupied(mut chan_entry) => {
				if let Some(chan) = chan_entry.get_mut().as_funded_mut() {
					try_channel_entry!(self, peer_state, chan.update_fail_htlc(&msg, HTLCFailReason::from_msg(msg)), chan_entry);
				} else {
					return try_channel_entry!(self, peer_state, Err(ChannelError::close(
						"Got an update_fail_htlc message for an unfunded channel!".into())), chan_entry);
				}
			},
			hash_map::Entry::Vacant(_) => return Err(MsgHandleErrInternal::no_such_channel_for_peer(counterparty_node_id, msg.channel_id))
		}
		Ok(())
	}

	#[rustfmt::skip]
	fn internal_update_fail_malformed_htlc(&self, counterparty_node_id: &PublicKey, msg: &msgs::UpdateFailMalformedHTLC) -> Result<(), MsgHandleErrInternal> {
		// Note that the ChannelManager is NOT re-persisted on disk after this (unless we error
		// closing a channel), so any changes are likely to be lost on restart!
		let per_peer_state = self.per_peer_state.read().unwrap();
		let peer_state_mutex = per_peer_state.get(counterparty_node_id).ok_or_else(|| {
			MsgHandleErrInternal::unreachable_no_such_peer(counterparty_node_id, msg.channel_id)
		})?;
		let mut peer_state_lock = peer_state_mutex.lock().unwrap();
		let peer_state = &mut *peer_state_lock;
		match peer_state.channel_by_id.entry(msg.channel_id) {
			hash_map::Entry::Occupied(mut chan_entry) => {
				if (msg.failure_code & 0x8000) == 0 {
					let chan_err = ChannelError::close("Got update_fail_malformed_htlc with BADONION not set".to_owned());
					try_channel_entry!(self, peer_state, Err(chan_err), chan_entry);
				}
				if let Some(chan) = chan_entry.get_mut().as_funded_mut() {
					try_channel_entry!(self, peer_state, chan.update_fail_malformed_htlc(&msg, HTLCFailReason::reason(msg.failure_code.into(), msg.sha256_of_onion.to_vec())), chan_entry);
				} else {
					return try_channel_entry!(self, peer_state, Err(ChannelError::close(
						"Got an update_fail_malformed_htlc message for an unfunded channel!".into())), chan_entry);
				}
				Ok(())
			},
			hash_map::Entry::Vacant(_) => return Err(MsgHandleErrInternal::no_such_channel_for_peer(counterparty_node_id, msg.channel_id))
		}
	}

	fn internal_commitment_signed(
		&self, counterparty_node_id: &PublicKey, msg: &msgs::CommitmentSigned,
	) -> Result<(), MsgHandleErrInternal> {
		let best_block = *self.best_block.read().unwrap();
		let per_peer_state = self.per_peer_state.read().unwrap();
		let peer_state_mutex = per_peer_state.get(counterparty_node_id).ok_or_else(|| {
			MsgHandleErrInternal::unreachable_no_such_peer(counterparty_node_id, msg.channel_id)
		})?;
		let mut peer_state_lock = peer_state_mutex.lock().unwrap();
		let peer_state = &mut *peer_state_lock;
		match peer_state.channel_by_id.entry(msg.channel_id) {
			hash_map::Entry::Occupied(mut chan_entry) => {
				let chan = chan_entry.get_mut();
				let logger = WithChannelContext::from(&self.logger, &chan.context(), None);
				let funding_txo = chan.funding().get_funding_txo();
				let res = chan.commitment_signed(
					msg,
					best_block,
					&self.signer_provider,
					&self.fee_estimator,
					&&logger,
				);
				let (monitor_opt, monitor_update_opt) =
					try_channel_entry!(self, peer_state, res, chan_entry);

				if let Some(chan) = chan.as_funded_mut() {
					if let Some(monitor) = monitor_opt {
						let monitor_res =
							self.chain_monitor.watch_channel(monitor.channel_id(), monitor);
						if let Ok(persist_state) = monitor_res {
							if let Some(data) = self.handle_initial_monitor(
								&mut peer_state.in_flight_monitor_updates,
								&mut peer_state.monitor_update_blocked_actions,
								&mut peer_state.pending_msg_events,
								peer_state.is_connected,
								chan,
								persist_state,
							) {
								mem::drop(peer_state_lock);
								mem::drop(per_peer_state);
								self.handle_post_monitor_update_chan_resume(data);
							}
						} else {
							let logger =
								WithChannelContext::from(&self.logger, &chan.context, None);
							log_error!(logger, "Persisting initial ChannelMonitor failed, implying the channel ID was duplicated");
							let msg = "Channel ID was a duplicate";
							let reason = ClosureReason::ProcessingError { err: msg.to_owned() };
							let err = ChannelError::Close((msg.to_owned(), reason));
							try_channel_entry!(self, peer_state, Err(err), chan_entry)
						}
					} else if let Some(monitor_update) = monitor_update_opt {
						if let Some(data) = self.handle_new_monitor_update(
							&mut peer_state.in_flight_monitor_updates,
							&mut peer_state.monitor_update_blocked_actions,
							&mut peer_state.pending_msg_events,
							peer_state.is_connected,
							chan,
							funding_txo.unwrap(),
							monitor_update,
						) {
							mem::drop(peer_state_lock);
							mem::drop(per_peer_state);
							self.handle_post_monitor_update_chan_resume(data);
						}
					}
				}
				Ok(())
			},
			hash_map::Entry::Vacant(_) => Err(MsgHandleErrInternal::no_such_channel_for_peer(
				counterparty_node_id,
				msg.channel_id,
			)),
		}
	}

	#[rustfmt::skip]
	fn internal_commitment_signed_batch(&self, counterparty_node_id: &PublicKey, channel_id: ChannelId, batch: Vec<msgs::CommitmentSigned>) -> Result<(), MsgHandleErrInternal> {
		let per_peer_state = self.per_peer_state.read().unwrap();
		let peer_state_mutex = per_peer_state.get(counterparty_node_id).ok_or_else(|| {
			MsgHandleErrInternal::unreachable_no_such_peer(counterparty_node_id, channel_id)
		})?;
		let mut peer_state_lock = peer_state_mutex.lock().unwrap();
		let peer_state = &mut *peer_state_lock;
		match peer_state.channel_by_id.entry(channel_id) {
			hash_map::Entry::Occupied(mut chan_entry) => {
				let chan = chan_entry.get_mut();
				let logger = WithChannelContext::from(&self.logger, &chan.context(), None);
				let funding_txo = chan.funding().get_funding_txo();
				if let Some(chan) = chan.as_funded_mut() {
					let monitor_update_opt = try_channel_entry!(
						self, peer_state, chan.commitment_signed_batch(batch, &self.fee_estimator, &&logger), chan_entry
					);

					if let Some(monitor_update) = monitor_update_opt {
						if let Some(data) = self.handle_new_monitor_update(
							&mut peer_state.in_flight_monitor_updates,
							&mut peer_state.monitor_update_blocked_actions,
							&mut peer_state.pending_msg_events,
							peer_state.is_connected,
							chan,
							funding_txo.unwrap(),
							monitor_update,
						) {
							mem::drop(peer_state_lock);
							mem::drop(per_peer_state);
							self.handle_post_monitor_update_chan_resume(data);
						}
					}
				}
				Ok(())
			},
			hash_map::Entry::Vacant(_) => Err(MsgHandleErrInternal::no_such_channel_for_peer(counterparty_node_id, channel_id))
		}
	}

	fn push_decode_update_add_htlcs(&self, mut update_add_htlcs: (u64, Vec<msgs::UpdateAddHTLC>)) {
		let mut decode_update_add_htlcs = self.decode_update_add_htlcs.lock().unwrap();
		let src_outbound_scid_alias = update_add_htlcs.0;
		match decode_update_add_htlcs.entry(src_outbound_scid_alias) {
			hash_map::Entry::Occupied(mut e) => {
				e.get_mut().append(&mut update_add_htlcs.1);
			},
			hash_map::Entry::Vacant(e) => {
				e.insert(update_add_htlcs.1);
			},
		}
	}

	#[inline]
	fn forward_htlcs<I: IntoIterator<Item = PendingAddHTLCInfo>>(&self, pending_forwards: I) {
		for htlc in pending_forwards.into_iter() {
			let scid = match htlc.forward_info.routing {
				PendingHTLCRouting::Forward { short_channel_id, .. } => short_channel_id,
				PendingHTLCRouting::TrampolineForward { .. }
				| PendingHTLCRouting::Receive { .. }
				| PendingHTLCRouting::ReceiveKeysend { .. } => 0,
			};

			match self.forward_htlcs.lock().unwrap().entry(scid) {
				hash_map::Entry::Occupied(mut entry) => {
					entry.get_mut().push(HTLCForwardInfo::AddHTLC(htlc));
				},
				hash_map::Entry::Vacant(entry) => {
					entry.insert(vec![HTLCForwardInfo::AddHTLC(htlc)]);
				},
			}
		}
	}

	/// Checks whether [`ChannelMonitorUpdate`]s generated by the receipt of a remote
	/// [`msgs::RevokeAndACK`] should be held for the given channel until some other action
	/// completes. Note that this needs to happen in the same [`PeerState`] mutex as any release of
	/// the [`ChannelMonitorUpdate`] in question.
	#[rustfmt::skip]
	fn raa_monitor_updates_held(&self,
		actions_blocking_raa_monitor_updates: &BTreeMap<ChannelId, Vec<RAAMonitorUpdateBlockingAction>>,
		channel_id: ChannelId, counterparty_node_id: PublicKey,
	) -> bool {
		actions_blocking_raa_monitor_updates
			.get(&channel_id).map(|v| !v.is_empty()).unwrap_or(false)
		|| self.pending_events.lock().unwrap().iter().any(|(_, action)| {
			if let Some(EventCompletionAction::ReleaseRAAChannelMonitorUpdate {
				channel_funding_outpoint: _,
				channel_id: ev_channel_id,
				counterparty_node_id: ev_counterparty_node_id
			}) = action {
				*ev_channel_id == channel_id && *ev_counterparty_node_id == counterparty_node_id
			} else {
				false
			}
		})
	}

	#[cfg(any(test, feature = "_test_utils"))]
	pub(crate) fn test_raa_monitor_updates_held(
		&self, counterparty_node_id: PublicKey, channel_id: ChannelId,
	) -> bool {
		let per_peer_state = self.per_peer_state.read().unwrap();
		if let Some(peer_state_mtx) = per_peer_state.get(&counterparty_node_id) {
			let mut peer_state_lck = peer_state_mtx.lock().unwrap();
			let peer_state = &mut *peer_state_lck;

			assert!(peer_state.channel_by_id.contains_key(&channel_id));
			return self.raa_monitor_updates_held(
				&peer_state.actions_blocking_raa_monitor_updates,
				channel_id,
				counterparty_node_id,
			);
		}
		false
	}

	#[rustfmt::skip]
	fn internal_revoke_and_ack(&self, counterparty_node_id: &PublicKey, msg: &msgs::RevokeAndACK) -> Result<(), MsgHandleErrInternal> {
		let (htlcs_to_fail, static_invoices) = {
			let per_peer_state = self.per_peer_state.read().unwrap();
			let mut peer_state_lock = per_peer_state.get(counterparty_node_id).ok_or_else(|| {
				MsgHandleErrInternal::unreachable_no_such_peer(counterparty_node_id, msg.channel_id)
			}).map(|mtx| mtx.lock().unwrap())?;
			let peer_state = &mut *peer_state_lock;
			match peer_state.channel_by_id.entry(msg.channel_id) {
				hash_map::Entry::Occupied(mut chan_entry) => {
					if let Some(chan) = chan_entry.get_mut().as_funded_mut() {
						let logger = WithChannelContext::from(&self.logger, &chan.context, None);
						let funding_txo_opt = chan.funding.get_funding_txo();
						let mon_update_blocked = self.raa_monitor_updates_held(
							&peer_state.actions_blocking_raa_monitor_updates, msg.channel_id,
							*counterparty_node_id);
						let (htlcs_to_fail, static_invoices, monitor_update_opt) = try_channel_entry!(self, peer_state,
							chan.revoke_and_ack(&msg, &self.fee_estimator, &&logger, mon_update_blocked), chan_entry);
						if let Some(monitor_update) = monitor_update_opt {
							let funding_txo = funding_txo_opt
								.expect("Funding outpoint must have been set for RAA handling to succeed");
							if let Some(data) = self.handle_new_monitor_update(
								&mut peer_state.in_flight_monitor_updates,
								&mut peer_state.monitor_update_blocked_actions,
								&mut peer_state.pending_msg_events,
								peer_state.is_connected,
								chan,
								funding_txo,
								monitor_update,
							) {
								mem::drop(peer_state_lock);
								mem::drop(per_peer_state);
								self.handle_post_monitor_update_chan_resume(data);
							}
						}
						(htlcs_to_fail, static_invoices)
					} else {
						return try_channel_entry!(self, peer_state, Err(ChannelError::close(
							"Got a revoke_and_ack message for an unfunded channel!".into())), chan_entry);
					}
				},
				hash_map::Entry::Vacant(_) => return Err(MsgHandleErrInternal::no_such_channel_for_peer(counterparty_node_id, msg.channel_id))
			}
		};
		self.fail_holding_cell_htlcs(htlcs_to_fail, msg.channel_id, counterparty_node_id);
		for (static_invoice, reply_path) in static_invoices {
			let res = self.flow.enqueue_held_htlc_available(&static_invoice, HeldHtlcReplyPath::ToCounterparty { path: reply_path });
			debug_assert!(res.is_ok(), "enqueue_held_htlc_available can only fail for non-async senders");
		}
		Ok(())
	}

	#[rustfmt::skip]
	fn internal_update_fee(&self, counterparty_node_id: &PublicKey, msg: &msgs::UpdateFee) -> Result<(), MsgHandleErrInternal> {
		let per_peer_state = self.per_peer_state.read().unwrap();
		let peer_state_mutex = per_peer_state.get(counterparty_node_id).ok_or_else(|| {
			MsgHandleErrInternal::unreachable_no_such_peer(counterparty_node_id, msg.channel_id)
		})?;
		let mut peer_state_lock = peer_state_mutex.lock().unwrap();
		let peer_state = &mut *peer_state_lock;
		match peer_state.channel_by_id.entry(msg.channel_id) {
			hash_map::Entry::Occupied(mut chan_entry) => {
				if let Some(chan) = chan_entry.get_mut().as_funded_mut() {
					let logger = WithChannelContext::from(&self.logger, &chan.context, None);
					try_channel_entry!(self, peer_state, chan.update_fee(&self.fee_estimator, &msg, &&logger), chan_entry);
				} else {
					return try_channel_entry!(self, peer_state, Err(ChannelError::close(
						"Got an update_fee message for an unfunded channel!".into())), chan_entry);
				}
			},
			hash_map::Entry::Vacant(_) => return Err(MsgHandleErrInternal::no_such_channel_for_peer(counterparty_node_id, msg.channel_id))
		}
		Ok(())
	}

	#[rustfmt::skip]
	fn internal_stfu(&self, counterparty_node_id: &PublicKey, msg: &msgs::Stfu) -> Result<bool, MsgHandleErrInternal> {
		let per_peer_state = self.per_peer_state.read().unwrap();
		let peer_state_mutex = per_peer_state.get(counterparty_node_id).ok_or_else(|| {
			MsgHandleErrInternal::unreachable_no_such_peer(counterparty_node_id, msg.channel_id)
		})?;
		let mut peer_state_lock = peer_state_mutex.lock().unwrap();
		let peer_state = &mut *peer_state_lock;

		if !self.init_features().supports_quiescence() {
			return Err(MsgHandleErrInternal::from_chan_no_close(
				ChannelError::Warn("Quiescense not supported".to_string()), msg.channel_id
			));
		}

		match peer_state.channel_by_id.entry(msg.channel_id) {
			hash_map::Entry::Occupied(mut chan_entry) => {
				if let Some(chan) = chan_entry.get_mut().as_funded_mut() {
					let logger = WithContext::from(
						&self.logger, Some(*counterparty_node_id), Some(msg.channel_id), None
					);

					let res = chan.stfu(&msg, &&logger);
					let resp = try_channel_entry!(self, peer_state, res, chan_entry);
					match resp {
						None => Ok(false),
						Some(StfuResponse::Stfu(msg)) => {
							peer_state.pending_msg_events.push(MessageSendEvent::SendStfu {
								node_id: *counterparty_node_id,
								msg,
							});
							Ok(true)
						},
						Some(StfuResponse::SpliceInit(msg)) => {
							peer_state.pending_msg_events.push(MessageSendEvent::SendSpliceInit {
								node_id: *counterparty_node_id,
								msg,
							});
							Ok(true)
						},
					}
				} else {
					let msg = "Peer sent `stfu` for an unfunded channel";
					let err = Err(ChannelError::Close(
						(msg.into(), ClosureReason::ProcessingError { err: msg.into() })
					));
					return try_channel_entry!(self, peer_state, err, chan_entry);
				}
			},
			hash_map::Entry::Vacant(_) => return Err(MsgHandleErrInternal::no_such_channel_for_peer(counterparty_node_id, msg.channel_id
			))
		}
	}

	#[rustfmt::skip]
	fn internal_announcement_signatures(&self, counterparty_node_id: &PublicKey, msg: &msgs::AnnouncementSignatures) -> Result<(), MsgHandleErrInternal> {
		let per_peer_state = self.per_peer_state.read().unwrap();
		let peer_state_mutex = per_peer_state.get(counterparty_node_id).ok_or_else(|| {
			MsgHandleErrInternal::unreachable_no_such_peer(counterparty_node_id, msg.channel_id)
		})?;
		let mut peer_state_lock = peer_state_mutex.lock().unwrap();
		let peer_state = &mut *peer_state_lock;
		match peer_state.channel_by_id.entry(msg.channel_id) {
			hash_map::Entry::Occupied(mut chan_entry) => {
				if let Some(chan) = chan_entry.get_mut().as_funded_mut() {
					if !chan.context.is_usable() {
						return Err(MsgHandleErrInternal::from_no_close(LightningError{err: "Got an announcement_signatures before we were ready for it".to_owned(), action: msgs::ErrorAction::IgnoreError}));
					}

					let cur_height = self.best_block.read().unwrap().height;
					let res = chan.announcement_signatures(
						&self.node_signer,
						self.chain_hash,
						cur_height,
						msg,
						&self.config.read().unwrap(),
					);
					peer_state.pending_msg_events.push(MessageSendEvent::BroadcastChannelAnnouncement {
						msg: try_channel_entry!(self, peer_state, res, chan_entry),
						// Note that announcement_signatures fails if the channel cannot be announced,
						// so get_channel_update_for_broadcast will never fail by the time we get here.
						update_msg: Some(self.get_channel_update_for_broadcast(chan).unwrap().0),
					});
				} else {
					return try_channel_entry!(self, peer_state, Err(ChannelError::close(
						"Got an announcement_signatures message for an unfunded channel!".into())), chan_entry);
				}
			},
			hash_map::Entry::Vacant(_) => return Err(MsgHandleErrInternal::no_such_channel_for_peer(counterparty_node_id, msg.channel_id))
		}
		Ok(())
	}

	/// Returns DoPersist if anything changed, otherwise either SkipPersistNoEvents or an Err.
	#[rustfmt::skip]
	fn internal_channel_update(&self, counterparty_node_id: &PublicKey, msg: &msgs::ChannelUpdate) -> Result<NotifyOption, MsgHandleErrInternal> {
		let (chan_counterparty_node_id, chan_id) = match self.short_to_chan_info.read().unwrap().get(&msg.contents.short_channel_id) {
			Some((cp_id, chan_id)) => (cp_id.clone(), chan_id.clone()),
			None => {
				// It's not a local channel
				if msg.contents.message_flags & (1 << 1) != 0 {
					log_debug!(self.logger, "Received channel_update for unknown channel {} with dont_forward set. You may wish to check if an incorrect tx_index was passed to chain::Confirm::transactions_confirmed.", msg.contents.short_channel_id);
				}
				return Ok(NotifyOption::SkipPersistNoEvents)
			}
		};
		let per_peer_state = self.per_peer_state.read().unwrap();
		let peer_state_mutex_opt = per_peer_state.get(&chan_counterparty_node_id);
		if peer_state_mutex_opt.is_none() {
			return Ok(NotifyOption::SkipPersistNoEvents)
		}
		let mut peer_state_lock = peer_state_mutex_opt.unwrap().lock().unwrap();
		let peer_state = &mut *peer_state_lock;
		match peer_state.channel_by_id.entry(chan_id) {
			hash_map::Entry::Occupied(mut chan_entry) => {
				if let Some(chan) = chan_entry.get_mut().as_funded_mut() {
					if chan.context.get_counterparty_node_id() != *counterparty_node_id {
						if chan.context.should_announce() {
							// If the announcement is about a channel of ours which is public, some
							// other peer may simply be forwarding all its gossip to us. Don't provide
							// a scary-looking error message and return Ok instead.
							return Ok(NotifyOption::SkipPersistNoEvents);
						}
						return Err(MsgHandleErrInternal::send_err_msg_no_close("Got a channel_update for a channel from the wrong node - it shouldn't know about our private channels!".to_owned(), chan_id));
					}
					let were_node_one = self.get_our_node_id().serialize()[..] < chan.context.get_counterparty_node_id().serialize()[..];
					let msg_from_node_one = msg.contents.channel_flags & 1 == 0;
					if were_node_one == msg_from_node_one {
						return Ok(NotifyOption::SkipPersistNoEvents);
					} else {
						let logger = WithChannelContext::from(&self.logger, &chan.context, None);
						log_debug!(logger, "Received channel_update {:?}.", msg);
						let did_change = try_channel_entry!(self, peer_state, chan.channel_update(&msg), chan_entry);
						// If nothing changed after applying their update, we don't need to bother
						// persisting.
						if !did_change {
							return Ok(NotifyOption::SkipPersistNoEvents);
						}
					}
				} else {
					return try_channel_entry!(self, peer_state, Err(ChannelError::close(
						"Got a channel_update for an unfunded channel!".into())), chan_entry);
				}
			},
			hash_map::Entry::Vacant(_) => return Ok(NotifyOption::SkipPersistNoEvents)
		}
		Ok(NotifyOption::DoPersist)
	}

	#[rustfmt::skip]
	fn internal_channel_reestablish(&self, counterparty_node_id: &PublicKey, msg: &msgs::ChannelReestablish) -> Result<(), MsgHandleErrInternal> {
		let (inferred_splice_locked, need_lnd_workaround, holding_cell_res) = {
			let per_peer_state = self.per_peer_state.read().unwrap();

			let peer_state_mutex = per_peer_state.get(counterparty_node_id).ok_or_else(|| {
				MsgHandleErrInternal::unreachable_no_such_peer(counterparty_node_id, msg.channel_id)
			})?;
			let logger = WithContext::from(&self.logger, Some(*counterparty_node_id), Some(msg.channel_id), None);
			let mut peer_state_lock = peer_state_mutex.lock().unwrap();
			let peer_state = &mut *peer_state_lock;
			match peer_state.channel_by_id.entry(msg.channel_id) {
				hash_map::Entry::Occupied(mut chan_entry) => {
					if let Some(chan) = chan_entry.get_mut().as_funded_mut() {
						// Currently, we expect all holding cell update_adds to be dropped on peer
						// disconnect, so Channel's reestablish will never hand us any holding cell
						// freed HTLCs to fail backwards. If in the future we no longer drop pending
						// add-HTLCs on disconnect, we may be handed HTLCs to fail backwards here.
						let outbound_scid_alias = chan.context.outbound_scid_alias();
						let res = chan.channel_reestablish(
							msg,
							&&logger,
							&self.node_signer,
							self.chain_hash,
							&self.config.read().unwrap(),
							&*self.best_block.read().unwrap(),
							|htlc_id| self.path_for_release_held_htlc(htlc_id, outbound_scid_alias, &msg.channel_id, counterparty_node_id)
						);
						let responses = try_channel_entry!(self, peer_state, res, chan_entry);
						let mut channel_update = None;
						if let Some(msg) = responses.shutdown_msg {
							peer_state.pending_msg_events.push(MessageSendEvent::SendShutdown {
								node_id: counterparty_node_id.clone(),
								msg,
							});
						} else if chan.context.is_usable() {
							// If the channel is in a usable state (ie the channel is not being shut
							// down), send a unicast channel_update to our counterparty to make sure
							// they have the latest channel parameters.
							if let Ok((msg, _, _)) = self.get_channel_update_for_unicast(chan) {
								channel_update = Some(MessageSendEvent::SendChannelUpdate {
									node_id: chan.context.get_counterparty_node_id(),
									msg,
								});
							}
						}
						let need_lnd_workaround = chan.context.workaround_lnd_bug_4006.take();
						let (htlc_forwards, decode_update_add_htlcs) = self.handle_channel_resumption(
							&mut peer_state.pending_msg_events, chan, responses.raa, responses.commitment_update, responses.commitment_order,
							Vec::new(), Vec::new(), None, responses.channel_ready, responses.announcement_sigs,
							responses.tx_signatures, responses.tx_abort, responses.channel_ready_order,
						);
						debug_assert!(htlc_forwards.is_empty());
						debug_assert!(decode_update_add_htlcs.is_none());
						if let Some(upd) = channel_update {
							peer_state.pending_msg_events.push(upd);
						}

						let holding_cell_res = self.check_free_peer_holding_cells(peer_state);
						(responses.inferred_splice_locked, need_lnd_workaround, holding_cell_res)
					} else {
						return try_channel_entry!(self, peer_state, Err(ChannelError::close(
							"Got a channel_reestablish message for an unfunded channel!".into())), chan_entry);
					}
				},
				hash_map::Entry::Vacant(_) => {
					log_debug!(logger, "Sending bogus ChannelReestablish for unknown channel to force channel closure",
						);
					// Unfortunately, lnd doesn't force close on errors
					// (https://github.com/lightningnetwork/lnd/blob/abb1e3463f3a83bbb843d5c399869dbe930ad94f/htlcswitch/link.go#L2119).
					// One of the few ways to get an lnd counterparty to force close is by
					// replicating what they do when restoring static channel backups (SCBs). They
					// send an invalid `ChannelReestablish` with `0` commitment numbers and an
					// invalid `your_last_per_commitment_secret`.
					//
					// Since we received a `ChannelReestablish` for a channel that doesn't exist, we
					// can assume it's likely the channel closed from our point of view, but it
					// remains open on the counterparty's side. By sending this bogus
					// `ChannelReestablish` message now as a response to theirs, we trigger them to
					// force close broadcasting their latest state. If the closing transaction from
					// our point of view remains unconfirmed, it'll enter a race with the
					// counterparty's to-be-broadcast latest commitment transaction.
					peer_state.pending_msg_events.push(MessageSendEvent::SendChannelReestablish {
						node_id: *counterparty_node_id,
						msg: msgs::ChannelReestablish {
							channel_id: msg.channel_id,
							next_local_commitment_number: 0,
							next_remote_commitment_number: 0,
							your_last_per_commitment_secret: [1u8; 32],
							my_current_per_commitment_point: PublicKey::from_slice(&[2u8; 33]).unwrap(),
							next_funding: None,
							my_current_funding_locked: None,
						},
					});
					return Err(MsgHandleErrInternal::no_such_channel_for_peer(counterparty_node_id, msg.channel_id)
					)
				}
			}
		};

		self.handle_holding_cell_free_result(holding_cell_res);

		if let Some(channel_ready_msg) = need_lnd_workaround {
			self.internal_channel_ready(counterparty_node_id, &channel_ready_msg)?;
		}

		if let Some(splice_locked) = inferred_splice_locked {
			self.internal_splice_locked(counterparty_node_id, &splice_locked)?;
		}

		Ok(())
	}

	/// Handle incoming splice request, transition channel to splice-pending (unless some check fails).
	fn internal_splice_init(
		&self, counterparty_node_id: &PublicKey, msg: &msgs::SpliceInit,
	) -> Result<(), MsgHandleErrInternal> {
		let per_peer_state = self.per_peer_state.read().unwrap();
		let peer_state_mutex = per_peer_state.get(counterparty_node_id).ok_or_else(|| {
			MsgHandleErrInternal::unreachable_no_such_peer(counterparty_node_id, msg.channel_id)
		})?;
		let mut peer_state_lock = peer_state_mutex.lock().unwrap();
		let peer_state = &mut *peer_state_lock;

		// TODO(splicing): Currently not possible to contribute on the splicing-acceptor side
		let our_funding_contribution = 0i64;

		// Look for the channel
		match peer_state.channel_by_id.entry(msg.channel_id) {
			hash_map::Entry::Vacant(_) => {
				return Err(MsgHandleErrInternal::no_such_channel_for_peer(
					counterparty_node_id,
					msg.channel_id,
				))
			},
			hash_map::Entry::Occupied(mut chan_entry) => {
				if self.config.read().unwrap().reject_inbound_splices {
					let err = ChannelError::WarnAndDisconnect(
						"Inbound channel splices are currently not allowed".to_owned(),
					);
					return Err(MsgHandleErrInternal::from_chan_no_close(err, msg.channel_id));
				}

				if let Some(ref mut funded_channel) = chan_entry.get_mut().as_funded_mut() {
					let init_res = funded_channel.splice_init(
						msg,
						our_funding_contribution,
						&self.signer_provider,
						&self.entropy_source,
						&self.get_our_node_id(),
						&self.logger,
					);
					let splice_ack_msg = try_channel_entry!(self, peer_state, init_res, chan_entry);
					peer_state.pending_msg_events.push(MessageSendEvent::SendSpliceAck {
						node_id: *counterparty_node_id,
						msg: splice_ack_msg,
					});
					Ok(())
				} else {
					try_channel_entry!(
						self,
						peer_state,
						Err(ChannelError::close("Channel is not funded, cannot be spliced".into())),
						chan_entry
					)
				}
			},
		}
	}

	/// Handle incoming splice request ack, transition channel to splice-pending (unless some check fails).
	fn internal_splice_ack(
		&self, counterparty_node_id: &PublicKey, msg: &msgs::SpliceAck,
	) -> Result<(), MsgHandleErrInternal> {
		let per_peer_state = self.per_peer_state.read().unwrap();
		let peer_state_mutex = per_peer_state.get(counterparty_node_id).ok_or_else(|| {
			MsgHandleErrInternal::unreachable_no_such_peer(counterparty_node_id, msg.channel_id)
		})?;
		let mut peer_state_lock = peer_state_mutex.lock().unwrap();
		let peer_state = &mut *peer_state_lock;

		// Look for the channel
		match peer_state.channel_by_id.entry(msg.channel_id) {
			hash_map::Entry::Vacant(_) => Err(MsgHandleErrInternal::no_such_channel_for_peer(
				counterparty_node_id,
				msg.channel_id,
			)),
			hash_map::Entry::Occupied(mut chan_entry) => {
				if let Some(ref mut funded_channel) = chan_entry.get_mut().as_funded_mut() {
					let splice_ack_res = funded_channel.splice_ack(
						msg,
						&self.signer_provider,
						&self.entropy_source,
						&self.get_our_node_id(),
						&self.logger,
					);
					let tx_msg_opt =
						try_channel_entry!(self, peer_state, splice_ack_res, chan_entry);
					if let Some(tx_msg) = tx_msg_opt {
						peer_state
							.pending_msg_events
							.push(tx_msg.into_msg_send_event(counterparty_node_id.clone()));
					}
					Ok(())
				} else {
					try_channel_entry!(
						self,
						peer_state,
						Err(ChannelError::close("Channel is not funded, cannot be spliced".into())),
						chan_entry
					)
				}
			},
		}
	}

	fn internal_splice_locked(
		&self, counterparty_node_id: &PublicKey, msg: &msgs::SpliceLocked,
	) -> Result<(), MsgHandleErrInternal> {
		let per_peer_state = self.per_peer_state.read().unwrap();
		let peer_state_mutex = per_peer_state.get(counterparty_node_id).ok_or_else(|| {
			MsgHandleErrInternal::unreachable_no_such_peer(counterparty_node_id, msg.channel_id)
		})?;
		let mut peer_state_lock = peer_state_mutex.lock().unwrap();
		let peer_state = &mut *peer_state_lock;

		// Look for the channel
		match peer_state.channel_by_id.entry(msg.channel_id) {
			hash_map::Entry::Vacant(_) => {
				return Err(MsgHandleErrInternal::no_such_channel_for_peer(
					counterparty_node_id,
					msg.channel_id,
				));
			},
			hash_map::Entry::Occupied(mut chan_entry) => {
				if let Some(chan) = chan_entry.get_mut().as_funded_mut() {
					let logger = WithChannelContext::from(&self.logger, &chan.context, None);
					let result = chan.splice_locked(
						msg,
						&self.node_signer,
						self.chain_hash,
						&self.config.read().unwrap(),
						self.best_block.read().unwrap().height,
						&&logger,
					);
					let splice_promotion = try_channel_entry!(self, peer_state, result, chan_entry);
					if let Some(splice_promotion) = splice_promotion {
						{
							let mut short_to_chan_info = self.short_to_chan_info.write().unwrap();
							insert_short_channel_id!(short_to_chan_info, chan);
						}

						{
							let mut pending_events = self.pending_events.lock().unwrap();
							pending_events.push_back((
								events::Event::ChannelReady {
									channel_id: chan.context.channel_id(),
									user_channel_id: chan.context.get_user_id(),
									counterparty_node_id: chan.context.get_counterparty_node_id(),
									funding_txo: Some(
										splice_promotion.funding_txo.into_bitcoin_outpoint(),
									),
									channel_type: chan.funding.get_channel_type().clone(),
								},
								None,
							));
							splice_promotion.discarded_funding.into_iter().for_each(
								|funding_info| {
									let event = Event::DiscardFunding {
										channel_id: chan.context.channel_id(),
										funding_info,
									};
									pending_events.push_back((event, None));
								},
							);
						}

						if let Some(announcement_sigs) = splice_promotion.announcement_sigs {
							log_trace!(logger, "Sending announcement_signatures",);
							peer_state.pending_msg_events.push(
								MessageSendEvent::SendAnnouncementSignatures {
									node_id: counterparty_node_id.clone(),
									msg: announcement_sigs,
								},
							);
						}

						if let Some(monitor_update) = splice_promotion.monitor_update {
							if let Some(data) = self.handle_new_monitor_update(
								&mut peer_state.in_flight_monitor_updates,
								&mut peer_state.monitor_update_blocked_actions,
								&mut peer_state.pending_msg_events,
								peer_state.is_connected,
								chan,
								splice_promotion.funding_txo,
								monitor_update,
							) {
								mem::drop(peer_state_lock);
								mem::drop(per_peer_state);
								self.handle_post_monitor_update_chan_resume(data);
							}
						}
					}
				} else {
					return Err(MsgHandleErrInternal::send_err_msg_no_close(
						"Channel is not funded, cannot splice".to_owned(),
						msg.channel_id,
					));
				}
			},
		};

		Ok(())
	}

	/// Process pending events from the [`chain::Watch`], returning whether any events were processed.
	fn process_pending_monitor_events(&self) -> bool {
		debug_assert!(self.total_consistency_lock.try_write().is_err()); // Caller holds read lock

		let mut failed_channels: Vec<(Result<Infallible, _>, _)> = Vec::new();
		let mut pending_monitor_events = self.chain_monitor.release_pending_monitor_events();
		let has_pending_monitor_events = !pending_monitor_events.is_empty();
		for (funding_outpoint, channel_id, mut monitor_events, counterparty_node_id) in
			pending_monitor_events.drain(..)
		{
			for monitor_event in monitor_events.drain(..) {
				match monitor_event {
					MonitorEvent::HTLCEvent(htlc_update) => {
						let logger = WithContext::from(
							&self.logger,
							Some(counterparty_node_id),
							Some(channel_id),
							Some(htlc_update.payment_hash),
						);
						if let Some(preimage) = htlc_update.payment_preimage {
							log_trace!(
								logger,
								"Claiming HTLC with preimage {} from our monitor",
								preimage
							);
							// Claim the funds from the previous hop, if there is one. Because this is in response to a
							// chain event, no attribution data is available.
							self.claim_funds_internal(
								htlc_update.source,
								preimage,
								htlc_update.htlc_value_satoshis.map(|v| v * 1000),
								None,
								true,
								counterparty_node_id,
								funding_outpoint,
								channel_id,
								None,
								None,
								None,
							);
						} else {
							log_trace!(logger, "Failing HTLC from our monitor");
							let failure_reason = LocalHTLCFailureReason::OnChainTimeout;
							let receiver = HTLCHandlingFailureType::Forward {
								node_id: Some(counterparty_node_id),
								channel_id,
							};
							let reason = HTLCFailReason::from_failure_code(failure_reason);
							let completion_update = Some(PaymentCompleteUpdate {
								counterparty_node_id,
								channel_funding_outpoint: funding_outpoint,
								channel_id,
								htlc_id: SentHTLCId::from_source(&htlc_update.source),
							});
							self.fail_htlc_backwards_internal(
								&htlc_update.source,
								&htlc_update.payment_hash,
								&reason,
								receiver,
								completion_update,
							);
						}
					},
					MonitorEvent::HolderForceClosed(_)
					| MonitorEvent::HolderForceClosedWithInfo { .. } => {
						let per_peer_state = self.per_peer_state.read().unwrap();
						if let Some(peer_state_mutex) = per_peer_state.get(&counterparty_node_id) {
							let mut peer_state_lock = peer_state_mutex.lock().unwrap();
							let peer_state = &mut *peer_state_lock;
							if let hash_map::Entry::Occupied(chan_entry) =
								peer_state.channel_by_id.entry(channel_id)
							{
								let reason = if let MonitorEvent::HolderForceClosedWithInfo {
									reason,
									..
								} = monitor_event
								{
									reason
								} else {
									ClosureReason::HolderForceClosed {
										broadcasted_latest_txn: Some(true),
										message: "Legacy ChannelMonitor closure".to_owned(),
									}
								};
								let err = ChannelError::Close((reason.to_string(), reason));
								let mut chan = chan_entry.remove();
								let (_, e) = self.locked_handle_force_close(
									&mut peer_state.closed_channel_monitor_update_ids,
									&mut peer_state.in_flight_monitor_updates,
									err,
									&mut chan,
								);
								failed_channels.push((Err(e), counterparty_node_id));
							}
						}
					},
					MonitorEvent::CommitmentTxConfirmed(_) => {
						let per_peer_state = self.per_peer_state.read().unwrap();
						if let Some(peer_state_mutex) = per_peer_state.get(&counterparty_node_id) {
							let mut peer_state_lock = peer_state_mutex.lock().unwrap();
							let peer_state = &mut *peer_state_lock;
							if let hash_map::Entry::Occupied(chan_entry) =
								peer_state.channel_by_id.entry(channel_id)
							{
								let reason = ClosureReason::CommitmentTxConfirmed;
								let err = ChannelError::Close((reason.to_string(), reason));
								let mut chan = chan_entry.remove();
								let (_, e) = self.locked_handle_force_close(
									&mut peer_state.closed_channel_monitor_update_ids,
									&mut peer_state.in_flight_monitor_updates,
									err,
									&mut chan,
								);
								failed_channels.push((Err(e), counterparty_node_id));
							}
						}
					},
					MonitorEvent::Completed { channel_id, monitor_update_id, .. } => {
						self.channel_monitor_updated(
							&channel_id,
							Some(monitor_update_id),
							&counterparty_node_id,
						);
					},
				}
			}
		}

		for (err, counterparty_node_id) in failed_channels {
			let _ = self.handle_error(err, counterparty_node_id);
		}

		has_pending_monitor_events
	}

	fn handle_holding_cell_free_result(&self, result: FreeHoldingCellsResult) {
		debug_assert_ne!(
			self.total_consistency_lock.held_by_thread(),
			LockHeldState::NotHeldByThread
		);
		for (chan_id, cp_node_id, post_update_data, failed_htlcs) in result {
			if let Some(data) = post_update_data {
				self.handle_post_monitor_update_chan_resume(data);
			}

			self.fail_holding_cell_htlcs(failed_htlcs, chan_id, &cp_node_id);
			self.needs_persist_flag.store(true, Ordering::Release);
			self.event_persist_notifier.notify();
		}
	}

	/// Frees all holding cells in all the channels for a peer.
	///
	/// Includes elements in the returned Vec only for channels which changed (implying persistence
	/// is required).
	#[must_use]
	fn check_free_peer_holding_cells(
		&self, peer_state: &mut PeerState<SP>,
	) -> FreeHoldingCellsResult {
		debug_assert_ne!(
			self.total_consistency_lock.held_by_thread(),
			LockHeldState::NotHeldByThread
		);

		let mut updates = Vec::new();
		let funded_chan_iter = peer_state
			.channel_by_id
			.iter_mut()
			.filter_map(|(chan_id, chan)| chan.as_funded_mut().map(|chan| (chan_id, chan)));
		for (chan_id, chan) in funded_chan_iter {
			let (monitor_opt, holding_cell_failed_htlcs) = chan.maybe_free_holding_cell_htlcs(
				&self.fee_estimator,
				&&WithChannelContext::from(&self.logger, &chan.context, None),
			);
			if monitor_opt.is_some() || !holding_cell_failed_htlcs.is_empty() {
				let update_res = monitor_opt
					.map(|monitor_update| {
						self.handle_new_monitor_update(
							&mut peer_state.in_flight_monitor_updates,
							&mut peer_state.monitor_update_blocked_actions,
							&mut peer_state.pending_msg_events,
							peer_state.is_connected,
							chan,
							chan.funding.get_funding_txo().unwrap(),
							monitor_update,
						)
					})
					.flatten();
				let cp_node_id = chan.context.get_counterparty_node_id();
				updates.push((*chan_id, cp_node_id, update_res, holding_cell_failed_htlcs));
			}
		}
		updates
	}

	/// Check the holding cell in each channel and free any pending HTLCs in them if possible.
	/// Returns whether there were any updates such as if pending HTLCs were freed or a monitor
	/// update was applied.
	fn check_free_holding_cells(&self) -> bool {
		let mut unlocked_results = Vec::new();

		{
			let per_peer_state = self.per_peer_state.read().unwrap();
			for (_cp_id, peer_state_mutex) in per_peer_state.iter() {
				let mut peer_state_lock = peer_state_mutex.lock().unwrap();
				let peer_state: &mut PeerState<_> = &mut *peer_state_lock;
				unlocked_results.append(&mut self.check_free_peer_holding_cells(peer_state));
			}
		}

		let has_update = !unlocked_results.is_empty();
		self.handle_holding_cell_free_result(unlocked_results);

		has_update
	}

	/// When a call to a [`ChannelSigner`] method returns an error, this indicates that the signer
	/// is (temporarily) unavailable, and the operation should be retried later.
	///
	/// This method allows for that retry - either checking for any signer-pending messages to be
	/// attempted in every channel, or in the specifically provided channel.
	///
	/// [`ChannelSigner`]: crate::sign::ChannelSigner
	pub fn signer_unblocked(&self, channel_opt: Option<(PublicKey, ChannelId)>) {
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(self);

		// Returns whether we should remove this channel as it's just been closed.
		let unblock_chan = |chan: &mut Channel<SP>,
		                    pending_msg_events: &mut Vec<MessageSendEvent>|
		 -> Result<Option<ShutdownResult>, ChannelError> {
			let channel_id = chan.context().channel_id();
			let outbound_scid_alias = chan.context().outbound_scid_alias();
			let logger = WithChannelContext::from(&self.logger, &chan.context(), None);
			let node_id = chan.context().get_counterparty_node_id();
			let cbp = |htlc_id| {
				self.path_for_release_held_htlc(htlc_id, outbound_scid_alias, &channel_id, &node_id)
			};
			let msgs = chan.signer_maybe_unblocked(self.chain_hash, &&logger, cbp)?;
			if let Some(msgs) = msgs {
				if chan.context().is_connected() {
					if let Some(msg) = msgs.open_channel {
						pending_msg_events.push(MessageSendEvent::SendOpenChannel { node_id, msg });
					}
					if let Some(msg) = msgs.funding_created {
						pending_msg_events
							.push(MessageSendEvent::SendFundingCreated { node_id, msg });
					}
					if let Some(msg) = msgs.accept_channel {
						pending_msg_events
							.push(MessageSendEvent::SendAcceptChannel { node_id, msg });
					}
					let cu_msg = msgs.commitment_update.map(|updates| {
						MessageSendEvent::UpdateHTLCs { node_id, channel_id, updates }
					});
					let raa_msg = msgs
						.revoke_and_ack
						.map(|msg| MessageSendEvent::SendRevokeAndACK { node_id, msg });
					match (cu_msg, raa_msg) {
						(Some(cu), Some(raa))
							if msgs.order == RAACommitmentOrder::CommitmentFirst =>
						{
							pending_msg_events.push(cu);
							pending_msg_events.push(raa);
						},
						(Some(cu), Some(raa))
							if msgs.order == RAACommitmentOrder::RevokeAndACKFirst =>
						{
							pending_msg_events.push(raa);
							pending_msg_events.push(cu);
						},
						(Some(cu), _) => pending_msg_events.push(cu),
						(_, Some(raa)) => pending_msg_events.push(raa),
						(_, _) => {},
					}
					if let Some(msg) = msgs.funding_signed {
						pending_msg_events
							.push(MessageSendEvent::SendFundingSigned { node_id, msg });
					}
					if let Some(msg) = msgs.funding_commit_sig {
						pending_msg_events.push(MessageSendEvent::UpdateHTLCs {
							node_id,
							channel_id,
							updates: CommitmentUpdate {
								update_add_htlcs: vec![],
								update_fulfill_htlcs: vec![],
								update_fail_htlcs: vec![],
								update_fail_malformed_htlcs: vec![],
								update_fee: None,
								commitment_signed: vec![msg],
							},
						});
					}
					if let Some(msg) = msgs.tx_signatures {
						pending_msg_events
							.push(MessageSendEvent::SendTxSignatures { node_id, msg });
					}
					if let Some(msg) = msgs.closing_signed {
						pending_msg_events
							.push(MessageSendEvent::SendClosingSigned { node_id, msg });
					}
				}
				if let Some(funded_chan) = chan.as_funded() {
					if let Some(msg) = msgs.channel_ready {
						self.send_channel_ready(pending_msg_events, funded_chan, msg);
					}
					if let Some(broadcast_tx) = msgs.signed_closing_tx {
						log_info!(logger, "Broadcasting closing tx {}", log_tx!(broadcast_tx));
						self.tx_broadcaster.broadcast_transactions(&[(
							&broadcast_tx,
							TransactionType::CooperativeClose {
								counterparty_node_id: node_id,
								channel_id,
							},
						)]);
					}
				} else {
					// We don't know how to handle a channel_ready or signed_closing_tx for a
					// non-funded channel.
					debug_assert!(msgs.channel_ready.is_none());
					debug_assert!(msgs.signed_closing_tx.is_none());
				}
				Ok(msgs.shutdown_result)
			} else {
				Ok(None)
			}
		};

		let mut shutdown_results: Vec<(Result<Infallible, _>, _)> = Vec::new();
		let per_peer_state = self.per_peer_state.read().unwrap();
		let per_peer_state_iter = per_peer_state.iter().filter(|(cp_id, _)| {
			if let Some((counterparty_node_id, _)) = channel_opt {
				**cp_id == counterparty_node_id
			} else {
				true
			}
		});
		for (cp_id, peer_state_mutex) in per_peer_state_iter {
			let mut peer_state_lock = peer_state_mutex.lock().unwrap();
			let peer_state = &mut *peer_state_lock;
			peer_state.channel_by_id.retain(|_, chan| {
				let shutdown_result = match channel_opt {
					Some((_, channel_id)) if chan.context().channel_id() != channel_id => None,
					_ => match unblock_chan(chan, &mut peer_state.pending_msg_events) {
						Ok(shutdown_result) => shutdown_result,
						Err(err) => {
							let (_, err) = self.locked_handle_force_close(
								&mut peer_state.closed_channel_monitor_update_ids,
								&mut peer_state.in_flight_monitor_updates,
								err,
								chan,
							);
							shutdown_results.push((Err(err), *cp_id));
							return false;
						},
					},
				};
				if let Some(shutdown) = shutdown_result {
					let context = chan.context();
					let logger = WithChannelContext::from(&self.logger, context, None);
					log_trace!(logger, "Removing channel now that the signer is unblocked");
					let (remove, err) = if let Some(funded) = chan.as_funded_mut() {
						let err = self.locked_handle_funded_coop_close(
							&mut peer_state.closed_channel_monitor_update_ids,
							&mut peer_state.in_flight_monitor_updates,
							shutdown,
							funded,
						);
						(true, err)
					} else {
						debug_assert!(false);
						let reason = shutdown.closure_reason.clone();
						let err = ChannelError::Close((reason.to_string(), reason));
						self.locked_handle_unfunded_close(err, chan)
					};
					debug_assert!(remove);
					shutdown_results.push((Err(err), *cp_id));
					false
				} else {
					true
				}
			});
		}
		drop(per_peer_state);
		for (err, counterparty_node_id) in shutdown_results {
			let _ = self.handle_error(err, counterparty_node_id);
		}
	}

	/// Check whether any channels have finished removing all pending updates after a shutdown
	/// exchange and can now send a closing_signed.
	/// Returns whether any closing_signed messages were generated.
	fn maybe_generate_initial_closing_signed(&self) -> bool {
		let mut handle_errors: Vec<(PublicKey, Result<(), _>)> = Vec::new();
		let mut has_update = false;
		{
			let per_peer_state = self.per_peer_state.read().unwrap();

			for (cp_id, peer_state_mutex) in per_peer_state.iter() {
				let mut peer_state_lock = peer_state_mutex.lock().unwrap();
				let peer_state = &mut *peer_state_lock;
				let pending_msg_events = &mut peer_state.pending_msg_events;
				peer_state.channel_by_id.retain(|_, chan| {
					if !chan.context().is_connected() {
						return true;
					}
					match chan.as_funded_mut() {
						Some(funded_chan) => {
							let logger =
								WithChannelContext::from(&self.logger, &funded_chan.context, None);
							match funded_chan
								.maybe_propose_closing_signed(&self.fee_estimator, &&logger)
							{
								Ok((msg_opt, tx_shutdown_result_opt)) => {
									if let Some(msg) = msg_opt {
										has_update = true;
										pending_msg_events.push(
											MessageSendEvent::SendClosingSigned {
												node_id: funded_chan
													.context
													.get_counterparty_node_id(),
												msg,
											},
										);
									}
									debug_assert_eq!(
										tx_shutdown_result_opt.is_some(),
										funded_chan.is_shutdown()
									);
									if let Some((tx, shutdown_res)) = tx_shutdown_result_opt {
										// We're done with this channel. We got a closing_signed and sent back
										// a closing_signed with a closing transaction to broadcast.
										let channel_id = funded_chan.context.channel_id();
										let err = self.locked_handle_funded_coop_close(
											&mut peer_state.closed_channel_monitor_update_ids,
											&mut peer_state.in_flight_monitor_updates,
											shutdown_res,
											funded_chan,
										);
										handle_errors.push((*cp_id, Err(err)));

										log_info!(logger, "Broadcasting {}", log_tx!(tx));
										self.tx_broadcaster.broadcast_transactions(&[(
											&tx,
											TransactionType::CooperativeClose {
												counterparty_node_id: *cp_id,
												channel_id,
											},
										)]);
										false
									} else {
										true
									}
								},
								Err(e) => {
									has_update = true;
									let (close_channel, res) = self
										.locked_handle_funded_force_close(
											&mut peer_state.closed_channel_monitor_update_ids,
											&mut peer_state.in_flight_monitor_updates,
											e,
											funded_chan,
										);
									handle_errors.push((
										funded_chan.context.get_counterparty_node_id(),
										Err(res),
									));
									!close_channel
								},
							}
						},
						None => true, // Retain unfunded channels if present.
					}
				});
			}
		}

		for (counterparty_node_id, err) in handle_errors {
			let _ = self.handle_error(err, counterparty_node_id);
		}

		has_update
	}

	#[rustfmt::skip]
	fn maybe_send_stfu(&self) {
		let per_peer_state = self.per_peer_state.read().unwrap();
		for (counterparty_node_id, peer_state_mutex) in per_peer_state.iter() {
			let mut peer_state_lock = peer_state_mutex.lock().unwrap();
			let peer_state = &mut *peer_state_lock;
			let pending_msg_events = &mut peer_state.pending_msg_events;
			for (channel_id, chan) in &mut peer_state.channel_by_id {
				if let Some(funded_chan) = chan.as_funded_mut() {
					let logger = WithContext::from(
						&self.logger, Some(*counterparty_node_id), Some(*channel_id), None
					);
					match funded_chan.try_send_stfu(&&logger) {
						Ok(None) => {},
						Ok(Some(stfu)) => {
							pending_msg_events.push(MessageSendEvent::SendStfu {
								node_id: chan.context().get_counterparty_node_id(),
								msg: stfu,
							});
						},
						Err(e) => {
							log_debug!(logger, "Could not advance quiescence handshake: {}", e);
						}
					}
				}
			}
		}
	}

	#[cfg(any(test, fuzzing, feature = "_test_utils"))]
	#[rustfmt::skip]
	pub fn maybe_propose_quiescence(&self, counterparty_node_id: &PublicKey, channel_id: &ChannelId) -> Result<(), APIError> {
		let mut result = Ok(());
		PersistenceNotifierGuard::optionally_notify(self, || {
			let mut notify = NotifyOption::SkipPersistNoEvents;

			let per_peer_state = self.per_peer_state.read().unwrap();
			let peer_state_mutex_opt = per_peer_state.get(counterparty_node_id);
			if peer_state_mutex_opt.is_none() {
				result = Err(APIError::no_such_peer(counterparty_node_id));
				return notify;
			}

			let mut peer_state = peer_state_mutex_opt.unwrap().lock().unwrap();
			if !peer_state.latest_features.supports_quiescence() {
				result = Err(APIError::ChannelUnavailable { err: "Peer does not support quiescence".to_owned() });
				return notify;
			}

			match peer_state.channel_by_id.entry(channel_id.clone()) {
				hash_map::Entry::Occupied(mut chan_entry) => {
					if let Some(chan) = chan_entry.get_mut().as_funded_mut() {
						let logger = WithContext::from(
							&self.logger, Some(*counterparty_node_id), Some(*channel_id), None
						);

						match chan.propose_quiescence(&&logger, QuiescentAction::DoNothing) {
							Ok(None) => {},
							Ok(Some(stfu)) => {
								peer_state.pending_msg_events.push(MessageSendEvent::SendStfu {
									node_id: *counterparty_node_id, msg: stfu
								});
								notify = NotifyOption::SkipPersistHandleEvents;
							},
							Err(action) => log_trace!(logger, "Failed to propose quiescence for: {:?}", action),
						}
					} else {
						result = Err(APIError::APIMisuseError {
							err: format!("Unfunded channel {} cannot be quiescent", channel_id),
						});
					}
				},
				hash_map::Entry::Vacant(_) => {
					result = Err(APIError::no_such_channel_for_peer(
						channel_id,
						counterparty_node_id,
					));
				},
			}

			notify
		});

		result
	}

	#[cfg(any(test, fuzzing, feature = "_test_utils"))]
	#[rustfmt::skip]
	pub fn exit_quiescence(&self, counterparty_node_id: &PublicKey, channel_id: &ChannelId) -> Result<bool, APIError> {
		let _read_guard = self.total_consistency_lock.read().unwrap();

		let initiator = {
			let per_peer_state = self.per_peer_state.read().unwrap();
			let peer_state_mutex = per_peer_state.get(counterparty_node_id)
				.ok_or_else(|| APIError::no_such_peer(counterparty_node_id))?;
			let mut peer_state = peer_state_mutex.lock().unwrap();
			match peer_state.channel_by_id.entry(*channel_id) {
				hash_map::Entry::Occupied(mut chan_entry) => {
					if let Some(chan) = chan_entry.get_mut().as_funded_mut() {
						chan.exit_quiescence()
					} else {
						return Err(APIError::APIMisuseError {
							err: format!("Unfunded channel {} cannot be quiescent", channel_id),
						})
					}
				},
				hash_map::Entry::Vacant(_) => {
					return Err(APIError::no_such_channel_for_peer(
						channel_id,
						counterparty_node_id,
					))
				},
			}
		};
		self.check_free_holding_cells();
		Ok(initiator)
	}

	/// Utility for creating a BOLT11 invoice that can be verified by [`ChannelManager`] without
	/// storing any additional state. It achieves this by including a [`PaymentSecret`] in the
	/// invoice which it uses to verify that the invoice has not expired and the payment amount is
	/// sufficient, reproducing the [`PaymentPreimage`] if applicable.
	#[rustfmt::skip]
	pub fn create_bolt11_invoice(
		&self, params: Bolt11InvoiceParameters,
	) -> Result<Bolt11Invoice, SignOrCreationError<()>> {
		let Bolt11InvoiceParameters {
			amount_msats, description, invoice_expiry_delta_secs, min_final_cltv_expiry_delta,
			payment_hash,
		} = params;

		let currency =
			Network::from_chain_hash(self.chain_hash).map(Into::into).unwrap_or(Currency::Bitcoin);

		#[cfg(feature = "std")]
		let duration_since_epoch = {
			use std::time::SystemTime;
			SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)
				.expect("SystemTime::now() should be after SystemTime::UNIX_EPOCH")
		};

		// This may be up to 2 hours in the future because of bitcoin's block time rule or about
		// 10-30 minutes in the past if a block hasn't been found recently. This should be fine as
		// the default invoice expiration is 2 hours, though shorter expirations may be problematic.
		#[cfg(not(feature = "std"))]
		let duration_since_epoch =
			Duration::from_secs(self.highest_seen_timestamp.load(Ordering::Acquire) as u64);

		if let Some(min_final_cltv_expiry_delta) = min_final_cltv_expiry_delta {
			if min_final_cltv_expiry_delta.saturating_add(3) < MIN_FINAL_CLTV_EXPIRY_DELTA {
				return Err(SignOrCreationError::CreationError(CreationError::MinFinalCltvExpiryDeltaTooShort));
			}
		}

		let (payment_hash, payment_secret) = match payment_hash {
			Some(payment_hash) => {
				let payment_secret = self
					.create_inbound_payment_for_hash(
						payment_hash, amount_msats,
						invoice_expiry_delta_secs.unwrap_or(DEFAULT_EXPIRY_TIME as u32),
						min_final_cltv_expiry_delta,
					)
					.map_err(|()| SignOrCreationError::CreationError(CreationError::InvalidAmount))?;
				(payment_hash, payment_secret)
			},
			None => {
				self
					.create_inbound_payment(
						amount_msats, invoice_expiry_delta_secs.unwrap_or(DEFAULT_EXPIRY_TIME as u32),
						min_final_cltv_expiry_delta,
					)
					.map_err(|()| SignOrCreationError::CreationError(CreationError::InvalidAmount))?
			},
		};

		log_trace!(self.logger, "Creating invoice with payment hash {}", &payment_hash);

		let invoice = Bolt11InvoiceBuilder::new(currency);
		let invoice = match description {
			Bolt11InvoiceDescription::Direct(description) => invoice.description(description.into_inner().0),
			Bolt11InvoiceDescription::Hash(hash) => invoice.description_hash(hash.0),
		};

		let mut invoice = invoice
			.duration_since_epoch(duration_since_epoch)
			.payee_pub_key(self.get_our_node_id())
			.payment_hash(payment_hash)
			.payment_secret(payment_secret)
			.basic_mpp()
			.min_final_cltv_expiry_delta(
				// Add a buffer of 3 to the delta if present, otherwise use LDK's minimum.
				min_final_cltv_expiry_delta.map(|x| x.saturating_add(3)).unwrap_or(MIN_FINAL_CLTV_EXPIRY_DELTA).into()
			);

		if let Some(invoice_expiry_delta_secs) = invoice_expiry_delta_secs{
			invoice = invoice.expiry_time(Duration::from_secs(invoice_expiry_delta_secs.into()));
		}

		if let Some(amount_msats) = amount_msats {
			invoice = invoice.amount_milli_satoshis(amount_msats);
		}

		let channels = self.list_channels();
		let route_hints = super::invoice_utils::sort_and_filter_channels(channels, amount_msats, &self.logger);
		for hint in route_hints {
			invoice = invoice.private_route(hint);
		}

		let raw_invoice = invoice.build_raw().map_err(|e| SignOrCreationError::CreationError(e))?;
		let signature = self.node_signer.sign_invoice(&raw_invoice, Recipient::Node);

		raw_invoice
			.sign(|_| signature)
			.map(|invoice| Bolt11Invoice::from_signed(invoice).unwrap())
			.map_err(|e| SignOrCreationError::SignError(e))
	}
}

/// Parameters used with [`create_bolt11_invoice`].
///
/// [`create_bolt11_invoice`]: ChannelManager::create_bolt11_invoice
pub struct Bolt11InvoiceParameters {
	/// The amount for the invoice, if any.
	pub amount_msats: Option<u64>,

	/// The description for what the invoice is for, or hash of such description.
	pub description: Bolt11InvoiceDescription,

	/// The invoice expiration relative to its creation time. If not set, the invoice will expire in
	/// [`DEFAULT_EXPIRY_TIME`] by default.
	///
	/// The creation time used is the duration since the Unix epoch for `std` builds. For non-`std`
	/// builds, the highest block timestamp seen is used instead. In the latter case, use a long
	/// enough expiry to account for the average block time.
	pub invoice_expiry_delta_secs: Option<u32>,

	/// The minimum `cltv_expiry` for the last HTLC in the route. If not set, will use
	/// [`MIN_FINAL_CLTV_EXPIRY_DELTA`].
	///
	/// If set, must be at least [`MIN_FINAL_CLTV_EXPIRY_DELTA`], and a three-block buffer will be
	/// added as well to allow for up to a few new block confirmations during routing.
	pub min_final_cltv_expiry_delta: Option<u16>,

	/// The payment hash used in the invoice. If not set, a payment hash will be generated using a
	/// preimage that can be reproduced by [`ChannelManager`] without storing any state.
	///
	/// Uses the payment hash if set. This may be useful if you're building an on-chain swap or
	/// involving another protocol where the payment hash is also involved outside the scope of
	/// lightning.
	pub payment_hash: Option<PaymentHash>,
}

impl Default for Bolt11InvoiceParameters {
	fn default() -> Self {
		Self {
			amount_msats: None,
			description: Bolt11InvoiceDescription::Direct(Description::empty()),
			invoice_expiry_delta_secs: None,
			min_final_cltv_expiry_delta: None,
			payment_hash: None,
		}
	}
}

macro_rules! create_offer_builder { ($self: ident, $builder: ty) => {
	/// Creates an [`OfferBuilder`] such that the [`Offer`] it builds is recognized by the
	/// [`ChannelManager`] when handling [`InvoiceRequest`] messages for the offer. The offer's
	/// expiration will be `absolute_expiry` if `Some`, otherwise it will not expire.
	///
	/// # Privacy
	///
	/// Uses [`MessageRouter`] provided at construction to construct a [`BlindedMessagePath`] for
	/// the offer. See the documentation of the selected [`MessageRouter`] for details on how it
	/// selects blinded paths including privacy implications and reliability tradeoffs.
	///
	/// Also, uses a derived signing pubkey in the offer for recipient privacy.
	///
	/// # Limitations
	///
	/// See [`OffersMessageFlow::create_offer_builder`] for limitations on the offer builder.
	///
	/// # Errors
	///
	/// Errors if the parameterized [`MessageRouter`] is unable to create a blinded path for the offer.
	///
	/// [`BlindedMessagePath`]: crate::blinded_path::message::BlindedMessagePath
	/// [`Offer`]: crate::offers::offer::Offer
	/// [`InvoiceRequest`]: crate::offers::invoice_request::InvoiceRequest
	pub fn create_offer_builder(&$self) -> Result<$builder, Bolt12SemanticError> {
		let builder = $self.flow.create_offer_builder(
			&$self.entropy_source, $self.get_peers_for_blinded_path()
		)?;

		Ok(builder.into())
	}

	/// Same as [`Self::create_offer_builder`], but allows specifying a custom [`MessageRouter`]
	/// instead of using the [`MessageRouter`] provided to the [`ChannelManager`] at construction.
	///
	/// This gives users full control over how the [`BlindedMessagePath`] is constructed,
	/// including the option to omit it entirely.
	///
	/// See [`Self::create_offer_builder`] for more details on usage.
	///
	/// [`BlindedMessagePath`]: crate::blinded_path::message::BlindedMessagePath
	/// [`Offer`]: crate::offers::offer::Offer
	/// [`InvoiceRequest`]: crate::offers::invoice_request::InvoiceRequest
	pub fn create_offer_builder_using_router<ME: MessageRouter>(
		&$self,
		router: ME,
	) -> Result<$builder, Bolt12SemanticError> {
		let builder = $self.flow.create_offer_builder_using_router(
			router, &$self.entropy_source, $self.get_peers_for_blinded_path()
		)?;

		Ok(builder.into())
	}

	/// Creates an [`OfferBuilder`] such that the [`Offer`] it builds is recognized by any
	/// [`ChannelManager`] (or [`OffersMessageFlow`]) using the same [`ExpandedKey`] (as returned
	/// from [`NodeSigner::get_expanded_key`]). This allows any nodes participating in a BOLT 11
	/// "phantom node" cluster to also receive BOLT 12 payments.
	///
	/// Note that, unlike with BOLT 11 invoices, BOLT 12 "phantom" offers do not in fact have any
	/// "phantom node" appended to receiving paths. Instead, multiple blinded paths are simply
	/// included which terminate at different final nodes.
	///
	/// `other_nodes_channels` must be set to a list of each participating node's `node_id` (from
	/// [`NodeSigner::get_node_id`] with a [`Recipient::Node`]) and its channels.
	///
	/// `path_count_limit` is used to limit the number of blinded paths included in the resulting
	/// [`Offer`]. Note that if this is less than the number of participating nodes (i.e.
	/// `other_nodes_channels.len() + 1`) not all nodes will participate in receiving funds.
	/// Because the parameterized [`MessageRouter`] will only get a chance to limit the number of
	/// paths *per-node*, it is important to set this for offers that will be included in a QR
	/// code.
	///
	/// See [`Self::create_offer_builder`] for more details on the blinded path construction.
	///
	/// [`ExpandedKey`]: inbound_payment::ExpandedKey
	pub fn create_phantom_offer_builder(
		&$self, other_nodes_channels: Vec<(PublicKey, Vec<ChannelDetails>)>,
		path_count_limit: usize,
	) -> Result<$builder, Bolt12SemanticError> {
		let mut peers = Vec::with_capacity(other_nodes_channels.len() + 1);
		if !other_nodes_channels.iter().any(|(node_id, _)| *node_id == $self.get_our_node_id()) {
			peers.push(($self.get_our_node_id(), $self.get_peers_for_blinded_path()));
		}
		for (node_id, peer_chans) in other_nodes_channels {
			peers.push((node_id, Self::channel_details_to_forward_nodes(peer_chans)));
		}

		let builder = $self.flow.create_phantom_offer_builder(
			&$self.entropy_source, peers, path_count_limit
		)?;

		Ok(builder.into())
	}
} }

macro_rules! create_refund_builder { ($self: ident, $builder: ty) => {
	/// Creates a [`RefundBuilder`] such that the [`Refund`] it builds is recognized by the
	/// [`ChannelManager`] when handling [`Bolt12Invoice`] messages for the refund.
	///
	/// # Payment
	///
	/// The provided `payment_id` is used to ensure that only one invoice is paid for the refund.
	/// See [Avoiding Duplicate Payments] for other requirements once the payment has been sent.
	///
	/// The builder will have the provided expiration set. Any changes to the expiration on the
	/// returned builder will not be honored by [`ChannelManager`]. For non-`std`, the highest seen
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
	/// Uses [`MessageRouter`] provided at construction to construct a [`BlindedMessagePath`] for
	/// the refund. See the documentation of the selected [`MessageRouter`] for details on how it
	/// selects blinded paths including privacy implications and reliability tradeoffs.
	///
	/// Also, uses a derived payer id in the refund for payer privacy.
	///
	/// # Errors
	///
	/// Errors if:
	/// - a duplicate `payment_id` is provided given the caveats in the aforementioned link,
	/// - `amount_msats` is invalid, or
	/// - the parameterized [`Router`] is unable to create a blinded path for the refund.
	///
	/// [`Refund`]: crate::offers::refund::Refund
	/// [`Bolt12Invoice`]: crate::offers::invoice::Bolt12Invoice
	/// [`Bolt12Invoice::payment_paths`]: crate::offers::invoice::Bolt12Invoice::payment_paths
	/// [`BlindedMessagePath`]: crate::blinded_path::message::BlindedMessagePath
	/// [Avoiding Duplicate Payments]: #avoiding-duplicate-payments
	pub fn create_refund_builder(
		&$self, amount_msats: u64, absolute_expiry: Duration, payment_id: PaymentId,
		retry_strategy: Retry, route_params_config: RouteParametersConfig
	) -> Result<$builder, Bolt12SemanticError> {
		let entropy = &$self.entropy_source;

		let builder = $self.flow.create_refund_builder(
			entropy, amount_msats, absolute_expiry,
			payment_id, $self.get_peers_for_blinded_path()
		)?;

		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop($self);

		let expiration = StaleExpiration::AbsoluteTimeout(absolute_expiry);
		$self.pending_outbound_payments
			.add_new_awaiting_invoice(
				payment_id, expiration, retry_strategy, route_params_config, None,
			)
			.map_err(|_| Bolt12SemanticError::DuplicatePaymentId)?;

		Ok(builder.into())
	}

	/// Same as [`Self::create_refund_builder`], but allows specifying a custom [`MessageRouter`]
	/// instead of using the one provided during [`ChannelManager`] construction for
	/// [`BlindedMessagePath`] creation.
	///
	/// This gives users full control over how the [`BlindedMessagePath`] is constructed for the
	/// refund, including the option to omit it entirely. This is useful for testing or when
	/// alternative privacy strategies are needed.
	///
	/// See [`Self::create_refund_builder`] for more details on usage.
	///
	/// # Errors
	///
	/// In addition to the errors in [`Self::create_refund_builder`], this returns an error if
	/// the provided [`MessageRouter`] fails to construct a valid [`BlindedMessagePath`] for the refund.
	///
	/// [`Refund`]: crate::offers::refund::Refund
	/// [`BlindedMessagePath`]: crate::blinded_path::message::BlindedMessagePath
	/// [`Bolt12Invoice`]: crate::offers::invoice::Bolt12Invoice
	pub fn create_refund_builder_using_router<ME: MessageRouter>(
		&$self, router: ME, amount_msats: u64, absolute_expiry: Duration, payment_id: PaymentId,
		retry_strategy: Retry, route_params_config: RouteParametersConfig
	) -> Result<$builder, Bolt12SemanticError> {
		let entropy = &$self.entropy_source;

		let builder = $self.flow.create_refund_builder_using_router(
			router, entropy, amount_msats, absolute_expiry,
			payment_id, $self.get_peers_for_blinded_path()
		)?;

		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop($self);

		let expiration = StaleExpiration::AbsoluteTimeout(absolute_expiry);
		$self.pending_outbound_payments
			.add_new_awaiting_invoice(
				payment_id, expiration, retry_strategy, route_params_config, None,
			)
			.map_err(|_| Bolt12SemanticError::DuplicatePaymentId)?;

		Ok(builder.into())
	}
} }

impl<
		M: Watch<SP::EcdsaSigner>,
		T: BroadcasterInterface,
		ES: EntropySource,
		NS: NodeSigner,
		SP: SignerProvider,
		F: FeeEstimator,
		R: Router,
		MR: MessageRouter,
		L: Logger,
	> ChannelManager<M, T, ES, NS, SP, F, R, MR, L>
{
	#[cfg(not(c_bindings))]
	create_offer_builder!(self, OfferBuilder<'_, DerivedMetadata, secp256k1::All>);
	#[cfg(not(c_bindings))]
	create_refund_builder!(self, RefundBuilder<'_, secp256k1::All>);

	#[cfg(c_bindings)]
	create_offer_builder!(self, OfferWithDerivedMetadataBuilder);
	#[cfg(c_bindings)]
	create_refund_builder!(self, RefundMaybeWithDerivedMetadataBuilder);

	/// Retrieve an [`Offer`] for receiving async payments as an often-offline recipient. Will only
	/// return an offer if [`Self::set_paths_to_static_invoice_server`] was called and we succeeded in
	/// interactively building a [`StaticInvoice`] with the static invoice server.
	///
	/// Useful for posting offers to receive payments later, such as posting an offer on a website.
	pub fn get_async_receive_offer(&self) -> Result<Offer, ()> {
		let (offer, needs_persist) = self.flow.get_async_receive_offer()?;
		if needs_persist {
			// We need to re-persist the cache if a fresh offer was just marked as used to ensure we
			// continue to keep this offer's invoice updated and don't replace it with the server.
			let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(self);
		}
		Ok(offer)
	}

	/// Sets the [`BlindedMessagePath`]s that we will use as an async recipient to interactively build
	/// [`Offer`]s with a static invoice server, so the server can serve [`StaticInvoice`]s to payers
	/// on our behalf when we're offline.
	///
	/// This method only needs to be called once when the server first takes on the recipient as a
	/// client, or when the paths change, e.g. if the paths are set to expire at a particular time.
	pub fn set_paths_to_static_invoice_server(
		&self, paths_to_static_invoice_server: Vec<BlindedMessagePath>,
	) -> Result<(), ()> {
		let peers = self.get_peers_for_blinded_path();
		self.flow.set_paths_to_static_invoice_server(paths_to_static_invoice_server, peers)?;

		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(self);
		Ok(())
	}

	/// Pays for an [`Offer`] using the given parameters by creating an [`InvoiceRequest`] and
	/// enqueuing it to be sent via an onion message. [`ChannelManager`] will pay the actual
	/// [`Bolt12Invoice`] once it is received.
	///
	/// Uses [`InvoiceRequestBuilder`] such that the [`InvoiceRequest`] it builds is recognized by
	/// the [`ChannelManager`] when handling a [`Bolt12Invoice`] message in response to the request.
	///
	/// `amount_msats` allows you to overpay what is required to satisfy the offer, or may be
	/// required if the offer does not require a specific amount.
	///
	/// If the [`Offer`] was built from a human readable name resolved using BIP 353, you *must*
	/// instead call [`Self::pay_for_offer_from_hrn`].
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
	/// to construct a [`BlindedMessagePath`] for the reply path.
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
	/// [`InvoiceRequest`]: crate::offers::invoice_request::InvoiceRequest
	/// [`InvoiceRequestBuilder`]: crate::offers::invoice_request::InvoiceRequestBuilder
	/// [`Bolt12Invoice`]: crate::offers::invoice::Bolt12Invoice
	/// [`BlindedMessagePath`]: crate::blinded_path::message::BlindedMessagePath
	/// [`Bolt12Invoice::payment_paths`]: crate::offers::invoice::Bolt12Invoice::payment_paths
	/// [Avoiding Duplicate Payments]: #avoiding-duplicate-payments
	pub fn pay_for_offer(
		&self, offer: &Offer, amount_msats: Option<u64>, payment_id: PaymentId,
		optional_params: OptionalOfferPaymentParams,
	) -> Result<(), Bolt12SemanticError> {
		let create_pending_payment_fn = |retryable_invoice_request: RetryableInvoiceRequest| {
			self.pending_outbound_payments
				.add_new_awaiting_invoice(
					payment_id,
					StaleExpiration::TimerTicks(1),
					optional_params.retry_strategy,
					optional_params.route_params_config,
					Some(retryable_invoice_request),
				)
				.map_err(|_| Bolt12SemanticError::DuplicatePaymentId)
		};

		self.pay_for_offer_intern(
			offer,
			if offer.expects_quantity() { Some(1) } else { None },
			amount_msats,
			optional_params.payer_note,
			payment_id,
			None,
			create_pending_payment_fn,
		)
	}

	/// Pays for an [`Offer`] which was built by resolving a human readable name. It is otherwise
	/// identical to [`Self::pay_for_offer`].
	pub fn pay_for_offer_from_hrn(
		&self, offer: &OfferFromHrn, amount_msats: u64, payment_id: PaymentId,
		optional_params: OptionalOfferPaymentParams,
	) -> Result<(), Bolt12SemanticError> {
		let create_pending_payment_fn = |retryable_invoice_request: RetryableInvoiceRequest| {
			self.pending_outbound_payments
				.add_new_awaiting_invoice(
					payment_id,
					StaleExpiration::TimerTicks(1),
					optional_params.retry_strategy,
					optional_params.route_params_config,
					Some(retryable_invoice_request),
				)
				.map_err(|_| Bolt12SemanticError::DuplicatePaymentId)
		};

		self.pay_for_offer_intern(
			&offer.offer,
			if offer.offer.expects_quantity() { Some(1) } else { None },
			Some(amount_msats),
			optional_params.payer_note,
			payment_id,
			Some(offer.hrn),
			create_pending_payment_fn,
		)
	}

	/// Pays for an [`Offer`] using the given parameters, including a `quantity`, by creating an
	/// [`InvoiceRequest`] and enqueuing it to be sent via an onion message. [`ChannelManager`] will
	/// pay the actual [`Bolt12Invoice`] once it is received.
	///
	/// This method is identical to [`Self::pay_for_offer`] with the one exception that it allows
	/// you to specify the [`InvoiceRequest::quantity`]. We expect this to be rather seldomly used,
	/// as the "quantity" feature of offers doesn't line up with common payment flows today.
	///
	/// This method is otherwise identical to [`Self::pay_for_offer`] but will additionally fail if
	/// the provided `quantity` does not meet the requirements described by
	/// [`Offer::supported_quantity`].
	///
	/// [`InvoiceRequest`]: crate::offers::invoice_request::InvoiceRequest
	/// [`Bolt12Invoice`]: crate::offers::invoice::Bolt12Invoice
	/// [`InvoiceRequest::quantity`]: crate::offers::invoice_request::InvoiceRequest::quantity
	pub fn pay_for_offer_with_quantity(
		&self, offer: &Offer, amount_msats: Option<u64>, payment_id: PaymentId,
		optional_params: OptionalOfferPaymentParams, quantity: u64,
	) -> Result<(), Bolt12SemanticError> {
		let create_pending_payment_fn = |retryable_invoice_request: RetryableInvoiceRequest| {
			self.pending_outbound_payments
				.add_new_awaiting_invoice(
					payment_id,
					StaleExpiration::TimerTicks(1),
					optional_params.retry_strategy,
					optional_params.route_params_config,
					Some(retryable_invoice_request),
				)
				.map_err(|_| Bolt12SemanticError::DuplicatePaymentId)
		};

		self.pay_for_offer_intern(
			offer,
			Some(quantity),
			amount_msats,
			optional_params.payer_note,
			payment_id,
			None,
			create_pending_payment_fn,
		)
	}

	#[rustfmt::skip]
	fn pay_for_offer_intern<CPP: FnOnce(RetryableInvoiceRequest) -> Result<(), Bolt12SemanticError>>(
		&self, offer: &Offer, quantity: Option<u64>, amount_msats: Option<u64>,
		payer_note: Option<String>, payment_id: PaymentId,
		human_readable_name: Option<HumanReadableName>, create_pending_payment: CPP,
	) -> Result<(), Bolt12SemanticError> {
		let entropy = &self.entropy_source;
		let nonce = Nonce::from_entropy_source(entropy);

		let builder = self.flow.create_invoice_request_builder(
			offer, nonce, payment_id,
		)?;

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
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(self);

		self.flow.enqueue_invoice_request(
			invoice_request.clone(), payment_id, nonce,
			self.get_peers_for_blinded_path()
		)?;

		let retryable_invoice_request = RetryableInvoiceRequest {
			invoice_request: invoice_request.clone(),
			nonce,
			needs_retry: true,
		};

		create_pending_payment(retryable_invoice_request)
	}

	/// Creates a [`Bolt12Invoice`] for a [`Refund`] and enqueues it to be sent via an onion
	/// message.
	///
	/// The resulting invoice uses a [`PaymentHash`] recognized by the [`ChannelManager`] and a
	/// [`BlindedPaymentPath`] containing the [`PaymentSecret`] needed to reconstruct the
	/// corresponding [`PaymentPreimage`]. It is returned purely for informational purposes.
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
	/// [`Bolt12Invoice`]: crate::offers::invoice::Bolt12Invoice
	pub fn request_refund_payment(
		&self, refund: &Refund,
	) -> Result<Bolt12Invoice, Bolt12SemanticError> {
		let secp_ctx = &self.secp_ctx;
		let entropy = &self.entropy_source;

		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(self);

		let builder = self.flow.create_invoice_builder_from_refund(
			&self.router,
			entropy,
			refund,
			self.list_usable_channels(),
			|amount_msats, relative_expiry| {
				self.create_inbound_payment(Some(amount_msats), relative_expiry, None)
					.map_err(|()| Bolt12SemanticError::InvalidAmount)
			},
		)?;

		let invoice = builder.allow_mpp().build_and_sign(secp_ctx)?;

		self.flow.enqueue_invoice(invoice.clone(), refund, self.get_peers_for_blinded_path())?;
		Ok(invoice)
	}

	/// Pays for an [`Offer`] looked up using [BIP 353] Human Readable Names resolved by the DNS
	/// resolver(s) at `dns_resolvers` which resolve names according to [bLIP 32].
	///
	/// Because most wallets support on-chain or other payment schemes beyond only offers, this is
	/// deprecated in favor of the [`bitcoin-payment-instructions`] crate, which can be used to
	/// build an [`OfferFromHrn`] and call [`Self::pay_for_offer_from_hrn`]. Thus, this method is
	/// deprecated.
	///
	/// # Payment
	///
	/// The provided `payment_id` is used to ensure that only one invoice is paid for the request
	/// when received. See [Avoiding Duplicate Payments] for other requirements once the payment has
	/// been sent.
	///
	/// To revoke the request, use [`ChannelManager::abandon_payment`] prior to receiving the
	/// invoice. If abandoned, or an invoice isn't received in a reasonable amount of time, the
	/// payment will fail with an [`PaymentFailureReason::UserAbandoned`] or
	/// [`PaymentFailureReason::InvoiceRequestExpired`], respectively.
	///
	/// # Privacy
	///
	/// For payer privacy, uses a derived payer id and uses [`MessageRouter::create_blinded_paths`]
	/// to construct a [`BlindedMessagePath`] for the reply path.
	///
	/// # Errors
	///
	/// Errors if a duplicate `payment_id` is provided given the caveats in the aforementioned link.
	///
	/// [BIP 353]: https://github.com/bitcoin/bips/blob/master/bip-0353.mediawiki
	/// [bLIP 32]: https://github.com/lightning/blips/blob/master/blip-0032.md
	/// [`OMNameResolver::resolve_name`]: crate::onion_message::dns_resolution::OMNameResolver::resolve_name
	/// [`OMNameResolver::handle_dnssec_proof_for_uri`]: crate::onion_message::dns_resolution::OMNameResolver::handle_dnssec_proof_for_uri
	/// [`bitcoin-payment-instructions`]: https://docs.rs/bitcoin-payment-instructions/
	/// [Avoiding Duplicate Payments]: #avoiding-duplicate-payments
	/// [`BlindedMessagePath`]: crate::blinded_path::message::BlindedMessagePath
	/// [`PaymentFailureReason::UserAbandoned`]: crate::events::PaymentFailureReason::UserAbandoned
	/// [`PaymentFailureReason::InvoiceRequestRejected`]: crate::events::PaymentFailureReason::InvoiceRequestRejected
	#[cfg(feature = "dnssec")]
	#[deprecated(note = "Use bitcoin-payment-instructions and pay_for_offer_from_hrn instead")]
	pub fn pay_for_offer_from_human_readable_name(
		&self, name: HumanReadableName, amount_msats: u64, payment_id: PaymentId,
		optional_params: OptionalOfferPaymentParams, dns_resolvers: Vec<Destination>,
	) -> Result<(), ()> {
		let (onion_message, context) =
			self.flow.hrn_resolver.resolve_name(payment_id, name, &self.entropy_source)?;

		let expiration = StaleExpiration::TimerTicks(1);
		self.pending_outbound_payments.add_new_awaiting_offer(
			payment_id,
			expiration,
			optional_params.retry_strategy,
			optional_params.route_params_config,
			amount_msats,
			optional_params.payer_note,
		)?;

		self.flow
			.enqueue_dns_onion_message(
				onion_message,
				context,
				dns_resolvers,
				self.get_peers_for_blinded_path(),
			)
			.map_err(|_| ())
	}

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
	/// [`claim_funds`]: Self::claim_funds
	/// [`PaymentClaimable`]: events::Event::PaymentClaimable
	/// [`PaymentClaimable::purpose`]: events::Event::PaymentClaimable::purpose
	/// [`PaymentPurpose::preimage`]: events::PaymentPurpose::preimage
	/// [`create_inbound_payment_for_hash`]: Self::create_inbound_payment_for_hash
	pub fn create_inbound_payment(
		&self, min_value_msat: Option<u64>, invoice_expiry_delta_secs: u32,
		min_final_cltv_expiry_delta: Option<u16>,
	) -> Result<(PaymentHash, PaymentSecret), ()> {
		inbound_payment::create(
			&self.inbound_payment_key,
			min_value_msat,
			invoice_expiry_delta_secs,
			&self.entropy_source,
			self.highest_seen_timestamp.load(Ordering::Acquire) as u64,
			min_final_cltv_expiry_delta,
		)
	}

	/// Gets a [`PaymentSecret`] for a given [`PaymentHash`], for which the payment preimage is
	/// stored external to LDK.
	///
	/// A [`PaymentClaimable`] event will only be generated if the [`PaymentSecret`] matches a
	/// payment secret fetched via this method or [`create_inbound_payment`], and which is at least
	/// the `min_value_msat` provided here, if one is provided.
	///
	/// The [`PaymentHash`] (and corresponding [`PaymentPreimage`]) should be globally unique, though
	/// note that LDK will not stop you from registering duplicate payment hashes for inbound
	/// payments.
	///
	/// `min_value_msat` should be set if the invoice being generated contains a value. Any payment
	/// received for the returned [`PaymentHash`] will be required to be at least `min_value_msat`
	/// before a [`PaymentClaimable`] event will be generated, ensuring that we do not provide the
	/// sender "proof-of-payment" unless they have paid the required amount.
	///
	/// `invoice_expiry_delta_secs` describes the number of seconds that the invoice is valid for
	/// in excess of the current time. This should roughly match the expiry time set in the invoice.
	/// After this many seconds, we will remove the inbound payment, resulting in any attempts to
	/// pay the invoice failing. The BOLT spec suggests 3,600 secs as a default validity time for
	/// invoices when no timeout is set.
	///
	/// Note that we use block header time to time-out pending inbound payments (with some margin
	/// to compensate for the inaccuracy of block header timestamps). Thus, in practice we will
	/// accept a payment and generate a [`PaymentClaimable`] event for some time after the expiry.
	/// If you need exact expiry semantics, you should enforce them upon receipt of
	/// [`PaymentClaimable`].
	///
	/// Note that invoices generated for inbound payments should have their `min_final_cltv_expiry_delta`
	/// set to at least [`MIN_FINAL_CLTV_EXPIRY_DELTA`].
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
	/// [`create_inbound_payment`]: Self::create_inbound_payment
	/// [`PaymentClaimable`]: events::Event::PaymentClaimable
	pub fn create_inbound_payment_for_hash(
		&self, payment_hash: PaymentHash, min_value_msat: Option<u64>,
		invoice_expiry_delta_secs: u32, min_final_cltv_expiry: Option<u16>,
	) -> Result<PaymentSecret, ()> {
		inbound_payment::create_from_hash(
			&self.inbound_payment_key,
			min_value_msat,
			payment_hash,
			invoice_expiry_delta_secs,
			self.highest_seen_timestamp.load(Ordering::Acquire) as u64,
			min_final_cltv_expiry,
		)
	}

	/// Gets an LDK-generated payment preimage from a payment hash and payment secret that were
	/// previously returned from [`create_inbound_payment`].
	///
	/// [`create_inbound_payment`]: Self::create_inbound_payment
	pub fn get_payment_preimage(
		&self, payment_hash: PaymentHash, payment_secret: PaymentSecret,
	) -> Result<PaymentPreimage, APIError> {
		let expanded_key = &self.inbound_payment_key;
		inbound_payment::get_payment_preimage(payment_hash, payment_secret, expanded_key)
	}

	/// [`BlindedMessagePath`]s for an async recipient to communicate with this node and interactively
	/// build [`Offer`]s and [`StaticInvoice`]s for receiving async payments.
	///
	/// ## Usage
	/// 1. Static invoice server calls [`Self::blinded_paths_for_async_recipient`]
	/// 2. Static invoice server communicates the resulting paths out-of-band to the async recipient,
	///    who calls [`Self::set_paths_to_static_invoice_server`] to configure themselves with these
	///    paths
	/// 3. Async recipient automatically sends [`OfferPathsRequest`]s over the configured paths, and
	///    uses the resulting paths from the server's [`OfferPaths`] response to build their async
	///    receive offer
	///
	/// If `relative_expiry` is unset, the [`BlindedMessagePath`]s will never expire.
	///
	/// Returns the paths that the recipient should be configured with via
	/// [`Self::set_paths_to_static_invoice_server`].
	///
	/// The provided `recipient_id` must uniquely identify the recipient, and will be surfaced later
	/// when the recipient provides us with a static invoice to persist and serve to payers on their
	/// behalf.
	pub fn blinded_paths_for_async_recipient(
		&self, recipient_id: Vec<u8>, relative_expiry: Option<Duration>,
	) -> Result<Vec<BlindedMessagePath>, ()> {
		let peers = self.get_peers_for_blinded_path();
		self.flow.blinded_paths_for_async_recipient(recipient_id, relative_expiry, peers)
	}

	pub(super) fn duration_since_epoch(&self) -> Duration {
		#[cfg(not(feature = "std"))]
		let now = Duration::from_secs(self.highest_seen_timestamp.load(Ordering::Acquire) as u64);
		#[cfg(feature = "std")]
		let now = std::time::SystemTime::now()
			.duration_since(std::time::SystemTime::UNIX_EPOCH)
			.expect("SystemTime::now() should come after SystemTime::UNIX_EPOCH");

		now
	}

	/// Converts a list of channels to a list of peers which may be suitable to receive onion
	/// messages through.
	fn channel_details_to_forward_nodes(
		mut channel_list: Vec<ChannelDetails>,
	) -> Vec<MessageForwardNode> {
		channel_list.sort_unstable_by_key(|chan| chan.counterparty.node_id);
		let mut res = Vec::new();
		// TODO: When MSRV reaches 1.77 use chunk_by
		let mut start = 0;
		while start < channel_list.len() {
			let counterparty_node_id = channel_list[start].counterparty.node_id;
			let end = channel_list[start..]
				.iter()
				.position(|chan| chan.counterparty.node_id != counterparty_node_id)
				.map(|pos| start + pos)
				.unwrap_or(channel_list.len());

			let peer_chans = &channel_list[start..end];
			if peer_chans.iter().any(|chan| chan.is_usable)
				&& peer_chans.iter().any(|c| c.counterparty.features.supports_onion_messages())
			{
				res.push(MessageForwardNode {
					node_id: peer_chans[0].counterparty.node_id,
					short_channel_id: peer_chans
						.iter()
						.filter(|chan| chan.is_usable)
						// Select the channel which has the highest local balance. We assume this
						// channel is the most likely to stick around.
						.max_by_key(|chan| chan.inbound_capacity_msat)
						.and_then(|chan| chan.get_inbound_payment_scid()),
				})
			}
			start = end;
		}
		res
	}

	fn get_peers_for_blinded_path(&self) -> Vec<MessageForwardNode> {
		let per_peer_state = self.per_peer_state.read().unwrap();
		per_peer_state
			.iter()
			.map(|(node_id, peer_state)| (node_id, peer_state.lock().unwrap()))
			.filter(|(_, peer)| peer.is_connected)
			.filter(|(_, peer)| peer.latest_features.supports_onion_messages())
			.map(|(node_id, peer)| MessageForwardNode {
				node_id: *node_id,
				short_channel_id: peer
					.channel_by_id
					.iter()
					.filter(|(_, channel)| channel.context().is_usable())
					.filter_map(|(_, channel)| channel.as_funded())
					// Select the channel which has the highest local balance. We assume this
					// channel is the most likely to stick around.
					.max_by_key(|funded_channel| funded_channel.funding.get_value_to_self_msat())
					.and_then(|funded_channel| funded_channel.get_inbound_scid()),
			})
			.collect::<Vec<_>>()
	}

	#[cfg(test)]
	pub(super) fn test_get_peers_for_blinded_path(&self) -> Vec<MessageForwardNode> {
		self.get_peers_for_blinded_path()
	}

	#[cfg(test)]
	/// Creates multi-hop blinded payment paths for the given `amount_msats` by delegating to
	/// [`Router::create_blinded_payment_paths`].
	pub(super) fn test_create_blinded_payment_paths(
		&self, amount_msats: Option<u64>, payment_secret: PaymentSecret,
		payment_context: PaymentContext, relative_expiry_seconds: u32,
	) -> Result<Vec<BlindedPaymentPath>, ()> {
		self.flow.test_create_blinded_payment_paths(
			&self.router,
			self.list_usable_channels(),
			amount_msats,
			payment_secret,
			payment_context,
			relative_expiry_seconds,
		)
	}

	/// Gets a fake short channel id for use in receiving [phantom node payments]. These fake scids
	/// are used when constructing the phantom invoice's route hints.
	///
	/// [phantom node payments]: crate::sign::PhantomKeysManager
	pub fn get_phantom_scid(&self) -> u64 {
		let best_block_height = self.best_block.read().unwrap().height;
		let short_to_chan_info = self.short_to_chan_info.read().unwrap();
		loop {
			let scid_candidate = fake_scid::Namespace::Phantom.get_fake_scid(
				best_block_height,
				&self.chain_hash,
				&self.fake_scid_rand_bytes,
				&self.entropy_source,
			);
			// Ensure the generated scid doesn't conflict with a real channel.
			match short_to_chan_info.get(&scid_candidate) {
				Some(_) => continue,
				None => return scid_candidate,
			}
		}
	}

	/// Gets route hints for use in receiving [phantom node payments].
	///
	/// [phantom node payments]: crate::sign::PhantomKeysManager
	pub fn get_phantom_route_hints(&self) -> PhantomRouteHints {
		PhantomRouteHints {
			channels: self.list_usable_channels(),
			phantom_scid: self.get_phantom_scid(),
			real_node_pubkey: self.get_our_node_id(),
		}
	}

	/// Gets a fake short channel id for use in receiving intercepted payments. These fake scids are
	/// used when constructing the route hints for HTLCs intended to be intercepted. See
	/// [`ChannelManager::forward_intercepted_htlc`].
	///
	/// Note that this method is not guaranteed to return unique values, you may need to call it a few
	/// times to get a unique scid.
	pub fn get_intercept_scid(&self) -> u64 {
		let best_block_height = self.best_block.read().unwrap().height;
		let short_to_chan_info = self.short_to_chan_info.read().unwrap();
		loop {
			let scid_candidate = fake_scid::Namespace::Intercept.get_fake_scid(
				best_block_height,
				&self.chain_hash,
				&self.fake_scid_rand_bytes,
				&self.entropy_source,
			);
			// Ensure the generated scid doesn't conflict with a real channel.
			if short_to_chan_info.contains_key(&scid_candidate) {
				continue;
			}
			return scid_candidate;
		}
	}

	/// Gets inflight HTLC information by processing pending outbound payments that are in
	/// our channels. May be used during pathfinding to account for in-use channel liquidity.
	pub fn compute_inflight_htlcs(&self) -> InFlightHtlcs {
		let mut inflight_htlcs = InFlightHtlcs::new();

		let per_peer_state = self.per_peer_state.read().unwrap();
		for (_cp_id, peer_state_mutex) in per_peer_state.iter() {
			let mut peer_state_lock = peer_state_mutex.lock().unwrap();
			let peer_state = &mut *peer_state_lock;
			for chan in peer_state.channel_by_id.values().filter_map(Channel::as_funded) {
				for (htlc_source, _) in chan.inflight_htlc_sources() {
					if let HTLCSource::OutboundRoute { path, .. } = htlc_source {
						inflight_htlcs.process_path(path, self.get_our_node_id());
					}
				}
			}
		}

		inflight_htlcs
	}

	#[cfg(any(test, feature = "_test_utils"))]
	pub fn get_and_clear_pending_events(&self) -> Vec<events::Event> {
		let events = core::cell::RefCell::new(Vec::new());
		let event_handler = |event: events::Event| Ok(events.borrow_mut().push(event));
		self.process_pending_events(&event_handler);
		let collected_events = events.into_inner();

		// To expand the coverage and make sure all events are properly serialised and deserialised,
		// we test all generated events round-trip:
		for event in &collected_events {
			let ser = event.encode();
			if let Some(deser) =
				events::Event::read(&mut &ser[..]).expect("event should deserialize")
			{
				assert_eq!(&deser, event, "event should roundtrip correctly");
			}
		}

		collected_events
	}

	#[cfg(feature = "_test_utils")]
	pub fn push_pending_event(&self, event: events::Event) {
		let mut events = self.pending_events.lock().unwrap();
		events.push_back((event, None));
		self.event_persist_notifier.notify();
	}

	#[cfg(test)]
	pub fn pop_pending_event(&self) -> Option<events::Event> {
		let mut events = self.pending_events.lock().unwrap();
		events.pop_front().map(|(e, _)| e)
	}

	#[cfg(test)]
	pub fn has_pending_payments(&self) -> bool {
		self.pending_outbound_payments.has_pending_payments()
	}

	#[cfg(test)]
	pub fn clear_pending_payments(&self) {
		self.pending_outbound_payments.clear_pending_payments()
	}

	#[cfg(any(test, feature = "_test_utils"))]
	pub(crate) fn get_and_clear_pending_raa_blockers(
		&self,
	) -> Vec<(ChannelId, Vec<RAAMonitorUpdateBlockingAction>)> {
		let per_peer_state = self.per_peer_state.read().unwrap();
		let mut pending_blockers = Vec::new();

		for (_peer_pubkey, peer_state_mutex) in per_peer_state.iter() {
			let mut peer_state = peer_state_mutex.lock().unwrap();

			for (chan_id, actions) in peer_state.actions_blocking_raa_monitor_updates.iter() {
				// Only collect the non-empty actions into `pending_blockers`.
				if !actions.is_empty() {
					pending_blockers.push((chan_id.clone(), actions.clone()));
				}
			}

			peer_state.actions_blocking_raa_monitor_updates.clear();
		}

		pending_blockers
	}

	/// When something which was blocking a channel from updating its [`ChannelMonitor`] (e.g. an
	/// [`Event`] being handled) completes, this should be called to restore the channel to normal
	/// operation. It will double-check that nothing *else* is also blocking the same channel from
	/// making progress and then let any blocked [`ChannelMonitorUpdate`]s fly.
	#[rustfmt::skip]
	fn handle_monitor_update_release(
		&self, counterparty_node_id: PublicKey, channel_id: ChannelId,
		mut completed_blocker: Option<RAAMonitorUpdateBlockingAction>,
	) {
		let logger = WithContext::from(
			&self.logger, Some(counterparty_node_id), Some(channel_id), None
		);
		loop {
			let per_peer_state = self.per_peer_state.read().unwrap();
			if let Some(peer_state_mtx) = per_peer_state.get(&counterparty_node_id) {
				let mut peer_state_lck = peer_state_mtx.lock().unwrap();
				let peer_state = &mut *peer_state_lck;
				if let Some(blocker) = completed_blocker.take() {
					// Only do this on the first iteration of the loop.
					if let Some(blockers) = peer_state.actions_blocking_raa_monitor_updates
						.get_mut(&channel_id)
					{
						blockers.retain(|iter| iter != &blocker);
					}
				}

				if self.raa_monitor_updates_held(&peer_state.actions_blocking_raa_monitor_updates,
					channel_id, counterparty_node_id) {
					// Check that, while holding the peer lock, we don't have anything else
					// blocking monitor updates for this channel. If we do, release the monitor
					// update(s) when those blockers complete.
					log_trace!(logger, "Delaying monitor unlock as another channel's mon update needs to complete first",
						);
					break;
				}

				if let hash_map::Entry::Occupied(mut chan_entry) = peer_state.channel_by_id.entry(
					channel_id) {
					if let Some(chan) = chan_entry.get_mut().as_funded_mut() {
						let channel_funding_outpoint = chan.funding_outpoint();
						if let Some((monitor_update, further_update_exists)) = chan.unblock_next_blocked_monitor_update() {
							log_debug!(logger, "Unlocking monitor updating and updating monitor",
								);
							let post_update_data = self.handle_new_monitor_update(
								&mut peer_state.in_flight_monitor_updates,
								&mut peer_state.monitor_update_blocked_actions,
								&mut peer_state.pending_msg_events,
								peer_state.is_connected,
								chan,
								channel_funding_outpoint,
								monitor_update,
							);
							let holding_cell_res = self.check_free_peer_holding_cells(peer_state);

							mem::drop(peer_state_lck);
							mem::drop(per_peer_state);

							if let Some(data) = post_update_data {
								self.handle_post_monitor_update_chan_resume(data);
							}

							self.handle_holding_cell_free_result(holding_cell_res);

							if further_update_exists {
								// If there are more `ChannelMonitorUpdate`s to process, restart at the
								// top of the loop.
								continue;
							}
						} else {
							log_trace!(logger, "Unlocked monitor updating without monitors to update",
								);
						}
					}
				}
			} else {
				log_debug!(logger,
					"Got a release post-RAA monitor update for peer {} but the channel is gone",
					log_pubkey!(counterparty_node_id));
			}
			break;
		}
	}

	fn handle_post_event_actions<I: IntoIterator<Item = EventCompletionAction>>(&self, actions: I) {
		debug_assert_ne!(
			self.total_consistency_lock.held_by_thread(),
			LockHeldState::NotHeldByThread
		);
		for action in actions.into_iter() {
			match action {
				EventCompletionAction::ReleaseRAAChannelMonitorUpdate {
					channel_funding_outpoint: _,
					channel_id,
					counterparty_node_id,
				} => {
					let startup_complete =
						self.background_events_processed_since_startup.load(Ordering::Acquire);
					debug_assert!(startup_complete);
					self.handle_monitor_update_release(counterparty_node_id, channel_id, None);
				},
				EventCompletionAction::ReleasePaymentCompleteChannelMonitorUpdate(
					PaymentCompleteUpdate {
						counterparty_node_id,
						channel_funding_outpoint,
						channel_id,
						htlc_id,
					},
				) => {
					let per_peer_state = self.per_peer_state.read().unwrap();
					let mut peer_state_lock = per_peer_state
						.get(&counterparty_node_id)
						.map(|state| state.lock().unwrap())
						.expect("Channels originating a payment resolution must have peer state");
					let peer_state = &mut *peer_state_lock;
					let update_id = peer_state
						.closed_channel_monitor_update_ids
						.get_mut(&channel_id)
						.expect("Channels originating a payment resolution must have a monitor");
					// Note that for channels closed pre-0.1, the latest update_id is `u64::MAX`.
					*update_id = update_id.saturating_add(1);

					let update = ChannelMonitorUpdate {
						update_id: *update_id,
						channel_id: Some(channel_id),
						updates: vec![ChannelMonitorUpdateStep::ReleasePaymentComplete {
							htlc: htlc_id,
						}],
					};

					let during_startup =
						!self.background_events_processed_since_startup.load(Ordering::Acquire);
					if during_startup {
						let event = BackgroundEvent::MonitorUpdateRegeneratedOnStartup {
							counterparty_node_id,
							funding_txo: channel_funding_outpoint,
							channel_id,
							update,
						};
						self.pending_background_events.lock().unwrap().push(event);
					} else {
						if let Some(actions) = self.handle_post_close_monitor_update(
							&mut peer_state.in_flight_monitor_updates,
							&mut peer_state.monitor_update_blocked_actions,
							channel_funding_outpoint,
							update,
							counterparty_node_id,
							channel_id,
						) {
							mem::drop(peer_state_lock);
							mem::drop(per_peer_state);
							self.handle_monitor_update_completion_actions(actions);
						}
					}
				},
			}
		}
	}

	/// Processes any events asynchronously in the order they were generated since the last call
	/// using the given event handler.
	///
	/// See the trait-level documentation of [`EventsProvider`] for requirements.
	pub async fn process_pending_events_async<
		Future: core::future::Future<Output = Result<(), ReplayEvent>>,
		H: Fn(Event) -> Future,
	>(
		&self, handler: H,
	) {
		let mut ev;
		process_events_body!(self, ev, { handler(ev).await });
	}
}

impl<
		M: chain::Watch<SP::EcdsaSigner>,
		T: BroadcasterInterface,
		ES: EntropySource,
		NS: NodeSigner,
		SP: SignerProvider,
		F: FeeEstimator,
		R: Router,
		MR: MessageRouter,
		L: Logger,
	> BaseMessageHandler for ChannelManager<M, T, ES, NS, SP, F, R, MR, L>
{
	fn provided_node_features(&self) -> NodeFeatures {
		provided_node_features(&self.config.read().unwrap())
	}

	fn provided_init_features(&self, _their_init_features: PublicKey) -> InitFeatures {
		provided_init_features(&self.config.read().unwrap())
	}

	fn peer_disconnected(&self, counterparty_node_id: PublicKey) {
		let _persistence_guard = PersistenceNotifierGuard::optionally_notify(self, || {
			let mut splice_failed_events = Vec::new();
			let mut failed_channels: Vec<(Result<Infallible, _>, _)> = Vec::new();
			let mut per_peer_state = self.per_peer_state.write().unwrap();
			let remove_peer = {
				log_debug!(
					WithContext::from(&self.logger, Some(counterparty_node_id), None, None),
					"Marking channels disconnected and generating channel_updates.",
				);
				if let Some(peer_state_mutex) = per_peer_state.get(&counterparty_node_id) {
					let mut peer_state_lock = peer_state_mutex.lock().unwrap();
					let peer_state = &mut *peer_state_lock;
					let pending_msg_events = &mut peer_state.pending_msg_events;
					peer_state.channel_by_id.retain(|_, chan| {
						let logger = WithChannelContext::from(&self.logger, &chan.context(), None);
						let DisconnectResult { is_resumable, splice_funding_failed } =
							chan.peer_disconnected_is_resumable(&&logger);

						if let Some(splice_funding_failed) = splice_funding_failed {
							splice_failed_events.push(events::Event::SpliceFailed {
								channel_id: chan.context().channel_id(),
								counterparty_node_id,
								user_channel_id: chan.context().get_user_id(),
								abandoned_funding_txo: splice_funding_failed.funding_txo,
								channel_type: splice_funding_failed.channel_type,
								contributed_inputs: splice_funding_failed.contributed_inputs,
								contributed_outputs: splice_funding_failed.contributed_outputs,
							});
						}

						if is_resumable {
							return true;
						}

						// Clean up for removal.
						let reason = ClosureReason::DisconnectedPeer;
						let err = ChannelError::Close((reason.to_string(), reason));
						let (_, e) = self.locked_handle_force_close(
							&mut peer_state.closed_channel_monitor_update_ids,
							&mut peer_state.in_flight_monitor_updates,
							err,
							chan,
						);
						failed_channels.push((Err(e), counterparty_node_id));
						false
					});
					// Note that we don't bother generating any events for pre-accept channels -
					// they're not considered "channels" yet from the PoV of our events interface.
					peer_state.inbound_channel_request_by_id.clear();
					pending_msg_events.retain(|msg| {
						match msg {
							// V1 Channel Establishment
							&MessageSendEvent::SendAcceptChannel { .. } => false,
							&MessageSendEvent::SendOpenChannel { .. } => false,
							&MessageSendEvent::SendFundingCreated { .. } => false,
							&MessageSendEvent::SendFundingSigned { .. } => false,
							// V2 Channel Establishment
							&MessageSendEvent::SendAcceptChannelV2 { .. } => false,
							&MessageSendEvent::SendOpenChannelV2 { .. } => false,
							// Common Channel Establishment
							&MessageSendEvent::SendChannelReady { .. } => false,
							&MessageSendEvent::SendAnnouncementSignatures { .. } => false,
							// Quiescence
							&MessageSendEvent::SendStfu { .. } => false,
							// Splicing
							&MessageSendEvent::SendSpliceInit { .. } => false,
							&MessageSendEvent::SendSpliceAck { .. } => false,
							&MessageSendEvent::SendSpliceLocked { .. } => false,
							// Interactive Transaction Construction
							&MessageSendEvent::SendTxAddInput { .. } => false,
							&MessageSendEvent::SendTxAddOutput { .. } => false,
							&MessageSendEvent::SendTxRemoveInput { .. } => false,
							&MessageSendEvent::SendTxRemoveOutput { .. } => false,
							&MessageSendEvent::SendTxComplete { .. } => false,
							&MessageSendEvent::SendTxSignatures { .. } => false,
							&MessageSendEvent::SendTxInitRbf { .. } => false,
							&MessageSendEvent::SendTxAckRbf { .. } => false,
							&MessageSendEvent::SendTxAbort { .. } => false,
							// Channel Operations
							&MessageSendEvent::UpdateHTLCs { .. } => false,
							&MessageSendEvent::SendRevokeAndACK { .. } => false,
							&MessageSendEvent::SendClosingSigned { .. } => false,
							#[cfg(simple_close)]
							&MessageSendEvent::SendClosingComplete { .. } => false,
							#[cfg(simple_close)]
							&MessageSendEvent::SendClosingSig { .. } => false,
							&MessageSendEvent::SendShutdown { .. } => false,
							&MessageSendEvent::SendChannelReestablish { .. } => false,
							&MessageSendEvent::HandleError { .. } => false,
							// Gossip
							&MessageSendEvent::SendChannelAnnouncement { .. } => false,
							&MessageSendEvent::BroadcastChannelAnnouncement { .. } => true,
							// [`ChannelManager::pending_broadcast_events`] holds the [`BroadcastChannelUpdate`]
							// This check here is to ensure exhaustivity.
							&MessageSendEvent::BroadcastChannelUpdate { .. } => {
								debug_assert!(false, "This event shouldn't have been here");
								false
							},
							&MessageSendEvent::BroadcastNodeAnnouncement { .. } => true,
							&MessageSendEvent::SendChannelUpdate { .. } => false,
							&MessageSendEvent::SendChannelRangeQuery { .. } => false,
							&MessageSendEvent::SendShortIdsQuery { .. } => false,
							&MessageSendEvent::SendReplyChannelRange { .. } => false,
							&MessageSendEvent::SendGossipTimestampFilter { .. } => false,

							// Peer Storage
							&MessageSendEvent::SendPeerStorage { .. } => false,
							&MessageSendEvent::SendPeerStorageRetrieval { .. } => false,
						}
					});
					debug_assert!(peer_state.is_connected, "A disconnected peer cannot disconnect");
					peer_state.is_connected = false;
					peer_state.ok_to_remove(true)
				} else {
					debug_assert!(false, "Unconnected peer disconnected");
					true
				}
			};
			if remove_peer {
				per_peer_state.remove(&counterparty_node_id);
			}
			mem::drop(per_peer_state);

			let persist = if splice_failed_events.is_empty() {
				NotifyOption::SkipPersistHandleEvents
			} else {
				let mut pending_events = self.pending_events.lock().unwrap();
				for event in splice_failed_events {
					pending_events.push_back((event, None));
				}
				NotifyOption::DoPersist
			};

			for (err, counterparty_node_id) in failed_channels.drain(..) {
				let _ = self.handle_error(err, counterparty_node_id);
			}

			persist
		});
	}

	fn peer_connected(
		&self, counterparty_node_id: PublicKey, init_msg: &msgs::Init, inbound: bool,
	) -> Result<(), ()> {
		let logger = WithContext::from(&self.logger, Some(counterparty_node_id), None, None);
		if !init_msg.features.supports_static_remote_key() {
			log_debug!(
				logger,
				"Peer {} does not support static remote key, disconnecting",
				log_pubkey!(counterparty_node_id)
			);
			return Err(());
		}

		let mut res = Ok(());

		PersistenceNotifierGuard::optionally_notify(self, || {
			// If we have too many peers connected which don't have funded channels, disconnect the
			// peer immediately (as long as it doesn't have funded channels). If we have a bunch of
			// unfunded channels taking up space in memory for disconnected peers, we still let new
			// peers connect, but we'll reject new channels from them.
			let connected_peers_without_funded_channels =
				self.peers_without_funded_channels(|node| node.is_connected);
			let inbound_peer_limited =
				inbound && connected_peers_without_funded_channels >= MAX_NO_CHANNEL_PEERS;

			{
				let mut peer_state_lock = self.per_peer_state.write().unwrap();
				match peer_state_lock.entry(counterparty_node_id) {
					hash_map::Entry::Vacant(e) => {
						if inbound_peer_limited {
							res = Err(());
							return NotifyOption::SkipPersistNoEvents;
						}
						e.insert(Mutex::new(PeerState {
							channel_by_id: new_hash_map(),
							inbound_channel_request_by_id: new_hash_map(),
							latest_features: init_msg.features.clone(),
							pending_msg_events: Vec::new(),
							in_flight_monitor_updates: BTreeMap::new(),
							monitor_update_blocked_actions: BTreeMap::new(),
							actions_blocking_raa_monitor_updates: BTreeMap::new(),
							closed_channel_monitor_update_ids: BTreeMap::new(),
							is_connected: true,
							peer_storage: Vec::new(),
						}));
					},
					hash_map::Entry::Occupied(e) => {
						let mut peer_state = e.get().lock().unwrap();
						peer_state.latest_features = init_msg.features.clone();

						let best_block_height = self.best_block.read().unwrap().height;
						if inbound_peer_limited
							&& Self::unfunded_channel_count(&*peer_state, best_block_height)
								== peer_state.channel_by_id.len()
						{
							res = Err(());
							return NotifyOption::SkipPersistNoEvents;
						}

						debug_assert!(peer_state.pending_msg_events.is_empty());
						peer_state.pending_msg_events.clear();

						debug_assert!(
							!peer_state.is_connected,
							"A peer shouldn't be connected twice"
						);
						peer_state.is_connected = true;
					},
				}
			}

			log_debug!(logger, "Generating channel_reestablish events");

			let per_peer_state = self.per_peer_state.read().unwrap();
			if let Some(peer_state_mutex) = per_peer_state.get(&counterparty_node_id) {
				let mut peer_state_lock = peer_state_mutex.lock().unwrap();
				let peer_state = &mut *peer_state_lock;
				let pending_msg_events = &mut peer_state.pending_msg_events;

				if !peer_state.peer_storage.is_empty() {
					pending_msg_events.push(MessageSendEvent::SendPeerStorageRetrieval {
						node_id: counterparty_node_id.clone(),
						msg: msgs::PeerStorageRetrieval { data: peer_state.peer_storage.clone() },
					});
				}

				for (_, chan) in peer_state.channel_by_id.iter_mut() {
					let logger = WithChannelContext::from(&self.logger, &chan.context(), None);
					match chan.peer_connected_get_handshake(self.chain_hash, &&logger) {
						ReconnectionMsg::Reestablish(msg) => {
							pending_msg_events.push(MessageSendEvent::SendChannelReestablish {
								node_id: chan.context().get_counterparty_node_id(),
								msg,
							})
						},
						ReconnectionMsg::Open(OpenChannelMessage::V1(msg)) => pending_msg_events
							.push(MessageSendEvent::SendOpenChannel {
								node_id: chan.context().get_counterparty_node_id(),
								msg,
							}),
						ReconnectionMsg::Open(OpenChannelMessage::V2(msg)) => pending_msg_events
							.push(MessageSendEvent::SendOpenChannelV2 {
								node_id: chan.context().get_counterparty_node_id(),
								msg,
							}),
						ReconnectionMsg::None => {},
					}
				}
			}

			return NotifyOption::SkipPersistHandleEvents;
			//TODO: Also re-broadcast announcement_signatures
		});

		// While we usually refresh the AsyncReceiveOfferCache on a timer, we also want to start
		// interactively building offers as soon as we can after startup. We can't start building offers
		// until we have some peer connection(s) to receive onion messages over, so as a minor optimization
		// refresh the cache when a peer connects.
		self.check_refresh_async_receive_offer_cache(false);
		res
	}

	/// Returns `MessageSendEvent`s strictly ordered per-peer, in the order they were generated.
	/// The returned array will contain `MessageSendEvent`s for different peers if
	/// `MessageSendEvent`s to more than one peer exists, but `MessageSendEvent`s to the same peer
	/// is always placed next to each other.
	///
	/// Note that that while `MessageSendEvent`s are strictly ordered per-peer, the peer order for
	/// the chunks of `MessageSendEvent`s for different peers is random. I.e. if the array contains
	/// `MessageSendEvent`s  for both `node_a` and `node_b`, the `MessageSendEvent`s for `node_a`
	/// will randomly be placed first or last in the returned array.
	///
	/// Note that even though `BroadcastChannelAnnouncement` and `BroadcastChannelUpdate`
	/// `MessageSendEvent`s are intended to be broadcasted to all peers, they will be placed among
	/// the `MessageSendEvent`s to the specific peer they were generated under.
	fn get_and_clear_pending_msg_events(&self) -> Vec<MessageSendEvent> {
		let events = RefCell::new(Vec::new());
		PersistenceNotifierGuard::optionally_notify(self, || {
			let mut result = NotifyOption::SkipPersistNoEvents;

			// This method is quite performance-sensitive. Not only is it called very often, but it
			// *is* the critical path between generating a message for a peer and giving it to the
			// `PeerManager` to send. Thus, we should avoid adding any more logic here than we
			// need, especially anything that might end up causing I/O (like a
			// `ChannelMonitorUpdate`)!

			// TODO: This behavior should be documented. It's unintuitive that we query
			// ChannelMonitors when clearing other events.
			if self.process_pending_monitor_events() {
				result = NotifyOption::DoPersist;
			}

			if self.maybe_generate_initial_closing_signed() {
				result = NotifyOption::DoPersist;
			}

			#[cfg(test)]
			if self.check_free_holding_cells() {
				// In tests, we want to ensure that we never forget to free holding cells
				// immediately, so we check it here.
				// Note that we can't turn this on for `debug_assertions` because there's a race in
				// (at least) the fee-update logic in `timer_tick_occurred` which can lead to us
				// freeing holding cells here while its running.
				debug_assert!(false, "Holding cells should always be auto-free'd");
			}

			// Quiescence is an in-memory protocol, so we don't have to persist because of it.
			self.maybe_send_stfu();

			let mut is_any_peer_connected = false;
			let mut pending_events = Vec::new();
			let per_peer_state = self.per_peer_state.read().unwrap();
			for (_cp_id, peer_state_mutex) in per_peer_state.iter() {
				let mut peer_state_lock = peer_state_mutex.lock().unwrap();
				let peer_state = &mut *peer_state_lock;
				if peer_state.pending_msg_events.len() > 0 {
					pending_events.append(&mut peer_state.pending_msg_events);
				}
				if peer_state.is_connected {
					is_any_peer_connected = true
				}
			}

			// Ensure that we are connected to some peers before getting broadcast messages.
			if is_any_peer_connected {
				let mut broadcast_msgs = self.pending_broadcast_messages.lock().unwrap();
				pending_events.append(&mut broadcast_msgs);
			}

			if !pending_events.is_empty() {
				events.replace(pending_events);
			}

			result
		});
		events.into_inner()
	}
}

impl<
		M: chain::Watch<SP::EcdsaSigner>,
		T: BroadcasterInterface,
		ES: EntropySource,
		NS: NodeSigner,
		SP: SignerProvider,
		F: FeeEstimator,
		R: Router,
		MR: MessageRouter,
		L: Logger,
	> EventsProvider for ChannelManager<M, T, ES, NS, SP, F, R, MR, L>
{
	/// Processes events that must be periodically handled.
	///
	/// An [`EventHandler`] may safely call back to the provider in order to handle an event.
	/// However, it must not call [`Writeable::write`] as doing so would result in a deadlock.
	fn process_pending_events<H: Deref>(&self, handler: H)
	where
		H::Target: EventHandler,
	{
		let mut ev;
		process_events_body!(self, ev, handler.handle_event(ev));
	}
}

impl<
		M: chain::Watch<SP::EcdsaSigner>,
		T: BroadcasterInterface,
		ES: EntropySource,
		NS: NodeSigner,
		SP: SignerProvider,
		F: FeeEstimator,
		R: Router,
		MR: MessageRouter,
		L: Logger,
	> chain::Listen for ChannelManager<M, T, ES, NS, SP, F, R, MR, L>
{
	fn filtered_block_connected(&self, header: &Header, txdata: &TransactionData, height: u32) {
		{
			let best_block = self.best_block.read().unwrap();
			assert_eq!(best_block.block_hash, header.prev_blockhash,
				"Blocks must be connected in chain-order - the connected header must build on the last connected header");
			assert_eq!(best_block.height, height - 1,
				"Blocks must be connected in chain-order - the connected block height must be one greater than the previous height");
		}

		self.transactions_confirmed(header, txdata, height);
		self.best_block_updated(header, height);
	}

	fn blocks_disconnected(&self, fork_point: BestBlock) {
		let _persistence_guard =
			PersistenceNotifierGuard::optionally_notify_skipping_background_events(
				self,
				|| -> NotifyOption { NotifyOption::DoPersist },
			);
		{
			let mut best_block = self.best_block.write().unwrap();
			assert!(best_block.height > fork_point.height,
				"Blocks disconnected must indicate disconnection from the current best height, i.e. the new chain tip must be lower than the previous best height");
			*best_block = fork_point;
		}

		self.do_chain_event(Some(fork_point.height), |channel| {
			channel.best_block_updated(
				fork_point.height,
				None,
				self.chain_hash,
				&self.node_signer,
				&self.config.read().unwrap(),
				&&WithChannelContext::from(&self.logger, &channel.context, None),
			)
		});
	}
}

impl<
		M: chain::Watch<SP::EcdsaSigner>,
		T: BroadcasterInterface,
		ES: EntropySource,
		NS: NodeSigner,
		SP: SignerProvider,
		F: FeeEstimator,
		R: Router,
		MR: MessageRouter,
		L: Logger,
	> chain::Confirm for ChannelManager<M, T, ES, NS, SP, F, R, MR, L>
{
	#[rustfmt::skip]
	fn transactions_confirmed(&self, header: &Header, txdata: &TransactionData, height: u32) {
		// Note that we MUST NOT end up calling methods on self.chain_monitor here - we're called
		// during initialization prior to the chain_monitor being fully configured in some cases.
		// See the docs for `ChannelManagerReadArgs` for more.

		let block_hash = header.block_hash();
		log_trace!(self.logger, "{} transactions included in block {} at height {} provided", txdata.len(), block_hash, height);

		let _persistence_guard =
			PersistenceNotifierGuard::optionally_notify_skipping_background_events(
				self, || -> NotifyOption { NotifyOption::DoPersist });
		self.do_chain_event(Some(height), |channel| channel.transactions_confirmed(&block_hash, height, txdata, self.chain_hash, &self.node_signer, &self.config.read().unwrap(), &&WithChannelContext::from(&self.logger, &channel.context, None))
			.map(|(a, b)| (a, Vec::new(), b)));

		let last_best_block_height = self.best_block.read().unwrap().height;
		if height < last_best_block_height {
			let timestamp = self.highest_seen_timestamp.load(Ordering::Acquire);
			let do_update = |channel: &mut FundedChannel<SP>| {
				channel.best_block_updated(
					last_best_block_height,
					Some(timestamp as u32),
					self.chain_hash,
					&self.node_signer,
					&self.config.read().unwrap(),
					&&WithChannelContext::from(&self.logger, &channel.context, None),
				)
			};
			self.do_chain_event(Some(last_best_block_height), do_update);
		}
	}

	#[rustfmt::skip]
	fn best_block_updated(&self, header: &Header, height: u32) {
		// Note that we MUST NOT end up calling methods on self.chain_monitor here - we're called
		// during initialization prior to the chain_monitor being fully configured in some cases.
		// See the docs for `ChannelManagerReadArgs` for more.

		let block_hash = header.block_hash();
		log_trace!(self.logger, "New best block: {} at height {}", block_hash, height);

		let _persistence_guard =
			PersistenceNotifierGuard::optionally_notify_skipping_background_events(
				self, || -> NotifyOption { NotifyOption::DoPersist });
		*self.best_block.write().unwrap() = BestBlock::new(block_hash, height);

		let mut min_anchor_feerate = None;
		let mut min_non_anchor_feerate = None;
		if self.background_events_processed_since_startup.load(Ordering::Relaxed) {
			// If we're past the startup phase, update our feerate cache
			let mut last_days_feerates = self.last_days_feerates.lock().unwrap();
			if last_days_feerates.len() >= FEERATE_TRACKING_BLOCKS {
				last_days_feerates.pop_front();
			}
			let anchor_feerate = self.fee_estimator
				.bounded_sat_per_1000_weight(ConfirmationTarget::MinAllowedAnchorChannelRemoteFee);
			let non_anchor_feerate = self.fee_estimator
				.bounded_sat_per_1000_weight(ConfirmationTarget::MinAllowedNonAnchorChannelRemoteFee);
			last_days_feerates.push_back((anchor_feerate, non_anchor_feerate));
			if last_days_feerates.len() >= FEERATE_TRACKING_BLOCKS {
				min_anchor_feerate = last_days_feerates.iter().map(|(f, _)| f).min().copied();
				min_non_anchor_feerate = last_days_feerates.iter().map(|(_, f)| f).min().copied();
			}
		}

		self.do_chain_event(Some(height), |channel| {
			let logger = WithChannelContext::from(&self.logger, &channel.context, None);
			if channel.funding.get_channel_type().supports_anchors_zero_fee_htlc_tx() {
				if let Some(feerate) = min_anchor_feerate {
					channel.check_for_stale_feerate(&logger, feerate)?;
				}
			} else {
				if let Some(feerate) = min_non_anchor_feerate {
					channel.check_for_stale_feerate(&logger, feerate)?;
				}
			}

			// Remove any SCIDs used by older funding transactions
			{
				let legacy_scids = channel.remove_legacy_scids_before_block(height);
				if !legacy_scids.as_slice().is_empty() {
					let mut short_to_chan_info = self.short_to_chan_info.write().unwrap();
					for scid in legacy_scids {
						short_to_chan_info.remove(&scid);
					}
				}
			}

			channel.best_block_updated(
				height,
				Some(header.time),
				self.chain_hash,
				&self.node_signer,
				&self.config.read().unwrap(),
				&&WithChannelContext::from(&self.logger, &channel.context, None),
			)
		});

		macro_rules! max_time {
			($timestamp: expr) => {
				loop {
					// Update $timestamp to be the max of its current value and the block
					// timestamp. This should keep us close to the current time without relying on
					// having an explicit local time source.
					// Just in case we end up in a race, we loop until we either successfully
					// update $timestamp or decide we don't need to.
					let old_serial = $timestamp.load(Ordering::Acquire);
					if old_serial >= header.time as usize { break; }
					if $timestamp.compare_exchange(old_serial, header.time as usize, Ordering::AcqRel, Ordering::Relaxed).is_ok() {
						break;
					}
				}
			}
		}
		max_time!(self.highest_seen_timestamp);

		self.flow.best_block_updated(header, height);
	}

	fn get_relevant_txids(&self) -> Vec<(Txid, u32, Option<BlockHash>)> {
		let mut res = Vec::with_capacity(self.short_to_chan_info.read().unwrap().len());
		for (_cp_id, peer_state_mutex) in self.per_peer_state.read().unwrap().iter() {
			let mut peer_state_lock = peer_state_mutex.lock().unwrap();
			let peer_state = &mut *peer_state_lock;
			for chan in peer_state.channel_by_id.values().filter_map(Channel::as_funded) {
				for (funding_txid, conf_height, block_hash) in chan.get_relevant_txids() {
					res.push((funding_txid, conf_height, block_hash));
				}
			}
		}
		res
	}

	fn transaction_unconfirmed(&self, txid: &Txid) {
		let _persistence_guard =
			PersistenceNotifierGuard::optionally_notify_skipping_background_events(
				self,
				|| -> NotifyOption { NotifyOption::DoPersist },
			);
		self.do_chain_event(None, |channel| {
			let logger = WithChannelContext::from(&self.logger, &channel.context, None);
			channel.transaction_unconfirmed(txid, &&logger).map(|()| (None, Vec::new(), None))
		});
	}
}

pub(super) enum FundingConfirmedMessage {
	Establishment(msgs::ChannelReady),
	Splice(msgs::SpliceLocked, Option<OutPoint>, Option<ChannelMonitorUpdate>, Vec<FundingInfo>),
}

impl<
		M: chain::Watch<SP::EcdsaSigner>,
		T: BroadcasterInterface,
		ES: EntropySource,
		NS: NodeSigner,
		SP: SignerProvider,
		F: FeeEstimator,
		R: Router,
		MR: MessageRouter,
		L: Logger,
	> ChannelManager<M, T, ES, NS, SP, F, R, MR, L>
{
	/// Calls a function which handles an on-chain event (blocks dis/connected, transactions
	/// un/confirmed, etc) on each channel, handling any resulting errors or messages generated by
	/// the function.
	fn do_chain_event<
		FN: Fn(
			&mut FundedChannel<SP>,
		) -> Result<
			(
				Option<FundingConfirmedMessage>,
				Vec<(HTLCSource, PaymentHash)>,
				Option<msgs::AnnouncementSignatures>,
			),
			ClosureReason,
		>,
	>(
		&self, height_opt: Option<u32>, f: FN,
	) {
		// Note that we MUST NOT end up calling methods on self.chain_monitor here - we're called
		// during initialization prior to the chain_monitor being fully configured in some cases.
		// See the docs for `ChannelManagerReadArgs` for more.

		let mut failed_channels: Vec<(Result<Infallible, _>, _)> = Vec::new();
		let mut timed_out_htlcs = Vec::new();
		let mut to_process_monitor_update_actions = Vec::new();
		{
			let per_peer_state = self.per_peer_state.read().unwrap();
			for (counterparty_node_id, peer_state_mutex) in per_peer_state.iter() {
				let mut peer_state_lock = peer_state_mutex.lock().unwrap();
				let peer_state = &mut *peer_state_lock;
				let pending_msg_events = &mut peer_state.pending_msg_events;

				peer_state.channel_by_id.retain(|channel_id, chan| {
					match chan.as_funded_mut() {
						// Retain unfunded channels.
						None => true,
						Some(funded_channel) => {
							let res = f(funded_channel);
							if let Ok((funding_confirmed_opt, mut timed_out_pending_htlcs, announcement_sigs)) = res {
								for (source, payment_hash) in timed_out_pending_htlcs.drain(..) {
									let reason = LocalHTLCFailureReason::CLTVExpiryTooSoon;
									let data = self.get_htlc_inbound_temp_fail_data(reason);
									timed_out_htlcs.push((source, payment_hash, HTLCFailReason::reason(reason, data),
										HTLCHandlingFailureType::Forward { node_id: Some(funded_channel.context.get_counterparty_node_id()), channel_id: *channel_id }));
								}
								let logger = WithChannelContext::from(&self.logger, &funded_channel.context, None);
								match funding_confirmed_opt {
									Some(FundingConfirmedMessage::Establishment(channel_ready)) => {
										self.send_channel_ready(pending_msg_events, funded_channel, channel_ready);
										if funded_channel.context.is_usable() && peer_state.is_connected {
											log_trace!(logger, "Sending channel_ready with private initial channel_update for our counterparty");
											if let Ok((msg, _, _)) = self.get_channel_update_for_unicast(funded_channel) {
												pending_msg_events.push(MessageSendEvent::SendChannelUpdate {
													node_id: funded_channel.context.get_counterparty_node_id(),
													msg,
												});
											}
										} else {
											log_trace!(logger, "Sending channel_ready WITHOUT channel_update");
										}
									},
									Some(FundingConfirmedMessage::Splice(splice_locked, funding_txo, monitor_update_opt, discarded_funding)) => {
										let counterparty_node_id = funded_channel.context.get_counterparty_node_id();
										let channel_id = funded_channel.context.channel_id();

										if let Some(funding_txo) = funding_txo {
											let mut short_to_chan_info = self.short_to_chan_info.write().unwrap();
											insert_short_channel_id!(short_to_chan_info, funded_channel);

											if let Some(monitor_update) = monitor_update_opt {
												self.handle_new_monitor_update_locked_actions_handled_by_caller(
													&mut peer_state.in_flight_monitor_updates,
													funded_channel.context.channel_id(),
													funding_txo,
													funded_channel.context.get_counterparty_node_id(),
													monitor_update,
												);
												to_process_monitor_update_actions.push((
													counterparty_node_id, channel_id
												));
											}

											let mut pending_events = self.pending_events.lock().unwrap();
											pending_events.push_back((events::Event::ChannelReady {
												channel_id,
												user_channel_id: funded_channel.context.get_user_id(),
												counterparty_node_id,
												funding_txo: Some(funding_txo.into_bitcoin_outpoint()),
												channel_type: funded_channel.funding.get_channel_type().clone(),
											}, None));
											discarded_funding.into_iter().for_each(|funding_info| {
												let event = Event::DiscardFunding {
													channel_id: funded_channel.context.channel_id(),
													funding_info,
												};
												pending_events.push_back((event, None));
											});
										}

										if funded_channel.context.is_connected() {
											pending_msg_events.push(MessageSendEvent::SendSpliceLocked {
												node_id: counterparty_node_id,
												msg: splice_locked,
											});
										}
									},
									None => {},
								}

								{
									let mut pending_events = self.pending_events.lock().unwrap();
									emit_initial_channel_ready_event!(pending_events, funded_channel);
								}

								if let Some(height) = height_opt {
									// (re-)broadcast signed `channel_announcement`s and
									// `channel_update`s for any channels less than a week old.
									let funding_conf_height =
										funded_channel.funding.get_funding_tx_confirmation_height().unwrap_or(height);
									// To avoid broadcast storms after each block, only
									// re-broadcast every hour (6 blocks) after the initial
									// broadcast, or if this is the first time we're ready to
									// broadcast this channel.
									let rebroadcast_announcement = funding_conf_height < height + 1008
										&& funding_conf_height % 6 == height % 6;
									#[allow(unused_mut, unused_assignments)]
									let mut should_announce = announcement_sigs.is_some() || rebroadcast_announcement;
									// Most of our tests were written when we only broadcasted
									// `channel_announcement`s once and then never re-broadcasted
									// them again, so disable the re-broadcasting entirely in tests
									#[cfg(any(test, feature = "_test_utils"))]
									{
										should_announce = announcement_sigs.is_some();
									}
									if should_announce {
										if let Some(announcement) = funded_channel.get_signed_channel_announcement(
											&self.node_signer, self.chain_hash, height, &self.config.read().unwrap(),
										) {
											pending_msg_events.push(MessageSendEvent::BroadcastChannelAnnouncement {
												msg: announcement,
												// Note that get_signed_channel_announcement fails
												// if the channel cannot be announced, so
												// get_channel_update_for_broadcast will never fail
												// by the time we get here.
												update_msg: Some(self.get_channel_update_for_broadcast(funded_channel).unwrap().0),
											});
										}
									}
								}
								if let Some(announcement_sigs) = announcement_sigs {
									if peer_state.is_connected {
										log_trace!(logger, "Sending announcement_signatures");
										pending_msg_events.push(MessageSendEvent::SendAnnouncementSignatures {
											node_id: funded_channel.context.get_counterparty_node_id(),
											msg: announcement_sigs,
										});
									}
								}
								if funded_channel.is_our_channel_ready() {
									if let Some(real_scid) = funded_channel.funding.get_short_channel_id() {
										// If we sent a 0conf channel_ready, and now have an SCID, we add it
										// to the short_to_chan_info map here. Note that we check whether we
										// can relay using the real SCID at relay-time (i.e.
										// enforce option_scid_alias then), and if the funding tx is ever
										// un-confirmed we force-close the channel, ensuring short_to_chan_info
										// is always consistent.
										let mut short_to_chan_info = self.short_to_chan_info.write().unwrap();
										let scid_insert = short_to_chan_info.insert(real_scid, (funded_channel.context.get_counterparty_node_id(), *channel_id));
										assert!(scid_insert.is_none() || scid_insert.unwrap() == (funded_channel.context.get_counterparty_node_id(), *channel_id),
											"SCIDs should never collide - ensure you weren't behind by a full {} blocks when creating channels",
											fake_scid::MAX_SCID_BLOCKS_FROM_NOW);
									}
								}
							} else if let Err(reason) = res {
								// It looks like our counterparty went on-chain or funding transaction was
								// reorged out of the main chain. Close the channel.
								let err = ChannelError::Close((reason.to_string(), reason));
								let (_, e) = self.locked_handle_funded_force_close(
									&mut peer_state.closed_channel_monitor_update_ids, &mut peer_state.in_flight_monitor_updates,
									err,
									funded_channel
								);
								failed_channels.push((Err(e), *counterparty_node_id));
								return false;
							}
							true
						}
					}
				});
			}
		}

		for (counterparty_node_id, channel_id) in to_process_monitor_update_actions {
			self.channel_monitor_updated(&channel_id, None, &counterparty_node_id);
		}

		if let Some(height) = height_opt {
			self.claimable_payments.lock().unwrap().claimable_payments.retain(
				|payment_hash, payment| {
					payment.htlcs.retain(|htlc| {
						// If height is approaching the number of blocks we think it takes us to get
						// our commitment transaction confirmed before the HTLC expires, plus the
						// number of blocks we generally consider it to take to do a commitment update,
						// just give up on it and fail the HTLC.
						if height >= htlc.cltv_expiry - HTLC_FAIL_BACK_BUFFER {
							let reason = LocalHTLCFailureReason::PaymentClaimBuffer;
							timed_out_htlcs.push((
								HTLCSource::PreviousHopData(htlc.prev_hop.clone()),
								payment_hash.clone(),
								HTLCFailReason::reason(
									reason,
									invalid_payment_err_data(htlc.value, height),
								),
								HTLCHandlingFailureType::Receive {
									payment_hash: payment_hash.clone(),
								},
							));
							false
						} else {
							true
						}
					});
					!payment.htlcs.is_empty() // Only retain this entry if htlcs has at least one entry.
				},
			);

			let mut intercepted_htlcs = self.pending_intercepted_htlcs.lock().unwrap();
			intercepted_htlcs.retain(|_, htlc| {
				if height >= htlc.forward_info.outgoing_cltv_value - HTLC_FAIL_BACK_BUFFER {
					let prev_hop_data = HTLCSource::PreviousHopData(htlc.htlc_previous_hop_data());
					let requested_forward_scid /* intercept scid */ = match htlc.forward_info.routing {
						PendingHTLCRouting::Forward { short_channel_id, .. } => short_channel_id,
						_ => unreachable!(),
					};
					timed_out_htlcs.push((
						prev_hop_data,
						htlc.forward_info.payment_hash,
						HTLCFailReason::from_failure_code(
							LocalHTLCFailureReason::ForwardExpiryBuffer,
						),
						HTLCHandlingFailureType::InvalidForward { requested_forward_scid },
					));
					let logger = WithContext::from(
						&self.logger,
						None,
						Some(htlc.prev_channel_id),
						Some(htlc.forward_info.payment_hash),
					);
					log_trace!(
						logger,
						"Timing out intercepted HTLC with requested forward scid {}",
						requested_forward_scid
					);
					false
				} else {
					true
				}
			});
		}

		for (failure, counterparty_node_id) in failed_channels {
			let _ = self.handle_error(failure, counterparty_node_id);
		}

		for (source, payment_hash, reason, destination) in timed_out_htlcs.drain(..) {
			self.fail_htlc_backwards_internal(&source, &payment_hash, &reason, destination, None);
		}
	}

	/// Gets a [`Future`] that completes when this [`ChannelManager`] may need to be persisted or
	/// may have events that need processing.
	///
	/// In order to check if this [`ChannelManager`] needs persisting, call
	/// [`Self::get_and_clear_needs_persistence`].
	///
	/// Note that callbacks registered on the [`Future`] MUST NOT call back into this
	/// [`ChannelManager`] and should instead register actions to be taken later.
	pub fn get_event_or_persistence_needed_future(&self) -> Future {
		self.event_persist_notifier.get_future()
	}

	/// Returns true if this [`ChannelManager`] needs to be persisted.
	///
	/// See [`Self::get_event_or_persistence_needed_future`] for retrieving a [`Future`] that
	/// indicates this should be checked.
	pub fn get_and_clear_needs_persistence(&self) -> bool {
		self.needs_persist_flag.swap(false, Ordering::AcqRel)
	}

	#[cfg(any(test, feature = "_test_utils"))]
	pub fn get_event_or_persist_condvar_value(&self) -> bool {
		self.event_persist_notifier.notify_pending()
	}

	/// Gets the latest best block which was connected either via the [`chain::Listen`] or
	/// [`chain::Confirm`] interfaces.
	pub fn current_best_block(&self) -> BestBlock {
		self.best_block.read().unwrap().clone()
	}

	/// Fetches the set of [`NodeFeatures`] flags that are provided by or required by
	/// [`ChannelManager`].
	pub fn node_features(&self) -> NodeFeatures {
		provided_node_features(&self.config.read().unwrap())
	}

	/// Fetches the set of [`Bolt11InvoiceFeatures`] flags that are provided by or required by
	/// [`ChannelManager`].
	///
	/// Note that the invoice feature flags can vary depending on if the invoice is a "phantom invoice"
	/// or not. Thus, this method is not public.
	#[cfg(any(feature = "_test_utils", test))]
	pub fn bolt11_invoice_features(&self) -> Bolt11InvoiceFeatures {
		provided_bolt11_invoice_features(&self.config.read().unwrap())
	}

	/// Fetches the set of [`Bolt12InvoiceFeatures`] flags that are provided by or required by
	/// [`ChannelManager`].
	fn bolt12_invoice_features(&self) -> Bolt12InvoiceFeatures {
		provided_bolt12_invoice_features(&self.config.read().unwrap())
	}

	/// Fetches the set of [`ChannelFeatures`] flags that are provided by or required by
	/// [`ChannelManager`].
	pub fn channel_features(&self) -> ChannelFeatures {
		provided_channel_features(&self.config.read().unwrap())
	}

	/// Fetches the set of [`ChannelTypeFeatures`] flags that are provided by or required by
	/// [`ChannelManager`].
	pub fn channel_type_features(&self) -> ChannelTypeFeatures {
		provided_channel_type_features(&self.config.read().unwrap())
	}

	/// Fetches the set of [`InitFeatures`] flags that are provided by or required by
	/// [`ChannelManager`].
	pub fn init_features(&self) -> InitFeatures {
		provided_init_features(&self.config.read().unwrap())
	}
}

impl<
		M: chain::Watch<SP::EcdsaSigner>,
		T: BroadcasterInterface,
		ES: EntropySource,
		NS: NodeSigner,
		SP: SignerProvider,
		F: FeeEstimator,
		R: Router,
		MR: MessageRouter,
		L: Logger,
	> ChannelMessageHandler for ChannelManager<M, T, ES, NS, SP, F, R, MR, L>
{
	fn handle_open_channel(&self, counterparty_node_id: PublicKey, message: &msgs::OpenChannel) {
		// Note that we never need to persist the updated ChannelManager for an inbound
		// open_channel message - pre-funded channels are never written so there should be no
		// change to the contents.
		let _persistence_guard = PersistenceNotifierGuard::optionally_notify(self, || {
			let msg = OpenChannelMessageRef::V1(message);
			let res = self.internal_open_channel(&counterparty_node_id, msg);
			let persist = match &res {
				Err(e) if e.closes_channel() => {
					debug_assert!(false, "We shouldn't close a new channel");
					NotifyOption::DoPersist
				},
				_ => NotifyOption::SkipPersistHandleEvents,
			};
			let _ = self.handle_error(res, counterparty_node_id);
			persist
		});
	}

	#[rustfmt::skip]
	fn handle_open_channel_v2(&self, counterparty_node_id: PublicKey, msg: &msgs::OpenChannelV2) {
		if !self.init_features().supports_dual_fund() {
			let _: Result<(), _> = self.handle_error(Err(MsgHandleErrInternal::send_err_msg_no_close(
				"Dual-funded channels not supported".to_owned(),
				msg.common_fields.temporary_channel_id.clone())), counterparty_node_id);
			return;
		}
		// Note that we never need to persist the updated ChannelManager for an inbound
		// open_channel message - pre-funded channels are never written so there should be no
		// change to the contents.
		let _persistence_guard = PersistenceNotifierGuard::optionally_notify(self, || {
			let res = self.internal_open_channel(&counterparty_node_id, OpenChannelMessageRef::V2(msg));
			let persist = match &res {
				Err(e) if e.closes_channel() => {
					debug_assert!(false, "We shouldn't close a new channel");
					NotifyOption::DoPersist
				},
				_ => NotifyOption::SkipPersistHandleEvents,
			};
			let _ = self.handle_error(res, counterparty_node_id);
			persist
		});
	}

	fn handle_accept_channel(&self, counterparty_node_id: PublicKey, msg: &msgs::AcceptChannel) {
		// Note that we never need to persist the updated ChannelManager for an inbound
		// accept_channel message - pre-funded channels are never written so there should be no
		// change to the contents.
		let _persistence_guard = PersistenceNotifierGuard::optionally_notify(self, || {
			let res = self.internal_accept_channel(&counterparty_node_id, msg);
			let _ = self.handle_error(res, counterparty_node_id);
			NotifyOption::SkipPersistHandleEvents
		});
	}

	fn handle_accept_channel_v2(
		&self, counterparty_node_id: PublicKey, msg: &msgs::AcceptChannelV2,
	) {
		let err = Err(MsgHandleErrInternal::send_err_msg_no_close(
			"Dual-funded channels not supported".to_owned(),
			msg.common_fields.temporary_channel_id.clone(),
		));
		let _: Result<(), _> = self.handle_error(err, counterparty_node_id);
	}

	fn handle_funding_created(&self, counterparty_node_id: PublicKey, msg: &msgs::FundingCreated) {
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(self);
		let res = self.internal_funding_created(&counterparty_node_id, msg);
		let _ = self.handle_error(res, counterparty_node_id);
	}

	fn handle_funding_signed(&self, counterparty_node_id: PublicKey, msg: &msgs::FundingSigned) {
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(self);
		let res = self.internal_funding_signed(&counterparty_node_id, msg);
		let _ = self.handle_error(res, counterparty_node_id);
	}

	fn handle_peer_storage(&self, counterparty_node_id: PublicKey, msg: msgs::PeerStorage) {
		let _persistence_guard =
			PersistenceNotifierGuard::optionally_notify(self, || NotifyOption::SkipPersistNoEvents);
		let res = self.internal_peer_storage(counterparty_node_id, msg);
		let _ = self.handle_error(res, counterparty_node_id);
	}

	fn handle_peer_storage_retrieval(
		&self, counterparty_node_id: PublicKey, msg: msgs::PeerStorageRetrieval,
	) {
		let _persistence_guard =
			PersistenceNotifierGuard::optionally_notify(self, || NotifyOption::SkipPersistNoEvents);
		let res = self.internal_peer_storage_retrieval(counterparty_node_id, msg);
		let _ = self.handle_error(res, counterparty_node_id);
	}

	fn handle_channel_ready(&self, counterparty_node_id: PublicKey, msg: &msgs::ChannelReady) {
		// Note that we never need to persist the updated ChannelManager for an inbound
		// channel_ready message - while the channel's state will change, any channel_ready message
		// will ultimately be re-sent on startup and the `ChannelMonitor` won't be updated so we
		// will not force-close the channel on startup.
		let _persistence_guard = PersistenceNotifierGuard::optionally_notify(self, || {
			let res = self.internal_channel_ready(&counterparty_node_id, msg);
			let persist = match &res {
				Err(e) if e.closes_channel() => NotifyOption::DoPersist,
				_ => NotifyOption::SkipPersistHandleEvents,
			};
			let _ = self.handle_error(res, counterparty_node_id);
			persist
		});
	}

	fn handle_stfu(&self, counterparty_node_id: PublicKey, msg: &msgs::Stfu) {
		let _persistence_guard = PersistenceNotifierGuard::optionally_notify(self, || {
			let res = self.internal_stfu(&counterparty_node_id, msg);
			let persist = match &res {
				Err(e) if e.closes_channel() => NotifyOption::DoPersist,
				Err(_) => NotifyOption::SkipPersistHandleEvents,
				Ok(responded) => {
					if *responded {
						NotifyOption::SkipPersistHandleEvents
					} else {
						NotifyOption::SkipPersistNoEvents
					}
				},
			};
			let _ = self.handle_error(res, counterparty_node_id);
			persist
		});
	}

	fn handle_splice_init(&self, counterparty_node_id: PublicKey, msg: &msgs::SpliceInit) {
		let _persistence_guard = PersistenceNotifierGuard::optionally_notify(self, || {
			let res = self.internal_splice_init(&counterparty_node_id, msg);
			let persist = match &res {
				Err(e) if e.closes_channel() => NotifyOption::DoPersist,
				Err(_) => NotifyOption::SkipPersistHandleEvents,
				Ok(()) => NotifyOption::SkipPersistHandleEvents,
			};
			let _ = self.handle_error(res, counterparty_node_id);
			persist
		});
	}

	fn handle_splice_ack(&self, counterparty_node_id: PublicKey, msg: &msgs::SpliceAck) {
		let _persistence_guard = PersistenceNotifierGuard::optionally_notify(self, || {
			let res = self.internal_splice_ack(&counterparty_node_id, msg);
			let persist = match &res {
				Err(e) if e.closes_channel() => NotifyOption::DoPersist,
				Err(_) => NotifyOption::SkipPersistHandleEvents,
				Ok(()) => NotifyOption::SkipPersistHandleEvents,
			};
			let _ = self.handle_error(res, counterparty_node_id);
			persist
		});
	}

	#[rustfmt::skip]
	fn handle_splice_locked(&self, counterparty_node_id: PublicKey, msg: &msgs::SpliceLocked) {
		let _persistence_guard = PersistenceNotifierGuard::optionally_notify(self, || {
			let res = self.internal_splice_locked(&counterparty_node_id, msg);
			let persist = match &res {
				Err(e) if e.closes_channel() => NotifyOption::DoPersist,
				Err(_) => NotifyOption::SkipPersistHandleEvents,
				Ok(()) => NotifyOption::DoPersist,
			};
			let _ = self.handle_error(res, counterparty_node_id);
			persist
		});
	}

	fn handle_shutdown(&self, counterparty_node_id: PublicKey, msg: &msgs::Shutdown) {
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(self);
		let res = self.internal_shutdown(&counterparty_node_id, msg);
		let _ = self.handle_error(res, counterparty_node_id);
	}

	fn handle_closing_signed(&self, counterparty_node_id: PublicKey, msg: &msgs::ClosingSigned) {
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(self);
		let res = self.internal_closing_signed(&counterparty_node_id, msg);
		let _ = self.handle_error(res, counterparty_node_id);
	}

	#[cfg(simple_close)]
	fn handle_closing_complete(&self, counterparty_node_id: PublicKey, msg: msgs::ClosingComplete) {
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(self);
		let res = self.internal_closing_complete(counterparty_node_id, msg);
		let _ = self.handle_error(res, counterparty_node_id);
	}

	#[cfg(simple_close)]
	fn handle_closing_sig(&self, counterparty_node_id: PublicKey, msg: msgs::ClosingSig) {
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(self);
		let res = self.internal_closing_sig(counterparty_node_id, msg);
		let _ = self.handle_error(res, counterparty_node_id);
	}

	fn handle_update_add_htlc(&self, counterparty_node_id: PublicKey, msg: &msgs::UpdateAddHTLC) {
		// Note that we never need to persist the updated ChannelManager for an inbound
		// update_add_htlc message - the message itself doesn't change our channel state only the
		// `commitment_signed` message afterwards will.
		let _persistence_guard = PersistenceNotifierGuard::optionally_notify(self, || {
			let res = self.internal_update_add_htlc(&counterparty_node_id, msg);
			let persist = match &res {
				Err(e) if e.closes_channel() => NotifyOption::DoPersist,
				Err(_) => NotifyOption::SkipPersistHandleEvents,
				Ok(()) => NotifyOption::SkipPersistNoEvents,
			};
			let _ = self.handle_error(res, counterparty_node_id);
			persist
		});
	}

	fn handle_update_fulfill_htlc(
		&self, counterparty_node_id: PublicKey, msg: msgs::UpdateFulfillHTLC,
	) {
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(self);
		let res = self.internal_update_fulfill_htlc(&counterparty_node_id, msg);
		let _ = self.handle_error(res, counterparty_node_id);
	}

	fn handle_update_fail_htlc(&self, counterparty_node_id: PublicKey, msg: &msgs::UpdateFailHTLC) {
		// Note that we never need to persist the updated ChannelManager for an inbound
		// update_fail_htlc message - the message itself doesn't change our channel state only the
		// `commitment_signed` message afterwards will.
		let _persistence_guard = PersistenceNotifierGuard::optionally_notify(self, || {
			let res = self.internal_update_fail_htlc(&counterparty_node_id, msg);
			let persist = match &res {
				Err(e) if e.closes_channel() => NotifyOption::DoPersist,
				Err(_) => NotifyOption::SkipPersistHandleEvents,
				Ok(()) => NotifyOption::SkipPersistNoEvents,
			};
			let _ = self.handle_error(res, counterparty_node_id);
			persist
		});
	}

	fn handle_update_fail_malformed_htlc(
		&self, counterparty_node_id: PublicKey, msg: &msgs::UpdateFailMalformedHTLC,
	) {
		// Note that we never need to persist the updated ChannelManager for an inbound
		// update_fail_malformed_htlc message - the message itself doesn't change our channel state
		// only the `commitment_signed` message afterwards will.
		let _persistence_guard = PersistenceNotifierGuard::optionally_notify(self, || {
			let res = self.internal_update_fail_malformed_htlc(&counterparty_node_id, msg);
			let persist = match &res {
				Err(e) if e.closes_channel() => NotifyOption::DoPersist,
				Err(_) => NotifyOption::SkipPersistHandleEvents,
				Ok(()) => NotifyOption::SkipPersistNoEvents,
			};
			let _ = self.handle_error(res, counterparty_node_id);
			persist
		});
	}

	fn handle_commitment_signed(
		&self, counterparty_node_id: PublicKey, msg: &msgs::CommitmentSigned,
	) {
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(self);
		let res = self.internal_commitment_signed(&counterparty_node_id, msg);
		let _ = self.handle_error(res, counterparty_node_id);
	}

	fn handle_commitment_signed_batch(
		&self, counterparty_node_id: PublicKey, channel_id: ChannelId,
		batch: Vec<msgs::CommitmentSigned>,
	) {
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(self);
		let res = self.internal_commitment_signed_batch(&counterparty_node_id, channel_id, batch);
		let _ = self.handle_error(res, counterparty_node_id);
	}

	fn handle_revoke_and_ack(&self, counterparty_node_id: PublicKey, msg: &msgs::RevokeAndACK) {
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(self);
		let res = self.internal_revoke_and_ack(&counterparty_node_id, msg);
		let _ = self.handle_error(res, counterparty_node_id);
	}

	fn handle_update_fee(&self, counterparty_node_id: PublicKey, msg: &msgs::UpdateFee) {
		// Note that we never need to persist the updated ChannelManager for an inbound
		// update_fee message - the message itself doesn't change our channel state only the
		// `commitment_signed` message afterwards will.
		let _persistence_guard = PersistenceNotifierGuard::optionally_notify(self, || {
			let res = self.internal_update_fee(&counterparty_node_id, msg);
			let persist = match &res {
				Err(e) if e.closes_channel() => NotifyOption::DoPersist,
				Err(_) => NotifyOption::SkipPersistHandleEvents,
				Ok(()) => NotifyOption::SkipPersistNoEvents,
			};
			let _ = self.handle_error(res, counterparty_node_id);
			persist
		});
	}

	fn handle_announcement_signatures(
		&self, counterparty_node_id: PublicKey, msg: &msgs::AnnouncementSignatures,
	) {
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(self);
		let res = self.internal_announcement_signatures(&counterparty_node_id, msg);
		let _ = self.handle_error(res, counterparty_node_id);
	}

	fn handle_channel_update(&self, counterparty_node_id: PublicKey, msg: &msgs::ChannelUpdate) {
		PersistenceNotifierGuard::optionally_notify(self, || {
			let res = self.internal_channel_update(&counterparty_node_id, msg);
			if let Ok(persist) = self.handle_error(res, counterparty_node_id) {
				persist
			} else {
				NotifyOption::DoPersist
			}
		});
	}

	fn handle_channel_reestablish(
		&self, counterparty_node_id: PublicKey, msg: &msgs::ChannelReestablish,
	) {
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(self);
		let res = self.internal_channel_reestablish(&counterparty_node_id, msg);
		let _ = self.handle_error(res, counterparty_node_id);
	}

	#[rustfmt::skip]
	fn handle_error(&self, counterparty_node_id: PublicKey, msg: &msgs::ErrorMessage) {
		match &msg.data as &str {
			"cannot co-op close channel w/ active htlcs"|
			"link failed to shutdown" =>
			{
				// LND hasn't properly handled shutdown messages ever, and force-closes any time we
				// send one while HTLCs are still present. The issue is tracked at
				// https://github.com/lightningnetwork/lnd/issues/6039 and has had multiple patches
				// to fix it but none so far have managed to land upstream. The issue appears to be
				// very low priority for the LND team despite being marked "P1".
				// We're not going to bother handling this in a sensible way, instead simply
				// repeating the Shutdown message on repeat until morale improves.
				if !msg.channel_id.is_zero() {
					PersistenceNotifierGuard::optionally_notify(
						self,
						|| -> NotifyOption {
							let per_peer_state = self.per_peer_state.read().unwrap();
							let peer_state_mutex_opt = per_peer_state.get(&counterparty_node_id);
							if peer_state_mutex_opt.is_none() { return NotifyOption::SkipPersistNoEvents; }
							let mut peer_state = peer_state_mutex_opt.unwrap().lock().unwrap();
							if let Some(chan) = peer_state.channel_by_id
								.get(&msg.channel_id)
								.and_then(Channel::as_funded)
							{
								if let Some(msg) = chan.get_outbound_shutdown() {
									peer_state.pending_msg_events.push(MessageSendEvent::SendShutdown {
										node_id: counterparty_node_id,
										msg,
									});
								}
								peer_state.pending_msg_events.push(MessageSendEvent::HandleError {
									node_id: counterparty_node_id,
									action: msgs::ErrorAction::SendWarningMessage {
										msg: msgs::WarningMessage {
											channel_id: msg.channel_id,
											data: "You appear to be exhibiting LND bug 6039, we'll keep sending you shutdown messages until you handle them correctly".to_owned()
										},
										log_level: Level::Trace,
									}
								});
								// This can happen in a fairly tight loop, so we absolutely cannot trigger
								// a `ChannelManager` write here.
								return NotifyOption::SkipPersistHandleEvents;
							}
							NotifyOption::SkipPersistNoEvents
						}
					);
				}
				return;
			}
			_ => {}
		}

		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(self);

		let peer_msg = UntrustedString(msg.data.clone());
		let reason = ClosureReason::CounterpartyForceClosed { peer_msg };

		if msg.channel_id.is_zero() {
			let channel_ids: Vec<ChannelId> = {
				let per_peer_state = self.per_peer_state.read().unwrap();
				let peer_state_mutex_opt = per_peer_state.get(&counterparty_node_id);
				if peer_state_mutex_opt.is_none() { return; }
				let mut peer_state_lock = peer_state_mutex_opt.unwrap().lock().unwrap();
				let peer_state = &mut *peer_state_lock;
				// Note that we don't bother generating any events for pre-accept channels -
				// they're not considered "channels" yet from the PoV of our events interface.
				peer_state.inbound_channel_request_by_id.clear();
				peer_state.channel_by_id.keys().cloned().collect()
			};
			for channel_id in channel_ids {
				// Untrusted messages from peer, we throw away the error if id points to a non-existent channel
				let _ = self.force_close_channel_with_peer(&channel_id, &counterparty_node_id, reason.clone());
			}
		} else {
			{
				// First check if we can advance the channel type and try again.
				let per_peer_state = self.per_peer_state.read().unwrap();
				let peer_state_mutex_opt = per_peer_state.get(&counterparty_node_id);
				if peer_state_mutex_opt.is_none() { return; }
				let mut peer_state_lock = peer_state_mutex_opt.unwrap().lock().unwrap();
				let peer_state = &mut *peer_state_lock;
				match peer_state.channel_by_id.get_mut(&msg.channel_id) {
					Some(chan) => match chan.maybe_handle_error_without_close(
						self.chain_hash, &self.fee_estimator, &self.logger,
						&self.config.read().unwrap(), &peer_state.latest_features,
					) {
						Ok(Some(OpenChannelMessage::V1(msg))) => {
							peer_state.pending_msg_events.push(MessageSendEvent::SendOpenChannel {
								node_id: counterparty_node_id,
								msg,
							});
							return;
						},
						Ok(Some(OpenChannelMessage::V2(msg))) => {
							peer_state.pending_msg_events.push(MessageSendEvent::SendOpenChannelV2 {
								node_id: counterparty_node_id,
								msg,
							});
							return;
						},
						Ok(None) | Err(()) => {},
					},
					None => {},
				}
			}

			// Untrusted messages from peer, we throw away the error if id points to a non-existent channel
			let _ = self.force_close_channel_with_peer(&msg.channel_id, &counterparty_node_id, reason);
		}
	}

	fn get_chain_hashes(&self) -> Option<Vec<ChainHash>> {
		Some(vec![self.chain_hash])
	}

	fn handle_tx_add_input(&self, counterparty_node_id: PublicKey, msg: &msgs::TxAddInput) {
		let _persistence_guard = PersistenceNotifierGuard::manually_notify(self, || {
			let res = self.internal_tx_add_input(counterparty_node_id, msg);
			debug_assert!(res.as_ref().err().map_or(true, |err| !err.closes_channel()));
			let _ = self.handle_error(res, counterparty_node_id);
			self.event_persist_notifier.notify();
		});
	}

	fn handle_tx_add_output(&self, counterparty_node_id: PublicKey, msg: &msgs::TxAddOutput) {
		let _persistence_guard = PersistenceNotifierGuard::manually_notify(self, || {
			let res = self.internal_tx_add_output(counterparty_node_id, msg);
			debug_assert!(res.as_ref().err().map_or(true, |err| !err.closes_channel()));
			let _ = self.handle_error(res, counterparty_node_id);
			self.event_persist_notifier.notify();
		});
	}

	fn handle_tx_remove_input(&self, counterparty_node_id: PublicKey, msg: &msgs::TxRemoveInput) {
		let _persistence_guard = PersistenceNotifierGuard::manually_notify(self, || {
			let res = self.internal_tx_remove_input(counterparty_node_id, msg);
			debug_assert!(res.as_ref().err().map_or(true, |err| !err.closes_channel()));
			let _ = self.handle_error(res, counterparty_node_id);
			self.event_persist_notifier.notify();
		});
	}

	fn handle_tx_remove_output(&self, counterparty_node_id: PublicKey, msg: &msgs::TxRemoveOutput) {
		let _persistence_guard = PersistenceNotifierGuard::manually_notify(self, || {
			let res = self.internal_tx_remove_output(counterparty_node_id, msg);
			debug_assert!(res.as_ref().err().map_or(true, |err| !err.closes_channel()));
			let _ = self.handle_error(res, counterparty_node_id);
			self.event_persist_notifier.notify();
		});
	}

	fn handle_tx_complete(&self, counterparty_node_id: PublicKey, msg: &msgs::TxComplete) {
		let _persistence_guard = PersistenceNotifierGuard::manually_notify(self, || {
			let res = self.internal_tx_complete(counterparty_node_id, msg);
			debug_assert!(res.as_ref().err().map_or(true, |err| !err.closes_channel()));
			let _ = self.handle_error(res, counterparty_node_id);
			self.event_persist_notifier.notify();
		});
	}

	fn handle_tx_signatures(&self, counterparty_node_id: PublicKey, msg: &msgs::TxSignatures) {
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(self);
		let res = self.internal_tx_signatures(&counterparty_node_id, msg);
		let _ = self.handle_error(res, counterparty_node_id);
	}

	fn handle_tx_init_rbf(&self, counterparty_node_id: PublicKey, msg: &msgs::TxInitRbf) {
		let err = Err(MsgHandleErrInternal::send_err_msg_no_close(
			"Dual-funded channels not supported".to_owned(),
			msg.channel_id.clone(),
		));
		let _: Result<(), _> = self.handle_error(err, counterparty_node_id);
	}

	fn handle_tx_ack_rbf(&self, counterparty_node_id: PublicKey, msg: &msgs::TxAckRbf) {
		let err = Err(MsgHandleErrInternal::send_err_msg_no_close(
			"Dual-funded channels not supported".to_owned(),
			msg.channel_id.clone(),
		));
		let _: Result<(), _> = self.handle_error(err, counterparty_node_id);
	}

	fn handle_tx_abort(&self, counterparty_node_id: PublicKey, msg: &msgs::TxAbort) {
		// Note that we never need to persist the updated ChannelManager for an inbound
		// tx_abort message - interactive transaction construction does not need to
		// be persisted before any signatures are exchanged.
		let _persistence_guard = PersistenceNotifierGuard::optionally_notify(self, || {
			let res = self.internal_tx_abort(&counterparty_node_id, msg);
			let persist = match &res {
				Err(e) if e.closes_channel() => NotifyOption::DoPersist,
				Err(_) => NotifyOption::SkipPersistHandleEvents,
				Ok(persist) => *persist,
			};
			let _ = self.handle_error(res, counterparty_node_id);
			persist
		});
	}

	fn message_received(&self) {
		for (payment_id, retryable_invoice_request) in
			self.pending_outbound_payments.release_invoice_requests_awaiting_invoice()
		{
			let RetryableInvoiceRequest { invoice_request, nonce, .. } = retryable_invoice_request;

			let peers = self.get_peers_for_blinded_path();
			let enqueue_invreq_res =
				self.flow.enqueue_invoice_request(invoice_request, payment_id, nonce, peers);
			if enqueue_invreq_res.is_err() {
				log_warn!(
					self.logger,
					"Retry failed for invoice request with payment_id {}",
					payment_id
				);
			}
		}
	}
}

impl<
		M: chain::Watch<SP::EcdsaSigner>,
		T: BroadcasterInterface,
		ES: EntropySource,
		NS: NodeSigner,
		SP: SignerProvider,
		F: FeeEstimator,
		R: Router,
		MR: MessageRouter,
		L: Logger,
	> OffersMessageHandler for ChannelManager<M, T, ES, NS, SP, F, R, MR, L>
{
	#[rustfmt::skip]
	fn handle_message(
		&self, message: OffersMessage, context: Option<OffersContext>, responder: Option<Responder>,
	) -> Option<(OffersMessage, ResponseInstruction)> {
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

				let invoice_request = match self.flow.verify_invoice_request(invoice_request, context) {
					Ok(InvreqResponseInstructions::SendInvoice(invoice_request)) => invoice_request,
					Ok(InvreqResponseInstructions::SendStaticInvoice { recipient_id, invoice_slot, invoice_request }) => {
						self.pending_events.lock().unwrap().push_back((Event::StaticInvoiceRequested {
							recipient_id, invoice_slot, reply_path: responder, invoice_request,
						}, None));

						return None
					},
					Err(_) => return None,
				};

				let get_payment_info = |amount_msats, relative_expiry| {
					self.create_inbound_payment(
						Some(amount_msats),
						relative_expiry,
						None
					).map_err(|_| Bolt12SemanticError::InvalidAmount)
				};

				let (result, context) = match invoice_request {
					InvoiceRequestVerifiedFromOffer::DerivedKeys(request) => {
						let result = self.flow.create_invoice_builder_from_invoice_request_with_keys(
							&self.router,
							&request,
							self.list_usable_channels(),
							get_payment_info,
						);

						match result {
							Ok((builder, context)) => {
								let res = builder
									.build_and_sign(&self.secp_ctx)
									.map_err(InvoiceError::from);

								(res, context)
							},
							Err(error) => {
								return Some((
									OffersMessage::InvoiceError(InvoiceError::from(error)),
									responder.respond(),
								));
							},
						}
					},
					InvoiceRequestVerifiedFromOffer::ExplicitKeys(request) => {
						let result = self.flow.create_invoice_builder_from_invoice_request_without_keys(
							&self.router,
							&request,
							self.list_usable_channels(),
							get_payment_info,
						);

						match result {
							Ok((builder, context)) => {
								let res = builder
									.build()
									.map_err(InvoiceError::from)
									.and_then(|invoice| {
										#[cfg(c_bindings)]
										let mut invoice = invoice;
										invoice
											.sign(|invoice: &UnsignedBolt12Invoice| self.node_signer.sign_bolt12_invoice(invoice))
											.map_err(InvoiceError::from)
									});
								(res, context)
							},
							Err(error) => {
								return Some((
									OffersMessage::InvoiceError(InvoiceError::from(error)),
									responder.respond(),
								));
							},
						}
					}
				};

				Some(match result {
					Ok(invoice) => (
						OffersMessage::Invoice(invoice),
						responder.respond_with_reply_path(context),
					),
					Err(error) => (
						OffersMessage::InvoiceError(error),
						responder.respond(),
					),
				})
			},
			OffersMessage::Invoice(invoice) => {
				let payment_id = match self.flow.verify_bolt12_invoice(&invoice, context.as_ref()) {
					Ok(payment_id) => payment_id,
					Err(()) => return None,
				};

				let logger = WithContext::for_payment(
					&self.logger, None, None, Some(invoice.payment_hash()), payment_id,
				);

				if self.config.read().unwrap().manually_handle_bolt12_invoices {
					// Update the corresponding entry in `PendingOutboundPayment` for this invoice.
					// This ensures that event generation remains idempotent in case we receive
					// the same invoice multiple times.
					self.pending_outbound_payments.mark_invoice_received(&invoice, payment_id).ok()?;

					let event = Event::InvoiceReceived {
						payment_id, invoice, context, responder,
					};
					self.pending_events.lock().unwrap().push_back((event, None));
					return None;
				}

				let res = self.send_payment_for_verified_bolt12_invoice(&invoice, payment_id);
				handle_pay_invoice_res!(res, invoice, logger);
			},
			OffersMessage::StaticInvoice(invoice) => {
				let payment_id = match context {
					Some(OffersContext::OutboundPaymentForOffer { payment_id, .. }) => payment_id,
					_ => return None
				};
				let res = self.initiate_async_payment(&invoice, payment_id);
				handle_pay_invoice_res!(res, invoice, self.logger);
			},
			OffersMessage::InvoiceError(invoice_error) => {
				let payment_hash = match context {
					Some(OffersContext::InboundPayment { payment_hash }) => Some(payment_hash),
					_ => None,
				};

				let logger = WithContext::from(&self.logger, None, None, payment_hash);
				log_trace!(logger, "Received invoice_error: {}", invoice_error);

				match context {
					Some(OffersContext::OutboundPaymentForOffer { payment_id, .. })
					|Some(OffersContext::OutboundPaymentForRefund { payment_id, .. }) => {
						self.abandon_payment_with_reason(
							payment_id, PaymentFailureReason::InvoiceRequestRejected,
						);
					},
					_ => {},
				}

				None
			},
		}
	}

	fn release_pending_messages(&self) -> Vec<(OffersMessage, MessageSendInstructions)> {
		self.flow.release_pending_offers_messages()
	}
}

impl<
		M: chain::Watch<SP::EcdsaSigner>,
		T: BroadcasterInterface,
		ES: EntropySource,
		NS: NodeSigner,
		SP: SignerProvider,
		F: FeeEstimator,
		R: Router,
		MR: MessageRouter,
		L: Logger,
	> AsyncPaymentsMessageHandler for ChannelManager<M, T, ES, NS, SP, F, R, MR, L>
{
	fn handle_offer_paths_request(
		&self, message: OfferPathsRequest, context: AsyncPaymentsContext,
		responder: Option<Responder>,
	) -> Option<(OfferPaths, ResponseInstruction)> {
		let peers = self.get_peers_for_blinded_path();
		let (message, reply_path_context) =
			match self.flow.handle_offer_paths_request(&message, context, peers) {
				Some(msg) => msg,
				None => return None,
			};
		responder.map(|resp| (message, resp.respond_with_reply_path(reply_path_context)))
	}

	fn handle_offer_paths(
		&self, message: OfferPaths, context: AsyncPaymentsContext, responder: Option<Responder>,
	) -> Option<(ServeStaticInvoice, ResponseInstruction)> {
		let responder = match responder {
			Some(responder) => responder,
			None => return None,
		};
		let (serve_static_invoice, reply_context) = match self.flow.handle_offer_paths(
			message,
			context,
			responder.clone(),
			self.get_peers_for_blinded_path(),
			self.list_usable_channels(),
			&self.entropy_source,
			&self.router,
		) {
			Some((msg, ctx)) => (msg, ctx),
			None => return None,
		};

		// We cached a new pending offer, so persist the cache.
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(self);

		let response_instructions = responder.respond_with_reply_path(reply_context);
		return Some((serve_static_invoice, response_instructions));
	}

	fn handle_serve_static_invoice(
		&self, message: ServeStaticInvoice, context: AsyncPaymentsContext,
		responder: Option<Responder>,
	) {
		let responder = match responder {
			Some(resp) => resp,
			None => return,
		};

		let (recipient_id, invoice_slot) =
			match self.flow.verify_serve_static_invoice_message(&message, context) {
				Ok((recipient_id, inv_slot)) => (recipient_id, inv_slot),
				Err(()) => return,
			};

		let mut pending_events = self.pending_events.lock().unwrap();
		pending_events.push_back((
			Event::PersistStaticInvoice {
				invoice: message.invoice,
				invoice_request_path: message.forward_invoice_request_path,
				invoice_slot,
				recipient_id,
				invoice_persisted_path: responder,
			},
			None,
		));
	}

	fn handle_static_invoice_persisted(
		&self, _message: StaticInvoicePersisted, context: AsyncPaymentsContext,
	) {
		let should_persist = self.flow.handle_static_invoice_persisted(context);
		if should_persist {
			let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(self);
		}
	}

	fn handle_held_htlc_available(
		&self, _message: HeldHtlcAvailable, context: AsyncPaymentsContext,
		responder: Option<Responder>,
	) -> Option<(ReleaseHeldHtlc, ResponseInstruction)> {
		self.flow.verify_inbound_async_payment_context(context).ok()?;
		return responder.map(|responder| (ReleaseHeldHtlc {}, responder.respond()));
	}

	fn handle_release_held_htlc(&self, _message: ReleaseHeldHtlc, context: AsyncPaymentsContext) {
		match context {
			AsyncPaymentsContext::OutboundPayment { payment_id } => {
				if let Err(e) = self.send_payment_for_static_invoice(payment_id) {
					log_trace!(
						self.logger,
						"Failed to release held HTLC with payment id {}: {:?}",
						payment_id,
						e
					);
				}
			},
			AsyncPaymentsContext::ReleaseHeldHtlc {
				intercept_id,
				prev_outbound_scid_alias,
				htlc_id,
			} => {
				let _serialize_guard = PersistenceNotifierGuard::notify_on_drop(self);
				// It's possible the release_held_htlc message raced ahead of us transitioning the pending
				// update_add to `Self::pending_intercept_htlcs`. If that's the case, update the pending
				// update_add to indicate that the HTLC should be released immediately.
				//
				// Check for the HTLC here before checking `pending_intercept_htlcs` to avoid a different
				// race where the HTLC gets transitioned to `pending_intercept_htlcs` after we drop that
				// map's lock but before acquiring the `decode_update_add_htlcs` lock.
				let mut decode_update_add_htlcs = self.decode_update_add_htlcs.lock().unwrap();
				if let Some(htlcs) = decode_update_add_htlcs.get_mut(&prev_outbound_scid_alias) {
					for update_add in htlcs.iter_mut() {
						if update_add.htlc_id == htlc_id {
							log_trace!(
								self.logger,
								"Marking held htlc with intercept_id {} as ready to release",
								intercept_id
							);
							update_add.hold_htlc.take();
							return;
						}
					}
				}
				core::mem::drop(decode_update_add_htlcs);

				let mut htlc = {
					let mut pending_intercept_htlcs =
						self.pending_intercepted_htlcs.lock().unwrap();
					match pending_intercept_htlcs.remove(&intercept_id) {
						Some(htlc) => htlc,
						None => {
							log_trace!(
								self.logger,
								"Failed to release HTLC with intercept_id {}: HTLC not found",
								intercept_id
							);
							return;
						},
					}
				};
				let next_hop_scid = match htlc.forward_info.routing {
					PendingHTLCRouting::Forward { ref mut hold_htlc, short_channel_id, .. } => {
						debug_assert!(hold_htlc.is_some());
						*hold_htlc = None;
						short_channel_id
					},
					_ => {
						debug_assert!(false, "HTLC intercepts can only be forwards");
						// Let the HTLC be auto-failed before it expires.
						return;
					},
				};

				let logger = WithContext::from(
					&self.logger,
					Some(htlc.prev_counterparty_node_id),
					Some(htlc.prev_channel_id),
					Some(htlc.forward_info.payment_hash),
				);
				log_trace!(logger, "Releasing held htlc with intercept_id {}", intercept_id);

				let prev_chan_public = {
					let per_peer_state = self.per_peer_state.read().unwrap();
					let peer_state = per_peer_state
						.get(&htlc.prev_counterparty_node_id)
						.map(|mtx| mtx.lock().unwrap());
					let chan_state = peer_state
						.as_ref()
						.map(|state| state.channel_by_id.get(&htlc.prev_channel_id))
						.flatten();
					if let Some(chan_state) = chan_state {
						chan_state.context().should_announce()
					} else {
						// If the inbound channel has closed since the HTLC was held, we really
						// shouldn't forward it - forwarding it now would result in, at best,
						// having to claim the HTLC on chain. Instead, drop the HTLC and let the
						// counterparty claim their money on chain.
						return;
					}
				};

				let should_intercept = self
					.do_funded_channel_callback(next_hop_scid, |chan| {
						self.forward_needs_intercept_to_known_chan(prev_chan_public, chan)
					})
					.unwrap_or_else(|| self.forward_needs_intercept_to_unknown_chan(next_hop_scid));

				if should_intercept {
					let intercept_id = InterceptId::from_htlc_id_and_chan_id(
						htlc.prev_htlc_id,
						&htlc.prev_channel_id,
						&htlc.prev_counterparty_node_id,
					);
					let mut pending_intercepts = self.pending_intercepted_htlcs.lock().unwrap();
					match pending_intercepts.entry(intercept_id) {
						hash_map::Entry::Vacant(entry) => {
							if let Ok(intercept_ev) =
								create_htlc_intercepted_event(intercept_id, &htlc)
							{
								self.pending_events.lock().unwrap().push_back((intercept_ev, None));
								entry.insert(htlc);
							} else {
								debug_assert!(false);
								// Let the HTLC be auto-failed before it expires.
								return;
							}
						},
						hash_map::Entry::Occupied(_) => {
							log_error!(
								logger,
								"Failed to forward incoming HTLC: detected duplicate intercepted payment",
							);
							debug_assert!(
								false,
								"Should never have two HTLCs with the same channel id and htlc id",
							);
							// Let the HTLC be auto-failed before it expires.
							return;
						},
					}
				} else {
					self.forward_htlcs([htlc]);
				}
			},
			_ => return,
		}
	}

	fn release_pending_messages(&self) -> Vec<(AsyncPaymentsMessage, MessageSendInstructions)> {
		self.flow.release_pending_async_messages()
	}
}

#[cfg(feature = "dnssec")]
impl<
		M: chain::Watch<SP::EcdsaSigner>,
		T: BroadcasterInterface,
		ES: EntropySource,
		NS: NodeSigner,
		SP: SignerProvider,
		F: FeeEstimator,
		R: Router,
		MR: MessageRouter,
		L: Logger,
	> DNSResolverMessageHandler for ChannelManager<M, T, ES, NS, SP, F, R, MR, L>
{
	fn handle_dnssec_query(
		&self, _message: DNSSECQuery, _responder: Option<Responder>,
	) -> Option<(DNSResolverMessage, ResponseInstruction)> {
		None
	}

	#[rustfmt::skip]
	fn handle_dnssec_proof(&self, message: DNSSECProof, context: DNSResolverContext) {
		let offer_opt = self.flow.hrn_resolver.handle_dnssec_proof_for_offer(message, context);
		#[cfg_attr(not(feature = "_test_utils"), allow(unused_mut))]
		if let Some((completed_requests, mut offer)) = offer_opt {
			for (name, payment_id) in completed_requests {
				#[cfg(feature = "_test_utils")]
				if let Some(replacement_offer) = self.testing_dnssec_proof_offer_resolution_override.lock().unwrap().remove(&name) {
					// If we have multiple pending requests we may end up over-using the override
					// offer, but tests can deal with that.
					offer = replacement_offer;
				}
				if let Ok((amt_msats, payer_note)) = self.pending_outbound_payments.params_for_payment_awaiting_offer(payment_id) {
					let offer_pay_res =
						self.pay_for_offer_intern(&offer, None, Some(amt_msats), payer_note, payment_id, Some(name),
							|retryable_invoice_request| {
								self.pending_outbound_payments
									.received_offer(payment_id, Some(retryable_invoice_request))
									.map_err(|_| Bolt12SemanticError::DuplicatePaymentId)
						});
					if offer_pay_res.is_err() {
						// The offer we tried to pay is the canonical current offer for the name we
						// wanted to pay. If we can't pay it, there's no way to recover so fail the
						// payment.
						// Note that the PaymentFailureReason should be ignored for an
						// AwaitingInvoice payment.
						self.pending_outbound_payments.abandon_payment(
							payment_id, PaymentFailureReason::RouteNotFound, &self.pending_events,
						);
					}
				}
			}
		}
	}

	fn release_pending_messages(&self) -> Vec<(DNSResolverMessage, MessageSendInstructions)> {
		self.flow.release_pending_dns_messages()
	}
}

impl<
		M: chain::Watch<SP::EcdsaSigner>,
		T: BroadcasterInterface,
		ES: EntropySource,
		NS: NodeSigner,
		SP: SignerProvider,
		F: FeeEstimator,
		R: Router,
		MR: MessageRouter,
		L: Logger,
	> NodeIdLookUp for ChannelManager<M, T, ES, NS, SP, F, R, MR, L>
{
	fn next_node_id(&self, short_channel_id: u64) -> Option<PublicKey> {
		self.short_to_chan_info.read().unwrap().get(&short_channel_id).map(|(pubkey, _)| *pubkey)
	}
}

/// Fetches the set of [`NodeFeatures`] flags that are provided by or required by
/// [`ChannelManager`].
pub(crate) fn provided_node_features(config: &UserConfig) -> NodeFeatures {
	let mut node_features = provided_init_features(config).to_context();
	node_features.set_keysend_optional();
	node_features
}

/// Fetches the set of [`Bolt11InvoiceFeatures`] flags that are provided by or required by
/// [`ChannelManager`].
///
/// Note that the invoice feature flags can vary depending on if the invoice is a "phantom invoice"
/// or not. Thus, this method is not public.
#[cfg(any(feature = "_test_utils", test))]
pub(crate) fn provided_bolt11_invoice_features(config: &UserConfig) -> Bolt11InvoiceFeatures {
	provided_init_features(config).to_context()
}

/// Fetches the set of [`Bolt12InvoiceFeatures`] flags that are provided by or required by
/// [`ChannelManager`].
pub(crate) fn provided_bolt12_invoice_features(config: &UserConfig) -> Bolt12InvoiceFeatures {
	provided_init_features(config).to_context()
}

/// Fetches the set of [`ChannelFeatures`] flags that are provided by or required by
/// [`ChannelManager`].
pub(crate) fn provided_channel_features(config: &UserConfig) -> ChannelFeatures {
	provided_init_features(config).to_context()
}

/// Fetches the set of [`ChannelTypeFeatures`] flags that are provided by or required by
/// [`ChannelManager`].
pub(crate) fn provided_channel_type_features(config: &UserConfig) -> ChannelTypeFeatures {
	ChannelTypeFeatures::from_init(&provided_init_features(config))
}

/// Fetches the set of [`InitFeatures`] flags that are provided by or required by
/// [`ChannelManager`].
pub fn provided_init_features(config: &UserConfig) -> InitFeatures {
	// Note that if new features are added here which other peers may (eventually) require, we
	// should also add the corresponding (optional) bit to the [`BaseMessageHandler`] impl for
	// [`ErroringMessageHandler`].
	let mut features = InitFeatures::empty();
	features.set_data_loss_protect_required();
	features.set_upfront_shutdown_script_optional();
	features.set_variable_length_onion_required();
	features.set_static_remote_key_required();
	features.set_payment_secret_required();
	features.set_basic_mpp_optional();
	features.set_wumbo_optional();
	features.set_shutdown_any_segwit_optional();
	features.set_channel_type_required();
	features.set_scid_privacy_optional();
	features.set_zero_conf_optional();
	features.set_route_blinding_optional();
	features.set_provide_storage_optional();
	#[cfg(simple_close)]
	features.set_simple_close_optional();
	features.set_quiescence_optional();
	features.set_splicing_optional();

	if config.channel_handshake_config.negotiate_anchors_zero_fee_htlc_tx {
		features.set_anchors_zero_fee_htlc_tx_optional();
	}
	if config.enable_dual_funded_channels {
		features.set_dual_fund_optional();
	}

	if config.channel_handshake_config.negotiate_anchor_zero_fee_commitments {
		features.set_anchor_zero_fee_commitments_optional();
	}

	if config.enable_htlc_hold {
		features.set_htlc_hold_optional();
	}

	features
}

const SERIALIZATION_VERSION: u8 = 1;
const MIN_SERIALIZATION_VERSION: u8 = 1;

// We plan to start writing this version in 0.5.
//
// LDK 0.5+ will reconstruct the set of pending HTLCs from `Channel{Monitor}` data that started
// being written in 0.3, ignoring legacy `ChannelManager` HTLC maps on read and not writing them.
// LDK 0.5+ will automatically fail to read if the pending HTLC set cannot be reconstructed, i.e.
// if we were last written with pending HTLCs on 0.2- or if the new 0.3+ fields are missing.
//
// If 0.3 or 0.4 reads this manager version, it knows that the legacy maps were not written and
// acts accordingly.
const RECONSTRUCT_HTLCS_FROM_CHANS_VERSION: u8 = 2;

impl_writeable_tlv_based!(PhantomRouteHints, {
	(2, channels, required_vec),
	(4, phantom_scid, required),
	(6, real_node_pubkey, required),
});

impl_writeable_tlv_based!(BlindedForward, {
	(0, inbound_blinding_point, required),
	(1, failure, (default_value, BlindedFailure::FromIntroductionNode)),
	(3, next_blinding_override, option),
});

impl_writeable_tlv_based_enum!(PendingHTLCRouting,
	(0, Forward) => {
		(0, onion_packet, required),
		(1, blinded, option),
		(2, short_channel_id, required),
		(3, incoming_cltv_expiry, option),
		(4, hold_htlc, option),
	},
	(1, Receive) => {
		(0, payment_data, required),
		(1, phantom_shared_secret, option),
		(2, incoming_cltv_expiry, required),
		(3, payment_metadata, option),
		(5, custom_tlvs, optional_vec),
		(7, requires_blinded_error, (default_value, false)),
		(9, payment_context, option),
		(11, trampoline_shared_secret, option),
	},
	(2, ReceiveKeysend) => {
		(0, payment_preimage, required),
		(1, requires_blinded_error, (default_value, false)),
		(2, incoming_cltv_expiry, required),
		(3, payment_metadata, option),
		(4, payment_data, option), // Added in 0.0.116
		(5, custom_tlvs, optional_vec),
		(7, has_recipient_created_payment_secret, (default_value, false)),
		(9, payment_context, option),
		(11, invoice_request, option),
	},
	(3, TrampolineForward) => {
		(0, incoming_shared_secret, required),
		(2, onion_packet, required),
		(4, blinded, option),
		(6, node_id, required),
		(8, incoming_cltv_expiry, required),
	}
);

impl_writeable_tlv_based!(PendingHTLCInfo, {
	(0, routing, required),
	(2, incoming_shared_secret, required),
	(4, payment_hash, required),
	(6, outgoing_amt_msat, required),
	(8, outgoing_cltv_value, required),
	(9, incoming_amt_msat, option),
	(10, skimmed_fee_msat, option),
	(11, incoming_accountable, (default_value, false)),
});

impl Writeable for HTLCFailureMsg {
	#[rustfmt::skip]
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		match self {
			HTLCFailureMsg::Relay(msgs::UpdateFailHTLC { channel_id, htlc_id, reason, attribution_data }) => {
				0u8.write(writer)?;
				channel_id.write(writer)?;
				htlc_id.write(writer)?;
				reason.write(writer)?;

				// This code will only ever be hit for legacy data that is re-serialized. It isn't necessary to try
				// writing out attribution data, because it can never be present.
				debug_assert!(attribution_data.is_none());
			},
			HTLCFailureMsg::Malformed(msgs::UpdateFailMalformedHTLC {
				channel_id, htlc_id, sha256_of_onion, failure_code
			}) => {
				1u8.write(writer)?;
				channel_id.write(writer)?;
				htlc_id.write(writer)?;
				sha256_of_onion.write(writer)?;
				failure_code.write(writer)?;
			},
		}
		Ok(())
	}
}

impl Readable for HTLCFailureMsg {
	#[rustfmt::skip]
	fn read<R: Read>(reader: &mut R) -> Result<Self, DecodeError> {
		let id: u8 = Readable::read(reader)?;
		match id {
			0 => {
				Ok(HTLCFailureMsg::Relay(msgs::UpdateFailHTLC {
					channel_id: Readable::read(reader)?,
					htlc_id: Readable::read(reader)?,
					reason: Readable::read(reader)?,
					attribution_data: None,
				}))
			},
			1 => {
				Ok(HTLCFailureMsg::Malformed(msgs::UpdateFailMalformedHTLC {
					channel_id: Readable::read(reader)?,
					htlc_id: Readable::read(reader)?,
					sha256_of_onion: Readable::read(reader)?,
					failure_code: Readable::read(reader)?,
				}))
			},
			// In versions prior to 0.0.101, HTLCFailureMsg objects were written with type 0 or 1 but
			// weren't length-prefixed and thus didn't support reading the TLV stream suffix of the network
			// messages contained in the variants.
			// In version 0.0.101, support for reading the variants with these types was added, and
			// we should migrate to writing these variants when UpdateFailHTLC or
			// UpdateFailMalformedHTLC get TLV fields.
			2 => {
				let length: BigSize = Readable::read(reader)?;
				let mut s = FixedLengthReader::new(reader, length.0);
				let res = LengthReadable::read_from_fixed_length_buffer(&mut s)?;
				s.eat_remaining()?; // Return ShortRead if there's actually not enough bytes
				Ok(HTLCFailureMsg::Relay(res))
			},
			3 => {
				let length: BigSize = Readable::read(reader)?;
				let mut s = FixedLengthReader::new(reader, length.0);
				let res = LengthReadable::read_from_fixed_length_buffer(&mut s)?;
				s.eat_remaining()?; // Return ShortRead if there's actually not enough bytes
				Ok(HTLCFailureMsg::Malformed(res))
			},
			_ => Err(DecodeError::UnknownRequiredFeature),
		}
	}
}

impl_writeable_tlv_based_enum_legacy!(PendingHTLCStatus, ;
	(0, Forward),
	(1, Fail),
);

impl_writeable_tlv_based_enum!(BlindedFailure,
	(0, FromIntroductionNode) => {},
	(2, FromBlindedNode) => {},
);

impl_writeable_tlv_based!(HTLCPreviousHopData, {
	(0, prev_outbound_scid_alias, required),
	(1, phantom_shared_secret, option),
	(2, outpoint, required),
	(3, blinded_failure, option),
	(4, htlc_id, required),
	(5, cltv_expiry, option),
	(6, incoming_packet_shared_secret, required),
	(7, user_channel_id, option),
	// Note that by the time we get past the required read for type 2 above, outpoint will be
	// filled in, so we can safely unwrap it here.
	(9, channel_id, (default_value, ChannelId::v1_from_funding_outpoint(outpoint.0.unwrap()))),
	(11, counterparty_node_id, option),
	(13, trampoline_shared_secret, option),
});

impl Writeable for ClaimableHTLC {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		let (payment_data, keysend_preimage) = match &self.onion_payload {
			OnionPayload::Invoice { _legacy_hop_data } => (_legacy_hop_data.as_ref(), None),
			OnionPayload::Spontaneous(preimage) => (None, Some(preimage)),
		};
		write_tlv_fields!(writer, {
			(0, self.prev_hop, required),
			(1, self.total_msat, required),
			(2, self.value, required),
			(3, self.sender_intended_value, required),
			(4, payment_data, option),
			(5, self.total_value_received, option),
			(6, self.cltv_expiry, required),
			(8, keysend_preimage, option),
			(10, self.counterparty_skimmed_fee_msat, option),
		});
		Ok(())
	}
}

impl Readable for ClaimableHTLC {
	#[rustfmt::skip]
	fn read<R: Read>(reader: &mut R) -> Result<Self, DecodeError> {
		_init_and_read_len_prefixed_tlv_fields!(reader, {
			(0, prev_hop, required),
			(1, total_msat, option),
			(2, value_ser, required),
			(3, sender_intended_value, option),
			(4, payment_data_opt, option),
			(5, total_value_received, option),
			(6, cltv_expiry, required),
			(8, keysend_preimage, option),
			(10, counterparty_skimmed_fee_msat, option),
		});
		let payment_data: Option<msgs::FinalOnionHopData> = payment_data_opt;
		let value = value_ser.0.unwrap();
		let onion_payload = match keysend_preimage {
			Some(p) => {
				if payment_data.is_some() {
					return Err(DecodeError::InvalidValue)
				}
				if total_msat.is_none() {
					total_msat = Some(value);
				}
				OnionPayload::Spontaneous(p)
			},
			None => {
				if total_msat.is_none() {
					if payment_data.is_none() {
						return Err(DecodeError::InvalidValue)
					}
					total_msat = Some(payment_data.as_ref().unwrap().total_msat);
				}
				OnionPayload::Invoice { _legacy_hop_data: payment_data }
			},
		};
		Ok(Self {
			prev_hop: prev_hop.0.unwrap(),
			timer_ticks: 0,
			value,
			sender_intended_value: sender_intended_value.unwrap_or(value),
			total_value_received,
			total_msat: total_msat.unwrap(),
			onion_payload,
			cltv_expiry: cltv_expiry.0.unwrap(),
			counterparty_skimmed_fee_msat,
		})
	}
}

impl Readable for HTLCSource {
	#[rustfmt::skip]
	fn read<R: Read>(reader: &mut R) -> Result<Self, DecodeError> {
		let id: u8 = Readable::read(reader)?;
		match id {
			0 => {
				let mut session_priv: crate::util::ser::RequiredWrapper<SecretKey> = crate::util::ser::RequiredWrapper(None);
				let mut first_hop_htlc_msat: u64 = 0;
				let mut path_hops = Vec::new();
				let mut payment_id = None;
				let mut payment_params: Option<PaymentParameters> = None;
				let mut blinded_tail: Option<BlindedTail> = None;
				let mut bolt12_invoice: Option<PaidBolt12Invoice> = None;
				read_tlv_fields!(reader, {
					(0, session_priv, required),
					(1, payment_id, option),
					(2, first_hop_htlc_msat, required),
					(4, path_hops, required_vec),
					(5, payment_params, (option: ReadableArgs, 0)),
					(6, blinded_tail, option),
					(7, bolt12_invoice, option),
				});
				if payment_id.is_none() {
					// For backwards compat, if there was no payment_id written, use the session_priv bytes
					// instead.
					payment_id = Some(PaymentId(*session_priv.0.unwrap().as_ref()));
				}
				let path = Path { hops: path_hops, blinded_tail };
				if path.hops.len() == 0 {
					return Err(DecodeError::InvalidValue);
				}
				if let Some(params) = payment_params.as_mut() {
					if let Payee::Clear { ref mut final_cltv_expiry_delta, .. } = params.payee {
						if final_cltv_expiry_delta == &0 {
							*final_cltv_expiry_delta = path.final_cltv_expiry_delta().ok_or(DecodeError::InvalidValue)?;
						}
					}
				}
				Ok(HTLCSource::OutboundRoute {
					session_priv: session_priv.0.unwrap(),
					first_hop_htlc_msat,
					path,
					payment_id: payment_id.unwrap(),
					bolt12_invoice,
				})
			}
			1 => Ok(HTLCSource::PreviousHopData(Readable::read(reader)?)),
			_ => Err(DecodeError::UnknownRequiredFeature),
		}
	}
}

impl Writeable for HTLCSource {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), crate::io::Error> {
		match self {
			HTLCSource::OutboundRoute {
				ref session_priv,
				ref first_hop_htlc_msat,
				ref path,
				payment_id,
				bolt12_invoice,
			} => {
				0u8.write(writer)?;
				let payment_id_opt = Some(payment_id);
				write_tlv_fields!(writer, {
				   (0, session_priv, required),
				   (1, payment_id_opt, option),
				   (2, first_hop_htlc_msat, required),
				   // 3 was previously used to write a PaymentSecret for the payment.
				   (4, path.hops, required_vec),
				   (5, None::<PaymentParameters>, option), // payment_params in LDK versions prior to 0.0.115
				   (6, path.blinded_tail, option),
				   (7, bolt12_invoice, option),
				});
			},
			HTLCSource::PreviousHopData(ref field) => {
				1u8.write(writer)?;
				field.write(writer)?;
			},
		}
		Ok(())
	}
}

impl_writeable_tlv_based!(PendingAddHTLCInfo, {
	(0, forward_info, required),
	(1, prev_user_channel_id, (default_value, 0)),
	(2, prev_outbound_scid_alias, required),
	(4, prev_htlc_id, required),
	(6, prev_funding_outpoint, required),
	// Note that by the time we get past the required read for type 6 above, prev_funding_outpoint will be
	// filled in, so we can safely unwrap it here.
	(7, prev_channel_id, (default_value, ChannelId::v1_from_funding_outpoint(prev_funding_outpoint.0.unwrap()))),
	(9, prev_counterparty_node_id, required),
});

impl Writeable for HTLCForwardInfo {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		const FAIL_HTLC_VARIANT_ID: u8 = 1;
		match self {
			Self::AddHTLC(info) => {
				0u8.write(w)?;
				info.write(w)?;
			},
			Self::FailHTLC { htlc_id, err_packet } => {
				FAIL_HTLC_VARIANT_ID.write(w)?;
				write_tlv_fields!(w, {
					(0, htlc_id, required),
					(2, err_packet.data, required),
					(5, err_packet.attribution_data, option),
				});
			},
			Self::FailMalformedHTLC { htlc_id, failure_code, sha256_of_onion } => {
				// Since this variant was added in 0.0.119, write this as `::FailHTLC` with an empty error
				// packet so older versions have something to fail back with, but serialize the real data as
				// optional TLVs for the benefit of newer versions.
				FAIL_HTLC_VARIANT_ID.write(w)?;
				write_tlv_fields!(w, {
					(0, htlc_id, required),
					(1, failure_code, required),
					(2, Vec::<u8>::new(), required),
					(3, sha256_of_onion, required),
				});
			},
		}
		Ok(())
	}
}

impl Readable for HTLCForwardInfo {
	#[rustfmt::skip]
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		let id: u8 = Readable::read(r)?;
		Ok(match id {
			0 => Self::AddHTLC(Readable::read(r)?),
			1 => {
				_init_and_read_len_prefixed_tlv_fields!(r, {
					(0, htlc_id, required),
					(1, malformed_htlc_failure_code, option),
					(2, err_packet, required),
					(3, sha256_of_onion, option),
					(5, attribution_data, option),
				});
				if let Some(failure_code) = malformed_htlc_failure_code {
					if attribution_data.is_some() {
						return Err(DecodeError::InvalidValue);
					}
					Self::FailMalformedHTLC {
						htlc_id: _init_tlv_based_struct_field!(htlc_id, required),
						failure_code,
						sha256_of_onion: sha256_of_onion.ok_or(DecodeError::InvalidValue)?,
					}
				} else {
					Self::FailHTLC {
						htlc_id: _init_tlv_based_struct_field!(htlc_id, required),
						err_packet: crate::ln::msgs::OnionErrorPacket {
							data: _init_tlv_based_struct_field!(err_packet, required),
							attribution_data: _init_tlv_based_struct_field!(attribution_data, option),
						},
					}
				}
			},
			_ => return Err(DecodeError::InvalidValue),
		})
	}
}

impl_writeable_tlv_based!(PendingInboundPayment, {
	(0, payment_secret, required),
	(2, expiry_time, required),
	(4, user_payment_id, required),
	(6, payment_preimage, required),
	(8, min_value_msat, required),
});

impl<
		M: chain::Watch<SP::EcdsaSigner>,
		T: BroadcasterInterface,
		ES: EntropySource,
		NS: NodeSigner,
		SP: SignerProvider,
		F: FeeEstimator,
		R: Router,
		MR: MessageRouter,
		L: Logger,
	> Writeable for ChannelManager<M, T, ES, NS, SP, F, R, MR, L>
{
	#[rustfmt::skip]
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		let _consistency_lock = self.total_consistency_lock.write().unwrap();

		write_ver_prefix!(writer, SERIALIZATION_VERSION, MIN_SERIALIZATION_VERSION);

		self.chain_hash.write(writer)?;
		{
			let best_block = self.best_block.read().unwrap();
			best_block.height.write(writer)?;
			best_block.block_hash.write(writer)?;
		}

		let per_peer_state = self.per_peer_state.write().unwrap();

		let mut serializable_peer_count: u64 = 0;
		{
			let mut number_of_funded_channels = 0;
			for (_, peer_state_mutex) in per_peer_state.iter() {
				let mut peer_state_lock = peer_state_mutex.lock().unwrap();
				let peer_state = &mut *peer_state_lock;
				if !peer_state.ok_to_remove(false) {
					serializable_peer_count += 1;
				}

				number_of_funded_channels += peer_state.channel_by_id
					.values()
					.filter_map(Channel::as_funded)
					.filter(|chan| chan.context.can_resume_on_restart())
					.count();
			}

			(number_of_funded_channels as u64).write(writer)?;

			for (_, peer_state_mutex) in per_peer_state.iter() {
				let mut peer_state_lock = peer_state_mutex.lock().unwrap();
				let peer_state = &mut *peer_state_lock;
				for channel in peer_state.channel_by_id
					.values()
					.filter_map(Channel::as_funded)
					.filter(|channel| channel.context.can_resume_on_restart())
				{
					channel.write(writer)?;
				}
			}
		}

		{
			let forward_htlcs = self.forward_htlcs.lock().unwrap();
			(forward_htlcs.len() as u64).write(writer)?;
			for (short_channel_id, pending_forwards) in forward_htlcs.iter() {
				short_channel_id.write(writer)?;
				(pending_forwards.len() as u64).write(writer)?;
				for forward in pending_forwards {
					forward.write(writer)?;
				}
			}
		}

		let mut decode_update_add_htlcs_opt = None;
		let decode_update_add_htlcs = self.decode_update_add_htlcs.lock().unwrap();
		if !decode_update_add_htlcs.is_empty() {
			decode_update_add_htlcs_opt = Some(decode_update_add_htlcs);
		}

		let claimable_payments = self.claimable_payments.lock().unwrap();
		let pending_outbound_payments = self.pending_outbound_payments.pending_outbound_payments.lock().unwrap();

		let mut htlc_purposes: Vec<&events::PaymentPurpose> = Vec::new();
		let mut htlc_onion_fields: Vec<&_> = Vec::new();
		(claimable_payments.claimable_payments.len() as u64).write(writer)?;
		for (payment_hash, payment) in claimable_payments.claimable_payments.iter() {
			payment_hash.write(writer)?;
			(payment.htlcs.len() as u64).write(writer)?;
			for htlc in payment.htlcs.iter() {
				htlc.write(writer)?;
			}
			htlc_purposes.push(&payment.purpose);
			htlc_onion_fields.push(&payment.onion_fields);
		}

		let mut monitor_update_blocked_actions_per_peer = None;
		let mut peer_states = Vec::new();
		for (_, peer_state_mutex) in per_peer_state.iter() {
			// Because we're holding the owning `per_peer_state` write lock here there's no chance
			// of a lockorder violation deadlock - no other thread can be holding any
			// per_peer_state lock at all.
			peer_states.push(peer_state_mutex.unsafe_well_ordered_double_lock_self());
		}

		let mut peer_storage_dir: Vec<(&PublicKey, &Vec<u8>)> = Vec::new();

		(serializable_peer_count).write(writer)?;
		for ((peer_pubkey, _), peer_state) in per_peer_state.iter().zip(peer_states.iter()) {
			// Peers which we have no channels to should be dropped once disconnected. As we
			// disconnect all peers when shutting down and serializing the ChannelManager, we
			// consider all peers as disconnected here. There's therefore no need write peers with
			// no channels.
			if !peer_state.ok_to_remove(false) {
				peer_pubkey.write(writer)?;
				peer_state.latest_features.write(writer)?;
				peer_storage_dir.push((peer_pubkey, &peer_state.peer_storage));

				if !peer_state.monitor_update_blocked_actions.is_empty() {
					monitor_update_blocked_actions_per_peer
						.get_or_insert_with(Vec::new)
						.push((*peer_pubkey, &peer_state.monitor_update_blocked_actions));
				}
			}
		}

		let our_pending_intercepts = self.pending_intercepted_htlcs.lock().unwrap();

		// Since some FundingNegotiation variants are not persisted, any splice in such state must
		// be failed upon reload. However, as the necessary information for the SpliceFailed event
		// is not persisted, the event itself needs to be persisted even though it hasn't been
		// emitted yet. These are removed after the events are written.
		let mut events = self.pending_events.lock().unwrap();
		let event_count = events.len();
		for peer_state in peer_states.iter() {
			for chan in peer_state.channel_by_id.values().filter_map(Channel::as_funded) {
				if let Some(splice_funding_failed) = chan.maybe_splice_funding_failed() {
					events.push_back((
						events::Event::SpliceFailed {
							channel_id: chan.context.channel_id(),
							counterparty_node_id: chan.context.get_counterparty_node_id(),
							user_channel_id: chan.context.get_user_id(),
							abandoned_funding_txo: splice_funding_failed.funding_txo,
							channel_type: splice_funding_failed.channel_type,
							contributed_inputs: splice_funding_failed.contributed_inputs,
							contributed_outputs: splice_funding_failed.contributed_outputs,
						},
						None,
					));
				}
			}
		}

		// LDK versions prior to 0.0.115 don't support post-event actions, thus if there's no
		// actions at all, skip writing the required TLV. Otherwise, pre-0.0.115 versions will
		// refuse to read the new ChannelManager.
		let events_not_backwards_compatible = events.iter().any(|(_, action)| action.is_some());
		if events_not_backwards_compatible {
			// If we're gonna write a even TLV that will overwrite our events anyway we might as
			// well save the space and not write any events here.
			0u64.write(writer)?;
		} else {
			(events.len() as u64).write(writer)?;
			for (event, _) in events.iter() {
				event.write(writer)?;
			}
		}

		// LDK versions prior to 0.0.116 wrote the `pending_background_events`
		// `MonitorUpdateRegeneratedOnStartup`s here, however there was never a reason to do so -
		// the closing monitor updates were always effectively replayed on startup (either directly
		// by calling `broadcast_latest_holder_commitment_txn` on a `ChannelMonitor` during
		// deserialization or, in 0.0.115, by regenerating the monitor update itself).
		0u64.write(writer)?;

		// Prior to 0.0.111 we tracked node_announcement serials here, however that now happens in
		// `PeerManager`, and thus we simply write the `highest_seen_timestamp` twice, which is
		// likely to be identical.
		(self.highest_seen_timestamp.load(Ordering::Acquire) as u32).write(writer)?;
		(self.highest_seen_timestamp.load(Ordering::Acquire) as u32).write(writer)?;

		// LDK versions prior to 0.0.104 wrote `pending_inbound_payments` here, with deprecated support
		// for stateful inbound payments maintained until 0.0.116, after which no further inbound
		// payments could have been written here.
		(0 as u64).write(writer)?;

		// For backwards compat, write the session privs and their total length.
		let mut num_pending_outbounds_compat: u64 = 0;
		for (_, outbound) in pending_outbound_payments.iter() {
			if !outbound.is_fulfilled() && !outbound.abandoned() {
				num_pending_outbounds_compat += outbound.remaining_parts() as u64;
			}
		}
		num_pending_outbounds_compat.write(writer)?;
		for (_, outbound) in pending_outbound_payments.iter() {
			match outbound {
				PendingOutboundPayment::Legacy { session_privs } |
				PendingOutboundPayment::Retryable { session_privs, .. } => {
					for session_priv in session_privs.iter() {
						session_priv.write(writer)?;
					}
				}
				PendingOutboundPayment::AwaitingInvoice { .. } => {},
				PendingOutboundPayment::AwaitingOffer { .. } => {},
				PendingOutboundPayment::InvoiceReceived { .. } => {},
				PendingOutboundPayment::StaticInvoiceReceived { .. } => {},
				PendingOutboundPayment::Fulfilled { .. } => {},
				PendingOutboundPayment::Abandoned { .. } => {},
			}
		}

		// Encode without retry info for 0.0.101 compatibility.
		let mut pending_outbound_payments_no_retry: HashMap<PaymentId, HashSet<[u8; 32]>> = new_hash_map();
		for (id, outbound) in pending_outbound_payments.iter() {
			match outbound {
				PendingOutboundPayment::Legacy { session_privs } |
				PendingOutboundPayment::Retryable { session_privs, .. } => {
					pending_outbound_payments_no_retry.insert(*id, session_privs.clone());
				},
				_ => {},
			}
		}

		let mut pending_intercepted_htlcs = None;
		if our_pending_intercepts.len() != 0 {
			pending_intercepted_htlcs = Some(our_pending_intercepts);
		}

		let mut pending_claiming_payments = Some(&claimable_payments.pending_claiming_payments);
		if pending_claiming_payments.as_ref().unwrap().is_empty() {
			// LDK versions prior to 0.0.113 do not know how to read the pending claimed payments
			// map. Thus, if there are no entries we skip writing a TLV for it.
			pending_claiming_payments = None;
		}

		let mut legacy_in_flight_monitor_updates: Option<HashMap<(&PublicKey, &OutPoint), &Vec<ChannelMonitorUpdate>>> = None;
		let mut in_flight_monitor_updates: Option<HashMap<(&PublicKey, &ChannelId), &Vec<ChannelMonitorUpdate>>> = None;
		for ((counterparty_id, _), peer_state) in per_peer_state.iter().zip(peer_states.iter()) {
			for (channel_id, (funding_txo, updates)) in peer_state.in_flight_monitor_updates.iter() {
				if !updates.is_empty() {
					legacy_in_flight_monitor_updates.get_or_insert_with(|| new_hash_map())
						.insert((counterparty_id, funding_txo), updates);
					in_flight_monitor_updates.get_or_insert_with(|| new_hash_map())
						.insert((counterparty_id, channel_id), updates);
				}
			}
		}

		write_tlv_fields!(writer, {
			(1, pending_outbound_payments_no_retry, required),
			(2, pending_intercepted_htlcs, option),
			(3, pending_outbound_payments, required),
			(4, pending_claiming_payments, option),
			(5, self.our_network_pubkey, required),
			(6, monitor_update_blocked_actions_per_peer, option),
			(7, self.fake_scid_rand_bytes, required),
			(8, if events_not_backwards_compatible { Some(&*events) } else { None }, option),
			(9, htlc_purposes, required_vec),
			(10, legacy_in_flight_monitor_updates, option),
			(11, self.probing_cookie_secret, required),
			(13, htlc_onion_fields, optional_vec),
			(14, decode_update_add_htlcs_opt, option),
			(15, self.inbound_payment_id_secret, required),
			(17, in_flight_monitor_updates, option),
			(19, peer_storage_dir, optional_vec),
			(21, WithoutLength(&self.flow.writeable_async_receive_offer_cache()), required),
		});

		// Remove the SpliceFailed events added earlier.
		events.truncate(event_count);

		Ok(())
	}
}

impl Writeable for VecDeque<(Event, Option<EventCompletionAction>)> {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		(self.len() as u64).write(w)?;
		for (event, action) in self.iter() {
			event.write(w)?;
			action.write(w)?;
			#[cfg(debug_assertions)]
			{
				// Events are MaybeReadable, in some cases indicating that they shouldn't actually
				// be persisted and are regenerated on restart. However, if such an event has a
				// post-event-handling action we'll write nothing for the event and would have to
				// either forget the action or fail on deserialization (which we do below). Thus,
				// check that the event is sane here.
				let event_encoded = event.encode();
				let event_read: Option<Event> =
					MaybeReadable::read(&mut &event_encoded[..]).unwrap();
				if action.is_some() {
					assert!(event_read.is_some());
				}
			}
		}
		Ok(())
	}
}
impl Readable for VecDeque<(Event, Option<EventCompletionAction>)> {
	fn read<R: Read>(reader: &mut R) -> Result<Self, DecodeError> {
		let len: u64 = Readable::read(reader)?;
		const MAX_ALLOC_SIZE: u64 = 1024 * 16;
		let event_size = mem::size_of::<(events::Event, Option<EventCompletionAction>)>();
		let mut events: Self =
			VecDeque::with_capacity(cmp::min(MAX_ALLOC_SIZE / event_size as u64, len) as usize);
		for _ in 0..len {
			let ev_opt = MaybeReadable::read(reader)?;
			let action = Readable::read(reader)?;
			if let Some(ev) = ev_opt {
				events.push_back((ev, action));
			} else if action.is_some() {
				return Err(DecodeError::InvalidValue);
			}
		}
		Ok(events)
	}
}

// Raw deserialized data from a ChannelManager, before validation or reconstruction.
// This is an internal DTO used in the two-stage deserialization process.
pub(super) struct ChannelManagerData<SP: SignerProvider> {
	chain_hash: ChainHash,
	best_block_height: u32,
	best_block_hash: BlockHash,
	channels: Vec<FundedChannel<SP>>,
	claimable_payments: HashMap<PaymentHash, ClaimablePayment>,
	peer_init_features: Vec<(PublicKey, InitFeatures)>,
	pending_events_read: VecDeque<(events::Event, Option<EventCompletionAction>)>,
	highest_seen_timestamp: u32,
	pending_outbound_payments: HashMap<PaymentId, PendingOutboundPayment>,
	pending_claiming_payments: HashMap<PaymentHash, ClaimingPayment>,
	received_network_pubkey: Option<PublicKey>,
	monitor_update_blocked_actions_per_peer:
		Vec<(PublicKey, BTreeMap<ChannelId, Vec<MonitorUpdateCompletionAction>>)>,
	fake_scid_rand_bytes: Option<[u8; 32]>,
	probing_cookie_secret: Option<[u8; 32]>,
	inbound_payment_id_secret: Option<[u8; 32]>,
	in_flight_monitor_updates: HashMap<(PublicKey, ChannelId), Vec<ChannelMonitorUpdate>>,
	peer_storage_dir: Vec<(PublicKey, Vec<u8>)>,
	async_receive_offer_cache: AsyncReceiveOfferCache,
	// Marked `_legacy` because in versions > 0.2 we are taking steps to remove the requirement of
	// regularly persisting the `ChannelManager` and instead rebuild the set of HTLC forwards from
	// `Channel{Monitor}` data.
	forward_htlcs_legacy: HashMap<u64, Vec<HTLCForwardInfo>>,
	pending_intercepted_htlcs_legacy: HashMap<InterceptId, PendingAddHTLCInfo>,
	decode_update_add_htlcs_legacy: HashMap<u64, Vec<msgs::UpdateAddHTLC>>,
	// The `ChannelManager` version that was written.
	version: u8,
}

/// Arguments for deserializing [`ChannelManagerData`].
struct ChannelManagerDataReadArgs<
	'a,
	ES: EntropySource,
	NS: NodeSigner,
	SP: SignerProvider,
	L: Logger,
> {
	entropy_source: &'a ES,
	node_signer: &'a NS,
	signer_provider: &'a SP,
	config: UserConfig,
	logger: &'a L,
}

impl<'a, ES: EntropySource, NS: NodeSigner, SP: SignerProvider, L: Logger>
	ReadableArgs<ChannelManagerDataReadArgs<'a, ES, NS, SP, L>> for ChannelManagerData<SP>
{
	fn read<R: io::Read>(
		reader: &mut R, args: ChannelManagerDataReadArgs<'a, ES, NS, SP, L>,
	) -> Result<Self, DecodeError> {
		let version = read_ver_prefix!(reader, SERIALIZATION_VERSION);

		let chain_hash: ChainHash = Readable::read(reader)?;
		let best_block_height: u32 = Readable::read(reader)?;
		let best_block_hash: BlockHash = Readable::read(reader)?;

		const MAX_ALLOC_SIZE: usize = 1024 * 64;

		let channel_count: u64 = Readable::read(reader)?;
		let mut channels = Vec::with_capacity(cmp::min(channel_count as usize, 128));
		for _ in 0..channel_count {
			let channel: FundedChannel<SP> = FundedChannel::read(
				reader,
				(
					args.entropy_source,
					args.signer_provider,
					&provided_channel_type_features(&args.config),
				),
			)?;
			channels.push(channel);
		}

		let forward_htlcs_legacy: HashMap<u64, Vec<HTLCForwardInfo>> =
			if version < RECONSTRUCT_HTLCS_FROM_CHANS_VERSION {
				let forward_htlcs_count: u64 = Readable::read(reader)?;
				let mut fwds = hash_map_with_capacity(cmp::min(forward_htlcs_count as usize, 128));
				for _ in 0..forward_htlcs_count {
					let short_channel_id = Readable::read(reader)?;
					let pending_forwards_count: u64 = Readable::read(reader)?;
					let mut pending_forwards = Vec::with_capacity(cmp::min(
						pending_forwards_count as usize,
						MAX_ALLOC_SIZE / mem::size_of::<HTLCForwardInfo>(),
					));
					for _ in 0..pending_forwards_count {
						pending_forwards.push(Readable::read(reader)?);
					}
					fwds.insert(short_channel_id, pending_forwards);
				}
				fwds
			} else {
				new_hash_map()
			};

		let claimable_htlcs_count: u64 = Readable::read(reader)?;
		let mut claimable_htlcs_list =
			Vec::with_capacity(cmp::min(claimable_htlcs_count as usize, 128));
		for _ in 0..claimable_htlcs_count {
			let payment_hash = Readable::read(reader)?;
			let previous_hops_len: u64 = Readable::read(reader)?;
			let mut previous_hops = Vec::with_capacity(cmp::min(
				previous_hops_len as usize,
				MAX_ALLOC_SIZE / mem::size_of::<ClaimableHTLC>(),
			));
			for _ in 0..previous_hops_len {
				previous_hops.push(<ClaimableHTLC as Readable>::read(reader)?);
			}
			claimable_htlcs_list.push((payment_hash, previous_hops));
		}

		let peer_count: u64 = Readable::read(reader)?;
		let mut peer_init_features = Vec::with_capacity(cmp::min(peer_count as usize, 128));
		for _ in 0..peer_count {
			let peer_pubkey: PublicKey = Readable::read(reader)?;
			let latest_features = Readable::read(reader)?;
			peer_init_features.push((peer_pubkey, latest_features));
		}

		let event_count: u64 = Readable::read(reader)?;
		let mut pending_events_read: VecDeque<(events::Event, Option<EventCompletionAction>)> =
			VecDeque::with_capacity(cmp::min(
				event_count as usize,
				MAX_ALLOC_SIZE / mem::size_of::<(events::Event, Option<EventCompletionAction>)>(),
			));
		for _ in 0..event_count {
			match MaybeReadable::read(reader)? {
				Some(event) => pending_events_read.push_back((event, None)),
				None => continue,
			}
		}

		let background_event_count: u64 = Readable::read(reader)?;
		for _ in 0..background_event_count {
			match <u8 as Readable>::read(reader)? {
				0 => {
					// LDK versions prior to 0.0.116 wrote pending `MonitorUpdateRegeneratedOnStartup`s here,
					// however we really don't (and never did) need them - we regenerate all
					// on-startup monitor updates.
					let _: OutPoint = Readable::read(reader)?;
					let _: ChannelMonitorUpdate = Readable::read(reader)?;
				},
				_ => return Err(DecodeError::InvalidValue),
			}
		}

		let _last_node_announcement_serial: u32 = Readable::read(reader)?; // Only used < 0.0.111
		let highest_seen_timestamp: u32 = Readable::read(reader)?;

		// The last version where a pending inbound payment may have been added was 0.0.116.
		let pending_inbound_payment_count: u64 = Readable::read(reader)?;
		for _ in 0..pending_inbound_payment_count {
			let payment_hash: PaymentHash = Readable::read(reader)?;
			let logger = WithContext::from(args.logger, None, None, Some(payment_hash));
			let inbound: PendingInboundPayment = Readable::read(reader)?;
			log_warn!(
				logger,
				"Ignoring deprecated pending inbound payment with payment hash {}: {:?}",
				payment_hash,
				inbound
			);
		}

		let pending_outbound_payments_count_compat: u64 = Readable::read(reader)?;
		let mut pending_outbound_payments_compat: HashMap<PaymentId, PendingOutboundPayment> =
			hash_map_with_capacity(cmp::min(
				pending_outbound_payments_count_compat as usize,
				MAX_ALLOC_SIZE / 32,
			));
		for _ in 0..pending_outbound_payments_count_compat {
			let session_priv = Readable::read(reader)?;
			let payment = PendingOutboundPayment::Legacy {
				session_privs: hash_set_from_iter([session_priv]),
			};
			if pending_outbound_payments_compat.insert(PaymentId(session_priv), payment).is_some() {
				return Err(DecodeError::InvalidValue);
			};
		}

		let mut pending_intercepted_htlcs_legacy: Option<HashMap<InterceptId, PendingAddHTLCInfo>> =
			None;
		let mut decode_update_add_htlcs_legacy: Option<HashMap<u64, Vec<msgs::UpdateAddHTLC>>> =
			None;
		// pending_outbound_payments_no_retry is for compatibility with 0.0.101 clients.
		let mut pending_outbound_payments_no_retry: Option<HashMap<PaymentId, HashSet<[u8; 32]>>> =
			None;
		let mut pending_outbound_payments = None;
		let mut received_network_pubkey: Option<PublicKey> = None;
		let mut fake_scid_rand_bytes: Option<[u8; 32]> = None;
		let mut probing_cookie_secret: Option<[u8; 32]> = None;
		let mut claimable_htlc_purposes = None;
		let mut claimable_htlc_onion_fields = None;
		let mut pending_claiming_payments = None;
		let mut monitor_update_blocked_actions_per_peer: Option<Vec<(_, BTreeMap<_, Vec<_>>)>> =
			None;
		let mut events_override = None;
		let mut legacy_in_flight_monitor_updates: Option<
			HashMap<(PublicKey, OutPoint), Vec<ChannelMonitorUpdate>>,
		> = None;
		// We use this one over the legacy since they represent the same data, just with a different
		// key. We still need to read the legacy one as it's an even TLV.
		let mut in_flight_monitor_updates: Option<
			HashMap<(PublicKey, ChannelId), Vec<ChannelMonitorUpdate>>,
		> = None;
		let mut inbound_payment_id_secret = None;
		let mut peer_storage_dir: Option<Vec<(PublicKey, Vec<u8>)>> = None;
		let mut async_receive_offer_cache: AsyncReceiveOfferCache = AsyncReceiveOfferCache::new();
		read_tlv_fields!(reader, {
			(1, pending_outbound_payments_no_retry, option),
			(2, pending_intercepted_htlcs_legacy, option),
			(3, pending_outbound_payments, option),
			(4, pending_claiming_payments, option),
			(5, received_network_pubkey, option),
			(6, monitor_update_blocked_actions_per_peer, option),
			(7, fake_scid_rand_bytes, option),
			(8, events_override, option),
			(9, claimable_htlc_purposes, optional_vec),
			(10, legacy_in_flight_monitor_updates, option),
			(11, probing_cookie_secret, option),
			(13, claimable_htlc_onion_fields, optional_vec),
			(14, decode_update_add_htlcs_legacy, option),
			(15, inbound_payment_id_secret, option),
			(17, in_flight_monitor_updates, option),
			(19, peer_storage_dir, optional_vec),
			(21, async_receive_offer_cache, (default_value, async_receive_offer_cache)),
		});

		// Merge legacy pending_outbound_payments fields into a single HashMap.
		// Priority: pending_outbound_payments (TLV 3) > pending_outbound_payments_no_retry (TLV 1)
		//           > pending_outbound_payments_compat (non-TLV legacy)
		let pending_outbound_payments = pending_outbound_payments
			.or_else(|| {
				pending_outbound_payments_no_retry.map(|no_retry| {
					no_retry
						.into_iter()
						.map(|(id, session_privs)| {
							(id, PendingOutboundPayment::Legacy { session_privs })
						})
						.collect()
				})
			})
			.unwrap_or(pending_outbound_payments_compat);

		// Merge legacy in-flight monitor updates (keyed by OutPoint) into the new format (keyed by
		// ChannelId).
		if let Some(legacy_in_flight_upds) = legacy_in_flight_monitor_updates {
			// We should never serialize an empty map.
			if legacy_in_flight_upds.is_empty() {
				return Err(DecodeError::InvalidValue);
			}
			match &in_flight_monitor_updates {
				None => {
					// Convert legacy format (OutPoint) to new format (ChannelId).
					// All channels with legacy in flight monitor updates are v1 channels.
					in_flight_monitor_updates = Some(
						legacy_in_flight_upds
							.into_iter()
							.map(|((counterparty_node_id, funding_txo), updates)| {
								let channel_id = ChannelId::v1_from_funding_outpoint(funding_txo);
								((counterparty_node_id, channel_id), updates)
							})
							.collect(),
					);
				},
				Some(upds) if upds.is_empty() => {
					// Both TLVs present but new one is empty - invalid.
					return Err(DecodeError::InvalidValue);
				},
				Some(_) => {}, // New format takes precedence, nothing to do.
			}
		}

		// Resolve events_override: if present, it replaces pending_events.
		let pending_events_read = events_override.unwrap_or(pending_events_read);

		// Combine claimable_htlcs_list with their purposes and onion fields. For very old data
		// (pre-0.0.107) that lacks purposes, reconstruct them from legacy hop data.
		let expanded_inbound_key = args.node_signer.get_expanded_key();

		let mut claimable_payments = hash_map_with_capacity(claimable_htlcs_list.len());
		if let Some(purposes) = claimable_htlc_purposes {
			if purposes.len() != claimable_htlcs_list.len() {
				return Err(DecodeError::InvalidValue);
			}
			if let Some(onion_fields) = claimable_htlc_onion_fields {
				if onion_fields.len() != claimable_htlcs_list.len() {
					return Err(DecodeError::InvalidValue);
				}
				for (purpose, (onion, (payment_hash, htlcs))) in purposes
					.into_iter()
					.zip(onion_fields.into_iter().zip(claimable_htlcs_list.into_iter()))
				{
					let claimable = ClaimablePayment { purpose, htlcs, onion_fields: onion };
					let existing_payment = claimable_payments.insert(payment_hash, claimable);
					if existing_payment.is_some() {
						return Err(DecodeError::InvalidValue);
					}
				}
			} else {
				for (purpose, (payment_hash, htlcs)) in
					purposes.into_iter().zip(claimable_htlcs_list.into_iter())
				{
					let claimable = ClaimablePayment { purpose, htlcs, onion_fields: None };
					let existing_payment = claimable_payments.insert(payment_hash, claimable);
					if existing_payment.is_some() {
						return Err(DecodeError::InvalidValue);
					}
				}
			}
		} else {
			// LDK versions prior to 0.0.107 did not write a `pending_htlc_purposes`, but do
			// include a `_legacy_hop_data` in the `OnionPayload`.
			for (payment_hash, htlcs) in claimable_htlcs_list.into_iter() {
				if htlcs.is_empty() {
					return Err(DecodeError::InvalidValue);
				}
				let purpose = match &htlcs[0].onion_payload {
					OnionPayload::Invoice { _legacy_hop_data } => {
						if let Some(hop_data) = _legacy_hop_data {
							events::PaymentPurpose::Bolt11InvoicePayment {
								payment_preimage: match inbound_payment::verify(
									payment_hash,
									&hop_data,
									0,
									&expanded_inbound_key,
									&args.logger,
								) {
									Ok((payment_preimage, _)) => payment_preimage,
									Err(()) => {
										log_error!(args.logger, "Failed to read claimable payment data for HTLC with payment hash {} - was not a pending inbound payment and didn't match our payment key", &payment_hash);
										return Err(DecodeError::InvalidValue);
									},
								},
								payment_secret: hop_data.payment_secret,
							}
						} else {
							return Err(DecodeError::InvalidValue);
						}
					},
					OnionPayload::Spontaneous(payment_preimage) => {
						events::PaymentPurpose::SpontaneousPayment(*payment_preimage)
					},
				};
				claimable_payments
					.insert(payment_hash, ClaimablePayment { purpose, htlcs, onion_fields: None });
			}
		}

		Ok(ChannelManagerData {
			chain_hash,
			best_block_height,
			best_block_hash,
			channels,
			forward_htlcs_legacy,
			claimable_payments,
			peer_init_features,
			pending_events_read,
			highest_seen_timestamp,
			pending_intercepted_htlcs_legacy: pending_intercepted_htlcs_legacy
				.unwrap_or_else(new_hash_map),
			pending_outbound_payments,
			pending_claiming_payments: pending_claiming_payments.unwrap_or_else(new_hash_map),
			received_network_pubkey,
			monitor_update_blocked_actions_per_peer: monitor_update_blocked_actions_per_peer
				.unwrap_or_else(Vec::new),
			fake_scid_rand_bytes,
			probing_cookie_secret,
			decode_update_add_htlcs_legacy: decode_update_add_htlcs_legacy
				.unwrap_or_else(new_hash_map),
			inbound_payment_id_secret,
			in_flight_monitor_updates: in_flight_monitor_updates.unwrap_or_default(),
			peer_storage_dir: peer_storage_dir.unwrap_or_default(),
			async_receive_offer_cache,
			version,
		})
	}
}

/// Arguments for the creation of a ChannelManager that are not deserialized.
///
/// At a high-level, the process for deserializing a ChannelManager and resuming normal operation
/// is:
/// 1) Deserialize all stored [`ChannelMonitor`]s.
/// 2) Deserialize the [`ChannelManager`] by filling in this struct and calling:
///    `<(BlockHash, ChannelManager)>::read(reader, args)`
///    This may result in closing some channels if the [`ChannelMonitor`] is newer than the stored
///    [`ChannelManager`] state to ensure no loss of funds. Thus, transactions may be broadcasted.
/// 3) If you are not fetching full blocks, register all relevant [`ChannelMonitor`] outpoints the
///    same way you would handle a [`chain::Filter`] call using
///    [`ChannelMonitor::get_outputs_to_watch`] and [`ChannelMonitor::get_funding_txo`].
/// 4) Disconnect/connect blocks on your [`ChannelMonitor`]s to get them in sync with the chain.
/// 5) Disconnect/connect blocks on the [`ChannelManager`] to get it in sync with the chain.
/// 6) Optionally re-persist the [`ChannelMonitor`]s to ensure the latest state is on disk.
///    This is important if you have replayed a nontrivial number of blocks in step (4), allowing
///    you to avoid having to replay the same blocks if you shut down quickly after startup. It is
///    otherwise not required.
///
///    Note that if you're using a [`ChainMonitor`] for your [`chain::Watch`] implementation, you
///    will likely accomplish this as a side-effect of calling [`chain::Watch::watch_channel`] in
///    the next step.
///
///    If you wish to avoid this for performance reasons, use
///    [`ChainMonitor::load_existing_monitor`].
/// 7) Move the [`ChannelMonitor`]s into your local [`chain::Watch`]. If you're using a
///    [`ChainMonitor`], this is done by calling [`chain::Watch::watch_channel`].
///
/// Note that the ordering of #4-7 is not of importance, however all four must occur before you
/// call any other methods on the newly-deserialized [`ChannelManager`].
///
/// Note that because some channels may be closed during deserialization, it is critical that you
/// always deserialize only the latest version of a ChannelManager and ChannelMonitors available to
/// you. If you deserialize an old ChannelManager (during which force-closure transactions may be
/// broadcast), and then later deserialize a newer version of the same ChannelManager (which will
/// not force-close the same channels but consider them live), you may end up revoking a state for
/// which you've already broadcasted the transaction.
///
/// [`ChainMonitor`]: crate::chain::chainmonitor::ChainMonitor
/// [`ChainMonitor::load_existing_monitor`]: crate::chain::chainmonitor::ChainMonitor::load_existing_monitor
pub struct ChannelManagerReadArgs<
	'a,
	M: chain::Watch<SP::EcdsaSigner>,
	T: BroadcasterInterface,
	ES: EntropySource,
	NS: NodeSigner,
	SP: SignerProvider,
	F: FeeEstimator,
	R: Router,
	MR: MessageRouter,
	L: Logger + Clone,
> {
	/// A cryptographically secure source of entropy.
	pub entropy_source: ES,

	/// A signer that is able to perform node-scoped cryptographic operations.
	pub node_signer: NS,

	/// The keys provider which will give us relevant keys. Some keys will be loaded during
	/// deserialization and [`SignerProvider::derive_channel_signer`] will be used to derive
	/// per-Channel signing data.
	pub signer_provider: SP,

	/// The fee_estimator for use in the ChannelManager in the future.
	///
	/// No calls to the FeeEstimator will be made during deserialization.
	pub fee_estimator: F,
	/// The chain::Watch for use in the ChannelManager in the future.
	///
	/// No calls to the chain::Watch will be made during deserialization. It is assumed that
	/// you have deserialized ChannelMonitors separately and will add them to your
	/// chain::Watch after deserializing this ChannelManager.
	pub chain_monitor: M,

	/// The BroadcasterInterface which will be used in the ChannelManager in the future and may be
	/// used to broadcast the latest local commitment transactions of channels which must be
	/// force-closed during deserialization.
	pub tx_broadcaster: T,
	/// The router which will be used in the ChannelManager in the future for finding routes
	/// on-the-fly for trampoline payments. Absent in private nodes that don't support forwarding.
	///
	/// No calls to the router will be made during deserialization.
	pub router: R,
	/// The [`MessageRouter`] used for constructing [`BlindedMessagePath`]s for [`Offer`]s,
	/// [`Refund`]s, and any reply paths.
	///
	/// [`BlindedMessagePath`]: crate::blinded_path::message::BlindedMessagePath
	pub message_router: MR,
	/// The Logger for use in the ChannelManager and which may be used to log information during
	/// deserialization.
	pub logger: L,
	/// Default settings used for new channels. Any existing channels will continue to use the
	/// runtime settings which were stored when the ChannelManager was serialized.
	pub config: UserConfig,

	/// A map from channel IDs to ChannelMonitors for those channels.
	///
	/// If a monitor is inconsistent with the channel state during deserialization the channel will
	/// be force-closed using the data in the ChannelMonitor and the channel will be dropped. This
	/// is true for missing channels as well. If there is a monitor missing for which we find
	/// channel data Err(DecodeError::InvalidValue) will be returned.
	///
	/// In such cases the latest local transactions will be sent to the tx_broadcaster included in
	/// this struct.
	///
	/// This is not exported to bindings users because we have no HashMap bindings
	pub channel_monitors: HashMap<ChannelId, &'a ChannelMonitor<SP::EcdsaSigner>>,

	/// Whether the `ChannelManager` should attempt to reconstruct its set of pending HTLCs from
	/// `Channel{Monitor}` data rather than its own persisted maps, which is planned to become
	/// the default behavior in upcoming versions.
	///
	/// If `None`, whether we reconstruct or use the legacy maps will be decided randomly during
	/// `ChannelManager::from_channel_manager_data`.
	#[cfg(test)]
	pub reconstruct_manager_from_monitors: Option<bool>,
}

impl<
		'a,
		M: chain::Watch<SP::EcdsaSigner>,
		T: BroadcasterInterface,
		ES: EntropySource,
		NS: NodeSigner,
		SP: SignerProvider,
		F: FeeEstimator,
		R: Router,
		MR: MessageRouter,
		L: Logger + Clone,
	> ChannelManagerReadArgs<'a, M, T, ES, NS, SP, F, R, MR, L>
{
	/// Simple utility function to create a ChannelManagerReadArgs which creates the monitor
	/// HashMap for you. This is primarily useful for C bindings where it is not practical to
	/// populate a HashMap directly from C.
	pub fn new(
		entropy_source: ES, node_signer: NS, signer_provider: SP, fee_estimator: F,
		chain_monitor: M, tx_broadcaster: T, router: R, message_router: MR, logger: L,
		config: UserConfig, mut channel_monitors: Vec<&'a ChannelMonitor<SP::EcdsaSigner>>,
	) -> Self {
		Self {
			entropy_source,
			node_signer,
			signer_provider,
			fee_estimator,
			chain_monitor,
			tx_broadcaster,
			router,
			message_router,
			logger,
			config,
			channel_monitors: hash_map_from_iter(
				channel_monitors.drain(..).map(|monitor| (monitor.channel_id(), monitor)),
			),
			#[cfg(test)]
			reconstruct_manager_from_monitors: None,
		}
	}
}

// If the HTLC corresponding to `prev_hop_data` is present in `decode_update_add_htlcs`, remove it
// from the map as it is already being stored and processed elsewhere.
fn dedup_decode_update_add_htlcs<L: Logger>(
	decode_update_add_htlcs: &mut HashMap<u64, Vec<msgs::UpdateAddHTLC>>,
	prev_hop_data: &HTLCPreviousHopData, removal_reason: &'static str, logger: &L,
) {
	match decode_update_add_htlcs.entry(prev_hop_data.prev_outbound_scid_alias) {
		hash_map::Entry::Occupied(mut update_add_htlcs) => {
			update_add_htlcs.get_mut().retain(|update_add| {
				let matches = update_add.htlc_id == prev_hop_data.htlc_id;
				if matches {
					let logger = WithContext::from(
						logger,
						prev_hop_data.counterparty_node_id,
						Some(update_add.channel_id),
						Some(update_add.payment_hash),
					);
					log_info!(
						logger,
						"Removing pending to-decode HTLC with id {}: {}",
						update_add.htlc_id,
						removal_reason
					);
				}
				!matches
			});
			if update_add_htlcs.get().is_empty() {
				update_add_htlcs.remove();
			}
		},
		_ => {},
	}
}

// Implement ReadableArgs for an Arc'd ChannelManager to make it a bit easier to work with the
// SipmleArcChannelManager type:
impl<
		'a,
		M: chain::Watch<SP::EcdsaSigner>,
		T: BroadcasterInterface,
		ES: EntropySource,
		NS: NodeSigner,
		SP: SignerProvider,
		F: FeeEstimator,
		R: Router,
		MR: MessageRouter,
		L: Logger + Clone,
	> ReadableArgs<ChannelManagerReadArgs<'a, M, T, ES, NS, SP, F, R, MR, L>>
	for (BlockHash, Arc<ChannelManager<M, T, ES, NS, SP, F, R, MR, L>>)
{
	fn read<Reader: io::Read>(
		reader: &mut Reader, args: ChannelManagerReadArgs<'a, M, T, ES, NS, SP, F, R, MR, L>,
	) -> Result<Self, DecodeError> {
		let (blockhash, chan_manager) =
			<(BlockHash, ChannelManager<M, T, ES, NS, SP, F, R, MR, L>)>::read(reader, args)?;
		Ok((blockhash, Arc::new(chan_manager)))
	}
}

impl<
		'a,
		M: chain::Watch<SP::EcdsaSigner>,
		T: BroadcasterInterface,
		ES: EntropySource,
		NS: NodeSigner,
		SP: SignerProvider,
		F: FeeEstimator,
		R: Router,
		MR: MessageRouter,
		L: Logger + Clone,
	> ReadableArgs<ChannelManagerReadArgs<'a, M, T, ES, NS, SP, F, R, MR, L>>
	for (BlockHash, ChannelManager<M, T, ES, NS, SP, F, R, MR, L>)
{
	fn read<Reader: io::Read>(
		reader: &mut Reader, args: ChannelManagerReadArgs<'a, M, T, ES, NS, SP, F, R, MR, L>,
	) -> Result<Self, DecodeError> {
		// Stage 1: Pure deserialization into DTO
		let data: ChannelManagerData<SP> = ChannelManagerData::read(
			reader,
			ChannelManagerDataReadArgs {
				entropy_source: &args.entropy_source,
				node_signer: &args.node_signer,
				signer_provider: &args.signer_provider,
				config: args.config.clone(),
				logger: &args.logger,
			},
		)?;

		// Stage 2: Validation and reconstruction
		ChannelManager::from_channel_manager_data(data, args)
	}
}

impl<
		M: chain::Watch<SP::EcdsaSigner>,
		T: BroadcasterInterface,
		ES: EntropySource,
		NS: NodeSigner,
		SP: SignerProvider,
		F: FeeEstimator,
		R: Router,
		MR: MessageRouter,
		L: Logger + Clone,
	> ChannelManager<M, T, ES, NS, SP, F, R, MR, L>
{
	/// Constructs a `ChannelManager` from deserialized data and runtime dependencies.
	///
	/// This is the second stage of deserialization, taking the raw [`ChannelManagerData`] and combining it with the
	/// provided [`ChannelManagerReadArgs`] to produce a fully functional `ChannelManager`.
	///
	/// This method performs validation, reconciliation with [`ChannelMonitor`]s, and reconstruction of internal state.
	/// It may close channels if monitors are ahead of the serialized state, and will replay any pending
	/// [`ChannelMonitorUpdate`]s.
	pub(super) fn from_channel_manager_data(
		data: ChannelManagerData<SP>,
		mut args: ChannelManagerReadArgs<'_, M, T, ES, NS, SP, F, R, MR, L>,
	) -> Result<(BlockHash, Self), DecodeError> {
		let ChannelManagerData {
			chain_hash,
			best_block_height,
			best_block_hash,
			channels,
			mut forward_htlcs_legacy,
			claimable_payments,
			peer_init_features,
			mut pending_events_read,
			highest_seen_timestamp,
			mut pending_intercepted_htlcs_legacy,
			pending_outbound_payments,
			pending_claiming_payments,
			received_network_pubkey,
			monitor_update_blocked_actions_per_peer,
			mut fake_scid_rand_bytes,
			mut probing_cookie_secret,
			mut decode_update_add_htlcs_legacy,
			mut inbound_payment_id_secret,
			mut in_flight_monitor_updates,
			peer_storage_dir,
			async_receive_offer_cache,
			version: _version,
		} = data;

		let empty_peer_state = || PeerState {
			channel_by_id: new_hash_map(),
			inbound_channel_request_by_id: new_hash_map(),
			latest_features: InitFeatures::empty(),
			pending_msg_events: Vec::new(),
			in_flight_monitor_updates: BTreeMap::new(),
			monitor_update_blocked_actions: BTreeMap::new(),
			actions_blocking_raa_monitor_updates: BTreeMap::new(),
			closed_channel_monitor_update_ids: BTreeMap::new(),
			peer_storage: Vec::new(),
			is_connected: false,
		};

		const MAX_ALLOC_SIZE: usize = 1024 * 64;
		let mut failed_htlcs = Vec::new();
		let channel_count = channels.len();
		let mut channel_id_set = hash_set_with_capacity(cmp::min(channel_count, 128));
		let mut per_peer_state = hash_map_with_capacity(cmp::min(
			channel_count,
			MAX_ALLOC_SIZE / mem::size_of::<(PublicKey, Mutex<PeerState<SP>>)>(),
		));
		let mut short_to_chan_info = hash_map_with_capacity(cmp::min(channel_count, 128));
		let mut channel_closures = VecDeque::new();
		let mut close_background_events = Vec::new();
		for mut channel in channels {
			let logger = WithChannelContext::from(&args.logger, &channel.context, None);
			let channel_id = channel.context.channel_id();
			channel_id_set.insert(channel_id);
			if let Some(ref mut monitor) = args.channel_monitors.get_mut(&channel_id) {
				if channel.get_cur_holder_commitment_transaction_number()
					> monitor.get_cur_holder_commitment_number()
					|| channel.get_revoked_counterparty_commitment_transaction_number()
						> monitor.get_min_seen_secret()
					|| channel.get_cur_counterparty_commitment_transaction_number()
						> monitor.get_cur_counterparty_commitment_number()
					|| channel.context.get_latest_monitor_update_id()
						< monitor.get_latest_update_id()
				{
					// But if the channel is behind of the monitor, close the channel:
					log_error!(
						logger,
						"A ChannelManager is stale compared to the current ChannelMonitor!"
					);
					log_error!(logger, " The channel will be force-closed and the latest commitment transaction from the ChannelMonitor broadcast.");
					if channel.context.get_latest_monitor_update_id()
						< monitor.get_latest_update_id()
					{
						log_error!(logger, " The ChannelMonitor is at update_id {} but the ChannelManager is at update_id {}.",
							monitor.get_latest_update_id(), channel.context.get_latest_monitor_update_id());
					}
					if channel.get_cur_holder_commitment_transaction_number()
						> monitor.get_cur_holder_commitment_number()
					{
						log_error!(logger, " The ChannelMonitor is at holder commitment number {} but the ChannelManager is at holder commitment number {}.",
							monitor.get_cur_holder_commitment_number(), channel.get_cur_holder_commitment_transaction_number());
					}
					if channel.get_revoked_counterparty_commitment_transaction_number()
						> monitor.get_min_seen_secret()
					{
						log_error!(logger, " The ChannelMonitor is at revoked counterparty transaction number {} but the ChannelManager is at revoked counterparty transaction number {}.",
							monitor.get_min_seen_secret(), channel.get_revoked_counterparty_commitment_transaction_number());
					}
					if channel.get_cur_counterparty_commitment_transaction_number()
						> monitor.get_cur_counterparty_commitment_number()
					{
						log_error!(logger, " The ChannelMonitor is at counterparty commitment transaction number {} but the ChannelManager is at counterparty commitment transaction number {}.",
							monitor.get_cur_counterparty_commitment_number(), channel.get_cur_counterparty_commitment_transaction_number());
					}
					let shutdown_result =
						channel.force_shutdown(ClosureReason::OutdatedChannelManager);
					if shutdown_result.unbroadcasted_batch_funding_txid.is_some() {
						return Err(DecodeError::InvalidValue);
					}
					if let Some((counterparty_node_id, funding_txo, channel_id, mut update)) =
						shutdown_result.monitor_update
					{
						// Our channel information is out of sync with the `ChannelMonitor`, so
						// force the update to use the `ChannelMonitor`'s update_id for the close
						// update.
						let latest_update_id = monitor.get_latest_update_id().saturating_add(1);
						update.update_id = latest_update_id;
						per_peer_state
							.entry(counterparty_node_id)
							.or_insert_with(|| Mutex::new(empty_peer_state()))
							.lock()
							.unwrap()
							.closed_channel_monitor_update_ids
							.entry(channel_id)
							.and_modify(|v| *v = cmp::max(latest_update_id, *v))
							.or_insert(latest_update_id);

						close_background_events.push(
							BackgroundEvent::MonitorUpdateRegeneratedOnStartup {
								counterparty_node_id,
								funding_txo,
								channel_id,
								update,
							},
						);
					}
					for (source, hash, cp_id, chan_id) in shutdown_result.dropped_outbound_htlcs {
						let reason = LocalHTLCFailureReason::ChannelClosed;
						failed_htlcs.push((source, hash, cp_id, chan_id, reason, None));
					}
					channel_closures.push_back((
						events::Event::ChannelClosed {
							channel_id: channel.context.channel_id(),
							user_channel_id: channel.context.get_user_id(),
							reason: ClosureReason::OutdatedChannelManager,
							counterparty_node_id: Some(channel.context.get_counterparty_node_id()),
							channel_capacity_sats: Some(channel.funding.get_value_satoshis()),
							channel_funding_txo: channel.funding.get_funding_txo(),
							last_local_balance_msat: Some(channel.funding.get_value_to_self_msat()),
						},
						None,
					));
					for (channel_htlc_source, payment_hash) in channel.inflight_htlc_sources() {
						let mut found_htlc = false;
						for (monitor_htlc_source, _) in monitor.get_all_current_outbound_htlcs() {
							if *channel_htlc_source == monitor_htlc_source {
								found_htlc = true;
								break;
							}
						}
						if !found_htlc {
							// If we have some HTLCs in the channel which are not present in the newer
							// ChannelMonitor, they have been removed and should be failed back to
							// ensure we don't forget them entirely. Note that if the missing HTLC(s)
							// were actually claimed we'd have generated and ensured the previous-hop
							// claim update ChannelMonitor updates were persisted prior to persising
							// the ChannelMonitor update for the forward leg, so attempting to fail the
							// backwards leg of the HTLC will simply be rejected.
							let logger = WithChannelContext::from(
								&args.logger,
								&channel.context,
								Some(*payment_hash),
							);
							log_info!(logger,
								"Failing HTLC as it is missing in the ChannelMonitor but was present in the (stale) ChannelManager");
							failed_htlcs.push((
								channel_htlc_source.clone(),
								*payment_hash,
								channel.context.get_counterparty_node_id(),
								channel.context.channel_id(),
								LocalHTLCFailureReason::ChannelClosed,
								None,
							));
						}
					}
				} else {
					channel.on_startup_drop_completed_blocked_mon_updates_through(
						&logger,
						monitor.get_latest_update_id(),
					);
					log_info!(logger, "Successfully loaded at update_id {} against monitor at update id {} with {} blocked updates",
						channel.context.get_latest_monitor_update_id(),
						monitor.get_latest_update_id(), channel.blocked_monitor_updates_pending());
					if let Some(short_channel_id) = channel.funding.get_short_channel_id() {
						short_to_chan_info.insert(
							short_channel_id,
							(
								channel.context.get_counterparty_node_id(),
								channel.context.channel_id(),
							),
						);
					}

					for short_channel_id in channel.context.historical_scids() {
						let cp_id = channel.context.get_counterparty_node_id();
						let chan_id = channel.context.channel_id();
						short_to_chan_info.insert(*short_channel_id, (cp_id, chan_id));
					}

					per_peer_state
						.entry(channel.context.get_counterparty_node_id())
						.or_insert_with(|| Mutex::new(empty_peer_state()))
						.get_mut()
						.unwrap()
						.channel_by_id
						.insert(channel.context.channel_id(), Channel::from(channel));
				}
			} else if channel.is_awaiting_initial_mon_persist() {
				// If we were persisted and shut down while the initial ChannelMonitor persistence
				// was in-progress, we never broadcasted the funding transaction and can still
				// safely discard the channel.
				channel_closures.push_back((
					events::Event::ChannelClosed {
						channel_id: channel.context.channel_id(),
						user_channel_id: channel.context.get_user_id(),
						reason: ClosureReason::DisconnectedPeer,
						counterparty_node_id: Some(channel.context.get_counterparty_node_id()),
						channel_capacity_sats: Some(channel.funding.get_value_satoshis()),
						channel_funding_txo: channel.funding.get_funding_txo(),
						last_local_balance_msat: Some(channel.funding.get_value_to_self_msat()),
					},
					None,
				));
			} else {
				log_error!(
					logger,
					"Missing ChannelMonitor for channel {} needed by ChannelManager.",
					&channel.context.channel_id()
				);
				log_error!(logger, " The chain::Watch API *requires* that monitors are persisted durably before returning,");
				log_error!(logger, " client applications must ensure that ChannelMonitor data is always available and the latest to avoid funds loss!");
				log_error!(
					logger,
					" Without the ChannelMonitor we cannot continue without risking funds."
				);
				log_error!(logger, " Please ensure the chain::Watch API requirements are met and file a bug report at https://github.com/lightningdevkit/rust-lightning");
				return Err(DecodeError::InvalidValue);
			}
		}

		for (channel_id, monitor) in args.channel_monitors.iter() {
			if !channel_id_set.contains(channel_id) {
				let mut should_queue_fc_update = false;
				let counterparty_node_id = monitor.get_counterparty_node_id();

				// If the ChannelMonitor had any updates, we may need to update it further and
				// thus track it in `closed_channel_monitor_update_ids`. If the channel never
				// had any updates at all, there can't be any HTLCs pending which we need to
				// claim.
				// Note that a `ChannelMonitor` is created with `update_id` 0 and after we
				// provide it with a closure update its `update_id` will be at 1.
				if !monitor.no_further_updates_allowed() || monitor.get_latest_update_id() > 1 {
					should_queue_fc_update = !monitor.no_further_updates_allowed();
					let mut latest_update_id = monitor.get_latest_update_id();
					if should_queue_fc_update {
						// Note that for channels closed pre-0.1, the latest update_id is
						// `u64::MAX`.
						latest_update_id = latest_update_id.saturating_add(1);
					}
					per_peer_state
						.entry(counterparty_node_id)
						.or_insert_with(|| Mutex::new(empty_peer_state()))
						.lock()
						.unwrap()
						.closed_channel_monitor_update_ids
						.entry(monitor.channel_id())
						.and_modify(|v| *v = cmp::max(latest_update_id, *v))
						.or_insert(latest_update_id);
				}

				if !should_queue_fc_update {
					continue;
				}

				let logger = WithChannelMonitor::from(&args.logger, monitor, None);
				let channel_id = monitor.channel_id();
				let monitor_update = ChannelMonitorUpdate {
					update_id: monitor.get_latest_update_id().saturating_add(1),
					updates: vec![ChannelMonitorUpdateStep::ChannelForceClosed {
						should_broadcast: true,
					}],
					channel_id: Some(monitor.channel_id()),
				};
				log_info!(
					logger,
					"Queueing monitor update {} to ensure missing channel is force closed",
					monitor_update.update_id
				);
				let funding_txo = monitor.get_funding_txo();
				let update = BackgroundEvent::MonitorUpdateRegeneratedOnStartup {
					counterparty_node_id,
					funding_txo,
					channel_id,
					update: monitor_update,
				};
				close_background_events.push(update);
			}
		}

		// Apply peer features from deserialized data
		for (peer_pubkey, latest_features) in peer_init_features {
			if let Some(peer_state) = per_peer_state.get_mut(&peer_pubkey) {
				peer_state.get_mut().unwrap().latest_features = latest_features;
			}
		}

		// Post-deserialization processing
		let mut decode_update_add_htlcs: HashMap<u64, Vec<msgs::UpdateAddHTLC>> = new_hash_map();
		if fake_scid_rand_bytes.is_none() {
			fake_scid_rand_bytes = Some(args.entropy_source.get_secure_random_bytes());
		}

		if probing_cookie_secret.is_none() {
			probing_cookie_secret = Some(args.entropy_source.get_secure_random_bytes());
		}

		if inbound_payment_id_secret.is_none() {
			inbound_payment_id_secret = Some(args.entropy_source.get_secure_random_bytes());
		}

		if !channel_closures.is_empty() {
			pending_events_read.append(&mut channel_closures);
		}

		let pending_outbounds = OutboundPayments::new(pending_outbound_payments);

		for (peer_pubkey, peer_storage) in peer_storage_dir {
			if let Some(peer_state) = per_peer_state.get_mut(&peer_pubkey) {
				peer_state.get_mut().unwrap().peer_storage = peer_storage;
			}
		}

		// We have to replay (or skip, if they were completed after we wrote the `ChannelManager`)
		// each `ChannelMonitorUpdate` in `in_flight_monitor_updates`. After doing so, we have to
		// check that each channel we have isn't newer than the latest `ChannelMonitorUpdate`(s) we
		// replayed, and for each monitor update we have to replay we have to ensure there's a
		// `ChannelMonitor` for it.
		//
		// In order to do so we first walk all of our live channels (so that we can check their
		// state immediately after doing the update replays, when we have the `update_id`s
		// available) and then walk any remaining in-flight updates.
		//
		// Because the actual handling of the in-flight updates is the same, it's macro'ized here:
		let mut pending_background_events = Vec::new();
		macro_rules! handle_in_flight_updates {
			($counterparty_node_id: expr, $chan_in_flight_upds: expr, $monitor: expr,
			 $peer_state: expr, $logger: expr, $channel_info_log: expr
			) => { {
				// When all in-flight updates have completed after we were last serialized, we
				// need to remove them. However, we can't guarantee that the next serialization
				// will have happened after processing the
				// `BackgroundEvent::MonitorUpdatesComplete`, so removing them now could lead to the
				// channel never being resumed as the event would not be regenerated after another
				// reload. At the same time, we don't want to resume the channel now because there
				// may be post-update actions to handle. Therefore, we're forced to keep tracking
				// the completed in-flight updates (but only when they have all completed) until we
				// are processing the `BackgroundEvent::MonitorUpdatesComplete`.
				let mut max_in_flight_update_id = 0;
				let num_updates_completed = $chan_in_flight_upds
					.iter()
					.filter(|update| {
						max_in_flight_update_id = cmp::max(max_in_flight_update_id, update.update_id);
						update.update_id <= $monitor.get_latest_update_id()
					})
					.count();
				if num_updates_completed > 0 {
					log_debug!(
						$logger,
						"{} ChannelMonitorUpdates completed after ChannelManager was last serialized",
						num_updates_completed,
					);
				}
				let all_updates_completed = num_updates_completed == $chan_in_flight_upds.len();

				let funding_txo = $monitor.get_funding_txo();
				if all_updates_completed {
					log_debug!($logger, "All monitor updates completed since the ChannelManager was last serialized");
					pending_background_events.push(
						BackgroundEvent::MonitorUpdatesComplete {
							counterparty_node_id: $counterparty_node_id,
							channel_id: $monitor.channel_id(),
							highest_update_id_completed: max_in_flight_update_id,
						});
				} else {
					$chan_in_flight_upds.retain(|update| {
						let replay = update.update_id > $monitor.get_latest_update_id();
						if replay {
							log_debug!($logger, "Replaying ChannelMonitorUpdate {} for {}channel {}",
								update.update_id, $channel_info_log, &$monitor.channel_id());
							pending_background_events.push(
								BackgroundEvent::MonitorUpdateRegeneratedOnStartup {
									counterparty_node_id: $counterparty_node_id,
									funding_txo: funding_txo,
									channel_id: $monitor.channel_id(),
									update: update.clone(),
								}
							);
						}
						replay
					});
					$peer_state.closed_channel_monitor_update_ids.entry($monitor.channel_id())
						.and_modify(|v| *v = cmp::max(max_in_flight_update_id, *v))
						.or_insert(max_in_flight_update_id);
				}
				if $peer_state.in_flight_monitor_updates.insert($monitor.channel_id(), (funding_txo, $chan_in_flight_upds)).is_some() {
					log_error!($logger, "Duplicate in-flight monitor update set for the same channel!");
					return Err(DecodeError::InvalidValue);
				}
				max_in_flight_update_id
			} }
		}

		for (counterparty_id, peer_state_mtx) in per_peer_state.iter_mut() {
			let mut peer_state_lock = peer_state_mtx.lock().unwrap();
			let peer_state = &mut *peer_state_lock;
			for (chan_id, chan) in peer_state.channel_by_id.iter() {
				if let Some(funded_chan) = chan.as_funded() {
					let logger = WithChannelContext::from(&args.logger, &funded_chan.context, None);

					// Channels that were persisted have to be funded, otherwise they should have been
					// discarded.
					let monitor = args
						.channel_monitors
						.get(chan_id)
						.expect("We already checked for monitor presence when loading channels");
					let mut max_in_flight_update_id = monitor.get_latest_update_id();
					if let Some(mut chan_in_flight_upds) =
						in_flight_monitor_updates.remove(&(*counterparty_id, *chan_id))
					{
						max_in_flight_update_id = cmp::max(
							max_in_flight_update_id,
							handle_in_flight_updates!(
								*counterparty_id,
								chan_in_flight_upds,
								monitor,
								peer_state,
								logger,
								""
							),
						);
					}
					if funded_chan.get_latest_unblocked_monitor_update_id()
						> max_in_flight_update_id
					{
						// If the channel is ahead of the monitor, return DangerousValue:
						log_error!(logger, "A ChannelMonitor is stale compared to the current ChannelManager! This indicates a potentially-critical violation of the chain::Watch API!");
						log_error!(logger, " The ChannelMonitor is at update_id {} with update_id through {} in-flight",
							monitor.get_latest_update_id(), max_in_flight_update_id);
						log_error!(
							logger,
							" but the ChannelManager is at update_id {}.",
							funded_chan.get_latest_unblocked_monitor_update_id()
						);
						log_error!(logger, " The chain::Watch API *requires* that monitors are persisted durably before returning,");
						log_error!(logger, " client applications must ensure that ChannelMonitor data is always available and the latest to avoid funds loss!");
						log_error!(logger, " Without the latest ChannelMonitor we cannot continue without risking funds.");
						log_error!(logger, " Please ensure the chain::Watch API requirements are met and file a bug report at https://github.com/lightningdevkit/rust-lightning");
						return Err(DecodeError::DangerousValue);
					}
				} else {
					// We shouldn't have persisted (or read) any unfunded channel types so none should have been
					// created in this `channel_by_id` map.
					debug_assert!(false);
					return Err(DecodeError::InvalidValue);
				}
			}
		}

		for ((counterparty_id, channel_id), mut chan_in_flight_updates) in in_flight_monitor_updates
		{
			let logger =
				WithContext::from(&args.logger, Some(counterparty_id), Some(channel_id), None);
			if let Some(monitor) = args.channel_monitors.get(&channel_id) {
				// Now that we've removed all the in-flight monitor updates for channels that are
				// still open, we need to replay any monitor updates that are for closed channels,
				// creating the neccessary peer_state entries as we go.
				let peer_state_mutex = per_peer_state
					.entry(counterparty_id)
					.or_insert_with(|| Mutex::new(empty_peer_state()));
				let mut peer_state = peer_state_mutex.lock().unwrap();
				handle_in_flight_updates!(
					counterparty_id,
					chan_in_flight_updates,
					monitor,
					peer_state,
					logger,
					"closed "
				);
			} else {
				log_error!(logger, "A ChannelMonitor is missing even though we have in-flight updates for it! This indicates a potentially-critical violation of the chain::Watch API!");
				log_error!(logger, " The ChannelMonitor for channel {} is missing.", channel_id);
				log_error!(logger, " The chain::Watch API *requires* that monitors are persisted durably before returning,");
				log_error!(logger, " client applications must ensure that ChannelMonitor data is always available and the latest to avoid funds loss!");
				log_error!(
					logger,
					" Without the latest ChannelMonitor we cannot continue without risking funds."
				);
				log_error!(logger, " Please ensure the chain::Watch API requirements are met and file a bug report at https://github.com/lightningdevkit/rust-lightning");
				log_error!(logger, " Pending in-flight updates are: {:?}", chan_in_flight_updates);
				return Err(DecodeError::InvalidValue);
			}
		}

		// The newly generated `close_background_events` have to be added after any updates that
		// were already in-flight on shutdown, so we append them here.
		pending_background_events.reserve(close_background_events.len());
		'each_bg_event: for mut new_event in close_background_events {
			if let BackgroundEvent::MonitorUpdateRegeneratedOnStartup {
				counterparty_node_id,
				funding_txo,
				channel_id,
				update,
			} = &mut new_event
			{
				debug_assert_eq!(update.updates.len(), 1);
				debug_assert!(matches!(
					update.updates[0],
					ChannelMonitorUpdateStep::ChannelForceClosed { .. }
				));
				let mut updated_id = false;
				for pending_event in pending_background_events.iter() {
					if let BackgroundEvent::MonitorUpdateRegeneratedOnStartup {
						counterparty_node_id: pending_cp,
						funding_txo: pending_funding,
						channel_id: pending_chan_id,
						update: pending_update,
					} = pending_event
					{
						let for_same_channel = counterparty_node_id == pending_cp
							&& funding_txo == pending_funding
							&& channel_id == pending_chan_id;
						if for_same_channel {
							debug_assert!(update.update_id >= pending_update.update_id);
							if pending_update.updates.iter().any(|upd| {
								matches!(upd, ChannelMonitorUpdateStep::ChannelForceClosed { .. })
							}) {
								// If the background event we're looking at is just
								// force-closing the channel which already has a pending
								// force-close update, no need to duplicate it.
								continue 'each_bg_event;
							}
							update.update_id = pending_update.update_id.saturating_add(1);
							updated_id = true;
						}
					}
				}
				let mut per_peer_state = per_peer_state
					.get(counterparty_node_id)
					.expect("If we have pending updates for a channel it must have an entry")
					.lock()
					.unwrap();
				if updated_id {
					per_peer_state
						.closed_channel_monitor_update_ids
						.entry(*channel_id)
						.and_modify(|v| *v = cmp::max(update.update_id, *v))
						.or_insert(update.update_id);
				}
				let in_flight_updates = &mut per_peer_state
					.in_flight_monitor_updates
					.entry(*channel_id)
					.or_insert_with(|| (*funding_txo, Vec::new()))
					.1;
				debug_assert!(!in_flight_updates.iter().any(|upd| upd == update));
				in_flight_updates.push(update.clone());
			}
			pending_background_events.push(new_event);
		}

		// In LDK 0.2 and below, the `ChannelManager` would track all payments and HTLCs internally and
		// persist that state, relying on it being up-to-date on restart. Newer versions are moving
		// towards reducing this reliance on regular persistence of the `ChannelManager`, and instead
		// reconstruct HTLC/payment state based on `Channel{Monitor}` data if
		// `reconstruct_manager_from_monitors` is set below. Currently we set in tests randomly to
		// ensure the legacy codepaths also have test coverage.
		#[cfg(not(test))]
		let reconstruct_manager_from_monitors = _version >= RECONSTRUCT_HTLCS_FROM_CHANS_VERSION;
		#[cfg(test)]
		let reconstruct_manager_from_monitors =
			args.reconstruct_manager_from_monitors.unwrap_or_else(|| {
				use core::hash::{BuildHasher, Hasher};

				match std::env::var("LDK_TEST_REBUILD_MGR_FROM_MONITORS") {
					Ok(val) => match val.as_str() {
						"1" => true,
						"0" => false,
						_ => panic!(
							"LDK_TEST_REBUILD_MGR_FROM_MONITORS must be 0 or 1, got: {}",
							val
						),
					},
					Err(_) => {
						let rand_val =
							std::collections::hash_map::RandomState::new().build_hasher().finish();
						if rand_val % 2 == 0 {
							true
						} else {
							false
						}
					},
				}
			});

		// If there's any preimages for forwarded HTLCs hanging around in ChannelMonitors we
		// should ensure we try them again on the inbound edge. We put them here and do so after we
		// have a fully-constructed `ChannelManager` at the end.
		let mut pending_claims_to_replay = Vec::new();

		// If we find an inbound HTLC that claims to already be forwarded to the outbound edge, we
		// store an identifier for it here and verify that it is either (a) present in the outbound
		// edge or (b) removed from the outbound edge via claim. If it's in neither of these states, we
		// infer that it was removed from the outbound edge via fail, and fail it backwards to ensure
		// that it is handled.
		let mut already_forwarded_htlcs: HashMap<
			(ChannelId, PaymentHash),
			Vec<(HTLCPreviousHopData, OutboundHop)>,
		> = new_hash_map();
		let prune_forwarded_htlc = |already_forwarded_htlcs: &mut HashMap<
			(ChannelId, PaymentHash),
			Vec<(HTLCPreviousHopData, OutboundHop)>,
		>,
		                            prev_hop: &HTLCPreviousHopData,
		                            payment_hash: &PaymentHash| {
			if let hash_map::Entry::Occupied(mut entry) =
				already_forwarded_htlcs.entry((prev_hop.channel_id, *payment_hash))
			{
				entry.get_mut().retain(|(htlc, _)| prev_hop.htlc_id != htlc.htlc_id);
				if entry.get().is_empty() {
					entry.remove();
				}
			}
		};
		{
			// If we're tracking pending payments, ensure we haven't lost any by looking at the
			// ChannelMonitor data for any channels for which we do not have authorative state
			// (i.e. those for which we just force-closed above or we otherwise don't have a
			// corresponding `Channel` at all).
			// This avoids several edge-cases where we would otherwise "forget" about pending
			// payments which are still in-flight via their on-chain state.
			// We only rebuild the pending payments map if we were most recently serialized by
			// 0.0.102+
			//
			// First we rebuild all pending payments, then separately re-claim and re-fail pending
			// payments. This avoids edge-cases around MPP payments resulting in redundant actions.
			for (channel_id, monitor) in args.channel_monitors.iter() {
				let mut is_channel_closed = true;
				let counterparty_node_id = monitor.get_counterparty_node_id();
				if let Some(peer_state_mtx) = per_peer_state.get(&counterparty_node_id) {
					let mut peer_state_lock = peer_state_mtx.lock().unwrap();
					let peer_state = &mut *peer_state_lock;
					is_channel_closed = !peer_state.channel_by_id.contains_key(channel_id);
					if reconstruct_manager_from_monitors {
						if let Some(chan) = peer_state.channel_by_id.get(channel_id) {
							if let Some(funded_chan) = chan.as_funded() {
								// Legacy HTLCs are from pre-LDK 0.3 and cannot be reconstructed.
								if funded_chan.has_legacy_inbound_htlcs() {
									return Err(DecodeError::InvalidValue);
								}
								// Reconstruct `ChannelManager::decode_update_add_htlcs` from the serialized
								// `Channel` as part of removing the requirement to regularly persist the
								// `ChannelManager`.
								let scid_alias = funded_chan.context.outbound_scid_alias();
								for update_add_htlc in funded_chan.inbound_htlcs_pending_decode() {
									decode_update_add_htlcs
										.entry(scid_alias)
										.or_insert_with(Vec::new)
										.push(update_add_htlc);
								}
								for (payment_hash, prev_hop, next_hop) in
									funded_chan.inbound_forwarded_htlcs()
								{
									already_forwarded_htlcs
										.entry((prev_hop.channel_id, payment_hash))
										.or_insert_with(Vec::new)
										.push((prev_hop, next_hop));
								}
							}
						}
					}
				}

				if is_channel_closed {
					for (htlc_source, (htlc, _)) in monitor.get_all_current_outbound_htlcs() {
						let logger = WithChannelMonitor::from(
							&args.logger,
							monitor,
							Some(htlc.payment_hash),
						);
						if let HTLCSource::OutboundRoute {
							payment_id, session_priv, path, ..
						} = htlc_source
						{
							if path.hops.is_empty() {
								log_error!(logger, "Got an empty path for a pending payment");
								return Err(DecodeError::InvalidValue);
							}

							let mut session_priv_bytes = [0; 32];
							session_priv_bytes[..].copy_from_slice(&session_priv[..]);
							pending_outbounds.insert_from_monitor_on_startup(
								payment_id,
								htlc.payment_hash,
								session_priv_bytes,
								&path,
								best_block_height,
								&logger,
							);
						}
					}
				}
			}
			for (channel_id, monitor) in args.channel_monitors.iter() {
				let (mut is_channel_closed, mut user_channel_id_opt) = (true, None);
				let counterparty_node_id = monitor.get_counterparty_node_id();
				if let Some(peer_state_mtx) = per_peer_state.get(&counterparty_node_id) {
					let mut peer_state_lock = peer_state_mtx.lock().unwrap();
					let peer_state = &mut *peer_state_lock;
					if let Some(chan) = peer_state.channel_by_id.get(channel_id) {
						is_channel_closed = false;
						user_channel_id_opt = Some(chan.context().get_user_id());

						if reconstruct_manager_from_monitors {
							if let Some(funded_chan) = chan.as_funded() {
								for (payment_hash, prev_hop) in funded_chan.outbound_htlc_forwards()
								{
									dedup_decode_update_add_htlcs(
										&mut decode_update_add_htlcs,
										&prev_hop,
										"HTLC already forwarded to the outbound edge",
										&args.logger,
									);
									prune_forwarded_htlc(
										&mut already_forwarded_htlcs,
										&prev_hop,
										&payment_hash,
									);
								}
							}
						}
					}
				}

				if is_channel_closed {
					for (htlc_source, (htlc, preimage_opt)) in
						monitor.get_all_current_outbound_htlcs()
					{
						let logger = WithChannelMonitor::from(
							&args.logger,
							monitor,
							Some(htlc.payment_hash),
						);
						let htlc_id = SentHTLCId::from_source(&htlc_source);
						match htlc_source {
							HTLCSource::PreviousHopData(prev_hop_data) => {
								let pending_forward_matches_htlc = |info: &PendingAddHTLCInfo| {
									info.prev_funding_outpoint == prev_hop_data.outpoint
										&& info.prev_htlc_id == prev_hop_data.htlc_id
								};

								// If `reconstruct_manager_from_monitors` is set, we always add all inbound committed
								// HTLCs to `decode_update_add_htlcs` in the above loop, but we need to prune from
								// those added HTLCs if they were already forwarded to the outbound edge. Otherwise,
								// we'll double-forward.
								if reconstruct_manager_from_monitors {
									dedup_decode_update_add_htlcs(
										&mut decode_update_add_htlcs,
										&prev_hop_data,
										"HTLC already forwarded to the outbound edge",
										&&logger,
									);
									prune_forwarded_htlc(
										&mut already_forwarded_htlcs,
										&prev_hop_data,
										&htlc.payment_hash,
									);
								}

								// The ChannelMonitor is now responsible for this HTLC's
								// failure/success and will let us know what its outcome is. If we
								// still have an entry for this HTLC in `forward_htlcs_legacy`,
								// `pending_intercepted_htlcs_legacy`, or
								// `decode_update_add_htlcs_legacy`, we were apparently not persisted
								// after the monitor was when forwarding the payment.
								dedup_decode_update_add_htlcs(
									&mut decode_update_add_htlcs_legacy,
									&prev_hop_data,
									"HTLC was forwarded to the closed channel",
									&&logger,
								);
								forward_htlcs_legacy.retain(|_, forwards| {
								forwards.retain(|forward| {
									if let HTLCForwardInfo::AddHTLC(htlc_info) = forward {
										if pending_forward_matches_htlc(&htlc_info) {
											log_info!(logger, "Removing pending to-forward HTLC with hash {} as it was forwarded to the closed channel {}",
												&htlc.payment_hash, &monitor.channel_id());
											false
										} else { true }
									} else { true }
								});
								!forwards.is_empty()
							});
								pending_intercepted_htlcs_legacy.retain(|intercepted_id, htlc_info| {
								if pending_forward_matches_htlc(&htlc_info) {
									log_info!(logger, "Removing pending intercepted HTLC with hash {} as it was forwarded to the closed channel {}",
										&htlc.payment_hash, &monitor.channel_id());
									pending_events_read.retain(|(event, _)| {
										if let Event::HTLCIntercepted { intercept_id: ev_id, .. } = event {
											intercepted_id != ev_id
										} else { true }
									});
									false
								} else { true }
							});
							},
							HTLCSource::OutboundRoute {
								payment_id,
								session_priv,
								path,
								bolt12_invoice,
								..
							} => {
								if let Some(preimage) = preimage_opt {
									let pending_events = Mutex::new(pending_events_read);
									let update = PaymentCompleteUpdate {
										counterparty_node_id: monitor.get_counterparty_node_id(),
										channel_funding_outpoint: monitor.get_funding_txo(),
										channel_id: monitor.channel_id(),
										htlc_id,
									};
									let mut compl_action = Some(
									EventCompletionAction::ReleasePaymentCompleteChannelMonitorUpdate(update)
								);
									pending_outbounds.claim_htlc(
										payment_id,
										preimage,
										bolt12_invoice,
										session_priv,
										path,
										true,
										&mut compl_action,
										&pending_events,
										&logger,
									);
									// If the completion action was not consumed, then there was no
									// payment to claim, and we need to tell the `ChannelMonitor`
									// we don't need to hear about the HTLC again, at least as long
									// as the PaymentSent event isn't still sitting around in our
									// event queue.
									let have_action = if compl_action.is_some() {
										let pending_events = pending_events.lock().unwrap();
										pending_events.iter().any(|(_, act)| *act == compl_action)
									} else {
										false
									};
									if !have_action && compl_action.is_some() {
										let mut peer_state = per_peer_state
										.get(&counterparty_node_id)
										.map(|state| state.lock().unwrap())
										.expect(
											"Channels originating a preimage must have peer state",
										);
										let update_id = peer_state
										.closed_channel_monitor_update_ids
										.get_mut(channel_id)
										.expect(
											"Channels originating a preimage must have a monitor",
										);
										// Note that for channels closed pre-0.1, the latest
										// update_id is `u64::MAX`.
										*update_id = update_id.saturating_add(1);

										pending_background_events.push(
											BackgroundEvent::MonitorUpdateRegeneratedOnStartup {
												counterparty_node_id: monitor
													.get_counterparty_node_id(),
												funding_txo: monitor.get_funding_txo(),
												channel_id: monitor.channel_id(),
												update: ChannelMonitorUpdate {
													update_id: *update_id,
													channel_id: Some(monitor.channel_id()),
													updates: vec![
													ChannelMonitorUpdateStep::ReleasePaymentComplete {
														htlc: htlc_id,
													},
												],
												},
											},
										);
									}
									pending_events_read = pending_events.into_inner().unwrap();
								}
							},
						}
					}
					for (htlc_source, payment_hash) in monitor.get_onchain_failed_outbound_htlcs() {
						let logger =
							WithChannelMonitor::from(&args.logger, monitor, Some(payment_hash));
						log_info!(
							logger,
							"Failing HTLC with payment hash {} as it was resolved on-chain.",
							payment_hash
						);
						let completion_action = Some(PaymentCompleteUpdate {
							counterparty_node_id: monitor.get_counterparty_node_id(),
							channel_funding_outpoint: monitor.get_funding_txo(),
							channel_id: monitor.channel_id(),
							htlc_id: SentHTLCId::from_source(&htlc_source),
						});

						failed_htlcs.push((
							htlc_source,
							payment_hash,
							monitor.get_counterparty_node_id(),
							monitor.channel_id(),
							LocalHTLCFailureReason::OnChainTimeout,
							completion_action,
						));
					}
				}

				// Whether the downstream channel was closed or not, try to re-apply any payment
				// preimages from it which may be needed in upstream channels for forwarded
				// payments.
				let mut fail_read = false;
				let outbound_claimed_htlcs_iter = monitor.get_all_current_outbound_htlcs()
					.into_iter()
					.filter_map(|(htlc_source, (htlc, preimage_opt))| {
						if let HTLCSource::PreviousHopData(prev_hop) = &htlc_source {
							if let Some(payment_preimage) = preimage_opt {
								let inbound_edge_monitor = args.channel_monitors.get(&prev_hop.channel_id);
								// Note that for channels which have gone to chain,
								// `get_all_current_outbound_htlcs` is never pruned and always returns
								// a constant set until the monitor is removed/archived. Thus, we
								// want to skip replaying claims that have definitely been resolved
								// on-chain.

								// If the inbound monitor is not present, we assume it was fully
								// resolved and properly archived, implying this payment had plenty
								// of time to get claimed and we can safely skip any further
								// attempts to claim it (they wouldn't succeed anyway as we don't
								// have a monitor against which to do so).
								let inbound_edge_monitor = if let Some(monitor) = inbound_edge_monitor {
									monitor
								} else {
									return None;
								};
								// Second, if the inbound edge of the payment's monitor has been
								// fully claimed we've had at least `ANTI_REORG_DELAY` blocks to
								// get any PaymentForwarded event(s) to the user and assume that
								// there's no need to try to replay the claim just for that.
								let inbound_edge_balances = inbound_edge_monitor.get_claimable_balances();
								if inbound_edge_balances.is_empty() {
									return None;
								}

								if prev_hop.counterparty_node_id.is_none() {
									// We no longer support claiming an HTLC where we don't have
									// the counterparty_node_id available if the claim has to go to
									// a closed channel. Its possible we can get away with it if
									// the channel is not yet closed, but its by no means a
									// guarantee.

									// Thus, in this case we are a bit more aggressive with our
									// pruning - if we have no use for the claim (because the
									// inbound edge of the payment's monitor has already claimed
									// the HTLC) we skip trying to replay the claim.
									let htlc_payment_hash: PaymentHash = payment_preimage.into();
									let logger = WithChannelMonitor::from(
										&args.logger,
										monitor,
										Some(htlc_payment_hash),
									);
									let balance_could_incl_htlc = |bal| match bal {
										&Balance::ClaimableOnChannelClose { .. } => {
											// The channel is still open, assume we can still
											// claim against it
											true
										},
										&Balance::MaybePreimageClaimableHTLC { payment_hash, .. } => {
											payment_hash == htlc_payment_hash
										},
										_ => false,
									};
									let htlc_may_be_in_balances =
										inbound_edge_balances.iter().any(balance_could_incl_htlc);
									if !htlc_may_be_in_balances {
										return None;
									}

									// First check if we're absolutely going to fail - if we need
									// to replay this claim to get the preimage into the inbound
									// edge monitor but the channel is closed (and thus we'll
									// immediately panic if we call claim_funds_from_hop).
									if short_to_chan_info.get(&prev_hop.prev_outbound_scid_alias).is_none() {
										log_error!(logger,
											"We need to replay the HTLC claim for payment_hash {} (preimage {}) but cannot do so as the HTLC was forwarded prior to LDK 0.0.124.\
											All HTLCs that were forwarded by LDK 0.0.123 and prior must be resolved prior to upgrading to LDK 0.1",
											htlc_payment_hash,
											payment_preimage,
										);
										fail_read = true;
									}

									// At this point we're confident we need the claim, but the
									// inbound edge channel is still live. As long as this remains
									// the case, we can conceivably proceed, but we run some risk
									// of panicking at runtime. The user ideally should have read
									// the release notes and we wouldn't be here, but we go ahead
									// and let things run in the hope that it'll all just work out.
									log_error!(logger,
										"We need to replay the HTLC claim for payment_hash {} (preimage {}) but don't have all the required information to do so reliably.\
										As long as the channel for the inbound edge of the forward remains open, this may work okay, but we may panic at runtime!\
										All HTLCs that were forwarded by LDK 0.0.123 and prior must be resolved prior to upgrading to LDK 0.1\
										Continuing anyway, though panics may occur!",
										htlc_payment_hash,
										payment_preimage,
									);
								}

								Some((htlc_source, payment_preimage, htlc.amount_msat,
									is_channel_closed, monitor.get_counterparty_node_id(),
									monitor.get_funding_txo(), monitor.channel_id(), user_channel_id_opt))
							} else { None }
						} else {
							// If it was an outbound payment, we've handled it above - if a preimage
							// came in and we persisted the `ChannelManager` we either handled it and
							// are good to go or the channel force-closed - we don't have to handle the
							// channel still live case here.
							None
						}
					});
				for tuple in outbound_claimed_htlcs_iter {
					pending_claims_to_replay.push(tuple);
				}
				if fail_read {
					return Err(DecodeError::InvalidValue);
				}
			}
		}

		// Similar to the above cases for forwarded payments, if we have any pending inbound HTLCs
		// which haven't yet been claimed, we may be missing counterparty_node_id info and would
		// panic if we attempted to claim them at this point.
		for (payment_hash, payment) in claimable_payments.iter() {
			for htlc in payment.htlcs.iter() {
				if htlc.prev_hop.counterparty_node_id.is_some() {
					continue;
				}
				if short_to_chan_info.get(&htlc.prev_hop.prev_outbound_scid_alias).is_some() {
					log_error!(args.logger,
						"We do not have the required information to claim a pending payment with payment hash {} reliably.\
						As long as the channel for the inbound edge of the forward remains open, this may work okay, but we may panic at runtime!\
						All HTLCs that were received by LDK 0.0.123 and prior must be resolved prior to upgrading to LDK 0.1\
						Continuing anyway, though panics may occur!",
						payment_hash,
					);
				} else {
					log_error!(args.logger,
						"We do not have the required information to claim a pending payment with payment hash {}.\
						All HTLCs that were received by LDK 0.0.123 and prior must be resolved prior to upgrading to LDK 0.1",
						payment_hash,
					);
					return Err(DecodeError::InvalidValue);
				}
			}
		}

		let mut secp_ctx = Secp256k1::new();
		secp_ctx.seeded_randomize(&args.entropy_source.get_secure_random_bytes());

		let expanded_inbound_key = args.node_signer.get_expanded_key();

		let our_network_pubkey = match args.node_signer.get_node_id(Recipient::Node) {
			Ok(key) => key,
			Err(()) => return Err(DecodeError::InvalidValue),
		};
		if let Some(network_pubkey) = received_network_pubkey {
			if network_pubkey != our_network_pubkey {
				log_error!(args.logger, "Key that was generated does not match the existing key.");
				return Err(DecodeError::InvalidValue);
			}
		}

		let mut outbound_scid_aliases = new_hash_set();
		for (_peer_node_id, peer_state_mutex) in per_peer_state.iter_mut() {
			let mut peer_state_lock = peer_state_mutex.lock().unwrap();
			let peer_state = &mut *peer_state_lock;
			for (chan_id, chan) in peer_state.channel_by_id.iter_mut() {
				if let Some(funded_chan) = chan.as_funded_mut() {
					let logger = WithChannelContext::from(&args.logger, &funded_chan.context, None);
					if funded_chan.context.outbound_scid_alias() == 0 {
						let mut outbound_scid_alias;
						loop {
							outbound_scid_alias = fake_scid::Namespace::OutboundAlias
								.get_fake_scid(
									best_block_height,
									&chain_hash,
									fake_scid_rand_bytes.as_ref().unwrap(),
									&args.entropy_source,
								);
							if outbound_scid_aliases.insert(outbound_scid_alias) {
								break;
							}
						}
						funded_chan.context.set_outbound_scid_alias(outbound_scid_alias);
					} else if !outbound_scid_aliases
						.insert(funded_chan.context.outbound_scid_alias())
					{
						// Note that in rare cases its possible to hit this while reading an older
						// channel if we just happened to pick a colliding outbound alias above.
						log_error!(
							logger,
							"Got duplicate outbound SCID alias; {}",
							funded_chan.context.outbound_scid_alias()
						);
						return Err(DecodeError::InvalidValue);
					}
					if funded_chan.context.is_usable() {
						let alias = funded_chan.context.outbound_scid_alias();
						let cp_id = funded_chan.context.get_counterparty_node_id();
						if short_to_chan_info.insert(alias, (cp_id, *chan_id)).is_some() {
							// Note that in rare cases its possible to hit this while reading an older
							// channel if we just happened to pick a colliding outbound alias above.
							log_error!(
								logger,
								"Got duplicate outbound SCID alias; {}",
								funded_chan.context.outbound_scid_alias()
							);
							return Err(DecodeError::InvalidValue);
						}
					}
				} else {
					// We shouldn't have persisted (or read) any unfunded channel types so none should have been
					// created in this `channel_by_id` map.
					debug_assert!(false);
					return Err(DecodeError::InvalidValue);
				}
			}
		}

		let bounded_fee_estimator = LowerBoundedFeeEstimator::new(args.fee_estimator);

		for (node_id, monitor_update_blocked_actions) in monitor_update_blocked_actions_per_peer {
			if let Some(peer_state) = per_peer_state.get(&node_id) {
				for (channel_id, actions) in monitor_update_blocked_actions.iter() {
					let logger =
						WithContext::from(&args.logger, Some(node_id), Some(*channel_id), None);
					for action in actions.iter() {
						if let MonitorUpdateCompletionAction::EmitEventAndFreeOtherChannel {
							downstream_counterparty_and_funding_outpoint:
								Some(EventUnblockedChannel {
									counterparty_node_id: blocked_node_id,
									funding_txo: _,
									channel_id: blocked_channel_id,
									blocking_action,
								}),
							..
						} = action
						{
							if let Some(blocked_peer_state) = per_peer_state.get(blocked_node_id) {
								log_trace!(logger,
									"Holding the next revoke_and_ack from {} until the preimage is durably persisted in the inbound edge's ChannelMonitor",
									blocked_channel_id);
								blocked_peer_state
									.lock()
									.unwrap()
									.actions_blocking_raa_monitor_updates
									.entry(*blocked_channel_id)
									.or_insert_with(Vec::new)
									.push(blocking_action.clone());
							} else {
								// If the channel we were blocking has closed, we don't need to
								// worry about it - the blocked monitor update should never have
								// been released from the `Channel` object so it can't have
								// completed, and if the channel closed there's no reason to bother
								// anymore.
							}
						}
						if let MonitorUpdateCompletionAction::FreeOtherChannelImmediately {
							..
						} = action
						{
							debug_assert!(false, "Non-event-generating channel freeing should not appear in our queue");
						}
					}
					// Note that we may have a post-update action for a channel that has no pending
					// `ChannelMonitorUpdate`s, but unlike the no-peer-state case, it may simply be
					// because we had a `ChannelMonitorUpdate` complete after the last time this
					// `ChannelManager` was serialized. In that case, we'll run the post-update
					// actions as soon as we get going.
				}
				peer_state.lock().unwrap().monitor_update_blocked_actions =
					monitor_update_blocked_actions;
			} else {
				for actions in monitor_update_blocked_actions.values() {
					for action in actions.iter() {
						if matches!(action, MonitorUpdateCompletionAction::PaymentClaimed { .. }) {
							// If there are no state for this channel but we have pending
							// post-update actions, its possible that one was left over from pre-0.1
							// payment claims where MPP claims led to a channel blocked on itself
							// and later `ChannelMonitorUpdate`s didn't get their post-update
							// actions run.
							// This should only have happened for `PaymentClaimed` post-update actions,
							// which we ignore here.
						} else {
							let logger = WithContext::from(&args.logger, Some(node_id), None, None);
							log_error!(
								logger,
								"Got blocked actions {:?} without a per-peer-state for {}",
								monitor_update_blocked_actions,
								node_id
							);
							return Err(DecodeError::InvalidValue);
						}
					}
				}
			}
		}

		if reconstruct_manager_from_monitors {
			// De-duplicate HTLCs that are present in both `failed_htlcs` and `decode_update_add_htlcs`.
			// Omitting this de-duplication could lead to redundant HTLC processing and/or bugs.
			for (src, payment_hash, _, _, _, _) in failed_htlcs.iter() {
				if let HTLCSource::PreviousHopData(prev_hop_data) = src {
					dedup_decode_update_add_htlcs(
						&mut decode_update_add_htlcs,
						prev_hop_data,
						"HTLC was failed backwards during manager read",
						&args.logger,
					);
					prune_forwarded_htlc(&mut already_forwarded_htlcs, prev_hop_data, payment_hash);
				}
			}

			// See above comment on `failed_htlcs`.
			for htlcs in claimable_payments.values().map(|pmt| &pmt.htlcs) {
				for prev_hop_data in htlcs.iter().map(|h| &h.prev_hop) {
					dedup_decode_update_add_htlcs(
						&mut decode_update_add_htlcs,
						prev_hop_data,
						"HTLC was already decoded and marked as a claimable payment",
						&args.logger,
					);
				}
			}
		}

		let (decode_update_add_htlcs, forward_htlcs, pending_intercepted_htlcs) =
			if reconstruct_manager_from_monitors {
				(decode_update_add_htlcs, new_hash_map(), new_hash_map())
			} else {
				(
					decode_update_add_htlcs_legacy,
					forward_htlcs_legacy,
					pending_intercepted_htlcs_legacy,
				)
			};

		// If we have a pending intercept HTLC present but no corresponding event, add that now rather
		// than relying on the user having persisted the event prior to shutdown.
		for (id, fwd) in pending_intercepted_htlcs.iter() {
			if !pending_events_read.iter().any(
				|(ev, _)| matches!(ev, Event::HTLCIntercepted { intercept_id, .. } if intercept_id == id),
			) {
				match create_htlc_intercepted_event(*id, fwd) {
					Ok(ev) => pending_events_read.push_back((ev, None)),
					Err(()) => debug_assert!(false),
				}
			}
		}

		// We may need to regenerate [`Event::FundingTransactionReadyForSigning`] for channels that
		// still need their holder `tx_signatures`.
		for (counterparty_node_id, peer_state_mutex) in per_peer_state.iter() {
			let peer_state = peer_state_mutex.lock().unwrap();
			for (channel_id, chan) in peer_state.channel_by_id.iter() {
				if let Some(signing_session) =
					chan.context().interactive_tx_signing_session.as_ref()
				{
					if signing_session.holder_tx_signatures().is_none()
						&& signing_session.has_local_contribution()
					{
						let unsigned_transaction = signing_session.unsigned_tx().tx().clone();
						pending_events_read.push_back((
							Event::FundingTransactionReadyForSigning {
								unsigned_transaction,
								counterparty_node_id: *counterparty_node_id,
								channel_id: *channel_id,
								user_channel_id: chan.context().get_user_id(),
							},
							None,
						));
					}
				}
			}
		}

		let best_block = BestBlock::new(best_block_hash, best_block_height);
		let flow = OffersMessageFlow::new(
			chain_hash,
			best_block,
			our_network_pubkey,
			highest_seen_timestamp,
			expanded_inbound_key,
			args.node_signer.get_receive_auth_key(),
			secp_ctx.clone(),
			args.message_router,
			args.logger.clone(),
		)
		.with_async_payments_offers_cache(async_receive_offer_cache);

		let channel_manager = ChannelManager {
			chain_hash,
			fee_estimator: bounded_fee_estimator,
			chain_monitor: args.chain_monitor,
			tx_broadcaster: args.tx_broadcaster,
			router: args.router,
			flow,

			best_block: RwLock::new(best_block),

			inbound_payment_key: expanded_inbound_key,
			pending_outbound_payments: pending_outbounds,
			pending_intercepted_htlcs: Mutex::new(pending_intercepted_htlcs),

			forward_htlcs: Mutex::new(forward_htlcs),
			decode_update_add_htlcs: Mutex::new(decode_update_add_htlcs),
			claimable_payments: Mutex::new(ClaimablePayments {
				claimable_payments,
				pending_claiming_payments,
			}),
			outbound_scid_aliases: Mutex::new(outbound_scid_aliases),
			short_to_chan_info: FairRwLock::new(short_to_chan_info),
			fake_scid_rand_bytes: fake_scid_rand_bytes.unwrap(),

			probing_cookie_secret: probing_cookie_secret.unwrap(),
			inbound_payment_id_secret: inbound_payment_id_secret.unwrap(),

			our_network_pubkey,
			secp_ctx,

			highest_seen_timestamp: AtomicUsize::new(highest_seen_timestamp as usize),

			per_peer_state: FairRwLock::new(per_peer_state),

			#[cfg(not(any(test, feature = "_externalize_tests")))]
			monitor_update_type: AtomicUsize::new(0),

			pending_events: Mutex::new(pending_events_read),
			pending_events_processor: AtomicBool::new(false),
			pending_htlc_forwards_processor: AtomicBool::new(false),
			pending_background_events: Mutex::new(pending_background_events),
			total_consistency_lock: RwLock::new(()),
			background_events_processed_since_startup: AtomicBool::new(false),

			event_persist_notifier: Notifier::new(),
			needs_persist_flag: AtomicBool::new(false),

			funding_batch_states: Mutex::new(BTreeMap::new()),

			pending_broadcast_messages: Mutex::new(Vec::new()),

			entropy_source: args.entropy_source,
			node_signer: args.node_signer,
			signer_provider: args.signer_provider,

			last_days_feerates: Mutex::new(VecDeque::new()),

			logger: args.logger,
			config: RwLock::new(args.config),

			#[cfg(feature = "_test_utils")]
			testing_dnssec_proof_offer_resolution_override: Mutex::new(new_hash_map()),
		};

		let mut processed_claims: HashSet<Vec<MPPClaimHTLCSource>> = new_hash_set();
		for (channel_id, monitor) in args.channel_monitors.iter() {
			for (payment_hash, (payment_preimage, payment_claims)) in monitor.get_stored_preimages()
			{
				// If we have unresolved inbound committed HTLCs that were already forwarded to the
				// outbound edge and removed via claim, we need to make sure to claim them backwards via
				// adding them to `pending_claims_to_replay`.
				if let Some(forwarded_htlcs) =
					already_forwarded_htlcs.remove(&(*channel_id, payment_hash))
				{
					for (prev_hop, next_hop) in forwarded_htlcs {
						let new_pending_claim =
							!pending_claims_to_replay.iter().any(|(src, _, _, _, _, _, _, _)| {
								matches!(src, HTLCSource::PreviousHopData(hop) if hop.htlc_id == prev_hop.htlc_id && hop.channel_id == prev_hop.channel_id)
							});
						if new_pending_claim {
							let is_downstream_closed = channel_manager
								.per_peer_state
								.read()
								.unwrap()
								.get(&next_hop.node_id)
								.map_or(true, |peer_state_mtx| {
									!peer_state_mtx
										.lock()
										.unwrap()
										.channel_by_id
										.contains_key(&next_hop.channel_id)
								});
							pending_claims_to_replay.push((
								HTLCSource::PreviousHopData(prev_hop),
								payment_preimage,
								next_hop.amt_msat,
								is_downstream_closed,
								next_hop.node_id,
								next_hop.funding_txo,
								next_hop.channel_id,
								Some(next_hop.user_channel_id),
							));
						}
					}
				}
				if !payment_claims.is_empty() {
					for payment_claim in payment_claims {
						if processed_claims.contains(&payment_claim.mpp_parts) {
							// We might get the same payment a few times from different channels
							// that the MPP payment was received using. There's no point in trying
							// to claim the same payment again and again, so we check if the HTLCs
							// are the same and skip the payment here.
							continue;
						}
						if payment_claim.mpp_parts.is_empty() {
							return Err(DecodeError::InvalidValue);
						}
						{
							let payments = channel_manager.claimable_payments.lock().unwrap();
							if !payments.claimable_payments.contains_key(&payment_hash) {
								if let Some(payment) =
									payments.pending_claiming_payments.get(&payment_hash)
								{
									if payment.payment_id
										== payment_claim.claiming_payment.payment_id
									{
										// If this payment already exists and was marked as
										// being-claimed then the serialized state must contain all
										// of the pending `ChannelMonitorUpdate`s required to get
										// the preimage on disk in all MPP parts. Thus we can skip
										// the replay below.
										continue;
									}
								}
							}
						}

						let mut channels_without_preimage = payment_claim
							.mpp_parts
							.iter()
							.map(|htlc_info| (htlc_info.counterparty_node_id, htlc_info.channel_id))
							.collect::<Vec<_>>();
						// If we have multiple MPP parts which were received over the same channel,
						// we only track it once as once we get a preimage durably in the
						// `ChannelMonitor` it will be used for all HTLCs with a matching hash.
						channels_without_preimage.sort_unstable();
						channels_without_preimage.dedup();
						let pending_claims = PendingMPPClaim {
							channels_without_preimage,
							channels_with_preimage: Vec::new(),
						};
						let pending_claim_ptr_opt = Some(Arc::new(Mutex::new(pending_claims)));

						// While it may be duplicative to generate a PaymentClaimed here, trying to
						// figure out if the user definitely saw it before shutdown would require some
						// nontrivial logic and may break as we move away from regularly persisting
						// ChannelManager. Instead, we rely on the users' event handler being
						// idempotent and just blindly generate one no matter what, letting the
						// preimages eventually timing out from ChannelMonitors to prevent us from
						// doing so forever.

						let claim_found = channel_manager
							.claimable_payments
							.lock()
							.unwrap()
							.begin_claiming_payment(
								payment_hash,
								&channel_manager.node_signer,
								&channel_manager.logger,
								&channel_manager.inbound_payment_id_secret,
								true,
							);
						if claim_found.is_err() {
							let mut claimable_payments =
								channel_manager.claimable_payments.lock().unwrap();
							match claimable_payments.pending_claiming_payments.entry(payment_hash) {
								hash_map::Entry::Occupied(_) => {
									debug_assert!(
										false,
										"Entry was added in begin_claiming_payment"
									);
									return Err(DecodeError::InvalidValue);
								},
								hash_map::Entry::Vacant(entry) => {
									entry.insert(payment_claim.claiming_payment);
								},
							}
						}

						for part in payment_claim.mpp_parts.iter() {
							let pending_mpp_claim = pending_claim_ptr_opt.as_ref().map(|ptr| {
								(
									part.counterparty_node_id,
									part.channel_id,
									PendingMPPClaimPointer(Arc::clone(&ptr)),
								)
							});
							let pending_claim_ptr = pending_claim_ptr_opt.as_ref().map(|ptr| {
								RAAMonitorUpdateBlockingAction::ClaimedMPPPayment {
									pending_claim: PendingMPPClaimPointer(Arc::clone(&ptr)),
								}
							});
							// Note that we don't need to pass the `payment_info` here - its
							// already (clearly) durably on disk in the `ChannelMonitor` so there's
							// no need to worry about getting it into others.
							//
							// We don't encode any attribution data, because the required onion shared secret isn't
							// available here.
							channel_manager.claim_mpp_part(
								part.into(),
								payment_preimage,
								None,
								None,
								|_, _| {
									(
										Some(MonitorUpdateCompletionAction::PaymentClaimed {
											payment_hash,
											pending_mpp_claim,
										}),
										pending_claim_ptr,
									)
								},
							);
						}
						processed_claims.insert(payment_claim.mpp_parts);
					}
				} else {
					let per_peer_state = channel_manager.per_peer_state.read().unwrap();
					let mut claimable_payments = channel_manager.claimable_payments.lock().unwrap();
					let payment = claimable_payments.claimable_payments.remove(&payment_hash);
					mem::drop(claimable_payments);
					if let Some(payment) = payment {
						log_info!(channel_manager.logger, "Re-claiming HTLCs with payment hash {} as we've released the preimage to a ChannelMonitor!", &payment_hash);
						let mut claimable_amt_msat = 0;
						let mut receiver_node_id = Some(our_network_pubkey);
						let phantom_shared_secret = payment.htlcs[0].prev_hop.phantom_shared_secret;
						if phantom_shared_secret.is_some() {
							let phantom_pubkey = channel_manager
								.node_signer
								.get_node_id(Recipient::PhantomNode)
								.expect("Failed to get node_id for phantom node recipient");
							receiver_node_id = Some(phantom_pubkey)
						}
						for claimable_htlc in &payment.htlcs {
							claimable_amt_msat += claimable_htlc.value;

							// Add a holding-cell claim of the payment to the Channel, which should be
							// applied ~immediately on peer reconnection. Because it won't generate a
							// new commitment transaction we can just provide the payment preimage to
							// the corresponding ChannelMonitor and nothing else.
							//
							// We do so directly instead of via the normal ChannelMonitor update
							// procedure as the ChainMonitor hasn't yet been initialized, implying
							// we're not allowed to call it directly yet. Further, we do the update
							// without incrementing the ChannelMonitor update ID as there isn't any
							// reason to.
							// If we were to generate a new ChannelMonitor update ID here and then
							// crash before the user finishes block connect we'd end up force-closing
							// this channel as well. On the flip side, there's no harm in restarting
							// without the new monitor persisted - we'll end up right back here on
							// restart.
							let previous_channel_id = claimable_htlc.prev_hop.channel_id;
							let peer_node_id = monitor.get_counterparty_node_id();
							{
								let peer_state_mutex = per_peer_state.get(&peer_node_id).unwrap();
								let mut peer_state_lock = peer_state_mutex.lock().unwrap();
								let peer_state = &mut *peer_state_lock;
								if let Some(channel) = peer_state
									.channel_by_id
									.get_mut(&previous_channel_id)
									.and_then(Channel::as_funded_mut)
								{
									let logger = WithChannelContext::from(
										&channel_manager.logger,
										&channel.context,
										Some(payment_hash),
									);
									channel
										.claim_htlc_while_disconnected_dropping_mon_update_legacy(
											claimable_htlc.prev_hop.htlc_id,
											payment_preimage,
											&&logger,
										);
								}
							}
							if let Some(previous_hop_monitor) =
								args.channel_monitors.get(&claimable_htlc.prev_hop.channel_id)
							{
								// Note that this is unsafe as we no longer require the
								// `ChannelMonitor`s to be re-persisted prior to this
								// `ChannelManager` being persisted after we get started running.
								// If this `ChannelManager` gets persisted first then we crash, we
								// won't have the `claimable_payments` entry we need to re-enter
								// this code block, causing us to not re-apply the preimage to this
								// `ChannelMonitor`.
								//
								// We should never be here with modern payment claims, however, as
								// they should always include the HTLC list. Instead, this is only
								// for nodes during upgrade, and we explicitly require the old
								// persistence semantics on upgrade in the release notes.
								previous_hop_monitor.provide_payment_preimage_unsafe_legacy(
									&payment_hash,
									&payment_preimage,
									&channel_manager.tx_broadcaster,
									&channel_manager.fee_estimator,
									&channel_manager.logger,
								);
							}
						}
						let mut pending_events = channel_manager.pending_events.lock().unwrap();
						let payment_id =
							payment.inbound_payment_id(&inbound_payment_id_secret.unwrap());
						let htlcs = payment.htlcs.iter().map(events::ClaimedHTLC::from).collect();
						let sender_intended_total_msat =
							payment.htlcs.first().map(|htlc| htlc.total_msat);
						pending_events.push_back((
							events::Event::PaymentClaimed {
								receiver_node_id,
								payment_hash,
								purpose: payment.purpose,
								amount_msat: claimable_amt_msat,
								htlcs,
								sender_intended_total_msat,
								onion_fields: payment.onion_fields,
								payment_id: Some(payment_id),
							},
							// Note that we don't bother adding a EventCompletionAction here to
							// ensure the `PaymentClaimed` event is durable processed as this
							// should only be hit for particularly old channels and we don't have
							// enough information to generate such an action.
							None,
						));
					}
				}
			}
		}

		for htlc_source in failed_htlcs {
			let (source, hash, counterparty_id, channel_id, failure_reason, ev_action) =
				htlc_source;
			let receiver =
				HTLCHandlingFailureType::Forward { node_id: Some(counterparty_id), channel_id };
			let reason = HTLCFailReason::from_failure_code(failure_reason);
			channel_manager
				.fail_htlc_backwards_internal(&source, &hash, &reason, receiver, ev_action);
		}
		for ((_, hash), htlcs) in already_forwarded_htlcs.into_iter() {
			for (htlc, _) in htlcs {
				let channel_id = htlc.channel_id;
				let node_id = htlc.counterparty_node_id;
				let source = HTLCSource::PreviousHopData(htlc);
				let failure_reason = LocalHTLCFailureReason::TemporaryChannelFailure;
				let failure_data = channel_manager.get_htlc_inbound_temp_fail_data(failure_reason);
				let reason = HTLCFailReason::reason(failure_reason, failure_data);
				let receiver = HTLCHandlingFailureType::Forward { node_id, channel_id };
				// The event completion action is only relevant for HTLCs that originate from our node, not
				// forwarded HTLCs.
				channel_manager
					.fail_htlc_backwards_internal(&source, &hash, &reason, receiver, None);
			}
		}

		for (
			source,
			preimage,
			downstream_value,
			downstream_closed,
			downstream_node_id,
			downstream_funding,
			downstream_channel_id,
			downstream_user_channel_id,
		) in pending_claims_to_replay
		{
			// We use `downstream_closed` in place of `from_onchain` here just as a guess - we
			// don't remember in the `ChannelMonitor` where we got a preimage from, but if the
			// channel is closed we just assume that it probably came from an on-chain claim.
			// The same holds for attribution data. We don't have any, so we pass an empty one.
			channel_manager.claim_funds_internal(
				source,
				preimage,
				Some(downstream_value),
				None,
				downstream_closed,
				downstream_node_id,
				downstream_funding,
				downstream_channel_id,
				downstream_user_channel_id,
				None,
				None,
			);
		}

		//TODO: Broadcast channel update for closed channels, but only after we've made a
		//connection or two.

		Ok((best_block_hash, channel_manager))
	}
}

#[cfg(test)]
mod tests {
	use crate::events::{ClosureReason, Event, HTLCHandlingFailureType};
	use crate::ln::channelmanager::{
		create_recv_pending_htlc_info, inbound_payment, InterceptId, PaymentId,
		RecipientOnionFields,
	};
	use crate::ln::functional_test_utils::*;
	use crate::ln::msgs::{self, BaseMessageHandler, ChannelMessageHandler, MessageSendEvent};
	use crate::ln::onion_utils::{self, LocalHTLCFailureReason};
	use crate::ln::outbound_payment::Retry;
	use crate::ln::types::ChannelId;
	use crate::prelude::*;
	use crate::routing::router::{find_route, PaymentParameters, RouteParameters};
	use crate::sign::EntropySource;
	use crate::types::payment::{PaymentHash, PaymentPreimage, PaymentSecret};
	use crate::util::config::{ChannelConfig, ChannelConfigUpdate};
	use crate::util::errors::APIError;
	use crate::util::test_utils;
	use bitcoin::secp256k1::ecdh::SharedSecret;
	use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
	use core::sync::atomic::Ordering;

	#[test]
	#[rustfmt::skip]
	fn test_notify_limits() {
		// Check that a few cases which don't require the persistence of a new ChannelManager,
		// indeed, do not cause the persistence of a new ChannelManager.
		let chanmon_cfgs = create_chanmon_cfgs(3);
		let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
		let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
		let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

		// All nodes start with a persistable update pending as `create_network` connects each node
		// with all other nodes to make most tests simpler.
		assert!(nodes[0].node.get_event_or_persistence_needed_future().poll_is_complete());
		assert!(nodes[1].node.get_event_or_persistence_needed_future().poll_is_complete());
		assert!(nodes[2].node.get_event_or_persistence_needed_future().poll_is_complete());

		let mut chan = create_announced_chan_between_nodes(&nodes, 0, 1);

		// We check that the channel info nodes have doesn't change too early, even though we try
		// to connect messages with new values
		chan.0.contents.fee_base_msat *= 2;
		chan.1.contents.fee_base_msat *= 2;
		let node_a_chan_info = nodes[0].node.list_channels_with_counterparty(
			&nodes[1].node.get_our_node_id()).pop().unwrap();
		let node_b_chan_info = nodes[1].node.list_channels_with_counterparty(
			&nodes[0].node.get_our_node_id()).pop().unwrap();

		// The first two nodes (which opened a channel) should now require fresh persistence
		assert!(nodes[0].node.get_event_or_persistence_needed_future().poll_is_complete());
		assert!(nodes[1].node.get_event_or_persistence_needed_future().poll_is_complete());
		// ... but the last node should not.
		assert!(!nodes[2].node.get_event_or_persistence_needed_future().poll_is_complete());
		// After persisting the first two nodes they should no longer need fresh persistence.
		assert!(!nodes[0].node.get_event_or_persistence_needed_future().poll_is_complete());
		assert!(!nodes[1].node.get_event_or_persistence_needed_future().poll_is_complete());

		// Node 3, unrelated to the only channel, shouldn't care if it receives a channel_update
		// about the channel.
		nodes[2].node.handle_channel_update(nodes[1].node.get_our_node_id(), &chan.0);
		nodes[2].node.handle_channel_update(nodes[1].node.get_our_node_id(), &chan.1);
		assert!(!nodes[2].node.get_event_or_persistence_needed_future().poll_is_complete());

		// The nodes which are a party to the channel should also ignore messages from unrelated
		// parties.
		nodes[0].node.handle_channel_update(nodes[2].node.get_our_node_id(), &chan.0);
		nodes[0].node.handle_channel_update(nodes[2].node.get_our_node_id(), &chan.1);
		nodes[1].node.handle_channel_update(nodes[2].node.get_our_node_id(), &chan.0);
		nodes[1].node.handle_channel_update(nodes[2].node.get_our_node_id(), &chan.1);
		assert!(!nodes[0].node.get_event_or_persistence_needed_future().poll_is_complete());
		assert!(!nodes[1].node.get_event_or_persistence_needed_future().poll_is_complete());

		// At this point the channel info given by peers should still be the same.
		assert_eq!(nodes[0].node.list_channels()[0], node_a_chan_info);
		assert_eq!(nodes[1].node.list_channels()[0], node_b_chan_info);

		// An earlier version of handle_channel_update didn't check the directionality of the
		// update message and would always update the local fee info, even if our peer was
		// (spuriously) forwarding us our own channel_update.
		let as_node_one = nodes[0].node.get_our_node_id().serialize()[..] < nodes[1].node.get_our_node_id().serialize()[..];
		let as_update = if as_node_one == (chan.0.contents.channel_flags & 1 == 0 /* chan.0 is from node one */) { &chan.0 } else { &chan.1 };
		let bs_update = if as_node_one == (chan.0.contents.channel_flags & 1 == 0 /* chan.0 is from node one */) { &chan.1 } else { &chan.0 };

		// First deliver each peers' own message, checking that the node doesn't need to be
		// persisted and that its channel info remains the same.
		nodes[0].node.handle_channel_update(nodes[1].node.get_our_node_id(), &as_update);
		nodes[1].node.handle_channel_update(nodes[0].node.get_our_node_id(), &bs_update);
		assert!(!nodes[0].node.get_event_or_persistence_needed_future().poll_is_complete());
		assert!(!nodes[1].node.get_event_or_persistence_needed_future().poll_is_complete());
		assert_eq!(nodes[0].node.list_channels()[0], node_a_chan_info);
		assert_eq!(nodes[1].node.list_channels()[0], node_b_chan_info);

		// Finally, deliver the other peers' message, ensuring each node needs to be persisted and
		// the channel info has updated.
		nodes[0].node.handle_channel_update(nodes[1].node.get_our_node_id(), &bs_update);
		nodes[1].node.handle_channel_update(nodes[0].node.get_our_node_id(), &as_update);
		assert!(nodes[0].node.get_event_or_persistence_needed_future().poll_is_complete());
		assert!(nodes[1].node.get_event_or_persistence_needed_future().poll_is_complete());
		assert_ne!(nodes[0].node.list_channels()[0], node_a_chan_info);
		assert_ne!(nodes[1].node.list_channels()[0], node_b_chan_info);
	}

	#[test]
	#[rustfmt::skip]
	fn test_keysend_dup_hash_partial_mpp() {
		// Test that a keysend payment with a duplicate hash to an existing partial MPP payment fails as
		// expected.
		let chanmon_cfgs = create_chanmon_cfgs(2);
		let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
		let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
		let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
		create_announced_chan_between_nodes(&nodes, 0, 1);

		// First, send a partial MPP payment.
		let (route, our_payment_hash, payment_preimage, payment_secret) = get_route_and_payment_hash!(&nodes[0], nodes[1], 100_000);
		let mut mpp_route = route.clone();
		mpp_route.paths.push(mpp_route.paths[0].clone());

		let payment_id = PaymentId([42; 32]);
		// Use the utility function send_payment_along_path to send the payment with MPP data which
		// indicates there are more HTLCs coming.
		let cur_height = CHAN_CONFIRM_DEPTH + 1; // route_payment calls send_payment, which adds 1 to the current height. So we do the same here to match.
		let session_privs = nodes[0].node.test_add_new_pending_payment(our_payment_hash,
			RecipientOnionFields::secret_only(payment_secret), payment_id, &mpp_route).unwrap();
		nodes[0].node.test_send_payment_along_path(&mpp_route.paths[0], &our_payment_hash,
			RecipientOnionFields::secret_only(payment_secret), 200_000, cur_height, payment_id, &None, session_privs[0]).unwrap();
		check_added_monitors(&nodes[0], 1);
		let mut events = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		pass_along_path(&nodes[0], &[&nodes[1]], 200_000, our_payment_hash, Some(payment_secret), events.drain(..).next().unwrap(), false, None);

		// Next, send a keysend payment with the same payment_hash and make sure it fails.
		nodes[0].node.send_spontaneous_payment(
			Some(payment_preimage), RecipientOnionFields::spontaneous_empty(),
			PaymentId(payment_preimage.0), route.route_params.clone().unwrap(), Retry::Attempts(0)
		).unwrap();
		check_added_monitors(&nodes[0], 1);
		let mut events = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		let ev = events.drain(..).next().unwrap();
		let payment_event = SendEvent::from_event(ev);
		nodes[1].node.handle_update_add_htlc(nodes[0].node.get_our_node_id(), &payment_event.msgs[0]);
		check_added_monitors(&nodes[1], 0);
		do_commitment_signed_dance(&nodes[1], &nodes[0], &payment_event.commitment_msg, false, false);
		expect_and_process_pending_htlcs(&nodes[1], true);
		let events = nodes[1].node.get_and_clear_pending_events();
		let fail = HTLCHandlingFailureType::Receive { payment_hash: our_payment_hash };
		expect_htlc_failure_conditions(events, &[fail]);
		check_added_monitors(&nodes[1], 1);
		let updates = get_htlc_update_msgs(&nodes[1], &nodes[0].node.get_our_node_id());
		assert!(updates.update_add_htlcs.is_empty());
		assert!(updates.update_fulfill_htlcs.is_empty());
		assert_eq!(updates.update_fail_htlcs.len(), 1);
		assert!(updates.update_fail_malformed_htlcs.is_empty());
		assert!(updates.update_fee.is_none());
		nodes[0].node.handle_update_fail_htlc(nodes[1].node.get_our_node_id(), &updates.update_fail_htlcs[0]);
		do_commitment_signed_dance(&nodes[0], &nodes[1], &updates.commitment_signed, true, true);
		expect_payment_failed!(nodes[0], our_payment_hash, true);

		// Send the second half of the original MPP payment.
		nodes[0].node.test_send_payment_along_path(&mpp_route.paths[1], &our_payment_hash,
			RecipientOnionFields::secret_only(payment_secret), 200_000, cur_height, payment_id, &None, session_privs[1]).unwrap();
		check_added_monitors(&nodes[0], 1);
		let mut events = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		pass_along_path(&nodes[0], &[&nodes[1]], 200_000, our_payment_hash, Some(payment_secret), events.drain(..).next().unwrap(), true, None);

		// Claim the full MPP payment. Note that we can't use a test utility like
		// claim_funds_along_route because the ordering of the messages causes the second half of the
		// payment to be put in the holding cell, which confuses the test utilities. So we exchange the
		// lightning messages manually.
		nodes[1].node.claim_funds(payment_preimage);
		expect_payment_claimed!(nodes[1], our_payment_hash, 200_000);
		check_added_monitors(&nodes[1], 2);

		let mut bs_1st_updates = get_htlc_update_msgs(&nodes[1], &nodes[0].node.get_our_node_id());
		nodes[0].node.handle_update_fulfill_htlc(nodes[1].node.get_our_node_id(), bs_1st_updates.update_fulfill_htlcs.remove(0));
		expect_payment_sent(&nodes[0], payment_preimage, None, false, false);
		nodes[0].node.handle_commitment_signed_batch_test(nodes[1].node.get_our_node_id(), &bs_1st_updates.commitment_signed);
		check_added_monitors(&nodes[0], 1);
		let (as_first_raa, as_first_cs) = get_revoke_commit_msgs(&nodes[0], &nodes[1].node.get_our_node_id());
		nodes[1].node.handle_revoke_and_ack(nodes[0].node.get_our_node_id(), &as_first_raa);
		check_added_monitors(&nodes[1], 1);
		let mut bs_2nd_updates = get_htlc_update_msgs(&nodes[1], &nodes[0].node.get_our_node_id());
		nodes[1].node.handle_commitment_signed_batch_test(nodes[0].node.get_our_node_id(), &as_first_cs);
		check_added_monitors(&nodes[1], 1);
		let bs_first_raa = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, nodes[0].node.get_our_node_id());
		nodes[0].node.handle_update_fulfill_htlc(nodes[1].node.get_our_node_id(), bs_2nd_updates.update_fulfill_htlcs.remove(0));
		nodes[0].node.handle_commitment_signed_batch_test(nodes[1].node.get_our_node_id(), &bs_2nd_updates.commitment_signed);
		check_added_monitors(&nodes[0], 1);
		let as_second_raa = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());
		nodes[0].node.handle_revoke_and_ack(nodes[1].node.get_our_node_id(), &bs_first_raa);
		let as_second_updates = get_htlc_update_msgs(&nodes[0], &nodes[1].node.get_our_node_id());
		check_added_monitors(&nodes[0], 1);
		nodes[1].node.handle_revoke_and_ack(nodes[0].node.get_our_node_id(), &as_second_raa);
		check_added_monitors(&nodes[1], 1);
		nodes[1].node.handle_commitment_signed_batch_test(nodes[0].node.get_our_node_id(), &as_second_updates.commitment_signed);
		check_added_monitors(&nodes[1], 1);
		let bs_third_raa = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, nodes[0].node.get_our_node_id());
		nodes[0].node.handle_revoke_and_ack(nodes[1].node.get_our_node_id(), &bs_third_raa);
		check_added_monitors(&nodes[0], 1);

		// Note that successful MPP payments will generate a single PaymentSent event upon the first
		// path's success and a PaymentPathSuccessful event for each path's success.
		let events = nodes[0].node.get_and_clear_pending_events();
		assert_eq!(events.len(), 2);
		match events[0] {
			Event::PaymentPathSuccessful { payment_id: ref actual_payment_id, ref payment_hash, ref path, .. } => {
				assert_eq!(payment_id, *actual_payment_id);
				assert_eq!(our_payment_hash, *payment_hash.as_ref().unwrap());
				assert_eq!(route.paths[0], *path);
			},
			_ => panic!("Unexpected event"),
		}
		match events[1] {
			Event::PaymentPathSuccessful { payment_id: ref actual_payment_id, ref payment_hash, ref path, ..} => {
				assert_eq!(payment_id, *actual_payment_id);
				assert_eq!(our_payment_hash, *payment_hash.as_ref().unwrap());
				assert_eq!(route.paths[0], *path);
			},
			_ => panic!("Unexpected event"),
		}
	}

	#[test]
	#[rustfmt::skip]
	fn test_keysend_dup_payment_hash() {
		// (1): Test that a keysend payment with a duplicate payment hash to an existing pending
		//      outbound regular payment fails as expected.
		// (2): Test that a regular payment with a duplicate payment hash to an existing keysend payment
		//      fails as expected.
		// (3): Test that a keysend payment with a duplicate payment hash to an existing keysend
		//      payment fails as expected. We only accept MPP keysends with payment secrets and reject
		//      otherwise.
		let chanmon_cfgs = create_chanmon_cfgs(2);
		let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
		let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
		let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
		create_announced_chan_between_nodes(&nodes, 0, 1);
		let scorer = test_utils::TestScorer::new();
		let random_seed_bytes = chanmon_cfgs[1].keys_manager.get_secure_random_bytes();

		// To start (1), send a regular payment but don't claim it.
		let expected_route = [&nodes[1]];
		let (payment_preimage, payment_hash, ..) = route_payment(&nodes[0], &expected_route, 100_000);

		// Next, attempt a keysend payment and make sure it fails.
		let route_params = RouteParameters::from_payment_params_and_value(
			PaymentParameters::for_keysend(expected_route.last().unwrap().node.get_our_node_id(),
			TEST_FINAL_CLTV, false), 100_000);
		nodes[0].node.send_spontaneous_payment(
			Some(payment_preimage), RecipientOnionFields::spontaneous_empty(),
			PaymentId(payment_preimage.0), route_params.clone(), Retry::Attempts(0)
		).unwrap();
		check_added_monitors(&nodes[0], 1);
		let mut events = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		let ev = events.drain(..).next().unwrap();
		let payment_event = SendEvent::from_event(ev);
		nodes[1].node.handle_update_add_htlc(nodes[0].node.get_our_node_id(), &payment_event.msgs[0]);
	check_added_monitors(&nodes[1], 0);
		do_commitment_signed_dance(&nodes[1], &nodes[0], &payment_event.commitment_msg, false, false);
		// We have to forward pending HTLCs twice - once tries to forward the payment forward (and
		// fails), the second will process the resulting failure and fail the HTLC backward
		expect_and_process_pending_htlcs(&nodes[1], true);
		let events = nodes[1].node.get_and_clear_pending_events();
		let fail = HTLCHandlingFailureType::Receive { payment_hash };
		expect_htlc_failure_conditions(events, &[fail]);
		check_added_monitors(&nodes[1], 1);
		let updates = get_htlc_update_msgs(&nodes[1], &nodes[0].node.get_our_node_id());
		assert!(updates.update_add_htlcs.is_empty());
		assert!(updates.update_fulfill_htlcs.is_empty());
		assert_eq!(updates.update_fail_htlcs.len(), 1);
		assert!(updates.update_fail_malformed_htlcs.is_empty());
		assert!(updates.update_fee.is_none());
		nodes[0].node.handle_update_fail_htlc(nodes[1].node.get_our_node_id(), &updates.update_fail_htlcs[0]);
		do_commitment_signed_dance(&nodes[0], &nodes[1], &updates.commitment_signed, true, true);
		expect_payment_failed!(nodes[0], payment_hash, true);

		// Finally, claim the original payment.
		claim_payment(&nodes[0], &expected_route, payment_preimage);

		// To start (2), send a keysend payment but don't claim it.
		let payment_preimage = PaymentPreimage([42; 32]);
		let route = find_route(
			&nodes[0].node.get_our_node_id(), &route_params, &nodes[0].network_graph,
			None, nodes[0].logger, &scorer, &Default::default(), &random_seed_bytes
		).unwrap();
		let payment_hash = nodes[0].node.send_spontaneous_payment(
			Some(payment_preimage), RecipientOnionFields::spontaneous_empty(),
			PaymentId(payment_preimage.0), route.route_params.clone().unwrap(), Retry::Attempts(0)
		).unwrap();
	check_added_monitors(&nodes[0], 1);
		let mut events = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		let event = events.pop().unwrap();
		let path = vec![&nodes[1]];
		pass_along_path(&nodes[0], &path, 100_000, payment_hash, None, event, true, Some(payment_preimage));

		// Next, attempt a regular payment and make sure it fails.
		let payment_secret = PaymentSecret([43; 32]);
		nodes[0].node.send_payment_with_route(route.clone(), payment_hash,
			RecipientOnionFields::secret_only(payment_secret), PaymentId(payment_hash.0)).unwrap();
		check_added_monitors(&nodes[0], 1);
		let mut events = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		let ev = events.drain(..).next().unwrap();
		let payment_event = SendEvent::from_event(ev);
		nodes[1].node.handle_update_add_htlc(nodes[0].node.get_our_node_id(), &payment_event.msgs[0]);
		check_added_monitors(&nodes[1], 0);
		do_commitment_signed_dance(&nodes[1], &nodes[0], &payment_event.commitment_msg, false, false);
		expect_and_process_pending_htlcs(&nodes[1], true);
		let events = nodes[1].node.get_and_clear_pending_events();
		let fail = HTLCHandlingFailureType::Receive { payment_hash };
		expect_htlc_failure_conditions(events, &[fail]);
		check_added_monitors(&nodes[1], 1);
		let updates = get_htlc_update_msgs(&nodes[1], &nodes[0].node.get_our_node_id());
		assert!(updates.update_add_htlcs.is_empty());
		assert!(updates.update_fulfill_htlcs.is_empty());
		assert_eq!(updates.update_fail_htlcs.len(), 1);
		assert!(updates.update_fail_malformed_htlcs.is_empty());
		assert!(updates.update_fee.is_none());
		nodes[0].node.handle_update_fail_htlc(nodes[1].node.get_our_node_id(), &updates.update_fail_htlcs[0]);
		do_commitment_signed_dance(&nodes[0], &nodes[1], &updates.commitment_signed, true, true);
		expect_payment_failed!(nodes[0], payment_hash, true);

		// Finally, succeed the keysend payment.
		claim_payment(&nodes[0], &expected_route, payment_preimage);

		// To start (3), send a keysend payment but don't claim it.
		let payment_id_1 = PaymentId([44; 32]);
		let payment_hash = nodes[0].node.send_spontaneous_payment(
			Some(payment_preimage), RecipientOnionFields::spontaneous_empty(), payment_id_1,
			route.route_params.clone().unwrap(), Retry::Attempts(0)
		).unwrap();
		check_added_monitors(&nodes[0], 1);
		let mut events = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		let event = events.pop().unwrap();
		let path = vec![&nodes[1]];
		pass_along_path(&nodes[0], &path, 100_000, payment_hash, None, event, true, Some(payment_preimage));

		// Next, attempt a keysend payment and make sure it fails.
		let route_params = RouteParameters::from_payment_params_and_value(
			PaymentParameters::for_keysend(expected_route.last().unwrap().node.get_our_node_id(), TEST_FINAL_CLTV, false),
			100_000
		);
		let payment_id_2 = PaymentId([45; 32]);
		nodes[0].node.send_spontaneous_payment(
			Some(payment_preimage), RecipientOnionFields::spontaneous_empty(), payment_id_2, route_params,
			Retry::Attempts(0)
		).unwrap();
		check_added_monitors(&nodes[0], 1);
		let mut events = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		let ev = events.drain(..).next().unwrap();
		let payment_event = SendEvent::from_event(ev);
		nodes[1].node.handle_update_add_htlc(nodes[0].node.get_our_node_id(), &payment_event.msgs[0]);
		check_added_monitors(&nodes[1], 0);
		do_commitment_signed_dance(&nodes[1], &nodes[0], &payment_event.commitment_msg, false, false);
		expect_and_process_pending_htlcs(&nodes[1], true);
		let events = nodes[1].node.get_and_clear_pending_events();
		let fail = HTLCHandlingFailureType::Receive { payment_hash };
		expect_htlc_failure_conditions(events, &[fail]);
		check_added_monitors(&nodes[1], 1);
		let updates = get_htlc_update_msgs(&nodes[1], &nodes[0].node.get_our_node_id());
		assert!(updates.update_add_htlcs.is_empty());
		assert!(updates.update_fulfill_htlcs.is_empty());
		assert_eq!(updates.update_fail_htlcs.len(), 1);
		assert!(updates.update_fail_malformed_htlcs.is_empty());
		assert!(updates.update_fee.is_none());
		nodes[0].node.handle_update_fail_htlc(nodes[1].node.get_our_node_id(), &updates.update_fail_htlcs[0]);
		do_commitment_signed_dance(&nodes[0], &nodes[1], &updates.commitment_signed, true, true);
		expect_payment_failed!(nodes[0], payment_hash, true);

		// Finally, claim the original payment.
		claim_payment(&nodes[0], &expected_route, payment_preimage);
	}

	#[test]
	#[rustfmt::skip]
	fn test_keysend_hash_mismatch() {
		// Test that if we receive a keysend `update_add_htlc` msg, we fail as expected if the keysend
		// preimage doesn't match the msg's payment hash.
		let chanmon_cfgs = create_chanmon_cfgs(2);
		let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
		let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
		let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

		let payer_pubkey = nodes[0].node.get_our_node_id();
		let payee_pubkey = nodes[1].node.get_our_node_id();

		let _chan = create_chan_between_nodes(&nodes[0], &nodes[1]);
		let route_params = RouteParameters::from_payment_params_and_value(
			PaymentParameters::for_keysend(payee_pubkey, 40, false), 10_000);
		let network_graph = nodes[0].network_graph;
		let first_hops = nodes[0].node.list_usable_channels();
		let scorer = test_utils::TestScorer::new();
		let random_seed_bytes = chanmon_cfgs[1].keys_manager.get_secure_random_bytes();
		let route = find_route(
			&payer_pubkey, &route_params, &network_graph, Some(&first_hops.iter().collect::<Vec<_>>()),
			nodes[0].logger, &scorer, &Default::default(), &random_seed_bytes
		).unwrap();

		let test_preimage = PaymentPreimage([42; 32]);
		let mismatch_payment_hash = PaymentHash([43; 32]);
		let session_privs = nodes[0].node.test_add_new_pending_payment(mismatch_payment_hash,
			RecipientOnionFields::spontaneous_empty(), PaymentId(mismatch_payment_hash.0), &route).unwrap();
		nodes[0].node.test_send_payment_internal(&route, mismatch_payment_hash,
			RecipientOnionFields::spontaneous_empty(), Some(test_preimage), PaymentId(mismatch_payment_hash.0), None, session_privs).unwrap();
		check_added_monitors(&nodes[0], 1);

		let updates = get_htlc_update_msgs(&nodes[0], &nodes[1].node.get_our_node_id());
		assert_eq!(updates.update_add_htlcs.len(), 1);
		assert!(updates.update_fulfill_htlcs.is_empty());
		assert!(updates.update_fail_htlcs.is_empty());
		assert!(updates.update_fail_malformed_htlcs.is_empty());
		assert!(updates.update_fee.is_none());
		nodes[1].node.handle_update_add_htlc(nodes[0].node.get_our_node_id(), &updates.update_add_htlcs[0]);
		do_commitment_signed_dance(&nodes[1], &nodes[0], &updates.commitment_signed, false, false);
		expect_and_process_pending_htlcs(&nodes[1], false);
		expect_htlc_handling_failed_destinations!(nodes[1].node.get_and_clear_pending_events(), &[HTLCHandlingFailureType::Receive { payment_hash: mismatch_payment_hash }]);
		check_added_monitors(&nodes[1], 1);
		let _ = get_htlc_update_msgs(&nodes[1], &nodes[0].node.get_our_node_id());

		nodes[1].logger.assert_log_contains("lightning::ln::channelmanager", "Payment preimage didn't match payment hash", 1);
	}

	#[test]
	#[rustfmt::skip]
	fn test_multi_hop_missing_secret() {
		let chanmon_cfgs = create_chanmon_cfgs(4);
		let node_cfgs = create_node_cfgs(4, &chanmon_cfgs);
		let node_chanmgrs = create_node_chanmgrs(4, &node_cfgs, &[None, None, None, None]);
		let nodes = create_network(4, &node_cfgs, &node_chanmgrs);

		let chan_1_id = create_announced_chan_between_nodes(&nodes, 0, 1).0.contents.short_channel_id;
		let chan_2_id = create_announced_chan_between_nodes(&nodes, 0, 2).0.contents.short_channel_id;
		let chan_3_id = create_announced_chan_between_nodes(&nodes, 1, 3).0.contents.short_channel_id;
		let chan_4_id = create_announced_chan_between_nodes(&nodes, 2, 3).0.contents.short_channel_id;

		// Marshall an MPP route.
		let (mut route, payment_hash, _, _) = get_route_and_payment_hash!(&nodes[0], nodes[3], 100000);
		let path = route.paths[0].clone();
		route.paths.push(path);
		route.paths[0].hops[0].pubkey = nodes[1].node.get_our_node_id();
		route.paths[0].hops[0].short_channel_id = chan_1_id;
		route.paths[0].hops[1].short_channel_id = chan_3_id;
		route.paths[1].hops[0].pubkey = nodes[2].node.get_our_node_id();
		route.paths[1].hops[0].short_channel_id = chan_2_id;
		route.paths[1].hops[1].short_channel_id = chan_4_id;

		nodes[0].node.send_payment_with_route(route, payment_hash,
			RecipientOnionFields::spontaneous_empty(), PaymentId(payment_hash.0)).unwrap();
		let events = nodes[0].node.get_and_clear_pending_events();
		assert_eq!(events.len(), 1);
		match events[0] {
			Event::PaymentFailed { reason, .. } => {
				assert_eq!(reason.unwrap(), crate::events::PaymentFailureReason::UnexpectedError);
			}
			_ => panic!()
		}
		nodes[0].logger.assert_log_contains("lightning::ln::outbound_payment", "Payment secret is required for multi-path payments", 2);
		assert!(nodes[0].node.list_recent_payments().is_empty());
	}

	#[test]
	#[rustfmt::skip]
	fn test_channel_update_cached() {
		let chanmon_cfgs = create_chanmon_cfgs(3);
		let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
		let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
		let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

		let chan = create_announced_chan_between_nodes(&nodes, 0, 1);

		let message = "Channel force-closed".to_owned();
		nodes[0].node.force_close_broadcasting_latest_txn(&chan.2, &nodes[1].node.get_our_node_id(), message.clone()).unwrap();
		check_added_monitors(&nodes[0], 1);
		let reason = ClosureReason::HolderForceClosed { broadcasted_latest_txn: Some(true), message };
		check_closed_event(&nodes[0], 1, reason, &[nodes[1].node.get_our_node_id()], 100000);

		// Confirm that the channel_update was not sent immediately to node[1] but was cached.
		let node_1_events = nodes[1].node.get_and_clear_pending_msg_events();
		assert_eq!(node_1_events.len(), 0);

		{
			// Assert that ChannelUpdate message has been added to node[0] pending broadcast messages
			let pending_broadcast_messages= nodes[0].node.pending_broadcast_messages.lock().unwrap();
			assert_eq!(pending_broadcast_messages.len(), 1);
		}

		// Test that we do not retrieve the pending broadcast messages when we are not connected to any peer
		nodes[0].node.peer_disconnected(nodes[1].node.get_our_node_id());
		nodes[1].node.peer_disconnected(nodes[0].node.get_our_node_id());

		nodes[0].node.peer_disconnected(nodes[2].node.get_our_node_id());
		nodes[2].node.peer_disconnected(nodes[0].node.get_our_node_id());

		let node_0_events = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(node_0_events.len(), 0);

		// Now we reconnect to a peer
		nodes[0].node.peer_connected(nodes[2].node.get_our_node_id(), &msgs::Init {
			features: nodes[2].node.init_features(), networks: None, remote_network_address: None
		}, true).unwrap();
		nodes[2].node.peer_connected(nodes[0].node.get_our_node_id(), &msgs::Init {
			features: nodes[0].node.init_features(), networks: None, remote_network_address: None
		}, false).unwrap();

		// Confirm that get_and_clear_pending_msg_events correctly captures pending broadcast messages
		let node_0_events = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(node_0_events.len(), 1);
		match &node_0_events[0] {
			MessageSendEvent::BroadcastChannelUpdate { .. } => (),
			_ => panic!("Unexpected event"),
		}
		{
			// Assert that ChannelUpdate message has been cleared from nodes[0] pending broadcast messages
			let pending_broadcast_messages= nodes[0].node.pending_broadcast_messages.lock().unwrap();
			assert_eq!(pending_broadcast_messages.len(), 0);
		}
	}

	#[test]
	#[rustfmt::skip]
	fn test_drop_disconnected_peers_when_removing_channels() {
		let chanmon_cfgs = create_chanmon_cfgs(2);
		let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
		let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
		let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

		create_chan_between_nodes_with_value_init(&nodes[0], &nodes[1], 1_000_000, 0);

		nodes[0].node.peer_disconnected(nodes[1].node.get_our_node_id());
		nodes[1].node.peer_disconnected(nodes[0].node.get_our_node_id());
		let chan_id = nodes[0].node.list_channels()[0].channel_id;
		let message = "Channel force-closed".to_owned();
		nodes[0]
			.node
			.force_close_broadcasting_latest_txn(&chan_id, &nodes[1].node.get_our_node_id(), message.clone())
			.unwrap();
		check_added_monitors(&nodes[0], 1);
		let reason = ClosureReason::HolderForceClosed { broadcasted_latest_txn: Some(true), message };
		check_closed_event(&nodes[0], 1, reason, &[nodes[1].node.get_our_node_id()], 1_000_000);

		{
			// Assert that nodes[1] is awaiting removal for nodes[0] once nodes[1] has been
			// disconnected and the channel between has been force closed.
			let nodes_0_per_peer_state = nodes[0].node.per_peer_state.read().unwrap();
			// Assert that nodes[1] isn't removed before `timer_tick_occurred` has been executed.
			assert_eq!(nodes_0_per_peer_state.len(), 1);
			assert!(nodes_0_per_peer_state.get(&nodes[1].node.get_our_node_id()).is_some());
		}

		nodes[0].node.timer_tick_occurred();

		{
			// Assert that nodes[1] has now been removed.
			assert_eq!(nodes[0].node.per_peer_state.read().unwrap().len(), 0);
		}
	}

	#[test]
	#[rustfmt::skip]
	fn test_drop_peers_when_removing_unfunded_channels() {
		let chanmon_cfgs = create_chanmon_cfgs(2);
		let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
		let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
		let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

		exchange_open_accept_chan(&nodes[0], &nodes[1], 1_000_000, 0);
		let events = nodes[0].node.get_and_clear_pending_events();
		assert_eq!(events.len(), 1, "Unexpected events {:?}", events);
		match events[0] {
			Event::FundingGenerationReady { .. } => {}
			_ => panic!("Unexpected event {:?}", events),
		}

		nodes[0].node.peer_disconnected(nodes[1].node.get_our_node_id());
		nodes[1].node.peer_disconnected(nodes[0].node.get_our_node_id());
		check_closed_event(&nodes[0], 1, ClosureReason::DisconnectedPeer, &[nodes[1].node.get_our_node_id()], 1_000_000);
		check_closed_event(&nodes[1], 1, ClosureReason::DisconnectedPeer, &[nodes[0].node.get_our_node_id()], 1_000_000);

		// At this point the state for the peers should have been removed.
		assert_eq!(nodes[0].node.per_peer_state.read().unwrap().len(), 0);
		assert_eq!(nodes[1].node.per_peer_state.read().unwrap().len(), 0);
	}

	#[test]
	#[rustfmt::skip]
	fn bad_inbound_payment_hash() {
		// Add coverage for checking that a user-provided payment hash matches the payment secret.
		let chanmon_cfgs = create_chanmon_cfgs(2);
		let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
		let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
		let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

		let (_, payment_hash, payment_secret) = get_payment_preimage_hash(&nodes[0], None, None);
		let payment_data = msgs::FinalOnionHopData {
			payment_secret,
			total_msat: 100_000,
		};

		// Ensure that if the payment hash given to `inbound_payment::verify` differs from the original,
		// payment verification fails as expected.
		let mut bad_payment_hash = payment_hash.clone();
		bad_payment_hash.0[0] += 1;
		match inbound_payment::verify(bad_payment_hash, &payment_data, nodes[0].node.highest_seen_timestamp.load(Ordering::Acquire) as u64, &nodes[0].node.inbound_payment_key, &nodes[0].logger) {
			Ok(_) => panic!("Unexpected ok"),
			Err(()) => {
				nodes[0].logger.assert_log_contains("lightning::ln::inbound_payment", "Failing HTLC with user-generated payment_hash", 1);
			}
		}

		// Check that using the original payment hash succeeds.
		assert!(inbound_payment::verify(payment_hash, &payment_data, nodes[0].node.highest_seen_timestamp.load(Ordering::Acquire) as u64, &nodes[0].node.inbound_payment_key, &nodes[0].logger).is_ok());
	}

	fn check_not_connected_to_peer_error<T>(
		res_err: Result<T, APIError>, expected_public_key: PublicKey,
	) {
		let expected_message = format!("Not connected to node: {}", expected_public_key);
		check_api_error_message(expected_message, res_err)
	}

	#[rustfmt::skip]
	fn check_unkown_peer_error<T>(res_err: Result<T, APIError>, expected_public_key: PublicKey) {
		let expected_message = format!("No such peer for the passed counterparty_node_id {}", expected_public_key);
		check_api_error_message(expected_message, res_err)
	}

	#[rustfmt::skip]
	fn check_channel_unavailable_error<T>(res_err: Result<T, APIError>, expected_channel_id: ChannelId, peer_node_id: PublicKey) {
		let expected_message = format!("No such channel_id {} for the passed counterparty_node_id {}", expected_channel_id, peer_node_id);
		check_api_error_message(expected_message, res_err)
	}

	fn check_api_misuse_error<T>(res_err: Result<T, APIError>) {
		let expected_message = "No such channel awaiting to be accepted.".to_string();
		check_api_error_message(expected_message, res_err)
	}

	fn check_api_error_message<T>(expected_err_message: String, res_err: Result<T, APIError>) {
		match res_err {
			Err(APIError::APIMisuseError { err }) => {
				assert_eq!(err, expected_err_message);
			},
			Err(APIError::ChannelUnavailable { err }) => {
				assert_eq!(err, expected_err_message);
			},
			Ok(_) => panic!("Unexpected Ok"),
			Err(_) => panic!("Unexpected Error"),
		}
	}

	#[test]
	#[rustfmt::skip]
	fn test_api_calls_with_unkown_counterparty_node() {
		// Tests that our API functions that expects a `counterparty_node_id` as input, behaves as
		// expected if the `counterparty_node_id` is an unkown peer in the
		// `ChannelManager::per_peer_state` map.
		let chanmon_cfg = create_chanmon_cfgs(2);
		let node_cfg = create_node_cfgs(2, &chanmon_cfg);
		let node_chanmgr = create_node_chanmgrs(2, &node_cfg, &[None, None]);
		let nodes = create_network(2, &node_cfg, &node_chanmgr);

		// Dummy values
		let channel_id = ChannelId::from_bytes([4; 32]);
		let unkown_public_key = PublicKey::from_secret_key(&Secp256k1::signing_only(), &SecretKey::from_slice(&[42; 32]).unwrap());
		let intercept_id = InterceptId([0; 32]);
		let error_message = "Channel force-closed";

		// Test the API functions.
		check_not_connected_to_peer_error(nodes[0].node.create_channel(unkown_public_key, 1_000_000, 500_000_000, 42, None, None), unkown_public_key);

		check_unkown_peer_error(nodes[0].node.accept_inbound_channel(&channel_id, &unkown_public_key, 42, None), unkown_public_key);

		check_unkown_peer_error(nodes[0].node.close_channel(&channel_id, &unkown_public_key), unkown_public_key);

		check_unkown_peer_error(nodes[0].node.force_close_broadcasting_latest_txn(&channel_id, &unkown_public_key, error_message.to_string()), unkown_public_key);

		check_unkown_peer_error(nodes[0].node.forward_intercepted_htlc(intercept_id, &channel_id, unkown_public_key, 1_000_000), unkown_public_key);

		check_unkown_peer_error(nodes[0].node.update_channel_config(&unkown_public_key, &[channel_id], &ChannelConfig::default()), unkown_public_key);
	}

	#[test]
	#[rustfmt::skip]
	fn test_api_calls_with_unavailable_channel() {
		// Tests that our API functions that expects a `counterparty_node_id` and a `channel_id`
		// as input, behaves as expected if the `counterparty_node_id` is a known peer in the
		// `ChannelManager::per_peer_state` map, but the peer state doesn't contain a channel with
		// the given `channel_id`.
		let chanmon_cfg = create_chanmon_cfgs(2);
		let node_cfg = create_node_cfgs(2, &chanmon_cfg);
		let node_chanmgr = create_node_chanmgrs(2, &node_cfg, &[None, None]);
		let nodes = create_network(2, &node_cfg, &node_chanmgr);

		let counterparty_node_id = nodes[1].node.get_our_node_id();

		// Dummy values
		let channel_id = ChannelId::from_bytes([4; 32]);
		let error_message = "Channel force-closed";

		// Test the API functions.
		check_api_misuse_error(nodes[0].node.accept_inbound_channel(&channel_id, &counterparty_node_id, 42, None));

		check_channel_unavailable_error(nodes[0].node.close_channel(&channel_id, &counterparty_node_id), channel_id, counterparty_node_id);

		check_channel_unavailable_error(nodes[0].node.force_close_broadcasting_latest_txn(&channel_id, &counterparty_node_id, error_message.to_string()), channel_id, counterparty_node_id);

		check_channel_unavailable_error(nodes[0].node.forward_intercepted_htlc(InterceptId([0; 32]), &channel_id, counterparty_node_id, 1_000_000), channel_id, counterparty_node_id);

		check_channel_unavailable_error(nodes[0].node.update_channel_config(&counterparty_node_id, &[channel_id], &ChannelConfig::default()), channel_id, counterparty_node_id);
	}

	#[test]
	#[rustfmt::skip]
	fn test_connection_limiting() {
		// Test that we limit un-channel'd peers and un-funded channels properly.
		let chanmon_cfgs = create_chanmon_cfgs(2);
		let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
		let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
		let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

		// Note that create_network connects the nodes together for us

		nodes[0].node.create_channel(nodes[1].node.get_our_node_id(), 100_000, 0, 42, None, None).unwrap();
		let mut open_channel_msg = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, nodes[1].node.get_our_node_id());

		let mut funding_tx = None;
		for idx in 0..super::MAX_UNFUNDED_CHANS_PER_PEER {
			handle_and_accept_open_channel(&nodes[1], nodes[0].node.get_our_node_id(), &open_channel_msg);
			let accept_channel = get_event_msg!(nodes[1], MessageSendEvent::SendAcceptChannel, nodes[0].node.get_our_node_id());

			if idx == 0 {
				nodes[0].node.handle_accept_channel(nodes[1].node.get_our_node_id(), &accept_channel);
				let (temporary_channel_id, tx, _) = create_funding_transaction(&nodes[0], &nodes[1].node.get_our_node_id(), 100_000, 42);
				funding_tx = Some(tx.clone());
				nodes[0].node.funding_transaction_generated(temporary_channel_id, nodes[1].node.get_our_node_id(), tx).unwrap();
				let funding_created_msg = get_event_msg!(nodes[0], MessageSendEvent::SendFundingCreated, nodes[1].node.get_our_node_id());

				nodes[1].node.handle_funding_created(nodes[0].node.get_our_node_id(), &funding_created_msg);
				check_added_monitors(&nodes[1], 1);
				expect_channel_pending_event(&nodes[1], &nodes[0].node.get_our_node_id());

				let funding_signed = get_event_msg!(nodes[1], MessageSendEvent::SendFundingSigned, nodes[0].node.get_our_node_id());

				nodes[0].node.handle_funding_signed(nodes[1].node.get_our_node_id(), &funding_signed);
				check_added_monitors(&nodes[0], 1);
				expect_channel_pending_event(&nodes[0], &nodes[1].node.get_our_node_id());
			}
			open_channel_msg.common_fields.temporary_channel_id = ChannelId::temporary_from_entropy_source(&nodes[0].keys_manager);
		}

		// A MAX_UNFUNDED_CHANS_PER_PEER + 1 channel will be summarily rejected
		open_channel_msg.common_fields.temporary_channel_id = ChannelId::temporary_from_entropy_source(
			&nodes[0].keys_manager);
		nodes[1].node.handle_open_channel(nodes[0].node.get_our_node_id(), &open_channel_msg);
		assert_eq!(get_err_msg(&nodes[1], &nodes[0].node.get_our_node_id()).channel_id,
			open_channel_msg.common_fields.temporary_channel_id);

		// Further, because all of our channels with nodes[0] are inbound, and none of them funded,
		// it doesn't count as a "protected" peer, i.e. it counts towards the MAX_NO_CHANNEL_PEERS
		// limit.
		let mut peer_pks = Vec::with_capacity(super::MAX_NO_CHANNEL_PEERS);
		for _ in 1..super::MAX_NO_CHANNEL_PEERS {
			let random_pk = PublicKey::from_secret_key(&nodes[0].node.secp_ctx,
				&SecretKey::from_slice(&nodes[1].keys_manager.get_secure_random_bytes()).unwrap());
			peer_pks.push(random_pk);
			nodes[1].node.peer_connected(random_pk, &msgs::Init {
				features: nodes[0].node.init_features(), networks: None, remote_network_address: None
			}, true).unwrap();
		}
		let last_random_pk = PublicKey::from_secret_key(&nodes[0].node.secp_ctx,
			&SecretKey::from_slice(&nodes[1].keys_manager.get_secure_random_bytes()).unwrap());
		nodes[1].node.peer_connected(last_random_pk, &msgs::Init {
			features: nodes[0].node.init_features(), networks: None, remote_network_address: None
		}, true).unwrap_err();

		// Also importantly, because nodes[0] isn't "protected", we will refuse a reconnection from
		// them if we have too many un-channel'd peers.
		nodes[1].node.peer_disconnected(nodes[0].node.get_our_node_id());
		let chan_closed_events = nodes[1].node.get_and_clear_pending_events();
		assert_eq!(chan_closed_events.len(), super::MAX_UNFUNDED_CHANS_PER_PEER - 1);
		for ev in chan_closed_events {
			if let Event::ChannelClosed { .. } = ev { } else { panic!(); }
		}
		nodes[1].node.peer_connected(last_random_pk, &msgs::Init {
			features: nodes[0].node.init_features(), networks: None, remote_network_address: None
		}, true).unwrap();
		nodes[1].node.peer_connected(nodes[0].node.get_our_node_id(), &msgs::Init {
			features: nodes[0].node.init_features(), networks: None, remote_network_address: None
		}, true).unwrap_err();

		// but of course if the connection is outbound its allowed...
		nodes[1].node.peer_connected(nodes[0].node.get_our_node_id(), &msgs::Init {
			features: nodes[0].node.init_features(), networks: None, remote_network_address: None
		}, false).unwrap();
		nodes[1].node.peer_disconnected(nodes[0].node.get_our_node_id());

		// Now nodes[0] is disconnected but still has a pending, un-funded channel lying around.
		// Even though we accept one more connection from new peers, we won't actually let them
		// open channels.
		assert!(peer_pks.len() > super::MAX_UNFUNDED_CHANNEL_PEERS - 1);
		for i in 0..super::MAX_UNFUNDED_CHANNEL_PEERS - 1 {
			handle_and_accept_open_channel(&nodes[1], peer_pks[i], &open_channel_msg);
			get_event_msg!(nodes[1], MessageSendEvent::SendAcceptChannel, peer_pks[i]);
			open_channel_msg.common_fields.temporary_channel_id = ChannelId::temporary_from_entropy_source(&nodes[0].keys_manager);
		}
		nodes[1].node.handle_open_channel(last_random_pk, &open_channel_msg);
		let events = nodes[1].node.get_and_clear_pending_events();
		match events[0] {
			Event::OpenChannelRequest { temporary_channel_id, .. } => {
				assert!(nodes[1]
					.node
					.accept_inbound_channel(&temporary_channel_id, &last_random_pk, 23, None,)
					.is_err())
			},
			_ => panic!("Unexpected event"),
		}

		assert_eq!(get_err_msg(&nodes[1], &last_random_pk).channel_id,
			open_channel_msg.common_fields.temporary_channel_id);

		// Of course, however, outbound channels are always allowed
		nodes[1].node.create_channel(last_random_pk, 100_000, 0, 42, None, None).unwrap();
		get_event_msg!(nodes[1], MessageSendEvent::SendOpenChannel, last_random_pk);

		// If we fund the first channel, nodes[0] has a live on-chain channel with us, it is now
		// "protected" and can connect again.
		mine_transaction(&nodes[1], funding_tx.as_ref().unwrap());
		nodes[1].node.peer_connected(nodes[0].node.get_our_node_id(), &msgs::Init {
			features: nodes[0].node.init_features(), networks: None, remote_network_address: None
		}, true).unwrap();
		get_event_msg!(nodes[1], MessageSendEvent::SendChannelReestablish, nodes[0].node.get_our_node_id());

		// Further, because the first channel was funded, we can open another channel with
		// last_random_pk.
		handle_and_accept_open_channel(&nodes[1], last_random_pk, &open_channel_msg);
		get_event_msg!(nodes[1], MessageSendEvent::SendAcceptChannel, last_random_pk);
	}

	#[test]
	#[rustfmt::skip]
	fn reject_excessively_underpaying_htlcs() {
		let chanmon_cfg = create_chanmon_cfgs(1);
		let node_cfg = create_node_cfgs(1, &chanmon_cfg);
		let node_chanmgr = create_node_chanmgrs(1, &node_cfg, &[None]);
		let node = create_network(1, &node_cfg, &node_chanmgr);
		let sender_intended_amt_msat = 100;
		let extra_fee_msat = 10;
		let hop_data = onion_utils::Hop::Receive {
			hop_data: msgs::InboundOnionReceivePayload {
				sender_intended_htlc_amt_msat: 100,
				cltv_expiry_height: 42,
				payment_metadata: None,
				keysend_preimage: None,
				payment_data: Some(msgs::FinalOnionHopData {
					payment_secret: PaymentSecret([0; 32]),
					total_msat: sender_intended_amt_msat,
				}),
				custom_tlvs: Vec::new(),
			},
			shared_secret: SharedSecret::from_bytes([0; 32]),
		};
		// Check that if the amount we received + the penultimate hop extra fee is less than the sender
		// intended amount, we fail the payment.
		let current_height: u32 = node[0].node.best_block.read().unwrap().height;
		if let Err(crate::ln::channelmanager::InboundHTLCErr { reason, .. }) =
			create_recv_pending_htlc_info(hop_data, [0; 32], PaymentHash([0; 32]),
				sender_intended_amt_msat - extra_fee_msat - 1, 42, None, true, Some(extra_fee_msat),
				false, current_height)
		{
			assert_eq!(reason, LocalHTLCFailureReason::FinalIncorrectHTLCAmount);
		} else { panic!(); }

		// If amt_received + extra_fee is equal to the sender intended amount, we're fine.
		let hop_data = onion_utils::Hop::Receive {
			hop_data: msgs::InboundOnionReceivePayload { // This is the same payload as above, InboundOnionPayload doesn't implement Clone
				sender_intended_htlc_amt_msat: 100,
				cltv_expiry_height: 42,
				payment_metadata: None,
				keysend_preimage: None,
				payment_data: Some(msgs::FinalOnionHopData {
					payment_secret: PaymentSecret([0; 32]),
					total_msat: sender_intended_amt_msat,
				}),
				custom_tlvs: Vec::new(),
			},
			shared_secret: SharedSecret::from_bytes([0; 32]),
		};
		let current_height: u32 = node[0].node.best_block.read().unwrap().height;
		assert!(create_recv_pending_htlc_info(hop_data, [0; 32], PaymentHash([0; 32]),
			sender_intended_amt_msat - extra_fee_msat, 42, None, true, Some(extra_fee_msat),
			false, current_height).is_ok());
	}

	#[test]
	#[rustfmt::skip]
	fn test_final_incorrect_cltv(){
		let chanmon_cfg = create_chanmon_cfgs(1);
		let node_cfg = create_node_cfgs(1, &chanmon_cfg);
		let node_chanmgr = create_node_chanmgrs(1, &node_cfg, &[None]);
		let node = create_network(1, &node_cfg, &node_chanmgr);

		let current_height: u32 = node[0].node.best_block.read().unwrap().height;
		let result = create_recv_pending_htlc_info(onion_utils::Hop::Receive {
			hop_data: msgs::InboundOnionReceivePayload {
				sender_intended_htlc_amt_msat: 100,
				cltv_expiry_height: TEST_FINAL_CLTV,
				payment_metadata: None,
				keysend_preimage: None,
				payment_data: Some(msgs::FinalOnionHopData {
					payment_secret: PaymentSecret([0; 32]),
					total_msat: 100,
				}),
				custom_tlvs: Vec::new(),
			},
			shared_secret: SharedSecret::from_bytes([0; 32]),
		}, [0; 32], PaymentHash([0; 32]), 100, TEST_FINAL_CLTV + 1, None, true, None, false, current_height);

		// Should not return an error as this condition:
		// https://github.com/lightning/bolts/blob/4dcc377209509b13cf89a4b91fde7d478f5b46d8/04-onion-routing.md?plain=1#L334
		// is not satisfied.
		assert!(result.is_ok());
	}

	#[test]
	#[rustfmt::skip]
	fn test_update_channel_config() {
		let chanmon_cfg = create_chanmon_cfgs(2);
		let node_cfg = create_node_cfgs(2, &chanmon_cfg);
		let mut user_config = test_default_channel_config();
		let node_chanmgr = create_node_chanmgrs(2, &node_cfg, &[Some(user_config.clone()), Some(user_config.clone())]);
		let nodes = create_network(2, &node_cfg, &node_chanmgr);
		let _ = create_announced_chan_between_nodes(&nodes, 0, 1);
		let channel = &nodes[0].node.list_channels()[0];

		nodes[0].node.update_channel_config(&channel.counterparty.node_id, &[channel.channel_id], &user_config.channel_config).unwrap();
		let events = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 0);

		user_config.channel_config.forwarding_fee_base_msat += 10;
		nodes[0].node.update_channel_config(&channel.counterparty.node_id, &[channel.channel_id], &user_config.channel_config).unwrap();
		assert_eq!(nodes[0].node.list_channels()[0].config.unwrap().forwarding_fee_base_msat, user_config.channel_config.forwarding_fee_base_msat);
		let events = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		match &events[0] {
			MessageSendEvent::BroadcastChannelUpdate { .. } => {},
			_ => panic!("expected BroadcastChannelUpdate event"),
		}

		nodes[0].node.update_partial_channel_config(&channel.counterparty.node_id, &[channel.channel_id], &ChannelConfigUpdate::default()).unwrap();
		let events = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 0);

		let new_cltv_expiry_delta = user_config.channel_config.cltv_expiry_delta + 6;
		nodes[0].node.update_partial_channel_config(&channel.counterparty.node_id, &[channel.channel_id], &ChannelConfigUpdate {
			cltv_expiry_delta: Some(new_cltv_expiry_delta),
			..Default::default()
		}).unwrap();
		assert_eq!(nodes[0].node.list_channels()[0].config.unwrap().cltv_expiry_delta, new_cltv_expiry_delta);
		let events = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		match &events[0] {
			MessageSendEvent::BroadcastChannelUpdate { .. } => {},
			_ => panic!("expected BroadcastChannelUpdate event"),
		}

		let new_fee = user_config.channel_config.forwarding_fee_proportional_millionths + 100;
		nodes[0].node.update_partial_channel_config(&channel.counterparty.node_id, &[channel.channel_id], &ChannelConfigUpdate {
			forwarding_fee_proportional_millionths: Some(new_fee),
			accept_underpaying_htlcs: Some(true),
			..Default::default()
		}).unwrap();
		assert_eq!(nodes[0].node.list_channels()[0].config.unwrap().cltv_expiry_delta, new_cltv_expiry_delta);
		assert_eq!(nodes[0].node.list_channels()[0].config.unwrap().forwarding_fee_proportional_millionths, new_fee);
		assert_eq!(nodes[0].node.list_channels()[0].config.unwrap().accept_underpaying_htlcs, true);
		let events = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		match &events[0] {
			MessageSendEvent::BroadcastChannelUpdate { .. } => {},
			_ => panic!("expected BroadcastChannelUpdate event"),
		}

		// If we provide a channel_id not associated with the peer, we should get an error and no updates
		// should be applied to ensure update atomicity as specified in the API docs.
		let bad_channel_id = ChannelId::v1_from_funding_txid(&[10; 32], 10);
		let current_fee = nodes[0].node.list_channels()[0].config.unwrap().forwarding_fee_proportional_millionths;
		let new_fee = current_fee + 100;
		assert!(
			matches!(
				nodes[0].node.update_partial_channel_config(&channel.counterparty.node_id, &[channel.channel_id, bad_channel_id], &ChannelConfigUpdate {
					forwarding_fee_proportional_millionths: Some(new_fee),
					..Default::default()
				}),
				Err(APIError::ChannelUnavailable { err: _ }),
			)
		);
		// Check that the fee hasn't changed for the channel that exists.
		assert_eq!(nodes[0].node.list_channels()[0].config.unwrap().forwarding_fee_proportional_millionths, current_fee);
		let events = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 0);
	}

	#[test]
	#[rustfmt::skip]
	fn test_payment_display() {
		let payment_id = PaymentId([42; 32]);
		assert_eq!(format!("{}", &payment_id), "2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a");
		let payment_hash = PaymentHash([42; 32]);
		assert_eq!(format!("{}", &payment_hash), "2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a");
		let payment_preimage = PaymentPreimage([42; 32]);
		assert_eq!(format!("{}", &payment_preimage), "2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a");
	}

	#[test]
	#[rustfmt::skip]
	fn test_trigger_lnd_force_close() {
		let chanmon_cfg = create_chanmon_cfgs(2);
		let node_cfg = create_node_cfgs(2, &chanmon_cfg);
		let user_config = test_legacy_channel_config();
		let node_chanmgr = create_node_chanmgrs(2, &node_cfg, &[Some(user_config.clone()), Some(user_config)]);
		let nodes = create_network(2, &node_cfg, &node_chanmgr);
		let message = "Channel force-closed".to_owned();

		// Open a channel, immediately disconnect each other, and broadcast Alice's latest state.
		let (_, _, chan_id, funding_tx) = create_announced_chan_between_nodes(&nodes, 0, 1);
		nodes[0].node.peer_disconnected(nodes[1].node.get_our_node_id());
		nodes[1].node.peer_disconnected(nodes[0].node.get_our_node_id());
		nodes[0]
			.node
			.force_close_broadcasting_latest_txn(&chan_id, &nodes[1].node.get_our_node_id(), message.clone())
			.unwrap();
		check_closed_broadcast(&nodes[0], 1, false);
		check_added_monitors(&nodes[0], 1);
		let reason = ClosureReason::HolderForceClosed { broadcasted_latest_txn: Some(true), message };
		check_closed_event(&nodes[0], 1, reason, &[nodes[1].node.get_our_node_id()], 100000);
		{
			let txn = nodes[0].tx_broadcaster.txn_broadcast();
			assert_eq!(txn.len(), 1);
			check_spends!(txn[0], funding_tx);
		}

		// Since they're disconnected, Bob won't receive Alice's `Error` message. Reconnect them
		// such that Bob sends a `ChannelReestablish` to Alice since the channel is still open from
		// their side.
		nodes[0].node.peer_connected(nodes[1].node.get_our_node_id(), &msgs::Init {
			features: nodes[1].node.init_features(), networks: None, remote_network_address: None
		}, true).unwrap();
		nodes[1].node.peer_connected(nodes[0].node.get_our_node_id(), &msgs::Init {
			features: nodes[0].node.init_features(), networks: None, remote_network_address: None
		}, false).unwrap();
		assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
		let channel_reestablish = get_event_msg!(
			nodes[1], MessageSendEvent::SendChannelReestablish, nodes[0].node.get_our_node_id()
		);
		nodes[0].node.handle_channel_reestablish(nodes[1].node.get_our_node_id(), &channel_reestablish);

		// Alice should respond with an error since the channel isn't known, but a bogus
		// `ChannelReestablish` should be sent first, such that we actually trigger Bob to force
		// close even if it was an lnd node.
		let msg_events = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(msg_events.len(), 2);
		if let MessageSendEvent::SendChannelReestablish { node_id, msg } = &msg_events[0] {
			assert_eq!(*node_id, nodes[1].node.get_our_node_id());
			assert_eq!(msg.next_local_commitment_number, 0);
			assert_eq!(msg.next_remote_commitment_number, 0);
			nodes[1].node.handle_channel_reestablish(nodes[0].node.get_our_node_id(), &msg);
		} else { panic!() };
		check_closed_broadcast(&nodes[1], 1, true);
		check_added_monitors(&nodes[1], 1);
		let expected_close_reason = ClosureReason::ProcessingError {
			err: "Peer sent an invalid channel_reestablish to force close in a non-standard way".to_string()
		};
		check_closed_event(&nodes[1], 1, expected_close_reason, &[nodes[0].node.get_our_node_id()], 100000);
		{
			let txn = nodes[1].tx_broadcaster.txn_broadcast();
			assert_eq!(txn.len(), 1);
			check_spends!(txn[0], funding_tx);
		}
	}
}

#[cfg(ldk_bench)]
pub mod bench {
	use crate::chain::chainmonitor::{ChainMonitor, Persist};
	use crate::chain::Listen;
	use crate::events::Event;
	use crate::ln::channelmanager::{
		BestBlock, ChainParameters, ChannelManager, PaymentHash, PaymentId, PaymentPreimage,
		RecipientOnionFields, Retry,
	};
	use crate::ln::functional_test_utils::*;
	use crate::ln::msgs::{BaseMessageHandler, ChannelMessageHandler, Init, MessageSendEvent};
	use crate::routing::gossip::NetworkGraph;
	use crate::routing::router::{PaymentParameters, RouteParameters};
	use crate::sign::{InMemorySigner, KeysManager, NodeSigner};
	use crate::util::config::{MaxDustHTLCExposure, UserConfig};
	use crate::util::test_utils;

	use bitcoin::amount::Amount;
	use bitcoin::hashes::sha256::Hash as Sha256;
	use bitcoin::hashes::Hash;
	use bitcoin::locktime::absolute::LockTime;
	use bitcoin::transaction::Version;
	use bitcoin::{Transaction, TxOut};

	use crate::sync::{Arc, RwLock};

	use criterion::Criterion;

	type Manager<'a, P> = ChannelManager<
		&'a ChainMonitor<
			InMemorySigner,
			&'a test_utils::TestChainSource,
			&'a test_utils::TestBroadcaster,
			&'a test_utils::TestFeeEstimator,
			&'a test_utils::TestLogger,
			&'a P,
			&'a KeysManager,
		>,
		&'a test_utils::TestBroadcaster,
		&'a KeysManager,
		&'a KeysManager,
		&'a KeysManager,
		&'a test_utils::TestFeeEstimator,
		&'a test_utils::TestRouter<'a>,
		&'a test_utils::TestMessageRouter<'a>,
		&'a test_utils::TestLogger,
	>;

	struct ANodeHolder<'node_cfg, 'chan_mon_cfg: 'node_cfg, P: Persist<InMemorySigner>> {
		node: &'node_cfg Manager<'chan_mon_cfg, P>,
	}
	impl<'node_cfg, 'chan_mon_cfg: 'node_cfg, P: Persist<InMemorySigner>> NodeHolder
		for ANodeHolder<'node_cfg, 'chan_mon_cfg, P>
	{
		type CM = Manager<'chan_mon_cfg, P>;
		#[inline]
		#[rustfmt::skip]
		fn node(&self) -> &Manager<'chan_mon_cfg, P> { self.node }
		#[inline]
		#[rustfmt::skip]
		fn chain_monitor(&self) -> Option<&test_utils::TestChainMonitor> { None }
	}

	#[rustfmt::skip]
	pub fn bench_sends(bench: &mut Criterion) {
		bench_two_sends(bench, "bench_sends", test_utils::TestPersister::new(), test_utils::TestPersister::new());
	}

	#[rustfmt::skip]
	pub fn bench_two_sends<P: Persist<InMemorySigner>>(bench: &mut Criterion, bench_name: &str, persister_a: P, persister_b: P) {
		// Do a simple benchmark of sending a payment back and forth between two nodes.
		// Note that this is unrealistic as each payment send will require at least two fsync
		// calls per node.
		let network = bitcoin::Network::Testnet;
		let genesis_block = bitcoin::constants::genesis_block(network);

		let tx_broadcaster = test_utils::TestBroadcaster::new(network);
		let fee_estimator = test_utils::TestFeeEstimator::new(253);
		let logger_a = test_utils::TestLogger::with_id("node a".to_owned());
		let scorer = RwLock::new(test_utils::TestScorer::new());
		let entropy = test_utils::TestKeysInterface::new(&[0u8; 32], network);
		let router = test_utils::TestRouter::new(Arc::new(NetworkGraph::new(network, &logger_a)), &logger_a, &scorer);
		let message_router = test_utils::TestMessageRouter::new_default(Arc::new(NetworkGraph::new(network, &logger_a)), &entropy);

		let mut config: UserConfig = Default::default();
		config.channel_config.max_dust_htlc_exposure = MaxDustHTLCExposure::FeeRateMultiplier(5_000_000 / 253);
		config.channel_handshake_config.minimum_depth = 1;

		let seed_a = [1u8; 32];
		let keys_manager_a = KeysManager::new(&seed_a, 42, 42, true);
		let chain_monitor_a = ChainMonitor::new(None, &tx_broadcaster, &logger_a, &fee_estimator, &persister_a, &keys_manager_a, keys_manager_a.get_peer_storage_key(), false);
		let node_a = ChannelManager::new(&fee_estimator, &chain_monitor_a, &tx_broadcaster, &router, &message_router, &logger_a, &keys_manager_a, &keys_manager_a, &keys_manager_a, config.clone(), ChainParameters {
			network,
			best_block: BestBlock::from_network(network),
		}, genesis_block.header.time);
		let node_a_holder = ANodeHolder { node: &node_a };

		let logger_b = test_utils::TestLogger::with_id("node a".to_owned());
		let seed_b = [2u8; 32];
		let keys_manager_b = KeysManager::new(&seed_b, 42, 42, true);
		let chain_monitor_b = ChainMonitor::new(None, &tx_broadcaster, &logger_a, &fee_estimator, &persister_b, &keys_manager_b, keys_manager_b.get_peer_storage_key(), false);
		let node_b = ChannelManager::new(&fee_estimator, &chain_monitor_b, &tx_broadcaster, &router, &message_router, &logger_b, &keys_manager_b, &keys_manager_b, &keys_manager_b, config.clone(), ChainParameters {
			network,
			best_block: BestBlock::from_network(network),
		}, genesis_block.header.time);
		let node_b_holder = ANodeHolder { node: &node_b };

		node_a.peer_connected(node_b.get_our_node_id(), &Init {
			features: node_b.init_features(), networks: None, remote_network_address: None
		}, true).unwrap();
		node_b.peer_connected(node_a.get_our_node_id(), &Init {
			features: node_a.init_features(), networks: None, remote_network_address: None
		}, false).unwrap();
		node_a.create_channel(node_b.get_our_node_id(), 8_000_000, 100_000_000, 42, None, None).unwrap();
		node_b.handle_open_channel(node_a.get_our_node_id(), &get_event_msg!(node_a_holder, MessageSendEvent::SendOpenChannel, node_b.get_our_node_id()));
		let events = node_b.get_and_clear_pending_events();
		assert_eq!(events.len(), 1);
		match &events[0] {
			Event::OpenChannelRequest { temporary_channel_id, counterparty_node_id, .. } => {
				node_b
					.accept_inbound_channel(temporary_channel_id, counterparty_node_id, 42, None)
					.unwrap();
			},
			_ => panic!("Unexpected event"),
		};
		node_a.handle_accept_channel(node_b.get_our_node_id(), &get_event_msg!(node_b_holder, MessageSendEvent::SendAcceptChannel, node_a.get_our_node_id()));

		let tx;
		if let Event::FundingGenerationReady { temporary_channel_id, output_script, .. } = get_event!(node_a_holder, Event::FundingGenerationReady) {
			tx = Transaction { version: Version::TWO, lock_time: LockTime::ZERO, input: Vec::new(), output: vec![TxOut {
				value: Amount::from_sat(8_000_000), script_pubkey: output_script,
			}]};
			node_a.funding_transaction_generated(temporary_channel_id, node_b.get_our_node_id(), tx.clone()).unwrap();
		} else { panic!(); }

		node_b.handle_funding_created(node_a.get_our_node_id(), &get_event_msg!(node_a_holder, MessageSendEvent::SendFundingCreated, node_b.get_our_node_id()));
		let events_b = node_b.get_and_clear_pending_events();
		assert_eq!(events_b.len(), 1);
		match events_b[0] {
			Event::ChannelPending{ ref counterparty_node_id, .. } => {
				assert_eq!(*counterparty_node_id, node_a.get_our_node_id());
			},
			_ => panic!("Unexpected event"),
		}

		node_a.handle_funding_signed(node_b.get_our_node_id(), &get_event_msg!(node_b_holder, MessageSendEvent::SendFundingSigned, node_a.get_our_node_id()));
		let events_a = node_a.get_and_clear_pending_events();
		assert_eq!(events_a.len(), 1);
		match events_a[0] {
			Event::ChannelPending{ ref counterparty_node_id, .. } => {
				assert_eq!(*counterparty_node_id, node_b.get_our_node_id());
			},
			_ => panic!("Unexpected event"),
		}

		assert_eq!(&tx_broadcaster.txn_broadcasted.lock().unwrap()[..], &[tx.clone()]);

		let block = create_dummy_block(BestBlock::from_network(network).block_hash, 42, vec![tx]);
		Listen::block_connected(&node_a, &block, 1);
		Listen::block_connected(&node_b, &block, 1);

		node_a.handle_channel_ready(node_b.get_our_node_id(), &get_event_msg!(node_b_holder, MessageSendEvent::SendChannelReady, node_a.get_our_node_id()));
		let msg_events = node_a.get_and_clear_pending_msg_events();
		assert_eq!(msg_events.len(), 2);
		match msg_events[0] {
			MessageSendEvent::SendChannelReady { ref msg, .. } => {
				node_b.handle_channel_ready(node_a.get_our_node_id(), msg);
				get_event_msg!(node_b_holder, MessageSendEvent::SendChannelUpdate, node_a.get_our_node_id());
			},
			_ => panic!(),
		}
		match msg_events[1] {
			MessageSendEvent::SendChannelUpdate { .. } => {},
			_ => panic!(),
		}

		let events_a = node_a.get_and_clear_pending_events();
		assert_eq!(events_a.len(), 1);
		match events_a[0] {
			Event::ChannelReady{ ref counterparty_node_id, .. } => {
				assert_eq!(*counterparty_node_id, node_b.get_our_node_id());
			},
			_ => panic!("Unexpected event"),
		}

		let events_b = node_b.get_and_clear_pending_events();
		assert_eq!(events_b.len(), 1);
		match events_b[0] {
			Event::ChannelReady{ ref counterparty_node_id, .. } => {
				assert_eq!(*counterparty_node_id, node_a.get_our_node_id());
			},
			_ => panic!("Unexpected event"),
		}

		let mut payment_count: u64 = 0;
		macro_rules! send_payment {
			($node_a: expr, $node_b: expr) => {
				let payment_params = PaymentParameters::from_node_id($node_b.get_our_node_id(), TEST_FINAL_CLTV)
					.with_bolt11_features($node_b.bolt11_invoice_features()).unwrap();
				let mut payment_preimage = PaymentPreimage([0; 32]);
				payment_preimage.0[0..8].copy_from_slice(&payment_count.to_le_bytes());
				payment_count += 1;
				let payment_hash = PaymentHash(Sha256::hash(&payment_preimage.0[..]).to_byte_array());
				let payment_secret = $node_b.create_inbound_payment_for_hash(payment_hash, None, 7200, None).unwrap();

				$node_a.send_payment(payment_hash, RecipientOnionFields::secret_only(payment_secret),
					PaymentId(payment_hash.0),
					RouteParameters::from_payment_params_and_value(payment_params, 10_000),
					Retry::Attempts(0)).unwrap();
				let payment_event = SendEvent::from_event($node_a.get_and_clear_pending_msg_events().pop().unwrap());
				$node_b.handle_update_add_htlc($node_a.get_our_node_id(), &payment_event.msgs[0]);
				$node_b.handle_commitment_signed_batch_test($node_a.get_our_node_id(), &payment_event.commitment_msg);
				let (raa, cs) = get_revoke_commit_msgs(&ANodeHolder { node: &$node_b }, &$node_a.get_our_node_id());
				$node_a.handle_revoke_and_ack($node_b.get_our_node_id(), &raa);
				$node_a.handle_commitment_signed_batch_test($node_b.get_our_node_id(), &cs);
				$node_b.handle_revoke_and_ack($node_a.get_our_node_id(), &get_event_msg!(ANodeHolder { node: &$node_a }, MessageSendEvent::SendRevokeAndACK, $node_b.get_our_node_id()));

				$node_b.process_pending_htlc_forwards();
				expect_payment_claimable!(ANodeHolder { node: &$node_b }, payment_hash, payment_secret, 10_000);
				$node_b.claim_funds(payment_preimage);
				expect_payment_claimed!(ANodeHolder { node: &$node_b }, payment_hash, 10_000);

				match $node_b.get_and_clear_pending_msg_events().pop().unwrap() {
					MessageSendEvent::UpdateHTLCs { node_id, mut updates, .. } => {
						assert_eq!(node_id, $node_a.get_our_node_id());
						let fulfill = updates.update_fulfill_htlcs.remove(0);
						$node_a.handle_update_fulfill_htlc($node_b.get_our_node_id(), fulfill);
						$node_a.handle_commitment_signed_batch_test($node_b.get_our_node_id(), &updates.commitment_signed);
					},
					_ => panic!("Failed to generate claim event"),
				}

				let (raa, cs) = get_revoke_commit_msgs(&ANodeHolder { node: &$node_a }, &$node_b.get_our_node_id());
				$node_b.handle_revoke_and_ack($node_a.get_our_node_id(), &raa);
				$node_b.handle_commitment_signed_batch_test($node_a.get_our_node_id(), &cs);
				$node_a.handle_revoke_and_ack($node_b.get_our_node_id(), &get_event_msg!(ANodeHolder { node: &$node_b }, MessageSendEvent::SendRevokeAndACK, $node_a.get_our_node_id()));

				expect_payment_sent!(ANodeHolder { node: &$node_a }, payment_preimage);
			}
		}

		bench.bench_function(bench_name, |b| b.iter(|| {
			send_payment!(node_a, node_b);
			send_payment!(node_b, node_a);
		}));
	}
}
