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

use bitcoin::blockdata::block::Header;
use bitcoin::blockdata::transaction::Transaction;
use bitcoin::blockdata::constants::ChainHash;
use bitcoin::key::constants::SECRET_KEY_SIZE;
use bitcoin::network::constants::Network;

use bitcoin::hashes::Hash;
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hash_types::{BlockHash, Txid};

use bitcoin::secp256k1::{SecretKey,PublicKey};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{secp256k1, Sequence};

use crate::blinded_path::{BlindedPath, NodeIdLookUp};
use crate::blinded_path::payment::{PaymentConstraints, ReceiveTlvs};
use crate::chain;
use crate::chain::{Confirm, ChannelMonitorUpdateStatus, Watch, BestBlock};
use crate::chain::chaininterface::{BroadcasterInterface, ConfirmationTarget, FeeEstimator, LowerBoundedFeeEstimator};
use crate::chain::channelmonitor::{ChannelMonitor, ChannelMonitorUpdate, WithChannelMonitor, ChannelMonitorUpdateStep, HTLC_FAIL_BACK_BUFFER, CLTV_CLAIM_BUFFER, LATENCY_GRACE_PERIOD_BLOCKS, ANTI_REORG_DELAY, MonitorEvent, CLOSED_CHANNEL_UPDATE_ID};
use crate::chain::transaction::{OutPoint, TransactionData};
use crate::events;
use crate::events::{Event, EventHandler, EventsProvider, MessageSendEvent, MessageSendEventsProvider, ClosureReason, HTLCDestination, PaymentFailureReason};
// Since this struct is returned in `list_channels` methods, expose it here in case users want to
// construct one themselves.
use crate::ln::{inbound_payment, ChannelId, PaymentHash, PaymentPreimage, PaymentSecret};
use crate::ln::channel::{self, Channel, ChannelPhase, ChannelContext, ChannelError, ChannelUpdateStatus, ShutdownResult, UnfundedChannelContext, UpdateFulfillCommitFetch, OutboundV1Channel, InboundV1Channel, WithChannelContext};
pub use crate::ln::channel::{InboundHTLCDetails, InboundHTLCStateDetails, OutboundHTLCDetails, OutboundHTLCStateDetails};
use crate::ln::features::{Bolt12InvoiceFeatures, ChannelFeatures, ChannelTypeFeatures, InitFeatures, NodeFeatures};
#[cfg(any(feature = "_test_utils", test))]
use crate::ln::features::Bolt11InvoiceFeatures;
use crate::routing::router::{BlindedTail, InFlightHtlcs, Path, Payee, PaymentParameters, Route, RouteParameters, Router};
use crate::ln::onion_payment::{check_incoming_htlc_cltv, create_recv_pending_htlc_info, create_fwd_pending_htlc_info, decode_incoming_update_add_htlc_onion, InboundHTLCErr, NextPacketDetails};
use crate::ln::msgs;
use crate::ln::onion_utils;
use crate::ln::onion_utils::{HTLCFailReason, INVALID_ONION_BLINDING};
use crate::ln::msgs::{ChannelMessageHandler, DecodeError, LightningError};
#[cfg(test)]
use crate::ln::outbound_payment;
use crate::ln::outbound_payment::{Bolt12PaymentError, OutboundPayments, PaymentAttempts, PendingOutboundPayment, SendAlongPathArgs, StaleExpiration};
use crate::ln::wire::Encode;
use crate::offers::invoice::{BlindedPayInfo, Bolt12Invoice, DEFAULT_RELATIVE_EXPIRY, DerivedSigningPubkey, ExplicitSigningPubkey, InvoiceBuilder, UnsignedBolt12Invoice};
use crate::offers::invoice_error::InvoiceError;
use crate::offers::invoice_request::{DerivedPayerId, InvoiceRequestBuilder};
use crate::offers::offer::{Offer, OfferBuilder};
use crate::offers::parse::Bolt12SemanticError;
use crate::offers::refund::{Refund, RefundBuilder};
use crate::onion_message::messenger::{Destination, MessageRouter, PendingOnionMessage, new_pending_onion_message};
use crate::onion_message::offers::{OffersMessage, OffersMessageHandler};
use crate::sign::{EntropySource, NodeSigner, Recipient, SignerProvider};
use crate::sign::ecdsa::WriteableEcdsaChannelSigner;
use crate::util::config::{UserConfig, ChannelConfig, ChannelConfigUpdate};
use crate::util::wakers::{Future, Notifier};
use crate::util::scid_utils::fake_scid;
use crate::util::string::UntrustedString;
use crate::util::ser::{BigSize, FixedLengthReader, Readable, ReadableArgs, MaybeReadable, Writeable, Writer, VecWriter};
use crate::util::logger::{Level, Logger, WithContext};
use crate::util::errors::APIError;
#[cfg(not(c_bindings))]
use {
	crate::offers::offer::DerivedMetadata,
	crate::routing::router::DefaultRouter,
	crate::routing::gossip::NetworkGraph,
	crate::routing::scoring::{ProbabilisticScorer, ProbabilisticScoringFeeParameters},
	crate::sign::KeysManager,
};
#[cfg(c_bindings)]
use {
	crate::offers::offer::OfferWithDerivedMetadataBuilder,
	crate::offers::refund::RefundMaybeWithDerivedMetadataBuilder,
};

use alloc::collections::{btree_map, BTreeMap};

use crate::io;
use crate::prelude::*;
use core::{cmp, mem};
use core::cell::RefCell;
use crate::io::Read;
use crate::sync::{Arc, Mutex, RwLock, RwLockReadGuard, FairRwLock, LockTestExt, LockHeldState};
use core::sync::atomic::{AtomicUsize, AtomicBool, Ordering};
use core::time::Duration;
use core::ops::Deref;

// Re-export this for use in the public API.
pub use crate::ln::outbound_payment::{PaymentSendFailure, ProbeSendFailure, Retry, RetryableSendFailure, RecipientOnionFields};
use crate::ln::script::ShutdownScript;

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
#[derive(Clone)] // See Channel::revoke_and_ack for why, tl;dr: Rust bug
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
		/// CLTV expiry of the received HTLC.
		///
		/// Used to track when we should expire pending HTLCs that go unclaimed.
		incoming_cltv_expiry: u32,
		/// If the onion had forwarding instructions to one of our phantom node SCIDs, this will
		/// provide the onion shared secret used to decrypt the next level of forwarding
		/// instructions.
		phantom_shared_secret: Option<[u8; 32]>,
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
}

impl PendingHTLCRouting {
	// Used to override the onion failure code and data if the HTLC is blinded.
	fn blinded_failure(&self) -> Option<BlindedFailure> {
		match self {
			Self::Forward { blinded: Some(BlindedForward { failure, .. }), .. } => Some(*failure),
			Self::Receive { requires_blinded_error: true, .. } => Some(BlindedFailure::FromBlindedNode),
			Self::ReceiveKeysend { requires_blinded_error: true, .. } => Some(BlindedFailure::FromBlindedNode),
			_ => None,
		}
	}
}

/// Information about an incoming HTLC, including the [`PendingHTLCRouting`] describing where it
/// should go next.
#[derive(Clone)] // See Channel::revoke_and_ack for why, tl;dr: Rust bug
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
}

#[derive(Clone)] // See Channel::revoke_and_ack for why, tl;dr: Rust bug
pub(super) enum HTLCFailureMsg {
	Relay(msgs::UpdateFailHTLC),
	Malformed(msgs::UpdateFailMalformedHTLC),
}

/// Stores whether we can't forward an HTLC or relevant forwarding info
#[derive(Clone)] // See Channel::revoke_and_ack for why, tl;dr: Rust bug
pub(super) enum PendingHTLCStatus {
	Forward(PendingHTLCInfo),
	Fail(HTLCFailureMsg),
}

#[cfg_attr(test, derive(Clone, Debug, PartialEq))]
pub(super) struct PendingAddHTLCInfo {
	pub(super) forward_info: PendingHTLCInfo,

	// These fields are produced in `forward_htlcs()` and consumed in
	// `process_pending_htlc_forwards()` for constructing the
	// `HTLCSource::PreviousHopData` for failed and forwarded
	// HTLCs.
	//
	// Note that this may be an outbound SCID alias for the associated channel.
	prev_short_channel_id: u64,
	prev_htlc_id: u64,
	prev_channel_id: ChannelId,
	prev_funding_outpoint: OutPoint,
	prev_user_channel_id: u128,
}

#[cfg_attr(test, derive(Clone, Debug, PartialEq))]
pub(super) enum HTLCForwardInfo {
	AddHTLC(PendingAddHTLCInfo),
	FailHTLC {
		htlc_id: u64,
		err_packet: msgs::OnionErrorPacket,
	},
	FailMalformedHTLC {
		htlc_id: u64,
		failure_code: u16,
		sha256_of_onion: [u8; 32],
	},
}

/// Whether this blinded HTLC is being failed backwards by the introduction node or a blinded node,
/// which determines the failure message that should be used.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub enum BlindedFailure {
	/// This HTLC is being failed backwards by the introduction node, and thus should be failed with
	/// [`msgs::UpdateFailHTLC`] and error code `0x8000|0x4000|24`.
	FromIntroductionNode,
	/// This HTLC is being failed backwards by a blinded node within the path, and thus should be
	/// failed with [`msgs::UpdateFailMalformedHTLC`] and error code `0x8000|0x4000|24`.
	FromBlindedNode,
}

/// Tracks the inbound corresponding to an outbound HTLC
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub(crate) struct HTLCPreviousHopData {
	// Note that this may be an outbound SCID alias for the associated channel.
	short_channel_id: u64,
	user_channel_id: Option<u128>,
	htlc_id: u64,
	incoming_packet_shared_secret: [u8; 32],
	phantom_shared_secret: Option<[u8; 32]>,
	blinded_failure: Option<BlindedFailure>,
	channel_id: ChannelId,

	// This field is consumed by `claim_funds_from_hop()` when updating a force-closed backwards
	// channel with a preimage provided by the forward channel.
	outpoint: OutPoint,
}

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
			channel_id: val.prev_hop.channel_id,
			user_channel_id: val.prev_hop.user_channel_id.unwrap_or(0),
			cltv_expiry: val.cltv_expiry,
			value_msat: val.value,
			counterparty_skimmed_fee_msat: val.counterparty_skimmed_fee_msat.unwrap_or(0),
		}
	}
}

/// A user-provided identifier in [`ChannelManager::send_payment`] used to uniquely identify
/// a payment and ensure idempotency in LDK.
///
/// This is not exported to bindings users as we just use [u8; 32] directly
#[derive(Hash, Copy, Clone, PartialEq, Eq, Debug)]
pub struct PaymentId(pub [u8; Self::LENGTH]);

impl PaymentId {
	/// Number of bytes in the id.
	pub const LENGTH: usize = 32;
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

impl core::fmt::Display for PaymentId {
	fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
		crate::util::logger::DebugBytes(&self.0).fmt(f)
	}
}

/// An identifier used to uniquely identify an intercepted HTLC to LDK.
///
/// This is not exported to bindings users as we just use [u8; 32] directly
#[derive(Hash, Copy, Clone, PartialEq, Eq, Debug)]
pub struct InterceptId(pub [u8; 32]);

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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
/// Uniquely describes an HTLC by its source. Just the guaranteed-unique subset of [`HTLCSource`].
pub(crate) enum SentHTLCId {
	PreviousHopData { short_channel_id: u64, htlc_id: u64 },
	OutboundRoute { session_priv: [u8; SECRET_KEY_SIZE] },
}
impl SentHTLCId {
	pub(crate) fn from_source(source: &HTLCSource) -> Self {
		match source {
			HTLCSource::PreviousHopData(hop_data) => Self::PreviousHopData {
				short_channel_id: hop_data.short_channel_id,
				htlc_id: hop_data.htlc_id,
			},
			HTLCSource::OutboundRoute { session_priv, .. } =>
				Self::OutboundRoute { session_priv: session_priv.secret_bytes() },
		}
	}
}
impl_writeable_tlv_based_enum!(SentHTLCId,
	(0, PreviousHopData) => {
		(0, short_channel_id, required),
		(2, htlc_id, required),
	},
	(2, OutboundRoute) => {
		(0, session_priv, required),
	};
);


/// Tracks the inbound corresponding to an outbound HTLC
#[allow(clippy::derive_hash_xor_eq)] // Our Hash is faithful to the data, we just don't have SecretKey::hash
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum HTLCSource {
	PreviousHopData(HTLCPreviousHopData),
	OutboundRoute {
		path: Path,
		session_priv: SecretKey,
		/// Technically we can recalculate this from the route, but we cache it here to avoid
		/// doing a double-pass on route when we get a failure back
		first_hop_htlc_msat: u64,
		payment_id: PaymentId,
	},
}
#[allow(clippy::derive_hash_xor_eq)] // Our Hash is faithful to the data, we just don't have SecretKey::hash
impl core::hash::Hash for HTLCSource {
	fn hash<H: core::hash::Hasher>(&self, hasher: &mut H) {
		match self {
			HTLCSource::PreviousHopData(prev_hop_data) => {
				0u8.hash(hasher);
				prev_hop_data.hash(hasher);
			},
			HTLCSource::OutboundRoute { path, session_priv, payment_id, first_hop_htlc_msat } => {
				1u8.hash(hasher);
				path.hash(hasher);
				session_priv[..].hash(hasher);
				payment_id.hash(hasher);
				first_hop_htlc_msat.hash(hasher);
			},
		}
	}
}
impl HTLCSource {
	#[cfg(all(feature = "_test_vectors", not(feature = "grind_signatures")))]
	#[cfg(test)]
	pub fn dummy() -> Self {
		HTLCSource::OutboundRoute {
			path: Path { hops: Vec::new(), blinded_tail: None },
			session_priv: SecretKey::from_slice(&[1; 32]).unwrap(),
			first_hop_htlc_msat: 0,
			payment_id: PaymentId([2; 32]),
		}
	}

	#[cfg(debug_assertions)]
	/// Checks whether this HTLCSource could possibly match the given HTLC output in a commitment
	/// transaction. Useful to ensure different datastructures match up.
	pub(crate) fn possibly_matches_output(&self, htlc: &super::chan_utils::HTLCOutputInCommitment) -> bool {
		if let HTLCSource::OutboundRoute { first_hop_htlc_msat, .. } = self {
			*first_hop_htlc_msat == htlc.amount_msat
		} else {
			// There's nothing we can check for forwarded HTLCs
			true
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

impl Into<u16> for FailureCode {
    fn into(self) -> u16 {
		match self {
			FailureCode::TemporaryNodeFailure => 0x2000 | 2,
			FailureCode::RequiredNodeFeatureMissing => 0x4000 | 0x2000 | 3,
			FailureCode::IncorrectOrUnknownPaymentDetails => 0x4000 | 15,
			FailureCode::InvalidOnionPayload(_) => 0x4000 | 22,
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
	shutdown_finish: Option<(ShutdownResult, Option<msgs::ChannelUpdate>)>,
}
impl MsgHandleErrInternal {
	#[inline]
	fn send_err_msg_no_close(err: String, channel_id: ChannelId) -> Self {
		Self {
			err: LightningError {
				err: err.clone(),
				action: msgs::ErrorAction::SendErrorMessage {
					msg: msgs::ErrorMessage {
						channel_id,
						data: err
					},
				},
			},
			closes_channel: false,
			shutdown_finish: None,
		}
	}
	#[inline]
	fn from_no_close(err: msgs::LightningError) -> Self {
		Self { err, closes_channel: false, shutdown_finish: None }
	}
	#[inline]
	fn from_finish_shutdown(err: String, channel_id: ChannelId, shutdown_res: ShutdownResult, channel_update: Option<msgs::ChannelUpdate>) -> Self {
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
		}
	}
	#[inline]
	fn from_chan_no_close(err: ChannelError, channel_id: ChannelId) -> Self {
		Self {
			err: match err {
				ChannelError::Warn(msg) =>  LightningError {
					err: msg.clone(),
					action: msgs::ErrorAction::SendWarningMessage {
						msg: msgs::WarningMessage {
							channel_id,
							data: msg
						},
						log_level: Level::Warn,
					},
				},
				ChannelError::Ignore(msg) => LightningError {
					err: msg,
					action: msgs::ErrorAction::IgnoreError,
				},
				ChannelError::Close(msg) => LightningError {
					err: msg.clone(),
					action: msgs::ErrorAction::SendErrorMessage {
						msg: msgs::ErrorMessage {
							channel_id,
							data: msg
						},
					},
				},
			},
			closes_channel: false,
			shutdown_finish: None,
		}
	}

	fn closes_channel(&self) -> bool {
		self.closes_channel
	}
}

/// We hold back HTLCs we intend to relay for a random interval greater than this (see
/// Event::PendingHTLCsForwardable for the API guidelines indicating how long should be waited).
/// This provides some limited amount of privacy. Ideally this would range from somewhere like one
/// second to 30 seconds, but people expect lightning to be, you know, kinda fast, sadly.
pub(super) const MIN_HTLC_RELAY_HOLDING_CELL_MILLIS: u64 = 100;

/// For events which result in both a RevokeAndACK and a CommitmentUpdate, by default they should
/// be sent in the order they appear in the return value, however sometimes the order needs to be
/// variable at runtime (eg Channel::channel_reestablish needs to re-send messages in the order
/// they were originally sent). In those cases, this enum is also returned.
#[derive(Clone, PartialEq)]
pub(super) enum RAACommitmentOrder {
	/// Send the CommitmentUpdate messages first
	CommitmentFirst,
	/// Send the RevokeAndACK message first
	RevokeAndACKFirst,
}

/// Information about a payment which is currently being claimed.
struct ClaimingPayment {
	amount_msat: u64,
	payment_purpose: events::PaymentPurpose,
	receiver_node_id: PublicKey,
	htlcs: Vec<events::ClaimedHTLC>,
	sender_intended_value: Option<u64>,
}
impl_writeable_tlv_based!(ClaimingPayment, {
	(0, amount_msat, required),
	(2, payment_purpose, required),
	(4, receiver_node_id, required),
	(5, htlcs, optional_vec),
	(7, sender_intended_value, option),
});

struct ClaimablePayment {
	purpose: events::PaymentPurpose,
	onion_fields: Option<RecipientOnionFields>,
	htlcs: Vec<ClaimableHTLC>,
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

/// Events which we process internally but cannot be processed immediately at the generation site
/// usually because we're running pre-full-init. They are handled immediately once we detect we are
/// running normally, and specifically must be processed before any other non-background
/// [`ChannelMonitorUpdate`]s are applied.
#[derive(Debug)]
enum BackgroundEvent {
	/// Handle a ChannelMonitorUpdate which closes the channel or for an already-closed channel.
	/// This is only separated from [`Self::MonitorUpdateRegeneratedOnStartup`] as the
	/// maybe-non-closing variant needs a public key to handle channel resumption, whereas if the
	/// channel has been force-closed we do not need the counterparty node_id.
	///
	/// Note that any such events are lost on shutdown, so in general they must be updates which
	/// are regenerated on startup.
	ClosedMonitorUpdateRegeneratedOnStartup((OutPoint, ChannelId, ChannelMonitorUpdate)),
	/// Handle a ChannelMonitorUpdate which may or may not close the channel and may unblock the
	/// channel to continue normal operation.
	///
	/// In general this should be used rather than
	/// [`Self::ClosedMonitorUpdateRegeneratedOnStartup`], however in cases where the
	/// `counterparty_node_id` is not available as the channel has closed from a [`ChannelMonitor`]
	/// error the other variant is acceptable.
	///
	/// Note that any such events are lost on shutdown, so in general they must be updates which
	/// are regenerated on startup.
	MonitorUpdateRegeneratedOnStartup {
		counterparty_node_id: PublicKey,
		funding_txo: OutPoint,
		channel_id: ChannelId,
		update: ChannelMonitorUpdate
	},
	/// Some [`ChannelMonitorUpdate`] (s) completed before we were serialized but we still have
	/// them marked pending, thus we need to run any [`MonitorUpdateCompletionAction`] (s) pending
	/// on a channel.
	MonitorUpdatesComplete {
		counterparty_node_id: PublicKey,
		channel_id: ChannelId,
	},
}

#[derive(Debug)]
pub(crate) enum MonitorUpdateCompletionAction {
	/// Indicates that a payment ultimately destined for us was claimed and we should emit an
	/// [`events::Event::PaymentClaimed`] to the user if we haven't yet generated such an event for
	/// this payment. Note that this is only best-effort. On restart it's possible such a duplicate
	/// event can be generated.
	PaymentClaimed { payment_hash: PaymentHash },
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
		downstream_counterparty_and_funding_outpoint: Option<(PublicKey, OutPoint, ChannelId, RAAMonitorUpdateBlockingAction)>,
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
		downstream_funding_outpoint: OutPoint,
		blocking_action: RAAMonitorUpdateBlockingAction,
		downstream_channel_id: ChannelId,
	},
}

impl_writeable_tlv_based_enum_upgradable!(MonitorUpdateCompletionAction,
	(0, PaymentClaimed) => { (0, payment_hash, required) },
	// Note that FreeOtherChannelImmediately should never be written - we were supposed to free
	// *immediately*. However, for simplicity we implement read/write here.
	(1, FreeOtherChannelImmediately) => {
		(0, downstream_counterparty_node_id, required),
		(2, downstream_funding_outpoint, required),
		(4, blocking_action, required),
		// Note that by the time we get past the required read above, downstream_funding_outpoint will be
		// filled in, so we can safely unwrap it here.
		(5, downstream_channel_id, (default_value, ChannelId::v1_from_funding_outpoint(downstream_funding_outpoint.0.unwrap()))),
	},
	(2, EmitEventAndFreeOtherChannel) => {
		(0, event, upgradable_required),
		// LDK prior to 0.0.116 did not have this field as the monitor update application order was
		// required by clients. If we downgrade to something prior to 0.0.116 this may result in
		// monitor updates which aren't properly blocked or resumed, however that's fine - we don't
		// support async monitor updates even in LDK 0.0.116 and once we do we'll require no
		// downgrades to prior versions.
		(1, downstream_counterparty_and_funding_outpoint, option),
	},
);

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum EventCompletionAction {
	ReleaseRAAChannelMonitorUpdate {
		counterparty_node_id: PublicKey,
		channel_funding_outpoint: OutPoint,
		channel_id: ChannelId,
	},
}
impl_writeable_tlv_based_enum!(EventCompletionAction,
	(0, ReleaseRAAChannelMonitorUpdate) => {
		(0, channel_funding_outpoint, required),
		(2, counterparty_node_id, required),
		// Note that by the time we get past the required read above, channel_funding_outpoint will be
		// filled in, so we can safely unwrap it here.
		(3, channel_id, (default_value, ChannelId::v1_from_funding_outpoint(channel_funding_outpoint.0.unwrap()))),
	};
);

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
}

impl RAAMonitorUpdateBlockingAction {
	fn from_prev_hop_data(prev_hop: &HTLCPreviousHopData) -> Self {
		Self::ForwardedPaymentInboundClaim {
			channel_id: prev_hop.channel_id,
			htlc_id: prev_hop.htlc_id,
		}
	}
}

impl_writeable_tlv_based_enum!(RAAMonitorUpdateBlockingAction,
	(0, ForwardedPaymentInboundClaim) => { (0, channel_id, required), (2, htlc_id, required) }
;);


/// State we hold per-peer.
pub(super) struct PeerState<SP: Deref> where SP::Target: SignerProvider {
	/// `channel_id` -> `ChannelPhase`
	///
	/// Holds all channels within corresponding `ChannelPhase`s where the peer is the counterparty.
	pub(super) channel_by_id: HashMap<ChannelId, ChannelPhase<SP>>,
	/// `temporary_channel_id` -> `InboundChannelRequest`.
	///
	/// When manual channel acceptance is enabled, this holds all unaccepted inbound channels where
	/// the peer is the counterparty. If the channel is accepted, then the entry in this table is
	/// removed, and an InboundV1Channel is created and placed in the `inbound_v1_channel_by_id` table. If
	/// the channel is rejected, then the entry is simply removed.
	pub(super) inbound_channel_request_by_id: HashMap<ChannelId, InboundChannelRequest>,
	/// The latest `InitFeatures` we heard from the peer.
	latest_features: InitFeatures,
	/// Messages to send to the peer - pushed to in the same lock that they are generated in (except
	/// for broadcast messages, where ordering isn't as strict).
	pub(super) pending_msg_events: Vec<MessageSendEvent>,
	/// Map from Channel IDs to pending [`ChannelMonitorUpdate`]s which have been passed to the
	/// user but which have not yet completed.
	///
	/// Note that the channel may no longer exist. For example if the channel was closed but we
	/// later needed to claim an HTLC which is pending on-chain, we may generate a monitor update
	/// for a missing channel.
	in_flight_monitor_updates: BTreeMap<OutPoint, Vec<ChannelMonitorUpdate>>,
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
	monitor_update_blocked_actions: BTreeMap<ChannelId, Vec<MonitorUpdateCompletionAction>>,
	/// If another channel's [`ChannelMonitorUpdate`] needs to complete before a channel we have
	/// with this peer can complete an RAA [`ChannelMonitorUpdate`] (e.g. because the RAA update
	/// will remove a preimage that needs to be durably in an upstream channel first), we put an
	/// entry here to note that the channel with the key's ID is blocked on a set of actions.
	actions_blocking_raa_monitor_updates: BTreeMap<ChannelId, Vec<RAAMonitorUpdateBlockingAction>>,
	/// The peer is currently connected (i.e. we've seen a
	/// [`ChannelMessageHandler::peer_connected`] and no corresponding
	/// [`ChannelMessageHandler::peer_disconnected`].
	pub is_connected: bool,
}

impl <SP: Deref> PeerState<SP> where SP::Target: SignerProvider {
	/// Indicates that a peer meets the criteria where we're ok to remove it from our storage.
	/// If true is passed for `require_disconnected`, the function will return false if we haven't
	/// disconnected from the node already, ie. `PeerState::is_connected` is set to `true`.
	fn ok_to_remove(&self, require_disconnected: bool) -> bool {
		if require_disconnected && self.is_connected {
			return false
		}
		!self.channel_by_id.iter().any(|(_, phase)|
			match phase {
				ChannelPhase::Funded(_) | ChannelPhase::UnfundedOutboundV1(_) => true,
				ChannelPhase::UnfundedInboundV1(_) => false,
				#[cfg(dual_funding)]
				ChannelPhase::UnfundedOutboundV2(_) => true,
				#[cfg(dual_funding)]
				ChannelPhase::UnfundedInboundV2(_) => false,
			}
		)
			&& self.monitor_update_blocked_actions.is_empty()
			&& self.in_flight_monitor_updates.is_empty()
	}

	// Returns a count of all channels we have with this peer, including unfunded channels.
	fn total_channel_count(&self) -> usize {
		self.channel_by_id.len() + self.inbound_channel_request_by_id.len()
	}

	// Returns a bool indicating if the given `channel_id` matches a channel we have with this peer.
	fn has_channel(&self, channel_id: &ChannelId) -> bool {
		self.channel_by_id.contains_key(channel_id) ||
			self.inbound_channel_request_by_id.contains_key(channel_id)
	}
}

/// A not-yet-accepted inbound (from counterparty) channel. Once
/// accepted, the parameters will be used to construct a channel.
pub(super) struct InboundChannelRequest {
	/// The original OpenChannel message.
	pub open_channel_msg: msgs::OpenChannel,
	/// The number of ticks remaining before the request expires.
	pub ticks_remaining: i32,
}

/// The number of ticks that may elapse while we're waiting for an unaccepted inbound channel to be
/// accepted. An unaccepted channel that exceeds this limit will be abandoned.
const UNACCEPTED_INBOUND_CHANNEL_AGE_LIMIT_TICKS: i32 = 2;

/// Stores a PaymentSecret and any other data we may need to validate an inbound payment is
/// actually ours and not some duplicate HTLC sent to us by a node along the route.
///
/// For users who don't want to bother doing their own payment preimage storage, we also store that
/// here.
///
/// Note that this struct will be removed entirely soon, in favor of storing no inbound payment data
/// and instead encoding it in the payment secret.
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
	Arc<DefaultRouter<
		Arc<NetworkGraph<Arc<L>>>,
		Arc<L>,
		Arc<KeysManager>,
		Arc<RwLock<ProbabilisticScorer<Arc<NetworkGraph<Arc<L>>>, Arc<L>>>>,
		ProbabilisticScoringFeeParameters,
		ProbabilisticScorer<Arc<NetworkGraph<Arc<L>>>, Arc<L>>,
	>>,
	Arc<L>
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
pub type SimpleRefChannelManager<'a, 'b, 'c, 'd, 'e, 'f, 'g, 'h, M, T, F, L> =
	ChannelManager<
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
			ProbabilisticScorer<&'f NetworkGraph<&'g L>, &'g L>
		>,
		&'g L
	>;

/// A trivial trait which describes any [`ChannelManager`].
///
/// This is not exported to bindings users as general cover traits aren't useful in other
/// languages.
pub trait AChannelManager {
	/// A type implementing [`chain::Watch`].
	type Watch: chain::Watch<Self::Signer> + ?Sized;
	/// A type that may be dereferenced to [`Self::Watch`].
	type M: Deref<Target = Self::Watch>;
	/// A type implementing [`BroadcasterInterface`].
	type Broadcaster: BroadcasterInterface + ?Sized;
	/// A type that may be dereferenced to [`Self::Broadcaster`].
	type T: Deref<Target = Self::Broadcaster>;
	/// A type implementing [`EntropySource`].
	type EntropySource: EntropySource + ?Sized;
	/// A type that may be dereferenced to [`Self::EntropySource`].
	type ES: Deref<Target = Self::EntropySource>;
	/// A type implementing [`NodeSigner`].
	type NodeSigner: NodeSigner + ?Sized;
	/// A type that may be dereferenced to [`Self::NodeSigner`].
	type NS: Deref<Target = Self::NodeSigner>;
	/// A type implementing [`WriteableEcdsaChannelSigner`].
	type Signer: WriteableEcdsaChannelSigner + Sized;
	/// A type implementing [`SignerProvider`] for [`Self::Signer`].
	type SignerProvider: SignerProvider<EcdsaSigner= Self::Signer> + ?Sized;
	/// A type that may be dereferenced to [`Self::SignerProvider`].
	type SP: Deref<Target = Self::SignerProvider>;
	/// A type implementing [`FeeEstimator`].
	type FeeEstimator: FeeEstimator + ?Sized;
	/// A type that may be dereferenced to [`Self::FeeEstimator`].
	type F: Deref<Target = Self::FeeEstimator>;
	/// A type implementing [`Router`].
	type Router: Router + ?Sized;
	/// A type that may be dereferenced to [`Self::Router`].
	type R: Deref<Target = Self::Router>;
	/// A type implementing [`Logger`].
	type Logger: Logger + ?Sized;
	/// A type that may be dereferenced to [`Self::Logger`].
	type L: Deref<Target = Self::Logger>;
	/// Returns a reference to the actual [`ChannelManager`] object.
	fn get_cm(&self) -> &ChannelManager<Self::M, Self::T, Self::ES, Self::NS, Self::SP, Self::F, Self::R, Self::L>;
}

impl<M: Deref, T: Deref, ES: Deref, NS: Deref, SP: Deref, F: Deref, R: Deref, L: Deref> AChannelManager
for ChannelManager<M, T, ES, NS, SP, F, R, L>
where
	M::Target: chain::Watch<<SP::Target as SignerProvider>::EcdsaSigner>,
	T::Target: BroadcasterInterface,
	ES::Target: EntropySource,
	NS::Target: NodeSigner,
	SP::Target: SignerProvider,
	F::Target: FeeEstimator,
	R::Target: Router,
	L::Target: Logger,
{
	type Watch = M::Target;
	type M = M;
	type Broadcaster = T::Target;
	type T = T;
	type EntropySource = ES::Target;
	type ES = ES;
	type NodeSigner = NS::Target;
	type NS = NS;
	type Signer = <SP::Target as SignerProvider>::EcdsaSigner;
	type SignerProvider = SP::Target;
	type SP = SP;
	type FeeEstimator = F::Target;
	type F = F;
	type Router = R::Target;
	type R = R;
	type Logger = L::Target;
	type L = L;
	fn get_cm(&self) -> &ChannelManager<M, T, ES, NS, SP, F, R, L> { self }
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
/// - [`Logger`] for logging operational information of varying degrees
///
/// Additionally, it implements the following traits:
/// - [`ChannelMessageHandler`] to handle off-chain channel activity from peers
/// - [`MessageSendEventsProvider`] to similarly send such messages to peers
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
/// use bitcoin::network::constants::Network;
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
/// let default_config = UserConfig::default();
/// let channel_manager = ChannelManager::new(
///     fee_estimator, chain_monitor, tx_broadcaster, router, logger, entropy_source, node_signer,
///     signer_provider, default_config, params, current_timestamp
/// );
///
/// // Restart from deserialized data
/// let mut channel_monitors = read_channel_monitors();
/// let args = ChannelManagerReadArgs::new(
///     entropy_source, node_signer, signer_provider, fee_estimator, chain_monitor, tx_broadcaster,
///     router, logger, default_config, channel_monitors.iter_mut().collect()
/// );
/// let (block_hash, channel_manager) =
///     <(BlockHash, ChannelManager<_, _, _, _, _, _, _, _>)>::read(&mut reader, args)?;
///
/// // Update the ChannelManager and ChannelMonitors with the latest chain data
/// // ...
///
/// // Move the monitors to the ChannelManager's chain::Watch parameter
/// for monitor in channel_monitors {
///     chain_monitor.watch_channel(monitor.get_funding_txo().0, monitor);
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
/// - Send messages to peers obtained via its [`MessageSendEventsProvider`] implementation
///   (typically initiated when [`PeerManager::process_events`] is called)
/// - Feed on-chain activity using either its [`chain::Listen`] or [`chain::Confirm`] implementation
///   as documented by those traits
/// - Perform any periodic channel and payment checks by calling [`timer_tick_occurred`] roughly
///   every minute
/// - Persist to disk whenever [`get_and_clear_needs_persistence`] returns `true` using a
///   [`Persister`] such as a [`KVStore`] implementation
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
/// To an open a channel with a peer, call [`create_channel`]. This will initiate the process of
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
/// channel_manager.process_pending_events(&|event| match event {
///     Event::FundingGenerationReady {
///         temporary_channel_id, counterparty_node_id, channel_value_satoshis, output_script,
///         user_channel_id, ..
///     } => {
///         assert_eq!(user_channel_id, 42);
///         let funding_transaction = wallet.create_funding_transaction(
///             channel_value_satoshis, output_script
///         );
///         match channel_manager.funding_transaction_generated(
///             &temporary_channel_id, &counterparty_node_id, funding_transaction
///         ) {
///             Ok(()) => println!("Funding channel {}", temporary_channel_id),
///             Err(e) => println!("Error funding channel {}: {:?}", temporary_channel_id, e),
///         }
///     },
///     Event::ChannelPending { channel_id, user_channel_id, former_temporary_channel_id, .. } => {
///         assert_eq!(user_channel_id, 42);
///         println!(
///             "Channel {} now {} pending (funding transaction has been broadcasted)", channel_id,
///             former_temporary_channel_id.unwrap()
///         );
///     },
///     Event::ChannelReady { channel_id, user_channel_id, .. } => {
///         assert_eq!(user_channel_id, 42);
///         println!("Channel {} ready", channel_id);
///     },
///     // ...
/// #     _ => {},
/// });
/// # }
/// ```
///
/// ## Accepting Channels
///
/// Inbound channels are initiated by peers and are automatically accepted unless [`ChannelManager`]
/// has [`UserConfig::manually_accept_inbound_channels`] set. In that case, the channel may be
/// either accepted or rejected when handling [`Event::OpenChannelRequest`].
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
/// channel_manager.process_pending_events(&|event| match event {
///     Event::OpenChannelRequest { temporary_channel_id, counterparty_node_id, ..  } => {
///         if !is_trusted(counterparty_node_id) {
///             match channel_manager.force_close_without_broadcasting_txn(
///                 &temporary_channel_id, &counterparty_node_id
///             ) {
///                 Ok(()) => println!("Rejecting channel {}", temporary_channel_id),
///                 Err(e) => println!("Error rejecting channel {}: {:?}", temporary_channel_id, e),
///             }
///             return;
///         }
///
///         let user_channel_id = 43;
///         match channel_manager.accept_inbound_channel(
///             &temporary_channel_id, &counterparty_node_id, user_channel_id
///         ) {
///             Ok(()) => println!("Accepting channel {}", temporary_channel_id),
///             Err(e) => println!("Error accepting channel {}: {:?}", temporary_channel_id, e),
///         }
///     },
///     // ...
/// #     _ => {},
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
/// # use lightning::ln::ChannelId;
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
/// channel_manager.process_pending_events(&|event| match event {
///     Event::ChannelClosed { channel_id, user_channel_id, ..  } => {
///         assert_eq!(user_channel_id, 42);
///         println!("Channel {} closed", channel_id);
///     },
///     // ...
/// #     _ => {},
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
/// The [`lightning-invoice`] crate is useful for creating BOLT 11 invoices. Specifically, use the
/// functions in its `utils` module for constructing invoices that are compatible with
/// [`ChannelManager`]. These functions serve as a convenience for building invoices with the
/// [`PaymentHash`] and [`PaymentSecret`] returned from [`create_inbound_payment`]. To provide your
/// own [`PaymentHash`], use [`create_inbound_payment_for_hash`] or the corresponding functions in
/// the [`lightning-invoice`] `utils` module.
///
/// [`ChannelManager`] generates an [`Event::PaymentClaimable`] once the full payment has been
/// received. Call [`claim_funds`] to release the [`PaymentPreimage`], which in turn will result in
/// an [`Event::PaymentClaimed`].
///
/// ```
/// # use lightning::events::{Event, EventsProvider, PaymentPurpose};
/// # use lightning::ln::channelmanager::AChannelManager;
/// #
/// # fn example<T: AChannelManager>(channel_manager: T) {
/// # let channel_manager = channel_manager.get_cm();
/// // Or use utils::create_invoice_from_channelmanager
/// let known_payment_hash = match channel_manager.create_inbound_payment(
///     Some(10_000_000), 3600, None
/// ) {
///     Ok((payment_hash, _payment_secret)) => {
///         println!("Creating inbound payment {}", payment_hash);
///         payment_hash
///     },
///     Err(()) => panic!("Error creating inbound payment"),
/// };
///
/// // On the event processing thread
/// channel_manager.process_pending_events(&|event| match event {
///     Event::PaymentClaimable { payment_hash, purpose, .. } => match purpose {
///         PaymentPurpose::InvoicePayment { payment_preimage: Some(payment_preimage), .. } => {
///             assert_eq!(payment_hash, known_payment_hash);
///             println!("Claiming payment {}", payment_hash);
///             channel_manager.claim_funds(payment_preimage);
///         },
///         PaymentPurpose::InvoicePayment { payment_preimage: None, .. } => {
///             println!("Unknown payment hash: {}", payment_hash);
///         },
///         PaymentPurpose::SpontaneousPayment(payment_preimage) => {
///             assert_ne!(payment_hash, known_payment_hash);
///             println!("Claiming spontaneous payment {}", payment_hash);
///             channel_manager.claim_funds(payment_preimage);
///         },
///     },
///     Event::PaymentClaimed { payment_hash, amount_msat, .. } => {
///         assert_eq!(payment_hash, known_payment_hash);
///         println!("Claimed {} msats", amount_msat);
///     },
///     // ...
/// #     _ => {},
/// });
/// # }
/// ```
///
/// For paying an invoice, [`lightning-invoice`] provides a `payment` module with convenience
/// functions for use with [`send_payment`].
///
/// ```
/// # use lightning::events::{Event, EventsProvider};
/// # use lightning::ln::PaymentHash;
/// # use lightning::ln::channelmanager::{AChannelManager, PaymentId, RecentPaymentDetails, RecipientOnionFields, Retry};
/// # use lightning::routing::router::RouteParameters;
/// #
/// # fn example<T: AChannelManager>(
/// #     channel_manager: T, payment_hash: PaymentHash, recipient_onion: RecipientOnionFields,
/// #     route_params: RouteParameters, retry: Retry
/// # ) {
/// # let channel_manager = channel_manager.get_cm();
/// // let (payment_hash, recipient_onion, route_params) =
/// //     payment::payment_parameters_from_invoice(&invoice);
/// let payment_id = PaymentId([42; 32]);
/// match channel_manager.send_payment(
///     payment_hash, recipient_onion, payment_id, route_params, retry
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
/// channel_manager.process_pending_events(&|event| match event {
///     Event::PaymentSent { payment_hash, .. } => println!("Paid {}", payment_hash),
///     Event::PaymentFailed { payment_hash, .. } => println!("Failed paying {}", payment_hash),
///     // ...
/// #     _ => {},
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
/// #
/// # fn example<T: AChannelManager>(channel_manager: T) -> Result<(), Bolt12SemanticError> {
/// # let channel_manager = channel_manager.get_cm();
/// let offer = channel_manager
///     .create_offer_builder("coffee".to_string())?
/// # ;
/// # // Needed for compiling for c_bindings
/// # let builder: lightning::offers::offer::OfferBuilder<_, _> = offer.into();
/// # let offer = builder
///     .amount_msats(10_000_000)
///     .build()?;
/// let bech32_offer = offer.to_string();
///
/// // On the event processing thread
/// channel_manager.process_pending_events(&|event| match event {
///     Event::PaymentClaimable { payment_hash, purpose, .. } => match purpose {
///         PaymentPurpose::InvoicePayment { payment_preimage: Some(payment_preimage), .. } => {
///             println!("Claiming payment {}", payment_hash);
///             channel_manager.claim_funds(payment_preimage);
///         },
///         PaymentPurpose::InvoicePayment { payment_preimage: None, .. } => {
///             println!("Unknown payment hash: {}", payment_hash);
///         },
///         // ...
/// #         _ => {},
///     },
///     Event::PaymentClaimed { payment_hash, amount_msat, .. } => {
///         println!("Claimed {} msats", amount_msat);
///     },
///     // ...
/// #     _ => {},
/// });
/// # Ok(())
/// # }
/// ```
///
/// Use [`pay_for_offer`] to initiated payment, which sends an [`InvoiceRequest`] for an [`Offer`]
/// and pays the [`Bolt12Invoice`] response. In addition to success and failure events,
/// [`ChannelManager`] may also generate an [`Event::InvoiceRequestFailed`].
///
/// ```
/// # use lightning::events::{Event, EventsProvider};
/// # use lightning::ln::channelmanager::{AChannelManager, PaymentId, RecentPaymentDetails, Retry};
/// # use lightning::offers::offer::Offer;
/// #
/// # fn example<T: AChannelManager>(
/// #     channel_manager: T, offer: &Offer, quantity: Option<u64>, amount_msats: Option<u64>,
/// #     payer_note: Option<String>, retry: Retry, max_total_routing_fee_msat: Option<u64>
/// # ) {
/// # let channel_manager = channel_manager.get_cm();
/// let payment_id = PaymentId([42; 32]);
/// match channel_manager.pay_for_offer(
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
/// channel_manager.process_pending_events(&|event| match event {
///     Event::PaymentSent { payment_id: Some(payment_id), .. } => println!("Paid {}", payment_id),
///     Event::PaymentFailed { payment_id, .. } => println!("Failed paying {}", payment_id),
///     Event::InvoiceRequestFailed { payment_id, .. } => println!("Failed paying {}", payment_id),
///     // ...
/// #     _ => {},
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
/// # use lightning::ln::channelmanager::{AChannelManager, PaymentId, RecentPaymentDetails, Retry};
/// # use lightning::offers::parse::Bolt12SemanticError;
/// #
/// # fn example<T: AChannelManager>(
/// #     channel_manager: T, amount_msats: u64, absolute_expiry: Duration, retry: Retry,
/// #     max_total_routing_fee_msat: Option<u64>
/// # ) -> Result<(), Bolt12SemanticError> {
/// # let channel_manager = channel_manager.get_cm();
/// let payment_id = PaymentId([42; 32]);
/// let refund = channel_manager
///     .create_refund_builder(
///         "coffee".to_string(), amount_msats, absolute_expiry, payment_id, retry,
///         max_total_routing_fee_msat
///     )?
/// # ;
/// # // Needed for compiling for c_bindings
/// # let builder: lightning::offers::refund::RefundBuilder<_> = refund.into();
/// # let refund = builder
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
/// channel_manager.process_pending_events(&|event| match event {
///     Event::PaymentSent { payment_id: Some(payment_id), .. } => println!("Paid {}", payment_id),
///     Event::PaymentFailed { payment_id, .. } => println!("Failed paying {}", payment_id),
///     // ...
/// #     _ => {},
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
/// match channel_manager.request_refund_payment(refund) {
///     Ok(()) => println!("Requesting payment for refund"),
///     Err(e) => println!("Unable to request payment for refund: {:?}", e),
/// }
///
/// // On the event processing thread
/// channel_manager.process_pending_events(&|event| match event {
///     Event::PaymentClaimable { payment_hash, purpose, .. } => match purpose {
///     	PaymentPurpose::InvoicePayment { payment_preimage: Some(payment_preimage), .. } => {
///             println!("Claiming payment {}", payment_hash);
///             channel_manager.claim_funds(payment_preimage);
///         },
///     	PaymentPurpose::InvoicePayment { payment_preimage: None, .. } => {
///             println!("Unknown payment hash: {}", payment_hash);
///     	},
///         // ...
/// #         _ => {},
///     },
///     Event::PaymentClaimed { payment_hash, amount_msat, .. } => {
///         println!("Claimed {} msats", amount_msat);
///     },
///     // ...
/// #     _ => {},
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
/// [`Persister`]: crate::util::persist::Persister
/// [`KVStore`]: crate::util::persist::KVStore
/// [`get_event_or_persistence_needed_future`]: Self::get_event_or_persistence_needed_future
/// [`lightning-block-sync`]: https://docs.rs/lightning_block_sync/latest/lightning_block_sync
/// [`lightning-transaction-sync`]: https://docs.rs/lightning_transaction_sync/latest/lightning_transaction_sync
/// [`lightning-background-processor`]: https://docs.rs/lightning_background_processor/lightning_background_processor
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
/// [`peer_disconnected`]: msgs::ChannelMessageHandler::peer_disconnected
/// [`funding_created`]: msgs::FundingCreated
/// [`funding_transaction_generated`]: Self::funding_transaction_generated
/// [`BlockHash`]: bitcoin::hash_types::BlockHash
/// [`update_channel`]: chain::Watch::update_channel
/// [`ChannelUpdate`]: msgs::ChannelUpdate
/// [`read`]: ReadableArgs::read
//
// Lock order:
// The tree structure below illustrates the lock order requirements for the different locks of the
// `ChannelManager`. Locks can be held at the same time if they are on the same branch in the tree,
// and should then be taken in the order of the lowest to the highest level in the tree.
// Note that locks on different branches shall not be taken at the same time, as doing so will
// create a new lock order for those specific locks in the order they were taken.
//
// Lock order tree:
//
// `pending_offers_messages`
//
// `total_consistency_lock`
//  |
//  |__`forward_htlcs`
//  |   |
//  |   |__`pending_intercepted_htlcs`
//  |
//  |__`decode_update_add_htlcs`
//  |
//  |__`per_peer_state`
//      |
//      |__`pending_inbound_payments`
//          |
//          |__`claimable_payments`
//          |
//          |__`pending_outbound_payments` // This field's struct contains a map of pending outbounds
//              |
//              |__`peer_state`
//                  |
//                  |__`outpoint_to_peer`
//                  |
//                  |__`short_to_chan_info`
//                  |
//                  |__`outbound_scid_aliases`
//                  |
//                  |__`best_block`
//                  |
//                  |__`pending_events`
//                      |
//                      |__`pending_background_events`
//
pub struct ChannelManager<M: Deref, T: Deref, ES: Deref, NS: Deref, SP: Deref, F: Deref, R: Deref, L: Deref>
where
	M::Target: chain::Watch<<SP::Target as SignerProvider>::EcdsaSigner>,
	T::Target: BroadcasterInterface,
	ES::Target: EntropySource,
	NS::Target: NodeSigner,
	SP::Target: SignerProvider,
	F::Target: FeeEstimator,
	R::Target: Router,
	L::Target: Logger,
{
	default_configuration: UserConfig,
	chain_hash: ChainHash,
	fee_estimator: LowerBoundedFeeEstimator<F>,
	chain_monitor: M,
	tx_broadcaster: T,
	#[allow(unused)]
	router: R,

	/// See `ChannelManager` struct-level documentation for lock order requirements.
	#[cfg(test)]
	pub(super) best_block: RwLock<BestBlock>,
	#[cfg(not(test))]
	best_block: RwLock<BestBlock>,
	secp_ctx: Secp256k1<secp256k1::All>,

	/// Storage for PaymentSecrets and any requirements on future inbound payments before we will
	/// expose them to users via a PaymentClaimable event. HTLCs which do not meet the requirements
	/// here are failed when we process them as pending-forwardable-HTLCs, and entries are removed
	/// after we generate a PaymentClaimable upon receipt of all MPP parts or when they time out.
	///
	/// See `ChannelManager` struct-level documentation for lock order requirements.
	pending_inbound_payments: Mutex<HashMap<PaymentHash, PendingInboundPayment>>,

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
	///
	/// See `ChannelManager` struct-level documentation for lock order requirements.
	pending_outbound_payments: OutboundPayments,

	/// SCID/SCID Alias -> forward infos. Key of 0 means payments received.
	///
	/// Note that because we may have an SCID Alias as the key we can have two entries per channel,
	/// though in practice we probably won't be receiving HTLCs for a channel both via the alias
	/// and via the classic SCID.
	///
	/// Note that no consistency guarantees are made about the existence of a channel with the
	/// `short_channel_id` here, nor the `short_channel_id` in the `PendingHTLCInfo`!
	///
	/// See `ChannelManager` struct-level documentation for lock order requirements.
	#[cfg(test)]
	pub(super) forward_htlcs: Mutex<HashMap<u64, Vec<HTLCForwardInfo>>>,
	#[cfg(not(test))]
	forward_htlcs: Mutex<HashMap<u64, Vec<HTLCForwardInfo>>>,
	/// Storage for HTLCs that have been intercepted and bubbled up to the user. We hold them here
	/// until the user tells us what we should do with them.
	///
	/// See `ChannelManager` struct-level documentation for lock order requirements.
	pending_intercepted_htlcs: Mutex<HashMap<InterceptId, PendingAddHTLCInfo>>,

	/// SCID/SCID Alias -> pending `update_add_htlc`s to decode.
	///
	/// Note that because we may have an SCID Alias as the key we can have two entries per channel,
	/// though in practice we probably won't be receiving HTLCs for a channel both via the alias
	/// and via the classic SCID.
	///
	/// Note that no consistency guarantees are made about the existence of a channel with the
	/// `short_channel_id` here, nor the `channel_id` in `UpdateAddHTLC`!
	///
	/// See `ChannelManager` struct-level documentation for lock order requirements.
	decode_update_add_htlcs: Mutex<HashMap<u64, Vec<msgs::UpdateAddHTLC>>>,

	/// The sets of payments which are claimable or currently being claimed. See
	/// [`ClaimablePayments`]' individual field docs for more info.
	///
	/// See `ChannelManager` struct-level documentation for lock order requirements.
	claimable_payments: Mutex<ClaimablePayments>,

	/// The set of outbound SCID aliases across all our channels, including unconfirmed channels
	/// and some closed channels which reached a usable state prior to being closed. This is used
	/// only to avoid duplicates, and is not persisted explicitly to disk, but rebuilt from the
	/// active channel list on load.
	///
	/// See `ChannelManager` struct-level documentation for lock order requirements.
	outbound_scid_aliases: Mutex<HashSet<u64>>,

	/// Channel funding outpoint -> `counterparty_node_id`.
	///
	/// Note that this map should only be used for `MonitorEvent` handling, to be able to access
	/// the corresponding channel for the event, as we only have access to the `channel_id` during
	/// the handling of the events.
	///
	/// Note that no consistency guarantees are made about the existence of a peer with the
	/// `counterparty_node_id` in our other maps.
	///
	/// TODO:
	/// The `counterparty_node_id` isn't passed with `MonitorEvent`s currently. To pass it, we need
	/// to make `counterparty_node_id`'s a required field in `ChannelMonitor`s, which unfortunately
	/// would break backwards compatability.
	/// We should add `counterparty_node_id`s to `MonitorEvent`s, and eventually rely on it in the
	/// future. That would make this map redundant, as only the `ChannelManager::per_peer_state` is
	/// required to access the channel with the `counterparty_node_id`.
	///
	/// See `ChannelManager` struct-level documentation for lock order requirements.
	#[cfg(not(test))]
	outpoint_to_peer: Mutex<HashMap<OutPoint, PublicKey>>,
	#[cfg(test)]
	pub(crate) outpoint_to_peer: Mutex<HashMap<OutPoint, PublicKey>>,

	/// SCIDs (and outbound SCID aliases) -> `counterparty_node_id`s and `channel_id`s.
	///
	/// Outbound SCID aliases are added here once the channel is available for normal use, with
	/// SCIDs being added once the funding transaction is confirmed at the channel's required
	/// confirmation depth.
	///
	/// Note that while this holds `counterparty_node_id`s and `channel_id`s, no consistency
	/// guarantees are made about the existence of a peer with the `counterparty_node_id` nor a
	/// channel with the `channel_id` in our other maps.
	///
	/// See `ChannelManager` struct-level documentation for lock order requirements.
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
	///
	/// See `ChannelManager` struct-level documentation for lock order requirements.
	#[cfg(not(any(test, feature = "_test_utils")))]
	per_peer_state: FairRwLock<HashMap<PublicKey, Mutex<PeerState<SP>>>>,
	#[cfg(any(test, feature = "_test_utils"))]
	pub(super) per_peer_state: FairRwLock<HashMap<PublicKey, Mutex<PeerState<SP>>>>,

	/// The set of events which we need to give to the user to handle. In some cases an event may
	/// require some further action after the user handles it (currently only blocking a monitor
	/// update from being handed to the user to ensure the included changes to the channel state
	/// are handled by the user before they're persisted durably to disk). In that case, the second
	/// element in the tuple is set to `Some` with further details of the action.
	///
	/// Note that events MUST NOT be removed from pending_events after deserialization, as they
	/// could be in the middle of being processed without the direct mutex held.
	///
	/// See `ChannelManager` struct-level documentation for lock order requirements.
	#[cfg(not(any(test, feature = "_test_utils")))]
	pending_events: Mutex<VecDeque<(events::Event, Option<EventCompletionAction>)>>,
	#[cfg(any(test, feature = "_test_utils"))]
	pub(crate) pending_events: Mutex<VecDeque<(events::Event, Option<EventCompletionAction>)>>,

	/// A simple atomic flag to ensure only one task at a time can be processing events asynchronously.
	pending_events_processor: AtomicBool,

	/// If we are running during init (either directly during the deserialization method or in
	/// block connection methods which run after deserialization but before normal operation) we
	/// cannot provide the user with [`ChannelMonitorUpdate`]s through the normal update flow -
	/// prior to normal operation the user may not have loaded the [`ChannelMonitor`]s into their
	/// [`ChainMonitor`] and thus attempting to update it will fail or panic.
	///
	/// Thus, we place them here to be handled as soon as possible once we are running normally.
	///
	/// See `ChannelManager` struct-level documentation for lock order requirements.
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

	pending_offers_messages: Mutex<Vec<PendingOnionMessage<OffersMessage>>>,

	/// Tracks the message events that are to be broadcasted when we are connected to some peer.
	pending_broadcast_messages: Mutex<Vec<MessageSendEvent>>,

	entropy_source: ES,
	node_signer: NS,
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
struct PersistenceNotifierGuard<'a, F: FnMut() -> NotifyOption> {
	event_persist_notifier: &'a Notifier,
	needs_persist_flag: &'a AtomicBool,
	should_persist: F,
	// We hold onto this result so the lock doesn't get released immediately.
	_read_guard: RwLockReadGuard<'a, ()>,
}

impl<'a> PersistenceNotifierGuard<'a, fn() -> NotifyOption> { // We don't care what the concrete F is here, it's unused
	/// Notifies any waiters and indicates that we need to persist, in addition to possibly having
	/// events to handle.
	///
	/// This must always be called if the changes included a `ChannelMonitorUpdate`, as well as in
	/// other cases where losing the changes on restart may result in a force-close or otherwise
	/// isn't ideal.
	fn notify_on_drop<C: AChannelManager>(cm: &'a C) -> PersistenceNotifierGuard<'a, impl FnMut() -> NotifyOption> {
		Self::optionally_notify(cm, || -> NotifyOption { NotifyOption::DoPersist })
	}

	fn optionally_notify<F: FnMut() -> NotifyOption, C: AChannelManager>(cm: &'a C, mut persist_check: F)
	-> PersistenceNotifierGuard<'a, impl FnMut() -> NotifyOption> {
		let read_guard = cm.get_cm().total_consistency_lock.read().unwrap();
		let force_notify = cm.get_cm().process_background_events();

		PersistenceNotifierGuard {
			event_persist_notifier: &cm.get_cm().event_persist_notifier,
			needs_persist_flag: &cm.get_cm().needs_persist_flag,
			should_persist: move || {
				// Pick the "most" action between `persist_check` and the background events
				// processing and return that.
				let notify = persist_check();
				match (notify, force_notify) {
					(NotifyOption::DoPersist, _) => NotifyOption::DoPersist,
					(_, NotifyOption::DoPersist) => NotifyOption::DoPersist,
					(NotifyOption::SkipPersistHandleEvents, _) => NotifyOption::SkipPersistHandleEvents,
					(_, NotifyOption::SkipPersistHandleEvents) => NotifyOption::SkipPersistHandleEvents,
					_ => NotifyOption::SkipPersistNoEvents,
				}
			},
			_read_guard: read_guard,
		}
	}

	/// Note that if any [`ChannelMonitorUpdate`]s are possibly generated,
	/// [`ChannelManager::process_background_events`] MUST be called first (or
	/// [`Self::optionally_notify`] used).
	fn optionally_notify_skipping_background_events<F: Fn() -> NotifyOption, C: AChannelManager>
	(cm: &'a C, persist_check: F) -> PersistenceNotifierGuard<'a, F> {
		let read_guard = cm.get_cm().total_consistency_lock.read().unwrap();

		PersistenceNotifierGuard {
			event_persist_notifier: &cm.get_cm().event_persist_notifier,
			needs_persist_flag: &cm.get_cm().needs_persist_flag,
			should_persist: persist_check,
			_read_guard: read_guard,
		}
	}
}

impl<'a, F: FnMut() -> NotifyOption> Drop for PersistenceNotifierGuard<'a, F> {
	fn drop(&mut self) {
		match (self.should_persist)() {
			NotifyOption::DoPersist => {
				self.needs_persist_flag.store(true, Ordering::Release);
				self.event_persist_notifier.notify()
			},
			NotifyOption::SkipPersistHandleEvents =>
				self.event_persist_notifier.notify(),
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
/// HTLC's CLTV. The current default represents roughly seven hours of blocks at six blocks/hour.
///
/// This can be increased (but not decreased) through [`ChannelConfig::cltv_expiry_delta`]
///
/// [`ChannelConfig::cltv_expiry_delta`]: crate::util::config::ChannelConfig::cltv_expiry_delta
// This should always be a few blocks greater than channelmonitor::CLTV_CLAIM_BUFFER,
// i.e. the node we forwarded the payment on to should always have enough room to reliably time out
// the HTLC via a full update_fail_htlc/commitment_signed dance before we hit the
// CLTV_CLAIM_BUFFER point (we static assert that it's at least 3 blocks more).
pub const MIN_CLTV_EXPIRY_DELTA: u16 = 6*7;
// This should be long enough to allow a payment path drawn across multiple routing hops with substantial
// `cltv_expiry_delta`. Indeed, the length of those values is the reaction delay offered to a routing node
// in case of HTLC on-chain settlement. While appearing less competitive, a node operator could decide to
// scale them up to suit its security policy. At the network-level, we shouldn't constrain them too much,
// while avoiding to introduce a DoS vector. Further, a low CTLV_FAR_FAR_AWAY could be a source of
// routing failure for any HTLC sender picking up an LDK node among the first hops.
pub(super) const CLTV_FAR_FAR_AWAY: u32 = 14 * 24 * 6;

/// Minimum CLTV difference between the current block height and received inbound payments.
/// Invoices generated for payment to us must set their `min_final_cltv_expiry_delta` field to at least
/// this value.
// Note that we fail if exactly HTLC_FAIL_BACK_BUFFER + 1 was used, so we need to add one for
// any payments to succeed. Further, we don't want payments to fail if a block was found while
// a payment was being routed, so we add an extra block to be safe.
pub const MIN_FINAL_CLTV_EXPIRY_DELTA: u16 = HTLC_FAIL_BACK_BUFFER as u16 + 3;

// Check that our CLTV_EXPIRY is at least CLTV_CLAIM_BUFFER + ANTI_REORG_DELAY + LATENCY_GRACE_PERIOD_BLOCKS,
// ie that if the next-hop peer fails the HTLC within
// LATENCY_GRACE_PERIOD_BLOCKS then we'll still have CLTV_CLAIM_BUFFER left to timeout it onchain,
// then waiting ANTI_REORG_DELAY to be reorg-safe on the outbound HLTC and
// failing the corresponding htlc backward, and us now seeing the last block of ANTI_REORG_DELAY before
// LATENCY_GRACE_PERIOD_BLOCKS.
#[allow(dead_code)]
const CHECK_CLTV_EXPIRY_SANITY: u32 = MIN_CLTV_EXPIRY_DELTA as u32 - LATENCY_GRACE_PERIOD_BLOCKS - CLTV_CLAIM_BUFFER - ANTI_REORG_DELAY - LATENCY_GRACE_PERIOD_BLOCKS;

// Check for ability of an attacker to make us fail on-chain by delaying an HTLC claim. See
// ChannelMonitor::should_broadcast_holder_commitment_txn for a description of why this is needed.
#[allow(dead_code)]
const CHECK_CLTV_EXPIRY_SANITY_2: u32 = MIN_CLTV_EXPIRY_DELTA as u32 - LATENCY_GRACE_PERIOD_BLOCKS - 2*CLTV_CLAIM_BUFFER;

/// The number of ticks of [`ChannelManager::timer_tick_occurred`] until expiry of incomplete MPPs
pub(crate) const MPP_TIMEOUT_TICKS: u8 = 3;

/// The number of ticks of [`ChannelManager::timer_tick_occurred`] where a peer is disconnected
/// until we mark the channel disabled and gossip the update.
pub(crate) const DISABLE_GOSSIP_TICKS: u8 = 10;

/// The number of ticks of [`ChannelManager::timer_tick_occurred`] where a peer is connected until
/// we mark the channel enabled and gossip the update.
pub(crate) const ENABLE_GOSSIP_TICKS: u8 = 5;

/// The maximum number of unfunded channels we can have per-peer before we start rejecting new
/// (inbound) ones. The number of peers with unfunded channels is limited separately in
/// [`MAX_UNFUNDED_CHANNEL_PEERS`].
const MAX_UNFUNDED_CHANS_PER_PEER: usize = 4;

/// The maximum number of peers from which we will allow pending unfunded channels. Once we reach
/// this many peers we reject new (inbound) channels from peers with which we don't have a channel.
const MAX_UNFUNDED_CHANNEL_PEERS: usize = 50;

/// The maximum number of peers which we do not have a (funded) channel with. Once we reach this
/// many peers we reject new (inbound) connections.
const MAX_NO_CHANNEL_PEERS: usize = 250;

/// Information needed for constructing an invoice route hint for this channel.
#[derive(Clone, Debug, PartialEq)]
pub struct CounterpartyForwardingInfo {
	/// Base routing fee in millisatoshis.
	pub fee_base_msat: u32,
	/// Amount in millionths of a satoshi the channel will charge per transferred satoshi.
	pub fee_proportional_millionths: u32,
	/// The minimum difference in cltv_expiry between an ingoing HTLC and its outgoing counterpart,
	/// such that the outgoing HTLC is forwardable to this counterparty. See `msgs::ChannelUpdate`'s
	/// `cltv_expiry_delta` for more details.
	pub cltv_expiry_delta: u16,
}

/// Channel parameters which apply to our counterparty. These are split out from [`ChannelDetails`]
/// to better separate parameters.
#[derive(Clone, Debug, PartialEq)]
pub struct ChannelCounterparty {
	/// The node_id of our counterparty
	pub node_id: PublicKey,
	/// The Features the channel counterparty provided upon last connection.
	/// Useful for routing as it is the most up-to-date copy of the counterparty's features and
	/// many routing-relevant features are present in the init context.
	pub features: InitFeatures,
	/// The value, in satoshis, that must always be held in the channel for our counterparty. This
	/// value ensures that if our counterparty broadcasts a revoked state, we can punish them by
	/// claiming at least this value on chain.
	///
	/// This value is not included in [`inbound_capacity_msat`] as it can never be spent.
	///
	/// [`inbound_capacity_msat`]: ChannelDetails::inbound_capacity_msat
	pub unspendable_punishment_reserve: u64,
	/// Information on the fees and requirements that the counterparty requires when forwarding
	/// payments to us through this channel.
	pub forwarding_info: Option<CounterpartyForwardingInfo>,
	/// The smallest value HTLC (in msat) the remote peer will accept, for this channel. This field
	/// is only `None` before we have received either the `OpenChannel` or `AcceptChannel` message
	/// from the remote peer, or for `ChannelCounterparty` objects serialized prior to LDK 0.0.107.
	pub outbound_htlc_minimum_msat: Option<u64>,
	/// The largest value HTLC (in msat) the remote peer currently will accept, for this channel.
	pub outbound_htlc_maximum_msat: Option<u64>,
}

/// Details of a channel, as returned by [`ChannelManager::list_channels`] and [`ChannelManager::list_usable_channels`]
#[derive(Clone, Debug, PartialEq)]
pub struct ChannelDetails {
	/// The channel's ID (prior to funding transaction generation, this is a random 32 bytes,
	/// thereafter this is the txid of the funding transaction xor the funding transaction output).
	/// Note that this means this value is *not* persistent - it can change once during the
	/// lifetime of the channel.
	pub channel_id: ChannelId,
	/// Parameters which apply to our counterparty. See individual fields for more information.
	pub counterparty: ChannelCounterparty,
	/// The Channel's funding transaction output, if we've negotiated the funding transaction with
	/// our counterparty already.
	pub funding_txo: Option<OutPoint>,
	/// The features which this channel operates with. See individual features for more info.
	///
	/// `None` until negotiation completes and the channel type is finalized.
	pub channel_type: Option<ChannelTypeFeatures>,
	/// The position of the funding transaction in the chain. None if the funding transaction has
	/// not yet been confirmed and the channel fully opened.
	///
	/// Note that if [`inbound_scid_alias`] is set, it must be used for invoices and inbound
	/// payments instead of this. See [`get_inbound_payment_scid`].
	///
	/// For channels with [`confirmations_required`] set to `Some(0)`, [`outbound_scid_alias`] may
	/// be used in place of this in outbound routes. See [`get_outbound_payment_scid`].
	///
	/// [`inbound_scid_alias`]: Self::inbound_scid_alias
	/// [`outbound_scid_alias`]: Self::outbound_scid_alias
	/// [`get_inbound_payment_scid`]: Self::get_inbound_payment_scid
	/// [`get_outbound_payment_scid`]: Self::get_outbound_payment_scid
	/// [`confirmations_required`]: Self::confirmations_required
	pub short_channel_id: Option<u64>,
	/// An optional [`short_channel_id`] alias for this channel, randomly generated by us and
	/// usable in place of [`short_channel_id`] to reference the channel in outbound routes when
	/// the channel has not yet been confirmed (as long as [`confirmations_required`] is
	/// `Some(0)`).
	///
	/// This will be `None` as long as the channel is not available for routing outbound payments.
	///
	/// [`short_channel_id`]: Self::short_channel_id
	/// [`confirmations_required`]: Self::confirmations_required
	pub outbound_scid_alias: Option<u64>,
	/// An optional [`short_channel_id`] alias for this channel, randomly generated by our
	/// counterparty and usable in place of [`short_channel_id`] in invoice route hints. Our
	/// counterparty will recognize the alias provided here in place of the [`short_channel_id`]
	/// when they see a payment to be routed to us.
	///
	/// Our counterparty may choose to rotate this value at any time, though will always recognize
	/// previous values for inbound payment forwarding.
	///
	/// [`short_channel_id`]: Self::short_channel_id
	pub inbound_scid_alias: Option<u64>,
	/// The value, in satoshis, of this channel as appears in the funding output
	pub channel_value_satoshis: u64,
	/// The value, in satoshis, that must always be held in the channel for us. This value ensures
	/// that if we broadcast a revoked state, our counterparty can punish us by claiming at least
	/// this value on chain.
	///
	/// This value is not included in [`outbound_capacity_msat`] as it can never be spent.
	///
	/// This value will be `None` for outbound channels until the counterparty accepts the channel.
	///
	/// [`outbound_capacity_msat`]: ChannelDetails::outbound_capacity_msat
	pub unspendable_punishment_reserve: Option<u64>,
	/// The `user_channel_id` value passed in to [`ChannelManager::create_channel`] for outbound
	/// channels, or to [`ChannelManager::accept_inbound_channel`] for inbound channels if
	/// [`UserConfig::manually_accept_inbound_channels`] config flag is set to true. Otherwise
	/// `user_channel_id` will be randomized for an inbound channel.  This may be zero for objects
	/// serialized with LDK versions prior to 0.0.113.
	///
	/// [`ChannelManager::create_channel`]: crate::ln::channelmanager::ChannelManager::create_channel
	/// [`ChannelManager::accept_inbound_channel`]: crate::ln::channelmanager::ChannelManager::accept_inbound_channel
	/// [`UserConfig::manually_accept_inbound_channels`]: crate::util::config::UserConfig::manually_accept_inbound_channels
	pub user_channel_id: u128,
	/// The currently negotiated fee rate denominated in satoshi per 1000 weight units,
	/// which is applied to commitment and HTLC transactions.
	///
	/// This value will be `None` for objects serialized with LDK versions prior to 0.0.115.
	pub feerate_sat_per_1000_weight: Option<u32>,
	/// Our total balance.  This is the amount we would get if we close the channel.
	/// This value is not exact. Due to various in-flight changes and feerate changes, exactly this
	/// amount is not likely to be recoverable on close.
	///
	/// This does not include any pending HTLCs which are not yet fully resolved (and, thus, whose
	/// balance is not available for inclusion in new outbound HTLCs). This further does not include
	/// any pending outgoing HTLCs which are awaiting some other resolution to be sent.
	/// This does not consider any on-chain fees.
	///
	/// See also [`ChannelDetails::outbound_capacity_msat`]
	pub balance_msat: u64,
	/// The available outbound capacity for sending HTLCs to the remote peer. This does not include
	/// any pending HTLCs which are not yet fully resolved (and, thus, whose balance is not
	/// available for inclusion in new outbound HTLCs). This further does not include any pending
	/// outgoing HTLCs which are awaiting some other resolution to be sent.
	///
	/// See also [`ChannelDetails::balance_msat`]
	///
	/// This value is not exact. Due to various in-flight changes, feerate changes, and our
	/// conflict-avoidance policy, exactly this amount is not likely to be spendable. However, we
	/// should be able to spend nearly this amount.
	pub outbound_capacity_msat: u64,
	/// The available outbound capacity for sending a single HTLC to the remote peer. This is
	/// similar to [`ChannelDetails::outbound_capacity_msat`] but it may be further restricted by
	/// the current state and per-HTLC limit(s). This is intended for use when routing, allowing us
	/// to use a limit as close as possible to the HTLC limit we can currently send.
	///
	/// See also [`ChannelDetails::next_outbound_htlc_minimum_msat`],
	/// [`ChannelDetails::balance_msat`], and [`ChannelDetails::outbound_capacity_msat`].
	pub next_outbound_htlc_limit_msat: u64,
	/// The minimum value for sending a single HTLC to the remote peer. This is the equivalent of
	/// [`ChannelDetails::next_outbound_htlc_limit_msat`] but represents a lower-bound, rather than
	/// an upper-bound. This is intended for use when routing, allowing us to ensure we pick a
	/// route which is valid.
	pub next_outbound_htlc_minimum_msat: u64,
	/// The available inbound capacity for the remote peer to send HTLCs to us. This does not
	/// include any pending HTLCs which are not yet fully resolved (and, thus, whose balance is not
	/// available for inclusion in new inbound HTLCs).
	/// Note that there are some corner cases not fully handled here, so the actual available
	/// inbound capacity may be slightly higher than this.
	///
	/// This value is not exact. Due to various in-flight changes, feerate changes, and our
	/// counterparty's conflict-avoidance policy, exactly this amount is not likely to be spendable.
	/// However, our counterparty should be able to spend nearly this amount.
	pub inbound_capacity_msat: u64,
	/// The number of required confirmations on the funding transaction before the funding will be
	/// considered "locked". This number is selected by the channel fundee (i.e. us if
	/// [`is_outbound`] is *not* set), and can be selected for inbound channels with
	/// [`ChannelHandshakeConfig::minimum_depth`] or limited for outbound channels with
	/// [`ChannelHandshakeLimits::max_minimum_depth`].
	///
	/// This value will be `None` for outbound channels until the counterparty accepts the channel.
	///
	/// [`is_outbound`]: ChannelDetails::is_outbound
	/// [`ChannelHandshakeConfig::minimum_depth`]: crate::util::config::ChannelHandshakeConfig::minimum_depth
	/// [`ChannelHandshakeLimits::max_minimum_depth`]: crate::util::config::ChannelHandshakeLimits::max_minimum_depth
	pub confirmations_required: Option<u32>,
	/// The current number of confirmations on the funding transaction.
	///
	/// This value will be `None` for objects serialized with LDK versions prior to 0.0.113.
	pub confirmations: Option<u32>,
	/// The number of blocks (after our commitment transaction confirms) that we will need to wait
	/// until we can claim our funds after we force-close the channel. During this time our
	/// counterparty is allowed to punish us if we broadcasted a stale state. If our counterparty
	/// force-closes the channel and broadcasts a commitment transaction we do not have to wait any
	/// time to claim our non-HTLC-encumbered funds.
	///
	/// This value will be `None` for outbound channels until the counterparty accepts the channel.
	pub force_close_spend_delay: Option<u16>,
	/// True if the channel was initiated (and thus funded) by us.
	pub is_outbound: bool,
	/// True if the channel is confirmed, channel_ready messages have been exchanged, and the
	/// channel is not currently being shut down. `channel_ready` message exchange implies the
	/// required confirmation count has been reached (and we were connected to the peer at some
	/// point after the funding transaction received enough confirmations). The required
	/// confirmation count is provided in [`confirmations_required`].
	///
	/// [`confirmations_required`]: ChannelDetails::confirmations_required
	pub is_channel_ready: bool,
	/// The stage of the channel's shutdown.
	/// `None` for `ChannelDetails` serialized on LDK versions prior to 0.0.116.
	pub channel_shutdown_state: Option<ChannelShutdownState>,
	/// True if the channel is (a) confirmed and channel_ready messages have been exchanged, (b)
	/// the peer is connected, and (c) the channel is not currently negotiating a shutdown.
	///
	/// This is a strict superset of `is_channel_ready`.
	pub is_usable: bool,
	/// True if this channel is (or will be) publicly-announced.
	pub is_public: bool,
	/// The smallest value HTLC (in msat) we will accept, for this channel. This field
	/// is only `None` for `ChannelDetails` objects serialized prior to LDK 0.0.107
	pub inbound_htlc_minimum_msat: Option<u64>,
	/// The largest value HTLC (in msat) we currently will accept, for this channel.
	pub inbound_htlc_maximum_msat: Option<u64>,
	/// Set of configurable parameters that affect channel operation.
	///
	/// This field is only `None` for `ChannelDetails` objects serialized prior to LDK 0.0.109.
	pub config: Option<ChannelConfig>,
	/// Pending inbound HTLCs.
	///
	/// This field is empty for objects serialized with LDK versions prior to 0.0.122.
	pub pending_inbound_htlcs: Vec<InboundHTLCDetails>,
	/// Pending outbound HTLCs.
	///
	/// This field is empty for objects serialized with LDK versions prior to 0.0.122.
	pub pending_outbound_htlcs: Vec<OutboundHTLCDetails>,
}

impl ChannelDetails {
	/// Gets the current SCID which should be used to identify this channel for inbound payments.
	/// This should be used for providing invoice hints or in any other context where our
	/// counterparty will forward a payment to us.
	///
	/// This is either the [`ChannelDetails::inbound_scid_alias`], if set, or the
	/// [`ChannelDetails::short_channel_id`]. See those for more information.
	pub fn get_inbound_payment_scid(&self) -> Option<u64> {
		self.inbound_scid_alias.or(self.short_channel_id)
	}

	/// Gets the current SCID which should be used to identify this channel for outbound payments.
	/// This should be used in [`Route`]s to describe the first hop or in other contexts where
	/// we're sending or forwarding a payment outbound over this channel.
	///
	/// This is either the [`ChannelDetails::short_channel_id`], if set, or the
	/// [`ChannelDetails::outbound_scid_alias`]. See those for more information.
	pub fn get_outbound_payment_scid(&self) -> Option<u64> {
		self.short_channel_id.or(self.outbound_scid_alias)
	}

	fn from_channel_context<SP: Deref, F: Deref>(
		context: &ChannelContext<SP>, best_block_height: u32, latest_features: InitFeatures,
		fee_estimator: &LowerBoundedFeeEstimator<F>
	) -> Self
	where
		SP::Target: SignerProvider,
		F::Target: FeeEstimator
	{
		let balance = context.get_available_balances(fee_estimator);
		let (to_remote_reserve_satoshis, to_self_reserve_satoshis) =
			context.get_holder_counterparty_selected_channel_reserve_satoshis();
		ChannelDetails {
			channel_id: context.channel_id(),
			counterparty: ChannelCounterparty {
				node_id: context.get_counterparty_node_id(),
				features: latest_features,
				unspendable_punishment_reserve: to_remote_reserve_satoshis,
				forwarding_info: context.counterparty_forwarding_info(),
				// Ensures that we have actually received the `htlc_minimum_msat` value
				// from the counterparty through the `OpenChannel` or `AcceptChannel`
				// message (as they are always the first message from the counterparty).
				// Else `Channel::get_counterparty_htlc_minimum_msat` could return the
				// default `0` value set by `Channel::new_outbound`.
				outbound_htlc_minimum_msat: if context.have_received_message() {
					Some(context.get_counterparty_htlc_minimum_msat()) } else { None },
				outbound_htlc_maximum_msat: context.get_counterparty_htlc_maximum_msat(),
			},
			funding_txo: context.get_funding_txo(),
			// Note that accept_channel (or open_channel) is always the first message, so
			// `have_received_message` indicates that type negotiation has completed.
			channel_type: if context.have_received_message() { Some(context.get_channel_type().clone()) } else { None },
			short_channel_id: context.get_short_channel_id(),
			outbound_scid_alias: if context.is_usable() { Some(context.outbound_scid_alias()) } else { None },
			inbound_scid_alias: context.latest_inbound_scid_alias(),
			channel_value_satoshis: context.get_value_satoshis(),
			feerate_sat_per_1000_weight: Some(context.get_feerate_sat_per_1000_weight()),
			unspendable_punishment_reserve: to_self_reserve_satoshis,
			balance_msat: balance.balance_msat,
			inbound_capacity_msat: balance.inbound_capacity_msat,
			outbound_capacity_msat: balance.outbound_capacity_msat,
			next_outbound_htlc_limit_msat: balance.next_outbound_htlc_limit_msat,
			next_outbound_htlc_minimum_msat: balance.next_outbound_htlc_minimum_msat,
			user_channel_id: context.get_user_id(),
			confirmations_required: context.minimum_depth(),
			confirmations: Some(context.get_funding_tx_confirmations(best_block_height)),
			force_close_spend_delay: context.get_counterparty_selected_contest_delay(),
			is_outbound: context.is_outbound(),
			is_channel_ready: context.is_usable(),
			is_usable: context.is_live(),
			is_public: context.should_announce(),
			inbound_htlc_minimum_msat: Some(context.get_holder_htlc_minimum_msat()),
			inbound_htlc_maximum_msat: context.get_holder_htlc_maximum_msat(),
			config: Some(context.config()),
			channel_shutdown_state: Some(context.shutdown_state()),
			pending_inbound_htlcs: context.get_pending_inbound_htlc_details(),
			pending_outbound_htlcs: context.get_pending_outbound_htlc_details(),
		}
	}
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// Further information on the details of the channel shutdown.
/// Upon channels being forced closed (i.e. commitment transaction confirmation detected
/// by `ChainMonitor`), ChannelShutdownState will be set to `ShutdownComplete` or
/// the channel will be removed shortly.
/// Also note, that in normal operation, peers could disconnect at any of these states
/// and require peer re-connection before making progress onto other states
pub enum ChannelShutdownState {
	/// Channel has not sent or received a shutdown message.
	NotShuttingDown,
	/// Local node has sent a shutdown message for this channel.
	ShutdownInitiated,
	/// Shutdown message exchanges have concluded and the channels are in the midst of
	/// resolving all existing open HTLCs before closing can continue.
	ResolvingHTLCs,
	/// All HTLCs have been resolved, nodes are currently negotiating channel close onchain fee rates.
	NegotiatingClosingFee,
	/// We've successfully negotiated a closing_signed dance. At this point `ChannelManager` is about
	/// to drop the channel.
	ShutdownComplete,
}

/// Used by [`ChannelManager::list_recent_payments`] to express the status of recent payments.
/// These include payments that have yet to find a successful path, or have unresolved HTLCs.
#[derive(Debug, PartialEq)]
pub enum RecentPaymentDetails {
	/// When an invoice was requested and thus a payment has not yet been sent.
	AwaitingInvoice {
		/// A user-provided identifier in [`ChannelManager::send_payment`] used to uniquely identify
		/// a payment and ensure idempotency in LDK.
		payment_id: PaymentId,
	},
	/// When a payment is still being sent and awaiting successful delivery.
	Pending {
		/// A user-provided identifier in [`ChannelManager::send_payment`] used to uniquely identify
		/// a payment and ensure idempotency in LDK.
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
		/// A user-provided identifier in [`ChannelManager::send_payment`] used to uniquely identify
		/// a payment and ensure idempotency in LDK.
		payment_id: PaymentId,
		/// Hash of the payment that was claimed. `None` for serializations of [`ChannelManager`]
		/// made before LDK version 0.0.104.
		payment_hash: Option<PaymentHash>,
	},
	/// After a payment's retries are exhausted per the provided [`Retry`], or it is explicitly
	/// abandoned via [`ChannelManager::abandon_payment`], it is marked as abandoned until all
	/// pending HTLCs for this payment resolve and an [`Event::PaymentFailed`] is generated.
	Abandoned {
		/// A user-provided identifier in [`ChannelManager::send_payment`] used to uniquely identify
		/// a payment and ensure idempotency in LDK.
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

macro_rules! handle_error {
	($self: ident, $internal: expr, $counterparty_node_id: expr) => { {
		// In testing, ensure there are no deadlocks where the lock is already held upon
		// entering the macro.
		debug_assert_ne!($self.pending_events.held_by_thread(), LockHeldState::HeldByThread);
		debug_assert_ne!($self.per_peer_state.held_by_thread(), LockHeldState::HeldByThread);

		match $internal {
			Ok(msg) => Ok(msg),
			Err(MsgHandleErrInternal { err, shutdown_finish, .. }) => {
				let mut msg_event = None;

				if let Some((shutdown_res, update_option)) = shutdown_finish {
					let counterparty_node_id = shutdown_res.counterparty_node_id;
					let channel_id = shutdown_res.channel_id;
					let logger = WithContext::from(
						&$self.logger, Some(counterparty_node_id), Some(channel_id),
					);
					log_error!(logger, "Force-closing channel: {}", err.err);

					$self.finish_close_channel(shutdown_res);
					if let Some(update) = update_option {
						let mut pending_broadcast_messages = $self.pending_broadcast_messages.lock().unwrap();
						pending_broadcast_messages.push(events::MessageSendEvent::BroadcastChannelUpdate {
							msg: update
						});
					}
				} else {
					log_error!($self.logger, "Got non-closing error: {}", err.err);
				}

				if let msgs::ErrorAction::IgnoreError = err.action {
				} else {
					msg_event = Some(events::MessageSendEvent::HandleError {
						node_id: $counterparty_node_id,
						action: err.action.clone()
					});
				}

				if let Some(msg_event) = msg_event {
					let per_peer_state = $self.per_peer_state.read().unwrap();
					if let Some(peer_state_mutex) = per_peer_state.get(&$counterparty_node_id) {
						let mut peer_state = peer_state_mutex.lock().unwrap();
						peer_state.pending_msg_events.push(msg_event);
					}
				}

				// Return error in case higher-API need one
				Err(err)
			},
		}
	} };
}

macro_rules! update_maps_on_chan_removal {
	($self: expr, $channel_context: expr) => {{
		if let Some(outpoint) = $channel_context.get_funding_txo() {
			$self.outpoint_to_peer.lock().unwrap().remove(&outpoint);
		}
		let mut short_to_chan_info = $self.short_to_chan_info.write().unwrap();
		if let Some(short_id) = $channel_context.get_short_channel_id() {
			short_to_chan_info.remove(&short_id);
		} else {
			// If the channel was never confirmed on-chain prior to its closure, remove the
			// outbound SCID alias we used for it from the collision-prevention set. While we
			// generally want to avoid ever re-using an outbound SCID alias across all channels, we
			// also don't want a counterparty to be able to trivially cause a memory leak by simply
			// opening a million channels with us which are closed before we ever reach the funding
			// stage.
			let alias_removed = $self.outbound_scid_aliases.lock().unwrap().remove(&$channel_context.outbound_scid_alias());
			debug_assert!(alias_removed);
		}
		short_to_chan_info.remove(&$channel_context.outbound_scid_alias());
	}}
}

/// Returns (boolean indicating if we should remove the Channel object from memory, a mapped error)
macro_rules! convert_chan_phase_err {
	($self: ident, $err: expr, $channel: expr, $channel_id: expr, MANUAL_CHANNEL_UPDATE, $channel_update: expr) => {
		match $err {
			ChannelError::Warn(msg) => {
				(false, MsgHandleErrInternal::from_chan_no_close(ChannelError::Warn(msg), *$channel_id))
			},
			ChannelError::Ignore(msg) => {
				(false, MsgHandleErrInternal::from_chan_no_close(ChannelError::Ignore(msg), *$channel_id))
			},
			ChannelError::Close(msg) => {
				let logger = WithChannelContext::from(&$self.logger, &$channel.context);
				log_error!(logger, "Closing channel {} due to close-required error: {}", $channel_id, msg);
				update_maps_on_chan_removal!($self, $channel.context);
				let reason = ClosureReason::ProcessingError { err: msg.clone() };
				let shutdown_res = $channel.context.force_shutdown(true, reason);
				let err =
					MsgHandleErrInternal::from_finish_shutdown(msg, *$channel_id, shutdown_res, $channel_update);
				(true, err)
			},
		}
	};
	($self: ident, $err: expr, $channel: expr, $channel_id: expr, FUNDED_CHANNEL) => {
		convert_chan_phase_err!($self, $err, $channel, $channel_id, MANUAL_CHANNEL_UPDATE, { $self.get_channel_update_for_broadcast($channel).ok() })
	};
	($self: ident, $err: expr, $channel: expr, $channel_id: expr, UNFUNDED_CHANNEL) => {
		convert_chan_phase_err!($self, $err, $channel, $channel_id, MANUAL_CHANNEL_UPDATE, None)
	};
	($self: ident, $err: expr, $channel_phase: expr, $channel_id: expr) => {
		match $channel_phase {
			ChannelPhase::Funded(channel) => {
				convert_chan_phase_err!($self, $err, channel, $channel_id, FUNDED_CHANNEL)
			},
			ChannelPhase::UnfundedOutboundV1(channel) => {
				convert_chan_phase_err!($self, $err, channel, $channel_id, UNFUNDED_CHANNEL)
			},
			ChannelPhase::UnfundedInboundV1(channel) => {
				convert_chan_phase_err!($self, $err, channel, $channel_id, UNFUNDED_CHANNEL)
			},
			#[cfg(dual_funding)]
			ChannelPhase::UnfundedOutboundV2(channel) => {
				convert_chan_phase_err!($self, $err, channel, $channel_id, UNFUNDED_CHANNEL)
			},
			#[cfg(dual_funding)]
			ChannelPhase::UnfundedInboundV2(channel) => {
				convert_chan_phase_err!($self, $err, channel, $channel_id, UNFUNDED_CHANNEL)
			},
		}
	};
}

macro_rules! break_chan_phase_entry {
	($self: ident, $res: expr, $entry: expr) => {
		match $res {
			Ok(res) => res,
			Err(e) => {
				let key = *$entry.key();
				let (drop, res) = convert_chan_phase_err!($self, e, $entry.get_mut(), &key);
				if drop {
					$entry.remove_entry();
				}
				break Err(res);
			}
		}
	}
}

macro_rules! try_chan_phase_entry {
	($self: ident, $res: expr, $entry: expr) => {
		match $res {
			Ok(res) => res,
			Err(e) => {
				let key = *$entry.key();
				let (drop, res) = convert_chan_phase_err!($self, e, $entry.get_mut(), &key);
				if drop {
					$entry.remove_entry();
				}
				return Err(res);
			}
		}
	}
}

macro_rules! remove_channel_phase {
	($self: expr, $entry: expr) => {
		{
			let channel = $entry.remove_entry().1;
			update_maps_on_chan_removal!($self, &channel.context());
			channel
		}
	}
}

macro_rules! send_channel_ready {
	($self: ident, $pending_msg_events: expr, $channel: expr, $channel_ready_msg: expr) => {{
		$pending_msg_events.push(events::MessageSendEvent::SendChannelReady {
			node_id: $channel.context.get_counterparty_node_id(),
			msg: $channel_ready_msg,
		});
		// Note that we may send a `channel_ready` multiple times for a channel if we reconnect, so
		// we allow collisions, but we shouldn't ever be updating the channel ID pointed to.
		let mut short_to_chan_info = $self.short_to_chan_info.write().unwrap();
		let outbound_alias_insert = short_to_chan_info.insert($channel.context.outbound_scid_alias(), ($channel.context.get_counterparty_node_id(), $channel.context.channel_id()));
		assert!(outbound_alias_insert.is_none() || outbound_alias_insert.unwrap() == ($channel.context.get_counterparty_node_id(), $channel.context.channel_id()),
			"SCIDs should never collide - ensure you weren't behind the chain tip by a full month when creating channels");
		if let Some(real_scid) = $channel.context.get_short_channel_id() {
			let scid_insert = short_to_chan_info.insert(real_scid, ($channel.context.get_counterparty_node_id(), $channel.context.channel_id()));
			assert!(scid_insert.is_none() || scid_insert.unwrap() == ($channel.context.get_counterparty_node_id(), $channel.context.channel_id()),
				"SCIDs should never collide - ensure you weren't behind the chain tip by a full month when creating channels");
		}
	}}
}

macro_rules! emit_channel_pending_event {
	($locked_events: expr, $channel: expr) => {
		if $channel.context.should_emit_channel_pending_event() {
			$locked_events.push_back((events::Event::ChannelPending {
				channel_id: $channel.context.channel_id(),
				former_temporary_channel_id: $channel.context.temporary_channel_id(),
				counterparty_node_id: $channel.context.get_counterparty_node_id(),
				user_channel_id: $channel.context.get_user_id(),
				funding_txo: $channel.context.get_funding_txo().unwrap().into_bitcoin_outpoint(),
				channel_type: Some($channel.context.get_channel_type().clone()),
			}, None));
			$channel.context.set_channel_pending_event_emitted();
		}
	}
}

macro_rules! emit_channel_ready_event {
	($locked_events: expr, $channel: expr) => {
		if $channel.context.should_emit_channel_ready_event() {
			debug_assert!($channel.context.channel_pending_event_emitted());
			$locked_events.push_back((events::Event::ChannelReady {
				channel_id: $channel.context.channel_id(),
				user_channel_id: $channel.context.get_user_id(),
				counterparty_node_id: $channel.context.get_counterparty_node_id(),
				channel_type: $channel.context.get_channel_type().clone(),
			}, None));
			$channel.context.set_channel_ready_event_emitted();
		}
	}
}

macro_rules! handle_monitor_update_completion {
	($self: ident, $peer_state_lock: expr, $peer_state: expr, $per_peer_state_lock: expr, $chan: expr) => { {
		let logger = WithChannelContext::from(&$self.logger, &$chan.context);
		let mut updates = $chan.monitor_updating_restored(&&logger,
			&$self.node_signer, $self.chain_hash, &$self.default_configuration,
			$self.best_block.read().unwrap().height);
		let counterparty_node_id = $chan.context.get_counterparty_node_id();
		let channel_update = if updates.channel_ready.is_some() && $chan.context.is_usable() {
			// We only send a channel_update in the case where we are just now sending a
			// channel_ready and the channel is in a usable state. We may re-send a
			// channel_update later through the announcement_signatures process for public
			// channels, but there's no reason not to just inform our counterparty of our fees
			// now.
			if let Ok(msg) = $self.get_channel_update_for_unicast($chan) {
				Some(events::MessageSendEvent::SendChannelUpdate {
					node_id: counterparty_node_id,
					msg,
				})
			} else { None }
		} else { None };

		let update_actions = $peer_state.monitor_update_blocked_actions
			.remove(&$chan.context.channel_id()).unwrap_or(Vec::new());

		let (htlc_forwards, decode_update_add_htlcs) = $self.handle_channel_resumption(
			&mut $peer_state.pending_msg_events, $chan, updates.raa,
			updates.commitment_update, updates.order, updates.accepted_htlcs, updates.pending_update_adds,
			updates.funding_broadcastable, updates.channel_ready,
			updates.announcement_sigs);
		if let Some(upd) = channel_update {
			$peer_state.pending_msg_events.push(upd);
		}

		let channel_id = $chan.context.channel_id();
		let unbroadcasted_batch_funding_txid = $chan.context.unbroadcasted_batch_funding_txid();
		core::mem::drop($peer_state_lock);
		core::mem::drop($per_peer_state_lock);

		// If the channel belongs to a batch funding transaction, the progress of the batch
		// should be updated as we have received funding_signed and persisted the monitor.
		if let Some(txid) = unbroadcasted_batch_funding_txid {
			let mut funding_batch_states = $self.funding_batch_states.lock().unwrap();
			let mut batch_completed = false;
			if let Some(batch_state) = funding_batch_states.get_mut(&txid) {
				let channel_state = batch_state.iter_mut().find(|(chan_id, pubkey, _)| (
					*chan_id == channel_id &&
					*pubkey == counterparty_node_id
				));
				if let Some(channel_state) = channel_state {
					channel_state.2 = true;
				} else {
					debug_assert!(false, "Missing channel batch state for channel which completed initial monitor update");
				}
				batch_completed = batch_state.iter().all(|(_, _, completed)| *completed);
			} else {
				debug_assert!(false, "Missing batch state for channel which completed initial monitor update");
			}

			// When all channels in a batched funding transaction have become ready, it is not necessary
			// to track the progress of the batch anymore and the state of the channels can be updated.
			if batch_completed {
				let removed_batch_state = funding_batch_states.remove(&txid).into_iter().flatten();
				let per_peer_state = $self.per_peer_state.read().unwrap();
				let mut batch_funding_tx = None;
				for (channel_id, counterparty_node_id, _) in removed_batch_state {
					if let Some(peer_state_mutex) = per_peer_state.get(&counterparty_node_id) {
						let mut peer_state = peer_state_mutex.lock().unwrap();
						if let Some(ChannelPhase::Funded(chan)) = peer_state.channel_by_id.get_mut(&channel_id) {
							batch_funding_tx = batch_funding_tx.or_else(|| chan.context.unbroadcasted_funding());
							chan.set_batch_ready();
							let mut pending_events = $self.pending_events.lock().unwrap();
							emit_channel_pending_event!(pending_events, chan);
						}
					}
				}
				if let Some(tx) = batch_funding_tx {
					log_info!($self.logger, "Broadcasting batch funding transaction with txid {}", tx.txid());
					$self.tx_broadcaster.broadcast_transactions(&[&tx]);
				}
			}
		}

		$self.handle_monitor_update_completion_actions(update_actions);

		if let Some(forwards) = htlc_forwards {
			$self.forward_htlcs(&mut [forwards][..]);
		}
		if let Some(decode) = decode_update_add_htlcs {
			$self.push_decode_update_add_htlcs(decode);
		}
		$self.finalize_claims(updates.finalized_claimed_htlcs);
		for failure in updates.failed_htlcs.drain(..) {
			let receiver = HTLCDestination::NextHopChannel { node_id: Some(counterparty_node_id), channel_id };
			$self.fail_htlc_backwards_internal(&failure.0, &failure.1, &failure.2, receiver);
		}
	} }
}

macro_rules! handle_new_monitor_update {
	($self: ident, $update_res: expr, $chan: expr, _internal, $completed: expr) => { {
		debug_assert!($self.background_events_processed_since_startup.load(Ordering::Acquire));
		let logger = WithChannelContext::from(&$self.logger, &$chan.context);
		match $update_res {
			ChannelMonitorUpdateStatus::UnrecoverableError => {
				let err_str = "ChannelMonitor[Update] persistence failed unrecoverably. This indicates we cannot continue normal operation and must shut down.";
				log_error!(logger, "{}", err_str);
				panic!("{}", err_str);
			},
			ChannelMonitorUpdateStatus::InProgress => {
				log_debug!(logger, "ChannelMonitor update for {} in flight, holding messages until the update completes.",
					&$chan.context.channel_id());
				false
			},
			ChannelMonitorUpdateStatus::Completed => {
				$completed;
				true
			},
		}
	} };
	($self: ident, $update_res: expr, $peer_state_lock: expr, $peer_state: expr, $per_peer_state_lock: expr, $chan: expr, INITIAL_MONITOR) => {
		handle_new_monitor_update!($self, $update_res, $chan, _internal,
			handle_monitor_update_completion!($self, $peer_state_lock, $peer_state, $per_peer_state_lock, $chan))
	};
	($self: ident, $funding_txo: expr, $update: expr, $peer_state_lock: expr, $peer_state: expr, $per_peer_state_lock: expr, $chan: expr) => { {
		let in_flight_updates = $peer_state.in_flight_monitor_updates.entry($funding_txo)
			.or_insert_with(Vec::new);
		// During startup, we push monitor updates as background events through to here in
		// order to replay updates that were in-flight when we shut down. Thus, we have to
		// filter for uniqueness here.
		let idx = in_flight_updates.iter().position(|upd| upd == &$update)
			.unwrap_or_else(|| {
				in_flight_updates.push($update);
				in_flight_updates.len() - 1
			});
		let update_res = $self.chain_monitor.update_channel($funding_txo, &in_flight_updates[idx]);
		handle_new_monitor_update!($self, update_res, $chan, _internal,
			{
				let _ = in_flight_updates.remove(idx);
				if in_flight_updates.is_empty() && $chan.blocked_monitor_updates_pending() == 0 {
					handle_monitor_update_completion!($self, $peer_state_lock, $peer_state, $per_peer_state_lock, $chan);
				}
			})
	} };
}

macro_rules! process_events_body {
	($self: expr, $event_to_handle: expr, $handle_event: expr) => {
		let mut processed_all_events = false;
		while !processed_all_events {
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
			let num_events = pending_events.len();
			if !pending_events.is_empty() {
				result = NotifyOption::DoPersist;
			}

			let mut post_event_actions = Vec::new();

			for (event, action_opt) in pending_events {
				$event_to_handle = event;
				$handle_event;
				if let Some(action) = action_opt {
					post_event_actions.push(action);
				}
			}

			{
				let mut pending_events = $self.pending_events.lock().unwrap();
				pending_events.drain(..num_events);
				processed_all_events = pending_events.is_empty();
				// Note that `push_pending_forwards_ev` relies on `pending_events_processor` being
				// updated here with the `pending_events` lock acquired.
				$self.pending_events_processor.store(false, Ordering::Release);
			}

			if !post_event_actions.is_empty() {
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

impl<M: Deref, T: Deref, ES: Deref, NS: Deref, SP: Deref, F: Deref, R: Deref, L: Deref> ChannelManager<M, T, ES, NS, SP, F, R, L>
where
	M::Target: chain::Watch<<SP::Target as SignerProvider>::EcdsaSigner>,
	T::Target: BroadcasterInterface,
	ES::Target: EntropySource,
	NS::Target: NodeSigner,
	SP::Target: SignerProvider,
	F::Target: FeeEstimator,
	R::Target: Router,
	L::Target: Logger,
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
	/// disconnected using its [`block_connected`] and [`block_disconnected`] methods, starting
	/// from after [`params.best_block.block_hash`]. See [`chain::Listen`] and [`chain::Confirm`] for
	/// more details.
	///
	/// [`block_connected`]: chain::Listen::block_connected
	/// [`block_disconnected`]: chain::Listen::block_disconnected
	/// [`params.best_block.block_hash`]: chain::BestBlock::block_hash
	pub fn new(
		fee_est: F, chain_monitor: M, tx_broadcaster: T, router: R, logger: L, entropy_source: ES,
		node_signer: NS, signer_provider: SP, config: UserConfig, params: ChainParameters,
		current_timestamp: u32,
	) -> Self {
		let mut secp_ctx = Secp256k1::new();
		secp_ctx.seeded_randomize(&entropy_source.get_secure_random_bytes());
		let inbound_pmt_key_material = node_signer.get_inbound_payment_key_material();
		let expanded_inbound_key = inbound_payment::ExpandedKey::new(&inbound_pmt_key_material);
		ChannelManager {
			default_configuration: config.clone(),
			chain_hash: ChainHash::using_genesis_block(params.network),
			fee_estimator: LowerBoundedFeeEstimator::new(fee_est),
			chain_monitor,
			tx_broadcaster,
			router,

			best_block: RwLock::new(params.best_block),

			outbound_scid_aliases: Mutex::new(new_hash_set()),
			pending_inbound_payments: Mutex::new(new_hash_map()),
			pending_outbound_payments: OutboundPayments::new(),
			forward_htlcs: Mutex::new(new_hash_map()),
			decode_update_add_htlcs: Mutex::new(new_hash_map()),
			claimable_payments: Mutex::new(ClaimablePayments { claimable_payments: new_hash_map(), pending_claiming_payments: new_hash_map() }),
			pending_intercepted_htlcs: Mutex::new(new_hash_map()),
			outpoint_to_peer: Mutex::new(new_hash_map()),
			short_to_chan_info: FairRwLock::new(new_hash_map()),

			our_network_pubkey: node_signer.get_node_id(Recipient::Node).unwrap(),
			secp_ctx,

			inbound_payment_key: expanded_inbound_key,
			fake_scid_rand_bytes: entropy_source.get_secure_random_bytes(),

			probing_cookie_secret: entropy_source.get_secure_random_bytes(),

			highest_seen_timestamp: AtomicUsize::new(current_timestamp as usize),

			per_peer_state: FairRwLock::new(new_hash_map()),

			pending_events: Mutex::new(VecDeque::new()),
			pending_events_processor: AtomicBool::new(false),
			pending_background_events: Mutex::new(Vec::new()),
			total_consistency_lock: RwLock::new(()),
			background_events_processed_since_startup: AtomicBool::new(false),
			event_persist_notifier: Notifier::new(),
			needs_persist_flag: AtomicBool::new(false),
			funding_batch_states: Mutex::new(BTreeMap::new()),

			pending_offers_messages: Mutex::new(Vec::new()),
			pending_broadcast_messages: Mutex::new(Vec::new()),

			entropy_source,
			node_signer,
			signer_provider,

			logger,
		}
	}

	/// Gets the current configuration applied to all new channels.
	pub fn get_current_default_configuration(&self) -> &UserConfig {
		&self.default_configuration
	}

	fn create_and_insert_outbound_scid_alias(&self) -> u64 {
		let height = self.best_block.read().unwrap().height;
		let mut outbound_scid_alias = 0;
		let mut i = 0;
		loop {
			if cfg!(fuzzing) { // fuzzing chacha20 doesn't use the key at all so we always get the same alias
				outbound_scid_alias += 1;
			} else {
				outbound_scid_alias = fake_scid::Namespace::OutboundAlias.get_fake_scid(height, &self.chain_hash, &self.fake_scid_rand_bytes, &self.entropy_source);
			}
			if outbound_scid_alias != 0 && self.outbound_scid_aliases.lock().unwrap().insert(outbound_scid_alias) {
				break;
			}
			i += 1;
			if i > 1_000_000 { panic!("Your RNG is busted or we ran out of possible outbound SCID aliases (which should never happen before we run out of memory to store channels"); }
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

		if let Some(temporary_channel_id) = temporary_channel_id {
			if peer_state.channel_by_id.contains_key(&temporary_channel_id) {
				return Err(APIError::APIMisuseError{ err: format!("Channel with temporary channel ID {} already exists!", temporary_channel_id)});
			}
		}

		let channel = {
			let outbound_scid_alias = self.create_and_insert_outbound_scid_alias();
			let their_features = &peer_state.latest_features;
			let config = if override_config.is_some() { override_config.as_ref().unwrap() } else { &self.default_configuration };
			match OutboundV1Channel::new(&self.fee_estimator, &self.entropy_source, &self.signer_provider, their_network_key,
				their_features, channel_value_satoshis, push_msat, user_channel_id, config,
				self.best_block.read().unwrap().height, outbound_scid_alias, temporary_channel_id)
			{
				Ok(res) => res,
				Err(e) => {
					self.outbound_scid_aliases.lock().unwrap().remove(&outbound_scid_alias);
					return Err(e);
				},
			}
		};
		let res = channel.get_open_channel(self.chain_hash);

		let temporary_channel_id = channel.context.channel_id();
		match peer_state.channel_by_id.entry(temporary_channel_id) {
			hash_map::Entry::Occupied(_) => {
				if cfg!(fuzzing) {
					return Err(APIError::APIMisuseError { err: "Fuzzy bad RNG".to_owned() });
				} else {
					panic!("RNG is bad???");
				}
			},
			hash_map::Entry::Vacant(entry) => { entry.insert(ChannelPhase::UnfundedOutboundV1(channel)); }
		}

		peer_state.pending_msg_events.push(events::MessageSendEvent::SendOpenChannel {
			node_id: their_network_key,
			msg: res,
		});
		Ok(temporary_channel_id)
	}

	fn list_funded_channels_with_filter<Fn: FnMut(&(&ChannelId, &Channel<SP>)) -> bool + Copy>(&self, f: Fn) -> Vec<ChannelDetails> {
		// Allocate our best estimate of the number of channels we have in the `res`
		// Vec. Sadly the `short_to_chan_info` map doesn't cover channels without
		// a scid or a scid alias, and the `outpoint_to_peer` shouldn't be used outside
		// of the ChannelMonitor handling. Therefore reallocations may still occur, but is
		// unlikely as the `short_to_chan_info` map often contains 2 entries for
		// the same channel.
		let mut res = Vec::with_capacity(self.short_to_chan_info.read().unwrap().len());
		{
			let best_block_height = self.best_block.read().unwrap().height;
			let per_peer_state = self.per_peer_state.read().unwrap();
			for (_cp_id, peer_state_mutex) in per_peer_state.iter() {
				let mut peer_state_lock = peer_state_mutex.lock().unwrap();
				let peer_state = &mut *peer_state_lock;
				res.extend(peer_state.channel_by_id.iter()
					.filter_map(|(chan_id, phase)| match phase {
						// Only `Channels` in the `ChannelPhase::Funded` phase can be considered funded.
						ChannelPhase::Funded(chan) => Some((chan_id, chan)),
						_ => None,
					})
					.filter(f)
					.map(|(_channel_id, channel)| {
						ChannelDetails::from_channel_context(&channel.context, best_block_height,
							peer_state.latest_features.clone(), &self.fee_estimator)
					})
				);
			}
		}
		res
	}

	/// Gets the list of open channels, in random order. See [`ChannelDetails`] field documentation for
	/// more information.
	pub fn list_channels(&self) -> Vec<ChannelDetails> {
		// Allocate our best estimate of the number of channels we have in the `res`
		// Vec. Sadly the `short_to_chan_info` map doesn't cover channels without
		// a scid or a scid alias, and the `outpoint_to_peer` shouldn't be used outside
		// of the ChannelMonitor handling. Therefore reallocations may still occur, but is
		// unlikely as the `short_to_chan_info` map often contains 2 entries for
		// the same channel.
		let mut res = Vec::with_capacity(self.short_to_chan_info.read().unwrap().len());
		{
			let best_block_height = self.best_block.read().unwrap().height;
			let per_peer_state = self.per_peer_state.read().unwrap();
			for (_cp_id, peer_state_mutex) in per_peer_state.iter() {
				let mut peer_state_lock = peer_state_mutex.lock().unwrap();
				let peer_state = &mut *peer_state_lock;
				for context in peer_state.channel_by_id.iter().map(|(_, phase)| phase.context()) {
					let details = ChannelDetails::from_channel_context(context, best_block_height,
						peer_state.latest_features.clone(), &self.fee_estimator);
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
		self.list_funded_channels_with_filter(|&(_, ref channel)| channel.context.is_live())
	}

	/// Gets the list of channels we have with a given counterparty, in random order.
	pub fn list_channels_with_counterparty(&self, counterparty_node_id: &PublicKey) -> Vec<ChannelDetails> {
		let best_block_height = self.best_block.read().unwrap().height;
		let per_peer_state = self.per_peer_state.read().unwrap();

		if let Some(peer_state_mutex) = per_peer_state.get(counterparty_node_id) {
			let mut peer_state_lock = peer_state_mutex.lock().unwrap();
			let peer_state = &mut *peer_state_lock;
			let features = &peer_state.latest_features;
			let context_to_details = |context| {
				ChannelDetails::from_channel_context(context, best_block_height, features.clone(), &self.fee_estimator)
			};
			return peer_state.channel_by_id
				.iter()
				.map(|(_, phase)| phase.context())
				.map(context_to_details)
				.collect();
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
	pub fn list_recent_payments(&self) -> Vec<RecentPaymentDetails> {
		self.pending_outbound_payments.pending_outbound_payments.lock().unwrap().iter()
			.filter_map(|(payment_id, pending_outbound_payment)| match pending_outbound_payment {
				PendingOutboundPayment::AwaitingInvoice { .. } => {
					Some(RecentPaymentDetails::AwaitingInvoice { payment_id: *payment_id })
				},
				// InvoiceReceived is an intermediate state and doesn't need to be exposed
				PendingOutboundPayment::InvoiceReceived { .. } => {
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

	fn close_channel_internal(&self, channel_id: &ChannelId, counterparty_node_id: &PublicKey, target_feerate_sats_per_1000_weight: Option<u32>, override_shutdown_script: Option<ShutdownScript>) -> Result<(), APIError> {
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(self);

		let mut failed_htlcs: Vec<(HTLCSource, PaymentHash)> = Vec::new();
		let mut shutdown_result = None;

		{
			let per_peer_state = self.per_peer_state.read().unwrap();

			let peer_state_mutex = per_peer_state.get(counterparty_node_id)
				.ok_or_else(|| APIError::ChannelUnavailable { err: format!("Can't find a peer matching the passed counterparty node_id {}", counterparty_node_id) })?;

			let mut peer_state_lock = peer_state_mutex.lock().unwrap();
			let peer_state = &mut *peer_state_lock;

			match peer_state.channel_by_id.entry(channel_id.clone()) {
				hash_map::Entry::Occupied(mut chan_phase_entry) => {
					if let ChannelPhase::Funded(chan) = chan_phase_entry.get_mut() {
						let funding_txo_opt = chan.context.get_funding_txo();
						let their_features = &peer_state.latest_features;
						let (shutdown_msg, mut monitor_update_opt, htlcs) =
							chan.get_shutdown(&self.signer_provider, their_features, target_feerate_sats_per_1000_weight, override_shutdown_script)?;
						failed_htlcs = htlcs;

						// We can send the `shutdown` message before updating the `ChannelMonitor`
						// here as we don't need the monitor update to complete until we send a
						// `shutdown_signed`, which we'll delay if we're pending a monitor update.
						peer_state.pending_msg_events.push(events::MessageSendEvent::SendShutdown {
							node_id: *counterparty_node_id,
							msg: shutdown_msg,
						});

						debug_assert!(monitor_update_opt.is_none() || !chan.is_shutdown(),
							"We can't both complete shutdown and generate a monitor update");

						// Update the monitor with the shutdown script if necessary.
						if let Some(monitor_update) = monitor_update_opt.take() {
							handle_new_monitor_update!(self, funding_txo_opt.unwrap(), monitor_update,
								peer_state_lock, peer_state, per_peer_state, chan);
						}
					} else {
						let mut chan_phase = remove_channel_phase!(self, chan_phase_entry);
						shutdown_result = Some(chan_phase.context_mut().force_shutdown(false, ClosureReason::HolderForceClosed));
					}
				},
				hash_map::Entry::Vacant(_) => {
					return Err(APIError::ChannelUnavailable {
						err: format!(
							"Channel with id {} not found for the passed counterparty node_id {}",
							channel_id, counterparty_node_id,
						)
					});
				},
			}
		}

		for htlc_source in failed_htlcs.drain(..) {
			let reason = HTLCFailReason::from_failure_code(0x4000 | 8);
			let receiver = HTLCDestination::NextHopChannel { node_id: Some(*counterparty_node_id), channel_id: *channel_id };
			self.fail_htlc_backwards_internal(&htlc_source.0, &htlc_source.1, &reason, receiver);
		}

		if let Some(shutdown_result) = shutdown_result {
			self.finish_close_channel(shutdown_result);
		}

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
	/// [`SendShutdown`]: crate::events::MessageSendEvent::SendShutdown
	pub fn close_channel(&self, channel_id: &ChannelId, counterparty_node_id: &PublicKey) -> Result<(), APIError> {
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
	/// ['ChannelHandshakeConfig::commit_upfront_shutdown_pubkey`]. The given shutdown script must
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
	/// [`SendShutdown`]: crate::events::MessageSendEvent::SendShutdown
	pub fn close_channel_with_feerate_and_script(&self, channel_id: &ChannelId, counterparty_node_id: &PublicKey, target_feerate_sats_per_1000_weight: Option<u32>, shutdown_script: Option<ShutdownScript>) -> Result<(), APIError> {
		self.close_channel_internal(channel_id, counterparty_node_id, target_feerate_sats_per_1000_weight, shutdown_script)
	}

	fn finish_close_channel(&self, mut shutdown_res: ShutdownResult) {
		debug_assert_ne!(self.per_peer_state.held_by_thread(), LockHeldState::HeldByThread);
		#[cfg(debug_assertions)]
		for (_, peer) in self.per_peer_state.read().unwrap().iter() {
			debug_assert_ne!(peer.held_by_thread(), LockHeldState::HeldByThread);
		}

		let logger = WithContext::from(
			&self.logger, Some(shutdown_res.counterparty_node_id), Some(shutdown_res.channel_id),
		);

		log_debug!(logger, "Finishing closure of channel due to {} with {} HTLCs to fail",
			shutdown_res.closure_reason, shutdown_res.dropped_outbound_htlcs.len());
		for htlc_source in shutdown_res.dropped_outbound_htlcs.drain(..) {
			let (source, payment_hash, counterparty_node_id, channel_id) = htlc_source;
			let reason = HTLCFailReason::from_failure_code(0x4000 | 8);
			let receiver = HTLCDestination::NextHopChannel { node_id: Some(counterparty_node_id), channel_id };
			self.fail_htlc_backwards_internal(&source, &payment_hash, &reason, receiver);
		}
		if let Some((_, funding_txo, _channel_id, monitor_update)) = shutdown_res.monitor_update {
			// There isn't anything we can do if we get an update failure - we're already
			// force-closing. The monitor update on the required in-memory copy should broadcast
			// the latest local state, which is the best we can do anyway. Thus, it is safe to
			// ignore the result here.
			let _ = self.chain_monitor.update_channel(funding_txo, &monitor_update);
		}
		let mut shutdown_results = Vec::new();
		if let Some(txid) = shutdown_res.unbroadcasted_batch_funding_txid {
			let mut funding_batch_states = self.funding_batch_states.lock().unwrap();
			let affected_channels = funding_batch_states.remove(&txid).into_iter().flatten();
			let per_peer_state = self.per_peer_state.read().unwrap();
			let mut has_uncompleted_channel = None;
			for (channel_id, counterparty_node_id, state) in affected_channels {
				if let Some(peer_state_mutex) = per_peer_state.get(&counterparty_node_id) {
					let mut peer_state = peer_state_mutex.lock().unwrap();
					if let Some(mut chan) = peer_state.channel_by_id.remove(&channel_id) {
						update_maps_on_chan_removal!(self, &chan.context());
						shutdown_results.push(chan.context_mut().force_shutdown(false, ClosureReason::FundingBatchClosure));
					}
				}
				has_uncompleted_channel = Some(has_uncompleted_channel.map_or(!state, |v| v || !state));
			}
			debug_assert!(
				has_uncompleted_channel.unwrap_or(true),
				"Closing a batch where all channels have completed initial monitor update",
			);
		}

		{
			let mut pending_events = self.pending_events.lock().unwrap();
			pending_events.push_back((events::Event::ChannelClosed {
				channel_id: shutdown_res.channel_id,
				user_channel_id: shutdown_res.user_channel_id,
				reason: shutdown_res.closure_reason,
				counterparty_node_id: Some(shutdown_res.counterparty_node_id),
				channel_capacity_sats: Some(shutdown_res.channel_capacity_satoshis),
				channel_funding_txo: shutdown_res.channel_funding_txo,
			}, None));

			if let Some(transaction) = shutdown_res.unbroadcasted_funding_tx {
				pending_events.push_back((events::Event::DiscardFunding {
					channel_id: shutdown_res.channel_id, transaction
				}, None));
			}
		}
		for shutdown_result in shutdown_results.drain(..) {
			self.finish_close_channel(shutdown_result);
		}
	}

	/// `peer_msg` should be set when we receive a message from a peer, but not set when the
	/// user closes, which will be re-exposed as the `ChannelClosed` reason.
	fn force_close_channel_with_peer(&self, channel_id: &ChannelId, peer_node_id: &PublicKey, peer_msg: Option<&String>, broadcast: bool)
	-> Result<PublicKey, APIError> {
		let per_peer_state = self.per_peer_state.read().unwrap();
		let peer_state_mutex = per_peer_state.get(peer_node_id)
			.ok_or_else(|| APIError::ChannelUnavailable { err: format!("Can't find a peer matching the passed counterparty node_id {}", peer_node_id) })?;
		let (update_opt, counterparty_node_id) = {
			let mut peer_state = peer_state_mutex.lock().unwrap();
			let closure_reason = if let Some(peer_msg) = peer_msg {
				ClosureReason::CounterpartyForceClosed { peer_msg: UntrustedString(peer_msg.to_string()) }
			} else {
				ClosureReason::HolderForceClosed
			};
			let logger = WithContext::from(&self.logger, Some(*peer_node_id), Some(*channel_id));
			if let hash_map::Entry::Occupied(chan_phase_entry) = peer_state.channel_by_id.entry(channel_id.clone()) {
				log_error!(logger, "Force-closing channel {}", channel_id);
				let mut chan_phase = remove_channel_phase!(self, chan_phase_entry);
				mem::drop(peer_state);
				mem::drop(per_peer_state);
				match chan_phase {
					ChannelPhase::Funded(mut chan) => {
						self.finish_close_channel(chan.context.force_shutdown(broadcast, closure_reason));
						(self.get_channel_update_for_broadcast(&chan).ok(), chan.context.get_counterparty_node_id())
					},
					ChannelPhase::UnfundedOutboundV1(_) | ChannelPhase::UnfundedInboundV1(_) => {
						self.finish_close_channel(chan_phase.context_mut().force_shutdown(false, closure_reason));
						// Unfunded channel has no update
						(None, chan_phase.context().get_counterparty_node_id())
					},
					// TODO(dual_funding): Combine this match arm with above once #[cfg(dual_funding)] is removed.
					#[cfg(dual_funding)]
					ChannelPhase::UnfundedOutboundV2(_) | ChannelPhase::UnfundedInboundV2(_) => {
						self.finish_close_channel(chan_phase.context_mut().force_shutdown(false, closure_reason));
						// Unfunded channel has no update
						(None, chan_phase.context().get_counterparty_node_id())
					},
				}
			} else if peer_state.inbound_channel_request_by_id.remove(channel_id).is_some() {
				log_error!(logger, "Force-closing channel {}", &channel_id);
				// N.B. that we don't send any channel close event here: we
				// don't have a user_channel_id, and we never sent any opening
				// events anyway.
				(None, *peer_node_id)
			} else {
				return Err(APIError::ChannelUnavailable{ err: format!("Channel with id {} not found for the passed counterparty node_id {}", channel_id, peer_node_id) });
			}
		};
		if let Some(update) = update_opt {
			// If we have some Channel Update to broadcast, we cache it and broadcast it later.
			let mut pending_broadcast_messages = self.pending_broadcast_messages.lock().unwrap();
			pending_broadcast_messages.push(events::MessageSendEvent::BroadcastChannelUpdate {
				msg: update
			});
		}

		Ok(counterparty_node_id)
	}

	fn force_close_sending_error(&self, channel_id: &ChannelId, counterparty_node_id: &PublicKey, broadcast: bool) -> Result<(), APIError> {
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(self);
		match self.force_close_channel_with_peer(channel_id, counterparty_node_id, None, broadcast) {
			Ok(counterparty_node_id) => {
				let per_peer_state = self.per_peer_state.read().unwrap();
				if let Some(peer_state_mutex) = per_peer_state.get(&counterparty_node_id) {
					let mut peer_state = peer_state_mutex.lock().unwrap();
					peer_state.pending_msg_events.push(
						events::MessageSendEvent::HandleError {
							node_id: counterparty_node_id,
							action: msgs::ErrorAction::DisconnectPeer {
								msg: Some(msgs::ErrorMessage { channel_id: *channel_id, data: "Channel force-closed".to_owned() })
							},
						}
					);
				}
				Ok(())
			},
			Err(e) => Err(e)
		}
	}

	/// Force closes a channel, immediately broadcasting the latest local transaction(s) and
	/// rejecting new HTLCs on the given channel. Fails if `channel_id` is unknown to
	/// the manager, or if the `counterparty_node_id` isn't the counterparty of the corresponding
	/// channel.
	pub fn force_close_broadcasting_latest_txn(&self, channel_id: &ChannelId, counterparty_node_id: &PublicKey)
	-> Result<(), APIError> {
		self.force_close_sending_error(channel_id, counterparty_node_id, true)
	}

	/// Force closes a channel, rejecting new HTLCs on the given channel but skips broadcasting
	/// the latest local transaction(s). Fails if `channel_id` is unknown to the manager, or if the
	/// `counterparty_node_id` isn't the counterparty of the corresponding channel.
	///
	/// You can always broadcast the latest local transaction(s) via
	/// [`ChannelMonitor::broadcast_latest_holder_commitment_txn`].
	pub fn force_close_without_broadcasting_txn(&self, channel_id: &ChannelId, counterparty_node_id: &PublicKey)
	-> Result<(), APIError> {
		self.force_close_sending_error(channel_id, counterparty_node_id, false)
	}

	/// Force close all channels, immediately broadcasting the latest local commitment transaction
	/// for each to the chain and rejecting new HTLCs on each.
	pub fn force_close_all_channels_broadcasting_latest_txn(&self) {
		for chan in self.list_channels() {
			let _ = self.force_close_broadcasting_latest_txn(&chan.channel_id, &chan.counterparty.node_id);
		}
	}

	/// Force close all channels rejecting new HTLCs on each but without broadcasting the latest
	/// local transaction(s).
	pub fn force_close_all_channels_without_broadcasting_txn(&self) {
		for chan in self.list_channels() {
			let _ = self.force_close_without_broadcasting_txn(&chan.channel_id, &chan.counterparty.node_id);
		}
	}

	fn can_forward_htlc_to_outgoing_channel(
		&self, chan: &mut Channel<SP>, msg: &msgs::UpdateAddHTLC, next_packet: &NextPacketDetails
	) -> Result<(), (&'static str, u16, Option<msgs::ChannelUpdate>)> {
		if !chan.context.should_announce() && !self.default_configuration.accept_forwards_to_priv_channels {
			// Note that the behavior here should be identical to the above block - we
			// should NOT reveal the existence or non-existence of a private channel if
			// we don't allow forwards outbound over them.
			return Err(("Refusing to forward to a private channel based on our config.", 0x4000 | 10, None));
		}
		if chan.context.get_channel_type().supports_scid_privacy() && next_packet.outgoing_scid != chan.context.outbound_scid_alias() {
			// `option_scid_alias` (referred to in LDK as `scid_privacy`) means
			// "refuse to forward unless the SCID alias was used", so we pretend
			// we don't have the channel here.
			return Err(("Refusing to forward over real channel SCID as our counterparty requested.", 0x4000 | 10, None));
		}

		// Note that we could technically not return an error yet here and just hope
		// that the connection is reestablished or monitor updated by the time we get
		// around to doing the actual forward, but better to fail early if we can and
		// hopefully an attacker trying to path-trace payments cannot make this occur
		// on a small/per-node/per-channel scale.
		if !chan.context.is_live() { // channel_disabled
			// If the channel_update we're going to return is disabled (i.e. the
			// peer has been disabled for some time), return `channel_disabled`,
			// otherwise return `temporary_channel_failure`.
			let chan_update_opt = self.get_channel_update_for_onion(next_packet.outgoing_scid, chan).ok();
			if chan_update_opt.as_ref().map(|u| u.contents.flags & 2 == 2).unwrap_or(false) {
				return Err(("Forwarding channel has been disconnected for some time.", 0x1000 | 20, chan_update_opt));
			} else {
				return Err(("Forwarding channel is not in a ready state.", 0x1000 | 7, chan_update_opt));
			}
		}
		if next_packet.outgoing_amt_msat < chan.context.get_counterparty_htlc_minimum_msat() { // amount_below_minimum
			let chan_update_opt = self.get_channel_update_for_onion(next_packet.outgoing_scid, chan).ok();
			return Err(("HTLC amount was below the htlc_minimum_msat", 0x1000 | 11, chan_update_opt));
		}
		if let Err((err, code)) = chan.htlc_satisfies_config(msg, next_packet.outgoing_amt_msat, next_packet.outgoing_cltv_value) {
			let chan_update_opt = self.get_channel_update_for_onion(next_packet.outgoing_scid, chan).ok();
			return Err((err, code, chan_update_opt));
		}

		Ok(())
	}

	/// Executes a callback `C` that returns some value `X` on the channel found with the given
	/// `scid`. `None` is returned when the channel is not found.
	fn do_funded_channel_callback<X, C: Fn(&mut Channel<SP>) -> X>(
		&self, scid: u64, callback: C,
	) -> Option<X> {
		let (counterparty_node_id, channel_id) = match self.short_to_chan_info.read().unwrap().get(&scid).cloned() {
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
		match peer_state.channel_by_id.get_mut(&channel_id).and_then(
			|chan_phase| if let ChannelPhase::Funded(chan) = chan_phase { Some(chan) } else { None }
		) {
			None => None,
			Some(chan) => Some(callback(chan)),
		}
	}

	fn can_forward_htlc(
		&self, msg: &msgs::UpdateAddHTLC, next_packet_details: &NextPacketDetails
	) -> Result<(), (&'static str, u16, Option<msgs::ChannelUpdate>)> {
		match self.do_funded_channel_callback(next_packet_details.outgoing_scid, |chan: &mut Channel<SP>| {
			self.can_forward_htlc_to_outgoing_channel(chan, msg, next_packet_details)
		}) {
			Some(Ok(())) => {},
			Some(Err(e)) => return Err(e),
			None => {
				// If we couldn't find the channel info for the scid, it may be a phantom or
				// intercept forward.
				if (self.default_configuration.accept_intercept_htlcs &&
					fake_scid::is_valid_intercept(&self.fake_scid_rand_bytes, next_packet_details.outgoing_scid, &self.chain_hash)) ||
					fake_scid::is_valid_phantom(&self.fake_scid_rand_bytes, next_packet_details.outgoing_scid, &self.chain_hash)
				{} else {
					return Err(("Don't have available channel for forwarding as requested.", 0x4000 | 10, None));
				}
			}
		}

		let cur_height = self.best_block.read().unwrap().height + 1;
		if let Err((err_msg, err_code)) = check_incoming_htlc_cltv(
			cur_height, next_packet_details.outgoing_cltv_value, msg.cltv_expiry
		) {
			let chan_update_opt = self.do_funded_channel_callback(next_packet_details.outgoing_scid, |chan: &mut Channel<SP>| {
				self.get_channel_update_for_onion(next_packet_details.outgoing_scid, chan).ok()
			}).flatten();
			return Err((err_msg, err_code, chan_update_opt));
		}

		Ok(())
	}

	fn htlc_failure_from_update_add_err(
		&self, msg: &msgs::UpdateAddHTLC, counterparty_node_id: &PublicKey, err_msg: &'static str,
		mut err_code: u16, chan_update: Option<msgs::ChannelUpdate>, is_intro_node_blinded_forward: bool,
		shared_secret: &[u8; 32]
	) -> HTLCFailureMsg {
		let mut res = VecWriter(Vec::with_capacity(chan_update.serialized_length() + 2 + 8 + 2));
		if chan_update.is_some() && err_code & 0x1000 == 0x1000 {
			let chan_update = chan_update.unwrap();
			if err_code == 0x1000 | 11 || err_code == 0x1000 | 12 {
				msg.amount_msat.write(&mut res).expect("Writes cannot fail");
			}
			else if err_code == 0x1000 | 13 {
				msg.cltv_expiry.write(&mut res).expect("Writes cannot fail");
			}
			else if err_code == 0x1000 | 20 {
				// TODO: underspecified, follow https://github.com/lightning/bolts/issues/791
				0u16.write(&mut res).expect("Writes cannot fail");
			}
			(chan_update.serialized_length() as u16 + 2).write(&mut res).expect("Writes cannot fail");
			msgs::ChannelUpdate::TYPE.write(&mut res).expect("Writes cannot fail");
			chan_update.write(&mut res).expect("Writes cannot fail");
		} else if err_code & 0x1000 == 0x1000 {
			// If we're trying to return an error that requires a `channel_update` but
			// we're forwarding to a phantom or intercept "channel" (i.e. cannot
			// generate an update), just use the generic "temporary_node_failure"
			// instead.
			err_code = 0x2000 | 2;
		}

		log_info!(
			WithContext::from(&self.logger, Some(*counterparty_node_id), Some(msg.channel_id)),
			"Failed to accept/forward incoming HTLC: {}", err_msg
		);
		// If `msg.blinding_point` is set, we must always fail with malformed.
		if msg.blinding_point.is_some() {
			return HTLCFailureMsg::Malformed(msgs::UpdateFailMalformedHTLC {
				channel_id: msg.channel_id,
				htlc_id: msg.htlc_id,
				sha256_of_onion: [0; 32],
				failure_code: INVALID_ONION_BLINDING,
			});
		}

		let (err_code, err_data) = if is_intro_node_blinded_forward {
			(INVALID_ONION_BLINDING, &[0; 32][..])
		} else {
			(err_code, &res.0[..])
		};
		HTLCFailureMsg::Relay(msgs::UpdateFailHTLC {
			channel_id: msg.channel_id,
			htlc_id: msg.htlc_id,
			reason: HTLCFailReason::reason(err_code, err_data.to_vec())
				.get_encrypted_failure_packet(shared_secret, &None),
		})
	}

	fn decode_update_add_htlc_onion(
		&self, msg: &msgs::UpdateAddHTLC, counterparty_node_id: &PublicKey,
	) -> Result<
		(onion_utils::Hop, [u8; 32], Option<Result<PublicKey, secp256k1::Error>>), HTLCFailureMsg
	> {
		let (next_hop, shared_secret, next_packet_details_opt) = decode_incoming_update_add_htlc_onion(
			msg, &self.node_signer, &self.logger, &self.secp_ctx
		)?;

		let next_packet_details = match next_packet_details_opt {
			Some(next_packet_details) => next_packet_details,
			// it is a receive, so no need for outbound checks
			None => return Ok((next_hop, shared_secret, None)),
		};

		// Perform outbound checks here instead of in [`Self::construct_pending_htlc_info`] because we
		// can't hold the outbound peer state lock at the same time as the inbound peer state lock.
		self.can_forward_htlc(&msg, &next_packet_details).map_err(|e| {
			let (err_msg, err_code, chan_update_opt) = e;
			self.htlc_failure_from_update_add_err(
				msg, counterparty_node_id, err_msg, err_code, chan_update_opt,
				next_hop.is_intro_node_blinded_forward(), &shared_secret
			)
		})?;

		Ok((next_hop, shared_secret, Some(next_packet_details.next_packet_pubkey)))
	}

	fn construct_pending_htlc_status<'a>(
		&self, msg: &msgs::UpdateAddHTLC, counterparty_node_id: &PublicKey, shared_secret: [u8; 32],
		decoded_hop: onion_utils::Hop, allow_underpay: bool,
		next_packet_pubkey_opt: Option<Result<PublicKey, secp256k1::Error>>,
	) -> PendingHTLCStatus {
		macro_rules! return_err {
			($msg: expr, $err_code: expr, $data: expr) => {
				{
					let logger = WithContext::from(&self.logger, Some(*counterparty_node_id), Some(msg.channel_id));
					log_info!(logger, "Failed to accept/forward incoming HTLC: {}", $msg);
					if msg.blinding_point.is_some() {
						return PendingHTLCStatus::Fail(HTLCFailureMsg::Malformed(
							msgs::UpdateFailMalformedHTLC {
								channel_id: msg.channel_id,
								htlc_id: msg.htlc_id,
								sha256_of_onion: [0; 32],
								failure_code: INVALID_ONION_BLINDING,
							}
						))
					}
					return PendingHTLCStatus::Fail(HTLCFailureMsg::Relay(msgs::UpdateFailHTLC {
						channel_id: msg.channel_id,
						htlc_id: msg.htlc_id,
						reason: HTLCFailReason::reason($err_code, $data.to_vec())
							.get_encrypted_failure_packet(&shared_secret, &None),
					}));
				}
			}
		}
		match decoded_hop {
			onion_utils::Hop::Receive(next_hop_data) => {
				// OUR PAYMENT!
				let current_height: u32 = self.best_block.read().unwrap().height;
				match create_recv_pending_htlc_info(next_hop_data, shared_secret, msg.payment_hash,
					msg.amount_msat, msg.cltv_expiry, None, allow_underpay, msg.skimmed_fee_msat,
					current_height, self.default_configuration.accept_mpp_keysend)
				{
					Ok(info) => {
						// Note that we could obviously respond immediately with an update_fulfill_htlc
						// message, however that would leak that we are the recipient of this payment, so
						// instead we stay symmetric with the forwarding case, only responding (after a
						// delay) once they've send us a commitment_signed!
						PendingHTLCStatus::Forward(info)
					},
					Err(InboundHTLCErr { err_code, err_data, msg }) => return_err!(msg, err_code, &err_data)
				}
			},
			onion_utils::Hop::Forward { next_hop_data, next_hop_hmac, new_packet_bytes } => {
				match create_fwd_pending_htlc_info(msg, next_hop_data, next_hop_hmac,
					new_packet_bytes, shared_secret, next_packet_pubkey_opt) {
					Ok(info) => PendingHTLCStatus::Forward(info),
					Err(InboundHTLCErr { err_code, err_data, msg }) => return_err!(msg, err_code, &err_data)
				}
			}
		}
	}

	/// Gets the current [`channel_update`] for the given channel. This first checks if the channel is
	/// public, and thus should be called whenever the result is going to be passed out in a
	/// [`MessageSendEvent::BroadcastChannelUpdate`] event.
	///
	/// Note that in [`internal_closing_signed`], this function is called without the `peer_state`
	/// corresponding to the channel's counterparty locked, as the channel been removed from the
	/// storage and the `peer_state` lock has been dropped.
	///
	/// [`channel_update`]: msgs::ChannelUpdate
	/// [`internal_closing_signed`]: Self::internal_closing_signed
	fn get_channel_update_for_broadcast(&self, chan: &Channel<SP>) -> Result<msgs::ChannelUpdate, LightningError> {
		if !chan.context.should_announce() {
			return Err(LightningError {
				err: "Cannot broadcast a channel_update for a private channel".to_owned(),
				action: msgs::ErrorAction::IgnoreError
			});
		}
		if chan.context.get_short_channel_id().is_none() {
			return Err(LightningError{err: "Channel not yet established".to_owned(), action: msgs::ErrorAction::IgnoreError});
		}
		let logger = WithChannelContext::from(&self.logger, &chan.context);
		log_trace!(logger, "Attempting to generate broadcast channel update for channel {}", &chan.context.channel_id());
		self.get_channel_update_for_unicast(chan)
	}

	/// Gets the current [`channel_update`] for the given channel. This does not check if the channel
	/// is public (only returning an `Err` if the channel does not yet have an assigned SCID),
	/// and thus MUST NOT be called unless the recipient of the resulting message has already
	/// provided evidence that they know about the existence of the channel.
	///
	/// Note that through [`internal_closing_signed`], this function is called without the
	/// `peer_state`  corresponding to the channel's counterparty locked, as the channel been
	/// removed from the storage and the `peer_state` lock has been dropped.
	///
	/// [`channel_update`]: msgs::ChannelUpdate
	/// [`internal_closing_signed`]: Self::internal_closing_signed
	fn get_channel_update_for_unicast(&self, chan: &Channel<SP>) -> Result<msgs::ChannelUpdate, LightningError> {
		let logger = WithChannelContext::from(&self.logger, &chan.context);
		log_trace!(logger, "Attempting to generate channel update for channel {}", chan.context.channel_id());
		let short_channel_id = match chan.context.get_short_channel_id().or(chan.context.latest_inbound_scid_alias()) {
			None => return Err(LightningError{err: "Channel not yet established".to_owned(), action: msgs::ErrorAction::IgnoreError}),
			Some(id) => id,
		};

		self.get_channel_update_for_onion(short_channel_id, chan)
	}

	fn get_channel_update_for_onion(&self, short_channel_id: u64, chan: &Channel<SP>) -> Result<msgs::ChannelUpdate, LightningError> {
		let logger = WithChannelContext::from(&self.logger, &chan.context);
		log_trace!(logger, "Generating channel update for channel {}", chan.context.channel_id());
		let were_node_one = self.our_network_pubkey.serialize()[..] < chan.context.get_counterparty_node_id().serialize()[..];

		let enabled = chan.context.is_usable() && match chan.channel_update_status() {
			ChannelUpdateStatus::Enabled => true,
			ChannelUpdateStatus::DisabledStaged(_) => true,
			ChannelUpdateStatus::Disabled => false,
			ChannelUpdateStatus::EnabledStaged(_) => false,
		};

		let unsigned = msgs::UnsignedChannelUpdate {
			chain_hash: self.chain_hash,
			short_channel_id,
			timestamp: chan.context.get_update_time_counter(),
			flags: (!were_node_one) as u8 | ((!enabled as u8) << 1),
			cltv_expiry_delta: chan.context.get_cltv_expiry_delta(),
			htlc_minimum_msat: chan.context.get_counterparty_htlc_minimum_msat(),
			htlc_maximum_msat: chan.context.get_announced_htlc_max_msat(),
			fee_base_msat: chan.context.get_outbound_forwarding_fee_base_msat(),
			fee_proportional_millionths: chan.context.get_fee_proportional_millionths(),
			excess_data: Vec::new(),
		};
		// Panic on failure to signal LDK should be restarted to retry signing the `ChannelUpdate`.
		// If we returned an error and the `node_signer` cannot provide a signature for whatever
		// reason`, we wouldn't be able to receive inbound payments through the corresponding
		// channel.
		let sig = self.node_signer.sign_gossip_message(msgs::UnsignedGossipMessage::ChannelUpdate(&unsigned)).unwrap();

		Ok(msgs::ChannelUpdate {
			signature: sig,
			contents: unsigned
		})
	}

	#[cfg(test)]
	pub(crate) fn test_send_payment_along_path(&self, path: &Path, payment_hash: &PaymentHash, recipient_onion: RecipientOnionFields, total_value: u64, cur_height: u32, payment_id: PaymentId, keysend_preimage: &Option<PaymentPreimage>, session_priv_bytes: [u8; 32]) -> Result<(), APIError> {
		let _lck = self.total_consistency_lock.read().unwrap();
		self.send_payment_along_path(SendAlongPathArgs {
			path, payment_hash, recipient_onion, total_value, cur_height, payment_id, keysend_preimage,
			session_priv_bytes
		})
	}

	fn send_payment_along_path(&self, args: SendAlongPathArgs) -> Result<(), APIError> {
		let SendAlongPathArgs {
			path, payment_hash, recipient_onion, total_value, cur_height, payment_id, keysend_preimage,
			session_priv_bytes
		} = args;
		// The top-level caller should hold the total_consistency_lock read lock.
		debug_assert!(self.total_consistency_lock.try_write().is_err());
		let prng_seed = self.entropy_source.get_secure_random_bytes();
		let session_priv = SecretKey::from_slice(&session_priv_bytes[..]).expect("RNG is busted");

		let (onion_packet, htlc_msat, htlc_cltv) = onion_utils::create_payment_onion(
			&self.secp_ctx, &path, &session_priv, total_value, recipient_onion, cur_height,
			payment_hash, keysend_preimage, prng_seed
		).map_err(|e| {
			let logger = WithContext::from(&self.logger, Some(path.hops.first().unwrap().pubkey), None);
			log_error!(logger, "Failed to build an onion for path for payment hash {}", payment_hash);
			e
		})?;

		let err: Result<(), _> = loop {
			let (counterparty_node_id, id) = match self.short_to_chan_info.read().unwrap().get(&path.hops.first().unwrap().short_channel_id) {
				None => {
					let logger = WithContext::from(&self.logger, Some(path.hops.first().unwrap().pubkey), None);
					log_error!(logger, "Failed to find first-hop for payment hash {}", payment_hash);
					return Err(APIError::ChannelUnavailable{err: "No channel available with first hop!".to_owned()})
				},
				Some((cp_id, chan_id)) => (cp_id.clone(), chan_id.clone()),
			};

			let logger = WithContext::from(&self.logger, Some(counterparty_node_id), Some(id));
			log_trace!(logger,
				"Attempting to send payment with payment hash {} along path with next hop {}",
				payment_hash, path.hops.first().unwrap().short_channel_id);

			let per_peer_state = self.per_peer_state.read().unwrap();
			let peer_state_mutex = per_peer_state.get(&counterparty_node_id)
				.ok_or_else(|| APIError::ChannelUnavailable{err: "No peer matching the path's first hop found!".to_owned() })?;
			let mut peer_state_lock = peer_state_mutex.lock().unwrap();
			let peer_state = &mut *peer_state_lock;
			if let hash_map::Entry::Occupied(mut chan_phase_entry) = peer_state.channel_by_id.entry(id) {
				match chan_phase_entry.get_mut() {
					ChannelPhase::Funded(chan) => {
						if !chan.context.is_live() {
							return Err(APIError::ChannelUnavailable{err: "Peer for first hop currently disconnected".to_owned()});
						}
						let funding_txo = chan.context.get_funding_txo().unwrap();
						let logger = WithChannelContext::from(&self.logger, &chan.context);
						let send_res = chan.send_htlc_and_commit(htlc_msat, payment_hash.clone(),
							htlc_cltv, HTLCSource::OutboundRoute {
								path: path.clone(),
								session_priv: session_priv.clone(),
								first_hop_htlc_msat: htlc_msat,
								payment_id,
							}, onion_packet, None, &self.fee_estimator, &&logger);
						match break_chan_phase_entry!(self, send_res, chan_phase_entry) {
							Some(monitor_update) => {
								match handle_new_monitor_update!(self, funding_txo, monitor_update, peer_state_lock, peer_state, per_peer_state, chan) {
									false => {
										// Note that MonitorUpdateInProgress here indicates (per function
										// docs) that we will resend the commitment update once monitor
										// updating completes. Therefore, we must return an error
										// indicating that it is unsafe to retry the payment wholesale,
										// which we do in the send_payment check for
										// MonitorUpdateInProgress, below.
										return Err(APIError::MonitorUpdateInProgress);
									},
									true => {},
								}
							},
							None => {},
						}
					},
					_ => return Err(APIError::ChannelUnavailable{err: "Channel to first hop is unfunded".to_owned()}),
				};
			} else {
				// The channel was likely removed after we fetched the id from the
				// `short_to_chan_info` map, but before we successfully locked the
				// `channel_by_id` map.
				// This can occur as no consistency guarantees exists between the two maps.
				return Err(APIError::ChannelUnavailable{err: "No channel available with first hop!".to_owned()});
			}
			return Ok(());
		};
		match handle_error!(self, err, path.hops.first().unwrap().pubkey) {
			Ok(_) => unreachable!(),
			Err(e) => {
				Err(APIError::ChannelUnavailable { err: e.err })
			},
		}
	}

	/// Sends a payment along a given route.
	///
	/// Value parameters are provided via the last hop in route, see documentation for [`RouteHop`]
	/// fields for more info.
	///
	/// May generate [`UpdateHTLCs`] message(s) event on success, which should be relayed (e.g. via
	/// [`PeerManager::process_events`]).
	///
	/// # Avoiding Duplicate Payments
	///
	/// If a pending payment is currently in-flight with the same [`PaymentId`] provided, this
	/// method will error with an [`APIError::InvalidRoute`]. Note, however, that once a payment
	/// is no longer pending (either via [`ChannelManager::abandon_payment`], or handling of an
	/// [`Event::PaymentSent`] or [`Event::PaymentFailed`]) LDK will not stop you from sending a
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
	/// # Possible Error States on [`PaymentSendFailure`]
	///
	/// Each path may have a different return value, and [`PaymentSendFailure`] may return a `Vec` with
	/// each entry matching the corresponding-index entry in the route paths, see
	/// [`PaymentSendFailure`] for more info.
	///
	/// In general, a path may raise:
	///  * [`APIError::InvalidRoute`] when an invalid route or forwarding parameter (cltv_delta, fee,
	///    node public key) is specified.
	///  * [`APIError::ChannelUnavailable`] if the next-hop channel is not available as it has been
	///    closed, doesn't exist, or the peer is currently disconnected.
	///  * [`APIError::MonitorUpdateInProgress`] if a new monitor update failure prevented sending the
	///    relevant updates.
	///
	/// Note that depending on the type of the [`PaymentSendFailure`] the HTLC may have been
	/// irrevocably committed to on our end. In such a case, do NOT retry the payment with a
	/// different route unless you intend to pay twice!
	///
	/// [`RouteHop`]: crate::routing::router::RouteHop
	/// [`Event::PaymentSent`]: events::Event::PaymentSent
	/// [`Event::PaymentFailed`]: events::Event::PaymentFailed
	/// [`UpdateHTLCs`]: events::MessageSendEvent::UpdateHTLCs
	/// [`PeerManager::process_events`]: crate::ln::peer_handler::PeerManager::process_events
	/// [`ChannelMonitorUpdateStatus::InProgress`]: crate::chain::ChannelMonitorUpdateStatus::InProgress
	pub fn send_payment_with_route(&self, route: &Route, payment_hash: PaymentHash, recipient_onion: RecipientOnionFields, payment_id: PaymentId) -> Result<(), PaymentSendFailure> {
		let best_block_height = self.best_block.read().unwrap().height;
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(self);
		self.pending_outbound_payments
			.send_payment_with_route(route, payment_hash, recipient_onion, payment_id,
				&self.entropy_source, &self.node_signer, best_block_height,
				|args| self.send_payment_along_path(args))
	}

	/// Similar to [`ChannelManager::send_payment_with_route`], but will automatically find a route based on
	/// `route_params` and retry failed payment paths based on `retry_strategy`.
	pub fn send_payment(&self, payment_hash: PaymentHash, recipient_onion: RecipientOnionFields, payment_id: PaymentId, route_params: RouteParameters, retry_strategy: Retry) -> Result<(), RetryableSendFailure> {
		let best_block_height = self.best_block.read().unwrap().height;
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(self);
		self.pending_outbound_payments
			.send_payment(payment_hash, recipient_onion, payment_id, retry_strategy, route_params,
				&self.router, self.list_usable_channels(), || self.compute_inflight_htlcs(),
				&self.entropy_source, &self.node_signer, best_block_height, &self.logger,
				&self.pending_events, |args| self.send_payment_along_path(args))
	}

	#[cfg(test)]
	pub(super) fn test_send_payment_internal(&self, route: &Route, payment_hash: PaymentHash, recipient_onion: RecipientOnionFields, keysend_preimage: Option<PaymentPreimage>, payment_id: PaymentId, recv_value_msat: Option<u64>, onion_session_privs: Vec<[u8; 32]>) -> Result<(), PaymentSendFailure> {
		let best_block_height = self.best_block.read().unwrap().height;
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(self);
		self.pending_outbound_payments.test_send_payment_internal(route, payment_hash, recipient_onion,
			keysend_preimage, payment_id, recv_value_msat, onion_session_privs, &self.node_signer,
			best_block_height, |args| self.send_payment_along_path(args))
	}

	#[cfg(test)]
	pub(crate) fn test_add_new_pending_payment(&self, payment_hash: PaymentHash, recipient_onion: RecipientOnionFields, payment_id: PaymentId, route: &Route) -> Result<Vec<[u8; 32]>, PaymentSendFailure> {
		let best_block_height = self.best_block.read().unwrap().height;
		self.pending_outbound_payments.test_add_new_pending_payment(payment_hash, recipient_onion, payment_id, route, None, &self.entropy_source, best_block_height)
	}

	#[cfg(test)]
	pub(crate) fn test_set_payment_metadata(&self, payment_id: PaymentId, new_payment_metadata: Option<Vec<u8>>) {
		self.pending_outbound_payments.test_set_payment_metadata(payment_id, new_payment_metadata);
	}

	pub(super) fn send_payment_for_bolt12_invoice(&self, invoice: &Bolt12Invoice, payment_id: PaymentId) -> Result<(), Bolt12PaymentError> {
		let best_block_height = self.best_block.read().unwrap().height;
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(self);
		self.pending_outbound_payments
			.send_payment_for_bolt12_invoice(
				invoice, payment_id, &self.router, self.list_usable_channels(),
				|| self.compute_inflight_htlcs(), &self.entropy_source, &self.node_signer,
				best_block_height, &self.logger, &self.pending_events,
				|args| self.send_payment_along_path(args)
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
	/// the payment prior to receiving the invoice will result in an [`Event::InvoiceRequestFailed`]
	/// and prevent any attempts at paying it once received. The other events may only be generated
	/// once the invoice has been received.
	///
	/// # Restart Behavior
	///
	/// If an [`Event::PaymentFailed`] is generated and we restart without first persisting the
	/// [`ChannelManager`], another [`Event::PaymentFailed`] may be generated; likewise for
	/// [`Event::InvoiceRequestFailed`].
	///
	/// [`Bolt12Invoice`]: crate::offers::invoice::Bolt12Invoice
	pub fn abandon_payment(&self, payment_id: PaymentId) {
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(self);
		self.pending_outbound_payments.abandon_payment(payment_id, PaymentFailureReason::UserAbandoned, &self.pending_events);
	}

	/// Send a spontaneous payment, which is a payment that does not require the recipient to have
	/// generated an invoice. Optionally, you may specify the preimage. If you do choose to specify
	/// the preimage, it must be a cryptographically secure random value that no intermediate node
	/// would be able to guess -- otherwise, an intermediate node may claim the payment and it will
	/// never reach the recipient.
	///
	/// See [`send_payment`] documentation for more details on the return value of this function
	/// and idempotency guarantees provided by the [`PaymentId`] key.
	///
	/// Similar to regular payments, you MUST NOT reuse a `payment_preimage` value. See
	/// [`send_payment`] for more information about the risks of duplicate preimage usage.
	///
	/// [`send_payment`]: Self::send_payment
	pub fn send_spontaneous_payment(&self, route: &Route, payment_preimage: Option<PaymentPreimage>, recipient_onion: RecipientOnionFields, payment_id: PaymentId) -> Result<PaymentHash, PaymentSendFailure> {
		let best_block_height = self.best_block.read().unwrap().height;
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(self);
		self.pending_outbound_payments.send_spontaneous_payment_with_route(
			route, payment_preimage, recipient_onion, payment_id, &self.entropy_source,
			&self.node_signer, best_block_height, |args| self.send_payment_along_path(args))
	}

	/// Similar to [`ChannelManager::send_spontaneous_payment`], but will automatically find a route
	/// based on `route_params` and retry failed payment paths based on `retry_strategy`.
	///
	/// See [`PaymentParameters::for_keysend`] for help in constructing `route_params` for spontaneous
	/// payments.
	///
	/// [`PaymentParameters::for_keysend`]: crate::routing::router::PaymentParameters::for_keysend
	pub fn send_spontaneous_payment_with_retry(&self, payment_preimage: Option<PaymentPreimage>, recipient_onion: RecipientOnionFields, payment_id: PaymentId, route_params: RouteParameters, retry_strategy: Retry) -> Result<PaymentHash, RetryableSendFailure> {
		let best_block_height = self.best_block.read().unwrap().height;
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(self);
		self.pending_outbound_payments.send_spontaneous_payment(payment_preimage, recipient_onion,
			payment_id, retry_strategy, route_params, &self.router, self.list_usable_channels(),
			|| self.compute_inflight_htlcs(),  &self.entropy_source, &self.node_signer, best_block_height,
			&self.logger, &self.pending_events, |args| self.send_payment_along_path(args))
	}

	/// Send a payment that is probing the given route for liquidity. We calculate the
	/// [`PaymentHash`] of probes based on a static secret and a random [`PaymentId`], which allows
	/// us to easily discern them from real payments.
	pub fn send_probe(&self, path: Path) -> Result<(PaymentHash, PaymentId), PaymentSendFailure> {
		let best_block_height = self.best_block.read().unwrap().height;
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(self);
		self.pending_outbound_payments.send_probe(path, self.probing_cookie_secret,
			&self.entropy_source, &self.node_signer, best_block_height,
			|args| self.send_payment_along_path(args))
	}

	/// Returns whether a payment with the given [`PaymentHash`] and [`PaymentId`] is, in fact, a
	/// payment probe.
	#[cfg(test)]
	pub(crate) fn payment_is_probe(&self, payment_hash: &PaymentHash, payment_id: &PaymentId) -> bool {
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
		let payment_params =
			PaymentParameters::from_node_id(node_id, final_cltv_expiry_delta);

		let route_params = RouteParameters::from_payment_params_and_value(payment_params, amount_msat);

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
				ProbeSendFailure::SendingFailed(e)
			})?);
		}

		Ok(res)
	}

	/// Handles the generation of a funding transaction, optionally (for tests) with a function
	/// which checks the correctness of the funding transaction given the associated channel.
	fn funding_transaction_generated_intern<FundingOutput: FnMut(&OutboundV1Channel<SP>, &Transaction) -> Result<OutPoint, APIError>>(
		&self, temporary_channel_id: &ChannelId, counterparty_node_id: &PublicKey, funding_transaction: Transaction, is_batch_funding: bool,
		mut find_funding_output: FundingOutput,
	) -> Result<(), APIError> {
		let per_peer_state = self.per_peer_state.read().unwrap();
		let peer_state_mutex = per_peer_state.get(counterparty_node_id)
			.ok_or_else(|| APIError::ChannelUnavailable { err: format!("Can't find a peer matching the passed counterparty node_id {}", counterparty_node_id) })?;

		let mut peer_state_lock = peer_state_mutex.lock().unwrap();
		let peer_state = &mut *peer_state_lock;
		let funding_txo;
		let (mut chan, msg_opt) = match peer_state.channel_by_id.remove(temporary_channel_id) {
			Some(ChannelPhase::UnfundedOutboundV1(mut chan)) => {
				funding_txo = find_funding_output(&chan, &funding_transaction)?;

				let logger = WithChannelContext::from(&self.logger, &chan.context);
				let funding_res = chan.get_funding_created(funding_transaction, funding_txo, is_batch_funding, &&logger)
					.map_err(|(mut chan, e)| if let ChannelError::Close(msg) = e {
						let channel_id = chan.context.channel_id();
						let reason = ClosureReason::ProcessingError { err: msg.clone() };
						let shutdown_res = chan.context.force_shutdown(false, reason);
						(chan, MsgHandleErrInternal::from_finish_shutdown(msg, channel_id, shutdown_res, None))
					} else { unreachable!(); });
				match funding_res {
					Ok(funding_msg) => (chan, funding_msg),
					Err((chan, err)) => {
						mem::drop(peer_state_lock);
						mem::drop(per_peer_state);
						let _: Result<(), _> = handle_error!(self, Err(err), chan.context.get_counterparty_node_id());
						return Err(APIError::ChannelUnavailable {
							err: "Signer refused to sign the initial commitment transaction".to_owned()
						});
					},
				}
			},
			Some(phase) => {
				peer_state.channel_by_id.insert(*temporary_channel_id, phase);
				return Err(APIError::APIMisuseError {
					err: format!(
						"Channel with id {} for the passed counterparty node_id {} is not an unfunded, outbound V1 channel",
						temporary_channel_id, counterparty_node_id),
				})
			},
			None => return Err(APIError::ChannelUnavailable {err: format!(
				"Channel with id {} not found for the passed counterparty node_id {}",
				temporary_channel_id, counterparty_node_id),
				}),
		};

		if let Some(msg) = msg_opt {
			peer_state.pending_msg_events.push(events::MessageSendEvent::SendFundingCreated {
				node_id: chan.context.get_counterparty_node_id(),
				msg,
			});
		}
		match peer_state.channel_by_id.entry(chan.context.channel_id()) {
			hash_map::Entry::Occupied(_) => {
				panic!("Generated duplicate funding txid?");
			},
			hash_map::Entry::Vacant(e) => {
				let mut outpoint_to_peer = self.outpoint_to_peer.lock().unwrap();
				match outpoint_to_peer.entry(funding_txo) {
					hash_map::Entry::Vacant(e) => { e.insert(chan.context.get_counterparty_node_id()); },
					hash_map::Entry::Occupied(o) => {
						let err = format!(
							"An existing channel using outpoint {} is open with peer {}",
							funding_txo, o.get()
						);
						mem::drop(outpoint_to_peer);
						mem::drop(peer_state_lock);
						mem::drop(per_peer_state);
						let reason = ClosureReason::ProcessingError { err: err.clone() };
						self.finish_close_channel(chan.context.force_shutdown(true, reason));
						return Err(APIError::ChannelUnavailable { err });
					}
				}
				e.insert(ChannelPhase::UnfundedOutboundV1(chan));
			}
		}
		Ok(())
	}

	#[cfg(test)]
	pub(crate) fn funding_transaction_generated_unchecked(&self, temporary_channel_id: &ChannelId, counterparty_node_id: &PublicKey, funding_transaction: Transaction, output_index: u16) -> Result<(), APIError> {
		self.funding_transaction_generated_intern(temporary_channel_id, counterparty_node_id, funding_transaction, false, |_, tx| {
			Ok(OutPoint { txid: tx.txid(), index: output_index })
		})
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
	pub fn funding_transaction_generated(&self, temporary_channel_id: &ChannelId, counterparty_node_id: &PublicKey, funding_transaction: Transaction) -> Result<(), APIError> {
		self.batch_funding_transaction_generated(&[(temporary_channel_id, counterparty_node_id)], funding_transaction)
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
	pub fn batch_funding_transaction_generated(&self, temporary_channels: &[(&ChannelId, &PublicKey)], funding_transaction: Transaction) -> Result<(), APIError> {
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(self);
		let mut result = Ok(());

		if !funding_transaction.is_coin_base() {
			for inp in funding_transaction.input.iter() {
				if inp.witness.is_empty() {
					result = result.and(Err(APIError::APIMisuseError {
						err: "Funding transaction must be fully signed and spend Segwit outputs".to_owned()
					}));
				}
			}
		}
		if funding_transaction.output.len() > u16::max_value() as usize {
			result = result.and(Err(APIError::APIMisuseError {
				err: "Transaction had more than 2^16 outputs, which is not supported".to_owned()
			}));
		}
		{
			let height = self.best_block.read().unwrap().height;
			// Transactions are evaluated as final by network mempools if their locktime is strictly
			// lower than the next block height. However, the modules constituting our Lightning
			// node might not have perfect sync about their blockchain views. Thus, if the wallet
			// module is ahead of LDK, only allow one more block of headroom.
			if !funding_transaction.input.iter().all(|input| input.sequence == Sequence::MAX) &&
				funding_transaction.lock_time.is_block_height() &&
				funding_transaction.lock_time.to_consensus_u32() > height + 1
			{
				result = result.and(Err(APIError::APIMisuseError {
					err: "Funding transaction absolute timelock is non-final".to_owned()
				}));
			}
		}

		let txid = funding_transaction.txid();
		let is_batch_funding = temporary_channels.len() > 1;
		let mut funding_batch_states = if is_batch_funding {
			Some(self.funding_batch_states.lock().unwrap())
		} else {
			None
		};
		let mut funding_batch_state = funding_batch_states.as_mut().and_then(|states| {
			match states.entry(txid) {
				btree_map::Entry::Occupied(_) => {
					result = result.clone().and(Err(APIError::APIMisuseError {
						err: "Batch funding transaction with the same txid already exists".to_owned()
					}));
					None
				},
				btree_map::Entry::Vacant(vacant) => Some(vacant.insert(Vec::new())),
			}
		});
		for &(temporary_channel_id, counterparty_node_id) in temporary_channels {
			result = result.and_then(|_| self.funding_transaction_generated_intern(
				temporary_channel_id,
				counterparty_node_id,
				funding_transaction.clone(),
				is_batch_funding,
				|chan, tx| {
					let mut output_index = None;
					let expected_spk = chan.context.get_funding_redeemscript().to_v0_p2wsh();
					for (idx, outp) in tx.output.iter().enumerate() {
						if outp.script_pubkey == expected_spk && outp.value == chan.context.get_value_satoshis() {
							if output_index.is_some() {
								return Err(APIError::APIMisuseError {
									err: "Multiple outputs matched the expected script and value".to_owned()
								});
							}
							output_index = Some(idx as u16);
						}
					}
					if output_index.is_none() {
						return Err(APIError::APIMisuseError {
							err: "No output matched the script_pubkey and value in the FundingGenerationReady event".to_owned()
						});
					}
					let outpoint = OutPoint { txid: tx.txid(), index: output_index.unwrap() };
					if let Some(funding_batch_state) = funding_batch_state.as_mut() {
						// TODO(dual_funding): We only do batch funding for V1 channels at the moment, but we'll probably
						// need to fix this somehow to not rely on using the outpoint for the channel ID if we
						// want to support V2 batching here as well.
						funding_batch_state.push((ChannelId::v1_from_funding_outpoint(outpoint), *counterparty_node_id, false));
					}
					Ok(outpoint)
				})
			);
		}
		if let Err(ref e) = result {
			// Remaining channels need to be removed on any error.
			let e = format!("Error in transaction funding: {:?}", e);
			let mut channels_to_remove = Vec::new();
			channels_to_remove.extend(funding_batch_states.as_mut()
				.and_then(|states| states.remove(&txid))
				.into_iter().flatten()
				.map(|(chan_id, node_id, _state)| (chan_id, node_id))
			);
			channels_to_remove.extend(temporary_channels.iter()
				.map(|(&chan_id, &node_id)| (chan_id, node_id))
			);
			let mut shutdown_results = Vec::new();
			{
				let per_peer_state = self.per_peer_state.read().unwrap();
				for (channel_id, counterparty_node_id) in channels_to_remove {
					per_peer_state.get(&counterparty_node_id)
						.map(|peer_state_mutex| peer_state_mutex.lock().unwrap())
						.and_then(|mut peer_state| peer_state.channel_by_id.remove(&channel_id))
						.map(|mut chan| {
							update_maps_on_chan_removal!(self, &chan.context());
							let closure_reason = ClosureReason::ProcessingError { err: e.clone() };
							shutdown_results.push(chan.context_mut().force_shutdown(false, closure_reason));
						});
				}
			}
			mem::drop(funding_batch_states);
			for shutdown_result in shutdown_results.drain(..) {
				self.finish_close_channel(shutdown_result);
			}
		}
		result
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
	/// [`BroadcastChannelUpdate`]: events::MessageSendEvent::BroadcastChannelUpdate
	/// [`ChannelUpdate`]: msgs::ChannelUpdate
	/// [`ChannelUnavailable`]: APIError::ChannelUnavailable
	/// [`APIMisuseError`]: APIError::APIMisuseError
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
			.ok_or_else(|| APIError::ChannelUnavailable { err: format!("Can't find a peer matching the passed counterparty node_id {}", counterparty_node_id) })?;
		let mut peer_state_lock = peer_state_mutex.lock().unwrap();
		let peer_state = &mut *peer_state_lock;

		for channel_id in channel_ids {
			if !peer_state.has_channel(channel_id) {
				return Err(APIError::ChannelUnavailable {
					err: format!("Channel with id {} not found for the passed counterparty node_id {}", channel_id, counterparty_node_id),
				});
			};
		}
		for channel_id in channel_ids {
			if let Some(channel_phase) = peer_state.channel_by_id.get_mut(channel_id) {
				let mut config = channel_phase.context().config();
				config.apply(config_update);
				if !channel_phase.context_mut().update_config(&config) {
					continue;
				}
				if let ChannelPhase::Funded(channel) = channel_phase {
					if let Ok(msg) = self.get_channel_update_for_broadcast(channel) {
						let mut pending_broadcast_messages = self.pending_broadcast_messages.lock().unwrap();
						pending_broadcast_messages.push(events::MessageSendEvent::BroadcastChannelUpdate { msg });
					} else if let Ok(msg) = self.get_channel_update_for_unicast(channel) {
						peer_state.pending_msg_events.push(events::MessageSendEvent::SendChannelUpdate {
							node_id: channel.context.get_counterparty_node_id(),
							msg,
						});
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
	/// [`BroadcastChannelUpdate`]: events::MessageSendEvent::BroadcastChannelUpdate
	/// [`ChannelUpdate`]: msgs::ChannelUpdate
	/// [`ChannelUnavailable`]: APIError::ChannelUnavailable
	/// [`APIMisuseError`]: APIError::APIMisuseError
	pub fn update_channel_config(
		&self, counterparty_node_id: &PublicKey, channel_ids: &[ChannelId], config: &ChannelConfig,
	) -> Result<(), APIError> {
		return self.update_partial_channel_config(counterparty_node_id, channel_ids, &(*config).into());
	}

	/// Attempts to forward an intercepted HTLC over the provided channel id and with the provided
	/// amount to forward. Should only be called in response to an [`HTLCIntercepted`] event.
	///
	/// Intercepted HTLCs can be useful for Lightning Service Providers (LSPs) to open a just-in-time
	/// channel to a receiving node if the node lacks sufficient inbound liquidity.
	///
	/// To make use of intercepted HTLCs, set [`UserConfig::accept_intercept_htlcs`] and use
	/// [`ChannelManager::get_intercept_scid`] to generate short channel id(s) to put in the
	/// receiver's invoice route hints. These route hints will signal to LDK to generate an
	/// [`HTLCIntercepted`] event when it receives the forwarded HTLC, and this method or
	/// [`ChannelManager::fail_intercepted_htlc`] MUST be called in response to the event.
	///
	/// Note that LDK does not enforce fee requirements in `amt_to_forward_msat`, and will not stop
	/// you from forwarding more than you received. See
	/// [`HTLCIntercepted::expected_outbound_amount_msat`] for more on forwarding a different amount
	/// than expected.
	///
	/// Errors if the event was not handled in time, in which case the HTLC was automatically failed
	/// backwards.
	///
	/// [`UserConfig::accept_intercept_htlcs`]: crate::util::config::UserConfig::accept_intercept_htlcs
	/// [`HTLCIntercepted`]: events::Event::HTLCIntercepted
	/// [`HTLCIntercepted::expected_outbound_amount_msat`]: events::Event::HTLCIntercepted::expected_outbound_amount_msat
	// TODO: when we move to deciding the best outbound channel at forward time, only take
	// `next_node_id` and not `next_hop_channel_id`
	pub fn forward_intercepted_htlc(&self, intercept_id: InterceptId, next_hop_channel_id: &ChannelId, next_node_id: PublicKey, amt_to_forward_msat: u64) -> Result<(), APIError> {
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(self);

		let next_hop_scid = {
			let peer_state_lock = self.per_peer_state.read().unwrap();
			let peer_state_mutex = peer_state_lock.get(&next_node_id)
				.ok_or_else(|| APIError::ChannelUnavailable { err: format!("Can't find a peer matching the passed counterparty node_id {}", next_node_id) })?;
			let mut peer_state_lock = peer_state_mutex.lock().unwrap();
			let peer_state = &mut *peer_state_lock;
			match peer_state.channel_by_id.get(next_hop_channel_id) {
				Some(ChannelPhase::Funded(chan)) => {
					if !chan.context.is_usable() {
						return Err(APIError::ChannelUnavailable {
							err: format!("Channel with id {} not fully established", next_hop_channel_id)
						})
					}
					chan.context.get_short_channel_id().unwrap_or(chan.context.outbound_scid_alias())
				},
				Some(_) => return Err(APIError::ChannelUnavailable {
					err: format!("Channel with id {} for the passed counterparty node_id {} is still opening.",
						next_hop_channel_id, next_node_id)
				}),
				None => {
					let error = format!("Channel with id {} not found for the passed counterparty node_id {}",
						next_hop_channel_id, next_node_id);
					let logger = WithContext::from(&self.logger, Some(next_node_id), Some(*next_hop_channel_id));
					log_error!(logger, "{} when attempting to forward intercepted HTLC", error);
					return Err(APIError::ChannelUnavailable {
						err: error
					})
				}
			}
		};

		let payment = self.pending_intercepted_htlcs.lock().unwrap().remove(&intercept_id)
			.ok_or_else(|| APIError::APIMisuseError {
				err: format!("Payment with intercept id {} not found", log_bytes!(intercept_id.0))
			})?;

		let routing = match payment.forward_info.routing {
			PendingHTLCRouting::Forward { onion_packet, blinded, .. } => {
				PendingHTLCRouting::Forward {
					onion_packet, blinded, short_channel_id: next_hop_scid
				}
			},
			_ => unreachable!() // Only `PendingHTLCRouting::Forward`s are intercepted
		};
		let skimmed_fee_msat =
			payment.forward_info.outgoing_amt_msat.saturating_sub(amt_to_forward_msat);
		let pending_htlc_info = PendingHTLCInfo {
			skimmed_fee_msat: if skimmed_fee_msat == 0 { None } else { Some(skimmed_fee_msat) },
			outgoing_amt_msat: amt_to_forward_msat, routing, ..payment.forward_info
		};

		let mut per_source_pending_forward = [(
			payment.prev_short_channel_id,
			payment.prev_funding_outpoint,
			payment.prev_channel_id,
			payment.prev_user_channel_id,
			vec![(pending_htlc_info, payment.prev_htlc_id)]
		)];
		self.forward_htlcs(&mut per_source_pending_forward);
		Ok(())
	}

	/// Fails the intercepted HTLC indicated by intercept_id. Should only be called in response to
	/// an [`HTLCIntercepted`] event. See [`ChannelManager::forward_intercepted_htlc`].
	///
	/// Errors if the event was not handled in time, in which case the HTLC was automatically failed
	/// backwards.
	///
	/// [`HTLCIntercepted`]: events::Event::HTLCIntercepted
	pub fn fail_intercepted_htlc(&self, intercept_id: InterceptId) -> Result<(), APIError> {
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(self);

		let payment = self.pending_intercepted_htlcs.lock().unwrap().remove(&intercept_id)
			.ok_or_else(|| APIError::APIMisuseError {
				err: format!("Payment with intercept id {} not found", log_bytes!(intercept_id.0))
			})?;

		if let PendingHTLCRouting::Forward { short_channel_id, .. } = payment.forward_info.routing {
			let htlc_source = HTLCSource::PreviousHopData(HTLCPreviousHopData {
				short_channel_id: payment.prev_short_channel_id,
				user_channel_id: Some(payment.prev_user_channel_id),
				outpoint: payment.prev_funding_outpoint,
				channel_id: payment.prev_channel_id,
				htlc_id: payment.prev_htlc_id,
				incoming_packet_shared_secret: payment.forward_info.incoming_shared_secret,
				phantom_shared_secret: None,
				blinded_failure: payment.forward_info.routing.blinded_failure(),
			});

			let failure_reason = HTLCFailReason::from_failure_code(0x4000 | 10);
			let destination = HTLCDestination::UnknownNextHop { requested_forward_scid: short_channel_id };
			self.fail_htlc_backwards_internal(&htlc_source, &payment.forward_info.payment_hash, &failure_reason, destination);
		} else { unreachable!() } // Only `PendingHTLCRouting::Forward`s are intercepted

		Ok(())
	}

	fn process_pending_update_add_htlcs(&self) {
		let mut decode_update_add_htlcs = new_hash_map();
		mem::swap(&mut decode_update_add_htlcs, &mut self.decode_update_add_htlcs.lock().unwrap());

		let get_failed_htlc_destination = |outgoing_scid_opt: Option<u64>, payment_hash: PaymentHash| {
			if let Some(outgoing_scid) = outgoing_scid_opt {
				match self.short_to_chan_info.read().unwrap().get(&outgoing_scid) {
					Some((outgoing_counterparty_node_id, outgoing_channel_id)) =>
						HTLCDestination::NextHopChannel {
							node_id: Some(*outgoing_counterparty_node_id),
							channel_id: *outgoing_channel_id,
						},
					None => HTLCDestination::UnknownNextHop {
						requested_forward_scid: outgoing_scid,
					},
				}
			} else {
				HTLCDestination::FailedPayment { payment_hash }
			}
		};

		'outer_loop: for (incoming_scid, update_add_htlcs) in decode_update_add_htlcs {
			let incoming_channel_details_opt = self.do_funded_channel_callback(incoming_scid, |chan: &mut Channel<SP>| {
				let counterparty_node_id = chan.context.get_counterparty_node_id();
				let channel_id = chan.context.channel_id();
				let funding_txo = chan.context.get_funding_txo().unwrap();
				let user_channel_id = chan.context.get_user_id();
				let accept_underpaying_htlcs = chan.context.config().accept_underpaying_htlcs;
				(counterparty_node_id, channel_id, funding_txo, user_channel_id, accept_underpaying_htlcs)
			});
			let (
				incoming_counterparty_node_id, incoming_channel_id, incoming_funding_txo,
				incoming_user_channel_id, incoming_accept_underpaying_htlcs
			 ) = if let Some(incoming_channel_details) = incoming_channel_details_opt {
				incoming_channel_details
			} else {
				// The incoming channel no longer exists, HTLCs should be resolved onchain instead.
				continue;
			};

			let mut htlc_forwards = Vec::new();
			let mut htlc_fails = Vec::new();
			for update_add_htlc in &update_add_htlcs {
				let (next_hop, shared_secret, next_packet_details_opt) = match decode_incoming_update_add_htlc_onion(
					&update_add_htlc, &self.node_signer, &self.logger, &self.secp_ctx
				) {
					Ok(decoded_onion) => decoded_onion,
					Err(htlc_fail) => {
						htlc_fails.push((htlc_fail, HTLCDestination::InvalidOnion));
						continue;
					},
				};

				let is_intro_node_blinded_forward = next_hop.is_intro_node_blinded_forward();
				let outgoing_scid_opt = next_packet_details_opt.as_ref().map(|d| d.outgoing_scid);

				// Process the HTLC on the incoming channel.
				match self.do_funded_channel_callback(incoming_scid, |chan: &mut Channel<SP>| {
					let logger = WithChannelContext::from(&self.logger, &chan.context);
					chan.can_accept_incoming_htlc(
						update_add_htlc, &self.fee_estimator, &logger,
					)
				}) {
					Some(Ok(_)) => {},
					Some(Err((err, code))) => {
						let outgoing_chan_update_opt = if let Some(outgoing_scid) = outgoing_scid_opt.as_ref() {
							self.do_funded_channel_callback(*outgoing_scid, |chan: &mut Channel<SP>| {
								self.get_channel_update_for_onion(*outgoing_scid, chan).ok()
							}).flatten()
						} else {
							None
						};
						let htlc_fail = self.htlc_failure_from_update_add_err(
							&update_add_htlc, &incoming_counterparty_node_id, err, code,
							outgoing_chan_update_opt, is_intro_node_blinded_forward, &shared_secret,
						);
						let htlc_destination = get_failed_htlc_destination(outgoing_scid_opt, update_add_htlc.payment_hash);
						htlc_fails.push((htlc_fail, htlc_destination));
						continue;
					},
					// The incoming channel no longer exists, HTLCs should be resolved onchain instead.
					None => continue 'outer_loop,
				}

				// Now process the HTLC on the outgoing channel if it's a forward.
				if let Some(next_packet_details) = next_packet_details_opt.as_ref() {
					if let Err((err, code, chan_update_opt)) = self.can_forward_htlc(
						&update_add_htlc, next_packet_details
					) {
						let htlc_fail = self.htlc_failure_from_update_add_err(
							&update_add_htlc, &incoming_counterparty_node_id, err, code,
							chan_update_opt, is_intro_node_blinded_forward, &shared_secret,
						);
						let htlc_destination = get_failed_htlc_destination(outgoing_scid_opt, update_add_htlc.payment_hash);
						htlc_fails.push((htlc_fail, htlc_destination));
						continue;
					}
				}

				match self.construct_pending_htlc_status(
					&update_add_htlc, &incoming_counterparty_node_id, shared_secret, next_hop,
					incoming_accept_underpaying_htlcs, next_packet_details_opt.map(|d| d.next_packet_pubkey),
				) {
					PendingHTLCStatus::Forward(htlc_forward) => {
						htlc_forwards.push((htlc_forward, update_add_htlc.htlc_id));
					},
					PendingHTLCStatus::Fail(htlc_fail) => {
						let htlc_destination = get_failed_htlc_destination(outgoing_scid_opt, update_add_htlc.payment_hash);
						htlc_fails.push((htlc_fail, htlc_destination));
					},
				}
			}

			// Process all of the forwards and failures for the channel in which the HTLCs were
			// proposed to as a batch.
			let pending_forwards = (incoming_scid, incoming_funding_txo, incoming_channel_id,
				incoming_user_channel_id, htlc_forwards.drain(..).collect());
			self.forward_htlcs_without_forward_event(&mut [pending_forwards]);
			for (htlc_fail, htlc_destination) in htlc_fails.drain(..) {
				let failure = match htlc_fail {
					HTLCFailureMsg::Relay(fail_htlc) => HTLCForwardInfo::FailHTLC {
						htlc_id: fail_htlc.htlc_id,
						err_packet: fail_htlc.reason,
					},
					HTLCFailureMsg::Malformed(fail_malformed_htlc) => HTLCForwardInfo::FailMalformedHTLC {
						htlc_id: fail_malformed_htlc.htlc_id,
						sha256_of_onion: fail_malformed_htlc.sha256_of_onion,
						failure_code: fail_malformed_htlc.failure_code,
					},
				};
				self.forward_htlcs.lock().unwrap().entry(incoming_scid).or_insert(vec![]).push(failure);
				self.pending_events.lock().unwrap().push_back((events::Event::HTLCHandlingFailed {
					prev_channel_id: incoming_channel_id,
					failed_next_destination: htlc_destination,
				}, None));
			}
		}
	}

	/// Processes HTLCs which are pending waiting on random forward delay.
	///
	/// Should only really ever be called in response to a PendingHTLCsForwardable event.
	/// Will likely generate further events.
	pub fn process_pending_htlc_forwards(&self) {
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(self);

		self.process_pending_update_add_htlcs();

		let mut new_events = VecDeque::new();
		let mut failed_forwards = Vec::new();
		let mut phantom_receives: Vec<(u64, OutPoint, ChannelId, u128, Vec<(PendingHTLCInfo, u64)>)> = Vec::new();
		{
			let mut forward_htlcs = new_hash_map();
			mem::swap(&mut forward_htlcs, &mut self.forward_htlcs.lock().unwrap());

			for (short_chan_id, mut pending_forwards) in forward_htlcs {
				if short_chan_id != 0 {
					let mut forwarding_counterparty = None;
					macro_rules! forwarding_channel_not_found {
						() => {
							for forward_info in pending_forwards.drain(..) {
								match forward_info {
									HTLCForwardInfo::AddHTLC(PendingAddHTLCInfo {
										prev_short_channel_id, prev_htlc_id, prev_channel_id, prev_funding_outpoint,
										prev_user_channel_id, forward_info: PendingHTLCInfo {
											routing, incoming_shared_secret, payment_hash, outgoing_amt_msat,
											outgoing_cltv_value, ..
										}
									}) => {
										macro_rules! failure_handler {
											($msg: expr, $err_code: expr, $err_data: expr, $phantom_ss: expr, $next_hop_unknown: expr) => {
												let logger = WithContext::from(&self.logger, forwarding_counterparty, Some(prev_channel_id));
												log_info!(logger, "Failed to accept/forward incoming HTLC: {}", $msg);

												let htlc_source = HTLCSource::PreviousHopData(HTLCPreviousHopData {
													short_channel_id: prev_short_channel_id,
													user_channel_id: Some(prev_user_channel_id),
													channel_id: prev_channel_id,
													outpoint: prev_funding_outpoint,
													htlc_id: prev_htlc_id,
													incoming_packet_shared_secret: incoming_shared_secret,
													phantom_shared_secret: $phantom_ss,
													blinded_failure: routing.blinded_failure(),
												});

												let reason = if $next_hop_unknown {
													HTLCDestination::UnknownNextHop { requested_forward_scid: short_chan_id }
												} else {
													HTLCDestination::FailedPayment{ payment_hash }
												};

												failed_forwards.push((htlc_source, payment_hash,
													HTLCFailReason::reason($err_code, $err_data),
													reason
												));
												continue;
											}
										}
										macro_rules! fail_forward {
											($msg: expr, $err_code: expr, $err_data: expr, $phantom_ss: expr) => {
												{
													failure_handler!($msg, $err_code, $err_data, $phantom_ss, true);
												}
											}
										}
										macro_rules! failed_payment {
											($msg: expr, $err_code: expr, $err_data: expr, $phantom_ss: expr) => {
												{
													failure_handler!($msg, $err_code, $err_data, $phantom_ss, false);
												}
											}
										}
										if let PendingHTLCRouting::Forward { ref onion_packet, .. } = routing {
											let phantom_pubkey_res = self.node_signer.get_node_id(Recipient::PhantomNode);
											if phantom_pubkey_res.is_ok() && fake_scid::is_valid_phantom(&self.fake_scid_rand_bytes, short_chan_id, &self.chain_hash) {
												let phantom_shared_secret = self.node_signer.ecdh(Recipient::PhantomNode, &onion_packet.public_key.unwrap(), None).unwrap().secret_bytes();
												let next_hop = match onion_utils::decode_next_payment_hop(
													phantom_shared_secret, &onion_packet.hop_data, onion_packet.hmac,
													payment_hash, None, &self.node_signer
												) {
													Ok(res) => res,
													Err(onion_utils::OnionDecodeErr::Malformed { err_msg, err_code }) => {
														let sha256_of_onion = Sha256::hash(&onion_packet.hop_data).to_byte_array();
														// In this scenario, the phantom would have sent us an
														// `update_fail_malformed_htlc`, meaning here we encrypt the error as
														// if it came from us (the second-to-last hop) but contains the sha256
														// of the onion.
														failed_payment!(err_msg, err_code, sha256_of_onion.to_vec(), None);
													},
													Err(onion_utils::OnionDecodeErr::Relay { err_msg, err_code }) => {
														failed_payment!(err_msg, err_code, Vec::new(), Some(phantom_shared_secret));
													},
												};
												match next_hop {
													onion_utils::Hop::Receive(hop_data) => {
														let current_height: u32 = self.best_block.read().unwrap().height;
														match create_recv_pending_htlc_info(hop_data,
															incoming_shared_secret, payment_hash, outgoing_amt_msat,
															outgoing_cltv_value, Some(phantom_shared_secret), false, None,
															current_height, self.default_configuration.accept_mpp_keysend)
														{
															Ok(info) => phantom_receives.push((prev_short_channel_id, prev_funding_outpoint, prev_channel_id, prev_user_channel_id, vec![(info, prev_htlc_id)])),
															Err(InboundHTLCErr { err_code, err_data, msg }) => failed_payment!(msg, err_code, err_data, Some(phantom_shared_secret))
														}
													},
													_ => panic!(),
												}
											} else {
												fail_forward!(format!("Unknown short channel id {} for forward HTLC", short_chan_id), 0x4000 | 10, Vec::new(), None);
											}
										} else {
											fail_forward!(format!("Unknown short channel id {} for forward HTLC", short_chan_id), 0x4000 | 10, Vec::new(), None);
										}
									},
									HTLCForwardInfo::FailHTLC { .. } | HTLCForwardInfo::FailMalformedHTLC { .. } => {
										// Channel went away before we could fail it. This implies
										// the channel is now on chain and our counterparty is
										// trying to broadcast the HTLC-Timeout, but that's their
										// problem, not ours.
									}
								}
							}
						}
					}
					let chan_info_opt = self.short_to_chan_info.read().unwrap().get(&short_chan_id).cloned();
					let (counterparty_node_id, forward_chan_id) = match chan_info_opt {
						Some((cp_id, chan_id)) => (cp_id, chan_id),
						None => {
							forwarding_channel_not_found!();
							continue;
						}
					};
					forwarding_counterparty = Some(counterparty_node_id);
					let per_peer_state = self.per_peer_state.read().unwrap();
					let peer_state_mutex_opt = per_peer_state.get(&counterparty_node_id);
					if peer_state_mutex_opt.is_none() {
						forwarding_channel_not_found!();
						continue;
					}
					let mut peer_state_lock = peer_state_mutex_opt.unwrap().lock().unwrap();
					let peer_state = &mut *peer_state_lock;
					if let Some(ChannelPhase::Funded(ref mut chan)) = peer_state.channel_by_id.get_mut(&forward_chan_id) {
						let logger = WithChannelContext::from(&self.logger, &chan.context);
						for forward_info in pending_forwards.drain(..) {
							let queue_fail_htlc_res = match forward_info {
								HTLCForwardInfo::AddHTLC(PendingAddHTLCInfo {
									prev_short_channel_id, prev_htlc_id, prev_channel_id, prev_funding_outpoint,
									prev_user_channel_id, forward_info: PendingHTLCInfo {
										incoming_shared_secret, payment_hash, outgoing_amt_msat, outgoing_cltv_value,
										routing: PendingHTLCRouting::Forward {
											onion_packet, blinded, ..
										}, skimmed_fee_msat, ..
									},
								}) => {
									log_trace!(logger, "Adding HTLC from short id {} with payment_hash {} to channel with short id {} after delay", prev_short_channel_id, &payment_hash, short_chan_id);
									let htlc_source = HTLCSource::PreviousHopData(HTLCPreviousHopData {
										short_channel_id: prev_short_channel_id,
										user_channel_id: Some(prev_user_channel_id),
										channel_id: prev_channel_id,
										outpoint: prev_funding_outpoint,
										htlc_id: prev_htlc_id,
										incoming_packet_shared_secret: incoming_shared_secret,
										// Phantom payments are only PendingHTLCRouting::Receive.
										phantom_shared_secret: None,
										blinded_failure: blinded.map(|b| b.failure),
									});
									let next_blinding_point = blinded.and_then(|b| {
										let encrypted_tlvs_ss = self.node_signer.ecdh(
											Recipient::Node, &b.inbound_blinding_point, None
										).unwrap().secret_bytes();
										onion_utils::next_hop_pubkey(
											&self.secp_ctx, b.inbound_blinding_point, &encrypted_tlvs_ss
										).ok()
									});
									if let Err(e) = chan.queue_add_htlc(outgoing_amt_msat,
										payment_hash, outgoing_cltv_value, htlc_source.clone(),
										onion_packet, skimmed_fee_msat, next_blinding_point, &self.fee_estimator,
										&&logger)
									{
										if let ChannelError::Ignore(msg) = e {
											log_trace!(logger, "Failed to forward HTLC with payment_hash {}: {}", &payment_hash, msg);
										} else {
											panic!("Stated return value requirements in send_htlc() were not met");
										}
										let (failure_code, data) = self.get_htlc_temp_fail_err_and_data(0x1000|7, short_chan_id, chan);
										failed_forwards.push((htlc_source, payment_hash,
											HTLCFailReason::reason(failure_code, data),
											HTLCDestination::NextHopChannel { node_id: Some(chan.context.get_counterparty_node_id()), channel_id: forward_chan_id }
										));
										continue;
									}
									None
								},
								HTLCForwardInfo::AddHTLC { .. } => {
									panic!("short_channel_id != 0 should imply any pending_forward entries are of type Forward");
								},
								HTLCForwardInfo::FailHTLC { htlc_id, err_packet } => {
									log_trace!(logger, "Failing HTLC back to channel with short id {} (backward HTLC ID {}) after delay", short_chan_id, htlc_id);
									Some((chan.queue_fail_htlc(htlc_id, err_packet, &&logger), htlc_id))
								},
								HTLCForwardInfo::FailMalformedHTLC { htlc_id, failure_code, sha256_of_onion } => {
									log_trace!(logger, "Failing malformed HTLC back to channel with short id {} (backward HTLC ID {}) after delay", short_chan_id, htlc_id);
									let res = chan.queue_fail_malformed_htlc(
										htlc_id, failure_code, sha256_of_onion, &&logger
									);
									Some((res, htlc_id))
								},
							};
							if let Some((queue_fail_htlc_res, htlc_id)) = queue_fail_htlc_res {
								if let Err(e) = queue_fail_htlc_res {
									if let ChannelError::Ignore(msg) = e {
										log_trace!(logger, "Failed to fail HTLC with ID {} backwards to short_id {}: {}", htlc_id, short_chan_id, msg);
									} else {
										panic!("Stated return value requirements in queue_fail_{{malformed_}}htlc() were not met");
									}
									// fail-backs are best-effort, we probably already have one
									// pending, and if not that's OK, if not, the channel is on
									// the chain and sending the HTLC-Timeout is their problem.
									continue;
								}
							}
						}
					} else {
						forwarding_channel_not_found!();
						continue;
					}
				} else {
					'next_forwardable_htlc: for forward_info in pending_forwards.drain(..) {
						match forward_info {
							HTLCForwardInfo::AddHTLC(PendingAddHTLCInfo {
								prev_short_channel_id, prev_htlc_id, prev_channel_id, prev_funding_outpoint,
								prev_user_channel_id, forward_info: PendingHTLCInfo {
									routing, incoming_shared_secret, payment_hash, incoming_amt_msat, outgoing_amt_msat,
									skimmed_fee_msat, ..
								}
							}) => {
								let blinded_failure = routing.blinded_failure();
								let (cltv_expiry, onion_payload, payment_data, phantom_shared_secret, mut onion_fields) = match routing {
									PendingHTLCRouting::Receive {
										payment_data, payment_metadata, incoming_cltv_expiry, phantom_shared_secret,
										custom_tlvs, requires_blinded_error: _
									} => {
										let _legacy_hop_data = Some(payment_data.clone());
										let onion_fields = RecipientOnionFields { payment_secret: Some(payment_data.payment_secret),
												payment_metadata, custom_tlvs };
										(incoming_cltv_expiry, OnionPayload::Invoice { _legacy_hop_data },
											Some(payment_data), phantom_shared_secret, onion_fields)
									},
									PendingHTLCRouting::ReceiveKeysend {
										payment_data, payment_preimage, payment_metadata,
										incoming_cltv_expiry, custom_tlvs, requires_blinded_error: _
									} => {
										let onion_fields = RecipientOnionFields {
											payment_secret: payment_data.as_ref().map(|data| data.payment_secret),
											payment_metadata,
											custom_tlvs,
										};
										(incoming_cltv_expiry, OnionPayload::Spontaneous(payment_preimage),
											payment_data, None, onion_fields)
									},
									_ => {
										panic!("short_channel_id == 0 should imply any pending_forward entries are of type Receive");
									}
								};
								let claimable_htlc = ClaimableHTLC {
									prev_hop: HTLCPreviousHopData {
										short_channel_id: prev_short_channel_id,
										user_channel_id: Some(prev_user_channel_id),
										channel_id: prev_channel_id,
										outpoint: prev_funding_outpoint,
										htlc_id: prev_htlc_id,
										incoming_packet_shared_secret: incoming_shared_secret,
										phantom_shared_secret,
										blinded_failure,
									},
									// We differentiate the received value from the sender intended value
									// if possible so that we don't prematurely mark MPP payments complete
									// if routing nodes overpay
									value: incoming_amt_msat.unwrap_or(outgoing_amt_msat),
									sender_intended_value: outgoing_amt_msat,
									timer_ticks: 0,
									total_value_received: None,
									total_msat: if let Some(data) = &payment_data { data.total_msat } else { outgoing_amt_msat },
									cltv_expiry,
									onion_payload,
									counterparty_skimmed_fee_msat: skimmed_fee_msat,
								};

								let mut committed_to_claimable = false;

								macro_rules! fail_htlc {
									($htlc: expr, $payment_hash: expr) => {
										debug_assert!(!committed_to_claimable);
										let mut htlc_msat_height_data = $htlc.value.to_be_bytes().to_vec();
										htlc_msat_height_data.extend_from_slice(
											&self.best_block.read().unwrap().height.to_be_bytes(),
										);
										failed_forwards.push((HTLCSource::PreviousHopData(HTLCPreviousHopData {
												short_channel_id: $htlc.prev_hop.short_channel_id,
												user_channel_id: $htlc.prev_hop.user_channel_id,
												channel_id: prev_channel_id,
												outpoint: prev_funding_outpoint,
												htlc_id: $htlc.prev_hop.htlc_id,
												incoming_packet_shared_secret: $htlc.prev_hop.incoming_packet_shared_secret,
												phantom_shared_secret,
												blinded_failure,
											}), payment_hash,
											HTLCFailReason::reason(0x4000 | 15, htlc_msat_height_data),
											HTLCDestination::FailedPayment { payment_hash: $payment_hash },
										));
										continue 'next_forwardable_htlc;
									}
								}
								let phantom_shared_secret = claimable_htlc.prev_hop.phantom_shared_secret;
								let mut receiver_node_id = self.our_network_pubkey;
								if phantom_shared_secret.is_some() {
									receiver_node_id = self.node_signer.get_node_id(Recipient::PhantomNode)
										.expect("Failed to get node_id for phantom node recipient");
								}

								macro_rules! check_total_value {
									($purpose: expr) => {{
										let mut payment_claimable_generated = false;
										let is_keysend = match $purpose {
											events::PaymentPurpose::SpontaneousPayment(_) => true,
											events::PaymentPurpose::InvoicePayment { .. } => false,
										};
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
										if !self.default_configuration.accept_mpp_keysend && is_keysend && !claimable_payment.htlcs.is_empty() {
											log_trace!(self.logger, "Failing new keysend HTLC with payment_hash {} as we already had an existing keysend HTLC with the same payment hash and our config states we don't accept MPP keysend", &payment_hash);
											fail_htlc!(claimable_htlc, payment_hash);
										}
										if let Some(earlier_fields) = &mut claimable_payment.onion_fields {
											if earlier_fields.check_merge(&mut onion_fields).is_err() {
												fail_htlc!(claimable_htlc, payment_hash);
											}
										} else {
											claimable_payment.onion_fields = Some(onion_fields);
										}
										let ref mut htlcs = &mut claimable_payment.htlcs;
										let mut total_value = claimable_htlc.sender_intended_value;
										let mut earliest_expiry = claimable_htlc.cltv_expiry;
										for htlc in htlcs.iter() {
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
											htlcs.push(claimable_htlc);
											let amount_msat = htlcs.iter().map(|htlc| htlc.value).sum();
											htlcs.iter_mut().for_each(|htlc| htlc.total_value_received = Some(amount_msat));
											let counterparty_skimmed_fee_msat = htlcs.iter()
												.map(|htlc| htlc.counterparty_skimmed_fee_msat.unwrap_or(0)).sum();
											debug_assert!(total_value.saturating_sub(amount_msat) <=
												counterparty_skimmed_fee_msat);
											new_events.push_back((events::Event::PaymentClaimable {
												receiver_node_id: Some(receiver_node_id),
												payment_hash,
												purpose: $purpose,
												amount_msat,
												counterparty_skimmed_fee_msat,
												via_channel_id: Some(prev_channel_id),
												via_user_channel_id: Some(prev_user_channel_id),
												claim_deadline: Some(earliest_expiry - HTLC_FAIL_BACK_BUFFER),
												onion_fields: claimable_payment.onion_fields.clone(),
											}, None));
											payment_claimable_generated = true;
										} else {
											// Nothing to do - we haven't reached the total
											// payment value yet, wait until we receive more
											// MPP parts.
											htlcs.push(claimable_htlc);
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
								let mut payment_secrets = self.pending_inbound_payments.lock().unwrap();
								match payment_secrets.entry(payment_hash) {
									hash_map::Entry::Vacant(_) => {
										match claimable_htlc.onion_payload {
											OnionPayload::Invoice { .. } => {
												let payment_data = payment_data.unwrap();
												let (payment_preimage, min_final_cltv_expiry_delta) = match inbound_payment::verify(payment_hash, &payment_data, self.highest_seen_timestamp.load(Ordering::Acquire) as u64, &self.inbound_payment_key, &self.logger) {
													Ok(result) => result,
													Err(()) => {
														log_trace!(self.logger, "Failing new HTLC with payment_hash {} as payment verification failed", &payment_hash);
														fail_htlc!(claimable_htlc, payment_hash);
													}
												};
												if let Some(min_final_cltv_expiry_delta) = min_final_cltv_expiry_delta {
													let expected_min_expiry_height = (self.current_best_block().height + min_final_cltv_expiry_delta as u32) as u64;
													if (cltv_expiry as u64) < expected_min_expiry_height {
														log_trace!(self.logger, "Failing new HTLC with payment_hash {} as its CLTV expiry was too soon (had {}, earliest expected {})",
															&payment_hash, cltv_expiry, expected_min_expiry_height);
														fail_htlc!(claimable_htlc, payment_hash);
													}
												}
												let purpose = events::PaymentPurpose::InvoicePayment {
													payment_preimage: payment_preimage.clone(),
													payment_secret: payment_data.payment_secret,
												};
												check_total_value!(purpose);
											},
											OnionPayload::Spontaneous(preimage) => {
												let purpose = events::PaymentPurpose::SpontaneousPayment(preimage);
												check_total_value!(purpose);
											}
										}
									},
									hash_map::Entry::Occupied(inbound_payment) => {
										if let OnionPayload::Spontaneous(_) = claimable_htlc.onion_payload {
											log_trace!(self.logger, "Failing new keysend HTLC with payment_hash {} because we already have an inbound payment with the same payment hash", &payment_hash);
											fail_htlc!(claimable_htlc, payment_hash);
										}
										let payment_data = payment_data.unwrap();
										if inbound_payment.get().payment_secret != payment_data.payment_secret {
											log_trace!(self.logger, "Failing new HTLC with payment_hash {} as it didn't match our expected payment secret.", &payment_hash);
											fail_htlc!(claimable_htlc, payment_hash);
										} else if inbound_payment.get().min_value_msat.is_some() && payment_data.total_msat < inbound_payment.get().min_value_msat.unwrap() {
											log_trace!(self.logger, "Failing new HTLC with payment_hash {} as it didn't match our minimum value (had {}, needed {}).",
												&payment_hash, payment_data.total_msat, inbound_payment.get().min_value_msat.unwrap());
											fail_htlc!(claimable_htlc, payment_hash);
										} else {
											let purpose = events::PaymentPurpose::InvoicePayment {
												payment_preimage: inbound_payment.get().payment_preimage,
												payment_secret: payment_data.payment_secret,
											};
											let payment_claimable_generated = check_total_value!(purpose);
											if payment_claimable_generated {
												inbound_payment.remove_entry();
											}
										}
									},
								};
							},
							HTLCForwardInfo::FailHTLC { .. } | HTLCForwardInfo::FailMalformedHTLC { .. } => {
								panic!("Got pending fail of our own HTLC");
							}
						}
					}
				}
			}
		}

		let best_block_height = self.best_block.read().unwrap().height;
		self.pending_outbound_payments.check_retry_payments(&self.router, || self.list_usable_channels(),
			|| self.compute_inflight_htlcs(), &self.entropy_source, &self.node_signer, best_block_height,
			&self.pending_events, &self.logger, |args| self.send_payment_along_path(args));

		for (htlc_source, payment_hash, failure_reason, destination) in failed_forwards.drain(..) {
			self.fail_htlc_backwards_internal(&htlc_source, &payment_hash, &failure_reason, destination);
		}
		self.forward_htlcs(&mut phantom_receives);

		// Freeing the holding cell here is relatively redundant - in practice we'll do it when we
		// next get a `get_and_clear_pending_msg_events` call, but some tests rely on it, and it's
		// nice to do the work now if we can rather than while we're trying to get messages in the
		// network stack.
		self.check_free_holding_cells();

		if new_events.is_empty() { return }
		let mut events = self.pending_events.lock().unwrap();
		events.append(&mut new_events);
	}

	/// Free the background events, generally called from [`PersistenceNotifierGuard`] constructors.
	///
	/// Expects the caller to have a total_consistency_lock read lock.
	fn process_background_events(&self) -> NotifyOption {
		debug_assert_ne!(self.total_consistency_lock.held_by_thread(), LockHeldState::NotHeldByThread);

		self.background_events_processed_since_startup.store(true, Ordering::Release);

		let mut background_events = Vec::new();
		mem::swap(&mut *self.pending_background_events.lock().unwrap(), &mut background_events);
		if background_events.is_empty() {
			return NotifyOption::SkipPersistNoEvents;
		}

		for event in background_events.drain(..) {
			match event {
				BackgroundEvent::ClosedMonitorUpdateRegeneratedOnStartup((funding_txo, _channel_id, update)) => {
					// The channel has already been closed, so no use bothering to care about the
					// monitor updating completing.
					let _ = self.chain_monitor.update_channel(funding_txo, &update);
				},
				BackgroundEvent::MonitorUpdateRegeneratedOnStartup { counterparty_node_id, funding_txo, channel_id, update } => {
					let mut updated_chan = false;
					{
						let per_peer_state = self.per_peer_state.read().unwrap();
						if let Some(peer_state_mutex) = per_peer_state.get(&counterparty_node_id) {
							let mut peer_state_lock = peer_state_mutex.lock().unwrap();
							let peer_state = &mut *peer_state_lock;
							match peer_state.channel_by_id.entry(channel_id) {
								hash_map::Entry::Occupied(mut chan_phase) => {
									if let ChannelPhase::Funded(chan) = chan_phase.get_mut() {
										updated_chan = true;
										handle_new_monitor_update!(self, funding_txo, update.clone(),
											peer_state_lock, peer_state, per_peer_state, chan);
									} else {
										debug_assert!(false, "We shouldn't have an update for a non-funded channel");
									}
								},
								hash_map::Entry::Vacant(_) => {},
							}
						}
					}
					if !updated_chan {
						// TODO: Track this as in-flight even though the channel is closed.
						let _ = self.chain_monitor.update_channel(funding_txo, &update);
					}
				},
				BackgroundEvent::MonitorUpdatesComplete { counterparty_node_id, channel_id } => {
					let per_peer_state = self.per_peer_state.read().unwrap();
					if let Some(peer_state_mutex) = per_peer_state.get(&counterparty_node_id) {
						let mut peer_state_lock = peer_state_mutex.lock().unwrap();
						let peer_state = &mut *peer_state_lock;
						if let Some(ChannelPhase::Funded(chan)) = peer_state.channel_by_id.get_mut(&channel_id) {
							handle_monitor_update_completion!(self, peer_state_lock, peer_state, per_peer_state, chan);
						} else {
							let update_actions = peer_state.monitor_update_blocked_actions
								.remove(&channel_id).unwrap_or(Vec::new());
							mem::drop(peer_state_lock);
							mem::drop(per_peer_state);
							self.handle_monitor_update_completion_actions(update_actions);
						}
					}
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

	fn update_channel_fee(&self, chan_id: &ChannelId, chan: &mut Channel<SP>, new_feerate: u32) -> NotifyOption {
		if !chan.context.is_outbound() { return NotifyOption::SkipPersistNoEvents; }

		let logger = WithChannelContext::from(&self.logger, &chan.context);

		// If the feerate has decreased by less than half, don't bother
		if new_feerate <= chan.context.get_feerate_sat_per_1000_weight() && new_feerate * 2 > chan.context.get_feerate_sat_per_1000_weight() {
			return NotifyOption::SkipPersistNoEvents;
		}
		if !chan.context.is_live() {
			log_trace!(logger, "Channel {} does not qualify for a feerate change from {} to {} as it cannot currently be updated (probably the peer is disconnected).",
				chan_id, chan.context.get_feerate_sat_per_1000_weight(), new_feerate);
			return NotifyOption::SkipPersistNoEvents;
		}
		log_trace!(logger, "Channel {} qualifies for a feerate change from {} to {}.",
			&chan_id, chan.context.get_feerate_sat_per_1000_weight(), new_feerate);

		chan.queue_update_fee(new_feerate, &self.fee_estimator, &&logger);
		NotifyOption::DoPersist
	}

	#[cfg(fuzzing)]
	/// In chanmon_consistency we want to sometimes do the channel fee updates done in
	/// timer_tick_occurred, but we can't generate the disabled channel updates as it considers
	/// these a fuzz failure (as they usually indicate a channel force-close, which is exactly what
	/// it wants to detect). Thus, we have a variant exposed here for its benefit.
	pub fn maybe_update_chan_fees(&self) {
		PersistenceNotifierGuard::optionally_notify(self, || {
			let mut should_persist = NotifyOption::SkipPersistNoEvents;

			let non_anchor_feerate = self.fee_estimator.bounded_sat_per_1000_weight(ConfirmationTarget::NonAnchorChannelFee);
			let anchor_feerate = self.fee_estimator.bounded_sat_per_1000_weight(ConfirmationTarget::AnchorChannelFee);

			let per_peer_state = self.per_peer_state.read().unwrap();
			for (_cp_id, peer_state_mutex) in per_peer_state.iter() {
				let mut peer_state_lock = peer_state_mutex.lock().unwrap();
				let peer_state = &mut *peer_state_lock;
				for (chan_id, chan) in peer_state.channel_by_id.iter_mut().filter_map(
					|(chan_id, phase)| if let ChannelPhase::Funded(chan) = phase { Some((chan_id, chan)) } else { None }
				) {
					let new_feerate = if chan.context.get_channel_type().supports_anchors_zero_fee_htlc_tx() {
						anchor_feerate
					} else {
						non_anchor_feerate
					};
					let chan_needs_persist = self.update_channel_fee(chan_id, chan, new_feerate);
					if chan_needs_persist == NotifyOption::DoPersist { should_persist = NotifyOption::DoPersist; }
				}
			}

			should_persist
		});
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
	///    minus two hours in `no-std`.
	///
	/// Note that this may cause reentrancy through [`chain::Watch::update_channel`] calls or feerate
	/// estimate fetches.
	///
	/// [`ChannelUpdate`]: msgs::ChannelUpdate
	/// [`ChannelConfig`]: crate::util::config::ChannelConfig
	pub fn timer_tick_occurred(&self) {
		PersistenceNotifierGuard::optionally_notify(self, || {
			let mut should_persist = NotifyOption::SkipPersistNoEvents;

			let non_anchor_feerate = self.fee_estimator.bounded_sat_per_1000_weight(ConfirmationTarget::NonAnchorChannelFee);
			let anchor_feerate = self.fee_estimator.bounded_sat_per_1000_weight(ConfirmationTarget::AnchorChannelFee);

			let mut handle_errors: Vec<(Result<(), _>, _)> = Vec::new();
			let mut timed_out_mpp_htlcs = Vec::new();
			let mut pending_peers_awaiting_removal = Vec::new();
			let mut shutdown_channels = Vec::new();

			let mut process_unfunded_channel_tick = |
				chan_id: &ChannelId,
				context: &mut ChannelContext<SP>,
				unfunded_context: &mut UnfundedChannelContext,
				pending_msg_events: &mut Vec<MessageSendEvent>,
				counterparty_node_id: PublicKey,
			| {
				context.maybe_expire_prev_config();
				if unfunded_context.should_expire_unfunded_channel() {
					let logger = WithChannelContext::from(&self.logger, context);
					log_error!(logger,
						"Force-closing pending channel with ID {} for not establishing in a timely manner", chan_id);
					update_maps_on_chan_removal!(self, &context);
					shutdown_channels.push(context.force_shutdown(false, ClosureReason::HolderForceClosed));
					pending_msg_events.push(MessageSendEvent::HandleError {
						node_id: counterparty_node_id,
						action: msgs::ErrorAction::SendErrorMessage {
							msg: msgs::ErrorMessage {
								channel_id: *chan_id,
								data: "Force-closing pending channel due to timeout awaiting establishment handshake".to_owned(),
							},
						},
					});
					false
				} else {
					true
				}
			};

			{
				let per_peer_state = self.per_peer_state.read().unwrap();
				for (counterparty_node_id, peer_state_mutex) in per_peer_state.iter() {
					let mut peer_state_lock = peer_state_mutex.lock().unwrap();
					let peer_state = &mut *peer_state_lock;
					let pending_msg_events = &mut peer_state.pending_msg_events;
					let counterparty_node_id = *counterparty_node_id;
					peer_state.channel_by_id.retain(|chan_id, phase| {
						match phase {
							ChannelPhase::Funded(chan) => {
								let new_feerate = if chan.context.get_channel_type().supports_anchors_zero_fee_htlc_tx() {
									anchor_feerate
								} else {
									non_anchor_feerate
								};
								let chan_needs_persist = self.update_channel_fee(chan_id, chan, new_feerate);
								if chan_needs_persist == NotifyOption::DoPersist { should_persist = NotifyOption::DoPersist; }

								if let Err(e) = chan.timer_check_closing_negotiation_progress() {
									let (needs_close, err) = convert_chan_phase_err!(self, e, chan, chan_id, FUNDED_CHANNEL);
									handle_errors.push((Err(err), counterparty_node_id));
									if needs_close { return false; }
								}

								match chan.channel_update_status() {
									ChannelUpdateStatus::Enabled if !chan.context.is_live() => chan.set_channel_update_status(ChannelUpdateStatus::DisabledStaged(0)),
									ChannelUpdateStatus::Disabled if chan.context.is_live() => chan.set_channel_update_status(ChannelUpdateStatus::EnabledStaged(0)),
									ChannelUpdateStatus::DisabledStaged(_) if chan.context.is_live()
										=> chan.set_channel_update_status(ChannelUpdateStatus::Enabled),
									ChannelUpdateStatus::EnabledStaged(_) if !chan.context.is_live()
										=> chan.set_channel_update_status(ChannelUpdateStatus::Disabled),
									ChannelUpdateStatus::DisabledStaged(mut n) if !chan.context.is_live() => {
										n += 1;
										if n >= DISABLE_GOSSIP_TICKS {
											chan.set_channel_update_status(ChannelUpdateStatus::Disabled);
											if let Ok(update) = self.get_channel_update_for_broadcast(&chan) {
												let mut pending_broadcast_messages = self.pending_broadcast_messages.lock().unwrap();
												pending_broadcast_messages.push(events::MessageSendEvent::BroadcastChannelUpdate {
													msg: update
												});
											}
											should_persist = NotifyOption::DoPersist;
										} else {
											chan.set_channel_update_status(ChannelUpdateStatus::DisabledStaged(n));
										}
									},
									ChannelUpdateStatus::EnabledStaged(mut n) if chan.context.is_live() => {
										n += 1;
										if n >= ENABLE_GOSSIP_TICKS {
											chan.set_channel_update_status(ChannelUpdateStatus::Enabled);
											if let Ok(update) = self.get_channel_update_for_broadcast(&chan) {
												let mut pending_broadcast_messages = self.pending_broadcast_messages.lock().unwrap();
												pending_broadcast_messages.push(events::MessageSendEvent::BroadcastChannelUpdate {
													msg: update
												});
											}
											should_persist = NotifyOption::DoPersist;
										} else {
											chan.set_channel_update_status(ChannelUpdateStatus::EnabledStaged(n));
										}
									},
									_ => {},
								}

								chan.context.maybe_expire_prev_config();

								if chan.should_disconnect_peer_awaiting_response() {
									let logger = WithChannelContext::from(&self.logger, &chan.context);
									log_debug!(logger, "Disconnecting peer {} due to not making any progress on channel {}",
											counterparty_node_id, chan_id);
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

								true
							},
							ChannelPhase::UnfundedInboundV1(chan) => {
								process_unfunded_channel_tick(chan_id, &mut chan.context, &mut chan.unfunded_context,
									pending_msg_events, counterparty_node_id)
							},
							ChannelPhase::UnfundedOutboundV1(chan) => {
								process_unfunded_channel_tick(chan_id, &mut chan.context, &mut chan.unfunded_context,
									pending_msg_events, counterparty_node_id)
							},
							#[cfg(dual_funding)]
							ChannelPhase::UnfundedInboundV2(chan) => {
								process_unfunded_channel_tick(chan_id, &mut chan.context, &mut chan.unfunded_context,
									pending_msg_events, counterparty_node_id)
							},
							#[cfg(dual_funding)]
							ChannelPhase::UnfundedOutboundV2(chan) => {
								process_unfunded_channel_tick(chan_id, &mut chan.context, &mut chan.unfunded_context,
									pending_msg_events, counterparty_node_id)
							},
						}
					});

					for (chan_id, req) in peer_state.inbound_channel_request_by_id.iter_mut() {
						if { req.ticks_remaining -= 1 ; req.ticks_remaining } <= 0 {
							let logger = WithContext::from(&self.logger, Some(counterparty_node_id), Some(*chan_id));
							log_error!(logger, "Force-closing unaccepted inbound channel {} for not accepting in a timely manner", &chan_id);
							peer_state.pending_msg_events.push(
								events::MessageSendEvent::HandleError {
									node_id: counterparty_node_id,
									action: msgs::ErrorAction::SendErrorMessage {
										msg: msgs::ErrorMessage { channel_id: chan_id.clone(), data: "Channel force-closed".to_owned() }
									},
								}
							);
						}
					}
					peer_state.inbound_channel_request_by_id.retain(|_, req| req.ticks_remaining > 0);

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
						hash_map::Entry::Vacant(_) => { /* The PeerState has already been removed */ }
					}
				}
			}

			self.claimable_payments.lock().unwrap().claimable_payments.retain(|payment_hash, payment| {
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
					if payment.htlcs[0].total_msat <= payment.htlcs.iter()
						.fold(0, |total, htlc| total + htlc.sender_intended_value)
					{
						return true;
					} else if payment.htlcs.iter_mut().any(|htlc| {
						htlc.timer_ticks += 1;
						return htlc.timer_ticks >= MPP_TIMEOUT_TICKS
					}) {
						timed_out_mpp_htlcs.extend(payment.htlcs.drain(..)
							.map(|htlc: ClaimableHTLC| (htlc.prev_hop, *payment_hash)));
						return false;
					}
				}
				true
			});

			for htlc_source in timed_out_mpp_htlcs.drain(..) {
				let source = HTLCSource::PreviousHopData(htlc_source.0.clone());
				let reason = HTLCFailReason::from_failure_code(23);
				let receiver = HTLCDestination::FailedPayment { payment_hash: htlc_source.1 };
				self.fail_htlc_backwards_internal(&source, &htlc_source.1, &reason, receiver);
			}

			for (err, counterparty_node_id) in handle_errors.drain(..) {
				let _ = handle_error!(self, err, counterparty_node_id);
			}

			for shutdown_res in shutdown_channels {
				self.finish_close_channel(shutdown_res);
			}

			#[cfg(feature = "std")]
			let duration_since_epoch = std::time::SystemTime::now()
				.duration_since(std::time::SystemTime::UNIX_EPOCH)
				.expect("SystemTime::now() should come after SystemTime::UNIX_EPOCH");
			#[cfg(not(feature = "std"))]
			let duration_since_epoch = Duration::from_secs(
				self.highest_seen_timestamp.load(Ordering::Acquire).saturating_sub(7200) as u64
			);

			self.pending_outbound_payments.remove_stale_payments(
				duration_since_epoch, &self.pending_events
			);

			// Technically we don't need to do this here, but if we have holding cell entries in a
			// channel that need freeing, it's better to do that here and block a background task
			// than block the message queueing pipeline.
			if self.check_free_holding_cells() {
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
		self.fail_htlc_backwards_with_reason(payment_hash, FailureCode::IncorrectOrUnknownPaymentDetails);
	}

	/// This is a variant of [`ChannelManager::fail_htlc_backwards`] that allows you to specify the
	/// reason for the failure.
	///
	/// See [`FailureCode`] for valid failure codes.
	pub fn fail_htlc_backwards_with_reason(&self, payment_hash: &PaymentHash, failure_code: FailureCode) {
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(self);

		let removed_source = self.claimable_payments.lock().unwrap().claimable_payments.remove(payment_hash);
		if let Some(payment) = removed_source {
			for htlc in payment.htlcs {
				let reason = self.get_htlc_fail_reason_from_failure_code(failure_code, &htlc);
				let source = HTLCSource::PreviousHopData(htlc.prev_hop);
				let receiver = HTLCDestination::FailedPayment { payment_hash: *payment_hash };
				self.fail_htlc_backwards_internal(&source, &payment_hash, &reason, receiver);
			}
		}
	}

	/// Gets error data to form an [`HTLCFailReason`] given a [`FailureCode`] and [`ClaimableHTLC`].
	fn get_htlc_fail_reason_from_failure_code(&self, failure_code: FailureCode, htlc: &ClaimableHTLC) -> HTLCFailReason {
		match failure_code {
			FailureCode::TemporaryNodeFailure => HTLCFailReason::from_failure_code(failure_code.into()),
			FailureCode::RequiredNodeFeatureMissing => HTLCFailReason::from_failure_code(failure_code.into()),
			FailureCode::IncorrectOrUnknownPaymentDetails => {
				let mut htlc_msat_height_data = htlc.value.to_be_bytes().to_vec();
				htlc_msat_height_data.extend_from_slice(&self.best_block.read().unwrap().height.to_be_bytes());
				HTLCFailReason::reason(failure_code.into(), htlc_msat_height_data)
			},
			FailureCode::InvalidOnionPayload(data) => {
				let fail_data = match data {
					Some((typ, offset)) => [BigSize(typ).encode(), offset.encode()].concat(),
					None => Vec::new(),
				};
				HTLCFailReason::reason(failure_code.into(), fail_data)
			}
		}
	}

	/// Gets an HTLC onion failure code and error data for an `UPDATE` error, given the error code
	/// that we want to return and a channel.
	///
	/// This is for failures on the channel on which the HTLC was *received*, not failures
	/// forwarding
	fn get_htlc_inbound_temp_fail_err_and_data(&self, desired_err_code: u16, chan: &Channel<SP>) -> (u16, Vec<u8>) {
		// We can't be sure what SCID was used when relaying inbound towards us, so we have to
		// guess somewhat. If its a public channel, we figure best to just use the real SCID (as
		// we're not leaking that we have a channel with the counterparty), otherwise we try to use
		// an inbound SCID alias before the real SCID.
		let scid_pref = if chan.context.should_announce() {
			chan.context.get_short_channel_id().or(chan.context.latest_inbound_scid_alias())
		} else {
			chan.context.latest_inbound_scid_alias().or(chan.context.get_short_channel_id())
		};
		if let Some(scid) = scid_pref {
			self.get_htlc_temp_fail_err_and_data(desired_err_code, scid, chan)
		} else {
			(0x4000|10, Vec::new())
		}
	}


	/// Gets an HTLC onion failure code and error data for an `UPDATE` error, given the error code
	/// that we want to return and a channel.
	fn get_htlc_temp_fail_err_and_data(&self, desired_err_code: u16, scid: u64, chan: &Channel<SP>) -> (u16, Vec<u8>) {
		debug_assert_eq!(desired_err_code & 0x1000, 0x1000);
		if let Ok(upd) = self.get_channel_update_for_onion(scid, chan) {
			let mut enc = VecWriter(Vec::with_capacity(upd.serialized_length() + 6));
			if desired_err_code == 0x1000 | 20 {
				// No flags for `disabled_flags` are currently defined so they're always two zero bytes.
				// See https://github.com/lightning/bolts/blob/341ec84/04-onion-routing.md?plain=1#L1008
				0u16.write(&mut enc).expect("Writes cannot fail");
			}
			(upd.serialized_length() as u16 + 2).write(&mut enc).expect("Writes cannot fail");
			msgs::ChannelUpdate::TYPE.write(&mut enc).expect("Writes cannot fail");
			upd.write(&mut enc).expect("Writes cannot fail");
			(desired_err_code, enc.0)
		} else {
			// If we fail to get a unicast channel_update, it implies we don't yet have an SCID,
			// which means we really shouldn't have gotten a payment to be forwarded over this
			// channel yet, or if we did it's from a route hint. Either way, returning an error of
			// PERM|no_such_channel should be fine.
			(0x4000|10, Vec::new())
		}
	}

	// Fail a list of HTLCs that were just freed from the holding cell. The HTLCs need to be
	// failed backwards or, if they were one of our outgoing HTLCs, then their failure needs to
	// be surfaced to the user.
	fn fail_holding_cell_htlcs(
		&self, mut htlcs_to_fail: Vec<(HTLCSource, PaymentHash)>, channel_id: ChannelId,
		counterparty_node_id: &PublicKey
	) {
		let (failure_code, onion_failure_data) = {
			let per_peer_state = self.per_peer_state.read().unwrap();
			if let Some(peer_state_mutex) = per_peer_state.get(counterparty_node_id) {
				let mut peer_state_lock = peer_state_mutex.lock().unwrap();
				let peer_state = &mut *peer_state_lock;
				match peer_state.channel_by_id.entry(channel_id) {
					hash_map::Entry::Occupied(chan_phase_entry) => {
						if let ChannelPhase::Funded(chan) = chan_phase_entry.get() {
							self.get_htlc_inbound_temp_fail_err_and_data(0x1000|7, &chan)
						} else {
							// We shouldn't be trying to fail holding cell HTLCs on an unfunded channel.
							debug_assert!(false);
							(0x4000|10, Vec::new())
						}
					},
					hash_map::Entry::Vacant(_) => (0x4000|10, Vec::new())
				}
			} else { (0x4000|10, Vec::new()) }
		};

		for (htlc_src, payment_hash) in htlcs_to_fail.drain(..) {
			let reason = HTLCFailReason::reason(failure_code, onion_failure_data.clone());
			let receiver = HTLCDestination::NextHopChannel { node_id: Some(counterparty_node_id.clone()), channel_id };
			self.fail_htlc_backwards_internal(&htlc_src, &payment_hash, &reason, receiver);
		}
	}

	fn fail_htlc_backwards_internal(&self, source: &HTLCSource, payment_hash: &PaymentHash, onion_error: &HTLCFailReason, destination: HTLCDestination) {
		let push_forward_event = self.fail_htlc_backwards_internal_without_forward_event(source, payment_hash, onion_error, destination);
		if push_forward_event { self.push_pending_forwards_ev(); }
	}

	/// Fails an HTLC backwards to the sender of it to us.
	/// Note that we do not assume that channels corresponding to failed HTLCs are still available.
	fn fail_htlc_backwards_internal_without_forward_event(&self, source: &HTLCSource, payment_hash: &PaymentHash, onion_error: &HTLCFailReason, destination: HTLCDestination) -> bool {
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
		let mut push_forward_event;
		match source {
			HTLCSource::OutboundRoute { ref path, ref session_priv, ref payment_id, .. } => {
				push_forward_event = self.pending_outbound_payments.fail_htlc(source, payment_hash, onion_error, path,
					session_priv, payment_id, self.probing_cookie_secret, &self.secp_ctx,
					&self.pending_events, &self.logger);
			},
			HTLCSource::PreviousHopData(HTLCPreviousHopData {
				ref short_channel_id, ref htlc_id, ref incoming_packet_shared_secret,
				ref phantom_shared_secret, outpoint: _, ref blinded_failure, ref channel_id, ..
			}) => {
				log_trace!(
					WithContext::from(&self.logger, None, Some(*channel_id)),
					"Failing {}HTLC with payment_hash {} backwards from us: {:?}",
					if blinded_failure.is_some() { "blinded " } else { "" }, &payment_hash, onion_error
				);
				let failure = match blinded_failure {
					Some(BlindedFailure::FromIntroductionNode) => {
						let blinded_onion_error = HTLCFailReason::reason(INVALID_ONION_BLINDING, vec![0; 32]);
						let err_packet = blinded_onion_error.get_encrypted_failure_packet(
							incoming_packet_shared_secret, phantom_shared_secret
						);
						HTLCForwardInfo::FailHTLC { htlc_id: *htlc_id, err_packet }
					},
					Some(BlindedFailure::FromBlindedNode) => {
						HTLCForwardInfo::FailMalformedHTLC {
							htlc_id: *htlc_id,
							failure_code: INVALID_ONION_BLINDING,
							sha256_of_onion: [0; 32]
						}
					},
					None => {
						let err_packet = onion_error.get_encrypted_failure_packet(
							incoming_packet_shared_secret, phantom_shared_secret
						);
						HTLCForwardInfo::FailHTLC { htlc_id: *htlc_id, err_packet }
					}
				};

				push_forward_event = self.decode_update_add_htlcs.lock().unwrap().is_empty();
				let mut forward_htlcs = self.forward_htlcs.lock().unwrap();
				push_forward_event &= forward_htlcs.is_empty();
				match forward_htlcs.entry(*short_channel_id) {
					hash_map::Entry::Occupied(mut entry) => {
						entry.get_mut().push(failure);
					},
					hash_map::Entry::Vacant(entry) => {
						entry.insert(vec!(failure));
					}
				}
				mem::drop(forward_htlcs);
				let mut pending_events = self.pending_events.lock().unwrap();
				pending_events.push_back((events::Event::HTLCHandlingFailed {
					prev_channel_id: *channel_id,
					failed_next_destination: destination,
				}, None));
			},
		}
		push_forward_event
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

		let mut sources = {
			let mut claimable_payments = self.claimable_payments.lock().unwrap();
			if let Some(payment) = claimable_payments.claimable_payments.remove(&payment_hash) {
				let mut receiver_node_id = self.our_network_pubkey;
				for htlc in payment.htlcs.iter() {
					if htlc.prev_hop.phantom_shared_secret.is_some() {
						let phantom_pubkey = self.node_signer.get_node_id(Recipient::PhantomNode)
							.expect("Failed to get node_id for phantom node recipient");
						receiver_node_id = phantom_pubkey;
						break;
					}
				}

				let htlcs = payment.htlcs.iter().map(events::ClaimedHTLC::from).collect();
				let sender_intended_value = payment.htlcs.first().map(|htlc| htlc.total_msat);
				let dup_purpose = claimable_payments.pending_claiming_payments.insert(payment_hash,
					ClaimingPayment { amount_msat: payment.htlcs.iter().map(|source| source.value).sum(),
					payment_purpose: payment.purpose, receiver_node_id, htlcs, sender_intended_value
				});
				if dup_purpose.is_some() {
					debug_assert!(false, "Shouldn't get a duplicate pending claim event ever");
					log_error!(self.logger, "Got a duplicate pending claimable event on payment hash {}! Please report this bug",
						&payment_hash);
				}

				if let Some(RecipientOnionFields { ref custom_tlvs, .. }) = payment.onion_fields {
					if !custom_tlvs_known && custom_tlvs.iter().any(|(typ, _)| typ % 2 == 0) {
						log_info!(self.logger, "Rejecting payment with payment hash {} as we cannot accept payment with unknown even TLVs: {}",
							&payment_hash, log_iter!(custom_tlvs.iter().map(|(typ, _)| typ).filter(|typ| *typ % 2 == 0)));
						claimable_payments.pending_claiming_payments.remove(&payment_hash);
						mem::drop(claimable_payments);
						for htlc in payment.htlcs {
							let reason = self.get_htlc_fail_reason_from_failure_code(FailureCode::InvalidOnionPayload(None), &htlc);
							let source = HTLCSource::PreviousHopData(htlc.prev_hop);
							let receiver = HTLCDestination::FailedPayment { payment_hash };
							self.fail_htlc_backwards_internal(&source, &payment_hash, &reason, receiver);
						}
						return;
					}
				}

				payment.htlcs
			} else { return; }
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
			log_info!(self.logger, "Attempted to claim an incomplete payment which no longer had any available HTLCs!");
			return;
		}
		if claimable_amt_msat != expected_amt_msat.unwrap() {
			self.claimable_payments.lock().unwrap().pending_claiming_payments.remove(&payment_hash);
			log_info!(self.logger, "Attempted to claim an incomplete payment, expected {} msat, had {} available to claim.",
				expected_amt_msat.unwrap(), claimable_amt_msat);
			return;
		}
		if valid_mpp {
			for htlc in sources.drain(..) {
				let prev_hop_chan_id = htlc.prev_hop.channel_id;
				if let Err((pk, err)) = self.claim_funds_from_hop(
					htlc.prev_hop, payment_preimage,
					|_, definitely_duplicate| {
						debug_assert!(!definitely_duplicate, "We shouldn't claim duplicatively from a payment");
						Some(MonitorUpdateCompletionAction::PaymentClaimed { payment_hash })
					}
				) {
					if let msgs::ErrorAction::IgnoreError = err.err.action {
						// We got a temporary failure updating monitor, but will claim the
						// HTLC when the monitor updating is restored (or on chain).
						let logger = WithContext::from(&self.logger, None, Some(prev_hop_chan_id));
						log_error!(logger, "Temporary failure claiming HTLC, treating as success: {}", err.err.err);
					} else { errs.push((pk, err)); }
				}
			}
		}
		if !valid_mpp {
			for htlc in sources.drain(..) {
				let mut htlc_msat_height_data = htlc.value.to_be_bytes().to_vec();
				htlc_msat_height_data.extend_from_slice(&self.best_block.read().unwrap().height.to_be_bytes());
				let source = HTLCSource::PreviousHopData(htlc.prev_hop);
				let reason = HTLCFailReason::reason(0x4000 | 15, htlc_msat_height_data);
				let receiver = HTLCDestination::FailedPayment { payment_hash };
				self.fail_htlc_backwards_internal(&source, &payment_hash, &reason, receiver);
			}
			self.claimable_payments.lock().unwrap().pending_claiming_payments.remove(&payment_hash);
		}

		// Now we can handle any errors which were generated.
		for (counterparty_node_id, err) in errs.drain(..) {
			let res: Result<(), _> = Err(err);
			let _ = handle_error!(self, res, counterparty_node_id);
		}
	}

	fn claim_funds_from_hop<ComplFunc: FnOnce(Option<u64>, bool) -> Option<MonitorUpdateCompletionAction>>(&self,
		prev_hop: HTLCPreviousHopData, payment_preimage: PaymentPreimage, completion_action: ComplFunc)
	-> Result<(), (PublicKey, MsgHandleErrInternal)> {
		//TODO: Delay the claimed_funds relaying just like we do outbound relay!

		// If we haven't yet run background events assume we're still deserializing and shouldn't
		// actually pass `ChannelMonitorUpdate`s to users yet. Instead, queue them up as
		// `BackgroundEvent`s.
		let during_init = !self.background_events_processed_since_startup.load(Ordering::Acquire);

		// As we may call handle_monitor_update_completion_actions in rather rare cases, check that
		// the required mutexes are not held before we start.
		debug_assert_ne!(self.pending_events.held_by_thread(), LockHeldState::HeldByThread);
		debug_assert_ne!(self.claimable_payments.held_by_thread(), LockHeldState::HeldByThread);

		{
			let per_peer_state = self.per_peer_state.read().unwrap();
			let chan_id = prev_hop.channel_id;
			let counterparty_node_id_opt = match self.short_to_chan_info.read().unwrap().get(&prev_hop.short_channel_id) {
				Some((cp_id, _dup_chan_id)) => Some(cp_id.clone()),
				None => None
			};

			let peer_state_opt = counterparty_node_id_opt.as_ref().map(
				|counterparty_node_id| per_peer_state.get(counterparty_node_id)
					.map(|peer_mutex| peer_mutex.lock().unwrap())
			).unwrap_or(None);

			if peer_state_opt.is_some() {
				let mut peer_state_lock = peer_state_opt.unwrap();
				let peer_state = &mut *peer_state_lock;
				if let hash_map::Entry::Occupied(mut chan_phase_entry) = peer_state.channel_by_id.entry(chan_id) {
					if let ChannelPhase::Funded(chan) = chan_phase_entry.get_mut() {
						let counterparty_node_id = chan.context.get_counterparty_node_id();
						let logger = WithChannelContext::from(&self.logger, &chan.context);
						let fulfill_res = chan.get_update_fulfill_htlc_and_commit(prev_hop.htlc_id, payment_preimage, &&logger);

						match fulfill_res {
							UpdateFulfillCommitFetch::NewClaim { htlc_value_msat, monitor_update } => {
								if let Some(action) = completion_action(Some(htlc_value_msat), false) {
									log_trace!(logger, "Tracking monitor update completion action for channel {}: {:?}",
										chan_id, action);
									peer_state.monitor_update_blocked_actions.entry(chan_id).or_insert(Vec::new()).push(action);
								}
								if !during_init {
									handle_new_monitor_update!(self, prev_hop.outpoint, monitor_update, peer_state_lock,
										peer_state, per_peer_state, chan);
								} else {
									// If we're running during init we cannot update a monitor directly -
									// they probably haven't actually been loaded yet. Instead, push the
									// monitor update as a background event.
									self.pending_background_events.lock().unwrap().push(
										BackgroundEvent::MonitorUpdateRegeneratedOnStartup {
											counterparty_node_id,
											funding_txo: prev_hop.outpoint,
											channel_id: prev_hop.channel_id,
											update: monitor_update.clone(),
										});
								}
							}
							UpdateFulfillCommitFetch::DuplicateClaim {} => {
								let action = if let Some(action) = completion_action(None, true) {
									action
								} else {
									return Ok(());
								};
								mem::drop(peer_state_lock);

								log_trace!(logger, "Completing monitor update completion action for channel {} as claim was redundant: {:?}",
									chan_id, action);
								let (node_id, _funding_outpoint, channel_id, blocker) =
								if let MonitorUpdateCompletionAction::FreeOtherChannelImmediately {
									downstream_counterparty_node_id: node_id,
									downstream_funding_outpoint: funding_outpoint,
									blocking_action: blocker, downstream_channel_id: channel_id,
								} = action {
									(node_id, funding_outpoint, channel_id, blocker)
								} else {
									debug_assert!(false,
										"Duplicate claims should always free another channel immediately");
									return Ok(());
								};
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
											if *iter == blocker { found_blocker = true; }
											*iter != blocker || !first_blocker
										});
										debug_assert!(found_blocker);
									}
								} else {
									debug_assert!(false);
								}
							}
						}
					}
					return Ok(());
				}
			}
		}
		let preimage_update = ChannelMonitorUpdate {
			update_id: CLOSED_CHANNEL_UPDATE_ID,
			counterparty_node_id: None,
			updates: vec![ChannelMonitorUpdateStep::PaymentPreimage {
				payment_preimage,
			}],
			channel_id: Some(prev_hop.channel_id),
		};

		if !during_init {
			// We update the ChannelMonitor on the backward link, after
			// receiving an `update_fulfill_htlc` from the forward link.
			let update_res = self.chain_monitor.update_channel(prev_hop.outpoint, &preimage_update);
			if update_res != ChannelMonitorUpdateStatus::Completed {
				// TODO: This needs to be handled somehow - if we receive a monitor update
				// with a preimage we *must* somehow manage to propagate it to the upstream
				// channel, or we must have an ability to receive the same event and try
				// again on restart.
				log_error!(WithContext::from(&self.logger, None, Some(prev_hop.channel_id)),
					"Critical error: failed to update channel monitor with preimage {:?}: {:?}",
					payment_preimage, update_res);
			}
		} else {
			// If we're running during init we cannot update a monitor directly - they probably
			// haven't actually been loaded yet. Instead, push the monitor update as a background
			// event.
			// Note that while it's safe to use `ClosedMonitorUpdateRegeneratedOnStartup` here (the
			// channel is already closed) we need to ultimately handle the monitor update
			// completion action only after we've completed the monitor update. This is the only
			// way to guarantee this update *will* be regenerated on startup (otherwise if this was
			// from a forwarded HTLC the downstream preimage may be deleted before we claim
			// upstream). Thus, we need to transition to some new `BackgroundEvent` type which will
			// complete the monitor update completion action from `completion_action`.
			self.pending_background_events.lock().unwrap().push(
				BackgroundEvent::ClosedMonitorUpdateRegeneratedOnStartup((
					prev_hop.outpoint, prev_hop.channel_id, preimage_update,
				)));
		}
		// Note that we do process the completion action here. This totally could be a
		// duplicate claim, but we have no way of knowing without interrogating the
		// `ChannelMonitor` we've provided the above update to. Instead, note that `Event`s are
		// generally always allowed to be duplicative (and it's specifically noted in
		// `PaymentForwarded`).
		self.handle_monitor_update_completion_actions(completion_action(None, false));
		Ok(())
	}

	fn finalize_claims(&self, sources: Vec<HTLCSource>) {
		self.pending_outbound_payments.finalize_claims(sources, &self.pending_events);
	}

	fn claim_funds_internal(&self, source: HTLCSource, payment_preimage: PaymentPreimage,
		forwarded_htlc_value_msat: Option<u64>, skimmed_fee_msat: Option<u64>, from_onchain: bool,
		startup_replay: bool, next_channel_counterparty_node_id: Option<PublicKey>,
		next_channel_outpoint: OutPoint, next_channel_id: ChannelId, next_user_channel_id: Option<u128>,
	) {
		match source {
			HTLCSource::OutboundRoute { session_priv, payment_id, path, .. } => {
				debug_assert!(self.background_events_processed_since_startup.load(Ordering::Acquire),
					"We don't support claim_htlc claims during startup - monitors may not be available yet");
				if let Some(pubkey) = next_channel_counterparty_node_id {
					debug_assert_eq!(pubkey, path.hops[0].pubkey);
				}
				let ev_completion_action = EventCompletionAction::ReleaseRAAChannelMonitorUpdate {
					channel_funding_outpoint: next_channel_outpoint, channel_id: next_channel_id,
					counterparty_node_id: path.hops[0].pubkey,
				};
				self.pending_outbound_payments.claim_htlc(payment_id, payment_preimage,
					session_priv, path, from_onchain, ev_completion_action, &self.pending_events,
					&self.logger);
			},
			HTLCSource::PreviousHopData(hop_data) => {
				let prev_channel_id = hop_data.channel_id;
				let prev_user_channel_id = hop_data.user_channel_id;
				let completed_blocker = RAAMonitorUpdateBlockingAction::from_prev_hop_data(&hop_data);
				#[cfg(debug_assertions)]
				let claiming_chan_funding_outpoint = hop_data.outpoint;
				let res = self.claim_funds_from_hop(hop_data, payment_preimage,
					|htlc_claim_value_msat, definitely_duplicate| {
						let chan_to_release =
							if let Some(node_id) = next_channel_counterparty_node_id {
								Some((node_id, next_channel_outpoint, next_channel_id, completed_blocker))
							} else {
								// We can only get `None` here if we are processing a
								// `ChannelMonitor`-originated event, in which case we
								// don't care about ensuring we wake the downstream
								// channel's monitor updating - the channel is already
								// closed.
								None
							};

						if definitely_duplicate && startup_replay {
							// On startup we may get redundant claims which are related to
							// monitor updates still in flight. In that case, we shouldn't
							// immediately free, but instead let that monitor update complete
							// in the background.
							#[cfg(debug_assertions)] {
								let background_events = self.pending_background_events.lock().unwrap();
								// There should be a `BackgroundEvent` pending...
								assert!(background_events.iter().any(|ev| {
									match ev {
										// to apply a monitor update that blocked the claiming channel,
										BackgroundEvent::MonitorUpdateRegeneratedOnStartup {
											funding_txo, update, ..
										} => {
											if *funding_txo == claiming_chan_funding_outpoint {
												assert!(update.updates.iter().any(|upd|
													if let ChannelMonitorUpdateStep::PaymentPreimage {
														payment_preimage: update_preimage
													} = upd {
														payment_preimage == *update_preimage
													} else { false }
												), "{:?}", update);
												true
											} else { false }
										},
										// or the channel we'd unblock is already closed,
										BackgroundEvent::ClosedMonitorUpdateRegeneratedOnStartup(
											(funding_txo, _channel_id, monitor_update)
										) => {
											if *funding_txo == next_channel_outpoint {
												assert_eq!(monitor_update.updates.len(), 1);
												assert!(matches!(
													monitor_update.updates[0],
													ChannelMonitorUpdateStep::ChannelForceClosed { .. }
												));
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
								}), "{:?}", *background_events);
							}
							None
						} else if definitely_duplicate {
							if let Some(other_chan) = chan_to_release {
								Some(MonitorUpdateCompletionAction::FreeOtherChannelImmediately {
									downstream_counterparty_node_id: other_chan.0,
									downstream_funding_outpoint: other_chan.1,
									downstream_channel_id: other_chan.2,
									blocking_action: other_chan.3,
								})
							} else { None }
						} else {
							let total_fee_earned_msat = if let Some(forwarded_htlc_value) = forwarded_htlc_value_msat {
								if let Some(claimed_htlc_value) = htlc_claim_value_msat {
									Some(claimed_htlc_value - forwarded_htlc_value)
								} else { None }
							} else { None };
							debug_assert!(skimmed_fee_msat <= total_fee_earned_msat,
								"skimmed_fee_msat must always be included in total_fee_earned_msat");
							Some(MonitorUpdateCompletionAction::EmitEventAndFreeOtherChannel {
								event: events::Event::PaymentForwarded {
									prev_channel_id: Some(prev_channel_id),
									next_channel_id: Some(next_channel_id),
									prev_user_channel_id,
									next_user_channel_id,
									total_fee_earned_msat,
									skimmed_fee_msat,
									claim_from_onchain_tx: from_onchain,
									outbound_amount_forwarded_msat: forwarded_htlc_value_msat,
								},
								downstream_counterparty_and_funding_outpoint: chan_to_release,
							})
						}
					});
				if let Err((pk, err)) = res {
					let result: Result<(), _> = Err(err);
					let _ = handle_error!(self, result, pk);
				}
			},
		}
	}

	/// Gets the node_id held by this ChannelManager
	pub fn get_our_node_id(&self) -> PublicKey {
		self.our_network_pubkey.clone()
	}

	fn handle_monitor_update_completion_actions<I: IntoIterator<Item=MonitorUpdateCompletionAction>>(&self, actions: I) {
		debug_assert_ne!(self.pending_events.held_by_thread(), LockHeldState::HeldByThread);
		debug_assert_ne!(self.claimable_payments.held_by_thread(), LockHeldState::HeldByThread);
		debug_assert_ne!(self.per_peer_state.held_by_thread(), LockHeldState::HeldByThread);

		for action in actions.into_iter() {
			match action {
				MonitorUpdateCompletionAction::PaymentClaimed { payment_hash } => {
					let payment = self.claimable_payments.lock().unwrap().pending_claiming_payments.remove(&payment_hash);
					if let Some(ClaimingPayment {
						amount_msat,
						payment_purpose: purpose,
						receiver_node_id,
						htlcs,
						sender_intended_value: sender_intended_total_msat,
					}) = payment {
						self.pending_events.lock().unwrap().push_back((events::Event::PaymentClaimed {
							payment_hash,
							purpose,
							amount_msat,
							receiver_node_id: Some(receiver_node_id),
							htlcs,
							sender_intended_total_msat,
						}, None));
					}
				},
				MonitorUpdateCompletionAction::EmitEventAndFreeOtherChannel {
					event, downstream_counterparty_and_funding_outpoint
				} => {
					self.pending_events.lock().unwrap().push_back((event, None));
					if let Some((node_id, funding_outpoint, channel_id, blocker)) = downstream_counterparty_and_funding_outpoint {
						self.handle_monitor_update_release(node_id, funding_outpoint, channel_id, Some(blocker));
					}
				},
				MonitorUpdateCompletionAction::FreeOtherChannelImmediately {
					downstream_counterparty_node_id, downstream_funding_outpoint, downstream_channel_id, blocking_action,
				} => {
					self.handle_monitor_update_release(
						downstream_counterparty_node_id,
						downstream_funding_outpoint,
						downstream_channel_id,
						Some(blocking_action),
					);
				},
			}
		}
	}

	/// Handles a channel reentering a functional state, either due to reconnect or a monitor
	/// update completion.
	fn handle_channel_resumption(&self, pending_msg_events: &mut Vec<MessageSendEvent>,
		channel: &mut Channel<SP>, raa: Option<msgs::RevokeAndACK>,
		commitment_update: Option<msgs::CommitmentUpdate>, order: RAACommitmentOrder,
		pending_forwards: Vec<(PendingHTLCInfo, u64)>, pending_update_adds: Vec<msgs::UpdateAddHTLC>,
		funding_broadcastable: Option<Transaction>,
		channel_ready: Option<msgs::ChannelReady>, announcement_sigs: Option<msgs::AnnouncementSignatures>)
	-> (Option<(u64, OutPoint, ChannelId, u128, Vec<(PendingHTLCInfo, u64)>)>, Option<(u64, Vec<msgs::UpdateAddHTLC>)>) {
		let logger = WithChannelContext::from(&self.logger, &channel.context);
		log_trace!(logger, "Handling channel resumption for channel {} with {} RAA, {} commitment update, {} pending forwards, {} pending update_add_htlcs, {}broadcasting funding, {} channel ready, {} announcement",
			&channel.context.channel_id(),
			if raa.is_some() { "an" } else { "no" },
			if commitment_update.is_some() { "a" } else { "no" },
			pending_forwards.len(), pending_update_adds.len(),
			if funding_broadcastable.is_some() { "" } else { "not " },
			if channel_ready.is_some() { "sending" } else { "without" },
			if announcement_sigs.is_some() { "sending" } else { "without" });

		let counterparty_node_id = channel.context.get_counterparty_node_id();
		let short_channel_id = channel.context.get_short_channel_id().unwrap_or(channel.context.outbound_scid_alias());

		let mut htlc_forwards = None;
		if !pending_forwards.is_empty() {
			htlc_forwards = Some((short_channel_id, channel.context.get_funding_txo().unwrap(),
				channel.context.channel_id(), channel.context.get_user_id(), pending_forwards));
		}
		let mut decode_update_add_htlcs = None;
		if !pending_update_adds.is_empty() {
			decode_update_add_htlcs = Some((short_channel_id, pending_update_adds));
		}

		if let Some(msg) = channel_ready {
			send_channel_ready!(self, pending_msg_events, channel, msg);
		}
		if let Some(msg) = announcement_sigs {
			pending_msg_events.push(events::MessageSendEvent::SendAnnouncementSignatures {
				node_id: counterparty_node_id,
				msg,
			});
		}

		macro_rules! handle_cs { () => {
			if let Some(update) = commitment_update {
				pending_msg_events.push(events::MessageSendEvent::UpdateHTLCs {
					node_id: counterparty_node_id,
					updates: update,
				});
			}
		} }
		macro_rules! handle_raa { () => {
			if let Some(revoke_and_ack) = raa {
				pending_msg_events.push(events::MessageSendEvent::SendRevokeAndACK {
					node_id: counterparty_node_id,
					msg: revoke_and_ack,
				});
			}
		} }
		match order {
			RAACommitmentOrder::CommitmentFirst => {
				handle_cs!();
				handle_raa!();
			},
			RAACommitmentOrder::RevokeAndACKFirst => {
				handle_raa!();
				handle_cs!();
			},
		}

		if let Some(tx) = funding_broadcastable {
			log_info!(logger, "Broadcasting funding transaction with txid {}", tx.txid());
			self.tx_broadcaster.broadcast_transactions(&[&tx]);
		}

		{
			let mut pending_events = self.pending_events.lock().unwrap();
			emit_channel_pending_event!(pending_events, channel);
			emit_channel_ready_event!(pending_events, channel);
		}

		(htlc_forwards, decode_update_add_htlcs)
	}

	fn channel_monitor_updated(&self, funding_txo: &OutPoint, channel_id: &ChannelId, highest_applied_update_id: u64, counterparty_node_id: Option<&PublicKey>) {
		debug_assert!(self.total_consistency_lock.try_write().is_err()); // Caller holds read lock

		let counterparty_node_id = match counterparty_node_id {
			Some(cp_id) => cp_id.clone(),
			None => {
				// TODO: Once we can rely on the counterparty_node_id from the
				// monitor event, this and the outpoint_to_peer map should be removed.
				let outpoint_to_peer = self.outpoint_to_peer.lock().unwrap();
				match outpoint_to_peer.get(funding_txo) {
					Some(cp_id) => cp_id.clone(),
					None => return,
				}
			}
		};
		let per_peer_state = self.per_peer_state.read().unwrap();
		let mut peer_state_lock;
		let peer_state_mutex_opt = per_peer_state.get(&counterparty_node_id);
		if peer_state_mutex_opt.is_none() { return }
		peer_state_lock = peer_state_mutex_opt.unwrap().lock().unwrap();
		let peer_state = &mut *peer_state_lock;
		let channel =
			if let Some(ChannelPhase::Funded(chan)) = peer_state.channel_by_id.get_mut(channel_id) {
				chan
			} else {
				let update_actions = peer_state.monitor_update_blocked_actions
					.remove(&channel_id).unwrap_or(Vec::new());
				mem::drop(peer_state_lock);
				mem::drop(per_peer_state);
				self.handle_monitor_update_completion_actions(update_actions);
				return;
			};
		let remaining_in_flight =
			if let Some(pending) = peer_state.in_flight_monitor_updates.get_mut(funding_txo) {
				pending.retain(|upd| upd.update_id > highest_applied_update_id);
				pending.len()
			} else { 0 };
		let logger = WithChannelContext::from(&self.logger, &channel.context);
		log_trace!(logger, "ChannelMonitor updated to {}. Current highest is {}. {} pending in-flight updates.",
			highest_applied_update_id, channel.context.get_latest_monitor_update_id(),
			remaining_in_flight);
		if !channel.is_awaiting_monitor_update() || channel.context.get_latest_monitor_update_id() != highest_applied_update_id {
			return;
		}
		handle_monitor_update_completion!(self, peer_state_lock, peer_state, per_peer_state, channel);
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
	/// [`Event::OpenChannelRequest`]: events::Event::OpenChannelRequest
	/// [`Event::ChannelClosed::user_channel_id`]: events::Event::ChannelClosed::user_channel_id
	pub fn accept_inbound_channel(&self, temporary_channel_id: &ChannelId, counterparty_node_id: &PublicKey, user_channel_id: u128) -> Result<(), APIError> {
		self.do_accept_inbound_channel(temporary_channel_id, counterparty_node_id, false, user_channel_id)
	}

	/// Accepts a request to open a channel after a [`events::Event::OpenChannelRequest`], treating
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
	pub fn accept_inbound_channel_from_trusted_peer_0conf(&self, temporary_channel_id: &ChannelId, counterparty_node_id: &PublicKey, user_channel_id: u128) -> Result<(), APIError> {
		self.do_accept_inbound_channel(temporary_channel_id, counterparty_node_id, true, user_channel_id)
	}

	fn do_accept_inbound_channel(&self, temporary_channel_id: &ChannelId, counterparty_node_id: &PublicKey, accept_0conf: bool, user_channel_id: u128) -> Result<(), APIError> {

		let logger = WithContext::from(&self.logger, Some(*counterparty_node_id), Some(*temporary_channel_id));
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(self);

		let peers_without_funded_channels =
			self.peers_without_funded_channels(|peer| { peer.total_channel_count() > 0 });
		let per_peer_state = self.per_peer_state.read().unwrap();
		let peer_state_mutex = per_peer_state.get(counterparty_node_id)
		.ok_or_else(|| {
			let err_str = format!("Can't find a peer matching the passed counterparty node_id {}", counterparty_node_id);
			log_error!(logger, "{}", err_str);

			APIError::ChannelUnavailable { err: err_str }
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
				InboundV1Channel::new(&self.fee_estimator, &self.entropy_source, &self.signer_provider,
					counterparty_node_id.clone(), &self.channel_type_features(), &peer_state.latest_features,
					&unaccepted_channel.open_channel_msg, user_channel_id, &self.default_configuration, best_block_height,
					&self.logger, accept_0conf).map_err(|err| MsgHandleErrInternal::from_chan_no_close(err, *temporary_channel_id))
			},
			_ => {
				let err_str = "No such channel awaiting to be accepted.".to_owned();
				log_error!(logger, "{}", err_str);

				return Err(APIError::APIMisuseError { err: err_str });
			}
		};

		match res {
			Err(err) => {
				mem::drop(peer_state_lock);
				mem::drop(per_peer_state);
				match handle_error!(self, Result::<(), MsgHandleErrInternal>::Err(err), *counterparty_node_id) {
					Ok(_) => unreachable!("`handle_error` only returns Err as we've passed in an Err"),
					Err(e) => {
						return Err(APIError::ChannelUnavailable { err: e.err });
					},
				}
			}
			Ok(mut channel) => {
				if accept_0conf {
					// This should have been correctly configured by the call to InboundV1Channel::new.
					debug_assert!(channel.context.minimum_depth().unwrap() == 0);
				} else if channel.context.get_channel_type().requires_zero_conf() {
					let send_msg_err_event = events::MessageSendEvent::HandleError {
						node_id: channel.context.get_counterparty_node_id(),
						action: msgs::ErrorAction::SendErrorMessage{
							msg: msgs::ErrorMessage { channel_id: temporary_channel_id.clone(), data: "No zero confirmation channels accepted".to_owned(), }
						}
					};
					peer_state.pending_msg_events.push(send_msg_err_event);
					let err_str = "Please use accept_inbound_channel_from_trusted_peer_0conf to accept channels with zero confirmations.".to_owned();
					log_error!(logger, "{}", err_str);

					return Err(APIError::APIMisuseError { err: err_str });
				} else {
					// If this peer already has some channels, a new channel won't increase our number of peers
					// with unfunded channels, so as long as we aren't over the maximum number of unfunded
					// channels per-peer we can accept channels from a peer with existing ones.
					if is_only_peer_channel && peers_without_funded_channels >= MAX_UNFUNDED_CHANNEL_PEERS {
						let send_msg_err_event = events::MessageSendEvent::HandleError {
							node_id: channel.context.get_counterparty_node_id(),
							action: msgs::ErrorAction::SendErrorMessage{
								msg: msgs::ErrorMessage { channel_id: temporary_channel_id.clone(), data: "Have too many peers with unfunded channels, not accepting new ones".to_owned(), }
							}
						};
						peer_state.pending_msg_events.push(send_msg_err_event);
						let err_str = "Too many peers with unfunded channels, refusing to accept new ones".to_owned();
						log_error!(logger, "{}", err_str);

						return Err(APIError::APIMisuseError { err: err_str });
					}
				}

				// Now that we know we have a channel, assign an outbound SCID alias.
				let outbound_scid_alias = self.create_and_insert_outbound_scid_alias();
				channel.context.set_outbound_scid_alias(outbound_scid_alias);

				peer_state.pending_msg_events.push(events::MessageSendEvent::SendAcceptChannel {
					node_id: channel.context.get_counterparty_node_id(),
					msg: channel.accept_inbound_channel(),
				});

				peer_state.channel_by_id.insert(temporary_channel_id.clone(), ChannelPhase::UnfundedInboundV1(channel));

				Ok(())
			},
		}
	}

	/// Gets the number of peers which match the given filter and do not have any funded, outbound,
	/// or 0-conf channels.
	///
	/// The filter is called for each peer and provided with the number of unfunded, inbound, and
	/// non-0-conf channels we have with the peer.
	fn peers_without_funded_channels<Filter>(&self, maybe_count_peer: Filter) -> usize
	where Filter: Fn(&PeerState<SP>) -> bool {
		let mut peers_without_funded_channels = 0;
		let best_block_height = self.best_block.read().unwrap().height;
		{
			let peer_state_lock = self.per_peer_state.read().unwrap();
			for (_, peer_mtx) in peer_state_lock.iter() {
				let peer = peer_mtx.lock().unwrap();
				if !maybe_count_peer(&*peer) { continue; }
				let num_unfunded_channels = Self::unfunded_channel_count(&peer, best_block_height);
				if num_unfunded_channels == peer.total_channel_count() {
					peers_without_funded_channels += 1;
				}
			}
		}
		return peers_without_funded_channels;
	}

	fn unfunded_channel_count(
		peer: &PeerState<SP>, best_block_height: u32
	) -> usize {
		let mut num_unfunded_channels = 0;
		for (_, phase) in peer.channel_by_id.iter() {
			match phase {
				ChannelPhase::Funded(chan) => {
					// This covers non-zero-conf inbound `Channel`s that we are currently monitoring, but those
					// which have not yet had any confirmations on-chain.
					if !chan.context.is_outbound() && chan.context.minimum_depth().unwrap_or(1) != 0 &&
						chan.context.get_funding_tx_confirmations(best_block_height) == 0
					{
						num_unfunded_channels += 1;
					}
				},
				ChannelPhase::UnfundedInboundV1(chan) => {
					if chan.context.minimum_depth().unwrap_or(1) != 0 {
						num_unfunded_channels += 1;
					}
				},
				// TODO(dual_funding): Combine this match arm with above once #[cfg(dual_funding)] is removed.
				#[cfg(dual_funding)]
				ChannelPhase::UnfundedInboundV2(chan) => {
					// Only inbound V2 channels that are not 0conf and that we do not contribute to will be
					// included in the unfunded count.
					if chan.context.minimum_depth().unwrap_or(1) != 0 &&
						chan.dual_funding_context.our_funding_satoshis == 0 {
						num_unfunded_channels += 1;
					}
				},
				ChannelPhase::UnfundedOutboundV1(_) => {
					// Outbound channels don't contribute to the unfunded count in the DoS context.
					continue;
				},
				// TODO(dual_funding): Combine this match arm with above once #[cfg(dual_funding)] is removed.
				#[cfg(dual_funding)]
				ChannelPhase::UnfundedOutboundV2(_) => {
					// Outbound channels don't contribute to the unfunded count in the DoS context.
					continue;
				}
			}
		}
		num_unfunded_channels + peer.inbound_channel_request_by_id.len()
	}

	fn internal_open_channel(&self, counterparty_node_id: &PublicKey, msg: &msgs::OpenChannel) -> Result<(), MsgHandleErrInternal> {
		// Note that the ChannelManager is NOT re-persisted on disk after this, so any changes are
		// likely to be lost on restart!
		if msg.common_fields.chain_hash != self.chain_hash {
			return Err(MsgHandleErrInternal::send_err_msg_no_close("Unknown genesis block hash".to_owned(),
				 msg.common_fields.temporary_channel_id.clone()));
		}

		if !self.default_configuration.accept_inbound_channels {
			return Err(MsgHandleErrInternal::send_err_msg_no_close("No inbound channels accepted".to_owned(),
				 msg.common_fields.temporary_channel_id.clone()));
		}

		// Get the number of peers with channels, but without funded ones. We don't care too much
		// about peers that never open a channel, so we filter by peers that have at least one
		// channel, and then limit the number of those with unfunded channels.
		let channeled_peers_without_funding =
			self.peers_without_funded_channels(|node| node.total_channel_count() > 0);

		let per_peer_state = self.per_peer_state.read().unwrap();
		let peer_state_mutex = per_peer_state.get(counterparty_node_id)
		    .ok_or_else(|| {
				debug_assert!(false);
				MsgHandleErrInternal::send_err_msg_no_close(
					format!("Can't find a peer matching the passed counterparty node_id {}", counterparty_node_id),
					msg.common_fields.temporary_channel_id.clone())
			})?;
		let mut peer_state_lock = peer_state_mutex.lock().unwrap();
		let peer_state = &mut *peer_state_lock;

		// If this peer already has some channels, a new channel won't increase our number of peers
		// with unfunded channels, so as long as we aren't over the maximum number of unfunded
		// channels per-peer we can accept channels from a peer with existing ones.
		if peer_state.total_channel_count() == 0 &&
			channeled_peers_without_funding >= MAX_UNFUNDED_CHANNEL_PEERS &&
			!self.default_configuration.manually_accept_inbound_channels
		{
			return Err(MsgHandleErrInternal::send_err_msg_no_close(
				"Have too many peers with unfunded channels, not accepting new ones".to_owned(),
				msg.common_fields.temporary_channel_id.clone()));
		}

		let best_block_height = self.best_block.read().unwrap().height;
		if Self::unfunded_channel_count(peer_state, best_block_height) >= MAX_UNFUNDED_CHANS_PER_PEER {
			return Err(MsgHandleErrInternal::send_err_msg_no_close(
				format!("Refusing more than {} unfunded channels.", MAX_UNFUNDED_CHANS_PER_PEER),
				msg.common_fields.temporary_channel_id.clone()));
		}

		let channel_id = msg.common_fields.temporary_channel_id;
		let channel_exists = peer_state.has_channel(&channel_id);
		if channel_exists {
			return Err(MsgHandleErrInternal::send_err_msg_no_close(
				"temporary_channel_id collision for the same peer!".to_owned(),
				msg.common_fields.temporary_channel_id.clone()));
		}

		// If we're doing manual acceptance checks on the channel, then defer creation until we're sure we want to accept.
		if self.default_configuration.manually_accept_inbound_channels {
			let channel_type = channel::channel_type_from_open_channel(
					&msg.common_fields, &peer_state.latest_features, &self.channel_type_features()
				).map_err(|e|
					MsgHandleErrInternal::from_chan_no_close(e, msg.common_fields.temporary_channel_id)
				)?;
			let mut pending_events = self.pending_events.lock().unwrap();
			pending_events.push_back((events::Event::OpenChannelRequest {
				temporary_channel_id: msg.common_fields.temporary_channel_id.clone(),
				counterparty_node_id: counterparty_node_id.clone(),
				funding_satoshis: msg.common_fields.funding_satoshis,
				push_msat: msg.push_msat,
				channel_type,
			}, None));
			peer_state.inbound_channel_request_by_id.insert(channel_id, InboundChannelRequest {
				open_channel_msg: msg.clone(),
				ticks_remaining: UNACCEPTED_INBOUND_CHANNEL_AGE_LIMIT_TICKS,
			});
			return Ok(());
		}

		// Otherwise create the channel right now.
		let mut random_bytes = [0u8; 16];
		random_bytes.copy_from_slice(&self.entropy_source.get_secure_random_bytes()[..16]);
		let user_channel_id = u128::from_be_bytes(random_bytes);
		let mut channel = match InboundV1Channel::new(&self.fee_estimator, &self.entropy_source, &self.signer_provider,
			counterparty_node_id.clone(), &self.channel_type_features(), &peer_state.latest_features, msg, user_channel_id,
			&self.default_configuration, best_block_height, &self.logger, /*is_0conf=*/false)
		{
			Err(e) => {
				return Err(MsgHandleErrInternal::from_chan_no_close(e, msg.common_fields.temporary_channel_id));
			},
			Ok(res) => res
		};

		let channel_type = channel.context.get_channel_type();
		if channel_type.requires_zero_conf() {
			return Err(MsgHandleErrInternal::send_err_msg_no_close(
				"No zero confirmation channels accepted".to_owned(),
				msg.common_fields.temporary_channel_id.clone()));
		}
		if channel_type.requires_anchors_zero_fee_htlc_tx() {
			return Err(MsgHandleErrInternal::send_err_msg_no_close(
				"No channels with anchor outputs accepted".to_owned(),
				msg.common_fields.temporary_channel_id.clone()));
		}

		let outbound_scid_alias = self.create_and_insert_outbound_scid_alias();
		channel.context.set_outbound_scid_alias(outbound_scid_alias);

		peer_state.pending_msg_events.push(events::MessageSendEvent::SendAcceptChannel {
			node_id: counterparty_node_id.clone(),
			msg: channel.accept_inbound_channel(),
		});
		peer_state.channel_by_id.insert(channel_id, ChannelPhase::UnfundedInboundV1(channel));
		Ok(())
	}

	fn internal_accept_channel(&self, counterparty_node_id: &PublicKey, msg: &msgs::AcceptChannel) -> Result<(), MsgHandleErrInternal> {
		// Note that the ChannelManager is NOT re-persisted on disk after this, so any changes are
		// likely to be lost on restart!
		let (value, output_script, user_id) = {
			let per_peer_state = self.per_peer_state.read().unwrap();
			let peer_state_mutex = per_peer_state.get(counterparty_node_id)
				.ok_or_else(|| {
					debug_assert!(false);
					MsgHandleErrInternal::send_err_msg_no_close(format!("Can't find a peer matching the passed counterparty node_id {}", counterparty_node_id), msg.common_fields.temporary_channel_id)
				})?;
			let mut peer_state_lock = peer_state_mutex.lock().unwrap();
			let peer_state = &mut *peer_state_lock;
			match peer_state.channel_by_id.entry(msg.common_fields.temporary_channel_id) {
				hash_map::Entry::Occupied(mut phase) => {
					match phase.get_mut() {
						ChannelPhase::UnfundedOutboundV1(chan) => {
							try_chan_phase_entry!(self, chan.accept_channel(&msg, &self.default_configuration.channel_handshake_limits, &peer_state.latest_features), phase);
							(chan.context.get_value_satoshis(), chan.context.get_funding_redeemscript().to_v0_p2wsh(), chan.context.get_user_id())
						},
						_ => {
							return Err(MsgHandleErrInternal::send_err_msg_no_close(format!("Got an unexpected accept_channel message from peer with counterparty_node_id {}", counterparty_node_id), msg.common_fields.temporary_channel_id));
						}
					}
				},
				hash_map::Entry::Vacant(_) => return Err(MsgHandleErrInternal::send_err_msg_no_close(format!("Got a message for a channel from the wrong node! No such channel for the passed counterparty_node_id {}", counterparty_node_id), msg.common_fields.temporary_channel_id))
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

	fn internal_funding_created(&self, counterparty_node_id: &PublicKey, msg: &msgs::FundingCreated) -> Result<(), MsgHandleErrInternal> {
		let best_block = *self.best_block.read().unwrap();

		let per_peer_state = self.per_peer_state.read().unwrap();
		let peer_state_mutex = per_peer_state.get(counterparty_node_id)
			.ok_or_else(|| {
				debug_assert!(false);
				MsgHandleErrInternal::send_err_msg_no_close(format!("Can't find a peer matching the passed counterparty node_id {}", counterparty_node_id), msg.temporary_channel_id)
			})?;

		let mut peer_state_lock = peer_state_mutex.lock().unwrap();
		let peer_state = &mut *peer_state_lock;
		let (mut chan, funding_msg_opt, monitor) =
			match peer_state.channel_by_id.remove(&msg.temporary_channel_id) {
				Some(ChannelPhase::UnfundedInboundV1(inbound_chan)) => {
					let logger = WithChannelContext::from(&self.logger, &inbound_chan.context);
					match inbound_chan.funding_created(msg, best_block, &self.signer_provider, &&logger) {
						Ok(res) => res,
						Err((inbound_chan, err)) => {
							// We've already removed this inbound channel from the map in `PeerState`
							// above so at this point we just need to clean up any lingering entries
							// concerning this channel as it is safe to do so.
							debug_assert!(matches!(err, ChannelError::Close(_)));
							// Really we should be returning the channel_id the peer expects based
							// on their funding info here, but they're horribly confused anyway, so
							// there's not a lot we can do to save them.
							return Err(convert_chan_phase_err!(self, err, &mut ChannelPhase::UnfundedInboundV1(inbound_chan), &msg.temporary_channel_id).1);
						},
					}
				},
				Some(mut phase) => {
					let err_msg = format!("Got an unexpected funding_created message from peer with counterparty_node_id {}", counterparty_node_id);
					let err = ChannelError::Close(err_msg);
					return Err(convert_chan_phase_err!(self, err, &mut phase, &msg.temporary_channel_id).1);
				},
				None => return Err(MsgHandleErrInternal::send_err_msg_no_close(format!("Got a message for a channel from the wrong node! No such channel for the passed counterparty_node_id {}", counterparty_node_id), msg.temporary_channel_id))
			};

		let funded_channel_id = chan.context.channel_id();

		macro_rules! fail_chan { ($err: expr) => { {
			// Note that at this point we've filled in the funding outpoint on our
			// channel, but its actually in conflict with another channel. Thus, if
			// we call `convert_chan_phase_err` immediately (thus calling
			// `update_maps_on_chan_removal`), we'll remove the existing channel
			// from `outpoint_to_peer`. Thus, we must first unset the funding outpoint
			// on the channel.
			let err = ChannelError::Close($err.to_owned());
			chan.unset_funding_info(msg.temporary_channel_id);
			return Err(convert_chan_phase_err!(self, err, chan, &funded_channel_id, UNFUNDED_CHANNEL).1);
		} } }

		match peer_state.channel_by_id.entry(funded_channel_id) {
			hash_map::Entry::Occupied(_) => {
				fail_chan!("Already had channel with the new channel_id");
			},
			hash_map::Entry::Vacant(e) => {
				let mut outpoint_to_peer_lock = self.outpoint_to_peer.lock().unwrap();
				match outpoint_to_peer_lock.entry(monitor.get_funding_txo().0) {
					hash_map::Entry::Occupied(_) => {
						fail_chan!("The funding_created message had the same funding_txid as an existing channel - funding is not possible");
					},
					hash_map::Entry::Vacant(i_e) => {
						let monitor_res = self.chain_monitor.watch_channel(monitor.get_funding_txo().0, monitor);
						if let Ok(persist_state) = monitor_res {
							i_e.insert(chan.context.get_counterparty_node_id());
							mem::drop(outpoint_to_peer_lock);

							// There's no problem signing a counterparty's funding transaction if our monitor
							// hasn't persisted to disk yet - we can't lose money on a transaction that we haven't
							// accepted payment from yet. We do, however, need to wait to send our channel_ready
							// until we have persisted our monitor.
							if let Some(msg) = funding_msg_opt {
								peer_state.pending_msg_events.push(events::MessageSendEvent::SendFundingSigned {
									node_id: counterparty_node_id.clone(),
									msg,
								});
							}

							if let ChannelPhase::Funded(chan) = e.insert(ChannelPhase::Funded(chan)) {
								handle_new_monitor_update!(self, persist_state, peer_state_lock, peer_state,
									per_peer_state, chan, INITIAL_MONITOR);
							} else {
								unreachable!("This must be a funded channel as we just inserted it.");
							}
							Ok(())
						} else {
							let logger = WithChannelContext::from(&self.logger, &chan.context);
							log_error!(logger, "Persisting initial ChannelMonitor failed, implying the funding outpoint was duplicated");
							fail_chan!("Duplicate funding outpoint");
						}
					}
				}
			}
		}
	}

	fn internal_funding_signed(&self, counterparty_node_id: &PublicKey, msg: &msgs::FundingSigned) -> Result<(), MsgHandleErrInternal> {
		let best_block = *self.best_block.read().unwrap();
		let per_peer_state = self.per_peer_state.read().unwrap();
		let peer_state_mutex = per_peer_state.get(counterparty_node_id)
			.ok_or_else(|| {
				debug_assert!(false);
				MsgHandleErrInternal::send_err_msg_no_close(format!("Can't find a peer matching the passed counterparty node_id {}", counterparty_node_id), msg.channel_id)
			})?;

		let mut peer_state_lock = peer_state_mutex.lock().unwrap();
		let peer_state = &mut *peer_state_lock;
		match peer_state.channel_by_id.entry(msg.channel_id) {
			hash_map::Entry::Occupied(chan_phase_entry) => {
				if matches!(chan_phase_entry.get(), ChannelPhase::UnfundedOutboundV1(_)) {
					let chan = if let ChannelPhase::UnfundedOutboundV1(chan) = chan_phase_entry.remove() { chan } else { unreachable!() };
					let logger = WithContext::from(
						&self.logger,
						Some(chan.context.get_counterparty_node_id()),
						Some(chan.context.channel_id())
					);
					let res =
						chan.funding_signed(&msg, best_block, &self.signer_provider, &&logger);
					match res {
						Ok((mut chan, monitor)) => {
							if let Ok(persist_status) = self.chain_monitor.watch_channel(chan.context.get_funding_txo().unwrap(), monitor) {
								// We really should be able to insert here without doing a second
								// lookup, but sadly rust stdlib doesn't currently allow keeping
								// the original Entry around with the value removed.
								let mut chan = peer_state.channel_by_id.entry(msg.channel_id).or_insert(ChannelPhase::Funded(chan));
								if let ChannelPhase::Funded(ref mut chan) = &mut chan {
									handle_new_monitor_update!(self, persist_status, peer_state_lock, peer_state, per_peer_state, chan, INITIAL_MONITOR);
								} else { unreachable!(); }
								Ok(())
							} else {
								let e = ChannelError::Close("Channel funding outpoint was a duplicate".to_owned());
								// We weren't able to watch the channel to begin with, so no
								// updates should be made on it. Previously, full_stack_target
								// found an (unreachable) panic when the monitor update contained
								// within `shutdown_finish` was applied.
								chan.unset_funding_info(msg.channel_id);
								return Err(convert_chan_phase_err!(self, e, &mut ChannelPhase::Funded(chan), &msg.channel_id).1);
							}
						},
						Err((chan, e)) => {
							debug_assert!(matches!(e, ChannelError::Close(_)),
								"We don't have a channel anymore, so the error better have expected close");
							// We've already removed this outbound channel from the map in
							// `PeerState` above so at this point we just need to clean up any
							// lingering entries concerning this channel as it is safe to do so.
							return Err(convert_chan_phase_err!(self, e, &mut ChannelPhase::UnfundedOutboundV1(chan), &msg.channel_id).1);
						}
					}
				} else {
					return Err(MsgHandleErrInternal::send_err_msg_no_close("Failed to find corresponding channel".to_owned(), msg.channel_id));
				}
			},
			hash_map::Entry::Vacant(_) => return Err(MsgHandleErrInternal::send_err_msg_no_close("Failed to find corresponding channel".to_owned(), msg.channel_id))
		}
	}

	fn internal_channel_ready(&self, counterparty_node_id: &PublicKey, msg: &msgs::ChannelReady) -> Result<(), MsgHandleErrInternal> {
		// Note that the ChannelManager is NOT re-persisted on disk after this (unless we error
		// closing a channel), so any changes are likely to be lost on restart!
		let per_peer_state = self.per_peer_state.read().unwrap();
		let peer_state_mutex = per_peer_state.get(counterparty_node_id)
			.ok_or_else(|| {
				debug_assert!(false);
				MsgHandleErrInternal::send_err_msg_no_close(format!("Can't find a peer matching the passed counterparty node_id {}", counterparty_node_id), msg.channel_id)
			})?;
		let mut peer_state_lock = peer_state_mutex.lock().unwrap();
		let peer_state = &mut *peer_state_lock;
		match peer_state.channel_by_id.entry(msg.channel_id) {
			hash_map::Entry::Occupied(mut chan_phase_entry) => {
				if let ChannelPhase::Funded(chan) = chan_phase_entry.get_mut() {
					let logger = WithChannelContext::from(&self.logger, &chan.context);
					let announcement_sigs_opt = try_chan_phase_entry!(self, chan.channel_ready(&msg, &self.node_signer,
						self.chain_hash, &self.default_configuration, &self.best_block.read().unwrap(), &&logger), chan_phase_entry);
					if let Some(announcement_sigs) = announcement_sigs_opt {
						log_trace!(logger, "Sending announcement_signatures for channel {}", chan.context.channel_id());
						peer_state.pending_msg_events.push(events::MessageSendEvent::SendAnnouncementSignatures {
							node_id: counterparty_node_id.clone(),
							msg: announcement_sigs,
						});
					} else if chan.context.is_usable() {
						// If we're sending an announcement_signatures, we'll send the (public)
						// channel_update after sending a channel_announcement when we receive our
						// counterparty's announcement_signatures. Thus, we only bother to send a
						// channel_update here if the channel is not public, i.e. we're not sending an
						// announcement_signatures.
						log_trace!(logger, "Sending private initial channel_update for our counterparty on channel {}", chan.context.channel_id());
						if let Ok(msg) = self.get_channel_update_for_unicast(chan) {
							peer_state.pending_msg_events.push(events::MessageSendEvent::SendChannelUpdate {
								node_id: counterparty_node_id.clone(),
								msg,
							});
						}
					}

					{
						let mut pending_events = self.pending_events.lock().unwrap();
						emit_channel_ready_event!(pending_events, chan);
					}

					Ok(())
				} else {
					try_chan_phase_entry!(self, Err(ChannelError::Close(
						"Got a channel_ready message for an unfunded channel!".into())), chan_phase_entry)
				}
			},
			hash_map::Entry::Vacant(_) => {
				Err(MsgHandleErrInternal::send_err_msg_no_close(format!("Got a message for a channel from the wrong node! No such channel for the passed counterparty_node_id {}", counterparty_node_id), msg.channel_id))
			}
		}
	}

	fn internal_shutdown(&self, counterparty_node_id: &PublicKey, msg: &msgs::Shutdown) -> Result<(), MsgHandleErrInternal> {
		let mut dropped_htlcs: Vec<(HTLCSource, PaymentHash)> = Vec::new();
		let mut finish_shutdown = None;
		{
			let per_peer_state = self.per_peer_state.read().unwrap();
			let peer_state_mutex = per_peer_state.get(counterparty_node_id)
				.ok_or_else(|| {
					debug_assert!(false);
					MsgHandleErrInternal::send_err_msg_no_close(format!("Can't find a peer matching the passed counterparty node_id {}", counterparty_node_id), msg.channel_id)
				})?;
			let mut peer_state_lock = peer_state_mutex.lock().unwrap();
			let peer_state = &mut *peer_state_lock;
			if let hash_map::Entry::Occupied(mut chan_phase_entry) = peer_state.channel_by_id.entry(msg.channel_id.clone()) {
				let phase = chan_phase_entry.get_mut();
				match phase {
					ChannelPhase::Funded(chan) => {
						if !chan.received_shutdown() {
							let logger = WithChannelContext::from(&self.logger, &chan.context);
							log_info!(logger, "Received a shutdown message from our counterparty for channel {}{}.",
								msg.channel_id,
								if chan.sent_shutdown() { " after we initiated shutdown" } else { "" });
						}

						let funding_txo_opt = chan.context.get_funding_txo();
						let (shutdown, monitor_update_opt, htlcs) = try_chan_phase_entry!(self,
							chan.shutdown(&self.signer_provider, &peer_state.latest_features, &msg), chan_phase_entry);
						dropped_htlcs = htlcs;

						if let Some(msg) = shutdown {
							// We can send the `shutdown` message before updating the `ChannelMonitor`
							// here as we don't need the monitor update to complete until we send a
							// `shutdown_signed`, which we'll delay if we're pending a monitor update.
							peer_state.pending_msg_events.push(events::MessageSendEvent::SendShutdown {
								node_id: *counterparty_node_id,
								msg,
							});
						}
						// Update the monitor with the shutdown script if necessary.
						if let Some(monitor_update) = monitor_update_opt {
							handle_new_monitor_update!(self, funding_txo_opt.unwrap(), monitor_update,
								peer_state_lock, peer_state, per_peer_state, chan);
						}
					},
					ChannelPhase::UnfundedInboundV1(_) | ChannelPhase::UnfundedOutboundV1(_) => {
						let context = phase.context_mut();
						let logger = WithChannelContext::from(&self.logger, context);
						log_error!(logger, "Immediately closing unfunded channel {} as peer asked to cooperatively shut it down (which is unnecessary)", &msg.channel_id);
						let mut chan = remove_channel_phase!(self, chan_phase_entry);
						finish_shutdown = Some(chan.context_mut().force_shutdown(false, ClosureReason::CounterpartyCoopClosedUnfundedChannel));
					},
					// TODO(dual_funding): Combine this match arm with above.
					#[cfg(dual_funding)]
					ChannelPhase::UnfundedInboundV2(_) | ChannelPhase::UnfundedOutboundV2(_) => {
						let context = phase.context_mut();
						log_error!(self.logger, "Immediately closing unfunded channel {} as peer asked to cooperatively shut it down (which is unnecessary)", &msg.channel_id);
						let mut chan = remove_channel_phase!(self, chan_phase_entry);
						finish_shutdown = Some(chan.context_mut().force_shutdown(false, ClosureReason::CounterpartyCoopClosedUnfundedChannel));
					},
				}
			} else {
				return Err(MsgHandleErrInternal::send_err_msg_no_close(format!("Got a message for a channel from the wrong node! No such channel for the passed counterparty_node_id {}", counterparty_node_id), msg.channel_id))
			}
		}
		for htlc_source in dropped_htlcs.drain(..) {
			let receiver = HTLCDestination::NextHopChannel { node_id: Some(counterparty_node_id.clone()), channel_id: msg.channel_id };
			let reason = HTLCFailReason::from_failure_code(0x4000 | 8);
			self.fail_htlc_backwards_internal(&htlc_source.0, &htlc_source.1, &reason, receiver);
		}
		if let Some(shutdown_res) = finish_shutdown {
			self.finish_close_channel(shutdown_res);
		}

		Ok(())
	}

	fn internal_closing_signed(&self, counterparty_node_id: &PublicKey, msg: &msgs::ClosingSigned) -> Result<(), MsgHandleErrInternal> {
		let per_peer_state = self.per_peer_state.read().unwrap();
		let peer_state_mutex = per_peer_state.get(counterparty_node_id)
			.ok_or_else(|| {
				debug_assert!(false);
				MsgHandleErrInternal::send_err_msg_no_close(format!("Can't find a peer matching the passed counterparty node_id {}", counterparty_node_id), msg.channel_id)
			})?;
		let (tx, chan_option, shutdown_result) = {
			let mut peer_state_lock = peer_state_mutex.lock().unwrap();
			let peer_state = &mut *peer_state_lock;
			match peer_state.channel_by_id.entry(msg.channel_id.clone()) {
				hash_map::Entry::Occupied(mut chan_phase_entry) => {
					if let ChannelPhase::Funded(chan) = chan_phase_entry.get_mut() {
						let (closing_signed, tx, shutdown_result) = try_chan_phase_entry!(self, chan.closing_signed(&self.fee_estimator, &msg), chan_phase_entry);
						debug_assert_eq!(shutdown_result.is_some(), chan.is_shutdown());
						if let Some(msg) = closing_signed {
							peer_state.pending_msg_events.push(events::MessageSendEvent::SendClosingSigned {
								node_id: counterparty_node_id.clone(),
								msg,
							});
						}
						if tx.is_some() {
							// We're done with this channel, we've got a signed closing transaction and
							// will send the closing_signed back to the remote peer upon return. This
							// also implies there are no pending HTLCs left on the channel, so we can
							// fully delete it from tracking (the channel monitor is still around to
							// watch for old state broadcasts)!
							(tx, Some(remove_channel_phase!(self, chan_phase_entry)), shutdown_result)
						} else { (tx, None, shutdown_result) }
					} else {
						return try_chan_phase_entry!(self, Err(ChannelError::Close(
							"Got a closing_signed message for an unfunded channel!".into())), chan_phase_entry);
					}
				},
				hash_map::Entry::Vacant(_) => return Err(MsgHandleErrInternal::send_err_msg_no_close(format!("Got a message for a channel from the wrong node! No such channel for the passed counterparty_node_id {}", counterparty_node_id), msg.channel_id))
			}
		};
		if let Some(broadcast_tx) = tx {
			let channel_id = chan_option.as_ref().map(|channel| channel.context().channel_id());
			log_info!(WithContext::from(&self.logger, Some(*counterparty_node_id), channel_id), "Broadcasting {}", log_tx!(broadcast_tx));
			self.tx_broadcaster.broadcast_transactions(&[&broadcast_tx]);
		}
		if let Some(ChannelPhase::Funded(chan)) = chan_option {
			if let Ok(update) = self.get_channel_update_for_broadcast(&chan) {
				let mut pending_broadcast_messages = self.pending_broadcast_messages.lock().unwrap();
				pending_broadcast_messages.push(events::MessageSendEvent::BroadcastChannelUpdate {
					msg: update
				});
			}
		}
		mem::drop(per_peer_state);
		if let Some(shutdown_result) = shutdown_result {
			self.finish_close_channel(shutdown_result);
		}
		Ok(())
	}

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

		let decoded_hop_res = self.decode_update_add_htlc_onion(msg, counterparty_node_id);
		let per_peer_state = self.per_peer_state.read().unwrap();
		let peer_state_mutex = per_peer_state.get(counterparty_node_id)
			.ok_or_else(|| {
				debug_assert!(false);
				MsgHandleErrInternal::send_err_msg_no_close(format!("Can't find a peer matching the passed counterparty node_id {}", counterparty_node_id), msg.channel_id)
			})?;
		let mut peer_state_lock = peer_state_mutex.lock().unwrap();
		let peer_state = &mut *peer_state_lock;
		match peer_state.channel_by_id.entry(msg.channel_id) {
			hash_map::Entry::Occupied(mut chan_phase_entry) => {
				if let ChannelPhase::Funded(chan) = chan_phase_entry.get_mut() {
					let mut pending_forward_info = match decoded_hop_res {
						Ok((next_hop, shared_secret, next_packet_pk_opt)) =>
							self.construct_pending_htlc_status(
								msg, counterparty_node_id, shared_secret, next_hop,
								chan.context.config().accept_underpaying_htlcs, next_packet_pk_opt,
							),
						Err(e) => PendingHTLCStatus::Fail(e)
					};
					let logger = WithChannelContext::from(&self.logger, &chan.context);
					// If the update_add is completely bogus, the call will Err and we will close,
					// but if we've sent a shutdown and they haven't acknowledged it yet, we just
					// want to reject the new HTLC and fail it backwards instead of forwarding.
					if let Err((_, error_code)) = chan.can_accept_incoming_htlc(&msg, &self.fee_estimator, &logger) {
						if msg.blinding_point.is_some() {
							pending_forward_info = PendingHTLCStatus::Fail(HTLCFailureMsg::Malformed(
								msgs::UpdateFailMalformedHTLC {
									channel_id: msg.channel_id,
									htlc_id: msg.htlc_id,
									sha256_of_onion: [0; 32],
									failure_code: INVALID_ONION_BLINDING,
								}
							))
						} else {
							match pending_forward_info {
								PendingHTLCStatus::Forward(PendingHTLCInfo {
									ref incoming_shared_secret, ref routing, ..
								}) => {
									let reason = if routing.blinded_failure().is_some() {
										HTLCFailReason::reason(INVALID_ONION_BLINDING, vec![0; 32])
									} else if (error_code & 0x1000) != 0 {
										let (real_code, error_data) = self.get_htlc_inbound_temp_fail_err_and_data(error_code, chan);
										HTLCFailReason::reason(real_code, error_data)
									} else {
										HTLCFailReason::from_failure_code(error_code)
									}.get_encrypted_failure_packet(incoming_shared_secret, &None);
									let msg = msgs::UpdateFailHTLC {
										channel_id: msg.channel_id,
										htlc_id: msg.htlc_id,
										reason
									};
									pending_forward_info = PendingHTLCStatus::Fail(HTLCFailureMsg::Relay(msg));
								},
								_ => {},
							}
						}
					}
					try_chan_phase_entry!(self, chan.update_add_htlc(&msg, pending_forward_info), chan_phase_entry);
				} else {
					return try_chan_phase_entry!(self, Err(ChannelError::Close(
						"Got an update_add_htlc message for an unfunded channel!".into())), chan_phase_entry);
				}
			},
			hash_map::Entry::Vacant(_) => return Err(MsgHandleErrInternal::send_err_msg_no_close(format!("Got a message for a channel from the wrong node! No such channel for the passed counterparty_node_id {}", counterparty_node_id), msg.channel_id))
		}
		Ok(())
	}

	fn internal_update_fulfill_htlc(&self, counterparty_node_id: &PublicKey, msg: &msgs::UpdateFulfillHTLC) -> Result<(), MsgHandleErrInternal> {
		let funding_txo;
		let next_user_channel_id;
		let (htlc_source, forwarded_htlc_value, skimmed_fee_msat) = {
			let per_peer_state = self.per_peer_state.read().unwrap();
			let peer_state_mutex = per_peer_state.get(counterparty_node_id)
				.ok_or_else(|| {
					debug_assert!(false);
					MsgHandleErrInternal::send_err_msg_no_close(format!("Can't find a peer matching the passed counterparty node_id {}", counterparty_node_id), msg.channel_id)
				})?;
			let mut peer_state_lock = peer_state_mutex.lock().unwrap();
			let peer_state = &mut *peer_state_lock;
			match peer_state.channel_by_id.entry(msg.channel_id) {
				hash_map::Entry::Occupied(mut chan_phase_entry) => {
					if let ChannelPhase::Funded(chan) = chan_phase_entry.get_mut() {
						let res = try_chan_phase_entry!(self, chan.update_fulfill_htlc(&msg), chan_phase_entry);
						if let HTLCSource::PreviousHopData(prev_hop) = &res.0 {
							let logger = WithChannelContext::from(&self.logger, &chan.context);
							log_trace!(logger,
								"Holding the next revoke_and_ack from {} until the preimage is durably persisted in the inbound edge's ChannelMonitor",
								msg.channel_id);
							peer_state.actions_blocking_raa_monitor_updates.entry(msg.channel_id)
								.or_insert_with(Vec::new)
								.push(RAAMonitorUpdateBlockingAction::from_prev_hop_data(&prev_hop));
						}
						// Note that we do not need to push an `actions_blocking_raa_monitor_updates`
						// entry here, even though we *do* need to block the next RAA monitor update.
						// We do this instead in the `claim_funds_internal` by attaching a
						// `ReleaseRAAChannelMonitorUpdate` action to the event generated when the
						// outbound HTLC is claimed. This is guaranteed to all complete before we
						// process the RAA as messages are processed from single peers serially.
						funding_txo = chan.context.get_funding_txo().expect("We won't accept a fulfill until funded");
						next_user_channel_id = chan.context.get_user_id();
						res
					} else {
						return try_chan_phase_entry!(self, Err(ChannelError::Close(
							"Got an update_fulfill_htlc message for an unfunded channel!".into())), chan_phase_entry);
					}
				},
				hash_map::Entry::Vacant(_) => return Err(MsgHandleErrInternal::send_err_msg_no_close(format!("Got a message for a channel from the wrong node! No such channel for the passed counterparty_node_id {}", counterparty_node_id), msg.channel_id))
			}
		};
		self.claim_funds_internal(htlc_source, msg.payment_preimage.clone(),
			Some(forwarded_htlc_value), skimmed_fee_msat, false, false, Some(*counterparty_node_id),
			funding_txo, msg.channel_id, Some(next_user_channel_id),
		);

		Ok(())
	}

	fn internal_update_fail_htlc(&self, counterparty_node_id: &PublicKey, msg: &msgs::UpdateFailHTLC) -> Result<(), MsgHandleErrInternal> {
		// Note that the ChannelManager is NOT re-persisted on disk after this (unless we error
		// closing a channel), so any changes are likely to be lost on restart!
		let per_peer_state = self.per_peer_state.read().unwrap();
		let peer_state_mutex = per_peer_state.get(counterparty_node_id)
			.ok_or_else(|| {
				debug_assert!(false);
				MsgHandleErrInternal::send_err_msg_no_close(format!("Can't find a peer matching the passed counterparty node_id {}", counterparty_node_id), msg.channel_id)
			})?;
		let mut peer_state_lock = peer_state_mutex.lock().unwrap();
		let peer_state = &mut *peer_state_lock;
		match peer_state.channel_by_id.entry(msg.channel_id) {
			hash_map::Entry::Occupied(mut chan_phase_entry) => {
				if let ChannelPhase::Funded(chan) = chan_phase_entry.get_mut() {
					try_chan_phase_entry!(self, chan.update_fail_htlc(&msg, HTLCFailReason::from_msg(msg)), chan_phase_entry);
				} else {
					return try_chan_phase_entry!(self, Err(ChannelError::Close(
						"Got an update_fail_htlc message for an unfunded channel!".into())), chan_phase_entry);
				}
			},
			hash_map::Entry::Vacant(_) => return Err(MsgHandleErrInternal::send_err_msg_no_close(format!("Got a message for a channel from the wrong node! No such channel for the passed counterparty_node_id {}", counterparty_node_id), msg.channel_id))
		}
		Ok(())
	}

	fn internal_update_fail_malformed_htlc(&self, counterparty_node_id: &PublicKey, msg: &msgs::UpdateFailMalformedHTLC) -> Result<(), MsgHandleErrInternal> {
		// Note that the ChannelManager is NOT re-persisted on disk after this (unless we error
		// closing a channel), so any changes are likely to be lost on restart!
		let per_peer_state = self.per_peer_state.read().unwrap();
		let peer_state_mutex = per_peer_state.get(counterparty_node_id)
			.ok_or_else(|| {
				debug_assert!(false);
				MsgHandleErrInternal::send_err_msg_no_close(format!("Can't find a peer matching the passed counterparty node_id {}", counterparty_node_id), msg.channel_id)
			})?;
		let mut peer_state_lock = peer_state_mutex.lock().unwrap();
		let peer_state = &mut *peer_state_lock;
		match peer_state.channel_by_id.entry(msg.channel_id) {
			hash_map::Entry::Occupied(mut chan_phase_entry) => {
				if (msg.failure_code & 0x8000) == 0 {
					let chan_err: ChannelError = ChannelError::Close("Got update_fail_malformed_htlc with BADONION not set".to_owned());
					try_chan_phase_entry!(self, Err(chan_err), chan_phase_entry);
				}
				if let ChannelPhase::Funded(chan) = chan_phase_entry.get_mut() {
					try_chan_phase_entry!(self, chan.update_fail_malformed_htlc(&msg, HTLCFailReason::reason(msg.failure_code, msg.sha256_of_onion.to_vec())), chan_phase_entry);
				} else {
					return try_chan_phase_entry!(self, Err(ChannelError::Close(
						"Got an update_fail_malformed_htlc message for an unfunded channel!".into())), chan_phase_entry);
				}
				Ok(())
			},
			hash_map::Entry::Vacant(_) => return Err(MsgHandleErrInternal::send_err_msg_no_close(format!("Got a message for a channel from the wrong node! No such channel for the passed counterparty_node_id {}", counterparty_node_id), msg.channel_id))
		}
	}

	fn internal_commitment_signed(&self, counterparty_node_id: &PublicKey, msg: &msgs::CommitmentSigned) -> Result<(), MsgHandleErrInternal> {
		let per_peer_state = self.per_peer_state.read().unwrap();
		let peer_state_mutex = per_peer_state.get(counterparty_node_id)
			.ok_or_else(|| {
				debug_assert!(false);
				MsgHandleErrInternal::send_err_msg_no_close(format!("Can't find a peer matching the passed counterparty node_id {}", counterparty_node_id), msg.channel_id)
			})?;
		let mut peer_state_lock = peer_state_mutex.lock().unwrap();
		let peer_state = &mut *peer_state_lock;
		match peer_state.channel_by_id.entry(msg.channel_id) {
			hash_map::Entry::Occupied(mut chan_phase_entry) => {
				if let ChannelPhase::Funded(chan) = chan_phase_entry.get_mut() {
					let logger = WithChannelContext::from(&self.logger, &chan.context);
					let funding_txo = chan.context.get_funding_txo();
					let monitor_update_opt = try_chan_phase_entry!(self, chan.commitment_signed(&msg, &&logger), chan_phase_entry);
					if let Some(monitor_update) = monitor_update_opt {
						handle_new_monitor_update!(self, funding_txo.unwrap(), monitor_update, peer_state_lock,
							peer_state, per_peer_state, chan);
					}
					Ok(())
				} else {
					return try_chan_phase_entry!(self, Err(ChannelError::Close(
						"Got a commitment_signed message for an unfunded channel!".into())), chan_phase_entry);
				}
			},
			hash_map::Entry::Vacant(_) => return Err(MsgHandleErrInternal::send_err_msg_no_close(format!("Got a message for a channel from the wrong node! No such channel for the passed counterparty_node_id {}", counterparty_node_id), msg.channel_id))
		}
	}

	fn push_decode_update_add_htlcs(&self, mut update_add_htlcs: (u64, Vec<msgs::UpdateAddHTLC>)) {
		let mut push_forward_event = self.forward_htlcs.lock().unwrap().is_empty();
		let mut decode_update_add_htlcs = self.decode_update_add_htlcs.lock().unwrap();
		push_forward_event &= decode_update_add_htlcs.is_empty();
		let scid = update_add_htlcs.0;
		match decode_update_add_htlcs.entry(scid) {
			hash_map::Entry::Occupied(mut e) => { e.get_mut().append(&mut update_add_htlcs.1); },
			hash_map::Entry::Vacant(e) => { e.insert(update_add_htlcs.1); },
		}
		if push_forward_event { self.push_pending_forwards_ev(); }
	}

	#[inline]
	fn forward_htlcs(&self, per_source_pending_forwards: &mut [(u64, OutPoint, ChannelId, u128, Vec<(PendingHTLCInfo, u64)>)]) {
		let push_forward_event = self.forward_htlcs_without_forward_event(per_source_pending_forwards);
		if push_forward_event { self.push_pending_forwards_ev() }
	}

	#[inline]
	fn forward_htlcs_without_forward_event(&self, per_source_pending_forwards: &mut [(u64, OutPoint, ChannelId, u128, Vec<(PendingHTLCInfo, u64)>)]) -> bool {
		let mut push_forward_event = false;
		for &mut (prev_short_channel_id, prev_funding_outpoint, prev_channel_id, prev_user_channel_id, ref mut pending_forwards) in per_source_pending_forwards {
			let mut new_intercept_events = VecDeque::new();
			let mut failed_intercept_forwards = Vec::new();
			if !pending_forwards.is_empty() {
				for (forward_info, prev_htlc_id) in pending_forwards.drain(..) {
					let scid = match forward_info.routing {
						PendingHTLCRouting::Forward { short_channel_id, .. } => short_channel_id,
						PendingHTLCRouting::Receive { .. } => 0,
						PendingHTLCRouting::ReceiveKeysend { .. } => 0,
					};
					// Pull this now to avoid introducing a lock order with `forward_htlcs`.
					let is_our_scid = self.short_to_chan_info.read().unwrap().contains_key(&scid);

					let decode_update_add_htlcs_empty = self.decode_update_add_htlcs.lock().unwrap().is_empty();
					let mut forward_htlcs = self.forward_htlcs.lock().unwrap();
					let forward_htlcs_empty = forward_htlcs.is_empty();
					match forward_htlcs.entry(scid) {
						hash_map::Entry::Occupied(mut entry) => {
							entry.get_mut().push(HTLCForwardInfo::AddHTLC(PendingAddHTLCInfo {
								prev_short_channel_id, prev_funding_outpoint, prev_channel_id, prev_htlc_id, prev_user_channel_id, forward_info }));
						},
						hash_map::Entry::Vacant(entry) => {
							if !is_our_scid && forward_info.incoming_amt_msat.is_some() &&
							   fake_scid::is_valid_intercept(&self.fake_scid_rand_bytes, scid, &self.chain_hash)
							{
								let intercept_id = InterceptId(Sha256::hash(&forward_info.incoming_shared_secret).to_byte_array());
								let mut pending_intercepts = self.pending_intercepted_htlcs.lock().unwrap();
								match pending_intercepts.entry(intercept_id) {
									hash_map::Entry::Vacant(entry) => {
										new_intercept_events.push_back((events::Event::HTLCIntercepted {
											requested_next_hop_scid: scid,
											payment_hash: forward_info.payment_hash,
											inbound_amount_msat: forward_info.incoming_amt_msat.unwrap(),
											expected_outbound_amount_msat: forward_info.outgoing_amt_msat,
											intercept_id
										}, None));
										entry.insert(PendingAddHTLCInfo {
											prev_short_channel_id, prev_funding_outpoint, prev_channel_id, prev_htlc_id, prev_user_channel_id, forward_info });
									},
									hash_map::Entry::Occupied(_) => {
										let logger = WithContext::from(&self.logger, None, Some(prev_channel_id));
										log_info!(logger, "Failed to forward incoming HTLC: detected duplicate intercepted payment over short channel id {}", scid);
										let htlc_source = HTLCSource::PreviousHopData(HTLCPreviousHopData {
											short_channel_id: prev_short_channel_id,
											user_channel_id: Some(prev_user_channel_id),
											outpoint: prev_funding_outpoint,
											channel_id: prev_channel_id,
											htlc_id: prev_htlc_id,
											incoming_packet_shared_secret: forward_info.incoming_shared_secret,
											phantom_shared_secret: None,
											blinded_failure: forward_info.routing.blinded_failure(),
										});

										failed_intercept_forwards.push((htlc_source, forward_info.payment_hash,
												HTLCFailReason::from_failure_code(0x4000 | 10),
												HTLCDestination::InvalidForward { requested_forward_scid: scid },
										));
									}
								}
							} else {
								// We don't want to generate a PendingHTLCsForwardable event if only intercepted
								// payments are being processed.
								push_forward_event |= forward_htlcs_empty && decode_update_add_htlcs_empty;
								entry.insert(vec!(HTLCForwardInfo::AddHTLC(PendingAddHTLCInfo {
									prev_short_channel_id, prev_funding_outpoint, prev_channel_id, prev_htlc_id, prev_user_channel_id, forward_info })));
							}
						}
					}
				}
			}

			for (htlc_source, payment_hash, failure_reason, destination) in failed_intercept_forwards.drain(..) {
				push_forward_event |= self.fail_htlc_backwards_internal_without_forward_event(&htlc_source, &payment_hash, &failure_reason, destination);
			}

			if !new_intercept_events.is_empty() {
				let mut events = self.pending_events.lock().unwrap();
				events.append(&mut new_intercept_events);
			}
		}
		push_forward_event
	}

	fn push_pending_forwards_ev(&self) {
		let mut pending_events = self.pending_events.lock().unwrap();
		let is_processing_events = self.pending_events_processor.load(Ordering::Acquire);
		let num_forward_events = pending_events.iter().filter(|(ev, _)|
			if let events::Event::PendingHTLCsForwardable { .. } = ev { true } else { false }
		).count();
		// We only want to push a PendingHTLCsForwardable event if no others are queued. Processing
		// events is done in batches and they are not removed until we're done processing each
		// batch. Since handling a `PendingHTLCsForwardable` event will call back into the
		// `ChannelManager`, we'll still see the original forwarding event not removed. Phantom
		// payments will need an additional forwarding event before being claimed to make them look
		// real by taking more time.
		if (is_processing_events && num_forward_events <= 1) || num_forward_events < 1 {
			pending_events.push_back((Event::PendingHTLCsForwardable {
				time_forwardable: Duration::from_millis(MIN_HTLC_RELAY_HOLDING_CELL_MILLIS),
			}, None));
		}
	}

	/// Checks whether [`ChannelMonitorUpdate`]s generated by the receipt of a remote
	/// [`msgs::RevokeAndACK`] should be held for the given channel until some other action
	/// completes. Note that this needs to happen in the same [`PeerState`] mutex as any release of
	/// the [`ChannelMonitorUpdate`] in question.
	fn raa_monitor_updates_held(&self,
		actions_blocking_raa_monitor_updates: &BTreeMap<ChannelId, Vec<RAAMonitorUpdateBlockingAction>>,
		channel_funding_outpoint: OutPoint, channel_id: ChannelId, counterparty_node_id: PublicKey
	) -> bool {
		actions_blocking_raa_monitor_updates
			.get(&channel_id).map(|v| !v.is_empty()).unwrap_or(false)
		|| self.pending_events.lock().unwrap().iter().any(|(_, action)| {
			action == &Some(EventCompletionAction::ReleaseRAAChannelMonitorUpdate {
				channel_funding_outpoint,
				channel_id,
				counterparty_node_id,
			})
		})
	}

	#[cfg(any(test, feature = "_test_utils"))]
	pub(crate) fn test_raa_monitor_updates_held(&self,
		counterparty_node_id: PublicKey, channel_id: ChannelId
	) -> bool {
		let per_peer_state = self.per_peer_state.read().unwrap();
		if let Some(peer_state_mtx) = per_peer_state.get(&counterparty_node_id) {
			let mut peer_state_lck = peer_state_mtx.lock().unwrap();
			let peer_state = &mut *peer_state_lck;

			if let Some(chan) = peer_state.channel_by_id.get(&channel_id) {
				return self.raa_monitor_updates_held(&peer_state.actions_blocking_raa_monitor_updates,
					chan.context().get_funding_txo().unwrap(), channel_id, counterparty_node_id);
			}
		}
		false
	}

	fn internal_revoke_and_ack(&self, counterparty_node_id: &PublicKey, msg: &msgs::RevokeAndACK) -> Result<(), MsgHandleErrInternal> {
		let htlcs_to_fail = {
			let per_peer_state = self.per_peer_state.read().unwrap();
			let mut peer_state_lock = per_peer_state.get(counterparty_node_id)
				.ok_or_else(|| {
					debug_assert!(false);
					MsgHandleErrInternal::send_err_msg_no_close(format!("Can't find a peer matching the passed counterparty node_id {}", counterparty_node_id), msg.channel_id)
				}).map(|mtx| mtx.lock().unwrap())?;
			let peer_state = &mut *peer_state_lock;
			match peer_state.channel_by_id.entry(msg.channel_id) {
				hash_map::Entry::Occupied(mut chan_phase_entry) => {
					if let ChannelPhase::Funded(chan) = chan_phase_entry.get_mut() {
						let logger = WithChannelContext::from(&self.logger, &chan.context);
						let funding_txo_opt = chan.context.get_funding_txo();
						let mon_update_blocked = if let Some(funding_txo) = funding_txo_opt {
							self.raa_monitor_updates_held(
								&peer_state.actions_blocking_raa_monitor_updates, funding_txo, msg.channel_id,
								*counterparty_node_id)
						} else { false };
						let (htlcs_to_fail, monitor_update_opt) = try_chan_phase_entry!(self,
							chan.revoke_and_ack(&msg, &self.fee_estimator, &&logger, mon_update_blocked), chan_phase_entry);
						if let Some(monitor_update) = monitor_update_opt {
							let funding_txo = funding_txo_opt
								.expect("Funding outpoint must have been set for RAA handling to succeed");
							handle_new_monitor_update!(self, funding_txo, monitor_update,
								peer_state_lock, peer_state, per_peer_state, chan);
						}
						htlcs_to_fail
					} else {
						return try_chan_phase_entry!(self, Err(ChannelError::Close(
							"Got a revoke_and_ack message for an unfunded channel!".into())), chan_phase_entry);
					}
				},
				hash_map::Entry::Vacant(_) => return Err(MsgHandleErrInternal::send_err_msg_no_close(format!("Got a message for a channel from the wrong node! No such channel for the passed counterparty_node_id {}", counterparty_node_id), msg.channel_id))
			}
		};
		self.fail_holding_cell_htlcs(htlcs_to_fail, msg.channel_id, counterparty_node_id);
		Ok(())
	}

	fn internal_update_fee(&self, counterparty_node_id: &PublicKey, msg: &msgs::UpdateFee) -> Result<(), MsgHandleErrInternal> {
		let per_peer_state = self.per_peer_state.read().unwrap();
		let peer_state_mutex = per_peer_state.get(counterparty_node_id)
			.ok_or_else(|| {
				debug_assert!(false);
				MsgHandleErrInternal::send_err_msg_no_close(format!("Can't find a peer matching the passed counterparty node_id {}", counterparty_node_id), msg.channel_id)
			})?;
		let mut peer_state_lock = peer_state_mutex.lock().unwrap();
		let peer_state = &mut *peer_state_lock;
		match peer_state.channel_by_id.entry(msg.channel_id) {
			hash_map::Entry::Occupied(mut chan_phase_entry) => {
				if let ChannelPhase::Funded(chan) = chan_phase_entry.get_mut() {
					let logger = WithChannelContext::from(&self.logger, &chan.context);
					try_chan_phase_entry!(self, chan.update_fee(&self.fee_estimator, &msg, &&logger), chan_phase_entry);
				} else {
					return try_chan_phase_entry!(self, Err(ChannelError::Close(
						"Got an update_fee message for an unfunded channel!".into())), chan_phase_entry);
				}
			},
			hash_map::Entry::Vacant(_) => return Err(MsgHandleErrInternal::send_err_msg_no_close(format!("Got a message for a channel from the wrong node! No such channel for the passed counterparty_node_id {}", counterparty_node_id), msg.channel_id))
		}
		Ok(())
	}

	fn internal_announcement_signatures(&self, counterparty_node_id: &PublicKey, msg: &msgs::AnnouncementSignatures) -> Result<(), MsgHandleErrInternal> {
		let per_peer_state = self.per_peer_state.read().unwrap();
		let peer_state_mutex = per_peer_state.get(counterparty_node_id)
			.ok_or_else(|| {
				debug_assert!(false);
				MsgHandleErrInternal::send_err_msg_no_close(format!("Can't find a peer matching the passed counterparty node_id {}", counterparty_node_id), msg.channel_id)
			})?;
		let mut peer_state_lock = peer_state_mutex.lock().unwrap();
		let peer_state = &mut *peer_state_lock;
		match peer_state.channel_by_id.entry(msg.channel_id) {
			hash_map::Entry::Occupied(mut chan_phase_entry) => {
				if let ChannelPhase::Funded(chan) = chan_phase_entry.get_mut() {
					if !chan.context.is_usable() {
						return Err(MsgHandleErrInternal::from_no_close(LightningError{err: "Got an announcement_signatures before we were ready for it".to_owned(), action: msgs::ErrorAction::IgnoreError}));
					}

					peer_state.pending_msg_events.push(events::MessageSendEvent::BroadcastChannelAnnouncement {
						msg: try_chan_phase_entry!(self, chan.announcement_signatures(
							&self.node_signer, self.chain_hash, self.best_block.read().unwrap().height,
							msg, &self.default_configuration
						), chan_phase_entry),
						// Note that announcement_signatures fails if the channel cannot be announced,
						// so get_channel_update_for_broadcast will never fail by the time we get here.
						update_msg: Some(self.get_channel_update_for_broadcast(chan).unwrap()),
					});
				} else {
					return try_chan_phase_entry!(self, Err(ChannelError::Close(
						"Got an announcement_signatures message for an unfunded channel!".into())), chan_phase_entry);
				}
			},
			hash_map::Entry::Vacant(_) => return Err(MsgHandleErrInternal::send_err_msg_no_close(format!("Got a message for a channel from the wrong node! No such channel for the passed counterparty_node_id {}", counterparty_node_id), msg.channel_id))
		}
		Ok(())
	}

	/// Returns DoPersist if anything changed, otherwise either SkipPersistNoEvents or an Err.
	fn internal_channel_update(&self, counterparty_node_id: &PublicKey, msg: &msgs::ChannelUpdate) -> Result<NotifyOption, MsgHandleErrInternal> {
		let (chan_counterparty_node_id, chan_id) = match self.short_to_chan_info.read().unwrap().get(&msg.contents.short_channel_id) {
			Some((cp_id, chan_id)) => (cp_id.clone(), chan_id.clone()),
			None => {
				// It's not a local channel
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
			hash_map::Entry::Occupied(mut chan_phase_entry) => {
				if let ChannelPhase::Funded(chan) = chan_phase_entry.get_mut() {
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
					let msg_from_node_one = msg.contents.flags & 1 == 0;
					if were_node_one == msg_from_node_one {
						return Ok(NotifyOption::SkipPersistNoEvents);
					} else {
						let logger = WithChannelContext::from(&self.logger, &chan.context);
						log_debug!(logger, "Received channel_update {:?} for channel {}.", msg, chan_id);
						let did_change = try_chan_phase_entry!(self, chan.channel_update(&msg), chan_phase_entry);
						// If nothing changed after applying their update, we don't need to bother
						// persisting.
						if !did_change {
							return Ok(NotifyOption::SkipPersistNoEvents);
						}
					}
				} else {
					return try_chan_phase_entry!(self, Err(ChannelError::Close(
						"Got a channel_update for an unfunded channel!".into())), chan_phase_entry);
				}
			},
			hash_map::Entry::Vacant(_) => return Ok(NotifyOption::SkipPersistNoEvents)
		}
		Ok(NotifyOption::DoPersist)
	}

	fn internal_channel_reestablish(&self, counterparty_node_id: &PublicKey, msg: &msgs::ChannelReestablish) -> Result<NotifyOption, MsgHandleErrInternal> {
		let need_lnd_workaround = {
			let per_peer_state = self.per_peer_state.read().unwrap();

			let peer_state_mutex = per_peer_state.get(counterparty_node_id)
				.ok_or_else(|| {
					debug_assert!(false);
					MsgHandleErrInternal::send_err_msg_no_close(
						format!("Can't find a peer matching the passed counterparty node_id {}", counterparty_node_id),
						msg.channel_id
					)
				})?;
			let logger = WithContext::from(&self.logger, Some(*counterparty_node_id), Some(msg.channel_id));
			let mut peer_state_lock = peer_state_mutex.lock().unwrap();
			let peer_state = &mut *peer_state_lock;
			match peer_state.channel_by_id.entry(msg.channel_id) {
				hash_map::Entry::Occupied(mut chan_phase_entry) => {
					if let ChannelPhase::Funded(chan) = chan_phase_entry.get_mut() {
						// Currently, we expect all holding cell update_adds to be dropped on peer
						// disconnect, so Channel's reestablish will never hand us any holding cell
						// freed HTLCs to fail backwards. If in the future we no longer drop pending
						// add-HTLCs on disconnect, we may be handed HTLCs to fail backwards here.
						let responses = try_chan_phase_entry!(self, chan.channel_reestablish(
							msg, &&logger, &self.node_signer, self.chain_hash,
							&self.default_configuration, &*self.best_block.read().unwrap()), chan_phase_entry);
						let mut channel_update = None;
						if let Some(msg) = responses.shutdown_msg {
							peer_state.pending_msg_events.push(events::MessageSendEvent::SendShutdown {
								node_id: counterparty_node_id.clone(),
								msg,
							});
						} else if chan.context.is_usable() {
							// If the channel is in a usable state (ie the channel is not being shut
							// down), send a unicast channel_update to our counterparty to make sure
							// they have the latest channel parameters.
							if let Ok(msg) = self.get_channel_update_for_unicast(chan) {
								channel_update = Some(events::MessageSendEvent::SendChannelUpdate {
									node_id: chan.context.get_counterparty_node_id(),
									msg,
								});
							}
						}
						let need_lnd_workaround = chan.context.workaround_lnd_bug_4006.take();
						let (htlc_forwards, decode_update_add_htlcs) = self.handle_channel_resumption(
							&mut peer_state.pending_msg_events, chan, responses.raa, responses.commitment_update, responses.order,
							Vec::new(), Vec::new(), None, responses.channel_ready, responses.announcement_sigs);
						debug_assert!(htlc_forwards.is_none());
						debug_assert!(decode_update_add_htlcs.is_none());
						if let Some(upd) = channel_update {
							peer_state.pending_msg_events.push(upd);
						}
						need_lnd_workaround
					} else {
						return try_chan_phase_entry!(self, Err(ChannelError::Close(
							"Got a channel_reestablish message for an unfunded channel!".into())), chan_phase_entry);
					}
				},
				hash_map::Entry::Vacant(_) => {
					log_debug!(logger, "Sending bogus ChannelReestablish for unknown channel {} to force channel closure",
						msg.channel_id);
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
							next_funding_txid: None,
						},
					});
					return Err(MsgHandleErrInternal::send_err_msg_no_close(
						format!("Got a message for a channel from the wrong node! No such channel for the passed counterparty_node_id {}",
							counterparty_node_id), msg.channel_id)
					)
				}
			}
		};

		if let Some(channel_ready_msg) = need_lnd_workaround {
			self.internal_channel_ready(counterparty_node_id, &channel_ready_msg)?;
		}
		Ok(NotifyOption::SkipPersistHandleEvents)
	}

	/// Process pending events from the [`chain::Watch`], returning whether any events were processed.
	fn process_pending_monitor_events(&self) -> bool {
		debug_assert!(self.total_consistency_lock.try_write().is_err()); // Caller holds read lock

		let mut failed_channels = Vec::new();
		let mut pending_monitor_events = self.chain_monitor.release_pending_monitor_events();
		let has_pending_monitor_events = !pending_monitor_events.is_empty();
		for (funding_outpoint, channel_id, mut monitor_events, counterparty_node_id) in pending_monitor_events.drain(..) {
			for monitor_event in monitor_events.drain(..) {
				match monitor_event {
					MonitorEvent::HTLCEvent(htlc_update) => {
						let logger = WithContext::from(&self.logger, counterparty_node_id, Some(channel_id));
						if let Some(preimage) = htlc_update.payment_preimage {
							log_trace!(logger, "Claiming HTLC with preimage {} from our monitor", preimage);
							self.claim_funds_internal(htlc_update.source, preimage,
								htlc_update.htlc_value_satoshis.map(|v| v * 1000), None, true,
								false, counterparty_node_id, funding_outpoint, channel_id, None);
						} else {
							log_trace!(logger, "Failing HTLC with hash {} from our monitor", &htlc_update.payment_hash);
							let receiver = HTLCDestination::NextHopChannel { node_id: counterparty_node_id, channel_id };
							let reason = HTLCFailReason::from_failure_code(0x4000 | 8);
							self.fail_htlc_backwards_internal(&htlc_update.source, &htlc_update.payment_hash, &reason, receiver);
						}
					},
					MonitorEvent::HolderForceClosed(_) | MonitorEvent::HolderForceClosedWithInfo { .. } => {
						let counterparty_node_id_opt = match counterparty_node_id {
							Some(cp_id) => Some(cp_id),
							None => {
								// TODO: Once we can rely on the counterparty_node_id from the
								// monitor event, this and the outpoint_to_peer map should be removed.
								let outpoint_to_peer = self.outpoint_to_peer.lock().unwrap();
								outpoint_to_peer.get(&funding_outpoint).cloned()
							}
						};
						if let Some(counterparty_node_id) = counterparty_node_id_opt {
							let per_peer_state = self.per_peer_state.read().unwrap();
							if let Some(peer_state_mutex) = per_peer_state.get(&counterparty_node_id) {
								let mut peer_state_lock = peer_state_mutex.lock().unwrap();
								let peer_state = &mut *peer_state_lock;
								let pending_msg_events = &mut peer_state.pending_msg_events;
								if let hash_map::Entry::Occupied(chan_phase_entry) = peer_state.channel_by_id.entry(channel_id) {
									if let ChannelPhase::Funded(mut chan) = remove_channel_phase!(self, chan_phase_entry) {
										let reason = if let MonitorEvent::HolderForceClosedWithInfo { reason, .. } = monitor_event {
											reason
										} else {
											ClosureReason::HolderForceClosed
										};
										failed_channels.push(chan.context.force_shutdown(false, reason.clone()));
										if let Ok(update) = self.get_channel_update_for_broadcast(&chan) {
											let mut pending_broadcast_messages = self.pending_broadcast_messages.lock().unwrap();
											pending_broadcast_messages.push(events::MessageSendEvent::BroadcastChannelUpdate {
												msg: update
											});
										}
										pending_msg_events.push(events::MessageSendEvent::HandleError {
											node_id: chan.context.get_counterparty_node_id(),
											action: msgs::ErrorAction::DisconnectPeer {
												msg: Some(msgs::ErrorMessage { channel_id: chan.context.channel_id(), data: reason.to_string() })
											},
										});
									}
								}
							}
						}
					},
					MonitorEvent::Completed { funding_txo, channel_id, monitor_update_id } => {
						self.channel_monitor_updated(&funding_txo, &channel_id, monitor_update_id, counterparty_node_id.as_ref());
					},
				}
			}
		}

		for failure in failed_channels.drain(..) {
			self.finish_close_channel(failure);
		}

		has_pending_monitor_events
	}

	/// In chanmon_consistency_target, we'd like to be able to restore monitor updating without
	/// handling all pending events (i.e. not PendingHTLCsForwardable). Thus, we expose monitor
	/// update events as a separate process method here.
	#[cfg(fuzzing)]
	pub fn process_monitor_events(&self) {
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(self);
		self.process_pending_monitor_events();
	}

	/// Check the holding cell in each channel and free any pending HTLCs in them if possible.
	/// Returns whether there were any updates such as if pending HTLCs were freed or a monitor
	/// update was applied.
	fn check_free_holding_cells(&self) -> bool {
		let mut has_monitor_update = false;
		let mut failed_htlcs = Vec::new();

		// Walk our list of channels and find any that need to update. Note that when we do find an
		// update, if it includes actions that must be taken afterwards, we have to drop the
		// per-peer state lock as well as the top level per_peer_state lock. Thus, we loop until we
		// manage to go through all our peers without finding a single channel to update.
		'peer_loop: loop {
			let per_peer_state = self.per_peer_state.read().unwrap();
			for (_cp_id, peer_state_mutex) in per_peer_state.iter() {
				'chan_loop: loop {
					let mut peer_state_lock = peer_state_mutex.lock().unwrap();
					let peer_state: &mut PeerState<_> = &mut *peer_state_lock;
					for (channel_id, chan) in peer_state.channel_by_id.iter_mut().filter_map(
						|(chan_id, phase)| if let ChannelPhase::Funded(chan) = phase { Some((chan_id, chan)) } else { None }
					) {
						let counterparty_node_id = chan.context.get_counterparty_node_id();
						let funding_txo = chan.context.get_funding_txo();
						let (monitor_opt, holding_cell_failed_htlcs) =
							chan.maybe_free_holding_cell_htlcs(&self.fee_estimator, &&WithChannelContext::from(&self.logger, &chan.context));
						if !holding_cell_failed_htlcs.is_empty() {
							failed_htlcs.push((holding_cell_failed_htlcs, *channel_id, counterparty_node_id));
						}
						if let Some(monitor_update) = monitor_opt {
							has_monitor_update = true;

							handle_new_monitor_update!(self, funding_txo.unwrap(), monitor_update,
								peer_state_lock, peer_state, per_peer_state, chan);
							continue 'peer_loop;
						}
					}
					break 'chan_loop;
				}
			}
			break 'peer_loop;
		}

		let has_update = has_monitor_update || !failed_htlcs.is_empty();
		for (failures, channel_id, counterparty_node_id) in failed_htlcs.drain(..) {
			self.fail_holding_cell_htlcs(failures, channel_id, &counterparty_node_id);
		}

		has_update
	}

	/// When a call to a [`ChannelSigner`] method returns an error, this indicates that the signer
	/// is (temporarily) unavailable, and the operation should be retried later.
	///
	/// This method allows for that retry - either checking for any signer-pending messages to be
	/// attempted in every channel, or in the specifically provided channel.
	///
	/// [`ChannelSigner`]: crate::sign::ChannelSigner
	#[cfg(async_signing)]
	pub fn signer_unblocked(&self, channel_opt: Option<(PublicKey, ChannelId)>) {
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(self);

		let unblock_chan = |phase: &mut ChannelPhase<SP>, pending_msg_events: &mut Vec<MessageSendEvent>| {
			let node_id = phase.context().get_counterparty_node_id();
			match phase {
				ChannelPhase::Funded(chan) => {
					let msgs = chan.signer_maybe_unblocked(&self.logger);
					if let Some(updates) = msgs.commitment_update {
						pending_msg_events.push(events::MessageSendEvent::UpdateHTLCs {
							node_id,
							updates,
						});
					}
					if let Some(msg) = msgs.funding_signed {
						pending_msg_events.push(events::MessageSendEvent::SendFundingSigned {
							node_id,
							msg,
						});
					}
					if let Some(msg) = msgs.channel_ready {
						send_channel_ready!(self, pending_msg_events, chan, msg);
					}
				}
				ChannelPhase::UnfundedOutboundV1(chan) => {
					if let Some(msg) = chan.signer_maybe_unblocked(&self.logger) {
						pending_msg_events.push(events::MessageSendEvent::SendFundingCreated {
							node_id,
							msg,
						});
					}
				}
				ChannelPhase::UnfundedInboundV1(_) => {},
			}
		};

		let per_peer_state = self.per_peer_state.read().unwrap();
		if let Some((counterparty_node_id, channel_id)) = channel_opt {
			if let Some(peer_state_mutex) = per_peer_state.get(&counterparty_node_id) {
				let mut peer_state_lock = peer_state_mutex.lock().unwrap();
				let peer_state = &mut *peer_state_lock;
				if let Some(chan) = peer_state.channel_by_id.get_mut(&channel_id) {
					unblock_chan(chan, &mut peer_state.pending_msg_events);
				}
			}
		} else {
			for (_cp_id, peer_state_mutex) in per_peer_state.iter() {
				let mut peer_state_lock = peer_state_mutex.lock().unwrap();
				let peer_state = &mut *peer_state_lock;
				for (_, chan) in peer_state.channel_by_id.iter_mut() {
					unblock_chan(chan, &mut peer_state.pending_msg_events);
				}
			}
		}
	}

	/// Check whether any channels have finished removing all pending updates after a shutdown
	/// exchange and can now send a closing_signed.
	/// Returns whether any closing_signed messages were generated.
	fn maybe_generate_initial_closing_signed(&self) -> bool {
		let mut handle_errors: Vec<(PublicKey, Result<(), _>)> = Vec::new();
		let mut has_update = false;
		let mut shutdown_results = Vec::new();
		{
			let per_peer_state = self.per_peer_state.read().unwrap();

			for (_cp_id, peer_state_mutex) in per_peer_state.iter() {
				let mut peer_state_lock = peer_state_mutex.lock().unwrap();
				let peer_state = &mut *peer_state_lock;
				let pending_msg_events = &mut peer_state.pending_msg_events;
				peer_state.channel_by_id.retain(|channel_id, phase| {
					match phase {
						ChannelPhase::Funded(chan) => {
							let logger = WithChannelContext::from(&self.logger, &chan.context);
							match chan.maybe_propose_closing_signed(&self.fee_estimator, &&logger) {
								Ok((msg_opt, tx_opt, shutdown_result_opt)) => {
									if let Some(msg) = msg_opt {
										has_update = true;
										pending_msg_events.push(events::MessageSendEvent::SendClosingSigned {
											node_id: chan.context.get_counterparty_node_id(), msg,
										});
									}
									debug_assert_eq!(shutdown_result_opt.is_some(), chan.is_shutdown());
									if let Some(shutdown_result) = shutdown_result_opt {
										shutdown_results.push(shutdown_result);
									}
									if let Some(tx) = tx_opt {
										// We're done with this channel. We got a closing_signed and sent back
										// a closing_signed with a closing transaction to broadcast.
										if let Ok(update) = self.get_channel_update_for_broadcast(&chan) {
											let mut pending_broadcast_messages = self.pending_broadcast_messages.lock().unwrap();
											pending_broadcast_messages.push(events::MessageSendEvent::BroadcastChannelUpdate {
												msg: update
											});
										}

										log_info!(logger, "Broadcasting {}", log_tx!(tx));
										self.tx_broadcaster.broadcast_transactions(&[&tx]);
										update_maps_on_chan_removal!(self, &chan.context);
										false
									} else { true }
								},
								Err(e) => {
									has_update = true;
									let (close_channel, res) = convert_chan_phase_err!(self, e, chan, channel_id, FUNDED_CHANNEL);
									handle_errors.push((chan.context.get_counterparty_node_id(), Err(res)));
									!close_channel
								}
							}
						},
						_ => true, // Retain unfunded channels if present.
					}
				});
			}
		}

		for (counterparty_node_id, err) in handle_errors.drain(..) {
			let _ = handle_error!(self, err, counterparty_node_id);
		}

		for shutdown_result in shutdown_results.drain(..) {
			self.finish_close_channel(shutdown_result);
		}

		has_update
	}

	/// Handle a list of channel failures during a block_connected or block_disconnected call,
	/// pushing the channel monitor update (if any) to the background events queue and removing the
	/// Channel object.
	fn handle_init_event_channel_failures(&self, mut failed_channels: Vec<ShutdownResult>) {
		for mut failure in failed_channels.drain(..) {
			// Either a commitment transactions has been confirmed on-chain or
			// Channel::block_disconnected detected that the funding transaction has been
			// reorganized out of the main chain.
			// We cannot broadcast our latest local state via monitor update (as
			// Channel::force_shutdown tries to make us do) as we may still be in initialization,
			// so we track the update internally and handle it when the user next calls
			// timer_tick_occurred, guaranteeing we're running normally.
			if let Some((counterparty_node_id, funding_txo, channel_id, update)) = failure.monitor_update.take() {
				assert_eq!(update.updates.len(), 1);
				if let ChannelMonitorUpdateStep::ChannelForceClosed { should_broadcast } = update.updates[0] {
					assert!(should_broadcast);
				} else { unreachable!(); }
				self.pending_background_events.lock().unwrap().push(
					BackgroundEvent::MonitorUpdateRegeneratedOnStartup {
						counterparty_node_id, funding_txo, update, channel_id,
					});
			}
			self.finish_close_channel(failure);
		}
	}
}

macro_rules! create_offer_builder { ($self: ident, $builder: ty) => {
	/// Creates an [`OfferBuilder`] such that the [`Offer`] it builds is recognized by the
	/// [`ChannelManager`] when handling [`InvoiceRequest`] messages for the offer. The offer will
	/// not have an expiration unless otherwise set on the builder.
	///
	/// # Privacy
	///
	/// Uses [`MessageRouter::create_blinded_paths`] to construct a [`BlindedPath`] for the offer.
	/// However, if one is not found, uses a one-hop [`BlindedPath`] with
	/// [`ChannelManager::get_our_node_id`] as the introduction node instead. In the latter case,
	/// the node must be announced, otherwise, there is no way to find a path to the introduction in
	/// order to send the [`InvoiceRequest`].
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
	/// This is not exported to bindings users as builder patterns don't map outside of move semantics.
	///
	/// [`Offer`]: crate::offers::offer::Offer
	/// [`InvoiceRequest`]: crate::offers::invoice_request::InvoiceRequest
	pub fn create_offer_builder(
		&$self, description: String
	) -> Result<$builder, Bolt12SemanticError> {
		let node_id = $self.get_our_node_id();
		let expanded_key = &$self.inbound_payment_key;
		let entropy = &*$self.entropy_source;
		let secp_ctx = &$self.secp_ctx;

		let path = $self.create_blinded_path().map_err(|_| Bolt12SemanticError::MissingPaths)?;
		let builder = OfferBuilder::deriving_signing_pubkey(
			description, node_id, expanded_key, entropy, secp_ctx
		)
			.chain_hash($self.chain_hash)
			.path(path);

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
	/// returned builder will not be honored by [`ChannelManager`]. For `no-std`, the highest seen
	/// block time minus two hours is used for the current time when determining if the refund has
	/// expired.
	///
	/// To revoke the refund, use [`ChannelManager::abandon_payment`] prior to receiving the
	/// invoice. If abandoned, or an invoice isn't received before expiration, the payment will fail
	/// with an [`Event::InvoiceRequestFailed`].
	///
	/// If `max_total_routing_fee_msat` is not specified, The default from
	/// [`RouteParameters::from_payment_params_and_value`] is applied.
	///
	/// # Privacy
	///
	/// Uses [`MessageRouter::create_blinded_paths`] to construct a [`BlindedPath`] for the refund.
	/// However, if one is not found, uses a one-hop [`BlindedPath`] with
	/// [`ChannelManager::get_our_node_id`] as the introduction node instead. In the latter case,
	/// the node must be announced, otherwise, there is no way to find a path to the introduction in
	/// order to send the [`Bolt12Invoice`].
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
	/// This is not exported to bindings users as builder patterns don't map outside of move semantics.
	///
	/// [`Refund`]: crate::offers::refund::Refund
	/// [`Bolt12Invoice`]: crate::offers::invoice::Bolt12Invoice
	/// [`Bolt12Invoice::payment_paths`]: crate::offers::invoice::Bolt12Invoice::payment_paths
	/// [Avoiding Duplicate Payments]: #avoiding-duplicate-payments
	pub fn create_refund_builder(
		&$self, description: String, amount_msats: u64, absolute_expiry: Duration,
		payment_id: PaymentId, retry_strategy: Retry, max_total_routing_fee_msat: Option<u64>
	) -> Result<$builder, Bolt12SemanticError> {
		let node_id = $self.get_our_node_id();
		let expanded_key = &$self.inbound_payment_key;
		let entropy = &*$self.entropy_source;
		let secp_ctx = &$self.secp_ctx;

		let path = $self.create_blinded_path().map_err(|_| Bolt12SemanticError::MissingPaths)?;
		let builder = RefundBuilder::deriving_payer_id(
			description, node_id, expanded_key, entropy, secp_ctx, amount_msats, payment_id
		)?
			.chain_hash($self.chain_hash)
			.absolute_expiry(absolute_expiry)
			.path(path);

		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop($self);

		let expiration = StaleExpiration::AbsoluteTimeout(absolute_expiry);
		$self.pending_outbound_payments
			.add_new_awaiting_invoice(
				payment_id, expiration, retry_strategy, max_total_routing_fee_msat,
			)
			.map_err(|_| Bolt12SemanticError::DuplicatePaymentId)?;

		Ok(builder.into())
	}
} }

impl<M: Deref, T: Deref, ES: Deref, NS: Deref, SP: Deref, F: Deref, R: Deref, L: Deref> ChannelManager<M, T, ES, NS, SP, F, R, L>
where
	M::Target: chain::Watch<<SP::Target as SignerProvider>::EcdsaSigner>,
	T::Target: BroadcasterInterface,
	ES::Target: EntropySource,
	NS::Target: NodeSigner,
	SP::Target: SignerProvider,
	F::Target: FeeEstimator,
	R::Target: Router,
	L::Target: Logger,
{
	#[cfg(not(c_bindings))]
	create_offer_builder!(self, OfferBuilder<DerivedMetadata, secp256k1::All>);
	#[cfg(not(c_bindings))]
	create_refund_builder!(self, RefundBuilder<secp256k1::All>);

	#[cfg(c_bindings)]
	create_offer_builder!(self, OfferWithDerivedMetadataBuilder);
	#[cfg(c_bindings)]
	create_refund_builder!(self, RefundMaybeWithDerivedMetadataBuilder);

	/// Pays for an [`Offer`] using the given parameters by creating an [`InvoiceRequest`] and
	/// enqueuing it to be sent via an onion message. [`ChannelManager`] will pay the actual
	/// [`Bolt12Invoice`] once it is received.
	///
	/// Uses [`InvoiceRequestBuilder`] such that the [`InvoiceRequest`] it builds is recognized by
	/// the [`ChannelManager`] when handling a [`Bolt12Invoice`] message in response to the request.
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
	/// payment will fail with an [`Event::InvoiceRequestFailed`].
	///
	/// # Privacy
	///
	/// Uses a one-hop [`BlindedPath`] for the reply path with [`ChannelManager::get_our_node_id`]
	/// as the introduction node and a derived payer id for payer privacy. As such, currently, the
	/// node must be announced. Otherwise, there is no way to find a path to the introduction node
	/// in order to send the [`Bolt12Invoice`].
	///
	/// # Limitations
	///
	/// Requires a direct connection to an introduction node in [`Offer::paths`] or to
	/// [`Offer::signing_pubkey`], if empty. A similar restriction applies to the responding
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
	/// [`InvoiceRequest`]: crate::offers::invoice_request::InvoiceRequest
	/// [`InvoiceRequest::quantity`]: crate::offers::invoice_request::InvoiceRequest::quantity
	/// [`InvoiceRequest::payer_note`]: crate::offers::invoice_request::InvoiceRequest::payer_note
	/// [`InvoiceRequestBuilder`]: crate::offers::invoice_request::InvoiceRequestBuilder
	/// [`Bolt12Invoice`]: crate::offers::invoice::Bolt12Invoice
	/// [`Bolt12Invoice::payment_paths`]: crate::offers::invoice::Bolt12Invoice::payment_paths
	/// [Avoiding Duplicate Payments]: #avoiding-duplicate-payments
	pub fn pay_for_offer(
		&self, offer: &Offer, quantity: Option<u64>, amount_msats: Option<u64>,
		payer_note: Option<String>, payment_id: PaymentId, retry_strategy: Retry,
		max_total_routing_fee_msat: Option<u64>
	) -> Result<(), Bolt12SemanticError> {
		let expanded_key = &self.inbound_payment_key;
		let entropy = &*self.entropy_source;
		let secp_ctx = &self.secp_ctx;

		let builder: InvoiceRequestBuilder<DerivedPayerId, secp256k1::All> = offer
			.request_invoice_deriving_payer_id(expanded_key, entropy, secp_ctx, payment_id)?
			.into();
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
		let invoice_request = builder.build_and_sign()?;
		let reply_path = self.create_blinded_path().map_err(|_| Bolt12SemanticError::MissingPaths)?;

		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(self);

		let expiration = StaleExpiration::TimerTicks(1);
		self.pending_outbound_payments
			.add_new_awaiting_invoice(
				payment_id, expiration, retry_strategy, max_total_routing_fee_msat
			)
			.map_err(|_| Bolt12SemanticError::DuplicatePaymentId)?;

		let mut pending_offers_messages = self.pending_offers_messages.lock().unwrap();
		if offer.paths().is_empty() {
			let message = new_pending_onion_message(
				OffersMessage::InvoiceRequest(invoice_request),
				Destination::Node(offer.signing_pubkey()),
				Some(reply_path),
			);
			pending_offers_messages.push(message);
		} else {
			// Send as many invoice requests as there are paths in the offer (with an upper bound).
			// Using only one path could result in a failure if the path no longer exists. But only
			// one invoice for a given payment id will be paid, even if more than one is received.
			const REQUEST_LIMIT: usize = 10;
			for path in offer.paths().into_iter().take(REQUEST_LIMIT) {
				let message = new_pending_onion_message(
					OffersMessage::InvoiceRequest(invoice_request.clone()),
					Destination::BlindedPath(path.clone()),
					Some(reply_path.clone()),
				);
				pending_offers_messages.push(message);
			}
		}

		Ok(())
	}

	/// Creates a [`Bolt12Invoice`] for a [`Refund`] and enqueues it to be sent via an onion
	/// message.
	///
	/// The resulting invoice uses a [`PaymentHash`] recognized by the [`ChannelManager`] and a
	/// [`BlindedPath`] containing the [`PaymentSecret`] needed to reconstruct the corresponding
	/// [`PaymentPreimage`].
	///
	/// # Limitations
	///
	/// Requires a direct connection to an introduction node in [`Refund::paths`] or to
	/// [`Refund::payer_id`], if empty. This request is best effort; an invoice will be sent to each
	/// node meeting the aforementioned criteria, but there's no guarantee that they will be
	/// received and no retries will be made.
	///
	/// # Errors
	///
	/// Errors if:
	/// - the refund is for an unsupported chain, or
	/// - the parameterized [`Router`] is unable to create a blinded payment path or reply path for
	///   the invoice.
	///
	/// [`Bolt12Invoice`]: crate::offers::invoice::Bolt12Invoice
	pub fn request_refund_payment(&self, refund: &Refund) -> Result<(), Bolt12SemanticError> {
		let expanded_key = &self.inbound_payment_key;
		let entropy = &*self.entropy_source;
		let secp_ctx = &self.secp_ctx;

		let amount_msats = refund.amount_msats();
		let relative_expiry = DEFAULT_RELATIVE_EXPIRY.as_secs() as u32;

		if refund.chain() != self.chain_hash {
			return Err(Bolt12SemanticError::UnsupportedChain);
		}

		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(self);

		match self.create_inbound_payment(Some(amount_msats), relative_expiry, None) {
			Ok((payment_hash, payment_secret)) => {
				let payment_paths = self.create_blinded_payment_paths(amount_msats, payment_secret)
					.map_err(|_| Bolt12SemanticError::MissingPaths)?;

				#[cfg(feature = "std")]
				let builder = refund.respond_using_derived_keys(
					payment_paths, payment_hash, expanded_key, entropy
				)?;
				#[cfg(not(feature = "std"))]
				let created_at = Duration::from_secs(
					self.highest_seen_timestamp.load(Ordering::Acquire) as u64
				);
				#[cfg(not(feature = "std"))]
				let builder = refund.respond_using_derived_keys_no_std(
					payment_paths, payment_hash, created_at, expanded_key, entropy
				)?;
				let builder: InvoiceBuilder<DerivedSigningPubkey> = builder.into();
				let invoice = builder.allow_mpp().build_and_sign(secp_ctx)?;
				let reply_path = self.create_blinded_path()
					.map_err(|_| Bolt12SemanticError::MissingPaths)?;

				let mut pending_offers_messages = self.pending_offers_messages.lock().unwrap();
				if refund.paths().is_empty() {
					let message = new_pending_onion_message(
						OffersMessage::Invoice(invoice),
						Destination::Node(refund.payer_id()),
						Some(reply_path),
					);
					pending_offers_messages.push(message);
				} else {
					for path in refund.paths() {
						let message = new_pending_onion_message(
							OffersMessage::Invoice(invoice.clone()),
							Destination::BlindedPath(path.clone()),
							Some(reply_path.clone()),
						);
						pending_offers_messages.push(message);
					}
				}

				Ok(())
			},
			Err(()) => Err(Bolt12SemanticError::InvalidAmount),
		}
	}

	/// Gets a payment secret and payment hash for use in an invoice given to a third party wishing
	/// to pay us.
	///
	/// This differs from [`create_inbound_payment_for_hash`] only in that it generates the
	/// [`PaymentHash`] and [`PaymentPreimage`] for you.
	///
	/// The [`PaymentPreimage`] will ultimately be returned to you in the [`PaymentClaimable`], which
	/// will have the [`PaymentClaimable::purpose`] be [`PaymentPurpose::InvoicePayment`] with
	/// its [`PaymentPurpose::InvoicePayment::payment_preimage`] field filled in. That should then be
	/// passed directly to [`claim_funds`].
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
	/// [`PaymentPurpose::InvoicePayment`]: events::PaymentPurpose::InvoicePayment
	/// [`PaymentPurpose::InvoicePayment::payment_preimage`]: events::PaymentPurpose::InvoicePayment::payment_preimage
	/// [`create_inbound_payment_for_hash`]: Self::create_inbound_payment_for_hash
	pub fn create_inbound_payment(&self, min_value_msat: Option<u64>, invoice_expiry_delta_secs: u32,
		min_final_cltv_expiry_delta: Option<u16>) -> Result<(PaymentHash, PaymentSecret), ()> {
		inbound_payment::create(&self.inbound_payment_key, min_value_msat, invoice_expiry_delta_secs,
			&self.entropy_source, self.highest_seen_timestamp.load(Ordering::Acquire) as u64,
			min_final_cltv_expiry_delta)
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
	pub fn create_inbound_payment_for_hash(&self, payment_hash: PaymentHash, min_value_msat: Option<u64>,
		invoice_expiry_delta_secs: u32, min_final_cltv_expiry: Option<u16>) -> Result<PaymentSecret, ()> {
		inbound_payment::create_from_hash(&self.inbound_payment_key, min_value_msat, payment_hash,
			invoice_expiry_delta_secs, self.highest_seen_timestamp.load(Ordering::Acquire) as u64,
			min_final_cltv_expiry)
	}

	/// Gets an LDK-generated payment preimage from a payment hash and payment secret that were
	/// previously returned from [`create_inbound_payment`].
	///
	/// [`create_inbound_payment`]: Self::create_inbound_payment
	pub fn get_payment_preimage(&self, payment_hash: PaymentHash, payment_secret: PaymentSecret) -> Result<PaymentPreimage, APIError> {
		inbound_payment::get_payment_preimage(payment_hash, payment_secret, &self.inbound_payment_key)
	}

	/// Creates a blinded path by delegating to [`MessageRouter::create_blinded_paths`].
	///
	/// Errors if the `MessageRouter` errors or returns an empty `Vec`.
	fn create_blinded_path(&self) -> Result<BlindedPath, ()> {
		let recipient = self.get_our_node_id();
		let secp_ctx = &self.secp_ctx;

		let peers = self.per_peer_state.read().unwrap()
			.iter()
			.filter(|(_, peer)| peer.lock().unwrap().latest_features.supports_onion_messages())
			.map(|(node_id, _)| *node_id)
			.collect::<Vec<_>>();

		self.router
			.create_blinded_paths(recipient, peers, secp_ctx)
			.and_then(|paths| paths.into_iter().next().ok_or(()))
	}

	/// Creates multi-hop blinded payment paths for the given `amount_msats` by delegating to
	/// [`Router::create_blinded_payment_paths`].
	fn create_blinded_payment_paths(
		&self, amount_msats: u64, payment_secret: PaymentSecret
	) -> Result<Vec<(BlindedPayInfo, BlindedPath)>, ()> {
		let secp_ctx = &self.secp_ctx;

		let first_hops = self.list_usable_channels();
		let payee_node_id = self.get_our_node_id();
		let max_cltv_expiry = self.best_block.read().unwrap().height + CLTV_FAR_FAR_AWAY
			+ LATENCY_GRACE_PERIOD_BLOCKS;
		let payee_tlvs = ReceiveTlvs {
			payment_secret,
			payment_constraints: PaymentConstraints {
				max_cltv_expiry,
				htlc_minimum_msat: 1,
			},
		};
		self.router.create_blinded_payment_paths(
			payee_node_id, first_hops, payee_tlvs, amount_msats, secp_ctx
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
			let scid_candidate = fake_scid::Namespace::Phantom.get_fake_scid(best_block_height, &self.chain_hash, &self.fake_scid_rand_bytes, &self.entropy_source);
			// Ensure the generated scid doesn't conflict with a real channel.
			match short_to_chan_info.get(&scid_candidate) {
				Some(_) => continue,
				None => return scid_candidate
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
			let scid_candidate = fake_scid::Namespace::Intercept.get_fake_scid(best_block_height, &self.chain_hash, &self.fake_scid_rand_bytes, &self.entropy_source);
			// Ensure the generated scid doesn't conflict with a real channel.
			if short_to_chan_info.contains_key(&scid_candidate) { continue }
			return scid_candidate
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
			for chan in peer_state.channel_by_id.values().filter_map(
				|phase| if let ChannelPhase::Funded(chan) = phase { Some(chan) } else { None }
			) {
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
		let event_handler = |event: events::Event| events.borrow_mut().push(event);
		self.process_pending_events(&event_handler);
		events.into_inner()
	}

	#[cfg(feature = "_test_utils")]
	pub fn push_pending_event(&self, event: events::Event) {
		let mut events = self.pending_events.lock().unwrap();
		events.push_back((event, None));
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

	/// When something which was blocking a channel from updating its [`ChannelMonitor`] (e.g. an
	/// [`Event`] being handled) completes, this should be called to restore the channel to normal
	/// operation. It will double-check that nothing *else* is also blocking the same channel from
	/// making progress and then let any blocked [`ChannelMonitorUpdate`]s fly.
	fn handle_monitor_update_release(&self, counterparty_node_id: PublicKey,
		channel_funding_outpoint: OutPoint, channel_id: ChannelId,
		mut completed_blocker: Option<RAAMonitorUpdateBlockingAction>) {

		let logger = WithContext::from(
			&self.logger, Some(counterparty_node_id), Some(channel_id),
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
					channel_funding_outpoint, channel_id, counterparty_node_id) {
					// Check that, while holding the peer lock, we don't have anything else
					// blocking monitor updates for this channel. If we do, release the monitor
					// update(s) when those blockers complete.
					log_trace!(logger, "Delaying monitor unlock for channel {} as another channel's mon update needs to complete first",
						&channel_id);
					break;
				}

				if let hash_map::Entry::Occupied(mut chan_phase_entry) = peer_state.channel_by_id.entry(
					channel_id) {
					if let ChannelPhase::Funded(chan) = chan_phase_entry.get_mut() {
						debug_assert_eq!(chan.context.get_funding_txo().unwrap(), channel_funding_outpoint);
						if let Some((monitor_update, further_update_exists)) = chan.unblock_next_blocked_monitor_update() {
							log_debug!(logger, "Unlocking monitor updating for channel {} and updating monitor",
								channel_id);
							handle_new_monitor_update!(self, channel_funding_outpoint, monitor_update,
								peer_state_lck, peer_state, per_peer_state, chan);
							if further_update_exists {
								// If there are more `ChannelMonitorUpdate`s to process, restart at the
								// top of the loop.
								continue;
							}
						} else {
							log_trace!(logger, "Unlocked monitor updating for channel {} without monitors to update",
								channel_id);
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

	fn handle_post_event_actions(&self, actions: Vec<EventCompletionAction>) {
		for action in actions {
			match action {
				EventCompletionAction::ReleaseRAAChannelMonitorUpdate {
					channel_funding_outpoint, channel_id, counterparty_node_id
				} => {
					self.handle_monitor_update_release(counterparty_node_id, channel_funding_outpoint, channel_id, None);
				}
			}
		}
	}

	/// Processes any events asynchronously in the order they were generated since the last call
	/// using the given event handler.
	///
	/// See the trait-level documentation of [`EventsProvider`] for requirements.
	pub async fn process_pending_events_async<Future: core::future::Future, H: Fn(Event) -> Future>(
		&self, handler: H
	) {
		let mut ev;
		process_events_body!(self, ev, { handler(ev).await });
	}
}

impl<M: Deref, T: Deref, ES: Deref, NS: Deref, SP: Deref, F: Deref, R: Deref, L: Deref> MessageSendEventsProvider for ChannelManager<M, T, ES, NS, SP, F, R, L>
where
	M::Target: chain::Watch<<SP::Target as SignerProvider>::EcdsaSigner>,
	T::Target: BroadcasterInterface,
	ES::Target: EntropySource,
	NS::Target: NodeSigner,
	SP::Target: SignerProvider,
	F::Target: FeeEstimator,
	R::Target: Router,
	L::Target: Logger,
{
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

			// TODO: This behavior should be documented. It's unintuitive that we query
			// ChannelMonitors when clearing other events.
			if self.process_pending_monitor_events() {
				result = NotifyOption::DoPersist;
			}

			if self.check_free_holding_cells() {
				result = NotifyOption::DoPersist;
			}
			if self.maybe_generate_initial_closing_signed() {
				result = NotifyOption::DoPersist;
			}

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

impl<M: Deref, T: Deref, ES: Deref, NS: Deref, SP: Deref, F: Deref, R: Deref, L: Deref> EventsProvider for ChannelManager<M, T, ES, NS, SP, F, R, L>
where
	M::Target: chain::Watch<<SP::Target as SignerProvider>::EcdsaSigner>,
	T::Target: BroadcasterInterface,
	ES::Target: EntropySource,
	NS::Target: NodeSigner,
	SP::Target: SignerProvider,
	F::Target: FeeEstimator,
	R::Target: Router,
	L::Target: Logger,
{
	/// Processes events that must be periodically handled.
	///
	/// An [`EventHandler`] may safely call back to the provider in order to handle an event.
	/// However, it must not call [`Writeable::write`] as doing so would result in a deadlock.
	fn process_pending_events<H: Deref>(&self, handler: H) where H::Target: EventHandler {
		let mut ev;
		process_events_body!(self, ev, handler.handle_event(ev));
	}
}

impl<M: Deref, T: Deref, ES: Deref, NS: Deref, SP: Deref, F: Deref, R: Deref, L: Deref> chain::Listen for ChannelManager<M, T, ES, NS, SP, F, R, L>
where
	M::Target: chain::Watch<<SP::Target as SignerProvider>::EcdsaSigner>,
	T::Target: BroadcasterInterface,
	ES::Target: EntropySource,
	NS::Target: NodeSigner,
	SP::Target: SignerProvider,
	F::Target: FeeEstimator,
	R::Target: Router,
	L::Target: Logger,
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

	fn block_disconnected(&self, header: &Header, height: u32) {
		let _persistence_guard =
			PersistenceNotifierGuard::optionally_notify_skipping_background_events(
				self, || -> NotifyOption { NotifyOption::DoPersist });
		let new_height = height - 1;
		{
			let mut best_block = self.best_block.write().unwrap();
			assert_eq!(best_block.block_hash, header.block_hash(),
				"Blocks must be disconnected in chain-order - the disconnected header must be the last connected header");
			assert_eq!(best_block.height, height,
				"Blocks must be disconnected in chain-order - the disconnected block must have the correct height");
			*best_block = BestBlock::new(header.prev_blockhash, new_height)
		}

		self.do_chain_event(Some(new_height), |channel| channel.best_block_updated(new_height, header.time, self.chain_hash, &self.node_signer, &self.default_configuration, &&WithChannelContext::from(&self.logger, &channel.context)));
	}
}

impl<M: Deref, T: Deref, ES: Deref, NS: Deref, SP: Deref, F: Deref, R: Deref, L: Deref> chain::Confirm for ChannelManager<M, T, ES, NS, SP, F, R, L>
where
	M::Target: chain::Watch<<SP::Target as SignerProvider>::EcdsaSigner>,
	T::Target: BroadcasterInterface,
	ES::Target: EntropySource,
	NS::Target: NodeSigner,
	SP::Target: SignerProvider,
	F::Target: FeeEstimator,
	R::Target: Router,
	L::Target: Logger,
{
	fn transactions_confirmed(&self, header: &Header, txdata: &TransactionData, height: u32) {
		// Note that we MUST NOT end up calling methods on self.chain_monitor here - we're called
		// during initialization prior to the chain_monitor being fully configured in some cases.
		// See the docs for `ChannelManagerReadArgs` for more.

		let block_hash = header.block_hash();
		log_trace!(self.logger, "{} transactions included in block {} at height {} provided", txdata.len(), block_hash, height);

		let _persistence_guard =
			PersistenceNotifierGuard::optionally_notify_skipping_background_events(
				self, || -> NotifyOption { NotifyOption::DoPersist });
		self.do_chain_event(Some(height), |channel| channel.transactions_confirmed(&block_hash, height, txdata, self.chain_hash, &self.node_signer, &self.default_configuration, &&WithChannelContext::from(&self.logger, &channel.context))
			.map(|(a, b)| (a, Vec::new(), b)));

		let last_best_block_height = self.best_block.read().unwrap().height;
		if height < last_best_block_height {
			let timestamp = self.highest_seen_timestamp.load(Ordering::Acquire);
			self.do_chain_event(Some(last_best_block_height), |channel| channel.best_block_updated(last_best_block_height, timestamp as u32, self.chain_hash, &self.node_signer, &self.default_configuration, &&WithChannelContext::from(&self.logger, &channel.context)));
		}
	}

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

		self.do_chain_event(Some(height), |channel| channel.best_block_updated(height, header.time, self.chain_hash, &self.node_signer, &self.default_configuration, &&WithChannelContext::from(&self.logger, &channel.context)));

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
		let mut payment_secrets = self.pending_inbound_payments.lock().unwrap();
		payment_secrets.retain(|_, inbound_payment| {
			inbound_payment.expiry_time > header.time as u64
		});
	}

	fn get_relevant_txids(&self) -> Vec<(Txid, u32, Option<BlockHash>)> {
		let mut res = Vec::with_capacity(self.short_to_chan_info.read().unwrap().len());
		for (_cp_id, peer_state_mutex) in self.per_peer_state.read().unwrap().iter() {
			let mut peer_state_lock = peer_state_mutex.lock().unwrap();
			let peer_state = &mut *peer_state_lock;
			for chan in peer_state.channel_by_id.values().filter_map(|phase| if let ChannelPhase::Funded(chan) = phase { Some(chan) } else { None }) {
				let txid_opt = chan.context.get_funding_txo();
				let height_opt = chan.context.get_funding_tx_confirmation_height();
				let hash_opt = chan.context.get_funding_tx_confirmed_in();
				if let (Some(funding_txo), Some(conf_height), Some(block_hash)) = (txid_opt, height_opt, hash_opt) {
					res.push((funding_txo.txid, conf_height, Some(block_hash)));
				}
			}
		}
		res
	}

	fn transaction_unconfirmed(&self, txid: &Txid) {
		let _persistence_guard =
			PersistenceNotifierGuard::optionally_notify_skipping_background_events(
				self, || -> NotifyOption { NotifyOption::DoPersist });
		self.do_chain_event(None, |channel| {
			if let Some(funding_txo) = channel.context.get_funding_txo() {
				if funding_txo.txid == *txid {
					channel.funding_transaction_unconfirmed(&&WithChannelContext::from(&self.logger, &channel.context)).map(|()| (None, Vec::new(), None))
				} else { Ok((None, Vec::new(), None)) }
			} else { Ok((None, Vec::new(), None)) }
		});
	}
}

impl<M: Deref, T: Deref, ES: Deref, NS: Deref, SP: Deref, F: Deref, R: Deref, L: Deref> ChannelManager<M, T, ES, NS, SP, F, R, L>
where
	M::Target: chain::Watch<<SP::Target as SignerProvider>::EcdsaSigner>,
	T::Target: BroadcasterInterface,
	ES::Target: EntropySource,
	NS::Target: NodeSigner,
	SP::Target: SignerProvider,
	F::Target: FeeEstimator,
	R::Target: Router,
	L::Target: Logger,
{
	/// Calls a function which handles an on-chain event (blocks dis/connected, transactions
	/// un/confirmed, etc) on each channel, handling any resulting errors or messages generated by
	/// the function.
	fn do_chain_event<FN: Fn(&mut Channel<SP>) -> Result<(Option<msgs::ChannelReady>, Vec<(HTLCSource, PaymentHash)>, Option<msgs::AnnouncementSignatures>), ClosureReason>>
			(&self, height_opt: Option<u32>, f: FN) {
		// Note that we MUST NOT end up calling methods on self.chain_monitor here - we're called
		// during initialization prior to the chain_monitor being fully configured in some cases.
		// See the docs for `ChannelManagerReadArgs` for more.

		let mut failed_channels = Vec::new();
		let mut timed_out_htlcs = Vec::new();
		{
			let per_peer_state = self.per_peer_state.read().unwrap();
			for (_cp_id, peer_state_mutex) in per_peer_state.iter() {
				let mut peer_state_lock = peer_state_mutex.lock().unwrap();
				let peer_state = &mut *peer_state_lock;
				let pending_msg_events = &mut peer_state.pending_msg_events;

				peer_state.channel_by_id.retain(|_, phase| {
					match phase {
						// Retain unfunded channels.
						ChannelPhase::UnfundedOutboundV1(_) | ChannelPhase::UnfundedInboundV1(_) => true,
						// TODO(dual_funding): Combine this match arm with above.
						#[cfg(dual_funding)]
						ChannelPhase::UnfundedOutboundV2(_) | ChannelPhase::UnfundedInboundV2(_) => true,
						ChannelPhase::Funded(channel) => {
							let res = f(channel);
							if let Ok((channel_ready_opt, mut timed_out_pending_htlcs, announcement_sigs)) = res {
								for (source, payment_hash) in timed_out_pending_htlcs.drain(..) {
									let (failure_code, data) = self.get_htlc_inbound_temp_fail_err_and_data(0x1000|14 /* expiry_too_soon */, &channel);
									timed_out_htlcs.push((source, payment_hash, HTLCFailReason::reason(failure_code, data),
										HTLCDestination::NextHopChannel { node_id: Some(channel.context.get_counterparty_node_id()), channel_id: channel.context.channel_id() }));
								}
								let logger = WithChannelContext::from(&self.logger, &channel.context);
								if let Some(channel_ready) = channel_ready_opt {
									send_channel_ready!(self, pending_msg_events, channel, channel_ready);
									if channel.context.is_usable() {
										log_trace!(logger, "Sending channel_ready with private initial channel_update for our counterparty on channel {}", channel.context.channel_id());
										if let Ok(msg) = self.get_channel_update_for_unicast(channel) {
											pending_msg_events.push(events::MessageSendEvent::SendChannelUpdate {
												node_id: channel.context.get_counterparty_node_id(),
												msg,
											});
										}
									} else {
										log_trace!(logger, "Sending channel_ready WITHOUT channel_update for {}", channel.context.channel_id());
									}
								}

								{
									let mut pending_events = self.pending_events.lock().unwrap();
									emit_channel_ready_event!(pending_events, channel);
								}

								if let Some(announcement_sigs) = announcement_sigs {
									log_trace!(logger, "Sending announcement_signatures for channel {}", channel.context.channel_id());
									pending_msg_events.push(events::MessageSendEvent::SendAnnouncementSignatures {
										node_id: channel.context.get_counterparty_node_id(),
										msg: announcement_sigs,
									});
									if let Some(height) = height_opt {
										if let Some(announcement) = channel.get_signed_channel_announcement(&self.node_signer, self.chain_hash, height, &self.default_configuration) {
											pending_msg_events.push(events::MessageSendEvent::BroadcastChannelAnnouncement {
												msg: announcement,
												// Note that announcement_signatures fails if the channel cannot be announced,
												// so get_channel_update_for_broadcast will never fail by the time we get here.
												update_msg: Some(self.get_channel_update_for_broadcast(channel).unwrap()),
											});
										}
									}
								}
								if channel.is_our_channel_ready() {
									if let Some(real_scid) = channel.context.get_short_channel_id() {
										// If we sent a 0conf channel_ready, and now have an SCID, we add it
										// to the short_to_chan_info map here. Note that we check whether we
										// can relay using the real SCID at relay-time (i.e.
										// enforce option_scid_alias then), and if the funding tx is ever
										// un-confirmed we force-close the channel, ensuring short_to_chan_info
										// is always consistent.
										let mut short_to_chan_info = self.short_to_chan_info.write().unwrap();
										let scid_insert = short_to_chan_info.insert(real_scid, (channel.context.get_counterparty_node_id(), channel.context.channel_id()));
										assert!(scid_insert.is_none() || scid_insert.unwrap() == (channel.context.get_counterparty_node_id(), channel.context.channel_id()),
											"SCIDs should never collide - ensure you weren't behind by a full {} blocks when creating channels",
											fake_scid::MAX_SCID_BLOCKS_FROM_NOW);
									}
								}
							} else if let Err(reason) = res {
								update_maps_on_chan_removal!(self, &channel.context);
								// It looks like our counterparty went on-chain or funding transaction was
								// reorged out of the main chain. Close the channel.
								let reason_message = format!("{}", reason);
								failed_channels.push(channel.context.force_shutdown(true, reason));
								if let Ok(update) = self.get_channel_update_for_broadcast(&channel) {
									let mut pending_broadcast_messages = self.pending_broadcast_messages.lock().unwrap();
									pending_broadcast_messages.push(events::MessageSendEvent::BroadcastChannelUpdate {
										msg: update
									});
								}
								pending_msg_events.push(events::MessageSendEvent::HandleError {
									node_id: channel.context.get_counterparty_node_id(),
									action: msgs::ErrorAction::DisconnectPeer {
										msg: Some(msgs::ErrorMessage {
											channel_id: channel.context.channel_id(),
											data: reason_message,
										})
									},
								});
								return false;
							}
							true
						}
					}
				});
			}
		}

		if let Some(height) = height_opt {
			self.claimable_payments.lock().unwrap().claimable_payments.retain(|payment_hash, payment| {
				payment.htlcs.retain(|htlc| {
					// If height is approaching the number of blocks we think it takes us to get
					// our commitment transaction confirmed before the HTLC expires, plus the
					// number of blocks we generally consider it to take to do a commitment update,
					// just give up on it and fail the HTLC.
					if height >= htlc.cltv_expiry - HTLC_FAIL_BACK_BUFFER {
						let mut htlc_msat_height_data = htlc.value.to_be_bytes().to_vec();
						htlc_msat_height_data.extend_from_slice(&height.to_be_bytes());

						timed_out_htlcs.push((HTLCSource::PreviousHopData(htlc.prev_hop.clone()), payment_hash.clone(),
							HTLCFailReason::reason(0x4000 | 15, htlc_msat_height_data),
							HTLCDestination::FailedPayment { payment_hash: payment_hash.clone() }));
						false
					} else { true }
				});
				!payment.htlcs.is_empty() // Only retain this entry if htlcs has at least one entry.
			});

			let mut intercepted_htlcs = self.pending_intercepted_htlcs.lock().unwrap();
			intercepted_htlcs.retain(|_, htlc| {
				if height >= htlc.forward_info.outgoing_cltv_value - HTLC_FAIL_BACK_BUFFER {
					let prev_hop_data = HTLCSource::PreviousHopData(HTLCPreviousHopData {
						short_channel_id: htlc.prev_short_channel_id,
						user_channel_id: Some(htlc.prev_user_channel_id),
						htlc_id: htlc.prev_htlc_id,
						incoming_packet_shared_secret: htlc.forward_info.incoming_shared_secret,
						phantom_shared_secret: None,
						outpoint: htlc.prev_funding_outpoint,
						channel_id: htlc.prev_channel_id,
						blinded_failure: htlc.forward_info.routing.blinded_failure(),
					});

					let requested_forward_scid /* intercept scid */ = match htlc.forward_info.routing {
						PendingHTLCRouting::Forward { short_channel_id, .. } => short_channel_id,
						_ => unreachable!(),
					};
					timed_out_htlcs.push((prev_hop_data, htlc.forward_info.payment_hash,
							HTLCFailReason::from_failure_code(0x2000 | 2),
							HTLCDestination::InvalidForward { requested_forward_scid }));
					let logger = WithContext::from(
						&self.logger, None, Some(htlc.prev_channel_id)
					);
					log_trace!(logger, "Timing out intercepted HTLC with requested forward scid {}", requested_forward_scid);
					false
				} else { true }
			});
		}

		self.handle_init_event_channel_failures(failed_channels);

		for (source, payment_hash, reason, destination) in timed_out_htlcs.drain(..) {
			self.fail_htlc_backwards_internal(&source, &payment_hash, &reason, destination);
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
		provided_node_features(&self.default_configuration)
	}

	/// Fetches the set of [`Bolt11InvoiceFeatures`] flags that are provided by or required by
	/// [`ChannelManager`].
	///
	/// Note that the invoice feature flags can vary depending on if the invoice is a "phantom invoice"
	/// or not. Thus, this method is not public.
	#[cfg(any(feature = "_test_utils", test))]
	pub fn bolt11_invoice_features(&self) -> Bolt11InvoiceFeatures {
		provided_bolt11_invoice_features(&self.default_configuration)
	}

	/// Fetches the set of [`Bolt12InvoiceFeatures`] flags that are provided by or required by
	/// [`ChannelManager`].
	fn bolt12_invoice_features(&self) -> Bolt12InvoiceFeatures {
		provided_bolt12_invoice_features(&self.default_configuration)
	}

	/// Fetches the set of [`ChannelFeatures`] flags that are provided by or required by
	/// [`ChannelManager`].
	pub fn channel_features(&self) -> ChannelFeatures {
		provided_channel_features(&self.default_configuration)
	}

	/// Fetches the set of [`ChannelTypeFeatures`] flags that are provided by or required by
	/// [`ChannelManager`].
	pub fn channel_type_features(&self) -> ChannelTypeFeatures {
		provided_channel_type_features(&self.default_configuration)
	}

	/// Fetches the set of [`InitFeatures`] flags that are provided by or required by
	/// [`ChannelManager`].
	pub fn init_features(&self) -> InitFeatures {
		provided_init_features(&self.default_configuration)
	}
}

impl<M: Deref, T: Deref, ES: Deref, NS: Deref, SP: Deref, F: Deref, R: Deref, L: Deref>
	ChannelMessageHandler for ChannelManager<M, T, ES, NS, SP, F, R, L>
where
	M::Target: chain::Watch<<SP::Target as SignerProvider>::EcdsaSigner>,
	T::Target: BroadcasterInterface,
	ES::Target: EntropySource,
	NS::Target: NodeSigner,
	SP::Target: SignerProvider,
	F::Target: FeeEstimator,
	R::Target: Router,
	L::Target: Logger,
{
	fn handle_open_channel(&self, counterparty_node_id: &PublicKey, msg: &msgs::OpenChannel) {
		// Note that we never need to persist the updated ChannelManager for an inbound
		// open_channel message - pre-funded channels are never written so there should be no
		// change to the contents.
		let _persistence_guard = PersistenceNotifierGuard::optionally_notify(self, || {
			let res = self.internal_open_channel(counterparty_node_id, msg);
			let persist = match &res {
				Err(e) if e.closes_channel() => {
					debug_assert!(false, "We shouldn't close a new channel");
					NotifyOption::DoPersist
				},
				_ => NotifyOption::SkipPersistHandleEvents,
			};
			let _ = handle_error!(self, res, *counterparty_node_id);
			persist
		});
	}

	fn handle_open_channel_v2(&self, counterparty_node_id: &PublicKey, msg: &msgs::OpenChannelV2) {
		let _: Result<(), _> = handle_error!(self, Err(MsgHandleErrInternal::send_err_msg_no_close(
			"Dual-funded channels not supported".to_owned(),
			 msg.common_fields.temporary_channel_id.clone())), *counterparty_node_id);
	}

	fn handle_accept_channel(&self, counterparty_node_id: &PublicKey, msg: &msgs::AcceptChannel) {
		// Note that we never need to persist the updated ChannelManager for an inbound
		// accept_channel message - pre-funded channels are never written so there should be no
		// change to the contents.
		let _persistence_guard = PersistenceNotifierGuard::optionally_notify(self, || {
			let _ = handle_error!(self, self.internal_accept_channel(counterparty_node_id, msg), *counterparty_node_id);
			NotifyOption::SkipPersistHandleEvents
		});
	}

	fn handle_accept_channel_v2(&self, counterparty_node_id: &PublicKey, msg: &msgs::AcceptChannelV2) {
		let _: Result<(), _> = handle_error!(self, Err(MsgHandleErrInternal::send_err_msg_no_close(
			"Dual-funded channels not supported".to_owned(),
			 msg.common_fields.temporary_channel_id.clone())), *counterparty_node_id);
	}

	fn handle_funding_created(&self, counterparty_node_id: &PublicKey, msg: &msgs::FundingCreated) {
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(self);
		let _ = handle_error!(self, self.internal_funding_created(counterparty_node_id, msg), *counterparty_node_id);
	}

	fn handle_funding_signed(&self, counterparty_node_id: &PublicKey, msg: &msgs::FundingSigned) {
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(self);
		let _ = handle_error!(self, self.internal_funding_signed(counterparty_node_id, msg), *counterparty_node_id);
	}

	fn handle_channel_ready(&self, counterparty_node_id: &PublicKey, msg: &msgs::ChannelReady) {
		// Note that we never need to persist the updated ChannelManager for an inbound
		// channel_ready message - while the channel's state will change, any channel_ready message
		// will ultimately be re-sent on startup and the `ChannelMonitor` won't be updated so we
		// will not force-close the channel on startup.
		let _persistence_guard = PersistenceNotifierGuard::optionally_notify(self, || {
			let res = self.internal_channel_ready(counterparty_node_id, msg);
			let persist = match &res {
				Err(e) if e.closes_channel() => NotifyOption::DoPersist,
				_ => NotifyOption::SkipPersistHandleEvents,
			};
			let _ = handle_error!(self, res, *counterparty_node_id);
			persist
		});
	}

	fn handle_stfu(&self, counterparty_node_id: &PublicKey, msg: &msgs::Stfu) {
		let _: Result<(), _> = handle_error!(self, Err(MsgHandleErrInternal::send_err_msg_no_close(
			"Quiescence not supported".to_owned(),
			 msg.channel_id.clone())), *counterparty_node_id);
	}

	fn handle_splice(&self, counterparty_node_id: &PublicKey, msg: &msgs::Splice) {
		let _: Result<(), _> = handle_error!(self, Err(MsgHandleErrInternal::send_err_msg_no_close(
			"Splicing not supported".to_owned(),
			 msg.channel_id.clone())), *counterparty_node_id);
	}

	fn handle_splice_ack(&self, counterparty_node_id: &PublicKey, msg: &msgs::SpliceAck) {
		let _: Result<(), _> = handle_error!(self, Err(MsgHandleErrInternal::send_err_msg_no_close(
			"Splicing not supported (splice_ack)".to_owned(),
			 msg.channel_id.clone())), *counterparty_node_id);
	}

	fn handle_splice_locked(&self, counterparty_node_id: &PublicKey, msg: &msgs::SpliceLocked) {
		let _: Result<(), _> = handle_error!(self, Err(MsgHandleErrInternal::send_err_msg_no_close(
			"Splicing not supported (splice_locked)".to_owned(),
			 msg.channel_id.clone())), *counterparty_node_id);
	}

	fn handle_shutdown(&self, counterparty_node_id: &PublicKey, msg: &msgs::Shutdown) {
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(self);
		let _ = handle_error!(self, self.internal_shutdown(counterparty_node_id, msg), *counterparty_node_id);
	}

	fn handle_closing_signed(&self, counterparty_node_id: &PublicKey, msg: &msgs::ClosingSigned) {
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(self);
		let _ = handle_error!(self, self.internal_closing_signed(counterparty_node_id, msg), *counterparty_node_id);
	}

	fn handle_update_add_htlc(&self, counterparty_node_id: &PublicKey, msg: &msgs::UpdateAddHTLC) {
		// Note that we never need to persist the updated ChannelManager for an inbound
		// update_add_htlc message - the message itself doesn't change our channel state only the
		// `commitment_signed` message afterwards will.
		let _persistence_guard = PersistenceNotifierGuard::optionally_notify(self, || {
			let res = self.internal_update_add_htlc(counterparty_node_id, msg);
			let persist = match &res {
				Err(e) if e.closes_channel() => NotifyOption::DoPersist,
				Err(_) => NotifyOption::SkipPersistHandleEvents,
				Ok(()) => NotifyOption::SkipPersistNoEvents,
			};
			let _ = handle_error!(self, res, *counterparty_node_id);
			persist
		});
	}

	fn handle_update_fulfill_htlc(&self, counterparty_node_id: &PublicKey, msg: &msgs::UpdateFulfillHTLC) {
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(self);
		let _ = handle_error!(self, self.internal_update_fulfill_htlc(counterparty_node_id, msg), *counterparty_node_id);
	}

	fn handle_update_fail_htlc(&self, counterparty_node_id: &PublicKey, msg: &msgs::UpdateFailHTLC) {
		// Note that we never need to persist the updated ChannelManager for an inbound
		// update_fail_htlc message - the message itself doesn't change our channel state only the
		// `commitment_signed` message afterwards will.
		let _persistence_guard = PersistenceNotifierGuard::optionally_notify(self, || {
			let res = self.internal_update_fail_htlc(counterparty_node_id, msg);
			let persist = match &res {
				Err(e) if e.closes_channel() => NotifyOption::DoPersist,
				Err(_) => NotifyOption::SkipPersistHandleEvents,
				Ok(()) => NotifyOption::SkipPersistNoEvents,
			};
			let _ = handle_error!(self, res, *counterparty_node_id);
			persist
		});
	}

	fn handle_update_fail_malformed_htlc(&self, counterparty_node_id: &PublicKey, msg: &msgs::UpdateFailMalformedHTLC) {
		// Note that we never need to persist the updated ChannelManager for an inbound
		// update_fail_malformed_htlc message - the message itself doesn't change our channel state
		// only the `commitment_signed` message afterwards will.
		let _persistence_guard = PersistenceNotifierGuard::optionally_notify(self, || {
			let res = self.internal_update_fail_malformed_htlc(counterparty_node_id, msg);
			let persist = match &res {
				Err(e) if e.closes_channel() => NotifyOption::DoPersist,
				Err(_) => NotifyOption::SkipPersistHandleEvents,
				Ok(()) => NotifyOption::SkipPersistNoEvents,
			};
			let _ = handle_error!(self, res, *counterparty_node_id);
			persist
		});
	}

	fn handle_commitment_signed(&self, counterparty_node_id: &PublicKey, msg: &msgs::CommitmentSigned) {
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(self);
		let _ = handle_error!(self, self.internal_commitment_signed(counterparty_node_id, msg), *counterparty_node_id);
	}

	fn handle_revoke_and_ack(&self, counterparty_node_id: &PublicKey, msg: &msgs::RevokeAndACK) {
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(self);
		let _ = handle_error!(self, self.internal_revoke_and_ack(counterparty_node_id, msg), *counterparty_node_id);
	}

	fn handle_update_fee(&self, counterparty_node_id: &PublicKey, msg: &msgs::UpdateFee) {
		// Note that we never need to persist the updated ChannelManager for an inbound
		// update_fee message - the message itself doesn't change our channel state only the
		// `commitment_signed` message afterwards will.
		let _persistence_guard = PersistenceNotifierGuard::optionally_notify(self, || {
			let res = self.internal_update_fee(counterparty_node_id, msg);
			let persist = match &res {
				Err(e) if e.closes_channel() => NotifyOption::DoPersist,
				Err(_) => NotifyOption::SkipPersistHandleEvents,
				Ok(()) => NotifyOption::SkipPersistNoEvents,
			};
			let _ = handle_error!(self, res, *counterparty_node_id);
			persist
		});
	}

	fn handle_announcement_signatures(&self, counterparty_node_id: &PublicKey, msg: &msgs::AnnouncementSignatures) {
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(self);
		let _ = handle_error!(self, self.internal_announcement_signatures(counterparty_node_id, msg), *counterparty_node_id);
	}

	fn handle_channel_update(&self, counterparty_node_id: &PublicKey, msg: &msgs::ChannelUpdate) {
		PersistenceNotifierGuard::optionally_notify(self, || {
			if let Ok(persist) = handle_error!(self, self.internal_channel_update(counterparty_node_id, msg), *counterparty_node_id) {
				persist
			} else {
				NotifyOption::DoPersist
			}
		});
	}

	fn handle_channel_reestablish(&self, counterparty_node_id: &PublicKey, msg: &msgs::ChannelReestablish) {
		let _persistence_guard = PersistenceNotifierGuard::optionally_notify(self, || {
			let res = self.internal_channel_reestablish(counterparty_node_id, msg);
			let persist = match &res {
				Err(e) if e.closes_channel() => NotifyOption::DoPersist,
				Err(_) => NotifyOption::SkipPersistHandleEvents,
				Ok(persist) => *persist,
			};
			let _ = handle_error!(self, res, *counterparty_node_id);
			persist
		});
	}

	fn peer_disconnected(&self, counterparty_node_id: &PublicKey) {
		let _persistence_guard = PersistenceNotifierGuard::optionally_notify(
			self, || NotifyOption::SkipPersistHandleEvents);
		let mut failed_channels = Vec::new();
		let mut per_peer_state = self.per_peer_state.write().unwrap();
		let remove_peer = {
			log_debug!(
				WithContext::from(&self.logger, Some(*counterparty_node_id), None),
				"Marking channels with {} disconnected and generating channel_updates.",
				log_pubkey!(counterparty_node_id)
			);
			if let Some(peer_state_mutex) = per_peer_state.get(counterparty_node_id) {
				let mut peer_state_lock = peer_state_mutex.lock().unwrap();
				let peer_state = &mut *peer_state_lock;
				let pending_msg_events = &mut peer_state.pending_msg_events;
				peer_state.channel_by_id.retain(|_, phase| {
					let context = match phase {
						ChannelPhase::Funded(chan) => {
							let logger = WithChannelContext::from(&self.logger, &chan.context);
							if chan.remove_uncommitted_htlcs_and_mark_paused(&&logger).is_ok() {
								// We only retain funded channels that are not shutdown.
								return true;
							}
							&mut chan.context
						},
						// We retain UnfundedOutboundV1 channel for some time in case
						// peer unexpectedly disconnects, and intends to reconnect again.
						ChannelPhase::UnfundedOutboundV1(_) => {
							return true;
						},
						// Unfunded inbound channels will always be removed.
						ChannelPhase::UnfundedInboundV1(chan) => {
							&mut chan.context
						},
						#[cfg(dual_funding)]
						ChannelPhase::UnfundedOutboundV2(chan) => {
							&mut chan.context
						},
						#[cfg(dual_funding)]
						ChannelPhase::UnfundedInboundV2(chan) => {
							&mut chan.context
						},
					};
					// Clean up for removal.
					update_maps_on_chan_removal!(self, &context);
					failed_channels.push(context.force_shutdown(false, ClosureReason::DisconnectedPeer));
					false
				});
				// Note that we don't bother generating any events for pre-accept channels -
				// they're not considered "channels" yet from the PoV of our events interface.
				peer_state.inbound_channel_request_by_id.clear();
				pending_msg_events.retain(|msg| {
					match msg {
						// V1 Channel Establishment
						&events::MessageSendEvent::SendAcceptChannel { .. } => false,
						&events::MessageSendEvent::SendOpenChannel { .. } => false,
						&events::MessageSendEvent::SendFundingCreated { .. } => false,
						&events::MessageSendEvent::SendFundingSigned { .. } => false,
						// V2 Channel Establishment
						&events::MessageSendEvent::SendAcceptChannelV2 { .. } => false,
						&events::MessageSendEvent::SendOpenChannelV2 { .. } => false,
						// Common Channel Establishment
						&events::MessageSendEvent::SendChannelReady { .. } => false,
						&events::MessageSendEvent::SendAnnouncementSignatures { .. } => false,
						// Quiescence
						&events::MessageSendEvent::SendStfu { .. } => false,
						// Splicing
						&events::MessageSendEvent::SendSplice { .. } => false,
						&events::MessageSendEvent::SendSpliceAck { .. } => false,
						&events::MessageSendEvent::SendSpliceLocked { .. } => false,
						// Interactive Transaction Construction
						&events::MessageSendEvent::SendTxAddInput { .. } => false,
						&events::MessageSendEvent::SendTxAddOutput { .. } => false,
						&events::MessageSendEvent::SendTxRemoveInput { .. } => false,
						&events::MessageSendEvent::SendTxRemoveOutput { .. } => false,
						&events::MessageSendEvent::SendTxComplete { .. } => false,
						&events::MessageSendEvent::SendTxSignatures { .. } => false,
						&events::MessageSendEvent::SendTxInitRbf { .. } => false,
						&events::MessageSendEvent::SendTxAckRbf { .. } => false,
						&events::MessageSendEvent::SendTxAbort { .. } => false,
						// Channel Operations
						&events::MessageSendEvent::UpdateHTLCs { .. } => false,
						&events::MessageSendEvent::SendRevokeAndACK { .. } => false,
						&events::MessageSendEvent::SendClosingSigned { .. } => false,
						&events::MessageSendEvent::SendShutdown { .. } => false,
						&events::MessageSendEvent::SendChannelReestablish { .. } => false,
						&events::MessageSendEvent::HandleError { .. } => false,
						// Gossip
						&events::MessageSendEvent::SendChannelAnnouncement { .. } => false,
						&events::MessageSendEvent::BroadcastChannelAnnouncement { .. } => true,
						// [`ChannelManager::pending_broadcast_events`] holds the [`BroadcastChannelUpdate`]
						// This check here is to ensure exhaustivity.
						&events::MessageSendEvent::BroadcastChannelUpdate { .. } => {
							debug_assert!(false, "This event shouldn't have been here");
							false
						},
						&events::MessageSendEvent::BroadcastNodeAnnouncement { .. } => true,
						&events::MessageSendEvent::SendChannelUpdate { .. } => false,
						&events::MessageSendEvent::SendChannelRangeQuery { .. } => false,
						&events::MessageSendEvent::SendShortIdsQuery { .. } => false,
						&events::MessageSendEvent::SendReplyChannelRange { .. } => false,
						&events::MessageSendEvent::SendGossipTimestampFilter { .. } => false,
					}
				});
				debug_assert!(peer_state.is_connected, "A disconnected peer cannot disconnect");
				peer_state.is_connected = false;
				peer_state.ok_to_remove(true)
			} else { debug_assert!(false, "Unconnected peer disconnected"); true }
		};
		if remove_peer {
			per_peer_state.remove(counterparty_node_id);
		}
		mem::drop(per_peer_state);

		for failure in failed_channels.drain(..) {
			self.finish_close_channel(failure);
		}
	}

	fn peer_connected(&self, counterparty_node_id: &PublicKey, init_msg: &msgs::Init, inbound: bool) -> Result<(), ()> {
		let logger = WithContext::from(&self.logger, Some(*counterparty_node_id), None);
		if !init_msg.features.supports_static_remote_key() {
			log_debug!(logger, "Peer {} does not support static remote key, disconnecting", log_pubkey!(counterparty_node_id));
			return Err(());
		}

		let mut res = Ok(());

		PersistenceNotifierGuard::optionally_notify(self, || {
			// If we have too many peers connected which don't have funded channels, disconnect the
			// peer immediately (as long as it doesn't have funded channels). If we have a bunch of
			// unfunded channels taking up space in memory for disconnected peers, we still let new
			// peers connect, but we'll reject new channels from them.
			let connected_peers_without_funded_channels = self.peers_without_funded_channels(|node| node.is_connected);
			let inbound_peer_limited = inbound && connected_peers_without_funded_channels >= MAX_NO_CHANNEL_PEERS;

			{
				let mut peer_state_lock = self.per_peer_state.write().unwrap();
				match peer_state_lock.entry(counterparty_node_id.clone()) {
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
							is_connected: true,
						}));
					},
					hash_map::Entry::Occupied(e) => {
						let mut peer_state = e.get().lock().unwrap();
						peer_state.latest_features = init_msg.features.clone();

						let best_block_height = self.best_block.read().unwrap().height;
						if inbound_peer_limited &&
							Self::unfunded_channel_count(&*peer_state, best_block_height) ==
							peer_state.channel_by_id.len()
						{
							res = Err(());
							return NotifyOption::SkipPersistNoEvents;
						}

						debug_assert!(!peer_state.is_connected, "A peer shouldn't be connected twice");
						peer_state.is_connected = true;
					},
				}
			}

			log_debug!(logger, "Generating channel_reestablish events for {}", log_pubkey!(counterparty_node_id));

			let per_peer_state = self.per_peer_state.read().unwrap();
			if let Some(peer_state_mutex) = per_peer_state.get(counterparty_node_id) {
				let mut peer_state_lock = peer_state_mutex.lock().unwrap();
				let peer_state = &mut *peer_state_lock;
				let pending_msg_events = &mut peer_state.pending_msg_events;

				for (_, phase) in peer_state.channel_by_id.iter_mut() {
					match phase {
						ChannelPhase::Funded(chan) => {
							let logger = WithChannelContext::from(&self.logger, &chan.context);
							pending_msg_events.push(events::MessageSendEvent::SendChannelReestablish {
								node_id: chan.context.get_counterparty_node_id(),
								msg: chan.get_channel_reestablish(&&logger),
							});
						}

						ChannelPhase::UnfundedOutboundV1(chan) => {
							pending_msg_events.push(events::MessageSendEvent::SendOpenChannel {
								node_id: chan.context.get_counterparty_node_id(),
								msg: chan.get_open_channel(self.chain_hash),
							});
						}

						// TODO(dual_funding): Combine this match arm with above once #[cfg(dual_funding)] is removed.
						#[cfg(dual_funding)]
						ChannelPhase::UnfundedOutboundV2(chan) => {
							pending_msg_events.push(events::MessageSendEvent::SendOpenChannelV2 {
								node_id: chan.context.get_counterparty_node_id(),
								msg: chan.get_open_channel_v2(self.chain_hash),
							});
						},

						ChannelPhase::UnfundedInboundV1(_) => {
							// Since unfunded inbound channel maps are cleared upon disconnecting a peer,
							// they are not persisted and won't be recovered after a crash.
							// Therefore, they shouldn't exist at this point.
							debug_assert!(false);
						}

						// TODO(dual_funding): Combine this match arm with above once #[cfg(dual_funding)] is removed.
						#[cfg(dual_funding)]
						ChannelPhase::UnfundedInboundV2(channel) => {
							// Since unfunded inbound channel maps are cleared upon disconnecting a peer,
							// they are not persisted and won't be recovered after a crash.
							// Therefore, they shouldn't exist at this point.
							debug_assert!(false);
						},
					}
				}
			}

			return NotifyOption::SkipPersistHandleEvents;
			//TODO: Also re-broadcast announcement_signatures
		});
		res
	}

	fn handle_error(&self, counterparty_node_id: &PublicKey, msg: &msgs::ErrorMessage) {
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
							let peer_state_mutex_opt = per_peer_state.get(counterparty_node_id);
							if peer_state_mutex_opt.is_none() { return NotifyOption::SkipPersistNoEvents; }
							let mut peer_state = peer_state_mutex_opt.unwrap().lock().unwrap();
							if let Some(ChannelPhase::Funded(chan)) = peer_state.channel_by_id.get(&msg.channel_id) {
								if let Some(msg) = chan.get_outbound_shutdown() {
									peer_state.pending_msg_events.push(events::MessageSendEvent::SendShutdown {
										node_id: *counterparty_node_id,
										msg,
									});
								}
								peer_state.pending_msg_events.push(events::MessageSendEvent::HandleError {
									node_id: *counterparty_node_id,
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

		if msg.channel_id.is_zero() {
			let channel_ids: Vec<ChannelId> = {
				let per_peer_state = self.per_peer_state.read().unwrap();
				let peer_state_mutex_opt = per_peer_state.get(counterparty_node_id);
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
				let _ = self.force_close_channel_with_peer(&channel_id, counterparty_node_id, Some(&msg.data), true);
			}
		} else {
			{
				// First check if we can advance the channel type and try again.
				let per_peer_state = self.per_peer_state.read().unwrap();
				let peer_state_mutex_opt = per_peer_state.get(counterparty_node_id);
				if peer_state_mutex_opt.is_none() { return; }
				let mut peer_state_lock = peer_state_mutex_opt.unwrap().lock().unwrap();
				let peer_state = &mut *peer_state_lock;
				match peer_state.channel_by_id.get_mut(&msg.channel_id) {
					Some(ChannelPhase::UnfundedOutboundV1(ref mut chan)) => {
						if let Ok(msg) = chan.maybe_handle_error_without_close(self.chain_hash, &self.fee_estimator) {
							peer_state.pending_msg_events.push(events::MessageSendEvent::SendOpenChannel {
								node_id: *counterparty_node_id,
								msg,
							});
							return;
						}
					},
					#[cfg(dual_funding)]
					Some(ChannelPhase::UnfundedOutboundV2(ref mut chan)) => {
						if let Ok(msg) = chan.maybe_handle_error_without_close(self.chain_hash, &self.fee_estimator) {
							peer_state.pending_msg_events.push(events::MessageSendEvent::SendOpenChannelV2 {
								node_id: *counterparty_node_id,
								msg,
							});
							return;
						}
					},
					None | Some(ChannelPhase::UnfundedInboundV1(_) | ChannelPhase::Funded(_)) => (),
					#[cfg(dual_funding)]
					Some(ChannelPhase::UnfundedInboundV2(_)) => (),
				}
			}

			// Untrusted messages from peer, we throw away the error if id points to a non-existent channel
			let _ = self.force_close_channel_with_peer(&msg.channel_id, counterparty_node_id, Some(&msg.data), true);
		}
	}

	fn provided_node_features(&self) -> NodeFeatures {
		provided_node_features(&self.default_configuration)
	}

	fn provided_init_features(&self, _their_init_features: &PublicKey) -> InitFeatures {
		provided_init_features(&self.default_configuration)
	}

	fn get_chain_hashes(&self) -> Option<Vec<ChainHash>> {
		Some(vec![self.chain_hash])
	}

	fn handle_tx_add_input(&self, counterparty_node_id: &PublicKey, msg: &msgs::TxAddInput) {
		let _: Result<(), _> = handle_error!(self, Err(MsgHandleErrInternal::send_err_msg_no_close(
			"Dual-funded channels not supported".to_owned(),
			 msg.channel_id.clone())), *counterparty_node_id);
	}

	fn handle_tx_add_output(&self, counterparty_node_id: &PublicKey, msg: &msgs::TxAddOutput) {
		let _: Result<(), _> = handle_error!(self, Err(MsgHandleErrInternal::send_err_msg_no_close(
			"Dual-funded channels not supported".to_owned(),
			 msg.channel_id.clone())), *counterparty_node_id);
	}

	fn handle_tx_remove_input(&self, counterparty_node_id: &PublicKey, msg: &msgs::TxRemoveInput) {
		let _: Result<(), _> = handle_error!(self, Err(MsgHandleErrInternal::send_err_msg_no_close(
			"Dual-funded channels not supported".to_owned(),
			 msg.channel_id.clone())), *counterparty_node_id);
	}

	fn handle_tx_remove_output(&self, counterparty_node_id: &PublicKey, msg: &msgs::TxRemoveOutput) {
		let _: Result<(), _> = handle_error!(self, Err(MsgHandleErrInternal::send_err_msg_no_close(
			"Dual-funded channels not supported".to_owned(),
			 msg.channel_id.clone())), *counterparty_node_id);
	}

	fn handle_tx_complete(&self, counterparty_node_id: &PublicKey, msg: &msgs::TxComplete) {
		let _: Result<(), _> = handle_error!(self, Err(MsgHandleErrInternal::send_err_msg_no_close(
			"Dual-funded channels not supported".to_owned(),
			 msg.channel_id.clone())), *counterparty_node_id);
	}

	fn handle_tx_signatures(&self, counterparty_node_id: &PublicKey, msg: &msgs::TxSignatures) {
		let _: Result<(), _> = handle_error!(self, Err(MsgHandleErrInternal::send_err_msg_no_close(
			"Dual-funded channels not supported".to_owned(),
			 msg.channel_id.clone())), *counterparty_node_id);
	}

	fn handle_tx_init_rbf(&self, counterparty_node_id: &PublicKey, msg: &msgs::TxInitRbf) {
		let _: Result<(), _> = handle_error!(self, Err(MsgHandleErrInternal::send_err_msg_no_close(
			"Dual-funded channels not supported".to_owned(),
			 msg.channel_id.clone())), *counterparty_node_id);
	}

	fn handle_tx_ack_rbf(&self, counterparty_node_id: &PublicKey, msg: &msgs::TxAckRbf) {
		let _: Result<(), _> = handle_error!(self, Err(MsgHandleErrInternal::send_err_msg_no_close(
			"Dual-funded channels not supported".to_owned(),
			 msg.channel_id.clone())), *counterparty_node_id);
	}

	fn handle_tx_abort(&self, counterparty_node_id: &PublicKey, msg: &msgs::TxAbort) {
		let _: Result<(), _> = handle_error!(self, Err(MsgHandleErrInternal::send_err_msg_no_close(
			"Dual-funded channels not supported".to_owned(),
			 msg.channel_id.clone())), *counterparty_node_id);
	}
}

impl<M: Deref, T: Deref, ES: Deref, NS: Deref, SP: Deref, F: Deref, R: Deref, L: Deref>
OffersMessageHandler for ChannelManager<M, T, ES, NS, SP, F, R, L>
where
	M::Target: chain::Watch<<SP::Target as SignerProvider>::EcdsaSigner>,
	T::Target: BroadcasterInterface,
	ES::Target: EntropySource,
	NS::Target: NodeSigner,
	SP::Target: SignerProvider,
	F::Target: FeeEstimator,
	R::Target: Router,
	L::Target: Logger,
{
	fn handle_message(&self, message: OffersMessage) -> Option<OffersMessage> {
		let secp_ctx = &self.secp_ctx;
		let expanded_key = &self.inbound_payment_key;

		match message {
			OffersMessage::InvoiceRequest(invoice_request) => {
				let amount_msats = match InvoiceBuilder::<DerivedSigningPubkey>::amount_msats(
					&invoice_request
				) {
					Ok(amount_msats) => amount_msats,
					Err(error) => return Some(OffersMessage::InvoiceError(error.into())),
				};
				let invoice_request = match invoice_request.verify(expanded_key, secp_ctx) {
					Ok(invoice_request) => invoice_request,
					Err(()) => {
						let error = Bolt12SemanticError::InvalidMetadata;
						return Some(OffersMessage::InvoiceError(error.into()));
					},
				};

				let relative_expiry = DEFAULT_RELATIVE_EXPIRY.as_secs() as u32;
				let (payment_hash, payment_secret) = match self.create_inbound_payment(
					Some(amount_msats), relative_expiry, None
				) {
					Ok((payment_hash, payment_secret)) => (payment_hash, payment_secret),
					Err(()) => {
						let error = Bolt12SemanticError::InvalidAmount;
						return Some(OffersMessage::InvoiceError(error.into()));
					},
				};

				let payment_paths = match self.create_blinded_payment_paths(
					amount_msats, payment_secret
				) {
					Ok(payment_paths) => payment_paths,
					Err(()) => {
						let error = Bolt12SemanticError::MissingPaths;
						return Some(OffersMessage::InvoiceError(error.into()));
					},
				};

				#[cfg(not(feature = "std"))]
				let created_at = Duration::from_secs(
					self.highest_seen_timestamp.load(Ordering::Acquire) as u64
				);

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
									self.node_signer.sign_bolt12_invoice(invoice)
								)
								.map_err(InvoiceError::from)
						})
				};

				match response {
					Ok(invoice) => Some(OffersMessage::Invoice(invoice)),
					Err(error) => Some(OffersMessage::InvoiceError(error.into())),
				}
			},
			OffersMessage::Invoice(invoice) => {
				let response = invoice
					.verify(expanded_key, secp_ctx)
					.map_err(|()| InvoiceError::from_string("Unrecognized invoice".to_owned()))
					.and_then(|payment_id| {
						let features = self.bolt12_invoice_features();
						if invoice.invoice_features().requires_unknown_bits_from(&features) {
							Err(InvoiceError::from(Bolt12SemanticError::UnknownRequiredFeatures))
						} else {
							self.send_payment_for_bolt12_invoice(&invoice, payment_id)
								.map_err(|e| {
									log_trace!(self.logger, "Failed paying invoice: {:?}", e);
									InvoiceError::from_string(format!("{:?}", e))
								})
						}
					});

				match response {
					Ok(()) => None,
					Err(e) => Some(OffersMessage::InvoiceError(e)),
				}
			},
			OffersMessage::InvoiceError(invoice_error) => {
				log_trace!(self.logger, "Received invoice_error: {}", invoice_error);
				None
			},
		}
	}

	fn release_pending_messages(&self) -> Vec<PendingOnionMessage<OffersMessage>> {
		core::mem::take(&mut self.pending_offers_messages.lock().unwrap())
	}
}

impl<M: Deref, T: Deref, ES: Deref, NS: Deref, SP: Deref, F: Deref, R: Deref, L: Deref>
NodeIdLookUp for ChannelManager<M, T, ES, NS, SP, F, R, L>
where
	M::Target: chain::Watch<<SP::Target as SignerProvider>::EcdsaSigner>,
	T::Target: BroadcasterInterface,
	ES::Target: EntropySource,
	NS::Target: NodeSigner,
	SP::Target: SignerProvider,
	F::Target: FeeEstimator,
	R::Target: Router,
	L::Target: Logger,
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
	// should also add the corresponding (optional) bit to the [`ChannelMessageHandler`] impl for
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
	features.set_channel_type_optional();
	features.set_scid_privacy_optional();
	features.set_zero_conf_optional();
	features.set_route_blinding_optional();
	if config.channel_handshake_config.negotiate_anchors_zero_fee_htlc_tx {
		features.set_anchors_zero_fee_htlc_tx_optional();
	}
	features
}

const SERIALIZATION_VERSION: u8 = 1;
const MIN_SERIALIZATION_VERSION: u8 = 1;

impl_writeable_tlv_based!(CounterpartyForwardingInfo, {
	(2, fee_base_msat, required),
	(4, fee_proportional_millionths, required),
	(6, cltv_expiry_delta, required),
});

impl_writeable_tlv_based!(ChannelCounterparty, {
	(2, node_id, required),
	(4, features, required),
	(6, unspendable_punishment_reserve, required),
	(8, forwarding_info, option),
	(9, outbound_htlc_minimum_msat, option),
	(11, outbound_htlc_maximum_msat, option),
});

impl Writeable for ChannelDetails {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		// `user_channel_id` used to be a single u64 value. In order to remain backwards compatible with
		// versions prior to 0.0.113, the u128 is serialized as two separate u64 values.
		let user_channel_id_low = self.user_channel_id as u64;
		let user_channel_id_high_opt = Some((self.user_channel_id >> 64) as u64);
		write_tlv_fields!(writer, {
			(1, self.inbound_scid_alias, option),
			(2, self.channel_id, required),
			(3, self.channel_type, option),
			(4, self.counterparty, required),
			(5, self.outbound_scid_alias, option),
			(6, self.funding_txo, option),
			(7, self.config, option),
			(8, self.short_channel_id, option),
			(9, self.confirmations, option),
			(10, self.channel_value_satoshis, required),
			(12, self.unspendable_punishment_reserve, option),
			(14, user_channel_id_low, required),
			(16, self.balance_msat, required),
			(18, self.outbound_capacity_msat, required),
			(19, self.next_outbound_htlc_limit_msat, required),
			(20, self.inbound_capacity_msat, required),
			(21, self.next_outbound_htlc_minimum_msat, required),
			(22, self.confirmations_required, option),
			(24, self.force_close_spend_delay, option),
			(26, self.is_outbound, required),
			(28, self.is_channel_ready, required),
			(30, self.is_usable, required),
			(32, self.is_public, required),
			(33, self.inbound_htlc_minimum_msat, option),
			(35, self.inbound_htlc_maximum_msat, option),
			(37, user_channel_id_high_opt, option),
			(39, self.feerate_sat_per_1000_weight, option),
			(41, self.channel_shutdown_state, option),
			(43, self.pending_inbound_htlcs, optional_vec),
			(45, self.pending_outbound_htlcs, optional_vec),
		});
		Ok(())
	}
}

impl Readable for ChannelDetails {
	fn read<R: Read>(reader: &mut R) -> Result<Self, DecodeError> {
		_init_and_read_len_prefixed_tlv_fields!(reader, {
			(1, inbound_scid_alias, option),
			(2, channel_id, required),
			(3, channel_type, option),
			(4, counterparty, required),
			(5, outbound_scid_alias, option),
			(6, funding_txo, option),
			(7, config, option),
			(8, short_channel_id, option),
			(9, confirmations, option),
			(10, channel_value_satoshis, required),
			(12, unspendable_punishment_reserve, option),
			(14, user_channel_id_low, required),
			(16, balance_msat, required),
			(18, outbound_capacity_msat, required),
			// Note that by the time we get past the required read above, outbound_capacity_msat will be
			// filled in, so we can safely unwrap it here.
			(19, next_outbound_htlc_limit_msat, (default_value, outbound_capacity_msat.0.unwrap() as u64)),
			(20, inbound_capacity_msat, required),
			(21, next_outbound_htlc_minimum_msat, (default_value, 0)),
			(22, confirmations_required, option),
			(24, force_close_spend_delay, option),
			(26, is_outbound, required),
			(28, is_channel_ready, required),
			(30, is_usable, required),
			(32, is_public, required),
			(33, inbound_htlc_minimum_msat, option),
			(35, inbound_htlc_maximum_msat, option),
			(37, user_channel_id_high_opt, option),
			(39, feerate_sat_per_1000_weight, option),
			(41, channel_shutdown_state, option),
			(43, pending_inbound_htlcs, optional_vec),
			(45, pending_outbound_htlcs, optional_vec),
		});

		// `user_channel_id` used to be a single u64 value. In order to remain backwards compatible with
		// versions prior to 0.0.113, the u128 is serialized as two separate u64 values.
		let user_channel_id_low: u64 = user_channel_id_low.0.unwrap();
		let user_channel_id = user_channel_id_low as u128 +
			((user_channel_id_high_opt.unwrap_or(0 as u64) as u128) << 64);

		Ok(Self {
			inbound_scid_alias,
			channel_id: channel_id.0.unwrap(),
			channel_type,
			counterparty: counterparty.0.unwrap(),
			outbound_scid_alias,
			funding_txo,
			config,
			short_channel_id,
			channel_value_satoshis: channel_value_satoshis.0.unwrap(),
			unspendable_punishment_reserve,
			user_channel_id,
			balance_msat: balance_msat.0.unwrap(),
			outbound_capacity_msat: outbound_capacity_msat.0.unwrap(),
			next_outbound_htlc_limit_msat: next_outbound_htlc_limit_msat.0.unwrap(),
			next_outbound_htlc_minimum_msat: next_outbound_htlc_minimum_msat.0.unwrap(),
			inbound_capacity_msat: inbound_capacity_msat.0.unwrap(),
			confirmations_required,
			confirmations,
			force_close_spend_delay,
			is_outbound: is_outbound.0.unwrap(),
			is_channel_ready: is_channel_ready.0.unwrap(),
			is_usable: is_usable.0.unwrap(),
			is_public: is_public.0.unwrap(),
			inbound_htlc_minimum_msat,
			inbound_htlc_maximum_msat,
			feerate_sat_per_1000_weight,
			channel_shutdown_state,
			pending_inbound_htlcs: pending_inbound_htlcs.unwrap_or(Vec::new()),
			pending_outbound_htlcs: pending_outbound_htlcs.unwrap_or(Vec::new()),
		})
	}
}

impl_writeable_tlv_based!(PhantomRouteHints, {
	(2, channels, required_vec),
	(4, phantom_scid, required),
	(6, real_node_pubkey, required),
});

impl_writeable_tlv_based!(BlindedForward, {
	(0, inbound_blinding_point, required),
	(1, failure, (default_value, BlindedFailure::FromIntroductionNode)),
});

impl_writeable_tlv_based_enum!(PendingHTLCRouting,
	(0, Forward) => {
		(0, onion_packet, required),
		(1, blinded, option),
		(2, short_channel_id, required),
	},
	(1, Receive) => {
		(0, payment_data, required),
		(1, phantom_shared_secret, option),
		(2, incoming_cltv_expiry, required),
		(3, payment_metadata, option),
		(5, custom_tlvs, optional_vec),
		(7, requires_blinded_error, (default_value, false)),
	},
	(2, ReceiveKeysend) => {
		(0, payment_preimage, required),
		(1, requires_blinded_error, (default_value, false)),
		(2, incoming_cltv_expiry, required),
		(3, payment_metadata, option),
		(4, payment_data, option), // Added in 0.0.116
		(5, custom_tlvs, optional_vec),
	},
;);

impl_writeable_tlv_based!(PendingHTLCInfo, {
	(0, routing, required),
	(2, incoming_shared_secret, required),
	(4, payment_hash, required),
	(6, outgoing_amt_msat, required),
	(8, outgoing_cltv_value, required),
	(9, incoming_amt_msat, option),
	(10, skimmed_fee_msat, option),
});


impl Writeable for HTLCFailureMsg {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		match self {
			HTLCFailureMsg::Relay(msgs::UpdateFailHTLC { channel_id, htlc_id, reason }) => {
				0u8.write(writer)?;
				channel_id.write(writer)?;
				htlc_id.write(writer)?;
				reason.write(writer)?;
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
	fn read<R: Read>(reader: &mut R) -> Result<Self, DecodeError> {
		let id: u8 = Readable::read(reader)?;
		match id {
			0 => {
				Ok(HTLCFailureMsg::Relay(msgs::UpdateFailHTLC {
					channel_id: Readable::read(reader)?,
					htlc_id: Readable::read(reader)?,
					reason: Readable::read(reader)?,
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
				let res = Readable::read(&mut s)?;
				s.eat_remaining()?; // Return ShortRead if there's actually not enough bytes
				Ok(HTLCFailureMsg::Relay(res))
			},
			3 => {
				let length: BigSize = Readable::read(reader)?;
				let mut s = FixedLengthReader::new(reader, length.0);
				let res = Readable::read(&mut s)?;
				s.eat_remaining()?; // Return ShortRead if there's actually not enough bytes
				Ok(HTLCFailureMsg::Malformed(res))
			},
			_ => Err(DecodeError::UnknownRequiredFeature),
		}
	}
}

impl_writeable_tlv_based_enum!(PendingHTLCStatus, ;
	(0, Forward),
	(1, Fail),
);

impl_writeable_tlv_based_enum!(BlindedFailure,
	(0, FromIntroductionNode) => {},
	(2, FromBlindedNode) => {}, ;
);

impl_writeable_tlv_based!(HTLCPreviousHopData, {
	(0, short_channel_id, required),
	(1, phantom_shared_secret, option),
	(2, outpoint, required),
	(3, blinded_failure, option),
	(4, htlc_id, required),
	(6, incoming_packet_shared_secret, required),
	(7, user_channel_id, option),
	// Note that by the time we get past the required read for type 2 above, outpoint will be
	// filled in, so we can safely unwrap it here.
	(9, channel_id, (default_value, ChannelId::v1_from_funding_outpoint(outpoint.0.unwrap()))),
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
				read_tlv_fields!(reader, {
					(0, session_priv, required),
					(1, payment_id, option),
					(2, first_hop_htlc_msat, required),
					(4, path_hops, required_vec),
					(5, payment_params, (option: ReadableArgs, 0)),
					(6, blinded_tail, option),
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
			HTLCSource::OutboundRoute { ref session_priv, ref first_hop_htlc_msat, ref path, payment_id } => {
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
				 });
			}
			HTLCSource::PreviousHopData(ref field) => {
				1u8.write(writer)?;
				field.write(writer)?;
			}
		}
		Ok(())
	}
}

impl_writeable_tlv_based!(PendingAddHTLCInfo, {
	(0, forward_info, required),
	(1, prev_user_channel_id, (default_value, 0)),
	(2, prev_short_channel_id, required),
	(4, prev_htlc_id, required),
	(6, prev_funding_outpoint, required),
	// Note that by the time we get past the required read for type 6 above, prev_funding_outpoint will be
	// filled in, so we can safely unwrap it here.
	(7, prev_channel_id, (default_value, ChannelId::v1_from_funding_outpoint(prev_funding_outpoint.0.unwrap()))),
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
					(2, err_packet, required),
				});
			},
			Self::FailMalformedHTLC { htlc_id, failure_code, sha256_of_onion } => {
				// Since this variant was added in 0.0.119, write this as `::FailHTLC` with an empty error
				// packet so older versions have something to fail back with, but serialize the real data as
				// optional TLVs for the benefit of newer versions.
				FAIL_HTLC_VARIANT_ID.write(w)?;
				let dummy_err_packet = msgs::OnionErrorPacket { data: Vec::new() };
				write_tlv_fields!(w, {
					(0, htlc_id, required),
					(1, failure_code, required),
					(2, dummy_err_packet, required),
					(3, sha256_of_onion, required),
				});
			},
		}
		Ok(())
	}
}

impl Readable for HTLCForwardInfo {
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
				});
				if let Some(failure_code) = malformed_htlc_failure_code {
					Self::FailMalformedHTLC {
						htlc_id: _init_tlv_based_struct_field!(htlc_id, required),
						failure_code,
						sha256_of_onion: sha256_of_onion.ok_or(DecodeError::InvalidValue)?,
					}
				} else {
					Self::FailHTLC {
						htlc_id: _init_tlv_based_struct_field!(htlc_id, required),
						err_packet: _init_tlv_based_struct_field!(err_packet, required),
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

impl<M: Deref, T: Deref, ES: Deref, NS: Deref, SP: Deref, F: Deref, R: Deref, L: Deref> Writeable for ChannelManager<M, T, ES, NS, SP, F, R, L>
where
	M::Target: chain::Watch<<SP::Target as SignerProvider>::EcdsaSigner>,
	T::Target: BroadcasterInterface,
	ES::Target: EntropySource,
	NS::Target: NodeSigner,
	SP::Target: SignerProvider,
	F::Target: FeeEstimator,
	R::Target: Router,
	L::Target: Logger,
{
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		let _consistency_lock = self.total_consistency_lock.write().unwrap();

		write_ver_prefix!(writer, SERIALIZATION_VERSION, MIN_SERIALIZATION_VERSION);

		self.chain_hash.write(writer)?;
		{
			let best_block = self.best_block.read().unwrap();
			best_block.height.write(writer)?;
			best_block.block_hash.write(writer)?;
		}

		let mut serializable_peer_count: u64 = 0;
		{
			let per_peer_state = self.per_peer_state.read().unwrap();
			let mut number_of_funded_channels = 0;
			for (_, peer_state_mutex) in per_peer_state.iter() {
				let mut peer_state_lock = peer_state_mutex.lock().unwrap();
				let peer_state = &mut *peer_state_lock;
				if !peer_state.ok_to_remove(false) {
					serializable_peer_count += 1;
				}

				number_of_funded_channels += peer_state.channel_by_id.iter().filter(
					|(_, phase)| if let ChannelPhase::Funded(chan) = phase { chan.context.is_funding_broadcast() } else { false }
				).count();
			}

			(number_of_funded_channels as u64).write(writer)?;

			for (_, peer_state_mutex) in per_peer_state.iter() {
				let mut peer_state_lock = peer_state_mutex.lock().unwrap();
				let peer_state = &mut *peer_state_lock;
				for channel in peer_state.channel_by_id.iter().filter_map(
					|(_, phase)| if let ChannelPhase::Funded(channel) = phase {
						if channel.context.is_funding_broadcast() { Some(channel) } else { None }
					} else { None }
				) {
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

		let per_peer_state = self.per_peer_state.write().unwrap();

		let pending_inbound_payments = self.pending_inbound_payments.lock().unwrap();
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

		(serializable_peer_count).write(writer)?;
		for ((peer_pubkey, _), peer_state) in per_peer_state.iter().zip(peer_states.iter()) {
			// Peers which we have no channels to should be dropped once disconnected. As we
			// disconnect all peers when shutting down and serializing the ChannelManager, we
			// consider all peers as disconnected here. There's therefore no need write peers with
			// no channels.
			if !peer_state.ok_to_remove(false) {
				peer_pubkey.write(writer)?;
				peer_state.latest_features.write(writer)?;
				if !peer_state.monitor_update_blocked_actions.is_empty() {
					monitor_update_blocked_actions_per_peer
						.get_or_insert_with(Vec::new)
						.push((*peer_pubkey, &peer_state.monitor_update_blocked_actions));
				}
			}
		}

		let events = self.pending_events.lock().unwrap();
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

		(pending_inbound_payments.len() as u64).write(writer)?;
		for (hash, pending_payment) in pending_inbound_payments.iter() {
			hash.write(writer)?;
			pending_payment.write(writer)?;
		}

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
				PendingOutboundPayment::InvoiceReceived { .. } => {},
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
		let our_pending_intercepts = self.pending_intercepted_htlcs.lock().unwrap();
		if our_pending_intercepts.len() != 0 {
			pending_intercepted_htlcs = Some(our_pending_intercepts);
		}

		let mut pending_claiming_payments = Some(&claimable_payments.pending_claiming_payments);
		if pending_claiming_payments.as_ref().unwrap().is_empty() {
			// LDK versions prior to 0.0.113 do not know how to read the pending claimed payments
			// map. Thus, if there are no entries we skip writing a TLV for it.
			pending_claiming_payments = None;
		}

		let mut in_flight_monitor_updates: Option<HashMap<(&PublicKey, &OutPoint), &Vec<ChannelMonitorUpdate>>> = None;
		for ((counterparty_id, _), peer_state) in per_peer_state.iter().zip(peer_states.iter()) {
			for (funding_outpoint, updates) in peer_state.in_flight_monitor_updates.iter() {
				if !updates.is_empty() {
					if in_flight_monitor_updates.is_none() { in_flight_monitor_updates = Some(new_hash_map()); }
					in_flight_monitor_updates.as_mut().unwrap().insert((counterparty_id, funding_outpoint), updates);
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
			(10, in_flight_monitor_updates, option),
			(11, self.probing_cookie_secret, required),
			(13, htlc_onion_fields, optional_vec),
			(14, decode_update_add_htlcs_opt, option),
		});

		Ok(())
	}
}

impl Writeable for VecDeque<(Event, Option<EventCompletionAction>)> {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		(self.len() as u64).write(w)?;
		for (event, action) in self.iter() {
			event.write(w)?;
			action.write(w)?;
			#[cfg(debug_assertions)] {
				// Events are MaybeReadable, in some cases indicating that they shouldn't actually
				// be persisted and are regenerated on restart. However, if such an event has a
				// post-event-handling action we'll write nothing for the event and would have to
				// either forget the action or fail on deserialization (which we do below). Thus,
				// check that the event is sane here.
				let event_encoded = event.encode();
				let event_read: Option<Event> =
					MaybeReadable::read(&mut &event_encoded[..]).unwrap();
				if action.is_some() { assert!(event_read.is_some()); }
			}
		}
		Ok(())
	}
}
impl Readable for VecDeque<(Event, Option<EventCompletionAction>)> {
	fn read<R: Read>(reader: &mut R) -> Result<Self, DecodeError> {
		let len: u64 = Readable::read(reader)?;
		const MAX_ALLOC_SIZE: u64 = 1024 * 16;
		let mut events: Self = VecDeque::with_capacity(cmp::min(
			MAX_ALLOC_SIZE/mem::size_of::<(events::Event, Option<EventCompletionAction>)>() as u64,
			len) as usize);
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

impl_writeable_tlv_based_enum!(ChannelShutdownState,
	(0, NotShuttingDown) => {},
	(2, ShutdownInitiated) => {},
	(4, ResolvingHTLCs) => {},
	(6, NegotiatingClosingFee) => {},
	(8, ShutdownComplete) => {}, ;
);

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
/// 4) Reconnect blocks on your [`ChannelMonitor`]s.
/// 5) Disconnect/connect blocks on the [`ChannelManager`].
/// 6) Re-persist the [`ChannelMonitor`]s to ensure the latest state is on disk.
///    Note that if you're using a [`ChainMonitor`] for your [`chain::Watch`] implementation, you
///    will likely accomplish this as a side-effect of calling [`chain::Watch::watch_channel`] in
///    the next step.
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
pub struct ChannelManagerReadArgs<'a, M: Deref, T: Deref, ES: Deref, NS: Deref, SP: Deref, F: Deref, R: Deref, L: Deref>
where
	M::Target: chain::Watch<<SP::Target as SignerProvider>::EcdsaSigner>,
	T::Target: BroadcasterInterface,
	ES::Target: EntropySource,
	NS::Target: NodeSigner,
	SP::Target: SignerProvider,
	F::Target: FeeEstimator,
	R::Target: Router,
	L::Target: Logger,
{
	/// A cryptographically secure source of entropy.
	pub entropy_source: ES,

	/// A signer that is able to perform node-scoped cryptographic operations.
	pub node_signer: NS,

	/// The keys provider which will give us relevant keys. Some keys will be loaded during
	/// deserialization and KeysInterface::read_chan_signer will be used to read per-Channel
	/// signing data.
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
	/// The Logger for use in the ChannelManager and which may be used to log information during
	/// deserialization.
	pub logger: L,
	/// Default settings used for new channels. Any existing channels will continue to use the
	/// runtime settings which were stored when the ChannelManager was serialized.
	pub default_config: UserConfig,

	/// A map from channel funding outpoints to ChannelMonitors for those channels (ie
	/// value.context.get_funding_txo() should be the key).
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
	pub channel_monitors: HashMap<OutPoint, &'a mut ChannelMonitor<<SP::Target as SignerProvider>::EcdsaSigner>>,
}

impl<'a, M: Deref, T: Deref, ES: Deref, NS: Deref, SP: Deref, F: Deref, R: Deref, L: Deref>
		ChannelManagerReadArgs<'a, M, T, ES, NS, SP, F, R, L>
where
	M::Target: chain::Watch<<SP::Target as SignerProvider>::EcdsaSigner>,
	T::Target: BroadcasterInterface,
	ES::Target: EntropySource,
	NS::Target: NodeSigner,
	SP::Target: SignerProvider,
	F::Target: FeeEstimator,
	R::Target: Router,
	L::Target: Logger,
{
	/// Simple utility function to create a ChannelManagerReadArgs which creates the monitor
	/// HashMap for you. This is primarily useful for C bindings where it is not practical to
	/// populate a HashMap directly from C.
	pub fn new(entropy_source: ES, node_signer: NS, signer_provider: SP, fee_estimator: F, chain_monitor: M, tx_broadcaster: T, router: R, logger: L, default_config: UserConfig,
			mut channel_monitors: Vec<&'a mut ChannelMonitor<<SP::Target as SignerProvider>::EcdsaSigner>>) -> Self {
		Self {
			entropy_source, node_signer, signer_provider, fee_estimator, chain_monitor, tx_broadcaster, router, logger, default_config,
			channel_monitors: hash_map_from_iter(
				channel_monitors.drain(..).map(|monitor| { (monitor.get_funding_txo().0, monitor) })
			),
		}
	}
}

// Implement ReadableArgs for an Arc'd ChannelManager to make it a bit easier to work with the
// SipmleArcChannelManager type:
impl<'a, M: Deref, T: Deref, ES: Deref, NS: Deref, SP: Deref, F: Deref, R: Deref, L: Deref>
	ReadableArgs<ChannelManagerReadArgs<'a, M, T, ES, NS, SP, F, R, L>> for (BlockHash, Arc<ChannelManager<M, T, ES, NS, SP, F, R, L>>)
where
	M::Target: chain::Watch<<SP::Target as SignerProvider>::EcdsaSigner>,
	T::Target: BroadcasterInterface,
	ES::Target: EntropySource,
	NS::Target: NodeSigner,
	SP::Target: SignerProvider,
	F::Target: FeeEstimator,
	R::Target: Router,
	L::Target: Logger,
{
	fn read<Reader: io::Read>(reader: &mut Reader, args: ChannelManagerReadArgs<'a, M, T, ES, NS, SP, F, R, L>) -> Result<Self, DecodeError> {
		let (blockhash, chan_manager) = <(BlockHash, ChannelManager<M, T, ES, NS, SP, F, R, L>)>::read(reader, args)?;
		Ok((blockhash, Arc::new(chan_manager)))
	}
}

impl<'a, M: Deref, T: Deref, ES: Deref, NS: Deref, SP: Deref, F: Deref, R: Deref, L: Deref>
	ReadableArgs<ChannelManagerReadArgs<'a, M, T, ES, NS, SP, F, R, L>> for (BlockHash, ChannelManager<M, T, ES, NS, SP, F, R, L>)
where
	M::Target: chain::Watch<<SP::Target as SignerProvider>::EcdsaSigner>,
	T::Target: BroadcasterInterface,
	ES::Target: EntropySource,
	NS::Target: NodeSigner,
	SP::Target: SignerProvider,
	F::Target: FeeEstimator,
	R::Target: Router,
	L::Target: Logger,
{
	fn read<Reader: io::Read>(reader: &mut Reader, mut args: ChannelManagerReadArgs<'a, M, T, ES, NS, SP, F, R, L>) -> Result<Self, DecodeError> {
		let _ver = read_ver_prefix!(reader, SERIALIZATION_VERSION);

		let chain_hash: ChainHash = Readable::read(reader)?;
		let best_block_height: u32 = Readable::read(reader)?;
		let best_block_hash: BlockHash = Readable::read(reader)?;

		let mut failed_htlcs = Vec::new();

		let channel_count: u64 = Readable::read(reader)?;
		let mut funding_txo_set = hash_set_with_capacity(cmp::min(channel_count as usize, 128));
		let mut funded_peer_channels: HashMap<PublicKey, HashMap<ChannelId, ChannelPhase<SP>>> = hash_map_with_capacity(cmp::min(channel_count as usize, 128));
		let mut outpoint_to_peer = hash_map_with_capacity(cmp::min(channel_count as usize, 128));
		let mut short_to_chan_info = hash_map_with_capacity(cmp::min(channel_count as usize, 128));
		let mut channel_closures = VecDeque::new();
		let mut close_background_events = Vec::new();
		let mut funding_txo_to_channel_id = hash_map_with_capacity(channel_count as usize);
		for _ in 0..channel_count {
			let mut channel: Channel<SP> = Channel::read(reader, (
				&args.entropy_source, &args.signer_provider, best_block_height, &provided_channel_type_features(&args.default_config)
			))?;
			let logger = WithChannelContext::from(&args.logger, &channel.context);
			let funding_txo = channel.context.get_funding_txo().ok_or(DecodeError::InvalidValue)?;
			funding_txo_to_channel_id.insert(funding_txo, channel.context.channel_id());
			funding_txo_set.insert(funding_txo.clone());
			if let Some(ref mut monitor) = args.channel_monitors.get_mut(&funding_txo) {
				if channel.get_cur_holder_commitment_transaction_number() > monitor.get_cur_holder_commitment_number() ||
						channel.get_revoked_counterparty_commitment_transaction_number() > monitor.get_min_seen_secret() ||
						channel.get_cur_counterparty_commitment_transaction_number() > monitor.get_cur_counterparty_commitment_number() ||
						channel.context.get_latest_monitor_update_id() < monitor.get_latest_update_id() {
					// But if the channel is behind of the monitor, close the channel:
					log_error!(logger, "A ChannelManager is stale compared to the current ChannelMonitor!");
					log_error!(logger, " The channel will be force-closed and the latest commitment transaction from the ChannelMonitor broadcast.");
					if channel.context.get_latest_monitor_update_id() < monitor.get_latest_update_id() {
						log_error!(logger, " The ChannelMonitor for channel {} is at update_id {} but the ChannelManager is at update_id {}.",
							&channel.context.channel_id(), monitor.get_latest_update_id(), channel.context.get_latest_monitor_update_id());
					}
					if channel.get_cur_holder_commitment_transaction_number() > monitor.get_cur_holder_commitment_number() {
						log_error!(logger, " The ChannelMonitor for channel {} is at holder commitment number {} but the ChannelManager is at holder commitment number {}.",
							&channel.context.channel_id(), monitor.get_cur_holder_commitment_number(), channel.get_cur_holder_commitment_transaction_number());
					}
					if channel.get_revoked_counterparty_commitment_transaction_number() > monitor.get_min_seen_secret() {
						log_error!(logger, " The ChannelMonitor for channel {} is at revoked counterparty transaction number {} but the ChannelManager is at revoked counterparty transaction number {}.",
							&channel.context.channel_id(), monitor.get_min_seen_secret(), channel.get_revoked_counterparty_commitment_transaction_number());
					}
					if channel.get_cur_counterparty_commitment_transaction_number() > monitor.get_cur_counterparty_commitment_number() {
						log_error!(logger, " The ChannelMonitor for channel {} is at counterparty commitment transaction number {} but the ChannelManager is at counterparty commitment transaction number {}.",
							&channel.context.channel_id(), monitor.get_cur_counterparty_commitment_number(), channel.get_cur_counterparty_commitment_transaction_number());
					}
					let mut shutdown_result = channel.context.force_shutdown(true, ClosureReason::OutdatedChannelManager);
					if shutdown_result.unbroadcasted_batch_funding_txid.is_some() {
						return Err(DecodeError::InvalidValue);
					}
					if let Some((counterparty_node_id, funding_txo, channel_id, update)) = shutdown_result.monitor_update {
						close_background_events.push(BackgroundEvent::MonitorUpdateRegeneratedOnStartup {
							counterparty_node_id, funding_txo, channel_id, update
						});
					}
					failed_htlcs.append(&mut shutdown_result.dropped_outbound_htlcs);
					channel_closures.push_back((events::Event::ChannelClosed {
						channel_id: channel.context.channel_id(),
						user_channel_id: channel.context.get_user_id(),
						reason: ClosureReason::OutdatedChannelManager,
						counterparty_node_id: Some(channel.context.get_counterparty_node_id()),
						channel_capacity_sats: Some(channel.context.get_value_satoshis()),
						channel_funding_txo: channel.context.get_funding_txo(),
					}, None));
					for (channel_htlc_source, payment_hash) in channel.inflight_htlc_sources() {
						let mut found_htlc = false;
						for (monitor_htlc_source, _) in monitor.get_all_current_outbound_htlcs() {
							if *channel_htlc_source == monitor_htlc_source { found_htlc = true; break; }
						}
						if !found_htlc {
							// If we have some HTLCs in the channel which are not present in the newer
							// ChannelMonitor, they have been removed and should be failed back to
							// ensure we don't forget them entirely. Note that if the missing HTLC(s)
							// were actually claimed we'd have generated and ensured the previous-hop
							// claim update ChannelMonitor updates were persisted prior to persising
							// the ChannelMonitor update for the forward leg, so attempting to fail the
							// backwards leg of the HTLC will simply be rejected.
							log_info!(logger,
								"Failing HTLC with hash {} as it is missing in the ChannelMonitor for channel {} but was present in the (stale) ChannelManager",
								&channel.context.channel_id(), &payment_hash);
							failed_htlcs.push((channel_htlc_source.clone(), *payment_hash, channel.context.get_counterparty_node_id(), channel.context.channel_id()));
						}
					}
				} else {
					log_info!(logger, "Successfully loaded channel {} at update_id {} against monitor at update id {}",
						&channel.context.channel_id(), channel.context.get_latest_monitor_update_id(),
						monitor.get_latest_update_id());
					if let Some(short_channel_id) = channel.context.get_short_channel_id() {
						short_to_chan_info.insert(short_channel_id, (channel.context.get_counterparty_node_id(), channel.context.channel_id()));
					}
					if let Some(funding_txo) = channel.context.get_funding_txo() {
						outpoint_to_peer.insert(funding_txo, channel.context.get_counterparty_node_id());
					}
					match funded_peer_channels.entry(channel.context.get_counterparty_node_id()) {
						hash_map::Entry::Occupied(mut entry) => {
							let by_id_map = entry.get_mut();
							by_id_map.insert(channel.context.channel_id(), ChannelPhase::Funded(channel));
						},
						hash_map::Entry::Vacant(entry) => {
							let mut by_id_map = new_hash_map();
							by_id_map.insert(channel.context.channel_id(), ChannelPhase::Funded(channel));
							entry.insert(by_id_map);
						}
					}
				}
			} else if channel.is_awaiting_initial_mon_persist() {
				// If we were persisted and shut down while the initial ChannelMonitor persistence
				// was in-progress, we never broadcasted the funding transaction and can still
				// safely discard the channel.
				let _ = channel.context.force_shutdown(false, ClosureReason::DisconnectedPeer);
				channel_closures.push_back((events::Event::ChannelClosed {
					channel_id: channel.context.channel_id(),
					user_channel_id: channel.context.get_user_id(),
					reason: ClosureReason::DisconnectedPeer,
					counterparty_node_id: Some(channel.context.get_counterparty_node_id()),
					channel_capacity_sats: Some(channel.context.get_value_satoshis()),
					channel_funding_txo: channel.context.get_funding_txo(),
				}, None));
			} else {
				log_error!(logger, "Missing ChannelMonitor for channel {} needed by ChannelManager.", &channel.context.channel_id());
				log_error!(logger, " The chain::Watch API *requires* that monitors are persisted durably before returning,");
				log_error!(logger, " client applications must ensure that ChannelMonitor data is always available and the latest to avoid funds loss!");
				log_error!(logger, " Without the ChannelMonitor we cannot continue without risking funds.");
				log_error!(logger, " Please ensure the chain::Watch API requirements are met and file a bug report at https://github.com/lightningdevkit/rust-lightning");
				return Err(DecodeError::InvalidValue);
			}
		}

		for (funding_txo, monitor) in args.channel_monitors.iter() {
			if !funding_txo_set.contains(funding_txo) {
				let logger = WithChannelMonitor::from(&args.logger, monitor);
				let channel_id = monitor.channel_id();
				log_info!(logger, "Queueing monitor update to ensure missing channel {} is force closed",
					&channel_id);
				let monitor_update = ChannelMonitorUpdate {
					update_id: CLOSED_CHANNEL_UPDATE_ID,
					counterparty_node_id: None,
					updates: vec![ChannelMonitorUpdateStep::ChannelForceClosed { should_broadcast: true }],
					channel_id: Some(monitor.channel_id()),
				};
				close_background_events.push(BackgroundEvent::ClosedMonitorUpdateRegeneratedOnStartup((*funding_txo, channel_id, monitor_update)));
			}
		}

		const MAX_ALLOC_SIZE: usize = 1024 * 64;
		let forward_htlcs_count: u64 = Readable::read(reader)?;
		let mut forward_htlcs = hash_map_with_capacity(cmp::min(forward_htlcs_count as usize, 128));
		for _ in 0..forward_htlcs_count {
			let short_channel_id = Readable::read(reader)?;
			let pending_forwards_count: u64 = Readable::read(reader)?;
			let mut pending_forwards = Vec::with_capacity(cmp::min(pending_forwards_count as usize, MAX_ALLOC_SIZE/mem::size_of::<HTLCForwardInfo>()));
			for _ in 0..pending_forwards_count {
				pending_forwards.push(Readable::read(reader)?);
			}
			forward_htlcs.insert(short_channel_id, pending_forwards);
		}

		let claimable_htlcs_count: u64 = Readable::read(reader)?;
		let mut claimable_htlcs_list = Vec::with_capacity(cmp::min(claimable_htlcs_count as usize, 128));
		for _ in 0..claimable_htlcs_count {
			let payment_hash = Readable::read(reader)?;
			let previous_hops_len: u64 = Readable::read(reader)?;
			let mut previous_hops = Vec::with_capacity(cmp::min(previous_hops_len as usize, MAX_ALLOC_SIZE/mem::size_of::<ClaimableHTLC>()));
			for _ in 0..previous_hops_len {
				previous_hops.push(<ClaimableHTLC as Readable>::read(reader)?);
			}
			claimable_htlcs_list.push((payment_hash, previous_hops));
		}

		let peer_state_from_chans = |channel_by_id| {
			PeerState {
				channel_by_id,
				inbound_channel_request_by_id: new_hash_map(),
				latest_features: InitFeatures::empty(),
				pending_msg_events: Vec::new(),
				in_flight_monitor_updates: BTreeMap::new(),
				monitor_update_blocked_actions: BTreeMap::new(),
				actions_blocking_raa_monitor_updates: BTreeMap::new(),
				is_connected: false,
			}
		};

		let peer_count: u64 = Readable::read(reader)?;
		let mut per_peer_state = hash_map_with_capacity(cmp::min(peer_count as usize, MAX_ALLOC_SIZE/mem::size_of::<(PublicKey, Mutex<PeerState<SP>>)>()));
		for _ in 0..peer_count {
			let peer_pubkey = Readable::read(reader)?;
			let peer_chans = funded_peer_channels.remove(&peer_pubkey).unwrap_or(new_hash_map());
			let mut peer_state = peer_state_from_chans(peer_chans);
			peer_state.latest_features = Readable::read(reader)?;
			per_peer_state.insert(peer_pubkey, Mutex::new(peer_state));
		}

		let event_count: u64 = Readable::read(reader)?;
		let mut pending_events_read: VecDeque<(events::Event, Option<EventCompletionAction>)> =
			VecDeque::with_capacity(cmp::min(event_count as usize, MAX_ALLOC_SIZE/mem::size_of::<(events::Event, Option<EventCompletionAction>)>()));
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
				}
				_ => return Err(DecodeError::InvalidValue),
			}
		}

		let _last_node_announcement_serial: u32 = Readable::read(reader)?; // Only used < 0.0.111
		let highest_seen_timestamp: u32 = Readable::read(reader)?;

		let pending_inbound_payment_count: u64 = Readable::read(reader)?;
		let mut pending_inbound_payments: HashMap<PaymentHash, PendingInboundPayment> = hash_map_with_capacity(cmp::min(pending_inbound_payment_count as usize, MAX_ALLOC_SIZE/(3*32)));
		for _ in 0..pending_inbound_payment_count {
			if pending_inbound_payments.insert(Readable::read(reader)?, Readable::read(reader)?).is_some() {
				return Err(DecodeError::InvalidValue);
			}
		}

		let pending_outbound_payments_count_compat: u64 = Readable::read(reader)?;
		let mut pending_outbound_payments_compat: HashMap<PaymentId, PendingOutboundPayment> =
			hash_map_with_capacity(cmp::min(pending_outbound_payments_count_compat as usize, MAX_ALLOC_SIZE/32));
		for _ in 0..pending_outbound_payments_count_compat {
			let session_priv = Readable::read(reader)?;
			let payment = PendingOutboundPayment::Legacy {
				session_privs: hash_set_from_iter([session_priv]),
			};
			if pending_outbound_payments_compat.insert(PaymentId(session_priv), payment).is_some() {
				return Err(DecodeError::InvalidValue)
			};
		}

		// pending_outbound_payments_no_retry is for compatibility with 0.0.101 clients.
		let mut pending_outbound_payments_no_retry: Option<HashMap<PaymentId, HashSet<[u8; 32]>>> = None;
		let mut pending_outbound_payments = None;
		let mut pending_intercepted_htlcs: Option<HashMap<InterceptId, PendingAddHTLCInfo>> = Some(new_hash_map());
		let mut received_network_pubkey: Option<PublicKey> = None;
		let mut fake_scid_rand_bytes: Option<[u8; 32]> = None;
		let mut probing_cookie_secret: Option<[u8; 32]> = None;
		let mut claimable_htlc_purposes = None;
		let mut claimable_htlc_onion_fields = None;
		let mut pending_claiming_payments = Some(new_hash_map());
		let mut monitor_update_blocked_actions_per_peer: Option<Vec<(_, BTreeMap<_, Vec<_>>)>> = Some(Vec::new());
		let mut events_override = None;
		let mut in_flight_monitor_updates: Option<HashMap<(PublicKey, OutPoint), Vec<ChannelMonitorUpdate>>> = None;
		let mut decode_update_add_htlcs: Option<HashMap<u64, Vec<msgs::UpdateAddHTLC>>> = None;
		read_tlv_fields!(reader, {
			(1, pending_outbound_payments_no_retry, option),
			(2, pending_intercepted_htlcs, option),
			(3, pending_outbound_payments, option),
			(4, pending_claiming_payments, option),
			(5, received_network_pubkey, option),
			(6, monitor_update_blocked_actions_per_peer, option),
			(7, fake_scid_rand_bytes, option),
			(8, events_override, option),
			(9, claimable_htlc_purposes, optional_vec),
			(10, in_flight_monitor_updates, option),
			(11, probing_cookie_secret, option),
			(13, claimable_htlc_onion_fields, optional_vec),
			(14, decode_update_add_htlcs, option),
		});
		let mut decode_update_add_htlcs = decode_update_add_htlcs.unwrap_or_else(|| new_hash_map());
		if fake_scid_rand_bytes.is_none() {
			fake_scid_rand_bytes = Some(args.entropy_source.get_secure_random_bytes());
		}

		if probing_cookie_secret.is_none() {
			probing_cookie_secret = Some(args.entropy_source.get_secure_random_bytes());
		}

		if let Some(events) = events_override {
			pending_events_read = events;
		}

		if !channel_closures.is_empty() {
			pending_events_read.append(&mut channel_closures);
		}

		if pending_outbound_payments.is_none() && pending_outbound_payments_no_retry.is_none() {
			pending_outbound_payments = Some(pending_outbound_payments_compat);
		} else if pending_outbound_payments.is_none() {
			let mut outbounds = new_hash_map();
			for (id, session_privs) in pending_outbound_payments_no_retry.unwrap().drain() {
				outbounds.insert(id, PendingOutboundPayment::Legacy { session_privs });
			}
			pending_outbound_payments = Some(outbounds);
		}
		let pending_outbounds = OutboundPayments {
			pending_outbound_payments: Mutex::new(pending_outbound_payments.unwrap()),
			retry_lock: Mutex::new(())
		};

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
			($counterparty_node_id: expr, $chan_in_flight_upds: expr, $funding_txo: expr,
			 $monitor: expr, $peer_state: expr, $logger: expr, $channel_info_log: expr
			) => { {
				let mut max_in_flight_update_id = 0;
				$chan_in_flight_upds.retain(|upd| upd.update_id > $monitor.get_latest_update_id());
				for update in $chan_in_flight_upds.iter() {
					log_trace!($logger, "Replaying ChannelMonitorUpdate {} for {}channel {}",
						update.update_id, $channel_info_log, &$monitor.channel_id());
					max_in_flight_update_id = cmp::max(max_in_flight_update_id, update.update_id);
					pending_background_events.push(
						BackgroundEvent::MonitorUpdateRegeneratedOnStartup {
							counterparty_node_id: $counterparty_node_id,
							funding_txo: $funding_txo,
							channel_id: $monitor.channel_id(),
							update: update.clone(),
						});
				}
				if $chan_in_flight_upds.is_empty() {
					// We had some updates to apply, but it turns out they had completed before we
					// were serialized, we just weren't notified of that. Thus, we may have to run
					// the completion actions for any monitor updates, but otherwise are done.
					pending_background_events.push(
						BackgroundEvent::MonitorUpdatesComplete {
							counterparty_node_id: $counterparty_node_id,
							channel_id: $monitor.channel_id(),
						});
				}
				if $peer_state.in_flight_monitor_updates.insert($funding_txo, $chan_in_flight_upds).is_some() {
					log_error!($logger, "Duplicate in-flight monitor update set for the same channel!");
					return Err(DecodeError::InvalidValue);
				}
				max_in_flight_update_id
			} }
		}

		for (counterparty_id, peer_state_mtx) in per_peer_state.iter_mut() {
			let mut peer_state_lock = peer_state_mtx.lock().unwrap();
			let peer_state = &mut *peer_state_lock;
			for phase in peer_state.channel_by_id.values() {
				if let ChannelPhase::Funded(chan) = phase {
					let logger = WithChannelContext::from(&args.logger, &chan.context);

					// Channels that were persisted have to be funded, otherwise they should have been
					// discarded.
					let funding_txo = chan.context.get_funding_txo().ok_or(DecodeError::InvalidValue)?;
					let monitor = args.channel_monitors.get(&funding_txo)
						.expect("We already checked for monitor presence when loading channels");
					let mut max_in_flight_update_id = monitor.get_latest_update_id();
					if let Some(in_flight_upds) = &mut in_flight_monitor_updates {
						if let Some(mut chan_in_flight_upds) = in_flight_upds.remove(&(*counterparty_id, funding_txo)) {
							max_in_flight_update_id = cmp::max(max_in_flight_update_id,
								handle_in_flight_updates!(*counterparty_id, chan_in_flight_upds,
									funding_txo, monitor, peer_state, logger, ""));
						}
					}
					if chan.get_latest_unblocked_monitor_update_id() > max_in_flight_update_id {
						// If the channel is ahead of the monitor, return DangerousValue:
						log_error!(logger, "A ChannelMonitor is stale compared to the current ChannelManager! This indicates a potentially-critical violation of the chain::Watch API!");
						log_error!(logger, " The ChannelMonitor for channel {} is at update_id {} with update_id through {} in-flight",
							chan.context.channel_id(), monitor.get_latest_update_id(), max_in_flight_update_id);
						log_error!(logger, " but the ChannelManager is at update_id {}.", chan.get_latest_unblocked_monitor_update_id());
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

		if let Some(in_flight_upds) = in_flight_monitor_updates {
			for ((counterparty_id, funding_txo), mut chan_in_flight_updates) in in_flight_upds {
				let channel_id = funding_txo_to_channel_id.get(&funding_txo).copied();
				let logger = WithContext::from(&args.logger, Some(counterparty_id), channel_id);
				if let Some(monitor) = args.channel_monitors.get(&funding_txo) {
					// Now that we've removed all the in-flight monitor updates for channels that are
					// still open, we need to replay any monitor updates that are for closed channels,
					// creating the neccessary peer_state entries as we go.
					let peer_state_mutex = per_peer_state.entry(counterparty_id).or_insert_with(|| {
						Mutex::new(peer_state_from_chans(new_hash_map()))
					});
					let mut peer_state = peer_state_mutex.lock().unwrap();
					handle_in_flight_updates!(counterparty_id, chan_in_flight_updates,
						funding_txo, monitor, peer_state, logger, "closed ");
				} else {
					log_error!(logger, "A ChannelMonitor is missing even though we have in-flight updates for it! This indicates a potentially-critical violation of the chain::Watch API!");
					log_error!(logger, " The ChannelMonitor for channel {} is missing.", if let Some(channel_id) =
						channel_id { channel_id.to_string() } else { format!("with outpoint {}", funding_txo) } );
					log_error!(logger, " The chain::Watch API *requires* that monitors are persisted durably before returning,");
					log_error!(logger, " client applications must ensure that ChannelMonitor data is always available and the latest to avoid funds loss!");
					log_error!(logger, " Without the latest ChannelMonitor we cannot continue without risking funds.");
					log_error!(logger, " Please ensure the chain::Watch API requirements are met and file a bug report at https://github.com/lightningdevkit/rust-lightning");
					return Err(DecodeError::InvalidValue);
				}
			}
		}

		// Note that we have to do the above replays before we push new monitor updates.
		pending_background_events.append(&mut close_background_events);

		// If there's any preimages for forwarded HTLCs hanging around in ChannelMonitors we
		// should ensure we try them again on the inbound edge. We put them here and do so after we
		// have a fully-constructed `ChannelManager` at the end.
		let mut pending_claims_to_replay = Vec::new();

		{
			// If we're tracking pending payments, ensure we haven't lost any by looking at the
			// ChannelMonitor data for any channels for which we do not have authorative state
			// (i.e. those for which we just force-closed above or we otherwise don't have a
			// corresponding `Channel` at all).
			// This avoids several edge-cases where we would otherwise "forget" about pending
			// payments which are still in-flight via their on-chain state.
			// We only rebuild the pending payments map if we were most recently serialized by
			// 0.0.102+
			for (_, monitor) in args.channel_monitors.iter() {
				let counterparty_opt = outpoint_to_peer.get(&monitor.get_funding_txo().0);
				if counterparty_opt.is_none() {
					let logger = WithChannelMonitor::from(&args.logger, monitor);
					for (htlc_source, (htlc, _)) in monitor.get_pending_or_resolved_outbound_htlcs() {
						if let HTLCSource::OutboundRoute { payment_id, session_priv, path, .. } = htlc_source {
							if path.hops.is_empty() {
								log_error!(logger, "Got an empty path for a pending payment");
								return Err(DecodeError::InvalidValue);
							}

							let path_amt = path.final_value_msat();
							let mut session_priv_bytes = [0; 32];
							session_priv_bytes[..].copy_from_slice(&session_priv[..]);
							match pending_outbounds.pending_outbound_payments.lock().unwrap().entry(payment_id) {
								hash_map::Entry::Occupied(mut entry) => {
									let newly_added = entry.get_mut().insert(session_priv_bytes, &path);
									log_info!(logger, "{} a pending payment path for {} msat for session priv {} on an existing pending payment with payment hash {}",
										if newly_added { "Added" } else { "Had" }, path_amt, log_bytes!(session_priv_bytes), htlc.payment_hash);
								},
								hash_map::Entry::Vacant(entry) => {
									let path_fee = path.fee_msat();
									entry.insert(PendingOutboundPayment::Retryable {
										retry_strategy: None,
										attempts: PaymentAttempts::new(),
										payment_params: None,
										session_privs: hash_set_from_iter([session_priv_bytes]),
										payment_hash: htlc.payment_hash,
										payment_secret: None, // only used for retries, and we'll never retry on startup
										payment_metadata: None, // only used for retries, and we'll never retry on startup
										keysend_preimage: None, // only used for retries, and we'll never retry on startup
										custom_tlvs: Vec::new(), // only used for retries, and we'll never retry on startup
										pending_amt_msat: path_amt,
										pending_fee_msat: Some(path_fee),
										total_msat: path_amt,
										starting_block_height: best_block_height,
										remaining_max_total_routing_fee_msat: None, // only used for retries, and we'll never retry on startup
									});
									log_info!(logger, "Added a pending payment for {} msat with payment hash {} for path with session priv {}",
										path_amt, &htlc.payment_hash,  log_bytes!(session_priv_bytes));
								}
							}
						}
					}
					for (htlc_source, (htlc, preimage_opt)) in monitor.get_all_current_outbound_htlcs() {
						match htlc_source {
							HTLCSource::PreviousHopData(prev_hop_data) => {
								let pending_forward_matches_htlc = |info: &PendingAddHTLCInfo| {
									info.prev_funding_outpoint == prev_hop_data.outpoint &&
										info.prev_htlc_id == prev_hop_data.htlc_id
								};
								// The ChannelMonitor is now responsible for this HTLC's
								// failure/success and will let us know what its outcome is. If we
								// still have an entry for this HTLC in `forward_htlcs` or
								// `pending_intercepted_htlcs`, we were apparently not persisted after
								// the monitor was when forwarding the payment.
								decode_update_add_htlcs.retain(|scid, update_add_htlcs| {
									update_add_htlcs.retain(|update_add_htlc| {
										let matches = *scid == prev_hop_data.short_channel_id &&
											update_add_htlc.htlc_id == prev_hop_data.htlc_id;
										if matches {
											log_info!(logger, "Removing pending to-decode HTLC with hash {} as it was forwarded to the closed channel {}",
												&htlc.payment_hash, &monitor.channel_id());
										}
										!matches
									});
									!update_add_htlcs.is_empty()
								});
								forward_htlcs.retain(|_, forwards| {
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
								pending_intercepted_htlcs.as_mut().unwrap().retain(|intercepted_id, htlc_info| {
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
							HTLCSource::OutboundRoute { payment_id, session_priv, path, .. } => {
								if let Some(preimage) = preimage_opt {
									let pending_events = Mutex::new(pending_events_read);
									// Note that we set `from_onchain` to "false" here,
									// deliberately keeping the pending payment around forever.
									// Given it should only occur when we have a channel we're
									// force-closing for being stale that's okay.
									// The alternative would be to wipe the state when claiming,
									// generating a `PaymentPathSuccessful` event but regenerating
									// it and the `PaymentSent` on every restart until the
									// `ChannelMonitor` is removed.
									let compl_action =
										EventCompletionAction::ReleaseRAAChannelMonitorUpdate {
											channel_funding_outpoint: monitor.get_funding_txo().0,
											channel_id: monitor.channel_id(),
											counterparty_node_id: path.hops[0].pubkey,
										};
									pending_outbounds.claim_htlc(payment_id, preimage, session_priv,
										path, false, compl_action, &pending_events, &&logger);
									pending_events_read = pending_events.into_inner().unwrap();
								}
							},
						}
					}
				}

				// Whether the downstream channel was closed or not, try to re-apply any payment
				// preimages from it which may be needed in upstream channels for forwarded
				// payments.
				let outbound_claimed_htlcs_iter = monitor.get_all_current_outbound_htlcs()
					.into_iter()
					.filter_map(|(htlc_source, (htlc, preimage_opt))| {
						if let HTLCSource::PreviousHopData(_) = htlc_source {
							if let Some(payment_preimage) = preimage_opt {
								Some((htlc_source, payment_preimage, htlc.amount_msat,
									// Check if `counterparty_opt.is_none()` to see if the
									// downstream chan is closed (because we don't have a
									// channel_id -> peer map entry).
									counterparty_opt.is_none(),
									counterparty_opt.cloned().or(monitor.get_counterparty_node_id()),
									monitor.get_funding_txo().0, monitor.channel_id()))
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
			}
		}

		if !forward_htlcs.is_empty() || !decode_update_add_htlcs.is_empty() || pending_outbounds.needs_abandon() {
			// If we have pending HTLCs to forward, assume we either dropped a
			// `PendingHTLCsForwardable` or the user received it but never processed it as they
			// shut down before the timer hit. Either way, set the time_forwardable to a small
			// constant as enough time has likely passed that we should simply handle the forwards
			// now, or at least after the user gets a chance to reconnect to our peers.
			pending_events_read.push_back((events::Event::PendingHTLCsForwardable {
				time_forwardable: Duration::from_secs(2),
			}, None));
		}

		let inbound_pmt_key_material = args.node_signer.get_inbound_payment_key_material();
		let expanded_inbound_key = inbound_payment::ExpandedKey::new(&inbound_pmt_key_material);

		let mut claimable_payments = hash_map_with_capacity(claimable_htlcs_list.len());
		if let Some(purposes) = claimable_htlc_purposes {
			if purposes.len() != claimable_htlcs_list.len() {
				return Err(DecodeError::InvalidValue);
			}
			if let Some(onion_fields) = claimable_htlc_onion_fields {
				if onion_fields.len() != claimable_htlcs_list.len() {
					return Err(DecodeError::InvalidValue);
				}
				for (purpose, (onion, (payment_hash, htlcs))) in
					purposes.into_iter().zip(onion_fields.into_iter().zip(claimable_htlcs_list.into_iter()))
				{
					let existing_payment = claimable_payments.insert(payment_hash, ClaimablePayment {
						purpose, htlcs, onion_fields: onion,
					});
					if existing_payment.is_some() { return Err(DecodeError::InvalidValue); }
				}
			} else {
				for (purpose, (payment_hash, htlcs)) in purposes.into_iter().zip(claimable_htlcs_list.into_iter()) {
					let existing_payment = claimable_payments.insert(payment_hash, ClaimablePayment {
						purpose, htlcs, onion_fields: None,
					});
					if existing_payment.is_some() { return Err(DecodeError::InvalidValue); }
				}
			}
		} else {
			// LDK versions prior to 0.0.107 did not write a `pending_htlc_purposes`, but do
			// include a `_legacy_hop_data` in the `OnionPayload`.
			for (payment_hash, htlcs) in claimable_htlcs_list.drain(..) {
				if htlcs.is_empty() {
					return Err(DecodeError::InvalidValue);
				}
				let purpose = match &htlcs[0].onion_payload {
					OnionPayload::Invoice { _legacy_hop_data } => {
						if let Some(hop_data) = _legacy_hop_data {
							events::PaymentPurpose::InvoicePayment {
								payment_preimage: match pending_inbound_payments.get(&payment_hash) {
									Some(inbound_payment) => inbound_payment.payment_preimage,
									None => match inbound_payment::verify(payment_hash, &hop_data, 0, &expanded_inbound_key, &args.logger) {
										Ok((payment_preimage, _)) => payment_preimage,
										Err(()) => {
											log_error!(args.logger, "Failed to read claimable payment data for HTLC with payment hash {} - was not a pending inbound payment and didn't match our payment key", &payment_hash);
											return Err(DecodeError::InvalidValue);
										}
									}
								},
								payment_secret: hop_data.payment_secret,
							}
						} else { return Err(DecodeError::InvalidValue); }
					},
					OnionPayload::Spontaneous(payment_preimage) =>
						events::PaymentPurpose::SpontaneousPayment(*payment_preimage),
				};
				claimable_payments.insert(payment_hash, ClaimablePayment {
					purpose, htlcs, onion_fields: None,
				});
			}
		}

		let mut secp_ctx = Secp256k1::new();
		secp_ctx.seeded_randomize(&args.entropy_source.get_secure_random_bytes());

		let our_network_pubkey = match args.node_signer.get_node_id(Recipient::Node) {
			Ok(key) => key,
			Err(()) => return Err(DecodeError::InvalidValue)
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
			for (chan_id, phase) in peer_state.channel_by_id.iter_mut() {
				if let ChannelPhase::Funded(chan) = phase {
					let logger = WithChannelContext::from(&args.logger, &chan.context);
					if chan.context.outbound_scid_alias() == 0 {
						let mut outbound_scid_alias;
						loop {
							outbound_scid_alias = fake_scid::Namespace::OutboundAlias
								.get_fake_scid(best_block_height, &chain_hash, fake_scid_rand_bytes.as_ref().unwrap(), &args.entropy_source);
							if outbound_scid_aliases.insert(outbound_scid_alias) { break; }
						}
						chan.context.set_outbound_scid_alias(outbound_scid_alias);
					} else if !outbound_scid_aliases.insert(chan.context.outbound_scid_alias()) {
						// Note that in rare cases its possible to hit this while reading an older
						// channel if we just happened to pick a colliding outbound alias above.
						log_error!(logger, "Got duplicate outbound SCID alias; {}", chan.context.outbound_scid_alias());
						return Err(DecodeError::InvalidValue);
					}
					if chan.context.is_usable() {
						if short_to_chan_info.insert(chan.context.outbound_scid_alias(), (chan.context.get_counterparty_node_id(), *chan_id)).is_some() {
							// Note that in rare cases its possible to hit this while reading an older
							// channel if we just happened to pick a colliding outbound alias above.
							log_error!(logger, "Got duplicate outbound SCID alias; {}", chan.context.outbound_scid_alias());
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

		for (_, monitor) in args.channel_monitors.iter() {
			for (payment_hash, payment_preimage) in monitor.get_stored_preimages() {
				if let Some(payment) = claimable_payments.remove(&payment_hash) {
					log_info!(args.logger, "Re-claiming HTLCs with payment hash {} as we've released the preimage to a ChannelMonitor!", &payment_hash);
					let mut claimable_amt_msat = 0;
					let mut receiver_node_id = Some(our_network_pubkey);
					let phantom_shared_secret = payment.htlcs[0].prev_hop.phantom_shared_secret;
					if phantom_shared_secret.is_some() {
						let phantom_pubkey = args.node_signer.get_node_id(Recipient::PhantomNode)
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
						if let Some(peer_node_id) = outpoint_to_peer.get(&claimable_htlc.prev_hop.outpoint) {
							let peer_state_mutex = per_peer_state.get(peer_node_id).unwrap();
							let mut peer_state_lock = peer_state_mutex.lock().unwrap();
							let peer_state = &mut *peer_state_lock;
							if let Some(ChannelPhase::Funded(channel)) = peer_state.channel_by_id.get_mut(&previous_channel_id) {
								let logger = WithChannelContext::from(&args.logger, &channel.context);
								channel.claim_htlc_while_disconnected_dropping_mon_update(claimable_htlc.prev_hop.htlc_id, payment_preimage, &&logger);
							}
						}
						if let Some(previous_hop_monitor) = args.channel_monitors.get(&claimable_htlc.prev_hop.outpoint) {
							previous_hop_monitor.provide_payment_preimage(&payment_hash, &payment_preimage, &args.tx_broadcaster, &bounded_fee_estimator, &args.logger);
						}
					}
					pending_events_read.push_back((events::Event::PaymentClaimed {
						receiver_node_id,
						payment_hash,
						purpose: payment.purpose,
						amount_msat: claimable_amt_msat,
						htlcs: payment.htlcs.iter().map(events::ClaimedHTLC::from).collect(),
						sender_intended_total_msat: payment.htlcs.first().map(|htlc| htlc.total_msat),
					}, None));
				}
			}
		}

		for (node_id, monitor_update_blocked_actions) in monitor_update_blocked_actions_per_peer.unwrap() {
			if let Some(peer_state) = per_peer_state.get(&node_id) {
				for (channel_id, actions) in monitor_update_blocked_actions.iter() {
					let logger = WithContext::from(&args.logger, Some(node_id), Some(*channel_id));
					for action in actions.iter() {
						if let MonitorUpdateCompletionAction::EmitEventAndFreeOtherChannel {
							downstream_counterparty_and_funding_outpoint:
								Some((blocked_node_id, _blocked_channel_outpoint, blocked_channel_id, blocking_action)), ..
						} = action {
							if let Some(blocked_peer_state) = per_peer_state.get(blocked_node_id) {
								log_trace!(logger,
									"Holding the next revoke_and_ack from {} until the preimage is durably persisted in the inbound edge's ChannelMonitor",
									blocked_channel_id);
								blocked_peer_state.lock().unwrap().actions_blocking_raa_monitor_updates
									.entry(*blocked_channel_id)
									.or_insert_with(Vec::new).push(blocking_action.clone());
							} else {
								// If the channel we were blocking has closed, we don't need to
								// worry about it - the blocked monitor update should never have
								// been released from the `Channel` object so it can't have
								// completed, and if the channel closed there's no reason to bother
								// anymore.
							}
						}
						if let MonitorUpdateCompletionAction::FreeOtherChannelImmediately { .. } = action {
							debug_assert!(false, "Non-event-generating channel freeing should not appear in our queue");
						}
					}
				}
				peer_state.lock().unwrap().monitor_update_blocked_actions = monitor_update_blocked_actions;
			} else {
				log_error!(WithContext::from(&args.logger, Some(node_id), None), "Got blocked actions without a per-peer-state for {}", node_id);
				return Err(DecodeError::InvalidValue);
			}
		}

		let channel_manager = ChannelManager {
			chain_hash,
			fee_estimator: bounded_fee_estimator,
			chain_monitor: args.chain_monitor,
			tx_broadcaster: args.tx_broadcaster,
			router: args.router,

			best_block: RwLock::new(BestBlock::new(best_block_hash, best_block_height)),

			inbound_payment_key: expanded_inbound_key,
			pending_inbound_payments: Mutex::new(pending_inbound_payments),
			pending_outbound_payments: pending_outbounds,
			pending_intercepted_htlcs: Mutex::new(pending_intercepted_htlcs.unwrap()),

			forward_htlcs: Mutex::new(forward_htlcs),
			decode_update_add_htlcs: Mutex::new(decode_update_add_htlcs),
			claimable_payments: Mutex::new(ClaimablePayments { claimable_payments, pending_claiming_payments: pending_claiming_payments.unwrap() }),
			outbound_scid_aliases: Mutex::new(outbound_scid_aliases),
			outpoint_to_peer: Mutex::new(outpoint_to_peer),
			short_to_chan_info: FairRwLock::new(short_to_chan_info),
			fake_scid_rand_bytes: fake_scid_rand_bytes.unwrap(),

			probing_cookie_secret: probing_cookie_secret.unwrap(),

			our_network_pubkey,
			secp_ctx,

			highest_seen_timestamp: AtomicUsize::new(highest_seen_timestamp as usize),

			per_peer_state: FairRwLock::new(per_peer_state),

			pending_events: Mutex::new(pending_events_read),
			pending_events_processor: AtomicBool::new(false),
			pending_background_events: Mutex::new(pending_background_events),
			total_consistency_lock: RwLock::new(()),
			background_events_processed_since_startup: AtomicBool::new(false),

			event_persist_notifier: Notifier::new(),
			needs_persist_flag: AtomicBool::new(false),

			funding_batch_states: Mutex::new(BTreeMap::new()),

			pending_offers_messages: Mutex::new(Vec::new()),

			pending_broadcast_messages: Mutex::new(Vec::new()),

			entropy_source: args.entropy_source,
			node_signer: args.node_signer,
			signer_provider: args.signer_provider,

			logger: args.logger,
			default_configuration: args.default_config,
		};

		for htlc_source in failed_htlcs.drain(..) {
			let (source, payment_hash, counterparty_node_id, channel_id) = htlc_source;
			let receiver = HTLCDestination::NextHopChannel { node_id: Some(counterparty_node_id), channel_id };
			let reason = HTLCFailReason::from_failure_code(0x4000 | 8);
			channel_manager.fail_htlc_backwards_internal(&source, &payment_hash, &reason, receiver);
		}

		for (source, preimage, downstream_value, downstream_closed, downstream_node_id, downstream_funding, downstream_channel_id) in pending_claims_to_replay {
			// We use `downstream_closed` in place of `from_onchain` here just as a guess - we
			// don't remember in the `ChannelMonitor` where we got a preimage from, but if the
			// channel is closed we just assume that it probably came from an on-chain claim.
			channel_manager.claim_funds_internal(source, preimage, Some(downstream_value), None,
				downstream_closed, true, downstream_node_id, downstream_funding,
				downstream_channel_id, None
			);
		}

		//TODO: Broadcast channel update for closed channels, but only after we've made a
		//connection or two.

		Ok((best_block_hash.clone(), channel_manager))
	}
}

#[cfg(test)]
mod tests {
	use bitcoin::hashes::Hash;
	use bitcoin::hashes::sha256::Hash as Sha256;
	use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
	use core::sync::atomic::Ordering;
	use crate::events::{Event, HTLCDestination, MessageSendEvent, MessageSendEventsProvider, ClosureReason};
	use crate::ln::{PaymentPreimage, PaymentHash, PaymentSecret};
	use crate::ln::ChannelId;
	use crate::ln::channelmanager::{create_recv_pending_htlc_info, HTLCForwardInfo, inbound_payment, PaymentId, PaymentSendFailure, RecipientOnionFields, InterceptId};
	use crate::ln::functional_test_utils::*;
	use crate::ln::msgs::{self, ErrorAction};
	use crate::ln::msgs::ChannelMessageHandler;
	use crate::prelude::*;
	use crate::routing::router::{PaymentParameters, RouteParameters, find_route};
	use crate::util::errors::APIError;
	use crate::util::ser::Writeable;
	use crate::util::test_utils;
	use crate::util::config::{ChannelConfig, ChannelConfigUpdate};
	use crate::sign::EntropySource;

	#[test]
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
		nodes[2].node.handle_channel_update(&nodes[1].node.get_our_node_id(), &chan.0);
		nodes[2].node.handle_channel_update(&nodes[1].node.get_our_node_id(), &chan.1);
		assert!(!nodes[2].node.get_event_or_persistence_needed_future().poll_is_complete());

		// The nodes which are a party to the channel should also ignore messages from unrelated
		// parties.
		nodes[0].node.handle_channel_update(&nodes[2].node.get_our_node_id(), &chan.0);
		nodes[0].node.handle_channel_update(&nodes[2].node.get_our_node_id(), &chan.1);
		nodes[1].node.handle_channel_update(&nodes[2].node.get_our_node_id(), &chan.0);
		nodes[1].node.handle_channel_update(&nodes[2].node.get_our_node_id(), &chan.1);
		assert!(!nodes[0].node.get_event_or_persistence_needed_future().poll_is_complete());
		assert!(!nodes[1].node.get_event_or_persistence_needed_future().poll_is_complete());

		// At this point the channel info given by peers should still be the same.
		assert_eq!(nodes[0].node.list_channels()[0], node_a_chan_info);
		assert_eq!(nodes[1].node.list_channels()[0], node_b_chan_info);

		// An earlier version of handle_channel_update didn't check the directionality of the
		// update message and would always update the local fee info, even if our peer was
		// (spuriously) forwarding us our own channel_update.
		let as_node_one = nodes[0].node.get_our_node_id().serialize()[..] < nodes[1].node.get_our_node_id().serialize()[..];
		let as_update = if as_node_one == (chan.0.contents.flags & 1 == 0 /* chan.0 is from node one */) { &chan.0 } else { &chan.1 };
		let bs_update = if as_node_one == (chan.0.contents.flags & 1 == 0 /* chan.0 is from node one */) { &chan.1 } else { &chan.0 };

		// First deliver each peers' own message, checking that the node doesn't need to be
		// persisted and that its channel info remains the same.
		nodes[0].node.handle_channel_update(&nodes[1].node.get_our_node_id(), &as_update);
		nodes[1].node.handle_channel_update(&nodes[0].node.get_our_node_id(), &bs_update);
		assert!(!nodes[0].node.get_event_or_persistence_needed_future().poll_is_complete());
		assert!(!nodes[1].node.get_event_or_persistence_needed_future().poll_is_complete());
		assert_eq!(nodes[0].node.list_channels()[0], node_a_chan_info);
		assert_eq!(nodes[1].node.list_channels()[0], node_b_chan_info);

		// Finally, deliver the other peers' message, ensuring each node needs to be persisted and
		// the channel info has updated.
		nodes[0].node.handle_channel_update(&nodes[1].node.get_our_node_id(), &bs_update);
		nodes[1].node.handle_channel_update(&nodes[0].node.get_our_node_id(), &as_update);
		assert!(nodes[0].node.get_event_or_persistence_needed_future().poll_is_complete());
		assert!(nodes[1].node.get_event_or_persistence_needed_future().poll_is_complete());
		assert_ne!(nodes[0].node.list_channels()[0], node_a_chan_info);
		assert_ne!(nodes[1].node.list_channels()[0], node_b_chan_info);
	}

	#[test]
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
		check_added_monitors!(nodes[0], 1);
		let mut events = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		pass_along_path(&nodes[0], &[&nodes[1]], 200_000, our_payment_hash, Some(payment_secret), events.drain(..).next().unwrap(), false, None);

		// Next, send a keysend payment with the same payment_hash and make sure it fails.
		nodes[0].node.send_spontaneous_payment(&route, Some(payment_preimage),
			RecipientOnionFields::spontaneous_empty(), PaymentId(payment_preimage.0)).unwrap();
		check_added_monitors!(nodes[0], 1);
		let mut events = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		let ev = events.drain(..).next().unwrap();
		let payment_event = SendEvent::from_event(ev);
		nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &payment_event.msgs[0]);
		check_added_monitors!(nodes[1], 0);
		commitment_signed_dance!(nodes[1], nodes[0], payment_event.commitment_msg, false);
		expect_pending_htlcs_forwardable!(nodes[1]);
		expect_pending_htlcs_forwardable_and_htlc_handling_failed!(nodes[1], vec![HTLCDestination::FailedPayment { payment_hash: our_payment_hash }]);
		check_added_monitors!(nodes[1], 1);
		let updates = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
		assert!(updates.update_add_htlcs.is_empty());
		assert!(updates.update_fulfill_htlcs.is_empty());
		assert_eq!(updates.update_fail_htlcs.len(), 1);
		assert!(updates.update_fail_malformed_htlcs.is_empty());
		assert!(updates.update_fee.is_none());
		nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &updates.update_fail_htlcs[0]);
		commitment_signed_dance!(nodes[0], nodes[1], updates.commitment_signed, true, true);
		expect_payment_failed!(nodes[0], our_payment_hash, true);

		// Send the second half of the original MPP payment.
		nodes[0].node.test_send_payment_along_path(&mpp_route.paths[1], &our_payment_hash,
			RecipientOnionFields::secret_only(payment_secret), 200_000, cur_height, payment_id, &None, session_privs[1]).unwrap();
		check_added_monitors!(nodes[0], 1);
		let mut events = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		pass_along_path(&nodes[0], &[&nodes[1]], 200_000, our_payment_hash, Some(payment_secret), events.drain(..).next().unwrap(), true, None);

		// Claim the full MPP payment. Note that we can't use a test utility like
		// claim_funds_along_route because the ordering of the messages causes the second half of the
		// payment to be put in the holding cell, which confuses the test utilities. So we exchange the
		// lightning messages manually.
		nodes[1].node.claim_funds(payment_preimage);
		expect_payment_claimed!(nodes[1], our_payment_hash, 200_000);
		check_added_monitors!(nodes[1], 2);

		let bs_first_updates = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
		nodes[0].node.handle_update_fulfill_htlc(&nodes[1].node.get_our_node_id(), &bs_first_updates.update_fulfill_htlcs[0]);
		expect_payment_sent(&nodes[0], payment_preimage, None, false, false);
		nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &bs_first_updates.commitment_signed);
		check_added_monitors!(nodes[0], 1);
		let (as_first_raa, as_first_cs) = get_revoke_commit_msgs!(nodes[0], nodes[1].node.get_our_node_id());
		nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &as_first_raa);
		check_added_monitors!(nodes[1], 1);
		let bs_second_updates = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
		nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &as_first_cs);
		check_added_monitors!(nodes[1], 1);
		let bs_first_raa = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, nodes[0].node.get_our_node_id());
		nodes[0].node.handle_update_fulfill_htlc(&nodes[1].node.get_our_node_id(), &bs_second_updates.update_fulfill_htlcs[0]);
		nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &bs_second_updates.commitment_signed);
		check_added_monitors!(nodes[0], 1);
		let as_second_raa = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());
		nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_first_raa);
		let as_second_updates = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
		check_added_monitors!(nodes[0], 1);
		nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &as_second_raa);
		check_added_monitors!(nodes[1], 1);
		nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &as_second_updates.commitment_signed);
		check_added_monitors!(nodes[1], 1);
		let bs_third_raa = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, nodes[0].node.get_our_node_id());
		nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_third_raa);
		check_added_monitors!(nodes[0], 1);

		// Note that successful MPP payments will generate a single PaymentSent event upon the first
		// path's success and a PaymentPathSuccessful event for each path's success.
		let events = nodes[0].node.get_and_clear_pending_events();
		assert_eq!(events.len(), 2);
		match events[0] {
			Event::PaymentPathSuccessful { payment_id: ref actual_payment_id, ref payment_hash, ref path } => {
				assert_eq!(payment_id, *actual_payment_id);
				assert_eq!(our_payment_hash, *payment_hash.as_ref().unwrap());
				assert_eq!(route.paths[0], *path);
			},
			_ => panic!("Unexpected event"),
		}
		match events[1] {
			Event::PaymentPathSuccessful { payment_id: ref actual_payment_id, ref payment_hash, ref path } => {
				assert_eq!(payment_id, *actual_payment_id);
				assert_eq!(our_payment_hash, *payment_hash.as_ref().unwrap());
				assert_eq!(route.paths[0], *path);
			},
			_ => panic!("Unexpected event"),
		}
	}

	#[test]
	fn test_keysend_dup_payment_hash() {
		do_test_keysend_dup_payment_hash(false);
		do_test_keysend_dup_payment_hash(true);
	}

	fn do_test_keysend_dup_payment_hash(accept_mpp_keysend: bool) {
		// (1): Test that a keysend payment with a duplicate payment hash to an existing pending
		//      outbound regular payment fails as expected.
		// (2): Test that a regular payment with a duplicate payment hash to an existing keysend payment
		//      fails as expected.
		// (3): Test that a keysend payment with a duplicate payment hash to an existing keysend
		//      payment fails as expected. When `accept_mpp_keysend` is false, this tests that we
		//      reject MPP keysend payments, since in this case where the payment has no payment
		//      secret, a keysend payment with a duplicate hash is basically an MPP keysend. If
		//      `accept_mpp_keysend` is true, this tests that we only accept MPP keysends with
		//      payment secrets and reject otherwise.
		let chanmon_cfgs = create_chanmon_cfgs(2);
		let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
		let mut mpp_keysend_cfg = test_default_channel_config();
		mpp_keysend_cfg.accept_mpp_keysend = accept_mpp_keysend;
		let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, Some(mpp_keysend_cfg)]);
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
		let route = find_route(
			&nodes[0].node.get_our_node_id(), &route_params, &nodes[0].network_graph,
			None, nodes[0].logger, &scorer, &Default::default(), &random_seed_bytes
		).unwrap();
		nodes[0].node.send_spontaneous_payment(&route, Some(payment_preimage),
			RecipientOnionFields::spontaneous_empty(), PaymentId(payment_preimage.0)).unwrap();
		check_added_monitors!(nodes[0], 1);
		let mut events = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		let ev = events.drain(..).next().unwrap();
		let payment_event = SendEvent::from_event(ev);
		nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &payment_event.msgs[0]);
		check_added_monitors!(nodes[1], 0);
		commitment_signed_dance!(nodes[1], nodes[0], payment_event.commitment_msg, false);
		// We have to forward pending HTLCs twice - once tries to forward the payment forward (and
		// fails), the second will process the resulting failure and fail the HTLC backward
		expect_pending_htlcs_forwardable!(nodes[1]);
		expect_pending_htlcs_forwardable_and_htlc_handling_failed!(nodes[1], vec![HTLCDestination::FailedPayment { payment_hash }]);
		check_added_monitors!(nodes[1], 1);
		let updates = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
		assert!(updates.update_add_htlcs.is_empty());
		assert!(updates.update_fulfill_htlcs.is_empty());
		assert_eq!(updates.update_fail_htlcs.len(), 1);
		assert!(updates.update_fail_malformed_htlcs.is_empty());
		assert!(updates.update_fee.is_none());
		nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &updates.update_fail_htlcs[0]);
		commitment_signed_dance!(nodes[0], nodes[1], updates.commitment_signed, true, true);
		expect_payment_failed!(nodes[0], payment_hash, true);

		// Finally, claim the original payment.
		claim_payment(&nodes[0], &expected_route, payment_preimage);

		// To start (2), send a keysend payment but don't claim it.
		let payment_preimage = PaymentPreimage([42; 32]);
		let route = find_route(
			&nodes[0].node.get_our_node_id(), &route_params, &nodes[0].network_graph,
			None, nodes[0].logger, &scorer, &Default::default(), &random_seed_bytes
		).unwrap();
		let payment_hash = nodes[0].node.send_spontaneous_payment(&route, Some(payment_preimage),
			RecipientOnionFields::spontaneous_empty(), PaymentId(payment_preimage.0)).unwrap();
		check_added_monitors!(nodes[0], 1);
		let mut events = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		let event = events.pop().unwrap();
		let path = vec![&nodes[1]];
		pass_along_path(&nodes[0], &path, 100_000, payment_hash, None, event, true, Some(payment_preimage));

		// Next, attempt a regular payment and make sure it fails.
		let payment_secret = PaymentSecret([43; 32]);
		nodes[0].node.send_payment_with_route(&route, payment_hash,
			RecipientOnionFields::secret_only(payment_secret), PaymentId(payment_hash.0)).unwrap();
		check_added_monitors!(nodes[0], 1);
		let mut events = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		let ev = events.drain(..).next().unwrap();
		let payment_event = SendEvent::from_event(ev);
		nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &payment_event.msgs[0]);
		check_added_monitors!(nodes[1], 0);
		commitment_signed_dance!(nodes[1], nodes[0], payment_event.commitment_msg, false);
		expect_pending_htlcs_forwardable!(nodes[1]);
		expect_pending_htlcs_forwardable_and_htlc_handling_failed!(nodes[1], vec![HTLCDestination::FailedPayment { payment_hash }]);
		check_added_monitors!(nodes[1], 1);
		let updates = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
		assert!(updates.update_add_htlcs.is_empty());
		assert!(updates.update_fulfill_htlcs.is_empty());
		assert_eq!(updates.update_fail_htlcs.len(), 1);
		assert!(updates.update_fail_malformed_htlcs.is_empty());
		assert!(updates.update_fee.is_none());
		nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &updates.update_fail_htlcs[0]);
		commitment_signed_dance!(nodes[0], nodes[1], updates.commitment_signed, true, true);
		expect_payment_failed!(nodes[0], payment_hash, true);

		// Finally, succeed the keysend payment.
		claim_payment(&nodes[0], &expected_route, payment_preimage);

		// To start (3), send a keysend payment but don't claim it.
		let payment_id_1 = PaymentId([44; 32]);
		let payment_hash = nodes[0].node.send_spontaneous_payment(&route, Some(payment_preimage),
			RecipientOnionFields::spontaneous_empty(), payment_id_1).unwrap();
		check_added_monitors!(nodes[0], 1);
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
		let route = find_route(
			&nodes[0].node.get_our_node_id(), &route_params, &nodes[0].network_graph,
			None, nodes[0].logger, &scorer, &Default::default(), &random_seed_bytes
		).unwrap();
		let payment_id_2 = PaymentId([45; 32]);
		nodes[0].node.send_spontaneous_payment(&route, Some(payment_preimage),
			RecipientOnionFields::spontaneous_empty(), payment_id_2).unwrap();
		check_added_monitors!(nodes[0], 1);
		let mut events = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		let ev = events.drain(..).next().unwrap();
		let payment_event = SendEvent::from_event(ev);
		nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &payment_event.msgs[0]);
		check_added_monitors!(nodes[1], 0);
		commitment_signed_dance!(nodes[1], nodes[0], payment_event.commitment_msg, false);
		expect_pending_htlcs_forwardable!(nodes[1]);
		expect_pending_htlcs_forwardable_and_htlc_handling_failed!(nodes[1], vec![HTLCDestination::FailedPayment { payment_hash }]);
		check_added_monitors!(nodes[1], 1);
		let updates = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
		assert!(updates.update_add_htlcs.is_empty());
		assert!(updates.update_fulfill_htlcs.is_empty());
		assert_eq!(updates.update_fail_htlcs.len(), 1);
		assert!(updates.update_fail_malformed_htlcs.is_empty());
		assert!(updates.update_fee.is_none());
		nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &updates.update_fail_htlcs[0]);
		commitment_signed_dance!(nodes[0], nodes[1], updates.commitment_signed, true, true);
		expect_payment_failed!(nodes[0], payment_hash, true);

		// Finally, claim the original payment.
		claim_payment(&nodes[0], &expected_route, payment_preimage);
	}

	#[test]
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
		check_added_monitors!(nodes[0], 1);

		let updates = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
		assert_eq!(updates.update_add_htlcs.len(), 1);
		assert!(updates.update_fulfill_htlcs.is_empty());
		assert!(updates.update_fail_htlcs.is_empty());
		assert!(updates.update_fail_malformed_htlcs.is_empty());
		assert!(updates.update_fee.is_none());
		nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &updates.update_add_htlcs[0]);

		nodes[1].logger.assert_log_contains("lightning::ln::channelmanager", "Payment preimage didn't match payment hash", 1);
	}

	#[test]
	fn test_keysend_msg_with_secret_err() {
		// Test that we error as expected if we receive a keysend payment that includes a payment
		// secret when we don't support MPP keysend.
		let mut reject_mpp_keysend_cfg = test_default_channel_config();
		reject_mpp_keysend_cfg.accept_mpp_keysend = false;
		let chanmon_cfgs = create_chanmon_cfgs(2);
		let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
		let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, Some(reject_mpp_keysend_cfg)]);
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
		let test_secret = PaymentSecret([43; 32]);
		let payment_hash = PaymentHash(Sha256::hash(&test_preimage.0).to_byte_array());
		let session_privs = nodes[0].node.test_add_new_pending_payment(payment_hash,
			RecipientOnionFields::secret_only(test_secret), PaymentId(payment_hash.0), &route).unwrap();
		nodes[0].node.test_send_payment_internal(&route, payment_hash,
			RecipientOnionFields::secret_only(test_secret), Some(test_preimage),
			PaymentId(payment_hash.0), None, session_privs).unwrap();
		check_added_monitors!(nodes[0], 1);

		let updates = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
		assert_eq!(updates.update_add_htlcs.len(), 1);
		assert!(updates.update_fulfill_htlcs.is_empty());
		assert!(updates.update_fail_htlcs.is_empty());
		assert!(updates.update_fail_malformed_htlcs.is_empty());
		assert!(updates.update_fee.is_none());
		nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &updates.update_add_htlcs[0]);

		nodes[1].logger.assert_log_contains("lightning::ln::channelmanager", "We don't support MPP keysend payments", 1);
	}

	#[test]
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

		match nodes[0].node.send_payment_with_route(&route, payment_hash,
			RecipientOnionFields::spontaneous_empty(), PaymentId(payment_hash.0))
		.unwrap_err() {
			PaymentSendFailure::ParameterError(APIError::APIMisuseError { ref err }) => {
				assert!(regex::Regex::new(r"Payment secret is required for multi-path payments").unwrap().is_match(err))
			},
			_ => panic!("unexpected error")
		}
	}

	#[test]
	fn test_channel_update_cached() {
		let chanmon_cfgs = create_chanmon_cfgs(3);
		let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
		let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
		let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

		let chan = create_announced_chan_between_nodes(&nodes, 0, 1);

		nodes[0].node.force_close_channel_with_peer(&chan.2, &nodes[1].node.get_our_node_id(), None, true).unwrap();
		check_added_monitors!(nodes[0], 1);
		check_closed_event!(nodes[0], 1, ClosureReason::HolderForceClosed, [nodes[1].node.get_our_node_id()], 100000);

		// Confirm that the channel_update was not sent immediately to node[1] but was cached.
		let node_1_events = nodes[1].node.get_and_clear_pending_msg_events();
		assert_eq!(node_1_events.len(), 0);

		{
			// Assert that ChannelUpdate message has been added to node[0] pending broadcast messages
			let pending_broadcast_messages= nodes[0].node.pending_broadcast_messages.lock().unwrap();
			assert_eq!(pending_broadcast_messages.len(), 1);
		}

		// Test that we do not retrieve the pending broadcast messages when we are not connected to any peer
		nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id());
		nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id());

		nodes[0].node.peer_disconnected(&nodes[2].node.get_our_node_id());
		nodes[2].node.peer_disconnected(&nodes[0].node.get_our_node_id());

		let node_0_events = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(node_0_events.len(), 0);

		// Now we reconnect to a peer
		nodes[0].node.peer_connected(&nodes[2].node.get_our_node_id(), &msgs::Init {
			features: nodes[2].node.init_features(), networks: None, remote_network_address: None
		}, true).unwrap();
		nodes[2].node.peer_connected(&nodes[0].node.get_our_node_id(), &msgs::Init {
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
	fn test_drop_disconnected_peers_when_removing_channels() {
		let chanmon_cfgs = create_chanmon_cfgs(2);
		let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
		let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
		let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

		let chan = create_announced_chan_between_nodes(&nodes, 0, 1);

		nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id());
		nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id());

		nodes[0].node.force_close_broadcasting_latest_txn(&chan.2, &nodes[1].node.get_our_node_id()).unwrap();
		check_closed_broadcast!(nodes[0], true);
		check_added_monitors!(nodes[0], 1);
		check_closed_event!(nodes[0], 1, ClosureReason::HolderForceClosed, [nodes[1].node.get_our_node_id()], 100000);

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
	fn bad_inbound_payment_hash() {
		// Add coverage for checking that a user-provided payment hash matches the payment secret.
		let chanmon_cfgs = create_chanmon_cfgs(2);
		let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
		let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
		let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

		let (_, payment_hash, payment_secret) = get_payment_preimage_hash!(&nodes[0]);
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

	#[test]
	fn test_outpoint_to_peer_coverage() {
		// Test that the `ChannelManager:outpoint_to_peer` contains channels which have been assigned
		// a `channel_id` (i.e. have had the funding tx created), and that they are removed once
		// the channel is successfully closed.
		let chanmon_cfgs = create_chanmon_cfgs(2);
		let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
		let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
		let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

		nodes[0].node.create_channel(nodes[1].node.get_our_node_id(), 1_000_000, 500_000_000, 42, None, None).unwrap();
		let open_channel = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, nodes[1].node.get_our_node_id());
		nodes[1].node.handle_open_channel(&nodes[0].node.get_our_node_id(), &open_channel);
		let accept_channel = get_event_msg!(nodes[1], MessageSendEvent::SendAcceptChannel, nodes[0].node.get_our_node_id());
		nodes[0].node.handle_accept_channel(&nodes[1].node.get_our_node_id(), &accept_channel);

		let (temporary_channel_id, tx, funding_output) = create_funding_transaction(&nodes[0], &nodes[1].node.get_our_node_id(), 1_000_000, 42);
		let channel_id = ChannelId::from_bytes(tx.txid().to_byte_array());
		{
			// Ensure that the `outpoint_to_peer` map is empty until either party has received the
			// funding transaction, and have the real `channel_id`.
			assert_eq!(nodes[0].node.outpoint_to_peer.lock().unwrap().len(), 0);
			assert_eq!(nodes[1].node.outpoint_to_peer.lock().unwrap().len(), 0);
		}

		nodes[0].node.funding_transaction_generated(&temporary_channel_id, &nodes[1].node.get_our_node_id(), tx.clone()).unwrap();
		{
			// Assert that `nodes[0]`'s `outpoint_to_peer` map is populated with the channel as soon as
			// as it has the funding transaction.
			let nodes_0_lock = nodes[0].node.outpoint_to_peer.lock().unwrap();
			assert_eq!(nodes_0_lock.len(), 1);
			assert!(nodes_0_lock.contains_key(&funding_output));
		}

		assert_eq!(nodes[1].node.outpoint_to_peer.lock().unwrap().len(), 0);

		let funding_created_msg = get_event_msg!(nodes[0], MessageSendEvent::SendFundingCreated, nodes[1].node.get_our_node_id());

		nodes[1].node.handle_funding_created(&nodes[0].node.get_our_node_id(), &funding_created_msg);
		{
			let nodes_0_lock = nodes[0].node.outpoint_to_peer.lock().unwrap();
			assert_eq!(nodes_0_lock.len(), 1);
			assert!(nodes_0_lock.contains_key(&funding_output));
		}
		expect_channel_pending_event(&nodes[1], &nodes[0].node.get_our_node_id());

		{
			// Assert that `nodes[1]`'s `outpoint_to_peer` map is populated with the channel as
			// soon as it has the funding transaction.
			let nodes_1_lock = nodes[1].node.outpoint_to_peer.lock().unwrap();
			assert_eq!(nodes_1_lock.len(), 1);
			assert!(nodes_1_lock.contains_key(&funding_output));
		}
		check_added_monitors!(nodes[1], 1);
		let funding_signed = get_event_msg!(nodes[1], MessageSendEvent::SendFundingSigned, nodes[0].node.get_our_node_id());
		nodes[0].node.handle_funding_signed(&nodes[1].node.get_our_node_id(), &funding_signed);
		check_added_monitors!(nodes[0], 1);
		expect_channel_pending_event(&nodes[0], &nodes[1].node.get_our_node_id());
		let (channel_ready, _) = create_chan_between_nodes_with_value_confirm(&nodes[0], &nodes[1], &tx);
		let (announcement, nodes_0_update, nodes_1_update) = create_chan_between_nodes_with_value_b(&nodes[0], &nodes[1], &channel_ready);
		update_nodes_with_chan_announce(&nodes, 0, 1, &announcement, &nodes_0_update, &nodes_1_update);

		nodes[0].node.close_channel(&channel_id, &nodes[1].node.get_our_node_id()).unwrap();
		nodes[1].node.handle_shutdown(&nodes[0].node.get_our_node_id(), &get_event_msg!(nodes[0], MessageSendEvent::SendShutdown, nodes[1].node.get_our_node_id()));
		let nodes_1_shutdown = get_event_msg!(nodes[1], MessageSendEvent::SendShutdown, nodes[0].node.get_our_node_id());
		nodes[0].node.handle_shutdown(&nodes[1].node.get_our_node_id(), &nodes_1_shutdown);

		let closing_signed_node_0 = get_event_msg!(nodes[0], MessageSendEvent::SendClosingSigned, nodes[1].node.get_our_node_id());
		nodes[1].node.handle_closing_signed(&nodes[0].node.get_our_node_id(), &closing_signed_node_0);
		{
			// Assert that the channel is kept in the `outpoint_to_peer` map for both nodes until the
			// channel can be fully closed by both parties (i.e. no outstanding htlcs exists, the
			// fee for the closing transaction has been negotiated and the parties has the other
			// party's signature for the fee negotiated closing transaction.)
			let nodes_0_lock = nodes[0].node.outpoint_to_peer.lock().unwrap();
			assert_eq!(nodes_0_lock.len(), 1);
			assert!(nodes_0_lock.contains_key(&funding_output));
		}

		{
			// At this stage, `nodes[1]` has proposed a fee for the closing transaction in the
			// `handle_closing_signed` call above. As `nodes[1]` has not yet received the signature
			// from `nodes[0]` for the closing transaction with the proposed fee, the channel is
			// kept in the `nodes[1]`'s `outpoint_to_peer` map.
			let nodes_1_lock = nodes[1].node.outpoint_to_peer.lock().unwrap();
			assert_eq!(nodes_1_lock.len(), 1);
			assert!(nodes_1_lock.contains_key(&funding_output));
		}

		nodes[0].node.handle_closing_signed(&nodes[1].node.get_our_node_id(), &get_event_msg!(nodes[1], MessageSendEvent::SendClosingSigned, nodes[0].node.get_our_node_id()));
		{
			// `nodes[0]` accepts `nodes[1]`'s proposed fee for the closing transaction, and
			// therefore has all it needs to fully close the channel (both signatures for the
			// closing transaction).
			// Assert that the channel is removed from `nodes[0]`'s `outpoint_to_peer` map as it can be
			// fully closed by `nodes[0]`.
			assert_eq!(nodes[0].node.outpoint_to_peer.lock().unwrap().len(), 0);

			// Assert that the channel is still in `nodes[1]`'s  `outpoint_to_peer` map, as `nodes[1]`
			// doesn't have `nodes[0]`'s signature for the closing transaction yet.
			let nodes_1_lock = nodes[1].node.outpoint_to_peer.lock().unwrap();
			assert_eq!(nodes_1_lock.len(), 1);
			assert!(nodes_1_lock.contains_key(&funding_output));
		}

		let (_nodes_0_update, closing_signed_node_0) = get_closing_signed_broadcast!(nodes[0].node, nodes[1].node.get_our_node_id());

		nodes[1].node.handle_closing_signed(&nodes[0].node.get_our_node_id(), &closing_signed_node_0.unwrap());
		{
			// Assert that the channel has now been removed from both parties `outpoint_to_peer` map once
			// they both have everything required to fully close the channel.
			assert_eq!(nodes[1].node.outpoint_to_peer.lock().unwrap().len(), 0);
		}
		let (_nodes_1_update, _none) = get_closing_signed_broadcast!(nodes[1].node, nodes[0].node.get_our_node_id());

		check_closed_event!(nodes[0], 1, ClosureReason::LocallyInitiatedCooperativeClosure, [nodes[1].node.get_our_node_id()], 1000000);
		check_closed_event!(nodes[1], 1, ClosureReason::CounterpartyInitiatedCooperativeClosure, [nodes[0].node.get_our_node_id()], 1000000);
	}

	fn check_not_connected_to_peer_error<T>(res_err: Result<T, APIError>, expected_public_key: PublicKey) {
		let expected_message = format!("Not connected to node: {}", expected_public_key);
		check_api_error_message(expected_message, res_err)
	}

	fn check_unkown_peer_error<T>(res_err: Result<T, APIError>, expected_public_key: PublicKey) {
		let expected_message = format!("Can't find a peer matching the passed counterparty node_id {}", expected_public_key);
		check_api_error_message(expected_message, res_err)
	}

	fn check_channel_unavailable_error<T>(res_err: Result<T, APIError>, expected_channel_id: ChannelId, peer_node_id: PublicKey) {
		let expected_message = format!("Channel with id {} not found for the passed counterparty node_id {}", expected_channel_id, peer_node_id);
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

		// Test the API functions.
		check_not_connected_to_peer_error(nodes[0].node.create_channel(unkown_public_key, 1_000_000, 500_000_000, 42, None, None), unkown_public_key);

		check_unkown_peer_error(nodes[0].node.accept_inbound_channel(&channel_id, &unkown_public_key, 42), unkown_public_key);

		check_unkown_peer_error(nodes[0].node.close_channel(&channel_id, &unkown_public_key), unkown_public_key);

		check_unkown_peer_error(nodes[0].node.force_close_broadcasting_latest_txn(&channel_id, &unkown_public_key), unkown_public_key);

		check_unkown_peer_error(nodes[0].node.force_close_without_broadcasting_txn(&channel_id, &unkown_public_key), unkown_public_key);

		check_unkown_peer_error(nodes[0].node.forward_intercepted_htlc(intercept_id, &channel_id, unkown_public_key, 1_000_000), unkown_public_key);

		check_unkown_peer_error(nodes[0].node.update_channel_config(&unkown_public_key, &[channel_id], &ChannelConfig::default()), unkown_public_key);
	}

	#[test]
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

		// Test the API functions.
		check_api_misuse_error(nodes[0].node.accept_inbound_channel(&channel_id, &counterparty_node_id, 42));

		check_channel_unavailable_error(nodes[0].node.close_channel(&channel_id, &counterparty_node_id), channel_id, counterparty_node_id);

		check_channel_unavailable_error(nodes[0].node.force_close_broadcasting_latest_txn(&channel_id, &counterparty_node_id), channel_id, counterparty_node_id);

		check_channel_unavailable_error(nodes[0].node.force_close_without_broadcasting_txn(&channel_id, &counterparty_node_id), channel_id, counterparty_node_id);

		check_channel_unavailable_error(nodes[0].node.forward_intercepted_htlc(InterceptId([0; 32]), &channel_id, counterparty_node_id, 1_000_000), channel_id, counterparty_node_id);

		check_channel_unavailable_error(nodes[0].node.update_channel_config(&counterparty_node_id, &[channel_id], &ChannelConfig::default()), channel_id, counterparty_node_id);
	}

	#[test]
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
			nodes[1].node.handle_open_channel(&nodes[0].node.get_our_node_id(), &open_channel_msg);
			let accept_channel = get_event_msg!(nodes[1], MessageSendEvent::SendAcceptChannel, nodes[0].node.get_our_node_id());

			if idx == 0 {
				nodes[0].node.handle_accept_channel(&nodes[1].node.get_our_node_id(), &accept_channel);
				let (temporary_channel_id, tx, _) = create_funding_transaction(&nodes[0], &nodes[1].node.get_our_node_id(), 100_000, 42);
				funding_tx = Some(tx.clone());
				nodes[0].node.funding_transaction_generated(&temporary_channel_id, &nodes[1].node.get_our_node_id(), tx).unwrap();
				let funding_created_msg = get_event_msg!(nodes[0], MessageSendEvent::SendFundingCreated, nodes[1].node.get_our_node_id());

				nodes[1].node.handle_funding_created(&nodes[0].node.get_our_node_id(), &funding_created_msg);
				check_added_monitors!(nodes[1], 1);
				expect_channel_pending_event(&nodes[1], &nodes[0].node.get_our_node_id());

				let funding_signed = get_event_msg!(nodes[1], MessageSendEvent::SendFundingSigned, nodes[0].node.get_our_node_id());

				nodes[0].node.handle_funding_signed(&nodes[1].node.get_our_node_id(), &funding_signed);
				check_added_monitors!(nodes[0], 1);
				expect_channel_pending_event(&nodes[0], &nodes[1].node.get_our_node_id());
			}
			open_channel_msg.common_fields.temporary_channel_id = ChannelId::temporary_from_entropy_source(&nodes[0].keys_manager);
		}

		// A MAX_UNFUNDED_CHANS_PER_PEER + 1 channel will be summarily rejected
		open_channel_msg.common_fields.temporary_channel_id = ChannelId::temporary_from_entropy_source(
			&nodes[0].keys_manager);
		nodes[1].node.handle_open_channel(&nodes[0].node.get_our_node_id(), &open_channel_msg);
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
			nodes[1].node.peer_connected(&random_pk, &msgs::Init {
				features: nodes[0].node.init_features(), networks: None, remote_network_address: None
			}, true).unwrap();
		}
		let last_random_pk = PublicKey::from_secret_key(&nodes[0].node.secp_ctx,
			&SecretKey::from_slice(&nodes[1].keys_manager.get_secure_random_bytes()).unwrap());
		nodes[1].node.peer_connected(&last_random_pk, &msgs::Init {
			features: nodes[0].node.init_features(), networks: None, remote_network_address: None
		}, true).unwrap_err();

		// Also importantly, because nodes[0] isn't "protected", we will refuse a reconnection from
		// them if we have too many un-channel'd peers.
		nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id());
		let chan_closed_events = nodes[1].node.get_and_clear_pending_events();
		assert_eq!(chan_closed_events.len(), super::MAX_UNFUNDED_CHANS_PER_PEER - 1);
		for ev in chan_closed_events {
			if let Event::ChannelClosed { .. } = ev { } else { panic!(); }
		}
		nodes[1].node.peer_connected(&last_random_pk, &msgs::Init {
			features: nodes[0].node.init_features(), networks: None, remote_network_address: None
		}, true).unwrap();
		nodes[1].node.peer_connected(&nodes[0].node.get_our_node_id(), &msgs::Init {
			features: nodes[0].node.init_features(), networks: None, remote_network_address: None
		}, true).unwrap_err();

		// but of course if the connection is outbound its allowed...
		nodes[1].node.peer_connected(&nodes[0].node.get_our_node_id(), &msgs::Init {
			features: nodes[0].node.init_features(), networks: None, remote_network_address: None
		}, false).unwrap();
		nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id());

		// Now nodes[0] is disconnected but still has a pending, un-funded channel lying around.
		// Even though we accept one more connection from new peers, we won't actually let them
		// open channels.
		assert!(peer_pks.len() > super::MAX_UNFUNDED_CHANNEL_PEERS - 1);
		for i in 0..super::MAX_UNFUNDED_CHANNEL_PEERS - 1 {
			nodes[1].node.handle_open_channel(&peer_pks[i], &open_channel_msg);
			get_event_msg!(nodes[1], MessageSendEvent::SendAcceptChannel, peer_pks[i]);
			open_channel_msg.common_fields.temporary_channel_id = ChannelId::temporary_from_entropy_source(&nodes[0].keys_manager);
		}
		nodes[1].node.handle_open_channel(&last_random_pk, &open_channel_msg);
		assert_eq!(get_err_msg(&nodes[1], &last_random_pk).channel_id,
			open_channel_msg.common_fields.temporary_channel_id);

		// Of course, however, outbound channels are always allowed
		nodes[1].node.create_channel(last_random_pk, 100_000, 0, 42, None, None).unwrap();
		get_event_msg!(nodes[1], MessageSendEvent::SendOpenChannel, last_random_pk);

		// If we fund the first channel, nodes[0] has a live on-chain channel with us, it is now
		// "protected" and can connect again.
		mine_transaction(&nodes[1], funding_tx.as_ref().unwrap());
		nodes[1].node.peer_connected(&nodes[0].node.get_our_node_id(), &msgs::Init {
			features: nodes[0].node.init_features(), networks: None, remote_network_address: None
		}, true).unwrap();
		get_event_msg!(nodes[1], MessageSendEvent::SendChannelReestablish, nodes[0].node.get_our_node_id());

		// Further, because the first channel was funded, we can open another channel with
		// last_random_pk.
		nodes[1].node.handle_open_channel(&last_random_pk, &open_channel_msg);
		get_event_msg!(nodes[1], MessageSendEvent::SendAcceptChannel, last_random_pk);
	}

	#[test]
	fn test_outbound_chans_unlimited() {
		// Test that we never refuse an outbound channel even if a peer is unfuned-channel-limited
		let chanmon_cfgs = create_chanmon_cfgs(2);
		let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
		let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
		let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

		// Note that create_network connects the nodes together for us

		nodes[0].node.create_channel(nodes[1].node.get_our_node_id(), 100_000, 0, 42, None, None).unwrap();
		let mut open_channel_msg = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, nodes[1].node.get_our_node_id());

		for _ in 0..super::MAX_UNFUNDED_CHANS_PER_PEER {
			nodes[1].node.handle_open_channel(&nodes[0].node.get_our_node_id(), &open_channel_msg);
			get_event_msg!(nodes[1], MessageSendEvent::SendAcceptChannel, nodes[0].node.get_our_node_id());
			open_channel_msg.common_fields.temporary_channel_id = ChannelId::temporary_from_entropy_source(&nodes[0].keys_manager);
		}

		// Once we have MAX_UNFUNDED_CHANS_PER_PEER unfunded channels, new inbound channels will be
		// rejected.
		nodes[1].node.handle_open_channel(&nodes[0].node.get_our_node_id(), &open_channel_msg);
		assert_eq!(get_err_msg(&nodes[1], &nodes[0].node.get_our_node_id()).channel_id,
			open_channel_msg.common_fields.temporary_channel_id);

		// but we can still open an outbound channel.
		nodes[1].node.create_channel(nodes[0].node.get_our_node_id(), 100_000, 0, 42, None, None).unwrap();
		get_event_msg!(nodes[1], MessageSendEvent::SendOpenChannel, nodes[0].node.get_our_node_id());

		// but even with such an outbound channel, additional inbound channels will still fail.
		nodes[1].node.handle_open_channel(&nodes[0].node.get_our_node_id(), &open_channel_msg);
		assert_eq!(get_err_msg(&nodes[1], &nodes[0].node.get_our_node_id()).channel_id,
			open_channel_msg.common_fields.temporary_channel_id);
	}

	#[test]
	fn test_0conf_limiting() {
		// Tests that we properly limit inbound channels when we have the manual-channel-acceptance
		// flag set and (sometimes) accept channels as 0conf.
		let chanmon_cfgs = create_chanmon_cfgs(2);
		let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
		let mut settings = test_default_channel_config();
		settings.manually_accept_inbound_channels = true;
		let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, Some(settings)]);
		let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

		// Note that create_network connects the nodes together for us

		nodes[0].node.create_channel(nodes[1].node.get_our_node_id(), 100_000, 0, 42, None, None).unwrap();
		let mut open_channel_msg = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, nodes[1].node.get_our_node_id());

		// First, get us up to MAX_UNFUNDED_CHANNEL_PEERS so we can test at the edge
		for _ in 0..super::MAX_UNFUNDED_CHANNEL_PEERS - 1 {
			let random_pk = PublicKey::from_secret_key(&nodes[0].node.secp_ctx,
				&SecretKey::from_slice(&nodes[1].keys_manager.get_secure_random_bytes()).unwrap());
			nodes[1].node.peer_connected(&random_pk, &msgs::Init {
				features: nodes[0].node.init_features(), networks: None, remote_network_address: None
			}, true).unwrap();

			nodes[1].node.handle_open_channel(&random_pk, &open_channel_msg);
			let events = nodes[1].node.get_and_clear_pending_events();
			match events[0] {
				Event::OpenChannelRequest { temporary_channel_id, .. } => {
					nodes[1].node.accept_inbound_channel(&temporary_channel_id, &random_pk, 23).unwrap();
				}
				_ => panic!("Unexpected event"),
			}
			get_event_msg!(nodes[1], MessageSendEvent::SendAcceptChannel, random_pk);
			open_channel_msg.common_fields.temporary_channel_id = ChannelId::temporary_from_entropy_source(&nodes[0].keys_manager);
		}

		// If we try to accept a channel from another peer non-0conf it will fail.
		let last_random_pk = PublicKey::from_secret_key(&nodes[0].node.secp_ctx,
			&SecretKey::from_slice(&nodes[1].keys_manager.get_secure_random_bytes()).unwrap());
		nodes[1].node.peer_connected(&last_random_pk, &msgs::Init {
			features: nodes[0].node.init_features(), networks: None, remote_network_address: None
		}, true).unwrap();
		nodes[1].node.handle_open_channel(&last_random_pk, &open_channel_msg);
		let events = nodes[1].node.get_and_clear_pending_events();
		match events[0] {
			Event::OpenChannelRequest { temporary_channel_id, .. } => {
				match nodes[1].node.accept_inbound_channel(&temporary_channel_id, &last_random_pk, 23) {
					Err(APIError::APIMisuseError { err }) =>
						assert_eq!(err, "Too many peers with unfunded channels, refusing to accept new ones"),
					_ => panic!(),
				}
			}
			_ => panic!("Unexpected event"),
		}
		assert_eq!(get_err_msg(&nodes[1], &last_random_pk).channel_id,
			open_channel_msg.common_fields.temporary_channel_id);

		// ...however if we accept the same channel 0conf it should work just fine.
		nodes[1].node.handle_open_channel(&last_random_pk, &open_channel_msg);
		let events = nodes[1].node.get_and_clear_pending_events();
		match events[0] {
			Event::OpenChannelRequest { temporary_channel_id, .. } => {
				nodes[1].node.accept_inbound_channel_from_trusted_peer_0conf(&temporary_channel_id, &last_random_pk, 23).unwrap();
			}
			_ => panic!("Unexpected event"),
		}
		get_event_msg!(nodes[1], MessageSendEvent::SendAcceptChannel, last_random_pk);
	}

	#[test]
	fn reject_excessively_underpaying_htlcs() {
		let chanmon_cfg = create_chanmon_cfgs(1);
		let node_cfg = create_node_cfgs(1, &chanmon_cfg);
		let node_chanmgr = create_node_chanmgrs(1, &node_cfg, &[None]);
		let node = create_network(1, &node_cfg, &node_chanmgr);
		let sender_intended_amt_msat = 100;
		let extra_fee_msat = 10;
		let hop_data = msgs::InboundOnionPayload::Receive {
			sender_intended_htlc_amt_msat: 100,
			cltv_expiry_height: 42,
			payment_metadata: None,
			keysend_preimage: None,
			payment_data: Some(msgs::FinalOnionHopData {
				payment_secret: PaymentSecret([0; 32]), total_msat: sender_intended_amt_msat,
			}),
			custom_tlvs: Vec::new(),
		};
		// Check that if the amount we received + the penultimate hop extra fee is less than the sender
		// intended amount, we fail the payment.
		let current_height: u32 = node[0].node.best_block.read().unwrap().height;
		if let Err(crate::ln::channelmanager::InboundHTLCErr { err_code, .. }) =
			create_recv_pending_htlc_info(hop_data, [0; 32], PaymentHash([0; 32]),
				sender_intended_amt_msat - extra_fee_msat - 1, 42, None, true, Some(extra_fee_msat),
				current_height, node[0].node.default_configuration.accept_mpp_keysend)
		{
			assert_eq!(err_code, 19);
		} else { panic!(); }

		// If amt_received + extra_fee is equal to the sender intended amount, we're fine.
		let hop_data = msgs::InboundOnionPayload::Receive { // This is the same payload as above, InboundOnionPayload doesn't implement Clone
			sender_intended_htlc_amt_msat: 100,
			cltv_expiry_height: 42,
			payment_metadata: None,
			keysend_preimage: None,
			payment_data: Some(msgs::FinalOnionHopData {
				payment_secret: PaymentSecret([0; 32]), total_msat: sender_intended_amt_msat,
			}),
			custom_tlvs: Vec::new(),
		};
		let current_height: u32 = node[0].node.best_block.read().unwrap().height;
		assert!(create_recv_pending_htlc_info(hop_data, [0; 32], PaymentHash([0; 32]),
			sender_intended_amt_msat - extra_fee_msat, 42, None, true, Some(extra_fee_msat),
			current_height, node[0].node.default_configuration.accept_mpp_keysend).is_ok());
	}

	#[test]
	fn test_final_incorrect_cltv(){
		let chanmon_cfg = create_chanmon_cfgs(1);
		let node_cfg = create_node_cfgs(1, &chanmon_cfg);
		let node_chanmgr = create_node_chanmgrs(1, &node_cfg, &[None]);
		let node = create_network(1, &node_cfg, &node_chanmgr);

		let current_height: u32 = node[0].node.best_block.read().unwrap().height;
		let result = create_recv_pending_htlc_info(msgs::InboundOnionPayload::Receive {
			sender_intended_htlc_amt_msat: 100,
			cltv_expiry_height: 22,
			payment_metadata: None,
			keysend_preimage: None,
			payment_data: Some(msgs::FinalOnionHopData {
				payment_secret: PaymentSecret([0; 32]), total_msat: 100,
			}),
			custom_tlvs: Vec::new(),
		}, [0; 32], PaymentHash([0; 32]), 100, 23, None, true, None, current_height,
			node[0].node.default_configuration.accept_mpp_keysend);

		// Should not return an error as this condition:
		// https://github.com/lightning/bolts/blob/4dcc377209509b13cf89a4b91fde7d478f5b46d8/04-onion-routing.md?plain=1#L334
		// is not satisfied.
		assert!(result.is_ok());
	}

	#[test]
	fn test_inbound_anchors_manual_acceptance() {
		// Tests that we properly limit inbound channels when we have the manual-channel-acceptance
		// flag set and (sometimes) accept channels as 0conf.
		let mut anchors_cfg = test_default_channel_config();
		anchors_cfg.channel_handshake_config.negotiate_anchors_zero_fee_htlc_tx = true;

		let mut anchors_manual_accept_cfg = anchors_cfg.clone();
		anchors_manual_accept_cfg.manually_accept_inbound_channels = true;

		let chanmon_cfgs = create_chanmon_cfgs(3);
		let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
		let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs,
			&[Some(anchors_cfg.clone()), Some(anchors_cfg.clone()), Some(anchors_manual_accept_cfg.clone())]);
		let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

		nodes[0].node.create_channel(nodes[1].node.get_our_node_id(), 100_000, 0, 42, None, None).unwrap();
		let open_channel_msg = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, nodes[1].node.get_our_node_id());

		nodes[1].node.handle_open_channel(&nodes[0].node.get_our_node_id(), &open_channel_msg);
		assert!(nodes[1].node.get_and_clear_pending_events().is_empty());
		let msg_events = nodes[1].node.get_and_clear_pending_msg_events();
		match &msg_events[0] {
			MessageSendEvent::HandleError { node_id, action } => {
				assert_eq!(*node_id, nodes[0].node.get_our_node_id());
				match action {
					ErrorAction::SendErrorMessage { msg } =>
						assert_eq!(msg.data, "No channels with anchor outputs accepted".to_owned()),
					_ => panic!("Unexpected error action"),
				}
			}
			_ => panic!("Unexpected event"),
		}

		nodes[2].node.handle_open_channel(&nodes[0].node.get_our_node_id(), &open_channel_msg);
		let events = nodes[2].node.get_and_clear_pending_events();
		match events[0] {
			Event::OpenChannelRequest { temporary_channel_id, .. } =>
				nodes[2].node.accept_inbound_channel(&temporary_channel_id, &nodes[0].node.get_our_node_id(), 23).unwrap(),
			_ => panic!("Unexpected event"),
		}
		get_event_msg!(nodes[2], MessageSendEvent::SendAcceptChannel, nodes[0].node.get_our_node_id());
	}

	#[test]
	fn test_anchors_zero_fee_htlc_tx_fallback() {
		// Tests that if both nodes support anchors, but the remote node does not want to accept
		// anchor channels at the moment, an error it sent to the local node such that it can retry
		// the channel without the anchors feature.
		let chanmon_cfgs = create_chanmon_cfgs(2);
		let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
		let mut anchors_config = test_default_channel_config();
		anchors_config.channel_handshake_config.negotiate_anchors_zero_fee_htlc_tx = true;
		anchors_config.manually_accept_inbound_channels = true;
		let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[Some(anchors_config.clone()), Some(anchors_config.clone())]);
		let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

		nodes[0].node.create_channel(nodes[1].node.get_our_node_id(), 100_000, 0, 0, None, None).unwrap();
		let open_channel_msg = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, nodes[1].node.get_our_node_id());
		assert!(open_channel_msg.common_fields.channel_type.as_ref().unwrap().supports_anchors_zero_fee_htlc_tx());

		nodes[1].node.handle_open_channel(&nodes[0].node.get_our_node_id(), &open_channel_msg);
		let events = nodes[1].node.get_and_clear_pending_events();
		match events[0] {
			Event::OpenChannelRequest { temporary_channel_id, .. } => {
				nodes[1].node.force_close_broadcasting_latest_txn(&temporary_channel_id, &nodes[0].node.get_our_node_id()).unwrap();
			}
			_ => panic!("Unexpected event"),
		}

		let error_msg = get_err_msg(&nodes[1], &nodes[0].node.get_our_node_id());
		nodes[0].node.handle_error(&nodes[1].node.get_our_node_id(), &error_msg);

		let open_channel_msg = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, nodes[1].node.get_our_node_id());
		assert!(!open_channel_msg.common_fields.channel_type.unwrap().supports_anchors_zero_fee_htlc_tx());

		// Since nodes[1] should not have accepted the channel, it should
		// not have generated any events.
		assert!(nodes[1].node.get_and_clear_pending_events().is_empty());
	}

	#[test]
	fn test_update_channel_config() {
		let chanmon_cfg = create_chanmon_cfgs(2);
		let node_cfg = create_node_cfgs(2, &chanmon_cfg);
		let mut user_config = test_default_channel_config();
		let node_chanmgr = create_node_chanmgrs(2, &node_cfg, &[Some(user_config), Some(user_config)]);
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
			..Default::default()
		}).unwrap();
		assert_eq!(nodes[0].node.list_channels()[0].config.unwrap().cltv_expiry_delta, new_cltv_expiry_delta);
		assert_eq!(nodes[0].node.list_channels()[0].config.unwrap().forwarding_fee_proportional_millionths, new_fee);
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
	fn test_payment_display() {
		let payment_id = PaymentId([42; 32]);
		assert_eq!(format!("{}", &payment_id), "2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a");
		let payment_hash = PaymentHash([42; 32]);
		assert_eq!(format!("{}", &payment_hash), "2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a");
		let payment_preimage = PaymentPreimage([42; 32]);
		assert_eq!(format!("{}", &payment_preimage), "2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a");
	}

	#[test]
	fn test_trigger_lnd_force_close() {
		let chanmon_cfg = create_chanmon_cfgs(2);
		let node_cfg = create_node_cfgs(2, &chanmon_cfg);
		let user_config = test_default_channel_config();
		let node_chanmgr = create_node_chanmgrs(2, &node_cfg, &[Some(user_config), Some(user_config)]);
		let nodes = create_network(2, &node_cfg, &node_chanmgr);

		// Open a channel, immediately disconnect each other, and broadcast Alice's latest state.
		let (_, _, chan_id, funding_tx) = create_announced_chan_between_nodes(&nodes, 0, 1);
		nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id());
		nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id());
		nodes[0].node.force_close_broadcasting_latest_txn(&chan_id, &nodes[1].node.get_our_node_id()).unwrap();
		check_closed_broadcast(&nodes[0], 1, true);
		check_added_monitors(&nodes[0], 1);
		check_closed_event!(nodes[0], 1, ClosureReason::HolderForceClosed, [nodes[1].node.get_our_node_id()], 100000);
		{
			let txn = nodes[0].tx_broadcaster.txn_broadcast();
			assert_eq!(txn.len(), 1);
			check_spends!(txn[0], funding_tx);
		}

		// Since they're disconnected, Bob won't receive Alice's `Error` message. Reconnect them
		// such that Bob sends a `ChannelReestablish` to Alice since the channel is still open from
		// their side.
		nodes[0].node.peer_connected(&nodes[1].node.get_our_node_id(), &msgs::Init {
			features: nodes[1].node.init_features(), networks: None, remote_network_address: None
		}, true).unwrap();
		nodes[1].node.peer_connected(&nodes[0].node.get_our_node_id(), &msgs::Init {
			features: nodes[0].node.init_features(), networks: None, remote_network_address: None
		}, false).unwrap();
		assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
		let channel_reestablish = get_event_msg!(
			nodes[1], MessageSendEvent::SendChannelReestablish, nodes[0].node.get_our_node_id()
		);
		nodes[0].node.handle_channel_reestablish(&nodes[1].node.get_our_node_id(), &channel_reestablish);

		// Alice should respond with an error since the channel isn't known, but a bogus
		// `ChannelReestablish` should be sent first, such that we actually trigger Bob to force
		// close even if it was an lnd node.
		let msg_events = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(msg_events.len(), 2);
		if let MessageSendEvent::SendChannelReestablish { node_id, msg } = &msg_events[0] {
			assert_eq!(*node_id, nodes[1].node.get_our_node_id());
			assert_eq!(msg.next_local_commitment_number, 0);
			assert_eq!(msg.next_remote_commitment_number, 0);
			nodes[1].node.handle_channel_reestablish(&nodes[0].node.get_our_node_id(), &msg);
		} else { panic!() };
		check_closed_broadcast(&nodes[1], 1, true);
		check_added_monitors(&nodes[1], 1);
		let expected_close_reason = ClosureReason::ProcessingError {
			err: "Peer sent an invalid channel_reestablish to force close in a non-standard way".to_string()
		};
		check_closed_event!(nodes[1], 1, expected_close_reason, [nodes[0].node.get_our_node_id()], 100000);
		{
			let txn = nodes[1].tx_broadcaster.txn_broadcast();
			assert_eq!(txn.len(), 1);
			check_spends!(txn[0], funding_tx);
		}
	}

	#[test]
	fn test_malformed_forward_htlcs_ser() {
		// Ensure that `HTLCForwardInfo::FailMalformedHTLC`s are (de)serialized properly.
		let chanmon_cfg = create_chanmon_cfgs(1);
		let node_cfg = create_node_cfgs(1, &chanmon_cfg);
		let persister;
		let chain_monitor;
		let chanmgrs = create_node_chanmgrs(1, &node_cfg, &[None]);
		let deserialized_chanmgr;
		let mut nodes = create_network(1, &node_cfg, &chanmgrs);

		let dummy_failed_htlc = |htlc_id| {
			HTLCForwardInfo::FailHTLC { htlc_id, err_packet: msgs::OnionErrorPacket { data: vec![42] }, }
		};
		let dummy_malformed_htlc = |htlc_id| {
			HTLCForwardInfo::FailMalformedHTLC { htlc_id, failure_code: 0x4000, sha256_of_onion: [0; 32] }
		};

		let dummy_htlcs_1: Vec<HTLCForwardInfo> = (1..10).map(|htlc_id| {
			if htlc_id % 2 == 0 {
				dummy_failed_htlc(htlc_id)
			} else {
				dummy_malformed_htlc(htlc_id)
			}
		}).collect();

		let dummy_htlcs_2: Vec<HTLCForwardInfo> = (1..10).map(|htlc_id| {
			if htlc_id % 2 == 1 {
				dummy_failed_htlc(htlc_id)
			} else {
				dummy_malformed_htlc(htlc_id)
			}
		}).collect();


		let (scid_1, scid_2) = (42, 43);
		let mut forward_htlcs = new_hash_map();
		forward_htlcs.insert(scid_1, dummy_htlcs_1.clone());
		forward_htlcs.insert(scid_2, dummy_htlcs_2.clone());

		let mut chanmgr_fwd_htlcs = nodes[0].node.forward_htlcs.lock().unwrap();
		*chanmgr_fwd_htlcs = forward_htlcs.clone();
		core::mem::drop(chanmgr_fwd_htlcs);

		reload_node!(nodes[0], nodes[0].node.encode(), &[], persister, chain_monitor, deserialized_chanmgr);

		let mut deserialized_fwd_htlcs = nodes[0].node.forward_htlcs.lock().unwrap();
		for scid in [scid_1, scid_2].iter() {
			let deserialized_htlcs = deserialized_fwd_htlcs.remove(scid).unwrap();
			assert_eq!(forward_htlcs.remove(scid).unwrap(), deserialized_htlcs);
		}
		assert!(deserialized_fwd_htlcs.is_empty());
		core::mem::drop(deserialized_fwd_htlcs);

		expect_pending_htlcs_forwardable!(nodes[0]);
	}
}

#[cfg(ldk_bench)]
pub mod bench {
	use crate::chain::Listen;
	use crate::chain::chainmonitor::{ChainMonitor, Persist};
	use crate::sign::{KeysManager, InMemorySigner};
	use crate::events::{Event, MessageSendEvent, MessageSendEventsProvider};
	use crate::ln::channelmanager::{BestBlock, ChainParameters, ChannelManager, PaymentHash, PaymentPreimage, PaymentId, RecipientOnionFields, Retry};
	use crate::ln::functional_test_utils::*;
	use crate::ln::msgs::{ChannelMessageHandler, Init};
	use crate::routing::gossip::NetworkGraph;
	use crate::routing::router::{PaymentParameters, RouteParameters};
	use crate::util::test_utils;
	use crate::util::config::{UserConfig, MaxDustHTLCExposure};

	use bitcoin::blockdata::locktime::absolute::LockTime;
	use bitcoin::hashes::Hash;
	use bitcoin::hashes::sha256::Hash as Sha256;
	use bitcoin::{Transaction, TxOut};

	use crate::sync::{Arc, Mutex, RwLock};

	use criterion::Criterion;

	type Manager<'a, P> = ChannelManager<
		&'a ChainMonitor<InMemorySigner, &'a test_utils::TestChainSource,
			&'a test_utils::TestBroadcaster, &'a test_utils::TestFeeEstimator,
			&'a test_utils::TestLogger, &'a P>,
		&'a test_utils::TestBroadcaster, &'a KeysManager, &'a KeysManager, &'a KeysManager,
		&'a test_utils::TestFeeEstimator, &'a test_utils::TestRouter<'a>,
		&'a test_utils::TestLogger>;

	struct ANodeHolder<'node_cfg, 'chan_mon_cfg: 'node_cfg, P: Persist<InMemorySigner>> {
		node: &'node_cfg Manager<'chan_mon_cfg, P>,
	}
	impl<'node_cfg, 'chan_mon_cfg: 'node_cfg, P: Persist<InMemorySigner>> NodeHolder for ANodeHolder<'node_cfg, 'chan_mon_cfg, P> {
		type CM = Manager<'chan_mon_cfg, P>;
		#[inline]
		fn node(&self) -> &Manager<'chan_mon_cfg, P> { self.node }
		#[inline]
		fn chain_monitor(&self) -> Option<&test_utils::TestChainMonitor> { None }
	}

	pub fn bench_sends(bench: &mut Criterion) {
		bench_two_sends(bench, "bench_sends", test_utils::TestPersister::new(), test_utils::TestPersister::new());
	}

	pub fn bench_two_sends<P: Persist<InMemorySigner>>(bench: &mut Criterion, bench_name: &str, persister_a: P, persister_b: P) {
		// Do a simple benchmark of sending a payment back and forth between two nodes.
		// Note that this is unrealistic as each payment send will require at least two fsync
		// calls per node.
		let network = bitcoin::Network::Testnet;
		let genesis_block = bitcoin::blockdata::constants::genesis_block(network);

		let tx_broadcaster = test_utils::TestBroadcaster::new(network);
		let fee_estimator = test_utils::TestFeeEstimator { sat_per_kw: Mutex::new(253) };
		let logger_a = test_utils::TestLogger::with_id("node a".to_owned());
		let scorer = RwLock::new(test_utils::TestScorer::new());
		let router = test_utils::TestRouter::new(Arc::new(NetworkGraph::new(network, &logger_a)), &logger_a, &scorer);

		let mut config: UserConfig = Default::default();
		config.channel_config.max_dust_htlc_exposure = MaxDustHTLCExposure::FeeRateMultiplier(5_000_000 / 253);
		config.channel_handshake_config.minimum_depth = 1;

		let chain_monitor_a = ChainMonitor::new(None, &tx_broadcaster, &logger_a, &fee_estimator, &persister_a);
		let seed_a = [1u8; 32];
		let keys_manager_a = KeysManager::new(&seed_a, 42, 42);
		let node_a = ChannelManager::new(&fee_estimator, &chain_monitor_a, &tx_broadcaster, &router, &logger_a, &keys_manager_a, &keys_manager_a, &keys_manager_a, config.clone(), ChainParameters {
			network,
			best_block: BestBlock::from_network(network),
		}, genesis_block.header.time);
		let node_a_holder = ANodeHolder { node: &node_a };

		let logger_b = test_utils::TestLogger::with_id("node a".to_owned());
		let chain_monitor_b = ChainMonitor::new(None, &tx_broadcaster, &logger_a, &fee_estimator, &persister_b);
		let seed_b = [2u8; 32];
		let keys_manager_b = KeysManager::new(&seed_b, 42, 42);
		let node_b = ChannelManager::new(&fee_estimator, &chain_monitor_b, &tx_broadcaster, &router, &logger_b, &keys_manager_b, &keys_manager_b, &keys_manager_b, config.clone(), ChainParameters {
			network,
			best_block: BestBlock::from_network(network),
		}, genesis_block.header.time);
		let node_b_holder = ANodeHolder { node: &node_b };

		node_a.peer_connected(&node_b.get_our_node_id(), &Init {
			features: node_b.init_features(), networks: None, remote_network_address: None
		}, true).unwrap();
		node_b.peer_connected(&node_a.get_our_node_id(), &Init {
			features: node_a.init_features(), networks: None, remote_network_address: None
		}, false).unwrap();
		node_a.create_channel(node_b.get_our_node_id(), 8_000_000, 100_000_000, 42, None, None).unwrap();
		node_b.handle_open_channel(&node_a.get_our_node_id(), &get_event_msg!(node_a_holder, MessageSendEvent::SendOpenChannel, node_b.get_our_node_id()));
		node_a.handle_accept_channel(&node_b.get_our_node_id(), &get_event_msg!(node_b_holder, MessageSendEvent::SendAcceptChannel, node_a.get_our_node_id()));

		let tx;
		if let Event::FundingGenerationReady { temporary_channel_id, output_script, .. } = get_event!(node_a_holder, Event::FundingGenerationReady) {
			tx = Transaction { version: 2, lock_time: LockTime::ZERO, input: Vec::new(), output: vec![TxOut {
				value: 8_000_000, script_pubkey: output_script,
			}]};
			node_a.funding_transaction_generated(&temporary_channel_id, &node_b.get_our_node_id(), tx.clone()).unwrap();
		} else { panic!(); }

		node_b.handle_funding_created(&node_a.get_our_node_id(), &get_event_msg!(node_a_holder, MessageSendEvent::SendFundingCreated, node_b.get_our_node_id()));
		let events_b = node_b.get_and_clear_pending_events();
		assert_eq!(events_b.len(), 1);
		match events_b[0] {
			Event::ChannelPending{ ref counterparty_node_id, .. } => {
				assert_eq!(*counterparty_node_id, node_a.get_our_node_id());
			},
			_ => panic!("Unexpected event"),
		}

		node_a.handle_funding_signed(&node_b.get_our_node_id(), &get_event_msg!(node_b_holder, MessageSendEvent::SendFundingSigned, node_a.get_our_node_id()));
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

		node_a.handle_channel_ready(&node_b.get_our_node_id(), &get_event_msg!(node_b_holder, MessageSendEvent::SendChannelReady, node_a.get_our_node_id()));
		let msg_events = node_a.get_and_clear_pending_msg_events();
		assert_eq!(msg_events.len(), 2);
		match msg_events[0] {
			MessageSendEvent::SendChannelReady { ref msg, .. } => {
				node_b.handle_channel_ready(&node_a.get_our_node_id(), msg);
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
				$node_b.handle_update_add_htlc(&$node_a.get_our_node_id(), &payment_event.msgs[0]);
				$node_b.handle_commitment_signed(&$node_a.get_our_node_id(), &payment_event.commitment_msg);
				let (raa, cs) = get_revoke_commit_msgs(&ANodeHolder { node: &$node_b }, &$node_a.get_our_node_id());
				$node_a.handle_revoke_and_ack(&$node_b.get_our_node_id(), &raa);
				$node_a.handle_commitment_signed(&$node_b.get_our_node_id(), &cs);
				$node_b.handle_revoke_and_ack(&$node_a.get_our_node_id(), &get_event_msg!(ANodeHolder { node: &$node_a }, MessageSendEvent::SendRevokeAndACK, $node_b.get_our_node_id()));

				expect_pending_htlcs_forwardable!(ANodeHolder { node: &$node_b });
				expect_payment_claimable!(ANodeHolder { node: &$node_b }, payment_hash, payment_secret, 10_000);
				$node_b.claim_funds(payment_preimage);
				expect_payment_claimed!(ANodeHolder { node: &$node_b }, payment_hash, 10_000);

				match $node_b.get_and_clear_pending_msg_events().pop().unwrap() {
					MessageSendEvent::UpdateHTLCs { node_id, updates } => {
						assert_eq!(node_id, $node_a.get_our_node_id());
						$node_a.handle_update_fulfill_htlc(&$node_b.get_our_node_id(), &updates.update_fulfill_htlcs[0]);
						$node_a.handle_commitment_signed(&$node_b.get_our_node_id(), &updates.commitment_signed);
					},
					_ => panic!("Failed to generate claim event"),
				}

				let (raa, cs) = get_revoke_commit_msgs(&ANodeHolder { node: &$node_a }, &$node_b.get_our_node_id());
				$node_b.handle_revoke_and_ack(&$node_a.get_our_node_id(), &raa);
				$node_b.handle_commitment_signed(&$node_a.get_our_node_id(), &cs);
				$node_a.handle_revoke_and_ack(&$node_b.get_our_node_id(), &get_event_msg!(ANodeHolder { node: &$node_b }, MessageSendEvent::SendRevokeAndACK, $node_a.get_our_node_id()));

				expect_payment_sent!(ANodeHolder { node: &$node_a }, payment_preimage);
			}
		}

		bench.bench_function(bench_name, |b| b.iter(|| {
			send_payment!(node_a, node_b);
			send_payment!(node_b, node_a);
		}));
	}
}
