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
//! The ChannelManager is the main chunk of logic implementing the lightning protocol and is
//! responsible for tracking which channels are open, HTLCs are in flight and reestablishing those
//! upon reconnect to the relevant peer(s).
//!
//! It does not manage routing logic (see [`Router`] for that) nor does it manage constructing
//! on-chain transactions (it only monitors the chain to watch for any force-closes that might
//! imply it needs to fail HTLCs/payments/channels it manages).

use bitcoin::blockdata::block::BlockHeader;
use bitcoin::blockdata::transaction::Transaction;
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::network::constants::Network;

use bitcoin::hashes::Hash;
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hash_types::{BlockHash, Txid};

use bitcoin::secp256k1::{SecretKey,PublicKey};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{LockTime, secp256k1, Sequence};

use crate::chain;
use crate::chain::{Confirm, ChannelMonitorUpdateStatus, Watch, BestBlock};
use crate::chain::chaininterface::{BroadcasterInterface, ConfirmationTarget, FeeEstimator, LowerBoundedFeeEstimator};
use crate::chain::channelmonitor::{ChannelMonitor, ChannelMonitorUpdate, ChannelMonitorUpdateStep, HTLC_FAIL_BACK_BUFFER, CLTV_CLAIM_BUFFER, LATENCY_GRACE_PERIOD_BLOCKS, ANTI_REORG_DELAY, MonitorEvent, CLOSED_CHANNEL_UPDATE_ID};
use crate::chain::transaction::{OutPoint, TransactionData};
// Since this struct is returned in `list_channels` methods, expose it here in case users want to
// construct one themselves.
use crate::ln::{inbound_payment, PaymentHash, PaymentPreimage, PaymentSecret};
use crate::ln::channel::{Channel, ChannelError, ChannelUpdateStatus, UpdateFulfillCommitFetch};
use crate::ln::features::{ChannelFeatures, ChannelTypeFeatures, InitFeatures, NodeFeatures};
#[cfg(any(feature = "_test_utils", test))]
use crate::ln::features::InvoiceFeatures;
use crate::routing::gossip::NetworkGraph;
use crate::routing::router::{DefaultRouter, InFlightHtlcs, PaymentParameters, Route, RouteHop, RouteParameters, RoutePath, Router};
use crate::routing::scoring::ProbabilisticScorer;
use crate::ln::msgs;
use crate::ln::onion_utils;
use crate::ln::onion_utils::HTLCFailReason;
use crate::ln::msgs::{ChannelMessageHandler, DecodeError, LightningError, MAX_VALUE_MSAT};
#[cfg(test)]
use crate::ln::outbound_payment;
use crate::ln::outbound_payment::{OutboundPayments, PaymentAttempts, PendingOutboundPayment};
use crate::ln::wire::Encode;
use crate::chain::keysinterface::{EntropySource, KeysManager, NodeSigner, Recipient, SignerProvider, ChannelSigner};
use crate::util::config::{UserConfig, ChannelConfig};
use crate::util::events::{Event, EventHandler, EventsProvider, MessageSendEvent, MessageSendEventsProvider, ClosureReason, HTLCDestination};
use crate::util::events;
use crate::util::wakers::{Future, Notifier};
use crate::util::scid_utils::fake_scid;
use crate::util::ser::{BigSize, FixedLengthReader, Readable, ReadableArgs, MaybeReadable, Writeable, Writer, VecWriter};
use crate::util::logger::{Level, Logger};
use crate::util::errors::APIError;

use alloc::collections::BTreeMap;

use crate::io;
use crate::prelude::*;
use core::{cmp, mem};
use core::cell::RefCell;
use crate::io::Read;
use crate::sync::{Arc, Mutex, RwLock, RwLockReadGuard, FairRwLock, LockTestExt, LockHeldState};
use core::sync::atomic::{AtomicUsize, Ordering};
use core::time::Duration;
use core::ops::Deref;

// Re-export this for use in the public API.
pub use crate::ln::outbound_payment::{PaymentSendFailure, Retry, RetryableSendFailure};

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

#[derive(Clone)] // See Channel::revoke_and_ack for why, tl;dr: Rust bug
pub(super) enum PendingHTLCRouting {
	Forward {
		onion_packet: msgs::OnionPacket,
		/// The SCID from the onion that we should forward to. This could be a real SCID or a fake one
		/// generated using `get_fake_scid` from the scid_utils::fake_scid module.
		short_channel_id: u64, // This should be NonZero<u64> eventually when we bump MSRV
	},
	Receive {
		payment_data: msgs::FinalOnionHopData,
		incoming_cltv_expiry: u32, // Used to track when we should expire pending HTLCs that go unclaimed
		phantom_shared_secret: Option<[u8; 32]>,
	},
	ReceiveKeysend {
		payment_preimage: PaymentPreimage,
		incoming_cltv_expiry: u32, // Used to track when we should expire pending HTLCs that go unclaimed
	},
}

#[derive(Clone)] // See Channel::revoke_and_ack for why, tl;dr: Rust bug
pub(super) struct PendingHTLCInfo {
	pub(super) routing: PendingHTLCRouting,
	pub(super) incoming_shared_secret: [u8; 32],
	payment_hash: PaymentHash,
	pub(super) incoming_amt_msat: Option<u64>, // Added in 0.0.113
	pub(super) outgoing_amt_msat: u64,
	pub(super) outgoing_cltv_value: u32,
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
	prev_funding_outpoint: OutPoint,
	prev_user_channel_id: u128,
}

pub(super) enum HTLCForwardInfo {
	AddHTLC(PendingAddHTLCInfo),
	FailHTLC {
		htlc_id: u64,
		err_packet: msgs::OnionErrorPacket,
	},
}

/// Tracks the inbound corresponding to an outbound HTLC
#[derive(Clone, Hash, PartialEq, Eq)]
pub(crate) struct HTLCPreviousHopData {
	// Note that this may be an outbound SCID alias for the associated channel.
	short_channel_id: u64,
	htlc_id: u64,
	incoming_packet_shared_secret: [u8; 32],
	phantom_shared_secret: Option<[u8; 32]>,

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
	onion_payload: OnionPayload,
	timer_ticks: u8,
	/// The sum total of all MPP parts
	total_msat: u64,
}

/// A payment identifier used to uniquely identify a payment to LDK.
/// (C-not exported) as we just use [u8; 32] directly
#[derive(Hash, Copy, Clone, PartialEq, Eq, Debug)]
pub struct PaymentId(pub [u8; 32]);

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
/// (C-not exported) as we just use [u8; 32] directly
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

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
/// Uniquely describes an HTLC by its source. Just the guaranteed-unique subset of [`HTLCSource`].
pub(crate) enum SentHTLCId {
	PreviousHopData { short_channel_id: u64, htlc_id: u64 },
	OutboundRoute { session_priv: SecretKey },
}
impl SentHTLCId {
	pub(crate) fn from_source(source: &HTLCSource) -> Self {
		match source {
			HTLCSource::PreviousHopData(hop_data) => Self::PreviousHopData {
				short_channel_id: hop_data.short_channel_id,
				htlc_id: hop_data.htlc_id,
			},
			HTLCSource::OutboundRoute { session_priv, .. } =>
				Self::OutboundRoute { session_priv: *session_priv },
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
#[derive(Clone, PartialEq, Eq)]
pub(crate) enum HTLCSource {
	PreviousHopData(HTLCPreviousHopData),
	OutboundRoute {
		path: Vec<RouteHop>,
		session_priv: SecretKey,
		/// Technically we can recalculate this from the route, but we cache it here to avoid
		/// doing a double-pass on route when we get a failure back
		first_hop_htlc_msat: u64,
		payment_id: PaymentId,
		payment_secret: Option<PaymentSecret>,
		/// Note that this is now "deprecated" - we write it for forwards (and read it for
		/// backwards) compatibility reasons, but prefer to use the data in the
		/// [`super::outbound_payment`] module, which stores per-payment data once instead of in
		/// each HTLC.
		payment_params: Option<PaymentParameters>,
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
			HTLCSource::OutboundRoute { path, session_priv, payment_id, payment_secret, first_hop_htlc_msat, payment_params } => {
				1u8.hash(hasher);
				path.hash(hasher);
				session_priv[..].hash(hasher);
				payment_id.hash(hasher);
				payment_secret.hash(hasher);
				first_hop_htlc_msat.hash(hasher);
				payment_params.hash(hasher);
			},
		}
	}
}
#[cfg(not(feature = "grind_signatures"))]
#[cfg(test)]
impl HTLCSource {
	pub fn dummy() -> Self {
		HTLCSource::OutboundRoute {
			path: Vec::new(),
			session_priv: SecretKey::from_slice(&[1; 32]).unwrap(),
			first_hop_htlc_msat: 0,
			payment_id: PaymentId([2; 32]),
			payment_secret: None,
			payment_params: None,
		}
	}
}

struct ReceiveError {
	err_code: u16,
	err_data: Vec<u8>,
	msg: &'static str,
}

/// This enum is used to specify which error data to send to peers when failing back an HTLC
/// using [`ChannelManager::fail_htlc_backwards_with_reason`].
///
/// For more info on failure codes, see <https://github.com/lightning/bolts/blob/master/04-onion-routing.md#failure-messages>.
#[derive(Clone, Copy)]
pub enum FailureCode {
	/// We had a temporary error processing the payment. Useful if no other error codes fit
	/// and you want to indicate that the payer may want to retry.
	TemporaryNodeFailure             = 0x2000 | 2,
	/// We have a required feature which was not in this onion. For example, you may require
	/// some additional metadata that was not provided with this payment.
	RequiredNodeFeatureMissing       = 0x4000 | 0x2000 | 3,
	/// You may wish to use this when a `payment_preimage` is unknown, or the CLTV expiry of
	/// the HTLC is too close to the current block height for safe handling.
	/// Using this failure code in [`ChannelManager::fail_htlc_backwards_with_reason`] is
	/// equivalent to calling [`ChannelManager::fail_htlc_backwards`].
	IncorrectOrUnknownPaymentDetails = 0x4000 | 15,
}

type ShutdownResult = (Option<(OutPoint, ChannelMonitorUpdate)>, Vec<(HTLCSource, PaymentHash, PublicKey, [u8; 32])>);

/// Error type returned across the peer_state mutex boundary. When an Err is generated for a
/// Channel, we generally end up with a ChannelError::Close for which we have to close the channel
/// immediately (ie with no further calls on it made). Thus, this step happens inside a
/// peer_state lock. We then return the set of things that need to be done outside the lock in
/// this struct and call handle_error!() on it.

struct MsgHandleErrInternal {
	err: msgs::LightningError,
	chan_id: Option<([u8; 32], u128)>, // If Some a channel of ours has been closed
	shutdown_finish: Option<(ShutdownResult, Option<msgs::ChannelUpdate>)>,
}
impl MsgHandleErrInternal {
	#[inline]
	fn send_err_msg_no_close(err: String, channel_id: [u8; 32]) -> Self {
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
			chan_id: None,
			shutdown_finish: None,
		}
	}
	#[inline]
	fn from_no_close(err: msgs::LightningError) -> Self {
		Self { err, chan_id: None, shutdown_finish: None }
	}
	#[inline]
	fn from_finish_shutdown(err: String, channel_id: [u8; 32], user_channel_id: u128, shutdown_res: ShutdownResult, channel_update: Option<msgs::ChannelUpdate>) -> Self {
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
			chan_id: Some((channel_id, user_channel_id)),
			shutdown_finish: Some((shutdown_res, channel_update)),
		}
	}
	#[inline]
	fn from_chan_no_close(err: ChannelError, channel_id: [u8; 32]) -> Self {
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
			chan_id: None,
			shutdown_finish: None,
		}
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
}
impl_writeable_tlv_based!(ClaimingPayment, {
	(0, amount_msat, required),
	(2, payment_purpose, required),
	(4, receiver_node_id, required),
});

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
	claimable_htlcs: HashMap<PaymentHash, (events::PaymentPurpose, Vec<ClaimableHTLC>)>,

	/// Map from payment hash to the payment data for HTLCs which we have begun claiming, but which
	/// are waiting on a [`ChannelMonitorUpdate`] to complete in order to be surfaced to the user
	/// as an [`events::Event::PaymentClaimed`].
	pending_claiming_payments: HashMap<PaymentHash, ClaimingPayment>,
}

/// Events which we process internally but cannot be procsesed immediately at the generation site
/// for some reason. They are handled in timer_tick_occurred, so may be processed with
/// quite some time lag.
enum BackgroundEvent {
	/// Handle a ChannelMonitorUpdate that closes a channel, broadcasting its current latest holder
	/// commitment transaction.
	ClosingMonitorUpdate((OutPoint, ChannelMonitorUpdate)),
}

#[derive(Debug)]
pub(crate) enum MonitorUpdateCompletionAction {
	/// Indicates that a payment ultimately destined for us was claimed and we should emit an
	/// [`events::Event::PaymentClaimed`] to the user if we haven't yet generated such an event for
	/// this payment. Note that this is only best-effort. On restart it's possible such a duplicate
	/// event can be generated.
	PaymentClaimed { payment_hash: PaymentHash },
	/// Indicates an [`events::Event`] should be surfaced to the user.
	EmitEvent { event: events::Event },
}

impl_writeable_tlv_based_enum_upgradable!(MonitorUpdateCompletionAction,
	(0, PaymentClaimed) => { (0, payment_hash, required) },
	(2, EmitEvent) => { (0, event, upgradable_required) },
);

/// State we hold per-peer.
pub(super) struct PeerState<Signer: ChannelSigner> {
	/// `temporary_channel_id` or `channel_id` -> `channel`.
	///
	/// Holds all channels where the peer is the counterparty. Once a channel has been assigned a
	/// `channel_id`, the `temporary_channel_id` key in the map is updated and is replaced by the
	/// `channel_id`.
	pub(super) channel_by_id: HashMap<[u8; 32], Channel<Signer>>,
	/// The latest `InitFeatures` we heard from the peer.
	latest_features: InitFeatures,
	/// Messages to send to the peer - pushed to in the same lock that they are generated in (except
	/// for broadcast messages, where ordering isn't as strict).
	pub(super) pending_msg_events: Vec<MessageSendEvent>,
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
	monitor_update_blocked_actions: BTreeMap<[u8; 32], Vec<MonitorUpdateCompletionAction>>,
	/// The peer is currently connected (i.e. we've seen a
	/// [`ChannelMessageHandler::peer_connected`] and no corresponding
	/// [`ChannelMessageHandler::peer_disconnected`].
	is_connected: bool,
}

impl <Signer: ChannelSigner> PeerState<Signer> {
	/// Indicates that a peer meets the criteria where we're ok to remove it from our storage.
	/// If true is passed for `require_disconnected`, the function will return false if we haven't
	/// disconnected from the node already, ie. `PeerState::is_connected` is set to `true`.
	fn ok_to_remove(&self, require_disconnected: bool) -> bool {
		if require_disconnected && self.is_connected {
			return false
		}
		self.channel_by_id.is_empty() && self.monitor_update_blocked_actions.is_empty()
	}
}

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

/// SimpleArcChannelManager is useful when you need a ChannelManager with a static lifetime, e.g.
/// when you're using lightning-net-tokio (since tokio::spawn requires parameters with static
/// lifetimes). Other times you can afford a reference, which is more efficient, in which case
/// SimpleRefChannelManager is the more appropriate type. Defining these type aliases prevents
/// issues such as overly long function definitions. Note that the ChannelManager can take any type
/// that implements KeysInterface or Router for its keys manager and router, respectively, but this
/// type alias chooses the concrete types of KeysManager and DefaultRouter.
///
/// (C-not exported) as Arcs don't make sense in bindings
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
		Arc<Mutex<ProbabilisticScorer<Arc<NetworkGraph<Arc<L>>>, Arc<L>>>>
	>>,
	Arc<L>
>;

/// SimpleRefChannelManager is a type alias for a ChannelManager reference, and is the reference
/// counterpart to the SimpleArcChannelManager type alias. Use this type by default when you don't
/// need a ChannelManager with a static lifetime. You'll need a static lifetime in cases such as
/// usage of lightning-net-tokio (since tokio::spawn requires parameters with static lifetimes).
/// But if this is not necessary, using a reference is more efficient. Defining these type aliases
/// issues such as overly long function definitions. Note that the ChannelManager can take any type
/// that implements KeysInterface or Router for its keys manager and router, respectively, but this
/// type alias chooses the concrete types of KeysManager and DefaultRouter.
///
/// (C-not exported) as Arcs don't make sense in bindings
pub type SimpleRefChannelManager<'a, 'b, 'c, 'd, 'e, 'f, 'g, 'h, M, T, F, L> = ChannelManager<&'a M, &'b T, &'c KeysManager, &'c KeysManager, &'c KeysManager, &'d F, &'e DefaultRouter<&'f NetworkGraph<&'g L>, &'g L, &'h Mutex<ProbabilisticScorer<&'f NetworkGraph<&'g L>, &'g L>>>, &'g L>;

/// Manager which keeps track of a number of channels and sends messages to the appropriate
/// channel, also tracking HTLC preimages and forwarding onion packets appropriately.
///
/// Implements ChannelMessageHandler, handling the multi-channel parts and passing things through
/// to individual Channels.
///
/// Implements Writeable to write out all channel state to disk. Implies peer_disconnected() for
/// all peers during write/read (though does not modify this instance, only the instance being
/// serialized). This will result in any channels which have not yet exchanged funding_created (ie
/// called funding_transaction_generated for outbound channels).
///
/// Note that you can be a bit lazier about writing out ChannelManager than you can be with
/// ChannelMonitors. With ChannelMonitors you MUST write each monitor update out to disk before
/// returning from chain::Watch::watch_/update_channel, with ChannelManagers, writing updates
/// happens out-of-band (and will prevent any other ChannelManager operations from occurring during
/// the serialization process). If the deserialized version is out-of-date compared to the
/// ChannelMonitors passed by reference to read(), those channels will be force-closed based on the
/// ChannelMonitor state and no funds will be lost (mod on-chain transaction fees).
///
/// Note that the deserializer is only implemented for (BlockHash, ChannelManager), which
/// tells you the last block hash which was block_connect()ed. You MUST rescan any blocks along
/// the "reorg path" (ie call block_disconnected() until you get to a common block and then call
/// block_connected() to step towards your best block) upon deserialization before using the
/// object!
///
/// Note that ChannelManager is responsible for tracking liveness of its channels and generating
/// ChannelUpdate messages informing peers that the channel is temporarily disabled. To avoid
/// spam due to quick disconnection/reconnection, updates are not sent until the channel has been
/// offline for a full minute. In order to track this, you must call
/// timer_tick_occurred roughly once per minute, though it doesn't have to be perfect.
///
/// To avoid trivial DoS issues, ChannelManager limits the number of inbound connections and
/// inbound channels without confirmed funding transactions. This may result in nodes which we do
/// not have a channel with being unable to connect to us or open new channels with us if we have
/// many peers with unfunded channels.
///
/// Because it is an indication of trust, inbound channels which we've accepted as 0conf are
/// exempted from the count of unfunded channels. Similarly, outbound channels and connections are
/// never limited. Please ensure you limit the count of such channels yourself.
///
/// Rather than using a plain ChannelManager, it is preferable to use either a SimpleArcChannelManager
/// a SimpleRefChannelManager, for conciseness. See their documentation for more details, but
/// essentially you should default to using a SimpleRefChannelManager, and use a
/// SimpleArcChannelManager when you require a ChannelManager with a static lifetime, such as when
/// you're using lightning-net-tokio.
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
// `total_consistency_lock`
//  |
//  |__`forward_htlcs`
//  |   |
//  |   |__`pending_intercepted_htlcs`
//  |
//  |__`per_peer_state`
//  |   |
//  |   |__`pending_inbound_payments`
//  |       |
//  |       |__`claimable_payments`
//  |       |
//  |       |__`pending_outbound_payments` // This field's struct contains a map of pending outbounds
//  |           |
//  |           |__`peer_state`
//  |               |
//  |               |__`id_to_peer`
//  |               |
//  |               |__`short_to_chan_info`
//  |               |
//  |               |__`outbound_scid_aliases`
//  |               |
//  |               |__`best_block`
//  |               |
//  |               |__`pending_events`
//  |                   |
//  |                   |__`pending_background_events`
//
pub struct ChannelManager<M: Deref, T: Deref, ES: Deref, NS: Deref, SP: Deref, F: Deref, R: Deref, L: Deref>
where
	M::Target: chain::Watch<<SP::Target as SignerProvider>::Signer>,
	T::Target: BroadcasterInterface,
	ES::Target: EntropySource,
	NS::Target: NodeSigner,
	SP::Target: SignerProvider,
	F::Target: FeeEstimator,
	R::Target: Router,
	L::Target: Logger,
{
	default_configuration: UserConfig,
	genesis_hash: BlockHash,
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

	/// `channel_id` -> `counterparty_node_id`.
	///
	/// Only `channel_id`s are allowed as keys in this map, and not `temporary_channel_id`s. As
	/// multiple channels with the same `temporary_channel_id` to different peers can exist,
	/// allowing `temporary_channel_id`s in this map would cause collisions for such channels.
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
	id_to_peer: Mutex<HashMap<[u8; 32], PublicKey>>,

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
	pub(super) short_to_chan_info: FairRwLock<HashMap<u64, (PublicKey, [u8; 32])>>,
	#[cfg(not(test))]
	short_to_chan_info: FairRwLock<HashMap<u64, (PublicKey, [u8; 32])>>,

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
	per_peer_state: FairRwLock<HashMap<PublicKey, Mutex<PeerState<<SP::Target as SignerProvider>::Signer>>>>,
	#[cfg(any(test, feature = "_test_utils"))]
	pub(super) per_peer_state: FairRwLock<HashMap<PublicKey, Mutex<PeerState<<SP::Target as SignerProvider>::Signer>>>>,

	/// See `ChannelManager` struct-level documentation for lock order requirements.
	pending_events: Mutex<Vec<events::Event>>,
	/// See `ChannelManager` struct-level documentation for lock order requirements.
	pending_background_events: Mutex<Vec<BackgroundEvent>>,
	/// Used when we have to take a BIG lock to make sure everything is self-consistent.
	/// Essentially just when we're serializing ourselves out.
	/// Taken first everywhere where we are making changes before any other locks.
	/// When acquiring this lock in read mode, rather than acquiring it directly, call
	/// `PersistenceNotifierGuard::notify_on_drop(..)` and pass the lock to it, to ensure the
	/// Notifier the lock contains sends out a notification when the lock is released.
	total_consistency_lock: RwLock<()>,

	persistence_notifier: Notifier,

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
enum NotifyOption {
	DoPersist,
	SkipPersist,
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
struct PersistenceNotifierGuard<'a, F: Fn() -> NotifyOption> {
	persistence_notifier: &'a Notifier,
	should_persist: F,
	// We hold onto this result so the lock doesn't get released immediately.
	_read_guard: RwLockReadGuard<'a, ()>,
}

impl<'a> PersistenceNotifierGuard<'a, fn() -> NotifyOption> { // We don't care what the concrete F is here, it's unused
	fn notify_on_drop(lock: &'a RwLock<()>, notifier: &'a Notifier) -> PersistenceNotifierGuard<'a, impl Fn() -> NotifyOption> {
		PersistenceNotifierGuard::optionally_notify(lock, notifier, || -> NotifyOption { NotifyOption::DoPersist })
	}

	fn optionally_notify<F: Fn() -> NotifyOption>(lock: &'a RwLock<()>, notifier: &'a Notifier, persist_check: F) -> PersistenceNotifierGuard<'a, F> {
		let read_guard = lock.read().unwrap();

		PersistenceNotifierGuard {
			persistence_notifier: notifier,
			should_persist: persist_check,
			_read_guard: read_guard,
		}
	}
}

impl<'a, F: Fn() -> NotifyOption> Drop for PersistenceNotifierGuard<'a, F> {
	fn drop(&mut self) {
		if (self.should_persist)() == NotifyOption::DoPersist {
			self.persistence_notifier.notify();
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
#[deny(const_err)]
#[allow(dead_code)]
const CHECK_CLTV_EXPIRY_SANITY: u32 = MIN_CLTV_EXPIRY_DELTA as u32 - LATENCY_GRACE_PERIOD_BLOCKS - CLTV_CLAIM_BUFFER - ANTI_REORG_DELAY - LATENCY_GRACE_PERIOD_BLOCKS;

// Check for ability of an attacker to make us fail on-chain by delaying an HTLC claim. See
// ChannelMonitor::should_broadcast_holder_commitment_txn for a description of why this is needed.
#[deny(const_err)]
#[allow(dead_code)]
const CHECK_CLTV_EXPIRY_SANITY_2: u32 = MIN_CLTV_EXPIRY_DELTA as u32 - LATENCY_GRACE_PERIOD_BLOCKS - 2*CLTV_CLAIM_BUFFER;

/// The number of ticks of [`ChannelManager::timer_tick_occurred`] until expiry of incomplete MPPs
pub(crate) const MPP_TIMEOUT_TICKS: u8 = 3;

/// The number of ticks of [`ChannelManager::timer_tick_occurred`] until we time-out the
/// idempotency of payments by [`PaymentId`]. See
/// [`OutboundPayments::remove_stale_resolved_payments`].
pub(crate) const IDEMPOTENCY_TIMEOUT_TICKS: u8 = 7;

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

/// Details of a channel, as returned by ChannelManager::list_channels and ChannelManager::list_usable_channels
#[derive(Clone, Debug, PartialEq)]
pub struct ChannelDetails {
	/// The channel's ID (prior to funding transaction generation, this is a random 32 bytes,
	/// thereafter this is the txid of the funding transaction xor the funding transaction output).
	/// Note that this means this value is *not* persistent - it can change once during the
	/// lifetime of the channel.
	pub channel_id: [u8; 32],
	/// Parameters which apply to our counterparty. See individual fields for more information.
	pub counterparty: ChannelCounterparty,
	/// The Channel's funding transaction output, if we've negotiated the funding transaction with
	/// our counterparty already.
	///
	/// Note that, if this has been set, `channel_id` will be equivalent to
	/// `funding_txo.unwrap().to_channel_id()`.
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
	/// The `user_channel_id` passed in to create_channel, or a random value if the channel was
	/// inbound. This may be zero for inbound channels serialized with LDK versions prior to
	/// 0.0.113.
	pub user_channel_id: u128,
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
	/// See also [`ChannelDetails::balance_msat`] and [`ChannelDetails::outbound_capacity_msat`].
	pub next_outbound_htlc_limit_msat: u64,
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
}

/// Used by [`ChannelManager::list_recent_payments`] to express the status of recent payments.
/// These include payments that have yet to find a successful path, or have unresolved HTLCs.
#[derive(Debug, PartialEq)]
pub enum RecentPaymentDetails {
	/// When a payment is still being sent and awaiting successful delivery.
	Pending {
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
		/// Hash of the payment that was claimed. `None` for serializations of [`ChannelManager`]
		/// made before LDK version 0.0.104.
		payment_hash: Option<PaymentHash>,
	},
	/// After a payment's retries are exhausted per the provided [`Retry`], or it is explicitly
	/// abandoned via [`ChannelManager::abandon_payment`], it is marked as abandoned until all
	/// pending HTLCs for this payment resolve and an [`Event::PaymentFailed`] is generated.
	Abandoned {
		/// Hash of the payment that we have given up trying to send.
		payment_hash: PaymentHash,
	},
}

/// Route hints used in constructing invoices for [phantom node payents].
///
/// [phantom node payments]: crate::chain::keysinterface::PhantomKeysManager
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
	($self: ident, $internal: expr, $counterparty_node_id: expr) => {
		match $internal {
			Ok(msg) => Ok(msg),
			Err(MsgHandleErrInternal { err, chan_id, shutdown_finish }) => {
				// In testing, ensure there are no deadlocks where the lock is already held upon
				// entering the macro.
				debug_assert_ne!($self.pending_events.held_by_thread(), LockHeldState::HeldByThread);
				debug_assert_ne!($self.per_peer_state.held_by_thread(), LockHeldState::HeldByThread);

				let mut msg_events = Vec::with_capacity(2);

				if let Some((shutdown_res, update_option)) = shutdown_finish {
					$self.finish_force_close_channel(shutdown_res);
					if let Some(update) = update_option {
						msg_events.push(events::MessageSendEvent::BroadcastChannelUpdate {
							msg: update
						});
					}
					if let Some((channel_id, user_channel_id)) = chan_id {
						$self.pending_events.lock().unwrap().push(events::Event::ChannelClosed {
							channel_id, user_channel_id,
							reason: ClosureReason::ProcessingError { err: err.err.clone() }
						});
					}
				}

				log_error!($self.logger, "{}", err.err);
				if let msgs::ErrorAction::IgnoreError = err.action {
				} else {
					msg_events.push(events::MessageSendEvent::HandleError {
						node_id: $counterparty_node_id,
						action: err.action.clone()
					});
				}

				if !msg_events.is_empty() {
					let per_peer_state = $self.per_peer_state.read().unwrap();
					if let Some(peer_state_mutex) = per_peer_state.get(&$counterparty_node_id) {
						let mut peer_state = peer_state_mutex.lock().unwrap();
						peer_state.pending_msg_events.append(&mut msg_events);
					}
				}

				// Return error in case higher-API need one
				Err(err)
			},
		}
	}
}

macro_rules! update_maps_on_chan_removal {
	($self: expr, $channel: expr) => {{
		$self.id_to_peer.lock().unwrap().remove(&$channel.channel_id());
		let mut short_to_chan_info = $self.short_to_chan_info.write().unwrap();
		if let Some(short_id) = $channel.get_short_channel_id() {
			short_to_chan_info.remove(&short_id);
		} else {
			// If the channel was never confirmed on-chain prior to its closure, remove the
			// outbound SCID alias we used for it from the collision-prevention set. While we
			// generally want to avoid ever re-using an outbound SCID alias across all channels, we
			// also don't want a counterparty to be able to trivially cause a memory leak by simply
			// opening a million channels with us which are closed before we ever reach the funding
			// stage.
			let alias_removed = $self.outbound_scid_aliases.lock().unwrap().remove(&$channel.outbound_scid_alias());
			debug_assert!(alias_removed);
		}
		short_to_chan_info.remove(&$channel.outbound_scid_alias());
	}}
}

/// Returns (boolean indicating if we should remove the Channel object from memory, a mapped error)
macro_rules! convert_chan_err {
	($self: ident, $err: expr, $channel: expr, $channel_id: expr) => {
		match $err {
			ChannelError::Warn(msg) => {
				(false, MsgHandleErrInternal::from_chan_no_close(ChannelError::Warn(msg), $channel_id.clone()))
			},
			ChannelError::Ignore(msg) => {
				(false, MsgHandleErrInternal::from_chan_no_close(ChannelError::Ignore(msg), $channel_id.clone()))
			},
			ChannelError::Close(msg) => {
				log_error!($self.logger, "Closing channel {} due to close-required error: {}", log_bytes!($channel_id[..]), msg);
				update_maps_on_chan_removal!($self, $channel);
				let shutdown_res = $channel.force_shutdown(true);
				(true, MsgHandleErrInternal::from_finish_shutdown(msg, *$channel_id, $channel.get_user_id(),
					shutdown_res, $self.get_channel_update_for_broadcast(&$channel).ok()))
			},
		}
	}
}

macro_rules! break_chan_entry {
	($self: ident, $res: expr, $entry: expr) => {
		match $res {
			Ok(res) => res,
			Err(e) => {
				let (drop, res) = convert_chan_err!($self, e, $entry.get_mut(), $entry.key());
				if drop {
					$entry.remove_entry();
				}
				break Err(res);
			}
		}
	}
}

macro_rules! try_chan_entry {
	($self: ident, $res: expr, $entry: expr) => {
		match $res {
			Ok(res) => res,
			Err(e) => {
				let (drop, res) = convert_chan_err!($self, e, $entry.get_mut(), $entry.key());
				if drop {
					$entry.remove_entry();
				}
				return Err(res);
			}
		}
	}
}

macro_rules! remove_channel {
	($self: expr, $entry: expr) => {
		{
			let channel = $entry.remove_entry().1;
			update_maps_on_chan_removal!($self, channel);
			channel
		}
	}
}

macro_rules! send_channel_ready {
	($self: ident, $pending_msg_events: expr, $channel: expr, $channel_ready_msg: expr) => {{
		$pending_msg_events.push(events::MessageSendEvent::SendChannelReady {
			node_id: $channel.get_counterparty_node_id(),
			msg: $channel_ready_msg,
		});
		// Note that we may send a `channel_ready` multiple times for a channel if we reconnect, so
		// we allow collisions, but we shouldn't ever be updating the channel ID pointed to.
		let mut short_to_chan_info = $self.short_to_chan_info.write().unwrap();
		let outbound_alias_insert = short_to_chan_info.insert($channel.outbound_scid_alias(), ($channel.get_counterparty_node_id(), $channel.channel_id()));
		assert!(outbound_alias_insert.is_none() || outbound_alias_insert.unwrap() == ($channel.get_counterparty_node_id(), $channel.channel_id()),
			"SCIDs should never collide - ensure you weren't behind the chain tip by a full month when creating channels");
		if let Some(real_scid) = $channel.get_short_channel_id() {
			let scid_insert = short_to_chan_info.insert(real_scid, ($channel.get_counterparty_node_id(), $channel.channel_id()));
			assert!(scid_insert.is_none() || scid_insert.unwrap() == ($channel.get_counterparty_node_id(), $channel.channel_id()),
				"SCIDs should never collide - ensure you weren't behind the chain tip by a full month when creating channels");
		}
	}}
}

macro_rules! emit_channel_ready_event {
	($self: expr, $channel: expr) => {
		if $channel.should_emit_channel_ready_event() {
			{
				let mut pending_events = $self.pending_events.lock().unwrap();
				pending_events.push(events::Event::ChannelReady {
					channel_id: $channel.channel_id(),
					user_channel_id: $channel.get_user_id(),
					counterparty_node_id: $channel.get_counterparty_node_id(),
					channel_type: $channel.get_channel_type().clone(),
				});
			}
			$channel.set_channel_ready_event_emitted();
		}
	}
}

macro_rules! handle_monitor_update_completion {
	($self: ident, $update_id: expr, $peer_state_lock: expr, $peer_state: expr, $per_peer_state_lock: expr, $chan: expr) => { {
		let mut updates = $chan.monitor_updating_restored(&$self.logger,
			&$self.node_signer, $self.genesis_hash, &$self.default_configuration,
			$self.best_block.read().unwrap().height());
		let counterparty_node_id = $chan.get_counterparty_node_id();
		let channel_update = if updates.channel_ready.is_some() && $chan.is_usable() {
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
			.remove(&$chan.channel_id()).unwrap_or(Vec::new());

		let htlc_forwards = $self.handle_channel_resumption(
			&mut $peer_state.pending_msg_events, $chan, updates.raa,
			updates.commitment_update, updates.order, updates.accepted_htlcs,
			updates.funding_broadcastable, updates.channel_ready,
			updates.announcement_sigs);
		if let Some(upd) = channel_update {
			$peer_state.pending_msg_events.push(upd);
		}

		let channel_id = $chan.channel_id();
		core::mem::drop($peer_state_lock);
		core::mem::drop($per_peer_state_lock);

		$self.handle_monitor_update_completion_actions(update_actions);

		if let Some(forwards) = htlc_forwards {
			$self.forward_htlcs(&mut [forwards][..]);
		}
		$self.finalize_claims(updates.finalized_claimed_htlcs);
		for failure in updates.failed_htlcs.drain(..) {
			let receiver = HTLCDestination::NextHopChannel { node_id: Some(counterparty_node_id), channel_id };
			$self.fail_htlc_backwards_internal(&failure.0, &failure.1, &failure.2, receiver);
		}
	} }
}

macro_rules! handle_new_monitor_update {
	($self: ident, $update_res: expr, $update_id: expr, $peer_state_lock: expr, $peer_state: expr, $per_peer_state_lock: expr, $chan: expr, MANUALLY_REMOVING, $remove: expr) => { {
		// update_maps_on_chan_removal needs to be able to take id_to_peer, so make sure we can in
		// any case so that it won't deadlock.
		debug_assert!($self.id_to_peer.try_lock().is_ok());
		match $update_res {
			ChannelMonitorUpdateStatus::InProgress => {
				log_debug!($self.logger, "ChannelMonitor update for {} in flight, holding messages until the update completes.",
					log_bytes!($chan.channel_id()[..]));
				Ok(())
			},
			ChannelMonitorUpdateStatus::PermanentFailure => {
				log_error!($self.logger, "Closing channel {} due to monitor update ChannelMonitorUpdateStatus::PermanentFailure",
					log_bytes!($chan.channel_id()[..]));
				update_maps_on_chan_removal!($self, $chan);
				let res: Result<(), _> = Err(MsgHandleErrInternal::from_finish_shutdown(
					"ChannelMonitor storage failure".to_owned(), $chan.channel_id(),
					$chan.get_user_id(), $chan.force_shutdown(false),
					$self.get_channel_update_for_broadcast(&$chan).ok()));
				$remove;
				res
			},
			ChannelMonitorUpdateStatus::Completed => {
				if ($update_id == 0 || $chan.get_next_monitor_update()
					.expect("We can't be processing a monitor update if it isn't queued")
					.update_id == $update_id) &&
					$chan.get_latest_monitor_update_id() == $update_id
				{
					handle_monitor_update_completion!($self, $update_id, $peer_state_lock, $peer_state, $per_peer_state_lock, $chan);
				}
				Ok(())
			},
		}
	} };
	($self: ident, $update_res: expr, $update_id: expr, $peer_state_lock: expr, $peer_state: expr, $per_peer_state_lock: expr, $chan_entry: expr) => {
		handle_new_monitor_update!($self, $update_res, $update_id, $peer_state_lock, $peer_state, $per_peer_state_lock, $chan_entry.get_mut(), MANUALLY_REMOVING, $chan_entry.remove_entry())
	}
}

impl<M: Deref, T: Deref, ES: Deref, NS: Deref, SP: Deref, F: Deref, R: Deref, L: Deref> ChannelManager<M, T, ES, NS, SP, F, R, L>
where
	M::Target: chain::Watch<<SP::Target as SignerProvider>::Signer>,
	T::Target: BroadcasterInterface,
	ES::Target: EntropySource,
	NS::Target: NodeSigner,
	SP::Target: SignerProvider,
	F::Target: FeeEstimator,
	R::Target: Router,
	L::Target: Logger,
{
	/// Constructs a new ChannelManager to hold several channels and route between them.
	///
	/// This is the main "logic hub" for all channel-related actions, and implements
	/// ChannelMessageHandler.
	///
	/// Non-proportional fees are fixed according to our risk using the provided fee estimator.
	///
	/// Users need to notify the new ChannelManager when a new block is connected or
	/// disconnected using its `block_connected` and `block_disconnected` methods, starting
	/// from after `params.latest_hash`.
	pub fn new(fee_est: F, chain_monitor: M, tx_broadcaster: T, router: R, logger: L, entropy_source: ES, node_signer: NS, signer_provider: SP, config: UserConfig, params: ChainParameters) -> Self {
		let mut secp_ctx = Secp256k1::new();
		secp_ctx.seeded_randomize(&entropy_source.get_secure_random_bytes());
		let inbound_pmt_key_material = node_signer.get_inbound_payment_key_material();
		let expanded_inbound_key = inbound_payment::ExpandedKey::new(&inbound_pmt_key_material);
		ChannelManager {
			default_configuration: config.clone(),
			genesis_hash: genesis_block(params.network).header.block_hash(),
			fee_estimator: LowerBoundedFeeEstimator::new(fee_est),
			chain_monitor,
			tx_broadcaster,
			router,

			best_block: RwLock::new(params.best_block),

			outbound_scid_aliases: Mutex::new(HashSet::new()),
			pending_inbound_payments: Mutex::new(HashMap::new()),
			pending_outbound_payments: OutboundPayments::new(),
			forward_htlcs: Mutex::new(HashMap::new()),
			claimable_payments: Mutex::new(ClaimablePayments { claimable_htlcs: HashMap::new(), pending_claiming_payments: HashMap::new() }),
			pending_intercepted_htlcs: Mutex::new(HashMap::new()),
			id_to_peer: Mutex::new(HashMap::new()),
			short_to_chan_info: FairRwLock::new(HashMap::new()),

			our_network_pubkey: node_signer.get_node_id(Recipient::Node).unwrap(),
			secp_ctx,

			inbound_payment_key: expanded_inbound_key,
			fake_scid_rand_bytes: entropy_source.get_secure_random_bytes(),

			probing_cookie_secret: entropy_source.get_secure_random_bytes(),

			highest_seen_timestamp: AtomicUsize::new(0),

			per_peer_state: FairRwLock::new(HashMap::new()),

			pending_events: Mutex::new(Vec::new()),
			pending_background_events: Mutex::new(Vec::new()),
			total_consistency_lock: RwLock::new(()),
			persistence_notifier: Notifier::new(),

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
		let height = self.best_block.read().unwrap().height();
		let mut outbound_scid_alias = 0;
		let mut i = 0;
		loop {
			if cfg!(fuzzing) { // fuzzing chacha20 doesn't use the key at all so we always get the same alias
				outbound_scid_alias += 1;
			} else {
				outbound_scid_alias = fake_scid::Namespace::OutboundAlias.get_fake_scid(height, &self.genesis_hash, &self.fake_scid_rand_bytes, &self.entropy_source);
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
	/// Note that we do not check if you are currently connected to the given peer. If no
	/// connection is available, the outbound `open_channel` message may fail to send, resulting in
	/// the channel eventually being silently forgotten (dropped on reload).
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
	pub fn create_channel(&self, their_network_key: PublicKey, channel_value_satoshis: u64, push_msat: u64, user_channel_id: u128, override_config: Option<UserConfig>) -> Result<[u8; 32], APIError> {
		if channel_value_satoshis < 1000 {
			return Err(APIError::APIMisuseError { err: format!("Channel value must be at least 1000 satoshis. It was {}", channel_value_satoshis) });
		}

		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(&self.total_consistency_lock, &self.persistence_notifier);
		// We want to make sure the lock is actually acquired by PersistenceNotifierGuard.
		debug_assert!(&self.total_consistency_lock.try_write().is_err());

		let per_peer_state = self.per_peer_state.read().unwrap();

		let peer_state_mutex = per_peer_state.get(&their_network_key)
			.ok_or_else(|| APIError::APIMisuseError{ err: format!("Not connected to node: {}", their_network_key) })?;

		let mut peer_state = peer_state_mutex.lock().unwrap();
		let channel = {
			let outbound_scid_alias = self.create_and_insert_outbound_scid_alias();
			let their_features = &peer_state.latest_features;
			let config = if override_config.is_some() { override_config.as_ref().unwrap() } else { &self.default_configuration };
			match Channel::new_outbound(&self.fee_estimator, &self.entropy_source, &self.signer_provider, their_network_key,
				their_features, channel_value_satoshis, push_msat, user_channel_id, config,
				self.best_block.read().unwrap().height(), outbound_scid_alias)
			{
				Ok(res) => res,
				Err(e) => {
					self.outbound_scid_aliases.lock().unwrap().remove(&outbound_scid_alias);
					return Err(e);
				},
			}
		};
		let res = channel.get_open_channel(self.genesis_hash.clone());

		let temporary_channel_id = channel.channel_id();
		match peer_state.channel_by_id.entry(temporary_channel_id) {
			hash_map::Entry::Occupied(_) => {
				if cfg!(fuzzing) {
					return Err(APIError::APIMisuseError { err: "Fuzzy bad RNG".to_owned() });
				} else {
					panic!("RNG is bad???");
				}
			},
			hash_map::Entry::Vacant(entry) => { entry.insert(channel); }
		}

		peer_state.pending_msg_events.push(events::MessageSendEvent::SendOpenChannel {
			node_id: their_network_key,
			msg: res,
		});
		Ok(temporary_channel_id)
	}

	fn list_channels_with_filter<Fn: FnMut(&(&[u8; 32], &Channel<<SP::Target as SignerProvider>::Signer>)) -> bool + Copy>(&self, f: Fn) -> Vec<ChannelDetails> {
		// Allocate our best estimate of the number of channels we have in the `res`
		// Vec. Sadly the `short_to_chan_info` map doesn't cover channels without
		// a scid or a scid alias, and the `id_to_peer` shouldn't be used outside
		// of the ChannelMonitor handling. Therefore reallocations may still occur, but is
		// unlikely as the `short_to_chan_info` map often contains 2 entries for
		// the same channel.
		let mut res = Vec::with_capacity(self.short_to_chan_info.read().unwrap().len());
		{
			let best_block_height = self.best_block.read().unwrap().height();
			let per_peer_state = self.per_peer_state.read().unwrap();
			for (_cp_id, peer_state_mutex) in per_peer_state.iter() {
				let mut peer_state_lock = peer_state_mutex.lock().unwrap();
				let peer_state = &mut *peer_state_lock;
				for (channel_id, channel) in peer_state.channel_by_id.iter().filter(f) {
					let balance = channel.get_available_balances();
					let (to_remote_reserve_satoshis, to_self_reserve_satoshis) =
						channel.get_holder_counterparty_selected_channel_reserve_satoshis();
					res.push(ChannelDetails {
						channel_id: (*channel_id).clone(),
						counterparty: ChannelCounterparty {
							node_id: channel.get_counterparty_node_id(),
							features: peer_state.latest_features.clone(),
							unspendable_punishment_reserve: to_remote_reserve_satoshis,
							forwarding_info: channel.counterparty_forwarding_info(),
							// Ensures that we have actually received the `htlc_minimum_msat` value
							// from the counterparty through the `OpenChannel` or `AcceptChannel`
							// message (as they are always the first message from the counterparty).
							// Else `Channel::get_counterparty_htlc_minimum_msat` could return the
							// default `0` value set by `Channel::new_outbound`.
							outbound_htlc_minimum_msat: if channel.have_received_message() {
								Some(channel.get_counterparty_htlc_minimum_msat()) } else { None },
							outbound_htlc_maximum_msat: channel.get_counterparty_htlc_maximum_msat(),
						},
						funding_txo: channel.get_funding_txo(),
						// Note that accept_channel (or open_channel) is always the first message, so
						// `have_received_message` indicates that type negotiation has completed.
						channel_type: if channel.have_received_message() { Some(channel.get_channel_type().clone()) } else { None },
						short_channel_id: channel.get_short_channel_id(),
						outbound_scid_alias: if channel.is_usable() { Some(channel.outbound_scid_alias()) } else { None },
						inbound_scid_alias: channel.latest_inbound_scid_alias(),
						channel_value_satoshis: channel.get_value_satoshis(),
						unspendable_punishment_reserve: to_self_reserve_satoshis,
						balance_msat: balance.balance_msat,
						inbound_capacity_msat: balance.inbound_capacity_msat,
						outbound_capacity_msat: balance.outbound_capacity_msat,
						next_outbound_htlc_limit_msat: balance.next_outbound_htlc_limit_msat,
						user_channel_id: channel.get_user_id(),
						confirmations_required: channel.minimum_depth(),
						confirmations: Some(channel.get_funding_tx_confirmations(best_block_height)),
						force_close_spend_delay: channel.get_counterparty_selected_contest_delay(),
						is_outbound: channel.is_outbound(),
						is_channel_ready: channel.is_usable(),
						is_usable: channel.is_live(),
						is_public: channel.should_announce(),
						inbound_htlc_minimum_msat: Some(channel.get_holder_htlc_minimum_msat()),
						inbound_htlc_maximum_msat: channel.get_holder_htlc_maximum_msat(),
						config: Some(channel.config()),
					});
				}
			}
		}
		res
	}

	/// Gets the list of open channels, in random order. See ChannelDetail field documentation for
	/// more information.
	pub fn list_channels(&self) -> Vec<ChannelDetails> {
		self.list_channels_with_filter(|_| true)
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
		self.list_channels_with_filter(|&(_, ref channel)| channel.is_live())
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
			.filter_map(|(_, pending_outbound_payment)| match pending_outbound_payment {
				PendingOutboundPayment::Retryable { payment_hash, total_msat, .. } => {
					Some(RecentPaymentDetails::Pending {
						payment_hash: *payment_hash,
						total_msat: *total_msat,
					})
				},
				PendingOutboundPayment::Abandoned { payment_hash, .. } => {
					Some(RecentPaymentDetails::Abandoned { payment_hash: *payment_hash })
				},
				PendingOutboundPayment::Fulfilled { payment_hash, .. } => {
					Some(RecentPaymentDetails::Fulfilled { payment_hash: *payment_hash })
				},
				PendingOutboundPayment::Legacy { .. } => None
			})
			.collect()
	}

	/// Helper function that issues the channel close events
	fn issue_channel_close_events(&self, channel: &Channel<<SP::Target as SignerProvider>::Signer>, closure_reason: ClosureReason) {
		let mut pending_events_lock = self.pending_events.lock().unwrap();
		match channel.unbroadcasted_funding() {
			Some(transaction) => {
				pending_events_lock.push(events::Event::DiscardFunding { channel_id: channel.channel_id(), transaction })
			},
			None => {},
		}
		pending_events_lock.push(events::Event::ChannelClosed {
			channel_id: channel.channel_id(),
			user_channel_id: channel.get_user_id(),
			reason: closure_reason
		});
	}

	fn close_channel_internal(&self, channel_id: &[u8; 32], counterparty_node_id: &PublicKey, target_feerate_sats_per_1000_weight: Option<u32>) -> Result<(), APIError> {
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(&self.total_consistency_lock, &self.persistence_notifier);

		let mut failed_htlcs: Vec<(HTLCSource, PaymentHash)>;
		let result: Result<(), _> = loop {
			let per_peer_state = self.per_peer_state.read().unwrap();

			let peer_state_mutex = per_peer_state.get(counterparty_node_id)
				.ok_or_else(|| APIError::ChannelUnavailable { err: format!("Can't find a peer matching the passed counterparty node_id {}", counterparty_node_id) })?;

			let mut peer_state_lock = peer_state_mutex.lock().unwrap();
			let peer_state = &mut *peer_state_lock;
			match peer_state.channel_by_id.entry(channel_id.clone()) {
				hash_map::Entry::Occupied(mut chan_entry) => {
					let funding_txo_opt = chan_entry.get().get_funding_txo();
					let their_features = &peer_state.latest_features;
					let (shutdown_msg, mut monitor_update_opt, htlcs) = chan_entry.get_mut()
						.get_shutdown(&self.signer_provider, their_features, target_feerate_sats_per_1000_weight)?;
					failed_htlcs = htlcs;

					// We can send the `shutdown` message before updating the `ChannelMonitor`
					// here as we don't need the monitor update to complete until we send a
					// `shutdown_signed`, which we'll delay if we're pending a monitor update.
					peer_state.pending_msg_events.push(events::MessageSendEvent::SendShutdown {
						node_id: *counterparty_node_id,
						msg: shutdown_msg,
					});

					// Update the monitor with the shutdown script if necessary.
					if let Some(monitor_update) = monitor_update_opt.take() {
						let update_id = monitor_update.update_id;
						let update_res = self.chain_monitor.update_channel(funding_txo_opt.unwrap(), monitor_update);
						break handle_new_monitor_update!(self, update_res, update_id, peer_state_lock, peer_state, per_peer_state, chan_entry);
					}

					if chan_entry.get().is_shutdown() {
						let channel = remove_channel!(self, chan_entry);
						if let Ok(channel_update) = self.get_channel_update_for_broadcast(&channel) {
							peer_state.pending_msg_events.push(events::MessageSendEvent::BroadcastChannelUpdate {
								msg: channel_update
							});
						}
						self.issue_channel_close_events(&channel, ClosureReason::HolderForceClosed);
					}
					break Ok(());
				},
				hash_map::Entry::Vacant(_) => return Err(APIError::ChannelUnavailable{err: format!("Channel with id {} not found for the passed counterparty node_id {}", log_bytes!(*channel_id), counterparty_node_id) })
			}
		};

		for htlc_source in failed_htlcs.drain(..) {
			let reason = HTLCFailReason::from_failure_code(0x4000 | 8);
			let receiver = HTLCDestination::NextHopChannel { node_id: Some(*counterparty_node_id), channel_id: *channel_id };
			self.fail_htlc_backwards_internal(&htlc_source.0, &htlc_source.1, &reason, receiver);
		}

		let _ = handle_error!(self, result, *counterparty_node_id);
		Ok(())
	}

	/// Begins the process of closing a channel. After this call (plus some timeout), no new HTLCs
	/// will be accepted on the given channel, and after additional timeout/the closing of all
	/// pending HTLCs, the channel will be closed on chain.
	///
	///  * If we are the channel initiator, we will pay between our [`Background`] and
	///    [`ChannelConfig::force_close_avoidance_max_fee_satoshis`] plus our [`Normal`] fee
	///    estimate.
	///  * If our counterparty is the channel initiator, we will require a channel closing
	///    transaction feerate of at least our [`Background`] feerate or the feerate which
	///    would appear on a force-closure transaction, whichever is lower. We will allow our
	///    counterparty to pay as much fee as they'd like, however.
	///
	/// May generate a SendShutdown message event on success, which should be relayed.
	///
	/// [`ChannelConfig::force_close_avoidance_max_fee_satoshis`]: crate::util::config::ChannelConfig::force_close_avoidance_max_fee_satoshis
	/// [`Background`]: crate::chain::chaininterface::ConfirmationTarget::Background
	/// [`Normal`]: crate::chain::chaininterface::ConfirmationTarget::Normal
	pub fn close_channel(&self, channel_id: &[u8; 32], counterparty_node_id: &PublicKey) -> Result<(), APIError> {
		self.close_channel_internal(channel_id, counterparty_node_id, None)
	}

	/// Begins the process of closing a channel. After this call (plus some timeout), no new HTLCs
	/// will be accepted on the given channel, and after additional timeout/the closing of all
	/// pending HTLCs, the channel will be closed on chain.
	///
	/// `target_feerate_sat_per_1000_weight` has different meanings depending on if we initiated
	/// the channel being closed or not:
	///  * If we are the channel initiator, we will pay at least this feerate on the closing
	///    transaction. The upper-bound is set by
	///    [`ChannelConfig::force_close_avoidance_max_fee_satoshis`] plus our [`Normal`] fee
	///    estimate (or `target_feerate_sat_per_1000_weight`, if it is greater).
	///  * If our counterparty is the channel initiator, we will refuse to accept a channel closure
	///    transaction feerate below `target_feerate_sat_per_1000_weight` (or the feerate which
	///    will appear on a force-closure transaction, whichever is lower).
	///
	/// May generate a SendShutdown message event on success, which should be relayed.
	///
	/// [`ChannelConfig::force_close_avoidance_max_fee_satoshis`]: crate::util::config::ChannelConfig::force_close_avoidance_max_fee_satoshis
	/// [`Background`]: crate::chain::chaininterface::ConfirmationTarget::Background
	/// [`Normal`]: crate::chain::chaininterface::ConfirmationTarget::Normal
	pub fn close_channel_with_target_feerate(&self, channel_id: &[u8; 32], counterparty_node_id: &PublicKey, target_feerate_sats_per_1000_weight: u32) -> Result<(), APIError> {
		self.close_channel_internal(channel_id, counterparty_node_id, Some(target_feerate_sats_per_1000_weight))
	}

	#[inline]
	fn finish_force_close_channel(&self, shutdown_res: ShutdownResult) {
		let (monitor_update_option, mut failed_htlcs) = shutdown_res;
		log_debug!(self.logger, "Finishing force-closure of channel with {} HTLCs to fail", failed_htlcs.len());
		for htlc_source in failed_htlcs.drain(..) {
			let (source, payment_hash, counterparty_node_id, channel_id) = htlc_source;
			let reason = HTLCFailReason::from_failure_code(0x4000 | 8);
			let receiver = HTLCDestination::NextHopChannel { node_id: Some(counterparty_node_id), channel_id };
			self.fail_htlc_backwards_internal(&source, &payment_hash, &reason, receiver);
		}
		if let Some((funding_txo, monitor_update)) = monitor_update_option {
			// There isn't anything we can do if we get an update failure - we're already
			// force-closing. The monitor update on the required in-memory copy should broadcast
			// the latest local state, which is the best we can do anyway. Thus, it is safe to
			// ignore the result here.
			let _ = self.chain_monitor.update_channel(funding_txo, &monitor_update);
		}
	}

	/// `peer_msg` should be set when we receive a message from a peer, but not set when the
	/// user closes, which will be re-exposed as the `ChannelClosed` reason.
	fn force_close_channel_with_peer(&self, channel_id: &[u8; 32], peer_node_id: &PublicKey, peer_msg: Option<&String>, broadcast: bool)
	-> Result<PublicKey, APIError> {
		let per_peer_state = self.per_peer_state.read().unwrap();
		let peer_state_mutex = per_peer_state.get(peer_node_id)
			.ok_or_else(|| APIError::ChannelUnavailable { err: format!("Can't find a peer matching the passed counterparty node_id {}", peer_node_id) })?;
		let mut chan = {
			let mut peer_state_lock = peer_state_mutex.lock().unwrap();
			let peer_state = &mut *peer_state_lock;
			if let hash_map::Entry::Occupied(chan) = peer_state.channel_by_id.entry(channel_id.clone()) {
				if let Some(peer_msg) = peer_msg {
					self.issue_channel_close_events(chan.get(),ClosureReason::CounterpartyForceClosed { peer_msg: peer_msg.to_string() });
				} else {
					self.issue_channel_close_events(chan.get(),ClosureReason::HolderForceClosed);
				}
				remove_channel!(self, chan)
			} else {
				return Err(APIError::ChannelUnavailable{ err: format!("Channel with id {} not found for the passed counterparty node_id {}", log_bytes!(*channel_id), peer_node_id) });
			}
		};
		log_error!(self.logger, "Force-closing channel {}", log_bytes!(channel_id[..]));
		self.finish_force_close_channel(chan.force_shutdown(broadcast));
		if let Ok(update) = self.get_channel_update_for_broadcast(&chan) {
			let mut peer_state = peer_state_mutex.lock().unwrap();
			peer_state.pending_msg_events.push(events::MessageSendEvent::BroadcastChannelUpdate {
				msg: update
			});
		}

		Ok(chan.get_counterparty_node_id())
	}

	fn force_close_sending_error(&self, channel_id: &[u8; 32], counterparty_node_id: &PublicKey, broadcast: bool) -> Result<(), APIError> {
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(&self.total_consistency_lock, &self.persistence_notifier);
		match self.force_close_channel_with_peer(channel_id, counterparty_node_id, None, broadcast) {
			Ok(counterparty_node_id) => {
				let per_peer_state = self.per_peer_state.read().unwrap();
				if let Some(peer_state_mutex) = per_peer_state.get(&counterparty_node_id) {
					let mut peer_state = peer_state_mutex.lock().unwrap();
					peer_state.pending_msg_events.push(
						events::MessageSendEvent::HandleError {
							node_id: counterparty_node_id,
							action: msgs::ErrorAction::SendErrorMessage {
								msg: msgs::ErrorMessage { channel_id: *channel_id, data: "Channel force-closed".to_owned() }
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
	pub fn force_close_broadcasting_latest_txn(&self, channel_id: &[u8; 32], counterparty_node_id: &PublicKey)
	-> Result<(), APIError> {
		self.force_close_sending_error(channel_id, counterparty_node_id, true)
	}

	/// Force closes a channel, rejecting new HTLCs on the given channel but skips broadcasting
	/// the latest local transaction(s). Fails if `channel_id` is unknown to the manager, or if the
	/// `counterparty_node_id` isn't the counterparty of the corresponding channel.
	///
	/// You can always get the latest local transaction(s) to broadcast from
	/// [`ChannelMonitor::get_latest_holder_commitment_txn`].
	pub fn force_close_without_broadcasting_txn(&self, channel_id: &[u8; 32], counterparty_node_id: &PublicKey)
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

	fn construct_recv_pending_htlc_info(&self, hop_data: msgs::OnionHopData, shared_secret: [u8; 32],
		payment_hash: PaymentHash, amt_msat: u64, cltv_expiry: u32, phantom_shared_secret: Option<[u8; 32]>) -> Result<PendingHTLCInfo, ReceiveError>
	{
		// final_incorrect_cltv_expiry
		if hop_data.outgoing_cltv_value != cltv_expiry {
			return Err(ReceiveError {
				msg: "Upstream node set CLTV to the wrong value",
				err_code: 18,
				err_data: cltv_expiry.to_be_bytes().to_vec()
			})
		}
		// final_expiry_too_soon
		// We have to have some headroom to broadcast on chain if we have the preimage, so make sure
		// we have at least HTLC_FAIL_BACK_BUFFER blocks to go.
		//
		// Also, ensure that, in the case of an unknown preimage for the received payment hash, our
		// payment logic has enough time to fail the HTLC backward before our onchain logic triggers a
		// channel closure (see HTLC_FAIL_BACK_BUFFER rationale).
		let current_height: u32 = self.best_block.read().unwrap().height();
		if (hop_data.outgoing_cltv_value as u64) <= current_height as u64 + HTLC_FAIL_BACK_BUFFER as u64 + 1 {
			let mut err_data = Vec::with_capacity(12);
			err_data.extend_from_slice(&amt_msat.to_be_bytes());
			err_data.extend_from_slice(&current_height.to_be_bytes());
			return Err(ReceiveError {
				err_code: 0x4000 | 15, err_data,
				msg: "The final CLTV expiry is too soon to handle",
			});
		}
		if hop_data.amt_to_forward > amt_msat {
			return Err(ReceiveError {
				err_code: 19,
				err_data: amt_msat.to_be_bytes().to_vec(),
				msg: "Upstream node sent less than we were supposed to receive in payment",
			});
		}

		let routing = match hop_data.format {
			msgs::OnionHopDataFormat::NonFinalNode { .. } => {
				return Err(ReceiveError {
					err_code: 0x4000|22,
					err_data: Vec::new(),
					msg: "Got non final data with an HMAC of 0",
				});
			},
			msgs::OnionHopDataFormat::FinalNode { payment_data, keysend_preimage } => {
				if payment_data.is_some() && keysend_preimage.is_some() {
					return Err(ReceiveError {
						err_code: 0x4000|22,
						err_data: Vec::new(),
						msg: "We don't support MPP keysend payments",
					});
				} else if let Some(data) = payment_data {
					PendingHTLCRouting::Receive {
						payment_data: data,
						incoming_cltv_expiry: hop_data.outgoing_cltv_value,
						phantom_shared_secret,
					}
				} else if let Some(payment_preimage) = keysend_preimage {
					// We need to check that the sender knows the keysend preimage before processing this
					// payment further. Otherwise, an intermediary routing hop forwarding non-keysend-HTLC X
					// could discover the final destination of X, by probing the adjacent nodes on the route
					// with a keysend payment of identical payment hash to X and observing the processing
					// time discrepancies due to a hash collision with X.
					let hashed_preimage = PaymentHash(Sha256::hash(&payment_preimage.0).into_inner());
					if hashed_preimage != payment_hash {
						return Err(ReceiveError {
							err_code: 0x4000|22,
							err_data: Vec::new(),
							msg: "Payment preimage didn't match payment hash",
						});
					}

					PendingHTLCRouting::ReceiveKeysend {
						payment_preimage,
						incoming_cltv_expiry: hop_data.outgoing_cltv_value,
					}
				} else {
					return Err(ReceiveError {
						err_code: 0x4000|0x2000|3,
						err_data: Vec::new(),
						msg: "We require payment_secrets",
					});
				}
			},
		};
		Ok(PendingHTLCInfo {
			routing,
			payment_hash,
			incoming_shared_secret: shared_secret,
			incoming_amt_msat: Some(amt_msat),
			outgoing_amt_msat: amt_msat,
			outgoing_cltv_value: hop_data.outgoing_cltv_value,
		})
	}

	fn decode_update_add_htlc_onion(&self, msg: &msgs::UpdateAddHTLC) -> PendingHTLCStatus {
		macro_rules! return_malformed_err {
			($msg: expr, $err_code: expr) => {
				{
					log_info!(self.logger, "Failed to accept/forward incoming HTLC: {}", $msg);
					return PendingHTLCStatus::Fail(HTLCFailureMsg::Malformed(msgs::UpdateFailMalformedHTLC {
						channel_id: msg.channel_id,
						htlc_id: msg.htlc_id,
						sha256_of_onion: Sha256::hash(&msg.onion_routing_packet.hop_data).into_inner(),
						failure_code: $err_code,
					}));
				}
			}
		}

		if let Err(_) = msg.onion_routing_packet.public_key {
			return_malformed_err!("invalid ephemeral pubkey", 0x8000 | 0x4000 | 6);
		}

		let shared_secret = self.node_signer.ecdh(
			Recipient::Node, &msg.onion_routing_packet.public_key.unwrap(), None
		).unwrap().secret_bytes();

		if msg.onion_routing_packet.version != 0 {
			//TODO: Spec doesn't indicate if we should only hash hop_data here (and in other
			//sha256_of_onion error data packets), or the entire onion_routing_packet. Either way,
			//the hash doesn't really serve any purpose - in the case of hashing all data, the
			//receiving node would have to brute force to figure out which version was put in the
			//packet by the node that send us the message, in the case of hashing the hop_data, the
			//node knows the HMAC matched, so they already know what is there...
			return_malformed_err!("Unknown onion packet version", 0x8000 | 0x4000 | 4);
		}
		macro_rules! return_err {
			($msg: expr, $err_code: expr, $data: expr) => {
				{
					log_info!(self.logger, "Failed to accept/forward incoming HTLC: {}", $msg);
					return PendingHTLCStatus::Fail(HTLCFailureMsg::Relay(msgs::UpdateFailHTLC {
						channel_id: msg.channel_id,
						htlc_id: msg.htlc_id,
						reason: HTLCFailReason::reason($err_code, $data.to_vec())
							.get_encrypted_failure_packet(&shared_secret, &None),
					}));
				}
			}
		}

		let next_hop = match onion_utils::decode_next_payment_hop(shared_secret, &msg.onion_routing_packet.hop_data[..], msg.onion_routing_packet.hmac, msg.payment_hash) {
			Ok(res) => res,
			Err(onion_utils::OnionDecodeErr::Malformed { err_msg, err_code }) => {
				return_malformed_err!(err_msg, err_code);
			},
			Err(onion_utils::OnionDecodeErr::Relay { err_msg, err_code }) => {
				return_err!(err_msg, err_code, &[0; 0]);
			},
		};

		let pending_forward_info = match next_hop {
			onion_utils::Hop::Receive(next_hop_data) => {
				// OUR PAYMENT!
				match self.construct_recv_pending_htlc_info(next_hop_data, shared_secret, msg.payment_hash, msg.amount_msat, msg.cltv_expiry, None) {
					Ok(info) => {
						// Note that we could obviously respond immediately with an update_fulfill_htlc
						// message, however that would leak that we are the recipient of this payment, so
						// instead we stay symmetric with the forwarding case, only responding (after a
						// delay) once they've send us a commitment_signed!
						PendingHTLCStatus::Forward(info)
					},
					Err(ReceiveError { err_code, err_data, msg }) => return_err!(msg, err_code, &err_data)
				}
			},
			onion_utils::Hop::Forward { next_hop_data, next_hop_hmac, new_packet_bytes } => {
				let new_pubkey = msg.onion_routing_packet.public_key.unwrap();
				let outgoing_packet = msgs::OnionPacket {
					version: 0,
					public_key: onion_utils::next_hop_packet_pubkey(&self.secp_ctx, new_pubkey, &shared_secret),
					hop_data: new_packet_bytes,
					hmac: next_hop_hmac.clone(),
				};

				let short_channel_id = match next_hop_data.format {
					msgs::OnionHopDataFormat::NonFinalNode { short_channel_id } => short_channel_id,
					msgs::OnionHopDataFormat::FinalNode { .. } => {
						return_err!("Final Node OnionHopData provided for us as an intermediary node", 0x4000 | 22, &[0;0]);
					},
				};

				PendingHTLCStatus::Forward(PendingHTLCInfo {
					routing: PendingHTLCRouting::Forward {
						onion_packet: outgoing_packet,
						short_channel_id,
					},
					payment_hash: msg.payment_hash.clone(),
					incoming_shared_secret: shared_secret,
					incoming_amt_msat: Some(msg.amount_msat),
					outgoing_amt_msat: next_hop_data.amt_to_forward,
					outgoing_cltv_value: next_hop_data.outgoing_cltv_value,
				})
			}
		};

		if let &PendingHTLCStatus::Forward(PendingHTLCInfo { ref routing, ref outgoing_amt_msat, ref outgoing_cltv_value, .. }) = &pending_forward_info {
			// If short_channel_id is 0 here, we'll reject the HTLC as there cannot be a channel
			// with a short_channel_id of 0. This is important as various things later assume
			// short_channel_id is non-0 in any ::Forward.
			if let &PendingHTLCRouting::Forward { ref short_channel_id, .. } = routing {
				if let Some((err, mut code, chan_update)) = loop {
					let id_option = self.short_to_chan_info.read().unwrap().get(short_channel_id).cloned();
					let forwarding_chan_info_opt = match id_option {
						None => { // unknown_next_peer
							// Note that this is likely a timing oracle for detecting whether an scid is a
							// phantom or an intercept.
							if (self.default_configuration.accept_intercept_htlcs &&
							   fake_scid::is_valid_intercept(&self.fake_scid_rand_bytes, *short_channel_id, &self.genesis_hash)) ||
							   fake_scid::is_valid_phantom(&self.fake_scid_rand_bytes, *short_channel_id, &self.genesis_hash)
							{
								None
							} else {
								break Some(("Don't have available channel for forwarding as requested.", 0x4000 | 10, None));
							}
						},
						Some((cp_id, id)) => Some((cp_id.clone(), id.clone())),
					};
					let chan_update_opt = if let Some((counterparty_node_id, forwarding_id)) = forwarding_chan_info_opt {
						let per_peer_state = self.per_peer_state.read().unwrap();
						let peer_state_mutex_opt = per_peer_state.get(&counterparty_node_id);
						if peer_state_mutex_opt.is_none() {
							break Some(("Don't have available channel for forwarding as requested.", 0x4000 | 10, None));
						}
						let mut peer_state_lock = peer_state_mutex_opt.unwrap().lock().unwrap();
						let peer_state = &mut *peer_state_lock;
						let chan = match peer_state.channel_by_id.get_mut(&forwarding_id) {
							None => {
								// Channel was removed. The short_to_chan_info and channel_by_id maps
								// have no consistency guarantees.
								break Some(("Don't have available channel for forwarding as requested.", 0x4000 | 10, None));
							},
							Some(chan) => chan
						};
						if !chan.should_announce() && !self.default_configuration.accept_forwards_to_priv_channels {
							// Note that the behavior here should be identical to the above block - we
							// should NOT reveal the existence or non-existence of a private channel if
							// we don't allow forwards outbound over them.
							break Some(("Refusing to forward to a private channel based on our config.", 0x4000 | 10, None));
						}
						if chan.get_channel_type().supports_scid_privacy() && *short_channel_id != chan.outbound_scid_alias() {
							// `option_scid_alias` (referred to in LDK as `scid_privacy`) means
							// "refuse to forward unless the SCID alias was used", so we pretend
							// we don't have the channel here.
							break Some(("Refusing to forward over real channel SCID as our counterparty requested.", 0x4000 | 10, None));
						}
						let chan_update_opt = self.get_channel_update_for_onion(*short_channel_id, chan).ok();

						// Note that we could technically not return an error yet here and just hope
						// that the connection is reestablished or monitor updated by the time we get
						// around to doing the actual forward, but better to fail early if we can and
						// hopefully an attacker trying to path-trace payments cannot make this occur
						// on a small/per-node/per-channel scale.
						if !chan.is_live() { // channel_disabled
							break Some(("Forwarding channel is not in a ready state.", 0x1000 | 20, chan_update_opt));
						}
						if *outgoing_amt_msat < chan.get_counterparty_htlc_minimum_msat() { // amount_below_minimum
							break Some(("HTLC amount was below the htlc_minimum_msat", 0x1000 | 11, chan_update_opt));
						}
						if let Err((err, code)) = chan.htlc_satisfies_config(&msg, *outgoing_amt_msat, *outgoing_cltv_value) {
							break Some((err, code, chan_update_opt));
						}
						chan_update_opt
					} else {
						if (msg.cltv_expiry as u64) < (*outgoing_cltv_value) as u64 + MIN_CLTV_EXPIRY_DELTA as u64 {
							// We really should set `incorrect_cltv_expiry` here but as we're not
							// forwarding over a real channel we can't generate a channel_update
							// for it. Instead we just return a generic temporary_node_failure.
							break Some((
								"Forwarding node has tampered with the intended HTLC values or origin node has an obsolete cltv_expiry_delta",
								0x2000 | 2, None,
							));
						}
						None
					};

					let cur_height = self.best_block.read().unwrap().height() + 1;
					// Theoretically, channel counterparty shouldn't send us a HTLC expiring now,
					// but we want to be robust wrt to counterparty packet sanitization (see
					// HTLC_FAIL_BACK_BUFFER rationale).
					if msg.cltv_expiry <= cur_height + HTLC_FAIL_BACK_BUFFER as u32 { // expiry_too_soon
						break Some(("CLTV expiry is too close", 0x1000 | 14, chan_update_opt));
					}
					if msg.cltv_expiry > cur_height + CLTV_FAR_FAR_AWAY as u32 { // expiry_too_far
						break Some(("CLTV expiry is too far in the future", 21, None));
					}
					// If the HTLC expires ~now, don't bother trying to forward it to our
					// counterparty. They should fail it anyway, but we don't want to bother with
					// the round-trips or risk them deciding they definitely want the HTLC and
					// force-closing to ensure they get it if we're offline.
					// We previously had a much more aggressive check here which tried to ensure
					// our counterparty receives an HTLC which has *our* risk threshold met on it,
					// but there is no need to do that, and since we're a bit conservative with our
					// risk threshold it just results in failing to forward payments.
					if (*outgoing_cltv_value) as u64 <= (cur_height + LATENCY_GRACE_PERIOD_BLOCKS) as u64 {
						break Some(("Outgoing CLTV value is too soon", 0x1000 | 14, chan_update_opt));
					}

					break None;
				}
				{
					let mut res = VecWriter(Vec::with_capacity(chan_update.serialized_length() + 2 + 8 + 2));
					if let Some(chan_update) = chan_update {
						if code == 0x1000 | 11 || code == 0x1000 | 12 {
							msg.amount_msat.write(&mut res).expect("Writes cannot fail");
						}
						else if code == 0x1000 | 13 {
							msg.cltv_expiry.write(&mut res).expect("Writes cannot fail");
						}
						else if code == 0x1000 | 20 {
							// TODO: underspecified, follow https://github.com/lightning/bolts/issues/791
							0u16.write(&mut res).expect("Writes cannot fail");
						}
						(chan_update.serialized_length() as u16 + 2).write(&mut res).expect("Writes cannot fail");
						msgs::ChannelUpdate::TYPE.write(&mut res).expect("Writes cannot fail");
						chan_update.write(&mut res).expect("Writes cannot fail");
					} else if code & 0x1000 == 0x1000 {
						// If we're trying to return an error that requires a `channel_update` but
						// we're forwarding to a phantom or intercept "channel" (i.e. cannot
						// generate an update), just use the generic "temporary_node_failure"
						// instead.
						code = 0x2000 | 2;
					}
					return_err!(err, code, &res.0[..]);
				}
			}
		}

		pending_forward_info
	}

	/// Gets the current channel_update for the given channel. This first checks if the channel is
	/// public, and thus should be called whenever the result is going to be passed out in a
	/// [`MessageSendEvent::BroadcastChannelUpdate`] event.
	///
	/// Note that in `internal_closing_signed`, this function is called without the `peer_state`
	/// corresponding to the channel's counterparty locked, as the channel been removed from the
	/// storage and the `peer_state` lock has been dropped.
	fn get_channel_update_for_broadcast(&self, chan: &Channel<<SP::Target as SignerProvider>::Signer>) -> Result<msgs::ChannelUpdate, LightningError> {
		if !chan.should_announce() {
			return Err(LightningError {
				err: "Cannot broadcast a channel_update for a private channel".to_owned(),
				action: msgs::ErrorAction::IgnoreError
			});
		}
		if chan.get_short_channel_id().is_none() {
			return Err(LightningError{err: "Channel not yet established".to_owned(), action: msgs::ErrorAction::IgnoreError});
		}
		log_trace!(self.logger, "Attempting to generate broadcast channel update for channel {}", log_bytes!(chan.channel_id()));
		self.get_channel_update_for_unicast(chan)
	}

	/// Gets the current channel_update for the given channel. This does not check if the channel
	/// is public (only returning an Err if the channel does not yet have an assigned short_id),
	/// and thus MUST NOT be called unless the recipient of the resulting message has already
	/// provided evidence that they know about the existence of the channel.
	///
	/// Note that through `internal_closing_signed`, this function is called without the
	/// `peer_state`  corresponding to the channel's counterparty locked, as the channel been
	/// removed from the storage and the `peer_state` lock has been dropped.
	fn get_channel_update_for_unicast(&self, chan: &Channel<<SP::Target as SignerProvider>::Signer>) -> Result<msgs::ChannelUpdate, LightningError> {
		log_trace!(self.logger, "Attempting to generate channel update for channel {}", log_bytes!(chan.channel_id()));
		let short_channel_id = match chan.get_short_channel_id().or(chan.latest_inbound_scid_alias()) {
			None => return Err(LightningError{err: "Channel not yet established".to_owned(), action: msgs::ErrorAction::IgnoreError}),
			Some(id) => id,
		};

		self.get_channel_update_for_onion(short_channel_id, chan)
	}
	fn get_channel_update_for_onion(&self, short_channel_id: u64, chan: &Channel<<SP::Target as SignerProvider>::Signer>) -> Result<msgs::ChannelUpdate, LightningError> {
		log_trace!(self.logger, "Generating channel update for channel {}", log_bytes!(chan.channel_id()));
		let were_node_one = self.our_network_pubkey.serialize()[..] < chan.get_counterparty_node_id().serialize()[..];

		let unsigned = msgs::UnsignedChannelUpdate {
			chain_hash: self.genesis_hash,
			short_channel_id,
			timestamp: chan.get_update_time_counter(),
			flags: (!were_node_one) as u8 | ((!chan.is_live() as u8) << 1),
			cltv_expiry_delta: chan.get_cltv_expiry_delta(),
			htlc_minimum_msat: chan.get_counterparty_htlc_minimum_msat(),
			htlc_maximum_msat: chan.get_announced_htlc_max_msat(),
			fee_base_msat: chan.get_outbound_forwarding_fee_base_msat(),
			fee_proportional_millionths: chan.get_fee_proportional_millionths(),
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
	pub(crate) fn test_send_payment_along_path(&self, path: &Vec<RouteHop>, payment_params: &Option<PaymentParameters>, payment_hash: &PaymentHash, payment_secret: &Option<PaymentSecret>, total_value: u64, cur_height: u32, payment_id: PaymentId, keysend_preimage: &Option<PaymentPreimage>, session_priv_bytes: [u8; 32]) -> Result<(), APIError> {
		let _lck = self.total_consistency_lock.read().unwrap();
		self.send_payment_along_path(path, payment_params, payment_hash, payment_secret, total_value, cur_height, payment_id, keysend_preimage, session_priv_bytes)
	}

	fn send_payment_along_path(&self, path: &Vec<RouteHop>, payment_params: &Option<PaymentParameters>, payment_hash: &PaymentHash, payment_secret: &Option<PaymentSecret>, total_value: u64, cur_height: u32, payment_id: PaymentId, keysend_preimage: &Option<PaymentPreimage>, session_priv_bytes: [u8; 32]) -> Result<(), APIError> {
		// The top-level caller should hold the total_consistency_lock read lock.
		debug_assert!(self.total_consistency_lock.try_write().is_err());

		log_trace!(self.logger, "Attempting to send payment for path with next hop {}", path.first().unwrap().short_channel_id);
		let prng_seed = self.entropy_source.get_secure_random_bytes();
		let session_priv = SecretKey::from_slice(&session_priv_bytes[..]).expect("RNG is busted");

		let onion_keys = onion_utils::construct_onion_keys(&self.secp_ctx, &path, &session_priv)
			.map_err(|_| APIError::InvalidRoute{err: "Pubkey along hop was maliciously selected".to_owned()})?;
		let (onion_payloads, htlc_msat, htlc_cltv) = onion_utils::build_onion_payloads(path, total_value, payment_secret, cur_height, keysend_preimage)?;
		if onion_utils::route_size_insane(&onion_payloads) {
			return Err(APIError::InvalidRoute{err: "Route size too large considering onion data".to_owned()});
		}
		let onion_packet = onion_utils::construct_onion_packet(onion_payloads, onion_keys, prng_seed, payment_hash);

		let err: Result<(), _> = loop {
			let (counterparty_node_id, id) = match self.short_to_chan_info.read().unwrap().get(&path.first().unwrap().short_channel_id) {
				None => return Err(APIError::ChannelUnavailable{err: "No channel available with first hop!".to_owned()}),
				Some((cp_id, chan_id)) => (cp_id.clone(), chan_id.clone()),
			};

			let per_peer_state = self.per_peer_state.read().unwrap();
			let peer_state_mutex = per_peer_state.get(&counterparty_node_id)
				.ok_or_else(|| APIError::ChannelUnavailable{err: "No peer matching the path's first hop found!".to_owned() })?;
			let mut peer_state_lock = peer_state_mutex.lock().unwrap();
			let peer_state = &mut *peer_state_lock;
			if let hash_map::Entry::Occupied(mut chan) = peer_state.channel_by_id.entry(id) {
				if !chan.get().is_live() {
					return Err(APIError::ChannelUnavailable{err: "Peer for first hop currently disconnected".to_owned()});
				}
				let funding_txo = chan.get().get_funding_txo().unwrap();
				let send_res = chan.get_mut().send_htlc_and_commit(htlc_msat, payment_hash.clone(),
					htlc_cltv, HTLCSource::OutboundRoute {
						path: path.clone(),
						session_priv: session_priv.clone(),
						first_hop_htlc_msat: htlc_msat,
						payment_id,
						payment_secret: payment_secret.clone(),
						payment_params: payment_params.clone(),
					}, onion_packet, &self.logger);
				match break_chan_entry!(self, send_res, chan) {
					Some(monitor_update) => {
						let update_id = monitor_update.update_id;
						let update_res = self.chain_monitor.update_channel(funding_txo, monitor_update);
						if let Err(e) = handle_new_monitor_update!(self, update_res, update_id, peer_state_lock, peer_state, per_peer_state, chan) {
							break Err(e);
						}
						if update_res == ChannelMonitorUpdateStatus::InProgress {
							// Note that MonitorUpdateInProgress here indicates (per function
							// docs) that we will resend the commitment update once monitor
							// updating completes. Therefore, we must return an error
							// indicating that it is unsafe to retry the payment wholesale,
							// which we do in the send_payment check for
							// MonitorUpdateInProgress, below.
							return Err(APIError::MonitorUpdateInProgress);
						}
					},
					None => { },
				}
			} else {
				// The channel was likely removed after we fetched the id from the
				// `short_to_chan_info` map, but before we successfully locked the
				// `channel_by_id` map.
				// This can occur as no consistency guarantees exists between the two maps.
				return Err(APIError::ChannelUnavailable{err: "No channel available with first hop!".to_owned()});
			}
			return Ok(());
		};

		match handle_error!(self, err, path.first().unwrap().pubkey) {
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
	/// May generate SendHTLCs message(s) event on success, which should be relayed (e.g. via
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
	/// Each path may have a different return value, and PaymentSendValue may return a Vec with
	/// each entry matching the corresponding-index entry in the route paths, see
	/// [`PaymentSendFailure`] for more info.
	///
	/// In general, a path may raise:
	///  * [`APIError::InvalidRoute`] when an invalid route or forwarding parameter (cltv_delta, fee,
	///    node public key) is specified.
	///  * [`APIError::ChannelUnavailable`] if the next-hop channel is not available for updates
	///    (including due to previous monitor update failure or new permanent monitor update
	///    failure).
	///  * [`APIError::MonitorUpdateInProgress`] if a new monitor update failure prevented sending the
	///    relevant updates.
	///
	/// Note that depending on the type of the PaymentSendFailure the HTLC may have been
	/// irrevocably committed to on our end. In such a case, do NOT retry the payment with a
	/// different route unless you intend to pay twice!
	///
	/// # A caution on `payment_secret`
	///
	/// `payment_secret` is unrelated to `payment_hash` (or [`PaymentPreimage`]) and exists to
	/// authenticate the sender to the recipient and prevent payment-probing (deanonymization)
	/// attacks. For newer nodes, it will be provided to you in the invoice. If you do not have one,
	/// the [`Route`] must not contain multiple paths as multi-path payments require a
	/// recipient-provided `payment_secret`.
	///
	/// If a `payment_secret` *is* provided, we assume that the invoice had the payment_secret
	/// feature bit set (either as required or as available). If multiple paths are present in the
	/// [`Route`], we assume the invoice had the basic_mpp feature set.
	///
	/// [`Event::PaymentSent`]: events::Event::PaymentSent
	/// [`Event::PaymentFailed`]: events::Event::PaymentFailed
	/// [`PeerManager::process_events`]: crate::ln::peer_handler::PeerManager::process_events
	/// [`ChannelMonitorUpdateStatus::InProgress`]: crate::chain::ChannelMonitorUpdateStatus::InProgress
	pub fn send_payment(&self, route: &Route, payment_hash: PaymentHash, payment_secret: &Option<PaymentSecret>, payment_id: PaymentId) -> Result<(), PaymentSendFailure> {
		let best_block_height = self.best_block.read().unwrap().height();
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(&self.total_consistency_lock, &self.persistence_notifier);
		self.pending_outbound_payments
			.send_payment_with_route(route, payment_hash, payment_secret, payment_id, &self.entropy_source, &self.node_signer, best_block_height,
				|path, payment_params, payment_hash, payment_secret, total_value, cur_height, payment_id, keysend_preimage, session_priv|
				self.send_payment_along_path(path, payment_params, payment_hash, payment_secret, total_value, cur_height, payment_id, keysend_preimage, session_priv))
	}

	/// Similar to [`ChannelManager::send_payment`], but will automatically find a route based on
	/// `route_params` and retry failed payment paths based on `retry_strategy`.
	pub fn send_payment_with_retry(&self, payment_hash: PaymentHash, payment_secret: &Option<PaymentSecret>, payment_id: PaymentId, route_params: RouteParameters, retry_strategy: Retry) -> Result<(), RetryableSendFailure> {
		let best_block_height = self.best_block.read().unwrap().height();
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(&self.total_consistency_lock, &self.persistence_notifier);
		self.pending_outbound_payments
			.send_payment(payment_hash, payment_secret, payment_id, retry_strategy, route_params,
				&self.router, self.list_usable_channels(), || self.compute_inflight_htlcs(),
				&self.entropy_source, &self.node_signer, best_block_height, &self.logger,
				&self.pending_events,
				|path, payment_params, payment_hash, payment_secret, total_value, cur_height, payment_id, keysend_preimage, session_priv|
				self.send_payment_along_path(path, payment_params, payment_hash, payment_secret, total_value, cur_height, payment_id, keysend_preimage, session_priv))
	}

	#[cfg(test)]
	fn test_send_payment_internal(&self, route: &Route, payment_hash: PaymentHash, payment_secret: &Option<PaymentSecret>, keysend_preimage: Option<PaymentPreimage>, payment_id: PaymentId, recv_value_msat: Option<u64>, onion_session_privs: Vec<[u8; 32]>) -> Result<(), PaymentSendFailure> {
		let best_block_height = self.best_block.read().unwrap().height();
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(&self.total_consistency_lock, &self.persistence_notifier);
		self.pending_outbound_payments.test_send_payment_internal(route, payment_hash, payment_secret, keysend_preimage, payment_id, recv_value_msat, onion_session_privs, &self.node_signer, best_block_height,
			|path, payment_params, payment_hash, payment_secret, total_value, cur_height, payment_id, keysend_preimage, session_priv|
			self.send_payment_along_path(path, payment_params, payment_hash, payment_secret, total_value, cur_height, payment_id, keysend_preimage, session_priv))
	}

	#[cfg(test)]
	pub(crate) fn test_add_new_pending_payment(&self, payment_hash: PaymentHash, payment_secret: Option<PaymentSecret>, payment_id: PaymentId, route: &Route) -> Result<Vec<[u8; 32]>, PaymentSendFailure> {
		let best_block_height = self.best_block.read().unwrap().height();
		self.pending_outbound_payments.test_add_new_pending_payment(payment_hash, payment_secret, payment_id, route, None, &self.entropy_source, best_block_height)
	}


	/// Signals that no further retries for the given payment should occur. Useful if you have a
	/// pending outbound payment with retries remaining, but wish to stop retrying the payment before
	/// retries are exhausted.
	///
	/// If no [`Event::PaymentFailed`] event had been generated before, one will be generated as soon
	/// as there are no remaining pending HTLCs for this payment.
	///
	/// Note that calling this method does *not* prevent a payment from succeeding. You must still
	/// wait until you receive either a [`Event::PaymentFailed`] or [`Event::PaymentSent`] event to
	/// determine the ultimate status of a payment.
	///
	/// If an [`Event::PaymentFailed`] event is generated and we restart without this
	/// [`ChannelManager`] having been persisted, another [`Event::PaymentFailed`] may be generated.
	///
	/// [`Event::PaymentFailed`]: events::Event::PaymentFailed
	/// [`Event::PaymentSent`]: events::Event::PaymentSent
	pub fn abandon_payment(&self, payment_id: PaymentId) {
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(&self.total_consistency_lock, &self.persistence_notifier);
		self.pending_outbound_payments.abandon_payment(payment_id, &self.pending_events);
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
	/// Note that `route` must have exactly one path.
	///
	/// [`send_payment`]: Self::send_payment
	pub fn send_spontaneous_payment(&self, route: &Route, payment_preimage: Option<PaymentPreimage>, payment_id: PaymentId) -> Result<PaymentHash, PaymentSendFailure> {
		let best_block_height = self.best_block.read().unwrap().height();
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(&self.total_consistency_lock, &self.persistence_notifier);
		self.pending_outbound_payments.send_spontaneous_payment_with_route(
			route, payment_preimage, payment_id, &self.entropy_source, &self.node_signer,
			best_block_height,
			|path, payment_params, payment_hash, payment_secret, total_value, cur_height, payment_id, keysend_preimage, session_priv|
			self.send_payment_along_path(path, payment_params, payment_hash, payment_secret, total_value, cur_height, payment_id, keysend_preimage, session_priv))
	}

	/// Similar to [`ChannelManager::send_spontaneous_payment`], but will automatically find a route
	/// based on `route_params` and retry failed payment paths based on `retry_strategy`.
	///
	/// See [`PaymentParameters::for_keysend`] for help in constructing `route_params` for spontaneous
	/// payments.
	///
	/// [`PaymentParameters::for_keysend`]: crate::routing::router::PaymentParameters::for_keysend
	pub fn send_spontaneous_payment_with_retry(&self, payment_preimage: Option<PaymentPreimage>, payment_id: PaymentId, route_params: RouteParameters, retry_strategy: Retry) -> Result<PaymentHash, RetryableSendFailure> {
		let best_block_height = self.best_block.read().unwrap().height();
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(&self.total_consistency_lock, &self.persistence_notifier);
		self.pending_outbound_payments.send_spontaneous_payment(payment_preimage, payment_id,
			retry_strategy, route_params, &self.router, self.list_usable_channels(),
			|| self.compute_inflight_htlcs(),  &self.entropy_source, &self.node_signer, best_block_height,
			&self.logger, &self.pending_events,
			|path, payment_params, payment_hash, payment_secret, total_value, cur_height, payment_id, keysend_preimage, session_priv|
			self.send_payment_along_path(path, payment_params, payment_hash, payment_secret, total_value, cur_height, payment_id, keysend_preimage, session_priv))
	}

	/// Send a payment that is probing the given route for liquidity. We calculate the
	/// [`PaymentHash`] of probes based on a static secret and a random [`PaymentId`], which allows
	/// us to easily discern them from real payments.
	pub fn send_probe(&self, hops: Vec<RouteHop>) -> Result<(PaymentHash, PaymentId), PaymentSendFailure> {
		let best_block_height = self.best_block.read().unwrap().height();
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(&self.total_consistency_lock, &self.persistence_notifier);
		self.pending_outbound_payments.send_probe(hops, self.probing_cookie_secret, &self.entropy_source, &self.node_signer, best_block_height,
			|path, payment_params, payment_hash, payment_secret, total_value, cur_height, payment_id, keysend_preimage, session_priv|
			self.send_payment_along_path(path, payment_params, payment_hash, payment_secret, total_value, cur_height, payment_id, keysend_preimage, session_priv))
	}

	/// Returns whether a payment with the given [`PaymentHash`] and [`PaymentId`] is, in fact, a
	/// payment probe.
	#[cfg(test)]
	pub(crate) fn payment_is_probe(&self, payment_hash: &PaymentHash, payment_id: &PaymentId) -> bool {
		outbound_payment::payment_is_probe(payment_hash, payment_id, self.probing_cookie_secret)
	}

	/// Handles the generation of a funding transaction, optionally (for tests) with a function
	/// which checks the correctness of the funding transaction given the associated channel.
	fn funding_transaction_generated_intern<FundingOutput: Fn(&Channel<<SP::Target as SignerProvider>::Signer>, &Transaction) -> Result<OutPoint, APIError>>(
		&self, temporary_channel_id: &[u8; 32], counterparty_node_id: &PublicKey, funding_transaction: Transaction, find_funding_output: FundingOutput
	) -> Result<(), APIError> {
		let per_peer_state = self.per_peer_state.read().unwrap();
		let peer_state_mutex = per_peer_state.get(counterparty_node_id)
			.ok_or_else(|| APIError::ChannelUnavailable { err: format!("Can't find a peer matching the passed counterparty node_id {}", counterparty_node_id) })?;

		let mut peer_state_lock = peer_state_mutex.lock().unwrap();
		let peer_state = &mut *peer_state_lock;
		let (chan, msg) = {
			let (res, chan) = {
				match peer_state.channel_by_id.remove(temporary_channel_id) {
					Some(mut chan) => {
						let funding_txo = find_funding_output(&chan, &funding_transaction)?;

						(chan.get_outbound_funding_created(funding_transaction, funding_txo, &self.logger)
							.map_err(|e| if let ChannelError::Close(msg) = e {
								MsgHandleErrInternal::from_finish_shutdown(msg, chan.channel_id(), chan.get_user_id(), chan.force_shutdown(true), None)
							} else { unreachable!(); })
						, chan)
					},
					None => { return Err(APIError::ChannelUnavailable { err: format!("Channel with id {} not found for the passed counterparty node_id {}", log_bytes!(*temporary_channel_id), counterparty_node_id) }) },
				}
			};
			match handle_error!(self, res, chan.get_counterparty_node_id()) {
				Ok(funding_msg) => {
					(chan, funding_msg)
				},
				Err(_) => { return Err(APIError::ChannelUnavailable {
					err: "Signer refused to sign the initial commitment transaction".to_owned()
				}) },
			}
		};

		peer_state.pending_msg_events.push(events::MessageSendEvent::SendFundingCreated {
			node_id: chan.get_counterparty_node_id(),
			msg,
		});
		match peer_state.channel_by_id.entry(chan.channel_id()) {
			hash_map::Entry::Occupied(_) => {
				panic!("Generated duplicate funding txid?");
			},
			hash_map::Entry::Vacant(e) => {
				let mut id_to_peer = self.id_to_peer.lock().unwrap();
				if id_to_peer.insert(chan.channel_id(), chan.get_counterparty_node_id()).is_some() {
					panic!("id_to_peer map already contained funding txid, which shouldn't be possible");
				}
				e.insert(chan);
			}
		}
		Ok(())
	}

	#[cfg(test)]
	pub(crate) fn funding_transaction_generated_unchecked(&self, temporary_channel_id: &[u8; 32], counterparty_node_id: &PublicKey, funding_transaction: Transaction, output_index: u16) -> Result<(), APIError> {
		self.funding_transaction_generated_intern(temporary_channel_id, counterparty_node_id, funding_transaction, |_, tx| {
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
	/// [`Event::FundingGenerationReady`]: crate::util::events::Event::FundingGenerationReady
	/// [`Event::ChannelClosed`]: crate::util::events::Event::ChannelClosed
	pub fn funding_transaction_generated(&self, temporary_channel_id: &[u8; 32], counterparty_node_id: &PublicKey, funding_transaction: Transaction) -> Result<(), APIError> {
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(&self.total_consistency_lock, &self.persistence_notifier);

		for inp in funding_transaction.input.iter() {
			if inp.witness.is_empty() {
				return Err(APIError::APIMisuseError {
					err: "Funding transaction must be fully signed and spend Segwit outputs".to_owned()
				});
			}
		}
		{
			let height = self.best_block.read().unwrap().height();
			// Transactions are evaluated as final by network mempools at the next block. However, the modules
			// constituting our Lightning node might not have perfect sync about their blockchain views. Thus, if
			// the wallet module is in advance on the LDK view, allow one more block of headroom.
			if !funding_transaction.input.iter().all(|input| input.sequence == Sequence::MAX) && LockTime::from(funding_transaction.lock_time).is_block_height() && funding_transaction.lock_time.0 > height + 2 {
				return Err(APIError::APIMisuseError {
					err: "Funding transaction absolute timelock is non-final".to_owned()
				});
			}
		}
		self.funding_transaction_generated_intern(temporary_channel_id, counterparty_node_id, funding_transaction, |chan, tx| {
			let mut output_index = None;
			let expected_spk = chan.get_funding_redeemscript().to_v0_p2wsh();
			for (idx, outp) in tx.output.iter().enumerate() {
				if outp.script_pubkey == expected_spk && outp.value == chan.get_value_satoshis() {
					if output_index.is_some() {
						return Err(APIError::APIMisuseError {
							err: "Multiple outputs matched the expected script and value".to_owned()
						});
					}
					if idx > u16::max_value() as usize {
						return Err(APIError::APIMisuseError {
							err: "Transaction had more than 2^16 outputs, which is not supported".to_owned()
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
			Ok(OutPoint { txid: tx.txid(), index: output_index.unwrap() })
		})
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
		&self, counterparty_node_id: &PublicKey, channel_ids: &[[u8; 32]], config: &ChannelConfig,
	) -> Result<(), APIError> {
		if config.cltv_expiry_delta < MIN_CLTV_EXPIRY_DELTA {
			return Err(APIError::APIMisuseError {
				err: format!("The chosen CLTV expiry delta is below the minimum of {}", MIN_CLTV_EXPIRY_DELTA),
			});
		}

		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(
			&self.total_consistency_lock, &self.persistence_notifier,
		);
		let per_peer_state = self.per_peer_state.read().unwrap();
		let peer_state_mutex = per_peer_state.get(counterparty_node_id)
			.ok_or_else(|| APIError::ChannelUnavailable { err: format!("Can't find a peer matching the passed counterparty node_id {}", counterparty_node_id) })?;
		let mut peer_state_lock = peer_state_mutex.lock().unwrap();
		let peer_state = &mut *peer_state_lock;
		for channel_id in channel_ids {
			if !peer_state.channel_by_id.contains_key(channel_id) {
				return Err(APIError::ChannelUnavailable {
					err: format!("Channel with ID {} was not found for the passed counterparty_node_id {}", log_bytes!(*channel_id), counterparty_node_id),
				});
			}
		}
		for channel_id in channel_ids {
			let channel = peer_state.channel_by_id.get_mut(channel_id).unwrap();
			if !channel.update_config(config) {
				continue;
			}
			if let Ok(msg) = self.get_channel_update_for_broadcast(channel) {
				peer_state.pending_msg_events.push(events::MessageSendEvent::BroadcastChannelUpdate { msg });
			} else if let Ok(msg) = self.get_channel_update_for_unicast(channel) {
				peer_state.pending_msg_events.push(events::MessageSendEvent::SendChannelUpdate {
					node_id: channel.get_counterparty_node_id(),
					msg,
				});
			}
		}
		Ok(())
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
	/// you from forwarding more than you received.
	///
	/// Errors if the event was not handled in time, in which case the HTLC was automatically failed
	/// backwards.
	///
	/// [`UserConfig::accept_intercept_htlcs`]: crate::util::config::UserConfig::accept_intercept_htlcs
	/// [`HTLCIntercepted`]: events::Event::HTLCIntercepted
	// TODO: when we move to deciding the best outbound channel at forward time, only take
	// `next_node_id` and not `next_hop_channel_id`
	pub fn forward_intercepted_htlc(&self, intercept_id: InterceptId, next_hop_channel_id: &[u8; 32], next_node_id: PublicKey, amt_to_forward_msat: u64) -> Result<(), APIError> {
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(&self.total_consistency_lock, &self.persistence_notifier);

		let next_hop_scid = {
			let peer_state_lock = self.per_peer_state.read().unwrap();
			let peer_state_mutex = peer_state_lock.get(&next_node_id)
				.ok_or_else(|| APIError::ChannelUnavailable { err: format!("Can't find a peer matching the passed counterparty node_id {}", next_node_id) })?;
			let mut peer_state_lock = peer_state_mutex.lock().unwrap();
			let peer_state = &mut *peer_state_lock;
			match peer_state.channel_by_id.get(next_hop_channel_id) {
				Some(chan) => {
					if !chan.is_usable() {
						return Err(APIError::ChannelUnavailable {
							err: format!("Channel with id {} not fully established", log_bytes!(*next_hop_channel_id))
						})
					}
					chan.get_short_channel_id().unwrap_or(chan.outbound_scid_alias())
				},
				None => return Err(APIError::ChannelUnavailable {
					err: format!("Channel with id {} not found for the passed counterparty node_id {}", log_bytes!(*next_hop_channel_id), next_node_id)
				})
			}
		};

		let payment = self.pending_intercepted_htlcs.lock().unwrap().remove(&intercept_id)
			.ok_or_else(|| APIError::APIMisuseError {
				err: format!("Payment with intercept id {} not found", log_bytes!(intercept_id.0))
			})?;

		let routing = match payment.forward_info.routing {
			PendingHTLCRouting::Forward { onion_packet, .. } => {
				PendingHTLCRouting::Forward { onion_packet, short_channel_id: next_hop_scid }
			},
			_ => unreachable!() // Only `PendingHTLCRouting::Forward`s are intercepted
		};
		let pending_htlc_info = PendingHTLCInfo {
			outgoing_amt_msat: amt_to_forward_msat, routing, ..payment.forward_info
		};

		let mut per_source_pending_forward = [(
			payment.prev_short_channel_id,
			payment.prev_funding_outpoint,
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
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(&self.total_consistency_lock, &self.persistence_notifier);

		let payment = self.pending_intercepted_htlcs.lock().unwrap().remove(&intercept_id)
			.ok_or_else(|| APIError::APIMisuseError {
				err: format!("Payment with intercept id {} not found", log_bytes!(intercept_id.0))
			})?;

		if let PendingHTLCRouting::Forward { short_channel_id, .. } = payment.forward_info.routing {
			let htlc_source = HTLCSource::PreviousHopData(HTLCPreviousHopData {
				short_channel_id: payment.prev_short_channel_id,
				outpoint: payment.prev_funding_outpoint,
				htlc_id: payment.prev_htlc_id,
				incoming_packet_shared_secret: payment.forward_info.incoming_shared_secret,
				phantom_shared_secret: None,
			});

			let failure_reason = HTLCFailReason::from_failure_code(0x4000 | 10);
			let destination = HTLCDestination::UnknownNextHop { requested_forward_scid: short_channel_id };
			self.fail_htlc_backwards_internal(&htlc_source, &payment.forward_info.payment_hash, &failure_reason, destination);
		} else { unreachable!() } // Only `PendingHTLCRouting::Forward`s are intercepted

		Ok(())
	}

	/// Processes HTLCs which are pending waiting on random forward delay.
	///
	/// Should only really ever be called in response to a PendingHTLCsForwardable event.
	/// Will likely generate further events.
	pub fn process_pending_htlc_forwards(&self) {
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(&self.total_consistency_lock, &self.persistence_notifier);

		let mut new_events = Vec::new();
		let mut failed_forwards = Vec::new();
		let mut phantom_receives: Vec<(u64, OutPoint, u128, Vec<(PendingHTLCInfo, u64)>)> = Vec::new();
		{
			let mut forward_htlcs = HashMap::new();
			mem::swap(&mut forward_htlcs, &mut self.forward_htlcs.lock().unwrap());

			for (short_chan_id, mut pending_forwards) in forward_htlcs {
				if short_chan_id != 0 {
					macro_rules! forwarding_channel_not_found {
						() => {
							for forward_info in pending_forwards.drain(..) {
								match forward_info {
									HTLCForwardInfo::AddHTLC(PendingAddHTLCInfo {
										prev_short_channel_id, prev_htlc_id, prev_funding_outpoint, prev_user_channel_id,
										forward_info: PendingHTLCInfo {
											routing, incoming_shared_secret, payment_hash, outgoing_amt_msat,
											outgoing_cltv_value, incoming_amt_msat: _
										}
									}) => {
										macro_rules! failure_handler {
											($msg: expr, $err_code: expr, $err_data: expr, $phantom_ss: expr, $next_hop_unknown: expr) => {
												log_info!(self.logger, "Failed to accept/forward incoming HTLC: {}", $msg);

												let htlc_source = HTLCSource::PreviousHopData(HTLCPreviousHopData {
													short_channel_id: prev_short_channel_id,
													outpoint: prev_funding_outpoint,
													htlc_id: prev_htlc_id,
													incoming_packet_shared_secret: incoming_shared_secret,
													phantom_shared_secret: $phantom_ss,
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
										if let PendingHTLCRouting::Forward { onion_packet, .. } = routing {
											let phantom_pubkey_res = self.node_signer.get_node_id(Recipient::PhantomNode);
											if phantom_pubkey_res.is_ok() && fake_scid::is_valid_phantom(&self.fake_scid_rand_bytes, short_chan_id, &self.genesis_hash) {
												let phantom_shared_secret = self.node_signer.ecdh(Recipient::PhantomNode, &onion_packet.public_key.unwrap(), None).unwrap().secret_bytes();
												let next_hop = match onion_utils::decode_next_payment_hop(phantom_shared_secret, &onion_packet.hop_data, onion_packet.hmac, payment_hash) {
													Ok(res) => res,
													Err(onion_utils::OnionDecodeErr::Malformed { err_msg, err_code }) => {
														let sha256_of_onion = Sha256::hash(&onion_packet.hop_data).into_inner();
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
														match self.construct_recv_pending_htlc_info(hop_data, incoming_shared_secret, payment_hash, outgoing_amt_msat, outgoing_cltv_value, Some(phantom_shared_secret)) {
															Ok(info) => phantom_receives.push((prev_short_channel_id, prev_funding_outpoint, prev_user_channel_id, vec![(info, prev_htlc_id)])),
															Err(ReceiveError { err_code, err_data, msg }) => failed_payment!(msg, err_code, err_data, Some(phantom_shared_secret))
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
									HTLCForwardInfo::FailHTLC { .. } => {
										// Channel went away before we could fail it. This implies
										// the channel is now on chain and our counterparty is
										// trying to broadcast the HTLC-Timeout, but that's their
										// problem, not ours.
									}
								}
							}
						}
					}
					let (counterparty_node_id, forward_chan_id) = match self.short_to_chan_info.read().unwrap().get(&short_chan_id) {
						Some((cp_id, chan_id)) => (cp_id.clone(), chan_id.clone()),
						None => {
							forwarding_channel_not_found!();
							continue;
						}
					};
					let per_peer_state = self.per_peer_state.read().unwrap();
					let peer_state_mutex_opt = per_peer_state.get(&counterparty_node_id);
					if peer_state_mutex_opt.is_none() {
						forwarding_channel_not_found!();
						continue;
					}
					let mut peer_state_lock = peer_state_mutex_opt.unwrap().lock().unwrap();
					let peer_state = &mut *peer_state_lock;
					match peer_state.channel_by_id.entry(forward_chan_id) {
						hash_map::Entry::Vacant(_) => {
							forwarding_channel_not_found!();
							continue;
						},
						hash_map::Entry::Occupied(mut chan) => {
							for forward_info in pending_forwards.drain(..) {
								match forward_info {
									HTLCForwardInfo::AddHTLC(PendingAddHTLCInfo {
										prev_short_channel_id, prev_htlc_id, prev_funding_outpoint, prev_user_channel_id: _,
										forward_info: PendingHTLCInfo {
											incoming_shared_secret, payment_hash, outgoing_amt_msat, outgoing_cltv_value,
											routing: PendingHTLCRouting::Forward { onion_packet, .. }, incoming_amt_msat: _,
										},
									}) => {
										log_trace!(self.logger, "Adding HTLC from short id {} with payment_hash {} to channel with short id {} after delay", prev_short_channel_id, log_bytes!(payment_hash.0), short_chan_id);
										let htlc_source = HTLCSource::PreviousHopData(HTLCPreviousHopData {
											short_channel_id: prev_short_channel_id,
											outpoint: prev_funding_outpoint,
											htlc_id: prev_htlc_id,
											incoming_packet_shared_secret: incoming_shared_secret,
											// Phantom payments are only PendingHTLCRouting::Receive.
											phantom_shared_secret: None,
										});
										if let Err(e) = chan.get_mut().queue_add_htlc(outgoing_amt_msat,
											payment_hash, outgoing_cltv_value, htlc_source.clone(),
											onion_packet, &self.logger)
										{
											if let ChannelError::Ignore(msg) = e {
												log_trace!(self.logger, "Failed to forward HTLC with payment_hash {}: {}", log_bytes!(payment_hash.0), msg);
											} else {
												panic!("Stated return value requirements in send_htlc() were not met");
											}
											let (failure_code, data) = self.get_htlc_temp_fail_err_and_data(0x1000|7, short_chan_id, chan.get());
											failed_forwards.push((htlc_source, payment_hash,
												HTLCFailReason::reason(failure_code, data),
												HTLCDestination::NextHopChannel { node_id: Some(chan.get().get_counterparty_node_id()), channel_id: forward_chan_id }
											));
											continue;
										}
									},
									HTLCForwardInfo::AddHTLC { .. } => {
										panic!("short_channel_id != 0 should imply any pending_forward entries are of type Forward");
									},
									HTLCForwardInfo::FailHTLC { htlc_id, err_packet } => {
										log_trace!(self.logger, "Failing HTLC back to channel with short id {} (backward HTLC ID {}) after delay", short_chan_id, htlc_id);
										if let Err(e) = chan.get_mut().queue_fail_htlc(
											htlc_id, err_packet, &self.logger
										) {
											if let ChannelError::Ignore(msg) = e {
												log_trace!(self.logger, "Failed to fail HTLC with ID {} backwards to short_id {}: {}", htlc_id, short_chan_id, msg);
											} else {
												panic!("Stated return value requirements in queue_fail_htlc() were not met");
											}
											// fail-backs are best-effort, we probably already have one
											// pending, and if not that's OK, if not, the channel is on
											// the chain and sending the HTLC-Timeout is their problem.
											continue;
										}
									},
								}
							}
						}
					}
				} else {
					for forward_info in pending_forwards.drain(..) {
						match forward_info {
							HTLCForwardInfo::AddHTLC(PendingAddHTLCInfo {
								prev_short_channel_id, prev_htlc_id, prev_funding_outpoint, prev_user_channel_id,
								forward_info: PendingHTLCInfo {
									routing, incoming_shared_secret, payment_hash, outgoing_amt_msat, ..
								}
							}) => {
								let (cltv_expiry, onion_payload, payment_data, phantom_shared_secret) = match routing {
									PendingHTLCRouting::Receive { payment_data, incoming_cltv_expiry, phantom_shared_secret } => {
										let _legacy_hop_data = Some(payment_data.clone());
										(incoming_cltv_expiry, OnionPayload::Invoice { _legacy_hop_data }, Some(payment_data), phantom_shared_secret)
									},
									PendingHTLCRouting::ReceiveKeysend { payment_preimage, incoming_cltv_expiry } =>
										(incoming_cltv_expiry, OnionPayload::Spontaneous(payment_preimage), None, None),
									_ => {
										panic!("short_channel_id == 0 should imply any pending_forward entries are of type Receive");
									}
								};
								let claimable_htlc = ClaimableHTLC {
									prev_hop: HTLCPreviousHopData {
										short_channel_id: prev_short_channel_id,
										outpoint: prev_funding_outpoint,
										htlc_id: prev_htlc_id,
										incoming_packet_shared_secret: incoming_shared_secret,
										phantom_shared_secret,
									},
									value: outgoing_amt_msat,
									timer_ticks: 0,
									total_msat: if let Some(data) = &payment_data { data.total_msat } else { outgoing_amt_msat },
									cltv_expiry,
									onion_payload,
								};

								macro_rules! fail_htlc {
									($htlc: expr, $payment_hash: expr) => {
										let mut htlc_msat_height_data = $htlc.value.to_be_bytes().to_vec();
										htlc_msat_height_data.extend_from_slice(
											&self.best_block.read().unwrap().height().to_be_bytes(),
										);
										failed_forwards.push((HTLCSource::PreviousHopData(HTLCPreviousHopData {
												short_channel_id: $htlc.prev_hop.short_channel_id,
												outpoint: prev_funding_outpoint,
												htlc_id: $htlc.prev_hop.htlc_id,
												incoming_packet_shared_secret: $htlc.prev_hop.incoming_packet_shared_secret,
												phantom_shared_secret,
											}), payment_hash,
											HTLCFailReason::reason(0x4000 | 15, htlc_msat_height_data),
											HTLCDestination::FailedPayment { payment_hash: $payment_hash },
										));
									}
								}
								let phantom_shared_secret = claimable_htlc.prev_hop.phantom_shared_secret;
								let mut receiver_node_id = self.our_network_pubkey;
								if phantom_shared_secret.is_some() {
									receiver_node_id = self.node_signer.get_node_id(Recipient::PhantomNode)
										.expect("Failed to get node_id for phantom node recipient");
								}

								macro_rules! check_total_value {
									($payment_data: expr, $payment_preimage: expr) => {{
										let mut payment_claimable_generated = false;
										let purpose = || {
											events::PaymentPurpose::InvoicePayment {
												payment_preimage: $payment_preimage,
												payment_secret: $payment_data.payment_secret,
											}
										};
										let mut claimable_payments = self.claimable_payments.lock().unwrap();
										if claimable_payments.pending_claiming_payments.contains_key(&payment_hash) {
											fail_htlc!(claimable_htlc, payment_hash);
											continue
										}
										let (_, htlcs) = claimable_payments.claimable_htlcs.entry(payment_hash)
											.or_insert_with(|| (purpose(), Vec::new()));
										if htlcs.len() == 1 {
											if let OnionPayload::Spontaneous(_) = htlcs[0].onion_payload {
												log_trace!(self.logger, "Failing new HTLC with payment_hash {} as we already had an existing keysend HTLC with the same payment hash", log_bytes!(payment_hash.0));
												fail_htlc!(claimable_htlc, payment_hash);
												continue
											}
										}
										let mut total_value = claimable_htlc.value;
										for htlc in htlcs.iter() {
											total_value += htlc.value;
											match &htlc.onion_payload {
												OnionPayload::Invoice { .. } => {
													if htlc.total_msat != $payment_data.total_msat {
														log_trace!(self.logger, "Failing HTLCs with payment_hash {} as the HTLCs had inconsistent total values (eg {} and {})",
															log_bytes!(payment_hash.0), $payment_data.total_msat, htlc.total_msat);
														total_value = msgs::MAX_VALUE_MSAT;
													}
													if total_value >= msgs::MAX_VALUE_MSAT { break; }
												},
												_ => unreachable!(),
											}
										}
										if total_value >= msgs::MAX_VALUE_MSAT || total_value > $payment_data.total_msat {
											log_trace!(self.logger, "Failing HTLCs with payment_hash {} as the total value {} ran over expected value {} (or HTLCs were inconsistent)",
												log_bytes!(payment_hash.0), total_value, $payment_data.total_msat);
											fail_htlc!(claimable_htlc, payment_hash);
										} else if total_value == $payment_data.total_msat {
											let prev_channel_id = prev_funding_outpoint.to_channel_id();
											htlcs.push(claimable_htlc);
											new_events.push(events::Event::PaymentClaimable {
												receiver_node_id: Some(receiver_node_id),
												payment_hash,
												purpose: purpose(),
												amount_msat: total_value,
												via_channel_id: Some(prev_channel_id),
												via_user_channel_id: Some(prev_user_channel_id),
											});
											payment_claimable_generated = true;
										} else {
											// Nothing to do - we haven't reached the total
											// payment value yet, wait until we receive more
											// MPP parts.
											htlcs.push(claimable_htlc);
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
														log_trace!(self.logger, "Failing new HTLC with payment_hash {} as payment verification failed", log_bytes!(payment_hash.0));
														fail_htlc!(claimable_htlc, payment_hash);
														continue
													}
												};
												if let Some(min_final_cltv_expiry_delta) = min_final_cltv_expiry_delta {
													let expected_min_expiry_height = (self.current_best_block().height() + min_final_cltv_expiry_delta as u32) as u64;
													if (cltv_expiry as u64) < expected_min_expiry_height {
														log_trace!(self.logger, "Failing new HTLC with payment_hash {} as its CLTV expiry was too soon (had {}, earliest expected {})",
															log_bytes!(payment_hash.0), cltv_expiry, expected_min_expiry_height);
														fail_htlc!(claimable_htlc, payment_hash);
														continue;
													}
												}
												check_total_value!(payment_data, payment_preimage);
											},
											OnionPayload::Spontaneous(preimage) => {
												let mut claimable_payments = self.claimable_payments.lock().unwrap();
												if claimable_payments.pending_claiming_payments.contains_key(&payment_hash) {
													fail_htlc!(claimable_htlc, payment_hash);
													continue
												}
												match claimable_payments.claimable_htlcs.entry(payment_hash) {
													hash_map::Entry::Vacant(e) => {
														let purpose = events::PaymentPurpose::SpontaneousPayment(preimage);
														e.insert((purpose.clone(), vec![claimable_htlc]));
														let prev_channel_id = prev_funding_outpoint.to_channel_id();
														new_events.push(events::Event::PaymentClaimable {
															receiver_node_id: Some(receiver_node_id),
															payment_hash,
															amount_msat: outgoing_amt_msat,
															purpose,
															via_channel_id: Some(prev_channel_id),
															via_user_channel_id: Some(prev_user_channel_id),
														});
													},
													hash_map::Entry::Occupied(_) => {
														log_trace!(self.logger, "Failing new keysend HTLC with payment_hash {} for a duplicative payment hash", log_bytes!(payment_hash.0));
														fail_htlc!(claimable_htlc, payment_hash);
													}
												}
											}
										}
									},
									hash_map::Entry::Occupied(inbound_payment) => {
										if payment_data.is_none() {
											log_trace!(self.logger, "Failing new keysend HTLC with payment_hash {} because we already have an inbound payment with the same payment hash", log_bytes!(payment_hash.0));
											fail_htlc!(claimable_htlc, payment_hash);
											continue
										};
										let payment_data = payment_data.unwrap();
										if inbound_payment.get().payment_secret != payment_data.payment_secret {
											log_trace!(self.logger, "Failing new HTLC with payment_hash {} as it didn't match our expected payment secret.", log_bytes!(payment_hash.0));
											fail_htlc!(claimable_htlc, payment_hash);
										} else if inbound_payment.get().min_value_msat.is_some() && payment_data.total_msat < inbound_payment.get().min_value_msat.unwrap() {
											log_trace!(self.logger, "Failing new HTLC with payment_hash {} as it didn't match our minimum value (had {}, needed {}).",
												log_bytes!(payment_hash.0), payment_data.total_msat, inbound_payment.get().min_value_msat.unwrap());
											fail_htlc!(claimable_htlc, payment_hash);
										} else {
											let payment_claimable_generated = check_total_value!(payment_data, inbound_payment.get().payment_preimage);
											if payment_claimable_generated {
												inbound_payment.remove_entry();
											}
										}
									},
								};
							},
							HTLCForwardInfo::FailHTLC { .. } => {
								panic!("Got pending fail of our own HTLC");
							}
						}
					}
				}
			}
		}

		let best_block_height = self.best_block.read().unwrap().height();
		self.pending_outbound_payments.check_retry_payments(&self.router, || self.list_usable_channels(),
			|| self.compute_inflight_htlcs(), &self.entropy_source, &self.node_signer, best_block_height,
			&self.pending_events, &self.logger,
			|path, payment_params, payment_hash, payment_secret, total_value, cur_height, payment_id, keysend_preimage, session_priv|
			self.send_payment_along_path(path, payment_params, payment_hash, payment_secret, total_value, cur_height, payment_id, keysend_preimage, session_priv));

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

	/// Free the background events, generally called from timer_tick_occurred.
	///
	/// Exposed for testing to allow us to process events quickly without generating accidental
	/// BroadcastChannelUpdate events in timer_tick_occurred.
	///
	/// Expects the caller to have a total_consistency_lock read lock.
	fn process_background_events(&self) -> bool {
		let mut background_events = Vec::new();
		mem::swap(&mut *self.pending_background_events.lock().unwrap(), &mut background_events);
		if background_events.is_empty() {
			return false;
		}

		for event in background_events.drain(..) {
			match event {
				BackgroundEvent::ClosingMonitorUpdate((funding_txo, update)) => {
					// The channel has already been closed, so no use bothering to care about the
					// monitor updating completing.
					let _ = self.chain_monitor.update_channel(funding_txo, &update);
				},
			}
		}
		true
	}

	#[cfg(any(test, feature = "_test_utils"))]
	/// Process background events, for functional testing
	pub fn test_process_background_events(&self) {
		self.process_background_events();
	}

	fn update_channel_fee(&self, chan_id: &[u8; 32], chan: &mut Channel<<SP::Target as SignerProvider>::Signer>, new_feerate: u32) -> NotifyOption {
		if !chan.is_outbound() { return NotifyOption::SkipPersist; }
		// If the feerate has decreased by less than half, don't bother
		if new_feerate <= chan.get_feerate() && new_feerate * 2 > chan.get_feerate() {
			log_trace!(self.logger, "Channel {} does not qualify for a feerate change from {} to {}.",
				log_bytes!(chan_id[..]), chan.get_feerate(), new_feerate);
			return NotifyOption::SkipPersist;
		}
		if !chan.is_live() {
			log_trace!(self.logger, "Channel {} does not qualify for a feerate change from {} to {} as it cannot currently be updated (probably the peer is disconnected).",
				log_bytes!(chan_id[..]), chan.get_feerate(), new_feerate);
			return NotifyOption::SkipPersist;
		}
		log_trace!(self.logger, "Channel {} qualifies for a feerate change from {} to {}.",
			log_bytes!(chan_id[..]), chan.get_feerate(), new_feerate);

		chan.queue_update_fee(new_feerate, &self.logger);
		NotifyOption::DoPersist
	}

	#[cfg(fuzzing)]
	/// In chanmon_consistency we want to sometimes do the channel fee updates done in
	/// timer_tick_occurred, but we can't generate the disabled channel updates as it considers
	/// these a fuzz failure (as they usually indicate a channel force-close, which is exactly what
	/// it wants to detect). Thus, we have a variant exposed here for its benefit.
	pub fn maybe_update_chan_fees(&self) {
		PersistenceNotifierGuard::optionally_notify(&self.total_consistency_lock, &self.persistence_notifier, || {
			let mut should_persist = NotifyOption::SkipPersist;

			let new_feerate = self.fee_estimator.bounded_sat_per_1000_weight(ConfirmationTarget::Normal);

			let per_peer_state = self.per_peer_state.read().unwrap();
			for (_cp_id, peer_state_mutex) in per_peer_state.iter() {
				let mut peer_state_lock = peer_state_mutex.lock().unwrap();
				let peer_state = &mut *peer_state_lock;
				for (chan_id, chan) in peer_state.channel_by_id.iter_mut() {
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
	///  * Broadcasting `ChannelUpdate` messages if we've been disconnected from our peer for more
	///    than a minute, informing the network that they should no longer attempt to route over
	///    the channel.
	///  * Expiring a channel's previous `ChannelConfig` if necessary to only allow forwarding HTLCs
	///    with the current `ChannelConfig`.
	///  * Removing peers which have disconnected but and no longer have any channels.
	///
	/// Note that this may cause reentrancy through `chain::Watch::update_channel` calls or feerate
	/// estimate fetches.
	pub fn timer_tick_occurred(&self) {
		PersistenceNotifierGuard::optionally_notify(&self.total_consistency_lock, &self.persistence_notifier, || {
			let mut should_persist = NotifyOption::SkipPersist;
			if self.process_background_events() { should_persist = NotifyOption::DoPersist; }

			let new_feerate = self.fee_estimator.bounded_sat_per_1000_weight(ConfirmationTarget::Normal);

			let mut handle_errors: Vec<(Result<(), _>, _)> = Vec::new();
			let mut timed_out_mpp_htlcs = Vec::new();
			let mut pending_peers_awaiting_removal = Vec::new();
			{
				let per_peer_state = self.per_peer_state.read().unwrap();
				for (counterparty_node_id, peer_state_mutex) in per_peer_state.iter() {
					let mut peer_state_lock = peer_state_mutex.lock().unwrap();
					let peer_state = &mut *peer_state_lock;
					let pending_msg_events = &mut peer_state.pending_msg_events;
					let counterparty_node_id = *counterparty_node_id;
					peer_state.channel_by_id.retain(|chan_id, chan| {
						let chan_needs_persist = self.update_channel_fee(chan_id, chan, new_feerate);
						if chan_needs_persist == NotifyOption::DoPersist { should_persist = NotifyOption::DoPersist; }

						if let Err(e) = chan.timer_check_closing_negotiation_progress() {
							let (needs_close, err) = convert_chan_err!(self, e, chan, chan_id);
							handle_errors.push((Err(err), counterparty_node_id));
							if needs_close { return false; }
						}

						match chan.channel_update_status() {
							ChannelUpdateStatus::Enabled if !chan.is_live() => chan.set_channel_update_status(ChannelUpdateStatus::DisabledStaged),
							ChannelUpdateStatus::Disabled if chan.is_live() => chan.set_channel_update_status(ChannelUpdateStatus::EnabledStaged),
							ChannelUpdateStatus::DisabledStaged if chan.is_live() => chan.set_channel_update_status(ChannelUpdateStatus::Enabled),
							ChannelUpdateStatus::EnabledStaged if !chan.is_live() => chan.set_channel_update_status(ChannelUpdateStatus::Disabled),
							ChannelUpdateStatus::DisabledStaged if !chan.is_live() => {
								if let Ok(update) = self.get_channel_update_for_broadcast(&chan) {
									pending_msg_events.push(events::MessageSendEvent::BroadcastChannelUpdate {
										msg: update
									});
								}
								should_persist = NotifyOption::DoPersist;
								chan.set_channel_update_status(ChannelUpdateStatus::Disabled);
							},
							ChannelUpdateStatus::EnabledStaged if chan.is_live() => {
								if let Ok(update) = self.get_channel_update_for_broadcast(&chan) {
									pending_msg_events.push(events::MessageSendEvent::BroadcastChannelUpdate {
										msg: update
									});
								}
								should_persist = NotifyOption::DoPersist;
								chan.set_channel_update_status(ChannelUpdateStatus::Enabled);
							},
							_ => {},
						}

						chan.maybe_expire_prev_config();

						true
					});
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

			self.claimable_payments.lock().unwrap().claimable_htlcs.retain(|payment_hash, (_, htlcs)| {
				if htlcs.is_empty() {
					// This should be unreachable
					debug_assert!(false);
					return false;
				}
				if let OnionPayload::Invoice { .. } = htlcs[0].onion_payload {
					// Check if we've received all the parts we need for an MPP (the value of the parts adds to total_msat).
					// In this case we're not going to handle any timeouts of the parts here.
					if htlcs[0].total_msat == htlcs.iter().fold(0, |total, htlc| total + htlc.value) {
						return true;
					} else if htlcs.into_iter().any(|htlc| {
						htlc.timer_ticks += 1;
						return htlc.timer_ticks >= MPP_TIMEOUT_TICKS
					}) {
						timed_out_mpp_htlcs.extend(htlcs.drain(..).map(|htlc: ClaimableHTLC| (htlc.prev_hop, *payment_hash)));
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

			self.pending_outbound_payments.remove_stale_resolved_payments(&self.pending_events);

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
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(&self.total_consistency_lock, &self.persistence_notifier);

		let removed_source = self.claimable_payments.lock().unwrap().claimable_htlcs.remove(payment_hash);
		if let Some((_, mut sources)) = removed_source {
			for htlc in sources.drain(..) {
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
			FailureCode::TemporaryNodeFailure => HTLCFailReason::from_failure_code(failure_code as u16),
			FailureCode::RequiredNodeFeatureMissing => HTLCFailReason::from_failure_code(failure_code as u16),
			FailureCode::IncorrectOrUnknownPaymentDetails => {
				let mut htlc_msat_height_data = htlc.value.to_be_bytes().to_vec();
				htlc_msat_height_data.extend_from_slice(&self.best_block.read().unwrap().height().to_be_bytes());
				HTLCFailReason::reason(failure_code as u16, htlc_msat_height_data)
			}
		}
	}

	/// Gets an HTLC onion failure code and error data for an `UPDATE` error, given the error code
	/// that we want to return and a channel.
	///
	/// This is for failures on the channel on which the HTLC was *received*, not failures
	/// forwarding
	fn get_htlc_inbound_temp_fail_err_and_data(&self, desired_err_code: u16, chan: &Channel<<SP::Target as SignerProvider>::Signer>) -> (u16, Vec<u8>) {
		// We can't be sure what SCID was used when relaying inbound towards us, so we have to
		// guess somewhat. If its a public channel, we figure best to just use the real SCID (as
		// we're not leaking that we have a channel with the counterparty), otherwise we try to use
		// an inbound SCID alias before the real SCID.
		let scid_pref = if chan.should_announce() {
			chan.get_short_channel_id().or(chan.latest_inbound_scid_alias())
		} else {
			chan.latest_inbound_scid_alias().or(chan.get_short_channel_id())
		};
		if let Some(scid) = scid_pref {
			self.get_htlc_temp_fail_err_and_data(desired_err_code, scid, chan)
		} else {
			(0x4000|10, Vec::new())
		}
	}


	/// Gets an HTLC onion failure code and error data for an `UPDATE` error, given the error code
	/// that we want to return and a channel.
	fn get_htlc_temp_fail_err_and_data(&self, desired_err_code: u16, scid: u64, chan: &Channel<<SP::Target as SignerProvider>::Signer>) -> (u16, Vec<u8>) {
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
		&self, mut htlcs_to_fail: Vec<(HTLCSource, PaymentHash)>, channel_id: [u8; 32],
		counterparty_node_id: &PublicKey
	) {
		let (failure_code, onion_failure_data) = {
			let per_peer_state = self.per_peer_state.read().unwrap();
			if let Some(peer_state_mutex) = per_peer_state.get(counterparty_node_id) {
				let mut peer_state_lock = peer_state_mutex.lock().unwrap();
				let peer_state = &mut *peer_state_lock;
				match peer_state.channel_by_id.entry(channel_id) {
					hash_map::Entry::Occupied(chan_entry) => {
						self.get_htlc_inbound_temp_fail_err_and_data(0x1000|7, &chan_entry.get())
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

	/// Fails an HTLC backwards to the sender of it to us.
	/// Note that we do not assume that channels corresponding to failed HTLCs are still available.
	fn fail_htlc_backwards_internal(&self, source: &HTLCSource, payment_hash: &PaymentHash, onion_error: &HTLCFailReason, destination: HTLCDestination) {
		// Ensure that no peer state channel storage lock is held when calling this function.
		// This ensures that future code doesn't introduce a lock-order requirement for
		// `forward_htlcs` to be locked after the `per_peer_state` peer locks, which calling
		// this function with any `per_peer_state` peer lock acquired would.
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
			HTLCSource::OutboundRoute { ref path, ref session_priv, ref payment_id, ref payment_params, .. } => {
				if self.pending_outbound_payments.fail_htlc(source, payment_hash, onion_error, path,
					session_priv, payment_id, payment_params, self.probing_cookie_secret, &self.secp_ctx,
					&self.pending_events, &self.logger)
				{ self.push_pending_forwards_ev(); }
			},
			HTLCSource::PreviousHopData(HTLCPreviousHopData { ref short_channel_id, ref htlc_id, ref incoming_packet_shared_secret, ref phantom_shared_secret, ref outpoint }) => {
				log_trace!(self.logger, "Failing HTLC with payment_hash {} backwards from us with {:?}", log_bytes!(payment_hash.0), onion_error);
				let err_packet = onion_error.get_encrypted_failure_packet(incoming_packet_shared_secret, phantom_shared_secret);

				let mut push_forward_ev = false;
				let mut forward_htlcs = self.forward_htlcs.lock().unwrap();
				if forward_htlcs.is_empty() {
					push_forward_ev = true;
				}
				match forward_htlcs.entry(*short_channel_id) {
					hash_map::Entry::Occupied(mut entry) => {
						entry.get_mut().push(HTLCForwardInfo::FailHTLC { htlc_id: *htlc_id, err_packet });
					},
					hash_map::Entry::Vacant(entry) => {
						entry.insert(vec!(HTLCForwardInfo::FailHTLC { htlc_id: *htlc_id, err_packet }));
					}
				}
				mem::drop(forward_htlcs);
				if push_forward_ev { self.push_pending_forwards_ev(); }
				let mut pending_events = self.pending_events.lock().unwrap();
				pending_events.push(events::Event::HTLCHandlingFailed {
					prev_channel_id: outpoint.to_channel_id(),
					failed_next_destination: destination,
				});
			},
		}
	}

	/// Provides a payment preimage in response to [`Event::PaymentClaimable`], generating any
	/// [`MessageSendEvent`]s needed to claim the payment.
	///
	/// Note that calling this method does *not* guarantee that the payment has been claimed. You
	/// *must* wait for an [`Event::PaymentClaimed`] event which upon a successful claim will be
	/// provided to your [`EventHandler`] when [`process_pending_events`] is next called.
	///
	/// Note that if you did not set an `amount_msat` when calling [`create_inbound_payment`] or
	/// [`create_inbound_payment_for_hash`] you must check that the amount in the `PaymentClaimable`
	/// event matches your expectation. If you fail to do so and call this method, you may provide
	/// the sender "proof-of-payment" when they did not fulfill the full expected payment.
	///
	/// [`Event::PaymentClaimable`]: crate::util::events::Event::PaymentClaimable
	/// [`Event::PaymentClaimed`]: crate::util::events::Event::PaymentClaimed
	/// [`process_pending_events`]: EventsProvider::process_pending_events
	/// [`create_inbound_payment`]: Self::create_inbound_payment
	/// [`create_inbound_payment_for_hash`]: Self::create_inbound_payment_for_hash
	pub fn claim_funds(&self, payment_preimage: PaymentPreimage) {
		let payment_hash = PaymentHash(Sha256::hash(&payment_preimage.0).into_inner());

		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(&self.total_consistency_lock, &self.persistence_notifier);

		let mut sources = {
			let mut claimable_payments = self.claimable_payments.lock().unwrap();
			if let Some((payment_purpose, sources)) = claimable_payments.claimable_htlcs.remove(&payment_hash) {
				let mut receiver_node_id = self.our_network_pubkey;
				for htlc in sources.iter() {
					if htlc.prev_hop.phantom_shared_secret.is_some() {
						let phantom_pubkey = self.node_signer.get_node_id(Recipient::PhantomNode)
							.expect("Failed to get node_id for phantom node recipient");
						receiver_node_id = phantom_pubkey;
						break;
					}
				}

				let dup_purpose = claimable_payments.pending_claiming_payments.insert(payment_hash,
					ClaimingPayment { amount_msat: sources.iter().map(|source| source.value).sum(),
					payment_purpose, receiver_node_id,
				});
				if dup_purpose.is_some() {
					debug_assert!(false, "Shouldn't get a duplicate pending claim event ever");
					log_error!(self.logger, "Got a duplicate pending claimable event on payment hash {}! Please report this bug",
						log_bytes!(payment_hash.0));
				}
				sources
			} else { return; }
		};
		debug_assert!(!sources.is_empty());

		// If we are claiming an MPP payment, we check that all channels which contain a claimable
		// HTLC still exist. While this isn't guaranteed to remain true if a channel closes while
		// we're claiming (or even after we claim, before the commitment update dance completes),
		// it should be a relatively rare race, and we'd rather not claim HTLCs that require us to
		// go on-chain (and lose the on-chain fee to do so) than just reject the payment.
		//
		// Note that we'll still always get our funds - as long as the generated
		// `ChannelMonitorUpdate` makes it out to the relevant monitor we can claim on-chain.
		//
		// If we find an HTLC which we would need to claim but for which we do not have a
		// channel, we will fail all parts of the MPP payment. While we could wait and see if
		// the sender retries the already-failed path(s), it should be a pretty rare case where
		// we got all the HTLCs and then a channel closed while we were waiting for the user to
		// provide the preimage, so worrying too much about the optimal handling isn't worth
		// it.
		let mut claimable_amt_msat = 0;
		let mut expected_amt_msat = None;
		let mut valid_mpp = true;
		let mut errs = Vec::new();
		let per_peer_state = self.per_peer_state.read().unwrap();
		for htlc in sources.iter() {
			let (counterparty_node_id, chan_id) = match self.short_to_chan_info.read().unwrap().get(&htlc.prev_hop.short_channel_id) {
				Some((cp_id, chan_id)) => (cp_id.clone(), chan_id.clone()),
				None => {
					valid_mpp = false;
					break;
				}
			};

			let peer_state_mutex_opt = per_peer_state.get(&counterparty_node_id);
			if peer_state_mutex_opt.is_none() {
				valid_mpp = false;
				break;
			}

			let mut peer_state_lock = peer_state_mutex_opt.unwrap().lock().unwrap();
			let peer_state = &mut *peer_state_lock;

			if peer_state.channel_by_id.get(&chan_id).is_none() {
				valid_mpp = false;
				break;
			}

			if expected_amt_msat.is_some() && expected_amt_msat != Some(htlc.total_msat) {
				log_error!(self.logger, "Somehow ended up with an MPP payment with different total amounts - this should not be reachable!");
				debug_assert!(false);
				valid_mpp = false;
				break;
			}

			expected_amt_msat = Some(htlc.total_msat);
			if let OnionPayload::Spontaneous(_) = &htlc.onion_payload {
				// We don't currently support MPP for spontaneous payments, so just check
				// that there's one payment here and move on.
				if sources.len() != 1 {
					log_error!(self.logger, "Somehow ended up with an MPP spontaneous payment - this should not be reachable!");
					debug_assert!(false);
					valid_mpp = false;
					break;
				}
			}

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
				if let Err((pk, err)) = self.claim_funds_from_hop(
					htlc.prev_hop, payment_preimage,
					|_| Some(MonitorUpdateCompletionAction::PaymentClaimed { payment_hash }))
				{
					if let msgs::ErrorAction::IgnoreError = err.err.action {
						// We got a temporary failure updating monitor, but will claim the
						// HTLC when the monitor updating is restored (or on chain).
						log_error!(self.logger, "Temporary failure claiming HTLC, treating as success: {}", err.err.err);
					} else { errs.push((pk, err)); }
				}
			}
		}
		if !valid_mpp {
			for htlc in sources.drain(..) {
				let mut htlc_msat_height_data = htlc.value.to_be_bytes().to_vec();
				htlc_msat_height_data.extend_from_slice(&self.best_block.read().unwrap().height().to_be_bytes());
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

	fn claim_funds_from_hop<ComplFunc: FnOnce(Option<u64>) -> Option<MonitorUpdateCompletionAction>>(&self,
		prev_hop: HTLCPreviousHopData, payment_preimage: PaymentPreimage, completion_action: ComplFunc)
	-> Result<(), (PublicKey, MsgHandleErrInternal)> {
		//TODO: Delay the claimed_funds relaying just like we do outbound relay!

		let per_peer_state = self.per_peer_state.read().unwrap();
		let chan_id = prev_hop.outpoint.to_channel_id();
		let counterparty_node_id_opt = match self.short_to_chan_info.read().unwrap().get(&prev_hop.short_channel_id) {
			Some((cp_id, _dup_chan_id)) => Some(cp_id.clone()),
			None => None
		};

		let peer_state_opt = counterparty_node_id_opt.as_ref().map(
			|counterparty_node_id| per_peer_state.get(counterparty_node_id).map(
				|peer_mutex| peer_mutex.lock().unwrap()
			)
		).unwrap_or(None);

		if peer_state_opt.is_some() {
			let mut peer_state_lock = peer_state_opt.unwrap();
			let peer_state = &mut *peer_state_lock;
			if let hash_map::Entry::Occupied(mut chan) = peer_state.channel_by_id.entry(chan_id) {
				let counterparty_node_id = chan.get().get_counterparty_node_id();
				let fulfill_res = chan.get_mut().get_update_fulfill_htlc_and_commit(prev_hop.htlc_id, payment_preimage, &self.logger);

				if let UpdateFulfillCommitFetch::NewClaim { htlc_value_msat, monitor_update } = fulfill_res {
					if let Some(action) = completion_action(Some(htlc_value_msat)) {
						log_trace!(self.logger, "Tracking monitor update completion action for channel {}: {:?}",
							log_bytes!(chan_id), action);
						peer_state.monitor_update_blocked_actions.entry(chan_id).or_insert(Vec::new()).push(action);
					}
					let update_id = monitor_update.update_id;
					let update_res = self.chain_monitor.update_channel(prev_hop.outpoint, monitor_update);
					let res = handle_new_monitor_update!(self, update_res, update_id, peer_state_lock,
						peer_state, per_peer_state, chan);
					if let Err(e) = res {
						// TODO: This is a *critical* error - we probably updated the outbound edge
						// of the HTLC's monitor with a preimage. We should retry this monitor
						// update over and over again until morale improves.
						log_error!(self.logger, "Failed to update channel monitor with preimage {:?}", payment_preimage);
						return Err((counterparty_node_id, e));
					}
				}
				return Ok(());
			}
		}
		let preimage_update = ChannelMonitorUpdate {
			update_id: CLOSED_CHANNEL_UPDATE_ID,
			updates: vec![ChannelMonitorUpdateStep::PaymentPreimage {
				payment_preimage,
			}],
		};
		// We update the ChannelMonitor on the backward link, after
		// receiving an `update_fulfill_htlc` from the forward link.
		let update_res = self.chain_monitor.update_channel(prev_hop.outpoint, &preimage_update);
		if update_res != ChannelMonitorUpdateStatus::Completed {
			// TODO: This needs to be handled somehow - if we receive a monitor update
			// with a preimage we *must* somehow manage to propagate it to the upstream
			// channel, or we must have an ability to receive the same event and try
			// again on restart.
			log_error!(self.logger, "Critical error: failed to update channel monitor with preimage {:?}: {:?}",
				payment_preimage, update_res);
		}
		// Note that we do process the completion action here. This totally could be a
		// duplicate claim, but we have no way of knowing without interrogating the
		// `ChannelMonitor` we've provided the above update to. Instead, note that `Event`s are
		// generally always allowed to be duplicative (and it's specifically noted in
		// `PaymentForwarded`).
		self.handle_monitor_update_completion_actions(completion_action(None));
		Ok(())
	}

	fn finalize_claims(&self, sources: Vec<HTLCSource>) {
		self.pending_outbound_payments.finalize_claims(sources, &self.pending_events);
	}

	fn claim_funds_internal(&self, source: HTLCSource, payment_preimage: PaymentPreimage, forwarded_htlc_value_msat: Option<u64>, from_onchain: bool, next_channel_id: [u8; 32]) {
		match source {
			HTLCSource::OutboundRoute { session_priv, payment_id, path, .. } => {
				self.pending_outbound_payments.claim_htlc(payment_id, payment_preimage, session_priv, path, from_onchain, &self.pending_events, &self.logger);
			},
			HTLCSource::PreviousHopData(hop_data) => {
				let prev_outpoint = hop_data.outpoint;
				let res = self.claim_funds_from_hop(hop_data, payment_preimage,
					|htlc_claim_value_msat| {
						if let Some(forwarded_htlc_value) = forwarded_htlc_value_msat {
							let fee_earned_msat = if let Some(claimed_htlc_value) = htlc_claim_value_msat {
								Some(claimed_htlc_value - forwarded_htlc_value)
							} else { None };

							let prev_channel_id = Some(prev_outpoint.to_channel_id());
							let next_channel_id = Some(next_channel_id);

							Some(MonitorUpdateCompletionAction::EmitEvent { event: events::Event::PaymentForwarded {
								fee_earned_msat,
								claim_from_onchain_tx: from_onchain,
								prev_channel_id,
								next_channel_id,
							}})
						} else { None }
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
		for action in actions.into_iter() {
			match action {
				MonitorUpdateCompletionAction::PaymentClaimed { payment_hash } => {
					let payment = self.claimable_payments.lock().unwrap().pending_claiming_payments.remove(&payment_hash);
					if let Some(ClaimingPayment { amount_msat, payment_purpose: purpose, receiver_node_id }) = payment {
						self.pending_events.lock().unwrap().push(events::Event::PaymentClaimed {
							payment_hash, purpose, amount_msat, receiver_node_id: Some(receiver_node_id),
						});
					}
				},
				MonitorUpdateCompletionAction::EmitEvent { event } => {
					self.pending_events.lock().unwrap().push(event);
				},
			}
		}
	}

	/// Handles a channel reentering a functional state, either due to reconnect or a monitor
	/// update completion.
	fn handle_channel_resumption(&self, pending_msg_events: &mut Vec<MessageSendEvent>,
		channel: &mut Channel<<SP::Target as SignerProvider>::Signer>, raa: Option<msgs::RevokeAndACK>,
		commitment_update: Option<msgs::CommitmentUpdate>, order: RAACommitmentOrder,
		pending_forwards: Vec<(PendingHTLCInfo, u64)>, funding_broadcastable: Option<Transaction>,
		channel_ready: Option<msgs::ChannelReady>, announcement_sigs: Option<msgs::AnnouncementSignatures>)
	-> Option<(u64, OutPoint, u128, Vec<(PendingHTLCInfo, u64)>)> {
		log_trace!(self.logger, "Handling channel resumption for channel {} with {} RAA, {} commitment update, {} pending forwards, {}broadcasting funding, {} channel ready, {} announcement",
			log_bytes!(channel.channel_id()),
			if raa.is_some() { "an" } else { "no" },
			if commitment_update.is_some() { "a" } else { "no" }, pending_forwards.len(),
			if funding_broadcastable.is_some() { "" } else { "not " },
			if channel_ready.is_some() { "sending" } else { "without" },
			if announcement_sigs.is_some() { "sending" } else { "without" });

		let mut htlc_forwards = None;

		let counterparty_node_id = channel.get_counterparty_node_id();
		if !pending_forwards.is_empty() {
			htlc_forwards = Some((channel.get_short_channel_id().unwrap_or(channel.outbound_scid_alias()),
				channel.get_funding_txo().unwrap(), channel.get_user_id(), pending_forwards));
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

		emit_channel_ready_event!(self, channel);

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
			log_info!(self.logger, "Broadcasting funding transaction with txid {}", tx.txid());
			self.tx_broadcaster.broadcast_transaction(&tx);
		}

		htlc_forwards
	}

	fn channel_monitor_updated(&self, funding_txo: &OutPoint, highest_applied_update_id: u64, counterparty_node_id: Option<&PublicKey>) {
		debug_assert!(self.total_consistency_lock.try_write().is_err()); // Caller holds read lock

		let counterparty_node_id = match counterparty_node_id {
			Some(cp_id) => cp_id.clone(),
			None => {
				// TODO: Once we can rely on the counterparty_node_id from the
				// monitor event, this and the id_to_peer map should be removed.
				let id_to_peer = self.id_to_peer.lock().unwrap();
				match id_to_peer.get(&funding_txo.to_channel_id()) {
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
		let mut channel = {
			match peer_state.channel_by_id.entry(funding_txo.to_channel_id()){
				hash_map::Entry::Occupied(chan) => chan,
				hash_map::Entry::Vacant(_) => return,
			}
		};
		log_trace!(self.logger, "ChannelMonitor updated to {}. Current highest is {}",
			highest_applied_update_id, channel.get().get_latest_monitor_update_id());
		if !channel.get().is_awaiting_monitor_update() || channel.get().get_latest_monitor_update_id() != highest_applied_update_id {
			return;
		}
		handle_monitor_update_completion!(self, highest_applied_update_id, peer_state_lock, peer_state, per_peer_state, channel.get_mut());
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
	pub fn accept_inbound_channel(&self, temporary_channel_id: &[u8; 32], counterparty_node_id: &PublicKey, user_channel_id: u128) -> Result<(), APIError> {
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
	pub fn accept_inbound_channel_from_trusted_peer_0conf(&self, temporary_channel_id: &[u8; 32], counterparty_node_id: &PublicKey, user_channel_id: u128) -> Result<(), APIError> {
		self.do_accept_inbound_channel(temporary_channel_id, counterparty_node_id, true, user_channel_id)
	}

	fn do_accept_inbound_channel(&self, temporary_channel_id: &[u8; 32], counterparty_node_id: &PublicKey, accept_0conf: bool, user_channel_id: u128) -> Result<(), APIError> {
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(&self.total_consistency_lock, &self.persistence_notifier);

		let peers_without_funded_channels = self.peers_without_funded_channels(|peer| !peer.channel_by_id.is_empty());
		let per_peer_state = self.per_peer_state.read().unwrap();
		let peer_state_mutex = per_peer_state.get(counterparty_node_id)
			.ok_or_else(|| APIError::ChannelUnavailable { err: format!("Can't find a peer matching the passed counterparty node_id {}", counterparty_node_id) })?;
		let mut peer_state_lock = peer_state_mutex.lock().unwrap();
		let peer_state = &mut *peer_state_lock;
		let is_only_peer_channel = peer_state.channel_by_id.len() == 1;
		match peer_state.channel_by_id.entry(temporary_channel_id.clone()) {
			hash_map::Entry::Occupied(mut channel) => {
				if !channel.get().inbound_is_awaiting_accept() {
					return Err(APIError::APIMisuseError { err: "The channel isn't currently awaiting to be accepted.".to_owned() });
				}
				if accept_0conf {
					channel.get_mut().set_0conf();
				} else if channel.get().get_channel_type().requires_zero_conf() {
					let send_msg_err_event = events::MessageSendEvent::HandleError {
						node_id: channel.get().get_counterparty_node_id(),
						action: msgs::ErrorAction::SendErrorMessage{
							msg: msgs::ErrorMessage { channel_id: temporary_channel_id.clone(), data: "No zero confirmation channels accepted".to_owned(), }
						}
					};
					peer_state.pending_msg_events.push(send_msg_err_event);
					let _ = remove_channel!(self, channel);
					return Err(APIError::APIMisuseError { err: "Please use accept_inbound_channel_from_trusted_peer_0conf to accept channels with zero confirmations.".to_owned() });
				} else {
					// If this peer already has some channels, a new channel won't increase our number of peers
					// with unfunded channels, so as long as we aren't over the maximum number of unfunded
					// channels per-peer we can accept channels from a peer with existing ones.
					if is_only_peer_channel && peers_without_funded_channels >= MAX_UNFUNDED_CHANNEL_PEERS {
						let send_msg_err_event = events::MessageSendEvent::HandleError {
							node_id: channel.get().get_counterparty_node_id(),
							action: msgs::ErrorAction::SendErrorMessage{
								msg: msgs::ErrorMessage { channel_id: temporary_channel_id.clone(), data: "Have too many peers with unfunded channels, not accepting new ones".to_owned(), }
							}
						};
						peer_state.pending_msg_events.push(send_msg_err_event);
						let _ = remove_channel!(self, channel);
						return Err(APIError::APIMisuseError { err: "Too many peers with unfunded channels, refusing to accept new ones".to_owned() });
					}
				}

				peer_state.pending_msg_events.push(events::MessageSendEvent::SendAcceptChannel {
					node_id: channel.get().get_counterparty_node_id(),
					msg: channel.get_mut().accept_inbound_channel(user_channel_id),
				});
			}
			hash_map::Entry::Vacant(_) => {
				return Err(APIError::ChannelUnavailable { err: format!("Channel with id {} not found for the passed counterparty node_id {}", log_bytes!(*temporary_channel_id), counterparty_node_id) });
			}
		}
		Ok(())
	}

	/// Gets the number of peers which match the given filter and do not have any funded, outbound,
	/// or 0-conf channels.
	///
	/// The filter is called for each peer and provided with the number of unfunded, inbound, and
	/// non-0-conf channels we have with the peer.
	fn peers_without_funded_channels<Filter>(&self, maybe_count_peer: Filter) -> usize
	where Filter: Fn(&PeerState<<SP::Target as SignerProvider>::Signer>) -> bool {
		let mut peers_without_funded_channels = 0;
		let best_block_height = self.best_block.read().unwrap().height();
		{
			let peer_state_lock = self.per_peer_state.read().unwrap();
			for (_, peer_mtx) in peer_state_lock.iter() {
				let peer = peer_mtx.lock().unwrap();
				if !maybe_count_peer(&*peer) { continue; }
				let num_unfunded_channels = Self::unfunded_channel_count(&peer, best_block_height);
				if num_unfunded_channels == peer.channel_by_id.len() {
					peers_without_funded_channels += 1;
				}
			}
		}
		return peers_without_funded_channels;
	}

	fn unfunded_channel_count(
		peer: &PeerState<<SP::Target as SignerProvider>::Signer>, best_block_height: u32
	) -> usize {
		let mut num_unfunded_channels = 0;
		for (_, chan) in peer.channel_by_id.iter() {
			if !chan.is_outbound() && chan.minimum_depth().unwrap_or(1) != 0 &&
				chan.get_funding_tx_confirmations(best_block_height) == 0
			{
				num_unfunded_channels += 1;
			}
		}
		num_unfunded_channels
	}

	fn internal_open_channel(&self, counterparty_node_id: &PublicKey, msg: &msgs::OpenChannel) -> Result<(), MsgHandleErrInternal> {
		if msg.chain_hash != self.genesis_hash {
			return Err(MsgHandleErrInternal::send_err_msg_no_close("Unknown genesis block hash".to_owned(), msg.temporary_channel_id.clone()));
		}

		if !self.default_configuration.accept_inbound_channels {
			return Err(MsgHandleErrInternal::send_err_msg_no_close("No inbound channels accepted".to_owned(), msg.temporary_channel_id.clone()));
		}

		let mut random_bytes = [0u8; 16];
		random_bytes.copy_from_slice(&self.entropy_source.get_secure_random_bytes()[..16]);
		let user_channel_id = u128::from_be_bytes(random_bytes);
		let outbound_scid_alias = self.create_and_insert_outbound_scid_alias();

		// Get the number of peers with channels, but without funded ones. We don't care too much
		// about peers that never open a channel, so we filter by peers that have at least one
		// channel, and then limit the number of those with unfunded channels.
		let channeled_peers_without_funding = self.peers_without_funded_channels(|node| !node.channel_by_id.is_empty());

		let per_peer_state = self.per_peer_state.read().unwrap();
		let peer_state_mutex = per_peer_state.get(counterparty_node_id)
		    .ok_or_else(|| {
				debug_assert!(false);
				MsgHandleErrInternal::send_err_msg_no_close(format!("Can't find a peer matching the passed counterparty node_id {}", counterparty_node_id), msg.temporary_channel_id.clone())
			})?;
		let mut peer_state_lock = peer_state_mutex.lock().unwrap();
		let peer_state = &mut *peer_state_lock;

		// If this peer already has some channels, a new channel won't increase our number of peers
		// with unfunded channels, so as long as we aren't over the maximum number of unfunded
		// channels per-peer we can accept channels from a peer with existing ones.
		if peer_state.channel_by_id.is_empty() &&
			channeled_peers_without_funding >= MAX_UNFUNDED_CHANNEL_PEERS &&
			!self.default_configuration.manually_accept_inbound_channels
		{
			return Err(MsgHandleErrInternal::send_err_msg_no_close(
				"Have too many peers with unfunded channels, not accepting new ones".to_owned(),
				msg.temporary_channel_id.clone()));
		}

		let best_block_height = self.best_block.read().unwrap().height();
		if Self::unfunded_channel_count(peer_state, best_block_height) >= MAX_UNFUNDED_CHANS_PER_PEER {
			return Err(MsgHandleErrInternal::send_err_msg_no_close(
				format!("Refusing more than {} unfunded channels.", MAX_UNFUNDED_CHANS_PER_PEER),
				msg.temporary_channel_id.clone()));
		}

		let mut channel = match Channel::new_from_req(&self.fee_estimator, &self.entropy_source, &self.signer_provider,
			counterparty_node_id.clone(), &self.channel_type_features(), &peer_state.latest_features, msg, user_channel_id,
			&self.default_configuration, best_block_height, &self.logger, outbound_scid_alias)
		{
			Err(e) => {
				self.outbound_scid_aliases.lock().unwrap().remove(&outbound_scid_alias);
				return Err(MsgHandleErrInternal::from_chan_no_close(e, msg.temporary_channel_id));
			},
			Ok(res) => res
		};
		match peer_state.channel_by_id.entry(channel.channel_id()) {
			hash_map::Entry::Occupied(_) => {
				self.outbound_scid_aliases.lock().unwrap().remove(&outbound_scid_alias);
				return Err(MsgHandleErrInternal::send_err_msg_no_close("temporary_channel_id collision for the same peer!".to_owned(), msg.temporary_channel_id.clone()))
			},
			hash_map::Entry::Vacant(entry) => {
				if !self.default_configuration.manually_accept_inbound_channels {
					if channel.get_channel_type().requires_zero_conf() {
						return Err(MsgHandleErrInternal::send_err_msg_no_close("No zero confirmation channels accepted".to_owned(), msg.temporary_channel_id.clone()));
					}
					peer_state.pending_msg_events.push(events::MessageSendEvent::SendAcceptChannel {
						node_id: counterparty_node_id.clone(),
						msg: channel.accept_inbound_channel(user_channel_id),
					});
				} else {
					let mut pending_events = self.pending_events.lock().unwrap();
					pending_events.push(
						events::Event::OpenChannelRequest {
							temporary_channel_id: msg.temporary_channel_id.clone(),
							counterparty_node_id: counterparty_node_id.clone(),
							funding_satoshis: msg.funding_satoshis,
							push_msat: msg.push_msat,
							channel_type: channel.get_channel_type().clone(),
						}
					);
				}

				entry.insert(channel);
			}
		}
		Ok(())
	}

	fn internal_accept_channel(&self, counterparty_node_id: &PublicKey, msg: &msgs::AcceptChannel) -> Result<(), MsgHandleErrInternal> {
		let (value, output_script, user_id) = {
			let per_peer_state = self.per_peer_state.read().unwrap();
			let peer_state_mutex = per_peer_state.get(counterparty_node_id)
				.ok_or_else(|| {
					debug_assert!(false);
					MsgHandleErrInternal::send_err_msg_no_close(format!("Can't find a peer matching the passed counterparty node_id {}", counterparty_node_id), msg.temporary_channel_id)
				})?;
			let mut peer_state_lock = peer_state_mutex.lock().unwrap();
			let peer_state = &mut *peer_state_lock;
			match peer_state.channel_by_id.entry(msg.temporary_channel_id) {
				hash_map::Entry::Occupied(mut chan) => {
					try_chan_entry!(self, chan.get_mut().accept_channel(&msg, &self.default_configuration.channel_handshake_limits, &peer_state.latest_features), chan);
					(chan.get().get_value_satoshis(), chan.get().get_funding_redeemscript().to_v0_p2wsh(), chan.get().get_user_id())
				},
				hash_map::Entry::Vacant(_) => return Err(MsgHandleErrInternal::send_err_msg_no_close(format!("Got a message for a channel from the wrong node! No such channel for the passed counterparty_node_id {}", counterparty_node_id), msg.temporary_channel_id))
			}
		};
		let mut pending_events = self.pending_events.lock().unwrap();
		pending_events.push(events::Event::FundingGenerationReady {
			temporary_channel_id: msg.temporary_channel_id,
			counterparty_node_id: *counterparty_node_id,
			channel_value_satoshis: value,
			output_script,
			user_channel_id: user_id,
		});
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
		let ((funding_msg, monitor), chan) =
			match peer_state.channel_by_id.entry(msg.temporary_channel_id) {
				hash_map::Entry::Occupied(mut chan) => {
					(try_chan_entry!(self, chan.get_mut().funding_created(msg, best_block, &self.signer_provider, &self.logger), chan), chan.remove())
				},
				hash_map::Entry::Vacant(_) => return Err(MsgHandleErrInternal::send_err_msg_no_close(format!("Got a message for a channel from the wrong node! No such channel for the passed counterparty_node_id {}", counterparty_node_id), msg.temporary_channel_id))
			};

		match peer_state.channel_by_id.entry(funding_msg.channel_id) {
			hash_map::Entry::Occupied(_) => {
				Err(MsgHandleErrInternal::send_err_msg_no_close("Already had channel with the new channel_id".to_owned(), funding_msg.channel_id))
			},
			hash_map::Entry::Vacant(e) => {
				match self.id_to_peer.lock().unwrap().entry(chan.channel_id()) {
					hash_map::Entry::Occupied(_) => {
						return Err(MsgHandleErrInternal::send_err_msg_no_close(
							"The funding_created message had the same funding_txid as an existing channel - funding is not possible".to_owned(),
							funding_msg.channel_id))
					},
					hash_map::Entry::Vacant(i_e) => {
						i_e.insert(chan.get_counterparty_node_id());
					}
				}

				// There's no problem signing a counterparty's funding transaction if our monitor
				// hasn't persisted to disk yet - we can't lose money on a transaction that we haven't
				// accepted payment from yet. We do, however, need to wait to send our channel_ready
				// until we have persisted our monitor.
				let new_channel_id = funding_msg.channel_id;
				peer_state.pending_msg_events.push(events::MessageSendEvent::SendFundingSigned {
					node_id: counterparty_node_id.clone(),
					msg: funding_msg,
				});

				let monitor_res = self.chain_monitor.watch_channel(monitor.get_funding_txo().0, monitor);

				let chan = e.insert(chan);
				let mut res = handle_new_monitor_update!(self, monitor_res, 0, peer_state_lock, peer_state,
					per_peer_state, chan, MANUALLY_REMOVING, { peer_state.channel_by_id.remove(&new_channel_id) });

				// Note that we reply with the new channel_id in error messages if we gave up on the
				// channel, not the temporary_channel_id. This is compatible with ourselves, but the
				// spec is somewhat ambiguous here. Not a huge deal since we'll send error messages for
				// any messages referencing a previously-closed channel anyway.
				// We do not propagate the monitor update to the user as it would be for a monitor
				// that we didn't manage to store (and that we don't care about - we don't respond
				// with the funding_signed so the channel can never go on chain).
				if let Err(MsgHandleErrInternal { shutdown_finish: Some((res, _)), .. }) = &mut res {
					res.0 = None;
				}
				res
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
			hash_map::Entry::Occupied(mut chan) => {
				let monitor = try_chan_entry!(self,
					chan.get_mut().funding_signed(&msg, best_block, &self.signer_provider, &self.logger), chan);
				let update_res = self.chain_monitor.watch_channel(chan.get().get_funding_txo().unwrap(), monitor);
				let mut res = handle_new_monitor_update!(self, update_res, 0, peer_state_lock, peer_state, per_peer_state, chan);
				if let Err(MsgHandleErrInternal { ref mut shutdown_finish, .. }) = res {
					// We weren't able to watch the channel to begin with, so no updates should be made on
					// it. Previously, full_stack_target found an (unreachable) panic when the
					// monitor update contained within `shutdown_finish` was applied.
					if let Some((ref mut shutdown_finish, _)) = shutdown_finish {
						shutdown_finish.0.take();
					}
				}
				res
			},
			hash_map::Entry::Vacant(_) => return Err(MsgHandleErrInternal::send_err_msg_no_close("Failed to find corresponding channel".to_owned(), msg.channel_id))
		}
	}

	fn internal_channel_ready(&self, counterparty_node_id: &PublicKey, msg: &msgs::ChannelReady) -> Result<(), MsgHandleErrInternal> {
		let per_peer_state = self.per_peer_state.read().unwrap();
		let peer_state_mutex = per_peer_state.get(counterparty_node_id)
			.ok_or_else(|| {
				debug_assert!(false);
				MsgHandleErrInternal::send_err_msg_no_close(format!("Can't find a peer matching the passed counterparty node_id {}", counterparty_node_id), msg.channel_id)
			})?;
		let mut peer_state_lock = peer_state_mutex.lock().unwrap();
		let peer_state = &mut *peer_state_lock;
		match peer_state.channel_by_id.entry(msg.channel_id) {
			hash_map::Entry::Occupied(mut chan) => {
				let announcement_sigs_opt = try_chan_entry!(self, chan.get_mut().channel_ready(&msg, &self.node_signer,
					self.genesis_hash.clone(), &self.default_configuration, &self.best_block.read().unwrap(), &self.logger), chan);
				if let Some(announcement_sigs) = announcement_sigs_opt {
					log_trace!(self.logger, "Sending announcement_signatures for channel {}", log_bytes!(chan.get().channel_id()));
					peer_state.pending_msg_events.push(events::MessageSendEvent::SendAnnouncementSignatures {
						node_id: counterparty_node_id.clone(),
						msg: announcement_sigs,
					});
				} else if chan.get().is_usable() {
					// If we're sending an announcement_signatures, we'll send the (public)
					// channel_update after sending a channel_announcement when we receive our
					// counterparty's announcement_signatures. Thus, we only bother to send a
					// channel_update here if the channel is not public, i.e. we're not sending an
					// announcement_signatures.
					log_trace!(self.logger, "Sending private initial channel_update for our counterparty on channel {}", log_bytes!(chan.get().channel_id()));
					if let Ok(msg) = self.get_channel_update_for_unicast(chan.get()) {
						peer_state.pending_msg_events.push(events::MessageSendEvent::SendChannelUpdate {
							node_id: counterparty_node_id.clone(),
							msg,
						});
					}
				}

				emit_channel_ready_event!(self, chan.get_mut());

				Ok(())
			},
			hash_map::Entry::Vacant(_) => Err(MsgHandleErrInternal::send_err_msg_no_close(format!("Got a message for a channel from the wrong node! No such channel for the passed counterparty_node_id {}", counterparty_node_id), msg.channel_id))
		}
	}

	fn internal_shutdown(&self, counterparty_node_id: &PublicKey, msg: &msgs::Shutdown) -> Result<(), MsgHandleErrInternal> {
		let mut dropped_htlcs: Vec<(HTLCSource, PaymentHash)>;
		let result: Result<(), _> = loop {
			let per_peer_state = self.per_peer_state.read().unwrap();
			let peer_state_mutex = per_peer_state.get(counterparty_node_id)
				.ok_or_else(|| {
					debug_assert!(false);
					MsgHandleErrInternal::send_err_msg_no_close(format!("Can't find a peer matching the passed counterparty node_id {}", counterparty_node_id), msg.channel_id)
				})?;
			let mut peer_state_lock = peer_state_mutex.lock().unwrap();
			let peer_state = &mut *peer_state_lock;
			match peer_state.channel_by_id.entry(msg.channel_id.clone()) {
				hash_map::Entry::Occupied(mut chan_entry) => {

					if !chan_entry.get().received_shutdown() {
						log_info!(self.logger, "Received a shutdown message from our counterparty for channel {}{}.",
							log_bytes!(msg.channel_id),
							if chan_entry.get().sent_shutdown() { " after we initiated shutdown" } else { "" });
					}

					let funding_txo_opt = chan_entry.get().get_funding_txo();
					let (shutdown, monitor_update_opt, htlcs) = try_chan_entry!(self,
						chan_entry.get_mut().shutdown(&self.signer_provider, &peer_state.latest_features, &msg), chan_entry);
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
						let update_id = monitor_update.update_id;
						let update_res = self.chain_monitor.update_channel(funding_txo_opt.unwrap(), monitor_update);
						break handle_new_monitor_update!(self, update_res, update_id, peer_state_lock, peer_state, per_peer_state, chan_entry);
					}
					break Ok(());
				},
				hash_map::Entry::Vacant(_) => return Err(MsgHandleErrInternal::send_err_msg_no_close(format!("Got a message for a channel from the wrong node! No such channel for the passed counterparty_node_id {}", counterparty_node_id), msg.channel_id))
			}
		};
		for htlc_source in dropped_htlcs.drain(..) {
			let receiver = HTLCDestination::NextHopChannel { node_id: Some(counterparty_node_id.clone()), channel_id: msg.channel_id };
			let reason = HTLCFailReason::from_failure_code(0x4000 | 8);
			self.fail_htlc_backwards_internal(&htlc_source.0, &htlc_source.1, &reason, receiver);
		}

		result
	}

	fn internal_closing_signed(&self, counterparty_node_id: &PublicKey, msg: &msgs::ClosingSigned) -> Result<(), MsgHandleErrInternal> {
		let per_peer_state = self.per_peer_state.read().unwrap();
		let peer_state_mutex = per_peer_state.get(counterparty_node_id)
			.ok_or_else(|| {
				debug_assert!(false);
				MsgHandleErrInternal::send_err_msg_no_close(format!("Can't find a peer matching the passed counterparty node_id {}", counterparty_node_id), msg.channel_id)
			})?;
		let (tx, chan_option) = {
			let mut peer_state_lock = peer_state_mutex.lock().unwrap();
			let peer_state = &mut *peer_state_lock;
			match peer_state.channel_by_id.entry(msg.channel_id.clone()) {
				hash_map::Entry::Occupied(mut chan_entry) => {
					let (closing_signed, tx) = try_chan_entry!(self, chan_entry.get_mut().closing_signed(&self.fee_estimator, &msg), chan_entry);
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
						(tx, Some(remove_channel!(self, chan_entry)))
					} else { (tx, None) }
				},
				hash_map::Entry::Vacant(_) => return Err(MsgHandleErrInternal::send_err_msg_no_close(format!("Got a message for a channel from the wrong node! No such channel for the passed counterparty_node_id {}", counterparty_node_id), msg.channel_id))
			}
		};
		if let Some(broadcast_tx) = tx {
			log_info!(self.logger, "Broadcasting {}", log_tx!(broadcast_tx));
			self.tx_broadcaster.broadcast_transaction(&broadcast_tx);
		}
		if let Some(chan) = chan_option {
			if let Ok(update) = self.get_channel_update_for_broadcast(&chan) {
				let mut peer_state_lock = peer_state_mutex.lock().unwrap();
				let peer_state = &mut *peer_state_lock;
				peer_state.pending_msg_events.push(events::MessageSendEvent::BroadcastChannelUpdate {
					msg: update
				});
			}
			self.issue_channel_close_events(&chan, ClosureReason::CooperativeClosure);
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

		let pending_forward_info = self.decode_update_add_htlc_onion(msg);
		let per_peer_state = self.per_peer_state.read().unwrap();
		let peer_state_mutex = per_peer_state.get(counterparty_node_id)
			.ok_or_else(|| {
				debug_assert!(false);
				MsgHandleErrInternal::send_err_msg_no_close(format!("Can't find a peer matching the passed counterparty node_id {}", counterparty_node_id), msg.channel_id)
			})?;
		let mut peer_state_lock = peer_state_mutex.lock().unwrap();
		let peer_state = &mut *peer_state_lock;
		match peer_state.channel_by_id.entry(msg.channel_id) {
			hash_map::Entry::Occupied(mut chan) => {

				let create_pending_htlc_status = |chan: &Channel<<SP::Target as SignerProvider>::Signer>, pending_forward_info: PendingHTLCStatus, error_code: u16| {
					// If the update_add is completely bogus, the call will Err and we will close,
					// but if we've sent a shutdown and they haven't acknowledged it yet, we just
					// want to reject the new HTLC and fail it backwards instead of forwarding.
					match pending_forward_info {
						PendingHTLCStatus::Forward(PendingHTLCInfo { ref incoming_shared_secret, .. }) => {
							let reason = if (error_code & 0x1000) != 0 {
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
							PendingHTLCStatus::Fail(HTLCFailureMsg::Relay(msg))
						},
						_ => pending_forward_info
					}
				};
				try_chan_entry!(self, chan.get_mut().update_add_htlc(&msg, pending_forward_info, create_pending_htlc_status, &self.logger), chan);
			},
			hash_map::Entry::Vacant(_) => return Err(MsgHandleErrInternal::send_err_msg_no_close(format!("Got a message for a channel from the wrong node! No such channel for the passed counterparty_node_id {}", counterparty_node_id), msg.channel_id))
		}
		Ok(())
	}

	fn internal_update_fulfill_htlc(&self, counterparty_node_id: &PublicKey, msg: &msgs::UpdateFulfillHTLC) -> Result<(), MsgHandleErrInternal> {
		let (htlc_source, forwarded_htlc_value) = {
			let per_peer_state = self.per_peer_state.read().unwrap();
			let peer_state_mutex = per_peer_state.get(counterparty_node_id)
				.ok_or_else(|| {
					debug_assert!(false);
					MsgHandleErrInternal::send_err_msg_no_close(format!("Can't find a peer matching the passed counterparty node_id {}", counterparty_node_id), msg.channel_id)
				})?;
			let mut peer_state_lock = peer_state_mutex.lock().unwrap();
			let peer_state = &mut *peer_state_lock;
			match peer_state.channel_by_id.entry(msg.channel_id) {
				hash_map::Entry::Occupied(mut chan) => {
					try_chan_entry!(self, chan.get_mut().update_fulfill_htlc(&msg), chan)
				},
				hash_map::Entry::Vacant(_) => return Err(MsgHandleErrInternal::send_err_msg_no_close(format!("Got a message for a channel from the wrong node! No such channel for the passed counterparty_node_id {}", counterparty_node_id), msg.channel_id))
			}
		};
		self.claim_funds_internal(htlc_source, msg.payment_preimage.clone(), Some(forwarded_htlc_value), false, msg.channel_id);
		Ok(())
	}

	fn internal_update_fail_htlc(&self, counterparty_node_id: &PublicKey, msg: &msgs::UpdateFailHTLC) -> Result<(), MsgHandleErrInternal> {
		let per_peer_state = self.per_peer_state.read().unwrap();
		let peer_state_mutex = per_peer_state.get(counterparty_node_id)
			.ok_or_else(|| {
				debug_assert!(false);
				MsgHandleErrInternal::send_err_msg_no_close(format!("Can't find a peer matching the passed counterparty node_id {}", counterparty_node_id), msg.channel_id)
			})?;
		let mut peer_state_lock = peer_state_mutex.lock().unwrap();
		let peer_state = &mut *peer_state_lock;
		match peer_state.channel_by_id.entry(msg.channel_id) {
			hash_map::Entry::Occupied(mut chan) => {
				try_chan_entry!(self, chan.get_mut().update_fail_htlc(&msg, HTLCFailReason::from_msg(msg)), chan);
			},
			hash_map::Entry::Vacant(_) => return Err(MsgHandleErrInternal::send_err_msg_no_close(format!("Got a message for a channel from the wrong node! No such channel for the passed counterparty_node_id {}", counterparty_node_id), msg.channel_id))
		}
		Ok(())
	}

	fn internal_update_fail_malformed_htlc(&self, counterparty_node_id: &PublicKey, msg: &msgs::UpdateFailMalformedHTLC) -> Result<(), MsgHandleErrInternal> {
		let per_peer_state = self.per_peer_state.read().unwrap();
		let peer_state_mutex = per_peer_state.get(counterparty_node_id)
			.ok_or_else(|| {
				debug_assert!(false);
				MsgHandleErrInternal::send_err_msg_no_close(format!("Can't find a peer matching the passed counterparty node_id {}", counterparty_node_id), msg.channel_id)
			})?;
		let mut peer_state_lock = peer_state_mutex.lock().unwrap();
		let peer_state = &mut *peer_state_lock;
		match peer_state.channel_by_id.entry(msg.channel_id) {
			hash_map::Entry::Occupied(mut chan) => {
				if (msg.failure_code & 0x8000) == 0 {
					let chan_err: ChannelError = ChannelError::Close("Got update_fail_malformed_htlc with BADONION not set".to_owned());
					try_chan_entry!(self, Err(chan_err), chan);
				}
				try_chan_entry!(self, chan.get_mut().update_fail_malformed_htlc(&msg, HTLCFailReason::reason(msg.failure_code, msg.sha256_of_onion.to_vec())), chan);
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
			hash_map::Entry::Occupied(mut chan) => {
				let funding_txo = chan.get().get_funding_txo();
				let monitor_update = try_chan_entry!(self, chan.get_mut().commitment_signed(&msg, &self.logger), chan);
				let update_res = self.chain_monitor.update_channel(funding_txo.unwrap(), monitor_update);
				let update_id = monitor_update.update_id;
				handle_new_monitor_update!(self, update_res, update_id, peer_state_lock,
					peer_state, per_peer_state, chan)
			},
			hash_map::Entry::Vacant(_) => return Err(MsgHandleErrInternal::send_err_msg_no_close(format!("Got a message for a channel from the wrong node! No such channel for the passed counterparty_node_id {}", counterparty_node_id), msg.channel_id))
		}
	}

	#[inline]
	fn forward_htlcs(&self, per_source_pending_forwards: &mut [(u64, OutPoint, u128, Vec<(PendingHTLCInfo, u64)>)]) {
		for &mut (prev_short_channel_id, prev_funding_outpoint, prev_user_channel_id, ref mut pending_forwards) in per_source_pending_forwards {
			let mut push_forward_event = false;
			let mut new_intercept_events = Vec::new();
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

					let mut forward_htlcs = self.forward_htlcs.lock().unwrap();
					let forward_htlcs_empty = forward_htlcs.is_empty();
					match forward_htlcs.entry(scid) {
						hash_map::Entry::Occupied(mut entry) => {
							entry.get_mut().push(HTLCForwardInfo::AddHTLC(PendingAddHTLCInfo {
								prev_short_channel_id, prev_funding_outpoint, prev_htlc_id, prev_user_channel_id, forward_info }));
						},
						hash_map::Entry::Vacant(entry) => {
							if !is_our_scid && forward_info.incoming_amt_msat.is_some() &&
							   fake_scid::is_valid_intercept(&self.fake_scid_rand_bytes, scid, &self.genesis_hash)
							{
								let intercept_id = InterceptId(Sha256::hash(&forward_info.incoming_shared_secret).into_inner());
								let mut pending_intercepts = self.pending_intercepted_htlcs.lock().unwrap();
								match pending_intercepts.entry(intercept_id) {
									hash_map::Entry::Vacant(entry) => {
										new_intercept_events.push(events::Event::HTLCIntercepted {
											requested_next_hop_scid: scid,
											payment_hash: forward_info.payment_hash,
											inbound_amount_msat: forward_info.incoming_amt_msat.unwrap(),
											expected_outbound_amount_msat: forward_info.outgoing_amt_msat,
											intercept_id
										});
										entry.insert(PendingAddHTLCInfo {
											prev_short_channel_id, prev_funding_outpoint, prev_htlc_id, prev_user_channel_id, forward_info });
									},
									hash_map::Entry::Occupied(_) => {
										log_info!(self.logger, "Failed to forward incoming HTLC: detected duplicate intercepted payment over short channel id {}", scid);
										let htlc_source = HTLCSource::PreviousHopData(HTLCPreviousHopData {
											short_channel_id: prev_short_channel_id,
											outpoint: prev_funding_outpoint,
											htlc_id: prev_htlc_id,
											incoming_packet_shared_secret: forward_info.incoming_shared_secret,
											phantom_shared_secret: None,
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
								if forward_htlcs_empty {
									push_forward_event = true;
								}
								entry.insert(vec!(HTLCForwardInfo::AddHTLC(PendingAddHTLCInfo {
									prev_short_channel_id, prev_funding_outpoint, prev_htlc_id, prev_user_channel_id, forward_info })));
							}
						}
					}
				}
			}

			for (htlc_source, payment_hash, failure_reason, destination) in failed_intercept_forwards.drain(..) {
				self.fail_htlc_backwards_internal(&htlc_source, &payment_hash, &failure_reason, destination);
			}

			if !new_intercept_events.is_empty() {
				let mut events = self.pending_events.lock().unwrap();
				events.append(&mut new_intercept_events);
			}
			if push_forward_event { self.push_pending_forwards_ev() }
		}
	}

	// We only want to push a PendingHTLCsForwardable event if no others are queued.
	fn push_pending_forwards_ev(&self) {
		let mut pending_events = self.pending_events.lock().unwrap();
		let forward_ev_exists = pending_events.iter()
			.find(|ev| if let events::Event::PendingHTLCsForwardable { .. } = ev { true } else { false })
			.is_some();
		if !forward_ev_exists {
			pending_events.push(events::Event::PendingHTLCsForwardable {
				time_forwardable:
					Duration::from_millis(MIN_HTLC_RELAY_HOLDING_CELL_MILLIS),
			});
		}
	}

	fn internal_revoke_and_ack(&self, counterparty_node_id: &PublicKey, msg: &msgs::RevokeAndACK) -> Result<(), MsgHandleErrInternal> {
		let (htlcs_to_fail, res) = {
			let per_peer_state = self.per_peer_state.read().unwrap();
			let mut peer_state_lock = per_peer_state.get(counterparty_node_id)
				.ok_or_else(|| {
					debug_assert!(false);
					MsgHandleErrInternal::send_err_msg_no_close(format!("Can't find a peer matching the passed counterparty node_id {}", counterparty_node_id), msg.channel_id)
				}).map(|mtx| mtx.lock().unwrap())?;
			let peer_state = &mut *peer_state_lock;
			match peer_state.channel_by_id.entry(msg.channel_id) {
				hash_map::Entry::Occupied(mut chan) => {
					let funding_txo = chan.get().get_funding_txo();
					let (htlcs_to_fail, monitor_update) = try_chan_entry!(self, chan.get_mut().revoke_and_ack(&msg, &self.logger), chan);
					let update_res = self.chain_monitor.update_channel(funding_txo.unwrap(), monitor_update);
					let update_id = monitor_update.update_id;
					let res = handle_new_monitor_update!(self, update_res, update_id,
						peer_state_lock, peer_state, per_peer_state, chan);
					(htlcs_to_fail, res)
				},
				hash_map::Entry::Vacant(_) => return Err(MsgHandleErrInternal::send_err_msg_no_close(format!("Got a message for a channel from the wrong node! No such channel for the passed counterparty_node_id {}", counterparty_node_id), msg.channel_id))
			}
		};
		self.fail_holding_cell_htlcs(htlcs_to_fail, msg.channel_id, counterparty_node_id);
		res
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
			hash_map::Entry::Occupied(mut chan) => {
				try_chan_entry!(self, chan.get_mut().update_fee(&self.fee_estimator, &msg, &self.logger), chan);
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
			hash_map::Entry::Occupied(mut chan) => {
				if !chan.get().is_usable() {
					return Err(MsgHandleErrInternal::from_no_close(LightningError{err: "Got an announcement_signatures before we were ready for it".to_owned(), action: msgs::ErrorAction::IgnoreError}));
				}

				peer_state.pending_msg_events.push(events::MessageSendEvent::BroadcastChannelAnnouncement {
					msg: try_chan_entry!(self, chan.get_mut().announcement_signatures(
						&self.node_signer, self.genesis_hash.clone(), self.best_block.read().unwrap().height(),
						msg, &self.default_configuration
					), chan),
					// Note that announcement_signatures fails if the channel cannot be announced,
					// so get_channel_update_for_broadcast will never fail by the time we get here.
					update_msg: Some(self.get_channel_update_for_broadcast(chan.get()).unwrap()),
				});
			},
			hash_map::Entry::Vacant(_) => return Err(MsgHandleErrInternal::send_err_msg_no_close(format!("Got a message for a channel from the wrong node! No such channel for the passed counterparty_node_id {}", counterparty_node_id), msg.channel_id))
		}
		Ok(())
	}

	/// Returns ShouldPersist if anything changed, otherwise either SkipPersist or an Err.
	fn internal_channel_update(&self, counterparty_node_id: &PublicKey, msg: &msgs::ChannelUpdate) -> Result<NotifyOption, MsgHandleErrInternal> {
		let (chan_counterparty_node_id, chan_id) = match self.short_to_chan_info.read().unwrap().get(&msg.contents.short_channel_id) {
			Some((cp_id, chan_id)) => (cp_id.clone(), chan_id.clone()),
			None => {
				// It's not a local channel
				return Ok(NotifyOption::SkipPersist)
			}
		};
		let per_peer_state = self.per_peer_state.read().unwrap();
		let peer_state_mutex_opt = per_peer_state.get(&chan_counterparty_node_id);
		if peer_state_mutex_opt.is_none() {
			return Ok(NotifyOption::SkipPersist)
		}
		let mut peer_state_lock = peer_state_mutex_opt.unwrap().lock().unwrap();
		let peer_state = &mut *peer_state_lock;
		match peer_state.channel_by_id.entry(chan_id) {
			hash_map::Entry::Occupied(mut chan) => {
				if chan.get().get_counterparty_node_id() != *counterparty_node_id {
					if chan.get().should_announce() {
						// If the announcement is about a channel of ours which is public, some
						// other peer may simply be forwarding all its gossip to us. Don't provide
						// a scary-looking error message and return Ok instead.
						return Ok(NotifyOption::SkipPersist);
					}
					return Err(MsgHandleErrInternal::send_err_msg_no_close("Got a channel_update for a channel from the wrong node - it shouldn't know about our private channels!".to_owned(), chan_id));
				}
				let were_node_one = self.get_our_node_id().serialize()[..] < chan.get().get_counterparty_node_id().serialize()[..];
				let msg_from_node_one = msg.contents.flags & 1 == 0;
				if were_node_one == msg_from_node_one {
					return Ok(NotifyOption::SkipPersist);
				} else {
					log_debug!(self.logger, "Received channel_update for channel {}.", log_bytes!(chan_id));
					try_chan_entry!(self, chan.get_mut().channel_update(&msg), chan);
				}
			},
			hash_map::Entry::Vacant(_) => return Ok(NotifyOption::SkipPersist)
		}
		Ok(NotifyOption::DoPersist)
	}

	fn internal_channel_reestablish(&self, counterparty_node_id: &PublicKey, msg: &msgs::ChannelReestablish) -> Result<(), MsgHandleErrInternal> {
		let htlc_forwards;
		let need_lnd_workaround = {
			let per_peer_state = self.per_peer_state.read().unwrap();

			let peer_state_mutex = per_peer_state.get(counterparty_node_id)
				.ok_or_else(|| {
					debug_assert!(false);
					MsgHandleErrInternal::send_err_msg_no_close(format!("Can't find a peer matching the passed counterparty node_id {}", counterparty_node_id), msg.channel_id)
				})?;
			let mut peer_state_lock = peer_state_mutex.lock().unwrap();
			let peer_state = &mut *peer_state_lock;
			match peer_state.channel_by_id.entry(msg.channel_id) {
				hash_map::Entry::Occupied(mut chan) => {
					// Currently, we expect all holding cell update_adds to be dropped on peer
					// disconnect, so Channel's reestablish will never hand us any holding cell
					// freed HTLCs to fail backwards. If in the future we no longer drop pending
					// add-HTLCs on disconnect, we may be handed HTLCs to fail backwards here.
					let responses = try_chan_entry!(self, chan.get_mut().channel_reestablish(
						msg, &self.logger, &self.node_signer, self.genesis_hash,
						&self.default_configuration, &*self.best_block.read().unwrap()), chan);
					let mut channel_update = None;
					if let Some(msg) = responses.shutdown_msg {
						peer_state.pending_msg_events.push(events::MessageSendEvent::SendShutdown {
							node_id: counterparty_node_id.clone(),
							msg,
						});
					} else if chan.get().is_usable() {
						// If the channel is in a usable state (ie the channel is not being shut
						// down), send a unicast channel_update to our counterparty to make sure
						// they have the latest channel parameters.
						if let Ok(msg) = self.get_channel_update_for_unicast(chan.get()) {
							channel_update = Some(events::MessageSendEvent::SendChannelUpdate {
								node_id: chan.get().get_counterparty_node_id(),
								msg,
							});
						}
					}
					let need_lnd_workaround = chan.get_mut().workaround_lnd_bug_4006.take();
					htlc_forwards = self.handle_channel_resumption(
						&mut peer_state.pending_msg_events, chan.get_mut(), responses.raa, responses.commitment_update, responses.order,
						Vec::new(), None, responses.channel_ready, responses.announcement_sigs);
					if let Some(upd) = channel_update {
						peer_state.pending_msg_events.push(upd);
					}
					need_lnd_workaround
				},
				hash_map::Entry::Vacant(_) => return Err(MsgHandleErrInternal::send_err_msg_no_close(format!("Got a message for a channel from the wrong node! No such channel for the passed counterparty_node_id {}", counterparty_node_id), msg.channel_id))
			}
		};

		if let Some(forwards) = htlc_forwards {
			self.forward_htlcs(&mut [forwards][..]);
		}

		if let Some(channel_ready_msg) = need_lnd_workaround {
			self.internal_channel_ready(counterparty_node_id, &channel_ready_msg)?;
		}
		Ok(())
	}

	/// Process pending events from the `chain::Watch`, returning whether any events were processed.
	fn process_pending_monitor_events(&self) -> bool {
		debug_assert!(self.total_consistency_lock.try_write().is_err()); // Caller holds read lock

		let mut failed_channels = Vec::new();
		let mut pending_monitor_events = self.chain_monitor.release_pending_monitor_events();
		let has_pending_monitor_events = !pending_monitor_events.is_empty();
		for (funding_outpoint, mut monitor_events, counterparty_node_id) in pending_monitor_events.drain(..) {
			for monitor_event in monitor_events.drain(..) {
				match monitor_event {
					MonitorEvent::HTLCEvent(htlc_update) => {
						if let Some(preimage) = htlc_update.payment_preimage {
							log_trace!(self.logger, "Claiming HTLC with preimage {} from our monitor", log_bytes!(preimage.0));
							self.claim_funds_internal(htlc_update.source, preimage, htlc_update.htlc_value_satoshis.map(|v| v * 1000), true, funding_outpoint.to_channel_id());
						} else {
							log_trace!(self.logger, "Failing HTLC with hash {} from our monitor", log_bytes!(htlc_update.payment_hash.0));
							let receiver = HTLCDestination::NextHopChannel { node_id: counterparty_node_id, channel_id: funding_outpoint.to_channel_id() };
							let reason = HTLCFailReason::from_failure_code(0x4000 | 8);
							self.fail_htlc_backwards_internal(&htlc_update.source, &htlc_update.payment_hash, &reason, receiver);
						}
					},
					MonitorEvent::CommitmentTxConfirmed(funding_outpoint) |
					MonitorEvent::UpdateFailed(funding_outpoint) => {
						let counterparty_node_id_opt = match counterparty_node_id {
							Some(cp_id) => Some(cp_id),
							None => {
								// TODO: Once we can rely on the counterparty_node_id from the
								// monitor event, this and the id_to_peer map should be removed.
								let id_to_peer = self.id_to_peer.lock().unwrap();
								id_to_peer.get(&funding_outpoint.to_channel_id()).cloned()
							}
						};
						if let Some(counterparty_node_id) = counterparty_node_id_opt {
							let per_peer_state = self.per_peer_state.read().unwrap();
							if let Some(peer_state_mutex) = per_peer_state.get(&counterparty_node_id) {
								let mut peer_state_lock = peer_state_mutex.lock().unwrap();
								let peer_state = &mut *peer_state_lock;
								let pending_msg_events = &mut peer_state.pending_msg_events;
								if let hash_map::Entry::Occupied(chan_entry) = peer_state.channel_by_id.entry(funding_outpoint.to_channel_id()) {
									let mut chan = remove_channel!(self, chan_entry);
									failed_channels.push(chan.force_shutdown(false));
									if let Ok(update) = self.get_channel_update_for_broadcast(&chan) {
										pending_msg_events.push(events::MessageSendEvent::BroadcastChannelUpdate {
											msg: update
										});
									}
									let reason = if let MonitorEvent::UpdateFailed(_) = monitor_event {
										ClosureReason::ProcessingError { err: "Failed to persist ChannelMonitor update during chain sync".to_string() }
									} else {
										ClosureReason::CommitmentTxConfirmed
									};
									self.issue_channel_close_events(&chan, reason);
									pending_msg_events.push(events::MessageSendEvent::HandleError {
										node_id: chan.get_counterparty_node_id(),
										action: msgs::ErrorAction::SendErrorMessage {
											msg: msgs::ErrorMessage { channel_id: chan.channel_id(), data: "Channel force-closed".to_owned() }
										},
									});
								}
							}
						}
					},
					MonitorEvent::Completed { funding_txo, monitor_update_id } => {
						self.channel_monitor_updated(&funding_txo, monitor_update_id, counterparty_node_id.as_ref());
					},
				}
			}
		}

		for failure in failed_channels.drain(..) {
			self.finish_force_close_channel(failure);
		}

		has_pending_monitor_events
	}

	/// In chanmon_consistency_target, we'd like to be able to restore monitor updating without
	/// handling all pending events (i.e. not PendingHTLCsForwardable). Thus, we expose monitor
	/// update events as a separate process method here.
	#[cfg(fuzzing)]
	pub fn process_monitor_events(&self) {
		PersistenceNotifierGuard::optionally_notify(&self.total_consistency_lock, &self.persistence_notifier, || {
			if self.process_pending_monitor_events() {
				NotifyOption::DoPersist
			} else {
				NotifyOption::SkipPersist
			}
		});
	}

	/// Check the holding cell in each channel and free any pending HTLCs in them if possible.
	/// Returns whether there were any updates such as if pending HTLCs were freed or a monitor
	/// update was applied.
	fn check_free_holding_cells(&self) -> bool {
		let mut has_monitor_update = false;
		let mut failed_htlcs = Vec::new();
		let mut handle_errors = Vec::new();

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
					for (channel_id, chan) in peer_state.channel_by_id.iter_mut() {
						let counterparty_node_id = chan.get_counterparty_node_id();
						let funding_txo = chan.get_funding_txo();
						let (monitor_opt, holding_cell_failed_htlcs) =
							chan.maybe_free_holding_cell_htlcs(&self.logger);
						if !holding_cell_failed_htlcs.is_empty() {
							failed_htlcs.push((holding_cell_failed_htlcs, *channel_id, counterparty_node_id));
						}
						if let Some(monitor_update) = monitor_opt {
							has_monitor_update = true;

							let update_res = self.chain_monitor.update_channel(
								funding_txo.expect("channel is live"), monitor_update);
							let update_id = monitor_update.update_id;
							let channel_id: [u8; 32] = *channel_id;
							let res = handle_new_monitor_update!(self, update_res, update_id,
								peer_state_lock, peer_state, per_peer_state, chan, MANUALLY_REMOVING,
								peer_state.channel_by_id.remove(&channel_id));
							if res.is_err() {
								handle_errors.push((counterparty_node_id, res));
							}
							continue 'peer_loop;
						}
					}
					break 'chan_loop;
				}
			}
			break 'peer_loop;
		}

		let has_update = has_monitor_update || !failed_htlcs.is_empty() || !handle_errors.is_empty();
		for (failures, channel_id, counterparty_node_id) in failed_htlcs.drain(..) {
			self.fail_holding_cell_htlcs(failures, channel_id, &counterparty_node_id);
		}

		for (counterparty_node_id, err) in handle_errors.drain(..) {
			let _ = handle_error!(self, err, counterparty_node_id);
		}

		has_update
	}

	/// Check whether any channels have finished removing all pending updates after a shutdown
	/// exchange and can now send a closing_signed.
	/// Returns whether any closing_signed messages were generated.
	fn maybe_generate_initial_closing_signed(&self) -> bool {
		let mut handle_errors: Vec<(PublicKey, Result<(), _>)> = Vec::new();
		let mut has_update = false;
		{
			let per_peer_state = self.per_peer_state.read().unwrap();

			for (_cp_id, peer_state_mutex) in per_peer_state.iter() {
				let mut peer_state_lock = peer_state_mutex.lock().unwrap();
				let peer_state = &mut *peer_state_lock;
				let pending_msg_events = &mut peer_state.pending_msg_events;
				peer_state.channel_by_id.retain(|channel_id, chan| {
					match chan.maybe_propose_closing_signed(&self.fee_estimator, &self.logger) {
						Ok((msg_opt, tx_opt)) => {
							if let Some(msg) = msg_opt {
								has_update = true;
								pending_msg_events.push(events::MessageSendEvent::SendClosingSigned {
									node_id: chan.get_counterparty_node_id(), msg,
								});
							}
							if let Some(tx) = tx_opt {
								// We're done with this channel. We got a closing_signed and sent back
								// a closing_signed with a closing transaction to broadcast.
								if let Ok(update) = self.get_channel_update_for_broadcast(&chan) {
									pending_msg_events.push(events::MessageSendEvent::BroadcastChannelUpdate {
										msg: update
									});
								}

								self.issue_channel_close_events(chan, ClosureReason::CooperativeClosure);

								log_info!(self.logger, "Broadcasting {}", log_tx!(tx));
								self.tx_broadcaster.broadcast_transaction(&tx);
								update_maps_on_chan_removal!(self, chan);
								false
							} else { true }
						},
						Err(e) => {
							has_update = true;
							let (close_channel, res) = convert_chan_err!(self, e, chan, channel_id);
							handle_errors.push((chan.get_counterparty_node_id(), Err(res)));
							!close_channel
						}
					}
				});
			}
		}

		for (counterparty_node_id, err) in handle_errors.drain(..) {
			let _ = handle_error!(self, err, counterparty_node_id);
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
			if let Some((funding_txo, update)) = failure.0.take() {
				assert_eq!(update.updates.len(), 1);
				if let ChannelMonitorUpdateStep::ChannelForceClosed { should_broadcast } = update.updates[0] {
					assert!(should_broadcast);
				} else { unreachable!(); }
				self.pending_background_events.lock().unwrap().push(BackgroundEvent::ClosingMonitorUpdate((funding_txo, update)));
			}
			self.finish_force_close_channel(failure);
		}
	}

	fn set_payment_hash_secret_map(&self, payment_hash: PaymentHash, payment_preimage: Option<PaymentPreimage>, min_value_msat: Option<u64>, invoice_expiry_delta_secs: u32) -> Result<PaymentSecret, APIError> {
		assert!(invoice_expiry_delta_secs <= 60*60*24*365); // Sadly bitcoin timestamps are u32s, so panic before 2106

		if min_value_msat.is_some() && min_value_msat.unwrap() > MAX_VALUE_MSAT {
			return Err(APIError::APIMisuseError { err: format!("min_value_msat of {} greater than total 21 million bitcoin supply", min_value_msat.unwrap()) });
		}

		let payment_secret = PaymentSecret(self.entropy_source.get_secure_random_bytes());

		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(&self.total_consistency_lock, &self.persistence_notifier);
		let mut payment_secrets = self.pending_inbound_payments.lock().unwrap();
		match payment_secrets.entry(payment_hash) {
			hash_map::Entry::Vacant(e) => {
				e.insert(PendingInboundPayment {
					payment_secret, min_value_msat, payment_preimage,
					user_payment_id: 0, // For compatibility with version 0.0.103 and earlier
					// We assume that highest_seen_timestamp is pretty close to the current time -
					// it's updated when we receive a new block with the maximum time we've seen in
					// a header. It should never be more than two hours in the future.
					// Thus, we add two hours here as a buffer to ensure we absolutely
					// never fail a payment too early.
					// Note that we assume that received blocks have reasonably up-to-date
					// timestamps.
					expiry_time: self.highest_seen_timestamp.load(Ordering::Acquire) as u64 + invoice_expiry_delta_secs as u64 + 7200,
				});
			},
			hash_map::Entry::Occupied(_) => return Err(APIError::APIMisuseError { err: "Duplicate payment hash".to_owned() }),
		}
		Ok(payment_secret)
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

	/// Legacy version of [`create_inbound_payment`]. Use this method if you wish to share
	/// serialized state with LDK node(s) running 0.0.103 and earlier.
	///
	/// May panic if `invoice_expiry_delta_secs` is greater than one year.
	///
	/// # Note
	/// This method is deprecated and will be removed soon.
	///
	/// [`create_inbound_payment`]: Self::create_inbound_payment
	#[deprecated]
	pub fn create_inbound_payment_legacy(&self, min_value_msat: Option<u64>, invoice_expiry_delta_secs: u32) -> Result<(PaymentHash, PaymentSecret), APIError> {
		let payment_preimage = PaymentPreimage(self.entropy_source.get_secure_random_bytes());
		let payment_hash = PaymentHash(Sha256::hash(&payment_preimage.0).into_inner());
		let payment_secret = self.set_payment_hash_secret_map(payment_hash, Some(payment_preimage), min_value_msat, invoice_expiry_delta_secs)?;
		Ok((payment_hash, payment_secret))
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

	/// Legacy version of [`create_inbound_payment_for_hash`]. Use this method if you wish to share
	/// serialized state with LDK node(s) running 0.0.103 and earlier.
	///
	/// May panic if `invoice_expiry_delta_secs` is greater than one year.
	///
	/// # Note
	/// This method is deprecated and will be removed soon.
	///
	/// [`create_inbound_payment_for_hash`]: Self::create_inbound_payment_for_hash
	#[deprecated]
	pub fn create_inbound_payment_for_hash_legacy(&self, payment_hash: PaymentHash, min_value_msat: Option<u64>, invoice_expiry_delta_secs: u32) -> Result<PaymentSecret, APIError> {
		self.set_payment_hash_secret_map(payment_hash, None, min_value_msat, invoice_expiry_delta_secs)
	}

	/// Gets an LDK-generated payment preimage from a payment hash and payment secret that were
	/// previously returned from [`create_inbound_payment`].
	///
	/// [`create_inbound_payment`]: Self::create_inbound_payment
	pub fn get_payment_preimage(&self, payment_hash: PaymentHash, payment_secret: PaymentSecret) -> Result<PaymentPreimage, APIError> {
		inbound_payment::get_payment_preimage(payment_hash, payment_secret, &self.inbound_payment_key)
	}

	/// Gets a fake short channel id for use in receiving [phantom node payments]. These fake scids
	/// are used when constructing the phantom invoice's route hints.
	///
	/// [phantom node payments]: crate::chain::keysinterface::PhantomKeysManager
	pub fn get_phantom_scid(&self) -> u64 {
		let best_block_height = self.best_block.read().unwrap().height();
		let short_to_chan_info = self.short_to_chan_info.read().unwrap();
		loop {
			let scid_candidate = fake_scid::Namespace::Phantom.get_fake_scid(best_block_height, &self.genesis_hash, &self.fake_scid_rand_bytes, &self.entropy_source);
			// Ensure the generated scid doesn't conflict with a real channel.
			match short_to_chan_info.get(&scid_candidate) {
				Some(_) => continue,
				None => return scid_candidate
			}
		}
	}

	/// Gets route hints for use in receiving [phantom node payments].
	///
	/// [phantom node payments]: crate::chain::keysinterface::PhantomKeysManager
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
		let best_block_height = self.best_block.read().unwrap().height();
		let short_to_chan_info = self.short_to_chan_info.read().unwrap();
		loop {
			let scid_candidate = fake_scid::Namespace::Intercept.get_fake_scid(best_block_height, &self.genesis_hash, &self.fake_scid_rand_bytes, &self.entropy_source);
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
			for chan in peer_state.channel_by_id.values() {
				for (htlc_source, _) in chan.inflight_htlc_sources() {
					if let HTLCSource::OutboundRoute { path, .. } = htlc_source {
						inflight_htlcs.process_path(path, self.get_our_node_id());
					}
				}
			}
		}

		inflight_htlcs
	}

	#[cfg(any(test, fuzzing, feature = "_test_utils"))]
	pub fn get_and_clear_pending_events(&self) -> Vec<events::Event> {
		let events = core::cell::RefCell::new(Vec::new());
		let event_handler = |event: events::Event| events.borrow_mut().push(event);
		self.process_pending_events(&event_handler);
		events.into_inner()
	}

	#[cfg(feature = "_test_utils")]
	pub fn push_pending_event(&self, event: events::Event) {
		let mut events = self.pending_events.lock().unwrap();
		events.push(event);
	}

	#[cfg(test)]
	pub fn pop_pending_event(&self) -> Option<events::Event> {
		let mut events = self.pending_events.lock().unwrap();
		if events.is_empty() { None } else { Some(events.remove(0)) }
	}

	#[cfg(test)]
	pub fn has_pending_payments(&self) -> bool {
		self.pending_outbound_payments.has_pending_payments()
	}

	#[cfg(test)]
	pub fn clear_pending_payments(&self) {
		self.pending_outbound_payments.clear_pending_payments()
	}

	/// Processes any events asynchronously in the order they were generated since the last call
	/// using the given event handler.
	///
	/// See the trait-level documentation of [`EventsProvider`] for requirements.
	pub async fn process_pending_events_async<Future: core::future::Future, H: Fn(Event) -> Future>(
		&self, handler: H
	) {
		// We'll acquire our total consistency lock until the returned future completes so that
		// we can be sure no other persists happen while processing events.
		let _read_guard = self.total_consistency_lock.read().unwrap();

		let mut result = NotifyOption::SkipPersist;

		// TODO: This behavior should be documented. It's unintuitive that we query
		// ChannelMonitors when clearing other events.
		if self.process_pending_monitor_events() {
			result = NotifyOption::DoPersist;
		}

		let pending_events = mem::replace(&mut *self.pending_events.lock().unwrap(), vec![]);
		if !pending_events.is_empty() {
			result = NotifyOption::DoPersist;
		}

		for event in pending_events {
			handler(event).await;
		}

		if result == NotifyOption::DoPersist {
			self.persistence_notifier.notify();
		}
	}
}

impl<M: Deref, T: Deref, ES: Deref, NS: Deref, SP: Deref, F: Deref, R: Deref, L: Deref> MessageSendEventsProvider for ChannelManager<M, T, ES, NS, SP, F, R, L>
where
	M::Target: chain::Watch<<SP::Target as SignerProvider>::Signer>,
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
	/// `MessageSendEvent`s are intended to be broadcasted to all peers, they will be pleaced among
	/// the `MessageSendEvent`s to the specific peer they were generated under.
	fn get_and_clear_pending_msg_events(&self) -> Vec<MessageSendEvent> {
		let events = RefCell::new(Vec::new());
		PersistenceNotifierGuard::optionally_notify(&self.total_consistency_lock, &self.persistence_notifier, || {
			let mut result = NotifyOption::SkipPersist;

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

			let mut pending_events = Vec::new();
			let per_peer_state = self.per_peer_state.read().unwrap();
			for (_cp_id, peer_state_mutex) in per_peer_state.iter() {
				let mut peer_state_lock = peer_state_mutex.lock().unwrap();
				let peer_state = &mut *peer_state_lock;
				if peer_state.pending_msg_events.len() > 0 {
					pending_events.append(&mut peer_state.pending_msg_events);
				}
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
	M::Target: chain::Watch<<SP::Target as SignerProvider>::Signer>,
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
		PersistenceNotifierGuard::optionally_notify(&self.total_consistency_lock, &self.persistence_notifier, || {
			let mut result = NotifyOption::SkipPersist;

			// TODO: This behavior should be documented. It's unintuitive that we query
			// ChannelMonitors when clearing other events.
			if self.process_pending_monitor_events() {
				result = NotifyOption::DoPersist;
			}

			let pending_events = mem::replace(&mut *self.pending_events.lock().unwrap(), vec![]);
			if !pending_events.is_empty() {
				result = NotifyOption::DoPersist;
			}

			for event in pending_events {
				handler.handle_event(event);
			}

			result
		});
	}
}

impl<M: Deref, T: Deref, ES: Deref, NS: Deref, SP: Deref, F: Deref, R: Deref, L: Deref> chain::Listen for ChannelManager<M, T, ES, NS, SP, F, R, L>
where
	M::Target: chain::Watch<<SP::Target as SignerProvider>::Signer>,
	T::Target: BroadcasterInterface,
	ES::Target: EntropySource,
	NS::Target: NodeSigner,
	SP::Target: SignerProvider,
	F::Target: FeeEstimator,
	R::Target: Router,
	L::Target: Logger,
{
	fn filtered_block_connected(&self, header: &BlockHeader, txdata: &TransactionData, height: u32) {
		{
			let best_block = self.best_block.read().unwrap();
			assert_eq!(best_block.block_hash(), header.prev_blockhash,
				"Blocks must be connected in chain-order - the connected header must build on the last connected header");
			assert_eq!(best_block.height(), height - 1,
				"Blocks must be connected in chain-order - the connected block height must be one greater than the previous height");
		}

		self.transactions_confirmed(header, txdata, height);
		self.best_block_updated(header, height);
	}

	fn block_disconnected(&self, header: &BlockHeader, height: u32) {
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(&self.total_consistency_lock, &self.persistence_notifier);
		let new_height = height - 1;
		{
			let mut best_block = self.best_block.write().unwrap();
			assert_eq!(best_block.block_hash(), header.block_hash(),
				"Blocks must be disconnected in chain-order - the disconnected header must be the last connected header");
			assert_eq!(best_block.height(), height,
				"Blocks must be disconnected in chain-order - the disconnected block must have the correct height");
			*best_block = BestBlock::new(header.prev_blockhash, new_height)
		}

		self.do_chain_event(Some(new_height), |channel| channel.best_block_updated(new_height, header.time, self.genesis_hash.clone(), &self.node_signer, &self.default_configuration, &self.logger));
	}
}

impl<M: Deref, T: Deref, ES: Deref, NS: Deref, SP: Deref, F: Deref, R: Deref, L: Deref> chain::Confirm for ChannelManager<M, T, ES, NS, SP, F, R, L>
where
	M::Target: chain::Watch<<SP::Target as SignerProvider>::Signer>,
	T::Target: BroadcasterInterface,
	ES::Target: EntropySource,
	NS::Target: NodeSigner,
	SP::Target: SignerProvider,
	F::Target: FeeEstimator,
	R::Target: Router,
	L::Target: Logger,
{
	fn transactions_confirmed(&self, header: &BlockHeader, txdata: &TransactionData, height: u32) {
		// Note that we MUST NOT end up calling methods on self.chain_monitor here - we're called
		// during initialization prior to the chain_monitor being fully configured in some cases.
		// See the docs for `ChannelManagerReadArgs` for more.

		let block_hash = header.block_hash();
		log_trace!(self.logger, "{} transactions included in block {} at height {} provided", txdata.len(), block_hash, height);

		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(&self.total_consistency_lock, &self.persistence_notifier);
		self.do_chain_event(Some(height), |channel| channel.transactions_confirmed(&block_hash, height, txdata, self.genesis_hash.clone(), &self.node_signer, &self.default_configuration, &self.logger)
			.map(|(a, b)| (a, Vec::new(), b)));

		let last_best_block_height = self.best_block.read().unwrap().height();
		if height < last_best_block_height {
			let timestamp = self.highest_seen_timestamp.load(Ordering::Acquire);
			self.do_chain_event(Some(last_best_block_height), |channel| channel.best_block_updated(last_best_block_height, timestamp as u32, self.genesis_hash.clone(), &self.node_signer, &self.default_configuration, &self.logger));
		}
	}

	fn best_block_updated(&self, header: &BlockHeader, height: u32) {
		// Note that we MUST NOT end up calling methods on self.chain_monitor here - we're called
		// during initialization prior to the chain_monitor being fully configured in some cases.
		// See the docs for `ChannelManagerReadArgs` for more.

		let block_hash = header.block_hash();
		log_trace!(self.logger, "New best block: {} at height {}", block_hash, height);

		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(&self.total_consistency_lock, &self.persistence_notifier);

		*self.best_block.write().unwrap() = BestBlock::new(block_hash, height);

		self.do_chain_event(Some(height), |channel| channel.best_block_updated(height, header.time, self.genesis_hash.clone(), &self.node_signer, &self.default_configuration, &self.logger));

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

	fn get_relevant_txids(&self) -> Vec<(Txid, Option<BlockHash>)> {
		let mut res = Vec::with_capacity(self.short_to_chan_info.read().unwrap().len());
		for (_cp_id, peer_state_mutex) in self.per_peer_state.read().unwrap().iter() {
			let mut peer_state_lock = peer_state_mutex.lock().unwrap();
			let peer_state = &mut *peer_state_lock;
			for chan in peer_state.channel_by_id.values() {
				if let (Some(funding_txo), Some(block_hash)) = (chan.get_funding_txo(), chan.get_funding_tx_confirmed_in()) {
					res.push((funding_txo.txid, Some(block_hash)));
				}
			}
		}
		res
	}

	fn transaction_unconfirmed(&self, txid: &Txid) {
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(&self.total_consistency_lock, &self.persistence_notifier);
		self.do_chain_event(None, |channel| {
			if let Some(funding_txo) = channel.get_funding_txo() {
				if funding_txo.txid == *txid {
					channel.funding_transaction_unconfirmed(&self.logger).map(|()| (None, Vec::new(), None))
				} else { Ok((None, Vec::new(), None)) }
			} else { Ok((None, Vec::new(), None)) }
		});
	}
}

impl<M: Deref, T: Deref, ES: Deref, NS: Deref, SP: Deref, F: Deref, R: Deref, L: Deref> ChannelManager<M, T, ES, NS, SP, F, R, L>
where
	M::Target: chain::Watch<<SP::Target as SignerProvider>::Signer>,
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
	fn do_chain_event<FN: Fn(&mut Channel<<SP::Target as SignerProvider>::Signer>) -> Result<(Option<msgs::ChannelReady>, Vec<(HTLCSource, PaymentHash)>, Option<msgs::AnnouncementSignatures>), ClosureReason>>
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
				peer_state.channel_by_id.retain(|_, channel| {
					let res = f(channel);
					if let Ok((channel_ready_opt, mut timed_out_pending_htlcs, announcement_sigs)) = res {
						for (source, payment_hash) in timed_out_pending_htlcs.drain(..) {
							let (failure_code, data) = self.get_htlc_inbound_temp_fail_err_and_data(0x1000|14 /* expiry_too_soon */, &channel);
							timed_out_htlcs.push((source, payment_hash, HTLCFailReason::reason(failure_code, data),
								HTLCDestination::NextHopChannel { node_id: Some(channel.get_counterparty_node_id()), channel_id: channel.channel_id() }));
						}
						if let Some(channel_ready) = channel_ready_opt {
							send_channel_ready!(self, pending_msg_events, channel, channel_ready);
							if channel.is_usable() {
								log_trace!(self.logger, "Sending channel_ready with private initial channel_update for our counterparty on channel {}", log_bytes!(channel.channel_id()));
								if let Ok(msg) = self.get_channel_update_for_unicast(channel) {
									pending_msg_events.push(events::MessageSendEvent::SendChannelUpdate {
										node_id: channel.get_counterparty_node_id(),
										msg,
									});
								}
							} else {
								log_trace!(self.logger, "Sending channel_ready WITHOUT channel_update for {}", log_bytes!(channel.channel_id()));
							}
						}

						emit_channel_ready_event!(self, channel);

						if let Some(announcement_sigs) = announcement_sigs {
							log_trace!(self.logger, "Sending announcement_signatures for channel {}", log_bytes!(channel.channel_id()));
							pending_msg_events.push(events::MessageSendEvent::SendAnnouncementSignatures {
								node_id: channel.get_counterparty_node_id(),
								msg: announcement_sigs,
							});
							if let Some(height) = height_opt {
								if let Some(announcement) = channel.get_signed_channel_announcement(&self.node_signer, self.genesis_hash, height, &self.default_configuration) {
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
							if let Some(real_scid) = channel.get_short_channel_id() {
								// If we sent a 0conf channel_ready, and now have an SCID, we add it
								// to the short_to_chan_info map here. Note that we check whether we
								// can relay using the real SCID at relay-time (i.e.
								// enforce option_scid_alias then), and if the funding tx is ever
								// un-confirmed we force-close the channel, ensuring short_to_chan_info
								// is always consistent.
								let mut short_to_chan_info = self.short_to_chan_info.write().unwrap();
								let scid_insert = short_to_chan_info.insert(real_scid, (channel.get_counterparty_node_id(), channel.channel_id()));
								assert!(scid_insert.is_none() || scid_insert.unwrap() == (channel.get_counterparty_node_id(), channel.channel_id()),
									"SCIDs should never collide - ensure you weren't behind by a full {} blocks when creating channels",
									fake_scid::MAX_SCID_BLOCKS_FROM_NOW);
							}
						}
					} else if let Err(reason) = res {
						update_maps_on_chan_removal!(self, channel);
						// It looks like our counterparty went on-chain or funding transaction was
						// reorged out of the main chain. Close the channel.
						failed_channels.push(channel.force_shutdown(true));
						if let Ok(update) = self.get_channel_update_for_broadcast(&channel) {
							pending_msg_events.push(events::MessageSendEvent::BroadcastChannelUpdate {
								msg: update
							});
						}
						let reason_message = format!("{}", reason);
						self.issue_channel_close_events(channel, reason);
						pending_msg_events.push(events::MessageSendEvent::HandleError {
							node_id: channel.get_counterparty_node_id(),
							action: msgs::ErrorAction::SendErrorMessage { msg: msgs::ErrorMessage {
								channel_id: channel.channel_id(),
								data: reason_message,
							} },
						});
						return false;
					}
					true
				});
			}
		}

		if let Some(height) = height_opt {
			self.claimable_payments.lock().unwrap().claimable_htlcs.retain(|payment_hash, (_, htlcs)| {
				htlcs.retain(|htlc| {
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
				!htlcs.is_empty() // Only retain this entry if htlcs has at least one entry.
			});

			let mut intercepted_htlcs = self.pending_intercepted_htlcs.lock().unwrap();
			intercepted_htlcs.retain(|_, htlc| {
				if height >= htlc.forward_info.outgoing_cltv_value - HTLC_FAIL_BACK_BUFFER {
					let prev_hop_data = HTLCSource::PreviousHopData(HTLCPreviousHopData {
						short_channel_id: htlc.prev_short_channel_id,
						htlc_id: htlc.prev_htlc_id,
						incoming_packet_shared_secret: htlc.forward_info.incoming_shared_secret,
						phantom_shared_secret: None,
						outpoint: htlc.prev_funding_outpoint,
					});

					let requested_forward_scid /* intercept scid */ = match htlc.forward_info.routing {
						PendingHTLCRouting::Forward { short_channel_id, .. } => short_channel_id,
						_ => unreachable!(),
					};
					timed_out_htlcs.push((prev_hop_data, htlc.forward_info.payment_hash,
							HTLCFailReason::from_failure_code(0x2000 | 2),
							HTLCDestination::InvalidForward { requested_forward_scid }));
					log_trace!(self.logger, "Timing out intercepted HTLC with requested forward scid {}", requested_forward_scid);
					false
				} else { true }
			});
		}

		self.handle_init_event_channel_failures(failed_channels);

		for (source, payment_hash, reason, destination) in timed_out_htlcs.drain(..) {
			self.fail_htlc_backwards_internal(&source, &payment_hash, &reason, destination);
		}
	}

	/// Blocks until ChannelManager needs to be persisted or a timeout is reached. It returns a bool
	/// indicating whether persistence is necessary. Only one listener on
	/// [`await_persistable_update`], [`await_persistable_update_timeout`], or a future returned by
	/// [`get_persistable_update_future`] is guaranteed to be woken up.
	///
	/// Note that this method is not available with the `no-std` feature.
	///
	/// [`await_persistable_update`]: Self::await_persistable_update
	/// [`await_persistable_update_timeout`]: Self::await_persistable_update_timeout
	/// [`get_persistable_update_future`]: Self::get_persistable_update_future
	#[cfg(any(test, feature = "std"))]
	pub fn await_persistable_update_timeout(&self, max_wait: Duration) -> bool {
		self.persistence_notifier.wait_timeout(max_wait)
	}

	/// Blocks until ChannelManager needs to be persisted. Only one listener on
	/// [`await_persistable_update`], `await_persistable_update_timeout`, or a future returned by
	/// [`get_persistable_update_future`] is guaranteed to be woken up.
	///
	/// [`await_persistable_update`]: Self::await_persistable_update
	/// [`get_persistable_update_future`]: Self::get_persistable_update_future
	pub fn await_persistable_update(&self) {
		self.persistence_notifier.wait()
	}

	/// Gets a [`Future`] that completes when a persistable update is available. Note that
	/// callbacks registered on the [`Future`] MUST NOT call back into this [`ChannelManager`] and
	/// should instead register actions to be taken later.
	pub fn get_persistable_update_future(&self) -> Future {
		self.persistence_notifier.get_future()
	}

	#[cfg(any(test, feature = "_test_utils"))]
	pub fn get_persistence_condvar_value(&self) -> bool {
		self.persistence_notifier.notify_pending()
	}

	/// Gets the latest best block which was connected either via the [`chain::Listen`] or
	/// [`chain::Confirm`] interfaces.
	pub fn current_best_block(&self) -> BestBlock {
		self.best_block.read().unwrap().clone()
	}

	/// Fetches the set of [`NodeFeatures`] flags which are provided by or required by
	/// [`ChannelManager`].
	pub fn node_features(&self) -> NodeFeatures {
		provided_node_features(&self.default_configuration)
	}

	/// Fetches the set of [`InvoiceFeatures`] flags which are provided by or required by
	/// [`ChannelManager`].
	///
	/// Note that the invoice feature flags can vary depending on if the invoice is a "phantom invoice"
	/// or not. Thus, this method is not public.
	#[cfg(any(feature = "_test_utils", test))]
	pub fn invoice_features(&self) -> InvoiceFeatures {
		provided_invoice_features(&self.default_configuration)
	}

	/// Fetches the set of [`ChannelFeatures`] flags which are provided by or required by
	/// [`ChannelManager`].
	pub fn channel_features(&self) -> ChannelFeatures {
		provided_channel_features(&self.default_configuration)
	}

	/// Fetches the set of [`ChannelTypeFeatures`] flags which are provided by or required by
	/// [`ChannelManager`].
	pub fn channel_type_features(&self) -> ChannelTypeFeatures {
		provided_channel_type_features(&self.default_configuration)
	}

	/// Fetches the set of [`InitFeatures`] flags which are provided by or required by
	/// [`ChannelManager`].
	pub fn init_features(&self) -> InitFeatures {
		provided_init_features(&self.default_configuration)
	}
}

impl<M: Deref, T: Deref, ES: Deref, NS: Deref, SP: Deref, F: Deref, R: Deref, L: Deref>
	ChannelMessageHandler for ChannelManager<M, T, ES, NS, SP, F, R, L>
where
	M::Target: chain::Watch<<SP::Target as SignerProvider>::Signer>,
	T::Target: BroadcasterInterface,
	ES::Target: EntropySource,
	NS::Target: NodeSigner,
	SP::Target: SignerProvider,
	F::Target: FeeEstimator,
	R::Target: Router,
	L::Target: Logger,
{
	fn handle_open_channel(&self, counterparty_node_id: &PublicKey, msg: &msgs::OpenChannel) {
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(&self.total_consistency_lock, &self.persistence_notifier);
		let _ = handle_error!(self, self.internal_open_channel(counterparty_node_id, msg), *counterparty_node_id);
	}

	fn handle_accept_channel(&self, counterparty_node_id: &PublicKey, msg: &msgs::AcceptChannel) {
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(&self.total_consistency_lock, &self.persistence_notifier);
		let _ = handle_error!(self, self.internal_accept_channel(counterparty_node_id, msg), *counterparty_node_id);
	}

	fn handle_funding_created(&self, counterparty_node_id: &PublicKey, msg: &msgs::FundingCreated) {
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(&self.total_consistency_lock, &self.persistence_notifier);
		let _ = handle_error!(self, self.internal_funding_created(counterparty_node_id, msg), *counterparty_node_id);
	}

	fn handle_funding_signed(&self, counterparty_node_id: &PublicKey, msg: &msgs::FundingSigned) {
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(&self.total_consistency_lock, &self.persistence_notifier);
		let _ = handle_error!(self, self.internal_funding_signed(counterparty_node_id, msg), *counterparty_node_id);
	}

	fn handle_channel_ready(&self, counterparty_node_id: &PublicKey, msg: &msgs::ChannelReady) {
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(&self.total_consistency_lock, &self.persistence_notifier);
		let _ = handle_error!(self, self.internal_channel_ready(counterparty_node_id, msg), *counterparty_node_id);
	}

	fn handle_shutdown(&self, counterparty_node_id: &PublicKey, msg: &msgs::Shutdown) {
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(&self.total_consistency_lock, &self.persistence_notifier);
		let _ = handle_error!(self, self.internal_shutdown(counterparty_node_id, msg), *counterparty_node_id);
	}

	fn handle_closing_signed(&self, counterparty_node_id: &PublicKey, msg: &msgs::ClosingSigned) {
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(&self.total_consistency_lock, &self.persistence_notifier);
		let _ = handle_error!(self, self.internal_closing_signed(counterparty_node_id, msg), *counterparty_node_id);
	}

	fn handle_update_add_htlc(&self, counterparty_node_id: &PublicKey, msg: &msgs::UpdateAddHTLC) {
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(&self.total_consistency_lock, &self.persistence_notifier);
		let _ = handle_error!(self, self.internal_update_add_htlc(counterparty_node_id, msg), *counterparty_node_id);
	}

	fn handle_update_fulfill_htlc(&self, counterparty_node_id: &PublicKey, msg: &msgs::UpdateFulfillHTLC) {
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(&self.total_consistency_lock, &self.persistence_notifier);
		let _ = handle_error!(self, self.internal_update_fulfill_htlc(counterparty_node_id, msg), *counterparty_node_id);
	}

	fn handle_update_fail_htlc(&self, counterparty_node_id: &PublicKey, msg: &msgs::UpdateFailHTLC) {
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(&self.total_consistency_lock, &self.persistence_notifier);
		let _ = handle_error!(self, self.internal_update_fail_htlc(counterparty_node_id, msg), *counterparty_node_id);
	}

	fn handle_update_fail_malformed_htlc(&self, counterparty_node_id: &PublicKey, msg: &msgs::UpdateFailMalformedHTLC) {
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(&self.total_consistency_lock, &self.persistence_notifier);
		let _ = handle_error!(self, self.internal_update_fail_malformed_htlc(counterparty_node_id, msg), *counterparty_node_id);
	}

	fn handle_commitment_signed(&self, counterparty_node_id: &PublicKey, msg: &msgs::CommitmentSigned) {
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(&self.total_consistency_lock, &self.persistence_notifier);
		let _ = handle_error!(self, self.internal_commitment_signed(counterparty_node_id, msg), *counterparty_node_id);
	}

	fn handle_revoke_and_ack(&self, counterparty_node_id: &PublicKey, msg: &msgs::RevokeAndACK) {
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(&self.total_consistency_lock, &self.persistence_notifier);
		let _ = handle_error!(self, self.internal_revoke_and_ack(counterparty_node_id, msg), *counterparty_node_id);
	}

	fn handle_update_fee(&self, counterparty_node_id: &PublicKey, msg: &msgs::UpdateFee) {
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(&self.total_consistency_lock, &self.persistence_notifier);
		let _ = handle_error!(self, self.internal_update_fee(counterparty_node_id, msg), *counterparty_node_id);
	}

	fn handle_announcement_signatures(&self, counterparty_node_id: &PublicKey, msg: &msgs::AnnouncementSignatures) {
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(&self.total_consistency_lock, &self.persistence_notifier);
		let _ = handle_error!(self, self.internal_announcement_signatures(counterparty_node_id, msg), *counterparty_node_id);
	}

	fn handle_channel_update(&self, counterparty_node_id: &PublicKey, msg: &msgs::ChannelUpdate) {
		PersistenceNotifierGuard::optionally_notify(&self.total_consistency_lock, &self.persistence_notifier, || {
			if let Ok(persist) = handle_error!(self, self.internal_channel_update(counterparty_node_id, msg), *counterparty_node_id) {
				persist
			} else {
				NotifyOption::SkipPersist
			}
		});
	}

	fn handle_channel_reestablish(&self, counterparty_node_id: &PublicKey, msg: &msgs::ChannelReestablish) {
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(&self.total_consistency_lock, &self.persistence_notifier);
		let _ = handle_error!(self, self.internal_channel_reestablish(counterparty_node_id, msg), *counterparty_node_id);
	}

	fn peer_disconnected(&self, counterparty_node_id: &PublicKey) {
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(&self.total_consistency_lock, &self.persistence_notifier);
		let mut failed_channels = Vec::new();
		let mut per_peer_state = self.per_peer_state.write().unwrap();
		let remove_peer = {
			log_debug!(self.logger, "Marking channels with {} disconnected and generating channel_updates.",
				log_pubkey!(counterparty_node_id));
			if let Some(peer_state_mutex) = per_peer_state.get(counterparty_node_id) {
				let mut peer_state_lock = peer_state_mutex.lock().unwrap();
				let peer_state = &mut *peer_state_lock;
				let pending_msg_events = &mut peer_state.pending_msg_events;
				peer_state.channel_by_id.retain(|_, chan| {
					chan.remove_uncommitted_htlcs_and_mark_paused(&self.logger);
					if chan.is_shutdown() {
						update_maps_on_chan_removal!(self, chan);
						self.issue_channel_close_events(chan, ClosureReason::DisconnectedPeer);
						return false;
					}
					true
				});
				pending_msg_events.retain(|msg| {
					match msg {
						&events::MessageSendEvent::SendAcceptChannel { .. } => false,
						&events::MessageSendEvent::SendOpenChannel { .. } => false,
						&events::MessageSendEvent::SendFundingCreated { .. } => false,
						&events::MessageSendEvent::SendFundingSigned { .. } => false,
						&events::MessageSendEvent::SendChannelReady { .. } => false,
						&events::MessageSendEvent::SendAnnouncementSignatures { .. } => false,
						&events::MessageSendEvent::UpdateHTLCs { .. } => false,
						&events::MessageSendEvent::SendRevokeAndACK { .. } => false,
						&events::MessageSendEvent::SendClosingSigned { .. } => false,
						&events::MessageSendEvent::SendShutdown { .. } => false,
						&events::MessageSendEvent::SendChannelReestablish { .. } => false,
						&events::MessageSendEvent::SendChannelAnnouncement { .. } => false,
						&events::MessageSendEvent::BroadcastChannelAnnouncement { .. } => true,
						&events::MessageSendEvent::BroadcastChannelUpdate { .. } => true,
						&events::MessageSendEvent::BroadcastNodeAnnouncement { .. } => true,
						&events::MessageSendEvent::SendChannelUpdate { .. } => false,
						&events::MessageSendEvent::HandleError { .. } => false,
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
			self.finish_force_close_channel(failure);
		}
	}

	fn peer_connected(&self, counterparty_node_id: &PublicKey, init_msg: &msgs::Init, inbound: bool) -> Result<(), ()> {
		if !init_msg.features.supports_static_remote_key() {
			log_debug!(self.logger, "Peer {} does not support static remote key, disconnecting", log_pubkey!(counterparty_node_id));
			return Err(());
		}

		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(&self.total_consistency_lock, &self.persistence_notifier);

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
						return Err(());
					}
					e.insert(Mutex::new(PeerState {
						channel_by_id: HashMap::new(),
						latest_features: init_msg.features.clone(),
						pending_msg_events: Vec::new(),
						monitor_update_blocked_actions: BTreeMap::new(),
						is_connected: true,
					}));
				},
				hash_map::Entry::Occupied(e) => {
					let mut peer_state = e.get().lock().unwrap();
					peer_state.latest_features = init_msg.features.clone();

					let best_block_height = self.best_block.read().unwrap().height();
					if inbound_peer_limited &&
						Self::unfunded_channel_count(&*peer_state, best_block_height) ==
						peer_state.channel_by_id.len()
					{
						return Err(());
					}

					debug_assert!(!peer_state.is_connected, "A peer shouldn't be connected twice");
					peer_state.is_connected = true;
				},
			}
		}

		log_debug!(self.logger, "Generating channel_reestablish events for {}", log_pubkey!(counterparty_node_id));

		let per_peer_state = self.per_peer_state.read().unwrap();
		for (_cp_id, peer_state_mutex) in per_peer_state.iter() {
			let mut peer_state_lock = peer_state_mutex.lock().unwrap();
			let peer_state = &mut *peer_state_lock;
			let pending_msg_events = &mut peer_state.pending_msg_events;
			peer_state.channel_by_id.retain(|_, chan| {
				let retain = if chan.get_counterparty_node_id() == *counterparty_node_id {
					if !chan.have_received_message() {
						// If we created this (outbound) channel while we were disconnected from the
						// peer we probably failed to send the open_channel message, which is now
						// lost. We can't have had anything pending related to this channel, so we just
						// drop it.
						false
					} else {
						pending_msg_events.push(events::MessageSendEvent::SendChannelReestablish {
							node_id: chan.get_counterparty_node_id(),
							msg: chan.get_channel_reestablish(&self.logger),
						});
						true
					}
				} else { true };
				if retain && chan.get_counterparty_node_id() != *counterparty_node_id {
					if let Some(msg) = chan.get_signed_channel_announcement(&self.node_signer, self.genesis_hash.clone(), self.best_block.read().unwrap().height(), &self.default_configuration) {
						if let Ok(update_msg) = self.get_channel_update_for_broadcast(chan) {
							pending_msg_events.push(events::MessageSendEvent::SendChannelAnnouncement {
								node_id: *counterparty_node_id,
								msg, update_msg,
							});
						}
					}
				}
				retain
			});
		}
		//TODO: Also re-broadcast announcement_signatures
		Ok(())
	}

	fn handle_error(&self, counterparty_node_id: &PublicKey, msg: &msgs::ErrorMessage) {
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(&self.total_consistency_lock, &self.persistence_notifier);

		if msg.channel_id == [0; 32] {
			let channel_ids: Vec<[u8; 32]> = {
				let per_peer_state = self.per_peer_state.read().unwrap();
				let peer_state_mutex_opt = per_peer_state.get(counterparty_node_id);
				if peer_state_mutex_opt.is_none() { return; }
				let mut peer_state_lock = peer_state_mutex_opt.unwrap().lock().unwrap();
				let peer_state = &mut *peer_state_lock;
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
				if let Some(chan) = peer_state.channel_by_id.get_mut(&msg.channel_id) {
					if let Ok(msg) = chan.maybe_handle_error_without_close(self.genesis_hash) {
						peer_state.pending_msg_events.push(events::MessageSendEvent::SendOpenChannel {
							node_id: *counterparty_node_id,
							msg,
						});
						return;
					}
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
}

/// Fetches the set of [`NodeFeatures`] flags which are provided by or required by
/// [`ChannelManager`].
pub(crate) fn provided_node_features(config: &UserConfig) -> NodeFeatures {
	provided_init_features(config).to_context()
}

/// Fetches the set of [`InvoiceFeatures`] flags which are provided by or required by
/// [`ChannelManager`].
///
/// Note that the invoice feature flags can vary depending on if the invoice is a "phantom invoice"
/// or not. Thus, this method is not public.
#[cfg(any(feature = "_test_utils", test))]
pub(crate) fn provided_invoice_features(config: &UserConfig) -> InvoiceFeatures {
	provided_init_features(config).to_context()
}

/// Fetches the set of [`ChannelFeatures`] flags which are provided by or required by
/// [`ChannelManager`].
pub(crate) fn provided_channel_features(config: &UserConfig) -> ChannelFeatures {
	provided_init_features(config).to_context()
}

/// Fetches the set of [`ChannelTypeFeatures`] flags which are provided by or required by
/// [`ChannelManager`].
pub(crate) fn provided_channel_type_features(config: &UserConfig) -> ChannelTypeFeatures {
	ChannelTypeFeatures::from_init(&provided_init_features(config))
}

/// Fetches the set of [`InitFeatures`] flags which are provided by or required by
/// [`ChannelManager`].
pub fn provided_init_features(_config: &UserConfig) -> InitFeatures {
	// Note that if new features are added here which other peers may (eventually) require, we
	// should also add the corresponding (optional) bit to the ChannelMessageHandler impl for
	// ErroringMessageHandler.
	let mut features = InitFeatures::empty();
	features.set_data_loss_protect_optional();
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
	#[cfg(anchors)]
	{ // Attributes are not allowed on if expressions on our current MSRV of 1.41.
		if _config.channel_handshake_config.negotiate_anchors_zero_fee_htlc_tx {
			features.set_anchors_zero_fee_htlc_tx_optional();
		}
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
			// Note that by the time we get past the required read above, outbound_capacity_msat will be
			// filled in, so we can safely unwrap it here.
			(19, self.next_outbound_htlc_limit_msat, (default_value, outbound_capacity_msat.0.unwrap() as u64)),
			(20, self.inbound_capacity_msat, required),
			(22, self.confirmations_required, option),
			(24, self.force_close_spend_delay, option),
			(26, self.is_outbound, required),
			(28, self.is_channel_ready, required),
			(30, self.is_usable, required),
			(32, self.is_public, required),
			(33, self.inbound_htlc_minimum_msat, option),
			(35, self.inbound_htlc_maximum_msat, option),
			(37, user_channel_id_high_opt, option),
		});
		Ok(())
	}
}

impl Readable for ChannelDetails {
	fn read<R: Read>(reader: &mut R) -> Result<Self, DecodeError> {
		_init_and_read_tlv_fields!(reader, {
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
			(22, confirmations_required, option),
			(24, force_close_spend_delay, option),
			(26, is_outbound, required),
			(28, is_channel_ready, required),
			(30, is_usable, required),
			(32, is_public, required),
			(33, inbound_htlc_minimum_msat, option),
			(35, inbound_htlc_maximum_msat, option),
			(37, user_channel_id_high_opt, option),
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
		})
	}
}

impl_writeable_tlv_based!(PhantomRouteHints, {
	(2, channels, vec_type),
	(4, phantom_scid, required),
	(6, real_node_pubkey, required),
});

impl_writeable_tlv_based_enum!(PendingHTLCRouting,
	(0, Forward) => {
		(0, onion_packet, required),
		(2, short_channel_id, required),
	},
	(1, Receive) => {
		(0, payment_data, required),
		(1, phantom_shared_secret, option),
		(2, incoming_cltv_expiry, required),
	},
	(2, ReceiveKeysend) => {
		(0, payment_preimage, required),
		(2, incoming_cltv_expiry, required),
	},
;);

impl_writeable_tlv_based!(PendingHTLCInfo, {
	(0, routing, required),
	(2, incoming_shared_secret, required),
	(4, payment_hash, required),
	(6, outgoing_amt_msat, required),
	(8, outgoing_cltv_value, required),
	(9, incoming_amt_msat, option),
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

impl_writeable_tlv_based!(HTLCPreviousHopData, {
	(0, short_channel_id, required),
	(1, phantom_shared_secret, option),
	(2, outpoint, required),
	(4, htlc_id, required),
	(6, incoming_packet_shared_secret, required)
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
			(4, payment_data, option),
			(6, self.cltv_expiry, required),
			(8, keysend_preimage, option),
		});
		Ok(())
	}
}

impl Readable for ClaimableHTLC {
	fn read<R: Read>(reader: &mut R) -> Result<Self, DecodeError> {
		let mut prev_hop = crate::util::ser::RequiredWrapper(None);
		let mut value = 0;
		let mut payment_data: Option<msgs::FinalOnionHopData> = None;
		let mut cltv_expiry = 0;
		let mut total_msat = None;
		let mut keysend_preimage: Option<PaymentPreimage> = None;
		read_tlv_fields!(reader, {
			(0, prev_hop, required),
			(1, total_msat, option),
			(2, value, required),
			(4, payment_data, option),
			(6, cltv_expiry, required),
			(8, keysend_preimage, option)
		});
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
			total_msat: total_msat.unwrap(),
			onion_payload,
			cltv_expiry,
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
				let mut path: Option<Vec<RouteHop>> = Some(Vec::new());
				let mut payment_id = None;
				let mut payment_secret = None;
				let mut payment_params: Option<PaymentParameters> = None;
				read_tlv_fields!(reader, {
					(0, session_priv, required),
					(1, payment_id, option),
					(2, first_hop_htlc_msat, required),
					(3, payment_secret, option),
					(4, path, vec_type),
					(5, payment_params, (option: ReadableArgs, 0)),
				});
				if payment_id.is_none() {
					// For backwards compat, if there was no payment_id written, use the session_priv bytes
					// instead.
					payment_id = Some(PaymentId(*session_priv.0.unwrap().as_ref()));
				}
				if path.is_none() || path.as_ref().unwrap().is_empty() {
					return Err(DecodeError::InvalidValue);
				}
				let path = path.unwrap();
				if let Some(params) = payment_params.as_mut() {
					if params.final_cltv_expiry_delta == 0 {
						params.final_cltv_expiry_delta = path.last().unwrap().cltv_expiry_delta;
					}
				}
				Ok(HTLCSource::OutboundRoute {
					session_priv: session_priv.0.unwrap(),
					first_hop_htlc_msat,
					path,
					payment_id: payment_id.unwrap(),
					payment_secret,
					payment_params,
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
			HTLCSource::OutboundRoute { ref session_priv, ref first_hop_htlc_msat, ref path, payment_id, payment_secret, payment_params } => {
				0u8.write(writer)?;
				let payment_id_opt = Some(payment_id);
				write_tlv_fields!(writer, {
					(0, session_priv, required),
					(1, payment_id_opt, option),
					(2, first_hop_htlc_msat, required),
					(3, payment_secret, option),
					(4, *path, vec_type),
					(5, payment_params, option),
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
});

impl_writeable_tlv_based_enum!(HTLCForwardInfo,
	(1, FailHTLC) => {
		(0, htlc_id, required),
		(2, err_packet, required),
	};
	(0, AddHTLC)
);

impl_writeable_tlv_based!(PendingInboundPayment, {
	(0, payment_secret, required),
	(2, expiry_time, required),
	(4, user_payment_id, required),
	(6, payment_preimage, required),
	(8, min_value_msat, required),
});

impl<M: Deref, T: Deref, ES: Deref, NS: Deref, SP: Deref, F: Deref, R: Deref, L: Deref> Writeable for ChannelManager<M, T, ES, NS, SP, F, R, L>
where
	M::Target: chain::Watch<<SP::Target as SignerProvider>::Signer>,
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

		self.genesis_hash.write(writer)?;
		{
			let best_block = self.best_block.read().unwrap();
			best_block.height().write(writer)?;
			best_block.block_hash().write(writer)?;
		}

		let mut serializable_peer_count: u64 = 0;
		{
			let per_peer_state = self.per_peer_state.read().unwrap();
			let mut unfunded_channels = 0;
			let mut number_of_channels = 0;
			for (_, peer_state_mutex) in per_peer_state.iter() {
				let mut peer_state_lock = peer_state_mutex.lock().unwrap();
				let peer_state = &mut *peer_state_lock;
				if !peer_state.ok_to_remove(false) {
					serializable_peer_count += 1;
				}
				number_of_channels += peer_state.channel_by_id.len();
				for (_, channel) in peer_state.channel_by_id.iter() {
					if !channel.is_funding_initiated() {
						unfunded_channels += 1;
					}
				}
			}

			((number_of_channels - unfunded_channels) as u64).write(writer)?;

			for (_, peer_state_mutex) in per_peer_state.iter() {
				let mut peer_state_lock = peer_state_mutex.lock().unwrap();
				let peer_state = &mut *peer_state_lock;
				for (_, channel) in peer_state.channel_by_id.iter() {
					if channel.is_funding_initiated() {
						channel.write(writer)?;
					}
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

		let per_peer_state = self.per_peer_state.write().unwrap();

		let pending_inbound_payments = self.pending_inbound_payments.lock().unwrap();
		let claimable_payments = self.claimable_payments.lock().unwrap();
		let pending_outbound_payments = self.pending_outbound_payments.pending_outbound_payments.lock().unwrap();

		let mut htlc_purposes: Vec<&events::PaymentPurpose> = Vec::new();
		(claimable_payments.claimable_htlcs.len() as u64).write(writer)?;
		for (payment_hash, (purpose, previous_hops)) in claimable_payments.claimable_htlcs.iter() {
			payment_hash.write(writer)?;
			(previous_hops.len() as u64).write(writer)?;
			for htlc in previous_hops.iter() {
				htlc.write(writer)?;
			}
			htlc_purposes.push(purpose);
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
		(events.len() as u64).write(writer)?;
		for event in events.iter() {
			event.write(writer)?;
		}

		let background_events = self.pending_background_events.lock().unwrap();
		(background_events.len() as u64).write(writer)?;
		for event in background_events.iter() {
			match event {
				BackgroundEvent::ClosingMonitorUpdate((funding_txo, monitor_update)) => {
					0u8.write(writer)?;
					funding_txo.write(writer)?;
					monitor_update.write(writer)?;
				},
			}
		}

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
				PendingOutboundPayment::Fulfilled { .. } => {},
				PendingOutboundPayment::Abandoned { .. } => {},
			}
		}

		// Encode without retry info for 0.0.101 compatibility.
		let mut pending_outbound_payments_no_retry: HashMap<PaymentId, HashSet<[u8; 32]>> = HashMap::new();
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

		write_tlv_fields!(writer, {
			(1, pending_outbound_payments_no_retry, required),
			(2, pending_intercepted_htlcs, option),
			(3, pending_outbound_payments, required),
			(4, pending_claiming_payments, option),
			(5, self.our_network_pubkey, required),
			(6, monitor_update_blocked_actions_per_peer, option),
			(7, self.fake_scid_rand_bytes, required),
			(9, htlc_purposes, vec_type),
			(11, self.probing_cookie_secret, required),
		});

		Ok(())
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
	M::Target: chain::Watch<<SP::Target as SignerProvider>::Signer>,
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
	/// value.get_funding_txo() should be the key).
	///
	/// If a monitor is inconsistent with the channel state during deserialization the channel will
	/// be force-closed using the data in the ChannelMonitor and the channel will be dropped. This
	/// is true for missing channels as well. If there is a monitor missing for which we find
	/// channel data Err(DecodeError::InvalidValue) will be returned.
	///
	/// In such cases the latest local transactions will be sent to the tx_broadcaster included in
	/// this struct.
	///
	/// (C-not exported) because we have no HashMap bindings
	pub channel_monitors: HashMap<OutPoint, &'a mut ChannelMonitor<<SP::Target as SignerProvider>::Signer>>,
}

impl<'a, M: Deref, T: Deref, ES: Deref, NS: Deref, SP: Deref, F: Deref, R: Deref, L: Deref>
		ChannelManagerReadArgs<'a, M, T, ES, NS, SP, F, R, L>
where
	M::Target: chain::Watch<<SP::Target as SignerProvider>::Signer>,
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
			mut channel_monitors: Vec<&'a mut ChannelMonitor<<SP::Target as SignerProvider>::Signer>>) -> Self {
		Self {
			entropy_source, node_signer, signer_provider, fee_estimator, chain_monitor, tx_broadcaster, router, logger, default_config,
			channel_monitors: channel_monitors.drain(..).map(|monitor| { (monitor.get_funding_txo().0, monitor) }).collect()
		}
	}
}

// Implement ReadableArgs for an Arc'd ChannelManager to make it a bit easier to work with the
// SipmleArcChannelManager type:
impl<'a, M: Deref, T: Deref, ES: Deref, NS: Deref, SP: Deref, F: Deref, R: Deref, L: Deref>
	ReadableArgs<ChannelManagerReadArgs<'a, M, T, ES, NS, SP, F, R, L>> for (BlockHash, Arc<ChannelManager<M, T, ES, NS, SP, F, R, L>>)
where
	M::Target: chain::Watch<<SP::Target as SignerProvider>::Signer>,
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
	M::Target: chain::Watch<<SP::Target as SignerProvider>::Signer>,
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

		let genesis_hash: BlockHash = Readable::read(reader)?;
		let best_block_height: u32 = Readable::read(reader)?;
		let best_block_hash: BlockHash = Readable::read(reader)?;

		let mut failed_htlcs = Vec::new();

		let channel_count: u64 = Readable::read(reader)?;
		let mut funding_txo_set = HashSet::with_capacity(cmp::min(channel_count as usize, 128));
		let mut peer_channels: HashMap<PublicKey, HashMap<[u8; 32], Channel<<SP::Target as SignerProvider>::Signer>>> = HashMap::with_capacity(cmp::min(channel_count as usize, 128));
		let mut id_to_peer = HashMap::with_capacity(cmp::min(channel_count as usize, 128));
		let mut short_to_chan_info = HashMap::with_capacity(cmp::min(channel_count as usize, 128));
		let mut channel_closures = Vec::new();
		for _ in 0..channel_count {
			let mut channel: Channel<<SP::Target as SignerProvider>::Signer> = Channel::read(reader, (
				&args.entropy_source, &args.signer_provider, best_block_height, &provided_channel_type_features(&args.default_config)
			))?;
			let funding_txo = channel.get_funding_txo().ok_or(DecodeError::InvalidValue)?;
			funding_txo_set.insert(funding_txo.clone());
			if let Some(ref mut monitor) = args.channel_monitors.get_mut(&funding_txo) {
				if channel.get_cur_holder_commitment_transaction_number() < monitor.get_cur_holder_commitment_number() ||
						channel.get_revoked_counterparty_commitment_transaction_number() < monitor.get_min_seen_secret() ||
						channel.get_cur_counterparty_commitment_transaction_number() < monitor.get_cur_counterparty_commitment_number() ||
						channel.get_latest_monitor_update_id() > monitor.get_latest_update_id() {
					// If the channel is ahead of the monitor, return InvalidValue:
					log_error!(args.logger, "A ChannelMonitor is stale compared to the current ChannelManager! This indicates a potentially-critical violation of the chain::Watch API!");
					log_error!(args.logger, " The ChannelMonitor for channel {} is at update_id {} but the ChannelManager is at update_id {}.",
						log_bytes!(channel.channel_id()), monitor.get_latest_update_id(), channel.get_latest_monitor_update_id());
					log_error!(args.logger, " The chain::Watch API *requires* that monitors are persisted durably before returning,");
					log_error!(args.logger, " client applications must ensure that ChannelMonitor data is always available and the latest to avoid funds loss!");
					log_error!(args.logger, " Without the latest ChannelMonitor we cannot continue without risking funds.");
					log_error!(args.logger, " Please ensure the chain::Watch API requirements are met and file a bug report at https://github.com/lightningdevkit/rust-lightning");
					return Err(DecodeError::InvalidValue);
				} else if channel.get_cur_holder_commitment_transaction_number() > monitor.get_cur_holder_commitment_number() ||
						channel.get_revoked_counterparty_commitment_transaction_number() > monitor.get_min_seen_secret() ||
						channel.get_cur_counterparty_commitment_transaction_number() > monitor.get_cur_counterparty_commitment_number() ||
						channel.get_latest_monitor_update_id() < monitor.get_latest_update_id() {
					// But if the channel is behind of the monitor, close the channel:
					log_error!(args.logger, "A ChannelManager is stale compared to the current ChannelMonitor!");
					log_error!(args.logger, " The channel will be force-closed and the latest commitment transaction from the ChannelMonitor broadcast.");
					log_error!(args.logger, " The ChannelMonitor for channel {} is at update_id {} but the ChannelManager is at update_id {}.",
						log_bytes!(channel.channel_id()), monitor.get_latest_update_id(), channel.get_latest_monitor_update_id());
					let (_, mut new_failed_htlcs) = channel.force_shutdown(true);
					failed_htlcs.append(&mut new_failed_htlcs);
					monitor.broadcast_latest_holder_commitment_txn(&args.tx_broadcaster, &args.logger);
					channel_closures.push(events::Event::ChannelClosed {
						channel_id: channel.channel_id(),
						user_channel_id: channel.get_user_id(),
						reason: ClosureReason::OutdatedChannelManager
					});
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
							log_info!(args.logger,
								"Failing HTLC with hash {} as it is missing in the ChannelMonitor for channel {} but was present in the (stale) ChannelManager",
								log_bytes!(channel.channel_id()), log_bytes!(payment_hash.0));
							failed_htlcs.push((channel_htlc_source.clone(), *payment_hash, channel.get_counterparty_node_id(), channel.channel_id()));
						}
					}
				} else {
					log_info!(args.logger, "Successfully loaded channel {}", log_bytes!(channel.channel_id()));
					if let Some(short_channel_id) = channel.get_short_channel_id() {
						short_to_chan_info.insert(short_channel_id, (channel.get_counterparty_node_id(), channel.channel_id()));
					}
					if channel.is_funding_initiated() {
						id_to_peer.insert(channel.channel_id(), channel.get_counterparty_node_id());
					}
					match peer_channels.entry(channel.get_counterparty_node_id()) {
						hash_map::Entry::Occupied(mut entry) => {
							let by_id_map = entry.get_mut();
							by_id_map.insert(channel.channel_id(), channel);
						},
						hash_map::Entry::Vacant(entry) => {
							let mut by_id_map = HashMap::new();
							by_id_map.insert(channel.channel_id(), channel);
							entry.insert(by_id_map);
						}
					}
				}
			} else if channel.is_awaiting_initial_mon_persist() {
				// If we were persisted and shut down while the initial ChannelMonitor persistence
				// was in-progress, we never broadcasted the funding transaction and can still
				// safely discard the channel.
				let _ = channel.force_shutdown(false);
				channel_closures.push(events::Event::ChannelClosed {
					channel_id: channel.channel_id(),
					user_channel_id: channel.get_user_id(),
					reason: ClosureReason::DisconnectedPeer,
				});
			} else {
				log_error!(args.logger, "Missing ChannelMonitor for channel {} needed by ChannelManager.", log_bytes!(channel.channel_id()));
				log_error!(args.logger, " The chain::Watch API *requires* that monitors are persisted durably before returning,");
				log_error!(args.logger, " client applications must ensure that ChannelMonitor data is always available and the latest to avoid funds loss!");
				log_error!(args.logger, " Without the ChannelMonitor we cannot continue without risking funds.");
				log_error!(args.logger, " Please ensure the chain::Watch API requirements are met and file a bug report at https://github.com/lightningdevkit/rust-lightning");
				return Err(DecodeError::InvalidValue);
			}
		}

		for (funding_txo, monitor) in args.channel_monitors.iter_mut() {
			if !funding_txo_set.contains(funding_txo) {
				log_info!(args.logger, "Broadcasting latest holder commitment transaction for closed channel {}", log_bytes!(funding_txo.to_channel_id()));
				monitor.broadcast_latest_holder_commitment_txn(&args.tx_broadcaster, &args.logger);
			}
		}

		const MAX_ALLOC_SIZE: usize = 1024 * 64;
		let forward_htlcs_count: u64 = Readable::read(reader)?;
		let mut forward_htlcs = HashMap::with_capacity(cmp::min(forward_htlcs_count as usize, 128));
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

		let peer_count: u64 = Readable::read(reader)?;
		let mut per_peer_state = HashMap::with_capacity(cmp::min(peer_count as usize, MAX_ALLOC_SIZE/mem::size_of::<(PublicKey, Mutex<PeerState<<SP::Target as SignerProvider>::Signer>>)>()));
		for _ in 0..peer_count {
			let peer_pubkey = Readable::read(reader)?;
			let peer_state = PeerState {
				channel_by_id: peer_channels.remove(&peer_pubkey).unwrap_or(HashMap::new()),
				latest_features: Readable::read(reader)?,
				pending_msg_events: Vec::new(),
				monitor_update_blocked_actions: BTreeMap::new(),
				is_connected: false,
			};
			per_peer_state.insert(peer_pubkey, Mutex::new(peer_state));
		}

		let event_count: u64 = Readable::read(reader)?;
		let mut pending_events_read: Vec<events::Event> = Vec::with_capacity(cmp::min(event_count as usize, MAX_ALLOC_SIZE/mem::size_of::<events::Event>()));
		for _ in 0..event_count {
			match MaybeReadable::read(reader)? {
				Some(event) => pending_events_read.push(event),
				None => continue,
			}
		}

		let background_event_count: u64 = Readable::read(reader)?;
		let mut pending_background_events_read: Vec<BackgroundEvent> = Vec::with_capacity(cmp::min(background_event_count as usize, MAX_ALLOC_SIZE/mem::size_of::<BackgroundEvent>()));
		for _ in 0..background_event_count {
			match <u8 as Readable>::read(reader)? {
				0 => pending_background_events_read.push(BackgroundEvent::ClosingMonitorUpdate((Readable::read(reader)?, Readable::read(reader)?))),
				_ => return Err(DecodeError::InvalidValue),
			}
		}

		let _last_node_announcement_serial: u32 = Readable::read(reader)?; // Only used < 0.0.111
		let highest_seen_timestamp: u32 = Readable::read(reader)?;

		let pending_inbound_payment_count: u64 = Readable::read(reader)?;
		let mut pending_inbound_payments: HashMap<PaymentHash, PendingInboundPayment> = HashMap::with_capacity(cmp::min(pending_inbound_payment_count as usize, MAX_ALLOC_SIZE/(3*32)));
		for _ in 0..pending_inbound_payment_count {
			if pending_inbound_payments.insert(Readable::read(reader)?, Readable::read(reader)?).is_some() {
				return Err(DecodeError::InvalidValue);
			}
		}

		let pending_outbound_payments_count_compat: u64 = Readable::read(reader)?;
		let mut pending_outbound_payments_compat: HashMap<PaymentId, PendingOutboundPayment> =
			HashMap::with_capacity(cmp::min(pending_outbound_payments_count_compat as usize, MAX_ALLOC_SIZE/32));
		for _ in 0..pending_outbound_payments_count_compat {
			let session_priv = Readable::read(reader)?;
			let payment = PendingOutboundPayment::Legacy {
				session_privs: [session_priv].iter().cloned().collect()
			};
			if pending_outbound_payments_compat.insert(PaymentId(session_priv), payment).is_some() {
				return Err(DecodeError::InvalidValue)
			};
		}

		// pending_outbound_payments_no_retry is for compatibility with 0.0.101 clients.
		let mut pending_outbound_payments_no_retry: Option<HashMap<PaymentId, HashSet<[u8; 32]>>> = None;
		let mut pending_outbound_payments = None;
		let mut pending_intercepted_htlcs: Option<HashMap<InterceptId, PendingAddHTLCInfo>> = Some(HashMap::new());
		let mut received_network_pubkey: Option<PublicKey> = None;
		let mut fake_scid_rand_bytes: Option<[u8; 32]> = None;
		let mut probing_cookie_secret: Option<[u8; 32]> = None;
		let mut claimable_htlc_purposes = None;
		let mut pending_claiming_payments = Some(HashMap::new());
		let mut monitor_update_blocked_actions_per_peer = Some(Vec::new());
		read_tlv_fields!(reader, {
			(1, pending_outbound_payments_no_retry, option),
			(2, pending_intercepted_htlcs, option),
			(3, pending_outbound_payments, option),
			(4, pending_claiming_payments, option),
			(5, received_network_pubkey, option),
			(6, monitor_update_blocked_actions_per_peer, option),
			(7, fake_scid_rand_bytes, option),
			(9, claimable_htlc_purposes, vec_type),
			(11, probing_cookie_secret, option),
		});
		if fake_scid_rand_bytes.is_none() {
			fake_scid_rand_bytes = Some(args.entropy_source.get_secure_random_bytes());
		}

		if probing_cookie_secret.is_none() {
			probing_cookie_secret = Some(args.entropy_source.get_secure_random_bytes());
		}

		if !channel_closures.is_empty() {
			pending_events_read.append(&mut channel_closures);
		}

		if pending_outbound_payments.is_none() && pending_outbound_payments_no_retry.is_none() {
			pending_outbound_payments = Some(pending_outbound_payments_compat);
		} else if pending_outbound_payments.is_none() {
			let mut outbounds = HashMap::new();
			for (id, session_privs) in pending_outbound_payments_no_retry.unwrap().drain() {
				outbounds.insert(id, PendingOutboundPayment::Legacy { session_privs });
			}
			pending_outbound_payments = Some(outbounds);
		}
		let pending_outbounds = OutboundPayments {
			pending_outbound_payments: Mutex::new(pending_outbound_payments.unwrap()),
			retry_lock: Mutex::new(())
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
			for (_, monitor) in args.channel_monitors.iter() {
				if id_to_peer.get(&monitor.get_funding_txo().0.to_channel_id()).is_none() {
					for (htlc_source, (htlc, _)) in monitor.get_pending_or_resolved_outbound_htlcs() {
						if let HTLCSource::OutboundRoute { payment_id, session_priv, path, payment_secret, .. } = htlc_source {
							if path.is_empty() {
								log_error!(args.logger, "Got an empty path for a pending payment");
								return Err(DecodeError::InvalidValue);
							}

							let path_amt = path.last().unwrap().fee_msat;
							let mut session_priv_bytes = [0; 32];
							session_priv_bytes[..].copy_from_slice(&session_priv[..]);
							match pending_outbounds.pending_outbound_payments.lock().unwrap().entry(payment_id) {
								hash_map::Entry::Occupied(mut entry) => {
									let newly_added = entry.get_mut().insert(session_priv_bytes, &path);
									log_info!(args.logger, "{} a pending payment path for {} msat for session priv {} on an existing pending payment with payment hash {}",
										if newly_added { "Added" } else { "Had" }, path_amt, log_bytes!(session_priv_bytes), log_bytes!(htlc.payment_hash.0));
								},
								hash_map::Entry::Vacant(entry) => {
									let path_fee = path.get_path_fees();
									entry.insert(PendingOutboundPayment::Retryable {
										retry_strategy: None,
										attempts: PaymentAttempts::new(),
										payment_params: None,
										session_privs: [session_priv_bytes].iter().map(|a| *a).collect(),
										payment_hash: htlc.payment_hash,
										payment_secret,
										keysend_preimage: None, // only used for retries, and we'll never retry on startup
										pending_amt_msat: path_amt,
										pending_fee_msat: Some(path_fee),
										total_msat: path_amt,
										starting_block_height: best_block_height,
									});
									log_info!(args.logger, "Added a pending payment for {} msat with payment hash {} for path with session priv {}",
										path_amt, log_bytes!(htlc.payment_hash.0),  log_bytes!(session_priv_bytes));
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
								forward_htlcs.retain(|_, forwards| {
									forwards.retain(|forward| {
										if let HTLCForwardInfo::AddHTLC(htlc_info) = forward {
											if pending_forward_matches_htlc(&htlc_info) {
												log_info!(args.logger, "Removing pending to-forward HTLC with hash {} as it was forwarded to the closed channel {}",
													log_bytes!(htlc.payment_hash.0), log_bytes!(monitor.get_funding_txo().0.to_channel_id()));
												false
											} else { true }
										} else { true }
									});
									!forwards.is_empty()
								});
								pending_intercepted_htlcs.as_mut().unwrap().retain(|intercepted_id, htlc_info| {
									if pending_forward_matches_htlc(&htlc_info) {
										log_info!(args.logger, "Removing pending intercepted HTLC with hash {} as it was forwarded to the closed channel {}",
											log_bytes!(htlc.payment_hash.0), log_bytes!(monitor.get_funding_txo().0.to_channel_id()));
										pending_events_read.retain(|event| {
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
									pending_outbounds.claim_htlc(payment_id, preimage, session_priv, path, false, &pending_events, &args.logger);
									pending_events_read = pending_events.into_inner().unwrap();
								}
							},
						}
					}
				}
			}
		}

		if !forward_htlcs.is_empty() || pending_outbounds.needs_abandon() {
			// If we have pending HTLCs to forward, assume we either dropped a
			// `PendingHTLCsForwardable` or the user received it but never processed it as they
			// shut down before the timer hit. Either way, set the time_forwardable to a small
			// constant as enough time has likely passed that we should simply handle the forwards
			// now, or at least after the user gets a chance to reconnect to our peers.
			pending_events_read.push(events::Event::PendingHTLCsForwardable {
				time_forwardable: Duration::from_secs(2),
			});
		}

		let inbound_pmt_key_material = args.node_signer.get_inbound_payment_key_material();
		let expanded_inbound_key = inbound_payment::ExpandedKey::new(&inbound_pmt_key_material);

		let mut claimable_htlcs = HashMap::with_capacity(claimable_htlcs_list.len());
		if let Some(mut purposes) = claimable_htlc_purposes {
			if purposes.len() != claimable_htlcs_list.len() {
				return Err(DecodeError::InvalidValue);
			}
			for (purpose, (payment_hash, previous_hops)) in purposes.drain(..).zip(claimable_htlcs_list.drain(..)) {
				claimable_htlcs.insert(payment_hash, (purpose, previous_hops));
			}
		} else {
			// LDK versions prior to 0.0.107 did not write a `pending_htlc_purposes`, but do
			// include a `_legacy_hop_data` in the `OnionPayload`.
			for (payment_hash, previous_hops) in claimable_htlcs_list.drain(..) {
				if previous_hops.is_empty() {
					return Err(DecodeError::InvalidValue);
				}
				let purpose = match &previous_hops[0].onion_payload {
					OnionPayload::Invoice { _legacy_hop_data } => {
						if let Some(hop_data) = _legacy_hop_data {
							events::PaymentPurpose::InvoicePayment {
								payment_preimage: match pending_inbound_payments.get(&payment_hash) {
									Some(inbound_payment) => inbound_payment.payment_preimage,
									None => match inbound_payment::verify(payment_hash, &hop_data, 0, &expanded_inbound_key, &args.logger) {
										Ok((payment_preimage, _)) => payment_preimage,
										Err(()) => {
											log_error!(args.logger, "Failed to read claimable payment data for HTLC with payment hash {} - was not a pending inbound payment and didn't match our payment key", log_bytes!(payment_hash.0));
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
				claimable_htlcs.insert(payment_hash, (purpose, previous_hops));
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

		let mut outbound_scid_aliases = HashSet::new();
		for (_peer_node_id, peer_state_mutex) in per_peer_state.iter_mut() {
			let mut peer_state_lock = peer_state_mutex.lock().unwrap();
			let peer_state = &mut *peer_state_lock;
			for (chan_id, chan) in peer_state.channel_by_id.iter_mut() {
				if chan.outbound_scid_alias() == 0 {
					let mut outbound_scid_alias;
					loop {
						outbound_scid_alias = fake_scid::Namespace::OutboundAlias
							.get_fake_scid(best_block_height, &genesis_hash, fake_scid_rand_bytes.as_ref().unwrap(), &args.entropy_source);
						if outbound_scid_aliases.insert(outbound_scid_alias) { break; }
					}
					chan.set_outbound_scid_alias(outbound_scid_alias);
				} else if !outbound_scid_aliases.insert(chan.outbound_scid_alias()) {
					// Note that in rare cases its possible to hit this while reading an older
					// channel if we just happened to pick a colliding outbound alias above.
					log_error!(args.logger, "Got duplicate outbound SCID alias; {}", chan.outbound_scid_alias());
					return Err(DecodeError::InvalidValue);
				}
				if chan.is_usable() {
					if short_to_chan_info.insert(chan.outbound_scid_alias(), (chan.get_counterparty_node_id(), *chan_id)).is_some() {
						// Note that in rare cases its possible to hit this while reading an older
						// channel if we just happened to pick a colliding outbound alias above.
						log_error!(args.logger, "Got duplicate outbound SCID alias; {}", chan.outbound_scid_alias());
						return Err(DecodeError::InvalidValue);
					}
				}
			}
		}

		let bounded_fee_estimator = LowerBoundedFeeEstimator::new(args.fee_estimator);

		for (_, monitor) in args.channel_monitors.iter() {
			for (payment_hash, payment_preimage) in monitor.get_stored_preimages() {
				if let Some((payment_purpose, claimable_htlcs)) = claimable_htlcs.remove(&payment_hash) {
					log_info!(args.logger, "Re-claiming HTLCs with payment hash {} as we've released the preimage to a ChannelMonitor!", log_bytes!(payment_hash.0));
					let mut claimable_amt_msat = 0;
					let mut receiver_node_id = Some(our_network_pubkey);
					let phantom_shared_secret = claimable_htlcs[0].prev_hop.phantom_shared_secret;
					if phantom_shared_secret.is_some() {
						let phantom_pubkey = args.node_signer.get_node_id(Recipient::PhantomNode)
							.expect("Failed to get node_id for phantom node recipient");
						receiver_node_id = Some(phantom_pubkey)
					}
					for claimable_htlc in claimable_htlcs {
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
						let previous_channel_id = claimable_htlc.prev_hop.outpoint.to_channel_id();
						if let Some(peer_node_id) = id_to_peer.get(&previous_channel_id){
							let peer_state_mutex = per_peer_state.get(peer_node_id).unwrap();
							let mut peer_state_lock = peer_state_mutex.lock().unwrap();
							let peer_state = &mut *peer_state_lock;
							if let Some(channel) = peer_state.channel_by_id.get_mut(&previous_channel_id) {
								channel.claim_htlc_while_disconnected_dropping_mon_update(claimable_htlc.prev_hop.htlc_id, payment_preimage, &args.logger);
							}
						}
						if let Some(previous_hop_monitor) = args.channel_monitors.get(&claimable_htlc.prev_hop.outpoint) {
							previous_hop_monitor.provide_payment_preimage(&payment_hash, &payment_preimage, &args.tx_broadcaster, &bounded_fee_estimator, &args.logger);
						}
					}
					pending_events_read.push(events::Event::PaymentClaimed {
						receiver_node_id,
						payment_hash,
						purpose: payment_purpose,
						amount_msat: claimable_amt_msat,
					});
				}
			}
		}

		for (node_id, monitor_update_blocked_actions) in monitor_update_blocked_actions_per_peer.unwrap() {
			if let Some(peer_state) = per_peer_state.get_mut(&node_id) {
				peer_state.lock().unwrap().monitor_update_blocked_actions = monitor_update_blocked_actions;
			} else {
				log_error!(args.logger, "Got blocked actions without a per-peer-state for {}", node_id);
				return Err(DecodeError::InvalidValue);
			}
		}

		let channel_manager = ChannelManager {
			genesis_hash,
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
			claimable_payments: Mutex::new(ClaimablePayments { claimable_htlcs, pending_claiming_payments: pending_claiming_payments.unwrap() }),
			outbound_scid_aliases: Mutex::new(outbound_scid_aliases),
			id_to_peer: Mutex::new(id_to_peer),
			short_to_chan_info: FairRwLock::new(short_to_chan_info),
			fake_scid_rand_bytes: fake_scid_rand_bytes.unwrap(),

			probing_cookie_secret: probing_cookie_secret.unwrap(),

			our_network_pubkey,
			secp_ctx,

			highest_seen_timestamp: AtomicUsize::new(highest_seen_timestamp as usize),

			per_peer_state: FairRwLock::new(per_peer_state),

			pending_events: Mutex::new(pending_events_read),
			pending_background_events: Mutex::new(pending_background_events_read),
			total_consistency_lock: RwLock::new(()),
			persistence_notifier: Notifier::new(),

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
	use core::time::Duration;
	use core::sync::atomic::Ordering;
	use crate::ln::{PaymentPreimage, PaymentHash, PaymentSecret};
	use crate::ln::channelmanager::{inbound_payment, PaymentId, PaymentSendFailure, InterceptId};
	use crate::ln::functional_test_utils::*;
	use crate::ln::msgs;
	use crate::ln::msgs::ChannelMessageHandler;
	use crate::routing::router::{PaymentParameters, RouteParameters, find_route};
	use crate::util::errors::APIError;
	use crate::util::events::{Event, HTLCDestination, MessageSendEvent, MessageSendEventsProvider, ClosureReason};
	use crate::util::test_utils;
	use crate::util::config::ChannelConfig;
	use crate::chain::keysinterface::EntropySource;

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
		assert!(nodes[0].node.await_persistable_update_timeout(Duration::from_millis(1)));
		assert!(nodes[1].node.await_persistable_update_timeout(Duration::from_millis(1)));
		assert!(nodes[2].node.await_persistable_update_timeout(Duration::from_millis(1)));

		let mut chan = create_announced_chan_between_nodes(&nodes, 0, 1);

		// We check that the channel info nodes have doesn't change too early, even though we try
		// to connect messages with new values
		chan.0.contents.fee_base_msat *= 2;
		chan.1.contents.fee_base_msat *= 2;
		let node_a_chan_info = nodes[0].node.list_channels()[0].clone();
		let node_b_chan_info = nodes[1].node.list_channels()[0].clone();

		// The first two nodes (which opened a channel) should now require fresh persistence
		assert!(nodes[0].node.await_persistable_update_timeout(Duration::from_millis(1)));
		assert!(nodes[1].node.await_persistable_update_timeout(Duration::from_millis(1)));
		// ... but the last node should not.
		assert!(!nodes[2].node.await_persistable_update_timeout(Duration::from_millis(1)));
		// After persisting the first two nodes they should no longer need fresh persistence.
		assert!(!nodes[0].node.await_persistable_update_timeout(Duration::from_millis(1)));
		assert!(!nodes[1].node.await_persistable_update_timeout(Duration::from_millis(1)));

		// Node 3, unrelated to the only channel, shouldn't care if it receives a channel_update
		// about the channel.
		nodes[2].node.handle_channel_update(&nodes[1].node.get_our_node_id(), &chan.0);
		nodes[2].node.handle_channel_update(&nodes[1].node.get_our_node_id(), &chan.1);
		assert!(!nodes[2].node.await_persistable_update_timeout(Duration::from_millis(1)));

		// The nodes which are a party to the channel should also ignore messages from unrelated
		// parties.
		nodes[0].node.handle_channel_update(&nodes[2].node.get_our_node_id(), &chan.0);
		nodes[0].node.handle_channel_update(&nodes[2].node.get_our_node_id(), &chan.1);
		nodes[1].node.handle_channel_update(&nodes[2].node.get_our_node_id(), &chan.0);
		nodes[1].node.handle_channel_update(&nodes[2].node.get_our_node_id(), &chan.1);
		assert!(!nodes[0].node.await_persistable_update_timeout(Duration::from_millis(1)));
		assert!(!nodes[1].node.await_persistable_update_timeout(Duration::from_millis(1)));

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
		assert!(!nodes[0].node.await_persistable_update_timeout(Duration::from_millis(1)));
		assert!(!nodes[1].node.await_persistable_update_timeout(Duration::from_millis(1)));
		assert_eq!(nodes[0].node.list_channels()[0], node_a_chan_info);
		assert_eq!(nodes[1].node.list_channels()[0], node_b_chan_info);

		// Finally, deliver the other peers' message, ensuring each node needs to be persisted and
		// the channel info has updated.
		nodes[0].node.handle_channel_update(&nodes[1].node.get_our_node_id(), &bs_update);
		nodes[1].node.handle_channel_update(&nodes[0].node.get_our_node_id(), &as_update);
		assert!(nodes[0].node.await_persistable_update_timeout(Duration::from_millis(1)));
		assert!(nodes[1].node.await_persistable_update_timeout(Duration::from_millis(1)));
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
		let session_privs = nodes[0].node.test_add_new_pending_payment(our_payment_hash, Some(payment_secret), payment_id, &mpp_route).unwrap();
		nodes[0].node.test_send_payment_along_path(&mpp_route.paths[0], &route.payment_params, &our_payment_hash, &Some(payment_secret), 200_000, cur_height, payment_id, &None, session_privs[0]).unwrap();
		check_added_monitors!(nodes[0], 1);
		let mut events = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		pass_along_path(&nodes[0], &[&nodes[1]], 200_000, our_payment_hash, Some(payment_secret), events.drain(..).next().unwrap(), false, None);

		// Next, send a keysend payment with the same payment_hash and make sure it fails.
		nodes[0].node.send_spontaneous_payment(&route, Some(payment_preimage), PaymentId(payment_preimage.0)).unwrap();
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
		nodes[0].node.test_send_payment_along_path(&mpp_route.paths[1], &route.payment_params, &our_payment_hash, &Some(payment_secret), 200_000, cur_height, payment_id, &None, session_privs[1]).unwrap();
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
		assert_eq!(events.len(), 3);
		match events[0] {
			Event::PaymentSent { payment_id: ref id, payment_preimage: ref preimage, payment_hash: ref hash, .. } => {
				assert_eq!(Some(payment_id), *id);
				assert_eq!(payment_preimage, *preimage);
				assert_eq!(our_payment_hash, *hash);
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
		match events[2] {
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
		// (1): Test that a keysend payment with a duplicate payment hash to an existing pending
		//      outbound regular payment fails as expected.
		// (2): Test that a regular payment with a duplicate payment hash to an existing keysend payment
		//      fails as expected.
		let chanmon_cfgs = create_chanmon_cfgs(2);
		let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
		let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
		let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
		create_announced_chan_between_nodes(&nodes, 0, 1);
		let scorer = test_utils::TestScorer::new();
		let random_seed_bytes = chanmon_cfgs[1].keys_manager.get_secure_random_bytes();

		// To start (1), send a regular payment but don't claim it.
		let expected_route = [&nodes[1]];
		let (payment_preimage, payment_hash, _) = route_payment(&nodes[0], &expected_route, 100_000);

		// Next, attempt a keysend payment and make sure it fails.
		let route_params = RouteParameters {
			payment_params: PaymentParameters::for_keysend(expected_route.last().unwrap().node.get_our_node_id(), TEST_FINAL_CLTV),
			final_value_msat: 100_000,
		};
		let route = find_route(
			&nodes[0].node.get_our_node_id(), &route_params, &nodes[0].network_graph,
			None, nodes[0].logger, &scorer, &random_seed_bytes
		).unwrap();
		nodes[0].node.send_spontaneous_payment(&route, Some(payment_preimage), PaymentId(payment_preimage.0)).unwrap();
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
			None, nodes[0].logger, &scorer, &random_seed_bytes
		).unwrap();
		let payment_hash = nodes[0].node.send_spontaneous_payment(&route, Some(payment_preimage), PaymentId(payment_preimage.0)).unwrap();
		check_added_monitors!(nodes[0], 1);
		let mut events = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		let event = events.pop().unwrap();
		let path = vec![&nodes[1]];
		pass_along_path(&nodes[0], &path, 100_000, payment_hash, None, event, true, Some(payment_preimage));

		// Next, attempt a regular payment and make sure it fails.
		let payment_secret = PaymentSecret([43; 32]);
		nodes[0].node.send_payment(&route, payment_hash, &Some(payment_secret), PaymentId(payment_hash.0)).unwrap();
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
		let route_params = RouteParameters {
			payment_params: PaymentParameters::for_keysend(payee_pubkey, 40),
			final_value_msat: 10_000,
		};
		let network_graph = nodes[0].network_graph.clone();
		let first_hops = nodes[0].node.list_usable_channels();
		let scorer = test_utils::TestScorer::new();
		let random_seed_bytes = chanmon_cfgs[1].keys_manager.get_secure_random_bytes();
		let route = find_route(
			&payer_pubkey, &route_params, &network_graph, Some(&first_hops.iter().collect::<Vec<_>>()),
			nodes[0].logger, &scorer, &random_seed_bytes
		).unwrap();

		let test_preimage = PaymentPreimage([42; 32]);
		let mismatch_payment_hash = PaymentHash([43; 32]);
		let session_privs = nodes[0].node.test_add_new_pending_payment(mismatch_payment_hash, None, PaymentId(mismatch_payment_hash.0), &route).unwrap();
		nodes[0].node.test_send_payment_internal(&route, mismatch_payment_hash, &None, Some(test_preimage), PaymentId(mismatch_payment_hash.0), None, session_privs).unwrap();
		check_added_monitors!(nodes[0], 1);

		let updates = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
		assert_eq!(updates.update_add_htlcs.len(), 1);
		assert!(updates.update_fulfill_htlcs.is_empty());
		assert!(updates.update_fail_htlcs.is_empty());
		assert!(updates.update_fail_malformed_htlcs.is_empty());
		assert!(updates.update_fee.is_none());
		nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &updates.update_add_htlcs[0]);

		nodes[1].logger.assert_log_contains("lightning::ln::channelmanager".to_string(), "Payment preimage didn't match payment hash".to_string(), 1);
	}

	#[test]
	fn test_keysend_msg_with_secret_err() {
		// Test that we error as expected if we receive a keysend payment that includes a payment secret.
		let chanmon_cfgs = create_chanmon_cfgs(2);
		let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
		let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
		let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

		let payer_pubkey = nodes[0].node.get_our_node_id();
		let payee_pubkey = nodes[1].node.get_our_node_id();

		let _chan = create_chan_between_nodes(&nodes[0], &nodes[1]);
		let route_params = RouteParameters {
			payment_params: PaymentParameters::for_keysend(payee_pubkey, 40),
			final_value_msat: 10_000,
		};
		let network_graph = nodes[0].network_graph.clone();
		let first_hops = nodes[0].node.list_usable_channels();
		let scorer = test_utils::TestScorer::new();
		let random_seed_bytes = chanmon_cfgs[1].keys_manager.get_secure_random_bytes();
		let route = find_route(
			&payer_pubkey, &route_params, &network_graph, Some(&first_hops.iter().collect::<Vec<_>>()),
			nodes[0].logger, &scorer, &random_seed_bytes
		).unwrap();

		let test_preimage = PaymentPreimage([42; 32]);
		let test_secret = PaymentSecret([43; 32]);
		let payment_hash = PaymentHash(Sha256::hash(&test_preimage.0).into_inner());
		let session_privs = nodes[0].node.test_add_new_pending_payment(payment_hash, Some(test_secret), PaymentId(payment_hash.0), &route).unwrap();
		nodes[0].node.test_send_payment_internal(&route, payment_hash, &Some(test_secret), Some(test_preimage), PaymentId(payment_hash.0), None, session_privs).unwrap();
		check_added_monitors!(nodes[0], 1);

		let updates = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
		assert_eq!(updates.update_add_htlcs.len(), 1);
		assert!(updates.update_fulfill_htlcs.is_empty());
		assert!(updates.update_fail_htlcs.is_empty());
		assert!(updates.update_fail_malformed_htlcs.is_empty());
		assert!(updates.update_fee.is_none());
		nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &updates.update_add_htlcs[0]);

		nodes[1].logger.assert_log_contains("lightning::ln::channelmanager".to_string(), "We don't support MPP keysend payments".to_string(), 1);
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
		route.paths[0][0].pubkey = nodes[1].node.get_our_node_id();
		route.paths[0][0].short_channel_id = chan_1_id;
		route.paths[0][1].short_channel_id = chan_3_id;
		route.paths[1][0].pubkey = nodes[2].node.get_our_node_id();
		route.paths[1][0].short_channel_id = chan_2_id;
		route.paths[1][1].short_channel_id = chan_4_id;

		match nodes[0].node.send_payment(&route, payment_hash, &None, PaymentId(payment_hash.0)).unwrap_err() {
			PaymentSendFailure::ParameterError(APIError::APIMisuseError { ref err }) => {
				assert!(regex::Regex::new(r"Payment secret is required for multi-path payments").unwrap().is_match(err))			},
			_ => panic!("unexpected error")
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
		check_closed_event!(nodes[0], 1, ClosureReason::HolderForceClosed);

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
				nodes[0].logger.assert_log_contains("lightning::ln::inbound_payment".to_string(), "Failing HTLC with user-generated payment_hash".to_string(), 1);
			}
		}

		// Check that using the original payment hash succeeds.
		assert!(inbound_payment::verify(payment_hash, &payment_data, nodes[0].node.highest_seen_timestamp.load(Ordering::Acquire) as u64, &nodes[0].node.inbound_payment_key, &nodes[0].logger).is_ok());
	}

	#[test]
	fn test_id_to_peer_coverage() {
		// Test that the `ChannelManager:id_to_peer` contains channels which have been assigned
		// a `channel_id` (i.e. have had the funding tx created), and that they are removed once
		// the channel is successfully closed.
		let chanmon_cfgs = create_chanmon_cfgs(2);
		let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
		let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
		let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

		nodes[0].node.create_channel(nodes[1].node.get_our_node_id(), 1_000_000, 500_000_000, 42, None).unwrap();
		let open_channel = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, nodes[1].node.get_our_node_id());
		nodes[1].node.handle_open_channel(&nodes[0].node.get_our_node_id(), &open_channel);
		let accept_channel = get_event_msg!(nodes[1], MessageSendEvent::SendAcceptChannel, nodes[0].node.get_our_node_id());
		nodes[0].node.handle_accept_channel(&nodes[1].node.get_our_node_id(), &accept_channel);

		let (temporary_channel_id, tx, _funding_output) = create_funding_transaction(&nodes[0], &nodes[1].node.get_our_node_id(), 1_000_000, 42);
		let channel_id = &tx.txid().into_inner();
		{
			// Ensure that the `id_to_peer` map is empty until either party has received the
			// funding transaction, and have the real `channel_id`.
			assert_eq!(nodes[0].node.id_to_peer.lock().unwrap().len(), 0);
			assert_eq!(nodes[1].node.id_to_peer.lock().unwrap().len(), 0);
		}

		nodes[0].node.funding_transaction_generated(&temporary_channel_id, &nodes[1].node.get_our_node_id(), tx.clone()).unwrap();
		{
			// Assert that `nodes[0]`'s `id_to_peer` map is populated with the channel as soon as
			// as it has the funding transaction.
			let nodes_0_lock = nodes[0].node.id_to_peer.lock().unwrap();
			assert_eq!(nodes_0_lock.len(), 1);
			assert!(nodes_0_lock.contains_key(channel_id));
		}

		assert_eq!(nodes[1].node.id_to_peer.lock().unwrap().len(), 0);

		let funding_created_msg = get_event_msg!(nodes[0], MessageSendEvent::SendFundingCreated, nodes[1].node.get_our_node_id());

		nodes[1].node.handle_funding_created(&nodes[0].node.get_our_node_id(), &funding_created_msg);
		{
			let nodes_0_lock = nodes[0].node.id_to_peer.lock().unwrap();
			assert_eq!(nodes_0_lock.len(), 1);
			assert!(nodes_0_lock.contains_key(channel_id));
		}

		{
			// Assert that `nodes[1]`'s `id_to_peer` map is populated with the channel as soon as
			// as it has the funding transaction.
			let nodes_1_lock = nodes[1].node.id_to_peer.lock().unwrap();
			assert_eq!(nodes_1_lock.len(), 1);
			assert!(nodes_1_lock.contains_key(channel_id));
		}
		check_added_monitors!(nodes[1], 1);
		let funding_signed = get_event_msg!(nodes[1], MessageSendEvent::SendFundingSigned, nodes[0].node.get_our_node_id());
		nodes[0].node.handle_funding_signed(&nodes[1].node.get_our_node_id(), &funding_signed);
		check_added_monitors!(nodes[0], 1);
		let (channel_ready, _) = create_chan_between_nodes_with_value_confirm(&nodes[0], &nodes[1], &tx);
		let (announcement, nodes_0_update, nodes_1_update) = create_chan_between_nodes_with_value_b(&nodes[0], &nodes[1], &channel_ready);
		update_nodes_with_chan_announce(&nodes, 0, 1, &announcement, &nodes_0_update, &nodes_1_update);

		nodes[0].node.close_channel(channel_id, &nodes[1].node.get_our_node_id()).unwrap();
		nodes[1].node.handle_shutdown(&nodes[0].node.get_our_node_id(), &get_event_msg!(nodes[0], MessageSendEvent::SendShutdown, nodes[1].node.get_our_node_id()));
		let nodes_1_shutdown = get_event_msg!(nodes[1], MessageSendEvent::SendShutdown, nodes[0].node.get_our_node_id());
		nodes[0].node.handle_shutdown(&nodes[1].node.get_our_node_id(), &nodes_1_shutdown);

		let closing_signed_node_0 = get_event_msg!(nodes[0], MessageSendEvent::SendClosingSigned, nodes[1].node.get_our_node_id());
		nodes[1].node.handle_closing_signed(&nodes[0].node.get_our_node_id(), &closing_signed_node_0);
		{
			// Assert that the channel is kept in the `id_to_peer` map for both nodes until the
			// channel can be fully closed by both parties (i.e. no outstanding htlcs exists, the
			// fee for the closing transaction has been negotiated and the parties has the other
			// party's signature for the fee negotiated closing transaction.)
			let nodes_0_lock = nodes[0].node.id_to_peer.lock().unwrap();
			assert_eq!(nodes_0_lock.len(), 1);
			assert!(nodes_0_lock.contains_key(channel_id));
		}

		{
			// At this stage, `nodes[1]` has proposed a fee for the closing transaction in the
			// `handle_closing_signed` call above. As `nodes[1]` has not yet received the signature
			// from `nodes[0]` for the closing transaction with the proposed fee, the channel is
			// kept in the `nodes[1]`'s `id_to_peer` map.
			let nodes_1_lock = nodes[1].node.id_to_peer.lock().unwrap();
			assert_eq!(nodes_1_lock.len(), 1);
			assert!(nodes_1_lock.contains_key(channel_id));
		}

		nodes[0].node.handle_closing_signed(&nodes[1].node.get_our_node_id(), &get_event_msg!(nodes[1], MessageSendEvent::SendClosingSigned, nodes[0].node.get_our_node_id()));
		{
			// `nodes[0]` accepts `nodes[1]`'s proposed fee for the closing transaction, and
			// therefore has all it needs to fully close the channel (both signatures for the
			// closing transaction).
			// Assert that the channel is removed from `nodes[0]`'s `id_to_peer` map as it can be
			// fully closed by `nodes[0]`.
			assert_eq!(nodes[0].node.id_to_peer.lock().unwrap().len(), 0);

			// Assert that the channel is still in `nodes[1]`'s  `id_to_peer` map, as `nodes[1]`
			// doesn't have `nodes[0]`'s signature for the closing transaction yet.
			let nodes_1_lock = nodes[1].node.id_to_peer.lock().unwrap();
			assert_eq!(nodes_1_lock.len(), 1);
			assert!(nodes_1_lock.contains_key(channel_id));
		}

		let (_nodes_0_update, closing_signed_node_0) = get_closing_signed_broadcast!(nodes[0].node, nodes[1].node.get_our_node_id());

		nodes[1].node.handle_closing_signed(&nodes[0].node.get_our_node_id(), &closing_signed_node_0.unwrap());
		{
			// Assert that the channel has now been removed from both parties `id_to_peer` map once
			// they both have everything required to fully close the channel.
			assert_eq!(nodes[1].node.id_to_peer.lock().unwrap().len(), 0);
		}
		let (_nodes_1_update, _none) = get_closing_signed_broadcast!(nodes[1].node, nodes[0].node.get_our_node_id());

		check_closed_event!(nodes[0], 1, ClosureReason::CooperativeClosure);
		check_closed_event!(nodes[1], 1, ClosureReason::CooperativeClosure);
	}

	fn check_not_connected_to_peer_error<T>(res_err: Result<T, APIError>, expected_public_key: PublicKey) {
		let expected_message = format!("Not connected to node: {}", expected_public_key);
		check_api_error_message(expected_message, res_err)
	}

	fn check_unkown_peer_error<T>(res_err: Result<T, APIError>, expected_public_key: PublicKey) {
		let expected_message = format!("Can't find a peer matching the passed counterparty node_id {}", expected_public_key);
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
		let channel_id = [4; 32];
		let unkown_public_key = PublicKey::from_secret_key(&Secp256k1::signing_only(), &SecretKey::from_slice(&[42; 32]).unwrap());
		let intercept_id = InterceptId([0; 32]);

		// Test the API functions.
		check_not_connected_to_peer_error(nodes[0].node.create_channel(unkown_public_key, 1_000_000, 500_000_000, 42, None), unkown_public_key);

		check_unkown_peer_error(nodes[0].node.accept_inbound_channel(&channel_id, &unkown_public_key, 42), unkown_public_key);

		check_unkown_peer_error(nodes[0].node.close_channel(&channel_id, &unkown_public_key), unkown_public_key);

		check_unkown_peer_error(nodes[0].node.force_close_broadcasting_latest_txn(&channel_id, &unkown_public_key), unkown_public_key);

		check_unkown_peer_error(nodes[0].node.force_close_without_broadcasting_txn(&channel_id, &unkown_public_key), unkown_public_key);

		check_unkown_peer_error(nodes[0].node.forward_intercepted_htlc(intercept_id, &channel_id, unkown_public_key, 1_000_000), unkown_public_key);

		check_unkown_peer_error(nodes[0].node.update_channel_config(&unkown_public_key, &[channel_id], &ChannelConfig::default()), unkown_public_key);
	}

	#[test]
	fn test_connection_limiting() {
		// Test that we limit un-channel'd peers and un-funded channels properly.
		let chanmon_cfgs = create_chanmon_cfgs(2);
		let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
		let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
		let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

		// Note that create_network connects the nodes together for us

		nodes[0].node.create_channel(nodes[1].node.get_our_node_id(), 100_000, 0, 42, None).unwrap();
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
				let funding_signed = get_event_msg!(nodes[1], MessageSendEvent::SendFundingSigned, nodes[0].node.get_our_node_id());

				nodes[0].node.handle_funding_signed(&nodes[1].node.get_our_node_id(), &funding_signed);
				check_added_monitors!(nodes[0], 1);
			}
			open_channel_msg.temporary_channel_id = nodes[0].keys_manager.get_secure_random_bytes();
		}

		// A MAX_UNFUNDED_CHANS_PER_PEER + 1 channel will be summarily rejected
		open_channel_msg.temporary_channel_id = nodes[0].keys_manager.get_secure_random_bytes();
		nodes[1].node.handle_open_channel(&nodes[0].node.get_our_node_id(), &open_channel_msg);
		assert_eq!(get_err_msg(&nodes[1], &nodes[0].node.get_our_node_id()).channel_id,
			open_channel_msg.temporary_channel_id);

		// Further, because all of our channels with nodes[0] are inbound, and none of them funded,
		// it doesn't count as a "protected" peer, i.e. it counts towards the MAX_NO_CHANNEL_PEERS
		// limit.
		let mut peer_pks = Vec::with_capacity(super::MAX_NO_CHANNEL_PEERS);
		for _ in 1..super::MAX_NO_CHANNEL_PEERS {
			let random_pk = PublicKey::from_secret_key(&nodes[0].node.secp_ctx,
				&SecretKey::from_slice(&nodes[1].keys_manager.get_secure_random_bytes()).unwrap());
			peer_pks.push(random_pk);
			nodes[1].node.peer_connected(&random_pk, &msgs::Init {
				features: nodes[0].node.init_features(), remote_network_address: None }, true).unwrap();
		}
		let last_random_pk = PublicKey::from_secret_key(&nodes[0].node.secp_ctx,
			&SecretKey::from_slice(&nodes[1].keys_manager.get_secure_random_bytes()).unwrap());
		nodes[1].node.peer_connected(&last_random_pk, &msgs::Init {
			features: nodes[0].node.init_features(), remote_network_address: None }, true).unwrap_err();

		// Also importantly, because nodes[0] isn't "protected", we will refuse a reconnection from
		// them if we have too many un-channel'd peers.
		nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id());
		let chan_closed_events = nodes[1].node.get_and_clear_pending_events();
		assert_eq!(chan_closed_events.len(), super::MAX_UNFUNDED_CHANS_PER_PEER - 1);
		for ev in chan_closed_events {
			if let Event::ChannelClosed { .. } = ev { } else { panic!(); }
		}
		nodes[1].node.peer_connected(&last_random_pk, &msgs::Init {
			features: nodes[0].node.init_features(), remote_network_address: None }, true).unwrap();
		nodes[1].node.peer_connected(&nodes[0].node.get_our_node_id(), &msgs::Init {
			features: nodes[0].node.init_features(), remote_network_address: None }, true).unwrap_err();

		// but of course if the connection is outbound its allowed...
		nodes[1].node.peer_connected(&nodes[0].node.get_our_node_id(), &msgs::Init {
			features: nodes[0].node.init_features(), remote_network_address: None }, false).unwrap();
		nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id());

		// Now nodes[0] is disconnected but still has a pending, un-funded channel lying around.
		// Even though we accept one more connection from new peers, we won't actually let them
		// open channels.
		assert!(peer_pks.len() > super::MAX_UNFUNDED_CHANNEL_PEERS - 1);
		for i in 0..super::MAX_UNFUNDED_CHANNEL_PEERS - 1 {
			nodes[1].node.handle_open_channel(&peer_pks[i], &open_channel_msg);
			get_event_msg!(nodes[1], MessageSendEvent::SendAcceptChannel, peer_pks[i]);
			open_channel_msg.temporary_channel_id = nodes[0].keys_manager.get_secure_random_bytes();
		}
		nodes[1].node.handle_open_channel(&last_random_pk, &open_channel_msg);
		assert_eq!(get_err_msg(&nodes[1], &last_random_pk).channel_id,
			open_channel_msg.temporary_channel_id);

		// Of course, however, outbound channels are always allowed
		nodes[1].node.create_channel(last_random_pk, 100_000, 0, 42, None).unwrap();
		get_event_msg!(nodes[1], MessageSendEvent::SendOpenChannel, last_random_pk);

		// If we fund the first channel, nodes[0] has a live on-chain channel with us, it is now
		// "protected" and can connect again.
		mine_transaction(&nodes[1], funding_tx.as_ref().unwrap());
		nodes[1].node.peer_connected(&nodes[0].node.get_our_node_id(), &msgs::Init {
			features: nodes[0].node.init_features(), remote_network_address: None }, true).unwrap();
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

		nodes[0].node.create_channel(nodes[1].node.get_our_node_id(), 100_000, 0, 42, None).unwrap();
		let mut open_channel_msg = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, nodes[1].node.get_our_node_id());

		for _ in 0..super::MAX_UNFUNDED_CHANS_PER_PEER {
			nodes[1].node.handle_open_channel(&nodes[0].node.get_our_node_id(), &open_channel_msg);
			get_event_msg!(nodes[1], MessageSendEvent::SendAcceptChannel, nodes[0].node.get_our_node_id());
			open_channel_msg.temporary_channel_id = nodes[0].keys_manager.get_secure_random_bytes();
		}

		// Once we have MAX_UNFUNDED_CHANS_PER_PEER unfunded channels, new inbound channels will be
		// rejected.
		nodes[1].node.handle_open_channel(&nodes[0].node.get_our_node_id(), &open_channel_msg);
		assert_eq!(get_err_msg(&nodes[1], &nodes[0].node.get_our_node_id()).channel_id,
			open_channel_msg.temporary_channel_id);

		// but we can still open an outbound channel.
		nodes[1].node.create_channel(nodes[0].node.get_our_node_id(), 100_000, 0, 42, None).unwrap();
		get_event_msg!(nodes[1], MessageSendEvent::SendOpenChannel, nodes[0].node.get_our_node_id());

		// but even with such an outbound channel, additional inbound channels will still fail.
		nodes[1].node.handle_open_channel(&nodes[0].node.get_our_node_id(), &open_channel_msg);
		assert_eq!(get_err_msg(&nodes[1], &nodes[0].node.get_our_node_id()).channel_id,
			open_channel_msg.temporary_channel_id);
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

		nodes[0].node.create_channel(nodes[1].node.get_our_node_id(), 100_000, 0, 42, None).unwrap();
		let mut open_channel_msg = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, nodes[1].node.get_our_node_id());

		// First, get us up to MAX_UNFUNDED_CHANNEL_PEERS so we can test at the edge
		for _ in 0..super::MAX_UNFUNDED_CHANNEL_PEERS - 1 {
			let random_pk = PublicKey::from_secret_key(&nodes[0].node.secp_ctx,
				&SecretKey::from_slice(&nodes[1].keys_manager.get_secure_random_bytes()).unwrap());
			nodes[1].node.peer_connected(&random_pk, &msgs::Init {
				features: nodes[0].node.init_features(), remote_network_address: None }, true).unwrap();

			nodes[1].node.handle_open_channel(&random_pk, &open_channel_msg);
			let events = nodes[1].node.get_and_clear_pending_events();
			match events[0] {
				Event::OpenChannelRequest { temporary_channel_id, .. } => {
					nodes[1].node.accept_inbound_channel(&temporary_channel_id, &random_pk, 23).unwrap();
				}
				_ => panic!("Unexpected event"),
			}
			get_event_msg!(nodes[1], MessageSendEvent::SendAcceptChannel, random_pk);
			open_channel_msg.temporary_channel_id = nodes[0].keys_manager.get_secure_random_bytes();
		}

		// If we try to accept a channel from another peer non-0conf it will fail.
		let last_random_pk = PublicKey::from_secret_key(&nodes[0].node.secp_ctx,
			&SecretKey::from_slice(&nodes[1].keys_manager.get_secure_random_bytes()).unwrap());
		nodes[1].node.peer_connected(&last_random_pk, &msgs::Init {
			features: nodes[0].node.init_features(), remote_network_address: None }, true).unwrap();
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
			open_channel_msg.temporary_channel_id);

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

	#[cfg(anchors)]
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

		nodes[0].node.create_channel(nodes[1].node.get_our_node_id(), 100_000, 0, 0, None).unwrap();
		let open_channel_msg = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, nodes[1].node.get_our_node_id());
		assert!(open_channel_msg.channel_type.as_ref().unwrap().supports_anchors_zero_fee_htlc_tx());

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
		assert!(!open_channel_msg.channel_type.unwrap().supports_anchors_zero_fee_htlc_tx());

		check_closed_event!(nodes[1], 1, ClosureReason::HolderForceClosed);
	}
}

#[cfg(all(any(test, feature = "_test_utils"), feature = "_bench_unstable"))]
pub mod bench {
	use crate::chain::Listen;
	use crate::chain::chainmonitor::{ChainMonitor, Persist};
	use crate::chain::keysinterface::{EntropySource, KeysManager, InMemorySigner};
	use crate::ln::channelmanager::{self, BestBlock, ChainParameters, ChannelManager, PaymentHash, PaymentPreimage, PaymentId};
	use crate::ln::functional_test_utils::*;
	use crate::ln::msgs::{ChannelMessageHandler, Init};
	use crate::routing::gossip::NetworkGraph;
	use crate::routing::router::{PaymentParameters, get_route};
	use crate::util::test_utils;
	use crate::util::config::UserConfig;
	use crate::util::events::{Event, MessageSendEvent, MessageSendEventsProvider};

	use bitcoin::hashes::Hash;
	use bitcoin::hashes::sha256::Hash as Sha256;
	use bitcoin::{Block, BlockHeader, PackedLockTime, Transaction, TxMerkleNode, TxOut};

	use crate::sync::{Arc, Mutex};

	use test::Bencher;

	struct NodeHolder<'a, P: Persist<InMemorySigner>> {
		node: &'a ChannelManager<
			&'a ChainMonitor<InMemorySigner, &'a test_utils::TestChainSource,
				&'a test_utils::TestBroadcaster, &'a test_utils::TestFeeEstimator,
				&'a test_utils::TestLogger, &'a P>,
			&'a test_utils::TestBroadcaster, &'a KeysManager, &'a KeysManager, &'a KeysManager,
			&'a test_utils::TestFeeEstimator, &'a test_utils::TestRouter<'a>,
			&'a test_utils::TestLogger>,
	}

	#[cfg(test)]
	#[bench]
	fn bench_sends(bench: &mut Bencher) {
		bench_two_sends(bench, test_utils::TestPersister::new(), test_utils::TestPersister::new());
	}

	pub fn bench_two_sends<P: Persist<InMemorySigner>>(bench: &mut Bencher, persister_a: P, persister_b: P) {
		// Do a simple benchmark of sending a payment back and forth between two nodes.
		// Note that this is unrealistic as each payment send will require at least two fsync
		// calls per node.
		let network = bitcoin::Network::Testnet;

		let tx_broadcaster = test_utils::TestBroadcaster{txn_broadcasted: Mutex::new(Vec::new()), blocks: Arc::new(Mutex::new(Vec::new()))};
		let fee_estimator = test_utils::TestFeeEstimator { sat_per_kw: Mutex::new(253) };
		let logger_a = test_utils::TestLogger::with_id("node a".to_owned());
		let scorer = Mutex::new(test_utils::TestScorer::new());
		let router = test_utils::TestRouter::new(Arc::new(NetworkGraph::new(network, &logger_a)), &scorer);

		let mut config: UserConfig = Default::default();
		config.channel_handshake_config.minimum_depth = 1;

		let chain_monitor_a = ChainMonitor::new(None, &tx_broadcaster, &logger_a, &fee_estimator, &persister_a);
		let seed_a = [1u8; 32];
		let keys_manager_a = KeysManager::new(&seed_a, 42, 42);
		let node_a = ChannelManager::new(&fee_estimator, &chain_monitor_a, &tx_broadcaster, &router, &logger_a, &keys_manager_a, &keys_manager_a, &keys_manager_a, config.clone(), ChainParameters {
			network,
			best_block: BestBlock::from_network(network),
		});
		let node_a_holder = NodeHolder { node: &node_a };

		let logger_b = test_utils::TestLogger::with_id("node a".to_owned());
		let chain_monitor_b = ChainMonitor::new(None, &tx_broadcaster, &logger_a, &fee_estimator, &persister_b);
		let seed_b = [2u8; 32];
		let keys_manager_b = KeysManager::new(&seed_b, 42, 42);
		let node_b = ChannelManager::new(&fee_estimator, &chain_monitor_b, &tx_broadcaster, &router, &logger_b, &keys_manager_b, &keys_manager_b, &keys_manager_b, config.clone(), ChainParameters {
			network,
			best_block: BestBlock::from_network(network),
		});
		let node_b_holder = NodeHolder { node: &node_b };

		node_a.peer_connected(&node_b.get_our_node_id(), &Init { features: node_b.init_features(), remote_network_address: None }, true).unwrap();
		node_b.peer_connected(&node_a.get_our_node_id(), &Init { features: node_a.init_features(), remote_network_address: None }, false).unwrap();
		node_a.create_channel(node_b.get_our_node_id(), 8_000_000, 100_000_000, 42, None).unwrap();
		node_b.handle_open_channel(&node_a.get_our_node_id(), &get_event_msg!(node_a_holder, MessageSendEvent::SendOpenChannel, node_b.get_our_node_id()));
		node_a.handle_accept_channel(&node_b.get_our_node_id(), &get_event_msg!(node_b_holder, MessageSendEvent::SendAcceptChannel, node_a.get_our_node_id()));

		let tx;
		if let Event::FundingGenerationReady { temporary_channel_id, output_script, .. } = get_event!(node_a_holder, Event::FundingGenerationReady) {
			tx = Transaction { version: 2, lock_time: PackedLockTime::ZERO, input: Vec::new(), output: vec![TxOut {
				value: 8_000_000, script_pubkey: output_script,
			}]};
			node_a.funding_transaction_generated(&temporary_channel_id, &node_b.get_our_node_id(), tx.clone()).unwrap();
		} else { panic!(); }

		node_b.handle_funding_created(&node_a.get_our_node_id(), &get_event_msg!(node_a_holder, MessageSendEvent::SendFundingCreated, node_b.get_our_node_id()));
		node_a.handle_funding_signed(&node_b.get_our_node_id(), &get_event_msg!(node_b_holder, MessageSendEvent::SendFundingSigned, node_a.get_our_node_id()));

		assert_eq!(&tx_broadcaster.txn_broadcasted.lock().unwrap()[..], &[tx.clone()]);

		let block = Block {
			header: BlockHeader { version: 0x20000000, prev_blockhash: BestBlock::from_network(network).block_hash(), merkle_root: TxMerkleNode::all_zeros(), time: 42, bits: 42, nonce: 42 },
			txdata: vec![tx],
		};
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

		let dummy_graph = NetworkGraph::new(network, &logger_a);

		let mut payment_count: u64 = 0;
		macro_rules! send_payment {
			($node_a: expr, $node_b: expr) => {
				let usable_channels = $node_a.list_usable_channels();
				let payment_params = PaymentParameters::from_node_id($node_b.get_our_node_id(), TEST_FINAL_CLTV)
					.with_features($node_b.invoice_features());
				let scorer = test_utils::TestScorer::new();
				let seed = [3u8; 32];
				let keys_manager = KeysManager::new(&seed, 42, 42);
				let random_seed_bytes = keys_manager.get_secure_random_bytes();
				let route = get_route(&$node_a.get_our_node_id(), &payment_params, &dummy_graph.read_only(),
					Some(&usable_channels.iter().map(|r| r).collect::<Vec<_>>()), 10_000, TEST_FINAL_CLTV, &logger_a, &scorer, &random_seed_bytes).unwrap();

				let mut payment_preimage = PaymentPreimage([0; 32]);
				payment_preimage.0[0..8].copy_from_slice(&payment_count.to_le_bytes());
				payment_count += 1;
				let payment_hash = PaymentHash(Sha256::hash(&payment_preimage.0[..]).into_inner());
				let payment_secret = $node_b.create_inbound_payment_for_hash(payment_hash, None, 7200, None).unwrap();

				$node_a.send_payment(&route, payment_hash, &Some(payment_secret), PaymentId(payment_hash.0)).unwrap();
				let payment_event = SendEvent::from_event($node_a.get_and_clear_pending_msg_events().pop().unwrap());
				$node_b.handle_update_add_htlc(&$node_a.get_our_node_id(), &payment_event.msgs[0]);
				$node_b.handle_commitment_signed(&$node_a.get_our_node_id(), &payment_event.commitment_msg);
				let (raa, cs) = do_get_revoke_commit_msgs!(NodeHolder { node: &$node_b }, &$node_a.get_our_node_id());
				$node_a.handle_revoke_and_ack(&$node_b.get_our_node_id(), &raa);
				$node_a.handle_commitment_signed(&$node_b.get_our_node_id(), &cs);
				$node_b.handle_revoke_and_ack(&$node_a.get_our_node_id(), &get_event_msg!(NodeHolder { node: &$node_a }, MessageSendEvent::SendRevokeAndACK, $node_b.get_our_node_id()));

				expect_pending_htlcs_forwardable!(NodeHolder { node: &$node_b });
				expect_payment_claimable!(NodeHolder { node: &$node_b }, payment_hash, payment_secret, 10_000);
				$node_b.claim_funds(payment_preimage);
				expect_payment_claimed!(NodeHolder { node: &$node_b }, payment_hash, 10_000);

				match $node_b.get_and_clear_pending_msg_events().pop().unwrap() {
					MessageSendEvent::UpdateHTLCs { node_id, updates } => {
						assert_eq!(node_id, $node_a.get_our_node_id());
						$node_a.handle_update_fulfill_htlc(&$node_b.get_our_node_id(), &updates.update_fulfill_htlcs[0]);
						$node_a.handle_commitment_signed(&$node_b.get_our_node_id(), &updates.commitment_signed);
					},
					_ => panic!("Failed to generate claim event"),
				}

				let (raa, cs) = do_get_revoke_commit_msgs!(NodeHolder { node: &$node_a }, &$node_b.get_our_node_id());
				$node_b.handle_revoke_and_ack(&$node_a.get_our_node_id(), &raa);
				$node_b.handle_commitment_signed(&$node_a.get_our_node_id(), &cs);
				$node_a.handle_revoke_and_ack(&$node_b.get_our_node_id(), &get_event_msg!(NodeHolder { node: &$node_b }, MessageSendEvent::SendRevokeAndACK, $node_a.get_our_node_id()));

				expect_payment_sent!(NodeHolder { node: &$node_a }, payment_preimage);
			}
		}

		bench.iter(|| {
			send_payment!(node_a, node_b);
			send_payment!(node_b, node_a);
		});
	}
}
