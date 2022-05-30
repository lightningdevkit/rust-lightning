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
//! It does not manage routing logic (see routing::router::get_route for that) nor does it manage constructing
//! on-chain transactions (it only monitors the chain to watch for any force-closes that might
//! imply it needs to fail HTLCs/payments/channels it manages).
//!

use bitcoin::blockdata::block::BlockHeader;
use bitcoin::blockdata::transaction::Transaction;
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::network::constants::Network;

use bitcoin::hashes::{Hash, HashEngine};
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::sha256d::Hash as Sha256dHash;
use bitcoin::hash_types::{BlockHash, Txid};

use bitcoin::secp256k1::{SecretKey,PublicKey};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::secp256k1::ecdh::SharedSecret;
use bitcoin::secp256k1;

use chain;
use chain::{Confirm, ChannelMonitorUpdateErr, Watch, BestBlock};
use chain::chaininterface::{BroadcasterInterface, ConfirmationTarget, FeeEstimator};
use chain::channelmonitor::{ChannelMonitor, ChannelMonitorUpdate, ChannelMonitorUpdateStep, HTLC_FAIL_BACK_BUFFER, CLTV_CLAIM_BUFFER, LATENCY_GRACE_PERIOD_BLOCKS, ANTI_REORG_DELAY, MonitorEvent, CLOSED_CHANNEL_UPDATE_ID};
use chain::transaction::{OutPoint, TransactionData};
// Since this struct is returned in `list_channels` methods, expose it here in case users want to
// construct one themselves.
use ln::{inbound_payment, PaymentHash, PaymentPreimage, PaymentSecret};
use ln::channel::{Channel, ChannelError, ChannelUpdateStatus, UpdateFulfillCommitFetch};
use ln::features::{ChannelTypeFeatures, InitFeatures, NodeFeatures};
use routing::router::{PaymentParameters, Route, RouteHop, RoutePath, RouteParameters};
use ln::msgs;
use ln::msgs::NetAddress;
use ln::onion_utils;
use ln::msgs::{ChannelMessageHandler, DecodeError, LightningError, MAX_VALUE_MSAT, OptionalField};
use ln::wire::Encode;
use chain::keysinterface::{Sign, KeysInterface, KeysManager, InMemorySigner, Recipient};
use util::config::UserConfig;
use util::events::{EventHandler, EventsProvider, MessageSendEvent, MessageSendEventsProvider, ClosureReason};
use util::{byte_utils, events};
use util::scid_utils::fake_scid;
use util::ser::{BigSize, FixedLengthReader, Readable, ReadableArgs, MaybeReadable, Writeable, Writer, VecWriter};
use util::logger::{Level, Logger};
use util::errors::APIError;

use io;
use prelude::*;
use core::{cmp, mem};
use core::cell::RefCell;
use io::Read;
use sync::{Arc, Condvar, Mutex, MutexGuard, RwLock, RwLockReadGuard};
use core::sync::atomic::{AtomicUsize, Ordering};
use core::time::Duration;
use core::ops::Deref;

#[cfg(any(test, feature = "std"))]
use std::time::Instant;
use util::crypto::sign;

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
		/// The SCID from the onion that we should forward to. This could be a "real" SCID, an
		/// outbound SCID alias, or a phantom node SCID.
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
	pub(super) amt_to_forward: u64,
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

pub(super) enum HTLCForwardInfo {
	AddHTLC {
		forward_info: PendingHTLCInfo,

		// These fields are produced in `forward_htlcs()` and consumed in
		// `process_pending_htlc_forwards()` for constructing the
		// `HTLCSource::PreviousHopData` for failed and forwarded
		// HTLCs.
		//
		// Note that this may be an outbound SCID alias for the associated channel.
		prev_short_channel_id: u64,
		prev_htlc_id: u64,
		prev_funding_outpoint: OutPoint,
	},
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

#[derive(Clone)] // See Channel::revoke_and_ack for why, tl;dr: Rust bug
pub(super) enum HTLCFailReason {
	LightningError {
		err: msgs::OnionErrorPacket,
	},
	Reason {
		failure_code: u16,
		data: Vec<u8>,
	}
}

struct ReceiveError {
	err_code: u16,
	err_data: Vec<u8>,
	msg: &'static str,
}

/// Return value for claim_funds_from_hop
enum ClaimFundsFromHop {
	PrevHopForceClosed,
	MonitorUpdateFail(PublicKey, MsgHandleErrInternal, Option<u64>),
	Success(u64),
	DuplicateClaim,
}

type ShutdownResult = (Option<(OutPoint, ChannelMonitorUpdate)>, Vec<(HTLCSource, PaymentHash)>);

/// Error type returned across the channel_state mutex boundary. When an Err is generated for a
/// Channel, we generally end up with a ChannelError::Close for which we have to close the channel
/// immediately (ie with no further calls on it made). Thus, this step happens inside a
/// channel_state lock. We then return the set of things that need to be done outside the lock in
/// this struct and call handle_error!() on it.

struct MsgHandleErrInternal {
	err: msgs::LightningError,
	chan_id: Option<([u8; 32], u64)>, // If Some a channel of ours has been closed
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
	fn ignore_no_close(err: String) -> Self {
		Self {
			err: LightningError {
				err,
				action: msgs::ErrorAction::IgnoreError,
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
	fn from_finish_shutdown(err: String, channel_id: [u8; 32], user_channel_id: u64, shutdown_res: ShutdownResult, channel_update: Option<msgs::ChannelUpdate>) -> Self {
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
				ChannelError::CloseDelayBroadcast(msg) => LightningError {
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
const MIN_HTLC_RELAY_HOLDING_CELL_MILLIS: u64 = 100;

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

// Note this is only exposed in cfg(test):
pub(super) struct ChannelHolder<Signer: Sign> {
	pub(super) by_id: HashMap<[u8; 32], Channel<Signer>>,
	/// SCIDs (and outbound SCID aliases) to the real channel id. Outbound SCID aliases are added
	/// here once the channel is available for normal use, with SCIDs being added once the funding
	/// transaction is confirmed at the channel's required confirmation depth.
	pub(super) short_to_id: HashMap<u64, [u8; 32]>,
	/// SCID/SCID Alias -> forward infos. Key of 0 means payments received.
	///
	/// Note that because we may have an SCID Alias as the key we can have two entries per channel,
	/// though in practice we probably won't be receiving HTLCs for a channel both via the alias
	/// and via the classic SCID.
	///
	/// Note that while this is held in the same mutex as the channels themselves, no consistency
	/// guarantees are made about the existence of a channel with the short id here, nor the short
	/// ids in the PendingHTLCInfo!
	pub(super) forward_htlcs: HashMap<u64, Vec<HTLCForwardInfo>>,
	/// Map from payment hash to the payment data and any HTLCs which are to us and can be
	/// failed/claimed by the user.
	///
	/// Note that while this is held in the same mutex as the channels themselves, no consistency
	/// guarantees are made about the channels given here actually existing anymore by the time you
	/// go to read them!
	claimable_htlcs: HashMap<PaymentHash, (events::PaymentPurpose, Vec<ClaimableHTLC>)>,
	/// Messages to send to peers - pushed to in the same lock that they are generated in (except
	/// for broadcast messages, where ordering isn't as strict).
	pub(super) pending_msg_events: Vec<MessageSendEvent>,
}

/// Events which we process internally but cannot be procsesed immediately at the generation site
/// for some reason. They are handled in timer_tick_occurred, so may be processed with
/// quite some time lag.
enum BackgroundEvent {
	/// Handle a ChannelMonitorUpdate that closes a channel, broadcasting its current latest holder
	/// commitment transaction.
	ClosingMonitorUpdate((OutPoint, ChannelMonitorUpdate)),
}

/// State we hold per-peer. In the future we should put channels in here, but for now we only hold
/// the latest Init features we heard from the peer.
struct PeerState {
	latest_features: InitFeatures,
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

/// Stores the session_priv for each part of a payment that is still pending. For versions 0.0.102
/// and later, also stores information for retrying the payment.
pub(crate) enum PendingOutboundPayment {
	Legacy {
		session_privs: HashSet<[u8; 32]>,
	},
	Retryable {
		session_privs: HashSet<[u8; 32]>,
		payment_hash: PaymentHash,
		payment_secret: Option<PaymentSecret>,
		pending_amt_msat: u64,
		/// Used to track the fee paid. Only present if the payment was serialized on 0.0.103+.
		pending_fee_msat: Option<u64>,
		/// The total payment amount across all paths, used to verify that a retry is not overpaying.
		total_msat: u64,
		/// Our best known block height at the time this payment was initiated.
		starting_block_height: u32,
	},
	/// When a pending payment is fulfilled, we continue tracking it until all pending HTLCs have
	/// been resolved. This ensures we don't look up pending payments in ChannelMonitors on restart
	/// and add a pending payment that was already fulfilled.
	Fulfilled {
		session_privs: HashSet<[u8; 32]>,
		payment_hash: Option<PaymentHash>,
	},
	/// When a payer gives up trying to retry a payment, they inform us, letting us generate a
	/// `PaymentFailed` event when all HTLCs have irrevocably failed. This avoids a number of race
	/// conditions in MPP-aware payment retriers (1), where the possibility of multiple
	/// `PaymentPathFailed` events with `all_paths_failed` can be pending at once, confusing a
	/// downstream event handler as to when a payment has actually failed.
	///
	/// (1) https://github.com/lightningdevkit/rust-lightning/issues/1164
	Abandoned {
		session_privs: HashSet<[u8; 32]>,
		payment_hash: PaymentHash,
	},
}

impl PendingOutboundPayment {
	fn is_retryable(&self) -> bool {
		match self {
			PendingOutboundPayment::Retryable { .. } => true,
			_ => false,
		}
	}
	fn is_fulfilled(&self) -> bool {
		match self {
			PendingOutboundPayment::Fulfilled { .. } => true,
			_ => false,
		}
	}
	fn abandoned(&self) -> bool {
		match self {
			PendingOutboundPayment::Abandoned { .. } => true,
			_ => false,
		}
	}
	fn get_pending_fee_msat(&self) -> Option<u64> {
		match self {
			PendingOutboundPayment::Retryable { pending_fee_msat, .. } => pending_fee_msat.clone(),
			_ => None,
		}
	}

	fn payment_hash(&self) -> Option<PaymentHash> {
		match self {
			PendingOutboundPayment::Legacy { .. } => None,
			PendingOutboundPayment::Retryable { payment_hash, .. } => Some(*payment_hash),
			PendingOutboundPayment::Fulfilled { payment_hash, .. } => *payment_hash,
			PendingOutboundPayment::Abandoned { payment_hash, .. } => Some(*payment_hash),
		}
	}

	fn mark_fulfilled(&mut self) {
		let mut session_privs = HashSet::new();
		core::mem::swap(&mut session_privs, match self {
			PendingOutboundPayment::Legacy { session_privs } |
			PendingOutboundPayment::Retryable { session_privs, .. } |
			PendingOutboundPayment::Fulfilled { session_privs, .. } |
			PendingOutboundPayment::Abandoned { session_privs, .. }
				=> session_privs,
		});
		let payment_hash = self.payment_hash();
		*self = PendingOutboundPayment::Fulfilled { session_privs, payment_hash };
	}

	fn mark_abandoned(&mut self) -> Result<(), ()> {
		let mut session_privs = HashSet::new();
		let our_payment_hash;
		core::mem::swap(&mut session_privs, match self {
			PendingOutboundPayment::Legacy { .. } |
			PendingOutboundPayment::Fulfilled { .. } =>
				return Err(()),
			PendingOutboundPayment::Retryable { session_privs, payment_hash, .. } |
			PendingOutboundPayment::Abandoned { session_privs, payment_hash, .. } => {
				our_payment_hash = *payment_hash;
				session_privs
			},
		});
		*self = PendingOutboundPayment::Abandoned { session_privs, payment_hash: our_payment_hash };
		Ok(())
	}

	/// panics if path is None and !self.is_fulfilled
	fn remove(&mut self, session_priv: &[u8; 32], path: Option<&Vec<RouteHop>>) -> bool {
		let remove_res = match self {
			PendingOutboundPayment::Legacy { session_privs } |
			PendingOutboundPayment::Retryable { session_privs, .. } |
			PendingOutboundPayment::Fulfilled { session_privs, .. } |
			PendingOutboundPayment::Abandoned { session_privs, .. } => {
				session_privs.remove(session_priv)
			}
		};
		if remove_res {
			if let PendingOutboundPayment::Retryable { ref mut pending_amt_msat, ref mut pending_fee_msat, .. } = self {
				let path = path.expect("Fulfilling a payment should always come with a path");
				let path_last_hop = path.last().expect("Outbound payments must have had a valid path");
				*pending_amt_msat -= path_last_hop.fee_msat;
				if let Some(fee_msat) = pending_fee_msat.as_mut() {
					*fee_msat -= path.get_path_fees();
				}
			}
		}
		remove_res
	}

	fn insert(&mut self, session_priv: [u8; 32], path: &Vec<RouteHop>) -> bool {
		let insert_res = match self {
			PendingOutboundPayment::Legacy { session_privs } |
			PendingOutboundPayment::Retryable { session_privs, .. } => {
				session_privs.insert(session_priv)
			}
			PendingOutboundPayment::Fulfilled { .. } => false,
			PendingOutboundPayment::Abandoned { .. } => false,
		};
		if insert_res {
			if let PendingOutboundPayment::Retryable { ref mut pending_amt_msat, ref mut pending_fee_msat, .. } = self {
				let path_last_hop = path.last().expect("Outbound payments must have had a valid path");
				*pending_amt_msat += path_last_hop.fee_msat;
				if let Some(fee_msat) = pending_fee_msat.as_mut() {
					*fee_msat += path.get_path_fees();
				}
			}
		}
		insert_res
	}

	fn remaining_parts(&self) -> usize {
		match self {
			PendingOutboundPayment::Legacy { session_privs } |
			PendingOutboundPayment::Retryable { session_privs, .. } |
			PendingOutboundPayment::Fulfilled { session_privs, .. } |
			PendingOutboundPayment::Abandoned { session_privs, .. } => {
				session_privs.len()
			}
		}
	}
}

/// SimpleArcChannelManager is useful when you need a ChannelManager with a static lifetime, e.g.
/// when you're using lightning-net-tokio (since tokio::spawn requires parameters with static
/// lifetimes). Other times you can afford a reference, which is more efficient, in which case
/// SimpleRefChannelManager is the more appropriate type. Defining these type aliases prevents
/// issues such as overly long function definitions. Note that the ChannelManager can take any
/// type that implements KeysInterface for its keys manager, but this type alias chooses the
/// concrete type of the KeysManager.
///
/// (C-not exported) as Arcs don't make sense in bindings
pub type SimpleArcChannelManager<M, T, F, L> = ChannelManager<InMemorySigner, Arc<M>, Arc<T>, Arc<KeysManager>, Arc<F>, Arc<L>>;

/// SimpleRefChannelManager is a type alias for a ChannelManager reference, and is the reference
/// counterpart to the SimpleArcChannelManager type alias. Use this type by default when you don't
/// need a ChannelManager with a static lifetime. You'll need a static lifetime in cases such as
/// usage of lightning-net-tokio (since tokio::spawn requires parameters with static lifetimes).
/// But if this is not necessary, using a reference is more efficient. Defining these type aliases
/// helps with issues such as long function definitions. Note that the ChannelManager can take any
/// type that implements KeysInterface for its keys manager, but this type alias chooses the
/// concrete type of the KeysManager.
///
/// (C-not exported) as Arcs don't make sense in bindings
pub type SimpleRefChannelManager<'a, 'b, 'c, 'd, 'e, M, T, F, L> = ChannelManager<InMemorySigner, &'a M, &'b T, &'c KeysManager, &'d F, &'e L>;

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
/// Rather than using a plain ChannelManager, it is preferable to use either a SimpleArcChannelManager
/// a SimpleRefChannelManager, for conciseness. See their documentation for more details, but
/// essentially you should default to using a SimpleRefChannelManager, and use a
/// SimpleArcChannelManager when you require a ChannelManager with a static lifetime, such as when
/// you're using lightning-net-tokio.
pub struct ChannelManager<Signer: Sign, M: Deref, T: Deref, K: Deref, F: Deref, L: Deref>
	where M::Target: chain::Watch<Signer>,
        T::Target: BroadcasterInterface,
        K::Target: KeysInterface<Signer = Signer>,
        F::Target: FeeEstimator,
				L::Target: Logger,
{
	default_configuration: UserConfig,
	genesis_hash: BlockHash,
	fee_estimator: F,
	chain_monitor: M,
	tx_broadcaster: T,

	#[cfg(test)]
	pub(super) best_block: RwLock<BestBlock>,
	#[cfg(not(test))]
	best_block: RwLock<BestBlock>,
	secp_ctx: Secp256k1<secp256k1::All>,

	#[cfg(any(test, feature = "_test_utils"))]
	pub(super) channel_state: Mutex<ChannelHolder<Signer>>,
	#[cfg(not(any(test, feature = "_test_utils")))]
	channel_state: Mutex<ChannelHolder<Signer>>,

	/// Storage for PaymentSecrets and any requirements on future inbound payments before we will
	/// expose them to users via a PaymentReceived event. HTLCs which do not meet the requirements
	/// here are failed when we process them as pending-forwardable-HTLCs, and entries are removed
	/// after we generate a PaymentReceived upon receipt of all MPP parts or when they time out.
	/// Locked *after* channel_state.
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
	/// Locked *after* channel_state.
	pending_outbound_payments: Mutex<HashMap<PaymentId, PendingOutboundPayment>>,

	/// The set of outbound SCID aliases across all our channels, including unconfirmed channels
	/// and some closed channels which reached a usable state prior to being closed. This is used
	/// only to avoid duplicates, and is not persisted explicitly to disk, but rebuilt from the
	/// active channel list on load.
	outbound_scid_aliases: Mutex<HashSet<u64>>,

	our_network_key: SecretKey,
	our_network_pubkey: PublicKey,

	inbound_payment_key: inbound_payment::ExpandedKey,

	/// LDK puts the [fake scids] that it generates into namespaces, to identify the type of an
	/// incoming payment. To make it harder for a third-party to identify the type of a payment,
	/// we encrypt the namespace identifier using these bytes.
	///
	/// [fake scids]: crate::util::scid_utils::fake_scid
	fake_scid_rand_bytes: [u8; 32],

	/// Used to track the last value sent in a node_announcement "timestamp" field. We ensure this
	/// value increases strictly since we don't assume access to a time source.
	last_node_announcement_serial: AtomicUsize,

	/// The highest block timestamp we've seen, which is usually a good guess at the current time.
	/// Assuming most miners are generating blocks with reasonable timestamps, this shouldn't be
	/// very far in the past, and can only ever be up to two hours in the future.
	highest_seen_timestamp: AtomicUsize,

	/// The bulk of our storage will eventually be here (channels and message queues and the like).
	/// If we are connected to a peer we always at least have an entry here, even if no channels
	/// are currently open with that peer.
	/// Because adding or removing an entry is rare, we usually take an outer read lock and then
	/// operate on the inner value freely. Sadly, this prevents parallel operation when opening a
	/// new channel.
	///
	/// If also holding `channel_state` lock, must lock `channel_state` prior to `per_peer_state`.
	per_peer_state: RwLock<HashMap<PublicKey, Mutex<PeerState>>>,

	pending_events: Mutex<Vec<events::Event>>,
	pending_background_events: Mutex<Vec<BackgroundEvent>>,
	/// Used when we have to take a BIG lock to make sure everything is self-consistent.
	/// Essentially just when we're serializing ourselves out.
	/// Taken first everywhere where we are making changes before any other locks.
	/// When acquiring this lock in read mode, rather than acquiring it directly, call
	/// `PersistenceNotifierGuard::notify_on_drop(..)` and pass the lock to it, to ensure the
	/// PersistenceNotifier the lock contains sends out a notification when the lock is released.
	total_consistency_lock: RwLock<()>,

	persistence_notifier: PersistenceNotifier,

	keys_manager: K,

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
	persistence_notifier: &'a PersistenceNotifier,
	should_persist: F,
	// We hold onto this result so the lock doesn't get released immediately.
	_read_guard: RwLockReadGuard<'a, ()>,
}

impl<'a> PersistenceNotifierGuard<'a, fn() -> NotifyOption> { // We don't care what the concrete F is here, it's unused
	fn notify_on_drop(lock: &'a RwLock<()>, notifier: &'a PersistenceNotifier) -> PersistenceNotifierGuard<'a, impl Fn() -> NotifyOption> {
		PersistenceNotifierGuard::optionally_notify(lock, notifier, || -> NotifyOption { NotifyOption::DoPersist })
	}

	fn optionally_notify<F: Fn() -> NotifyOption>(lock: &'a RwLock<()>, notifier: &'a PersistenceNotifier, persist_check: F) -> PersistenceNotifierGuard<'a, F> {
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
pub(super) const CLTV_FAR_FAR_AWAY: u32 = 6 * 24 * 7; //TODO?

/// Minimum CLTV difference between the current block height and received inbound payments.
/// Invoices generated for payment to us must set their `min_final_cltv_expiry` field to at least
/// this value.
// Note that we fail if exactly HTLC_FAIL_BACK_BUFFER + 1 was used, so we need to add one for
// any payments to succeed. Further, we don't want payments to fail if a block was found while
// a payment was being routed, so we add an extra block to be safe.
pub const MIN_FINAL_CLTV_EXPIRY: u32 = HTLC_FAIL_BACK_BUFFER + 3;

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

/// The number of blocks before we consider an outbound payment for expiry if it doesn't have any
/// pending HTLCs in flight.
pub(crate) const PAYMENT_EXPIRY_BLOCKS: u32 = 3;

/// The number of ticks of [`ChannelManager::timer_tick_occurred`] until expiry of incomplete MPPs
pub(crate) const MPP_TIMEOUT_TICKS: u8 = 3;

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
	/// The `user_channel_id` passed in to create_channel, or 0 if the channel was inbound.
	pub user_channel_id: u64,
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

/// If a payment fails to send, it can be in one of several states. This enum is returned as the
/// Err() type describing which state the payment is in, see the description of individual enum
/// states for more.
#[derive(Clone, Debug)]
pub enum PaymentSendFailure {
	/// A parameter which was passed to send_payment was invalid, preventing us from attempting to
	/// send the payment at all. No channel state has been changed or messages sent to peers, and
	/// once you've changed the parameter at error, you can freely retry the payment in full.
	ParameterError(APIError),
	/// A parameter in a single path which was passed to send_payment was invalid, preventing us
	/// from attempting to send the payment at all. No channel state has been changed or messages
	/// sent to peers, and once you've changed the parameter at error, you can freely retry the
	/// payment in full.
	///
	/// The results here are ordered the same as the paths in the route object which was passed to
	/// send_payment.
	PathParameterError(Vec<Result<(), APIError>>),
	/// All paths which were attempted failed to send, with no channel state change taking place.
	/// You can freely retry the payment in full (though you probably want to do so over different
	/// paths than the ones selected).
	AllFailedRetrySafe(Vec<APIError>),
	/// Some paths which were attempted failed to send, though possibly not all. At least some
	/// paths have irrevocably committed to the HTLC and retrying the payment in full would result
	/// in over-/re-payment.
	///
	/// The results here are ordered the same as the paths in the route object which was passed to
	/// send_payment, and any Errs which are not APIError::MonitorUpdateFailed can be safely
	/// retried (though there is currently no API with which to do so).
	///
	/// Any entries which contain Err(APIError::MonitorUpdateFailed) or Ok(()) MUST NOT be retried
	/// as they will result in over-/re-payment. These HTLCs all either successfully sent (in the
	/// case of Ok(())) or will send once channel_monitor_updated is called on the next-hop channel
	/// with the latest update_id.
	PartialFailure {
		/// The errors themselves, in the same order as the route hops.
		results: Vec<Result<(), APIError>>,
		/// If some paths failed without irrevocably committing to the new HTLC(s), this will
		/// contain a [`RouteParameters`] object which can be used to calculate a new route that
		/// will pay all remaining unpaid balance.
		failed_paths_retry: Option<RouteParameters>,
		/// The payment id for the payment, which is now at least partially pending.
		payment_id: PaymentId,
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
				#[cfg(debug_assertions)]
				{
					// In testing, ensure there are no deadlocks where the lock is already held upon
					// entering the macro.
					assert!($self.channel_state.try_lock().is_ok());
					assert!($self.pending_events.try_lock().is_ok());
				}

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
					$self.channel_state.lock().unwrap().pending_msg_events.append(&mut msg_events);
				}

				// Return error in case higher-API need one
				Err(err)
			},
		}
	}
}

macro_rules! update_maps_on_chan_removal {
	($self: expr, $short_to_id: expr, $channel: expr) => {
		if let Some(short_id) = $channel.get_short_channel_id() {
			$short_to_id.remove(&short_id);
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
		$short_to_id.remove(&$channel.outbound_scid_alias());
	}
}

/// Returns (boolean indicating if we should remove the Channel object from memory, a mapped error)
macro_rules! convert_chan_err {
	($self: ident, $err: expr, $short_to_id: expr, $channel: expr, $channel_id: expr) => {
		match $err {
			ChannelError::Warn(msg) => {
				(false, MsgHandleErrInternal::from_chan_no_close(ChannelError::Warn(msg), $channel_id.clone()))
			},
			ChannelError::Ignore(msg) => {
				(false, MsgHandleErrInternal::from_chan_no_close(ChannelError::Ignore(msg), $channel_id.clone()))
			},
			ChannelError::Close(msg) => {
				log_error!($self.logger, "Closing channel {} due to close-required error: {}", log_bytes!($channel_id[..]), msg);
				update_maps_on_chan_removal!($self, $short_to_id, $channel);
				let shutdown_res = $channel.force_shutdown(true);
				(true, MsgHandleErrInternal::from_finish_shutdown(msg, *$channel_id, $channel.get_user_id(),
					shutdown_res, $self.get_channel_update_for_broadcast(&$channel).ok()))
			},
			ChannelError::CloseDelayBroadcast(msg) => {
				log_error!($self.logger, "Channel {} need to be shutdown but closing transactions not broadcast due to {}", log_bytes!($channel_id[..]), msg);
				update_maps_on_chan_removal!($self, $short_to_id, $channel);
				let shutdown_res = $channel.force_shutdown(false);
				(true, MsgHandleErrInternal::from_finish_shutdown(msg, *$channel_id, $channel.get_user_id(),
					shutdown_res, $self.get_channel_update_for_broadcast(&$channel).ok()))
			}
		}
	}
}

macro_rules! break_chan_entry {
	($self: ident, $res: expr, $channel_state: expr, $entry: expr) => {
		match $res {
			Ok(res) => res,
			Err(e) => {
				let (drop, res) = convert_chan_err!($self, e, $channel_state.short_to_id, $entry.get_mut(), $entry.key());
				if drop {
					$entry.remove_entry();
				}
				break Err(res);
			}
		}
	}
}

macro_rules! try_chan_entry {
	($self: ident, $res: expr, $channel_state: expr, $entry: expr) => {
		match $res {
			Ok(res) => res,
			Err(e) => {
				let (drop, res) = convert_chan_err!($self, e, $channel_state.short_to_id, $entry.get_mut(), $entry.key());
				if drop {
					$entry.remove_entry();
				}
				return Err(res);
			}
		}
	}
}

macro_rules! remove_channel {
	($self: expr, $channel_state: expr, $entry: expr) => {
		{
			let channel = $entry.remove_entry().1;
			update_maps_on_chan_removal!($self, $channel_state.short_to_id, channel);
			channel
		}
	}
}

macro_rules! handle_monitor_err {
	($self: ident, $err: expr, $short_to_id: expr, $chan: expr, $action_type: path, $resend_raa: expr, $resend_commitment: expr, $resend_channel_ready: expr, $failed_forwards: expr, $failed_fails: expr, $failed_finalized_fulfills: expr, $chan_id: expr) => {
		match $err {
			ChannelMonitorUpdateErr::PermanentFailure => {
				log_error!($self.logger, "Closing channel {} due to monitor update ChannelMonitorUpdateErr::PermanentFailure", log_bytes!($chan_id[..]));
				update_maps_on_chan_removal!($self, $short_to_id, $chan);
				// TODO: $failed_fails is dropped here, which will cause other channels to hit the
				// chain in a confused state! We need to move them into the ChannelMonitor which
				// will be responsible for failing backwards once things confirm on-chain.
				// It's ok that we drop $failed_forwards here - at this point we'd rather they
				// broadcast HTLC-Timeout and pay the associated fees to get their funds back than
				// us bother trying to claim it just to forward on to another peer. If we're
				// splitting hairs we'd prefer to claim payments that were to us, but we haven't
				// given up the preimage yet, so might as well just wait until the payment is
				// retried, avoiding the on-chain fees.
				let res: Result<(), _> = Err(MsgHandleErrInternal::from_finish_shutdown("ChannelMonitor storage failure".to_owned(), *$chan_id, $chan.get_user_id(),
						$chan.force_shutdown(true), $self.get_channel_update_for_broadcast(&$chan).ok() ));
				(res, true)
			},
			ChannelMonitorUpdateErr::TemporaryFailure => {
				log_info!($self.logger, "Disabling channel {} due to monitor update TemporaryFailure. On restore will send {} and process {} forwards, {} fails, and {} fulfill finalizations",
						log_bytes!($chan_id[..]),
						if $resend_commitment && $resend_raa {
								match $action_type {
									RAACommitmentOrder::CommitmentFirst => { "commitment then RAA" },
									RAACommitmentOrder::RevokeAndACKFirst => { "RAA then commitment" },
								}
							} else if $resend_commitment { "commitment" }
							else if $resend_raa { "RAA" }
							else { "nothing" },
						(&$failed_forwards as &Vec<(PendingHTLCInfo, u64)>).len(),
						(&$failed_fails as &Vec<(HTLCSource, PaymentHash, HTLCFailReason)>).len(),
						(&$failed_finalized_fulfills as &Vec<HTLCSource>).len());
				if !$resend_commitment {
					debug_assert!($action_type == RAACommitmentOrder::RevokeAndACKFirst || !$resend_raa);
				}
				if !$resend_raa {
					debug_assert!($action_type == RAACommitmentOrder::CommitmentFirst || !$resend_commitment);
				}
				$chan.monitor_update_failed($resend_raa, $resend_commitment, $resend_channel_ready, $failed_forwards, $failed_fails, $failed_finalized_fulfills);
				(Err(MsgHandleErrInternal::from_chan_no_close(ChannelError::Ignore("Failed to update ChannelMonitor".to_owned()), *$chan_id)), false)
			},
		}
	};
	($self: ident, $err: expr, $channel_state: expr, $entry: expr, $action_type: path, $resend_raa: expr, $resend_commitment: expr, $resend_channel_ready: expr, $failed_forwards: expr, $failed_fails: expr, $failed_finalized_fulfills: expr) => { {
		let (res, drop) = handle_monitor_err!($self, $err, $channel_state.short_to_id, $entry.get_mut(), $action_type, $resend_raa, $resend_commitment, $resend_channel_ready, $failed_forwards, $failed_fails, $failed_finalized_fulfills, $entry.key());
		if drop {
			$entry.remove_entry();
		}
		res
	} };
	($self: ident, $err: expr, $channel_state: expr, $entry: expr, $action_type: path, $chan_id: expr, COMMITMENT_UPDATE_ONLY) => { {
		debug_assert!($action_type == RAACommitmentOrder::CommitmentFirst);
		handle_monitor_err!($self, $err, $channel_state, $entry, $action_type, false, true, false, Vec::new(), Vec::new(), Vec::new(), $chan_id)
	} };
	($self: ident, $err: expr, $channel_state: expr, $entry: expr, $action_type: path, $chan_id: expr, NO_UPDATE) => {
		handle_monitor_err!($self, $err, $channel_state, $entry, $action_type, false, false, false, Vec::new(), Vec::new(), Vec::new(), $chan_id)
	};
	($self: ident, $err: expr, $channel_state: expr, $entry: expr, $action_type: path, $resend_channel_ready: expr, OPTIONALLY_RESEND_FUNDING_LOCKED) => {
		handle_monitor_err!($self, $err, $channel_state, $entry, $action_type, false, false, $resend_channel_ready, Vec::new(), Vec::new(), Vec::new())
	};
	($self: ident, $err: expr, $channel_state: expr, $entry: expr, $action_type: path, $resend_raa: expr, $resend_commitment: expr) => {
		handle_monitor_err!($self, $err, $channel_state, $entry, $action_type, $resend_raa, $resend_commitment, false, Vec::new(), Vec::new(), Vec::new())
	};
	($self: ident, $err: expr, $channel_state: expr, $entry: expr, $action_type: path, $resend_raa: expr, $resend_commitment: expr, $failed_forwards: expr, $failed_fails: expr) => {
		handle_monitor_err!($self, $err, $channel_state, $entry, $action_type, $resend_raa, $resend_commitment, false, $failed_forwards, $failed_fails, Vec::new())
	};
}

macro_rules! return_monitor_err {
	($self: ident, $err: expr, $channel_state: expr, $entry: expr, $action_type: path, $resend_raa: expr, $resend_commitment: expr) => {
		return handle_monitor_err!($self, $err, $channel_state, $entry, $action_type, $resend_raa, $resend_commitment);
	};
	($self: ident, $err: expr, $channel_state: expr, $entry: expr, $action_type: path, $resend_raa: expr, $resend_commitment: expr, $failed_forwards: expr, $failed_fails: expr) => {
		return handle_monitor_err!($self, $err, $channel_state, $entry, $action_type, $resend_raa, $resend_commitment, $failed_forwards, $failed_fails);
	}
}

// Does not break in case of TemporaryFailure!
macro_rules! maybe_break_monitor_err {
	($self: ident, $err: expr, $channel_state: expr, $entry: expr, $action_type: path, $resend_raa: expr, $resend_commitment: expr) => {
		match (handle_monitor_err!($self, $err, $channel_state, $entry, $action_type, $resend_raa, $resend_commitment), $err) {
			(e, ChannelMonitorUpdateErr::PermanentFailure) => {
				break e;
			},
			(_, ChannelMonitorUpdateErr::TemporaryFailure) => { },
		}
	}
}

macro_rules! send_channel_ready {
	($short_to_id: expr, $pending_msg_events: expr, $channel: expr, $channel_ready_msg: expr) => {
		$pending_msg_events.push(events::MessageSendEvent::SendChannelReady {
			node_id: $channel.get_counterparty_node_id(),
			msg: $channel_ready_msg,
		});
		// Note that we may send a `channel_ready` multiple times for a channel if we reconnect, so
		// we allow collisions, but we shouldn't ever be updating the channel ID pointed to.
		let outbound_alias_insert = $short_to_id.insert($channel.outbound_scid_alias(), $channel.channel_id());
		assert!(outbound_alias_insert.is_none() || outbound_alias_insert.unwrap() == $channel.channel_id(),
			"SCIDs should never collide - ensure you weren't behind the chain tip by a full month when creating channels");
		if let Some(real_scid) = $channel.get_short_channel_id() {
			let scid_insert = $short_to_id.insert(real_scid, $channel.channel_id());
			assert!(scid_insert.is_none() || scid_insert.unwrap() == $channel.channel_id(),
				"SCIDs should never collide - ensure you weren't behind the chain tip by a full month when creating channels");
		}
	}
}

macro_rules! handle_chan_restoration_locked {
	($self: ident, $channel_lock: expr, $channel_state: expr, $channel_entry: expr,
	 $raa: expr, $commitment_update: expr, $order: expr, $chanmon_update: expr,
	 $pending_forwards: expr, $funding_broadcastable: expr, $channel_ready: expr, $announcement_sigs: expr) => { {
		let mut htlc_forwards = None;

		let chanmon_update: Option<ChannelMonitorUpdate> = $chanmon_update; // Force type-checking to resolve
		let chanmon_update_is_none = chanmon_update.is_none();
		let counterparty_node_id = $channel_entry.get().get_counterparty_node_id();
		let res = loop {
			let forwards: Vec<(PendingHTLCInfo, u64)> = $pending_forwards; // Force type-checking to resolve
			if !forwards.is_empty() {
				htlc_forwards = Some(($channel_entry.get().get_short_channel_id().unwrap_or($channel_entry.get().outbound_scid_alias()),
					$channel_entry.get().get_funding_txo().unwrap(), forwards));
			}

			if chanmon_update.is_some() {
				// On reconnect, we, by definition, only resend a channel_ready if there have been
				// no commitment updates, so the only channel monitor update which could also be
				// associated with a channel_ready would be the funding_created/funding_signed
				// monitor update. That monitor update failing implies that we won't send
				// channel_ready until it's been updated, so we can't have a channel_ready and a
				// monitor update here (so we don't bother to handle it correctly below).
				assert!($channel_ready.is_none());
				// A channel monitor update makes no sense without either a channel_ready or a
				// commitment update to process after it. Since we can't have a channel_ready, we
				// only bother to handle the monitor-update + commitment_update case below.
				assert!($commitment_update.is_some());
			}

			if let Some(msg) = $channel_ready {
				// Similar to the above, this implies that we're letting the channel_ready fly
				// before it should be allowed to.
				assert!(chanmon_update.is_none());
				send_channel_ready!($channel_state.short_to_id, $channel_state.pending_msg_events, $channel_entry.get(), msg);
			}
			if let Some(msg) = $announcement_sigs {
				$channel_state.pending_msg_events.push(events::MessageSendEvent::SendAnnouncementSignatures {
					node_id: counterparty_node_id,
					msg,
				});
			}

			let funding_broadcastable: Option<Transaction> = $funding_broadcastable; // Force type-checking to resolve
			if let Some(monitor_update) = chanmon_update {
				// We only ever broadcast a funding transaction in response to a funding_signed
				// message and the resulting monitor update. Thus, on channel_reestablish
				// message handling we can't have a funding transaction to broadcast. When
				// processing a monitor update finishing resulting in a funding broadcast, we
				// cannot have a second monitor update, thus this case would indicate a bug.
				assert!(funding_broadcastable.is_none());
				// Given we were just reconnected or finished updating a channel monitor, the
				// only case where we can get a new ChannelMonitorUpdate would be if we also
				// have some commitment updates to send as well.
				assert!($commitment_update.is_some());
				if let Err(e) = $self.chain_monitor.update_channel($channel_entry.get().get_funding_txo().unwrap(), monitor_update) {
					// channel_reestablish doesn't guarantee the order it returns is sensical
					// for the messages it returns, but if we're setting what messages to
					// re-transmit on monitor update success, we need to make sure it is sane.
					let mut order = $order;
					if $raa.is_none() {
						order = RAACommitmentOrder::CommitmentFirst;
					}
					break handle_monitor_err!($self, e, $channel_state, $channel_entry, order, $raa.is_some(), true);
				}
			}

			macro_rules! handle_cs { () => {
				if let Some(update) = $commitment_update {
					$channel_state.pending_msg_events.push(events::MessageSendEvent::UpdateHTLCs {
						node_id: counterparty_node_id,
						updates: update,
					});
				}
			} }
			macro_rules! handle_raa { () => {
				if let Some(revoke_and_ack) = $raa {
					$channel_state.pending_msg_events.push(events::MessageSendEvent::SendRevokeAndACK {
						node_id: counterparty_node_id,
						msg: revoke_and_ack,
					});
				}
			} }
			match $order {
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
				log_info!($self.logger, "Broadcasting funding transaction with txid {}", tx.txid());
				$self.tx_broadcaster.broadcast_transaction(&tx);
			}
			break Ok(());
		};

		if chanmon_update_is_none {
			// If there was no ChannelMonitorUpdate, we should never generate an Err in the res loop
			// above. Doing so would imply calling handle_err!() from channel_monitor_updated() which
			// should *never* end up calling back to `chain_monitor.update_channel()`.
			assert!(res.is_ok());
		}

		(htlc_forwards, res, counterparty_node_id)
	} }
}

macro_rules! post_handle_chan_restoration {
	($self: ident, $locked_res: expr) => { {
		let (htlc_forwards, res, counterparty_node_id) = $locked_res;

		let _ = handle_error!($self, res, counterparty_node_id);

		if let Some(forwards) = htlc_forwards {
			$self.forward_htlcs(&mut [forwards][..]);
		}
	} }
}

impl<Signer: Sign, M: Deref, T: Deref, K: Deref, F: Deref, L: Deref> ChannelManager<Signer, M, T, K, F, L>
	where M::Target: chain::Watch<Signer>,
        T::Target: BroadcasterInterface,
        K::Target: KeysInterface<Signer = Signer>,
        F::Target: FeeEstimator,
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
	pub fn new(fee_est: F, chain_monitor: M, tx_broadcaster: T, logger: L, keys_manager: K, config: UserConfig, params: ChainParameters) -> Self {
		let mut secp_ctx = Secp256k1::new();
		secp_ctx.seeded_randomize(&keys_manager.get_secure_random_bytes());
		let inbound_pmt_key_material = keys_manager.get_inbound_payment_key_material();
		let expanded_inbound_key = inbound_payment::ExpandedKey::new(&inbound_pmt_key_material);
		ChannelManager {
			default_configuration: config.clone(),
			genesis_hash: genesis_block(params.network).header.block_hash(),
			fee_estimator: fee_est,
			chain_monitor,
			tx_broadcaster,

			best_block: RwLock::new(params.best_block),

			channel_state: Mutex::new(ChannelHolder{
				by_id: HashMap::new(),
				short_to_id: HashMap::new(),
				forward_htlcs: HashMap::new(),
				claimable_htlcs: HashMap::new(),
				pending_msg_events: Vec::new(),
			}),
			outbound_scid_aliases: Mutex::new(HashSet::new()),
			pending_inbound_payments: Mutex::new(HashMap::new()),
			pending_outbound_payments: Mutex::new(HashMap::new()),

			our_network_key: keys_manager.get_node_secret(Recipient::Node).unwrap(),
			our_network_pubkey: PublicKey::from_secret_key(&secp_ctx, &keys_manager.get_node_secret(Recipient::Node).unwrap()),
			secp_ctx,

			inbound_payment_key: expanded_inbound_key,
			fake_scid_rand_bytes: keys_manager.get_secure_random_bytes(),

			last_node_announcement_serial: AtomicUsize::new(0),
			highest_seen_timestamp: AtomicUsize::new(0),

			per_peer_state: RwLock::new(HashMap::new()),

			pending_events: Mutex::new(Vec::new()),
			pending_background_events: Mutex::new(Vec::new()),
			total_consistency_lock: RwLock::new(()),
			persistence_notifier: PersistenceNotifier::new(),

			keys_manager,

			logger,
		}
	}

	/// Gets the current configuration applied to all new channels,  as
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
				outbound_scid_alias = fake_scid::Namespace::OutboundAlias.get_fake_scid(height, &self.genesis_hash, &self.fake_scid_rand_bytes, &self.keys_manager);
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
	/// correspond with which `create_channel` call. Note that the `user_channel_id` defaults to 0
	/// for inbound channels, so you may wish to avoid using 0 for `user_channel_id` here.
	/// `user_channel_id` has no meaning inside of LDK, it is simply copied to events and otherwise
	/// ignored.
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
	pub fn create_channel(&self, their_network_key: PublicKey, channel_value_satoshis: u64, push_msat: u64, user_channel_id: u64, override_config: Option<UserConfig>) -> Result<[u8; 32], APIError> {
		if channel_value_satoshis < 1000 {
			return Err(APIError::APIMisuseError { err: format!("Channel value must be at least 1000 satoshis. It was {}", channel_value_satoshis) });
		}

		let channel = {
			let per_peer_state = self.per_peer_state.read().unwrap();
			match per_peer_state.get(&their_network_key) {
				Some(peer_state) => {
					let outbound_scid_alias = self.create_and_insert_outbound_scid_alias();
					let peer_state = peer_state.lock().unwrap();
					let their_features = &peer_state.latest_features;
					let config = if override_config.is_some() { override_config.as_ref().unwrap() } else { &self.default_configuration };
					match Channel::new_outbound(&self.fee_estimator, &self.keys_manager, their_network_key,
						their_features, channel_value_satoshis, push_msat, user_channel_id, config,
						self.best_block.read().unwrap().height(), outbound_scid_alias)
					{
						Ok(res) => res,
						Err(e) => {
							self.outbound_scid_aliases.lock().unwrap().remove(&outbound_scid_alias);
							return Err(e);
						},
					}
				},
				None => return Err(APIError::ChannelUnavailable { err: format!("Not connected to node: {}", their_network_key) }),
			}
		};
		let res = channel.get_open_channel(self.genesis_hash.clone());

		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(&self.total_consistency_lock, &self.persistence_notifier);
		// We want to make sure the lock is actually acquired by PersistenceNotifierGuard.
		debug_assert!(&self.total_consistency_lock.try_write().is_err());

		let temporary_channel_id = channel.channel_id();
		let mut channel_state = self.channel_state.lock().unwrap();
		match channel_state.by_id.entry(temporary_channel_id) {
			hash_map::Entry::Occupied(_) => {
				if cfg!(fuzzing) {
					return Err(APIError::APIMisuseError { err: "Fuzzy bad RNG".to_owned() });
				} else {
					panic!("RNG is bad???");
				}
			},
			hash_map::Entry::Vacant(entry) => { entry.insert(channel); }
		}
		channel_state.pending_msg_events.push(events::MessageSendEvent::SendOpenChannel {
			node_id: their_network_key,
			msg: res,
		});
		Ok(temporary_channel_id)
	}

	fn list_channels_with_filter<Fn: FnMut(&(&[u8; 32], &Channel<Signer>)) -> bool>(&self, f: Fn) -> Vec<ChannelDetails> {
		let mut res = Vec::new();
		{
			let channel_state = self.channel_state.lock().unwrap();
			res.reserve(channel_state.by_id.len());
			for (channel_id, channel) in channel_state.by_id.iter().filter(f) {
				let balance = channel.get_available_balances();
				let (to_remote_reserve_satoshis, to_self_reserve_satoshis) =
					channel.get_holder_counterparty_selected_channel_reserve_satoshis();
				res.push(ChannelDetails {
					channel_id: (*channel_id).clone(),
					counterparty: ChannelCounterparty {
						node_id: channel.get_counterparty_node_id(),
						features: InitFeatures::empty(),
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
					force_close_spend_delay: channel.get_counterparty_selected_contest_delay(),
					is_outbound: channel.is_outbound(),
					is_channel_ready: channel.is_usable(),
					is_usable: channel.is_live(),
					is_public: channel.should_announce(),
					inbound_htlc_minimum_msat: Some(channel.get_holder_htlc_minimum_msat()),
					inbound_htlc_maximum_msat: channel.get_holder_htlc_maximum_msat()
				});
			}
		}
		let per_peer_state = self.per_peer_state.read().unwrap();
		for chan in res.iter_mut() {
			if let Some(peer_state) = per_peer_state.get(&chan.counterparty.node_id) {
				chan.counterparty.features = peer_state.lock().unwrap().latest_features.clone();
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
	/// get_route to ensure non-announced channels are used.
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

	/// Helper function that issues the channel close events
	fn issue_channel_close_events(&self, channel: &Channel<Signer>, closure_reason: ClosureReason) {
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
			let mut channel_state_lock = self.channel_state.lock().unwrap();
			let channel_state = &mut *channel_state_lock;
			match channel_state.by_id.entry(channel_id.clone()) {
				hash_map::Entry::Occupied(mut chan_entry) => {
					if *counterparty_node_id != chan_entry.get().get_counterparty_node_id(){
						return Err(APIError::APIMisuseError { err: "The passed counterparty_node_id doesn't match the channel's counterparty node_id".to_owned() });
					}
					let per_peer_state = self.per_peer_state.read().unwrap();
					let (shutdown_msg, monitor_update, htlcs) = match per_peer_state.get(&counterparty_node_id) {
						Some(peer_state) => {
							let peer_state = peer_state.lock().unwrap();
							let their_features = &peer_state.latest_features;
							chan_entry.get_mut().get_shutdown(&self.keys_manager, their_features, target_feerate_sats_per_1000_weight)?
						},
						None => return Err(APIError::ChannelUnavailable { err: format!("Not connected to node: {}", counterparty_node_id) }),
					};
					failed_htlcs = htlcs;

					// Update the monitor with the shutdown script if necessary.
					if let Some(monitor_update) = monitor_update {
						if let Err(e) = self.chain_monitor.update_channel(chan_entry.get().get_funding_txo().unwrap(), monitor_update) {
							let (result, is_permanent) =
								handle_monitor_err!(self, e, channel_state.short_to_id, chan_entry.get_mut(), RAACommitmentOrder::CommitmentFirst, chan_entry.key(), NO_UPDATE);
							if is_permanent {
								remove_channel!(self, channel_state, chan_entry);
								break result;
							}
						}
					}

					channel_state.pending_msg_events.push(events::MessageSendEvent::SendShutdown {
						node_id: *counterparty_node_id,
						msg: shutdown_msg
					});

					if chan_entry.get().is_shutdown() {
						let channel = remove_channel!(self, channel_state, chan_entry);
						if let Ok(channel_update) = self.get_channel_update_for_broadcast(&channel) {
							channel_state.pending_msg_events.push(events::MessageSendEvent::BroadcastChannelUpdate {
								msg: channel_update
							});
						}
						self.issue_channel_close_events(&channel, ClosureReason::HolderForceClosed);
					}
					break Ok(());
				},
				hash_map::Entry::Vacant(_) => return Err(APIError::ChannelUnavailable{err: "No such channel".to_owned()})
			}
		};

		for htlc_source in failed_htlcs.drain(..) {
			self.fail_htlc_backwards_internal(self.channel_state.lock().unwrap(), htlc_source.0, &htlc_source.1, HTLCFailReason::Reason { failure_code: 0x4000 | 8, data: Vec::new() });
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
			self.fail_htlc_backwards_internal(self.channel_state.lock().unwrap(), htlc_source.0, &htlc_source.1, HTLCFailReason::Reason { failure_code: 0x4000 | 8, data: Vec::new() });
		}
		if let Some((funding_txo, monitor_update)) = monitor_update_option {
			// There isn't anything we can do if we get an update failure - we're already
			// force-closing. The monitor update on the required in-memory copy should broadcast
			// the latest local state, which is the best we can do anyway. Thus, it is safe to
			// ignore the result here.
			let _ = self.chain_monitor.update_channel(funding_txo, monitor_update);
		}
	}

	/// `peer_msg` should be set when we receive a message from a peer, but not set when the
	/// user closes, which will be re-exposed as the `ChannelClosed` reason.
	fn force_close_channel_with_peer(&self, channel_id: &[u8; 32], peer_node_id: &PublicKey, peer_msg: Option<&String>) -> Result<PublicKey, APIError> {
		let mut chan = {
			let mut channel_state_lock = self.channel_state.lock().unwrap();
			let channel_state = &mut *channel_state_lock;
			if let hash_map::Entry::Occupied(chan) = channel_state.by_id.entry(channel_id.clone()) {
				if chan.get().get_counterparty_node_id() != *peer_node_id {
					return Err(APIError::ChannelUnavailable{err: "No such channel".to_owned()});
				}
				if let Some(peer_msg) = peer_msg {
					self.issue_channel_close_events(chan.get(),ClosureReason::CounterpartyForceClosed { peer_msg: peer_msg.to_string() });
				} else {
					self.issue_channel_close_events(chan.get(),ClosureReason::HolderForceClosed);
				}
				remove_channel!(self, channel_state, chan)
			} else {
				return Err(APIError::ChannelUnavailable{err: "No such channel".to_owned()});
			}
		};
		log_error!(self.logger, "Force-closing channel {}", log_bytes!(channel_id[..]));
		self.finish_force_close_channel(chan.force_shutdown(true));
		if let Ok(update) = self.get_channel_update_for_broadcast(&chan) {
			let mut channel_state = self.channel_state.lock().unwrap();
			channel_state.pending_msg_events.push(events::MessageSendEvent::BroadcastChannelUpdate {
				msg: update
			});
		}

		Ok(chan.get_counterparty_node_id())
	}

	/// Force closes a channel, immediately broadcasting the latest local commitment transaction to
	/// the chain and rejecting new HTLCs on the given channel. Fails if `channel_id` is unknown to
	/// the manager, or if the `counterparty_node_id` isn't the counterparty of the corresponding
	/// channel.
	pub fn force_close_channel(&self, channel_id: &[u8; 32], counterparty_node_id: &PublicKey) -> Result<(), APIError> {
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(&self.total_consistency_lock, &self.persistence_notifier);
		match self.force_close_channel_with_peer(channel_id, counterparty_node_id, None) {
			Ok(counterparty_node_id) => {
				self.channel_state.lock().unwrap().pending_msg_events.push(
					events::MessageSendEvent::HandleError {
						node_id: counterparty_node_id,
						action: msgs::ErrorAction::SendErrorMessage {
							msg: msgs::ErrorMessage { channel_id: *channel_id, data: "Channel force-closed".to_owned() }
						},
					}
				);
				Ok(())
			},
			Err(e) => Err(e)
		}
	}

	/// Force close all channels, immediately broadcasting the latest local commitment transaction
	/// for each to the chain and rejecting new HTLCs on each.
	pub fn force_close_all_channels(&self) {
		for chan in self.list_channels() {
			let _ = self.force_close_channel(&chan.channel_id, &chan.counterparty.node_id);
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
				err_data: byte_utils::be32_to_array(cltv_expiry).to_vec()
			})
		}
		// final_expiry_too_soon
		// We have to have some headroom to broadcast on chain if we have the preimage, so make sure
		// we have at least HTLC_FAIL_BACK_BUFFER blocks to go.
		// Also, ensure that, in the case of an unknown preimage for the received payment hash, our
		// payment logic has enough time to fail the HTLC backward before our onchain logic triggers a
		// channel closure (see HTLC_FAIL_BACK_BUFFER rationale).
		if (hop_data.outgoing_cltv_value as u64) <= self.best_block.read().unwrap().height() as u64 + HTLC_FAIL_BACK_BUFFER as u64 + 1	{
			return Err(ReceiveError {
				err_code: 17,
				err_data: Vec::new(),
				msg: "The final CLTV expiry is too soon to handle",
			});
		}
		if hop_data.amt_to_forward > amt_msat {
			return Err(ReceiveError {
				err_code: 19,
				err_data: byte_utils::be64_to_array(amt_msat).to_vec(),
				msg: "Upstream node sent less than we were supposed to receive in payment",
			});
		}

		let routing = match hop_data.format {
			msgs::OnionHopDataFormat::Legacy { .. } => {
				return Err(ReceiveError {
					err_code: 0x4000|0x2000|3,
					err_data: Vec::new(),
					msg: "We require payment_secrets",
				});
			},
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
			amt_to_forward: amt_msat,
			outgoing_cltv_value: hop_data.outgoing_cltv_value,
		})
	}

	fn decode_update_add_htlc_onion(&self, msg: &msgs::UpdateAddHTLC) -> (PendingHTLCStatus, MutexGuard<ChannelHolder<Signer>>) {
		macro_rules! return_malformed_err {
			($msg: expr, $err_code: expr) => {
				{
					log_info!(self.logger, "Failed to accept/forward incoming HTLC: {}", $msg);
					return (PendingHTLCStatus::Fail(HTLCFailureMsg::Malformed(msgs::UpdateFailMalformedHTLC {
						channel_id: msg.channel_id,
						htlc_id: msg.htlc_id,
						sha256_of_onion: Sha256::hash(&msg.onion_routing_packet.hop_data).into_inner(),
						failure_code: $err_code,
					})), self.channel_state.lock().unwrap());
				}
			}
		}

		if let Err(_) = msg.onion_routing_packet.public_key {
			return_malformed_err!("invalid ephemeral pubkey", 0x8000 | 0x4000 | 6);
		}

		let shared_secret = SharedSecret::new(&msg.onion_routing_packet.public_key.unwrap(), &self.our_network_key).secret_bytes();

		if msg.onion_routing_packet.version != 0 {
			//TODO: Spec doesn't indicate if we should only hash hop_data here (and in other
			//sha256_of_onion error data packets), or the entire onion_routing_packet. Either way,
			//the hash doesn't really serve any purpose - in the case of hashing all data, the
			//receiving node would have to brute force to figure out which version was put in the
			//packet by the node that send us the message, in the case of hashing the hop_data, the
			//node knows the HMAC matched, so they already know what is there...
			return_malformed_err!("Unknown onion packet version", 0x8000 | 0x4000 | 4);
		}

		let mut channel_state = None;
		macro_rules! return_err {
			($msg: expr, $err_code: expr, $data: expr) => {
				{
					log_info!(self.logger, "Failed to accept/forward incoming HTLC: {}", $msg);
					if channel_state.is_none() {
						channel_state = Some(self.channel_state.lock().unwrap());
					}
					return (PendingHTLCStatus::Fail(HTLCFailureMsg::Relay(msgs::UpdateFailHTLC {
						channel_id: msg.channel_id,
						htlc_id: msg.htlc_id,
						reason: onion_utils::build_first_hop_failure_packet(&shared_secret, $err_code, $data),
					})), channel_state.unwrap());
				}
			}
		}

		let next_hop = match onion_utils::decode_next_hop(shared_secret, &msg.onion_routing_packet.hop_data[..], msg.onion_routing_packet.hmac, msg.payment_hash) {
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
				let mut new_pubkey = msg.onion_routing_packet.public_key.unwrap();

				let blinding_factor = {
					let mut sha = Sha256::engine();
					sha.input(&new_pubkey.serialize()[..]);
					sha.input(&shared_secret);
					Sha256::from_engine(sha).into_inner()
				};

				let public_key = if let Err(e) = new_pubkey.mul_assign(&self.secp_ctx, &blinding_factor[..]) {
					Err(e)
				} else { Ok(new_pubkey) };

				let outgoing_packet = msgs::OnionPacket {
					version: 0,
					public_key,
					hop_data: new_packet_bytes,
					hmac: next_hop_hmac.clone(),
				};

				let short_channel_id = match next_hop_data.format {
					msgs::OnionHopDataFormat::Legacy { short_channel_id } => short_channel_id,
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
					amt_to_forward: next_hop_data.amt_to_forward,
					outgoing_cltv_value: next_hop_data.outgoing_cltv_value,
				})
			}
		};

		channel_state = Some(self.channel_state.lock().unwrap());
		if let &PendingHTLCStatus::Forward(PendingHTLCInfo { ref routing, ref amt_to_forward, ref outgoing_cltv_value, .. }) = &pending_forward_info {
			// If short_channel_id is 0 here, we'll reject the HTLC as there cannot be a channel
			// with a short_channel_id of 0. This is important as various things later assume
			// short_channel_id is non-0 in any ::Forward.
			if let &PendingHTLCRouting::Forward { ref short_channel_id, .. } = routing {
				let id_option = channel_state.as_ref().unwrap().short_to_id.get(&short_channel_id).cloned();
				if let Some((err, code, chan_update)) = loop {
					let forwarding_id_opt = match id_option {
						None => { // unknown_next_peer
							// Note that this is likely a timing oracle for detecting whether an scid is a
							// phantom.
							if fake_scid::is_valid_phantom(&self.fake_scid_rand_bytes, *short_channel_id) {
								None
							} else {
								break Some(("Don't have available channel for forwarding as requested.", 0x4000 | 10, None));
							}
						},
						Some(id) => Some(id.clone()),
					};
					let (chan_update_opt, forwardee_cltv_expiry_delta) = if let Some(forwarding_id) = forwarding_id_opt {
						let chan = channel_state.as_mut().unwrap().by_id.get_mut(&forwarding_id).unwrap();
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
						if *amt_to_forward < chan.get_counterparty_htlc_minimum_msat() { // amount_below_minimum
							break Some(("HTLC amount was below the htlc_minimum_msat", 0x1000 | 11, chan_update_opt));
						}
						let fee = amt_to_forward.checked_mul(chan.get_fee_proportional_millionths() as u64)
							.and_then(|prop_fee| { (prop_fee / 1000000)
							.checked_add(chan.get_outbound_forwarding_fee_base_msat() as u64) });
						if fee.is_none() || msg.amount_msat < fee.unwrap() || (msg.amount_msat - fee.unwrap()) < *amt_to_forward { // fee_insufficient
							break Some(("Prior hop has deviated from specified fees parameters or origin node has obsolete ones", 0x1000 | 12, chan_update_opt));
						}
						(chan_update_opt, chan.get_cltv_expiry_delta())
					} else { (None, MIN_CLTV_EXPIRY_DELTA) };

					if (msg.cltv_expiry as u64) < (*outgoing_cltv_value) as u64 + forwardee_cltv_expiry_delta as u64 { // incorrect_cltv_expiry
						break Some(("Forwarding node has tampered with the intended HTLC values or origin node has an obsolete cltv_expiry_delta", 0x1000 | 13, chan_update_opt));
					}
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
					}
					return_err!(err, code, &res.0[..]);
				}
			}
		}

		(pending_forward_info, channel_state.unwrap())
	}

	/// Gets the current channel_update for the given channel. This first checks if the channel is
	/// public, and thus should be called whenever the result is going to be passed out in a
	/// [`MessageSendEvent::BroadcastChannelUpdate`] event.
	///
	/// May be called with channel_state already locked!
	fn get_channel_update_for_broadcast(&self, chan: &Channel<Signer>) -> Result<msgs::ChannelUpdate, LightningError> {
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
	/// May be called with channel_state already locked!
	fn get_channel_update_for_unicast(&self, chan: &Channel<Signer>) -> Result<msgs::ChannelUpdate, LightningError> {
		log_trace!(self.logger, "Attempting to generate channel update for channel {}", log_bytes!(chan.channel_id()));
		let short_channel_id = match chan.get_short_channel_id().or(chan.latest_inbound_scid_alias()) {
			None => return Err(LightningError{err: "Channel not yet established".to_owned(), action: msgs::ErrorAction::IgnoreError}),
			Some(id) => id,
		};

		self.get_channel_update_for_onion(short_channel_id, chan)
	}
	fn get_channel_update_for_onion(&self, short_channel_id: u64, chan: &Channel<Signer>) -> Result<msgs::ChannelUpdate, LightningError> {
		log_trace!(self.logger, "Generating channel update for channel {}", log_bytes!(chan.channel_id()));
		let were_node_one = PublicKey::from_secret_key(&self.secp_ctx, &self.our_network_key).serialize()[..] < chan.get_counterparty_node_id().serialize()[..];

		let unsigned = msgs::UnsignedChannelUpdate {
			chain_hash: self.genesis_hash,
			short_channel_id,
			timestamp: chan.get_update_time_counter(),
			flags: (!were_node_one) as u8 | ((!chan.is_live() as u8) << 1),
			cltv_expiry_delta: chan.get_cltv_expiry_delta(),
			htlc_minimum_msat: chan.get_counterparty_htlc_minimum_msat(),
			htlc_maximum_msat: OptionalField::Present(chan.get_announced_htlc_max_msat()),
			fee_base_msat: chan.get_outbound_forwarding_fee_base_msat(),
			fee_proportional_millionths: chan.get_fee_proportional_millionths(),
			excess_data: Vec::new(),
		};

		let msg_hash = Sha256dHash::hash(&unsigned.encode()[..]);
		let sig = self.secp_ctx.sign_ecdsa(&hash_to_message!(&msg_hash[..]), &self.our_network_key);

		Ok(msgs::ChannelUpdate {
			signature: sig,
			contents: unsigned
		})
	}

	// Only public for testing, this should otherwise never be called direcly
	pub(crate) fn send_payment_along_path(&self, path: &Vec<RouteHop>, payment_params: &Option<PaymentParameters>, payment_hash: &PaymentHash, payment_secret: &Option<PaymentSecret>, total_value: u64, cur_height: u32, payment_id: PaymentId, keysend_preimage: &Option<PaymentPreimage>) -> Result<(), APIError> {
		log_trace!(self.logger, "Attempting to send payment for path with next hop {}", path.first().unwrap().short_channel_id);
		let prng_seed = self.keys_manager.get_secure_random_bytes();
		let session_priv_bytes = self.keys_manager.get_secure_random_bytes();
		let session_priv = SecretKey::from_slice(&session_priv_bytes[..]).expect("RNG is busted");

		let onion_keys = onion_utils::construct_onion_keys(&self.secp_ctx, &path, &session_priv)
			.map_err(|_| APIError::RouteError{err: "Pubkey along hop was maliciously selected"})?;
		let (onion_payloads, htlc_msat, htlc_cltv) = onion_utils::build_onion_payloads(path, total_value, payment_secret, cur_height, keysend_preimage)?;
		if onion_utils::route_size_insane(&onion_payloads) {
			return Err(APIError::RouteError{err: "Route size too large considering onion data"});
		}
		let onion_packet = onion_utils::construct_onion_packet(onion_payloads, onion_keys, prng_seed, payment_hash);

		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(&self.total_consistency_lock, &self.persistence_notifier);

		let err: Result<(), _> = loop {
			let mut channel_lock = self.channel_state.lock().unwrap();

			let mut pending_outbounds = self.pending_outbound_payments.lock().unwrap();
			let payment_entry = pending_outbounds.entry(payment_id);
			if let hash_map::Entry::Occupied(payment) = &payment_entry {
				if !payment.get().is_retryable() {
					return Err(APIError::RouteError {
						err: "Payment already completed"
					});
				}
			}

			let id = match channel_lock.short_to_id.get(&path.first().unwrap().short_channel_id) {
				None => return Err(APIError::ChannelUnavailable{err: "No channel available with first hop!".to_owned()}),
				Some(id) => id.clone(),
			};

			macro_rules! insert_outbound_payment {
				() => {
					let payment = payment_entry.or_insert_with(|| PendingOutboundPayment::Retryable {
						session_privs: HashSet::new(),
						pending_amt_msat: 0,
						pending_fee_msat: Some(0),
						payment_hash: *payment_hash,
						payment_secret: *payment_secret,
						starting_block_height: self.best_block.read().unwrap().height(),
						total_msat: total_value,
					});
					assert!(payment.insert(session_priv_bytes, path));
				}
			}

			let channel_state = &mut *channel_lock;
			if let hash_map::Entry::Occupied(mut chan) = channel_state.by_id.entry(id) {
				match {
					if chan.get().get_counterparty_node_id() != path.first().unwrap().pubkey {
						return Err(APIError::RouteError{err: "Node ID mismatch on first hop!"});
					}
					if !chan.get().is_live() {
						return Err(APIError::ChannelUnavailable{err: "Peer for first hop currently disconnected/pending monitor update!".to_owned()});
					}
					break_chan_entry!(self, chan.get_mut().send_htlc_and_commit(
						htlc_msat, payment_hash.clone(), htlc_cltv, HTLCSource::OutboundRoute {
							path: path.clone(),
							session_priv: session_priv.clone(),
							first_hop_htlc_msat: htlc_msat,
							payment_id,
							payment_secret: payment_secret.clone(),
							payment_params: payment_params.clone(),
						}, onion_packet, &self.logger),
					channel_state, chan)
				} {
					Some((update_add, commitment_signed, monitor_update)) => {
						if let Err(e) = self.chain_monitor.update_channel(chan.get().get_funding_txo().unwrap(), monitor_update) {
							maybe_break_monitor_err!(self, e, channel_state, chan, RAACommitmentOrder::CommitmentFirst, false, true);
							// Note that MonitorUpdateFailed here indicates (per function docs)
							// that we will resend the commitment update once monitor updating
							// is restored. Therefore, we must return an error indicating that
							// it is unsafe to retry the payment wholesale, which we do in the
							// send_payment check for MonitorUpdateFailed, below.
							insert_outbound_payment!(); // Only do this after possibly break'ing on Perm failure above.
							return Err(APIError::MonitorUpdateFailed);
						}
						insert_outbound_payment!();

						log_debug!(self.logger, "Sending payment along path resulted in a commitment_signed for channel {}", log_bytes!(chan.get().channel_id()));
						channel_state.pending_msg_events.push(events::MessageSendEvent::UpdateHTLCs {
							node_id: path.first().unwrap().pubkey,
							updates: msgs::CommitmentUpdate {
								update_add_htlcs: vec![update_add],
								update_fulfill_htlcs: Vec::new(),
								update_fail_htlcs: Vec::new(),
								update_fail_malformed_htlcs: Vec::new(),
								update_fee: None,
								commitment_signed,
							},
						});
					},
					None => { insert_outbound_payment!(); },
				}
			} else { unreachable!(); }
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
	/// Value parameters are provided via the last hop in route, see documentation for RouteHop
	/// fields for more info.
	///
	/// Note that if the payment_hash already exists elsewhere (eg you're sending a duplicative
	/// payment), we don't do anything to stop you! We always try to ensure that if the provided
	/// next hop knows the preimage to payment_hash they can claim an additional amount as
	/// specified in the last hop in the route! Thus, you should probably do your own
	/// payment_preimage tracking (which you should already be doing as they represent "proof of
	/// payment") and prevent double-sends yourself.
	///
	/// May generate SendHTLCs message(s) event on success, which should be relayed.
	///
	/// Each path may have a different return value, and PaymentSendValue may return a Vec with
	/// each entry matching the corresponding-index entry in the route paths, see
	/// PaymentSendFailure for more info.
	///
	/// In general, a path may raise:
	///  * APIError::RouteError when an invalid route or forwarding parameter (cltv_delta, fee,
	///    node public key) is specified.
	///  * APIError::ChannelUnavailable if the next-hop channel is not available for updates
	///    (including due to previous monitor update failure or new permanent monitor update
	///    failure).
	///  * APIError::MonitorUpdateFailed if a new monitor update failure prevented sending the
	///    relevant updates.
	///
	/// Note that depending on the type of the PaymentSendFailure the HTLC may have been
	/// irrevocably committed to on our end. In such a case, do NOT retry the payment with a
	/// different route unless you intend to pay twice!
	///
	/// payment_secret is unrelated to payment_hash (or PaymentPreimage) and exists to authenticate
	/// the sender to the recipient and prevent payment-probing (deanonymization) attacks. For
	/// newer nodes, it will be provided to you in the invoice. If you do not have one, the Route
	/// must not contain multiple paths as multi-path payments require a recipient-provided
	/// payment_secret.
	/// If a payment_secret *is* provided, we assume that the invoice had the payment_secret feature
	/// bit set (either as required or as available). If multiple paths are present in the Route,
	/// we assume the invoice had the basic_mpp feature set.
	pub fn send_payment(&self, route: &Route, payment_hash: PaymentHash, payment_secret: &Option<PaymentSecret>) -> Result<PaymentId, PaymentSendFailure> {
		self.send_payment_internal(route, payment_hash, payment_secret, None, None, None)
	}

	fn send_payment_internal(&self, route: &Route, payment_hash: PaymentHash, payment_secret: &Option<PaymentSecret>, keysend_preimage: Option<PaymentPreimage>, payment_id: Option<PaymentId>, recv_value_msat: Option<u64>) -> Result<PaymentId, PaymentSendFailure> {
		if route.paths.len() < 1 {
			return Err(PaymentSendFailure::ParameterError(APIError::RouteError{err: "There must be at least one path to send over"}));
		}
		if route.paths.len() > 10 {
			// This limit is completely arbitrary - there aren't any real fundamental path-count
			// limits. After we support retrying individual paths we should likely bump this, but
			// for now more than 10 paths likely carries too much one-path failure.
			return Err(PaymentSendFailure::ParameterError(APIError::RouteError{err: "Sending over more than 10 paths is not currently supported"}));
		}
		if payment_secret.is_none() && route.paths.len() > 1 {
			return Err(PaymentSendFailure::ParameterError(APIError::APIMisuseError{err: "Payment secret is required for multi-path payments".to_string()}));
		}
		let mut total_value = 0;
		let our_node_id = self.get_our_node_id();
		let mut path_errs = Vec::with_capacity(route.paths.len());
		let payment_id = if let Some(id) = payment_id { id } else { PaymentId(self.keys_manager.get_secure_random_bytes()) };
		'path_check: for path in route.paths.iter() {
			if path.len() < 1 || path.len() > 20 {
				path_errs.push(Err(APIError::RouteError{err: "Path didn't go anywhere/had bogus size"}));
				continue 'path_check;
			}
			for (idx, hop) in path.iter().enumerate() {
				if idx != path.len() - 1 && hop.pubkey == our_node_id {
					path_errs.push(Err(APIError::RouteError{err: "Path went through us but wasn't a simple rebalance loop to us"}));
					continue 'path_check;
				}
			}
			total_value += path.last().unwrap().fee_msat;
			path_errs.push(Ok(()));
		}
		if path_errs.iter().any(|e| e.is_err()) {
			return Err(PaymentSendFailure::PathParameterError(path_errs));
		}
		if let Some(amt_msat) = recv_value_msat {
			debug_assert!(amt_msat >= total_value);
			total_value = amt_msat;
		}

		let cur_height = self.best_block.read().unwrap().height() + 1;
		let mut results = Vec::new();
		for path in route.paths.iter() {
			results.push(self.send_payment_along_path(&path, &route.payment_params, &payment_hash, payment_secret, total_value, cur_height, payment_id, &keysend_preimage));
		}
		let mut has_ok = false;
		let mut has_err = false;
		let mut pending_amt_unsent = 0;
		let mut max_unsent_cltv_delta = 0;
		for (res, path) in results.iter().zip(route.paths.iter()) {
			if res.is_ok() { has_ok = true; }
			if res.is_err() { has_err = true; }
			if let &Err(APIError::MonitorUpdateFailed) = res {
				// MonitorUpdateFailed is inherently unsafe to retry, so we call it a
				// PartialFailure.
				has_err = true;
				has_ok = true;
			} else if res.is_err() {
				pending_amt_unsent += path.last().unwrap().fee_msat;
				max_unsent_cltv_delta = cmp::max(max_unsent_cltv_delta, path.last().unwrap().cltv_expiry_delta);
			}
		}
		if has_err && has_ok {
			Err(PaymentSendFailure::PartialFailure {
				results,
				payment_id,
				failed_paths_retry: if pending_amt_unsent != 0 {
					if let Some(payment_params) = &route.payment_params {
						Some(RouteParameters {
							payment_params: payment_params.clone(),
							final_value_msat: pending_amt_unsent,
							final_cltv_expiry_delta: max_unsent_cltv_delta,
						})
					} else { None }
				} else { None },
			})
		} else if has_err {
			// If we failed to send any paths, we shouldn't have inserted the new PaymentId into
			// our `pending_outbound_payments` map at all.
			debug_assert!(self.pending_outbound_payments.lock().unwrap().get(&payment_id).is_none());
			Err(PaymentSendFailure::AllFailedRetrySafe(results.drain(..).map(|r| r.unwrap_err()).collect()))
		} else {
			Ok(payment_id)
		}
	}

	/// Retries a payment along the given [`Route`].
	///
	/// Errors returned are a superset of those returned from [`send_payment`], so see
	/// [`send_payment`] documentation for more details on errors. This method will also error if the
	/// retry amount puts the payment more than 10% over the payment's total amount, if the payment
	/// for the given `payment_id` cannot be found (likely due to timeout or success), or if
	/// further retries have been disabled with [`abandon_payment`].
	///
	/// [`send_payment`]: [`ChannelManager::send_payment`]
	/// [`abandon_payment`]: [`ChannelManager::abandon_payment`]
	pub fn retry_payment(&self, route: &Route, payment_id: PaymentId) -> Result<(), PaymentSendFailure> {
		const RETRY_OVERFLOW_PERCENTAGE: u64 = 10;
		for path in route.paths.iter() {
			if path.len() == 0 {
				return Err(PaymentSendFailure::ParameterError(APIError::APIMisuseError {
					err: "length-0 path in route".to_string()
				}))
			}
		}

		let (total_msat, payment_hash, payment_secret) = {
			let outbounds = self.pending_outbound_payments.lock().unwrap();
			if let Some(payment) = outbounds.get(&payment_id) {
				match payment {
					PendingOutboundPayment::Retryable {
						total_msat, payment_hash, payment_secret, pending_amt_msat, ..
					} => {
						let retry_amt_msat: u64 = route.paths.iter().map(|path| path.last().unwrap().fee_msat).sum();
						if retry_amt_msat + *pending_amt_msat > *total_msat * (100 + RETRY_OVERFLOW_PERCENTAGE) / 100 {
							return Err(PaymentSendFailure::ParameterError(APIError::APIMisuseError {
								err: format!("retry_amt_msat of {} will put pending_amt_msat (currently: {}) more than 10% over total_payment_amt_msat of {}", retry_amt_msat, pending_amt_msat, total_msat).to_string()
							}))
						}
						(*total_msat, *payment_hash, *payment_secret)
					},
					PendingOutboundPayment::Legacy { .. } => {
						return Err(PaymentSendFailure::ParameterError(APIError::APIMisuseError {
							err: "Unable to retry payments that were initially sent on LDK versions prior to 0.0.102".to_string()
						}))
					},
					PendingOutboundPayment::Fulfilled { .. } => {
						return Err(PaymentSendFailure::ParameterError(APIError::APIMisuseError {
							err: "Payment already completed".to_owned()
						}));
					},
					PendingOutboundPayment::Abandoned { .. } => {
						return Err(PaymentSendFailure::ParameterError(APIError::APIMisuseError {
							err: "Payment already abandoned (with some HTLCs still pending)".to_owned()
						}));
					},
				}
			} else {
				return Err(PaymentSendFailure::ParameterError(APIError::APIMisuseError {
					err: format!("Payment with ID {} not found", log_bytes!(payment_id.0)),
				}))
			}
		};
		return self.send_payment_internal(route, payment_hash, &payment_secret, None, Some(payment_id), Some(total_msat)).map(|_| ())
	}

	/// Signals that no further retries for the given payment will occur.
	///
	/// After this method returns, any future calls to [`retry_payment`] for the given `payment_id`
	/// will fail with [`PaymentSendFailure::ParameterError`]. If no such event has been generated,
	/// an [`Event::PaymentFailed`] event will be generated as soon as there are no remaining
	/// pending HTLCs for this payment.
	///
	/// Note that calling this method does *not* prevent a payment from succeeding. You must still
	/// wait until you receive either a [`Event::PaymentFailed`] or [`Event::PaymentSent`] event to
	/// determine the ultimate status of a payment.
	///
	/// [`retry_payment`]: Self::retry_payment
	/// [`Event::PaymentFailed`]: events::Event::PaymentFailed
	/// [`Event::PaymentSent`]: events::Event::PaymentSent
	pub fn abandon_payment(&self, payment_id: PaymentId) {
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(&self.total_consistency_lock, &self.persistence_notifier);

		let mut outbounds = self.pending_outbound_payments.lock().unwrap();
		if let hash_map::Entry::Occupied(mut payment) = outbounds.entry(payment_id) {
			if let Ok(()) = payment.get_mut().mark_abandoned() {
				if payment.get().remaining_parts() == 0 {
					self.pending_events.lock().unwrap().push(events::Event::PaymentFailed {
						payment_id,
						payment_hash: payment.get().payment_hash().expect("PendingOutboundPayments::RetriesExceeded always has a payment hash set"),
					});
					payment.remove();
				}
			}
		}
	}

	/// Send a spontaneous payment, which is a payment that does not require the recipient to have
	/// generated an invoice. Optionally, you may specify the preimage. If you do choose to specify
	/// the preimage, it must be a cryptographically secure random value that no intermediate node
	/// would be able to guess -- otherwise, an intermediate node may claim the payment and it will
	/// never reach the recipient.
	///
	/// See [`send_payment`] documentation for more details on the return value of this function.
	///
	/// Similar to regular payments, you MUST NOT reuse a `payment_preimage` value. See
	/// [`send_payment`] for more information about the risks of duplicate preimage usage.
	///
	/// Note that `route` must have exactly one path.
	///
	/// [`send_payment`]: Self::send_payment
	pub fn send_spontaneous_payment(&self, route: &Route, payment_preimage: Option<PaymentPreimage>) -> Result<(PaymentHash, PaymentId), PaymentSendFailure> {
		let preimage = match payment_preimage {
			Some(p) => p,
			None => PaymentPreimage(self.keys_manager.get_secure_random_bytes()),
		};
		let payment_hash = PaymentHash(Sha256::hash(&preimage.0).into_inner());
		match self.send_payment_internal(route, payment_hash, &None, Some(preimage), None, None) {
			Ok(payment_id) => Ok((payment_hash, payment_id)),
			Err(e) => Err(e)
		}
	}

	/// Handles the generation of a funding transaction, optionally (for tests) with a function
	/// which checks the correctness of the funding transaction given the associated channel.
	fn funding_transaction_generated_intern<FundingOutput: Fn(&Channel<Signer>, &Transaction) -> Result<OutPoint, APIError>>(
		&self, temporary_channel_id: &[u8; 32], _counterparty_node_id: &PublicKey, funding_transaction: Transaction, find_funding_output: FundingOutput
	) -> Result<(), APIError> {
		let (chan, msg) = {
			let (res, chan) = match self.channel_state.lock().unwrap().by_id.remove(temporary_channel_id) {
				Some(mut chan) => {
					let funding_txo = find_funding_output(&chan, &funding_transaction)?;

					(chan.get_outbound_funding_created(funding_transaction, funding_txo, &self.logger)
						.map_err(|e| if let ChannelError::Close(msg) = e {
							MsgHandleErrInternal::from_finish_shutdown(msg, chan.channel_id(), chan.get_user_id(), chan.force_shutdown(true), None)
						} else { unreachable!(); })
					, chan)
				},
				None => { return Err(APIError::ChannelUnavailable { err: "No such channel".to_owned() }) },
			};
			match handle_error!(self, res, chan.get_counterparty_node_id()) {
				Ok(funding_msg) => {
					(chan, funding_msg)
				},
				Err(_) => { return Err(APIError::ChannelUnavailable {
					err: "Error deriving keys or signing initial commitment transactions - either our RNG or our counterparty's RNG is broken or the Signer refused to sign".to_owned()
				}) },
			}
		};

		let mut channel_state = self.channel_state.lock().unwrap();
		channel_state.pending_msg_events.push(events::MessageSendEvent::SendFundingCreated {
			node_id: chan.get_counterparty_node_id(),
			msg,
		});
		match channel_state.by_id.entry(chan.channel_id()) {
			hash_map::Entry::Occupied(_) => {
				panic!("Generated duplicate funding txid?");
			},
			hash_map::Entry::Vacant(e) => {
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

	#[allow(dead_code)]
	// Messages of up to 64KB should never end up more than half full with addresses, as that would
	// be absurd. We ensure this by checking that at least 500 (our stated public contract on when
	// broadcast_node_announcement panics) of the maximum-length addresses would fit in a 64KB
	// message...
	const HALF_MESSAGE_IS_ADDRS: u32 = ::core::u16::MAX as u32 / (NetAddress::MAX_LEN as u32 + 1) / 2;
	#[deny(const_err)]
	#[allow(dead_code)]
	// ...by failing to compile if the number of addresses that would be half of a message is
	// smaller than 500:
	const STATIC_ASSERT: u32 = Self::HALF_MESSAGE_IS_ADDRS - 500;

	/// Regenerates channel_announcements and generates a signed node_announcement from the given
	/// arguments, providing them in corresponding events via
	/// [`get_and_clear_pending_msg_events`], if at least one public channel has been confirmed
	/// on-chain. This effectively re-broadcasts all channel announcements and sends our node
	/// announcement to ensure that the lightning P2P network is aware of the channels we have and
	/// our network addresses.
	///
	/// `rgb` is a node "color" and `alias` is a printable human-readable string to describe this
	/// node to humans. They carry no in-protocol meaning.
	///
	/// `addresses` represent the set (possibly empty) of socket addresses on which this node
	/// accepts incoming connections. These will be included in the node_announcement, publicly
	/// tying these addresses together and to this node. If you wish to preserve user privacy,
	/// addresses should likely contain only Tor Onion addresses.
	///
	/// Panics if `addresses` is absurdly large (more than 500).
	///
	/// [`get_and_clear_pending_msg_events`]: MessageSendEventsProvider::get_and_clear_pending_msg_events
	pub fn broadcast_node_announcement(&self, rgb: [u8; 3], alias: [u8; 32], mut addresses: Vec<NetAddress>) {
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(&self.total_consistency_lock, &self.persistence_notifier);

		if addresses.len() > 500 {
			panic!("More than half the message size was taken up by public addresses!");
		}

		// While all existing nodes handle unsorted addresses just fine, the spec requires that
		// addresses be sorted for future compatibility.
		addresses.sort_by_key(|addr| addr.get_id());

		let announcement = msgs::UnsignedNodeAnnouncement {
			features: NodeFeatures::known(),
			timestamp: self.last_node_announcement_serial.fetch_add(1, Ordering::AcqRel) as u32,
			node_id: self.get_our_node_id(),
			rgb, alias, addresses,
			excess_address_data: Vec::new(),
			excess_data: Vec::new(),
		};
		let msghash = hash_to_message!(&Sha256dHash::hash(&announcement.encode()[..])[..]);
		let node_announce_sig = sign(&self.secp_ctx, &msghash, &self.our_network_key);

		let mut channel_state_lock = self.channel_state.lock().unwrap();
		let channel_state = &mut *channel_state_lock;

		let mut announced_chans = false;
		for (_, chan) in channel_state.by_id.iter() {
			if let Some(msg) = chan.get_signed_channel_announcement(self.get_our_node_id(), self.genesis_hash.clone(), self.best_block.read().unwrap().height()) {
				channel_state.pending_msg_events.push(events::MessageSendEvent::BroadcastChannelAnnouncement {
					msg,
					update_msg: match self.get_channel_update_for_broadcast(chan) {
						Ok(msg) => msg,
						Err(_) => continue,
					},
				});
				announced_chans = true;
			} else {
				// If the channel is not public or has not yet reached channel_ready, check the
				// next channel. If we don't yet have any public channels, we'll skip the broadcast
				// below as peers may not accept it without channels on chain first.
			}
		}

		if announced_chans {
			channel_state.pending_msg_events.push(events::MessageSendEvent::BroadcastNodeAnnouncement {
				msg: msgs::NodeAnnouncement {
					signature: node_announce_sig,
					contents: announcement
				},
			});
		}
	}

	/// Processes HTLCs which are pending waiting on random forward delay.
	///
	/// Should only really ever be called in response to a PendingHTLCsForwardable event.
	/// Will likely generate further events.
	pub fn process_pending_htlc_forwards(&self) {
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(&self.total_consistency_lock, &self.persistence_notifier);

		let mut new_events = Vec::new();
		let mut failed_forwards = Vec::new();
		let mut phantom_receives: Vec<(u64, OutPoint, Vec<(PendingHTLCInfo, u64)>)> = Vec::new();
		let mut handle_errors = Vec::new();
		{
			let mut channel_state_lock = self.channel_state.lock().unwrap();
			let channel_state = &mut *channel_state_lock;

			for (short_chan_id, mut pending_forwards) in channel_state.forward_htlcs.drain() {
				if short_chan_id != 0 {
					let forward_chan_id = match channel_state.short_to_id.get(&short_chan_id) {
						Some(chan_id) => chan_id.clone(),
						None => {
							for forward_info in pending_forwards.drain(..) {
								match forward_info {
									HTLCForwardInfo::AddHTLC { prev_short_channel_id, prev_htlc_id, forward_info: PendingHTLCInfo {
										routing, incoming_shared_secret, payment_hash, amt_to_forward, outgoing_cltv_value },
										prev_funding_outpoint } => {
											macro_rules! fail_forward {
												($msg: expr, $err_code: expr, $err_data: expr, $phantom_ss: expr) => {
													{
														log_info!(self.logger, "Failed to accept/forward incoming HTLC: {}", $msg);
														let htlc_source = HTLCSource::PreviousHopData(HTLCPreviousHopData {
															short_channel_id: prev_short_channel_id,
															outpoint: prev_funding_outpoint,
															htlc_id: prev_htlc_id,
															incoming_packet_shared_secret: incoming_shared_secret,
															phantom_shared_secret: $phantom_ss,
														});
														failed_forwards.push((htlc_source, payment_hash,
															HTLCFailReason::Reason { failure_code: $err_code, data: $err_data }
														));
														continue;
													}
												}
											}
											if let PendingHTLCRouting::Forward { onion_packet, .. } = routing {
												let phantom_secret_res = self.keys_manager.get_node_secret(Recipient::PhantomNode);
												if phantom_secret_res.is_ok() && fake_scid::is_valid_phantom(&self.fake_scid_rand_bytes, short_chan_id) {
													let phantom_shared_secret = SharedSecret::new(&onion_packet.public_key.unwrap(), &phantom_secret_res.unwrap()).secret_bytes();
													let next_hop = match onion_utils::decode_next_hop(phantom_shared_secret, &onion_packet.hop_data, onion_packet.hmac, payment_hash) {
														Ok(res) => res,
														Err(onion_utils::OnionDecodeErr::Malformed { err_msg, err_code }) => {
															let sha256_of_onion = Sha256::hash(&onion_packet.hop_data).into_inner();
															// In this scenario, the phantom would have sent us an
															// `update_fail_malformed_htlc`, meaning here we encrypt the error as
															// if it came from us (the second-to-last hop) but contains the sha256
															// of the onion.
															fail_forward!(err_msg, err_code, sha256_of_onion.to_vec(), None);
														},
														Err(onion_utils::OnionDecodeErr::Relay { err_msg, err_code }) => {
															fail_forward!(err_msg, err_code, Vec::new(), Some(phantom_shared_secret));
														},
													};
													match next_hop {
														onion_utils::Hop::Receive(hop_data) => {
															match self.construct_recv_pending_htlc_info(hop_data, incoming_shared_secret, payment_hash, amt_to_forward, outgoing_cltv_value, Some(phantom_shared_secret)) {
																Ok(info) => phantom_receives.push((prev_short_channel_id, prev_funding_outpoint, vec![(info, prev_htlc_id)])),
																Err(ReceiveError { err_code, err_data, msg }) => fail_forward!(msg, err_code, err_data, Some(phantom_shared_secret))
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
							continue;
						}
					};
					if let hash_map::Entry::Occupied(mut chan) = channel_state.by_id.entry(forward_chan_id) {
						let mut add_htlc_msgs = Vec::new();
						let mut fail_htlc_msgs = Vec::new();
						for forward_info in pending_forwards.drain(..) {
							match forward_info {
								HTLCForwardInfo::AddHTLC { prev_short_channel_id, prev_htlc_id, forward_info: PendingHTLCInfo {
										routing: PendingHTLCRouting::Forward {
											onion_packet, ..
										}, incoming_shared_secret, payment_hash, amt_to_forward, outgoing_cltv_value },
										prev_funding_outpoint } => {
									log_trace!(self.logger, "Adding HTLC from short id {} with payment_hash {} to channel with short id {} after delay", prev_short_channel_id, log_bytes!(payment_hash.0), short_chan_id);
									let htlc_source = HTLCSource::PreviousHopData(HTLCPreviousHopData {
										short_channel_id: prev_short_channel_id,
										outpoint: prev_funding_outpoint,
										htlc_id: prev_htlc_id,
										incoming_packet_shared_secret: incoming_shared_secret,
										// Phantom payments are only PendingHTLCRouting::Receive.
										phantom_shared_secret: None,
									});
									match chan.get_mut().send_htlc(amt_to_forward, payment_hash, outgoing_cltv_value, htlc_source.clone(), onion_packet, &self.logger) {
										Err(e) => {
											if let ChannelError::Ignore(msg) = e {
												log_trace!(self.logger, "Failed to forward HTLC with payment_hash {}: {}", log_bytes!(payment_hash.0), msg);
											} else {
												panic!("Stated return value requirements in send_htlc() were not met");
											}
											let (failure_code, data) = self.get_htlc_temp_fail_err_and_data(0x1000|7, short_chan_id, chan.get());
											failed_forwards.push((htlc_source, payment_hash,
												HTLCFailReason::Reason { failure_code, data }
											));
											continue;
										},
										Ok(update_add) => {
											match update_add {
												Some(msg) => { add_htlc_msgs.push(msg); },
												None => {
													// Nothing to do here...we're waiting on a remote
													// revoke_and_ack before we can add anymore HTLCs. The Channel
													// will automatically handle building the update_add_htlc and
													// commitment_signed messages when we can.
													// TODO: Do some kind of timer to set the channel as !is_live()
													// as we don't really want others relying on us relaying through
													// this channel currently :/.
												}
											}
										}
									}
								},
								HTLCForwardInfo::AddHTLC { .. } => {
									panic!("short_channel_id != 0 should imply any pending_forward entries are of type Forward");
								},
								HTLCForwardInfo::FailHTLC { htlc_id, err_packet } => {
									log_trace!(self.logger, "Failing HTLC back to channel with short id {} (backward HTLC ID {}) after delay", short_chan_id, htlc_id);
									match chan.get_mut().get_update_fail_htlc(htlc_id, err_packet, &self.logger) {
										Err(e) => {
											if let ChannelError::Ignore(msg) = e {
												log_trace!(self.logger, "Failed to fail HTLC with ID {} backwards to short_id {}: {}", htlc_id, short_chan_id, msg);
											} else {
												panic!("Stated return value requirements in get_update_fail_htlc() were not met");
											}
											// fail-backs are best-effort, we probably already have one
											// pending, and if not that's OK, if not, the channel is on
											// the chain and sending the HTLC-Timeout is their problem.
											continue;
										},
										Ok(Some(msg)) => { fail_htlc_msgs.push(msg); },
										Ok(None) => {
											// Nothing to do here...we're waiting on a remote
											// revoke_and_ack before we can update the commitment
											// transaction. The Channel will automatically handle
											// building the update_fail_htlc and commitment_signed
											// messages when we can.
											// We don't need any kind of timer here as they should fail
											// the channel onto the chain if they can't get our
											// update_fail_htlc in time, it's not our problem.
										}
									}
								},
							}
						}

						if !add_htlc_msgs.is_empty() || !fail_htlc_msgs.is_empty() {
							let (commitment_msg, monitor_update) = match chan.get_mut().send_commitment(&self.logger) {
								Ok(res) => res,
								Err(e) => {
									// We surely failed send_commitment due to bad keys, in that case
									// close channel and then send error message to peer.
									let counterparty_node_id = chan.get().get_counterparty_node_id();
									let err: Result<(), _>  = match e {
										ChannelError::Ignore(_) | ChannelError::Warn(_) => {
											panic!("Stated return value requirements in send_commitment() were not met");
										}
										ChannelError::Close(msg) => {
											log_trace!(self.logger, "Closing channel {} due to Close-required error: {}", log_bytes!(chan.key()[..]), msg);
											let mut channel = remove_channel!(self, channel_state, chan);
											// ChannelClosed event is generated by handle_error for us.
											Err(MsgHandleErrInternal::from_finish_shutdown(msg, channel.channel_id(), channel.get_user_id(), channel.force_shutdown(true), self.get_channel_update_for_broadcast(&channel).ok()))
										},
										ChannelError::CloseDelayBroadcast(_) => { panic!("Wait is only generated on receipt of channel_reestablish, which is handled by try_chan_entry, we don't bother to support it here"); }
									};
									handle_errors.push((counterparty_node_id, err));
									continue;
								}
							};
							if let Err(e) = self.chain_monitor.update_channel(chan.get().get_funding_txo().unwrap(), monitor_update) {
								handle_errors.push((chan.get().get_counterparty_node_id(), handle_monitor_err!(self, e, channel_state, chan, RAACommitmentOrder::CommitmentFirst, false, true)));
								continue;
							}
							log_debug!(self.logger, "Forwarding HTLCs resulted in a commitment update with {} HTLCs added and {} HTLCs failed for channel {}",
								add_htlc_msgs.len(), fail_htlc_msgs.len(), log_bytes!(chan.get().channel_id()));
							channel_state.pending_msg_events.push(events::MessageSendEvent::UpdateHTLCs {
								node_id: chan.get().get_counterparty_node_id(),
								updates: msgs::CommitmentUpdate {
									update_add_htlcs: add_htlc_msgs,
									update_fulfill_htlcs: Vec::new(),
									update_fail_htlcs: fail_htlc_msgs,
									update_fail_malformed_htlcs: Vec::new(),
									update_fee: None,
									commitment_signed: commitment_msg,
								},
							});
						}
					} else {
						unreachable!();
					}
				} else {
					for forward_info in pending_forwards.drain(..) {
						match forward_info {
							HTLCForwardInfo::AddHTLC { prev_short_channel_id, prev_htlc_id, forward_info: PendingHTLCInfo {
									routing, incoming_shared_secret, payment_hash, amt_to_forward, .. },
									prev_funding_outpoint } => {
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
									value: amt_to_forward,
									timer_ticks: 0,
									total_msat: if let Some(data) = &payment_data { data.total_msat } else { amt_to_forward },
									cltv_expiry,
									onion_payload,
								};

								macro_rules! fail_htlc {
									($htlc: expr) => {
										let mut htlc_msat_height_data = byte_utils::be64_to_array($htlc.value).to_vec();
										htlc_msat_height_data.extend_from_slice(
											&byte_utils::be32_to_array(self.best_block.read().unwrap().height()),
										);
										failed_forwards.push((HTLCSource::PreviousHopData(HTLCPreviousHopData {
												short_channel_id: $htlc.prev_hop.short_channel_id,
												outpoint: prev_funding_outpoint,
												htlc_id: $htlc.prev_hop.htlc_id,
												incoming_packet_shared_secret: $htlc.prev_hop.incoming_packet_shared_secret,
												phantom_shared_secret,
											}), payment_hash,
											HTLCFailReason::Reason { failure_code: 0x4000 | 15, data: htlc_msat_height_data }
										));
									}
								}

								macro_rules! check_total_value {
									($payment_data: expr, $payment_preimage: expr) => {{
										let mut payment_received_generated = false;
										let purpose = || {
											events::PaymentPurpose::InvoicePayment {
												payment_preimage: $payment_preimage,
												payment_secret: $payment_data.payment_secret,
											}
										};
										let (_, htlcs) = channel_state.claimable_htlcs.entry(payment_hash)
											.or_insert_with(|| (purpose(), Vec::new()));
										if htlcs.len() == 1 {
											if let OnionPayload::Spontaneous(_) = htlcs[0].onion_payload {
												log_trace!(self.logger, "Failing new HTLC with payment_hash {} as we already had an existing keysend HTLC with the same payment hash", log_bytes!(payment_hash.0));
												fail_htlc!(claimable_htlc);
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
											fail_htlc!(claimable_htlc);
										} else if total_value == $payment_data.total_msat {
											htlcs.push(claimable_htlc);
											new_events.push(events::Event::PaymentReceived {
												payment_hash,
												purpose: purpose(),
												amount_msat: total_value,
											});
											payment_received_generated = true;
										} else {
											// Nothing to do - we haven't reached the total
											// payment value yet, wait until we receive more
											// MPP parts.
											htlcs.push(claimable_htlc);
										}
										payment_received_generated
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
												let payment_preimage = match inbound_payment::verify(payment_hash, &payment_data, self.highest_seen_timestamp.load(Ordering::Acquire) as u64, &self.inbound_payment_key, &self.logger) {
													Ok(payment_preimage) => payment_preimage,
													Err(()) => {
														fail_htlc!(claimable_htlc);
														continue
													}
												};
												check_total_value!(payment_data, payment_preimage);
											},
											OnionPayload::Spontaneous(preimage) => {
												match channel_state.claimable_htlcs.entry(payment_hash) {
													hash_map::Entry::Vacant(e) => {
														let purpose = events::PaymentPurpose::SpontaneousPayment(preimage);
														e.insert((purpose.clone(), vec![claimable_htlc]));
														new_events.push(events::Event::PaymentReceived {
															payment_hash,
															amount_msat: amt_to_forward,
															purpose,
														});
													},
													hash_map::Entry::Occupied(_) => {
														log_trace!(self.logger, "Failing new keysend HTLC with payment_hash {} for a duplicative payment hash", log_bytes!(payment_hash.0));
														fail_htlc!(claimable_htlc);
													}
												}
											}
										}
									},
									hash_map::Entry::Occupied(inbound_payment) => {
										if payment_data.is_none() {
											log_trace!(self.logger, "Failing new keysend HTLC with payment_hash {} because we already have an inbound payment with the same payment hash", log_bytes!(payment_hash.0));
											fail_htlc!(claimable_htlc);
											continue
										};
										let payment_data = payment_data.unwrap();
										if inbound_payment.get().payment_secret != payment_data.payment_secret {
											log_trace!(self.logger, "Failing new HTLC with payment_hash {} as it didn't match our expected payment secret.", log_bytes!(payment_hash.0));
											fail_htlc!(claimable_htlc);
										} else if inbound_payment.get().min_value_msat.is_some() && payment_data.total_msat < inbound_payment.get().min_value_msat.unwrap() {
											log_trace!(self.logger, "Failing new HTLC with payment_hash {} as it didn't match our minimum value (had {}, needed {}).",
												log_bytes!(payment_hash.0), payment_data.total_msat, inbound_payment.get().min_value_msat.unwrap());
											fail_htlc!(claimable_htlc);
										} else {
											let payment_received_generated = check_total_value!(payment_data, inbound_payment.get().payment_preimage);
											if payment_received_generated {
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

		for (htlc_source, payment_hash, failure_reason) in failed_forwards.drain(..) {
			self.fail_htlc_backwards_internal(self.channel_state.lock().unwrap(), htlc_source, &payment_hash, failure_reason);
		}
		self.forward_htlcs(&mut phantom_receives);

		for (counterparty_node_id, err) in handle_errors.drain(..) {
			let _ = handle_error!(self, err, counterparty_node_id);
		}

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
					let _ = self.chain_monitor.update_channel(funding_txo, update);
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

	fn update_channel_fee(&self, short_to_id: &mut HashMap<u64, [u8; 32]>, pending_msg_events: &mut Vec<events::MessageSendEvent>, chan_id: &[u8; 32], chan: &mut Channel<Signer>, new_feerate: u32) -> (bool, NotifyOption, Result<(), MsgHandleErrInternal>) {
		if !chan.is_outbound() { return (true, NotifyOption::SkipPersist, Ok(())); }
		// If the feerate has decreased by less than half, don't bother
		if new_feerate <= chan.get_feerate() && new_feerate * 2 > chan.get_feerate() {
			log_trace!(self.logger, "Channel {} does not qualify for a feerate change from {} to {}.",
				log_bytes!(chan_id[..]), chan.get_feerate(), new_feerate);
			return (true, NotifyOption::SkipPersist, Ok(()));
		}
		if !chan.is_live() {
			log_trace!(self.logger, "Channel {} does not qualify for a feerate change from {} to {} as it cannot currently be updated (probably the peer is disconnected).",
				log_bytes!(chan_id[..]), chan.get_feerate(), new_feerate);
			return (true, NotifyOption::SkipPersist, Ok(()));
		}
		log_trace!(self.logger, "Channel {} qualifies for a feerate change from {} to {}.",
			log_bytes!(chan_id[..]), chan.get_feerate(), new_feerate);

		let mut retain_channel = true;
		let res = match chan.send_update_fee_and_commit(new_feerate, &self.logger) {
			Ok(res) => Ok(res),
			Err(e) => {
				let (drop, res) = convert_chan_err!(self, e, short_to_id, chan, chan_id);
				if drop { retain_channel = false; }
				Err(res)
			}
		};
		let ret_err = match res {
			Ok(Some((update_fee, commitment_signed, monitor_update))) => {
				if let Err(e) = self.chain_monitor.update_channel(chan.get_funding_txo().unwrap(), monitor_update) {
					let (res, drop) = handle_monitor_err!(self, e, short_to_id, chan, RAACommitmentOrder::CommitmentFirst, chan_id, COMMITMENT_UPDATE_ONLY);
					if drop { retain_channel = false; }
					res
				} else {
					pending_msg_events.push(events::MessageSendEvent::UpdateHTLCs {
						node_id: chan.get_counterparty_node_id(),
						updates: msgs::CommitmentUpdate {
							update_add_htlcs: Vec::new(),
							update_fulfill_htlcs: Vec::new(),
							update_fail_htlcs: Vec::new(),
							update_fail_malformed_htlcs: Vec::new(),
							update_fee: Some(update_fee),
							commitment_signed,
						},
					});
					Ok(())
				}
			},
			Ok(None) => Ok(()),
			Err(e) => Err(e),
		};
		(retain_channel, NotifyOption::DoPersist, ret_err)
	}

	#[cfg(fuzzing)]
	/// In chanmon_consistency we want to sometimes do the channel fee updates done in
	/// timer_tick_occurred, but we can't generate the disabled channel updates as it considers
	/// these a fuzz failure (as they usually indicate a channel force-close, which is exactly what
	/// it wants to detect). Thus, we have a variant exposed here for its benefit.
	pub fn maybe_update_chan_fees(&self) {
		PersistenceNotifierGuard::optionally_notify(&self.total_consistency_lock, &self.persistence_notifier, || {
			let mut should_persist = NotifyOption::SkipPersist;

			let new_feerate = self.fee_estimator.get_est_sat_per_1000_weight(ConfirmationTarget::Normal);

			let mut handle_errors = Vec::new();
			{
				let mut channel_state_lock = self.channel_state.lock().unwrap();
				let channel_state = &mut *channel_state_lock;
				let pending_msg_events = &mut channel_state.pending_msg_events;
				let short_to_id = &mut channel_state.short_to_id;
				channel_state.by_id.retain(|chan_id, chan| {
					let (retain_channel, chan_needs_persist, err) = self.update_channel_fee(short_to_id, pending_msg_events, chan_id, chan, new_feerate);
					if chan_needs_persist == NotifyOption::DoPersist { should_persist = NotifyOption::DoPersist; }
					if err.is_err() {
						handle_errors.push(err);
					}
					retain_channel
				});
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
	///
	/// Note that this may cause reentrancy through `chain::Watch::update_channel` calls or feerate
	/// estimate fetches.
	pub fn timer_tick_occurred(&self) {
		PersistenceNotifierGuard::optionally_notify(&self.total_consistency_lock, &self.persistence_notifier, || {
			let mut should_persist = NotifyOption::SkipPersist;
			if self.process_background_events() { should_persist = NotifyOption::DoPersist; }

			let new_feerate = self.fee_estimator.get_est_sat_per_1000_weight(ConfirmationTarget::Normal);

			let mut handle_errors = Vec::new();
			let mut timed_out_mpp_htlcs = Vec::new();
			{
				let mut channel_state_lock = self.channel_state.lock().unwrap();
				let channel_state = &mut *channel_state_lock;
				let pending_msg_events = &mut channel_state.pending_msg_events;
				let short_to_id = &mut channel_state.short_to_id;
				channel_state.by_id.retain(|chan_id, chan| {
					let counterparty_node_id = chan.get_counterparty_node_id();
					let (retain_channel, chan_needs_persist, err) = self.update_channel_fee(short_to_id, pending_msg_events, chan_id, chan, new_feerate);
					if chan_needs_persist == NotifyOption::DoPersist { should_persist = NotifyOption::DoPersist; }
					if err.is_err() {
						handle_errors.push((err, counterparty_node_id));
					}
					if !retain_channel { return false; }

					if let Err(e) = chan.timer_check_closing_negotiation_progress() {
						let (needs_close, err) = convert_chan_err!(self, e, short_to_id, chan, chan_id);
						handle_errors.push((Err(err), chan.get_counterparty_node_id()));
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

					true
				});

				channel_state.claimable_htlcs.retain(|payment_hash, (_, htlcs)| {
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
							timed_out_mpp_htlcs.extend(htlcs.into_iter().map(|htlc| (htlc.prev_hop.clone(), payment_hash.clone())));
							return false;
						}
					}
					true
				});
			}

			for htlc_source in timed_out_mpp_htlcs.drain(..) {
				self.fail_htlc_backwards_internal(self.channel_state.lock().unwrap(), HTLCSource::PreviousHopData(htlc_source.0), &htlc_source.1, HTLCFailReason::Reason { failure_code: 23, data: Vec::new() });
			}

			for (err, counterparty_node_id) in handle_errors.drain(..) {
				let _ = handle_error!(self, err, counterparty_node_id);
			}
			should_persist
		});
	}

	/// Indicates that the preimage for payment_hash is unknown or the received amount is incorrect
	/// after a PaymentReceived event, failing the HTLC back to its origin and freeing resources
	/// along the path (including in our own channel on which we received it).
	///
	/// Note that in some cases around unclean shutdown, it is possible the payment may have
	/// already been claimed by you via [`ChannelManager::claim_funds`] prior to you seeing (a
	/// second copy of) the [`events::Event::PaymentReceived`] event. Alternatively, the payment
	/// may have already been failed automatically by LDK if it was nearing its expiration time.
	///
	/// While LDK will never claim a payment automatically on your behalf (i.e. without you calling
	/// [`ChannelManager::claim_funds`]), you should still monitor for
	/// [`events::Event::PaymentClaimed`] events even for payments you intend to fail, especially on
	/// startup during which time claims that were in-progress at shutdown may be replayed.
	pub fn fail_htlc_backwards(&self, payment_hash: &PaymentHash) {
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(&self.total_consistency_lock, &self.persistence_notifier);

		let mut channel_state = Some(self.channel_state.lock().unwrap());
		let removed_source = channel_state.as_mut().unwrap().claimable_htlcs.remove(payment_hash);
		if let Some((_, mut sources)) = removed_source {
			for htlc in sources.drain(..) {
				if channel_state.is_none() { channel_state = Some(self.channel_state.lock().unwrap()); }
				let mut htlc_msat_height_data = byte_utils::be64_to_array(htlc.value).to_vec();
				htlc_msat_height_data.extend_from_slice(&byte_utils::be32_to_array(
						self.best_block.read().unwrap().height()));
				self.fail_htlc_backwards_internal(channel_state.take().unwrap(),
						HTLCSource::PreviousHopData(htlc.prev_hop), payment_hash,
						HTLCFailReason::Reason { failure_code: 0x4000 | 15, data: htlc_msat_height_data });
			}
		}
	}

	/// Gets an HTLC onion failure code and error data for an `UPDATE` error, given the error code
	/// that we want to return and a channel.
	///
	/// This is for failures on the channel on which the HTLC was *received*, not failures
	/// forwarding
	fn get_htlc_inbound_temp_fail_err_and_data(&self, desired_err_code: u16, chan: &Channel<Signer>) -> (u16, Vec<u8>) {
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
	fn get_htlc_temp_fail_err_and_data(&self, desired_err_code: u16, scid: u64, chan: &Channel<Signer>) -> (u16, Vec<u8>) {
		debug_assert_eq!(desired_err_code & 0x1000, 0x1000);
		if let Ok(upd) = self.get_channel_update_for_onion(scid, chan) {
			let mut enc = VecWriter(Vec::with_capacity(upd.serialized_length() + 6));
			if desired_err_code == 0x1000 | 20 {
				// TODO: underspecified, follow https://github.com/lightning/bolts/issues/791
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
	fn fail_holding_cell_htlcs(&self, mut htlcs_to_fail: Vec<(HTLCSource, PaymentHash)>, channel_id: [u8; 32]) {
		for (htlc_src, payment_hash) in htlcs_to_fail.drain(..) {
			match htlc_src {
				HTLCSource::PreviousHopData(HTLCPreviousHopData { .. }) => {
					let (failure_code, onion_failure_data) =
						match self.channel_state.lock().unwrap().by_id.entry(channel_id) {
							hash_map::Entry::Occupied(chan_entry) => {
								self.get_htlc_inbound_temp_fail_err_and_data(0x1000|7, &chan_entry.get())
							},
							hash_map::Entry::Vacant(_) => (0x4000|10, Vec::new())
						};
					let channel_state = self.channel_state.lock().unwrap();
					self.fail_htlc_backwards_internal(channel_state,
						htlc_src, &payment_hash, HTLCFailReason::Reason { failure_code, data: onion_failure_data});
				},
				HTLCSource::OutboundRoute { session_priv, payment_id, path, payment_params, .. } => {
					let mut session_priv_bytes = [0; 32];
					session_priv_bytes.copy_from_slice(&session_priv[..]);
					let mut outbounds = self.pending_outbound_payments.lock().unwrap();
					if let hash_map::Entry::Occupied(mut payment) = outbounds.entry(payment_id) {
						if payment.get_mut().remove(&session_priv_bytes, Some(&path)) && !payment.get().is_fulfilled() {
							let retry = if let Some(payment_params_data) = payment_params {
								let path_last_hop = path.last().expect("Outbound payments must have had a valid path");
								Some(RouteParameters {
									payment_params: payment_params_data,
									final_value_msat: path_last_hop.fee_msat,
									final_cltv_expiry_delta: path_last_hop.cltv_expiry_delta,
								})
							} else { None };
							let mut pending_events = self.pending_events.lock().unwrap();
							pending_events.push(events::Event::PaymentPathFailed {
								payment_id: Some(payment_id),
								payment_hash,
								rejected_by_dest: false,
								network_update: None,
								all_paths_failed: payment.get().remaining_parts() == 0,
								path: path.clone(),
								short_channel_id: None,
								retry,
								#[cfg(test)]
								error_code: None,
								#[cfg(test)]
								error_data: None,
							});
							if payment.get().abandoned() && payment.get().remaining_parts() == 0 {
								pending_events.push(events::Event::PaymentFailed {
									payment_id,
									payment_hash: payment.get().payment_hash().expect("PendingOutboundPayments::RetriesExceeded always has a payment hash set"),
								});
								payment.remove();
							}
						}
					} else {
						log_trace!(self.logger, "Received duplicative fail for HTLC with payment_hash {}", log_bytes!(payment_hash.0));
					}
				},
			};
		}
	}

	/// Fails an HTLC backwards to the sender of it to us.
	/// Note that while we take a channel_state lock as input, we do *not* assume consistency here.
	/// There are several callsites that do stupid things like loop over a list of payment_hashes
	/// to fail and take the channel_state lock for each iteration (as we take ownership and may
	/// drop it). In other words, no assumptions are made that entries in claimable_htlcs point to
	/// still-available channels.
	fn fail_htlc_backwards_internal(&self, mut channel_state_lock: MutexGuard<ChannelHolder<Signer>>, source: HTLCSource, payment_hash: &PaymentHash, onion_error: HTLCFailReason) {
		//TODO: There is a timing attack here where if a node fails an HTLC back to us they can
		//identify whether we sent it or not based on the (I presume) very different runtime
		//between the branches here. We should make this async and move it into the forward HTLCs
		//timer handling.

		// Note that we MUST NOT end up calling methods on self.chain_monitor here - we're called
		// from block_connected which may run during initialization prior to the chain_monitor
		// being fully configured. See the docs for `ChannelManagerReadArgs` for more.
		match source {
			HTLCSource::OutboundRoute { ref path, session_priv, payment_id, ref payment_params, .. } => {
				let mut session_priv_bytes = [0; 32];
				session_priv_bytes.copy_from_slice(&session_priv[..]);
				let mut outbounds = self.pending_outbound_payments.lock().unwrap();
				let mut all_paths_failed = false;
				let mut full_failure_ev = None;
				if let hash_map::Entry::Occupied(mut payment) = outbounds.entry(payment_id) {
					if !payment.get_mut().remove(&session_priv_bytes, Some(&path)) {
						log_trace!(self.logger, "Received duplicative fail for HTLC with payment_hash {}", log_bytes!(payment_hash.0));
						return;
					}
					if payment.get().is_fulfilled() {
						log_trace!(self.logger, "Received failure of HTLC with payment_hash {} after payment completion", log_bytes!(payment_hash.0));
						return;
					}
					if payment.get().remaining_parts() == 0 {
						all_paths_failed = true;
						if payment.get().abandoned() {
							full_failure_ev = Some(events::Event::PaymentFailed {
								payment_id,
								payment_hash: payment.get().payment_hash().expect("PendingOutboundPayments::RetriesExceeded always has a payment hash set"),
							});
							payment.remove();
						}
					}
				} else {
					log_trace!(self.logger, "Received duplicative fail for HTLC with payment_hash {}", log_bytes!(payment_hash.0));
					return;
				}
				mem::drop(channel_state_lock);
				let retry = if let Some(payment_params_data) = payment_params {
					let path_last_hop = path.last().expect("Outbound payments must have had a valid path");
					Some(RouteParameters {
						payment_params: payment_params_data.clone(),
						final_value_msat: path_last_hop.fee_msat,
						final_cltv_expiry_delta: path_last_hop.cltv_expiry_delta,
					})
				} else { None };
				log_trace!(self.logger, "Failing outbound payment HTLC with payment_hash {}", log_bytes!(payment_hash.0));

				let path_failure = match &onion_error {
					&HTLCFailReason::LightningError { ref err } => {
#[cfg(test)]
						let (network_update, short_channel_id, payment_retryable, onion_error_code, onion_error_data) = onion_utils::process_onion_failure(&self.secp_ctx, &self.logger, &source, err.data.clone());
#[cfg(not(test))]
						let (network_update, short_channel_id, payment_retryable, _, _) = onion_utils::process_onion_failure(&self.secp_ctx, &self.logger, &source, err.data.clone());
						// TODO: If we decided to blame ourselves (or one of our channels) in
						// process_onion_failure we should close that channel as it implies our
						// next-hop is needlessly blaming us!
						events::Event::PaymentPathFailed {
							payment_id: Some(payment_id),
							payment_hash: payment_hash.clone(),
							rejected_by_dest: !payment_retryable,
							network_update,
							all_paths_failed,
							path: path.clone(),
							short_channel_id,
							retry,
#[cfg(test)]
							error_code: onion_error_code,
#[cfg(test)]
							error_data: onion_error_data
						}
					},
					&HTLCFailReason::Reason {
#[cfg(test)]
							ref failure_code,
#[cfg(test)]
							ref data,
							.. } => {
						// we get a fail_malformed_htlc from the first hop
						// TODO: We'd like to generate a NetworkUpdate for temporary
						// failures here, but that would be insufficient as get_route
						// generally ignores its view of our own channels as we provide them via
						// ChannelDetails.
						// TODO: For non-temporary failures, we really should be closing the
						// channel here as we apparently can't relay through them anyway.
						events::Event::PaymentPathFailed {
							payment_id: Some(payment_id),
							payment_hash: payment_hash.clone(),
							rejected_by_dest: path.len() == 1,
							network_update: None,
							all_paths_failed,
							path: path.clone(),
							short_channel_id: Some(path.first().unwrap().short_channel_id),
							retry,
#[cfg(test)]
							error_code: Some(*failure_code),
#[cfg(test)]
							error_data: Some(data.clone()),
						}
					}
				};
				let mut pending_events = self.pending_events.lock().unwrap();
				pending_events.push(path_failure);
				if let Some(ev) = full_failure_ev { pending_events.push(ev); }
			},
			HTLCSource::PreviousHopData(HTLCPreviousHopData { short_channel_id, htlc_id, incoming_packet_shared_secret, phantom_shared_secret, .. }) => {
				let err_packet = match onion_error {
					HTLCFailReason::Reason { failure_code, data } => {
						log_trace!(self.logger, "Failing HTLC with payment_hash {} backwards from us with code {}", log_bytes!(payment_hash.0), failure_code);
						if let Some(phantom_ss) = phantom_shared_secret {
							let phantom_packet = onion_utils::build_failure_packet(&phantom_ss, failure_code, &data[..]).encode();
							let encrypted_phantom_packet = onion_utils::encrypt_failure_packet(&phantom_ss, &phantom_packet);
							onion_utils::encrypt_failure_packet(&incoming_packet_shared_secret, &encrypted_phantom_packet.data[..])
						} else {
							let packet = onion_utils::build_failure_packet(&incoming_packet_shared_secret, failure_code, &data[..]).encode();
							onion_utils::encrypt_failure_packet(&incoming_packet_shared_secret, &packet)
						}
					},
					HTLCFailReason::LightningError { err } => {
						log_trace!(self.logger, "Failing HTLC with payment_hash {} backwards with pre-built LightningError", log_bytes!(payment_hash.0));
						onion_utils::encrypt_failure_packet(&incoming_packet_shared_secret, &err.data)
					}
				};

				let mut forward_event = None;
				if channel_state_lock.forward_htlcs.is_empty() {
					forward_event = Some(Duration::from_millis(MIN_HTLC_RELAY_HOLDING_CELL_MILLIS));
				}
				match channel_state_lock.forward_htlcs.entry(short_channel_id) {
					hash_map::Entry::Occupied(mut entry) => {
						entry.get_mut().push(HTLCForwardInfo::FailHTLC { htlc_id, err_packet });
					},
					hash_map::Entry::Vacant(entry) => {
						entry.insert(vec!(HTLCForwardInfo::FailHTLC { htlc_id, err_packet }));
					}
				}
				mem::drop(channel_state_lock);
				if let Some(time) = forward_event {
					let mut pending_events = self.pending_events.lock().unwrap();
					pending_events.push(events::Event::PendingHTLCsForwardable {
						time_forwardable: time
					});
				}
			},
		}
	}

	/// Provides a payment preimage in response to [`Event::PaymentReceived`], generating any
	/// [`MessageSendEvent`]s needed to claim the payment.
	///
	/// Note that calling this method does *not* guarantee that the payment has been claimed. You
	/// *must* wait for an [`Event::PaymentClaimed`] event which upon a successful claim will be
	/// provided to your [`EventHandler`] when [`process_pending_events`] is next called.
	///
	/// Note that if you did not set an `amount_msat` when calling [`create_inbound_payment`] or
	/// [`create_inbound_payment_for_hash`] you must check that the amount in the `PaymentReceived`
	/// event matches your expectation. If you fail to do so and call this method, you may provide
	/// the sender "proof-of-payment" when they did not fulfill the full expected payment.
	///
	/// [`Event::PaymentReceived`]: crate::util::events::Event::PaymentReceived
	/// [`Event::PaymentClaimed`]: crate::util::events::Event::PaymentClaimed
	/// [`process_pending_events`]: EventsProvider::process_pending_events
	/// [`create_inbound_payment`]: Self::create_inbound_payment
	/// [`create_inbound_payment_for_hash`]: Self::create_inbound_payment_for_hash
	/// [`get_and_clear_pending_msg_events`]: MessageSendEventsProvider::get_and_clear_pending_msg_events
	pub fn claim_funds(&self, payment_preimage: PaymentPreimage) {
		let payment_hash = PaymentHash(Sha256::hash(&payment_preimage.0).into_inner());

		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(&self.total_consistency_lock, &self.persistence_notifier);

		let mut channel_state = Some(self.channel_state.lock().unwrap());
		let removed_source = channel_state.as_mut().unwrap().claimable_htlcs.remove(&payment_hash);
		if let Some((payment_purpose, mut sources)) = removed_source {
			assert!(!sources.is_empty());

			// If we are claiming an MPP payment, we have to take special care to ensure that each
			// channel exists before claiming all of the payments (inside one lock).
			// Note that channel existance is sufficient as we should always get a monitor update
			// which will take care of the real HTLC claim enforcement.
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
			for htlc in sources.iter() {
				if let None = channel_state.as_ref().unwrap().short_to_id.get(&htlc.prev_hop.short_channel_id) {
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
			if sources.is_empty() || expected_amt_msat.is_none() {
				log_info!(self.logger, "Attempted to claim an incomplete payment which no longer had any available HTLCs!");
				return;
			}
			if claimable_amt_msat != expected_amt_msat.unwrap() {
				log_info!(self.logger, "Attempted to claim an incomplete payment, expected {} msat, had {} available to claim.",
					expected_amt_msat.unwrap(), claimable_amt_msat);
				return;
			}

			let mut errs = Vec::new();
			let mut claimed_any_htlcs = false;
			for htlc in sources.drain(..) {
				if !valid_mpp {
					if channel_state.is_none() { channel_state = Some(self.channel_state.lock().unwrap()); }
					let mut htlc_msat_height_data = byte_utils::be64_to_array(htlc.value).to_vec();
					htlc_msat_height_data.extend_from_slice(&byte_utils::be32_to_array(
							self.best_block.read().unwrap().height()));
					self.fail_htlc_backwards_internal(channel_state.take().unwrap(),
									 HTLCSource::PreviousHopData(htlc.prev_hop), &payment_hash,
									 HTLCFailReason::Reason { failure_code: 0x4000|15, data: htlc_msat_height_data });
				} else {
					match self.claim_funds_from_hop(channel_state.as_mut().unwrap(), htlc.prev_hop, payment_preimage) {
						ClaimFundsFromHop::MonitorUpdateFail(pk, err, _) => {
							if let msgs::ErrorAction::IgnoreError = err.err.action {
								// We got a temporary failure updating monitor, but will claim the
								// HTLC when the monitor updating is restored (or on chain).
								log_error!(self.logger, "Temporary failure claiming HTLC, treating as success: {}", err.err.err);
								claimed_any_htlcs = true;
							} else { errs.push((pk, err)); }
						},
						ClaimFundsFromHop::PrevHopForceClosed => unreachable!("We already checked for channel existence, we can't fail here!"),
						ClaimFundsFromHop::DuplicateClaim => {
							// While we should never get here in most cases, if we do, it likely
							// indicates that the HTLC was timed out some time ago and is no longer
							// available to be claimed. Thus, it does not make sense to set
							// `claimed_any_htlcs`.
						},
						ClaimFundsFromHop::Success(_) => claimed_any_htlcs = true,
					}
				}
			}

			if claimed_any_htlcs {
				self.pending_events.lock().unwrap().push(events::Event::PaymentClaimed {
					payment_hash,
					purpose: payment_purpose,
					amount_msat: claimable_amt_msat,
				});
			}

			// Now that we've done the entire above loop in one lock, we can handle any errors
			// which were generated.
			channel_state.take();

			for (counterparty_node_id, err) in errs.drain(..) {
				let res: Result<(), _> = Err(err);
				let _ = handle_error!(self, res, counterparty_node_id);
			}
		}
	}

	fn claim_funds_from_hop(&self, channel_state_lock: &mut MutexGuard<ChannelHolder<Signer>>, prev_hop: HTLCPreviousHopData, payment_preimage: PaymentPreimage) -> ClaimFundsFromHop {
		//TODO: Delay the claimed_funds relaying just like we do outbound relay!
		let channel_state = &mut **channel_state_lock;
		let chan_id = match channel_state.short_to_id.get(&prev_hop.short_channel_id) {
			Some(chan_id) => chan_id.clone(),
			None => {
				return ClaimFundsFromHop::PrevHopForceClosed
			}
		};

		if let hash_map::Entry::Occupied(mut chan) = channel_state.by_id.entry(chan_id) {
			match chan.get_mut().get_update_fulfill_htlc_and_commit(prev_hop.htlc_id, payment_preimage, &self.logger) {
				Ok(msgs_monitor_option) => {
					if let UpdateFulfillCommitFetch::NewClaim { msgs, htlc_value_msat, monitor_update } = msgs_monitor_option {
						if let Err(e) = self.chain_monitor.update_channel(chan.get().get_funding_txo().unwrap(), monitor_update) {
							log_given_level!(self.logger, if e == ChannelMonitorUpdateErr::PermanentFailure { Level::Error } else { Level::Debug },
								"Failed to update channel monitor with preimage {:?}: {:?}",
								payment_preimage, e);
							return ClaimFundsFromHop::MonitorUpdateFail(
								chan.get().get_counterparty_node_id(),
								handle_monitor_err!(self, e, channel_state, chan, RAACommitmentOrder::CommitmentFirst, false, msgs.is_some()).unwrap_err(),
								Some(htlc_value_msat)
							);
						}
						if let Some((msg, commitment_signed)) = msgs {
							log_debug!(self.logger, "Claiming funds for HTLC with preimage {} resulted in a commitment_signed for channel {}",
								log_bytes!(payment_preimage.0), log_bytes!(chan.get().channel_id()));
							channel_state.pending_msg_events.push(events::MessageSendEvent::UpdateHTLCs {
								node_id: chan.get().get_counterparty_node_id(),
								updates: msgs::CommitmentUpdate {
									update_add_htlcs: Vec::new(),
									update_fulfill_htlcs: vec![msg],
									update_fail_htlcs: Vec::new(),
									update_fail_malformed_htlcs: Vec::new(),
									update_fee: None,
									commitment_signed,
								}
							});
						}
						return ClaimFundsFromHop::Success(htlc_value_msat);
					} else {
						return ClaimFundsFromHop::DuplicateClaim;
					}
				},
				Err((e, monitor_update)) => {
					if let Err(e) = self.chain_monitor.update_channel(chan.get().get_funding_txo().unwrap(), monitor_update) {
						log_given_level!(self.logger, if e == ChannelMonitorUpdateErr::PermanentFailure { Level::Error } else { Level::Info },
							"Failed to update channel monitor with preimage {:?} immediately prior to force-close: {:?}",
							payment_preimage, e);
					}
					let counterparty_node_id = chan.get().get_counterparty_node_id();
					let (drop, res) = convert_chan_err!(self, e, channel_state.short_to_id, chan.get_mut(), &chan_id);
					if drop {
						chan.remove_entry();
					}
					return ClaimFundsFromHop::MonitorUpdateFail(counterparty_node_id, res, None);
				},
			}
		} else { unreachable!(); }
	}

	fn finalize_claims(&self, mut sources: Vec<HTLCSource>) {
		let mut outbounds = self.pending_outbound_payments.lock().unwrap();
		let mut pending_events = self.pending_events.lock().unwrap();
		for source in sources.drain(..) {
			if let HTLCSource::OutboundRoute { session_priv, payment_id, path, .. } = source {
				let mut session_priv_bytes = [0; 32];
				session_priv_bytes.copy_from_slice(&session_priv[..]);
				if let hash_map::Entry::Occupied(mut payment) = outbounds.entry(payment_id) {
					assert!(payment.get().is_fulfilled());
					if payment.get_mut().remove(&session_priv_bytes, None) {
						pending_events.push(
							events::Event::PaymentPathSuccessful {
								payment_id,
								payment_hash: payment.get().payment_hash(),
								path,
							}
						);
					}
					if payment.get().remaining_parts() == 0 {
						payment.remove();
					}
				}
			}
		}
	}

	fn claim_funds_internal(&self, mut channel_state_lock: MutexGuard<ChannelHolder<Signer>>, source: HTLCSource, payment_preimage: PaymentPreimage, forwarded_htlc_value_msat: Option<u64>, from_onchain: bool, next_channel_id: [u8; 32]) {
		match source {
			HTLCSource::OutboundRoute { session_priv, payment_id, path, .. } => {
				mem::drop(channel_state_lock);
				let mut session_priv_bytes = [0; 32];
				session_priv_bytes.copy_from_slice(&session_priv[..]);
				let mut outbounds = self.pending_outbound_payments.lock().unwrap();
				if let hash_map::Entry::Occupied(mut payment) = outbounds.entry(payment_id) {
					let mut pending_events = self.pending_events.lock().unwrap();
					if !payment.get().is_fulfilled() {
						let payment_hash = PaymentHash(Sha256::hash(&payment_preimage.0).into_inner());
						let fee_paid_msat = payment.get().get_pending_fee_msat();
						pending_events.push(
							events::Event::PaymentSent {
								payment_id: Some(payment_id),
								payment_preimage,
								payment_hash,
								fee_paid_msat,
							}
						);
						payment.get_mut().mark_fulfilled();
					}

					if from_onchain {
						// We currently immediately remove HTLCs which were fulfilled on-chain.
						// This could potentially lead to removing a pending payment too early,
						// with a reorg of one block causing us to re-add the fulfilled payment on
						// restart.
						// TODO: We should have a second monitor event that informs us of payments
						// irrevocably fulfilled.
						if payment.get_mut().remove(&session_priv_bytes, Some(&path)) {
							let payment_hash = Some(PaymentHash(Sha256::hash(&payment_preimage.0).into_inner()));
							pending_events.push(
								events::Event::PaymentPathSuccessful {
									payment_id,
									payment_hash,
									path,
								}
							);
						}

						if payment.get().remaining_parts() == 0 {
							payment.remove();
						}
					}
				} else {
					log_trace!(self.logger, "Received duplicative fulfill for HTLC with payment_preimage {}", log_bytes!(payment_preimage.0));
				}
			},
			HTLCSource::PreviousHopData(hop_data) => {
				let prev_outpoint = hop_data.outpoint;
				let res = self.claim_funds_from_hop(&mut channel_state_lock, hop_data, payment_preimage);
				let claimed_htlc = if let ClaimFundsFromHop::DuplicateClaim = res { false } else { true };
				let htlc_claim_value_msat = match res {
					ClaimFundsFromHop::MonitorUpdateFail(_, _, amt_opt) => amt_opt,
					ClaimFundsFromHop::Success(amt) => Some(amt),
					_ => None,
				};
				if let ClaimFundsFromHop::PrevHopForceClosed = res {
					let preimage_update = ChannelMonitorUpdate {
						update_id: CLOSED_CHANNEL_UPDATE_ID,
						updates: vec![ChannelMonitorUpdateStep::PaymentPreimage {
							payment_preimage: payment_preimage.clone(),
						}],
					};
					// We update the ChannelMonitor on the backward link, after
					// receiving an offchain preimage event from the forward link (the
					// event being update_fulfill_htlc).
					if let Err(e) = self.chain_monitor.update_channel(prev_outpoint, preimage_update) {
						log_error!(self.logger, "Critical error: failed to update channel monitor with preimage {:?}: {:?}",
											 payment_preimage, e);
					}
					// Note that we do *not* set `claimed_htlc` to false here. In fact, this
					// totally could be a duplicate claim, but we have no way of knowing
					// without interrogating the `ChannelMonitor` we've provided the above
					// update to. Instead, we simply document in `PaymentForwarded` that this
					// can happen.
				}
				mem::drop(channel_state_lock);
				if let ClaimFundsFromHop::MonitorUpdateFail(pk, err, _) = res {
					let result: Result<(), _> = Err(err);
					let _ = handle_error!(self, result, pk);
				}

				if claimed_htlc {
					if let Some(forwarded_htlc_value) = forwarded_htlc_value_msat {
						let fee_earned_msat = if let Some(claimed_htlc_value) = htlc_claim_value_msat {
							Some(claimed_htlc_value - forwarded_htlc_value)
						} else { None };

						let mut pending_events = self.pending_events.lock().unwrap();
						let prev_channel_id = Some(prev_outpoint.to_channel_id());
						let next_channel_id = Some(next_channel_id);

						pending_events.push(events::Event::PaymentForwarded {
							fee_earned_msat,
							claim_from_onchain_tx: from_onchain,
							prev_channel_id,
							next_channel_id,
						});
					}
				}
			},
		}
	}

	/// Gets the node_id held by this ChannelManager
	pub fn get_our_node_id(&self) -> PublicKey {
		self.our_network_pubkey.clone()
	}

	fn channel_monitor_updated(&self, funding_txo: &OutPoint, highest_applied_update_id: u64) {
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(&self.total_consistency_lock, &self.persistence_notifier);

		let chan_restoration_res;
		let (mut pending_failures, finalized_claims) = {
			let mut channel_lock = self.channel_state.lock().unwrap();
			let channel_state = &mut *channel_lock;
			let mut channel = match channel_state.by_id.entry(funding_txo.to_channel_id()) {
				hash_map::Entry::Occupied(chan) => chan,
				hash_map::Entry::Vacant(_) => return,
			};
			if !channel.get().is_awaiting_monitor_update() || channel.get().get_latest_monitor_update_id() != highest_applied_update_id {
				return;
			}

			let updates = channel.get_mut().monitor_updating_restored(&self.logger, self.get_our_node_id(), self.genesis_hash, self.best_block.read().unwrap().height());
			let channel_update = if updates.channel_ready.is_some() && channel.get().is_usable() {
				// We only send a channel_update in the case where we are just now sending a
				// channel_ready and the channel is in a usable state. We may re-send a
				// channel_update later through the announcement_signatures process for public
				// channels, but there's no reason not to just inform our counterparty of our fees
				// now.
				if let Ok(msg) = self.get_channel_update_for_unicast(channel.get()) {
					Some(events::MessageSendEvent::SendChannelUpdate {
						node_id: channel.get().get_counterparty_node_id(),
						msg,
					})
				} else { None }
			} else { None };
			chan_restoration_res = handle_chan_restoration_locked!(self, channel_lock, channel_state, channel, updates.raa, updates.commitment_update, updates.order, None, updates.accepted_htlcs, updates.funding_broadcastable, updates.channel_ready, updates.announcement_sigs);
			if let Some(upd) = channel_update {
				channel_state.pending_msg_events.push(upd);
			}
			(updates.failed_htlcs, updates.finalized_claimed_htlcs)
		};
		post_handle_chan_restoration!(self, chan_restoration_res);
		self.finalize_claims(finalized_claims);
		for failure in pending_failures.drain(..) {
			self.fail_htlc_backwards_internal(self.channel_state.lock().unwrap(), failure.0, &failure.1, failure.2);
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
	/// [`Event::OpenChannelRequest`]: events::Event::OpenChannelRequest
	/// [`Event::ChannelClosed::user_channel_id`]: events::Event::ChannelClosed::user_channel_id
	pub fn accept_inbound_channel(&self, temporary_channel_id: &[u8; 32], counterparty_node_id: &PublicKey, user_channel_id: u64) -> Result<(), APIError> {
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
	pub fn accept_inbound_channel_from_trusted_peer_0conf(&self, temporary_channel_id: &[u8; 32], counterparty_node_id: &PublicKey, user_channel_id: u64) -> Result<(), APIError> {
		self.do_accept_inbound_channel(temporary_channel_id, counterparty_node_id, true, user_channel_id)
	}

	fn do_accept_inbound_channel(&self, temporary_channel_id: &[u8; 32], counterparty_node_id: &PublicKey, accept_0conf: bool, user_channel_id: u64) -> Result<(), APIError> {
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(&self.total_consistency_lock, &self.persistence_notifier);

		let mut channel_state_lock = self.channel_state.lock().unwrap();
		let channel_state = &mut *channel_state_lock;
		match channel_state.by_id.entry(temporary_channel_id.clone()) {
			hash_map::Entry::Occupied(mut channel) => {
				if !channel.get().inbound_is_awaiting_accept() {
					return Err(APIError::APIMisuseError { err: "The channel isn't currently awaiting to be accepted.".to_owned() });
				}
				if *counterparty_node_id != channel.get().get_counterparty_node_id() {
					return Err(APIError::APIMisuseError { err: "The passed counterparty_node_id doesn't match the channel's counterparty node_id".to_owned() });
				}
				if accept_0conf { channel.get_mut().set_0conf(); }
				channel_state.pending_msg_events.push(events::MessageSendEvent::SendAcceptChannel {
					node_id: channel.get().get_counterparty_node_id(),
					msg: channel.get_mut().accept_inbound_channel(user_channel_id),
				});
			}
			hash_map::Entry::Vacant(_) => {
				return Err(APIError::ChannelUnavailable { err: "Can't accept a channel that doesn't exist".to_owned() });
			}
		}
		Ok(())
	}

	fn internal_open_channel(&self, counterparty_node_id: &PublicKey, their_features: InitFeatures, msg: &msgs::OpenChannel) -> Result<(), MsgHandleErrInternal> {
		if msg.chain_hash != self.genesis_hash {
			return Err(MsgHandleErrInternal::send_err_msg_no_close("Unknown genesis block hash".to_owned(), msg.temporary_channel_id.clone()));
		}

		if !self.default_configuration.accept_inbound_channels {
			return Err(MsgHandleErrInternal::send_err_msg_no_close("No inbound channels accepted".to_owned(), msg.temporary_channel_id.clone()));
		}

		let outbound_scid_alias = self.create_and_insert_outbound_scid_alias();
		let mut channel = match Channel::new_from_req(&self.fee_estimator, &self.keys_manager,
			counterparty_node_id.clone(), &their_features, msg, 0, &self.default_configuration,
			self.best_block.read().unwrap().height(), &self.logger, outbound_scid_alias)
		{
			Err(e) => {
				self.outbound_scid_aliases.lock().unwrap().remove(&outbound_scid_alias);
				return Err(MsgHandleErrInternal::from_chan_no_close(e, msg.temporary_channel_id));
			},
			Ok(res) => res
		};
		let mut channel_state_lock = self.channel_state.lock().unwrap();
		let channel_state = &mut *channel_state_lock;
		match channel_state.by_id.entry(channel.channel_id()) {
			hash_map::Entry::Occupied(_) => {
				self.outbound_scid_aliases.lock().unwrap().remove(&outbound_scid_alias);
				return Err(MsgHandleErrInternal::send_err_msg_no_close("temporary_channel_id collision!".to_owned(), msg.temporary_channel_id.clone()))
			},
			hash_map::Entry::Vacant(entry) => {
				if !self.default_configuration.manually_accept_inbound_channels {
					channel_state.pending_msg_events.push(events::MessageSendEvent::SendAcceptChannel {
						node_id: counterparty_node_id.clone(),
						msg: channel.accept_inbound_channel(0),
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

	fn internal_accept_channel(&self, counterparty_node_id: &PublicKey, their_features: InitFeatures, msg: &msgs::AcceptChannel) -> Result<(), MsgHandleErrInternal> {
		let (value, output_script, user_id) = {
			let mut channel_lock = self.channel_state.lock().unwrap();
			let channel_state = &mut *channel_lock;
			match channel_state.by_id.entry(msg.temporary_channel_id) {
				hash_map::Entry::Occupied(mut chan) => {
					if chan.get().get_counterparty_node_id() != *counterparty_node_id {
						return Err(MsgHandleErrInternal::send_err_msg_no_close("Got a message for a channel from the wrong node!".to_owned(), msg.temporary_channel_id));
					}
					try_chan_entry!(self, chan.get_mut().accept_channel(&msg, &self.default_configuration.peer_channel_config_limits, &their_features), channel_state, chan);
					(chan.get().get_value_satoshis(), chan.get().get_funding_redeemscript().to_v0_p2wsh(), chan.get().get_user_id())
				},
				hash_map::Entry::Vacant(_) => return Err(MsgHandleErrInternal::send_err_msg_no_close("Failed to find corresponding channel".to_owned(), msg.temporary_channel_id))
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
		let ((funding_msg, monitor, mut channel_ready), mut chan) = {
			let best_block = *self.best_block.read().unwrap();
			let mut channel_lock = self.channel_state.lock().unwrap();
			let channel_state = &mut *channel_lock;
			match channel_state.by_id.entry(msg.temporary_channel_id.clone()) {
				hash_map::Entry::Occupied(mut chan) => {
					if chan.get().get_counterparty_node_id() != *counterparty_node_id {
						return Err(MsgHandleErrInternal::send_err_msg_no_close("Got a message for a channel from the wrong node!".to_owned(), msg.temporary_channel_id));
					}
					(try_chan_entry!(self, chan.get_mut().funding_created(msg, best_block, &self.logger), channel_state, chan), chan.remove())
				},
				hash_map::Entry::Vacant(_) => return Err(MsgHandleErrInternal::send_err_msg_no_close("Failed to find corresponding channel".to_owned(), msg.temporary_channel_id))
			}
		};
		// Because we have exclusive ownership of the channel here we can release the channel_state
		// lock before watch_channel
		if let Err(e) = self.chain_monitor.watch_channel(monitor.get_funding_txo().0, monitor) {
			match e {
				ChannelMonitorUpdateErr::PermanentFailure => {
					// Note that we reply with the new channel_id in error messages if we gave up on the
					// channel, not the temporary_channel_id. This is compatible with ourselves, but the
					// spec is somewhat ambiguous here. Not a huge deal since we'll send error messages for
					// any messages referencing a previously-closed channel anyway.
					// We do not do a force-close here as that would generate a monitor update for
					// a monitor that we didn't manage to store (and that we don't care about - we
					// don't respond with the funding_signed so the channel can never go on chain).
					let (_monitor_update, failed_htlcs) = chan.force_shutdown(true);
					assert!(failed_htlcs.is_empty());
					return Err(MsgHandleErrInternal::send_err_msg_no_close("ChannelMonitor storage failure".to_owned(), funding_msg.channel_id));
				},
				ChannelMonitorUpdateErr::TemporaryFailure => {
					// There's no problem signing a counterparty's funding transaction if our monitor
					// hasn't persisted to disk yet - we can't lose money on a transaction that we haven't
					// accepted payment from yet. We do, however, need to wait to send our channel_ready
					// until we have persisted our monitor.
					chan.monitor_update_failed(false, false, channel_ready.is_some(), Vec::new(), Vec::new(), Vec::new());
					channel_ready = None; // Don't send the channel_ready now
				},
			}
		}
		let mut channel_state_lock = self.channel_state.lock().unwrap();
		let channel_state = &mut *channel_state_lock;
		match channel_state.by_id.entry(funding_msg.channel_id) {
			hash_map::Entry::Occupied(_) => {
				return Err(MsgHandleErrInternal::send_err_msg_no_close("Already had channel with the new channel_id".to_owned(), funding_msg.channel_id))
			},
			hash_map::Entry::Vacant(e) => {
				channel_state.pending_msg_events.push(events::MessageSendEvent::SendFundingSigned {
					node_id: counterparty_node_id.clone(),
					msg: funding_msg,
				});
				if let Some(msg) = channel_ready {
					send_channel_ready!(channel_state.short_to_id, channel_state.pending_msg_events, chan, msg);
				}
				e.insert(chan);
			}
		}
		Ok(())
	}

	fn internal_funding_signed(&self, counterparty_node_id: &PublicKey, msg: &msgs::FundingSigned) -> Result<(), MsgHandleErrInternal> {
		let funding_tx = {
			let best_block = *self.best_block.read().unwrap();
			let mut channel_lock = self.channel_state.lock().unwrap();
			let channel_state = &mut *channel_lock;
			match channel_state.by_id.entry(msg.channel_id) {
				hash_map::Entry::Occupied(mut chan) => {
					if chan.get().get_counterparty_node_id() != *counterparty_node_id {
						return Err(MsgHandleErrInternal::send_err_msg_no_close("Got a message for a channel from the wrong node!".to_owned(), msg.channel_id));
					}
					let (monitor, funding_tx, channel_ready) = match chan.get_mut().funding_signed(&msg, best_block, &self.logger) {
						Ok(update) => update,
						Err(e) => try_chan_entry!(self, Err(e), channel_state, chan),
					};
					if let Err(e) = self.chain_monitor.watch_channel(chan.get().get_funding_txo().unwrap(), monitor) {
						let mut res = handle_monitor_err!(self, e, channel_state, chan, RAACommitmentOrder::RevokeAndACKFirst, channel_ready.is_some(), OPTIONALLY_RESEND_FUNDING_LOCKED);
						if let Err(MsgHandleErrInternal { ref mut shutdown_finish, .. }) = res {
							// We weren't able to watch the channel to begin with, so no updates should be made on
							// it. Previously, full_stack_target found an (unreachable) panic when the
							// monitor update contained within `shutdown_finish` was applied.
							if let Some((ref mut shutdown_finish, _)) = shutdown_finish {
								shutdown_finish.0.take();
							}
						}
						return res
					}
					if let Some(msg) = channel_ready {
						send_channel_ready!(channel_state.short_to_id, channel_state.pending_msg_events, chan.get(), msg);
					}
					funding_tx
				},
				hash_map::Entry::Vacant(_) => return Err(MsgHandleErrInternal::send_err_msg_no_close("Failed to find corresponding channel".to_owned(), msg.channel_id))
			}
		};
		log_info!(self.logger, "Broadcasting funding transaction with txid {}", funding_tx.txid());
		self.tx_broadcaster.broadcast_transaction(&funding_tx);
		Ok(())
	}

	fn internal_channel_ready(&self, counterparty_node_id: &PublicKey, msg: &msgs::ChannelReady) -> Result<(), MsgHandleErrInternal> {
		let mut channel_state_lock = self.channel_state.lock().unwrap();
		let channel_state = &mut *channel_state_lock;
		match channel_state.by_id.entry(msg.channel_id) {
			hash_map::Entry::Occupied(mut chan) => {
				if chan.get().get_counterparty_node_id() != *counterparty_node_id {
					return Err(MsgHandleErrInternal::send_err_msg_no_close("Got a message for a channel from the wrong node!".to_owned(), msg.channel_id));
				}
				let announcement_sigs_opt = try_chan_entry!(self, chan.get_mut().channel_ready(&msg, self.get_our_node_id(),
					self.genesis_hash.clone(), &self.best_block.read().unwrap(), &self.logger), channel_state, chan);
				if let Some(announcement_sigs) = announcement_sigs_opt {
					log_trace!(self.logger, "Sending announcement_signatures for channel {}", log_bytes!(chan.get().channel_id()));
					channel_state.pending_msg_events.push(events::MessageSendEvent::SendAnnouncementSignatures {
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
						channel_state.pending_msg_events.push(events::MessageSendEvent::SendChannelUpdate {
							node_id: counterparty_node_id.clone(),
							msg,
						});
					}
				}
				Ok(())
			},
			hash_map::Entry::Vacant(_) => Err(MsgHandleErrInternal::send_err_msg_no_close("Failed to find corresponding channel".to_owned(), msg.channel_id))
		}
	}

	fn internal_shutdown(&self, counterparty_node_id: &PublicKey, their_features: &InitFeatures, msg: &msgs::Shutdown) -> Result<(), MsgHandleErrInternal> {
		let mut dropped_htlcs: Vec<(HTLCSource, PaymentHash)>;
		let result: Result<(), _> = loop {
			let mut channel_state_lock = self.channel_state.lock().unwrap();
			let channel_state = &mut *channel_state_lock;

			match channel_state.by_id.entry(msg.channel_id.clone()) {
				hash_map::Entry::Occupied(mut chan_entry) => {
					if chan_entry.get().get_counterparty_node_id() != *counterparty_node_id {
						return Err(MsgHandleErrInternal::send_err_msg_no_close("Got a message for a channel from the wrong node!".to_owned(), msg.channel_id));
					}

					if !chan_entry.get().received_shutdown() {
						log_info!(self.logger, "Received a shutdown message from our counterparty for channel {}{}.",
							log_bytes!(msg.channel_id),
							if chan_entry.get().sent_shutdown() { " after we initiated shutdown" } else { "" });
					}

					let (shutdown, monitor_update, htlcs) = try_chan_entry!(self, chan_entry.get_mut().shutdown(&self.keys_manager, &their_features, &msg), channel_state, chan_entry);
					dropped_htlcs = htlcs;

					// Update the monitor with the shutdown script if necessary.
					if let Some(monitor_update) = monitor_update {
						if let Err(e) = self.chain_monitor.update_channel(chan_entry.get().get_funding_txo().unwrap(), monitor_update) {
							let (result, is_permanent) =
								handle_monitor_err!(self, e, channel_state.short_to_id, chan_entry.get_mut(), RAACommitmentOrder::CommitmentFirst, chan_entry.key(), NO_UPDATE);
							if is_permanent {
								remove_channel!(self, channel_state, chan_entry);
								break result;
							}
						}
					}

					if let Some(msg) = shutdown {
						channel_state.pending_msg_events.push(events::MessageSendEvent::SendShutdown {
							node_id: *counterparty_node_id,
							msg,
						});
					}

					break Ok(());
				},
				hash_map::Entry::Vacant(_) => return Err(MsgHandleErrInternal::send_err_msg_no_close("Failed to find corresponding channel".to_owned(), msg.channel_id))
			}
		};
		for htlc_source in dropped_htlcs.drain(..) {
			self.fail_htlc_backwards_internal(self.channel_state.lock().unwrap(), htlc_source.0, &htlc_source.1, HTLCFailReason::Reason { failure_code: 0x4000 | 8, data: Vec::new() });
		}

		let _ = handle_error!(self, result, *counterparty_node_id);
		Ok(())
	}

	fn internal_closing_signed(&self, counterparty_node_id: &PublicKey, msg: &msgs::ClosingSigned) -> Result<(), MsgHandleErrInternal> {
		let (tx, chan_option) = {
			let mut channel_state_lock = self.channel_state.lock().unwrap();
			let channel_state = &mut *channel_state_lock;
			match channel_state.by_id.entry(msg.channel_id.clone()) {
				hash_map::Entry::Occupied(mut chan_entry) => {
					if chan_entry.get().get_counterparty_node_id() != *counterparty_node_id {
						return Err(MsgHandleErrInternal::send_err_msg_no_close("Got a message for a channel from the wrong node!".to_owned(), msg.channel_id));
					}
					let (closing_signed, tx) = try_chan_entry!(self, chan_entry.get_mut().closing_signed(&self.fee_estimator, &msg), channel_state, chan_entry);
					if let Some(msg) = closing_signed {
						channel_state.pending_msg_events.push(events::MessageSendEvent::SendClosingSigned {
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
						(tx, Some(remove_channel!(self, channel_state, chan_entry)))
					} else { (tx, None) }
				},
				hash_map::Entry::Vacant(_) => return Err(MsgHandleErrInternal::send_err_msg_no_close("Failed to find corresponding channel".to_owned(), msg.channel_id))
			}
		};
		if let Some(broadcast_tx) = tx {
			log_info!(self.logger, "Broadcasting {}", log_tx!(broadcast_tx));
			self.tx_broadcaster.broadcast_transaction(&broadcast_tx);
		}
		if let Some(chan) = chan_option {
			if let Ok(update) = self.get_channel_update_for_broadcast(&chan) {
				let mut channel_state = self.channel_state.lock().unwrap();
				channel_state.pending_msg_events.push(events::MessageSendEvent::BroadcastChannelUpdate {
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

		let (pending_forward_info, mut channel_state_lock) = self.decode_update_add_htlc_onion(msg);
		let channel_state = &mut *channel_state_lock;

		match channel_state.by_id.entry(msg.channel_id) {
			hash_map::Entry::Occupied(mut chan) => {
				if chan.get().get_counterparty_node_id() != *counterparty_node_id {
					return Err(MsgHandleErrInternal::send_err_msg_no_close("Got a message for a channel from the wrong node!".to_owned(), msg.channel_id));
				}

				let create_pending_htlc_status = |chan: &Channel<Signer>, pending_forward_info: PendingHTLCStatus, error_code: u16| {
					// If the update_add is completely bogus, the call will Err and we will close,
					// but if we've sent a shutdown and they haven't acknowledged it yet, we just
					// want to reject the new HTLC and fail it backwards instead of forwarding.
					match pending_forward_info {
						PendingHTLCStatus::Forward(PendingHTLCInfo { ref incoming_shared_secret, .. }) => {
							let reason = if (error_code & 0x1000) != 0 {
								let (real_code, error_data) = self.get_htlc_inbound_temp_fail_err_and_data(error_code, chan);
								onion_utils::build_first_hop_failure_packet(incoming_shared_secret, real_code, &error_data)
							} else {
								onion_utils::build_first_hop_failure_packet(incoming_shared_secret, error_code, &[])
							};
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
				try_chan_entry!(self, chan.get_mut().update_add_htlc(&msg, pending_forward_info, create_pending_htlc_status, &self.logger), channel_state, chan);
			},
			hash_map::Entry::Vacant(_) => return Err(MsgHandleErrInternal::send_err_msg_no_close("Failed to find corresponding channel".to_owned(), msg.channel_id))
		}
		Ok(())
	}

	fn internal_update_fulfill_htlc(&self, counterparty_node_id: &PublicKey, msg: &msgs::UpdateFulfillHTLC) -> Result<(), MsgHandleErrInternal> {
		let mut channel_lock = self.channel_state.lock().unwrap();
		let (htlc_source, forwarded_htlc_value) = {
			let channel_state = &mut *channel_lock;
			match channel_state.by_id.entry(msg.channel_id) {
				hash_map::Entry::Occupied(mut chan) => {
					if chan.get().get_counterparty_node_id() != *counterparty_node_id {
						return Err(MsgHandleErrInternal::send_err_msg_no_close("Got a message for a channel from the wrong node!".to_owned(), msg.channel_id));
					}
					try_chan_entry!(self, chan.get_mut().update_fulfill_htlc(&msg), channel_state, chan)
				},
				hash_map::Entry::Vacant(_) => return Err(MsgHandleErrInternal::send_err_msg_no_close("Failed to find corresponding channel".to_owned(), msg.channel_id))
			}
		};
		self.claim_funds_internal(channel_lock, htlc_source, msg.payment_preimage.clone(), Some(forwarded_htlc_value), false, msg.channel_id);
		Ok(())
	}

	fn internal_update_fail_htlc(&self, counterparty_node_id: &PublicKey, msg: &msgs::UpdateFailHTLC) -> Result<(), MsgHandleErrInternal> {
		let mut channel_lock = self.channel_state.lock().unwrap();
		let channel_state = &mut *channel_lock;
		match channel_state.by_id.entry(msg.channel_id) {
			hash_map::Entry::Occupied(mut chan) => {
				if chan.get().get_counterparty_node_id() != *counterparty_node_id {
					return Err(MsgHandleErrInternal::send_err_msg_no_close("Got a message for a channel from the wrong node!".to_owned(), msg.channel_id));
				}
				try_chan_entry!(self, chan.get_mut().update_fail_htlc(&msg, HTLCFailReason::LightningError { err: msg.reason.clone() }), channel_state, chan);
			},
			hash_map::Entry::Vacant(_) => return Err(MsgHandleErrInternal::send_err_msg_no_close("Failed to find corresponding channel".to_owned(), msg.channel_id))
		}
		Ok(())
	}

	fn internal_update_fail_malformed_htlc(&self, counterparty_node_id: &PublicKey, msg: &msgs::UpdateFailMalformedHTLC) -> Result<(), MsgHandleErrInternal> {
		let mut channel_lock = self.channel_state.lock().unwrap();
		let channel_state = &mut *channel_lock;
		match channel_state.by_id.entry(msg.channel_id) {
			hash_map::Entry::Occupied(mut chan) => {
				if chan.get().get_counterparty_node_id() != *counterparty_node_id {
					return Err(MsgHandleErrInternal::send_err_msg_no_close("Got a message for a channel from the wrong node!".to_owned(), msg.channel_id));
				}
				if (msg.failure_code & 0x8000) == 0 {
					let chan_err: ChannelError = ChannelError::Close("Got update_fail_malformed_htlc with BADONION not set".to_owned());
					try_chan_entry!(self, Err(chan_err), channel_state, chan);
				}
				try_chan_entry!(self, chan.get_mut().update_fail_malformed_htlc(&msg, HTLCFailReason::Reason { failure_code: msg.failure_code, data: Vec::new() }), channel_state, chan);
				Ok(())
			},
			hash_map::Entry::Vacant(_) => return Err(MsgHandleErrInternal::send_err_msg_no_close("Failed to find corresponding channel".to_owned(), msg.channel_id))
		}
	}

	fn internal_commitment_signed(&self, counterparty_node_id: &PublicKey, msg: &msgs::CommitmentSigned) -> Result<(), MsgHandleErrInternal> {
		let mut channel_state_lock = self.channel_state.lock().unwrap();
		let channel_state = &mut *channel_state_lock;
		match channel_state.by_id.entry(msg.channel_id) {
			hash_map::Entry::Occupied(mut chan) => {
				if chan.get().get_counterparty_node_id() != *counterparty_node_id {
					return Err(MsgHandleErrInternal::send_err_msg_no_close("Got a message for a channel from the wrong node!".to_owned(), msg.channel_id));
				}
				let (revoke_and_ack, commitment_signed, monitor_update) =
					match chan.get_mut().commitment_signed(&msg, &self.logger) {
						Err((None, e)) => try_chan_entry!(self, Err(e), channel_state, chan),
						Err((Some(update), e)) => {
							assert!(chan.get().is_awaiting_monitor_update());
							let _ = self.chain_monitor.update_channel(chan.get().get_funding_txo().unwrap(), update);
							try_chan_entry!(self, Err(e), channel_state, chan);
							unreachable!();
						},
						Ok(res) => res
					};
				if let Err(e) = self.chain_monitor.update_channel(chan.get().get_funding_txo().unwrap(), monitor_update) {
					return_monitor_err!(self, e, channel_state, chan, RAACommitmentOrder::RevokeAndACKFirst, true, commitment_signed.is_some());
				}
				channel_state.pending_msg_events.push(events::MessageSendEvent::SendRevokeAndACK {
					node_id: counterparty_node_id.clone(),
					msg: revoke_and_ack,
				});
				if let Some(msg) = commitment_signed {
					channel_state.pending_msg_events.push(events::MessageSendEvent::UpdateHTLCs {
						node_id: counterparty_node_id.clone(),
						updates: msgs::CommitmentUpdate {
							update_add_htlcs: Vec::new(),
							update_fulfill_htlcs: Vec::new(),
							update_fail_htlcs: Vec::new(),
							update_fail_malformed_htlcs: Vec::new(),
							update_fee: None,
							commitment_signed: msg,
						},
					});
				}
				Ok(())
			},
			hash_map::Entry::Vacant(_) => return Err(MsgHandleErrInternal::send_err_msg_no_close("Failed to find corresponding channel".to_owned(), msg.channel_id))
		}
	}

	#[inline]
	fn forward_htlcs(&self, per_source_pending_forwards: &mut [(u64, OutPoint, Vec<(PendingHTLCInfo, u64)>)]) {
		for &mut (prev_short_channel_id, prev_funding_outpoint, ref mut pending_forwards) in per_source_pending_forwards {
			let mut forward_event = None;
			if !pending_forwards.is_empty() {
				let mut channel_state = self.channel_state.lock().unwrap();
				if channel_state.forward_htlcs.is_empty() {
					forward_event = Some(Duration::from_millis(MIN_HTLC_RELAY_HOLDING_CELL_MILLIS))
				}
				for (forward_info, prev_htlc_id) in pending_forwards.drain(..) {
					match channel_state.forward_htlcs.entry(match forward_info.routing {
							PendingHTLCRouting::Forward { short_channel_id, .. } => short_channel_id,
							PendingHTLCRouting::Receive { .. } => 0,
							PendingHTLCRouting::ReceiveKeysend { .. } => 0,
					}) {
						hash_map::Entry::Occupied(mut entry) => {
							entry.get_mut().push(HTLCForwardInfo::AddHTLC { prev_short_channel_id, prev_funding_outpoint,
							                                                prev_htlc_id, forward_info });
						},
						hash_map::Entry::Vacant(entry) => {
							entry.insert(vec!(HTLCForwardInfo::AddHTLC { prev_short_channel_id, prev_funding_outpoint,
							                                             prev_htlc_id, forward_info }));
						}
					}
				}
			}
			match forward_event {
				Some(time) => {
					let mut pending_events = self.pending_events.lock().unwrap();
					pending_events.push(events::Event::PendingHTLCsForwardable {
						time_forwardable: time
					});
				}
				None => {},
			}
		}
	}

	fn internal_revoke_and_ack(&self, counterparty_node_id: &PublicKey, msg: &msgs::RevokeAndACK) -> Result<(), MsgHandleErrInternal> {
		let mut htlcs_to_fail = Vec::new();
		let res = loop {
			let mut channel_state_lock = self.channel_state.lock().unwrap();
			let channel_state = &mut *channel_state_lock;
			match channel_state.by_id.entry(msg.channel_id) {
				hash_map::Entry::Occupied(mut chan) => {
					if chan.get().get_counterparty_node_id() != *counterparty_node_id {
						break Err(MsgHandleErrInternal::send_err_msg_no_close("Got a message for a channel from the wrong node!".to_owned(), msg.channel_id));
					}
					let was_frozen_for_monitor = chan.get().is_awaiting_monitor_update();
					let raa_updates = break_chan_entry!(self,
						chan.get_mut().revoke_and_ack(&msg, &self.logger), channel_state, chan);
					htlcs_to_fail = raa_updates.holding_cell_failed_htlcs;
					if let Err(e) = self.chain_monitor.update_channel(chan.get().get_funding_txo().unwrap(), raa_updates.monitor_update) {
						if was_frozen_for_monitor {
							assert!(raa_updates.commitment_update.is_none());
							assert!(raa_updates.accepted_htlcs.is_empty());
							assert!(raa_updates.failed_htlcs.is_empty());
							assert!(raa_updates.finalized_claimed_htlcs.is_empty());
							break Err(MsgHandleErrInternal::ignore_no_close("Previous monitor update failure prevented responses to RAA".to_owned()));
						} else {
							if let Err(e) = handle_monitor_err!(self, e, channel_state, chan,
									RAACommitmentOrder::CommitmentFirst, false,
									raa_updates.commitment_update.is_some(), false,
									raa_updates.accepted_htlcs, raa_updates.failed_htlcs,
									raa_updates.finalized_claimed_htlcs) {
								break Err(e);
							} else { unreachable!(); }
						}
					}
					if let Some(updates) = raa_updates.commitment_update {
						channel_state.pending_msg_events.push(events::MessageSendEvent::UpdateHTLCs {
							node_id: counterparty_node_id.clone(),
							updates,
						});
					}
					break Ok((raa_updates.accepted_htlcs, raa_updates.failed_htlcs,
							raa_updates.finalized_claimed_htlcs,
							chan.get().get_short_channel_id()
								.unwrap_or(chan.get().outbound_scid_alias()),
							chan.get().get_funding_txo().unwrap()))
				},
				hash_map::Entry::Vacant(_) => break Err(MsgHandleErrInternal::send_err_msg_no_close("Failed to find corresponding channel".to_owned(), msg.channel_id))
			}
		};
		self.fail_holding_cell_htlcs(htlcs_to_fail, msg.channel_id);
		match res {
			Ok((pending_forwards, mut pending_failures, finalized_claim_htlcs,
				short_channel_id, channel_outpoint)) =>
			{
				for failure in pending_failures.drain(..) {
					self.fail_htlc_backwards_internal(self.channel_state.lock().unwrap(), failure.0, &failure.1, failure.2);
				}
				self.forward_htlcs(&mut [(short_channel_id, channel_outpoint, pending_forwards)]);
				self.finalize_claims(finalized_claim_htlcs);
				Ok(())
			},
			Err(e) => Err(e)
		}
	}

	fn internal_update_fee(&self, counterparty_node_id: &PublicKey, msg: &msgs::UpdateFee) -> Result<(), MsgHandleErrInternal> {
		let mut channel_lock = self.channel_state.lock().unwrap();
		let channel_state = &mut *channel_lock;
		match channel_state.by_id.entry(msg.channel_id) {
			hash_map::Entry::Occupied(mut chan) => {
				if chan.get().get_counterparty_node_id() != *counterparty_node_id {
					return Err(MsgHandleErrInternal::send_err_msg_no_close("Got a message for a channel from the wrong node!".to_owned(), msg.channel_id));
				}
				try_chan_entry!(self, chan.get_mut().update_fee(&self.fee_estimator, &msg), channel_state, chan);
			},
			hash_map::Entry::Vacant(_) => return Err(MsgHandleErrInternal::send_err_msg_no_close("Failed to find corresponding channel".to_owned(), msg.channel_id))
		}
		Ok(())
	}

	fn internal_announcement_signatures(&self, counterparty_node_id: &PublicKey, msg: &msgs::AnnouncementSignatures) -> Result<(), MsgHandleErrInternal> {
		let mut channel_state_lock = self.channel_state.lock().unwrap();
		let channel_state = &mut *channel_state_lock;

		match channel_state.by_id.entry(msg.channel_id) {
			hash_map::Entry::Occupied(mut chan) => {
				if chan.get().get_counterparty_node_id() != *counterparty_node_id {
					return Err(MsgHandleErrInternal::send_err_msg_no_close("Got a message for a channel from the wrong node!".to_owned(), msg.channel_id));
				}
				if !chan.get().is_usable() {
					return Err(MsgHandleErrInternal::from_no_close(LightningError{err: "Got an announcement_signatures before we were ready for it".to_owned(), action: msgs::ErrorAction::IgnoreError}));
				}

				channel_state.pending_msg_events.push(events::MessageSendEvent::BroadcastChannelAnnouncement {
					msg: try_chan_entry!(self, chan.get_mut().announcement_signatures(
						self.get_our_node_id(), self.genesis_hash.clone(), self.best_block.read().unwrap().height(), msg), channel_state, chan),
					// Note that announcement_signatures fails if the channel cannot be announced,
					// so get_channel_update_for_broadcast will never fail by the time we get here.
					update_msg: self.get_channel_update_for_broadcast(chan.get()).unwrap(),
				});
			},
			hash_map::Entry::Vacant(_) => return Err(MsgHandleErrInternal::send_err_msg_no_close("Failed to find corresponding channel".to_owned(), msg.channel_id))
		}
		Ok(())
	}

	/// Returns ShouldPersist if anything changed, otherwise either SkipPersist or an Err.
	fn internal_channel_update(&self, counterparty_node_id: &PublicKey, msg: &msgs::ChannelUpdate) -> Result<NotifyOption, MsgHandleErrInternal> {
		let mut channel_state_lock = self.channel_state.lock().unwrap();
		let channel_state = &mut *channel_state_lock;
		let chan_id = match channel_state.short_to_id.get(&msg.contents.short_channel_id) {
			Some(chan_id) => chan_id.clone(),
			None => {
				// It's not a local channel
				return Ok(NotifyOption::SkipPersist)
			}
		};
		match channel_state.by_id.entry(chan_id) {
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
					try_chan_entry!(self, chan.get_mut().channel_update(&msg), channel_state, chan);
				}
			},
			hash_map::Entry::Vacant(_) => unreachable!()
		}
		Ok(NotifyOption::DoPersist)
	}

	fn internal_channel_reestablish(&self, counterparty_node_id: &PublicKey, msg: &msgs::ChannelReestablish) -> Result<(), MsgHandleErrInternal> {
		let chan_restoration_res;
		let (htlcs_failed_forward, need_lnd_workaround) = {
			let mut channel_state_lock = self.channel_state.lock().unwrap();
			let channel_state = &mut *channel_state_lock;

			match channel_state.by_id.entry(msg.channel_id) {
				hash_map::Entry::Occupied(mut chan) => {
					if chan.get().get_counterparty_node_id() != *counterparty_node_id {
						return Err(MsgHandleErrInternal::send_err_msg_no_close("Got a message for a channel from the wrong node!".to_owned(), msg.channel_id));
					}
					// Currently, we expect all holding cell update_adds to be dropped on peer
					// disconnect, so Channel's reestablish will never hand us any holding cell
					// freed HTLCs to fail backwards. If in the future we no longer drop pending
					// add-HTLCs on disconnect, we may be handed HTLCs to fail backwards here.
					let responses = try_chan_entry!(self, chan.get_mut().channel_reestablish(
						msg, &self.logger, self.our_network_pubkey.clone(), self.genesis_hash,
						&*self.best_block.read().unwrap()), channel_state, chan);
					let mut channel_update = None;
					if let Some(msg) = responses.shutdown_msg {
						channel_state.pending_msg_events.push(events::MessageSendEvent::SendShutdown {
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
					chan_restoration_res = handle_chan_restoration_locked!(
						self, channel_state_lock, channel_state, chan, responses.raa, responses.commitment_update, responses.order,
						responses.mon_update, Vec::new(), None, responses.channel_ready, responses.announcement_sigs);
					if let Some(upd) = channel_update {
						channel_state.pending_msg_events.push(upd);
					}
					(responses.holding_cell_failed_htlcs, need_lnd_workaround)
				},
				hash_map::Entry::Vacant(_) => return Err(MsgHandleErrInternal::send_err_msg_no_close("Failed to find corresponding channel".to_owned(), msg.channel_id))
			}
		};
		post_handle_chan_restoration!(self, chan_restoration_res);
		self.fail_holding_cell_htlcs(htlcs_failed_forward, msg.channel_id);

		if let Some(channel_ready_msg) = need_lnd_workaround {
			self.internal_channel_ready(counterparty_node_id, &channel_ready_msg)?;
		}
		Ok(())
	}

	/// Process pending events from the `chain::Watch`, returning whether any events were processed.
	fn process_pending_monitor_events(&self) -> bool {
		let mut failed_channels = Vec::new();
		let mut pending_monitor_events = self.chain_monitor.release_pending_monitor_events();
		let has_pending_monitor_events = !pending_monitor_events.is_empty();
		for (funding_outpoint, mut monitor_events) in pending_monitor_events.drain(..) {
			for monitor_event in monitor_events.drain(..) {
				match monitor_event {
					MonitorEvent::HTLCEvent(htlc_update) => {
						if let Some(preimage) = htlc_update.payment_preimage {
							log_trace!(self.logger, "Claiming HTLC with preimage {} from our monitor", log_bytes!(preimage.0));
							self.claim_funds_internal(self.channel_state.lock().unwrap(), htlc_update.source, preimage, htlc_update.htlc_value_satoshis.map(|v| v * 1000), true, funding_outpoint.to_channel_id());
						} else {
							log_trace!(self.logger, "Failing HTLC with hash {} from our monitor", log_bytes!(htlc_update.payment_hash.0));
							self.fail_htlc_backwards_internal(self.channel_state.lock().unwrap(), htlc_update.source, &htlc_update.payment_hash, HTLCFailReason::Reason { failure_code: 0x4000 | 8, data: Vec::new() });
						}
					},
					MonitorEvent::CommitmentTxConfirmed(funding_outpoint) |
					MonitorEvent::UpdateFailed(funding_outpoint) => {
						let mut channel_lock = self.channel_state.lock().unwrap();
						let channel_state = &mut *channel_lock;
						let by_id = &mut channel_state.by_id;
						let pending_msg_events = &mut channel_state.pending_msg_events;
						if let hash_map::Entry::Occupied(chan_entry) = by_id.entry(funding_outpoint.to_channel_id()) {
							let mut chan = remove_channel!(self, channel_state, chan_entry);
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
					},
					MonitorEvent::UpdateCompleted { funding_txo, monitor_update_id } => {
						self.channel_monitor_updated(&funding_txo, monitor_update_id);
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
		self.process_pending_monitor_events();
	}

	/// Check the holding cell in each channel and free any pending HTLCs in them if possible.
	/// Returns whether there were any updates such as if pending HTLCs were freed or a monitor
	/// update was applied.
	///
	/// This should only apply to HTLCs which were added to the holding cell because we were
	/// waiting on a monitor update to finish. In that case, we don't want to free the holding cell
	/// directly in `channel_monitor_updated` as it may introduce deadlocks calling back into user
	/// code to inform them of a channel monitor update.
	fn check_free_holding_cells(&self) -> bool {
		let mut has_monitor_update = false;
		let mut failed_htlcs = Vec::new();
		let mut handle_errors = Vec::new();
		{
			let mut channel_state_lock = self.channel_state.lock().unwrap();
			let channel_state = &mut *channel_state_lock;
			let by_id = &mut channel_state.by_id;
			let short_to_id = &mut channel_state.short_to_id;
			let pending_msg_events = &mut channel_state.pending_msg_events;

			by_id.retain(|channel_id, chan| {
				match chan.maybe_free_holding_cell_htlcs(&self.logger) {
					Ok((commitment_opt, holding_cell_failed_htlcs)) => {
						if !holding_cell_failed_htlcs.is_empty() {
							failed_htlcs.push((holding_cell_failed_htlcs, *channel_id));
						}
						if let Some((commitment_update, monitor_update)) = commitment_opt {
							if let Err(e) = self.chain_monitor.update_channel(chan.get_funding_txo().unwrap(), monitor_update) {
								has_monitor_update = true;
								let (res, close_channel) = handle_monitor_err!(self, e, short_to_id, chan, RAACommitmentOrder::CommitmentFirst, channel_id, COMMITMENT_UPDATE_ONLY);
								handle_errors.push((chan.get_counterparty_node_id(), res));
								if close_channel { return false; }
							} else {
								pending_msg_events.push(events::MessageSendEvent::UpdateHTLCs {
									node_id: chan.get_counterparty_node_id(),
									updates: commitment_update,
								});
							}
						}
						true
					},
					Err(e) => {
						let (close_channel, res) = convert_chan_err!(self, e, short_to_id, chan, channel_id);
						handle_errors.push((chan.get_counterparty_node_id(), Err(res)));
						// ChannelClosed event is generated by handle_error for us
						!close_channel
					}
				}
			});
		}

		let has_update = has_monitor_update || !failed_htlcs.is_empty() || !handle_errors.is_empty();
		for (failures, channel_id) in failed_htlcs.drain(..) {
			self.fail_holding_cell_htlcs(failures, channel_id);
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
			let mut channel_state_lock = self.channel_state.lock().unwrap();
			let channel_state = &mut *channel_state_lock;
			let by_id = &mut channel_state.by_id;
			let short_to_id = &mut channel_state.short_to_id;
			let pending_msg_events = &mut channel_state.pending_msg_events;

			by_id.retain(|channel_id, chan| {
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
							update_maps_on_chan_removal!(self, short_to_id, chan);
							false
						} else { true }
					},
					Err(e) => {
						has_update = true;
						let (close_channel, res) = convert_chan_err!(self, e, short_to_id, chan, channel_id);
						handle_errors.push((chan.get_counterparty_node_id(), Err(res)));
						!close_channel
					}
				}
			});
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

		let payment_secret = PaymentSecret(self.keys_manager.get_secure_random_bytes());

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
	/// The [`PaymentPreimage`] will ultimately be returned to you in the [`PaymentReceived`], which
	/// will have the [`PaymentReceived::payment_preimage`] field filled in. That should then be
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
	/// [`claim_funds`]: Self::claim_funds
	/// [`PaymentReceived`]: events::Event::PaymentReceived
	/// [`PaymentReceived::payment_preimage`]: events::Event::PaymentReceived::payment_preimage
	/// [`create_inbound_payment_for_hash`]: Self::create_inbound_payment_for_hash
	pub fn create_inbound_payment(&self, min_value_msat: Option<u64>, invoice_expiry_delta_secs: u32) -> Result<(PaymentHash, PaymentSecret), ()> {
		inbound_payment::create(&self.inbound_payment_key, min_value_msat, invoice_expiry_delta_secs, &self.keys_manager, self.highest_seen_timestamp.load(Ordering::Acquire) as u64)
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
		let payment_preimage = PaymentPreimage(self.keys_manager.get_secure_random_bytes());
		let payment_hash = PaymentHash(Sha256::hash(&payment_preimage.0).into_inner());
		let payment_secret = self.set_payment_hash_secret_map(payment_hash, Some(payment_preimage), min_value_msat, invoice_expiry_delta_secs)?;
		Ok((payment_hash, payment_secret))
	}

	/// Gets a [`PaymentSecret`] for a given [`PaymentHash`], for which the payment preimage is
	/// stored external to LDK.
	///
	/// A [`PaymentReceived`] event will only be generated if the [`PaymentSecret`] matches a
	/// payment secret fetched via this method or [`create_inbound_payment`], and which is at least
	/// the `min_value_msat` provided here, if one is provided.
	///
	/// The [`PaymentHash`] (and corresponding [`PaymentPreimage`]) should be globally unique, though
	/// note that LDK will not stop you from registering duplicate payment hashes for inbound
	/// payments.
	///
	/// `min_value_msat` should be set if the invoice being generated contains a value. Any payment
	/// received for the returned [`PaymentHash`] will be required to be at least `min_value_msat`
	/// before a [`PaymentReceived`] event will be generated, ensuring that we do not provide the
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
	/// accept a payment and generate a [`PaymentReceived`] event for some time after the expiry.
	/// If you need exact expiry semantics, you should enforce them upon receipt of
	/// [`PaymentReceived`].
	///
	/// Note that invoices generated for inbound payments should have their `min_final_cltv_expiry`
	/// set to at least [`MIN_FINAL_CLTV_EXPIRY`].
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
	/// [`create_inbound_payment`]: Self::create_inbound_payment
	/// [`PaymentReceived`]: events::Event::PaymentReceived
	pub fn create_inbound_payment_for_hash(&self, payment_hash: PaymentHash, min_value_msat: Option<u64>, invoice_expiry_delta_secs: u32) -> Result<PaymentSecret, ()> {
		inbound_payment::create_from_hash(&self.inbound_payment_key, min_value_msat, payment_hash, invoice_expiry_delta_secs, self.highest_seen_timestamp.load(Ordering::Acquire) as u64)
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
		let mut channel_state = self.channel_state.lock().unwrap();
		let best_block = self.best_block.read().unwrap();
		loop {
			let scid_candidate = fake_scid::Namespace::Phantom.get_fake_scid(best_block.height(), &self.genesis_hash, &self.fake_scid_rand_bytes, &self.keys_manager);
			// Ensure the generated scid doesn't conflict with a real channel.
			match channel_state.short_to_id.entry(scid_candidate) {
				hash_map::Entry::Occupied(_) => continue,
				hash_map::Entry::Vacant(_) => return scid_candidate
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

	#[cfg(any(test, fuzzing, feature = "_test_utils"))]
	pub fn get_and_clear_pending_events(&self) -> Vec<events::Event> {
		let events = core::cell::RefCell::new(Vec::new());
		let event_handler = |event: &events::Event| events.borrow_mut().push(event.clone());
		self.process_pending_events(&event_handler);
		events.into_inner()
	}

	#[cfg(test)]
	pub fn has_pending_payments(&self) -> bool {
		!self.pending_outbound_payments.lock().unwrap().is_empty()
	}

	#[cfg(test)]
	pub fn clear_pending_payments(&self) {
		self.pending_outbound_payments.lock().unwrap().clear()
	}
}

impl<Signer: Sign, M: Deref, T: Deref, K: Deref, F: Deref, L: Deref> MessageSendEventsProvider for ChannelManager<Signer, M, T, K, F, L>
	where M::Target: chain::Watch<Signer>,
        T::Target: BroadcasterInterface,
        K::Target: KeysInterface<Signer = Signer>,
        F::Target: FeeEstimator,
				L::Target: Logger,
{
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
			let mut channel_state = self.channel_state.lock().unwrap();
			mem::swap(&mut pending_events, &mut channel_state.pending_msg_events);

			if !pending_events.is_empty() {
				events.replace(pending_events);
			}

			result
		});
		events.into_inner()
	}
}

impl<Signer: Sign, M: Deref, T: Deref, K: Deref, F: Deref, L: Deref> EventsProvider for ChannelManager<Signer, M, T, K, F, L>
where
	M::Target: chain::Watch<Signer>,
	T::Target: BroadcasterInterface,
	K::Target: KeysInterface<Signer = Signer>,
	F::Target: FeeEstimator,
	L::Target: Logger,
{
	/// Processes events that must be periodically handled.
	///
	/// An [`EventHandler`] may safely call back to the provider in order to handle an event.
	/// However, it must not call [`Writeable::write`] as doing so would result in a deadlock.
	///
	/// Pending events are persisted as part of [`ChannelManager`]. While these events are cleared
	/// when processed, an [`EventHandler`] must be able to handle previously seen events when
	/// restarting from an old state.
	fn process_pending_events<H: Deref>(&self, handler: H) where H::Target: EventHandler {
		PersistenceNotifierGuard::optionally_notify(&self.total_consistency_lock, &self.persistence_notifier, || {
			let mut result = NotifyOption::SkipPersist;

			// TODO: This behavior should be documented. It's unintuitive that we query
			// ChannelMonitors when clearing other events.
			if self.process_pending_monitor_events() {
				result = NotifyOption::DoPersist;
			}

			let mut pending_events = mem::replace(&mut *self.pending_events.lock().unwrap(), vec![]);
			if !pending_events.is_empty() {
				result = NotifyOption::DoPersist;
			}

			for event in pending_events.drain(..) {
				handler.handle_event(&event);
			}

			result
		});
	}
}

impl<Signer: Sign, M: Deref, T: Deref, K: Deref, F: Deref, L: Deref> chain::Listen for ChannelManager<Signer, M, T, K, F, L>
where
	M::Target: chain::Watch<Signer>,
	T::Target: BroadcasterInterface,
	K::Target: KeysInterface<Signer = Signer>,
	F::Target: FeeEstimator,
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

		self.do_chain_event(Some(new_height), |channel| channel.best_block_updated(new_height, header.time, self.genesis_hash.clone(), self.get_our_node_id(), &self.logger));
	}
}

impl<Signer: Sign, M: Deref, T: Deref, K: Deref, F: Deref, L: Deref> chain::Confirm for ChannelManager<Signer, M, T, K, F, L>
where
	M::Target: chain::Watch<Signer>,
	T::Target: BroadcasterInterface,
	K::Target: KeysInterface<Signer = Signer>,
	F::Target: FeeEstimator,
	L::Target: Logger,
{
	fn transactions_confirmed(&self, header: &BlockHeader, txdata: &TransactionData, height: u32) {
		// Note that we MUST NOT end up calling methods on self.chain_monitor here - we're called
		// during initialization prior to the chain_monitor being fully configured in some cases.
		// See the docs for `ChannelManagerReadArgs` for more.

		let block_hash = header.block_hash();
		log_trace!(self.logger, "{} transactions included in block {} at height {} provided", txdata.len(), block_hash, height);

		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(&self.total_consistency_lock, &self.persistence_notifier);
		self.do_chain_event(Some(height), |channel| channel.transactions_confirmed(&block_hash, height, txdata, self.genesis_hash.clone(), self.get_our_node_id(), &self.logger)
			.map(|(a, b)| (a, Vec::new(), b)));

		let last_best_block_height = self.best_block.read().unwrap().height();
		if height < last_best_block_height {
			let timestamp = self.highest_seen_timestamp.load(Ordering::Acquire);
			self.do_chain_event(Some(last_best_block_height), |channel| channel.best_block_updated(last_best_block_height, timestamp as u32, self.genesis_hash.clone(), self.get_our_node_id(), &self.logger));
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

		self.do_chain_event(Some(height), |channel| channel.best_block_updated(height, header.time, self.genesis_hash.clone(), self.get_our_node_id(), &self.logger));

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
		max_time!(self.last_node_announcement_serial);
		max_time!(self.highest_seen_timestamp);
		let mut payment_secrets = self.pending_inbound_payments.lock().unwrap();
		payment_secrets.retain(|_, inbound_payment| {
			inbound_payment.expiry_time > header.time as u64
		});

		let mut outbounds = self.pending_outbound_payments.lock().unwrap();
		let mut pending_events = self.pending_events.lock().unwrap();
		outbounds.retain(|payment_id, payment| {
			if payment.remaining_parts() != 0 { return true }
			if let PendingOutboundPayment::Retryable { starting_block_height, payment_hash, .. } = payment {
				if *starting_block_height + PAYMENT_EXPIRY_BLOCKS <= height {
					log_info!(self.logger, "Timing out payment with id {} and hash {}", log_bytes!(payment_id.0), log_bytes!(payment_hash.0));
					pending_events.push(events::Event::PaymentFailed {
						payment_id: *payment_id, payment_hash: *payment_hash,
					});
					false
				} else { true }
			} else { true }
		});
	}

	fn get_relevant_txids(&self) -> Vec<Txid> {
		let channel_state = self.channel_state.lock().unwrap();
		let mut res = Vec::with_capacity(channel_state.short_to_id.len());
		for chan in channel_state.by_id.values() {
			if let Some(funding_txo) = chan.get_funding_txo() {
				res.push(funding_txo.txid);
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

impl<Signer: Sign, M: Deref, T: Deref, K: Deref, F: Deref, L: Deref> ChannelManager<Signer, M, T, K, F, L>
where
	M::Target: chain::Watch<Signer>,
	T::Target: BroadcasterInterface,
	K::Target: KeysInterface<Signer = Signer>,
	F::Target: FeeEstimator,
	L::Target: Logger,
{
	/// Calls a function which handles an on-chain event (blocks dis/connected, transactions
	/// un/confirmed, etc) on each channel, handling any resulting errors or messages generated by
	/// the function.
	fn do_chain_event<FN: Fn(&mut Channel<Signer>) -> Result<(Option<msgs::ChannelReady>, Vec<(HTLCSource, PaymentHash)>, Option<msgs::AnnouncementSignatures>), ClosureReason>>
			(&self, height_opt: Option<u32>, f: FN) {
		// Note that we MUST NOT end up calling methods on self.chain_monitor here - we're called
		// during initialization prior to the chain_monitor being fully configured in some cases.
		// See the docs for `ChannelManagerReadArgs` for more.

		let mut failed_channels = Vec::new();
		let mut timed_out_htlcs = Vec::new();
		{
			let mut channel_lock = self.channel_state.lock().unwrap();
			let channel_state = &mut *channel_lock;
			let short_to_id = &mut channel_state.short_to_id;
			let pending_msg_events = &mut channel_state.pending_msg_events;
			channel_state.by_id.retain(|_, channel| {
				let res = f(channel);
				if let Ok((channel_ready_opt, mut timed_out_pending_htlcs, announcement_sigs)) = res {
					for (source, payment_hash) in timed_out_pending_htlcs.drain(..) {
						let (failure_code, data) = self.get_htlc_inbound_temp_fail_err_and_data(0x1000|14 /* expiry_too_soon */, &channel);
						timed_out_htlcs.push((source, payment_hash, HTLCFailReason::Reason {
							failure_code, data,
						}));
					}
					if let Some(channel_ready) = channel_ready_opt {
						send_channel_ready!(short_to_id, pending_msg_events, channel, channel_ready);
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
					if let Some(announcement_sigs) = announcement_sigs {
						log_trace!(self.logger, "Sending announcement_signatures for channel {}", log_bytes!(channel.channel_id()));
						pending_msg_events.push(events::MessageSendEvent::SendAnnouncementSignatures {
							node_id: channel.get_counterparty_node_id(),
							msg: announcement_sigs,
						});
						if let Some(height) = height_opt {
							if let Some(announcement) = channel.get_signed_channel_announcement(self.get_our_node_id(), self.genesis_hash, height) {
								pending_msg_events.push(events::MessageSendEvent::BroadcastChannelAnnouncement {
									msg: announcement,
									// Note that announcement_signatures fails if the channel cannot be announced,
									// so get_channel_update_for_broadcast will never fail by the time we get here.
									update_msg: self.get_channel_update_for_broadcast(channel).unwrap(),
								});
							}
						}
					}
					if channel.is_our_channel_ready() {
						if let Some(real_scid) = channel.get_short_channel_id() {
							// If we sent a 0conf channel_ready, and now have an SCID, we add it
							// to the short_to_id map here. Note that we check whether we can relay
							// using the real SCID at relay-time (i.e. enforce option_scid_alias
							// then), and if the funding tx is ever un-confirmed we force-close the
							// channel, ensuring short_to_id is always consistent.
							let scid_insert = short_to_id.insert(real_scid, channel.channel_id());
							assert!(scid_insert.is_none() || scid_insert.unwrap() == channel.channel_id(),
								"SCIDs should never collide - ensure you weren't behind by a full {} blocks when creating channels",
								fake_scid::MAX_SCID_BLOCKS_FROM_NOW);
						}
					}
				} else if let Err(reason) = res {
					update_maps_on_chan_removal!(self, short_to_id, channel);
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

			if let Some(height) = height_opt {
				channel_state.claimable_htlcs.retain(|payment_hash, (_, htlcs)| {
					htlcs.retain(|htlc| {
						// If height is approaching the number of blocks we think it takes us to get
						// our commitment transaction confirmed before the HTLC expires, plus the
						// number of blocks we generally consider it to take to do a commitment update,
						// just give up on it and fail the HTLC.
						if height >= htlc.cltv_expiry - HTLC_FAIL_BACK_BUFFER {
							let mut htlc_msat_height_data = byte_utils::be64_to_array(htlc.value).to_vec();
							htlc_msat_height_data.extend_from_slice(&byte_utils::be32_to_array(height));
							timed_out_htlcs.push((HTLCSource::PreviousHopData(htlc.prev_hop.clone()), payment_hash.clone(), HTLCFailReason::Reason {
								failure_code: 0x4000 | 15,
								data: htlc_msat_height_data
							}));
							false
						} else { true }
					});
					!htlcs.is_empty() // Only retain this entry if htlcs has at least one entry.
				});
			}
		}

		self.handle_init_event_channel_failures(failed_channels);

		for (source, payment_hash, reason) in timed_out_htlcs.drain(..) {
			self.fail_htlc_backwards_internal(self.channel_state.lock().unwrap(), source, &payment_hash, reason);
		}
	}

	/// Blocks until ChannelManager needs to be persisted or a timeout is reached. It returns a bool
	/// indicating whether persistence is necessary. Only one listener on
	/// `await_persistable_update` or `await_persistable_update_timeout` is guaranteed to be woken
	/// up.
	///
	/// Note that this method is not available with the `no-std` feature.
	#[cfg(any(test, feature = "std"))]
	pub fn await_persistable_update_timeout(&self, max_wait: Duration) -> bool {
		self.persistence_notifier.wait_timeout(max_wait)
	}

	/// Blocks until ChannelManager needs to be persisted. Only one listener on
	/// `await_persistable_update` or `await_persistable_update_timeout` is guaranteed to be woken
	/// up.
	pub fn await_persistable_update(&self) {
		self.persistence_notifier.wait()
	}

	#[cfg(any(test, feature = "_test_utils"))]
	pub fn get_persistence_condvar_value(&self) -> bool {
		let mutcond = &self.persistence_notifier.persistence_lock;
		let &(ref mtx, _) = mutcond;
		let guard = mtx.lock().unwrap();
		*guard
	}

	/// Gets the latest best block which was connected either via the [`chain::Listen`] or
	/// [`chain::Confirm`] interfaces.
	pub fn current_best_block(&self) -> BestBlock {
		self.best_block.read().unwrap().clone()
	}
}

impl<Signer: Sign, M: Deref , T: Deref , K: Deref , F: Deref , L: Deref >
	ChannelMessageHandler for ChannelManager<Signer, M, T, K, F, L>
	where M::Target: chain::Watch<Signer>,
        T::Target: BroadcasterInterface,
        K::Target: KeysInterface<Signer = Signer>,
        F::Target: FeeEstimator,
        L::Target: Logger,
{
	fn handle_open_channel(&self, counterparty_node_id: &PublicKey, their_features: InitFeatures, msg: &msgs::OpenChannel) {
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(&self.total_consistency_lock, &self.persistence_notifier);
		let _ = handle_error!(self, self.internal_open_channel(counterparty_node_id, their_features, msg), *counterparty_node_id);
	}

	fn handle_accept_channel(&self, counterparty_node_id: &PublicKey, their_features: InitFeatures, msg: &msgs::AcceptChannel) {
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(&self.total_consistency_lock, &self.persistence_notifier);
		let _ = handle_error!(self, self.internal_accept_channel(counterparty_node_id, their_features, msg), *counterparty_node_id);
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

	fn handle_shutdown(&self, counterparty_node_id: &PublicKey, their_features: &InitFeatures, msg: &msgs::Shutdown) {
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(&self.total_consistency_lock, &self.persistence_notifier);
		let _ = handle_error!(self, self.internal_shutdown(counterparty_node_id, their_features, msg), *counterparty_node_id);
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

	fn peer_disconnected(&self, counterparty_node_id: &PublicKey, no_connection_possible: bool) {
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(&self.total_consistency_lock, &self.persistence_notifier);
		let mut failed_channels = Vec::new();
		let mut no_channels_remain = true;
		{
			let mut channel_state_lock = self.channel_state.lock().unwrap();
			let channel_state = &mut *channel_state_lock;
			let pending_msg_events = &mut channel_state.pending_msg_events;
			let short_to_id = &mut channel_state.short_to_id;
			log_debug!(self.logger, "Marking channels with {} disconnected and generating channel_updates. We believe we {} make future connections to this peer.",
				log_pubkey!(counterparty_node_id), if no_connection_possible { "cannot" } else { "can" });
			channel_state.by_id.retain(|_, chan| {
				if chan.get_counterparty_node_id() == *counterparty_node_id {
					chan.remove_uncommitted_htlcs_and_mark_paused(&self.logger);
					if chan.is_shutdown() {
						update_maps_on_chan_removal!(self, short_to_id, chan);
						self.issue_channel_close_events(chan, ClosureReason::DisconnectedPeer);
						return false;
					} else {
						no_channels_remain = false;
					}
				}
				true
			});
			pending_msg_events.retain(|msg| {
				match msg {
					&events::MessageSendEvent::SendAcceptChannel { ref node_id, .. } => node_id != counterparty_node_id,
					&events::MessageSendEvent::SendOpenChannel { ref node_id, .. } => node_id != counterparty_node_id,
					&events::MessageSendEvent::SendFundingCreated { ref node_id, .. } => node_id != counterparty_node_id,
					&events::MessageSendEvent::SendFundingSigned { ref node_id, .. } => node_id != counterparty_node_id,
					&events::MessageSendEvent::SendChannelReady { ref node_id, .. } => node_id != counterparty_node_id,
					&events::MessageSendEvent::SendAnnouncementSignatures { ref node_id, .. } => node_id != counterparty_node_id,
					&events::MessageSendEvent::UpdateHTLCs { ref node_id, .. } => node_id != counterparty_node_id,
					&events::MessageSendEvent::SendRevokeAndACK { ref node_id, .. } => node_id != counterparty_node_id,
					&events::MessageSendEvent::SendClosingSigned { ref node_id, .. } => node_id != counterparty_node_id,
					&events::MessageSendEvent::SendShutdown { ref node_id, .. } => node_id != counterparty_node_id,
					&events::MessageSendEvent::SendChannelReestablish { ref node_id, .. } => node_id != counterparty_node_id,
					&events::MessageSendEvent::BroadcastChannelAnnouncement { .. } => true,
					&events::MessageSendEvent::BroadcastNodeAnnouncement { .. } => true,
					&events::MessageSendEvent::BroadcastChannelUpdate { .. } => true,
					&events::MessageSendEvent::SendChannelUpdate { ref node_id, .. } => node_id != counterparty_node_id,
					&events::MessageSendEvent::HandleError { ref node_id, .. } => node_id != counterparty_node_id,
					&events::MessageSendEvent::SendChannelRangeQuery { .. } => false,
					&events::MessageSendEvent::SendShortIdsQuery { .. } => false,
					&events::MessageSendEvent::SendReplyChannelRange { .. } => false,
					&events::MessageSendEvent::SendGossipTimestampFilter { .. } => false,
				}
			});
		}
		if no_channels_remain {
			self.per_peer_state.write().unwrap().remove(counterparty_node_id);
		}

		for failure in failed_channels.drain(..) {
			self.finish_force_close_channel(failure);
		}
	}

	fn peer_connected(&self, counterparty_node_id: &PublicKey, init_msg: &msgs::Init) {
		log_debug!(self.logger, "Generating channel_reestablish events for {}", log_pubkey!(counterparty_node_id));

		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(&self.total_consistency_lock, &self.persistence_notifier);

		{
			let mut peer_state_lock = self.per_peer_state.write().unwrap();
			match peer_state_lock.entry(counterparty_node_id.clone()) {
				hash_map::Entry::Vacant(e) => {
					e.insert(Mutex::new(PeerState {
						latest_features: init_msg.features.clone(),
					}));
				},
				hash_map::Entry::Occupied(e) => {
					e.get().lock().unwrap().latest_features = init_msg.features.clone();
				},
			}
		}

		let mut channel_state_lock = self.channel_state.lock().unwrap();
		let channel_state = &mut *channel_state_lock;
		let pending_msg_events = &mut channel_state.pending_msg_events;
		channel_state.by_id.retain(|_, chan| {
			if chan.get_counterparty_node_id() == *counterparty_node_id {
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
			} else { true }
		});
		//TODO: Also re-broadcast announcement_signatures
	}

	fn handle_error(&self, counterparty_node_id: &PublicKey, msg: &msgs::ErrorMessage) {
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(&self.total_consistency_lock, &self.persistence_notifier);

		if msg.channel_id == [0; 32] {
			for chan in self.list_channels() {
				if chan.counterparty.node_id == *counterparty_node_id {
					// Untrusted messages from peer, we throw away the error if id points to a non-existent channel
					let _ = self.force_close_channel_with_peer(&chan.channel_id, counterparty_node_id, Some(&msg.data));
				}
			}
		} else {
			{
				// First check if we can advance the channel type and try again.
				let mut channel_state = self.channel_state.lock().unwrap();
				if let Some(chan) = channel_state.by_id.get_mut(&msg.channel_id) {
					if chan.get_counterparty_node_id() != *counterparty_node_id {
						return;
					}
					if let Ok(msg) = chan.maybe_handle_error_without_close(self.genesis_hash) {
						channel_state.pending_msg_events.push(events::MessageSendEvent::SendOpenChannel {
							node_id: *counterparty_node_id,
							msg,
						});
						return;
					}
				}
			}

			// Untrusted messages from peer, we throw away the error if id points to a non-existent channel
			let _ = self.force_close_channel_with_peer(&msg.channel_id, counterparty_node_id, Some(&msg.data));
		}
	}
}

/// Used to signal to the ChannelManager persister that the manager needs to be re-persisted to
/// disk/backups, through `await_persistable_update_timeout` and `await_persistable_update`.
struct PersistenceNotifier {
	/// Users won't access the persistence_lock directly, but rather wait on its bool using
	/// `wait_timeout` and `wait`.
	persistence_lock: (Mutex<bool>, Condvar),
}

impl PersistenceNotifier {
	fn new() -> Self {
		Self {
			persistence_lock: (Mutex::new(false), Condvar::new()),
		}
	}

	fn wait(&self) {
		loop {
			let &(ref mtx, ref cvar) = &self.persistence_lock;
			let mut guard = mtx.lock().unwrap();
			if *guard {
				*guard = false;
				return;
			}
			guard = cvar.wait(guard).unwrap();
			let result = *guard;
			if result {
				*guard = false;
				return
			}
		}
	}

	#[cfg(any(test, feature = "std"))]
	fn wait_timeout(&self, max_wait: Duration) -> bool {
		let current_time = Instant::now();
		loop {
			let &(ref mtx, ref cvar) = &self.persistence_lock;
			let mut guard = mtx.lock().unwrap();
			if *guard {
				*guard = false;
				return true;
			}
			guard = cvar.wait_timeout(guard, max_wait).unwrap().0;
			// Due to spurious wakeups that can happen on `wait_timeout`, here we need to check if the
			// desired wait time has actually passed, and if not then restart the loop with a reduced wait
			// time. Note that this logic can be highly simplified through the use of
			// `Condvar::wait_while` and `Condvar::wait_timeout_while`, if and when our MSRV is raised to
			// 1.42.0.
			let elapsed = current_time.elapsed();
			let result = *guard;
			if result || elapsed >= max_wait {
				*guard = false;
				return result;
			}
			match max_wait.checked_sub(elapsed) {
				None => return result,
				Some(_) => continue
			}
		}
	}

	// Signal to the ChannelManager persister that there are updates necessitating persisting to disk.
	fn notify(&self) {
		let &(ref persist_mtx, ref cnd) = &self.persistence_lock;
		let mut persistence_lock = persist_mtx.lock().unwrap();
		*persistence_lock = true;
		mem::drop(persistence_lock);
		cnd.notify_all();
	}
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

impl_writeable_tlv_based!(ChannelDetails, {
	(1, inbound_scid_alias, option),
	(2, channel_id, required),
	(3, channel_type, option),
	(4, counterparty, required),
	(5, outbound_scid_alias, option),
	(6, funding_txo, option),
	(8, short_channel_id, option),
	(10, channel_value_satoshis, required),
	(12, unspendable_punishment_reserve, option),
	(14, user_channel_id, required),
	(16, balance_msat, required),
	(18, outbound_capacity_msat, required),
	// Note that by the time we get past the required read above, outbound_capacity_msat will be
	// filled in, so we can safely unwrap it here.
	(19, next_outbound_htlc_limit_msat, (default_value, outbound_capacity_msat.0.unwrap())),
	(20, inbound_capacity_msat, required),
	(22, confirmations_required, option),
	(24, force_close_spend_delay, option),
	(26, is_outbound, required),
	(28, is_channel_ready, required),
	(30, is_usable, required),
	(32, is_public, required),
	(33, inbound_htlc_minimum_msat, option),
	(35, inbound_htlc_maximum_msat, option),
});

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
	(6, amt_to_forward, required),
	(8, outgoing_cltv_value, required)
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
		let mut prev_hop = ::util::ser::OptionDeserWrapper(None);
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
				let mut session_priv: ::util::ser::OptionDeserWrapper<SecretKey> = ::util::ser::OptionDeserWrapper(None);
				let mut first_hop_htlc_msat: u64 = 0;
				let mut path = Some(Vec::new());
				let mut payment_id = None;
				let mut payment_secret = None;
				let mut payment_params = None;
				read_tlv_fields!(reader, {
					(0, session_priv, required),
					(1, payment_id, option),
					(2, first_hop_htlc_msat, required),
					(3, payment_secret, option),
					(4, path, vec_type),
					(5, payment_params, option),
				});
				if payment_id.is_none() {
					// For backwards compat, if there was no payment_id written, use the session_priv bytes
					// instead.
					payment_id = Some(PaymentId(*session_priv.0.unwrap().as_ref()));
				}
				Ok(HTLCSource::OutboundRoute {
					session_priv: session_priv.0.unwrap(),
					first_hop_htlc_msat: first_hop_htlc_msat,
					path: path.unwrap(),
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
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::io::Error> {
		match self {
			HTLCSource::OutboundRoute { ref session_priv, ref first_hop_htlc_msat, ref path, payment_id, payment_secret, payment_params } => {
				0u8.write(writer)?;
				let payment_id_opt = Some(payment_id);
				write_tlv_fields!(writer, {
					(0, session_priv, required),
					(1, payment_id_opt, option),
					(2, first_hop_htlc_msat, required),
					(3, payment_secret, option),
					(4, path, vec_type),
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

impl_writeable_tlv_based_enum!(HTLCFailReason,
	(0, LightningError) => {
		(0, err, required),
	},
	(1, Reason) => {
		(0, failure_code, required),
		(2, data, vec_type),
	},
;);

impl_writeable_tlv_based_enum!(HTLCForwardInfo,
	(0, AddHTLC) => {
		(0, forward_info, required),
		(2, prev_short_channel_id, required),
		(4, prev_htlc_id, required),
		(6, prev_funding_outpoint, required),
	},
	(1, FailHTLC) => {
		(0, htlc_id, required),
		(2, err_packet, required),
	},
;);

impl_writeable_tlv_based!(PendingInboundPayment, {
	(0, payment_secret, required),
	(2, expiry_time, required),
	(4, user_payment_id, required),
	(6, payment_preimage, required),
	(8, min_value_msat, required),
});

impl_writeable_tlv_based_enum_upgradable!(PendingOutboundPayment,
	(0, Legacy) => {
		(0, session_privs, required),
	},
	(1, Fulfilled) => {
		(0, session_privs, required),
		(1, payment_hash, option),
	},
	(2, Retryable) => {
		(0, session_privs, required),
		(1, pending_fee_msat, option),
		(2, payment_hash, required),
		(4, payment_secret, option),
		(6, total_msat, required),
		(8, pending_amt_msat, required),
		(10, starting_block_height, required),
	},
	(3, Abandoned) => {
		(0, session_privs, required),
		(2, payment_hash, required),
	},
);

impl<Signer: Sign, M: Deref, T: Deref, K: Deref, F: Deref, L: Deref> Writeable for ChannelManager<Signer, M, T, K, F, L>
	where M::Target: chain::Watch<Signer>,
        T::Target: BroadcasterInterface,
        K::Target: KeysInterface<Signer = Signer>,
        F::Target: FeeEstimator,
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

		let channel_state = self.channel_state.lock().unwrap();
		let mut unfunded_channels = 0;
		for (_, channel) in channel_state.by_id.iter() {
			if !channel.is_funding_initiated() {
				unfunded_channels += 1;
			}
		}
		((channel_state.by_id.len() - unfunded_channels) as u64).write(writer)?;
		for (_, channel) in channel_state.by_id.iter() {
			if channel.is_funding_initiated() {
				channel.write(writer)?;
			}
		}

		(channel_state.forward_htlcs.len() as u64).write(writer)?;
		for (short_channel_id, pending_forwards) in channel_state.forward_htlcs.iter() {
			short_channel_id.write(writer)?;
			(pending_forwards.len() as u64).write(writer)?;
			for forward in pending_forwards {
				forward.write(writer)?;
			}
		}

		let mut htlc_purposes: Vec<&events::PaymentPurpose> = Vec::new();
		(channel_state.claimable_htlcs.len() as u64).write(writer)?;
		for (payment_hash, (purpose, previous_hops)) in channel_state.claimable_htlcs.iter() {
			payment_hash.write(writer)?;
			(previous_hops.len() as u64).write(writer)?;
			for htlc in previous_hops.iter() {
				htlc.write(writer)?;
			}
			htlc_purposes.push(purpose);
		}

		let per_peer_state = self.per_peer_state.write().unwrap();
		(per_peer_state.len() as u64).write(writer)?;
		for (peer_pubkey, peer_state_mutex) in per_peer_state.iter() {
			peer_pubkey.write(writer)?;
			let peer_state = peer_state_mutex.lock().unwrap();
			peer_state.latest_features.write(writer)?;
		}

		let pending_inbound_payments = self.pending_inbound_payments.lock().unwrap();
		let pending_outbound_payments = self.pending_outbound_payments.lock().unwrap();
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

		(self.last_node_announcement_serial.load(Ordering::Acquire) as u32).write(writer)?;
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
		write_tlv_fields!(writer, {
			(1, pending_outbound_payments_no_retry, required),
			(3, pending_outbound_payments, required),
			(5, self.our_network_pubkey, required),
			(7, self.fake_scid_rand_bytes, required),
			(9, htlc_purposes, vec_type),
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
pub struct ChannelManagerReadArgs<'a, Signer: 'a + Sign, M: Deref, T: Deref, K: Deref, F: Deref, L: Deref>
	where M::Target: chain::Watch<Signer>,
        T::Target: BroadcasterInterface,
        K::Target: KeysInterface<Signer = Signer>,
        F::Target: FeeEstimator,
        L::Target: Logger,
{
	/// The keys provider which will give us relevant keys. Some keys will be loaded during
	/// deserialization and KeysInterface::read_chan_signer will be used to read per-Channel
	/// signing data.
	pub keys_manager: K,

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
	pub channel_monitors: HashMap<OutPoint, &'a mut ChannelMonitor<Signer>>,
}

impl<'a, Signer: 'a + Sign, M: Deref, T: Deref, K: Deref, F: Deref, L: Deref>
		ChannelManagerReadArgs<'a, Signer, M, T, K, F, L>
	where M::Target: chain::Watch<Signer>,
		T::Target: BroadcasterInterface,
		K::Target: KeysInterface<Signer = Signer>,
		F::Target: FeeEstimator,
		L::Target: Logger,
	{
	/// Simple utility function to create a ChannelManagerReadArgs which creates the monitor
	/// HashMap for you. This is primarily useful for C bindings where it is not practical to
	/// populate a HashMap directly from C.
	pub fn new(keys_manager: K, fee_estimator: F, chain_monitor: M, tx_broadcaster: T, logger: L, default_config: UserConfig,
			mut channel_monitors: Vec<&'a mut ChannelMonitor<Signer>>) -> Self {
		Self {
			keys_manager, fee_estimator, chain_monitor, tx_broadcaster, logger, default_config,
			channel_monitors: channel_monitors.drain(..).map(|monitor| { (monitor.get_funding_txo().0, monitor) }).collect()
		}
	}
}

// Implement ReadableArgs for an Arc'd ChannelManager to make it a bit easier to work with the
// SipmleArcChannelManager type:
impl<'a, Signer: Sign, M: Deref, T: Deref, K: Deref, F: Deref, L: Deref>
	ReadableArgs<ChannelManagerReadArgs<'a, Signer, M, T, K, F, L>> for (BlockHash, Arc<ChannelManager<Signer, M, T, K, F, L>>)
	where M::Target: chain::Watch<Signer>,
        T::Target: BroadcasterInterface,
        K::Target: KeysInterface<Signer = Signer>,
        F::Target: FeeEstimator,
        L::Target: Logger,
{
	fn read<R: io::Read>(reader: &mut R, args: ChannelManagerReadArgs<'a, Signer, M, T, K, F, L>) -> Result<Self, DecodeError> {
		let (blockhash, chan_manager) = <(BlockHash, ChannelManager<Signer, M, T, K, F, L>)>::read(reader, args)?;
		Ok((blockhash, Arc::new(chan_manager)))
	}
}

impl<'a, Signer: Sign, M: Deref, T: Deref, K: Deref, F: Deref, L: Deref>
	ReadableArgs<ChannelManagerReadArgs<'a, Signer, M, T, K, F, L>> for (BlockHash, ChannelManager<Signer, M, T, K, F, L>)
	where M::Target: chain::Watch<Signer>,
        T::Target: BroadcasterInterface,
        K::Target: KeysInterface<Signer = Signer>,
        F::Target: FeeEstimator,
        L::Target: Logger,
{
	fn read<R: io::Read>(reader: &mut R, mut args: ChannelManagerReadArgs<'a, Signer, M, T, K, F, L>) -> Result<Self, DecodeError> {
		let _ver = read_ver_prefix!(reader, SERIALIZATION_VERSION);

		let genesis_hash: BlockHash = Readable::read(reader)?;
		let best_block_height: u32 = Readable::read(reader)?;
		let best_block_hash: BlockHash = Readable::read(reader)?;

		let mut failed_htlcs = Vec::new();

		let channel_count: u64 = Readable::read(reader)?;
		let mut funding_txo_set = HashSet::with_capacity(cmp::min(channel_count as usize, 128));
		let mut by_id = HashMap::with_capacity(cmp::min(channel_count as usize, 128));
		let mut short_to_id = HashMap::with_capacity(cmp::min(channel_count as usize, 128));
		let mut channel_closures = Vec::new();
		for _ in 0..channel_count {
			let mut channel: Channel<Signer> = Channel::read(reader, (&args.keys_manager, best_block_height))?;
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
				} else {
					log_info!(args.logger, "Successfully loaded channel {}", log_bytes!(channel.channel_id()));
					if let Some(short_channel_id) = channel.get_short_channel_id() {
						short_to_id.insert(short_channel_id, channel.channel_id());
					}
					by_id.insert(channel.channel_id(), channel);
				}
			} else {
				log_error!(args.logger, "Missing ChannelMonitor for channel {} needed by ChannelManager.", log_bytes!(channel.channel_id()));
				log_error!(args.logger, " The chain::Watch API *requires* that monitors are persisted durably before returning,");
				log_error!(args.logger, " client applications must ensure that ChannelMonitor data is always available and the latest to avoid funds loss!");
				log_error!(args.logger, " Without the ChannelMonitor we cannot continue without risking funds.");
				log_error!(args.logger, " Please ensure the chain::Watch API requirements are met and file a bug report at https://github.com/lightningdevkit/rust-lightning");
				return Err(DecodeError::InvalidValue);
			}
		}

		for (ref funding_txo, ref mut monitor) in args.channel_monitors.iter_mut() {
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
		let mut per_peer_state = HashMap::with_capacity(cmp::min(peer_count as usize, MAX_ALLOC_SIZE/mem::size_of::<(PublicKey, Mutex<PeerState>)>()));
		for _ in 0..peer_count {
			let peer_pubkey = Readable::read(reader)?;
			let peer_state = PeerState {
				latest_features: Readable::read(reader)?,
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
		if forward_htlcs_count > 0 {
			// If we have pending HTLCs to forward, assume we either dropped a
			// `PendingHTLCsForwardable` or the user received it but never processed it as they
			// shut down before the timer hit. Either way, set the time_forwardable to a small
			// constant as enough time has likely passed that we should simply handle the forwards
			// now, or at least after the user gets a chance to reconnect to our peers.
			pending_events_read.push(events::Event::PendingHTLCsForwardable {
				time_forwardable: Duration::from_secs(2),
			});
		}

		let background_event_count: u64 = Readable::read(reader)?;
		let mut pending_background_events_read: Vec<BackgroundEvent> = Vec::with_capacity(cmp::min(background_event_count as usize, MAX_ALLOC_SIZE/mem::size_of::<BackgroundEvent>()));
		for _ in 0..background_event_count {
			match <u8 as Readable>::read(reader)? {
				0 => pending_background_events_read.push(BackgroundEvent::ClosingMonitorUpdate((Readable::read(reader)?, Readable::read(reader)?))),
				_ => return Err(DecodeError::InvalidValue),
			}
		}

		let last_node_announcement_serial: u32 = Readable::read(reader)?;
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
		let mut received_network_pubkey: Option<PublicKey> = None;
		let mut fake_scid_rand_bytes: Option<[u8; 32]> = None;
		let mut claimable_htlc_purposes = None;
		read_tlv_fields!(reader, {
			(1, pending_outbound_payments_no_retry, option),
			(3, pending_outbound_payments, option),
			(5, received_network_pubkey, option),
			(7, fake_scid_rand_bytes, option),
			(9, claimable_htlc_purposes, vec_type),
		});
		if fake_scid_rand_bytes.is_none() {
			fake_scid_rand_bytes = Some(args.keys_manager.get_secure_random_bytes());
		}

		if pending_outbound_payments.is_none() && pending_outbound_payments_no_retry.is_none() {
			pending_outbound_payments = Some(pending_outbound_payments_compat);
		} else if pending_outbound_payments.is_none() {
			let mut outbounds = HashMap::new();
			for (id, session_privs) in pending_outbound_payments_no_retry.unwrap().drain() {
				outbounds.insert(id, PendingOutboundPayment::Legacy { session_privs });
			}
			pending_outbound_payments = Some(outbounds);
		} else {
			// If we're tracking pending payments, ensure we haven't lost any by looking at the
			// ChannelMonitor data for any channels for which we do not have authorative state
			// (i.e. those for which we just force-closed above or we otherwise don't have a
			// corresponding `Channel` at all).
			// This avoids several edge-cases where we would otherwise "forget" about pending
			// payments which are still in-flight via their on-chain state.
			// We only rebuild the pending payments map if we were most recently serialized by
			// 0.0.102+
			for (_, monitor) in args.channel_monitors.iter() {
				if by_id.get(&monitor.get_funding_txo().0.to_channel_id()).is_none() {
					for (htlc_source, htlc) in monitor.get_pending_outbound_htlcs() {
						if let HTLCSource::OutboundRoute { payment_id, session_priv, path, payment_secret, .. } = htlc_source {
							if path.is_empty() {
								log_error!(args.logger, "Got an empty path for a pending payment");
								return Err(DecodeError::InvalidValue);
							}
							let path_amt = path.last().unwrap().fee_msat;
							let mut session_priv_bytes = [0; 32];
							session_priv_bytes[..].copy_from_slice(&session_priv[..]);
							match pending_outbound_payments.as_mut().unwrap().entry(payment_id) {
								hash_map::Entry::Occupied(mut entry) => {
									let newly_added = entry.get_mut().insert(session_priv_bytes, &path);
									log_info!(args.logger, "{} a pending payment path for {} msat for session priv {} on an existing pending payment with payment hash {}",
										if newly_added { "Added" } else { "Had" }, path_amt, log_bytes!(session_priv_bytes), log_bytes!(htlc.payment_hash.0));
								},
								hash_map::Entry::Vacant(entry) => {
									let path_fee = path.get_path_fees();
									entry.insert(PendingOutboundPayment::Retryable {
										session_privs: [session_priv_bytes].iter().map(|a| *a).collect(),
										payment_hash: htlc.payment_hash,
										payment_secret,
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
				}
			}
		}

		let inbound_pmt_key_material = args.keys_manager.get_inbound_payment_key_material();
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
										Ok(payment_preimage) => payment_preimage,
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
		secp_ctx.seeded_randomize(&args.keys_manager.get_secure_random_bytes());

		if !channel_closures.is_empty() {
			pending_events_read.append(&mut channel_closures);
		}

		let our_network_key = match args.keys_manager.get_node_secret(Recipient::Node) {
			Ok(key) => key,
			Err(()) => return Err(DecodeError::InvalidValue)
		};
		let our_network_pubkey = PublicKey::from_secret_key(&secp_ctx, &our_network_key);
		if let Some(network_pubkey) = received_network_pubkey {
			if network_pubkey != our_network_pubkey {
				log_error!(args.logger, "Key that was generated does not match the existing key.");
				return Err(DecodeError::InvalidValue);
			}
		}

		let mut outbound_scid_aliases = HashSet::new();
		for (chan_id, chan) in by_id.iter_mut() {
			if chan.outbound_scid_alias() == 0 {
				let mut outbound_scid_alias;
				loop {
					outbound_scid_alias = fake_scid::Namespace::OutboundAlias
						.get_fake_scid(best_block_height, &genesis_hash, fake_scid_rand_bytes.as_ref().unwrap(), &args.keys_manager);
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
				if short_to_id.insert(chan.outbound_scid_alias(), *chan_id).is_some() {
					// Note that in rare cases its possible to hit this while reading an older
					// channel if we just happened to pick a colliding outbound alias above.
					log_error!(args.logger, "Got duplicate outbound SCID alias; {}", chan.outbound_scid_alias());
					return Err(DecodeError::InvalidValue);
				}
			}
		}

		for (_, monitor) in args.channel_monitors.iter() {
			for (payment_hash, payment_preimage) in monitor.get_stored_preimages() {
				if let Some((payment_purpose, claimable_htlcs)) = claimable_htlcs.remove(&payment_hash) {
					log_info!(args.logger, "Re-claiming HTLCs with payment hash {} as we've released the preimage to a ChannelMonitor!", log_bytes!(payment_hash.0));
					let mut claimable_amt_msat = 0;
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
						if let Some(channel) = by_id.get_mut(&previous_channel_id) {
							channel.claim_htlc_while_disconnected_dropping_mon_update(claimable_htlc.prev_hop.htlc_id, payment_preimage, &args.logger);
						}
						if let Some(previous_hop_monitor) = args.channel_monitors.get(&claimable_htlc.prev_hop.outpoint) {
							previous_hop_monitor.provide_payment_preimage(&payment_hash, &payment_preimage, &args.tx_broadcaster, &args.fee_estimator, &args.logger);
						}
					}
					pending_events_read.push(events::Event::PaymentClaimed {
						payment_hash,
						purpose: payment_purpose,
						amount_msat: claimable_amt_msat,
					});
				}
			}
		}

		let channel_manager = ChannelManager {
			genesis_hash,
			fee_estimator: args.fee_estimator,
			chain_monitor: args.chain_monitor,
			tx_broadcaster: args.tx_broadcaster,

			best_block: RwLock::new(BestBlock::new(best_block_hash, best_block_height)),

			channel_state: Mutex::new(ChannelHolder {
				by_id,
				short_to_id,
				forward_htlcs,
				claimable_htlcs,
				pending_msg_events: Vec::new(),
			}),
			inbound_payment_key: expanded_inbound_key,
			pending_inbound_payments: Mutex::new(pending_inbound_payments),
			pending_outbound_payments: Mutex::new(pending_outbound_payments.unwrap()),

			outbound_scid_aliases: Mutex::new(outbound_scid_aliases),
			fake_scid_rand_bytes: fake_scid_rand_bytes.unwrap(),

			our_network_key,
			our_network_pubkey,
			secp_ctx,

			last_node_announcement_serial: AtomicUsize::new(last_node_announcement_serial as usize),
			highest_seen_timestamp: AtomicUsize::new(highest_seen_timestamp as usize),

			per_peer_state: RwLock::new(per_peer_state),

			pending_events: Mutex::new(pending_events_read),
			pending_background_events: Mutex::new(pending_background_events_read),
			total_consistency_lock: RwLock::new(()),
			persistence_notifier: PersistenceNotifier::new(),

			keys_manager: args.keys_manager,
			logger: args.logger,
			default_configuration: args.default_config,
		};

		for htlc_source in failed_htlcs.drain(..) {
			channel_manager.fail_htlc_backwards_internal(channel_manager.channel_state.lock().unwrap(), htlc_source.0, &htlc_source.1, HTLCFailReason::Reason { failure_code: 0x4000 | 8, data: Vec::new() });
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
	use core::time::Duration;
	use core::sync::atomic::Ordering;
	use ln::{PaymentPreimage, PaymentHash, PaymentSecret};
	use ln::channelmanager::{PaymentId, PaymentSendFailure};
	use ln::channelmanager::inbound_payment;
	use ln::features::InitFeatures;
	use ln::functional_test_utils::*;
	use ln::msgs;
	use ln::msgs::ChannelMessageHandler;
	use routing::router::{PaymentParameters, RouteParameters, find_route};
	use util::errors::APIError;
	use util::events::{Event, MessageSendEvent, MessageSendEventsProvider};
	use util::test_utils;
	use chain::keysinterface::KeysInterface;

	#[cfg(feature = "std")]
	#[test]
	fn test_wait_timeout() {
		use ln::channelmanager::PersistenceNotifier;
		use sync::Arc;
		use core::sync::atomic::AtomicBool;
		use std::thread;

		let persistence_notifier = Arc::new(PersistenceNotifier::new());
		let thread_notifier = Arc::clone(&persistence_notifier);

		let exit_thread = Arc::new(AtomicBool::new(false));
		let exit_thread_clone = exit_thread.clone();
		thread::spawn(move || {
			loop {
				let &(ref persist_mtx, ref cnd) = &thread_notifier.persistence_lock;
				let mut persistence_lock = persist_mtx.lock().unwrap();
				*persistence_lock = true;
				cnd.notify_all();

				if exit_thread_clone.load(Ordering::SeqCst) {
					break
				}
			}
		});

		// Check that we can block indefinitely until updates are available.
		let _ = persistence_notifier.wait();

		// Check that the PersistenceNotifier will return after the given duration if updates are
		// available.
		loop {
			if persistence_notifier.wait_timeout(Duration::from_millis(100)) {
				break
			}
		}

		exit_thread.store(true, Ordering::SeqCst);

		// Check that the PersistenceNotifier will return after the given duration even if no updates
		// are available.
		loop {
			if !persistence_notifier.wait_timeout(Duration::from_millis(100)) {
				break
			}
		}
	}

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

		let mut chan = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());

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
		create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());

		// First, send a partial MPP payment.
		let (route, our_payment_hash, payment_preimage, payment_secret) = get_route_and_payment_hash!(&nodes[0], nodes[1], 100_000);
		let payment_id = PaymentId([42; 32]);
		// Use the utility function send_payment_along_path to send the payment with MPP data which
		// indicates there are more HTLCs coming.
		let cur_height = CHAN_CONFIRM_DEPTH + 1; // route_payment calls send_payment, which adds 1 to the current height. So we do the same here to match.
		nodes[0].node.send_payment_along_path(&route.paths[0], &route.payment_params, &our_payment_hash, &Some(payment_secret), 200_000, cur_height, payment_id, &None).unwrap();
		check_added_monitors!(nodes[0], 1);
		let mut events = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		pass_along_path(&nodes[0], &[&nodes[1]], 200_000, our_payment_hash, Some(payment_secret), events.drain(..).next().unwrap(), false, None);

		// Next, send a keysend payment with the same payment_hash and make sure it fails.
		nodes[0].node.send_spontaneous_payment(&route, Some(payment_preimage)).unwrap();
		check_added_monitors!(nodes[0], 1);
		let mut events = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		let ev = events.drain(..).next().unwrap();
		let payment_event = SendEvent::from_event(ev);
		nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &payment_event.msgs[0]);
		check_added_monitors!(nodes[1], 0);
		commitment_signed_dance!(nodes[1], nodes[0], payment_event.commitment_msg, false);
		expect_pending_htlcs_forwardable!(nodes[1]);
		expect_pending_htlcs_forwardable!(nodes[1]);
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
		nodes[0].node.send_payment_along_path(&route.paths[0], &route.payment_params, &our_payment_hash, &Some(payment_secret), 200_000, cur_height, payment_id, &None).unwrap();
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
		create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());
		let scorer = test_utils::TestScorer::with_penalty(0);
		let random_seed_bytes = chanmon_cfgs[1].keys_manager.get_secure_random_bytes();

		// To start (1), send a regular payment but don't claim it.
		let expected_route = [&nodes[1]];
		let (payment_preimage, payment_hash, _) = route_payment(&nodes[0], &expected_route, 100_000);

		// Next, attempt a keysend payment and make sure it fails.
		let route_params = RouteParameters {
			payment_params: PaymentParameters::for_keysend(expected_route.last().unwrap().node.get_our_node_id()),
			final_value_msat: 100_000,
			final_cltv_expiry_delta: TEST_FINAL_CLTV,
		};
		let route = find_route(
			&nodes[0].node.get_our_node_id(), &route_params, nodes[0].network_graph, None,
			nodes[0].logger, &scorer, &random_seed_bytes
		).unwrap();
		nodes[0].node.send_spontaneous_payment(&route, Some(payment_preimage)).unwrap();
		check_added_monitors!(nodes[0], 1);
		let mut events = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		let ev = events.drain(..).next().unwrap();
		let payment_event = SendEvent::from_event(ev);
		nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &payment_event.msgs[0]);
		check_added_monitors!(nodes[1], 0);
		commitment_signed_dance!(nodes[1], nodes[0], payment_event.commitment_msg, false);
		expect_pending_htlcs_forwardable!(nodes[1]);
		expect_pending_htlcs_forwardable!(nodes[1]);
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
			&nodes[0].node.get_our_node_id(), &route_params, nodes[0].network_graph, None,
			nodes[0].logger, &scorer, &random_seed_bytes
		).unwrap();
		let (payment_hash, _) = nodes[0].node.send_spontaneous_payment(&route, Some(payment_preimage)).unwrap();
		check_added_monitors!(nodes[0], 1);
		let mut events = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		let event = events.pop().unwrap();
		let path = vec![&nodes[1]];
		pass_along_path(&nodes[0], &path, 100_000, payment_hash, None, event, true, Some(payment_preimage));

		// Next, attempt a regular payment and make sure it fails.
		let payment_secret = PaymentSecret([43; 32]);
		nodes[0].node.send_payment(&route, payment_hash, &Some(payment_secret)).unwrap();
		check_added_monitors!(nodes[0], 1);
		let mut events = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		let ev = events.drain(..).next().unwrap();
		let payment_event = SendEvent::from_event(ev);
		nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &payment_event.msgs[0]);
		check_added_monitors!(nodes[1], 0);
		commitment_signed_dance!(nodes[1], nodes[0], payment_event.commitment_msg, false);
		expect_pending_htlcs_forwardable!(nodes[1]);
		expect_pending_htlcs_forwardable!(nodes[1]);
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
		nodes[0].node.peer_connected(&payee_pubkey, &msgs::Init { features: InitFeatures::known(), remote_network_address: None });
		nodes[1].node.peer_connected(&payer_pubkey, &msgs::Init { features: InitFeatures::known(), remote_network_address: None });

		let _chan = create_chan_between_nodes(&nodes[0], &nodes[1], InitFeatures::known(), InitFeatures::known());
		let route_params = RouteParameters {
			payment_params: PaymentParameters::for_keysend(payee_pubkey),
			final_value_msat: 10000,
			final_cltv_expiry_delta: 40,
		};
		let network_graph = nodes[0].network_graph;
		let first_hops = nodes[0].node.list_usable_channels();
		let scorer = test_utils::TestScorer::with_penalty(0);
		let random_seed_bytes = chanmon_cfgs[1].keys_manager.get_secure_random_bytes();
		let route = find_route(
			&payer_pubkey, &route_params, network_graph, Some(&first_hops.iter().collect::<Vec<_>>()),
			nodes[0].logger, &scorer, &random_seed_bytes
		).unwrap();

		let test_preimage = PaymentPreimage([42; 32]);
		let mismatch_payment_hash = PaymentHash([43; 32]);
		let _ = nodes[0].node.send_payment_internal(&route, mismatch_payment_hash, &None, Some(test_preimage), None, None).unwrap();
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
		nodes[0].node.peer_connected(&payee_pubkey, &msgs::Init { features: InitFeatures::known(), remote_network_address: None });
		nodes[1].node.peer_connected(&payer_pubkey, &msgs::Init { features: InitFeatures::known(), remote_network_address: None });

		let _chan = create_chan_between_nodes(&nodes[0], &nodes[1], InitFeatures::known(), InitFeatures::known());
		let route_params = RouteParameters {
			payment_params: PaymentParameters::for_keysend(payee_pubkey),
			final_value_msat: 10000,
			final_cltv_expiry_delta: 40,
		};
		let network_graph = nodes[0].network_graph;
		let first_hops = nodes[0].node.list_usable_channels();
		let scorer = test_utils::TestScorer::with_penalty(0);
		let random_seed_bytes = chanmon_cfgs[1].keys_manager.get_secure_random_bytes();
		let route = find_route(
			&payer_pubkey, &route_params, network_graph, Some(&first_hops.iter().collect::<Vec<_>>()),
			nodes[0].logger, &scorer, &random_seed_bytes
		).unwrap();

		let test_preimage = PaymentPreimage([42; 32]);
		let test_secret = PaymentSecret([43; 32]);
		let payment_hash = PaymentHash(Sha256::hash(&test_preimage.0).into_inner());
		let _ = nodes[0].node.send_payment_internal(&route, payment_hash, &Some(test_secret), Some(test_preimage), None, None).unwrap();
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

		let chan_1_id = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known()).0.contents.short_channel_id;
		let chan_2_id = create_announced_chan_between_nodes(&nodes, 0, 2, InitFeatures::known(), InitFeatures::known()).0.contents.short_channel_id;
		let chan_3_id = create_announced_chan_between_nodes(&nodes, 1, 3, InitFeatures::known(), InitFeatures::known()).0.contents.short_channel_id;
		let chan_4_id = create_announced_chan_between_nodes(&nodes, 2, 3, InitFeatures::known(), InitFeatures::known()).0.contents.short_channel_id;

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

		match nodes[0].node.send_payment(&route, payment_hash, &None).unwrap_err() {
			PaymentSendFailure::ParameterError(APIError::APIMisuseError { ref err }) => {
				assert!(regex::Regex::new(r"Payment secret is required for multi-path payments").unwrap().is_match(err))			},
			_ => panic!("unexpected error")
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
}

#[cfg(all(any(test, feature = "_test_utils"), feature = "_bench_unstable"))]
pub mod bench {
	use chain::Listen;
	use chain::chainmonitor::{ChainMonitor, Persist};
	use chain::keysinterface::{KeysManager, KeysInterface, InMemorySigner};
	use ln::channelmanager::{BestBlock, ChainParameters, ChannelManager, PaymentHash, PaymentPreimage};
	use ln::features::{InitFeatures, InvoiceFeatures};
	use ln::functional_test_utils::*;
	use ln::msgs::{ChannelMessageHandler, Init};
	use routing::network_graph::NetworkGraph;
	use routing::router::{PaymentParameters, get_route};
	use util::test_utils;
	use util::config::UserConfig;
	use util::events::{Event, MessageSendEvent, MessageSendEventsProvider};

	use bitcoin::hashes::Hash;
	use bitcoin::hashes::sha256::Hash as Sha256;
	use bitcoin::{Block, BlockHeader, Transaction, TxOut};

	use sync::{Arc, Mutex};

	use test::Bencher;

	struct NodeHolder<'a, P: Persist<InMemorySigner>> {
		node: &'a ChannelManager<InMemorySigner,
			&'a ChainMonitor<InMemorySigner, &'a test_utils::TestChainSource,
				&'a test_utils::TestBroadcaster, &'a test_utils::TestFeeEstimator,
				&'a test_utils::TestLogger, &'a P>,
			&'a test_utils::TestBroadcaster, &'a KeysManager,
			&'a test_utils::TestFeeEstimator, &'a test_utils::TestLogger>
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
		let genesis_hash = bitcoin::blockdata::constants::genesis_block(network).header.block_hash();

		let tx_broadcaster = test_utils::TestBroadcaster{txn_broadcasted: Mutex::new(Vec::new()), blocks: Arc::new(Mutex::new(Vec::new()))};
		let fee_estimator = test_utils::TestFeeEstimator { sat_per_kw: Mutex::new(253) };

		let mut config: UserConfig = Default::default();
		config.own_channel_config.minimum_depth = 1;

		let logger_a = test_utils::TestLogger::with_id("node a".to_owned());
		let chain_monitor_a = ChainMonitor::new(None, &tx_broadcaster, &logger_a, &fee_estimator, &persister_a);
		let seed_a = [1u8; 32];
		let keys_manager_a = KeysManager::new(&seed_a, 42, 42);
		let node_a = ChannelManager::new(&fee_estimator, &chain_monitor_a, &tx_broadcaster, &logger_a, &keys_manager_a, config.clone(), ChainParameters {
			network,
			best_block: BestBlock::from_genesis(network),
		});
		let node_a_holder = NodeHolder { node: &node_a };

		let logger_b = test_utils::TestLogger::with_id("node a".to_owned());
		let chain_monitor_b = ChainMonitor::new(None, &tx_broadcaster, &logger_a, &fee_estimator, &persister_b);
		let seed_b = [2u8; 32];
		let keys_manager_b = KeysManager::new(&seed_b, 42, 42);
		let node_b = ChannelManager::new(&fee_estimator, &chain_monitor_b, &tx_broadcaster, &logger_b, &keys_manager_b, config.clone(), ChainParameters {
			network,
			best_block: BestBlock::from_genesis(network),
		});
		let node_b_holder = NodeHolder { node: &node_b };

		node_a.peer_connected(&node_b.get_our_node_id(), &Init { features: InitFeatures::known(), remote_network_address: None });
		node_b.peer_connected(&node_a.get_our_node_id(), &Init { features: InitFeatures::known(), remote_network_address: None });
		node_a.create_channel(node_b.get_our_node_id(), 8_000_000, 100_000_000, 42, None).unwrap();
		node_b.handle_open_channel(&node_a.get_our_node_id(), InitFeatures::known(), &get_event_msg!(node_a_holder, MessageSendEvent::SendOpenChannel, node_b.get_our_node_id()));
		node_a.handle_accept_channel(&node_b.get_our_node_id(), InitFeatures::known(), &get_event_msg!(node_b_holder, MessageSendEvent::SendAcceptChannel, node_a.get_our_node_id()));

		let tx;
		if let Event::FundingGenerationReady { temporary_channel_id, output_script, .. } = get_event!(node_a_holder, Event::FundingGenerationReady) {
			tx = Transaction { version: 2, lock_time: 0, input: Vec::new(), output: vec![TxOut {
				value: 8_000_000, script_pubkey: output_script,
			}]};
			node_a.funding_transaction_generated(&temporary_channel_id, &node_b.get_our_node_id(), tx.clone()).unwrap();
		} else { panic!(); }

		node_b.handle_funding_created(&node_a.get_our_node_id(), &get_event_msg!(node_a_holder, MessageSendEvent::SendFundingCreated, node_b.get_our_node_id()));
		node_a.handle_funding_signed(&node_b.get_our_node_id(), &get_event_msg!(node_b_holder, MessageSendEvent::SendFundingSigned, node_a.get_our_node_id()));

		assert_eq!(&tx_broadcaster.txn_broadcasted.lock().unwrap()[..], &[tx.clone()]);

		let block = Block {
			header: BlockHeader { version: 0x20000000, prev_blockhash: genesis_hash, merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 },
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

		let dummy_graph = NetworkGraph::new(genesis_hash);

		let mut payment_count: u64 = 0;
		macro_rules! send_payment {
			($node_a: expr, $node_b: expr) => {
				let usable_channels = $node_a.list_usable_channels();
				let payment_params = PaymentParameters::from_node_id($node_b.get_our_node_id())
					.with_features(InvoiceFeatures::known());
				let scorer = test_utils::TestScorer::with_penalty(0);
				let seed = [3u8; 32];
				let keys_manager = KeysManager::new(&seed, 42, 42);
				let random_seed_bytes = keys_manager.get_secure_random_bytes();
				let route = get_route(&$node_a.get_our_node_id(), &payment_params, &dummy_graph.read_only(),
					Some(&usable_channels.iter().map(|r| r).collect::<Vec<_>>()), 10_000, TEST_FINAL_CLTV, &logger_a, &scorer, &random_seed_bytes).unwrap();

				let mut payment_preimage = PaymentPreimage([0; 32]);
				payment_preimage.0[0..8].copy_from_slice(&payment_count.to_le_bytes());
				payment_count += 1;
				let payment_hash = PaymentHash(Sha256::hash(&payment_preimage.0[..]).into_inner());
				let payment_secret = $node_b.create_inbound_payment_for_hash(payment_hash, None, 7200).unwrap();

				$node_a.send_payment(&route, payment_hash, &Some(payment_secret)).unwrap();
				let payment_event = SendEvent::from_event($node_a.get_and_clear_pending_msg_events().pop().unwrap());
				$node_b.handle_update_add_htlc(&$node_a.get_our_node_id(), &payment_event.msgs[0]);
				$node_b.handle_commitment_signed(&$node_a.get_our_node_id(), &payment_event.commitment_msg);
				let (raa, cs) = get_revoke_commit_msgs!(NodeHolder { node: &$node_b }, $node_a.get_our_node_id());
				$node_a.handle_revoke_and_ack(&$node_b.get_our_node_id(), &raa);
				$node_a.handle_commitment_signed(&$node_b.get_our_node_id(), &cs);
				$node_b.handle_revoke_and_ack(&$node_a.get_our_node_id(), &get_event_msg!(NodeHolder { node: &$node_a }, MessageSendEvent::SendRevokeAndACK, $node_b.get_our_node_id()));

				expect_pending_htlcs_forwardable!(NodeHolder { node: &$node_b });
				expect_payment_received!(NodeHolder { node: &$node_b }, payment_hash, payment_secret, 10_000);
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

				let (raa, cs) = get_revoke_commit_msgs!(NodeHolder { node: &$node_a }, $node_b.get_our_node_id());
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
