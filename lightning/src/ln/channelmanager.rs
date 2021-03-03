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

use bitcoin::blockdata::block::{Block, BlockHeader};
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::network::constants::Network;

use bitcoin::hashes::{Hash, HashEngine};
use bitcoin::hashes::hmac::{Hmac, HmacEngine};
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::sha256d::Hash as Sha256dHash;
use bitcoin::hashes::cmp::fixed_time_eq;
use bitcoin::hash_types::BlockHash;

use bitcoin::secp256k1::key::{SecretKey,PublicKey};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::secp256k1::ecdh::SharedSecret;
use bitcoin::secp256k1;

use chain;
use chain::Watch;
use chain::chaininterface::{BroadcasterInterface, FeeEstimator};
use chain::channelmonitor::{ChannelMonitor, ChannelMonitorUpdate, ChannelMonitorUpdateStep, ChannelMonitorUpdateErr, HTLC_FAIL_BACK_BUFFER, CLTV_CLAIM_BUFFER, LATENCY_GRACE_PERIOD_BLOCKS, ANTI_REORG_DELAY, MonitorEvent, CLOSED_CHANNEL_UPDATE_ID};
use chain::transaction::{OutPoint, TransactionData};
use ln::channel::{Channel, ChannelError};
use ln::features::{InitFeatures, NodeFeatures};
use routing::router::{Route, RouteHop};
use ln::msgs;
use ln::msgs::NetAddress;
use ln::onion_utils;
use ln::msgs::{ChannelMessageHandler, DecodeError, LightningError, OptionalField};
use chain::keysinterface::{Sign, KeysInterface, KeysManager, InMemorySigner};
use util::config::UserConfig;
use util::events::{Event, EventsProvider, MessageSendEvent, MessageSendEventsProvider};
use util::{byte_utils, events};
use util::ser::{Readable, ReadableArgs, MaybeReadable, Writeable, Writer};
use util::chacha20::{ChaCha20, ChaChaReader};
use util::logger::Logger;
use util::errors::APIError;

use std::{cmp, mem};
use std::collections::{HashMap, hash_map, HashSet};
use std::io::{Cursor, Read};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, RwLock, RwLockReadGuard};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
#[cfg(any(test, feature = "allow_wallclock_use"))]
use std::time::Instant;
use std::marker::{Sync, Send};
use std::ops::Deref;
use bitcoin::hashes::hex::ToHex;

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
enum PendingHTLCRouting {
	Forward {
		onion_packet: msgs::OnionPacket,
		short_channel_id: u64, // This should be NonZero<u64> eventually when we bump MSRV
	},
	Receive {
		payment_data: Option<msgs::FinalOnionHopData>,
		incoming_cltv_expiry: u32, // Used to track when we should expire pending HTLCs that go unclaimed
	},
}

#[derive(Clone)] // See Channel::revoke_and_ack for why, tl;dr: Rust bug
pub(super) struct PendingHTLCInfo {
	routing: PendingHTLCRouting,
	incoming_shared_secret: [u8; 32],
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
#[derive(Clone, PartialEq)]
pub(crate) struct HTLCPreviousHopData {
	short_channel_id: u64,
	htlc_id: u64,
	incoming_packet_shared_secret: [u8; 32],

	// This field is consumed by `claim_funds_from_hop()` when updating a force-closed backwards
	// channel with a preimage provided by the forward channel.
	outpoint: OutPoint,
}

struct ClaimableHTLC {
	prev_hop: HTLCPreviousHopData,
	value: u64,
	/// Filled in when the HTLC was received with a payment_secret packet, which contains a
	/// total_msat (which may differ from value if this is a Multi-Path Payment) and a
	/// payment_secret which prevents path-probing attacks and can associate different HTLCs which
	/// are part of the same payment.
	payment_data: Option<msgs::FinalOnionHopData>,
	cltv_expiry: u32,
}

/// Tracks the inbound corresponding to an outbound HTLC
#[derive(Clone, PartialEq)]
pub(crate) enum HTLCSource {
	PreviousHopData(HTLCPreviousHopData),
	OutboundRoute {
		path: Vec<RouteHop>,
		session_priv: SecretKey,
		/// Technically we can recalculate this from the route, but we cache it here to avoid
		/// doing a double-pass on route when we get a failure back
		first_hop_htlc_msat: u64,
	},
}
#[cfg(test)]
impl HTLCSource {
	pub fn dummy() -> Self {
		HTLCSource::OutboundRoute {
			path: Vec::new(),
			session_priv: SecretKey::from_slice(&[1; 32]).unwrap(),
			first_hop_htlc_msat: 0,
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

/// payment_hash type, use to cross-lock hop
/// (C-not exported) as we just use [u8; 32] directly
#[derive(Hash, Copy, Clone, PartialEq, Eq, Debug)]
pub struct PaymentHash(pub [u8;32]);
/// payment_preimage type, use to route payment between hop
/// (C-not exported) as we just use [u8; 32] directly
#[derive(Hash, Copy, Clone, PartialEq, Eq, Debug)]
pub struct PaymentPreimage(pub [u8;32]);
/// payment_secret type, use to authenticate sender to the receiver and tie MPP HTLCs together
/// (C-not exported) as we just use [u8; 32] directly
#[derive(Hash, Copy, Clone, PartialEq, Eq, Debug)]
pub struct PaymentSecret(pub [u8;32]);

type ShutdownResult = (Option<OutPoint>, ChannelMonitorUpdate, Vec<(HTLCSource, PaymentHash)>);

/// Error type returned across the channel_state mutex boundary. When an Err is generated for a
/// Channel, we generally end up with a ChannelError::Close for which we have to close the channel
/// immediately (ie with no further calls on it made). Thus, this step happens inside a
/// channel_state lock. We then return the set of things that need to be done outside the lock in
/// this struct and call handle_error!() on it.

struct MsgHandleErrInternal {
	err: msgs::LightningError,
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
			shutdown_finish: None,
		}
	}
	#[inline]
	fn from_no_close(err: msgs::LightningError) -> Self {
		Self { err, shutdown_finish: None }
	}
	#[inline]
	fn from_finish_shutdown(err: String, channel_id: [u8; 32], shutdown_res: ShutdownResult, channel_update: Option<msgs::ChannelUpdate>) -> Self {
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
			shutdown_finish: Some((shutdown_res, channel_update)),
		}
	}
	#[inline]
	fn from_chan_no_close(err: ChannelError, channel_id: [u8; 32]) -> Self {
		Self {
			err: match err {
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
	pub(super) short_to_id: HashMap<u64, [u8; 32]>,
	/// short channel id -> forward infos. Key of 0 means payments received
	/// Note that while this is held in the same mutex as the channels themselves, no consistency
	/// guarantees are made about the existence of a channel with the short id here, nor the short
	/// ids in the PendingHTLCInfo!
	pub(super) forward_htlcs: HashMap<u64, Vec<HTLCForwardInfo>>,
	/// (payment_hash, payment_secret) -> Vec<HTLCs> for tracking HTLCs that
	/// were to us and can be failed/claimed by the user
	/// Note that while this is held in the same mutex as the channels themselves, no consistency
	/// guarantees are made about the channels given here actually existing anymore by the time you
	/// go to read them!
	claimable_htlcs: HashMap<(PaymentHash, Option<PaymentSecret>), Vec<ClaimableHTLC>>,
	/// Messages to send to peers - pushed to in the same lock that they are generated in (except
	/// for broadcast messages, where ordering isn't as strict).
	pub(super) pending_msg_events: Vec<MessageSendEvent>,
}

/// State we hold per-peer. In the future we should put channels in here, but for now we only hold
/// the latest Init features we heard from the peer.
struct PeerState {
	latest_features: InitFeatures,
}

#[cfg(not(any(target_pointer_width = "32", target_pointer_width = "64")))]
const ERR: () = "You need at least 32 bit pointers (well, usize, but we'll assume they're the same) for ChannelManager::latest_block_height";

/// SimpleArcChannelManager is useful when you need a ChannelManager with a static lifetime, e.g.
/// when you're using lightning-net-tokio (since tokio::spawn requires parameters with static
/// lifetimes). Other times you can afford a reference, which is more efficient, in which case
/// SimpleRefChannelManager is the more appropriate type. Defining these type aliases prevents
/// issues such as overly long function definitions. Note that the ChannelManager can take any
/// type that implements KeysInterface for its keys manager, but this type alias chooses the
/// concrete type of the KeysManager.
pub type SimpleArcChannelManager<M, T, F, L> = ChannelManager<InMemorySigner, Arc<M>, Arc<T>, Arc<KeysManager>, Arc<F>, Arc<L>>;

/// SimpleRefChannelManager is a type alias for a ChannelManager reference, and is the reference
/// counterpart to the SimpleArcChannelManager type alias. Use this type by default when you don't
/// need a ChannelManager with a static lifetime. You'll need a static lifetime in cases such as
/// usage of lightning-net-tokio (since tokio::spawn requires parameters with static lifetimes).
/// But if this is not necessary, using a reference is more efficient. Defining these type aliases
/// helps with issues such as long function definitions. Note that the ChannelManager can take any
/// type that implements KeysInterface for its keys manager, but this type alias chooses the
/// concrete type of the KeysManager.
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
/// Note that the deserializer is only implemented for (Sha256dHash, ChannelManager), which
/// tells you the last block hash which was block_connect()ed. You MUST rescan any blocks along
/// the "reorg path" (ie call block_disconnected() until you get to a common block and then call
/// block_connected() to step towards your best block) upon deserialization before using the
/// object!
///
/// Note that ChannelManager is responsible for tracking liveness of its channels and generating
/// ChannelUpdate messages informing peers that the channel is temporarily disabled. To avoid
/// spam due to quick disconnection/reconnection, updates are not sent until the channel has been
/// offline for a full minute. In order to track this, you must call
/// timer_chan_freshness_every_min roughly once per minute, though it doesn't have to be perfect.
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
	pub(super) latest_block_height: AtomicUsize,
	#[cfg(not(test))]
	latest_block_height: AtomicUsize,
	last_block_hash: Mutex<BlockHash>,
	secp_ctx: Secp256k1<secp256k1::All>,

	#[cfg(any(test, feature = "_test_utils"))]
	pub(super) channel_state: Mutex<ChannelHolder<Signer>>,
	#[cfg(not(any(test, feature = "_test_utils")))]
	channel_state: Mutex<ChannelHolder<Signer>>,
	our_network_key: SecretKey,

	/// Used to track the last value sent in a node_announcement "timestamp" field. We ensure this
	/// value increases strictly since we don't assume access to a time source.
	last_node_announcement_serial: AtomicUsize,

	/// The bulk of our storage will eventually be here (channels and message queues and the like).
	/// If we are connected to a peer we always at least have an entry here, even if no channels
	/// are currently open with that peer.
	/// Because adding or removing an entry is rare, we usually take an outer read lock and then
	/// operate on the inner value freely. Sadly, this prevents parallel operation when opening a
	/// new channel.
	per_peer_state: RwLock<HashMap<PublicKey, Mutex<PeerState>>>,

	pending_events: Mutex<Vec<events::Event>>,
	/// Used when we have to take a BIG lock to make sure everything is self-consistent.
	/// Essentially just when we're serializing ourselves out.
	/// Taken first everywhere where we are making changes before any other locks.
	/// When acquiring this lock in read mode, rather than acquiring it directly, call
	/// `PersistenceNotifierGuard::new(..)` and pass the lock to it, to ensure the PersistenceNotifier
	/// the lock contains sends out a notification when the lock is released.
	total_consistency_lock: RwLock<()>,

	persistence_notifier: PersistenceNotifier,

	keys_manager: K,

	logger: L,
}

/// Whenever we release the `ChannelManager`'s `total_consistency_lock`, from read mode, it is
/// desirable to notify any listeners on `wait_timeout`/`wait` that new updates are available for
/// persistence. Therefore, this struct is responsible for locking the total consistency lock and,
/// upon going out of scope, sending the aforementioned notification (since the lock being released
/// indicates that the updates are ready for persistence).
struct PersistenceNotifierGuard<'a> {
	persistence_notifier: &'a PersistenceNotifier,
	// We hold onto this result so the lock doesn't get released immediately.
	_read_guard: RwLockReadGuard<'a, ()>,
}

impl<'a> PersistenceNotifierGuard<'a> {
	fn new(lock: &'a RwLock<()>, notifier: &'a PersistenceNotifier) -> Self {
		let read_guard = lock.read().unwrap();

		Self {
			persistence_notifier: notifier,
			_read_guard: read_guard,
		}
	}
}

impl<'a> Drop for PersistenceNotifierGuard<'a> {
	fn drop(&mut self) {
		self.persistence_notifier.notify();
	}
}

/// The amount of time we require our counterparty wait to claim their money (ie time between when
/// we, or our watchtower, must check for them having broadcast a theft transaction).
pub(crate) const BREAKDOWN_TIMEOUT: u16 = 6 * 24;
/// The amount of time we're willing to wait to claim money back to us
pub(crate) const MAX_LOCAL_BREAKDOWN_TIMEOUT: u16 = 6 * 24 * 7;

/// The minimum number of blocks between an inbound HTLC's CLTV and the corresponding outbound
/// HTLC's CLTV. This should always be a few blocks greater than channelmonitor::CLTV_CLAIM_BUFFER,
/// ie the node we forwarded the payment on to should always have enough room to reliably time out
/// the HTLC via a full update_fail_htlc/commitment_signed dance before we hit the
/// CLTV_CLAIM_BUFFER point (we static assert that it's at least 3 blocks more).
const CLTV_EXPIRY_DELTA: u16 = 6 * 12; //TODO?
pub(super) const CLTV_FAR_FAR_AWAY: u32 = 6 * 24 * 7; //TODO?

// Check that our CLTV_EXPIRY is at least CLTV_CLAIM_BUFFER + ANTI_REORG_DELAY + LATENCY_GRACE_PERIOD_BLOCKS,
// ie that if the next-hop peer fails the HTLC within
// LATENCY_GRACE_PERIOD_BLOCKS then we'll still have CLTV_CLAIM_BUFFER left to timeout it onchain,
// then waiting ANTI_REORG_DELAY to be reorg-safe on the outbound HLTC and
// failing the corresponding htlc backward, and us now seeing the last block of ANTI_REORG_DELAY before
// LATENCY_GRACE_PERIOD_BLOCKS.
#[deny(const_err)]
#[allow(dead_code)]
const CHECK_CLTV_EXPIRY_SANITY: u32 = CLTV_EXPIRY_DELTA as u32 - LATENCY_GRACE_PERIOD_BLOCKS - CLTV_CLAIM_BUFFER - ANTI_REORG_DELAY - LATENCY_GRACE_PERIOD_BLOCKS;

// Check for ability of an attacker to make us fail on-chain by delaying inbound claim. See
// ChannelMontior::would_broadcast_at_height for a description of why this is needed.
#[deny(const_err)]
#[allow(dead_code)]
const CHECK_CLTV_EXPIRY_SANITY_2: u32 = CLTV_EXPIRY_DELTA as u32 - LATENCY_GRACE_PERIOD_BLOCKS - 2*CLTV_CLAIM_BUFFER;

/// Details of a channel, as returned by ChannelManager::list_channels and ChannelManager::list_usable_channels
#[derive(Clone)]
pub struct ChannelDetails {
	/// The channel's ID (prior to funding transaction generation, this is a random 32 bytes,
	/// thereafter this is the txid of the funding transaction xor the funding transaction output).
	/// Note that this means this value is *not* persistent - it can change once during the
	/// lifetime of the channel.
	pub channel_id: [u8; 32],
	/// The position of the funding transaction in the chain. None if the funding transaction has
	/// not yet been confirmed and the channel fully opened.
	pub short_channel_id: Option<u64>,
	/// The node_id of our counterparty
	pub remote_network_id: PublicKey,
	/// The Features the channel counterparty provided upon last connection.
	/// Useful for routing as it is the most up-to-date copy of the counterparty's features and
	/// many routing-relevant features are present in the init context.
	pub counterparty_features: InitFeatures,
	/// The value, in satoshis, of this channel as appears in the funding output
	pub channel_value_satoshis: u64,
	/// The user_id passed in to create_channel, or 0 if the channel was inbound.
	pub user_id: u64,
	/// The available outbound capacity for sending HTLCs to the remote peer. This does not include
	/// any pending HTLCs which are not yet fully resolved (and, thus, who's balance is not
	/// available for inclusion in new outbound HTLCs). This further does not include any pending
	/// outgoing HTLCs which are awaiting some other resolution to be sent.
	pub outbound_capacity_msat: u64,
	/// The available inbound capacity for the remote peer to send HTLCs to us. This does not
	/// include any pending HTLCs which are not yet fully resolved (and, thus, who's balance is not
	/// available for inclusion in new inbound HTLCs).
	/// Note that there are some corner cases not fully handled here, so the actual available
	/// inbound capacity may be slightly higher than this.
	pub inbound_capacity_msat: u64,
	/// True if the channel is (a) confirmed and funding_locked messages have been exchanged, (b)
	/// the peer is connected, and (c) no monitor update failure is pending resolution.
	pub is_live: bool,
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
	PartialFailure(Vec<Result<(), APIError>>),
}

macro_rules! handle_error {
	($self: ident, $internal: expr, $counterparty_node_id: expr) => {
		match $internal {
			Ok(msg) => Ok(msg),
			Err(MsgHandleErrInternal { err, shutdown_finish }) => {
				#[cfg(debug_assertions)]
				{
					// In testing, ensure there are no deadlocks where the lock is already held upon
					// entering the macro.
					assert!($self.channel_state.try_lock().is_ok());
				}

				let mut msg_events = Vec::with_capacity(2);

				if let Some((shutdown_res, update_option)) = shutdown_finish {
					$self.finish_force_close_channel(shutdown_res);
					if let Some(update) = update_option {
						msg_events.push(events::MessageSendEvent::BroadcastChannelUpdate {
							msg: update
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

macro_rules! break_chan_entry {
	($self: ident, $res: expr, $channel_state: expr, $entry: expr) => {
		match $res {
			Ok(res) => res,
			Err(ChannelError::Ignore(msg)) => {
				break Err(MsgHandleErrInternal::from_chan_no_close(ChannelError::Ignore(msg), $entry.key().clone()))
			},
			Err(ChannelError::Close(msg)) => {
				log_trace!($self.logger, "Closing channel {} due to Close-required error: {}", log_bytes!($entry.key()[..]), msg);
				let (channel_id, mut chan) = $entry.remove_entry();
				if let Some(short_id) = chan.get_short_channel_id() {
					$channel_state.short_to_id.remove(&short_id);
				}
				break Err(MsgHandleErrInternal::from_finish_shutdown(msg, channel_id, chan.force_shutdown(true), $self.get_channel_update(&chan).ok()))
			},
			Err(ChannelError::CloseDelayBroadcast(_)) => { panic!("Wait is only generated on receipt of channel_reestablish, which is handled by try_chan_entry, we don't bother to support it here"); }
		}
	}
}

macro_rules! try_chan_entry {
	($self: ident, $res: expr, $channel_state: expr, $entry: expr) => {
		match $res {
			Ok(res) => res,
			Err(ChannelError::Ignore(msg)) => {
				return Err(MsgHandleErrInternal::from_chan_no_close(ChannelError::Ignore(msg), $entry.key().clone()))
			},
			Err(ChannelError::Close(msg)) => {
				log_trace!($self.logger, "Closing channel {} due to Close-required error: {}", log_bytes!($entry.key()[..]), msg);
				let (channel_id, mut chan) = $entry.remove_entry();
				if let Some(short_id) = chan.get_short_channel_id() {
					$channel_state.short_to_id.remove(&short_id);
				}
				return Err(MsgHandleErrInternal::from_finish_shutdown(msg, channel_id, chan.force_shutdown(true), $self.get_channel_update(&chan).ok()))
			},
			Err(ChannelError::CloseDelayBroadcast(msg)) => {
				log_error!($self.logger, "Channel {} need to be shutdown but closing transactions not broadcast due to {}", log_bytes!($entry.key()[..]), msg);
				let (channel_id, mut chan) = $entry.remove_entry();
				if let Some(short_id) = chan.get_short_channel_id() {
					$channel_state.short_to_id.remove(&short_id);
				}
				let shutdown_res = chan.force_shutdown(false);
				return Err(MsgHandleErrInternal::from_finish_shutdown(msg, channel_id, shutdown_res, $self.get_channel_update(&chan).ok()))
			}
		}
	}
}

macro_rules! handle_monitor_err {
	($self: ident, $err: expr, $channel_state: expr, $entry: expr, $action_type: path, $resend_raa: expr, $resend_commitment: expr) => {
		handle_monitor_err!($self, $err, $channel_state, $entry, $action_type, $resend_raa, $resend_commitment, Vec::new(), Vec::new())
	};
	($self: ident, $err: expr, $channel_state: expr, $entry: expr, $action_type: path, $resend_raa: expr, $resend_commitment: expr, $failed_forwards: expr, $failed_fails: expr) => {
		match $err {
			ChannelMonitorUpdateErr::PermanentFailure => {
				log_error!($self.logger, "Closing channel {} due to monitor update PermanentFailure", log_bytes!($entry.key()[..]));
				let (channel_id, mut chan) = $entry.remove_entry();
				if let Some(short_id) = chan.get_short_channel_id() {
					$channel_state.short_to_id.remove(&short_id);
				}
				// TODO: $failed_fails is dropped here, which will cause other channels to hit the
				// chain in a confused state! We need to move them into the ChannelMonitor which
				// will be responsible for failing backwards once things confirm on-chain.
				// It's ok that we drop $failed_forwards here - at this point we'd rather they
				// broadcast HTLC-Timeout and pay the associated fees to get their funds back than
				// us bother trying to claim it just to forward on to another peer. If we're
				// splitting hairs we'd prefer to claim payments that were to us, but we haven't
				// given up the preimage yet, so might as well just wait until the payment is
				// retried, avoiding the on-chain fees.
				let res: Result<(), _> = Err(MsgHandleErrInternal::from_finish_shutdown("ChannelMonitor storage failure".to_owned(), channel_id, chan.force_shutdown(true), $self.get_channel_update(&chan).ok()));
				res
			},
			ChannelMonitorUpdateErr::TemporaryFailure => {
				log_info!($self.logger, "Disabling channel {} due to monitor update TemporaryFailure. On restore will send {} and process {} forwards and {} fails",
						log_bytes!($entry.key()[..]),
						if $resend_commitment && $resend_raa {
								match $action_type {
									RAACommitmentOrder::CommitmentFirst => { "commitment then RAA" },
									RAACommitmentOrder::RevokeAndACKFirst => { "RAA then commitment" },
								}
							} else if $resend_commitment { "commitment" }
							else if $resend_raa { "RAA" }
							else { "nothing" },
						(&$failed_forwards as &Vec<(PendingHTLCInfo, u64)>).len(),
						(&$failed_fails as &Vec<(HTLCSource, PaymentHash, HTLCFailReason)>).len());
				if !$resend_commitment {
					debug_assert!($action_type == RAACommitmentOrder::RevokeAndACKFirst || !$resend_raa);
				}
				if !$resend_raa {
					debug_assert!($action_type == RAACommitmentOrder::CommitmentFirst || !$resend_commitment);
				}
				$entry.get_mut().monitor_update_failed($resend_raa, $resend_commitment, $failed_forwards, $failed_fails);
				Err(MsgHandleErrInternal::from_chan_no_close(ChannelError::Ignore("Failed to update ChannelMonitor".to_owned()), *$entry.key()))
			},
		}
	}
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
	/// panics if channel_value_satoshis is >= `MAX_FUNDING_SATOSHIS`!
	///
	/// Users must provide the current blockchain height from which to track onchain channel
	/// funding outpoints and send payments with reliable timelocks.
	///
	/// Users need to notify the new ChannelManager when a new block is connected or
	/// disconnected using its `block_connected` and `block_disconnected` methods.
	pub fn new(network: Network, fee_est: F, chain_monitor: M, tx_broadcaster: T, logger: L, keys_manager: K, config: UserConfig, current_blockchain_height: usize) -> Self {
		let mut secp_ctx = Secp256k1::new();
		secp_ctx.seeded_randomize(&keys_manager.get_secure_random_bytes());

		ChannelManager {
			default_configuration: config.clone(),
			genesis_hash: genesis_block(network).header.block_hash(),
			fee_estimator: fee_est,
			chain_monitor,
			tx_broadcaster,

			latest_block_height: AtomicUsize::new(current_blockchain_height),
			last_block_hash: Mutex::new(Default::default()),
			secp_ctx,

			channel_state: Mutex::new(ChannelHolder{
				by_id: HashMap::new(),
				short_to_id: HashMap::new(),
				forward_htlcs: HashMap::new(),
				claimable_htlcs: HashMap::new(),
				pending_msg_events: Vec::new(),
			}),
			our_network_key: keys_manager.get_node_secret(),

			last_node_announcement_serial: AtomicUsize::new(0),

			per_peer_state: RwLock::new(HashMap::new()),

			pending_events: Mutex::new(Vec::new()),
			total_consistency_lock: RwLock::new(()),
			persistence_notifier: PersistenceNotifier::new(),

			keys_manager,

			logger,
		}
	}

	/// Creates a new outbound channel to the given remote node and with the given value.
	///
	/// user_id will be provided back as user_channel_id in FundingGenerationReady and
	/// FundingBroadcastSafe events to allow tracking of which events correspond with which
	/// create_channel call. Note that user_channel_id defaults to 0 for inbound channels, so you
	/// may wish to avoid using 0 for user_id here.
	///
	/// If successful, will generate a SendOpenChannel message event, so you should probably poll
	/// PeerManager::process_events afterwards.
	///
	/// Raises APIError::APIMisuseError when channel_value_satoshis > 2**24 or push_msat is
	/// greater than channel_value_satoshis * 1k or channel_value_satoshis is < 1000.
	pub fn create_channel(&self, their_network_key: PublicKey, channel_value_satoshis: u64, push_msat: u64, user_id: u64, override_config: Option<UserConfig>) -> Result<(), APIError> {
		if channel_value_satoshis < 1000 {
			return Err(APIError::APIMisuseError { err: format!("Channel value must be at least 1000 satoshis. It was {}", channel_value_satoshis) });
		}

		let config = if override_config.is_some() { override_config.as_ref().unwrap() } else { &self.default_configuration };
		let channel = Channel::new_outbound(&self.fee_estimator, &self.keys_manager, their_network_key, channel_value_satoshis, push_msat, user_id, config)?;
		let res = channel.get_open_channel(self.genesis_hash.clone());

		let _persistence_guard = PersistenceNotifierGuard::new(&self.total_consistency_lock, &self.persistence_notifier);
		// We want to make sure the lock is actually acquired by PersistenceNotifierGuard.
		debug_assert!(&self.total_consistency_lock.try_write().is_err());

		let mut channel_state = self.channel_state.lock().unwrap();
		match channel_state.by_id.entry(channel.channel_id()) {
			hash_map::Entry::Occupied(_) => {
				if cfg!(feature = "fuzztarget") {
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
		Ok(())
	}

	fn list_channels_with_filter<Fn: FnMut(&(&[u8; 32], &Channel<Signer>)) -> bool>(&self, f: Fn) -> Vec<ChannelDetails> {
		let mut res = Vec::new();
		{
			let channel_state = self.channel_state.lock().unwrap();
			res.reserve(channel_state.by_id.len());
			for (channel_id, channel) in channel_state.by_id.iter().filter(f) {
				let (inbound_capacity_msat, outbound_capacity_msat) = channel.get_inbound_outbound_available_balance_msat();
				res.push(ChannelDetails {
					channel_id: (*channel_id).clone(),
					short_channel_id: channel.get_short_channel_id(),
					remote_network_id: channel.get_counterparty_node_id(),
					counterparty_features: InitFeatures::empty(),
					channel_value_satoshis: channel.get_value_satoshis(),
					inbound_capacity_msat,
					outbound_capacity_msat,
					user_id: channel.get_user_id(),
					is_live: channel.is_live(),
				});
			}
		}
		let per_peer_state = self.per_peer_state.read().unwrap();
		for chan in res.iter_mut() {
			if let Some(peer_state) = per_peer_state.get(&chan.remote_network_id) {
				chan.counterparty_features = peer_state.lock().unwrap().latest_features.clone();
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
	/// These are guaranteed to have their is_live value set to true, see the documentation for
	/// ChannelDetails::is_live for more info on exactly what the criteria are.
	pub fn list_usable_channels(&self) -> Vec<ChannelDetails> {
		// Note we use is_live here instead of usable which leads to somewhat confused
		// internal/external nomenclature, but that's ok cause that's probably what the user
		// really wanted anyway.
		self.list_channels_with_filter(|&(_, ref channel)| channel.is_live())
	}

	/// Begins the process of closing a channel. After this call (plus some timeout), no new HTLCs
	/// will be accepted on the given channel, and after additional timeout/the closing of all
	/// pending HTLCs, the channel will be closed on chain.
	///
	/// May generate a SendShutdown message event on success, which should be relayed.
	pub fn close_channel(&self, channel_id: &[u8; 32]) -> Result<(), APIError> {
		let _persistence_guard = PersistenceNotifierGuard::new(&self.total_consistency_lock, &self.persistence_notifier);

		let (mut failed_htlcs, chan_option) = {
			let mut channel_state_lock = self.channel_state.lock().unwrap();
			let channel_state = &mut *channel_state_lock;
			match channel_state.by_id.entry(channel_id.clone()) {
				hash_map::Entry::Occupied(mut chan_entry) => {
					let (shutdown_msg, failed_htlcs) = chan_entry.get_mut().get_shutdown()?;
					channel_state.pending_msg_events.push(events::MessageSendEvent::SendShutdown {
						node_id: chan_entry.get().get_counterparty_node_id(),
						msg: shutdown_msg
					});
					if chan_entry.get().is_shutdown() {
						if let Some(short_id) = chan_entry.get().get_short_channel_id() {
							channel_state.short_to_id.remove(&short_id);
						}
						(failed_htlcs, Some(chan_entry.remove_entry().1))
					} else { (failed_htlcs, None) }
				},
				hash_map::Entry::Vacant(_) => return Err(APIError::ChannelUnavailable{err: "No such channel".to_owned()})
			}
		};
		for htlc_source in failed_htlcs.drain(..) {
			self.fail_htlc_backwards_internal(self.channel_state.lock().unwrap(), htlc_source.0, &htlc_source.1, HTLCFailReason::Reason { failure_code: 0x4000 | 8, data: Vec::new() });
		}
		let chan_update = if let Some(chan) = chan_option {
			if let Ok(update) = self.get_channel_update(&chan) {
				Some(update)
			} else { None }
		} else { None };

		if let Some(update) = chan_update {
			let mut channel_state = self.channel_state.lock().unwrap();
			channel_state.pending_msg_events.push(events::MessageSendEvent::BroadcastChannelUpdate {
				msg: update
			});
		}

		Ok(())
	}

	#[inline]
	fn finish_force_close_channel(&self, shutdown_res: ShutdownResult) {
		let (funding_txo_option, monitor_update, mut failed_htlcs) = shutdown_res;
		log_trace!(self.logger, "Finishing force-closure of channel {} HTLCs to fail", failed_htlcs.len());
		for htlc_source in failed_htlcs.drain(..) {
			self.fail_htlc_backwards_internal(self.channel_state.lock().unwrap(), htlc_source.0, &htlc_source.1, HTLCFailReason::Reason { failure_code: 0x4000 | 8, data: Vec::new() });
		}
		if let Some(funding_txo) = funding_txo_option {
			// There isn't anything we can do if we get an update failure - we're already
			// force-closing. The monitor update on the required in-memory copy should broadcast
			// the latest local state, which is the best we can do anyway. Thus, it is safe to
			// ignore the result here.
			let _ = self.chain_monitor.update_channel(funding_txo, monitor_update);
		}
	}

	fn force_close_channel_with_peer(&self, channel_id: &[u8; 32], peer_node_id: Option<&PublicKey>) -> Result<(), APIError> {
		let mut chan = {
			let mut channel_state_lock = self.channel_state.lock().unwrap();
			let channel_state = &mut *channel_state_lock;
			if let hash_map::Entry::Occupied(chan) = channel_state.by_id.entry(channel_id.clone()) {
				if let Some(node_id) = peer_node_id {
					if chan.get().get_counterparty_node_id() != *node_id {
						// Error or Ok here doesn't matter - the result is only exposed publicly
						// when peer_node_id is None anyway.
						return Ok(());
					}
				}
				if let Some(short_id) = chan.get().get_short_channel_id() {
					channel_state.short_to_id.remove(&short_id);
				}
				chan.remove_entry().1
			} else {
				return Err(APIError::ChannelUnavailable{err: "No such channel".to_owned()});
			}
		};
		log_trace!(self.logger, "Force-closing channel {}", log_bytes!(channel_id[..]));
		self.finish_force_close_channel(chan.force_shutdown(true));
		if let Ok(update) = self.get_channel_update(&chan) {
			let mut channel_state = self.channel_state.lock().unwrap();
			channel_state.pending_msg_events.push(events::MessageSendEvent::BroadcastChannelUpdate {
				msg: update
			});
		}

		Ok(())
	}

	/// Force closes a channel, immediately broadcasting the latest local commitment transaction to
	/// the chain and rejecting new HTLCs on the given channel. Fails if channel_id is unknown to the manager.
	pub fn force_close_channel(&self, channel_id: &[u8; 32]) -> Result<(), APIError> {
		let _persistence_guard = PersistenceNotifierGuard::new(&self.total_consistency_lock, &self.persistence_notifier);
		self.force_close_channel_with_peer(channel_id, None)
	}

	/// Force close all channels, immediately broadcasting the latest local commitment transaction
	/// for each to the chain and rejecting new HTLCs on each.
	pub fn force_close_all_channels(&self) {
		for chan in self.list_channels() {
			let _ = self.force_close_channel(&chan.channel_id);
		}
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

		let shared_secret = {
			let mut arr = [0; 32];
			arr.copy_from_slice(&SharedSecret::new(&msg.onion_routing_packet.public_key.unwrap(), &self.our_network_key)[..]);
			arr
		};
		let (rho, mu) = onion_utils::gen_rho_mu_from_shared_secret(&shared_secret);

		if msg.onion_routing_packet.version != 0 {
			//TODO: Spec doesn't indicate if we should only hash hop_data here (and in other
			//sha256_of_onion error data packets), or the entire onion_routing_packet. Either way,
			//the hash doesn't really serve any purpose - in the case of hashing all data, the
			//receiving node would have to brute force to figure out which version was put in the
			//packet by the node that send us the message, in the case of hashing the hop_data, the
			//node knows the HMAC matched, so they already know what is there...
			return_malformed_err!("Unknown onion packet version", 0x8000 | 0x4000 | 4);
		}

		let mut hmac = HmacEngine::<Sha256>::new(&mu);
		hmac.input(&msg.onion_routing_packet.hop_data);
		hmac.input(&msg.payment_hash.0[..]);
		if !fixed_time_eq(&Hmac::from_engine(hmac).into_inner(), &msg.onion_routing_packet.hmac) {
			return_malformed_err!("HMAC Check failed", 0x8000 | 0x4000 | 5);
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

		let mut chacha = ChaCha20::new(&rho, &[0u8; 8]);
		let mut chacha_stream = ChaChaReader { chacha: &mut chacha, read: Cursor::new(&msg.onion_routing_packet.hop_data[..]) };
		let (next_hop_data, next_hop_hmac) = {
			match msgs::OnionHopData::read(&mut chacha_stream) {
				Err(err) => {
					let error_code = match err {
						msgs::DecodeError::UnknownVersion => 0x4000 | 1, // unknown realm byte
						msgs::DecodeError::UnknownRequiredFeature|
						msgs::DecodeError::InvalidValue|
						msgs::DecodeError::ShortRead => 0x4000 | 22, // invalid_onion_payload
						_ => 0x2000 | 2, // Should never happen
					};
					return_err!("Unable to decode our hop data", error_code, &[0;0]);
				},
				Ok(msg) => {
					let mut hmac = [0; 32];
					if let Err(_) = chacha_stream.read_exact(&mut hmac[..]) {
						return_err!("Unable to decode hop data", 0x4000 | 22, &[0;0]);
					}
					(msg, hmac)
				},
			}
		};

		let pending_forward_info = if next_hop_hmac == [0; 32] {
				#[cfg(test)]
				{
					// In tests, make sure that the initial onion pcket data is, at least, non-0.
					// We could do some fancy randomness test here, but, ehh, whatever.
					// This checks for the issue where you can calculate the path length given the
					// onion data as all the path entries that the originator sent will be here
					// as-is (and were originally 0s).
					// Of course reverse path calculation is still pretty easy given naive routing
					// algorithms, but this fixes the most-obvious case.
					let mut next_bytes = [0; 32];
					chacha_stream.read_exact(&mut next_bytes).unwrap();
					assert_ne!(next_bytes[..], [0; 32][..]);
					chacha_stream.read_exact(&mut next_bytes).unwrap();
					assert_ne!(next_bytes[..], [0; 32][..]);
				}

				// OUR PAYMENT!
				// final_expiry_too_soon
				// We have to have some headroom to broadcast on chain if we have the preimage, so make sure we have at least
				// HTLC_FAIL_BACK_BUFFER blocks to go.
				// Also, ensure that, in the case of an unknown payment hash, our payment logic has enough time to fail the HTLC backward
				// before our onchain logic triggers a channel closure (see HTLC_FAIL_BACK_BUFFER rational).
				if (msg.cltv_expiry as u64) <= self.latest_block_height.load(Ordering::Acquire) as u64 + HTLC_FAIL_BACK_BUFFER as u64 + 1 {
					return_err!("The final CLTV expiry is too soon to handle", 17, &[0;0]);
				}
				// final_incorrect_htlc_amount
				if next_hop_data.amt_to_forward > msg.amount_msat {
					return_err!("Upstream node sent less than we were supposed to receive in payment", 19, &byte_utils::be64_to_array(msg.amount_msat));
				}
				// final_incorrect_cltv_expiry
				if next_hop_data.outgoing_cltv_value != msg.cltv_expiry {
					return_err!("Upstream node set CLTV to the wrong value", 18, &byte_utils::be32_to_array(msg.cltv_expiry));
				}

				let payment_data = match next_hop_data.format {
					msgs::OnionHopDataFormat::Legacy { .. } => None,
					msgs::OnionHopDataFormat::NonFinalNode { .. } => return_err!("Got non final data with an HMAC of 0", 0x4000 | 22, &[0;0]),
					msgs::OnionHopDataFormat::FinalNode { payment_data } => payment_data,
				};

				// Note that we could obviously respond immediately with an update_fulfill_htlc
				// message, however that would leak that we are the recipient of this payment, so
				// instead we stay symmetric with the forwarding case, only responding (after a
				// delay) once they've send us a commitment_signed!

				PendingHTLCStatus::Forward(PendingHTLCInfo {
					routing: PendingHTLCRouting::Receive {
						payment_data,
						incoming_cltv_expiry: msg.cltv_expiry,
					},
					payment_hash: msg.payment_hash.clone(),
					incoming_shared_secret: shared_secret,
					amt_to_forward: next_hop_data.amt_to_forward,
					outgoing_cltv_value: next_hop_data.outgoing_cltv_value,
				})
			} else {
				let mut new_packet_data = [0; 20*65];
				let read_pos = chacha_stream.read(&mut new_packet_data).unwrap();
				#[cfg(debug_assertions)]
				{
					// Check two things:
					// a) that the behavior of our stream here will return Ok(0) even if the TLV
					//    read above emptied out our buffer and the unwrap() wont needlessly panic
					// b) that we didn't somehow magically end up with extra data.
					let mut t = [0; 1];
					debug_assert!(chacha_stream.read(&mut t).unwrap() == 0);
				}
				// Once we've emptied the set of bytes our peer gave us, encrypt 0 bytes until we
				// fill the onion hop data we'll forward to our next-hop peer.
				chacha_stream.chacha.process_in_place(&mut new_packet_data[read_pos..]);

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
					hop_data: new_packet_data,
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
			};

		channel_state = Some(self.channel_state.lock().unwrap());
		if let &PendingHTLCStatus::Forward(PendingHTLCInfo { ref routing, ref amt_to_forward, ref outgoing_cltv_value, .. }) = &pending_forward_info {
			// If short_channel_id is 0 here, we'll reject the HTLC as there cannot be a channel
			// with a short_channel_id of 0. This is important as various things later assume
			// short_channel_id is non-0 in any ::Forward.
			if let &PendingHTLCRouting::Forward { ref short_channel_id, .. } = routing {
				let id_option = channel_state.as_ref().unwrap().short_to_id.get(&short_channel_id).cloned();
				let forwarding_id = match id_option {
					None => { // unknown_next_peer
						return_err!("Don't have available channel for forwarding as requested.", 0x4000 | 10, &[0;0]);
					},
					Some(id) => id.clone(),
				};
				if let Some((err, code, chan_update)) = loop {
					let chan = channel_state.as_mut().unwrap().by_id.get_mut(&forwarding_id).unwrap();

					// Note that we could technically not return an error yet here and just hope
					// that the connection is reestablished or monitor updated by the time we get
					// around to doing the actual forward, but better to fail early if we can and
					// hopefully an attacker trying to path-trace payments cannot make this occur
					// on a small/per-node/per-channel scale.
					if !chan.is_live() { // channel_disabled
						break Some(("Forwarding channel is not in a ready state.", 0x1000 | 20, Some(self.get_channel_update(chan).unwrap())));
					}
					if *amt_to_forward < chan.get_counterparty_htlc_minimum_msat() { // amount_below_minimum
						break Some(("HTLC amount was below the htlc_minimum_msat", 0x1000 | 11, Some(self.get_channel_update(chan).unwrap())));
					}
					let fee = amt_to_forward.checked_mul(chan.get_fee_proportional_millionths() as u64).and_then(|prop_fee| { (prop_fee / 1000000).checked_add(chan.get_holder_fee_base_msat(&self.fee_estimator) as u64) });
					if fee.is_none() || msg.amount_msat < fee.unwrap() || (msg.amount_msat - fee.unwrap()) < *amt_to_forward { // fee_insufficient
						break Some(("Prior hop has deviated from specified fees parameters or origin node has obsolete ones", 0x1000 | 12, Some(self.get_channel_update(chan).unwrap())));
					}
					if (msg.cltv_expiry as u64) < (*outgoing_cltv_value) as u64 + CLTV_EXPIRY_DELTA as u64 { // incorrect_cltv_expiry
						break Some(("Forwarding node has tampered with the intended HTLC values or origin node has an obsolete cltv_expiry_delta", 0x1000 | 13, Some(self.get_channel_update(chan).unwrap())));
					}
					let cur_height = self.latest_block_height.load(Ordering::Acquire) as u32 + 1;
					// Theoretically, channel counterparty shouldn't send us a HTLC expiring now, but we want to be robust wrt to counterparty
					// packet sanitization (see HTLC_FAIL_BACK_BUFFER rational)
					if msg.cltv_expiry <= cur_height + HTLC_FAIL_BACK_BUFFER as u32 { // expiry_too_soon
						break Some(("CLTV expiry is too close", 0x1000 | 14, Some(self.get_channel_update(chan).unwrap())));
					}
					if msg.cltv_expiry > cur_height + CLTV_FAR_FAR_AWAY as u32 { // expiry_too_far
						break Some(("CLTV expiry is too far in the future", 21, None));
					}
					// In theory, we would be safe against unitentional channel-closure, if we only required a margin of LATENCY_GRACE_PERIOD_BLOCKS.
					// But, to be safe against policy reception, we use a longuer delay.
					if (*outgoing_cltv_value) as u64 <= (cur_height + HTLC_FAIL_BACK_BUFFER) as u64 {
						break Some(("Outgoing CLTV value is too soon", 0x1000 | 14, Some(self.get_channel_update(chan).unwrap())));
					}

					break None;
				}
				{
					let mut res = Vec::with_capacity(8 + 128);
					if let Some(chan_update) = chan_update {
						if code == 0x1000 | 11 || code == 0x1000 | 12 {
							res.extend_from_slice(&byte_utils::be64_to_array(msg.amount_msat));
						}
						else if code == 0x1000 | 13 {
							res.extend_from_slice(&byte_utils::be32_to_array(msg.cltv_expiry));
						}
						else if code == 0x1000 | 20 {
							// TODO: underspecified, follow https://github.com/lightningnetwork/lightning-rfc/issues/791
							res.extend_from_slice(&byte_utils::be16_to_array(0));
						}
						res.extend_from_slice(&chan_update.encode_with_len()[..]);
					}
					return_err!(err, code, &res[..]);
				}
			}
		}

		(pending_forward_info, channel_state.unwrap())
	}

	/// only fails if the channel does not yet have an assigned short_id
	/// May be called with channel_state already locked!
	fn get_channel_update(&self, chan: &Channel<Signer>) -> Result<msgs::ChannelUpdate, LightningError> {
		let short_channel_id = match chan.get_short_channel_id() {
			None => return Err(LightningError{err: "Channel not yet established".to_owned(), action: msgs::ErrorAction::IgnoreError}),
			Some(id) => id,
		};

		let were_node_one = PublicKey::from_secret_key(&self.secp_ctx, &self.our_network_key).serialize()[..] < chan.get_counterparty_node_id().serialize()[..];

		let unsigned = msgs::UnsignedChannelUpdate {
			chain_hash: self.genesis_hash,
			short_channel_id,
			timestamp: chan.get_update_time_counter(),
			flags: (!were_node_one) as u8 | ((!chan.is_live() as u8) << 1),
			cltv_expiry_delta: CLTV_EXPIRY_DELTA,
			htlc_minimum_msat: chan.get_counterparty_htlc_minimum_msat(),
			htlc_maximum_msat: OptionalField::Present(chan.get_announced_htlc_max_msat()),
			fee_base_msat: chan.get_holder_fee_base_msat(&self.fee_estimator),
			fee_proportional_millionths: chan.get_fee_proportional_millionths(),
			excess_data: Vec::new(),
		};

		let msg_hash = Sha256dHash::hash(&unsigned.encode()[..]);
		let sig = self.secp_ctx.sign(&hash_to_message!(&msg_hash[..]), &self.our_network_key);

		Ok(msgs::ChannelUpdate {
			signature: sig,
			contents: unsigned
		})
	}

	// Only public for testing, this should otherwise never be called direcly
	pub(crate) fn send_payment_along_path(&self, path: &Vec<RouteHop>, payment_hash: &PaymentHash, payment_secret: &Option<PaymentSecret>, total_value: u64, cur_height: u32) -> Result<(), APIError> {
		log_trace!(self.logger, "Attempting to send payment for path with next hop {}", path.first().unwrap().short_channel_id);
		let prng_seed = self.keys_manager.get_secure_random_bytes();
		let session_priv = SecretKey::from_slice(&self.keys_manager.get_secure_random_bytes()[..]).expect("RNG is busted");

		let onion_keys = onion_utils::construct_onion_keys(&self.secp_ctx, &path, &session_priv)
			.map_err(|_| APIError::RouteError{err: "Pubkey along hop was maliciously selected"})?;
		let (onion_payloads, htlc_msat, htlc_cltv) = onion_utils::build_onion_payloads(path, total_value, payment_secret, cur_height)?;
		if onion_utils::route_size_insane(&onion_payloads) {
			return Err(APIError::RouteError{err: "Route size too large considering onion data"});
		}
		let onion_packet = onion_utils::construct_onion_packet(onion_payloads, onion_keys, prng_seed, payment_hash);

		let _persistence_guard = PersistenceNotifierGuard::new(&self.total_consistency_lock, &self.persistence_notifier);

		let err: Result<(), _> = loop {
			let mut channel_lock = self.channel_state.lock().unwrap();
			let id = match channel_lock.short_to_id.get(&path.first().unwrap().short_channel_id) {
				None => return Err(APIError::ChannelUnavailable{err: "No channel available with first hop!".to_owned()}),
				Some(id) => id.clone(),
			};

			let channel_state = &mut *channel_lock;
			if let hash_map::Entry::Occupied(mut chan) = channel_state.by_id.entry(id) {
				match {
					if chan.get().get_counterparty_node_id() != path.first().unwrap().pubkey {
						return Err(APIError::RouteError{err: "Node ID mismatch on first hop!"});
					}
					if !chan.get().is_live() {
						return Err(APIError::ChannelUnavailable{err: "Peer for first hop currently disconnected/pending monitor update!".to_owned()});
					}
					break_chan_entry!(self, chan.get_mut().send_htlc_and_commit(htlc_msat, payment_hash.clone(), htlc_cltv, HTLCSource::OutboundRoute {
						path: path.clone(),
						session_priv: session_priv.clone(),
						first_hop_htlc_msat: htlc_msat,
					}, onion_packet, &self.logger), channel_state, chan)
				} {
					Some((update_add, commitment_signed, monitor_update)) => {
						if let Err(e) = self.chain_monitor.update_channel(chan.get().get_funding_txo().unwrap(), monitor_update) {
							maybe_break_monitor_err!(self, e, channel_state, chan, RAACommitmentOrder::CommitmentFirst, false, true);
							// Note that MonitorUpdateFailed here indicates (per function docs)
							// that we will resend the commitment update once monitor updating
							// is restored. Therefore, we must return an error indicating that
							// it is unsafe to retry the payment wholesale, which we do in the
							// send_payment check for MonitorUpdateFailed, below.
							return Err(APIError::MonitorUpdateFailed);
						}

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
					None => {},
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
	pub fn send_payment(&self, route: &Route, payment_hash: PaymentHash, payment_secret: &Option<PaymentSecret>) -> Result<(), PaymentSendFailure> {
		if route.paths.len() < 1 {
			return Err(PaymentSendFailure::ParameterError(APIError::RouteError{err: "There must be at least one path to send over"}));
		}
		if route.paths.len() > 10 {
			// This limit is completely arbitrary - there aren't any real fundamental path-count
			// limits. After we support retrying individual paths we should likely bump this, but
			// for now more than 10 paths likely carries too much one-path failure.
			return Err(PaymentSendFailure::ParameterError(APIError::RouteError{err: "Sending over more than 10 paths is not currently supported"}));
		}
		let mut total_value = 0;
		let our_node_id = self.get_our_node_id();
		let mut path_errs = Vec::with_capacity(route.paths.len());
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

		let cur_height = self.latest_block_height.load(Ordering::Acquire) as u32 + 1;
		let mut results = Vec::new();
		for path in route.paths.iter() {
			results.push(self.send_payment_along_path(&path, &payment_hash, payment_secret, total_value, cur_height));
		}
		let mut has_ok = false;
		let mut has_err = false;
		for res in results.iter() {
			if res.is_ok() { has_ok = true; }
			if res.is_err() { has_err = true; }
			if let &Err(APIError::MonitorUpdateFailed) = res {
				// MonitorUpdateFailed is inherently unsafe to retry, so we call it a
				// PartialFailure.
				has_err = true;
				has_ok = true;
				break;
			}
		}
		if has_err && has_ok {
			Err(PaymentSendFailure::PartialFailure(results))
		} else if has_err {
			Err(PaymentSendFailure::AllFailedRetrySafe(results.drain(..).map(|r| r.unwrap_err()).collect()))
		} else {
			Ok(())
		}
	}

	/// Call this upon creation of a funding transaction for the given channel.
	///
	/// Note that ALL inputs in the transaction pointed to by funding_txo MUST spend SegWit outputs
	/// or your counterparty can steal your funds!
	///
	/// Panics if a funding transaction has already been provided for this channel.
	///
	/// May panic if the funding_txo is duplicative with some other channel (note that this should
	/// be trivially prevented by using unique funding transaction keys per-channel).
	pub fn funding_transaction_generated(&self, temporary_channel_id: &[u8; 32], funding_txo: OutPoint) {
		let _persistence_guard = PersistenceNotifierGuard::new(&self.total_consistency_lock, &self.persistence_notifier);

		let (chan, msg) = {
			let (res, chan) = match self.channel_state.lock().unwrap().by_id.remove(temporary_channel_id) {
				Some(mut chan) => {
					(chan.get_outbound_funding_created(funding_txo, &self.logger)
						.map_err(|e| if let ChannelError::Close(msg) = e {
							MsgHandleErrInternal::from_finish_shutdown(msg, chan.channel_id(), chan.force_shutdown(true), None)
						} else { unreachable!(); })
					, chan)
				},
				None => return
			};
			match handle_error!(self, res, chan.get_counterparty_node_id()) {
				Ok(funding_msg) => {
					(chan, funding_msg)
				},
				Err(_) => { return; }
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
	}

	fn get_announcement_sigs(&self, chan: &Channel<Signer>) -> Option<msgs::AnnouncementSignatures> {
		if !chan.should_announce() {
			log_trace!(self.logger, "Can't send announcement_signatures for private channel {}", log_bytes!(chan.channel_id()));
			return None
		}

		let (announcement, our_bitcoin_sig) = match chan.get_channel_announcement(self.get_our_node_id(), self.genesis_hash.clone()) {
			Ok(res) => res,
			Err(_) => return None, // Only in case of state precondition violations eg channel is closing
		};
		let msghash = hash_to_message!(&Sha256dHash::hash(&announcement.encode()[..])[..]);
		let our_node_sig = self.secp_ctx.sign(&msghash, &self.our_network_key);

		Some(msgs::AnnouncementSignatures {
			channel_id: chan.channel_id(),
			short_channel_id: chan.get_short_channel_id().unwrap(),
			node_signature: our_node_sig,
			bitcoin_signature: our_bitcoin_sig,
		})
	}

	#[allow(dead_code)]
	// Messages of up to 64KB should never end up more than half full with addresses, as that would
	// be absurd. We ensure this by checking that at least 500 (our stated public contract on when
	// broadcast_node_announcement panics) of the maximum-length addresses would fit in a 64KB
	// message...
	const HALF_MESSAGE_IS_ADDRS: u32 = ::std::u16::MAX as u32 / (NetAddress::MAX_LEN as u32 + 1) / 2;
	#[deny(const_err)]
	#[allow(dead_code)]
	// ...by failing to compile if the number of addresses that would be half of a message is
	// smaller than 500:
	const STATIC_ASSERT: u32 = Self::HALF_MESSAGE_IS_ADDRS - 500;

	/// Generates a signed node_announcement from the given arguments and creates a
	/// BroadcastNodeAnnouncement event. Note that such messages will be ignored unless peers have
	/// seen a channel_announcement from us (ie unless we have public channels open).
	///
	/// RGB is a node "color" and alias is a printable human-readable string to describe this node
	/// to humans. They carry no in-protocol meaning.
	///
	/// addresses represent the set (possibly empty) of socket addresses on which this node accepts
	/// incoming connections. These will be broadcast to the network, publicly tying these
	/// addresses together. If you wish to preserve user privacy, addresses should likely contain
	/// only Tor Onion addresses.
	///
	/// Panics if addresses is absurdly large (more than 500).
	pub fn broadcast_node_announcement(&self, rgb: [u8; 3], alias: [u8; 32], addresses: Vec<NetAddress>) {
		let _persistence_guard = PersistenceNotifierGuard::new(&self.total_consistency_lock, &self.persistence_notifier);

		if addresses.len() > 500 {
			panic!("More than half the message size was taken up by public addresses!");
		}

		let announcement = msgs::UnsignedNodeAnnouncement {
			features: NodeFeatures::known(),
			timestamp: self.last_node_announcement_serial.fetch_add(1, Ordering::AcqRel) as u32,
			node_id: self.get_our_node_id(),
			rgb, alias, addresses,
			excess_address_data: Vec::new(),
			excess_data: Vec::new(),
		};
		let msghash = hash_to_message!(&Sha256dHash::hash(&announcement.encode()[..])[..]);

		let mut channel_state = self.channel_state.lock().unwrap();
		channel_state.pending_msg_events.push(events::MessageSendEvent::BroadcastNodeAnnouncement {
			msg: msgs::NodeAnnouncement {
				signature: self.secp_ctx.sign(&msghash, &self.our_network_key),
				contents: announcement
			},
		});
	}

	/// Processes HTLCs which are pending waiting on random forward delay.
	///
	/// Should only really ever be called in response to a PendingHTLCsForwardable event.
	/// Will likely generate further events.
	pub fn process_pending_htlc_forwards(&self) {
		let _persistence_guard = PersistenceNotifierGuard::new(&self.total_consistency_lock, &self.persistence_notifier);

		let mut new_events = Vec::new();
		let mut failed_forwards = Vec::new();
		let mut handle_errors = Vec::new();
		{
			let mut channel_state_lock = self.channel_state.lock().unwrap();
			let channel_state = &mut *channel_state_lock;

			for (short_chan_id, mut pending_forwards) in channel_state.forward_htlcs.drain() {
				if short_chan_id != 0 {
					let forward_chan_id = match channel_state.short_to_id.get(&short_chan_id) {
						Some(chan_id) => chan_id.clone(),
						None => {
							failed_forwards.reserve(pending_forwards.len());
							for forward_info in pending_forwards.drain(..) {
								match forward_info {
									HTLCForwardInfo::AddHTLC { prev_short_channel_id, prev_htlc_id, forward_info,
									                           prev_funding_outpoint } => {
										let htlc_source = HTLCSource::PreviousHopData(HTLCPreviousHopData {
											short_channel_id: prev_short_channel_id,
											outpoint: prev_funding_outpoint,
											htlc_id: prev_htlc_id,
											incoming_packet_shared_secret: forward_info.incoming_shared_secret,
										});
										failed_forwards.push((htlc_source, forward_info.payment_hash,
											HTLCFailReason::Reason { failure_code: 0x4000 | 10, data: Vec::new() }
										));
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
									log_trace!(self.logger, "Adding HTLC from short id {} with payment_hash {} to channel with short id {} after delay", log_bytes!(payment_hash.0), prev_short_channel_id, short_chan_id);
									let htlc_source = HTLCSource::PreviousHopData(HTLCPreviousHopData {
										short_channel_id: prev_short_channel_id,
										outpoint: prev_funding_outpoint,
										htlc_id: prev_htlc_id,
										incoming_packet_shared_secret: incoming_shared_secret,
									});
									match chan.get_mut().send_htlc(amt_to_forward, payment_hash, outgoing_cltv_value, htlc_source.clone(), onion_packet) {
										Err(e) => {
											if let ChannelError::Ignore(msg) = e {
												log_trace!(self.logger, "Failed to forward HTLC with payment_hash {}: {}", log_bytes!(payment_hash.0), msg);
											} else {
												panic!("Stated return value requirements in send_htlc() were not met");
											}
											let chan_update = self.get_channel_update(chan.get()).unwrap();
											failed_forwards.push((htlc_source, payment_hash,
												HTLCFailReason::Reason { failure_code: 0x1000 | 7, data: chan_update.encode_with_len() }
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
									log_trace!(self.logger, "Failing HTLC back to channel with short id {} after delay", short_chan_id);
									match chan.get_mut().get_update_fail_htlc(htlc_id, err_packet) {
										Err(e) => {
											if let ChannelError::Ignore(msg) = e {
												log_trace!(self.logger, "Failed to fail backwards to short_id {}: {}", short_chan_id, msg);
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
										ChannelError::Ignore(_) => {
											panic!("Stated return value requirements in send_commitment() were not met");
										},
										ChannelError::Close(msg) => {
											log_trace!(self.logger, "Closing channel {} due to Close-required error: {}", log_bytes!(chan.key()[..]), msg);
											let (channel_id, mut channel) = chan.remove_entry();
											if let Some(short_id) = channel.get_short_channel_id() {
												channel_state.short_to_id.remove(&short_id);
											}
											Err(MsgHandleErrInternal::from_finish_shutdown(msg, channel_id, channel.force_shutdown(true), self.get_channel_update(&channel).ok()))
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
									routing: PendingHTLCRouting::Receive { payment_data, incoming_cltv_expiry },
									incoming_shared_secret, payment_hash, amt_to_forward, .. },
									prev_funding_outpoint } => {
								let prev_hop = HTLCPreviousHopData {
									short_channel_id: prev_short_channel_id,
									outpoint: prev_funding_outpoint,
									htlc_id: prev_htlc_id,
									incoming_packet_shared_secret: incoming_shared_secret,
								};

								let mut total_value = 0;
								let payment_secret_opt =
									if let &Some(ref data) = &payment_data { Some(data.payment_secret.clone()) } else { None };
								let htlcs = channel_state.claimable_htlcs.entry((payment_hash, payment_secret_opt))
									.or_insert(Vec::new());
								htlcs.push(ClaimableHTLC {
									prev_hop,
									value: amt_to_forward,
									payment_data: payment_data.clone(),
									cltv_expiry: incoming_cltv_expiry,
								});
								if let &Some(ref data) = &payment_data {
									for htlc in htlcs.iter() {
										total_value += htlc.value;
										if htlc.payment_data.as_ref().unwrap().total_msat != data.total_msat {
											total_value = msgs::MAX_VALUE_MSAT;
										}
										if total_value >= msgs::MAX_VALUE_MSAT { break; }
									}
									if total_value >= msgs::MAX_VALUE_MSAT || total_value > data.total_msat  {
										for htlc in htlcs.iter() {
											let mut htlc_msat_height_data = byte_utils::be64_to_array(htlc.value).to_vec();
											htlc_msat_height_data.extend_from_slice(
												&byte_utils::be32_to_array(
													self.latest_block_height.load(Ordering::Acquire)
														as u32,
												),
											);
											failed_forwards.push((HTLCSource::PreviousHopData(HTLCPreviousHopData {
													short_channel_id: htlc.prev_hop.short_channel_id,
													outpoint: prev_funding_outpoint,
													htlc_id: htlc.prev_hop.htlc_id,
													incoming_packet_shared_secret: htlc.prev_hop.incoming_packet_shared_secret,
												}), payment_hash,
												HTLCFailReason::Reason { failure_code: 0x4000 | 15, data: htlc_msat_height_data }
											));
										}
									} else if total_value == data.total_msat {
										new_events.push(events::Event::PaymentReceived {
											payment_hash,
											payment_secret: Some(data.payment_secret),
											amt: total_value,
										});
									}
								} else {
									new_events.push(events::Event::PaymentReceived {
										payment_hash,
										payment_secret: None,
										amt: amt_to_forward,
									});
								}
							},
							HTLCForwardInfo::AddHTLC { .. } => {
								panic!("short_channel_id == 0 should imply any pending_forward entries are of type Receive");
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

		for (counterparty_node_id, err) in handle_errors.drain(..) {
			let _ = handle_error!(self, err, counterparty_node_id);
		}

		if new_events.is_empty() { return }
		let mut events = self.pending_events.lock().unwrap();
		events.append(&mut new_events);
	}

	/// If a peer is disconnected we mark any channels with that peer as 'disabled'.
	/// After some time, if channels are still disabled we need to broadcast a ChannelUpdate
	/// to inform the network about the uselessness of these channels.
	///
	/// This method handles all the details, and must be called roughly once per minute.
	pub fn timer_chan_freshness_every_min(&self) {
		let _persistence_guard = PersistenceNotifierGuard::new(&self.total_consistency_lock, &self.persistence_notifier);
		let mut channel_state_lock = self.channel_state.lock().unwrap();
		let channel_state = &mut *channel_state_lock;
		for (_, chan) in channel_state.by_id.iter_mut() {
			if chan.is_disabled_staged() && !chan.is_live() {
				if let Ok(update) = self.get_channel_update(&chan) {
					channel_state.pending_msg_events.push(events::MessageSendEvent::BroadcastChannelUpdate {
						msg: update
					});
				}
				chan.to_fresh();
			} else if chan.is_disabled_staged() && chan.is_live() {
				chan.to_fresh();
			} else if chan.is_disabled_marked() {
				chan.to_disabled_staged();
			}
		}
	}

	/// Indicates that the preimage for payment_hash is unknown or the received amount is incorrect
	/// after a PaymentReceived event, failing the HTLC back to its origin and freeing resources
	/// along the path (including in our own channel on which we received it).
	/// Returns false if no payment was found to fail backwards, true if the process of failing the
	/// HTLC backwards has been started.
	pub fn fail_htlc_backwards(&self, payment_hash: &PaymentHash, payment_secret: &Option<PaymentSecret>) -> bool {
		let _persistence_guard = PersistenceNotifierGuard::new(&self.total_consistency_lock, &self.persistence_notifier);

		let mut channel_state = Some(self.channel_state.lock().unwrap());
		let removed_source = channel_state.as_mut().unwrap().claimable_htlcs.remove(&(*payment_hash, *payment_secret));
		if let Some(mut sources) = removed_source {
			for htlc in sources.drain(..) {
				if channel_state.is_none() { channel_state = Some(self.channel_state.lock().unwrap()); }
				let mut htlc_msat_height_data = byte_utils::be64_to_array(htlc.value).to_vec();
				htlc_msat_height_data.extend_from_slice(&byte_utils::be32_to_array(
					self.latest_block_height.load(Ordering::Acquire) as u32,
				));
				self.fail_htlc_backwards_internal(channel_state.take().unwrap(),
						HTLCSource::PreviousHopData(htlc.prev_hop), payment_hash,
						HTLCFailReason::Reason { failure_code: 0x4000 | 15, data: htlc_msat_height_data });
			}
			true
		} else { false }
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
								if let Ok(upd) = self.get_channel_update(&chan_entry.get()) {
									(0x1000|7, upd.encode_with_len())
								} else {
									(0x4000|10, Vec::new())
								}
							},
							hash_map::Entry::Vacant(_) => (0x4000|10, Vec::new())
						};
					let channel_state = self.channel_state.lock().unwrap();
					self.fail_htlc_backwards_internal(channel_state,
						htlc_src, &payment_hash, HTLCFailReason::Reason { failure_code, data: onion_failure_data});
				},
				HTLCSource::OutboundRoute { .. } => {
					self.pending_events.lock().unwrap().push(
						events::Event::PaymentFailed {
							payment_hash,
							rejected_by_dest: false,
#[cfg(test)]
							error_code: None,
#[cfg(test)]
							error_data: None,
						}
					)
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
		match source {
			HTLCSource::OutboundRoute { ref path, .. } => {
				log_trace!(self.logger, "Failing outbound payment HTLC with payment_hash {}", log_bytes!(payment_hash.0));
				mem::drop(channel_state_lock);
				match &onion_error {
					&HTLCFailReason::LightningError { ref err } => {
#[cfg(test)]
						let (channel_update, payment_retryable, onion_error_code, onion_error_data) = onion_utils::process_onion_failure(&self.secp_ctx, &self.logger, &source, err.data.clone());
#[cfg(not(test))]
						let (channel_update, payment_retryable, _, _) = onion_utils::process_onion_failure(&self.secp_ctx, &self.logger, &source, err.data.clone());
						// TODO: If we decided to blame ourselves (or one of our channels) in
						// process_onion_failure we should close that channel as it implies our
						// next-hop is needlessly blaming us!
						if let Some(update) = channel_update {
							self.channel_state.lock().unwrap().pending_msg_events.push(
								events::MessageSendEvent::PaymentFailureNetworkUpdate {
									update,
								}
							);
						}
						self.pending_events.lock().unwrap().push(
							events::Event::PaymentFailed {
								payment_hash: payment_hash.clone(),
								rejected_by_dest: !payment_retryable,
#[cfg(test)]
								error_code: onion_error_code,
#[cfg(test)]
								error_data: onion_error_data
							}
						);
					},
					&HTLCFailReason::Reason {
#[cfg(test)]
							ref failure_code,
#[cfg(test)]
							ref data,
							.. } => {
						// we get a fail_malformed_htlc from the first hop
						// TODO: We'd like to generate a PaymentFailureNetworkUpdate for temporary
						// failures here, but that would be insufficient as get_route
						// generally ignores its view of our own channels as we provide them via
						// ChannelDetails.
						// TODO: For non-temporary failures, we really should be closing the
						// channel here as we apparently can't relay through them anyway.
						self.pending_events.lock().unwrap().push(
							events::Event::PaymentFailed {
								payment_hash: payment_hash.clone(),
								rejected_by_dest: path.len() == 1,
#[cfg(test)]
								error_code: Some(*failure_code),
#[cfg(test)]
								error_data: Some(data.clone()),
							}
						);
					}
				}
			},
			HTLCSource::PreviousHopData(HTLCPreviousHopData { short_channel_id, htlc_id, incoming_packet_shared_secret, .. }) => {
				let err_packet = match onion_error {
					HTLCFailReason::Reason { failure_code, data } => {
						log_trace!(self.logger, "Failing HTLC with payment_hash {} backwards from us with code {}", log_bytes!(payment_hash.0), failure_code);
						let packet = onion_utils::build_failure_packet(&incoming_packet_shared_secret, failure_code, &data[..]).encode();
						onion_utils::encrypt_failure_packet(&incoming_packet_shared_secret, &packet)
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

	/// Provides a payment preimage in response to a PaymentReceived event, returning true and
	/// generating message events for the net layer to claim the payment, if possible. Thus, you
	/// should probably kick the net layer to go send messages if this returns true!
	///
	/// You must specify the expected amounts for this HTLC, and we will only claim HTLCs
	/// available within a few percent of the expected amount. This is critical for several
	/// reasons : a) it avoids providing senders with `proof-of-payment` (in the form of the
	/// payment_preimage without having provided the full value and b) it avoids certain
	/// privacy-breaking recipient-probing attacks which may reveal payment activity to
	/// motivated attackers.
	///
	/// Note that the privacy concerns in (b) are not relevant in payments with a payment_secret
	/// set. Thus, for such payments we will claim any payments which do not under-pay.
	///
	/// May panic if called except in response to a PaymentReceived event.
	pub fn claim_funds(&self, payment_preimage: PaymentPreimage, payment_secret: &Option<PaymentSecret>, expected_amount: u64) -> bool {
		let payment_hash = PaymentHash(Sha256::hash(&payment_preimage.0).into_inner());

		let _persistence_guard = PersistenceNotifierGuard::new(&self.total_consistency_lock, &self.persistence_notifier);

		let mut channel_state = Some(self.channel_state.lock().unwrap());
		let removed_source = channel_state.as_mut().unwrap().claimable_htlcs.remove(&(payment_hash, *payment_secret));
		if let Some(mut sources) = removed_source {
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

			let (is_mpp, mut valid_mpp) = if let &Some(ref data) = &sources[0].payment_data {
				assert!(payment_secret.is_some());
				(true, data.total_msat >= expected_amount)
			} else {
				assert!(payment_secret.is_none());
				(false, false)
			};

			for htlc in sources.iter() {
				if !is_mpp || !valid_mpp { break; }
				if let None = channel_state.as_ref().unwrap().short_to_id.get(&htlc.prev_hop.short_channel_id) {
					valid_mpp = false;
				}
			}

			let mut errs = Vec::new();
			let mut claimed_any_htlcs = false;
			for htlc in sources.drain(..) {
				if channel_state.is_none() { channel_state = Some(self.channel_state.lock().unwrap()); }
				if (is_mpp && !valid_mpp) || (!is_mpp && (htlc.value < expected_amount || htlc.value > expected_amount * 2)) {
					let mut htlc_msat_height_data = byte_utils::be64_to_array(htlc.value).to_vec();
					htlc_msat_height_data.extend_from_slice(&byte_utils::be32_to_array(
						self.latest_block_height.load(Ordering::Acquire) as u32,
					));
					self.fail_htlc_backwards_internal(channel_state.take().unwrap(),
									 HTLCSource::PreviousHopData(htlc.prev_hop), &payment_hash,
									 HTLCFailReason::Reason { failure_code: 0x4000|15, data: htlc_msat_height_data });
				} else {
					match self.claim_funds_from_hop(channel_state.as_mut().unwrap(), htlc.prev_hop, payment_preimage) {
						Err(Some(e)) => {
							if let msgs::ErrorAction::IgnoreError = e.1.err.action {
								// We got a temporary failure updating monitor, but will claim the
								// HTLC when the monitor updating is restored (or on chain).
								log_error!(self.logger, "Temporary failure claiming HTLC, treating as success: {}", e.1.err.err);
								claimed_any_htlcs = true;
							} else { errs.push(e); }
						},
						Err(None) if is_mpp => unreachable!("We already checked for channel existence, we can't fail here!"),
						Err(None) => {
							log_warn!(self.logger, "Channel we expected to claim an HTLC from was closed.");
						},
						Ok(()) => claimed_any_htlcs = true,
					}
				}
			}

			// Now that we've done the entire above loop in one lock, we can handle any errors
			// which were generated.
			channel_state.take();

			for (counterparty_node_id, err) in errs.drain(..) {
				let res: Result<(), _> = Err(err);
				let _ = handle_error!(self, res, counterparty_node_id);
			}

			claimed_any_htlcs
		} else { false }
	}

	fn claim_funds_from_hop(&self, channel_state_lock: &mut MutexGuard<ChannelHolder<Signer>>, prev_hop: HTLCPreviousHopData, payment_preimage: PaymentPreimage) -> Result<(), Option<(PublicKey, MsgHandleErrInternal)>> {
		//TODO: Delay the claimed_funds relaying just like we do outbound relay!
		let channel_state = &mut **channel_state_lock;
		let chan_id = match channel_state.short_to_id.get(&prev_hop.short_channel_id) {
			Some(chan_id) => chan_id.clone(),
			None => {
				return Err(None)
			}
		};

		if let hash_map::Entry::Occupied(mut chan) = channel_state.by_id.entry(chan_id) {
			let was_frozen_for_monitor = chan.get().is_awaiting_monitor_update();
			match chan.get_mut().get_update_fulfill_htlc_and_commit(prev_hop.htlc_id, payment_preimage, &self.logger) {
				Ok((msgs, monitor_option)) => {
					if let Some(monitor_update) = monitor_option {
						if let Err(e) = self.chain_monitor.update_channel(chan.get().get_funding_txo().unwrap(), monitor_update) {
							if was_frozen_for_monitor {
								assert!(msgs.is_none());
							} else {
								return Err(Some((chan.get().get_counterparty_node_id(), handle_monitor_err!(self, e, channel_state, chan, RAACommitmentOrder::CommitmentFirst, false, msgs.is_some()).unwrap_err())));
							}
						}
					}
					if let Some((msg, commitment_signed)) = msgs {
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
					return Ok(())
				},
				Err(e) => {
					// TODO: Do something with e?
					// This should only occur if we are claiming an HTLC at the same time as the
					// HTLC is being failed (eg because a block is being connected and this caused
					// an HTLC to time out). This should, of course, only occur if the user is the
					// one doing the claiming (as it being a part of a peer claim would imply we're
					// about to lose funds) and only if the lock in claim_funds was dropped as a
					// previous HTLC was failed (thus not for an MPP payment).
					debug_assert!(false, "This shouldn't be reachable except in absurdly rare cases between monitor updates and HTLC timeouts: {:?}", e);
					return Err(None)
				},
			}
		} else { unreachable!(); }
	}

	fn claim_funds_internal(&self, mut channel_state_lock: MutexGuard<ChannelHolder<Signer>>, source: HTLCSource, payment_preimage: PaymentPreimage) {
		match source {
			HTLCSource::OutboundRoute { .. } => {
				mem::drop(channel_state_lock);
				let mut pending_events = self.pending_events.lock().unwrap();
				pending_events.push(events::Event::PaymentSent {
					payment_preimage
				});
			},
			HTLCSource::PreviousHopData(hop_data) => {
				let prev_outpoint = hop_data.outpoint;
				if let Err((counterparty_node_id, err)) = match self.claim_funds_from_hop(&mut channel_state_lock, hop_data, payment_preimage) {
					Ok(()) => Ok(()),
					Err(None) => {
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
						Ok(())
					},
					Err(Some(res)) => Err(res),
				} {
					mem::drop(channel_state_lock);
					let res: Result<(), _> = Err(err);
					let _ = handle_error!(self, res, counterparty_node_id);
				}
			},
		}
	}

	/// Gets the node_id held by this ChannelManager
	pub fn get_our_node_id(&self) -> PublicKey {
		PublicKey::from_secret_key(&self.secp_ctx, &self.our_network_key)
	}

	/// Restores a single, given channel to normal operation after a
	/// ChannelMonitorUpdateErr::TemporaryFailure was returned from a channel monitor update
	/// operation.
	///
	/// All ChannelMonitor updates up to and including highest_applied_update_id must have been
	/// fully committed in every copy of the given channels' ChannelMonitors.
	///
	/// Note that there is no effect to calling with a highest_applied_update_id other than the
	/// current latest ChannelMonitorUpdate and one call to this function after multiple
	/// ChannelMonitorUpdateErr::TemporaryFailures is fine. The highest_applied_update_id field
	/// exists largely only to prevent races between this and concurrent update_monitor calls.
	///
	/// Thus, the anticipated use is, at a high level:
	///  1) You register a chain::Watch with this ChannelManager,
	///  2) it stores each update to disk, and begins updating any remote (eg watchtower) copies of
	///     said ChannelMonitors as it can, returning ChannelMonitorUpdateErr::TemporaryFailures
	///     any time it cannot do so instantly,
	///  3) update(s) are applied to each remote copy of a ChannelMonitor,
	///  4) once all remote copies are updated, you call this function with the update_id that
	///     completed, and once it is the latest the Channel will be re-enabled.
	pub fn channel_monitor_updated(&self, funding_txo: &OutPoint, highest_applied_update_id: u64) {
		let _persistence_guard = PersistenceNotifierGuard::new(&self.total_consistency_lock, &self.persistence_notifier);

		let mut close_results = Vec::new();
		let mut htlc_forwards = Vec::new();
		let mut htlc_failures = Vec::new();
		let mut pending_events = Vec::new();

		{
			let mut channel_lock = self.channel_state.lock().unwrap();
			let channel_state = &mut *channel_lock;
			let short_to_id = &mut channel_state.short_to_id;
			let pending_msg_events = &mut channel_state.pending_msg_events;
			let channel = match channel_state.by_id.get_mut(&funding_txo.to_channel_id()) {
				Some(chan) => chan,
				None => return,
			};
			if !channel.is_awaiting_monitor_update() || channel.get_latest_monitor_update_id() != highest_applied_update_id {
				return;
			}

			let (raa, commitment_update, order, pending_forwards, mut pending_failures, needs_broadcast_safe, funding_locked) = channel.monitor_updating_restored(&self.logger);
			if !pending_forwards.is_empty() {
				htlc_forwards.push((channel.get_short_channel_id().expect("We can't have pending forwards before funding confirmation"), funding_txo.clone(), pending_forwards));
			}
			htlc_failures.append(&mut pending_failures);

			macro_rules! handle_cs { () => {
				if let Some(update) = commitment_update {
					pending_msg_events.push(events::MessageSendEvent::UpdateHTLCs {
						node_id: channel.get_counterparty_node_id(),
						updates: update,
					});
				}
			} }
			macro_rules! handle_raa { () => {
				if let Some(revoke_and_ack) = raa {
					pending_msg_events.push(events::MessageSendEvent::SendRevokeAndACK {
						node_id: channel.get_counterparty_node_id(),
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
			if needs_broadcast_safe {
				pending_events.push(events::Event::FundingBroadcastSafe {
					funding_txo: channel.get_funding_txo().unwrap(),
					user_channel_id: channel.get_user_id(),
				});
			}
			if let Some(msg) = funding_locked {
				pending_msg_events.push(events::MessageSendEvent::SendFundingLocked {
					node_id: channel.get_counterparty_node_id(),
					msg,
				});
				if let Some(announcement_sigs) = self.get_announcement_sigs(channel) {
					pending_msg_events.push(events::MessageSendEvent::SendAnnouncementSignatures {
						node_id: channel.get_counterparty_node_id(),
						msg: announcement_sigs,
					});
				}
				short_to_id.insert(channel.get_short_channel_id().unwrap(), channel.channel_id());
			}
		}

		self.pending_events.lock().unwrap().append(&mut pending_events);

		for failure in htlc_failures.drain(..) {
			self.fail_htlc_backwards_internal(self.channel_state.lock().unwrap(), failure.0, &failure.1, failure.2);
		}
		self.forward_htlcs(&mut htlc_forwards[..]);

		for res in close_results.drain(..) {
			self.finish_force_close_channel(res);
		}
	}

	fn internal_open_channel(&self, counterparty_node_id: &PublicKey, their_features: InitFeatures, msg: &msgs::OpenChannel) -> Result<(), MsgHandleErrInternal> {
		if msg.chain_hash != self.genesis_hash {
			return Err(MsgHandleErrInternal::send_err_msg_no_close("Unknown genesis block hash".to_owned(), msg.temporary_channel_id.clone()));
		}

		let channel = Channel::new_from_req(&self.fee_estimator, &self.keys_manager, counterparty_node_id.clone(), their_features, msg, 0, &self.default_configuration)
			.map_err(|e| MsgHandleErrInternal::from_chan_no_close(e, msg.temporary_channel_id))?;
		let mut channel_state_lock = self.channel_state.lock().unwrap();
		let channel_state = &mut *channel_state_lock;
		match channel_state.by_id.entry(channel.channel_id()) {
			hash_map::Entry::Occupied(_) => return Err(MsgHandleErrInternal::send_err_msg_no_close("temporary_channel_id collision!".to_owned(), msg.temporary_channel_id.clone())),
			hash_map::Entry::Vacant(entry) => {
				channel_state.pending_msg_events.push(events::MessageSendEvent::SendAcceptChannel {
					node_id: counterparty_node_id.clone(),
					msg: channel.get_accept_channel(),
				});
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
					try_chan_entry!(self, chan.get_mut().accept_channel(&msg, &self.default_configuration, their_features), channel_state, chan);
					(chan.get().get_value_satoshis(), chan.get().get_funding_redeemscript().to_v0_p2wsh(), chan.get().get_user_id())
				},
				hash_map::Entry::Vacant(_) => return Err(MsgHandleErrInternal::send_err_msg_no_close("Failed to find corresponding channel".to_owned(), msg.temporary_channel_id))
			}
		};
		let mut pending_events = self.pending_events.lock().unwrap();
		pending_events.push(events::Event::FundingGenerationReady {
			temporary_channel_id: msg.temporary_channel_id,
			channel_value_satoshis: value,
			output_script,
			user_channel_id: user_id,
		});
		Ok(())
	}

	fn internal_funding_created(&self, counterparty_node_id: &PublicKey, msg: &msgs::FundingCreated) -> Result<(), MsgHandleErrInternal> {
		let ((funding_msg, monitor), mut chan) = {
			let mut channel_lock = self.channel_state.lock().unwrap();
			let channel_state = &mut *channel_lock;
			match channel_state.by_id.entry(msg.temporary_channel_id.clone()) {
				hash_map::Entry::Occupied(mut chan) => {
					if chan.get().get_counterparty_node_id() != *counterparty_node_id {
						return Err(MsgHandleErrInternal::send_err_msg_no_close("Got a message for a channel from the wrong node!".to_owned(), msg.temporary_channel_id));
					}
					(try_chan_entry!(self, chan.get_mut().funding_created(msg, &self.logger), channel_state, chan), chan.remove())
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
					let (_funding_txo_option, _monitor_update, failed_htlcs) = chan.force_shutdown(true);
					assert!(failed_htlcs.is_empty());
					return Err(MsgHandleErrInternal::send_err_msg_no_close("ChannelMonitor storage failure".to_owned(), funding_msg.channel_id));
				},
				ChannelMonitorUpdateErr::TemporaryFailure => {
					// There's no problem signing a counterparty's funding transaction if our monitor
					// hasn't persisted to disk yet - we can't lose money on a transaction that we haven't
					// accepted payment from yet. We do, however, need to wait to send our funding_locked
					// until we have persisted our monitor.
					chan.monitor_update_failed(false, false, Vec::new(), Vec::new());
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
				e.insert(chan);
			}
		}
		Ok(())
	}

	fn internal_funding_signed(&self, counterparty_node_id: &PublicKey, msg: &msgs::FundingSigned) -> Result<(), MsgHandleErrInternal> {
		let (funding_txo, user_id) = {
			let mut channel_lock = self.channel_state.lock().unwrap();
			let channel_state = &mut *channel_lock;
			match channel_state.by_id.entry(msg.channel_id) {
				hash_map::Entry::Occupied(mut chan) => {
					if chan.get().get_counterparty_node_id() != *counterparty_node_id {
						return Err(MsgHandleErrInternal::send_err_msg_no_close("Got a message for a channel from the wrong node!".to_owned(), msg.channel_id));
					}
					let monitor = match chan.get_mut().funding_signed(&msg, &self.logger) {
						Ok(update) => update,
						Err(e) => try_chan_entry!(self, Err(e), channel_state, chan),
					};
					if let Err(e) = self.chain_monitor.watch_channel(chan.get().get_funding_txo().unwrap(), monitor) {
						return_monitor_err!(self, e, channel_state, chan, RAACommitmentOrder::RevokeAndACKFirst, false, false);
					}
					(chan.get().get_funding_txo().unwrap(), chan.get().get_user_id())
				},
				hash_map::Entry::Vacant(_) => return Err(MsgHandleErrInternal::send_err_msg_no_close("Failed to find corresponding channel".to_owned(), msg.channel_id))
			}
		};
		let mut pending_events = self.pending_events.lock().unwrap();
		pending_events.push(events::Event::FundingBroadcastSafe {
			funding_txo,
			user_channel_id: user_id,
		});
		Ok(())
	}

	fn internal_funding_locked(&self, counterparty_node_id: &PublicKey, msg: &msgs::FundingLocked) -> Result<(), MsgHandleErrInternal> {
		let mut channel_state_lock = self.channel_state.lock().unwrap();
		let channel_state = &mut *channel_state_lock;
		match channel_state.by_id.entry(msg.channel_id) {
			hash_map::Entry::Occupied(mut chan) => {
				if chan.get().get_counterparty_node_id() != *counterparty_node_id {
					return Err(MsgHandleErrInternal::send_err_msg_no_close("Got a message for a channel from the wrong node!".to_owned(), msg.channel_id));
				}
				try_chan_entry!(self, chan.get_mut().funding_locked(&msg), channel_state, chan);
				if let Some(announcement_sigs) = self.get_announcement_sigs(chan.get()) {
					log_trace!(self.logger, "Sending announcement_signatures for {} in response to funding_locked", log_bytes!(chan.get().channel_id()));
					// If we see locking block before receiving remote funding_locked, we broadcast our
					// announcement_sigs at remote funding_locked reception. If we receive remote
					// funding_locked before seeing locking block, we broadcast our announcement_sigs at locking
					// block connection. We should guanrantee to broadcast announcement_sigs to our peer whatever
					// the order of the events but our peer may not receive it due to disconnection. The specs
					// lacking an acknowledgement for announcement_sigs we may have to re-send them at peer
					// connection in the future if simultaneous misses by both peers due to network/hardware
					// failures is an issue. Note, to achieve its goal, only one of the announcement_sigs needs
					// to be received, from then sigs are going to be flood to the whole network.
					channel_state.pending_msg_events.push(events::MessageSendEvent::SendAnnouncementSignatures {
						node_id: counterparty_node_id.clone(),
						msg: announcement_sigs,
					});
				}
				Ok(())
			},
			hash_map::Entry::Vacant(_) => Err(MsgHandleErrInternal::send_err_msg_no_close("Failed to find corresponding channel".to_owned(), msg.channel_id))
		}
	}

	fn internal_shutdown(&self, counterparty_node_id: &PublicKey, their_features: &InitFeatures, msg: &msgs::Shutdown) -> Result<(), MsgHandleErrInternal> {
		let (mut dropped_htlcs, chan_option) = {
			let mut channel_state_lock = self.channel_state.lock().unwrap();
			let channel_state = &mut *channel_state_lock;

			match channel_state.by_id.entry(msg.channel_id.clone()) {
				hash_map::Entry::Occupied(mut chan_entry) => {
					if chan_entry.get().get_counterparty_node_id() != *counterparty_node_id {
						return Err(MsgHandleErrInternal::send_err_msg_no_close("Got a message for a channel from the wrong node!".to_owned(), msg.channel_id));
					}
					let (shutdown, closing_signed, dropped_htlcs) = try_chan_entry!(self, chan_entry.get_mut().shutdown(&self.fee_estimator, &their_features, &msg), channel_state, chan_entry);
					if let Some(msg) = shutdown {
						channel_state.pending_msg_events.push(events::MessageSendEvent::SendShutdown {
							node_id: counterparty_node_id.clone(),
							msg,
						});
					}
					if let Some(msg) = closing_signed {
						channel_state.pending_msg_events.push(events::MessageSendEvent::SendClosingSigned {
							node_id: counterparty_node_id.clone(),
							msg,
						});
					}
					if chan_entry.get().is_shutdown() {
						if let Some(short_id) = chan_entry.get().get_short_channel_id() {
							channel_state.short_to_id.remove(&short_id);
						}
						(dropped_htlcs, Some(chan_entry.remove_entry().1))
					} else { (dropped_htlcs, None) }
				},
				hash_map::Entry::Vacant(_) => return Err(MsgHandleErrInternal::send_err_msg_no_close("Failed to find corresponding channel".to_owned(), msg.channel_id))
			}
		};
		for htlc_source in dropped_htlcs.drain(..) {
			self.fail_htlc_backwards_internal(self.channel_state.lock().unwrap(), htlc_source.0, &htlc_source.1, HTLCFailReason::Reason { failure_code: 0x4000 | 8, data: Vec::new() });
		}
		if let Some(chan) = chan_option {
			if let Ok(update) = self.get_channel_update(&chan) {
				let mut channel_state = self.channel_state.lock().unwrap();
				channel_state.pending_msg_events.push(events::MessageSendEvent::BroadcastChannelUpdate {
					msg: update
				});
			}
		}
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
						if let Some(short_id) = chan_entry.get().get_short_channel_id() {
							channel_state.short_to_id.remove(&short_id);
						}
						(tx, Some(chan_entry.remove_entry().1))
					} else { (tx, None) }
				},
				hash_map::Entry::Vacant(_) => return Err(MsgHandleErrInternal::send_err_msg_no_close("Failed to find corresponding channel".to_owned(), msg.channel_id))
			}
		};
		if let Some(broadcast_tx) = tx {
			log_trace!(self.logger, "Broadcast onchain {}", log_tx!(broadcast_tx));
			self.tx_broadcaster.broadcast_transaction(&broadcast_tx);
		}
		if let Some(chan) = chan_option {
			if let Ok(update) = self.get_channel_update(&chan) {
				let mut channel_state = self.channel_state.lock().unwrap();
				channel_state.pending_msg_events.push(events::MessageSendEvent::BroadcastChannelUpdate {
					msg: update
				});
			}
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
					// Ensure error_code has the UPDATE flag set, since by default we send a
					// channel update along as part of failing the HTLC.
					assert!((error_code & 0x1000) != 0);
					// If the update_add is completely bogus, the call will Err and we will close,
					// but if we've sent a shutdown and they haven't acknowledged it yet, we just
					// want to reject the new HTLC and fail it backwards instead of forwarding.
					match pending_forward_info {
						PendingHTLCStatus::Forward(PendingHTLCInfo { ref incoming_shared_secret, .. }) => {
							let reason = if let Ok(upd) = self.get_channel_update(chan) {
								onion_utils::build_first_hop_failure_packet(incoming_shared_secret, error_code, &{
									let mut res = Vec::with_capacity(8 + 128);
									// TODO: underspecified, follow https://github.com/lightningnetwork/lightning-rfc/issues/791
									res.extend_from_slice(&byte_utils::be16_to_array(0));
									res.extend_from_slice(&upd.encode_with_len()[..]);
									res
								}[..])
							} else {
								// The only case where we'd be unable to
								// successfully get a channel update is if the
								// channel isn't in the fully-funded state yet,
								// implying our counterparty is trying to route
								// payments over the channel back to themselves
								// (cause no one else should know the short_id
								// is a lightning channel yet). We should have
								// no problem just calling this
								// unknown_next_peer (0x4000|10).
								onion_utils::build_first_hop_failure_packet(incoming_shared_secret, 0x4000|10, &[])
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
		let htlc_source = {
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
		self.claim_funds_internal(channel_lock, htlc_source, msg.payment_preimage.clone());
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
				let (revoke_and_ack, commitment_signed, closing_signed, monitor_update) =
					match chan.get_mut().commitment_signed(&msg, &self.fee_estimator, &self.logger) {
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
					//TODO: Rebroadcast closing_signed if present on monitor update restoration
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
				if let Some(msg) = closing_signed {
					channel_state.pending_msg_events.push(events::MessageSendEvent::SendClosingSigned {
						node_id: counterparty_node_id.clone(),
						msg,
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
					let (commitment_update, pending_forwards, pending_failures, closing_signed, monitor_update, htlcs_to_fail_in) =
						break_chan_entry!(self, chan.get_mut().revoke_and_ack(&msg, &self.fee_estimator, &self.logger), channel_state, chan);
					htlcs_to_fail = htlcs_to_fail_in;
					if let Err(e) = self.chain_monitor.update_channel(chan.get().get_funding_txo().unwrap(), monitor_update) {
						if was_frozen_for_monitor {
							assert!(commitment_update.is_none() && closing_signed.is_none() && pending_forwards.is_empty() && pending_failures.is_empty());
							break Err(MsgHandleErrInternal::ignore_no_close("Previous monitor update failure prevented responses to RAA".to_owned()));
						} else {
							if let Err(e) = handle_monitor_err!(self, e, channel_state, chan, RAACommitmentOrder::CommitmentFirst, false, commitment_update.is_some(), pending_forwards, pending_failures) {
								break Err(e);
							} else { unreachable!(); }
						}
					}
					if let Some(updates) = commitment_update {
						channel_state.pending_msg_events.push(events::MessageSendEvent::UpdateHTLCs {
							node_id: counterparty_node_id.clone(),
							updates,
						});
					}
					if let Some(msg) = closing_signed {
						channel_state.pending_msg_events.push(events::MessageSendEvent::SendClosingSigned {
							node_id: counterparty_node_id.clone(),
							msg,
						});
					}
					break Ok((pending_forwards, pending_failures, chan.get().get_short_channel_id().expect("RAA should only work on a short-id-available channel"), chan.get().get_funding_txo().unwrap()))
				},
				hash_map::Entry::Vacant(_) => break Err(MsgHandleErrInternal::send_err_msg_no_close("Failed to find corresponding channel".to_owned(), msg.channel_id))
			}
		};
		self.fail_holding_cell_htlcs(htlcs_to_fail, msg.channel_id);
		match res {
			Ok((pending_forwards, mut pending_failures, short_channel_id, channel_outpoint)) => {
				for failure in pending_failures.drain(..) {
					self.fail_htlc_backwards_internal(self.channel_state.lock().unwrap(), failure.0, &failure.1, failure.2);
				}
				self.forward_htlcs(&mut [(short_channel_id, channel_outpoint, pending_forwards)]);
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

				let our_node_id = self.get_our_node_id();
				let (announcement, our_bitcoin_sig) =
					try_chan_entry!(self, chan.get_mut().get_channel_announcement(our_node_id.clone(), self.genesis_hash.clone()), channel_state, chan);

				let were_node_one = announcement.node_id_1 == our_node_id;
				let msghash = hash_to_message!(&Sha256dHash::hash(&announcement.encode()[..])[..]);
				{
					let their_node_key = if were_node_one { &announcement.node_id_2 } else { &announcement.node_id_1 };
					let their_bitcoin_key = if were_node_one { &announcement.bitcoin_key_2 } else { &announcement.bitcoin_key_1 };
					match (self.secp_ctx.verify(&msghash, &msg.node_signature, their_node_key),
						   self.secp_ctx.verify(&msghash, &msg.bitcoin_signature, their_bitcoin_key)) {
						(Err(e), _) => {
							let chan_err: ChannelError = ChannelError::Close(format!("Bad announcement_signatures. Failed to verify node_signature: {:?}. Maybe using different node_secret for transport and routing msg? UnsignedChannelAnnouncement used for verification is {:?}. their_node_key is {:?}", e, &announcement, their_node_key));
							try_chan_entry!(self, Err(chan_err), channel_state, chan);
						},
						(_, Err(e)) => {
							let chan_err: ChannelError = ChannelError::Close(format!("Bad announcement_signatures. Failed to verify bitcoin_signature: {:?}. UnsignedChannelAnnouncement used for verification is {:?}. their_bitcoin_key is ({:?})", e, &announcement, their_bitcoin_key));
							try_chan_entry!(self, Err(chan_err), channel_state, chan);
						},
						_ => {}
					}
				}

				let our_node_sig = self.secp_ctx.sign(&msghash, &self.our_network_key);

				channel_state.pending_msg_events.push(events::MessageSendEvent::BroadcastChannelAnnouncement {
					msg: msgs::ChannelAnnouncement {
						node_signature_1: if were_node_one { our_node_sig } else { msg.node_signature },
						node_signature_2: if were_node_one { msg.node_signature } else { our_node_sig },
						bitcoin_signature_1: if were_node_one { our_bitcoin_sig } else { msg.bitcoin_signature },
						bitcoin_signature_2: if were_node_one { msg.bitcoin_signature } else { our_bitcoin_sig },
						contents: announcement,
					},
					update_msg: self.get_channel_update(chan.get()).unwrap(), // can only fail if we're not in a ready state
				});
			},
			hash_map::Entry::Vacant(_) => return Err(MsgHandleErrInternal::send_err_msg_no_close("Failed to find corresponding channel".to_owned(), msg.channel_id))
		}
		Ok(())
	}

	fn internal_channel_reestablish(&self, counterparty_node_id: &PublicKey, msg: &msgs::ChannelReestablish) -> Result<(), MsgHandleErrInternal> {
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
				let (funding_locked, revoke_and_ack, commitment_update, monitor_update_opt, mut order, shutdown) =
					try_chan_entry!(self, chan.get_mut().channel_reestablish(msg, &self.logger), channel_state, chan);
				if let Some(monitor_update) = monitor_update_opt {
					if let Err(e) = self.chain_monitor.update_channel(chan.get().get_funding_txo().unwrap(), monitor_update) {
						// channel_reestablish doesn't guarantee the order it returns is sensical
						// for the messages it returns, but if we're setting what messages to
						// re-transmit on monitor update success, we need to make sure it is sane.
						if revoke_and_ack.is_none() {
							order = RAACommitmentOrder::CommitmentFirst;
						}
						if commitment_update.is_none() {
							order = RAACommitmentOrder::RevokeAndACKFirst;
						}
						return_monitor_err!(self, e, channel_state, chan, order, revoke_and_ack.is_some(), commitment_update.is_some());
						//TODO: Resend the funding_locked if needed once we get the monitor running again
					}
				}
				if let Some(msg) = funding_locked {
					channel_state.pending_msg_events.push(events::MessageSendEvent::SendFundingLocked {
						node_id: counterparty_node_id.clone(),
						msg
					});
				}
				macro_rules! send_raa { () => {
					if let Some(msg) = revoke_and_ack {
						channel_state.pending_msg_events.push(events::MessageSendEvent::SendRevokeAndACK {
							node_id: counterparty_node_id.clone(),
							msg
						});
					}
				} }
				macro_rules! send_cu { () => {
					if let Some(updates) = commitment_update {
						channel_state.pending_msg_events.push(events::MessageSendEvent::UpdateHTLCs {
							node_id: counterparty_node_id.clone(),
							updates
						});
					}
				} }
				match order {
					RAACommitmentOrder::RevokeAndACKFirst => {
						send_raa!();
						send_cu!();
					},
					RAACommitmentOrder::CommitmentFirst => {
						send_cu!();
						send_raa!();
					},
				}
				if let Some(msg) = shutdown {
					channel_state.pending_msg_events.push(events::MessageSendEvent::SendShutdown {
						node_id: counterparty_node_id.clone(),
						msg,
					});
				}
				Ok(())
			},
			hash_map::Entry::Vacant(_) => return Err(MsgHandleErrInternal::send_err_msg_no_close("Failed to find corresponding channel".to_owned(), msg.channel_id))
		}
	}

	/// Begin Update fee process. Allowed only on an outbound channel.
	/// If successful, will generate a UpdateHTLCs event, so you should probably poll
	/// PeerManager::process_events afterwards.
	/// Note: This API is likely to change!
	/// (C-not exported) Cause its doc(hidden) anyway
	#[doc(hidden)]
	pub fn update_fee(&self, channel_id: [u8;32], feerate_per_kw: u32) -> Result<(), APIError> {
		let _persistence_guard = PersistenceNotifierGuard::new(&self.total_consistency_lock, &self.persistence_notifier);
		let counterparty_node_id;
		let err: Result<(), _> = loop {
			let mut channel_state_lock = self.channel_state.lock().unwrap();
			let channel_state = &mut *channel_state_lock;

			match channel_state.by_id.entry(channel_id) {
				hash_map::Entry::Vacant(_) => return Err(APIError::APIMisuseError{err: format!("Failed to find corresponding channel for id {}", channel_id.to_hex())}),
				hash_map::Entry::Occupied(mut chan) => {
					if !chan.get().is_outbound() {
						return Err(APIError::APIMisuseError{err: "update_fee cannot be sent for an inbound channel".to_owned()});
					}
					if chan.get().is_awaiting_monitor_update() {
						return Err(APIError::MonitorUpdateFailed);
					}
					if !chan.get().is_live() {
						return Err(APIError::ChannelUnavailable{err: "Channel is either not yet fully established or peer is currently disconnected".to_owned()});
					}
					counterparty_node_id = chan.get().get_counterparty_node_id();
					if let Some((update_fee, commitment_signed, monitor_update)) =
							break_chan_entry!(self, chan.get_mut().send_update_fee_and_commit(feerate_per_kw, &self.logger), channel_state, chan)
					{
						if let Err(_e) = self.chain_monitor.update_channel(chan.get().get_funding_txo().unwrap(), monitor_update) {
							unimplemented!();
						}
						channel_state.pending_msg_events.push(events::MessageSendEvent::UpdateHTLCs {
							node_id: chan.get().get_counterparty_node_id(),
							updates: msgs::CommitmentUpdate {
								update_add_htlcs: Vec::new(),
								update_fulfill_htlcs: Vec::new(),
								update_fail_htlcs: Vec::new(),
								update_fail_malformed_htlcs: Vec::new(),
								update_fee: Some(update_fee),
								commitment_signed,
							},
						});
					}
				},
			}
			return Ok(())
		};

		match handle_error!(self, err, counterparty_node_id) {
			Ok(_) => unreachable!(),
			Err(e) => { Err(APIError::APIMisuseError { err: e.err })}
		}
	}

	/// Process pending events from the `chain::Watch`.
	fn process_pending_monitor_events(&self) {
		let mut failed_channels = Vec::new();
		{
			for monitor_event in self.chain_monitor.release_pending_monitor_events() {
				match monitor_event {
					MonitorEvent::HTLCEvent(htlc_update) => {
						if let Some(preimage) = htlc_update.payment_preimage {
							log_trace!(self.logger, "Claiming HTLC with preimage {} from our monitor", log_bytes!(preimage.0));
							self.claim_funds_internal(self.channel_state.lock().unwrap(), htlc_update.source, preimage);
						} else {
							log_trace!(self.logger, "Failing HTLC with hash {} from our monitor", log_bytes!(htlc_update.payment_hash.0));
							self.fail_htlc_backwards_internal(self.channel_state.lock().unwrap(), htlc_update.source, &htlc_update.payment_hash, HTLCFailReason::Reason { failure_code: 0x4000 | 8, data: Vec::new() });
						}
					},
					MonitorEvent::CommitmentTxBroadcasted(funding_outpoint) => {
						let mut channel_lock = self.channel_state.lock().unwrap();
						let channel_state = &mut *channel_lock;
						let by_id = &mut channel_state.by_id;
						let short_to_id = &mut channel_state.short_to_id;
						let pending_msg_events = &mut channel_state.pending_msg_events;
						if let Some(mut chan) = by_id.remove(&funding_outpoint.to_channel_id()) {
							if let Some(short_id) = chan.get_short_channel_id() {
								short_to_id.remove(&short_id);
							}
							failed_channels.push(chan.force_shutdown(false));
							if let Ok(update) = self.get_channel_update(&chan) {
								pending_msg_events.push(events::MessageSendEvent::BroadcastChannelUpdate {
									msg: update
								});
							}
						}
					},
				}
			}
		}

		for failure in failed_channels.drain(..) {
			self.finish_force_close_channel(failure);
		}
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
		//TODO: This behavior should be documented. It's non-intuitive that we query
		// ChannelMonitors when clearing other events.
		self.process_pending_monitor_events();

		let mut ret = Vec::new();
		let mut channel_state = self.channel_state.lock().unwrap();
		mem::swap(&mut ret, &mut channel_state.pending_msg_events);
		ret
	}
}

impl<Signer: Sign, M: Deref, T: Deref, K: Deref, F: Deref, L: Deref> EventsProvider for ChannelManager<Signer, M, T, K, F, L>
	where M::Target: chain::Watch<Signer>,
        T::Target: BroadcasterInterface,
        K::Target: KeysInterface<Signer = Signer>,
        F::Target: FeeEstimator,
				L::Target: Logger,
{
	fn get_and_clear_pending_events(&self) -> Vec<Event> {
		//TODO: This behavior should be documented. It's non-intuitive that we query
		// ChannelMonitors when clearing other events.
		self.process_pending_monitor_events();

		let mut ret = Vec::new();
		let mut pending_events = self.pending_events.lock().unwrap();
		mem::swap(&mut ret, &mut *pending_events);
		ret
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
	fn block_connected(&self, block: &Block, height: u32) {
		let txdata: Vec<_> = block.txdata.iter().enumerate().collect();
		ChannelManager::block_connected(self, &block.header, &txdata, height);
	}

	fn block_disconnected(&self, header: &BlockHeader, _height: u32) {
		ChannelManager::block_disconnected(self, header);
	}
}

impl<Signer: Sign, M: Deref, T: Deref, K: Deref, F: Deref, L: Deref> ChannelManager<Signer, M, T, K, F, L>
	where M::Target: chain::Watch<Signer>,
        T::Target: BroadcasterInterface,
        K::Target: KeysInterface<Signer = Signer>,
        F::Target: FeeEstimator,
        L::Target: Logger,
{
	/// Updates channel state based on transactions seen in a connected block.
	pub fn block_connected(&self, header: &BlockHeader, txdata: &TransactionData, height: u32) {
		let header_hash = header.block_hash();
		log_trace!(self.logger, "Block {} at height {} connected", header_hash, height);
		let _persistence_guard = PersistenceNotifierGuard::new(&self.total_consistency_lock, &self.persistence_notifier);
		let mut failed_channels = Vec::new();
		let mut timed_out_htlcs = Vec::new();
		{
			let mut channel_lock = self.channel_state.lock().unwrap();
			let channel_state = &mut *channel_lock;
			let short_to_id = &mut channel_state.short_to_id;
			let pending_msg_events = &mut channel_state.pending_msg_events;
			channel_state.by_id.retain(|_, channel| {
				let res = channel.block_connected(header, txdata, height);
				if let Ok((chan_res, mut timed_out_pending_htlcs)) = res {
					for (source, payment_hash) in timed_out_pending_htlcs.drain(..) {
						let chan_update = self.get_channel_update(&channel).map(|u| u.encode_with_len()).unwrap(); // Cannot add/recv HTLCs before we have a short_id so unwrap is safe
						timed_out_htlcs.push((source, payment_hash,  HTLCFailReason::Reason {
							failure_code: 0x1000 | 14, // expiry_too_soon, or at least it is now
							data: chan_update,
						}));
					}
					if let Some(funding_locked) = chan_res {
						pending_msg_events.push(events::MessageSendEvent::SendFundingLocked {
							node_id: channel.get_counterparty_node_id(),
							msg: funding_locked,
						});
						if let Some(announcement_sigs) = self.get_announcement_sigs(channel) {
							log_trace!(self.logger, "Sending funding_locked and announcement_signatures for {}", log_bytes!(channel.channel_id()));
							pending_msg_events.push(events::MessageSendEvent::SendAnnouncementSignatures {
								node_id: channel.get_counterparty_node_id(),
								msg: announcement_sigs,
							});
						} else {
							log_trace!(self.logger, "Sending funding_locked WITHOUT announcement_signatures for {}", log_bytes!(channel.channel_id()));
						}
						short_to_id.insert(channel.get_short_channel_id().unwrap(), channel.channel_id());
					}
				} else if let Err(e) = res {
					pending_msg_events.push(events::MessageSendEvent::HandleError {
						node_id: channel.get_counterparty_node_id(),
						action: msgs::ErrorAction::SendErrorMessage { msg: e },
					});
					return false;
				}
				if let Some(funding_txo) = channel.get_funding_txo() {
					for &(_, tx) in txdata.iter() {
						for inp in tx.input.iter() {
							if inp.previous_output == funding_txo.into_bitcoin_outpoint() {
								log_trace!(self.logger, "Detected channel-closing tx {} spending {}:{}, closing channel {}", tx.txid(), inp.previous_output.txid, inp.previous_output.vout, log_bytes!(channel.channel_id()));
								if let Some(short_id) = channel.get_short_channel_id() {
									short_to_id.remove(&short_id);
								}
								// It looks like our counterparty went on-chain. We go ahead and
								// broadcast our latest local state as well here, just in case its
								// some kind of SPV attack, though we expect these to be dropped.
								failed_channels.push(channel.force_shutdown(true));
								if let Ok(update) = self.get_channel_update(&channel) {
									pending_msg_events.push(events::MessageSendEvent::BroadcastChannelUpdate {
										msg: update
									});
								}
								return false;
							}
						}
					}
				}
				true
			});

			channel_state.claimable_htlcs.retain(|&(ref payment_hash, _), htlcs| {
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
		for failure in failed_channels.drain(..) {
			self.finish_force_close_channel(failure);
		}

		for (source, payment_hash, reason) in timed_out_htlcs.drain(..) {
			self.fail_htlc_backwards_internal(self.channel_state.lock().unwrap(), source, &payment_hash, reason);
		}
		self.latest_block_height.store(height as usize, Ordering::Release);
		*self.last_block_hash.try_lock().expect("block_(dis)connected must not be called in parallel") = header_hash;
		loop {
			// Update last_node_announcement_serial to be the max of its current value and the
			// block timestamp. This should keep us close to the current time without relying on
			// having an explicit local time source.
			// Just in case we end up in a race, we loop until we either successfully update
			// last_node_announcement_serial or decide we don't need to.
			let old_serial = self.last_node_announcement_serial.load(Ordering::Acquire);
			if old_serial >= header.time as usize { break; }
			if self.last_node_announcement_serial.compare_exchange(old_serial, header.time as usize, Ordering::AcqRel, Ordering::Relaxed).is_ok() {
				break;
			}
		}
	}

	/// Updates channel state based on a disconnected block.
	///
	/// If necessary, the channel may be force-closed without letting the counterparty participate
	/// in the shutdown.
	pub fn block_disconnected(&self, header: &BlockHeader) {
		let _persistence_guard = PersistenceNotifierGuard::new(&self.total_consistency_lock, &self.persistence_notifier);
		let mut failed_channels = Vec::new();
		{
			let mut channel_lock = self.channel_state.lock().unwrap();
			let channel_state = &mut *channel_lock;
			let short_to_id = &mut channel_state.short_to_id;
			let pending_msg_events = &mut channel_state.pending_msg_events;
			channel_state.by_id.retain(|_,  v| {
				if v.block_disconnected(header) {
					if let Some(short_id) = v.get_short_channel_id() {
						short_to_id.remove(&short_id);
					}
					failed_channels.push(v.force_shutdown(true));
					if let Ok(update) = self.get_channel_update(&v) {
						pending_msg_events.push(events::MessageSendEvent::BroadcastChannelUpdate {
							msg: update
						});
					}
					false
				} else {
					true
				}
			});
		}
		for failure in failed_channels.drain(..) {
			self.finish_force_close_channel(failure);
		}
		self.latest_block_height.fetch_sub(1, Ordering::AcqRel);
		*self.last_block_hash.try_lock().expect("block_(dis)connected must not be called in parallel") = header.block_hash();
	}

	/// Blocks until ChannelManager needs to be persisted or a timeout is reached. It returns a bool
	/// indicating whether persistence is necessary. Only one listener on `wait_timeout` is
	/// guaranteed to be woken up.
	/// Note that the feature `allow_wallclock_use` must be enabled to use this function.
	#[cfg(any(test, feature = "allow_wallclock_use"))]
	pub fn wait_timeout(&self, max_wait: Duration) -> bool {
		self.persistence_notifier.wait_timeout(max_wait)
	}

	/// Blocks until ChannelManager needs to be persisted. Only one listener on `wait` is
	/// guaranteed to be woken up.
	pub fn wait(&self) {
		self.persistence_notifier.wait()
	}

	#[cfg(any(test, feature = "_test_utils"))]
	pub fn get_persistence_condvar_value(&self) -> bool {
		let mutcond = &self.persistence_notifier.persistence_lock;
		let &(ref mtx, _) = mutcond;
		let guard = mtx.lock().unwrap();
		*guard
	}
}

impl<Signer: Sign, M: Deref + Sync + Send, T: Deref + Sync + Send, K: Deref + Sync + Send, F: Deref + Sync + Send, L: Deref + Sync + Send>
	ChannelMessageHandler for ChannelManager<Signer, M, T, K, F, L>
	where M::Target: chain::Watch<Signer>,
        T::Target: BroadcasterInterface,
        K::Target: KeysInterface<Signer = Signer>,
        F::Target: FeeEstimator,
        L::Target: Logger,
{
	fn handle_open_channel(&self, counterparty_node_id: &PublicKey, their_features: InitFeatures, msg: &msgs::OpenChannel) {
		let _persistence_guard = PersistenceNotifierGuard::new(&self.total_consistency_lock, &self.persistence_notifier);
		let _ = handle_error!(self, self.internal_open_channel(counterparty_node_id, their_features, msg), *counterparty_node_id);
	}

	fn handle_accept_channel(&self, counterparty_node_id: &PublicKey, their_features: InitFeatures, msg: &msgs::AcceptChannel) {
		let _persistence_guard = PersistenceNotifierGuard::new(&self.total_consistency_lock, &self.persistence_notifier);
		let _ = handle_error!(self, self.internal_accept_channel(counterparty_node_id, their_features, msg), *counterparty_node_id);
	}

	fn handle_funding_created(&self, counterparty_node_id: &PublicKey, msg: &msgs::FundingCreated) {
		let _persistence_guard = PersistenceNotifierGuard::new(&self.total_consistency_lock, &self.persistence_notifier);
		let _ = handle_error!(self, self.internal_funding_created(counterparty_node_id, msg), *counterparty_node_id);
	}

	fn handle_funding_signed(&self, counterparty_node_id: &PublicKey, msg: &msgs::FundingSigned) {
		let _persistence_guard = PersistenceNotifierGuard::new(&self.total_consistency_lock, &self.persistence_notifier);
		let _ = handle_error!(self, self.internal_funding_signed(counterparty_node_id, msg), *counterparty_node_id);
	}

	fn handle_funding_locked(&self, counterparty_node_id: &PublicKey, msg: &msgs::FundingLocked) {
		let _persistence_guard = PersistenceNotifierGuard::new(&self.total_consistency_lock, &self.persistence_notifier);
		let _ = handle_error!(self, self.internal_funding_locked(counterparty_node_id, msg), *counterparty_node_id);
	}

	fn handle_shutdown(&self, counterparty_node_id: &PublicKey, their_features: &InitFeatures, msg: &msgs::Shutdown) {
		let _persistence_guard = PersistenceNotifierGuard::new(&self.total_consistency_lock, &self.persistence_notifier);
		let _ = handle_error!(self, self.internal_shutdown(counterparty_node_id, their_features, msg), *counterparty_node_id);
	}

	fn handle_closing_signed(&self, counterparty_node_id: &PublicKey, msg: &msgs::ClosingSigned) {
		let _persistence_guard = PersistenceNotifierGuard::new(&self.total_consistency_lock, &self.persistence_notifier);
		let _ = handle_error!(self, self.internal_closing_signed(counterparty_node_id, msg), *counterparty_node_id);
	}

	fn handle_update_add_htlc(&self, counterparty_node_id: &PublicKey, msg: &msgs::UpdateAddHTLC) {
		let _persistence_guard = PersistenceNotifierGuard::new(&self.total_consistency_lock, &self.persistence_notifier);
		let _ = handle_error!(self, self.internal_update_add_htlc(counterparty_node_id, msg), *counterparty_node_id);
	}

	fn handle_update_fulfill_htlc(&self, counterparty_node_id: &PublicKey, msg: &msgs::UpdateFulfillHTLC) {
		let _persistence_guard = PersistenceNotifierGuard::new(&self.total_consistency_lock, &self.persistence_notifier);
		let _ = handle_error!(self, self.internal_update_fulfill_htlc(counterparty_node_id, msg), *counterparty_node_id);
	}

	fn handle_update_fail_htlc(&self, counterparty_node_id: &PublicKey, msg: &msgs::UpdateFailHTLC) {
		let _persistence_guard = PersistenceNotifierGuard::new(&self.total_consistency_lock, &self.persistence_notifier);
		let _ = handle_error!(self, self.internal_update_fail_htlc(counterparty_node_id, msg), *counterparty_node_id);
	}

	fn handle_update_fail_malformed_htlc(&self, counterparty_node_id: &PublicKey, msg: &msgs::UpdateFailMalformedHTLC) {
		let _persistence_guard = PersistenceNotifierGuard::new(&self.total_consistency_lock, &self.persistence_notifier);
		let _ = handle_error!(self, self.internal_update_fail_malformed_htlc(counterparty_node_id, msg), *counterparty_node_id);
	}

	fn handle_commitment_signed(&self, counterparty_node_id: &PublicKey, msg: &msgs::CommitmentSigned) {
		let _persistence_guard = PersistenceNotifierGuard::new(&self.total_consistency_lock, &self.persistence_notifier);
		let _ = handle_error!(self, self.internal_commitment_signed(counterparty_node_id, msg), *counterparty_node_id);
	}

	fn handle_revoke_and_ack(&self, counterparty_node_id: &PublicKey, msg: &msgs::RevokeAndACK) {
		let _persistence_guard = PersistenceNotifierGuard::new(&self.total_consistency_lock, &self.persistence_notifier);
		let _ = handle_error!(self, self.internal_revoke_and_ack(counterparty_node_id, msg), *counterparty_node_id);
	}

	fn handle_update_fee(&self, counterparty_node_id: &PublicKey, msg: &msgs::UpdateFee) {
		let _persistence_guard = PersistenceNotifierGuard::new(&self.total_consistency_lock, &self.persistence_notifier);
		let _ = handle_error!(self, self.internal_update_fee(counterparty_node_id, msg), *counterparty_node_id);
	}

	fn handle_announcement_signatures(&self, counterparty_node_id: &PublicKey, msg: &msgs::AnnouncementSignatures) {
		let _persistence_guard = PersistenceNotifierGuard::new(&self.total_consistency_lock, &self.persistence_notifier);
		let _ = handle_error!(self, self.internal_announcement_signatures(counterparty_node_id, msg), *counterparty_node_id);
	}

	fn handle_channel_reestablish(&self, counterparty_node_id: &PublicKey, msg: &msgs::ChannelReestablish) {
		let _persistence_guard = PersistenceNotifierGuard::new(&self.total_consistency_lock, &self.persistence_notifier);
		let _ = handle_error!(self, self.internal_channel_reestablish(counterparty_node_id, msg), *counterparty_node_id);
	}

	fn peer_disconnected(&self, counterparty_node_id: &PublicKey, no_connection_possible: bool) {
		let _persistence_guard = PersistenceNotifierGuard::new(&self.total_consistency_lock, &self.persistence_notifier);
		let mut failed_channels = Vec::new();
		let mut failed_payments = Vec::new();
		let mut no_channels_remain = true;
		{
			let mut channel_state_lock = self.channel_state.lock().unwrap();
			let channel_state = &mut *channel_state_lock;
			let short_to_id = &mut channel_state.short_to_id;
			let pending_msg_events = &mut channel_state.pending_msg_events;
			if no_connection_possible {
				log_debug!(self.logger, "Failing all channels with {} due to no_connection_possible", log_pubkey!(counterparty_node_id));
				channel_state.by_id.retain(|_, chan| {
					if chan.get_counterparty_node_id() == *counterparty_node_id {
						if let Some(short_id) = chan.get_short_channel_id() {
							short_to_id.remove(&short_id);
						}
						failed_channels.push(chan.force_shutdown(true));
						if let Ok(update) = self.get_channel_update(&chan) {
							pending_msg_events.push(events::MessageSendEvent::BroadcastChannelUpdate {
								msg: update
							});
						}
						false
					} else {
						true
					}
				});
			} else {
				log_debug!(self.logger, "Marking channels with {} disconnected and generating channel_updates", log_pubkey!(counterparty_node_id));
				channel_state.by_id.retain(|_, chan| {
					if chan.get_counterparty_node_id() == *counterparty_node_id {
						// Note that currently on channel reestablish we assert that there are no
						// holding cell add-HTLCs, so if in the future we stop removing uncommitted HTLCs
						// on peer disconnect here, there will need to be corresponding changes in
						// reestablish logic.
						let failed_adds = chan.remove_uncommitted_htlcs_and_mark_paused(&self.logger);
						chan.to_disabled_marked();
						if !failed_adds.is_empty() {
							let chan_update = self.get_channel_update(&chan).map(|u| u.encode_with_len()).unwrap(); // Cannot add/recv HTLCs before we have a short_id so unwrap is safe
							failed_payments.push((chan_update, failed_adds));
						}
						if chan.is_shutdown() {
							if let Some(short_id) = chan.get_short_channel_id() {
								short_to_id.remove(&short_id);
							}
							return false;
						} else {
							no_channels_remain = false;
						}
					}
					true
				})
			}
			pending_msg_events.retain(|msg| {
				match msg {
					&events::MessageSendEvent::SendAcceptChannel { ref node_id, .. } => node_id != counterparty_node_id,
					&events::MessageSendEvent::SendOpenChannel { ref node_id, .. } => node_id != counterparty_node_id,
					&events::MessageSendEvent::SendFundingCreated { ref node_id, .. } => node_id != counterparty_node_id,
					&events::MessageSendEvent::SendFundingSigned { ref node_id, .. } => node_id != counterparty_node_id,
					&events::MessageSendEvent::SendFundingLocked { ref node_id, .. } => node_id != counterparty_node_id,
					&events::MessageSendEvent::SendAnnouncementSignatures { ref node_id, .. } => node_id != counterparty_node_id,
					&events::MessageSendEvent::UpdateHTLCs { ref node_id, .. } => node_id != counterparty_node_id,
					&events::MessageSendEvent::SendRevokeAndACK { ref node_id, .. } => node_id != counterparty_node_id,
					&events::MessageSendEvent::SendClosingSigned { ref node_id, .. } => node_id != counterparty_node_id,
					&events::MessageSendEvent::SendShutdown { ref node_id, .. } => node_id != counterparty_node_id,
					&events::MessageSendEvent::SendChannelReestablish { ref node_id, .. } => node_id != counterparty_node_id,
					&events::MessageSendEvent::BroadcastChannelAnnouncement { .. } => true,
					&events::MessageSendEvent::BroadcastNodeAnnouncement { .. } => true,
					&events::MessageSendEvent::BroadcastChannelUpdate { .. } => true,
					&events::MessageSendEvent::HandleError { ref node_id, .. } => node_id != counterparty_node_id,
					&events::MessageSendEvent::PaymentFailureNetworkUpdate { .. } => true,
					&events::MessageSendEvent::SendChannelRangeQuery { .. } => false,
					&events::MessageSendEvent::SendShortIdsQuery { .. } => false,
				}
			});
		}
		if no_channels_remain {
			self.per_peer_state.write().unwrap().remove(counterparty_node_id);
		}

		for failure in failed_channels.drain(..) {
			self.finish_force_close_channel(failure);
		}
		for (chan_update, mut htlc_sources) in failed_payments {
			for (htlc_source, payment_hash) in htlc_sources.drain(..) {
				self.fail_htlc_backwards_internal(self.channel_state.lock().unwrap(), htlc_source, &payment_hash, HTLCFailReason::Reason { failure_code: 0x1000 | 7, data: chan_update.clone() });
			}
		}
	}

	fn peer_connected(&self, counterparty_node_id: &PublicKey, init_msg: &msgs::Init) {
		log_debug!(self.logger, "Generating channel_reestablish events for {}", log_pubkey!(counterparty_node_id));

		let _persistence_guard = PersistenceNotifierGuard::new(&self.total_consistency_lock, &self.persistence_notifier);

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
		let _persistence_guard = PersistenceNotifierGuard::new(&self.total_consistency_lock, &self.persistence_notifier);

		if msg.channel_id == [0; 32] {
			for chan in self.list_channels() {
				if chan.remote_network_id == *counterparty_node_id {
					// Untrusted messages from peer, we throw away the error if id points to a non-existent channel
					let _ = self.force_close_channel_with_peer(&chan.channel_id, Some(counterparty_node_id));
				}
			}
		} else {
			// Untrusted messages from peer, we throw away the error if id points to a non-existent channel
			let _ = self.force_close_channel_with_peer(&msg.channel_id, Some(counterparty_node_id));
		}
	}
}

/// Used to signal to the ChannelManager persister that the manager needs to be re-persisted to
/// disk/backups, through `wait_timeout` and `wait`.
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
			guard = cvar.wait(guard).unwrap();
			let result = *guard;
			if result {
				*guard = false;
				return
			}
		}
	}

	#[cfg(any(test, feature = "allow_wallclock_use"))]
	fn wait_timeout(&self, max_wait: Duration) -> bool {
		let current_time = Instant::now();
		loop {
			let &(ref mtx, ref cvar) = &self.persistence_lock;
			let mut guard = mtx.lock().unwrap();
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

impl Writeable for PendingHTLCInfo {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
		match &self.routing {
			&PendingHTLCRouting::Forward { ref onion_packet, ref short_channel_id } => {
				0u8.write(writer)?;
				onion_packet.write(writer)?;
				short_channel_id.write(writer)?;
			},
			&PendingHTLCRouting::Receive { ref payment_data, ref incoming_cltv_expiry } => {
				1u8.write(writer)?;
				payment_data.write(writer)?;
				incoming_cltv_expiry.write(writer)?;
			},
		}
		self.incoming_shared_secret.write(writer)?;
		self.payment_hash.write(writer)?;
		self.amt_to_forward.write(writer)?;
		self.outgoing_cltv_value.write(writer)?;
		Ok(())
	}
}

impl Readable for PendingHTLCInfo {
	fn read<R: ::std::io::Read>(reader: &mut R) -> Result<PendingHTLCInfo, DecodeError> {
		Ok(PendingHTLCInfo {
			routing: match Readable::read(reader)? {
				0u8 => PendingHTLCRouting::Forward {
					onion_packet: Readable::read(reader)?,
					short_channel_id: Readable::read(reader)?,
				},
				1u8 => PendingHTLCRouting::Receive {
					payment_data: Readable::read(reader)?,
					incoming_cltv_expiry: Readable::read(reader)?,
				},
				_ => return Err(DecodeError::InvalidValue),
			},
			incoming_shared_secret: Readable::read(reader)?,
			payment_hash: Readable::read(reader)?,
			amt_to_forward: Readable::read(reader)?,
			outgoing_cltv_value: Readable::read(reader)?,
		})
	}
}

impl Writeable for HTLCFailureMsg {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
		match self {
			&HTLCFailureMsg::Relay(ref fail_msg) => {
				0u8.write(writer)?;
				fail_msg.write(writer)?;
			},
			&HTLCFailureMsg::Malformed(ref fail_msg) => {
				1u8.write(writer)?;
				fail_msg.write(writer)?;
			}
		}
		Ok(())
	}
}

impl Readable for HTLCFailureMsg {
	fn read<R: ::std::io::Read>(reader: &mut R) -> Result<HTLCFailureMsg, DecodeError> {
		match <u8 as Readable>::read(reader)? {
			0 => Ok(HTLCFailureMsg::Relay(Readable::read(reader)?)),
			1 => Ok(HTLCFailureMsg::Malformed(Readable::read(reader)?)),
			_ => Err(DecodeError::InvalidValue),
		}
	}
}

impl Writeable for PendingHTLCStatus {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
		match self {
			&PendingHTLCStatus::Forward(ref forward_info) => {
				0u8.write(writer)?;
				forward_info.write(writer)?;
			},
			&PendingHTLCStatus::Fail(ref fail_msg) => {
				1u8.write(writer)?;
				fail_msg.write(writer)?;
			}
		}
		Ok(())
	}
}

impl Readable for PendingHTLCStatus {
	fn read<R: ::std::io::Read>(reader: &mut R) -> Result<PendingHTLCStatus, DecodeError> {
		match <u8 as Readable>::read(reader)? {
			0 => Ok(PendingHTLCStatus::Forward(Readable::read(reader)?)),
			1 => Ok(PendingHTLCStatus::Fail(Readable::read(reader)?)),
			_ => Err(DecodeError::InvalidValue),
		}
	}
}

impl_writeable!(HTLCPreviousHopData, 0, {
	short_channel_id,
	outpoint,
	htlc_id,
	incoming_packet_shared_secret
});

impl_writeable!(ClaimableHTLC, 0, {
	prev_hop,
	value,
	payment_data,
	cltv_expiry
});

impl Writeable for HTLCSource {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
		match self {
			&HTLCSource::PreviousHopData(ref hop_data) => {
				0u8.write(writer)?;
				hop_data.write(writer)?;
			},
			&HTLCSource::OutboundRoute { ref path, ref session_priv, ref first_hop_htlc_msat } => {
				1u8.write(writer)?;
				path.write(writer)?;
				session_priv.write(writer)?;
				first_hop_htlc_msat.write(writer)?;
			}
		}
		Ok(())
	}
}

impl Readable for HTLCSource {
	fn read<R: ::std::io::Read>(reader: &mut R) -> Result<HTLCSource, DecodeError> {
		match <u8 as Readable>::read(reader)? {
			0 => Ok(HTLCSource::PreviousHopData(Readable::read(reader)?)),
			1 => Ok(HTLCSource::OutboundRoute {
				path: Readable::read(reader)?,
				session_priv: Readable::read(reader)?,
				first_hop_htlc_msat: Readable::read(reader)?,
			}),
			_ => Err(DecodeError::InvalidValue),
		}
	}
}

impl Writeable for HTLCFailReason {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
		match self {
			&HTLCFailReason::LightningError { ref err } => {
				0u8.write(writer)?;
				err.write(writer)?;
			},
			&HTLCFailReason::Reason { ref failure_code, ref data } => {
				1u8.write(writer)?;
				failure_code.write(writer)?;
				data.write(writer)?;
			}
		}
		Ok(())
	}
}

impl Readable for HTLCFailReason {
	fn read<R: ::std::io::Read>(reader: &mut R) -> Result<HTLCFailReason, DecodeError> {
		match <u8 as Readable>::read(reader)? {
			0 => Ok(HTLCFailReason::LightningError { err: Readable::read(reader)? }),
			1 => Ok(HTLCFailReason::Reason {
				failure_code: Readable::read(reader)?,
				data: Readable::read(reader)?,
			}),
			_ => Err(DecodeError::InvalidValue),
		}
	}
}

impl Writeable for HTLCForwardInfo {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
		match self {
			&HTLCForwardInfo::AddHTLC { ref prev_short_channel_id, ref prev_funding_outpoint, ref prev_htlc_id, ref forward_info } => {
				0u8.write(writer)?;
				prev_short_channel_id.write(writer)?;
				prev_funding_outpoint.write(writer)?;
				prev_htlc_id.write(writer)?;
				forward_info.write(writer)?;
			},
			&HTLCForwardInfo::FailHTLC { ref htlc_id, ref err_packet } => {
				1u8.write(writer)?;
				htlc_id.write(writer)?;
				err_packet.write(writer)?;
			},
		}
		Ok(())
	}
}

impl Readable for HTLCForwardInfo {
	fn read<R: ::std::io::Read>(reader: &mut R) -> Result<HTLCForwardInfo, DecodeError> {
		match <u8 as Readable>::read(reader)? {
			0 => Ok(HTLCForwardInfo::AddHTLC {
				prev_short_channel_id: Readable::read(reader)?,
				prev_funding_outpoint: Readable::read(reader)?,
				prev_htlc_id: Readable::read(reader)?,
				forward_info: Readable::read(reader)?,
			}),
			1 => Ok(HTLCForwardInfo::FailHTLC {
				htlc_id: Readable::read(reader)?,
				err_packet: Readable::read(reader)?,
			}),
			_ => Err(DecodeError::InvalidValue),
		}
	}
}

impl<Signer: Sign, M: Deref, T: Deref, K: Deref, F: Deref, L: Deref> Writeable for ChannelManager<Signer, M, T, K, F, L>
	where M::Target: chain::Watch<Signer>,
        T::Target: BroadcasterInterface,
        K::Target: KeysInterface<Signer = Signer>,
        F::Target: FeeEstimator,
        L::Target: Logger,
{
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
		let _consistency_lock = self.total_consistency_lock.write().unwrap();

		writer.write_all(&[SERIALIZATION_VERSION; 1])?;
		writer.write_all(&[MIN_SERIALIZATION_VERSION; 1])?;

		self.genesis_hash.write(writer)?;
		(self.latest_block_height.load(Ordering::Acquire) as u32).write(writer)?;
		self.last_block_hash.lock().unwrap().write(writer)?;

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

		(channel_state.claimable_htlcs.len() as u64).write(writer)?;
		for (payment_hash, previous_hops) in channel_state.claimable_htlcs.iter() {
			payment_hash.write(writer)?;
			(previous_hops.len() as u64).write(writer)?;
			for htlc in previous_hops.iter() {
				htlc.write(writer)?;
			}
		}

		let per_peer_state = self.per_peer_state.write().unwrap();
		(per_peer_state.len() as u64).write(writer)?;
		for (peer_pubkey, peer_state_mutex) in per_peer_state.iter() {
			peer_pubkey.write(writer)?;
			let peer_state = peer_state_mutex.lock().unwrap();
			peer_state.latest_features.write(writer)?;
		}

		let events = self.pending_events.lock().unwrap();
		(events.len() as u64).write(writer)?;
		for event in events.iter() {
			event.write(writer)?;
		}

		(self.last_node_announcement_serial.load(Ordering::Acquire) as u32).write(writer)?;

		Ok(())
	}
}

/// Arguments for the creation of a ChannelManager that are not deserialized.
///
/// At a high-level, the process for deserializing a ChannelManager and resuming normal operation
/// is:
/// 1) Deserialize all stored ChannelMonitors.
/// 2) Deserialize the ChannelManager by filling in this struct and calling <(Sha256dHash,
///    ChannelManager)>::read(reader, args).
///    This may result in closing some Channels if the ChannelMonitor is newer than the stored
///    ChannelManager state to ensure no loss of funds. Thus, transactions may be broadcasted.
/// 3) Register all relevant ChannelMonitor outpoints with your chain watch mechanism using
///    ChannelMonitor::get_outputs_to_watch() and ChannelMonitor::get_funding_txo().
/// 4) Reconnect blocks on your ChannelMonitors.
/// 5) Move the ChannelMonitors into your local chain::Watch.
/// 6) Disconnect/connect blocks on the ChannelManager.
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
	fn read<R: ::std::io::Read>(reader: &mut R, args: ChannelManagerReadArgs<'a, Signer, M, T, K, F, L>) -> Result<Self, DecodeError> {
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
	fn read<R: ::std::io::Read>(reader: &mut R, mut args: ChannelManagerReadArgs<'a, Signer, M, T, K, F, L>) -> Result<Self, DecodeError> {
		let _ver: u8 = Readable::read(reader)?;
		let min_ver: u8 = Readable::read(reader)?;
		if min_ver > SERIALIZATION_VERSION {
			return Err(DecodeError::UnknownVersion);
		}

		let genesis_hash: BlockHash = Readable::read(reader)?;
		let latest_block_height: u32 = Readable::read(reader)?;
		let last_block_hash: BlockHash = Readable::read(reader)?;

		let mut failed_htlcs = Vec::new();

		let channel_count: u64 = Readable::read(reader)?;
		let mut funding_txo_set = HashSet::with_capacity(cmp::min(channel_count as usize, 128));
		let mut by_id = HashMap::with_capacity(cmp::min(channel_count as usize, 128));
		let mut short_to_id = HashMap::with_capacity(cmp::min(channel_count as usize, 128));
		for _ in 0..channel_count {
			let mut channel: Channel<Signer> = Channel::read(reader, &args.keys_manager)?;
			if channel.last_block_connected != Default::default() && channel.last_block_connected != last_block_hash {
				return Err(DecodeError::InvalidValue);
			}

			let funding_txo = channel.get_funding_txo().ok_or(DecodeError::InvalidValue)?;
			funding_txo_set.insert(funding_txo.clone());
			if let Some(ref mut monitor) = args.channel_monitors.get_mut(&funding_txo) {
				if channel.get_cur_holder_commitment_transaction_number() < monitor.get_cur_holder_commitment_number() ||
						channel.get_revoked_counterparty_commitment_transaction_number() < monitor.get_min_seen_secret() ||
						channel.get_cur_counterparty_commitment_transaction_number() < monitor.get_cur_counterparty_commitment_number() ||
						channel.get_latest_monitor_update_id() > monitor.get_latest_update_id() {
					// If the channel is ahead of the monitor, return InvalidValue:
					return Err(DecodeError::InvalidValue);
				} else if channel.get_cur_holder_commitment_transaction_number() > monitor.get_cur_holder_commitment_number() ||
						channel.get_revoked_counterparty_commitment_transaction_number() > monitor.get_min_seen_secret() ||
						channel.get_cur_counterparty_commitment_transaction_number() > monitor.get_cur_counterparty_commitment_number() ||
						channel.get_latest_monitor_update_id() < monitor.get_latest_update_id() {
					// But if the channel is behind of the monitor, close the channel:
					let (_, _, mut new_failed_htlcs) = channel.force_shutdown(true);
					failed_htlcs.append(&mut new_failed_htlcs);
					monitor.broadcast_latest_holder_commitment_txn(&args.tx_broadcaster, &args.logger);
				} else {
					if let Some(short_channel_id) = channel.get_short_channel_id() {
						short_to_id.insert(short_channel_id, channel.channel_id());
					}
					by_id.insert(channel.channel_id(), channel);
				}
			} else {
				return Err(DecodeError::InvalidValue);
			}
		}

		for (ref funding_txo, ref mut monitor) in args.channel_monitors.iter_mut() {
			if !funding_txo_set.contains(funding_txo) {
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
		let mut claimable_htlcs = HashMap::with_capacity(cmp::min(claimable_htlcs_count as usize, 128));
		for _ in 0..claimable_htlcs_count {
			let payment_hash = Readable::read(reader)?;
			let previous_hops_len: u64 = Readable::read(reader)?;
			let mut previous_hops = Vec::with_capacity(cmp::min(previous_hops_len as usize, MAX_ALLOC_SIZE/mem::size_of::<ClaimableHTLC>()));
			for _ in 0..previous_hops_len {
				previous_hops.push(Readable::read(reader)?);
			}
			claimable_htlcs.insert(payment_hash, previous_hops);
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

		let last_node_announcement_serial: u32 = Readable::read(reader)?;

		let mut secp_ctx = Secp256k1::new();
		secp_ctx.seeded_randomize(&args.keys_manager.get_secure_random_bytes());

		let channel_manager = ChannelManager {
			genesis_hash,
			fee_estimator: args.fee_estimator,
			chain_monitor: args.chain_monitor,
			tx_broadcaster: args.tx_broadcaster,

			latest_block_height: AtomicUsize::new(latest_block_height as usize),
			last_block_hash: Mutex::new(last_block_hash),
			secp_ctx,

			channel_state: Mutex::new(ChannelHolder {
				by_id,
				short_to_id,
				forward_htlcs,
				claimable_htlcs,
				pending_msg_events: Vec::new(),
			}),
			our_network_key: args.keys_manager.get_node_secret(),

			last_node_announcement_serial: AtomicUsize::new(last_node_announcement_serial as usize),

			per_peer_state: RwLock::new(per_peer_state),

			pending_events: Mutex::new(pending_events_read),
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

		Ok((last_block_hash.clone(), channel_manager))
	}
}

#[cfg(test)]
mod tests {
	use ln::channelmanager::PersistenceNotifier;
	use std::sync::Arc;
	use std::sync::atomic::{AtomicBool, Ordering};
	use std::thread;
	use std::time::Duration;

	#[test]
	fn test_wait_timeout() {
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
}
