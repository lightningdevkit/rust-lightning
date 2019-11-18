//! The top-level channel management and payment tracking stuff lives here.
//!
//! The ChannelManager is the main chunk of logic implementing the lightning protocol and is
//! responsible for tracking which channels are open, HTLCs are in flight and reestablishing those
//! upon reconnect to the relevant peer(s).
//!
//! It does not manage routing logic (see ln::router for that) nor does it manage constructing
//! on-chain transactions (it only monitors the chain to watch for any force-closes that might
//! imply it needs to fail HTLCs/payments/channels it manages).

use bitcoin::blockdata::block::BlockHeader;
use bitcoin::blockdata::transaction::Transaction;
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::network::constants::Network;
use bitcoin::util::hash::BitcoinHash;

use bitcoin_hashes::{Hash, HashEngine};
use bitcoin_hashes::hmac::{Hmac, HmacEngine};
use bitcoin_hashes::sha256::Hash as Sha256;
use bitcoin_hashes::sha256d::Hash as Sha256dHash;
use bitcoin_hashes::cmp::fixed_time_eq;

use secp256k1::key::{SecretKey,PublicKey};
use secp256k1::Secp256k1;
use secp256k1::ecdh::SharedSecret;
use secp256k1;

use chain::chaininterface::{BroadcasterInterface,ChainListener,ChainWatchInterface,FeeEstimator};
use chain::transaction::OutPoint;
use ln::channel::{Channel, ChannelError};
use ln::channelmonitor::{ChannelMonitor, ChannelMonitorUpdateErr, ManyChannelMonitor, CLTV_CLAIM_BUFFER, LATENCY_GRACE_PERIOD_BLOCKS, ANTI_REORG_DELAY};
use ln::router::Route;
use ln::msgs;
use ln::msgs::LocalFeatures;
use ln::onion_utils;
use ln::msgs::{ChannelMessageHandler, DecodeError, LightningError};
use chain::keysinterface::KeysInterface;
use util::config::UserConfig;
use util::{byte_utils, events};
use util::ser::{Readable, ReadableArgs, Writeable, Writer};
use util::chacha20::ChaCha20;
use util::logger::Logger;
use util::errors::APIError;

use std::{cmp, mem};
use std::collections::{HashMap, hash_map, HashSet};
use std::io::Cursor;
use std::sync::{Arc, Mutex, MutexGuard, RwLock};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

// We hold various information about HTLC relay in the HTLC objects in Channel itself:
//
// Upon receipt of an HTLC from a peer, we'll give it a PendingHTLCStatus indicating if it should
// forward the HTLC with information it will give back to us when it does so, or if it should Fail
// the HTLC with the relevant message for the Channel to handle giving to the remote peer.
//
// When a Channel forwards an HTLC to its peer, it will give us back the PendingForwardHTLCInfo
// which we will use to construct an outbound HTLC, with a relevant HTLCSource::PreviousHopData
// filled in to indicate where it came from (which we can use to either fail-backwards or fulfill
// the HTLC backwards along the relevant path).
// Alternatively, we can fill an outbound HTLC with a HTLCSource::OutboundRoute indicating this is
// our payment, which we can use to decode errors or inform the user that the payment was sent.
/// Stores the info we will need to send when we want to forward an HTLC onwards
#[derive(Clone)] // See Channel::revoke_and_ack for why, tl;dr: Rust bug
pub(super) struct PendingForwardHTLCInfo {
	onion_packet: Option<msgs::OnionPacket>,
	incoming_shared_secret: [u8; 32],
	payment_hash: PaymentHash,
	short_channel_id: u64,
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
	Forward(PendingForwardHTLCInfo),
	Fail(HTLCFailureMsg),
}

/// Tracks the inbound corresponding to an outbound HTLC
#[derive(Clone, PartialEq)]
pub(super) struct HTLCPreviousHopData {
	short_channel_id: u64,
	htlc_id: u64,
	incoming_packet_shared_secret: [u8; 32],
}

/// Tracks the inbound corresponding to an outbound HTLC
#[derive(Clone, PartialEq)]
pub(super) enum HTLCSource {
	PreviousHopData(HTLCPreviousHopData),
	OutboundRoute {
		route: Route,
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
			route: Route { hops: Vec::new() },
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
#[derive(Hash, Copy, Clone, PartialEq, Eq, Debug)]
pub struct PaymentHash(pub [u8;32]);
/// payment_preimage type, use to route payment between hop
#[derive(Hash, Copy, Clone, PartialEq, Eq, Debug)]
pub struct PaymentPreimage(pub [u8;32]);

type ShutdownResult = (Vec<Transaction>, Vec<(HTLCSource, PaymentHash)>);

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
	fn send_err_msg_no_close(err: &'static str, channel_id: [u8; 32]) -> Self {
		Self {
			err: LightningError {
				err,
				action: msgs::ErrorAction::SendErrorMessage {
					msg: msgs::ErrorMessage {
						channel_id,
						data: err.to_string()
					},
				},
			},
			shutdown_finish: None,
		}
	}
	#[inline]
	fn ignore_no_close(err: &'static str) -> Self {
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
	fn from_finish_shutdown(err: &'static str, channel_id: [u8; 32], shutdown_res: ShutdownResult, channel_update: Option<msgs::ChannelUpdate>) -> Self {
		Self {
			err: LightningError {
				err,
				action: msgs::ErrorAction::SendErrorMessage {
					msg: msgs::ErrorMessage {
						channel_id,
						data: err.to_string()
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
					err: msg,
					action: msgs::ErrorAction::SendErrorMessage {
						msg: msgs::ErrorMessage {
							channel_id,
							data: msg.to_string()
						},
					},
				},
				ChannelError::CloseDelayBroadcast { msg, .. } => LightningError {
					err: msg,
					action: msgs::ErrorAction::SendErrorMessage {
						msg: msgs::ErrorMessage {
							channel_id,
							data: msg.to_string()
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

pub(super) enum HTLCForwardInfo {
	AddHTLC {
		prev_short_channel_id: u64,
		prev_htlc_id: u64,
		forward_info: PendingForwardHTLCInfo,
	},
	FailHTLC {
		htlc_id: u64,
		err_packet: msgs::OnionErrorPacket,
	},
}

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
pub(super) struct ChannelHolder {
	pub(super) by_id: HashMap<[u8; 32], Channel>,
	pub(super) short_to_id: HashMap<u64, [u8; 32]>,
	/// short channel id -> forward infos. Key of 0 means payments received
	/// Note that while this is held in the same mutex as the channels themselves, no consistency
	/// guarantees are made about the existence of a channel with the short id here, nor the short
	/// ids in the PendingForwardHTLCInfo!
	pub(super) forward_htlcs: HashMap<u64, Vec<HTLCForwardInfo>>,
	/// payment_hash -> Vec<(amount_received, htlc_source)> for tracking things that were to us and
	/// can be failed/claimed by the user
	/// Note that while this is held in the same mutex as the channels themselves, no consistency
	/// guarantees are made about the channels given here actually existing anymore by the time you
	/// go to read them!
	pub(super) claimable_htlcs: HashMap<PaymentHash, Vec<(u64, HTLCPreviousHopData)>>,
	/// Messages to send to peers - pushed to in the same lock that they are generated in (except
	/// for broadcast messages, where ordering isn't as strict).
	pub(super) pending_msg_events: Vec<events::MessageSendEvent>,
}
pub(super) struct MutChannelHolder<'a> {
	pub(super) by_id: &'a mut HashMap<[u8; 32], Channel>,
	pub(super) short_to_id: &'a mut HashMap<u64, [u8; 32]>,
	pub(super) forward_htlcs: &'a mut HashMap<u64, Vec<HTLCForwardInfo>>,
	pub(super) claimable_htlcs: &'a mut HashMap<PaymentHash, Vec<(u64, HTLCPreviousHopData)>>,
	pub(super) pending_msg_events: &'a mut Vec<events::MessageSendEvent>,
}
impl ChannelHolder {
	pub(super) fn borrow_parts(&mut self) -> MutChannelHolder {
		MutChannelHolder {
			by_id: &mut self.by_id,
			short_to_id: &mut self.short_to_id,
			forward_htlcs: &mut self.forward_htlcs,
			claimable_htlcs: &mut self.claimable_htlcs,
			pending_msg_events: &mut self.pending_msg_events,
		}
	}
}

#[cfg(not(any(target_pointer_width = "32", target_pointer_width = "64")))]
const ERR: () = "You need at least 32 bit pointers (well, usize, but we'll assume they're the same) for ChannelManager::latest_block_height";

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
/// returning from ManyChannelMonitor::add_update_monitor, with ChannelManagers, writing updates
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
pub struct ChannelManager {
	default_configuration: UserConfig,
	genesis_hash: Sha256dHash,
	fee_estimator: Arc<FeeEstimator>,
	monitor: Arc<ManyChannelMonitor>,
	chain_monitor: Arc<ChainWatchInterface>,
	tx_broadcaster: Arc<BroadcasterInterface>,

	#[cfg(test)]
	pub(super) latest_block_height: AtomicUsize,
	#[cfg(not(test))]
	latest_block_height: AtomicUsize,
	last_block_hash: Mutex<Sha256dHash>,
	secp_ctx: Secp256k1<secp256k1::All>,

	#[cfg(test)]
	pub(super) channel_state: Mutex<ChannelHolder>,
	#[cfg(not(test))]
	channel_state: Mutex<ChannelHolder>,
	our_network_key: SecretKey,

	pending_events: Mutex<Vec<events::Event>>,
	/// Used when we have to take a BIG lock to make sure everything is self-consistent.
	/// Essentially just when we're serializing ourselves out.
	/// Taken first everywhere where we are making changes before any other locks.
	total_consistency_lock: RwLock<()>,

	keys_manager: Arc<KeysInterface>,

	logger: Arc<Logger>,
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

macro_rules! secp_call {
	( $res: expr, $err: expr ) => {
		match $res {
			Ok(key) => key,
			Err(_) => return Err($err),
		}
	};
}

/// Details of a channel, as returned by ChannelManager::list_channels and ChannelManager::list_usable_channels
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

macro_rules! handle_error {
	($self: ident, $internal: expr) => {
		match $internal {
			Ok(msg) => Ok(msg),
			Err(MsgHandleErrInternal { err, shutdown_finish }) => {
				if let Some((shutdown_res, update_option)) = shutdown_finish {
					$self.finish_force_close_channel(shutdown_res);
					if let Some(update) = update_option {
						let mut channel_state = $self.channel_state.lock().unwrap();
						channel_state.pending_msg_events.push(events::MessageSendEvent::BroadcastChannelUpdate {
							msg: update
						});
					}
				}
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
				log_trace!($self, "Closing channel {} due to Close-required error: {}", log_bytes!($entry.key()[..]), msg);
				let (channel_id, mut chan) = $entry.remove_entry();
				if let Some(short_id) = chan.get_short_channel_id() {
					$channel_state.short_to_id.remove(&short_id);
				}
				break Err(MsgHandleErrInternal::from_finish_shutdown(msg, channel_id, chan.force_shutdown(), $self.get_channel_update(&chan).ok()))
			},
			Err(ChannelError::CloseDelayBroadcast { .. }) => { panic!("Wait is only generated on receipt of channel_reestablish, which is handled by try_chan_entry, we don't bother to support it here"); }
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
				log_trace!($self, "Closing channel {} due to Close-required error: {}", log_bytes!($entry.key()[..]), msg);
				let (channel_id, mut chan) = $entry.remove_entry();
				if let Some(short_id) = chan.get_short_channel_id() {
					$channel_state.short_to_id.remove(&short_id);
				}
				return Err(MsgHandleErrInternal::from_finish_shutdown(msg, channel_id, chan.force_shutdown(), $self.get_channel_update(&chan).ok()))
			},
			Err(ChannelError::CloseDelayBroadcast { msg, update }) => {
				log_error!($self, "Channel {} need to be shutdown but closing transactions not broadcast due to {}", log_bytes!($entry.key()[..]), msg);
				let (channel_id, mut chan) = $entry.remove_entry();
				if let Some(short_id) = chan.get_short_channel_id() {
					$channel_state.short_to_id.remove(&short_id);
				}
				if let Some(update) = update {
					if let Err(e) = $self.monitor.add_update_monitor(update.get_funding_txo().unwrap(), update) {
						match e {
							// Upstream channel is dead, but we want at least to fail backward HTLCs to save
							// downstream channels. In case of PermanentFailure, we are not going to be able
							// to claim back to_remote output on remote commitment transaction. Doesn't
							// make a difference here, we are concern about HTLCs circuit, not onchain funds.
							ChannelMonitorUpdateErr::PermanentFailure => {},
							ChannelMonitorUpdateErr::TemporaryFailure => {},
						}
					}
				}
				let mut shutdown_res = chan.force_shutdown();
				if shutdown_res.0.len() >= 1 {
					log_error!($self, "You have a toxic local commitment transaction {} avaible in channel monitor, read comment in ChannelMonitor::get_latest_local_commitment_txn to be informed of manual action to take", shutdown_res.0[0].txid());
				}
				shutdown_res.0.clear();
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
				log_error!($self, "Closing channel {} due to monitor update PermanentFailure", log_bytes!($entry.key()[..]));
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
				let res: Result<(), _> = Err(MsgHandleErrInternal::from_finish_shutdown("ChannelMonitor storage failure", channel_id, chan.force_shutdown(), $self.get_channel_update(&chan).ok()));
				res
			},
			ChannelMonitorUpdateErr::TemporaryFailure => {
				log_info!($self, "Disabling channel {} due to monitor update TemporaryFailure. On restore will send {} and process {} forwards and {} fails",
						log_bytes!($entry.key()[..]),
						if $resend_commitment && $resend_raa {
								match $action_type {
									RAACommitmentOrder::CommitmentFirst => { "commitment then RAA" },
									RAACommitmentOrder::RevokeAndACKFirst => { "RAA then commitment" },
								}
							} else if $resend_commitment { "commitment" }
							else if $resend_raa { "RAA" }
							else { "nothing" },
						(&$failed_forwards as &Vec<(PendingForwardHTLCInfo, u64)>).len(),
						(&$failed_fails as &Vec<(HTLCSource, PaymentHash, HTLCFailReason)>).len());
				if !$resend_commitment {
					debug_assert!($action_type == RAACommitmentOrder::RevokeAndACKFirst || !$resend_raa);
				}
				if !$resend_raa {
					debug_assert!($action_type == RAACommitmentOrder::CommitmentFirst || !$resend_commitment);
				}
				$entry.get_mut().monitor_update_failed($resend_raa, $resend_commitment, $failed_forwards, $failed_fails);
				Err(MsgHandleErrInternal::from_chan_no_close(ChannelError::Ignore("Failed to update ChannelMonitor"), *$entry.key()))
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

impl ChannelManager {
	/// Constructs a new ChannelManager to hold several channels and route between them.
	///
	/// This is the main "logic hub" for all channel-related actions, and implements
	/// ChannelMessageHandler.
	///
	/// Non-proportional fees are fixed according to our risk using the provided fee estimator.
	///
	/// panics if channel_value_satoshis is >= `MAX_FUNDING_SATOSHIS`!
	///
	/// User must provide the current blockchain height from which to track onchain channel
	/// funding outpoints and send payments with reliable timelocks.
	pub fn new(network: Network, feeest: Arc<FeeEstimator>, monitor: Arc<ManyChannelMonitor>, chain_monitor: Arc<ChainWatchInterface>, tx_broadcaster: Arc<BroadcasterInterface>, logger: Arc<Logger>,keys_manager: Arc<KeysInterface>, config: UserConfig, current_blockchain_height: usize) -> Result<Arc<ChannelManager>, secp256k1::Error> {
		let secp_ctx = Secp256k1::new();

		let res = Arc::new(ChannelManager {
			default_configuration: config.clone(),
			genesis_hash: genesis_block(network).header.bitcoin_hash(),
			fee_estimator: feeest.clone(),
			monitor: monitor.clone(),
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

			pending_events: Mutex::new(Vec::new()),
			total_consistency_lock: RwLock::new(()),

			keys_manager,

			logger,
		});
		let weak_res = Arc::downgrade(&res);
		res.chain_monitor.register_listener(weak_res);
		Ok(res)
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
	pub fn create_channel(&self, their_network_key: PublicKey, channel_value_satoshis: u64, push_msat: u64, user_id: u64) -> Result<(), APIError> {
		if channel_value_satoshis < 1000 {
			return Err(APIError::APIMisuseError { err: "channel_value must be at least 1000 satoshis" });
		}

		let channel = Channel::new_outbound(&*self.fee_estimator, &self.keys_manager, their_network_key, channel_value_satoshis, push_msat, user_id, Arc::clone(&self.logger), &self.default_configuration)?;
		let res = channel.get_open_channel(self.genesis_hash.clone(), &*self.fee_estimator);

		let _ = self.total_consistency_lock.read().unwrap();
		let mut channel_state = self.channel_state.lock().unwrap();
		match channel_state.by_id.entry(channel.channel_id()) {
			hash_map::Entry::Occupied(_) => {
				if cfg!(feature = "fuzztarget") {
					return Err(APIError::APIMisuseError { err: "Fuzzy bad RNG" });
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

	/// Gets the list of open channels, in random order. See ChannelDetail field documentation for
	/// more information.
	pub fn list_channels(&self) -> Vec<ChannelDetails> {
		let channel_state = self.channel_state.lock().unwrap();
		let mut res = Vec::with_capacity(channel_state.by_id.len());
		for (channel_id, channel) in channel_state.by_id.iter() {
			let (inbound_capacity_msat, outbound_capacity_msat) = channel.get_inbound_outbound_available_balance_msat();
			res.push(ChannelDetails {
				channel_id: (*channel_id).clone(),
				short_channel_id: channel.get_short_channel_id(),
				remote_network_id: channel.get_their_node_id(),
				channel_value_satoshis: channel.get_value_satoshis(),
				inbound_capacity_msat,
				outbound_capacity_msat,
				user_id: channel.get_user_id(),
				is_live: channel.is_live(),
			});
		}
		res
	}

	/// Gets the list of usable channels, in random order. Useful as an argument to
	/// Router::get_route to ensure non-announced channels are used.
	///
	/// These are guaranteed to have their is_live value set to true, see the documentation for
	/// ChannelDetails::is_live for more info on exactly what the criteria are.
	pub fn list_usable_channels(&self) -> Vec<ChannelDetails> {
		let channel_state = self.channel_state.lock().unwrap();
		let mut res = Vec::with_capacity(channel_state.by_id.len());
		for (channel_id, channel) in channel_state.by_id.iter() {
			// Note we use is_live here instead of usable which leads to somewhat confused
			// internal/external nomenclature, but that's ok cause that's probably what the user
			// really wanted anyway.
			if channel.is_live() {
				let (inbound_capacity_msat, outbound_capacity_msat) = channel.get_inbound_outbound_available_balance_msat();
				res.push(ChannelDetails {
					channel_id: (*channel_id).clone(),
					short_channel_id: channel.get_short_channel_id(),
					remote_network_id: channel.get_their_node_id(),
					channel_value_satoshis: channel.get_value_satoshis(),
					inbound_capacity_msat,
					outbound_capacity_msat,
					user_id: channel.get_user_id(),
					is_live: true,
				});
			}
		}
		res
	}

	/// Begins the process of closing a channel. After this call (plus some timeout), no new HTLCs
	/// will be accepted on the given channel, and after additional timeout/the closing of all
	/// pending HTLCs, the channel will be closed on chain.
	///
	/// May generate a SendShutdown message event on success, which should be relayed.
	pub fn close_channel(&self, channel_id: &[u8; 32]) -> Result<(), APIError> {
		let _ = self.total_consistency_lock.read().unwrap();

		let (mut failed_htlcs, chan_option) = {
			let mut channel_state_lock = self.channel_state.lock().unwrap();
			let channel_state = channel_state_lock.borrow_parts();
			match channel_state.by_id.entry(channel_id.clone()) {
				hash_map::Entry::Occupied(mut chan_entry) => {
					let (shutdown_msg, failed_htlcs) = chan_entry.get_mut().get_shutdown()?;
					channel_state.pending_msg_events.push(events::MessageSendEvent::SendShutdown {
						node_id: chan_entry.get().get_their_node_id(),
						msg: shutdown_msg
					});
					if chan_entry.get().is_shutdown() {
						if let Some(short_id) = chan_entry.get().get_short_channel_id() {
							channel_state.short_to_id.remove(&short_id);
						}
						(failed_htlcs, Some(chan_entry.remove_entry().1))
					} else { (failed_htlcs, None) }
				},
				hash_map::Entry::Vacant(_) => return Err(APIError::ChannelUnavailable{err: "No such channel"})
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
		let (local_txn, mut failed_htlcs) = shutdown_res;
		log_trace!(self, "Finishing force-closure of channel with {} transactions to broadcast and {} HTLCs to fail", local_txn.len(), failed_htlcs.len());
		for htlc_source in failed_htlcs.drain(..) {
			self.fail_htlc_backwards_internal(self.channel_state.lock().unwrap(), htlc_source.0, &htlc_source.1, HTLCFailReason::Reason { failure_code: 0x4000 | 8, data: Vec::new() });
		}
		for tx in local_txn {
			self.tx_broadcaster.broadcast_transaction(&tx);
		}
	}

	/// Force closes a channel, immediately broadcasting the latest local commitment transaction to
	/// the chain and rejecting new HTLCs on the given channel.
	pub fn force_close_channel(&self, channel_id: &[u8; 32]) {
		let _ = self.total_consistency_lock.read().unwrap();

		let mut chan = {
			let mut channel_state_lock = self.channel_state.lock().unwrap();
			let channel_state = channel_state_lock.borrow_parts();
			if let Some(chan) = channel_state.by_id.remove(channel_id) {
				if let Some(short_id) = chan.get_short_channel_id() {
					channel_state.short_to_id.remove(&short_id);
				}
				chan
			} else {
				return;
			}
		};
		log_trace!(self, "Force-closing channel {}", log_bytes!(channel_id[..]));
		self.finish_force_close_channel(chan.force_shutdown());
		if let Ok(update) = self.get_channel_update(&chan) {
			let mut channel_state = self.channel_state.lock().unwrap();
			channel_state.pending_msg_events.push(events::MessageSendEvent::BroadcastChannelUpdate {
				msg: update
			});
		}
	}

	/// Force close all channels, immediately broadcasting the latest local commitment transaction
	/// for each to the chain and rejecting new HTLCs on each.
	pub fn force_close_all_channels(&self) {
		for chan in self.list_channels() {
			self.force_close_channel(&chan.channel_id);
		}
	}

	const ZERO:[u8; 65] = [0; 65];
	fn decode_update_add_htlc_onion(&self, msg: &msgs::UpdateAddHTLC) -> (PendingHTLCStatus, MutexGuard<ChannelHolder>) {
		macro_rules! return_malformed_err {
			($msg: expr, $err_code: expr) => {
				{
					log_info!(self, "Failed to accept/forward incoming HTLC: {}", $msg);
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
					log_info!(self, "Failed to accept/forward incoming HTLC: {}", $msg);
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
		let next_hop_data = {
			let mut decoded = [0; 65];
			chacha.process(&msg.onion_routing_packet.hop_data[0..65], &mut decoded);
			match msgs::OnionHopData::read(&mut Cursor::new(&decoded[..])) {
				Err(err) => {
					let error_code = match err {
						msgs::DecodeError::UnknownVersion => 0x4000 | 1, // unknown realm byte
						_ => 0x2000 | 2, // Should never happen
					};
					return_err!("Unable to decode our hop data", error_code, &[0;0]);
				},
				Ok(msg) => msg
			}
		};

		let pending_forward_info = if next_hop_data.hmac == [0; 32] {
				// OUR PAYMENT!
				// final_expiry_too_soon
				if (msg.cltv_expiry as u64) < self.latest_block_height.load(Ordering::Acquire) as u64 + (CLTV_CLAIM_BUFFER + LATENCY_GRACE_PERIOD_BLOCKS) as u64 {
					return_err!("The final CLTV expiry is too soon to handle", 17, &[0;0]);
				}
				// final_incorrect_htlc_amount
				if next_hop_data.data.amt_to_forward > msg.amount_msat {
					return_err!("Upstream node sent less than we were supposed to receive in payment", 19, &byte_utils::be64_to_array(msg.amount_msat));
				}
				// final_incorrect_cltv_expiry
				if next_hop_data.data.outgoing_cltv_value != msg.cltv_expiry {
					return_err!("Upstream node set CLTV to the wrong value", 18, &byte_utils::be32_to_array(msg.cltv_expiry));
				}

				// Note that we could obviously respond immediately with an update_fulfill_htlc
				// message, however that would leak that we are the recipient of this payment, so
				// instead we stay symmetric with the forwarding case, only responding (after a
				// delay) once they've send us a commitment_signed!

				PendingHTLCStatus::Forward(PendingForwardHTLCInfo {
					onion_packet: None,
					payment_hash: msg.payment_hash.clone(),
					short_channel_id: 0,
					incoming_shared_secret: shared_secret,
					amt_to_forward: next_hop_data.data.amt_to_forward,
					outgoing_cltv_value: next_hop_data.data.outgoing_cltv_value,
				})
			} else {
				let mut new_packet_data = [0; 20*65];
				chacha.process(&msg.onion_routing_packet.hop_data[65..], &mut new_packet_data[0..19*65]);
				chacha.process(&ChannelManager::ZERO[..], &mut new_packet_data[19*65..]);

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
					hmac: next_hop_data.hmac.clone(),
				};

				PendingHTLCStatus::Forward(PendingForwardHTLCInfo {
					onion_packet: Some(outgoing_packet),
					payment_hash: msg.payment_hash.clone(),
					short_channel_id: next_hop_data.data.short_channel_id,
					incoming_shared_secret: shared_secret,
					amt_to_forward: next_hop_data.data.amt_to_forward,
					outgoing_cltv_value: next_hop_data.data.outgoing_cltv_value,
				})
			};

		channel_state = Some(self.channel_state.lock().unwrap());
		if let &PendingHTLCStatus::Forward(PendingForwardHTLCInfo { ref onion_packet, ref short_channel_id, ref amt_to_forward, ref outgoing_cltv_value, .. }) = &pending_forward_info {
			if onion_packet.is_some() { // If short_channel_id is 0 here, we'll reject them in the body here
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
					if *amt_to_forward < chan.get_their_htlc_minimum_msat() { // amount_below_minimum
						break Some(("HTLC amount was below the htlc_minimum_msat", 0x1000 | 11, Some(self.get_channel_update(chan).unwrap())));
					}
					let fee = amt_to_forward.checked_mul(chan.get_fee_proportional_millionths() as u64).and_then(|prop_fee| { (prop_fee / 1000000).checked_add(chan.get_our_fee_base_msat(&*self.fee_estimator) as u64) });
					if fee.is_none() || msg.amount_msat < fee.unwrap() || (msg.amount_msat - fee.unwrap()) < *amt_to_forward { // fee_insufficient
						break Some(("Prior hop has deviated from specified fees parameters or origin node has obsolete ones", 0x1000 | 12, Some(self.get_channel_update(chan).unwrap())));
					}
					if (msg.cltv_expiry as u64) < (*outgoing_cltv_value) as u64 + CLTV_EXPIRY_DELTA as u64 { // incorrect_cltv_expiry
						break Some(("Forwarding node has tampered with the intended HTLC values or origin node has an obsolete cltv_expiry_delta", 0x1000 | 13, Some(self.get_channel_update(chan).unwrap())));
					}
					let cur_height = self.latest_block_height.load(Ordering::Acquire) as u32 + 1;
					// We want to have at least LATENCY_GRACE_PERIOD_BLOCKS to fail prior to going on chain CLAIM_BUFFER blocks before expiration
					if msg.cltv_expiry <= cur_height + CLTV_CLAIM_BUFFER + LATENCY_GRACE_PERIOD_BLOCKS as u32 { // expiry_too_soon
						break Some(("CLTV expiry is too close", 0x1000 | 14, Some(self.get_channel_update(chan).unwrap())));
					}
					if msg.cltv_expiry > cur_height + CLTV_FAR_FAR_AWAY as u32 { // expiry_too_far
						break Some(("CLTV expiry is too far in the future", 21, None));
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
							res.extend_from_slice(&byte_utils::be16_to_array(chan_update.contents.flags));
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
	fn get_channel_update(&self, chan: &Channel) -> Result<msgs::ChannelUpdate, LightningError> {
		let short_channel_id = match chan.get_short_channel_id() {
			None => return Err(LightningError{err: "Channel not yet established", action: msgs::ErrorAction::IgnoreError}),
			Some(id) => id,
		};

		let were_node_one = PublicKey::from_secret_key(&self.secp_ctx, &self.our_network_key).serialize()[..] < chan.get_their_node_id().serialize()[..];

		let unsigned = msgs::UnsignedChannelUpdate {
			chain_hash: self.genesis_hash,
			short_channel_id: short_channel_id,
			timestamp: chan.get_channel_update_count(),
			flags: (!were_node_one) as u16 | ((!chan.is_live() as u16) << 1),
			cltv_expiry_delta: CLTV_EXPIRY_DELTA,
			htlc_minimum_msat: chan.get_our_htlc_minimum_msat(),
			fee_base_msat: chan.get_our_fee_base_msat(&*self.fee_estimator),
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
	/// May generate a SendHTLCs message event on success, which should be relayed.
	///
	/// Raises APIError::RoutError when invalid route or forward parameter
	/// (cltv_delta, fee, node public key) is specified.
	/// Raises APIError::ChannelUnavailable if the next-hop channel is not available for updates
	/// (including due to previous monitor update failure or new permanent monitor update failure).
	/// Raised APIError::MonitorUpdateFailed if a new monitor update failure prevented sending the
	/// relevant updates.
	///
	/// In case of APIError::RouteError/APIError::ChannelUnavailable, the payment send has failed
	/// and you may wish to retry via a different route immediately.
	/// In case of APIError::MonitorUpdateFailed, the commitment update has been irrevocably
	/// committed on our end and we're just waiting for a monitor update to send it. Do NOT retry
	/// the payment via a different route unless you intend to pay twice!
	pub fn send_payment(&self, route: Route, payment_hash: PaymentHash) -> Result<(), APIError> {
		if route.hops.len() < 1 || route.hops.len() > 20 {
			return Err(APIError::RouteError{err: "Route didn't go anywhere/had bogus size"});
		}
		let our_node_id = self.get_our_node_id();
		for (idx, hop) in route.hops.iter().enumerate() {
			if idx != route.hops.len() - 1 && hop.pubkey == our_node_id {
				return Err(APIError::RouteError{err: "Route went through us but wasn't a simple rebalance loop to us"});
			}
		}

		let session_priv = self.keys_manager.get_session_key();

		let cur_height = self.latest_block_height.load(Ordering::Acquire) as u32 + 1;

		let onion_keys = secp_call!(onion_utils::construct_onion_keys(&self.secp_ctx, &route, &session_priv),
				APIError::RouteError{err: "Pubkey along hop was maliciously selected"});
		let (onion_payloads, htlc_msat, htlc_cltv) = onion_utils::build_onion_payloads(&route, cur_height)?;
		let onion_packet = onion_utils::construct_onion_packet(onion_payloads, onion_keys, &payment_hash);

		let _ = self.total_consistency_lock.read().unwrap();

		let err: Result<(), _> = loop {
			let mut channel_lock = self.channel_state.lock().unwrap();

			let id = match channel_lock.short_to_id.get(&route.hops.first().unwrap().short_channel_id) {
				None => return Err(APIError::ChannelUnavailable{err: "No channel available with first hop!"}),
				Some(id) => id.clone(),
			};

			let channel_state = channel_lock.borrow_parts();
			if let hash_map::Entry::Occupied(mut chan) = channel_state.by_id.entry(id) {
				match {
					if chan.get().get_their_node_id() != route.hops.first().unwrap().pubkey {
						return Err(APIError::RouteError{err: "Node ID mismatch on first hop!"});
					}
					if !chan.get().is_live() {
						return Err(APIError::ChannelUnavailable{err: "Peer for first hop currently disconnected/pending monitor update!"});
					}
					break_chan_entry!(self, chan.get_mut().send_htlc_and_commit(htlc_msat, payment_hash.clone(), htlc_cltv, HTLCSource::OutboundRoute {
						route: route.clone(),
						session_priv: session_priv.clone(),
						first_hop_htlc_msat: htlc_msat,
					}, onion_packet), channel_state, chan)
				} {
					Some((update_add, commitment_signed, chan_monitor)) => {
						if let Err(e) = self.monitor.add_update_monitor(chan_monitor.get_funding_txo().unwrap(), chan_monitor) {
							maybe_break_monitor_err!(self, e, channel_state, chan, RAACommitmentOrder::CommitmentFirst, false, true);
							// Note that MonitorUpdateFailed here indicates (per function docs)
							// that we will resent the commitment update once we unfree monitor
							// updating, so we have to take special care that we don't return
							// something else in case we will resend later!
							return Err(APIError::MonitorUpdateFailed);
						}

						channel_state.pending_msg_events.push(events::MessageSendEvent::UpdateHTLCs {
							node_id: route.hops.first().unwrap().pubkey,
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

		match handle_error!(self, err) {
			Ok(_) => unreachable!(),
			Err(e) => {
				if let msgs::ErrorAction::IgnoreError = e.action {
				} else {
					log_error!(self, "Got bad keys: {}!", e.err);
					let mut channel_state = self.channel_state.lock().unwrap();
					channel_state.pending_msg_events.push(events::MessageSendEvent::HandleError {
						node_id: route.hops.first().unwrap().pubkey,
						action: e.action,
					});
				}
				Err(APIError::ChannelUnavailable { err: e.err })
			},
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
		let _ = self.total_consistency_lock.read().unwrap();

		let (mut chan, msg, chan_monitor) = {
			let (res, chan) = {
				let mut channel_state = self.channel_state.lock().unwrap();
				match channel_state.by_id.remove(temporary_channel_id) {
					Some(mut chan) => {
						(chan.get_outbound_funding_created(funding_txo)
							.map_err(|e| if let ChannelError::Close(msg) = e {
								MsgHandleErrInternal::from_finish_shutdown(msg, chan.channel_id(), chan.force_shutdown(), None)
							} else { unreachable!(); })
						, chan)
					},
					None => return
				}
			};
			match handle_error!(self, res) {
				Ok(funding_msg) => {
					(chan, funding_msg.0, funding_msg.1)
				},
				Err(e) => {
					log_error!(self, "Got bad signatures: {}!", e.err);
					let mut channel_state = self.channel_state.lock().unwrap();
					channel_state.pending_msg_events.push(events::MessageSendEvent::HandleError {
						node_id: chan.get_their_node_id(),
						action: e.action,
					});
					return;
				},
			}
		};
		// Because we have exclusive ownership of the channel here we can release the channel_state
		// lock before add_update_monitor
		if let Err(e) = self.monitor.add_update_monitor(chan_monitor.get_funding_txo().unwrap(), chan_monitor) {
			match e {
				ChannelMonitorUpdateErr::PermanentFailure => {
					match handle_error!(self, Err(MsgHandleErrInternal::from_finish_shutdown("ChannelMonitor storage failure", *temporary_channel_id, chan.force_shutdown(), None))) {
						Err(e) => {
							log_error!(self, "Failed to store ChannelMonitor update for funding tx generation");
							let mut channel_state = self.channel_state.lock().unwrap();
							channel_state.pending_msg_events.push(events::MessageSendEvent::HandleError {
								node_id: chan.get_their_node_id(),
								action: e.action,
							});
							return;
						},
						Ok(()) => unreachable!(),
					}
				},
				ChannelMonitorUpdateErr::TemporaryFailure => {
					// Its completely fine to continue with a FundingCreated until the monitor
					// update is persisted, as long as we don't generate the FundingBroadcastSafe
					// until the monitor has been safely persisted (as funding broadcast is not,
					// in fact, safe).
					chan.monitor_update_failed(false, false, Vec::new(), Vec::new());
				},
			}
		}

		let mut channel_state = self.channel_state.lock().unwrap();
		channel_state.pending_msg_events.push(events::MessageSendEvent::SendFundingCreated {
			node_id: chan.get_their_node_id(),
			msg: msg,
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

	fn get_announcement_sigs(&self, chan: &Channel) -> Option<msgs::AnnouncementSignatures> {
		if !chan.should_announce() { return None }

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

	/// Processes HTLCs which are pending waiting on random forward delay.
	///
	/// Should only really ever be called in response to a PendingHTLCsForwardable event.
	/// Will likely generate further events.
	pub fn process_pending_htlc_forwards(&self) {
		let _ = self.total_consistency_lock.read().unwrap();

		let mut new_events = Vec::new();
		let mut failed_forwards = Vec::new();
		let mut handle_errors = Vec::new();
		{
			let mut channel_state_lock = self.channel_state.lock().unwrap();
			let channel_state = channel_state_lock.borrow_parts();

			for (short_chan_id, mut pending_forwards) in channel_state.forward_htlcs.drain() {
				if short_chan_id != 0 {
					let forward_chan_id = match channel_state.short_to_id.get(&short_chan_id) {
						Some(chan_id) => chan_id.clone(),
						None => {
							failed_forwards.reserve(pending_forwards.len());
							for forward_info in pending_forwards.drain(..) {
								match forward_info {
									HTLCForwardInfo::AddHTLC { prev_short_channel_id, prev_htlc_id, forward_info } => {
										let htlc_source = HTLCSource::PreviousHopData(HTLCPreviousHopData {
											short_channel_id: prev_short_channel_id,
											htlc_id: prev_htlc_id,
											incoming_packet_shared_secret: forward_info.incoming_shared_secret,
										});
										failed_forwards.push((htlc_source, forward_info.payment_hash, 0x4000 | 10, None));
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
								HTLCForwardInfo::AddHTLC { prev_short_channel_id, prev_htlc_id, forward_info } => {
									log_trace!(self, "Adding HTLC from short id {} with payment_hash {} to channel with short id {} after delay", log_bytes!(forward_info.payment_hash.0), prev_short_channel_id, short_chan_id);
									let htlc_source = HTLCSource::PreviousHopData(HTLCPreviousHopData {
										short_channel_id: prev_short_channel_id,
										htlc_id: prev_htlc_id,
										incoming_packet_shared_secret: forward_info.incoming_shared_secret,
									});
									match chan.get_mut().send_htlc(forward_info.amt_to_forward, forward_info.payment_hash, forward_info.outgoing_cltv_value, htlc_source.clone(), forward_info.onion_packet.unwrap()) {
										Err(e) => {
											if let ChannelError::Ignore(msg) = e {
												log_trace!(self, "Failed to forward HTLC with payment_hash {}: {}", log_bytes!(forward_info.payment_hash.0), msg);
											} else {
												panic!("Stated return value requirements in send_htlc() were not met");
											}
											let chan_update = self.get_channel_update(chan.get()).unwrap();
											failed_forwards.push((htlc_source, forward_info.payment_hash, 0x1000 | 7, Some(chan_update)));
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
								HTLCForwardInfo::FailHTLC { htlc_id, err_packet } => {
									log_trace!(self, "Failing HTLC back to channel with short id {} after delay", short_chan_id);
									match chan.get_mut().get_update_fail_htlc(htlc_id, err_packet) {
										Err(e) => {
											if let ChannelError::Ignore(msg) = e {
												log_trace!(self, "Failed to fail backwards to short_id {}: {}", short_chan_id, msg);
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
							let (commitment_msg, monitor) = match chan.get_mut().send_commitment() {
								Ok(res) => res,
								Err(e) => {
									// We surely failed send_commitment due to bad keys, in that case
									// close channel and then send error message to peer.
									let their_node_id = chan.get().get_their_node_id();
									let err: Result<(), _>  = match e {
										ChannelError::Ignore(_) => {
											panic!("Stated return value requirements in send_commitment() were not met");
										},
										ChannelError::Close(msg) => {
											log_trace!(self, "Closing channel {} due to Close-required error: {}", log_bytes!(chan.key()[..]), msg);
											let (channel_id, mut channel) = chan.remove_entry();
											if let Some(short_id) = channel.get_short_channel_id() {
												channel_state.short_to_id.remove(&short_id);
											}
											Err(MsgHandleErrInternal::from_finish_shutdown(msg, channel_id, channel.force_shutdown(), self.get_channel_update(&channel).ok()))
										},
										ChannelError::CloseDelayBroadcast { .. } => { panic!("Wait is only generated on receipt of channel_reestablish, which is handled by try_chan_entry, we don't bother to support it here"); }
									};
									match handle_error!(self, err) {
										Ok(_) => unreachable!(),
										Err(e) => {
											match e.action {
												msgs::ErrorAction::IgnoreError => {},
												_ => {
													log_error!(self, "Got bad keys: {}!", e.err);
													let mut channel_state = self.channel_state.lock().unwrap();
													channel_state.pending_msg_events.push(events::MessageSendEvent::HandleError {
														node_id: their_node_id,
														action: e.action,
													});
												},
											}
											continue;
										},
									}
								}
							};
							if let Err(e) = self.monitor.add_update_monitor(monitor.get_funding_txo().unwrap(), monitor) {
								handle_errors.push((chan.get().get_their_node_id(), handle_monitor_err!(self, e, channel_state, chan, RAACommitmentOrder::CommitmentFirst, false, true)));
								continue;
							}
							channel_state.pending_msg_events.push(events::MessageSendEvent::UpdateHTLCs {
								node_id: chan.get().get_their_node_id(),
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
							HTLCForwardInfo::AddHTLC { prev_short_channel_id, prev_htlc_id, forward_info } => {
								let prev_hop_data = HTLCPreviousHopData {
									short_channel_id: prev_short_channel_id,
									htlc_id: prev_htlc_id,
									incoming_packet_shared_secret: forward_info.incoming_shared_secret,
								};
								match channel_state.claimable_htlcs.entry(forward_info.payment_hash) {
									hash_map::Entry::Occupied(mut entry) => entry.get_mut().push((forward_info.amt_to_forward, prev_hop_data)),
									hash_map::Entry::Vacant(entry) => { entry.insert(vec![(forward_info.amt_to_forward, prev_hop_data)]); },
								};
								new_events.push(events::Event::PaymentReceived {
									payment_hash: forward_info.payment_hash,
									amt: forward_info.amt_to_forward,
								});
							},
							HTLCForwardInfo::FailHTLC { .. } => {
								panic!("Got pending fail of our own HTLC");
							}
						}
					}
				}
			}
		}

		for (htlc_source, payment_hash, failure_code, update) in failed_forwards.drain(..) {
			match update {
				None => self.fail_htlc_backwards_internal(self.channel_state.lock().unwrap(), htlc_source, &payment_hash, HTLCFailReason::Reason { failure_code, data: Vec::new() }),
				Some(chan_update) => self.fail_htlc_backwards_internal(self.channel_state.lock().unwrap(), htlc_source, &payment_hash, HTLCFailReason::Reason { failure_code, data: chan_update.encode_with_len() }),
			};
		}

		for (their_node_id, err) in handle_errors.drain(..) {
			match handle_error!(self, err) {
				Ok(_) => {},
				Err(e) => {
					if let msgs::ErrorAction::IgnoreError = e.action {
					} else {
						let mut channel_state = self.channel_state.lock().unwrap();
						channel_state.pending_msg_events.push(events::MessageSendEvent::HandleError {
							node_id: their_node_id,
							action: e.action,
						});
					}
				},
			}
		}

		if new_events.is_empty() { return }
		let mut events = self.pending_events.lock().unwrap();
		events.append(&mut new_events);
	}

	/// Indicates that the preimage for payment_hash is unknown or the received amount is incorrect
	/// after a PaymentReceived event, failing the HTLC back to its origin and freeing resources
	/// along the path (including in our own channel on which we received it).
	/// Returns false if no payment was found to fail backwards, true if the process of failing the
	/// HTLC backwards has been started.
	pub fn fail_htlc_backwards(&self, payment_hash: &PaymentHash) -> bool {
		let _ = self.total_consistency_lock.read().unwrap();

		let mut channel_state = Some(self.channel_state.lock().unwrap());
		let removed_source = channel_state.as_mut().unwrap().claimable_htlcs.remove(payment_hash);
		if let Some(mut sources) = removed_source {
			for (recvd_value, htlc_with_hash) in sources.drain(..) {
				if channel_state.is_none() { channel_state = Some(self.channel_state.lock().unwrap()); }
				self.fail_htlc_backwards_internal(channel_state.take().unwrap(),
						HTLCSource::PreviousHopData(htlc_with_hash), payment_hash,
						HTLCFailReason::Reason { failure_code: 0x4000 | 15, data: byte_utils::be64_to_array(recvd_value).to_vec() });
			}
			true
		} else { false }
	}

	/// Fails an HTLC backwards to the sender of it to us.
	/// Note that while we take a channel_state lock as input, we do *not* assume consistency here.
	/// There are several callsites that do stupid things like loop over a list of payment_hashes
	/// to fail and take the channel_state lock for each iteration (as we take ownership and may
	/// drop it). In other words, no assumptions are made that entries in claimable_htlcs point to
	/// still-available channels.
	fn fail_htlc_backwards_internal(&self, mut channel_state_lock: MutexGuard<ChannelHolder>, source: HTLCSource, payment_hash: &PaymentHash, onion_error: HTLCFailReason) {
		//TODO: There is a timing attack here where if a node fails an HTLC back to us they can
		//identify whether we sent it or not based on the (I presume) very different runtime
		//between the branches here. We should make this async and move it into the forward HTLCs
		//timer handling.
		match source {
			HTLCSource::OutboundRoute { ref route, .. } => {
				log_trace!(self, "Failing outbound payment HTLC with payment_hash {}", log_bytes!(payment_hash.0));
				mem::drop(channel_state_lock);
				match &onion_error {
					&HTLCFailReason::LightningError { ref err } => {
#[cfg(test)]
						let (channel_update, payment_retryable, onion_error_code) = onion_utils::process_onion_failure(&self.secp_ctx, &self.logger, &source, err.data.clone());
#[cfg(not(test))]
						let (channel_update, payment_retryable, _) = onion_utils::process_onion_failure(&self.secp_ctx, &self.logger, &source, err.data.clone());
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
								error_code: onion_error_code
							}
						);
					},
					&HTLCFailReason::Reason {
#[cfg(test)]
							ref failure_code,
							.. } => {
						// we get a fail_malformed_htlc from the first hop
						// TODO: We'd like to generate a PaymentFailureNetworkUpdate for temporary
						// failures here, but that would be insufficient as Router::get_route
						// generally ignores its view of our own channels as we provide them via
						// ChannelDetails.
						// TODO: For non-temporary failures, we really should be closing the
						// channel here as we apparently can't relay through them anyway.
						self.pending_events.lock().unwrap().push(
							events::Event::PaymentFailed {
								payment_hash: payment_hash.clone(),
								rejected_by_dest: route.hops.len() == 1,
#[cfg(test)]
								error_code: Some(*failure_code),
							}
						);
					}
				}
			},
			HTLCSource::PreviousHopData(HTLCPreviousHopData { short_channel_id, htlc_id, incoming_packet_shared_secret }) => {
				let err_packet = match onion_error {
					HTLCFailReason::Reason { failure_code, data } => {
						log_trace!(self, "Failing HTLC with payment_hash {} backwards from us with code {}", log_bytes!(payment_hash.0), failure_code);
						let packet = onion_utils::build_failure_packet(&incoming_packet_shared_secret, failure_code, &data[..]).encode();
						onion_utils::encrypt_failure_packet(&incoming_packet_shared_secret, &packet)
					},
					HTLCFailReason::LightningError { err } => {
						log_trace!(self, "Failing HTLC with payment_hash {} backwards with pre-built LightningError", log_bytes!(payment_hash.0));
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
	/// May panic if called except in response to a PaymentReceived event.
	pub fn claim_funds(&self, payment_preimage: PaymentPreimage) -> bool {
		let payment_hash = PaymentHash(Sha256::hash(&payment_preimage.0).into_inner());

		let _ = self.total_consistency_lock.read().unwrap();

		let mut channel_state = Some(self.channel_state.lock().unwrap());
		let removed_source = channel_state.as_mut().unwrap().claimable_htlcs.remove(&payment_hash);
		if let Some(mut sources) = removed_source {
			// TODO: We should require the user specify the expected amount so that we can claim
			// only payments for the correct amount, and reject payments for incorrect amounts
			// (which are probably middle nodes probing to break our privacy).
			for (_, htlc_with_hash) in sources.drain(..) {
				if channel_state.is_none() { channel_state = Some(self.channel_state.lock().unwrap()); }
				self.claim_funds_internal(channel_state.take().unwrap(), HTLCSource::PreviousHopData(htlc_with_hash), payment_preimage);
			}
			true
		} else { false }
	}
	fn claim_funds_internal(&self, mut channel_state_lock: MutexGuard<ChannelHolder>, source: HTLCSource, payment_preimage: PaymentPreimage) {
		let (their_node_id, err) = loop {
			match source {
				HTLCSource::OutboundRoute { .. } => {
					mem::drop(channel_state_lock);
					let mut pending_events = self.pending_events.lock().unwrap();
					pending_events.push(events::Event::PaymentSent {
						payment_preimage
					});
				},
				HTLCSource::PreviousHopData(HTLCPreviousHopData { short_channel_id, htlc_id, .. }) => {
					//TODO: Delay the claimed_funds relaying just like we do outbound relay!
					let channel_state = channel_state_lock.borrow_parts();

					let chan_id = match channel_state.short_to_id.get(&short_channel_id) {
						Some(chan_id) => chan_id.clone(),
						None => {
							// TODO: There is probably a channel manager somewhere that needs to
							// learn the preimage as the channel already hit the chain and that's
							// why it's missing.
							return
						}
					};

					if let hash_map::Entry::Occupied(mut chan) = channel_state.by_id.entry(chan_id) {
						let was_frozen_for_monitor = chan.get().is_awaiting_monitor_update();
						match chan.get_mut().get_update_fulfill_htlc_and_commit(htlc_id, payment_preimage) {
							Ok((msgs, monitor_option)) => {
								if let Some(chan_monitor) = monitor_option {
									if let Err(e) = self.monitor.add_update_monitor(chan_monitor.get_funding_txo().unwrap(), chan_monitor) {
										if was_frozen_for_monitor {
											assert!(msgs.is_none());
										} else {
											break (chan.get().get_their_node_id(), handle_monitor_err!(self, e, channel_state, chan, RAACommitmentOrder::CommitmentFirst, false, msgs.is_some()));
										}
									}
								}
								if let Some((msg, commitment_signed)) = msgs {
									channel_state.pending_msg_events.push(events::MessageSendEvent::UpdateHTLCs {
										node_id: chan.get().get_their_node_id(),
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
							},
							Err(_e) => {
								// TODO: There is probably a channel manager somewhere that needs to
								// learn the preimage as the channel may be about to hit the chain.
								//TODO: Do something with e?
								return
							},
						}
					} else { unreachable!(); }
				},
			}
			return;
		};

		match handle_error!(self, err) {
			Ok(_) => {},
			Err(e) => {
				if let msgs::ErrorAction::IgnoreError = e.action {
				} else {
					let mut channel_state = self.channel_state.lock().unwrap();
					channel_state.pending_msg_events.push(events::MessageSendEvent::HandleError {
						node_id: their_node_id,
						action: e.action,
					});
				}
			},
		}
	}

	/// Gets the node_id held by this ChannelManager
	pub fn get_our_node_id(&self) -> PublicKey {
		PublicKey::from_secret_key(&self.secp_ctx, &self.our_network_key)
	}

	/// Used to restore channels to normal operation after a
	/// ChannelMonitorUpdateErr::TemporaryFailure was returned from a channel monitor update
	/// operation.
	pub fn test_restore_channel_monitor(&self) {
		let mut close_results = Vec::new();
		let mut htlc_forwards = Vec::new();
		let mut htlc_failures = Vec::new();
		let mut pending_events = Vec::new();
		let _ = self.total_consistency_lock.read().unwrap();

		{
			let mut channel_lock = self.channel_state.lock().unwrap();
			let channel_state = channel_lock.borrow_parts();
			let short_to_id = channel_state.short_to_id;
			let pending_msg_events = channel_state.pending_msg_events;
			channel_state.by_id.retain(|_, channel| {
				if channel.is_awaiting_monitor_update() {
					let chan_monitor = channel.channel_monitor();
					if let Err(e) = self.monitor.add_update_monitor(chan_monitor.get_funding_txo().unwrap(), chan_monitor) {
						match e {
							ChannelMonitorUpdateErr::PermanentFailure => {
								// TODO: There may be some pending HTLCs that we intended to fail
								// backwards when a monitor update failed. We should make sure
								// knowledge of those gets moved into the appropriate in-memory
								// ChannelMonitor and they get failed backwards once we get
								// on-chain confirmations.
								// Note I think #198 addresses this, so once it's merged a test
								// should be written.
								if let Some(short_id) = channel.get_short_channel_id() {
									short_to_id.remove(&short_id);
								}
								close_results.push(channel.force_shutdown());
								if let Ok(update) = self.get_channel_update(&channel) {
									pending_msg_events.push(events::MessageSendEvent::BroadcastChannelUpdate {
										msg: update
									});
								}
								false
							},
							ChannelMonitorUpdateErr::TemporaryFailure => true,
						}
					} else {
						let (raa, commitment_update, order, pending_forwards, mut pending_failures, needs_broadcast_safe, funding_locked) = channel.monitor_updating_restored();
						if !pending_forwards.is_empty() {
							htlc_forwards.push((channel.get_short_channel_id().expect("We can't have pending forwards before funding confirmation"), pending_forwards));
						}
						htlc_failures.append(&mut pending_failures);

						macro_rules! handle_cs { () => {
							if let Some(update) = commitment_update {
								pending_msg_events.push(events::MessageSendEvent::UpdateHTLCs {
									node_id: channel.get_their_node_id(),
									updates: update,
								});
							}
						} }
						macro_rules! handle_raa { () => {
							if let Some(revoke_and_ack) = raa {
								pending_msg_events.push(events::MessageSendEvent::SendRevokeAndACK {
									node_id: channel.get_their_node_id(),
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
								node_id: channel.get_their_node_id(),
								msg,
							});
							if let Some(announcement_sigs) = self.get_announcement_sigs(channel) {
								pending_msg_events.push(events::MessageSendEvent::SendAnnouncementSignatures {
									node_id: channel.get_their_node_id(),
									msg: announcement_sigs,
								});
							}
							short_to_id.insert(channel.get_short_channel_id().unwrap(), channel.channel_id());
						}
						true
					}
				} else { true }
			});
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

	fn internal_open_channel(&self, their_node_id: &PublicKey, their_local_features: LocalFeatures, msg: &msgs::OpenChannel) -> Result<(), MsgHandleErrInternal> {
		if msg.chain_hash != self.genesis_hash {
			return Err(MsgHandleErrInternal::send_err_msg_no_close("Unknown genesis block hash", msg.temporary_channel_id.clone()));
		}

		let channel = Channel::new_from_req(&*self.fee_estimator, &self.keys_manager, their_node_id.clone(), their_local_features, msg, 0, Arc::clone(&self.logger), &self.default_configuration)
			.map_err(|e| MsgHandleErrInternal::from_chan_no_close(e, msg.temporary_channel_id))?;
		let mut channel_state_lock = self.channel_state.lock().unwrap();
		let channel_state = channel_state_lock.borrow_parts();
		match channel_state.by_id.entry(channel.channel_id()) {
			hash_map::Entry::Occupied(_) => return Err(MsgHandleErrInternal::send_err_msg_no_close("temporary_channel_id collision!", msg.temporary_channel_id.clone())),
			hash_map::Entry::Vacant(entry) => {
				channel_state.pending_msg_events.push(events::MessageSendEvent::SendAcceptChannel {
					node_id: their_node_id.clone(),
					msg: channel.get_accept_channel(),
				});
				entry.insert(channel);
			}
		}
		Ok(())
	}

	fn internal_accept_channel(&self, their_node_id: &PublicKey, their_local_features: LocalFeatures, msg: &msgs::AcceptChannel) -> Result<(), MsgHandleErrInternal> {
		let (value, output_script, user_id) = {
			let mut channel_lock = self.channel_state.lock().unwrap();
			let channel_state = channel_lock.borrow_parts();
			match channel_state.by_id.entry(msg.temporary_channel_id) {
				hash_map::Entry::Occupied(mut chan) => {
					if chan.get().get_their_node_id() != *their_node_id {
						//TODO: see issue #153, need a consistent behavior on obnoxious behavior from random node
						return Err(MsgHandleErrInternal::send_err_msg_no_close("Got a message for a channel from the wrong node!", msg.temporary_channel_id));
					}
					try_chan_entry!(self, chan.get_mut().accept_channel(&msg, &self.default_configuration, their_local_features), channel_state, chan);
					(chan.get().get_value_satoshis(), chan.get().get_funding_redeemscript().to_v0_p2wsh(), chan.get().get_user_id())
				},
				//TODO: same as above
				hash_map::Entry::Vacant(_) => return Err(MsgHandleErrInternal::send_err_msg_no_close("Failed to find corresponding channel", msg.temporary_channel_id))
			}
		};
		let mut pending_events = self.pending_events.lock().unwrap();
		pending_events.push(events::Event::FundingGenerationReady {
			temporary_channel_id: msg.temporary_channel_id,
			channel_value_satoshis: value,
			output_script: output_script,
			user_channel_id: user_id,
		});
		Ok(())
	}

	fn internal_funding_created(&self, their_node_id: &PublicKey, msg: &msgs::FundingCreated) -> Result<(), MsgHandleErrInternal> {
		let ((funding_msg, monitor_update), mut chan) = {
			let mut channel_lock = self.channel_state.lock().unwrap();
			let channel_state = channel_lock.borrow_parts();
			match channel_state.by_id.entry(msg.temporary_channel_id.clone()) {
				hash_map::Entry::Occupied(mut chan) => {
					if chan.get().get_their_node_id() != *their_node_id {
						//TODO: here and below MsgHandleErrInternal, #153 case
						return Err(MsgHandleErrInternal::send_err_msg_no_close("Got a message for a channel from the wrong node!", msg.temporary_channel_id));
					}
					(try_chan_entry!(self, chan.get_mut().funding_created(msg), channel_state, chan), chan.remove())
				},
				hash_map::Entry::Vacant(_) => return Err(MsgHandleErrInternal::send_err_msg_no_close("Failed to find corresponding channel", msg.temporary_channel_id))
			}
		};
		// Because we have exclusive ownership of the channel here we can release the channel_state
		// lock before add_update_monitor
		if let Err(e) = self.monitor.add_update_monitor(monitor_update.get_funding_txo().unwrap(), monitor_update) {
			match e {
				ChannelMonitorUpdateErr::PermanentFailure => {
					// Note that we reply with the new channel_id in error messages if we gave up on the
					// channel, not the temporary_channel_id. This is compatible with ourselves, but the
					// spec is somewhat ambiguous here. Not a huge deal since we'll send error messages for
					// any messages referencing a previously-closed channel anyway.
					return Err(MsgHandleErrInternal::from_finish_shutdown("ChannelMonitor storage failure", funding_msg.channel_id, chan.force_shutdown(), None));
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
		let channel_state = channel_state_lock.borrow_parts();
		match channel_state.by_id.entry(funding_msg.channel_id) {
			hash_map::Entry::Occupied(_) => {
				return Err(MsgHandleErrInternal::send_err_msg_no_close("Already had channel with the new channel_id", funding_msg.channel_id))
			},
			hash_map::Entry::Vacant(e) => {
				channel_state.pending_msg_events.push(events::MessageSendEvent::SendFundingSigned {
					node_id: their_node_id.clone(),
					msg: funding_msg,
				});
				e.insert(chan);
			}
		}
		Ok(())
	}

	fn internal_funding_signed(&self, their_node_id: &PublicKey, msg: &msgs::FundingSigned) -> Result<(), MsgHandleErrInternal> {
		let (funding_txo, user_id) = {
			let mut channel_lock = self.channel_state.lock().unwrap();
			let channel_state = channel_lock.borrow_parts();
			match channel_state.by_id.entry(msg.channel_id) {
				hash_map::Entry::Occupied(mut chan) => {
					if chan.get().get_their_node_id() != *their_node_id {
						//TODO: here and below MsgHandleErrInternal, #153 case
						return Err(MsgHandleErrInternal::send_err_msg_no_close("Got a message for a channel from the wrong node!", msg.channel_id));
					}
					let chan_monitor = try_chan_entry!(self, chan.get_mut().funding_signed(&msg), channel_state, chan);
					if let Err(e) = self.monitor.add_update_monitor(chan_monitor.get_funding_txo().unwrap(), chan_monitor) {
						return_monitor_err!(self, e, channel_state, chan, RAACommitmentOrder::RevokeAndACKFirst, false, false);
					}
					(chan.get().get_funding_txo().unwrap(), chan.get().get_user_id())
				},
				hash_map::Entry::Vacant(_) => return Err(MsgHandleErrInternal::send_err_msg_no_close("Failed to find corresponding channel", msg.channel_id))
			}
		};
		let mut pending_events = self.pending_events.lock().unwrap();
		pending_events.push(events::Event::FundingBroadcastSafe {
			funding_txo: funding_txo,
			user_channel_id: user_id,
		});
		Ok(())
	}

	fn internal_funding_locked(&self, their_node_id: &PublicKey, msg: &msgs::FundingLocked) -> Result<(), MsgHandleErrInternal> {
		let mut channel_state_lock = self.channel_state.lock().unwrap();
		let channel_state = channel_state_lock.borrow_parts();
		match channel_state.by_id.entry(msg.channel_id) {
			hash_map::Entry::Occupied(mut chan) => {
				if chan.get().get_their_node_id() != *their_node_id {
					//TODO: here and below MsgHandleErrInternal, #153 case
					return Err(MsgHandleErrInternal::send_err_msg_no_close("Got a message for a channel from the wrong node!", msg.channel_id));
				}
				try_chan_entry!(self, chan.get_mut().funding_locked(&msg), channel_state, chan);
				if let Some(announcement_sigs) = self.get_announcement_sigs(chan.get()) {
					channel_state.pending_msg_events.push(events::MessageSendEvent::SendAnnouncementSignatures {
						node_id: their_node_id.clone(),
						msg: announcement_sigs,
					});
				}
				Ok(())
			},
			hash_map::Entry::Vacant(_) => Err(MsgHandleErrInternal::send_err_msg_no_close("Failed to find corresponding channel", msg.channel_id))
		}
	}

	fn internal_shutdown(&self, their_node_id: &PublicKey, msg: &msgs::Shutdown) -> Result<(), MsgHandleErrInternal> {
		let (mut dropped_htlcs, chan_option) = {
			let mut channel_state_lock = self.channel_state.lock().unwrap();
			let channel_state = channel_state_lock.borrow_parts();

			match channel_state.by_id.entry(msg.channel_id.clone()) {
				hash_map::Entry::Occupied(mut chan_entry) => {
					if chan_entry.get().get_their_node_id() != *their_node_id {
						//TODO: here and below MsgHandleErrInternal, #153 case
						return Err(MsgHandleErrInternal::send_err_msg_no_close("Got a message for a channel from the wrong node!", msg.channel_id));
					}
					let (shutdown, closing_signed, dropped_htlcs) = try_chan_entry!(self, chan_entry.get_mut().shutdown(&*self.fee_estimator, &msg), channel_state, chan_entry);
					if let Some(msg) = shutdown {
						channel_state.pending_msg_events.push(events::MessageSendEvent::SendShutdown {
							node_id: their_node_id.clone(),
							msg,
						});
					}
					if let Some(msg) = closing_signed {
						channel_state.pending_msg_events.push(events::MessageSendEvent::SendClosingSigned {
							node_id: their_node_id.clone(),
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
				hash_map::Entry::Vacant(_) => return Err(MsgHandleErrInternal::send_err_msg_no_close("Failed to find corresponding channel", msg.channel_id))
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

	fn internal_closing_signed(&self, their_node_id: &PublicKey, msg: &msgs::ClosingSigned) -> Result<(), MsgHandleErrInternal> {
		let (tx, chan_option) = {
			let mut channel_state_lock = self.channel_state.lock().unwrap();
			let channel_state = channel_state_lock.borrow_parts();
			match channel_state.by_id.entry(msg.channel_id.clone()) {
				hash_map::Entry::Occupied(mut chan_entry) => {
					if chan_entry.get().get_their_node_id() != *their_node_id {
						//TODO: here and below MsgHandleErrInternal, #153 case
						return Err(MsgHandleErrInternal::send_err_msg_no_close("Got a message for a channel from the wrong node!", msg.channel_id));
					}
					let (closing_signed, tx) = try_chan_entry!(self, chan_entry.get_mut().closing_signed(&*self.fee_estimator, &msg), channel_state, chan_entry);
					if let Some(msg) = closing_signed {
						channel_state.pending_msg_events.push(events::MessageSendEvent::SendClosingSigned {
							node_id: their_node_id.clone(),
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
				hash_map::Entry::Vacant(_) => return Err(MsgHandleErrInternal::send_err_msg_no_close("Failed to find corresponding channel", msg.channel_id))
			}
		};
		if let Some(broadcast_tx) = tx {
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

	fn internal_update_add_htlc(&self, their_node_id: &PublicKey, msg: &msgs::UpdateAddHTLC) -> Result<(), MsgHandleErrInternal> {
		//TODO: BOLT 4 points out a specific attack where a peer may re-send an onion packet and
		//determine the state of the payment based on our response/if we forward anything/the time
		//we take to respond. We should take care to avoid allowing such an attack.
		//
		//TODO: There exists a further attack where a node may garble the onion data, forward it to
		//us repeatedly garbled in different ways, and compare our error messages, which are
		//encrypted with the same key. It's not immediately obvious how to usefully exploit that,
		//but we should prevent it anyway.

		let (mut pending_forward_info, mut channel_state_lock) = self.decode_update_add_htlc_onion(msg);
		let channel_state = channel_state_lock.borrow_parts();

		match channel_state.by_id.entry(msg.channel_id) {
			hash_map::Entry::Occupied(mut chan) => {
				if chan.get().get_their_node_id() != *their_node_id {
					//TODO: here MsgHandleErrInternal, #153 case
					return Err(MsgHandleErrInternal::send_err_msg_no_close("Got a message for a channel from the wrong node!", msg.channel_id));
				}
				if !chan.get().is_usable() {
					// If the update_add is completely bogus, the call will Err and we will close,
					// but if we've sent a shutdown and they haven't acknowledged it yet, we just
					// want to reject the new HTLC and fail it backwards instead of forwarding.
					if let PendingHTLCStatus::Forward(PendingForwardHTLCInfo { incoming_shared_secret, .. }) = pending_forward_info {
						let chan_update = self.get_channel_update(chan.get());
						pending_forward_info = PendingHTLCStatus::Fail(HTLCFailureMsg::Relay(msgs::UpdateFailHTLC {
							channel_id: msg.channel_id,
							htlc_id: msg.htlc_id,
							reason: if let Ok(update) = chan_update {
								// TODO: Note that |20 is defined as "channel FROM the processing
								// node has been disabled" (emphasis mine), which seems to imply
								// that we can't return |20 for an inbound channel being disabled.
								// This probably needs a spec update but should definitely be
								// allowed.
								onion_utils::build_first_hop_failure_packet(&incoming_shared_secret, 0x1000|20, &{
									let mut res = Vec::with_capacity(8 + 128);
									res.extend_from_slice(&byte_utils::be16_to_array(update.contents.flags));
									res.extend_from_slice(&update.encode_with_len()[..]);
									res
								}[..])
							} else {
								// This can only happen if the channel isn't in the fully-funded
								// state yet, implying our counterparty is trying to route payments
								// over the channel back to themselves (cause no one else should
								// know the short_id is a lightning channel yet). We should have no
								// problem just calling this unknown_next_peer
								onion_utils::build_first_hop_failure_packet(&incoming_shared_secret, 0x4000|10, &[])
							},
						}));
					}
				}
				try_chan_entry!(self, chan.get_mut().update_add_htlc(&msg, pending_forward_info), channel_state, chan);
			},
			hash_map::Entry::Vacant(_) => return Err(MsgHandleErrInternal::send_err_msg_no_close("Failed to find corresponding channel", msg.channel_id))
		}
		Ok(())
	}

	fn internal_update_fulfill_htlc(&self, their_node_id: &PublicKey, msg: &msgs::UpdateFulfillHTLC) -> Result<(), MsgHandleErrInternal> {
		let mut channel_lock = self.channel_state.lock().unwrap();
		let htlc_source = {
			let channel_state = channel_lock.borrow_parts();
			match channel_state.by_id.entry(msg.channel_id) {
				hash_map::Entry::Occupied(mut chan) => {
					if chan.get().get_their_node_id() != *their_node_id {
						//TODO: here and below MsgHandleErrInternal, #153 case
						return Err(MsgHandleErrInternal::send_err_msg_no_close("Got a message for a channel from the wrong node!", msg.channel_id));
					}
					try_chan_entry!(self, chan.get_mut().update_fulfill_htlc(&msg), channel_state, chan)
				},
				hash_map::Entry::Vacant(_) => return Err(MsgHandleErrInternal::send_err_msg_no_close("Failed to find corresponding channel", msg.channel_id))
			}
		};
		self.claim_funds_internal(channel_lock, htlc_source, msg.payment_preimage.clone());
		Ok(())
	}

	fn internal_update_fail_htlc(&self, their_node_id: &PublicKey, msg: &msgs::UpdateFailHTLC) -> Result<(), MsgHandleErrInternal> {
		let mut channel_lock = self.channel_state.lock().unwrap();
		let channel_state = channel_lock.borrow_parts();
		match channel_state.by_id.entry(msg.channel_id) {
			hash_map::Entry::Occupied(mut chan) => {
				if chan.get().get_their_node_id() != *their_node_id {
					//TODO: here and below MsgHandleErrInternal, #153 case
					return Err(MsgHandleErrInternal::send_err_msg_no_close("Got a message for a channel from the wrong node!", msg.channel_id));
				}
				try_chan_entry!(self, chan.get_mut().update_fail_htlc(&msg, HTLCFailReason::LightningError { err: msg.reason.clone() }), channel_state, chan);
			},
			hash_map::Entry::Vacant(_) => return Err(MsgHandleErrInternal::send_err_msg_no_close("Failed to find corresponding channel", msg.channel_id))
		}
		Ok(())
	}

	fn internal_update_fail_malformed_htlc(&self, their_node_id: &PublicKey, msg: &msgs::UpdateFailMalformedHTLC) -> Result<(), MsgHandleErrInternal> {
		let mut channel_lock = self.channel_state.lock().unwrap();
		let channel_state = channel_lock.borrow_parts();
		match channel_state.by_id.entry(msg.channel_id) {
			hash_map::Entry::Occupied(mut chan) => {
				if chan.get().get_their_node_id() != *their_node_id {
					//TODO: here and below MsgHandleErrInternal, #153 case
					return Err(MsgHandleErrInternal::send_err_msg_no_close("Got a message for a channel from the wrong node!", msg.channel_id));
				}
				if (msg.failure_code & 0x8000) == 0 {
					try_chan_entry!(self, Err(ChannelError::Close("Got update_fail_malformed_htlc with BADONION not set")), channel_state, chan);
				}
				try_chan_entry!(self, chan.get_mut().update_fail_malformed_htlc(&msg, HTLCFailReason::Reason { failure_code: msg.failure_code, data: Vec::new() }), channel_state, chan);
				Ok(())
			},
			hash_map::Entry::Vacant(_) => return Err(MsgHandleErrInternal::send_err_msg_no_close("Failed to find corresponding channel", msg.channel_id))
		}
	}

	fn internal_commitment_signed(&self, their_node_id: &PublicKey, msg: &msgs::CommitmentSigned) -> Result<(), MsgHandleErrInternal> {
		let mut channel_state_lock = self.channel_state.lock().unwrap();
		let channel_state = channel_state_lock.borrow_parts();
		match channel_state.by_id.entry(msg.channel_id) {
			hash_map::Entry::Occupied(mut chan) => {
				if chan.get().get_their_node_id() != *their_node_id {
					//TODO: here and below MsgHandleErrInternal, #153 case
					return Err(MsgHandleErrInternal::send_err_msg_no_close("Got a message for a channel from the wrong node!", msg.channel_id));
				}
				let (revoke_and_ack, commitment_signed, closing_signed, chan_monitor) =
					try_chan_entry!(self, chan.get_mut().commitment_signed(&msg, &*self.fee_estimator), channel_state, chan);
				if let Err(e) = self.monitor.add_update_monitor(chan_monitor.get_funding_txo().unwrap(), chan_monitor) {
					return_monitor_err!(self, e, channel_state, chan, RAACommitmentOrder::RevokeAndACKFirst, true, commitment_signed.is_some());
					//TODO: Rebroadcast closing_signed if present on monitor update restoration
				}
				channel_state.pending_msg_events.push(events::MessageSendEvent::SendRevokeAndACK {
					node_id: their_node_id.clone(),
					msg: revoke_and_ack,
				});
				if let Some(msg) = commitment_signed {
					channel_state.pending_msg_events.push(events::MessageSendEvent::UpdateHTLCs {
						node_id: their_node_id.clone(),
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
						node_id: their_node_id.clone(),
						msg,
					});
				}
				Ok(())
			},
			hash_map::Entry::Vacant(_) => return Err(MsgHandleErrInternal::send_err_msg_no_close("Failed to find corresponding channel", msg.channel_id))
		}
	}

	#[inline]
	fn forward_htlcs(&self, per_source_pending_forwards: &mut [(u64, Vec<(PendingForwardHTLCInfo, u64)>)]) {
		for &mut (prev_short_channel_id, ref mut pending_forwards) in per_source_pending_forwards {
			let mut forward_event = None;
			if !pending_forwards.is_empty() {
				let mut channel_state = self.channel_state.lock().unwrap();
				if channel_state.forward_htlcs.is_empty() {
					forward_event = Some(Duration::from_millis(MIN_HTLC_RELAY_HOLDING_CELL_MILLIS))
				}
				for (forward_info, prev_htlc_id) in pending_forwards.drain(..) {
					match channel_state.forward_htlcs.entry(forward_info.short_channel_id) {
						hash_map::Entry::Occupied(mut entry) => {
							entry.get_mut().push(HTLCForwardInfo::AddHTLC { prev_short_channel_id, prev_htlc_id, forward_info });
						},
						hash_map::Entry::Vacant(entry) => {
							entry.insert(vec!(HTLCForwardInfo::AddHTLC { prev_short_channel_id, prev_htlc_id, forward_info }));
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

	fn internal_revoke_and_ack(&self, their_node_id: &PublicKey, msg: &msgs::RevokeAndACK) -> Result<(), MsgHandleErrInternal> {
		let (pending_forwards, mut pending_failures, short_channel_id) = {
			let mut channel_state_lock = self.channel_state.lock().unwrap();
			let channel_state = channel_state_lock.borrow_parts();
			match channel_state.by_id.entry(msg.channel_id) {
				hash_map::Entry::Occupied(mut chan) => {
					if chan.get().get_their_node_id() != *their_node_id {
						//TODO: here and below MsgHandleErrInternal, #153 case
						return Err(MsgHandleErrInternal::send_err_msg_no_close("Got a message for a channel from the wrong node!", msg.channel_id));
					}
					let was_frozen_for_monitor = chan.get().is_awaiting_monitor_update();
					let (commitment_update, pending_forwards, pending_failures, closing_signed, chan_monitor) =
						try_chan_entry!(self, chan.get_mut().revoke_and_ack(&msg, &*self.fee_estimator), channel_state, chan);
					if let Err(e) = self.monitor.add_update_monitor(chan_monitor.get_funding_txo().unwrap(), chan_monitor) {
						if was_frozen_for_monitor {
							assert!(commitment_update.is_none() && closing_signed.is_none() && pending_forwards.is_empty() && pending_failures.is_empty());
							return Err(MsgHandleErrInternal::ignore_no_close("Previous monitor update failure prevented responses to RAA"));
						} else {
							return_monitor_err!(self, e, channel_state, chan, RAACommitmentOrder::CommitmentFirst, false, commitment_update.is_some(), pending_forwards, pending_failures);
						}
					}
					if let Some(updates) = commitment_update {
						channel_state.pending_msg_events.push(events::MessageSendEvent::UpdateHTLCs {
							node_id: their_node_id.clone(),
							updates,
						});
					}
					if let Some(msg) = closing_signed {
						channel_state.pending_msg_events.push(events::MessageSendEvent::SendClosingSigned {
							node_id: their_node_id.clone(),
							msg,
						});
					}
					(pending_forwards, pending_failures, chan.get().get_short_channel_id().expect("RAA should only work on a short-id-available channel"))
				},
				hash_map::Entry::Vacant(_) => return Err(MsgHandleErrInternal::send_err_msg_no_close("Failed to find corresponding channel", msg.channel_id))
			}
		};
		for failure in pending_failures.drain(..) {
			self.fail_htlc_backwards_internal(self.channel_state.lock().unwrap(), failure.0, &failure.1, failure.2);
		}
		self.forward_htlcs(&mut [(short_channel_id, pending_forwards)]);

		Ok(())
	}

	fn internal_update_fee(&self, their_node_id: &PublicKey, msg: &msgs::UpdateFee) -> Result<(), MsgHandleErrInternal> {
		let mut channel_lock = self.channel_state.lock().unwrap();
		let channel_state = channel_lock.borrow_parts();
		match channel_state.by_id.entry(msg.channel_id) {
			hash_map::Entry::Occupied(mut chan) => {
				if chan.get().get_their_node_id() != *their_node_id {
					//TODO: here and below MsgHandleErrInternal, #153 case
					return Err(MsgHandleErrInternal::send_err_msg_no_close("Got a message for a channel from the wrong node!", msg.channel_id));
				}
				try_chan_entry!(self, chan.get_mut().update_fee(&*self.fee_estimator, &msg), channel_state, chan);
			},
			hash_map::Entry::Vacant(_) => return Err(MsgHandleErrInternal::send_err_msg_no_close("Failed to find corresponding channel", msg.channel_id))
		}
		Ok(())
	}

	fn internal_announcement_signatures(&self, their_node_id: &PublicKey, msg: &msgs::AnnouncementSignatures) -> Result<(), MsgHandleErrInternal> {
		let mut channel_state_lock = self.channel_state.lock().unwrap();
		let channel_state = channel_state_lock.borrow_parts();

		match channel_state.by_id.entry(msg.channel_id) {
			hash_map::Entry::Occupied(mut chan) => {
				if chan.get().get_their_node_id() != *their_node_id {
					return Err(MsgHandleErrInternal::send_err_msg_no_close("Got a message for a channel from the wrong node!", msg.channel_id));
				}
				if !chan.get().is_usable() {
					return Err(MsgHandleErrInternal::from_no_close(LightningError{err: "Got an announcement_signatures before we were ready for it", action: msgs::ErrorAction::IgnoreError}));
				}

				let our_node_id = self.get_our_node_id();
				let (announcement, our_bitcoin_sig) =
					try_chan_entry!(self, chan.get_mut().get_channel_announcement(our_node_id.clone(), self.genesis_hash.clone()), channel_state, chan);

				let were_node_one = announcement.node_id_1 == our_node_id;
				let msghash = hash_to_message!(&Sha256dHash::hash(&announcement.encode()[..])[..]);
				if self.secp_ctx.verify(&msghash, &msg.node_signature, if were_node_one { &announcement.node_id_2 } else { &announcement.node_id_1 }).is_err() ||
						self.secp_ctx.verify(&msghash, &msg.bitcoin_signature, if were_node_one { &announcement.bitcoin_key_2 } else { &announcement.bitcoin_key_1 }).is_err() {
					try_chan_entry!(self, Err(ChannelError::Close("Bad announcement_signatures node_signature")), channel_state, chan);
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
			hash_map::Entry::Vacant(_) => return Err(MsgHandleErrInternal::send_err_msg_no_close("Failed to find corresponding channel", msg.channel_id))
		}
		Ok(())
	}

	fn internal_channel_reestablish(&self, their_node_id: &PublicKey, msg: &msgs::ChannelReestablish) -> Result<(), MsgHandleErrInternal> {
		let mut channel_state_lock = self.channel_state.lock().unwrap();
		let channel_state = channel_state_lock.borrow_parts();

		match channel_state.by_id.entry(msg.channel_id) {
			hash_map::Entry::Occupied(mut chan) => {
				if chan.get().get_their_node_id() != *their_node_id {
					return Err(MsgHandleErrInternal::send_err_msg_no_close("Got a message for a channel from the wrong node!", msg.channel_id));
				}
				let (funding_locked, revoke_and_ack, commitment_update, channel_monitor, mut order, shutdown) =
					try_chan_entry!(self, chan.get_mut().channel_reestablish(msg), channel_state, chan);
				if let Some(monitor) = channel_monitor {
					if let Err(e) = self.monitor.add_update_monitor(monitor.get_funding_txo().unwrap(), monitor) {
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
						node_id: their_node_id.clone(),
						msg
					});
				}
				macro_rules! send_raa { () => {
					if let Some(msg) = revoke_and_ack {
						channel_state.pending_msg_events.push(events::MessageSendEvent::SendRevokeAndACK {
							node_id: their_node_id.clone(),
							msg
						});
					}
				} }
				macro_rules! send_cu { () => {
					if let Some(updates) = commitment_update {
						channel_state.pending_msg_events.push(events::MessageSendEvent::UpdateHTLCs {
							node_id: their_node_id.clone(),
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
						node_id: their_node_id.clone(),
						msg,
					});
				}
				Ok(())
			},
			hash_map::Entry::Vacant(_) => return Err(MsgHandleErrInternal::send_err_msg_no_close("Failed to find corresponding channel", msg.channel_id))
		}
	}

	/// Begin Update fee process. Allowed only on an outbound channel.
	/// If successful, will generate a UpdateHTLCs event, so you should probably poll
	/// PeerManager::process_events afterwards.
	/// Note: This API is likely to change!
	#[doc(hidden)]
	pub fn update_fee(&self, channel_id: [u8;32], feerate_per_kw: u64) -> Result<(), APIError> {
		let _ = self.total_consistency_lock.read().unwrap();
		let their_node_id;
		let err: Result<(), _> = loop {
			let mut channel_state_lock = self.channel_state.lock().unwrap();
			let channel_state = channel_state_lock.borrow_parts();

			match channel_state.by_id.entry(channel_id) {
				hash_map::Entry::Vacant(_) => return Err(APIError::APIMisuseError{err: "Failed to find corresponding channel"}),
				hash_map::Entry::Occupied(mut chan) => {
					if !chan.get().is_outbound() {
						return Err(APIError::APIMisuseError{err: "update_fee cannot be sent for an inbound channel"});
					}
					if chan.get().is_awaiting_monitor_update() {
						return Err(APIError::MonitorUpdateFailed);
					}
					if !chan.get().is_live() {
						return Err(APIError::ChannelUnavailable{err: "Channel is either not yet fully established or peer is currently disconnected"});
					}
					their_node_id = chan.get().get_their_node_id();
					if let Some((update_fee, commitment_signed, chan_monitor)) =
							break_chan_entry!(self, chan.get_mut().send_update_fee_and_commit(feerate_per_kw), channel_state, chan)
					{
						if let Err(_e) = self.monitor.add_update_monitor(chan_monitor.get_funding_txo().unwrap(), chan_monitor) {
							unimplemented!();
						}
						channel_state.pending_msg_events.push(events::MessageSendEvent::UpdateHTLCs {
							node_id: chan.get().get_their_node_id(),
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

		match handle_error!(self, err) {
			Ok(_) => unreachable!(),
			Err(e) => {
				if let msgs::ErrorAction::IgnoreError = e.action {
				} else {
					log_error!(self, "Got bad keys: {}!", e.err);
					let mut channel_state = self.channel_state.lock().unwrap();
					channel_state.pending_msg_events.push(events::MessageSendEvent::HandleError {
						node_id: their_node_id,
						action: e.action,
					});
				}
				Err(APIError::APIMisuseError { err: e.err })
			},
		}
	}
}

impl events::MessageSendEventsProvider for ChannelManager {
	fn get_and_clear_pending_msg_events(&self) -> Vec<events::MessageSendEvent> {
		// TODO: Event release to users and serialization is currently race-y: it's very easy for a
		// user to serialize a ChannelManager with pending events in it and lose those events on
		// restart. This is doubly true for the fail/fulfill-backs from monitor events!
		{
			//TODO: This behavior should be documented.
			for htlc_update in self.monitor.fetch_pending_htlc_updated() {
				if let Some(preimage) = htlc_update.payment_preimage {
					log_trace!(self, "Claiming HTLC with preimage {} from our monitor", log_bytes!(preimage.0));
					self.claim_funds_internal(self.channel_state.lock().unwrap(), htlc_update.source, preimage);
				} else {
					log_trace!(self, "Failing HTLC with hash {} from our monitor", log_bytes!(htlc_update.payment_hash.0));
					self.fail_htlc_backwards_internal(self.channel_state.lock().unwrap(), htlc_update.source, &htlc_update.payment_hash, HTLCFailReason::Reason { failure_code: 0x4000 | 8, data: Vec::new() });
				}
			}
		}

		let mut ret = Vec::new();
		let mut channel_state = self.channel_state.lock().unwrap();
		mem::swap(&mut ret, &mut channel_state.pending_msg_events);
		ret
	}
}

impl events::EventsProvider for ChannelManager {
	fn get_and_clear_pending_events(&self) -> Vec<events::Event> {
		// TODO: Event release to users and serialization is currently race-y: it's very easy for a
		// user to serialize a ChannelManager with pending events in it and lose those events on
		// restart. This is doubly true for the fail/fulfill-backs from monitor events!
		{
			//TODO: This behavior should be documented.
			for htlc_update in self.monitor.fetch_pending_htlc_updated() {
				if let Some(preimage) = htlc_update.payment_preimage {
					log_trace!(self, "Claiming HTLC with preimage {} from our monitor", log_bytes!(preimage.0));
					self.claim_funds_internal(self.channel_state.lock().unwrap(), htlc_update.source, preimage);
				} else {
					log_trace!(self, "Failing HTLC with hash {} from our monitor", log_bytes!(htlc_update.payment_hash.0));
					self.fail_htlc_backwards_internal(self.channel_state.lock().unwrap(), htlc_update.source, &htlc_update.payment_hash, HTLCFailReason::Reason { failure_code: 0x4000 | 8, data: Vec::new() });
				}
			}
		}

		let mut ret = Vec::new();
		let mut pending_events = self.pending_events.lock().unwrap();
		mem::swap(&mut ret, &mut *pending_events);
		ret
	}
}

impl ChainListener for ChannelManager {
	fn block_connected(&self, header: &BlockHeader, height: u32, txn_matched: &[&Transaction], indexes_of_txn_matched: &[u32]) {
		let header_hash = header.bitcoin_hash();
		log_trace!(self, "Block {} at height {} connected with {} txn matched", header_hash, height, txn_matched.len());
		let _ = self.total_consistency_lock.read().unwrap();
		let mut failed_channels = Vec::new();
		{
			let mut channel_lock = self.channel_state.lock().unwrap();
			let channel_state = channel_lock.borrow_parts();
			let short_to_id = channel_state.short_to_id;
			let pending_msg_events = channel_state.pending_msg_events;
			channel_state.by_id.retain(|_, channel| {
				let chan_res = channel.block_connected(header, height, txn_matched, indexes_of_txn_matched);
				if let Ok(Some(funding_locked)) = chan_res {
					pending_msg_events.push(events::MessageSendEvent::SendFundingLocked {
						node_id: channel.get_their_node_id(),
						msg: funding_locked,
					});
					if let Some(announcement_sigs) = self.get_announcement_sigs(channel) {
						pending_msg_events.push(events::MessageSendEvent::SendAnnouncementSignatures {
							node_id: channel.get_their_node_id(),
							msg: announcement_sigs,
						});
					}
					short_to_id.insert(channel.get_short_channel_id().unwrap(), channel.channel_id());
				} else if let Err(e) = chan_res {
					pending_msg_events.push(events::MessageSendEvent::HandleError {
						node_id: channel.get_their_node_id(),
						action: msgs::ErrorAction::SendErrorMessage { msg: e },
					});
					return false;
				}
				if let Some(funding_txo) = channel.get_funding_txo() {
					for tx in txn_matched {
						for inp in tx.input.iter() {
							if inp.previous_output == funding_txo.into_bitcoin_outpoint() {
								log_trace!(self, "Detected channel-closing tx {} spending {}:{}, closing channel {}", tx.txid(), inp.previous_output.txid, inp.previous_output.vout, log_bytes!(channel.channel_id()));
								if let Some(short_id) = channel.get_short_channel_id() {
									short_to_id.remove(&short_id);
								}
								// It looks like our counterparty went on-chain. We go ahead and
								// broadcast our latest local state as well here, just in case its
								// some kind of SPV attack, though we expect these to be dropped.
								failed_channels.push(channel.force_shutdown());
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
				if channel.is_funding_initiated() && channel.channel_monitor().would_broadcast_at_height(height) {
					if let Some(short_id) = channel.get_short_channel_id() {
						short_to_id.remove(&short_id);
					}
					failed_channels.push(channel.force_shutdown());
					// If would_broadcast_at_height() is true, the channel_monitor will broadcast
					// the latest local tx for us, so we should skip that here (it doesn't really
					// hurt anything, but does make tests a bit simpler).
					failed_channels.last_mut().unwrap().0 = Vec::new();
					if let Ok(update) = self.get_channel_update(&channel) {
						pending_msg_events.push(events::MessageSendEvent::BroadcastChannelUpdate {
							msg: update
						});
					}
					return false;
				}
				true
			});
		}
		for failure in failed_channels.drain(..) {
			self.finish_force_close_channel(failure);
		}
		self.latest_block_height.store(height as usize, Ordering::Release);
		*self.last_block_hash.try_lock().expect("block_(dis)connected must not be called in parallel") = header_hash;
	}

	/// We force-close the channel without letting our counterparty participate in the shutdown
	fn block_disconnected(&self, header: &BlockHeader, _: u32) {
		let _ = self.total_consistency_lock.read().unwrap();
		let mut failed_channels = Vec::new();
		{
			let mut channel_lock = self.channel_state.lock().unwrap();
			let channel_state = channel_lock.borrow_parts();
			let short_to_id = channel_state.short_to_id;
			let pending_msg_events = channel_state.pending_msg_events;
			channel_state.by_id.retain(|_,  v| {
				if v.block_disconnected(header) {
					if let Some(short_id) = v.get_short_channel_id() {
						short_to_id.remove(&short_id);
					}
					failed_channels.push(v.force_shutdown());
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
		*self.last_block_hash.try_lock().expect("block_(dis)connected must not be called in parallel") = header.bitcoin_hash();
	}
}

impl ChannelMessageHandler for ChannelManager {
	//TODO: Handle errors and close channel (or so)
	fn handle_open_channel(&self, their_node_id: &PublicKey, their_local_features: LocalFeatures, msg: &msgs::OpenChannel) -> Result<(), LightningError> {
		let _ = self.total_consistency_lock.read().unwrap();
		handle_error!(self, self.internal_open_channel(their_node_id, their_local_features, msg))
	}

	fn handle_accept_channel(&self, their_node_id: &PublicKey, their_local_features: LocalFeatures, msg: &msgs::AcceptChannel) -> Result<(), LightningError> {
		let _ = self.total_consistency_lock.read().unwrap();
		handle_error!(self, self.internal_accept_channel(their_node_id, their_local_features, msg))
	}

	fn handle_funding_created(&self, their_node_id: &PublicKey, msg: &msgs::FundingCreated) -> Result<(), LightningError> {
		let _ = self.total_consistency_lock.read().unwrap();
		handle_error!(self, self.internal_funding_created(their_node_id, msg))
	}

	fn handle_funding_signed(&self, their_node_id: &PublicKey, msg: &msgs::FundingSigned) -> Result<(), LightningError> {
		let _ = self.total_consistency_lock.read().unwrap();
		handle_error!(self, self.internal_funding_signed(their_node_id, msg))
	}

	fn handle_funding_locked(&self, their_node_id: &PublicKey, msg: &msgs::FundingLocked) -> Result<(), LightningError> {
		let _ = self.total_consistency_lock.read().unwrap();
		handle_error!(self, self.internal_funding_locked(their_node_id, msg))
	}

	fn handle_shutdown(&self, their_node_id: &PublicKey, msg: &msgs::Shutdown) -> Result<(), LightningError> {
		let _ = self.total_consistency_lock.read().unwrap();
		handle_error!(self, self.internal_shutdown(their_node_id, msg))
	}

	fn handle_closing_signed(&self, their_node_id: &PublicKey, msg: &msgs::ClosingSigned) -> Result<(), LightningError> {
		let _ = self.total_consistency_lock.read().unwrap();
		handle_error!(self, self.internal_closing_signed(their_node_id, msg))
	}

	fn handle_update_add_htlc(&self, their_node_id: &PublicKey, msg: &msgs::UpdateAddHTLC) -> Result<(), LightningError> {
		let _ = self.total_consistency_lock.read().unwrap();
		handle_error!(self, self.internal_update_add_htlc(their_node_id, msg))
	}

	fn handle_update_fulfill_htlc(&self, their_node_id: &PublicKey, msg: &msgs::UpdateFulfillHTLC) -> Result<(), LightningError> {
		let _ = self.total_consistency_lock.read().unwrap();
		handle_error!(self, self.internal_update_fulfill_htlc(their_node_id, msg))
	}

	fn handle_update_fail_htlc(&self, their_node_id: &PublicKey, msg: &msgs::UpdateFailHTLC) -> Result<(), LightningError> {
		let _ = self.total_consistency_lock.read().unwrap();
		handle_error!(self, self.internal_update_fail_htlc(their_node_id, msg))
	}

	fn handle_update_fail_malformed_htlc(&self, their_node_id: &PublicKey, msg: &msgs::UpdateFailMalformedHTLC) -> Result<(), LightningError> {
		let _ = self.total_consistency_lock.read().unwrap();
		handle_error!(self, self.internal_update_fail_malformed_htlc(their_node_id, msg))
	}

	fn handle_commitment_signed(&self, their_node_id: &PublicKey, msg: &msgs::CommitmentSigned) -> Result<(), LightningError> {
		let _ = self.total_consistency_lock.read().unwrap();
		handle_error!(self, self.internal_commitment_signed(their_node_id, msg))
	}

	fn handle_revoke_and_ack(&self, their_node_id: &PublicKey, msg: &msgs::RevokeAndACK) -> Result<(), LightningError> {
		let _ = self.total_consistency_lock.read().unwrap();
		handle_error!(self, self.internal_revoke_and_ack(their_node_id, msg))
	}

	fn handle_update_fee(&self, their_node_id: &PublicKey, msg: &msgs::UpdateFee) -> Result<(), LightningError> {
		let _ = self.total_consistency_lock.read().unwrap();
		handle_error!(self, self.internal_update_fee(their_node_id, msg))
	}

	fn handle_announcement_signatures(&self, their_node_id: &PublicKey, msg: &msgs::AnnouncementSignatures) -> Result<(), LightningError> {
		let _ = self.total_consistency_lock.read().unwrap();
		handle_error!(self, self.internal_announcement_signatures(their_node_id, msg))
	}

	fn handle_channel_reestablish(&self, their_node_id: &PublicKey, msg: &msgs::ChannelReestablish) -> Result<(), LightningError> {
		let _ = self.total_consistency_lock.read().unwrap();
		handle_error!(self, self.internal_channel_reestablish(their_node_id, msg))
	}

	fn peer_disconnected(&self, their_node_id: &PublicKey, no_connection_possible: bool) {
		let _ = self.total_consistency_lock.read().unwrap();
		let mut failed_channels = Vec::new();
		let mut failed_payments = Vec::new();
		{
			let mut channel_state_lock = self.channel_state.lock().unwrap();
			let channel_state = channel_state_lock.borrow_parts();
			let short_to_id = channel_state.short_to_id;
			let pending_msg_events = channel_state.pending_msg_events;
			if no_connection_possible {
				log_debug!(self, "Failing all channels with {} due to no_connection_possible", log_pubkey!(their_node_id));
				channel_state.by_id.retain(|_, chan| {
					if chan.get_their_node_id() == *their_node_id {
						if let Some(short_id) = chan.get_short_channel_id() {
							short_to_id.remove(&short_id);
						}
						failed_channels.push(chan.force_shutdown());
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
				log_debug!(self, "Marking channels with {} disconnected and generating channel_updates", log_pubkey!(their_node_id));
				channel_state.by_id.retain(|_, chan| {
					if chan.get_their_node_id() == *their_node_id {
						//TODO: mark channel disabled (and maybe announce such after a timeout).
						let failed_adds = chan.remove_uncommitted_htlcs_and_mark_paused();
						if !failed_adds.is_empty() {
							let chan_update = self.get_channel_update(&chan).map(|u| u.encode_with_len()).unwrap(); // Cannot add/recv HTLCs before we have a short_id so unwrap is safe
							failed_payments.push((chan_update, failed_adds));
						}
						if chan.is_shutdown() {
							if let Some(short_id) = chan.get_short_channel_id() {
								short_to_id.remove(&short_id);
							}
							return false;
						}
					}
					true
				})
			}
			pending_msg_events.retain(|msg| {
				match msg {
					&events::MessageSendEvent::SendAcceptChannel { ref node_id, .. } => node_id != their_node_id,
					&events::MessageSendEvent::SendOpenChannel { ref node_id, .. } => node_id != their_node_id,
					&events::MessageSendEvent::SendFundingCreated { ref node_id, .. } => node_id != their_node_id,
					&events::MessageSendEvent::SendFundingSigned { ref node_id, .. } => node_id != their_node_id,
					&events::MessageSendEvent::SendFundingLocked { ref node_id, .. } => node_id != their_node_id,
					&events::MessageSendEvent::SendAnnouncementSignatures { ref node_id, .. } => node_id != their_node_id,
					&events::MessageSendEvent::UpdateHTLCs { ref node_id, .. } => node_id != their_node_id,
					&events::MessageSendEvent::SendRevokeAndACK { ref node_id, .. } => node_id != their_node_id,
					&events::MessageSendEvent::SendClosingSigned { ref node_id, .. } => node_id != their_node_id,
					&events::MessageSendEvent::SendShutdown { ref node_id, .. } => node_id != their_node_id,
					&events::MessageSendEvent::SendChannelReestablish { ref node_id, .. } => node_id != their_node_id,
					&events::MessageSendEvent::BroadcastChannelAnnouncement { .. } => true,
					&events::MessageSendEvent::BroadcastChannelUpdate { .. } => true,
					&events::MessageSendEvent::HandleError { ref node_id, .. } => node_id != their_node_id,
					&events::MessageSendEvent::PaymentFailureNetworkUpdate { .. } => true,
				}
			});
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

	fn peer_connected(&self, their_node_id: &PublicKey) {
		log_debug!(self, "Generating channel_reestablish events for {}", log_pubkey!(their_node_id));

		let _ = self.total_consistency_lock.read().unwrap();
		let mut channel_state_lock = self.channel_state.lock().unwrap();
		let channel_state = channel_state_lock.borrow_parts();
		let pending_msg_events = channel_state.pending_msg_events;
		channel_state.by_id.retain(|_, chan| {
			if chan.get_their_node_id() == *their_node_id {
				if !chan.have_received_message() {
					// If we created this (outbound) channel while we were disconnected from the
					// peer we probably failed to send the open_channel message, which is now
					// lost. We can't have had anything pending related to this channel, so we just
					// drop it.
					false
				} else {
					pending_msg_events.push(events::MessageSendEvent::SendChannelReestablish {
						node_id: chan.get_their_node_id(),
						msg: chan.get_channel_reestablish(),
					});
					true
				}
			} else { true }
		});
		//TODO: Also re-broadcast announcement_signatures
	}

	fn handle_error(&self, their_node_id: &PublicKey, msg: &msgs::ErrorMessage) {
		let _ = self.total_consistency_lock.read().unwrap();

		if msg.channel_id == [0; 32] {
			for chan in self.list_channels() {
				if chan.remote_network_id == *their_node_id {
					self.force_close_channel(&chan.channel_id);
				}
			}
		} else {
			self.force_close_channel(&msg.channel_id);
		}
	}
}

const SERIALIZATION_VERSION: u8 = 1;
const MIN_SERIALIZATION_VERSION: u8 = 1;

impl Writeable for PendingForwardHTLCInfo {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
		self.onion_packet.write(writer)?;
		self.incoming_shared_secret.write(writer)?;
		self.payment_hash.write(writer)?;
		self.short_channel_id.write(writer)?;
		self.amt_to_forward.write(writer)?;
		self.outgoing_cltv_value.write(writer)?;
		Ok(())
	}
}

impl<R: ::std::io::Read> Readable<R> for PendingForwardHTLCInfo {
	fn read(reader: &mut R) -> Result<PendingForwardHTLCInfo, DecodeError> {
		Ok(PendingForwardHTLCInfo {
			onion_packet: Readable::read(reader)?,
			incoming_shared_secret: Readable::read(reader)?,
			payment_hash: Readable::read(reader)?,
			short_channel_id: Readable::read(reader)?,
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

impl<R: ::std::io::Read> Readable<R> for HTLCFailureMsg {
	fn read(reader: &mut R) -> Result<HTLCFailureMsg, DecodeError> {
		match <u8 as Readable<R>>::read(reader)? {
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

impl<R: ::std::io::Read> Readable<R> for PendingHTLCStatus {
	fn read(reader: &mut R) -> Result<PendingHTLCStatus, DecodeError> {
		match <u8 as Readable<R>>::read(reader)? {
			0 => Ok(PendingHTLCStatus::Forward(Readable::read(reader)?)),
			1 => Ok(PendingHTLCStatus::Fail(Readable::read(reader)?)),
			_ => Err(DecodeError::InvalidValue),
		}
	}
}

impl_writeable!(HTLCPreviousHopData, 0, {
	short_channel_id,
	htlc_id,
	incoming_packet_shared_secret
});

impl Writeable for HTLCSource {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
		match self {
			&HTLCSource::PreviousHopData(ref hop_data) => {
				0u8.write(writer)?;
				hop_data.write(writer)?;
			},
			&HTLCSource::OutboundRoute { ref route, ref session_priv, ref first_hop_htlc_msat } => {
				1u8.write(writer)?;
				route.write(writer)?;
				session_priv.write(writer)?;
				first_hop_htlc_msat.write(writer)?;
			}
		}
		Ok(())
	}
}

impl<R: ::std::io::Read> Readable<R> for HTLCSource {
	fn read(reader: &mut R) -> Result<HTLCSource, DecodeError> {
		match <u8 as Readable<R>>::read(reader)? {
			0 => Ok(HTLCSource::PreviousHopData(Readable::read(reader)?)),
			1 => Ok(HTLCSource::OutboundRoute {
				route: Readable::read(reader)?,
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

impl<R: ::std::io::Read> Readable<R> for HTLCFailReason {
	fn read(reader: &mut R) -> Result<HTLCFailReason, DecodeError> {
		match <u8 as Readable<R>>::read(reader)? {
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
			&HTLCForwardInfo::AddHTLC { ref prev_short_channel_id, ref prev_htlc_id, ref forward_info } => {
				0u8.write(writer)?;
				prev_short_channel_id.write(writer)?;
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

impl<R: ::std::io::Read> Readable<R> for HTLCForwardInfo {
	fn read(reader: &mut R) -> Result<HTLCForwardInfo, DecodeError> {
		match <u8 as Readable<R>>::read(reader)? {
			0 => Ok(HTLCForwardInfo::AddHTLC {
				prev_short_channel_id: Readable::read(reader)?,
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

impl Writeable for ChannelManager {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
		let _ = self.total_consistency_lock.write().unwrap();

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
			for &(recvd_amt, ref previous_hop) in previous_hops.iter() {
				recvd_amt.write(writer)?;
				previous_hop.write(writer)?;
			}
		}

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
///    ChannelMonitor::get_monitored_outpoints and ChannelMonitor::get_funding_txo().
/// 4) Reconnect blocks on your ChannelMonitors.
/// 5) Move the ChannelMonitors into your local ManyChannelMonitor.
/// 6) Disconnect/connect blocks on the ChannelManager.
/// 7) Register the new ChannelManager with your ChainWatchInterface (this does not happen
///    automatically as it does in ChannelManager::new()).
pub struct ChannelManagerReadArgs<'a> {
	/// The keys provider which will give us relevant keys. Some keys will be loaded during
	/// deserialization.
	pub keys_manager: Arc<KeysInterface>,

	/// The fee_estimator for use in the ChannelManager in the future.
	///
	/// No calls to the FeeEstimator will be made during deserialization.
	pub fee_estimator: Arc<FeeEstimator>,
	/// The ManyChannelMonitor for use in the ChannelManager in the future.
	///
	/// No calls to the ManyChannelMonitor will be made during deserialization. It is assumed that
	/// you have deserialized ChannelMonitors separately and will add them to your
	/// ManyChannelMonitor after deserializing this ChannelManager.
	pub monitor: Arc<ManyChannelMonitor>,
	/// The ChainWatchInterface for use in the ChannelManager in the future.
	///
	/// No calls to the ChainWatchInterface will be made during deserialization.
	pub chain_monitor: Arc<ChainWatchInterface>,
	/// The BroadcasterInterface which will be used in the ChannelManager in the future and may be
	/// used to broadcast the latest local commitment transactions of channels which must be
	/// force-closed during deserialization.
	pub tx_broadcaster: Arc<BroadcasterInterface>,
	/// The Logger for use in the ChannelManager and which may be used to log information during
	/// deserialization.
	pub logger: Arc<Logger>,
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
	pub channel_monitors: &'a HashMap<OutPoint, &'a ChannelMonitor>,
}

impl<'a, R : ::std::io::Read> ReadableArgs<R, ChannelManagerReadArgs<'a>> for (Sha256dHash, ChannelManager) {
	fn read(reader: &mut R, args: ChannelManagerReadArgs<'a>) -> Result<Self, DecodeError> {
		let _ver: u8 = Readable::read(reader)?;
		let min_ver: u8 = Readable::read(reader)?;
		if min_ver > SERIALIZATION_VERSION {
			return Err(DecodeError::UnknownVersion);
		}

		let genesis_hash: Sha256dHash = Readable::read(reader)?;
		let latest_block_height: u32 = Readable::read(reader)?;
		let last_block_hash: Sha256dHash = Readable::read(reader)?;

		let mut closed_channels = Vec::new();

		let channel_count: u64 = Readable::read(reader)?;
		let mut funding_txo_set = HashSet::with_capacity(cmp::min(channel_count as usize, 128));
		let mut by_id = HashMap::with_capacity(cmp::min(channel_count as usize, 128));
		let mut short_to_id = HashMap::with_capacity(cmp::min(channel_count as usize, 128));
		for _ in 0..channel_count {
			let mut channel: Channel = ReadableArgs::read(reader, args.logger.clone())?;
			if channel.last_block_connected != last_block_hash {
				return Err(DecodeError::InvalidValue);
			}

			let funding_txo = channel.channel_monitor().get_funding_txo().ok_or(DecodeError::InvalidValue)?;
			funding_txo_set.insert(funding_txo.clone());
			if let Some(monitor) = args.channel_monitors.get(&funding_txo) {
				if channel.get_cur_local_commitment_transaction_number() != monitor.get_cur_local_commitment_number() ||
						channel.get_revoked_remote_commitment_transaction_number() != monitor.get_min_seen_secret() ||
						channel.get_cur_remote_commitment_transaction_number() != monitor.get_cur_remote_commitment_number() {
					let mut force_close_res = channel.force_shutdown();
					force_close_res.0 = monitor.get_latest_local_commitment_txn();
					closed_channels.push(force_close_res);
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

		for (ref funding_txo, ref monitor) in args.channel_monitors.iter() {
			if !funding_txo_set.contains(funding_txo) {
				closed_channels.push((monitor.get_latest_local_commitment_txn(), Vec::new()));
			}
		}

		let forward_htlcs_count: u64 = Readable::read(reader)?;
		let mut forward_htlcs = HashMap::with_capacity(cmp::min(forward_htlcs_count as usize, 128));
		for _ in 0..forward_htlcs_count {
			let short_channel_id = Readable::read(reader)?;
			let pending_forwards_count: u64 = Readable::read(reader)?;
			let mut pending_forwards = Vec::with_capacity(cmp::min(pending_forwards_count as usize, 128));
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
			let mut previous_hops = Vec::with_capacity(cmp::min(previous_hops_len as usize, 2));
			for _ in 0..previous_hops_len {
				previous_hops.push((Readable::read(reader)?, Readable::read(reader)?));
			}
			claimable_htlcs.insert(payment_hash, previous_hops);
		}

		let channel_manager = ChannelManager {
			genesis_hash,
			fee_estimator: args.fee_estimator,
			monitor: args.monitor,
			chain_monitor: args.chain_monitor,
			tx_broadcaster: args.tx_broadcaster,

			latest_block_height: AtomicUsize::new(latest_block_height as usize),
			last_block_hash: Mutex::new(last_block_hash),
			secp_ctx: Secp256k1::new(),

			channel_state: Mutex::new(ChannelHolder {
				by_id,
				short_to_id,
				forward_htlcs,
				claimable_htlcs,
				pending_msg_events: Vec::new(),
			}),
			our_network_key: args.keys_manager.get_node_secret(),

			pending_events: Mutex::new(Vec::new()),
			total_consistency_lock: RwLock::new(()),
			keys_manager: args.keys_manager,
			logger: args.logger,
			default_configuration: args.default_config,
		};

		for close_res in closed_channels.drain(..) {
			channel_manager.finish_force_close_channel(close_res);
			//TODO: Broadcast channel update for closed channels, but only after we've made a
			//connection or two.
		}

		Ok((last_block_hash.clone(), channel_manager))
	}
}
