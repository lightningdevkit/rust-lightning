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
use bitcoin::util::hash::{BitcoinHash, Sha256dHash};

use secp256k1::key::{SecretKey,PublicKey};
use secp256k1::{Secp256k1,Message};
use secp256k1::ecdh::SharedSecret;
use secp256k1;

use chain::chaininterface::{BroadcasterInterface,ChainListener,ChainWatchInterface,FeeEstimator};
use chain::transaction::OutPoint;
use ln::channel::{Channel, ChannelError};
use ln::channelmonitor::{ChannelMonitor, ChannelMonitorUpdateErr, ManyChannelMonitor, CLTV_CLAIM_BUFFER, HTLC_FAIL_TIMEOUT_BLOCKS};
use ln::router::{Route,RouteHop};
use ln::msgs;
use ln::msgs::{ChannelMessageHandler, DecodeError, HandleError};
use chain::keysinterface::KeysInterface;
use util::config::UserConfig;
use util::{byte_utils, events, internal_traits, rng};
use util::sha2::Sha256;
use util::ser::{Readable, ReadableArgs, Writeable, Writer};
use util::chacha20poly1305rfc::ChaCha20;
use util::logger::Logger;
use util::errors::APIError;

use crypto;
use crypto::mac::{Mac,MacResult};
use crypto::hmac::Hmac;
use crypto::digest::Digest;
use crypto::symmetriccipher::SynchronousStreamCipher;

use std::{cmp, ptr, mem};
use std::collections::{HashMap, hash_map, HashSet};
use std::io::Cursor;
use std::sync::{Arc, Mutex, MutexGuard, RwLock};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Instant,Duration};

/// We hold various information about HTLC relay in the HTLC objects in Channel itself:
///
/// Upon receipt of an HTLC from a peer, we'll give it a PendingHTLCStatus indicating if it should
/// forward the HTLC with information it will give back to us when it does so, or if it should Fail
/// the HTLC with the relevant message for the Channel to handle giving to the remote peer.
///
/// When a Channel forwards an HTLC to its peer, it will give us back the PendingForwardHTLCInfo
/// which we will use to construct an outbound HTLC, with a relevant HTLCSource::PreviousHopData
/// filled in to indicate where it came from (which we can use to either fail-backwards or fulfill
/// the HTLC backwards along the relevant path).
/// Alternatively, we can fill an outbound HTLC with a HTLCSource::OutboundRoute indicating this is
/// our payment, which we can use to decode errors or inform the user that the payment was sent.
mod channel_held_info {
	use ln::msgs;
	use ln::router::Route;
	use secp256k1::key::SecretKey;

	/// Stores the info we will need to send when we want to forward an HTLC onwards
	#[derive(Clone)] // See Channel::revoke_and_ack for why, tl;dr: Rust bug
	pub struct PendingForwardHTLCInfo {
		pub(super) onion_packet: Option<msgs::OnionPacket>,
		pub(super) incoming_shared_secret: [u8; 32],
		pub(super) payment_hash: [u8; 32],
		pub(super) short_channel_id: u64,
		pub(super) amt_to_forward: u64,
		pub(super) outgoing_cltv_value: u32,
	}

	#[derive(Clone)] // See Channel::revoke_and_ack for why, tl;dr: Rust bug
	pub enum HTLCFailureMsg {
		Relay(msgs::UpdateFailHTLC),
		Malformed(msgs::UpdateFailMalformedHTLC),
	}

	/// Stores whether we can't forward an HTLC or relevant forwarding info
	#[derive(Clone)] // See Channel::revoke_and_ack for why, tl;dr: Rust bug
	pub enum PendingHTLCStatus {
		Forward(PendingForwardHTLCInfo),
		Fail(HTLCFailureMsg),
	}

	/// Tracks the inbound corresponding to an outbound HTLC
	#[derive(Clone)]
	pub struct HTLCPreviousHopData {
		pub(super) short_channel_id: u64,
		pub(super) htlc_id: u64,
		pub(super) incoming_packet_shared_secret: [u8; 32],
	}

	/// Tracks the inbound corresponding to an outbound HTLC
	#[derive(Clone)]
	pub enum HTLCSource {
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
				session_priv: SecretKey::from_slice(&::secp256k1::Secp256k1::without_caps(), &[1; 32]).unwrap(),
				first_hop_htlc_msat: 0,
			}
		}
	}

	#[derive(Clone)] // See Channel::revoke_and_ack for why, tl;dr: Rust bug
	pub(crate) enum HTLCFailReason {
		ErrorPacket {
			err: msgs::OnionErrorPacket,
		},
		Reason {
			failure_code: u16,
			data: Vec<u8>,
		}
	}
}
pub(super) use self::channel_held_info::*;

struct MsgHandleErrInternal {
	err: msgs::HandleError,
	needs_channel_force_close: bool,
}
impl MsgHandleErrInternal {
	#[inline]
	fn send_err_msg_no_close(err: &'static str, channel_id: [u8; 32]) -> Self {
		Self {
			err: HandleError {
				err,
				action: Some(msgs::ErrorAction::SendErrorMessage {
					msg: msgs::ErrorMessage {
						channel_id,
						data: err.to_string()
					},
				}),
			},
			needs_channel_force_close: false,
		}
	}
	#[inline]
	fn send_err_msg_close_chan(err: &'static str, channel_id: [u8; 32]) -> Self {
		Self {
			err: HandleError {
				err,
				action: Some(msgs::ErrorAction::SendErrorMessage {
					msg: msgs::ErrorMessage {
						channel_id,
						data: err.to_string()
					},
				}),
			},
			needs_channel_force_close: true,
		}
	}
	#[inline]
	fn from_maybe_close(err: msgs::HandleError) -> Self {
		Self { err, needs_channel_force_close: true }
	}
	#[inline]
	fn from_no_close(err: msgs::HandleError) -> Self {
		Self { err, needs_channel_force_close: false }
	}
	#[inline]
	fn from_chan_no_close(err: ChannelError, channel_id: [u8; 32]) -> Self {
		Self {
			err: match err {
				ChannelError::Ignore(msg) => HandleError {
					err: msg,
					action: Some(msgs::ErrorAction::IgnoreError),
				},
				ChannelError::Close(msg) => HandleError {
					err: msg,
					action: Some(msgs::ErrorAction::SendErrorMessage {
						msg: msgs::ErrorMessage {
							channel_id,
							data: msg.to_string()
						},
					}),
				},
			},
			needs_channel_force_close: false,
		}
	}
	#[inline]
	fn from_chan_maybe_close(err: ChannelError, channel_id: [u8; 32]) -> Self {
		Self {
			err: match err {
				ChannelError::Ignore(msg) => HandleError {
					err: msg,
					action: Some(msgs::ErrorAction::IgnoreError),
				},
				ChannelError::Close(msg) => HandleError {
					err: msg,
					action: Some(msgs::ErrorAction::SendErrorMessage {
						msg: msgs::ErrorMessage {
							channel_id,
							data: msg.to_string()
						},
					}),
				},
			},
			needs_channel_force_close: true,
		}
	}
}

/// Pass to fail_htlc_backwwards to indicate the reason to fail the payment
/// after a PaymentReceived event.
#[derive(PartialEq)]
pub enum PaymentFailReason {
	/// Indicate the preimage for payment_hash is not known after a PaymentReceived event
	PreimageUnknown,
	/// Indicate the payment amount is incorrect ( received is < expected or > 2*expected ) after a PaymentReceived event
	AmountMismatch,
}

/// We hold back HTLCs we intend to relay for a random interval in the range (this, 5*this). This
/// provides some limited amount of privacy. Ideally this would range from somewhere like 1 second
/// to 30 seconds, but people expect lightning to be, you know, kinda fast, sadly. We could
/// probably increase this significantly.
const MIN_HTLC_RELAY_HOLDING_CELL_MILLIS: u32 = 50;

struct HTLCForwardInfo {
	prev_short_channel_id: u64,
	prev_htlc_id: u64,
	forward_info: PendingForwardHTLCInfo,
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

struct ChannelHolder {
	by_id: HashMap<[u8; 32], Channel>,
	short_to_id: HashMap<u64, [u8; 32]>,
	next_forward: Instant,
	/// short channel id -> forward infos. Key of 0 means payments received
	/// Note that while this is held in the same mutex as the channels themselves, no consistency
	/// guarantees are made about there existing a channel with the short id here, nor the short
	/// ids in the PendingForwardHTLCInfo!
	forward_htlcs: HashMap<u64, Vec<HTLCForwardInfo>>,
	/// Note that while this is held in the same mutex as the channels themselves, no consistency
	/// guarantees are made about the channels given here actually existing anymore by the time you
	/// go to read them!
	claimable_htlcs: HashMap<[u8; 32], Vec<HTLCPreviousHopData>>,
	/// Messages to send to peers - pushed to in the same lock that they are generated in (except
	/// for broadcast messages, where ordering isn't as strict).
	pending_msg_events: Vec<events::MessageSendEvent>,
}
struct MutChannelHolder<'a> {
	by_id: &'a mut HashMap<[u8; 32], Channel>,
	short_to_id: &'a mut HashMap<u64, [u8; 32]>,
	next_forward: &'a mut Instant,
	forward_htlcs: &'a mut HashMap<u64, Vec<HTLCForwardInfo>>,
	claimable_htlcs: &'a mut HashMap<[u8; 32], Vec<HTLCPreviousHopData>>,
	pending_msg_events: &'a mut Vec<events::MessageSendEvent>,
}
impl ChannelHolder {
	fn borrow_parts(&mut self) -> MutChannelHolder {
		MutChannelHolder {
			by_id: &mut self.by_id,
			short_to_id: &mut self.short_to_id,
			next_forward: &mut self.next_forward,
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

	latest_block_height: AtomicUsize,
	last_block_hash: Mutex<Sha256dHash>,
	secp_ctx: Secp256k1<secp256k1::All>,

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

/// The minimum number of blocks between an inbound HTLC's CLTV and the corresponding outbound
/// HTLC's CLTV. This should always be a few blocks greater than channelmonitor::CLTV_CLAIM_BUFFER,
/// ie the node we forwarded the payment on to should always have enough room to reliably time out
/// the HTLC via a full update_fail_htlc/commitment_signed dance before we hit the
/// CLTV_CLAIM_BUFFER point (we static assert that its at least 3 blocks more).
const CLTV_EXPIRY_DELTA: u16 = 6 * 24 * 2; //TODO?
const CLTV_FAR_FAR_AWAY: u32 = 6 * 24 * 7; //TODO?

// Check that our CLTV_EXPIRY is at least CLTV_CLAIM_BUFFER + 2*HTLC_FAIL_TIMEOUT_BLOCKS, ie that
// if the next-hop peer fails the HTLC within HTLC_FAIL_TIMEOUT_BLOCKS then we'll still have
// HTLC_FAIL_TIMEOUT_BLOCKS left to fail it backwards ourselves before hitting the
// CLTV_CLAIM_BUFFER point and failing the channel on-chain to time out the HTLC.
#[deny(const_err)]
#[allow(dead_code)]
const CHECK_CLTV_EXPIRY_SANITY: u32 = CLTV_EXPIRY_DELTA as u32 - 2*HTLC_FAIL_TIMEOUT_BLOCKS - CLTV_CLAIM_BUFFER;

// Check for ability of an attacker to make us fail on-chain by delaying inbound claim. See
// ChannelMontior::would_broadcast_at_height for a description of why this is needed.
#[deny(const_err)]
#[allow(dead_code)]
const CHECK_CLTV_EXPIRY_SANITY_2: u32 = CLTV_EXPIRY_DELTA as u32 - HTLC_FAIL_TIMEOUT_BLOCKS - 2*CLTV_CLAIM_BUFFER;

macro_rules! secp_call {
	( $res: expr, $err: expr ) => {
		match $res {
			Ok(key) => key,
			Err(_) => return Err($err),
		}
	};
}

struct OnionKeys {
	#[cfg(test)]
	shared_secret: SharedSecret,
	#[cfg(test)]
	blinding_factor: [u8; 32],
	ephemeral_pubkey: PublicKey,
	rho: [u8; 32],
	mu: [u8; 32],
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
}

macro_rules! handle_error {
	($self: ident, $internal: expr, $their_node_id: expr) => {
		match $internal {
			Ok(msg) => Ok(msg),
			Err(MsgHandleErrInternal { err, needs_channel_force_close }) => {
				if needs_channel_force_close {
					match &err.action {
						&Some(msgs::ErrorAction::DisconnectPeer { msg: Some(ref msg) }) => {
							if msg.channel_id == [0; 32] {
								$self.peer_disconnected(&$their_node_id, true);
							} else {
								$self.force_close_channel(&msg.channel_id);
							}
						},
						&Some(msgs::ErrorAction::DisconnectPeer { msg: None }) => {},
						&Some(msgs::ErrorAction::IgnoreError) => {},
						&Some(msgs::ErrorAction::SendErrorMessage { ref msg }) => {
							if msg.channel_id == [0; 32] {
								$self.peer_disconnected(&$their_node_id, true);
							} else {
								$self.force_close_channel(&msg.channel_id);
							}
						},
						&None => {},
					}
				}
				Err(err)
			},
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
	pub fn new(network: Network, feeest: Arc<FeeEstimator>, monitor: Arc<ManyChannelMonitor>, chain_monitor: Arc<ChainWatchInterface>, tx_broadcaster: Arc<BroadcasterInterface>, logger: Arc<Logger>,keys_manager: Arc<KeysInterface>, config: UserConfig) -> Result<Arc<ChannelManager>, secp256k1::Error> {
		let secp_ctx = Secp256k1::new();

		let res = Arc::new(ChannelManager {
			default_configuration: config.clone(),
			genesis_hash: genesis_block(network).header.bitcoin_hash(),
			fee_estimator: feeest.clone(),
			monitor: monitor.clone(),
			chain_monitor,
			tx_broadcaster,

			latest_block_height: AtomicUsize::new(0), //TODO: Get an init value
			last_block_hash: Mutex::new(Default::default()),
			secp_ctx,

			channel_state: Mutex::new(ChannelHolder{
				by_id: HashMap::new(),
				short_to_id: HashMap::new(),
				next_forward: Instant::now(),
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
			res.push(ChannelDetails {
				channel_id: (*channel_id).clone(),
				short_channel_id: channel.get_short_channel_id(),
				remote_network_id: channel.get_their_node_id(),
				channel_value_satoshis: channel.get_value_satoshis(),
				user_id: channel.get_user_id(),
			});
		}
		res
	}

	/// Gets the list of usable channels, in random order. Useful as an argument to
	/// Router::get_route to ensure non-announced channels are used.
	pub fn list_usable_channels(&self) -> Vec<ChannelDetails> {
		let channel_state = self.channel_state.lock().unwrap();
		let mut res = Vec::with_capacity(channel_state.by_id.len());
		for (channel_id, channel) in channel_state.by_id.iter() {
			// Note we use is_live here instead of usable which leads to somewhat confused
			// internal/external nomenclature, but that's ok cause that's probably what the user
			// really wanted anyway.
			if channel.is_live() {
				res.push(ChannelDetails {
					channel_id: (*channel_id).clone(),
					short_channel_id: channel.get_short_channel_id(),
					remote_network_id: channel.get_their_node_id(),
					channel_value_satoshis: channel.get_value_satoshis(),
					user_id: channel.get_user_id(),
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
			// unknown_next_peer...I dunno who that is anymore....
			self.fail_htlc_backwards_internal(self.channel_state.lock().unwrap(), htlc_source.0, &htlc_source.1, HTLCFailReason::Reason { failure_code: 0x4000 | 10, data: Vec::new() });
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
	fn finish_force_close_channel(&self, shutdown_res: (Vec<Transaction>, Vec<(HTLCSource, [u8; 32])>)) {
		let (local_txn, mut failed_htlcs) = shutdown_res;
		for htlc_source in failed_htlcs.drain(..) {
			// unknown_next_peer...I dunno who that is anymore....
			self.fail_htlc_backwards_internal(self.channel_state.lock().unwrap(), htlc_source.0, &htlc_source.1, HTLCFailReason::Reason { failure_code: 0x4000 | 10, data: Vec::new() });
		}
		for tx in local_txn {
			self.tx_broadcaster.broadcast_transaction(&tx);
		}
		//TODO: We need to have a way where outbound HTLC claims can result in us claiming the
		//now-on-chain HTLC output for ourselves (and, thereafter, passing the HTLC backwards).
		//TODO: We need to handle monitoring of pending offered HTLCs which just hit the chain and
		//may be claimed, resulting in us claiming the inbound HTLCs (and back-failing after
		//timeouts are hit and our claims confirm).
		//TODO: In any case, we need to make sure we remove any pending htlc tracking (via
		//fail_backwards or claim_funds) eventually for all HTLCs that were in the channel
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

	fn handle_monitor_update_fail(&self, mut channel_state_lock: MutexGuard<ChannelHolder>, channel_id: &[u8; 32], err: ChannelMonitorUpdateErr, reason: RAACommitmentOrder) {
		match err {
			ChannelMonitorUpdateErr::PermanentFailure => {
				let mut chan = {
					let channel_state = channel_state_lock.borrow_parts();
					let chan = channel_state.by_id.remove(channel_id).expect("monitor_update_failed must be called within the same lock as the channel get!");
					if let Some(short_id) = chan.get_short_channel_id() {
						channel_state.short_to_id.remove(&short_id);
					}
					chan
				};
				mem::drop(channel_state_lock);
				self.finish_force_close_channel(chan.force_shutdown());
				if let Ok(update) = self.get_channel_update(&chan) {
					let mut channel_state = self.channel_state.lock().unwrap();
					channel_state.pending_msg_events.push(events::MessageSendEvent::BroadcastChannelUpdate {
						msg: update
					});
				}
			},
			ChannelMonitorUpdateErr::TemporaryFailure => {
				let channel = channel_state_lock.by_id.get_mut(channel_id).expect("monitor_update_failed must be called within the same lock as the channel get!");
				channel.monitor_update_failed(reason);
			},
		}
	}

	#[inline]
	fn gen_rho_mu_from_shared_secret(shared_secret: &[u8]) -> ([u8; 32], [u8; 32]) {
		assert_eq!(shared_secret.len(), 32);
		({
			let mut hmac = Hmac::new(Sha256::new(), &[0x72, 0x68, 0x6f]); // rho
			hmac.input(&shared_secret[..]);
			let mut res = [0; 32];
			hmac.raw_result(&mut res);
			res
		},
		{
			let mut hmac = Hmac::new(Sha256::new(), &[0x6d, 0x75]); // mu
			hmac.input(&shared_secret[..]);
			let mut res = [0; 32];
			hmac.raw_result(&mut res);
			res
		})
	}

	#[inline]
	fn gen_um_from_shared_secret(shared_secret: &[u8]) -> [u8; 32] {
		assert_eq!(shared_secret.len(), 32);
		let mut hmac = Hmac::new(Sha256::new(), &[0x75, 0x6d]); // um
		hmac.input(&shared_secret[..]);
		let mut res = [0; 32];
		hmac.raw_result(&mut res);
		res
	}

	#[inline]
	fn gen_ammag_from_shared_secret(shared_secret: &[u8]) -> [u8; 32] {
		assert_eq!(shared_secret.len(), 32);
		let mut hmac = Hmac::new(Sha256::new(), &[0x61, 0x6d, 0x6d, 0x61, 0x67]); // ammag
		hmac.input(&shared_secret[..]);
		let mut res = [0; 32];
		hmac.raw_result(&mut res);
		res
	}

	// can only fail if an intermediary hop has an invalid public key or session_priv is invalid
	#[inline]
	fn construct_onion_keys_callback<T: secp256k1::Signing, FType: FnMut(SharedSecret, [u8; 32], PublicKey, &RouteHop)> (secp_ctx: &Secp256k1<T>, route: &Route, session_priv: &SecretKey, mut callback: FType) -> Result<(), secp256k1::Error> {
		let mut blinded_priv = session_priv.clone();
		let mut blinded_pub = PublicKey::from_secret_key(secp_ctx, &blinded_priv);

		for hop in route.hops.iter() {
			let shared_secret = SharedSecret::new(secp_ctx, &hop.pubkey, &blinded_priv);

			let mut sha = Sha256::new();
			sha.input(&blinded_pub.serialize()[..]);
			sha.input(&shared_secret[..]);
			let mut blinding_factor = [0u8; 32];
			sha.result(&mut blinding_factor);

			let ephemeral_pubkey = blinded_pub;

			blinded_priv.mul_assign(secp_ctx, &SecretKey::from_slice(secp_ctx, &blinding_factor)?)?;
			blinded_pub = PublicKey::from_secret_key(secp_ctx, &blinded_priv);

			callback(shared_secret, blinding_factor, ephemeral_pubkey, hop);
		}

		Ok(())
	}

	// can only fail if an intermediary hop has an invalid public key or session_priv is invalid
	fn construct_onion_keys<T: secp256k1::Signing>(secp_ctx: &Secp256k1<T>, route: &Route, session_priv: &SecretKey) -> Result<Vec<OnionKeys>, secp256k1::Error> {
		let mut res = Vec::with_capacity(route.hops.len());

		Self::construct_onion_keys_callback(secp_ctx, route, session_priv, |shared_secret, _blinding_factor, ephemeral_pubkey, _| {
			let (rho, mu) = ChannelManager::gen_rho_mu_from_shared_secret(&shared_secret[..]);

			res.push(OnionKeys {
				#[cfg(test)]
				shared_secret,
				#[cfg(test)]
				blinding_factor: _blinding_factor,
				ephemeral_pubkey,
				rho,
				mu,
			});
		})?;

		Ok(res)
	}

	/// returns the hop data, as well as the first-hop value_msat and CLTV value we should send.
	fn build_onion_payloads(route: &Route, starting_htlc_offset: u32) -> Result<(Vec<msgs::OnionHopData>, u64, u32), APIError> {
		let mut cur_value_msat = 0u64;
		let mut cur_cltv = starting_htlc_offset;
		let mut last_short_channel_id = 0;
		let mut res: Vec<msgs::OnionHopData> = Vec::with_capacity(route.hops.len());
		internal_traits::test_no_dealloc::<msgs::OnionHopData>(None);
		unsafe { res.set_len(route.hops.len()); }

		for (idx, hop) in route.hops.iter().enumerate().rev() {
			// First hop gets special values so that it can check, on receipt, that everything is
			// exactly as it should be (and the next hop isn't trying to probe to find out if we're
			// the intended recipient).
			let value_msat = if cur_value_msat == 0 { hop.fee_msat } else { cur_value_msat };
			let cltv = if cur_cltv == starting_htlc_offset { hop.cltv_expiry_delta + starting_htlc_offset } else { cur_cltv };
			res[idx] = msgs::OnionHopData {
				realm: 0,
				data: msgs::OnionRealm0HopData {
					short_channel_id: last_short_channel_id,
					amt_to_forward: value_msat,
					outgoing_cltv_value: cltv,
				},
				hmac: [0; 32],
			};
			cur_value_msat += hop.fee_msat;
			if cur_value_msat >= 21000000 * 100000000 * 1000 {
				return Err(APIError::RouteError{err: "Channel fees overflowed?!"});
			}
			cur_cltv += hop.cltv_expiry_delta as u32;
			if cur_cltv >= 500000000 {
				return Err(APIError::RouteError{err: "Channel CLTV overflowed?!"});
			}
			last_short_channel_id = hop.short_channel_id;
		}
		Ok((res, cur_value_msat, cur_cltv))
	}

	#[inline]
	fn shift_arr_right(arr: &mut [u8; 20*65]) {
		unsafe {
			ptr::copy(arr[0..].as_ptr(), arr[65..].as_mut_ptr(), 19*65);
		}
		for i in 0..65 {
			arr[i] = 0;
		}
	}

	#[inline]
	fn xor_bufs(dst: &mut[u8], src: &[u8]) {
		assert_eq!(dst.len(), src.len());

		for i in 0..dst.len() {
			dst[i] ^= src[i];
		}
	}

	const ZERO:[u8; 21*65] = [0; 21*65];
	fn construct_onion_packet(mut payloads: Vec<msgs::OnionHopData>, onion_keys: Vec<OnionKeys>, associated_data: &[u8; 32]) -> msgs::OnionPacket {
		let mut buf = Vec::with_capacity(21*65);
		buf.resize(21*65, 0);

		let filler = {
			let iters = payloads.len() - 1;
			let end_len = iters * 65;
			let mut res = Vec::with_capacity(end_len);
			res.resize(end_len, 0);

			for (i, keys) in onion_keys.iter().enumerate() {
				if i == payloads.len() - 1 { continue; }
				let mut chacha = ChaCha20::new(&keys.rho, &[0u8; 8]);
				chacha.process(&ChannelManager::ZERO, &mut buf); // We don't have a seek function :(
				ChannelManager::xor_bufs(&mut res[0..(i + 1)*65], &buf[(20 - i)*65..21*65]);
			}
			res
		};

		let mut packet_data = [0; 20*65];
		let mut hmac_res = [0; 32];

		for (i, (payload, keys)) in payloads.iter_mut().zip(onion_keys.iter()).rev().enumerate() {
			ChannelManager::shift_arr_right(&mut packet_data);
			payload.hmac = hmac_res;
			packet_data[0..65].copy_from_slice(&payload.encode()[..]);

			let mut chacha = ChaCha20::new(&keys.rho, &[0u8; 8]);
			chacha.process(&packet_data, &mut buf[0..20*65]);
			packet_data[..].copy_from_slice(&buf[0..20*65]);

			if i == 0 {
				packet_data[20*65 - filler.len()..20*65].copy_from_slice(&filler[..]);
			}

			let mut hmac = Hmac::new(Sha256::new(), &keys.mu);
			hmac.input(&packet_data);
			hmac.input(&associated_data[..]);
			hmac.raw_result(&mut hmac_res);
		}

		msgs::OnionPacket{
			version: 0,
			public_key: Ok(onion_keys.first().unwrap().ephemeral_pubkey),
			hop_data: packet_data,
			hmac: hmac_res,
		}
	}

	/// Encrypts a failure packet. raw_packet can either be a
	/// msgs::DecodedOnionErrorPacket.encode() result or a msgs::OnionErrorPacket.data element.
	fn encrypt_failure_packet(shared_secret: &[u8], raw_packet: &[u8]) -> msgs::OnionErrorPacket {
		let ammag = ChannelManager::gen_ammag_from_shared_secret(&shared_secret);

		let mut packet_crypted = Vec::with_capacity(raw_packet.len());
		packet_crypted.resize(raw_packet.len(), 0);
		let mut chacha = ChaCha20::new(&ammag, &[0u8; 8]);
		chacha.process(&raw_packet, &mut packet_crypted[..]);
		msgs::OnionErrorPacket {
			data: packet_crypted,
		}
	}

	fn build_failure_packet(shared_secret: &[u8], failure_type: u16, failure_data: &[u8]) -> msgs::DecodedOnionErrorPacket {
		assert_eq!(shared_secret.len(), 32);
		assert!(failure_data.len() <= 256 - 2);

		let um = ChannelManager::gen_um_from_shared_secret(&shared_secret);

		let failuremsg = {
			let mut res = Vec::with_capacity(2 + failure_data.len());
			res.push(((failure_type >> 8) & 0xff) as u8);
			res.push(((failure_type >> 0) & 0xff) as u8);
			res.extend_from_slice(&failure_data[..]);
			res
		};
		let pad = {
			let mut res = Vec::with_capacity(256 - 2 - failure_data.len());
			res.resize(256 - 2 - failure_data.len(), 0);
			res
		};
		let mut packet = msgs::DecodedOnionErrorPacket {
			hmac: [0; 32],
			failuremsg: failuremsg,
			pad: pad,
		};

		let mut hmac = Hmac::new(Sha256::new(), &um);
		hmac.input(&packet.encode()[32..]);
		hmac.raw_result(&mut packet.hmac);

		packet
	}

	#[inline]
	fn build_first_hop_failure_packet(shared_secret: &[u8], failure_type: u16, failure_data: &[u8]) -> msgs::OnionErrorPacket {
		let failure_packet = ChannelManager::build_failure_packet(shared_secret, failure_type, failure_data);
		ChannelManager::encrypt_failure_packet(shared_secret, &failure_packet.encode()[..])
	}

	fn decode_update_add_htlc_onion(&self, msg: &msgs::UpdateAddHTLC) -> (PendingHTLCStatus, MutexGuard<ChannelHolder>) {
		macro_rules! get_onion_hash {
			() => {
				{
					let mut sha = Sha256::new();
					sha.input(&msg.onion_routing_packet.hop_data);
					let mut onion_hash = [0; 32];
					sha.result(&mut onion_hash);
					onion_hash
				}
			}
		}

		if let Err(_) = msg.onion_routing_packet.public_key {
			log_info!(self, "Failed to accept/forward incoming HTLC with invalid ephemeral pubkey");
			return (PendingHTLCStatus::Fail(HTLCFailureMsg::Malformed(msgs::UpdateFailMalformedHTLC {
				channel_id: msg.channel_id,
				htlc_id: msg.htlc_id,
				sha256_of_onion: get_onion_hash!(),
				failure_code: 0x8000 | 0x4000 | 6,
			})), self.channel_state.lock().unwrap());
		}

		let shared_secret = {
			let mut arr = [0; 32];
			arr.copy_from_slice(&SharedSecret::new(&self.secp_ctx, &msg.onion_routing_packet.public_key.unwrap(), &self.our_network_key)[..]);
			arr
		};
		let (rho, mu) = ChannelManager::gen_rho_mu_from_shared_secret(&shared_secret);

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
						reason: ChannelManager::build_first_hop_failure_packet(&shared_secret, $err_code, $data),
					})), channel_state.unwrap());
				}
			}
		}

		if msg.onion_routing_packet.version != 0 {
			//TODO: Spec doesn't indicate if we should only hash hop_data here (and in other
			//sha256_of_onion error data packets), or the entire onion_routing_packet. Either way,
			//the hash doesn't really serve any purpuse - in the case of hashing all data, the
			//receiving node would have to brute force to figure out which version was put in the
			//packet by the node that send us the message, in the case of hashing the hop_data, the
			//node knows the HMAC matched, so they already know what is there...
			return_err!("Unknown onion packet version", 0x8000 | 0x4000 | 4, &get_onion_hash!());
		}

		let mut hmac = Hmac::new(Sha256::new(), &mu);
		hmac.input(&msg.onion_routing_packet.hop_data);
		hmac.input(&msg.payment_hash);
		if hmac.result() != MacResult::new(&msg.onion_routing_packet.hmac) {
			return_err!("HMAC Check failed", 0x8000 | 0x4000 | 5, &get_onion_hash!());
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
				if (msg.cltv_expiry as u64) < self.latest_block_height.load(Ordering::Acquire) as u64 + (CLTV_CLAIM_BUFFER + HTLC_FAIL_TIMEOUT_BLOCKS) as u64 {
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
				chacha.process(&ChannelManager::ZERO[0..65], &mut new_packet_data[19*65..]);

				let mut new_pubkey = msg.onion_routing_packet.public_key.unwrap();

				let blinding_factor = {
					let mut sha = Sha256::new();
					sha.input(&new_pubkey.serialize()[..]);
					sha.input(&shared_secret);
					let mut res = [0u8; 32];
					sha.result(&mut res);
					match SecretKey::from_slice(&self.secp_ctx, &res) {
						Err(_) => {
							return_err!("Blinding factor is an invalid private key", 0x8000 | 0x4000 | 6, &get_onion_hash!());
						},
						Ok(key) => key
					}
				};

				if let Err(_) = new_pubkey.mul_assign(&self.secp_ctx, &blinding_factor) {
					return_err!("New blinding factor is an invalid private key", 0x8000 | 0x4000 | 6, &get_onion_hash!());
				}

				let outgoing_packet = msgs::OnionPacket {
					version: 0,
					public_key: Ok(new_pubkey),
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
					// We want to have at least HTLC_FAIL_TIMEOUT_BLOCKS to fail prior to going on chain CLAIM_BUFFER blocks before expiration
					if msg.cltv_expiry <= cur_height + CLTV_CLAIM_BUFFER + HTLC_FAIL_TIMEOUT_BLOCKS as u32 { // expiry_too_soon
						break Some(("CLTV expiry is too close", 0x1000 | 14, Some(self.get_channel_update(chan).unwrap())));
					}
					if msg.cltv_expiry > cur_height + CLTV_FAR_FAR_AWAY as u32 { // expiry_too_far
						break Some(("CLTV expiry is too far in the future", 21, None));
					}
					break None;
				}
				{
					let mut res = Vec::with_capacity(8 + 128);
					if code == 0x1000 | 11 || code == 0x1000 | 12 {
						res.extend_from_slice(&byte_utils::be64_to_array(msg.amount_msat));
					}
					else if code == 0x1000 | 13 {
						res.extend_from_slice(&byte_utils::be32_to_array(msg.cltv_expiry));
					}
					if let Some(chan_update) = chan_update {
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
	fn get_channel_update(&self, chan: &Channel) -> Result<msgs::ChannelUpdate, HandleError> {
		let short_channel_id = match chan.get_short_channel_id() {
			None => return Err(HandleError{err: "Channel not yet established", action: None}),
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

		let msg_hash = Sha256dHash::from_data(&unsigned.encode()[..]);
		let sig = self.secp_ctx.sign(&Message::from_slice(&msg_hash[..]).unwrap(), &self.our_network_key);

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
	/// (cltv_delta, fee, node public key) is specified
	pub fn send_payment(&self, route: Route, payment_hash: [u8; 32]) -> Result<(), APIError> {
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

		let onion_keys = secp_call!(ChannelManager::construct_onion_keys(&self.secp_ctx, &route, &session_priv),
				APIError::RouteError{err: "Pubkey along hop was maliciously selected"});
		let (onion_payloads, htlc_msat, htlc_cltv) = ChannelManager::build_onion_payloads(&route, cur_height)?;
		let onion_packet = ChannelManager::construct_onion_packet(onion_payloads, onion_keys, &payment_hash);

		let _ = self.total_consistency_lock.read().unwrap();
		let mut channel_state = self.channel_state.lock().unwrap();

		let id = match channel_state.short_to_id.get(&route.hops.first().unwrap().short_channel_id) {
			None => return Err(APIError::ChannelUnavailable{err: "No channel available with first hop!"}),
			Some(id) => id.clone(),
		};

		let res = {
			let chan = channel_state.by_id.get_mut(&id).unwrap();
			if chan.get_their_node_id() != route.hops.first().unwrap().pubkey {
				return Err(APIError::RouteError{err: "Node ID mismatch on first hop!"});
			}
			if chan.is_awaiting_monitor_update() {
				return Err(APIError::MonitorUpdateFailed);
			}
			if !chan.is_live() {
				return Err(APIError::ChannelUnavailable{err: "Peer for first hop currently disconnected!"});
			}
			chan.send_htlc_and_commit(htlc_msat, payment_hash.clone(), htlc_cltv, HTLCSource::OutboundRoute {
				route: route.clone(),
				session_priv: session_priv.clone(),
				first_hop_htlc_msat: htlc_msat,
			}, onion_packet).map_err(|he|
				match he {
					ChannelError::Close(err) => {
						// TODO: We need to close the channel here, but for that to be safe we have
						// to do all channel closure inside the channel_state lock which is a
						// somewhat-larger refactor, so we leave that for later.
						APIError::ChannelUnavailable { err }
					},
					ChannelError::Ignore(err) => APIError::ChannelUnavailable { err },
				}
			)?
		};
		match res {
			Some((update_add, commitment_signed, chan_monitor)) => {
				if let Err(e) = self.monitor.add_update_monitor(chan_monitor.get_funding_txo().unwrap(), chan_monitor) {
					self.handle_monitor_update_fail(channel_state, &id, e, RAACommitmentOrder::CommitmentFirst);
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

		Ok(())
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

		let (chan, msg, chan_monitor) = {
			let (res, chan) = {
				let mut channel_state = self.channel_state.lock().unwrap();
				match channel_state.by_id.remove(temporary_channel_id) {
					Some(mut chan) => {
						(chan.get_outbound_funding_created(funding_txo)
							.map_err(|e| MsgHandleErrInternal::from_chan_maybe_close(e, chan.channel_id()))
						, chan)
					},
					None => return
				}
			};
			match handle_error!(self, res, chan.get_their_node_id()) {
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
		if let Err(_e) = self.monitor.add_update_monitor(chan_monitor.get_funding_txo().unwrap(), chan_monitor) {
			unimplemented!();
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
		let msghash = Message::from_slice(&Sha256dHash::from_data(&announcement.encode()[..])[..]).unwrap();
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
	/// Should only really ever be called in response to an PendingHTLCsForwardable event.
	/// Will likely generate further events.
	pub fn process_pending_htlc_forwards(&self) {
		let _ = self.total_consistency_lock.read().unwrap();

		let mut new_events = Vec::new();
		let mut failed_forwards = Vec::new();
		{
			let mut channel_state_lock = self.channel_state.lock().unwrap();
			let channel_state = channel_state_lock.borrow_parts();

			if cfg!(not(feature = "fuzztarget")) && Instant::now() < *channel_state.next_forward {
				return;
			}

			for (short_chan_id, mut pending_forwards) in channel_state.forward_htlcs.drain() {
				if short_chan_id != 0 {
					let forward_chan_id = match channel_state.short_to_id.get(&short_chan_id) {
						Some(chan_id) => chan_id.clone(),
						None => {
							failed_forwards.reserve(pending_forwards.len());
							for HTLCForwardInfo { prev_short_channel_id, prev_htlc_id, forward_info } in pending_forwards.drain(..) {
								let htlc_source = HTLCSource::PreviousHopData(HTLCPreviousHopData {
									short_channel_id: prev_short_channel_id,
									htlc_id: prev_htlc_id,
									incoming_packet_shared_secret: forward_info.incoming_shared_secret,
								});
								failed_forwards.push((htlc_source, forward_info.payment_hash, 0x4000 | 10, None));
							}
							continue;
						}
					};
					let forward_chan = &mut channel_state.by_id.get_mut(&forward_chan_id).unwrap();

					let mut add_htlc_msgs = Vec::new();
					for HTLCForwardInfo { prev_short_channel_id, prev_htlc_id, forward_info } in pending_forwards.drain(..) {
						let htlc_source = HTLCSource::PreviousHopData(HTLCPreviousHopData {
							short_channel_id: prev_short_channel_id,
							htlc_id: prev_htlc_id,
							incoming_packet_shared_secret: forward_info.incoming_shared_secret,
						});
						match forward_chan.send_htlc(forward_info.amt_to_forward, forward_info.payment_hash, forward_info.outgoing_cltv_value, htlc_source.clone(), forward_info.onion_packet.unwrap()) {
							Err(_e) => {
								let chan_update = self.get_channel_update(forward_chan).unwrap();
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
					}

					if !add_htlc_msgs.is_empty() {
						let (commitment_msg, monitor) = match forward_chan.send_commitment() {
							Ok(res) => res,
							Err(e) => {
								if let ChannelError::Ignore(_) = e {
									panic!("Stated return value requirements in send_commitment() were not met");
								}
								//TODO: Handle...this is bad!
								continue;
							},
						};
						if let Err(_e) = self.monitor.add_update_monitor(monitor.get_funding_txo().unwrap(), monitor) {
							unimplemented!();// but def dont push the event...
						}
						channel_state.pending_msg_events.push(events::MessageSendEvent::UpdateHTLCs {
							node_id: forward_chan.get_their_node_id(),
							updates: msgs::CommitmentUpdate {
								update_add_htlcs: add_htlc_msgs,
								update_fulfill_htlcs: Vec::new(),
								update_fail_htlcs: Vec::new(),
								update_fail_malformed_htlcs: Vec::new(),
								update_fee: None,
								commitment_signed: commitment_msg,
							},
						});
					}
				} else {
					for HTLCForwardInfo { prev_short_channel_id, prev_htlc_id, forward_info } in pending_forwards.drain(..) {
						let prev_hop_data = HTLCPreviousHopData {
							short_channel_id: prev_short_channel_id,
							htlc_id: prev_htlc_id,
							incoming_packet_shared_secret: forward_info.incoming_shared_secret,
						};
						match channel_state.claimable_htlcs.entry(forward_info.payment_hash) {
							hash_map::Entry::Occupied(mut entry) => entry.get_mut().push(prev_hop_data),
							hash_map::Entry::Vacant(entry) => { entry.insert(vec![prev_hop_data]); },
						};
						new_events.push(events::Event::PaymentReceived {
							payment_hash: forward_info.payment_hash,
							amt: forward_info.amt_to_forward,
						});
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

		if new_events.is_empty() { return }
		let mut events = self.pending_events.lock().unwrap();
		events.append(&mut new_events);
	}

	/// Indicates that the preimage for payment_hash is unknown or the received amount is incorrect after a PaymentReceived event.
	pub fn fail_htlc_backwards(&self, payment_hash: &[u8; 32], reason: PaymentFailReason) -> bool {
		let _ = self.total_consistency_lock.read().unwrap();

		let mut channel_state = Some(self.channel_state.lock().unwrap());
		let removed_source = channel_state.as_mut().unwrap().claimable_htlcs.remove(payment_hash);
		if let Some(mut sources) = removed_source {
			for htlc_with_hash in sources.drain(..) {
				if channel_state.is_none() { channel_state = Some(self.channel_state.lock().unwrap()); }
				self.fail_htlc_backwards_internal(channel_state.take().unwrap(), HTLCSource::PreviousHopData(htlc_with_hash), payment_hash, HTLCFailReason::Reason { failure_code: if reason == PaymentFailReason::PreimageUnknown {0x4000 | 15} else {0x4000 | 16}, data: Vec::new() });
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
	fn fail_htlc_backwards_internal(&self, mut channel_state_lock: MutexGuard<ChannelHolder>, source: HTLCSource, payment_hash: &[u8; 32], onion_error: HTLCFailReason) {
		match source {
			HTLCSource::OutboundRoute { .. } => {
				mem::drop(channel_state_lock);
				if let &HTLCFailReason::ErrorPacket { ref err } = &onion_error {
					let (channel_update, payment_retryable) = self.process_onion_failure(&source, err.data.clone());
					if let Some(update) = channel_update {
						self.channel_state.lock().unwrap().pending_msg_events.push(
							events::MessageSendEvent::PaymentFailureNetworkUpdate {
								update,
							}
						);
					}
					self.pending_events.lock().unwrap().push(events::Event::PaymentFailed {
						payment_hash: payment_hash.clone(),
						rejected_by_dest: !payment_retryable,
					});
				} else {
					panic!("should have onion error packet here");
				}
			},
			HTLCSource::PreviousHopData(HTLCPreviousHopData { short_channel_id, htlc_id, incoming_packet_shared_secret }) => {
				let err_packet = match onion_error {
					HTLCFailReason::Reason { failure_code, data } => {
						let packet = ChannelManager::build_failure_packet(&incoming_packet_shared_secret, failure_code, &data[..]).encode();
						ChannelManager::encrypt_failure_packet(&incoming_packet_shared_secret, &packet)
					},
					HTLCFailReason::ErrorPacket { err } => {
						ChannelManager::encrypt_failure_packet(&incoming_packet_shared_secret, &err.data)
					}
				};

				let channel_state = channel_state_lock.borrow_parts();

				let chan_id = match channel_state.short_to_id.get(&short_channel_id) {
					Some(chan_id) => chan_id.clone(),
					None => return
				};

				let chan = channel_state.by_id.get_mut(&chan_id).unwrap();
				match chan.get_update_fail_htlc_and_commit(htlc_id, err_packet) {
					Ok(Some((msg, commitment_msg, chan_monitor))) => {
						if let Err(_e) = self.monitor.add_update_monitor(chan_monitor.get_funding_txo().unwrap(), chan_monitor) {
							unimplemented!();
						}
						channel_state.pending_msg_events.push(events::MessageSendEvent::UpdateHTLCs {
							node_id: chan.get_their_node_id(),
							updates: msgs::CommitmentUpdate {
								update_add_htlcs: Vec::new(),
								update_fulfill_htlcs: Vec::new(),
								update_fail_htlcs: vec![msg],
								update_fail_malformed_htlcs: Vec::new(),
								update_fee: None,
								commitment_signed: commitment_msg,
							},
						});
					},
					Ok(None) => {},
					Err(_e) => {
						//TODO: Do something with e?
						return;
					},
				}
			},
		}
	}

	/// Provides a payment preimage in response to a PaymentReceived event, returning true and
	/// generating message events for the net layer to claim the payment, if possible. Thus, you
	/// should probably kick the net layer to go send messages if this returns true!
	///
	/// May panic if called except in response to a PaymentReceived event.
	pub fn claim_funds(&self, payment_preimage: [u8; 32]) -> bool {
		let mut sha = Sha256::new();
		sha.input(&payment_preimage);
		let mut payment_hash = [0; 32];
		sha.result(&mut payment_hash);

		let _ = self.total_consistency_lock.read().unwrap();

		let mut channel_state = Some(self.channel_state.lock().unwrap());
		let removed_source = channel_state.as_mut().unwrap().claimable_htlcs.remove(&payment_hash);
		if let Some(mut sources) = removed_source {
			for htlc_with_hash in sources.drain(..) {
				if channel_state.is_none() { channel_state = Some(self.channel_state.lock().unwrap()); }
				self.claim_funds_internal(channel_state.take().unwrap(), HTLCSource::PreviousHopData(htlc_with_hash), payment_preimage);
			}
			true
		} else { false }
	}
	fn claim_funds_internal(&self, mut channel_state_lock: MutexGuard<ChannelHolder>, source: HTLCSource, payment_preimage: [u8; 32]) {
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
						// why its missing.
						return
					}
				};

				let chan = channel_state.by_id.get_mut(&chan_id).unwrap();
				match chan.get_update_fulfill_htlc_and_commit(htlc_id, payment_preimage) {
					Ok((msgs, monitor_option)) => {
						if let Some(chan_monitor) = monitor_option {
							if let Err(_e) = self.monitor.add_update_monitor(chan_monitor.get_funding_txo().unwrap(), chan_monitor) {
								unimplemented!();// but def dont push the event...
							}
						}
						if let Some((msg, commitment_signed)) = msgs {
							channel_state.pending_msg_events.push(events::MessageSendEvent::UpdateHTLCs {
								node_id: chan.get_their_node_id(),
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
						let (raa, commitment_update, order, pending_forwards, mut pending_failures) = channel.monitor_updating_restored();
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
						true
					}
				} else { true }
			});
		}

		for failure in htlc_failures.drain(..) {
			self.fail_htlc_backwards_internal(self.channel_state.lock().unwrap(), failure.0, &failure.1, failure.2);
		}
		self.forward_htlcs(&mut htlc_forwards[..]);

		for res in close_results.drain(..) {
			self.finish_force_close_channel(res);
		}
	}

	fn internal_open_channel(&self, their_node_id: &PublicKey, msg: &msgs::OpenChannel) -> Result<(), MsgHandleErrInternal> {
		if msg.chain_hash != self.genesis_hash {
			return Err(MsgHandleErrInternal::send_err_msg_no_close("Unknown genesis block hash", msg.temporary_channel_id.clone()));
		}

		let channel = Channel::new_from_req(&*self.fee_estimator, &self.keys_manager, their_node_id.clone(), msg, 0, Arc::clone(&self.logger), &self.default_configuration)
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

	fn internal_accept_channel(&self, their_node_id: &PublicKey, msg: &msgs::AcceptChannel) -> Result<(), MsgHandleErrInternal> {
		let (value, output_script, user_id) = {
			let mut channel_state = self.channel_state.lock().unwrap();
			match channel_state.by_id.get_mut(&msg.temporary_channel_id) {
				Some(chan) => {
					if chan.get_their_node_id() != *their_node_id {
						//TODO: see issue #153, need a consistent behavior on obnoxious behavior from random node
						return Err(MsgHandleErrInternal::send_err_msg_no_close("Got a message for a channel from the wrong node!", msg.temporary_channel_id));
					}
					chan.accept_channel(&msg, &self.default_configuration)
						.map_err(|e| MsgHandleErrInternal::from_chan_maybe_close(e, msg.temporary_channel_id))?;
					(chan.get_value_satoshis(), chan.get_funding_redeemscript().to_v0_p2wsh(), chan.get_user_id())
				},
				//TODO: same as above
				None => return Err(MsgHandleErrInternal::send_err_msg_no_close("Failed to find corresponding channel", msg.temporary_channel_id))
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
		let (chan, funding_msg, monitor_update) = {
			let mut channel_state = self.channel_state.lock().unwrap();
			match channel_state.by_id.entry(msg.temporary_channel_id.clone()) {
				hash_map::Entry::Occupied(mut chan) => {
					if chan.get().get_their_node_id() != *their_node_id {
						//TODO: here and below MsgHandleErrInternal, #153 case
						return Err(MsgHandleErrInternal::send_err_msg_no_close("Got a message for a channel from the wrong node!", msg.temporary_channel_id));
					}
					match chan.get_mut().funding_created(msg) {
						Ok((funding_msg, monitor_update)) => {
							(chan.remove(), funding_msg, monitor_update)
						},
						Err(e) => {
							return Err(e).map_err(|e| MsgHandleErrInternal::from_chan_maybe_close(e, msg.temporary_channel_id))
						}
					}
				},
				hash_map::Entry::Vacant(_) => return Err(MsgHandleErrInternal::send_err_msg_no_close("Failed to find corresponding channel", msg.temporary_channel_id))
			}
		};
		// Because we have exclusive ownership of the channel here we can release the channel_state
		// lock before add_update_monitor
		if let Err(_e) = self.monitor.add_update_monitor(monitor_update.get_funding_txo().unwrap(), monitor_update) {
			unimplemented!();
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
			let mut channel_state = self.channel_state.lock().unwrap();
			match channel_state.by_id.get_mut(&msg.channel_id) {
				Some(chan) => {
					if chan.get_their_node_id() != *their_node_id {
						//TODO: here and below MsgHandleErrInternal, #153 case
						return Err(MsgHandleErrInternal::send_err_msg_no_close("Got a message for a channel from the wrong node!", msg.channel_id));
					}
					let chan_monitor = chan.funding_signed(&msg).map_err(|e| MsgHandleErrInternal::from_chan_maybe_close(e, msg.channel_id))?;
					if let Err(_e) = self.monitor.add_update_monitor(chan_monitor.get_funding_txo().unwrap(), chan_monitor) {
						unimplemented!();
					}
					(chan.get_funding_txo().unwrap(), chan.get_user_id())
				},
				None => return Err(MsgHandleErrInternal::send_err_msg_no_close("Failed to find corresponding channel", msg.channel_id))
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
		match channel_state.by_id.get_mut(&msg.channel_id) {
			Some(chan) => {
				if chan.get_their_node_id() != *their_node_id {
					//TODO: here and below MsgHandleErrInternal, #153 case
					return Err(MsgHandleErrInternal::send_err_msg_no_close("Got a message for a channel from the wrong node!", msg.channel_id));
				}
				chan.funding_locked(&msg)
					.map_err(|e| MsgHandleErrInternal::from_chan_maybe_close(e, msg.channel_id))?;
				if let Some(announcement_sigs) = self.get_announcement_sigs(chan) {
					channel_state.pending_msg_events.push(events::MessageSendEvent::SendAnnouncementSignatures {
						node_id: their_node_id.clone(),
						msg: announcement_sigs,
					});
				}
				Ok(())
			},
			None => Err(MsgHandleErrInternal::send_err_msg_no_close("Failed to find corresponding channel", msg.channel_id))
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
					let (shutdown, closing_signed, dropped_htlcs) = chan_entry.get_mut().shutdown(&*self.fee_estimator, &msg).map_err(|e| MsgHandleErrInternal::from_chan_maybe_close(e, msg.channel_id))?;
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
			// unknown_next_peer...I dunno who that is anymore....
			self.fail_htlc_backwards_internal(self.channel_state.lock().unwrap(), htlc_source.0, &htlc_source.1, HTLCFailReason::Reason { failure_code: 0x4000 | 10, data: Vec::new() });
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
					let (closing_signed, tx) = chan_entry.get_mut().closing_signed(&*self.fee_estimator, &msg).map_err(|e| MsgHandleErrInternal::from_maybe_close(e))?;
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
		//encrypted with the same key. Its not immediately obvious how to usefully exploit that,
		//but we should prevent it anyway.

		let (mut pending_forward_info, mut channel_state_lock) = self.decode_update_add_htlc_onion(msg);
		let channel_state = channel_state_lock.borrow_parts();

		match channel_state.by_id.get_mut(&msg.channel_id) {
			Some(chan) => {
				if chan.get_their_node_id() != *their_node_id {
					//TODO: here MsgHandleErrInternal, #153 case
					return Err(MsgHandleErrInternal::send_err_msg_no_close("Got a message for a channel from the wrong node!", msg.channel_id));
				}
				if !chan.is_usable() {
					// If the update_add is completely bogus, the call will Err and we will close,
					// but if we've sent a shutdown and they haven't acknowledged it yet, we just
					// want to reject the new HTLC and fail it backwards instead of forwarding.
					if let PendingHTLCStatus::Forward(PendingForwardHTLCInfo { incoming_shared_secret, .. }) = pending_forward_info {
						let chan_update = self.get_channel_update(chan);
						pending_forward_info = PendingHTLCStatus::Fail(HTLCFailureMsg::Relay(msgs::UpdateFailHTLC {
							channel_id: msg.channel_id,
							htlc_id: msg.htlc_id,
							reason: if let Ok(update) = chan_update {
								ChannelManager::build_first_hop_failure_packet(&incoming_shared_secret, 0x1000|20, &update.encode_with_len()[..])
							} else {
								// This can only happen if the channel isn't in the fully-funded
								// state yet, implying our counterparty is trying to route payments
								// over the channel back to themselves (cause no one else should
								// know the short_id is a lightning channel yet). We should have no
								// problem just calling this unknown_next_peer
								ChannelManager::build_first_hop_failure_packet(&incoming_shared_secret, 0x4000|10, &[])
							},
						}));
					}
				}
				chan.update_add_htlc(&msg, pending_forward_info).map_err(|e| MsgHandleErrInternal::from_maybe_close(e))
			},
			None => return Err(MsgHandleErrInternal::send_err_msg_no_close("Failed to find corresponding channel", msg.channel_id))
		}
	}

	fn internal_update_fulfill_htlc(&self, their_node_id: &PublicKey, msg: &msgs::UpdateFulfillHTLC) -> Result<(), MsgHandleErrInternal> {
		let mut channel_state = self.channel_state.lock().unwrap();
		let htlc_source = match channel_state.by_id.get_mut(&msg.channel_id) {
			Some(chan) => {
				if chan.get_their_node_id() != *their_node_id {
					//TODO: here and below MsgHandleErrInternal, #153 case
					return Err(MsgHandleErrInternal::send_err_msg_no_close("Got a message for a channel from the wrong node!", msg.channel_id));
				}
				chan.update_fulfill_htlc(&msg)
					.map_err(|e| MsgHandleErrInternal::from_chan_maybe_close(e, msg.channel_id))?.clone()
			},
			None => return Err(MsgHandleErrInternal::send_err_msg_no_close("Failed to find corresponding channel", msg.channel_id))
		};
		self.claim_funds_internal(channel_state, htlc_source, msg.payment_preimage.clone());
		Ok(())
	}

	// Process failure we got back from upstream on a payment we sent. Returns update and a boolean
	// indicating that the payment itself failed
	fn process_onion_failure(&self, htlc_source: &HTLCSource, mut packet_decrypted: Vec<u8>) -> (Option<msgs::HTLCFailChannelUpdate>, bool) {
		if let &HTLCSource::OutboundRoute { ref route, ref session_priv, ref first_hop_htlc_msat } = htlc_source {
			macro_rules! onion_failure_log {
				( $error_code_textual: expr, $error_code: expr, $reported_name: expr, $reported_value: expr ) => {
					log_trace!(self, "{}({:#x}) {}({})", $error_code_textual, $error_code, $reported_name, $reported_value);
				};
				( $error_code_textual: expr, $error_code: expr ) => {
					log_trace!(self, "{}({})", $error_code_textual, $error_code);
				};
			}

			const BADONION: u16 = 0x8000;
			const PERM: u16 = 0x4000;
			const UPDATE: u16 = 0x1000;

			let mut res = None;
			let mut htlc_msat = *first_hop_htlc_msat;

			// Handle packed channel/node updates for passing back for the route handler
			Self::construct_onion_keys_callback(&self.secp_ctx, route, session_priv, |shared_secret, _, _, route_hop| {
				if res.is_some() { return; }

				let incoming_htlc_msat = htlc_msat;
				let amt_to_forward = htlc_msat - route_hop.fee_msat;
				htlc_msat = amt_to_forward;

				let ammag = ChannelManager::gen_ammag_from_shared_secret(&shared_secret[..]);

				let mut decryption_tmp = Vec::with_capacity(packet_decrypted.len());
				decryption_tmp.resize(packet_decrypted.len(), 0);
				let mut chacha = ChaCha20::new(&ammag, &[0u8; 8]);
				chacha.process(&packet_decrypted, &mut decryption_tmp[..]);
				packet_decrypted = decryption_tmp;

				let is_from_final_node = route.hops.last().unwrap().pubkey == route_hop.pubkey;

				if let Ok(err_packet) = msgs::DecodedOnionErrorPacket::read(&mut Cursor::new(&packet_decrypted)) {
					let um = ChannelManager::gen_um_from_shared_secret(&shared_secret[..]);
					let mut hmac = Hmac::new(Sha256::new(), &um);
					hmac.input(&err_packet.encode()[32..]);
					let mut calc_tag = [0u8; 32];
					hmac.raw_result(&mut calc_tag);

					if crypto::util::fixed_time_eq(&calc_tag, &err_packet.hmac) {
						if err_packet.failuremsg.len() < 2 {
							// Useless packet that we can't use but it passed HMAC, so it
							// definitely came from the peer in question
							res = Some((None, !is_from_final_node));
						} else {
							let error_code = byte_utils::slice_to_be16(&err_packet.failuremsg[0..2]);

							match error_code & 0xff {
								1|2|3 => {
									// either from an intermediate or final node
									//   invalid_realm(PERM|1),
									//   temporary_node_failure(NODE|2)
									//   permanent_node_failure(PERM|NODE|2)
									//   required_node_feature_mssing(PERM|NODE|3)
									res = Some((Some(msgs::HTLCFailChannelUpdate::NodeFailure {
										node_id: route_hop.pubkey,
										is_permanent: error_code & PERM == PERM,
									}), !(error_code & PERM == PERM && is_from_final_node)));
									// node returning invalid_realm is removed from network_map,
									// although NODE flag is not set, TODO: or remove channel only?
									// retry payment when removed node is not a final node
									return;
								},
								_ => {}
							}

							if is_from_final_node {
								let payment_retryable = match error_code {
									c if c == PERM|15 => false, // unknown_payment_hash
									c if c == PERM|16 => false, // incorrect_payment_amount
									17 => true, // final_expiry_too_soon
									18 if err_packet.failuremsg.len() == 6 => { // final_incorrect_cltv_expiry
										let _reported_cltv_expiry = byte_utils::slice_to_be32(&err_packet.failuremsg[2..2+4]);
										true
									},
									19 if err_packet.failuremsg.len() == 10 => { // final_incorrect_htlc_amount
										let _reported_incoming_htlc_msat = byte_utils::slice_to_be64(&err_packet.failuremsg[2..2+8]);
										true
									},
									_ => {
										// A final node has sent us either an invalid code or an error_code that
										// MUST be sent from the processing node, or the formmat of failuremsg
										// does not coform to the spec.
										// Remove it from the network map and don't may retry payment
										res = Some((Some(msgs::HTLCFailChannelUpdate::NodeFailure {
											node_id: route_hop.pubkey,
											is_permanent: true,
										}), false));
										return;
									}
								};
								res = Some((None, payment_retryable));
								return;
							}

							// now, error_code should be only from the intermediate nodes
							match error_code {
								_c if error_code & PERM == PERM => {
									res = Some((Some(msgs::HTLCFailChannelUpdate::ChannelClosed {
										short_channel_id: route_hop.short_channel_id,
										is_permanent: true,
									}), false));
								},
								_c if error_code & UPDATE == UPDATE => {
									let offset = match error_code {
										c if c == UPDATE|7  => 0, // temporary_channel_failure
										c if c == UPDATE|11 => 8, // amount_below_minimum
										c if c == UPDATE|12 => 8, // fee_insufficient
										c if c == UPDATE|13 => 4, // incorrect_cltv_expiry
										c if c == UPDATE|14 => 0, // expiry_too_soon
										c if c == UPDATE|20 => 2, // channel_disabled
										_ =>  {
											// node sending unknown code
											res = Some((Some(msgs::HTLCFailChannelUpdate::NodeFailure {
												node_id: route_hop.pubkey,
												is_permanent: true,
											}), false));
											return;
										}
									};

									if err_packet.failuremsg.len() >= offset + 2 {
										let update_len = byte_utils::slice_to_be16(&err_packet.failuremsg[offset+2..offset+4]) as usize;
										if err_packet.failuremsg.len() >= offset + 4 + update_len {
											if let Ok(chan_update) = msgs::ChannelUpdate::read(&mut Cursor::new(&err_packet.failuremsg[offset + 4..offset + 4 + update_len])) {
												// if channel_update should NOT have caused the failure:
												// MAY treat the channel_update as invalid.
												let is_chan_update_invalid = match error_code {
													c if c == UPDATE|7 => { // temporary_channel_failure
														false
													},
													c if c == UPDATE|11 => { // amount_below_minimum
														let reported_htlc_msat = byte_utils::slice_to_be64(&err_packet.failuremsg[2..2+8]);
														onion_failure_log!("amount_below_minimum", UPDATE|11, "htlc_msat", reported_htlc_msat);
														incoming_htlc_msat > chan_update.contents.htlc_minimum_msat
													},
													c if c == UPDATE|12 => { // fee_insufficient
														let reported_htlc_msat = byte_utils::slice_to_be64(&err_packet.failuremsg[2..2+8]);
														let new_fee =  amt_to_forward.checked_mul(chan_update.contents.fee_proportional_millionths as u64).and_then(|prop_fee| { (prop_fee / 1000000).checked_add(chan_update.contents.fee_base_msat as u64) });
														onion_failure_log!("fee_insufficient", UPDATE|12, "htlc_msat", reported_htlc_msat);
														new_fee.is_none() || incoming_htlc_msat >= new_fee.unwrap() && incoming_htlc_msat >= amt_to_forward + new_fee.unwrap()
													}
													c if c == UPDATE|13 => { // incorrect_cltv_expiry
														let reported_cltv_expiry = byte_utils::slice_to_be32(&err_packet.failuremsg[2..2+4]);
														onion_failure_log!("incorrect_cltv_expiry", UPDATE|13, "cltv_expiry", reported_cltv_expiry);
														route_hop.cltv_expiry_delta as u16 >= chan_update.contents.cltv_expiry_delta
													},
													c if c == UPDATE|20 => { // channel_disabled
														let reported_flags = byte_utils::slice_to_be16(&err_packet.failuremsg[2..2+2]);
														onion_failure_log!("channel_disabled", UPDATE|20, "flags", reported_flags);
														chan_update.contents.flags & 0x01 == 0x01
													},
													c if c == UPDATE|21 => true, // expiry_too_far
													_ => { unreachable!(); },
												};

												let msg = if is_chan_update_invalid { None } else {
													Some(msgs::HTLCFailChannelUpdate::ChannelUpdateMessage {
														msg: chan_update,
													})
												};
												res = Some((msg, true));
												return;
											}
										}
									}
								},
								_c if error_code & BADONION == BADONION => {
									//TODO
								},
								14 => { // expiry_too_soon
									res = Some((None, true));
									return;
								}
								_ => {
									// node sending unknown code
									res = Some((Some(msgs::HTLCFailChannelUpdate::NodeFailure {
										node_id: route_hop.pubkey,
										is_permanent: true,
									}), false));
									return;
								}
							}
						}
					}
				}
			}).expect("Route that we sent via spontaneously grew invalid keys in the middle of it?");
			res.unwrap_or((None, true))
		} else { ((None, true)) }
	}

	fn internal_update_fail_htlc(&self, their_node_id: &PublicKey, msg: &msgs::UpdateFailHTLC) -> Result<(), MsgHandleErrInternal> {
		let mut channel_state = self.channel_state.lock().unwrap();
		match channel_state.by_id.get_mut(&msg.channel_id) {
			Some(chan) => {
				if chan.get_their_node_id() != *their_node_id {
					//TODO: here and below MsgHandleErrInternal, #153 case
					return Err(MsgHandleErrInternal::send_err_msg_no_close("Got a message for a channel from the wrong node!", msg.channel_id));
				}
				chan.update_fail_htlc(&msg, HTLCFailReason::ErrorPacket { err: msg.reason.clone() })
					.map_err(|e| MsgHandleErrInternal::from_chan_maybe_close(e, msg.channel_id))
			},
			None => return Err(MsgHandleErrInternal::send_err_msg_no_close("Failed to find corresponding channel", msg.channel_id))
		}?;
		Ok(())
	}

	fn internal_update_fail_malformed_htlc(&self, their_node_id: &PublicKey, msg: &msgs::UpdateFailMalformedHTLC) -> Result<(), MsgHandleErrInternal> {
		let mut channel_state = self.channel_state.lock().unwrap();
		match channel_state.by_id.get_mut(&msg.channel_id) {
			Some(chan) => {
				if chan.get_their_node_id() != *their_node_id {
					//TODO: here and below MsgHandleErrInternal, #153 case
					return Err(MsgHandleErrInternal::send_err_msg_no_close("Got a message for a channel from the wrong node!", msg.channel_id));
				}
				if (msg.failure_code & 0x8000) == 0 {
					return Err(MsgHandleErrInternal::send_err_msg_close_chan("Got update_fail_malformed_htlc with BADONION not set", msg.channel_id));
				}
				chan.update_fail_malformed_htlc(&msg, HTLCFailReason::Reason { failure_code: msg.failure_code, data: Vec::new() })
					.map_err(|e| MsgHandleErrInternal::from_chan_maybe_close(e, msg.channel_id))?;
				Ok(())
			},
			None => return Err(MsgHandleErrInternal::send_err_msg_no_close("Failed to find corresponding channel", msg.channel_id))
		}
	}

	fn internal_commitment_signed(&self, their_node_id: &PublicKey, msg: &msgs::CommitmentSigned) -> Result<(), MsgHandleErrInternal> {
		let mut channel_state_lock = self.channel_state.lock().unwrap();
		let channel_state = channel_state_lock.borrow_parts();
		match channel_state.by_id.get_mut(&msg.channel_id) {
			Some(chan) => {
				if chan.get_their_node_id() != *their_node_id {
					//TODO: here and below MsgHandleErrInternal, #153 case
					return Err(MsgHandleErrInternal::send_err_msg_no_close("Got a message for a channel from the wrong node!", msg.channel_id));
				}
				let (revoke_and_ack, commitment_signed, closing_signed, chan_monitor) = chan.commitment_signed(&msg, &*self.fee_estimator)
					.map_err(|e| MsgHandleErrInternal::from_chan_maybe_close(e, msg.channel_id))?;
				if let Err(_e) = self.monitor.add_update_monitor(chan_monitor.get_funding_txo().unwrap(), chan_monitor) {
					unimplemented!();
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
			None => Err(MsgHandleErrInternal::send_err_msg_no_close("Failed to find corresponding channel", msg.channel_id))
		}
	}

	#[inline]
	fn forward_htlcs(&self, per_source_pending_forwards: &mut [(u64, Vec<(PendingForwardHTLCInfo, u64)>)]) {
		for &mut (prev_short_channel_id, ref mut pending_forwards) in per_source_pending_forwards {
			let mut forward_event = None;
			if !pending_forwards.is_empty() {
				let mut channel_state = self.channel_state.lock().unwrap();
				if channel_state.forward_htlcs.is_empty() {
					forward_event = Some(Instant::now() + Duration::from_millis(((rng::rand_f32() * 4.0 + 1.0) * MIN_HTLC_RELAY_HOLDING_CELL_MILLIS as f32) as u64));
					channel_state.next_forward = forward_event.unwrap();
				}
				for (forward_info, prev_htlc_id) in pending_forwards.drain(..) {
					match channel_state.forward_htlcs.entry(forward_info.short_channel_id) {
						hash_map::Entry::Occupied(mut entry) => {
							entry.get_mut().push(HTLCForwardInfo { prev_short_channel_id, prev_htlc_id, forward_info });
						},
						hash_map::Entry::Vacant(entry) => {
							entry.insert(vec!(HTLCForwardInfo { prev_short_channel_id, prev_htlc_id, forward_info }));
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
			match channel_state.by_id.get_mut(&msg.channel_id) {
				Some(chan) => {
					if chan.get_their_node_id() != *their_node_id {
						//TODO: here and below MsgHandleErrInternal, #153 case
						return Err(MsgHandleErrInternal::send_err_msg_no_close("Got a message for a channel from the wrong node!", msg.channel_id));
					}
					let (commitment_update, pending_forwards, pending_failures, closing_signed, chan_monitor) = chan.revoke_and_ack(&msg, &*self.fee_estimator)
							.map_err(|e| MsgHandleErrInternal::from_chan_maybe_close(e, msg.channel_id))?;
					if let Err(_e) = self.monitor.add_update_monitor(chan_monitor.get_funding_txo().unwrap(), chan_monitor) {
						unimplemented!();
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
					(pending_forwards, pending_failures, chan.get_short_channel_id().expect("RAA should only work on a short-id-available channel"))
				},
				None => return Err(MsgHandleErrInternal::send_err_msg_no_close("Failed to find corresponding channel", msg.channel_id))
			}
		};
		for failure in pending_failures.drain(..) {
			self.fail_htlc_backwards_internal(self.channel_state.lock().unwrap(), failure.0, &failure.1, failure.2);
		}
		self.forward_htlcs(&mut [(short_channel_id, pending_forwards)]);

		Ok(())
	}

	fn internal_update_fee(&self, their_node_id: &PublicKey, msg: &msgs::UpdateFee) -> Result<(), MsgHandleErrInternal> {
		let mut channel_state = self.channel_state.lock().unwrap();
		match channel_state.by_id.get_mut(&msg.channel_id) {
			Some(chan) => {
				if chan.get_their_node_id() != *their_node_id {
					//TODO: here and below MsgHandleErrInternal, #153 case
					return Err(MsgHandleErrInternal::send_err_msg_no_close("Got a message for a channel from the wrong node!", msg.channel_id));
				}
				chan.update_fee(&*self.fee_estimator, &msg).map_err(|e| MsgHandleErrInternal::from_chan_maybe_close(e, msg.channel_id))
			},
			None => return Err(MsgHandleErrInternal::send_err_msg_no_close("Failed to find corresponding channel", msg.channel_id))
		}
	}

	fn internal_announcement_signatures(&self, their_node_id: &PublicKey, msg: &msgs::AnnouncementSignatures) -> Result<(), MsgHandleErrInternal> {
		let mut channel_state_lock = self.channel_state.lock().unwrap();
		let channel_state = channel_state_lock.borrow_parts();

		match channel_state.by_id.get_mut(&msg.channel_id) {
			Some(chan) => {
				if chan.get_their_node_id() != *their_node_id {
					return Err(MsgHandleErrInternal::send_err_msg_no_close("Got a message for a channel from the wrong node!", msg.channel_id));
				}
				if !chan.is_usable() {
					return Err(MsgHandleErrInternal::from_no_close(HandleError{err: "Got an announcement_signatures before we were ready for it", action: Some(msgs::ErrorAction::IgnoreError)}));
				}

				let our_node_id = self.get_our_node_id();
				let (announcement, our_bitcoin_sig) = chan.get_channel_announcement(our_node_id.clone(), self.genesis_hash.clone())
					.map_err(|e| MsgHandleErrInternal::from_chan_maybe_close(e, msg.channel_id))?;

				let were_node_one = announcement.node_id_1 == our_node_id;
				let msghash = Message::from_slice(&Sha256dHash::from_data(&announcement.encode()[..])[..]).unwrap();
				let bad_sig_action = MsgHandleErrInternal::send_err_msg_close_chan("Bad announcement_signatures node_signature", msg.channel_id);
				secp_call!(self.secp_ctx.verify(&msghash, &msg.node_signature, if were_node_one { &announcement.node_id_2 } else { &announcement.node_id_1 }), bad_sig_action);
				secp_call!(self.secp_ctx.verify(&msghash, &msg.bitcoin_signature, if were_node_one { &announcement.bitcoin_key_2 } else { &announcement.bitcoin_key_1 }), bad_sig_action);

				let our_node_sig = self.secp_ctx.sign(&msghash, &self.our_network_key);

				channel_state.pending_msg_events.push(events::MessageSendEvent::BroadcastChannelAnnouncement {
					msg: msgs::ChannelAnnouncement {
						node_signature_1: if were_node_one { our_node_sig } else { msg.node_signature },
						node_signature_2: if were_node_one { msg.node_signature } else { our_node_sig },
						bitcoin_signature_1: if were_node_one { our_bitcoin_sig } else { msg.bitcoin_signature },
						bitcoin_signature_2: if were_node_one { msg.bitcoin_signature } else { our_bitcoin_sig },
						contents: announcement,
					},
					update_msg: self.get_channel_update(chan).unwrap(), // can only fail if we're not in a ready state
				});
			},
			None => return Err(MsgHandleErrInternal::send_err_msg_no_close("Failed to find corresponding channel", msg.channel_id))
		}
		Ok(())
	}

	fn internal_channel_reestablish(&self, their_node_id: &PublicKey, msg: &msgs::ChannelReestablish) -> Result<(), MsgHandleErrInternal> {
		let mut channel_state_lock = self.channel_state.lock().unwrap();
		let channel_state = channel_state_lock.borrow_parts();

		match channel_state.by_id.get_mut(&msg.channel_id) {
			Some(chan) => {
				if chan.get_their_node_id() != *their_node_id {
					return Err(MsgHandleErrInternal::send_err_msg_no_close("Got a message for a channel from the wrong node!", msg.channel_id));
				}
				let (funding_locked, revoke_and_ack, commitment_update, channel_monitor, order, shutdown) = chan.channel_reestablish(msg)
					.map_err(|e| MsgHandleErrInternal::from_chan_maybe_close(e, msg.channel_id))?;
				if let Some(monitor) = channel_monitor {
					if let Err(_e) = self.monitor.add_update_monitor(monitor.get_funding_txo().unwrap(), monitor) {
						unimplemented!();
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
			None => Err(MsgHandleErrInternal::send_err_msg_no_close("Failed to find corresponding channel", msg.channel_id))
		}
	}

	/// Begin Update fee process. Allowed only on an outbound channel.
	/// If successful, will generate a UpdateHTLCs event, so you should probably poll
	/// PeerManager::process_events afterwards.
	/// Note: This API is likely to change!
	#[doc(hidden)]
	pub fn update_fee(&self, channel_id: [u8;32], feerate_per_kw: u64) -> Result<(), APIError> {
		let _ = self.total_consistency_lock.read().unwrap();
		let mut channel_state_lock = self.channel_state.lock().unwrap();
		let channel_state = channel_state_lock.borrow_parts();

		match channel_state.by_id.get_mut(&channel_id) {
			None => return Err(APIError::APIMisuseError{err: "Failed to find corresponding channel"}),
			Some(chan) => {
				if !chan.is_outbound() {
					return Err(APIError::APIMisuseError{err: "update_fee cannot be sent for an inbound channel"});
				}
				if chan.is_awaiting_monitor_update() {
					return Err(APIError::MonitorUpdateFailed);
				}
				if !chan.is_live() {
					return Err(APIError::ChannelUnavailable{err: "Channel is either not yet fully established or peer is currently disconnected"});
				}
				if let Some((update_fee, commitment_signed, chan_monitor)) = chan.send_update_fee_and_commit(feerate_per_kw)
						.map_err(|e| match e {
							ChannelError::Ignore(err) => APIError::APIMisuseError{err},
							ChannelError::Close(err) => {
								// TODO: We need to close the channel here, but for that to be safe we have
								// to do all channel closure inside the channel_state lock which is a
								// somewhat-larger refactor, so we leave that for later.
								APIError::APIMisuseError{err}
							},
						})? {
					if let Err(_e) = self.monitor.add_update_monitor(chan_monitor.get_funding_txo().unwrap(), chan_monitor) {
						unimplemented!();
					}
					channel_state.pending_msg_events.push(events::MessageSendEvent::UpdateHTLCs {
						node_id: chan.get_their_node_id(),
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
		Ok(())
	}
}

impl events::MessageSendEventsProvider for ChannelManager {
	fn get_and_clear_pending_msg_events(&self) -> Vec<events::MessageSendEvent> {
		let mut ret = Vec::new();
		let mut channel_state = self.channel_state.lock().unwrap();
		mem::swap(&mut ret, &mut channel_state.pending_msg_events);
		ret
	}
}

impl events::EventsProvider for ChannelManager {
	fn get_and_clear_pending_events(&self) -> Vec<events::Event> {
		let mut ret = Vec::new();
		let mut pending_events = self.pending_events.lock().unwrap();
		mem::swap(&mut ret, &mut *pending_events);
		ret
	}
}

impl ChainListener for ChannelManager {
	fn block_connected(&self, header: &BlockHeader, height: u32, txn_matched: &[&Transaction], indexes_of_txn_matched: &[u32]) {
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
						action: e.action,
					});
					if channel.is_shutdown() {
						return false;
					}
				}
				if let Some(funding_txo) = channel.get_funding_txo() {
					for tx in txn_matched {
						for inp in tx.input.iter() {
							if inp.previous_output == funding_txo.into_bitcoin_outpoint() {
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
		*self.last_block_hash.try_lock().expect("block_(dis)connected must not be called in parallel") = header.bitcoin_hash();
	}

	/// We force-close the channel without letting our counterparty participate in the shutdown
	fn block_disconnected(&self, header: &BlockHeader) {
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
	fn handle_open_channel(&self, their_node_id: &PublicKey, msg: &msgs::OpenChannel) -> Result<(), HandleError> {
		let _ = self.total_consistency_lock.read().unwrap();
		handle_error!(self, self.internal_open_channel(their_node_id, msg), their_node_id)
	}

	fn handle_accept_channel(&self, their_node_id: &PublicKey, msg: &msgs::AcceptChannel) -> Result<(), HandleError> {
		let _ = self.total_consistency_lock.read().unwrap();
		handle_error!(self, self.internal_accept_channel(their_node_id, msg), their_node_id)
	}

	fn handle_funding_created(&self, their_node_id: &PublicKey, msg: &msgs::FundingCreated) -> Result<(), HandleError> {
		let _ = self.total_consistency_lock.read().unwrap();
		handle_error!(self, self.internal_funding_created(their_node_id, msg), their_node_id)
	}

	fn handle_funding_signed(&self, their_node_id: &PublicKey, msg: &msgs::FundingSigned) -> Result<(), HandleError> {
		let _ = self.total_consistency_lock.read().unwrap();
		handle_error!(self, self.internal_funding_signed(their_node_id, msg), their_node_id)
	}

	fn handle_funding_locked(&self, their_node_id: &PublicKey, msg: &msgs::FundingLocked) -> Result<(), HandleError> {
		let _ = self.total_consistency_lock.read().unwrap();
		handle_error!(self, self.internal_funding_locked(their_node_id, msg), their_node_id)
	}

	fn handle_shutdown(&self, their_node_id: &PublicKey, msg: &msgs::Shutdown) -> Result<(), HandleError> {
		let _ = self.total_consistency_lock.read().unwrap();
		handle_error!(self, self.internal_shutdown(their_node_id, msg), their_node_id)
	}

	fn handle_closing_signed(&self, their_node_id: &PublicKey, msg: &msgs::ClosingSigned) -> Result<(), HandleError> {
		let _ = self.total_consistency_lock.read().unwrap();
		handle_error!(self, self.internal_closing_signed(their_node_id, msg), their_node_id)
	}

	fn handle_update_add_htlc(&self, their_node_id: &PublicKey, msg: &msgs::UpdateAddHTLC) -> Result<(), msgs::HandleError> {
		let _ = self.total_consistency_lock.read().unwrap();
		handle_error!(self, self.internal_update_add_htlc(their_node_id, msg), their_node_id)
	}

	fn handle_update_fulfill_htlc(&self, their_node_id: &PublicKey, msg: &msgs::UpdateFulfillHTLC) -> Result<(), HandleError> {
		let _ = self.total_consistency_lock.read().unwrap();
		handle_error!(self, self.internal_update_fulfill_htlc(their_node_id, msg), their_node_id)
	}

	fn handle_update_fail_htlc(&self, their_node_id: &PublicKey, msg: &msgs::UpdateFailHTLC) -> Result<(), HandleError> {
		let _ = self.total_consistency_lock.read().unwrap();
		handle_error!(self, self.internal_update_fail_htlc(their_node_id, msg), their_node_id)
	}

	fn handle_update_fail_malformed_htlc(&self, their_node_id: &PublicKey, msg: &msgs::UpdateFailMalformedHTLC) -> Result<(), HandleError> {
		let _ = self.total_consistency_lock.read().unwrap();
		handle_error!(self, self.internal_update_fail_malformed_htlc(their_node_id, msg), their_node_id)
	}

	fn handle_commitment_signed(&self, their_node_id: &PublicKey, msg: &msgs::CommitmentSigned) -> Result<(), HandleError> {
		let _ = self.total_consistency_lock.read().unwrap();
		handle_error!(self, self.internal_commitment_signed(their_node_id, msg), their_node_id)
	}

	fn handle_revoke_and_ack(&self, their_node_id: &PublicKey, msg: &msgs::RevokeAndACK) -> Result<(), HandleError> {
		let _ = self.total_consistency_lock.read().unwrap();
		handle_error!(self, self.internal_revoke_and_ack(their_node_id, msg), their_node_id)
	}

	fn handle_update_fee(&self, their_node_id: &PublicKey, msg: &msgs::UpdateFee) -> Result<(), HandleError> {
		let _ = self.total_consistency_lock.read().unwrap();
		handle_error!(self, self.internal_update_fee(their_node_id, msg), their_node_id)
	}

	fn handle_announcement_signatures(&self, their_node_id: &PublicKey, msg: &msgs::AnnouncementSignatures) -> Result<(), HandleError> {
		let _ = self.total_consistency_lock.read().unwrap();
		handle_error!(self, self.internal_announcement_signatures(their_node_id, msg), their_node_id)
	}

	fn handle_channel_reestablish(&self, their_node_id: &PublicKey, msg: &msgs::ChannelReestablish) -> Result<(), HandleError> {
		let _ = self.total_consistency_lock.read().unwrap();
		handle_error!(self, self.internal_channel_reestablish(their_node_id, msg), their_node_id)
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
		if let &Some(ref onion) = &self.onion_packet {
			1u8.write(writer)?;
			onion.write(writer)?;
		} else {
			0u8.write(writer)?;
		}
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
		let onion_packet = match <u8 as Readable<R>>::read(reader)? {
			0 => None,
			1 => Some(msgs::OnionPacket::read(reader)?),
			_ => return Err(DecodeError::InvalidValue),
		};
		Ok(PendingForwardHTLCInfo {
			onion_packet,
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
			&HTLCFailReason::ErrorPacket { ref err } => {
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
			0 => Ok(HTLCFailReason::ErrorPacket { err: Readable::read(reader)? }),
			1 => Ok(HTLCFailReason::Reason {
				failure_code: Readable::read(reader)?,
				data: Readable::read(reader)?,
			}),
			_ => Err(DecodeError::InvalidValue),
		}
	}
}

impl_writeable!(HTLCForwardInfo, 0, {
	prev_short_channel_id,
	prev_htlc_id,
	forward_info
});

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
			for previous_hop in previous_hops {
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
	/// be force-closed using the data in the channelmonitor and the Channel will be dropped. This
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
				previous_hops.push(Readable::read(reader)?);
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
				next_forward: Instant::now(),
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

#[cfg(test)]
mod tests {
	use chain::chaininterface;
	use chain::transaction::OutPoint;
	use chain::chaininterface::{ChainListener, ChainWatchInterface};
	use chain::keysinterface::{KeysInterface, SpendableOutputDescriptor};
	use chain::keysinterface;
	use ln::channel::{COMMITMENT_TX_BASE_WEIGHT, COMMITMENT_TX_WEIGHT_PER_HTLC};
	use ln::channelmanager::{ChannelManager,ChannelManagerReadArgs,OnionKeys,PaymentFailReason,RAACommitmentOrder};
	use ln::channelmonitor::{ChannelMonitor, ChannelMonitorUpdateErr, CLTV_CLAIM_BUFFER, HTLC_FAIL_TIMEOUT_BLOCKS, ManyChannelMonitor};
	use ln::router::{Route, RouteHop, Router};
	use ln::msgs;
	use ln::msgs::{ChannelMessageHandler,RoutingMessageHandler};
	use util::test_utils;
	use util::events::{Event, EventsProvider, MessageSendEvent, MessageSendEventsProvider};
	use util::errors::APIError;
	use util::logger::Logger;
	use util::ser::{Writeable, Writer, ReadableArgs};
	use util::config::UserConfig;

	use bitcoin::util::hash::{BitcoinHash, Sha256dHash};
	use bitcoin::util::bip143;
	use bitcoin::util::address::Address;
	use bitcoin::util::bip32::{ChildNumber, ExtendedPubKey, ExtendedPrivKey};
	use bitcoin::blockdata::block::{Block, BlockHeader};
	use bitcoin::blockdata::transaction::{Transaction, TxOut, TxIn, SigHashType};
	use bitcoin::blockdata::script::{Builder, Script};
	use bitcoin::blockdata::opcodes;
	use bitcoin::blockdata::constants::genesis_block;
	use bitcoin::network::constants::Network;

	use hex;

	use secp256k1::{Secp256k1, Message};
	use secp256k1::key::{PublicKey,SecretKey};

	use crypto::sha2::Sha256;
	use crypto::digest::Digest;

	use rand::{thread_rng,Rng};

	use std::cell::RefCell;
	use std::collections::{BTreeSet, HashMap};
	use std::default::Default;
	use std::rc::Rc;
	use std::sync::{Arc, Mutex};
	use std::sync::atomic::Ordering;
	use std::time::Instant;
	use std::mem;

	fn build_test_onion_keys() -> Vec<OnionKeys> {
		// Keys from BOLT 4, used in both test vector tests
		let secp_ctx = Secp256k1::new();

		let route = Route {
			hops: vec!(
					RouteHop {
						pubkey: PublicKey::from_slice(&secp_ctx, &hex::decode("02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619").unwrap()[..]).unwrap(),
						short_channel_id: 0, fee_msat: 0, cltv_expiry_delta: 0 // Test vectors are garbage and not generateble from a RouteHop, we fill in payloads manually
					},
					RouteHop {
						pubkey: PublicKey::from_slice(&secp_ctx, &hex::decode("0324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c").unwrap()[..]).unwrap(),
						short_channel_id: 0, fee_msat: 0, cltv_expiry_delta: 0 // Test vectors are garbage and not generateble from a RouteHop, we fill in payloads manually
					},
					RouteHop {
						pubkey: PublicKey::from_slice(&secp_ctx, &hex::decode("027f31ebc5462c1fdce1b737ecff52d37d75dea43ce11c74d25aa297165faa2007").unwrap()[..]).unwrap(),
						short_channel_id: 0, fee_msat: 0, cltv_expiry_delta: 0 // Test vectors are garbage and not generateble from a RouteHop, we fill in payloads manually
					},
					RouteHop {
						pubkey: PublicKey::from_slice(&secp_ctx, &hex::decode("032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991").unwrap()[..]).unwrap(),
						short_channel_id: 0, fee_msat: 0, cltv_expiry_delta: 0 // Test vectors are garbage and not generateble from a RouteHop, we fill in payloads manually
					},
					RouteHop {
						pubkey: PublicKey::from_slice(&secp_ctx, &hex::decode("02edabbd16b41c8371b92ef2f04c1185b4f03b6dcd52ba9b78d9d7c89c8f221145").unwrap()[..]).unwrap(),
						short_channel_id: 0, fee_msat: 0, cltv_expiry_delta: 0 // Test vectors are garbage and not generateble from a RouteHop, we fill in payloads manually
					},
			),
		};

		let session_priv = SecretKey::from_slice(&secp_ctx, &hex::decode("4141414141414141414141414141414141414141414141414141414141414141").unwrap()[..]).unwrap();

		let onion_keys = ChannelManager::construct_onion_keys(&secp_ctx, &route, &session_priv).unwrap();
		assert_eq!(onion_keys.len(), route.hops.len());
		onion_keys
	}

	#[test]
	fn onion_vectors() {
		// Packet creation test vectors from BOLT 4
		let onion_keys = build_test_onion_keys();

		assert_eq!(onion_keys[0].shared_secret[..], hex::decode("53eb63ea8a3fec3b3cd433b85cd62a4b145e1dda09391b348c4e1cd36a03ea66").unwrap()[..]);
		assert_eq!(onion_keys[0].blinding_factor[..], hex::decode("2ec2e5da605776054187180343287683aa6a51b4b1c04d6dd49c45d8cffb3c36").unwrap()[..]);
		assert_eq!(onion_keys[0].ephemeral_pubkey.serialize()[..], hex::decode("02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619").unwrap()[..]);
		assert_eq!(onion_keys[0].rho, hex::decode("ce496ec94def95aadd4bec15cdb41a740c9f2b62347c4917325fcc6fb0453986").unwrap()[..]);
		assert_eq!(onion_keys[0].mu, hex::decode("b57061dc6d0a2b9f261ac410c8b26d64ac5506cbba30267a649c28c179400eba").unwrap()[..]);

		assert_eq!(onion_keys[1].shared_secret[..], hex::decode("a6519e98832a0b179f62123b3567c106db99ee37bef036e783263602f3488fae").unwrap()[..]);
		assert_eq!(onion_keys[1].blinding_factor[..], hex::decode("bf66c28bc22e598cfd574a1931a2bafbca09163df2261e6d0056b2610dab938f").unwrap()[..]);
		assert_eq!(onion_keys[1].ephemeral_pubkey.serialize()[..], hex::decode("028f9438bfbf7feac2e108d677e3a82da596be706cc1cf342b75c7b7e22bf4e6e2").unwrap()[..]);
		assert_eq!(onion_keys[1].rho, hex::decode("450ffcabc6449094918ebe13d4f03e433d20a3d28a768203337bc40b6e4b2c59").unwrap()[..]);
		assert_eq!(onion_keys[1].mu, hex::decode("05ed2b4a3fb023c2ff5dd6ed4b9b6ea7383f5cfe9d59c11d121ec2c81ca2eea9").unwrap()[..]);

		assert_eq!(onion_keys[2].shared_secret[..], hex::decode("3a6b412548762f0dbccce5c7ae7bb8147d1caf9b5471c34120b30bc9c04891cc").unwrap()[..]);
		assert_eq!(onion_keys[2].blinding_factor[..], hex::decode("a1f2dadd184eb1627049673f18c6325814384facdee5bfd935d9cb031a1698a5").unwrap()[..]);
		assert_eq!(onion_keys[2].ephemeral_pubkey.serialize()[..], hex::decode("03bfd8225241ea71cd0843db7709f4c222f62ff2d4516fd38b39914ab6b83e0da0").unwrap()[..]);
		assert_eq!(onion_keys[2].rho, hex::decode("11bf5c4f960239cb37833936aa3d02cea82c0f39fd35f566109c41f9eac8deea").unwrap()[..]);
		assert_eq!(onion_keys[2].mu, hex::decode("caafe2820fa00eb2eeb78695ae452eba38f5a53ed6d53518c5c6edf76f3f5b78").unwrap()[..]);

		assert_eq!(onion_keys[3].shared_secret[..], hex::decode("21e13c2d7cfe7e18836df50872466117a295783ab8aab0e7ecc8c725503ad02d").unwrap()[..]);
		assert_eq!(onion_keys[3].blinding_factor[..], hex::decode("7cfe0b699f35525029ae0fa437c69d0f20f7ed4e3916133f9cacbb13c82ff262").unwrap()[..]);
		assert_eq!(onion_keys[3].ephemeral_pubkey.serialize()[..], hex::decode("031dde6926381289671300239ea8e57ffaf9bebd05b9a5b95beaf07af05cd43595").unwrap()[..]);
		assert_eq!(onion_keys[3].rho, hex::decode("cbe784ab745c13ff5cffc2fbe3e84424aa0fd669b8ead4ee562901a4a4e89e9e").unwrap()[..]);
		assert_eq!(onion_keys[3].mu, hex::decode("5052aa1b3d9f0655a0932e50d42f0c9ba0705142c25d225515c45f47c0036ee9").unwrap()[..]);

		assert_eq!(onion_keys[4].shared_secret[..], hex::decode("b5756b9b542727dbafc6765a49488b023a725d631af688fc031217e90770c328").unwrap()[..]);
		assert_eq!(onion_keys[4].blinding_factor[..], hex::decode("c96e00dddaf57e7edcd4fb5954be5b65b09f17cb6d20651b4e90315be5779205").unwrap()[..]);
		assert_eq!(onion_keys[4].ephemeral_pubkey.serialize()[..], hex::decode("03a214ebd875aab6ddfd77f22c5e7311d7f77f17a169e599f157bbcdae8bf071f4").unwrap()[..]);
		assert_eq!(onion_keys[4].rho, hex::decode("034e18b8cc718e8af6339106e706c52d8df89e2b1f7e9142d996acf88df8799b").unwrap()[..]);
		assert_eq!(onion_keys[4].mu, hex::decode("8e45e5c61c2b24cb6382444db6698727afb063adecd72aada233d4bf273d975a").unwrap()[..]);

		// Test vectors below are flat-out wrong: they claim to set outgoing_cltv_value to non-0 :/
		let payloads = vec!(
			msgs::OnionHopData {
				realm: 0,
				data: msgs::OnionRealm0HopData {
					short_channel_id: 0,
					amt_to_forward: 0,
					outgoing_cltv_value: 0,
				},
				hmac: [0; 32],
			},
			msgs::OnionHopData {
				realm: 0,
				data: msgs::OnionRealm0HopData {
					short_channel_id: 0x0101010101010101,
					amt_to_forward: 0x0100000001,
					outgoing_cltv_value: 0,
				},
				hmac: [0; 32],
			},
			msgs::OnionHopData {
				realm: 0,
				data: msgs::OnionRealm0HopData {
					short_channel_id: 0x0202020202020202,
					amt_to_forward: 0x0200000002,
					outgoing_cltv_value: 0,
				},
				hmac: [0; 32],
			},
			msgs::OnionHopData {
				realm: 0,
				data: msgs::OnionRealm0HopData {
					short_channel_id: 0x0303030303030303,
					amt_to_forward: 0x0300000003,
					outgoing_cltv_value: 0,
				},
				hmac: [0; 32],
			},
			msgs::OnionHopData {
				realm: 0,
				data: msgs::OnionRealm0HopData {
					short_channel_id: 0x0404040404040404,
					amt_to_forward: 0x0400000004,
					outgoing_cltv_value: 0,
				},
				hmac: [0; 32],
			},
		);

		let packet = ChannelManager::construct_onion_packet(payloads, onion_keys, &[0x42; 32]);
		// Just check the final packet encoding, as it includes all the per-hop vectors in it
		// anyway...
		assert_eq!(packet.encode(), hex::decode("0002eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619e5f14350c2a76fc232b5e46d421e9615471ab9e0bc887beff8c95fdb878f7b3a716a996c7845c93d90e4ecbb9bde4ece2f69425c99e4bc820e44485455f135edc0d10f7d61ab590531cf08000179a333a347f8b4072f216400406bdf3bf038659793d4a1fd7b246979e3150a0a4cb052c9ec69acf0f48c3d39cd55675fe717cb7d80ce721caad69320c3a469a202f1e468c67eaf7a7cd8226d0fd32f7b48084dca885d56047694762b67021713ca673929c163ec36e04e40ca8e1c6d17569419d3039d9a1ec866abe044a9ad635778b961fc0776dc832b3a451bd5d35072d2269cf9b040f6b7a7dad84fb114ed413b1426cb96ceaf83825665ed5a1d002c1687f92465b49ed4c7f0218ff8c6c7dd7221d589c65b3b9aaa71a41484b122846c7c7b57e02e679ea8469b70e14fe4f70fee4d87b910cf144be6fe48eef24da475c0b0bcc6565ae82cd3f4e3b24c76eaa5616c6111343306ab35c1fe5ca4a77c0e314ed7dba39d6f1e0de791719c241a939cc493bea2bae1c1e932679ea94d29084278513c77b899cc98059d06a27d171b0dbdf6bee13ddc4fc17a0c4d2827d488436b57baa167544138ca2e64a11b43ac8a06cd0c2fba2d4d900ed2d9205305e2d7383cc98dacb078133de5f6fb6bed2ef26ba92cea28aafc3b9948dd9ae5559e8bd6920b8cea462aa445ca6a95e0e7ba52961b181c79e73bd581821df2b10173727a810c92b83b5ba4a0403eb710d2ca10689a35bec6c3a708e9e92f7d78ff3c5d9989574b00c6736f84c199256e76e19e78f0c98a9d580b4a658c84fc8f2096c2fbea8f5f8c59d0fdacb3be2802ef802abbecb3aba4acaac69a0e965abd8981e9896b1f6ef9d60f7a164b371af869fd0e48073742825e9434fc54da837e120266d53302954843538ea7c6c3dbfb4ff3b2fdbe244437f2a153ccf7bdb4c92aa08102d4f3cff2ae5ef86fab4653595e6a5837fa2f3e29f27a9cde5966843fb847a4a61f1e76c281fe8bb2b0a181d096100db5a1a5ce7a910238251a43ca556712eaadea167fb4d7d75825e440f3ecd782036d7574df8bceacb397abefc5f5254d2722215c53ff54af8299aaaad642c6d72a14d27882d9bbd539e1cc7a527526ba89b8c037ad09120e98ab042d3e8652b31ae0e478516bfaf88efca9f3676ffe99d2819dcaeb7610a626695f53117665d267d3f7abebd6bbd6733f645c72c389f03855bdf1e4b8075b516569b118233a0f0971d24b83113c0b096f5216a207ca99a7cddc81c130923fe3d91e7508c9ac5f2e914ff5dccab9e558566fa14efb34ac98d878580814b94b73acbfde9072f30b881f7f0fff42d4045d1ace6322d86a97d164aa84d93a60498065cc7c20e636f5862dc81531a88c60305a2e59a985be327a6902e4bed986dbf4a0b50c217af0ea7fdf9ab37f9ea1a1aaa72f54cf40154ea9b269f1a7c09f9f43245109431a175d50e2db0132337baa0ef97eed0fcf20489da36b79a1172faccc2f7ded7c60e00694282d93359c4682135642bc81f433574aa8ef0c97b4ade7ca372c5ffc23c7eddd839bab4e0f14d6df15c9dbeab176bec8b5701cf054eb3072f6dadc98f88819042bf10c407516ee58bce33fbe3b3d86a54255e577db4598e30a135361528c101683a5fcde7e8ba53f3456254be8f45fe3a56120ae96ea3773631fcb3873aa3abd91bcff00bd38bd43697a2e789e00da6077482e7b1b1a677b5afae4c54e6cbdf7377b694eb7d7a5b913476a5be923322d3de06060fd5e819635232a2cf4f0731da13b8546d1d6d4f8d75b9fce6c2341a71b0ea6f780df54bfdb0dd5cd9855179f602f9172307c7268724c3618e6817abd793adc214a0dc0bc616816632f27ea336fb56dfd").unwrap());
	}

	#[test]
	fn test_failure_packet_onion() {
		// Returning Errors test vectors from BOLT 4

		let onion_keys = build_test_onion_keys();
		let onion_error = ChannelManager::build_failure_packet(&onion_keys[4].shared_secret[..], 0x2002, &[0; 0]);
		assert_eq!(onion_error.encode(), hex::decode("4c2fc8bc08510334b6833ad9c3e79cd1b52ae59dfe5c2a4b23ead50f09f7ee0b0002200200fe0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").unwrap());

		let onion_packet_1 = ChannelManager::encrypt_failure_packet(&onion_keys[4].shared_secret[..], &onion_error.encode()[..]);
		assert_eq!(onion_packet_1.data, hex::decode("a5e6bd0c74cb347f10cce367f949098f2457d14c046fd8a22cb96efb30b0fdcda8cb9168b50f2fd45edd73c1b0c8b33002df376801ff58aaa94000bf8a86f92620f343baef38a580102395ae3abf9128d1047a0736ff9b83d456740ebbb4aeb3aa9737f18fb4afb4aa074fb26c4d702f42968888550a3bded8c05247e045b866baef0499f079fdaeef6538f31d44deafffdfd3afa2fb4ca9082b8f1c465371a9894dd8c243fb4847e004f5256b3e90e2edde4c9fb3082ddfe4d1e734cacd96ef0706bf63c9984e22dc98851bcccd1c3494351feb458c9c6af41c0044bea3c47552b1d992ae542b17a2d0bba1a096c78d169034ecb55b6e3a7263c26017f033031228833c1daefc0dedb8cf7c3e37c9c37ebfe42f3225c326e8bcfd338804c145b16e34e4").unwrap());

		let onion_packet_2 = ChannelManager::encrypt_failure_packet(&onion_keys[3].shared_secret[..], &onion_packet_1.data[..]);
		assert_eq!(onion_packet_2.data, hex::decode("c49a1ce81680f78f5f2000cda36268de34a3f0a0662f55b4e837c83a8773c22aa081bab1616a0011585323930fa5b9fae0c85770a2279ff59ec427ad1bbff9001c0cd1497004bd2a0f68b50704cf6d6a4bf3c8b6a0833399a24b3456961ba00736785112594f65b6b2d44d9f5ea4e49b5e1ec2af978cbe31c67114440ac51a62081df0ed46d4a3df295da0b0fe25c0115019f03f15ec86fabb4c852f83449e812f141a9395b3f70b766ebbd4ec2fae2b6955bd8f32684c15abfe8fd3a6261e52650e8807a92158d9f1463261a925e4bfba44bd20b166d532f0017185c3a6ac7957adefe45559e3072c8dc35abeba835a8cb01a71a15c736911126f27d46a36168ca5ef7dccd4e2886212602b181463e0dd30185c96348f9743a02aca8ec27c0b90dca270").unwrap());

		let onion_packet_3 = ChannelManager::encrypt_failure_packet(&onion_keys[2].shared_secret[..], &onion_packet_2.data[..]);
		assert_eq!(onion_packet_3.data, hex::decode("a5d3e8634cfe78b2307d87c6d90be6fe7855b4f2cc9b1dfb19e92e4b79103f61ff9ac25f412ddfb7466e74f81b3e545563cdd8f5524dae873de61d7bdfccd496af2584930d2b566b4f8d3881f8c043df92224f38cf094cfc09d92655989531524593ec6d6caec1863bdfaa79229b5020acc034cd6deeea1021c50586947b9b8e6faa83b81fbfa6133c0af5d6b07c017f7158fa94f0d206baf12dda6b68f785b773b360fd0497e16cc402d779c8d48d0fa6315536ef0660f3f4e1865f5b38ea49c7da4fd959de4e83ff3ab686f059a45c65ba2af4a6a79166aa0f496bf04d06987b6d2ea205bdb0d347718b9aeff5b61dfff344993a275b79717cd815b6ad4c0beb568c4ac9c36ff1c315ec1119a1993c4b61e6eaa0375e0aaf738ac691abd3263bf937e3").unwrap());

		let onion_packet_4 = ChannelManager::encrypt_failure_packet(&onion_keys[1].shared_secret[..], &onion_packet_3.data[..]);
		assert_eq!(onion_packet_4.data, hex::decode("aac3200c4968f56b21f53e5e374e3a2383ad2b1b6501bbcc45abc31e59b26881b7dfadbb56ec8dae8857add94e6702fb4c3a4de22e2e669e1ed926b04447fc73034bb730f4932acd62727b75348a648a1128744657ca6a4e713b9b646c3ca66cac02cdab44dd3439890ef3aaf61708714f7375349b8da541b2548d452d84de7084bb95b3ac2345201d624d31f4d52078aa0fa05a88b4e20202bd2b86ac5b52919ea305a8949de95e935eed0319cf3cf19ebea61d76ba92532497fcdc9411d06bcd4275094d0a4a3c5d3a945e43305a5a9256e333e1f64dbca5fcd4e03a39b9012d197506e06f29339dfee3331995b21615337ae060233d39befea925cc262873e0530408e6990f1cbd233a150ef7b004ff6166c70c68d9f8c853c1abca640b8660db2921").unwrap());

		let onion_packet_5 = ChannelManager::encrypt_failure_packet(&onion_keys[0].shared_secret[..], &onion_packet_4.data[..]);
		assert_eq!(onion_packet_5.data, hex::decode("9c5add3963fc7f6ed7f148623c84134b5647e1306419dbe2174e523fa9e2fbed3a06a19f899145610741c83ad40b7712aefaddec8c6baf7325d92ea4ca4d1df8bce517f7e54554608bf2bd8071a4f52a7a2f7ffbb1413edad81eeea5785aa9d990f2865dc23b4bc3c301a94eec4eabebca66be5cf638f693ec256aec514620cc28ee4a94bd9565bc4d4962b9d3641d4278fb319ed2b84de5b665f307a2db0f7fbb757366067d88c50f7e829138fde4f78d39b5b5802f1b92a8a820865af5cc79f9f30bc3f461c66af95d13e5e1f0381c184572a91dee1c849048a647a1158cf884064deddbf1b0b88dfe2f791428d0ba0f6fb2f04e14081f69165ae66d9297c118f0907705c9c4954a199bae0bb96fad763d690e7daa6cfda59ba7f2c8d11448b604d12d").unwrap());
	}

	fn confirm_transaction(chain: &chaininterface::ChainWatchInterfaceUtil, tx: &Transaction, chan_id: u32) {
		assert!(chain.does_match_tx(tx));
		let mut header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
		chain.block_connected_checked(&header, 1, &[tx; 1], &[chan_id; 1]);
		for i in 2..100 {
			header = BlockHeader { version: 0x20000000, prev_blockhash: header.bitcoin_hash(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
			chain.block_connected_checked(&header, i, &[tx; 0], &[0; 0]);
		}
	}

	struct Node {
		chain_monitor: Arc<chaininterface::ChainWatchInterfaceUtil>,
		tx_broadcaster: Arc<test_utils::TestBroadcaster>,
		chan_monitor: Arc<test_utils::TestChannelMonitor>,
		node: Arc<ChannelManager>,
		router: Router,
		node_seed: [u8; 32],
		network_payment_count: Rc<RefCell<u8>>,
		network_chan_count: Rc<RefCell<u32>>,
	}
	impl Drop for Node {
		fn drop(&mut self) {
			if !::std::thread::panicking() {
				// Check that we processed all pending events
				assert_eq!(self.node.get_and_clear_pending_msg_events().len(), 0);
				assert_eq!(self.node.get_and_clear_pending_events().len(), 0);
				assert_eq!(self.chan_monitor.added_monitors.lock().unwrap().len(), 0);
			}
		}
	}

	fn create_chan_between_nodes(node_a: &Node, node_b: &Node) -> (msgs::ChannelAnnouncement, msgs::ChannelUpdate, msgs::ChannelUpdate, [u8; 32], Transaction) {
		create_chan_between_nodes_with_value(node_a, node_b, 100000, 10001)
	}

	fn create_chan_between_nodes_with_value(node_a: &Node, node_b: &Node, channel_value: u64, push_msat: u64) -> (msgs::ChannelAnnouncement, msgs::ChannelUpdate, msgs::ChannelUpdate, [u8; 32], Transaction) {
		let (funding_locked, channel_id, tx) = create_chan_between_nodes_with_value_a(node_a, node_b, channel_value, push_msat);
		let (announcement, as_update, bs_update) = create_chan_between_nodes_with_value_b(node_a, node_b, &funding_locked);
		(announcement, as_update, bs_update, channel_id, tx)
	}

	macro_rules! get_revoke_commit_msgs {
		($node: expr, $node_id: expr) => {
			{
				let events = $node.node.get_and_clear_pending_msg_events();
				assert_eq!(events.len(), 2);
				(match events[0] {
					MessageSendEvent::SendRevokeAndACK { ref node_id, ref msg } => {
						assert_eq!(*node_id, $node_id);
						(*msg).clone()
					},
					_ => panic!("Unexpected event"),
				}, match events[1] {
					MessageSendEvent::UpdateHTLCs { ref node_id, ref updates } => {
						assert_eq!(*node_id, $node_id);
						assert!(updates.update_add_htlcs.is_empty());
						assert!(updates.update_fulfill_htlcs.is_empty());
						assert!(updates.update_fail_htlcs.is_empty());
						assert!(updates.update_fail_malformed_htlcs.is_empty());
						assert!(updates.update_fee.is_none());
						updates.commitment_signed.clone()
					},
					_ => panic!("Unexpected event"),
				})
			}
		}
	}

	macro_rules! get_event_msg {
		($node: expr, $event_type: path, $node_id: expr) => {
			{
				let events = $node.node.get_and_clear_pending_msg_events();
				assert_eq!(events.len(), 1);
				match events[0] {
					$event_type { ref node_id, ref msg } => {
						assert_eq!(*node_id, $node_id);
						(*msg).clone()
					},
					_ => panic!("Unexpected event"),
				}
			}
		}
	}

	macro_rules! get_htlc_update_msgs {
		($node: expr, $node_id: expr) => {
			{
				let events = $node.node.get_and_clear_pending_msg_events();
				assert_eq!(events.len(), 1);
				match events[0] {
					MessageSendEvent::UpdateHTLCs { ref node_id, ref updates } => {
						assert_eq!(*node_id, $node_id);
						(*updates).clone()
					},
					_ => panic!("Unexpected event"),
				}
			}
		}
	}

	macro_rules! get_feerate {
		($node: expr, $channel_id: expr) => {
			{
				let chan_lock = $node.node.channel_state.lock().unwrap();
				let chan = chan_lock.by_id.get(&$channel_id).unwrap();
				chan.get_feerate()
			}
		}
	}


	fn create_chan_between_nodes_with_value_init(node_a: &Node, node_b: &Node, channel_value: u64, push_msat: u64) -> Transaction {
		node_a.node.create_channel(node_b.node.get_our_node_id(), channel_value, push_msat, 42).unwrap();
		node_b.node.handle_open_channel(&node_a.node.get_our_node_id(), &get_event_msg!(node_a, MessageSendEvent::SendOpenChannel, node_b.node.get_our_node_id())).unwrap();
		node_a.node.handle_accept_channel(&node_b.node.get_our_node_id(), &get_event_msg!(node_b, MessageSendEvent::SendAcceptChannel, node_a.node.get_our_node_id())).unwrap();

		let chan_id = *node_a.network_chan_count.borrow();
		let tx;
		let funding_output;

		let events_2 = node_a.node.get_and_clear_pending_events();
		assert_eq!(events_2.len(), 1);
		match events_2[0] {
			Event::FundingGenerationReady { ref temporary_channel_id, ref channel_value_satoshis, ref output_script, user_channel_id } => {
				assert_eq!(*channel_value_satoshis, channel_value);
				assert_eq!(user_channel_id, 42);

				tx = Transaction { version: chan_id as u32, lock_time: 0, input: Vec::new(), output: vec![TxOut {
					value: *channel_value_satoshis, script_pubkey: output_script.clone(),
				}]};
				funding_output = OutPoint::new(tx.txid(), 0);

				node_a.node.funding_transaction_generated(&temporary_channel_id, funding_output);
				let mut added_monitors = node_a.chan_monitor.added_monitors.lock().unwrap();
				assert_eq!(added_monitors.len(), 1);
				assert_eq!(added_monitors[0].0, funding_output);
				added_monitors.clear();
			},
			_ => panic!("Unexpected event"),
		}

		node_b.node.handle_funding_created(&node_a.node.get_our_node_id(), &get_event_msg!(node_a, MessageSendEvent::SendFundingCreated, node_b.node.get_our_node_id())).unwrap();
		{
			let mut added_monitors = node_b.chan_monitor.added_monitors.lock().unwrap();
			assert_eq!(added_monitors.len(), 1);
			assert_eq!(added_monitors[0].0, funding_output);
			added_monitors.clear();
		}

		node_a.node.handle_funding_signed(&node_b.node.get_our_node_id(), &get_event_msg!(node_b, MessageSendEvent::SendFundingSigned, node_a.node.get_our_node_id())).unwrap();
		{
			let mut added_monitors = node_a.chan_monitor.added_monitors.lock().unwrap();
			assert_eq!(added_monitors.len(), 1);
			assert_eq!(added_monitors[0].0, funding_output);
			added_monitors.clear();
		}

		let events_4 = node_a.node.get_and_clear_pending_events();
		assert_eq!(events_4.len(), 1);
		match events_4[0] {
			Event::FundingBroadcastSafe { ref funding_txo, user_channel_id } => {
				assert_eq!(user_channel_id, 42);
				assert_eq!(*funding_txo, funding_output);
			},
			_ => panic!("Unexpected event"),
		};

		tx
	}

	fn create_chan_between_nodes_with_value_confirm(node_a: &Node, node_b: &Node, tx: &Transaction) -> ((msgs::FundingLocked, msgs::AnnouncementSignatures), [u8; 32]) {
		confirm_transaction(&node_b.chain_monitor, &tx, tx.version);
		node_a.node.handle_funding_locked(&node_b.node.get_our_node_id(), &get_event_msg!(node_b, MessageSendEvent::SendFundingLocked, node_a.node.get_our_node_id())).unwrap();

		let channel_id;

		confirm_transaction(&node_a.chain_monitor, &tx, tx.version);
		let events_6 = node_a.node.get_and_clear_pending_msg_events();
		assert_eq!(events_6.len(), 2);
		((match events_6[0] {
			MessageSendEvent::SendFundingLocked { ref node_id, ref msg } => {
				channel_id = msg.channel_id.clone();
				assert_eq!(*node_id, node_b.node.get_our_node_id());
				msg.clone()
			},
			_ => panic!("Unexpected event"),
		}, match events_6[1] {
			MessageSendEvent::SendAnnouncementSignatures { ref node_id, ref msg } => {
				assert_eq!(*node_id, node_b.node.get_our_node_id());
				msg.clone()
			},
			_ => panic!("Unexpected event"),
		}), channel_id)
	}

	fn create_chan_between_nodes_with_value_a(node_a: &Node, node_b: &Node, channel_value: u64, push_msat: u64) -> ((msgs::FundingLocked, msgs::AnnouncementSignatures), [u8; 32], Transaction) {
		let tx = create_chan_between_nodes_with_value_init(node_a, node_b, channel_value, push_msat);
		let (msgs, chan_id) = create_chan_between_nodes_with_value_confirm(node_a, node_b, &tx);
		(msgs, chan_id, tx)
	}

	fn create_chan_between_nodes_with_value_b(node_a: &Node, node_b: &Node, as_funding_msgs: &(msgs::FundingLocked, msgs::AnnouncementSignatures)) -> (msgs::ChannelAnnouncement, msgs::ChannelUpdate, msgs::ChannelUpdate) {
		node_b.node.handle_funding_locked(&node_a.node.get_our_node_id(), &as_funding_msgs.0).unwrap();
		let bs_announcement_sigs = get_event_msg!(node_b, MessageSendEvent::SendAnnouncementSignatures, node_a.node.get_our_node_id());
		node_b.node.handle_announcement_signatures(&node_a.node.get_our_node_id(), &as_funding_msgs.1).unwrap();

		let events_7 = node_b.node.get_and_clear_pending_msg_events();
		assert_eq!(events_7.len(), 1);
		let (announcement, bs_update) = match events_7[0] {
			MessageSendEvent::BroadcastChannelAnnouncement { ref msg, ref update_msg } => {
				(msg, update_msg)
			},
			_ => panic!("Unexpected event"),
		};

		node_a.node.handle_announcement_signatures(&node_b.node.get_our_node_id(), &bs_announcement_sigs).unwrap();
		let events_8 = node_a.node.get_and_clear_pending_msg_events();
		assert_eq!(events_8.len(), 1);
		let as_update = match events_8[0] {
			MessageSendEvent::BroadcastChannelAnnouncement { ref msg, ref update_msg } => {
				assert!(*announcement == *msg);
				update_msg
			},
			_ => panic!("Unexpected event"),
		};

		*node_a.network_chan_count.borrow_mut() += 1;

		((*announcement).clone(), (*as_update).clone(), (*bs_update).clone())
	}

	fn create_announced_chan_between_nodes(nodes: &Vec<Node>, a: usize, b: usize) -> (msgs::ChannelUpdate, msgs::ChannelUpdate, [u8; 32], Transaction) {
		create_announced_chan_between_nodes_with_value(nodes, a, b, 100000, 10001)
	}

	fn create_announced_chan_between_nodes_with_value(nodes: &Vec<Node>, a: usize, b: usize, channel_value: u64, push_msat: u64) -> (msgs::ChannelUpdate, msgs::ChannelUpdate, [u8; 32], Transaction) {
		let chan_announcement = create_chan_between_nodes_with_value(&nodes[a], &nodes[b], channel_value, push_msat);
		for node in nodes {
			assert!(node.router.handle_channel_announcement(&chan_announcement.0).unwrap());
			node.router.handle_channel_update(&chan_announcement.1).unwrap();
			node.router.handle_channel_update(&chan_announcement.2).unwrap();
		}
		(chan_announcement.1, chan_announcement.2, chan_announcement.3, chan_announcement.4)
	}

	macro_rules! check_spends {
		($tx: expr, $spends_tx: expr) => {
			{
				let mut funding_tx_map = HashMap::new();
				let spends_tx = $spends_tx;
				funding_tx_map.insert(spends_tx.txid(), spends_tx);
				$tx.verify(&funding_tx_map).unwrap();
			}
		}
	}

	macro_rules! get_closing_signed_broadcast {
		($node: expr, $dest_pubkey: expr) => {
			{
				let events = $node.get_and_clear_pending_msg_events();
				assert!(events.len() == 1 || events.len() == 2);
				(match events[events.len() - 1] {
					MessageSendEvent::BroadcastChannelUpdate { ref msg } => {
						assert_eq!(msg.contents.flags & 2, 2);
						msg.clone()
					},
					_ => panic!("Unexpected event"),
				}, if events.len() == 2 {
					match events[0] {
						MessageSendEvent::SendClosingSigned { ref node_id, ref msg } => {
							assert_eq!(*node_id, $dest_pubkey);
							Some(msg.clone())
						},
						_ => panic!("Unexpected event"),
					}
				} else { None })
			}
		}
	}

	fn close_channel(outbound_node: &Node, inbound_node: &Node, channel_id: &[u8; 32], funding_tx: Transaction, close_inbound_first: bool) -> (msgs::ChannelUpdate, msgs::ChannelUpdate, Transaction) {
		let (node_a, broadcaster_a, struct_a) = if close_inbound_first { (&inbound_node.node, &inbound_node.tx_broadcaster, inbound_node) } else { (&outbound_node.node, &outbound_node.tx_broadcaster, outbound_node) };
		let (node_b, broadcaster_b) = if close_inbound_first { (&outbound_node.node, &outbound_node.tx_broadcaster) } else { (&inbound_node.node, &inbound_node.tx_broadcaster) };
		let (tx_a, tx_b);

		node_a.close_channel(channel_id).unwrap();
		node_b.handle_shutdown(&node_a.get_our_node_id(), &get_event_msg!(struct_a, MessageSendEvent::SendShutdown, node_b.get_our_node_id())).unwrap();

		let events_1 = node_b.get_and_clear_pending_msg_events();
		assert!(events_1.len() >= 1);
		let shutdown_b = match events_1[0] {
			MessageSendEvent::SendShutdown { ref node_id, ref msg } => {
				assert_eq!(node_id, &node_a.get_our_node_id());
				msg.clone()
			},
			_ => panic!("Unexpected event"),
		};

		let closing_signed_b = if !close_inbound_first {
			assert_eq!(events_1.len(), 1);
			None
		} else {
			Some(match events_1[1] {
				MessageSendEvent::SendClosingSigned { ref node_id, ref msg } => {
					assert_eq!(node_id, &node_a.get_our_node_id());
					msg.clone()
				},
				_ => panic!("Unexpected event"),
			})
		};

		node_a.handle_shutdown(&node_b.get_our_node_id(), &shutdown_b).unwrap();
		let (as_update, bs_update) = if close_inbound_first {
			assert!(node_a.get_and_clear_pending_msg_events().is_empty());
			node_a.handle_closing_signed(&node_b.get_our_node_id(), &closing_signed_b.unwrap()).unwrap();
			assert_eq!(broadcaster_a.txn_broadcasted.lock().unwrap().len(), 1);
			tx_a = broadcaster_a.txn_broadcasted.lock().unwrap().remove(0);
			let (as_update, closing_signed_a) = get_closing_signed_broadcast!(node_a, node_b.get_our_node_id());

			node_b.handle_closing_signed(&node_a.get_our_node_id(), &closing_signed_a.unwrap()).unwrap();
			let (bs_update, none_b) = get_closing_signed_broadcast!(node_b, node_a.get_our_node_id());
			assert!(none_b.is_none());
			assert_eq!(broadcaster_b.txn_broadcasted.lock().unwrap().len(), 1);
			tx_b = broadcaster_b.txn_broadcasted.lock().unwrap().remove(0);
			(as_update, bs_update)
		} else {
			let closing_signed_a = get_event_msg!(struct_a, MessageSendEvent::SendClosingSigned, node_b.get_our_node_id());

			node_b.handle_closing_signed(&node_a.get_our_node_id(), &closing_signed_a).unwrap();
			assert_eq!(broadcaster_b.txn_broadcasted.lock().unwrap().len(), 1);
			tx_b = broadcaster_b.txn_broadcasted.lock().unwrap().remove(0);
			let (bs_update, closing_signed_b) = get_closing_signed_broadcast!(node_b, node_a.get_our_node_id());

			node_a.handle_closing_signed(&node_b.get_our_node_id(), &closing_signed_b.unwrap()).unwrap();
			let (as_update, none_a) = get_closing_signed_broadcast!(node_a, node_b.get_our_node_id());
			assert!(none_a.is_none());
			assert_eq!(broadcaster_a.txn_broadcasted.lock().unwrap().len(), 1);
			tx_a = broadcaster_a.txn_broadcasted.lock().unwrap().remove(0);
			(as_update, bs_update)
		};
		assert_eq!(tx_a, tx_b);
		check_spends!(tx_a, funding_tx);

		(as_update, bs_update, tx_a)
	}

	struct SendEvent {
		node_id: PublicKey,
		msgs: Vec<msgs::UpdateAddHTLC>,
		commitment_msg: msgs::CommitmentSigned,
	}
	impl SendEvent {
		fn from_commitment_update(node_id: PublicKey, updates: msgs::CommitmentUpdate) -> SendEvent {
			assert!(updates.update_fulfill_htlcs.is_empty());
			assert!(updates.update_fail_htlcs.is_empty());
			assert!(updates.update_fail_malformed_htlcs.is_empty());
			assert!(updates.update_fee.is_none());
			SendEvent { node_id: node_id, msgs: updates.update_add_htlcs, commitment_msg: updates.commitment_signed }
		}

		fn from_event(event: MessageSendEvent) -> SendEvent {
			match event {
				MessageSendEvent::UpdateHTLCs { node_id, updates } => SendEvent::from_commitment_update(node_id, updates),
				_ => panic!("Unexpected event type!"),
			}
		}
	}

	macro_rules! check_added_monitors {
		($node: expr, $count: expr) => {
			{
				let mut added_monitors = $node.chan_monitor.added_monitors.lock().unwrap();
				assert_eq!(added_monitors.len(), $count);
				added_monitors.clear();
			}
		}
	}

	macro_rules! commitment_signed_dance {
		($node_a: expr, $node_b: expr, $commitment_signed: expr, $fail_backwards: expr, true /* skip last step */) => {
			{
				check_added_monitors!($node_a, 0);
				assert!($node_a.node.get_and_clear_pending_msg_events().is_empty());
				$node_a.node.handle_commitment_signed(&$node_b.node.get_our_node_id(), &$commitment_signed).unwrap();
				check_added_monitors!($node_a, 1);
				commitment_signed_dance!($node_a, $node_b, (), $fail_backwards, true, false);
			}
		};
		($node_a: expr, $node_b: expr, (), $fail_backwards: expr, true /* skip last step */, true /* return extra message */) => {
			{
				let (as_revoke_and_ack, as_commitment_signed) = get_revoke_commit_msgs!($node_a, $node_b.node.get_our_node_id());
				check_added_monitors!($node_b, 0);
				assert!($node_b.node.get_and_clear_pending_msg_events().is_empty());
				$node_b.node.handle_revoke_and_ack(&$node_a.node.get_our_node_id(), &as_revoke_and_ack).unwrap();
				assert!($node_b.node.get_and_clear_pending_msg_events().is_empty());
				check_added_monitors!($node_b, 1);
				$node_b.node.handle_commitment_signed(&$node_a.node.get_our_node_id(), &as_commitment_signed).unwrap();
				let (bs_revoke_and_ack, extra_msg_option) = {
					let events = $node_b.node.get_and_clear_pending_msg_events();
					assert!(events.len() <= 2);
					(match events[0] {
						MessageSendEvent::SendRevokeAndACK { ref node_id, ref msg } => {
							assert_eq!(*node_id, $node_a.node.get_our_node_id());
							(*msg).clone()
						},
						_ => panic!("Unexpected event"),
					}, events.get(1).map(|e| e.clone()))
				};
				check_added_monitors!($node_b, 1);
				if $fail_backwards {
					assert!($node_a.node.get_and_clear_pending_events().is_empty());
					assert!($node_a.node.get_and_clear_pending_msg_events().is_empty());
				}
				$node_a.node.handle_revoke_and_ack(&$node_b.node.get_our_node_id(), &bs_revoke_and_ack).unwrap();
				{
					let mut added_monitors = $node_a.chan_monitor.added_monitors.lock().unwrap();
					if $fail_backwards {
						assert_eq!(added_monitors.len(), 2);
						assert!(added_monitors[0].0 != added_monitors[1].0);
					} else {
						assert_eq!(added_monitors.len(), 1);
					}
					added_monitors.clear();
				}
				extra_msg_option
			}
		};
		($node_a: expr, $node_b: expr, (), $fail_backwards: expr, true /* skip last step */, false /* no extra message */) => {
			{
				assert!(commitment_signed_dance!($node_a, $node_b, (), $fail_backwards, true, true).is_none());
			}
		};
		($node_a: expr, $node_b: expr, $commitment_signed: expr, $fail_backwards: expr) => {
			{
				commitment_signed_dance!($node_a, $node_b, $commitment_signed, $fail_backwards, true);
				if $fail_backwards {
					let channel_state = $node_a.node.channel_state.lock().unwrap();
					assert_eq!(channel_state.pending_msg_events.len(), 1);
					if let MessageSendEvent::UpdateHTLCs { ref node_id, .. } = channel_state.pending_msg_events[0] {
						assert_ne!(*node_id, $node_b.node.get_our_node_id());
					} else { panic!("Unexpected event"); }
				} else {
					assert!($node_a.node.get_and_clear_pending_msg_events().is_empty());
				}
			}
		}
	}

	macro_rules! get_payment_preimage_hash {
		($node: expr) => {
			{
				let payment_preimage = [*$node.network_payment_count.borrow(); 32];
				*$node.network_payment_count.borrow_mut() += 1;
				let mut payment_hash = [0; 32];
				let mut sha = Sha256::new();
				sha.input(&payment_preimage[..]);
				sha.result(&mut payment_hash);
				(payment_preimage, payment_hash)
			}
		}
	}

	fn send_along_route(origin_node: &Node, route: Route, expected_route: &[&Node], recv_value: u64) -> ([u8; 32], [u8; 32]) {
		let (our_payment_preimage, our_payment_hash) = get_payment_preimage_hash!(origin_node);

		let mut payment_event = {
			origin_node.node.send_payment(route, our_payment_hash).unwrap();
			check_added_monitors!(origin_node, 1);

			let mut events = origin_node.node.get_and_clear_pending_msg_events();
			assert_eq!(events.len(), 1);
			SendEvent::from_event(events.remove(0))
		};
		let mut prev_node = origin_node;

		for (idx, &node) in expected_route.iter().enumerate() {
			assert_eq!(node.node.get_our_node_id(), payment_event.node_id);

			node.node.handle_update_add_htlc(&prev_node.node.get_our_node_id(), &payment_event.msgs[0]).unwrap();
			check_added_monitors!(node, 0);
			commitment_signed_dance!(node, prev_node, payment_event.commitment_msg, false);

			let events_1 = node.node.get_and_clear_pending_events();
			assert_eq!(events_1.len(), 1);
			match events_1[0] {
				Event::PendingHTLCsForwardable { .. } => { },
				_ => panic!("Unexpected event"),
			};

			node.node.channel_state.lock().unwrap().next_forward = Instant::now();
			node.node.process_pending_htlc_forwards();

			if idx == expected_route.len() - 1 {
				let events_2 = node.node.get_and_clear_pending_events();
				assert_eq!(events_2.len(), 1);
				match events_2[0] {
					Event::PaymentReceived { ref payment_hash, amt } => {
						assert_eq!(our_payment_hash, *payment_hash);
						assert_eq!(amt, recv_value);
					},
					_ => panic!("Unexpected event"),
				}
			} else {
				let mut events_2 = node.node.get_and_clear_pending_msg_events();
				assert_eq!(events_2.len(), 1);
				check_added_monitors!(node, 1);
				payment_event = SendEvent::from_event(events_2.remove(0));
				assert_eq!(payment_event.msgs.len(), 1);
			}

			prev_node = node;
		}

		(our_payment_preimage, our_payment_hash)
	}

	fn claim_payment_along_route(origin_node: &Node, expected_route: &[&Node], skip_last: bool, our_payment_preimage: [u8; 32]) {
		assert!(expected_route.last().unwrap().node.claim_funds(our_payment_preimage));
		check_added_monitors!(expected_route.last().unwrap(), 1);

		let mut next_msgs: Option<(msgs::UpdateFulfillHTLC, msgs::CommitmentSigned)> = None;
		let mut expected_next_node = expected_route.last().unwrap().node.get_our_node_id();
		macro_rules! get_next_msgs {
			($node: expr) => {
				{
					let events = $node.node.get_and_clear_pending_msg_events();
					assert_eq!(events.len(), 1);
					match events[0] {
						MessageSendEvent::UpdateHTLCs { ref node_id, updates: msgs::CommitmentUpdate { ref update_add_htlcs, ref update_fulfill_htlcs, ref update_fail_htlcs, ref update_fail_malformed_htlcs, ref update_fee, ref commitment_signed } } => {
							assert!(update_add_htlcs.is_empty());
							assert_eq!(update_fulfill_htlcs.len(), 1);
							assert!(update_fail_htlcs.is_empty());
							assert!(update_fail_malformed_htlcs.is_empty());
							assert!(update_fee.is_none());
							expected_next_node = node_id.clone();
							Some((update_fulfill_htlcs[0].clone(), commitment_signed.clone()))
						},
						_ => panic!("Unexpected event"),
					}
				}
			}
		}

		macro_rules! last_update_fulfill_dance {
			($node: expr, $prev_node: expr) => {
				{
					$node.node.handle_update_fulfill_htlc(&$prev_node.node.get_our_node_id(), &next_msgs.as_ref().unwrap().0).unwrap();
					check_added_monitors!($node, 0);
					assert!($node.node.get_and_clear_pending_msg_events().is_empty());
					commitment_signed_dance!($node, $prev_node, next_msgs.as_ref().unwrap().1, false);
				}
			}
		}
		macro_rules! mid_update_fulfill_dance {
			($node: expr, $prev_node: expr, $new_msgs: expr) => {
				{
					$node.node.handle_update_fulfill_htlc(&$prev_node.node.get_our_node_id(), &next_msgs.as_ref().unwrap().0).unwrap();
					check_added_monitors!($node, 1);
					let new_next_msgs = if $new_msgs {
						get_next_msgs!($node)
					} else {
						assert!($node.node.get_and_clear_pending_msg_events().is_empty());
						None
					};
					commitment_signed_dance!($node, $prev_node, next_msgs.as_ref().unwrap().1, false);
					next_msgs = new_next_msgs;
				}
			}
		}

		let mut prev_node = expected_route.last().unwrap();
		for (idx, node) in expected_route.iter().rev().enumerate() {
			assert_eq!(expected_next_node, node.node.get_our_node_id());
			let update_next_msgs = !skip_last || idx != expected_route.len() - 1;
			if next_msgs.is_some() {
				mid_update_fulfill_dance!(node, prev_node, update_next_msgs);
			} else if update_next_msgs {
				next_msgs = get_next_msgs!(node);
			} else {
				assert!(node.node.get_and_clear_pending_msg_events().is_empty());
			}
			if !skip_last && idx == expected_route.len() - 1 {
				assert_eq!(expected_next_node, origin_node.node.get_our_node_id());
			}

			prev_node = node;
		}

		if !skip_last {
			last_update_fulfill_dance!(origin_node, expected_route.first().unwrap());
			let events = origin_node.node.get_and_clear_pending_events();
			assert_eq!(events.len(), 1);
			match events[0] {
				Event::PaymentSent { payment_preimage } => {
					assert_eq!(payment_preimage, our_payment_preimage);
				},
				_ => panic!("Unexpected event"),
			}
		}
	}

	fn claim_payment(origin_node: &Node, expected_route: &[&Node], our_payment_preimage: [u8; 32]) {
		claim_payment_along_route(origin_node, expected_route, false, our_payment_preimage);
	}

	const TEST_FINAL_CLTV: u32 = 32;

	fn route_payment(origin_node: &Node, expected_route: &[&Node], recv_value: u64) -> ([u8; 32], [u8; 32]) {
		let route = origin_node.router.get_route(&expected_route.last().unwrap().node.get_our_node_id(), None, &Vec::new(), recv_value, TEST_FINAL_CLTV).unwrap();
		assert_eq!(route.hops.len(), expected_route.len());
		for (node, hop) in expected_route.iter().zip(route.hops.iter()) {
			assert_eq!(hop.pubkey, node.node.get_our_node_id());
		}

		send_along_route(origin_node, route, expected_route, recv_value)
	}

	fn route_over_limit(origin_node: &Node, expected_route: &[&Node], recv_value: u64) {
		let route = origin_node.router.get_route(&expected_route.last().unwrap().node.get_our_node_id(), None, &Vec::new(), recv_value, TEST_FINAL_CLTV).unwrap();
		assert_eq!(route.hops.len(), expected_route.len());
		for (node, hop) in expected_route.iter().zip(route.hops.iter()) {
			assert_eq!(hop.pubkey, node.node.get_our_node_id());
		}

		let (_, our_payment_hash) = get_payment_preimage_hash!(origin_node);

		let err = origin_node.node.send_payment(route, our_payment_hash).err().unwrap();
		match err {
			APIError::ChannelUnavailable{err} => assert_eq!(err, "Cannot send value that would put us over our max HTLC value in flight"),
			_ => panic!("Unknown error variants"),
		};
	}

	fn send_payment(origin: &Node, expected_route: &[&Node], recv_value: u64) {
		let our_payment_preimage = route_payment(&origin, expected_route, recv_value).0;
		claim_payment(&origin, expected_route, our_payment_preimage);
	}

	fn fail_payment_along_route(origin_node: &Node, expected_route: &[&Node], skip_last: bool, our_payment_hash: [u8; 32]) {
		assert!(expected_route.last().unwrap().node.fail_htlc_backwards(&our_payment_hash, PaymentFailReason::PreimageUnknown));
		check_added_monitors!(expected_route.last().unwrap(), 1);

		let mut next_msgs: Option<(msgs::UpdateFailHTLC, msgs::CommitmentSigned)> = None;
		macro_rules! update_fail_dance {
			($node: expr, $prev_node: expr, $last_node: expr) => {
				{
					$node.node.handle_update_fail_htlc(&$prev_node.node.get_our_node_id(), &next_msgs.as_ref().unwrap().0).unwrap();
					commitment_signed_dance!($node, $prev_node, next_msgs.as_ref().unwrap().1, !$last_node);
				}
			}
		}

		let mut expected_next_node = expected_route.last().unwrap().node.get_our_node_id();
		let mut prev_node = expected_route.last().unwrap();
		for (idx, node) in expected_route.iter().rev().enumerate() {
			assert_eq!(expected_next_node, node.node.get_our_node_id());
			if next_msgs.is_some() {
				// We may be the "last node" for the purpose of the commitment dance if we're
				// skipping the last node (implying it is disconnected) and we're the
				// second-to-last node!
				update_fail_dance!(node, prev_node, skip_last && idx == expected_route.len() - 1);
			}

			let events = node.node.get_and_clear_pending_msg_events();
			if !skip_last || idx != expected_route.len() - 1 {
				assert_eq!(events.len(), 1);
				match events[0] {
					MessageSendEvent::UpdateHTLCs { ref node_id, updates: msgs::CommitmentUpdate { ref update_add_htlcs, ref update_fulfill_htlcs, ref update_fail_htlcs, ref update_fail_malformed_htlcs, ref update_fee, ref commitment_signed } } => {
						assert!(update_add_htlcs.is_empty());
						assert!(update_fulfill_htlcs.is_empty());
						assert_eq!(update_fail_htlcs.len(), 1);
						assert!(update_fail_malformed_htlcs.is_empty());
						assert!(update_fee.is_none());
						expected_next_node = node_id.clone();
						next_msgs = Some((update_fail_htlcs[0].clone(), commitment_signed.clone()));
					},
					_ => panic!("Unexpected event"),
				}
			} else {
				assert!(events.is_empty());
			}
			if !skip_last && idx == expected_route.len() - 1 {
				assert_eq!(expected_next_node, origin_node.node.get_our_node_id());
			}

			prev_node = node;
		}

		if !skip_last {
			update_fail_dance!(origin_node, expected_route.first().unwrap(), true);

			let events = origin_node.node.get_and_clear_pending_events();
			assert_eq!(events.len(), 1);
			match events[0] {
				Event::PaymentFailed { payment_hash, rejected_by_dest } => {
					assert_eq!(payment_hash, our_payment_hash);
					assert!(rejected_by_dest);
				},
				_ => panic!("Unexpected event"),
			}
		}
	}

	fn fail_payment(origin_node: &Node, expected_route: &[&Node], our_payment_hash: [u8; 32]) {
		fail_payment_along_route(origin_node, expected_route, false, our_payment_hash);
	}

	fn create_network(node_count: usize) -> Vec<Node> {
		let mut nodes = Vec::new();
		let mut rng = thread_rng();
		let secp_ctx = Secp256k1::new();
		let logger: Arc<Logger> = Arc::new(test_utils::TestLogger::new());

		let chan_count = Rc::new(RefCell::new(0));
		let payment_count = Rc::new(RefCell::new(0));

		for _ in 0..node_count {
			let feeest = Arc::new(test_utils::TestFeeEstimator { sat_per_kw: 253 });
			let chain_monitor = Arc::new(chaininterface::ChainWatchInterfaceUtil::new(Network::Testnet, Arc::clone(&logger)));
			let tx_broadcaster = Arc::new(test_utils::TestBroadcaster{txn_broadcasted: Mutex::new(Vec::new())});
			let mut seed = [0; 32];
			rng.fill_bytes(&mut seed);
			let keys_manager = Arc::new(keysinterface::KeysManager::new(&seed, Network::Testnet, Arc::clone(&logger)));
			let chan_monitor = Arc::new(test_utils::TestChannelMonitor::new(chain_monitor.clone(), tx_broadcaster.clone(), logger.clone()));
			let mut config = UserConfig::new();
			config.channel_options.announced_channel = true;
			config.channel_limits.force_announced_channel_preference = false;
			let node = ChannelManager::new(Network::Testnet, feeest.clone(), chan_monitor.clone(), chain_monitor.clone(), tx_broadcaster.clone(), Arc::clone(&logger), keys_manager.clone(), config).unwrap();
			let router = Router::new(PublicKey::from_secret_key(&secp_ctx, &keys_manager.get_node_secret()), chain_monitor.clone(), Arc::clone(&logger));
			nodes.push(Node { chain_monitor, tx_broadcaster, chan_monitor, node, router, node_seed: seed,
				network_payment_count: payment_count.clone(),
				network_chan_count: chan_count.clone(),
			});
		}

		nodes
	}

	#[test]
	fn test_async_inbound_update_fee() {
		let mut nodes = create_network(2);
		let chan = create_announced_chan_between_nodes(&nodes, 0, 1);
		let channel_id = chan.2;

		// balancing
		send_payment(&nodes[0], &vec!(&nodes[1])[..], 8000000);

		// A                                        B
		// update_fee                            ->
		// send (1) commitment_signed            -.
		//                                       <- update_add_htlc/commitment_signed
		// send (2) RAA (awaiting remote revoke) -.
		// (1) commitment_signed is delivered    ->
		//                                       .- send (3) RAA (awaiting remote revoke)
		// (2) RAA is delivered                  ->
		//                                       .- send (4) commitment_signed
		//                                       <- (3) RAA is delivered
		// send (5) commitment_signed            -.
		//                                       <- (4) commitment_signed is delivered
		// send (6) RAA                          -.
		// (5) commitment_signed is delivered    ->
		//                                       <- RAA
		// (6) RAA is delivered                  ->

		// First nodes[0] generates an update_fee
		nodes[0].node.update_fee(channel_id, get_feerate!(nodes[0], channel_id) + 20).unwrap();
		check_added_monitors!(nodes[0], 1);

		let events_0 = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(events_0.len(), 1);
		let (update_msg, commitment_signed) = match events_0[0] { // (1)
			MessageSendEvent::UpdateHTLCs { updates: msgs::CommitmentUpdate { ref update_fee, ref commitment_signed, .. }, .. } => {
				(update_fee.as_ref(), commitment_signed)
			},
			_ => panic!("Unexpected event"),
		};

		nodes[1].node.handle_update_fee(&nodes[0].node.get_our_node_id(), update_msg.unwrap()).unwrap();

		// ...but before it's delivered, nodes[1] starts to send a payment back to nodes[0]...
		let (_, our_payment_hash) = get_payment_preimage_hash!(nodes[0]);
		nodes[1].node.send_payment(nodes[1].router.get_route(&nodes[0].node.get_our_node_id(), None, &Vec::new(), 40000, TEST_FINAL_CLTV).unwrap(), our_payment_hash).unwrap();
		check_added_monitors!(nodes[1], 1);

		let payment_event = {
			let mut events_1 = nodes[1].node.get_and_clear_pending_msg_events();
			assert_eq!(events_1.len(), 1);
			SendEvent::from_event(events_1.remove(0))
		};
		assert_eq!(payment_event.node_id, nodes[0].node.get_our_node_id());
		assert_eq!(payment_event.msgs.len(), 1);

		// ...now when the messages get delivered everyone should be happy
		nodes[0].node.handle_update_add_htlc(&nodes[1].node.get_our_node_id(), &payment_event.msgs[0]).unwrap();
		nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &payment_event.commitment_msg).unwrap(); // (2)
		let as_revoke_and_ack = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());
		// nodes[0] is awaiting nodes[1] revoke_and_ack so get_event_msg's assert(len == 1) passes
		check_added_monitors!(nodes[0], 1);

		// deliver(1), generate (3):
		nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), commitment_signed).unwrap();
		let bs_revoke_and_ack = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, nodes[0].node.get_our_node_id());
		// nodes[1] is awaiting nodes[0] revoke_and_ack so get_event_msg's assert(len == 1) passes
		check_added_monitors!(nodes[1], 1);

		nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &as_revoke_and_ack).unwrap(); // deliver (2)
		let bs_update = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
		assert!(bs_update.update_add_htlcs.is_empty()); // (4)
		assert!(bs_update.update_fulfill_htlcs.is_empty()); // (4)
		assert!(bs_update.update_fail_htlcs.is_empty()); // (4)
		assert!(bs_update.update_fail_malformed_htlcs.is_empty()); // (4)
		assert!(bs_update.update_fee.is_none()); // (4)
		check_added_monitors!(nodes[1], 1);

		nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_revoke_and_ack).unwrap(); // deliver (3)
		let as_update = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
		assert!(as_update.update_add_htlcs.is_empty()); // (5)
		assert!(as_update.update_fulfill_htlcs.is_empty()); // (5)
		assert!(as_update.update_fail_htlcs.is_empty()); // (5)
		assert!(as_update.update_fail_malformed_htlcs.is_empty()); // (5)
		assert!(as_update.update_fee.is_none()); // (5)
		check_added_monitors!(nodes[0], 1);

		nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &bs_update.commitment_signed).unwrap(); // deliver (4)
		let as_second_revoke = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());
		// only (6) so get_event_msg's assert(len == 1) passes
		check_added_monitors!(nodes[0], 1);

		nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &as_update.commitment_signed).unwrap(); // deliver (5)
		let bs_second_revoke = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, nodes[0].node.get_our_node_id());
		check_added_monitors!(nodes[1], 1);

		nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_second_revoke).unwrap();
		check_added_monitors!(nodes[0], 1);

		let events_2 = nodes[0].node.get_and_clear_pending_events();
		assert_eq!(events_2.len(), 1);
		match events_2[0] {
			Event::PendingHTLCsForwardable {..} => {}, // If we actually processed we'd receive the payment
			_ => panic!("Unexpected event"),
		}

		nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &as_second_revoke).unwrap(); // deliver (6)
		check_added_monitors!(nodes[1], 1);
	}

	#[test]
	fn test_update_fee_unordered_raa() {
		// Just the intro to the previous test followed by an out-of-order RAA (which caused a
		// crash in an earlier version of the update_fee patch)
		let mut nodes = create_network(2);
		let chan = create_announced_chan_between_nodes(&nodes, 0, 1);
		let channel_id = chan.2;

		// balancing
		send_payment(&nodes[0], &vec!(&nodes[1])[..], 8000000);

		// First nodes[0] generates an update_fee
		nodes[0].node.update_fee(channel_id, get_feerate!(nodes[0], channel_id) + 20).unwrap();
		check_added_monitors!(nodes[0], 1);

		let events_0 = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(events_0.len(), 1);
		let update_msg = match events_0[0] { // (1)
			MessageSendEvent::UpdateHTLCs { updates: msgs::CommitmentUpdate { ref update_fee, .. }, .. } => {
				update_fee.as_ref()
			},
			_ => panic!("Unexpected event"),
		};

		nodes[1].node.handle_update_fee(&nodes[0].node.get_our_node_id(), update_msg.unwrap()).unwrap();

		// ...but before it's delivered, nodes[1] starts to send a payment back to nodes[0]...
		let (_, our_payment_hash) = get_payment_preimage_hash!(nodes[0]);
		nodes[1].node.send_payment(nodes[1].router.get_route(&nodes[0].node.get_our_node_id(), None, &Vec::new(), 40000, TEST_FINAL_CLTV).unwrap(), our_payment_hash).unwrap();
		check_added_monitors!(nodes[1], 1);

		let payment_event = {
			let mut events_1 = nodes[1].node.get_and_clear_pending_msg_events();
			assert_eq!(events_1.len(), 1);
			SendEvent::from_event(events_1.remove(0))
		};
		assert_eq!(payment_event.node_id, nodes[0].node.get_our_node_id());
		assert_eq!(payment_event.msgs.len(), 1);

		// ...now when the messages get delivered everyone should be happy
		nodes[0].node.handle_update_add_htlc(&nodes[1].node.get_our_node_id(), &payment_event.msgs[0]).unwrap();
		nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &payment_event.commitment_msg).unwrap(); // (2)
		let as_revoke_msg = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());
		// nodes[0] is awaiting nodes[1] revoke_and_ack so get_event_msg's assert(len == 1) passes
		check_added_monitors!(nodes[0], 1);

		nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &as_revoke_msg).unwrap(); // deliver (2)
		check_added_monitors!(nodes[1], 1);

		// We can't continue, sadly, because our (1) now has a bogus signature
	}

	#[test]
	fn test_multi_flight_update_fee() {
		let nodes = create_network(2);
		let chan = create_announced_chan_between_nodes(&nodes, 0, 1);
		let channel_id = chan.2;

		// A                                        B
		// update_fee/commitment_signed          ->
		//                                       .- send (1) RAA and (2) commitment_signed
		// update_fee (never committed)          ->
		// (3) update_fee                        ->
		// We have to manually generate the above update_fee, it is allowed by the protocol but we
		// don't track which updates correspond to which revoke_and_ack responses so we're in
		// AwaitingRAA mode and will not generate the update_fee yet.
		//                                       <- (1) RAA delivered
		// (3) is generated and send (4) CS      -.
		// Note that A cannot generate (4) prior to (1) being delivered as it otherwise doesn't
		// know the per_commitment_point to use for it.
		//                                       <- (2) commitment_signed delivered
		// revoke_and_ack                        ->
		//                                          B should send no response here
		// (4) commitment_signed delivered       ->
		//                                       <- RAA/commitment_signed delivered
		// revoke_and_ack                        ->

		// First nodes[0] generates an update_fee
		let initial_feerate = get_feerate!(nodes[0], channel_id);
		nodes[0].node.update_fee(channel_id, initial_feerate + 20).unwrap();
		check_added_monitors!(nodes[0], 1);

		let events_0 = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(events_0.len(), 1);
		let (update_msg_1, commitment_signed_1) = match events_0[0] { // (1)
			MessageSendEvent::UpdateHTLCs { updates: msgs::CommitmentUpdate { ref update_fee, ref commitment_signed, .. }, .. } => {
				(update_fee.as_ref().unwrap(), commitment_signed)
			},
			_ => panic!("Unexpected event"),
		};

		// Deliver first update_fee/commitment_signed pair, generating (1) and (2):
		nodes[1].node.handle_update_fee(&nodes[0].node.get_our_node_id(), update_msg_1).unwrap();
		nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), commitment_signed_1).unwrap();
		let (bs_revoke_msg, bs_commitment_signed) = get_revoke_commit_msgs!(nodes[1], nodes[0].node.get_our_node_id());
		check_added_monitors!(nodes[1], 1);

		// nodes[0] is awaiting a revoke from nodes[1] before it will create a new commitment
		// transaction:
		nodes[0].node.update_fee(channel_id, initial_feerate + 40).unwrap();
		assert!(nodes[0].node.get_and_clear_pending_events().is_empty());
		assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());

		// Create the (3) update_fee message that nodes[0] will generate before it does...
		let mut update_msg_2 = msgs::UpdateFee {
			channel_id: update_msg_1.channel_id.clone(),
			feerate_per_kw: (initial_feerate + 30) as u32,
		};

		nodes[1].node.handle_update_fee(&nodes[0].node.get_our_node_id(), &update_msg_2).unwrap();

		update_msg_2.feerate_per_kw = (initial_feerate + 40) as u32;
		// Deliver (3)
		nodes[1].node.handle_update_fee(&nodes[0].node.get_our_node_id(), &update_msg_2).unwrap();

		// Deliver (1), generating (3) and (4)
		nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_revoke_msg).unwrap();
		let as_second_update = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
		check_added_monitors!(nodes[0], 1);
		assert!(as_second_update.update_add_htlcs.is_empty());
		assert!(as_second_update.update_fulfill_htlcs.is_empty());
		assert!(as_second_update.update_fail_htlcs.is_empty());
		assert!(as_second_update.update_fail_malformed_htlcs.is_empty());
		// Check that the update_fee newly generated matches what we delivered:
		assert_eq!(as_second_update.update_fee.as_ref().unwrap().channel_id, update_msg_2.channel_id);
		assert_eq!(as_second_update.update_fee.as_ref().unwrap().feerate_per_kw, update_msg_2.feerate_per_kw);

		// Deliver (2) commitment_signed
		nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &bs_commitment_signed).unwrap();
		let as_revoke_msg = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());
		check_added_monitors!(nodes[0], 1);
		// No commitment_signed so get_event_msg's assert(len == 1) passes

		nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &as_revoke_msg).unwrap();
		assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
		check_added_monitors!(nodes[1], 1);

		// Delever (4)
		nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &as_second_update.commitment_signed).unwrap();
		let (bs_second_revoke, bs_second_commitment) = get_revoke_commit_msgs!(nodes[1], nodes[0].node.get_our_node_id());
		check_added_monitors!(nodes[1], 1);

		nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_second_revoke).unwrap();
		assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
		check_added_monitors!(nodes[0], 1);

		nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &bs_second_commitment).unwrap();
		let as_second_revoke = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());
		// No commitment_signed so get_event_msg's assert(len == 1) passes
		check_added_monitors!(nodes[0], 1);

		nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &as_second_revoke).unwrap();
		assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
		check_added_monitors!(nodes[1], 1);
	}

	#[test]
	fn test_update_fee_vanilla() {
		let nodes = create_network(2);
		let chan = create_announced_chan_between_nodes(&nodes, 0, 1);
		let channel_id = chan.2;

		let feerate = get_feerate!(nodes[0], channel_id);
		nodes[0].node.update_fee(channel_id, feerate+25).unwrap();
		check_added_monitors!(nodes[0], 1);

		let events_0 = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(events_0.len(), 1);
		let (update_msg, commitment_signed) = match events_0[0] {
				MessageSendEvent::UpdateHTLCs { node_id:_, updates: msgs::CommitmentUpdate { update_add_htlcs:_, update_fulfill_htlcs:_, update_fail_htlcs:_, update_fail_malformed_htlcs:_, ref update_fee, ref commitment_signed } } => {
				(update_fee.as_ref(), commitment_signed)
			},
			_ => panic!("Unexpected event"),
		};
		nodes[1].node.handle_update_fee(&nodes[0].node.get_our_node_id(), update_msg.unwrap()).unwrap();

		nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), commitment_signed).unwrap();
		let (revoke_msg, commitment_signed) = get_revoke_commit_msgs!(nodes[1], nodes[0].node.get_our_node_id());
		check_added_monitors!(nodes[1], 1);

		nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &revoke_msg).unwrap();
		assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
		check_added_monitors!(nodes[0], 1);

		nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &commitment_signed).unwrap();
		let revoke_msg = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());
		// No commitment_signed so get_event_msg's assert(len == 1) passes
		check_added_monitors!(nodes[0], 1);

		nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &revoke_msg).unwrap();
		assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
		check_added_monitors!(nodes[1], 1);
	}

	#[test]
	fn test_update_fee_that_funder_cannot_afford() {
		let nodes = create_network(2);
		let channel_value = 1888;
		let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, channel_value, 700000);
		let channel_id = chan.2;

		let feerate = 260;
		nodes[0].node.update_fee(channel_id, feerate).unwrap();
		check_added_monitors!(nodes[0], 1);
		let update_msg = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());

		nodes[1].node.handle_update_fee(&nodes[0].node.get_our_node_id(), &update_msg.update_fee.unwrap()).unwrap();

		commitment_signed_dance!(nodes[1], nodes[0], update_msg.commitment_signed, false);

		//Confirm that the new fee based on the last local commitment txn is what we expected based on the feerate of 260 set above.
		//This value results in a fee that is exactly what the funder can afford (277 sat + 1000 sat channel reserve)
		{
			let chan_lock = nodes[1].node.channel_state.lock().unwrap();
			let chan = chan_lock.by_id.get(&channel_id).unwrap();

			//We made sure neither party's funds are below the dust limit so -2 non-HTLC txns from number of outputs
			let num_htlcs = chan.last_local_commitment_txn[0].output.len() - 2;
			let total_fee: u64 = feerate * (COMMITMENT_TX_BASE_WEIGHT + (num_htlcs as u64) * COMMITMENT_TX_WEIGHT_PER_HTLC) / 1000;
			let mut actual_fee = chan.last_local_commitment_txn[0].output.iter().fold(0, |acc, output| acc + output.value);
			actual_fee = channel_value - actual_fee;
			assert_eq!(total_fee, actual_fee);
		} //drop the mutex

		//Add 2 to the previous fee rate to the final fee increases by 1 (with no HTLCs the fee is essentially
		//fee_rate*(724/1000) so the increment of 1*0.724 is rounded back down)
		nodes[0].node.update_fee(channel_id, feerate+2).unwrap();
		check_added_monitors!(nodes[0], 1);

		let update2_msg = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());

		nodes[1].node.handle_update_fee(&nodes[0].node.get_our_node_id(), &update2_msg.update_fee.unwrap()).unwrap();

		//While producing the commitment_signed response after handling a received update_fee request the
		//check to see if the funder, who sent the update_fee request, can afford the new fee (funder_balance >= fee+channel_reserve)
		//Should produce and error.
		let err = nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &update2_msg.commitment_signed).unwrap_err();

		assert!(match err.err {
			"Funding remote cannot afford proposed new fee" => true,
			_ => false,
		});

		//clear the message we could not handle
		nodes[1].node.get_and_clear_pending_msg_events();
	}

	#[test]
	fn test_update_fee_with_fundee_update_add_htlc() {
		let mut nodes = create_network(2);
		let chan = create_announced_chan_between_nodes(&nodes, 0, 1);
		let channel_id = chan.2;

		// balancing
		send_payment(&nodes[0], &vec!(&nodes[1])[..], 8000000);

		let feerate = get_feerate!(nodes[0], channel_id);
		nodes[0].node.update_fee(channel_id, feerate+20).unwrap();
		check_added_monitors!(nodes[0], 1);

		let events_0 = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(events_0.len(), 1);
		let (update_msg, commitment_signed) = match events_0[0] {
				MessageSendEvent::UpdateHTLCs { node_id:_, updates: msgs::CommitmentUpdate { update_add_htlcs:_, update_fulfill_htlcs:_, update_fail_htlcs:_, update_fail_malformed_htlcs:_, ref update_fee, ref commitment_signed } } => {
				(update_fee.as_ref(), commitment_signed)
			},
			_ => panic!("Unexpected event"),
		};
		nodes[1].node.handle_update_fee(&nodes[0].node.get_our_node_id(), update_msg.unwrap()).unwrap();
		nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), commitment_signed).unwrap();
		let (revoke_msg, commitment_signed) = get_revoke_commit_msgs!(nodes[1], nodes[0].node.get_our_node_id());
		check_added_monitors!(nodes[1], 1);

		let route = nodes[1].router.get_route(&nodes[0].node.get_our_node_id(), None, &Vec::new(), 800000, TEST_FINAL_CLTV).unwrap();

		let (our_payment_preimage, our_payment_hash) = get_payment_preimage_hash!(nodes[1]);

		// nothing happens since node[1] is in AwaitingRemoteRevoke
		nodes[1].node.send_payment(route, our_payment_hash).unwrap();
		{
			let mut added_monitors = nodes[0].chan_monitor.added_monitors.lock().unwrap();
			assert_eq!(added_monitors.len(), 0);
			added_monitors.clear();
		}
		assert!(nodes[0].node.get_and_clear_pending_events().is_empty());
		assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
		// node[1] has nothing to do

		nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &revoke_msg).unwrap();
		assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
		check_added_monitors!(nodes[0], 1);

		nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &commitment_signed).unwrap();
		let revoke_msg = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());
		// No commitment_signed so get_event_msg's assert(len == 1) passes
		check_added_monitors!(nodes[0], 1);
		nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &revoke_msg).unwrap();
		check_added_monitors!(nodes[1], 1);
		// AwaitingRemoteRevoke ends here

		let commitment_update = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
		assert_eq!(commitment_update.update_add_htlcs.len(), 1);
		assert_eq!(commitment_update.update_fulfill_htlcs.len(), 0);
		assert_eq!(commitment_update.update_fail_htlcs.len(), 0);
		assert_eq!(commitment_update.update_fail_malformed_htlcs.len(), 0);
		assert_eq!(commitment_update.update_fee.is_none(), true);

		nodes[0].node.handle_update_add_htlc(&nodes[1].node.get_our_node_id(), &commitment_update.update_add_htlcs[0]).unwrap();
		nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &commitment_update.commitment_signed).unwrap();
		check_added_monitors!(nodes[0], 1);
		let (revoke, commitment_signed) = get_revoke_commit_msgs!(nodes[0], nodes[1].node.get_our_node_id());

		nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &revoke).unwrap();
		check_added_monitors!(nodes[1], 1);
		assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

		nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &commitment_signed).unwrap();
		check_added_monitors!(nodes[1], 1);
		let revoke = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, nodes[0].node.get_our_node_id());
		// No commitment_signed so get_event_msg's assert(len == 1) passes

		nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &revoke).unwrap();
		check_added_monitors!(nodes[0], 1);
		assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());

		let events = nodes[0].node.get_and_clear_pending_events();
		assert_eq!(events.len(), 1);
		match events[0] {
			Event::PendingHTLCsForwardable { .. } => { },
			_ => panic!("Unexpected event"),
		};
		nodes[0].node.channel_state.lock().unwrap().next_forward = Instant::now();
		nodes[0].node.process_pending_htlc_forwards();

		let events = nodes[0].node.get_and_clear_pending_events();
		assert_eq!(events.len(), 1);
		match events[0] {
			Event::PaymentReceived { .. } => { },
			_ => panic!("Unexpected event"),
		};

		claim_payment(&nodes[1], &vec!(&nodes[0])[..], our_payment_preimage);

		send_payment(&nodes[1], &vec!(&nodes[0])[..], 800000);
		send_payment(&nodes[0], &vec!(&nodes[1])[..], 800000);
		close_channel(&nodes[0], &nodes[1], &chan.2, chan.3, true);
	}

	#[test]
	fn test_update_fee() {
		let nodes = create_network(2);
		let chan = create_announced_chan_between_nodes(&nodes, 0, 1);
		let channel_id = chan.2;

		// A                                        B
		// (1) update_fee/commitment_signed      ->
		//                                       <- (2) revoke_and_ack
		//                                       .- send (3) commitment_signed
		// (4) update_fee/commitment_signed      ->
		//                                       .- send (5) revoke_and_ack (no CS as we're awaiting a revoke)
		//                                       <- (3) commitment_signed delivered
		// send (6) revoke_and_ack               -.
		//                                       <- (5) deliver revoke_and_ack
		// (6) deliver revoke_and_ack            ->
		//                                       .- send (7) commitment_signed in response to (4)
		//                                       <- (7) deliver commitment_signed
		// revoke_and_ack                        ->

		// Create and deliver (1)...
		let feerate = get_feerate!(nodes[0], channel_id);
		nodes[0].node.update_fee(channel_id, feerate+20).unwrap();
		check_added_monitors!(nodes[0], 1);

		let events_0 = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(events_0.len(), 1);
		let (update_msg, commitment_signed) = match events_0[0] {
				MessageSendEvent::UpdateHTLCs { node_id:_, updates: msgs::CommitmentUpdate { update_add_htlcs:_, update_fulfill_htlcs:_, update_fail_htlcs:_, update_fail_malformed_htlcs:_, ref update_fee, ref commitment_signed } } => {
				(update_fee.as_ref(), commitment_signed)
			},
			_ => panic!("Unexpected event"),
		};
		nodes[1].node.handle_update_fee(&nodes[0].node.get_our_node_id(), update_msg.unwrap()).unwrap();

		// Generate (2) and (3):
		nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), commitment_signed).unwrap();
		let (revoke_msg, commitment_signed_0) = get_revoke_commit_msgs!(nodes[1], nodes[0].node.get_our_node_id());
		check_added_monitors!(nodes[1], 1);

		// Deliver (2):
		nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &revoke_msg).unwrap();
		assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
		check_added_monitors!(nodes[0], 1);

		// Create and deliver (4)...
		nodes[0].node.update_fee(channel_id, feerate+30).unwrap();
		check_added_monitors!(nodes[0], 1);
		let events_0 = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(events_0.len(), 1);
		let (update_msg, commitment_signed) = match events_0[0] {
				MessageSendEvent::UpdateHTLCs { node_id:_, updates: msgs::CommitmentUpdate { update_add_htlcs:_, update_fulfill_htlcs:_, update_fail_htlcs:_, update_fail_malformed_htlcs:_, ref update_fee, ref commitment_signed } } => {
				(update_fee.as_ref(), commitment_signed)
			},
			_ => panic!("Unexpected event"),
		};

		nodes[1].node.handle_update_fee(&nodes[0].node.get_our_node_id(), update_msg.unwrap()).unwrap();
		nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), commitment_signed).unwrap();
		check_added_monitors!(nodes[1], 1);
		// ... creating (5)
		let revoke_msg = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, nodes[0].node.get_our_node_id());
		// No commitment_signed so get_event_msg's assert(len == 1) passes

		// Handle (3), creating (6):
		nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &commitment_signed_0).unwrap();
		check_added_monitors!(nodes[0], 1);
		let revoke_msg_0 = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());
		// No commitment_signed so get_event_msg's assert(len == 1) passes

		// Deliver (5):
		nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &revoke_msg).unwrap();
		assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
		check_added_monitors!(nodes[0], 1);

		// Deliver (6), creating (7):
		nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &revoke_msg_0).unwrap();
		let commitment_update = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
		assert!(commitment_update.update_add_htlcs.is_empty());
		assert!(commitment_update.update_fulfill_htlcs.is_empty());
		assert!(commitment_update.update_fail_htlcs.is_empty());
		assert!(commitment_update.update_fail_malformed_htlcs.is_empty());
		assert!(commitment_update.update_fee.is_none());
		check_added_monitors!(nodes[1], 1);

		// Deliver (7)
		nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &commitment_update.commitment_signed).unwrap();
		check_added_monitors!(nodes[0], 1);
		let revoke_msg = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());
		// No commitment_signed so get_event_msg's assert(len == 1) passes

		nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &revoke_msg).unwrap();
		check_added_monitors!(nodes[1], 1);
		assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

		assert_eq!(get_feerate!(nodes[0], channel_id), feerate + 30);
		assert_eq!(get_feerate!(nodes[1], channel_id), feerate + 30);
		close_channel(&nodes[0], &nodes[1], &chan.2, chan.3, true);
	}

	#[test]
	fn pre_funding_lock_shutdown_test() {
		// Test sending a shutdown prior to funding_locked after funding generation
		let nodes = create_network(2);
		let tx = create_chan_between_nodes_with_value_init(&nodes[0], &nodes[1], 8000000, 0);
		let header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
		nodes[0].chain_monitor.block_connected_checked(&header, 1, &[&tx; 1], &[1; 1]);
		nodes[1].chain_monitor.block_connected_checked(&header, 1, &[&tx; 1], &[1; 1]);

		nodes[0].node.close_channel(&OutPoint::new(tx.txid(), 0).to_channel_id()).unwrap();
		let node_0_shutdown = get_event_msg!(nodes[0], MessageSendEvent::SendShutdown, nodes[1].node.get_our_node_id());
		nodes[1].node.handle_shutdown(&nodes[0].node.get_our_node_id(), &node_0_shutdown).unwrap();
		let node_1_shutdown = get_event_msg!(nodes[1], MessageSendEvent::SendShutdown, nodes[0].node.get_our_node_id());
		nodes[0].node.handle_shutdown(&nodes[1].node.get_our_node_id(), &node_1_shutdown).unwrap();

		let node_0_closing_signed = get_event_msg!(nodes[0], MessageSendEvent::SendClosingSigned, nodes[1].node.get_our_node_id());
		nodes[1].node.handle_closing_signed(&nodes[0].node.get_our_node_id(), &node_0_closing_signed).unwrap();
		let (_, node_1_closing_signed) = get_closing_signed_broadcast!(nodes[1].node, nodes[0].node.get_our_node_id());
		nodes[0].node.handle_closing_signed(&nodes[1].node.get_our_node_id(), &node_1_closing_signed.unwrap()).unwrap();
		let (_, node_0_none) = get_closing_signed_broadcast!(nodes[0].node, nodes[1].node.get_our_node_id());
		assert!(node_0_none.is_none());

		assert!(nodes[0].node.list_channels().is_empty());
		assert!(nodes[1].node.list_channels().is_empty());
	}

	#[test]
	fn updates_shutdown_wait() {
		// Test sending a shutdown with outstanding updates pending
		let mut nodes = create_network(3);
		let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1);
		let chan_2 = create_announced_chan_between_nodes(&nodes, 1, 2);
		let route_1 = nodes[0].router.get_route(&nodes[1].node.get_our_node_id(), None, &[], 100000, TEST_FINAL_CLTV).unwrap();
		let route_2 = nodes[1].router.get_route(&nodes[0].node.get_our_node_id(), None, &[], 100000, TEST_FINAL_CLTV).unwrap();

		let (our_payment_preimage, _) = route_payment(&nodes[0], &[&nodes[1], &nodes[2]], 100000);

		nodes[0].node.close_channel(&chan_1.2).unwrap();
		let node_0_shutdown = get_event_msg!(nodes[0], MessageSendEvent::SendShutdown, nodes[1].node.get_our_node_id());
		nodes[1].node.handle_shutdown(&nodes[0].node.get_our_node_id(), &node_0_shutdown).unwrap();
		let node_1_shutdown = get_event_msg!(nodes[1], MessageSendEvent::SendShutdown, nodes[0].node.get_our_node_id());
		nodes[0].node.handle_shutdown(&nodes[1].node.get_our_node_id(), &node_1_shutdown).unwrap();

		assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
		assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

		let (_, payment_hash) = get_payment_preimage_hash!(nodes[0]);
		if let Err(APIError::ChannelUnavailable {..}) = nodes[0].node.send_payment(route_1, payment_hash) {}
		else { panic!("New sends should fail!") };
		if let Err(APIError::ChannelUnavailable {..}) = nodes[1].node.send_payment(route_2, payment_hash) {}
		else { panic!("New sends should fail!") };

		assert!(nodes[2].node.claim_funds(our_payment_preimage));
		check_added_monitors!(nodes[2], 1);
		let updates = get_htlc_update_msgs!(nodes[2], nodes[1].node.get_our_node_id());
		assert!(updates.update_add_htlcs.is_empty());
		assert!(updates.update_fail_htlcs.is_empty());
		assert!(updates.update_fail_malformed_htlcs.is_empty());
		assert!(updates.update_fee.is_none());
		assert_eq!(updates.update_fulfill_htlcs.len(), 1);
		nodes[1].node.handle_update_fulfill_htlc(&nodes[2].node.get_our_node_id(), &updates.update_fulfill_htlcs[0]).unwrap();
		check_added_monitors!(nodes[1], 1);
		let updates_2 = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
		commitment_signed_dance!(nodes[1], nodes[2], updates.commitment_signed, false);

		assert!(updates_2.update_add_htlcs.is_empty());
		assert!(updates_2.update_fail_htlcs.is_empty());
		assert!(updates_2.update_fail_malformed_htlcs.is_empty());
		assert!(updates_2.update_fee.is_none());
		assert_eq!(updates_2.update_fulfill_htlcs.len(), 1);
		nodes[0].node.handle_update_fulfill_htlc(&nodes[1].node.get_our_node_id(), &updates_2.update_fulfill_htlcs[0]).unwrap();
		commitment_signed_dance!(nodes[0], nodes[1], updates_2.commitment_signed, false, true);

		let events = nodes[0].node.get_and_clear_pending_events();
		assert_eq!(events.len(), 1);
		match events[0] {
			Event::PaymentSent { ref payment_preimage } => {
				assert_eq!(our_payment_preimage, *payment_preimage);
			},
			_ => panic!("Unexpected event"),
		}

		let node_0_closing_signed = get_event_msg!(nodes[0], MessageSendEvent::SendClosingSigned, nodes[1].node.get_our_node_id());
		nodes[1].node.handle_closing_signed(&nodes[0].node.get_our_node_id(), &node_0_closing_signed).unwrap();
		let (_, node_1_closing_signed) = get_closing_signed_broadcast!(nodes[1].node, nodes[0].node.get_our_node_id());
		nodes[0].node.handle_closing_signed(&nodes[1].node.get_our_node_id(), &node_1_closing_signed.unwrap()).unwrap();
		let (_, node_0_none) = get_closing_signed_broadcast!(nodes[0].node, nodes[1].node.get_our_node_id());
		assert!(node_0_none.is_none());

		assert!(nodes[0].node.list_channels().is_empty());

		assert_eq!(nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().len(), 1);
		nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().clear();
		close_channel(&nodes[1], &nodes[2], &chan_2.2, chan_2.3, true);
		assert!(nodes[1].node.list_channels().is_empty());
		assert!(nodes[2].node.list_channels().is_empty());
	}

	#[test]
	fn htlc_fail_async_shutdown() {
		// Test HTLCs fail if shutdown starts even if messages are delivered out-of-order
		let mut nodes = create_network(3);
		let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1);
		let chan_2 = create_announced_chan_between_nodes(&nodes, 1, 2);

		let route = nodes[0].router.get_route(&nodes[2].node.get_our_node_id(), None, &[], 100000, TEST_FINAL_CLTV).unwrap();
		let (_, our_payment_hash) = get_payment_preimage_hash!(nodes[0]);
		nodes[0].node.send_payment(route, our_payment_hash).unwrap();
		check_added_monitors!(nodes[0], 1);
		let updates = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
		assert_eq!(updates.update_add_htlcs.len(), 1);
		assert!(updates.update_fulfill_htlcs.is_empty());
		assert!(updates.update_fail_htlcs.is_empty());
		assert!(updates.update_fail_malformed_htlcs.is_empty());
		assert!(updates.update_fee.is_none());

		nodes[1].node.close_channel(&chan_1.2).unwrap();
		let node_1_shutdown = get_event_msg!(nodes[1], MessageSendEvent::SendShutdown, nodes[0].node.get_our_node_id());
		nodes[0].node.handle_shutdown(&nodes[1].node.get_our_node_id(), &node_1_shutdown).unwrap();
		let node_0_shutdown = get_event_msg!(nodes[0], MessageSendEvent::SendShutdown, nodes[1].node.get_our_node_id());

		nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &updates.update_add_htlcs[0]).unwrap();
		nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &updates.commitment_signed).unwrap();
		check_added_monitors!(nodes[1], 1);
		nodes[1].node.handle_shutdown(&nodes[0].node.get_our_node_id(), &node_0_shutdown).unwrap();
		commitment_signed_dance!(nodes[1], nodes[0], (), false, true, false);

		let updates_2 = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
		assert!(updates_2.update_add_htlcs.is_empty());
		assert!(updates_2.update_fulfill_htlcs.is_empty());
		assert_eq!(updates_2.update_fail_htlcs.len(), 1);
		assert!(updates_2.update_fail_malformed_htlcs.is_empty());
		assert!(updates_2.update_fee.is_none());

		nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &updates_2.update_fail_htlcs[0]).unwrap();
		commitment_signed_dance!(nodes[0], nodes[1], updates_2.commitment_signed, false, true);

		let events = nodes[0].node.get_and_clear_pending_events();
		assert_eq!(events.len(), 1);
		match events[0] {
			Event::PaymentFailed { ref payment_hash, ref rejected_by_dest } => {
				assert_eq!(our_payment_hash, *payment_hash);
				assert!(!rejected_by_dest);
			},
			_ => panic!("Unexpected event"),
		}

		assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
		let node_0_closing_signed = get_event_msg!(nodes[0], MessageSendEvent::SendClosingSigned, nodes[1].node.get_our_node_id());
		nodes[1].node.handle_closing_signed(&nodes[0].node.get_our_node_id(), &node_0_closing_signed).unwrap();
		let (_, node_1_closing_signed) = get_closing_signed_broadcast!(nodes[1].node, nodes[0].node.get_our_node_id());
		nodes[0].node.handle_closing_signed(&nodes[1].node.get_our_node_id(), &node_1_closing_signed.unwrap()).unwrap();
		let (_, node_0_none) = get_closing_signed_broadcast!(nodes[0].node, nodes[1].node.get_our_node_id());
		assert!(node_0_none.is_none());

		assert!(nodes[0].node.list_channels().is_empty());

		assert_eq!(nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().len(), 1);
		nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().clear();
		close_channel(&nodes[1], &nodes[2], &chan_2.2, chan_2.3, true);
		assert!(nodes[1].node.list_channels().is_empty());
		assert!(nodes[2].node.list_channels().is_empty());
	}

	#[test]
	fn update_fee_async_shutdown() {
		// Test update_fee works after shutdown start if messages are delivered out-of-order
		let nodes = create_network(2);
		let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1);

		let starting_feerate = nodes[0].node.channel_state.lock().unwrap().by_id.get(&chan_1.2).unwrap().get_feerate();
		nodes[0].node.update_fee(chan_1.2.clone(), starting_feerate + 20).unwrap();
		check_added_monitors!(nodes[0], 1);
		let updates = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
		assert!(updates.update_add_htlcs.is_empty());
		assert!(updates.update_fulfill_htlcs.is_empty());
		assert!(updates.update_fail_htlcs.is_empty());
		assert!(updates.update_fail_malformed_htlcs.is_empty());
		assert!(updates.update_fee.is_some());

		nodes[1].node.close_channel(&chan_1.2).unwrap();
		let node_1_shutdown = get_event_msg!(nodes[1], MessageSendEvent::SendShutdown, nodes[0].node.get_our_node_id());
		nodes[0].node.handle_shutdown(&nodes[1].node.get_our_node_id(), &node_1_shutdown).unwrap();
		// Note that we don't actually test normative behavior here. The spec indicates we could
		// actually send a closing_signed here, but is kinda unclear and could possibly be amended
		// to require waiting on the full commitment dance before doing so (see
		// https://github.com/lightningnetwork/lightning-rfc/issues/499). In any case, to avoid
		// ambiguity, we should wait until after the full commitment dance to send closing_signed.
		let node_0_shutdown = get_event_msg!(nodes[0], MessageSendEvent::SendShutdown, nodes[1].node.get_our_node_id());

		nodes[1].node.handle_update_fee(&nodes[0].node.get_our_node_id(), &updates.update_fee.unwrap()).unwrap();
		nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &updates.commitment_signed).unwrap();
		check_added_monitors!(nodes[1], 1);
		nodes[1].node.handle_shutdown(&nodes[0].node.get_our_node_id(), &node_0_shutdown).unwrap();
		let node_0_closing_signed = commitment_signed_dance!(nodes[1], nodes[0], (), false, true, true);

		assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
		nodes[1].node.handle_closing_signed(&nodes[0].node.get_our_node_id(), match node_0_closing_signed.unwrap() {
			MessageSendEvent::SendClosingSigned { ref node_id, ref msg } => {
				assert_eq!(*node_id, nodes[1].node.get_our_node_id());
				msg
			},
			_ => panic!("Unexpected event"),
		}).unwrap();
		let (_, node_1_closing_signed) = get_closing_signed_broadcast!(nodes[1].node, nodes[0].node.get_our_node_id());
		nodes[0].node.handle_closing_signed(&nodes[1].node.get_our_node_id(), &node_1_closing_signed.unwrap()).unwrap();
		let (_, node_0_none) = get_closing_signed_broadcast!(nodes[0].node, nodes[1].node.get_our_node_id());
		assert!(node_0_none.is_none());
	}

	fn do_test_shutdown_rebroadcast(recv_count: u8) {
		// Test that shutdown/closing_signed is re-sent on reconnect with a variable number of
		// messages delivered prior to disconnect
		let nodes = create_network(3);
		let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1);
		let chan_2 = create_announced_chan_between_nodes(&nodes, 1, 2);

		let (our_payment_preimage, _) = route_payment(&nodes[0], &[&nodes[1], &nodes[2]], 100000);

		nodes[1].node.close_channel(&chan_1.2).unwrap();
		let node_1_shutdown = get_event_msg!(nodes[1], MessageSendEvent::SendShutdown, nodes[0].node.get_our_node_id());
		if recv_count > 0 {
			nodes[0].node.handle_shutdown(&nodes[1].node.get_our_node_id(), &node_1_shutdown).unwrap();
			let node_0_shutdown = get_event_msg!(nodes[0], MessageSendEvent::SendShutdown, nodes[1].node.get_our_node_id());
			if recv_count > 1 {
				nodes[1].node.handle_shutdown(&nodes[0].node.get_our_node_id(), &node_0_shutdown).unwrap();
			}
		}

		nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id(), false);
		nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);

		nodes[0].node.peer_connected(&nodes[1].node.get_our_node_id());
		let node_0_reestablish = get_event_msg!(nodes[0], MessageSendEvent::SendChannelReestablish, nodes[1].node.get_our_node_id());
		nodes[1].node.peer_connected(&nodes[0].node.get_our_node_id());
		let node_1_reestablish = get_event_msg!(nodes[1], MessageSendEvent::SendChannelReestablish, nodes[0].node.get_our_node_id());

		nodes[1].node.handle_channel_reestablish(&nodes[0].node.get_our_node_id(), &node_0_reestablish).unwrap();
		let node_1_2nd_shutdown = get_event_msg!(nodes[1], MessageSendEvent::SendShutdown, nodes[0].node.get_our_node_id());
		assert!(node_1_shutdown == node_1_2nd_shutdown);

		nodes[0].node.handle_channel_reestablish(&nodes[1].node.get_our_node_id(), &node_1_reestablish).unwrap();
		let node_0_2nd_shutdown = if recv_count > 0 {
			let node_0_2nd_shutdown = get_event_msg!(nodes[0], MessageSendEvent::SendShutdown, nodes[1].node.get_our_node_id());
			nodes[0].node.handle_shutdown(&nodes[1].node.get_our_node_id(), &node_1_2nd_shutdown).unwrap();
			node_0_2nd_shutdown
		} else {
			assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
			nodes[0].node.handle_shutdown(&nodes[1].node.get_our_node_id(), &node_1_2nd_shutdown).unwrap();
			get_event_msg!(nodes[0], MessageSendEvent::SendShutdown, nodes[1].node.get_our_node_id())
		};
		nodes[1].node.handle_shutdown(&nodes[0].node.get_our_node_id(), &node_0_2nd_shutdown).unwrap();

		assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
		assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

		assert!(nodes[2].node.claim_funds(our_payment_preimage));
		check_added_monitors!(nodes[2], 1);
		let updates = get_htlc_update_msgs!(nodes[2], nodes[1].node.get_our_node_id());
		assert!(updates.update_add_htlcs.is_empty());
		assert!(updates.update_fail_htlcs.is_empty());
		assert!(updates.update_fail_malformed_htlcs.is_empty());
		assert!(updates.update_fee.is_none());
		assert_eq!(updates.update_fulfill_htlcs.len(), 1);
		nodes[1].node.handle_update_fulfill_htlc(&nodes[2].node.get_our_node_id(), &updates.update_fulfill_htlcs[0]).unwrap();
		check_added_monitors!(nodes[1], 1);
		let updates_2 = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
		commitment_signed_dance!(nodes[1], nodes[2], updates.commitment_signed, false);

		assert!(updates_2.update_add_htlcs.is_empty());
		assert!(updates_2.update_fail_htlcs.is_empty());
		assert!(updates_2.update_fail_malformed_htlcs.is_empty());
		assert!(updates_2.update_fee.is_none());
		assert_eq!(updates_2.update_fulfill_htlcs.len(), 1);
		nodes[0].node.handle_update_fulfill_htlc(&nodes[1].node.get_our_node_id(), &updates_2.update_fulfill_htlcs[0]).unwrap();
		commitment_signed_dance!(nodes[0], nodes[1], updates_2.commitment_signed, false, true);

		let events = nodes[0].node.get_and_clear_pending_events();
		assert_eq!(events.len(), 1);
		match events[0] {
			Event::PaymentSent { ref payment_preimage } => {
				assert_eq!(our_payment_preimage, *payment_preimage);
			},
			_ => panic!("Unexpected event"),
		}

		let node_0_closing_signed = get_event_msg!(nodes[0], MessageSendEvent::SendClosingSigned, nodes[1].node.get_our_node_id());
		if recv_count > 0 {
			nodes[1].node.handle_closing_signed(&nodes[0].node.get_our_node_id(), &node_0_closing_signed).unwrap();
			let (_, node_1_closing_signed) = get_closing_signed_broadcast!(nodes[1].node, nodes[0].node.get_our_node_id());
			assert!(node_1_closing_signed.is_some());
		}

		nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id(), false);
		nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);

		nodes[0].node.peer_connected(&nodes[1].node.get_our_node_id());
		let node_0_2nd_reestablish = get_event_msg!(nodes[0], MessageSendEvent::SendChannelReestablish, nodes[1].node.get_our_node_id());
		nodes[1].node.peer_connected(&nodes[0].node.get_our_node_id());
		if recv_count == 0 {
			// If all closing_signeds weren't delivered we can just resume where we left off...
			let node_1_2nd_reestablish = get_event_msg!(nodes[1], MessageSendEvent::SendChannelReestablish, nodes[0].node.get_our_node_id());

			nodes[0].node.handle_channel_reestablish(&nodes[1].node.get_our_node_id(), &node_1_2nd_reestablish).unwrap();
			let node_0_3rd_shutdown = get_event_msg!(nodes[0], MessageSendEvent::SendShutdown, nodes[1].node.get_our_node_id());
			assert!(node_0_2nd_shutdown == node_0_3rd_shutdown);

			nodes[1].node.handle_channel_reestablish(&nodes[0].node.get_our_node_id(), &node_0_2nd_reestablish).unwrap();
			let node_1_3rd_shutdown = get_event_msg!(nodes[1], MessageSendEvent::SendShutdown, nodes[0].node.get_our_node_id());
			assert!(node_1_3rd_shutdown == node_1_2nd_shutdown);

			nodes[1].node.handle_shutdown(&nodes[0].node.get_our_node_id(), &node_0_3rd_shutdown).unwrap();
			assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

			nodes[0].node.handle_shutdown(&nodes[1].node.get_our_node_id(), &node_1_3rd_shutdown).unwrap();
			let node_0_2nd_closing_signed = get_event_msg!(nodes[0], MessageSendEvent::SendClosingSigned, nodes[1].node.get_our_node_id());
			assert!(node_0_closing_signed == node_0_2nd_closing_signed);

			nodes[1].node.handle_closing_signed(&nodes[0].node.get_our_node_id(), &node_0_2nd_closing_signed).unwrap();
			let (_, node_1_closing_signed) = get_closing_signed_broadcast!(nodes[1].node, nodes[0].node.get_our_node_id());
			nodes[0].node.handle_closing_signed(&nodes[1].node.get_our_node_id(), &node_1_closing_signed.unwrap()).unwrap();
			let (_, node_0_none) = get_closing_signed_broadcast!(nodes[0].node, nodes[1].node.get_our_node_id());
			assert!(node_0_none.is_none());
		} else {
			// If one node, however, received + responded with an identical closing_signed we end
			// up erroring and node[0] will try to broadcast its own latest commitment transaction.
			// There isn't really anything better we can do simply, but in the future we might
			// explore storing a set of recently-closed channels that got disconnected during
			// closing_signed and avoiding broadcasting local commitment txn for some timeout to
			// give our counterparty enough time to (potentially) broadcast a cooperative closing
			// transaction.
			assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

			if let Err(msgs::HandleError{action: Some(msgs::ErrorAction::SendErrorMessage{msg}), ..}) =
					nodes[1].node.handle_channel_reestablish(&nodes[0].node.get_our_node_id(), &node_0_2nd_reestablish) {
				nodes[0].node.handle_error(&nodes[1].node.get_our_node_id(), &msg);
				let msgs::ErrorMessage {ref channel_id, ..} = msg;
				assert_eq!(*channel_id, chan_1.2);
			} else { panic!("Needed SendErrorMessage close"); }

			// get_closing_signed_broadcast usually eats the BroadcastChannelUpdate for us and
			// checks it, but in this case nodes[0] didn't ever get a chance to receive a
			// closing_signed so we do it ourselves
			let events = nodes[0].node.get_and_clear_pending_msg_events();
			assert_eq!(events.len(), 1);
			match events[0] {
				MessageSendEvent::BroadcastChannelUpdate { ref msg } => {
					assert_eq!(msg.contents.flags & 2, 2);
				},
				_ => panic!("Unexpected event"),
			}
		}

		assert!(nodes[0].node.list_channels().is_empty());

		assert_eq!(nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().len(), 1);
		nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().clear();
		close_channel(&nodes[1], &nodes[2], &chan_2.2, chan_2.3, true);
		assert!(nodes[1].node.list_channels().is_empty());
		assert!(nodes[2].node.list_channels().is_empty());
	}

	#[test]
	fn test_shutdown_rebroadcast() {
		do_test_shutdown_rebroadcast(0);
		do_test_shutdown_rebroadcast(1);
		do_test_shutdown_rebroadcast(2);
	}

	#[test]
	fn fake_network_test() {
		// Simple test which builds a network of ChannelManagers, connects them to each other, and
		// tests that payments get routed and transactions broadcast in semi-reasonable ways.
		let nodes = create_network(4);

		// Create some initial channels
		let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1);
		let chan_2 = create_announced_chan_between_nodes(&nodes, 1, 2);
		let chan_3 = create_announced_chan_between_nodes(&nodes, 2, 3);

		// Rebalance the network a bit by relaying one payment through all the channels...
		send_payment(&nodes[0], &vec!(&nodes[1], &nodes[2], &nodes[3])[..], 8000000);
		send_payment(&nodes[0], &vec!(&nodes[1], &nodes[2], &nodes[3])[..], 8000000);
		send_payment(&nodes[0], &vec!(&nodes[1], &nodes[2], &nodes[3])[..], 8000000);
		send_payment(&nodes[0], &vec!(&nodes[1], &nodes[2], &nodes[3])[..], 8000000);

		// Send some more payments
		send_payment(&nodes[1], &vec!(&nodes[2], &nodes[3])[..], 1000000);
		send_payment(&nodes[3], &vec!(&nodes[2], &nodes[1], &nodes[0])[..], 1000000);
		send_payment(&nodes[3], &vec!(&nodes[2], &nodes[1])[..], 1000000);

		// Test failure packets
		let payment_hash_1 = route_payment(&nodes[0], &vec!(&nodes[1], &nodes[2], &nodes[3])[..], 1000000).1;
		fail_payment(&nodes[0], &vec!(&nodes[1], &nodes[2], &nodes[3])[..], payment_hash_1);

		// Add a new channel that skips 3
		let chan_4 = create_announced_chan_between_nodes(&nodes, 1, 3);

		send_payment(&nodes[0], &vec!(&nodes[1], &nodes[3])[..], 1000000);
		send_payment(&nodes[2], &vec!(&nodes[3])[..], 1000000);
		send_payment(&nodes[1], &vec!(&nodes[3])[..], 8000000);
		send_payment(&nodes[1], &vec!(&nodes[3])[..], 8000000);
		send_payment(&nodes[1], &vec!(&nodes[3])[..], 8000000);
		send_payment(&nodes[1], &vec!(&nodes[3])[..], 8000000);
		send_payment(&nodes[1], &vec!(&nodes[3])[..], 8000000);

		// Do some rebalance loop payments, simultaneously
		let mut hops = Vec::with_capacity(3);
		hops.push(RouteHop {
			pubkey: nodes[2].node.get_our_node_id(),
			short_channel_id: chan_2.0.contents.short_channel_id,
			fee_msat: 0,
			cltv_expiry_delta: chan_3.0.contents.cltv_expiry_delta as u32
		});
		hops.push(RouteHop {
			pubkey: nodes[3].node.get_our_node_id(),
			short_channel_id: chan_3.0.contents.short_channel_id,
			fee_msat: 0,
			cltv_expiry_delta: chan_4.1.contents.cltv_expiry_delta as u32
		});
		hops.push(RouteHop {
			pubkey: nodes[1].node.get_our_node_id(),
			short_channel_id: chan_4.0.contents.short_channel_id,
			fee_msat: 1000000,
			cltv_expiry_delta: TEST_FINAL_CLTV,
		});
		hops[1].fee_msat = chan_4.1.contents.fee_base_msat as u64 + chan_4.1.contents.fee_proportional_millionths as u64 * hops[2].fee_msat as u64 / 1000000;
		hops[0].fee_msat = chan_3.0.contents.fee_base_msat as u64 + chan_3.0.contents.fee_proportional_millionths as u64 * hops[1].fee_msat as u64 / 1000000;
		let payment_preimage_1 = send_along_route(&nodes[1], Route { hops }, &vec!(&nodes[2], &nodes[3], &nodes[1])[..], 1000000).0;

		let mut hops = Vec::with_capacity(3);
		hops.push(RouteHop {
			pubkey: nodes[3].node.get_our_node_id(),
			short_channel_id: chan_4.0.contents.short_channel_id,
			fee_msat: 0,
			cltv_expiry_delta: chan_3.1.contents.cltv_expiry_delta as u32
		});
		hops.push(RouteHop {
			pubkey: nodes[2].node.get_our_node_id(),
			short_channel_id: chan_3.0.contents.short_channel_id,
			fee_msat: 0,
			cltv_expiry_delta: chan_2.1.contents.cltv_expiry_delta as u32
		});
		hops.push(RouteHop {
			pubkey: nodes[1].node.get_our_node_id(),
			short_channel_id: chan_2.0.contents.short_channel_id,
			fee_msat: 1000000,
			cltv_expiry_delta: TEST_FINAL_CLTV,
		});
		hops[1].fee_msat = chan_2.1.contents.fee_base_msat as u64 + chan_2.1.contents.fee_proportional_millionths as u64 * hops[2].fee_msat as u64 / 1000000;
		hops[0].fee_msat = chan_3.1.contents.fee_base_msat as u64 + chan_3.1.contents.fee_proportional_millionths as u64 * hops[1].fee_msat as u64 / 1000000;
		let payment_hash_2 = send_along_route(&nodes[1], Route { hops }, &vec!(&nodes[3], &nodes[2], &nodes[1])[..], 1000000).1;

		// Claim the rebalances...
		fail_payment(&nodes[1], &vec!(&nodes[3], &nodes[2], &nodes[1])[..], payment_hash_2);
		claim_payment(&nodes[1], &vec!(&nodes[2], &nodes[3], &nodes[1])[..], payment_preimage_1);

		// Add a duplicate new channel from 2 to 4
		let chan_5 = create_announced_chan_between_nodes(&nodes, 1, 3);

		// Send some payments across both channels
		let payment_preimage_3 = route_payment(&nodes[0], &vec!(&nodes[1], &nodes[3])[..], 3000000).0;
		let payment_preimage_4 = route_payment(&nodes[0], &vec!(&nodes[1], &nodes[3])[..], 3000000).0;
		let payment_preimage_5 = route_payment(&nodes[0], &vec!(&nodes[1], &nodes[3])[..], 3000000).0;

		route_over_limit(&nodes[0], &vec!(&nodes[1], &nodes[3])[..], 3000000);

		//TODO: Test that routes work again here as we've been notified that the channel is full

		claim_payment(&nodes[0], &vec!(&nodes[1], &nodes[3])[..], payment_preimage_3);
		claim_payment(&nodes[0], &vec!(&nodes[1], &nodes[3])[..], payment_preimage_4);
		claim_payment(&nodes[0], &vec!(&nodes[1], &nodes[3])[..], payment_preimage_5);

		// Close down the channels...
		close_channel(&nodes[0], &nodes[1], &chan_1.2, chan_1.3, true);
		close_channel(&nodes[1], &nodes[2], &chan_2.2, chan_2.3, false);
		close_channel(&nodes[2], &nodes[3], &chan_3.2, chan_3.3, true);
		close_channel(&nodes[1], &nodes[3], &chan_4.2, chan_4.3, false);
		close_channel(&nodes[1], &nodes[3], &chan_5.2, chan_5.3, false);
	}

	#[test]
	fn duplicate_htlc_test() {
		// Test that we accept duplicate payment_hash HTLCs across the network and that
		// claiming/failing them are all separate and don't effect each other
		let mut nodes = create_network(6);

		// Create some initial channels to route via 3 to 4/5 from 0/1/2
		create_announced_chan_between_nodes(&nodes, 0, 3);
		create_announced_chan_between_nodes(&nodes, 1, 3);
		create_announced_chan_between_nodes(&nodes, 2, 3);
		create_announced_chan_between_nodes(&nodes, 3, 4);
		create_announced_chan_between_nodes(&nodes, 3, 5);

		let (payment_preimage, payment_hash) = route_payment(&nodes[0], &vec!(&nodes[3], &nodes[4])[..], 1000000);

		*nodes[0].network_payment_count.borrow_mut() -= 1;
		assert_eq!(route_payment(&nodes[1], &vec!(&nodes[3])[..], 1000000).0, payment_preimage);

		*nodes[0].network_payment_count.borrow_mut() -= 1;
		assert_eq!(route_payment(&nodes[2], &vec!(&nodes[3], &nodes[5])[..], 1000000).0, payment_preimage);

		claim_payment(&nodes[0], &vec!(&nodes[3], &nodes[4])[..], payment_preimage);
		fail_payment(&nodes[2], &vec!(&nodes[3], &nodes[5])[..], payment_hash);
		claim_payment(&nodes[1], &vec!(&nodes[3])[..], payment_preimage);
	}

	#[derive(PartialEq)]
	enum HTLCType { NONE, TIMEOUT, SUCCESS }
	/// Tests that the given node has broadcast transactions for the given Channel
	///
	/// First checks that the latest local commitment tx has been broadcast, unless an explicit
	/// commitment_tx is provided, which may be used to test that a remote commitment tx was
	/// broadcast and the revoked outputs were claimed.
	///
	/// Next tests that there is (or is not) a transaction that spends the commitment transaction
	/// that appears to be the type of HTLC transaction specified in has_htlc_tx.
	///
	/// All broadcast transactions must be accounted for in one of the above three types of we'll
	/// also fail.
	fn test_txn_broadcast(node: &Node, chan: &(msgs::ChannelUpdate, msgs::ChannelUpdate, [u8; 32], Transaction), commitment_tx: Option<Transaction>, has_htlc_tx: HTLCType) -> Vec<Transaction> {
		let mut node_txn = node.tx_broadcaster.txn_broadcasted.lock().unwrap();
		assert!(node_txn.len() >= if commitment_tx.is_some() { 0 } else { 1 } + if has_htlc_tx == HTLCType::NONE { 0 } else { 1 });

		let mut res = Vec::with_capacity(2);
		node_txn.retain(|tx| {
			if tx.input.len() == 1 && tx.input[0].previous_output.txid == chan.3.txid() {
				check_spends!(tx, chan.3.clone());
				if commitment_tx.is_none() {
					res.push(tx.clone());
				}
				false
			} else { true }
		});
		if let Some(explicit_tx) = commitment_tx {
			res.push(explicit_tx.clone());
		}

		assert_eq!(res.len(), 1);

		if has_htlc_tx != HTLCType::NONE {
			node_txn.retain(|tx| {
				if tx.input.len() == 1 && tx.input[0].previous_output.txid == res[0].txid() {
					check_spends!(tx, res[0].clone());
					if has_htlc_tx == HTLCType::TIMEOUT {
						assert!(tx.lock_time != 0);
					} else {
						assert!(tx.lock_time == 0);
					}
					res.push(tx.clone());
					false
				} else { true }
			});
			assert_eq!(res.len(), 2);
		}

		assert!(node_txn.is_empty());
		res
	}

	/// Tests that the given node has broadcast a claim transaction against the provided revoked
	/// HTLC transaction.
	fn test_revoked_htlc_claim_txn_broadcast(node: &Node, revoked_tx: Transaction) {
		let mut node_txn = node.tx_broadcaster.txn_broadcasted.lock().unwrap();
		assert_eq!(node_txn.len(), 1);
		node_txn.retain(|tx| {
			if tx.input.len() == 1 && tx.input[0].previous_output.txid == revoked_tx.txid() {
				check_spends!(tx, revoked_tx.clone());
				false
			} else { true }
		});
		assert!(node_txn.is_empty());
	}

	fn check_preimage_claim(node: &Node, prev_txn: &Vec<Transaction>) -> Vec<Transaction> {
		let mut node_txn = node.tx_broadcaster.txn_broadcasted.lock().unwrap();

		assert!(node_txn.len() >= 1);
		assert_eq!(node_txn[0].input.len(), 1);
		let mut found_prev = false;

		for tx in prev_txn {
			if node_txn[0].input[0].previous_output.txid == tx.txid() {
				check_spends!(node_txn[0], tx.clone());
				assert!(node_txn[0].input[0].witness[2].len() > 106); // must spend an htlc output
				assert_eq!(tx.input.len(), 1); // must spend a commitment tx

				found_prev = true;
				break;
			}
		}
		assert!(found_prev);

		let mut res = Vec::new();
		mem::swap(&mut *node_txn, &mut res);
		res
	}

	fn get_announce_close_broadcast_events(nodes: &Vec<Node>, a: usize, b: usize) {
		let events_1 = nodes[a].node.get_and_clear_pending_msg_events();
		assert_eq!(events_1.len(), 1);
		let as_update = match events_1[0] {
			MessageSendEvent::BroadcastChannelUpdate { ref msg } => {
				msg.clone()
			},
			_ => panic!("Unexpected event"),
		};

		let events_2 = nodes[b].node.get_and_clear_pending_msg_events();
		assert_eq!(events_2.len(), 1);
		let bs_update = match events_2[0] {
			MessageSendEvent::BroadcastChannelUpdate { ref msg } => {
				msg.clone()
			},
			_ => panic!("Unexpected event"),
		};

		for node in nodes {
			node.router.handle_channel_update(&as_update).unwrap();
			node.router.handle_channel_update(&bs_update).unwrap();
		}
	}

	macro_rules! expect_pending_htlcs_forwardable {
		($node: expr) => {{
			let events = $node.node.get_and_clear_pending_events();
			assert_eq!(events.len(), 1);
			match events[0] {
				Event::PendingHTLCsForwardable { .. } => { },
				_ => panic!("Unexpected event"),
			};
			$node.node.channel_state.lock().unwrap().next_forward = Instant::now();
			$node.node.process_pending_htlc_forwards();
		}}
	}

	#[test]
	fn channel_reserve_test() {
		use util::rng;
		use std::sync::atomic::Ordering;
		use ln::msgs::HandleError;

		macro_rules! get_channel_value_stat {
			($node: expr, $channel_id: expr) => {{
				let chan_lock = $node.node.channel_state.lock().unwrap();
				let chan = chan_lock.by_id.get(&$channel_id).unwrap();
				chan.get_value_stat()
			}}
		}

		let mut nodes = create_network(3);
		let chan_1 = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1900, 1001);
		let chan_2 = create_announced_chan_between_nodes_with_value(&nodes, 1, 2, 1900, 1001);

		let mut stat01 = get_channel_value_stat!(nodes[0], chan_1.2);
		let mut stat11 = get_channel_value_stat!(nodes[1], chan_1.2);

		let mut stat12 = get_channel_value_stat!(nodes[1], chan_2.2);
		let mut stat22 = get_channel_value_stat!(nodes[2], chan_2.2);

		macro_rules! get_route_and_payment_hash {
			($recv_value: expr) => {{
				let route = nodes[0].router.get_route(&nodes.last().unwrap().node.get_our_node_id(), None, &Vec::new(), $recv_value, TEST_FINAL_CLTV).unwrap();
				let (payment_preimage, payment_hash) = get_payment_preimage_hash!(nodes[0]);
				(route, payment_hash, payment_preimage)
			}}
		};

		macro_rules! expect_forward {
			($node: expr) => {{
				let mut events = $node.node.get_and_clear_pending_msg_events();
				assert_eq!(events.len(), 1);
				check_added_monitors!($node, 1);
				let payment_event = SendEvent::from_event(events.remove(0));
				payment_event
			}}
		}

		macro_rules! expect_payment_received {
			($node: expr, $expected_payment_hash: expr, $expected_recv_value: expr) => {
				let events = $node.node.get_and_clear_pending_events();
				assert_eq!(events.len(), 1);
				match events[0] {
					Event::PaymentReceived { ref payment_hash, amt } => {
						assert_eq!($expected_payment_hash, *payment_hash);
						assert_eq!($expected_recv_value, amt);
					},
					_ => panic!("Unexpected event"),
				}
			}
		};

		let feemsat = 239; // somehow we know?
		let total_fee_msat = (nodes.len() - 2) as u64 * 239;

		let recv_value_0 = stat01.their_max_htlc_value_in_flight_msat - total_fee_msat;

		// attempt to send amt_msat > their_max_htlc_value_in_flight_msat
		{
			let (route, our_payment_hash, _) = get_route_and_payment_hash!(recv_value_0 + 1);
			assert!(route.hops.iter().rev().skip(1).all(|h| h.fee_msat == feemsat));
			let err = nodes[0].node.send_payment(route, our_payment_hash).err().unwrap();
			match err {
				APIError::ChannelUnavailable{err} => assert_eq!(err, "Cannot send value that would put us over our max HTLC value in flight"),
				_ => panic!("Unknown error variants"),
			}
		}

		let mut htlc_id = 0;
		// channel reserve is bigger than their_max_htlc_value_in_flight_msat so loop to deplete
		// nodes[0]'s wealth
		loop {
			let amt_msat = recv_value_0 + total_fee_msat;
			if stat01.value_to_self_msat - amt_msat < stat01.channel_reserve_msat {
				break;
			}
			send_payment(&nodes[0], &vec![&nodes[1], &nodes[2]][..], recv_value_0);
			htlc_id += 1;

			let (stat01_, stat11_, stat12_, stat22_) = (
				get_channel_value_stat!(nodes[0], chan_1.2),
				get_channel_value_stat!(nodes[1], chan_1.2),
				get_channel_value_stat!(nodes[1], chan_2.2),
				get_channel_value_stat!(nodes[2], chan_2.2),
			);

			assert_eq!(stat01_.value_to_self_msat, stat01.value_to_self_msat - amt_msat);
			assert_eq!(stat11_.value_to_self_msat, stat11.value_to_self_msat + amt_msat);
			assert_eq!(stat12_.value_to_self_msat, stat12.value_to_self_msat - (amt_msat - feemsat));
			assert_eq!(stat22_.value_to_self_msat, stat22.value_to_self_msat + (amt_msat - feemsat));
			stat01 = stat01_; stat11 = stat11_; stat12 = stat12_; stat22 = stat22_;
		}

		{
			let recv_value = stat01.value_to_self_msat - stat01.channel_reserve_msat - total_fee_msat;
			// attempt to get channel_reserve violation
			let (route, our_payment_hash, _) = get_route_and_payment_hash!(recv_value + 1);
			let err = nodes[0].node.send_payment(route.clone(), our_payment_hash).err().unwrap();
			match err {
				APIError::ChannelUnavailable{err} => assert_eq!(err, "Cannot send value that would put us over our reserve value"),
				_ => panic!("Unknown error variants"),
			}
		}

		// adding pending output
		let recv_value_1 = (stat01.value_to_self_msat - stat01.channel_reserve_msat - total_fee_msat)/2;
		let amt_msat_1 = recv_value_1 + total_fee_msat;

		let (route_1, our_payment_hash_1, our_payment_preimage_1) = get_route_and_payment_hash!(recv_value_1);
		let payment_event_1 = {
			nodes[0].node.send_payment(route_1, our_payment_hash_1).unwrap();
			check_added_monitors!(nodes[0], 1);

			let mut events = nodes[0].node.get_and_clear_pending_msg_events();
			assert_eq!(events.len(), 1);
			SendEvent::from_event(events.remove(0))
		};
		nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &payment_event_1.msgs[0]).unwrap();

		// channel reserve test with htlc pending output > 0
		let recv_value_2 = stat01.value_to_self_msat - amt_msat_1 - stat01.channel_reserve_msat - total_fee_msat;
		{
			let (route, our_payment_hash, _) = get_route_and_payment_hash!(recv_value_2 + 1);
			match nodes[0].node.send_payment(route, our_payment_hash).err().unwrap() {
				APIError::ChannelUnavailable{err} => assert_eq!(err, "Cannot send value that would put us over our reserve value"),
				_ => panic!("Unknown error variants"),
			}
		}

		{
			// test channel_reserve test on nodes[1] side
			let (route, our_payment_hash, _) = get_route_and_payment_hash!(recv_value_2 + 1);

			// Need to manually create update_add_htlc message to go around the channel reserve check in send_htlc()
			let secp_ctx = Secp256k1::new();
			let session_priv = SecretKey::from_slice(&secp_ctx, &{
				let mut session_key = [0; 32];
				rng::fill_bytes(&mut session_key);
				session_key
			}).expect("RNG is bad!");

			let cur_height = nodes[0].node.latest_block_height.load(Ordering::Acquire) as u32 + 1;
			let onion_keys = ChannelManager::construct_onion_keys(&secp_ctx, &route, &session_priv).unwrap();
			let (onion_payloads, htlc_msat, htlc_cltv) = ChannelManager::build_onion_payloads(&route, cur_height).unwrap();
			let onion_packet = ChannelManager::construct_onion_packet(onion_payloads, onion_keys, &our_payment_hash);
			let msg = msgs::UpdateAddHTLC {
				channel_id: chan_1.2,
				htlc_id,
				amount_msat: htlc_msat,
				payment_hash: our_payment_hash,
				cltv_expiry: htlc_cltv,
				onion_routing_packet: onion_packet,
			};

			let err = nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &msg).err().unwrap();
			match err {
				HandleError{err, .. } => assert_eq!(err, "Remote HTLC add would put them over their reserve value"),
			}
		}

		// split the rest to test holding cell
		let recv_value_21 = recv_value_2/2;
		let recv_value_22 = recv_value_2 - recv_value_21 - total_fee_msat;
		{
			let stat = get_channel_value_stat!(nodes[0], chan_1.2);
			assert_eq!(stat.value_to_self_msat - (stat.pending_outbound_htlcs_amount_msat + recv_value_21 + recv_value_22 + total_fee_msat + total_fee_msat), stat.channel_reserve_msat);
		}

		// now see if they go through on both sides
		let (route_21, our_payment_hash_21, our_payment_preimage_21) = get_route_and_payment_hash!(recv_value_21);
		// but this will stuck in the holding cell
		nodes[0].node.send_payment(route_21, our_payment_hash_21).unwrap();
		check_added_monitors!(nodes[0], 0);
		let events = nodes[0].node.get_and_clear_pending_events();
		assert_eq!(events.len(), 0);

		// test with outbound holding cell amount > 0
		{
			let (route, our_payment_hash, _) = get_route_and_payment_hash!(recv_value_22+1);
			match nodes[0].node.send_payment(route, our_payment_hash).err().unwrap() {
				APIError::ChannelUnavailable{err} => assert_eq!(err, "Cannot send value that would put us over our reserve value"),
				_ => panic!("Unknown error variants"),
			}
		}

		let (route_22, our_payment_hash_22, our_payment_preimage_22) = get_route_and_payment_hash!(recv_value_22);
		// this will also stuck in the holding cell
		nodes[0].node.send_payment(route_22, our_payment_hash_22).unwrap();
		check_added_monitors!(nodes[0], 0);
		assert!(nodes[0].node.get_and_clear_pending_events().is_empty());
		assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());

		// flush the pending htlc
		nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &payment_event_1.commitment_msg).unwrap();
		let (as_revoke_and_ack, as_commitment_signed) = get_revoke_commit_msgs!(nodes[1], nodes[0].node.get_our_node_id());
		check_added_monitors!(nodes[1], 1);

		nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &as_revoke_and_ack).unwrap();
		check_added_monitors!(nodes[0], 1);
		let commitment_update_2 = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());

		nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &as_commitment_signed).unwrap();
		let bs_revoke_and_ack = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());
		// No commitment_signed so get_event_msg's assert(len == 1) passes
		check_added_monitors!(nodes[0], 1);

		nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &bs_revoke_and_ack).unwrap();
		assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
		check_added_monitors!(nodes[1], 1);

		expect_pending_htlcs_forwardable!(nodes[1]);

		let ref payment_event_11 = expect_forward!(nodes[1]);
		nodes[2].node.handle_update_add_htlc(&nodes[1].node.get_our_node_id(), &payment_event_11.msgs[0]).unwrap();
		commitment_signed_dance!(nodes[2], nodes[1], payment_event_11.commitment_msg, false);

		expect_pending_htlcs_forwardable!(nodes[2]);
		expect_payment_received!(nodes[2], our_payment_hash_1, recv_value_1);

		// flush the htlcs in the holding cell
		assert_eq!(commitment_update_2.update_add_htlcs.len(), 2);
		nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &commitment_update_2.update_add_htlcs[0]).unwrap();
		nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &commitment_update_2.update_add_htlcs[1]).unwrap();
		commitment_signed_dance!(nodes[1], nodes[0], &commitment_update_2.commitment_signed, false);
		expect_pending_htlcs_forwardable!(nodes[1]);

		let ref payment_event_3 = expect_forward!(nodes[1]);
		assert_eq!(payment_event_3.msgs.len(), 2);
		nodes[2].node.handle_update_add_htlc(&nodes[1].node.get_our_node_id(), &payment_event_3.msgs[0]).unwrap();
		nodes[2].node.handle_update_add_htlc(&nodes[1].node.get_our_node_id(), &payment_event_3.msgs[1]).unwrap();

		commitment_signed_dance!(nodes[2], nodes[1], &payment_event_3.commitment_msg, false);
		expect_pending_htlcs_forwardable!(nodes[2]);

		let events = nodes[2].node.get_and_clear_pending_events();
		assert_eq!(events.len(), 2);
		match events[0] {
			Event::PaymentReceived { ref payment_hash, amt } => {
				assert_eq!(our_payment_hash_21, *payment_hash);
				assert_eq!(recv_value_21, amt);
			},
			_ => panic!("Unexpected event"),
		}
		match events[1] {
			Event::PaymentReceived { ref payment_hash, amt } => {
				assert_eq!(our_payment_hash_22, *payment_hash);
				assert_eq!(recv_value_22, amt);
			},
			_ => panic!("Unexpected event"),
		}

		claim_payment(&nodes[0], &vec!(&nodes[1], &nodes[2]), our_payment_preimage_1);
		claim_payment(&nodes[0], &vec!(&nodes[1], &nodes[2]), our_payment_preimage_21);
		claim_payment(&nodes[0], &vec!(&nodes[1], &nodes[2]), our_payment_preimage_22);

		let expected_value_to_self = stat01.value_to_self_msat - (recv_value_1 + total_fee_msat) - (recv_value_21 + total_fee_msat) - (recv_value_22 + total_fee_msat);
		let stat0 = get_channel_value_stat!(nodes[0], chan_1.2);
		assert_eq!(stat0.value_to_self_msat, expected_value_to_self);
		assert_eq!(stat0.value_to_self_msat, stat0.channel_reserve_msat);

		let stat2 = get_channel_value_stat!(nodes[2], chan_2.2);
		assert_eq!(stat2.value_to_self_msat, stat22.value_to_self_msat + recv_value_1 + recv_value_21 + recv_value_22);
	}

	#[test]
	fn channel_monitor_network_test() {
		// Simple test which builds a network of ChannelManagers, connects them to each other, and
		// tests that ChannelMonitor is able to recover from various states.
		let nodes = create_network(5);

		// Create some initial channels
		let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1);
		let chan_2 = create_announced_chan_between_nodes(&nodes, 1, 2);
		let chan_3 = create_announced_chan_between_nodes(&nodes, 2, 3);
		let chan_4 = create_announced_chan_between_nodes(&nodes, 3, 4);

		// Rebalance the network a bit by relaying one payment through all the channels...
		send_payment(&nodes[0], &vec!(&nodes[1], &nodes[2], &nodes[3], &nodes[4])[..], 8000000);
		send_payment(&nodes[0], &vec!(&nodes[1], &nodes[2], &nodes[3], &nodes[4])[..], 8000000);
		send_payment(&nodes[0], &vec!(&nodes[1], &nodes[2], &nodes[3], &nodes[4])[..], 8000000);
		send_payment(&nodes[0], &vec!(&nodes[1], &nodes[2], &nodes[3], &nodes[4])[..], 8000000);

		// Simple case with no pending HTLCs:
		nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id(), true);
		{
			let mut node_txn = test_txn_broadcast(&nodes[1], &chan_1, None, HTLCType::NONE);
			let header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
			nodes[0].chain_monitor.block_connected_with_filtering(&Block { header, txdata: vec![node_txn.drain(..).next().unwrap()] }, 1);
			test_txn_broadcast(&nodes[0], &chan_1, None, HTLCType::NONE);
		}
		get_announce_close_broadcast_events(&nodes, 0, 1);
		assert_eq!(nodes[0].node.list_channels().len(), 0);
		assert_eq!(nodes[1].node.list_channels().len(), 1);

		// One pending HTLC is discarded by the force-close:
		let payment_preimage_1 = route_payment(&nodes[1], &vec!(&nodes[2], &nodes[3])[..], 3000000).0;

		// Simple case of one pending HTLC to HTLC-Timeout
		nodes[1].node.peer_disconnected(&nodes[2].node.get_our_node_id(), true);
		{
			let mut node_txn = test_txn_broadcast(&nodes[1], &chan_2, None, HTLCType::TIMEOUT);
			let header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
			nodes[2].chain_monitor.block_connected_with_filtering(&Block { header, txdata: vec![node_txn.drain(..).next().unwrap()] }, 1);
			test_txn_broadcast(&nodes[2], &chan_2, None, HTLCType::NONE);
		}
		get_announce_close_broadcast_events(&nodes, 1, 2);
		assert_eq!(nodes[1].node.list_channels().len(), 0);
		assert_eq!(nodes[2].node.list_channels().len(), 1);

		macro_rules! claim_funds {
			($node: expr, $prev_node: expr, $preimage: expr) => {
				{
					assert!($node.node.claim_funds($preimage));
					check_added_monitors!($node, 1);

					let events = $node.node.get_and_clear_pending_msg_events();
					assert_eq!(events.len(), 1);
					match events[0] {
						MessageSendEvent::UpdateHTLCs { ref node_id, updates: msgs::CommitmentUpdate { ref update_add_htlcs, ref update_fail_htlcs, .. } } => {
							assert!(update_add_htlcs.is_empty());
							assert!(update_fail_htlcs.is_empty());
							assert_eq!(*node_id, $prev_node.node.get_our_node_id());
						},
						_ => panic!("Unexpected event"),
					};
				}
			}
		}

		// nodes[3] gets the preimage, but nodes[2] already disconnected, resulting in a nodes[2]
		// HTLC-Timeout and a nodes[3] claim against it (+ its own announces)
		nodes[2].node.peer_disconnected(&nodes[3].node.get_our_node_id(), true);
		{
			let node_txn = test_txn_broadcast(&nodes[2], &chan_3, None, HTLCType::TIMEOUT);

			// Claim the payment on nodes[3], giving it knowledge of the preimage
			claim_funds!(nodes[3], nodes[2], payment_preimage_1);

			let header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
			nodes[3].chain_monitor.block_connected_with_filtering(&Block { header, txdata: vec![node_txn[0].clone()] }, 1);

			check_preimage_claim(&nodes[3], &node_txn);
		}
		get_announce_close_broadcast_events(&nodes, 2, 3);
		assert_eq!(nodes[2].node.list_channels().len(), 0);
		assert_eq!(nodes[3].node.list_channels().len(), 1);

		{ // Cheat and reset nodes[4]'s height to 1
			let header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
			nodes[4].chain_monitor.block_connected_with_filtering(&Block { header, txdata: vec![] }, 1);
		}

		assert_eq!(nodes[3].node.latest_block_height.load(Ordering::Acquire), 1);
		assert_eq!(nodes[4].node.latest_block_height.load(Ordering::Acquire), 1);
		// One pending HTLC to time out:
		let payment_preimage_2 = route_payment(&nodes[3], &vec!(&nodes[4])[..], 3000000).0;
		// CLTV expires at TEST_FINAL_CLTV + 1 (current height) + 1 (added in send_payment for
		// buffer space).

		{
			let mut header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
			nodes[3].chain_monitor.block_connected_checked(&header, 2, &Vec::new()[..], &[0; 0]);
			for i in 3..TEST_FINAL_CLTV + 2 + HTLC_FAIL_TIMEOUT_BLOCKS + 1 {
				header = BlockHeader { version: 0x20000000, prev_blockhash: header.bitcoin_hash(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
				nodes[3].chain_monitor.block_connected_checked(&header, i, &Vec::new()[..], &[0; 0]);
			}

			let node_txn = test_txn_broadcast(&nodes[3], &chan_4, None, HTLCType::TIMEOUT);

			// Claim the payment on nodes[4], giving it knowledge of the preimage
			claim_funds!(nodes[4], nodes[3], payment_preimage_2);

			header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
			nodes[4].chain_monitor.block_connected_checked(&header, 2, &Vec::new()[..], &[0; 0]);
			for i in 3..TEST_FINAL_CLTV + 2 - CLTV_CLAIM_BUFFER + 1 {
				header = BlockHeader { version: 0x20000000, prev_blockhash: header.bitcoin_hash(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
				nodes[4].chain_monitor.block_connected_checked(&header, i, &Vec::new()[..], &[0; 0]);
			}

			test_txn_broadcast(&nodes[4], &chan_4, None, HTLCType::SUCCESS);

			header = BlockHeader { version: 0x20000000, prev_blockhash: header.bitcoin_hash(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
			nodes[4].chain_monitor.block_connected_with_filtering(&Block { header, txdata: vec![node_txn[0].clone()] }, TEST_FINAL_CLTV - 5);

			check_preimage_claim(&nodes[4], &node_txn);
		}
		get_announce_close_broadcast_events(&nodes, 3, 4);
		assert_eq!(nodes[3].node.list_channels().len(), 0);
		assert_eq!(nodes[4].node.list_channels().len(), 0);
	}

	#[test]
	fn test_justice_tx() {
		// Test justice txn built on revoked HTLC-Success tx, against both sides

		let nodes = create_network(2);
		// Create some new channels:
		let chan_5 = create_announced_chan_between_nodes(&nodes, 0, 1);

		// A pending HTLC which will be revoked:
		let payment_preimage_3 = route_payment(&nodes[0], &vec!(&nodes[1])[..], 3000000).0;
		// Get the will-be-revoked local txn from nodes[0]
		let revoked_local_txn = nodes[0].node.channel_state.lock().unwrap().by_id.iter().next().unwrap().1.last_local_commitment_txn.clone();
		assert_eq!(revoked_local_txn.len(), 2); // First commitment tx, then HTLC tx
		assert_eq!(revoked_local_txn[0].input.len(), 1);
		assert_eq!(revoked_local_txn[0].input[0].previous_output.txid, chan_5.3.txid());
		assert_eq!(revoked_local_txn[0].output.len(), 2); // Only HTLC and output back to 0 are present
		assert_eq!(revoked_local_txn[1].input.len(), 1);
		assert_eq!(revoked_local_txn[1].input[0].previous_output.txid, revoked_local_txn[0].txid());
		assert_eq!(revoked_local_txn[1].input[0].witness.last().unwrap().len(), 133); // HTLC-Timeout
		// Revoke the old state
		claim_payment(&nodes[0], &vec!(&nodes[1])[..], payment_preimage_3);

		{
			let mut header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
			nodes[1].chain_monitor.block_connected_with_filtering(&Block { header, txdata: vec![revoked_local_txn[0].clone()] }, 1);
			{
				let mut node_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap();
				assert_eq!(node_txn.len(), 3);
				assert_eq!(node_txn.pop().unwrap(), node_txn[0]); // An outpoint registration will result in a 2nd block_connected
				assert_eq!(node_txn[0].input.len(), 2); // We should claim the revoked output and the HTLC output

				check_spends!(node_txn[0], revoked_local_txn[0].clone());
				node_txn.swap_remove(0);
			}
			test_txn_broadcast(&nodes[1], &chan_5, None, HTLCType::NONE);

			nodes[0].chain_monitor.block_connected_with_filtering(&Block { header, txdata: vec![revoked_local_txn[0].clone()] }, 1);
			let node_txn = test_txn_broadcast(&nodes[0], &chan_5, Some(revoked_local_txn[0].clone()), HTLCType::TIMEOUT);
			header = BlockHeader { version: 0x20000000, prev_blockhash: header.bitcoin_hash(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
			nodes[1].chain_monitor.block_connected_with_filtering(&Block { header, txdata: vec![node_txn[1].clone()] }, 1);
			test_revoked_htlc_claim_txn_broadcast(&nodes[1], node_txn[1].clone());
		}
		get_announce_close_broadcast_events(&nodes, 0, 1);

		assert_eq!(nodes[0].node.list_channels().len(), 0);
		assert_eq!(nodes[1].node.list_channels().len(), 0);

		// We test justice_tx build by A on B's revoked HTLC-Success tx
		// Create some new channels:
		let chan_6 = create_announced_chan_between_nodes(&nodes, 0, 1);

		// A pending HTLC which will be revoked:
		let payment_preimage_4 = route_payment(&nodes[0], &vec!(&nodes[1])[..], 3000000).0;
		// Get the will-be-revoked local txn from B
		let revoked_local_txn = nodes[1].node.channel_state.lock().unwrap().by_id.iter().next().unwrap().1.last_local_commitment_txn.clone();
		assert_eq!(revoked_local_txn.len(), 1); // Only commitment tx
		assert_eq!(revoked_local_txn[0].input.len(), 1);
		assert_eq!(revoked_local_txn[0].input[0].previous_output.txid, chan_6.3.txid());
		assert_eq!(revoked_local_txn[0].output.len(), 2); // Only HTLC and output back to A are present
		// Revoke the old state
		claim_payment(&nodes[0], &vec!(&nodes[1])[..], payment_preimage_4);
		{
			let mut header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
			nodes[0].chain_monitor.block_connected_with_filtering(&Block { header, txdata: vec![revoked_local_txn[0].clone()] }, 1);
			{
				let mut node_txn = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap();
				assert_eq!(node_txn.len(), 3);
				assert_eq!(node_txn.pop().unwrap(), node_txn[0]); // An outpoint registration will result in a 2nd block_connected
				assert_eq!(node_txn[0].input.len(), 1); // We claim the received HTLC output

				check_spends!(node_txn[0], revoked_local_txn[0].clone());
				node_txn.swap_remove(0);
			}
			test_txn_broadcast(&nodes[0], &chan_6, None, HTLCType::NONE);

			nodes[1].chain_monitor.block_connected_with_filtering(&Block { header, txdata: vec![revoked_local_txn[0].clone()] }, 1);
			let node_txn = test_txn_broadcast(&nodes[1], &chan_6, Some(revoked_local_txn[0].clone()), HTLCType::SUCCESS);
			header = BlockHeader { version: 0x20000000, prev_blockhash: header.bitcoin_hash(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
			nodes[0].chain_monitor.block_connected_with_filtering(&Block { header, txdata: vec![node_txn[1].clone()] }, 1);
			test_revoked_htlc_claim_txn_broadcast(&nodes[0], node_txn[1].clone());
		}
		get_announce_close_broadcast_events(&nodes, 0, 1);
		assert_eq!(nodes[0].node.list_channels().len(), 0);
		assert_eq!(nodes[1].node.list_channels().len(), 0);
	}

	#[test]
	fn revoked_output_claim() {
		// Simple test to ensure a node will claim a revoked output when a stale remote commitment
		// transaction is broadcast by its counterparty
		let nodes = create_network(2);
		let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1);
		// node[0] is gonna to revoke an old state thus node[1] should be able to claim the revoked output
		let revoked_local_txn = nodes[0].node.channel_state.lock().unwrap().by_id.get(&chan_1.2).unwrap().last_local_commitment_txn.clone();
		assert_eq!(revoked_local_txn.len(), 1);
		// Only output is the full channel value back to nodes[0]:
		assert_eq!(revoked_local_txn[0].output.len(), 1);
		// Send a payment through, updating everyone's latest commitment txn
		send_payment(&nodes[0], &vec!(&nodes[1])[..], 5000000);

		// Inform nodes[1] that nodes[0] broadcast a stale tx
		let header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
		nodes[1].chain_monitor.block_connected_with_filtering(&Block { header, txdata: vec![revoked_local_txn[0].clone()] }, 1);
		let node_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap();
		assert_eq!(node_txn.len(), 3); // nodes[1] will broadcast justice tx twice, and its own local state once

		assert_eq!(node_txn[0], node_txn[2]);

		check_spends!(node_txn[0], revoked_local_txn[0].clone());
		check_spends!(node_txn[1], chan_1.3.clone());

		// Inform nodes[0] that a watchtower cheated on its behalf, so it will force-close the chan
		nodes[0].chain_monitor.block_connected_with_filtering(&Block { header, txdata: vec![revoked_local_txn[0].clone()] }, 1);
		get_announce_close_broadcast_events(&nodes, 0, 1);
	}

	#[test]
	fn claim_htlc_outputs_shared_tx() {
		// Node revoked old state, htlcs haven't time out yet, claim them in shared justice tx
		let nodes = create_network(2);

		// Create some new channel:
		let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1);

		// Rebalance the network to generate htlc in the two directions
		send_payment(&nodes[0], &vec!(&nodes[1])[..], 8000000);
		// node[0] is gonna to revoke an old state thus node[1] should be able to claim both offered/received HTLC outputs on top of commitment tx
		let payment_preimage_1 = route_payment(&nodes[0], &vec!(&nodes[1])[..], 3000000).0;
		let _payment_preimage_2 = route_payment(&nodes[1], &vec!(&nodes[0])[..], 3000000).0;

		// Get the will-be-revoked local txn from node[0]
		let revoked_local_txn = nodes[0].node.channel_state.lock().unwrap().by_id.get(&chan_1.2).unwrap().last_local_commitment_txn.clone();
		assert_eq!(revoked_local_txn.len(), 2); // commitment tx + 1 HTLC-Timeout tx
		assert_eq!(revoked_local_txn[0].input.len(), 1);
		assert_eq!(revoked_local_txn[0].input[0].previous_output.txid, chan_1.3.txid());
		assert_eq!(revoked_local_txn[1].input.len(), 1);
		assert_eq!(revoked_local_txn[1].input[0].previous_output.txid, revoked_local_txn[0].txid());
		assert_eq!(revoked_local_txn[1].input[0].witness.last().unwrap().len(), 133); // HTLC-Timeout
		check_spends!(revoked_local_txn[1], revoked_local_txn[0].clone());

		//Revoke the old state
		claim_payment(&nodes[0], &vec!(&nodes[1])[..], payment_preimage_1);

		{
			let header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };

			nodes[0].chain_monitor.block_connected_with_filtering(&Block { header, txdata: vec![revoked_local_txn[0].clone()] }, 1);

			nodes[1].chain_monitor.block_connected_with_filtering(&Block { header, txdata: vec![revoked_local_txn[0].clone()] }, 1);
			let node_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap();
			assert_eq!(node_txn.len(), 4);

			assert_eq!(node_txn[0].input.len(), 3); // Claim the revoked output + both revoked HTLC outputs
			check_spends!(node_txn[0], revoked_local_txn[0].clone());

			assert_eq!(node_txn[0], node_txn[3]); // justice tx is duplicated due to block re-scanning

			let mut witness_lens = BTreeSet::new();
			witness_lens.insert(node_txn[0].input[0].witness.last().unwrap().len());
			witness_lens.insert(node_txn[0].input[1].witness.last().unwrap().len());
			witness_lens.insert(node_txn[0].input[2].witness.last().unwrap().len());
			assert_eq!(witness_lens.len(), 3);
			assert_eq!(*witness_lens.iter().skip(0).next().unwrap(), 77); // revoked to_local
			assert_eq!(*witness_lens.iter().skip(1).next().unwrap(), 133); // revoked offered HTLC
			assert_eq!(*witness_lens.iter().skip(2).next().unwrap(), 138); // revoked received HTLC

			// Next nodes[1] broadcasts its current local tx state:
			assert_eq!(node_txn[1].input.len(), 1);
			assert_eq!(node_txn[1].input[0].previous_output.txid, chan_1.3.txid()); //Spending funding tx unique txouput, tx broadcasted by ChannelManager

			assert_eq!(node_txn[2].input.len(), 1);
			let witness_script = node_txn[2].clone().input[0].witness.pop().unwrap();
			assert_eq!(witness_script.len(), 133); //Spending an offered htlc output
			assert_eq!(node_txn[2].input[0].previous_output.txid, node_txn[1].txid());
			assert_ne!(node_txn[2].input[0].previous_output.txid, node_txn[0].input[0].previous_output.txid);
			assert_ne!(node_txn[2].input[0].previous_output.txid, node_txn[0].input[1].previous_output.txid);
		}
		get_announce_close_broadcast_events(&nodes, 0, 1);
		assert_eq!(nodes[0].node.list_channels().len(), 0);
		assert_eq!(nodes[1].node.list_channels().len(), 0);
	}

	#[test]
	fn claim_htlc_outputs_single_tx() {
		// Node revoked old state, htlcs have timed out, claim each of them in separated justice tx
		let nodes = create_network(2);

		let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1);

		// Rebalance the network to generate htlc in the two directions
		send_payment(&nodes[0], &vec!(&nodes[1])[..], 8000000);
		// node[0] is gonna to revoke an old state thus node[1] should be able to claim both offered/received HTLC outputs on top of commitment tx, but this
		// time as two different claim transactions as we're gonna to timeout htlc with given a high current height
		let payment_preimage_1 = route_payment(&nodes[0], &vec!(&nodes[1])[..], 3000000).0;
		let _payment_preimage_2 = route_payment(&nodes[1], &vec!(&nodes[0])[..], 3000000).0;

		// Get the will-be-revoked local txn from node[0]
		let revoked_local_txn = nodes[0].node.channel_state.lock().unwrap().by_id.get(&chan_1.2).unwrap().last_local_commitment_txn.clone();

		//Revoke the old state
		claim_payment(&nodes[0], &vec!(&nodes[1])[..], payment_preimage_1);

		{
			let header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };

			nodes[0].chain_monitor.block_connected_with_filtering(&Block { header, txdata: vec![revoked_local_txn[0].clone()] }, 200);

			nodes[1].chain_monitor.block_connected_with_filtering(&Block { header, txdata: vec![revoked_local_txn[0].clone()] }, 200);
			let node_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap();
			assert_eq!(node_txn.len(), 12); // ChannelManager : 2, ChannelMontitor: 8 (1 standard revoked output, 2 revocation htlc tx, 1 local commitment tx + 1 htlc timeout tx) * 2 (block-rescan)

			assert_eq!(node_txn[0], node_txn[7]);
			assert_eq!(node_txn[1], node_txn[8]);
			assert_eq!(node_txn[2], node_txn[9]);
			assert_eq!(node_txn[3], node_txn[10]);
			assert_eq!(node_txn[4], node_txn[11]);
			assert_eq!(node_txn[3], node_txn[5]); //local commitment tx + htlc timeout tx broadcated by ChannelManger
			assert_eq!(node_txn[4], node_txn[6]);

			assert_eq!(node_txn[0].input.len(), 1);
			assert_eq!(node_txn[1].input.len(), 1);
			assert_eq!(node_txn[2].input.len(), 1);

			let mut revoked_tx_map = HashMap::new();
			revoked_tx_map.insert(revoked_local_txn[0].txid(), revoked_local_txn[0].clone());
			node_txn[0].verify(&revoked_tx_map).unwrap();
			node_txn[1].verify(&revoked_tx_map).unwrap();
			node_txn[2].verify(&revoked_tx_map).unwrap();

			let mut witness_lens = BTreeSet::new();
			witness_lens.insert(node_txn[0].input[0].witness.last().unwrap().len());
			witness_lens.insert(node_txn[1].input[0].witness.last().unwrap().len());
			witness_lens.insert(node_txn[2].input[0].witness.last().unwrap().len());
			assert_eq!(witness_lens.len(), 3);
			assert_eq!(*witness_lens.iter().skip(0).next().unwrap(), 77); // revoked to_local
			assert_eq!(*witness_lens.iter().skip(1).next().unwrap(), 133); // revoked offered HTLC
			assert_eq!(*witness_lens.iter().skip(2).next().unwrap(), 138); // revoked received HTLC

			assert_eq!(node_txn[3].input.len(), 1);
			check_spends!(node_txn[3], chan_1.3.clone());

			assert_eq!(node_txn[4].input.len(), 1);
			let witness_script = node_txn[4].input[0].witness.last().unwrap();
			assert_eq!(witness_script.len(), 133); //Spending an offered htlc output
			assert_eq!(node_txn[4].input[0].previous_output.txid, node_txn[3].txid());
			assert_ne!(node_txn[4].input[0].previous_output.txid, node_txn[0].input[0].previous_output.txid);
			assert_ne!(node_txn[4].input[0].previous_output.txid, node_txn[1].input[0].previous_output.txid);
		}
		get_announce_close_broadcast_events(&nodes, 0, 1);
		assert_eq!(nodes[0].node.list_channels().len(), 0);
		assert_eq!(nodes[1].node.list_channels().len(), 0);
	}

	#[test]
	fn test_htlc_ignore_latest_remote_commitment() {
		// Test that HTLC transactions spending the latest remote commitment transaction are simply
		// ignored if we cannot claim them. This originally tickled an invalid unwrap().
		let nodes = create_network(2);
		create_announced_chan_between_nodes(&nodes, 0, 1);

		route_payment(&nodes[0], &[&nodes[1]], 10000000);
		nodes[0].node.force_close_channel(&nodes[0].node.list_channels()[0].channel_id);
		{
			let events = nodes[0].node.get_and_clear_pending_msg_events();
			assert_eq!(events.len(), 1);
			match events[0] {
				MessageSendEvent::BroadcastChannelUpdate { msg: msgs::ChannelUpdate { contents: msgs::UnsignedChannelUpdate { flags, .. }, .. } } => {
					assert_eq!(flags & 0b10, 0b10);
				},
				_ => panic!("Unexpected event"),
			}
		}

		let node_txn = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap();
		assert_eq!(node_txn.len(), 2);

		let header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
		nodes[1].chain_monitor.block_connected_checked(&header, 1, &[&node_txn[0], &node_txn[1]], &[1; 2]);

		{
			let events = nodes[1].node.get_and_clear_pending_msg_events();
			assert_eq!(events.len(), 1);
			match events[0] {
				MessageSendEvent::BroadcastChannelUpdate { msg: msgs::ChannelUpdate { contents: msgs::UnsignedChannelUpdate { flags, .. }, .. } } => {
					assert_eq!(flags & 0b10, 0b10);
				},
				_ => panic!("Unexpected event"),
			}
		}

		// Duplicate the block_connected call since this may happen due to other listeners
		// registering new transactions
		nodes[1].chain_monitor.block_connected_checked(&header, 1, &[&node_txn[0], &node_txn[1]], &[1; 2]);
	}

	#[test]
	fn test_force_close_fail_back() {
		// Check which HTLCs are failed-backwards on channel force-closure
		let mut nodes = create_network(3);
		create_announced_chan_between_nodes(&nodes, 0, 1);
		create_announced_chan_between_nodes(&nodes, 1, 2);

		let route = nodes[0].router.get_route(&nodes[2].node.get_our_node_id(), None, &Vec::new(), 1000000, 42).unwrap();

		let (our_payment_preimage, our_payment_hash) = get_payment_preimage_hash!(nodes[0]);

		let mut payment_event = {
			nodes[0].node.send_payment(route, our_payment_hash).unwrap();
			check_added_monitors!(nodes[0], 1);

			let mut events = nodes[0].node.get_and_clear_pending_msg_events();
			assert_eq!(events.len(), 1);
			SendEvent::from_event(events.remove(0))
		};

		nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &payment_event.msgs[0]).unwrap();
		commitment_signed_dance!(nodes[1], nodes[0], payment_event.commitment_msg, false);

		let events_1 = nodes[1].node.get_and_clear_pending_events();
		assert_eq!(events_1.len(), 1);
		match events_1[0] {
			Event::PendingHTLCsForwardable { .. } => { },
			_ => panic!("Unexpected event"),
		};

		nodes[1].node.channel_state.lock().unwrap().next_forward = Instant::now();
		nodes[1].node.process_pending_htlc_forwards();

		let mut events_2 = nodes[1].node.get_and_clear_pending_msg_events();
		assert_eq!(events_2.len(), 1);
		payment_event = SendEvent::from_event(events_2.remove(0));
		assert_eq!(payment_event.msgs.len(), 1);

		check_added_monitors!(nodes[1], 1);
		nodes[2].node.handle_update_add_htlc(&nodes[1].node.get_our_node_id(), &payment_event.msgs[0]).unwrap();
		nodes[2].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &payment_event.commitment_msg).unwrap();
		check_added_monitors!(nodes[2], 1);
		let (_, _) = get_revoke_commit_msgs!(nodes[2], nodes[1].node.get_our_node_id());

		// nodes[2] now has the latest commitment transaction, but hasn't revoked its previous
		// state or updated nodes[1]' state. Now force-close and broadcast that commitment/HTLC
		// transaction and ensure nodes[1] doesn't fail-backwards (this was originally a bug!).

		nodes[2].node.force_close_channel(&payment_event.commitment_msg.channel_id);
		let events_3 = nodes[2].node.get_and_clear_pending_msg_events();
		assert_eq!(events_3.len(), 1);
		match events_3[0] {
			MessageSendEvent::BroadcastChannelUpdate { msg: msgs::ChannelUpdate { contents: msgs::UnsignedChannelUpdate { flags, .. }, .. } } => {
				assert_eq!(flags & 0b10, 0b10);
			},
			_ => panic!("Unexpected event"),
		}

		let tx = {
			let mut node_txn = nodes[2].tx_broadcaster.txn_broadcasted.lock().unwrap();
			// Note that we don't bother broadcasting the HTLC-Success transaction here as we don't
			// have a use for it unless nodes[2] learns the preimage somehow, the funds will go
			// back to nodes[1] upon timeout otherwise.
			assert_eq!(node_txn.len(), 1);
			node_txn.remove(0)
		};

		let header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
		nodes[1].chain_monitor.block_connected_checked(&header, 1, &[&tx], &[1]);

		let events_4 = nodes[1].node.get_and_clear_pending_msg_events();
		// Note no UpdateHTLCs event here from nodes[1] to nodes[0]!
		assert_eq!(events_4.len(), 1);
		match events_4[0] {
			MessageSendEvent::BroadcastChannelUpdate { msg: msgs::ChannelUpdate { contents: msgs::UnsignedChannelUpdate { flags, .. }, .. } } => {
				assert_eq!(flags & 0b10, 0b10);
			},
			_ => panic!("Unexpected event"),
		}

		// Now check that if we add the preimage to ChannelMonitor it broadcasts our HTLC-Success..
		{
			let mut monitors = nodes[2].chan_monitor.simple_monitor.monitors.lock().unwrap();
			monitors.get_mut(&OutPoint::new(Sha256dHash::from(&payment_event.commitment_msg.channel_id[..]), 0)).unwrap()
				.provide_payment_preimage(&our_payment_hash, &our_payment_preimage);
		}
		nodes[2].chain_monitor.block_connected_checked(&header, 1, &[&tx], &[1]);
		let node_txn = nodes[2].tx_broadcaster.txn_broadcasted.lock().unwrap();
		assert_eq!(node_txn.len(), 1);
		assert_eq!(node_txn[0].input.len(), 1);
		assert_eq!(node_txn[0].input[0].previous_output.txid, tx.txid());
		assert_eq!(node_txn[0].lock_time, 0); // Must be an HTLC-Success
		assert_eq!(node_txn[0].input[0].witness.len(), 5); // Must be an HTLC-Success

		check_spends!(node_txn[0], tx);
	}

	#[test]
	fn test_unconf_chan() {
		// After creating a chan between nodes, we disconnect all blocks previously seen to force a channel close on nodes[0] side
		let nodes = create_network(2);
		create_announced_chan_between_nodes(&nodes, 0, 1);

		let channel_state = nodes[0].node.channel_state.lock().unwrap();
		assert_eq!(channel_state.by_id.len(), 1);
		assert_eq!(channel_state.short_to_id.len(), 1);
		mem::drop(channel_state);

		let mut headers = Vec::new();
		let mut header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
		headers.push(header.clone());
		for _i in 2..100 {
			header = BlockHeader { version: 0x20000000, prev_blockhash: header.bitcoin_hash(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
			headers.push(header.clone());
		}
		while !headers.is_empty() {
			nodes[0].node.block_disconnected(&headers.pop().unwrap());
		}
		{
			let events = nodes[0].node.get_and_clear_pending_msg_events();
			assert_eq!(events.len(), 1);
			match events[0] {
				MessageSendEvent::BroadcastChannelUpdate { msg: msgs::ChannelUpdate { contents: msgs::UnsignedChannelUpdate { flags, .. }, .. } } => {
					assert_eq!(flags & 0b10, 0b10);
				},
				_ => panic!("Unexpected event"),
			}
		}
		let channel_state = nodes[0].node.channel_state.lock().unwrap();
		assert_eq!(channel_state.by_id.len(), 0);
		assert_eq!(channel_state.short_to_id.len(), 0);
	}

	macro_rules! get_chan_reestablish_msgs {
		($src_node: expr, $dst_node: expr) => {
			{
				let mut res = Vec::with_capacity(1);
				for msg in $src_node.node.get_and_clear_pending_msg_events() {
					if let MessageSendEvent::SendChannelReestablish { ref node_id, ref msg } = msg {
						assert_eq!(*node_id, $dst_node.node.get_our_node_id());
						res.push(msg.clone());
					} else {
						panic!("Unexpected event")
					}
				}
				res
			}
		}
	}

	macro_rules! handle_chan_reestablish_msgs {
		($src_node: expr, $dst_node: expr) => {
			{
				let msg_events = $src_node.node.get_and_clear_pending_msg_events();
				let mut idx = 0;
				let funding_locked = if let Some(&MessageSendEvent::SendFundingLocked { ref node_id, ref msg }) = msg_events.get(0) {
					idx += 1;
					assert_eq!(*node_id, $dst_node.node.get_our_node_id());
					Some(msg.clone())
				} else {
					None
				};

				let mut revoke_and_ack = None;
				let mut commitment_update = None;
				let order = if let Some(ev) = msg_events.get(idx) {
					idx += 1;
					match ev {
						&MessageSendEvent::SendRevokeAndACK { ref node_id, ref msg } => {
							assert_eq!(*node_id, $dst_node.node.get_our_node_id());
							revoke_and_ack = Some(msg.clone());
							RAACommitmentOrder::RevokeAndACKFirst
						},
						&MessageSendEvent::UpdateHTLCs { ref node_id, ref updates } => {
							assert_eq!(*node_id, $dst_node.node.get_our_node_id());
							commitment_update = Some(updates.clone());
							RAACommitmentOrder::CommitmentFirst
						},
						_ => panic!("Unexpected event"),
					}
				} else {
					RAACommitmentOrder::CommitmentFirst
				};

				if let Some(ev) = msg_events.get(idx) {
					match ev {
						&MessageSendEvent::SendRevokeAndACK { ref node_id, ref msg } => {
							assert_eq!(*node_id, $dst_node.node.get_our_node_id());
							assert!(revoke_and_ack.is_none());
							revoke_and_ack = Some(msg.clone());
						},
						&MessageSendEvent::UpdateHTLCs { ref node_id, ref updates } => {
							assert_eq!(*node_id, $dst_node.node.get_our_node_id());
							assert!(commitment_update.is_none());
							commitment_update = Some(updates.clone());
						},
						_ => panic!("Unexpected event"),
					}
				}

				(funding_locked, revoke_and_ack, commitment_update, order)
			}
		}
	}

	/// pending_htlc_adds includes both the holding cell and in-flight update_add_htlcs, whereas
	/// for claims/fails they are separated out.
	fn reconnect_nodes(node_a: &Node, node_b: &Node, send_funding_locked: (bool, bool), pending_htlc_adds: (i64, i64), pending_htlc_claims: (usize, usize), pending_cell_htlc_claims: (usize, usize), pending_cell_htlc_fails: (usize, usize), pending_raa: (bool, bool)) {
		node_a.node.peer_connected(&node_b.node.get_our_node_id());
		let reestablish_1 = get_chan_reestablish_msgs!(node_a, node_b);
		node_b.node.peer_connected(&node_a.node.get_our_node_id());
		let reestablish_2 = get_chan_reestablish_msgs!(node_b, node_a);

		let mut resp_1 = Vec::new();
		for msg in reestablish_1 {
			node_b.node.handle_channel_reestablish(&node_a.node.get_our_node_id(), &msg).unwrap();
			resp_1.push(handle_chan_reestablish_msgs!(node_b, node_a));
		}
		if pending_cell_htlc_claims.0 != 0 || pending_cell_htlc_fails.0 != 0 {
			check_added_monitors!(node_b, 1);
		} else {
			check_added_monitors!(node_b, 0);
		}

		let mut resp_2 = Vec::new();
		for msg in reestablish_2 {
			node_a.node.handle_channel_reestablish(&node_b.node.get_our_node_id(), &msg).unwrap();
			resp_2.push(handle_chan_reestablish_msgs!(node_a, node_b));
		}
		if pending_cell_htlc_claims.1 != 0 || pending_cell_htlc_fails.1 != 0 {
			check_added_monitors!(node_a, 1);
		} else {
			check_added_monitors!(node_a, 0);
		}

		// We dont yet support both needing updates, as that would require a different commitment dance:
		assert!((pending_htlc_adds.0 == 0 && pending_htlc_claims.0 == 0 && pending_cell_htlc_claims.0 == 0 && pending_cell_htlc_fails.0 == 0) ||
		        (pending_htlc_adds.1 == 0 && pending_htlc_claims.1 == 0 && pending_cell_htlc_claims.1 == 0 && pending_cell_htlc_fails.1 == 0));

		for chan_msgs in resp_1.drain(..) {
			if send_funding_locked.0 {
				node_a.node.handle_funding_locked(&node_b.node.get_our_node_id(), &chan_msgs.0.unwrap()).unwrap();
				let announcement_event = node_a.node.get_and_clear_pending_msg_events();
				if !announcement_event.is_empty() {
					assert_eq!(announcement_event.len(), 1);
					if let MessageSendEvent::SendAnnouncementSignatures { .. } = announcement_event[0] {
						//TODO: Test announcement_sigs re-sending
					} else { panic!("Unexpected event!"); }
				}
			} else {
				assert!(chan_msgs.0.is_none());
			}
			if pending_raa.0 {
				assert!(chan_msgs.3 == RAACommitmentOrder::RevokeAndACKFirst);
				node_a.node.handle_revoke_and_ack(&node_b.node.get_our_node_id(), &chan_msgs.1.unwrap()).unwrap();
				assert!(node_a.node.get_and_clear_pending_msg_events().is_empty());
				check_added_monitors!(node_a, 1);
			} else {
				assert!(chan_msgs.1.is_none());
			}
			if pending_htlc_adds.0 != 0 || pending_htlc_claims.0 != 0 || pending_cell_htlc_claims.0 != 0 || pending_cell_htlc_fails.0 != 0 {
				let commitment_update = chan_msgs.2.unwrap();
				if pending_htlc_adds.0 != -1 { // We use -1 to denote a response commitment_signed
					assert_eq!(commitment_update.update_add_htlcs.len(), pending_htlc_adds.0 as usize);
				} else {
					assert!(commitment_update.update_add_htlcs.is_empty());
				}
				assert_eq!(commitment_update.update_fulfill_htlcs.len(), pending_htlc_claims.0 + pending_cell_htlc_claims.0);
				assert_eq!(commitment_update.update_fail_htlcs.len(), pending_cell_htlc_fails.0);
				assert!(commitment_update.update_fail_malformed_htlcs.is_empty());
				for update_add in commitment_update.update_add_htlcs {
					node_a.node.handle_update_add_htlc(&node_b.node.get_our_node_id(), &update_add).unwrap();
				}
				for update_fulfill in commitment_update.update_fulfill_htlcs {
					node_a.node.handle_update_fulfill_htlc(&node_b.node.get_our_node_id(), &update_fulfill).unwrap();
				}
				for update_fail in commitment_update.update_fail_htlcs {
					node_a.node.handle_update_fail_htlc(&node_b.node.get_our_node_id(), &update_fail).unwrap();
				}

				if pending_htlc_adds.0 != -1 { // We use -1 to denote a response commitment_signed
					commitment_signed_dance!(node_a, node_b, commitment_update.commitment_signed, false);
				} else {
					node_a.node.handle_commitment_signed(&node_b.node.get_our_node_id(), &commitment_update.commitment_signed).unwrap();
					check_added_monitors!(node_a, 1);
					let as_revoke_and_ack = get_event_msg!(node_a, MessageSendEvent::SendRevokeAndACK, node_b.node.get_our_node_id());
					// No commitment_signed so get_event_msg's assert(len == 1) passes
					node_b.node.handle_revoke_and_ack(&node_a.node.get_our_node_id(), &as_revoke_and_ack).unwrap();
					assert!(node_b.node.get_and_clear_pending_msg_events().is_empty());
					check_added_monitors!(node_b, 1);
				}
			} else {
				assert!(chan_msgs.2.is_none());
			}
		}

		for chan_msgs in resp_2.drain(..) {
			if send_funding_locked.1 {
				node_b.node.handle_funding_locked(&node_a.node.get_our_node_id(), &chan_msgs.0.unwrap()).unwrap();
				let announcement_event = node_b.node.get_and_clear_pending_msg_events();
				if !announcement_event.is_empty() {
					assert_eq!(announcement_event.len(), 1);
					if let MessageSendEvent::SendAnnouncementSignatures { .. } = announcement_event[0] {
						//TODO: Test announcement_sigs re-sending
					} else { panic!("Unexpected event!"); }
				}
			} else {
				assert!(chan_msgs.0.is_none());
			}
			if pending_raa.1 {
				assert!(chan_msgs.3 == RAACommitmentOrder::RevokeAndACKFirst);
				node_b.node.handle_revoke_and_ack(&node_a.node.get_our_node_id(), &chan_msgs.1.unwrap()).unwrap();
				assert!(node_b.node.get_and_clear_pending_msg_events().is_empty());
				check_added_monitors!(node_b, 1);
			} else {
				assert!(chan_msgs.1.is_none());
			}
			if pending_htlc_adds.1 != 0 || pending_htlc_claims.1 != 0 || pending_cell_htlc_claims.1 != 0 || pending_cell_htlc_fails.1 != 0 {
				let commitment_update = chan_msgs.2.unwrap();
				if pending_htlc_adds.1 != -1 { // We use -1 to denote a response commitment_signed
					assert_eq!(commitment_update.update_add_htlcs.len(), pending_htlc_adds.1 as usize);
				}
				assert_eq!(commitment_update.update_fulfill_htlcs.len(), pending_htlc_claims.0 + pending_cell_htlc_claims.0);
				assert_eq!(commitment_update.update_fail_htlcs.len(), pending_cell_htlc_fails.0);
				assert!(commitment_update.update_fail_malformed_htlcs.is_empty());
				for update_add in commitment_update.update_add_htlcs {
					node_b.node.handle_update_add_htlc(&node_a.node.get_our_node_id(), &update_add).unwrap();
				}
				for update_fulfill in commitment_update.update_fulfill_htlcs {
					node_b.node.handle_update_fulfill_htlc(&node_a.node.get_our_node_id(), &update_fulfill).unwrap();
				}
				for update_fail in commitment_update.update_fail_htlcs {
					node_b.node.handle_update_fail_htlc(&node_a.node.get_our_node_id(), &update_fail).unwrap();
				}

				if pending_htlc_adds.1 != -1 { // We use -1 to denote a response commitment_signed
					commitment_signed_dance!(node_b, node_a, commitment_update.commitment_signed, false);
				} else {
					node_b.node.handle_commitment_signed(&node_a.node.get_our_node_id(), &commitment_update.commitment_signed).unwrap();
					check_added_monitors!(node_b, 1);
					let bs_revoke_and_ack = get_event_msg!(node_b, MessageSendEvent::SendRevokeAndACK, node_a.node.get_our_node_id());
					// No commitment_signed so get_event_msg's assert(len == 1) passes
					node_a.node.handle_revoke_and_ack(&node_b.node.get_our_node_id(), &bs_revoke_and_ack).unwrap();
					assert!(node_a.node.get_and_clear_pending_msg_events().is_empty());
					check_added_monitors!(node_a, 1);
				}
			} else {
				assert!(chan_msgs.2.is_none());
			}
		}
	}

	#[test]
	fn test_simple_peer_disconnect() {
		// Test that we can reconnect when there are no lost messages
		let nodes = create_network(3);
		create_announced_chan_between_nodes(&nodes, 0, 1);
		create_announced_chan_between_nodes(&nodes, 1, 2);

		nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id(), false);
		nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);
		reconnect_nodes(&nodes[0], &nodes[1], (true, true), (0, 0), (0, 0), (0, 0), (0, 0), (false, false));

		let payment_preimage_1 = route_payment(&nodes[0], &vec!(&nodes[1], &nodes[2])[..], 1000000).0;
		let payment_hash_2 = route_payment(&nodes[0], &vec!(&nodes[1], &nodes[2])[..], 1000000).1;
		fail_payment(&nodes[0], &vec!(&nodes[1], &nodes[2]), payment_hash_2);
		claim_payment(&nodes[0], &vec!(&nodes[1], &nodes[2]), payment_preimage_1);

		nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id(), false);
		nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);
		reconnect_nodes(&nodes[0], &nodes[1], (false, false), (0, 0), (0, 0), (0, 0), (0, 0), (false, false));

		let payment_preimage_3 = route_payment(&nodes[0], &vec!(&nodes[1], &nodes[2])[..], 1000000).0;
		let payment_preimage_4 = route_payment(&nodes[0], &vec!(&nodes[1], &nodes[2])[..], 1000000).0;
		let payment_hash_5 = route_payment(&nodes[0], &vec!(&nodes[1], &nodes[2])[..], 1000000).1;
		let payment_hash_6 = route_payment(&nodes[0], &vec!(&nodes[1], &nodes[2])[..], 1000000).1;

		nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id(), false);
		nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);

		claim_payment_along_route(&nodes[0], &vec!(&nodes[1], &nodes[2]), true, payment_preimage_3);
		fail_payment_along_route(&nodes[0], &[&nodes[1], &nodes[2]], true, payment_hash_5);

		reconnect_nodes(&nodes[0], &nodes[1], (false, false), (0, 0), (0, 0), (1, 0), (1, 0), (false, false));
		{
			let events = nodes[0].node.get_and_clear_pending_events();
			assert_eq!(events.len(), 2);
			match events[0] {
				Event::PaymentSent { payment_preimage } => {
					assert_eq!(payment_preimage, payment_preimage_3);
				},
				_ => panic!("Unexpected event"),
			}
			match events[1] {
				Event::PaymentFailed { payment_hash, rejected_by_dest } => {
					assert_eq!(payment_hash, payment_hash_5);
					assert!(rejected_by_dest);
				},
				_ => panic!("Unexpected event"),
			}
		}

		claim_payment(&nodes[0], &vec!(&nodes[1], &nodes[2]), payment_preimage_4);
		fail_payment(&nodes[0], &vec!(&nodes[1], &nodes[2]), payment_hash_6);
	}

	fn do_test_drop_messages_peer_disconnect(messages_delivered: u8) {
		// Test that we can reconnect when in-flight HTLC updates get dropped
		let mut nodes = create_network(2);
		if messages_delivered == 0 {
			create_chan_between_nodes_with_value_a(&nodes[0], &nodes[1], 100000, 10001);
			// nodes[1] doesn't receive the funding_locked message (it'll be re-sent on reconnect)
		} else {
			create_announced_chan_between_nodes(&nodes, 0, 1);
		}

		let route = nodes[0].router.get_route(&nodes[1].node.get_our_node_id(), Some(&nodes[0].node.list_usable_channels()), &Vec::new(), 1000000, TEST_FINAL_CLTV).unwrap();
		let (payment_preimage_1, payment_hash_1) = get_payment_preimage_hash!(nodes[0]);

		let payment_event = {
			nodes[0].node.send_payment(route.clone(), payment_hash_1).unwrap();
			check_added_monitors!(nodes[0], 1);

			let mut events = nodes[0].node.get_and_clear_pending_msg_events();
			assert_eq!(events.len(), 1);
			SendEvent::from_event(events.remove(0))
		};
		assert_eq!(nodes[1].node.get_our_node_id(), payment_event.node_id);

		if messages_delivered < 2 {
			// Drop the payment_event messages, and let them get re-generated in reconnect_nodes!
		} else {
			nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &payment_event.msgs[0]).unwrap();
			if messages_delivered >= 3 {
				nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &payment_event.commitment_msg).unwrap();
				check_added_monitors!(nodes[1], 1);
				let (bs_revoke_and_ack, bs_commitment_signed) = get_revoke_commit_msgs!(nodes[1], nodes[0].node.get_our_node_id());

				if messages_delivered >= 4 {
					nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_revoke_and_ack).unwrap();
					assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
					check_added_monitors!(nodes[0], 1);

					if messages_delivered >= 5 {
						nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &bs_commitment_signed).unwrap();
						let as_revoke_and_ack = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());
						// No commitment_signed so get_event_msg's assert(len == 1) passes
						check_added_monitors!(nodes[0], 1);

						if messages_delivered >= 6 {
							nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &as_revoke_and_ack).unwrap();
							assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
							check_added_monitors!(nodes[1], 1);
						}
					}
				}
			}
		}

		nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id(), false);
		nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);
		if messages_delivered < 3 {
			// Even if the funding_locked messages get exchanged, as long as nothing further was
			// received on either side, both sides will need to resend them.
			reconnect_nodes(&nodes[0], &nodes[1], (true, true), (0, 1), (0, 0), (0, 0), (0, 0), (false, false));
		} else if messages_delivered == 3 {
			// nodes[0] still wants its RAA + commitment_signed
			reconnect_nodes(&nodes[0], &nodes[1], (false, false), (-1, 0), (0, 0), (0, 0), (0, 0), (true, false));
		} else if messages_delivered == 4 {
			// nodes[0] still wants its commitment_signed
			reconnect_nodes(&nodes[0], &nodes[1], (false, false), (-1, 0), (0, 0), (0, 0), (0, 0), (false, false));
		} else if messages_delivered == 5 {
			// nodes[1] still wants its final RAA
			reconnect_nodes(&nodes[0], &nodes[1], (false, false), (0, 0), (0, 0), (0, 0), (0, 0), (false, true));
		} else if messages_delivered == 6 {
			// Everything was delivered...
			reconnect_nodes(&nodes[0], &nodes[1], (false, false), (0, 0), (0, 0), (0, 0), (0, 0), (false, false));
		}

		let events_1 = nodes[1].node.get_and_clear_pending_events();
		assert_eq!(events_1.len(), 1);
		match events_1[0] {
			Event::PendingHTLCsForwardable { .. } => { },
			_ => panic!("Unexpected event"),
		};

		nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id(), false);
		nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);
		reconnect_nodes(&nodes[0], &nodes[1], (false, false), (0, 0), (0, 0), (0, 0), (0, 0), (false, false));

		nodes[1].node.channel_state.lock().unwrap().next_forward = Instant::now();
		nodes[1].node.process_pending_htlc_forwards();

		let events_2 = nodes[1].node.get_and_clear_pending_events();
		assert_eq!(events_2.len(), 1);
		match events_2[0] {
			Event::PaymentReceived { ref payment_hash, amt } => {
				assert_eq!(payment_hash_1, *payment_hash);
				assert_eq!(amt, 1000000);
			},
			_ => panic!("Unexpected event"),
		}

		nodes[1].node.claim_funds(payment_preimage_1);
		check_added_monitors!(nodes[1], 1);

		let events_3 = nodes[1].node.get_and_clear_pending_msg_events();
		assert_eq!(events_3.len(), 1);
		let (update_fulfill_htlc, commitment_signed) = match events_3[0] {
			MessageSendEvent::UpdateHTLCs { ref node_id, ref updates } => {
				assert_eq!(*node_id, nodes[0].node.get_our_node_id());
				assert!(updates.update_add_htlcs.is_empty());
				assert!(updates.update_fail_htlcs.is_empty());
				assert_eq!(updates.update_fulfill_htlcs.len(), 1);
				assert!(updates.update_fail_malformed_htlcs.is_empty());
				assert!(updates.update_fee.is_none());
				(updates.update_fulfill_htlcs[0].clone(), updates.commitment_signed.clone())
			},
			_ => panic!("Unexpected event"),
		};

		if messages_delivered >= 1 {
			nodes[0].node.handle_update_fulfill_htlc(&nodes[1].node.get_our_node_id(), &update_fulfill_htlc).unwrap();

			let events_4 = nodes[0].node.get_and_clear_pending_events();
			assert_eq!(events_4.len(), 1);
			match events_4[0] {
				Event::PaymentSent { ref payment_preimage } => {
					assert_eq!(payment_preimage_1, *payment_preimage);
				},
				_ => panic!("Unexpected event"),
			}

			if messages_delivered >= 2 {
				nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &commitment_signed).unwrap();
				check_added_monitors!(nodes[0], 1);
				let (as_revoke_and_ack, as_commitment_signed) = get_revoke_commit_msgs!(nodes[0], nodes[1].node.get_our_node_id());

				if messages_delivered >= 3 {
					nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &as_revoke_and_ack).unwrap();
					assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
					check_added_monitors!(nodes[1], 1);

					if messages_delivered >= 4 {
						nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &as_commitment_signed).unwrap();
						let bs_revoke_and_ack = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, nodes[0].node.get_our_node_id());
						// No commitment_signed so get_event_msg's assert(len == 1) passes
						check_added_monitors!(nodes[1], 1);

						if messages_delivered >= 5 {
							nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_revoke_and_ack).unwrap();
							assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
							check_added_monitors!(nodes[0], 1);
						}
					}
				}
			}
		}

		nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id(), false);
		nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);
		if messages_delivered < 2 {
			reconnect_nodes(&nodes[0], &nodes[1], (false, false), (0, 0), (1, 0), (0, 0), (0, 0), (false, false));
			//TODO: Deduplicate PaymentSent events, then enable this if:
			//if messages_delivered < 1 {
				let events_4 = nodes[0].node.get_and_clear_pending_events();
				assert_eq!(events_4.len(), 1);
				match events_4[0] {
					Event::PaymentSent { ref payment_preimage } => {
						assert_eq!(payment_preimage_1, *payment_preimage);
					},
					_ => panic!("Unexpected event"),
				}
			//}
		} else if messages_delivered == 2 {
			// nodes[0] still wants its RAA + commitment_signed
			reconnect_nodes(&nodes[0], &nodes[1], (false, false), (0, -1), (0, 0), (0, 0), (0, 0), (false, true));
		} else if messages_delivered == 3 {
			// nodes[0] still wants its commitment_signed
			reconnect_nodes(&nodes[0], &nodes[1], (false, false), (0, -1), (0, 0), (0, 0), (0, 0), (false, false));
		} else if messages_delivered == 4 {
			// nodes[1] still wants its final RAA
			reconnect_nodes(&nodes[0], &nodes[1], (false, false), (0, 0), (0, 0), (0, 0), (0, 0), (true, false));
		} else if messages_delivered == 5 {
			// Everything was delivered...
			reconnect_nodes(&nodes[0], &nodes[1], (false, false), (0, 0), (0, 0), (0, 0), (0, 0), (false, false));
		}

		nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id(), false);
		nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);
		reconnect_nodes(&nodes[0], &nodes[1], (false, false), (0, 0), (0, 0), (0, 0), (0, 0), (false, false));

		// Channel should still work fine...
		let payment_preimage_2 = send_along_route(&nodes[0], route, &[&nodes[1]], 1000000).0;
		claim_payment(&nodes[0], &[&nodes[1]], payment_preimage_2);
	}

	#[test]
	fn test_drop_messages_peer_disconnect_a() {
		do_test_drop_messages_peer_disconnect(0);
		do_test_drop_messages_peer_disconnect(1);
		do_test_drop_messages_peer_disconnect(2);
		do_test_drop_messages_peer_disconnect(3);
	}

	#[test]
	fn test_drop_messages_peer_disconnect_b() {
		do_test_drop_messages_peer_disconnect(4);
		do_test_drop_messages_peer_disconnect(5);
		do_test_drop_messages_peer_disconnect(6);
	}

	#[test]
	fn test_funding_peer_disconnect() {
		// Test that we can lock in our funding tx while disconnected
		let nodes = create_network(2);
		let tx = create_chan_between_nodes_with_value_init(&nodes[0], &nodes[1], 100000, 10001);

		nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id(), false);
		nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);

		confirm_transaction(&nodes[0].chain_monitor, &tx, tx.version);
		let events_1 = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(events_1.len(), 1);
		match events_1[0] {
			MessageSendEvent::SendFundingLocked { ref node_id, msg: _ } => {
				assert_eq!(*node_id, nodes[1].node.get_our_node_id());
			},
			_ => panic!("Unexpected event"),
		}

		reconnect_nodes(&nodes[0], &nodes[1], (false, true), (0, 0), (0, 0), (0, 0), (0, 0), (false, false));

		nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id(), false);
		nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);

		confirm_transaction(&nodes[1].chain_monitor, &tx, tx.version);
		let events_2 = nodes[1].node.get_and_clear_pending_msg_events();
		assert_eq!(events_2.len(), 2);
		match events_2[0] {
			MessageSendEvent::SendFundingLocked { ref node_id, msg: _ } => {
				assert_eq!(*node_id, nodes[0].node.get_our_node_id());
			},
			_ => panic!("Unexpected event"),
		}
		match events_2[1] {
			MessageSendEvent::SendAnnouncementSignatures { ref node_id, msg: _ } => {
				assert_eq!(*node_id, nodes[0].node.get_our_node_id());
			},
			_ => panic!("Unexpected event"),
		}

		reconnect_nodes(&nodes[0], &nodes[1], (true, true), (0, 0), (0, 0), (0, 0), (0, 0), (false, false));

		// TODO: We shouldn't need to manually pass list_usable_chanels here once we support
		// rebroadcasting announcement_signatures upon reconnect.

		let route = nodes[0].router.get_route(&nodes[1].node.get_our_node_id(), Some(&nodes[0].node.list_usable_channels()), &Vec::new(), 1000000, TEST_FINAL_CLTV).unwrap();
		let (payment_preimage, _) = send_along_route(&nodes[0], route, &[&nodes[1]], 1000000);
		claim_payment(&nodes[0], &[&nodes[1]], payment_preimage);
	}

	#[test]
	fn test_drop_messages_peer_disconnect_dual_htlc() {
		// Test that we can handle reconnecting when both sides of a channel have pending
		// commitment_updates when we disconnect.
		let mut nodes = create_network(2);
		create_announced_chan_between_nodes(&nodes, 0, 1);

		let (payment_preimage_1, _) = route_payment(&nodes[0], &[&nodes[1]], 1000000);

		// Now try to send a second payment which will fail to send
		let route = nodes[0].router.get_route(&nodes[1].node.get_our_node_id(), None, &Vec::new(), 1000000, TEST_FINAL_CLTV).unwrap();
		let (payment_preimage_2, payment_hash_2) = get_payment_preimage_hash!(nodes[0]);

		nodes[0].node.send_payment(route.clone(), payment_hash_2).unwrap();
		check_added_monitors!(nodes[0], 1);

		let events_1 = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(events_1.len(), 1);
		match events_1[0] {
			MessageSendEvent::UpdateHTLCs { .. } => {},
			_ => panic!("Unexpected event"),
		}

		assert!(nodes[1].node.claim_funds(payment_preimage_1));
		check_added_monitors!(nodes[1], 1);

		let events_2 = nodes[1].node.get_and_clear_pending_msg_events();
		assert_eq!(events_2.len(), 1);
		match events_2[0] {
			MessageSendEvent::UpdateHTLCs { ref node_id, updates: msgs::CommitmentUpdate { ref update_add_htlcs, ref update_fulfill_htlcs, ref update_fail_htlcs, ref update_fail_malformed_htlcs, ref update_fee, ref commitment_signed } } => {
				assert_eq!(*node_id, nodes[0].node.get_our_node_id());
				assert!(update_add_htlcs.is_empty());
				assert_eq!(update_fulfill_htlcs.len(), 1);
				assert!(update_fail_htlcs.is_empty());
				assert!(update_fail_malformed_htlcs.is_empty());
				assert!(update_fee.is_none());

				nodes[0].node.handle_update_fulfill_htlc(&nodes[1].node.get_our_node_id(), &update_fulfill_htlcs[0]).unwrap();
				let events_3 = nodes[0].node.get_and_clear_pending_events();
				assert_eq!(events_3.len(), 1);
				match events_3[0] {
					Event::PaymentSent { ref payment_preimage } => {
						assert_eq!(*payment_preimage, payment_preimage_1);
					},
					_ => panic!("Unexpected event"),
				}

				nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), commitment_signed).unwrap();
				let _ = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());
				// No commitment_signed so get_event_msg's assert(len == 1) passes
				check_added_monitors!(nodes[0], 1);
			},
			_ => panic!("Unexpected event"),
		}

		nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id(), false);
		nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);

		nodes[0].node.peer_connected(&nodes[1].node.get_our_node_id());
		let reestablish_1 = get_chan_reestablish_msgs!(nodes[0], nodes[1]);
		assert_eq!(reestablish_1.len(), 1);
		nodes[1].node.peer_connected(&nodes[0].node.get_our_node_id());
		let reestablish_2 = get_chan_reestablish_msgs!(nodes[1], nodes[0]);
		assert_eq!(reestablish_2.len(), 1);

		nodes[0].node.handle_channel_reestablish(&nodes[1].node.get_our_node_id(), &reestablish_2[0]).unwrap();
		let as_resp = handle_chan_reestablish_msgs!(nodes[0], nodes[1]);
		nodes[1].node.handle_channel_reestablish(&nodes[0].node.get_our_node_id(), &reestablish_1[0]).unwrap();
		let bs_resp = handle_chan_reestablish_msgs!(nodes[1], nodes[0]);

		assert!(as_resp.0.is_none());
		assert!(bs_resp.0.is_none());

		assert!(bs_resp.1.is_none());
		assert!(bs_resp.2.is_none());

		assert!(as_resp.3 == RAACommitmentOrder::CommitmentFirst);

		assert_eq!(as_resp.2.as_ref().unwrap().update_add_htlcs.len(), 1);
		assert!(as_resp.2.as_ref().unwrap().update_fulfill_htlcs.is_empty());
		assert!(as_resp.2.as_ref().unwrap().update_fail_htlcs.is_empty());
		assert!(as_resp.2.as_ref().unwrap().update_fail_malformed_htlcs.is_empty());
		assert!(as_resp.2.as_ref().unwrap().update_fee.is_none());
		nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &as_resp.2.as_ref().unwrap().update_add_htlcs[0]).unwrap();
		nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &as_resp.2.as_ref().unwrap().commitment_signed).unwrap();
		let bs_revoke_and_ack = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, nodes[0].node.get_our_node_id());
		// No commitment_signed so get_event_msg's assert(len == 1) passes
		check_added_monitors!(nodes[1], 1);

		nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), as_resp.1.as_ref().unwrap()).unwrap();
		let bs_second_commitment_signed = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
		assert!(bs_second_commitment_signed.update_add_htlcs.is_empty());
		assert!(bs_second_commitment_signed.update_fulfill_htlcs.is_empty());
		assert!(bs_second_commitment_signed.update_fail_htlcs.is_empty());
		assert!(bs_second_commitment_signed.update_fail_malformed_htlcs.is_empty());
		assert!(bs_second_commitment_signed.update_fee.is_none());
		check_added_monitors!(nodes[1], 1);

		nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_revoke_and_ack).unwrap();
		let as_commitment_signed = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
		assert!(as_commitment_signed.update_add_htlcs.is_empty());
		assert!(as_commitment_signed.update_fulfill_htlcs.is_empty());
		assert!(as_commitment_signed.update_fail_htlcs.is_empty());
		assert!(as_commitment_signed.update_fail_malformed_htlcs.is_empty());
		assert!(as_commitment_signed.update_fee.is_none());
		check_added_monitors!(nodes[0], 1);

		nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &bs_second_commitment_signed.commitment_signed).unwrap();
		let as_revoke_and_ack = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());
		// No commitment_signed so get_event_msg's assert(len == 1) passes
		check_added_monitors!(nodes[0], 1);

		nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &as_commitment_signed.commitment_signed).unwrap();
		let bs_second_revoke_and_ack = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, nodes[0].node.get_our_node_id());
		// No commitment_signed so get_event_msg's assert(len == 1) passes
		check_added_monitors!(nodes[1], 1);

		nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &as_revoke_and_ack).unwrap();
		assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
		check_added_monitors!(nodes[1], 1);

		let events_4 = nodes[1].node.get_and_clear_pending_events();
		assert_eq!(events_4.len(), 1);
		match events_4[0] {
			Event::PendingHTLCsForwardable { .. } => { },
			_ => panic!("Unexpected event"),
		};

		nodes[1].node.channel_state.lock().unwrap().next_forward = Instant::now();
		nodes[1].node.process_pending_htlc_forwards();

		let events_5 = nodes[1].node.get_and_clear_pending_events();
		assert_eq!(events_5.len(), 1);
		match events_5[0] {
			Event::PaymentReceived { ref payment_hash, amt: _ } => {
				assert_eq!(payment_hash_2, *payment_hash);
			},
			_ => panic!("Unexpected event"),
		}

		nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_second_revoke_and_ack).unwrap();
		assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
		check_added_monitors!(nodes[0], 1);

		claim_payment(&nodes[0], &[&nodes[1]], payment_preimage_2);
	}

	#[test]
	fn test_simple_monitor_permanent_update_fail() {
		// Test that we handle a simple permanent monitor update failure
		let mut nodes = create_network(2);
		create_announced_chan_between_nodes(&nodes, 0, 1);

		let route = nodes[0].router.get_route(&nodes[1].node.get_our_node_id(), None, &Vec::new(), 1000000, TEST_FINAL_CLTV).unwrap();
		let (_, payment_hash_1) = get_payment_preimage_hash!(nodes[0]);

		*nodes[0].chan_monitor.update_ret.lock().unwrap() = Err(ChannelMonitorUpdateErr::PermanentFailure);
		if let Err(APIError::MonitorUpdateFailed) = nodes[0].node.send_payment(route, payment_hash_1) {} else { panic!(); }
		check_added_monitors!(nodes[0], 1);

		let events_1 = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(events_1.len(), 1);
		match events_1[0] {
			MessageSendEvent::BroadcastChannelUpdate { .. } => {},
			_ => panic!("Unexpected event"),
		};

		// TODO: Once we hit the chain with the failure transaction we should check that we get a
		// PaymentFailed event

		assert_eq!(nodes[0].node.list_channels().len(), 0);
	}

	fn do_test_simple_monitor_temporary_update_fail(disconnect: bool) {
		// Test that we can recover from a simple temporary monitor update failure optionally with
		// a disconnect in between
		let mut nodes = create_network(2);
		create_announced_chan_between_nodes(&nodes, 0, 1);

		let route = nodes[0].router.get_route(&nodes[1].node.get_our_node_id(), None, &Vec::new(), 1000000, TEST_FINAL_CLTV).unwrap();
		let (payment_preimage_1, payment_hash_1) = get_payment_preimage_hash!(nodes[0]);

		*nodes[0].chan_monitor.update_ret.lock().unwrap() = Err(ChannelMonitorUpdateErr::TemporaryFailure);
		if let Err(APIError::MonitorUpdateFailed) = nodes[0].node.send_payment(route.clone(), payment_hash_1) {} else { panic!(); }
		check_added_monitors!(nodes[0], 1);

		assert!(nodes[0].node.get_and_clear_pending_events().is_empty());
		assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
		assert_eq!(nodes[0].node.list_channels().len(), 1);

		if disconnect {
			nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id(), false);
			nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);
			reconnect_nodes(&nodes[0], &nodes[1], (true, true), (0, 0), (0, 0), (0, 0), (0, 0), (false, false));
		}

		*nodes[0].chan_monitor.update_ret.lock().unwrap() = Ok(());
		nodes[0].node.test_restore_channel_monitor();
		check_added_monitors!(nodes[0], 1);

		let mut events_2 = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(events_2.len(), 1);
		let payment_event = SendEvent::from_event(events_2.pop().unwrap());
		assert_eq!(payment_event.node_id, nodes[1].node.get_our_node_id());
		nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &payment_event.msgs[0]).unwrap();
		commitment_signed_dance!(nodes[1], nodes[0], payment_event.commitment_msg, false);

		expect_pending_htlcs_forwardable!(nodes[1]);

		let events_3 = nodes[1].node.get_and_clear_pending_events();
		assert_eq!(events_3.len(), 1);
		match events_3[0] {
			Event::PaymentReceived { ref payment_hash, amt } => {
				assert_eq!(payment_hash_1, *payment_hash);
				assert_eq!(amt, 1000000);
			},
			_ => panic!("Unexpected event"),
		}

		claim_payment(&nodes[0], &[&nodes[1]], payment_preimage_1);

		// Now set it to failed again...
		let (_, payment_hash_2) = get_payment_preimage_hash!(nodes[0]);
		*nodes[0].chan_monitor.update_ret.lock().unwrap() = Err(ChannelMonitorUpdateErr::TemporaryFailure);
		if let Err(APIError::MonitorUpdateFailed) = nodes[0].node.send_payment(route, payment_hash_2) {} else { panic!(); }
		check_added_monitors!(nodes[0], 1);

		assert!(nodes[0].node.get_and_clear_pending_events().is_empty());
		assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
		assert_eq!(nodes[0].node.list_channels().len(), 1);

		if disconnect {
			nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id(), false);
			nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);
			reconnect_nodes(&nodes[0], &nodes[1], (false, false), (0, 0), (0, 0), (0, 0), (0, 0), (false, false));
		}

		// ...and make sure we can force-close a TemporaryFailure channel with a PermanentFailure
		*nodes[0].chan_monitor.update_ret.lock().unwrap() = Err(ChannelMonitorUpdateErr::PermanentFailure);
		nodes[0].node.test_restore_channel_monitor();
		check_added_monitors!(nodes[0], 1);

		let events_5 = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(events_5.len(), 1);
		match events_5[0] {
			MessageSendEvent::BroadcastChannelUpdate { .. } => {},
			_ => panic!("Unexpected event"),
		}

		// TODO: Once we hit the chain with the failure transaction we should check that we get a
		// PaymentFailed event

		assert_eq!(nodes[0].node.list_channels().len(), 0);
	}

	#[test]
	fn test_simple_monitor_temporary_update_fail() {
		do_test_simple_monitor_temporary_update_fail(false);
		do_test_simple_monitor_temporary_update_fail(true);
	}

	fn do_test_monitor_temporary_update_fail(disconnect_count: usize) {
		let disconnect_flags = 8 | 16;

		// Test that we can recover from a temporary monitor update failure with some in-flight
		// HTLCs going on at the same time potentially with some disconnection thrown in.
		// * First we route a payment, then get a temporary monitor update failure when trying to
		//   route a second payment. We then claim the first payment.
		// * If disconnect_count is set, we will disconnect at this point (which is likely as
		//   TemporaryFailure likely indicates net disconnect which resulted in failing to update
		//   the ChannelMonitor on a watchtower).
		// * If !(disconnect_count & 16) we deliver a update_fulfill_htlc/CS for the first payment
		//   immediately, otherwise we wait sconnect and deliver them via the reconnect
		//   channel_reestablish processing (ie disconnect_count & 16 makes no sense if
		//   disconnect_count & !disconnect_flags is 0).
		// * We then update the channel monitor, reconnecting if disconnect_count is set and walk
		//   through message sending, potentially disconnect/reconnecting multiple times based on
		//   disconnect_count, to get the update_fulfill_htlc through.
		// * We then walk through more message exchanges to get the original update_add_htlc
		//   through, swapping message ordering based on disconnect_count & 8 and optionally
		//   disconnect/reconnecting based on disconnect_count.
		let mut nodes = create_network(2);
		create_announced_chan_between_nodes(&nodes, 0, 1);

		let (payment_preimage_1, _) = route_payment(&nodes[0], &[&nodes[1]], 1000000);

		// Now try to send a second payment which will fail to send
		let route = nodes[0].router.get_route(&nodes[1].node.get_our_node_id(), None, &Vec::new(), 1000000, TEST_FINAL_CLTV).unwrap();
		let (payment_preimage_2, payment_hash_2) = get_payment_preimage_hash!(nodes[0]);

		*nodes[0].chan_monitor.update_ret.lock().unwrap() = Err(ChannelMonitorUpdateErr::TemporaryFailure);
		if let Err(APIError::MonitorUpdateFailed) = nodes[0].node.send_payment(route.clone(), payment_hash_2) {} else { panic!(); }
		check_added_monitors!(nodes[0], 1);

		assert!(nodes[0].node.get_and_clear_pending_events().is_empty());
		assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
		assert_eq!(nodes[0].node.list_channels().len(), 1);

		// Claim the previous payment, which will result in a update_fulfill_htlc/CS from nodes[1]
		// but nodes[0] won't respond since it is frozen.
		assert!(nodes[1].node.claim_funds(payment_preimage_1));
		check_added_monitors!(nodes[1], 1);
		let events_2 = nodes[1].node.get_and_clear_pending_msg_events();
		assert_eq!(events_2.len(), 1);
		let (bs_initial_fulfill, bs_initial_commitment_signed) = match events_2[0] {
			MessageSendEvent::UpdateHTLCs { ref node_id, updates: msgs::CommitmentUpdate { ref update_add_htlcs, ref update_fulfill_htlcs, ref update_fail_htlcs, ref update_fail_malformed_htlcs, ref update_fee, ref commitment_signed } } => {
				assert_eq!(*node_id, nodes[0].node.get_our_node_id());
				assert!(update_add_htlcs.is_empty());
				assert_eq!(update_fulfill_htlcs.len(), 1);
				assert!(update_fail_htlcs.is_empty());
				assert!(update_fail_malformed_htlcs.is_empty());
				assert!(update_fee.is_none());

				if (disconnect_count & 16) == 0 {
					nodes[0].node.handle_update_fulfill_htlc(&nodes[1].node.get_our_node_id(), &update_fulfill_htlcs[0]).unwrap();
					let events_3 = nodes[0].node.get_and_clear_pending_events();
					assert_eq!(events_3.len(), 1);
					match events_3[0] {
						Event::PaymentSent { ref payment_preimage } => {
							assert_eq!(*payment_preimage, payment_preimage_1);
						},
						_ => panic!("Unexpected event"),
					}

					if let Err(msgs::HandleError{err, action: Some(msgs::ErrorAction::IgnoreError) }) = nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), commitment_signed) {
						assert_eq!(err, "Previous monitor update failure prevented generation of RAA");
					} else { panic!(); }
				}

				(update_fulfill_htlcs[0].clone(), commitment_signed.clone())
			},
			_ => panic!("Unexpected event"),
		};

		if disconnect_count & !disconnect_flags > 0 {
			nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id(), false);
			nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);
		}

		// Now fix monitor updating...
		*nodes[0].chan_monitor.update_ret.lock().unwrap() = Ok(());
		nodes[0].node.test_restore_channel_monitor();
		check_added_monitors!(nodes[0], 1);

		macro_rules! disconnect_reconnect_peers { () => { {
			nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id(), false);
			nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);

			nodes[0].node.peer_connected(&nodes[1].node.get_our_node_id());
			let reestablish_1 = get_chan_reestablish_msgs!(nodes[0], nodes[1]);
			assert_eq!(reestablish_1.len(), 1);
			nodes[1].node.peer_connected(&nodes[0].node.get_our_node_id());
			let reestablish_2 = get_chan_reestablish_msgs!(nodes[1], nodes[0]);
			assert_eq!(reestablish_2.len(), 1);

			nodes[0].node.handle_channel_reestablish(&nodes[1].node.get_our_node_id(), &reestablish_2[0]).unwrap();
			let as_resp = handle_chan_reestablish_msgs!(nodes[0], nodes[1]);
			nodes[1].node.handle_channel_reestablish(&nodes[0].node.get_our_node_id(), &reestablish_1[0]).unwrap();
			let bs_resp = handle_chan_reestablish_msgs!(nodes[1], nodes[0]);

			assert!(as_resp.0.is_none());
			assert!(bs_resp.0.is_none());

			(reestablish_1, reestablish_2, as_resp, bs_resp)
		} } }

		let (payment_event, initial_revoke_and_ack) = if disconnect_count & !disconnect_flags > 0 {
			assert!(nodes[0].node.get_and_clear_pending_events().is_empty());
			assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());

			nodes[0].node.peer_connected(&nodes[1].node.get_our_node_id());
			let reestablish_1 = get_chan_reestablish_msgs!(nodes[0], nodes[1]);
			assert_eq!(reestablish_1.len(), 1);
			nodes[1].node.peer_connected(&nodes[0].node.get_our_node_id());
			let reestablish_2 = get_chan_reestablish_msgs!(nodes[1], nodes[0]);
			assert_eq!(reestablish_2.len(), 1);

			nodes[0].node.handle_channel_reestablish(&nodes[1].node.get_our_node_id(), &reestablish_2[0]).unwrap();
			check_added_monitors!(nodes[0], 0);
			let mut as_resp = handle_chan_reestablish_msgs!(nodes[0], nodes[1]);
			nodes[1].node.handle_channel_reestablish(&nodes[0].node.get_our_node_id(), &reestablish_1[0]).unwrap();
			check_added_monitors!(nodes[1], 0);
			let mut bs_resp = handle_chan_reestablish_msgs!(nodes[1], nodes[0]);

			assert!(as_resp.0.is_none());
			assert!(bs_resp.0.is_none());

			assert!(bs_resp.1.is_none());
			if (disconnect_count & 16) == 0 {
				assert!(bs_resp.2.is_none());

				assert!(as_resp.1.is_some());
				assert!(as_resp.2.is_some());
				assert!(as_resp.3 == RAACommitmentOrder::CommitmentFirst);
			} else {
				assert!(bs_resp.2.as_ref().unwrap().update_add_htlcs.is_empty());
				assert!(bs_resp.2.as_ref().unwrap().update_fail_htlcs.is_empty());
				assert!(bs_resp.2.as_ref().unwrap().update_fail_malformed_htlcs.is_empty());
				assert!(bs_resp.2.as_ref().unwrap().update_fee.is_none());
				assert!(bs_resp.2.as_ref().unwrap().update_fulfill_htlcs == vec![bs_initial_fulfill]);
				assert!(bs_resp.2.as_ref().unwrap().commitment_signed == bs_initial_commitment_signed);

				assert!(as_resp.1.is_none());

				nodes[0].node.handle_update_fulfill_htlc(&nodes[1].node.get_our_node_id(), &bs_resp.2.as_ref().unwrap().update_fulfill_htlcs[0]).unwrap();
				let events_3 = nodes[0].node.get_and_clear_pending_events();
				assert_eq!(events_3.len(), 1);
				match events_3[0] {
					Event::PaymentSent { ref payment_preimage } => {
						assert_eq!(*payment_preimage, payment_preimage_1);
					},
					_ => panic!("Unexpected event"),
				}

				nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &bs_resp.2.as_ref().unwrap().commitment_signed).unwrap();
				let as_resp_raa = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());
				// No commitment_signed so get_event_msg's assert(len == 1) passes
				check_added_monitors!(nodes[0], 1);

				as_resp.1 = Some(as_resp_raa);
				bs_resp.2 = None;
			}

			if disconnect_count & !disconnect_flags > 1 {
				let (second_reestablish_1, second_reestablish_2, second_as_resp, second_bs_resp) = disconnect_reconnect_peers!();

				if (disconnect_count & 16) == 0 {
					assert!(reestablish_1 == second_reestablish_1);
					assert!(reestablish_2 == second_reestablish_2);
				}
				assert!(as_resp == second_as_resp);
				assert!(bs_resp == second_bs_resp);
			}

			(SendEvent::from_commitment_update(nodes[1].node.get_our_node_id(), as_resp.2.unwrap()), as_resp.1.unwrap())
		} else {
			let mut events_4 = nodes[0].node.get_and_clear_pending_msg_events();
			assert_eq!(events_4.len(), 2);
			(SendEvent::from_event(events_4.remove(0)), match events_4[0] {
				MessageSendEvent::SendRevokeAndACK { ref node_id, ref msg } => {
					assert_eq!(*node_id, nodes[1].node.get_our_node_id());
					msg.clone()
				},
				_ => panic!("Unexpected event"),
			})
		};

		assert_eq!(payment_event.node_id, nodes[1].node.get_our_node_id());

		nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &payment_event.msgs[0]).unwrap();
		nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &payment_event.commitment_msg).unwrap();
		let bs_revoke_and_ack = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, nodes[0].node.get_our_node_id());
		// nodes[1] is awaiting an RAA from nodes[0] still so get_event_msg's assert(len == 1) passes
		check_added_monitors!(nodes[1], 1);

		if disconnect_count & !disconnect_flags > 2 {
			let (_, _, as_resp, bs_resp) = disconnect_reconnect_peers!();

			assert!(as_resp.1.unwrap() == initial_revoke_and_ack);
			assert!(bs_resp.1.unwrap() == bs_revoke_and_ack);

			assert!(as_resp.2.is_none());
			assert!(bs_resp.2.is_none());
		}

		let as_commitment_update;
		let bs_second_commitment_update;

		macro_rules! handle_bs_raa { () => {
			nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_revoke_and_ack).unwrap();
			as_commitment_update = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
			assert!(as_commitment_update.update_add_htlcs.is_empty());
			assert!(as_commitment_update.update_fulfill_htlcs.is_empty());
			assert!(as_commitment_update.update_fail_htlcs.is_empty());
			assert!(as_commitment_update.update_fail_malformed_htlcs.is_empty());
			assert!(as_commitment_update.update_fee.is_none());
			check_added_monitors!(nodes[0], 1);
		} }

		macro_rules! handle_initial_raa { () => {
			nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &initial_revoke_and_ack).unwrap();
			bs_second_commitment_update = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
			assert!(bs_second_commitment_update.update_add_htlcs.is_empty());
			assert!(bs_second_commitment_update.update_fulfill_htlcs.is_empty());
			assert!(bs_second_commitment_update.update_fail_htlcs.is_empty());
			assert!(bs_second_commitment_update.update_fail_malformed_htlcs.is_empty());
			assert!(bs_second_commitment_update.update_fee.is_none());
			check_added_monitors!(nodes[1], 1);
		} }

		if (disconnect_count & 8) == 0 {
			handle_bs_raa!();

			if disconnect_count & !disconnect_flags > 3 {
				let (_, _, as_resp, bs_resp) = disconnect_reconnect_peers!();

				assert!(as_resp.1.unwrap() == initial_revoke_and_ack);
				assert!(bs_resp.1.is_none());

				assert!(as_resp.2.unwrap() == as_commitment_update);
				assert!(bs_resp.2.is_none());

				assert!(as_resp.3 == RAACommitmentOrder::RevokeAndACKFirst);
			}

			handle_initial_raa!();

			if disconnect_count & !disconnect_flags > 4 {
				let (_, _, as_resp, bs_resp) = disconnect_reconnect_peers!();

				assert!(as_resp.1.is_none());
				assert!(bs_resp.1.is_none());

				assert!(as_resp.2.unwrap() == as_commitment_update);
				assert!(bs_resp.2.unwrap() == bs_second_commitment_update);
			}
		} else {
			handle_initial_raa!();

			if disconnect_count & !disconnect_flags > 3 {
				let (_, _, as_resp, bs_resp) = disconnect_reconnect_peers!();

				assert!(as_resp.1.is_none());
				assert!(bs_resp.1.unwrap() == bs_revoke_and_ack);

				assert!(as_resp.2.is_none());
				assert!(bs_resp.2.unwrap() == bs_second_commitment_update);

				assert!(bs_resp.3 == RAACommitmentOrder::RevokeAndACKFirst);
			}

			handle_bs_raa!();

			if disconnect_count & !disconnect_flags > 4 {
				let (_, _, as_resp, bs_resp) = disconnect_reconnect_peers!();

				assert!(as_resp.1.is_none());
				assert!(bs_resp.1.is_none());

				assert!(as_resp.2.unwrap() == as_commitment_update);
				assert!(bs_resp.2.unwrap() == bs_second_commitment_update);
			}
		}

		nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &bs_second_commitment_update.commitment_signed).unwrap();
		let as_revoke_and_ack = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());
		// No commitment_signed so get_event_msg's assert(len == 1) passes
		check_added_monitors!(nodes[0], 1);

		nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &as_commitment_update.commitment_signed).unwrap();
		let bs_second_revoke_and_ack = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, nodes[0].node.get_our_node_id());
		// No commitment_signed so get_event_msg's assert(len == 1) passes
		check_added_monitors!(nodes[1], 1);

		nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &as_revoke_and_ack).unwrap();
		assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
		check_added_monitors!(nodes[1], 1);

		nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_second_revoke_and_ack).unwrap();
		assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
		check_added_monitors!(nodes[0], 1);

		expect_pending_htlcs_forwardable!(nodes[1]);

		let events_5 = nodes[1].node.get_and_clear_pending_events();
		assert_eq!(events_5.len(), 1);
		match events_5[0] {
			Event::PaymentReceived { ref payment_hash, amt } => {
				assert_eq!(payment_hash_2, *payment_hash);
				assert_eq!(amt, 1000000);
			},
			_ => panic!("Unexpected event"),
		}

		claim_payment(&nodes[0], &[&nodes[1]], payment_preimage_2);
	}

	#[test]
	fn test_monitor_temporary_update_fail_a() {
		do_test_monitor_temporary_update_fail(0);
		do_test_monitor_temporary_update_fail(1);
		do_test_monitor_temporary_update_fail(2);
		do_test_monitor_temporary_update_fail(3);
		do_test_monitor_temporary_update_fail(4);
		do_test_monitor_temporary_update_fail(5);
	}

	#[test]
	fn test_monitor_temporary_update_fail_b() {
		do_test_monitor_temporary_update_fail(2 | 8);
		do_test_monitor_temporary_update_fail(3 | 8);
		do_test_monitor_temporary_update_fail(4 | 8);
		do_test_monitor_temporary_update_fail(5 | 8);
	}

	#[test]
	fn test_monitor_temporary_update_fail_c() {
		do_test_monitor_temporary_update_fail(1 | 16);
		do_test_monitor_temporary_update_fail(2 | 16);
		do_test_monitor_temporary_update_fail(3 | 16);
		do_test_monitor_temporary_update_fail(2 | 8 | 16);
		do_test_monitor_temporary_update_fail(3 | 8 | 16);
	}

	#[test]
	fn test_invalid_channel_announcement() {
		//Test BOLT 7 channel_announcement msg requirement for final node, gather data to build customed channel_announcement msgs
		let secp_ctx = Secp256k1::new();
		let nodes = create_network(2);

		let chan_announcement = create_chan_between_nodes(&nodes[0], &nodes[1]);

		let a_channel_lock = nodes[0].node.channel_state.lock().unwrap();
		let b_channel_lock = nodes[1].node.channel_state.lock().unwrap();
		let as_chan = a_channel_lock.by_id.get(&chan_announcement.3).unwrap();
		let bs_chan = b_channel_lock.by_id.get(&chan_announcement.3).unwrap();

		let _ = nodes[0].router.handle_htlc_fail_channel_update(&msgs::HTLCFailChannelUpdate::ChannelClosed { short_channel_id : as_chan.get_short_channel_id().unwrap(), is_permanent: false } );

		let as_bitcoin_key = PublicKey::from_secret_key(&secp_ctx, &as_chan.get_local_keys().funding_key);
		let bs_bitcoin_key = PublicKey::from_secret_key(&secp_ctx, &bs_chan.get_local_keys().funding_key);

		let as_network_key = nodes[0].node.get_our_node_id();
		let bs_network_key = nodes[1].node.get_our_node_id();

		let were_node_one = as_bitcoin_key.serialize()[..] < bs_bitcoin_key.serialize()[..];

		let mut chan_announcement;

		macro_rules! dummy_unsigned_msg {
			() => {
				msgs::UnsignedChannelAnnouncement {
					features: msgs::GlobalFeatures::new(),
					chain_hash: genesis_block(Network::Testnet).header.bitcoin_hash(),
					short_channel_id: as_chan.get_short_channel_id().unwrap(),
					node_id_1: if were_node_one { as_network_key } else { bs_network_key },
					node_id_2: if were_node_one { bs_network_key } else { as_network_key },
					bitcoin_key_1: if were_node_one { as_bitcoin_key } else { bs_bitcoin_key },
					bitcoin_key_2: if were_node_one { bs_bitcoin_key } else { as_bitcoin_key },
					excess_data: Vec::new(),
				};
			}
		}

		macro_rules! sign_msg {
			($unsigned_msg: expr) => {
				let msghash = Message::from_slice(&Sha256dHash::from_data(&$unsigned_msg.encode()[..])[..]).unwrap();
				let as_bitcoin_sig = secp_ctx.sign(&msghash, &as_chan.get_local_keys().funding_key);
				let bs_bitcoin_sig = secp_ctx.sign(&msghash, &bs_chan.get_local_keys().funding_key);
				let as_node_sig = secp_ctx.sign(&msghash, &nodes[0].node.our_network_key);
				let bs_node_sig = secp_ctx.sign(&msghash, &nodes[1].node.our_network_key);
				chan_announcement = msgs::ChannelAnnouncement {
					node_signature_1 : if were_node_one { as_node_sig } else { bs_node_sig},
					node_signature_2 : if were_node_one { bs_node_sig } else { as_node_sig},
					bitcoin_signature_1: if were_node_one { as_bitcoin_sig } else { bs_bitcoin_sig },
					bitcoin_signature_2 : if were_node_one { bs_bitcoin_sig } else { as_bitcoin_sig },
					contents: $unsigned_msg
				}
			}
		}

		let unsigned_msg = dummy_unsigned_msg!();
		sign_msg!(unsigned_msg);
		assert_eq!(nodes[0].router.handle_channel_announcement(&chan_announcement).unwrap(), true);
		let _ = nodes[0].router.handle_htlc_fail_channel_update(&msgs::HTLCFailChannelUpdate::ChannelClosed { short_channel_id : as_chan.get_short_channel_id().unwrap(), is_permanent: false } );

		// Configured with Network::Testnet
		let mut unsigned_msg = dummy_unsigned_msg!();
		unsigned_msg.chain_hash = genesis_block(Network::Bitcoin).header.bitcoin_hash();
		sign_msg!(unsigned_msg);
		assert!(nodes[0].router.handle_channel_announcement(&chan_announcement).is_err());

		let mut unsigned_msg = dummy_unsigned_msg!();
		unsigned_msg.chain_hash = Sha256dHash::from_data(&[1,2,3,4,5,6,7,8,9]);
		sign_msg!(unsigned_msg);
		assert!(nodes[0].router.handle_channel_announcement(&chan_announcement).is_err());
	}

	struct VecWriter(Vec<u8>);
	impl Writer for VecWriter {
		fn write_all(&mut self, buf: &[u8]) -> Result<(), ::std::io::Error> {
			self.0.extend_from_slice(buf);
			Ok(())
		}
		fn size_hint(&mut self, size: usize) {
			self.0.reserve_exact(size);
		}
	}

	#[test]
	fn test_no_txn_manager_serialize_deserialize() {
		let mut nodes = create_network(2);

		let tx = create_chan_between_nodes_with_value_init(&nodes[0], &nodes[1], 100000, 10001);

		nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);

		let nodes_0_serialized = nodes[0].node.encode();
		let mut chan_0_monitor_serialized = VecWriter(Vec::new());
		nodes[0].chan_monitor.simple_monitor.monitors.lock().unwrap().iter().next().unwrap().1.write_for_disk(&mut chan_0_monitor_serialized).unwrap();

		nodes[0].chan_monitor = Arc::new(test_utils::TestChannelMonitor::new(nodes[0].chain_monitor.clone(), nodes[0].tx_broadcaster.clone(), Arc::new(test_utils::TestLogger::new())));
		let mut chan_0_monitor_read = &chan_0_monitor_serialized.0[..];
		let (_, chan_0_monitor) = <(Sha256dHash, ChannelMonitor)>::read(&mut chan_0_monitor_read, Arc::new(test_utils::TestLogger::new())).unwrap();
		assert!(chan_0_monitor_read.is_empty());

		let mut nodes_0_read = &nodes_0_serialized[..];
		let config = UserConfig::new();
		let keys_manager = Arc::new(keysinterface::KeysManager::new(&nodes[0].node_seed, Network::Testnet, Arc::new(test_utils::TestLogger::new())));
		let (_, nodes_0_deserialized) = {
			let mut channel_monitors = HashMap::new();
			channel_monitors.insert(chan_0_monitor.get_funding_txo().unwrap(), &chan_0_monitor);
			<(Sha256dHash, ChannelManager)>::read(&mut nodes_0_read, ChannelManagerReadArgs {
				default_config: config,
				keys_manager,
				fee_estimator: Arc::new(test_utils::TestFeeEstimator { sat_per_kw: 253 }),
				monitor: nodes[0].chan_monitor.clone(),
				chain_monitor: nodes[0].chain_monitor.clone(),
				tx_broadcaster: nodes[0].tx_broadcaster.clone(),
				logger: Arc::new(test_utils::TestLogger::new()),
				channel_monitors: &channel_monitors,
			}).unwrap()
		};
		assert!(nodes_0_read.is_empty());

		assert!(nodes[0].chan_monitor.add_update_monitor(chan_0_monitor.get_funding_txo().unwrap(), chan_0_monitor).is_ok());
		nodes[0].node = Arc::new(nodes_0_deserialized);
		let nodes_0_as_listener: Arc<ChainListener> = nodes[0].node.clone();
		nodes[0].chain_monitor.register_listener(Arc::downgrade(&nodes_0_as_listener));
		assert_eq!(nodes[0].node.list_channels().len(), 1);
		check_added_monitors!(nodes[0], 1);

		nodes[0].node.peer_connected(&nodes[1].node.get_our_node_id());
		let reestablish_1 = get_chan_reestablish_msgs!(nodes[0], nodes[1]);
		nodes[1].node.peer_connected(&nodes[0].node.get_our_node_id());
		let reestablish_2 = get_chan_reestablish_msgs!(nodes[1], nodes[0]);

		nodes[1].node.handle_channel_reestablish(&nodes[0].node.get_our_node_id(), &reestablish_1[0]).unwrap();
		assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
		nodes[0].node.handle_channel_reestablish(&nodes[1].node.get_our_node_id(), &reestablish_2[0]).unwrap();
		assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());

		let (funding_locked, _) = create_chan_between_nodes_with_value_confirm(&nodes[0], &nodes[1], &tx);
		let (announcement, as_update, bs_update) = create_chan_between_nodes_with_value_b(&nodes[0], &nodes[1], &funding_locked);
		for node in nodes.iter() {
			assert!(node.router.handle_channel_announcement(&announcement).unwrap());
			node.router.handle_channel_update(&as_update).unwrap();
			node.router.handle_channel_update(&bs_update).unwrap();
		}

		send_payment(&nodes[0], &[&nodes[1]], 1000000);
	}

	#[test]
	fn test_simple_manager_serialize_deserialize() {
		let mut nodes = create_network(2);
		create_announced_chan_between_nodes(&nodes, 0, 1);

		let (our_payment_preimage, _) = route_payment(&nodes[0], &[&nodes[1]], 1000000);
		let (_, our_payment_hash) = route_payment(&nodes[0], &[&nodes[1]], 1000000);

		nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);

		let nodes_0_serialized = nodes[0].node.encode();
		let mut chan_0_monitor_serialized = VecWriter(Vec::new());
		nodes[0].chan_monitor.simple_monitor.monitors.lock().unwrap().iter().next().unwrap().1.write_for_disk(&mut chan_0_monitor_serialized).unwrap();

		nodes[0].chan_monitor = Arc::new(test_utils::TestChannelMonitor::new(nodes[0].chain_monitor.clone(), nodes[0].tx_broadcaster.clone(), Arc::new(test_utils::TestLogger::new())));
		let mut chan_0_monitor_read = &chan_0_monitor_serialized.0[..];
		let (_, chan_0_monitor) = <(Sha256dHash, ChannelMonitor)>::read(&mut chan_0_monitor_read, Arc::new(test_utils::TestLogger::new())).unwrap();
		assert!(chan_0_monitor_read.is_empty());

		let mut nodes_0_read = &nodes_0_serialized[..];
		let keys_manager = Arc::new(keysinterface::KeysManager::new(&nodes[0].node_seed, Network::Testnet, Arc::new(test_utils::TestLogger::new())));
		let (_, nodes_0_deserialized) = {
			let mut channel_monitors = HashMap::new();
			channel_monitors.insert(chan_0_monitor.get_funding_txo().unwrap(), &chan_0_monitor);
			<(Sha256dHash, ChannelManager)>::read(&mut nodes_0_read, ChannelManagerReadArgs {
				default_config: UserConfig::new(),
				keys_manager,
				fee_estimator: Arc::new(test_utils::TestFeeEstimator { sat_per_kw: 253 }),
				monitor: nodes[0].chan_monitor.clone(),
				chain_monitor: nodes[0].chain_monitor.clone(),
				tx_broadcaster: nodes[0].tx_broadcaster.clone(),
				logger: Arc::new(test_utils::TestLogger::new()),
				channel_monitors: &channel_monitors,
			}).unwrap()
		};
		assert!(nodes_0_read.is_empty());

		assert!(nodes[0].chan_monitor.add_update_monitor(chan_0_monitor.get_funding_txo().unwrap(), chan_0_monitor).is_ok());
		nodes[0].node = Arc::new(nodes_0_deserialized);
		check_added_monitors!(nodes[0], 1);

		reconnect_nodes(&nodes[0], &nodes[1], (false, false), (0, 0), (0, 0), (0, 0), (0, 0), (false, false));

		fail_payment(&nodes[0], &[&nodes[1]], our_payment_hash);
		claim_payment(&nodes[0], &[&nodes[1]], our_payment_preimage);
	}

	#[test]
	fn test_manager_serialize_deserialize_inconsistent_monitor() {
		// Test deserializing a ChannelManager with a out-of-date ChannelMonitor
		let mut nodes = create_network(4);
		create_announced_chan_between_nodes(&nodes, 0, 1);
		create_announced_chan_between_nodes(&nodes, 2, 0);
		let (_, _, channel_id, funding_tx) = create_announced_chan_between_nodes(&nodes, 0, 3);

		let (our_payment_preimage, _) = route_payment(&nodes[2], &[&nodes[0], &nodes[1]], 1000000);

		// Serialize the ChannelManager here, but the monitor we keep up-to-date
		let nodes_0_serialized = nodes[0].node.encode();

		route_payment(&nodes[0], &[&nodes[3]], 1000000);
		nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);
		nodes[2].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);
		nodes[3].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);

		// Now the ChannelMonitor (which is now out-of-sync with ChannelManager for channel w/
		// nodes[3])
		let mut node_0_monitors_serialized = Vec::new();
		for monitor in nodes[0].chan_monitor.simple_monitor.monitors.lock().unwrap().iter() {
			let mut writer = VecWriter(Vec::new());
			monitor.1.write_for_disk(&mut writer).unwrap();
			node_0_monitors_serialized.push(writer.0);
		}

		nodes[0].chan_monitor = Arc::new(test_utils::TestChannelMonitor::new(nodes[0].chain_monitor.clone(), nodes[0].tx_broadcaster.clone(), Arc::new(test_utils::TestLogger::new())));
		let mut node_0_monitors = Vec::new();
		for serialized in node_0_monitors_serialized.iter() {
			let mut read = &serialized[..];
			let (_, monitor) = <(Sha256dHash, ChannelMonitor)>::read(&mut read, Arc::new(test_utils::TestLogger::new())).unwrap();
			assert!(read.is_empty());
			node_0_monitors.push(monitor);
		}

		let mut nodes_0_read = &nodes_0_serialized[..];
		let keys_manager = Arc::new(keysinterface::KeysManager::new(&nodes[0].node_seed, Network::Testnet, Arc::new(test_utils::TestLogger::new())));
		let (_, nodes_0_deserialized) = <(Sha256dHash, ChannelManager)>::read(&mut nodes_0_read, ChannelManagerReadArgs {
			default_config: UserConfig::new(),
			keys_manager,
			fee_estimator: Arc::new(test_utils::TestFeeEstimator { sat_per_kw: 253 }),
			monitor: nodes[0].chan_monitor.clone(),
			chain_monitor: nodes[0].chain_monitor.clone(),
			tx_broadcaster: nodes[0].tx_broadcaster.clone(),
			logger: Arc::new(test_utils::TestLogger::new()),
			channel_monitors: &node_0_monitors.iter().map(|monitor| { (monitor.get_funding_txo().unwrap(), monitor) }).collect(),
		}).unwrap();
		assert!(nodes_0_read.is_empty());

		{ // Channel close should result in a commitment tx and an HTLC tx
			let txn = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap();
			assert_eq!(txn.len(), 2);
			assert_eq!(txn[0].input[0].previous_output.txid, funding_tx.txid());
			assert_eq!(txn[1].input[0].previous_output.txid, txn[0].txid());
		}

		for monitor in node_0_monitors.drain(..) {
			assert!(nodes[0].chan_monitor.add_update_monitor(monitor.get_funding_txo().unwrap(), monitor).is_ok());
			check_added_monitors!(nodes[0], 1);
		}
		nodes[0].node = Arc::new(nodes_0_deserialized);

		// nodes[1] and nodes[2] have no lost state with nodes[0]...
		reconnect_nodes(&nodes[0], &nodes[1], (false, false), (0, 0), (0, 0), (0, 0), (0, 0), (false, false));
		reconnect_nodes(&nodes[0], &nodes[2], (false, false), (0, 0), (0, 0), (0, 0), (0, 0), (false, false));
		//... and we can even still claim the payment!
		claim_payment(&nodes[2], &[&nodes[0], &nodes[1]], our_payment_preimage);

		nodes[3].node.peer_connected(&nodes[0].node.get_our_node_id());
		let reestablish = get_event_msg!(nodes[3], MessageSendEvent::SendChannelReestablish, nodes[0].node.get_our_node_id());
		nodes[0].node.peer_connected(&nodes[3].node.get_our_node_id());
		if let Err(msgs::HandleError { action: Some(msgs::ErrorAction::SendErrorMessage { msg }), .. }) = nodes[0].node.handle_channel_reestablish(&nodes[3].node.get_our_node_id(), &reestablish) {
			assert_eq!(msg.channel_id, channel_id);
		} else { panic!("Unexpected result"); }
	}

	macro_rules! check_spendable_outputs {
		($node: expr, $der_idx: expr) => {
			{
				let events = $node.chan_monitor.simple_monitor.get_and_clear_pending_events();
				let mut txn = Vec::new();
				for event in events {
					match event {
						Event::SpendableOutputs { ref outputs } => {
							for outp in outputs {
								match *outp {
									SpendableOutputDescriptor::DynamicOutputP2WPKH { ref outpoint, ref key, ref output } => {
										let input = TxIn {
											previous_output: outpoint.clone(),
											script_sig: Script::new(),
											sequence: 0,
											witness: Vec::new(),
										};
										let outp = TxOut {
											script_pubkey: Builder::new().push_opcode(opcodes::All::OP_RETURN).into_script(),
											value: output.value,
										};
										let mut spend_tx = Transaction {
											version: 2,
											lock_time: 0,
											input: vec![input],
											output: vec![outp],
										};
										let secp_ctx = Secp256k1::new();
										let remotepubkey = PublicKey::from_secret_key(&secp_ctx, &key);
										let witness_script = Address::p2pkh(&remotepubkey, Network::Testnet).script_pubkey();
										let sighash = Message::from_slice(&bip143::SighashComponents::new(&spend_tx).sighash_all(&spend_tx.input[0], &witness_script, output.value)[..]).unwrap();
										let remotesig = secp_ctx.sign(&sighash, key);
										spend_tx.input[0].witness.push(remotesig.serialize_der(&secp_ctx).to_vec());
										spend_tx.input[0].witness[0].push(SigHashType::All as u8);
										spend_tx.input[0].witness.push(remotepubkey.serialize().to_vec());
										txn.push(spend_tx);
									},
									SpendableOutputDescriptor::DynamicOutputP2WSH { ref outpoint, ref key, ref witness_script, ref to_self_delay, ref output } => {
										let input = TxIn {
											previous_output: outpoint.clone(),
											script_sig: Script::new(),
											sequence: *to_self_delay as u32,
											witness: Vec::new(),
										};
										let outp = TxOut {
											script_pubkey: Builder::new().push_opcode(opcodes::All::OP_RETURN).into_script(),
											value: output.value,
										};
										let mut spend_tx = Transaction {
											version: 2,
											lock_time: 0,
											input: vec![input],
											output: vec![outp],
										};
										let secp_ctx = Secp256k1::new();
										let sighash = Message::from_slice(&bip143::SighashComponents::new(&spend_tx).sighash_all(&spend_tx.input[0], witness_script, output.value)[..]).unwrap();
										let local_delaysig = secp_ctx.sign(&sighash, key);
										spend_tx.input[0].witness.push(local_delaysig.serialize_der(&secp_ctx).to_vec());
										spend_tx.input[0].witness[0].push(SigHashType::All as u8);
										spend_tx.input[0].witness.push(vec!(0));
										spend_tx.input[0].witness.push(witness_script.clone().into_bytes());
										txn.push(spend_tx);
									},
									SpendableOutputDescriptor::StaticOutput { ref outpoint, ref output } => {
										let secp_ctx = Secp256k1::new();
										let input = TxIn {
											previous_output: outpoint.clone(),
											script_sig: Script::new(),
											sequence: 0,
											witness: Vec::new(),
										};
										let outp = TxOut {
											script_pubkey: Builder::new().push_opcode(opcodes::All::OP_RETURN).into_script(),
											value: output.value,
										};
										let mut spend_tx = Transaction {
											version: 2,
											lock_time: 0,
											input: vec![input],
											output: vec![outp.clone()],
										};
										let secret = {
											match ExtendedPrivKey::new_master(&secp_ctx, Network::Testnet, &$node.node_seed) {
												Ok(master_key) => {
													match master_key.ckd_priv(&secp_ctx, ChildNumber::from_hardened_idx($der_idx)) {
														Ok(key) => key,
														Err(_) => panic!("Your RNG is busted"),
													}
												}
												Err(_) => panic!("Your rng is busted"),
											}
										};
										let pubkey = ExtendedPubKey::from_private(&secp_ctx, &secret).public_key;
										let witness_script = Address::p2pkh(&pubkey, Network::Testnet).script_pubkey();
										let sighash = Message::from_slice(&bip143::SighashComponents::new(&spend_tx).sighash_all(&spend_tx.input[0], &witness_script, output.value)[..]).unwrap();
										let sig = secp_ctx.sign(&sighash, &secret.secret_key);
										spend_tx.input[0].witness.push(sig.serialize_der(&secp_ctx).to_vec());
										spend_tx.input[0].witness[0].push(SigHashType::All as u8);
										spend_tx.input[0].witness.push(pubkey.serialize().to_vec());
										txn.push(spend_tx);
									},
								}
							}
						},
						_ => panic!("Unexpected event"),
					};
				}
				txn
			}
		}
	}

	#[test]
	fn test_claim_sizeable_push_msat() {
		// Incidentally test SpendableOutput event generation due to detection of to_local output on commitment tx
		let nodes = create_network(2);

		let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100000, 99000000);
		nodes[1].node.force_close_channel(&chan.2);
		let events = nodes[1].node.get_and_clear_pending_msg_events();
		match events[0] {
			MessageSendEvent::BroadcastChannelUpdate { .. } => {},
			_ => panic!("Unexpected event"),
		}
		let node_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap();
		assert_eq!(node_txn.len(), 1);
		check_spends!(node_txn[0], chan.3.clone());
		assert_eq!(node_txn[0].output.len(), 2); // We can't force trimming of to_remote output as channel_reserve_satoshis block us to do so at channel opening

		let header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
		nodes[1].chain_monitor.block_connected_with_filtering(&Block { header, txdata: vec![node_txn[0].clone()] }, 0);
		let spend_txn = check_spendable_outputs!(nodes[1], 1);
		assert_eq!(spend_txn.len(), 1);
		check_spends!(spend_txn[0], node_txn[0].clone());
	}

	#[test]
	fn test_claim_on_remote_sizeable_push_msat() {
		// Same test as previous, just test on remote commitment tx, as per_commitment_point registration changes following you're funder/fundee and
		// to_remote output is encumbered by a P2WPKH

		let nodes = create_network(2);

		let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100000, 99000000);
		nodes[0].node.force_close_channel(&chan.2);
		let events = nodes[0].node.get_and_clear_pending_msg_events();
		match events[0] {
			MessageSendEvent::BroadcastChannelUpdate { .. } => {},
			_ => panic!("Unexpected event"),
		}
		let node_txn = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap();
		assert_eq!(node_txn.len(), 1);
		check_spends!(node_txn[0], chan.3.clone());
		assert_eq!(node_txn[0].output.len(), 2); // We can't force trimming of to_remote output as channel_reserve_satoshis block us to do so at channel opening

		let header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
		nodes[1].chain_monitor.block_connected_with_filtering(&Block { header, txdata: vec![node_txn[0].clone()] }, 0);
		let events = nodes[1].node.get_and_clear_pending_msg_events();
		match events[0] {
			MessageSendEvent::BroadcastChannelUpdate { .. } => {},
			_ => panic!("Unexpected event"),
		}
		let spend_txn = check_spendable_outputs!(nodes[1], 1);
		assert_eq!(spend_txn.len(), 2);
		assert_eq!(spend_txn[0], spend_txn[1]);
		check_spends!(spend_txn[0], node_txn[0].clone());
	}

	#[test]
	fn test_claim_on_remote_revoked_sizeable_push_msat() {
		// Same test as previous, just test on remote revoked commitment tx, as per_commitment_point registration changes following you're funder/fundee and
		// to_remote output is encumbered by a P2WPKH

		let nodes = create_network(2);

		let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100000, 59000000);
		let payment_preimage = route_payment(&nodes[0], &vec!(&nodes[1])[..], 3000000).0;
		let revoked_local_txn = nodes[0].node.channel_state.lock().unwrap().by_id.get(&chan.2).unwrap().last_local_commitment_txn.clone();
		assert_eq!(revoked_local_txn[0].input.len(), 1);
		assert_eq!(revoked_local_txn[0].input[0].previous_output.txid, chan.3.txid());

		claim_payment(&nodes[0], &vec!(&nodes[1])[..], payment_preimage);
		let  header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
		nodes[1].chain_monitor.block_connected_with_filtering(&Block { header, txdata: vec![revoked_local_txn[0].clone()] }, 1);
		let events = nodes[1].node.get_and_clear_pending_msg_events();
		match events[0] {
			MessageSendEvent::BroadcastChannelUpdate { .. } => {},
			_ => panic!("Unexpected event"),
		}
		let node_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap();
		let spend_txn = check_spendable_outputs!(nodes[1], 1);
		assert_eq!(spend_txn.len(), 4);
		assert_eq!(spend_txn[0], spend_txn[2]); // to_remote output on revoked remote commitment_tx
		check_spends!(spend_txn[0], revoked_local_txn[0].clone());
		assert_eq!(spend_txn[1], spend_txn[3]); // to_local output on local commitment tx
		check_spends!(spend_txn[1], node_txn[0].clone());
	}

	#[test]
	fn test_static_spendable_outputs_preimage_tx() {
		let nodes = create_network(2);

		// Create some initial channels
		let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1);

		let payment_preimage = route_payment(&nodes[0], &vec!(&nodes[1])[..], 3000000).0;

		let commitment_tx = nodes[0].node.channel_state.lock().unwrap().by_id.get(&chan_1.2).unwrap().last_local_commitment_txn.clone();
		assert_eq!(commitment_tx[0].input.len(), 1);
		assert_eq!(commitment_tx[0].input[0].previous_output.txid, chan_1.3.txid());

		// Settle A's commitment tx on B's chain
		let header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
		assert!(nodes[1].node.claim_funds(payment_preimage));
		check_added_monitors!(nodes[1], 1);
		nodes[1].chain_monitor.block_connected_with_filtering(&Block { header, txdata: vec![commitment_tx[0].clone()] }, 1);
		let events = nodes[1].node.get_and_clear_pending_msg_events();
		match events[0] {
			MessageSendEvent::UpdateHTLCs { .. } => {},
			_ => panic!("Unexpected event"),
		}
		match events[1] {
			MessageSendEvent::BroadcastChannelUpdate { .. } => {},
			_ => panic!("Unexepected event"),
		}

		// Check B's monitor was able to send back output descriptor event for preimage tx on A's commitment tx
		let node_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap(); // ChannelManager : 1 (local commitment tx), ChannelMonitor: 2 (1 preimage tx) * 2 (block-rescan)
		check_spends!(node_txn[0], commitment_tx[0].clone());
		assert_eq!(node_txn[0], node_txn[2]);
		assert_eq!(node_txn[0].input[0].witness.last().unwrap().len(), 133);
		check_spends!(node_txn[1], chan_1.3.clone());

		let spend_txn = check_spendable_outputs!(nodes[1], 1); // , 0, 0, 1, 1);
		assert_eq!(spend_txn.len(), 2);
		assert_eq!(spend_txn[0], spend_txn[1]);
		check_spends!(spend_txn[0], node_txn[0].clone());
	}

	#[test]
	fn test_static_spendable_outputs_justice_tx_revoked_commitment_tx() {
		let nodes = create_network(2);

		// Create some initial channels
		let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1);

		let payment_preimage = route_payment(&nodes[0], &vec!(&nodes[1])[..], 3000000).0;
		let revoked_local_txn = nodes[0].node.channel_state.lock().unwrap().by_id.iter().next().unwrap().1.last_local_commitment_txn.clone();
		assert_eq!(revoked_local_txn[0].input.len(), 1);
		assert_eq!(revoked_local_txn[0].input[0].previous_output.txid, chan_1.3.txid());

		claim_payment(&nodes[0], &vec!(&nodes[1])[..], payment_preimage);

		let  header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
		nodes[1].chain_monitor.block_connected_with_filtering(&Block { header, txdata: vec![revoked_local_txn[0].clone()] }, 1);
		let events = nodes[1].node.get_and_clear_pending_msg_events();
		match events[0] {
			MessageSendEvent::BroadcastChannelUpdate { .. } => {},
			_ => panic!("Unexpected event"),
		}
		let mut node_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap();
		assert_eq!(node_txn.len(), 3);
		assert_eq!(node_txn.pop().unwrap(), node_txn[0]);
		assert_eq!(node_txn[0].input.len(), 2);
		check_spends!(node_txn[0], revoked_local_txn[0].clone());

		let spend_txn = check_spendable_outputs!(nodes[1], 1);
		assert_eq!(spend_txn.len(), 2);
		assert_eq!(spend_txn[0], spend_txn[1]);
		check_spends!(spend_txn[0], node_txn[0].clone());
	}

	#[test]
	fn test_static_spendable_outputs_justice_tx_revoked_htlc_timeout_tx() {
		let nodes = create_network(2);

		// Create some initial channels
		let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1);

		let payment_preimage = route_payment(&nodes[0], &vec!(&nodes[1])[..], 3000000).0;
		let revoked_local_txn = nodes[0].node.channel_state.lock().unwrap().by_id.get(&chan_1.2).unwrap().last_local_commitment_txn.clone();
		assert_eq!(revoked_local_txn[0].input.len(), 1);
		assert_eq!(revoked_local_txn[0].input[0].previous_output.txid, chan_1.3.txid());

		claim_payment(&nodes[0], &vec!(&nodes[1])[..], payment_preimage);

		let header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
		// A will generate HTLC-Timeout from revoked commitment tx
		nodes[0].chain_monitor.block_connected_with_filtering(&Block { header, txdata: vec![revoked_local_txn[0].clone()] }, 1);
		let events = nodes[0].node.get_and_clear_pending_msg_events();
		match events[0] {
			MessageSendEvent::BroadcastChannelUpdate { .. } => {},
			_ => panic!("Unexpected event"),
		}
		let revoked_htlc_txn = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap();
		assert_eq!(revoked_htlc_txn.len(), 2);
		assert_eq!(revoked_htlc_txn[0].input.len(), 1);
		assert_eq!(revoked_htlc_txn[0].input[0].witness.last().unwrap().len(), 133);
		check_spends!(revoked_htlc_txn[0], revoked_local_txn[0].clone());

		// B will generate justice tx from A's revoked commitment/HTLC tx
		nodes[1].chain_monitor.block_connected_with_filtering(&Block { header, txdata: vec![revoked_local_txn[0].clone(), revoked_htlc_txn[0].clone()] }, 1);
		let events = nodes[1].node.get_and_clear_pending_msg_events();
		match events[0] {
			MessageSendEvent::BroadcastChannelUpdate { .. } => {},
			_ => panic!("Unexpected event"),
		}

		let node_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap();
		assert_eq!(node_txn.len(), 4);
		assert_eq!(node_txn[3].input.len(), 1);
		check_spends!(node_txn[3], revoked_htlc_txn[0].clone());

		// Check B's ChannelMonitor was able to generate the right spendable output descriptor
		let spend_txn = check_spendable_outputs!(nodes[1], 1);
		assert_eq!(spend_txn.len(), 3);
		assert_eq!(spend_txn[0], spend_txn[1]);
		check_spends!(spend_txn[0], node_txn[0].clone());
		check_spends!(spend_txn[2], node_txn[3].clone());
	}

	#[test]
	fn test_static_spendable_outputs_justice_tx_revoked_htlc_success_tx() {
		let nodes = create_network(2);

		// Create some initial channels
		let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1);

		let payment_preimage = route_payment(&nodes[0], &vec!(&nodes[1])[..], 3000000).0;
		let revoked_local_txn = nodes[1].node.channel_state.lock().unwrap().by_id.get(&chan_1.2).unwrap().last_local_commitment_txn.clone();
		assert_eq!(revoked_local_txn[0].input.len(), 1);
		assert_eq!(revoked_local_txn[0].input[0].previous_output.txid, chan_1.3.txid());

		claim_payment(&nodes[0], &vec!(&nodes[1])[..], payment_preimage);

		let header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
		// B will generate HTLC-Success from revoked commitment tx
		nodes[1].chain_monitor.block_connected_with_filtering(&Block { header, txdata: vec![revoked_local_txn[0].clone()] }, 1);
		let events = nodes[1].node.get_and_clear_pending_msg_events();
		match events[0] {
			MessageSendEvent::BroadcastChannelUpdate { .. } => {},
			_ => panic!("Unexpected event"),
		}
		let revoked_htlc_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap();

		assert_eq!(revoked_htlc_txn.len(), 2);
		assert_eq!(revoked_htlc_txn[0].input.len(), 1);
		assert_eq!(revoked_htlc_txn[0].input[0].witness.last().unwrap().len(), 138);
		check_spends!(revoked_htlc_txn[0], revoked_local_txn[0].clone());

		// A will generate justice tx from B's revoked commitment/HTLC tx
		nodes[0].chain_monitor.block_connected_with_filtering(&Block { header, txdata: vec![revoked_local_txn[0].clone(), revoked_htlc_txn[0].clone()] }, 1);
		let events = nodes[0].node.get_and_clear_pending_msg_events();
		match events[0] {
			MessageSendEvent::BroadcastChannelUpdate { .. } => {},
			_ => panic!("Unexpected event"),
		}

		let node_txn = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap();
		assert_eq!(node_txn.len(), 4);
		assert_eq!(node_txn[3].input.len(), 1);
		check_spends!(node_txn[3], revoked_htlc_txn[0].clone());

		// Check A's ChannelMonitor was able to generate the right spendable output descriptor
		let spend_txn = check_spendable_outputs!(nodes[0], 1);
		assert_eq!(spend_txn.len(), 5);
		assert_eq!(spend_txn[0], spend_txn[2]);
		assert_eq!(spend_txn[1], spend_txn[3]);
		check_spends!(spend_txn[0], revoked_local_txn[0].clone()); // spending to_remote output from revoked local tx
		check_spends!(spend_txn[1], node_txn[2].clone()); // spending justice tx output from revoked local tx htlc received output
		check_spends!(spend_txn[4], node_txn[3].clone()); // spending justice tx output on htlc success tx
	}

	#[test]
	fn test_dynamic_spendable_outputs_local_htlc_success_tx() {
		let nodes = create_network(2);

		// Create some initial channels
		let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1);

		let payment_preimage = route_payment(&nodes[0], &vec!(&nodes[1])[..], 9000000).0;
		let local_txn = nodes[1].node.channel_state.lock().unwrap().by_id.get(&chan_1.2).unwrap().last_local_commitment_txn.clone();
		assert_eq!(local_txn[0].input.len(), 1);
		check_spends!(local_txn[0], chan_1.3.clone());

		// Give B knowledge of preimage to be able to generate a local HTLC-Success Tx
		nodes[1].node.claim_funds(payment_preimage);
		check_added_monitors!(nodes[1], 1);
		let header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
		nodes[1].chain_monitor.block_connected_with_filtering(&Block { header, txdata: vec![local_txn[0].clone()] }, 1);
		let events = nodes[1].node.get_and_clear_pending_msg_events();
		match events[0] {
			MessageSendEvent::UpdateHTLCs { .. } => {},
			_ => panic!("Unexpected event"),
		}
		match events[1] {
			MessageSendEvent::BroadcastChannelUpdate { .. } => {},
			_ => panic!("Unexepected event"),
		}
		let node_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap();
		assert_eq!(node_txn[0].input.len(), 1);
		assert_eq!(node_txn[0].input[0].witness.last().unwrap().len(), 138);
		check_spends!(node_txn[0], local_txn[0].clone());

		// Verify that B is able to spend its own HTLC-Success tx thanks to spendable output event given back by its ChannelMonitor
		let spend_txn = check_spendable_outputs!(nodes[1], 1);
		assert_eq!(spend_txn.len(), 1);
		check_spends!(spend_txn[0], node_txn[0].clone());
	}

	#[test]
	fn test_dynamic_spendable_outputs_local_htlc_timeout_tx() {
		let nodes = create_network(2);

		// Create some initial channels
		let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1);

		route_payment(&nodes[0], &vec!(&nodes[1])[..], 9000000).0;
		let local_txn = nodes[0].node.channel_state.lock().unwrap().by_id.get(&chan_1.2).unwrap().last_local_commitment_txn.clone();
		assert_eq!(local_txn[0].input.len(), 1);
		check_spends!(local_txn[0], chan_1.3.clone());

		// Timeout HTLC on A's chain and so it can generate a HTLC-Timeout tx
		let header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
		nodes[0].chain_monitor.block_connected_with_filtering(&Block { header, txdata: vec![local_txn[0].clone()] }, 200);
		let events = nodes[0].node.get_and_clear_pending_msg_events();
		match events[0] {
			MessageSendEvent::BroadcastChannelUpdate { .. } => {},
			_ => panic!("Unexepected event"),
		}
		let node_txn = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap();
		assert_eq!(node_txn[0].input.len(), 1);
		assert_eq!(node_txn[0].input[0].witness.last().unwrap().len(), 133);
		check_spends!(node_txn[0], local_txn[0].clone());

		// Verify that A is able to spend its own HTLC-Timeout tx thanks to spendable output event given back by its ChannelMonitor
		let spend_txn = check_spendable_outputs!(nodes[0], 1);
		assert_eq!(spend_txn.len(), 4);
		assert_eq!(spend_txn[0], spend_txn[2]);
		assert_eq!(spend_txn[1], spend_txn[3]);
		check_spends!(spend_txn[0], local_txn[0].clone());
		check_spends!(spend_txn[1], node_txn[0].clone());
	}

	#[test]
	fn test_static_output_closing_tx() {
		let nodes = create_network(2);

		let chan = create_announced_chan_between_nodes(&nodes, 0, 1);

		send_payment(&nodes[0], &vec!(&nodes[1])[..], 8000000);
		let closing_tx = close_channel(&nodes[0], &nodes[1], &chan.2, chan.3, true).2;

		let header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
		nodes[0].chain_monitor.block_connected_with_filtering(&Block { header, txdata: vec![closing_tx.clone()] }, 1);
		let spend_txn = check_spendable_outputs!(nodes[0], 2);
		assert_eq!(spend_txn.len(), 1);
		check_spends!(spend_txn[0], closing_tx.clone());

		nodes[1].chain_monitor.block_connected_with_filtering(&Block { header, txdata: vec![closing_tx.clone()] }, 1);
		let spend_txn = check_spendable_outputs!(nodes[1], 2);
		assert_eq!(spend_txn.len(), 1);
		check_spends!(spend_txn[0], closing_tx);
	}
}
