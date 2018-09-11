use bitcoin::blockdata::block::BlockHeader;
use bitcoin::blockdata::transaction::Transaction;
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::network::constants::Network;
use bitcoin::network::serialize::BitcoinHash;
use bitcoin::util::hash::Sha256dHash;

use secp256k1::key::{SecretKey,PublicKey};
use secp256k1::{Secp256k1,Message};
use secp256k1::ecdh::SharedSecret;
use secp256k1;

use chain::chaininterface::{BroadcasterInterface,ChainListener,ChainWatchInterface,FeeEstimator};
use chain::transaction::OutPoint;
use ln::channel::{Channel, ChannelKeys};
use ln::channelmonitor::ManyChannelMonitor;
use ln::router::{Route,RouteHop};
use ln::msgs;
use ln::msgs::{HandleError,ChannelMessageHandler,MsgEncodable,MsgDecodable};
use util::{byte_utils, events, internal_traits, rng};
use util::sha2::Sha256;
use util::chacha20poly1305rfc::ChaCha20;
use util::logger::Logger;
use util::errors::APIError;

use crypto;
use crypto::mac::{Mac,MacResult};
use crypto::hmac::Hmac;
use crypto::digest::Digest;
use crypto::symmetriccipher::SynchronousStreamCipher;

use std::{ptr, mem};
use std::collections::HashMap;
use std::collections::hash_map;
use std::sync::{Mutex,MutexGuard,Arc};
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
	use secp256k1::ecdh::SharedSecret;

	/// Stores the info we will need to send when we want to forward an HTLC onwards
	#[derive(Clone)] // See Channel::revoke_and_ack for why, tl;dr: Rust bug
	pub struct PendingForwardHTLCInfo {
		pub(super) onion_packet: Option<msgs::OnionPacket>,
		pub(super) incoming_shared_secret: SharedSecret,
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

	#[cfg(feature = "fuzztarget")]
	impl PendingHTLCStatus {
		pub fn dummy() -> Self {
			let secp_ctx = ::secp256k1::Secp256k1::signing_only();
			PendingHTLCStatus::Forward(PendingForwardHTLCInfo {
				onion_packet: None,
				incoming_shared_secret: SharedSecret::new(&secp_ctx,
						&::secp256k1::key::PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&secp_ctx, &[1; 32]).unwrap()),
						&SecretKey::from_slice(&secp_ctx, &[1; 32]).unwrap()),
				payment_hash: [0; 32],
				short_channel_id: 0,
				amt_to_forward: 0,
				outgoing_cltv_value: 0,
			})
		}
	}

	/// Tracks the inbound corresponding to an outbound HTLC
	#[derive(Clone)]
	pub struct HTLCPreviousHopData {
		pub(super) short_channel_id: u64,
		pub(super) htlc_id: u64,
		pub(super) incoming_packet_shared_secret: SharedSecret,
	}

	/// Tracks the inbound corresponding to an outbound HTLC
	#[derive(Clone)]
	pub enum HTLCSource {
		PreviousHopData(HTLCPreviousHopData),
		OutboundRoute {
			route: Route,
			session_priv: SecretKey,
		},
	}
	#[cfg(any(test, feature = "fuzztarget"))]
	impl HTLCSource {
		pub fn dummy() -> Self {
			HTLCSource::OutboundRoute {
				route: Route { hops: Vec::new() },
				session_priv: SecretKey::from_slice(&::secp256k1::Secp256k1::without_caps(), &[1; 32]).unwrap(),
			}
		}
	}

	#[derive(Clone)] // See Channel::revoke_and_ack for why, tl;dr: Rust bug
	pub enum HTLCFailReason {
		ErrorPacket {
			err: msgs::OnionErrorPacket,
		},
		Reason {
			failure_code: u16,
			data: Vec<u8>,
		}
	}

	#[cfg(feature = "fuzztarget")]
	impl HTLCFailReason {
		pub fn dummy() -> Self {
			HTLCFailReason::Reason {
				failure_code: 0, data: Vec::new(),
			}
		}
	}
}
#[cfg(feature = "fuzztarget")]
pub use self::channel_held_info::*;
#[cfg(not(feature = "fuzztarget"))]
pub(crate) use self::channel_held_info::*;

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
}
struct MutChannelHolder<'a> {
	by_id: &'a mut HashMap<[u8; 32], Channel>,
	short_to_id: &'a mut HashMap<u64, [u8; 32]>,
	next_forward: &'a mut Instant,
	forward_htlcs: &'a mut HashMap<u64, Vec<HTLCForwardInfo>>,
	claimable_htlcs: &'a mut HashMap<[u8; 32], Vec<HTLCPreviousHopData>>,
}
impl ChannelHolder {
	fn borrow_parts(&mut self) -> MutChannelHolder {
		MutChannelHolder {
			by_id: &mut self.by_id,
			short_to_id: &mut self.short_to_id,
			next_forward: &mut self.next_forward,
			forward_htlcs: &mut self.forward_htlcs,
			claimable_htlcs: &mut self.claimable_htlcs,
		}
	}
}

#[cfg(not(any(target_pointer_width = "32", target_pointer_width = "64")))]
const ERR: () = "You need at least 32 bit pointers (well, usize, but we'll assume they're the same) for ChannelManager::latest_block_height";

/// Manager which keeps track of a number of channels and sends messages to the appropriate
/// channel, also tracking HTLC preimages and forwarding onion packets appropriately.
/// Implements ChannelMessageHandler, handling the multi-channel parts and passing things through
/// to individual Channels.
pub struct ChannelManager {
	genesis_hash: Sha256dHash,
	fee_estimator: Arc<FeeEstimator>,
	monitor: Arc<ManyChannelMonitor>,
	chain_monitor: Arc<ChainWatchInterface>,
	tx_broadcaster: Arc<BroadcasterInterface>,

	announce_channels_publicly: bool,
	fee_proportional_millionths: u32,
	latest_block_height: AtomicUsize,
	secp_ctx: Secp256k1<secp256k1::All>,

	channel_state: Mutex<ChannelHolder>,
	our_network_key: SecretKey,

	pending_events: Mutex<Vec<events::Event>>,

	logger: Arc<Logger>,
}

const CLTV_EXPIRY_DELTA: u16 = 6 * 24 * 2; //TODO?

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

pub struct ChannelDetails {
	/// The channel's ID (prior to funding transaction generation, this is a random 32 bytes,
	/// thereafter this is the txid of the funding transaction xor the funding transaction output).
	/// Note that this means this value is *not* persistent - it can change once during the
	/// lifetime of the channel.
	pub channel_id: [u8; 32],
	/// The position of the funding transaction in the chain. None if the funding transaction has
	/// not yet been confirmed and the channel fully opened.
	pub short_channel_id: Option<u64>,
	pub remote_network_id: PublicKey,
	pub channel_value_satoshis: u64,
	/// The user_id passed in to create_channel, or 0 if the channel was inbound.
	pub user_id: u64,
}

impl ChannelManager {
	/// Constructs a new ChannelManager to hold several channels and route between them. This is
	/// the main "logic hub" for all channel-related actions, and implements ChannelMessageHandler.
	/// fee_proportional_millionths is an optional fee to charge any payments routed through us.
	/// Non-proportional fees are fixed according to our risk using the provided fee estimator.
	/// panics if channel_value_satoshis is >= `MAX_FUNDING_SATOSHIS`!
	pub fn new(our_network_key: SecretKey, fee_proportional_millionths: u32, announce_channels_publicly: bool, network: Network, feeest: Arc<FeeEstimator>, monitor: Arc<ManyChannelMonitor>, chain_monitor: Arc<ChainWatchInterface>, tx_broadcaster: Arc<BroadcasterInterface>, logger: Arc<Logger>) -> Result<Arc<ChannelManager>, secp256k1::Error> {
		let secp_ctx = Secp256k1::new();

		let res = Arc::new(ChannelManager {
			genesis_hash: genesis_block(network).header.bitcoin_hash(),
			fee_estimator: feeest.clone(),
			monitor: monitor.clone(),
			chain_monitor,
			tx_broadcaster,

			announce_channels_publicly,
			fee_proportional_millionths,
			latest_block_height: AtomicUsize::new(0), //TODO: Get an init value (generally need to replay recent chain on chain_monitor registration)
			secp_ctx,

			channel_state: Mutex::new(ChannelHolder{
				by_id: HashMap::new(),
				short_to_id: HashMap::new(),
				next_forward: Instant::now(),
				forward_htlcs: HashMap::new(),
				claimable_htlcs: HashMap::new(),
			}),
			our_network_key,

			pending_events: Mutex::new(Vec::new()),

			logger,
		});
		let weak_res = Arc::downgrade(&res);
		res.chain_monitor.register_listener(weak_res);
		Ok(res)
	}

	/// Creates a new outbound channel to the given remote node and with the given value.
	/// user_id will be provided back as user_channel_id in FundingGenerationReady and
	/// FundingBroadcastSafe events to allow tracking of which events correspond with which
	/// create_channel call. Note that user_channel_id defaults to 0 for inbound channels, so you
	/// may wish to avoid using 0 for user_id here.
	/// If successful, will generate a SendOpenChannel event, so you should probably poll
	/// PeerManager::process_events afterwards.
	/// Raises APIError::APIMisuseError when channel_value_satoshis > 2**24 or push_msat being greater than channel_value_satoshis * 1k
	pub fn create_channel(&self, their_network_key: PublicKey, channel_value_satoshis: u64, push_msat: u64, user_id: u64) -> Result<(), APIError> {
		let chan_keys = if cfg!(feature = "fuzztarget") {
			ChannelKeys {
				funding_key:               SecretKey::from_slice(&self.secp_ctx, &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).unwrap(),
				revocation_base_key:       SecretKey::from_slice(&self.secp_ctx, &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).unwrap(),
				payment_base_key:          SecretKey::from_slice(&self.secp_ctx, &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).unwrap(),
				delayed_payment_base_key:  SecretKey::from_slice(&self.secp_ctx, &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).unwrap(),
				htlc_base_key:             SecretKey::from_slice(&self.secp_ctx, &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).unwrap(),
				channel_close_key:         SecretKey::from_slice(&self.secp_ctx, &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).unwrap(),
				channel_monitor_claim_key: SecretKey::from_slice(&self.secp_ctx, &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).unwrap(),
				commitment_seed: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
			}
		} else {
			let mut key_seed = [0u8; 32];
			rng::fill_bytes(&mut key_seed);
			match ChannelKeys::new_from_seed(&key_seed) {
				Ok(key) => key,
				Err(_) => panic!("RNG is busted!")
			}
		};

		let channel = Channel::new_outbound(&*self.fee_estimator, chan_keys, their_network_key, channel_value_satoshis, push_msat, self.announce_channels_publicly, user_id, Arc::clone(&self.logger))?;
		let res = channel.get_open_channel(self.genesis_hash.clone(), &*self.fee_estimator)?;
		let mut channel_state = self.channel_state.lock().unwrap();
		match channel_state.by_id.insert(channel.channel_id(), channel) {
			Some(_) => panic!("RNG is bad???"),
			None => {}
		}

		let mut events = self.pending_events.lock().unwrap();
		events.push(events::Event::SendOpenChannel {
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
			if channel.is_usable() {
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
	/// May generate a SendShutdown event on success, which should be relayed.
	pub fn close_channel(&self, channel_id: &[u8; 32]) -> Result<(), HandleError> {
		let (mut res, node_id, chan_option) = {
			let mut channel_state_lock = self.channel_state.lock().unwrap();
			let channel_state = channel_state_lock.borrow_parts();
			match channel_state.by_id.entry(channel_id.clone()) {
				hash_map::Entry::Occupied(mut chan_entry) => {
					let res = chan_entry.get_mut().get_shutdown()?;
					if chan_entry.get().is_shutdown() {
						if let Some(short_id) = chan_entry.get().get_short_channel_id() {
							channel_state.short_to_id.remove(&short_id);
						}
						(res, chan_entry.get().get_their_node_id(), Some(chan_entry.remove_entry().1))
					} else { (res, chan_entry.get().get_their_node_id(), None) }
				},
				hash_map::Entry::Vacant(_) => return Err(HandleError{err: "No such channel", action: None})
			}
		};
		for htlc_source in res.1.drain(..) {
			// unknown_next_peer...I dunno who that is anymore....
			self.fail_htlc_backwards_internal(self.channel_state.lock().unwrap(), htlc_source.0, &htlc_source.1, HTLCFailReason::Reason { failure_code: 0x4000 | 10, data: Vec::new() });
		}
		let chan_update = if let Some(chan) = chan_option {
			if let Ok(update) = self.get_channel_update(&chan) {
				Some(update)
			} else { None }
		} else { None };

		let mut events = self.pending_events.lock().unwrap();
		if let Some(update) = chan_update {
			events.push(events::Event::BroadcastChannelUpdate {
				msg: update
			});
		}
		events.push(events::Event::SendShutdown {
			node_id,
			msg: res.0
		});

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
		let mut events = self.pending_events.lock().unwrap();
		if let Ok(update) = self.get_channel_update(&chan) {
			events.push(events::Event::BroadcastChannelUpdate {
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

	#[inline]
	fn gen_rho_mu_from_shared_secret(shared_secret: &SharedSecret) -> ([u8; 32], [u8; 32]) {
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
	fn gen_um_from_shared_secret(shared_secret: &SharedSecret) -> [u8; 32] {
		let mut hmac = Hmac::new(Sha256::new(), &[0x75, 0x6d]); // um
		hmac.input(&shared_secret[..]);
		let mut res = [0; 32];
		hmac.raw_result(&mut res);
		res
	}

	#[inline]
	fn gen_ammag_from_shared_secret(shared_secret: &SharedSecret) -> [u8; 32] {
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
			let (rho, mu) = ChannelManager::gen_rho_mu_from_shared_secret(&shared_secret);

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
	fn build_onion_payloads(route: &Route, starting_htlc_offset: u32) -> Result<(Vec<msgs::OnionHopData>, u64, u32), HandleError> {
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
				return Err(HandleError{err: "Channel fees overflowed?!", action: None});
			}
			cur_cltv += hop.cltv_expiry_delta as u32;
			if cur_cltv >= 500000000 {
				return Err(HandleError{err: "Channel CLTV overflowed?!", action: None});
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
	fn construct_onion_packet(mut payloads: Vec<msgs::OnionHopData>, onion_keys: Vec<OnionKeys>, associated_data: &[u8; 32]) -> Result<msgs::OnionPacket, HandleError> {
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

		Ok(msgs::OnionPacket{
			version: 0,
			public_key: Ok(onion_keys.first().unwrap().ephemeral_pubkey),
			hop_data: packet_data,
			hmac: hmac_res,
		})
	}

	/// Encrypts a failure packet. raw_packet can either be a
	/// msgs::DecodedOnionErrorPacket.encode() result or a msgs::OnionErrorPacket.data element.
	fn encrypt_failure_packet(shared_secret: &SharedSecret, raw_packet: &[u8]) -> msgs::OnionErrorPacket {
		let ammag = ChannelManager::gen_ammag_from_shared_secret(&shared_secret);

		let mut packet_crypted = Vec::with_capacity(raw_packet.len());
		packet_crypted.resize(raw_packet.len(), 0);
		let mut chacha = ChaCha20::new(&ammag, &[0u8; 8]);
		chacha.process(&raw_packet, &mut packet_crypted[..]);
		msgs::OnionErrorPacket {
			data: packet_crypted,
		}
	}

	fn build_failure_packet(shared_secret: &SharedSecret, failure_type: u16, failure_data: &[u8]) -> msgs::DecodedOnionErrorPacket {
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
	fn build_first_hop_failure_packet(shared_secret: &SharedSecret, failure_type: u16, failure_data: &[u8]) -> msgs::OnionErrorPacket {
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

		let shared_secret = SharedSecret::new(&self.secp_ctx, &msg.onion_routing_packet.public_key.unwrap(), &self.our_network_key);
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
			match msgs::OnionHopData::decode(&decoded[..]) {
				Err(err) => {
					let error_code = match err {
						msgs::DecodeError::UnknownRealmByte => 0x4000 | 1,
						_ => 0x2000 | 2, // Should never happen
					};
					return_err!("Unable to decode our hop data", error_code, &[0;0]);
				},
				Ok(msg) => msg
			}
		};

		//TODO: Check that msg.cltv_expiry is within acceptable bounds!

		let pending_forward_info = if next_hop_data.hmac == [0; 32] {
				// OUR PAYMENT!
				if next_hop_data.data.amt_to_forward != msg.amount_msat {
					return_err!("Upstream node sent less than we were supposed to receive in payment", 19, &byte_utils::be64_to_array(msg.amount_msat));
				}
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
					incoming_shared_secret: shared_secret.clone(),
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
					sha.input(&shared_secret[..]);
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
					incoming_shared_secret: shared_secret.clone(),
					amt_to_forward: next_hop_data.data.amt_to_forward,
					outgoing_cltv_value: next_hop_data.data.outgoing_cltv_value,
				})
			};

		channel_state = Some(self.channel_state.lock().unwrap());
		if let &PendingHTLCStatus::Forward(PendingForwardHTLCInfo { ref onion_packet, ref short_channel_id, ref amt_to_forward, ref outgoing_cltv_value, .. }) = &pending_forward_info {
			if onion_packet.is_some() { // If short_channel_id is 0 here, we'll reject them in the body here
				let id_option = channel_state.as_ref().unwrap().short_to_id.get(&short_channel_id).cloned();
				let forwarding_id = match id_option {
					None => {
						return_err!("Don't have available channel for forwarding as requested.", 0x4000 | 10, &[0;0]);
					},
					Some(id) => id.clone(),
				};
				if let Some((err, code, chan_update)) = {
					let chan = channel_state.as_mut().unwrap().by_id.get_mut(&forwarding_id).unwrap();
					if !chan.is_live() {
						Some(("Forwarding channel is not in a ready state.", 0x1000 | 7, self.get_channel_update(chan).unwrap()))
					} else {
						let fee = amt_to_forward.checked_mul(self.fee_proportional_millionths as u64).and_then(|prop_fee| { (prop_fee / 1000000).checked_add(chan.get_our_fee_base_msat(&*self.fee_estimator) as u64) });
						if fee.is_none() || msg.amount_msat < fee.unwrap() || (msg.amount_msat - fee.unwrap()) < *amt_to_forward {
							Some(("Prior hop has deviated from specified fees parameters or origin node has obsolete ones", 0x1000 | 12, self.get_channel_update(chan).unwrap()))
						} else {
							if (msg.cltv_expiry as u64) < (*outgoing_cltv_value) as u64 + CLTV_EXPIRY_DELTA as u64 {
								Some(("Forwarding node has tampered with the intended HTLC values or origin node has an obsolete cltv_expiry_delta", 0x1000 | 13, self.get_channel_update(chan).unwrap()))
							} else {
								None
							}
						}
					}
				} {
					return_err!(err, code, &chan_update.encode_with_len()[..]);
				}
			}
		}

		(pending_forward_info, channel_state.unwrap())
	}

	/// only fails if the channel does not yet have an assigned short_id
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
			fee_proportional_millionths: self.fee_proportional_millionths,
			excess_data: Vec::new(),
		};

		let msg_hash = Sha256dHash::from_data(&unsigned.encode()[..]);
		let sig = self.secp_ctx.sign(&Message::from_slice(&msg_hash[..]).unwrap(), &self.our_network_key); //TODO Can we unwrap here?

		Ok(msgs::ChannelUpdate {
			signature: sig,
			contents: unsigned
		})
	}

	/// Sends a payment along a given route.
	/// Value parameters are provided via the last hop in route, see documentation for RouteHop
	/// fields for more info.
	/// Note that if the payment_hash already exists elsewhere (eg you're sending a duplicative
	/// payment), we don't do anything to stop you! We always try to ensure that if the provided
	/// next hop knows the preimage to payment_hash they can claim an additional amount as
	/// specified in the last hop in the route! Thus, you should probably do your own
	/// payment_preimage tracking (which you should already be doing as they represent "proof of
	/// payment") and prevent double-sends yourself.
	/// See-also docs on Channel::send_htlc_and_commit.
	/// May generate a SendHTLCs event on success, which should be relayed.
	pub fn send_payment(&self, route: Route, payment_hash: [u8; 32]) -> Result<(), HandleError> {
		if route.hops.len() < 1 || route.hops.len() > 20 {
			return Err(HandleError{err: "Route didn't go anywhere/had bogus size", action: None});
		}
		let our_node_id = self.get_our_node_id();
		for (idx, hop) in route.hops.iter().enumerate() {
			if idx != route.hops.len() - 1 && hop.pubkey == our_node_id {
				return Err(HandleError{err: "Route went through us but wasn't a simple rebalance loop to us", action: None});
			}
		}

		let session_priv = SecretKey::from_slice(&self.secp_ctx, &{
			let mut session_key = [0; 32];
			rng::fill_bytes(&mut session_key);
			session_key
		}).expect("RNG is bad!");

		let cur_height = self.latest_block_height.load(Ordering::Acquire) as u32 + 1;

		//TODO: This should return something other than HandleError, that's really intended for
		//p2p-returns only.
		let onion_keys = secp_call!(ChannelManager::construct_onion_keys(&self.secp_ctx, &route, &session_priv),
				HandleError{err: "Pubkey along hop was maliciously selected", action: Some(msgs::ErrorAction::IgnoreError)});
		let (onion_payloads, htlc_msat, htlc_cltv) = ChannelManager::build_onion_payloads(&route, cur_height)?;
		let onion_packet = ChannelManager::construct_onion_packet(onion_payloads, onion_keys, &payment_hash)?;

		let (first_hop_node_id, (update_add, commitment_signed, chan_monitor)) = {
			let mut channel_state_lock = self.channel_state.lock().unwrap();
			let channel_state = channel_state_lock.borrow_parts();

			let id = match channel_state.short_to_id.get(&route.hops.first().unwrap().short_channel_id) {
				None => return Err(HandleError{err: "No channel available with first hop!", action: None}),
				Some(id) => id.clone()
			};

			let res = {
				let chan = channel_state.by_id.get_mut(&id).unwrap();
				if chan.get_their_node_id() != route.hops.first().unwrap().pubkey {
					return Err(HandleError{err: "Node ID mismatch on first hop!", action: None});
				}
				if !chan.is_live() {
					return Err(HandleError{err: "Peer for first hop currently disconnected!", action: None});
				}
				chan.send_htlc_and_commit(htlc_msat, payment_hash.clone(), htlc_cltv, HTLCSource::OutboundRoute {
					route: route.clone(),
					session_priv: session_priv.clone(),
				}, onion_packet)?
			};

			let first_hop_node_id = route.hops.first().unwrap().pubkey;

			match res {
				Some(msgs) => (first_hop_node_id, msgs),
				None => return Ok(()),
			}
		};

		if let Err(_e) = self.monitor.add_update_monitor(chan_monitor.get_funding_txo().unwrap(), chan_monitor) {
			unimplemented!();
		}

		let mut events = self.pending_events.lock().unwrap();
		events.push(events::Event::UpdateHTLCs {
			node_id: first_hop_node_id,
			updates: msgs::CommitmentUpdate {
				update_add_htlcs: vec![update_add],
				update_fulfill_htlcs: Vec::new(),
				update_fail_htlcs: Vec::new(),
				update_fail_malformed_htlcs: Vec::new(),
				commitment_signed,
			},
		});
		Ok(())
	}

	/// Call this upon creation of a funding transaction for the given channel.
	/// Panics if a funding transaction has already been provided for this channel.
	/// May panic if the funding_txo is duplicative with some other channel (note that this should
	/// be trivially prevented by using unique funding transaction keys per-channel).
	pub fn funding_transaction_generated(&self, temporary_channel_id: &[u8; 32], funding_txo: OutPoint) {

		macro_rules! add_pending_event {
			($event: expr) => {
				{
					let mut pending_events = self.pending_events.lock().unwrap();
					pending_events.push($event);
				}
			}
		}

		let (chan, msg, chan_monitor) = {
			let mut channel_state = self.channel_state.lock().unwrap();
			match channel_state.by_id.remove(temporary_channel_id) {
				Some(mut chan) => {
					match chan.get_outbound_funding_created(funding_txo) {
						Ok(funding_msg) => {
							(chan, funding_msg.0, funding_msg.1)
						},
						Err(e) => {
							log_error!(self, "Got bad signatures: {}!", e.err);
							mem::drop(channel_state);
							add_pending_event!(events::Event::HandleError {
								node_id: chan.get_their_node_id(),
								action: e.action,
							});
							return;
						},
					}
				},
				None => return
			}
		}; // Release channel lock for install_watch_outpoint call,
		if let Err(_e) = self.monitor.add_update_monitor(chan_monitor.get_funding_txo().unwrap(), chan_monitor) {
			unimplemented!();
		}
		add_pending_event!(events::Event::SendFundingCreated {
			node_id: chan.get_their_node_id(),
			msg: msg,
		});

		let mut channel_state = self.channel_state.lock().unwrap();
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
	/// Should only really ever be called in response to an PendingHTLCsForwardable event.
	/// Will likely generate further events.
	pub fn process_pending_htlc_forwards(&self) {
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
								if let &Some(msgs::ErrorAction::DisconnectPeer{msg: Some(ref _err_msg)}) = &e.action {
								} else if let &Some(msgs::ErrorAction::SendErrorMessage{msg: ref _err_msg}) = &e.action {
								} else {
									panic!("Stated return value requirements in send_commitment() were not met");
								}
								//TODO: Handle...this is bad!
								continue;
							},
						};
						new_events.push((Some(monitor), events::Event::UpdateHTLCs {
							node_id: forward_chan.get_their_node_id(),
							updates: msgs::CommitmentUpdate {
								update_add_htlcs: add_htlc_msgs,
								update_fulfill_htlcs: Vec::new(),
								update_fail_htlcs: Vec::new(),
								update_fail_malformed_htlcs: Vec::new(),
								commitment_signed: commitment_msg,
							},
						}));
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
							hash_map::Entry::Vacant(mut entry) => { entry.insert(vec![prev_hop_data]); },
						};
						new_events.push((None, events::Event::PaymentReceived {
							payment_hash: forward_info.payment_hash,
							amt: forward_info.amt_to_forward,
						}));
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

		new_events.retain(|event| {
			if let &Some(ref monitor) = &event.0 {
				if let Err(_e) = self.monitor.add_update_monitor(monitor.get_funding_txo().unwrap(), monitor.clone()) {
					unimplemented!();// but def dont push the event...
				}
			}
			true
		});

		let mut events = self.pending_events.lock().unwrap();
		events.reserve(new_events.len());
		for event in new_events.drain(..) {
			events.push(event.1);
		}
	}

	/// Indicates that the preimage for payment_hash is unknown after a PaymentReceived event.
	pub fn fail_htlc_backwards(&self, payment_hash: &[u8; 32]) -> bool {
		let mut channel_state = Some(self.channel_state.lock().unwrap());
		let removed_source = channel_state.as_mut().unwrap().claimable_htlcs.remove(payment_hash);
		if let Some(mut sources) = removed_source {
			for htlc_with_hash in sources.drain(..) {
				if channel_state.is_none() { channel_state = Some(self.channel_state.lock().unwrap()); }
				self.fail_htlc_backwards_internal(channel_state.take().unwrap(), HTLCSource::PreviousHopData(htlc_with_hash), payment_hash, HTLCFailReason::Reason { failure_code: 0x4000 | 15, data: Vec::new() });
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
	fn fail_htlc_backwards_internal(&self, mut channel_state: MutexGuard<ChannelHolder>, source: HTLCSource, payment_hash: &[u8; 32], onion_error: HTLCFailReason) {
		match source {
			HTLCSource::OutboundRoute { .. } => {
				mem::drop(channel_state);

				let mut pending_events = self.pending_events.lock().unwrap();
				pending_events.push(events::Event::PaymentFailed {
					payment_hash: payment_hash.clone()
				});
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

				let (node_id, fail_msgs) = {
					let chan_id = match channel_state.short_to_id.get(&short_channel_id) {
						Some(chan_id) => chan_id.clone(),
						None => return
					};

					let chan = channel_state.by_id.get_mut(&chan_id).unwrap();
					match chan.get_update_fail_htlc_and_commit(htlc_id, err_packet) {
						Ok(msg) => (chan.get_their_node_id(), msg),
						Err(_e) => {
							//TODO: Do something with e?
							return;
						},
					}
				};

				match fail_msgs {
					Some((msg, commitment_msg, chan_monitor)) => {
						mem::drop(channel_state);

						if let Err(_e) = self.monitor.add_update_monitor(chan_monitor.get_funding_txo().unwrap(), chan_monitor) {
							unimplemented!();// but def dont push the event...
						}

						let mut pending_events = self.pending_events.lock().unwrap();
						pending_events.push(events::Event::UpdateHTLCs {
							node_id,
							updates: msgs::CommitmentUpdate {
								update_add_htlcs: Vec::new(),
								update_fulfill_htlcs: Vec::new(),
								update_fail_htlcs: vec![msg],
								update_fail_malformed_htlcs: Vec::new(),
								commitment_signed: commitment_msg,
							},
						});
					},
					None => {},
				}
			},
		}
	}

	/// Provides a payment preimage in response to a PaymentReceived event, returning true and
	/// generating message events for the net layer to claim the payment, if possible. Thus, you
	/// should probably kick the net layer to go send messages if this returns true!
	/// May panic if called except in response to a PaymentReceived event.
	pub fn claim_funds(&self, payment_preimage: [u8; 32]) -> bool {
		let mut sha = Sha256::new();
		sha.input(&payment_preimage);
		let mut payment_hash = [0; 32];
		sha.result(&mut payment_hash);

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
	fn claim_funds_internal(&self, mut channel_state: MutexGuard<ChannelHolder>, source: HTLCSource, payment_preimage: [u8; 32]) {
		match source {
			HTLCSource::OutboundRoute { .. } => {
				mem::drop(channel_state);
				let mut pending_events = self.pending_events.lock().unwrap();
				pending_events.push(events::Event::PaymentSent {
					payment_preimage
				});
			},
			HTLCSource::PreviousHopData(HTLCPreviousHopData { short_channel_id, htlc_id, .. }) => {
				//TODO: Delay the claimed_funds relaying just like we do outbound relay!
				let (node_id, fulfill_msgs) = {
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
						Ok(msg) => (chan.get_their_node_id(), msg),
						Err(_e) => {
							// TODO: There is probably a channel manager somewhere that needs to
							// learn the preimage as the channel may be about to hit the chain.
							//TODO: Do something with e?
							return
						},
					}
				};

				mem::drop(channel_state);
				if let Some(chan_monitor) = fulfill_msgs.1 {
					if let Err(_e) = self.monitor.add_update_monitor(chan_monitor.get_funding_txo().unwrap(), chan_monitor) {
						unimplemented!();// but def dont push the event...
					}
				}

				if let Some((msg, commitment_msg)) = fulfill_msgs.0 {
					let mut pending_events = self.pending_events.lock().unwrap();
					pending_events.push(events::Event::UpdateHTLCs {
						node_id: node_id,
						updates: msgs::CommitmentUpdate {
							update_add_htlcs: Vec::new(),
							update_fulfill_htlcs: vec![msg],
							update_fail_htlcs: Vec::new(),
							update_fail_malformed_htlcs: Vec::new(),
							commitment_signed: commitment_msg,
						}
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
		unimplemented!();
	}

	fn internal_open_channel(&self, their_node_id: &PublicKey, msg: &msgs::OpenChannel) -> Result<msgs::AcceptChannel, MsgHandleErrInternal> {
		if msg.chain_hash != self.genesis_hash {
			return Err(MsgHandleErrInternal::send_err_msg_no_close("Unknown genesis block hash", msg.temporary_channel_id.clone()));
		}
		let mut channel_state = self.channel_state.lock().unwrap();
		if channel_state.by_id.contains_key(&msg.temporary_channel_id) {
			return Err(MsgHandleErrInternal::send_err_msg_no_close("temporary_channel_id collision!", msg.temporary_channel_id.clone()));
		}

		let chan_keys = if cfg!(feature = "fuzztarget") {
			ChannelKeys {
				funding_key:               SecretKey::from_slice(&self.secp_ctx, &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0]).unwrap(),
				revocation_base_key:       SecretKey::from_slice(&self.secp_ctx, &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0]).unwrap(),
				payment_base_key:          SecretKey::from_slice(&self.secp_ctx, &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0]).unwrap(),
				delayed_payment_base_key:  SecretKey::from_slice(&self.secp_ctx, &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0]).unwrap(),
				htlc_base_key:             SecretKey::from_slice(&self.secp_ctx, &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, 0]).unwrap(),
				channel_close_key:         SecretKey::from_slice(&self.secp_ctx, &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6, 0]).unwrap(),
				channel_monitor_claim_key: SecretKey::from_slice(&self.secp_ctx, &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7, 0]).unwrap(),
				commitment_seed: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
			}
		} else {
			let mut key_seed = [0u8; 32];
			rng::fill_bytes(&mut key_seed);
			match ChannelKeys::new_from_seed(&key_seed) {
				Ok(key) => key,
				Err(_) => panic!("RNG is busted!")
			}
		};

		let channel = Channel::new_from_req(&*self.fee_estimator, chan_keys, their_node_id.clone(), msg, 0, false, self.announce_channels_publicly, Arc::clone(&self.logger)).map_err(|e| MsgHandleErrInternal::from_no_close(e))?;
		let accept_msg = channel.get_accept_channel();
		channel_state.by_id.insert(channel.channel_id(), channel);
		Ok(accept_msg)
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
					chan.accept_channel(&msg).map_err(|e| MsgHandleErrInternal::from_maybe_close(e))?;
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

	fn internal_funding_created(&self, their_node_id: &PublicKey, msg: &msgs::FundingCreated) -> Result<msgs::FundingSigned, MsgHandleErrInternal> {
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
							return Err(e).map_err(|e| MsgHandleErrInternal::from_maybe_close(e))
						}
					}
				},
				hash_map::Entry::Vacant(_) => return Err(MsgHandleErrInternal::send_err_msg_no_close("Failed to find corresponding channel", msg.temporary_channel_id))
			}
		}; // Release channel lock for install_watch_outpoint call,
		   // note that this means if the remote end is misbehaving and sends a message for the same
		   // channel back-to-back with funding_created, we'll end up thinking they sent a message
		   // for a bogus channel.
		if let Err(_e) = self.monitor.add_update_monitor(monitor_update.get_funding_txo().unwrap(), monitor_update) {
			unimplemented!();
		}
		let mut channel_state = self.channel_state.lock().unwrap();
		match channel_state.by_id.entry(funding_msg.channel_id) {
			hash_map::Entry::Occupied(_) => {
				return Err(MsgHandleErrInternal::send_err_msg_no_close("Already had channel with the new channel_id", funding_msg.channel_id))
			},
			hash_map::Entry::Vacant(e) => {
				e.insert(chan);
			}
		}
		Ok(funding_msg)
	}

	fn internal_funding_signed(&self, their_node_id: &PublicKey, msg: &msgs::FundingSigned) -> Result<(), MsgHandleErrInternal> {
		let (funding_txo, user_id, monitor) = {
			let mut channel_state = self.channel_state.lock().unwrap();
			match channel_state.by_id.get_mut(&msg.channel_id) {
				Some(chan) => {
					if chan.get_their_node_id() != *their_node_id {
						//TODO: here and below MsgHandleErrInternal, #153 case
						return Err(MsgHandleErrInternal::send_err_msg_no_close("Got a message for a channel from the wrong node!", msg.channel_id));
					}
					let chan_monitor = chan.funding_signed(&msg).map_err(|e| MsgHandleErrInternal::from_maybe_close(e))?;
					(chan.get_funding_txo().unwrap(), chan.get_user_id(), chan_monitor)
				},
				None => return Err(MsgHandleErrInternal::send_err_msg_no_close("Failed to find corresponding channel", msg.channel_id))
			}
		};
		if let Err(_e) = self.monitor.add_update_monitor(monitor.get_funding_txo().unwrap(), monitor) {
			unimplemented!();
		}
		let mut pending_events = self.pending_events.lock().unwrap();
		pending_events.push(events::Event::FundingBroadcastSafe {
			funding_txo: funding_txo,
			user_channel_id: user_id,
		});
		Ok(())
	}

	fn internal_funding_locked(&self, their_node_id: &PublicKey, msg: &msgs::FundingLocked) -> Result<Option<msgs::AnnouncementSignatures>, MsgHandleErrInternal> {
		let mut channel_state = self.channel_state.lock().unwrap();
		match channel_state.by_id.get_mut(&msg.channel_id) {
			Some(chan) => {
				if chan.get_their_node_id() != *their_node_id {
					//TODO: here and below MsgHandleErrInternal, #153 case
					return Err(MsgHandleErrInternal::send_err_msg_no_close("Got a message for a channel from the wrong node!", msg.channel_id));
				}
				chan.funding_locked(&msg).map_err(|e| MsgHandleErrInternal::from_maybe_close(e))?;
				return Ok(self.get_announcement_sigs(chan));
			},
			None => return Err(MsgHandleErrInternal::send_err_msg_no_close("Failed to find corresponding channel", msg.channel_id))
		};
	}

	fn internal_shutdown(&self, their_node_id: &PublicKey, msg: &msgs::Shutdown) -> Result<(Option<msgs::Shutdown>, Option<msgs::ClosingSigned>), MsgHandleErrInternal> {
		let (mut res, chan_option) = {
			let mut channel_state_lock = self.channel_state.lock().unwrap();
			let channel_state = channel_state_lock.borrow_parts();

			match channel_state.by_id.entry(msg.channel_id.clone()) {
				hash_map::Entry::Occupied(mut chan_entry) => {
					if chan_entry.get().get_their_node_id() != *their_node_id {
						//TODO: here and below MsgHandleErrInternal, #153 case
						return Err(MsgHandleErrInternal::send_err_msg_no_close("Got a message for a channel from the wrong node!", msg.channel_id));
					}
					let res = chan_entry.get_mut().shutdown(&*self.fee_estimator, &msg).map_err(|e| MsgHandleErrInternal::from_maybe_close(e))?;
					if chan_entry.get().is_shutdown() {
						if let Some(short_id) = chan_entry.get().get_short_channel_id() {
							channel_state.short_to_id.remove(&short_id);
						}
						(res, Some(chan_entry.remove_entry().1))
					} else { (res, None) }
				},
				hash_map::Entry::Vacant(_) => return Err(MsgHandleErrInternal::send_err_msg_no_close("Failed to find corresponding channel", msg.channel_id))
			}
		};
		for htlc_source in res.2.drain(..) {
			// unknown_next_peer...I dunno who that is anymore....
			self.fail_htlc_backwards_internal(self.channel_state.lock().unwrap(), htlc_source.0, &htlc_source.1, HTLCFailReason::Reason { failure_code: 0x4000 | 10, data: Vec::new() });
		}
		if let Some(chan) = chan_option {
			if let Ok(update) = self.get_channel_update(&chan) {
				let mut events = self.pending_events.lock().unwrap();
				events.push(events::Event::BroadcastChannelUpdate {
					msg: update
				});
			}
		}
		Ok((res.0, res.1))
	}

	fn internal_closing_signed(&self, their_node_id: &PublicKey, msg: &msgs::ClosingSigned) -> Result<Option<msgs::ClosingSigned>, MsgHandleErrInternal> {
		let (res, chan_option) = {
			let mut channel_state_lock = self.channel_state.lock().unwrap();
			let channel_state = channel_state_lock.borrow_parts();
			match channel_state.by_id.entry(msg.channel_id.clone()) {
				hash_map::Entry::Occupied(mut chan_entry) => {
					if chan_entry.get().get_their_node_id() != *their_node_id {
						//TODO: here and below MsgHandleErrInternal, #153 case
						return Err(MsgHandleErrInternal::send_err_msg_no_close("Got a message for a channel from the wrong node!", msg.channel_id));
					}
					let res = chan_entry.get_mut().closing_signed(&*self.fee_estimator, &msg).map_err(|e| MsgHandleErrInternal::from_maybe_close(e))?;
					if res.1.is_some() {
						// We're done with this channel, we've got a signed closing transaction and
						// will send the closing_signed back to the remote peer upon return. This
						// also implies there are no pending HTLCs left on the channel, so we can
						// fully delete it from tracking (the channel monitor is still around to
						// watch for old state broadcasts)!
						if let Some(short_id) = chan_entry.get().get_short_channel_id() {
							channel_state.short_to_id.remove(&short_id);
						}
						(res, Some(chan_entry.remove_entry().1))
					} else { (res, None) }
				},
				hash_map::Entry::Vacant(_) => return Err(MsgHandleErrInternal::send_err_msg_no_close("Failed to find corresponding channel", msg.channel_id))
			}
		};
		if let Some(broadcast_tx) = res.1 {
			self.tx_broadcaster.broadcast_transaction(&broadcast_tx);
		}
		if let Some(chan) = chan_option {
			if let Ok(update) = self.get_channel_update(&chan) {
				let mut events = self.pending_events.lock().unwrap();
				events.push(events::Event::BroadcastChannelUpdate {
					msg: update
				});
			}
		}
		Ok(res.0)
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

		let (pending_forward_info, mut channel_state_lock) = self.decode_update_add_htlc_onion(msg);
		let channel_state = channel_state_lock.borrow_parts();

		match channel_state.by_id.get_mut(&msg.channel_id) {
			Some(chan) => {
				if chan.get_their_node_id() != *their_node_id {
					//TODO: here MsgHandleErrInternal, #153 case
					return Err(MsgHandleErrInternal::send_err_msg_no_close("Got a message for a channel from the wrong node!", msg.channel_id));
				}
				if !chan.is_usable() {
					return Err(MsgHandleErrInternal::from_no_close(HandleError{err: "Channel not yet available for receiving HTLCs", action: Some(msgs::ErrorAction::IgnoreError)}));
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
				chan.update_fulfill_htlc(&msg).map_err(|e| MsgHandleErrInternal::from_maybe_close(e))?.clone()
			},
			None => return Err(MsgHandleErrInternal::send_err_msg_no_close("Failed to find corresponding channel", msg.channel_id))
		};
		self.claim_funds_internal(channel_state, htlc_source, msg.payment_preimage.clone());
		Ok(())
	}

	fn internal_update_fail_htlc(&self, their_node_id: &PublicKey, msg: &msgs::UpdateFailHTLC) -> Result<Option<msgs::HTLCFailChannelUpdate>, MsgHandleErrInternal> {
		let mut channel_state = self.channel_state.lock().unwrap();
		let htlc_source = match channel_state.by_id.get_mut(&msg.channel_id) {
			Some(chan) => {
				if chan.get_their_node_id() != *their_node_id {
					//TODO: here and below MsgHandleErrInternal, #153 case
					return Err(MsgHandleErrInternal::send_err_msg_no_close("Got a message for a channel from the wrong node!", msg.channel_id));
				}
				chan.update_fail_htlc(&msg, HTLCFailReason::ErrorPacket { err: msg.reason.clone() }).map_err(|e| MsgHandleErrInternal::from_maybe_close(e))
			},
			None => return Err(MsgHandleErrInternal::send_err_msg_no_close("Failed to find corresponding channel", msg.channel_id))
		}?;

		match htlc_source {
			&HTLCSource::OutboundRoute { ref route, ref session_priv, .. } => {
				// Handle packed channel/node updates for passing back for the route handler
				let mut packet_decrypted = msg.reason.data.clone();
				let mut res = None;
				Self::construct_onion_keys_callback(&self.secp_ctx, &route, &session_priv, |shared_secret, _, _, route_hop| {
					if res.is_some() { return; }

					let ammag = ChannelManager::gen_ammag_from_shared_secret(&shared_secret);

					let mut decryption_tmp = Vec::with_capacity(packet_decrypted.len());
					decryption_tmp.resize(packet_decrypted.len(), 0);
					let mut chacha = ChaCha20::new(&ammag, &[0u8; 8]);
					chacha.process(&packet_decrypted, &mut decryption_tmp[..]);
					packet_decrypted = decryption_tmp;

					if let Ok(err_packet) = msgs::DecodedOnionErrorPacket::decode(&packet_decrypted) {
						if err_packet.failuremsg.len() >= 2 {
							let um = ChannelManager::gen_um_from_shared_secret(&shared_secret);

							let mut hmac = Hmac::new(Sha256::new(), &um);
							hmac.input(&err_packet.encode()[32..]);
							let mut calc_tag = [0u8; 32];
							hmac.raw_result(&mut calc_tag);
							if crypto::util::fixed_time_eq(&calc_tag, &err_packet.hmac) {
								const UNKNOWN_CHAN: u16 = 0x4000|10;
								const TEMP_CHAN_FAILURE: u16 = 0x4000|7;
								match byte_utils::slice_to_be16(&err_packet.failuremsg[0..2]) {
									TEMP_CHAN_FAILURE => {
										if err_packet.failuremsg.len() >= 4 {
											let update_len = byte_utils::slice_to_be16(&err_packet.failuremsg[2..4]) as usize;
											if err_packet.failuremsg.len() >= 4 + update_len {
												if let Ok(chan_update) = msgs::ChannelUpdate::decode(&err_packet.failuremsg[4..4 + update_len]) {
													res = Some(msgs::HTLCFailChannelUpdate::ChannelUpdateMessage {
														msg: chan_update,
													});
												}
											}
										}
									},
									UNKNOWN_CHAN => {
										// No such next-hop. We know this came from the
										// current node as the HMAC validated.
										res = Some(msgs::HTLCFailChannelUpdate::ChannelClosed {
											short_channel_id: route_hop.short_channel_id
										});
									},
									_ => {}, //TODO: Enumerate all of these!
								}
							}
						}
					}
				}).unwrap();
				Ok(res)
			},
			_ => { Ok(None) },
		}
	}

	fn internal_update_fail_malformed_htlc(&self, their_node_id: &PublicKey, msg: &msgs::UpdateFailMalformedHTLC) -> Result<(), MsgHandleErrInternal> {
		let mut channel_state = self.channel_state.lock().unwrap();
		match channel_state.by_id.get_mut(&msg.channel_id) {
			Some(chan) => {
				if chan.get_their_node_id() != *their_node_id {
					//TODO: here and below MsgHandleErrInternal, #153 case
					return Err(MsgHandleErrInternal::send_err_msg_no_close("Got a message for a channel from the wrong node!", msg.channel_id));
				}
				chan.update_fail_malformed_htlc(&msg, HTLCFailReason::Reason { failure_code: msg.failure_code, data: Vec::new() }).map_err(|e| MsgHandleErrInternal::from_maybe_close(e))?;
				Ok(())
			},
			None => return Err(MsgHandleErrInternal::send_err_msg_no_close("Failed to find corresponding channel", msg.channel_id))
		}
	}

	fn internal_commitment_signed(&self, their_node_id: &PublicKey, msg: &msgs::CommitmentSigned) -> Result<(msgs::RevokeAndACK, Option<msgs::CommitmentSigned>), MsgHandleErrInternal> {
		let (revoke_and_ack, commitment_signed, chan_monitor) = {
			let mut channel_state = self.channel_state.lock().unwrap();
			match channel_state.by_id.get_mut(&msg.channel_id) {
				Some(chan) => {
					if chan.get_their_node_id() != *their_node_id {
						//TODO: here and below MsgHandleErrInternal, #153 case
						return Err(MsgHandleErrInternal::send_err_msg_no_close("Got a message for a channel from the wrong node!", msg.channel_id));
					}
					chan.commitment_signed(&msg).map_err(|e| MsgHandleErrInternal::from_maybe_close(e))?
				},
				None => return Err(MsgHandleErrInternal::send_err_msg_no_close("Failed to find corresponding channel", msg.channel_id))
			}
		};
		if let Err(_e) = self.monitor.add_update_monitor(chan_monitor.get_funding_txo().unwrap(), chan_monitor) {
			unimplemented!();
		}

		Ok((revoke_and_ack, commitment_signed))
	}

	fn internal_revoke_and_ack(&self, their_node_id: &PublicKey, msg: &msgs::RevokeAndACK) -> Result<Option<msgs::CommitmentUpdate>, MsgHandleErrInternal> {
		let ((res, mut pending_forwards, mut pending_failures, chan_monitor), short_channel_id) = {
			let mut channel_state = self.channel_state.lock().unwrap();
			match channel_state.by_id.get_mut(&msg.channel_id) {
				Some(chan) => {
					if chan.get_their_node_id() != *their_node_id {
						//TODO: here and below MsgHandleErrInternal, #153 case
						return Err(MsgHandleErrInternal::send_err_msg_no_close("Got a message for a channel from the wrong node!", msg.channel_id));
					}
					(chan.revoke_and_ack(&msg).map_err(|e| MsgHandleErrInternal::from_maybe_close(e))?, chan.get_short_channel_id().expect("RAA should only work on a short-id-available channel"))
				},
				None => return Err(MsgHandleErrInternal::send_err_msg_no_close("Failed to find corresponding channel", msg.channel_id))
			}
		};
		if let Err(_e) = self.monitor.add_update_monitor(chan_monitor.get_funding_txo().unwrap(), chan_monitor) {
			unimplemented!();
		}
		for failure in pending_failures.drain(..) {
			self.fail_htlc_backwards_internal(self.channel_state.lock().unwrap(), failure.0, &failure.1, failure.2);
		}

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
						entry.get_mut().push(HTLCForwardInfo { prev_short_channel_id: short_channel_id, prev_htlc_id, forward_info });
					},
					hash_map::Entry::Vacant(entry) => {
						entry.insert(vec!(HTLCForwardInfo { prev_short_channel_id: short_channel_id, prev_htlc_id, forward_info }));
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

		Ok(res)
	}

	fn internal_update_fee(&self, their_node_id: &PublicKey, msg: &msgs::UpdateFee) -> Result<(), MsgHandleErrInternal> {
		let mut channel_state = self.channel_state.lock().unwrap();
		match channel_state.by_id.get_mut(&msg.channel_id) {
			Some(chan) => {
				if chan.get_their_node_id() != *their_node_id {
					//TODO: here and below MsgHandleErrInternal, #153 case
					return Err(MsgHandleErrInternal::send_err_msg_no_close("Got a message for a channel from the wrong node!", msg.channel_id));
				}
				chan.update_fee(&*self.fee_estimator, &msg).map_err(|e| MsgHandleErrInternal::from_maybe_close(e))
			},
			None => return Err(MsgHandleErrInternal::send_err_msg_no_close("Failed to find corresponding channel", msg.channel_id))
		}
	}

	fn internal_announcement_signatures(&self, their_node_id: &PublicKey, msg: &msgs::AnnouncementSignatures) -> Result<(), MsgHandleErrInternal> {
		let (chan_announcement, chan_update) = {
			let mut channel_state = self.channel_state.lock().unwrap();
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
						.map_err(|e| MsgHandleErrInternal::from_maybe_close(e))?;

					let were_node_one = announcement.node_id_1 == our_node_id;
					let msghash = Message::from_slice(&Sha256dHash::from_data(&announcement.encode()[..])[..]).unwrap();
					let bad_sig_action = MsgHandleErrInternal::send_err_msg_close_chan("Bad announcement_signatures node_signature", msg.channel_id);
					secp_call!(self.secp_ctx.verify(&msghash, &msg.node_signature, if were_node_one { &announcement.node_id_2 } else { &announcement.node_id_1 }), bad_sig_action);
					secp_call!(self.secp_ctx.verify(&msghash, &msg.bitcoin_signature, if were_node_one { &announcement.bitcoin_key_2 } else { &announcement.bitcoin_key_1 }), bad_sig_action);

					let our_node_sig = self.secp_ctx.sign(&msghash, &self.our_network_key);

					(msgs::ChannelAnnouncement {
						node_signature_1: if were_node_one { our_node_sig } else { msg.node_signature },
						node_signature_2: if were_node_one { msg.node_signature } else { our_node_sig },
						bitcoin_signature_1: if were_node_one { our_bitcoin_sig } else { msg.bitcoin_signature },
						bitcoin_signature_2: if were_node_one { msg.bitcoin_signature } else { our_bitcoin_sig },
						contents: announcement,
					}, self.get_channel_update(chan).unwrap()) // can only fail if we're not in a ready state
				},
				None => return Err(MsgHandleErrInternal::send_err_msg_no_close("Failed to find corresponding channel", msg.channel_id))
			}
		};
		let mut pending_events = self.pending_events.lock().unwrap();
		pending_events.push(events::Event::BroadcastChannelAnnouncement { msg: chan_announcement, update_msg: chan_update });
		Ok(())
	}


}

impl events::EventsProvider for ChannelManager {
	fn get_and_clear_pending_events(&self) -> Vec<events::Event> {
		let mut pending_events = self.pending_events.lock().unwrap();
		let mut ret = Vec::new();
		mem::swap(&mut ret, &mut *pending_events);
		ret
	}
}

impl ChainListener for ChannelManager {
	fn block_connected(&self, header: &BlockHeader, height: u32, txn_matched: &[&Transaction], indexes_of_txn_matched: &[u32]) {
		let mut new_events = Vec::new();
		let mut failed_channels = Vec::new();
		{
			let mut channel_lock = self.channel_state.lock().unwrap();
			let channel_state = channel_lock.borrow_parts();
			let short_to_id = channel_state.short_to_id;
			channel_state.by_id.retain(|_, channel| {
				let chan_res = channel.block_connected(header, height, txn_matched, indexes_of_txn_matched);
				if let Ok(Some(funding_locked)) = chan_res {
					let announcement_sigs = self.get_announcement_sigs(channel);
					new_events.push(events::Event::SendFundingLocked {
						node_id: channel.get_their_node_id(),
						msg: funding_locked,
						announcement_sigs: announcement_sigs
					});
					short_to_id.insert(channel.get_short_channel_id().unwrap(), channel.channel_id());
				} else if let Err(e) = chan_res {
					new_events.push(events::Event::HandleError {
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
									new_events.push(events::Event::BroadcastChannelUpdate {
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
						new_events.push(events::Event::BroadcastChannelUpdate {
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
		let mut pending_events = self.pending_events.lock().unwrap();
		for funding_locked in new_events.drain(..) {
			pending_events.push(funding_locked);
		}
		self.latest_block_height.store(height as usize, Ordering::Release);
	}

	/// We force-close the channel without letting our counterparty participate in the shutdown
	fn block_disconnected(&self, header: &BlockHeader) {
		let mut new_events = Vec::new();
		let mut failed_channels = Vec::new();
		{
			let mut channel_lock = self.channel_state.lock().unwrap();
			let channel_state = channel_lock.borrow_parts();
			let short_to_id = channel_state.short_to_id;
			channel_state.by_id.retain(|_,  v| {
				if v.block_disconnected(header) {
					if let Some(short_id) = v.get_short_channel_id() {
						short_to_id.remove(&short_id);
					}
					failed_channels.push(v.force_shutdown());
					if let Ok(update) = self.get_channel_update(&v) {
						new_events.push(events::Event::BroadcastChannelUpdate {
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
		if !new_events.is_empty() {
			let mut pending_events = self.pending_events.lock().unwrap();
			for funding_locked in new_events.drain(..) {
				pending_events.push(funding_locked);
			}
		}
		self.latest_block_height.fetch_sub(1, Ordering::AcqRel);
	}
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

impl ChannelMessageHandler for ChannelManager {
	//TODO: Handle errors and close channel (or so)
	fn handle_open_channel(&self, their_node_id: &PublicKey, msg: &msgs::OpenChannel) -> Result<msgs::AcceptChannel, HandleError> {
		handle_error!(self, self.internal_open_channel(their_node_id, msg), their_node_id)
	}

	fn handle_accept_channel(&self, their_node_id: &PublicKey, msg: &msgs::AcceptChannel) -> Result<(), HandleError> {
		handle_error!(self, self.internal_accept_channel(their_node_id, msg), their_node_id)
	}

	fn handle_funding_created(&self, their_node_id: &PublicKey, msg: &msgs::FundingCreated) -> Result<msgs::FundingSigned, HandleError> {
		handle_error!(self, self.internal_funding_created(their_node_id, msg), their_node_id)
	}

	fn handle_funding_signed(&self, their_node_id: &PublicKey, msg: &msgs::FundingSigned) -> Result<(), HandleError> {
		handle_error!(self, self.internal_funding_signed(their_node_id, msg), their_node_id)
	}

	fn handle_funding_locked(&self, their_node_id: &PublicKey, msg: &msgs::FundingLocked) -> Result<Option<msgs::AnnouncementSignatures>, HandleError> {
		handle_error!(self, self.internal_funding_locked(their_node_id, msg), their_node_id)
	}

	fn handle_shutdown(&self, their_node_id: &PublicKey, msg: &msgs::Shutdown) -> Result<(Option<msgs::Shutdown>, Option<msgs::ClosingSigned>), HandleError> {
		handle_error!(self, self.internal_shutdown(their_node_id, msg), their_node_id)
	}

	fn handle_closing_signed(&self, their_node_id: &PublicKey, msg: &msgs::ClosingSigned) -> Result<Option<msgs::ClosingSigned>, HandleError> {
		handle_error!(self, self.internal_closing_signed(their_node_id, msg), their_node_id)
	}

	fn handle_update_add_htlc(&self, their_node_id: &PublicKey, msg: &msgs::UpdateAddHTLC) -> Result<(), msgs::HandleError> {
		handle_error!(self, self.internal_update_add_htlc(their_node_id, msg), their_node_id)
	}

	fn handle_update_fulfill_htlc(&self, their_node_id: &PublicKey, msg: &msgs::UpdateFulfillHTLC) -> Result<(), HandleError> {
		handle_error!(self, self.internal_update_fulfill_htlc(their_node_id, msg), their_node_id)
	}

	fn handle_update_fail_htlc(&self, their_node_id: &PublicKey, msg: &msgs::UpdateFailHTLC) -> Result<Option<msgs::HTLCFailChannelUpdate>, HandleError> {
		handle_error!(self, self.internal_update_fail_htlc(their_node_id, msg), their_node_id)
	}

	fn handle_update_fail_malformed_htlc(&self, their_node_id: &PublicKey, msg: &msgs::UpdateFailMalformedHTLC) -> Result<(), HandleError> {
		handle_error!(self, self.internal_update_fail_malformed_htlc(their_node_id, msg), their_node_id)
	}

	fn handle_commitment_signed(&self, their_node_id: &PublicKey, msg: &msgs::CommitmentSigned) -> Result<(msgs::RevokeAndACK, Option<msgs::CommitmentSigned>), HandleError> {
		handle_error!(self, self.internal_commitment_signed(their_node_id, msg), their_node_id)
	}

	fn handle_revoke_and_ack(&self, their_node_id: &PublicKey, msg: &msgs::RevokeAndACK) -> Result<Option<msgs::CommitmentUpdate>, HandleError> {
		handle_error!(self, self.internal_revoke_and_ack(their_node_id, msg), their_node_id)
	}

	fn handle_update_fee(&self, their_node_id: &PublicKey, msg: &msgs::UpdateFee) -> Result<(), HandleError> {
		handle_error!(self, self.internal_update_fee(their_node_id, msg), their_node_id)
	}

	fn handle_announcement_signatures(&self, their_node_id: &PublicKey, msg: &msgs::AnnouncementSignatures) -> Result<(), HandleError> {
		handle_error!(self, self.internal_announcement_signatures(their_node_id, msg), their_node_id)
	}

	fn peer_disconnected(&self, their_node_id: &PublicKey, no_connection_possible: bool) {
		let mut new_events = Vec::new();
		let mut failed_channels = Vec::new();
		{
			let mut channel_state_lock = self.channel_state.lock().unwrap();
			let channel_state = channel_state_lock.borrow_parts();
			let short_to_id = channel_state.short_to_id;
			if no_connection_possible {
				channel_state.by_id.retain(|_, chan| {
					if chan.get_their_node_id() == *their_node_id {
						if let Some(short_id) = chan.get_short_channel_id() {
							short_to_id.remove(&short_id);
						}
						failed_channels.push(chan.force_shutdown());
						if let Ok(update) = self.get_channel_update(&chan) {
							new_events.push(events::Event::BroadcastChannelUpdate {
								msg: update
							});
						}
						false
					} else {
						true
					}
				});
			} else {
				for chan in channel_state.by_id {
					if chan.1.get_their_node_id() == *their_node_id {
						//TODO: mark channel disabled (and maybe announce such after a timeout). Also
						//fail and wipe any uncommitted outbound HTLCs as those are considered after
						//reconnect.
					}
				}
			}
		}
		for failure in failed_channels.drain(..) {
			self.finish_force_close_channel(failure);
		}
		if !new_events.is_empty() {
			let mut pending_events = self.pending_events.lock().unwrap();
			for event in new_events.drain(..) {
				pending_events.push(event);
			}
		}
	}

	fn handle_error(&self, their_node_id: &PublicKey, msg: &msgs::ErrorMessage) {
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

#[cfg(test)]
mod tests {
	use chain::chaininterface;
	use chain::transaction::OutPoint;
	use chain::chaininterface::ChainListener;
	use ln::channelmanager::{ChannelManager,OnionKeys};
	use ln::router::{Route, RouteHop, Router};
	use ln::msgs;
	use ln::msgs::{MsgEncodable,ChannelMessageHandler,RoutingMessageHandler};
	use util::test_utils;
	use util::events::{Event, EventsProvider};
	use util::logger::Logger;

	use bitcoin::util::hash::Sha256dHash;
	use bitcoin::blockdata::block::{Block, BlockHeader};
	use bitcoin::blockdata::transaction::{Transaction, TxOut};
	use bitcoin::blockdata::constants::genesis_block;
	use bitcoin::network::constants::Network;
	use bitcoin::network::serialize::serialize;
	use bitcoin::network::serialize::BitcoinHash;

	use hex;

	use secp256k1::{Secp256k1, Message};
	use secp256k1::key::{PublicKey,SecretKey};

	use crypto::sha2::Sha256;
	use crypto::digest::Digest;

	use rand::{thread_rng,Rng};

	use std::cell::RefCell;
	use std::collections::HashMap;
	use std::default::Default;
	use std::rc::Rc;
	use std::sync::{Arc, Mutex};
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

		let packet = ChannelManager::construct_onion_packet(payloads, onion_keys, &[0x42; 32]).unwrap();
		// Just check the final packet encoding, as it includes all the per-hop vectors in it
		// anyway...
		assert_eq!(packet.encode(), hex::decode("0002eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619e5f14350c2a76fc232b5e46d421e9615471ab9e0bc887beff8c95fdb878f7b3a716a996c7845c93d90e4ecbb9bde4ece2f69425c99e4bc820e44485455f135edc0d10f7d61ab590531cf08000179a333a347f8b4072f216400406bdf3bf038659793d4a1fd7b246979e3150a0a4cb052c9ec69acf0f48c3d39cd55675fe717cb7d80ce721caad69320c3a469a202f1e468c67eaf7a7cd8226d0fd32f7b48084dca885d56047694762b67021713ca673929c163ec36e04e40ca8e1c6d17569419d3039d9a1ec866abe044a9ad635778b961fc0776dc832b3a451bd5d35072d2269cf9b040f6b7a7dad84fb114ed413b1426cb96ceaf83825665ed5a1d002c1687f92465b49ed4c7f0218ff8c6c7dd7221d589c65b3b9aaa71a41484b122846c7c7b57e02e679ea8469b70e14fe4f70fee4d87b910cf144be6fe48eef24da475c0b0bcc6565ae82cd3f4e3b24c76eaa5616c6111343306ab35c1fe5ca4a77c0e314ed7dba39d6f1e0de791719c241a939cc493bea2bae1c1e932679ea94d29084278513c77b899cc98059d06a27d171b0dbdf6bee13ddc4fc17a0c4d2827d488436b57baa167544138ca2e64a11b43ac8a06cd0c2fba2d4d900ed2d9205305e2d7383cc98dacb078133de5f6fb6bed2ef26ba92cea28aafc3b9948dd9ae5559e8bd6920b8cea462aa445ca6a95e0e7ba52961b181c79e73bd581821df2b10173727a810c92b83b5ba4a0403eb710d2ca10689a35bec6c3a708e9e92f7d78ff3c5d9989574b00c6736f84c199256e76e19e78f0c98a9d580b4a658c84fc8f2096c2fbea8f5f8c59d0fdacb3be2802ef802abbecb3aba4acaac69a0e965abd8981e9896b1f6ef9d60f7a164b371af869fd0e48073742825e9434fc54da837e120266d53302954843538ea7c6c3dbfb4ff3b2fdbe244437f2a153ccf7bdb4c92aa08102d4f3cff2ae5ef86fab4653595e6a5837fa2f3e29f27a9cde5966843fb847a4a61f1e76c281fe8bb2b0a181d096100db5a1a5ce7a910238251a43ca556712eaadea167fb4d7d75825e440f3ecd782036d7574df8bceacb397abefc5f5254d2722215c53ff54af8299aaaad642c6d72a14d27882d9bbd539e1cc7a527526ba89b8c037ad09120e98ab042d3e8652b31ae0e478516bfaf88efca9f3676ffe99d2819dcaeb7610a626695f53117665d267d3f7abebd6bbd6733f645c72c389f03855bdf1e4b8075b516569b118233a0f0971d24b83113c0b096f5216a207ca99a7cddc81c130923fe3d91e7508c9ac5f2e914ff5dccab9e558566fa14efb34ac98d878580814b94b73acbfde9072f30b881f7f0fff42d4045d1ace6322d86a97d164aa84d93a60498065cc7c20e636f5862dc81531a88c60305a2e59a985be327a6902e4bed986dbf4a0b50c217af0ea7fdf9ab37f9ea1a1aaa72f54cf40154ea9b269f1a7c09f9f43245109431a175d50e2db0132337baa0ef97eed0fcf20489da36b79a1172faccc2f7ded7c60e00694282d93359c4682135642bc81f433574aa8ef0c97b4ade7ca372c5ffc23c7eddd839bab4e0f14d6df15c9dbeab176bec8b5701cf054eb3072f6dadc98f88819042bf10c407516ee58bce33fbe3b3d86a54255e577db4598e30a135361528c101683a5fcde7e8ba53f3456254be8f45fe3a56120ae96ea3773631fcb3873aa3abd91bcff00bd38bd43697a2e789e00da6077482e7b1b1a677b5afae4c54e6cbdf7377b694eb7d7a5b913476a5be923322d3de06060fd5e819635232a2cf4f0731da13b8546d1d6d4f8d75b9fce6c2341a71b0ea6f780df54bfdb0dd5cd9855179f602f9172307c7268724c3618e6817abd793adc214a0dc0bc616816632f27ea336fb56dfd").unwrap());
	}

	#[test]
	fn test_failure_packet_onion() {
		// Returning Errors test vectors from BOLT 4

		let onion_keys = build_test_onion_keys();
		let onion_error = ChannelManager::build_failure_packet(&onion_keys[4].shared_secret, 0x2002, &[0; 0]);
		assert_eq!(onion_error.encode(), hex::decode("4c2fc8bc08510334b6833ad9c3e79cd1b52ae59dfe5c2a4b23ead50f09f7ee0b0002200200fe0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").unwrap());

		let onion_packet_1 = ChannelManager::encrypt_failure_packet(&onion_keys[4].shared_secret, &onion_error.encode()[..]);
		assert_eq!(onion_packet_1.data, hex::decode("a5e6bd0c74cb347f10cce367f949098f2457d14c046fd8a22cb96efb30b0fdcda8cb9168b50f2fd45edd73c1b0c8b33002df376801ff58aaa94000bf8a86f92620f343baef38a580102395ae3abf9128d1047a0736ff9b83d456740ebbb4aeb3aa9737f18fb4afb4aa074fb26c4d702f42968888550a3bded8c05247e045b866baef0499f079fdaeef6538f31d44deafffdfd3afa2fb4ca9082b8f1c465371a9894dd8c243fb4847e004f5256b3e90e2edde4c9fb3082ddfe4d1e734cacd96ef0706bf63c9984e22dc98851bcccd1c3494351feb458c9c6af41c0044bea3c47552b1d992ae542b17a2d0bba1a096c78d169034ecb55b6e3a7263c26017f033031228833c1daefc0dedb8cf7c3e37c9c37ebfe42f3225c326e8bcfd338804c145b16e34e4").unwrap());

		let onion_packet_2 = ChannelManager::encrypt_failure_packet(&onion_keys[3].shared_secret, &onion_packet_1.data[..]);
		assert_eq!(onion_packet_2.data, hex::decode("c49a1ce81680f78f5f2000cda36268de34a3f0a0662f55b4e837c83a8773c22aa081bab1616a0011585323930fa5b9fae0c85770a2279ff59ec427ad1bbff9001c0cd1497004bd2a0f68b50704cf6d6a4bf3c8b6a0833399a24b3456961ba00736785112594f65b6b2d44d9f5ea4e49b5e1ec2af978cbe31c67114440ac51a62081df0ed46d4a3df295da0b0fe25c0115019f03f15ec86fabb4c852f83449e812f141a9395b3f70b766ebbd4ec2fae2b6955bd8f32684c15abfe8fd3a6261e52650e8807a92158d9f1463261a925e4bfba44bd20b166d532f0017185c3a6ac7957adefe45559e3072c8dc35abeba835a8cb01a71a15c736911126f27d46a36168ca5ef7dccd4e2886212602b181463e0dd30185c96348f9743a02aca8ec27c0b90dca270").unwrap());

		let onion_packet_3 = ChannelManager::encrypt_failure_packet(&onion_keys[2].shared_secret, &onion_packet_2.data[..]);
		assert_eq!(onion_packet_3.data, hex::decode("a5d3e8634cfe78b2307d87c6d90be6fe7855b4f2cc9b1dfb19e92e4b79103f61ff9ac25f412ddfb7466e74f81b3e545563cdd8f5524dae873de61d7bdfccd496af2584930d2b566b4f8d3881f8c043df92224f38cf094cfc09d92655989531524593ec6d6caec1863bdfaa79229b5020acc034cd6deeea1021c50586947b9b8e6faa83b81fbfa6133c0af5d6b07c017f7158fa94f0d206baf12dda6b68f785b773b360fd0497e16cc402d779c8d48d0fa6315536ef0660f3f4e1865f5b38ea49c7da4fd959de4e83ff3ab686f059a45c65ba2af4a6a79166aa0f496bf04d06987b6d2ea205bdb0d347718b9aeff5b61dfff344993a275b79717cd815b6ad4c0beb568c4ac9c36ff1c315ec1119a1993c4b61e6eaa0375e0aaf738ac691abd3263bf937e3").unwrap());

		let onion_packet_4 = ChannelManager::encrypt_failure_packet(&onion_keys[1].shared_secret, &onion_packet_3.data[..]);
		assert_eq!(onion_packet_4.data, hex::decode("aac3200c4968f56b21f53e5e374e3a2383ad2b1b6501bbcc45abc31e59b26881b7dfadbb56ec8dae8857add94e6702fb4c3a4de22e2e669e1ed926b04447fc73034bb730f4932acd62727b75348a648a1128744657ca6a4e713b9b646c3ca66cac02cdab44dd3439890ef3aaf61708714f7375349b8da541b2548d452d84de7084bb95b3ac2345201d624d31f4d52078aa0fa05a88b4e20202bd2b86ac5b52919ea305a8949de95e935eed0319cf3cf19ebea61d76ba92532497fcdc9411d06bcd4275094d0a4a3c5d3a945e43305a5a9256e333e1f64dbca5fcd4e03a39b9012d197506e06f29339dfee3331995b21615337ae060233d39befea925cc262873e0530408e6990f1cbd233a150ef7b004ff6166c70c68d9f8c853c1abca640b8660db2921").unwrap());

		let onion_packet_5 = ChannelManager::encrypt_failure_packet(&onion_keys[0].shared_secret, &onion_packet_4.data[..]);
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
		network_payment_count: Rc<RefCell<u8>>,
		network_chan_count: Rc<RefCell<u32>>,
	}

	fn create_chan_between_nodes(node_a: &Node, node_b: &Node) -> (msgs::ChannelAnnouncement, msgs::ChannelUpdate, msgs::ChannelUpdate, [u8; 32], Transaction) {
		node_a.node.create_channel(node_b.node.get_our_node_id(), 100000, 10001, 42).unwrap();

		let events_1 = node_a.node.get_and_clear_pending_events();
		assert_eq!(events_1.len(), 1);
		let accept_chan = match events_1[0] {
			Event::SendOpenChannel { ref node_id, ref msg } => {
				assert_eq!(*node_id, node_b.node.get_our_node_id());
				node_b.node.handle_open_channel(&node_a.node.get_our_node_id(), msg).unwrap()
			},
			_ => panic!("Unexpected event"),
		};

		node_a.node.handle_accept_channel(&node_b.node.get_our_node_id(), &accept_chan).unwrap();

		let chan_id = *node_a.network_chan_count.borrow();
		let tx;
		let funding_output;

		let events_2 = node_a.node.get_and_clear_pending_events();
		assert_eq!(events_2.len(), 1);
		match events_2[0] {
			Event::FundingGenerationReady { ref temporary_channel_id, ref channel_value_satoshis, ref output_script, user_channel_id } => {
				assert_eq!(*channel_value_satoshis, 100000);
				assert_eq!(user_channel_id, 42);

				tx = Transaction { version: chan_id as u32, lock_time: 0, input: Vec::new(), output: vec![TxOut {
					value: *channel_value_satoshis, script_pubkey: output_script.clone(),
				}]};
				funding_output = OutPoint::new(Sha256dHash::from_data(&serialize(&tx).unwrap()[..]), 0);

				node_a.node.funding_transaction_generated(&temporary_channel_id, funding_output);
				let mut added_monitors = node_a.chan_monitor.added_monitors.lock().unwrap();
				assert_eq!(added_monitors.len(), 1);
				assert_eq!(added_monitors[0].0, funding_output);
				added_monitors.clear();
			},
			_ => panic!("Unexpected event"),
		}

		let events_3 = node_a.node.get_and_clear_pending_events();
		assert_eq!(events_3.len(), 1);
		let funding_signed = match events_3[0] {
			Event::SendFundingCreated { ref node_id, ref msg } => {
				assert_eq!(*node_id, node_b.node.get_our_node_id());
				let res = node_b.node.handle_funding_created(&node_a.node.get_our_node_id(), msg).unwrap();
				let mut added_monitors = node_b.chan_monitor.added_monitors.lock().unwrap();
				assert_eq!(added_monitors.len(), 1);
				assert_eq!(added_monitors[0].0, funding_output);
				added_monitors.clear();
				res
			},
			_ => panic!("Unexpected event"),
		};

		node_a.node.handle_funding_signed(&node_b.node.get_our_node_id(), &funding_signed).unwrap();
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

		confirm_transaction(&node_a.chain_monitor, &tx, chan_id);
		let events_5 = node_a.node.get_and_clear_pending_events();
		assert_eq!(events_5.len(), 1);
		match events_5[0] {
			Event::SendFundingLocked { ref node_id, ref msg, ref announcement_sigs } => {
				assert_eq!(*node_id, node_b.node.get_our_node_id());
				assert!(announcement_sigs.is_none());
				node_b.node.handle_funding_locked(&node_a.node.get_our_node_id(), msg).unwrap()
			},
			_ => panic!("Unexpected event"),
		};

		let channel_id;

		confirm_transaction(&node_b.chain_monitor, &tx, chan_id);
		let events_6 = node_b.node.get_and_clear_pending_events();
		assert_eq!(events_6.len(), 1);
		let as_announcement_sigs = match events_6[0] {
			Event::SendFundingLocked { ref node_id, ref msg, ref announcement_sigs } => {
				assert_eq!(*node_id, node_a.node.get_our_node_id());
				channel_id = msg.channel_id.clone();
				let as_announcement_sigs = node_a.node.handle_funding_locked(&node_b.node.get_our_node_id(), msg).unwrap().unwrap();
				node_a.node.handle_announcement_signatures(&node_b.node.get_our_node_id(), &(*announcement_sigs).clone().unwrap()).unwrap();
				as_announcement_sigs
			},
			_ => panic!("Unexpected event"),
		};

		let events_7 = node_a.node.get_and_clear_pending_events();
		assert_eq!(events_7.len(), 1);
		let (announcement, as_update) = match events_7[0] {
			Event::BroadcastChannelAnnouncement { ref msg, ref update_msg } => {
				(msg, update_msg)
			},
			_ => panic!("Unexpected event"),
		};

		node_b.node.handle_announcement_signatures(&node_a.node.get_our_node_id(), &as_announcement_sigs).unwrap();
		let events_8 = node_b.node.get_and_clear_pending_events();
		assert_eq!(events_8.len(), 1);
		let bs_update = match events_8[0] {
			Event::BroadcastChannelAnnouncement { ref msg, ref update_msg } => {
				assert!(*announcement == *msg);
				update_msg
			},
			_ => panic!("Unexpected event"),
		};

		*node_a.network_chan_count.borrow_mut() += 1;

		((*announcement).clone(), (*as_update).clone(), (*bs_update).clone(), channel_id, tx)
	}

	fn create_announced_chan_between_nodes(nodes: &Vec<Node>, a: usize, b: usize) -> (msgs::ChannelUpdate, msgs::ChannelUpdate, [u8; 32], Transaction) {
		let chan_announcement = create_chan_between_nodes(&nodes[a], &nodes[b]);
		for node in nodes {
			assert!(node.router.handle_channel_announcement(&chan_announcement.0).unwrap());
			node.router.handle_channel_update(&chan_announcement.1).unwrap();
			node.router.handle_channel_update(&chan_announcement.2).unwrap();
		}
		(chan_announcement.1, chan_announcement.2, chan_announcement.3, chan_announcement.4)
	}

	fn close_channel(outbound_node: &Node, inbound_node: &Node, channel_id: &[u8; 32], funding_tx: Transaction, close_inbound_first: bool) -> (msgs::ChannelUpdate, msgs::ChannelUpdate) {
		let (node_a, broadcaster_a) = if close_inbound_first { (&inbound_node.node, &inbound_node.tx_broadcaster) } else { (&outbound_node.node, &outbound_node.tx_broadcaster) };
		let (node_b, broadcaster_b) = if close_inbound_first { (&outbound_node.node, &outbound_node.tx_broadcaster) } else { (&inbound_node.node, &inbound_node.tx_broadcaster) };
		let (tx_a, tx_b);

		node_a.close_channel(channel_id).unwrap();
		let events_1 = node_a.get_and_clear_pending_events();
		assert_eq!(events_1.len(), 1);
		let shutdown_a = match events_1[0] {
			Event::SendShutdown { ref node_id, ref msg } => {
				assert_eq!(node_id, &node_b.get_our_node_id());
				msg.clone()
			},
			_ => panic!("Unexpected event"),
		};

		let (shutdown_b, mut closing_signed_b) = node_b.handle_shutdown(&node_a.get_our_node_id(), &shutdown_a).unwrap();
		if !close_inbound_first {
			assert!(closing_signed_b.is_none());
		}
		let (empty_a, mut closing_signed_a) = node_a.handle_shutdown(&node_b.get_our_node_id(), &shutdown_b.unwrap()).unwrap();
		assert!(empty_a.is_none());
		if close_inbound_first {
			assert!(closing_signed_a.is_none());
			closing_signed_a = node_a.handle_closing_signed(&node_b.get_our_node_id(), &closing_signed_b.unwrap()).unwrap();
			assert_eq!(broadcaster_a.txn_broadcasted.lock().unwrap().len(), 1);
			tx_a = broadcaster_a.txn_broadcasted.lock().unwrap().remove(0);

			let empty_b = node_b.handle_closing_signed(&node_a.get_our_node_id(), &closing_signed_a.unwrap()).unwrap();
			assert!(empty_b.is_none());
			assert_eq!(broadcaster_b.txn_broadcasted.lock().unwrap().len(), 1);
			tx_b = broadcaster_b.txn_broadcasted.lock().unwrap().remove(0);
		} else {
			closing_signed_b = node_b.handle_closing_signed(&node_a.get_our_node_id(), &closing_signed_a.unwrap()).unwrap();
			assert_eq!(broadcaster_b.txn_broadcasted.lock().unwrap().len(), 1);
			tx_b = broadcaster_b.txn_broadcasted.lock().unwrap().remove(0);

			let empty_a2 = node_a.handle_closing_signed(&node_b.get_our_node_id(), &closing_signed_b.unwrap()).unwrap();
			assert!(empty_a2.is_none());
			assert_eq!(broadcaster_a.txn_broadcasted.lock().unwrap().len(), 1);
			tx_a = broadcaster_a.txn_broadcasted.lock().unwrap().remove(0);
		}
		assert_eq!(tx_a, tx_b);
		let mut funding_tx_map = HashMap::new();
		funding_tx_map.insert(funding_tx.txid(), funding_tx);
		tx_a.verify(&funding_tx_map).unwrap();

		let events_2 = node_a.get_and_clear_pending_events();
		assert_eq!(events_2.len(), 1);
		let as_update = match events_2[0] {
			Event::BroadcastChannelUpdate { ref msg } => {
				msg.clone()
			},
			_ => panic!("Unexpected event"),
		};

		let events_3 = node_b.get_and_clear_pending_events();
		assert_eq!(events_3.len(), 1);
		let bs_update = match events_3[0] {
			Event::BroadcastChannelUpdate { ref msg } => {
				msg.clone()
			},
			_ => panic!("Unexpected event"),
		};

		(as_update, bs_update)
	}

	struct SendEvent {
		node_id: PublicKey,
		msgs: Vec<msgs::UpdateAddHTLC>,
		commitment_msg: msgs::CommitmentSigned,
	}
	impl SendEvent {
		fn from_event(event: Event) -> SendEvent {
			match event {
				Event::UpdateHTLCs { node_id, updates: msgs::CommitmentUpdate { update_add_htlcs, update_fulfill_htlcs, update_fail_htlcs, update_fail_malformed_htlcs, commitment_signed } } => {
					assert!(update_fulfill_htlcs.is_empty());
					assert!(update_fail_htlcs.is_empty());
					assert!(update_fail_malformed_htlcs.is_empty());
					SendEvent { node_id: node_id, msgs: update_add_htlcs, commitment_msg: commitment_signed }
				},
				_ => panic!("Unexpected event type!"),
			}
		}
	}

	fn send_along_route(origin_node: &Node, route: Route, expected_route: &[&Node], recv_value: u64) -> ([u8; 32], [u8; 32]) {
		let our_payment_preimage = [*origin_node.network_payment_count.borrow(); 32];
		*origin_node.network_payment_count.borrow_mut() += 1;
		let our_payment_hash = {
			let mut sha = Sha256::new();
			sha.input(&our_payment_preimage[..]);
			let mut ret = [0; 32];
			sha.result(&mut ret);
			ret
		};

		let mut payment_event = {
			origin_node.node.send_payment(route, our_payment_hash).unwrap();
			{
				let mut added_monitors = origin_node.chan_monitor.added_monitors.lock().unwrap();
				assert_eq!(added_monitors.len(), 1);
				added_monitors.clear();
			}

			let mut events = origin_node.node.get_and_clear_pending_events();
			assert_eq!(events.len(), 1);
			SendEvent::from_event(events.remove(0))
		};
		let mut prev_node = origin_node;

		for (idx, &node) in expected_route.iter().enumerate() {
			assert_eq!(node.node.get_our_node_id(), payment_event.node_id);

			node.node.handle_update_add_htlc(&prev_node.node.get_our_node_id(), &payment_event.msgs[0]).unwrap();
			{
				let added_monitors = node.chan_monitor.added_monitors.lock().unwrap();
				assert_eq!(added_monitors.len(), 0);
			}

			let revoke_and_ack = node.node.handle_commitment_signed(&prev_node.node.get_our_node_id(), &payment_event.commitment_msg).unwrap();
			{
				let mut added_monitors = node.chan_monitor.added_monitors.lock().unwrap();
				assert_eq!(added_monitors.len(), 1);
				added_monitors.clear();
			}
			assert!(prev_node.node.handle_revoke_and_ack(&node.node.get_our_node_id(), &revoke_and_ack.0).unwrap().is_none());
			let prev_revoke_and_ack = prev_node.node.handle_commitment_signed(&node.node.get_our_node_id(), &revoke_and_ack.1.unwrap()).unwrap();
			{
				let mut added_monitors = prev_node.chan_monitor.added_monitors.lock().unwrap();
				assert_eq!(added_monitors.len(), 2);
				added_monitors.clear();
			}
			assert!(node.node.handle_revoke_and_ack(&prev_node.node.get_our_node_id(), &prev_revoke_and_ack.0).unwrap().is_none());
			assert!(prev_revoke_and_ack.1.is_none());
			{
				let mut added_monitors = node.chan_monitor.added_monitors.lock().unwrap();
				assert_eq!(added_monitors.len(), 1);
				added_monitors.clear();
			}

			let events_1 = node.node.get_and_clear_pending_events();
			assert_eq!(events_1.len(), 1);
			match events_1[0] {
				Event::PendingHTLCsForwardable { .. } => { },
				_ => panic!("Unexpected event"),
			};

			node.node.channel_state.lock().unwrap().next_forward = Instant::now();
			node.node.process_pending_htlc_forwards();

			let mut events_2 = node.node.get_and_clear_pending_events();
			assert_eq!(events_2.len(), 1);
			if idx == expected_route.len() - 1 {
				match events_2[0] {
					Event::PaymentReceived { ref payment_hash, amt } => {
						assert_eq!(our_payment_hash, *payment_hash);
						assert_eq!(amt, recv_value);
					},
					_ => panic!("Unexpected event"),
				}
			} else {
				{
					let mut added_monitors = node.chan_monitor.added_monitors.lock().unwrap();
					assert_eq!(added_monitors.len(), 1);
					added_monitors.clear();
				}
				payment_event = SendEvent::from_event(events_2.remove(0));
				assert_eq!(payment_event.msgs.len(), 1);
			}

			prev_node = node;
		}

		(our_payment_preimage, our_payment_hash)
	}

	fn claim_payment(origin_node: &Node, expected_route: &[&Node], our_payment_preimage: [u8; 32]) {
		assert!(expected_route.last().unwrap().node.claim_funds(our_payment_preimage));
		{
			let mut added_monitors = expected_route.last().unwrap().chan_monitor.added_monitors.lock().unwrap();
			assert_eq!(added_monitors.len(), 1);
			added_monitors.clear();
		}

		let mut next_msgs: Option<(msgs::UpdateFulfillHTLC, msgs::CommitmentSigned)> = None;
		macro_rules! update_fulfill_dance {
			($node: expr, $prev_node: expr, $last_node: expr) => {
				{
					$node.node.handle_update_fulfill_htlc(&$prev_node.node.get_our_node_id(), &next_msgs.as_ref().unwrap().0).unwrap();
					{
						let mut added_monitors = $node.chan_monitor.added_monitors.lock().unwrap();
						if $last_node {
							assert_eq!(added_monitors.len(), 0);
						} else {
							assert_eq!(added_monitors.len(), 1);
						}
						added_monitors.clear();
					}
					let revoke_and_commit = $node.node.handle_commitment_signed(&$prev_node.node.get_our_node_id(), &next_msgs.as_ref().unwrap().1).unwrap();
					{
						let mut added_monitors = $node.chan_monitor.added_monitors.lock().unwrap();
						assert_eq!(added_monitors.len(), 1);
						added_monitors.clear();
					}
					assert!($prev_node.node.handle_revoke_and_ack(&$node.node.get_our_node_id(), &revoke_and_commit.0).unwrap().is_none());
					let revoke_and_ack = $prev_node.node.handle_commitment_signed(&$node.node.get_our_node_id(), &revoke_and_commit.1.unwrap()).unwrap();
					assert!(revoke_and_ack.1.is_none());
					{
						let mut added_monitors = $prev_node.chan_monitor.added_monitors.lock().unwrap();
						assert_eq!(added_monitors.len(), 2);
						added_monitors.clear();
					}
					assert!($node.node.handle_revoke_and_ack(&$prev_node.node.get_our_node_id(), &revoke_and_ack.0).unwrap().is_none());
					{
						let mut added_monitors = $node.chan_monitor.added_monitors.lock().unwrap();
						assert_eq!(added_monitors.len(), 1);
						added_monitors.clear();
					}
				}
			}
		}

		let mut expected_next_node = expected_route.last().unwrap().node.get_our_node_id();
		let mut prev_node = expected_route.last().unwrap();
		for node in expected_route.iter().rev() {
			assert_eq!(expected_next_node, node.node.get_our_node_id());
			if next_msgs.is_some() {
				update_fulfill_dance!(node, prev_node, false);
			}

			let events = node.node.get_and_clear_pending_events();
			assert_eq!(events.len(), 1);
			match events[0] {
				Event::UpdateHTLCs { ref node_id, updates: msgs::CommitmentUpdate { ref update_add_htlcs, ref update_fulfill_htlcs, ref update_fail_htlcs, ref update_fail_malformed_htlcs, ref commitment_signed } } => {
					assert!(update_add_htlcs.is_empty());
					assert_eq!(update_fulfill_htlcs.len(), 1);
					assert!(update_fail_htlcs.is_empty());
					assert!(update_fail_malformed_htlcs.is_empty());
					expected_next_node = node_id.clone();
					next_msgs = Some((update_fulfill_htlcs[0].clone(), commitment_signed.clone()));
				},
				_ => panic!("Unexpected event"),
			};

			prev_node = node;
		}

		assert_eq!(expected_next_node, origin_node.node.get_our_node_id());
		update_fulfill_dance!(origin_node, expected_route.first().unwrap(), true);

		let events = origin_node.node.get_and_clear_pending_events();
		assert_eq!(events.len(), 1);
		match events[0] {
			Event::PaymentSent { payment_preimage } => {
				assert_eq!(payment_preimage, our_payment_preimage);
			},
			_ => panic!("Unexpected event"),
		}
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

		let our_payment_preimage = [*origin_node.network_payment_count.borrow(); 32];
		*origin_node.network_payment_count.borrow_mut() += 1;
		let our_payment_hash = {
			let mut sha = Sha256::new();
			sha.input(&our_payment_preimage[..]);
			let mut ret = [0; 32];
			sha.result(&mut ret);
			ret
		};

		let err = origin_node.node.send_payment(route, our_payment_hash).err().unwrap();
		assert_eq!(err.err, "Cannot send value that would put us over our max HTLC value in flight");
	}

	fn send_payment(origin: &Node, expected_route: &[&Node], recv_value: u64) {
		let our_payment_preimage = route_payment(&origin, expected_route, recv_value).0;
		claim_payment(&origin, expected_route, our_payment_preimage);
	}

	fn fail_payment(origin_node: &Node, expected_route: &[&Node], our_payment_hash: [u8; 32]) {
		assert!(expected_route.last().unwrap().node.fail_htlc_backwards(&our_payment_hash));
		{
			let mut added_monitors = expected_route.last().unwrap().chan_monitor.added_monitors.lock().unwrap();
			assert_eq!(added_monitors.len(), 1);
			added_monitors.clear();
		}

		let mut next_msgs: Option<(msgs::UpdateFailHTLC, msgs::CommitmentSigned)> = None;
		macro_rules! update_fail_dance {
			($node: expr, $prev_node: expr, $last_node: expr) => {
				{
					$node.node.handle_update_fail_htlc(&$prev_node.node.get_our_node_id(), &next_msgs.as_ref().unwrap().0).unwrap();
					let revoke_and_commit = $node.node.handle_commitment_signed(&$prev_node.node.get_our_node_id(), &next_msgs.as_ref().unwrap().1).unwrap();

					{
						let mut added_monitors = $node.chan_monitor.added_monitors.lock().unwrap();
						assert_eq!(added_monitors.len(), 1);
						added_monitors.clear();
					}
					assert!($prev_node.node.handle_revoke_and_ack(&$node.node.get_our_node_id(), &revoke_and_commit.0).unwrap().is_none());
					{
						let mut added_monitors = $prev_node.chan_monitor.added_monitors.lock().unwrap();
						assert_eq!(added_monitors.len(), 1);
						added_monitors.clear();
					}
					let revoke_and_ack = $prev_node.node.handle_commitment_signed(&$node.node.get_our_node_id(), &revoke_and_commit.1.unwrap()).unwrap();
					{
						let mut added_monitors = $prev_node.chan_monitor.added_monitors.lock().unwrap();
						assert_eq!(added_monitors.len(), 1);
						added_monitors.clear();
					}
					assert!(revoke_and_ack.1.is_none());
					assert!($node.node.get_and_clear_pending_events().is_empty());
					assert!($node.node.handle_revoke_and_ack(&$prev_node.node.get_our_node_id(), &revoke_and_ack.0).unwrap().is_none());
					{
						let mut added_monitors = $node.chan_monitor.added_monitors.lock().unwrap();
						if $last_node {
							assert_eq!(added_monitors.len(), 1);
						} else {
							assert_eq!(added_monitors.len(), 2);
							assert!(added_monitors[0].0 != added_monitors[1].0);
						}
						added_monitors.clear();
					}
				}
			}
		}

		let mut expected_next_node = expected_route.last().unwrap().node.get_our_node_id();
		let mut prev_node = expected_route.last().unwrap();
		for node in expected_route.iter().rev() {
			assert_eq!(expected_next_node, node.node.get_our_node_id());
			if next_msgs.is_some() {
				update_fail_dance!(node, prev_node, false);
			}

			let events = node.node.get_and_clear_pending_events();
			assert_eq!(events.len(), 1);
			match events[0] {
				Event::UpdateHTLCs { ref node_id, updates: msgs::CommitmentUpdate { ref update_add_htlcs, ref update_fulfill_htlcs, ref update_fail_htlcs, ref update_fail_malformed_htlcs, ref commitment_signed } } => {
					assert!(update_add_htlcs.is_empty());
					assert!(update_fulfill_htlcs.is_empty());
					assert_eq!(update_fail_htlcs.len(), 1);
					assert!(update_fail_malformed_htlcs.is_empty());
					expected_next_node = node_id.clone();
					next_msgs = Some((update_fail_htlcs[0].clone(), commitment_signed.clone()));
				},
				_ => panic!("Unexpected event"),
			};

			prev_node = node;
		}

		assert_eq!(expected_next_node, origin_node.node.get_our_node_id());
		update_fail_dance!(origin_node, expected_route.first().unwrap(), true);

		let events = origin_node.node.get_and_clear_pending_events();
		assert_eq!(events.len(), 1);
		match events[0] {
			Event::PaymentFailed { payment_hash } => {
				assert_eq!(payment_hash, our_payment_hash);
			},
			_ => panic!("Unexpected event"),
		}
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
			let chan_monitor = Arc::new(test_utils::TestChannelMonitor::new(chain_monitor.clone(), tx_broadcaster.clone()));
			let node_id = {
				let mut key_slice = [0; 32];
				rng.fill_bytes(&mut key_slice);
				SecretKey::from_slice(&secp_ctx, &key_slice).unwrap()
			};
			let node = ChannelManager::new(node_id.clone(), 0, true, Network::Testnet, feeest.clone(), chan_monitor.clone(), chain_monitor.clone(), tx_broadcaster.clone(), Arc::clone(&logger)).unwrap();
			let router = Router::new(PublicKey::from_secret_key(&secp_ctx, &node_id), chain_monitor.clone(), Arc::clone(&logger));
			nodes.push(Node { chain_monitor, tx_broadcaster, chan_monitor, node, router,
				network_payment_count: payment_count.clone(),
				network_chan_count: chan_count.clone(),
			});
		}

		nodes
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

		// Check that we processed all pending events
		for node in nodes {
			assert_eq!(node.node.get_and_clear_pending_events().len(), 0);
			assert_eq!(node.chan_monitor.added_monitors.lock().unwrap().len(), 0);
		}
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
	#[derive(PartialEq)]
	enum PenaltyType { NONE, HTLC }
	fn test_txn_broadcast(node: &Node, chan: &(msgs::ChannelUpdate, msgs::ChannelUpdate, [u8; 32], Transaction), commitment_tx: Option<Transaction>, revoked_tx: Option<Transaction>, has_htlc_tx: HTLCType, has_penalty_tx: PenaltyType) -> Vec<Transaction> {
		let mut node_txn = node.tx_broadcaster.txn_broadcasted.lock().unwrap();
		assert!(node_txn.len() >= if has_htlc_tx == HTLCType::NONE { 0 } else { 1 } + if has_penalty_tx == PenaltyType::NONE { 0 } else { 1 });

		let mut res = Vec::with_capacity(2);

		if let Some(explicit_tx) = commitment_tx {
			res.push(explicit_tx.clone());
		} else {
			for tx in node_txn.iter() {
				if tx.input.len() == 1 && tx.input[0].previous_output.txid == chan.3.txid() {
					let mut funding_tx_map = HashMap::new();
					funding_tx_map.insert(chan.3.txid(), chan.3.clone());
					tx.verify(&funding_tx_map).unwrap();
					res.push(tx.clone());
				}
			}
		}
		if !revoked_tx.is_some() && !(has_penalty_tx == PenaltyType::HTLC) {
			assert_eq!(res.len(), 1);
		}

		if has_htlc_tx != HTLCType::NONE {
			for tx in node_txn.iter() {
				if tx.input.len() == 1 && tx.input[0].previous_output.txid == res[0].txid() {
					let mut funding_tx_map = HashMap::new();
					funding_tx_map.insert(res[0].txid(), res[0].clone());
					tx.verify(&funding_tx_map).unwrap();
					if has_htlc_tx == HTLCType::TIMEOUT {
						assert!(tx.lock_time != 0);
					} else {
						assert!(tx.lock_time == 0);
					}
					res.push(tx.clone());
					break;
				}
			}
			assert_eq!(res.len(), 2);
		}

		if has_penalty_tx == PenaltyType::HTLC {
			let revoked_tx = revoked_tx.unwrap();
			for tx in node_txn.iter() {
				if tx.input.len() == 1 && tx.input[0].previous_output.txid == revoked_tx.txid() {
					let mut funding_tx_map = HashMap::new();
					funding_tx_map.insert(revoked_tx.txid(), revoked_tx.clone());
					tx.verify(&funding_tx_map).unwrap();
					res.push(tx.clone());
					break;
				}
			}
			assert_eq!(res.len(), 1);
		}
		node_txn.clear();
		res
	}

	fn check_preimage_claim(node: &Node, prev_txn: &Vec<Transaction>) -> Vec<Transaction> {
		let mut node_txn = node.tx_broadcaster.txn_broadcasted.lock().unwrap();

		assert!(node_txn.len() >= 1);
		assert_eq!(node_txn[0].input.len(), 1);
		let mut found_prev = false;

		for tx in prev_txn {
			if node_txn[0].input[0].previous_output.txid == tx.txid() {
				let mut funding_tx_map = HashMap::new();
				funding_tx_map.insert(tx.txid(), tx.clone());
				node_txn[0].verify(&funding_tx_map).unwrap();

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
		let events_1 = nodes[a].node.get_and_clear_pending_events();
		assert_eq!(events_1.len(), 1);
		let as_update = match events_1[0] {
			Event::BroadcastChannelUpdate { ref msg } => {
				msg.clone()
			},
			_ => panic!("Unexpected event"),
		};

		let events_2 = nodes[b].node.get_and_clear_pending_events();
		assert_eq!(events_2.len(), 1);
		let bs_update = match events_2[0] {
			Event::BroadcastChannelUpdate { ref msg } => {
				msg.clone()
			},
			_ => panic!("Unexpected event"),
		};

		for node in nodes {
			node.router.handle_channel_update(&as_update).unwrap();
			node.router.handle_channel_update(&bs_update).unwrap();
		}
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
			let mut node_txn = test_txn_broadcast(&nodes[1], &chan_1, None, None, HTLCType::NONE, PenaltyType::NONE);
			let header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
			nodes[0].chain_monitor.block_connected_with_filtering(&Block { header, txdata: vec![node_txn.drain(..).next().unwrap()] }, 1);
			test_txn_broadcast(&nodes[0], &chan_1, None, None, HTLCType::NONE, PenaltyType::NONE);
		}
		get_announce_close_broadcast_events(&nodes, 0, 1);
		assert_eq!(nodes[0].node.list_channels().len(), 0);
		assert_eq!(nodes[1].node.list_channels().len(), 1);

		// One pending HTLC is discarded by the force-close:
		let payment_preimage_1 = route_payment(&nodes[1], &vec!(&nodes[2], &nodes[3])[..], 3000000).0;

		// Simple case of one pending HTLC to HTLC-Timeout
		nodes[1].node.peer_disconnected(&nodes[2].node.get_our_node_id(), true);
		{
			let mut node_txn = test_txn_broadcast(&nodes[1], &chan_2, None, None, HTLCType::TIMEOUT, PenaltyType::NONE);
			let header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
			nodes[2].chain_monitor.block_connected_with_filtering(&Block { header, txdata: vec![node_txn.drain(..).next().unwrap()] }, 1);
			test_txn_broadcast(&nodes[2], &chan_2, None, None, HTLCType::NONE, PenaltyType::NONE);
		}
		get_announce_close_broadcast_events(&nodes, 1, 2);
		assert_eq!(nodes[1].node.list_channels().len(), 0);
		assert_eq!(nodes[2].node.list_channels().len(), 1);

		macro_rules! claim_funds {
			($node: expr, $prev_node: expr, $preimage: expr) => {
				{
					assert!($node.node.claim_funds($preimage));
					{
						let mut added_monitors = $node.chan_monitor.added_monitors.lock().unwrap();
						assert_eq!(added_monitors.len(), 1);
						added_monitors.clear();
					}

					let events = $node.node.get_and_clear_pending_events();
					assert_eq!(events.len(), 1);
					match events[0] {
						Event::UpdateHTLCs { ref node_id, updates: msgs::CommitmentUpdate { ref update_add_htlcs, ref update_fail_htlcs, .. } } => {
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
			let node_txn = test_txn_broadcast(&nodes[2], &chan_3, None, None, HTLCType::TIMEOUT, PenaltyType::NONE);

			// Claim the payment on nodes[3], giving it knowledge of the preimage
			claim_funds!(nodes[3], nodes[2], payment_preimage_1);

			let header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
			nodes[3].chain_monitor.block_connected_with_filtering(&Block { header, txdata: vec![node_txn[0].clone()] }, 1);

			check_preimage_claim(&nodes[3], &node_txn);
		}
		get_announce_close_broadcast_events(&nodes, 2, 3);
		assert_eq!(nodes[2].node.list_channels().len(), 0);
		assert_eq!(nodes[3].node.list_channels().len(), 1);

		// One pending HTLC to time out:
		let payment_preimage_2 = route_payment(&nodes[3], &vec!(&nodes[4])[..], 3000000).0;

		{
			let mut header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
			nodes[3].chain_monitor.block_connected_checked(&header, 1, &Vec::new()[..], &[0; 0]);
			for i in 2..TEST_FINAL_CLTV - 3 {
				header = BlockHeader { version: 0x20000000, prev_blockhash: header.bitcoin_hash(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
				nodes[3].chain_monitor.block_connected_checked(&header, i, &Vec::new()[..], &[0; 0]);
			}

			let node_txn = test_txn_broadcast(&nodes[3], &chan_4, None, None, HTLCType::TIMEOUT, PenaltyType::NONE);

			// Claim the payment on nodes[4], giving it knowledge of the preimage
			claim_funds!(nodes[4], nodes[3], payment_preimage_2);

			header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
			nodes[4].chain_monitor.block_connected_checked(&header, 1, &Vec::new()[..], &[0; 0]);
			for i in 2..TEST_FINAL_CLTV - 3 {
				header = BlockHeader { version: 0x20000000, prev_blockhash: header.bitcoin_hash(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
				nodes[4].chain_monitor.block_connected_checked(&header, i, &Vec::new()[..], &[0; 0]);
			}

			test_txn_broadcast(&nodes[4], &chan_4, None, None, HTLCType::SUCCESS, PenaltyType::NONE);

			header = BlockHeader { version: 0x20000000, prev_blockhash: header.bitcoin_hash(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
			nodes[4].chain_monitor.block_connected_with_filtering(&Block { header, txdata: vec![node_txn[0].clone()] }, TEST_FINAL_CLTV - 5);

			check_preimage_claim(&nodes[4], &node_txn);
		}
		get_announce_close_broadcast_events(&nodes, 3, 4);
		assert_eq!(nodes[3].node.list_channels().len(), 0);
		assert_eq!(nodes[4].node.list_channels().len(), 0);

		// Create some new channels:
		let chan_5 = create_announced_chan_between_nodes(&nodes, 0, 1);

		// A pending HTLC which will be revoked:
		let payment_preimage_3 = route_payment(&nodes[0], &vec!(&nodes[1])[..], 3000000).0;
		// Get the will-be-revoked local txn from nodes[0]
		let revoked_local_txn = nodes[0].node.channel_state.lock().unwrap().by_id.iter().next().unwrap().1.last_local_commitment_txn.clone();
		// Revoke the old state
		claim_payment(&nodes[0], &vec!(&nodes[1])[..], payment_preimage_3);

		{
			let mut header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
			nodes[1].chain_monitor.block_connected_with_filtering(&Block { header, txdata: vec![revoked_local_txn[0].clone()] }, 1);
			{
				let mut node_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap();
				assert_eq!(node_txn.len(), 3);
				assert_eq!(node_txn.pop().unwrap(), node_txn[0]); // An outpoint registration will result in a 2nd block_connected
				assert_eq!(node_txn[0].input.len(), 1);

				let mut funding_tx_map = HashMap::new();
				funding_tx_map.insert(revoked_local_txn[0].txid(), revoked_local_txn[0].clone());
				node_txn[0].verify(&funding_tx_map).unwrap();
				node_txn.swap_remove(0);
			}
			test_txn_broadcast(&nodes[1], &chan_5, None, None, HTLCType::NONE, PenaltyType::NONE);

			nodes[0].chain_monitor.block_connected_with_filtering(&Block { header, txdata: vec![revoked_local_txn[0].clone()] }, 1);
			let node_txn = test_txn_broadcast(&nodes[0], &chan_5, Some(revoked_local_txn[0].clone()), None, HTLCType::TIMEOUT, PenaltyType::NONE);
			header = BlockHeader { version: 0x20000000, prev_blockhash: header.bitcoin_hash(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
			nodes[1].chain_monitor.block_connected_with_filtering(&Block { header, txdata: vec![node_txn[1].clone()] }, 1);
			test_txn_broadcast(&nodes[1], &chan_5, None, Some(node_txn[1].clone()), HTLCType::NONE, PenaltyType::HTLC);
		}
		get_announce_close_broadcast_events(&nodes, 0, 1);
		assert_eq!(nodes[0].node.list_channels().len(), 0);
		assert_eq!(nodes[1].node.list_channels().len(), 0);

		// Check that we processed all pending events
		for node in nodes {
			assert_eq!(node.node.get_and_clear_pending_events().len(), 0);
			assert_eq!(node.chan_monitor.added_monitors.lock().unwrap().len(), 0);
		}
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
		let channel_state = nodes[0].node.channel_state.lock().unwrap();
		assert_eq!(channel_state.by_id.len(), 0);
		assert_eq!(channel_state.short_to_id.len(), 0);
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

		let _ = nodes[0].router.handle_htlc_fail_channel_update(&msgs::HTLCFailChannelUpdate::ChannelClosed { short_channel_id : as_chan.get_short_channel_id().unwrap() } );

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
		let _ = nodes[0].router.handle_htlc_fail_channel_update(&msgs::HTLCFailChannelUpdate::ChannelClosed { short_channel_id : as_chan.get_short_channel_id().unwrap() } );

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
}
