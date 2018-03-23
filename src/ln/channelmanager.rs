use bitcoin::blockdata::block::BlockHeader;
use bitcoin::blockdata::transaction::Transaction;
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::network::constants::Network;
use bitcoin::network::serialize::BitcoinHash;
use bitcoin::util::hash::Sha256dHash;
use bitcoin::util::uint::Uint256;

use secp256k1::key::{SecretKey,PublicKey};
use secp256k1::{Secp256k1,Message};
use secp256k1::ecdh::SharedSecret;
use secp256k1;

use chain::chaininterface::{ChainListener,ChainWatchInterface,FeeEstimator};
use ln::channel::Channel;
use ln::channelmonitor::ManyChannelMonitor;
use ln::router::Route;
use ln::msgs;
use ln::msgs::{HandleError,ChannelMessageHandler,MsgEncodable,MsgDecodable};
use util::{byte_utils, events, internal_traits, rng};
use util::sha2::Sha256;

use crypto::mac::{Mac,MacResult};
use crypto::hmac::Hmac;
use crypto::digest::Digest;
use crypto::symmetriccipher::SynchronousStreamCipher;
use crypto::chacha20::ChaCha20;

use std::sync::{Mutex,MutexGuard,Arc};
use std::collections::HashMap;
use std::collections::hash_map;
use std::{ptr, mem};
use std::time::{Instant,Duration};

/// Stores the info we will need to send when we want to forward an HTLC onwards
pub struct PendingForwardHTLCInfo {
	onion_packet: Option<msgs::OnionPacket>,
	payment_hash: [u8; 32],
	short_channel_id: u64,
	prev_short_channel_id: u64,
	amt_to_forward: u64,
	outgoing_cltv_value: u32,
}
//TODO: This is public, and needed to call Channel::update_add_htlc, so there needs to be a way to
//initialize it usefully...probably make it optional in Channel instead).
impl PendingForwardHTLCInfo {
	pub fn dummy() -> Self {
		Self {
			onion_packet: None,
			payment_hash: [0; 32],
			short_channel_id: 0,
			prev_short_channel_id: 0,
			amt_to_forward: 0,
			outgoing_cltv_value: 0,
		}
	}
}

enum PendingOutboundHTLC {
	IntermediaryHopData {
		source_short_channel_id: u64,
		incoming_packet_shared_secret: SharedSecret,
	},
	OutboundRoute {
		route: Route,
	},
	/// Used for channel rebalancing
	CycledRoute {
		source_short_channel_id: u64,
		incoming_packet_shared_secret: SharedSecret,
		route: Route,
	}
}

enum HTLCFailReason<'a> {
	ErrorPacket {
		err: &'a msgs::OnionErrorPacket,
	},
	Reason {
		failure_code: u16,
	}
}

/// We hold back HTLCs we intend to relay for a random interval in the range (this, 5*this). This
/// provides some limited amount of privacy. Ideally this would range from somewhere like 1 second
/// to 30 seconds, but people expect lightning to be, you know, kinda fast, sadly. We could
/// probably increase this significantly.
const MIN_HTLC_RELAY_HOLDING_CELL_MILLIS: u32 = 50;

struct ChannelHolder {
	by_id: HashMap<Uint256, Channel>,
	short_to_id: HashMap<u64, Uint256>,
	next_forward: Instant,
	/// short channel id -> forward infos. Key of 0 means payments received
	forward_htlcs: HashMap<u64, Vec<PendingForwardHTLCInfo>>,
	claimable_htlcs: HashMap<[u8; 32], PendingOutboundHTLC>,
}
struct MutChannelHolder<'a> {
	by_id: &'a mut HashMap<Uint256, Channel>,
	short_to_id: &'a mut HashMap<u64, Uint256>,
	next_forward: &'a mut Instant,
	/// short channel id -> forward infos. Key of 0 means payments received
	forward_htlcs: &'a mut HashMap<u64, Vec<PendingForwardHTLCInfo>>,
	claimable_htlcs: &'a mut HashMap<[u8; 32], PendingOutboundHTLC>,
}
impl ChannelHolder {
	fn borrow_parts(&mut self) -> MutChannelHolder {
		MutChannelHolder {
			by_id: &mut self.by_id,
			short_to_id: &mut self.short_to_id,
			next_forward: &mut self.next_forward,
			/// short channel id -> forward infos. Key of 0 means payments received
			forward_htlcs: &mut self.forward_htlcs,
			claimable_htlcs: &mut self.claimable_htlcs,
		}
	}
}

/// Manager which keeps track of a number of channels and sends messages to the appropriate
/// channel, also tracking HTLC preimages and forwarding onion packets appropriately.
/// Implements ChannelMessageHandler, handling the multi-channel parts and passing things through
/// to individual Channels.
pub struct ChannelManager {
	genesis_hash: Sha256dHash,
	fee_estimator: Arc<FeeEstimator>,
	monitor: Arc<ManyChannelMonitor>,
	chain_monitor: Arc<ChainWatchInterface>,

	announce_channels_publicly: bool,
	fee_proportional_millionths: u32,
	secp_ctx: Secp256k1,

	channel_state: Mutex<ChannelHolder>,
	our_network_key: SecretKey,

	pending_events: Mutex<Vec<events::Event>>,
}

const CLTV_EXPIRY_DELTA: u16 = 6 * 24 * 2; //TODO?

macro_rules! secp_call {
	( $res : expr ) => {
		match $res {
			Ok(key) => key,
			//TODO: Make the err a parameter!
			Err(_) => return Err(HandleError{err: "Key error", msg: None})
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

impl ChannelManager {
	/// Constructs a new ChannelManager to hold several channels and route between them. This is
	/// the main "logic hub" for all channel-related actions, and implements ChannelMessageHandler.
	/// fee_proportional_millionths is an optional fee to charge any payments routed through us.
	/// Non-proportional fees are fixed according to our risk using the provided fee estimator.
	/// panics if channel_value_satoshis is >= (1 << 24)!
	pub fn new(our_network_key: SecretKey, fee_proportional_millionths: u32, announce_channels_publicly: bool, network: Network, feeest: Arc<FeeEstimator>, monitor: Arc<ManyChannelMonitor>, chain_monitor: Arc<ChainWatchInterface>) -> Result<Arc<ChannelManager>, secp256k1::Error> {
		let secp_ctx = Secp256k1::new();

		let res = Arc::new(ChannelManager {
			genesis_hash: genesis_block(network).header.bitcoin_hash(),
			fee_estimator: feeest.clone(),
			monitor: monitor.clone(),
			chain_monitor: chain_monitor,

			announce_channels_publicly: announce_channels_publicly,
			fee_proportional_millionths: fee_proportional_millionths,
			secp_ctx: secp_ctx,

			channel_state: Mutex::new(ChannelHolder{
				by_id: HashMap::new(),
				short_to_id: HashMap::new(),
				next_forward: Instant::now(),
				forward_htlcs: HashMap::new(),
				claimable_htlcs: HashMap::new(),
			}),
			our_network_key: our_network_key,

			pending_events: Mutex::new(Vec::new()),
		});
		let weak_res = Arc::downgrade(&res);
		res.chain_monitor.register_listener(weak_res);
		Ok(res)
	}

	pub fn create_channel(&self, their_network_key: PublicKey, channel_value_satoshis: u64, user_id: u64) -> Result<msgs::OpenChannel, HandleError> {
		let channel = Channel::new_outbound(&*self.fee_estimator, their_network_key, channel_value_satoshis, self.announce_channels_publicly, user_id);
		let res = channel.get_open_channel(self.genesis_hash.clone(), &*self.fee_estimator)?;
		let mut channel_state = self.channel_state.lock().unwrap();
		match channel_state.by_id.insert(channel.channel_id(), channel) {
			Some(_) => panic!("RNG is bad???"),
			None => Ok(res)
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

	fn gen_ammag_from_shared_secret(shared_secret: &SharedSecret) -> [u8; 32] {
		let mut hmac = Hmac::new(Sha256::new(), &[0x61, 0x6d, 0x6d, 0x61, 0x67]); // ammag
		hmac.input(&shared_secret[..]);
		let mut res = [0; 32];
		hmac.raw_result(&mut res);
		res
	}

	fn construct_onion_keys(secp_ctx: &Secp256k1, route: &Route, session_priv: &SecretKey) -> Result<Vec<OnionKeys>, HandleError> {
		let mut res = Vec::with_capacity(route.hops.len());
		let mut blinded_priv = session_priv.clone();
		let mut blinded_pub = secp_call!(PublicKey::from_secret_key(secp_ctx, &blinded_priv));
		let mut first_iteration = true;

		for hop in route.hops.iter() {
			let shared_secret = SharedSecret::new(secp_ctx, &hop.pubkey, &blinded_priv);

			let mut sha = Sha256::new();
			sha.input(&blinded_pub.serialize()[..]);
			sha.input(&shared_secret[..]);
			let mut blinding_factor = [0u8; 32];
			sha.result(&mut blinding_factor);

			if first_iteration {
				blinded_pub = secp_call!(PublicKey::from_secret_key(secp_ctx, &blinded_priv));
				first_iteration = false;
			}
			let ephemeral_pubkey = blinded_pub;

			secp_call!(blinded_priv.mul_assign(secp_ctx, &secp_call!(SecretKey::from_slice(secp_ctx, &blinding_factor))));
			blinded_pub = secp_call!(PublicKey::from_secret_key(secp_ctx, &blinded_priv));

			let (rho, mu) = ChannelManager::gen_rho_mu_from_shared_secret(&shared_secret);

			res.push(OnionKeys {
				#[cfg(test)]
				shared_secret: shared_secret,
				#[cfg(test)]
				blinding_factor: blinding_factor,
				ephemeral_pubkey: ephemeral_pubkey,
				rho: rho,
				mu: mu,
			});
		}

		Ok(res)
	}

	/// returns the hop data, as well as the first-hop value_msat and CLTV value we should send.
	fn build_onion_payloads(route: &Route) -> Result<(Vec<msgs::OnionHopData>, u64, u32), HandleError> {
		let mut cur_value_msat = 0u64;
		let mut cur_cltv = 0u32;
		let mut last_short_channel_id = 0;
		let mut res: Vec<msgs::OnionHopData> = Vec::with_capacity(route.hops.len());
		internal_traits::test_no_dealloc::<msgs::OnionHopData>(None);
		unsafe { res.set_len(route.hops.len()); }

		for (idx, hop) in route.hops.iter().enumerate().rev() {
			// First hop gets special values so that it can check, on receipt, that everything is
			// exactly as it should be (and the next hop isn't trying to probe to find out if we're
			// the intended recipient).
			let value_msat = if cur_value_msat == 0 { hop.fee_msat } else { cur_value_msat };
			let cltv = if cur_cltv == 0 { hop.cltv_expiry_delta } else { cur_cltv };
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
				return Err(HandleError{err: "Channel fees overflowed?!", msg: None});
			}
			cur_cltv += hop.cltv_expiry_delta as u32;
			if cur_cltv >= 500000000 {
				return Err(HandleError{err: "Channel CLTV overflowed?!", msg: None});
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
	fn construct_onion_packet(mut payloads: Vec<msgs::OnionHopData>, onion_keys: Vec<OnionKeys>, associated_data: Vec<u8>) -> Result<msgs::OnionPacket, HandleError> {
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
			public_key: onion_keys.first().unwrap().ephemeral_pubkey,
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

	fn build_first_hop_failure_packet(shared_secret: &SharedSecret, failure_type: u16, failure_data: &[u8]) -> msgs::OnionErrorPacket {
		let failure_packet = ChannelManager::build_failure_packet(shared_secret, failure_type, failure_data);
		ChannelManager::encrypt_failure_packet(shared_secret, &failure_packet.encode()[..])
	}

	/// only fails if the channel does not yet have an assigned short_id
	fn get_channel_update(&self, chan: &mut Channel) -> Result<msgs::ChannelUpdate, HandleError> {
		let short_channel_id = match chan.get_short_channel_id() {
			None => return Err(HandleError{err: "Channel not yet established", msg: None}),
			Some(id) => id,
		};

		let were_node_one = PublicKey::from_secret_key(&self.secp_ctx, &self.our_network_key).unwrap().serialize()[..] < chan.get_their_node_id().serialize()[..];

		let unsigned = msgs::UnsignedChannelUpdate {
			chain_hash: self.genesis_hash,
			short_channel_id: short_channel_id,
			timestamp: chan.get_channel_update_count(),
			flags: (!were_node_one) as u16 | ((!chan.is_live() as u16) << 1),
			cltv_expiry_delta: CLTV_EXPIRY_DELTA,
			htlc_minimum_msat: chan.get_our_htlc_minimum_msat(),
			fee_base_msat: chan.get_our_fee_base_msat(&*self.fee_estimator),
			fee_proportional_millionths: self.fee_proportional_millionths,
		};

		let msg_hash = Sha256dHash::from_data(&unsigned.encode()[..]);
		let sig = self.secp_ctx.sign(&Message::from_slice(&msg_hash[..]).unwrap(), &self.our_network_key).unwrap(); //TODO Can we unwrap here?

		Ok(msgs::ChannelUpdate {
			signature: sig,
			contents: unsigned
		})
	}

	/// Sends a payment along a given route, returning the UpdateAddHTLC message to give to the
	/// first hop in route. Value parameters are provided via the last hop in route, see
	/// documentation for RouteHop fields for more info.
	/// See-also docs on Channel::send_htlc_and_commit.
	pub fn send_payment(&self, route: Route, payment_hash: [u8; 32]) -> Result<Option<(msgs::UpdateAddHTLC, msgs::CommitmentSigned)>, HandleError> {
		if route.hops.len() < 1 || route.hops.len() > 20 {
			return Err(HandleError{err: "Route didn't go anywhere/had bogus size", msg: None});
		}
		let our_node_id = self.get_our_node_id();
		for (idx, hop) in route.hops.iter().enumerate() {
			if idx != route.hops.len() - 1 && hop.pubkey == our_node_id {
				return Err(HandleError{err: "Route went through us but wasn't a simple rebalance loop to us", msg: None});
			}
		}

		let session_priv = secp_call!(SecretKey::from_slice(&self.secp_ctx, &{
			let mut session_key = [0; 32];
			rng::fill_bytes(&mut session_key);
			session_key
		}));

		let associated_data = Vec::new(); //TODO: What to put here?

		let onion_keys = ChannelManager::construct_onion_keys(&self.secp_ctx, &route, &session_priv)?;
		let (onion_payloads, htlc_msat, htlc_cltv) = ChannelManager::build_onion_payloads(&route)?;
		let onion_packet = ChannelManager::construct_onion_packet(onion_payloads, onion_keys, associated_data)?;

		let mut channel_state = self.channel_state.lock().unwrap();
		let id = match channel_state.short_to_id.get(&route.hops.first().unwrap().short_channel_id) {
			None => return Err(HandleError{err: "No channel available with first hop!", msg: None}),
			Some(id) => id.clone()
		};
		let res = {
			let chan = channel_state.by_id.get_mut(&id).unwrap();
			if chan.get_their_node_id() != route.hops.first().unwrap().pubkey {
				return Err(HandleError{err: "Node ID mismatch on first hop!", msg: None});
			}
			chan.send_htlc_and_commit(htlc_msat, payment_hash.clone(), htlc_cltv, onion_packet)?
		};

		if channel_state.claimable_htlcs.insert(payment_hash, PendingOutboundHTLC::OutboundRoute {
			route: route,
		}).is_some() {
			// TODO: We need to track these better, we're not generating these, so a
			// third-party might make this happen:
			panic!("payment_hash was repeated! Don't let this happen");
		}

		Ok(res)
	}

	/// Call this upon creation of a funding transaction for the given channel.
	/// Panics if a funding transaction has already been provided for this channel.
	pub fn funding_transaction_generated(&self, temporary_channel_id: &Uint256, funding_txo: (Sha256dHash, u16)) {
		let (chan, msg) = {
			let mut channel_state = self.channel_state.lock().unwrap();
			match channel_state.by_id.remove(&temporary_channel_id) {
				Some(mut chan) => {
					match chan.get_outbound_funding_created(funding_txo.0, funding_txo.1) {
						Ok(funding_msg) => {
							(chan, funding_msg)
						},
						Err(_e) => {
							//TODO: Push e to pendingevents
							return;
						}
					}
				},
				None => return
			}
		}; // Release channel lock for install_watch_outpoint call,
		let chan_monitor = chan.channel_monitor();
		match self.monitor.add_update_monitor(chan_monitor.get_funding_txo().unwrap(), chan_monitor) {
			Ok(()) => {},
			Err(_e) => {
				//TODO: Push e to pendingevents?
				return;
			}
		};

		{
			let mut pending_events = self.pending_events.lock().unwrap();
			pending_events.push(events::Event::SendFundingCreated {
				node_id: chan.get_their_node_id(),
				msg: msg,
			});
		}

		let mut channel_state = self.channel_state.lock().unwrap();
		channel_state.by_id.insert(chan.channel_id(), chan);
	}

	fn get_announcement_sigs(&self, chan: &Channel) -> Result<Option<msgs::AnnouncementSignatures>, HandleError> {
		if !chan.is_usable() { return Ok(None) }

		let (announcement, our_bitcoin_sig) = chan.get_channel_announcement(self.get_our_node_id(), self.genesis_hash.clone())?;
		let msghash = Message::from_slice(&Sha256dHash::from_data(&announcement.encode()[..])[..]).unwrap();
		let our_node_sig = secp_call!(self.secp_ctx.sign(&msghash, &self.our_network_key));

		Ok(Some(msgs::AnnouncementSignatures {
			channel_id: chan.channel_id(),
			short_channel_id: chan.get_short_channel_id().unwrap(),
			node_signature: our_node_sig,
			bitcoin_signature: our_bitcoin_sig,
		}))
	}

	pub fn process_pending_htlc_forward(&self) {
		let mut new_events = Vec::new();
		{
			let mut channel_state_lock = self.channel_state.lock().unwrap();
			let channel_state = channel_state_lock.borrow_parts();

			if Instant::now() < *channel_state.next_forward {
				return;
			}

			for (short_chan_id, pending_forwards) in channel_state.forward_htlcs.drain() {
				if short_chan_id != 0 {
					let forward_chan_id = match channel_state.short_to_id.get(&short_chan_id) {
						Some(chan_id) => chan_id.clone(),
						None => {
							// TODO: Send a failure packet back on each pending_forward
							continue;
						}
					};
					let forward_chan = &mut channel_state.by_id.get_mut(&forward_chan_id).unwrap();

					let mut add_htlc_msgs = Vec::new();
					for forward_info in pending_forwards {
						match forward_chan.send_htlc(forward_info.amt_to_forward, forward_info.payment_hash, forward_info.outgoing_cltv_value, forward_info.onion_packet.unwrap()) {
							Err(_e) => {
								// TODO: Send a failure packet back
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
						let commitment_msg = match forward_chan.send_commitment() {
							Ok(msg) => msg,
							Err(_) => {
								//TODO: Handle...this is bad!
								continue;
							},
						};
						new_events.push(events::Event::SendHTLCs {
							node_id: forward_chan.get_their_node_id(),
							msgs: add_htlc_msgs,
							commitment_msg: commitment_msg,
						});
					}
				} else {
					for forward_info in pending_forwards {
						new_events.push(events::Event::PaymentReceived {
							payment_hash: forward_info.payment_hash,
							amt: forward_info.amt_to_forward,
						});
					}
				}
			}
		}

		if new_events.is_empty() { return }

		let mut events = self.pending_events.lock().unwrap();
		events.reserve(new_events.len());
		for event in new_events.drain(..) {
			events.push(event);
		}
	}

	/// Indicates that the preimage for payment_hash is unknown after a PaymentReceived event.
	pub fn fail_htlc_backwards(&self, payment_hash: &[u8; 32]) -> bool {
		self.fail_htlc_backwards_internal(self.channel_state.lock().unwrap(), payment_hash, HTLCFailReason::Reason { failure_code: 0x4000 | 15 })
	}

	fn fail_htlc_backwards_internal(&self, mut channel_state: MutexGuard<ChannelHolder>, payment_hash: &[u8; 32], onion_error: HTLCFailReason) -> bool {
		let mut pending_htlc = {
			match channel_state.claimable_htlcs.remove(payment_hash) {
				Some(pending_htlc) => pending_htlc,
				None => return false,
			}
		};

		match pending_htlc {
			PendingOutboundHTLC::CycledRoute { source_short_channel_id, incoming_packet_shared_secret, .. } => {
				pending_htlc = PendingOutboundHTLC::IntermediaryHopData { source_short_channel_id, incoming_packet_shared_secret };
			},
			_ => {}
		}

		match pending_htlc {
			PendingOutboundHTLC::CycledRoute { .. } => { panic!("WAT"); },
			PendingOutboundHTLC::OutboundRoute { .. } => {
				//TODO: DECRYPT route from OutboundRoute
				mem::drop(channel_state);
				let mut pending_events = self.pending_events.lock().unwrap();
				pending_events.push(events::Event::PaymentFailed {
					payment_hash: payment_hash.clone()
				});
				false
			},
			PendingOutboundHTLC::IntermediaryHopData { source_short_channel_id, incoming_packet_shared_secret } => {
				let err_packet = match onion_error {
					HTLCFailReason::Reason { failure_code } => {
						let packet = ChannelManager::build_failure_packet(&incoming_packet_shared_secret, failure_code, &[0; 0]).encode();
						ChannelManager::encrypt_failure_packet(&incoming_packet_shared_secret, &packet)
					},
					HTLCFailReason::ErrorPacket { err } => {
						ChannelManager::encrypt_failure_packet(&incoming_packet_shared_secret, &err.data)
					}
				};

				let (node_id, fail_msg) = {
					let chan_id = match channel_state.short_to_id.get(&source_short_channel_id) {
						Some(chan_id) => chan_id.clone(),
						None => return false
					};

					let chan = channel_state.by_id.get_mut(&chan_id).unwrap();
					match chan.get_update_fail_htlc(payment_hash, err_packet) {
						Ok(msg) => (chan.get_their_node_id(), msg),
						Err(_e) => {
							//TODO: Do something with e?
							return false;
						},
					}
				};

				mem::drop(channel_state);
				let mut pending_events = self.pending_events.lock().unwrap();
				pending_events.push(events::Event::SendFailHTLC {
					node_id,
					msg: fail_msg
				});

				true
			},
		}
	}

	/// Provides a payment preimage in response to a PaymentReceived event, returning true and
	/// generating message events for the net layer to claim the payment, if possible. Thus, you
	/// should probably kick the net layer to go send messages if this returns true!
	pub fn claim_funds(&self, payment_preimage: [u8; 32]) -> bool {
		self.claim_funds_internal(payment_preimage, true)
	}
	pub fn claim_funds_internal(&self, payment_preimage: [u8; 32], from_user: bool) -> bool {
		let mut sha = Sha256::new();
		sha.input(&payment_preimage);
		let mut payment_hash = [0; 32];
		sha.result(&mut payment_hash);

		let mut channel_state = self.channel_state.lock().unwrap();
		let mut pending_htlc = {
			match channel_state.claimable_htlcs.remove(&payment_hash) {
				Some(pending_htlc) => pending_htlc,
				None => return false,
			}
		};

		match pending_htlc {
			PendingOutboundHTLC::CycledRoute { source_short_channel_id, incoming_packet_shared_secret, route } => {
				if from_user { // This was the end hop back to us
					pending_htlc = PendingOutboundHTLC::IntermediaryHopData { source_short_channel_id, incoming_packet_shared_secret };
					channel_state.claimable_htlcs.insert(payment_hash, PendingOutboundHTLC::OutboundRoute { route });
				} else { // This came from the first upstream node
					// Bank error in our favor! Maybe we should tell the user this somehow???
					pending_htlc = PendingOutboundHTLC::OutboundRoute { route };
					channel_state.claimable_htlcs.insert(payment_hash, PendingOutboundHTLC::IntermediaryHopData { source_short_channel_id, incoming_packet_shared_secret });
				}
			},
			_ => {},
		}

		match pending_htlc {
			PendingOutboundHTLC::CycledRoute { .. } => { panic!("WAT"); },
			PendingOutboundHTLC::OutboundRoute { .. } => {
				if from_user {
					panic!("Called claim_funds with a preimage for an outgoing payment. There is nothing we can do with this, and something is seriously wrong if you knew this...");
				}
				let mut pending_events = self.pending_events.lock().unwrap();
				pending_events.push(events::Event::PaymentSent {
					payment_preimage
				});
				false
			},
			PendingOutboundHTLC::IntermediaryHopData { source_short_channel_id, .. } => {
				let (node_id, fulfill_msg) = {
					let chan_id = match channel_state.short_to_id.get(&source_short_channel_id) {
						Some(chan_id) => chan_id.clone(),
						None => return false
					};

					let chan = channel_state.by_id.get_mut(&chan_id).unwrap();
					match chan.get_update_fulfill_htlc(payment_preimage) {
						Ok(msg) => (chan.get_their_node_id(), msg),
						Err(_e) => {
							//TODO: Do something with e?
							return false;
						},
					}
				};

				let mut pending_events = self.pending_events.lock().unwrap();
				pending_events.push(events::Event::SendFulfillHTLC {
					node_id: node_id,
					msg: fulfill_msg
				});

				true
			},
		}
	}

	/// Gets the node_id held by this ChannelManager
	pub fn get_our_node_id(&self) -> PublicKey {
		PublicKey::from_secret_key(&self.secp_ctx, &self.our_network_key).unwrap()
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
		let mut new_funding_locked_messages = Vec::new();
		{
			let mut channel_state = self.channel_state.lock().unwrap();
			let mut short_to_ids_to_insert = Vec::new();
			for channel in channel_state.by_id.values_mut() {
				match channel.block_connected(header, height, txn_matched, indexes_of_txn_matched) {
					Some(funding_locked) => {
						let announcement_sigs = match self.get_announcement_sigs(channel) {
							Ok(res) => res,
							Err(_e) => {
								//TODO: push e on events and blow up the channel (it has bad keys)
								continue;
							}
						};
						new_funding_locked_messages.push(events::Event::SendFundingLocked {
							node_id: channel.get_their_node_id(),
							msg: funding_locked,
							announcement_sigs: announcement_sigs
						});
						short_to_ids_to_insert.push((channel.get_short_channel_id().unwrap(), channel.channel_id()));
					},
					None => {}
				}
			}
			for to_insert in short_to_ids_to_insert {
				channel_state.short_to_id.insert(to_insert.0, to_insert.1);
			}
		}
		let mut pending_events = self.pending_events.lock().unwrap();
		for funding_locked in new_funding_locked_messages.drain(..) {
			pending_events.push(funding_locked);
		}
	}

	fn block_disconnected(&self, header: &BlockHeader) {
		let mut channel_state = self.channel_state.lock().unwrap();
		for channel in channel_state.by_id.values_mut() {
			if channel.block_disconnected(header) {
				//TODO Close channel here
			}
		}
	}
}

impl ChannelMessageHandler for ChannelManager {
	//TODO: Handle errors and close channel (or so)
	fn handle_open_channel(&self, their_node_id: &PublicKey, msg: &msgs::OpenChannel) -> Result<msgs::AcceptChannel, HandleError> {
		if msg.chain_hash != self.genesis_hash {
			return Err(HandleError{err: "Unknown genesis block hash", msg: None});
		}
		let mut channel_state = self.channel_state.lock().unwrap();
		if channel_state.by_id.contains_key(&msg.temporary_channel_id) {
			return Err(HandleError{err: "temporary_channel_id collision!", msg: None});
		}
		let channel = Channel::new_from_req(&*self.fee_estimator, their_node_id.clone(), msg, 0, self.announce_channels_publicly)?;
		let accept_msg = channel.get_accept_channel()?;
		channel_state.by_id.insert(channel.channel_id(), channel);
		Ok(accept_msg)
	}

	fn handle_accept_channel(&self, their_node_id: &PublicKey, msg: &msgs::AcceptChannel) -> Result<(), HandleError> {
		let (value, output_script, user_id) = {
			let mut channel_state = self.channel_state.lock().unwrap();
			match channel_state.by_id.get_mut(&msg.temporary_channel_id) {
				Some(chan) => {
					if chan.get_their_node_id() != *their_node_id {
						return Err(HandleError{err: "Got a message for a channel from the wrong node!", msg: None})
					}
					chan.accept_channel(&msg)?;
					(chan.get_value_satoshis(), chan.get_funding_redeemscript().to_v0_p2wsh(), chan.get_user_id())
				},
				None => return Err(HandleError{err: "Failed to find corresponding channel", msg: None})
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

	fn handle_funding_created(&self, their_node_id: &PublicKey, msg: &msgs::FundingCreated) -> Result<msgs::FundingSigned, HandleError> {
		//TODO: broke this - a node shouldn't be able to get their channel removed by sending a
		//funding_created a second time, or long after the first, or whatever (note this also
		//leaves the short_to_id map in a busted state.
		let chan = {
			let mut channel_state = self.channel_state.lock().unwrap();
			match channel_state.by_id.remove(&msg.temporary_channel_id) {
				Some(mut chan) => {
					if chan.get_their_node_id() != *their_node_id {
						return Err(HandleError{err: "Got a message for a channel from the wrong node!", msg: None})
					}
					match chan.funding_created(msg) {
						Ok(funding_msg) => {
							(chan, funding_msg)
						},
						Err(e) => {
							return Err(e);
						}
					}
				},
				None => return Err(HandleError{err: "Failed to find corresponding channel", msg: None})
			}
		}; // Release channel lock for install_watch_outpoint call,
		   // note that this means if the remote end is misbehaving and sends a message for the same
		   // channel back-to-back with funding_created, we'll end up thinking they sent a message
		   // for a bogus channel.
		let chan_monitor = chan.0.channel_monitor();
		self.monitor.add_update_monitor(chan_monitor.get_funding_txo().unwrap(), chan_monitor)?;
		let mut channel_state = self.channel_state.lock().unwrap();
		channel_state.by_id.insert(chan.1.channel_id, chan.0);
		Ok(chan.1)
	}

	fn handle_funding_signed(&self, their_node_id: &PublicKey, msg: &msgs::FundingSigned) -> Result<(), HandleError> {
		let (funding_txo, user_id) = {
			let mut channel_state = self.channel_state.lock().unwrap();
			match channel_state.by_id.get_mut(&msg.channel_id) {
				Some(chan) => {
					if chan.get_their_node_id() != *their_node_id {
						return Err(HandleError{err: "Got a message for a channel from the wrong node!", msg: None})
					}
					chan.funding_signed(&msg)?;
					(chan.get_funding_txo().unwrap(), chan.get_user_id())
				},
				None => return Err(HandleError{err: "Failed to find corresponding channel", msg: None})
			}
		};
		let mut pending_events = self.pending_events.lock().unwrap();
		pending_events.push(events::Event::FundingBroadcastSafe {
			funding_txo: funding_txo,
			user_channel_id: user_id,
		});
		Ok(())
	}

	fn handle_funding_locked(&self, their_node_id: &PublicKey, msg: &msgs::FundingLocked) -> Result<Option<msgs::AnnouncementSignatures>, HandleError> {
		let mut channel_state = self.channel_state.lock().unwrap();
		match channel_state.by_id.get_mut(&msg.channel_id) {
			Some(chan) => {
				if chan.get_their_node_id() != *their_node_id {
					return Err(HandleError{err: "Got a message for a channel from the wrong node!", msg: None})
				}
				chan.funding_locked(&msg)?;
				return Ok(self.get_announcement_sigs(chan)?);
			},
			None => return Err(HandleError{err: "Failed to find corresponding channel", msg: None})
		};
	}

	fn handle_shutdown(&self, _their_node_id: &PublicKey, _msg: &msgs::Shutdown) -> Result<(), HandleError> {
		unimplemented!()
	}

	fn handle_closing_signed(&self, _their_node_id: &PublicKey, _msg: &msgs::ClosingSigned) -> Result<(), HandleError> {
		unimplemented!()
	}

	fn handle_update_add_htlc(&self, their_node_id: &PublicKey, msg: &msgs::UpdateAddHTLC) -> Result<(), msgs::HandleError> {
		//TODO: BOLT 4 points out a specific attack where a peer may re-send an onion packet and
		//determine the state of the payment based on our response/if we forward anything/the time
		//we take to respond. We should take care to avoid allowing such an attack.
		//
		//TODO: There exists a further attack where a node may garble the onion data, forward it to
		//us repeatedly garbled in different ways, and compare our error messages, which are
		//encrypted with the same key. Its not immediately obvious how to usefully exploit that,
		//but we should prevent it anyway.

		let shared_secret = SharedSecret::new(&self.secp_ctx, &msg.onion_routing_packet.public_key, &self.our_network_key);
		let (rho, mu) = ChannelManager::gen_rho_mu_from_shared_secret(&shared_secret);

		let associated_data = Vec::new(); //TODO: What to put here?

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

		macro_rules! return_err {
			($msg: expr, $err_code: expr, $data: expr) => {
				return Err(msgs::HandleError {
					err: $msg,
					msg: Some(msgs::ErrorMessage::UpdateFailHTLC {
						msg: msgs::UpdateFailHTLC {
							channel_id: msg.channel_id,
							htlc_id: msg.htlc_id,
							reason: ChannelManager::build_first_hop_failure_packet(&shared_secret, $err_code, $data),
						}
					}),
				});
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
		hmac.input(&associated_data[..]);
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

		let mut pending_forward_info = if next_hop_data.hmac == [0; 32] {
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

				PendingForwardHTLCInfo {
					onion_packet: None,
					payment_hash: msg.payment_hash.clone(),
					short_channel_id: 0,
					prev_short_channel_id: 0,
					amt_to_forward: next_hop_data.data.amt_to_forward,
					outgoing_cltv_value: next_hop_data.data.outgoing_cltv_value,
				}
			} else {
				let mut new_packet_data = [0; 20*65];
				chacha.process(&msg.onion_routing_packet.hop_data[65..], &mut new_packet_data[0..19*65]);
				chacha.process(&ChannelManager::ZERO[0..65], &mut new_packet_data[19*65..]);

				let mut new_pubkey = msg.onion_routing_packet.public_key.clone();

				let blinding_factor = {
					let mut sha = Sha256::new();
					sha.input(&new_pubkey.serialize()[..]);
					sha.input(&shared_secret[..]);
					let mut res = [0u8; 32];
					sha.result(&mut res);
					match SecretKey::from_slice(&self.secp_ctx, &res) {
						Err(_) => {
							// Return temporary node failure as its technically our issue, not the
							// channel's issue.
							return_err!("Blinding factor is an invalid private key", 0x2000 | 2, &[0;0]);
						},
						Ok(key) => key
					}
				};

				match new_pubkey.mul_assign(&self.secp_ctx, &blinding_factor) {
					Err(_) => {
						// Return temporary node failure as its technically our issue, not the
						// channel's issue.
						return_err!("New blinding factor is an invalid private key", 0x2000 | 2, &[0;0]);
					},
					Ok(_) => {}
				};

				let outgoing_packet = msgs::OnionPacket {
					version: 0,
					public_key: new_pubkey,
					hop_data: new_packet_data,
					hmac: next_hop_data.hmac.clone(),
				};

				//TODO: Check amt_to_forward and outgoing_cltv_value are within acceptable ranges!

				PendingForwardHTLCInfo {
					onion_packet: Some(outgoing_packet),
					payment_hash: msg.payment_hash.clone(),
					short_channel_id: next_hop_data.data.short_channel_id,
					prev_short_channel_id: 0,
					amt_to_forward: next_hop_data.data.amt_to_forward,
					outgoing_cltv_value: next_hop_data.data.outgoing_cltv_value,
				}
			};

		let mut channel_state_lock = self.channel_state.lock().unwrap();
		let channel_state = channel_state_lock.borrow_parts();

		if pending_forward_info.onion_packet.is_some() { // If short_channel_id is 0 here, we'll reject them in the body here
			let forwarding_id = match channel_state.short_to_id.get(&pending_forward_info.short_channel_id) {
				None => {
					return_err!("Don't have available channel for forwarding as requested.", 0x4000 | 10, &[0;0]);
				},
				Some(id) => id.clone(),
			};
			let chan = channel_state.by_id.get_mut(&forwarding_id).unwrap();
			if !chan.is_live() {
				let chan_update = self.get_channel_update(chan).unwrap();
				return_err!("Forwarding channel is not in a ready state.", 0x4000 | 10, &chan_update.encode()[..]);
			}
		}

		let claimable_htlcs_entry = channel_state.claimable_htlcs.entry(msg.payment_hash.clone());

		// We dont correctly handle payments that route through us twice on their way to their
		// destination. That's OK since those nodes are probably busted or trying to do network
		// mapping through repeated loops. In either case, we want them to stop talking to us, so
		// we send permanent_node_failure.
		match &claimable_htlcs_entry {
			&hash_map::Entry::Occupied(ref e) => {
				let mut acceptable_cycle = false;
				match e.get() {
					&PendingOutboundHTLC::OutboundRoute { .. } => {
						acceptable_cycle = pending_forward_info.short_channel_id == 0;
					},
					_ => {},
				}
				if !acceptable_cycle {
					return_err!("Payment looped through us twice", 0x4000 | 0x2000 | 2, &[0;0]);
				}
			},
			_ => {},
		}

		let (source_short_channel_id, res) = match channel_state.by_id.get_mut(&msg.channel_id) {
			Some(chan) => {
				if chan.get_their_node_id() != *their_node_id {
					return Err(HandleError{err: "Got a message for a channel from the wrong node!", msg: None})
				}
				if !chan.is_usable() {
					return Err(HandleError{err: "Channel not yet available for receiving HTLCs", msg: None});
				}
				let short_channel_id = chan.get_short_channel_id().unwrap();
				pending_forward_info.prev_short_channel_id = short_channel_id;
				(short_channel_id, chan.update_add_htlc(&msg, pending_forward_info)?)
			},
			None => return Err(HandleError{err: "Failed to find corresponding channel", msg: None}), //TODO: panic?
		};

		match claimable_htlcs_entry {
			hash_map::Entry::Occupied(mut e) => {
				let outbound_route = e.get_mut();
				let route = match outbound_route {
					&mut PendingOutboundHTLC::OutboundRoute { ref route } => {
						route.clone()
					},
					_ => { panic!("WAT") },
				};
				*outbound_route = PendingOutboundHTLC::CycledRoute {
					source_short_channel_id,
					incoming_packet_shared_secret: shared_secret,
					route
				};
			},
			hash_map::Entry::Vacant(e) => {
				e.insert(PendingOutboundHTLC::IntermediaryHopData {
					source_short_channel_id,
					incoming_packet_shared_secret: shared_secret,
				});
			}
		}

		Ok(res)
	}

	fn handle_update_fulfill_htlc(&self, their_node_id: &PublicKey, msg: &msgs::UpdateFulfillHTLC) -> Result<Option<(Vec<msgs::UpdateAddHTLC>, msgs::CommitmentSigned)>, HandleError> {
		let res = {
			let mut channel_state = self.channel_state.lock().unwrap();
			match channel_state.by_id.get_mut(&msg.channel_id) {
				Some(chan) => {
					if chan.get_their_node_id() != *their_node_id {
						return Err(HandleError{err: "Got a message for a channel from the wrong node!", msg: None})
					}
					chan.update_fulfill_htlc(&msg)
				},
				None => return Err(HandleError{err: "Failed to find corresponding channel", msg: None})
			}
		};
		//TODO: Delay the claimed_funds relaying just like we do outbound relay!
		self.claim_funds_internal(msg.payment_preimage.clone(), false);
		res
	}

	fn handle_update_fail_htlc(&self, their_node_id: &PublicKey, msg: &msgs::UpdateFailHTLC) -> Result<Option<(Vec<msgs::UpdateAddHTLC>, msgs::CommitmentSigned)>, HandleError> {
		let mut channel_state = self.channel_state.lock().unwrap();
		let res;
		match channel_state.by_id.get_mut(&msg.channel_id) {
			Some(chan) => {
				if chan.get_their_node_id() != *their_node_id {
					return Err(HandleError{err: "Got a message for a channel from the wrong node!", msg: None})
				}
				res = chan.update_fail_htlc(&msg)?;
			},
			None => return Err(HandleError{err: "Failed to find corresponding channel", msg: None})
		}
		self.fail_htlc_backwards_internal(channel_state, &res.0, HTLCFailReason::ErrorPacket { err: &msg.reason });
		Ok(res.1)
	}

	fn handle_update_fail_malformed_htlc(&self, their_node_id: &PublicKey, msg: &msgs::UpdateFailMalformedHTLC) -> Result<Option<(Vec<msgs::UpdateAddHTLC>, msgs::CommitmentSigned)>, HandleError> {
		let mut channel_state = self.channel_state.lock().unwrap();
		let res;
		match channel_state.by_id.get_mut(&msg.channel_id) {
			Some(chan) => {
				if chan.get_their_node_id() != *their_node_id {
					return Err(HandleError{err: "Got a message for a channel from the wrong node!", msg: None})
				}
				res = chan.update_fail_malformed_htlc(&msg)?;
			},
			None => return Err(HandleError{err: "Failed to find corresponding channel", msg: None})
		}
		self.fail_htlc_backwards_internal(channel_state, &res.0, HTLCFailReason::Reason { failure_code: msg.failure_code });
		Ok(res.1)
	}

	fn handle_commitment_signed(&self, their_node_id: &PublicKey, msg: &msgs::CommitmentSigned) -> Result<msgs::RevokeAndACK, HandleError> {
		let mut forward_event = None;
		let (res, monitor) = {
			let mut channel_state = self.channel_state.lock().unwrap();

			let ((res, mut forwarding_infos), monitor) = match channel_state.by_id.get_mut(&msg.channel_id) {
				Some(chan) => {
					if chan.get_their_node_id() != *their_node_id {
						return Err(HandleError{err: "Got a message for a channel from the wrong node!", msg: None})
					}
					(chan.commitment_signed(&msg)?, chan.channel_monitor())
				},
				None => return Err(HandleError{err: "Failed to find corresponding channel", msg: None})
			};

			if channel_state.forward_htlcs.is_empty() {
				forward_event = Some(Instant::now() + Duration::from_millis(((rng::rand_f32() * 4.0 + 1.0) * MIN_HTLC_RELAY_HOLDING_CELL_MILLIS as f32) as u64));
				channel_state.next_forward = forward_event.unwrap();
			}
			for forward_info in forwarding_infos.drain(..) {
				match channel_state.forward_htlcs.entry(forward_info.short_channel_id) {
					hash_map::Entry::Occupied(mut entry) => {
						entry.get_mut().push(forward_info);
					},
					hash_map::Entry::Vacant(entry) => {
						entry.insert(vec!(forward_info));
					}
				}
			}

			(res, monitor)
		};
		//TODO: Only if we store HTLC sigs
		self.monitor.add_update_monitor(monitor.get_funding_txo().unwrap(), monitor)?;

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

	fn handle_revoke_and_ack(&self, their_node_id: &PublicKey, msg: &msgs::RevokeAndACK) -> Result<(), HandleError> {
		let monitor = {
			let mut channel_state = self.channel_state.lock().unwrap();
			match channel_state.by_id.get_mut(&msg.channel_id) {
				Some(chan) => {
					if chan.get_their_node_id() != *their_node_id {
						return Err(HandleError{err: "Got a message for a channel from the wrong node!", msg: None})
					}
					chan.revoke_and_ack(&msg)?;
					chan.channel_monitor()
				},
				None => return Err(HandleError{err: "Failed to find corresponding channel", msg: None})
			}
		};
		self.monitor.add_update_monitor(monitor.get_funding_txo().unwrap(), monitor)?;
		Ok(())
	}

	fn handle_update_fee(&self, their_node_id: &PublicKey, msg: &msgs::UpdateFee) -> Result<(), HandleError> {
		let mut channel_state = self.channel_state.lock().unwrap();
		match channel_state.by_id.get_mut(&msg.channel_id) {
			Some(chan) => {
				if chan.get_their_node_id() != *their_node_id {
					return Err(HandleError{err: "Got a message for a channel from the wrong node!", msg: None})
				}
				chan.update_fee(&*self.fee_estimator, &msg)
			},
			None => return Err(HandleError{err: "Failed to find corresponding channel", msg: None})
		}
	}

	fn handle_announcement_signatures(&self, their_node_id: &PublicKey, msg: &msgs::AnnouncementSignatures) -> Result<(), HandleError> {
		let (chan_announcement, chan_update) = {
			let mut channel_state = self.channel_state.lock().unwrap();
			match channel_state.by_id.get_mut(&msg.channel_id) {
				Some(chan) => {
					if chan.get_their_node_id() != *their_node_id {
						return Err(HandleError{err: "Got a message for a channel from the wrong node!", msg: None})
					}
					if !chan.is_usable() {
						return Err(HandleError{err: "Got an announcement_signatures before we were ready for it", msg: None });
					}

					let our_node_id = self.get_our_node_id();
					let (announcement, our_bitcoin_sig) = chan.get_channel_announcement(our_node_id.clone(), self.genesis_hash.clone())?;

					let were_node_one = announcement.node_id_1 == our_node_id;
					let msghash = Message::from_slice(&Sha256dHash::from_data(&announcement.encode()[..])[..]).unwrap();
					secp_call!(self.secp_ctx.verify(&msghash, &msg.node_signature, if were_node_one { &announcement.node_id_2 } else { &announcement.node_id_1 }));
					secp_call!(self.secp_ctx.verify(&msghash, &msg.bitcoin_signature, if were_node_one { &announcement.bitcoin_key_2 } else { &announcement.bitcoin_key_1 }));

					let our_node_sig = secp_call!(self.secp_ctx.sign(&msghash, &self.our_network_key));

					(msgs::ChannelAnnouncement {
						node_signature_1: if were_node_one { our_node_sig } else { msg.node_signature },
						node_signature_2: if were_node_one { msg.node_signature } else { our_node_sig },
						bitcoin_signature_1: if were_node_one { our_bitcoin_sig } else { msg.bitcoin_signature },
						bitcoin_signature_2: if were_node_one { msg.bitcoin_signature } else { our_bitcoin_sig },
						contents: announcement,
					}, self.get_channel_update(chan).unwrap()) // can only fail if we're not in a ready state
				},
				None => return Err(HandleError{err: "Failed to find corresponding channel", msg: None})
			}
		};
		let mut pending_events = self.pending_events.lock().unwrap();
		pending_events.push(events::Event::BroadcastChannelAnnouncement { msg: chan_announcement, update_msg: chan_update });
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use chain::chaininterface;
	use ln::channelmanager::{ChannelManager,OnionKeys};
	use ln::router::{Route, RouteHop, Router};
	use ln::msgs;
	use ln::msgs::{MsgEncodable,ChannelMessageHandler,RoutingMessageHandler};
	use util::test_utils;
	use util::events::{Event, EventsProvider};

	use bitcoin::util::misc::hex_bytes;
	use bitcoin::util::hash::Sha256dHash;
	use bitcoin::blockdata::block::BlockHeader;
	use bitcoin::blockdata::transaction::Transaction;
	use bitcoin::network::constants::Network;
	use bitcoin::network::serialize::serialize;
	use bitcoin::network::serialize::BitcoinHash;

	use secp256k1::Secp256k1;
	use secp256k1::key::{PublicKey,SecretKey};

	use crypto::sha2::Sha256;
	use crypto::digest::Digest;

	use rand::{thread_rng,Rng};

	use std::sync::Arc;
	use std::default::Default;
	use std::time::Instant;

	fn build_test_onion_keys() -> Vec<OnionKeys> {
		// Keys from BOLT 4, used in both test vector tests
		let secp_ctx = Secp256k1::new();

		let route = Route {
			hops: vec!(
					RouteHop {
						pubkey: PublicKey::from_slice(&secp_ctx, &hex_bytes("02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619").unwrap()[..]).unwrap(),
						short_channel_id: 0, fee_msat: 0, cltv_expiry_delta: 0 // Test vectors are garbage and not generateble from a RouteHop, we fill in payloads manually
					},
					RouteHop {
						pubkey: PublicKey::from_slice(&secp_ctx, &hex_bytes("0324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c").unwrap()[..]).unwrap(),
						short_channel_id: 0, fee_msat: 0, cltv_expiry_delta: 0 // Test vectors are garbage and not generateble from a RouteHop, we fill in payloads manually
					},
					RouteHop {
						pubkey: PublicKey::from_slice(&secp_ctx, &hex_bytes("027f31ebc5462c1fdce1b737ecff52d37d75dea43ce11c74d25aa297165faa2007").unwrap()[..]).unwrap(),
						short_channel_id: 0, fee_msat: 0, cltv_expiry_delta: 0 // Test vectors are garbage and not generateble from a RouteHop, we fill in payloads manually
					},
					RouteHop {
						pubkey: PublicKey::from_slice(&secp_ctx, &hex_bytes("032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991").unwrap()[..]).unwrap(),
						short_channel_id: 0, fee_msat: 0, cltv_expiry_delta: 0 // Test vectors are garbage and not generateble from a RouteHop, we fill in payloads manually
					},
					RouteHop {
						pubkey: PublicKey::from_slice(&secp_ctx, &hex_bytes("02edabbd16b41c8371b92ef2f04c1185b4f03b6dcd52ba9b78d9d7c89c8f221145").unwrap()[..]).unwrap(),
						short_channel_id: 0, fee_msat: 0, cltv_expiry_delta: 0 // Test vectors are garbage and not generateble from a RouteHop, we fill in payloads manually
					},
			),
		};

		let session_priv = SecretKey::from_slice(&secp_ctx, &hex_bytes("4141414141414141414141414141414141414141414141414141414141414141").unwrap()[..]).unwrap();

		let onion_keys = ChannelManager::construct_onion_keys(&secp_ctx, &route, &session_priv).unwrap();
		assert_eq!(onion_keys.len(), route.hops.len());
		onion_keys
	}

	#[test]
	fn onion_vectors() {
		// Packet creation test vectors from BOLT 4
		let onion_keys = build_test_onion_keys();

		assert_eq!(onion_keys[0].shared_secret[..], hex_bytes("53eb63ea8a3fec3b3cd433b85cd62a4b145e1dda09391b348c4e1cd36a03ea66").unwrap()[..]);
		assert_eq!(onion_keys[0].blinding_factor[..], hex_bytes("2ec2e5da605776054187180343287683aa6a51b4b1c04d6dd49c45d8cffb3c36").unwrap()[..]);
		assert_eq!(onion_keys[0].ephemeral_pubkey.serialize()[..], hex_bytes("02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619").unwrap()[..]);
		assert_eq!(onion_keys[0].rho, hex_bytes("ce496ec94def95aadd4bec15cdb41a740c9f2b62347c4917325fcc6fb0453986").unwrap()[..]);
		assert_eq!(onion_keys[0].mu, hex_bytes("b57061dc6d0a2b9f261ac410c8b26d64ac5506cbba30267a649c28c179400eba").unwrap()[..]);

		assert_eq!(onion_keys[1].shared_secret[..], hex_bytes("a6519e98832a0b179f62123b3567c106db99ee37bef036e783263602f3488fae").unwrap()[..]);
		assert_eq!(onion_keys[1].blinding_factor[..], hex_bytes("bf66c28bc22e598cfd574a1931a2bafbca09163df2261e6d0056b2610dab938f").unwrap()[..]);
		assert_eq!(onion_keys[1].ephemeral_pubkey.serialize()[..], hex_bytes("028f9438bfbf7feac2e108d677e3a82da596be706cc1cf342b75c7b7e22bf4e6e2").unwrap()[..]);
		assert_eq!(onion_keys[1].rho, hex_bytes("450ffcabc6449094918ebe13d4f03e433d20a3d28a768203337bc40b6e4b2c59").unwrap()[..]);
		assert_eq!(onion_keys[1].mu, hex_bytes("05ed2b4a3fb023c2ff5dd6ed4b9b6ea7383f5cfe9d59c11d121ec2c81ca2eea9").unwrap()[..]);

		assert_eq!(onion_keys[2].shared_secret[..], hex_bytes("3a6b412548762f0dbccce5c7ae7bb8147d1caf9b5471c34120b30bc9c04891cc").unwrap()[..]);
		assert_eq!(onion_keys[2].blinding_factor[..], hex_bytes("a1f2dadd184eb1627049673f18c6325814384facdee5bfd935d9cb031a1698a5").unwrap()[..]);
		assert_eq!(onion_keys[2].ephemeral_pubkey.serialize()[..], hex_bytes("03bfd8225241ea71cd0843db7709f4c222f62ff2d4516fd38b39914ab6b83e0da0").unwrap()[..]);
		assert_eq!(onion_keys[2].rho, hex_bytes("11bf5c4f960239cb37833936aa3d02cea82c0f39fd35f566109c41f9eac8deea").unwrap()[..]);
		assert_eq!(onion_keys[2].mu, hex_bytes("caafe2820fa00eb2eeb78695ae452eba38f5a53ed6d53518c5c6edf76f3f5b78").unwrap()[..]);

		assert_eq!(onion_keys[3].shared_secret[..], hex_bytes("21e13c2d7cfe7e18836df50872466117a295783ab8aab0e7ecc8c725503ad02d").unwrap()[..]);
		assert_eq!(onion_keys[3].blinding_factor[..], hex_bytes("7cfe0b699f35525029ae0fa437c69d0f20f7ed4e3916133f9cacbb13c82ff262").unwrap()[..]);
		assert_eq!(onion_keys[3].ephemeral_pubkey.serialize()[..], hex_bytes("031dde6926381289671300239ea8e57ffaf9bebd05b9a5b95beaf07af05cd43595").unwrap()[..]);
		assert_eq!(onion_keys[3].rho, hex_bytes("cbe784ab745c13ff5cffc2fbe3e84424aa0fd669b8ead4ee562901a4a4e89e9e").unwrap()[..]);
		assert_eq!(onion_keys[3].mu, hex_bytes("5052aa1b3d9f0655a0932e50d42f0c9ba0705142c25d225515c45f47c0036ee9").unwrap()[..]);

		assert_eq!(onion_keys[4].shared_secret[..], hex_bytes("b5756b9b542727dbafc6765a49488b023a725d631af688fc031217e90770c328").unwrap()[..]);
		assert_eq!(onion_keys[4].blinding_factor[..], hex_bytes("c96e00dddaf57e7edcd4fb5954be5b65b09f17cb6d20651b4e90315be5779205").unwrap()[..]);
		assert_eq!(onion_keys[4].ephemeral_pubkey.serialize()[..], hex_bytes("03a214ebd875aab6ddfd77f22c5e7311d7f77f17a169e599f157bbcdae8bf071f4").unwrap()[..]);
		assert_eq!(onion_keys[4].rho, hex_bytes("034e18b8cc718e8af6339106e706c52d8df89e2b1f7e9142d996acf88df8799b").unwrap()[..]);
		assert_eq!(onion_keys[4].mu, hex_bytes("8e45e5c61c2b24cb6382444db6698727afb063adecd72aada233d4bf273d975a").unwrap()[..]);

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

		let packet = ChannelManager::construct_onion_packet(payloads, onion_keys, hex_bytes("4242424242424242424242424242424242424242424242424242424242424242").unwrap()).unwrap();
		// Just check the final packet encoding, as it includes all the per-hop vectors in it
		// anyway...
		assert_eq!(packet.encode(), hex_bytes("0002eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619e5f14350c2a76fc232b5e46d421e9615471ab9e0bc887beff8c95fdb878f7b3a716a996c7845c93d90e4ecbb9bde4ece2f69425c99e4bc820e44485455f135edc0d10f7d61ab590531cf08000179a333a347f8b4072f216400406bdf3bf038659793d4a1fd7b246979e3150a0a4cb052c9ec69acf0f48c3d39cd55675fe717cb7d80ce721caad69320c3a469a202f1e468c67eaf7a7cd8226d0fd32f7b48084dca885d56047694762b67021713ca673929c163ec36e04e40ca8e1c6d17569419d3039d9a1ec866abe044a9ad635778b961fc0776dc832b3a451bd5d35072d2269cf9b040f6b7a7dad84fb114ed413b1426cb96ceaf83825665ed5a1d002c1687f92465b49ed4c7f0218ff8c6c7dd7221d589c65b3b9aaa71a41484b122846c7c7b57e02e679ea8469b70e14fe4f70fee4d87b910cf144be6fe48eef24da475c0b0bcc6565ae82cd3f4e3b24c76eaa5616c6111343306ab35c1fe5ca4a77c0e314ed7dba39d6f1e0de791719c241a939cc493bea2bae1c1e932679ea94d29084278513c77b899cc98059d06a27d171b0dbdf6bee13ddc4fc17a0c4d2827d488436b57baa167544138ca2e64a11b43ac8a06cd0c2fba2d4d900ed2d9205305e2d7383cc98dacb078133de5f6fb6bed2ef26ba92cea28aafc3b9948dd9ae5559e8bd6920b8cea462aa445ca6a95e0e7ba52961b181c79e73bd581821df2b10173727a810c92b83b5ba4a0403eb710d2ca10689a35bec6c3a708e9e92f7d78ff3c5d9989574b00c6736f84c199256e76e19e78f0c98a9d580b4a658c84fc8f2096c2fbea8f5f8c59d0fdacb3be2802ef802abbecb3aba4acaac69a0e965abd8981e9896b1f6ef9d60f7a164b371af869fd0e48073742825e9434fc54da837e120266d53302954843538ea7c6c3dbfb4ff3b2fdbe244437f2a153ccf7bdb4c92aa08102d4f3cff2ae5ef86fab4653595e6a5837fa2f3e29f27a9cde5966843fb847a4a61f1e76c281fe8bb2b0a181d096100db5a1a5ce7a910238251a43ca556712eaadea167fb4d7d75825e440f3ecd782036d7574df8bceacb397abefc5f5254d2722215c53ff54af8299aaaad642c6d72a14d27882d9bbd539e1cc7a527526ba89b8c037ad09120e98ab042d3e8652b31ae0e478516bfaf88efca9f3676ffe99d2819dcaeb7610a626695f53117665d267d3f7abebd6bbd6733f645c72c389f03855bdf1e4b8075b516569b118233a0f0971d24b83113c0b096f5216a207ca99a7cddc81c130923fe3d91e7508c9ac5f2e914ff5dccab9e558566fa14efb34ac98d878580814b94b73acbfde9072f30b881f7f0fff42d4045d1ace6322d86a97d164aa84d93a60498065cc7c20e636f5862dc81531a88c60305a2e59a985be327a6902e4bed986dbf4a0b50c217af0ea7fdf9ab37f9ea1a1aaa72f54cf40154ea9b269f1a7c09f9f43245109431a175d50e2db0132337baa0ef97eed0fcf20489da36b79a1172faccc2f7ded7c60e00694282d93359c4682135642bc81f433574aa8ef0c97b4ade7ca372c5ffc23c7eddd839bab4e0f14d6df15c9dbeab176bec8b5701cf054eb3072f6dadc98f88819042bf10c407516ee58bce33fbe3b3d86a54255e577db4598e30a135361528c101683a5fcde7e8ba53f3456254be8f45fe3a56120ae96ea3773631fcb3873aa3abd91bcff00bd38bd43697a2e789e00da6077482e7b1b1a677b5afae4c54e6cbdf7377b694eb7d7a5b913476a5be923322d3de06060fd5e819635232a2cf4f0731da13b8546d1d6d4f8d75b9fce6c2341a71b0ea6f780df54bfdb0dd5cd9855179f602f9172307c7268724c3618e6817abd793adc214a0dc0bc616816632f27ea336fb56dfd").unwrap());
	}

	#[test]
	fn test_failure_packet_onion() {
		// Returning Errors test vectors from BOLT 4

		let onion_keys = build_test_onion_keys();
		let onion_error = ChannelManager::build_failure_packet(&onion_keys[4].shared_secret, 0x2002, &[0; 0]);
		assert_eq!(onion_error.encode(), hex_bytes("4c2fc8bc08510334b6833ad9c3e79cd1b52ae59dfe5c2a4b23ead50f09f7ee0b0002200200fe0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").unwrap());

		let onion_packet_1 = ChannelManager::encrypt_failure_packet(&onion_keys[4].shared_secret, &onion_error.encode()[..]);
		assert_eq!(onion_packet_1.data, hex_bytes("a5e6bd0c74cb347f10cce367f949098f2457d14c046fd8a22cb96efb30b0fdcda8cb9168b50f2fd45edd73c1b0c8b33002df376801ff58aaa94000bf8a86f92620f343baef38a580102395ae3abf9128d1047a0736ff9b83d456740ebbb4aeb3aa9737f18fb4afb4aa074fb26c4d702f42968888550a3bded8c05247e045b866baef0499f079fdaeef6538f31d44deafffdfd3afa2fb4ca9082b8f1c465371a9894dd8c243fb4847e004f5256b3e90e2edde4c9fb3082ddfe4d1e734cacd96ef0706bf63c9984e22dc98851bcccd1c3494351feb458c9c6af41c0044bea3c47552b1d992ae542b17a2d0bba1a096c78d169034ecb55b6e3a7263c26017f033031228833c1daefc0dedb8cf7c3e37c9c37ebfe42f3225c326e8bcfd338804c145b16e34e4").unwrap());

		let onion_packet_2 = ChannelManager::encrypt_failure_packet(&onion_keys[3].shared_secret, &onion_packet_1.data[..]);
		assert_eq!(onion_packet_2.data, hex_bytes("c49a1ce81680f78f5f2000cda36268de34a3f0a0662f55b4e837c83a8773c22aa081bab1616a0011585323930fa5b9fae0c85770a2279ff59ec427ad1bbff9001c0cd1497004bd2a0f68b50704cf6d6a4bf3c8b6a0833399a24b3456961ba00736785112594f65b6b2d44d9f5ea4e49b5e1ec2af978cbe31c67114440ac51a62081df0ed46d4a3df295da0b0fe25c0115019f03f15ec86fabb4c852f83449e812f141a9395b3f70b766ebbd4ec2fae2b6955bd8f32684c15abfe8fd3a6261e52650e8807a92158d9f1463261a925e4bfba44bd20b166d532f0017185c3a6ac7957adefe45559e3072c8dc35abeba835a8cb01a71a15c736911126f27d46a36168ca5ef7dccd4e2886212602b181463e0dd30185c96348f9743a02aca8ec27c0b90dca270").unwrap());

		let onion_packet_3 = ChannelManager::encrypt_failure_packet(&onion_keys[2].shared_secret, &onion_packet_2.data[..]);
		assert_eq!(onion_packet_3.data, hex_bytes("a5d3e8634cfe78b2307d87c6d90be6fe7855b4f2cc9b1dfb19e92e4b79103f61ff9ac25f412ddfb7466e74f81b3e545563cdd8f5524dae873de61d7bdfccd496af2584930d2b566b4f8d3881f8c043df92224f38cf094cfc09d92655989531524593ec6d6caec1863bdfaa79229b5020acc034cd6deeea1021c50586947b9b8e6faa83b81fbfa6133c0af5d6b07c017f7158fa94f0d206baf12dda6b68f785b773b360fd0497e16cc402d779c8d48d0fa6315536ef0660f3f4e1865f5b38ea49c7da4fd959de4e83ff3ab686f059a45c65ba2af4a6a79166aa0f496bf04d06987b6d2ea205bdb0d347718b9aeff5b61dfff344993a275b79717cd815b6ad4c0beb568c4ac9c36ff1c315ec1119a1993c4b61e6eaa0375e0aaf738ac691abd3263bf937e3").unwrap());

		let onion_packet_4 = ChannelManager::encrypt_failure_packet(&onion_keys[1].shared_secret, &onion_packet_3.data[..]);
		assert_eq!(onion_packet_4.data, hex_bytes("aac3200c4968f56b21f53e5e374e3a2383ad2b1b6501bbcc45abc31e59b26881b7dfadbb56ec8dae8857add94e6702fb4c3a4de22e2e669e1ed926b04447fc73034bb730f4932acd62727b75348a648a1128744657ca6a4e713b9b646c3ca66cac02cdab44dd3439890ef3aaf61708714f7375349b8da541b2548d452d84de7084bb95b3ac2345201d624d31f4d52078aa0fa05a88b4e20202bd2b86ac5b52919ea305a8949de95e935eed0319cf3cf19ebea61d76ba92532497fcdc9411d06bcd4275094d0a4a3c5d3a945e43305a5a9256e333e1f64dbca5fcd4e03a39b9012d197506e06f29339dfee3331995b21615337ae060233d39befea925cc262873e0530408e6990f1cbd233a150ef7b004ff6166c70c68d9f8c853c1abca640b8660db2921").unwrap());

		let onion_packet_5 = ChannelManager::encrypt_failure_packet(&onion_keys[0].shared_secret, &onion_packet_4.data[..]);
		assert_eq!(onion_packet_5.data, hex_bytes("9c5add3963fc7f6ed7f148623c84134b5647e1306419dbe2174e523fa9e2fbed3a06a19f899145610741c83ad40b7712aefaddec8c6baf7325d92ea4ca4d1df8bce517f7e54554608bf2bd8071a4f52a7a2f7ffbb1413edad81eeea5785aa9d990f2865dc23b4bc3c301a94eec4eabebca66be5cf638f693ec256aec514620cc28ee4a94bd9565bc4d4962b9d3641d4278fb319ed2b84de5b665f307a2db0f7fbb757366067d88c50f7e829138fde4f78d39b5b5802f1b92a8a820865af5cc79f9f30bc3f461c66af95d13e5e1f0381c184572a91dee1c849048a647a1158cf884064deddbf1b0b88dfe2f791428d0ba0f6fb2f04e14081f69165ae66d9297c118f0907705c9c4954a199bae0bb96fad763d690e7daa6cfda59ba7f2c8d11448b604d12d").unwrap());
	}

	static mut CHAN_COUNT: u16 = 0;
	fn confirm_transaction(chain: &chaininterface::ChainWatchInterfaceUtil, tx: &Transaction) {
		let mut header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
		let chan_id = unsafe { CHAN_COUNT };
		chain.block_connected_checked(&header, 1, &[tx; 1], &[chan_id as u32; 1]);
		for i in 2..100 {
			header = BlockHeader { version: 0x20000000, prev_blockhash: header.bitcoin_hash(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
			chain.block_connected_checked(&header, i, &[tx; 0], &[0; 0]);
		}
	}

	fn create_chan_between_nodes(node_a: &ChannelManager, chain_a: &chaininterface::ChainWatchInterfaceUtil, node_b: &ChannelManager, chain_b: &chaininterface::ChainWatchInterfaceUtil) -> (msgs::ChannelAnnouncement, msgs::ChannelUpdate, msgs::ChannelUpdate) {
		let open_chan = node_a.create_channel(node_b.get_our_node_id(), (1 << 24) - 1, 42).unwrap();
		let accept_chan = node_b.handle_open_channel(&node_a.get_our_node_id(), &open_chan).unwrap();
		node_a.handle_accept_channel(&node_b.get_our_node_id(), &accept_chan).unwrap();

		let chan_id = unsafe { CHAN_COUNT };
		let tx = Transaction { version: chan_id as u32, lock_time: 0, input: Vec::new(), output: Vec::new(), witness: Vec::new() };
		let funding_output = (Sha256dHash::from_data(&serialize(&tx).unwrap()[..]), chan_id);

		let events_1 = node_a.get_and_clear_pending_events();
		assert_eq!(events_1.len(), 1);
		match events_1[0] {
			Event::FundingGenerationReady { ref temporary_channel_id, ref channel_value_satoshis, output_script: _, user_channel_id } => {
				assert_eq!(*channel_value_satoshis, (1 << 24) - 1);
				assert_eq!(user_channel_id, 42);

				node_a.funding_transaction_generated(&temporary_channel_id, funding_output.clone());
				//TODO: Check that we got added to chan_monitor_a!
			},
			_ => panic!("Unexpected event"),
		}

		let events_2 = node_a.get_and_clear_pending_events();
		assert_eq!(events_2.len(), 1);
		let funding_signed = match events_2[0] {
			Event::SendFundingCreated { ref node_id, ref msg } => {
				assert_eq!(*node_id, node_b.get_our_node_id());
				node_b.handle_funding_created(&node_a.get_our_node_id(), msg).unwrap()
				//TODO: Check that we got added to chan_monitor_b!
			},
			_ => panic!("Unexpected event"),
		};

		node_a.handle_funding_signed(&node_b.get_our_node_id(), &funding_signed).unwrap();

		let events_3 = node_a.get_and_clear_pending_events();
		assert_eq!(events_3.len(), 1);
		match events_3[0] {
			Event::FundingBroadcastSafe { ref funding_txo, user_channel_id } => {
				assert_eq!(user_channel_id, 42);
				assert_eq!(*funding_txo, funding_output);
			},
			_ => panic!("Unexpected event"),
		};

		confirm_transaction(&chain_a, &tx);
		let events_4 = node_a.get_and_clear_pending_events();
		assert_eq!(events_4.len(), 1);
		match events_4[0] {
			Event::SendFundingLocked { ref node_id, ref msg, ref announcement_sigs } => {
				assert_eq!(*node_id, node_b.get_our_node_id());
				assert!(announcement_sigs.is_none());
				node_b.handle_funding_locked(&node_a.get_our_node_id(), msg).unwrap()
			},
			_ => panic!("Unexpected event"),
		};

		confirm_transaction(&chain_b, &tx);
		let events_5 = node_b.get_and_clear_pending_events();
		assert_eq!(events_5.len(), 1);
		let as_announcement_sigs = match events_5[0] {
			Event::SendFundingLocked { ref node_id, ref msg, ref announcement_sigs } => {
				assert_eq!(*node_id, node_a.get_our_node_id());
				let as_announcement_sigs = node_a.handle_funding_locked(&node_b.get_our_node_id(), msg).unwrap().unwrap();
				node_a.handle_announcement_signatures(&node_b.get_our_node_id(), &(*announcement_sigs).clone().unwrap()).unwrap();
				as_announcement_sigs
			},
			_ => panic!("Unexpected event"),
		};

		let events_6 = node_a.get_and_clear_pending_events();
		assert_eq!(events_6.len(), 1);
		let (announcement, as_update) = match events_6[0] {
			Event::BroadcastChannelAnnouncement { ref msg, ref update_msg } => {
				(msg, update_msg)
			},
			_ => panic!("Unexpected event"),
		};

		node_b.handle_announcement_signatures(&node_a.get_our_node_id(), &as_announcement_sigs).unwrap();
		let events_7 = node_b.get_and_clear_pending_events();
		assert_eq!(events_7.len(), 1);
		let bs_update = match events_7[0] {
			Event::BroadcastChannelAnnouncement { ref msg, ref update_msg } => {
				assert!(*announcement == *msg);
				update_msg
			},
			_ => panic!("Unexpected event"),
		};

		unsafe {
			CHAN_COUNT += 1;
		}

		((*announcement).clone(), (*as_update).clone(), (*bs_update).clone())
	}

	struct SendEvent {
		node_id: PublicKey,
		msgs: Vec<msgs::UpdateAddHTLC>,
		commitment_msg: msgs::CommitmentSigned,
	}
	impl SendEvent {
		fn from_event(event: Event) -> SendEvent {
			match event {
				Event::SendHTLCs{ node_id, msgs, commitment_msg } => {
					SendEvent { node_id: node_id, msgs: msgs, commitment_msg: commitment_msg }
				},
				_ => panic!("Unexpected event type!"),
			}
		}
	}

	static mut PAYMENT_COUNT: u8 = 0;
	fn send_along_route(origin_node: &ChannelManager, route: Route, expected_route: &[&ChannelManager], recv_value: u64) -> ([u8; 32], [u8; 32]) {
		let our_payment_preimage = unsafe { [PAYMENT_COUNT; 32] };
		unsafe { PAYMENT_COUNT += 1 };
		let our_payment_hash = {
			let mut sha = Sha256::new();
			sha.input(&our_payment_preimage[..]);
			let mut ret = [0; 32];
			sha.result(&mut ret);
			ret
		};

		let mut payment_event = {
			let msgs = origin_node.send_payment(route, our_payment_hash).unwrap().unwrap();
			SendEvent {
				node_id: expected_route[0].get_our_node_id(),
				msgs: vec!(msgs.0),
				commitment_msg: msgs.1,
			}
		};
		let mut prev_node = origin_node;

		for (idx, node) in expected_route.iter().enumerate() {
			assert_eq!(node.get_our_node_id(), payment_event.node_id);

			node.handle_update_add_htlc(&prev_node.get_our_node_id(), &payment_event.msgs[0]).unwrap();
			let revoke_and_ack = node.handle_commitment_signed(&prev_node.get_our_node_id(), &payment_event.commitment_msg).unwrap();
			prev_node.handle_revoke_and_ack(&node.get_our_node_id(), &revoke_and_ack).unwrap();

			let events_1 = node.get_and_clear_pending_events();
			assert_eq!(events_1.len(), 1);
			match events_1[0] {
				Event::PendingHTLCsForwardable { .. } => { },
				_ => panic!("Unexpected event"),
			};

			node.channel_state.lock().unwrap().next_forward = Instant::now();
			node.process_pending_htlc_forward();

			let mut events_2 = node.get_and_clear_pending_events();
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
				for event in events_2.drain(..) {
					payment_event = SendEvent::from_event(event);
				}
				assert_eq!(payment_event.msgs.len(), 1);
			}

			prev_node = node;
		}

		(our_payment_preimage, our_payment_hash)
	}

	fn send_payment(origin_node: &ChannelManager, origin_router: &Router, expected_route: &[&ChannelManager], recv_value: u64) {
		let route = origin_router.get_route(&expected_route.last().unwrap().get_our_node_id(), &Vec::new(), recv_value, 142).unwrap();
		assert_eq!(route.hops.len(), expected_route.len());
		for (node, hop) in expected_route.iter().zip(route.hops.iter()) {
			assert_eq!(hop.pubkey, node.get_our_node_id());
		}

		let our_payment_preimage = send_along_route(origin_node, route, expected_route, recv_value).0;

		assert!(expected_route.last().unwrap().claim_funds(our_payment_preimage));

		let mut expected_next_node = expected_route.last().unwrap().get_our_node_id();
		let mut prev_node = expected_route.last().unwrap();
		let mut next_msg = None;
		for node in expected_route.iter().rev() {
			assert_eq!(expected_next_node, node.get_our_node_id());
			match next_msg {
				Some(msg) => {
					assert!(node.handle_update_fulfill_htlc(&prev_node.get_our_node_id(), &msg).unwrap().is_none());
				}, None => {}
			}

			let events = node.get_and_clear_pending_events();
			assert_eq!(events.len(), 1);
			match events[0] {
				Event::SendFulfillHTLC { ref node_id, ref msg } => {
					expected_next_node = node_id.clone();
					next_msg = Some(msg.clone());
				},
				_ => panic!("Unexpected event"),
			};

			prev_node = node;
		}

		assert_eq!(expected_next_node, origin_node.get_our_node_id());
		assert!(origin_node.handle_update_fulfill_htlc(&expected_route.first().unwrap().get_our_node_id(), &next_msg.unwrap()).unwrap().is_none());

		let events = origin_node.get_and_clear_pending_events();
		assert_eq!(events.len(), 1);
		match events[0] {
			Event::PaymentSent { payment_preimage } => {
				assert_eq!(payment_preimage, our_payment_preimage);
			},
			_ => panic!("Unexpected event"),
		}
	}

	fn send_failed_payment(origin_node: &ChannelManager, origin_router: &Router, expected_route: &[&ChannelManager]) {
		let route = origin_router.get_route(&expected_route.last().unwrap().get_our_node_id(), &Vec::new(), 1000000, 142).unwrap();
		assert_eq!(route.hops.len(), expected_route.len());
		for (node, hop) in expected_route.iter().zip(route.hops.iter()) {
			assert_eq!(hop.pubkey, node.get_our_node_id());
		}
		let our_payment_hash = send_along_route(origin_node, route, expected_route, 1000000).1;

		assert!(expected_route.last().unwrap().fail_htlc_backwards(&our_payment_hash));

		let mut expected_next_node = expected_route.last().unwrap().get_our_node_id();
		let mut prev_node = expected_route.last().unwrap();
		let mut next_msg = None;
		for node in expected_route.iter().rev() {
			assert_eq!(expected_next_node, node.get_our_node_id());
			match next_msg {
				Some(msg) => {
					assert!(node.handle_update_fail_htlc(&prev_node.get_our_node_id(), &msg).unwrap().is_none());
				}, None => {}
			}

			let events = node.get_and_clear_pending_events();
			assert_eq!(events.len(), 1);
			match events[0] {
				Event::SendFailHTLC { ref node_id, ref msg } => {
					expected_next_node = node_id.clone();
					next_msg = Some(msg.clone());
				},
				_ => panic!("Unexpected event"),
			};

			prev_node = node;
		}

		assert_eq!(expected_next_node, origin_node.get_our_node_id());
		assert!(origin_node.handle_update_fail_htlc(&expected_route.first().unwrap().get_our_node_id(), &next_msg.unwrap()).unwrap().is_none());

		let events = origin_node.get_and_clear_pending_events();
		assert_eq!(events.len(), 1);
		match events[0] {
			Event::PaymentFailed { payment_hash } => {
				assert_eq!(payment_hash, our_payment_hash);
			},
			_ => panic!("Unexpected event"),
		}
	}

	#[test]
	fn fake_network_test() {
		// Simple test which builds a network of ChannelManagers, connects them to each other, and
		// tests that payments get routed and transactions broadcast in semi-reasonable ways.
		let mut rng = thread_rng();
		let secp_ctx = Secp256k1::new();

		let feeest_1 = Arc::new(test_utils::TestFeeEstimator { sat_per_vbyte: 1 });
		let chain_monitor_1 = Arc::new(chaininterface::ChainWatchInterfaceUtil::new());
		let chan_monitor_1 = Arc::new(test_utils::TestChannelMonitor{});
		let node_id_1 = {
			let mut key_slice = [0; 32];
			rng.fill_bytes(&mut key_slice);
			SecretKey::from_slice(&secp_ctx, &key_slice).unwrap()
		};
		let node_1 = ChannelManager::new(node_id_1.clone(), 0, true, Network::Testnet, feeest_1.clone(), chan_monitor_1.clone(), chain_monitor_1.clone()).unwrap();
		let router_1 = Router::new(PublicKey::from_secret_key(&secp_ctx, &node_id_1).unwrap());

		let feeest_2 = Arc::new(test_utils::TestFeeEstimator { sat_per_vbyte: 1 });
		let chain_monitor_2 = Arc::new(chaininterface::ChainWatchInterfaceUtil::new());
		let chan_monitor_2 = Arc::new(test_utils::TestChannelMonitor{});
		let node_id_2 = {
			let mut key_slice = [0; 32];
			rng.fill_bytes(&mut key_slice);
			SecretKey::from_slice(&secp_ctx, &key_slice).unwrap()
		};
		let node_2 = ChannelManager::new(node_id_2.clone(), 0, true, Network::Testnet, feeest_2.clone(), chan_monitor_2.clone(), chain_monitor_2.clone()).unwrap();
		let router_2 = Router::new(PublicKey::from_secret_key(&secp_ctx, &node_id_2).unwrap());

		let feeest_3 = Arc::new(test_utils::TestFeeEstimator { sat_per_vbyte: 1 });
		let chain_monitor_3 = Arc::new(chaininterface::ChainWatchInterfaceUtil::new());
		let chan_monitor_3 = Arc::new(test_utils::TestChannelMonitor{});
		let node_id_3 = {
			let mut key_slice = [0; 32];
			rng.fill_bytes(&mut key_slice);
			SecretKey::from_slice(&secp_ctx, &key_slice).unwrap()
		};
		let node_3 = ChannelManager::new(node_id_3.clone(), 0, true, Network::Testnet, feeest_3.clone(), chan_monitor_3.clone(), chain_monitor_3.clone()).unwrap();
		let router_3 = Router::new(PublicKey::from_secret_key(&secp_ctx, &node_id_3).unwrap());

		let feeest_4 = Arc::new(test_utils::TestFeeEstimator { sat_per_vbyte: 1 });
		let chain_monitor_4 = Arc::new(chaininterface::ChainWatchInterfaceUtil::new());
		let chan_monitor_4 = Arc::new(test_utils::TestChannelMonitor{});
		let node_id_4 = {
			let mut key_slice = [0; 32];
			rng.fill_bytes(&mut key_slice);
			SecretKey::from_slice(&secp_ctx, &key_slice).unwrap()
		};
		let node_4 = ChannelManager::new(node_id_4.clone(), 0, true, Network::Testnet, feeest_4.clone(), chan_monitor_4.clone(), chain_monitor_4.clone()).unwrap();
		let router_4 = Router::new(PublicKey::from_secret_key(&secp_ctx, &node_id_4).unwrap());

		// Create some initial channels
		let chan_announcement_1 = create_chan_between_nodes(&node_1, &chain_monitor_1, &node_2, &chain_monitor_2);
		for router in vec!(&router_1, &router_2, &router_3, &router_4) {
			assert!(router.handle_channel_announcement(&chan_announcement_1.0).unwrap());
			router.handle_channel_update(&chan_announcement_1.1).unwrap();
			router.handle_channel_update(&chan_announcement_1.2).unwrap();
		}
		let chan_announcement_2 = create_chan_between_nodes(&node_2, &chain_monitor_2, &node_3, &chain_monitor_3);
		for router in vec!(&router_1, &router_2, &router_3, &router_4) {
			assert!(router.handle_channel_announcement(&chan_announcement_2.0).unwrap());
			router.handle_channel_update(&chan_announcement_2.1).unwrap();
			router.handle_channel_update(&chan_announcement_2.2).unwrap();
		}
		let chan_announcement_3 = create_chan_between_nodes(&node_3, &chain_monitor_3, &node_4, &chain_monitor_4);
		for router in vec!(&router_1, &router_2, &router_3, &router_4) {
			assert!(router.handle_channel_announcement(&chan_announcement_3.0).unwrap());
			router.handle_channel_update(&chan_announcement_3.1).unwrap();
			router.handle_channel_update(&chan_announcement_3.2).unwrap();
		}

		// Send some payments
		send_payment(&node_1, &router_1, &vec!(&*node_2, &*node_3, &*node_4)[..], 1000000);
		send_payment(&node_2, &router_2, &vec!(&*node_3, &*node_4)[..], 1000000);
		send_payment(&node_4, &router_4, &vec!(&*node_3, &*node_2, &*node_1)[..], 1000000);
		send_payment(&node_4, &router_4, &vec!(&*node_3, &*node_2)[..], 250000);

		// Test failure packets
		send_failed_payment(&node_1, &router_1, &vec!(&*node_2, &*node_3, &*node_4)[..]);

		// Add a new channel that skips 3
		let chan_announcement_4 = create_chan_between_nodes(&node_2, &chain_monitor_2, &node_4, &chain_monitor_4);
		for router in vec!(&router_1, &router_2, &router_3, &router_4) {
			assert!(router.handle_channel_announcement(&chan_announcement_4.0).unwrap());
			router.handle_channel_update(&chan_announcement_4.1).unwrap();
			router.handle_channel_update(&chan_announcement_4.2).unwrap();
		}

		send_payment(&node_1, &router_1, &vec!(&*node_2, &*node_4)[..], 1000000);

		// Rebalance a bit
		let mut hops = Vec::with_capacity(3);
		hops.push(RouteHop {
			pubkey: node_3.get_our_node_id(),
			short_channel_id: chan_announcement_2.1.contents.short_channel_id,
			fee_msat: 0,
			cltv_expiry_delta: chan_announcement_3.1.contents.cltv_expiry_delta as u32
		});
		hops.push(RouteHop {
			pubkey: node_4.get_our_node_id(),
			short_channel_id: chan_announcement_3.1.contents.short_channel_id,
			fee_msat: 0,
			cltv_expiry_delta: chan_announcement_4.2.contents.cltv_expiry_delta as u32
		});
		hops.push(RouteHop {
			pubkey: node_2.get_our_node_id(),
			short_channel_id: chan_announcement_4.1.contents.short_channel_id,
			fee_msat: 250000,
			cltv_expiry_delta: 142,
		});
		hops[1].fee_msat = chan_announcement_4.2.contents.fee_base_msat as u64 + chan_announcement_4.2.contents.fee_proportional_millionths as u64 * hops[2].fee_msat as u64 / 1000000;
		hops[0].fee_msat = chan_announcement_3.1.contents.fee_base_msat as u64 + chan_announcement_3.1.contents.fee_proportional_millionths as u64 * hops[1].fee_msat as u64 / 1000000;
		send_along_route(&node_2, Route { hops }, &vec!(&*node_3, &*node_4, &*node_2)[..], 250000);

		// Check that we processed all pending events
		for node in vec!(&node_1, &node_2, &node_3, &node_4) {
			assert_eq!(node.get_and_clear_pending_events().len(), 0);
		}
	}
}
