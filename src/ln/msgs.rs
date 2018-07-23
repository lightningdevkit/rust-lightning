use secp256k1::key::PublicKey;
use secp256k1::{Secp256k1, Signature};
use bitcoin::util::hash::Sha256dHash;
use bitcoin::network::serialize::{deserialize,serialize};
use bitcoin::blockdata::script::Script;

use std::error::Error;
use std::fmt;
use std::result::Result;

use util::{byte_utils, internal_traits, events};

pub trait MsgEncodable {
	fn encode(&self) -> Vec<u8>;
	#[inline]
	fn encoded_len(&self) -> usize { self.encode().len() }
	#[inline]
	fn encode_with_len(&self) -> Vec<u8> {
		let enc = self.encode();
		let mut res = Vec::with_capacity(enc.len() + 2);
		res.extend_from_slice(&byte_utils::be16_to_array(enc.len() as u16));
		res.extend_from_slice(&enc);
		res
	}
}
#[derive(Debug)]
pub enum DecodeError {
	/// Unknown realm byte in an OnionHopData packet
	UnknownRealmByte,
	/// Failed to decode a public key (ie it's invalid)
	BadPublicKey,
	/// Failed to decode a signature (ie it's invalid)
	BadSignature,
	/// Value expected to be text wasn't decodable as text
	BadText,
	/// Buffer not of right length (either too short or too long)
	WrongLength,
	/// node_announcement included more than one address of a given type!
	ExtraAddressesPerType,
}
pub trait MsgDecodable: Sized {
	fn decode(v: &[u8]) -> Result<Self, DecodeError>;
}

/// Tracks localfeatures which are only in init messages
#[derive(Clone, PartialEq)]
pub struct LocalFeatures {
	flags: Vec<u8>,
}

impl LocalFeatures {
	pub fn new() -> LocalFeatures {
		LocalFeatures {
			flags: Vec::new(),
		}
	}

	pub fn supports_data_loss_protect(&self) -> bool {
		self.flags.len() > 0 && (self.flags[0] & 3) != 0
	}
	pub fn requires_data_loss_protect(&self) -> bool {
		self.flags.len() > 0 && (self.flags[0] & 1) != 0
	}

	pub fn initial_routing_sync(&self) -> bool {
		self.flags.len() > 0 && (self.flags[0] & (1 << 3)) != 0
	}
	pub fn set_initial_routing_sync(&mut self) {
		if self.flags.len() == 0 {
			self.flags.resize(1, 1 << 3);
		} else {
			self.flags[0] |= 1 << 3;
		}
	}

	pub fn supports_upfront_shutdown_script(&self) -> bool {
		self.flags.len() > 0 && (self.flags[0] & (3 << 4)) != 0
	}
	pub fn requires_upfront_shutdown_script(&self) -> bool {
		self.flags.len() > 0 && (self.flags[0] & (1 << 4)) != 0
	}

	pub fn requires_unknown_bits(&self) -> bool {
		for (idx, &byte) in self.flags.iter().enumerate() {
			if idx != 0 && (byte & 0x55) != 0 {
				return true;
			} else if idx == 0 && (byte & 0x14) != 0 {
				return true;
			}
		}
		return false;
	}

	pub fn supports_unknown_bits(&self) -> bool {
		for (idx, &byte) in self.flags.iter().enumerate() {
			if idx != 0 && byte != 0 {
				return true;
			} else if idx == 0 && (byte & 0xc4) != 0 {
				return true;
			}
		}
		return false;
	}
}

/// Tracks globalfeatures which are in init messages and routing announcements
#[derive(Clone, PartialEq)]
pub struct GlobalFeatures {
	flags: Vec<u8>,
}

impl GlobalFeatures {
	pub fn new() -> GlobalFeatures {
		GlobalFeatures {
			flags: Vec::new(),
		}
	}

	pub fn requires_unknown_bits(&self) -> bool {
		for &byte in self.flags.iter() {
			if (byte & 0x55) != 0 {
				return true;
			}
		}
		return false;
	}

	pub fn supports_unknown_bits(&self) -> bool {
		for &byte in self.flags.iter() {
			if byte != 0 {
				return true;
			}
		}
		return false;
	}
}

pub struct Init {
	pub global_features: GlobalFeatures,
	pub local_features: LocalFeatures,
}

pub struct ErrorMessage {
	pub channel_id: [u8; 32],
	pub data: String,
}

pub struct Ping {
	pub ponglen: u16,
	pub byteslen: u16,
}

pub struct Pong {
	pub byteslen: u16,
}

pub struct OpenChannel {
	pub chain_hash: Sha256dHash,
	pub temporary_channel_id: [u8; 32],
	pub funding_satoshis: u64,
	pub push_msat: u64,
	pub dust_limit_satoshis: u64,
	pub max_htlc_value_in_flight_msat: u64,
	pub channel_reserve_satoshis: u64,
	pub htlc_minimum_msat: u64,
	pub feerate_per_kw: u32,
	pub to_self_delay: u16,
	pub max_accepted_htlcs: u16,
	pub funding_pubkey: PublicKey,
	pub revocation_basepoint: PublicKey,
	pub payment_basepoint: PublicKey,
	pub delayed_payment_basepoint: PublicKey,
	pub htlc_basepoint: PublicKey,
	pub first_per_commitment_point: PublicKey,
	pub channel_flags: u8,
	pub shutdown_scriptpubkey: Option<Script>,
}

pub struct AcceptChannel {
	pub temporary_channel_id: [u8; 32],
	pub dust_limit_satoshis: u64,
	pub max_htlc_value_in_flight_msat: u64,
	pub channel_reserve_satoshis: u64,
	pub htlc_minimum_msat: u64,
	pub minimum_depth: u32,
	pub to_self_delay: u16,
	pub max_accepted_htlcs: u16,
	pub funding_pubkey: PublicKey,
	pub revocation_basepoint: PublicKey,
	pub payment_basepoint: PublicKey,
	pub delayed_payment_basepoint: PublicKey,
	pub htlc_basepoint: PublicKey,
	pub first_per_commitment_point: PublicKey,
	pub shutdown_scriptpubkey: Option<Script>,
}

pub struct FundingCreated {
	pub temporary_channel_id: [u8; 32],
	pub funding_txid: Sha256dHash,
	pub funding_output_index: u16,
	pub signature: Signature,
}

pub struct FundingSigned {
	pub channel_id: [u8; 32],
	pub signature: Signature,
}

pub struct FundingLocked {
	pub channel_id: [u8; 32],
	pub next_per_commitment_point: PublicKey,
}

pub struct Shutdown {
	pub channel_id: [u8; 32],
	pub scriptpubkey: Script,
}

pub struct ClosingSigned {
	pub channel_id: [u8; 32],
	pub fee_satoshis: u64,
	pub signature: Signature,
}

#[derive(Clone)]
pub struct UpdateAddHTLC {
	pub channel_id: [u8; 32],
	pub htlc_id: u64,
	pub amount_msat: u64,
	pub payment_hash: [u8; 32],
	pub cltv_expiry: u32,
	pub onion_routing_packet: OnionPacket,
}

#[derive(Clone)]
pub struct UpdateFulfillHTLC {
	pub channel_id: [u8; 32],
	pub htlc_id: u64,
	pub payment_preimage: [u8; 32],
}

#[derive(Clone)]
pub struct UpdateFailHTLC {
	pub channel_id: [u8; 32],
	pub htlc_id: u64,
	pub reason: OnionErrorPacket,
}

#[derive(Clone)]
pub struct UpdateFailMalformedHTLC {
	pub channel_id: [u8; 32],
	pub htlc_id: u64,
	pub sha256_of_onion: [u8; 32],
	pub failure_code: u16,
}

#[derive(Clone)]
pub struct CommitmentSigned {
	pub channel_id: [u8; 32],
	pub signature: Signature,
	pub htlc_signatures: Vec<Signature>,
}

pub struct RevokeAndACK {
	pub channel_id: [u8; 32],
	pub per_commitment_secret: [u8; 32],
	pub next_per_commitment_point: PublicKey,
}

pub struct UpdateFee {
	pub channel_id: [u8; 32],
	pub feerate_per_kw: u32,
}

pub struct ChannelReestablish {
	pub channel_id: [u8; 32],
	pub next_local_commitment_number: u64,
	pub next_remote_commitment_number: u64,
	pub your_last_per_commitment_secret: Option<[u8; 32]>,
	pub my_current_per_commitment_point: PublicKey,
}

#[derive(Clone)]
pub struct AnnouncementSignatures {
	pub channel_id: [u8; 32],
	pub short_channel_id: u64,
	pub node_signature: Signature,
	pub bitcoin_signature: Signature,
}

#[derive(Clone)]
pub enum NetAddress {
	IPv4 {
		addr: [u8; 4],
		port: u16,
	},
	IPv6 {
		addr: [u8; 16],
		port: u16,
	},
	OnionV2 {
		addr: [u8; 10],
		port: u16,
	},
	OnionV3 {
		ed25519_pubkey: [u8; 32],
		checksum: u16,
		version: u8,
		port: u16,
	},
}
impl NetAddress {
	fn get_id(&self) -> u8 {
		match self {
			&NetAddress::IPv4 {..} => { 1 },
			&NetAddress::IPv6 {..} => { 2 },
			&NetAddress::OnionV2 {..} => { 3 },
			&NetAddress::OnionV3 {..} => { 4 },
		}
	}
}

pub struct UnsignedNodeAnnouncement {
	pub features: GlobalFeatures,
	pub timestamp: u32,
	pub node_id: PublicKey,
	pub rgb: [u8; 3],
	pub alias: [u8; 32],
	/// List of addresses on which this node is reachable. Note that you may only have up to one
	/// address of each type, if you have more, they may be silently discarded or we may panic!
	pub addresses: Vec<NetAddress>,
}
pub struct NodeAnnouncement {
	pub signature: Signature,
	pub contents: UnsignedNodeAnnouncement,
}

#[derive(PartialEq, Clone)]
pub struct UnsignedChannelAnnouncement {
	pub features: GlobalFeatures,
	pub chain_hash: Sha256dHash,
	pub short_channel_id: u64,
	pub node_id_1: PublicKey,
	pub node_id_2: PublicKey,
	pub bitcoin_key_1: PublicKey,
	pub bitcoin_key_2: PublicKey,
}
#[derive(PartialEq, Clone)]
pub struct ChannelAnnouncement {
	pub node_signature_1: Signature,
	pub node_signature_2: Signature,
	pub bitcoin_signature_1: Signature,
	pub bitcoin_signature_2: Signature,
	pub contents: UnsignedChannelAnnouncement,
}

#[derive(PartialEq, Clone)]
pub struct UnsignedChannelUpdate {
	pub chain_hash: Sha256dHash,
	pub short_channel_id: u64,
	pub timestamp: u32,
	pub flags: u16,
	pub cltv_expiry_delta: u16,
	pub htlc_minimum_msat: u64,
	pub fee_base_msat: u32,
	pub fee_proportional_millionths: u32,
}
#[derive(PartialEq, Clone)]
pub struct ChannelUpdate {
	pub signature: Signature,
	pub contents: UnsignedChannelUpdate,
}

/// Used to put an error message in a HandleError
pub enum ErrorAction {
	/// Indicates an inbound HTLC add resulted in a failure, and the UpdateFailHTLC provided in msg
	/// should be sent back to the sender.
	UpdateFailHTLC {
		msg: UpdateFailHTLC
	},
	/// The peer took some action which made us think they were useless. Disconnect them.
	DisconnectPeer {
		msg: Option<ErrorMessage>
	},
	/// The peer did something harmless that we weren't able to process, just log and ignore
	IgnoreError,
	/// The peer did something incorrect. Tell them.
	SendErrorMessage {
		msg: ErrorMessage
	},
}

pub struct HandleError { //TODO: rename me
	pub err: &'static str,
	pub action: Option<ErrorAction>, //TODO: Make this required
}

/// Struct used to return values from revoke_and_ack messages, containing a bunch of commitment
/// transaction updates if they were pending.
pub struct CommitmentUpdate {
	pub update_add_htlcs: Vec<UpdateAddHTLC>,
	pub update_fulfill_htlcs: Vec<UpdateFulfillHTLC>,
	pub update_fail_htlcs: Vec<UpdateFailHTLC>,
	pub commitment_signed: CommitmentSigned,
}

pub enum HTLCFailChannelUpdate {
	ChannelUpdateMessage {
		msg: ChannelUpdate,
	},
	ChannelClosed {
		short_channel_id: u64,
	},
}

/// A trait to describe an object which can receive channel messages. Messages MAY be called in
/// paralell when they originate from different their_node_ids, however they MUST NOT be called in
/// paralell when the two calls have the same their_node_id.
pub trait ChannelMessageHandler : events::EventsProvider + Send + Sync {
	//Channel init:
	fn handle_open_channel(&self, their_node_id: &PublicKey, msg: &OpenChannel) -> Result<AcceptChannel, HandleError>;
	fn handle_accept_channel(&self, their_node_id: &PublicKey, msg: &AcceptChannel) -> Result<(), HandleError>;
	fn handle_funding_created(&self, their_node_id: &PublicKey, msg: &FundingCreated) -> Result<FundingSigned, HandleError>;
	fn handle_funding_signed(&self, their_node_id: &PublicKey, msg: &FundingSigned) -> Result<(), HandleError>;
	fn handle_funding_locked(&self, their_node_id: &PublicKey, msg: &FundingLocked) -> Result<Option<AnnouncementSignatures>, HandleError>;

	// Channl close:
	fn handle_shutdown(&self, their_node_id: &PublicKey, msg: &Shutdown) -> Result<(Option<Shutdown>, Option<ClosingSigned>), HandleError>;
	fn handle_closing_signed(&self, their_node_id: &PublicKey, msg: &ClosingSigned) -> Result<Option<ClosingSigned>, HandleError>;

	// HTLC handling:
	fn handle_update_add_htlc(&self, their_node_id: &PublicKey, msg: &UpdateAddHTLC) -> Result<(), HandleError>;
	fn handle_update_fulfill_htlc(&self, their_node_id: &PublicKey, msg: &UpdateFulfillHTLC) -> Result<(), HandleError>;
	fn handle_update_fail_htlc(&self, their_node_id: &PublicKey, msg: &UpdateFailHTLC) -> Result<Option<HTLCFailChannelUpdate>, HandleError>;
	fn handle_update_fail_malformed_htlc(&self, their_node_id: &PublicKey, msg: &UpdateFailMalformedHTLC) -> Result<(), HandleError>;
	fn handle_commitment_signed(&self, their_node_id: &PublicKey, msg: &CommitmentSigned) -> Result<(RevokeAndACK, Option<CommitmentSigned>), HandleError>;
	fn handle_revoke_and_ack(&self, their_node_id: &PublicKey, msg: &RevokeAndACK) -> Result<Option<CommitmentUpdate>, HandleError>;

	fn handle_update_fee(&self, their_node_id: &PublicKey, msg: &UpdateFee) -> Result<(), HandleError>;

	// Channel-to-announce:
	fn handle_announcement_signatures(&self, their_node_id: &PublicKey, msg: &AnnouncementSignatures) -> Result<(), HandleError>;

	// Informational:
	/// Indicates a connection to the peer failed/an existing connection was lost. If no connection
	/// is believed to be possible in the future (eg they're sending us messages we don't
	/// understand or indicate they require unknown feature bits), no_connection_possible is set
	/// and any outstanding channels should be failed.
	fn peer_disconnected(&self, their_node_id: &PublicKey, no_connection_possible: bool);
}

pub trait RoutingMessageHandler : Send + Sync {
	fn handle_node_announcement(&self, msg: &NodeAnnouncement) -> Result<(), HandleError>;
	/// Handle a channel_announcement message, returning true if it should be forwarded on, false
	/// or returning an Err otherwise.
	fn handle_channel_announcement(&self, msg: &ChannelAnnouncement) -> Result<bool, HandleError>;
	fn handle_channel_update(&self, msg: &ChannelUpdate) -> Result<(), HandleError>;
	fn handle_htlc_fail_channel_update(&self, update: &HTLCFailChannelUpdate);
}

pub struct OnionRealm0HopData {
	pub short_channel_id: u64,
	pub amt_to_forward: u64,
	pub outgoing_cltv_value: u32,
	// 12 bytes of 0-padding
}

pub struct OnionHopData {
	pub realm: u8,
	pub data: OnionRealm0HopData,
	pub hmac: [u8; 32],
}
unsafe impl internal_traits::NoDealloc for OnionHopData{}

#[derive(Clone)]
pub struct OnionPacket {
	pub version: u8,
	pub public_key: PublicKey,
	pub hop_data: [u8; 20*65],
	pub hmac: [u8; 32],
}

pub struct DecodedOnionErrorPacket {
	pub hmac: [u8; 32],
	pub failuremsg: Vec<u8>,
	pub pad: Vec<u8>,
}

#[derive(Clone)]
pub struct OnionErrorPacket {
	// This really should be a constant size slice, but the spec lets these things be up to 128KB?
	// (TODO) We limit it in decode to much lower...
	pub data: Vec<u8>,
}

impl Error for DecodeError {
	fn description(&self) -> &str {
		match *self {
			DecodeError::UnknownRealmByte => "Unknown realm byte in Onion packet",
			DecodeError::BadPublicKey => "Invalid public key in packet",
			DecodeError::BadSignature => "Invalid signature in packet",
			DecodeError::BadText => "Invalid text in packet",
			DecodeError::WrongLength => "Data was wrong length for packet",
			DecodeError::ExtraAddressesPerType => "More than one address of a single type",
		}
	}
}
impl fmt::Display for DecodeError {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		f.write_str(self.description())
	}
}

impl fmt::Debug for HandleError {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		f.write_str(self.err)
	}
}

macro_rules! secp_pubkey {
	( $ctx: expr, $slice: expr ) => {
		match PublicKey::from_slice($ctx, $slice) {
			Ok(key) => key,
			Err(_) => return Err(DecodeError::BadPublicKey)
		}
	};
}

macro_rules! secp_signature {
	( $ctx: expr, $slice: expr ) => {
		match Signature::from_compact($ctx, $slice) {
			Ok(sig) => sig,
			Err(_) => return Err(DecodeError::BadSignature)
		}
	};
}

impl MsgDecodable for LocalFeatures {
	fn decode(v: &[u8]) -> Result<Self, DecodeError> {
		if v.len() < 2 { return Err(DecodeError::WrongLength); }
		let len = byte_utils::slice_to_be16(&v[0..2]) as usize;
		if v.len() < len + 2 { return Err(DecodeError::WrongLength); }
		let mut flags = Vec::with_capacity(len);
		flags.extend_from_slice(&v[2..2 + len]);
		Ok(Self {
			flags: flags
		})
	}
}
impl MsgEncodable for LocalFeatures {
	fn encode(&self) -> Vec<u8> {
		let mut res = Vec::with_capacity(self.flags.len() + 2);
		res.extend_from_slice(&byte_utils::be16_to_array(self.flags.len() as u16));
		res.extend_from_slice(&self.flags[..]);
		res
	}
	fn encoded_len(&self) -> usize { self.flags.len() + 2 }
}

impl MsgDecodable for GlobalFeatures {
	fn decode(v: &[u8]) -> Result<Self, DecodeError> {
		if v.len() < 2 { return Err(DecodeError::WrongLength); }
		let len = byte_utils::slice_to_be16(&v[0..2]) as usize;
		if v.len() < len + 2 { return Err(DecodeError::WrongLength); }
		let mut flags = Vec::with_capacity(len);
		flags.extend_from_slice(&v[2..2 + len]);
		Ok(Self {
			flags: flags
		})
	}
}
impl MsgEncodable for GlobalFeatures {
	fn encode(&self) -> Vec<u8> {
		let mut res = Vec::with_capacity(self.flags.len() + 2);
		res.extend_from_slice(&byte_utils::be16_to_array(self.flags.len() as u16));
		res.extend_from_slice(&self.flags[..]);
		res
	}
	fn encoded_len(&self) -> usize { self.flags.len() + 2 }
}

impl MsgDecodable for Init {
	fn decode(v: &[u8]) -> Result<Self, DecodeError> {
		let global_features = GlobalFeatures::decode(v)?;
		if v.len() < global_features.flags.len() + 4 {
			return Err(DecodeError::WrongLength);
		}
		let local_features = LocalFeatures::decode(&v[global_features.flags.len() + 2..])?;
		Ok(Self {
			global_features: global_features,
			local_features: local_features,
		})
	}
}
impl MsgEncodable for Init {
	fn encode(&self) -> Vec<u8> {
		let mut res = Vec::with_capacity(self.global_features.flags.len() + self.local_features.flags.len());
		res.extend_from_slice(&self.global_features.encode()[..]);
		res.extend_from_slice(&self.local_features.encode()[..]);
		res
	}
}

impl MsgDecodable for Ping {
	fn decode(v: &[u8]) -> Result<Self, DecodeError> {
		if v.len() < 4 {
			return Err(DecodeError::WrongLength);
		}
		let ponglen = byte_utils::slice_to_be16(&v[0..2]);
		let byteslen = byte_utils::slice_to_be16(&v[2..4]);
		if v.len() < 4 + byteslen as usize {
			return Err(DecodeError::WrongLength);
		}
		Ok(Self {
			ponglen,
			byteslen,
		})
	}
}
impl MsgEncodable for Ping {
	fn encode(&self) -> Vec<u8> {
		let mut res = Vec::with_capacity(self.byteslen as usize + 2);
		res.extend_from_slice(&byte_utils::be16_to_array(self.byteslen));
		res.resize(2 + self.byteslen as usize, 0);
		res
	}
}

impl MsgDecodable for Pong {
	fn decode(v: &[u8]) -> Result<Self, DecodeError> {
		if v.len() < 2 {
			return Err(DecodeError::WrongLength);
		}
		let byteslen = byte_utils::slice_to_be16(&v[0..2]);
		if v.len() < 2 + byteslen as usize {
			return Err(DecodeError::WrongLength);
		}
		Ok(Self {
			byteslen
		})
	}
}
impl MsgEncodable for Pong {
	fn encode(&self) -> Vec<u8> {
		let mut res = Vec::with_capacity(self.byteslen as usize + 2);
		res.extend_from_slice(&byte_utils::be16_to_array(self.byteslen));
		res.resize(2 + self.byteslen as usize, 0);
		res
	}
}

impl MsgDecodable for OpenChannel {
	fn decode(v: &[u8]) -> Result<Self, DecodeError> {
		if v.len() < 2*32+6*8+4+2*2+6*33+1 {
			return Err(DecodeError::WrongLength);
		}
		let ctx = Secp256k1::without_caps();

		let mut shutdown_scriptpubkey = None;
		if v.len() >= 321 {
			let len = byte_utils::slice_to_be16(&v[319..321]) as usize;
			if v.len() < 321+len {
				return Err(DecodeError::WrongLength);
			}
			shutdown_scriptpubkey = Some(Script::from(v[321..321+len].to_vec()));
		} else if v.len() != 2*32+6*8+4+2*2+6*33+1 { // Message cant have 1 extra byte
			return Err(DecodeError::WrongLength);
		}

		Ok(OpenChannel {
			chain_hash: deserialize(&v[0..32]).unwrap(),
			temporary_channel_id: deserialize(&v[32..64]).unwrap(),
			funding_satoshis: byte_utils::slice_to_be64(&v[64..72]),
			push_msat: byte_utils::slice_to_be64(&v[72..80]),
			dust_limit_satoshis: byte_utils::slice_to_be64(&v[80..88]),
			max_htlc_value_in_flight_msat: byte_utils::slice_to_be64(&v[88..96]),
			channel_reserve_satoshis: byte_utils::slice_to_be64(&v[96..104]),
			htlc_minimum_msat: byte_utils::slice_to_be64(&v[104..112]),
			feerate_per_kw: byte_utils::slice_to_be32(&v[112..116]),
			to_self_delay: byte_utils::slice_to_be16(&v[116..118]),
			max_accepted_htlcs: byte_utils::slice_to_be16(&v[118..120]),
			funding_pubkey: secp_pubkey!(&ctx, &v[120..153]),
			revocation_basepoint: secp_pubkey!(&ctx, &v[153..186]),
			payment_basepoint: secp_pubkey!(&ctx, &v[186..219]),
			delayed_payment_basepoint: secp_pubkey!(&ctx, &v[219..252]),
			htlc_basepoint: secp_pubkey!(&ctx, &v[252..285]),
			first_per_commitment_point: secp_pubkey!(&ctx, &v[285..318]),
			channel_flags: v[318],
			shutdown_scriptpubkey: shutdown_scriptpubkey
		})
	}
}
impl MsgEncodable for OpenChannel {
	fn encode(&self) -> Vec<u8> {
		let mut res = match &self.shutdown_scriptpubkey {
			&Some(ref script) => Vec::with_capacity(319 + 2 + script.len()),
			&None => Vec::with_capacity(319),
		};
		res.extend_from_slice(&serialize(&self.chain_hash).unwrap());
		res.extend_from_slice(&serialize(&self.temporary_channel_id).unwrap());
		res.extend_from_slice(&byte_utils::be64_to_array(self.funding_satoshis));
		res.extend_from_slice(&byte_utils::be64_to_array(self.push_msat));
		res.extend_from_slice(&byte_utils::be64_to_array(self.dust_limit_satoshis));
		res.extend_from_slice(&byte_utils::be64_to_array(self.max_htlc_value_in_flight_msat));
		res.extend_from_slice(&byte_utils::be64_to_array(self.channel_reserve_satoshis));
		res.extend_from_slice(&byte_utils::be64_to_array(self.htlc_minimum_msat));
		res.extend_from_slice(&byte_utils::be32_to_array(self.feerate_per_kw));
		res.extend_from_slice(&byte_utils::be16_to_array(self.to_self_delay));
		res.extend_from_slice(&byte_utils::be16_to_array(self.max_accepted_htlcs));
		res.extend_from_slice(&self.funding_pubkey.serialize());
		res.extend_from_slice(&self.revocation_basepoint.serialize());
		res.extend_from_slice(&self.payment_basepoint.serialize());
		res.extend_from_slice(&self.delayed_payment_basepoint.serialize());
		res.extend_from_slice(&self.htlc_basepoint.serialize());
		res.extend_from_slice(&self.first_per_commitment_point.serialize());
		res.push(self.channel_flags);
		if let &Some(ref script) = &self.shutdown_scriptpubkey {
			res.extend_from_slice(&byte_utils::be16_to_array(script.len() as u16));
			res.extend_from_slice(&script[..]);
		}
		res
	}
}

impl MsgDecodable for AcceptChannel {
	fn decode(v: &[u8]) -> Result<Self, DecodeError> {
		if v.len() < 32+4*8+4+2*2+6*33 {
			return Err(DecodeError::WrongLength);
		}
		let ctx = Secp256k1::without_caps();

		let mut shutdown_scriptpubkey = None;
		if v.len() >= 272 {
			let len = byte_utils::slice_to_be16(&v[270..272]) as usize;
			if v.len() < 272+len {
				return Err(DecodeError::WrongLength);
			}
			shutdown_scriptpubkey = Some(Script::from(v[272..272+len].to_vec()));
		} else if v.len() != 32+4*8+4+2*2+6*33 { // Message cant have 1 extra byte
			return Err(DecodeError::WrongLength);
		}

		let mut temporary_channel_id = [0; 32];
		temporary_channel_id[..].copy_from_slice(&v[0..32]);
		Ok(Self {
			temporary_channel_id,
			dust_limit_satoshis: byte_utils::slice_to_be64(&v[32..40]),
			max_htlc_value_in_flight_msat: byte_utils::slice_to_be64(&v[40..48]),
			channel_reserve_satoshis: byte_utils::slice_to_be64(&v[48..56]),
			htlc_minimum_msat: byte_utils::slice_to_be64(&v[56..64]),
			minimum_depth: byte_utils::slice_to_be32(&v[64..68]),
			to_self_delay: byte_utils::slice_to_be16(&v[68..70]),
			max_accepted_htlcs: byte_utils::slice_to_be16(&v[70..72]),
			funding_pubkey: secp_pubkey!(&ctx, &v[72..105]),
			revocation_basepoint: secp_pubkey!(&ctx, &v[105..138]),
			payment_basepoint: secp_pubkey!(&ctx, &v[138..171]),
			delayed_payment_basepoint: secp_pubkey!(&ctx, &v[171..204]),
			htlc_basepoint: secp_pubkey!(&ctx, &v[204..237]),
			first_per_commitment_point: secp_pubkey!(&ctx, &v[237..270]),
			shutdown_scriptpubkey: shutdown_scriptpubkey
		})
	}
}
impl MsgEncodable for AcceptChannel {
	fn encode(&self) -> Vec<u8> {
		let mut res = match &self.shutdown_scriptpubkey {
			&Some(ref script) => Vec::with_capacity(270 + 2 + script.len()),
			&None => Vec::with_capacity(270),
		};
		res.extend_from_slice(&self.temporary_channel_id);
		res.extend_from_slice(&byte_utils::be64_to_array(self.dust_limit_satoshis));
		res.extend_from_slice(&byte_utils::be64_to_array(self.max_htlc_value_in_flight_msat));
		res.extend_from_slice(&byte_utils::be64_to_array(self.channel_reserve_satoshis));
		res.extend_from_slice(&byte_utils::be64_to_array(self.htlc_minimum_msat));
		res.extend_from_slice(&byte_utils::be32_to_array(self.minimum_depth));
		res.extend_from_slice(&byte_utils::be16_to_array(self.to_self_delay));
		res.extend_from_slice(&byte_utils::be16_to_array(self.max_accepted_htlcs));
		res.extend_from_slice(&self.funding_pubkey.serialize());
		res.extend_from_slice(&self.revocation_basepoint.serialize());
		res.extend_from_slice(&self.payment_basepoint.serialize());
		res.extend_from_slice(&self.delayed_payment_basepoint.serialize());
		res.extend_from_slice(&self.htlc_basepoint.serialize());
		res.extend_from_slice(&self.first_per_commitment_point.serialize());
		if let &Some(ref script) = &self.shutdown_scriptpubkey {
			res.extend_from_slice(&byte_utils::be16_to_array(script.len() as u16));
			res.extend_from_slice(&script[..]);
		}
		res
	}
}

impl MsgDecodable for FundingCreated {
	fn decode(v: &[u8]) -> Result<Self, DecodeError> {
		if v.len() < 32+32+2+64 {
			return Err(DecodeError::WrongLength);
		}
		let ctx = Secp256k1::without_caps();
		let mut temporary_channel_id = [0; 32];
		temporary_channel_id[..].copy_from_slice(&v[0..32]);
		Ok(Self {
			temporary_channel_id,
			funding_txid: deserialize(&v[32..64]).unwrap(),
			funding_output_index: byte_utils::slice_to_be16(&v[64..66]),
			signature: secp_signature!(&ctx, &v[66..130]),
		})
	}
}
impl MsgEncodable for FundingCreated {
	fn encode(&self) -> Vec<u8> {
		let mut res = Vec::with_capacity(32+32+2+64);
		res.extend_from_slice(&self.temporary_channel_id);
		res.extend_from_slice(&serialize(&self.funding_txid).unwrap()[..]);
		res.extend_from_slice(&byte_utils::be16_to_array(self.funding_output_index));
		let secp_ctx = Secp256k1::without_caps();
		res.extend_from_slice(&self.signature.serialize_compact(&secp_ctx));
		res
	}
}

impl MsgDecodable for FundingSigned {
	fn decode(v: &[u8]) -> Result<Self, DecodeError> {
		if v.len() < 32+64 {
			return Err(DecodeError::WrongLength);
		}
		let ctx = Secp256k1::without_caps();
		let mut channel_id = [0; 32];
		channel_id[..].copy_from_slice(&v[0..32]);
		Ok(Self {
			channel_id,
			signature: secp_signature!(&ctx, &v[32..96]),
		})
	}
}
impl MsgEncodable for FundingSigned {
	fn encode(&self) -> Vec<u8> {
		let mut res = Vec::with_capacity(32+64);
		res.extend_from_slice(&self.channel_id);
		res.extend_from_slice(&self.signature.serialize_compact(&Secp256k1::without_caps()));
		res
	}
}

impl MsgDecodable for FundingLocked {
	fn decode(v: &[u8]) -> Result<Self, DecodeError> {
		if v.len() < 32+33 {
			return Err(DecodeError::WrongLength);
		}
		let ctx = Secp256k1::without_caps();
		let mut channel_id = [0; 32];
		channel_id[..].copy_from_slice(&v[0..32]);
		Ok(Self {
			channel_id,
			next_per_commitment_point: secp_pubkey!(&ctx, &v[32..65]),
		})
	}
}
impl MsgEncodable for FundingLocked {
	fn encode(&self) -> Vec<u8> {
		let mut res = Vec::with_capacity(32+33);
		res.extend_from_slice(&self.channel_id);
		res.extend_from_slice(&self.next_per_commitment_point.serialize());
		res
	}
}

impl MsgDecodable for Shutdown {
	fn decode(v: &[u8]) -> Result<Self, DecodeError> {
		if v.len() < 32 + 2 {
			return Err(DecodeError::WrongLength);
		}
		let scriptlen = byte_utils::slice_to_be16(&v[32..34]) as usize;
		if v.len() < 32 + 2 + scriptlen {
			return Err(DecodeError::WrongLength);
		}
		let mut channel_id = [0; 32];
		channel_id[..].copy_from_slice(&v[0..32]);
		Ok(Self {
			channel_id,
			scriptpubkey: Script::from(v[34..34 + scriptlen].to_vec()),
		})
	}
}
impl MsgEncodable for Shutdown {
	fn encode(&self) -> Vec<u8> {
		let mut res = Vec::with_capacity(32 + 2 + self.scriptpubkey.len());
		res.extend_from_slice(&self.channel_id);
		res.extend_from_slice(&byte_utils::be16_to_array(self.scriptpubkey.len() as u16));
		res.extend_from_slice(&self.scriptpubkey[..]);
		res
	}
}

impl MsgDecodable for ClosingSigned {
	fn decode(v: &[u8]) -> Result<Self, DecodeError> {
		if v.len() < 32 + 8 + 64 {
			return Err(DecodeError::WrongLength);
		}
		let secp_ctx = Secp256k1::without_caps();
		let mut channel_id = [0; 32];
		channel_id[..].copy_from_slice(&v[0..32]);
		Ok(Self {
			channel_id,
			fee_satoshis: byte_utils::slice_to_be64(&v[32..40]),
			signature: secp_signature!(&secp_ctx, &v[40..104]),
		})
	}
}
impl MsgEncodable for ClosingSigned {
	fn encode(&self) -> Vec<u8> {
		let mut res = Vec::with_capacity(32+8+64);
		res.extend_from_slice(&self.channel_id);
		res.extend_from_slice(&byte_utils::be64_to_array(self.fee_satoshis));
		let secp_ctx = Secp256k1::without_caps();
		res.extend_from_slice(&self.signature.serialize_compact(&secp_ctx));
		res
	}
}

impl MsgDecodable for UpdateAddHTLC {
	fn decode(v: &[u8]) -> Result<Self, DecodeError> {
		if v.len() < 32+8+8+32+4+1+33+20*65+32 {
			return Err(DecodeError::WrongLength);
		}
		let mut channel_id = [0; 32];
		channel_id[..].copy_from_slice(&v[0..32]);
		let mut payment_hash = [0; 32];
		payment_hash.copy_from_slice(&v[48..80]);
		Ok(Self{
			channel_id,
			htlc_id: byte_utils::slice_to_be64(&v[32..40]),
			amount_msat: byte_utils::slice_to_be64(&v[40..48]),
			payment_hash,
			cltv_expiry: byte_utils::slice_to_be32(&v[80..84]),
			onion_routing_packet: OnionPacket::decode(&v[84..84+1366])?,
		})
	}
}
impl MsgEncodable for UpdateAddHTLC {
	fn encode(&self) -> Vec<u8> {
		let mut res = Vec::with_capacity(32+8+8+32+4+1+1366);
		res.extend_from_slice(&self.channel_id);
		res.extend_from_slice(&byte_utils::be64_to_array(self.htlc_id));
		res.extend_from_slice(&byte_utils::be64_to_array(self.amount_msat));
		res.extend_from_slice(&self.payment_hash);
		res.extend_from_slice(&byte_utils::be32_to_array(self.cltv_expiry));
		res.extend_from_slice(&self.onion_routing_packet.encode()[..]);
		res
	}
}

impl MsgDecodable for UpdateFulfillHTLC {
	fn decode(v: &[u8]) -> Result<Self, DecodeError> {
		if v.len() < 32+8+32 {
			return Err(DecodeError::WrongLength);
		}
		let mut channel_id = [0; 32];
		channel_id[..].copy_from_slice(&v[0..32]);
		let mut payment_preimage = [0; 32];
		payment_preimage.copy_from_slice(&v[40..72]);
		Ok(Self{
			channel_id,
			htlc_id: byte_utils::slice_to_be64(&v[32..40]),
			payment_preimage,
		})
	}
}
impl MsgEncodable for UpdateFulfillHTLC {
	fn encode(&self) -> Vec<u8> {
		let mut res = Vec::with_capacity(32+8+32);
		res.extend_from_slice(&self.channel_id);
		res.extend_from_slice(&byte_utils::be64_to_array(self.htlc_id));
		res.extend_from_slice(&self.payment_preimage);
		res
	}
}

impl MsgDecodable for UpdateFailHTLC {
	fn decode(v: &[u8]) -> Result<Self, DecodeError> {
		if v.len() < 32+8 {
			return Err(DecodeError::WrongLength);
		}
		let mut channel_id = [0; 32];
		channel_id[..].copy_from_slice(&v[0..32]);
		Ok(Self{
			channel_id,
			htlc_id: byte_utils::slice_to_be64(&v[32..40]),
			reason: OnionErrorPacket::decode(&v[40..])?,
		})
	}
}
impl MsgEncodable for UpdateFailHTLC {
	fn encode(&self) -> Vec<u8> {
		let reason = self.reason.encode();
		let mut res = Vec::with_capacity(32+8+reason.len());
		res.extend_from_slice(&self.channel_id);
		res.extend_from_slice(&byte_utils::be64_to_array(self.htlc_id));
		res.extend_from_slice(&reason[..]);
		res
	}
}

impl MsgDecodable for UpdateFailMalformedHTLC {
	fn decode(v: &[u8]) -> Result<Self, DecodeError> {
		if v.len() < 32+8+32+2 {
			return Err(DecodeError::WrongLength);
		}
		let mut channel_id = [0; 32];
		channel_id[..].copy_from_slice(&v[0..32]);
		let mut sha256_of_onion = [0; 32];
		sha256_of_onion.copy_from_slice(&v[40..72]);
		Ok(Self{
			channel_id,
			htlc_id: byte_utils::slice_to_be64(&v[32..40]),
			sha256_of_onion,
			failure_code: byte_utils::slice_to_be16(&v[72..74]),
		})
	}
}
impl MsgEncodable for UpdateFailMalformedHTLC {
	fn encode(&self) -> Vec<u8> {
		let mut res = Vec::with_capacity(32+8+32+2);
		res.extend_from_slice(&self.channel_id);
		res.extend_from_slice(&byte_utils::be64_to_array(self.htlc_id));
		res.extend_from_slice(&self.sha256_of_onion);
		res.extend_from_slice(&byte_utils::be16_to_array(self.failure_code));
		res
	}
}

impl MsgDecodable for CommitmentSigned {
	fn decode(v: &[u8]) -> Result<Self, DecodeError> {
		if v.len() < 32+64+2 {
			return Err(DecodeError::WrongLength);
		}
		let mut channel_id = [0; 32];
		channel_id[..].copy_from_slice(&v[0..32]);

		let htlcs = byte_utils::slice_to_be16(&v[96..98]) as usize;
		if v.len() < 32+64+2+htlcs*64 {
			return Err(DecodeError::WrongLength);
		}
		let mut htlc_signatures = Vec::with_capacity(htlcs);
		let secp_ctx = Secp256k1::without_caps();
		for i in 0..htlcs {
			htlc_signatures.push(secp_signature!(&secp_ctx, &v[98+i*64..98+(i+1)*64]));
		}
		Ok(Self {
			channel_id,
			signature: secp_signature!(&secp_ctx, &v[32..96]),
			htlc_signatures,
		})
	}
}
impl MsgEncodable for CommitmentSigned {
	fn encode(&self) -> Vec<u8> {
		let mut res = Vec::with_capacity(32+64+2+self.htlc_signatures.len()*64);
		res.extend_from_slice(&self.channel_id);
		let secp_ctx = Secp256k1::without_caps();
		res.extend_from_slice(&self.signature.serialize_compact(&secp_ctx));
		res.extend_from_slice(&byte_utils::be16_to_array(self.htlc_signatures.len() as u16));
		for i in 0..self.htlc_signatures.len() {
			res.extend_from_slice(&self.htlc_signatures[i].serialize_compact(&secp_ctx));
		}
		res
	}
}

impl MsgDecodable for RevokeAndACK {
	fn decode(v: &[u8]) -> Result<Self, DecodeError> {
		if v.len() < 32+32+33 {
			return Err(DecodeError::WrongLength);
		}
		let mut channel_id = [0; 32];
		channel_id[..].copy_from_slice(&v[0..32]);
		let mut per_commitment_secret = [0; 32];
		per_commitment_secret.copy_from_slice(&v[32..64]);
		let secp_ctx = Secp256k1::without_caps();
		Ok(Self {
			channel_id,
			per_commitment_secret,
			next_per_commitment_point: secp_pubkey!(&secp_ctx, &v[64..97]),
		})
	}
}
impl MsgEncodable for RevokeAndACK {
	fn encode(&self) -> Vec<u8> {
		let mut res = Vec::with_capacity(32+32+33);
		res.extend_from_slice(&self.channel_id);
		res.extend_from_slice(&self.per_commitment_secret);
		res.extend_from_slice(&self.next_per_commitment_point.serialize());
		res
	}
}

impl MsgDecodable for UpdateFee {
	fn decode(v: &[u8]) -> Result<Self, DecodeError> {
		if v.len() < 32+4 {
			return Err(DecodeError::WrongLength);
		}
		let mut channel_id = [0; 32];
		channel_id[..].copy_from_slice(&v[0..32]);
		Ok(Self {
			channel_id,
			feerate_per_kw: byte_utils::slice_to_be32(&v[32..36]),
		})
	}
}
impl MsgEncodable for UpdateFee {
	fn encode(&self) -> Vec<u8> {
		let mut res = Vec::with_capacity(32+4);
		res.extend_from_slice(&self.channel_id);
		res.extend_from_slice(&byte_utils::be32_to_array(self.feerate_per_kw));
		res
	}
}

impl MsgDecodable for ChannelReestablish {
	fn decode(v: &[u8]) -> Result<Self, DecodeError> {
		if v.len() < 32+2*8+33 {
			return Err(DecodeError::WrongLength);
		}

		let your_last_per_commitment_secret = if v.len() > 32+2*8+33 {
			if v.len() < 32+2*8+33 + 32 {
				return Err(DecodeError::WrongLength);
			}
			let mut inner_array = [0; 32];
			inner_array.copy_from_slice(&v[48..48+32]);
			Some(inner_array)
		} else { None };

		let option_size = match &your_last_per_commitment_secret {
			&Some(ref _ary) => 32,
			&None => 0,
		};
		Ok(Self {
			channel_id: deserialize(&v[0..32]).unwrap(),
			next_local_commitment_number: byte_utils::slice_to_be64(&v[32..40]),
			next_remote_commitment_number: byte_utils::slice_to_be64(&v[40..48]),
			your_last_per_commitment_secret: your_last_per_commitment_secret,
			my_current_per_commitment_point: {
				let ctx = Secp256k1::without_caps();
				secp_pubkey!(&ctx, &v[48+option_size..48+option_size+33])
			}
		})
	}
}
impl MsgEncodable for ChannelReestablish {
	fn encode(&self) -> Vec<u8> {
		let mut res = Vec::with_capacity(if self.your_last_per_commitment_secret.is_some() { 32+2*3+33 + 32 } else { 32+2*8+33 });

		res.extend_from_slice(&serialize(&self.channel_id).unwrap()[..]);
		res.extend_from_slice(&byte_utils::be64_to_array(self.next_local_commitment_number));
		res.extend_from_slice(&byte_utils::be64_to_array(self.next_remote_commitment_number));

		if let &Some(ref ary) = &self.your_last_per_commitment_secret {
			res.extend_from_slice(&ary[..]);
		}

		res.extend_from_slice(&self.my_current_per_commitment_point.serialize());
		res
	}
}

impl MsgDecodable for AnnouncementSignatures {
	fn decode(v: &[u8]) -> Result<Self, DecodeError> {
		if v.len() < 32+8+64*2 {
			return Err(DecodeError::WrongLength);
		}
		let secp_ctx = Secp256k1::without_caps();
		let mut channel_id = [0; 32];
		channel_id[..].copy_from_slice(&v[0..32]);
		Ok(Self {
			channel_id,
			short_channel_id: byte_utils::slice_to_be64(&v[32..40]),
			node_signature: secp_signature!(&secp_ctx, &v[40..104]),
			bitcoin_signature: secp_signature!(&secp_ctx, &v[104..168]),
		})
	}
}
impl MsgEncodable for AnnouncementSignatures {
	fn encode(&self) -> Vec<u8> {
		let mut res = Vec::with_capacity(32+8+64*2);
		res.extend_from_slice(&self.channel_id);
		res.extend_from_slice(&byte_utils::be64_to_array(self.short_channel_id));
		let secp_ctx = Secp256k1::without_caps();
		res.extend_from_slice(&self.node_signature.serialize_compact(&secp_ctx));
		res.extend_from_slice(&self.bitcoin_signature.serialize_compact(&secp_ctx));
		res
	}
}

impl MsgDecodable for UnsignedNodeAnnouncement {
	fn decode(v: &[u8]) -> Result<Self, DecodeError> {
		let features = GlobalFeatures::decode(&v[..])?;
		if v.len() < features.encoded_len() + 4 + 33 + 3 + 32 + 2 {
			return Err(DecodeError::WrongLength);
		}
		let start = features.encoded_len();

		let mut rgb = [0; 3];
		rgb.copy_from_slice(&v[start + 37..start + 40]);

		let mut alias = [0; 32];
		alias.copy_from_slice(&v[start + 40..start + 72]);

		let addrlen = byte_utils::slice_to_be16(&v[start + 72..start + 74]) as usize;
		if v.len() < start + 74 + addrlen {
			return Err(DecodeError::WrongLength);
		}

		let mut addresses = Vec::with_capacity(4);
		let mut read_pos = start + 74;
		loop {
			if v.len() <= read_pos { break; }
			match v[read_pos] {
				0 => { read_pos += 1; },
				1 => {
					if v.len() < read_pos + 1 + 6 {
						return Err(DecodeError::WrongLength);
					}
					if addresses.len() > 0 {
						return Err(DecodeError::ExtraAddressesPerType);
					}
					let mut addr = [0; 4];
					addr.copy_from_slice(&v[read_pos + 1..read_pos + 5]);
					addresses.push(NetAddress::IPv4 {
						addr,
						port: byte_utils::slice_to_be16(&v[read_pos + 5..read_pos + 7]),
					});
					read_pos += 1 + 6;
				},
				2 => {
					if v.len() < read_pos + 1 + 18 {
						return Err(DecodeError::WrongLength);
					}
					if addresses.len() > 1 || (addresses.len() == 1 && addresses[0].get_id() != 1) {
						return Err(DecodeError::ExtraAddressesPerType);
					}
					let mut addr = [0; 16];
					addr.copy_from_slice(&v[read_pos + 1..read_pos + 17]);
					addresses.push(NetAddress::IPv6 {
						addr,
						port: byte_utils::slice_to_be16(&v[read_pos + 17..read_pos + 19]),
					});
					read_pos += 1 + 18;
				},
				3 => {
					if v.len() < read_pos + 1 + 12 {
						return Err(DecodeError::WrongLength);
					}
					if addresses.len() > 2 || (addresses.len() > 0 && addresses.last().unwrap().get_id() > 2) {
						return Err(DecodeError::ExtraAddressesPerType);
					}
					let mut addr = [0; 10];
					addr.copy_from_slice(&v[read_pos + 1..read_pos + 11]);
					addresses.push(NetAddress::OnionV2 {
						addr,
						port: byte_utils::slice_to_be16(&v[read_pos + 11..read_pos + 13]),
					});
					read_pos += 1 + 12;
				},
				4 => {
					if v.len() < read_pos + 1 + 37 {
						return Err(DecodeError::WrongLength);
					}
					if addresses.len() > 3 || (addresses.len() > 0 && addresses.last().unwrap().get_id() > 3) {
						return Err(DecodeError::ExtraAddressesPerType);
					}
					let mut ed25519_pubkey = [0; 32];
					ed25519_pubkey.copy_from_slice(&v[read_pos + 1..read_pos + 33]);
					addresses.push(NetAddress::OnionV3 {
						ed25519_pubkey,
						checksum: byte_utils::slice_to_be16(&v[read_pos + 33..read_pos + 35]),
						version: v[read_pos + 35],
						port: byte_utils::slice_to_be16(&v[read_pos + 36..read_pos + 38]),
					});
					read_pos += 1 + 37;
				},
				_ => { break; } // We've read all we can, we dont understand anything higher (and they're sorted)
			}
		}

		let secp_ctx = Secp256k1::without_caps();
		Ok(Self {
			features,
			timestamp: byte_utils::slice_to_be32(&v[start..start + 4]),
			node_id: secp_pubkey!(&secp_ctx, &v[start + 4..start + 37]),
			rgb,
			alias,
			addresses,
		})
	}
}
impl MsgEncodable for UnsignedNodeAnnouncement {
	fn encode(&self) -> Vec<u8> {
		let features = self.features.encode();
		let mut res = Vec::with_capacity(74 + features.len() + self.addresses.len());
		res.extend_from_slice(&features[..]);
		res.extend_from_slice(&byte_utils::be32_to_array(self.timestamp));
		res.extend_from_slice(&self.node_id.serialize());
		res.extend_from_slice(&self.rgb);
		res.extend_from_slice(&self.alias);
		let mut addr_slice = Vec::with_capacity(self.addresses.len() * 18);
		let mut addrs_to_encode = self.addresses.clone();
		addrs_to_encode.sort_unstable_by(|a, b| { a.get_id().cmp(&b.get_id()) });
		addrs_to_encode.dedup_by(|a, b| { a.get_id() == b.get_id() });
		for addr in addrs_to_encode.iter() {
			match addr {
				&NetAddress::IPv4{addr, port} => {
					addr_slice.push(1);
					addr_slice.extend_from_slice(&addr);
					addr_slice.extend_from_slice(&byte_utils::be16_to_array(port));
				},
				&NetAddress::IPv6{addr, port} => {
					addr_slice.push(2);
					addr_slice.extend_from_slice(&addr);
					addr_slice.extend_from_slice(&byte_utils::be16_to_array(port));
				},
				&NetAddress::OnionV2{addr, port} => {
					addr_slice.push(3);
					addr_slice.extend_from_slice(&addr);
					addr_slice.extend_from_slice(&byte_utils::be16_to_array(port));
				},
				&NetAddress::OnionV3{ed25519_pubkey, checksum, version, port} => {
					addr_slice.push(4);
					addr_slice.extend_from_slice(&ed25519_pubkey);
					addr_slice.extend_from_slice(&byte_utils::be16_to_array(checksum));
					addr_slice.push(version);
					addr_slice.extend_from_slice(&byte_utils::be16_to_array(port));
				},
			}
		}
		res.extend_from_slice(&byte_utils::be16_to_array(addr_slice.len() as u16));
		res.extend_from_slice(&addr_slice[..]);
		res
	}
}

impl MsgDecodable for NodeAnnouncement {
	fn decode(v: &[u8]) -> Result<Self, DecodeError> {
		if v.len() < 64 {
			return Err(DecodeError::WrongLength);
		}
		let secp_ctx = Secp256k1::without_caps();
		Ok(Self {
			signature: secp_signature!(&secp_ctx, &v[0..64]),
			contents: UnsignedNodeAnnouncement::decode(&v[64..])?,
		})
	}
}
impl MsgEncodable for NodeAnnouncement {
	fn encode(&self) -> Vec<u8> {
		let contents = self.contents.encode();
		let mut res = Vec::with_capacity(64 + contents.len());
		let secp_ctx = Secp256k1::without_caps();
		res.extend_from_slice(&self.signature.serialize_compact(&secp_ctx));
		res.extend_from_slice(&contents);
		res
	}
}

impl MsgDecodable for UnsignedChannelAnnouncement {
	fn decode(v: &[u8]) -> Result<Self, DecodeError> {
		let features = GlobalFeatures::decode(&v[..])?;
		if v.len() < features.encoded_len() + 32 + 8 + 33*4 {
			return Err(DecodeError::WrongLength);
		}
		let start = features.encoded_len();
		let secp_ctx = Secp256k1::without_caps();
		Ok(Self {
			features,
			chain_hash: deserialize(&v[start..start + 32]).unwrap(),
			short_channel_id: byte_utils::slice_to_be64(&v[start + 32..start + 40]),
			node_id_1: secp_pubkey!(&secp_ctx, &v[start + 40..start + 73]),
			node_id_2: secp_pubkey!(&secp_ctx, &v[start + 73..start + 106]),
			bitcoin_key_1: secp_pubkey!(&secp_ctx, &v[start + 106..start + 139]),
			bitcoin_key_2: secp_pubkey!(&secp_ctx, &v[start + 139..start + 172]),
		})
	}
}
impl MsgEncodable for UnsignedChannelAnnouncement {
	fn encode(&self) -> Vec<u8> {
		let features = self.features.encode();
		let mut res = Vec::with_capacity(172 + features.len());
		res.extend_from_slice(&features[..]);
		res.extend_from_slice(&self.chain_hash[..]);
		res.extend_from_slice(&byte_utils::be64_to_array(self.short_channel_id));
		res.extend_from_slice(&self.node_id_1.serialize());
		res.extend_from_slice(&self.node_id_2.serialize());
		res.extend_from_slice(&self.bitcoin_key_1.serialize());
		res.extend_from_slice(&self.bitcoin_key_2.serialize());
		res
	}
}

impl MsgDecodable for ChannelAnnouncement {
	fn decode(v: &[u8]) -> Result<Self, DecodeError> {
		if v.len() < 64*4 {
			return Err(DecodeError::WrongLength);
		}
		let secp_ctx = Secp256k1::without_caps();
		Ok(Self {
			node_signature_1: secp_signature!(&secp_ctx, &v[0..64]),
			node_signature_2: secp_signature!(&secp_ctx, &v[64..128]),
			bitcoin_signature_1: secp_signature!(&secp_ctx, &v[128..192]),
			bitcoin_signature_2: secp_signature!(&secp_ctx, &v[192..256]),
			contents: UnsignedChannelAnnouncement::decode(&v[256..])?,
		})
	}
}
impl MsgEncodable for ChannelAnnouncement {
	fn encode(&self) -> Vec<u8> {
		let secp_ctx = Secp256k1::without_caps();
		let contents = self.contents.encode();
		let mut res = Vec::with_capacity(64 + contents.len());
		res.extend_from_slice(&self.node_signature_1.serialize_compact(&secp_ctx));
		res.extend_from_slice(&self.node_signature_2.serialize_compact(&secp_ctx));
		res.extend_from_slice(&self.bitcoin_signature_1.serialize_compact(&secp_ctx));
		res.extend_from_slice(&self.bitcoin_signature_2.serialize_compact(&secp_ctx));
		res.extend_from_slice(&contents);
		res
	}
}

impl MsgDecodable for UnsignedChannelUpdate {
	fn decode(v: &[u8]) -> Result<Self, DecodeError> {
		if v.len() < 32+8+4+2+2+8+4+4 {
			return Err(DecodeError::WrongLength);
		}
		Ok(Self {
			chain_hash: deserialize(&v[0..32]).unwrap(),
			short_channel_id: byte_utils::slice_to_be64(&v[32..40]),
			timestamp: byte_utils::slice_to_be32(&v[40..44]),
			flags: byte_utils::slice_to_be16(&v[44..46]),
			cltv_expiry_delta: byte_utils::slice_to_be16(&v[46..48]),
			htlc_minimum_msat: byte_utils::slice_to_be64(&v[48..56]),
			fee_base_msat: byte_utils::slice_to_be32(&v[56..60]),
			fee_proportional_millionths: byte_utils::slice_to_be32(&v[60..64]),
		})
	}
}
impl MsgEncodable for UnsignedChannelUpdate {
	fn encode(&self) -> Vec<u8> {
		let mut res = Vec::with_capacity(64);
		res.extend_from_slice(&self.chain_hash[..]);
		res.extend_from_slice(&byte_utils::be64_to_array(self.short_channel_id));
		res.extend_from_slice(&byte_utils::be32_to_array(self.timestamp));
		res.extend_from_slice(&byte_utils::be16_to_array(self.flags));
		res.extend_from_slice(&byte_utils::be16_to_array(self.cltv_expiry_delta));
		res.extend_from_slice(&byte_utils::be64_to_array(self.htlc_minimum_msat));
		res.extend_from_slice(&byte_utils::be32_to_array(self.fee_base_msat));
		res.extend_from_slice(&byte_utils::be32_to_array(self.fee_proportional_millionths));
		res
	}
}

impl MsgDecodable for ChannelUpdate {
	fn decode(v: &[u8]) -> Result<Self, DecodeError> {
		if v.len() < 128 {
			return Err(DecodeError::WrongLength);
		}
		let secp_ctx = Secp256k1::without_caps();
		Ok(Self {
			signature: secp_signature!(&secp_ctx, &v[0..64]),
			contents: UnsignedChannelUpdate::decode(&v[64..])?,
		})
	}
}
impl MsgEncodable for ChannelUpdate {
	fn encode(&self) -> Vec<u8> {
		let mut res = Vec::with_capacity(128);
		res.extend_from_slice(&self.signature.serialize_compact(&Secp256k1::without_caps())[..]);
		res.extend_from_slice(&self.contents.encode()[..]);
		res
	}
}

impl MsgDecodable for OnionRealm0HopData {
	fn decode(v: &[u8]) -> Result<Self, DecodeError> {
		if v.len() < 32 {
			return Err(DecodeError::WrongLength);
		}
		Ok(OnionRealm0HopData {
			short_channel_id: byte_utils::slice_to_be64(&v[0..8]),
			amt_to_forward: byte_utils::slice_to_be64(&v[8..16]),
			outgoing_cltv_value: byte_utils::slice_to_be32(&v[16..20]),
		})
	}
}
impl MsgEncodable for OnionRealm0HopData {
	fn encode(&self) -> Vec<u8> {
		let mut res = Vec::with_capacity(32);
		res.extend_from_slice(&byte_utils::be64_to_array(self.short_channel_id));
		res.extend_from_slice(&byte_utils::be64_to_array(self.amt_to_forward));
		res.extend_from_slice(&byte_utils::be32_to_array(self.outgoing_cltv_value));
		res.resize(32, 0);
		res
	}
}

impl MsgDecodable for OnionHopData {
	fn decode(v: &[u8]) -> Result<Self, DecodeError> {
		if v.len() < 65 {
			return Err(DecodeError::WrongLength);
		}
		let realm = v[0];
		if realm != 0 {
			return Err(DecodeError::UnknownRealmByte);
		}
		let mut hmac = [0; 32];
		hmac[..].copy_from_slice(&v[33..65]);
		Ok(OnionHopData {
			realm: realm,
			data: OnionRealm0HopData::decode(&v[1..33])?,
			hmac: hmac,
		})
	}
}
impl MsgEncodable for OnionHopData {
	fn encode(&self) -> Vec<u8> {
		let mut res = Vec::with_capacity(65);
		res.push(self.realm);
		res.extend_from_slice(&self.data.encode()[..]);
		res.extend_from_slice(&self.hmac);
		res
	}
}

impl MsgDecodable for OnionPacket {
	fn decode(v: &[u8]) -> Result<Self, DecodeError> {
		if v.len() < 1+33+20*65+32 {
			return Err(DecodeError::WrongLength);
		}
		let mut hop_data = [0; 20*65];
		hop_data.copy_from_slice(&v[34..1334]);
		let mut hmac = [0; 32];
		hmac.copy_from_slice(&v[1334..1366]);
		let secp_ctx = Secp256k1::without_caps();
		Ok(Self {
			version: v[0],
			public_key: secp_pubkey!(&secp_ctx, &v[1..34]),
			hop_data,
			hmac,
		})
	}
}
impl MsgEncodable for OnionPacket {
	fn encode(&self) -> Vec<u8> {
		let mut res = Vec::with_capacity(1 + 33 + 20*65 + 32);
		res.push(self.version);
		res.extend_from_slice(&self.public_key.serialize());
		res.extend_from_slice(&self.hop_data);
		res.extend_from_slice(&self.hmac);
		res
	}
}

impl MsgDecodable for DecodedOnionErrorPacket {
	fn decode(v: &[u8]) -> Result<Self, DecodeError> {
		if v.len() < 32 + 4 {
			return Err(DecodeError::WrongLength);
		}
		let failuremsg_len = byte_utils::slice_to_be16(&v[32..34]) as usize;
		if v.len() < 32 + 4 + failuremsg_len {
			return Err(DecodeError::WrongLength);
		}
		let padding_len = byte_utils::slice_to_be16(&v[34 + failuremsg_len..]) as usize;
		if v.len() < 32 + 4 + failuremsg_len + padding_len {
			return Err(DecodeError::WrongLength);
		}

		let mut hmac = [0; 32];
		hmac.copy_from_slice(&v[0..32]);
		Ok(Self {
			hmac,
			failuremsg: v[34..34 + failuremsg_len].to_vec(),
			pad: v[36 + failuremsg_len..36 + failuremsg_len + padding_len].to_vec(),
		})
	}
}
impl MsgEncodable for DecodedOnionErrorPacket {
	fn encode(&self) -> Vec<u8> {
		let mut res = Vec::with_capacity(32 + 4 + self.failuremsg.len() + self.pad.len());
		res.extend_from_slice(&self.hmac);
		res.extend_from_slice(&[((self.failuremsg.len() >> 8) & 0xff) as u8, (self.failuremsg.len() & 0xff) as u8]);
		res.extend_from_slice(&self.failuremsg);
		res.extend_from_slice(&[((self.pad.len() >> 8) & 0xff) as u8, (self.pad.len() & 0xff) as u8]);
		res.extend_from_slice(&self.pad);
		res
	}
}

impl MsgDecodable for OnionErrorPacket {
	fn decode(v: &[u8]) -> Result<Self, DecodeError> {
		if v.len() < 2 {
			return Err(DecodeError::WrongLength);
		}
		let len = byte_utils::slice_to_be16(&v[0..2]) as usize;
		if v.len() < 2 + len {
			return Err(DecodeError::WrongLength);
		}
		Ok(Self {
			data: v[2..len+2].to_vec(),
		})
	}
}
impl MsgEncodable for OnionErrorPacket {
	fn encode(&self) -> Vec<u8> {
		let mut res = Vec::with_capacity(2 + self.data.len());
		res.extend_from_slice(&byte_utils::be16_to_array(self.data.len() as u16));
		res.extend_from_slice(&self.data);
		res
	}
}

impl MsgEncodable for ErrorMessage {
	fn encode(&self) -> Vec<u8> {
		let mut res = Vec::with_capacity(34 + self.data.len());
		res.extend_from_slice(&self.channel_id);
		res.extend_from_slice(&byte_utils::be16_to_array(self.data.len() as u16));
		res.extend_from_slice(&self.data.as_bytes());
		res
	}
}
impl MsgDecodable for ErrorMessage {
	fn decode(v: &[u8]) -> Result<Self,DecodeError> {
		if v.len() < 34 {
			return Err(DecodeError::WrongLength);
		}
		let len = byte_utils::slice_to_be16(&v[32..34]);
		if v.len() < 34 + len as usize {
			return Err(DecodeError::WrongLength);
		}
		let data = match String::from_utf8(v[34..34 + len as usize].to_vec()) {
			Ok(s) => s,
			Err(_) => return Err(DecodeError::BadText),
		};
		let mut channel_id = [0; 32];
		channel_id[..].copy_from_slice(&v[0..32]);
		Ok(Self {
			channel_id,
			data,
		})
	}
}

#[cfg(test)]
mod tests {
	use bitcoin::util::misc::hex_bytes;
	use ln::msgs::MsgEncodable;
	use ln::msgs;
	use secp256k1::key::{PublicKey,SecretKey};
	use secp256k1::Secp256k1;

	#[test]
	fn encoding_channel_reestablish_no_secret() {
		let public_key = {
			let secp_ctx = Secp256k1::new();
			PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&secp_ctx, &hex_bytes("0101010101010101010101010101010101010101010101010101010101010101").unwrap()[..]).unwrap()).unwrap()
		};

		let cr = msgs::ChannelReestablish {
			channel_id: [4, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0],
			next_local_commitment_number: 3,
			next_remote_commitment_number: 4,
			your_last_per_commitment_secret: None,
			my_current_per_commitment_point: public_key,
		};

		let encoded_value = cr.encode();
		assert_eq!(
			encoded_value,
			vec![4, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 4, 3, 27, 132, 197, 86, 123, 18, 100, 64, 153, 93, 62, 213, 170, 186, 5, 101, 215, 30, 24, 52, 96, 72, 25, 255, 156, 23, 245, 233, 213, 221, 7, 143]
		);
	}

	#[test]
	fn encoding_channel_reestablish_with_secret() {
		let public_key = {
			let secp_ctx = Secp256k1::new();
			PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&secp_ctx, &hex_bytes("0101010101010101010101010101010101010101010101010101010101010101").unwrap()[..]).unwrap()).unwrap()
		};

		let cr = msgs::ChannelReestablish {
			channel_id: [4, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0],
			next_local_commitment_number: 3,
			next_remote_commitment_number: 4,
			your_last_per_commitment_secret: Some([9; 32]),
			my_current_per_commitment_point: public_key,
		};

		let encoded_value = cr.encode();
		assert_eq!(
			encoded_value,
			vec![4, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 4, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 3, 27, 132, 197, 86, 123, 18, 100, 64, 153, 93, 62, 213, 170, 186, 5, 101, 215, 30, 24, 52, 96, 72, 25, 255, 156, 23, 245, 233, 213, 221, 7, 143]
		);
	}
}
