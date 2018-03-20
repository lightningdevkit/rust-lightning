use secp256k1::key::PublicKey;
use secp256k1::{Secp256k1, Signature};
use bitcoin::util::uint::Uint256;
use bitcoin::util::hash::Sha256dHash;
use bitcoin::network::serialize::deserialize;
use bitcoin::blockdata::script::Script;

use std::error::Error;
use std::fmt;
use std::result::Result;

use util::{byte_utils, internal_traits, events};

pub trait MsgEncodable {
	fn encode(&self) -> Vec<u8>;
}
#[derive(Debug)]
pub enum DecodeError {
	/// Unknown realm byte in an OnionHopData packet
	UnknownRealmByte,
	/// Failed to decode a public key (ie it's invalid)
	BadPublicKey,
	/// Failed to decode a signature (ie it's invalid)
	BadSignature,
	/// Buffer not of right length (either too short or too long)
	WrongLength,
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

	pub fn supports_initial_routing_sync(&self) -> bool {
		self.flags.len() > 0 && (self.flags[0] & (1 << 3)) != 0
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

pub struct OpenChannel {
	pub chain_hash: Sha256dHash,
	pub temporary_channel_id: Uint256,
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
	pub temporary_channel_id: Uint256,
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
	pub temporary_channel_id: Uint256,
	pub funding_txid: Sha256dHash,
	pub funding_output_index: u16,
	pub signature: Signature,
}

pub struct FundingSigned {
	pub channel_id: Uint256,
	pub signature: Signature,
}

pub struct FundingLocked {
	pub channel_id: Uint256,
	pub next_per_commitment_point: PublicKey,
}

pub struct Shutdown {
	pub channel_id: Uint256,
	pub scriptpubkey: Script,
}

pub struct ClosingSigned {
	pub channel_id: Uint256,
	pub fee_satoshis: u64,
	pub signature: Signature,
}

#[derive(Clone)]
pub struct UpdateAddHTLC {
	pub channel_id: Uint256,
	pub htlc_id: u64,
	pub amount_msat: u64,
	pub payment_hash: [u8; 32],
	pub cltv_expiry: u32,
	pub onion_routing_packet: OnionPacket,
}

#[derive(Clone)]
pub struct UpdateFulfillHTLC {
	pub channel_id: Uint256,
	pub htlc_id: u64,
	pub payment_preimage: [u8; 32],
}

pub struct UpdateFailHTLC {
	pub channel_id: Uint256,
	pub htlc_id: u64,
	pub reason: OnionErrorPacket,
}

pub struct UpdateFailMalformedHTLC {
	pub channel_id: Uint256,
	pub htlc_id: u64,
	pub sha256_of_onion: [u8; 32],
	pub failure_code: u16,
}

#[derive(Clone)]
pub struct CommitmentSigned {
	pub channel_id: Uint256,
	pub signature: Signature,
	pub htlc_signatures: Vec<Signature>,
}

pub struct RevokeAndACK {
	pub channel_id: Uint256,
	pub per_commitment_secret: [u8; 32],
	pub next_per_commitment_point: PublicKey,
}

pub struct UpdateFee {
	pub channel_id: Uint256,
	pub feerate_per_kw: u32,
}

pub struct ChannelReestablish {
	pub channel_id: Uint256,
	pub next_local_commitment_number: u64,
	pub next_remote_commitment_number: u64,
	pub your_last_per_commitment_secret: Option<[u8; 32]>,
	pub my_current_per_commitment_point: PublicKey,
}

#[derive(Clone)]
pub struct AnnouncementSignatures {
	pub channel_id: Uint256,
	pub short_channel_id: u64,
	pub node_signature: Signature,
	pub bitcoin_signature: Signature,
}

#[derive(Clone)]
pub enum NetAddress {
	Dummy,
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
		//TODO: Do we need a port number here???
	},
}

pub struct UnsignedNodeAnnouncement {
	pub features: GlobalFeatures,
	pub timestamp: u32,
	pub node_id: PublicKey,
	pub rgb: [u8; 3],
	pub alias: [u8; 32],
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
pub enum ErrorMessage {
	UpdateFailHTLC {
		msg: UpdateFailHTLC
	},
	DisconnectPeer {},
}

pub struct HandleError { //TODO: rename me
	pub err: &'static str,
	pub msg: Option<ErrorMessage>, //TODO: Move into an Action enum and require it!
}

pub trait ChannelMessageHandler : events::EventsProvider {
	//Channel init:
	fn handle_open_channel(&self, their_node_id: &PublicKey, msg: &OpenChannel) -> Result<AcceptChannel, HandleError>;
	fn handle_accept_channel(&self, their_node_id: &PublicKey, msg: &AcceptChannel) -> Result<(), HandleError>;
	fn handle_funding_created(&self, their_node_id: &PublicKey, msg: &FundingCreated) -> Result<FundingSigned, HandleError>;
	fn handle_funding_signed(&self, their_node_id: &PublicKey, msg: &FundingSigned) -> Result<(), HandleError>;
	fn handle_funding_locked(&self, their_node_id: &PublicKey, msg: &FundingLocked) -> Result<Option<AnnouncementSignatures>, HandleError>;

	// Channl close:
	fn handle_shutdown(&self, their_node_id: &PublicKey, msg: &Shutdown) -> Result<(), HandleError>;
	fn handle_closing_signed(&self, their_node_id: &PublicKey, msg: &ClosingSigned) -> Result<(), HandleError>;

	// HTLC handling:
	fn handle_update_add_htlc(&self, their_node_id: &PublicKey, msg: &UpdateAddHTLC) -> Result<(), HandleError>;
	fn handle_update_fulfill_htlc(&self, their_node_id: &PublicKey, msg: &UpdateFulfillHTLC) -> Result<Option<(Vec<UpdateAddHTLC>, CommitmentSigned)>, HandleError>;
	fn handle_update_fail_htlc(&self, their_node_id: &PublicKey, msg: &UpdateFailHTLC) -> Result<Option<(Vec<UpdateAddHTLC>, CommitmentSigned)>, HandleError>;
	fn handle_update_fail_malformed_htlc(&self, their_node_id: &PublicKey, msg: &UpdateFailMalformedHTLC) -> Result<Option<(Vec<UpdateAddHTLC>, CommitmentSigned)>, HandleError>;
	fn handle_commitment_signed(&self, their_node_id: &PublicKey, msg: &CommitmentSigned) -> Result<RevokeAndACK, HandleError>;
	fn handle_revoke_and_ack(&self, their_node_id: &PublicKey, msg: &RevokeAndACK) -> Result<(), HandleError>;

	fn handle_update_fee(&self, their_node_id: &PublicKey, msg: &UpdateFee) -> Result<(), HandleError>;

	// Channel-to-announce:
	fn handle_announcement_signatures(&self, their_node_id: &PublicKey, msg: &AnnouncementSignatures) -> Result<(), HandleError>;
}

pub trait RoutingMessageHandler {
	fn handle_node_announcement(&self, msg: &NodeAnnouncement) -> Result<(), HandleError>;
	/// Handle a channel_announcement message, returning true if it should be forwarded on, false
	/// or returning an Err otherwise.
	fn handle_channel_announcement(&self, msg: &ChannelAnnouncement) -> Result<bool, HandleError>;
	fn handle_channel_update(&self, msg: &ChannelUpdate) -> Result<(), HandleError>;
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
			DecodeError::WrongLength => "Data was wrong length for packet",
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
		if v.len() < 3 { return Err(DecodeError::WrongLength); }
		let len = byte_utils::slice_to_be16(&v[0..2]) as usize;
		if v.len() < len + 2 { return Err(DecodeError::WrongLength); }
		let mut flags = Vec::with_capacity(len);
		flags.extend_from_slice(&v[2..]);
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
}

impl MsgDecodable for GlobalFeatures {
	fn decode(v: &[u8]) -> Result<Self, DecodeError> {
		if v.len() < 3 { return Err(DecodeError::WrongLength); }
		let len = byte_utils::slice_to_be16(&v[0..2]) as usize;
		if v.len() < len + 2 { return Err(DecodeError::WrongLength); }
		let mut flags = Vec::with_capacity(len);
		flags.extend_from_slice(&v[2..]);
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
		unimplemented!();
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

		Ok(Self {
			temporary_channel_id: deserialize(&v[0..32]).unwrap(),
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
		unimplemented!();
	}
}

impl MsgDecodable for FundingCreated {
	fn decode(v: &[u8]) -> Result<Self, DecodeError> {
		if v.len() < 32+32+2+64 {
			return Err(DecodeError::WrongLength);
		}
		let ctx = Secp256k1::without_caps();
		Ok(Self {
			temporary_channel_id: deserialize(&v[0..32]).unwrap(),
			funding_txid: deserialize(&v[32..64]).unwrap(),
			funding_output_index: byte_utils::slice_to_be16(&v[64..66]),
			signature: secp_signature!(&ctx, &v[66..130]),
		})
	}
}
impl MsgEncodable for FundingCreated {
	fn encode(&self) -> Vec<u8> {
		unimplemented!();
	}
}

impl MsgDecodable for FundingSigned {
	fn decode(v: &[u8]) -> Result<Self, DecodeError> {
		if v.len() < 32+64 {
			return Err(DecodeError::WrongLength);
		}
		let ctx = Secp256k1::without_caps();
		Ok(Self {
			channel_id: deserialize(&v[0..32]).unwrap(),
			signature: secp_signature!(&ctx, &v[32..96]),
		})
	}
}
impl MsgEncodable for FundingSigned {
	fn encode(&self) -> Vec<u8> {
		unimplemented!();
	}
}

impl MsgDecodable for FundingLocked {
	fn decode(v: &[u8]) -> Result<Self, DecodeError> {
		if v.len() < 32+33 {
			return Err(DecodeError::WrongLength);
		}
		let ctx = Secp256k1::without_caps();
		Ok(Self {
			channel_id: deserialize(&v[0..32]).unwrap(),
			next_per_commitment_point: secp_pubkey!(&ctx, &v[32..65]),
		})
	}
}
impl MsgEncodable for FundingLocked {
	fn encode(&self) -> Vec<u8> {
		unimplemented!();
	}
}

impl MsgDecodable for Shutdown {
	fn decode(_v: &[u8]) -> Result<Self, DecodeError> {
		unimplemented!();
	}
}
impl MsgEncodable for Shutdown {
	fn encode(&self) -> Vec<u8> {
		unimplemented!();
	}
}

impl MsgDecodable for ClosingSigned {
	fn decode(_v: &[u8]) -> Result<Self, DecodeError> {
		unimplemented!();
	}
}
impl MsgEncodable for ClosingSigned {
	fn encode(&self) -> Vec<u8> {
		unimplemented!();
	}
}

impl MsgDecodable for UpdateAddHTLC {
	fn decode(_v: &[u8]) -> Result<Self, DecodeError> {
		unimplemented!();
	}
}
impl MsgEncodable for UpdateAddHTLC {
	fn encode(&self) -> Vec<u8> {
		unimplemented!();
	}
}

impl MsgDecodable for UpdateFulfillHTLC {
	fn decode(_v: &[u8]) -> Result<Self, DecodeError> {
		unimplemented!();
	}
}
impl MsgEncodable for UpdateFulfillHTLC {
	fn encode(&self) -> Vec<u8> {
		unimplemented!();
	}
}

impl MsgDecodable for UpdateFailHTLC {
	fn decode(_v: &[u8]) -> Result<Self, DecodeError> {
		unimplemented!();
	}
}
impl MsgEncodable for UpdateFailHTLC {
	fn encode(&self) -> Vec<u8> {
		unimplemented!();
	}
}

impl MsgDecodable for UpdateFailMalformedHTLC {
	fn decode(_v: &[u8]) -> Result<Self, DecodeError> {
		unimplemented!();
	}
}
impl MsgEncodable for UpdateFailMalformedHTLC {
	fn encode(&self) -> Vec<u8> {
		unimplemented!();
	}
}

impl MsgDecodable for CommitmentSigned {
	fn decode(_v: &[u8]) -> Result<Self, DecodeError> {
		unimplemented!();
	}
}
impl MsgEncodable for CommitmentSigned {
	fn encode(&self) -> Vec<u8> {
		unimplemented!();
	}
}

impl MsgDecodable for RevokeAndACK {
	fn decode(_v: &[u8]) -> Result<Self, DecodeError> {
		unimplemented!();
	}
}
impl MsgEncodable for RevokeAndACK {
	fn encode(&self) -> Vec<u8> {
		unimplemented!();
	}
}

impl MsgDecodable for UpdateFee {
	fn decode(_v: &[u8]) -> Result<Self, DecodeError> {
		unimplemented!();
	}
}
impl MsgEncodable for UpdateFee {
	fn encode(&self) -> Vec<u8> {
		unimplemented!();
	}
}

impl MsgDecodable for ChannelReestablish {
	fn decode(_v: &[u8]) -> Result<Self, DecodeError> {
		unimplemented!();
	}
}
impl MsgEncodable for ChannelReestablish {
	fn encode(&self) -> Vec<u8> {
		unimplemented!();
	}
}

impl MsgDecodable for AnnouncementSignatures {
	fn decode(_v: &[u8]) -> Result<Self, DecodeError> {
		unimplemented!();
	}
}
impl MsgEncodable for AnnouncementSignatures {
	fn encode(&self) -> Vec<u8> {
		unimplemented!();
	}
}

impl MsgDecodable for UnsignedNodeAnnouncement {
	fn decode(_v: &[u8]) -> Result<Self, DecodeError> {
		unimplemented!();
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
		for addr in self.addresses.iter() {
			match addr {
				&NetAddress::Dummy => {},
				&NetAddress::IPv4{addr, port} => {
					addr_slice.extend_from_slice(&addr);
					addr_slice.extend_from_slice(&byte_utils::be16_to_array(port));
				},
				&NetAddress::IPv6{addr, port} => {
					addr_slice.extend_from_slice(&addr);
					addr_slice.extend_from_slice(&byte_utils::be16_to_array(port));
				},
				&NetAddress::OnionV2{addr, port} => {
					addr_slice.extend_from_slice(&addr);
					addr_slice.extend_from_slice(&byte_utils::be16_to_array(port));
				},
				&NetAddress::OnionV3{ed25519_pubkey, checksum, version} => {
					addr_slice.extend_from_slice(&ed25519_pubkey);
					addr_slice.extend_from_slice(&byte_utils::be16_to_array(checksum));
					addr_slice.push(version);
				},
			}
		}
		res.extend_from_slice(&byte_utils::be16_to_array(addr_slice.len() as u16));
		res.extend_from_slice(&addr_slice[..]);
		res
	}
}

impl MsgDecodable for NodeAnnouncement {
	fn decode(_v: &[u8]) -> Result<Self, DecodeError> {
		unimplemented!();
	}
}
impl MsgEncodable for NodeAnnouncement {
	fn encode(&self) -> Vec<u8> {
		unimplemented!();
	}
}

impl MsgDecodable for UnsignedChannelAnnouncement {
	fn decode(_v: &[u8]) -> Result<Self, DecodeError> {
		unimplemented!();
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
	fn decode(_v: &[u8]) -> Result<Self, DecodeError> {
		unimplemented!();
	}
}
impl MsgEncodable for ChannelAnnouncement {
	fn encode(&self) -> Vec<u8> {
		unimplemented!();
	}
}

impl MsgDecodable for UnsignedChannelUpdate {
	fn decode(_v: &[u8]) -> Result<Self, DecodeError> {
		unimplemented!();
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
	fn decode(_v: &[u8]) -> Result<Self, DecodeError> {
		unimplemented!();
	}
}
impl MsgEncodable for ChannelUpdate {
	fn encode(&self) -> Vec<u8> {
		let mut res = Vec::with_capacity(128);
		//TODO: Should avoid creating a new secp ctx just for a serialize call :(
		res.extend_from_slice(&self.signature.serialize_der(&Secp256k1::new())[..]); //TODO: Need in non-der form! (probably elsewhere too)
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
	fn decode(_v: &[u8]) -> Result<Self, DecodeError> {
		unimplemented!();
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
	fn decode(_v: &[u8]) -> Result<Self, DecodeError> {
		unimplemented!();
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
	fn decode(_v: &[u8]) -> Result<Self, DecodeError> {
		unimplemented!();
	}
}
impl MsgEncodable for OnionErrorPacket {
	fn encode(&self) -> Vec<u8> {
		unimplemented!();
	}
}

