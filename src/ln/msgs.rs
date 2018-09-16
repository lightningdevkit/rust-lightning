use secp256k1::key::PublicKey;
use secp256k1::{Secp256k1, Signature};
use secp256k1;
use bitcoin::util::hash::Sha256dHash;
use bitcoin::network::serialize::serialize;
use bitcoin::blockdata::script::Script;

use std::error::Error;
use std::{cmp, fmt};
use std::io::Read;
use std::result::Result;

use util::{byte_utils, internal_traits, events};
use util::ser::{Readable, Writeable, Writer};

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
	/// Unknown feature mandating we fail to parse message
	UnknownRequiredFeature,
	/// Failed to decode a public key (ie it's invalid)
	BadPublicKey,
	/// Failed to decode a signature (ie it's invalid)
	BadSignature,
	/// Value expected to be text wasn't decodable as text
	BadText,
	/// Buffer too short
	ShortRead,
	/// node_announcement included more than one address of a given type!
	ExtraAddressesPerType,
	/// A length descriptor in the packet didn't describe the later data correctly
	/// (currently only generated in node_announcement)
	BadLengthDescriptor,
	/// Error from std::io
	Io(::std::io::Error),
	/// 1 or 0 is not found for boolean value
	InvalidValue,
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

pub struct DataLossProtect {
	pub your_last_per_commitment_secret: [u8; 32],
	pub my_current_per_commitment_point: PublicKey,
}

pub struct ChannelReestablish {
	pub channel_id: [u8; 32],
	pub next_local_commitment_number: u64,
	pub next_remote_commitment_number: u64,
	pub data_loss_protect: Option<DataLossProtect>,
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
	pub excess_address_data: Vec<u8>,
	pub excess_data: Vec<u8>,
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
	pub excess_data: Vec<u8>,
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
	pub excess_data: Vec<u8>,
}
#[derive(PartialEq, Clone)]
pub struct ChannelUpdate {
	pub signature: Signature,
	pub contents: UnsignedChannelUpdate,
}

/// Used to put an error message in a HandleError
pub enum ErrorAction {
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
	pub update_fail_malformed_htlcs: Vec<UpdateFailMalformedHTLC>,
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

	// Connection loss/reestablish:
	/// Indicates a connection to the peer failed/an existing connection was lost. If no connection
	/// is believed to be possible in the future (eg they're sending us messages we don't
	/// understand or indicate they require unknown feature bits), no_connection_possible is set
	/// and any outstanding channels should be failed.
	fn peer_disconnected(&self, their_node_id: &PublicKey, no_connection_possible: bool);

	fn peer_connected(&self, their_node_id: &PublicKey) -> Vec<ChannelReestablish>;
	fn handle_channel_reestablish(&self, their_node_id: &PublicKey, msg: &ChannelReestablish) -> Result<(Option<FundingLocked>, Option<RevokeAndACK>, Option<CommitmentUpdate>), HandleError>;

	// Error:
	fn handle_error(&self, their_node_id: &PublicKey, msg: &ErrorMessage);
}

pub trait RoutingMessageHandler : Send + Sync {
	fn handle_node_announcement(&self, msg: &NodeAnnouncement) -> Result<bool, HandleError>;
	/// Handle a channel_announcement message, returning true if it should be forwarded on, false
	/// or returning an Err otherwise.
	fn handle_channel_announcement(&self, msg: &ChannelAnnouncement) -> Result<bool, HandleError>;
	fn handle_channel_update(&self, msg: &ChannelUpdate) -> Result<bool, HandleError>;
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
	/// In order to ensure we always return an error on Onion decode in compliance with BOLT 4, we
	/// have to deserialize OnionPackets contained in UpdateAddHTLCs even if the ephemeral public
	/// key (here) is bogus, so we hold a Result instead of a PublicKey as we'd like.
	pub public_key: Result<PublicKey, secp256k1::Error>,
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
			DecodeError::UnknownRequiredFeature => "Unknown required feature preventing decode",
			DecodeError::BadPublicKey => "Invalid public key in packet",
			DecodeError::BadSignature => "Invalid signature in packet",
			DecodeError::BadText => "Invalid text in packet",
			DecodeError::ShortRead => "Packet extended beyond the provided bytes",
			DecodeError::ExtraAddressesPerType => "More than one address of a single type",
			DecodeError::BadLengthDescriptor => "A length descriptor in the packet didn't describe the later data correctly",
			DecodeError::Io(ref e) => e.description(),
			DecodeError::InvalidValue => "0 or 1 is not found for boolean",
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

impl From<::std::io::Error> for DecodeError {
	fn from(e: ::std::io::Error) -> Self {
		if e.kind() == ::std::io::ErrorKind::UnexpectedEof {
			DecodeError::ShortRead
		} else {
			DecodeError::Io(e)
		}
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

impl MsgEncodable for ChannelReestablish {
	fn encode(&self) -> Vec<u8> {
		let mut res = Vec::with_capacity(if self.data_loss_protect.is_some() { 32+2*8+33+32 } else { 32+2*8 });

		res.extend_from_slice(&serialize(&self.channel_id).unwrap()[..]);
		res.extend_from_slice(&byte_utils::be64_to_array(self.next_local_commitment_number));
		res.extend_from_slice(&byte_utils::be64_to_array(self.next_remote_commitment_number));

		if let &Some(ref data_loss_protect) = &self.data_loss_protect {
			res.extend_from_slice(&data_loss_protect.your_last_per_commitment_secret[..]);
			res.extend_from_slice(&data_loss_protect.my_current_per_commitment_point.serialize());
		}
		res
	}
}

impl MsgEncodable for UnsignedNodeAnnouncement {
	fn encode(&self) -> Vec<u8> {
		let features = self.features.encode();
		let mut res = Vec::with_capacity(74 + features.len() + self.addresses.len()*7 + self.excess_address_data.len() + self.excess_data.len());
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
		res.extend_from_slice(&byte_utils::be16_to_array((addr_slice.len() + self.excess_address_data.len()) as u16));
		res.extend_from_slice(&addr_slice[..]);
		res.extend_from_slice(&self.excess_address_data[..]);
		res.extend_from_slice(&self.excess_data[..]);
		res
	}
}

impl MsgEncodable for UnsignedChannelAnnouncement {
	fn encode(&self) -> Vec<u8> {
		let features = self.features.encode();
		let mut res = Vec::with_capacity(172 + features.len() + self.excess_data.len());
		res.extend_from_slice(&features[..]);
		res.extend_from_slice(&self.chain_hash[..]);
		res.extend_from_slice(&byte_utils::be64_to_array(self.short_channel_id));
		res.extend_from_slice(&self.node_id_1.serialize());
		res.extend_from_slice(&self.node_id_2.serialize());
		res.extend_from_slice(&self.bitcoin_key_1.serialize());
		res.extend_from_slice(&self.bitcoin_key_2.serialize());
		res.extend_from_slice(&self.excess_data[..]);
		res
	}
}

impl MsgEncodable for UnsignedChannelUpdate {
	fn encode(&self) -> Vec<u8> {
		let mut res = Vec::with_capacity(64 + self.excess_data.len());
		res.extend_from_slice(&self.chain_hash[..]);
		res.extend_from_slice(&byte_utils::be64_to_array(self.short_channel_id));
		res.extend_from_slice(&byte_utils::be32_to_array(self.timestamp));
		res.extend_from_slice(&byte_utils::be16_to_array(self.flags));
		res.extend_from_slice(&byte_utils::be16_to_array(self.cltv_expiry_delta));
		res.extend_from_slice(&byte_utils::be64_to_array(self.htlc_minimum_msat));
		res.extend_from_slice(&byte_utils::be32_to_array(self.fee_base_msat));
		res.extend_from_slice(&byte_utils::be32_to_array(self.fee_proportional_millionths));
		res.extend_from_slice(&self.excess_data[..]);
		res
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

impl MsgEncodable for OnionHopData {
	fn encode(&self) -> Vec<u8> {
		let mut res = Vec::with_capacity(65);
		res.push(self.realm);
		res.extend_from_slice(&self.data.encode()[..]);
		res.extend_from_slice(&self.hmac);
		res
	}
}

impl MsgEncodable for OnionPacket {
	fn encode(&self) -> Vec<u8> {
		let mut res = Vec::with_capacity(1 + 33 + 20*65 + 32);
		res.push(self.version);
		match self.public_key {
			Ok(pubkey) => res.extend_from_slice(&pubkey.serialize()),
			Err(_) => res.extend_from_slice(&[0; 33]),
		}
		res.extend_from_slice(&self.hop_data);
		res.extend_from_slice(&self.hmac);
		res
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

impl_writeable_len_match!(AcceptChannel, {
		{AcceptChannel{ shutdown_scriptpubkey: Some(ref script), ..}, 270 + 2 + script.len()},
		{_, 270}
	}, {
	temporary_channel_id,
	dust_limit_satoshis,
	max_htlc_value_in_flight_msat,
	channel_reserve_satoshis,
	htlc_minimum_msat,
	minimum_depth,
	to_self_delay,
	max_accepted_htlcs,
	funding_pubkey,
	revocation_basepoint,
	payment_basepoint,
	delayed_payment_basepoint,
	htlc_basepoint,
	first_per_commitment_point,
	shutdown_scriptpubkey
});

impl_writeable!(AnnouncementSignatures, 32+8+64*2, {
	channel_id,
	short_channel_id,
	node_signature,
	bitcoin_signature
});

impl<W: Writer> Writeable<W> for ChannelReestablish {
	fn write(&self, w: &mut W) -> Result<(), ::std::io::Error> {
		w.size_hint(if self.data_loss_protect.is_some() { 32+2*8+33+32 } else { 32+2*8 });
		self.channel_id.write(w)?;
		self.next_local_commitment_number.write(w)?;
		self.next_remote_commitment_number.write(w)?;
		if let Some(ref data_loss_protect) = self.data_loss_protect {
			data_loss_protect.your_last_per_commitment_secret.write(w)?;
			data_loss_protect.my_current_per_commitment_point.write(w)?;
		}
		Ok(())
	}
}

impl<R: Read> Readable<R> for ChannelReestablish{
	fn read(r: &mut R) -> Result<Self, DecodeError> {
		Ok(Self {
			channel_id: Readable::read(r)?,
			next_local_commitment_number: Readable::read(r)?,
			next_remote_commitment_number: Readable::read(r)?,
			data_loss_protect: {
				match <[u8; 32] as Readable<R>>::read(r) {
					Ok(your_last_per_commitment_secret) =>
						Some(DataLossProtect {
							your_last_per_commitment_secret,
							my_current_per_commitment_point: Readable::read(r)?,
						}),
					Err(DecodeError::ShortRead) => None,
					Err(e) => return Err(e)
				}
			}
		})
	}
}

impl_writeable!(ClosingSigned, 32+8+64, {
	channel_id,
	fee_satoshis,
	signature
});

impl_writeable_len_match!(CommitmentSigned, {
		{ CommitmentSigned { ref htlc_signatures, .. }, 32+64+2+htlc_signatures.len()*64 }
	}, {
	channel_id,
	signature,
	htlc_signatures
});

impl_writeable_len_match!(DecodedOnionErrorPacket, {
		{ DecodedOnionErrorPacket { ref failuremsg, ref pad, .. }, 32 + 4 + failuremsg.len() + pad.len() }
	}, {
	hmac,
	failuremsg,
	pad
});

impl_writeable!(FundingCreated, 32+32+2+64, {
	temporary_channel_id,
	funding_txid,
	funding_output_index,
	signature
});

impl_writeable!(FundingSigned, 32+64, {
	channel_id,
	signature
});

impl_writeable!(FundingLocked, 32+33, {
	channel_id,
	next_per_commitment_point
});

impl_writeable_len_match!(GlobalFeatures, {
		{ GlobalFeatures { ref flags }, flags.len() + 2 }
	}, {
	flags
});

impl_writeable_len_match!(LocalFeatures, {
		{ LocalFeatures { ref flags }, flags.len() + 2 }
	}, {
	flags
});

impl_writeable_len_match!(Init, {
		{ Init { ref global_features, ref local_features }, global_features.flags.len() + local_features.flags.len() + 4 }
	}, {
	global_features,
	local_features
});

impl_writeable_len_match!(OpenChannel, {
		{ OpenChannel { shutdown_scriptpubkey: Some(ref script), .. }, 319 + 2 + script.len() },
		{ OpenChannel { shutdown_scriptpubkey: None, .. }, 319 }
	}, {
	chain_hash,
	temporary_channel_id,
	funding_satoshis,
	push_msat,
	dust_limit_satoshis,
	max_htlc_value_in_flight_msat,
	channel_reserve_satoshis,
	htlc_minimum_msat,
	feerate_per_kw,
	to_self_delay,
	max_accepted_htlcs,
	funding_pubkey,
	revocation_basepoint,
	payment_basepoint,
	delayed_payment_basepoint,
	htlc_basepoint,
	first_per_commitment_point,
	channel_flags,
	shutdown_scriptpubkey
});

impl_writeable!(RevokeAndACK, 32+32+33, {
	channel_id,
	per_commitment_secret,
	next_per_commitment_point
});

impl_writeable_len_match!(Shutdown, {
		{ Shutdown { ref scriptpubkey, .. }, 32 + 2 + scriptpubkey.len() }
	}, {
	channel_id,
	scriptpubkey
});

impl_writeable_len_match!(UpdateFailHTLC, {
		{ UpdateFailHTLC { ref reason, .. }, 32 + 10 + reason.data.len() }
	}, {
	channel_id,
	htlc_id,
	reason
});

impl_writeable!(UpdateFailMalformedHTLC, 32+8+32+2, {
	channel_id,
	htlc_id,
	sha256_of_onion,
	failure_code
});

impl_writeable!(UpdateFee, 32+4, {
	channel_id,
	feerate_per_kw
});

impl_writeable!(UpdateFulfillHTLC, 32+8+32, {
	channel_id,
	htlc_id,
	payment_preimage
});

impl_writeable_len_match!(OnionErrorPacket, {
		{ OnionErrorPacket { ref data, .. }, 2 + data.len() }
	}, {
	data
});

impl<W: Writer> Writeable<W> for OnionPacket {
	fn write(&self, w: &mut W) -> Result<(), ::std::io::Error> {
		w.size_hint(1 + 33 + 20*65 + 32);
		self.version.write(w)?;
		match self.public_key {
			Ok(pubkey) => pubkey.write(w)?,
			Err(_) => [0u8;33].write(w)?,
		}
		w.write_all(&self.hop_data)?;
		self.hmac.write(w)?;
		Ok(())
	}
}

impl<R: Read> Readable<R> for OnionPacket {
	fn read(r: &mut R) -> Result<Self, DecodeError> {
		Ok(OnionPacket {
			version: Readable::read(r)?,
			public_key: {
				let mut buf = [0u8;33];
				r.read_exact(&mut buf)?;
				PublicKey::from_slice(&Secp256k1::without_caps(), &buf)
			},
			hop_data: Readable::read(r)?,
			hmac: Readable::read(r)?,
		})
	}
}

impl_writeable!(UpdateAddHTLC, 32+8+8+32+4+1366, {
	channel_id,
	htlc_id,
	amount_msat,
	payment_hash,
	cltv_expiry,
	onion_routing_packet
});

impl<W: Writer> Writeable<W> for OnionRealm0HopData {
	fn write(&self, w: &mut W) -> Result<(), ::std::io::Error> {
		w.size_hint(32);
		self.short_channel_id.write(w)?;
		self.amt_to_forward.write(w)?;
		self.outgoing_cltv_value.write(w)?;
		w.write_all(&[0;12])?;
		Ok(())
	}
}

impl<R: Read> Readable<R> for OnionRealm0HopData {
	fn read(r: &mut R) -> Result<Self, DecodeError> {
		Ok(OnionRealm0HopData {
			short_channel_id: Readable::read(r)?,
			amt_to_forward: Readable::read(r)?,
			outgoing_cltv_value: {
				let v: u32 = Readable::read(r)?;
				r.read_exact(&mut [0; 12])?;
				v
			}
		})
	}
}

impl<W: Writer> Writeable<W> for OnionHopData {
	fn write(&self, w: &mut W) -> Result<(), ::std::io::Error> {
		w.size_hint(65);
		self.realm.write(w)?;
		self.data.write(w)?;
		self.hmac.write(w)?;
		Ok(())
	}
}

impl<R: Read> Readable<R> for OnionHopData {
	fn read(r: &mut R) -> Result<Self, DecodeError> {
		Ok(OnionHopData {
			realm: {
				let r: u8 = Readable::read(r)?;
				if r != 0 {
					return Err(DecodeError::UnknownRealmByte);
				}
				r
			},
			data: Readable::read(r)?,
			hmac: Readable::read(r)?,
		})
	}
}

impl<W: Writer> Writeable<W> for Ping {
	fn write(&self, w: &mut W) -> Result<(), ::std::io::Error> {
		w.size_hint(self.byteslen as usize + 4);
		self.ponglen.write(w)?;
		vec![0u8; self.byteslen as usize].write(w)?; // size-unchecked write
		Ok(())
	}
}

impl<R: Read> Readable<R> for Ping {
	fn read(r: &mut R) -> Result<Self, DecodeError> {
		Ok(Ping {
			ponglen: Readable::read(r)?,
			byteslen: {
				let byteslen = Readable::read(r)?;
				r.read_exact(&mut vec![0u8; byteslen as usize][..])?;
				byteslen
			}
		})
	}
}

impl<W: Writer> Writeable<W> for Pong {
	fn write(&self, w: &mut W) -> Result<(), ::std::io::Error> {
		w.size_hint(self.byteslen as usize + 2);
		vec![0u8; self.byteslen as usize].write(w)?; // size-unchecked write
		Ok(())
	}
}

impl<R: Read> Readable<R> for Pong {
	fn read(r: &mut R) -> Result<Self, DecodeError> {
		Ok(Pong {
			byteslen: {
				let byteslen = Readable::read(r)?;
				r.read_exact(&mut vec![0u8; byteslen as usize][..])?;
				byteslen
			}
		})
	}
}

impl<W: Writer> Writeable<W> for UnsignedChannelAnnouncement {
	fn write(&self, w: &mut W) -> Result<(), ::std::io::Error> {
		w.size_hint(2 + 2*32 + 4*33 + self.features.flags.len() + self.excess_data.len());
		self.features.write(w)?;
		self.chain_hash.write(w)?;
		self.short_channel_id.write(w)?;
		self.node_id_1.write(w)?;
		self.node_id_2.write(w)?;
		self.bitcoin_key_1.write(w)?;
		self.bitcoin_key_2.write(w)?;
		w.write_all(&self.excess_data[..])?;
		Ok(())
	}
}

impl<R: Read> Readable<R> for UnsignedChannelAnnouncement {
	fn read(r: &mut R) -> Result<Self, DecodeError> {
		Ok(Self {
			features: {
				let f: GlobalFeatures = Readable::read(r)?;
				if f.requires_unknown_bits() {
					return Err(DecodeError::UnknownRequiredFeature);
				}
				f
			},
			chain_hash: Readable::read(r)?,
			short_channel_id: Readable::read(r)?,
			node_id_1: Readable::read(r)?,
			node_id_2: Readable::read(r)?,
			bitcoin_key_1: Readable::read(r)?,
			bitcoin_key_2: Readable::read(r)?,
			excess_data: {
				let mut excess_data = vec![];
				r.read_to_end(&mut excess_data)?;
				excess_data
			},
		})
	}
}

impl_writeable_len_match!(ChannelAnnouncement, {
		{ ChannelAnnouncement { contents: UnsignedChannelAnnouncement {ref features, ref excess_data, ..}, .. },
			2 + 2*32 + 4*33 + features.flags.len() + excess_data.len() + 4*64 }
	}, {
	node_signature_1,
	node_signature_2,
	bitcoin_signature_1,
	bitcoin_signature_2,
	contents
});

impl<W: Writer> Writeable<W> for UnsignedChannelUpdate {
	fn write(&self, w: &mut W) -> Result<(), ::std::io::Error> {
		w.size_hint(64 + self.excess_data.len());
		self.chain_hash.write(w)?;
		self.short_channel_id.write(w)?;
		self.timestamp.write(w)?;
		self.flags.write(w)?;
		self.cltv_expiry_delta.write(w)?;
		self.htlc_minimum_msat.write(w)?;
		self.fee_base_msat.write(w)?;
		self.fee_proportional_millionths.write(w)?;
		w.write_all(&self.excess_data[..])?;
		Ok(())
	}
}

impl<R: Read> Readable<R> for UnsignedChannelUpdate {
	fn read(r: &mut R) -> Result<Self, DecodeError> {
		Ok(Self {
			chain_hash: Readable::read(r)?,
			short_channel_id: Readable::read(r)?,
			timestamp: Readable::read(r)?,
			flags: Readable::read(r)?,
			cltv_expiry_delta: Readable::read(r)?,
			htlc_minimum_msat: Readable::read(r)?,
			fee_base_msat: Readable::read(r)?,
			fee_proportional_millionths: Readable::read(r)?,
			excess_data: {
				let mut excess_data = vec![];
				r.read_to_end(&mut excess_data)?;
				excess_data
			},
		})
	}
}

impl_writeable_len_match!(ChannelUpdate, {
		{ ChannelUpdate { contents: UnsignedChannelUpdate {ref excess_data, ..}, .. },
			64 + excess_data.len() + 64 }
	}, {
	signature,
	contents
});

impl<W: Writer> Writeable<W> for ErrorMessage {
	fn write(&self, w: &mut W) -> Result<(), ::std::io::Error> {
		w.size_hint(32 + 2 + self.data.len());
		self.channel_id.write(w)?;
		(self.data.len() as u16).write(w)?;
		w.write_all(self.data.as_bytes())?;
		Ok(())
	}
}

impl<R: Read> Readable<R> for ErrorMessage {
	fn read(r: &mut R) -> Result<Self, DecodeError> {
		Ok(Self {
			channel_id: Readable::read(r)?,
			data: {
				let mut sz: usize = <u16 as Readable<R>>::read(r)? as usize;
				let mut data = vec![];
				let data_len = r.read_to_end(&mut data)?;
				sz = cmp::min(data_len, sz);
				match String::from_utf8(data[..sz as usize].to_vec()) {
					Ok(s) => s,
					Err(_) => return Err(DecodeError::BadText),
				}
			}
		})
	}
}

impl<W: Writer> Writeable<W> for UnsignedNodeAnnouncement {
	fn write(&self, w: &mut W) -> Result<(), ::std::io::Error> {
		w.size_hint(64 + 76 + self.features.flags.len() + self.addresses.len()*38 + self.excess_address_data.len() + self.excess_data.len());
		self.features.write(w)?;
		self.timestamp.write(w)?;
		self.node_id.write(w)?;
		w.write_all(&self.rgb)?;
		self.alias.write(w)?;

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
		((addr_slice.len() + self.excess_address_data.len()) as u16).write(w)?;
		w.write_all(&addr_slice[..])?;
		w.write_all(&self.excess_address_data[..])?;
		w.write_all(&self.excess_data[..])?;
		Ok(())
	}
}

impl<R: Read> Readable<R> for UnsignedNodeAnnouncement {
	fn read(r: &mut R) -> Result<Self, DecodeError> {
		let features: GlobalFeatures = Readable::read(r)?;
		if features.requires_unknown_bits() {
			return Err(DecodeError::UnknownRequiredFeature);
		}
		let timestamp: u32 = Readable::read(r)?;
		let node_id: PublicKey = Readable::read(r)?;
		let mut rgb = [0; 3];
		r.read_exact(&mut rgb)?;
		let alias: [u8; 32] = Readable::read(r)?;

		let addrlen: u16 = Readable::read(r)?;
		let mut addr_readpos = 0;
		let mut addresses = Vec::with_capacity(4);
		let mut f: u8 = 0;
		let mut excess = 0;
		loop {
			if addrlen <= addr_readpos { break; }
			f = Readable::read(r)?;
			match f {
				1 => {
					if addresses.len() > 0 {
						return Err(DecodeError::ExtraAddressesPerType);
					}
					if addrlen < addr_readpos + 1 + 6 {
						return Err(DecodeError::BadLengthDescriptor);
					}
					addresses.push(NetAddress::IPv4 {
						addr: {
							let mut addr = [0; 4];
							r.read_exact(&mut addr)?;
							addr
						},
						port: Readable::read(r)?,
					});
					addr_readpos += 1 + 6
				},
				2 => {
					if addresses.len() > 1 || (addresses.len() == 1 && addresses[0].get_id() != 1) {
						return Err(DecodeError::ExtraAddressesPerType);
					}
					if addrlen < addr_readpos + 1 + 18 {
						return Err(DecodeError::BadLengthDescriptor);
					}
					addresses.push(NetAddress::IPv6 {
						addr: {
							let mut addr = [0; 16];
							r.read_exact(&mut addr)?;
							addr
						},
						port: Readable::read(r)?,
					});
					addr_readpos += 1 + 18
				},
				3 => {
					if addresses.len() > 2 || (addresses.len() > 0 && addresses.last().unwrap().get_id() > 2) {
						return Err(DecodeError::ExtraAddressesPerType);
					}
					if addrlen < addr_readpos + 1 + 12 {
						return Err(DecodeError::BadLengthDescriptor);
					}
					addresses.push(NetAddress::OnionV2 {
						addr: {
							let mut addr = [0; 10];
							r.read_exact(&mut addr)?;
							addr
						},
						port: Readable::read(r)?,
					});
					addr_readpos += 1 + 12
				},
				4 => {
					if addresses.len() > 3 || (addresses.len() > 0 && addresses.last().unwrap().get_id() > 3) {
						return Err(DecodeError::ExtraAddressesPerType);
					}
					if addrlen < addr_readpos + 1 + 37 {
						return Err(DecodeError::BadLengthDescriptor);
					}
					addresses.push(NetAddress::OnionV3 {
						ed25519_pubkey: Readable::read(r)?,
						checksum: Readable::read(r)?,
						version: Readable::read(r)?,
						port: Readable::read(r)?,
					});
					addr_readpos += 1 + 37
				},
				_ => { excess = 1; break; }
			}
		}

		let mut excess_data = vec![];
		let excess_address_data = if addr_readpos < addrlen {
			let mut excess_address_data = vec![0; (addrlen - addr_readpos) as usize];
			r.read_exact(&mut excess_address_data[excess..])?;
			if excess == 1 {
				excess_address_data[0] = f;
			}
			excess_address_data
		} else {
			if excess == 1 {
				excess_data.push(f);
			}
			Vec::new()
		};

		Ok(UnsignedNodeAnnouncement {
			features: features,
			timestamp: timestamp,
			node_id: node_id,
			rgb: rgb,
			alias: alias,
			addresses: addresses,
			excess_address_data: excess_address_data,
			excess_data: {
				r.read_to_end(&mut excess_data)?;
				excess_data
			},
		})
	}
}

impl_writeable_len_match!(NodeAnnouncement, {
		{ NodeAnnouncement { contents: UnsignedNodeAnnouncement { ref features, ref addresses, ref excess_address_data, ref excess_data, ..}, .. },
			64 + 76 + features.flags.len() + addresses.len()*38 + excess_address_data.len() + excess_data.len() }
	}, {
	signature,
	contents
});

#[cfg(test)]
mod tests {
	use hex;
	use ln::msgs::MsgEncodable;
	use ln::msgs;
	use secp256k1::key::{PublicKey,SecretKey};
	use secp256k1::Secp256k1;

	#[test]
	fn encoding_channel_reestablish_no_secret() {
		let cr = msgs::ChannelReestablish {
			channel_id: [4, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0],
			next_local_commitment_number: 3,
			next_remote_commitment_number: 4,
			data_loss_protect: None,
		};

		let encoded_value = cr.encode();
		assert_eq!(
			encoded_value,
			vec![4, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 4]
		);
	}

	#[test]
	fn encoding_channel_reestablish_with_secret() {
		let public_key = {
			let secp_ctx = Secp256k1::new();
			PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&secp_ctx, &hex::decode("0101010101010101010101010101010101010101010101010101010101010101").unwrap()[..]).unwrap())
		};

		let cr = msgs::ChannelReestablish {
			channel_id: [4, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0],
			next_local_commitment_number: 3,
			next_remote_commitment_number: 4,
			data_loss_protect: Some(msgs::DataLossProtect { your_last_per_commitment_secret: [9;32], my_current_per_commitment_point: public_key}),
		};

		let encoded_value = cr.encode();
		assert_eq!(
			encoded_value,
			vec![4, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 4, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 3, 27, 132, 197, 86, 123, 18, 100, 64, 153, 93, 62, 213, 170, 186, 5, 101, 215, 30, 24, 52, 96, 72, 25, 255, 156, 23, 245, 233, 213, 221, 7, 143]
		);
	}
}
