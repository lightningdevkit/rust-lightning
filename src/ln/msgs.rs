//! Wire messages, traits representing wire message handlers, and a few error types live here.
//!
//! For a normal node you probably don't need to use anything here, however, if you wish to split a
//! node into an internet-facing route/message socket handling daemon and a separate daemon (or
//! server entirely) which handles only channel-related messages you may wish to implement
//! ChannelMessageHandler yourself and use it to re-serialize messages and pass them across
//! daemons/servers.
//!
//! Note that if you go with such an architecture (instead of passing raw socket events to a
//! non-internet-facing system) you trust the frontend internet-facing system to not lie about the
//! source node_id of the mssage, however this does allow you to significantly reduce bandwidth
//! between the systems as routing messages can represent a significant chunk of bandwidth usage
//! (especially for non-channel-publicly-announcing nodes). As an alternate design which avoids
//! this issue, if you have sufficient bidirectional bandwidth between your systems, you may send
//! raw socket events into your non-internet-facing system and then send routing events back to
//! track the network on the less-secure system.

use secp256k1::key::PublicKey;
use secp256k1::{Secp256k1, Signature};
use secp256k1;
use bitcoin::util::hash::Sha256dHash;
use bitcoin::blockdata::script::Script;

use std::error::Error;
use std::{cmp, fmt};
use std::io::Read;
use std::result::Result;

use util::{byte_utils, events};
use util::ser::{Readable, Writeable, Writer};

use ln::channelmanager::{PaymentPreimage, PaymentHash};

/// An error in decoding a message or struct.
#[derive(Debug)]
pub enum DecodeError {
	/// A version byte specified something we don't know how to handle.
	/// Includes unknown realm byte in an OnionHopData packet
	UnknownVersion,
	/// Unknown feature mandating we fail to parse message
	UnknownRequiredFeature,
	/// Value was invalid, eg a byte which was supposed to be a bool was something other than a 0
	/// or 1, a public key/private key/signature was invalid, text wasn't UTF-8, etc
	InvalidValue,
	/// Buffer too short
	ShortRead,
	/// node_announcement included more than one address of a given type!
	ExtraAddressesPerType,
	/// A length descriptor in the packet didn't describe the later data correctly
	/// (currently only generated in node_announcement)
	BadLengthDescriptor,
	/// Error from std::io
	Io(::std::io::Error),
}

/// Tracks localfeatures which are only in init messages
#[derive(Clone, PartialEq)]
pub struct LocalFeatures {
	flags: Vec<u8>,
}

impl LocalFeatures {
	pub(crate) fn new() -> LocalFeatures {
		LocalFeatures {
			flags: Vec::new(),
		}
	}

	pub(crate) fn supports_data_loss_protect(&self) -> bool {
		self.flags.len() > 0 && (self.flags[0] & 3) != 0
	}
	pub(crate) fn requires_data_loss_protect(&self) -> bool {
		self.flags.len() > 0 && (self.flags[0] & 1) != 0
	}

	pub(crate) fn initial_routing_sync(&self) -> bool {
		self.flags.len() > 0 && (self.flags[0] & (1 << 3)) != 0
	}
	pub(crate) fn set_initial_routing_sync(&mut self) {
		if self.flags.len() == 0 {
			self.flags.resize(1, 1 << 3);
		} else {
			self.flags[0] |= 1 << 3;
		}
	}

	pub(crate) fn supports_upfront_shutdown_script(&self) -> bool {
		self.flags.len() > 0 && (self.flags[0] & (3 << 4)) != 0
	}
	pub(crate) fn requires_upfront_shutdown_script(&self) -> bool {
		self.flags.len() > 0 && (self.flags[0] & (1 << 4)) != 0
	}

	pub(crate) fn requires_unknown_bits(&self) -> bool {
		for (idx, &byte) in self.flags.iter().enumerate() {
			if idx != 0 && (byte & 0x55) != 0 {
				return true;
			} else if idx == 0 && (byte & 0x14) != 0 {
				return true;
			}
		}
		return false;
	}

	pub(crate) fn supports_unknown_bits(&self) -> bool {
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
	pub(crate) fn new() -> GlobalFeatures {
		GlobalFeatures {
			flags: Vec::new(),
		}
	}

	pub(crate) fn requires_unknown_bits(&self) -> bool {
		for &byte in self.flags.iter() {
			if (byte & 0x55) != 0 {
				return true;
			}
		}
		return false;
	}

	pub(crate) fn supports_unknown_bits(&self) -> bool {
		for &byte in self.flags.iter() {
			if byte != 0 {
				return true;
			}
		}
		return false;
	}
}

/// An init message to be sent or received from a peer
pub struct Init {
	pub(crate) global_features: GlobalFeatures,
	pub(crate) local_features: LocalFeatures,
}

/// An error message to be sent or received from a peer
#[derive(Clone)]
pub struct ErrorMessage {
	pub(crate) channel_id: [u8; 32],
	pub(crate) data: String,
}

/// A ping message to be sent or received from a peer
pub struct Ping {
	pub(crate) ponglen: u16,
	pub(crate) byteslen: u16,
}

/// A pong message to be sent or received from a peer
pub struct Pong {
	pub(crate) byteslen: u16,
}

/// An open_channel message to be sent or received from a peer
#[derive(Clone)]
pub struct OpenChannel {
	pub(crate) chain_hash: Sha256dHash,
	pub(crate) temporary_channel_id: [u8; 32],
	pub(crate) funding_satoshis: u64,
	pub(crate) push_msat: u64,
	pub(crate) dust_limit_satoshis: u64,
	pub(crate) max_htlc_value_in_flight_msat: u64,
	pub(crate) channel_reserve_satoshis: u64,
	pub(crate) htlc_minimum_msat: u64,
	pub(crate) feerate_per_kw: u32,
	pub(crate) to_self_delay: u16,
	pub(crate) max_accepted_htlcs: u16,
	pub(crate) funding_pubkey: PublicKey,
	pub(crate) revocation_basepoint: PublicKey,
	pub(crate) payment_basepoint: PublicKey,
	pub(crate) delayed_payment_basepoint: PublicKey,
	pub(crate) htlc_basepoint: PublicKey,
	pub(crate) first_per_commitment_point: PublicKey,
	pub(crate) channel_flags: u8,
	pub(crate) shutdown_scriptpubkey: Option<Script>,
}

/// An accept_channel message to be sent or received from a peer
#[derive(Clone)]
pub struct AcceptChannel {
	pub(crate) temporary_channel_id: [u8; 32],
	pub(crate) dust_limit_satoshis: u64,
	pub(crate) max_htlc_value_in_flight_msat: u64,
	pub(crate) channel_reserve_satoshis: u64,
	pub(crate) htlc_minimum_msat: u64,
	pub(crate) minimum_depth: u32,
	pub(crate) to_self_delay: u16,
	pub(crate) max_accepted_htlcs: u16,
	pub(crate) funding_pubkey: PublicKey,
	pub(crate) revocation_basepoint: PublicKey,
	pub(crate) payment_basepoint: PublicKey,
	pub(crate) delayed_payment_basepoint: PublicKey,
	pub(crate) htlc_basepoint: PublicKey,
	pub(crate) first_per_commitment_point: PublicKey,
	pub(crate) shutdown_scriptpubkey: Option<Script>,
}

/// A funding_created message to be sent or received from a peer
#[derive(Clone)]
pub struct FundingCreated {
	pub(crate) temporary_channel_id: [u8; 32],
	pub(crate) funding_txid: Sha256dHash,
	pub(crate) funding_output_index: u16,
	pub(crate) signature: Signature,
}

/// A funding_signed message to be sent or received from a peer
#[derive(Clone)]
pub struct FundingSigned {
	pub(crate) channel_id: [u8; 32],
	pub(crate) signature: Signature,
}

/// A funding_locked message to be sent or received from a peer
#[derive(Clone, PartialEq)]
pub struct FundingLocked {
	pub(crate) channel_id: [u8; 32],
	pub(crate) next_per_commitment_point: PublicKey,
}

/// A shutdown message to be sent or received from a peer
#[derive(Clone, PartialEq)]
pub struct Shutdown {
	pub(crate) channel_id: [u8; 32],
	pub(crate) scriptpubkey: Script,
}

/// A closing_signed message to be sent or received from a peer
#[derive(Clone, PartialEq)]
pub struct ClosingSigned {
	pub(crate) channel_id: [u8; 32],
	pub(crate) fee_satoshis: u64,
	pub(crate) signature: Signature,
}

/// An update_add_htlc message to be sent or received from a peer
#[derive(Clone, PartialEq)]
pub struct UpdateAddHTLC {
	pub(crate) channel_id: [u8; 32],
	pub(crate) htlc_id: u64,
	pub(crate) amount_msat: u64,
	pub(crate) payment_hash: PaymentHash,
	pub(crate) cltv_expiry: u32,
	pub(crate) onion_routing_packet: OnionPacket,
}

/// An update_fulfill_htlc message to be sent or received from a peer
#[derive(Clone, PartialEq)]
pub struct UpdateFulfillHTLC {
	pub(crate) channel_id: [u8; 32],
	pub(crate) htlc_id: u64,
	pub(crate) payment_preimage: PaymentPreimage,
}

/// An update_fail_htlc message to be sent or received from a peer
#[derive(Clone, PartialEq)]
pub struct UpdateFailHTLC {
	pub(crate) channel_id: [u8; 32],
	pub(crate) htlc_id: u64,
	pub(crate) reason: OnionErrorPacket,
}

/// An update_fail_malformed_htlc message to be sent or received from a peer
#[derive(Clone, PartialEq)]
pub struct UpdateFailMalformedHTLC {
	pub(crate) channel_id: [u8; 32],
	pub(crate) htlc_id: u64,
	pub(crate) sha256_of_onion: [u8; 32],
	pub(crate) failure_code: u16,
}

/// A commitment_signed message to be sent or received from a peer
#[derive(Clone, PartialEq)]
pub struct CommitmentSigned {
	pub(crate) channel_id: [u8; 32],
	pub(crate) signature: Signature,
	pub(crate) htlc_signatures: Vec<Signature>,
}

/// A revoke_and_ack message to be sent or received from a peer
#[derive(Clone, PartialEq)]
pub struct RevokeAndACK {
	pub(crate) channel_id: [u8; 32],
	pub(crate) per_commitment_secret: [u8; 32],
	pub(crate) next_per_commitment_point: PublicKey,
}

/// An update_fee message to be sent or received from a peer
#[derive(PartialEq, Clone)]
pub struct UpdateFee {
	pub(crate) channel_id: [u8; 32],
	pub(crate) feerate_per_kw: u32,
}

#[derive(PartialEq, Clone)]
pub(crate) struct DataLossProtect {
	pub(crate) your_last_per_commitment_secret: [u8; 32],
	pub(crate) my_current_per_commitment_point: PublicKey,
}

/// A channel_reestablish message to be sent or received from a peer
#[derive(PartialEq, Clone)]
pub struct ChannelReestablish {
	pub(crate) channel_id: [u8; 32],
	pub(crate) next_local_commitment_number: u64,
	pub(crate) next_remote_commitment_number: u64,
	pub(crate) data_loss_protect: Option<DataLossProtect>,
}

/// An announcement_signatures message to be sent or received from a peer
#[derive(Clone)]
pub struct AnnouncementSignatures {
	pub(crate) channel_id: [u8; 32],
	pub(crate) short_channel_id: u64,
	pub(crate) node_signature: Signature,
	pub(crate) bitcoin_signature: Signature,
}

/// An address which can be used to connect to a remote peer
#[derive(Clone)]
pub enum NetAddress {
	/// An IPv4 address/port on which the peer is listenting.
	IPv4 {
		/// The 4-byte IPv4 address
		addr: [u8; 4],
		/// The port on which the node is listenting
		port: u16,
	},
	/// An IPv6 address/port on which the peer is listenting.
	IPv6 {
		/// The 16-byte IPv6 address
		addr: [u8; 16],
		/// The port on which the node is listenting
		port: u16,
	},
	/// An old-style Tor onion address/port on which the peer is listening.
	OnionV2 {
		/// The bytes (usually encoded in base32 with ".onion" appended)
		addr: [u8; 10],
		/// The port on which the node is listenting
		port: u16,
	},
	/// A new-style Tor onion address/port on which the peer is listening.
	/// To create the human-readable "hostname", concatenate ed25519_pubkey, checksum, and version,
	/// wrap as base32 and append ".onion".
	OnionV3 {
		/// The ed25519 long-term public key of the peer
		ed25519_pubkey: [u8; 32],
		/// The checksum of the pubkey and version, as included in the onion address
		checksum: u16,
		/// The version byte, as defined by the Tor Onion v3 spec.
		version: u8,
		/// The port on which the node is listenting
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

#[derive(Clone)]
// Only exposed as broadcast of node_announcement should be filtered by node_id
/// The unsigned part of a node_announcement
pub struct UnsignedNodeAnnouncement {
	pub(crate) features: GlobalFeatures,
	pub(crate) timestamp: u32,
	/// The node_id this announcement originated from (don't rebroadcast the node_announcement back
	/// to this node).
	pub        node_id: PublicKey,
	pub(crate) rgb: [u8; 3],
	pub(crate) alias: [u8; 32],
	/// List of addresses on which this node is reachable. Note that you may only have up to one
	/// address of each type, if you have more, they may be silently discarded or we may panic!
	pub(crate) addresses: Vec<NetAddress>,
	pub(crate) excess_address_data: Vec<u8>,
	pub(crate) excess_data: Vec<u8>,
}
#[derive(Clone)]
/// A node_announcement message to be sent or received from a peer
pub struct NodeAnnouncement {
	pub(crate) signature: Signature,
	pub(crate) contents: UnsignedNodeAnnouncement,
}

// Only exposed as broadcast of channel_announcement should be filtered by node_id
/// The unsigned part of a channel_announcement
#[derive(PartialEq, Clone)]
pub struct UnsignedChannelAnnouncement {
	pub(crate) features: GlobalFeatures,
	pub(crate) chain_hash: Sha256dHash,
	pub(crate) short_channel_id: u64,
	/// One of the two node_ids which are endpoints of this channel
	pub        node_id_1: PublicKey,
	/// The other of the two node_ids which are endpoints of this channel
	pub        node_id_2: PublicKey,
	pub(crate) bitcoin_key_1: PublicKey,
	pub(crate) bitcoin_key_2: PublicKey,
	pub(crate) excess_data: Vec<u8>,
}
/// A channel_announcement message to be sent or received from a peer
#[derive(PartialEq, Clone)]
pub struct ChannelAnnouncement {
	pub(crate) node_signature_1: Signature,
	pub(crate) node_signature_2: Signature,
	pub(crate) bitcoin_signature_1: Signature,
	pub(crate) bitcoin_signature_2: Signature,
	pub(crate) contents: UnsignedChannelAnnouncement,
}

#[derive(PartialEq, Clone)]
pub(crate) struct UnsignedChannelUpdate {
	pub(crate) chain_hash: Sha256dHash,
	pub(crate) short_channel_id: u64,
	pub(crate) timestamp: u32,
	pub(crate) flags: u16,
	pub(crate) cltv_expiry_delta: u16,
	pub(crate) htlc_minimum_msat: u64,
	pub(crate) fee_base_msat: u32,
	pub(crate) fee_proportional_millionths: u32,
	pub(crate) excess_data: Vec<u8>,
}
/// A channel_update message to be sent or received from a peer
#[derive(PartialEq, Clone)]
pub struct ChannelUpdate {
	pub(crate) signature: Signature,
	pub(crate) contents: UnsignedChannelUpdate,
}

/// Used to put an error message in a HandleError
#[derive(Clone)]
pub enum ErrorAction {
	/// The peer took some action which made us think they were useless. Disconnect them.
	DisconnectPeer {
		/// An error message which we should make an effort to send before we disconnect.
		msg: Option<ErrorMessage>
	},
	/// The peer did something harmless that we weren't able to process, just log and ignore
	IgnoreError,
	/// The peer did something incorrect. Tell them.
	SendErrorMessage {
		/// The message to send.
		msg: ErrorMessage
	},
}

/// An Err type for failure to process messages.
pub struct HandleError { //TODO: rename me
	/// A human-readable message describing the error
	pub err: &'static str,
	/// The action which should be taken against the offending peer.
	pub action: Option<ErrorAction>, //TODO: Make this required
}

/// Struct used to return values from revoke_and_ack messages, containing a bunch of commitment
/// transaction updates if they were pending.
#[derive(PartialEq, Clone)]
pub struct CommitmentUpdate {
	pub(crate) update_add_htlcs: Vec<UpdateAddHTLC>,
	pub(crate) update_fulfill_htlcs: Vec<UpdateFulfillHTLC>,
	pub(crate) update_fail_htlcs: Vec<UpdateFailHTLC>,
	pub(crate) update_fail_malformed_htlcs: Vec<UpdateFailMalformedHTLC>,
	pub(crate) update_fee: Option<UpdateFee>,
	pub(crate) commitment_signed: CommitmentSigned,
}

/// The information we received from a peer along the route of a payment we originated. This is
/// returned by ChannelMessageHandler::handle_update_fail_htlc to be passed into
/// RoutingMessageHandler::handle_htlc_fail_channel_update to update our network map.
#[derive(Clone)]
pub enum HTLCFailChannelUpdate {
	/// We received an error which included a full ChannelUpdate message.
	ChannelUpdateMessage {
		/// The unwrapped message we received
		msg: ChannelUpdate,
	},
	/// We received an error which indicated only that a channel has been closed
	ChannelClosed {
		/// The short_channel_id which has now closed.
		short_channel_id: u64,
		/// when this true, this channel should be permanently removed from the
		/// consideration. Otherwise, this channel can be restored as new channel_update is received
		is_permanent: bool,
	},
	/// We received an error which indicated only that a node has failed
	NodeFailure {
		/// The node_id that has failed.
		node_id: PublicKey,
		/// when this true, node should be permanently removed from the
		/// consideration. Otherwise, the channels connected to this node can be
		/// restored as new channel_update is received
		is_permanent: bool,
	}
}

/// A trait to describe an object which can receive channel messages.
///
/// Messages MAY be called in parallel when they originate from different their_node_ids, however
/// they MUST NOT be called in parallel when the two calls have the same their_node_id.
pub trait ChannelMessageHandler : events::MessageSendEventsProvider + Send + Sync {
	//Channel init:
	/// Handle an incoming open_channel message from the given peer.
	fn handle_open_channel(&self, their_node_id: &PublicKey, msg: &OpenChannel) -> Result<(), HandleError>;
	/// Handle an incoming accept_channel message from the given peer.
	fn handle_accept_channel(&self, their_node_id: &PublicKey, msg: &AcceptChannel) -> Result<(), HandleError>;
	/// Handle an incoming funding_created message from the given peer.
	fn handle_funding_created(&self, their_node_id: &PublicKey, msg: &FundingCreated) -> Result<(), HandleError>;
	/// Handle an incoming funding_signed message from the given peer.
	fn handle_funding_signed(&self, their_node_id: &PublicKey, msg: &FundingSigned) -> Result<(), HandleError>;
	/// Handle an incoming funding_locked message from the given peer.
	fn handle_funding_locked(&self, their_node_id: &PublicKey, msg: &FundingLocked) -> Result<(), HandleError>;

	// Channl close:
	/// Handle an incoming shutdown message from the given peer.
	fn handle_shutdown(&self, their_node_id: &PublicKey, msg: &Shutdown) -> Result<(), HandleError>;
	/// Handle an incoming closing_signed message from the given peer.
	fn handle_closing_signed(&self, their_node_id: &PublicKey, msg: &ClosingSigned) -> Result<(), HandleError>;

	// HTLC handling:
	/// Handle an incoming update_add_htlc message from the given peer.
	fn handle_update_add_htlc(&self, their_node_id: &PublicKey, msg: &UpdateAddHTLC) -> Result<(), HandleError>;
	/// Handle an incoming update_fulfill_htlc message from the given peer.
	fn handle_update_fulfill_htlc(&self, their_node_id: &PublicKey, msg: &UpdateFulfillHTLC) -> Result<(), HandleError>;
	/// Handle an incoming update_fail_htlc message from the given peer.
	fn handle_update_fail_htlc(&self, their_node_id: &PublicKey, msg: &UpdateFailHTLC) -> Result<(), HandleError>;
	/// Handle an incoming update_fail_malformed_htlc message from the given peer.
	fn handle_update_fail_malformed_htlc(&self, their_node_id: &PublicKey, msg: &UpdateFailMalformedHTLC) -> Result<(), HandleError>;
	/// Handle an incoming commitment_signed message from the given peer.
	fn handle_commitment_signed(&self, their_node_id: &PublicKey, msg: &CommitmentSigned) -> Result<(), HandleError>;
	/// Handle an incoming revoke_and_ack message from the given peer.
	fn handle_revoke_and_ack(&self, their_node_id: &PublicKey, msg: &RevokeAndACK) -> Result<(), HandleError>;

	/// Handle an incoming update_fee message from the given peer.
	fn handle_update_fee(&self, their_node_id: &PublicKey, msg: &UpdateFee) -> Result<(), HandleError>;

	// Channel-to-announce:
	/// Handle an incoming announcement_signatures message from the given peer.
	fn handle_announcement_signatures(&self, their_node_id: &PublicKey, msg: &AnnouncementSignatures) -> Result<(), HandleError>;

	// Connection loss/reestablish:
	/// Indicates a connection to the peer failed/an existing connection was lost. If no connection
	/// is believed to be possible in the future (eg they're sending us messages we don't
	/// understand or indicate they require unknown feature bits), no_connection_possible is set
	/// and any outstanding channels should be failed.
	fn peer_disconnected(&self, their_node_id: &PublicKey, no_connection_possible: bool);

	/// Handle a peer reconnecting, possibly generating channel_reestablish message(s).
	fn peer_connected(&self, their_node_id: &PublicKey);
	/// Handle an incoming channel_reestablish message from the given peer.
	fn handle_channel_reestablish(&self, their_node_id: &PublicKey, msg: &ChannelReestablish) -> Result<(), HandleError>;

	// Error:
	/// Handle an incoming error message from the given peer.
	fn handle_error(&self, their_node_id: &PublicKey, msg: &ErrorMessage);
}

/// A trait to describe an object which can receive routing messages.
pub trait RoutingMessageHandler : Send + Sync {
	/// Handle an incoming node_announcement message, returning true if it should be forwarded on,
	/// false or returning an Err otherwise.
	fn handle_node_announcement(&self, msg: &NodeAnnouncement) -> Result<bool, HandleError>;
	/// Handle a channel_announcement message, returning true if it should be forwarded on, false
	/// or returning an Err otherwise.
	fn handle_channel_announcement(&self, msg: &ChannelAnnouncement) -> Result<bool, HandleError>;
	/// Handle an incoming channel_update message, returning true if it should be forwarded on,
	/// false or returning an Err otherwise.
	fn handle_channel_update(&self, msg: &ChannelUpdate) -> Result<bool, HandleError>;
	/// Handle some updates to the route graph that we learned due to an outbound failed payment.
	fn handle_htlc_fail_channel_update(&self, update: &HTLCFailChannelUpdate);
	/// Gets a subset of the channel announcements and updates required to dump our routing table
	/// to a remote node, starting at the short_channel_id indicated by starting_point and
	/// including batch_amount entries.
	fn get_next_channel_announcements(&self, starting_point: u64, batch_amount: u8) -> Vec<(ChannelAnnouncement, ChannelUpdate, ChannelUpdate)>;
	/// Gets a subset of the node announcements required to dump our routing table to a remote node,
	/// starting at the node *after* the provided publickey and including batch_amount entries.
	/// If None is provided for starting_point, we start at the first node.
	fn get_next_node_announcements(&self, starting_point: Option<&PublicKey>, batch_amount: u8) -> Vec<NodeAnnouncement>;
}

pub(crate) struct OnionRealm0HopData {
	pub(crate) short_channel_id: u64,
	pub(crate) amt_to_forward: u64,
	pub(crate) outgoing_cltv_value: u32,
	// 12 bytes of 0-padding
}

mod fuzzy_internal_msgs {
	// These types aren't intended to be pub, but are exposed for direct fuzzing (as we deserialize
	// them from untrusted input):

	use super::OnionRealm0HopData;
	pub struct OnionHopData {
		pub(crate) realm: u8,
		pub(crate) data: OnionRealm0HopData,
		pub(crate) hmac: [u8; 32],
	}
	unsafe impl ::util::internal_traits::NoDealloc for OnionHopData{}

	pub struct DecodedOnionErrorPacket {
		pub(crate) hmac: [u8; 32],
		pub(crate) failuremsg: Vec<u8>,
		pub(crate) pad: Vec<u8>,
	}
}
#[cfg(feature = "fuzztarget")]
pub use self::fuzzy_internal_msgs::*;
#[cfg(not(feature = "fuzztarget"))]
pub(crate) use self::fuzzy_internal_msgs::*;

#[derive(Clone)]
pub(crate) struct OnionPacket {
	pub(crate) version: u8,
	/// In order to ensure we always return an error on Onion decode in compliance with BOLT 4, we
	/// have to deserialize OnionPackets contained in UpdateAddHTLCs even if the ephemeral public
	/// key (here) is bogus, so we hold a Result instead of a PublicKey as we'd like.
	pub(crate) public_key: Result<PublicKey, secp256k1::Error>,
	pub(crate) hop_data: [u8; 20*65],
	pub(crate) hmac: [u8; 32],
}

impl PartialEq for OnionPacket {
	fn eq(&self, other: &OnionPacket) -> bool {
		for (i, j) in self.hop_data.iter().zip(other.hop_data.iter()) {
			if i != j { return false; }
		}
		self.version == other.version &&
			self.public_key == other.public_key &&
			self.hmac == other.hmac
	}
}

#[derive(Clone, PartialEq)]
pub(crate) struct OnionErrorPacket {
	// This really should be a constant size slice, but the spec lets these things be up to 128KB?
	// (TODO) We limit it in decode to much lower...
	pub(crate) data: Vec<u8>,
}

impl Error for DecodeError {
	fn description(&self) -> &str {
		match *self {
			DecodeError::UnknownVersion => "Unknown realm byte in Onion packet",
			DecodeError::UnknownRequiredFeature => "Unknown required feature preventing decode",
			DecodeError::InvalidValue => "Nonsense bytes didn't map to the type they were interpreted as",
			DecodeError::ShortRead => "Packet extended beyond the provided bytes",
			DecodeError::ExtraAddressesPerType => "More than one address of a single type",
			DecodeError::BadLengthDescriptor => "A length descriptor in the packet didn't describe the later data correctly",
			DecodeError::Io(ref e) => e.description(),
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

impl Writeable for ChannelReestablish {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), ::std::io::Error> {
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

impl Writeable for OnionPacket {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), ::std::io::Error> {
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

impl Writeable for OnionRealm0HopData {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), ::std::io::Error> {
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

impl Writeable for OnionHopData {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), ::std::io::Error> {
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
					return Err(DecodeError::UnknownVersion);
				}
				r
			},
			data: Readable::read(r)?,
			hmac: Readable::read(r)?,
		})
	}
}

impl Writeable for Ping {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), ::std::io::Error> {
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

impl Writeable for Pong {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), ::std::io::Error> {
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

impl Writeable for UnsignedChannelAnnouncement {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), ::std::io::Error> {
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

impl Writeable for UnsignedChannelUpdate {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), ::std::io::Error> {
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

impl Writeable for ErrorMessage {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), ::std::io::Error> {
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
					Err(_) => return Err(DecodeError::InvalidValue),
				}
			}
		})
	}
}

impl Writeable for UnsignedNodeAnnouncement {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), ::std::io::Error> {
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
	use ln::msgs;
	use util::ser::Writeable;
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
