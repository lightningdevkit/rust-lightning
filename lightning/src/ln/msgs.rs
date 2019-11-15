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
//! source node_id of the message, however this does allow you to significantly reduce bandwidth
//! between the systems as routing messages can represent a significant chunk of bandwidth usage
//! (especially for non-channel-publicly-announcing nodes). As an alternate design which avoids
//! this issue, if you have sufficient bidirectional bandwidth between your systems, you may send
//! raw socket events into your non-internet-facing system and then send routing events back to
//! track the network on the less-secure system.

use secp256k1::key::PublicKey;
use secp256k1::Signature;
use secp256k1;
use bitcoin_hashes::sha256d::Hash as Sha256dHash;
use bitcoin::blockdata::script::Script;

use std::error::Error;
use std::{cmp, fmt};
use std::io::Read;
use std::result::Result;

use util::events;
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
	/// Create a blank LocalFeatures flags (visibility extended for fuzz tests)
	#[cfg(not(feature = "fuzztarget"))]
	pub(crate) fn new() -> LocalFeatures {
		LocalFeatures {
			flags: vec![2 | 1 << 5],
		}
	}
	#[cfg(feature = "fuzztarget")]
	pub fn new() -> LocalFeatures {
		LocalFeatures {
			flags: vec![2 | 1 << 5],
		}
	}

	pub(crate) fn supports_data_loss_protect(&self) -> bool {
		self.flags.len() > 0 && (self.flags[0] & 3) != 0
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
	#[cfg(test)]
	pub(crate) fn unset_upfront_shutdown_script(&mut self) {
		self.flags[0] ^= 1 << 5;
	}

	pub(crate) fn requires_unknown_bits(&self) -> bool {
		self.flags.iter().enumerate().any(|(idx, &byte)| {
			( idx != 0 && (byte & 0x55) != 0 ) || ( idx == 0 && (byte & 0x14) != 0 )
		})
	}

	pub(crate) fn supports_unknown_bits(&self) -> bool {
		self.flags.iter().enumerate().any(|(idx, &byte)| {
			( idx != 0 && byte != 0 ) || ( idx == 0 && (byte & 0xc4) != 0 )
		})
	}
}

/// Tracks globalfeatures which are in init messages and routing announcements
#[derive(Clone, PartialEq, Debug)]
pub struct GlobalFeatures {
	#[cfg(not(test))]
	flags: Vec<u8>,
	// Used to test encoding of diverse msgs
	#[cfg(test)]
	pub flags: Vec<u8>
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
	pub(crate) shutdown_scriptpubkey: OptionalField<Script>,
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
	pub(crate) shutdown_scriptpubkey: OptionalField<Script>
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
	pub(crate) data_loss_protect: OptionalField<DataLossProtect>,
}

/// An announcement_signatures message to be sent or received from a peer
#[derive(PartialEq, Clone, Debug)]
pub struct AnnouncementSignatures {
	pub(crate) channel_id: [u8; 32],
	pub(crate) short_channel_id: u64,
	pub(crate) node_signature: Signature,
	pub(crate) bitcoin_signature: Signature,
}

/// An address which can be used to connect to a remote peer
#[derive(Clone, PartialEq, Debug)]
pub enum NetAddress {
	/// An IPv4 address/port on which the peer is listening.
	IPv4 {
		/// The 4-byte IPv4 address
		addr: [u8; 4],
		/// The port on which the node is listening
		port: u16,
	},
	/// An IPv6 address/port on which the peer is listening.
	IPv6 {
		/// The 16-byte IPv6 address
		addr: [u8; 16],
		/// The port on which the node is listening
		port: u16,
	},
	/// An old-style Tor onion address/port on which the peer is listening.
	OnionV2 {
		/// The bytes (usually encoded in base32 with ".onion" appended)
		addr: [u8; 10],
		/// The port on which the node is listening
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
		/// The port on which the node is listening
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

	/// Strict byte-length of address descriptor, 1-byte type not recorded
	fn len(&self) -> u16 {
		match self {
			&NetAddress::IPv4 { .. } => { 6 },
			&NetAddress::IPv6 { .. } => { 18 },
			&NetAddress::OnionV2 { .. } => { 12 },
			&NetAddress::OnionV3 { .. } => { 37 },
		}
	}
}

impl Writeable for NetAddress {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
		match self {
			&NetAddress::IPv4 { ref addr, ref port } => {
				1u8.write(writer)?;
				addr.write(writer)?;
				port.write(writer)?;
			},
			&NetAddress::IPv6 { ref addr, ref port } => {
				2u8.write(writer)?;
				addr.write(writer)?;
				port.write(writer)?;
			},
			&NetAddress::OnionV2 { ref addr, ref port } => {
				3u8.write(writer)?;
				addr.write(writer)?;
				port.write(writer)?;
			},
			&NetAddress::OnionV3 { ref ed25519_pubkey, ref checksum, ref version, ref port } => {
				4u8.write(writer)?;
				ed25519_pubkey.write(writer)?;
				checksum.write(writer)?;
				version.write(writer)?;
				port.write(writer)?;
			}
		}
		Ok(())
	}
}

impl<R: ::std::io::Read>  Readable<R> for Result<NetAddress, u8> {
	fn read(reader: &mut R) -> Result<Result<NetAddress, u8>, DecodeError> {
		let byte = <u8 as Readable<R>>::read(reader)?;
		match byte {
			1 => {
				Ok(Ok(NetAddress::IPv4 {
					addr: Readable::read(reader)?,
					port: Readable::read(reader)?,
				}))
			},
			2 => {
				Ok(Ok(NetAddress::IPv6 {
					addr: Readable::read(reader)?,
					port: Readable::read(reader)?,
				}))
			},
			3 => {
				Ok(Ok(NetAddress::OnionV2 {
					addr: Readable::read(reader)?,
					port: Readable::read(reader)?,
				}))
			},
			4 => {
				Ok(Ok(NetAddress::OnionV3 {
					ed25519_pubkey: Readable::read(reader)?,
					checksum: Readable::read(reader)?,
					version: Readable::read(reader)?,
					port: Readable::read(reader)?,
				}))
			},
			_ => return Ok(Err(byte)),
		}
	}
}

// Only exposed as broadcast of node_announcement should be filtered by node_id
/// The unsigned part of a node_announcement
#[derive(PartialEq, Clone, Debug)]
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
#[derive(PartialEq, Clone)]
/// A node_announcement message to be sent or received from a peer
pub struct NodeAnnouncement {
	pub(crate) signature: Signature,
	pub(crate) contents: UnsignedNodeAnnouncement,
}

// Only exposed as broadcast of channel_announcement should be filtered by node_id
/// The unsigned part of a channel_announcement
#[derive(PartialEq, Clone, Debug)]
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
#[derive(PartialEq, Clone, Debug)]
pub struct ChannelAnnouncement {
	pub(crate) node_signature_1: Signature,
	pub(crate) node_signature_2: Signature,
	pub(crate) bitcoin_signature_1: Signature,
	pub(crate) bitcoin_signature_2: Signature,
	pub(crate) contents: UnsignedChannelAnnouncement,
}

#[derive(PartialEq, Clone, Debug)]
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
#[derive(PartialEq, Clone, Debug)]
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
	/// update_add_htlc messages which should be sent
	pub update_add_htlcs: Vec<UpdateAddHTLC>,
	/// update_fulfill_htlc messages which should be sent
	pub update_fulfill_htlcs: Vec<UpdateFulfillHTLC>,
	/// update_fail_htlc messages which should be sent
	pub update_fail_htlcs: Vec<UpdateFailHTLC>,
	/// update_fail_malformed_htlc messages which should be sent
	pub update_fail_malformed_htlcs: Vec<UpdateFailMalformedHTLC>,
	/// An update_fee message which should be sent
	pub update_fee: Option<UpdateFee>,
	/// Finally, the commitment_signed message which should be sent
	pub commitment_signed: CommitmentSigned,
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

/// Messages could have optional fields to use with extended features
/// As we wish to serialize these differently from Option<T>s (Options get a tag byte, but
/// OptionalFeild simply gets Present if there are enough bytes to read into it), we have a
/// separate enum type for them.
#[derive(Clone, PartialEq)]
pub enum OptionalField<T> {
	/// Optional field is included in message
	Present(T),
	/// Optional field is absent in message
	Absent
}

/// A trait to describe an object which can receive channel messages.
///
/// Messages MAY be called in parallel when they originate from different their_node_ids, however
/// they MUST NOT be called in parallel when the two calls have the same their_node_id.
pub trait ChannelMessageHandler : events::MessageSendEventsProvider + Send + Sync {
	//Channel init:
	/// Handle an incoming open_channel message from the given peer.
	fn handle_open_channel(&self, their_node_id: &PublicKey, their_local_features: LocalFeatures, msg: &OpenChannel) -> Result<(), HandleError>;
	/// Handle an incoming accept_channel message from the given peer.
	fn handle_accept_channel(&self, their_node_id: &PublicKey, their_local_features: LocalFeatures, msg: &AcceptChannel) -> Result<(), HandleError>;
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

impl Writeable for OptionalField<Script> {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), ::std::io::Error> {
		match *self {
			OptionalField::Present(ref script) => {
				// Note that Writeable for script includes the 16-bit length tag for us
				script.write(w)?;
			},
			OptionalField::Absent => {}
		}
		Ok(())
	}
}

impl<R: Read> Readable<R> for OptionalField<Script> {
	fn read(r: &mut R) -> Result<Self, DecodeError> {
		match <u16 as Readable<R>>::read(r) {
			Ok(len) => {
				let mut buf = vec![0; len as usize];
				r.read_exact(&mut buf)?;
				Ok(OptionalField::Present(Script::from(buf)))
			},
			Err(DecodeError::ShortRead) => Ok(OptionalField::Absent),
			Err(e) => Err(e)
		}
	}
}

impl_writeable_len_match!(AcceptChannel, {
		{AcceptChannel{ shutdown_scriptpubkey: OptionalField::Present(ref script), .. }, 270 + 2 + script.len()},
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
		w.size_hint(if let OptionalField::Present(..) = self.data_loss_protect { 32+2*8+33+32 } else { 32+2*8 });
		self.channel_id.write(w)?;
		self.next_local_commitment_number.write(w)?;
		self.next_remote_commitment_number.write(w)?;
		match self.data_loss_protect {
			OptionalField::Present(ref data_loss_protect) => {
				(*data_loss_protect).your_last_per_commitment_secret.write(w)?;
				(*data_loss_protect).my_current_per_commitment_point.write(w)?;
			},
			OptionalField::Absent => {}
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
						OptionalField::Present(DataLossProtect {
							your_last_per_commitment_secret,
							my_current_per_commitment_point: Readable::read(r)?,
						}),
					Err(DecodeError::ShortRead) => OptionalField::Absent,
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
		{ OpenChannel { shutdown_scriptpubkey: OptionalField::Present(ref script), .. }, 319 + 2 + script.len() },
		{ _, 319 }
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
				PublicKey::from_slice(&buf)
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

		let mut addrs_to_encode = self.addresses.clone();
		addrs_to_encode.sort_unstable_by(|a, b| { a.get_id().cmp(&b.get_id()) });
		addrs_to_encode.dedup_by(|a, b| { a.get_id() == b.get_id() });
		let mut addr_len = 0;
		for addr in &addrs_to_encode {
			addr_len += 1 + addr.len();
		}
		(addr_len + self.excess_address_data.len() as u16).write(w)?;
		for addr in addrs_to_encode {
			addr.write(w)?;
		}
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

		let addr_len: u16 = Readable::read(r)?;
		let mut addresses: Vec<NetAddress> = Vec::with_capacity(4);
		let mut addr_readpos = 0;
		let mut excess = false;
		let mut excess_byte = 0;
		loop {
			if addr_len <= addr_readpos { break; }
			match Readable::read(r) {
				Ok(Ok(addr)) => {
					match addr {
						NetAddress::IPv4 { .. } => {
							if addresses.len() > 0 {
								return Err(DecodeError::ExtraAddressesPerType);
							}
						},
						NetAddress::IPv6 { .. } => {
							if addresses.len() > 1 || (addresses.len() == 1 && addresses[0].get_id() != 1) {
								return Err(DecodeError::ExtraAddressesPerType);
							}
						},
						NetAddress::OnionV2 { .. } => {
							if addresses.len() > 2 || (addresses.len() > 0 && addresses.last().unwrap().get_id() > 2) {
								return Err(DecodeError::ExtraAddressesPerType);
							}
						},
						NetAddress::OnionV3 { .. } => {
							if addresses.len() > 3 || (addresses.len() > 0 && addresses.last().unwrap().get_id() > 3) {
								return Err(DecodeError::ExtraAddressesPerType);
							}
						},
					}
					if addr_len < addr_readpos + 1 + addr.len() {
						return Err(DecodeError::BadLengthDescriptor);
					}
					addr_readpos += (1 + addr.len()) as u16;
					addresses.push(addr);
				},
				Ok(Err(unknown_descriptor)) => {
					excess = true;
					excess_byte = unknown_descriptor;
					break;
				},
				Err(DecodeError::ShortRead) => return Err(DecodeError::BadLengthDescriptor),
				Err(e) => return Err(e),
			}
		}

		let mut excess_data = vec![];
		let excess_address_data = if addr_readpos < addr_len {
			let mut excess_address_data = vec![0; (addr_len - addr_readpos) as usize];
			r.read_exact(&mut excess_address_data[if excess { 1 } else { 0 }..])?;
			if excess {
				excess_address_data[0] = excess_byte;
			}
			excess_address_data
		} else {
			if excess {
				excess_data.push(excess_byte);
			}
			Vec::new()
		};
		r.read_to_end(&mut excess_data)?;
		Ok(UnsignedNodeAnnouncement {
			features,
			timestamp,
			node_id,
			rgb,
			alias,
			addresses,
			excess_address_data,
			excess_data,
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
	use ln::msgs::{GlobalFeatures, LocalFeatures, OptionalField, OnionErrorPacket};
	use ln::channelmanager::{PaymentPreimage, PaymentHash};
	use util::ser::Writeable;

	use bitcoin_hashes::sha256d::Hash as Sha256dHash;
	use bitcoin_hashes::hex::FromHex;
	use bitcoin::util::address::Address;
	use bitcoin::network::constants::Network;
	use bitcoin::blockdata::script::Builder;
	use bitcoin::blockdata::opcodes;

	use secp256k1::key::{PublicKey,SecretKey};
	use secp256k1::{Secp256k1, Message};

	#[test]
	fn encoding_channel_reestablish_no_secret() {
		let cr = msgs::ChannelReestablish {
			channel_id: [4, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0],
			next_local_commitment_number: 3,
			next_remote_commitment_number: 4,
			data_loss_protect: OptionalField::Absent,
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
			PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&hex::decode("0101010101010101010101010101010101010101010101010101010101010101").unwrap()[..]).unwrap())
		};

		let cr = msgs::ChannelReestablish {
			channel_id: [4, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0],
			next_local_commitment_number: 3,
			next_remote_commitment_number: 4,
			data_loss_protect: OptionalField::Present(msgs::DataLossProtect { your_last_per_commitment_secret: [9;32], my_current_per_commitment_point: public_key}),
		};

		let encoded_value = cr.encode();
		assert_eq!(
			encoded_value,
			vec![4, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 4, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 3, 27, 132, 197, 86, 123, 18, 100, 64, 153, 93, 62, 213, 170, 186, 5, 101, 215, 30, 24, 52, 96, 72, 25, 255, 156, 23, 245, 233, 213, 221, 7, 143]
		);
	}

	macro_rules! get_keys_from {
		($slice: expr, $secp_ctx: expr) => {
			{
				let privkey = SecretKey::from_slice(&hex::decode($slice).unwrap()[..]).unwrap();
				let pubkey = PublicKey::from_secret_key(&$secp_ctx, &privkey);
				(privkey, pubkey)
			}
		}
	}

	macro_rules! get_sig_on {
		($privkey: expr, $ctx: expr, $string: expr) => {
			{
				let sighash = Message::from_slice(&$string.into_bytes()[..]).unwrap();
				$ctx.sign(&sighash, &$privkey)
			}
		}
	}

	#[test]
	fn encoding_announcement_signatures() {
		let secp_ctx = Secp256k1::new();
		let (privkey, _) = get_keys_from!("0101010101010101010101010101010101010101010101010101010101010101", secp_ctx);
		let sig_1 = get_sig_on!(privkey, secp_ctx, String::from("01010101010101010101010101010101"));
		let sig_2 = get_sig_on!(privkey, secp_ctx, String::from("02020202020202020202020202020202"));
		let announcement_signatures = msgs::AnnouncementSignatures {
			channel_id: [4, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0],
			short_channel_id: 2316138423780173,
			node_signature: sig_1,
			bitcoin_signature: sig_2,
		};

		let encoded_value = announcement_signatures.encode();
		assert_eq!(encoded_value, hex::decode("040000000000000005000000000000000600000000000000070000000000000000083a840000034dd977cb9b53d93a6ff64bb5f1e158b4094b66e798fb12911168a3ccdf80a83096340a6a95da0ae8d9f776528eecdbb747eb6b545495a4319ed5378e35b21e073acf9953cef4700860f5967838eba2bae89288ad188ebf8b20bf995c3ea53a26df1876d0a3a0e13172ba286a673140190c02ba9da60a2e43a745188c8a83c7f3ef").unwrap());
	}

	fn do_encoding_channel_announcement(unknown_features_bits: bool, non_bitcoin_chain_hash: bool, excess_data: bool) {
		let secp_ctx = Secp256k1::new();
		let (privkey_1, pubkey_1) = get_keys_from!("0101010101010101010101010101010101010101010101010101010101010101", secp_ctx);
		let (privkey_2, pubkey_2) = get_keys_from!("0202020202020202020202020202020202020202020202020202020202020202", secp_ctx);
		let (privkey_3, pubkey_3) = get_keys_from!("0303030303030303030303030303030303030303030303030303030303030303", secp_ctx);
		let (privkey_4, pubkey_4) = get_keys_from!("0404040404040404040404040404040404040404040404040404040404040404", secp_ctx);
		let sig_1 = get_sig_on!(privkey_1, secp_ctx, String::from("01010101010101010101010101010101"));
		let sig_2 = get_sig_on!(privkey_2, secp_ctx, String::from("01010101010101010101010101010101"));
		let sig_3 = get_sig_on!(privkey_3, secp_ctx, String::from("01010101010101010101010101010101"));
		let sig_4 = get_sig_on!(privkey_4, secp_ctx, String::from("01010101010101010101010101010101"));
		let mut features = GlobalFeatures::new();
		if unknown_features_bits {
			features.flags = vec![0xFF, 0xFF];
		}
		let unsigned_channel_announcement = msgs::UnsignedChannelAnnouncement {
			features,
			chain_hash: if !non_bitcoin_chain_hash { Sha256dHash::from_hex("6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000").unwrap() } else { Sha256dHash::from_hex("000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943").unwrap() },
			short_channel_id: 2316138423780173,
			node_id_1: pubkey_1,
			node_id_2: pubkey_2,
			bitcoin_key_1: pubkey_3,
			bitcoin_key_2: pubkey_4,
			excess_data: if excess_data { vec![10, 0, 0, 20, 0, 0, 30, 0, 0, 40] } else { Vec::new() },
		};
		let channel_announcement = msgs::ChannelAnnouncement {
			node_signature_1: sig_1,
			node_signature_2: sig_2,
			bitcoin_signature_1: sig_3,
			bitcoin_signature_2: sig_4,
			contents: unsigned_channel_announcement,
		};
		let encoded_value = channel_announcement.encode();
		let mut target_value = hex::decode("d977cb9b53d93a6ff64bb5f1e158b4094b66e798fb12911168a3ccdf80a83096340a6a95da0ae8d9f776528eecdbb747eb6b545495a4319ed5378e35b21e073a1735b6a427e80d5fe7cd90a2f4ee08dc9c27cda7c35a4172e5d85b12c49d4232537e98f9b1f3c5e6989a8b9644e90e8918127680dbd0d4043510840fc0f1e11a216c280b5395a2546e7e4b2663e04f811622f15a4f91e83aa2e92ba2a573c139142c54ae63072a1ec1ee7dc0c04bde5c847806172aa05c92c22ae8e308d1d2692b12cc195ce0a2d1bda6a88befa19fa07f51caa75ce83837f28965600b8aacab0855ffb0e741ec5f7c41421e9829a9d48611c8c831f71be5ea73e66594977ffd").unwrap();
		if unknown_features_bits {
			target_value.append(&mut hex::decode("0002ffff").unwrap());
		} else {
			target_value.append(&mut hex::decode("0000").unwrap());
		}
		if non_bitcoin_chain_hash {
			target_value.append(&mut hex::decode("43497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea330900000000").unwrap());
		} else {
			target_value.append(&mut hex::decode("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f").unwrap());
		}
		target_value.append(&mut hex::decode("00083a840000034d031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f024d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d076602531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe33703462779ad4aad39514614751a71085f2f10e1c7a593e4e030efb5b8721ce55b0b").unwrap());
		if excess_data {
			target_value.append(&mut hex::decode("0a00001400001e000028").unwrap());
		}
		assert_eq!(encoded_value, target_value);
	}

	#[test]
	fn encoding_channel_announcement() {
		do_encoding_channel_announcement(false, false, false);
		do_encoding_channel_announcement(true, false, false);
		do_encoding_channel_announcement(true, true, false);
		do_encoding_channel_announcement(true, true, true);
		do_encoding_channel_announcement(false, true, true);
		do_encoding_channel_announcement(false, false, true);
		do_encoding_channel_announcement(false, true, false);
		do_encoding_channel_announcement(true, false, true);
	}

	fn do_encoding_node_announcement(unknown_features_bits: bool, ipv4: bool, ipv6: bool, onionv2: bool, onionv3: bool, excess_address_data: bool, excess_data: bool) {
		let secp_ctx = Secp256k1::new();
		let (privkey_1, pubkey_1) = get_keys_from!("0101010101010101010101010101010101010101010101010101010101010101", secp_ctx);
		let sig_1 = get_sig_on!(privkey_1, secp_ctx, String::from("01010101010101010101010101010101"));
		let mut features = GlobalFeatures::new();
		if unknown_features_bits {
			features.flags = vec![0xFF, 0xFF];
		}
		let mut addresses = Vec::new();
		if ipv4 {
			addresses.push(msgs::NetAddress::IPv4 {
				addr: [255, 254, 253, 252],
				port: 9735
			});
		}
		if ipv6 {
			addresses.push(msgs::NetAddress::IPv6 {
				addr: [255, 254, 253, 252, 251, 250, 249, 248, 247, 246, 245, 244, 243, 242, 241, 240],
				port: 9735
			});
		}
		if onionv2 {
			addresses.push(msgs::NetAddress::OnionV2 {
				addr: [255, 254, 253, 252, 251, 250, 249, 248, 247, 246],
				port: 9735
			});
		}
		if onionv3 {
			addresses.push(msgs::NetAddress::OnionV3 {
				ed25519_pubkey:	[255, 254, 253, 252, 251, 250, 249, 248, 247, 246, 245, 244, 243, 242, 241, 240, 239, 238, 237, 236, 235, 234, 233, 232, 231, 230, 229, 228, 227, 226, 225, 224],
				checksum: 32,
				version: 16,
				port: 9735
			});
		}
		let mut addr_len = 0;
		for addr in &addresses {
			addr_len += addr.len() + 1;
		}
		let unsigned_node_announcement = msgs::UnsignedNodeAnnouncement {
			features,
			timestamp: 20190119,
			node_id: pubkey_1,
			rgb: [32; 3],
			alias: [16;32],
			addresses,
			excess_address_data: if excess_address_data { vec![33, 108, 40, 11, 83, 149, 162, 84, 110, 126, 75, 38, 99, 224, 79, 129, 22, 34, 241, 90, 79, 146, 232, 58, 162, 233, 43, 162, 165, 115, 193, 57, 20, 44, 84, 174, 99, 7, 42, 30, 193, 238, 125, 192, 192, 75, 222, 92, 132, 120, 6, 23, 42, 160, 92, 146, 194, 42, 232, 227, 8, 209, 210, 105] } else { Vec::new() },
			excess_data: if excess_data { vec![59, 18, 204, 25, 92, 224, 162, 209, 189, 166, 168, 139, 239, 161, 159, 160, 127, 81, 202, 167, 92, 232, 56, 55, 242, 137, 101, 96, 11, 138, 172, 171, 8, 85, 255, 176, 231, 65, 236, 95, 124, 65, 66, 30, 152, 41, 169, 212, 134, 17, 200, 200, 49, 247, 27, 229, 234, 115, 230, 101, 148, 151, 127, 253] } else { Vec::new() },
		};
		addr_len += unsigned_node_announcement.excess_address_data.len() as u16;
		let node_announcement = msgs::NodeAnnouncement {
			signature: sig_1,
			contents: unsigned_node_announcement,
		};
		let encoded_value = node_announcement.encode();
		let mut target_value = hex::decode("d977cb9b53d93a6ff64bb5f1e158b4094b66e798fb12911168a3ccdf80a83096340a6a95da0ae8d9f776528eecdbb747eb6b545495a4319ed5378e35b21e073a").unwrap();
		if unknown_features_bits {
			target_value.append(&mut hex::decode("0002ffff").unwrap());
		} else {
			target_value.append(&mut hex::decode("0000").unwrap());
		}
		target_value.append(&mut hex::decode("013413a7031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f2020201010101010101010101010101010101010101010101010101010101010101010").unwrap());
		target_value.append(&mut vec![(addr_len >> 8) as u8, addr_len as u8]);
		if ipv4 {
			target_value.append(&mut hex::decode("01fffefdfc2607").unwrap());
		}
		if ipv6 {
			target_value.append(&mut hex::decode("02fffefdfcfbfaf9f8f7f6f5f4f3f2f1f02607").unwrap());
		}
		if onionv2 {
			target_value.append(&mut hex::decode("03fffefdfcfbfaf9f8f7f62607").unwrap());
		}
		if onionv3 {
			target_value.append(&mut hex::decode("04fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e00020102607").unwrap());
		}
		if excess_address_data {
			target_value.append(&mut hex::decode("216c280b5395a2546e7e4b2663e04f811622f15a4f92e83aa2e92ba2a573c139142c54ae63072a1ec1ee7dc0c04bde5c847806172aa05c92c22ae8e308d1d269").unwrap());
		}
		if excess_data {
			target_value.append(&mut hex::decode("3b12cc195ce0a2d1bda6a88befa19fa07f51caa75ce83837f28965600b8aacab0855ffb0e741ec5f7c41421e9829a9d48611c8c831f71be5ea73e66594977ffd").unwrap());
		}
		assert_eq!(encoded_value, target_value);
	}

	#[test]
	fn encoding_node_announcement() {
		do_encoding_node_announcement(true, true, true, true, true, true, true);
		do_encoding_node_announcement(false, false, false, false, false, false, false);
		do_encoding_node_announcement(false, true, false, false, false, false, false);
		do_encoding_node_announcement(false, false, true, false, false, false, false);
		do_encoding_node_announcement(false, false, false, true, false, false, false);
		do_encoding_node_announcement(false, false, false, false, true, false, false);
		do_encoding_node_announcement(false, false, false, false, false, true, false);
		do_encoding_node_announcement(false, true, false, true, false, true, false);
		do_encoding_node_announcement(false, false, true, false, true, false, false);
	}

	fn do_encoding_channel_update(non_bitcoin_chain_hash: bool, direction: bool, disable: bool, htlc_maximum_msat: bool) {
		let secp_ctx = Secp256k1::new();
		let (privkey_1, _) = get_keys_from!("0101010101010101010101010101010101010101010101010101010101010101", secp_ctx);
		let sig_1 = get_sig_on!(privkey_1, secp_ctx, String::from("01010101010101010101010101010101"));
		let unsigned_channel_update = msgs::UnsignedChannelUpdate {
			chain_hash: if !non_bitcoin_chain_hash { Sha256dHash::from_hex("6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000").unwrap() } else { Sha256dHash::from_hex("000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943").unwrap() },
			short_channel_id: 2316138423780173,
			timestamp: 20190119,
			flags: if direction { 1 } else { 0 } | if disable { 1 << 1 } else { 0 } | if htlc_maximum_msat { 1 << 8 } else { 0 },
			cltv_expiry_delta: 144,
			htlc_minimum_msat: 1000000,
			fee_base_msat: 10000,
			fee_proportional_millionths: 20,
			excess_data: if htlc_maximum_msat { vec![0, 0, 0, 0, 59, 154, 202, 0] } else { Vec::new() }
		};
		let channel_update = msgs::ChannelUpdate {
			signature: sig_1,
			contents: unsigned_channel_update
		};
		let encoded_value = channel_update.encode();
		let mut target_value = hex::decode("d977cb9b53d93a6ff64bb5f1e158b4094b66e798fb12911168a3ccdf80a83096340a6a95da0ae8d9f776528eecdbb747eb6b545495a4319ed5378e35b21e073a").unwrap();
		if non_bitcoin_chain_hash {
			target_value.append(&mut hex::decode("43497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea330900000000").unwrap());
		} else {
			target_value.append(&mut hex::decode("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f").unwrap());
		}
		target_value.append(&mut hex::decode("00083a840000034d013413a7").unwrap());
		if htlc_maximum_msat {
			target_value.append(&mut hex::decode("01").unwrap());
		} else {
			target_value.append(&mut hex::decode("00").unwrap());
		}
		target_value.append(&mut hex::decode("00").unwrap());
		if direction {
			let flag = target_value.last_mut().unwrap();
			*flag = 1;
		}
		if disable {
			let flag = target_value.last_mut().unwrap();
			*flag = *flag | 1 << 1;
		}
		target_value.append(&mut hex::decode("009000000000000f42400000271000000014").unwrap());
		if htlc_maximum_msat {
			target_value.append(&mut hex::decode("000000003b9aca00").unwrap());
		}
		assert_eq!(encoded_value, target_value);
	}

	#[test]
	fn encoding_channel_update() {
		do_encoding_channel_update(false, false, false, false);
		do_encoding_channel_update(true, false, false, false);
		do_encoding_channel_update(false, true, false, false);
		do_encoding_channel_update(false, false, true, false);
		do_encoding_channel_update(false, false, false, true);
		do_encoding_channel_update(true, true, true, true);
	}

	fn do_encoding_open_channel(non_bitcoin_chain_hash: bool, random_bit: bool, shutdown: bool) {
		let secp_ctx = Secp256k1::new();
		let (_, pubkey_1) = get_keys_from!("0101010101010101010101010101010101010101010101010101010101010101", secp_ctx);
		let (_, pubkey_2) = get_keys_from!("0202020202020202020202020202020202020202020202020202020202020202", secp_ctx);
		let (_, pubkey_3) = get_keys_from!("0303030303030303030303030303030303030303030303030303030303030303", secp_ctx);
		let (_, pubkey_4) = get_keys_from!("0404040404040404040404040404040404040404040404040404040404040404", secp_ctx);
		let (_, pubkey_5) = get_keys_from!("0505050505050505050505050505050505050505050505050505050505050505", secp_ctx);
		let (_, pubkey_6) = get_keys_from!("0606060606060606060606060606060606060606060606060606060606060606", secp_ctx);
		let open_channel = msgs::OpenChannel {
			chain_hash: if !non_bitcoin_chain_hash { Sha256dHash::from_hex("6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000").unwrap() } else { Sha256dHash::from_hex("000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943").unwrap() },
			temporary_channel_id: [2; 32],
			funding_satoshis: 1311768467284833366,
			push_msat: 2536655962884945560,
			dust_limit_satoshis: 3608586615801332854,
			max_htlc_value_in_flight_msat: 8517154655701053848,
			channel_reserve_satoshis: 8665828695742877976,
			htlc_minimum_msat: 2316138423780173,
			feerate_per_kw: 821716,
			to_self_delay: 49340,
			max_accepted_htlcs: 49340,
			funding_pubkey: pubkey_1,
			revocation_basepoint: pubkey_2,
			payment_basepoint: pubkey_3,
			delayed_payment_basepoint: pubkey_4,
			htlc_basepoint: pubkey_5,
			first_per_commitment_point: pubkey_6,
			channel_flags: if random_bit { 1 << 5 } else { 0 },
			shutdown_scriptpubkey: if shutdown { OptionalField::Present(Address::p2pkh(&::bitcoin::PublicKey{compressed: true, key: pubkey_1}, Network::Testnet).script_pubkey()) } else { OptionalField::Absent }
		};
		let encoded_value = open_channel.encode();
		let mut target_value = Vec::new();
		if non_bitcoin_chain_hash {
			target_value.append(&mut hex::decode("43497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea330900000000").unwrap());
		} else {
			target_value.append(&mut hex::decode("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f").unwrap());
		}
		target_value.append(&mut hex::decode("02020202020202020202020202020202020202020202020202020202020202021234567890123456233403289122369832144668701144767633030896203198784335490624111800083a840000034d000c89d4c0bcc0bc031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f024d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d076602531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe33703462779ad4aad39514614751a71085f2f10e1c7a593e4e030efb5b8721ce55b0b0362c0a046dacce86ddd0343c6d3c7c79c2208ba0d9c9cf24a6d046d21d21f90f703f006a18d5653c4edf5391ff23a61f03ff83d237e880ee61187fa9f379a028e0a").unwrap());
		if random_bit {
			target_value.append(&mut hex::decode("20").unwrap());
		} else {
			target_value.append(&mut hex::decode("00").unwrap());
		}
		if shutdown {
			target_value.append(&mut hex::decode("001976a91479b000887626b294a914501a4cd226b58b23598388ac").unwrap());
		}
		assert_eq!(encoded_value, target_value);
	}

	#[test]
	fn encoding_open_channel() {
		do_encoding_open_channel(false, false, false);
		do_encoding_open_channel(true, false, false);
		do_encoding_open_channel(false, true, false);
		do_encoding_open_channel(false, false, true);
		do_encoding_open_channel(true, true, true);
	}

	fn do_encoding_accept_channel(shutdown: bool) {
		let secp_ctx = Secp256k1::new();
		let (_, pubkey_1) = get_keys_from!("0101010101010101010101010101010101010101010101010101010101010101", secp_ctx);
		let (_, pubkey_2) = get_keys_from!("0202020202020202020202020202020202020202020202020202020202020202", secp_ctx);
		let (_, pubkey_3) = get_keys_from!("0303030303030303030303030303030303030303030303030303030303030303", secp_ctx);
		let (_, pubkey_4) = get_keys_from!("0404040404040404040404040404040404040404040404040404040404040404", secp_ctx);
		let (_, pubkey_5) = get_keys_from!("0505050505050505050505050505050505050505050505050505050505050505", secp_ctx);
		let (_, pubkey_6) = get_keys_from!("0606060606060606060606060606060606060606060606060606060606060606", secp_ctx);
		let accept_channel = msgs::AcceptChannel {
			temporary_channel_id: [2; 32],
			dust_limit_satoshis: 1311768467284833366,
			max_htlc_value_in_flight_msat: 2536655962884945560,
			channel_reserve_satoshis: 3608586615801332854,
			htlc_minimum_msat: 2316138423780173,
			minimum_depth: 821716,
			to_self_delay: 49340,
			max_accepted_htlcs: 49340,
			funding_pubkey: pubkey_1,
			revocation_basepoint: pubkey_2,
			payment_basepoint: pubkey_3,
			delayed_payment_basepoint: pubkey_4,
			htlc_basepoint: pubkey_5,
			first_per_commitment_point: pubkey_6,
			shutdown_scriptpubkey: if shutdown { OptionalField::Present(Address::p2pkh(&::bitcoin::PublicKey{compressed: true, key: pubkey_1}, Network::Testnet).script_pubkey()) } else { OptionalField::Absent }
		};
		let encoded_value = accept_channel.encode();
		let mut target_value = hex::decode("020202020202020202020202020202020202020202020202020202020202020212345678901234562334032891223698321446687011447600083a840000034d000c89d4c0bcc0bc031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f024d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d076602531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe33703462779ad4aad39514614751a71085f2f10e1c7a593e4e030efb5b8721ce55b0b0362c0a046dacce86ddd0343c6d3c7c79c2208ba0d9c9cf24a6d046d21d21f90f703f006a18d5653c4edf5391ff23a61f03ff83d237e880ee61187fa9f379a028e0a").unwrap();
		if shutdown {
			target_value.append(&mut hex::decode("001976a91479b000887626b294a914501a4cd226b58b23598388ac").unwrap());
		}
		assert_eq!(encoded_value, target_value);
	}

	#[test]
	fn encoding_accept_channel() {
		do_encoding_accept_channel(false);
		do_encoding_accept_channel(true);
	}

	#[test]
	fn encoding_funding_created() {
		let secp_ctx = Secp256k1::new();
		let (privkey_1, _) = get_keys_from!("0101010101010101010101010101010101010101010101010101010101010101", secp_ctx);
		let sig_1 = get_sig_on!(privkey_1, secp_ctx, String::from("01010101010101010101010101010101"));
		let funding_created = msgs::FundingCreated {
			temporary_channel_id: [2; 32],
			funding_txid: Sha256dHash::from_hex("c2d4449afa8d26140898dd54d3390b057ba2a5afcf03ba29d7dc0d8b9ffe966e").unwrap(),
			funding_output_index: 255,
			signature: sig_1,
		};
		let encoded_value = funding_created.encode();
		let target_value = hex::decode("02020202020202020202020202020202020202020202020202020202020202026e96fe9f8b0ddcd729ba03cfafa5a27b050b39d354dd980814268dfa9a44d4c200ffd977cb9b53d93a6ff64bb5f1e158b4094b66e798fb12911168a3ccdf80a83096340a6a95da0ae8d9f776528eecdbb747eb6b545495a4319ed5378e35b21e073a").unwrap();
		assert_eq!(encoded_value, target_value);
	}

	#[test]
	fn encoding_funding_signed() {
		let secp_ctx = Secp256k1::new();
		let (privkey_1, _) = get_keys_from!("0101010101010101010101010101010101010101010101010101010101010101", secp_ctx);
		let sig_1 = get_sig_on!(privkey_1, secp_ctx, String::from("01010101010101010101010101010101"));
		let funding_signed = msgs::FundingSigned {
			channel_id: [2; 32],
			signature: sig_1,
		};
		let encoded_value = funding_signed.encode();
		let target_value = hex::decode("0202020202020202020202020202020202020202020202020202020202020202d977cb9b53d93a6ff64bb5f1e158b4094b66e798fb12911168a3ccdf80a83096340a6a95da0ae8d9f776528eecdbb747eb6b545495a4319ed5378e35b21e073a").unwrap();
		assert_eq!(encoded_value, target_value);
	}

	#[test]
	fn encoding_funding_locked() {
		let secp_ctx = Secp256k1::new();
		let (_, pubkey_1,) = get_keys_from!("0101010101010101010101010101010101010101010101010101010101010101", secp_ctx);
		let funding_locked = msgs::FundingLocked {
			channel_id: [2; 32],
			next_per_commitment_point: pubkey_1,
		};
		let encoded_value = funding_locked.encode();
		let target_value = hex::decode("0202020202020202020202020202020202020202020202020202020202020202031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f").unwrap();
		assert_eq!(encoded_value, target_value);
	}

	fn do_encoding_shutdown(script_type: u8) {
		let secp_ctx = Secp256k1::new();
		let (_, pubkey_1) = get_keys_from!("0101010101010101010101010101010101010101010101010101010101010101", secp_ctx);
		let script = Builder::new().push_opcode(opcodes::OP_TRUE).into_script();
		let shutdown = msgs::Shutdown {
			channel_id: [2; 32],
			scriptpubkey: if script_type == 1 { Address::p2pkh(&::bitcoin::PublicKey{compressed: true, key: pubkey_1}, Network::Testnet).script_pubkey() } else if script_type == 2 { Address::p2sh(&script, Network::Testnet).script_pubkey() } else if script_type == 3 { Address::p2wpkh(&::bitcoin::PublicKey{compressed: true, key: pubkey_1}, Network::Testnet).script_pubkey() } else { Address::p2wsh(&script, Network::Testnet).script_pubkey() },
		};
		let encoded_value = shutdown.encode();
		let mut target_value = hex::decode("0202020202020202020202020202020202020202020202020202020202020202").unwrap();
		if script_type == 1 {
			target_value.append(&mut hex::decode("001976a91479b000887626b294a914501a4cd226b58b23598388ac").unwrap());
		} else if script_type == 2 {
			target_value.append(&mut hex::decode("0017a914da1745e9b549bd0bfa1a569971c77eba30cd5a4b87").unwrap());
		} else if script_type == 3 {
			target_value.append(&mut hex::decode("0016001479b000887626b294a914501a4cd226b58b235983").unwrap());
		} else if script_type == 4 {
			target_value.append(&mut hex::decode("002200204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc33260").unwrap());
		}
		assert_eq!(encoded_value, target_value);
	}

	#[test]
	fn encoding_shutdown() {
		do_encoding_shutdown(1);
		do_encoding_shutdown(2);
		do_encoding_shutdown(3);
		do_encoding_shutdown(4);
	}

	#[test]
	fn encoding_closing_signed() {
		let secp_ctx = Secp256k1::new();
		let (privkey_1, _) = get_keys_from!("0101010101010101010101010101010101010101010101010101010101010101", secp_ctx);
		let sig_1 = get_sig_on!(privkey_1, secp_ctx, String::from("01010101010101010101010101010101"));
		let closing_signed = msgs::ClosingSigned {
			channel_id: [2; 32],
			fee_satoshis: 2316138423780173,
			signature: sig_1,
		};
		let encoded_value = closing_signed.encode();
		let target_value = hex::decode("020202020202020202020202020202020202020202020202020202020202020200083a840000034dd977cb9b53d93a6ff64bb5f1e158b4094b66e798fb12911168a3ccdf80a83096340a6a95da0ae8d9f776528eecdbb747eb6b545495a4319ed5378e35b21e073a").unwrap();
		assert_eq!(encoded_value, target_value);
	}

	#[test]
	fn encoding_update_add_htlc() {
		let secp_ctx = Secp256k1::new();
		let (_, pubkey_1) = get_keys_from!("0101010101010101010101010101010101010101010101010101010101010101", secp_ctx);
		let onion_routing_packet = msgs::OnionPacket {
			version: 255,
			public_key: Ok(pubkey_1),
			hop_data: [1; 20*65],
			hmac: [2; 32]
		};
		let update_add_htlc = msgs::UpdateAddHTLC {
			channel_id: [2; 32],
			htlc_id: 2316138423780173,
			amount_msat: 3608586615801332854,
			payment_hash: PaymentHash([1; 32]),
			cltv_expiry: 821716,
			onion_routing_packet
		};
		let encoded_value = update_add_htlc.encode();
		let target_value = hex::decode("020202020202020202020202020202020202020202020202020202020202020200083a840000034d32144668701144760101010101010101010101010101010101010101010101010101010101010101000c89d4ff031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010202020202020202020202020202020202020202020202020202020202020202").unwrap();
		assert_eq!(encoded_value, target_value);
	}

	#[test]
	fn encoding_update_fulfill_htlc() {
		let update_fulfill_htlc = msgs::UpdateFulfillHTLC {
			channel_id: [2; 32],
			htlc_id: 2316138423780173,
			payment_preimage: PaymentPreimage([1; 32]),
		};
		let encoded_value = update_fulfill_htlc.encode();
		let target_value = hex::decode("020202020202020202020202020202020202020202020202020202020202020200083a840000034d0101010101010101010101010101010101010101010101010101010101010101").unwrap();
		assert_eq!(encoded_value, target_value);
	}

	#[test]
	fn encoding_update_fail_htlc() {
		let reason = OnionErrorPacket {
			data: [1; 32].to_vec(),
		};
		let update_fail_htlc = msgs::UpdateFailHTLC {
			channel_id: [2; 32],
			htlc_id: 2316138423780173,
			reason
		};
		let encoded_value = update_fail_htlc.encode();
		let target_value = hex::decode("020202020202020202020202020202020202020202020202020202020202020200083a840000034d00200101010101010101010101010101010101010101010101010101010101010101").unwrap();
		assert_eq!(encoded_value, target_value);
	}

	#[test]
	fn encoding_update_fail_malformed_htlc() {
		let update_fail_malformed_htlc = msgs::UpdateFailMalformedHTLC {
			channel_id: [2; 32],
			htlc_id: 2316138423780173,
			sha256_of_onion: [1; 32],
			failure_code: 255
		};
		let encoded_value = update_fail_malformed_htlc.encode();
		let target_value = hex::decode("020202020202020202020202020202020202020202020202020202020202020200083a840000034d010101010101010101010101010101010101010101010101010101010101010100ff").unwrap();
		assert_eq!(encoded_value, target_value);
	}

	fn do_encoding_commitment_signed(htlcs: bool) {
		let secp_ctx = Secp256k1::new();
		let (privkey_1, _) = get_keys_from!("0101010101010101010101010101010101010101010101010101010101010101", secp_ctx);
		let (privkey_2, _) = get_keys_from!("0202020202020202020202020202020202020202020202020202020202020202", secp_ctx);
		let (privkey_3, _) = get_keys_from!("0303030303030303030303030303030303030303030303030303030303030303", secp_ctx);
		let (privkey_4, _) = get_keys_from!("0404040404040404040404040404040404040404040404040404040404040404", secp_ctx);
		let sig_1 = get_sig_on!(privkey_1, secp_ctx, String::from("01010101010101010101010101010101"));
		let sig_2 = get_sig_on!(privkey_2, secp_ctx, String::from("01010101010101010101010101010101"));
		let sig_3 = get_sig_on!(privkey_3, secp_ctx, String::from("01010101010101010101010101010101"));
		let sig_4 = get_sig_on!(privkey_4, secp_ctx, String::from("01010101010101010101010101010101"));
		let commitment_signed = msgs::CommitmentSigned {
			channel_id: [2; 32],
			signature: sig_1,
			htlc_signatures: if htlcs { vec![sig_2, sig_3, sig_4] } else { Vec::new() },
		};
		let encoded_value = commitment_signed.encode();
		let mut target_value = hex::decode("0202020202020202020202020202020202020202020202020202020202020202d977cb9b53d93a6ff64bb5f1e158b4094b66e798fb12911168a3ccdf80a83096340a6a95da0ae8d9f776528eecdbb747eb6b545495a4319ed5378e35b21e073a").unwrap();
		if htlcs {
			target_value.append(&mut hex::decode("00031735b6a427e80d5fe7cd90a2f4ee08dc9c27cda7c35a4172e5d85b12c49d4232537e98f9b1f3c5e6989a8b9644e90e8918127680dbd0d4043510840fc0f1e11a216c280b5395a2546e7e4b2663e04f811622f15a4f91e83aa2e92ba2a573c139142c54ae63072a1ec1ee7dc0c04bde5c847806172aa05c92c22ae8e308d1d2692b12cc195ce0a2d1bda6a88befa19fa07f51caa75ce83837f28965600b8aacab0855ffb0e741ec5f7c41421e9829a9d48611c8c831f71be5ea73e66594977ffd").unwrap());
		} else {
			target_value.append(&mut hex::decode("0000").unwrap());
		}
		assert_eq!(encoded_value, target_value);
	}

	#[test]
	fn encoding_commitment_signed() {
		do_encoding_commitment_signed(true);
		do_encoding_commitment_signed(false);
	}

	#[test]
	fn encoding_revoke_and_ack() {
		let secp_ctx = Secp256k1::new();
		let (_, pubkey_1) = get_keys_from!("0101010101010101010101010101010101010101010101010101010101010101", secp_ctx);
		let raa = msgs::RevokeAndACK {
			channel_id: [2; 32],
			per_commitment_secret: [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1],
			next_per_commitment_point: pubkey_1,
		};
		let encoded_value = raa.encode();
		let target_value = hex::decode("02020202020202020202020202020202020202020202020202020202020202020101010101010101010101010101010101010101010101010101010101010101031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f").unwrap();
		assert_eq!(encoded_value, target_value);
	}

	#[test]
	fn encoding_update_fee() {
		let update_fee = msgs::UpdateFee {
			channel_id: [2; 32],
			feerate_per_kw: 20190119,
		};
		let encoded_value = update_fee.encode();
		let target_value = hex::decode("0202020202020202020202020202020202020202020202020202020202020202013413a7").unwrap();
		assert_eq!(encoded_value, target_value);
	}

	fn do_encoding_init(unknown_global_bits: bool, initial_routing_sync: bool) {
		let mut global = GlobalFeatures::new();
		if unknown_global_bits {
			global.flags = vec![0xFF, 0xFF];
		}
		let mut local = LocalFeatures::new();
		if initial_routing_sync {
			local.set_initial_routing_sync();
		}
		let init = msgs::Init {
			global_features: global,
			local_features: local,
		};
		let encoded_value = init.encode();
		let mut target_value = Vec::new();
		if unknown_global_bits {
			target_value.append(&mut hex::decode("0002ffff").unwrap());
		} else {
			target_value.append(&mut hex::decode("0000").unwrap());
		}
		if initial_routing_sync {
			target_value.append(&mut hex::decode("00012a").unwrap());
		} else {
			target_value.append(&mut hex::decode("000122").unwrap());
		}
		assert_eq!(encoded_value, target_value);
	}

	#[test]
	fn encoding_init() {
		do_encoding_init(false, false);
		do_encoding_init(true, false);
		do_encoding_init(false, true);
		do_encoding_init(true, true);
	}

	#[test]
	fn encoding_error() {
		let error = msgs::ErrorMessage {
			channel_id: [2; 32],
			data: String::from("rust-lightning"),
		};
		let encoded_value = error.encode();
		let target_value = hex::decode("0202020202020202020202020202020202020202020202020202020202020202000e727573742d6c696768746e696e67").unwrap();
		assert_eq!(encoded_value, target_value);
	}

	#[test]
	fn encoding_ping() {
		let ping = msgs::Ping {
			ponglen: 64,
			byteslen: 64
		};
		let encoded_value = ping.encode();
		let target_value = hex::decode("0040004000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").unwrap();
		assert_eq!(encoded_value, target_value);
	}

	#[test]
	fn encoding_pong() {
		let pong = msgs::Pong {
			byteslen: 64
		};
		let encoded_value = pong.encode();
		let target_value = hex::decode("004000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").unwrap();
		assert_eq!(encoded_value, target_value);
	}
}
