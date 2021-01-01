// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

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

use bitcoin::secp256k1::key::PublicKey;
use bitcoin::secp256k1::Signature;
use bitcoin::secp256k1;
use bitcoin::blockdata::script::Script;
use bitcoin::hash_types::{Txid, BlockHash};

use ln::features::{ChannelFeatures, InitFeatures, NodeFeatures};

use std::{cmp, fmt};
use std::io::Read;

use util::events::MessageSendEventsProvider;
use util::ser::{Readable, Writeable, Writer, FixedLengthReader, HighZeroBytesDroppedVarInt};

use ln::channelmanager::{PaymentPreimage, PaymentHash, PaymentSecret};

/// 21 million * 10^8 * 1000
pub(crate) const MAX_VALUE_MSAT: u64 = 21_000_000_0000_0000_000;

/// An error in decoding a message or struct.
#[derive(Debug)]
pub enum DecodeError {
	/// A version byte specified something we don't know how to handle.
	/// Includes unknown realm byte in an OnionHopData packet
	UnknownVersion,
	/// Unknown feature mandating we fail to parse message (eg TLV with an even, unknown type)
	UnknownRequiredFeature,
	/// Value was invalid, eg a byte which was supposed to be a bool was something other than a 0
	/// or 1, a public key/private key/signature was invalid, text wasn't UTF-8, TLV was
	/// syntactically incorrect, etc
	InvalidValue,
	/// Buffer too short
	ShortRead,
	/// A length descriptor in the packet didn't describe the later data correctly
	BadLengthDescriptor,
	/// Error from std::io
	Io(::std::io::Error),
}

/// An init message to be sent or received from a peer
#[derive(Clone)]
pub struct Init {
	#[cfg(not(feature = "fuzztarget"))]
	pub(crate) features: InitFeatures,
	#[cfg(feature = "fuzztarget")]
	pub features: InitFeatures,
}

/// An error message to be sent or received from a peer
#[derive(Clone)]
pub struct ErrorMessage {
	/// The channel ID involved in the error
	pub channel_id: [u8; 32],
	/// A possibly human-readable error description.
	/// The string should be sanitized before it is used (e.g. emitted to logs
	/// or printed to stdout).  Otherwise, a well crafted error message may trigger a security
	/// vulnerability in the terminal emulator or the logging subsystem.
	pub data: String,
}

/// A ping message to be sent or received from a peer
#[derive(Clone)]
pub struct Ping {
	/// The desired response length
	pub ponglen: u16,
	/// The ping packet size.
	/// This field is not sent on the wire. byteslen zeros are sent.
	pub byteslen: u16,
}

/// A pong message to be sent or received from a peer
#[derive(Clone)]
pub struct Pong {
	/// The pong packet size.
	/// This field is not sent on the wire. byteslen zeros are sent.
	pub byteslen: u16,
}

/// An open_channel message to be sent or received from a peer
#[derive(Clone)]
pub struct OpenChannel {
	/// The genesis hash of the blockchain where the channel is to be opened
	pub chain_hash: BlockHash,
	/// A temporary channel ID, until the funding outpoint is announced
	pub temporary_channel_id: [u8; 32],
	/// The channel value
	pub funding_satoshis: u64,
	/// The amount to push to the counterparty as part of the open, in milli-satoshi
	pub push_msat: u64,
	/// The threshold below which outputs on transactions broadcast by sender will be omitted
	pub dust_limit_satoshis: u64,
	/// The maximum inbound HTLC value in flight towards sender, in milli-satoshi
	pub max_htlc_value_in_flight_msat: u64,
	/// The minimum value unencumbered by HTLCs for the counterparty to keep in the channel
	pub channel_reserve_satoshis: u64,
	/// The minimum HTLC size incoming to sender, in milli-satoshi
	pub htlc_minimum_msat: u64,
	/// The feerate per 1000-weight of sender generated transactions, until updated by update_fee
	pub feerate_per_kw: u32,
	/// The number of blocks which the counterparty will have to wait to claim on-chain funds if they broadcast a commitment transaction
	pub to_self_delay: u16,
	/// The maximum number of inbound HTLCs towards sender
	pub max_accepted_htlcs: u16,
	/// The sender's key controlling the funding transaction
	pub funding_pubkey: PublicKey,
	/// Used to derive a revocation key for transactions broadcast by counterparty
	pub revocation_basepoint: PublicKey,
	/// A payment key to sender for transactions broadcast by counterparty
	pub payment_point: PublicKey,
	/// Used to derive a payment key to sender for transactions broadcast by sender
	pub delayed_payment_basepoint: PublicKey,
	/// Used to derive an HTLC payment key to sender
	pub htlc_basepoint: PublicKey,
	/// The first to-be-broadcast-by-sender transaction's per commitment point
	pub first_per_commitment_point: PublicKey,
	/// Channel flags
	pub channel_flags: u8,
	/// Optionally, a request to pre-set the to-sender output's scriptPubkey for when we collaboratively close
	pub shutdown_scriptpubkey: OptionalField<Script>,
}

/// An accept_channel message to be sent or received from a peer
#[derive(Clone)]
pub struct AcceptChannel {
	/// A temporary channel ID, until the funding outpoint is announced
	pub temporary_channel_id: [u8; 32],
	/// The threshold below which outputs on transactions broadcast by sender will be omitted
	pub dust_limit_satoshis: u64,
	/// The maximum inbound HTLC value in flight towards sender, in milli-satoshi
	pub max_htlc_value_in_flight_msat: u64,
	/// The minimum value unencumbered by HTLCs for the counterparty to keep in the channel
	pub channel_reserve_satoshis: u64,
	/// The minimum HTLC size incoming to sender, in milli-satoshi
	pub htlc_minimum_msat: u64,
	/// Minimum depth of the funding transaction before the channel is considered open
	pub minimum_depth: u32,
	/// The number of blocks which the counterparty will have to wait to claim on-chain funds if they broadcast a commitment transaction
	pub to_self_delay: u16,
	/// The maximum number of inbound HTLCs towards sender
	pub max_accepted_htlcs: u16,
	/// The sender's key controlling the funding transaction
	pub funding_pubkey: PublicKey,
	/// Used to derive a revocation key for transactions broadcast by counterparty
	pub revocation_basepoint: PublicKey,
	/// A payment key to sender for transactions broadcast by counterparty
	pub payment_point: PublicKey,
	/// Used to derive a payment key to sender for transactions broadcast by sender
	pub delayed_payment_basepoint: PublicKey,
	/// Used to derive an HTLC payment key to sender for transactions broadcast by counterparty
	pub htlc_basepoint: PublicKey,
	/// The first to-be-broadcast-by-sender transaction's per commitment point
	pub first_per_commitment_point: PublicKey,
	/// Optionally, a request to pre-set the to-sender output's scriptPubkey for when we collaboratively close
	pub shutdown_scriptpubkey: OptionalField<Script>,
}

/// A funding_created message to be sent or received from a peer
#[derive(Clone)]
pub struct FundingCreated {
	/// A temporary channel ID, until the funding is established
	pub temporary_channel_id: [u8; 32],
	/// The funding transaction ID
	pub funding_txid: Txid,
	/// The specific output index funding this channel
	pub funding_output_index: u16,
	/// The signature of the channel initiator (funder) on the funding transaction
	pub signature: Signature,
}

/// A funding_signed message to be sent or received from a peer
#[derive(Clone)]
pub struct FundingSigned {
	/// The channel ID
	pub channel_id: [u8; 32],
	/// The signature of the channel acceptor (fundee) on the funding transaction
	pub signature: Signature,
}

/// A funding_locked message to be sent or received from a peer
#[derive(Clone, PartialEq)]
pub struct FundingLocked {
	/// The channel ID
	pub channel_id: [u8; 32],
	/// The per-commitment point of the second commitment transaction
	pub next_per_commitment_point: PublicKey,
}

/// A shutdown message to be sent or received from a peer
#[derive(Clone, PartialEq)]
pub struct Shutdown {
	/// The channel ID
	pub channel_id: [u8; 32],
	/// The destination of this peer's funds on closing.
	/// Must be in one of these forms: p2pkh, p2sh, p2wpkh, p2wsh.
	pub scriptpubkey: Script,
}

/// A closing_signed message to be sent or received from a peer
#[derive(Clone, PartialEq)]
pub struct ClosingSigned {
	/// The channel ID
	pub channel_id: [u8; 32],
	/// The proposed total fee for the closing transaction
	pub fee_satoshis: u64,
	/// A signature on the closing transaction
	pub signature: Signature,
}

/// An update_add_htlc message to be sent or received from a peer
#[derive(Clone, PartialEq)]
pub struct UpdateAddHTLC {
	/// The channel ID
	pub channel_id: [u8; 32],
	/// The HTLC ID
	pub htlc_id: u64,
	/// The HTLC value in milli-satoshi
	pub amount_msat: u64,
	/// The payment hash, the pre-image of which controls HTLC redemption
	pub payment_hash: PaymentHash,
	/// The expiry height of the HTLC
	pub cltv_expiry: u32,
	pub(crate) onion_routing_packet: OnionPacket,
}

/// An update_fulfill_htlc message to be sent or received from a peer
#[derive(Clone, PartialEq)]
pub struct UpdateFulfillHTLC {
	/// The channel ID
	pub channel_id: [u8; 32],
	/// The HTLC ID
	pub htlc_id: u64,
	/// The pre-image of the payment hash, allowing HTLC redemption
	pub payment_preimage: PaymentPreimage,
}

/// An update_fail_htlc message to be sent or received from a peer
#[derive(Clone, PartialEq)]
pub struct UpdateFailHTLC {
	/// The channel ID
	pub channel_id: [u8; 32],
	/// The HTLC ID
	pub htlc_id: u64,
	pub(crate) reason: OnionErrorPacket,
}

/// An update_fail_malformed_htlc message to be sent or received from a peer
#[derive(Clone, PartialEq)]
pub struct UpdateFailMalformedHTLC {
	/// The channel ID
	pub channel_id: [u8; 32],
	/// The HTLC ID
	pub htlc_id: u64,
	pub(crate) sha256_of_onion: [u8; 32],
	/// The failure code
	pub failure_code: u16,
}

/// A commitment_signed message to be sent or received from a peer
#[derive(Clone, PartialEq)]
pub struct CommitmentSigned {
	/// The channel ID
	pub channel_id: [u8; 32],
	/// A signature on the commitment transaction
	pub signature: Signature,
	/// Signatures on the HTLC transactions
	pub htlc_signatures: Vec<Signature>,
}

/// A revoke_and_ack message to be sent or received from a peer
#[derive(Clone, PartialEq)]
pub struct RevokeAndACK {
	/// The channel ID
	pub channel_id: [u8; 32],
	/// The secret corresponding to the per-commitment point
	pub per_commitment_secret: [u8; 32],
	/// The next sender-broadcast commitment transaction's per-commitment point
	pub next_per_commitment_point: PublicKey,
}

/// An update_fee message to be sent or received from a peer
#[derive(PartialEq, Clone)]
pub struct UpdateFee {
	/// The channel ID
	pub channel_id: [u8; 32],
	/// Fee rate per 1000-weight of the transaction
	pub feerate_per_kw: u32,
}

#[derive(PartialEq, Clone)]
/// Proof that the sender knows the per-commitment secret of the previous commitment transaction.
/// This is used to convince the recipient that the channel is at a certain commitment
/// number even if they lost that data due to a local failure.  Of course, the peer may lie
/// and even later commitments may have been revoked.
pub struct DataLossProtect {
	/// Proof that the sender knows the per-commitment secret of a specific commitment transaction
	/// belonging to the recipient
	pub your_last_per_commitment_secret: [u8; 32],
	/// The sender's per-commitment point for their current commitment transaction
	pub my_current_per_commitment_point: PublicKey,
}

/// A channel_reestablish message to be sent or received from a peer
#[derive(PartialEq, Clone)]
pub struct ChannelReestablish {
	/// The channel ID
	pub channel_id: [u8; 32],
	/// The next commitment number for the sender
	pub next_local_commitment_number: u64,
	/// The next commitment number for the recipient
	pub next_remote_commitment_number: u64,
	/// Optionally, a field proving that next_remote_commitment_number-1 has been revoked
	pub data_loss_protect: OptionalField<DataLossProtect>,
}

/// An announcement_signatures message to be sent or received from a peer
#[derive(PartialEq, Clone, Debug)]
pub struct AnnouncementSignatures {
	/// The channel ID
	pub channel_id: [u8; 32],
	/// The short channel ID
	pub short_channel_id: u64,
	/// A signature by the node key
	pub node_signature: Signature,
	/// A signature by the funding key
	pub bitcoin_signature: Signature,
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

	/// The maximum length of any address descriptor, not including the 1-byte type
	pub(crate) const MAX_LEN: u16 = 37;
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

impl Readable for Result<NetAddress, u8> {
	fn read<R: Read>(reader: &mut R) -> Result<Result<NetAddress, u8>, DecodeError> {
		let byte = <u8 as Readable>::read(reader)?;
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

/// The unsigned part of a node_announcement
#[derive(PartialEq, Clone, Debug)]
pub struct UnsignedNodeAnnouncement {
	/// The advertised features
	pub features: NodeFeatures,
	/// A strictly monotonic announcement counter, with gaps allowed
	pub timestamp: u32,
	/// The node_id this announcement originated from (don't rebroadcast the node_announcement back
	/// to this node).
	pub node_id: PublicKey,
	/// An RGB color for UI purposes
	pub rgb: [u8; 3],
	/// An alias, for UI purposes.  This should be sanitized before use.  There is no guarantee
	/// of uniqueness.
	pub alias: [u8; 32],
	/// List of addresses on which this node is reachable
	pub addresses: Vec<NetAddress>,
	pub(crate) excess_address_data: Vec<u8>,
	pub(crate) excess_data: Vec<u8>,
}
#[derive(PartialEq, Clone, Debug)]
/// A node_announcement message to be sent or received from a peer
pub struct NodeAnnouncement {
	/// The signature by the node key
	pub signature: Signature,
	/// The actual content of the announcement
	pub contents: UnsignedNodeAnnouncement,
}

/// The unsigned part of a channel_announcement
#[derive(PartialEq, Clone, Debug)]
pub struct UnsignedChannelAnnouncement {
	/// The advertised channel features
	pub features: ChannelFeatures,
	/// The genesis hash of the blockchain where the channel is to be opened
	pub chain_hash: BlockHash,
	/// The short channel ID
	pub short_channel_id: u64,
	/// One of the two node_ids which are endpoints of this channel
	pub node_id_1: PublicKey,
	/// The other of the two node_ids which are endpoints of this channel
	pub node_id_2: PublicKey,
	/// The funding key for the first node
	pub bitcoin_key_1: PublicKey,
	/// The funding key for the second node
	pub bitcoin_key_2: PublicKey,
	pub(crate) excess_data: Vec<u8>,
}
/// A channel_announcement message to be sent or received from a peer
#[derive(PartialEq, Clone, Debug)]
pub struct ChannelAnnouncement {
	/// Authentication of the announcement by the first public node
	pub node_signature_1: Signature,
	/// Authentication of the announcement by the second public node
	pub node_signature_2: Signature,
	/// Proof of funding UTXO ownership by the first public node
	pub bitcoin_signature_1: Signature,
	/// Proof of funding UTXO ownership by the second public node
	pub bitcoin_signature_2: Signature,
	/// The actual announcement
	pub contents: UnsignedChannelAnnouncement,
}

/// The unsigned part of a channel_update
#[derive(PartialEq, Clone, Debug)]
pub struct UnsignedChannelUpdate {
	/// The genesis hash of the blockchain where the channel is to be opened
	pub chain_hash: BlockHash,
	/// The short channel ID
	pub short_channel_id: u64,
	/// A strictly monotonic announcement counter, with gaps allowed, specific to this channel
	pub timestamp: u32,
	/// Channel flags
	pub flags: u8,
	/// The number of blocks to subtract from incoming HTLC cltv_expiry values
	pub cltv_expiry_delta: u16,
	/// The minimum HTLC size incoming to sender, in milli-satoshi
	pub htlc_minimum_msat: u64,
	/// Optionally, the maximum HTLC value incoming to sender, in milli-satoshi
	pub htlc_maximum_msat: OptionalField<u64>,
	/// The base HTLC fee charged by sender, in milli-satoshi
	pub fee_base_msat: u32,
	/// The amount to fee multiplier, in micro-satoshi
	pub fee_proportional_millionths: u32,
	pub(crate) excess_data: Vec<u8>,
}
/// A channel_update message to be sent or received from a peer
#[derive(PartialEq, Clone, Debug)]
pub struct ChannelUpdate {
	/// A signature of the channel update
	pub signature: Signature,
	/// The actual channel update
	pub contents: UnsignedChannelUpdate,
}

/// A query_channel_range message is used to query a peer for channel
/// UTXOs in a range of blocks. The recipient of a query makes a best
/// effort to reply to the query using one or more reply_channel_range
/// messages.
#[derive(Clone, Debug)]
pub struct QueryChannelRange {
	/// The genesis hash of the blockchain being queried
	pub chain_hash: BlockHash,
	/// The height of the first block for the channel UTXOs being queried
	pub first_blocknum: u32,
	/// The number of blocks to include in the query results
	pub number_of_blocks: u32,
}

/// A reply_channel_range message is a reply to a query_channel_range
/// message. Multiple reply_channel_range messages can be sent in reply
/// to a single query_channel_range message. The query recipient makes a
/// best effort to respond based on their local network view which may
/// not be a perfect view of the network. The short_channel_ids in the
/// reply are encoded. We only support encoding_type=0 uncompressed
/// serialization and do not support encoding_type=1 zlib serialization.
#[derive(Clone, Debug)]
pub struct ReplyChannelRange {
	/// The genesis hash of the blockchain being queried
	pub chain_hash: BlockHash,
	/// The height of the first block in the range of the reply
	pub first_blocknum: u32,
	/// The number of blocks included in the range of the reply
	pub number_of_blocks: u32,
	/// Indicates if the query recipient maintains up-to-date channel
	/// information for the chain_hash
	pub full_information: bool,
	/// The short_channel_ids in the channel range
	pub short_channel_ids: Vec<u64>,
}

/// A query_short_channel_ids message is used to query a peer for
/// routing gossip messages related to one or more short_channel_ids.
/// The query recipient will reply with the latest, if available,
/// channel_announcement, channel_update and node_announcement messages
/// it maintains for the requested short_channel_ids followed by a
/// reply_short_channel_ids_end message. The short_channel_ids sent in
/// this query are encoded. We only support encoding_type=0 uncompressed
/// serialization and do not support encoding_type=1 zlib serialization.
#[derive(Clone, Debug)]
pub struct QueryShortChannelIds {
	/// The genesis hash of the blockchain being queried
	pub chain_hash: BlockHash,
	/// The short_channel_ids that are being queried
	pub short_channel_ids: Vec<u64>,
}

/// A reply_short_channel_ids_end message is sent as a reply to a
/// query_short_channel_ids message. The query recipient makes a best
/// effort to respond based on their local network view which may not be
/// a perfect view of the network.
#[derive(Clone, Debug)]
pub struct ReplyShortChannelIdsEnd {
	/// The genesis hash of the blockchain that was queried
	pub chain_hash: BlockHash,
	/// Indicates if the query recipient maintains up-to-date channel
	/// information for the chain_hash
	pub full_information: bool,
}

/// A gossip_timestamp_filter message is used by a node to request
/// gossip relay for messages in the requested time range when the
/// gossip_queries feature has been negotiated.
#[derive(Clone, Debug)]
pub struct GossipTimestampFilter {
	/// The genesis hash of the blockchain for channel and node information
	pub chain_hash: BlockHash,
	/// The starting unix timestamp
	pub first_timestamp: u32,
	/// The range of information in seconds
	pub timestamp_range: u32,
}

/// Encoding type for data compression of collections in gossip queries.
/// We do not support encoding_type=1 zlib serialization defined in BOLT #7.
enum EncodingType {
	Uncompressed = 0x00,
}

/// Used to put an error message in a LightningError
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
pub struct LightningError {
	/// A human-readable message describing the error
	pub err: String,
	/// The action which should be taken against the offending peer.
	pub action: ErrorAction,
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
/// (C-not exported) due to a free generic in T
#[derive(Clone, PartialEq, Debug)]
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
pub trait ChannelMessageHandler : MessageSendEventsProvider + Send + Sync {
	//Channel init:
	/// Handle an incoming open_channel message from the given peer.
	fn handle_open_channel(&self, their_node_id: &PublicKey, their_features: InitFeatures, msg: &OpenChannel);
	/// Handle an incoming accept_channel message from the given peer.
	fn handle_accept_channel(&self, their_node_id: &PublicKey, their_features: InitFeatures, msg: &AcceptChannel);
	/// Handle an incoming funding_created message from the given peer.
	fn handle_funding_created(&self, their_node_id: &PublicKey, msg: &FundingCreated);
	/// Handle an incoming funding_signed message from the given peer.
	fn handle_funding_signed(&self, their_node_id: &PublicKey, msg: &FundingSigned);
	/// Handle an incoming funding_locked message from the given peer.
	fn handle_funding_locked(&self, their_node_id: &PublicKey, msg: &FundingLocked);

	// Channl close:
	/// Handle an incoming shutdown message from the given peer.
	fn handle_shutdown(&self, their_node_id: &PublicKey, msg: &Shutdown);
	/// Handle an incoming closing_signed message from the given peer.
	fn handle_closing_signed(&self, their_node_id: &PublicKey, msg: &ClosingSigned);

	// HTLC handling:
	/// Handle an incoming update_add_htlc message from the given peer.
	fn handle_update_add_htlc(&self, their_node_id: &PublicKey, msg: &UpdateAddHTLC);
	/// Handle an incoming update_fulfill_htlc message from the given peer.
	fn handle_update_fulfill_htlc(&self, their_node_id: &PublicKey, msg: &UpdateFulfillHTLC);
	/// Handle an incoming update_fail_htlc message from the given peer.
	fn handle_update_fail_htlc(&self, their_node_id: &PublicKey, msg: &UpdateFailHTLC);
	/// Handle an incoming update_fail_malformed_htlc message from the given peer.
	fn handle_update_fail_malformed_htlc(&self, their_node_id: &PublicKey, msg: &UpdateFailMalformedHTLC);
	/// Handle an incoming commitment_signed message from the given peer.
	fn handle_commitment_signed(&self, their_node_id: &PublicKey, msg: &CommitmentSigned);
	/// Handle an incoming revoke_and_ack message from the given peer.
	fn handle_revoke_and_ack(&self, their_node_id: &PublicKey, msg: &RevokeAndACK);

	/// Handle an incoming update_fee message from the given peer.
	fn handle_update_fee(&self, their_node_id: &PublicKey, msg: &UpdateFee);

	// Channel-to-announce:
	/// Handle an incoming announcement_signatures message from the given peer.
	fn handle_announcement_signatures(&self, their_node_id: &PublicKey, msg: &AnnouncementSignatures);

	// Connection loss/reestablish:
	/// Indicates a connection to the peer failed/an existing connection was lost. If no connection
	/// is believed to be possible in the future (eg they're sending us messages we don't
	/// understand or indicate they require unknown feature bits), no_connection_possible is set
	/// and any outstanding channels should be failed.
	fn peer_disconnected(&self, their_node_id: &PublicKey, no_connection_possible: bool);

	/// Handle a peer reconnecting, possibly generating channel_reestablish message(s).
	fn peer_connected(&self, their_node_id: &PublicKey, msg: &Init);
	/// Handle an incoming channel_reestablish message from the given peer.
	fn handle_channel_reestablish(&self, their_node_id: &PublicKey, msg: &ChannelReestablish);

	// Error:
	/// Handle an incoming error message from the given peer.
	fn handle_error(&self, their_node_id: &PublicKey, msg: &ErrorMessage);
}

/// A trait to describe an object which can receive routing messages.
///
/// # Implementor DoS Warnings
///
/// For `gossip_queries` messages there are potential DoS vectors when handling
/// inbound queries. Implementors using an on-disk network graph should be aware of
/// repeated disk I/O for queries accessing different parts of the network graph.
pub trait RoutingMessageHandler : Send + Sync + MessageSendEventsProvider {
	/// Handle an incoming node_announcement message, returning true if it should be forwarded on,
	/// false or returning an Err otherwise.
	fn handle_node_announcement(&self, msg: &NodeAnnouncement) -> Result<bool, LightningError>;
	/// Handle a channel_announcement message, returning true if it should be forwarded on, false
	/// or returning an Err otherwise.
	fn handle_channel_announcement(&self, msg: &ChannelAnnouncement) -> Result<bool, LightningError>;
	/// Handle an incoming channel_update message, returning true if it should be forwarded on,
	/// false or returning an Err otherwise.
	fn handle_channel_update(&self, msg: &ChannelUpdate) -> Result<bool, LightningError>;
	/// Handle some updates to the route graph that we learned due to an outbound failed payment.
	fn handle_htlc_fail_channel_update(&self, update: &HTLCFailChannelUpdate);
	/// Gets a subset of the channel announcements and updates required to dump our routing table
	/// to a remote node, starting at the short_channel_id indicated by starting_point and
	/// including the batch_amount entries immediately higher in numerical value than starting_point.
	fn get_next_channel_announcements(&self, starting_point: u64, batch_amount: u8) -> Vec<(ChannelAnnouncement, Option<ChannelUpdate>, Option<ChannelUpdate>)>;
	/// Gets a subset of the node announcements required to dump our routing table to a remote node,
	/// starting at the node *after* the provided publickey and including batch_amount entries
	/// immediately higher (as defined by <PublicKey as Ord>::cmp) than starting_point.
	/// If None is provided for starting_point, we start at the first node.
	fn get_next_node_announcements(&self, starting_point: Option<&PublicKey>, batch_amount: u8) -> Vec<NodeAnnouncement>;
	/// Called when a connection is established with a peer. This can be used to
	/// perform routing table synchronization using a strategy defined by the
	/// implementor.
	fn sync_routing_table(&self, their_node_id: &PublicKey, init: &Init);
	/// Handles the reply of a query we initiated to learn about channels
	/// for a given range of blocks. We can expect to receive one or more
	/// replies to a single query.
	fn handle_reply_channel_range(&self, their_node_id: &PublicKey, msg: ReplyChannelRange) -> Result<(), LightningError>;
	/// Handles the reply of a query we initiated asking for routing gossip
	/// messages for a list of channels. We should receive this message when
	/// a node has completed its best effort to send us the pertaining routing
	/// gossip messages.
	fn handle_reply_short_channel_ids_end(&self, their_node_id: &PublicKey, msg: ReplyShortChannelIdsEnd) -> Result<(), LightningError>;
	/// Handles when a peer asks us to send a list of short_channel_ids
	/// for the requested range of blocks.
	fn handle_query_channel_range(&self, their_node_id: &PublicKey, msg: QueryChannelRange) -> Result<(), LightningError>;
	/// Handles when a peer asks us to send routing gossip messages for a
	/// list of short_channel_ids.
	fn handle_query_short_channel_ids(&self, their_node_id: &PublicKey, msg: QueryShortChannelIds) -> Result<(), LightningError>;
}

mod fuzzy_internal_msgs {
	use ln::channelmanager::PaymentSecret;

	// These types aren't intended to be pub, but are exposed for direct fuzzing (as we deserialize
	// them from untrusted input):
	#[derive(Clone)]
	pub(crate) struct FinalOnionHopData {
		pub(crate) payment_secret: PaymentSecret,
		/// The total value, in msat, of the payment as received by the ultimate recipient.
		/// Message serialization may panic if this value is more than 21 million Bitcoin.
		pub(crate) total_msat: u64,
	}

	pub(crate) enum OnionHopDataFormat {
		Legacy { // aka Realm-0
			short_channel_id: u64,
		},
		NonFinalNode {
			short_channel_id: u64,
		},
		FinalNode {
			payment_data: Option<FinalOnionHopData>,
		},
	}

	pub struct OnionHopData {
		pub(crate) format: OnionHopDataFormat,
		/// The value, in msat, of the payment after this hop's fee is deducted.
		/// Message serialization may panic if this value is more than 21 million Bitcoin.
		pub(crate) amt_to_forward: u64,
		pub(crate) outgoing_cltv_value: u32,
		// 12 bytes of 0-padding for Legacy format
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

impl fmt::Display for DecodeError {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match *self {
			DecodeError::UnknownVersion => f.write_str("Unknown realm byte in Onion packet"),
			DecodeError::UnknownRequiredFeature => f.write_str("Unknown required feature preventing decode"),
			DecodeError::InvalidValue => f.write_str("Nonsense bytes didn't map to the type they were interpreted as"),
			DecodeError::ShortRead => f.write_str("Packet extended beyond the provided bytes"),
			DecodeError::BadLengthDescriptor => f.write_str("A length descriptor in the packet didn't describe the later data correctly"),
			DecodeError::Io(ref e) => e.fmt(f),
		}
	}
}

impl fmt::Debug for LightningError {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		f.write_str(self.err.as_str())
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

impl Readable for OptionalField<Script> {
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		match <u16 as Readable>::read(r) {
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

impl Writeable for OptionalField<u64> {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), ::std::io::Error> {
		match *self {
			OptionalField::Present(ref value) => {
				value.write(w)?;
			},
			OptionalField::Absent => {}
		}
		Ok(())
	}
}

impl Readable for OptionalField<u64> {
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		let value: u64 = Readable::read(r)?;
		Ok(OptionalField::Present(value))
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
	payment_point,
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

impl Readable for ChannelReestablish{
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		Ok(Self {
			channel_id: Readable::read(r)?,
			next_local_commitment_number: Readable::read(r)?,
			next_remote_commitment_number: Readable::read(r)?,
			data_loss_protect: {
				match <[u8; 32] as Readable>::read(r) {
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

impl Writeable for Init {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), ::std::io::Error> {
		// global_features gets the bottom 13 bits of our features, and local_features gets all of
		// our relevant feature bits. This keeps us compatible with old nodes.
		self.features.write_up_to_13(w)?;
		self.features.write(w)
	}
}

impl Readable for Init {
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		let global_features: InitFeatures = Readable::read(r)?;
		let features: InitFeatures = Readable::read(r)?;
		Ok(Init {
			features: features.or(global_features),
		})
	}
}

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
	payment_point,
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

impl Readable for OnionPacket {
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
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

impl Writeable for FinalOnionHopData {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), ::std::io::Error> {
		w.size_hint(32 + 8 - (self.total_msat.leading_zeros()/8) as usize);
		self.payment_secret.0.write(w)?;
		HighZeroBytesDroppedVarInt(self.total_msat).write(w)
	}
}

impl Readable for FinalOnionHopData {
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		let secret: [u8; 32] = Readable::read(r)?;
		let amt: HighZeroBytesDroppedVarInt<u64> = Readable::read(r)?;
		Ok(Self { payment_secret: PaymentSecret(secret), total_msat: amt.0 })
	}
}

impl Writeable for OnionHopData {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), ::std::io::Error> {
		w.size_hint(33);
		// Note that this should never be reachable if Rust-Lightning generated the message, as we
		// check values are sane long before we get here, though its possible in the future
		// user-generated messages may hit this.
		if self.amt_to_forward > MAX_VALUE_MSAT { panic!("We should never be sending infinite/overflow onion payments"); }
		match self.format {
			OnionHopDataFormat::Legacy { short_channel_id } => {
				0u8.write(w)?;
				short_channel_id.write(w)?;
				self.amt_to_forward.write(w)?;
				self.outgoing_cltv_value.write(w)?;
				w.write_all(&[0;12])?;
			},
			OnionHopDataFormat::NonFinalNode { short_channel_id } => {
				encode_varint_length_prefixed_tlv!(w, {
					(2, HighZeroBytesDroppedVarInt(self.amt_to_forward)),
					(4, HighZeroBytesDroppedVarInt(self.outgoing_cltv_value)),
					(6, short_channel_id)
				});
			},
			OnionHopDataFormat::FinalNode { payment_data: Some(ref final_data) } => {
				if final_data.total_msat > MAX_VALUE_MSAT { panic!("We should never be sending infinite/overflow onion payments"); }
				encode_varint_length_prefixed_tlv!(w, {
					(2, HighZeroBytesDroppedVarInt(self.amt_to_forward)),
					(4, HighZeroBytesDroppedVarInt(self.outgoing_cltv_value)),
					(8, final_data)
				});
			},
			OnionHopDataFormat::FinalNode { payment_data: None } => {
				encode_varint_length_prefixed_tlv!(w, {
					(2, HighZeroBytesDroppedVarInt(self.amt_to_forward)),
					(4, HighZeroBytesDroppedVarInt(self.outgoing_cltv_value))
				});
			},
		}
		Ok(())
	}
}

impl Readable for OnionHopData {
	fn read<R: Read>(mut r: &mut R) -> Result<Self, DecodeError> {
		use bitcoin::consensus::encode::{Decodable, Error, VarInt};
		let v: VarInt = Decodable::consensus_decode(&mut r)
			.map_err(|e| match e {
				Error::Io(ioe) => DecodeError::from(ioe),
				_ => DecodeError::InvalidValue
			})?;
		const LEGACY_ONION_HOP_FLAG: u64 = 0;
		let (format, amt, cltv_value) = if v.0 != LEGACY_ONION_HOP_FLAG {
			let mut rd = FixedLengthReader::new(r, v.0);
			let mut amt = HighZeroBytesDroppedVarInt(0u64);
			let mut cltv_value = HighZeroBytesDroppedVarInt(0u32);
			let mut short_id: Option<u64> = None;
			let mut payment_data: Option<FinalOnionHopData> = None;
			decode_tlv!(&mut rd, {
				(2, amt),
				(4, cltv_value)
			}, {
				(6, short_id),
				(8, payment_data)
			});
			rd.eat_remaining().map_err(|_| DecodeError::ShortRead)?;
			let format = if let Some(short_channel_id) = short_id {
				if payment_data.is_some() { return Err(DecodeError::InvalidValue); }
				OnionHopDataFormat::NonFinalNode {
					short_channel_id,
				}
			} else {
				if let &Some(ref data) = &payment_data {
					if data.total_msat > MAX_VALUE_MSAT {
						return Err(DecodeError::InvalidValue);
					}
				}
				OnionHopDataFormat::FinalNode {
					payment_data
				}
			};
			(format, amt.0, cltv_value.0)
		} else {
			let format = OnionHopDataFormat::Legacy {
				short_channel_id: Readable::read(r)?,
			};
			let amt: u64 = Readable::read(r)?;
			let cltv_value: u32 = Readable::read(r)?;
			r.read_exact(&mut [0; 12])?;
			(format, amt, cltv_value)
		};

		if amt > MAX_VALUE_MSAT {
			return Err(DecodeError::InvalidValue);
		}
		Ok(OnionHopData {
			format,
			amt_to_forward: amt,
			outgoing_cltv_value: cltv_value,
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

impl Readable for Ping {
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
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

impl Readable for Pong {
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
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
		w.size_hint(2 + 2*32 + 4*33 + self.features.byte_count() + self.excess_data.len());
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

impl Readable for UnsignedChannelAnnouncement {
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		Ok(Self {
			features: Readable::read(r)?,
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
			2 + 2*32 + 4*33 + features.byte_count() + excess_data.len() + 4*64 }
	}, {
	node_signature_1,
	node_signature_2,
	bitcoin_signature_1,
	bitcoin_signature_2,
	contents
});

impl Writeable for UnsignedChannelUpdate {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), ::std::io::Error> {
		let mut size = 64 + self.excess_data.len();
		let mut message_flags: u8 = 0;
		if let OptionalField::Present(_) = self.htlc_maximum_msat {
			size += 8;
			message_flags = 1;
		}
		w.size_hint(size);
		self.chain_hash.write(w)?;
		self.short_channel_id.write(w)?;
		self.timestamp.write(w)?;
		let all_flags = self.flags as u16 | ((message_flags as u16) << 8);
		all_flags.write(w)?;
		self.cltv_expiry_delta.write(w)?;
		self.htlc_minimum_msat.write(w)?;
		self.fee_base_msat.write(w)?;
		self.fee_proportional_millionths.write(w)?;
		self.htlc_maximum_msat.write(w)?;
		w.write_all(&self.excess_data[..])?;
		Ok(())
	}
}

impl Readable for UnsignedChannelUpdate {
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		let has_htlc_maximum_msat;
		Ok(Self {
			chain_hash: Readable::read(r)?,
			short_channel_id: Readable::read(r)?,
			timestamp: Readable::read(r)?,
			flags: {
				let flags: u16 = Readable::read(r)?;
				let message_flags = flags >> 8;
				has_htlc_maximum_msat = (message_flags as i32 & 1) == 1;
				flags as u8
			},
			cltv_expiry_delta: Readable::read(r)?,
			htlc_minimum_msat: Readable::read(r)?,
			fee_base_msat: Readable::read(r)?,
			fee_proportional_millionths: Readable::read(r)?,
			htlc_maximum_msat: if has_htlc_maximum_msat { Readable::read(r)? } else { OptionalField::Absent },
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

impl Readable for ErrorMessage {
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		Ok(Self {
			channel_id: Readable::read(r)?,
			data: {
				let mut sz: usize = <u16 as Readable>::read(r)? as usize;
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
		w.size_hint(64 + 76 + self.features.byte_count() + self.addresses.len()*38 + self.excess_address_data.len() + self.excess_data.len());
		self.features.write(w)?;
		self.timestamp.write(w)?;
		self.node_id.write(w)?;
		w.write_all(&self.rgb)?;
		self.alias.write(w)?;

		let mut addrs_to_encode = self.addresses.clone();
		addrs_to_encode.sort_by(|a, b| { a.get_id().cmp(&b.get_id()) });
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

impl Readable for UnsignedNodeAnnouncement {
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		let features: NodeFeatures = Readable::read(r)?;
		let timestamp: u32 = Readable::read(r)?;
		let node_id: PublicKey = Readable::read(r)?;
		let mut rgb = [0; 3];
		r.read_exact(&mut rgb)?;
		let alias: [u8; 32] = Readable::read(r)?;

		let addr_len: u16 = Readable::read(r)?;
		let mut addresses: Vec<NetAddress> = Vec::new();
		let mut highest_addr_type = 0;
		let mut addr_readpos = 0;
		let mut excess = false;
		let mut excess_byte = 0;
		loop {
			if addr_len <= addr_readpos { break; }
			match Readable::read(r) {
				Ok(Ok(addr)) => {
					if addr.get_id() < highest_addr_type {
						// Addresses must be sorted in increasing order
						return Err(DecodeError::InvalidValue);
					}
					highest_addr_type = addr.get_id();
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
			64 + 76 + features.byte_count() + addresses.len()*(NetAddress::MAX_LEN as usize + 1) + excess_address_data.len() + excess_data.len() }
	}, {
	signature,
	contents
});

impl Readable for QueryShortChannelIds {
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		let chain_hash: BlockHash = Readable::read(r)?;

		// We expect the encoding_len to always includes the 1-byte
		// encoding_type and that short_channel_ids are 8-bytes each
		let encoding_len: u16 = Readable::read(r)?;
		if encoding_len == 0 || (encoding_len - 1) % 8 != 0 {
			return Err(DecodeError::InvalidValue);
		}

		// Must be encoding_type=0 uncompressed serialization. We do not
		// support encoding_type=1 zlib serialization.
		let encoding_type: u8 = Readable::read(r)?;
		if encoding_type != EncodingType::Uncompressed as u8 {
			return Err(DecodeError::InvalidValue);
		}

		// Read short_channel_ids (8-bytes each), for the u16 encoding_len
		// less the 1-byte encoding_type
		let short_channel_id_count: u16 = (encoding_len - 1)/8;
		let mut short_channel_ids = Vec::with_capacity(short_channel_id_count as usize);
		for _ in 0..short_channel_id_count {
			short_channel_ids.push(Readable::read(r)?);
		}

		Ok(QueryShortChannelIds {
			chain_hash,
			short_channel_ids,
		})
	}
}

impl Writeable for QueryShortChannelIds {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), ::std::io::Error> {
		// Calculated from 1-byte encoding_type plus 8-bytes per short_channel_id
		let encoding_len: u16 = 1 + self.short_channel_ids.len() as u16 * 8;

		w.size_hint(32 + 2 + encoding_len as usize);
		self.chain_hash.write(w)?;
		encoding_len.write(w)?;

		// We only support type=0 uncompressed serialization
		(EncodingType::Uncompressed as u8).write(w)?;

		for scid in self.short_channel_ids.iter() {
			scid.write(w)?;
		}

		Ok(())
	}
}

impl Readable for ReplyShortChannelIdsEnd {
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		let chain_hash: BlockHash = Readable::read(r)?;
		let full_information: bool = Readable::read(r)?;
		Ok(ReplyShortChannelIdsEnd {
			chain_hash,
			full_information,
		})
	}
}

impl Writeable for ReplyShortChannelIdsEnd {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), ::std::io::Error> {
		w.size_hint(32 + 1);
		self.chain_hash.write(w)?;
		self.full_information.write(w)?;
		Ok(())
	}
}

impl Readable for QueryChannelRange {
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		let chain_hash: BlockHash = Readable::read(r)?;
		let first_blocknum: u32 = Readable::read(r)?;
		let number_of_blocks: u32 = Readable::read(r)?;
		Ok(QueryChannelRange {
			chain_hash,
			first_blocknum,
			number_of_blocks
		})
	}
}

impl Writeable for QueryChannelRange {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), ::std::io::Error> {
		w.size_hint(32 + 4 + 4);
		self.chain_hash.write(w)?;
		self.first_blocknum.write(w)?;
		self.number_of_blocks.write(w)?;
		Ok(())
	}
}

impl Readable for ReplyChannelRange {
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		let chain_hash: BlockHash = Readable::read(r)?;
		let first_blocknum: u32 = Readable::read(r)?;
		let number_of_blocks: u32 = Readable::read(r)?;
		let full_information: bool = Readable::read(r)?;

		// We expect the encoding_len to always includes the 1-byte
		// encoding_type and that short_channel_ids are 8-bytes each
		let encoding_len: u16 = Readable::read(r)?;
		if encoding_len == 0 || (encoding_len - 1) % 8 != 0 {
			return Err(DecodeError::InvalidValue);
		}

		// Must be encoding_type=0 uncompressed serialization. We do not
		// support encoding_type=1 zlib serialization.
		let encoding_type: u8 = Readable::read(r)?;
		if encoding_type != EncodingType::Uncompressed as u8 {
			return Err(DecodeError::InvalidValue);
		}

		// Read short_channel_ids (8-bytes each), for the u16 encoding_len
		// less the 1-byte encoding_type
		let short_channel_id_count: u16 = (encoding_len - 1)/8;
		let mut short_channel_ids = Vec::with_capacity(short_channel_id_count as usize);
		for _ in 0..short_channel_id_count {
			short_channel_ids.push(Readable::read(r)?);
		}

		Ok(ReplyChannelRange {
			chain_hash,
			first_blocknum,
			number_of_blocks,
			full_information,
			short_channel_ids
		})
	}
}

impl Writeable for ReplyChannelRange {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), ::std::io::Error> {
		let encoding_len: u16 = 1 + self.short_channel_ids.len() as u16 * 8;
		w.size_hint(32 + 4 + 4 + 1 + 2 + encoding_len as usize);
		self.chain_hash.write(w)?;
		self.first_blocknum.write(w)?;
		self.number_of_blocks.write(w)?;
		self.full_information.write(w)?;

		encoding_len.write(w)?;
		(EncodingType::Uncompressed as u8).write(w)?;
		for scid in self.short_channel_ids.iter() {
			scid.write(w)?;
		}

		Ok(())
	}
}

impl Readable for GossipTimestampFilter {
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		let chain_hash: BlockHash = Readable::read(r)?;
		let first_timestamp: u32 = Readable::read(r)?;
		let timestamp_range: u32 = Readable::read(r)?;
		Ok(GossipTimestampFilter {
			chain_hash,
			first_timestamp,
			timestamp_range,
		})
	}
}

impl Writeable for GossipTimestampFilter {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), ::std::io::Error> {
		w.size_hint(32 + 4 + 4);
		self.chain_hash.write(w)?;
		self.first_timestamp.write(w)?;
		self.timestamp_range.write(w)?;
		Ok(())
	}
}


#[cfg(test)]
mod tests {
	use hex;
	use ln::msgs;
	use ln::msgs::{ChannelFeatures, FinalOnionHopData, InitFeatures, NodeFeatures, OptionalField, OnionErrorPacket, OnionHopDataFormat};
	use ln::channelmanager::{PaymentPreimage, PaymentHash, PaymentSecret};
	use util::ser::{Writeable, Readable};

	use bitcoin::hashes::hex::FromHex;
	use bitcoin::util::address::Address;
	use bitcoin::network::constants::Network;
	use bitcoin::blockdata::script::Builder;
	use bitcoin::blockdata::opcodes;
	use bitcoin::hash_types::{Txid, BlockHash};

	use bitcoin::secp256k1::key::{PublicKey,SecretKey};
	use bitcoin::secp256k1::{Secp256k1, Message};

	use std::io::Cursor;

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

	fn do_encoding_channel_announcement(unknown_features_bits: bool, excess_data: bool) {
		let secp_ctx = Secp256k1::new();
		let (privkey_1, pubkey_1) = get_keys_from!("0101010101010101010101010101010101010101010101010101010101010101", secp_ctx);
		let (privkey_2, pubkey_2) = get_keys_from!("0202020202020202020202020202020202020202020202020202020202020202", secp_ctx);
		let (privkey_3, pubkey_3) = get_keys_from!("0303030303030303030303030303030303030303030303030303030303030303", secp_ctx);
		let (privkey_4, pubkey_4) = get_keys_from!("0404040404040404040404040404040404040404040404040404040404040404", secp_ctx);
		let sig_1 = get_sig_on!(privkey_1, secp_ctx, String::from("01010101010101010101010101010101"));
		let sig_2 = get_sig_on!(privkey_2, secp_ctx, String::from("01010101010101010101010101010101"));
		let sig_3 = get_sig_on!(privkey_3, secp_ctx, String::from("01010101010101010101010101010101"));
		let sig_4 = get_sig_on!(privkey_4, secp_ctx, String::from("01010101010101010101010101010101"));
		let mut features = ChannelFeatures::known();
		if unknown_features_bits {
			features = ChannelFeatures::from_le_bytes(vec![0xFF, 0xFF]);
		}
		let unsigned_channel_announcement = msgs::UnsignedChannelAnnouncement {
			features,
			chain_hash: BlockHash::from_hex("6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000").unwrap(),
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
		target_value.append(&mut hex::decode("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f").unwrap());
		target_value.append(&mut hex::decode("00083a840000034d031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f024d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d076602531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe33703462779ad4aad39514614751a71085f2f10e1c7a593e4e030efb5b8721ce55b0b").unwrap());
		if excess_data {
			target_value.append(&mut hex::decode("0a00001400001e000028").unwrap());
		}
		assert_eq!(encoded_value, target_value);
	}

	#[test]
	fn encoding_channel_announcement() {
		do_encoding_channel_announcement(true, false);
		do_encoding_channel_announcement(false, true);
		do_encoding_channel_announcement(false, false);
		do_encoding_channel_announcement(true, true);
	}

	fn do_encoding_node_announcement(unknown_features_bits: bool, ipv4: bool, ipv6: bool, onionv2: bool, onionv3: bool, excess_address_data: bool, excess_data: bool) {
		let secp_ctx = Secp256k1::new();
		let (privkey_1, pubkey_1) = get_keys_from!("0101010101010101010101010101010101010101010101010101010101010101", secp_ctx);
		let sig_1 = get_sig_on!(privkey_1, secp_ctx, String::from("01010101010101010101010101010101"));
		let features = if unknown_features_bits {
			NodeFeatures::from_le_bytes(vec![0xFF, 0xFF])
		} else {
			// Set to some features we may support
			NodeFeatures::from_le_bytes(vec![2 | 1 << 5])
		};
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
			target_value.append(&mut hex::decode("000122").unwrap());
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

	fn do_encoding_channel_update(direction: bool, disable: bool, htlc_maximum_msat: bool, excess_data: bool) {
		let secp_ctx = Secp256k1::new();
		let (privkey_1, _) = get_keys_from!("0101010101010101010101010101010101010101010101010101010101010101", secp_ctx);
		let sig_1 = get_sig_on!(privkey_1, secp_ctx, String::from("01010101010101010101010101010101"));
		let unsigned_channel_update = msgs::UnsignedChannelUpdate {
			chain_hash: BlockHash::from_hex("6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000").unwrap(),
			short_channel_id: 2316138423780173,
			timestamp: 20190119,
			flags: if direction { 1 } else { 0 } | if disable { 1 << 1 } else { 0 },
			cltv_expiry_delta: 144,
			htlc_minimum_msat: 1000000,
			htlc_maximum_msat: if htlc_maximum_msat { OptionalField::Present(131355275467161) } else { OptionalField::Absent },
			fee_base_msat: 10000,
			fee_proportional_millionths: 20,
			excess_data: if excess_data { vec![0, 0, 0, 0, 59, 154, 202, 0] } else { Vec::new() }
		};
		let channel_update = msgs::ChannelUpdate {
			signature: sig_1,
			contents: unsigned_channel_update
		};
		let encoded_value = channel_update.encode();
		let mut target_value = hex::decode("d977cb9b53d93a6ff64bb5f1e158b4094b66e798fb12911168a3ccdf80a83096340a6a95da0ae8d9f776528eecdbb747eb6b545495a4319ed5378e35b21e073a").unwrap();
		target_value.append(&mut hex::decode("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f").unwrap());
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
			target_value.append(&mut hex::decode("0000777788889999").unwrap());
		}
		if excess_data {
			target_value.append(&mut hex::decode("000000003b9aca00").unwrap());
		}
		assert_eq!(encoded_value, target_value);
	}

	#[test]
	fn encoding_channel_update() {
		do_encoding_channel_update(false, false, false, false);
		do_encoding_channel_update(false, false, false, true);
		do_encoding_channel_update(true, false, false, false);
		do_encoding_channel_update(true, false, false, true);
		do_encoding_channel_update(false, true, false, false);
		do_encoding_channel_update(false, true, false, true);
		do_encoding_channel_update(false, false, true, false);
		do_encoding_channel_update(false, false, true, true);
		do_encoding_channel_update(true, true, true, false);
		do_encoding_channel_update(true, true, true, true);
	}

	fn do_encoding_open_channel(random_bit: bool, shutdown: bool) {
		let secp_ctx = Secp256k1::new();
		let (_, pubkey_1) = get_keys_from!("0101010101010101010101010101010101010101010101010101010101010101", secp_ctx);
		let (_, pubkey_2) = get_keys_from!("0202020202020202020202020202020202020202020202020202020202020202", secp_ctx);
		let (_, pubkey_3) = get_keys_from!("0303030303030303030303030303030303030303030303030303030303030303", secp_ctx);
		let (_, pubkey_4) = get_keys_from!("0404040404040404040404040404040404040404040404040404040404040404", secp_ctx);
		let (_, pubkey_5) = get_keys_from!("0505050505050505050505050505050505050505050505050505050505050505", secp_ctx);
		let (_, pubkey_6) = get_keys_from!("0606060606060606060606060606060606060606060606060606060606060606", secp_ctx);
		let open_channel = msgs::OpenChannel {
			chain_hash: BlockHash::from_hex("6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000").unwrap(),
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
			payment_point: pubkey_3,
			delayed_payment_basepoint: pubkey_4,
			htlc_basepoint: pubkey_5,
			first_per_commitment_point: pubkey_6,
			channel_flags: if random_bit { 1 << 5 } else { 0 },
			shutdown_scriptpubkey: if shutdown { OptionalField::Present(Address::p2pkh(&::bitcoin::PublicKey{compressed: true, key: pubkey_1}, Network::Testnet).script_pubkey()) } else { OptionalField::Absent }
		};
		let encoded_value = open_channel.encode();
		let mut target_value = Vec::new();
		target_value.append(&mut hex::decode("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f").unwrap());
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
		do_encoding_open_channel(false, false);
		do_encoding_open_channel(true, false);
		do_encoding_open_channel(false, true);
		do_encoding_open_channel(true, true);
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
			payment_point: pubkey_3,
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
			funding_txid: Txid::from_hex("c2d4449afa8d26140898dd54d3390b057ba2a5afcf03ba29d7dc0d8b9ffe966e").unwrap(),
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
			scriptpubkey:
				     if script_type == 1 { Address::p2pkh(&::bitcoin::PublicKey{compressed: true, key: pubkey_1}, Network::Testnet).script_pubkey() }
				else if script_type == 2 { Address::p2sh(&script, Network::Testnet).script_pubkey() }
				else if script_type == 3 { Address::p2wpkh(&::bitcoin::PublicKey{compressed: true, key: pubkey_1}, Network::Testnet).unwrap().script_pubkey() }
				else                     { Address::p2wsh(&script, Network::Testnet).script_pubkey() },
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

	#[test]
	fn encoding_init() {
		assert_eq!(msgs::Init {
			features: InitFeatures::from_le_bytes(vec![0xFF, 0xFF, 0xFF]),
		}.encode(), hex::decode("00023fff0003ffffff").unwrap());
		assert_eq!(msgs::Init {
			features: InitFeatures::from_le_bytes(vec![0xFF]),
		}.encode(), hex::decode("0001ff0001ff").unwrap());
		assert_eq!(msgs::Init {
			features: InitFeatures::from_le_bytes(vec![]),
		}.encode(), hex::decode("00000000").unwrap());
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

	#[test]
	fn encoding_legacy_onion_hop_data() {
		let msg = msgs::OnionHopData {
			format: OnionHopDataFormat::Legacy {
				short_channel_id: 0xdeadbeef1bad1dea,
			},
			amt_to_forward: 0x0badf00d01020304,
			outgoing_cltv_value: 0xffffffff,
		};
		let encoded_value = msg.encode();
		let target_value = hex::decode("00deadbeef1bad1dea0badf00d01020304ffffffff000000000000000000000000").unwrap();
		assert_eq!(encoded_value, target_value);
	}

	#[test]
	fn encoding_nonfinal_onion_hop_data() {
		let mut msg = msgs::OnionHopData {
			format: OnionHopDataFormat::NonFinalNode {
				short_channel_id: 0xdeadbeef1bad1dea,
			},
			amt_to_forward: 0x0badf00d01020304,
			outgoing_cltv_value: 0xffffffff,
		};
		let encoded_value = msg.encode();
		let target_value = hex::decode("1a02080badf00d010203040404ffffffff0608deadbeef1bad1dea").unwrap();
		assert_eq!(encoded_value, target_value);
		msg = Readable::read(&mut Cursor::new(&target_value[..])).unwrap();
		if let OnionHopDataFormat::NonFinalNode { short_channel_id } = msg.format {
			assert_eq!(short_channel_id, 0xdeadbeef1bad1dea);
		} else { panic!(); }
		assert_eq!(msg.amt_to_forward, 0x0badf00d01020304);
		assert_eq!(msg.outgoing_cltv_value, 0xffffffff);
	}

	#[test]
	fn encoding_final_onion_hop_data() {
		let mut msg = msgs::OnionHopData {
			format: OnionHopDataFormat::FinalNode {
				payment_data: None,
			},
			amt_to_forward: 0x0badf00d01020304,
			outgoing_cltv_value: 0xffffffff,
		};
		let encoded_value = msg.encode();
		let target_value = hex::decode("1002080badf00d010203040404ffffffff").unwrap();
		assert_eq!(encoded_value, target_value);
		msg = Readable::read(&mut Cursor::new(&target_value[..])).unwrap();
		if let OnionHopDataFormat::FinalNode { payment_data: None } = msg.format { } else { panic!(); }
		assert_eq!(msg.amt_to_forward, 0x0badf00d01020304);
		assert_eq!(msg.outgoing_cltv_value, 0xffffffff);
	}

	#[test]
	fn encoding_final_onion_hop_data_with_secret() {
		let expected_payment_secret = PaymentSecret([0x42u8; 32]);
		let mut msg = msgs::OnionHopData {
			format: OnionHopDataFormat::FinalNode {
				payment_data: Some(FinalOnionHopData {
					payment_secret: expected_payment_secret,
					total_msat: 0x1badca1f
				}),
			},
			amt_to_forward: 0x0badf00d01020304,
			outgoing_cltv_value: 0xffffffff,
		};
		let encoded_value = msg.encode();
		let target_value = hex::decode("3602080badf00d010203040404ffffffff082442424242424242424242424242424242424242424242424242424242424242421badca1f").unwrap();
		assert_eq!(encoded_value, target_value);
		msg = Readable::read(&mut Cursor::new(&target_value[..])).unwrap();
		if let OnionHopDataFormat::FinalNode {
			payment_data: Some(FinalOnionHopData {
				payment_secret,
				total_msat: 0x1badca1f
			})
		} = msg.format {
			assert_eq!(payment_secret, expected_payment_secret);
		} else { panic!(); }
		assert_eq!(msg.amt_to_forward, 0x0badf00d01020304);
		assert_eq!(msg.outgoing_cltv_value, 0xffffffff);
	}

	#[test]
	fn encoding_query_channel_range() {
		let mut query_channel_range = msgs::QueryChannelRange {
			chain_hash: BlockHash::from_hex("06226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f").unwrap(),
			first_blocknum: 100000,
			number_of_blocks: 1500,
		};
		let encoded_value = query_channel_range.encode();
		let target_value = hex::decode("0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206000186a0000005dc").unwrap();
		assert_eq!(encoded_value, target_value);

		query_channel_range = Readable::read(&mut Cursor::new(&target_value[..])).unwrap();
		assert_eq!(query_channel_range.first_blocknum, 100000);
		assert_eq!(query_channel_range.number_of_blocks, 1500);
	}

	#[test]
	fn encoding_reply_channel_range() {
		do_encoding_reply_channel_range(0);
		do_encoding_reply_channel_range(1);
	}

	fn do_encoding_reply_channel_range(encoding_type: u8) {
		let mut target_value = hex::decode("0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206000b8a06000005dc01").unwrap();
		let expected_chain_hash = BlockHash::from_hex("06226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f").unwrap();
		let mut reply_channel_range = msgs::ReplyChannelRange {
			chain_hash: expected_chain_hash,
			first_blocknum: 756230,
			number_of_blocks: 1500,
			full_information: true,
			short_channel_ids: vec![0x000000000000008e, 0x0000000000003c69, 0x000000000045a6c4],
		};

		if encoding_type == 0 {
			target_value.append(&mut hex::decode("001900000000000000008e0000000000003c69000000000045a6c4").unwrap());
			let encoded_value = reply_channel_range.encode();
			assert_eq!(encoded_value, target_value);

			reply_channel_range = Readable::read(&mut Cursor::new(&target_value[..])).unwrap();
			assert_eq!(reply_channel_range.chain_hash, expected_chain_hash);
			assert_eq!(reply_channel_range.first_blocknum, 756230);
			assert_eq!(reply_channel_range.number_of_blocks, 1500);
			assert_eq!(reply_channel_range.full_information, true);
			assert_eq!(reply_channel_range.short_channel_ids[0], 0x000000000000008e);
			assert_eq!(reply_channel_range.short_channel_ids[1], 0x0000000000003c69);
			assert_eq!(reply_channel_range.short_channel_ids[2], 0x000000000045a6c4);
		} else {
			target_value.append(&mut hex::decode("001601789c636000833e08659309a65878be010010a9023a").unwrap());
			let result: Result<msgs::ReplyChannelRange, msgs::DecodeError> = Readable::read(&mut Cursor::new(&target_value[..]));
			assert!(result.is_err(), "Expected decode failure with unsupported zlib encoding");
		}
	}

	#[test]
	fn encoding_query_short_channel_ids() {
		do_encoding_query_short_channel_ids(0);
		do_encoding_query_short_channel_ids(1);
	}

	fn do_encoding_query_short_channel_ids(encoding_type: u8) {
		let mut target_value = hex::decode("0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206").unwrap();
		let expected_chain_hash = BlockHash::from_hex("06226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f").unwrap();
		let mut query_short_channel_ids = msgs::QueryShortChannelIds {
			chain_hash: expected_chain_hash,
			short_channel_ids: vec![0x0000000000008e, 0x0000000000003c69, 0x000000000045a6c4],
		};

		if encoding_type == 0 {
			target_value.append(&mut hex::decode("001900000000000000008e0000000000003c69000000000045a6c4").unwrap());
			let encoded_value = query_short_channel_ids.encode();
			assert_eq!(encoded_value, target_value);

			query_short_channel_ids = Readable::read(&mut Cursor::new(&target_value[..])).unwrap();
			assert_eq!(query_short_channel_ids.chain_hash, expected_chain_hash);
			assert_eq!(query_short_channel_ids.short_channel_ids[0], 0x000000000000008e);
			assert_eq!(query_short_channel_ids.short_channel_ids[1], 0x0000000000003c69);
			assert_eq!(query_short_channel_ids.short_channel_ids[2], 0x000000000045a6c4);
		} else {
			target_value.append(&mut hex::decode("001601789c636000833e08659309a65878be010010a9023a").unwrap());
			let result: Result<msgs::QueryShortChannelIds, msgs::DecodeError> = Readable::read(&mut Cursor::new(&target_value[..]));
			assert!(result.is_err(), "Expected decode failure with unsupported zlib encoding");
		}
	}

	#[test]
	fn encoding_reply_short_channel_ids_end() {
		let expected_chain_hash = BlockHash::from_hex("06226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f").unwrap();
		let mut reply_short_channel_ids_end = msgs::ReplyShortChannelIdsEnd {
			chain_hash: expected_chain_hash,
			full_information: true,
		};
		let encoded_value = reply_short_channel_ids_end.encode();
		let target_value = hex::decode("0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e220601").unwrap();
		assert_eq!(encoded_value, target_value);

		reply_short_channel_ids_end = Readable::read(&mut Cursor::new(&target_value[..])).unwrap();
		assert_eq!(reply_short_channel_ids_end.chain_hash, expected_chain_hash);
		assert_eq!(reply_short_channel_ids_end.full_information, true);
	}

	#[test]
	fn encoding_gossip_timestamp_filter(){
		let expected_chain_hash = BlockHash::from_hex("06226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f").unwrap();
		let mut gossip_timestamp_filter = msgs::GossipTimestampFilter {
			chain_hash: expected_chain_hash,
			first_timestamp: 1590000000,
			timestamp_range: 0xffff_ffff,
		};
		let encoded_value = gossip_timestamp_filter.encode();
		let target_value = hex::decode("0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e22065ec57980ffffffff").unwrap();
		assert_eq!(encoded_value, target_value);

		gossip_timestamp_filter = Readable::read(&mut Cursor::new(&target_value[..])).unwrap();
		assert_eq!(gossip_timestamp_filter.chain_hash, expected_chain_hash);
		assert_eq!(gossip_timestamp_filter.first_timestamp, 1590000000);
		assert_eq!(gossip_timestamp_filter.timestamp_range, 0xffff_ffff);
	}
}
