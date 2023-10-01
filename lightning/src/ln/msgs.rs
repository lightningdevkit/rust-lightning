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
//! [`ChannelMessageHandler`] yourself and use it to re-serialize messages and pass them across
//! daemons/servers.
//!
//! Note that if you go with such an architecture (instead of passing raw socket events to a
//! non-internet-facing system) you trust the frontend internet-facing system to not lie about the
//! source `node_id` of the message, however this does allow you to significantly reduce bandwidth
//! between the systems as routing messages can represent a significant chunk of bandwidth usage
//! (especially for non-channel-publicly-announcing nodes). As an alternate design which avoids
//! this issue, if you have sufficient bidirectional bandwidth between your systems, you may send
//! raw socket events into your non-internet-facing system and then send routing events back to
//! track the network on the less-secure system.

use bitcoin::blockdata::constants::ChainHash;
use bitcoin::secp256k1::PublicKey;
use bitcoin::secp256k1::ecdsa::Signature;
use bitcoin::{secp256k1, Witness};
use bitcoin::blockdata::script::Script;
use bitcoin::hash_types::{Txid, BlockHash};

use crate::ln::{ChannelId, PaymentPreimage, PaymentHash, PaymentSecret};
use crate::ln::features::{ChannelFeatures, ChannelTypeFeatures, InitFeatures, NodeFeatures};
use crate::ln::onion_utils;
use crate::onion_message;

use crate::prelude::*;
use core::convert::TryFrom;
use core::fmt;
use core::fmt::Debug;
use core::str::FromStr;
use crate::io::{self, Read};
use crate::io_extras::read_to_end;

use crate::events::{MessageSendEventsProvider, OnionMessageProvider};
use crate::util::logger;
use crate::util::ser::{LengthReadable, Readable, ReadableArgs, Writeable, Writer, WithoutLength, FixedLengthReader, HighZeroBytesDroppedBigSize, Hostname, TransactionU16LenLimited, BigSize};
use crate::util::base32;

use crate::routing::gossip::{NodeAlias, NodeId};

/// 21 million * 10^8 * 1000
pub(crate) const MAX_VALUE_MSAT: u64 = 21_000_000_0000_0000_000;

#[cfg(taproot)]
/// A partial signature that also contains the Musig2 nonce its signer used
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PartialSignatureWithNonce(pub musig2::types::PartialSignature, pub musig2::types::PublicNonce);

/// An error in decoding a message or struct.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecodeError {
	/// A version byte specified something we don't know how to handle.
	///
	/// Includes unknown realm byte in an onion hop data packet.
	UnknownVersion,
	/// Unknown feature mandating we fail to parse message (e.g., TLV with an even, unknown type)
	UnknownRequiredFeature,
	/// Value was invalid.
	///
	/// For example, a byte which was supposed to be a bool was something other than a 0
	/// or 1, a public key/private key/signature was invalid, text wasn't UTF-8, TLV was
	/// syntactically incorrect, etc.
	InvalidValue,
	/// The buffer to be read was too short.
	ShortRead,
	/// A length descriptor in the packet didn't describe the later data correctly.
	BadLengthDescriptor,
	/// Error from [`std::io`].
	Io(io::ErrorKind),
	/// The message included zlib-compressed values, which we don't support.
	UnsupportedCompression,
}

/// An [`init`] message to be sent to or received from a peer.
///
/// [`init`]: https://github.com/lightning/bolts/blob/master/01-messaging.md#the-init-message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Init {
	/// The relevant features which the sender supports.
	pub features: InitFeatures,
	/// Indicates chains the sender is interested in.
	///
	/// If there are no common chains, the connection will be closed.
	pub networks: Option<Vec<ChainHash>>,
	/// The receipient's network address.
	///
	/// This adds the option to report a remote IP address back to a connecting peer using the init
	/// message. A node can decide to use that information to discover a potential update to its
	/// public IPv4 address (NAT) and use that for a [`NodeAnnouncement`] update message containing
	/// the new address.
	pub remote_network_address: Option<NetAddress>,
}

/// An [`error`] message to be sent to or received from a peer.
///
/// [`error`]: https://github.com/lightning/bolts/blob/master/01-messaging.md#the-error-and-warning-messages
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ErrorMessage {
	/// The channel ID involved in the error.
	///
	/// All-0s indicates a general error unrelated to a specific channel, after which all channels
	/// with the sending peer should be closed.
	pub channel_id: ChannelId,
	/// A possibly human-readable error description.
	///
	/// The string should be sanitized before it is used (e.g., emitted to logs or printed to
	/// `stdout`). Otherwise, a well crafted error message may trigger a security vulnerability in
	/// the terminal emulator or the logging subsystem.
	pub data: String,
}

/// A [`warning`] message to be sent to or received from a peer.
///
/// [`warning`]: https://github.com/lightning/bolts/blob/master/01-messaging.md#the-error-and-warning-messages
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WarningMessage {
	/// The channel ID involved in the warning.
	///
	/// All-0s indicates a warning unrelated to a specific channel.
	pub channel_id: ChannelId,
	/// A possibly human-readable warning description.
	///
	/// The string should be sanitized before it is used (e.g. emitted to logs or printed to
	/// stdout). Otherwise, a well crafted error message may trigger a security vulnerability in
	/// the terminal emulator or the logging subsystem.
	pub data: String,
}

/// A [`ping`] message to be sent to or received from a peer.
///
/// [`ping`]: https://github.com/lightning/bolts/blob/master/01-messaging.md#the-ping-and-pong-messages
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ping {
	/// The desired response length.
	pub ponglen: u16,
	/// The ping packet size.
	///
	/// This field is not sent on the wire. byteslen zeros are sent.
	pub byteslen: u16,
}

/// A [`pong`] message to be sent to or received from a peer.
///
/// [`pong`]: https://github.com/lightning/bolts/blob/master/01-messaging.md#the-ping-and-pong-messages
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pong {
	/// The pong packet size.
	///
	/// This field is not sent on the wire. byteslen zeros are sent.
	pub byteslen: u16,
}

/// An [`open_channel`] message to be sent to or received from a peer.
///
/// Used in V1 channel establishment
///
/// [`open_channel`]: https://github.com/lightning/bolts/blob/master/02-peer-protocol.md#the-open_channel-message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenChannel {
	/// The genesis hash of the blockchain where the channel is to be opened
	pub chain_hash: BlockHash,
	/// A temporary channel ID, until the funding outpoint is announced
	pub temporary_channel_id: ChannelId,
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
	/// The feerate per 1000-weight of sender generated transactions, until updated by
	/// [`UpdateFee`]
	pub feerate_per_kw: u32,
	/// The number of blocks which the counterparty will have to wait to claim on-chain funds if
	/// they broadcast a commitment transaction
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
	/// The channel flags to be used
	pub channel_flags: u8,
	/// A request to pre-set the to-sender output's `scriptPubkey` for when we collaboratively close
	pub shutdown_scriptpubkey: Option<Script>,
	/// The channel type that this channel will represent
	///
	/// If this is `None`, we derive the channel type from the intersection of our
	/// feature bits with our counterparty's feature bits from the [`Init`] message.
	pub channel_type: Option<ChannelTypeFeatures>,
}

/// An open_channel2 message to be sent by or received from the channel initiator.
///
/// Used in V2 channel establishment
///
// TODO(dual_funding): Add spec link for `open_channel2`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenChannelV2 {
	/// The genesis hash of the blockchain where the channel is to be opened
	pub chain_hash: BlockHash,
	/// A temporary channel ID derived using a zeroed out value for the channel acceptor's revocation basepoint
	pub temporary_channel_id: ChannelId,
	/// The feerate for the funding transaction set by the channel initiator
	pub funding_feerate_sat_per_1000_weight: u32,
	/// The feerate for the commitment transaction set by the channel initiator
	pub commitment_feerate_sat_per_1000_weight: u32,
	/// Part of the channel value contributed by the channel initiator
	pub funding_satoshis: u64,
	/// The threshold below which outputs on transactions broadcast by the channel initiator will be
	/// omitted
	pub dust_limit_satoshis: u64,
	/// The maximum inbound HTLC value in flight towards channel initiator, in milli-satoshi
	pub max_htlc_value_in_flight_msat: u64,
	/// The minimum HTLC size incoming to channel initiator, in milli-satoshi
	pub htlc_minimum_msat: u64,
	/// The number of blocks which the counterparty will have to wait to claim on-chain funds if they
	/// broadcast a commitment transaction
	pub to_self_delay: u16,
	/// The maximum number of inbound HTLCs towards channel initiator
	pub max_accepted_htlcs: u16,
	/// The locktime for the funding transaction
	pub locktime: u32,
	/// The channel initiator's key controlling the funding transaction
	pub funding_pubkey: PublicKey,
	/// Used to derive a revocation key for transactions broadcast by counterparty
	pub revocation_basepoint: PublicKey,
	/// A payment key to channel initiator for transactions broadcast by counterparty
	pub payment_basepoint: PublicKey,
	/// Used to derive a payment key to channel initiator for transactions broadcast by channel
	/// initiator
	pub delayed_payment_basepoint: PublicKey,
	/// Used to derive an HTLC payment key to channel initiator
	pub htlc_basepoint: PublicKey,
	/// The first to-be-broadcast-by-channel-initiator transaction's per commitment point
	pub first_per_commitment_point: PublicKey,
	/// The second to-be-broadcast-by-channel-initiator transaction's per commitment point
	pub second_per_commitment_point: PublicKey,
	/// Channel flags
	pub channel_flags: u8,
	/// Optionally, a request to pre-set the to-channel-initiator output's scriptPubkey for when we
	/// collaboratively close
	pub shutdown_scriptpubkey: Option<Script>,
	/// The channel type that this channel will represent. If none is set, we derive the channel
	/// type from the intersection of our feature bits with our counterparty's feature bits from
	/// the Init message.
	pub channel_type: Option<ChannelTypeFeatures>,
	/// Optionally, a requirement that only confirmed inputs can be added
	pub require_confirmed_inputs: Option<()>,
}

/// An [`accept_channel`] message to be sent to or received from a peer.
///
/// Used in V1 channel establishment
///
/// [`accept_channel`]: https://github.com/lightning/bolts/blob/master/02-peer-protocol.md#the-accept_channel-message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcceptChannel {
	/// A temporary channel ID, until the funding outpoint is announced
	pub temporary_channel_id: ChannelId,
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
	/// A request to pre-set the to-sender output's scriptPubkey for when we collaboratively close
	pub shutdown_scriptpubkey: Option<Script>,
	/// The channel type that this channel will represent.
	///
	/// If this is `None`, we derive the channel type from the intersection of
	/// our feature bits with our counterparty's feature bits from the [`Init`] message.
	/// This is required to match the equivalent field in [`OpenChannel::channel_type`].
	pub channel_type: Option<ChannelTypeFeatures>,
	#[cfg(taproot)]
	/// Next nonce the channel initiator should use to create a funding output signature against
	pub next_local_nonce: Option<musig2::types::PublicNonce>,
}

/// An accept_channel2 message to be sent by or received from the channel accepter.
///
/// Used in V2 channel establishment
///
// TODO(dual_funding): Add spec link for `accept_channel2`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcceptChannelV2 {
	/// The same `temporary_channel_id` received from the initiator's `open_channel2` message.
	pub temporary_channel_id: ChannelId,
	/// Part of the channel value contributed by the channel acceptor
	pub funding_satoshis: u64,
	/// The threshold below which outputs on transactions broadcast by the channel acceptor will be
	/// omitted
	pub dust_limit_satoshis: u64,
	/// The maximum inbound HTLC value in flight towards channel acceptor, in milli-satoshi
	pub max_htlc_value_in_flight_msat: u64,
	/// The minimum HTLC size incoming to channel acceptor, in milli-satoshi
	pub htlc_minimum_msat: u64,
	/// Minimum depth of the funding transaction before the channel is considered open
	pub minimum_depth: u32,
	/// The number of blocks which the counterparty will have to wait to claim on-chain funds if they
	/// broadcast a commitment transaction
	pub to_self_delay: u16,
	/// The maximum number of inbound HTLCs towards channel acceptor
	pub max_accepted_htlcs: u16,
	/// The channel acceptor's key controlling the funding transaction
	pub funding_pubkey: PublicKey,
	/// Used to derive a revocation key for transactions broadcast by counterparty
	pub revocation_basepoint: PublicKey,
	/// A payment key to channel acceptor for transactions broadcast by counterparty
	pub payment_basepoint: PublicKey,
	/// Used to derive a payment key to channel acceptor for transactions broadcast by channel
	/// acceptor
	pub delayed_payment_basepoint: PublicKey,
	/// Used to derive an HTLC payment key to channel acceptor for transactions broadcast by counterparty
	pub htlc_basepoint: PublicKey,
	/// The first to-be-broadcast-by-channel-acceptor transaction's per commitment point
	pub first_per_commitment_point: PublicKey,
	/// The second to-be-broadcast-by-channel-acceptor transaction's per commitment point
	pub second_per_commitment_point: PublicKey,
	/// Optionally, a request to pre-set the to-channel-acceptor output's scriptPubkey for when we
	/// collaboratively close
	pub shutdown_scriptpubkey: Option<Script>,
	/// The channel type that this channel will represent. If none is set, we derive the channel
	/// type from the intersection of our feature bits with our counterparty's feature bits from
	/// the Init message.
	///
	/// This is required to match the equivalent field in [`OpenChannelV2::channel_type`].
	pub channel_type: Option<ChannelTypeFeatures>,
	/// Optionally, a requirement that only confirmed inputs can be added
	pub require_confirmed_inputs: Option<()>,
}

/// A [`funding_created`] message to be sent to or received from a peer.
///
/// Used in V1 channel establishment
///
/// [`funding_created`]: https://github.com/lightning/bolts/blob/master/02-peer-protocol.md#the-funding_created-message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FundingCreated {
	/// A temporary channel ID, until the funding is established
	pub temporary_channel_id: ChannelId,
	/// The funding transaction ID
	pub funding_txid: Txid,
	/// The specific output index funding this channel
	pub funding_output_index: u16,
	/// The signature of the channel initiator (funder) on the initial commitment transaction
	pub signature: Signature,
	#[cfg(taproot)]
	/// The partial signature of the channel initiator (funder)
	pub partial_signature_with_nonce: Option<PartialSignatureWithNonce>,
	#[cfg(taproot)]
	/// Next nonce the channel acceptor should use to finalize the funding output signature
	pub next_local_nonce: Option<musig2::types::PublicNonce>
}

/// A [`funding_signed`] message to be sent to or received from a peer.
///
/// Used in V1 channel establishment
///
/// [`funding_signed`]: https://github.com/lightning/bolts/blob/master/02-peer-protocol.md#the-funding_signed-message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FundingSigned {
	/// The channel ID
	pub channel_id: ChannelId,
	/// The signature of the channel acceptor (fundee) on the initial commitment transaction
	pub signature: Signature,
	#[cfg(taproot)]
	/// The partial signature of the channel acceptor (fundee)
	pub partial_signature_with_nonce: Option<PartialSignatureWithNonce>,
}

/// A [`channel_ready`] message to be sent to or received from a peer.
///
/// [`channel_ready`]: https://github.com/lightning/bolts/blob/master/02-peer-protocol.md#the-channel_ready-message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelReady {
	/// The channel ID
	pub channel_id: ChannelId,
	/// The per-commitment point of the second commitment transaction
	pub next_per_commitment_point: PublicKey,
	/// If set, provides a `short_channel_id` alias for this channel.
	///
	/// The sender will accept payments to be forwarded over this SCID and forward them to this
	/// messages' recipient.
	pub short_channel_id_alias: Option<u64>,
}

/// A tx_add_input message for adding an input during interactive transaction construction
///
// TODO(dual_funding): Add spec link for `tx_add_input`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxAddInput {
	/// The channel ID
	pub channel_id: ChannelId,
	/// A randomly chosen unique identifier for this input, which is even for initiators and odd for
	/// non-initiators.
	pub serial_id: u64,
	/// Serialized transaction that contains the output this input spends to verify that it is non
	/// malleable.
	pub prevtx: TransactionU16LenLimited,
	/// The index of the output being spent
	pub prevtx_out: u32,
	/// The sequence number of this input
	pub sequence: u32,
}

/// A tx_add_output message for adding an output during interactive transaction construction.
///
// TODO(dual_funding): Add spec link for `tx_add_output`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxAddOutput {
	/// The channel ID
	pub channel_id: ChannelId,
	/// A randomly chosen unique identifier for this output, which is even for initiators and odd for
	/// non-initiators.
	pub serial_id: u64,
	/// The satoshi value of the output
	pub sats: u64,
	/// The scriptPubKey for the output
	pub script: Script,
}

/// A tx_remove_input message for removing an input during interactive transaction construction.
///
// TODO(dual_funding): Add spec link for `tx_remove_input`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxRemoveInput {
	/// The channel ID
	pub channel_id: ChannelId,
	/// The serial ID of the input to be removed
	pub serial_id: u64,
}

/// A tx_remove_output message for removing an output during interactive transaction construction.
///
// TODO(dual_funding): Add spec link for `tx_remove_output`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxRemoveOutput {
	/// The channel ID
	pub channel_id: ChannelId,
	/// The serial ID of the output to be removed
	pub serial_id: u64,
}

/// A tx_complete message signalling the conclusion of a peer's transaction contributions during
/// interactive transaction construction.
///
// TODO(dual_funding): Add spec link for `tx_complete`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxComplete {
	/// The channel ID
	pub channel_id: ChannelId,
}

/// A tx_signatures message containing the sender's signatures for a transaction constructed with
/// interactive transaction construction.
///
// TODO(dual_funding): Add spec link for `tx_signatures`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxSignatures {
	/// The channel ID
	pub channel_id: ChannelId,
	/// The TXID
	pub tx_hash: Txid,
	/// The list of witnesses
	pub witnesses: Vec<Witness>,
}

/// A tx_init_rbf message which initiates a replacement of the transaction after it's been
/// completed.
///
// TODO(dual_funding): Add spec link for `tx_init_rbf`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxInitRbf {
	/// The channel ID
	pub channel_id: ChannelId,
	/// The locktime of the transaction
	pub locktime: u32,
	/// The feerate of the transaction
	pub feerate_sat_per_1000_weight: u32,
	/// The number of satoshis the sender will contribute to or, if negative, remove from
	/// (e.g. splice-out) the funding output of the transaction
	pub funding_output_contribution: Option<i64>,
}

/// A tx_ack_rbf message which acknowledges replacement of the transaction after it's been
/// completed.
///
// TODO(dual_funding): Add spec link for `tx_ack_rbf`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxAckRbf {
	/// The channel ID
	pub channel_id: ChannelId,
	/// The number of satoshis the sender will contribute to or, if negative, remove from
	/// (e.g. splice-out) the funding output of the transaction
	pub funding_output_contribution: Option<i64>,
}

/// A tx_abort message which signals the cancellation of an in-progress transaction negotiation.
///
// TODO(dual_funding): Add spec link for `tx_abort`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxAbort {
	/// The channel ID
	pub channel_id: ChannelId,
	/// Message data
	pub data: Vec<u8>,
}

/// A [`shutdown`] message to be sent to or received from a peer.
///
/// [`shutdown`]: https://github.com/lightning/bolts/blob/master/02-peer-protocol.md#closing-initiation-shutdown
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Shutdown {
	/// The channel ID
	pub channel_id: ChannelId,
	/// The destination of this peer's funds on closing.
	///
	/// Must be in one of these forms: P2PKH, P2SH, P2WPKH, P2WSH, P2TR.
	pub scriptpubkey: Script,
}

/// The minimum and maximum fees which the sender is willing to place on the closing transaction.
///
/// This is provided in [`ClosingSigned`] by both sides to indicate the fee range they are willing
/// to use.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClosingSignedFeeRange {
	/// The minimum absolute fee, in satoshis, which the sender is willing to place on the closing
	/// transaction.
	pub min_fee_satoshis: u64,
	/// The maximum absolute fee, in satoshis, which the sender is willing to place on the closing
	/// transaction.
	pub max_fee_satoshis: u64,
}

/// A [`closing_signed`] message to be sent to or received from a peer.
///
/// [`closing_signed`]: https://github.com/lightning/bolts/blob/master/02-peer-protocol.md#closing-negotiation-closing_signed
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClosingSigned {
	/// The channel ID
	pub channel_id: ChannelId,
	/// The proposed total fee for the closing transaction
	pub fee_satoshis: u64,
	/// A signature on the closing transaction
	pub signature: Signature,
	/// The minimum and maximum fees which the sender is willing to accept, provided only by new
	/// nodes.
	pub fee_range: Option<ClosingSignedFeeRange>,
}

/// An [`update_add_htlc`] message to be sent to or received from a peer.
///
/// [`update_add_htlc`]: https://github.com/lightning/bolts/blob/master/02-peer-protocol.md#adding-an-htlc-update_add_htlc
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpdateAddHTLC {
	/// The channel ID
	pub channel_id: ChannelId,
	/// The HTLC ID
	pub htlc_id: u64,
	/// The HTLC value in milli-satoshi
	pub amount_msat: u64,
	/// The payment hash, the pre-image of which controls HTLC redemption
	pub payment_hash: PaymentHash,
	/// The expiry height of the HTLC
	pub cltv_expiry: u32,
	/// The extra fee skimmed by the sender of this message. See
	/// [`ChannelConfig::accept_underpaying_htlcs`].
	///
	/// [`ChannelConfig::accept_underpaying_htlcs`]: crate::util::config::ChannelConfig::accept_underpaying_htlcs
	pub skimmed_fee_msat: Option<u64>,
	pub(crate) onion_routing_packet: OnionPacket,
}

 /// An onion message to be sent to or received from a peer.
 ///
 // TODO: update with link to OM when they are merged into the BOLTs
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OnionMessage {
	/// Used in decrypting the onion packet's payload.
	pub blinding_point: PublicKey,
	pub(crate) onion_routing_packet: onion_message::Packet,
}

/// An [`update_fulfill_htlc`] message to be sent to or received from a peer.
///
/// [`update_fulfill_htlc`]: https://github.com/lightning/bolts/blob/master/02-peer-protocol.md#removing-an-htlc-update_fulfill_htlc-update_fail_htlc-and-update_fail_malformed_htlc
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpdateFulfillHTLC {
	/// The channel ID
	pub channel_id: ChannelId,
	/// The HTLC ID
	pub htlc_id: u64,
	/// The pre-image of the payment hash, allowing HTLC redemption
	pub payment_preimage: PaymentPreimage,
}

/// An [`update_fail_htlc`] message to be sent to or received from a peer.
///
/// [`update_fail_htlc`]: https://github.com/lightning/bolts/blob/master/02-peer-protocol.md#removing-an-htlc-update_fulfill_htlc-update_fail_htlc-and-update_fail_malformed_htlc
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpdateFailHTLC {
	/// The channel ID
	pub channel_id: ChannelId,
	/// The HTLC ID
	pub htlc_id: u64,
	pub(crate) reason: OnionErrorPacket,
}

/// An [`update_fail_malformed_htlc`] message to be sent to or received from a peer.
///
/// [`update_fail_malformed_htlc`]: https://github.com/lightning/bolts/blob/master/02-peer-protocol.md#removing-an-htlc-update_fulfill_htlc-update_fail_htlc-and-update_fail_malformed_htlc
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpdateFailMalformedHTLC {
	/// The channel ID
	pub channel_id: ChannelId,
	/// The HTLC ID
	pub htlc_id: u64,
	pub(crate) sha256_of_onion: [u8; 32],
	/// The failure code
	pub failure_code: u16,
}

/// A [`commitment_signed`] message to be sent to or received from a peer.
///
/// [`commitment_signed`]: https://github.com/lightning/bolts/blob/master/02-peer-protocol.md#committing-updates-so-far-commitment_signed
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitmentSigned {
	/// The channel ID
	pub channel_id: ChannelId,
	/// A signature on the commitment transaction
	pub signature: Signature,
	/// Signatures on the HTLC transactions
	pub htlc_signatures: Vec<Signature>,
	#[cfg(taproot)]
	/// The partial Taproot signature on the commitment transaction
	pub partial_signature_with_nonce: Option<PartialSignatureWithNonce>,
}

/// A [`revoke_and_ack`] message to be sent to or received from a peer.
///
/// [`revoke_and_ack`]: https://github.com/lightning/bolts/blob/master/02-peer-protocol.md#completing-the-transition-to-the-updated-state-revoke_and_ack
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevokeAndACK {
	/// The channel ID
	pub channel_id: ChannelId,
	/// The secret corresponding to the per-commitment point
	pub per_commitment_secret: [u8; 32],
	/// The next sender-broadcast commitment transaction's per-commitment point
	pub next_per_commitment_point: PublicKey,
	#[cfg(taproot)]
	/// Musig nonce the recipient should use in their next commitment signature message
	pub next_local_nonce: Option<musig2::types::PublicNonce>
}

/// An [`update_fee`] message to be sent to or received from a peer
///
/// [`update_fee`]: https://github.com/lightning/bolts/blob/master/02-peer-protocol.md#updating-fees-update_fee
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpdateFee {
	/// The channel ID
	pub channel_id: ChannelId,
	/// Fee rate per 1000-weight of the transaction
	pub feerate_per_kw: u32,
}

/// A [`channel_reestablish`] message to be sent to or received from a peer.
///
/// [`channel_reestablish`]: https://github.com/lightning/bolts/blob/master/02-peer-protocol.md#message-retransmission
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelReestablish {
	/// The channel ID
	pub channel_id: ChannelId,
	/// The next commitment number for the sender
	pub next_local_commitment_number: u64,
	/// The next commitment number for the recipient
	pub next_remote_commitment_number: u64,
	/// Proof that the sender knows the per-commitment secret of a specific commitment transaction
	/// belonging to the recipient
	pub your_last_per_commitment_secret: [u8; 32],
	/// The sender's per-commitment point for their current commitment transaction
	pub my_current_per_commitment_point: PublicKey,
	/// The next funding transaction ID
	pub next_funding_txid: Option<Txid>,
}

/// An [`announcement_signatures`] message to be sent to or received from a peer.
///
/// [`announcement_signatures`]: https://github.com/lightning/bolts/blob/master/07-routing-gossip.md#the-announcement_signatures-message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnnouncementSignatures {
	/// The channel ID
	pub channel_id: ChannelId,
	/// The short channel ID
	pub short_channel_id: u64,
	/// A signature by the node key
	pub node_signature: Signature,
	/// A signature by the funding key
	pub bitcoin_signature: Signature,
}

/// An address which can be used to connect to a remote peer.
#[derive(Clone, Debug, PartialEq, Eq)]
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
	///
	/// This field is deprecated and the Tor network generally no longer supports V2 Onion
	/// addresses. Thus, the details are not parsed here.
	OnionV2([u8; 12]),
	/// A new-style Tor onion address/port on which the peer is listening.
	///
	/// To create the human-readable "hostname", concatenate the ED25519 pubkey, checksum, and version,
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
	/// A hostname/port on which the peer is listening.
	Hostname {
		/// The hostname on which the node is listening.
		hostname: Hostname,
		/// The port on which the node is listening.
		port: u16,
	},
}
impl NetAddress {
	/// Gets the ID of this address type. Addresses in [`NodeAnnouncement`] messages should be sorted
	/// by this.
	pub(crate) fn get_id(&self) -> u8 {
		match self {
			&NetAddress::IPv4 {..} => { 1 },
			&NetAddress::IPv6 {..} => { 2 },
			&NetAddress::OnionV2(_) => { 3 },
			&NetAddress::OnionV3 {..} => { 4 },
			&NetAddress::Hostname {..} => { 5 },
		}
	}

	/// Strict byte-length of address descriptor, 1-byte type not recorded
	fn len(&self) -> u16 {
		match self {
			&NetAddress::IPv4 { .. } => { 6 },
			&NetAddress::IPv6 { .. } => { 18 },
			&NetAddress::OnionV2(_) => { 12 },
			&NetAddress::OnionV3 { .. } => { 37 },
			// Consists of 1-byte hostname length, hostname bytes, and 2-byte port.
			&NetAddress::Hostname { ref hostname, .. } => { u16::from(hostname.len()) + 3 },
		}
	}

	/// The maximum length of any address descriptor, not including the 1-byte type.
	/// This maximum length is reached by a hostname address descriptor:
	/// a hostname with a maximum length of 255, its 1-byte length and a 2-byte port.
	pub(crate) const MAX_LEN: u16 = 258;
}

impl Writeable for NetAddress {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
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
			&NetAddress::OnionV2(bytes) => {
				3u8.write(writer)?;
				bytes.write(writer)?;
			},
			&NetAddress::OnionV3 { ref ed25519_pubkey, ref checksum, ref version, ref port } => {
				4u8.write(writer)?;
				ed25519_pubkey.write(writer)?;
				checksum.write(writer)?;
				version.write(writer)?;
				port.write(writer)?;
			},
			&NetAddress::Hostname { ref hostname, ref port } => {
				5u8.write(writer)?;
				hostname.write(writer)?;
				port.write(writer)?;
			},
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
			3 => Ok(Ok(NetAddress::OnionV2(Readable::read(reader)?))),
			4 => {
				Ok(Ok(NetAddress::OnionV3 {
					ed25519_pubkey: Readable::read(reader)?,
					checksum: Readable::read(reader)?,
					version: Readable::read(reader)?,
					port: Readable::read(reader)?,
				}))
			},
			5 => {
				Ok(Ok(NetAddress::Hostname {
					hostname: Readable::read(reader)?,
					port: Readable::read(reader)?,
				}))
			},
			_ => return Ok(Err(byte)),
		}
	}
}

impl Readable for NetAddress {
	fn read<R: Read>(reader: &mut R) -> Result<NetAddress, DecodeError> {
		match Readable::read(reader) {
			Ok(Ok(res)) => Ok(res),
			Ok(Err(_)) => Err(DecodeError::UnknownVersion),
			Err(e) => Err(e),
		}
	}
}

/// [`NetAddress`] error variants
#[derive(Debug, Eq, PartialEq, Clone)]
pub enum NetAddressParseError {
	/// Socket address (IPv4/IPv6) parsing error
	SocketAddrParse,
	/// Invalid input format
	InvalidInput,
	/// Invalid port
	InvalidPort,
	/// Invalid onion v3 address
	InvalidOnionV3,
}

impl fmt::Display for NetAddressParseError {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match self {
			NetAddressParseError::SocketAddrParse => write!(f, "Socket address (IPv4/IPv6) parsing error"),
			NetAddressParseError::InvalidInput => write!(f, "Invalid input format. \
				Expected: \"<ipv4>:<port>\", \"[<ipv6>]:<port>\", \"<onion address>.onion:<port>\" or \"<hostname>:<port>\""),
			NetAddressParseError::InvalidPort => write!(f, "Invalid port"),
			NetAddressParseError::InvalidOnionV3 => write!(f, "Invalid onion v3 address"),
		}
	}
}

#[cfg(feature = "std")]
impl From<std::net::SocketAddrV4> for NetAddress {
		fn from(addr: std::net::SocketAddrV4) -> Self {
			NetAddress::IPv4 { addr: addr.ip().octets(), port: addr.port() }
		}
}

#[cfg(feature = "std")]
impl From<std::net::SocketAddrV6> for NetAddress {
		fn from(addr: std::net::SocketAddrV6) -> Self {
			NetAddress::IPv6 { addr: addr.ip().octets(), port: addr.port() }
		}
}

#[cfg(feature = "std")]
impl From<std::net::SocketAddr> for NetAddress {
		fn from(addr: std::net::SocketAddr) -> Self {
			match addr {
				std::net::SocketAddr::V4(addr) => addr.into(),
				std::net::SocketAddr::V6(addr) => addr.into(),
			}
		}
}

fn parse_onion_address(host: &str, port: u16) -> Result<NetAddress, NetAddressParseError> {
	if host.ends_with(".onion") {
		let domain = &host[..host.len() - ".onion".len()];
		if domain.len() != 56 {
			return Err(NetAddressParseError::InvalidOnionV3);
		}
		let onion =  base32::Alphabet::RFC4648 { padding: false }.decode(&domain).map_err(|_| NetAddressParseError::InvalidOnionV3)?;
		if onion.len() != 35 {
			return Err(NetAddressParseError::InvalidOnionV3);
		}
		let version = onion[0];
		let first_checksum_flag = onion[1];
		let second_checksum_flag = onion[2];
		let mut ed25519_pubkey = [0; 32];
		ed25519_pubkey.copy_from_slice(&onion[3..35]);
		let checksum = u16::from_be_bytes([first_checksum_flag, second_checksum_flag]);
		return Ok(NetAddress::OnionV3 { ed25519_pubkey, checksum, version, port });

	} else {
		return Err(NetAddressParseError::InvalidInput);
	}
}

#[cfg(feature = "std")]
impl FromStr for NetAddress {
	type Err = NetAddressParseError;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		match std::net::SocketAddr::from_str(s) {
			Ok(addr) => Ok(addr.into()),
			Err(_) => {
				let trimmed_input = match s.rfind(":") {
					Some(pos) => pos,
					None => return Err(NetAddressParseError::InvalidInput),
				};
				let host = &s[..trimmed_input];
				let port: u16 = s[trimmed_input + 1..].parse().map_err(|_| NetAddressParseError::InvalidPort)?;
				if host.ends_with(".onion") {
					return parse_onion_address(host, port);
				};
				if let Ok(hostname) = Hostname::try_from(s[..trimmed_input].to_string()) {
					return Ok(NetAddress::Hostname { hostname, port });
				};
				return Err(NetAddressParseError::SocketAddrParse)
			},
		}
	}
}

/// Represents the set of gossip messages that require a signature from a node's identity key.
pub enum UnsignedGossipMessage<'a> {
	/// An unsigned channel announcement.
	ChannelAnnouncement(&'a UnsignedChannelAnnouncement),
	/// An unsigned channel update.
	ChannelUpdate(&'a UnsignedChannelUpdate),
	/// An unsigned node announcement.
	NodeAnnouncement(&'a UnsignedNodeAnnouncement)
}

impl<'a> Writeable for UnsignedGossipMessage<'a> {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		match self {
			UnsignedGossipMessage::ChannelAnnouncement(ref msg) => msg.write(writer),
			UnsignedGossipMessage::ChannelUpdate(ref msg) => msg.write(writer),
			UnsignedGossipMessage::NodeAnnouncement(ref msg) => msg.write(writer),
		}
	}
}

/// The unsigned part of a [`node_announcement`] message.
///
/// [`node_announcement`]: https://github.com/lightning/bolts/blob/master/07-routing-gossip.md#the-node_announcement-message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnsignedNodeAnnouncement {
	/// The advertised features
	pub features: NodeFeatures,
	/// A strictly monotonic announcement counter, with gaps allowed
	pub timestamp: u32,
	/// The `node_id` this announcement originated from (don't rebroadcast the `node_announcement` back
	/// to this node).
	pub node_id: NodeId,
	/// An RGB color for UI purposes
	pub rgb: [u8; 3],
	/// An alias, for UI purposes.
	///
	/// This should be sanitized before use. There is no guarantee of uniqueness.
	pub alias: NodeAlias,
	/// List of addresses on which this node is reachable
	pub addresses: Vec<NetAddress>,
	pub(crate) excess_address_data: Vec<u8>,
	pub(crate) excess_data: Vec<u8>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
/// A [`node_announcement`] message to be sent to or received from a peer.
///
/// [`node_announcement`]: https://github.com/lightning/bolts/blob/master/07-routing-gossip.md#the-node_announcement-message
pub struct NodeAnnouncement {
	/// The signature by the node key
	pub signature: Signature,
	/// The actual content of the announcement
	pub contents: UnsignedNodeAnnouncement,
}

/// The unsigned part of a [`channel_announcement`] message.
///
/// [`channel_announcement`]: https://github.com/lightning/bolts/blob/master/07-routing-gossip.md#the-channel_announcement-message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnsignedChannelAnnouncement {
	/// The advertised channel features
	pub features: ChannelFeatures,
	/// The genesis hash of the blockchain where the channel is to be opened
	pub chain_hash: BlockHash,
	/// The short channel ID
	pub short_channel_id: u64,
	/// One of the two `node_id`s which are endpoints of this channel
	pub node_id_1: NodeId,
	/// The other of the two `node_id`s which are endpoints of this channel
	pub node_id_2: NodeId,
	/// The funding key for the first node
	pub bitcoin_key_1: NodeId,
	/// The funding key for the second node
	pub bitcoin_key_2: NodeId,
	/// Excess data which was signed as a part of the message which we do not (yet) understand how
	/// to decode.
	///
	/// This is stored to ensure forward-compatibility as new fields are added to the lightning gossip protocol.
	pub excess_data: Vec<u8>,
}
/// A [`channel_announcement`] message to be sent to or received from a peer.
///
/// [`channel_announcement`]: https://github.com/lightning/bolts/blob/master/07-routing-gossip.md#the-channel_announcement-message
#[derive(Clone, Debug, PartialEq, Eq)]
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

/// The unsigned part of a [`channel_update`] message.
///
/// [`channel_update`]: https://github.com/lightning/bolts/blob/master/07-routing-gossip.md#the-channel_update-message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnsignedChannelUpdate {
	/// The genesis hash of the blockchain where the channel is to be opened
	pub chain_hash: BlockHash,
	/// The short channel ID
	pub short_channel_id: u64,
	/// A strictly monotonic announcement counter, with gaps allowed, specific to this channel
	pub timestamp: u32,
	/// Channel flags
	pub flags: u8,
	/// The number of blocks such that if:
	/// `incoming_htlc.cltv_expiry < outgoing_htlc.cltv_expiry + cltv_expiry_delta`
	/// then we need to fail the HTLC backwards. When forwarding an HTLC, `cltv_expiry_delta` determines
	/// the outgoing HTLC's minimum `cltv_expiry` value -- so, if an incoming HTLC comes in with a
	/// `cltv_expiry` of 100000, and the node we're forwarding to has a `cltv_expiry_delta` value of 10,
	/// then we'll check that the outgoing HTLC's `cltv_expiry` value is at least 100010 before
	/// forwarding. Note that the HTLC sender is the one who originally sets this value when
	/// constructing the route.
	pub cltv_expiry_delta: u16,
	/// The minimum HTLC size incoming to sender, in milli-satoshi
	pub htlc_minimum_msat: u64,
	/// The maximum HTLC value incoming to sender, in milli-satoshi.
	///
	/// This used to be optional.
	pub htlc_maximum_msat: u64,
	/// The base HTLC fee charged by sender, in milli-satoshi
	pub fee_base_msat: u32,
	/// The amount to fee multiplier, in micro-satoshi
	pub fee_proportional_millionths: u32,
	/// Excess data which was signed as a part of the message which we do not (yet) understand how
	/// to decode.
	///
	/// This is stored to ensure forward-compatibility as new fields are added to the lightning gossip protocol.
	pub excess_data: Vec<u8>,
}
/// A [`channel_update`] message to be sent to or received from a peer.
///
/// [`channel_update`]: https://github.com/lightning/bolts/blob/master/07-routing-gossip.md#the-channel_update-message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelUpdate {
	/// A signature of the channel update
	pub signature: Signature,
	/// The actual channel update
	pub contents: UnsignedChannelUpdate,
}

/// A [`query_channel_range`] message is used to query a peer for channel
/// UTXOs in a range of blocks. The recipient of a query makes a best
/// effort to reply to the query using one or more [`ReplyChannelRange`]
/// messages.
///
/// [`query_channel_range`]: https://github.com/lightning/bolts/blob/master/07-routing-gossip.md#the-query_channel_range-and-reply_channel_range-messages
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueryChannelRange {
	/// The genesis hash of the blockchain being queried
	pub chain_hash: BlockHash,
	/// The height of the first block for the channel UTXOs being queried
	pub first_blocknum: u32,
	/// The number of blocks to include in the query results
	pub number_of_blocks: u32,
}

/// A [`reply_channel_range`] message is a reply to a [`QueryChannelRange`]
/// message.
///
/// Multiple `reply_channel_range` messages can be sent in reply
/// to a single [`QueryChannelRange`] message. The query recipient makes a
/// best effort to respond based on their local network view which may
/// not be a perfect view of the network. The `short_channel_id`s in the
/// reply are encoded. We only support `encoding_type=0` uncompressed
/// serialization and do not support `encoding_type=1` zlib serialization.
///
/// [`reply_channel_range`]: https://github.com/lightning/bolts/blob/master/07-routing-gossip.md#the-query_channel_range-and-reply_channel_range-messages
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplyChannelRange {
	/// The genesis hash of the blockchain being queried
	pub chain_hash: BlockHash,
	/// The height of the first block in the range of the reply
	pub first_blocknum: u32,
	/// The number of blocks included in the range of the reply
	pub number_of_blocks: u32,
	/// True when this is the final reply for a query
	pub sync_complete: bool,
	/// The `short_channel_id`s in the channel range
	pub short_channel_ids: Vec<u64>,
}

/// A [`query_short_channel_ids`] message is used to query a peer for
/// routing gossip messages related to one or more `short_channel_id`s.
///
/// The query recipient will reply with the latest, if available,
/// [`ChannelAnnouncement`], [`ChannelUpdate`] and [`NodeAnnouncement`] messages
/// it maintains for the requested `short_channel_id`s followed by a
/// [`ReplyShortChannelIdsEnd`] message. The `short_channel_id`s sent in
/// this query are encoded. We only support `encoding_type=0` uncompressed
/// serialization and do not support `encoding_type=1` zlib serialization.
///
/// [`query_short_channel_ids`]: https://github.com/lightning/bolts/blob/master/07-routing-gossip.md#the-query_short_channel_idsreply_short_channel_ids_end-messages
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueryShortChannelIds {
	/// The genesis hash of the blockchain being queried
	pub chain_hash: BlockHash,
	/// The short_channel_ids that are being queried
	pub short_channel_ids: Vec<u64>,
}

/// A [`reply_short_channel_ids_end`] message is sent as a reply to a
/// message. The query recipient makes a best
/// effort to respond based on their local network view which may not be
/// a perfect view of the network.
///
/// [`reply_short_channel_ids_end`]: https://github.com/lightning/bolts/blob/master/07-routing-gossip.md#the-query_short_channel_idsreply_short_channel_ids_end-messages
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplyShortChannelIdsEnd {
	/// The genesis hash of the blockchain that was queried
	pub chain_hash: BlockHash,
	/// Indicates if the query recipient maintains up-to-date channel
	/// information for the `chain_hash`
	pub full_information: bool,
}

/// A [`gossip_timestamp_filter`] message is used by a node to request
/// gossip relay for messages in the requested time range when the
/// `gossip_queries` feature has been negotiated.
///
/// [`gossip_timestamp_filter`]: https://github.com/lightning/bolts/blob/master/07-routing-gossip.md#the-gossip_timestamp_filter-message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GossipTimestampFilter {
	/// The genesis hash of the blockchain for channel and node information
	pub chain_hash: BlockHash,
	/// The starting unix timestamp
	pub first_timestamp: u32,
	/// The range of information in seconds
	pub timestamp_range: u32,
}

/// Encoding type for data compression of collections in gossip queries.
///
/// We do not support `encoding_type=1` zlib serialization [defined in BOLT
/// #7](https://github.com/lightning/bolts/blob/master/07-routing-gossip.md#query-messages).
enum EncodingType {
	Uncompressed = 0x00,
}

/// Used to put an error message in a [`LightningError`].
#[derive(Clone, Debug, PartialEq)]
pub enum ErrorAction {
	/// The peer took some action which made us think they were useless. Disconnect them.
	DisconnectPeer {
		/// An error message which we should make an effort to send before we disconnect.
		msg: Option<ErrorMessage>
	},
	/// The peer did something incorrect. Tell them without closing any channels and disconnect them.
	DisconnectPeerWithWarning {
		/// A warning message which we should make an effort to send before we disconnect.
		msg: WarningMessage,
	},
	/// The peer did something harmless that we weren't able to process, just log and ignore
	// New code should *not* use this. New code must use IgnoreAndLog, below!
	IgnoreError,
	/// The peer did something harmless that we weren't able to meaningfully process.
	/// If the error is logged, log it at the given level.
	IgnoreAndLog(logger::Level),
	/// The peer provided us with a gossip message which we'd already seen. In most cases this
	/// should be ignored, but it may result in the message being forwarded if it is a duplicate of
	/// our own channel announcements.
	IgnoreDuplicateGossip,
	/// The peer did something incorrect. Tell them.
	SendErrorMessage {
		/// The message to send.
		msg: ErrorMessage,
	},
	/// The peer did something incorrect. Tell them without closing any channels.
	SendWarningMessage {
		/// The message to send.
		msg: WarningMessage,
		/// The peer may have done something harmless that we weren't able to meaningfully process,
		/// though we should still tell them about it.
		/// If this event is logged, log it at the given level.
		log_level: logger::Level,
	},
}

/// An Err type for failure to process messages.
#[derive(Clone, Debug)]
pub struct LightningError {
	/// A human-readable message describing the error
	pub err: String,
	/// The action which should be taken against the offending peer.
	pub action: ErrorAction,
}

/// Struct used to return values from [`RevokeAndACK`] messages, containing a bunch of commitment
/// transaction updates if they were pending.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitmentUpdate {
	/// `update_add_htlc` messages which should be sent
	pub update_add_htlcs: Vec<UpdateAddHTLC>,
	/// `update_fulfill_htlc` messages which should be sent
	pub update_fulfill_htlcs: Vec<UpdateFulfillHTLC>,
	/// `update_fail_htlc` messages which should be sent
	pub update_fail_htlcs: Vec<UpdateFailHTLC>,
	/// `update_fail_malformed_htlc` messages which should be sent
	pub update_fail_malformed_htlcs: Vec<UpdateFailMalformedHTLC>,
	/// An `update_fee` message which should be sent
	pub update_fee: Option<UpdateFee>,
	/// A `commitment_signed` message which should be sent
	pub commitment_signed: CommitmentSigned,
}

/// A trait to describe an object which can receive channel messages.
///
/// Messages MAY be called in parallel when they originate from different `their_node_ids`, however
/// they MUST NOT be called in parallel when the two calls have the same `their_node_id`.
pub trait ChannelMessageHandler : MessageSendEventsProvider {
	// Channel init:
	/// Handle an incoming `open_channel` message from the given peer.
	fn handle_open_channel(&self, their_node_id: &PublicKey, msg: &OpenChannel);
	/// Handle an incoming `open_channel2` message from the given peer.
	fn handle_open_channel_v2(&self, their_node_id: &PublicKey, msg: &OpenChannelV2);
	/// Handle an incoming `accept_channel` message from the given peer.
	fn handle_accept_channel(&self, their_node_id: &PublicKey, msg: &AcceptChannel);
	/// Handle an incoming `accept_channel2` message from the given peer.
	fn handle_accept_channel_v2(&self, their_node_id: &PublicKey, msg: &AcceptChannelV2);
	/// Handle an incoming `funding_created` message from the given peer.
	fn handle_funding_created(&self, their_node_id: &PublicKey, msg: &FundingCreated);
	/// Handle an incoming `funding_signed` message from the given peer.
	fn handle_funding_signed(&self, their_node_id: &PublicKey, msg: &FundingSigned);
	/// Handle an incoming `channel_ready` message from the given peer.
	fn handle_channel_ready(&self, their_node_id: &PublicKey, msg: &ChannelReady);

	// Channel close:
	/// Handle an incoming `shutdown` message from the given peer.
	fn handle_shutdown(&self, their_node_id: &PublicKey, msg: &Shutdown);
	/// Handle an incoming `closing_signed` message from the given peer.
	fn handle_closing_signed(&self, their_node_id: &PublicKey, msg: &ClosingSigned);

	// Interactive channel construction
	/// Handle an incoming `tx_add_input message` from the given peer.
	fn handle_tx_add_input(&self, their_node_id: &PublicKey, msg: &TxAddInput);
	/// Handle an incoming `tx_add_output` message from the given peer.
	fn handle_tx_add_output(&self, their_node_id: &PublicKey, msg: &TxAddOutput);
	/// Handle an incoming `tx_remove_input` message from the given peer.
	fn handle_tx_remove_input(&self, their_node_id: &PublicKey, msg: &TxRemoveInput);
	/// Handle an incoming `tx_remove_output` message from the given peer.
	fn handle_tx_remove_output(&self, their_node_id: &PublicKey, msg: &TxRemoveOutput);
	/// Handle an incoming `tx_complete message` from the given peer.
	fn handle_tx_complete(&self, their_node_id: &PublicKey, msg: &TxComplete);
	/// Handle an incoming `tx_signatures` message from the given peer.
	fn handle_tx_signatures(&self, their_node_id: &PublicKey, msg: &TxSignatures);
	/// Handle an incoming `tx_init_rbf` message from the given peer.
	fn handle_tx_init_rbf(&self, their_node_id: &PublicKey, msg: &TxInitRbf);
	/// Handle an incoming `tx_ack_rbf` message from the given peer.
	fn handle_tx_ack_rbf(&self, their_node_id: &PublicKey, msg: &TxAckRbf);
	/// Handle an incoming `tx_abort message` from the given peer.
	fn handle_tx_abort(&self, their_node_id: &PublicKey, msg: &TxAbort);

	// HTLC handling:
	/// Handle an incoming `update_add_htlc` message from the given peer.
	fn handle_update_add_htlc(&self, their_node_id: &PublicKey, msg: &UpdateAddHTLC);
	/// Handle an incoming `update_fulfill_htlc` message from the given peer.
	fn handle_update_fulfill_htlc(&self, their_node_id: &PublicKey, msg: &UpdateFulfillHTLC);
	/// Handle an incoming `update_fail_htlc` message from the given peer.
	fn handle_update_fail_htlc(&self, their_node_id: &PublicKey, msg: &UpdateFailHTLC);
	/// Handle an incoming `update_fail_malformed_htlc` message from the given peer.
	fn handle_update_fail_malformed_htlc(&self, their_node_id: &PublicKey, msg: &UpdateFailMalformedHTLC);
	/// Handle an incoming `commitment_signed` message from the given peer.
	fn handle_commitment_signed(&self, their_node_id: &PublicKey, msg: &CommitmentSigned);
	/// Handle an incoming `revoke_and_ack` message from the given peer.
	fn handle_revoke_and_ack(&self, their_node_id: &PublicKey, msg: &RevokeAndACK);

	/// Handle an incoming `update_fee` message from the given peer.
	fn handle_update_fee(&self, their_node_id: &PublicKey, msg: &UpdateFee);

	// Channel-to-announce:
	/// Handle an incoming `announcement_signatures` message from the given peer.
	fn handle_announcement_signatures(&self, their_node_id: &PublicKey, msg: &AnnouncementSignatures);

	// Connection loss/reestablish:
	/// Indicates a connection to the peer failed/an existing connection was lost.
	fn peer_disconnected(&self, their_node_id: &PublicKey);

	/// Handle a peer reconnecting, possibly generating `channel_reestablish` message(s).
	///
	/// May return an `Err(())` if the features the peer supports are not sufficient to communicate
	/// with us. Implementors should be somewhat conservative about doing so, however, as other
	/// message handlers may still wish to communicate with this peer.
	fn peer_connected(&self, their_node_id: &PublicKey, msg: &Init, inbound: bool) -> Result<(), ()>;
	/// Handle an incoming `channel_reestablish` message from the given peer.
	fn handle_channel_reestablish(&self, their_node_id: &PublicKey, msg: &ChannelReestablish);

	/// Handle an incoming `channel_update` message from the given peer.
	fn handle_channel_update(&self, their_node_id: &PublicKey, msg: &ChannelUpdate);

	// Error:
	/// Handle an incoming `error` message from the given peer.
	fn handle_error(&self, their_node_id: &PublicKey, msg: &ErrorMessage);

	// Handler information:
	/// Gets the node feature flags which this handler itself supports. All available handlers are
	/// queried similarly and their feature flags are OR'd together to form the [`NodeFeatures`]
	/// which are broadcasted in our [`NodeAnnouncement`] message.
	fn provided_node_features(&self) -> NodeFeatures;

	/// Gets the init feature flags which should be sent to the given peer. All available handlers
	/// are queried similarly and their feature flags are OR'd together to form the [`InitFeatures`]
	/// which are sent in our [`Init`] message.
	///
	/// Note that this method is called before [`Self::peer_connected`].
	fn provided_init_features(&self, their_node_id: &PublicKey) -> InitFeatures;

	/// Gets the genesis hashes for this `ChannelMessageHandler` indicating which chains it supports.
	///
	/// If it's `None`, then no particular network chain hash compatibility will be enforced when
	/// connecting to peers.
	fn get_genesis_hashes(&self) -> Option<Vec<ChainHash>>;
}

/// A trait to describe an object which can receive routing messages.
///
/// # Implementor DoS Warnings
///
/// For messages enabled with the `gossip_queries` feature there are potential DoS vectors when
/// handling inbound queries. Implementors using an on-disk network graph should be aware of
/// repeated disk I/O for queries accessing different parts of the network graph.
pub trait RoutingMessageHandler : MessageSendEventsProvider {
	/// Handle an incoming `node_announcement` message, returning `true` if it should be forwarded on,
	/// `false` or returning an `Err` otherwise.
	fn handle_node_announcement(&self, msg: &NodeAnnouncement) -> Result<bool, LightningError>;
	/// Handle a `channel_announcement` message, returning `true` if it should be forwarded on, `false`
	/// or returning an `Err` otherwise.
	fn handle_channel_announcement(&self, msg: &ChannelAnnouncement) -> Result<bool, LightningError>;
	/// Handle an incoming `channel_update` message, returning true if it should be forwarded on,
	/// `false` or returning an `Err` otherwise.
	fn handle_channel_update(&self, msg: &ChannelUpdate) -> Result<bool, LightningError>;
	/// Gets channel announcements and updates required to dump our routing table to a remote node,
	/// starting at the `short_channel_id` indicated by `starting_point` and including announcements
	/// for a single channel.
	fn get_next_channel_announcement(&self, starting_point: u64) -> Option<(ChannelAnnouncement, Option<ChannelUpdate>, Option<ChannelUpdate>)>;
	/// Gets a node announcement required to dump our routing table to a remote node, starting at
	/// the node *after* the provided pubkey and including up to one announcement immediately
	/// higher (as defined by `<PublicKey as Ord>::cmp`) than `starting_point`.
	/// If `None` is provided for `starting_point`, we start at the first node.
	fn get_next_node_announcement(&self, starting_point: Option<&NodeId>) -> Option<NodeAnnouncement>;
	/// Called when a connection is established with a peer. This can be used to
	/// perform routing table synchronization using a strategy defined by the
	/// implementor.
	///
	/// May return an `Err(())` if the features the peer supports are not sufficient to communicate
	/// with us. Implementors should be somewhat conservative about doing so, however, as other
	/// message handlers may still wish to communicate with this peer.
	fn peer_connected(&self, their_node_id: &PublicKey, init: &Init, inbound: bool) -> Result<(), ()>;
	/// Handles the reply of a query we initiated to learn about channels
	/// for a given range of blocks. We can expect to receive one or more
	/// replies to a single query.
	fn handle_reply_channel_range(&self, their_node_id: &PublicKey, msg: ReplyChannelRange) -> Result<(), LightningError>;
	/// Handles the reply of a query we initiated asking for routing gossip
	/// messages for a list of channels. We should receive this message when
	/// a node has completed its best effort to send us the pertaining routing
	/// gossip messages.
	fn handle_reply_short_channel_ids_end(&self, their_node_id: &PublicKey, msg: ReplyShortChannelIdsEnd) -> Result<(), LightningError>;
	/// Handles when a peer asks us to send a list of `short_channel_id`s
	/// for the requested range of blocks.
	fn handle_query_channel_range(&self, their_node_id: &PublicKey, msg: QueryChannelRange) -> Result<(), LightningError>;
	/// Handles when a peer asks us to send routing gossip messages for a
	/// list of `short_channel_id`s.
	fn handle_query_short_channel_ids(&self, their_node_id: &PublicKey, msg: QueryShortChannelIds) -> Result<(), LightningError>;

	// Handler queueing status:
	/// Indicates that there are a large number of [`ChannelAnnouncement`] (or other) messages
	/// pending some async action. While there is no guarantee of the rate of future messages, the
	/// caller should seek to reduce the rate of new gossip messages handled, especially
	/// [`ChannelAnnouncement`]s.
	fn processing_queue_high(&self) -> bool;

	// Handler information:
	/// Gets the node feature flags which this handler itself supports. All available handlers are
	/// queried similarly and their feature flags are OR'd together to form the [`NodeFeatures`]
	/// which are broadcasted in our [`NodeAnnouncement`] message.
	fn provided_node_features(&self) -> NodeFeatures;
	/// Gets the init feature flags which should be sent to the given peer. All available handlers
	/// are queried similarly and their feature flags are OR'd together to form the [`InitFeatures`]
	/// which are sent in our [`Init`] message.
	///
	/// Note that this method is called before [`Self::peer_connected`].
	fn provided_init_features(&self, their_node_id: &PublicKey) -> InitFeatures;
}

/// A trait to describe an object that can receive onion messages.
pub trait OnionMessageHandler : OnionMessageProvider {
	/// Handle an incoming `onion_message` message from the given peer.
	fn handle_onion_message(&self, peer_node_id: &PublicKey, msg: &OnionMessage);
	/// Called when a connection is established with a peer. Can be used to track which peers
	/// advertise onion message support and are online.
	///
	/// May return an `Err(())` if the features the peer supports are not sufficient to communicate
	/// with us. Implementors should be somewhat conservative about doing so, however, as other
	/// message handlers may still wish to communicate with this peer.
	fn peer_connected(&self, their_node_id: &PublicKey, init: &Init, inbound: bool) -> Result<(), ()>;
	/// Indicates a connection to the peer failed/an existing connection was lost. Allows handlers to
	/// drop and refuse to forward onion messages to this peer.
	fn peer_disconnected(&self, their_node_id: &PublicKey);

	// Handler information:
	/// Gets the node feature flags which this handler itself supports. All available handlers are
	/// queried similarly and their feature flags are OR'd together to form the [`NodeFeatures`]
	/// which are broadcasted in our [`NodeAnnouncement`] message.
	fn provided_node_features(&self) -> NodeFeatures;

	/// Gets the init feature flags which should be sent to the given peer. All available handlers
	/// are queried similarly and their feature flags are OR'd together to form the [`InitFeatures`]
	/// which are sent in our [`Init`] message.
	///
	/// Note that this method is called before [`Self::peer_connected`].
	fn provided_init_features(&self, their_node_id: &PublicKey) -> InitFeatures;
}

mod fuzzy_internal_msgs {
	use crate::prelude::*;
	use crate::ln::{PaymentPreimage, PaymentSecret};

	// These types aren't intended to be pub, but are exposed for direct fuzzing (as we deserialize
	// them from untrusted input):
	#[derive(Clone)]
	pub struct FinalOnionHopData {
		pub payment_secret: PaymentSecret,
		/// The total value, in msat, of the payment as received by the ultimate recipient.
		/// Message serialization may panic if this value is more than 21 million Bitcoin.
		pub total_msat: u64,
	}

	pub enum InboundOnionPayload {
		Forward {
			short_channel_id: u64,
			/// The value, in msat, of the payment after this hop's fee is deducted.
			amt_to_forward: u64,
			outgoing_cltv_value: u32,
		},
		Receive {
			payment_data: Option<FinalOnionHopData>,
			payment_metadata: Option<Vec<u8>>,
			keysend_preimage: Option<PaymentPreimage>,
			custom_tlvs: Vec<(u64, Vec<u8>)>,
			amt_msat: u64,
			outgoing_cltv_value: u32,
		},
	}

	pub(crate) enum OutboundOnionPayload {
		Forward {
			short_channel_id: u64,
			/// The value, in msat, of the payment after this hop's fee is deducted.
			amt_to_forward: u64,
			outgoing_cltv_value: u32,
		},
		Receive {
			payment_data: Option<FinalOnionHopData>,
			payment_metadata: Option<Vec<u8>>,
			keysend_preimage: Option<PaymentPreimage>,
			custom_tlvs: Vec<(u64, Vec<u8>)>,
			amt_msat: u64,
			outgoing_cltv_value: u32,
		},
	}

	pub struct DecodedOnionErrorPacket {
		pub(crate) hmac: [u8; 32],
		pub(crate) failuremsg: Vec<u8>,
		pub(crate) pad: Vec<u8>,
	}
}
#[cfg(fuzzing)]
pub use self::fuzzy_internal_msgs::*;
#[cfg(not(fuzzing))]
pub(crate) use self::fuzzy_internal_msgs::*;

#[derive(Clone)]
pub(crate) struct OnionPacket {
	pub(crate) version: u8,
	/// In order to ensure we always return an error on onion decode in compliance with [BOLT
	/// #4](https://github.com/lightning/bolts/blob/master/04-onion-routing.md), we have to
	/// deserialize `OnionPacket`s contained in [`UpdateAddHTLC`] messages even if the ephemeral
	/// public key (here) is bogus, so we hold a [`Result`] instead of a [`PublicKey`] as we'd
	/// like.
	pub(crate) public_key: Result<PublicKey, secp256k1::Error>,
	pub(crate) hop_data: [u8; 20*65],
	pub(crate) hmac: [u8; 32],
}

impl onion_utils::Packet for OnionPacket {
	type Data = onion_utils::FixedSizeOnionPacket;
	fn new(pubkey: PublicKey, hop_data: onion_utils::FixedSizeOnionPacket, hmac: [u8; 32]) -> Self {
		Self {
			version: 0,
			public_key: Ok(pubkey),
			hop_data: hop_data.0,
			hmac,
		}
	}
}

impl Eq for OnionPacket { }
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

impl fmt::Debug for OnionPacket {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		f.write_fmt(format_args!("OnionPacket version {} with hmac {:?}", self.version, &self.hmac[..]))
	}
}

#[derive(Clone, Debug, PartialEq, Eq)]
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
			DecodeError::Io(ref e) => fmt::Debug::fmt(e, f),
			DecodeError::UnsupportedCompression => f.write_str("We don't support receiving messages with zlib-compressed fields"),
		}
	}
}

impl From<io::Error> for DecodeError {
	fn from(e: io::Error) -> Self {
		if e.kind() == io::ErrorKind::UnexpectedEof {
			DecodeError::ShortRead
		} else {
			DecodeError::Io(e.kind())
		}
	}
}

#[cfg(not(taproot))]
impl_writeable_msg!(AcceptChannel, {
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
}, {
	(0, shutdown_scriptpubkey, (option, encoding: (Script, WithoutLength))), // Don't encode length twice.
	(1, channel_type, option),
});

#[cfg(taproot)]
impl_writeable_msg!(AcceptChannel, {
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
}, {
	(0, shutdown_scriptpubkey, (option, encoding: (Script, WithoutLength))), // Don't encode length twice.
	(1, channel_type, option),
	(4, next_local_nonce, option),
});

impl_writeable_msg!(AcceptChannelV2, {
	temporary_channel_id,
	funding_satoshis,
	dust_limit_satoshis,
	max_htlc_value_in_flight_msat,
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
	second_per_commitment_point,
}, {
	(0, shutdown_scriptpubkey, option),
	(1, channel_type, option),
	(2, require_confirmed_inputs, option),
});

impl_writeable_msg!(TxAddInput, {
	channel_id,
	serial_id,
	prevtx,
	prevtx_out,
	sequence,
}, {});

impl_writeable_msg!(TxAddOutput, {
	channel_id,
	serial_id,
	sats,
	script,
}, {});

impl_writeable_msg!(TxRemoveInput, {
	channel_id,
	serial_id,
}, {});

impl_writeable_msg!(TxRemoveOutput, {
	channel_id,
	serial_id,
}, {});

impl_writeable_msg!(TxComplete, {
	channel_id,
}, {});

impl_writeable_msg!(TxSignatures, {
	channel_id,
	tx_hash,
	witnesses,
}, {});

impl_writeable_msg!(TxInitRbf, {
	channel_id,
	locktime,
	feerate_sat_per_1000_weight,
}, {
	(0, funding_output_contribution, option),
});

impl_writeable_msg!(TxAckRbf, {
	channel_id,
}, {
	(0, funding_output_contribution, option),
});

impl_writeable_msg!(TxAbort, {
	channel_id,
	data,
}, {});

impl_writeable_msg!(AnnouncementSignatures, {
	channel_id,
	short_channel_id,
	node_signature,
	bitcoin_signature
}, {});

impl_writeable_msg!(ChannelReestablish, {
	channel_id,
	next_local_commitment_number,
	next_remote_commitment_number,
	your_last_per_commitment_secret,
	my_current_per_commitment_point,
}, {
	(0, next_funding_txid, option),
});

impl_writeable_msg!(ClosingSigned,
	{ channel_id, fee_satoshis, signature },
	{ (1, fee_range, option) }
);

impl_writeable!(ClosingSignedFeeRange, {
	min_fee_satoshis,
	max_fee_satoshis
});

#[cfg(not(taproot))]
impl_writeable_msg!(CommitmentSigned, {
	channel_id,
	signature,
	htlc_signatures
}, {});

#[cfg(taproot)]
impl_writeable_msg!(CommitmentSigned, {
	channel_id,
	signature,
	htlc_signatures
}, {
	(2, partial_signature_with_nonce, option)
});

impl_writeable!(DecodedOnionErrorPacket, {
	hmac,
	failuremsg,
	pad
});

#[cfg(not(taproot))]
impl_writeable_msg!(FundingCreated, {
	temporary_channel_id,
	funding_txid,
	funding_output_index,
	signature
}, {});
#[cfg(taproot)]
impl_writeable_msg!(FundingCreated, {
	temporary_channel_id,
	funding_txid,
	funding_output_index,
	signature
}, {
	(2, partial_signature_with_nonce, option),
	(4, next_local_nonce, option)
});

#[cfg(not(taproot))]
impl_writeable_msg!(FundingSigned, {
	channel_id,
	signature
}, {});

#[cfg(taproot)]
impl_writeable_msg!(FundingSigned, {
	channel_id,
	signature
}, {
	(2, partial_signature_with_nonce, option)
});

impl_writeable_msg!(ChannelReady, {
	channel_id,
	next_per_commitment_point,
}, {
	(1, short_channel_id_alias, option),
});

impl Writeable for Init {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		// global_features gets the bottom 13 bits of our features, and local_features gets all of
		// our relevant feature bits. This keeps us compatible with old nodes.
		self.features.write_up_to_13(w)?;
		self.features.write(w)?;
		encode_tlv_stream!(w, {
			(1, self.networks.as_ref().map(|n| WithoutLength(n)), option),
			(3, self.remote_network_address, option),
		});
		Ok(())
	}
}

impl Readable for Init {
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		let global_features: InitFeatures = Readable::read(r)?;
		let features: InitFeatures = Readable::read(r)?;
		let mut remote_network_address: Option<NetAddress> = None;
		let mut networks: Option<WithoutLength<Vec<ChainHash>>> = None;
		decode_tlv_stream!(r, {
			(1, networks, option),
			(3, remote_network_address, option)
		});
		Ok(Init {
			features: features | global_features,
			networks: networks.map(|n| n.0),
			remote_network_address,
		})
	}
}

impl_writeable_msg!(OpenChannel, {
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
}, {
	(0, shutdown_scriptpubkey, (option, encoding: (Script, WithoutLength))), // Don't encode length twice.
	(1, channel_type, option),
});

impl_writeable_msg!(OpenChannelV2, {
	chain_hash,
	temporary_channel_id,
	funding_feerate_sat_per_1000_weight,
	commitment_feerate_sat_per_1000_weight,
	funding_satoshis,
	dust_limit_satoshis,
	max_htlc_value_in_flight_msat,
	htlc_minimum_msat,
	to_self_delay,
	max_accepted_htlcs,
	locktime,
	funding_pubkey,
	revocation_basepoint,
	payment_basepoint,
	delayed_payment_basepoint,
	htlc_basepoint,
	first_per_commitment_point,
	second_per_commitment_point,
	channel_flags,
}, {
	(0, shutdown_scriptpubkey, option),
	(1, channel_type, option),
	(2, require_confirmed_inputs, option),
});

#[cfg(not(taproot))]
impl_writeable_msg!(RevokeAndACK, {
	channel_id,
	per_commitment_secret,
	next_per_commitment_point
}, {});

#[cfg(taproot)]
impl_writeable_msg!(RevokeAndACK, {
	channel_id,
	per_commitment_secret,
	next_per_commitment_point
}, {
	(4, next_local_nonce, option)
});

impl_writeable_msg!(Shutdown, {
	channel_id,
	scriptpubkey
}, {});

impl_writeable_msg!(UpdateFailHTLC, {
	channel_id,
	htlc_id,
	reason
}, {});

impl_writeable_msg!(UpdateFailMalformedHTLC, {
	channel_id,
	htlc_id,
	sha256_of_onion,
	failure_code
}, {});

impl_writeable_msg!(UpdateFee, {
	channel_id,
	feerate_per_kw
}, {});

impl_writeable_msg!(UpdateFulfillHTLC, {
	channel_id,
	htlc_id,
	payment_preimage
}, {});

// Note that this is written as a part of ChannelManager objects, and thus cannot change its
// serialization format in a way which assumes we know the total serialized length/message end
// position.
impl_writeable!(OnionErrorPacket, {
	data
});

// Note that this is written as a part of ChannelManager objects, and thus cannot change its
// serialization format in a way which assumes we know the total serialized length/message end
// position.
impl Writeable for OnionPacket {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
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

impl_writeable_msg!(UpdateAddHTLC, {
	channel_id,
	htlc_id,
	amount_msat,
	payment_hash,
	cltv_expiry,
	onion_routing_packet,
}, {
	(65537, skimmed_fee_msat, option)
});

impl Readable for OnionMessage {
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		let blinding_point: PublicKey = Readable::read(r)?;
		let len: u16 = Readable::read(r)?;
		let mut packet_reader = FixedLengthReader::new(r, len as u64);
		let onion_routing_packet: onion_message::Packet = <onion_message::Packet as LengthReadable>::read(&mut packet_reader)?;
		Ok(Self {
			blinding_point,
			onion_routing_packet,
		})
	}
}

impl Writeable for OnionMessage {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		self.blinding_point.write(w)?;
		let onion_packet_len = self.onion_routing_packet.serialized_length();
		(onion_packet_len as u16).write(w)?;
		self.onion_routing_packet.write(w)?;
		Ok(())
	}
}

impl Writeable for FinalOnionHopData {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		self.payment_secret.0.write(w)?;
		HighZeroBytesDroppedBigSize(self.total_msat).write(w)
	}
}

impl Readable for FinalOnionHopData {
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		let secret: [u8; 32] = Readable::read(r)?;
		let amt: HighZeroBytesDroppedBigSize<u64> = Readable::read(r)?;
		Ok(Self { payment_secret: PaymentSecret(secret), total_msat: amt.0 })
	}
}

impl Writeable for OutboundOnionPayload {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		match self {
			Self::Forward { short_channel_id, amt_to_forward, outgoing_cltv_value } => {
				_encode_varint_length_prefixed_tlv!(w, {
					(2, HighZeroBytesDroppedBigSize(*amt_to_forward), required),
					(4, HighZeroBytesDroppedBigSize(*outgoing_cltv_value), required),
					(6, short_channel_id, required)
				});
			},
			Self::Receive {
				ref payment_data, ref payment_metadata, ref keysend_preimage, amt_msat,
				outgoing_cltv_value, ref custom_tlvs,
			} => {
				// We need to update [`ln::outbound_payment::RecipientOnionFields::with_custom_tlvs`]
				// to reject any reserved types in the experimental range if new ones are ever
				// standardized.
				let keysend_tlv = keysend_preimage.map(|preimage| (5482373484, preimage.encode()));
				let mut custom_tlvs: Vec<&(u64, Vec<u8>)> = custom_tlvs.iter().chain(keysend_tlv.iter()).collect();
				custom_tlvs.sort_unstable_by_key(|(typ, _)| *typ);
				_encode_varint_length_prefixed_tlv!(w, {
					(2, HighZeroBytesDroppedBigSize(*amt_msat), required),
					(4, HighZeroBytesDroppedBigSize(*outgoing_cltv_value), required),
					(8, payment_data, option),
					(16, payment_metadata.as_ref().map(|m| WithoutLength(m)), option)
				}, custom_tlvs.iter());
			},
		}
		Ok(())
	}
}

impl Readable for InboundOnionPayload {
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		let mut amt = HighZeroBytesDroppedBigSize(0u64);
		let mut cltv_value = HighZeroBytesDroppedBigSize(0u32);
		let mut short_id: Option<u64> = None;
		let mut payment_data: Option<FinalOnionHopData> = None;
		let mut payment_metadata: Option<WithoutLength<Vec<u8>>> = None;
		let mut keysend_preimage: Option<PaymentPreimage> = None;
		let mut custom_tlvs = Vec::new();

		let tlv_len = BigSize::read(r)?;
		let rd = FixedLengthReader::new(r, tlv_len.0);
		decode_tlv_stream_with_custom_tlv_decode!(rd, {
			(2, amt, required),
			(4, cltv_value, required),
			(6, short_id, option),
			(8, payment_data, option),
			(16, payment_metadata, option),
			// See https://github.com/lightning/blips/blob/master/blip-0003.md
			(5482373484, keysend_preimage, option)
		}, |msg_type: u64, msg_reader: &mut FixedLengthReader<_>| -> Result<bool, DecodeError> {
			if msg_type < 1 << 16 { return Ok(false) }
			let mut value = Vec::new();
			msg_reader.read_to_end(&mut value)?;
			custom_tlvs.push((msg_type, value));
			Ok(true)
		});

		if amt.0 > MAX_VALUE_MSAT { return Err(DecodeError::InvalidValue) }
		if let Some(short_channel_id) = short_id {
			if payment_data.is_some() { return Err(DecodeError::InvalidValue) }
			if payment_metadata.is_some() { return Err(DecodeError::InvalidValue); }
			Ok(Self::Forward {
				short_channel_id,
				amt_to_forward: amt.0,
				outgoing_cltv_value: cltv_value.0,
			})
		} else {
			if let Some(data) = &payment_data {
				if data.total_msat > MAX_VALUE_MSAT {
					return Err(DecodeError::InvalidValue);
				}
			}
			Ok(Self::Receive {
				payment_data,
				payment_metadata: payment_metadata.map(|w| w.0),
				keysend_preimage,
				amt_msat: amt.0,
				outgoing_cltv_value: cltv_value.0,
				custom_tlvs,
			})
		}
	}
}

// ReadableArgs because we need onion_utils::decode_next_hop to accommodate payment packets and
// onion message packets.
impl ReadableArgs<()> for InboundOnionPayload {
	fn read<R: Read>(r: &mut R, _arg: ()) -> Result<Self, DecodeError> {
		<Self as Readable>::read(r)
	}
}

impl Writeable for Ping {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
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
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
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
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
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
			excess_data: read_to_end(r)?,
		})
	}
}

impl_writeable!(ChannelAnnouncement, {
	node_signature_1,
	node_signature_2,
	bitcoin_signature_1,
	bitcoin_signature_2,
	contents
});

impl Writeable for UnsignedChannelUpdate {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		// `message_flags` used to indicate presence of `htlc_maximum_msat`, but was deprecated in the spec.
		const MESSAGE_FLAGS: u8 = 1;
		self.chain_hash.write(w)?;
		self.short_channel_id.write(w)?;
		self.timestamp.write(w)?;
		let all_flags = self.flags as u16 | ((MESSAGE_FLAGS as u16) << 8);
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
		Ok(Self {
			chain_hash: Readable::read(r)?,
			short_channel_id: Readable::read(r)?,
			timestamp: Readable::read(r)?,
			flags: {
				let flags: u16 = Readable::read(r)?;
				// Note: we ignore the `message_flags` for now, since it was deprecated by the spec.
				flags as u8
			},
			cltv_expiry_delta: Readable::read(r)?,
			htlc_minimum_msat: Readable::read(r)?,
			fee_base_msat: Readable::read(r)?,
			fee_proportional_millionths: Readable::read(r)?,
			htlc_maximum_msat: Readable::read(r)?,
			excess_data: read_to_end(r)?,
		})
	}
}

impl_writeable!(ChannelUpdate, {
	signature,
	contents
});

impl Writeable for ErrorMessage {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
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
				let sz: usize = <u16 as Readable>::read(r)? as usize;
				let mut data = Vec::with_capacity(sz);
				data.resize(sz, 0);
				r.read_exact(&mut data)?;
				match String::from_utf8(data) {
					Ok(s) => s,
					Err(_) => return Err(DecodeError::InvalidValue),
				}
			}
		})
	}
}

impl Writeable for WarningMessage {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		self.channel_id.write(w)?;
		(self.data.len() as u16).write(w)?;
		w.write_all(self.data.as_bytes())?;
		Ok(())
	}
}

impl Readable for WarningMessage {
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		Ok(Self {
			channel_id: Readable::read(r)?,
			data: {
				let sz: usize = <u16 as Readable>::read(r)? as usize;
				let mut data = Vec::with_capacity(sz);
				data.resize(sz, 0);
				r.read_exact(&mut data)?;
				match String::from_utf8(data) {
					Ok(s) => s,
					Err(_) => return Err(DecodeError::InvalidValue),
				}
			}
		})
	}
}

impl Writeable for UnsignedNodeAnnouncement {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		self.features.write(w)?;
		self.timestamp.write(w)?;
		self.node_id.write(w)?;
		w.write_all(&self.rgb)?;
		self.alias.write(w)?;

		let mut addr_len = 0;
		for addr in self.addresses.iter() {
			addr_len += 1 + addr.len();
		}
		(addr_len + self.excess_address_data.len() as u16).write(w)?;
		for addr in self.addresses.iter() {
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
		let node_id: NodeId = Readable::read(r)?;
		let mut rgb = [0; 3];
		r.read_exact(&mut rgb)?;
		let alias: NodeAlias = Readable::read(r)?;

		let addr_len: u16 = Readable::read(r)?;
		let mut addresses: Vec<NetAddress> = Vec::new();
		let mut addr_readpos = 0;
		let mut excess = false;
		let mut excess_byte = 0;
		loop {
			if addr_len <= addr_readpos { break; }
			match Readable::read(r) {
				Ok(Ok(addr)) => {
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
		excess_data.extend(read_to_end(r)?.iter());
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

impl_writeable!(NodeAnnouncement, {
	signature,
	contents
});

impl Readable for QueryShortChannelIds {
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		let chain_hash: BlockHash = Readable::read(r)?;

		let encoding_len: u16 = Readable::read(r)?;
		let encoding_type: u8 = Readable::read(r)?;

		// Must be encoding_type=0 uncompressed serialization. We do not
		// support encoding_type=1 zlib serialization.
		if encoding_type != EncodingType::Uncompressed as u8 {
			return Err(DecodeError::UnsupportedCompression);
		}

		// We expect the encoding_len to always includes the 1-byte
		// encoding_type and that short_channel_ids are 8-bytes each
		if encoding_len == 0 || (encoding_len - 1) % 8 != 0 {
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
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		// Calculated from 1-byte encoding_type plus 8-bytes per short_channel_id
		let encoding_len: u16 = 1 + self.short_channel_ids.len() as u16 * 8;

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

impl_writeable_msg!(ReplyShortChannelIdsEnd, {
	chain_hash,
	full_information,
}, {});

impl QueryChannelRange {
	/// Calculates the overflow safe ending block height for the query.
	///
	/// Overflow returns `0xffffffff`, otherwise returns `first_blocknum + number_of_blocks`.
	pub fn end_blocknum(&self) -> u32 {
		match self.first_blocknum.checked_add(self.number_of_blocks) {
			Some(block) => block,
			None => u32::max_value(),
		}
	}
}

impl_writeable_msg!(QueryChannelRange, {
	chain_hash,
	first_blocknum,
	number_of_blocks
}, {});

impl Readable for ReplyChannelRange {
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		let chain_hash: BlockHash = Readable::read(r)?;
		let first_blocknum: u32 = Readable::read(r)?;
		let number_of_blocks: u32 = Readable::read(r)?;
		let sync_complete: bool = Readable::read(r)?;

		let encoding_len: u16 = Readable::read(r)?;
		let encoding_type: u8 = Readable::read(r)?;

		// Must be encoding_type=0 uncompressed serialization. We do not
		// support encoding_type=1 zlib serialization.
		if encoding_type != EncodingType::Uncompressed as u8 {
			return Err(DecodeError::UnsupportedCompression);
		}

		// We expect the encoding_len to always includes the 1-byte
		// encoding_type and that short_channel_ids are 8-bytes each
		if encoding_len == 0 || (encoding_len - 1) % 8 != 0 {
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
			sync_complete,
			short_channel_ids
		})
	}
}

impl Writeable for ReplyChannelRange {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		let encoding_len: u16 = 1 + self.short_channel_ids.len() as u16 * 8;
		self.chain_hash.write(w)?;
		self.first_blocknum.write(w)?;
		self.number_of_blocks.write(w)?;
		self.sync_complete.write(w)?;

		encoding_len.write(w)?;
		(EncodingType::Uncompressed as u8).write(w)?;
		for scid in self.short_channel_ids.iter() {
			scid.write(w)?;
		}

		Ok(())
	}
}

impl_writeable_msg!(GossipTimestampFilter, {
	chain_hash,
	first_timestamp,
	timestamp_range,
}, {});

#[cfg(test)]
mod tests {
	use std::convert::TryFrom;
	use bitcoin::blockdata::constants::ChainHash;
	use bitcoin::{Transaction, PackedLockTime, TxIn, Script, Sequence, Witness, TxOut};
	use hex;
	use crate::ln::{PaymentPreimage, PaymentHash, PaymentSecret};
	use crate::ln::ChannelId;
	use crate::ln::features::{ChannelFeatures, ChannelTypeFeatures, InitFeatures, NodeFeatures};
	use crate::ln::msgs::{self, FinalOnionHopData, OnionErrorPacket};
	use crate::ln::msgs::NetAddress;
	use crate::routing::gossip::{NodeAlias, NodeId};
	use crate::util::ser::{Writeable, Readable, Hostname, TransactionU16LenLimited};

	use bitcoin::hashes::hex::FromHex;
	use bitcoin::util::address::Address;
	use bitcoin::network::constants::Network;
	use bitcoin::blockdata::script::Builder;
	use bitcoin::blockdata::opcodes;
	use bitcoin::hash_types::{Txid, BlockHash};

	use bitcoin::secp256k1::{PublicKey,SecretKey};
	use bitcoin::secp256k1::{Secp256k1, Message};

	use crate::io::{self, Cursor};
	use crate::prelude::*;
	use core::str::FromStr;
	use crate::chain::transaction::OutPoint;

	#[cfg(feature = "std")]
	use std::net::{Ipv4Addr, Ipv6Addr};
	use crate::ln::msgs::NetAddressParseError;

	#[test]
	fn encoding_channel_reestablish() {
		let public_key = {
			let secp_ctx = Secp256k1::new();
			PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&hex::decode("0101010101010101010101010101010101010101010101010101010101010101").unwrap()[..]).unwrap())
		};

		let cr = msgs::ChannelReestablish {
			channel_id: ChannelId::from_bytes([4, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0]),
			next_local_commitment_number: 3,
			next_remote_commitment_number: 4,
			your_last_per_commitment_secret: [9;32],
			my_current_per_commitment_point: public_key,
			next_funding_txid: None,
		};

		let encoded_value = cr.encode();
		assert_eq!(
			encoded_value,
			vec![
				4, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, // channel_id
				0, 0, 0, 0, 0, 0, 0, 3, // next_local_commitment_number
				0, 0, 0, 0, 0, 0, 0, 4, // next_remote_commitment_number
				9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, // your_last_per_commitment_secret
				3, 27, 132, 197, 86, 123, 18, 100, 64, 153, 93, 62, 213, 170, 186, 5, 101, 215, 30, 24, 52, 96, 72, 25, 255, 156, 23, 245, 233, 213, 221, 7, 143, // my_current_per_commitment_point
			]
		);
	}

	#[test]
	fn encoding_channel_reestablish_with_next_funding_txid() {
		let public_key = {
			let secp_ctx = Secp256k1::new();
			PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&hex::decode("0101010101010101010101010101010101010101010101010101010101010101").unwrap()[..]).unwrap())
		};

		let cr = msgs::ChannelReestablish {
			channel_id: ChannelId::from_bytes([4, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0]),
			next_local_commitment_number: 3,
			next_remote_commitment_number: 4,
			your_last_per_commitment_secret: [9;32],
			my_current_per_commitment_point: public_key,
			next_funding_txid: Some(Txid::from_hash(bitcoin::hashes::Hash::from_slice(&[
				48, 167, 250, 69, 152, 48, 103, 172, 164, 99, 59, 19, 23, 11, 92, 84, 15, 80, 4, 12, 98, 82, 75, 31, 201, 11, 91, 23, 98, 23, 53, 124,
			]).unwrap())),
		};

		let encoded_value = cr.encode();
		assert_eq!(
			encoded_value,
			vec![
				4, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, // channel_id
				0, 0, 0, 0, 0, 0, 0, 3, // next_local_commitment_number
				0, 0, 0, 0, 0, 0, 0, 4, // next_remote_commitment_number
				9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, // your_last_per_commitment_secret
				3, 27, 132, 197, 86, 123, 18, 100, 64, 153, 93, 62, 213, 170, 186, 5, 101, 215, 30, 24, 52, 96, 72, 25, 255, 156, 23, 245, 233, 213, 221, 7, 143, // my_current_per_commitment_point
				0, // Type (next_funding_txid)
				32, // Length
				48, 167, 250, 69, 152, 48, 103, 172, 164, 99, 59, 19, 23, 11, 92, 84, 15, 80, 4, 12, 98, 82, 75, 31, 201, 11, 91, 23, 98, 23, 53, 124, // Value
			]
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
				$ctx.sign_ecdsa(&sighash, &$privkey)
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
			channel_id: ChannelId::from_bytes([4, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0]),
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
		let mut features = ChannelFeatures::empty();
		if unknown_features_bits {
			features = ChannelFeatures::from_le_bytes(vec![0xFF, 0xFF]);
		}
		let unsigned_channel_announcement = msgs::UnsignedChannelAnnouncement {
			features,
			chain_hash: BlockHash::from_hex("6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000").unwrap(),
			short_channel_id: 2316138423780173,
			node_id_1: NodeId::from_pubkey(&pubkey_1),
			node_id_2: NodeId::from_pubkey(&pubkey_2),
			bitcoin_key_1: NodeId::from_pubkey(&pubkey_3),
			bitcoin_key_2: NodeId::from_pubkey(&pubkey_4),
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

	fn do_encoding_node_announcement(unknown_features_bits: bool, ipv4: bool, ipv6: bool, onionv2: bool, onionv3: bool, hostname: bool, excess_address_data: bool, excess_data: bool) {
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
			addresses.push(NetAddress::IPv4 {
				addr: [255, 254, 253, 252],
				port: 9735
			});
		}
		if ipv6 {
			addresses.push(NetAddress::IPv6 {
				addr: [255, 254, 253, 252, 251, 250, 249, 248, 247, 246, 245, 244, 243, 242, 241, 240],
				port: 9735
			});
		}
		if onionv2 {
			addresses.push(NetAddress::OnionV2(
				[255, 254, 253, 252, 251, 250, 249, 248, 247, 246, 38, 7]
			));
		}
		if onionv3 {
			addresses.push(NetAddress::OnionV3 {
				ed25519_pubkey:	[255, 254, 253, 252, 251, 250, 249, 248, 247, 246, 245, 244, 243, 242, 241, 240, 239, 238, 237, 236, 235, 234, 233, 232, 231, 230, 229, 228, 227, 226, 225, 224],
				checksum: 32,
				version: 16,
				port: 9735
			});
		}
		if hostname {
			addresses.push(NetAddress::Hostname {
				hostname: Hostname::try_from(String::from("host")).unwrap(),
				port: 9735,
			});
		}
		let mut addr_len = 0;
		for addr in &addresses {
			addr_len += addr.len() + 1;
		}
		let unsigned_node_announcement = msgs::UnsignedNodeAnnouncement {
			features,
			timestamp: 20190119,
			node_id: NodeId::from_pubkey(&pubkey_1),
			rgb: [32; 3],
			alias: NodeAlias([16;32]),
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
		if hostname {
			target_value.append(&mut hex::decode("0504686f73742607").unwrap());
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
		do_encoding_node_announcement(true, true, true, true, true, true, true, true);
		do_encoding_node_announcement(false, false, false, false, false, false, false, false);
		do_encoding_node_announcement(false, true, false, false, false, false, false, false);
		do_encoding_node_announcement(false, false, true, false, false, false, false, false);
		do_encoding_node_announcement(false, false, false, true, false, false, false, false);
		do_encoding_node_announcement(false, false, false, false, true, false, false, false);
		do_encoding_node_announcement(false, false, false, false, false, true, false, false);
		do_encoding_node_announcement(false, false, false, false, false, false, true, false);
		do_encoding_node_announcement(false, true, false, true, false, false, true, false);
		do_encoding_node_announcement(false, false, true, false, true, false, false, false);
	}

	fn do_encoding_channel_update(direction: bool, disable: bool, excess_data: bool) {
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
			htlc_maximum_msat: 131355275467161,
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
		target_value.append(&mut hex::decode("01").unwrap());
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
		target_value.append(&mut hex::decode("0000777788889999").unwrap());
		if excess_data {
			target_value.append(&mut hex::decode("000000003b9aca00").unwrap());
		}
		assert_eq!(encoded_value, target_value);
	}

	#[test]
	fn encoding_channel_update() {
		do_encoding_channel_update(false, false, false);
		do_encoding_channel_update(false, false, true);
		do_encoding_channel_update(true, false, false);
		do_encoding_channel_update(true, false, true);
		do_encoding_channel_update(false, true, false);
		do_encoding_channel_update(false, true, true);
		do_encoding_channel_update(true, true, false);
		do_encoding_channel_update(true, true, true);
	}

	fn do_encoding_open_channel(random_bit: bool, shutdown: bool, incl_chan_type: bool) {
		let secp_ctx = Secp256k1::new();
		let (_, pubkey_1) = get_keys_from!("0101010101010101010101010101010101010101010101010101010101010101", secp_ctx);
		let (_, pubkey_2) = get_keys_from!("0202020202020202020202020202020202020202020202020202020202020202", secp_ctx);
		let (_, pubkey_3) = get_keys_from!("0303030303030303030303030303030303030303030303030303030303030303", secp_ctx);
		let (_, pubkey_4) = get_keys_from!("0404040404040404040404040404040404040404040404040404040404040404", secp_ctx);
		let (_, pubkey_5) = get_keys_from!("0505050505050505050505050505050505050505050505050505050505050505", secp_ctx);
		let (_, pubkey_6) = get_keys_from!("0606060606060606060606060606060606060606060606060606060606060606", secp_ctx);
		let open_channel = msgs::OpenChannel {
			chain_hash: BlockHash::from_hex("6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000").unwrap(),
			temporary_channel_id: ChannelId::from_bytes([2; 32]),
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
			shutdown_scriptpubkey: if shutdown { Some(Address::p2pkh(&::bitcoin::PublicKey{compressed: true, inner: pubkey_1}, Network::Testnet).script_pubkey()) } else { None },
			channel_type: if incl_chan_type { Some(ChannelTypeFeatures::empty()) } else { None },
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
		if incl_chan_type {
			target_value.append(&mut hex::decode("0100").unwrap());
		}
		assert_eq!(encoded_value, target_value);
	}

	#[test]
	fn encoding_open_channel() {
		do_encoding_open_channel(false, false, false);
		do_encoding_open_channel(false, false, true);
		do_encoding_open_channel(false, true, false);
		do_encoding_open_channel(false, true, true);
		do_encoding_open_channel(true, false, false);
		do_encoding_open_channel(true, false, true);
		do_encoding_open_channel(true, true, false);
		do_encoding_open_channel(true, true, true);
	}

	fn do_encoding_open_channelv2(random_bit: bool, shutdown: bool, incl_chan_type: bool, require_confirmed_inputs: bool) {
		let secp_ctx = Secp256k1::new();
		let (_, pubkey_1) = get_keys_from!("0101010101010101010101010101010101010101010101010101010101010101", secp_ctx);
		let (_, pubkey_2) = get_keys_from!("0202020202020202020202020202020202020202020202020202020202020202", secp_ctx);
		let (_, pubkey_3) = get_keys_from!("0303030303030303030303030303030303030303030303030303030303030303", secp_ctx);
		let (_, pubkey_4) = get_keys_from!("0404040404040404040404040404040404040404040404040404040404040404", secp_ctx);
		let (_, pubkey_5) = get_keys_from!("0505050505050505050505050505050505050505050505050505050505050505", secp_ctx);
		let (_, pubkey_6) = get_keys_from!("0606060606060606060606060606060606060606060606060606060606060606", secp_ctx);
		let (_, pubkey_7) = get_keys_from!("0707070707070707070707070707070707070707070707070707070707070707", secp_ctx);
		let open_channelv2 = msgs::OpenChannelV2 {
			chain_hash: BlockHash::from_hex("6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000").unwrap(),
			temporary_channel_id: ChannelId::from_bytes([2; 32]),
			funding_feerate_sat_per_1000_weight: 821716,
			commitment_feerate_sat_per_1000_weight: 821716,
			funding_satoshis: 1311768467284833366,
			dust_limit_satoshis: 3608586615801332854,
			max_htlc_value_in_flight_msat: 8517154655701053848,
			htlc_minimum_msat: 2316138423780173,
			to_self_delay: 49340,
			max_accepted_htlcs: 49340,
			locktime: 305419896,
			funding_pubkey: pubkey_1,
			revocation_basepoint: pubkey_2,
			payment_basepoint: pubkey_3,
			delayed_payment_basepoint: pubkey_4,
			htlc_basepoint: pubkey_5,
			first_per_commitment_point: pubkey_6,
			second_per_commitment_point: pubkey_7,
			channel_flags: if random_bit { 1 << 5 } else { 0 },
			shutdown_scriptpubkey: if shutdown { Some(Address::p2pkh(&::bitcoin::PublicKey{compressed: true, inner: pubkey_1}, Network::Testnet).script_pubkey()) } else { None },
			channel_type: if incl_chan_type { Some(ChannelTypeFeatures::empty()) } else { None },
			require_confirmed_inputs: if require_confirmed_inputs { Some(()) } else { None },
		};
		let encoded_value = open_channelv2.encode();
		let mut target_value = Vec::new();
		target_value.append(&mut hex::decode("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f").unwrap());
		target_value.append(&mut hex::decode("0202020202020202020202020202020202020202020202020202020202020202").unwrap());
		target_value.append(&mut hex::decode("000c89d4").unwrap());
		target_value.append(&mut hex::decode("000c89d4").unwrap());
		target_value.append(&mut hex::decode("1234567890123456").unwrap());
		target_value.append(&mut hex::decode("3214466870114476").unwrap());
		target_value.append(&mut hex::decode("7633030896203198").unwrap());
		target_value.append(&mut hex::decode("00083a840000034d").unwrap());
		target_value.append(&mut hex::decode("c0bc").unwrap());
		target_value.append(&mut hex::decode("c0bc").unwrap());
		target_value.append(&mut hex::decode("12345678").unwrap());
		target_value.append(&mut hex::decode("031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f").unwrap());
		target_value.append(&mut hex::decode("024d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d0766").unwrap());
		target_value.append(&mut hex::decode("02531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337").unwrap());
		target_value.append(&mut hex::decode("03462779ad4aad39514614751a71085f2f10e1c7a593e4e030efb5b8721ce55b0b").unwrap());
		target_value.append(&mut hex::decode("0362c0a046dacce86ddd0343c6d3c7c79c2208ba0d9c9cf24a6d046d21d21f90f7").unwrap());
		target_value.append(&mut hex::decode("03f006a18d5653c4edf5391ff23a61f03ff83d237e880ee61187fa9f379a028e0a").unwrap());
		target_value.append(&mut hex::decode("02989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f").unwrap());

		if random_bit {
			target_value.append(&mut hex::decode("20").unwrap());
		} else {
			target_value.append(&mut hex::decode("00").unwrap());
		}
		if shutdown {
			target_value.append(&mut hex::decode("001b").unwrap()); // Type 0 + Length 27
			target_value.append(&mut hex::decode("001976a91479b000887626b294a914501a4cd226b58b23598388ac").unwrap());
		}
		if incl_chan_type {
			target_value.append(&mut hex::decode("0100").unwrap());
		}
		if require_confirmed_inputs {
			target_value.append(&mut hex::decode("0200").unwrap());
		}
		assert_eq!(encoded_value, target_value);
	}

	#[test]
	fn encoding_open_channelv2() {
		do_encoding_open_channelv2(false, false, false, false);
		do_encoding_open_channelv2(false, false, false, true);
		do_encoding_open_channelv2(false, false, true, false);
		do_encoding_open_channelv2(false, false, true, true);
		do_encoding_open_channelv2(false, true, false, false);
		do_encoding_open_channelv2(false, true, false, true);
		do_encoding_open_channelv2(false, true, true, false);
		do_encoding_open_channelv2(false, true, true, true);
		do_encoding_open_channelv2(true, false, false, false);
		do_encoding_open_channelv2(true, false, false, true);
		do_encoding_open_channelv2(true, false, true, false);
		do_encoding_open_channelv2(true, false, true, true);
		do_encoding_open_channelv2(true, true, false, false);
		do_encoding_open_channelv2(true, true, false, true);
		do_encoding_open_channelv2(true, true, true, false);
		do_encoding_open_channelv2(true, true, true, true);
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
			temporary_channel_id: ChannelId::from_bytes([2; 32]),
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
			shutdown_scriptpubkey: if shutdown { Some(Address::p2pkh(&::bitcoin::PublicKey{compressed: true, inner: pubkey_1}, Network::Testnet).script_pubkey()) } else { None },
			channel_type: None,
			#[cfg(taproot)]
			next_local_nonce: None,
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

	fn do_encoding_accept_channelv2(shutdown: bool) {
		let secp_ctx = Secp256k1::new();
		let (_, pubkey_1) = get_keys_from!("0101010101010101010101010101010101010101010101010101010101010101", secp_ctx);
		let (_, pubkey_2) = get_keys_from!("0202020202020202020202020202020202020202020202020202020202020202", secp_ctx);
		let (_, pubkey_3) = get_keys_from!("0303030303030303030303030303030303030303030303030303030303030303", secp_ctx);
		let (_, pubkey_4) = get_keys_from!("0404040404040404040404040404040404040404040404040404040404040404", secp_ctx);
		let (_, pubkey_5) = get_keys_from!("0505050505050505050505050505050505050505050505050505050505050505", secp_ctx);
		let (_, pubkey_6) = get_keys_from!("0606060606060606060606060606060606060606060606060606060606060606", secp_ctx);
		let (_, pubkey_7) = get_keys_from!("0707070707070707070707070707070707070707070707070707070707070707", secp_ctx);
		let accept_channelv2 = msgs::AcceptChannelV2 {
			temporary_channel_id: ChannelId::from_bytes([2; 32]),
			funding_satoshis: 1311768467284833366,
			dust_limit_satoshis: 1311768467284833366,
			max_htlc_value_in_flight_msat: 2536655962884945560,
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
			second_per_commitment_point: pubkey_7,
			shutdown_scriptpubkey: if shutdown { Some(Address::p2pkh(&::bitcoin::PublicKey{compressed: true, inner: pubkey_1}, Network::Testnet).script_pubkey()) } else { None },
			channel_type: None,
			require_confirmed_inputs: None,
		};
		let encoded_value = accept_channelv2.encode();
		let mut target_value = hex::decode("0202020202020202020202020202020202020202020202020202020202020202").unwrap(); // temporary_channel_id
		target_value.append(&mut hex::decode("1234567890123456").unwrap()); // funding_satoshis
		target_value.append(&mut hex::decode("1234567890123456").unwrap()); // dust_limit_satoshis
		target_value.append(&mut hex::decode("2334032891223698").unwrap()); // max_htlc_value_in_flight_msat
		target_value.append(&mut hex::decode("00083a840000034d").unwrap()); // htlc_minimum_msat
		target_value.append(&mut hex::decode("000c89d4").unwrap()); //  minimum_depth
		target_value.append(&mut hex::decode("c0bc").unwrap()); // to_self_delay
		target_value.append(&mut hex::decode("c0bc").unwrap()); // max_accepted_htlcs
		target_value.append(&mut hex::decode("031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f").unwrap()); // funding_pubkey
		target_value.append(&mut hex::decode("024d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d0766").unwrap()); // revocation_basepoint
		target_value.append(&mut hex::decode("02531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337").unwrap()); // payment_basepoint
		target_value.append(&mut hex::decode("03462779ad4aad39514614751a71085f2f10e1c7a593e4e030efb5b8721ce55b0b").unwrap()); // delayed_payment_basepoint
		target_value.append(&mut hex::decode("0362c0a046dacce86ddd0343c6d3c7c79c2208ba0d9c9cf24a6d046d21d21f90f7").unwrap()); // htlc_basepoint
		target_value.append(&mut hex::decode("03f006a18d5653c4edf5391ff23a61f03ff83d237e880ee61187fa9f379a028e0a").unwrap()); // first_per_commitment_point
		target_value.append(&mut hex::decode("02989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f").unwrap()); // second_per_commitment_point
		if shutdown {
			target_value.append(&mut hex::decode("001b").unwrap()); // Type 0 + Length 27
			target_value.append(&mut hex::decode("001976a91479b000887626b294a914501a4cd226b58b23598388ac").unwrap());
		}
		assert_eq!(encoded_value, target_value);
	}

	#[test]
	fn encoding_accept_channelv2() {
		do_encoding_accept_channelv2(false);
		do_encoding_accept_channelv2(true);
	}

	#[test]
	fn encoding_funding_created() {
		let secp_ctx = Secp256k1::new();
		let (privkey_1, _) = get_keys_from!("0101010101010101010101010101010101010101010101010101010101010101", secp_ctx);
		let sig_1 = get_sig_on!(privkey_1, secp_ctx, String::from("01010101010101010101010101010101"));
		let funding_created = msgs::FundingCreated {
			temporary_channel_id: ChannelId::from_bytes([2; 32]),
			funding_txid: Txid::from_hex("c2d4449afa8d26140898dd54d3390b057ba2a5afcf03ba29d7dc0d8b9ffe966e").unwrap(),
			funding_output_index: 255,
			signature: sig_1,
			#[cfg(taproot)]
			partial_signature_with_nonce: None,
			#[cfg(taproot)]
			next_local_nonce: None,
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
			channel_id: ChannelId::from_bytes([2; 32]),
			signature: sig_1,
			#[cfg(taproot)]
			partial_signature_with_nonce: None,
		};
		let encoded_value = funding_signed.encode();
		let target_value = hex::decode("0202020202020202020202020202020202020202020202020202020202020202d977cb9b53d93a6ff64bb5f1e158b4094b66e798fb12911168a3ccdf80a83096340a6a95da0ae8d9f776528eecdbb747eb6b545495a4319ed5378e35b21e073a").unwrap();
		assert_eq!(encoded_value, target_value);
	}

	#[test]
	fn encoding_channel_ready() {
		let secp_ctx = Secp256k1::new();
		let (_, pubkey_1,) = get_keys_from!("0101010101010101010101010101010101010101010101010101010101010101", secp_ctx);
		let channel_ready = msgs::ChannelReady {
			channel_id: ChannelId::from_bytes([2; 32]),
			next_per_commitment_point: pubkey_1,
			short_channel_id_alias: None,
		};
		let encoded_value = channel_ready.encode();
		let target_value = hex::decode("0202020202020202020202020202020202020202020202020202020202020202031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f").unwrap();
		assert_eq!(encoded_value, target_value);
	}

	#[test]
	fn encoding_tx_add_input() {
		let tx_add_input = msgs::TxAddInput {
			channel_id: ChannelId::from_bytes([2; 32]),
			serial_id: 4886718345,
			prevtx: TransactionU16LenLimited::new(Transaction {
				version: 2,
				lock_time: PackedLockTime(0),
				input: vec![TxIn {
					previous_output: OutPoint { txid: Txid::from_hex("305bab643ee297b8b6b76b320792c8223d55082122cb606bf89382146ced9c77").unwrap(), index: 2 }.into_bitcoin_outpoint(),
					script_sig: Script::new(),
					sequence: Sequence(0xfffffffd),
					witness: Witness::from_vec(vec![
						hex::decode("304402206af85b7dd67450ad12c979302fac49dfacbc6a8620f49c5da2b5721cf9565ca502207002b32fed9ce1bf095f57aeb10c36928ac60b12e723d97d2964a54640ceefa701").unwrap(),
						hex::decode("0301ab7dc16488303549bfcdd80f6ae5ee4c20bf97ab5410bbd6b1bfa85dcd6944").unwrap()]),
				}],
				output: vec![
					TxOut {
						value: 12704566,
						script_pubkey: Address::from_str("bc1qzlffunw52jav8vwdu5x3jfk6sr8u22rmq3xzw2").unwrap().script_pubkey(),
					},
					TxOut {
						value: 245148,
						script_pubkey: Address::from_str("bc1qxmk834g5marzm227dgqvynd23y2nvt2ztwcw2z").unwrap().script_pubkey(),
					},
				],
			}).unwrap(),
			prevtx_out: 305419896,
			sequence: 305419896,
		};
		let encoded_value = tx_add_input.encode();
		let target_value = hex::decode("0202020202020202020202020202020202020202020202020202020202020202000000012345678900de02000000000101779ced6c148293f86b60cb222108553d22c89207326bb7b6b897e23e64ab5b300200000000fdffffff0236dbc1000000000016001417d29e4dd454bac3b1cde50d1926da80cfc5287b9cbd03000000000016001436ec78d514df462da95e6a00c24daa8915362d420247304402206af85b7dd67450ad12c979302fac49dfacbc6a8620f49c5da2b5721cf9565ca502207002b32fed9ce1bf095f57aeb10c36928ac60b12e723d97d2964a54640ceefa701210301ab7dc16488303549bfcdd80f6ae5ee4c20bf97ab5410bbd6b1bfa85dcd6944000000001234567812345678").unwrap();
		assert_eq!(encoded_value, target_value);
	}

	#[test]
	fn encoding_tx_add_output() {
		let tx_add_output = msgs::TxAddOutput {
			channel_id: ChannelId::from_bytes([2; 32]),
			serial_id: 4886718345,
			sats: 4886718345,
			script: Address::from_str("bc1qxmk834g5marzm227dgqvynd23y2nvt2ztwcw2z").unwrap().script_pubkey(),
		};
		let encoded_value = tx_add_output.encode();
		let target_value = hex::decode("0202020202020202020202020202020202020202020202020202020202020202000000012345678900000001234567890016001436ec78d514df462da95e6a00c24daa8915362d42").unwrap();
		assert_eq!(encoded_value, target_value);
	}

	#[test]
	fn encoding_tx_remove_input() {
		let tx_remove_input = msgs::TxRemoveInput {
			channel_id: ChannelId::from_bytes([2; 32]),
			serial_id: 4886718345,
		};
		let encoded_value = tx_remove_input.encode();
		let target_value = hex::decode("02020202020202020202020202020202020202020202020202020202020202020000000123456789").unwrap();
		assert_eq!(encoded_value, target_value);
	}

	#[test]
	fn encoding_tx_remove_output() {
		let tx_remove_output = msgs::TxRemoveOutput {
			channel_id: ChannelId::from_bytes([2; 32]),
			serial_id: 4886718345,
		};
		let encoded_value = tx_remove_output.encode();
		let target_value = hex::decode("02020202020202020202020202020202020202020202020202020202020202020000000123456789").unwrap();
		assert_eq!(encoded_value, target_value);
	}

	#[test]
	fn encoding_tx_complete() {
		let tx_complete = msgs::TxComplete {
			channel_id: ChannelId::from_bytes([2; 32]),
		};
		let encoded_value = tx_complete.encode();
		let target_value = hex::decode("0202020202020202020202020202020202020202020202020202020202020202").unwrap();
		assert_eq!(encoded_value, target_value);
	}

	#[test]
	fn encoding_tx_signatures() {
		let tx_signatures = msgs::TxSignatures {
			channel_id: ChannelId::from_bytes([2; 32]),
			tx_hash: Txid::from_hex("c2d4449afa8d26140898dd54d3390b057ba2a5afcf03ba29d7dc0d8b9ffe966e").unwrap(),
			witnesses: vec![
				Witness::from_vec(vec![
					hex::decode("304402206af85b7dd67450ad12c979302fac49dfacbc6a8620f49c5da2b5721cf9565ca502207002b32fed9ce1bf095f57aeb10c36928ac60b12e723d97d2964a54640ceefa701").unwrap(),
					hex::decode("0301ab7dc16488303549bfcdd80f6ae5ee4c20bf97ab5410bbd6b1bfa85dcd6944").unwrap()]),
				Witness::from_vec(vec![
					hex::decode("3045022100ee00dbf4a862463e837d7c08509de814d620e4d9830fa84818713e0fa358f145022021c3c7060c4d53fe84fd165d60208451108a778c13b92ca4c6bad439236126cc01").unwrap(),
					hex::decode("028fbbf0b16f5ba5bcb5dd37cd4047ce6f726a21c06682f9ec2f52b057de1dbdb5").unwrap()]),
			],
		};
		let encoded_value = tx_signatures.encode();
		let mut target_value = hex::decode("0202020202020202020202020202020202020202020202020202020202020202").unwrap(); // channel_id
		target_value.append(&mut hex::decode("6e96fe9f8b0ddcd729ba03cfafa5a27b050b39d354dd980814268dfa9a44d4c2").unwrap()); // tx_hash (sha256) (big endian byte order)
		target_value.append(&mut hex::decode("0002").unwrap()); // num_witnesses (u16)
		// Witness 1
		target_value.append(&mut hex::decode("006b").unwrap()); // len of witness_data
		target_value.append(&mut hex::decode("02").unwrap()); // num_witness_elements (VarInt)
		target_value.append(&mut hex::decode("47").unwrap()); // len of witness element data (VarInt)
		target_value.append(&mut hex::decode("304402206af85b7dd67450ad12c979302fac49dfacbc6a8620f49c5da2b5721cf9565ca502207002b32fed9ce1bf095f57aeb10c36928ac60b12e723d97d2964a54640ceefa701").unwrap());
		target_value.append(&mut hex::decode("21").unwrap()); // len of witness element data (VarInt)
		target_value.append(&mut hex::decode("0301ab7dc16488303549bfcdd80f6ae5ee4c20bf97ab5410bbd6b1bfa85dcd6944").unwrap());
		// Witness 2
		target_value.append(&mut hex::decode("006c").unwrap()); // len of witness_data
		target_value.append(&mut hex::decode("02").unwrap()); // num_witness_elements (VarInt)
		target_value.append(&mut hex::decode("48").unwrap()); // len of witness element data (VarInt)
		target_value.append(&mut hex::decode("3045022100ee00dbf4a862463e837d7c08509de814d620e4d9830fa84818713e0fa358f145022021c3c7060c4d53fe84fd165d60208451108a778c13b92ca4c6bad439236126cc01").unwrap());
		target_value.append(&mut hex::decode("21").unwrap()); // len of witness element data (VarInt)
		target_value.append(&mut hex::decode("028fbbf0b16f5ba5bcb5dd37cd4047ce6f726a21c06682f9ec2f52b057de1dbdb5").unwrap());
		assert_eq!(encoded_value, target_value);
	}

	fn do_encoding_tx_init_rbf(funding_value_with_hex_target: Option<(i64, &str)>) {
		let tx_init_rbf = msgs::TxInitRbf {
			channel_id: ChannelId::from_bytes([2; 32]),
			locktime: 305419896,
			feerate_sat_per_1000_weight: 20190119,
			funding_output_contribution: if let Some((value, _)) = funding_value_with_hex_target { Some(value) } else { None },
		};
		let encoded_value = tx_init_rbf.encode();
		let mut target_value = hex::decode("0202020202020202020202020202020202020202020202020202020202020202").unwrap(); // channel_id
		target_value.append(&mut hex::decode("12345678").unwrap()); // locktime
		target_value.append(&mut hex::decode("013413a7").unwrap()); // feerate_sat_per_1000_weight
		if let Some((_, target)) = funding_value_with_hex_target {
			target_value.push(0x00); // Type
			target_value.push(target.len() as u8 / 2); // Length
			target_value.append(&mut hex::decode(target).unwrap()); // Value (i64)
		}
		assert_eq!(encoded_value, target_value);
	}

	#[test]
	fn encoding_tx_init_rbf() {
		do_encoding_tx_init_rbf(Some((1311768467284833366, "1234567890123456")));
		do_encoding_tx_init_rbf(Some((13117684672, "000000030DDFFBC0")));
		do_encoding_tx_init_rbf(None);
	}

	fn do_encoding_tx_ack_rbf(funding_value_with_hex_target: Option<(i64, &str)>) {
		let tx_ack_rbf = msgs::TxAckRbf {
			channel_id: ChannelId::from_bytes([2; 32]),
			funding_output_contribution: if let Some((value, _)) = funding_value_with_hex_target { Some(value) } else { None },
		};
		let encoded_value = tx_ack_rbf.encode();
		let mut target_value = hex::decode("0202020202020202020202020202020202020202020202020202020202020202").unwrap();
		if let Some((_, target)) = funding_value_with_hex_target {
			target_value.push(0x00); // Type
			target_value.push(target.len() as u8 / 2); // Length
			target_value.append(&mut hex::decode(target).unwrap()); // Value (i64)
		}
		assert_eq!(encoded_value, target_value);
	}

	#[test]
	fn encoding_tx_ack_rbf() {
		do_encoding_tx_ack_rbf(Some((1311768467284833366, "1234567890123456")));
		do_encoding_tx_ack_rbf(Some((13117684672, "000000030DDFFBC0")));
		do_encoding_tx_ack_rbf(None);
	}

	#[test]
	fn encoding_tx_abort() {
		let tx_abort = msgs::TxAbort {
			channel_id: ChannelId::from_bytes([2; 32]),
			data: hex::decode("54686520717569636B2062726F776E20666F78206A756D7073206F76657220746865206C617A7920646F672E").unwrap(),
		};
		let encoded_value = tx_abort.encode();
		let target_value = hex::decode("0202020202020202020202020202020202020202020202020202020202020202002C54686520717569636B2062726F776E20666F78206A756D7073206F76657220746865206C617A7920646F672E").unwrap();
		assert_eq!(encoded_value, target_value);
	}

	fn do_encoding_shutdown(script_type: u8) {
		let secp_ctx = Secp256k1::new();
		let (_, pubkey_1) = get_keys_from!("0101010101010101010101010101010101010101010101010101010101010101", secp_ctx);
		let script = Builder::new().push_opcode(opcodes::OP_TRUE).into_script();
		let shutdown = msgs::Shutdown {
			channel_id: ChannelId::from_bytes([2; 32]),
			scriptpubkey:
				if script_type == 1 { Address::p2pkh(&::bitcoin::PublicKey{compressed: true, inner: pubkey_1}, Network::Testnet).script_pubkey() }
				else if script_type == 2 { Address::p2sh(&script, Network::Testnet).unwrap().script_pubkey() }
				else if script_type == 3 { Address::p2wpkh(&::bitcoin::PublicKey{compressed: true, inner: pubkey_1}, Network::Testnet).unwrap().script_pubkey() }
				else { Address::p2wsh(&script, Network::Testnet).script_pubkey() },
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
			channel_id: ChannelId::from_bytes([2; 32]),
			fee_satoshis: 2316138423780173,
			signature: sig_1,
			fee_range: None,
		};
		let encoded_value = closing_signed.encode();
		let target_value = hex::decode("020202020202020202020202020202020202020202020202020202020202020200083a840000034dd977cb9b53d93a6ff64bb5f1e158b4094b66e798fb12911168a3ccdf80a83096340a6a95da0ae8d9f776528eecdbb747eb6b545495a4319ed5378e35b21e073a").unwrap();
		assert_eq!(encoded_value, target_value);
		assert_eq!(msgs::ClosingSigned::read(&mut Cursor::new(&target_value)).unwrap(), closing_signed);

		let closing_signed_with_range = msgs::ClosingSigned {
			channel_id: ChannelId::from_bytes([2; 32]),
			fee_satoshis: 2316138423780173,
			signature: sig_1,
			fee_range: Some(msgs::ClosingSignedFeeRange {
				min_fee_satoshis: 0xdeadbeef,
				max_fee_satoshis: 0x1badcafe01234567,
			}),
		};
		let encoded_value_with_range = closing_signed_with_range.encode();
		let target_value_with_range = hex::decode("020202020202020202020202020202020202020202020202020202020202020200083a840000034dd977cb9b53d93a6ff64bb5f1e158b4094b66e798fb12911168a3ccdf80a83096340a6a95da0ae8d9f776528eecdbb747eb6b545495a4319ed5378e35b21e073a011000000000deadbeef1badcafe01234567").unwrap();
		assert_eq!(encoded_value_with_range, target_value_with_range);
		assert_eq!(msgs::ClosingSigned::read(&mut Cursor::new(&target_value_with_range)).unwrap(),
			closing_signed_with_range);
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
			channel_id: ChannelId::from_bytes([2; 32]),
			htlc_id: 2316138423780173,
			amount_msat: 3608586615801332854,
			payment_hash: PaymentHash([1; 32]),
			cltv_expiry: 821716,
			onion_routing_packet,
			skimmed_fee_msat: None,
		};
		let encoded_value = update_add_htlc.encode();
		let target_value = hex::decode("020202020202020202020202020202020202020202020202020202020202020200083a840000034d32144668701144760101010101010101010101010101010101010101010101010101010101010101000c89d4ff031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010202020202020202020202020202020202020202020202020202020202020202").unwrap();
		assert_eq!(encoded_value, target_value);
	}

	#[test]
	fn encoding_update_fulfill_htlc() {
		let update_fulfill_htlc = msgs::UpdateFulfillHTLC {
			channel_id: ChannelId::from_bytes([2; 32]),
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
			channel_id: ChannelId::from_bytes([2; 32]),
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
			channel_id: ChannelId::from_bytes([2; 32]),
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
			channel_id: ChannelId::from_bytes([2; 32]),
			signature: sig_1,
			htlc_signatures: if htlcs { vec![sig_2, sig_3, sig_4] } else { Vec::new() },
			#[cfg(taproot)]
			partial_signature_with_nonce: None,
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
			channel_id: ChannelId::from_bytes([2; 32]),
			per_commitment_secret: [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1],
			next_per_commitment_point: pubkey_1,
			#[cfg(taproot)]
			next_local_nonce: None,
		};
		let encoded_value = raa.encode();
		let target_value = hex::decode("02020202020202020202020202020202020202020202020202020202020202020101010101010101010101010101010101010101010101010101010101010101031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f").unwrap();
		assert_eq!(encoded_value, target_value);
	}

	#[test]
	fn encoding_update_fee() {
		let update_fee = msgs::UpdateFee {
			channel_id: ChannelId::from_bytes([2; 32]),
			feerate_per_kw: 20190119,
		};
		let encoded_value = update_fee.encode();
		let target_value = hex::decode("0202020202020202020202020202020202020202020202020202020202020202013413a7").unwrap();
		assert_eq!(encoded_value, target_value);
	}

	#[test]
	fn encoding_init() {
		let mainnet_hash = ChainHash::from_hex("6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000").unwrap();
		assert_eq!(msgs::Init {
			features: InitFeatures::from_le_bytes(vec![0xFF, 0xFF, 0xFF]),
			networks: Some(vec![mainnet_hash]),
			remote_network_address: None,
		}.encode(), hex::decode("00023fff0003ffffff01206fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000").unwrap());
		assert_eq!(msgs::Init {
			features: InitFeatures::from_le_bytes(vec![0xFF]),
			networks: None,
			remote_network_address: None,
		}.encode(), hex::decode("0001ff0001ff").unwrap());
		assert_eq!(msgs::Init {
			features: InitFeatures::from_le_bytes(vec![]),
			networks: Some(vec![mainnet_hash]),
			remote_network_address: None,
		}.encode(), hex::decode("0000000001206fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000").unwrap());
		assert_eq!(msgs::Init {
			features: InitFeatures::from_le_bytes(vec![]),
			networks: Some(vec![ChainHash::from(&[1; 32][..]), ChainHash::from(&[2; 32][..])]),
			remote_network_address: None,
		}.encode(), hex::decode("00000000014001010101010101010101010101010101010101010101010101010101010101010202020202020202020202020202020202020202020202020202020202020202").unwrap());
		let init_msg = msgs::Init { features: InitFeatures::from_le_bytes(vec![]),
			networks: Some(vec![mainnet_hash]),
			remote_network_address: Some(NetAddress::IPv4 {
				addr: [127, 0, 0, 1],
				port: 1000,
			}),
		};
		let encoded_value = init_msg.encode();
		let target_value = hex::decode("0000000001206fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d61900000000000307017f00000103e8").unwrap();
		assert_eq!(encoded_value, target_value);
		assert_eq!(msgs::Init::read(&mut Cursor::new(&target_value)).unwrap(), init_msg);
	}

	#[test]
	fn encoding_error() {
		let error = msgs::ErrorMessage {
			channel_id: ChannelId::from_bytes([2; 32]),
			data: String::from("rust-lightning"),
		};
		let encoded_value = error.encode();
		let target_value = hex::decode("0202020202020202020202020202020202020202020202020202020202020202000e727573742d6c696768746e696e67").unwrap();
		assert_eq!(encoded_value, target_value);
	}

	#[test]
	fn encoding_warning() {
		let error = msgs::WarningMessage {
			channel_id: ChannelId::from_bytes([2; 32]),
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
	fn encoding_nonfinal_onion_hop_data() {
		let outbound_msg = msgs::OutboundOnionPayload::Forward {
			short_channel_id: 0xdeadbeef1bad1dea,
			amt_to_forward: 0x0badf00d01020304,
			outgoing_cltv_value: 0xffffffff,
		};
		let encoded_value = outbound_msg.encode();
		let target_value = hex::decode("1a02080badf00d010203040404ffffffff0608deadbeef1bad1dea").unwrap();
		assert_eq!(encoded_value, target_value);

		let inbound_msg = Readable::read(&mut Cursor::new(&target_value[..])).unwrap();
		if let msgs::InboundOnionPayload::Forward { short_channel_id, amt_to_forward, outgoing_cltv_value } = inbound_msg {
			assert_eq!(short_channel_id, 0xdeadbeef1bad1dea);
			assert_eq!(amt_to_forward, 0x0badf00d01020304);
			assert_eq!(outgoing_cltv_value, 0xffffffff);
		} else { panic!(); }
	}

	#[test]
	fn encoding_final_onion_hop_data() {
		let outbound_msg = msgs::OutboundOnionPayload::Receive {
			payment_data: None,
			payment_metadata: None,
			keysend_preimage: None,
			amt_msat: 0x0badf00d01020304,
			outgoing_cltv_value: 0xffffffff,
			custom_tlvs: vec![],
		};
		let encoded_value = outbound_msg.encode();
		let target_value = hex::decode("1002080badf00d010203040404ffffffff").unwrap();
		assert_eq!(encoded_value, target_value);

		let inbound_msg = Readable::read(&mut Cursor::new(&target_value[..])).unwrap();
		if let msgs::InboundOnionPayload::Receive { payment_data: None, amt_msat, outgoing_cltv_value, .. } = inbound_msg {
			assert_eq!(amt_msat, 0x0badf00d01020304);
			assert_eq!(outgoing_cltv_value, 0xffffffff);
		} else { panic!(); }
	}

	#[test]
	fn encoding_final_onion_hop_data_with_secret() {
		let expected_payment_secret = PaymentSecret([0x42u8; 32]);
		let outbound_msg = msgs::OutboundOnionPayload::Receive {
			payment_data: Some(FinalOnionHopData {
				payment_secret: expected_payment_secret,
				total_msat: 0x1badca1f
			}),
			payment_metadata: None,
			keysend_preimage: None,
			amt_msat: 0x0badf00d01020304,
			outgoing_cltv_value: 0xffffffff,
			custom_tlvs: vec![],
		};
		let encoded_value = outbound_msg.encode();
		let target_value = hex::decode("3602080badf00d010203040404ffffffff082442424242424242424242424242424242424242424242424242424242424242421badca1f").unwrap();
		assert_eq!(encoded_value, target_value);

		let inbound_msg = Readable::read(&mut Cursor::new(&target_value[..])).unwrap();
		if let msgs::InboundOnionPayload::Receive {
			payment_data: Some(FinalOnionHopData {
				payment_secret,
				total_msat: 0x1badca1f
			}),
			amt_msat, outgoing_cltv_value,
			payment_metadata: None,
			keysend_preimage: None,
			custom_tlvs,
		} = inbound_msg  {
			assert_eq!(payment_secret, expected_payment_secret);
			assert_eq!(amt_msat, 0x0badf00d01020304);
			assert_eq!(outgoing_cltv_value, 0xffffffff);
			assert_eq!(custom_tlvs, vec![]);
		} else { panic!(); }
	}

	#[test]
	fn encoding_final_onion_hop_data_with_bad_custom_tlvs() {
		// If custom TLVs have type number within the range reserved for protocol, treat them as if
		// they're unknown
		let bad_type_range_tlvs = vec![
			((1 << 16) - 4, vec![42]),
			((1 << 16) - 2, vec![42; 32]),
		];
		let mut msg = msgs::OutboundOnionPayload::Receive {
			payment_data: None,
			payment_metadata: None,
			keysend_preimage: None,
			custom_tlvs: bad_type_range_tlvs,
			amt_msat: 0x0badf00d01020304,
			outgoing_cltv_value: 0xffffffff,
		};
		let encoded_value = msg.encode();
		assert!(msgs::InboundOnionPayload::read(&mut Cursor::new(&encoded_value[..])).is_err());
		let good_type_range_tlvs = vec![
			((1 << 16) - 3, vec![42]),
			((1 << 16) - 1, vec![42; 32]),
		];
		if let msgs::OutboundOnionPayload::Receive { ref mut custom_tlvs, .. } = msg {
			*custom_tlvs = good_type_range_tlvs.clone();
		}
		let encoded_value = msg.encode();
		let inbound_msg = Readable::read(&mut Cursor::new(&encoded_value[..])).unwrap();
		match inbound_msg {
			msgs::InboundOnionPayload::Receive { custom_tlvs, .. } => assert!(custom_tlvs.is_empty()),
			_ => panic!(),
		}
	}

	#[test]
	fn encoding_final_onion_hop_data_with_custom_tlvs() {
		let expected_custom_tlvs = vec![
			(5482373483, vec![0x12, 0x34]),
			(5482373487, vec![0x42u8; 8]),
		];
		let msg = msgs::OutboundOnionPayload::Receive {
			payment_data: None,
			payment_metadata: None,
			keysend_preimage: None,
			custom_tlvs: expected_custom_tlvs.clone(),
			amt_msat: 0x0badf00d01020304,
			outgoing_cltv_value: 0xffffffff,
		};
		let encoded_value = msg.encode();
		let target_value = hex::decode("2e02080badf00d010203040404ffffffffff0000000146c6616b021234ff0000000146c6616f084242424242424242").unwrap();
		assert_eq!(encoded_value, target_value);
		let inbound_msg: msgs::InboundOnionPayload = Readable::read(&mut Cursor::new(&target_value[..])).unwrap();
		if let msgs::InboundOnionPayload::Receive {
			payment_data: None,
			payment_metadata: None,
			keysend_preimage: None,
			custom_tlvs,
			amt_msat,
			outgoing_cltv_value,
			..
		} = inbound_msg {
			assert_eq!(custom_tlvs, expected_custom_tlvs);
			assert_eq!(amt_msat, 0x0badf00d01020304);
			assert_eq!(outgoing_cltv_value, 0xffffffff);
		} else { panic!(); }
	}

	#[test]
	fn query_channel_range_end_blocknum() {
		let tests: Vec<(u32, u32, u32)> = vec![
			(10000, 1500, 11500),
			(0, 0xffffffff, 0xffffffff),
			(1, 0xffffffff, 0xffffffff),
		];

		for (first_blocknum, number_of_blocks, expected) in tests.into_iter() {
			let sut = msgs::QueryChannelRange {
				chain_hash: BlockHash::from_hex("06226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f").unwrap(),
				first_blocknum,
				number_of_blocks,
			};
			assert_eq!(sut.end_blocknum(), expected);
		}
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
			sync_complete: true,
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
			assert_eq!(reply_channel_range.sync_complete, true);
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

	#[test]
	fn decode_onion_hop_data_len_as_bigsize() {
		// Tests that we can decode an onion payload that is >253 bytes.
		// Previously, receiving a payload of this size could've caused us to fail to decode a valid
		// payload, because we were decoding the length (a BigSize, big-endian) as a VarInt
		// (little-endian).

		// Encode a test onion payload with a big custom TLV such that it's >253 bytes, forcing the
		// payload length to be encoded over multiple bytes rather than a single u8.
		let big_payload = encode_big_payload().unwrap();
		let mut rd = Cursor::new(&big_payload[..]);
		<msgs::InboundOnionPayload as Readable>::read(&mut rd).unwrap();
	}
	// see above test, needs to be a separate method for use of the serialization macros.
	fn encode_big_payload() -> Result<Vec<u8>, io::Error> {
		use crate::util::ser::HighZeroBytesDroppedBigSize;
		let payload = msgs::OutboundOnionPayload::Forward {
			short_channel_id: 0xdeadbeef1bad1dea,
			amt_to_forward: 1000,
			outgoing_cltv_value: 0xffffffff,
		};
		let mut encoded_payload = Vec::new();
		let test_bytes = vec![42u8; 1000];
		if let msgs::OutboundOnionPayload::Forward { short_channel_id, amt_to_forward, outgoing_cltv_value } = payload {
			_encode_varint_length_prefixed_tlv!(&mut encoded_payload, {
				(1, test_bytes, required_vec),
				(2, HighZeroBytesDroppedBigSize(amt_to_forward), required),
				(4, HighZeroBytesDroppedBigSize(outgoing_cltv_value), required),
				(6, short_channel_id, required)
			});
		}
		Ok(encoded_payload)
	}

	#[test]
	#[cfg(feature = "std")]
	fn test_net_address_from_str() {
		assert_eq!(NetAddress::IPv4 {
			addr: Ipv4Addr::new(127, 0, 0, 1).octets(),
			port: 1234,
		}, NetAddress::from_str("127.0.0.1:1234").unwrap());

		assert_eq!(NetAddress::IPv6 {
			addr: Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1).octets(),
			port: 1234,
		}, NetAddress::from_str("[0:0:0:0:0:0:0:1]:1234").unwrap());
		assert_eq!(
			NetAddress::Hostname {
				hostname: Hostname::try_from("lightning-node.mydomain.com".to_string()).unwrap(),
				port: 1234,
			}, NetAddress::from_str("lightning-node.mydomain.com:1234").unwrap());
		assert_eq!(
			NetAddress::Hostname {
				hostname: Hostname::try_from("example.com".to_string()).unwrap(),
				port: 1234,
			}, NetAddress::from_str("example.com:1234").unwrap());
		assert_eq!(NetAddress::OnionV3 {
			ed25519_pubkey: [37, 24, 75, 5, 25, 73, 117, 194, 139, 102, 182, 107, 4, 105, 247, 246, 85,
			111, 177, 172, 49, 137, 167, 155, 64, 221, 163, 47, 31, 33, 71, 3],
			checksum: 48326,
			version: 121,
			port: 1234
		}, NetAddress::from_str("pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion:1234").unwrap());
		assert_eq!(Err(NetAddressParseError::InvalidOnionV3), NetAddress::from_str("pg6mmjiyjmcrsslvykfwnntlaru7p5svn6.onion:1234"));
		assert_eq!(Err(NetAddressParseError::InvalidInput), NetAddress::from_str("127.0.0.1@1234"));
		assert_eq!(Err(NetAddressParseError::InvalidInput), "".parse::<NetAddress>());
		assert!(NetAddress::from_str("pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion.onion:9735:94").is_err());
		assert!(NetAddress::from_str("wrong$%#.com:1234").is_err());
		assert_eq!(Err(NetAddressParseError::InvalidPort), NetAddress::from_str("example.com:wrong"));
		assert!("localhost".parse::<NetAddress>().is_err());
		assert!("localhost:invalid-port".parse::<NetAddress>().is_err());
		assert!( "invalid-onion-v3-hostname.onion:8080".parse::<NetAddress>().is_err());
		assert!("b32.example.onion:invalid-port".parse::<NetAddress>().is_err());
		assert!("invalid-address".parse::<NetAddress>().is_err());
		assert!(NetAddress::from_str("pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion.onion:1234").is_err());
	}
}
