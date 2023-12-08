// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! LDK sends, receives, and forwards onion messages via the [`OnionMessenger`]. See its docs for
//! more information.

use bitcoin::hashes::{Hash, HashEngine};
use bitcoin::hashes::hmac::{Hmac, HmacEngine};
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::secp256k1::{self, PublicKey, Scalar, Secp256k1, SecretKey};

use crate::blinded_path::BlindedPath;
use crate::blinded_path::message::{advance_path_by_one, ForwardTlvs, ReceiveTlvs};
use crate::blinded_path::utils;
use crate::sign::{EntropySource, KeysManager, NodeSigner, Recipient};
#[cfg(not(c_bindings))]
use crate::ln::channelmanager::{SimpleArcChannelManager, SimpleRefChannelManager};
use crate::ln::features::{InitFeatures, NodeFeatures};
use crate::ln::msgs::{self, OnionMessage, OnionMessageHandler};
use crate::ln::onion_utils;
use crate::ln::peer_handler::IgnoringMessageHandler;
pub use super::packet::OnionMessageContents;
use super::packet::ParsedOnionMessageContents;
use super::offers::OffersMessageHandler;
use super::packet::{BIG_PACKET_HOP_DATA_LEN, ForwardControlTlvs, Packet, Payload, ReceiveControlTlvs, SMALL_PACKET_HOP_DATA_LEN};
use crate::util::logger::Logger;
use crate::util::ser::Writeable;

use core::fmt;
use core::ops::Deref;
use crate::io;
use crate::sync::{Arc, Mutex};
use crate::prelude::*;

/// A sender, receiver and forwarder of [`OnionMessage`]s.
///
/// # Handling Messages
///
/// `OnionMessenger` implements [`OnionMessageHandler`], making it responsible for either forwarding
/// messages to peers or delegating to the appropriate handler for the message type. Currently, the
/// available handlers are:
/// * [`OffersMessageHandler`], for responding to [`InvoiceRequest`]s and paying [`Bolt12Invoice`]s
/// * [`CustomOnionMessageHandler`], for handling user-defined message types
///
/// # Sending Messages
///
/// [`OnionMessage`]s are sent initially using [`OnionMessenger::send_onion_message`]. When handling
/// a message, the matched handler may return a response message which `OnionMessenger` will send
/// on its behalf.
///
/// # Example
///
/// ```
/// # extern crate bitcoin;
/// # use bitcoin::hashes::_export::_core::time::Duration;
/// # use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
/// # use lightning::blinded_path::BlindedPath;
/// # use lightning::sign::KeysManager;
/// # use lightning::ln::peer_handler::IgnoringMessageHandler;
/// # use lightning::onion_message::{OnionMessageContents, Destination, MessageRouter, OnionMessagePath, OnionMessenger};
/// # use lightning::util::logger::{Logger, Record};
/// # use lightning::util::ser::{Writeable, Writer};
/// # use lightning::io;
/// # use std::sync::Arc;
/// # struct FakeLogger;
/// # impl Logger for FakeLogger {
/// #     fn log(&self, record: &Record) { unimplemented!() }
/// # }
/// # struct FakeMessageRouter {}
/// # impl MessageRouter for FakeMessageRouter {
/// #     fn find_path(&self, sender: PublicKey, peers: Vec<PublicKey>, destination: Destination) -> Result<OnionMessagePath, ()> {
/// #         unimplemented!()
/// #     }
/// # }
/// # let seed = [42u8; 32];
/// # let time = Duration::from_secs(123456);
/// # let keys_manager = KeysManager::new(&seed, time.as_secs(), time.subsec_nanos());
/// # let logger = Arc::new(FakeLogger {});
/// # let node_secret = SecretKey::from_slice(&hex::decode("0101010101010101010101010101010101010101010101010101010101010101").unwrap()[..]).unwrap();
/// # let secp_ctx = Secp256k1::new();
/// # let hop_node_id1 = PublicKey::from_secret_key(&secp_ctx, &node_secret);
/// # let (hop_node_id2, hop_node_id3, hop_node_id4) = (hop_node_id1, hop_node_id1, hop_node_id1);
/// # let destination_node_id = hop_node_id1;
/// # let message_router = Arc::new(FakeMessageRouter {});
/// # let custom_message_handler = IgnoringMessageHandler {};
/// # let offers_message_handler = IgnoringMessageHandler {};
/// // Create the onion messenger. This must use the same `keys_manager` as is passed to your
/// // ChannelManager.
/// let onion_messenger = OnionMessenger::new(
///     &keys_manager, &keys_manager, logger, message_router, &offers_message_handler,
///     &custom_message_handler
/// );
///
/// # struct YourCustomMessage {}
/// impl Writeable for YourCustomMessage {
/// 	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
/// 		# Ok(())
/// 		// Write your custom onion message to `w`
/// 	}
/// }
/// impl OnionMessageContents for YourCustomMessage {
/// 	fn tlv_type(&self) -> u64 {
/// 		# let your_custom_message_type = 42;
/// 		your_custom_message_type
/// 	}
/// }
/// // Send a custom onion message to a node id.
/// let path = OnionMessagePath {
/// 	intermediate_nodes: vec![hop_node_id1, hop_node_id2],
/// 	destination: Destination::Node(destination_node_id),
/// };
/// let reply_path = None;
/// # let message = YourCustomMessage {};
/// onion_messenger.send_onion_message(path, message, reply_path);
///
/// // Create a blinded path to yourself, for someone to send an onion message to.
/// # let your_node_id = hop_node_id1;
/// let hops = [hop_node_id3, hop_node_id4, your_node_id];
/// let blinded_path = BlindedPath::new_for_message(&hops, &keys_manager, &secp_ctx).unwrap();
///
/// // Send a custom onion message to a blinded path.
/// let path = OnionMessagePath {
/// 	intermediate_nodes: vec![hop_node_id1, hop_node_id2],
/// 	destination: Destination::BlindedPath(blinded_path),
/// };
/// let reply_path = None;
/// # let message = YourCustomMessage {};
/// onion_messenger.send_onion_message(path, message, reply_path);
/// ```
///
/// [`InvoiceRequest`]: crate::offers::invoice_request::InvoiceRequest
/// [`Bolt12Invoice`]: crate::offers::invoice::Bolt12Invoice
pub struct OnionMessenger<ES: Deref, NS: Deref, L: Deref, MR: Deref, OMH: Deref, CMH: Deref>
where
	ES::Target: EntropySource,
	NS::Target: NodeSigner,
	L::Target: Logger,
	MR::Target: MessageRouter,
	OMH::Target: OffersMessageHandler,
	CMH:: Target: CustomOnionMessageHandler,
{
	entropy_source: ES,
	node_signer: NS,
	logger: L,
	pending_messages: Mutex<HashMap<PublicKey, VecDeque<OnionMessage>>>,
	secp_ctx: Secp256k1<secp256k1::All>,
	message_router: MR,
	offers_handler: OMH,
	custom_handler: CMH,
}

/// An [`OnionMessage`] for [`OnionMessenger`] to send.
///
/// These are obtained when released from [`OnionMessenger`]'s handlers after which they are
/// enqueued for sending.
#[cfg(not(c_bindings))]
pub struct PendingOnionMessage<T: OnionMessageContents> {
	/// The message contents to send in an [`OnionMessage`].
	pub contents: T,

	/// The destination of the message.
	pub destination: Destination,

	/// A reply path to include in the [`OnionMessage`] for a response.
	pub reply_path: Option<BlindedPath>,
}

#[cfg(c_bindings)]
/// An [`OnionMessage`] for [`OnionMessenger`] to send.
///
/// These are obtained when released from [`OnionMessenger`]'s handlers after which they are
/// enqueued for sending.
pub type PendingOnionMessage<T: OnionMessageContents> = (T, Destination, Option<BlindedPath>);

pub(crate) fn new_pending_onion_message<T: OnionMessageContents>(
	contents: T, destination: Destination, reply_path: Option<BlindedPath>
) -> PendingOnionMessage<T> {
	#[cfg(not(c_bindings))]
	return PendingOnionMessage { contents, destination, reply_path };
	#[cfg(c_bindings)]
	return (contents, destination, reply_path);
}

/// A trait defining behavior for routing an [`OnionMessage`].
pub trait MessageRouter {
	/// Returns a route for sending an [`OnionMessage`] to the given [`Destination`].
	fn find_path(
		&self, sender: PublicKey, peers: Vec<PublicKey>, destination: Destination
	) -> Result<OnionMessagePath, ()>;
}

/// A [`MessageRouter`] that can only route to a directly connected [`Destination`].
pub struct DefaultMessageRouter;

impl MessageRouter for DefaultMessageRouter {
	fn find_path(
		&self, _sender: PublicKey, peers: Vec<PublicKey>, destination: Destination
	) -> Result<OnionMessagePath, ()> {
		if peers.contains(&destination.first_node()) {
			Ok(OnionMessagePath { intermediate_nodes: vec![], destination })
		} else {
			Err(())
		}
	}
}

/// A path for sending an [`OnionMessage`].
#[derive(Clone)]
pub struct OnionMessagePath {
	/// Nodes on the path between the sender and the destination.
	pub intermediate_nodes: Vec<PublicKey>,

	/// The recipient of the message.
	pub destination: Destination,
}

/// The destination of an onion message.
#[derive(Clone)]
pub enum Destination {
	/// We're sending this onion message to a node.
	Node(PublicKey),
	/// We're sending this onion message to a blinded path.
	BlindedPath(BlindedPath),
}

impl Destination {
	pub(super) fn num_hops(&self) -> usize {
		match self {
			Destination::Node(_) => 1,
			Destination::BlindedPath(BlindedPath { blinded_hops, .. }) => blinded_hops.len(),
		}
	}

	fn first_node(&self) -> PublicKey {
		match self {
			Destination::Node(node_id) => *node_id,
			Destination::BlindedPath(BlindedPath { introduction_node_id: node_id, .. }) => *node_id,
		}
	}
}

/// Errors that may occur when [sending an onion message].
///
/// [sending an onion message]: OnionMessenger::send_onion_message
#[derive(Debug, PartialEq, Eq)]
pub enum SendError {
	/// Errored computing onion message packet keys.
	Secp256k1(secp256k1::Error),
	/// Because implementations such as Eclair will drop onion messages where the message packet
	/// exceeds 32834 bytes, we refuse to send messages where the packet exceeds this size.
	TooBigPacket,
	/// The provided [`Destination`] was an invalid [`BlindedPath`] due to not having any blinded
	/// hops.
	TooFewBlindedHops,
	/// Our next-hop peer was offline or does not support onion message forwarding.
	InvalidFirstHop,
	/// Onion message contents must have a TLV type >= 64.
	InvalidMessage,
	/// Our next-hop peer's buffer was full or our total outbound buffer was full.
	BufferFull,
	/// Failed to retrieve our node id from the provided [`NodeSigner`].
	///
	/// [`NodeSigner`]: crate::sign::NodeSigner
	GetNodeIdFailed,
	/// We attempted to send to a blinded path where we are the introduction node, and failed to
	/// advance the blinded path to make the second hop the new introduction node. Either
	/// [`NodeSigner::ecdh`] failed, we failed to tweak the current blinding point to get the
	/// new blinding point, or we were attempting to send to ourselves.
	BlindedPathAdvanceFailed,
}

/// Handler for custom onion messages. If you are using [`SimpleArcOnionMessenger`],
/// [`SimpleRefOnionMessenger`], or prefer to ignore inbound custom onion messages,
/// [`IgnoringMessageHandler`] must be provided to [`OnionMessenger::new`]. Otherwise, a custom
/// implementation of this trait must be provided, with [`CustomMessage`] specifying the supported
/// message types.
///
/// See [`OnionMessenger`] for example usage.
///
/// [`IgnoringMessageHandler`]: crate::ln::peer_handler::IgnoringMessageHandler
/// [`CustomMessage`]: Self::CustomMessage
pub trait CustomOnionMessageHandler {
	/// The message known to the handler. To support multiple message types, you may want to make this
	/// an enum with a variant for each supported message.
	type CustomMessage: OnionMessageContents;

	/// Called with the custom message that was received, returning a response to send, if any.
	///
	/// The returned [`Self::CustomMessage`], if any, is enqueued to be sent by [`OnionMessenger`].
	fn handle_custom_message(&self, msg: Self::CustomMessage) -> Option<Self::CustomMessage>;

	/// Read a custom message of type `message_type` from `buffer`, returning `Ok(None)` if the
	/// message type is unknown.
	fn read_custom_message<R: io::Read>(&self, message_type: u64, buffer: &mut R) -> Result<Option<Self::CustomMessage>, msgs::DecodeError>;

	/// Releases any [`Self::CustomMessage`]s that need to be sent.
	///
	/// Typically, this is used for messages initiating a message flow rather than in response to
	/// another message. The latter should use the return value of [`Self::handle_custom_message`].
	#[cfg(not(c_bindings))]
	fn release_pending_custom_messages(&self) -> Vec<PendingOnionMessage<Self::CustomMessage>>;

	/// Releases any [`Self::CustomMessage`]s that need to be sent.
	///
	/// Typically, this is used for messages initiating a message flow rather than in response to
	/// another message. The latter should use the return value of [`Self::handle_custom_message`].
	#[cfg(c_bindings)]
	fn release_pending_custom_messages(&self) -> Vec<(Self::CustomMessage, Destination, Option<BlindedPath>)>;
}

/// A processed incoming onion message, containing either a Forward (another onion message)
/// or a Receive payload with decrypted contents.
pub enum PeeledOnion<T: OnionMessageContents> {
	/// Forwarded onion, with the next node id and a new onion
	Forward(PublicKey, OnionMessage),
	/// Received onion message, with decrypted contents, path_id, and reply path
	Receive(ParsedOnionMessageContents<T>, Option<[u8; 32]>, Option<BlindedPath>)
}

/// Creates an [`OnionMessage`] with the given `contents` for sending to the destination of
/// `path`.
///
/// Returns both the node id of the peer to send the message to and the message itself.
pub fn create_onion_message<ES: Deref, NS: Deref, T: OnionMessageContents>(
	entropy_source: &ES, node_signer: &NS, secp_ctx: &Secp256k1<secp256k1::All>,
	path: OnionMessagePath, contents: T, reply_path: Option<BlindedPath>,
) -> Result<(PublicKey, OnionMessage), SendError>
where
	ES::Target: EntropySource,
	NS::Target: NodeSigner,
{
	let OnionMessagePath { intermediate_nodes, mut destination } = path;
	if let Destination::BlindedPath(BlindedPath { ref blinded_hops, .. }) = destination {
		if blinded_hops.is_empty() {
			return Err(SendError::TooFewBlindedHops);
		}
	}

	if contents.tlv_type() < 64 { return Err(SendError::InvalidMessage) }

	// If we are sending straight to a blinded path and we are the introduction node, we need to
	// advance the blinded path by 1 hop so the second hop is the new introduction node.
	if intermediate_nodes.len() == 0 {
		if let Destination::BlindedPath(ref mut blinded_path) = destination {
			let our_node_id = node_signer.get_node_id(Recipient::Node)
				.map_err(|()| SendError::GetNodeIdFailed)?;
			if blinded_path.introduction_node_id == our_node_id {
				advance_path_by_one(blinded_path, node_signer, &secp_ctx)
					.map_err(|()| SendError::BlindedPathAdvanceFailed)?;
			}
		}
	}

	let blinding_secret_bytes = entropy_source.get_secure_random_bytes();
	let blinding_secret = SecretKey::from_slice(&blinding_secret_bytes[..]).expect("RNG is busted");
	let (first_node_id, blinding_point) = if let Some(first_node_id) = intermediate_nodes.first() {
		(*first_node_id, PublicKey::from_secret_key(&secp_ctx, &blinding_secret))
	} else {
		match destination {
			Destination::Node(pk) => (pk, PublicKey::from_secret_key(&secp_ctx, &blinding_secret)),
			Destination::BlindedPath(BlindedPath { introduction_node_id, blinding_point, .. }) =>
				(introduction_node_id, blinding_point),
		}
	};
	let (packet_payloads, packet_keys) = packet_payloads_and_keys(
		&secp_ctx, &intermediate_nodes, destination, contents, reply_path, &blinding_secret)
		.map_err(|e| SendError::Secp256k1(e))?;

	let prng_seed = entropy_source.get_secure_random_bytes();
	let onion_routing_packet = construct_onion_message_packet(
		packet_payloads, packet_keys, prng_seed).map_err(|()| SendError::TooBigPacket)?;

	Ok((first_node_id, OnionMessage {
		blinding_point,
		onion_routing_packet
	}))
}

/// Decode one layer of an incoming [`OnionMessage`].
///
/// Returns either the next layer of the onion for forwarding or the decrypted content for the
/// receiver.
pub fn peel_onion_message<NS: Deref, L: Deref, CMH: Deref>(
	msg: &OnionMessage, secp_ctx: &Secp256k1<secp256k1::All>, node_signer: NS, logger: L,
	custom_handler: CMH,
) -> Result<PeeledOnion<<<CMH>::Target as CustomOnionMessageHandler>::CustomMessage>, ()>
where
	NS::Target: NodeSigner,
	L::Target: Logger,
	CMH::Target: CustomOnionMessageHandler,
{
	let control_tlvs_ss = match node_signer.ecdh(Recipient::Node, &msg.blinding_point, None) {
		Ok(ss) => ss,
		Err(e) =>  {
			log_error!(logger, "Failed to retrieve node secret: {:?}", e);
			return Err(());
		}
	};
	let onion_decode_ss = {
		let blinding_factor = {
			let mut hmac = HmacEngine::<Sha256>::new(b"blinded_node_id");
			hmac.input(control_tlvs_ss.as_ref());
			Hmac::from_engine(hmac).into_inner()
		};
		match node_signer.ecdh(Recipient::Node, &msg.onion_routing_packet.public_key,
			Some(&Scalar::from_be_bytes(blinding_factor).unwrap()))
		{
			Ok(ss) => ss.secret_bytes(),
			Err(()) => {
				log_trace!(logger, "Failed to compute onion packet shared secret");
				return Err(());
			}
		}
	};
	match onion_utils::decode_next_untagged_hop(
		onion_decode_ss, &msg.onion_routing_packet.hop_data[..], msg.onion_routing_packet.hmac,
		(control_tlvs_ss, custom_handler.deref(), logger.deref())
	) {
		Ok((Payload::Receive::<ParsedOnionMessageContents<<<CMH as Deref>::Target as CustomOnionMessageHandler>::CustomMessage>> {
			message, control_tlvs: ReceiveControlTlvs::Unblinded(ReceiveTlvs { path_id }), reply_path,
		}, None)) => {
			Ok(PeeledOnion::Receive(message, path_id, reply_path))
		},
		Ok((Payload::Forward(ForwardControlTlvs::Unblinded(ForwardTlvs {
			next_node_id, next_blinding_override
		})), Some((next_hop_hmac, new_packet_bytes)))) => {
			// TODO: we need to check whether `next_node_id` is our node, in which case this is a dummy
			// blinded hop and this onion message is destined for us. In this situation, we should keep
			// unwrapping the onion layers to get to the final payload. Since we don't have the option
			// of creating blinded paths with dummy hops currently, we should be ok to not handle this
			// for now.
			let new_pubkey = match onion_utils::next_hop_pubkey(&secp_ctx, msg.onion_routing_packet.public_key, &onion_decode_ss) {
				Ok(pk) => pk,
				Err(e) => {
					log_trace!(logger, "Failed to compute next hop packet pubkey: {}", e);
					return Err(())
				}
			};
			let outgoing_packet = Packet {
				version: 0,
				public_key: new_pubkey,
				hop_data: new_packet_bytes,
				hmac: next_hop_hmac,
			};
			let onion_message = OnionMessage {
				blinding_point: match next_blinding_override {
					Some(blinding_point) => blinding_point,
					None => {
						match onion_utils::next_hop_pubkey(
							&secp_ctx, msg.blinding_point, control_tlvs_ss.as_ref()
						) {
							Ok(bp) => bp,
							Err(e) => {
								log_trace!(logger, "Failed to compute next blinding point: {}", e);
								return Err(())
							}
						}
					}
				},
				onion_routing_packet: outgoing_packet,
			};

			Ok(PeeledOnion::Forward(next_node_id, onion_message))
		},
		Err(e) => {
			log_trace!(logger, "Errored decoding onion message packet: {:?}", e);
			Err(())
		},
		_ => {
			log_trace!(logger, "Received bogus onion message packet, either the sender encoded a final hop as a forwarding hop or vice versa");
			Err(())
		},
	}
}

impl<ES: Deref, NS: Deref, L: Deref, MR: Deref, OMH: Deref, CMH: Deref>
OnionMessenger<ES, NS, L, MR, OMH, CMH>
where
	ES::Target: EntropySource,
	NS::Target: NodeSigner,
	L::Target: Logger,
	MR::Target: MessageRouter,
	OMH::Target: OffersMessageHandler,
	CMH::Target: CustomOnionMessageHandler,
{
	/// Constructs a new `OnionMessenger` to send, forward, and delegate received onion messages to
	/// their respective handlers.
	pub fn new(
		entropy_source: ES, node_signer: NS, logger: L, message_router: MR, offers_handler: OMH,
		custom_handler: CMH
	) -> Self {
		let mut secp_ctx = Secp256k1::new();
		secp_ctx.seeded_randomize(&entropy_source.get_secure_random_bytes());
		OnionMessenger {
			entropy_source,
			node_signer,
			pending_messages: Mutex::new(HashMap::new()),
			secp_ctx,
			logger,
			message_router,
			offers_handler,
			custom_handler,
		}
	}

	/// Sends an [`OnionMessage`] with the given `contents` for sending to the destination of
	/// `path`.
	///
	/// See [`OnionMessenger`] for example usage.
	pub fn send_onion_message<T: OnionMessageContents>(
		&self, path: OnionMessagePath, contents: T, reply_path: Option<BlindedPath>
	) -> Result<(), SendError> {
		let (first_node_id, onion_msg) = create_onion_message(
			&self.entropy_source, &self.node_signer, &self.secp_ctx, path, contents, reply_path
		)?;

		let mut pending_per_peer_msgs = self.pending_messages.lock().unwrap();
		if outbound_buffer_full(&first_node_id, &pending_per_peer_msgs) { return Err(SendError::BufferFull) }
		match pending_per_peer_msgs.entry(first_node_id) {
			hash_map::Entry::Vacant(_) => Err(SendError::InvalidFirstHop),
			hash_map::Entry::Occupied(mut e) => {
				e.get_mut().push_back(onion_msg);
				Ok(())
			}
		}
	}

	fn handle_onion_message_response<T: OnionMessageContents>(
		&self, response: Option<T>, reply_path: Option<BlindedPath>, log_suffix: fmt::Arguments
	) {
		if let Some(response) = response {
			match reply_path {
				Some(reply_path) => {
					self.find_path_and_enqueue_onion_message(
						response, Destination::BlindedPath(reply_path), None, log_suffix
					);
				},
				None => {
					log_trace!(self.logger, "Missing reply path {}", log_suffix);
				},
			}
		}
	}

	fn find_path_and_enqueue_onion_message<T: OnionMessageContents>(
		&self, contents: T, destination: Destination, reply_path: Option<BlindedPath>,
		log_suffix: fmt::Arguments
	) {
		let sender = match self.node_signer.get_node_id(Recipient::Node) {
			Ok(node_id) => node_id,
			Err(_) => {
				log_warn!(self.logger, "Unable to retrieve node id {}", log_suffix);
				return;
			}
		};

		let peers = self.pending_messages.lock().unwrap().keys().copied().collect();
		let path = match self.message_router.find_path(sender, peers, destination) {
			Ok(path) => path,
			Err(()) => {
				log_trace!(self.logger, "Failed to find path {}", log_suffix);
				return;
			},
		};

		log_trace!(self.logger, "Sending onion message {}", log_suffix);

		if let Err(e) = self.send_onion_message(path, contents, reply_path) {
			log_trace!(self.logger, "Failed sending onion message {}: {:?}", log_suffix, e);
			return;
		}
	}

	#[cfg(test)]
	pub(super) fn release_pending_msgs(&self) -> HashMap<PublicKey, VecDeque<OnionMessage>> {
		let mut pending_msgs = self.pending_messages.lock().unwrap();
		let mut msgs = HashMap::new();
		// We don't want to disconnect the peers by removing them entirely from the original map, so we
		// swap the pending message buffers individually.
		for (peer_node_id, pending_messages) in &mut *pending_msgs {
			msgs.insert(*peer_node_id, core::mem::take(pending_messages));
		}
		msgs
	}
}

fn outbound_buffer_full(peer_node_id: &PublicKey, buffer: &HashMap<PublicKey, VecDeque<OnionMessage>>) -> bool {
	const MAX_TOTAL_BUFFER_SIZE: usize = (1 << 20) * 128;
	const MAX_PER_PEER_BUFFER_SIZE: usize = (1 << 10) * 256;
	let mut total_buffered_bytes = 0;
	let mut peer_buffered_bytes = 0;
	for (pk, peer_buf) in buffer {
		for om in peer_buf {
			let om_len = om.serialized_length();
			if pk == peer_node_id {
				peer_buffered_bytes += om_len;
			}
			total_buffered_bytes += om_len;

			if total_buffered_bytes >= MAX_TOTAL_BUFFER_SIZE ||
				peer_buffered_bytes >= MAX_PER_PEER_BUFFER_SIZE
			{
				return true
			}
		}
	}
	false
}

impl<ES: Deref, NS: Deref, L: Deref, MR: Deref, OMH: Deref, CMH: Deref> OnionMessageHandler
for OnionMessenger<ES, NS, L, MR, OMH, CMH>
where
	ES::Target: EntropySource,
	NS::Target: NodeSigner,
	L::Target: Logger,
	MR::Target: MessageRouter,
	OMH::Target: OffersMessageHandler,
	CMH::Target: CustomOnionMessageHandler,
{
	fn handle_onion_message(&self, _peer_node_id: &PublicKey, msg: &OnionMessage) {
		match peel_onion_message(
			msg, &self.secp_ctx, &*self.node_signer, &*self.logger, &*self.custom_handler
		) {
			Ok(PeeledOnion::Receive(message, path_id, reply_path)) => {
				log_trace!(self.logger,
					"Received an onion message with path_id {:02x?} and {} reply_path",
						path_id, if reply_path.is_some() { "a" } else { "no" });

				match message {
					ParsedOnionMessageContents::Offers(msg) => {
						let response = self.offers_handler.handle_message(msg);
						self.handle_onion_message_response(
							response, reply_path, format_args!(
								"when responding to Offers onion message with path_id {:02x?}",
								path_id
							)
						);
					},
					ParsedOnionMessageContents::Custom(msg) => {
						let response = self.custom_handler.handle_custom_message(msg);
						self.handle_onion_message_response(
							response, reply_path, format_args!(
								"when responding to Custom onion message with path_id {:02x?}",
								path_id
							)
						);
					},
				}
			},
			Ok(PeeledOnion::Forward(next_node_id, onion_message)) => {
				let mut pending_per_peer_msgs = self.pending_messages.lock().unwrap();
				if outbound_buffer_full(&next_node_id, &pending_per_peer_msgs) {
					log_trace!(self.logger, "Dropping forwarded onion message to peer {:?}: outbound buffer full", next_node_id);
					return
				}

				#[cfg(fuzzing)]
				pending_per_peer_msgs.entry(next_node_id).or_insert_with(VecDeque::new);

				match pending_per_peer_msgs.entry(next_node_id) {
					hash_map::Entry::Vacant(_) => {
						log_trace!(self.logger, "Dropping forwarded onion message to disconnected peer {:?}", next_node_id);
						return
					},
					hash_map::Entry::Occupied(mut e) => {
						e.get_mut().push_back(onion_message);
						log_trace!(self.logger, "Forwarding an onion message to peer {}", next_node_id);
					}
				}
			},
			Err(e) => {
				log_error!(self.logger, "Failed to process onion message {:?}", e);
			}
		}
	}

	fn peer_connected(&self, their_node_id: &PublicKey, init: &msgs::Init, _inbound: bool) -> Result<(), ()> {
		if init.features.supports_onion_messages() {
			let mut peers = self.pending_messages.lock().unwrap();
			peers.insert(their_node_id.clone(), VecDeque::new());
		}
		Ok(())
	}

	fn peer_disconnected(&self, their_node_id: &PublicKey) {
		let mut pending_msgs = self.pending_messages.lock().unwrap();
		pending_msgs.remove(their_node_id);
	}

	fn provided_node_features(&self) -> NodeFeatures {
		let mut features = NodeFeatures::empty();
		features.set_onion_messages_optional();
		features
	}

	fn provided_init_features(&self, _their_node_id: &PublicKey) -> InitFeatures {
		let mut features = InitFeatures::empty();
		features.set_onion_messages_optional();
		features
	}

	// Before returning any messages to send for the peer, this method will see if any messages were
	// enqueued in the handler by users, find a path to the corresponding blinded path's introduction
	// node, and then enqueue the message for sending to the first peer in the full path.
	fn next_onion_message_for_peer(&self, peer_node_id: PublicKey) -> Option<OnionMessage> {
		// Enqueue any initiating `OffersMessage`s to send.
		for message in self.offers_handler.release_pending_messages() {
			#[cfg(not(c_bindings))]
			let PendingOnionMessage { contents, destination, reply_path } = message;
			#[cfg(c_bindings)]
			let (contents, destination, reply_path) = message;
			self.find_path_and_enqueue_onion_message(
				contents, destination, reply_path, format_args!("when sending OffersMessage")
			);
		}

		// Enqueue any initiating `CustomMessage`s to send.
		for message in self.custom_handler.release_pending_custom_messages() {
			#[cfg(not(c_bindings))]
			let PendingOnionMessage { contents, destination, reply_path } = message;
			#[cfg(c_bindings)]
			let (contents, destination, reply_path) = message;
			self.find_path_and_enqueue_onion_message(
				contents, destination, reply_path, format_args!("when sending CustomMessage")
			);
		}

		let mut pending_msgs = self.pending_messages.lock().unwrap();
		if let Some(msgs) = pending_msgs.get_mut(&peer_node_id) {
			return msgs.pop_front()
		}
		None
	}
}

// TODO: parameterize the below Simple* types with OnionMessenger and handle the messages it
// produces
/// Useful for simplifying the parameters of [`SimpleArcChannelManager`] and
/// [`SimpleArcPeerManager`]. See their docs for more details.
///
/// This is not exported to bindings users as type aliases aren't supported in most languages.
///
/// [`SimpleArcChannelManager`]: crate::ln::channelmanager::SimpleArcChannelManager
/// [`SimpleArcPeerManager`]: crate::ln::peer_handler::SimpleArcPeerManager
#[cfg(not(c_bindings))]
pub type SimpleArcOnionMessenger<M, T, F, L> = OnionMessenger<
	Arc<KeysManager>,
	Arc<KeysManager>,
	Arc<L>,
	Arc<DefaultMessageRouter>,
	Arc<SimpleArcChannelManager<M, T, F, L>>,
	IgnoringMessageHandler
>;

/// Useful for simplifying the parameters of [`SimpleRefChannelManager`] and
/// [`SimpleRefPeerManager`]. See their docs for more details.
///
/// This is not exported to bindings users as type aliases aren't supported in most languages.
///
/// [`SimpleRefChannelManager`]: crate::ln::channelmanager::SimpleRefChannelManager
/// [`SimpleRefPeerManager`]: crate::ln::peer_handler::SimpleRefPeerManager
#[cfg(not(c_bindings))]
pub type SimpleRefOnionMessenger<
	'a, 'b, 'c, 'd, 'e, 'f, 'g, 'h, 'i, 'j, M, T, F, L
> = OnionMessenger<
	&'a KeysManager,
	&'a KeysManager,
	&'b L,
	&'i DefaultMessageRouter,
	&'j SimpleRefChannelManager<'a, 'b, 'c, 'd, 'e, 'f, 'g, 'h, M, T, F, L>,
	IgnoringMessageHandler
>;

/// Construct onion packet payloads and keys for sending an onion message along the given
/// `unblinded_path` to the given `destination`.
fn packet_payloads_and_keys<T: OnionMessageContents, S: secp256k1::Signing + secp256k1::Verification>(
	secp_ctx: &Secp256k1<S>, unblinded_path: &[PublicKey], destination: Destination, message: T,
	mut reply_path: Option<BlindedPath>, session_priv: &SecretKey
) -> Result<(Vec<(Payload<T>, [u8; 32])>, Vec<onion_utils::OnionKeys>), secp256k1::Error> {
	let num_hops = unblinded_path.len() + destination.num_hops();
	let mut payloads = Vec::with_capacity(num_hops);
	let mut onion_packet_keys = Vec::with_capacity(num_hops);

	let (mut intro_node_id_blinding_pt, num_blinded_hops) = if let Destination::BlindedPath(BlindedPath {
		introduction_node_id, blinding_point, blinded_hops }) = &destination {
		(Some((*introduction_node_id, *blinding_point)), blinded_hops.len()) } else { (None, 0) };
	let num_unblinded_hops = num_hops - num_blinded_hops;

	let mut unblinded_path_idx = 0;
	let mut blinded_path_idx = 0;
	let mut prev_control_tlvs_ss = None;
	let mut final_control_tlvs = None;
	utils::construct_keys_callback(secp_ctx, unblinded_path.iter(), Some(destination), session_priv,
		|_, onion_packet_ss, ephemeral_pubkey, control_tlvs_ss, unblinded_pk_opt, enc_payload_opt| {
			if num_unblinded_hops != 0 && unblinded_path_idx < num_unblinded_hops {
				if let Some(ss) = prev_control_tlvs_ss.take() {
					payloads.push((Payload::Forward(ForwardControlTlvs::Unblinded(
						ForwardTlvs {
							next_node_id: unblinded_pk_opt.unwrap(),
							next_blinding_override: None,
						}
					)), ss));
				}
				prev_control_tlvs_ss = Some(control_tlvs_ss);
				unblinded_path_idx += 1;
			} else if let Some((intro_node_id, blinding_pt)) = intro_node_id_blinding_pt.take() {
				if let Some(control_tlvs_ss) = prev_control_tlvs_ss.take() {
					payloads.push((Payload::Forward(ForwardControlTlvs::Unblinded(ForwardTlvs {
						next_node_id: intro_node_id,
						next_blinding_override: Some(blinding_pt),
					})), control_tlvs_ss));
				}
			}
			if blinded_path_idx < num_blinded_hops.saturating_sub(1) && enc_payload_opt.is_some() {
				payloads.push((Payload::Forward(ForwardControlTlvs::Blinded(enc_payload_opt.unwrap())),
					control_tlvs_ss));
				blinded_path_idx += 1;
			} else if let Some(encrypted_payload) = enc_payload_opt {
				final_control_tlvs = Some(ReceiveControlTlvs::Blinded(encrypted_payload));
				prev_control_tlvs_ss = Some(control_tlvs_ss);
			}

			let (rho, mu) = onion_utils::gen_rho_mu_from_shared_secret(onion_packet_ss.as_ref());
			onion_packet_keys.push(onion_utils::OnionKeys {
				#[cfg(test)]
				shared_secret: onion_packet_ss,
				#[cfg(test)]
				blinding_factor: [0; 32],
				ephemeral_pubkey,
				rho,
				mu,
			});
		}
	)?;

	if let Some(control_tlvs) = final_control_tlvs {
		payloads.push((Payload::Receive {
			control_tlvs,
			reply_path: reply_path.take(),
			message,
		}, prev_control_tlvs_ss.unwrap()));
	} else {
		payloads.push((Payload::Receive {
			control_tlvs: ReceiveControlTlvs::Unblinded(ReceiveTlvs { path_id: None, }),
			reply_path: reply_path.take(),
			message,
		}, prev_control_tlvs_ss.unwrap()));
	}

	Ok((payloads, onion_packet_keys))
}

/// Errors if the serialized payload size exceeds onion_message::BIG_PACKET_HOP_DATA_LEN
fn construct_onion_message_packet<T: OnionMessageContents>(payloads: Vec<(Payload<T>, [u8; 32])>, onion_keys: Vec<onion_utils::OnionKeys>, prng_seed: [u8; 32]) -> Result<Packet, ()> {
	// Spec rationale:
	// "`len` allows larger messages to be sent than the standard 1300 bytes allowed for an HTLC
	// onion, but this should be used sparingly as it is reduces anonymity set, hence the
	// recommendation that it either look like an HTLC onion, or if larger, be a fixed size."
	let payloads_ser_len = onion_utils::payloads_serialized_length(&payloads);
	let hop_data_len = if payloads_ser_len <= SMALL_PACKET_HOP_DATA_LEN {
		SMALL_PACKET_HOP_DATA_LEN
	} else if payloads_ser_len <= BIG_PACKET_HOP_DATA_LEN {
		BIG_PACKET_HOP_DATA_LEN
	} else { return Err(()) };

	onion_utils::construct_onion_message_packet::<_, _>(
		payloads, onion_keys, prng_seed, hop_data_len)
}
