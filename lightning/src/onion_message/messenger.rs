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

use crate::chain::keysinterface::{EntropySource, KeysManager, NodeSigner, Recipient};
use crate::ln::features::{InitFeatures, NodeFeatures};
use crate::ln::msgs::{self, OnionMessageHandler};
use crate::ln::onion_utils;
use crate::ln::peer_handler::IgnoringMessageHandler;
use super::blinded_path::{BlindedPath, ForwardTlvs, ReceiveTlvs};
pub use super::packet::{CustomOnionMessageContents, OnionMessageContents};
use super::packet::{BIG_PACKET_HOP_DATA_LEN, ForwardControlTlvs, Packet, Payload, ReceiveControlTlvs, SMALL_PACKET_HOP_DATA_LEN};
use super::utils;
use crate::util::events::OnionMessageProvider;
use crate::util::logger::Logger;
use crate::util::ser::Writeable;

use core::ops::Deref;
use crate::io;
use crate::sync::{Arc, Mutex};
use crate::prelude::*;

/// A sender, receiver and forwarder of onion messages. In upcoming releases, this object will be
/// used to retrieve invoices and fulfill invoice requests from [offers]. Currently, only sending
/// and receiving custom onion messages is supported.
///
/// # Example
///
/// ```
/// # extern crate bitcoin;
/// # use bitcoin::hashes::_export::_core::time::Duration;
/// # use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
/// # use lightning::chain::keysinterface::KeysManager;
/// # use lightning::ln::peer_handler::IgnoringMessageHandler;
/// # use lightning::onion_message::{BlindedPath, CustomOnionMessageContents, Destination, OnionMessageContents, OnionMessenger};
/// # use lightning::util::logger::{Logger, Record};
/// # use lightning::util::ser::{Writeable, Writer};
/// # use lightning::io;
/// # use std::sync::Arc;
/// # struct FakeLogger;
/// # impl Logger for FakeLogger {
/// #     fn log(&self, record: &Record) { unimplemented!() }
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
/// # let your_custom_message_handler = IgnoringMessageHandler {};
/// // Create the onion messenger. This must use the same `keys_manager` as is passed to your
/// // ChannelManager.
/// let onion_messenger = OnionMessenger::new(&keys_manager, &keys_manager, logger, &your_custom_message_handler);
///
/// # struct YourCustomMessage {}
/// impl Writeable for YourCustomMessage {
/// 	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
/// 		# Ok(())
/// 		// Write your custom onion message to `w`
/// 	}
/// }
/// impl CustomOnionMessageContents for YourCustomMessage {
/// 	fn tlv_type(&self) -> u64 {
/// 		# let your_custom_message_type = 42;
/// 		your_custom_message_type
/// 	}
/// }
/// // Send a custom onion message to a node id.
/// let intermediate_hops = [hop_node_id1, hop_node_id2];
/// let reply_path = None;
/// # let your_custom_message = YourCustomMessage {};
/// let message = OnionMessageContents::Custom(your_custom_message);
/// onion_messenger.send_onion_message(&intermediate_hops, Destination::Node(destination_node_id), message, reply_path);
///
/// // Create a blinded path to yourself, for someone to send an onion message to.
/// # let your_node_id = hop_node_id1;
/// let hops = [hop_node_id3, hop_node_id4, your_node_id];
/// let blinded_path = BlindedPath::new(&hops, &keys_manager, &secp_ctx).unwrap();
///
/// // Send a custom onion message to a blinded path.
/// # let intermediate_hops = [hop_node_id1, hop_node_id2];
/// let reply_path = None;
/// # let your_custom_message = YourCustomMessage {};
/// let message = OnionMessageContents::Custom(your_custom_message);
/// onion_messenger.send_onion_message(&intermediate_hops, Destination::BlindedPath(blinded_path), message, reply_path);
/// ```
///
/// [offers]: <https://github.com/lightning/bolts/pull/798>
/// [`OnionMessenger`]: crate::onion_message::OnionMessenger
pub struct OnionMessenger<ES: Deref, NS: Deref, L: Deref, CMH: Deref>
	where ES::Target: EntropySource,
		  NS::Target: NodeSigner,
		  L::Target: Logger,
		  CMH:: Target: CustomOnionMessageHandler,
{
	entropy_source: ES,
	node_signer: NS,
	logger: L,
	pending_messages: Mutex<HashMap<PublicKey, VecDeque<msgs::OnionMessage>>>,
	secp_ctx: Secp256k1<secp256k1::All>,
	custom_handler: CMH,
	// Coming soon:
	// invoice_handler: InvoiceHandler,
}

/// The destination of an onion message.
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
	/// The provided [`Destination`] was an invalid [`BlindedPath`], due to having fewer than two
	/// blinded hops.
	TooFewBlindedHops,
	/// Our next-hop peer was offline or does not support onion message forwarding.
	InvalidFirstHop,
	/// Onion message contents must have a TLV type >= 64.
	InvalidMessage,
	/// Our next-hop peer's buffer was full or our total outbound buffer was full.
	BufferFull,
	/// Failed to retrieve our node id from the provided [`NodeSigner`].
	///
	/// [`NodeSigner`]: crate::chain::keysinterface::NodeSigner
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
	type CustomMessage: CustomOnionMessageContents;
	/// Called with the custom message that was received.
	fn handle_custom_message(&self, msg: Self::CustomMessage);
	/// Read a custom message of type `message_type` from `buffer`, returning `Ok(None)` if the
	/// message type is unknown.
	fn read_custom_message<R: io::Read>(&self, message_type: u64, buffer: &mut R) -> Result<Option<Self::CustomMessage>, msgs::DecodeError>;
}

impl<ES: Deref, NS: Deref, L: Deref, CMH: Deref> OnionMessenger<ES, NS, L, CMH>
	where ES::Target: EntropySource,
		  NS::Target: NodeSigner,
		  L::Target: Logger,
		  CMH::Target: CustomOnionMessageHandler,
{
	/// Constructs a new `OnionMessenger` to send, forward, and delegate received onion messages to
	/// their respective handlers.
	pub fn new(entropy_source: ES, node_signer: NS, logger: L, custom_handler: CMH) -> Self {
		let mut secp_ctx = Secp256k1::new();
		secp_ctx.seeded_randomize(&entropy_source.get_secure_random_bytes());
		OnionMessenger {
			entropy_source,
			node_signer,
			pending_messages: Mutex::new(HashMap::new()),
			secp_ctx,
			logger,
			custom_handler,
		}
	}

	/// Send an onion message with contents `message` to `destination`, routing it through `intermediate_nodes`.
	/// See [`OnionMessenger`] for example usage.
	pub fn send_onion_message<T: CustomOnionMessageContents>(&self, intermediate_nodes: &[PublicKey], mut destination: Destination, message: OnionMessageContents<T>, reply_path: Option<BlindedPath>) -> Result<(), SendError> {
		if let Destination::BlindedPath(BlindedPath { ref blinded_hops, .. }) = destination {
			if blinded_hops.len() < 2 {
				return Err(SendError::TooFewBlindedHops);
			}
		}
		let OnionMessageContents::Custom(ref msg) = message;
		if msg.tlv_type() < 64 { return Err(SendError::InvalidMessage) }

		// If we are sending straight to a blinded path and we are the introduction node, we need to
		// advance the blinded path by 1 hop so the second hop is the new introduction node.
		if intermediate_nodes.len() == 0 {
			if let Destination::BlindedPath(ref mut blinded_path) = destination {
				let our_node_id = self.node_signer.get_node_id(Recipient::Node)
					.map_err(|()| SendError::GetNodeIdFailed)?;
				if blinded_path.introduction_node_id == our_node_id {
					blinded_path.advance_by_one(&self.node_signer, &self.secp_ctx)
						.map_err(|()| SendError::BlindedPathAdvanceFailed)?;
				}
			}
		}

		let blinding_secret_bytes = self.entropy_source.get_secure_random_bytes();
		let blinding_secret = SecretKey::from_slice(&blinding_secret_bytes[..]).expect("RNG is busted");
		let (introduction_node_id, blinding_point) = if intermediate_nodes.len() != 0 {
			(intermediate_nodes[0], PublicKey::from_secret_key(&self.secp_ctx, &blinding_secret))
		} else {
			match destination {
				Destination::Node(pk) => (pk, PublicKey::from_secret_key(&self.secp_ctx, &blinding_secret)),
				Destination::BlindedPath(BlindedPath { introduction_node_id, blinding_point, .. }) =>
					(introduction_node_id, blinding_point),
			}
		};
		let (packet_payloads, packet_keys) = packet_payloads_and_keys(
			&self.secp_ctx, intermediate_nodes, destination, message, reply_path, &blinding_secret)
			.map_err(|e| SendError::Secp256k1(e))?;

		let prng_seed = self.entropy_source.get_secure_random_bytes();
		let onion_routing_packet = construct_onion_message_packet(
			packet_payloads, packet_keys, prng_seed).map_err(|()| SendError::TooBigPacket)?;

		let mut pending_per_peer_msgs = self.pending_messages.lock().unwrap();
		if outbound_buffer_full(&introduction_node_id, &pending_per_peer_msgs) { return Err(SendError::BufferFull) }
		match pending_per_peer_msgs.entry(introduction_node_id) {
			hash_map::Entry::Vacant(_) => Err(SendError::InvalidFirstHop),
			hash_map::Entry::Occupied(mut e) => {
				e.get_mut().push_back(msgs::OnionMessage { blinding_point, onion_routing_packet });
				Ok(())
			}
		}
	}

	#[cfg(test)]
	pub(super) fn release_pending_msgs(&self) -> HashMap<PublicKey, VecDeque<msgs::OnionMessage>> {
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

fn outbound_buffer_full(peer_node_id: &PublicKey, buffer: &HashMap<PublicKey, VecDeque<msgs::OnionMessage>>) -> bool {
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

impl<ES: Deref, NS: Deref, L: Deref, CMH: Deref> OnionMessageHandler for OnionMessenger<ES, NS, L, CMH>
	where ES::Target: EntropySource,
		  NS::Target: NodeSigner,
		  L::Target: Logger,
		  CMH::Target: CustomOnionMessageHandler + Sized,
{
	/// Handle an incoming onion message. Currently, if a message was destined for us we will log, but
	/// soon we'll delegate the onion message to a handler that can generate invoices or send
	/// payments.
	fn handle_onion_message(&self, _peer_node_id: &PublicKey, msg: &msgs::OnionMessage) {
		let control_tlvs_ss = match self.node_signer.ecdh(Recipient::Node, &msg.blinding_point, None) {
			Ok(ss) => ss,
			Err(e) =>  {
				log_error!(self.logger, "Failed to retrieve node secret: {:?}", e);
				return
			}
		};
		let onion_decode_ss = {
			let blinding_factor = {
				let mut hmac = HmacEngine::<Sha256>::new(b"blinded_node_id");
				hmac.input(control_tlvs_ss.as_ref());
				Hmac::from_engine(hmac).into_inner()
			};
			match self.node_signer.ecdh(Recipient::Node, &msg.onion_routing_packet.public_key,
				Some(&Scalar::from_be_bytes(blinding_factor).unwrap()))
			{
				Ok(ss) => ss.secret_bytes(),
				Err(()) => {
					log_trace!(self.logger, "Failed to compute onion packet shared secret");
					return
				}
			}
		};
		match onion_utils::decode_next_untagged_hop(onion_decode_ss, &msg.onion_routing_packet.hop_data[..],
			msg.onion_routing_packet.hmac, (control_tlvs_ss, &*self.custom_handler))
		{
			Ok((Payload::Receive::<<<CMH as Deref>::Target as CustomOnionMessageHandler>::CustomMessage> {
				message, control_tlvs: ReceiveControlTlvs::Unblinded(ReceiveTlvs { path_id }), reply_path,
			}, None)) => {
				log_info!(self.logger,
					"Received an onion message with path_id {:02x?} and {} reply_path",
						path_id, if reply_path.is_some() { "a" } else { "no" });
				match message {
					OnionMessageContents::Custom(msg) => self.custom_handler.handle_custom_message(msg),
				}
			},
			Ok((Payload::Forward(ForwardControlTlvs::Unblinded(ForwardTlvs {
				next_node_id, next_blinding_override
			})), Some((next_hop_hmac, new_packet_bytes)))) => {
				// TODO: we need to check whether `next_node_id` is our node, in which case this is a dummy
				// blinded hop and this onion message is destined for us. In this situation, we should keep
				// unwrapping the onion layers to get to the final payload. Since we don't have the option
				// of creating blinded paths with dummy hops currently, we should be ok to not handle this
				// for now.
				let new_pubkey = match onion_utils::next_hop_packet_pubkey(&self.secp_ctx, msg.onion_routing_packet.public_key, &onion_decode_ss) {
					Ok(pk) => pk,
					Err(e) => {
						log_trace!(self.logger, "Failed to compute next hop packet pubkey: {}", e);
						return
					}
				};
				let outgoing_packet = Packet {
					version: 0,
					public_key: new_pubkey,
					hop_data: new_packet_bytes,
					hmac: next_hop_hmac,
				};
				let onion_message = msgs::OnionMessage {
					blinding_point: match next_blinding_override {
						Some(blinding_point) => blinding_point,
						None => {
							let blinding_factor = {
								let mut sha = Sha256::engine();
								sha.input(&msg.blinding_point.serialize()[..]);
								sha.input(control_tlvs_ss.as_ref());
								Sha256::from_engine(sha).into_inner()
							};
							let next_blinding_point = msg.blinding_point;
							match next_blinding_point.mul_tweak(&self.secp_ctx, &Scalar::from_be_bytes(blinding_factor).unwrap()) {
								Ok(bp) => bp,
								Err(e) => {
									log_trace!(self.logger, "Failed to compute next blinding point: {}", e);
									return
								}
							}
						},
					},
					onion_routing_packet: outgoing_packet,
				};

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
				};
			},
			Err(e) => {
				log_trace!(self.logger, "Errored decoding onion message packet: {:?}", e);
			},
			_ => {
				log_trace!(self.logger, "Received bogus onion message packet, either the sender encoded a final hop as a forwarding hop or vice versa");
			},
		};
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
}

impl<ES: Deref, NS: Deref, L: Deref, CMH: Deref> OnionMessageProvider for OnionMessenger<ES, NS, L, CMH>
	where ES::Target: EntropySource,
		  NS::Target: NodeSigner,
		  L::Target: Logger,
		  CMH::Target: CustomOnionMessageHandler,
{
	fn next_onion_message_for_peer(&self, peer_node_id: PublicKey) -> Option<msgs::OnionMessage> {
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
/// (C-not exported) as `Arc`s don't make sense in bindings.
///
/// [`SimpleArcChannelManager`]: crate::ln::channelmanager::SimpleArcChannelManager
/// [`SimpleArcPeerManager`]: crate::ln::peer_handler::SimpleArcPeerManager
pub type SimpleArcOnionMessenger<L> = OnionMessenger<Arc<KeysManager>, Arc<KeysManager>, Arc<L>, IgnoringMessageHandler>;
/// Useful for simplifying the parameters of [`SimpleRefChannelManager`] and
/// [`SimpleRefPeerManager`]. See their docs for more details.
///
/// (C-not exported) as general type aliases don't make sense in bindings.
///
/// [`SimpleRefChannelManager`]: crate::ln::channelmanager::SimpleRefChannelManager
/// [`SimpleRefPeerManager`]: crate::ln::peer_handler::SimpleRefPeerManager
pub type SimpleRefOnionMessenger<'a, 'b, L> = OnionMessenger<&'a KeysManager, &'a KeysManager, &'b L, IgnoringMessageHandler>;

/// Construct onion packet payloads and keys for sending an onion message along the given
/// `unblinded_path` to the given `destination`.
fn packet_payloads_and_keys<T: CustomOnionMessageContents, S: secp256k1::Signing + secp256k1::Verification>(
	secp_ctx: &Secp256k1<S>, unblinded_path: &[PublicKey], destination: Destination,
	message: OnionMessageContents<T>, mut reply_path: Option<BlindedPath>, session_priv: &SecretKey
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
	utils::construct_keys_callback(secp_ctx, unblinded_path, Some(destination), session_priv, |_, onion_packet_ss, ephemeral_pubkey, control_tlvs_ss, unblinded_pk_opt, enc_payload_opt| {
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
	})?;

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
fn construct_onion_message_packet<T: CustomOnionMessageContents>(payloads: Vec<(Payload<T>, [u8; 32])>, onion_keys: Vec<onion_utils::OnionKeys>, prng_seed: [u8; 32]) -> Result<Packet, ()> {
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

	Ok(onion_utils::construct_onion_message_packet::<_, _>(
		payloads, onion_keys, prng_seed, hop_data_len))
}
