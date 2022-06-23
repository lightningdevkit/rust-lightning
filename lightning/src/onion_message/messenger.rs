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
use bitcoin::secp256k1::{self, PublicKey, Secp256k1, SecretKey};

use chain::keysinterface::{InMemorySigner, KeysInterface, KeysManager, Recipient, Sign};
use ln::msgs;
use ln::onion_utils;
use super::blinded_route::{BlindedRoute, ForwardTlvs, ReceiveTlvs};
use super::packet::{BIG_PACKET_HOP_DATA_LEN, ForwardControlTlvs, Packet, Payload, ReceiveControlTlvs, SMALL_PACKET_HOP_DATA_LEN};
use super::utils;
use util::logger::Logger;

use core::ops::Deref;
use sync::{Arc, Mutex};
use prelude::*;

/// A sender, receiver and forwarder of onion messages. In upcoming releases, this object will be
/// used to retrieve invoices and fulfill invoice requests from [offers]. Currently, only sending
/// and receiving empty onion messages is supported.
///
/// # Example
///
//  Needs to be `ignore` until the `onion_message` module is made public, otherwise this is a test
//  failure.
/// ```ignore
/// # extern crate bitcoin;
/// # use bitcoin::hashes::_export::_core::time::Duration;
/// # use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
/// # use lightning::chain::keysinterface::{InMemorySigner, KeysManager, KeysInterface};
/// # use lightning::onion_message::{BlindedRoute, Destination, OnionMessenger};
/// # use lightning::util::logger::{Logger, Record};
/// # use std::sync::Arc;
/// # struct FakeLogger {};
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
/// # let (hop_node_id2, hop_node_id3, hop_node_id4) = (hop_node_id1, hop_node_id1,
/// hop_node_id1);
/// # let destination_node_id = hop_node_id1;
/// #
/// // Create the onion messenger. This must use the same `keys_manager` as is passed to your
/// // ChannelManager.
/// let onion_messenger = OnionMessenger::new(&keys_manager, logger);
///
/// // Send an empty onion message to a node id.
/// let intermediate_hops = [hop_node_id1, hop_node_id2];
/// onion_messenger.send_onion_message(&intermediate_hops, Destination::Node(destination_node_id));
///
/// // Create a blinded route to yourself, for someone to send an onion message to.
/// # let your_node_id = hop_node_id1;
/// let hops = [hop_node_id3, hop_node_id4, your_node_id];
/// let blinded_route = BlindedRoute::new::<InMemorySigner, _, _>(&hops, &keys_manager, &secp_ctx).unwrap();
///
/// // Send an empty onion message to a blinded route.
/// # let intermediate_hops = [hop_node_id1, hop_node_id2];
/// onion_messenger.send_onion_message(&intermediate_hops, Destination::BlindedRoute(blinded_route));
/// ```
///
/// [offers]: <https://github.com/lightning/bolts/pull/798>
/// [`OnionMessenger`]: crate::onion_message::OnionMessenger
pub struct OnionMessenger<Signer: Sign, K: Deref, L: Deref>
	where K::Target: KeysInterface<Signer = Signer>,
	      L::Target: Logger,
{
	keys_manager: K,
	logger: L,
	pending_messages: Mutex<HashMap<PublicKey, Vec<msgs::OnionMessage>>>,
	secp_ctx: Secp256k1<secp256k1::All>,
	// Coming soon:
	// invoice_handler: InvoiceHandler,
	// custom_handler: CustomHandler, // handles custom onion messages
}

/// The destination of an onion message.
pub enum Destination {
	/// We're sending this onion message to a node.
	Node(PublicKey),
	/// We're sending this onion message to a blinded route.
	BlindedRoute(BlindedRoute),
}

impl Destination {
	pub(super) fn num_hops(&self) -> usize {
		match self {
			Destination::Node(_) => 1,
			Destination::BlindedRoute(BlindedRoute { blinded_hops, .. }) => blinded_hops.len(),
		}
	}
}

/// Errors that may occur when [sending an onion message].
///
/// [sending an onion message]: OnionMessenger::send_onion_message
#[derive(Debug, PartialEq)]
pub enum SendError {
	/// Errored computing onion message packet keys.
	Secp256k1(secp256k1::Error),
	/// Because implementations such as Eclair will drop onion messages where the message packet
	/// exceeds 32834 bytes, we refuse to send messages where the packet exceeds this size.
	TooBigPacket,
}

impl<Signer: Sign, K: Deref, L: Deref> OnionMessenger<Signer, K, L>
	where K::Target: KeysInterface<Signer = Signer>,
	      L::Target: Logger,
{
	/// Constructs a new `OnionMessenger` to send, forward, and delegate received onion messages to
	/// their respective handlers.
	pub fn new(keys_manager: K, logger: L) -> Self {
		let mut secp_ctx = Secp256k1::new();
		secp_ctx.seeded_randomize(&keys_manager.get_secure_random_bytes());
		OnionMessenger {
			keys_manager,
			pending_messages: Mutex::new(HashMap::new()),
			secp_ctx,
			logger,
		}
	}

	/// Send an empty onion message to `destination`, routing it through `intermediate_nodes`.
	/// See [`OnionMessenger`] for example usage.
	pub fn send_onion_message(&self, intermediate_nodes: &[PublicKey], destination: Destination) -> Result<(), SendError> {
		let blinding_secret_bytes = self.keys_manager.get_secure_random_bytes();
		let blinding_secret = SecretKey::from_slice(&blinding_secret_bytes[..]).expect("RNG is busted");
		let (introduction_node_id, blinding_point) = if intermediate_nodes.len() != 0 {
			(intermediate_nodes[0], PublicKey::from_secret_key(&self.secp_ctx, &blinding_secret))
		} else {
			match destination {
				Destination::Node(pk) => (pk, PublicKey::from_secret_key(&self.secp_ctx, &blinding_secret)),
				Destination::BlindedRoute(BlindedRoute { introduction_node_id, blinding_point, .. }) =>
					(introduction_node_id, blinding_point),
			}
		};
		let (packet_payloads, packet_keys) = packet_payloads_and_keys(
			&self.secp_ctx, intermediate_nodes, destination, &blinding_secret)
			.map_err(|e| SendError::Secp256k1(e))?;

		let prng_seed = self.keys_manager.get_secure_random_bytes();
		let onion_packet = construct_onion_message_packet(
			packet_payloads, packet_keys, prng_seed).map_err(|()| SendError::TooBigPacket)?;

		let mut pending_per_peer_msgs = self.pending_messages.lock().unwrap();
		let pending_msgs = pending_per_peer_msgs.entry(introduction_node_id).or_insert(Vec::new());
		pending_msgs.push(
			msgs::OnionMessage {
				blinding_point,
				onion_routing_packet: onion_packet,
			}
		);
		Ok(())
	}

	/// Handle an incoming onion message. Currently, if a message was destined for us we will log, but
	/// soon we'll delegate the onion message to a handler that can generate invoices or send
	/// payments.
	pub fn handle_onion_message(&self, _peer_node_id: &PublicKey, msg: &msgs::OnionMessage) {
		let control_tlvs_ss = match self.keys_manager.ecdh(Recipient::Node, &msg.blinding_point, None) {
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
			match self.keys_manager.ecdh(Recipient::Node, &msg.onion_routing_packet.public_key,
				Some(&blinding_factor))
			{
				Ok(ss) => ss.secret_bytes(),
				Err(()) => {
					log_trace!(self.logger, "Failed to compute onion packet shared secret");
					return
				}
			}
		};
		match onion_utils::decode_next_hop(onion_decode_ss, &msg.onion_routing_packet.hop_data[..],
			msg.onion_routing_packet.hmac, control_tlvs_ss)
		{
			Ok((Payload::Receive {
				control_tlvs: ReceiveControlTlvs::Unblinded(ReceiveTlvs { path_id })
			}, None)) => {
				log_info!(self.logger, "Received an onion message with path_id: {:02x?}", path_id);
			},
			Ok((Payload::Forward(ForwardControlTlvs::Unblinded(ForwardTlvs {
				next_node_id, next_blinding_override
			})), Some((next_hop_hmac, new_packet_bytes)))) => {
				// TODO: we need to check whether `next_node_id` is our node, in which case this is a dummy
				// blinded hop and this onion message is destined for us. In this situation, we should keep
				// unwrapping the onion layers to get to the final payload. Since we don't have the option
				// of creating blinded routes with dummy hops currently, we should be ok to not handle this
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

				let mut pending_per_peer_msgs = self.pending_messages.lock().unwrap();
				let pending_msgs = pending_per_peer_msgs.entry(next_node_id).or_insert(Vec::new());
				pending_msgs.push(
					msgs::OnionMessage {
						blinding_point: match next_blinding_override {
							Some(blinding_point) => blinding_point,
							None => {
								let blinding_factor = {
									let mut sha = Sha256::engine();
									sha.input(&msg.blinding_point.serialize()[..]);
									sha.input(control_tlvs_ss.as_ref());
									Sha256::from_engine(sha).into_inner()
								};
								let mut next_blinding_point = msg.blinding_point;
								if let Err(e) = next_blinding_point.mul_assign(&self.secp_ctx, &blinding_factor[..]) {
									log_trace!(self.logger, "Failed to compute next blinding point: {}", e);
									return
								}
								next_blinding_point
							},
						},
						onion_routing_packet: outgoing_packet,
					},
				);
			},
			Err(e) => {
				log_trace!(self.logger, "Errored decoding onion message packet: {:?}", e);
			},
			_ => {
				log_trace!(self.logger, "Received bogus onion message packet, either the sender encoded a final hop as a forwarding hop or vice versa");
			},
		};
	}

	#[cfg(test)]
	pub(super) fn release_pending_msgs(&self) -> HashMap<PublicKey, Vec<msgs::OnionMessage>> {
		let mut pending_msgs = self.pending_messages.lock().unwrap();
		let mut msgs = HashMap::new();
		core::mem::swap(&mut *pending_msgs, &mut msgs);
		msgs
	}
}

// TODO: parameterize the below Simple* types with OnionMessenger and handle the messages it
// produces
/// Useful for simplifying the parameters of [`SimpleArcChannelManager`] and
/// [`SimpleArcPeerManager`]. See their docs for more details.
///
///[`SimpleArcChannelManager`]: crate::ln::channelmanager::SimpleArcChannelManager
///[`SimpleArcPeerManager`]: crate::ln::peer_handler::SimpleArcPeerManager
pub type SimpleArcOnionMessenger<L> = OnionMessenger<InMemorySigner, Arc<KeysManager>, Arc<L>>;
/// Useful for simplifying the parameters of [`SimpleRefChannelManager`] and
/// [`SimpleRefPeerManager`]. See their docs for more details.
///
///[`SimpleRefChannelManager`]: crate::ln::channelmanager::SimpleRefChannelManager
///[`SimpleRefPeerManager`]: crate::ln::peer_handler::SimpleRefPeerManager
pub type SimpleRefOnionMessenger<'a, 'b, L> = OnionMessenger<InMemorySigner, &'a KeysManager, &'b L>;

/// Construct onion packet payloads and keys for sending an onion message along the given
/// `unblinded_path` to the given `destination`.
fn packet_payloads_and_keys<T: secp256k1::Signing + secp256k1::Verification>(
	secp_ctx: &Secp256k1<T>, unblinded_path: &[PublicKey], destination: Destination, session_priv: &SecretKey
) -> Result<(Vec<(Payload, [u8; 32])>, Vec<onion_utils::OnionKeys>), secp256k1::Error> {
	let num_hops = unblinded_path.len() + destination.num_hops();
	let mut payloads = Vec::with_capacity(num_hops);
	let mut onion_packet_keys = Vec::with_capacity(num_hops);

	let (mut intro_node_id_blinding_pt, num_blinded_hops) = if let Destination::BlindedRoute(BlindedRoute {
		introduction_node_id, blinding_point, blinded_hops }) = &destination {
		(Some((*introduction_node_id, *blinding_point)), blinded_hops.len()) } else { (None, 0) };
	let num_unblinded_hops = num_hops - num_blinded_hops;

	let mut unblinded_path_idx = 0;
	let mut blinded_path_idx = 0;
	let mut prev_control_tlvs_ss = None;
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
			if let Some(encrypted_payload) = enc_payload_opt {
				payloads.push((Payload::Forward(ForwardControlTlvs::Blinded(encrypted_payload)),
					control_tlvs_ss));
			} else { debug_assert!(false); }
			blinded_path_idx += 1;
		} else if blinded_path_idx < num_blinded_hops - 1 && enc_payload_opt.is_some() {
			payloads.push((Payload::Forward(ForwardControlTlvs::Blinded(enc_payload_opt.unwrap())),
				control_tlvs_ss));
			blinded_path_idx += 1;
		} else if let Some(encrypted_payload) = enc_payload_opt {
			payloads.push((Payload::Receive {
				control_tlvs: ReceiveControlTlvs::Blinded(encrypted_payload),
			}, control_tlvs_ss));
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

	if let Some(control_tlvs_ss) = prev_control_tlvs_ss {
		payloads.push((Payload::Receive {
			control_tlvs: ReceiveControlTlvs::Unblinded(ReceiveTlvs { path_id: None, })
		}, control_tlvs_ss));
	}

	Ok((payloads, onion_packet_keys))
}

/// Errors if the serialized payload size exceeds onion_message::BIG_PACKET_HOP_DATA_LEN
fn construct_onion_message_packet(payloads: Vec<(Payload, [u8; 32])>, onion_keys: Vec<onion_utils::OnionKeys>, prng_seed: [u8; 32]) -> Result<Packet, ()> {
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
