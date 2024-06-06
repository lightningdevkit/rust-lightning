// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! LDK sends, receives, and forwards onion messages via this [`OnionMessenger`], which lives here,
//! as well as various types, traits, and utilities that it uses.

use bitcoin::hashes::{Hash, HashEngine};
use bitcoin::hashes::hmac::{Hmac, HmacEngine};
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::secp256k1::{self, PublicKey, Scalar, Secp256k1, SecretKey};

use crate::blinded_path::{BlindedPath, IntroductionNode, NextMessageHop, NodeIdLookUp};
use crate::blinded_path::message::{advance_path_by_one, ForwardNode, ForwardTlvs, ReceiveTlvs};
use crate::blinded_path::utils;
use crate::events::{Event, EventHandler, EventsProvider};
use crate::sign::{EntropySource, NodeSigner, Recipient};
use crate::ln::features::{InitFeatures, NodeFeatures};
use crate::ln::msgs::{self, OnionMessage, OnionMessageHandler, SocketAddress};
use crate::ln::onion_utils;
use crate::routing::gossip::{NetworkGraph, NodeId, ReadOnlyNetworkGraph};
use super::async_payments::{AsyncPaymentsMessage, AsyncPaymentsMessageHandler};
use super::packet::OnionMessageContents;
use super::packet::ParsedOnionMessageContents;
use super::offers::OffersMessageHandler;
use super::packet::{BIG_PACKET_HOP_DATA_LEN, ForwardControlTlvs, Packet, Payload, ReceiveControlTlvs, SMALL_PACKET_HOP_DATA_LEN};
use crate::util::logger::{Logger, WithContext};
use crate::util::ser::Writeable;

use core::fmt;
use core::ops::Deref;
use crate::io;
use crate::sync::Mutex;
use crate::prelude::*;

#[cfg(not(c_bindings))]
use {
	crate::sign::KeysManager,
	crate::ln::channelmanager::{SimpleArcChannelManager, SimpleRefChannelManager},
	crate::ln::peer_handler::IgnoringMessageHandler,
	crate::sync::Arc,
};

pub(super) const MAX_TIMER_TICKS: usize = 2;

/// A trivial trait which describes any [`OnionMessenger`].
///
/// This is not exported to bindings users as general cover traits aren't useful in other
/// languages.
pub trait AOnionMessenger {
	/// A type implementing [`EntropySource`]
	type EntropySource: EntropySource + ?Sized;
	/// A type that may be dereferenced to [`Self::EntropySource`]
	type ES: Deref<Target = Self::EntropySource>;
	/// A type implementing [`NodeSigner`]
	type NodeSigner: NodeSigner + ?Sized;
	/// A type that may be dereferenced to [`Self::NodeSigner`]
	type NS: Deref<Target = Self::NodeSigner>;
	/// A type implementing [`Logger`]
	type Logger: Logger + ?Sized;
	/// A type that may be dereferenced to [`Self::Logger`]
	type L: Deref<Target = Self::Logger>;
	/// A type implementing [`NodeIdLookUp`]
	type NodeIdLookUp: NodeIdLookUp + ?Sized;
	/// A type that may be dereferenced to [`Self::NodeIdLookUp`]
	type NL: Deref<Target = Self::NodeIdLookUp>;
	/// A type implementing [`MessageRouter`]
	type MessageRouter: MessageRouter + ?Sized;
	/// A type that may be dereferenced to [`Self::MessageRouter`]
	type MR: Deref<Target = Self::MessageRouter>;
	/// A type implementing [`OffersMessageHandler`]
	type OffersMessageHandler: OffersMessageHandler + ?Sized;
	/// A type that may be dereferenced to [`Self::OffersMessageHandler`]
	type OMH: Deref<Target = Self::OffersMessageHandler>;
	/// A type implementing [`AsyncPaymentsMessageHandler`]
	type AsyncPaymentsMessageHandler: AsyncPaymentsMessageHandler + ?Sized;
	/// A type that may be dereferenced to [`Self::AsyncPaymentsMessageHandler`]
	type APH: Deref<Target = Self::AsyncPaymentsMessageHandler>;
	/// A type implementing [`CustomOnionMessageHandler`]
	type CustomOnionMessageHandler: CustomOnionMessageHandler + ?Sized;
	/// A type that may be dereferenced to [`Self::CustomOnionMessageHandler`]
	type CMH: Deref<Target = Self::CustomOnionMessageHandler>;
	/// Returns a reference to the actual [`OnionMessenger`] object.
	fn get_om(&self) -> &OnionMessenger<Self::ES, Self::NS, Self::L, Self::NL, Self::MR, Self::OMH, Self::APH, Self::CMH>;
}

impl<ES: Deref, NS: Deref, L: Deref, NL: Deref, MR: Deref, OMH: Deref, APH: Deref, CMH: Deref> AOnionMessenger
for OnionMessenger<ES, NS, L, NL, MR, OMH, APH, CMH> where
	ES::Target: EntropySource,
	NS::Target: NodeSigner,
	L::Target: Logger,
	NL::Target: NodeIdLookUp,
	MR::Target: MessageRouter,
	OMH::Target: OffersMessageHandler,
	APH:: Target: AsyncPaymentsMessageHandler,
	CMH::Target: CustomOnionMessageHandler,
{
	type EntropySource = ES::Target;
	type ES = ES;
	type NodeSigner = NS::Target;
	type NS = NS;
	type Logger = L::Target;
	type L = L;
	type NodeIdLookUp = NL::Target;
	type NL = NL;
	type MessageRouter = MR::Target;
	type MR = MR;
	type OffersMessageHandler = OMH::Target;
	type OMH = OMH;
	type AsyncPaymentsMessageHandler = APH::Target;
	type APH = APH;
	type CustomOnionMessageHandler = CMH::Target;
	type CMH = CMH;
	fn get_om(&self) -> &OnionMessenger<ES, NS, L, NL, MR, OMH, APH, CMH> { self }
}

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
/// # use bitcoin::hashes::hex::FromHex;
/// # use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey, self};
/// # use lightning::blinded_path::{BlindedPath, EmptyNodeIdLookUp};
/// # use lightning::blinded_path::message::ForwardNode;
/// # use lightning::sign::{EntropySource, KeysManager};
/// # use lightning::ln::peer_handler::IgnoringMessageHandler;
/// # use lightning::onion_message::messenger::{Destination, MessageRouter, OnionMessagePath, OnionMessenger};
/// # use lightning::onion_message::packet::OnionMessageContents;
/// # use lightning::util::logger::{Logger, Record};
/// # use lightning::util::ser::{Writeable, Writer};
/// # use lightning::io;
/// # use std::sync::Arc;
/// # struct FakeLogger;
/// # impl Logger for FakeLogger {
/// #     fn log(&self, record: Record) { println!("{:?}" , record); }
/// # }
/// # struct FakeMessageRouter {}
/// # impl MessageRouter for FakeMessageRouter {
/// #     fn find_path(&self, sender: PublicKey, peers: Vec<PublicKey>, destination: Destination) -> Result<OnionMessagePath, ()> {
/// #         let secp_ctx = Secp256k1::new();
/// #         let node_secret = SecretKey::from_slice(&<Vec<u8>>::from_hex("0101010101010101010101010101010101010101010101010101010101010101").unwrap()[..]).unwrap();
/// #         let hop_node_id1 = PublicKey::from_secret_key(&secp_ctx, &node_secret);
/// #         let hop_node_id2 = hop_node_id1;
/// #         Ok(OnionMessagePath {
/// #             intermediate_nodes: vec![hop_node_id1, hop_node_id2],
/// #             destination,
/// #             first_node_addresses: None,
/// #         })
/// #     }
/// #     fn create_blinded_paths<T: secp256k1::Signing + secp256k1::Verification>(
/// #         &self, _recipient: PublicKey, _peers: Vec<PublicKey>, _secp_ctx: &Secp256k1<T>
/// #     ) -> Result<Vec<BlindedPath>, ()> {
/// #         unreachable!()
/// #     }
/// # }
/// # let seed = [42u8; 32];
/// # let time = Duration::from_secs(123456);
/// # let keys_manager = KeysManager::new(&seed, time.as_secs(), time.subsec_nanos());
/// # let logger = Arc::new(FakeLogger {});
/// # let node_secret = SecretKey::from_slice(&<Vec<u8>>::from_hex("0101010101010101010101010101010101010101010101010101010101010101").unwrap()[..]).unwrap();
/// # let secp_ctx = Secp256k1::new();
/// # let hop_node_id1 = PublicKey::from_secret_key(&secp_ctx, &node_secret);
/// # let (hop_node_id3, hop_node_id4) = (hop_node_id1, hop_node_id1);
/// # let destination_node_id = hop_node_id1;
/// # let node_id_lookup = EmptyNodeIdLookUp {};
/// # let message_router = Arc::new(FakeMessageRouter {});
/// # let custom_message_handler = IgnoringMessageHandler {};
/// # let offers_message_handler = IgnoringMessageHandler {};
/// # let async_payments_message_handler = IgnoringMessageHandler {};
/// // Create the onion messenger. This must use the same `keys_manager` as is passed to your
/// // ChannelManager.
/// let onion_messenger = OnionMessenger::new(
///     &keys_manager, &keys_manager, logger, &node_id_lookup, message_router,
///     &offers_message_handler, &async_payments_message_handler, &custom_message_handler
/// );

/// # #[derive(Debug)]
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
/// 	fn msg_type(&self) -> &'static str { "YourCustomMessageType" }
/// }
/// // Send a custom onion message to a node id.
/// let destination = Destination::Node(destination_node_id);
/// let reply_path = None;
/// # let message = YourCustomMessage {};
/// onion_messenger.send_onion_message(message, destination, reply_path);
///
/// // Create a blinded path to yourself, for someone to send an onion message to.
/// # let your_node_id = hop_node_id1;
/// let hops = [
/// 	ForwardNode { node_id: hop_node_id3, short_channel_id: None },
/// 	ForwardNode { node_id: hop_node_id4, short_channel_id: None },
/// ];
/// let blinded_path = BlindedPath::new_for_message(&hops, your_node_id, &keys_manager, &secp_ctx).unwrap();
///
/// // Send a custom onion message to a blinded path.
/// let destination = Destination::BlindedPath(blinded_path);
/// let reply_path = None;
/// # let message = YourCustomMessage {};
/// onion_messenger.send_onion_message(message, destination, reply_path);
/// ```
///
/// [`InvoiceRequest`]: crate::offers::invoice_request::InvoiceRequest
/// [`Bolt12Invoice`]: crate::offers::invoice::Bolt12Invoice
pub struct OnionMessenger<
	ES: Deref, NS: Deref, L: Deref, NL: Deref, MR: Deref, OMH: Deref, APH: Deref, CMH: Deref
> where
	ES::Target: EntropySource,
	NS::Target: NodeSigner,
	L::Target: Logger,
	NL::Target: NodeIdLookUp,
	MR::Target: MessageRouter,
	OMH::Target: OffersMessageHandler,
	APH::Target: AsyncPaymentsMessageHandler,
	CMH::Target: CustomOnionMessageHandler,
{
	entropy_source: ES,
	node_signer: NS,
	logger: L,
	message_recipients: Mutex<HashMap<PublicKey, OnionMessageRecipient>>,
	secp_ctx: Secp256k1<secp256k1::All>,
	node_id_lookup: NL,
	message_router: MR,
	offers_handler: OMH,
	async_payments_handler: APH,
	custom_handler: CMH,
	intercept_messages_for_offline_peers: bool,
	pending_events: Mutex<PendingEvents>,
}

struct PendingEvents {
	intercepted_msgs: Vec<Event>,
	peer_connecteds: Vec<Event>,
}

/// [`OnionMessage`]s buffered to be sent.
enum OnionMessageRecipient {
	/// Messages for a node connected as a peer.
	ConnectedPeer(VecDeque<OnionMessage>),

	/// Messages for a node that is not yet connected, which are dropped after [`MAX_TIMER_TICKS`]
	/// and tracked here.
	PendingConnection(VecDeque<OnionMessage>, Option<Vec<SocketAddress>>, usize),
}

impl OnionMessageRecipient {
	fn pending_connection(addresses: Vec<SocketAddress>) -> Self {
		Self::PendingConnection(VecDeque::new(), Some(addresses), 0)
	}

	fn pending_messages(&self) -> &VecDeque<OnionMessage> {
		match self {
			OnionMessageRecipient::ConnectedPeer(pending_messages) => pending_messages,
			OnionMessageRecipient::PendingConnection(pending_messages, _, _) => pending_messages,
		}
	}

	fn enqueue_message(&mut self, message: OnionMessage) {
		let pending_messages = match self {
			OnionMessageRecipient::ConnectedPeer(pending_messages) => pending_messages,
			OnionMessageRecipient::PendingConnection(pending_messages, _, _) => pending_messages,
		};

		pending_messages.push_back(message);
	}

	fn dequeue_message(&mut self) -> Option<OnionMessage> {
		let pending_messages = match self {
			OnionMessageRecipient::ConnectedPeer(pending_messages) => pending_messages,
			OnionMessageRecipient::PendingConnection(pending_messages, _, _) => {
				debug_assert!(false);
				pending_messages
			},
		};

		pending_messages.pop_front()
	}

	#[cfg(test)]
	fn release_pending_messages(&mut self) -> VecDeque<OnionMessage> {
		let pending_messages = match self {
			OnionMessageRecipient::ConnectedPeer(pending_messages) => pending_messages,
			OnionMessageRecipient::PendingConnection(pending_messages, _, _) => pending_messages,
		};

		core::mem::take(pending_messages)
	}

	fn mark_connected(&mut self) {
		if let OnionMessageRecipient::PendingConnection(pending_messages, _, _) = self {
			let mut new_pending_messages = VecDeque::new();
			core::mem::swap(pending_messages, &mut new_pending_messages);
			*self = OnionMessageRecipient::ConnectedPeer(new_pending_messages);
		}
	}

	fn is_connected(&self) -> bool {
		match self {
			OnionMessageRecipient::ConnectedPeer(..) => true,
			OnionMessageRecipient::PendingConnection(..) => false,
		}
	}
}


/// The `Responder` struct creates an appropriate [`ResponseInstruction`]
/// for responding to a message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Responder {
	/// The path along which a response can be sent.
	reply_path: BlindedPath,
	path_id: Option<[u8; 32]>
}

impl_writeable_tlv_based!(Responder, {
	(0, reply_path, required),
	(2, path_id, option),
});

impl Responder {
	/// Creates a new [`Responder`] instance with the provided reply path.
	pub(super) fn new(reply_path: BlindedPath, path_id: Option<[u8; 32]>) -> Self {
		Responder {
			reply_path,
			path_id,
		}
	}

	/// Creates a [`ResponseInstruction::WithoutReplyPath`] for a given response.
	///
	/// Use when the recipient doesn't need to send back a reply to us.
	pub fn respond<T: OnionMessageContents>(self, response: T) -> ResponseInstruction<T> {
		ResponseInstruction::WithoutReplyPath(OnionMessageResponse {
			message: response,
			reply_path: self.reply_path,
			path_id: self.path_id,
		})
	}

	/// Creates a [`ResponseInstruction::WithReplyPath`] for a given response.
	///
	/// Use when the recipient needs to send back a reply to us.
	pub fn respond_with_reply_path<T: OnionMessageContents>(self, response: T) -> ResponseInstruction<T> {
		ResponseInstruction::WithReplyPath(OnionMessageResponse {
			message: response,
			reply_path: self.reply_path,
			path_id: self.path_id,
		})
	}
}

/// This struct contains the information needed to reply to a received message.
pub struct OnionMessageResponse<T: OnionMessageContents> {
	message: T,
	reply_path: BlindedPath,
	path_id: Option<[u8; 32]>,
}

/// `ResponseInstruction` represents instructions for responding to received messages.
pub enum ResponseInstruction<T: OnionMessageContents> {
	/// Indicates that a response should be sent including a reply path for
	/// the recipient to respond back.
	WithReplyPath(OnionMessageResponse<T>),
	/// Indicates that a response should be sent without including a reply path
	/// for the recipient to respond back.
	WithoutReplyPath(OnionMessageResponse<T>),
	/// Indicates that there's no response to send back.
	NoResponse,
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
pub type PendingOnionMessage<T> = (T, Destination, Option<BlindedPath>);

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

	/// Creates [`BlindedPath`]s to the `recipient` node. The nodes in `peers` are assumed to be
	/// direct peers with the `recipient`.
	fn create_blinded_paths<
		T: secp256k1::Signing + secp256k1::Verification
	>(
		&self, recipient: PublicKey, peers: Vec<PublicKey>, secp_ctx: &Secp256k1<T>,
	) -> Result<Vec<BlindedPath>, ()>;

	/// Creates compact [`BlindedPath`]s to the `recipient` node. The nodes in `peers` are assumed
	/// to be direct peers with the `recipient`.
	///
	/// Compact blinded paths use short channel ids instead of pubkeys for a smaller serialization,
	/// which is beneficial when a QR code is used to transport the data. The SCID is passed using a
	/// [`ForwardNode`] but may be `None` for graceful degradation.
	///
	/// Implementations using additional intermediate nodes are responsible for using a
	/// [`ForwardNode`] with `Some` short channel id, if possible. Similarly, implementations should
	/// call [`BlindedPath::use_compact_introduction_node`].
	///
	/// The provided implementation simply delegates to [`MessageRouter::create_blinded_paths`],
	/// ignoring the short channel ids.
	fn create_compact_blinded_paths<
		T: secp256k1::Signing + secp256k1::Verification
	>(
		&self, recipient: PublicKey, peers: Vec<ForwardNode>, secp_ctx: &Secp256k1<T>,
	) -> Result<Vec<BlindedPath>, ()> {
		let peers = peers
			.into_iter()
			.map(|ForwardNode { node_id, short_channel_id: _ }| node_id)
			.collect();
		self.create_blinded_paths(recipient, peers, secp_ctx)
	}
}

/// A [`MessageRouter`] that can only route to a directly connected [`Destination`].
///
/// # Privacy
///
/// Creating [`BlindedPath`]s may affect privacy since, if a suitable path cannot be found, it will
/// create a one-hop path using the recipient as the introduction node if it is a announced node.
/// Otherwise, there is no way to find a path to the introduction node in order to send a message,
/// and thus an `Err` is returned.
pub struct DefaultMessageRouter<G: Deref<Target=NetworkGraph<L>>, L: Deref, ES: Deref>
where
	L::Target: Logger,
	ES::Target: EntropySource,
{
	network_graph: G,
	entropy_source: ES,
}

impl<G: Deref<Target=NetworkGraph<L>>, L: Deref, ES: Deref> DefaultMessageRouter<G, L, ES>
where
	L::Target: Logger,
	ES::Target: EntropySource,
{
	/// Creates a [`DefaultMessageRouter`] using the given [`NetworkGraph`].
	pub fn new(network_graph: G, entropy_source: ES) -> Self {
		Self { network_graph, entropy_source }
	}

	fn create_blinded_paths_from_iter<
		I: Iterator<Item = ForwardNode>,
		T: secp256k1::Signing + secp256k1::Verification
	>(
		&self, recipient: PublicKey, peers: I, secp_ctx: &Secp256k1<T>, compact_paths: bool
	) -> Result<Vec<BlindedPath>, ()> {
		// Limit the number of blinded paths that are computed.
		const MAX_PATHS: usize = 3;

		// Ensure peers have at least three channels so that it is more difficult to infer the
		// recipient's node_id.
		const MIN_PEER_CHANNELS: usize = 3;

		let network_graph = self.network_graph.deref().read_only();
		let is_recipient_announced =
			network_graph.nodes().contains_key(&NodeId::from_pubkey(&recipient));

		let mut peer_info = peers
			// Limit to peers with announced channels
			.filter_map(|peer|
				network_graph
					.node(&NodeId::from_pubkey(&peer.node_id))
					.filter(|info| info.channels.len() >= MIN_PEER_CHANNELS)
					.map(|info| (peer, info.is_tor_only(), info.channels.len()))
			)
			// Exclude Tor-only nodes when the recipient is announced.
			.filter(|(_, is_tor_only, _)| !(*is_tor_only && is_recipient_announced))
			.collect::<Vec<_>>();

		// Prefer using non-Tor nodes with the most channels as the introduction node.
		peer_info.sort_unstable_by(|(_, a_tor_only, a_channels), (_, b_tor_only, b_channels)| {
			a_tor_only.cmp(b_tor_only).then(a_channels.cmp(b_channels).reverse())
		});

		let paths = peer_info.into_iter()
			.map(|(peer, _, _)| {
				BlindedPath::new_for_message(&[peer], recipient, &*self.entropy_source, secp_ctx)
			})
			.take(MAX_PATHS)
			.collect::<Result<Vec<_>, _>>();

		let mut paths = match paths {
			Ok(paths) if !paths.is_empty() => Ok(paths),
			_ => {
				if is_recipient_announced {
					BlindedPath::one_hop_for_message(recipient, &*self.entropy_source, secp_ctx)
						.map(|path| vec![path])
				} else {
					Err(())
				}
			},
		}?;

		if compact_paths {
			for path in &mut paths {
				path.use_compact_introduction_node(&network_graph);
			}
		}

		Ok(paths)
	}
}

impl<G: Deref<Target=NetworkGraph<L>>, L: Deref, ES: Deref> MessageRouter for DefaultMessageRouter<G, L, ES>
where
	L::Target: Logger,
	ES::Target: EntropySource,
{
	fn find_path(
		&self, sender: PublicKey, peers: Vec<PublicKey>, mut destination: Destination
	) -> Result<OnionMessagePath, ()> {
		let network_graph = self.network_graph.deref().read_only();
		destination.resolve(&network_graph);

		let first_node = match destination.first_node() {
			Some(first_node) => first_node,
			None => return Err(()),
		};

		if peers.contains(&first_node) || sender == first_node {
			Ok(OnionMessagePath {
				intermediate_nodes: vec![], destination, first_node_addresses: None
			})
		} else {
			let node_details = network_graph
				.node(&NodeId::from_pubkey(&first_node))
				.and_then(|node_info| node_info.announcement_info.as_ref())
				.map(|announcement_info| (announcement_info.features(), announcement_info.addresses()));

			match node_details {
				Some((features, addresses)) if features.supports_onion_messages() && addresses.len() > 0 => {
					let first_node_addresses = Some(addresses.clone());
					Ok(OnionMessagePath {
						intermediate_nodes: vec![], destination, first_node_addresses
					})
				},
				_ => Err(()),
			}
		}
	}

	fn create_blinded_paths<
		T: secp256k1::Signing + secp256k1::Verification
	>(
		&self, recipient: PublicKey, peers: Vec<PublicKey>, secp_ctx: &Secp256k1<T>,
	) -> Result<Vec<BlindedPath>, ()> {
		let peers = peers
			.into_iter()
			.map(|node_id| ForwardNode { node_id, short_channel_id: None });
		self.create_blinded_paths_from_iter(recipient, peers, secp_ctx, false)
	}

	fn create_compact_blinded_paths<
		T: secp256k1::Signing + secp256k1::Verification
	>(
		&self, recipient: PublicKey, peers: Vec<ForwardNode>, secp_ctx: &Secp256k1<T>,
	) -> Result<Vec<BlindedPath>, ()> {
		self.create_blinded_paths_from_iter(recipient, peers.into_iter(), secp_ctx, true)
	}
}

/// A path for sending an [`OnionMessage`].
#[derive(Clone)]
pub struct OnionMessagePath {
	/// Nodes on the path between the sender and the destination.
	pub intermediate_nodes: Vec<PublicKey>,

	/// The recipient of the message.
	pub destination: Destination,

	/// Addresses that may be used to connect to [`OnionMessagePath::first_node`].
	///
	/// Only needs to be set if a connection to the node is required. [`OnionMessenger`] may use
	/// this to initiate such a connection.
	pub first_node_addresses: Option<Vec<SocketAddress>>,
}

impl OnionMessagePath {
	/// Returns the first node in the path.
	pub fn first_node(&self) -> Option<PublicKey> {
		self.intermediate_nodes
			.first()
			.copied()
			.or_else(|| self.destination.first_node())
	}
}

/// The destination of an onion message.
#[derive(Clone, Hash, Debug, PartialEq, Eq)]
pub enum Destination {
	/// We're sending this onion message to a node.
	Node(PublicKey),
	/// We're sending this onion message to a blinded path.
	BlindedPath(BlindedPath),
}

impl Destination {
	/// Attempts to resolve the [`IntroductionNode::DirectedShortChannelId`] of a
	/// [`Destination::BlindedPath`] to a [`IntroductionNode::NodeId`], if applicable, using the
	/// provided [`ReadOnlyNetworkGraph`].
	pub fn resolve(&mut self, network_graph: &ReadOnlyNetworkGraph) {
		if let Destination::BlindedPath(path) = self {
			if let IntroductionNode::DirectedShortChannelId(..) = path.introduction_node {
				if let Some(pubkey) = path
					.public_introduction_node_id(network_graph)
					.and_then(|node_id| node_id.as_pubkey().ok())
				{
					path.introduction_node = IntroductionNode::NodeId(pubkey);
				}
			}
		}
	}

	pub(super) fn num_hops(&self) -> usize {
		match self {
			Destination::Node(_) => 1,
			Destination::BlindedPath(BlindedPath { blinded_hops, .. }) => blinded_hops.len(),
		}
	}

	fn first_node(&self) -> Option<PublicKey> {
		match self {
			Destination::Node(node_id) => Some(*node_id),
			Destination::BlindedPath(BlindedPath { introduction_node, .. }) => {
				match introduction_node {
					IntroductionNode::NodeId(pubkey) => Some(*pubkey),
					IntroductionNode::DirectedShortChannelId(..) => None,
				}
			},
		}
	}
}

/// Result of successfully [sending an onion message].
///
/// [sending an onion message]: OnionMessenger::send_onion_message
#[derive(Clone, Hash, Debug, PartialEq, Eq)]
pub enum SendSuccess {
	/// The message was buffered and will be sent once it is processed by
	/// [`OnionMessageHandler::next_onion_message_for_peer`].
	Buffered,
	/// The message was buffered and will be sent once the node is connected as a peer and it is
	/// processed by [`OnionMessageHandler::next_onion_message_for_peer`].
	BufferedAwaitingConnection(PublicKey),
}

/// Errors that may occur when [sending an onion message].
///
/// [sending an onion message]: OnionMessenger::send_onion_message
#[derive(Clone, Hash, Debug, PartialEq, Eq)]
pub enum SendError {
	/// Errored computing onion message packet keys.
	Secp256k1(secp256k1::Error),
	/// Because implementations such as Eclair will drop onion messages where the message packet
	/// exceeds 32834 bytes, we refuse to send messages where the packet exceeds this size.
	TooBigPacket,
	/// The provided [`Destination`] was an invalid [`BlindedPath`] due to not having any blinded
	/// hops.
	TooFewBlindedHops,
	/// The first hop is not a peer and doesn't have a known [`SocketAddress`].
	InvalidFirstHop(PublicKey),
	/// Indicates that a path could not be found by the [`MessageRouter`].
	///
	/// This occurs when either:
	/// - No path from the sender to the destination was found to send the onion message
	/// - No reply path to the sender could be created when responding to an onion message
	PathNotFound,
	/// Onion message contents must have a TLV type >= 64.
	InvalidMessage,
	/// Our next-hop peer's buffer was full or our total outbound buffer was full.
	BufferFull,
	/// Failed to retrieve our node id from the provided [`NodeSigner`].
	///
	/// [`NodeSigner`]: crate::sign::NodeSigner
	GetNodeIdFailed,
	/// The provided [`Destination`] has a blinded path with an unresolved introduction node. An
	/// attempt to resolve it in the [`MessageRouter`] when finding an [`OnionMessagePath`] likely
	/// failed.
	UnresolvedIntroductionNode,
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
	fn handle_custom_message(&self, message: Self::CustomMessage, responder: Option<Responder>) -> ResponseInstruction<Self::CustomMessage>;

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
#[derive(Clone, Debug)]
pub enum PeeledOnion<T: OnionMessageContents> {
	/// Forwarded onion, with the next node id and a new onion
	Forward(NextMessageHop, OnionMessage),
	/// Received onion message, with decrypted contents, path_id, and reply path
	Receive(ParsedOnionMessageContents<T>, Option<[u8; 32]>, Option<BlindedPath>)
}


/// Creates an [`OnionMessage`] with the given `contents` for sending to the destination of
/// `path`, first calling [`Destination::resolve`] on `path.destination` with the given
/// [`ReadOnlyNetworkGraph`].
///
/// Returns the node id of the peer to send the message to, the message itself, and any addresses
/// needed to connect to the first node.
pub fn create_onion_message_resolving_destination<
	ES: Deref, NS: Deref, NL: Deref, T: OnionMessageContents
>(
	entropy_source: &ES, node_signer: &NS, node_id_lookup: &NL,
	network_graph: &ReadOnlyNetworkGraph, secp_ctx: &Secp256k1<secp256k1::All>,
	mut path: OnionMessagePath, contents: T, reply_path: Option<BlindedPath>,
) -> Result<(PublicKey, OnionMessage, Option<Vec<SocketAddress>>), SendError>
where
	ES::Target: EntropySource,
	NS::Target: NodeSigner,
	NL::Target: NodeIdLookUp,
{
	path.destination.resolve(network_graph);
	create_onion_message(
		entropy_source, node_signer, node_id_lookup, secp_ctx, path, contents, reply_path,
	)
}

/// Creates an [`OnionMessage`] with the given `contents` for sending to the destination of
/// `path`.
///
/// Returns the node id of the peer to send the message to, the message itself, and any addresses
/// needed to connect to the first node.
///
/// Returns [`SendError::UnresolvedIntroductionNode`] if:
/// - `destination` contains a blinded path with an [`IntroductionNode::DirectedShortChannelId`],
/// - unless it can be resolved by [`NodeIdLookUp::next_node_id`].
/// Use [`create_onion_message_resolving_destination`] instead to resolve the introduction node
/// first with a [`ReadOnlyNetworkGraph`].
pub fn create_onion_message<ES: Deref, NS: Deref, NL: Deref, T: OnionMessageContents>(
	entropy_source: &ES, node_signer: &NS, node_id_lookup: &NL,
	secp_ctx: &Secp256k1<secp256k1::All>, path: OnionMessagePath, contents: T,
	reply_path: Option<BlindedPath>,
) -> Result<(PublicKey, OnionMessage, Option<Vec<SocketAddress>>), SendError>
where
	ES::Target: EntropySource,
	NS::Target: NodeSigner,
	NL::Target: NodeIdLookUp,
{
	let OnionMessagePath { intermediate_nodes, mut destination, first_node_addresses } = path;
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
			let introduction_node_id = match blinded_path.introduction_node {
				IntroductionNode::NodeId(pubkey) => pubkey,
				IntroductionNode::DirectedShortChannelId(direction, scid) => {
					match node_id_lookup.next_node_id(scid) {
						Some(next_node_id) => *direction.select_pubkey(&our_node_id, &next_node_id),
						None => return Err(SendError::UnresolvedIntroductionNode),
					}
				},
			};
			if introduction_node_id == our_node_id {
				advance_path_by_one(blinded_path, node_signer, node_id_lookup, &secp_ctx)
					.map_err(|()| SendError::BlindedPathAdvanceFailed)?;
			}
		}
	}

	let blinding_secret_bytes = entropy_source.get_secure_random_bytes();
	let blinding_secret = SecretKey::from_slice(&blinding_secret_bytes[..]).expect("RNG is busted");
	let (first_node_id, blinding_point) = if let Some(first_node_id) = intermediate_nodes.first() {
		(*first_node_id, PublicKey::from_secret_key(&secp_ctx, &blinding_secret))
	} else {
		match &destination {
			Destination::Node(pk) => (*pk, PublicKey::from_secret_key(&secp_ctx, &blinding_secret)),
			Destination::BlindedPath(BlindedPath { introduction_node, blinding_point, .. }) => {
				match introduction_node {
					IntroductionNode::NodeId(pubkey) => (*pubkey, *blinding_point),
					IntroductionNode::DirectedShortChannelId(..) => {
						return Err(SendError::UnresolvedIntroductionNode);
					},
				}
			}
		}
	};
	let (packet_payloads, packet_keys) = packet_payloads_and_keys(
		&secp_ctx, &intermediate_nodes, destination, contents, reply_path, &blinding_secret
	)?;

	let prng_seed = entropy_source.get_secure_random_bytes();
	let onion_routing_packet = construct_onion_message_packet(
		packet_payloads, packet_keys, prng_seed).map_err(|()| SendError::TooBigPacket)?;

	let message = OnionMessage { blinding_point, onion_routing_packet };
	Ok((first_node_id, message, first_node_addresses))
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
			Hmac::from_engine(hmac).to_byte_array()
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
			next_hop, next_blinding_override
		})), Some((next_hop_hmac, new_packet_bytes)))) => {
			// TODO: we need to check whether `next_hop` is our node, in which case this is a dummy
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

			Ok(PeeledOnion::Forward(next_hop, onion_message))
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

impl<ES: Deref, NS: Deref, L: Deref, NL: Deref, MR: Deref, OMH: Deref, APH: Deref, CMH: Deref>
OnionMessenger<ES, NS, L, NL, MR, OMH, APH, CMH>
where
	ES::Target: EntropySource,
	NS::Target: NodeSigner,
	L::Target: Logger,
	NL::Target: NodeIdLookUp,
	MR::Target: MessageRouter,
	OMH::Target: OffersMessageHandler,
	APH::Target: AsyncPaymentsMessageHandler,
	CMH::Target: CustomOnionMessageHandler,
{
	/// Constructs a new `OnionMessenger` to send, forward, and delegate received onion messages to
	/// their respective handlers.
	pub fn new(
		entropy_source: ES, node_signer: NS, logger: L, node_id_lookup: NL, message_router: MR,
		offers_handler: OMH, async_payments_handler: APH, custom_handler: CMH
	) -> Self {
		Self::new_inner(
			entropy_source, node_signer, logger, node_id_lookup, message_router,
			offers_handler, async_payments_handler, custom_handler, false
		)
	}

	/// Similar to [`Self::new`], but rather than dropping onion messages that are
	/// intended to be forwarded to offline peers, we will intercept them for
	/// later forwarding.
	///
	/// Interception flow:
	/// 1. If an onion message for an offline peer is received, `OnionMessenger` will
	///    generate an [`Event::OnionMessageIntercepted`]. Event handlers can
	///    then choose to persist this onion message for later forwarding, or drop
	///    it.
	/// 2. When the offline peer later comes back online, `OnionMessenger` will
	///    generate an [`Event::OnionMessagePeerConnected`]. Event handlers will
	///    then fetch all previously intercepted onion messages for this peer.
	/// 3. Once the stored onion messages are fetched, they can finally be
	///    forwarded to the now-online peer via [`Self::forward_onion_message`].
	///
	/// # Note
	///
	/// LDK will not rate limit how many [`Event::OnionMessageIntercepted`]s
	/// are generated, so it is the caller's responsibility to limit how many
	/// onion messages are persisted and only persist onion messages for relevant
	/// peers.
	pub fn new_with_offline_peer_interception(
		entropy_source: ES, node_signer: NS, logger: L, node_id_lookup: NL,
		message_router: MR, offers_handler: OMH, async_payments_handler: APH, custom_handler: CMH
	) -> Self {
		Self::new_inner(
			entropy_source, node_signer, logger, node_id_lookup, message_router,
			offers_handler, async_payments_handler, custom_handler, true
		)
	}

	fn new_inner(
		entropy_source: ES, node_signer: NS, logger: L, node_id_lookup: NL,
		message_router: MR, offers_handler: OMH, async_payments_handler: APH, custom_handler: CMH,
		intercept_messages_for_offline_peers: bool
	) -> Self {
		let mut secp_ctx = Secp256k1::new();
		secp_ctx.seeded_randomize(&entropy_source.get_secure_random_bytes());
		OnionMessenger {
			entropy_source,
			node_signer,
			message_recipients: Mutex::new(new_hash_map()),
			secp_ctx,
			logger,
			node_id_lookup,
			message_router,
			offers_handler,
			async_payments_handler,
			custom_handler,
			intercept_messages_for_offline_peers,
			pending_events: Mutex::new(PendingEvents {
				intercepted_msgs: Vec::new(),
				peer_connecteds: Vec::new(),
			}),
		}
	}

	#[cfg(test)]
	pub(crate) fn set_offers_handler(&mut self, offers_handler: OMH) {
		self.offers_handler = offers_handler;
	}

	/// Sends an [`OnionMessage`] with the given `contents` to `destination`.
	///
	/// See [`OnionMessenger`] for example usage.
	pub fn send_onion_message<T: OnionMessageContents>(
		&self, contents: T, destination: Destination, reply_path: Option<BlindedPath>
	) -> Result<SendSuccess, SendError> {
		self.find_path_and_enqueue_onion_message(
			contents, destination, reply_path, format_args!("")
		)
	}

	fn find_path_and_enqueue_onion_message<T: OnionMessageContents>(
		&self, contents: T, destination: Destination, reply_path: Option<BlindedPath>,
		log_suffix: fmt::Arguments
	) -> Result<SendSuccess, SendError> {
		let mut logger = WithContext::from(&self.logger, None, None, None);
		let result = self.find_path(destination).and_then(|path| {
			let first_hop = path.intermediate_nodes.get(0).map(|p| *p);
			logger = WithContext::from(&self.logger, first_hop, None, None);
			self.enqueue_onion_message(path, contents, reply_path, log_suffix)
		});

		match result.as_ref() {
			Err(SendError::GetNodeIdFailed) => {
				log_warn!(logger, "Unable to retrieve node id {}", log_suffix);
			},
			Err(SendError::PathNotFound) => {
				log_trace!(logger, "Failed to find path {}", log_suffix);
			},
			Err(e) => {
				log_trace!(logger, "Failed sending onion message {}: {:?}", log_suffix, e);
			},
			Ok(SendSuccess::Buffered) => {
				log_trace!(logger, "Buffered onion message {}", log_suffix);
			},
			Ok(SendSuccess::BufferedAwaitingConnection(node_id)) => {
				log_trace!(
					logger,
					"Buffered onion message waiting on peer connection {}: {}",
					log_suffix, node_id
				);
			},
		}

		result
	}

	fn find_path(&self, destination: Destination) -> Result<OnionMessagePath, SendError> {
		let sender = self.node_signer
			.get_node_id(Recipient::Node)
			.map_err(|_| SendError::GetNodeIdFailed)?;

		let peers = self.message_recipients.lock().unwrap()
			.iter()
			.filter(|(_, recipient)| matches!(recipient, OnionMessageRecipient::ConnectedPeer(_)))
			.map(|(node_id, _)| *node_id)
			.collect();

		self.message_router
			.find_path(sender, peers, destination)
			.map_err(|_| SendError::PathNotFound)
	}

	fn create_blinded_path(&self) -> Result<BlindedPath, SendError> {
		let recipient = self.node_signer
			.get_node_id(Recipient::Node)
			.map_err(|_| SendError::GetNodeIdFailed)?;
		let secp_ctx = &self.secp_ctx;

		let peers = self.message_recipients.lock().unwrap()
			.iter()
			.filter(|(_, peer)| matches!(peer, OnionMessageRecipient::ConnectedPeer(_)))
			.map(|(node_id, _ )| *node_id)
			.collect::<Vec<_>>();

		self.message_router
			.create_blinded_paths(recipient, peers, secp_ctx)
			.and_then(|paths| paths.into_iter().next().ok_or(()))
			.map_err(|_| SendError::PathNotFound)
	}

	fn enqueue_onion_message<T: OnionMessageContents>(
		&self, path: OnionMessagePath, contents: T, reply_path: Option<BlindedPath>,
		log_suffix: fmt::Arguments
	) -> Result<SendSuccess, SendError> {
		log_trace!(self.logger, "Constructing onion message {}: {:?}", log_suffix, contents);

		let (first_node_id, onion_message, addresses) = create_onion_message(
			&self.entropy_source, &self.node_signer, &self.node_id_lookup, &self.secp_ctx, path,
			contents, reply_path,
		)?;

		let mut message_recipients = self.message_recipients.lock().unwrap();
		if outbound_buffer_full(&first_node_id, &message_recipients) {
			return Err(SendError::BufferFull);
		}

		match message_recipients.entry(first_node_id) {
			hash_map::Entry::Vacant(e) => match addresses {
				None => Err(SendError::InvalidFirstHop(first_node_id)),
				Some(addresses) => {
					e.insert(OnionMessageRecipient::pending_connection(addresses))
						.enqueue_message(onion_message);
					Ok(SendSuccess::BufferedAwaitingConnection(first_node_id))
				},
			},
			hash_map::Entry::Occupied(mut e) => {
				e.get_mut().enqueue_message(onion_message);
				if e.get().is_connected() {
					Ok(SendSuccess::Buffered)
				} else {
					Ok(SendSuccess::BufferedAwaitingConnection(first_node_id))
				}
			},
		}
	}

	/// Forwards an [`OnionMessage`] to `peer_node_id`. Useful if we initialized
	/// the [`OnionMessenger`] with [`Self::new_with_offline_peer_interception`]
	/// and want to forward a previously intercepted onion message to a peer that
	/// has just come online.
	pub fn forward_onion_message(
		&self, message: OnionMessage, peer_node_id: &PublicKey
	) -> Result<(), SendError> {
		let mut message_recipients = self.message_recipients.lock().unwrap();
		if outbound_buffer_full(&peer_node_id, &message_recipients) {
			return Err(SendError::BufferFull);
		}

		match message_recipients.entry(*peer_node_id) {
			hash_map::Entry::Occupied(mut e) if e.get().is_connected() => {
				e.get_mut().enqueue_message(message);
				Ok(())
			},
			_ => Err(SendError::InvalidFirstHop(*peer_node_id))
		}
	}

	#[cfg(any(test, feature = "_test_utils"))]
	pub fn send_onion_message_using_path<T: OnionMessageContents>(
		&self, path: OnionMessagePath, contents: T, reply_path: Option<BlindedPath>
	) -> Result<SendSuccess, SendError> {
		self.enqueue_onion_message(path, contents, reply_path, format_args!(""))
	}

	pub(crate) fn peel_onion_message(
		&self, msg: &OnionMessage
	) -> Result<PeeledOnion<<<CMH>::Target as CustomOnionMessageHandler>::CustomMessage>, ()> {
		peel_onion_message(
			msg, &self.secp_ctx, &*self.node_signer, &*self.logger, &*self.custom_handler
		)
	}

	/// Handles the response to an [`OnionMessage`] based on its [`ResponseInstruction`],
	/// enqueueing any response for sending.
	///
	/// This function is useful for asynchronous handling of [`OnionMessage`]s.
	/// Handlers have the option to return [`ResponseInstruction::NoResponse`], indicating that
	/// no immediate response should be sent. Then, they can transfer the associated [`Responder`]
	/// to another task responsible for generating the response asynchronously. Subsequently, when
	/// the response is prepared and ready for sending, that task can invoke this method to enqueue
	/// the response for delivery.
	pub fn handle_onion_message_response<T: OnionMessageContents>(
		&self, response: ResponseInstruction<T>
	) -> Result<Option<SendSuccess>, SendError> {
		let (response, create_reply_path) = match response {
			ResponseInstruction::WithReplyPath(response) => (response, true),
			ResponseInstruction::WithoutReplyPath(response) => (response, false),
			ResponseInstruction::NoResponse => return Ok(None),
		};

		let message_type = response.message.msg_type();
		let reply_path = if create_reply_path {
			match self.create_blinded_path() {
				Ok(reply_path) => Some(reply_path),
				Err(err) => {
					log_trace!(
						self.logger,
						"Failed to create reply path when responding with {} to an onion message \
						with path_id {:02x?}: {:?}",
						message_type, response.path_id, err
					);
					return Err(err);
				}
			}
		} else { None };

		self.find_path_and_enqueue_onion_message(
			response.message, Destination::BlindedPath(response.reply_path), reply_path,
			format_args!(
				"when responding with {} to an onion message with path_id {:02x?}",
				message_type,
				response.path_id
			)
		).map(|result| Some(result))
	}

	#[cfg(test)]
	pub(super) fn release_pending_msgs(&self) -> HashMap<PublicKey, VecDeque<OnionMessage>> {
		let mut message_recipients = self.message_recipients.lock().unwrap();
		let mut msgs = new_hash_map();
		// We don't want to disconnect the peers by removing them entirely from the original map, so we
		// release the pending message buffers individually.
		for (node_id, recipient) in &mut *message_recipients {
			msgs.insert(*node_id, recipient.release_pending_messages());
		}
		msgs
	}

	fn enqueue_intercepted_event(&self, event: Event) {
		const MAX_EVENTS_BUFFER_SIZE: usize = (1 << 10) * 256;
		let mut pending_events = self.pending_events.lock().unwrap();
		let total_buffered_bytes: usize =
			pending_events.intercepted_msgs.iter().map(|ev| ev.serialized_length()).sum();
		if total_buffered_bytes >= MAX_EVENTS_BUFFER_SIZE {
			log_trace!(self.logger, "Dropping event {:?}: buffer full", event);
			return
		}
		pending_events.intercepted_msgs.push(event);
	}

	/// Processes any events asynchronously using the given handler.
	///
	/// Note that the event handler is called in the order each event was generated, however
	/// futures are polled in parallel for some events to allow for parallelism where events do not
	/// have an ordering requirement.
	///
	/// See the trait-level documentation of [`EventsProvider`] for requirements.
	pub async fn process_pending_events_async<Future: core::future::Future<Output = ()> + core::marker::Unpin, H: Fn(Event) -> Future>(
		&self, handler: H
	) {
		let mut intercepted_msgs = Vec::new();
		let mut peer_connecteds = Vec::new();
		{
			let mut pending_events = self.pending_events.lock().unwrap();
			core::mem::swap(&mut pending_events.intercepted_msgs, &mut intercepted_msgs);
			core::mem::swap(&mut pending_events.peer_connecteds, &mut peer_connecteds);
		}

		let mut futures = Vec::with_capacity(intercepted_msgs.len());
		for (node_id, recipient) in self.message_recipients.lock().unwrap().iter_mut() {
			if let OnionMessageRecipient::PendingConnection(_, addresses, _) = recipient {
				if let Some(addresses) = addresses.take() {
					futures.push(Some(handler(Event::ConnectionNeeded { node_id: *node_id, addresses })));
				}
			}
		}

		for ev in intercepted_msgs {
			if let Event::OnionMessageIntercepted { .. } = ev {} else { debug_assert!(false); }
			futures.push(Some(handler(ev)));
		}
		// Let the `OnionMessageIntercepted` events finish before moving on to peer_connecteds
		crate::util::async_poll::MultiFuturePoller(futures).await;

		if peer_connecteds.len() <= 1 {
			for event in peer_connecteds { handler(event).await; }
		} else {
			let mut futures = Vec::new();
			for event in peer_connecteds {
				futures.push(Some(handler(event)));
			}
			crate::util::async_poll::MultiFuturePoller(futures).await;
		}
	}
}

fn outbound_buffer_full(peer_node_id: &PublicKey, buffer: &HashMap<PublicKey, OnionMessageRecipient>) -> bool {
	const MAX_TOTAL_BUFFER_SIZE: usize = (1 << 20) * 128;
	const MAX_PER_PEER_BUFFER_SIZE: usize = (1 << 10) * 256;
	let mut total_buffered_bytes = 0;
	let mut peer_buffered_bytes = 0;
	for (pk, peer_buf) in buffer {
		for om in peer_buf.pending_messages() {
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

impl<ES: Deref, NS: Deref, L: Deref, NL: Deref, MR: Deref, OMH: Deref, APH: Deref, CMH: Deref> EventsProvider
for OnionMessenger<ES, NS, L, NL, MR, OMH, APH, CMH>
where
	ES::Target: EntropySource,
	NS::Target: NodeSigner,
	L::Target: Logger,
	NL::Target: NodeIdLookUp,
	MR::Target: MessageRouter,
	OMH::Target: OffersMessageHandler,
	APH::Target: AsyncPaymentsMessageHandler,
	CMH::Target: CustomOnionMessageHandler,
{
	fn process_pending_events<H: Deref>(&self, handler: H) where H::Target: EventHandler {
		for (node_id, recipient) in self.message_recipients.lock().unwrap().iter_mut() {
			if let OnionMessageRecipient::PendingConnection(_, addresses, _) = recipient {
				if let Some(addresses) = addresses.take() {
					handler.handle_event(Event::ConnectionNeeded { node_id: *node_id, addresses });
				}
			}
		}
		let mut events = Vec::new();
		{
			let mut pending_events = self.pending_events.lock().unwrap();
			#[cfg(debug_assertions)] {
				for ev in pending_events.intercepted_msgs.iter() {
					if let Event::OnionMessageIntercepted { .. } = ev {} else { panic!(); }
				}
				for ev in pending_events.peer_connecteds.iter() {
					if let Event::OnionMessagePeerConnected { .. } = ev {} else { panic!(); }
				}
			}
			core::mem::swap(&mut pending_events.intercepted_msgs, &mut events);
			events.append(&mut pending_events.peer_connecteds);
			pending_events.peer_connecteds.shrink_to(10); // Limit total heap usage
		}
		for ev in events {
			handler.handle_event(ev);
		}
	}
}

impl<ES: Deref, NS: Deref, L: Deref, NL: Deref, MR: Deref, OMH: Deref, APH: Deref, CMH: Deref> OnionMessageHandler
for OnionMessenger<ES, NS, L, NL, MR, OMH, APH, CMH>
where
	ES::Target: EntropySource,
	NS::Target: NodeSigner,
	L::Target: Logger,
	NL::Target: NodeIdLookUp,
	MR::Target: MessageRouter,
	OMH::Target: OffersMessageHandler,
	APH::Target: AsyncPaymentsMessageHandler,
	CMH::Target: CustomOnionMessageHandler,
{
	fn handle_onion_message(&self, peer_node_id: &PublicKey, msg: &OnionMessage) {
		let logger = WithContext::from(&self.logger, Some(*peer_node_id), None, None);
		match self.peel_onion_message(msg) {
			Ok(PeeledOnion::Receive(message, path_id, reply_path)) => {
				log_trace!(
					logger,
					"Received an onion message with path_id {:02x?} and {} reply_path: {:?}",
					path_id, if reply_path.is_some() { "a" } else { "no" }, message);

				let responder = reply_path.map(
					|reply_path| Responder::new(reply_path, path_id)
				);
				match message {
					ParsedOnionMessageContents::Offers(msg) => {
						let response_instructions = self.offers_handler.handle_message(msg, responder);
						let _ = self.handle_onion_message_response(response_instructions);
					},
					ParsedOnionMessageContents::AsyncPayments(AsyncPaymentsMessage::HeldHtlcAvailable(msg)) => {
						let response_instructions = self.async_payments_handler.held_htlc_available(
							msg, responder
						);
						let _ = self.handle_onion_message_response(response_instructions);
					},
					ParsedOnionMessageContents::AsyncPayments(AsyncPaymentsMessage::ReleaseHeldHtlc(msg)) => {
						self.async_payments_handler.release_held_htlc(msg);
					},
					ParsedOnionMessageContents::Custom(msg) => {
						let response_instructions = self.custom_handler.handle_custom_message(msg, responder);
						let _ = self.handle_onion_message_response(response_instructions);
					},
				}
			},
			Ok(PeeledOnion::Forward(next_hop, onion_message)) => {
				let next_node_id = match next_hop {
					NextMessageHop::NodeId(pubkey) => pubkey,
					NextMessageHop::ShortChannelId(scid) => match self.node_id_lookup.next_node_id(scid) {
						Some(pubkey) => pubkey,
						None => {
							log_trace!(self.logger, "Dropping forwarded onion messager: unable to resolve next hop using SCID {}", scid);
							return
						},
					},
				};

				let mut message_recipients = self.message_recipients.lock().unwrap();
				if outbound_buffer_full(&next_node_id, &message_recipients) {
					log_trace!(
						logger,
						"Dropping forwarded onion message to peer {}: outbound buffer full",
						next_node_id);
					return
				}

				#[cfg(fuzzing)]
				message_recipients
					.entry(next_node_id)
					.or_insert_with(|| OnionMessageRecipient::ConnectedPeer(VecDeque::new()));

				match message_recipients.entry(next_node_id) {
					hash_map::Entry::Occupied(mut e) if matches!(
						e.get(), OnionMessageRecipient::ConnectedPeer(..)
					) => {
						e.get_mut().enqueue_message(onion_message);
						log_trace!(logger, "Forwarding an onion message to peer {}", next_node_id);
					},
					_ if self.intercept_messages_for_offline_peers => {
						self.enqueue_intercepted_event(
							Event::OnionMessageIntercepted {
								peer_node_id: next_node_id, message: onion_message
							}
						);
					},
					_ => {
						log_trace!(
							logger,
							"Dropping forwarded onion message to disconnected peer {}",
							next_node_id);
						return
					},
				}
			},
			Err(e) => {
				log_error!(logger, "Failed to process onion message {:?}", e);
			}
		}
	}

	fn peer_connected(&self, their_node_id: &PublicKey, init: &msgs::Init, _inbound: bool) -> Result<(), ()> {
		if init.features.supports_onion_messages() {
			self.message_recipients.lock().unwrap()
				.entry(*their_node_id)
				.or_insert_with(|| OnionMessageRecipient::ConnectedPeer(VecDeque::new()))
				.mark_connected();
			if self.intercept_messages_for_offline_peers {
				self.pending_events.lock().unwrap().peer_connecteds.push(
					Event::OnionMessagePeerConnected { peer_node_id: *their_node_id }
				);
			}
		} else {
			self.message_recipients.lock().unwrap().remove(their_node_id);
		}

		Ok(())
	}

	fn peer_disconnected(&self, their_node_id: &PublicKey) {
		match self.message_recipients.lock().unwrap().remove(their_node_id) {
			Some(OnionMessageRecipient::ConnectedPeer(..)) => {},
			Some(_) => debug_assert!(false),
			None => {},
		}
	}

	fn timer_tick_occurred(&self) {
		let mut message_recipients = self.message_recipients.lock().unwrap();

		// Drop any pending recipients since the last call to avoid retaining buffered messages for
		// too long.
		message_recipients.retain(|_, recipient| match recipient {
			OnionMessageRecipient::PendingConnection(_, None, ticks) => *ticks < MAX_TIMER_TICKS,
			OnionMessageRecipient::PendingConnection(_, Some(_), _) => true,
			_ => true,
		});

		// Increment a timer tick for pending recipients so that their buffered messages are dropped
		// at MAX_TIMER_TICKS.
		for recipient in message_recipients.values_mut() {
			if let OnionMessageRecipient::PendingConnection(_, None, ticks) = recipient {
				*ticks += 1;
			}
		}
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
			let _ = self.find_path_and_enqueue_onion_message(
				contents, destination, reply_path, format_args!("when sending OffersMessage")
			);
		}

		// Enqueue any initiating `CustomMessage`s to send.
		for message in self.custom_handler.release_pending_custom_messages() {
			#[cfg(not(c_bindings))]
			let PendingOnionMessage { contents, destination, reply_path } = message;
			#[cfg(c_bindings)]
			let (contents, destination, reply_path) = message;
			let _ = self.find_path_and_enqueue_onion_message(
				contents, destination, reply_path, format_args!("when sending CustomMessage")
			);
		}

		self.message_recipients.lock().unwrap()
			.get_mut(&peer_node_id)
			.and_then(|buffer| buffer.dequeue_message())
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
	Arc<SimpleArcChannelManager<M, T, F, L>>,
	Arc<DefaultMessageRouter<Arc<NetworkGraph<Arc<L>>>, Arc<L>, Arc<KeysManager>>>,
	Arc<SimpleArcChannelManager<M, T, F, L>>,
	IgnoringMessageHandler,
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
	&'i SimpleRefChannelManager<'a, 'b, 'c, 'd, 'e, 'f, 'g, 'h, M, T, F, L>,
	&'j DefaultMessageRouter<&'g NetworkGraph<&'b L>, &'b L, &'a KeysManager>,
	&'i SimpleRefChannelManager<'a, 'b, 'c, 'd, 'e, 'f, 'g, 'h, M, T, F, L>,
	IgnoringMessageHandler,
	IgnoringMessageHandler
>;

/// Construct onion packet payloads and keys for sending an onion message along the given
/// `unblinded_path` to the given `destination`.
fn packet_payloads_and_keys<T: OnionMessageContents, S: secp256k1::Signing + secp256k1::Verification>(
	secp_ctx: &Secp256k1<S>, unblinded_path: &[PublicKey], destination: Destination, message: T,
	mut reply_path: Option<BlindedPath>, session_priv: &SecretKey
) -> Result<(Vec<(Payload<T>, [u8; 32])>, Vec<onion_utils::OnionKeys>), SendError> {
	let num_hops = unblinded_path.len() + destination.num_hops();
	let mut payloads = Vec::with_capacity(num_hops);
	let mut onion_packet_keys = Vec::with_capacity(num_hops);

	let (mut intro_node_id_blinding_pt, num_blinded_hops) = match &destination {
		Destination::Node(_) => (None, 0),
		Destination::BlindedPath(BlindedPath { introduction_node, blinding_point, blinded_hops }) => {
			let introduction_node_id = match introduction_node {
				IntroductionNode::NodeId(pubkey) => pubkey,
				IntroductionNode::DirectedShortChannelId(..) => {
					return Err(SendError::UnresolvedIntroductionNode);
				},
			};
			(Some((*introduction_node_id, *blinding_point)), blinded_hops.len())
		},
	};
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
							next_hop: NextMessageHop::NodeId(unblinded_pk_opt.unwrap()),
							next_blinding_override: None,
						}
					)), ss));
				}
				prev_control_tlvs_ss = Some(control_tlvs_ss);
				unblinded_path_idx += 1;
			} else if let Some((intro_node_id, blinding_pt)) = intro_node_id_blinding_pt.take() {
				if let Some(control_tlvs_ss) = prev_control_tlvs_ss.take() {
					payloads.push((Payload::Forward(ForwardControlTlvs::Unblinded(ForwardTlvs {
						next_hop: NextMessageHop::NodeId(intro_node_id),
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
	).map_err(|e| SendError::Secp256k1(e))?;

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
