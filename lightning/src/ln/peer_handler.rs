// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Top level peer message handling and socket handling logic lives here.
//!
//! Instead of actually servicing sockets ourselves we require that you implement the
//! SocketDescriptor interface and use that to receive actions which you should perform on the
//! socket, and call into PeerManager with bytes read from the socket. The PeerManager will then
//! call into the provided message handlers (probably a ChannelManager and NetGraphmsgHandler) with messages
//! they should handle, and encoding/sending response messages.

use bitcoin::secp256k1::key::{SecretKey,PublicKey};

use ln::features::InitFeatures;
use ln::msgs;
use ln::msgs::{ChannelMessageHandler, LightningError, RoutingMessageHandler};
use ln::channelmanager::{SimpleArcChannelManager, SimpleRefChannelManager};
use util::ser::{VecWriter, Writeable};
use ln::peer_channel_encryptor::{PeerChannelEncryptor,NextNoiseStep};
use ln::wire;
use ln::wire::Encode;
use util::byte_utils;
use util::events::{MessageSendEvent, MessageSendEventsProvider};
use util::logger::Logger;
use routing::network_graph::NetGraphMsgHandler;

use std::collections::{HashMap,hash_map,HashSet,LinkedList};
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::{cmp, error, hash, fmt, mem};
use std::ops::Deref;

use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::sha256::HashEngine as Sha256Engine;
use bitcoin::hashes::{HashEngine, Hash};

/// A dummy struct which implements `RoutingMessageHandler` without storing any routing information
/// or doing any processing. You can provide one of these as the route_handler in a MessageHandler.
pub struct IgnoringMessageHandler{}
impl MessageSendEventsProvider for IgnoringMessageHandler {
	fn get_and_clear_pending_msg_events(&self) -> Vec<MessageSendEvent> { Vec::new() }
}
impl RoutingMessageHandler for IgnoringMessageHandler {
	fn handle_node_announcement(&self, _msg: &msgs::NodeAnnouncement) -> Result<bool, LightningError> { Ok(false) }
	fn handle_channel_announcement(&self, _msg: &msgs::ChannelAnnouncement) -> Result<bool, LightningError> { Ok(false) }
	fn handle_channel_update(&self, _msg: &msgs::ChannelUpdate) -> Result<bool, LightningError> { Ok(false) }
	fn handle_htlc_fail_channel_update(&self, _update: &msgs::HTLCFailChannelUpdate) {}
	fn get_next_channel_announcements(&self, _starting_point: u64, _batch_amount: u8) ->
		Vec<(msgs::ChannelAnnouncement, Option<msgs::ChannelUpdate>, Option<msgs::ChannelUpdate>)> { Vec::new() }
	fn get_next_node_announcements(&self, _starting_point: Option<&PublicKey>, _batch_amount: u8) -> Vec<msgs::NodeAnnouncement> { Vec::new() }
	fn sync_routing_table(&self, _their_node_id: &PublicKey, _init: &msgs::Init) {}
	fn handle_reply_channel_range(&self, _their_node_id: &PublicKey, _msg: msgs::ReplyChannelRange) -> Result<(), LightningError> { Ok(()) }
	fn handle_reply_short_channel_ids_end(&self, _their_node_id: &PublicKey, _msg: msgs::ReplyShortChannelIdsEnd) -> Result<(), LightningError> { Ok(()) }
	fn handle_query_channel_range(&self, _their_node_id: &PublicKey, _msg: msgs::QueryChannelRange) -> Result<(), LightningError> { Ok(()) }
	fn handle_query_short_channel_ids(&self, _their_node_id: &PublicKey, _msg: msgs::QueryShortChannelIds) -> Result<(), LightningError> { Ok(()) }
}
impl Deref for IgnoringMessageHandler {
	type Target = IgnoringMessageHandler;
	fn deref(&self) -> &Self { self }
}

/// A dummy struct which implements `ChannelMessageHandler` without having any channels.
/// You can provide one of these as the route_handler in a MessageHandler.
pub struct ErroringMessageHandler {
	message_queue: Mutex<Vec<MessageSendEvent>>
}
impl ErroringMessageHandler {
	/// Constructs a new ErroringMessageHandler
	pub fn new() -> Self {
		Self { message_queue: Mutex::new(Vec::new()) }
	}
	fn push_error(&self, node_id: &PublicKey, channel_id: [u8; 32]) {
		self.message_queue.lock().unwrap().push(MessageSendEvent::HandleError {
			action: msgs::ErrorAction::SendErrorMessage {
				msg: msgs::ErrorMessage { channel_id, data: "We do not support channel messages, sorry.".to_owned() },
			},
			node_id: node_id.clone(),
		});
	}
}
impl MessageSendEventsProvider for ErroringMessageHandler {
	fn get_and_clear_pending_msg_events(&self) -> Vec<MessageSendEvent> {
		let mut res = Vec::new();
		mem::swap(&mut res, &mut self.message_queue.lock().unwrap());
		res
	}
}
impl ChannelMessageHandler for ErroringMessageHandler {
	// Any messages which are related to a specific channel generate an error message to let the
	// peer know we don't care about channels.
	fn handle_open_channel(&self, their_node_id: &PublicKey, _their_features: InitFeatures, msg: &msgs::OpenChannel) {
		ErroringMessageHandler::push_error(self, their_node_id, msg.temporary_channel_id);
	}
	fn handle_accept_channel(&self, their_node_id: &PublicKey, _their_features: InitFeatures, msg: &msgs::AcceptChannel) {
		ErroringMessageHandler::push_error(self, their_node_id, msg.temporary_channel_id);
	}
	fn handle_funding_created(&self, their_node_id: &PublicKey, msg: &msgs::FundingCreated) {
		ErroringMessageHandler::push_error(self, their_node_id, msg.temporary_channel_id);
	}
	fn handle_funding_signed(&self, their_node_id: &PublicKey, msg: &msgs::FundingSigned) {
		ErroringMessageHandler::push_error(self, their_node_id, msg.channel_id);
	}
	fn handle_funding_locked(&self, their_node_id: &PublicKey, msg: &msgs::FundingLocked) {
		ErroringMessageHandler::push_error(self, their_node_id, msg.channel_id);
	}
	fn handle_shutdown(&self, their_node_id: &PublicKey, _their_features: &InitFeatures, msg: &msgs::Shutdown) {
		ErroringMessageHandler::push_error(self, their_node_id, msg.channel_id);
	}
	fn handle_closing_signed(&self, their_node_id: &PublicKey, msg: &msgs::ClosingSigned) {
		ErroringMessageHandler::push_error(self, their_node_id, msg.channel_id);
	}
	fn handle_update_add_htlc(&self, their_node_id: &PublicKey, msg: &msgs::UpdateAddHTLC) {
		ErroringMessageHandler::push_error(self, their_node_id, msg.channel_id);
	}
	fn handle_update_fulfill_htlc(&self, their_node_id: &PublicKey, msg: &msgs::UpdateFulfillHTLC) {
		ErroringMessageHandler::push_error(self, their_node_id, msg.channel_id);
	}
	fn handle_update_fail_htlc(&self, their_node_id: &PublicKey, msg: &msgs::UpdateFailHTLC) {
		ErroringMessageHandler::push_error(self, their_node_id, msg.channel_id);
	}
	fn handle_update_fail_malformed_htlc(&self, their_node_id: &PublicKey, msg: &msgs::UpdateFailMalformedHTLC) {
		ErroringMessageHandler::push_error(self, their_node_id, msg.channel_id);
	}
	fn handle_commitment_signed(&self, their_node_id: &PublicKey, msg: &msgs::CommitmentSigned) {
		ErroringMessageHandler::push_error(self, their_node_id, msg.channel_id);
	}
	fn handle_revoke_and_ack(&self, their_node_id: &PublicKey, msg: &msgs::RevokeAndACK) {
		ErroringMessageHandler::push_error(self, their_node_id, msg.channel_id);
	}
	fn handle_update_fee(&self, their_node_id: &PublicKey, msg: &msgs::UpdateFee) {
		ErroringMessageHandler::push_error(self, their_node_id, msg.channel_id);
	}
	fn handle_announcement_signatures(&self, their_node_id: &PublicKey, msg: &msgs::AnnouncementSignatures) {
		ErroringMessageHandler::push_error(self, their_node_id, msg.channel_id);
	}
	fn handle_channel_reestablish(&self, their_node_id: &PublicKey, msg: &msgs::ChannelReestablish) {
		ErroringMessageHandler::push_error(self, their_node_id, msg.channel_id);
	}
	fn peer_disconnected(&self, _their_node_id: &PublicKey, _no_connection_possible: bool) {}
	fn peer_connected(&self, _their_node_id: &PublicKey, _msg: &msgs::Init) {}
	fn handle_error(&self, _their_node_id: &PublicKey, _msg: &msgs::ErrorMessage) {}
}
impl Deref for ErroringMessageHandler {
	type Target = ErroringMessageHandler;
	fn deref(&self) -> &Self { self }
}

/// Provides references to trait impls which handle different types of messages.
pub struct MessageHandler<CM: Deref, RM: Deref> where
		CM::Target: ChannelMessageHandler,
		RM::Target: RoutingMessageHandler {
	/// A message handler which handles messages specific to channels. Usually this is just a
	/// ChannelManager object or a ErroringMessageHandler.
	pub chan_handler: CM,
	/// A message handler which handles messages updating our knowledge of the network channel
	/// graph. Usually this is just a NetGraphMsgHandlerMonitor object or an IgnoringMessageHandler.
	pub route_handler: RM,
}

/// Provides an object which can be used to send data to and which uniquely identifies a connection
/// to a remote host. You will need to be able to generate multiple of these which meet Eq and
/// implement Hash to meet the PeerManager API.
///
/// For efficiency, Clone should be relatively cheap for this type.
///
/// You probably want to just extend an int and put a file descriptor in a struct and implement
/// send_data. Note that if you are using a higher-level net library that may call close() itself,
/// be careful to ensure you don't have races whereby you might register a new connection with an
/// fd which is the same as a previous one which has yet to be removed via
/// PeerManager::socket_disconnected().
pub trait SocketDescriptor : cmp::Eq + hash::Hash + Clone {
	/// Attempts to send some data from the given slice to the peer.
	///
	/// Returns the amount of data which was sent, possibly 0 if the socket has since disconnected.
	/// Note that in the disconnected case, socket_disconnected must still fire and further write
	/// attempts may occur until that time.
	///
	/// If the returned size is smaller than data.len(), a write_available event must
	/// trigger the next time more data can be written. Additionally, until the a send_data event
	/// completes fully, no further read_events should trigger on the same peer!
	///
	/// If a read_event on this descriptor had previously returned true (indicating that read
	/// events should be paused to prevent DoS in the send buffer), resume_read may be set
	/// indicating that read events on this descriptor should resume. A resume_read of false does
	/// *not* imply that further read events should be paused.
	fn send_data(&mut self, data: &[u8], resume_read: bool) -> usize;
	/// Disconnect the socket pointed to by this SocketDescriptor. Once this function returns, no
	/// more calls to write_buffer_space_avail, read_event or socket_disconnected may be made with
	/// this descriptor. No socket_disconnected call should be generated as a result of this call,
	/// though races may occur whereby disconnect_socket is called after a call to
	/// socket_disconnected but prior to socket_disconnected returning.
	fn disconnect_socket(&mut self);
}

/// Error for PeerManager errors. If you get one of these, you must disconnect the socket and
/// generate no further read_event/write_buffer_space_avail/socket_disconnected calls for the
/// descriptor.
#[derive(Clone)]
pub struct PeerHandleError {
	/// Used to indicate that we probably can't make any future connections to this peer, implying
	/// we should go ahead and force-close any channels we have with it.
	pub no_connection_possible: bool,
}
impl fmt::Debug for PeerHandleError {
	fn fmt(&self, formatter: &mut fmt::Formatter) -> Result<(), fmt::Error> {
		formatter.write_str("Peer Sent Invalid Data")
	}
}
impl fmt::Display for PeerHandleError {
	fn fmt(&self, formatter: &mut fmt::Formatter) -> Result<(), fmt::Error> {
		formatter.write_str("Peer Sent Invalid Data")
	}
}
impl error::Error for PeerHandleError {
	fn description(&self) -> &str {
		"Peer Sent Invalid Data"
	}
}

enum InitSyncTracker{
	NoSyncRequested,
	ChannelsSyncing(u64),
	NodesSyncing(PublicKey),
}

struct Peer {
	channel_encryptor: PeerChannelEncryptor,
	outbound: bool,
	their_node_id: Option<PublicKey>,
	their_features: Option<InitFeatures>,

	pending_outbound_buffer: LinkedList<Vec<u8>>,
	pending_outbound_buffer_first_msg_offset: usize,
	awaiting_write_event: bool,

	pending_read_buffer: Vec<u8>,
	pending_read_buffer_pos: usize,
	pending_read_is_header: bool,

	sync_status: InitSyncTracker,

	awaiting_pong: bool,
}

impl Peer {
	/// Returns true if the channel announcements/updates for the given channel should be
	/// forwarded to this peer.
	/// If we are sending our routing table to this peer and we have not yet sent channel
	/// announcements/updates for the given channel_id then we will send it when we get to that
	/// point and we shouldn't send it yet to avoid sending duplicate updates. If we've already
	/// sent the old versions, we should send the update, and so return true here.
	fn should_forward_channel_announcement(&self, channel_id: u64)->bool{
		match self.sync_status {
			InitSyncTracker::NoSyncRequested => true,
			InitSyncTracker::ChannelsSyncing(i) => i < channel_id,
			InitSyncTracker::NodesSyncing(_) => true,
		}
	}

	/// Similar to the above, but for node announcements indexed by node_id.
	fn should_forward_node_announcement(&self, node_id: PublicKey) -> bool {
		match self.sync_status {
			InitSyncTracker::NoSyncRequested => true,
			InitSyncTracker::ChannelsSyncing(_) => false,
			InitSyncTracker::NodesSyncing(pk) => pk < node_id,
		}
	}
}

struct PeerHolder<Descriptor: SocketDescriptor> {
	peers: HashMap<Descriptor, Peer>,
	/// Added to by do_read_event for cases where we pushed a message onto the send buffer but
	/// didn't call do_attempt_write_data to avoid reentrancy. Cleared in process_events()
	peers_needing_send: HashSet<Descriptor>,
	/// Only add to this set when noise completes:
	node_id_to_descriptor: HashMap<PublicKey, Descriptor>,
}

#[cfg(not(any(target_pointer_width = "32", target_pointer_width = "64")))]
fn _check_usize_is_32_or_64() {
	// See below, less than 32 bit pointers may be unsafe here!
	unsafe { mem::transmute::<*const usize, [u8; 4]>(panic!()); }
}

/// SimpleArcPeerManager is useful when you need a PeerManager with a static lifetime, e.g.
/// when you're using lightning-net-tokio (since tokio::spawn requires parameters with static
/// lifetimes). Other times you can afford a reference, which is more efficient, in which case
/// SimpleRefPeerManager is the more appropriate type. Defining these type aliases prevents
/// issues such as overly long function definitions.
pub type SimpleArcPeerManager<SD, M, T, F, C, L> = PeerManager<SD, Arc<SimpleArcChannelManager<M, T, F, L>>, Arc<NetGraphMsgHandler<Arc<C>, Arc<L>>>, Arc<L>>;

/// SimpleRefPeerManager is a type alias for a PeerManager reference, and is the reference
/// counterpart to the SimpleArcPeerManager type alias. Use this type by default when you don't
/// need a PeerManager with a static lifetime. You'll need a static lifetime in cases such as
/// usage of lightning-net-tokio (since tokio::spawn requires parameters with static lifetimes).
/// But if this is not necessary, using a reference is more efficient. Defining these type aliases
/// helps with issues such as long function definitions.
pub type SimpleRefPeerManager<'a, 'b, 'c, 'd, 'e, 'f, 'g, SD, M, T, F, C, L> = PeerManager<SD, SimpleRefChannelManager<'a, 'b, 'c, 'd, 'e, M, T, F, L>, &'e NetGraphMsgHandler<&'g C, &'f L>, &'f L>;

/// A PeerManager manages a set of peers, described by their SocketDescriptor and marshalls socket
/// events into messages which it passes on to its MessageHandlers.
///
/// Rather than using a plain PeerManager, it is preferable to use either a SimpleArcPeerManager
/// a SimpleRefPeerManager, for conciseness. See their documentation for more details, but
/// essentially you should default to using a SimpleRefPeerManager, and use a
/// SimpleArcPeerManager when you require a PeerManager with a static lifetime, such as when
/// you're using lightning-net-tokio.
pub struct PeerManager<Descriptor: SocketDescriptor, CM: Deref, RM: Deref, L: Deref> where
		CM::Target: ChannelMessageHandler,
		RM::Target: RoutingMessageHandler,
		L::Target: Logger {
	message_handler: MessageHandler<CM, RM>,
	peers: Mutex<PeerHolder<Descriptor>>,
	our_node_secret: SecretKey,
	ephemeral_key_midstate: Sha256Engine,

	// Usize needs to be at least 32 bits to avoid overflowing both low and high. If usize is 64
	// bits we will never realistically count into high:
	peer_counter_low: AtomicUsize,
	peer_counter_high: AtomicUsize,

	logger: L,
}

enum MessageHandlingError {
	PeerHandleError(PeerHandleError),
	LightningError(LightningError),
}

impl From<PeerHandleError> for MessageHandlingError {
	fn from(error: PeerHandleError) -> Self {
		MessageHandlingError::PeerHandleError(error)
	}
}

impl From<LightningError> for MessageHandlingError {
	fn from(error: LightningError) -> Self {
		MessageHandlingError::LightningError(error)
	}
}

macro_rules! encode_msg {
	($msg: expr) => {{
		let mut buffer = VecWriter(Vec::new());
		wire::write($msg, &mut buffer).unwrap();
		buffer.0
	}}
}

impl<Descriptor: SocketDescriptor, CM: Deref, L: Deref> PeerManager<Descriptor, CM, IgnoringMessageHandler, L> where
		CM::Target: ChannelMessageHandler,
		L::Target: Logger {
	/// Constructs a new PeerManager with the given ChannelMessageHandler. No routing message
	/// handler is used and network graph messages are ignored.
	///
	/// ephemeral_random_data is used to derive per-connection ephemeral keys and must be
	/// cryptographically secure random bytes.
	///
	/// (C-not exported) as we can't export a PeerManager with a dummy route handler
	pub fn new_channel_only(channel_message_handler: CM, our_node_secret: SecretKey, ephemeral_random_data: &[u8; 32], logger: L) -> Self {
		Self::new(MessageHandler {
			chan_handler: channel_message_handler,
			route_handler: IgnoringMessageHandler{},
		}, our_node_secret, ephemeral_random_data, logger)
	}
}

impl<Descriptor: SocketDescriptor, RM: Deref, L: Deref> PeerManager<Descriptor, ErroringMessageHandler, RM, L> where
		RM::Target: RoutingMessageHandler,
		L::Target: Logger {
	/// Constructs a new PeerManager with the given RoutingMessageHandler. No channel message
	/// handler is used and messages related to channels will be ignored (or generate error
	/// messages). Note that some other lightning implementations time-out connections after some
	/// time if no channel is built with the peer.
	///
	/// ephemeral_random_data is used to derive per-connection ephemeral keys and must be
	/// cryptographically secure random bytes.
	///
	/// (C-not exported) as we can't export a PeerManager with a dummy channel handler
	pub fn new_routing_only(routing_message_handler: RM, our_node_secret: SecretKey, ephemeral_random_data: &[u8; 32], logger: L) -> Self {
		Self::new(MessageHandler {
			chan_handler: ErroringMessageHandler::new(),
			route_handler: routing_message_handler,
		}, our_node_secret, ephemeral_random_data, logger)
	}
}

/// Manages and reacts to connection events. You probably want to use file descriptors as PeerIds.
/// PeerIds may repeat, but only after socket_disconnected() has been called.
impl<Descriptor: SocketDescriptor, CM: Deref, RM: Deref, L: Deref> PeerManager<Descriptor, CM, RM, L> where
		CM::Target: ChannelMessageHandler,
		RM::Target: RoutingMessageHandler,
		L::Target: Logger {
	/// Constructs a new PeerManager with the given message handlers and node_id secret key
	/// ephemeral_random_data is used to derive per-connection ephemeral keys and must be
	/// cryptographically secure random bytes.
	pub fn new(message_handler: MessageHandler<CM, RM>, our_node_secret: SecretKey, ephemeral_random_data: &[u8; 32], logger: L) -> Self {
		let mut ephemeral_key_midstate = Sha256::engine();
		ephemeral_key_midstate.input(ephemeral_random_data);

		PeerManager {
			message_handler,
			peers: Mutex::new(PeerHolder {
				peers: HashMap::new(),
				peers_needing_send: HashSet::new(),
				node_id_to_descriptor: HashMap::new()
			}),
			our_node_secret,
			ephemeral_key_midstate,
			peer_counter_low: AtomicUsize::new(0),
			peer_counter_high: AtomicUsize::new(0),
			logger,
		}
	}

	/// Get the list of node ids for peers which have completed the initial handshake.
	///
	/// For outbound connections, this will be the same as the their_node_id parameter passed in to
	/// new_outbound_connection, however entries will only appear once the initial handshake has
	/// completed and we are sure the remote peer has the private key for the given node_id.
	pub fn get_peer_node_ids(&self) -> Vec<PublicKey> {
		let peers = self.peers.lock().unwrap();
		peers.peers.values().filter_map(|p| {
			if !p.channel_encryptor.is_ready_for_encryption() || p.their_features.is_none() {
				return None;
			}
			p.their_node_id
		}).collect()
	}

	fn get_ephemeral_key(&self) -> SecretKey {
		let mut ephemeral_hash = self.ephemeral_key_midstate.clone();
		let low = self.peer_counter_low.fetch_add(1, Ordering::AcqRel);
		let high = if low == 0 {
			self.peer_counter_high.fetch_add(1, Ordering::AcqRel)
		} else {
			self.peer_counter_high.load(Ordering::Acquire)
		};
		ephemeral_hash.input(&byte_utils::le64_to_array(low as u64));
		ephemeral_hash.input(&byte_utils::le64_to_array(high as u64));
		SecretKey::from_slice(&Sha256::from_engine(ephemeral_hash).into_inner()).expect("You broke SHA-256!")
	}

	/// Indicates a new outbound connection has been established to a node with the given node_id.
	/// Note that if an Err is returned here you MUST NOT call socket_disconnected for the new
	/// descriptor but must disconnect the connection immediately.
	///
	/// Returns a small number of bytes to send to the remote node (currently always 50).
	///
	/// Panics if descriptor is duplicative with some other descriptor which has not yet had a
	/// socket_disconnected().
	pub fn new_outbound_connection(&self, their_node_id: PublicKey, descriptor: Descriptor) -> Result<Vec<u8>, PeerHandleError> {
		let mut peer_encryptor = PeerChannelEncryptor::new_outbound(their_node_id.clone(), self.get_ephemeral_key());
		let res = peer_encryptor.get_act_one().to_vec();
		let pending_read_buffer = [0; 50].to_vec(); // Noise act two is 50 bytes

		let mut peers = self.peers.lock().unwrap();
		if peers.peers.insert(descriptor, Peer {
			channel_encryptor: peer_encryptor,
			outbound: true,
			their_node_id: None,
			their_features: None,

			pending_outbound_buffer: LinkedList::new(),
			pending_outbound_buffer_first_msg_offset: 0,
			awaiting_write_event: false,

			pending_read_buffer,
			pending_read_buffer_pos: 0,
			pending_read_is_header: false,

			sync_status: InitSyncTracker::NoSyncRequested,

			awaiting_pong: false,
		}).is_some() {
			panic!("PeerManager driver duplicated descriptors!");
		};
		Ok(res)
	}

	/// Indicates a new inbound connection has been established.
	///
	/// May refuse the connection by returning an Err, but will never write bytes to the remote end
	/// (outbound connector always speaks first). Note that if an Err is returned here you MUST NOT
	/// call socket_disconnected for the new descriptor but must disconnect the connection
	/// immediately.
	///
	/// Panics if descriptor is duplicative with some other descriptor which has not yet had
	/// socket_disconnected called.
	pub fn new_inbound_connection(&self, descriptor: Descriptor) -> Result<(), PeerHandleError> {
		let peer_encryptor = PeerChannelEncryptor::new_inbound(&self.our_node_secret);
		let pending_read_buffer = [0; 50].to_vec(); // Noise act one is 50 bytes

		let mut peers = self.peers.lock().unwrap();
		if peers.peers.insert(descriptor, Peer {
			channel_encryptor: peer_encryptor,
			outbound: false,
			their_node_id: None,
			their_features: None,

			pending_outbound_buffer: LinkedList::new(),
			pending_outbound_buffer_first_msg_offset: 0,
			awaiting_write_event: false,

			pending_read_buffer,
			pending_read_buffer_pos: 0,
			pending_read_is_header: false,

			sync_status: InitSyncTracker::NoSyncRequested,

			awaiting_pong: false,
		}).is_some() {
			panic!("PeerManager driver duplicated descriptors!");
		};
		Ok(())
	}

	fn do_attempt_write_data(&self, descriptor: &mut Descriptor, peer: &mut Peer) {
		macro_rules! encode_and_send_msg {
			($msg: expr) => {
				{
					log_trace!(self.logger, "Encoding and sending sync update message of type {} to {}", $msg.type_id(), log_pubkey!(peer.their_node_id.unwrap()));
					peer.pending_outbound_buffer.push_back(peer.channel_encryptor.encrypt_message(&encode_msg!($msg)[..]));
				}
			}
		}
		const MSG_BUFF_SIZE: usize = 10;
		while !peer.awaiting_write_event {
			if peer.pending_outbound_buffer.len() < MSG_BUFF_SIZE {
				match peer.sync_status {
					InitSyncTracker::NoSyncRequested => {},
					InitSyncTracker::ChannelsSyncing(c) if c < 0xffff_ffff_ffff_ffff => {
						let steps = ((MSG_BUFF_SIZE - peer.pending_outbound_buffer.len() + 2) / 3) as u8;
						let all_messages = self.message_handler.route_handler.get_next_channel_announcements(c, steps);
						for &(ref announce, ref update_a_option, ref update_b_option) in all_messages.iter() {
							encode_and_send_msg!(announce);
							if let &Some(ref update_a) = update_a_option {
								encode_and_send_msg!(update_a);
							}
							if let &Some(ref update_b) = update_b_option {
								encode_and_send_msg!(update_b);
							}
							peer.sync_status = InitSyncTracker::ChannelsSyncing(announce.contents.short_channel_id + 1);
						}
						if all_messages.is_empty() || all_messages.len() != steps as usize {
							peer.sync_status = InitSyncTracker::ChannelsSyncing(0xffff_ffff_ffff_ffff);
						}
					},
					InitSyncTracker::ChannelsSyncing(c) if c == 0xffff_ffff_ffff_ffff => {
						let steps = (MSG_BUFF_SIZE - peer.pending_outbound_buffer.len()) as u8;
						let all_messages = self.message_handler.route_handler.get_next_node_announcements(None, steps);
						for msg in all_messages.iter() {
							encode_and_send_msg!(msg);
							peer.sync_status = InitSyncTracker::NodesSyncing(msg.contents.node_id);
						}
						if all_messages.is_empty() || all_messages.len() != steps as usize {
							peer.sync_status = InitSyncTracker::NoSyncRequested;
						}
					},
					InitSyncTracker::ChannelsSyncing(_) => unreachable!(),
					InitSyncTracker::NodesSyncing(key) => {
						let steps = (MSG_BUFF_SIZE - peer.pending_outbound_buffer.len()) as u8;
						let all_messages = self.message_handler.route_handler.get_next_node_announcements(Some(&key), steps);
						for msg in all_messages.iter() {
							encode_and_send_msg!(msg);
							peer.sync_status = InitSyncTracker::NodesSyncing(msg.contents.node_id);
						}
						if all_messages.is_empty() || all_messages.len() != steps as usize {
							peer.sync_status = InitSyncTracker::NoSyncRequested;
						}
					},
				}
			}

			if {
				let next_buff = match peer.pending_outbound_buffer.front() {
					None => return,
					Some(buff) => buff,
				};

				let should_be_reading = peer.pending_outbound_buffer.len() < MSG_BUFF_SIZE;
				let pending = &next_buff[peer.pending_outbound_buffer_first_msg_offset..];
				let data_sent = descriptor.send_data(pending, should_be_reading);
				peer.pending_outbound_buffer_first_msg_offset += data_sent;
				if peer.pending_outbound_buffer_first_msg_offset == next_buff.len() { true } else { false }
			} {
				peer.pending_outbound_buffer_first_msg_offset = 0;
				peer.pending_outbound_buffer.pop_front();
			} else {
				peer.awaiting_write_event = true;
			}
		}
	}

	/// Indicates that there is room to write data to the given socket descriptor.
	///
	/// May return an Err to indicate that the connection should be closed.
	///
	/// Will most likely call send_data on the descriptor passed in (or the descriptor handed into
	/// new_*\_connection) before returning. Thus, be very careful with reentrancy issues! The
	/// invariants around calling write_buffer_space_avail in case a write did not fully complete
	/// must still hold - be ready to call write_buffer_space_avail again if a write call generated
	/// here isn't sufficient! Panics if the descriptor was not previously registered in a
	/// new_\*_connection event.
	pub fn write_buffer_space_avail(&self, descriptor: &mut Descriptor) -> Result<(), PeerHandleError> {
		let mut peers = self.peers.lock().unwrap();
		match peers.peers.get_mut(descriptor) {
			None => panic!("Descriptor for write_event is not already known to PeerManager"),
			Some(peer) => {
				peer.awaiting_write_event = false;
				self.do_attempt_write_data(descriptor, peer);
			}
		};
		Ok(())
	}

	/// Indicates that data was read from the given socket descriptor.
	///
	/// May return an Err to indicate that the connection should be closed.
	///
	/// Will *not* call back into send_data on any descriptors to avoid reentrancy complexity.
	/// Thus, however, you almost certainly want to call process_events() after any read_event to
	/// generate send_data calls to handle responses.
	///
	/// If Ok(true) is returned, further read_events should not be triggered until a send_data call
	/// on this file descriptor has resume_read set (preventing DoS issues in the send buffer).
	///
	/// Panics if the descriptor was not previously registered in a new_*_connection event.
	pub fn read_event(&self, peer_descriptor: &mut Descriptor, data: &[u8]) -> Result<bool, PeerHandleError> {
		match self.do_read_event(peer_descriptor, data) {
			Ok(res) => Ok(res),
			Err(e) => {
				self.disconnect_event_internal(peer_descriptor, e.no_connection_possible);
				Err(e)
			}
		}
	}

	/// Append a message to a peer's pending outbound/write buffer, and update the map of peers needing sends accordingly.
	fn enqueue_message<M: Encode + Writeable>(&self, peers_needing_send: &mut HashSet<Descriptor>, peer: &mut Peer, descriptor: Descriptor, message: &M) {
		let mut buffer = VecWriter(Vec::new());
		wire::write(message, &mut buffer).unwrap(); // crash if the write failed
		let encoded_message = buffer.0;

		log_trace!(self.logger, "Enqueueing message of type {} to {}", message.type_id(), log_pubkey!(peer.their_node_id.unwrap()));
		peer.pending_outbound_buffer.push_back(peer.channel_encryptor.encrypt_message(&encoded_message[..]));
		peers_needing_send.insert(descriptor);
	}

	fn do_read_event(&self, peer_descriptor: &mut Descriptor, data: &[u8]) -> Result<bool, PeerHandleError> {
		let pause_read = {
			let mut peers_lock = self.peers.lock().unwrap();
			let peers = &mut *peers_lock;
			let pause_read = match peers.peers.get_mut(peer_descriptor) {
				None => panic!("Descriptor for read_event is not already known to PeerManager"),
				Some(peer) => {
					assert!(peer.pending_read_buffer.len() > 0);
					assert!(peer.pending_read_buffer.len() > peer.pending_read_buffer_pos);

					let mut read_pos = 0;
					while read_pos < data.len() {
						{
							let data_to_copy = cmp::min(peer.pending_read_buffer.len() - peer.pending_read_buffer_pos, data.len() - read_pos);
							peer.pending_read_buffer[peer.pending_read_buffer_pos..peer.pending_read_buffer_pos + data_to_copy].copy_from_slice(&data[read_pos..read_pos + data_to_copy]);
							read_pos += data_to_copy;
							peer.pending_read_buffer_pos += data_to_copy;
						}

						if peer.pending_read_buffer_pos == peer.pending_read_buffer.len() {
							peer.pending_read_buffer_pos = 0;

							macro_rules! try_potential_handleerror {
								($thing: expr) => {
									match $thing {
										Ok(x) => x,
										Err(e) => {
											match e.action {
												msgs::ErrorAction::DisconnectPeer { msg: _ } => {
													//TODO: Try to push msg
													log_trace!(self.logger, "Got Err handling message, disconnecting peer because {}", e.err);
													return Err(PeerHandleError{ no_connection_possible: false });
												},
												msgs::ErrorAction::IgnoreError => {
													log_trace!(self.logger, "Got Err handling message, ignoring because {}", e.err);
													continue;
												},
												msgs::ErrorAction::SendErrorMessage { msg } => {
													log_trace!(self.logger, "Got Err handling message, sending Error message because {}", e.err);
													self.enqueue_message(&mut peers.peers_needing_send, peer, peer_descriptor.clone(), &msg);
													continue;
												},
											}
										}
									};
								}
							}

							macro_rules! insert_node_id {
								() => {
									match peers.node_id_to_descriptor.entry(peer.their_node_id.unwrap()) {
										hash_map::Entry::Occupied(_) => {
											log_trace!(self.logger, "Got second connection with {}, closing", log_pubkey!(peer.their_node_id.unwrap()));
											peer.their_node_id = None; // Unset so that we don't generate a peer_disconnected event
											return Err(PeerHandleError{ no_connection_possible: false })
										},
										hash_map::Entry::Vacant(entry) => {
											log_trace!(self.logger, "Finished noise handshake for connection with {}", log_pubkey!(peer.their_node_id.unwrap()));
											entry.insert(peer_descriptor.clone())
										},
									};
								}
							}

							let next_step = peer.channel_encryptor.get_noise_step();
							match next_step {
								NextNoiseStep::ActOne => {
									let act_two = try_potential_handleerror!(peer.channel_encryptor.process_act_one_with_keys(&peer.pending_read_buffer[..], &self.our_node_secret, self.get_ephemeral_key())).to_vec();
									peer.pending_outbound_buffer.push_back(act_two);
									peer.pending_read_buffer = [0; 66].to_vec(); // act three is 66 bytes long
								},
								NextNoiseStep::ActTwo => {
									let (act_three, their_node_id) = try_potential_handleerror!(peer.channel_encryptor.process_act_two(&peer.pending_read_buffer[..], &self.our_node_secret));
									peer.pending_outbound_buffer.push_back(act_three.to_vec());
									peer.pending_read_buffer = [0; 18].to_vec(); // Message length header is 18 bytes
									peer.pending_read_is_header = true;

									peer.their_node_id = Some(their_node_id);
									insert_node_id!();
									let features = InitFeatures::known();
									let resp = msgs::Init { features };
									self.enqueue_message(&mut peers.peers_needing_send, peer, peer_descriptor.clone(), &resp);
								},
								NextNoiseStep::ActThree => {
									let their_node_id = try_potential_handleerror!(peer.channel_encryptor.process_act_three(&peer.pending_read_buffer[..]));
									peer.pending_read_buffer = [0; 18].to_vec(); // Message length header is 18 bytes
									peer.pending_read_is_header = true;
									peer.their_node_id = Some(their_node_id);
									insert_node_id!();
								},
								NextNoiseStep::NoiseComplete => {
									if peer.pending_read_is_header {
										let msg_len = try_potential_handleerror!(peer.channel_encryptor.decrypt_length_header(&peer.pending_read_buffer[..]));
										peer.pending_read_buffer = Vec::with_capacity(msg_len as usize + 16);
										peer.pending_read_buffer.resize(msg_len as usize + 16, 0);
										if msg_len < 2 { // Need at least the message type tag
											return Err(PeerHandleError{ no_connection_possible: false });
										}
										peer.pending_read_is_header = false;
									} else {
										let msg_data = try_potential_handleerror!(peer.channel_encryptor.decrypt_message(&peer.pending_read_buffer[..]));
										assert!(msg_data.len() >= 2);

										// Reset read buffer
										peer.pending_read_buffer = [0; 18].to_vec();
										peer.pending_read_is_header = true;

										let mut reader = ::std::io::Cursor::new(&msg_data[..]);
										let message_result = wire::read(&mut reader);
										let message = match message_result {
											Ok(x) => x,
											Err(e) => {
												match e {
													msgs::DecodeError::UnknownVersion => return Err(PeerHandleError { no_connection_possible: false }),
													msgs::DecodeError::UnknownRequiredFeature => {
														log_debug!(self.logger, "Got a channel/node announcement with an known required feature flag, you may want to update!");
														continue;
													}
													msgs::DecodeError::InvalidValue => {
														log_debug!(self.logger, "Got an invalid value while deserializing message");
														return Err(PeerHandleError { no_connection_possible: false });
													}
													msgs::DecodeError::ShortRead => {
														log_debug!(self.logger, "Deserialization failed due to shortness of message");
														return Err(PeerHandleError { no_connection_possible: false });
													}
													msgs::DecodeError::BadLengthDescriptor => return Err(PeerHandleError { no_connection_possible: false }),
													msgs::DecodeError::Io(_) => return Err(PeerHandleError { no_connection_possible: false }),
												}
											}
										};

										if let Err(handling_error) = self.handle_message(&mut peers.peers_needing_send, peer, peer_descriptor.clone(), message){
											match handling_error {
												MessageHandlingError::PeerHandleError(e) => { return Err(e) },
												MessageHandlingError::LightningError(e) => {
													try_potential_handleerror!(Err(e));
												},
											}
										}
									}
								}
							}
						}
					}

					self.do_attempt_write_data(peer_descriptor, peer);

					peer.pending_outbound_buffer.len() > 10 // pause_read
				}
			};

			pause_read
		};

		Ok(pause_read)
	}

	/// Process an incoming message and return a decision (ok, lightning error, peer handling error) regarding the next action with the peer
	fn handle_message(&self, peers_needing_send: &mut HashSet<Descriptor>, peer: &mut Peer, peer_descriptor: Descriptor, message: wire::Message) -> Result<(), MessageHandlingError> {
		log_trace!(self.logger, "Received message of type {} from {}", message.type_id(), log_pubkey!(peer.their_node_id.unwrap()));

		// Need an Init as first message
		if let wire::Message::Init(_) = message {
		} else if peer.their_features.is_none() {
			log_trace!(self.logger, "Peer {} sent non-Init first message", log_pubkey!(peer.their_node_id.unwrap()));
			return Err(PeerHandleError{ no_connection_possible: false }.into());
		}

		match message {
			// Setup and Control messages:
			wire::Message::Init(msg) => {
				if msg.features.requires_unknown_bits() {
					log_info!(self.logger, "Peer features required unknown version bits");
					return Err(PeerHandleError{ no_connection_possible: true }.into());
				}
				if peer.their_features.is_some() {
					return Err(PeerHandleError{ no_connection_possible: false }.into());
				}

				log_info!(
					self.logger, "Received peer Init message: data_loss_protect: {}, initial_routing_sync: {}, upfront_shutdown_script: {}, gossip_queries: {}, static_remote_key: {}, unknown flags (local and global): {}",
					if msg.features.supports_data_loss_protect() { "supported" } else { "not supported"},
					if msg.features.initial_routing_sync() { "requested" } else { "not requested" },
					if msg.features.supports_upfront_shutdown_script() { "supported" } else { "not supported"},
					if msg.features.supports_gossip_queries() { "supported" } else { "not supported" },
					if msg.features.supports_static_remote_key() { "supported" } else { "not supported"},
					if msg.features.supports_unknown_bits() { "present" } else { "none" }
				);

				if msg.features.initial_routing_sync() {
					peer.sync_status = InitSyncTracker::ChannelsSyncing(0);
					peers_needing_send.insert(peer_descriptor.clone());
				}
				if !msg.features.supports_static_remote_key() {
					log_debug!(self.logger, "Peer {} does not support static remote key, disconnecting with no_connection_possible", log_pubkey!(peer.their_node_id.unwrap()));
					return Err(PeerHandleError{ no_connection_possible: true }.into());
				}

				if !peer.outbound {
					let features = InitFeatures::known();
					let resp = msgs::Init { features };
					self.enqueue_message(peers_needing_send, peer, peer_descriptor.clone(), &resp);
				}

				self.message_handler.route_handler.sync_routing_table(&peer.their_node_id.unwrap(), &msg);

				self.message_handler.chan_handler.peer_connected(&peer.their_node_id.unwrap(), &msg);
				peer.their_features = Some(msg.features);
			},
			wire::Message::Error(msg) => {
				let mut data_is_printable = true;
				for b in msg.data.bytes() {
					if b < 32 || b > 126 {
						data_is_printable = false;
						break;
					}
				}

				if data_is_printable {
					log_debug!(self.logger, "Got Err message from {}: {}", log_pubkey!(peer.their_node_id.unwrap()), msg.data);
				} else {
					log_debug!(self.logger, "Got Err message from {} with non-ASCII error message", log_pubkey!(peer.their_node_id.unwrap()));
				}
				self.message_handler.chan_handler.handle_error(&peer.their_node_id.unwrap(), &msg);
				if msg.channel_id == [0; 32] {
					return Err(PeerHandleError{ no_connection_possible: true }.into());
				}
			},

			wire::Message::Ping(msg) => {
				if msg.ponglen < 65532 {
					let resp = msgs::Pong { byteslen: msg.ponglen };
					self.enqueue_message(peers_needing_send, peer, peer_descriptor.clone(), &resp);
				}
			},
			wire::Message::Pong(_msg) => {
				peer.awaiting_pong = false;
			},

			// Channel messages:
			wire::Message::OpenChannel(msg) => {
				self.message_handler.chan_handler.handle_open_channel(&peer.their_node_id.unwrap(), peer.their_features.clone().unwrap(), &msg);
			},
			wire::Message::AcceptChannel(msg) => {
				self.message_handler.chan_handler.handle_accept_channel(&peer.their_node_id.unwrap(), peer.their_features.clone().unwrap(), &msg);
			},

			wire::Message::FundingCreated(msg) => {
				self.message_handler.chan_handler.handle_funding_created(&peer.their_node_id.unwrap(), &msg);
			},
			wire::Message::FundingSigned(msg) => {
				self.message_handler.chan_handler.handle_funding_signed(&peer.their_node_id.unwrap(), &msg);
			},
			wire::Message::FundingLocked(msg) => {
				self.message_handler.chan_handler.handle_funding_locked(&peer.their_node_id.unwrap(), &msg);
			},

			wire::Message::Shutdown(msg) => {
				self.message_handler.chan_handler.handle_shutdown(&peer.their_node_id.unwrap(), peer.their_features.as_ref().unwrap(), &msg);
			},
			wire::Message::ClosingSigned(msg) => {
				self.message_handler.chan_handler.handle_closing_signed(&peer.their_node_id.unwrap(), &msg);
			},

			// Commitment messages:
			wire::Message::UpdateAddHTLC(msg) => {
				self.message_handler.chan_handler.handle_update_add_htlc(&peer.their_node_id.unwrap(), &msg);
			},
			wire::Message::UpdateFulfillHTLC(msg) => {
				self.message_handler.chan_handler.handle_update_fulfill_htlc(&peer.their_node_id.unwrap(), &msg);
			},
			wire::Message::UpdateFailHTLC(msg) => {
				self.message_handler.chan_handler.handle_update_fail_htlc(&peer.their_node_id.unwrap(), &msg);
			},
			wire::Message::UpdateFailMalformedHTLC(msg) => {
				self.message_handler.chan_handler.handle_update_fail_malformed_htlc(&peer.their_node_id.unwrap(), &msg);
			},

			wire::Message::CommitmentSigned(msg) => {
				self.message_handler.chan_handler.handle_commitment_signed(&peer.their_node_id.unwrap(), &msg);
			},
			wire::Message::RevokeAndACK(msg) => {
				self.message_handler.chan_handler.handle_revoke_and_ack(&peer.their_node_id.unwrap(), &msg);
			},
			wire::Message::UpdateFee(msg) => {
				self.message_handler.chan_handler.handle_update_fee(&peer.their_node_id.unwrap(), &msg);
			},
			wire::Message::ChannelReestablish(msg) => {
				self.message_handler.chan_handler.handle_channel_reestablish(&peer.their_node_id.unwrap(), &msg);
			},

			// Routing messages:
			wire::Message::AnnouncementSignatures(msg) => {
				self.message_handler.chan_handler.handle_announcement_signatures(&peer.their_node_id.unwrap(), &msg);
			},
			wire::Message::ChannelAnnouncement(msg) => {
				let should_forward = match self.message_handler.route_handler.handle_channel_announcement(&msg) {
					Ok(v) => v,
					Err(e) => { return Err(e.into()); },
				};

				if should_forward {
					// TODO: forward msg along to all our other peers!
				}
			},
			wire::Message::NodeAnnouncement(msg) => {
				let should_forward = match self.message_handler.route_handler.handle_node_announcement(&msg) {
					Ok(v) => v,
					Err(e) => { return Err(e.into()); },
				};

				if should_forward {
					// TODO: forward msg along to all our other peers!
				}
			},
			wire::Message::ChannelUpdate(msg) => {
				let should_forward = match self.message_handler.route_handler.handle_channel_update(&msg) {
					Ok(v) => v,
					Err(e) => { return Err(e.into()); },
				};

				if should_forward {
					// TODO: forward msg along to all our other peers!
				}
			},
			wire::Message::QueryShortChannelIds(msg) => {
				self.message_handler.route_handler.handle_query_short_channel_ids(&peer.their_node_id.unwrap(), msg)?;
			},
			wire::Message::ReplyShortChannelIdsEnd(msg) => {
				self.message_handler.route_handler.handle_reply_short_channel_ids_end(&peer.their_node_id.unwrap(), msg)?;
			},
			wire::Message::QueryChannelRange(msg) => {
				self.message_handler.route_handler.handle_query_channel_range(&peer.their_node_id.unwrap(), msg)?;
			},
			wire::Message::ReplyChannelRange(msg) => {
				self.message_handler.route_handler.handle_reply_channel_range(&peer.their_node_id.unwrap(), msg)?;
			},
			wire::Message::GossipTimestampFilter(_msg) => {
				// TODO: handle message
			},

			// Unknown messages:
			wire::Message::Unknown(msg_type) if msg_type.is_even() => {
				log_debug!(self.logger, "Received unknown even message of type {}, disconnecting peer!", msg_type);
				// Fail the channel if message is an even, unknown type as per BOLT #1.
				return Err(PeerHandleError{ no_connection_possible: true }.into());
			},
			wire::Message::Unknown(msg_type) => {
				log_trace!(self.logger, "Received unknown odd message of type {}, ignoring", msg_type);
			}
		};
		Ok(())
	}

	/// Checks for any events generated by our handlers and processes them. Includes sending most
	/// response messages as well as messages generated by calls to handler functions directly (eg
	/// functions like ChannelManager::process_pending_htlc_forward or send_payment).
	pub fn process_events(&self) {
		{
			// TODO: There are some DoS attacks here where you can flood someone's outbound send
			// buffer by doing things like announcing channels on another node. We should be willing to
			// drop optional-ish messages when send buffers get full!

			let mut events_generated = self.message_handler.chan_handler.get_and_clear_pending_msg_events();
			events_generated.append(&mut self.message_handler.route_handler.get_and_clear_pending_msg_events());
			let mut peers_lock = self.peers.lock().unwrap();
			let peers = &mut *peers_lock;
			for event in events_generated.drain(..) {
				macro_rules! get_peer_for_forwarding {
					($node_id: expr, $handle_no_such_peer: block) => {
						{
							let descriptor = match peers.node_id_to_descriptor.get($node_id) {
								Some(descriptor) => descriptor.clone(),
								None => {
									$handle_no_such_peer;
									continue;
								},
							};
							match peers.peers.get_mut(&descriptor) {
								Some(peer) => {
									if peer.their_features.is_none() {
										$handle_no_such_peer;
										continue;
									}
									(descriptor, peer)
								},
								None => panic!("Inconsistent peers set state!"),
							}
						}
					}
				}
				match event {
					MessageSendEvent::SendAcceptChannel { ref node_id, ref msg } => {
						log_trace!(self.logger, "Handling SendAcceptChannel event in peer_handler for node {} for channel {}",
								log_pubkey!(node_id),
								log_bytes!(msg.temporary_channel_id));
						let (mut descriptor, peer) = get_peer_for_forwarding!(node_id, {
								//TODO: Drop the pending channel? (or just let it timeout, but that sucks)
							});
						peer.pending_outbound_buffer.push_back(peer.channel_encryptor.encrypt_message(&encode_msg!(msg)));
						self.do_attempt_write_data(&mut descriptor, peer);
					},
					MessageSendEvent::SendOpenChannel { ref node_id, ref msg } => {
						log_trace!(self.logger, "Handling SendOpenChannel event in peer_handler for node {} for channel {}",
								log_pubkey!(node_id),
								log_bytes!(msg.temporary_channel_id));
						let (mut descriptor, peer) = get_peer_for_forwarding!(node_id, {
								//TODO: Drop the pending channel? (or just let it timeout, but that sucks)
							});
						peer.pending_outbound_buffer.push_back(peer.channel_encryptor.encrypt_message(&encode_msg!(msg)));
						self.do_attempt_write_data(&mut descriptor, peer);
					},
					MessageSendEvent::SendFundingCreated { ref node_id, ref msg } => {
						log_trace!(self.logger, "Handling SendFundingCreated event in peer_handler for node {} for channel {} (which becomes {})",
								log_pubkey!(node_id),
								log_bytes!(msg.temporary_channel_id),
								log_funding_channel_id!(msg.funding_txid, msg.funding_output_index));
						let (mut descriptor, peer) = get_peer_for_forwarding!(node_id, {
								//TODO: generate a DiscardFunding event indicating to the wallet that
								//they should just throw away this funding transaction
							});
						peer.pending_outbound_buffer.push_back(peer.channel_encryptor.encrypt_message(&encode_msg!(msg)));
						self.do_attempt_write_data(&mut descriptor, peer);
					},
					MessageSendEvent::SendFundingSigned { ref node_id, ref msg } => {
						log_trace!(self.logger, "Handling SendFundingSigned event in peer_handler for node {} for channel {}",
								log_pubkey!(node_id),
								log_bytes!(msg.channel_id));
						let (mut descriptor, peer) = get_peer_for_forwarding!(node_id, {
								//TODO: generate a DiscardFunding event indicating to the wallet that
								//they should just throw away this funding transaction
							});
						peer.pending_outbound_buffer.push_back(peer.channel_encryptor.encrypt_message(&encode_msg!(msg)));
						self.do_attempt_write_data(&mut descriptor, peer);
					},
					MessageSendEvent::SendFundingLocked { ref node_id, ref msg } => {
						log_trace!(self.logger, "Handling SendFundingLocked event in peer_handler for node {} for channel {}",
								log_pubkey!(node_id),
								log_bytes!(msg.channel_id));
						let (mut descriptor, peer) = get_peer_for_forwarding!(node_id, {
								//TODO: Do whatever we're gonna do for handling dropped messages
							});
						peer.pending_outbound_buffer.push_back(peer.channel_encryptor.encrypt_message(&encode_msg!(msg)));
						self.do_attempt_write_data(&mut descriptor, peer);
					},
					MessageSendEvent::SendAnnouncementSignatures { ref node_id, ref msg } => {
						log_trace!(self.logger, "Handling SendAnnouncementSignatures event in peer_handler for node {} for channel {})",
								log_pubkey!(node_id),
								log_bytes!(msg.channel_id));
						let (mut descriptor, peer) = get_peer_for_forwarding!(node_id, {
								//TODO: generate a DiscardFunding event indicating to the wallet that
								//they should just throw away this funding transaction
							});
						peer.pending_outbound_buffer.push_back(peer.channel_encryptor.encrypt_message(&encode_msg!(msg)));
						self.do_attempt_write_data(&mut descriptor, peer);
					},
					MessageSendEvent::UpdateHTLCs { ref node_id, updates: msgs::CommitmentUpdate { ref update_add_htlcs, ref update_fulfill_htlcs, ref update_fail_htlcs, ref update_fail_malformed_htlcs, ref update_fee, ref commitment_signed } } => {
						log_trace!(self.logger, "Handling UpdateHTLCs event in peer_handler for node {} with {} adds, {} fulfills, {} fails for channel {}",
								log_pubkey!(node_id),
								update_add_htlcs.len(),
								update_fulfill_htlcs.len(),
								update_fail_htlcs.len(),
								log_bytes!(commitment_signed.channel_id));
						let (mut descriptor, peer) = get_peer_for_forwarding!(node_id, {
								//TODO: Do whatever we're gonna do for handling dropped messages
							});
						for msg in update_add_htlcs {
							peer.pending_outbound_buffer.push_back(peer.channel_encryptor.encrypt_message(&encode_msg!(msg)));
						}
						for msg in update_fulfill_htlcs {
							peer.pending_outbound_buffer.push_back(peer.channel_encryptor.encrypt_message(&encode_msg!(msg)));
						}
						for msg in update_fail_htlcs {
							peer.pending_outbound_buffer.push_back(peer.channel_encryptor.encrypt_message(&encode_msg!(msg)));
						}
						for msg in update_fail_malformed_htlcs {
							peer.pending_outbound_buffer.push_back(peer.channel_encryptor.encrypt_message(&encode_msg!(msg)));
						}
						if let &Some(ref msg) = update_fee {
							peer.pending_outbound_buffer.push_back(peer.channel_encryptor.encrypt_message(&encode_msg!(msg)));
						}
						peer.pending_outbound_buffer.push_back(peer.channel_encryptor.encrypt_message(&encode_msg!(commitment_signed)));
						self.do_attempt_write_data(&mut descriptor, peer);
					},
					MessageSendEvent::SendRevokeAndACK { ref node_id, ref msg } => {
						log_trace!(self.logger, "Handling SendRevokeAndACK event in peer_handler for node {} for channel {}",
								log_pubkey!(node_id),
								log_bytes!(msg.channel_id));
						let (mut descriptor, peer) = get_peer_for_forwarding!(node_id, {
								//TODO: Do whatever we're gonna do for handling dropped messages
							});
						peer.pending_outbound_buffer.push_back(peer.channel_encryptor.encrypt_message(&encode_msg!(msg)));
						self.do_attempt_write_data(&mut descriptor, peer);
					},
					MessageSendEvent::SendClosingSigned { ref node_id, ref msg } => {
						log_trace!(self.logger, "Handling SendClosingSigned event in peer_handler for node {} for channel {}",
								log_pubkey!(node_id),
								log_bytes!(msg.channel_id));
						let (mut descriptor, peer) = get_peer_for_forwarding!(node_id, {
								//TODO: Do whatever we're gonna do for handling dropped messages
							});
						peer.pending_outbound_buffer.push_back(peer.channel_encryptor.encrypt_message(&encode_msg!(msg)));
						self.do_attempt_write_data(&mut descriptor, peer);
					},
					MessageSendEvent::SendShutdown { ref node_id, ref msg } => {
						log_trace!(self.logger, "Handling Shutdown event in peer_handler for node {} for channel {}",
								log_pubkey!(node_id),
								log_bytes!(msg.channel_id));
						let (mut descriptor, peer) = get_peer_for_forwarding!(node_id, {
								//TODO: Do whatever we're gonna do for handling dropped messages
							});
						peer.pending_outbound_buffer.push_back(peer.channel_encryptor.encrypt_message(&encode_msg!(msg)));
						self.do_attempt_write_data(&mut descriptor, peer);
					},
					MessageSendEvent::SendChannelReestablish { ref node_id, ref msg } => {
						log_trace!(self.logger, "Handling SendChannelReestablish event in peer_handler for node {} for channel {}",
								log_pubkey!(node_id),
								log_bytes!(msg.channel_id));
						let (mut descriptor, peer) = get_peer_for_forwarding!(node_id, {
								//TODO: Do whatever we're gonna do for handling dropped messages
							});
						peer.pending_outbound_buffer.push_back(peer.channel_encryptor.encrypt_message(&encode_msg!(msg)));
						self.do_attempt_write_data(&mut descriptor, peer);
					},
					MessageSendEvent::BroadcastChannelAnnouncement { ref msg, ref update_msg } => {
						log_trace!(self.logger, "Handling BroadcastChannelAnnouncement event in peer_handler for short channel id {}", msg.contents.short_channel_id);
						if self.message_handler.route_handler.handle_channel_announcement(msg).is_ok() && self.message_handler.route_handler.handle_channel_update(update_msg).is_ok() {
							let encoded_msg = encode_msg!(msg);
							let encoded_update_msg = encode_msg!(update_msg);

							for (ref descriptor, ref mut peer) in peers.peers.iter_mut() {
								if !peer.channel_encryptor.is_ready_for_encryption() || peer.their_features.is_none() ||
										!peer.should_forward_channel_announcement(msg.contents.short_channel_id) {
									continue
								}
								match peer.their_node_id {
									None => continue,
									Some(their_node_id) => {
										if their_node_id == msg.contents.node_id_1 || their_node_id == msg.contents.node_id_2 {
											continue
										}
									}
								}
								peer.pending_outbound_buffer.push_back(peer.channel_encryptor.encrypt_message(&encoded_msg[..]));
								peer.pending_outbound_buffer.push_back(peer.channel_encryptor.encrypt_message(&encoded_update_msg[..]));
								self.do_attempt_write_data(&mut (*descriptor).clone(), peer);
							}
						}
					},
					MessageSendEvent::BroadcastNodeAnnouncement { ref msg } => {
						log_trace!(self.logger, "Handling BroadcastNodeAnnouncement event in peer_handler");
						if self.message_handler.route_handler.handle_node_announcement(msg).is_ok() {
							let encoded_msg = encode_msg!(msg);

							for (ref descriptor, ref mut peer) in peers.peers.iter_mut() {
								if !peer.channel_encryptor.is_ready_for_encryption() || peer.their_features.is_none() ||
										!peer.should_forward_node_announcement(msg.contents.node_id) {
									continue
								}
								peer.pending_outbound_buffer.push_back(peer.channel_encryptor.encrypt_message(&encoded_msg[..]));
								self.do_attempt_write_data(&mut (*descriptor).clone(), peer);
							}
						}
					},
					MessageSendEvent::BroadcastChannelUpdate { ref msg } => {
						log_trace!(self.logger, "Handling BroadcastChannelUpdate event in peer_handler for short channel id {}", msg.contents.short_channel_id);
						if self.message_handler.route_handler.handle_channel_update(msg).is_ok() {
							let encoded_msg = encode_msg!(msg);

							for (ref descriptor, ref mut peer) in peers.peers.iter_mut() {
								if !peer.channel_encryptor.is_ready_for_encryption() || peer.their_features.is_none() ||
										!peer.should_forward_channel_announcement(msg.contents.short_channel_id)  {
									continue
								}
								peer.pending_outbound_buffer.push_back(peer.channel_encryptor.encrypt_message(&encoded_msg[..]));
								self.do_attempt_write_data(&mut (*descriptor).clone(), peer);
							}
						}
					},
					MessageSendEvent::PaymentFailureNetworkUpdate { ref update } => {
						self.message_handler.route_handler.handle_htlc_fail_channel_update(update);
					},
					MessageSendEvent::HandleError { ref node_id, ref action } => {
						match *action {
							msgs::ErrorAction::DisconnectPeer { ref msg } => {
								if let Some(mut descriptor) = peers.node_id_to_descriptor.remove(node_id) {
									peers.peers_needing_send.remove(&descriptor);
									if let Some(mut peer) = peers.peers.remove(&descriptor) {
										if let Some(ref msg) = *msg {
											log_trace!(self.logger, "Handling DisconnectPeer HandleError event in peer_handler for node {} with message {}",
													log_pubkey!(node_id),
													msg.data);
											peer.pending_outbound_buffer.push_back(peer.channel_encryptor.encrypt_message(&encode_msg!(msg)));
											// This isn't guaranteed to work, but if there is enough free
											// room in the send buffer, put the error message there...
											self.do_attempt_write_data(&mut descriptor, &mut peer);
										} else {
											log_trace!(self.logger, "Handling DisconnectPeer HandleError event in peer_handler for node {} with no message", log_pubkey!(node_id));
										}
									}
									descriptor.disconnect_socket();
									self.message_handler.chan_handler.peer_disconnected(&node_id, false);
								}
							},
							msgs::ErrorAction::IgnoreError => {},
							msgs::ErrorAction::SendErrorMessage { ref msg } => {
								log_trace!(self.logger, "Handling SendErrorMessage HandleError event in peer_handler for node {} with message {}",
										log_pubkey!(node_id),
										msg.data);
								let (mut descriptor, peer) = get_peer_for_forwarding!(node_id, {
									//TODO: Do whatever we're gonna do for handling dropped messages
								});
								peer.pending_outbound_buffer.push_back(peer.channel_encryptor.encrypt_message(&encode_msg!(msg)));
								self.do_attempt_write_data(&mut descriptor, peer);
							},
						}
					},
					MessageSendEvent::SendChannelRangeQuery { ref node_id, ref msg } => {
						let (mut descriptor, peer) = get_peer_for_forwarding!(node_id, {});
						peer.pending_outbound_buffer.push_back(peer.channel_encryptor.encrypt_message(&encode_msg!(msg)));
						self.do_attempt_write_data(&mut descriptor, peer);
					},
					MessageSendEvent::SendShortIdsQuery { ref node_id, ref msg } => {
						let (mut descriptor, peer) = get_peer_for_forwarding!(node_id, {});
						peer.pending_outbound_buffer.push_back(peer.channel_encryptor.encrypt_message(&encode_msg!(msg)));
						self.do_attempt_write_data(&mut descriptor, peer);
					}
					MessageSendEvent::SendReplyChannelRange { ref node_id, ref msg } => {
						log_trace!(self.logger, "Handling SendReplyChannelRange event in peer_handler for node {} with num_scids={} first_blocknum={} number_of_blocks={}, sync_complete={}",
							log_pubkey!(node_id),
							msg.short_channel_ids.len(),
							msg.first_blocknum,
							msg.number_of_blocks,
							msg.sync_complete);
						let (mut descriptor, peer) = get_peer_for_forwarding!(node_id, {});
						peer.pending_outbound_buffer.push_back(peer.channel_encryptor.encrypt_message(&encode_msg!(msg)));
						self.do_attempt_write_data(&mut descriptor, peer);
					}
				}
			}

			for mut descriptor in peers.peers_needing_send.drain() {
				match peers.peers.get_mut(&descriptor) {
					Some(peer) => self.do_attempt_write_data(&mut descriptor, peer),
					None => panic!("Inconsistent peers set state!"),
				}
			}
		}
	}

	/// Indicates that the given socket descriptor's connection is now closed.
	///
	/// This must only be called if the socket has been disconnected by the peer or your own
	/// decision to disconnect it and must NOT be called in any case where other parts of this
	/// library (eg PeerHandleError, explicit disconnect_socket calls) instruct you to disconnect
	/// the peer.
	///
	/// Panics if the descriptor was not previously registered in a successful new_*_connection event.
	pub fn socket_disconnected(&self, descriptor: &Descriptor) {
		self.disconnect_event_internal(descriptor, false);
	}

	fn disconnect_event_internal(&self, descriptor: &Descriptor, no_connection_possible: bool) {
		let mut peers = self.peers.lock().unwrap();
		peers.peers_needing_send.remove(descriptor);
		let peer_option = peers.peers.remove(descriptor);
		match peer_option {
			None => panic!("Descriptor for disconnect_event is not already known to PeerManager"),
			Some(peer) => {
				match peer.their_node_id {
					Some(node_id) => {
						peers.node_id_to_descriptor.remove(&node_id);
						self.message_handler.chan_handler.peer_disconnected(&node_id, no_connection_possible);
					},
					None => {}
				}
			}
		};
	}

	/// Disconnect a peer given its node id.
	///
	/// Set no_connection_possible to true to prevent any further connection with this peer,
	/// force-closing any channels we have with it.
	///
	/// If a peer is connected, this will call `disconnect_socket` on the descriptor for the peer,
	/// so be careful about reentrancy issues.
	pub fn disconnect_by_node_id(&self, node_id: PublicKey, no_connection_possible: bool) {
		let mut peers_lock = self.peers.lock().unwrap();
		if let Some(mut descriptor) = peers_lock.node_id_to_descriptor.remove(&node_id) {
			log_trace!(self.logger, "Disconnecting peer with id {} due to client request", node_id);
			peers_lock.peers.remove(&descriptor);
			peers_lock.peers_needing_send.remove(&descriptor);
			self.message_handler.chan_handler.peer_disconnected(&node_id, no_connection_possible);
			descriptor.disconnect_socket();
		}
	}

	/// This function should be called roughly once every 30 seconds.
	/// It will send pings to each peer and disconnect those which did not respond to the last round of pings.

	/// Will most likely call send_data on all of the registered descriptors, thus, be very careful with reentrancy issues!
	pub fn timer_tick_occurred(&self) {
		let mut peers_lock = self.peers.lock().unwrap();
		{
			let peers = &mut *peers_lock;
			let peers_needing_send = &mut peers.peers_needing_send;
			let node_id_to_descriptor = &mut peers.node_id_to_descriptor;
			let peers = &mut peers.peers;
			let mut descriptors_needing_disconnect = Vec::new();

			peers.retain(|descriptor, peer| {
				if peer.awaiting_pong {
					peers_needing_send.remove(descriptor);
					descriptors_needing_disconnect.push(descriptor.clone());
					match peer.their_node_id {
						Some(node_id) => {
							log_trace!(self.logger, "Disconnecting peer with id {} due to ping timeout", node_id);
							node_id_to_descriptor.remove(&node_id);
							self.message_handler.chan_handler.peer_disconnected(&node_id, false);
						}
						None => {
							// This can't actually happen as we should have hit
							// is_ready_for_encryption() previously on this same peer.
							unreachable!();
						},
					}
					return false;
				}

				if !peer.channel_encryptor.is_ready_for_encryption() {
					// The peer needs to complete its handshake before we can exchange messages
					return true;
				}

				let ping = msgs::Ping {
					ponglen: 0,
					byteslen: 64,
				};
				peer.pending_outbound_buffer.push_back(peer.channel_encryptor.encrypt_message(&encode_msg!(&ping)));

				let mut descriptor_clone = descriptor.clone();
				self.do_attempt_write_data(&mut descriptor_clone, peer);

				peer.awaiting_pong = true;
				true
			});

			for mut descriptor in descriptors_needing_disconnect.drain(..) {
				descriptor.disconnect_socket();
			}
		}
	}
}

#[cfg(test)]
mod tests {
	use ln::peer_handler::{PeerManager, MessageHandler, SocketDescriptor};
	use ln::msgs;
	use util::events;
	use util::test_utils;

	use bitcoin::secp256k1::Secp256k1;
	use bitcoin::secp256k1::key::{SecretKey, PublicKey};

	use std;
	use std::sync::{Arc, Mutex};
	use std::sync::atomic::Ordering;

	#[derive(Clone)]
	struct FileDescriptor {
		fd: u16,
		outbound_data: Arc<Mutex<Vec<u8>>>,
	}
	impl PartialEq for FileDescriptor {
		fn eq(&self, other: &Self) -> bool {
			self.fd == other.fd
		}
	}
	impl Eq for FileDescriptor { }
	impl std::hash::Hash for FileDescriptor {
		fn hash<H: std::hash::Hasher>(&self, hasher: &mut H) {
			self.fd.hash(hasher)
		}
	}

	impl SocketDescriptor for FileDescriptor {
		fn send_data(&mut self, data: &[u8], _resume_read: bool) -> usize {
			self.outbound_data.lock().unwrap().extend_from_slice(data);
			data.len()
		}

		fn disconnect_socket(&mut self) {}
	}

	struct PeerManagerCfg {
		chan_handler: test_utils::TestChannelMessageHandler,
		routing_handler: test_utils::TestRoutingMessageHandler,
		logger: test_utils::TestLogger,
	}

	fn create_peermgr_cfgs(peer_count: usize) -> Vec<PeerManagerCfg> {
		let mut cfgs = Vec::new();
		for _ in 0..peer_count {
			cfgs.push(
				PeerManagerCfg{
					chan_handler: test_utils::TestChannelMessageHandler::new(),
					logger: test_utils::TestLogger::new(),
					routing_handler: test_utils::TestRoutingMessageHandler::new(),
				}
			);
		}

		cfgs
	}

	fn create_network<'a>(peer_count: usize, cfgs: &'a Vec<PeerManagerCfg>) -> Vec<PeerManager<FileDescriptor, &'a test_utils::TestChannelMessageHandler, &'a test_utils::TestRoutingMessageHandler, &'a test_utils::TestLogger>> {
		let mut peers = Vec::new();
		for i in 0..peer_count {
			let node_secret = SecretKey::from_slice(&[42 + i as u8; 32]).unwrap();
			let ephemeral_bytes = [i as u8; 32];
			let msg_handler = MessageHandler { chan_handler: &cfgs[i].chan_handler, route_handler: &cfgs[i].routing_handler };
			let peer = PeerManager::new(msg_handler, node_secret, &ephemeral_bytes, &cfgs[i].logger);
			peers.push(peer);
		}

		peers
	}

	fn establish_connection<'a>(peer_a: &PeerManager<FileDescriptor, &'a test_utils::TestChannelMessageHandler, &'a test_utils::TestRoutingMessageHandler, &'a test_utils::TestLogger>, peer_b: &PeerManager<FileDescriptor, &'a test_utils::TestChannelMessageHandler, &'a test_utils::TestRoutingMessageHandler, &'a test_utils::TestLogger>) -> (FileDescriptor, FileDescriptor) {
		let secp_ctx = Secp256k1::new();
		let a_id = PublicKey::from_secret_key(&secp_ctx, &peer_a.our_node_secret);
		let mut fd_a = FileDescriptor { fd: 1, outbound_data: Arc::new(Mutex::new(Vec::new())) };
		let mut fd_b = FileDescriptor { fd: 1, outbound_data: Arc::new(Mutex::new(Vec::new())) };
		let initial_data = peer_b.new_outbound_connection(a_id, fd_b.clone()).unwrap();
		peer_a.new_inbound_connection(fd_a.clone()).unwrap();
		assert_eq!(peer_a.read_event(&mut fd_a, &initial_data).unwrap(), false);
		assert_eq!(peer_b.read_event(&mut fd_b, &fd_a.outbound_data.lock().unwrap().split_off(0)).unwrap(), false);
		assert_eq!(peer_a.read_event(&mut fd_a, &fd_b.outbound_data.lock().unwrap().split_off(0)).unwrap(), false);
		(fd_a.clone(), fd_b.clone())
	}

	#[test]
	fn test_disconnect_peer() {
		// Simple test which builds a network of PeerManager, connects and brings them to NoiseState::Finished and
		// push a DisconnectPeer event to remove the node flagged by id
		let cfgs = create_peermgr_cfgs(2);
		let chan_handler = test_utils::TestChannelMessageHandler::new();
		let mut peers = create_network(2, &cfgs);
		establish_connection(&peers[0], &peers[1]);
		assert_eq!(peers[0].peers.lock().unwrap().peers.len(), 1);

		let secp_ctx = Secp256k1::new();
		let their_id = PublicKey::from_secret_key(&secp_ctx, &peers[1].our_node_secret);

		chan_handler.pending_events.lock().unwrap().push(events::MessageSendEvent::HandleError {
			node_id: their_id,
			action: msgs::ErrorAction::DisconnectPeer { msg: None },
		});
		assert_eq!(chan_handler.pending_events.lock().unwrap().len(), 1);
		peers[0].message_handler.chan_handler = &chan_handler;

		peers[0].process_events();
		assert_eq!(peers[0].peers.lock().unwrap().peers.len(), 0);
	}

	#[test]
	fn test_timer_tick_occurred() {
		// Create peers, a vector of two peer managers, perform initial set up and check that peers[0] has one Peer.
		let cfgs = create_peermgr_cfgs(2);
		let peers = create_network(2, &cfgs);
		establish_connection(&peers[0], &peers[1]);
		assert_eq!(peers[0].peers.lock().unwrap().peers.len(), 1);

		// peers[0] awaiting_pong is set to true, but the Peer is still connected
		peers[0].timer_tick_occurred();
		assert_eq!(peers[0].peers.lock().unwrap().peers.len(), 1);

		// Since timer_tick_occurred() is called again when awaiting_pong is true, all Peers are disconnected
		peers[0].timer_tick_occurred();
		assert_eq!(peers[0].peers.lock().unwrap().peers.len(), 0);
	}

	#[test]
	fn test_do_attempt_write_data() {
		// Create 2 peers with custom TestRoutingMessageHandlers and connect them.
		let cfgs = create_peermgr_cfgs(2);
		cfgs[0].routing_handler.request_full_sync.store(true, Ordering::Release);
		cfgs[1].routing_handler.request_full_sync.store(true, Ordering::Release);
		let peers = create_network(2, &cfgs);

		// By calling establish_connect, we trigger do_attempt_write_data between
		// the peers. Previously this function would mistakenly enter an infinite loop
		// when there were more channel messages available than could fit into a peer's
		// buffer. This issue would now be detected by this test (because we use custom
		// RoutingMessageHandlers that intentionally return more channel messages
		// than can fit into a peer's buffer).
		let (mut fd_a, mut fd_b) = establish_connection(&peers[0], &peers[1]);

		// Make each peer to read the messages that the other peer just wrote to them.
		peers[1].read_event(&mut fd_b, &fd_a.outbound_data.lock().unwrap().split_off(0)).unwrap();
		peers[0].read_event(&mut fd_a, &fd_b.outbound_data.lock().unwrap().split_off(0)).unwrap();

		// Check that each peer has received the expected number of channel updates and channel
		// announcements.
		assert_eq!(cfgs[0].routing_handler.chan_upds_recvd.load(Ordering::Acquire), 100);
		assert_eq!(cfgs[0].routing_handler.chan_anns_recvd.load(Ordering::Acquire), 50);
		assert_eq!(cfgs[1].routing_handler.chan_upds_recvd.load(Ordering::Acquire), 100);
		assert_eq!(cfgs[1].routing_handler.chan_anns_recvd.load(Ordering::Acquire), 50);
	}
}
