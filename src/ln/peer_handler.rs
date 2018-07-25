use secp256k1::key::{SecretKey,PublicKey};

use ln::msgs;
use ln::msgs::{MsgEncodable,MsgDecodable};
use ln::peer_channel_encryptor::{PeerChannelEncryptor,NextNoiseStep};
use util::byte_utils;
use util::events::{EventsProvider,Event};

use std::collections::{HashMap,LinkedList};
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::{cmp,error,mem,hash,fmt};

pub struct MessageHandler {
	pub chan_handler: Arc<msgs::ChannelMessageHandler>,
	pub route_handler: Arc<msgs::RoutingMessageHandler>,
}

/// Provides an object which can be used to send data to and which uniquely identifies a connection
/// to a remote host. You will need to be able to generate multiple of these which meet Eq and
/// implement Hash to meet the PeerManager API.
/// For efficiency, Clone should be relatively cheap for this type.
/// You probably want to just extend an int and put a file descriptor in a struct and implement
/// send_data. Note that if you are using a higher-level net library that may close() itself, be
/// careful to ensure you don't have races whereby you might register a new connection with an fd
/// the same as a yet-to-be-disconnect_event()-ed.
pub trait SocketDescriptor : cmp::Eq + hash::Hash + Clone {
	/// Attempts to send some data from the given Vec starting at the given offset to the peer.
	/// Returns the amount of data which was sent, possibly 0 if the socket has since disconnected.
	/// Note that in the disconnected case, a disconnect_event must still fire and further write
	/// attempts may occur until that time.
	/// If the returned size is smaller than data.len() - write_offset, a write_available event must
	/// trigger the next time more data can be written. Additionally, until the a send_data event
	/// completes fully, no further read_events should trigger on the same peer!
	/// If a read_event on this descriptor had previously returned true (indicating that read
	/// events should be paused to prevent DoS in the send buffer), resume_read may be set
	/// indicating that read events on this descriptor should resume. A resume_read of false does
	/// *not* imply that further read events should be paused.
	fn send_data(&mut self, data: &Vec<u8>, write_offset: usize, resume_read: bool) -> usize;
	/// Disconnect the socket pointed to by this SocketDescriptor. Once this function returns, no
	/// more calls to write_event, read_event or disconnect_event may be made with this descriptor.
	/// No disconnect_event should be generated as a result of this call, though obviously races
	/// may occur whereby disconnect_socket is called after a call to disconnect_event but prior to
	/// that event completing.
	fn disconnect_socket(&mut self);
}

/// Error for PeerManager errors. If you get one of these, you must disconnect the socket and
/// generate no further read/write_events for the descriptor, only triggering a single
/// disconnect_event (unless it was provided in response to a new_*_connection event, in which case
/// no such disconnect_event must be generated and the socket be silently disconencted).
pub struct PeerHandleError {
	no_connection_possible: bool,
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

struct Peer {
	channel_encryptor: PeerChannelEncryptor,
	outbound: bool,
	their_node_id: Option<PublicKey>,
	their_global_features: Option<msgs::GlobalFeatures>,
	their_local_features: Option<msgs::LocalFeatures>,

	pending_outbound_buffer: LinkedList<Vec<u8>>,
	pending_outbound_buffer_first_msg_offset: usize,
	awaiting_write_event: bool,

	pending_read_buffer: Vec<u8>,
	pending_read_buffer_pos: usize,
	pending_read_is_header: bool,
}

struct PeerHolder<Descriptor: SocketDescriptor> {
	peers: HashMap<Descriptor, Peer>,
	/// Only add to this set when noise completes:
	node_id_to_descriptor: HashMap<PublicKey, Descriptor>,
}

pub struct PeerManager<Descriptor: SocketDescriptor> {
	message_handler: MessageHandler,
	peers: Mutex<PeerHolder<Descriptor>>,
	pending_events: Mutex<Vec<Event>>,
	our_node_secret: SecretKey,
	initial_syncs_sent: AtomicUsize,
}


macro_rules! encode_msg {
	($msg: expr, $msg_code: expr) => {
		{
			let just_msg = $msg.encode();
			let mut encoded_msg = Vec::with_capacity(just_msg.len() + 2);
			encoded_msg.extend_from_slice(&byte_utils::be16_to_array($msg_code));
			encoded_msg.extend_from_slice(&just_msg[..]);
			encoded_msg
		}
	}
}

//TODO: Really should do something smarter for this
const INITIAL_SYNCS_TO_SEND: usize = 5;

/// Manages and reacts to connection events. You probably want to use file descriptors as PeerIds.
/// PeerIds may repeat, but only after disconnect_event() has been called.
impl<Descriptor: SocketDescriptor> PeerManager<Descriptor> {
	pub fn new(message_handler: MessageHandler, our_node_secret: SecretKey) -> PeerManager<Descriptor> {
		PeerManager {
			message_handler: message_handler,
			peers: Mutex::new(PeerHolder { peers: HashMap::new(), node_id_to_descriptor: HashMap::new() }),
			pending_events: Mutex::new(Vec::new()),
			our_node_secret: our_node_secret,
			initial_syncs_sent: AtomicUsize::new(0),
		}
	}

	/// Get the list of node ids for peers which have completed the initial handshake.
	/// For outbound connections, this will be the same as the their_node_id parameter passed in to
	/// new_outbound_connection, however entries will only appear once the initial handshake has
	/// completed and we are sure the remote peer has the private key for the given node_id.
	pub fn get_peer_node_ids(&self) -> Vec<PublicKey> {
		let peers = self.peers.lock().unwrap();
		peers.peers.values().filter_map(|p| p.their_node_id).collect()
	}

	/// Indicates a new outbound connection has been established to a node with the given node_id.
	/// Note that if an Err is returned here you MUST NOT call disconnect_event for the new
	/// descriptor but must disconnect the connection immediately.
	/// Returns some bytes to send to the remote node.
	/// Panics if descriptor is duplicative with some other descriptor which has not yet has a
	/// disconnect_event.
	pub fn new_outbound_connection(&self, their_node_id: PublicKey, descriptor: Descriptor) -> Result<Vec<u8>, PeerHandleError> {
		let mut peer_encryptor = PeerChannelEncryptor::new_outbound(their_node_id.clone());
		let res = peer_encryptor.get_act_one().to_vec();
		let pending_read_buffer = [0; 50].to_vec(); // Noise act two is 50 bytes

		let mut peers = self.peers.lock().unwrap();
		if peers.peers.insert(descriptor, Peer {
			channel_encryptor: peer_encryptor,
			outbound: true,
			their_node_id: Some(their_node_id),
			their_global_features: None,
			their_local_features: None,

			pending_outbound_buffer: LinkedList::new(),
			pending_outbound_buffer_first_msg_offset: 0,
			awaiting_write_event: false,

			pending_read_buffer: pending_read_buffer,
			pending_read_buffer_pos: 0,
			pending_read_is_header: false,
		}).is_some() {
			panic!("PeerManager driver duplicated descriptors!");
		};
		Ok(res)
	}

	/// Indicates a new inbound connection has been established.
	/// May refuse the connection by returning an Err, but will never write bytes to the remote end
	/// (outbound connector always speaks first). Note that if an Err is returned here you MUST NOT
	/// call disconnect_event for the new descriptor but must disconnect the connection
	/// immediately.
	/// Panics if descriptor is duplicative with some other descriptor which has not yet has a
	/// disconnect_event.
	pub fn new_inbound_connection(&self, descriptor: Descriptor) -> Result<(), PeerHandleError> {
		let peer_encryptor = PeerChannelEncryptor::new_inbound(&self.our_node_secret);
		let pending_read_buffer = [0; 50].to_vec(); // Noise act one is 50 bytes

		let mut peers = self.peers.lock().unwrap();
		if peers.peers.insert(descriptor, Peer {
			channel_encryptor: peer_encryptor,
			outbound: false,
			their_node_id: None,
			their_global_features: None,
			their_local_features: None,

			pending_outbound_buffer: LinkedList::new(),
			pending_outbound_buffer_first_msg_offset: 0,
			awaiting_write_event: false,

			pending_read_buffer: pending_read_buffer,
			pending_read_buffer_pos: 0,
			pending_read_is_header: false,
		}).is_some() {
			panic!("PeerManager driver duplicated descriptors!");
		};
		Ok(())
	}

	fn do_attempt_write_data(descriptor: &mut Descriptor, peer: &mut Peer) {
		while !peer.awaiting_write_event {
			if {
				let next_buff = match peer.pending_outbound_buffer.front() {
					None => return,
					Some(buff) => buff,
				};
				let should_be_reading = peer.pending_outbound_buffer.len() < 10;

				let data_sent = descriptor.send_data(next_buff, peer.pending_outbound_buffer_first_msg_offset, should_be_reading);
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
	/// May return an Err to indicate that the connection should be closed.
	/// Will most likely call send_data on the descriptor passed in (or the descriptor handed into
	/// new_*_connection) before returning. Thus, be very careful with reentrancy issues! The
	/// invariants around calling write_event in case a write did not fully complete must still
	/// hold - be ready to call write_event again if a write call generated here isn't sufficient!
	/// Panics if the descriptor was not previously registered in a new_*_connection event.
	pub fn write_event(&self, descriptor: &mut Descriptor) -> Result<(), PeerHandleError> {
		let mut peers = self.peers.lock().unwrap();
		match peers.peers.get_mut(descriptor) {
			None => panic!("Descriptor for write_event is not already known to PeerManager"),
			Some(peer) => {
				peer.awaiting_write_event = false;
				Self::do_attempt_write_data(descriptor, peer);
			}
		};
		Ok(())
	}

	/// Indicates that data was read from the given socket descriptor.
	/// May return an Err to indicate that the connection should be closed.
	/// Will very likely call send_data on the descriptor passed in (or a descriptor handed into
	/// new_*_connection) before returning. Thus, be very careful with reentrancy issues! The
	/// invariants around calling write_event in case a write did not fully complete must still
	/// hold. Note that this function will often call send_data on many peers before returning, not
	/// just this peer!
	/// If Ok(true) is returned, further read_events should not be triggered until a write_event on
	/// this file descriptor has resume_read set (preventing DoS issues in the send buffer). Note
	/// that this must be true even if a send_data call with resume_read=true was made during the
	/// course of this function!
	/// Panics if the descriptor was not previously registered in a new_*_connection event.
	pub fn read_event(&self, peer_descriptor: &mut Descriptor, data: Vec<u8>) -> Result<bool, PeerHandleError> {
		match self.do_read_event(peer_descriptor, data) {
			Ok(res) => Ok(res),
			Err(e) => {
				self.disconnect_event_internal(peer_descriptor, e.no_connection_possible);
				Err(e)
			}
		}
	}

	fn do_read_event(&self, peer_descriptor: &mut Descriptor, data: Vec<u8>) -> Result<bool, PeerHandleError> {
		let pause_read = {
			let mut peers = self.peers.lock().unwrap();
			let (should_insert_node_id, pause_read) = match peers.peers.get_mut(peer_descriptor) {
				None => panic!("Descriptor for read_event is not already known to PeerManager"),
				Some(peer) => {
					assert!(peer.pending_read_buffer.len() > 0);
					assert!(peer.pending_read_buffer.len() > peer.pending_read_buffer_pos);

					let mut insert_node_id = None;
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

							macro_rules! encode_and_send_msg {
								($msg: expr, $msg_code: expr) => {
									peer.pending_outbound_buffer.push_back(peer.channel_encryptor.encrypt_message(&encode_msg!($msg, $msg_code)[..]));
								}
							}

							macro_rules! try_potential_handleerror {
								($thing: expr) => {
									match $thing {
										Ok(x) => x,
										Err(e) => {
											println!("Got error handling message: {}!", e.err);
											if let Some(action) = e.action {
												match action {
													msgs::ErrorAction::UpdateFailHTLC { msg } => {
														encode_and_send_msg!(msg, 131);
														continue;
													},
													msgs::ErrorAction::DisconnectPeer { msg: _ } => {
														return Err(PeerHandleError{ no_connection_possible: false });
													},
													msgs::ErrorAction::IgnoreError => {
														continue;
													},
													msgs::ErrorAction::SendErrorMessage { msg } => {
														encode_and_send_msg!(msg, 17);
														continue;
													},
												}
											} else {
												return Err(PeerHandleError{ no_connection_possible: false });
											}
										}
									};
								}
							}

							macro_rules! try_potential_decodeerror {
								($thing: expr) => {
									match $thing {
										Ok(x) => x,
										Err(_e) => {
											println!("Error decoding message");
											//TODO: Handle e?
											return Err(PeerHandleError{ no_connection_possible: false });
										}
									};
								}
							}

							macro_rules! try_ignore_potential_decodeerror {
								($thing: expr) => {
									match $thing {
										Ok(x) => x,
										Err(_e) => {
											println!("Error decoding message, ignoring due to lnd spec incompatibility. See https://github.com/lightningnetwork/lnd/issues/1407");
											continue;
										}
									};
								}
							}

							let next_step = peer.channel_encryptor.get_noise_step();
							match next_step {
								NextNoiseStep::ActOne => {
									let act_two = try_potential_handleerror!(peer.channel_encryptor.process_act_one_with_key(&peer.pending_read_buffer[..], &self.our_node_secret)).to_vec();
									peer.pending_outbound_buffer.push_back(act_two);
									peer.pending_read_buffer = [0; 66].to_vec(); // act three is 66 bytes long
								},
								NextNoiseStep::ActTwo => {
									let act_three = try_potential_handleerror!(peer.channel_encryptor.process_act_two(&peer.pending_read_buffer[..], &self.our_node_secret)).to_vec();
									peer.pending_outbound_buffer.push_back(act_three);
									peer.pending_read_buffer = [0; 18].to_vec(); // Message length header is 18 bytes
									peer.pending_read_is_header = true;

									insert_node_id = Some(peer.their_node_id.unwrap());
									let mut local_features = msgs::LocalFeatures::new();
									if self.initial_syncs_sent.load(Ordering::Acquire) < INITIAL_SYNCS_TO_SEND {
										self.initial_syncs_sent.fetch_add(1, Ordering::AcqRel);
										local_features.set_initial_routing_sync();
									}
									encode_and_send_msg!(msgs::Init {
										global_features: msgs::GlobalFeatures::new(),
										local_features,
									}, 16);
								},
								NextNoiseStep::ActThree => {
									let their_node_id = try_potential_handleerror!(peer.channel_encryptor.process_act_three(&peer.pending_read_buffer[..]));
									peer.pending_read_buffer = [0; 18].to_vec(); // Message length header is 18 bytes
									peer.pending_read_is_header = true;
									peer.their_node_id = Some(their_node_id);
									insert_node_id = Some(peer.their_node_id.unwrap());
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

										let msg_type = byte_utils::slice_to_be16(&msg_data[0..2]);
										if msg_type != 16 && peer.their_global_features.is_none() {
											// Need an init message as first message
											return Err(PeerHandleError{ no_connection_possible: false });
										}
										match msg_type {
											// Connection control:
											16 => {
												let msg = try_potential_decodeerror!(msgs::Init::decode(&msg_data[2..]));
												if msg.global_features.requires_unknown_bits() {
													return Err(PeerHandleError{ no_connection_possible: true });
												}
												if msg.local_features.requires_unknown_bits() {
													return Err(PeerHandleError{ no_connection_possible: true });
												}
												peer.their_global_features = Some(msg.global_features);
												peer.their_local_features = Some(msg.local_features);

												if !peer.outbound {
													let mut local_features = msgs::LocalFeatures::new();
													if self.initial_syncs_sent.load(Ordering::Acquire) < INITIAL_SYNCS_TO_SEND {
														self.initial_syncs_sent.fetch_add(1, Ordering::AcqRel);
														local_features.set_initial_routing_sync();
													}
													encode_and_send_msg!(msgs::Init {
														global_features: msgs::GlobalFeatures::new(),
														local_features,
													}, 16);
												}
											},
											17 => {
												// Error msg
											},

											18 => {
												let msg = try_potential_decodeerror!(msgs::Ping::decode(&msg_data[2..]));
												if msg.ponglen < 65532 {
													let resp = msgs::Pong { byteslen: msg.ponglen };
													encode_and_send_msg!(resp, 19);
												}
											},
											19 => {
												try_potential_decodeerror!(msgs::Pong::decode(&msg_data[2..]));
											},

											// Channel control:
											32 => {
												let msg = try_potential_decodeerror!(msgs::OpenChannel::decode(&msg_data[2..]));
												let resp = try_potential_handleerror!(self.message_handler.chan_handler.handle_open_channel(&peer.their_node_id.unwrap(), &msg));
												encode_and_send_msg!(resp, 33);
											},
											33 => {
												let msg = try_potential_decodeerror!(msgs::AcceptChannel::decode(&msg_data[2..]));
												try_potential_handleerror!(self.message_handler.chan_handler.handle_accept_channel(&peer.their_node_id.unwrap(), &msg));
											},

											34 => {
												let msg = try_potential_decodeerror!(msgs::FundingCreated::decode(&msg_data[2..]));
												let resp = try_potential_handleerror!(self.message_handler.chan_handler.handle_funding_created(&peer.their_node_id.unwrap(), &msg));
												encode_and_send_msg!(resp, 35);
											},
											35 => {
												let msg = try_potential_decodeerror!(msgs::FundingSigned::decode(&msg_data[2..]));
												try_potential_handleerror!(self.message_handler.chan_handler.handle_funding_signed(&peer.their_node_id.unwrap(), &msg));
											},
											36 => {
												let msg = try_potential_decodeerror!(msgs::FundingLocked::decode(&msg_data[2..]));
												let resp_option = try_potential_handleerror!(self.message_handler.chan_handler.handle_funding_locked(&peer.their_node_id.unwrap(), &msg));
												match resp_option {
													Some(resp) => encode_and_send_msg!(resp, 259),
													None => {},
												}
											},

											38 => {
												let msg = try_potential_decodeerror!(msgs::Shutdown::decode(&msg_data[2..]));
												let resp_options = try_potential_handleerror!(self.message_handler.chan_handler.handle_shutdown(&peer.their_node_id.unwrap(), &msg));
												if let Some(resp) = resp_options.0 {
													encode_and_send_msg!(resp, 38);
												}
												if let Some(resp) = resp_options.1 {
													encode_and_send_msg!(resp, 39);
												}
											},
											39 => {
												let msg = try_potential_decodeerror!(msgs::ClosingSigned::decode(&msg_data[2..]));
												let resp_option = try_potential_handleerror!(self.message_handler.chan_handler.handle_closing_signed(&peer.their_node_id.unwrap(), &msg));
												if let Some(resp) = resp_option {
													encode_and_send_msg!(resp, 39);
												}
											},

											128 => {
												let msg = try_potential_decodeerror!(msgs::UpdateAddHTLC::decode(&msg_data[2..]));
												try_potential_handleerror!(self.message_handler.chan_handler.handle_update_add_htlc(&peer.their_node_id.unwrap(), &msg));
											},
											130 => {
												let msg = try_potential_decodeerror!(msgs::UpdateFulfillHTLC::decode(&msg_data[2..]));
												try_potential_handleerror!(self.message_handler.chan_handler.handle_update_fulfill_htlc(&peer.their_node_id.unwrap(), &msg));
											},
											131 => {
												let msg = try_potential_decodeerror!(msgs::UpdateFailHTLC::decode(&msg_data[2..]));
												let chan_update = try_potential_handleerror!(self.message_handler.chan_handler.handle_update_fail_htlc(&peer.their_node_id.unwrap(), &msg));
												if let Some(update) = chan_update {
													self.message_handler.route_handler.handle_htlc_fail_channel_update(&update);
												}
											},
											135 => {
												let msg = try_potential_decodeerror!(msgs::UpdateFailMalformedHTLC::decode(&msg_data[2..]));
												try_potential_handleerror!(self.message_handler.chan_handler.handle_update_fail_malformed_htlc(&peer.their_node_id.unwrap(), &msg));
											},

											132 => {
												let msg = try_potential_decodeerror!(msgs::CommitmentSigned::decode(&msg_data[2..]));
												let resps = try_potential_handleerror!(self.message_handler.chan_handler.handle_commitment_signed(&peer.their_node_id.unwrap(), &msg));
												encode_and_send_msg!(resps.0, 133);
												if let Some(resp) = resps.1 {
													encode_and_send_msg!(resp, 132);
												}
											},
											133 => {
												let msg = try_potential_decodeerror!(msgs::RevokeAndACK::decode(&msg_data[2..]));
												let resp_option = try_potential_handleerror!(self.message_handler.chan_handler.handle_revoke_and_ack(&peer.their_node_id.unwrap(), &msg));
												match resp_option {
													Some(resps) => {
														for resp in resps.update_add_htlcs {
															encode_and_send_msg!(resp, 128);
														}
														for resp in resps.update_fulfill_htlcs {
															encode_and_send_msg!(resp, 130);
														}
														for resp in resps.update_fail_htlcs {
															encode_and_send_msg!(resp, 131);
														}
														encode_and_send_msg!(resps.commitment_signed, 132);
													},
													None => {},
												}
											},
											134 => {
												let msg = try_potential_decodeerror!(msgs::UpdateFee::decode(&msg_data[2..]));
												try_potential_handleerror!(self.message_handler.chan_handler.handle_update_fee(&peer.their_node_id.unwrap(), &msg));
											},
											136 => { }, // TODO: channel_reestablish

											// Routing control:
											259 => {
												let msg = try_potential_decodeerror!(msgs::AnnouncementSignatures::decode(&msg_data[2..]));
												try_potential_handleerror!(self.message_handler.chan_handler.handle_announcement_signatures(&peer.their_node_id.unwrap(), &msg));
											},
											256 => {
												let msg = try_potential_decodeerror!(msgs::ChannelAnnouncement::decode(&msg_data[2..]));
												let should_forward = try_potential_handleerror!(self.message_handler.route_handler.handle_channel_announcement(&msg));

												if should_forward {
													// TODO: forward msg along to all our other peers!
												}
											},
											257 => {
												let msg = try_ignore_potential_decodeerror!(msgs::NodeAnnouncement::decode(&msg_data[2..]));
												try_potential_handleerror!(self.message_handler.route_handler.handle_node_announcement(&msg));
											},
											258 => {
												let msg = try_potential_decodeerror!(msgs::ChannelUpdate::decode(&msg_data[2..]));
												try_potential_handleerror!(self.message_handler.route_handler.handle_channel_update(&msg));
											},
											_ => {
												if (msg_type & 1) == 0 {
													return Err(PeerHandleError{ no_connection_possible: true });
												}
											},
										}
									}
								}
							}
						}
					}

					Self::do_attempt_write_data(peer_descriptor, peer);

					(insert_node_id /* should_insert_node_id */, peer.pending_outbound_buffer.len() > 10) // pause_read
				}
			};

			match should_insert_node_id {
				Some(node_id) => { peers.node_id_to_descriptor.insert(node_id, peer_descriptor.clone()); },
				None => {}
			};

			pause_read
		};

		self.process_events();

		Ok(pause_read)
	}

	/// Checks for any events generated by our handlers and processes them. May be needed after eg
	/// calls to ChannelManager::process_pending_htlc_forward.
	pub fn process_events(&self) {
		let mut upstream_events = Vec::new();
		{
			// TODO: There are some DoS attacks here where you can flood someone's outbound send
			// buffer by doing things like announcing channels on another node. We should be willing to
			// drop optional-ish messages when send buffers get full!

			let mut events_generated = self.message_handler.chan_handler.get_and_clear_pending_events();
			let mut peers = self.peers.lock().unwrap();
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
									(descriptor, peer)
								},
								None => panic!("Inconsistent peers set state!"),
							}
						}
					}
				}
				match event {
					Event::FundingGenerationReady {..} => { /* Hand upstream */ },
					Event::FundingBroadcastSafe {..} => { /* Hand upstream */ },
					Event::PaymentReceived {..} => { /* Hand upstream */ },
					Event::PaymentSent {..} => { /* Hand upstream */ },
					Event::PaymentFailed {..} => { /* Hand upstream */ },
					Event::PendingHTLCsForwardable {..} => { /* Hand upstream */ },

					Event::SendOpenChannel { ref node_id, ref msg } => {
						let (mut descriptor, peer) = get_peer_for_forwarding!(node_id, {
								//TODO: Drop the pending channel? (or just let it timeout, but that sucks)
							});
						peer.pending_outbound_buffer.push_back(peer.channel_encryptor.encrypt_message(&encode_msg!(msg, 32)));
						Self::do_attempt_write_data(&mut descriptor, peer);
						continue;
					},
					Event::SendFundingCreated { ref node_id, ref msg } => {
						let (mut descriptor, peer) = get_peer_for_forwarding!(node_id, {
								//TODO: generate a DiscardFunding event indicating to the wallet that
								//they should just throw away this funding transaction
							});
						peer.pending_outbound_buffer.push_back(peer.channel_encryptor.encrypt_message(&encode_msg!(msg, 34)));
						Self::do_attempt_write_data(&mut descriptor, peer);
						continue;
					},
					Event::SendFundingLocked { ref node_id, ref msg, ref announcement_sigs } => {
						let (mut descriptor, peer) = get_peer_for_forwarding!(node_id, {
								//TODO: Do whatever we're gonna do for handling dropped messages
							});
						peer.pending_outbound_buffer.push_back(peer.channel_encryptor.encrypt_message(&encode_msg!(msg, 36)));
						match announcement_sigs {
							&Some(ref announce_msg) => peer.pending_outbound_buffer.push_back(peer.channel_encryptor.encrypt_message(&encode_msg!(announce_msg, 259))),
							&None => {},
						}
						Self::do_attempt_write_data(&mut descriptor, peer);
						continue;
					},
					Event::SendHTLCs { ref node_id, ref msgs, ref commitment_msg } => {
						let (mut descriptor, peer) = get_peer_for_forwarding!(node_id, {
								//TODO: Do whatever we're gonna do for handling dropped messages
							});
						for msg in msgs {
							peer.pending_outbound_buffer.push_back(peer.channel_encryptor.encrypt_message(&encode_msg!(msg, 128)));
						}
						peer.pending_outbound_buffer.push_back(peer.channel_encryptor.encrypt_message(&encode_msg!(commitment_msg, 132)));
						Self::do_attempt_write_data(&mut descriptor, peer);
						continue;
					},
					Event::SendFulfillHTLC { ref node_id, ref msg, ref commitment_msg } => {
						let (mut descriptor, peer) = get_peer_for_forwarding!(node_id, {
								//TODO: Do whatever we're gonna do for handling dropped messages
							});
						peer.pending_outbound_buffer.push_back(peer.channel_encryptor.encrypt_message(&encode_msg!(msg, 130)));
						peer.pending_outbound_buffer.push_back(peer.channel_encryptor.encrypt_message(&encode_msg!(commitment_msg, 132)));
						Self::do_attempt_write_data(&mut descriptor, peer);
						continue;
					},
					Event::SendFailHTLC { ref node_id, ref msg, ref commitment_msg } => {
						let (mut descriptor, peer) = get_peer_for_forwarding!(node_id, {
								//TODO: Do whatever we're gonna do for handling dropped messages
							});
						peer.pending_outbound_buffer.push_back(peer.channel_encryptor.encrypt_message(&encode_msg!(msg, 131)));
						peer.pending_outbound_buffer.push_back(peer.channel_encryptor.encrypt_message(&encode_msg!(commitment_msg, 132)));
						Self::do_attempt_write_data(&mut descriptor, peer);
						continue;
					},
					Event::SendShutdown { ref node_id, ref msg } => {
						let (mut descriptor, peer) = get_peer_for_forwarding!(node_id, {
								//TODO: Do whatever we're gonna do for handling dropped messages
							});
						peer.pending_outbound_buffer.push_back(peer.channel_encryptor.encrypt_message(&encode_msg!(msg, 38)));
						Self::do_attempt_write_data(&mut descriptor, peer);
						continue;
					},
					Event::BroadcastChannelAnnouncement { ref msg, ref update_msg } => {
						if self.message_handler.route_handler.handle_channel_announcement(msg).is_ok() && self.message_handler.route_handler.handle_channel_update(update_msg).is_ok() {
							let encoded_msg = encode_msg!(msg, 256);
							let encoded_update_msg = encode_msg!(update_msg, 258);

							for (ref descriptor, ref mut peer) in peers.peers.iter_mut() {
								if !peer.channel_encryptor.is_ready_for_encryption() {
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
								Self::do_attempt_write_data(&mut (*descriptor).clone(), peer);
							}
						}
						continue;
					},
					Event::BroadcastChannelUpdate { ref msg } => {
						if self.message_handler.route_handler.handle_channel_update(msg).is_ok() {
							let encoded_msg = encode_msg!(msg, 258);

							for (ref descriptor, ref mut peer) in peers.peers.iter_mut() {
								if !peer.channel_encryptor.is_ready_for_encryption() {
									continue
								}
								peer.pending_outbound_buffer.push_back(peer.channel_encryptor.encrypt_message(&encoded_msg[..]));
								Self::do_attempt_write_data(&mut (*descriptor).clone(), peer);
							}
						}
						continue;
					},
					Event::DisconnectPeer { ref node_id, ref msg } => {
						if let Some(mut descriptor) = peers.node_id_to_descriptor.remove(node_id) {
							if let Some(mut peer) = peers.peers.remove(&descriptor) {
								if let Some(ref msg) = *msg {
									peer.pending_outbound_buffer.push_back(peer.channel_encryptor.encrypt_message(&encode_msg!(msg, 17)));
									// This isn't guaranteed to work, but if there is enough free
									// room in the send buffer, put the error message there...
									Self::do_attempt_write_data(&mut descriptor, &mut peer);
								}
							}
							descriptor.disconnect_socket();
							self.message_handler.chan_handler.peer_disconnected(&node_id, false);
						}
						continue;
					},
				}

				upstream_events.push(event);
			}
		}

		let mut pending_events = self.pending_events.lock().unwrap();
		for event in upstream_events.drain(..) {
			pending_events.push(event);
		}
	}

	/// Indicates that the given socket descriptor's connection is now closed.
	/// This must be called even if a PeerHandleError was given for a read_event or write_event,
	/// but must NOT be called if a PeerHandleError was provided out of a new_*_connection event!
	/// Panics if the descriptor was not previously registered in a successful new_*_connection event.
	pub fn disconnect_event(&self, descriptor: &Descriptor) {
		self.disconnect_event_internal(descriptor, false);
	}

	fn disconnect_event_internal(&self, descriptor: &Descriptor, no_connection_possible: bool) {
		let mut peers = self.peers.lock().unwrap();
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
}

impl<Descriptor: SocketDescriptor> EventsProvider for PeerManager<Descriptor> {
	fn get_and_clear_pending_events(&self) -> Vec<Event> {
		let mut pending_events = self.pending_events.lock().unwrap();
		let mut ret = Vec::new();
		mem::swap(&mut ret, &mut *pending_events);
		ret
	}
}

#[cfg(test)]
mod tests {
	use ln::peer_handler::{PeerManager, MessageHandler, SocketDescriptor};
	use util::events;
	use util::test_utils;

	use secp256k1::Secp256k1;
	use secp256k1::key::{SecretKey, PublicKey};

	use rand::{thread_rng, Rng};

	use std::sync::{Arc};

	#[derive(PartialEq, Eq, Clone, Hash)]
	struct FileDescriptor {
		fd: u16,
	}

	impl SocketDescriptor for FileDescriptor {
		fn send_data(&mut self, data: &Vec<u8>, write_offset: usize, _resume_read: bool) -> usize {
			assert!(write_offset < data.len());
			data.len() - write_offset
		}

		fn disconnect_socket(&mut self) {}
	}

	fn create_network(peer_count: usize) -> Vec<PeerManager<FileDescriptor>> {
		let secp_ctx = Secp256k1::new();
		let mut peers = Vec::new();
		let mut rng = thread_rng();

		for _ in 0..peer_count {
			let chan_handler = test_utils::TestChannelMessageHandler::new();
			let router = test_utils::TestRoutingMessageHandler::new();
			let node_id = {
				let mut key_slice = [0;32];
				rng.fill_bytes(&mut key_slice);
				SecretKey::from_slice(&secp_ctx, &key_slice).unwrap()
			};
			let msg_handler = MessageHandler { chan_handler: Arc::new(chan_handler), route_handler: Arc::new(router) };
			let peer = PeerManager::new(msg_handler, node_id);
			peers.push(peer);
		}

		peers
	}

	fn establish_connection(peer_a: &PeerManager<FileDescriptor>, peer_b: &PeerManager<FileDescriptor>) {
		let secp_ctx = Secp256k1::new();
		let their_id = PublicKey::from_secret_key(&secp_ctx, &peer_b.our_node_secret).unwrap();
		let fd = FileDescriptor { fd: 1};
		peer_a.new_inbound_connection(fd.clone()).unwrap();
		peer_a.peers.lock().unwrap().node_id_to_descriptor.insert(their_id, fd.clone());
	}

	#[test]
	fn test_disconnect_peer() {
		// Simple test which builds a network of PeerManager, connects and brings them to NoiseState::Finished and
		// push an DisconnectPeer event to remove the node flagged by id
		let mut peers = create_network(2);
		establish_connection(&peers[0], &peers[1]);
		assert_eq!(peers[0].peers.lock().unwrap().peers.len(), 1);

		let secp_ctx = Secp256k1::new();
		let their_id = PublicKey::from_secret_key(&secp_ctx, &peers[1].our_node_secret).unwrap();

		let chan_handler = test_utils::TestChannelMessageHandler::new();
		chan_handler.pending_events.lock().unwrap().push(events::Event::DisconnectPeer {
			node_id: their_id,
			msg: None,
		});
		assert_eq!(chan_handler.pending_events.lock().unwrap().len(), 1);
		peers[0].message_handler.chan_handler = Arc::new(chan_handler);

		peers[0].process_events();
		assert_eq!(peers[0].peers.lock().unwrap().peers.len(), 0);
	}
}
