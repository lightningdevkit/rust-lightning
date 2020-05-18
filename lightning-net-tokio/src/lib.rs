//! A socket handling library for those running in Tokio environments who wish to use
//! rust-lightning with native TcpStreams.
//!
//! Designed to be as simple as possible, the high-level usage is almost as simple as "hand over a
//! TcpStream and a reference to a PeerManager and the rest is handled", except for the
//! [Event](../lightning/util/events/enum.Event.html) handlng mechanism, see below.
//!
//! The PeerHandler, due to the fire-and-forget nature of this logic, must be an Arc, and must use
//! the SocketDescriptor provided here as the PeerHandler's SocketDescriptor.
//!
//! Three methods are exposed to register a new connection for handling in tokio::spawn calls, see
//! their individual docs for more. All three take a
//! [mpsc::Sender<()>](../tokio/sync/mpsc/struct.Sender.html) which is sent into every time
//! something occurs which may result in lightning [Events](../lightning/util/events/enum.Event.html).
//! The call site should, thus, look something like this:
//! ```
//! use tokio::sync::mpsc;
//! use tokio::net::TcpStream;
//! use bitcoin::secp256k1::key::PublicKey;
//! use lightning::util::events::EventsProvider;
//! use std::net::SocketAddr;
//! use std::sync::Arc;
//!
//! // Define concrete types for our high-level objects:
//! type TxBroadcaster = dyn lightning::chain::chaininterface::BroadcasterInterface;
//! type FeeEstimator = dyn lightning::chain::chaininterface::FeeEstimator;
//! type Logger = dyn lightning::util::logger::Logger;
//! type ChainWatchInterface = dyn lightning::chain::chaininterface::ChainWatchInterface;
//! type ChannelMonitor = lightning::ln::channelmonitor::SimpleManyChannelMonitor<lightning::chain::transaction::OutPoint, lightning::chain::keysinterface::InMemoryChannelKeys, Arc<TxBroadcaster>, Arc<FeeEstimator>, Arc<Logger>, Arc<ChainWatchInterface>>;
//! type ChannelManager = lightning::ln::channelmanager::SimpleArcChannelManager<ChannelMonitor, TxBroadcaster, FeeEstimator, Logger>;
//! type PeerManager = lightning::ln::peer_handler::SimpleArcPeerManager<lightning_net_tokio::SocketDescriptor, ChannelMonitor, TxBroadcaster, FeeEstimator, Logger>;
//!
//! // Connect to node with pubkey their_node_id at addr:
//! async fn connect_to_node(peer_manager: PeerManager, channel_monitor: Arc<ChannelMonitor>, channel_manager: ChannelManager, their_node_id: PublicKey, addr: SocketAddr) {
//!     let (sender, mut receiver) = mpsc::channel(2);
//!     lightning_net_tokio::connect_outbound(peer_manager, sender, their_node_id, addr).await;
//!     loop {
//!         receiver.recv().await;
//!         for _event in channel_manager.get_and_clear_pending_events().drain(..) {
//!             // Handle the event!
//!         }
//!         for _event in channel_monitor.get_and_clear_pending_events().drain(..) {
//!             // Handle the event!
//!         }
//!     }
//! }
//!
//! // Begin reading from a newly accepted socket and talk to the peer:
//! async fn accept_socket(peer_manager: PeerManager, channel_monitor: Arc<ChannelMonitor>, channel_manager: ChannelManager, socket: TcpStream) {
//!     let (sender, mut receiver) = mpsc::channel(2);
//!     lightning_net_tokio::setup_inbound(peer_manager, sender, socket);
//!     loop {
//!         receiver.recv().await;
//!         for _event in channel_manager.get_and_clear_pending_events().drain(..) {
//!             // Handle the event!
//!         }
//!         for _event in channel_monitor.get_and_clear_pending_events().drain(..) {
//!             // Handle the event!
//!         }
//!     }
//! }
//! ```

use bitcoin::secp256k1::key::PublicKey;

use tokio::net::TcpStream;
use tokio::{io, time};
use tokio::sync::mpsc;
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};

use lightning::ln::peer_handler;
use lightning::ln::peer_handler::SocketDescriptor as LnSocketTrait;
use lightning::ln::msgs::ChannelMessageHandler;
use lightning::util::logger::Logger;

use std::{task, thread};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use std::hash::Hash;

static ID_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Connection contains all our internal state for a connection - we hold a reference to the
/// Connection object (in an Arc<Mutex<>>) in each SocketDescriptor we create as well as in the
/// read future (which is returned by schedule_read).
struct Connection {
	writer: Option<io::WriteHalf<TcpStream>>,
	event_notify: mpsc::Sender<()>,
	// Because our PeerManager is templated by user-provided types, and we can't (as far as I can
	// tell) have a const RawWakerVTable built out of templated functions, we need some indirection
	// between being woken up with write-ready and calling PeerManager::write_buffer_spce_avail.
	// This provides that indirection, with a Sender which gets handed to the PeerManager Arc on
	// the schedule_read stack.
	//
	// An alternative (likely more effecient) approach would involve creating a RawWakerVTable at
	// runtime with functions templated by the Arc<PeerManager> type, calling
	// write_buffer_space_avail directly from tokio's write wake, however doing so would require
	// more unsafe voodo than I really feel like writing.
	write_avail: mpsc::Sender<()>,
	// When we are told by rust-lightning to pause read (because we have writes backing up), we do
	// so by setting read_paused. At that point, the read task will stop reading bytes from the
	// socket. To wake it up (without otherwise changing its state, we can push a value into this
	// Sender.
	read_waker: mpsc::Sender<()>,
	// When we are told by rust-lightning to disconnect, we can't return to rust-lightning until we
	// are sure we won't call any more read/write PeerManager functions with the same connection.
	// This is set to true if we're in such a condition (with disconnect checked before with the
	// top-level mutex held) and false when we can return.
	block_disconnect_socket: bool,
	read_paused: bool,
	rl_requested_disconnect: bool,
	id: u64,
}
impl Connection {
	fn event_trigger(us: &mut MutexGuard<Self>) {
		match us.event_notify.try_send(()) {
			Ok(_) => {},
			Err(mpsc::error::TrySendError::Full(_)) => {
				// Ignore full errors as we just need the user to poll after this point, so if they
				// haven't received the last send yet, it doesn't matter.
			},
			_ => panic!()
		}
	}
	async fn schedule_read<CMH: ChannelMessageHandler + 'static, L: Logger + 'static + ?Sized>(peer_manager: Arc<peer_handler::PeerManager<SocketDescriptor, Arc<CMH>, Arc<L>>>, us: Arc<Mutex<Self>>, mut reader: io::ReadHalf<TcpStream>, mut read_wake_receiver: mpsc::Receiver<()>, mut write_avail_receiver: mpsc::Receiver<()>) {
		let peer_manager_ref = peer_manager.clone();
		// 8KB is nice and big but also should never cause any issues with stack overflowing.
		let mut buf = [0; 8192];

		let mut our_descriptor = SocketDescriptor::new(us.clone());
		// An enum describing why we did/are disconnecting:
		enum Disconnect {
			// Rust-Lightning told us to disconnect, either by returning an Err or by calling
			// SocketDescriptor::disconnect_socket.
			// In this case, we do not call peer_manager.socket_disconnected() as Rust-Lightning
			// already knows we're disconnected.
			CloseConnection,
			// The connection was disconnected for some other reason, ie because the socket was
			// closed.
			// In this case, we do need to call peer_manager.socket_disconnected() to inform
			// Rust-Lightning that the socket is gone.
			PeerDisconnected
		};
		let disconnect_type = loop {
			macro_rules! shutdown_socket {
				($err: expr, $need_disconnect: expr) => { {
					println!("Disconnecting peer due to {}!", $err);
					break $need_disconnect;
				} }
			}

			macro_rules! prepare_read_write_call {
				() => { {
					let mut us_lock = us.lock().unwrap();
					if us_lock.rl_requested_disconnect {
						shutdown_socket!("disconnect_socket() call from RL", Disconnect::CloseConnection);
					}
					us_lock.block_disconnect_socket = true;
				} }
			}

			let read_paused = us.lock().unwrap().read_paused;
			tokio::select! {
				v = write_avail_receiver.recv() => {
					assert!(v.is_some()); // We can't have dropped the sending end, its in the us Arc!
					prepare_read_write_call!();
					if let Err(e) = peer_manager.write_buffer_space_avail(&mut our_descriptor) {
						shutdown_socket!(e, Disconnect::CloseConnection);
					}
					us.lock().unwrap().block_disconnect_socket = false;
				},
				_ = read_wake_receiver.recv() => {},
				read = reader.read(&mut buf), if !read_paused => match read {
					Ok(0) => shutdown_socket!("Connection closed", Disconnect::PeerDisconnected),
					Ok(len) => {
						prepare_read_write_call!();
						let read_res = peer_manager.read_event(&mut our_descriptor, &buf[0..len]);
						let mut us_lock = us.lock().unwrap();
						match read_res {
							Ok(pause_read) => {
								if pause_read {
									us_lock.read_paused = true;
								}
								Self::event_trigger(&mut us_lock);
							},
							Err(e) => shutdown_socket!(e, Disconnect::CloseConnection),
						}
						us_lock.block_disconnect_socket = false;
					},
					Err(e) => shutdown_socket!(e, Disconnect::PeerDisconnected),
				},
			}
		};
		let writer_option = us.lock().unwrap().writer.take();
		if let Some(mut writer) = writer_option {
			// If the socket is already closed, shutdown() will fail, so just ignore it.
			let _ = writer.shutdown().await;
		}
		if let Disconnect::PeerDisconnected = disconnect_type {
			peer_manager_ref.socket_disconnected(&our_descriptor);
			Self::event_trigger(&mut us.lock().unwrap());
		}
	}

	fn new(event_notify: mpsc::Sender<()>, stream: TcpStream) -> (io::ReadHalf<TcpStream>, mpsc::Receiver<()>, mpsc::Receiver<()>, Arc<Mutex<Self>>) {
		// We only ever need a channel of depth 1 here: if we returned a non-full write to the
		// PeerManager, we will eventually get notified that there is room in the socket to write
		// new bytes, which will generate an event. That event will be popped off the queue before
		// we call write_buffer_space_avail, ensuring that we have room to push a new () if, during
		// the write_buffer_space_avail() call, send_data() returns a non-full write.
		let (write_avail, write_receiver) = mpsc::channel(1);
		// Similarly here - our only goal is to make sure the reader wakes up at some point after
		// we shove a value into the channel which comes after we've reset the read_paused bool to
		// false.
		let (read_waker, read_receiver) = mpsc::channel(1);
		let (reader, writer) = io::split(stream);

		(reader, write_receiver, read_receiver,
		Arc::new(Mutex::new(Self {
			writer: Some(writer), event_notify, write_avail, read_waker, read_paused: false,
			block_disconnect_socket: false, rl_requested_disconnect: false,
			id: ID_COUNTER.fetch_add(1, Ordering::AcqRel)
		})))
	}
}

/// Process incoming messages and feed outgoing messages on the provided socket generated by
/// accepting an incoming connection.
///
/// The returned future will complete when the peer is disconnected and associated handling
/// futures are freed, though, because all processing futures are spawned with tokio::spawn, you do
/// not need to poll the provided future in order to make progress.
///
/// See the module-level documentation for how to handle the event_notify mpsc::Sender.
pub fn setup_inbound<CMH: ChannelMessageHandler + 'static, L: Logger + 'static + ?Sized>(peer_manager: Arc<peer_handler::PeerManager<SocketDescriptor, Arc<CMH>, Arc<L>>>, event_notify: mpsc::Sender<()>, stream: TcpStream) -> impl std::future::Future<Output=()> {
	let (reader, write_receiver, read_receiver, us) = Connection::new(event_notify, stream);
	#[cfg(debug_assertions)]
	let last_us = Arc::clone(&us);

	let handle_opt = if let Ok(_) = peer_manager.new_inbound_connection(SocketDescriptor::new(us.clone())) {
		Some(tokio::spawn(Connection::schedule_read(peer_manager, us, reader, read_receiver, write_receiver)))
	} else {
		// Note that we will skip socket_disconnected here, in accordance with the PeerManager
		// requirements.
		None
	};

	async move {
		if let Some(handle) = handle_opt {
			if let Err(e) = handle.await {
				assert!(e.is_cancelled());
			} else {
				// This is certainly not guaranteed to always be true - the read loop may exit
				// while there are still pending write wakers that need to be woken up after the
				// socket shutdown(). Still, as a check during testing, to make sure tokio doesn't
				// keep too many wakers around, this makes sense. The race should be rare (we do
				// some work after shutdown()) and an error would be a major memory leak.
				#[cfg(debug_assertions)]
				assert!(Arc::try_unwrap(last_us).is_ok());
			}
		}
	}
}

/// Process incoming messages and feed outgoing messages on the provided socket generated by
/// making an outbound connection which is expected to be accepted by a peer with the given
/// public key. The relevant processing is set to run free (via tokio::spawn).
///
/// The returned future will complete when the peer is disconnected and associated handling
/// futures are freed, though, because all processing futures are spawned with tokio::spawn, you do
/// not need to poll the provided future in order to make progress.
///
/// See the module-level documentation for how to handle the event_notify mpsc::Sender.
pub fn setup_outbound<CMH: ChannelMessageHandler + 'static, L: Logger + 'static + ?Sized>(peer_manager: Arc<peer_handler::PeerManager<SocketDescriptor, Arc<CMH>, Arc<L>>>, event_notify: mpsc::Sender<()>, their_node_id: PublicKey, stream: TcpStream) -> impl std::future::Future<Output=()> {
	let (reader, mut write_receiver, read_receiver, us) = Connection::new(event_notify, stream);
	#[cfg(debug_assertions)]
	let last_us = Arc::clone(&us);

	let handle_opt = if let Ok(initial_send) = peer_manager.new_outbound_connection(their_node_id, SocketDescriptor::new(us.clone())) {
		Some(tokio::spawn(async move {
			// We should essentially always have enough room in a TCP socket buffer to send the
			// initial 10s of bytes. However, tokio running in single-threaded mode will always
			// fail writes and wake us back up later to write. Thus, we handle a single
			// std::task::Poll::Pending but still expect to write the full set of bytes at once
			// and use a relatively tight timeout.
			if let Ok(Ok(())) = tokio::time::timeout(Duration::from_millis(100), async {
				loop {
					match SocketDescriptor::new(us.clone()).send_data(&initial_send, true) {
						v if v == initial_send.len() => break Ok(()),
						0 => {
							write_receiver.recv().await;
							// In theory we could check for if we've been instructed to disconnect
							// the peer here, but its OK to just skip it - we'll check for it in
							// schedule_read prior to any relevant calls into RL.
						},
						_ => {
							eprintln!("Failed to write first full message to socket!");
							peer_manager.socket_disconnected(&SocketDescriptor::new(Arc::clone(&us)));
							break Err(());
						}
					}
				}
			}).await {
				Connection::schedule_read(peer_manager, us, reader, read_receiver, write_receiver).await;
			}
		}))
	} else {
		// Note that we will skip socket_disconnected here, in accordance with the PeerManager
		// requirements.
		None
	};

	async move {
		if let Some(handle) = handle_opt {
			if let Err(e) = handle.await {
				assert!(e.is_cancelled());
			} else {
				// This is certainly not guaranteed to always be true - the read loop may exit
				// while there are still pending write wakers that need to be woken up after the
				// socket shutdown(). Still, as a check during testing, to make sure tokio doesn't
				// keep too many wakers around, this makes sense. The race should be rare (we do
				// some work after shutdown()) and an error would be a major memory leak.
				#[cfg(debug_assertions)]
				assert!(Arc::try_unwrap(last_us).is_ok());
			}
		}
	}
}

/// Process incoming messages and feed outgoing messages on a new connection made to the given
/// socket address which is expected to be accepted by a peer with the given public key (by
/// scheduling futures with tokio::spawn).
///
/// Shorthand for TcpStream::connect(addr) with a timeout followed by setup_outbound().
///
/// Returns a future (as the fn is async) which needs to be polled to complete the connection and
/// connection setup. That future then returns a future which will complete when the peer is
/// disconnected and associated handling futures are freed, though, because all processing in said
/// futures are spawned with tokio::spawn, you do not need to poll the second future in order to
/// make progress.
///
/// See the module-level documentation for how to handle the event_notify mpsc::Sender.
pub async fn connect_outbound<CMH: ChannelMessageHandler + 'static, L: Logger + 'static + ?Sized>(peer_manager: Arc<peer_handler::PeerManager<SocketDescriptor, Arc<CMH>, Arc<L>>>, event_notify: mpsc::Sender<()>, their_node_id: PublicKey, addr: SocketAddr) -> Option<impl std::future::Future<Output=()>> {
	if let Ok(Ok(stream)) = time::timeout(Duration::from_secs(10), TcpStream::connect(&addr)).await {
		Some(setup_outbound(peer_manager, event_notify, their_node_id, stream))
	} else { None }
}

const SOCK_WAKER_VTABLE: task::RawWakerVTable =
	task::RawWakerVTable::new(clone_socket_waker, wake_socket_waker, wake_socket_waker_by_ref, drop_socket_waker);

fn clone_socket_waker(orig_ptr: *const ()) -> task::RawWaker {
	write_avail_to_waker(orig_ptr as *const mpsc::Sender<()>)
}
// When waking, an error should be fine. Most likely we got two send_datas in a row, both of which
// failed to fully write, but we only need to call write_buffer_space_avail() once. Otherwise, the
// sending thread may have already gone away due to a socket close, in which case there's nothing
// to wake up anyway.
fn wake_socket_waker(orig_ptr: *const ()) {
	let sender = unsafe { &mut *(orig_ptr as *mut mpsc::Sender<()>) };
	let _ = sender.try_send(());
	drop_socket_waker(orig_ptr);
}
fn wake_socket_waker_by_ref(orig_ptr: *const ()) {
	let sender_ptr = orig_ptr as *const mpsc::Sender<()>;
	let mut sender = unsafe { (*sender_ptr).clone() };
	let _ = sender.try_send(());
}
fn drop_socket_waker(orig_ptr: *const ()) {
	let _orig_box = unsafe { Box::from_raw(orig_ptr as *mut mpsc::Sender<()>) };
	// _orig_box is now dropped
}
fn write_avail_to_waker(sender: *const mpsc::Sender<()>) -> task::RawWaker {
	let new_box = Box::leak(Box::new(unsafe { (*sender).clone() }));
	let new_ptr = new_box as *const mpsc::Sender<()>;
	task::RawWaker::new(new_ptr as *const (), &SOCK_WAKER_VTABLE)
}

/// The SocketDescriptor used to refer to sockets by a PeerHandler. This is pub only as it is a
/// type in the template of PeerHandler.
pub struct SocketDescriptor {
	conn: Arc<Mutex<Connection>>,
	id: u64,
}
impl SocketDescriptor {
	fn new(conn: Arc<Mutex<Connection>>) -> Self {
		let id = conn.lock().unwrap().id;
		Self { conn, id }
	}
}
impl peer_handler::SocketDescriptor for SocketDescriptor {
	fn send_data(&mut self, data: &[u8], resume_read: bool) -> usize {
		// To send data, we take a lock on our Connection to access the WriteHalf of the TcpStream,
		// writing to it if there's room in the kernel buffer, or otherwise create a new Waker with
		// a SocketDescriptor in it which can wake up the write_avail Sender, waking up the
		// processing future which will call write_buffer_space_avail and we'll end up back here.
		let mut us = self.conn.lock().unwrap();
		if us.writer.is_none() {
			// The writer gets take()n when it is time to shut down, so just fast-return 0 here.
			return 0;
		}

		if resume_read && us.read_paused {
			// The schedule_read future may go to lock up but end up getting woken up by there
			// being more room in the write buffer, dropping the other end of this Sender
			// before we get here, so we ignore any failures to wake it up.
			us.read_paused = false;
			let _ = us.read_waker.try_send(());
		}
		if data.is_empty() { return 0; }
		let waker = unsafe { task::Waker::from_raw(write_avail_to_waker(&us.write_avail)) };
		let mut ctx = task::Context::from_waker(&waker);
		let mut written_len = 0;
		loop {
			match std::pin::Pin::new(us.writer.as_mut().unwrap()).poll_write(&mut ctx, &data[written_len..]) {
				task::Poll::Ready(Ok(res)) => {
					// The tokio docs *seem* to indicate this can't happen, and I certainly don't
					// know how to handle it if it does (cause it should be a Poll::Pending
					// instead):
					assert_ne!(res, 0);
					written_len += res;
					if written_len == data.len() { return written_len; }
				},
				task::Poll::Ready(Err(e)) => {
					// The tokio docs *seem* to indicate this can't happen, and I certainly don't
					// know how to handle it if it does (cause it should be a Poll::Pending
					// instead):
					assert_ne!(e.kind(), io::ErrorKind::WouldBlock);
					// Probably we've already been closed, just return what we have and let the
					// read thread handle closing logic.
					return written_len;
				},
				task::Poll::Pending => {
					// We're queued up for a write event now, but we need to make sure we also
					// pause read given we're now waiting on the remote end to ACK (and in
					// accordance with the send_data() docs).
					us.read_paused = true;
					return written_len;
				},
			}
		}
	}

	fn disconnect_socket(&mut self) {
		{
			let mut us = self.conn.lock().unwrap();
			us.rl_requested_disconnect = true;
			us.read_paused = true;
			// Wake up the sending thread, assuming it is still alive
			let _ = us.write_avail.try_send(());
			// Happy-path return:
			if !us.block_disconnect_socket { return; }
		}
		while self.conn.lock().unwrap().block_disconnect_socket {
			thread::yield_now();
		}
	}
}
impl Clone for SocketDescriptor {
	fn clone(&self) -> Self {
		Self {
			conn: Arc::clone(&self.conn),
			id: self.id,
		}
	}
}
impl Eq for SocketDescriptor {}
impl PartialEq for SocketDescriptor {
	fn eq(&self, o: &Self) -> bool {
		self.id == o.id
	}
}
impl Hash for SocketDescriptor {
	fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
		self.id.hash(state);
	}
}

#[cfg(test)]
mod tests {
	use lightning::ln::features::*;
	use lightning::ln::msgs::*;
	use lightning::ln::peer_handler::{MessageHandler, PeerManager};
	use lightning::util::events::*;
	use bitcoin::secp256k1::{Secp256k1, SecretKey, PublicKey};

	use tokio::sync::mpsc;

	use std::mem;
	use std::sync::{Arc, Mutex};
	use std::time::Duration;

	pub struct TestLogger();
	impl lightning::util::logger::Logger for TestLogger {
		fn log(&self, record: &lightning::util::logger::Record) {
			println!("{:<5} [{} : {}, {}] {}", record.level.to_string(), record.module_path, record.file, record.line, record.args);
		}
	}

	struct MsgHandler{
		expected_pubkey: PublicKey,
		pubkey_connected: mpsc::Sender<()>,
		pubkey_disconnected: mpsc::Sender<()>,
		msg_events: Mutex<Vec<MessageSendEvent>>,
	}
	impl RoutingMessageHandler for MsgHandler {
		fn handle_node_announcement(&self, _msg: &NodeAnnouncement) -> Result<bool, LightningError> { Ok(false) }
		fn handle_channel_announcement(&self, _msg: &ChannelAnnouncement) -> Result<bool, LightningError> { Ok(false) }
		fn handle_channel_update(&self, _msg: &ChannelUpdate) -> Result<bool, LightningError> { Ok(false) }
		fn handle_htlc_fail_channel_update(&self, _update: &HTLCFailChannelUpdate) { }
		fn get_next_channel_announcements(&self, _starting_point: u64, _batch_amount: u8) -> Vec<(ChannelAnnouncement, Option<ChannelUpdate>, Option<ChannelUpdate>)> { Vec::new() }
		fn get_next_node_announcements(&self, _starting_point: Option<&PublicKey>, _batch_amount: u8) -> Vec<NodeAnnouncement> { Vec::new() }
		fn should_request_full_sync(&self, _node_id: &PublicKey) -> bool { false }
	}
	impl ChannelMessageHandler for MsgHandler {
		fn handle_open_channel(&self, _their_node_id: &PublicKey, _their_features: InitFeatures, _msg: &OpenChannel) {}
		fn handle_accept_channel(&self, _their_node_id: &PublicKey, _their_features: InitFeatures, _msg: &AcceptChannel) {}
		fn handle_funding_created(&self, _their_node_id: &PublicKey, _msg: &FundingCreated) {}
		fn handle_funding_signed(&self, _their_node_id: &PublicKey, _msg: &FundingSigned) {}
		fn handle_funding_locked(&self, _their_node_id: &PublicKey, _msg: &FundingLocked) {}
		fn handle_shutdown(&self, _their_node_id: &PublicKey, _msg: &Shutdown) {}
		fn handle_closing_signed(&self, _their_node_id: &PublicKey, _msg: &ClosingSigned) {}
		fn handle_update_add_htlc(&self, _their_node_id: &PublicKey, _msg: &UpdateAddHTLC) {}
		fn handle_update_fulfill_htlc(&self, _their_node_id: &PublicKey, _msg: &UpdateFulfillHTLC) {}
		fn handle_update_fail_htlc(&self, _their_node_id: &PublicKey, _msg: &UpdateFailHTLC) {}
		fn handle_update_fail_malformed_htlc(&self, _their_node_id: &PublicKey, _msg: &UpdateFailMalformedHTLC) {}
		fn handle_commitment_signed(&self, _their_node_id: &PublicKey, _msg: &CommitmentSigned) {}
		fn handle_revoke_and_ack(&self, _their_node_id: &PublicKey, _msg: &RevokeAndACK) {}
		fn handle_update_fee(&self, _their_node_id: &PublicKey, _msg: &UpdateFee) {}
		fn handle_announcement_signatures(&self, _their_node_id: &PublicKey, _msg: &AnnouncementSignatures) {}
		fn peer_disconnected(&self, their_node_id: &PublicKey, _no_connection_possible: bool) {
			if *their_node_id == self.expected_pubkey {
				self.pubkey_disconnected.clone().try_send(()).unwrap();
			}
		}
		fn peer_connected(&self, their_node_id: &PublicKey, _msg: &Init) {
			if *their_node_id == self.expected_pubkey {
				self.pubkey_connected.clone().try_send(()).unwrap();
			}
		}
		fn handle_channel_reestablish(&self, _their_node_id: &PublicKey, _msg: &ChannelReestablish) {}
		fn handle_error(&self, _their_node_id: &PublicKey, _msg: &ErrorMessage) {}
	}
	impl MessageSendEventsProvider for MsgHandler {
		fn get_and_clear_pending_msg_events(&self) -> Vec<MessageSendEvent> {
			let mut ret = Vec::new();
			mem::swap(&mut *self.msg_events.lock().unwrap(), &mut ret);
			ret
		}
	}

	async fn do_basic_connection_test() {
		let secp_ctx = Secp256k1::new();
		let a_key = SecretKey::from_slice(&[1; 32]).unwrap();
		let b_key = SecretKey::from_slice(&[1; 32]).unwrap();
		let a_pub = PublicKey::from_secret_key(&secp_ctx, &a_key);
		let b_pub = PublicKey::from_secret_key(&secp_ctx, &b_key);

		let (a_connected_sender, mut a_connected) = mpsc::channel(1);
		let (a_disconnected_sender, mut a_disconnected) = mpsc::channel(1);
		let a_handler = Arc::new(MsgHandler {
			expected_pubkey: b_pub,
			pubkey_connected: a_connected_sender,
			pubkey_disconnected: a_disconnected_sender,
			msg_events: Mutex::new(Vec::new()),
		});
		let a_manager = Arc::new(PeerManager::new(MessageHandler {
			chan_handler: Arc::clone(&a_handler),
			route_handler: Arc::clone(&a_handler) as Arc<dyn RoutingMessageHandler>,
		}, a_key.clone(), &[1; 32], Arc::new(TestLogger())));

		let (b_connected_sender, mut b_connected) = mpsc::channel(1);
		let (b_disconnected_sender, mut b_disconnected) = mpsc::channel(1);
		let b_handler = Arc::new(MsgHandler {
			expected_pubkey: a_pub,
			pubkey_connected: b_connected_sender,
			pubkey_disconnected: b_disconnected_sender,
			msg_events: Mutex::new(Vec::new()),
		});
		let b_manager = Arc::new(PeerManager::new(MessageHandler {
			chan_handler: Arc::clone(&b_handler),
			route_handler: Arc::clone(&b_handler) as Arc<dyn RoutingMessageHandler>,
		}, b_key.clone(), &[2; 32], Arc::new(TestLogger())));

		// We bind on localhost, hoping the environment is properly configured with a local
		// address. This may not always be the case in containers and the like, so if this test is
		// failing for you check that you have a loopback interface and it is configured with
		// 127.0.0.1.
		let (conn_a, conn_b) = if let Ok(listener) = std::net::TcpListener::bind("127.0.0.1:9735") {
			(std::net::TcpStream::connect("127.0.0.1:9735").unwrap(), listener.accept().unwrap().0)
		} else if let Ok(listener) = std::net::TcpListener::bind("127.0.0.1:9999") {
			(std::net::TcpStream::connect("127.0.0.1:9999").unwrap(), listener.accept().unwrap().0)
		} else if let Ok(listener) = std::net::TcpListener::bind("127.0.0.1:46926") {
			(std::net::TcpStream::connect("127.0.0.1:46926").unwrap(), listener.accept().unwrap().0)
		} else { panic!("Failed to bind to v4 localhost on common ports"); };

		let (sender, _receiver) = mpsc::channel(2);
		let fut_a = super::setup_outbound(Arc::clone(&a_manager), sender.clone(), b_pub, tokio::net::TcpStream::from_std(conn_a).unwrap());
		let fut_b = super::setup_inbound(b_manager, sender, tokio::net::TcpStream::from_std(conn_b).unwrap());

		tokio::time::timeout(Duration::from_secs(10), a_connected.recv()).await.unwrap();
		tokio::time::timeout(Duration::from_secs(1), b_connected.recv()).await.unwrap();

		a_handler.msg_events.lock().unwrap().push(MessageSendEvent::HandleError {
			node_id: b_pub, action: ErrorAction::DisconnectPeer { msg: None }
		});
		assert!(a_disconnected.try_recv().is_err());
		assert!(b_disconnected.try_recv().is_err());

		a_manager.process_events();
		tokio::time::timeout(Duration::from_secs(10), a_disconnected.recv()).await.unwrap();
		tokio::time::timeout(Duration::from_secs(1), b_disconnected.recv()).await.unwrap();

		fut_a.await;
		fut_b.await;
	}

	#[tokio::test(threaded_scheduler)]
	async fn basic_threaded_connection_test() {
		do_basic_connection_test().await;
	}
	#[tokio::test]
	async fn basic_unthreaded_connection_test() {
		do_basic_connection_test().await;
	}
}
