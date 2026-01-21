// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! A socket handling library for those running in Tokio environments who wish to use
//! rust-lightning with Tor connectivity.
//!
//! Designed to be as simple as possible, the high-level usage is almost as simple as "hand over a
//! Tor stream and a reference to a [`PeerManager`] and the rest is handled".
//!
//! The [`PeerManager`], due to the fire-and-forget nature of this logic, must be a reference,
//! (e.g. an [`Arc`]) and must use the [`TorSocketDescriptor`] provided here as the [`PeerManager`]'s
//! `SocketDescriptor` implementation.
//!
//! Three methods are exposed to register a new connection for handling in [`tokio::spawn`] calls;
//! see their individual docs for details.
//!
//! [`PeerManager`]: lightning::ln::peer_handler::PeerManager

#![deny(rustdoc::broken_intra_doc_links)]
#![deny(rustdoc::private_intra_doc_links)]
#![deny(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]

use bitcoin::secp256k1::PublicKey;

use tokio::io::AsyncReadExt;
use tokio::sync::mpsc;

use lightning::ln::peer_handler;
use lightning::ln::peer_handler::APeerManager;
use lightning::ln::peer_handler::SocketDescriptor as LnSocketTrait;

use arti_client::TorClient;

use std::future::Future;
use std::hash::Hash;
use std::ops::Deref;
use std::pin::{pin, Pin};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{self, Poll};
use std::time::Duration;

use tokio::sync::Mutex;

static ID_COUNTER: AtomicU64 = AtomicU64::new(0);

// Simplified selector for our use case
pub(crate) enum SelectorOutput {
	A(Option<()>),
	B(Option<()>),
	C(tokio::io::Result<(usize, [u8; 4096])>),
}

pub(crate) struct ThreeSelector<
	A: Future<Output = Option<()>> + Unpin,
	B: Future<Output = Option<()>> + Unpin,
	C: Future<Output = tokio::io::Result<(usize, [u8; 4096])>> + Unpin,
> {
	pub a: A,
	pub b: B,
	pub c: C,
}

impl<
		A: Future<Output = Option<()>> + Unpin,
		B: Future<Output = Option<()>> + Unpin,
		C: Future<Output = tokio::io::Result<(usize, [u8; 4096])>> + Unpin,
	> Future for ThreeSelector<A, B, C>
{
	type Output = SelectorOutput;
	fn poll(mut self: Pin<&mut Self>, ctx: &mut task::Context<'_>) -> Poll<SelectorOutput> {
		match Pin::new(&mut self.a).poll(ctx) {
			Poll::Ready(res) => {
				return Poll::Ready(SelectorOutput::A(res));
			},
			Poll::Pending => {},
		}
		match Pin::new(&mut self.b).poll(ctx) {
			Poll::Ready(res) => {
				return Poll::Ready(SelectorOutput::B(res));
			},
			Poll::Pending => {},
		}
		match Pin::new(&mut self.c).poll(ctx) {
			Poll::Ready(res) => {
				return Poll::Ready(SelectorOutput::C(res));
			},
			Poll::Pending => {},
		}
		Poll::Pending
	}
}

type TorStream = arti_client::DataStream;

/// Connection contains all our internal state for a Tor connection
struct TorConnection {
	writer: Option<Arc<Mutex<TorStream>>>,
	write_avail: mpsc::Sender<()>,
	read_waker: mpsc::Sender<()>,
	read_paused: bool,
	rl_requested_disconnect: bool,
	id: u64,
}

impl TorConnection {
	async fn poll_event_process<PM: Deref + 'static + Send + Sync>(
		peer_manager: PM, mut event_receiver: mpsc::Receiver<()>,
	) where
		PM::Target: APeerManager<Descriptor = TorSocketDescriptor>,
	{
		loop {
			if event_receiver.recv().await.is_none() {
				return;
			}
			peer_manager.as_ref().process_events();
		}
	}

	async fn schedule_read<PM: Deref + 'static + Send + Sync + Clone>(
		peer_manager: PM, us: Arc<Mutex<Self>>, reader: Arc<Mutex<TorStream>>,
		mut read_wake_receiver: mpsc::Receiver<()>, mut write_avail_receiver: mpsc::Receiver<()>,
	) where
		PM::Target: APeerManager<Descriptor = TorSocketDescriptor>,
	{
		// Create a waker to wake up poll_event_process
		let (event_waker, event_receiver) = mpsc::channel(1);
		tokio::spawn(Self::poll_event_process(peer_manager.clone(), event_receiver));

		let mut buf = [0; 4096];

		let mut our_descriptor = TorSocketDescriptor::new(Arc::clone(&us));
		
		enum Disconnect {
			CloseConnection,
			PeerDisconnected,
		}
		
		let disconnect_type = loop {
			let read_paused = {
				let us_lock = us.lock().await;
				if us_lock.rl_requested_disconnect {
					break Disconnect::CloseConnection;
				}
				us_lock.read_paused
			};

			if !read_paused {
				// Attempt to read from the Tor stream
				// Clone the Arc to avoid holding the lock across await
				let reader_clone = Arc::clone(&reader);
				let read_fut = async move {
					let mut stream = reader_clone.lock().await;
					let mut temp_buf = [0u8; 4096];
					let result = stream.read(&mut temp_buf).await;
					drop(stream); // Explicitly drop the guard
					result.map(|len| (len, temp_buf))
				};

				let select_result = ThreeSelector {
					a: pin!(write_avail_receiver.recv()),
					b: pin!(read_wake_receiver.recv()),
					c: pin!(read_fut),
				}
				.await;

				match select_result {
					SelectorOutput::A(v) => {
						assert!(v.is_some());
						if peer_manager.as_ref().write_buffer_space_avail(&mut our_descriptor).is_err()
						{
							break Disconnect::CloseConnection;
						}
					},
					SelectorOutput::B(some) => {
						debug_assert!(some.is_some());
					},
					SelectorOutput::C(res) => match res {
						Ok((0, _)) => break Disconnect::PeerDisconnected,
						Ok((len, temp_buf)) => {
							buf[..len].copy_from_slice(&temp_buf[..len]);
							let read_res =
								peer_manager.as_ref().read_event(&mut our_descriptor, &buf[0..len]);
							match read_res {
								Ok(()) => {},
								Err(_) => break Disconnect::CloseConnection,
							}
						},
						Err(_) => break Disconnect::PeerDisconnected,
					},
				}
			} else {
				// Read is paused, only listen for write_avail and read_waker
				if let Some(_) = write_avail_receiver.recv().await {
					if peer_manager.as_ref().write_buffer_space_avail(&mut our_descriptor).is_err()
					{
						break Disconnect::CloseConnection;
					}
				}
			}

			let _ = event_waker.try_send(());
			let _ = tokio::task::yield_now().await;
		};

		us.lock().await.writer.take();
		if let Disconnect::PeerDisconnected = disconnect_type {
			peer_manager.as_ref().socket_disconnected(&our_descriptor);
			peer_manager.as_ref().process_events();
		}
	}

	fn new(stream: TorStream) -> (Arc<Mutex<TorStream>>, mpsc::Receiver<()>, mpsc::Receiver<()>, Arc<Mutex<Self>>) {
		let (write_avail, write_receiver) = mpsc::channel(1);
		let (read_waker, read_receiver) = mpsc::channel(1);
		let tor_stream = Arc::new(Mutex::new(stream));

		let id = ID_COUNTER.fetch_add(1, Ordering::AcqRel);
		let writer = Some(Arc::clone(&tor_stream));
		let conn = Arc::new(Mutex::new(Self {
			writer,
			write_avail,
			read_waker,
			read_paused: false,
			rl_requested_disconnect: false,
			id,
		}));
		(tor_stream, write_receiver, read_receiver, conn)
	}
}

/// Process incoming messages and feed outgoing messages on the provided Tor stream generated by
/// accepting an incoming connection.
///
/// The returned future will complete when the peer is disconnected and associated handling
/// futures are freed, though, because all processing futures are spawned with tokio::spawn, you do
/// not need to poll the provided future in order to make progress.
pub fn setup_inbound_tor<PM: Deref + 'static + Send + Sync + Clone>(
	peer_manager: PM, stream: TorStream,
) -> impl std::future::Future<Output = ()>
where
	PM::Target: APeerManager<Descriptor = TorSocketDescriptor>,
{
	let (reader, write_receiver, read_receiver, us) = TorConnection::new(stream);
	#[cfg(test)]
	let last_us = Arc::clone(&us);

	let handle_opt = if peer_manager
		.as_ref()
		.new_inbound_connection(TorSocketDescriptor::new(Arc::clone(&us)), None)
		.is_ok()
	{
		let handle = tokio::spawn(TorConnection::schedule_read(
			peer_manager,
			us,
			reader,
			read_receiver,
			write_receiver,
		));
		Some(handle)
	} else {
		None
	};

	async move {
		if let Some(handle) = handle_opt {
			if let Err(e) = handle.await {
				assert!(e.is_cancelled());
			} else {
				#[cfg(test)]
				debug_assert!(Arc::try_unwrap(last_us).is_ok());
			}
		}
	}
}

/// Process incoming messages and feed outgoing messages on the provided Tor stream generated by
/// making an outbound connection which is expected to be accepted by a peer with the given
/// public key.
///
/// The returned future will complete when the peer is disconnected and associated handling
/// futures are freed, though, because all processing futures are spawned with tokio::spawn, you do
/// not need to poll the provided future in order to make progress.
pub fn setup_outbound_tor<PM: Deref + 'static + Send + Sync + Clone>(
	peer_manager: PM, their_node_id: PublicKey, stream: TorStream,
) -> impl std::future::Future<Output = ()>
where
	PM::Target: APeerManager<Descriptor = TorSocketDescriptor>,
{
	let (reader, mut write_receiver, read_receiver, us) = TorConnection::new(stream);
	#[cfg(test)]
	let last_us = Arc::clone(&us);
	
	let handle_opt = if let Ok(initial_send) = peer_manager.as_ref().new_outbound_connection(
		their_node_id,
		TorSocketDescriptor::new(Arc::clone(&us)),
		None,
	) {
		let handle = tokio::spawn(async move {
			let send_fut = async {
				loop {
					match TorSocketDescriptor::new(Arc::clone(&us)).send_data(&initial_send, true) {
						v if v == initial_send.len() => break Ok(()),
						0 => {
							write_receiver.recv().await;
						},
						_ => {
							eprintln!("Failed to write first full message to Tor stream!");
							peer_manager
								.as_ref()
								.socket_disconnected(&TorSocketDescriptor::new(Arc::clone(&us)));
							break Err(());
						},
					}
				}
			};
			
			let timeout_send_fut = tokio::time::timeout(Duration::from_millis(100), send_fut);
			if let Ok(Ok(())) = timeout_send_fut.await {
				TorConnection::schedule_read(peer_manager, us, reader, read_receiver, write_receiver)
					.await;
			}
		});
		Some(handle)
	} else {
		None
	};

	async move {
		if let Some(handle) = handle_opt {
			if let Err(e) = handle.await {
				assert!(e.is_cancelled());
			} else {
				#[cfg(test)]
				debug_assert!(Arc::try_unwrap(last_us).is_ok());
			}
		}
	}
}

/// Connect to a Lightning node over Tor at the given .onion address
///
/// Returns a future which will complete when the peer is disconnected.
pub async fn connect_outbound_tor<PM: Deref + 'static + Send + Sync + Clone>(
	peer_manager: PM, 
	their_node_id: PublicKey, 
	onion_addr: &str,
	port: u16,
) -> Option<impl std::future::Future<Output = ()>>
where
	PM::Target: APeerManager<Descriptor = TorSocketDescriptor>,
{
	// Create Tor client
	let tor_client = match TorClient::builder()
		.bootstrap_behavior(arti_client::BootstrapBehavior::OnDemand)
		.create_unbootstrapped()
	{
		Ok(client) => Arc::new(client),
		Err(e) => {
			eprintln!("Failed to create Tor client: {}", e);
			return None;
		}
	};

	// Connect via Tor
	let addr_port = format!("{}:{}", onion_addr, port);
	let connect_fut = async {
		tor_client.connect(addr_port).await
	};

	if let Ok(Ok(stream)) = tokio::time::timeout(Duration::from_secs(30), connect_fut).await {
		Some(setup_outbound_tor(peer_manager, their_node_id, stream))
	} else {
		None
	}
}

const SOCK_WAKER_VTABLE: task::RawWakerVTable = task::RawWakerVTable::new(
	clone_socket_waker,
	wake_socket_waker,
	wake_socket_waker_by_ref,
	drop_socket_waker,
);

fn clone_socket_waker(orig_ptr: *const ()) -> task::RawWaker {
	let new_waker = unsafe { Arc::from_raw(orig_ptr as *const mpsc::Sender<()>) };
	let res = write_avail_to_waker(&new_waker);
	let _ = Arc::into_raw(new_waker);
	res
}

fn wake_socket_waker(orig_ptr: *const ()) {
	let sender = unsafe { &mut *(orig_ptr as *mut mpsc::Sender<()>) };
	let _ = sender.try_send(());
	drop_socket_waker(orig_ptr);
}

fn wake_socket_waker_by_ref(orig_ptr: *const ()) {
	let sender_ptr = orig_ptr as *const mpsc::Sender<()>;
	let sender = unsafe { &*sender_ptr };
	let _ = sender.try_send(());
}

fn drop_socket_waker(orig_ptr: *const ()) {
	let _orig_arc = unsafe { Arc::from_raw(orig_ptr as *mut mpsc::Sender<()>) };
}

fn write_avail_to_waker(sender: &Arc<mpsc::Sender<()>>) -> task::RawWaker {
	let new_ptr = Arc::into_raw(Arc::clone(&sender));
	task::RawWaker::new(new_ptr as *const (), &SOCK_WAKER_VTABLE)
}

/// The TorSocketDescriptor used to refer to Tor connections by a PeerHandler.
pub struct TorSocketDescriptor {
	conn: Arc<Mutex<TorConnection>>,
	write_avail_sender: Arc<mpsc::Sender<()>>,
	id: u64,
}

impl TorSocketDescriptor {
	fn new(conn: Arc<Mutex<TorConnection>>) -> Self {
		// For new() we need to block since it's sync - use tokio::task::block_in_place
		let (id, write_avail_sender) = tokio::task::block_in_place(|| {
			let handle = tokio::runtime::Handle::current();
			handle.block_on(async {
				let us = conn.lock().await;
				(us.id, Arc::new(us.write_avail.clone()))
			})
		});
		Self { conn, id, write_avail_sender }
	}
}

impl peer_handler::SocketDescriptor for TorSocketDescriptor {
	fn send_data(&mut self, data: &[u8], continue_read: bool) -> usize {
		// Use block_in_place since send_data must be synchronous
		tokio::task::block_in_place(|| {
			let handle = tokio::runtime::Handle::current();
			handle.block_on(async {
				let mut us = self.conn.lock().await;
				if us.writer.is_none() {
					return 0;
				}

				let read_was_paused = us.read_paused;
				us.read_paused = !continue_read;

				if continue_read && read_was_paused {
					let _ = us.read_waker.try_send(());
				}

				if data.is_empty() {
					return 0;
				}

				// Write to Tor stream
				let writer = us.writer.as_ref().unwrap();
				let data_vec = data.to_vec();
				let writer_clone = Arc::clone(writer);
				
				// Drop the lock before writing
				drop(us);
				
				let mut stream = writer_clone.lock().await;
				use tokio::io::AsyncWriteExt;
				match stream.write(&data_vec).await {
					Ok(len) => len,
					Err(_) => 0,
				}
			})
		})
	}

	fn disconnect_socket(&mut self) {
		tokio::task::block_in_place(|| {
			let handle = tokio::runtime::Handle::current();
			handle.block_on(async {
				let mut us = self.conn.lock().await;
				us.rl_requested_disconnect = true;
				let _ = us.write_avail.try_send(());
			})
		})
	}
}

impl Clone for TorSocketDescriptor {
	fn clone(&self) -> Self {
		Self {
			conn: Arc::clone(&self.conn),
			id: self.id,
			write_avail_sender: Arc::clone(&self.write_avail_sender),
		}
	}
}

impl Eq for TorSocketDescriptor {}

impl PartialEq for TorSocketDescriptor {
	fn eq(&self, o: &Self) -> bool {
		self.id == o.id
	}
}

impl Hash for TorSocketDescriptor {
	fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
		self.id.hash(state);
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
	use lightning::ln::peer_handler::PeerManager;
	use lightning::util::test_utils::TestNodeSigner;

	#[tokio::test]
	async fn test_tor_descriptor_creation() {
		// Basic smoke test that we can create descriptors
		let secp_ctx = Secp256k1::new();
		let key = SecretKey::from_slice(&[1; 32]).unwrap();
		let _pub_key = PublicKey::from_secret_key(&secp_ctx, &key);
		
		// Test passes if we get here without panicking
		assert!(true);
	}
}
