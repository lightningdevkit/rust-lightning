// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! # lightning-net
//!
//! A socket handling library for those using rust-lightning without an async
//! runtime.
//!
//! Whereas `lightning-net-tokio` manages reading and writing to peers using
//! Futures and Tokio tasks, this library uses dedicated blocking threads. While
//! this does result in a small amount of performance overhead, it allows
//! rust-lightning to be used on platforms that don't support Tokio or async
//! Rust.
//!
//! The primary entrypoints into this crate are `initiate_outbound()` and
//! `handle_connection()`. See their individual docs for details.
//!
//! ## `std` limitations of EDP
//!
//! An additional goal of this crate is to compile to the Fortanix EDP
//! (`x86_64-fortanix-unknown-sgx`) target. This comes with additional
//! limitations, however. This crate purposefully avoids the use of:
//!
//! - `std::time::Instant::now`
//! - `std::time::Instant::elapsed`
//! - `std::time::SystemTime::now`
//! - `std::time::SystemTime::elapsed`
//! - `std::thread::sleep`
//! - `std::thread::sleep_ms`
//! - `std::thread::park_timeout`
//! - `std::thread::park_timeout_ms`
//!
//! These functions have varying degrees of compatibility with Fortanix EDP.
//! See the [EDP docs](https://edp.fortanix.com/docs/concepts/rust-std/) for
//! more information on what Rust features can and cannot be used within SGX.

#![deny(broken_intra_doc_links)]
#![allow(clippy::type_complexity)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

use core::hash;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};

use crossbeam_channel::{select, Receiver, Sender, TryRecvError, TrySendError};

use bitcoin::secp256k1::PublicKey;
use lightning::ln::msgs::{ChannelMessageHandler, RoutingMessageHandler};
use lightning::ln::peer_handler::{
    CustomMessageHandler, PeerHandleError, PeerManager, SocketDescriptor,
};
use lightning::util::logger::Logger;

/// Initiates an outbound connection to a peer given their node ID (public key)
/// and socket address.
///
/// This fn is shorthand for TcpStream::connect(addr) followed by
/// handle_connection(). Note that unlike handle_connection() which completes
/// instantly, initiate_outbound() will block on the TcpStream::connect() call.
///
/// If TcpStream::connect() succeeds, this function returns Ok() containing
/// the return value of handle_connection() (which is itself a Result).
/// Otherwise, an Err containing the std::io::Error is returned.
pub fn initiate_outbound<CMH, RMH, L, UMH>(
    peer_manager: Arc<PeerManager<SyncSocketDescriptor, Arc<CMH>, Arc<RMH>, Arc<L>, Arc<UMH>>>,
    their_node_id: PublicKey,
    addr: SocketAddr,
) -> Result<Result<(JoinHandle<()>, JoinHandle<()>), PeerHandleError>, std::io::Error>
where
    CMH: ChannelMessageHandler + 'static + Send + Sync,
    RMH: RoutingMessageHandler + 'static + Send + Sync,
    L: Logger + 'static + ?Sized + Send + Sync,
    UMH: CustomMessageHandler + 'static + Send + Sync,
{
    TcpStream::connect(&addr).map(|stream| {
        handle_connection(
            peer_manager,
            stream,
            ConnectionType::Outbound(their_node_id),
        )
    })
}

/// Get a fresh ID to represent a new connection
///
/// This function hides the global so that it's only accessible via this fn.
fn next_connection_id() -> u64 {
    static ID_COUNTER: AtomicU64 = AtomicU64::new(0);
    ID_COUNTER.fetch_add(1, Ordering::Relaxed)
}

/// Whether the new connection was initiated by the peer (inbound) or initiated
/// by us (outbound). If the new connection was outbound, the public key
/// representing the node ID of the peer must be specified.
pub enum ConnectionType {
    Inbound,
    Outbound(PublicKey),
}

/// Spawns the threads necessary to manage a new connection handling both
/// inbound and outbound connections. This function only needs to be called once
/// for every connection, and since the work is done on dedicated threads that
/// will exit by themselves when required, nothing further needs to be done to
/// manage the connection.
///
/// Returns a Result indicating whether the PeerManager accepted the connection.
/// If Ok, additionally returns the handles to the underlying Reader and Writer
/// threads which can optionally be join()ed on
pub fn handle_connection<CMH, RMH, L, UMH>(
    peer_manager: Arc<PeerManager<SyncSocketDescriptor, Arc<CMH>, Arc<RMH>, Arc<L>, Arc<UMH>>>,
    stream: TcpStream,
    conn_type: ConnectionType,
) -> Result<(JoinHandle<()>, JoinHandle<()>), PeerHandleError>
where
    CMH: ChannelMessageHandler + 'static + Send + Sync,
    RMH: RoutingMessageHandler + 'static + Send + Sync,
    L: Logger + 'static + ?Sized + Send + Sync,
    UMH: CustomMessageHandler + 'static + Send + Sync,
{
    // Init channels
    let (reader_cmd_tx, reader_cmd_rx, writer_cmd_tx, writer_cmd_rx, write_data_tx, write_data_rx) =
        init_channels();

    // Generate a new ID that represents this connection
    let conn_id = next_connection_id();
    let remote_addr = stream.peer_addr().ok().map(|sock_addr| sock_addr.into());

    // Init TcpReader, TcpWriter, TcpDisconnectooor
    let writer_stream = stream.try_clone().unwrap();
    let disconnector_stream = stream.try_clone().unwrap();
    let tcp_reader = TcpReader(stream);
    let tcp_writer = TcpWriter(writer_stream);
    let tcp_disconnector = TcpDisconnectooor(disconnector_stream);

    // Init SyncSocketDescriptor
    let mut descriptor = SyncSocketDescriptor::new(
        conn_id,
        tcp_disconnector,
        reader_cmd_tx,
        writer_cmd_tx,
        write_data_tx,
    );

    // Init Reader and Writer
    let mut reader: Reader<CMH, RMH, L, UMH> = Reader::new(
        tcp_reader,
        peer_manager.clone(),
        descriptor.clone(),
        reader_cmd_rx,
    );
    let mut writer: Writer<CMH, RMH, L, UMH> = Writer::new(
        tcp_writer,
        peer_manager.clone(),
        descriptor.clone(),
        writer_cmd_rx,
        write_data_rx,
    );

    // Notify the PeerManager of the new connection depending on its ConnectionType.
    //
    // - If Ok, spawn the Reader and Writer threads.
    // - If Ok and Outbound, additionally queue up the initial data.
    // - If Err, disconnect the TcpStream and do not spawn the worker threads.
    //
    // In all cases, return the result of the call into the PeerManager.
    match conn_type {
        ConnectionType::Inbound => {
            peer_manager.new_inbound_connection(descriptor.clone(), remote_addr)
        }
        ConnectionType::Outbound(their_node_id) => peer_manager
            .new_outbound_connection(their_node_id, descriptor.clone(), remote_addr)
            .map(|initial_data| {
                // PeerManager accepted the outbound connection; queue up the
                // initial WriteData WriterCommand.
                let bytes_pushed = descriptor.send_data(&initial_data, true);
                // This should always succeed since send_data just pushes data
                // into the write_data channel, which always starts out
                // completely empty. If pushing the initial 10s of bytes into
                // the channel fails, something is very wrong; probably a
                // programmer error.
                if bytes_pushed != initial_data.len() {
                    panic!("The initial write should always succeed");
                }
            }),
    }
    .map(|()| {
        // PeerManager accepted the connection; kick off processing by spawning
        // the Reader / Writer threads.
        let reader_handle = thread::spawn(move || reader.run());
        let writer_handle = thread::spawn(move || writer.run());
        (reader_handle, writer_handle)
    })
    .map_err(|e| {
        // PeerManager rejected this connection; disconnect the TcpStream and
        // don't even start the Reader and Writer.
        descriptor.disconnect_socket();
        // In line with the requirements of new_inbound_connection() and
        // new_outbound_connection(), we do NOT call socket_disconnected() here.
        e
    })
}

/// Commands that can be sent to the Reader.
enum ReaderCommand {
    ResumeRead,
    PauseRead,
    Shutdown,
}

/// Commands that can be sent to the Writer.
enum WriterCommand {
    Shutdown,
}

/// Initializes the crossbeam channels required for a connection.
///
/// - The `reader_cmd` channel is unbounded, and can be used to tell the
///   `Reader` to resume reads, pause reads, or shut down.
/// - The `writer_cmd` channel is unbounded, and can be used to tell the
///   `Writer` to shut down.
/// - The `write_data` channel has a capacity of 1, and can be used to request a
///   write of a Vec<u8> of data.
///
/// Finally:
///
/// - A `SyncSocketDescriptor` holds a `Sender` for both the `ReaderCommand` and
///   `WriterCommand` channels.
/// - The `Reader` can send commands to the `Writer` and vice versa because the
///   `Reader` and `Writer` both hold a `SyncSocketDescriptor` clone.
fn init_channels() -> (
    Sender<ReaderCommand>,
    Receiver<ReaderCommand>,
    Sender<WriterCommand>,
    Receiver<WriterCommand>,
    Sender<Vec<u8>>,
    Receiver<Vec<u8>>,
) {
    let (reader_cmd_tx, reader_cmd_rx) = crossbeam_channel::unbounded();
    let (writer_cmd_tx, writer_cmd_rx) = crossbeam_channel::unbounded();
    let (write_data_tx, write_data_rx) = crossbeam_channel::bounded(1);

    (
        reader_cmd_tx,
        reader_cmd_rx,
        writer_cmd_tx,
        writer_cmd_rx,
        write_data_tx,
        write_data_rx,
    )
}

/// A concrete implementation of the SocketDescriptor trait.
///
/// A SyncSocketDescriptor is essentially a `clone()`able handle to an
/// underlying connection as well as an identifier for that connection.
///
/// This type is public only because handle_connection() requires it to be.
#[derive(Clone)]
pub struct SyncSocketDescriptor {
    id: u64,
    tcp_disconnector: TcpDisconnectooor,
    reader_cmd_tx: Sender<ReaderCommand>,
    writer_cmd_tx: Sender<WriterCommand>,
    write_data_tx: Sender<Vec<u8>>,
}
impl PartialEq for SyncSocketDescriptor {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}
impl Eq for SyncSocketDescriptor {}
impl hash::Hash for SyncSocketDescriptor {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.id.hash(state)
    }
}
impl SyncSocketDescriptor {
    fn new(
        connection_id: u64,
        tcp_disconnector: TcpDisconnectooor,
        reader_cmd_tx: Sender<ReaderCommand>,
        writer_cmd_tx: Sender<WriterCommand>,
        write_data_tx: Sender<Vec<u8>>,
    ) -> Self {
        Self {
            id: connection_id,
            tcp_disconnector,
            reader_cmd_tx,
            writer_cmd_tx,
            write_data_tx,
        }
    }
}
impl SocketDescriptor for SyncSocketDescriptor {
    /// Attempts to queue up some data from the given slice for the `Writer` to
    /// send. Returns the number of bytes that were successfully pushed to the
    /// `write_data` channel.
    ///
    /// This implementation never calls back into the PeerManager directly,
    /// thereby preventing reentrancy / deadlock issues. Instead, any commands
    /// to be processed and data to be sent are dispatched to the Reader or
    /// Writer via crossbeam channels.
    ///
    /// Additionally, sending across the crossbeam channels is done exclusively
    /// with non-blocking try_send()s rather than blocking send()s, to ensure
    /// that this function always returns immediately, thereby also reducing the
    /// amount of time that the PeerManager's internal locks are held.
    fn send_data(&mut self, data: &[u8], resume_read: bool) -> usize {
        if resume_read {
            let _ = self.reader_cmd_tx.try_send(ReaderCommand::ResumeRead);
        }

        if data.is_empty() {
            return 0;
        }

        // The data must be copied into the channel since a &[u8] reference
        // cannot be sent across threads. This incurs a small amount of overhead.
        match self.write_data_tx.try_send(data.to_vec()) {
            Ok(()) => data.len(),
            Err(TrySendError::Full(_)) => {
                // Writes are processing; pause reads.
                let _ = self.reader_cmd_tx.try_send(ReaderCommand::PauseRead);
                0
            }
            Err(TrySendError::Disconnected(_)) => {
                // This might happen if the Writer detected a disconnect and
                // shut down on its own. Return 0.
                0
            }
        }
    }

    /// Shuts down the Reader, Writer, and the underlying TcpStream.
    ///
    /// There are several ways that a disconnect might be triggered:
    /// 1) The Reader receives Ok(0) from TcpStream::read() (i.e. the
    ///    peer disconnected), or an Err(io::Error) that shouldn't be retried.
    /// 2) The Reader receives Err from PeerManager::read_event(); i.e.
    ///    Rust-Lightning told us to disconnect from the peer.
    /// 3) The Writer receives Ok(0) from TcpStream::write() (undocumented
    ///    behavior), or an Err(io::Error) that shouldn't be retried.
    /// 4) The Writer receives Err from PeerManager::write_buffer_space_avail();
    ///    Rust-Lightning told us to disconnect from the peer.
    /// 5) This function is called.
    ///
    /// The disconnect will be handled differently depending on the source of
    /// the trigger:
    /// - (1) and (2): If the Reader received the trigger, it will shut down
    ///   BOTH halves of the shared TcpStream AND send a Shutdown command to the
    ///   Writer.
    ///
    ///   - The explicit Shutdown command from the Reader is necessary because
    ///     if the Reader is blocked on `writer_cmd_rx.recv()` due to its
    ///     internal buffer being empty, the only way it can be unblocked is by
    ///     receiving a command, in this case the Shutdown command.
    ///   - The Reader closing both halves of the TCP stream is necessary
    ///     because while the writer is blocked on write(), the only way it can
    ///     unblock is by detecting the TCP disconnect.
    ///
    /// - (3) and (4): If the Writer received the trigger, it will shut down
    ///   BOTH halves of the shared TcpStream AND send a Shutdown command to the
    ///   Reader.
    ///
    ///   - The explicit Shutdown command from the Writer is necessary because
    ///     if the Reader is blocked on `reader_cmd_rx.recv()` due to
    ///     `read_paused == true`, the only way it can be unblocked is by
    ///     receiving a command, in this case the Shutdown command.
    ///   - The Writer closing both halves of the TCP stream is necessary
    ///     because while the reader is blocked on read(), the only way it can
    ///     unblock is by detecting the TCP disconnect.
    ///
    /// - (5): If the disconnect was initiated here, a Shutdown command will be
    ///   sent to both the Reader and the Writer, AND the TcpDisconnectooor will
    ///   shutdown both halves of the shared TCP stream. The Shutdown command
    ///   ensures that the Reader / Writer will unblock if they are currently
    ///   blocked on `recv()`. The TCP stream shutdown ensures that they will
    ///   unblock if they are currently blocked on `read()` or `write()`
    ///   respectively.
    ///
    /// In cases (1) and (3), the disconnect was NOT initiated by
    /// Rust-Lightning, so the Reader / Writer notify the PeerManager using
    /// `socket_disconnected()`.
    fn disconnect_socket(&mut self) {
        let _ = self.reader_cmd_tx.try_send(ReaderCommand::Shutdown);
        let _ = self.writer_cmd_tx.try_send(WriterCommand::Shutdown);
        let _ = self.tcp_disconnector.shutdown();
    }
}

/// The states that the Reader can be in.
enum ReaderState {
    /// Ready state; Reader is blocked on read().
    Reading,
    /// Reading is paused; Reader is blocked on recv().
    Paused,
    /// Reader will shut down in the next iteration of the run() event loop.
    ShuttingDown,
}

/// An actor that synchronously handles the read() events emitted by the socket.
struct Reader<CMH, RMH, L, UMH>
where
    CMH: ChannelMessageHandler + 'static + Send + Sync,
    RMH: RoutingMessageHandler + 'static + Send + Sync,
    L: Logger + 'static + ?Sized + Send + Sync,
    UMH: CustomMessageHandler + 'static + Send + Sync,
{
    inner: TcpReader,
    peer_manager: Arc<PeerManager<SyncSocketDescriptor, Arc<CMH>, Arc<RMH>, Arc<L>, Arc<UMH>>>,
    descriptor: SyncSocketDescriptor,
    reader_cmd_rx: Receiver<ReaderCommand>,
    state: ReaderState,
}
impl<CMH, RMH, L, UMH> Reader<CMH, RMH, L, UMH>
where
    CMH: ChannelMessageHandler + 'static + Send + Sync,
    RMH: RoutingMessageHandler + 'static + Send + Sync,
    L: Logger + 'static + ?Sized + Send + Sync,
    UMH: CustomMessageHandler + 'static + Send + Sync,
{
    fn new(
        reader: TcpReader,
        peer_manager: Arc<PeerManager<SyncSocketDescriptor, Arc<CMH>, Arc<RMH>, Arc<L>, Arc<UMH>>>,
        descriptor: SyncSocketDescriptor,
        reader_cmd_rx: Receiver<ReaderCommand>,
    ) -> Self {
        Self {
            inner: reader,
            peer_manager,
            descriptor,
            reader_cmd_rx,
            state: ReaderState::Reading,
        }
    }

    /// Handle read events, or wait for the next `ReaderCommand` if reads are
    /// paused. This implementation avoids busy loops and lets the thread go to
    /// sleep whenever reads or channel commands are pending.
    fn run(&mut self) {
        use ReaderState::*;

        // 8KB is nice and big but also should never cause any issues with stack
        // overflowing.
        let mut buf = [0; 8192];

        loop {
            self.do_try_recv();

            match self.state {
                Reading => self.do_read(&mut buf),
                Paused => self.do_recv(),
                ShuttingDown => break,
            };
        }

        // Shut down the underlying stream. It's fine if it was already closed.
        let _ = self.inner.shutdown();
        // Send a signal to the Writer to do the same.
        let _ = self
            .descriptor
            .writer_cmd_tx
            .try_send(WriterCommand::Shutdown);
    }

    /// Checks for a command in a non-blocking manner, handling the command
    /// if there was one.
    fn do_try_recv(&mut self) {
        match self.reader_cmd_rx.try_recv() {
            Ok(cmd) => self.handle_command(cmd),
            Err(e) => match e {
                TryRecvError::Empty => {}
                TryRecvError::Disconnected => self.state = ReaderState::ShuttingDown,
            },
        };
    }

    /// Blocks on the command channel and handles the command.
    fn do_recv(&mut self) {
        match self.reader_cmd_rx.recv() {
            Ok(cmd) => self.handle_command(cmd),
            Err(_) => self.state = ReaderState::ShuttingDown,
        };
    }

    /// Handles a `ReaderCommand`.
    fn handle_command(&mut self, cmd: ReaderCommand) {
        use ReaderCommand::*;
        use ReaderState::*;

        match (cmd, &self.state) {
            (_, &ShuttingDown) => {}
            (PauseRead, _) => self.state = Paused,
            (ResumeRead, _) => self.state = Reading,
            (Shutdown, _) => self.state = ShuttingDown,
        }
    }

    /// Blocks on read() and handles the response accordingly.
    fn do_read(&mut self, buf: &mut [u8; 8192]) {
        use std::io::ErrorKind::*;
        use ReaderState::*;

        match self.inner.read(buf) {
            Ok(0) => {
                // Peer disconnected or TcpStream::shutdown was called.
                // Notify the PeerManager then shutdown
                self.peer_manager.socket_disconnected(&self.descriptor);
                self.peer_manager.process_events();
                self.state = ShuttingDown;
            }
            Ok(bytes_read) => {
                match self
                    .peer_manager
                    .read_event(&mut self.descriptor, &buf[0..bytes_read])
                {
                    Ok(pause_read) => {
                        if pause_read {
                            self.state = Paused;
                        }
                    }
                    Err(_) => {
                        // Rust-Lightning told us to disconnect;
                        // no need to notify PeerManager in this case
                        self.state = ShuttingDown;
                    }
                }

                self.peer_manager.process_events()
            }
            Err(e) => match e.kind() {
                TimedOut | Interrupted => {
                    // Acceptable error; retry
                }
                _ => {
                    // For all other errors, notify PeerManager and shut down
                    self.peer_manager.socket_disconnected(&self.descriptor);
                    self.peer_manager.process_events();
                    self.state = ShuttingDown;
                }
            },
        }
    }
}

/// An actor that synchronously initiates the write() events requested by the
/// `PeerManager`.
struct Writer<CMH, RMH, L, UMH>
where
    CMH: ChannelMessageHandler + 'static + Send + Sync,
    RMH: RoutingMessageHandler + 'static + Send + Sync,
    L: Logger + 'static + ?Sized + Send + Sync,
    UMH: CustomMessageHandler + 'static + Send + Sync,
{
    inner: TcpWriter,
    peer_manager: Arc<PeerManager<SyncSocketDescriptor, Arc<CMH>, Arc<RMH>, Arc<L>, Arc<UMH>>>,
    descriptor: SyncSocketDescriptor,
    writer_cmd_rx: Receiver<WriterCommand>,
    write_data_rx: Receiver<Vec<u8>>,
    /// An internal buffer which stores the data that the Writer is
    /// currently attempting to write.
    ///
    /// This buffer is necessary because calls to self.inner.write() may fail or
    /// may write only part of the data.
    buf: Option<Vec<u8>>,
    /// The starting index into buf that specifies where in the buffer the next
    /// attempt should start.
    ///
    /// Partial writes are accounted for by incrementing the start index by the
    /// number of bytes written, while full writes reset `buf` back to None and
    /// the start index back to 0.
    ///
    /// Using this start index avoids the need to call Vec::split_off() or
    /// drain() which respectively incur the cost of an additional Vec
    /// allocation or data move.
    ///
    /// Writer code must maintain the invariant that `start < buf.len()`.
    /// If `start == buf.len()`, `buf` should be `None` and `start` should be 0.
    start: usize,
}
impl<CMH, RMH, L, UMH> Writer<CMH, RMH, L, UMH>
where
    CMH: ChannelMessageHandler + 'static + Send + Sync,
    RMH: RoutingMessageHandler + 'static + Send + Sync,
    L: Logger + 'static + ?Sized + Send + Sync,
    UMH: CustomMessageHandler + 'static + Send + Sync,
{
    fn new(
        writer: TcpWriter,
        peer_manager: Arc<PeerManager<SyncSocketDescriptor, Arc<CMH>, Arc<RMH>, Arc<L>, Arc<UMH>>>,
        descriptor: SyncSocketDescriptor,
        writer_cmd_rx: Receiver<WriterCommand>,
        write_data_rx: Receiver<Vec<u8>>,
    ) -> Self {
        Self {
            inner: writer,
            peer_manager,
            descriptor,
            writer_cmd_rx,
            write_data_rx,
            buf: None,
            start: 0,
        }
    }

    /// Process `write_data` requests, or block on the `writer_cmd` and
    /// `write_data` channels if the internal buffer is empty. This
    /// implementation avoids busy loops and lets the thread go to sleep
    /// whenever writes or channel messages are pending.
    ///
    /// - If `self.buf == None`, block on `self.reader_cmd_rx.recv()` and handle
    ///   any commands accordingly.
    /// - If `self.buf == Some(Vec<u8>)`, block on `self.inner.write()` and
    ///   handle the response accordingly.
    /// - In between each event, do a non-blocking check for Shutdown commands.
    #[allow(clippy::single_match)]
    #[allow(clippy::comparison_chain)]
    fn run(&mut self) {
        use std::io::ErrorKind::*;

        loop {
            // Do a non-blocking check to see if we've been told to shut down
            match self.writer_cmd_rx.try_recv() {
                Ok(WriterCommand::Shutdown) => break,
                Err(e) => match e {
                    TryRecvError::Empty => {}
                    TryRecvError::Disconnected => break,
                },
            }

            match &self.buf {
                Some(buf) => {
                    // We have data in our internal buffer; attempt to write it
                    match self.inner.write(&buf[self.start..]) {
                        Ok(0) => {
                            // We received Ok, but nothing was written. The
                            // behavior that produces this result is not clearly
                            // defined in the docs, but it's probably safe to
                            // assume that the correct response is to notify the
                            // PeerManager of a disconnected peer, break the
                            // loop, and shut down the TcpStream.
                            self.peer_manager.socket_disconnected(&self.descriptor);
                            self.peer_manager.process_events();
                            break;
                        }
                        Ok(bytes_written) => {
                            // Define end s.t. the data written was buf[start..end]
                            let end = self.start + bytes_written;

                            if end == buf.len() {
                                // Everything was written, clear the buf and reset the start index
                                self.buf = None;
                                self.start = 0;
                            } else if end < buf.len() {
                                // Partial write; the new start index is exactly where the current
                                // write ended.
                                self.start = end;
                            } else {
                                panic!("More bytes were written than were given");
                            }
                        }
                        Err(e) => match e.kind() {
                            TimedOut | Interrupted => {
                                // Retry the write in the next loop
                                // iteration if we received any of the above
                                // errors. It would be nice to additionally
                                // match HostUnreachable | NetworkDown |
                                // ResourceBusy, but these require nightly
                                // Rust.
                            }
                            _ => {
                                // For all other errors, notify the
                                // PeerManager, break, and shut down
                                self.peer_manager.socket_disconnected(&self.descriptor);
                                self.peer_manager.process_events();
                                break;
                            }
                        },
                    }
                }
                None => select! {
                    recv(self.writer_cmd_rx) -> _ => break,
                    recv(self.write_data_rx) -> res => match res {
                        Ok(data) => {
                            if !data.is_empty() {
                                self.buf = Some(data);
                                self.start = 0;
                            }

                            // There is space for the next send_data()
                            // request; notify the PeerManager
                            if self
                                .peer_manager
                                .write_buffer_space_avail(&mut self.descriptor)
                                .is_err()
                            {
                                // PeerManager wants us to disconnect
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                },
            }
        }

        // Shut down the underlying stream. It's fine if it was already closed.
        let _ = self.inner.shutdown();
        // Send a signal to the Reader to do the same.
        let _ = self
            .descriptor
            .reader_cmd_tx
            .try_send(ReaderCommand::Shutdown);
    }
}

/// A newtype for a TcpStream that can (and should) only be used for reading and
/// shutting down the stream. Managed by the `Reader`.
struct TcpReader(TcpStream);
impl Read for TcpReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(buf)
    }
}
impl TcpReader {
    /// Shuts down both halves of the underlying TcpStream.
    fn shutdown(&self) -> std::io::Result<()> {
        self.0.shutdown(Shutdown::Both)
    }
}

/// A newtype for a TcpStream that can (and should) only be used for writing and
/// shutting down the stream. Managed by the `Writer`.
struct TcpWriter(TcpStream);
impl Write for TcpWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}
impl TcpWriter {
    /// Shuts down both halves of the underlying TcpStream.
    fn shutdown(&self) -> std::io::Result<()> {
        self.0.shutdown(Shutdown::Both)
    }
}

/// A newtype for a TcpStream that can (and should) only be used for shutting
/// down the TcpStream. Managed by the `SyncSocketDescriptor`s.
struct TcpDisconnectooor(TcpStream);
// @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
// @@@@@@@@@@@@@@%%%%%%%%%%@@@@@@@@@@@@
// @@@@@@@@@@%###%@@@@@@@@%%##%@@@@@@@@
// @@@@@@@@#*%@@@@@%%%%%@@@@@@%##%@@@@@
// @@@@@@@##@@@@@@@@@@%%%@@@@@@@@#*@@@@
// @@@@@@%*@@@@@@@@@@@@@%%%%@%%@@@@*@@@
// @@@@@@*@@@@@@@@@%%%%%%@@@@@@@%%@**@@
// @@@@@@*@@@@@@@%#@@@@@%@%@@@@%%@@%*%@
// @@@@@%#@%%%%%@@@%##%%%##%@@%@@@@@#*@
// @@@@@%#*=%%##*#*-*+-:+#*=**#+==-*#:%
// @@@@@@*%%@@@@@@@=%#+=+%@-@@@:#-:@@:+
// @@@@@@@*@@%@#%@@#*#####*#@@#+##***=*
// @@@@@@@%*@%#:*@@@@@@@@@@@@@%##@@@#=#
// @@@@@@@@@*@@+=@@@@@@@@*#@%@@##@@@*=@
// @@@@@@@@@*@@%-=@@@@%#@%***#**%@@++@@
// @@@@@@@@@+@@@*-=@@@#%* ....: =%*=@@@
// @@@@@@@@##@@@%@=:#@@@*      .%*:%@@@
// @@@@@@@%+@@@@@@@*==#@@#. .:+#-=@@@@@
// @@@@@@#*@@@##%@@@@*=-+#*++**-*@@@@@@
// @%#####@@@#%@@@@@@@@%#+###**%%%%%#%%
// %%@@@@@@@@@@@@@@@%%%@%@@@@@@@@@@@@@@
// @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
impl Clone for TcpDisconnectooor {
    fn clone(&self) -> Self {
        Self(self.0.try_clone().unwrap())
    }
}
impl TcpDisconnectooor {
    /// Shuts down both halves of the underlying TcpStream.
    fn shutdown(&self) -> std::io::Result<()> {
        self.0.shutdown(Shutdown::Both)
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
    use lightning::ln::features::*;
    use lightning::ln::msgs::*;
    use lightning::ln::peer_handler::{IgnoringMessageHandler, MessageHandler, PeerManager};
    use lightning::util::events::*;
    use lightning::util::logger;

    use super::handle_connection;
    use super::ConnectionType::*;

    use std::mem;
    use std::net::{TcpListener, TcpStream};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    pub struct TestLogger();
    impl logger::Logger for TestLogger {
        fn log(&self, record: &logger::Record) {
            println!(
                "{:<5} [{} : {}, {}] {}",
                record.level.to_string(),
                record.module_path,
                record.file,
                record.line,
                record.args
            );
        }
    }

    /// A RoutingMessageHandler that uses the peer_connected() and
    /// peer_disconnected() callbacks to confirm that the peer was successfully
    /// connected (and disconnected)
    struct MsgHandler {
        expected_pubkey: PublicKey,
        connected_tx: crossbeam_channel::Sender<()>,
        disconnected_tx: crossbeam_channel::Sender<()>,
        disconnected_flag: AtomicBool,
        msg_events: Mutex<Vec<MessageSendEvent>>,
    }
    impl RoutingMessageHandler for MsgHandler {
        fn handle_node_announcement(
            &self,
            _msg: &NodeAnnouncement,
        ) -> Result<bool, LightningError> {
            Ok(false)
        }
        fn handle_channel_announcement(
            &self,
            _msg: &ChannelAnnouncement,
        ) -> Result<bool, LightningError> {
            Ok(false)
        }
        fn handle_channel_update(&self, _msg: &ChannelUpdate) -> Result<bool, LightningError> {
            Ok(false)
        }
        fn get_next_channel_announcements(
            &self,
            _starting_point: u64,
            _batch_amount: u8,
        ) -> Vec<(
            ChannelAnnouncement,
            Option<ChannelUpdate>,
            Option<ChannelUpdate>,
        )> {
            Vec::new()
        }
        fn get_next_node_announcements(
            &self,
            _starting_point: Option<&PublicKey>,
            _batch_amount: u8,
        ) -> Vec<NodeAnnouncement> {
            Vec::new()
        }
        fn peer_connected(&self, _their_node_id: &PublicKey, _init_msg: &Init) {}
        fn handle_reply_channel_range(
            &self,
            _their_node_id: &PublicKey,
            _msg: ReplyChannelRange,
        ) -> Result<(), LightningError> {
            Ok(())
        }
        fn handle_reply_short_channel_ids_end(
            &self,
            _their_node_id: &PublicKey,
            _msg: ReplyShortChannelIdsEnd,
        ) -> Result<(), LightningError> {
            Ok(())
        }
        fn handle_query_channel_range(
            &self,
            _their_node_id: &PublicKey,
            _msg: QueryChannelRange,
        ) -> Result<(), LightningError> {
            Ok(())
        }
        fn handle_query_short_channel_ids(
            &self,
            _their_node_id: &PublicKey,
            _msg: QueryShortChannelIds,
        ) -> Result<(), LightningError> {
            Ok(())
        }
    }
    impl ChannelMessageHandler for MsgHandler {
        fn handle_open_channel(
            &self,
            _their_node_id: &PublicKey,
            _their_features: InitFeatures,
            _msg: &OpenChannel,
        ) {
        }
        fn handle_accept_channel(
            &self,
            _their_node_id: &PublicKey,
            _their_features: InitFeatures,
            _msg: &AcceptChannel,
        ) {
        }
        fn handle_funding_created(&self, _their_node_id: &PublicKey, _msg: &FundingCreated) {}
        fn handle_funding_signed(&self, _their_node_id: &PublicKey, _msg: &FundingSigned) {}
        fn handle_funding_locked(&self, _their_node_id: &PublicKey, _msg: &FundingLocked) {}
        fn handle_shutdown(
            &self,
            _their_node_id: &PublicKey,
            _their_features: &InitFeatures,
            _msg: &Shutdown,
        ) {
        }
        fn handle_closing_signed(&self, _their_node_id: &PublicKey, _msg: &ClosingSigned) {}
        fn handle_update_add_htlc(&self, _their_node_id: &PublicKey, _msg: &UpdateAddHTLC) {}
        fn handle_update_fulfill_htlc(&self, _their_node_id: &PublicKey, _msg: &UpdateFulfillHTLC) {
        }
        fn handle_update_fail_htlc(&self, _their_node_id: &PublicKey, _msg: &UpdateFailHTLC) {}
        fn handle_update_fail_malformed_htlc(
            &self,
            _their_node_id: &PublicKey,
            _msg: &UpdateFailMalformedHTLC,
        ) {
        }
        fn handle_commitment_signed(&self, _their_node_id: &PublicKey, _msg: &CommitmentSigned) {}
        fn handle_revoke_and_ack(&self, _their_node_id: &PublicKey, _msg: &RevokeAndACK) {}
        fn handle_update_fee(&self, _their_node_id: &PublicKey, _msg: &UpdateFee) {}
        fn handle_announcement_signatures(
            &self,
            _their_node_id: &PublicKey,
            _msg: &AnnouncementSignatures,
        ) {
        }
        fn handle_channel_update(&self, _their_node_id: &PublicKey, _msg: &ChannelUpdate) {}
        fn peer_disconnected(&self, their_node_id: &PublicKey, _no_connection_possible: bool) {
            if *their_node_id == self.expected_pubkey {
                self.disconnected_flag.store(true, Ordering::SeqCst);
                self.disconnected_tx.try_send(()).unwrap();
            }
        }
        fn peer_connected(&self, their_node_id: &PublicKey, _msg: &Init) {
            if *their_node_id == self.expected_pubkey {
                self.connected_tx.try_send(()).unwrap();
            }
        }
        fn handle_channel_reestablish(
            &self,
            _their_node_id: &PublicKey,
            _msg: &ChannelReestablish,
        ) {
        }
        fn handle_error(&self, _their_node_id: &PublicKey, _msg: &ErrorMessage) {}
    }
    impl MessageSendEventsProvider for MsgHandler {
        fn get_and_clear_pending_msg_events(&self) -> Vec<MessageSendEvent> {
            let mut ret = Vec::new();
            mem::swap(&mut *self.msg_events.lock().unwrap(), &mut ret);
            ret
        }
    }

    #[test]
    fn basic_connection_test() {
        // Initialize public / private keys
        let secp_ctx = Secp256k1::new();
        let a_key = SecretKey::from_slice(&[1; 32]).unwrap();
        let b_key = SecretKey::from_slice(&[1; 32]).unwrap();
        let a_pub = PublicKey::from_secret_key(&secp_ctx, &a_key);
        let b_pub = PublicKey::from_secret_key(&secp_ctx, &b_key);

        // Initialize node A
        let (a_connected_tx, a_connected_rx) = crossbeam_channel::bounded(1);
        let (a_disconnected_tx, a_disconnected_rx) = crossbeam_channel::bounded(1);
        let a_handler = Arc::new(MsgHandler {
            expected_pubkey: b_pub,
            connected_tx: a_connected_tx,
            disconnected_tx: a_disconnected_tx,
            disconnected_flag: AtomicBool::new(false),
            msg_events: Mutex::new(Vec::new()),
        });
        let a_manager = Arc::new(PeerManager::new(
            MessageHandler {
                chan_handler: Arc::clone(&a_handler),
                route_handler: Arc::clone(&a_handler),
            },
            a_key.clone(),
            &[1; 32],
            Arc::new(TestLogger()),
            Arc::new(IgnoringMessageHandler {}),
        ));

        // Initialize node B
        let (b_connected_tx, b_connected_rx) = crossbeam_channel::bounded(1);
        let (b_disconnected_tx, b_disconnected_rx) = crossbeam_channel::bounded(1);
        let b_handler = Arc::new(MsgHandler {
            expected_pubkey: a_pub,
            connected_tx: b_connected_tx,
            disconnected_tx: b_disconnected_tx,
            disconnected_flag: AtomicBool::new(false),
            msg_events: Mutex::new(Vec::new()),
        });
        let b_manager = Arc::new(PeerManager::new(
            MessageHandler {
                chan_handler: Arc::clone(&b_handler),
                route_handler: Arc::clone(&b_handler),
            },
            b_key.clone(),
            &[2; 32],
            Arc::new(TestLogger()),
            Arc::new(IgnoringMessageHandler {}),
        ));

        // Create a connection. We bind on localhost, hoping the environment is
        // properly configured with a local address. This may not always be the
        // case in containers and the like, so if this test is failing for you
        // check that you have a loopback interface and it is configured with
        // 127.0.0.1.
        let (conn_a, conn_b) = if let Ok(server) = TcpListener::bind("127.0.0.1:9735") {
            (
                TcpStream::connect("127.0.0.1:9735").unwrap(),
                server.accept().unwrap().0,
            )
        } else if let Ok(server) = TcpListener::bind("127.0.0.1:9999") {
            (
                TcpStream::connect("127.0.0.1:9999").unwrap(),
                server.accept().unwrap().0,
            )
        } else if let Ok(server) = TcpListener::bind("127.0.0.1:46926") {
            (
                TcpStream::connect("127.0.0.1:46926").unwrap(),
                server.accept().unwrap().0,
            )
        } else {
            panic!("Failed to bind to v4 localhost on common ports");
        };

        // Initiate the connection handler threads for node A and B
        let (a_read, a_write) =
            handle_connection(Arc::clone(&a_manager), conn_a, Outbound(b_pub)).unwrap();
        let (b_read, b_write) = handle_connection(b_manager, conn_b, Inbound).unwrap();

        // Confirm that each of the node's MsgHandlers accepted the connection
        a_connected_rx.recv().unwrap();
        b_connected_rx.recv().unwrap();

        // Trigger a disconnect
        a_handler
            .msg_events
            .lock()
            .unwrap()
            .push(MessageSendEvent::HandleError {
                node_id: b_pub,
                action: ErrorAction::DisconnectPeer { msg: None },
            });
        assert!(!a_handler.disconnected_flag.load(Ordering::SeqCst));
        assert!(!b_handler.disconnected_flag.load(Ordering::SeqCst));
        a_manager.process_events();

        // Confirm recognition of disconnect
        a_disconnected_rx.recv().unwrap();
        b_disconnected_rx.recv().unwrap();
        assert!(a_handler.disconnected_flag.load(Ordering::SeqCst));
        assert!(b_handler.disconnected_flag.load(Ordering::SeqCst));

        // Confirm read and Writer threads finished for both nodes
        a_read.join().unwrap();
        a_write.join().unwrap();
        b_read.join().unwrap();
        b_write.join().unwrap();
    }
}
