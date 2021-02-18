//! Top level peer message handling and socket handling logic lives here.
//!
//! Instead of actually servicing sockets ourselves we require that you implement the
//! SocketDescriptor interface and use that to receive actions which you should perform on the
//! socket, and call into PeerManager with bytes read from the socket. The PeerManager will then
//! call into the provided message handlers (probably a ChannelManager and NetGraphmsgHandler) with messages
//! they should handle, and encoding/sending response messages.

use std::ffi::c_void;
use bitcoin::hashes::Hash;
use crate::c_types::*;


use lightning::ln::peer_handler::MessageHandler as nativeMessageHandlerImport;
type nativeMessageHandler = nativeMessageHandlerImport<crate::ln::msgs::ChannelMessageHandler, crate::ln::msgs::RoutingMessageHandler>;

/// Provides references to trait impls which handle different types of messages.
#[must_use]
#[repr(C)]
pub struct MessageHandler {
	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeMessageHandler,
	pub is_owned: bool,
}

impl Drop for MessageHandler {
	fn drop(&mut self) {
		if self.is_owned && !self.inner.is_null() {
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
#[no_mangle]
pub extern "C" fn MessageHandler_free(this_ptr: MessageHandler) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn MessageHandler_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeMessageHandler); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl MessageHandler {
	pub(crate) fn take_inner(mut self) -> *mut nativeMessageHandler {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}
/// A message handler which handles messages specific to channels. Usually this is just a
/// ChannelManager object.
#[no_mangle]
pub extern "C" fn MessageHandler_get_chan_handler(this_ptr: &MessageHandler) -> *const crate::ln::msgs::ChannelMessageHandler {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.chan_handler;
	&(*inner_val)
}
/// A message handler which handles messages specific to channels. Usually this is just a
/// ChannelManager object.
#[no_mangle]
pub extern "C" fn MessageHandler_set_chan_handler(this_ptr: &mut MessageHandler, mut val: crate::ln::msgs::ChannelMessageHandler) {
	unsafe { &mut *this_ptr.inner }.chan_handler = val;
}
/// A message handler which handles messages updating our knowledge of the network channel
/// graph. Usually this is just a NetGraphMsgHandlerMonitor object.
#[no_mangle]
pub extern "C" fn MessageHandler_get_route_handler(this_ptr: &MessageHandler) -> *const crate::ln::msgs::RoutingMessageHandler {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.route_handler;
	&(*inner_val)
}
/// A message handler which handles messages updating our knowledge of the network channel
/// graph. Usually this is just a NetGraphMsgHandlerMonitor object.
#[no_mangle]
pub extern "C" fn MessageHandler_set_route_handler(this_ptr: &mut MessageHandler, mut val: crate::ln::msgs::RoutingMessageHandler) {
	unsafe { &mut *this_ptr.inner }.route_handler = val;
}
#[must_use]
#[no_mangle]
pub extern "C" fn MessageHandler_new(mut chan_handler_arg: crate::ln::msgs::ChannelMessageHandler, mut route_handler_arg: crate::ln::msgs::RoutingMessageHandler) -> MessageHandler {
	MessageHandler { inner: Box::into_raw(Box::new(nativeMessageHandler {
		chan_handler: chan_handler_arg,
		route_handler: route_handler_arg,
	})), is_owned: true }
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
#[repr(C)]
pub struct SocketDescriptor {
	pub this_arg: *mut c_void,
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
	#[must_use]
	pub send_data: extern "C" fn (this_arg: *mut c_void, data: crate::c_types::u8slice, resume_read: bool) -> usize,
	/// Disconnect the socket pointed to by this SocketDescriptor. Once this function returns, no
	/// more calls to write_buffer_space_avail, read_event or socket_disconnected may be made with
	/// this descriptor. No socket_disconnected call should be generated as a result of this call,
	/// though races may occur whereby disconnect_socket is called after a call to
	/// socket_disconnected but prior to socket_disconnected returning.
	pub disconnect_socket: extern "C" fn (this_arg: *mut c_void),
	pub eq: extern "C" fn (this_arg: *const c_void, other_arg: &SocketDescriptor) -> bool,
	pub hash: extern "C" fn (this_arg: *const c_void) -> u64,
	pub clone: Option<extern "C" fn (this_arg: *const c_void) -> *mut c_void>,
	pub free: Option<extern "C" fn(this_arg: *mut c_void)>,
}
impl std::cmp::Eq for SocketDescriptor {}
impl std::cmp::PartialEq for SocketDescriptor {
	fn eq(&self, o: &Self) -> bool { (self.eq)(self.this_arg, o) }
}
impl std::hash::Hash for SocketDescriptor {
	fn hash<H: std::hash::Hasher>(&self, hasher: &mut H) { hasher.write_u64((self.hash)(self.this_arg)) }
}
#[no_mangle]
pub extern "C" fn SocketDescriptor_clone(orig: &SocketDescriptor) -> SocketDescriptor {
	SocketDescriptor {
		this_arg: if let Some(f) = orig.clone { (f)(orig.this_arg) } else { orig.this_arg },
		send_data: orig.send_data.clone(),
		disconnect_socket: orig.disconnect_socket.clone(),
		eq: orig.eq.clone(),
		hash: orig.hash.clone(),
		clone: orig.clone.clone(),
		free: orig.free.clone(),
	}
}
impl Clone for SocketDescriptor {
	fn clone(&self) -> Self {
		SocketDescriptor_clone(self)
	}
}

use lightning::ln::peer_handler::SocketDescriptor as rustSocketDescriptor;
impl rustSocketDescriptor for SocketDescriptor {
	fn send_data(&mut self, data: &[u8], resume_read: bool) -> usize {
		let mut local_data = crate::c_types::u8slice::from_slice(data);
		let mut ret = (self.send_data)(self.this_arg, local_data, resume_read);
		ret
	}
	fn disconnect_socket(&mut self) {
		(self.disconnect_socket)(self.this_arg)
	}
}

// We're essentially a pointer already, or at least a set of pointers, so allow us to be used
// directly as a Deref trait in higher-level structs:
impl std::ops::Deref for SocketDescriptor {
	type Target = Self;
	fn deref(&self) -> &Self {
		self
	}
}
/// Calls the free function if one is set
#[no_mangle]
pub extern "C" fn SocketDescriptor_free(this_ptr: SocketDescriptor) { }
impl Drop for SocketDescriptor {
	fn drop(&mut self) {
		if let Some(f) = self.free {
			f(self.this_arg);
		}
	}
}

use lightning::ln::peer_handler::PeerHandleError as nativePeerHandleErrorImport;
type nativePeerHandleError = nativePeerHandleErrorImport;

/// Error for PeerManager errors. If you get one of these, you must disconnect the socket and
/// generate no further read_event/write_buffer_space_avail/socket_disconnected calls for the
/// descriptor.
#[must_use]
#[repr(C)]
pub struct PeerHandleError {
	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativePeerHandleError,
	pub is_owned: bool,
}

impl Drop for PeerHandleError {
	fn drop(&mut self) {
		if self.is_owned && !self.inner.is_null() {
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
#[no_mangle]
pub extern "C" fn PeerHandleError_free(this_ptr: PeerHandleError) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn PeerHandleError_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativePeerHandleError); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl PeerHandleError {
	pub(crate) fn take_inner(mut self) -> *mut nativePeerHandleError {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}
/// Used to indicate that we probably can't make any future connections to this peer, implying
/// we should go ahead and force-close any channels we have with it.
#[no_mangle]
pub extern "C" fn PeerHandleError_get_no_connection_possible(this_ptr: &PeerHandleError) -> bool {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.no_connection_possible;
	(*inner_val)
}
/// Used to indicate that we probably can't make any future connections to this peer, implying
/// we should go ahead and force-close any channels we have with it.
#[no_mangle]
pub extern "C" fn PeerHandleError_set_no_connection_possible(this_ptr: &mut PeerHandleError, mut val: bool) {
	unsafe { &mut *this_ptr.inner }.no_connection_possible = val;
}
#[must_use]
#[no_mangle]
pub extern "C" fn PeerHandleError_new(mut no_connection_possible_arg: bool) -> PeerHandleError {
	PeerHandleError { inner: Box::into_raw(Box::new(nativePeerHandleError {
		no_connection_possible: no_connection_possible_arg,
	})), is_owned: true }
}
impl Clone for PeerHandleError {
	fn clone(&self) -> Self {
		Self {
			inner: if self.inner.is_null() { std::ptr::null_mut() } else {
				Box::into_raw(Box::new(unsafe { &*self.inner }.clone())) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn PeerHandleError_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativePeerHandleError)).clone() })) as *mut c_void
}
#[no_mangle]
pub extern "C" fn PeerHandleError_clone(orig: &PeerHandleError) -> PeerHandleError {
	orig.clone()
}

use lightning::ln::peer_handler::PeerManager as nativePeerManagerImport;
type nativePeerManager = nativePeerManagerImport<crate::ln::peer_handler::SocketDescriptor, crate::ln::msgs::ChannelMessageHandler, crate::ln::msgs::RoutingMessageHandler, crate::util::logger::Logger>;

/// A PeerManager manages a set of peers, described by their SocketDescriptor and marshalls socket
/// events into messages which it passes on to its MessageHandlers.
///
/// Rather than using a plain PeerManager, it is preferable to use either a SimpleArcPeerManager
/// a SimpleRefPeerManager, for conciseness. See their documentation for more details, but
/// essentially you should default to using a SimpleRefPeerManager, and use a
/// SimpleArcPeerManager when you require a PeerManager with a static lifetime, such as when
/// you're using lightning-net-tokio.
#[must_use]
#[repr(C)]
pub struct PeerManager {
	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativePeerManager,
	pub is_owned: bool,
}

impl Drop for PeerManager {
	fn drop(&mut self) {
		if self.is_owned && !self.inner.is_null() {
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
#[no_mangle]
pub extern "C" fn PeerManager_free(this_ptr: PeerManager) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn PeerManager_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativePeerManager); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl PeerManager {
	pub(crate) fn take_inner(mut self) -> *mut nativePeerManager {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}
/// Constructs a new PeerManager with the given message handlers and node_id secret key
/// ephemeral_random_data is used to derive per-connection ephemeral keys and must be
/// cryptographically secure random bytes.
#[must_use]
#[no_mangle]
pub extern "C" fn PeerManager_new(mut message_handler: crate::ln::peer_handler::MessageHandler, mut our_node_secret: crate::c_types::SecretKey, ephemeral_random_data: *const [u8; 32], mut logger: crate::util::logger::Logger) -> PeerManager {
	let mut ret = lightning::ln::peer_handler::PeerManager::new(*unsafe { Box::from_raw(message_handler.take_inner()) }, our_node_secret.into_rust(), unsafe { &*ephemeral_random_data}, logger);
	PeerManager { inner: Box::into_raw(Box::new(ret)), is_owned: true }
}

/// Get the list of node ids for peers which have completed the initial handshake.
///
/// For outbound connections, this will be the same as the their_node_id parameter passed in to
/// new_outbound_connection, however entries will only appear once the initial handshake has
/// completed and we are sure the remote peer has the private key for the given node_id.
#[must_use]
#[no_mangle]
pub extern "C" fn PeerManager_get_peer_node_ids(this_arg: &PeerManager) -> crate::c_types::derived::CVec_PublicKeyZ {
	let mut ret = unsafe { &*this_arg.inner }.get_peer_node_ids();
	let mut local_ret = Vec::new(); for item in ret.drain(..) { local_ret.push( { crate::c_types::PublicKey::from_rust(&item) }); };
	local_ret.into()
}

/// Indicates a new outbound connection has been established to a node with the given node_id.
/// Note that if an Err is returned here you MUST NOT call socket_disconnected for the new
/// descriptor but must disconnect the connection immediately.
///
/// Returns a small number of bytes to send to the remote node (currently always 50).
///
/// Panics if descriptor is duplicative with some other descriptor which has not yet had a
/// socket_disconnected().
#[must_use]
#[no_mangle]
pub extern "C" fn PeerManager_new_outbound_connection(this_arg: &PeerManager, mut their_node_id: crate::c_types::PublicKey, mut descriptor: crate::ln::peer_handler::SocketDescriptor) -> crate::c_types::derived::CResult_CVec_u8ZPeerHandleErrorZ {
	let mut ret = unsafe { &*this_arg.inner }.new_outbound_connection(their_node_id.into_rust(), descriptor);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { let mut local_ret_0 = Vec::new(); for item in o.drain(..) { local_ret_0.push( { item }); }; local_ret_0.into() }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::ln::peer_handler::PeerHandleError { inner: Box::into_raw(Box::new(e)), is_owned: true } }).into() };
	local_ret
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
#[must_use]
#[no_mangle]
pub extern "C" fn PeerManager_new_inbound_connection(this_arg: &PeerManager, mut descriptor: crate::ln::peer_handler::SocketDescriptor) -> crate::c_types::derived::CResult_NonePeerHandleErrorZ {
	let mut ret = unsafe { &*this_arg.inner }.new_inbound_connection(descriptor);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { 0u8 /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::ln::peer_handler::PeerHandleError { inner: Box::into_raw(Box::new(e)), is_owned: true } }).into() };
	local_ret
}

/// Indicates that there is room to write data to the given socket descriptor.
///
/// May return an Err to indicate that the connection should be closed.
///
/// Will most likely call send_data on the descriptor passed in (or the descriptor handed into
/// new_*\\_connection) before returning. Thus, be very careful with reentrancy issues! The
/// invariants around calling write_buffer_space_avail in case a write did not fully complete
/// must still hold - be ready to call write_buffer_space_avail again if a write call generated
/// here isn't sufficient! Panics if the descriptor was not previously registered in a
/// new_\\*_connection event.
#[must_use]
#[no_mangle]
pub extern "C" fn PeerManager_write_buffer_space_avail(this_arg: &PeerManager, descriptor: &mut crate::ln::peer_handler::SocketDescriptor) -> crate::c_types::derived::CResult_NonePeerHandleErrorZ {
	let mut ret = unsafe { &*this_arg.inner }.write_buffer_space_avail(descriptor);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { 0u8 /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::ln::peer_handler::PeerHandleError { inner: Box::into_raw(Box::new(e)), is_owned: true } }).into() };
	local_ret
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
#[must_use]
#[no_mangle]
pub extern "C" fn PeerManager_read_event(this_arg: &PeerManager, peer_descriptor: &mut crate::ln::peer_handler::SocketDescriptor, mut data: crate::c_types::u8slice) -> crate::c_types::derived::CResult_boolPeerHandleErrorZ {
	let mut ret = unsafe { &*this_arg.inner }.read_event(peer_descriptor, data.to_slice());
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { o }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::ln::peer_handler::PeerHandleError { inner: Box::into_raw(Box::new(e)), is_owned: true } }).into() };
	local_ret
}

/// Checks for any events generated by our handlers and processes them. Includes sending most
/// response messages as well as messages generated by calls to handler functions directly (eg
/// functions like ChannelManager::process_pending_htlc_forward or send_payment).
#[no_mangle]
pub extern "C" fn PeerManager_process_events(this_arg: &PeerManager) {
	unsafe { &*this_arg.inner }.process_events()
}

/// Indicates that the given socket descriptor's connection is now closed.
///
/// This must only be called if the socket has been disconnected by the peer or your own
/// decision to disconnect it and must NOT be called in any case where other parts of this
/// library (eg PeerHandleError, explicit disconnect_socket calls) instruct you to disconnect
/// the peer.
///
/// Panics if the descriptor was not previously registered in a successful new_*_connection event.
#[no_mangle]
pub extern "C" fn PeerManager_socket_disconnected(this_arg: &PeerManager, descriptor: &crate::ln::peer_handler::SocketDescriptor) {
	unsafe { &*this_arg.inner }.socket_disconnected(descriptor)
}

/// Disconnect a peer given its node id.
///
/// Set no_connection_possible to true to prevent any further connection with this peer,
/// force-closing any channels we have with it.
///
/// If a peer is connected, this will call `disconnect_socket` on the descriptor for the peer,
/// so be careful about reentrancy issues.
#[no_mangle]
pub extern "C" fn PeerManager_disconnect_by_node_id(this_arg: &PeerManager, mut node_id: crate::c_types::PublicKey, mut no_connection_possible: bool) {
	unsafe { &*this_arg.inner }.disconnect_by_node_id(node_id.into_rust(), no_connection_possible)
}

/// This function should be called roughly once every 30 seconds.
/// It will send pings to each peer and disconnect those which did not respond to the last round of pings.
/// Will most likely call send_data on all of the registered descriptors, thus, be very careful with reentrancy issues!
#[no_mangle]
pub extern "C" fn PeerManager_timer_tick_occured(this_arg: &PeerManager) {
	unsafe { &*this_arg.inner }.timer_tick_occured()
}

