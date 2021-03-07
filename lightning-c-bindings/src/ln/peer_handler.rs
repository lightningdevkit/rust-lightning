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


use lightning::ln::peer_handler::IgnoringMessageHandler as nativeIgnoringMessageHandlerImport;
type nativeIgnoringMessageHandler = nativeIgnoringMessageHandlerImport;

/// A dummy struct which implements `RoutingMessageHandler` without storing any routing information
/// or doing any processing. You can provide one of these as the route_handler in a MessageHandler.
#[must_use]
#[repr(C)]
pub struct IgnoringMessageHandler {
	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeIgnoringMessageHandler,
	pub is_owned: bool,
}

impl Drop for IgnoringMessageHandler {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeIgnoringMessageHandler>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
#[no_mangle]
pub extern "C" fn IgnoringMessageHandler_free(this_ptr: IgnoringMessageHandler) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn IgnoringMessageHandler_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeIgnoringMessageHandler); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl IgnoringMessageHandler {
	pub(crate) fn take_inner(mut self) -> *mut nativeIgnoringMessageHandler {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}
#[must_use]
#[no_mangle]
pub extern "C" fn IgnoringMessageHandler_new() -> IgnoringMessageHandler {
	IgnoringMessageHandler { inner: Box::into_raw(Box::new(nativeIgnoringMessageHandler {
	})), is_owned: true }
}
impl From<nativeIgnoringMessageHandler> for crate::util::events::MessageSendEventsProvider {
	fn from(obj: nativeIgnoringMessageHandler) -> Self {
		let mut rust_obj = IgnoringMessageHandler { inner: Box::into_raw(Box::new(obj)), is_owned: true };
		let mut ret = IgnoringMessageHandler_as_MessageSendEventsProvider(&rust_obj);
		// We want to free rust_obj when ret gets drop()'d, not rust_obj, so wipe rust_obj's pointer and set ret's free() fn
		rust_obj.inner = std::ptr::null_mut();
		ret.free = Some(IgnoringMessageHandler_free_void);
		ret
	}
}
#[no_mangle]
pub extern "C" fn IgnoringMessageHandler_as_MessageSendEventsProvider(this_arg: &IgnoringMessageHandler) -> crate::util::events::MessageSendEventsProvider {
	crate::util::events::MessageSendEventsProvider {
		this_arg: unsafe { (*this_arg).inner as *mut c_void },
		free: None,
		get_and_clear_pending_msg_events: IgnoringMessageHandler_MessageSendEventsProvider_get_and_clear_pending_msg_events,
	}
}

#[must_use]
extern "C" fn IgnoringMessageHandler_MessageSendEventsProvider_get_and_clear_pending_msg_events(this_arg: *const c_void) -> crate::c_types::derived::CVec_MessageSendEventZ {
	let mut ret = <nativeIgnoringMessageHandler as lightning::util::events::MessageSendEventsProvider<>>::get_and_clear_pending_msg_events(unsafe { &mut *(this_arg as *mut nativeIgnoringMessageHandler) }, );
	let mut local_ret = Vec::new(); for mut item in ret.drain(..) { local_ret.push( { crate::util::events::MessageSendEvent::native_into(item) }); };
	local_ret.into()
}

impl From<nativeIgnoringMessageHandler> for crate::ln::msgs::RoutingMessageHandler {
	fn from(obj: nativeIgnoringMessageHandler) -> Self {
		let mut rust_obj = IgnoringMessageHandler { inner: Box::into_raw(Box::new(obj)), is_owned: true };
		let mut ret = IgnoringMessageHandler_as_RoutingMessageHandler(&rust_obj);
		// We want to free rust_obj when ret gets drop()'d, not rust_obj, so wipe rust_obj's pointer and set ret's free() fn
		rust_obj.inner = std::ptr::null_mut();
		ret.free = Some(IgnoringMessageHandler_free_void);
		ret
	}
}
#[no_mangle]
pub extern "C" fn IgnoringMessageHandler_as_RoutingMessageHandler(this_arg: &IgnoringMessageHandler) -> crate::ln::msgs::RoutingMessageHandler {
	crate::ln::msgs::RoutingMessageHandler {
		this_arg: unsafe { (*this_arg).inner as *mut c_void },
		free: None,
		handle_node_announcement: IgnoringMessageHandler_RoutingMessageHandler_handle_node_announcement,
		handle_channel_announcement: IgnoringMessageHandler_RoutingMessageHandler_handle_channel_announcement,
		handle_channel_update: IgnoringMessageHandler_RoutingMessageHandler_handle_channel_update,
		handle_htlc_fail_channel_update: IgnoringMessageHandler_RoutingMessageHandler_handle_htlc_fail_channel_update,
		get_next_channel_announcements: IgnoringMessageHandler_RoutingMessageHandler_get_next_channel_announcements,
		get_next_node_announcements: IgnoringMessageHandler_RoutingMessageHandler_get_next_node_announcements,
		sync_routing_table: IgnoringMessageHandler_RoutingMessageHandler_sync_routing_table,
		handle_reply_channel_range: IgnoringMessageHandler_RoutingMessageHandler_handle_reply_channel_range,
		handle_reply_short_channel_ids_end: IgnoringMessageHandler_RoutingMessageHandler_handle_reply_short_channel_ids_end,
		handle_query_channel_range: IgnoringMessageHandler_RoutingMessageHandler_handle_query_channel_range,
		handle_query_short_channel_ids: IgnoringMessageHandler_RoutingMessageHandler_handle_query_short_channel_ids,
		MessageSendEventsProvider: crate::util::events::MessageSendEventsProvider {
			this_arg: unsafe { (*this_arg).inner as *mut c_void },
			free: None,
			get_and_clear_pending_msg_events: IgnoringMessageHandler_RoutingMessageHandler_get_and_clear_pending_msg_events,
		},
	}
}

#[must_use]
extern "C" fn IgnoringMessageHandler_RoutingMessageHandler_handle_node_announcement(this_arg: *const c_void, _msg: &crate::ln::msgs::NodeAnnouncement) -> crate::c_types::derived::CResult_boolLightningErrorZ {
	let mut ret = <nativeIgnoringMessageHandler as lightning::ln::msgs::RoutingMessageHandler<>>::handle_node_announcement(unsafe { &mut *(this_arg as *mut nativeIgnoringMessageHandler) }, unsafe { &*_msg.inner });
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { o }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::ln::msgs::LightningError { inner: Box::into_raw(Box::new(e)), is_owned: true } }).into() };
	local_ret
}
#[must_use]
extern "C" fn IgnoringMessageHandler_RoutingMessageHandler_handle_channel_announcement(this_arg: *const c_void, _msg: &crate::ln::msgs::ChannelAnnouncement) -> crate::c_types::derived::CResult_boolLightningErrorZ {
	let mut ret = <nativeIgnoringMessageHandler as lightning::ln::msgs::RoutingMessageHandler<>>::handle_channel_announcement(unsafe { &mut *(this_arg as *mut nativeIgnoringMessageHandler) }, unsafe { &*_msg.inner });
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { o }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::ln::msgs::LightningError { inner: Box::into_raw(Box::new(e)), is_owned: true } }).into() };
	local_ret
}
#[must_use]
extern "C" fn IgnoringMessageHandler_RoutingMessageHandler_handle_channel_update(this_arg: *const c_void, _msg: &crate::ln::msgs::ChannelUpdate) -> crate::c_types::derived::CResult_boolLightningErrorZ {
	let mut ret = <nativeIgnoringMessageHandler as lightning::ln::msgs::RoutingMessageHandler<>>::handle_channel_update(unsafe { &mut *(this_arg as *mut nativeIgnoringMessageHandler) }, unsafe { &*_msg.inner });
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { o }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::ln::msgs::LightningError { inner: Box::into_raw(Box::new(e)), is_owned: true } }).into() };
	local_ret
}
extern "C" fn IgnoringMessageHandler_RoutingMessageHandler_handle_htlc_fail_channel_update(this_arg: *const c_void, _update: &crate::ln::msgs::HTLCFailChannelUpdate) {
	<nativeIgnoringMessageHandler as lightning::ln::msgs::RoutingMessageHandler<>>::handle_htlc_fail_channel_update(unsafe { &mut *(this_arg as *mut nativeIgnoringMessageHandler) }, &_update.to_native())
}
#[must_use]
extern "C" fn IgnoringMessageHandler_RoutingMessageHandler_get_next_channel_announcements(this_arg: *const c_void, mut _starting_point: u64, mut _batch_amount: u8) -> crate::c_types::derived::CVec_C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZZ {
	let mut ret = <nativeIgnoringMessageHandler as lightning::ln::msgs::RoutingMessageHandler<>>::get_next_channel_announcements(unsafe { &mut *(this_arg as *mut nativeIgnoringMessageHandler) }, _starting_point, _batch_amount);
	let mut local_ret = Vec::new(); for mut item in ret.drain(..) { local_ret.push( { let (mut orig_ret_0_0, mut orig_ret_0_1, mut orig_ret_0_2) = item; let mut local_orig_ret_0_1 = crate::ln::msgs::ChannelUpdate { inner: if orig_ret_0_1.is_none() { std::ptr::null_mut() } else {  { Box::into_raw(Box::new((orig_ret_0_1.unwrap()))) } }, is_owned: true }; let mut local_orig_ret_0_2 = crate::ln::msgs::ChannelUpdate { inner: if orig_ret_0_2.is_none() { std::ptr::null_mut() } else {  { Box::into_raw(Box::new((orig_ret_0_2.unwrap()))) } }, is_owned: true }; let mut local_ret_0 = (crate::ln::msgs::ChannelAnnouncement { inner: Box::into_raw(Box::new(orig_ret_0_0)), is_owned: true }, local_orig_ret_0_1, local_orig_ret_0_2).into(); local_ret_0 }); };
	local_ret.into()
}
#[must_use]
extern "C" fn IgnoringMessageHandler_RoutingMessageHandler_get_next_node_announcements(this_arg: *const c_void, mut _starting_point: crate::c_types::PublicKey, mut _batch_amount: u8) -> crate::c_types::derived::CVec_NodeAnnouncementZ {
	let mut local__starting_point_base = if _starting_point.is_null() { None } else { Some( { _starting_point.into_rust() }) }; let mut local__starting_point = local__starting_point_base.as_ref();
	let mut ret = <nativeIgnoringMessageHandler as lightning::ln::msgs::RoutingMessageHandler<>>::get_next_node_announcements(unsafe { &mut *(this_arg as *mut nativeIgnoringMessageHandler) }, local__starting_point, _batch_amount);
	let mut local_ret = Vec::new(); for mut item in ret.drain(..) { local_ret.push( { crate::ln::msgs::NodeAnnouncement { inner: Box::into_raw(Box::new(item)), is_owned: true } }); };
	local_ret.into()
}
extern "C" fn IgnoringMessageHandler_RoutingMessageHandler_sync_routing_table(this_arg: *const c_void, mut _their_node_id: crate::c_types::PublicKey, _init: &crate::ln::msgs::Init) {
	<nativeIgnoringMessageHandler as lightning::ln::msgs::RoutingMessageHandler<>>::sync_routing_table(unsafe { &mut *(this_arg as *mut nativeIgnoringMessageHandler) }, &_their_node_id.into_rust(), unsafe { &*_init.inner })
}
#[must_use]
extern "C" fn IgnoringMessageHandler_RoutingMessageHandler_handle_reply_channel_range(this_arg: *const c_void, mut _their_node_id: crate::c_types::PublicKey, mut _msg: crate::ln::msgs::ReplyChannelRange) -> crate::c_types::derived::CResult_NoneLightningErrorZ {
	let mut ret = <nativeIgnoringMessageHandler as lightning::ln::msgs::RoutingMessageHandler<>>::handle_reply_channel_range(unsafe { &mut *(this_arg as *mut nativeIgnoringMessageHandler) }, &_their_node_id.into_rust(), *unsafe { Box::from_raw(_msg.take_inner()) });
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { 0u8 /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::ln::msgs::LightningError { inner: Box::into_raw(Box::new(e)), is_owned: true } }).into() };
	local_ret
}
#[must_use]
extern "C" fn IgnoringMessageHandler_RoutingMessageHandler_handle_reply_short_channel_ids_end(this_arg: *const c_void, mut _their_node_id: crate::c_types::PublicKey, mut _msg: crate::ln::msgs::ReplyShortChannelIdsEnd) -> crate::c_types::derived::CResult_NoneLightningErrorZ {
	let mut ret = <nativeIgnoringMessageHandler as lightning::ln::msgs::RoutingMessageHandler<>>::handle_reply_short_channel_ids_end(unsafe { &mut *(this_arg as *mut nativeIgnoringMessageHandler) }, &_their_node_id.into_rust(), *unsafe { Box::from_raw(_msg.take_inner()) });
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { 0u8 /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::ln::msgs::LightningError { inner: Box::into_raw(Box::new(e)), is_owned: true } }).into() };
	local_ret
}
#[must_use]
extern "C" fn IgnoringMessageHandler_RoutingMessageHandler_handle_query_channel_range(this_arg: *const c_void, mut _their_node_id: crate::c_types::PublicKey, mut _msg: crate::ln::msgs::QueryChannelRange) -> crate::c_types::derived::CResult_NoneLightningErrorZ {
	let mut ret = <nativeIgnoringMessageHandler as lightning::ln::msgs::RoutingMessageHandler<>>::handle_query_channel_range(unsafe { &mut *(this_arg as *mut nativeIgnoringMessageHandler) }, &_their_node_id.into_rust(), *unsafe { Box::from_raw(_msg.take_inner()) });
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { 0u8 /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::ln::msgs::LightningError { inner: Box::into_raw(Box::new(e)), is_owned: true } }).into() };
	local_ret
}
#[must_use]
extern "C" fn IgnoringMessageHandler_RoutingMessageHandler_handle_query_short_channel_ids(this_arg: *const c_void, mut _their_node_id: crate::c_types::PublicKey, mut _msg: crate::ln::msgs::QueryShortChannelIds) -> crate::c_types::derived::CResult_NoneLightningErrorZ {
	let mut ret = <nativeIgnoringMessageHandler as lightning::ln::msgs::RoutingMessageHandler<>>::handle_query_short_channel_ids(unsafe { &mut *(this_arg as *mut nativeIgnoringMessageHandler) }, &_their_node_id.into_rust(), *unsafe { Box::from_raw(_msg.take_inner()) });
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { 0u8 /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::ln::msgs::LightningError { inner: Box::into_raw(Box::new(e)), is_owned: true } }).into() };
	local_ret
}
#[must_use]
extern "C" fn IgnoringMessageHandler_RoutingMessageHandler_get_and_clear_pending_msg_events(this_arg: *const c_void) -> crate::c_types::derived::CVec_MessageSendEventZ {
	let mut ret = <nativeIgnoringMessageHandler as lightning::util::events::MessageSendEventsProvider<>>::get_and_clear_pending_msg_events(unsafe { &mut *(this_arg as *mut nativeIgnoringMessageHandler) }, );
	let mut local_ret = Vec::new(); for mut item in ret.drain(..) { local_ret.push( { crate::util::events::MessageSendEvent::native_into(item) }); };
	local_ret.into()
}


use lightning::ln::peer_handler::ErroringMessageHandler as nativeErroringMessageHandlerImport;
type nativeErroringMessageHandler = nativeErroringMessageHandlerImport;

/// A dummy struct which implements `ChannelMessageHandler` without having any channels.
/// You can provide one of these as the route_handler in a MessageHandler.
#[must_use]
#[repr(C)]
pub struct ErroringMessageHandler {
	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeErroringMessageHandler,
	pub is_owned: bool,
}

impl Drop for ErroringMessageHandler {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeErroringMessageHandler>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
#[no_mangle]
pub extern "C" fn ErroringMessageHandler_free(this_ptr: ErroringMessageHandler) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn ErroringMessageHandler_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeErroringMessageHandler); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl ErroringMessageHandler {
	pub(crate) fn take_inner(mut self) -> *mut nativeErroringMessageHandler {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}
/// Constructs a new ErroringMessageHandler
#[must_use]
#[no_mangle]
pub extern "C" fn ErroringMessageHandler_new() -> ErroringMessageHandler {
	let mut ret = lightning::ln::peer_handler::ErroringMessageHandler::new();
	ErroringMessageHandler { inner: Box::into_raw(Box::new(ret)), is_owned: true }
}

impl From<nativeErroringMessageHandler> for crate::util::events::MessageSendEventsProvider {
	fn from(obj: nativeErroringMessageHandler) -> Self {
		let mut rust_obj = ErroringMessageHandler { inner: Box::into_raw(Box::new(obj)), is_owned: true };
		let mut ret = ErroringMessageHandler_as_MessageSendEventsProvider(&rust_obj);
		// We want to free rust_obj when ret gets drop()'d, not rust_obj, so wipe rust_obj's pointer and set ret's free() fn
		rust_obj.inner = std::ptr::null_mut();
		ret.free = Some(ErroringMessageHandler_free_void);
		ret
	}
}
#[no_mangle]
pub extern "C" fn ErroringMessageHandler_as_MessageSendEventsProvider(this_arg: &ErroringMessageHandler) -> crate::util::events::MessageSendEventsProvider {
	crate::util::events::MessageSendEventsProvider {
		this_arg: unsafe { (*this_arg).inner as *mut c_void },
		free: None,
		get_and_clear_pending_msg_events: ErroringMessageHandler_MessageSendEventsProvider_get_and_clear_pending_msg_events,
	}
}

#[must_use]
extern "C" fn ErroringMessageHandler_MessageSendEventsProvider_get_and_clear_pending_msg_events(this_arg: *const c_void) -> crate::c_types::derived::CVec_MessageSendEventZ {
	let mut ret = <nativeErroringMessageHandler as lightning::util::events::MessageSendEventsProvider<>>::get_and_clear_pending_msg_events(unsafe { &mut *(this_arg as *mut nativeErroringMessageHandler) }, );
	let mut local_ret = Vec::new(); for mut item in ret.drain(..) { local_ret.push( { crate::util::events::MessageSendEvent::native_into(item) }); };
	local_ret.into()
}

impl From<nativeErroringMessageHandler> for crate::ln::msgs::ChannelMessageHandler {
	fn from(obj: nativeErroringMessageHandler) -> Self {
		let mut rust_obj = ErroringMessageHandler { inner: Box::into_raw(Box::new(obj)), is_owned: true };
		let mut ret = ErroringMessageHandler_as_ChannelMessageHandler(&rust_obj);
		// We want to free rust_obj when ret gets drop()'d, not rust_obj, so wipe rust_obj's pointer and set ret's free() fn
		rust_obj.inner = std::ptr::null_mut();
		ret.free = Some(ErroringMessageHandler_free_void);
		ret
	}
}
#[no_mangle]
pub extern "C" fn ErroringMessageHandler_as_ChannelMessageHandler(this_arg: &ErroringMessageHandler) -> crate::ln::msgs::ChannelMessageHandler {
	crate::ln::msgs::ChannelMessageHandler {
		this_arg: unsafe { (*this_arg).inner as *mut c_void },
		free: None,
		handle_open_channel: ErroringMessageHandler_ChannelMessageHandler_handle_open_channel,
		handle_accept_channel: ErroringMessageHandler_ChannelMessageHandler_handle_accept_channel,
		handle_funding_created: ErroringMessageHandler_ChannelMessageHandler_handle_funding_created,
		handle_funding_signed: ErroringMessageHandler_ChannelMessageHandler_handle_funding_signed,
		handle_funding_locked: ErroringMessageHandler_ChannelMessageHandler_handle_funding_locked,
		handle_shutdown: ErroringMessageHandler_ChannelMessageHandler_handle_shutdown,
		handle_closing_signed: ErroringMessageHandler_ChannelMessageHandler_handle_closing_signed,
		handle_update_add_htlc: ErroringMessageHandler_ChannelMessageHandler_handle_update_add_htlc,
		handle_update_fulfill_htlc: ErroringMessageHandler_ChannelMessageHandler_handle_update_fulfill_htlc,
		handle_update_fail_htlc: ErroringMessageHandler_ChannelMessageHandler_handle_update_fail_htlc,
		handle_update_fail_malformed_htlc: ErroringMessageHandler_ChannelMessageHandler_handle_update_fail_malformed_htlc,
		handle_commitment_signed: ErroringMessageHandler_ChannelMessageHandler_handle_commitment_signed,
		handle_revoke_and_ack: ErroringMessageHandler_ChannelMessageHandler_handle_revoke_and_ack,
		handle_update_fee: ErroringMessageHandler_ChannelMessageHandler_handle_update_fee,
		handle_announcement_signatures: ErroringMessageHandler_ChannelMessageHandler_handle_announcement_signatures,
		peer_disconnected: ErroringMessageHandler_ChannelMessageHandler_peer_disconnected,
		peer_connected: ErroringMessageHandler_ChannelMessageHandler_peer_connected,
		handle_channel_reestablish: ErroringMessageHandler_ChannelMessageHandler_handle_channel_reestablish,
		handle_error: ErroringMessageHandler_ChannelMessageHandler_handle_error,
		MessageSendEventsProvider: crate::util::events::MessageSendEventsProvider {
			this_arg: unsafe { (*this_arg).inner as *mut c_void },
			free: None,
			get_and_clear_pending_msg_events: ErroringMessageHandler_ChannelMessageHandler_get_and_clear_pending_msg_events,
		},
	}
}

extern "C" fn ErroringMessageHandler_ChannelMessageHandler_handle_open_channel(this_arg: *const c_void, mut their_node_id: crate::c_types::PublicKey, mut _their_features: crate::ln::features::InitFeatures, msg: &crate::ln::msgs::OpenChannel) {
	<nativeErroringMessageHandler as lightning::ln::msgs::ChannelMessageHandler<>>::handle_open_channel(unsafe { &mut *(this_arg as *mut nativeErroringMessageHandler) }, &their_node_id.into_rust(), *unsafe { Box::from_raw(_their_features.take_inner()) }, unsafe { &*msg.inner })
}
extern "C" fn ErroringMessageHandler_ChannelMessageHandler_handle_accept_channel(this_arg: *const c_void, mut their_node_id: crate::c_types::PublicKey, mut _their_features: crate::ln::features::InitFeatures, msg: &crate::ln::msgs::AcceptChannel) {
	<nativeErroringMessageHandler as lightning::ln::msgs::ChannelMessageHandler<>>::handle_accept_channel(unsafe { &mut *(this_arg as *mut nativeErroringMessageHandler) }, &their_node_id.into_rust(), *unsafe { Box::from_raw(_their_features.take_inner()) }, unsafe { &*msg.inner })
}
extern "C" fn ErroringMessageHandler_ChannelMessageHandler_handle_funding_created(this_arg: *const c_void, mut their_node_id: crate::c_types::PublicKey, msg: &crate::ln::msgs::FundingCreated) {
	<nativeErroringMessageHandler as lightning::ln::msgs::ChannelMessageHandler<>>::handle_funding_created(unsafe { &mut *(this_arg as *mut nativeErroringMessageHandler) }, &their_node_id.into_rust(), unsafe { &*msg.inner })
}
extern "C" fn ErroringMessageHandler_ChannelMessageHandler_handle_funding_signed(this_arg: *const c_void, mut their_node_id: crate::c_types::PublicKey, msg: &crate::ln::msgs::FundingSigned) {
	<nativeErroringMessageHandler as lightning::ln::msgs::ChannelMessageHandler<>>::handle_funding_signed(unsafe { &mut *(this_arg as *mut nativeErroringMessageHandler) }, &their_node_id.into_rust(), unsafe { &*msg.inner })
}
extern "C" fn ErroringMessageHandler_ChannelMessageHandler_handle_funding_locked(this_arg: *const c_void, mut their_node_id: crate::c_types::PublicKey, msg: &crate::ln::msgs::FundingLocked) {
	<nativeErroringMessageHandler as lightning::ln::msgs::ChannelMessageHandler<>>::handle_funding_locked(unsafe { &mut *(this_arg as *mut nativeErroringMessageHandler) }, &their_node_id.into_rust(), unsafe { &*msg.inner })
}
extern "C" fn ErroringMessageHandler_ChannelMessageHandler_handle_shutdown(this_arg: *const c_void, mut their_node_id: crate::c_types::PublicKey, _their_features: &crate::ln::features::InitFeatures, msg: &crate::ln::msgs::Shutdown) {
	<nativeErroringMessageHandler as lightning::ln::msgs::ChannelMessageHandler<>>::handle_shutdown(unsafe { &mut *(this_arg as *mut nativeErroringMessageHandler) }, &their_node_id.into_rust(), unsafe { &*_their_features.inner }, unsafe { &*msg.inner })
}
extern "C" fn ErroringMessageHandler_ChannelMessageHandler_handle_closing_signed(this_arg: *const c_void, mut their_node_id: crate::c_types::PublicKey, msg: &crate::ln::msgs::ClosingSigned) {
	<nativeErroringMessageHandler as lightning::ln::msgs::ChannelMessageHandler<>>::handle_closing_signed(unsafe { &mut *(this_arg as *mut nativeErroringMessageHandler) }, &their_node_id.into_rust(), unsafe { &*msg.inner })
}
extern "C" fn ErroringMessageHandler_ChannelMessageHandler_handle_update_add_htlc(this_arg: *const c_void, mut their_node_id: crate::c_types::PublicKey, msg: &crate::ln::msgs::UpdateAddHTLC) {
	<nativeErroringMessageHandler as lightning::ln::msgs::ChannelMessageHandler<>>::handle_update_add_htlc(unsafe { &mut *(this_arg as *mut nativeErroringMessageHandler) }, &their_node_id.into_rust(), unsafe { &*msg.inner })
}
extern "C" fn ErroringMessageHandler_ChannelMessageHandler_handle_update_fulfill_htlc(this_arg: *const c_void, mut their_node_id: crate::c_types::PublicKey, msg: &crate::ln::msgs::UpdateFulfillHTLC) {
	<nativeErroringMessageHandler as lightning::ln::msgs::ChannelMessageHandler<>>::handle_update_fulfill_htlc(unsafe { &mut *(this_arg as *mut nativeErroringMessageHandler) }, &their_node_id.into_rust(), unsafe { &*msg.inner })
}
extern "C" fn ErroringMessageHandler_ChannelMessageHandler_handle_update_fail_htlc(this_arg: *const c_void, mut their_node_id: crate::c_types::PublicKey, msg: &crate::ln::msgs::UpdateFailHTLC) {
	<nativeErroringMessageHandler as lightning::ln::msgs::ChannelMessageHandler<>>::handle_update_fail_htlc(unsafe { &mut *(this_arg as *mut nativeErroringMessageHandler) }, &their_node_id.into_rust(), unsafe { &*msg.inner })
}
extern "C" fn ErroringMessageHandler_ChannelMessageHandler_handle_update_fail_malformed_htlc(this_arg: *const c_void, mut their_node_id: crate::c_types::PublicKey, msg: &crate::ln::msgs::UpdateFailMalformedHTLC) {
	<nativeErroringMessageHandler as lightning::ln::msgs::ChannelMessageHandler<>>::handle_update_fail_malformed_htlc(unsafe { &mut *(this_arg as *mut nativeErroringMessageHandler) }, &their_node_id.into_rust(), unsafe { &*msg.inner })
}
extern "C" fn ErroringMessageHandler_ChannelMessageHandler_handle_commitment_signed(this_arg: *const c_void, mut their_node_id: crate::c_types::PublicKey, msg: &crate::ln::msgs::CommitmentSigned) {
	<nativeErroringMessageHandler as lightning::ln::msgs::ChannelMessageHandler<>>::handle_commitment_signed(unsafe { &mut *(this_arg as *mut nativeErroringMessageHandler) }, &their_node_id.into_rust(), unsafe { &*msg.inner })
}
extern "C" fn ErroringMessageHandler_ChannelMessageHandler_handle_revoke_and_ack(this_arg: *const c_void, mut their_node_id: crate::c_types::PublicKey, msg: &crate::ln::msgs::RevokeAndACK) {
	<nativeErroringMessageHandler as lightning::ln::msgs::ChannelMessageHandler<>>::handle_revoke_and_ack(unsafe { &mut *(this_arg as *mut nativeErroringMessageHandler) }, &their_node_id.into_rust(), unsafe { &*msg.inner })
}
extern "C" fn ErroringMessageHandler_ChannelMessageHandler_handle_update_fee(this_arg: *const c_void, mut their_node_id: crate::c_types::PublicKey, msg: &crate::ln::msgs::UpdateFee) {
	<nativeErroringMessageHandler as lightning::ln::msgs::ChannelMessageHandler<>>::handle_update_fee(unsafe { &mut *(this_arg as *mut nativeErroringMessageHandler) }, &their_node_id.into_rust(), unsafe { &*msg.inner })
}
extern "C" fn ErroringMessageHandler_ChannelMessageHandler_handle_announcement_signatures(this_arg: *const c_void, mut their_node_id: crate::c_types::PublicKey, msg: &crate::ln::msgs::AnnouncementSignatures) {
	<nativeErroringMessageHandler as lightning::ln::msgs::ChannelMessageHandler<>>::handle_announcement_signatures(unsafe { &mut *(this_arg as *mut nativeErroringMessageHandler) }, &their_node_id.into_rust(), unsafe { &*msg.inner })
}
extern "C" fn ErroringMessageHandler_ChannelMessageHandler_handle_channel_reestablish(this_arg: *const c_void, mut their_node_id: crate::c_types::PublicKey, msg: &crate::ln::msgs::ChannelReestablish) {
	<nativeErroringMessageHandler as lightning::ln::msgs::ChannelMessageHandler<>>::handle_channel_reestablish(unsafe { &mut *(this_arg as *mut nativeErroringMessageHandler) }, &their_node_id.into_rust(), unsafe { &*msg.inner })
}
extern "C" fn ErroringMessageHandler_ChannelMessageHandler_peer_disconnected(this_arg: *const c_void, mut _their_node_id: crate::c_types::PublicKey, mut _no_connection_possible: bool) {
	<nativeErroringMessageHandler as lightning::ln::msgs::ChannelMessageHandler<>>::peer_disconnected(unsafe { &mut *(this_arg as *mut nativeErroringMessageHandler) }, &_their_node_id.into_rust(), _no_connection_possible)
}
extern "C" fn ErroringMessageHandler_ChannelMessageHandler_peer_connected(this_arg: *const c_void, mut _their_node_id: crate::c_types::PublicKey, _msg: &crate::ln::msgs::Init) {
	<nativeErroringMessageHandler as lightning::ln::msgs::ChannelMessageHandler<>>::peer_connected(unsafe { &mut *(this_arg as *mut nativeErroringMessageHandler) }, &_their_node_id.into_rust(), unsafe { &*_msg.inner })
}
extern "C" fn ErroringMessageHandler_ChannelMessageHandler_handle_error(this_arg: *const c_void, mut _their_node_id: crate::c_types::PublicKey, _msg: &crate::ln::msgs::ErrorMessage) {
	<nativeErroringMessageHandler as lightning::ln::msgs::ChannelMessageHandler<>>::handle_error(unsafe { &mut *(this_arg as *mut nativeErroringMessageHandler) }, &_their_node_id.into_rust(), unsafe { &*_msg.inner })
}
#[must_use]
extern "C" fn ErroringMessageHandler_ChannelMessageHandler_get_and_clear_pending_msg_events(this_arg: *const c_void) -> crate::c_types::derived::CVec_MessageSendEventZ {
	let mut ret = <nativeErroringMessageHandler as lightning::util::events::MessageSendEventsProvider<>>::get_and_clear_pending_msg_events(unsafe { &mut *(this_arg as *mut nativeErroringMessageHandler) }, );
	let mut local_ret = Vec::new(); for mut item in ret.drain(..) { local_ret.push( { crate::util::events::MessageSendEvent::native_into(item) }); };
	local_ret.into()
}


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
		if self.is_owned && !<*mut nativeMessageHandler>::is_null(self.inner) {
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
/// ChannelManager object or a ErroringMessageHandler.
#[no_mangle]
pub extern "C" fn MessageHandler_get_chan_handler(this_ptr: &MessageHandler) -> *const crate::ln::msgs::ChannelMessageHandler {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.chan_handler;
	&(*inner_val)
}
/// A message handler which handles messages specific to channels. Usually this is just a
/// ChannelManager object or a ErroringMessageHandler.
#[no_mangle]
pub extern "C" fn MessageHandler_set_chan_handler(this_ptr: &mut MessageHandler, mut val: crate::ln::msgs::ChannelMessageHandler) {
	unsafe { &mut *this_ptr.inner }.chan_handler = val;
}
/// A message handler which handles messages updating our knowledge of the network channel
/// graph. Usually this is just a NetGraphMsgHandlerMonitor object or an IgnoringMessageHandler.
#[no_mangle]
pub extern "C" fn MessageHandler_get_route_handler(this_ptr: &MessageHandler) -> *const crate::ln::msgs::RoutingMessageHandler {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.route_handler;
	&(*inner_val)
}
/// A message handler which handles messages updating our knowledge of the network channel
/// graph. Usually this is just a NetGraphMsgHandlerMonitor object or an IgnoringMessageHandler.
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
		if self.is_owned && !<*mut nativePeerHandleError>::is_null(self.inner) {
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
			inner: if <*mut nativePeerHandleError>::is_null(self.inner) { std::ptr::null_mut() } else {
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
		if self.is_owned && !<*mut nativePeerManager>::is_null(self.inner) {
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
	let mut local_ret = Vec::new(); for mut item in ret.drain(..) { local_ret.push( { crate::c_types::PublicKey::from_rust(&item) }); };
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
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { let mut local_ret_0 = Vec::new(); for mut item in o.drain(..) { local_ret_0.push( { item }); }; local_ret_0.into() }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::ln::peer_handler::PeerHandleError { inner: Box::into_raw(Box::new(e)), is_owned: true } }).into() };
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

