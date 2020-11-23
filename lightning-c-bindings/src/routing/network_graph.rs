//! The top-level network map tracking logic lives here.

use std::ffi::c_void;
use bitcoin::hashes::Hash;
use crate::c_types::*;


use lightning::routing::network_graph::NetworkGraph as nativeNetworkGraphImport;
type nativeNetworkGraph = nativeNetworkGraphImport;

/// Represents the network as nodes and channels between them
#[must_use]
#[repr(C)]
pub struct NetworkGraph {
	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeNetworkGraph,
	pub is_owned: bool,
}

impl Drop for NetworkGraph {
	fn drop(&mut self) {
		if self.is_owned && !self.inner.is_null() {
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
#[no_mangle]
pub extern "C" fn NetworkGraph_free(this_ptr: NetworkGraph) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn NetworkGraph_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeNetworkGraph); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl NetworkGraph {
	pub(crate) fn take_ptr(mut self) -> *mut nativeNetworkGraph {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}

use lightning::routing::network_graph::LockedNetworkGraph as nativeLockedNetworkGraphImport;
type nativeLockedNetworkGraph = nativeLockedNetworkGraphImport<'static>;

/// A simple newtype for RwLockReadGuard<'a, NetworkGraph>.
/// This exists only to make accessing a RwLock<NetworkGraph> possible from
/// the C bindings, as it can be done directly in Rust code.
#[must_use]
#[repr(C)]
pub struct LockedNetworkGraph {
	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeLockedNetworkGraph,
	pub is_owned: bool,
}

impl Drop for LockedNetworkGraph {
	fn drop(&mut self) {
		if self.is_owned && !self.inner.is_null() {
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
#[no_mangle]
pub extern "C" fn LockedNetworkGraph_free(this_ptr: LockedNetworkGraph) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn LockedNetworkGraph_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeLockedNetworkGraph); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl LockedNetworkGraph {
	pub(crate) fn take_ptr(mut self) -> *mut nativeLockedNetworkGraph {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}

use lightning::routing::network_graph::NetGraphMsgHandler as nativeNetGraphMsgHandlerImport;
type nativeNetGraphMsgHandler = nativeNetGraphMsgHandlerImport<crate::chain::Access, crate::util::logger::Logger>;

/// Receives and validates network updates from peers,
/// stores authentic and relevant data as a network graph.
/// This network graph is then used for routing payments.
/// Provides interface to help with initial routing sync by
/// serving historical announcements.
#[must_use]
#[repr(C)]
pub struct NetGraphMsgHandler {
	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeNetGraphMsgHandler,
	pub is_owned: bool,
}

impl Drop for NetGraphMsgHandler {
	fn drop(&mut self) {
		if self.is_owned && !self.inner.is_null() {
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
#[no_mangle]
pub extern "C" fn NetGraphMsgHandler_free(this_ptr: NetGraphMsgHandler) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn NetGraphMsgHandler_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeNetGraphMsgHandler); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl NetGraphMsgHandler {
	pub(crate) fn take_ptr(mut self) -> *mut nativeNetGraphMsgHandler {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}
/// Creates a new tracker of the actual state of the network of channels and nodes,
/// assuming a fresh network graph.
/// Chain monitor is used to make sure announced channels exist on-chain,
/// channel data is correct, and that the announcement is signed with
/// channel owners' keys.
#[must_use]
#[no_mangle]
pub extern "C" fn NetGraphMsgHandler_new(chain_access: *mut crate::chain::Access, mut logger: crate::util::logger::Logger) -> NetGraphMsgHandler {
	let mut local_chain_access = if chain_access == std::ptr::null_mut() { None } else { Some( { unsafe { *Box::from_raw(chain_access) } }) };
	let mut ret = lightning::routing::network_graph::NetGraphMsgHandler::new(local_chain_access, logger);
	NetGraphMsgHandler { inner: Box::into_raw(Box::new(ret)), is_owned: true }
}

/// Creates a new tracker of the actual state of the network of channels and nodes,
/// assuming an existing Network Graph.
#[must_use]
#[no_mangle]
pub extern "C" fn NetGraphMsgHandler_from_net_graph(chain_access: *mut crate::chain::Access, mut logger: crate::util::logger::Logger, mut network_graph: crate::routing::network_graph::NetworkGraph) -> NetGraphMsgHandler {
	let mut local_chain_access = if chain_access == std::ptr::null_mut() { None } else { Some( { unsafe { *Box::from_raw(chain_access) } }) };
	let mut ret = lightning::routing::network_graph::NetGraphMsgHandler::from_net_graph(local_chain_access, logger, *unsafe { Box::from_raw(network_graph.take_ptr()) });
	NetGraphMsgHandler { inner: Box::into_raw(Box::new(ret)), is_owned: true }
}

/// Take a read lock on the network_graph and return it in the C-bindings
/// newtype helper. This is likely only useful when called via the C
/// bindings as you can call `self.network_graph.read().unwrap()` in Rust
/// yourself.
#[must_use]
#[no_mangle]
pub extern "C" fn NetGraphMsgHandler_read_locked_graph(this_arg: &NetGraphMsgHandler) -> crate::routing::network_graph::LockedNetworkGraph {
	let mut ret = unsafe { &*this_arg.inner }.read_locked_graph();
	crate::routing::network_graph::LockedNetworkGraph { inner: Box::into_raw(Box::new(ret)), is_owned: true }
}

/// Get a reference to the NetworkGraph which this read-lock contains.
#[must_use]
#[no_mangle]
pub extern "C" fn LockedNetworkGraph_graph(this_arg: &LockedNetworkGraph) -> crate::routing::network_graph::NetworkGraph {
	let mut ret = unsafe { &*this_arg.inner }.graph();
	crate::routing::network_graph::NetworkGraph { inner: unsafe { ( (&(*ret) as *const _) as *mut _) }, is_owned: false }
}

#[no_mangle]
pub extern "C" fn NetGraphMsgHandler_as_RoutingMessageHandler(this_arg: *const NetGraphMsgHandler) -> crate::ln::msgs::RoutingMessageHandler {
	crate::ln::msgs::RoutingMessageHandler {
		this_arg: unsafe { (*this_arg).inner as *mut c_void },
		free: None,
		handle_node_announcement: NetGraphMsgHandler_RoutingMessageHandler_handle_node_announcement,
		handle_channel_announcement: NetGraphMsgHandler_RoutingMessageHandler_handle_channel_announcement,
		handle_channel_update: NetGraphMsgHandler_RoutingMessageHandler_handle_channel_update,
		handle_htlc_fail_channel_update: NetGraphMsgHandler_RoutingMessageHandler_handle_htlc_fail_channel_update,
		get_next_channel_announcements: NetGraphMsgHandler_RoutingMessageHandler_get_next_channel_announcements,
		get_next_node_announcements: NetGraphMsgHandler_RoutingMessageHandler_get_next_node_announcements,
		should_request_full_sync: NetGraphMsgHandler_RoutingMessageHandler_should_request_full_sync,
	}
}
use lightning::ln::msgs::RoutingMessageHandler as RoutingMessageHandlerTraitImport;
#[must_use]
extern "C" fn NetGraphMsgHandler_RoutingMessageHandler_handle_node_announcement(this_arg: *const c_void, msg: &crate::ln::msgs::NodeAnnouncement) -> crate::c_types::derived::CResult_boolLightningErrorZ {
	let mut ret = unsafe { &mut *(this_arg as *mut nativeNetGraphMsgHandler) }.handle_node_announcement(unsafe { &*msg.inner });
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { o }), Err(mut e) => crate::c_types::CResultTempl::err( { crate::ln::msgs::LightningError { inner: Box::into_raw(Box::new(e)), is_owned: true } }) };
	local_ret
}
#[must_use]
extern "C" fn NetGraphMsgHandler_RoutingMessageHandler_handle_channel_announcement(this_arg: *const c_void, msg: &crate::ln::msgs::ChannelAnnouncement) -> crate::c_types::derived::CResult_boolLightningErrorZ {
	let mut ret = unsafe { &mut *(this_arg as *mut nativeNetGraphMsgHandler) }.handle_channel_announcement(unsafe { &*msg.inner });
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { o }), Err(mut e) => crate::c_types::CResultTempl::err( { crate::ln::msgs::LightningError { inner: Box::into_raw(Box::new(e)), is_owned: true } }) };
	local_ret
}
extern "C" fn NetGraphMsgHandler_RoutingMessageHandler_handle_htlc_fail_channel_update(this_arg: *const c_void, update: &crate::ln::msgs::HTLCFailChannelUpdate) {
	unsafe { &mut *(this_arg as *mut nativeNetGraphMsgHandler) }.handle_htlc_fail_channel_update(&update.to_native())
}
#[must_use]
extern "C" fn NetGraphMsgHandler_RoutingMessageHandler_handle_channel_update(this_arg: *const c_void, msg: &crate::ln::msgs::ChannelUpdate) -> crate::c_types::derived::CResult_boolLightningErrorZ {
	let mut ret = unsafe { &mut *(this_arg as *mut nativeNetGraphMsgHandler) }.handle_channel_update(unsafe { &*msg.inner });
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { o }), Err(mut e) => crate::c_types::CResultTempl::err( { crate::ln::msgs::LightningError { inner: Box::into_raw(Box::new(e)), is_owned: true } }) };
	local_ret
}
#[must_use]
extern "C" fn NetGraphMsgHandler_RoutingMessageHandler_get_next_channel_announcements(this_arg: *const c_void, mut starting_point: u64, mut batch_amount: u8) -> crate::c_types::derived::CVec_C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZZ {
	let mut ret = unsafe { &mut *(this_arg as *mut nativeNetGraphMsgHandler) }.get_next_channel_announcements(starting_point, batch_amount);
	let mut local_ret = Vec::new(); for item in ret.drain(..) { local_ret.push( { let (mut orig_ret_0_0, mut orig_ret_0_1, mut orig_ret_0_2) = item; let mut local_orig_ret_0_1 = crate::ln::msgs::ChannelUpdate { inner: if orig_ret_0_1.is_none() { std::ptr::null_mut() } else {  { Box::into_raw(Box::new((orig_ret_0_1.unwrap()))) } }, is_owned: true }; let mut local_orig_ret_0_2 = crate::ln::msgs::ChannelUpdate { inner: if orig_ret_0_2.is_none() { std::ptr::null_mut() } else {  { Box::into_raw(Box::new((orig_ret_0_2.unwrap()))) } }, is_owned: true }; let mut local_ret_0 = (crate::ln::msgs::ChannelAnnouncement { inner: Box::into_raw(Box::new(orig_ret_0_0)), is_owned: true }, local_orig_ret_0_1, local_orig_ret_0_2).into(); local_ret_0 }); };
	local_ret.into()
}
#[must_use]
extern "C" fn NetGraphMsgHandler_RoutingMessageHandler_get_next_node_announcements(this_arg: *const c_void, mut starting_point: crate::c_types::PublicKey, mut batch_amount: u8) -> crate::c_types::derived::CVec_NodeAnnouncementZ {
	let mut local_starting_point_base = if starting_point.is_null() { None } else { Some( { starting_point.into_rust() }) }; let mut local_starting_point = local_starting_point_base.as_ref();
	let mut ret = unsafe { &mut *(this_arg as *mut nativeNetGraphMsgHandler) }.get_next_node_announcements(local_starting_point, batch_amount);
	let mut local_ret = Vec::new(); for item in ret.drain(..) { local_ret.push( { crate::ln::msgs::NodeAnnouncement { inner: Box::into_raw(Box::new(item)), is_owned: true } }); };
	local_ret.into()
}
#[must_use]
extern "C" fn NetGraphMsgHandler_RoutingMessageHandler_should_request_full_sync(this_arg: *const c_void, mut _node_id: crate::c_types::PublicKey) -> bool {
	let mut ret = unsafe { &mut *(this_arg as *mut nativeNetGraphMsgHandler) }.should_request_full_sync(&_node_id.into_rust());
	ret
}


use lightning::routing::network_graph::DirectionalChannelInfo as nativeDirectionalChannelInfoImport;
type nativeDirectionalChannelInfo = nativeDirectionalChannelInfoImport;

/// Details about one direction of a channel. Received
/// within a channel update.
#[must_use]
#[repr(C)]
pub struct DirectionalChannelInfo {
	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeDirectionalChannelInfo,
	pub is_owned: bool,
}

impl Drop for DirectionalChannelInfo {
	fn drop(&mut self) {
		if self.is_owned && !self.inner.is_null() {
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
#[no_mangle]
pub extern "C" fn DirectionalChannelInfo_free(this_ptr: DirectionalChannelInfo) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn DirectionalChannelInfo_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeDirectionalChannelInfo); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl DirectionalChannelInfo {
	pub(crate) fn take_ptr(mut self) -> *mut nativeDirectionalChannelInfo {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}
/// When the last update to the channel direction was issued.
/// Value is opaque, as set in the announcement.
#[no_mangle]
pub extern "C" fn DirectionalChannelInfo_get_last_update(this_ptr: &DirectionalChannelInfo) -> u32 {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.last_update;
	(*inner_val)
}
/// When the last update to the channel direction was issued.
/// Value is opaque, as set in the announcement.
#[no_mangle]
pub extern "C" fn DirectionalChannelInfo_set_last_update(this_ptr: &mut DirectionalChannelInfo, mut val: u32) {
	unsafe { &mut *this_ptr.inner }.last_update = val;
}
/// Whether the channel can be currently used for payments (in this one direction).
#[no_mangle]
pub extern "C" fn DirectionalChannelInfo_get_enabled(this_ptr: &DirectionalChannelInfo) -> bool {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.enabled;
	(*inner_val)
}
/// Whether the channel can be currently used for payments (in this one direction).
#[no_mangle]
pub extern "C" fn DirectionalChannelInfo_set_enabled(this_ptr: &mut DirectionalChannelInfo, mut val: bool) {
	unsafe { &mut *this_ptr.inner }.enabled = val;
}
/// The difference in CLTV values that you must have when routing through this channel.
#[no_mangle]
pub extern "C" fn DirectionalChannelInfo_get_cltv_expiry_delta(this_ptr: &DirectionalChannelInfo) -> u16 {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.cltv_expiry_delta;
	(*inner_val)
}
/// The difference in CLTV values that you must have when routing through this channel.
#[no_mangle]
pub extern "C" fn DirectionalChannelInfo_set_cltv_expiry_delta(this_ptr: &mut DirectionalChannelInfo, mut val: u16) {
	unsafe { &mut *this_ptr.inner }.cltv_expiry_delta = val;
}
/// The minimum value, which must be relayed to the next hop via the channel
#[no_mangle]
pub extern "C" fn DirectionalChannelInfo_get_htlc_minimum_msat(this_ptr: &DirectionalChannelInfo) -> u64 {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.htlc_minimum_msat;
	(*inner_val)
}
/// The minimum value, which must be relayed to the next hop via the channel
#[no_mangle]
pub extern "C" fn DirectionalChannelInfo_set_htlc_minimum_msat(this_ptr: &mut DirectionalChannelInfo, mut val: u64) {
	unsafe { &mut *this_ptr.inner }.htlc_minimum_msat = val;
}
/// Most recent update for the channel received from the network
/// Mostly redundant with the data we store in fields explicitly.
/// Everything else is useful only for sending out for initial routing sync.
/// Not stored if contains excess data to prevent DoS.
#[no_mangle]
pub extern "C" fn DirectionalChannelInfo_get_last_update_message(this_ptr: &DirectionalChannelInfo) -> crate::ln::msgs::ChannelUpdate {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.last_update_message;
	let mut local_inner_val = crate::ln::msgs::ChannelUpdate { inner: unsafe { (if inner_val.is_none() { std::ptr::null() } else {  { (inner_val.as_ref().unwrap()) } } as *const _) as *mut _ }, is_owned: false };
	local_inner_val
}
/// Most recent update for the channel received from the network
/// Mostly redundant with the data we store in fields explicitly.
/// Everything else is useful only for sending out for initial routing sync.
/// Not stored if contains excess data to prevent DoS.
#[no_mangle]
pub extern "C" fn DirectionalChannelInfo_set_last_update_message(this_ptr: &mut DirectionalChannelInfo, mut val: crate::ln::msgs::ChannelUpdate) {
	let mut local_val = if val.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(val.take_ptr()) } }) };
	unsafe { &mut *this_ptr.inner }.last_update_message = local_val;
}
#[no_mangle]
pub extern "C" fn DirectionalChannelInfo_write(obj: *const DirectionalChannelInfo) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &(*(*obj).inner) })
}
#[no_mangle]
pub extern "C" fn DirectionalChannelInfo_read(ser: crate::c_types::u8slice) -> DirectionalChannelInfo {
	if let Ok(res) = crate::c_types::deserialize_obj(ser) {
		DirectionalChannelInfo { inner: Box::into_raw(Box::new(res)), is_owned: true }
	} else {
		DirectionalChannelInfo { inner: std::ptr::null_mut(), is_owned: true }
	}
}

use lightning::routing::network_graph::ChannelInfo as nativeChannelInfoImport;
type nativeChannelInfo = nativeChannelInfoImport;

/// Details about a channel (both directions).
/// Received within a channel announcement.
#[must_use]
#[repr(C)]
pub struct ChannelInfo {
	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeChannelInfo,
	pub is_owned: bool,
}

impl Drop for ChannelInfo {
	fn drop(&mut self) {
		if self.is_owned && !self.inner.is_null() {
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
#[no_mangle]
pub extern "C" fn ChannelInfo_free(this_ptr: ChannelInfo) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn ChannelInfo_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeChannelInfo); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl ChannelInfo {
	pub(crate) fn take_ptr(mut self) -> *mut nativeChannelInfo {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}
/// Protocol features of a channel communicated during its announcement
#[no_mangle]
pub extern "C" fn ChannelInfo_get_features(this_ptr: &ChannelInfo) -> crate::ln::features::ChannelFeatures {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.features;
	crate::ln::features::ChannelFeatures { inner: unsafe { ( (&((*inner_val)) as *const _) as *mut _) }, is_owned: false }
}
/// Protocol features of a channel communicated during its announcement
#[no_mangle]
pub extern "C" fn ChannelInfo_set_features(this_ptr: &mut ChannelInfo, mut val: crate::ln::features::ChannelFeatures) {
	unsafe { &mut *this_ptr.inner }.features = *unsafe { Box::from_raw(val.take_ptr()) };
}
/// Source node of the first direction of a channel
#[no_mangle]
pub extern "C" fn ChannelInfo_get_node_one(this_ptr: &ChannelInfo) -> crate::c_types::PublicKey {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.node_one;
	crate::c_types::PublicKey::from_rust(&(*inner_val))
}
/// Source node of the first direction of a channel
#[no_mangle]
pub extern "C" fn ChannelInfo_set_node_one(this_ptr: &mut ChannelInfo, mut val: crate::c_types::PublicKey) {
	unsafe { &mut *this_ptr.inner }.node_one = val.into_rust();
}
/// Details about the first direction of a channel
#[no_mangle]
pub extern "C" fn ChannelInfo_get_one_to_two(this_ptr: &ChannelInfo) -> crate::routing::network_graph::DirectionalChannelInfo {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.one_to_two;
	let mut local_inner_val = crate::routing::network_graph::DirectionalChannelInfo { inner: unsafe { (if inner_val.is_none() { std::ptr::null() } else {  { (inner_val.as_ref().unwrap()) } } as *const _) as *mut _ }, is_owned: false };
	local_inner_val
}
/// Details about the first direction of a channel
#[no_mangle]
pub extern "C" fn ChannelInfo_set_one_to_two(this_ptr: &mut ChannelInfo, mut val: crate::routing::network_graph::DirectionalChannelInfo) {
	let mut local_val = if val.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(val.take_ptr()) } }) };
	unsafe { &mut *this_ptr.inner }.one_to_two = local_val;
}
/// Source node of the second direction of a channel
#[no_mangle]
pub extern "C" fn ChannelInfo_get_node_two(this_ptr: &ChannelInfo) -> crate::c_types::PublicKey {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.node_two;
	crate::c_types::PublicKey::from_rust(&(*inner_val))
}
/// Source node of the second direction of a channel
#[no_mangle]
pub extern "C" fn ChannelInfo_set_node_two(this_ptr: &mut ChannelInfo, mut val: crate::c_types::PublicKey) {
	unsafe { &mut *this_ptr.inner }.node_two = val.into_rust();
}
/// Details about the second direction of a channel
#[no_mangle]
pub extern "C" fn ChannelInfo_get_two_to_one(this_ptr: &ChannelInfo) -> crate::routing::network_graph::DirectionalChannelInfo {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.two_to_one;
	let mut local_inner_val = crate::routing::network_graph::DirectionalChannelInfo { inner: unsafe { (if inner_val.is_none() { std::ptr::null() } else {  { (inner_val.as_ref().unwrap()) } } as *const _) as *mut _ }, is_owned: false };
	local_inner_val
}
/// Details about the second direction of a channel
#[no_mangle]
pub extern "C" fn ChannelInfo_set_two_to_one(this_ptr: &mut ChannelInfo, mut val: crate::routing::network_graph::DirectionalChannelInfo) {
	let mut local_val = if val.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(val.take_ptr()) } }) };
	unsafe { &mut *this_ptr.inner }.two_to_one = local_val;
}
/// An initial announcement of the channel
/// Mostly redundant with the data we store in fields explicitly.
/// Everything else is useful only for sending out for initial routing sync.
/// Not stored if contains excess data to prevent DoS.
#[no_mangle]
pub extern "C" fn ChannelInfo_get_announcement_message(this_ptr: &ChannelInfo) -> crate::ln::msgs::ChannelAnnouncement {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.announcement_message;
	let mut local_inner_val = crate::ln::msgs::ChannelAnnouncement { inner: unsafe { (if inner_val.is_none() { std::ptr::null() } else {  { (inner_val.as_ref().unwrap()) } } as *const _) as *mut _ }, is_owned: false };
	local_inner_val
}
/// An initial announcement of the channel
/// Mostly redundant with the data we store in fields explicitly.
/// Everything else is useful only for sending out for initial routing sync.
/// Not stored if contains excess data to prevent DoS.
#[no_mangle]
pub extern "C" fn ChannelInfo_set_announcement_message(this_ptr: &mut ChannelInfo, mut val: crate::ln::msgs::ChannelAnnouncement) {
	let mut local_val = if val.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(val.take_ptr()) } }) };
	unsafe { &mut *this_ptr.inner }.announcement_message = local_val;
}
#[no_mangle]
pub extern "C" fn ChannelInfo_write(obj: *const ChannelInfo) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &(*(*obj).inner) })
}
#[no_mangle]
pub extern "C" fn ChannelInfo_read(ser: crate::c_types::u8slice) -> ChannelInfo {
	if let Ok(res) = crate::c_types::deserialize_obj(ser) {
		ChannelInfo { inner: Box::into_raw(Box::new(res)), is_owned: true }
	} else {
		ChannelInfo { inner: std::ptr::null_mut(), is_owned: true }
	}
}

use lightning::routing::network_graph::RoutingFees as nativeRoutingFeesImport;
type nativeRoutingFees = nativeRoutingFeesImport;

/// Fees for routing via a given channel or a node
#[must_use]
#[repr(C)]
pub struct RoutingFees {
	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeRoutingFees,
	pub is_owned: bool,
}

impl Drop for RoutingFees {
	fn drop(&mut self) {
		if self.is_owned && !self.inner.is_null() {
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
#[no_mangle]
pub extern "C" fn RoutingFees_free(this_ptr: RoutingFees) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn RoutingFees_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeRoutingFees); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl RoutingFees {
	pub(crate) fn take_ptr(mut self) -> *mut nativeRoutingFees {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}
impl Clone for RoutingFees {
	fn clone(&self) -> Self {
		Self {
			inner: Box::into_raw(Box::new(unsafe { &*self.inner }.clone())),
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn RoutingFees_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeRoutingFees)).clone() })) as *mut c_void
}
#[no_mangle]
pub extern "C" fn RoutingFees_clone(orig: &RoutingFees) -> RoutingFees {
	RoutingFees { inner: Box::into_raw(Box::new(unsafe { &*orig.inner }.clone())), is_owned: true }
}
/// Flat routing fee in satoshis
#[no_mangle]
pub extern "C" fn RoutingFees_get_base_msat(this_ptr: &RoutingFees) -> u32 {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.base_msat;
	(*inner_val)
}
/// Flat routing fee in satoshis
#[no_mangle]
pub extern "C" fn RoutingFees_set_base_msat(this_ptr: &mut RoutingFees, mut val: u32) {
	unsafe { &mut *this_ptr.inner }.base_msat = val;
}
/// Liquidity-based routing fee in millionths of a routed amount.
/// In other words, 10000 is 1%.
#[no_mangle]
pub extern "C" fn RoutingFees_get_proportional_millionths(this_ptr: &RoutingFees) -> u32 {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.proportional_millionths;
	(*inner_val)
}
/// Liquidity-based routing fee in millionths of a routed amount.
/// In other words, 10000 is 1%.
#[no_mangle]
pub extern "C" fn RoutingFees_set_proportional_millionths(this_ptr: &mut RoutingFees, mut val: u32) {
	unsafe { &mut *this_ptr.inner }.proportional_millionths = val;
}
#[must_use]
#[no_mangle]
pub extern "C" fn RoutingFees_new(mut base_msat_arg: u32, mut proportional_millionths_arg: u32) -> RoutingFees {
	RoutingFees { inner: Box::into_raw(Box::new(nativeRoutingFees {
		base_msat: base_msat_arg,
		proportional_millionths: proportional_millionths_arg,
	})), is_owned: true }
}
#[no_mangle]
pub extern "C" fn RoutingFees_read(ser: crate::c_types::u8slice) -> RoutingFees {
	if let Ok(res) = crate::c_types::deserialize_obj(ser) {
		RoutingFees { inner: Box::into_raw(Box::new(res)), is_owned: true }
	} else {
		RoutingFees { inner: std::ptr::null_mut(), is_owned: true }
	}
}
#[no_mangle]
pub extern "C" fn RoutingFees_write(obj: *const RoutingFees) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &(*(*obj).inner) })
}

use lightning::routing::network_graph::NodeAnnouncementInfo as nativeNodeAnnouncementInfoImport;
type nativeNodeAnnouncementInfo = nativeNodeAnnouncementInfoImport;

/// Information received in the latest node_announcement from this node.
#[must_use]
#[repr(C)]
pub struct NodeAnnouncementInfo {
	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeNodeAnnouncementInfo,
	pub is_owned: bool,
}

impl Drop for NodeAnnouncementInfo {
	fn drop(&mut self) {
		if self.is_owned && !self.inner.is_null() {
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
#[no_mangle]
pub extern "C" fn NodeAnnouncementInfo_free(this_ptr: NodeAnnouncementInfo) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn NodeAnnouncementInfo_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeNodeAnnouncementInfo); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl NodeAnnouncementInfo {
	pub(crate) fn take_ptr(mut self) -> *mut nativeNodeAnnouncementInfo {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}
/// Protocol features the node announced support for
#[no_mangle]
pub extern "C" fn NodeAnnouncementInfo_get_features(this_ptr: &NodeAnnouncementInfo) -> crate::ln::features::NodeFeatures {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.features;
	crate::ln::features::NodeFeatures { inner: unsafe { ( (&((*inner_val)) as *const _) as *mut _) }, is_owned: false }
}
/// Protocol features the node announced support for
#[no_mangle]
pub extern "C" fn NodeAnnouncementInfo_set_features(this_ptr: &mut NodeAnnouncementInfo, mut val: crate::ln::features::NodeFeatures) {
	unsafe { &mut *this_ptr.inner }.features = *unsafe { Box::from_raw(val.take_ptr()) };
}
/// When the last known update to the node state was issued.
/// Value is opaque, as set in the announcement.
#[no_mangle]
pub extern "C" fn NodeAnnouncementInfo_get_last_update(this_ptr: &NodeAnnouncementInfo) -> u32 {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.last_update;
	(*inner_val)
}
/// When the last known update to the node state was issued.
/// Value is opaque, as set in the announcement.
#[no_mangle]
pub extern "C" fn NodeAnnouncementInfo_set_last_update(this_ptr: &mut NodeAnnouncementInfo, mut val: u32) {
	unsafe { &mut *this_ptr.inner }.last_update = val;
}
/// Color assigned to the node
#[no_mangle]
pub extern "C" fn NodeAnnouncementInfo_get_rgb(this_ptr: &NodeAnnouncementInfo) -> *const [u8; 3] {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.rgb;
	&(*inner_val)
}
/// Color assigned to the node
#[no_mangle]
pub extern "C" fn NodeAnnouncementInfo_set_rgb(this_ptr: &mut NodeAnnouncementInfo, mut val: crate::c_types::ThreeBytes) {
	unsafe { &mut *this_ptr.inner }.rgb = val.data;
}
/// Moniker assigned to the node.
/// May be invalid or malicious (eg control chars),
/// should not be exposed to the user.
#[no_mangle]
pub extern "C" fn NodeAnnouncementInfo_get_alias(this_ptr: &NodeAnnouncementInfo) -> *const [u8; 32] {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.alias;
	&(*inner_val)
}
/// Moniker assigned to the node.
/// May be invalid or malicious (eg control chars),
/// should not be exposed to the user.
#[no_mangle]
pub extern "C" fn NodeAnnouncementInfo_set_alias(this_ptr: &mut NodeAnnouncementInfo, mut val: crate::c_types::ThirtyTwoBytes) {
	unsafe { &mut *this_ptr.inner }.alias = val.data;
}
/// Internet-level addresses via which one can connect to the node
#[no_mangle]
pub extern "C" fn NodeAnnouncementInfo_set_addresses(this_ptr: &mut NodeAnnouncementInfo, mut val: crate::c_types::derived::CVec_NetAddressZ) {
	let mut local_val = Vec::new(); for mut item in val.into_rust().drain(..) { local_val.push( { item.into_native() }); };
	unsafe { &mut *this_ptr.inner }.addresses = local_val;
}
/// An initial announcement of the node
/// Mostly redundant with the data we store in fields explicitly.
/// Everything else is useful only for sending out for initial routing sync.
/// Not stored if contains excess data to prevent DoS.
#[no_mangle]
pub extern "C" fn NodeAnnouncementInfo_get_announcement_message(this_ptr: &NodeAnnouncementInfo) -> crate::ln::msgs::NodeAnnouncement {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.announcement_message;
	let mut local_inner_val = crate::ln::msgs::NodeAnnouncement { inner: unsafe { (if inner_val.is_none() { std::ptr::null() } else {  { (inner_val.as_ref().unwrap()) } } as *const _) as *mut _ }, is_owned: false };
	local_inner_val
}
/// An initial announcement of the node
/// Mostly redundant with the data we store in fields explicitly.
/// Everything else is useful only for sending out for initial routing sync.
/// Not stored if contains excess data to prevent DoS.
#[no_mangle]
pub extern "C" fn NodeAnnouncementInfo_set_announcement_message(this_ptr: &mut NodeAnnouncementInfo, mut val: crate::ln::msgs::NodeAnnouncement) {
	let mut local_val = if val.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(val.take_ptr()) } }) };
	unsafe { &mut *this_ptr.inner }.announcement_message = local_val;
}
#[must_use]
#[no_mangle]
pub extern "C" fn NodeAnnouncementInfo_new(mut features_arg: crate::ln::features::NodeFeatures, mut last_update_arg: u32, mut rgb_arg: crate::c_types::ThreeBytes, mut alias_arg: crate::c_types::ThirtyTwoBytes, mut addresses_arg: crate::c_types::derived::CVec_NetAddressZ, mut announcement_message_arg: crate::ln::msgs::NodeAnnouncement) -> NodeAnnouncementInfo {
	let mut local_addresses_arg = Vec::new(); for mut item in addresses_arg.into_rust().drain(..) { local_addresses_arg.push( { item.into_native() }); };
	let mut local_announcement_message_arg = if announcement_message_arg.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(announcement_message_arg.take_ptr()) } }) };
	NodeAnnouncementInfo { inner: Box::into_raw(Box::new(nativeNodeAnnouncementInfo {
		features: *unsafe { Box::from_raw(features_arg.take_ptr()) },
		last_update: last_update_arg,
		rgb: rgb_arg.data,
		alias: alias_arg.data,
		addresses: local_addresses_arg,
		announcement_message: local_announcement_message_arg,
	})), is_owned: true }
}
#[no_mangle]
pub extern "C" fn NodeAnnouncementInfo_write(obj: *const NodeAnnouncementInfo) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &(*(*obj).inner) })
}
#[no_mangle]
pub extern "C" fn NodeAnnouncementInfo_read(ser: crate::c_types::u8slice) -> NodeAnnouncementInfo {
	if let Ok(res) = crate::c_types::deserialize_obj(ser) {
		NodeAnnouncementInfo { inner: Box::into_raw(Box::new(res)), is_owned: true }
	} else {
		NodeAnnouncementInfo { inner: std::ptr::null_mut(), is_owned: true }
	}
}

use lightning::routing::network_graph::NodeInfo as nativeNodeInfoImport;
type nativeNodeInfo = nativeNodeInfoImport;

/// Details about a node in the network, known from the network announcement.
#[must_use]
#[repr(C)]
pub struct NodeInfo {
	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeNodeInfo,
	pub is_owned: bool,
}

impl Drop for NodeInfo {
	fn drop(&mut self) {
		if self.is_owned && !self.inner.is_null() {
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
#[no_mangle]
pub extern "C" fn NodeInfo_free(this_ptr: NodeInfo) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn NodeInfo_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeNodeInfo); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl NodeInfo {
	pub(crate) fn take_ptr(mut self) -> *mut nativeNodeInfo {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}
/// All valid channels a node has announced
#[no_mangle]
pub extern "C" fn NodeInfo_set_channels(this_ptr: &mut NodeInfo, mut val: crate::c_types::derived::CVec_u64Z) {
	let mut local_val = Vec::new(); for mut item in val.into_rust().drain(..) { local_val.push( { item }); };
	unsafe { &mut *this_ptr.inner }.channels = local_val;
}
/// Lowest fees enabling routing via any of the enabled, known channels to a node.
/// The two fields (flat and proportional fee) are independent,
/// meaning they don't have to refer to the same channel.
#[no_mangle]
pub extern "C" fn NodeInfo_get_lowest_inbound_channel_fees(this_ptr: &NodeInfo) -> crate::routing::network_graph::RoutingFees {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.lowest_inbound_channel_fees;
	let mut local_inner_val = crate::routing::network_graph::RoutingFees { inner: unsafe { (if inner_val.is_none() { std::ptr::null() } else {  { (inner_val.as_ref().unwrap()) } } as *const _) as *mut _ }, is_owned: false };
	local_inner_val
}
/// Lowest fees enabling routing via any of the enabled, known channels to a node.
/// The two fields (flat and proportional fee) are independent,
/// meaning they don't have to refer to the same channel.
#[no_mangle]
pub extern "C" fn NodeInfo_set_lowest_inbound_channel_fees(this_ptr: &mut NodeInfo, mut val: crate::routing::network_graph::RoutingFees) {
	let mut local_val = if val.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(val.take_ptr()) } }) };
	unsafe { &mut *this_ptr.inner }.lowest_inbound_channel_fees = local_val;
}
/// More information about a node from node_announcement.
/// Optional because we store a Node entry after learning about it from
/// a channel announcement, but before receiving a node announcement.
#[no_mangle]
pub extern "C" fn NodeInfo_get_announcement_info(this_ptr: &NodeInfo) -> crate::routing::network_graph::NodeAnnouncementInfo {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.announcement_info;
	let mut local_inner_val = crate::routing::network_graph::NodeAnnouncementInfo { inner: unsafe { (if inner_val.is_none() { std::ptr::null() } else {  { (inner_val.as_ref().unwrap()) } } as *const _) as *mut _ }, is_owned: false };
	local_inner_val
}
/// More information about a node from node_announcement.
/// Optional because we store a Node entry after learning about it from
/// a channel announcement, but before receiving a node announcement.
#[no_mangle]
pub extern "C" fn NodeInfo_set_announcement_info(this_ptr: &mut NodeInfo, mut val: crate::routing::network_graph::NodeAnnouncementInfo) {
	let mut local_val = if val.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(val.take_ptr()) } }) };
	unsafe { &mut *this_ptr.inner }.announcement_info = local_val;
}
#[must_use]
#[no_mangle]
pub extern "C" fn NodeInfo_new(mut channels_arg: crate::c_types::derived::CVec_u64Z, mut lowest_inbound_channel_fees_arg: crate::routing::network_graph::RoutingFees, mut announcement_info_arg: crate::routing::network_graph::NodeAnnouncementInfo) -> NodeInfo {
	let mut local_channels_arg = Vec::new(); for mut item in channels_arg.into_rust().drain(..) { local_channels_arg.push( { item }); };
	let mut local_lowest_inbound_channel_fees_arg = if lowest_inbound_channel_fees_arg.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(lowest_inbound_channel_fees_arg.take_ptr()) } }) };
	let mut local_announcement_info_arg = if announcement_info_arg.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(announcement_info_arg.take_ptr()) } }) };
	NodeInfo { inner: Box::into_raw(Box::new(nativeNodeInfo {
		channels: local_channels_arg,
		lowest_inbound_channel_fees: local_lowest_inbound_channel_fees_arg,
		announcement_info: local_announcement_info_arg,
	})), is_owned: true }
}
#[no_mangle]
pub extern "C" fn NodeInfo_write(obj: *const NodeInfo) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &(*(*obj).inner) })
}
#[no_mangle]
pub extern "C" fn NodeInfo_read(ser: crate::c_types::u8slice) -> NodeInfo {
	if let Ok(res) = crate::c_types::deserialize_obj(ser) {
		NodeInfo { inner: Box::into_raw(Box::new(res)), is_owned: true }
	} else {
		NodeInfo { inner: std::ptr::null_mut(), is_owned: true }
	}
}
#[no_mangle]
pub extern "C" fn NetworkGraph_write(obj: *const NetworkGraph) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &(*(*obj).inner) })
}
#[no_mangle]
pub extern "C" fn NetworkGraph_read(ser: crate::c_types::u8slice) -> NetworkGraph {
	if let Ok(res) = crate::c_types::deserialize_obj(ser) {
		NetworkGraph { inner: Box::into_raw(Box::new(res)), is_owned: true }
	} else {
		NetworkGraph { inner: std::ptr::null_mut(), is_owned: true }
	}
}
/// Creates a new, empty, network graph.
#[must_use]
#[no_mangle]
pub extern "C" fn NetworkGraph_new() -> crate::routing::network_graph::NetworkGraph {
	let mut ret = lightning::routing::network_graph::NetworkGraph::new();
	crate::routing::network_graph::NetworkGraph { inner: Box::into_raw(Box::new(ret)), is_owned: true }
}

/// Close a channel if a corresponding HTLC fail was sent.
/// If permanent, removes a channel from the local storage.
/// May cause the removal of nodes too, if this was their last channel.
/// If not permanent, makes channels unavailable for routing.
#[no_mangle]
pub extern "C" fn NetworkGraph_close_channel_from_update(this_arg: &mut NetworkGraph, mut short_channel_id: u64, mut is_permanent: bool) {
	unsafe { &mut (*(this_arg.inner as *mut nativeNetworkGraph)) }.close_channel_from_update(short_channel_id, is_permanent)
}

