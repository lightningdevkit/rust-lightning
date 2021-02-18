//! The top-level routing/network map tracking logic lives here.
//!
//! You probably want to create a NetGraphMsgHandler and use that as your RoutingMessageHandler and then
//! interrogate it to get routes for your own payments.

use std::ffi::c_void;
use bitcoin::hashes::Hash;
use crate::c_types::*;


use lightning::routing::router::RouteHop as nativeRouteHopImport;
type nativeRouteHop = nativeRouteHopImport;

/// A hop in a route
#[must_use]
#[repr(C)]
pub struct RouteHop {
	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeRouteHop,
	pub is_owned: bool,
}

impl Drop for RouteHop {
	fn drop(&mut self) {
		if self.is_owned && !self.inner.is_null() {
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
#[no_mangle]
pub extern "C" fn RouteHop_free(this_ptr: RouteHop) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn RouteHop_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeRouteHop); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl RouteHop {
	pub(crate) fn take_inner(mut self) -> *mut nativeRouteHop {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}
/// The node_id of the node at this hop.
#[no_mangle]
pub extern "C" fn RouteHop_get_pubkey(this_ptr: &RouteHop) -> crate::c_types::PublicKey {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.pubkey;
	crate::c_types::PublicKey::from_rust(&(*inner_val))
}
/// The node_id of the node at this hop.
#[no_mangle]
pub extern "C" fn RouteHop_set_pubkey(this_ptr: &mut RouteHop, mut val: crate::c_types::PublicKey) {
	unsafe { &mut *this_ptr.inner }.pubkey = val.into_rust();
}
/// The node_announcement features of the node at this hop. For the last hop, these may be
/// amended to match the features present in the invoice this node generated.
#[no_mangle]
pub extern "C" fn RouteHop_get_node_features(this_ptr: &RouteHop) -> crate::ln::features::NodeFeatures {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.node_features;
	crate::ln::features::NodeFeatures { inner: unsafe { ( (&((*inner_val)) as *const _) as *mut _) }, is_owned: false }
}
/// The node_announcement features of the node at this hop. For the last hop, these may be
/// amended to match the features present in the invoice this node generated.
#[no_mangle]
pub extern "C" fn RouteHop_set_node_features(this_ptr: &mut RouteHop, mut val: crate::ln::features::NodeFeatures) {
	unsafe { &mut *this_ptr.inner }.node_features = *unsafe { Box::from_raw(val.take_inner()) };
}
/// The channel that should be used from the previous hop to reach this node.
#[no_mangle]
pub extern "C" fn RouteHop_get_short_channel_id(this_ptr: &RouteHop) -> u64 {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.short_channel_id;
	(*inner_val)
}
/// The channel that should be used from the previous hop to reach this node.
#[no_mangle]
pub extern "C" fn RouteHop_set_short_channel_id(this_ptr: &mut RouteHop, mut val: u64) {
	unsafe { &mut *this_ptr.inner }.short_channel_id = val;
}
/// The channel_announcement features of the channel that should be used from the previous hop
/// to reach this node.
#[no_mangle]
pub extern "C" fn RouteHop_get_channel_features(this_ptr: &RouteHop) -> crate::ln::features::ChannelFeatures {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.channel_features;
	crate::ln::features::ChannelFeatures { inner: unsafe { ( (&((*inner_val)) as *const _) as *mut _) }, is_owned: false }
}
/// The channel_announcement features of the channel that should be used from the previous hop
/// to reach this node.
#[no_mangle]
pub extern "C" fn RouteHop_set_channel_features(this_ptr: &mut RouteHop, mut val: crate::ln::features::ChannelFeatures) {
	unsafe { &mut *this_ptr.inner }.channel_features = *unsafe { Box::from_raw(val.take_inner()) };
}
/// The fee taken on this hop. For the last hop, this should be the full value of the payment.
#[no_mangle]
pub extern "C" fn RouteHop_get_fee_msat(this_ptr: &RouteHop) -> u64 {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.fee_msat;
	(*inner_val)
}
/// The fee taken on this hop. For the last hop, this should be the full value of the payment.
#[no_mangle]
pub extern "C" fn RouteHop_set_fee_msat(this_ptr: &mut RouteHop, mut val: u64) {
	unsafe { &mut *this_ptr.inner }.fee_msat = val;
}
/// The CLTV delta added for this hop. For the last hop, this should be the full CLTV value
/// expected at the destination, in excess of the current block height.
#[no_mangle]
pub extern "C" fn RouteHop_get_cltv_expiry_delta(this_ptr: &RouteHop) -> u32 {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.cltv_expiry_delta;
	(*inner_val)
}
/// The CLTV delta added for this hop. For the last hop, this should be the full CLTV value
/// expected at the destination, in excess of the current block height.
#[no_mangle]
pub extern "C" fn RouteHop_set_cltv_expiry_delta(this_ptr: &mut RouteHop, mut val: u32) {
	unsafe { &mut *this_ptr.inner }.cltv_expiry_delta = val;
}
#[must_use]
#[no_mangle]
pub extern "C" fn RouteHop_new(mut pubkey_arg: crate::c_types::PublicKey, mut node_features_arg: crate::ln::features::NodeFeatures, mut short_channel_id_arg: u64, mut channel_features_arg: crate::ln::features::ChannelFeatures, mut fee_msat_arg: u64, mut cltv_expiry_delta_arg: u32) -> RouteHop {
	RouteHop { inner: Box::into_raw(Box::new(nativeRouteHop {
		pubkey: pubkey_arg.into_rust(),
		node_features: *unsafe { Box::from_raw(node_features_arg.take_inner()) },
		short_channel_id: short_channel_id_arg,
		channel_features: *unsafe { Box::from_raw(channel_features_arg.take_inner()) },
		fee_msat: fee_msat_arg,
		cltv_expiry_delta: cltv_expiry_delta_arg,
	})), is_owned: true }
}
impl Clone for RouteHop {
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
pub(crate) extern "C" fn RouteHop_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeRouteHop)).clone() })) as *mut c_void
}
#[no_mangle]
pub extern "C" fn RouteHop_clone(orig: &RouteHop) -> RouteHop {
	orig.clone()
}

use lightning::routing::router::Route as nativeRouteImport;
type nativeRoute = nativeRouteImport;

/// A route directs a payment from the sender (us) to the recipient. If the recipient supports MPP,
/// it can take multiple paths. Each path is composed of one or more hops through the network.
#[must_use]
#[repr(C)]
pub struct Route {
	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeRoute,
	pub is_owned: bool,
}

impl Drop for Route {
	fn drop(&mut self) {
		if self.is_owned && !self.inner.is_null() {
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
#[no_mangle]
pub extern "C" fn Route_free(this_ptr: Route) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn Route_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeRoute); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl Route {
	pub(crate) fn take_inner(mut self) -> *mut nativeRoute {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}
/// The list of routes taken for a single (potentially-)multi-part payment. The pubkey of the
/// last RouteHop in each path must be the same.
/// Each entry represents a list of hops, NOT INCLUDING our own, where the last hop is the
/// destination. Thus, this must always be at least length one. While the maximum length of any
/// given path is variable, keeping the length of any path to less than 20 should currently
/// ensure it is viable.
#[no_mangle]
pub extern "C" fn Route_set_paths(this_ptr: &mut Route, mut val: crate::c_types::derived::CVec_CVec_RouteHopZZ) {
	let mut local_val = Vec::new(); for mut item in val.into_rust().drain(..) { local_val.push( { let mut local_val_0 = Vec::new(); for mut item in item.into_rust().drain(..) { local_val_0.push( { *unsafe { Box::from_raw(item.take_inner()) } }); }; local_val_0 }); };
	unsafe { &mut *this_ptr.inner }.paths = local_val;
}
#[must_use]
#[no_mangle]
pub extern "C" fn Route_new(mut paths_arg: crate::c_types::derived::CVec_CVec_RouteHopZZ) -> Route {
	let mut local_paths_arg = Vec::new(); for mut item in paths_arg.into_rust().drain(..) { local_paths_arg.push( { let mut local_paths_arg_0 = Vec::new(); for mut item in item.into_rust().drain(..) { local_paths_arg_0.push( { *unsafe { Box::from_raw(item.take_inner()) } }); }; local_paths_arg_0 }); };
	Route { inner: Box::into_raw(Box::new(nativeRoute {
		paths: local_paths_arg,
	})), is_owned: true }
}
impl Clone for Route {
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
pub(crate) extern "C" fn Route_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeRoute)).clone() })) as *mut c_void
}
#[no_mangle]
pub extern "C" fn Route_clone(orig: &Route) -> Route {
	orig.clone()
}
#[no_mangle]
pub extern "C" fn Route_write(obj: &Route) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*unsafe { &*obj }.inner })
}
#[no_mangle]
pub(crate) extern "C" fn Route_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeRoute) })
}
#[no_mangle]
pub extern "C" fn Route_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_RouteDecodeErrorZ {
	let res = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::routing::router::Route { inner: Box::into_raw(Box::new(o)), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::ln::msgs::DecodeError { inner: Box::into_raw(Box::new(e)), is_owned: true } }).into() };
	local_res
}

use lightning::routing::router::RouteHint as nativeRouteHintImport;
type nativeRouteHint = nativeRouteHintImport;

/// A channel descriptor which provides a last-hop route to get_route
#[must_use]
#[repr(C)]
pub struct RouteHint {
	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeRouteHint,
	pub is_owned: bool,
}

impl Drop for RouteHint {
	fn drop(&mut self) {
		if self.is_owned && !self.inner.is_null() {
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
#[no_mangle]
pub extern "C" fn RouteHint_free(this_ptr: RouteHint) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn RouteHint_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeRouteHint); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl RouteHint {
	pub(crate) fn take_inner(mut self) -> *mut nativeRouteHint {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}
/// The node_id of the non-target end of the route
#[no_mangle]
pub extern "C" fn RouteHint_get_src_node_id(this_ptr: &RouteHint) -> crate::c_types::PublicKey {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.src_node_id;
	crate::c_types::PublicKey::from_rust(&(*inner_val))
}
/// The node_id of the non-target end of the route
#[no_mangle]
pub extern "C" fn RouteHint_set_src_node_id(this_ptr: &mut RouteHint, mut val: crate::c_types::PublicKey) {
	unsafe { &mut *this_ptr.inner }.src_node_id = val.into_rust();
}
/// The short_channel_id of this channel
#[no_mangle]
pub extern "C" fn RouteHint_get_short_channel_id(this_ptr: &RouteHint) -> u64 {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.short_channel_id;
	(*inner_val)
}
/// The short_channel_id of this channel
#[no_mangle]
pub extern "C" fn RouteHint_set_short_channel_id(this_ptr: &mut RouteHint, mut val: u64) {
	unsafe { &mut *this_ptr.inner }.short_channel_id = val;
}
/// The fees which must be paid to use this channel
#[no_mangle]
pub extern "C" fn RouteHint_get_fees(this_ptr: &RouteHint) -> crate::routing::network_graph::RoutingFees {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.fees;
	crate::routing::network_graph::RoutingFees { inner: unsafe { ( (&((*inner_val)) as *const _) as *mut _) }, is_owned: false }
}
/// The fees which must be paid to use this channel
#[no_mangle]
pub extern "C" fn RouteHint_set_fees(this_ptr: &mut RouteHint, mut val: crate::routing::network_graph::RoutingFees) {
	unsafe { &mut *this_ptr.inner }.fees = *unsafe { Box::from_raw(val.take_inner()) };
}
/// The difference in CLTV values between this node and the next node.
#[no_mangle]
pub extern "C" fn RouteHint_get_cltv_expiry_delta(this_ptr: &RouteHint) -> u16 {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.cltv_expiry_delta;
	(*inner_val)
}
/// The difference in CLTV values between this node and the next node.
#[no_mangle]
pub extern "C" fn RouteHint_set_cltv_expiry_delta(this_ptr: &mut RouteHint, mut val: u16) {
	unsafe { &mut *this_ptr.inner }.cltv_expiry_delta = val;
}
/// The minimum value, in msat, which must be relayed to the next hop.
#[no_mangle]
pub extern "C" fn RouteHint_get_htlc_minimum_msat(this_ptr: &RouteHint) -> u64 {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.htlc_minimum_msat;
	(*inner_val)
}
/// The minimum value, in msat, which must be relayed to the next hop.
#[no_mangle]
pub extern "C" fn RouteHint_set_htlc_minimum_msat(this_ptr: &mut RouteHint, mut val: u64) {
	unsafe { &mut *this_ptr.inner }.htlc_minimum_msat = val;
}
#[must_use]
#[no_mangle]
pub extern "C" fn RouteHint_new(mut src_node_id_arg: crate::c_types::PublicKey, mut short_channel_id_arg: u64, mut fees_arg: crate::routing::network_graph::RoutingFees, mut cltv_expiry_delta_arg: u16, mut htlc_minimum_msat_arg: u64) -> RouteHint {
	RouteHint { inner: Box::into_raw(Box::new(nativeRouteHint {
		src_node_id: src_node_id_arg.into_rust(),
		short_channel_id: short_channel_id_arg,
		fees: *unsafe { Box::from_raw(fees_arg.take_inner()) },
		cltv_expiry_delta: cltv_expiry_delta_arg,
		htlc_minimum_msat: htlc_minimum_msat_arg,
	})), is_owned: true }
}
impl Clone for RouteHint {
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
pub(crate) extern "C" fn RouteHint_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeRouteHint)).clone() })) as *mut c_void
}
#[no_mangle]
pub extern "C" fn RouteHint_clone(orig: &RouteHint) -> RouteHint {
	orig.clone()
}
/// Gets a route from us to the given target node.
///
/// Extra routing hops between known nodes and the target will be used if they are included in
/// last_hops.
///
/// If some channels aren't announced, it may be useful to fill in a first_hops with the
/// results from a local ChannelManager::list_usable_channels() call. If it is filled in, our
/// view of our local channels (from net_graph_msg_handler) will be ignored, and only those in first_hops
/// will be used.
///
/// Panics if first_hops contains channels without short_channel_ids
/// (ChannelManager::list_usable_channels will never include such channels).
///
/// The fees on channels from us to next-hops are ignored (as they are assumed to all be
/// equal), however the enabled/disabled bit on such channels as well as the htlc_minimum_msat
/// *is* checked as they may change based on the receiving node.
#[no_mangle]
pub extern "C" fn get_route(mut our_node_id: crate::c_types::PublicKey, network: &crate::routing::network_graph::NetworkGraph, mut target: crate::c_types::PublicKey, first_hops: *mut crate::c_types::derived::CVec_ChannelDetailsZ, mut last_hops: crate::c_types::derived::CVec_RouteHintZ, mut final_value_msat: u64, mut final_cltv: u32, mut logger: crate::util::logger::Logger) -> crate::c_types::derived::CResult_RouteLightningErrorZ {
	let mut local_first_hops_base = if first_hops == std::ptr::null_mut() { None } else { Some( { let mut local_first_hops_0 = Vec::new(); for mut item in unsafe { &mut *first_hops }.as_slice().iter() { local_first_hops_0.push( { unsafe { &*item.inner } }); }; local_first_hops_0 }) }; let mut local_first_hops = local_first_hops_base.as_ref().map(|a| &a[..]);
	let mut local_last_hops = Vec::new(); for mut item in last_hops.as_slice().iter() { local_last_hops.push( { unsafe { &*item.inner } }); };
	let mut ret = lightning::routing::router::get_route(&our_node_id.into_rust(), unsafe { &*network.inner }, &target.into_rust(), local_first_hops, &local_last_hops[..], final_value_msat, final_cltv, logger);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::routing::router::Route { inner: Box::into_raw(Box::new(o)), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::ln::msgs::LightningError { inner: Box::into_raw(Box::new(e)), is_owned: true } }).into() };
	local_ret
}

