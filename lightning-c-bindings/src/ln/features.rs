//! Feature flag definitions for the Lightning protocol according to [BOLT #9].
//!
//! Lightning nodes advertise a supported set of operation through feature flags. Features are
//! applicable for a specific context as indicated in some [messages]. [`Features`] encapsulates
//! behavior for specifying and checking feature flags for a particular context. Each feature is
//! defined internally by a trait specifying the corresponding flags (i.e., even and odd bits). A
//! [`Context`] is used to parameterize [`Features`] and defines which features it can support.
//!
//! Whether a feature is considered \"known\" or \"unknown\" is relative to the implementation, whereas
//! the term \"supports\" is used in reference to a particular set of [`Features`]. That is, a node
//! supports a feature if it advertises the feature (as either required or optional) to its peers.
//! And the implementation can interpret a feature if the feature is known to it.
//!
//! [BOLT #9]: https://github.com/lightningnetwork/lightning-rfc/blob/master/09-features.md
//! [messages]: ../msgs/index.html
//! [`Features`]: struct.Features.html
//! [`Context`]: sealed/trait.Context.html

use std::ffi::c_void;
use bitcoin::hashes::Hash;
use crate::c_types::*;

impl Clone for InitFeatures {
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
pub(crate) extern "C" fn InitFeatures_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeInitFeatures)).clone() })) as *mut c_void
}
#[no_mangle]
pub extern "C" fn InitFeatures_clone(orig: &InitFeatures) -> InitFeatures {
	orig.clone()
}
impl Clone for NodeFeatures {
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
pub(crate) extern "C" fn NodeFeatures_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeNodeFeatures)).clone() })) as *mut c_void
}
#[no_mangle]
pub extern "C" fn NodeFeatures_clone(orig: &NodeFeatures) -> NodeFeatures {
	orig.clone()
}
impl Clone for ChannelFeatures {
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
pub(crate) extern "C" fn ChannelFeatures_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeChannelFeatures)).clone() })) as *mut c_void
}
#[no_mangle]
pub extern "C" fn ChannelFeatures_clone(orig: &ChannelFeatures) -> ChannelFeatures {
	orig.clone()
}

use lightning::ln::features::InitFeatures as nativeInitFeaturesImport;
type nativeInitFeatures = nativeInitFeaturesImport;

/// Features used within an `init` message.
#[must_use]
#[repr(C)]
pub struct InitFeatures {
	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeInitFeatures,
	pub is_owned: bool,
}

impl Drop for InitFeatures {
	fn drop(&mut self) {
		if self.is_owned && !self.inner.is_null() {
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
#[no_mangle]
pub extern "C" fn InitFeatures_free(this_ptr: InitFeatures) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn InitFeatures_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeInitFeatures); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl InitFeatures {
	pub(crate) fn take_inner(mut self) -> *mut nativeInitFeatures {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}

use lightning::ln::features::NodeFeatures as nativeNodeFeaturesImport;
type nativeNodeFeatures = nativeNodeFeaturesImport;

/// Features used within a `node_announcement` message.
#[must_use]
#[repr(C)]
pub struct NodeFeatures {
	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeNodeFeatures,
	pub is_owned: bool,
}

impl Drop for NodeFeatures {
	fn drop(&mut self) {
		if self.is_owned && !self.inner.is_null() {
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
#[no_mangle]
pub extern "C" fn NodeFeatures_free(this_ptr: NodeFeatures) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn NodeFeatures_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeNodeFeatures); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl NodeFeatures {
	pub(crate) fn take_inner(mut self) -> *mut nativeNodeFeatures {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}

use lightning::ln::features::ChannelFeatures as nativeChannelFeaturesImport;
type nativeChannelFeatures = nativeChannelFeaturesImport;

/// Features used within a `channel_announcement` message.
#[must_use]
#[repr(C)]
pub struct ChannelFeatures {
	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeChannelFeatures,
	pub is_owned: bool,
}

impl Drop for ChannelFeatures {
	fn drop(&mut self) {
		if self.is_owned && !self.inner.is_null() {
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
#[no_mangle]
pub extern "C" fn ChannelFeatures_free(this_ptr: ChannelFeatures) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn ChannelFeatures_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeChannelFeatures); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl ChannelFeatures {
	pub(crate) fn take_inner(mut self) -> *mut nativeChannelFeatures {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}
/// Create a blank Features with no features set
#[must_use]
#[no_mangle]
pub extern "C" fn InitFeatures_empty() -> InitFeatures {
	let mut ret = lightning::ln::features::InitFeatures::empty();
	InitFeatures { inner: Box::into_raw(Box::new(ret)), is_owned: true }
}

/// Creates features known by the implementation as defined by [`T::KNOWN_FEATURE_FLAGS`].
///
/// [`T::KNOWN_FEATURE_FLAGS`]: sealed/trait.Context.html#associatedconstant.KNOWN_FEATURE_FLAGS
#[must_use]
#[no_mangle]
pub extern "C" fn InitFeatures_known() -> InitFeatures {
	let mut ret = lightning::ln::features::InitFeatures::known();
	InitFeatures { inner: Box::into_raw(Box::new(ret)), is_owned: true }
}

/// Create a blank Features with no features set
#[must_use]
#[no_mangle]
pub extern "C" fn NodeFeatures_empty() -> NodeFeatures {
	let mut ret = lightning::ln::features::NodeFeatures::empty();
	NodeFeatures { inner: Box::into_raw(Box::new(ret)), is_owned: true }
}

/// Creates features known by the implementation as defined by [`T::KNOWN_FEATURE_FLAGS`].
///
/// [`T::KNOWN_FEATURE_FLAGS`]: sealed/trait.Context.html#associatedconstant.KNOWN_FEATURE_FLAGS
#[must_use]
#[no_mangle]
pub extern "C" fn NodeFeatures_known() -> NodeFeatures {
	let mut ret = lightning::ln::features::NodeFeatures::known();
	NodeFeatures { inner: Box::into_raw(Box::new(ret)), is_owned: true }
}

/// Create a blank Features with no features set
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelFeatures_empty() -> ChannelFeatures {
	let mut ret = lightning::ln::features::ChannelFeatures::empty();
	ChannelFeatures { inner: Box::into_raw(Box::new(ret)), is_owned: true }
}

/// Creates features known by the implementation as defined by [`T::KNOWN_FEATURE_FLAGS`].
///
/// [`T::KNOWN_FEATURE_FLAGS`]: sealed/trait.Context.html#associatedconstant.KNOWN_FEATURE_FLAGS
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelFeatures_known() -> ChannelFeatures {
	let mut ret = lightning::ln::features::ChannelFeatures::known();
	ChannelFeatures { inner: Box::into_raw(Box::new(ret)), is_owned: true }
}

#[no_mangle]
pub extern "C" fn InitFeatures_write(obj: &InitFeatures) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*unsafe { &*obj }.inner })
}
#[no_mangle]
pub(crate) extern "C" fn InitFeatures_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeInitFeatures) })
}
#[no_mangle]
pub extern "C" fn NodeFeatures_write(obj: &NodeFeatures) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*unsafe { &*obj }.inner })
}
#[no_mangle]
pub(crate) extern "C" fn NodeFeatures_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeNodeFeatures) })
}
#[no_mangle]
pub extern "C" fn ChannelFeatures_write(obj: &ChannelFeatures) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*unsafe { &*obj }.inner })
}
#[no_mangle]
pub(crate) extern "C" fn ChannelFeatures_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeChannelFeatures) })
}
#[no_mangle]
pub extern "C" fn InitFeatures_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_InitFeaturesDecodeErrorZ {
	let res = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::ln::features::InitFeatures { inner: Box::into_raw(Box::new(o)), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::ln::msgs::DecodeError { inner: Box::into_raw(Box::new(e)), is_owned: true } }).into() };
	local_res
}
#[no_mangle]
pub extern "C" fn NodeFeatures_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_NodeFeaturesDecodeErrorZ {
	let res = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::ln::features::NodeFeatures { inner: Box::into_raw(Box::new(o)), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::ln::msgs::DecodeError { inner: Box::into_raw(Box::new(e)), is_owned: true } }).into() };
	local_res
}
#[no_mangle]
pub extern "C" fn ChannelFeatures_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_ChannelFeaturesDecodeErrorZ {
	let res = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::ln::features::ChannelFeatures { inner: Box::into_raw(Box::new(o)), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::ln::msgs::DecodeError { inner: Box::into_raw(Box::new(e)), is_owned: true } }).into() };
	local_res
}
