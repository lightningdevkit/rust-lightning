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
