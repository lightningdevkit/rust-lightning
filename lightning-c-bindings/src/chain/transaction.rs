//! Types describing on-chain transactions.

use std::ffi::c_void;
use bitcoin::hashes::Hash;
use crate::c_types::*;


use lightning::chain::transaction::OutPoint as nativeOutPointImport;
type nativeOutPoint = nativeOutPointImport;

/// A reference to a transaction output.
///
/// Differs from bitcoin::blockdata::transaction::OutPoint as the index is a u16 instead of u32
/// due to LN's restrictions on index values. Should reduce (possibly) unsafe conversions this way.
#[must_use]
#[repr(C)]
pub struct OutPoint {
	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeOutPoint,
	pub is_owned: bool,
}

impl Drop for OutPoint {
	fn drop(&mut self) {
		if self.is_owned && !self.inner.is_null() {
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
#[no_mangle]
pub extern "C" fn OutPoint_free(this_ptr: OutPoint) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn OutPoint_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeOutPoint); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl OutPoint {
	pub(crate) fn take_inner(mut self) -> *mut nativeOutPoint {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}
/// The referenced transaction's txid.
#[no_mangle]
pub extern "C" fn OutPoint_get_txid(this_ptr: &OutPoint) -> *const [u8; 32] {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.txid;
	(*inner_val).as_inner()
}
/// The referenced transaction's txid.
#[no_mangle]
pub extern "C" fn OutPoint_set_txid(this_ptr: &mut OutPoint, mut val: crate::c_types::ThirtyTwoBytes) {
	unsafe { &mut *this_ptr.inner }.txid = ::bitcoin::hash_types::Txid::from_slice(&val.data[..]).unwrap();
}
/// The index of the referenced output in its transaction's vout.
#[no_mangle]
pub extern "C" fn OutPoint_get_index(this_ptr: &OutPoint) -> u16 {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.index;
	(*inner_val)
}
/// The index of the referenced output in its transaction's vout.
#[no_mangle]
pub extern "C" fn OutPoint_set_index(this_ptr: &mut OutPoint, mut val: u16) {
	unsafe { &mut *this_ptr.inner }.index = val;
}
#[must_use]
#[no_mangle]
pub extern "C" fn OutPoint_new(mut txid_arg: crate::c_types::ThirtyTwoBytes, mut index_arg: u16) -> OutPoint {
	OutPoint { inner: Box::into_raw(Box::new(nativeOutPoint {
		txid: ::bitcoin::hash_types::Txid::from_slice(&txid_arg.data[..]).unwrap(),
		index: index_arg,
	})), is_owned: true }
}
impl Clone for OutPoint {
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
pub(crate) extern "C" fn OutPoint_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeOutPoint)).clone() })) as *mut c_void
}
#[no_mangle]
pub extern "C" fn OutPoint_clone(orig: &OutPoint) -> OutPoint {
	orig.clone()
}
/// Convert an `OutPoint` to a lightning channel id.
#[must_use]
#[no_mangle]
pub extern "C" fn OutPoint_to_channel_id(this_arg: &OutPoint) -> crate::c_types::ThirtyTwoBytes {
	let mut ret = unsafe { &*this_arg.inner }.to_channel_id();
	crate::c_types::ThirtyTwoBytes { data: ret }
}

#[no_mangle]
pub extern "C" fn OutPoint_write(obj: &OutPoint) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*unsafe { &*obj }.inner })
}
#[no_mangle]
pub(crate) extern "C" fn OutPoint_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeOutPoint) })
}
#[no_mangle]
pub extern "C" fn OutPoint_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_OutPointDecodeErrorZ {
	let res = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::chain::transaction::OutPoint { inner: Box::into_raw(Box::new(o)), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::ln::msgs::DecodeError { inner: Box::into_raw(Box::new(e)), is_owned: true } }).into() };
	local_res
}
