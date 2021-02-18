//! Wire messages, traits representing wire message handlers, and a few error types live here.
//!
//! For a normal node you probably don't need to use anything here, however, if you wish to split a
//! node into an internet-facing route/message socket handling daemon and a separate daemon (or
//! server entirely) which handles only channel-related messages you may wish to implement
//! ChannelMessageHandler yourself and use it to re-serialize messages and pass them across
//! daemons/servers.
//!
//! Note that if you go with such an architecture (instead of passing raw socket events to a
//! non-internet-facing system) you trust the frontend internet-facing system to not lie about the
//! source node_id of the message, however this does allow you to significantly reduce bandwidth
//! between the systems as routing messages can represent a significant chunk of bandwidth usage
//! (especially for non-channel-publicly-announcing nodes). As an alternate design which avoids
//! this issue, if you have sufficient bidirectional bandwidth between your systems, you may send
//! raw socket events into your non-internet-facing system and then send routing events back to
//! track the network on the less-secure system.

use std::ffi::c_void;
use bitcoin::hashes::Hash;
use crate::c_types::*;


use lightning::ln::msgs::DecodeError as nativeDecodeErrorImport;
type nativeDecodeError = nativeDecodeErrorImport;

/// An error in decoding a message or struct.
#[must_use]
#[repr(C)]
pub struct DecodeError {
	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeDecodeError,
	pub is_owned: bool,
}

impl Drop for DecodeError {
	fn drop(&mut self) {
		if self.is_owned && !self.inner.is_null() {
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
#[no_mangle]
pub extern "C" fn DecodeError_free(this_ptr: DecodeError) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn DecodeError_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeDecodeError); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl DecodeError {
	pub(crate) fn take_inner(mut self) -> *mut nativeDecodeError {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}
impl Clone for DecodeError {
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
pub(crate) extern "C" fn DecodeError_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeDecodeError)).clone() })) as *mut c_void
}
#[no_mangle]
pub extern "C" fn DecodeError_clone(orig: &DecodeError) -> DecodeError {
	orig.clone()
}

use lightning::ln::msgs::Init as nativeInitImport;
type nativeInit = nativeInitImport;

/// An init message to be sent or received from a peer
#[must_use]
#[repr(C)]
pub struct Init {
	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeInit,
	pub is_owned: bool,
}

impl Drop for Init {
	fn drop(&mut self) {
		if self.is_owned && !self.inner.is_null() {
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
#[no_mangle]
pub extern "C" fn Init_free(this_ptr: Init) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn Init_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeInit); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl Init {
	pub(crate) fn take_inner(mut self) -> *mut nativeInit {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}
impl Clone for Init {
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
pub(crate) extern "C" fn Init_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeInit)).clone() })) as *mut c_void
}
#[no_mangle]
pub extern "C" fn Init_clone(orig: &Init) -> Init {
	orig.clone()
}

use lightning::ln::msgs::ErrorMessage as nativeErrorMessageImport;
type nativeErrorMessage = nativeErrorMessageImport;

/// An error message to be sent or received from a peer
#[must_use]
#[repr(C)]
pub struct ErrorMessage {
	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeErrorMessage,
	pub is_owned: bool,
}

impl Drop for ErrorMessage {
	fn drop(&mut self) {
		if self.is_owned && !self.inner.is_null() {
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
#[no_mangle]
pub extern "C" fn ErrorMessage_free(this_ptr: ErrorMessage) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn ErrorMessage_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeErrorMessage); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl ErrorMessage {
	pub(crate) fn take_inner(mut self) -> *mut nativeErrorMessage {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}
/// The channel ID involved in the error
#[no_mangle]
pub extern "C" fn ErrorMessage_get_channel_id(this_ptr: &ErrorMessage) -> *const [u8; 32] {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.channel_id;
	&(*inner_val)
}
/// The channel ID involved in the error
#[no_mangle]
pub extern "C" fn ErrorMessage_set_channel_id(this_ptr: &mut ErrorMessage, mut val: crate::c_types::ThirtyTwoBytes) {
	unsafe { &mut *this_ptr.inner }.channel_id = val.data;
}
/// A possibly human-readable error description.
/// The string should be sanitized before it is used (e.g. emitted to logs
/// or printed to stdout).  Otherwise, a well crafted error message may trigger a security
/// vulnerability in the terminal emulator or the logging subsystem.
#[no_mangle]
pub extern "C" fn ErrorMessage_get_data(this_ptr: &ErrorMessage) -> crate::c_types::Str {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.data;
	(*inner_val).as_str().into()
}
/// A possibly human-readable error description.
/// The string should be sanitized before it is used (e.g. emitted to logs
/// or printed to stdout).  Otherwise, a well crafted error message may trigger a security
/// vulnerability in the terminal emulator or the logging subsystem.
#[no_mangle]
pub extern "C" fn ErrorMessage_set_data(this_ptr: &mut ErrorMessage, mut val: crate::c_types::derived::CVec_u8Z) {
	unsafe { &mut *this_ptr.inner }.data = String::from_utf8(val.into_rust()).unwrap();
}
#[must_use]
#[no_mangle]
pub extern "C" fn ErrorMessage_new(mut channel_id_arg: crate::c_types::ThirtyTwoBytes, mut data_arg: crate::c_types::derived::CVec_u8Z) -> ErrorMessage {
	ErrorMessage { inner: Box::into_raw(Box::new(nativeErrorMessage {
		channel_id: channel_id_arg.data,
		data: String::from_utf8(data_arg.into_rust()).unwrap(),
	})), is_owned: true }
}
impl Clone for ErrorMessage {
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
pub(crate) extern "C" fn ErrorMessage_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeErrorMessage)).clone() })) as *mut c_void
}
#[no_mangle]
pub extern "C" fn ErrorMessage_clone(orig: &ErrorMessage) -> ErrorMessage {
	orig.clone()
}

use lightning::ln::msgs::Ping as nativePingImport;
type nativePing = nativePingImport;

/// A ping message to be sent or received from a peer
#[must_use]
#[repr(C)]
pub struct Ping {
	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativePing,
	pub is_owned: bool,
}

impl Drop for Ping {
	fn drop(&mut self) {
		if self.is_owned && !self.inner.is_null() {
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
#[no_mangle]
pub extern "C" fn Ping_free(this_ptr: Ping) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn Ping_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativePing); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl Ping {
	pub(crate) fn take_inner(mut self) -> *mut nativePing {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}
/// The desired response length
#[no_mangle]
pub extern "C" fn Ping_get_ponglen(this_ptr: &Ping) -> u16 {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.ponglen;
	(*inner_val)
}
/// The desired response length
#[no_mangle]
pub extern "C" fn Ping_set_ponglen(this_ptr: &mut Ping, mut val: u16) {
	unsafe { &mut *this_ptr.inner }.ponglen = val;
}
/// The ping packet size.
/// This field is not sent on the wire. byteslen zeros are sent.
#[no_mangle]
pub extern "C" fn Ping_get_byteslen(this_ptr: &Ping) -> u16 {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.byteslen;
	(*inner_val)
}
/// The ping packet size.
/// This field is not sent on the wire. byteslen zeros are sent.
#[no_mangle]
pub extern "C" fn Ping_set_byteslen(this_ptr: &mut Ping, mut val: u16) {
	unsafe { &mut *this_ptr.inner }.byteslen = val;
}
#[must_use]
#[no_mangle]
pub extern "C" fn Ping_new(mut ponglen_arg: u16, mut byteslen_arg: u16) -> Ping {
	Ping { inner: Box::into_raw(Box::new(nativePing {
		ponglen: ponglen_arg,
		byteslen: byteslen_arg,
	})), is_owned: true }
}
impl Clone for Ping {
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
pub(crate) extern "C" fn Ping_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativePing)).clone() })) as *mut c_void
}
#[no_mangle]
pub extern "C" fn Ping_clone(orig: &Ping) -> Ping {
	orig.clone()
}

use lightning::ln::msgs::Pong as nativePongImport;
type nativePong = nativePongImport;

/// A pong message to be sent or received from a peer
#[must_use]
#[repr(C)]
pub struct Pong {
	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativePong,
	pub is_owned: bool,
}

impl Drop for Pong {
	fn drop(&mut self) {
		if self.is_owned && !self.inner.is_null() {
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
#[no_mangle]
pub extern "C" fn Pong_free(this_ptr: Pong) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn Pong_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativePong); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl Pong {
	pub(crate) fn take_inner(mut self) -> *mut nativePong {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}
/// The pong packet size.
/// This field is not sent on the wire. byteslen zeros are sent.
#[no_mangle]
pub extern "C" fn Pong_get_byteslen(this_ptr: &Pong) -> u16 {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.byteslen;
	(*inner_val)
}
/// The pong packet size.
/// This field is not sent on the wire. byteslen zeros are sent.
#[no_mangle]
pub extern "C" fn Pong_set_byteslen(this_ptr: &mut Pong, mut val: u16) {
	unsafe { &mut *this_ptr.inner }.byteslen = val;
}
#[must_use]
#[no_mangle]
pub extern "C" fn Pong_new(mut byteslen_arg: u16) -> Pong {
	Pong { inner: Box::into_raw(Box::new(nativePong {
		byteslen: byteslen_arg,
	})), is_owned: true }
}
impl Clone for Pong {
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
pub(crate) extern "C" fn Pong_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativePong)).clone() })) as *mut c_void
}
#[no_mangle]
pub extern "C" fn Pong_clone(orig: &Pong) -> Pong {
	orig.clone()
}

use lightning::ln::msgs::OpenChannel as nativeOpenChannelImport;
type nativeOpenChannel = nativeOpenChannelImport;

/// An open_channel message to be sent or received from a peer
#[must_use]
#[repr(C)]
pub struct OpenChannel {
	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeOpenChannel,
	pub is_owned: bool,
}

impl Drop for OpenChannel {
	fn drop(&mut self) {
		if self.is_owned && !self.inner.is_null() {
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
#[no_mangle]
pub extern "C" fn OpenChannel_free(this_ptr: OpenChannel) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn OpenChannel_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeOpenChannel); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl OpenChannel {
	pub(crate) fn take_inner(mut self) -> *mut nativeOpenChannel {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}
/// The genesis hash of the blockchain where the channel is to be opened
#[no_mangle]
pub extern "C" fn OpenChannel_get_chain_hash(this_ptr: &OpenChannel) -> *const [u8; 32] {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.chain_hash;
	(*inner_val).as_inner()
}
/// The genesis hash of the blockchain where the channel is to be opened
#[no_mangle]
pub extern "C" fn OpenChannel_set_chain_hash(this_ptr: &mut OpenChannel, mut val: crate::c_types::ThirtyTwoBytes) {
	unsafe { &mut *this_ptr.inner }.chain_hash = ::bitcoin::hash_types::BlockHash::from_slice(&val.data[..]).unwrap();
}
/// A temporary channel ID, until the funding outpoint is announced
#[no_mangle]
pub extern "C" fn OpenChannel_get_temporary_channel_id(this_ptr: &OpenChannel) -> *const [u8; 32] {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.temporary_channel_id;
	&(*inner_val)
}
/// A temporary channel ID, until the funding outpoint is announced
#[no_mangle]
pub extern "C" fn OpenChannel_set_temporary_channel_id(this_ptr: &mut OpenChannel, mut val: crate::c_types::ThirtyTwoBytes) {
	unsafe { &mut *this_ptr.inner }.temporary_channel_id = val.data;
}
/// The channel value
#[no_mangle]
pub extern "C" fn OpenChannel_get_funding_satoshis(this_ptr: &OpenChannel) -> u64 {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.funding_satoshis;
	(*inner_val)
}
/// The channel value
#[no_mangle]
pub extern "C" fn OpenChannel_set_funding_satoshis(this_ptr: &mut OpenChannel, mut val: u64) {
	unsafe { &mut *this_ptr.inner }.funding_satoshis = val;
}
/// The amount to push to the counterparty as part of the open, in milli-satoshi
#[no_mangle]
pub extern "C" fn OpenChannel_get_push_msat(this_ptr: &OpenChannel) -> u64 {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.push_msat;
	(*inner_val)
}
/// The amount to push to the counterparty as part of the open, in milli-satoshi
#[no_mangle]
pub extern "C" fn OpenChannel_set_push_msat(this_ptr: &mut OpenChannel, mut val: u64) {
	unsafe { &mut *this_ptr.inner }.push_msat = val;
}
/// The threshold below which outputs on transactions broadcast by sender will be omitted
#[no_mangle]
pub extern "C" fn OpenChannel_get_dust_limit_satoshis(this_ptr: &OpenChannel) -> u64 {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.dust_limit_satoshis;
	(*inner_val)
}
/// The threshold below which outputs on transactions broadcast by sender will be omitted
#[no_mangle]
pub extern "C" fn OpenChannel_set_dust_limit_satoshis(this_ptr: &mut OpenChannel, mut val: u64) {
	unsafe { &mut *this_ptr.inner }.dust_limit_satoshis = val;
}
/// The maximum inbound HTLC value in flight towards sender, in milli-satoshi
#[no_mangle]
pub extern "C" fn OpenChannel_get_max_htlc_value_in_flight_msat(this_ptr: &OpenChannel) -> u64 {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.max_htlc_value_in_flight_msat;
	(*inner_val)
}
/// The maximum inbound HTLC value in flight towards sender, in milli-satoshi
#[no_mangle]
pub extern "C" fn OpenChannel_set_max_htlc_value_in_flight_msat(this_ptr: &mut OpenChannel, mut val: u64) {
	unsafe { &mut *this_ptr.inner }.max_htlc_value_in_flight_msat = val;
}
/// The minimum value unencumbered by HTLCs for the counterparty to keep in the channel
#[no_mangle]
pub extern "C" fn OpenChannel_get_channel_reserve_satoshis(this_ptr: &OpenChannel) -> u64 {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.channel_reserve_satoshis;
	(*inner_val)
}
/// The minimum value unencumbered by HTLCs for the counterparty to keep in the channel
#[no_mangle]
pub extern "C" fn OpenChannel_set_channel_reserve_satoshis(this_ptr: &mut OpenChannel, mut val: u64) {
	unsafe { &mut *this_ptr.inner }.channel_reserve_satoshis = val;
}
/// The minimum HTLC size incoming to sender, in milli-satoshi
#[no_mangle]
pub extern "C" fn OpenChannel_get_htlc_minimum_msat(this_ptr: &OpenChannel) -> u64 {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.htlc_minimum_msat;
	(*inner_val)
}
/// The minimum HTLC size incoming to sender, in milli-satoshi
#[no_mangle]
pub extern "C" fn OpenChannel_set_htlc_minimum_msat(this_ptr: &mut OpenChannel, mut val: u64) {
	unsafe { &mut *this_ptr.inner }.htlc_minimum_msat = val;
}
/// The feerate per 1000-weight of sender generated transactions, until updated by update_fee
#[no_mangle]
pub extern "C" fn OpenChannel_get_feerate_per_kw(this_ptr: &OpenChannel) -> u32 {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.feerate_per_kw;
	(*inner_val)
}
/// The feerate per 1000-weight of sender generated transactions, until updated by update_fee
#[no_mangle]
pub extern "C" fn OpenChannel_set_feerate_per_kw(this_ptr: &mut OpenChannel, mut val: u32) {
	unsafe { &mut *this_ptr.inner }.feerate_per_kw = val;
}
/// The number of blocks which the counterparty will have to wait to claim on-chain funds if they broadcast a commitment transaction
#[no_mangle]
pub extern "C" fn OpenChannel_get_to_self_delay(this_ptr: &OpenChannel) -> u16 {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.to_self_delay;
	(*inner_val)
}
/// The number of blocks which the counterparty will have to wait to claim on-chain funds if they broadcast a commitment transaction
#[no_mangle]
pub extern "C" fn OpenChannel_set_to_self_delay(this_ptr: &mut OpenChannel, mut val: u16) {
	unsafe { &mut *this_ptr.inner }.to_self_delay = val;
}
/// The maximum number of inbound HTLCs towards sender
#[no_mangle]
pub extern "C" fn OpenChannel_get_max_accepted_htlcs(this_ptr: &OpenChannel) -> u16 {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.max_accepted_htlcs;
	(*inner_val)
}
/// The maximum number of inbound HTLCs towards sender
#[no_mangle]
pub extern "C" fn OpenChannel_set_max_accepted_htlcs(this_ptr: &mut OpenChannel, mut val: u16) {
	unsafe { &mut *this_ptr.inner }.max_accepted_htlcs = val;
}
/// The sender's key controlling the funding transaction
#[no_mangle]
pub extern "C" fn OpenChannel_get_funding_pubkey(this_ptr: &OpenChannel) -> crate::c_types::PublicKey {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.funding_pubkey;
	crate::c_types::PublicKey::from_rust(&(*inner_val))
}
/// The sender's key controlling the funding transaction
#[no_mangle]
pub extern "C" fn OpenChannel_set_funding_pubkey(this_ptr: &mut OpenChannel, mut val: crate::c_types::PublicKey) {
	unsafe { &mut *this_ptr.inner }.funding_pubkey = val.into_rust();
}
/// Used to derive a revocation key for transactions broadcast by counterparty
#[no_mangle]
pub extern "C" fn OpenChannel_get_revocation_basepoint(this_ptr: &OpenChannel) -> crate::c_types::PublicKey {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.revocation_basepoint;
	crate::c_types::PublicKey::from_rust(&(*inner_val))
}
/// Used to derive a revocation key for transactions broadcast by counterparty
#[no_mangle]
pub extern "C" fn OpenChannel_set_revocation_basepoint(this_ptr: &mut OpenChannel, mut val: crate::c_types::PublicKey) {
	unsafe { &mut *this_ptr.inner }.revocation_basepoint = val.into_rust();
}
/// A payment key to sender for transactions broadcast by counterparty
#[no_mangle]
pub extern "C" fn OpenChannel_get_payment_point(this_ptr: &OpenChannel) -> crate::c_types::PublicKey {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.payment_point;
	crate::c_types::PublicKey::from_rust(&(*inner_val))
}
/// A payment key to sender for transactions broadcast by counterparty
#[no_mangle]
pub extern "C" fn OpenChannel_set_payment_point(this_ptr: &mut OpenChannel, mut val: crate::c_types::PublicKey) {
	unsafe { &mut *this_ptr.inner }.payment_point = val.into_rust();
}
/// Used to derive a payment key to sender for transactions broadcast by sender
#[no_mangle]
pub extern "C" fn OpenChannel_get_delayed_payment_basepoint(this_ptr: &OpenChannel) -> crate::c_types::PublicKey {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.delayed_payment_basepoint;
	crate::c_types::PublicKey::from_rust(&(*inner_val))
}
/// Used to derive a payment key to sender for transactions broadcast by sender
#[no_mangle]
pub extern "C" fn OpenChannel_set_delayed_payment_basepoint(this_ptr: &mut OpenChannel, mut val: crate::c_types::PublicKey) {
	unsafe { &mut *this_ptr.inner }.delayed_payment_basepoint = val.into_rust();
}
/// Used to derive an HTLC payment key to sender
#[no_mangle]
pub extern "C" fn OpenChannel_get_htlc_basepoint(this_ptr: &OpenChannel) -> crate::c_types::PublicKey {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.htlc_basepoint;
	crate::c_types::PublicKey::from_rust(&(*inner_val))
}
/// Used to derive an HTLC payment key to sender
#[no_mangle]
pub extern "C" fn OpenChannel_set_htlc_basepoint(this_ptr: &mut OpenChannel, mut val: crate::c_types::PublicKey) {
	unsafe { &mut *this_ptr.inner }.htlc_basepoint = val.into_rust();
}
/// The first to-be-broadcast-by-sender transaction's per commitment point
#[no_mangle]
pub extern "C" fn OpenChannel_get_first_per_commitment_point(this_ptr: &OpenChannel) -> crate::c_types::PublicKey {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.first_per_commitment_point;
	crate::c_types::PublicKey::from_rust(&(*inner_val))
}
/// The first to-be-broadcast-by-sender transaction's per commitment point
#[no_mangle]
pub extern "C" fn OpenChannel_set_first_per_commitment_point(this_ptr: &mut OpenChannel, mut val: crate::c_types::PublicKey) {
	unsafe { &mut *this_ptr.inner }.first_per_commitment_point = val.into_rust();
}
/// Channel flags
#[no_mangle]
pub extern "C" fn OpenChannel_get_channel_flags(this_ptr: &OpenChannel) -> u8 {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.channel_flags;
	(*inner_val)
}
/// Channel flags
#[no_mangle]
pub extern "C" fn OpenChannel_set_channel_flags(this_ptr: &mut OpenChannel, mut val: u8) {
	unsafe { &mut *this_ptr.inner }.channel_flags = val;
}
impl Clone for OpenChannel {
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
pub(crate) extern "C" fn OpenChannel_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeOpenChannel)).clone() })) as *mut c_void
}
#[no_mangle]
pub extern "C" fn OpenChannel_clone(orig: &OpenChannel) -> OpenChannel {
	orig.clone()
}

use lightning::ln::msgs::AcceptChannel as nativeAcceptChannelImport;
type nativeAcceptChannel = nativeAcceptChannelImport;

/// An accept_channel message to be sent or received from a peer
#[must_use]
#[repr(C)]
pub struct AcceptChannel {
	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeAcceptChannel,
	pub is_owned: bool,
}

impl Drop for AcceptChannel {
	fn drop(&mut self) {
		if self.is_owned && !self.inner.is_null() {
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
#[no_mangle]
pub extern "C" fn AcceptChannel_free(this_ptr: AcceptChannel) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn AcceptChannel_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeAcceptChannel); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl AcceptChannel {
	pub(crate) fn take_inner(mut self) -> *mut nativeAcceptChannel {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}
/// A temporary channel ID, until the funding outpoint is announced
#[no_mangle]
pub extern "C" fn AcceptChannel_get_temporary_channel_id(this_ptr: &AcceptChannel) -> *const [u8; 32] {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.temporary_channel_id;
	&(*inner_val)
}
/// A temporary channel ID, until the funding outpoint is announced
#[no_mangle]
pub extern "C" fn AcceptChannel_set_temporary_channel_id(this_ptr: &mut AcceptChannel, mut val: crate::c_types::ThirtyTwoBytes) {
	unsafe { &mut *this_ptr.inner }.temporary_channel_id = val.data;
}
/// The threshold below which outputs on transactions broadcast by sender will be omitted
#[no_mangle]
pub extern "C" fn AcceptChannel_get_dust_limit_satoshis(this_ptr: &AcceptChannel) -> u64 {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.dust_limit_satoshis;
	(*inner_val)
}
/// The threshold below which outputs on transactions broadcast by sender will be omitted
#[no_mangle]
pub extern "C" fn AcceptChannel_set_dust_limit_satoshis(this_ptr: &mut AcceptChannel, mut val: u64) {
	unsafe { &mut *this_ptr.inner }.dust_limit_satoshis = val;
}
/// The maximum inbound HTLC value in flight towards sender, in milli-satoshi
#[no_mangle]
pub extern "C" fn AcceptChannel_get_max_htlc_value_in_flight_msat(this_ptr: &AcceptChannel) -> u64 {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.max_htlc_value_in_flight_msat;
	(*inner_val)
}
/// The maximum inbound HTLC value in flight towards sender, in milli-satoshi
#[no_mangle]
pub extern "C" fn AcceptChannel_set_max_htlc_value_in_flight_msat(this_ptr: &mut AcceptChannel, mut val: u64) {
	unsafe { &mut *this_ptr.inner }.max_htlc_value_in_flight_msat = val;
}
/// The minimum value unencumbered by HTLCs for the counterparty to keep in the channel
#[no_mangle]
pub extern "C" fn AcceptChannel_get_channel_reserve_satoshis(this_ptr: &AcceptChannel) -> u64 {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.channel_reserve_satoshis;
	(*inner_val)
}
/// The minimum value unencumbered by HTLCs for the counterparty to keep in the channel
#[no_mangle]
pub extern "C" fn AcceptChannel_set_channel_reserve_satoshis(this_ptr: &mut AcceptChannel, mut val: u64) {
	unsafe { &mut *this_ptr.inner }.channel_reserve_satoshis = val;
}
/// The minimum HTLC size incoming to sender, in milli-satoshi
#[no_mangle]
pub extern "C" fn AcceptChannel_get_htlc_minimum_msat(this_ptr: &AcceptChannel) -> u64 {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.htlc_minimum_msat;
	(*inner_val)
}
/// The minimum HTLC size incoming to sender, in milli-satoshi
#[no_mangle]
pub extern "C" fn AcceptChannel_set_htlc_minimum_msat(this_ptr: &mut AcceptChannel, mut val: u64) {
	unsafe { &mut *this_ptr.inner }.htlc_minimum_msat = val;
}
/// Minimum depth of the funding transaction before the channel is considered open
#[no_mangle]
pub extern "C" fn AcceptChannel_get_minimum_depth(this_ptr: &AcceptChannel) -> u32 {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.minimum_depth;
	(*inner_val)
}
/// Minimum depth of the funding transaction before the channel is considered open
#[no_mangle]
pub extern "C" fn AcceptChannel_set_minimum_depth(this_ptr: &mut AcceptChannel, mut val: u32) {
	unsafe { &mut *this_ptr.inner }.minimum_depth = val;
}
/// The number of blocks which the counterparty will have to wait to claim on-chain funds if they broadcast a commitment transaction
#[no_mangle]
pub extern "C" fn AcceptChannel_get_to_self_delay(this_ptr: &AcceptChannel) -> u16 {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.to_self_delay;
	(*inner_val)
}
/// The number of blocks which the counterparty will have to wait to claim on-chain funds if they broadcast a commitment transaction
#[no_mangle]
pub extern "C" fn AcceptChannel_set_to_self_delay(this_ptr: &mut AcceptChannel, mut val: u16) {
	unsafe { &mut *this_ptr.inner }.to_self_delay = val;
}
/// The maximum number of inbound HTLCs towards sender
#[no_mangle]
pub extern "C" fn AcceptChannel_get_max_accepted_htlcs(this_ptr: &AcceptChannel) -> u16 {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.max_accepted_htlcs;
	(*inner_val)
}
/// The maximum number of inbound HTLCs towards sender
#[no_mangle]
pub extern "C" fn AcceptChannel_set_max_accepted_htlcs(this_ptr: &mut AcceptChannel, mut val: u16) {
	unsafe { &mut *this_ptr.inner }.max_accepted_htlcs = val;
}
/// The sender's key controlling the funding transaction
#[no_mangle]
pub extern "C" fn AcceptChannel_get_funding_pubkey(this_ptr: &AcceptChannel) -> crate::c_types::PublicKey {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.funding_pubkey;
	crate::c_types::PublicKey::from_rust(&(*inner_val))
}
/// The sender's key controlling the funding transaction
#[no_mangle]
pub extern "C" fn AcceptChannel_set_funding_pubkey(this_ptr: &mut AcceptChannel, mut val: crate::c_types::PublicKey) {
	unsafe { &mut *this_ptr.inner }.funding_pubkey = val.into_rust();
}
/// Used to derive a revocation key for transactions broadcast by counterparty
#[no_mangle]
pub extern "C" fn AcceptChannel_get_revocation_basepoint(this_ptr: &AcceptChannel) -> crate::c_types::PublicKey {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.revocation_basepoint;
	crate::c_types::PublicKey::from_rust(&(*inner_val))
}
/// Used to derive a revocation key for transactions broadcast by counterparty
#[no_mangle]
pub extern "C" fn AcceptChannel_set_revocation_basepoint(this_ptr: &mut AcceptChannel, mut val: crate::c_types::PublicKey) {
	unsafe { &mut *this_ptr.inner }.revocation_basepoint = val.into_rust();
}
/// A payment key to sender for transactions broadcast by counterparty
#[no_mangle]
pub extern "C" fn AcceptChannel_get_payment_point(this_ptr: &AcceptChannel) -> crate::c_types::PublicKey {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.payment_point;
	crate::c_types::PublicKey::from_rust(&(*inner_val))
}
/// A payment key to sender for transactions broadcast by counterparty
#[no_mangle]
pub extern "C" fn AcceptChannel_set_payment_point(this_ptr: &mut AcceptChannel, mut val: crate::c_types::PublicKey) {
	unsafe { &mut *this_ptr.inner }.payment_point = val.into_rust();
}
/// Used to derive a payment key to sender for transactions broadcast by sender
#[no_mangle]
pub extern "C" fn AcceptChannel_get_delayed_payment_basepoint(this_ptr: &AcceptChannel) -> crate::c_types::PublicKey {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.delayed_payment_basepoint;
	crate::c_types::PublicKey::from_rust(&(*inner_val))
}
/// Used to derive a payment key to sender for transactions broadcast by sender
#[no_mangle]
pub extern "C" fn AcceptChannel_set_delayed_payment_basepoint(this_ptr: &mut AcceptChannel, mut val: crate::c_types::PublicKey) {
	unsafe { &mut *this_ptr.inner }.delayed_payment_basepoint = val.into_rust();
}
/// Used to derive an HTLC payment key to sender for transactions broadcast by counterparty
#[no_mangle]
pub extern "C" fn AcceptChannel_get_htlc_basepoint(this_ptr: &AcceptChannel) -> crate::c_types::PublicKey {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.htlc_basepoint;
	crate::c_types::PublicKey::from_rust(&(*inner_val))
}
/// Used to derive an HTLC payment key to sender for transactions broadcast by counterparty
#[no_mangle]
pub extern "C" fn AcceptChannel_set_htlc_basepoint(this_ptr: &mut AcceptChannel, mut val: crate::c_types::PublicKey) {
	unsafe { &mut *this_ptr.inner }.htlc_basepoint = val.into_rust();
}
/// The first to-be-broadcast-by-sender transaction's per commitment point
#[no_mangle]
pub extern "C" fn AcceptChannel_get_first_per_commitment_point(this_ptr: &AcceptChannel) -> crate::c_types::PublicKey {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.first_per_commitment_point;
	crate::c_types::PublicKey::from_rust(&(*inner_val))
}
/// The first to-be-broadcast-by-sender transaction's per commitment point
#[no_mangle]
pub extern "C" fn AcceptChannel_set_first_per_commitment_point(this_ptr: &mut AcceptChannel, mut val: crate::c_types::PublicKey) {
	unsafe { &mut *this_ptr.inner }.first_per_commitment_point = val.into_rust();
}
impl Clone for AcceptChannel {
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
pub(crate) extern "C" fn AcceptChannel_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeAcceptChannel)).clone() })) as *mut c_void
}
#[no_mangle]
pub extern "C" fn AcceptChannel_clone(orig: &AcceptChannel) -> AcceptChannel {
	orig.clone()
}

use lightning::ln::msgs::FundingCreated as nativeFundingCreatedImport;
type nativeFundingCreated = nativeFundingCreatedImport;

/// A funding_created message to be sent or received from a peer
#[must_use]
#[repr(C)]
pub struct FundingCreated {
	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeFundingCreated,
	pub is_owned: bool,
}

impl Drop for FundingCreated {
	fn drop(&mut self) {
		if self.is_owned && !self.inner.is_null() {
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
#[no_mangle]
pub extern "C" fn FundingCreated_free(this_ptr: FundingCreated) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn FundingCreated_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeFundingCreated); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl FundingCreated {
	pub(crate) fn take_inner(mut self) -> *mut nativeFundingCreated {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}
/// A temporary channel ID, until the funding is established
#[no_mangle]
pub extern "C" fn FundingCreated_get_temporary_channel_id(this_ptr: &FundingCreated) -> *const [u8; 32] {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.temporary_channel_id;
	&(*inner_val)
}
/// A temporary channel ID, until the funding is established
#[no_mangle]
pub extern "C" fn FundingCreated_set_temporary_channel_id(this_ptr: &mut FundingCreated, mut val: crate::c_types::ThirtyTwoBytes) {
	unsafe { &mut *this_ptr.inner }.temporary_channel_id = val.data;
}
/// The funding transaction ID
#[no_mangle]
pub extern "C" fn FundingCreated_get_funding_txid(this_ptr: &FundingCreated) -> *const [u8; 32] {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.funding_txid;
	(*inner_val).as_inner()
}
/// The funding transaction ID
#[no_mangle]
pub extern "C" fn FundingCreated_set_funding_txid(this_ptr: &mut FundingCreated, mut val: crate::c_types::ThirtyTwoBytes) {
	unsafe { &mut *this_ptr.inner }.funding_txid = ::bitcoin::hash_types::Txid::from_slice(&val.data[..]).unwrap();
}
/// The specific output index funding this channel
#[no_mangle]
pub extern "C" fn FundingCreated_get_funding_output_index(this_ptr: &FundingCreated) -> u16 {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.funding_output_index;
	(*inner_val)
}
/// The specific output index funding this channel
#[no_mangle]
pub extern "C" fn FundingCreated_set_funding_output_index(this_ptr: &mut FundingCreated, mut val: u16) {
	unsafe { &mut *this_ptr.inner }.funding_output_index = val;
}
/// The signature of the channel initiator (funder) on the funding transaction
#[no_mangle]
pub extern "C" fn FundingCreated_get_signature(this_ptr: &FundingCreated) -> crate::c_types::Signature {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.signature;
	crate::c_types::Signature::from_rust(&(*inner_val))
}
/// The signature of the channel initiator (funder) on the funding transaction
#[no_mangle]
pub extern "C" fn FundingCreated_set_signature(this_ptr: &mut FundingCreated, mut val: crate::c_types::Signature) {
	unsafe { &mut *this_ptr.inner }.signature = val.into_rust();
}
#[must_use]
#[no_mangle]
pub extern "C" fn FundingCreated_new(mut temporary_channel_id_arg: crate::c_types::ThirtyTwoBytes, mut funding_txid_arg: crate::c_types::ThirtyTwoBytes, mut funding_output_index_arg: u16, mut signature_arg: crate::c_types::Signature) -> FundingCreated {
	FundingCreated { inner: Box::into_raw(Box::new(nativeFundingCreated {
		temporary_channel_id: temporary_channel_id_arg.data,
		funding_txid: ::bitcoin::hash_types::Txid::from_slice(&funding_txid_arg.data[..]).unwrap(),
		funding_output_index: funding_output_index_arg,
		signature: signature_arg.into_rust(),
	})), is_owned: true }
}
impl Clone for FundingCreated {
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
pub(crate) extern "C" fn FundingCreated_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeFundingCreated)).clone() })) as *mut c_void
}
#[no_mangle]
pub extern "C" fn FundingCreated_clone(orig: &FundingCreated) -> FundingCreated {
	orig.clone()
}

use lightning::ln::msgs::FundingSigned as nativeFundingSignedImport;
type nativeFundingSigned = nativeFundingSignedImport;

/// A funding_signed message to be sent or received from a peer
#[must_use]
#[repr(C)]
pub struct FundingSigned {
	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeFundingSigned,
	pub is_owned: bool,
}

impl Drop for FundingSigned {
	fn drop(&mut self) {
		if self.is_owned && !self.inner.is_null() {
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
#[no_mangle]
pub extern "C" fn FundingSigned_free(this_ptr: FundingSigned) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn FundingSigned_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeFundingSigned); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl FundingSigned {
	pub(crate) fn take_inner(mut self) -> *mut nativeFundingSigned {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}
/// The channel ID
#[no_mangle]
pub extern "C" fn FundingSigned_get_channel_id(this_ptr: &FundingSigned) -> *const [u8; 32] {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.channel_id;
	&(*inner_val)
}
/// The channel ID
#[no_mangle]
pub extern "C" fn FundingSigned_set_channel_id(this_ptr: &mut FundingSigned, mut val: crate::c_types::ThirtyTwoBytes) {
	unsafe { &mut *this_ptr.inner }.channel_id = val.data;
}
/// The signature of the channel acceptor (fundee) on the funding transaction
#[no_mangle]
pub extern "C" fn FundingSigned_get_signature(this_ptr: &FundingSigned) -> crate::c_types::Signature {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.signature;
	crate::c_types::Signature::from_rust(&(*inner_val))
}
/// The signature of the channel acceptor (fundee) on the funding transaction
#[no_mangle]
pub extern "C" fn FundingSigned_set_signature(this_ptr: &mut FundingSigned, mut val: crate::c_types::Signature) {
	unsafe { &mut *this_ptr.inner }.signature = val.into_rust();
}
#[must_use]
#[no_mangle]
pub extern "C" fn FundingSigned_new(mut channel_id_arg: crate::c_types::ThirtyTwoBytes, mut signature_arg: crate::c_types::Signature) -> FundingSigned {
	FundingSigned { inner: Box::into_raw(Box::new(nativeFundingSigned {
		channel_id: channel_id_arg.data,
		signature: signature_arg.into_rust(),
	})), is_owned: true }
}
impl Clone for FundingSigned {
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
pub(crate) extern "C" fn FundingSigned_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeFundingSigned)).clone() })) as *mut c_void
}
#[no_mangle]
pub extern "C" fn FundingSigned_clone(orig: &FundingSigned) -> FundingSigned {
	orig.clone()
}

use lightning::ln::msgs::FundingLocked as nativeFundingLockedImport;
type nativeFundingLocked = nativeFundingLockedImport;

/// A funding_locked message to be sent or received from a peer
#[must_use]
#[repr(C)]
pub struct FundingLocked {
	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeFundingLocked,
	pub is_owned: bool,
}

impl Drop for FundingLocked {
	fn drop(&mut self) {
		if self.is_owned && !self.inner.is_null() {
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
#[no_mangle]
pub extern "C" fn FundingLocked_free(this_ptr: FundingLocked) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn FundingLocked_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeFundingLocked); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl FundingLocked {
	pub(crate) fn take_inner(mut self) -> *mut nativeFundingLocked {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}
/// The channel ID
#[no_mangle]
pub extern "C" fn FundingLocked_get_channel_id(this_ptr: &FundingLocked) -> *const [u8; 32] {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.channel_id;
	&(*inner_val)
}
/// The channel ID
#[no_mangle]
pub extern "C" fn FundingLocked_set_channel_id(this_ptr: &mut FundingLocked, mut val: crate::c_types::ThirtyTwoBytes) {
	unsafe { &mut *this_ptr.inner }.channel_id = val.data;
}
/// The per-commitment point of the second commitment transaction
#[no_mangle]
pub extern "C" fn FundingLocked_get_next_per_commitment_point(this_ptr: &FundingLocked) -> crate::c_types::PublicKey {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.next_per_commitment_point;
	crate::c_types::PublicKey::from_rust(&(*inner_val))
}
/// The per-commitment point of the second commitment transaction
#[no_mangle]
pub extern "C" fn FundingLocked_set_next_per_commitment_point(this_ptr: &mut FundingLocked, mut val: crate::c_types::PublicKey) {
	unsafe { &mut *this_ptr.inner }.next_per_commitment_point = val.into_rust();
}
#[must_use]
#[no_mangle]
pub extern "C" fn FundingLocked_new(mut channel_id_arg: crate::c_types::ThirtyTwoBytes, mut next_per_commitment_point_arg: crate::c_types::PublicKey) -> FundingLocked {
	FundingLocked { inner: Box::into_raw(Box::new(nativeFundingLocked {
		channel_id: channel_id_arg.data,
		next_per_commitment_point: next_per_commitment_point_arg.into_rust(),
	})), is_owned: true }
}
impl Clone for FundingLocked {
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
pub(crate) extern "C" fn FundingLocked_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeFundingLocked)).clone() })) as *mut c_void
}
#[no_mangle]
pub extern "C" fn FundingLocked_clone(orig: &FundingLocked) -> FundingLocked {
	orig.clone()
}

use lightning::ln::msgs::Shutdown as nativeShutdownImport;
type nativeShutdown = nativeShutdownImport;

/// A shutdown message to be sent or received from a peer
#[must_use]
#[repr(C)]
pub struct Shutdown {
	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeShutdown,
	pub is_owned: bool,
}

impl Drop for Shutdown {
	fn drop(&mut self) {
		if self.is_owned && !self.inner.is_null() {
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
#[no_mangle]
pub extern "C" fn Shutdown_free(this_ptr: Shutdown) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn Shutdown_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeShutdown); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl Shutdown {
	pub(crate) fn take_inner(mut self) -> *mut nativeShutdown {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}
/// The channel ID
#[no_mangle]
pub extern "C" fn Shutdown_get_channel_id(this_ptr: &Shutdown) -> *const [u8; 32] {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.channel_id;
	&(*inner_val)
}
/// The channel ID
#[no_mangle]
pub extern "C" fn Shutdown_set_channel_id(this_ptr: &mut Shutdown, mut val: crate::c_types::ThirtyTwoBytes) {
	unsafe { &mut *this_ptr.inner }.channel_id = val.data;
}
/// The destination of this peer's funds on closing.
/// Must be in one of these forms: p2pkh, p2sh, p2wpkh, p2wsh.
#[no_mangle]
pub extern "C" fn Shutdown_get_scriptpubkey(this_ptr: &Shutdown) -> crate::c_types::u8slice {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.scriptpubkey;
	crate::c_types::u8slice::from_slice(&(*inner_val)[..])
}
/// The destination of this peer's funds on closing.
/// Must be in one of these forms: p2pkh, p2sh, p2wpkh, p2wsh.
#[no_mangle]
pub extern "C" fn Shutdown_set_scriptpubkey(this_ptr: &mut Shutdown, mut val: crate::c_types::derived::CVec_u8Z) {
	unsafe { &mut *this_ptr.inner }.scriptpubkey = ::bitcoin::blockdata::script::Script::from(val.into_rust());
}
#[must_use]
#[no_mangle]
pub extern "C" fn Shutdown_new(mut channel_id_arg: crate::c_types::ThirtyTwoBytes, mut scriptpubkey_arg: crate::c_types::derived::CVec_u8Z) -> Shutdown {
	Shutdown { inner: Box::into_raw(Box::new(nativeShutdown {
		channel_id: channel_id_arg.data,
		scriptpubkey: ::bitcoin::blockdata::script::Script::from(scriptpubkey_arg.into_rust()),
	})), is_owned: true }
}
impl Clone for Shutdown {
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
pub(crate) extern "C" fn Shutdown_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeShutdown)).clone() })) as *mut c_void
}
#[no_mangle]
pub extern "C" fn Shutdown_clone(orig: &Shutdown) -> Shutdown {
	orig.clone()
}

use lightning::ln::msgs::ClosingSigned as nativeClosingSignedImport;
type nativeClosingSigned = nativeClosingSignedImport;

/// A closing_signed message to be sent or received from a peer
#[must_use]
#[repr(C)]
pub struct ClosingSigned {
	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeClosingSigned,
	pub is_owned: bool,
}

impl Drop for ClosingSigned {
	fn drop(&mut self) {
		if self.is_owned && !self.inner.is_null() {
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
#[no_mangle]
pub extern "C" fn ClosingSigned_free(this_ptr: ClosingSigned) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn ClosingSigned_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeClosingSigned); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl ClosingSigned {
	pub(crate) fn take_inner(mut self) -> *mut nativeClosingSigned {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}
/// The channel ID
#[no_mangle]
pub extern "C" fn ClosingSigned_get_channel_id(this_ptr: &ClosingSigned) -> *const [u8; 32] {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.channel_id;
	&(*inner_val)
}
/// The channel ID
#[no_mangle]
pub extern "C" fn ClosingSigned_set_channel_id(this_ptr: &mut ClosingSigned, mut val: crate::c_types::ThirtyTwoBytes) {
	unsafe { &mut *this_ptr.inner }.channel_id = val.data;
}
/// The proposed total fee for the closing transaction
#[no_mangle]
pub extern "C" fn ClosingSigned_get_fee_satoshis(this_ptr: &ClosingSigned) -> u64 {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.fee_satoshis;
	(*inner_val)
}
/// The proposed total fee for the closing transaction
#[no_mangle]
pub extern "C" fn ClosingSigned_set_fee_satoshis(this_ptr: &mut ClosingSigned, mut val: u64) {
	unsafe { &mut *this_ptr.inner }.fee_satoshis = val;
}
/// A signature on the closing transaction
#[no_mangle]
pub extern "C" fn ClosingSigned_get_signature(this_ptr: &ClosingSigned) -> crate::c_types::Signature {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.signature;
	crate::c_types::Signature::from_rust(&(*inner_val))
}
/// A signature on the closing transaction
#[no_mangle]
pub extern "C" fn ClosingSigned_set_signature(this_ptr: &mut ClosingSigned, mut val: crate::c_types::Signature) {
	unsafe { &mut *this_ptr.inner }.signature = val.into_rust();
}
#[must_use]
#[no_mangle]
pub extern "C" fn ClosingSigned_new(mut channel_id_arg: crate::c_types::ThirtyTwoBytes, mut fee_satoshis_arg: u64, mut signature_arg: crate::c_types::Signature) -> ClosingSigned {
	ClosingSigned { inner: Box::into_raw(Box::new(nativeClosingSigned {
		channel_id: channel_id_arg.data,
		fee_satoshis: fee_satoshis_arg,
		signature: signature_arg.into_rust(),
	})), is_owned: true }
}
impl Clone for ClosingSigned {
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
pub(crate) extern "C" fn ClosingSigned_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeClosingSigned)).clone() })) as *mut c_void
}
#[no_mangle]
pub extern "C" fn ClosingSigned_clone(orig: &ClosingSigned) -> ClosingSigned {
	orig.clone()
}

use lightning::ln::msgs::UpdateAddHTLC as nativeUpdateAddHTLCImport;
type nativeUpdateAddHTLC = nativeUpdateAddHTLCImport;

/// An update_add_htlc message to be sent or received from a peer
#[must_use]
#[repr(C)]
pub struct UpdateAddHTLC {
	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeUpdateAddHTLC,
	pub is_owned: bool,
}

impl Drop for UpdateAddHTLC {
	fn drop(&mut self) {
		if self.is_owned && !self.inner.is_null() {
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
#[no_mangle]
pub extern "C" fn UpdateAddHTLC_free(this_ptr: UpdateAddHTLC) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn UpdateAddHTLC_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeUpdateAddHTLC); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl UpdateAddHTLC {
	pub(crate) fn take_inner(mut self) -> *mut nativeUpdateAddHTLC {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}
/// The channel ID
#[no_mangle]
pub extern "C" fn UpdateAddHTLC_get_channel_id(this_ptr: &UpdateAddHTLC) -> *const [u8; 32] {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.channel_id;
	&(*inner_val)
}
/// The channel ID
#[no_mangle]
pub extern "C" fn UpdateAddHTLC_set_channel_id(this_ptr: &mut UpdateAddHTLC, mut val: crate::c_types::ThirtyTwoBytes) {
	unsafe { &mut *this_ptr.inner }.channel_id = val.data;
}
/// The HTLC ID
#[no_mangle]
pub extern "C" fn UpdateAddHTLC_get_htlc_id(this_ptr: &UpdateAddHTLC) -> u64 {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.htlc_id;
	(*inner_val)
}
/// The HTLC ID
#[no_mangle]
pub extern "C" fn UpdateAddHTLC_set_htlc_id(this_ptr: &mut UpdateAddHTLC, mut val: u64) {
	unsafe { &mut *this_ptr.inner }.htlc_id = val;
}
/// The HTLC value in milli-satoshi
#[no_mangle]
pub extern "C" fn UpdateAddHTLC_get_amount_msat(this_ptr: &UpdateAddHTLC) -> u64 {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.amount_msat;
	(*inner_val)
}
/// The HTLC value in milli-satoshi
#[no_mangle]
pub extern "C" fn UpdateAddHTLC_set_amount_msat(this_ptr: &mut UpdateAddHTLC, mut val: u64) {
	unsafe { &mut *this_ptr.inner }.amount_msat = val;
}
/// The payment hash, the pre-image of which controls HTLC redemption
#[no_mangle]
pub extern "C" fn UpdateAddHTLC_get_payment_hash(this_ptr: &UpdateAddHTLC) -> *const [u8; 32] {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.payment_hash;
	&(*inner_val).0
}
/// The payment hash, the pre-image of which controls HTLC redemption
#[no_mangle]
pub extern "C" fn UpdateAddHTLC_set_payment_hash(this_ptr: &mut UpdateAddHTLC, mut val: crate::c_types::ThirtyTwoBytes) {
	unsafe { &mut *this_ptr.inner }.payment_hash = ::lightning::ln::channelmanager::PaymentHash(val.data);
}
/// The expiry height of the HTLC
#[no_mangle]
pub extern "C" fn UpdateAddHTLC_get_cltv_expiry(this_ptr: &UpdateAddHTLC) -> u32 {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.cltv_expiry;
	(*inner_val)
}
/// The expiry height of the HTLC
#[no_mangle]
pub extern "C" fn UpdateAddHTLC_set_cltv_expiry(this_ptr: &mut UpdateAddHTLC, mut val: u32) {
	unsafe { &mut *this_ptr.inner }.cltv_expiry = val;
}
impl Clone for UpdateAddHTLC {
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
pub(crate) extern "C" fn UpdateAddHTLC_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeUpdateAddHTLC)).clone() })) as *mut c_void
}
#[no_mangle]
pub extern "C" fn UpdateAddHTLC_clone(orig: &UpdateAddHTLC) -> UpdateAddHTLC {
	orig.clone()
}

use lightning::ln::msgs::UpdateFulfillHTLC as nativeUpdateFulfillHTLCImport;
type nativeUpdateFulfillHTLC = nativeUpdateFulfillHTLCImport;

/// An update_fulfill_htlc message to be sent or received from a peer
#[must_use]
#[repr(C)]
pub struct UpdateFulfillHTLC {
	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeUpdateFulfillHTLC,
	pub is_owned: bool,
}

impl Drop for UpdateFulfillHTLC {
	fn drop(&mut self) {
		if self.is_owned && !self.inner.is_null() {
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
#[no_mangle]
pub extern "C" fn UpdateFulfillHTLC_free(this_ptr: UpdateFulfillHTLC) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn UpdateFulfillHTLC_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeUpdateFulfillHTLC); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl UpdateFulfillHTLC {
	pub(crate) fn take_inner(mut self) -> *mut nativeUpdateFulfillHTLC {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}
/// The channel ID
#[no_mangle]
pub extern "C" fn UpdateFulfillHTLC_get_channel_id(this_ptr: &UpdateFulfillHTLC) -> *const [u8; 32] {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.channel_id;
	&(*inner_val)
}
/// The channel ID
#[no_mangle]
pub extern "C" fn UpdateFulfillHTLC_set_channel_id(this_ptr: &mut UpdateFulfillHTLC, mut val: crate::c_types::ThirtyTwoBytes) {
	unsafe { &mut *this_ptr.inner }.channel_id = val.data;
}
/// The HTLC ID
#[no_mangle]
pub extern "C" fn UpdateFulfillHTLC_get_htlc_id(this_ptr: &UpdateFulfillHTLC) -> u64 {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.htlc_id;
	(*inner_val)
}
/// The HTLC ID
#[no_mangle]
pub extern "C" fn UpdateFulfillHTLC_set_htlc_id(this_ptr: &mut UpdateFulfillHTLC, mut val: u64) {
	unsafe { &mut *this_ptr.inner }.htlc_id = val;
}
/// The pre-image of the payment hash, allowing HTLC redemption
#[no_mangle]
pub extern "C" fn UpdateFulfillHTLC_get_payment_preimage(this_ptr: &UpdateFulfillHTLC) -> *const [u8; 32] {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.payment_preimage;
	&(*inner_val).0
}
/// The pre-image of the payment hash, allowing HTLC redemption
#[no_mangle]
pub extern "C" fn UpdateFulfillHTLC_set_payment_preimage(this_ptr: &mut UpdateFulfillHTLC, mut val: crate::c_types::ThirtyTwoBytes) {
	unsafe { &mut *this_ptr.inner }.payment_preimage = ::lightning::ln::channelmanager::PaymentPreimage(val.data);
}
#[must_use]
#[no_mangle]
pub extern "C" fn UpdateFulfillHTLC_new(mut channel_id_arg: crate::c_types::ThirtyTwoBytes, mut htlc_id_arg: u64, mut payment_preimage_arg: crate::c_types::ThirtyTwoBytes) -> UpdateFulfillHTLC {
	UpdateFulfillHTLC { inner: Box::into_raw(Box::new(nativeUpdateFulfillHTLC {
		channel_id: channel_id_arg.data,
		htlc_id: htlc_id_arg,
		payment_preimage: ::lightning::ln::channelmanager::PaymentPreimage(payment_preimage_arg.data),
	})), is_owned: true }
}
impl Clone for UpdateFulfillHTLC {
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
pub(crate) extern "C" fn UpdateFulfillHTLC_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeUpdateFulfillHTLC)).clone() })) as *mut c_void
}
#[no_mangle]
pub extern "C" fn UpdateFulfillHTLC_clone(orig: &UpdateFulfillHTLC) -> UpdateFulfillHTLC {
	orig.clone()
}

use lightning::ln::msgs::UpdateFailHTLC as nativeUpdateFailHTLCImport;
type nativeUpdateFailHTLC = nativeUpdateFailHTLCImport;

/// An update_fail_htlc message to be sent or received from a peer
#[must_use]
#[repr(C)]
pub struct UpdateFailHTLC {
	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeUpdateFailHTLC,
	pub is_owned: bool,
}

impl Drop for UpdateFailHTLC {
	fn drop(&mut self) {
		if self.is_owned && !self.inner.is_null() {
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
#[no_mangle]
pub extern "C" fn UpdateFailHTLC_free(this_ptr: UpdateFailHTLC) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn UpdateFailHTLC_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeUpdateFailHTLC); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl UpdateFailHTLC {
	pub(crate) fn take_inner(mut self) -> *mut nativeUpdateFailHTLC {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}
/// The channel ID
#[no_mangle]
pub extern "C" fn UpdateFailHTLC_get_channel_id(this_ptr: &UpdateFailHTLC) -> *const [u8; 32] {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.channel_id;
	&(*inner_val)
}
/// The channel ID
#[no_mangle]
pub extern "C" fn UpdateFailHTLC_set_channel_id(this_ptr: &mut UpdateFailHTLC, mut val: crate::c_types::ThirtyTwoBytes) {
	unsafe { &mut *this_ptr.inner }.channel_id = val.data;
}
/// The HTLC ID
#[no_mangle]
pub extern "C" fn UpdateFailHTLC_get_htlc_id(this_ptr: &UpdateFailHTLC) -> u64 {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.htlc_id;
	(*inner_val)
}
/// The HTLC ID
#[no_mangle]
pub extern "C" fn UpdateFailHTLC_set_htlc_id(this_ptr: &mut UpdateFailHTLC, mut val: u64) {
	unsafe { &mut *this_ptr.inner }.htlc_id = val;
}
impl Clone for UpdateFailHTLC {
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
pub(crate) extern "C" fn UpdateFailHTLC_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeUpdateFailHTLC)).clone() })) as *mut c_void
}
#[no_mangle]
pub extern "C" fn UpdateFailHTLC_clone(orig: &UpdateFailHTLC) -> UpdateFailHTLC {
	orig.clone()
}

use lightning::ln::msgs::UpdateFailMalformedHTLC as nativeUpdateFailMalformedHTLCImport;
type nativeUpdateFailMalformedHTLC = nativeUpdateFailMalformedHTLCImport;

/// An update_fail_malformed_htlc message to be sent or received from a peer
#[must_use]
#[repr(C)]
pub struct UpdateFailMalformedHTLC {
	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeUpdateFailMalformedHTLC,
	pub is_owned: bool,
}

impl Drop for UpdateFailMalformedHTLC {
	fn drop(&mut self) {
		if self.is_owned && !self.inner.is_null() {
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
#[no_mangle]
pub extern "C" fn UpdateFailMalformedHTLC_free(this_ptr: UpdateFailMalformedHTLC) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn UpdateFailMalformedHTLC_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeUpdateFailMalformedHTLC); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl UpdateFailMalformedHTLC {
	pub(crate) fn take_inner(mut self) -> *mut nativeUpdateFailMalformedHTLC {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}
/// The channel ID
#[no_mangle]
pub extern "C" fn UpdateFailMalformedHTLC_get_channel_id(this_ptr: &UpdateFailMalformedHTLC) -> *const [u8; 32] {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.channel_id;
	&(*inner_val)
}
/// The channel ID
#[no_mangle]
pub extern "C" fn UpdateFailMalformedHTLC_set_channel_id(this_ptr: &mut UpdateFailMalformedHTLC, mut val: crate::c_types::ThirtyTwoBytes) {
	unsafe { &mut *this_ptr.inner }.channel_id = val.data;
}
/// The HTLC ID
#[no_mangle]
pub extern "C" fn UpdateFailMalformedHTLC_get_htlc_id(this_ptr: &UpdateFailMalformedHTLC) -> u64 {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.htlc_id;
	(*inner_val)
}
/// The HTLC ID
#[no_mangle]
pub extern "C" fn UpdateFailMalformedHTLC_set_htlc_id(this_ptr: &mut UpdateFailMalformedHTLC, mut val: u64) {
	unsafe { &mut *this_ptr.inner }.htlc_id = val;
}
/// The failure code
#[no_mangle]
pub extern "C" fn UpdateFailMalformedHTLC_get_failure_code(this_ptr: &UpdateFailMalformedHTLC) -> u16 {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.failure_code;
	(*inner_val)
}
/// The failure code
#[no_mangle]
pub extern "C" fn UpdateFailMalformedHTLC_set_failure_code(this_ptr: &mut UpdateFailMalformedHTLC, mut val: u16) {
	unsafe { &mut *this_ptr.inner }.failure_code = val;
}
impl Clone for UpdateFailMalformedHTLC {
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
pub(crate) extern "C" fn UpdateFailMalformedHTLC_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeUpdateFailMalformedHTLC)).clone() })) as *mut c_void
}
#[no_mangle]
pub extern "C" fn UpdateFailMalformedHTLC_clone(orig: &UpdateFailMalformedHTLC) -> UpdateFailMalformedHTLC {
	orig.clone()
}

use lightning::ln::msgs::CommitmentSigned as nativeCommitmentSignedImport;
type nativeCommitmentSigned = nativeCommitmentSignedImport;

/// A commitment_signed message to be sent or received from a peer
#[must_use]
#[repr(C)]
pub struct CommitmentSigned {
	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeCommitmentSigned,
	pub is_owned: bool,
}

impl Drop for CommitmentSigned {
	fn drop(&mut self) {
		if self.is_owned && !self.inner.is_null() {
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
#[no_mangle]
pub extern "C" fn CommitmentSigned_free(this_ptr: CommitmentSigned) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn CommitmentSigned_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeCommitmentSigned); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl CommitmentSigned {
	pub(crate) fn take_inner(mut self) -> *mut nativeCommitmentSigned {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}
/// The channel ID
#[no_mangle]
pub extern "C" fn CommitmentSigned_get_channel_id(this_ptr: &CommitmentSigned) -> *const [u8; 32] {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.channel_id;
	&(*inner_val)
}
/// The channel ID
#[no_mangle]
pub extern "C" fn CommitmentSigned_set_channel_id(this_ptr: &mut CommitmentSigned, mut val: crate::c_types::ThirtyTwoBytes) {
	unsafe { &mut *this_ptr.inner }.channel_id = val.data;
}
/// A signature on the commitment transaction
#[no_mangle]
pub extern "C" fn CommitmentSigned_get_signature(this_ptr: &CommitmentSigned) -> crate::c_types::Signature {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.signature;
	crate::c_types::Signature::from_rust(&(*inner_val))
}
/// A signature on the commitment transaction
#[no_mangle]
pub extern "C" fn CommitmentSigned_set_signature(this_ptr: &mut CommitmentSigned, mut val: crate::c_types::Signature) {
	unsafe { &mut *this_ptr.inner }.signature = val.into_rust();
}
/// Signatures on the HTLC transactions
#[no_mangle]
pub extern "C" fn CommitmentSigned_set_htlc_signatures(this_ptr: &mut CommitmentSigned, mut val: crate::c_types::derived::CVec_SignatureZ) {
	let mut local_val = Vec::new(); for mut item in val.into_rust().drain(..) { local_val.push( { item.into_rust() }); };
	unsafe { &mut *this_ptr.inner }.htlc_signatures = local_val;
}
#[must_use]
#[no_mangle]
pub extern "C" fn CommitmentSigned_new(mut channel_id_arg: crate::c_types::ThirtyTwoBytes, mut signature_arg: crate::c_types::Signature, mut htlc_signatures_arg: crate::c_types::derived::CVec_SignatureZ) -> CommitmentSigned {
	let mut local_htlc_signatures_arg = Vec::new(); for mut item in htlc_signatures_arg.into_rust().drain(..) { local_htlc_signatures_arg.push( { item.into_rust() }); };
	CommitmentSigned { inner: Box::into_raw(Box::new(nativeCommitmentSigned {
		channel_id: channel_id_arg.data,
		signature: signature_arg.into_rust(),
		htlc_signatures: local_htlc_signatures_arg,
	})), is_owned: true }
}
impl Clone for CommitmentSigned {
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
pub(crate) extern "C" fn CommitmentSigned_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeCommitmentSigned)).clone() })) as *mut c_void
}
#[no_mangle]
pub extern "C" fn CommitmentSigned_clone(orig: &CommitmentSigned) -> CommitmentSigned {
	orig.clone()
}

use lightning::ln::msgs::RevokeAndACK as nativeRevokeAndACKImport;
type nativeRevokeAndACK = nativeRevokeAndACKImport;

/// A revoke_and_ack message to be sent or received from a peer
#[must_use]
#[repr(C)]
pub struct RevokeAndACK {
	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeRevokeAndACK,
	pub is_owned: bool,
}

impl Drop for RevokeAndACK {
	fn drop(&mut self) {
		if self.is_owned && !self.inner.is_null() {
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
#[no_mangle]
pub extern "C" fn RevokeAndACK_free(this_ptr: RevokeAndACK) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn RevokeAndACK_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeRevokeAndACK); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl RevokeAndACK {
	pub(crate) fn take_inner(mut self) -> *mut nativeRevokeAndACK {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}
/// The channel ID
#[no_mangle]
pub extern "C" fn RevokeAndACK_get_channel_id(this_ptr: &RevokeAndACK) -> *const [u8; 32] {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.channel_id;
	&(*inner_val)
}
/// The channel ID
#[no_mangle]
pub extern "C" fn RevokeAndACK_set_channel_id(this_ptr: &mut RevokeAndACK, mut val: crate::c_types::ThirtyTwoBytes) {
	unsafe { &mut *this_ptr.inner }.channel_id = val.data;
}
/// The secret corresponding to the per-commitment point
#[no_mangle]
pub extern "C" fn RevokeAndACK_get_per_commitment_secret(this_ptr: &RevokeAndACK) -> *const [u8; 32] {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.per_commitment_secret;
	&(*inner_val)
}
/// The secret corresponding to the per-commitment point
#[no_mangle]
pub extern "C" fn RevokeAndACK_set_per_commitment_secret(this_ptr: &mut RevokeAndACK, mut val: crate::c_types::ThirtyTwoBytes) {
	unsafe { &mut *this_ptr.inner }.per_commitment_secret = val.data;
}
/// The next sender-broadcast commitment transaction's per-commitment point
#[no_mangle]
pub extern "C" fn RevokeAndACK_get_next_per_commitment_point(this_ptr: &RevokeAndACK) -> crate::c_types::PublicKey {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.next_per_commitment_point;
	crate::c_types::PublicKey::from_rust(&(*inner_val))
}
/// The next sender-broadcast commitment transaction's per-commitment point
#[no_mangle]
pub extern "C" fn RevokeAndACK_set_next_per_commitment_point(this_ptr: &mut RevokeAndACK, mut val: crate::c_types::PublicKey) {
	unsafe { &mut *this_ptr.inner }.next_per_commitment_point = val.into_rust();
}
#[must_use]
#[no_mangle]
pub extern "C" fn RevokeAndACK_new(mut channel_id_arg: crate::c_types::ThirtyTwoBytes, mut per_commitment_secret_arg: crate::c_types::ThirtyTwoBytes, mut next_per_commitment_point_arg: crate::c_types::PublicKey) -> RevokeAndACK {
	RevokeAndACK { inner: Box::into_raw(Box::new(nativeRevokeAndACK {
		channel_id: channel_id_arg.data,
		per_commitment_secret: per_commitment_secret_arg.data,
		next_per_commitment_point: next_per_commitment_point_arg.into_rust(),
	})), is_owned: true }
}
impl Clone for RevokeAndACK {
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
pub(crate) extern "C" fn RevokeAndACK_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeRevokeAndACK)).clone() })) as *mut c_void
}
#[no_mangle]
pub extern "C" fn RevokeAndACK_clone(orig: &RevokeAndACK) -> RevokeAndACK {
	orig.clone()
}

use lightning::ln::msgs::UpdateFee as nativeUpdateFeeImport;
type nativeUpdateFee = nativeUpdateFeeImport;

/// An update_fee message to be sent or received from a peer
#[must_use]
#[repr(C)]
pub struct UpdateFee {
	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeUpdateFee,
	pub is_owned: bool,
}

impl Drop for UpdateFee {
	fn drop(&mut self) {
		if self.is_owned && !self.inner.is_null() {
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
#[no_mangle]
pub extern "C" fn UpdateFee_free(this_ptr: UpdateFee) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn UpdateFee_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeUpdateFee); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl UpdateFee {
	pub(crate) fn take_inner(mut self) -> *mut nativeUpdateFee {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}
/// The channel ID
#[no_mangle]
pub extern "C" fn UpdateFee_get_channel_id(this_ptr: &UpdateFee) -> *const [u8; 32] {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.channel_id;
	&(*inner_val)
}
/// The channel ID
#[no_mangle]
pub extern "C" fn UpdateFee_set_channel_id(this_ptr: &mut UpdateFee, mut val: crate::c_types::ThirtyTwoBytes) {
	unsafe { &mut *this_ptr.inner }.channel_id = val.data;
}
/// Fee rate per 1000-weight of the transaction
#[no_mangle]
pub extern "C" fn UpdateFee_get_feerate_per_kw(this_ptr: &UpdateFee) -> u32 {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.feerate_per_kw;
	(*inner_val)
}
/// Fee rate per 1000-weight of the transaction
#[no_mangle]
pub extern "C" fn UpdateFee_set_feerate_per_kw(this_ptr: &mut UpdateFee, mut val: u32) {
	unsafe { &mut *this_ptr.inner }.feerate_per_kw = val;
}
#[must_use]
#[no_mangle]
pub extern "C" fn UpdateFee_new(mut channel_id_arg: crate::c_types::ThirtyTwoBytes, mut feerate_per_kw_arg: u32) -> UpdateFee {
	UpdateFee { inner: Box::into_raw(Box::new(nativeUpdateFee {
		channel_id: channel_id_arg.data,
		feerate_per_kw: feerate_per_kw_arg,
	})), is_owned: true }
}
impl Clone for UpdateFee {
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
pub(crate) extern "C" fn UpdateFee_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeUpdateFee)).clone() })) as *mut c_void
}
#[no_mangle]
pub extern "C" fn UpdateFee_clone(orig: &UpdateFee) -> UpdateFee {
	orig.clone()
}

use lightning::ln::msgs::DataLossProtect as nativeDataLossProtectImport;
type nativeDataLossProtect = nativeDataLossProtectImport;

/// Proof that the sender knows the per-commitment secret of the previous commitment transaction.
/// This is used to convince the recipient that the channel is at a certain commitment
/// number even if they lost that data due to a local failure.  Of course, the peer may lie
/// and even later commitments may have been revoked.
#[must_use]
#[repr(C)]
pub struct DataLossProtect {
	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeDataLossProtect,
	pub is_owned: bool,
}

impl Drop for DataLossProtect {
	fn drop(&mut self) {
		if self.is_owned && !self.inner.is_null() {
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
#[no_mangle]
pub extern "C" fn DataLossProtect_free(this_ptr: DataLossProtect) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn DataLossProtect_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeDataLossProtect); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl DataLossProtect {
	pub(crate) fn take_inner(mut self) -> *mut nativeDataLossProtect {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}
/// Proof that the sender knows the per-commitment secret of a specific commitment transaction
/// belonging to the recipient
#[no_mangle]
pub extern "C" fn DataLossProtect_get_your_last_per_commitment_secret(this_ptr: &DataLossProtect) -> *const [u8; 32] {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.your_last_per_commitment_secret;
	&(*inner_val)
}
/// Proof that the sender knows the per-commitment secret of a specific commitment transaction
/// belonging to the recipient
#[no_mangle]
pub extern "C" fn DataLossProtect_set_your_last_per_commitment_secret(this_ptr: &mut DataLossProtect, mut val: crate::c_types::ThirtyTwoBytes) {
	unsafe { &mut *this_ptr.inner }.your_last_per_commitment_secret = val.data;
}
/// The sender's per-commitment point for their current commitment transaction
#[no_mangle]
pub extern "C" fn DataLossProtect_get_my_current_per_commitment_point(this_ptr: &DataLossProtect) -> crate::c_types::PublicKey {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.my_current_per_commitment_point;
	crate::c_types::PublicKey::from_rust(&(*inner_val))
}
/// The sender's per-commitment point for their current commitment transaction
#[no_mangle]
pub extern "C" fn DataLossProtect_set_my_current_per_commitment_point(this_ptr: &mut DataLossProtect, mut val: crate::c_types::PublicKey) {
	unsafe { &mut *this_ptr.inner }.my_current_per_commitment_point = val.into_rust();
}
#[must_use]
#[no_mangle]
pub extern "C" fn DataLossProtect_new(mut your_last_per_commitment_secret_arg: crate::c_types::ThirtyTwoBytes, mut my_current_per_commitment_point_arg: crate::c_types::PublicKey) -> DataLossProtect {
	DataLossProtect { inner: Box::into_raw(Box::new(nativeDataLossProtect {
		your_last_per_commitment_secret: your_last_per_commitment_secret_arg.data,
		my_current_per_commitment_point: my_current_per_commitment_point_arg.into_rust(),
	})), is_owned: true }
}
impl Clone for DataLossProtect {
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
pub(crate) extern "C" fn DataLossProtect_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeDataLossProtect)).clone() })) as *mut c_void
}
#[no_mangle]
pub extern "C" fn DataLossProtect_clone(orig: &DataLossProtect) -> DataLossProtect {
	orig.clone()
}

use lightning::ln::msgs::ChannelReestablish as nativeChannelReestablishImport;
type nativeChannelReestablish = nativeChannelReestablishImport;

/// A channel_reestablish message to be sent or received from a peer
#[must_use]
#[repr(C)]
pub struct ChannelReestablish {
	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeChannelReestablish,
	pub is_owned: bool,
}

impl Drop for ChannelReestablish {
	fn drop(&mut self) {
		if self.is_owned && !self.inner.is_null() {
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
#[no_mangle]
pub extern "C" fn ChannelReestablish_free(this_ptr: ChannelReestablish) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn ChannelReestablish_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeChannelReestablish); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl ChannelReestablish {
	pub(crate) fn take_inner(mut self) -> *mut nativeChannelReestablish {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}
/// The channel ID
#[no_mangle]
pub extern "C" fn ChannelReestablish_get_channel_id(this_ptr: &ChannelReestablish) -> *const [u8; 32] {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.channel_id;
	&(*inner_val)
}
/// The channel ID
#[no_mangle]
pub extern "C" fn ChannelReestablish_set_channel_id(this_ptr: &mut ChannelReestablish, mut val: crate::c_types::ThirtyTwoBytes) {
	unsafe { &mut *this_ptr.inner }.channel_id = val.data;
}
/// The next commitment number for the sender
#[no_mangle]
pub extern "C" fn ChannelReestablish_get_next_local_commitment_number(this_ptr: &ChannelReestablish) -> u64 {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.next_local_commitment_number;
	(*inner_val)
}
/// The next commitment number for the sender
#[no_mangle]
pub extern "C" fn ChannelReestablish_set_next_local_commitment_number(this_ptr: &mut ChannelReestablish, mut val: u64) {
	unsafe { &mut *this_ptr.inner }.next_local_commitment_number = val;
}
/// The next commitment number for the recipient
#[no_mangle]
pub extern "C" fn ChannelReestablish_get_next_remote_commitment_number(this_ptr: &ChannelReestablish) -> u64 {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.next_remote_commitment_number;
	(*inner_val)
}
/// The next commitment number for the recipient
#[no_mangle]
pub extern "C" fn ChannelReestablish_set_next_remote_commitment_number(this_ptr: &mut ChannelReestablish, mut val: u64) {
	unsafe { &mut *this_ptr.inner }.next_remote_commitment_number = val;
}
impl Clone for ChannelReestablish {
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
pub(crate) extern "C" fn ChannelReestablish_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeChannelReestablish)).clone() })) as *mut c_void
}
#[no_mangle]
pub extern "C" fn ChannelReestablish_clone(orig: &ChannelReestablish) -> ChannelReestablish {
	orig.clone()
}

use lightning::ln::msgs::AnnouncementSignatures as nativeAnnouncementSignaturesImport;
type nativeAnnouncementSignatures = nativeAnnouncementSignaturesImport;

/// An announcement_signatures message to be sent or received from a peer
#[must_use]
#[repr(C)]
pub struct AnnouncementSignatures {
	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeAnnouncementSignatures,
	pub is_owned: bool,
}

impl Drop for AnnouncementSignatures {
	fn drop(&mut self) {
		if self.is_owned && !self.inner.is_null() {
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
#[no_mangle]
pub extern "C" fn AnnouncementSignatures_free(this_ptr: AnnouncementSignatures) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn AnnouncementSignatures_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeAnnouncementSignatures); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl AnnouncementSignatures {
	pub(crate) fn take_inner(mut self) -> *mut nativeAnnouncementSignatures {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}
/// The channel ID
#[no_mangle]
pub extern "C" fn AnnouncementSignatures_get_channel_id(this_ptr: &AnnouncementSignatures) -> *const [u8; 32] {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.channel_id;
	&(*inner_val)
}
/// The channel ID
#[no_mangle]
pub extern "C" fn AnnouncementSignatures_set_channel_id(this_ptr: &mut AnnouncementSignatures, mut val: crate::c_types::ThirtyTwoBytes) {
	unsafe { &mut *this_ptr.inner }.channel_id = val.data;
}
/// The short channel ID
#[no_mangle]
pub extern "C" fn AnnouncementSignatures_get_short_channel_id(this_ptr: &AnnouncementSignatures) -> u64 {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.short_channel_id;
	(*inner_val)
}
/// The short channel ID
#[no_mangle]
pub extern "C" fn AnnouncementSignatures_set_short_channel_id(this_ptr: &mut AnnouncementSignatures, mut val: u64) {
	unsafe { &mut *this_ptr.inner }.short_channel_id = val;
}
/// A signature by the node key
#[no_mangle]
pub extern "C" fn AnnouncementSignatures_get_node_signature(this_ptr: &AnnouncementSignatures) -> crate::c_types::Signature {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.node_signature;
	crate::c_types::Signature::from_rust(&(*inner_val))
}
/// A signature by the node key
#[no_mangle]
pub extern "C" fn AnnouncementSignatures_set_node_signature(this_ptr: &mut AnnouncementSignatures, mut val: crate::c_types::Signature) {
	unsafe { &mut *this_ptr.inner }.node_signature = val.into_rust();
}
/// A signature by the funding key
#[no_mangle]
pub extern "C" fn AnnouncementSignatures_get_bitcoin_signature(this_ptr: &AnnouncementSignatures) -> crate::c_types::Signature {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.bitcoin_signature;
	crate::c_types::Signature::from_rust(&(*inner_val))
}
/// A signature by the funding key
#[no_mangle]
pub extern "C" fn AnnouncementSignatures_set_bitcoin_signature(this_ptr: &mut AnnouncementSignatures, mut val: crate::c_types::Signature) {
	unsafe { &mut *this_ptr.inner }.bitcoin_signature = val.into_rust();
}
#[must_use]
#[no_mangle]
pub extern "C" fn AnnouncementSignatures_new(mut channel_id_arg: crate::c_types::ThirtyTwoBytes, mut short_channel_id_arg: u64, mut node_signature_arg: crate::c_types::Signature, mut bitcoin_signature_arg: crate::c_types::Signature) -> AnnouncementSignatures {
	AnnouncementSignatures { inner: Box::into_raw(Box::new(nativeAnnouncementSignatures {
		channel_id: channel_id_arg.data,
		short_channel_id: short_channel_id_arg,
		node_signature: node_signature_arg.into_rust(),
		bitcoin_signature: bitcoin_signature_arg.into_rust(),
	})), is_owned: true }
}
impl Clone for AnnouncementSignatures {
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
pub(crate) extern "C" fn AnnouncementSignatures_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeAnnouncementSignatures)).clone() })) as *mut c_void
}
#[no_mangle]
pub extern "C" fn AnnouncementSignatures_clone(orig: &AnnouncementSignatures) -> AnnouncementSignatures {
	orig.clone()
}
/// An address which can be used to connect to a remote peer
#[must_use]
#[derive(Clone)]
#[repr(C)]
pub enum NetAddress {
	/// An IPv4 address/port on which the peer is listening.
	IPv4 {
		addr: crate::c_types::FourBytes,
		port: u16,
	},
	/// An IPv6 address/port on which the peer is listening.
	IPv6 {
		addr: crate::c_types::SixteenBytes,
		port: u16,
	},
	/// An old-style Tor onion address/port on which the peer is listening.
	OnionV2 {
		addr: crate::c_types::TenBytes,
		port: u16,
	},
	/// A new-style Tor onion address/port on which the peer is listening.
	/// To create the human-readable \"hostname\", concatenate ed25519_pubkey, checksum, and version,
	/// wrap as base32 and append \".onion\".
	OnionV3 {
		ed25519_pubkey: crate::c_types::ThirtyTwoBytes,
		checksum: u16,
		version: u8,
		port: u16,
	},
}
use lightning::ln::msgs::NetAddress as nativeNetAddress;
impl NetAddress {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeNetAddress {
		match self {
			NetAddress::IPv4 {ref addr, ref port, } => {
				let mut addr_nonref = (*addr).clone();
				let mut port_nonref = (*port).clone();
				nativeNetAddress::IPv4 {
					addr: addr_nonref.data,
					port: port_nonref,
				}
			},
			NetAddress::IPv6 {ref addr, ref port, } => {
				let mut addr_nonref = (*addr).clone();
				let mut port_nonref = (*port).clone();
				nativeNetAddress::IPv6 {
					addr: addr_nonref.data,
					port: port_nonref,
				}
			},
			NetAddress::OnionV2 {ref addr, ref port, } => {
				let mut addr_nonref = (*addr).clone();
				let mut port_nonref = (*port).clone();
				nativeNetAddress::OnionV2 {
					addr: addr_nonref.data,
					port: port_nonref,
				}
			},
			NetAddress::OnionV3 {ref ed25519_pubkey, ref checksum, ref version, ref port, } => {
				let mut ed25519_pubkey_nonref = (*ed25519_pubkey).clone();
				let mut checksum_nonref = (*checksum).clone();
				let mut version_nonref = (*version).clone();
				let mut port_nonref = (*port).clone();
				nativeNetAddress::OnionV3 {
					ed25519_pubkey: ed25519_pubkey_nonref.data,
					checksum: checksum_nonref,
					version: version_nonref,
					port: port_nonref,
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeNetAddress {
		match self {
			NetAddress::IPv4 {mut addr, mut port, } => {
				nativeNetAddress::IPv4 {
					addr: addr.data,
					port: port,
				}
			},
			NetAddress::IPv6 {mut addr, mut port, } => {
				nativeNetAddress::IPv6 {
					addr: addr.data,
					port: port,
				}
			},
			NetAddress::OnionV2 {mut addr, mut port, } => {
				nativeNetAddress::OnionV2 {
					addr: addr.data,
					port: port,
				}
			},
			NetAddress::OnionV3 {mut ed25519_pubkey, mut checksum, mut version, mut port, } => {
				nativeNetAddress::OnionV3 {
					ed25519_pubkey: ed25519_pubkey.data,
					checksum: checksum,
					version: version,
					port: port,
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &nativeNetAddress) -> Self {
		match native {
			nativeNetAddress::IPv4 {ref addr, ref port, } => {
				let mut addr_nonref = (*addr).clone();
				let mut port_nonref = (*port).clone();
				NetAddress::IPv4 {
					addr: crate::c_types::FourBytes { data: addr_nonref },
					port: port_nonref,
				}
			},
			nativeNetAddress::IPv6 {ref addr, ref port, } => {
				let mut addr_nonref = (*addr).clone();
				let mut port_nonref = (*port).clone();
				NetAddress::IPv6 {
					addr: crate::c_types::SixteenBytes { data: addr_nonref },
					port: port_nonref,
				}
			},
			nativeNetAddress::OnionV2 {ref addr, ref port, } => {
				let mut addr_nonref = (*addr).clone();
				let mut port_nonref = (*port).clone();
				NetAddress::OnionV2 {
					addr: crate::c_types::TenBytes { data: addr_nonref },
					port: port_nonref,
				}
			},
			nativeNetAddress::OnionV3 {ref ed25519_pubkey, ref checksum, ref version, ref port, } => {
				let mut ed25519_pubkey_nonref = (*ed25519_pubkey).clone();
				let mut checksum_nonref = (*checksum).clone();
				let mut version_nonref = (*version).clone();
				let mut port_nonref = (*port).clone();
				NetAddress::OnionV3 {
					ed25519_pubkey: crate::c_types::ThirtyTwoBytes { data: ed25519_pubkey_nonref },
					checksum: checksum_nonref,
					version: version_nonref,
					port: port_nonref,
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeNetAddress) -> Self {
		match native {
			nativeNetAddress::IPv4 {mut addr, mut port, } => {
				NetAddress::IPv4 {
					addr: crate::c_types::FourBytes { data: addr },
					port: port,
				}
			},
			nativeNetAddress::IPv6 {mut addr, mut port, } => {
				NetAddress::IPv6 {
					addr: crate::c_types::SixteenBytes { data: addr },
					port: port,
				}
			},
			nativeNetAddress::OnionV2 {mut addr, mut port, } => {
				NetAddress::OnionV2 {
					addr: crate::c_types::TenBytes { data: addr },
					port: port,
				}
			},
			nativeNetAddress::OnionV3 {mut ed25519_pubkey, mut checksum, mut version, mut port, } => {
				NetAddress::OnionV3 {
					ed25519_pubkey: crate::c_types::ThirtyTwoBytes { data: ed25519_pubkey },
					checksum: checksum,
					version: version,
					port: port,
				}
			},
		}
	}
}
#[no_mangle]
pub extern "C" fn NetAddress_free(this_ptr: NetAddress) { }
#[no_mangle]
pub extern "C" fn NetAddress_clone(orig: &NetAddress) -> NetAddress {
	orig.clone()
}
#[no_mangle]
pub extern "C" fn NetAddress_write(obj: &NetAddress) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(&unsafe { &*obj }.to_native())
}
#[no_mangle]
pub extern "C" fn Result_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_CResult_NetAddressu8ZDecodeErrorZ {
	let res = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { let mut local_res_0 = match o { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::ln::msgs::NetAddress::native_into(o) }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { e }).into() }; local_res_0 }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::ln::msgs::DecodeError { inner: Box::into_raw(Box::new(e)), is_owned: true } }).into() };
	local_res
}

use lightning::ln::msgs::UnsignedNodeAnnouncement as nativeUnsignedNodeAnnouncementImport;
type nativeUnsignedNodeAnnouncement = nativeUnsignedNodeAnnouncementImport;

/// The unsigned part of a node_announcement
#[must_use]
#[repr(C)]
pub struct UnsignedNodeAnnouncement {
	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeUnsignedNodeAnnouncement,
	pub is_owned: bool,
}

impl Drop for UnsignedNodeAnnouncement {
	fn drop(&mut self) {
		if self.is_owned && !self.inner.is_null() {
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
#[no_mangle]
pub extern "C" fn UnsignedNodeAnnouncement_free(this_ptr: UnsignedNodeAnnouncement) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn UnsignedNodeAnnouncement_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeUnsignedNodeAnnouncement); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl UnsignedNodeAnnouncement {
	pub(crate) fn take_inner(mut self) -> *mut nativeUnsignedNodeAnnouncement {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}
/// The advertised features
#[no_mangle]
pub extern "C" fn UnsignedNodeAnnouncement_get_features(this_ptr: &UnsignedNodeAnnouncement) -> crate::ln::features::NodeFeatures {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.features;
	crate::ln::features::NodeFeatures { inner: unsafe { ( (&((*inner_val)) as *const _) as *mut _) }, is_owned: false }
}
/// The advertised features
#[no_mangle]
pub extern "C" fn UnsignedNodeAnnouncement_set_features(this_ptr: &mut UnsignedNodeAnnouncement, mut val: crate::ln::features::NodeFeatures) {
	unsafe { &mut *this_ptr.inner }.features = *unsafe { Box::from_raw(val.take_inner()) };
}
/// A strictly monotonic announcement counter, with gaps allowed
#[no_mangle]
pub extern "C" fn UnsignedNodeAnnouncement_get_timestamp(this_ptr: &UnsignedNodeAnnouncement) -> u32 {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.timestamp;
	(*inner_val)
}
/// A strictly monotonic announcement counter, with gaps allowed
#[no_mangle]
pub extern "C" fn UnsignedNodeAnnouncement_set_timestamp(this_ptr: &mut UnsignedNodeAnnouncement, mut val: u32) {
	unsafe { &mut *this_ptr.inner }.timestamp = val;
}
/// The node_id this announcement originated from (don't rebroadcast the node_announcement back
/// to this node).
#[no_mangle]
pub extern "C" fn UnsignedNodeAnnouncement_get_node_id(this_ptr: &UnsignedNodeAnnouncement) -> crate::c_types::PublicKey {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.node_id;
	crate::c_types::PublicKey::from_rust(&(*inner_val))
}
/// The node_id this announcement originated from (don't rebroadcast the node_announcement back
/// to this node).
#[no_mangle]
pub extern "C" fn UnsignedNodeAnnouncement_set_node_id(this_ptr: &mut UnsignedNodeAnnouncement, mut val: crate::c_types::PublicKey) {
	unsafe { &mut *this_ptr.inner }.node_id = val.into_rust();
}
/// An RGB color for UI purposes
#[no_mangle]
pub extern "C" fn UnsignedNodeAnnouncement_get_rgb(this_ptr: &UnsignedNodeAnnouncement) -> *const [u8; 3] {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.rgb;
	&(*inner_val)
}
/// An RGB color for UI purposes
#[no_mangle]
pub extern "C" fn UnsignedNodeAnnouncement_set_rgb(this_ptr: &mut UnsignedNodeAnnouncement, mut val: crate::c_types::ThreeBytes) {
	unsafe { &mut *this_ptr.inner }.rgb = val.data;
}
/// An alias, for UI purposes.  This should be sanitized before use.  There is no guarantee
/// of uniqueness.
#[no_mangle]
pub extern "C" fn UnsignedNodeAnnouncement_get_alias(this_ptr: &UnsignedNodeAnnouncement) -> *const [u8; 32] {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.alias;
	&(*inner_val)
}
/// An alias, for UI purposes.  This should be sanitized before use.  There is no guarantee
/// of uniqueness.
#[no_mangle]
pub extern "C" fn UnsignedNodeAnnouncement_set_alias(this_ptr: &mut UnsignedNodeAnnouncement, mut val: crate::c_types::ThirtyTwoBytes) {
	unsafe { &mut *this_ptr.inner }.alias = val.data;
}
/// List of addresses on which this node is reachable
#[no_mangle]
pub extern "C" fn UnsignedNodeAnnouncement_set_addresses(this_ptr: &mut UnsignedNodeAnnouncement, mut val: crate::c_types::derived::CVec_NetAddressZ) {
	let mut local_val = Vec::new(); for mut item in val.into_rust().drain(..) { local_val.push( { item.into_native() }); };
	unsafe { &mut *this_ptr.inner }.addresses = local_val;
}
impl Clone for UnsignedNodeAnnouncement {
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
pub(crate) extern "C" fn UnsignedNodeAnnouncement_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeUnsignedNodeAnnouncement)).clone() })) as *mut c_void
}
#[no_mangle]
pub extern "C" fn UnsignedNodeAnnouncement_clone(orig: &UnsignedNodeAnnouncement) -> UnsignedNodeAnnouncement {
	orig.clone()
}

use lightning::ln::msgs::NodeAnnouncement as nativeNodeAnnouncementImport;
type nativeNodeAnnouncement = nativeNodeAnnouncementImport;

/// A node_announcement message to be sent or received from a peer
#[must_use]
#[repr(C)]
pub struct NodeAnnouncement {
	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeNodeAnnouncement,
	pub is_owned: bool,
}

impl Drop for NodeAnnouncement {
	fn drop(&mut self) {
		if self.is_owned && !self.inner.is_null() {
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
#[no_mangle]
pub extern "C" fn NodeAnnouncement_free(this_ptr: NodeAnnouncement) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn NodeAnnouncement_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeNodeAnnouncement); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl NodeAnnouncement {
	pub(crate) fn take_inner(mut self) -> *mut nativeNodeAnnouncement {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}
/// The signature by the node key
#[no_mangle]
pub extern "C" fn NodeAnnouncement_get_signature(this_ptr: &NodeAnnouncement) -> crate::c_types::Signature {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.signature;
	crate::c_types::Signature::from_rust(&(*inner_val))
}
/// The signature by the node key
#[no_mangle]
pub extern "C" fn NodeAnnouncement_set_signature(this_ptr: &mut NodeAnnouncement, mut val: crate::c_types::Signature) {
	unsafe { &mut *this_ptr.inner }.signature = val.into_rust();
}
/// The actual content of the announcement
#[no_mangle]
pub extern "C" fn NodeAnnouncement_get_contents(this_ptr: &NodeAnnouncement) -> crate::ln::msgs::UnsignedNodeAnnouncement {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.contents;
	crate::ln::msgs::UnsignedNodeAnnouncement { inner: unsafe { ( (&((*inner_val)) as *const _) as *mut _) }, is_owned: false }
}
/// The actual content of the announcement
#[no_mangle]
pub extern "C" fn NodeAnnouncement_set_contents(this_ptr: &mut NodeAnnouncement, mut val: crate::ln::msgs::UnsignedNodeAnnouncement) {
	unsafe { &mut *this_ptr.inner }.contents = *unsafe { Box::from_raw(val.take_inner()) };
}
#[must_use]
#[no_mangle]
pub extern "C" fn NodeAnnouncement_new(mut signature_arg: crate::c_types::Signature, mut contents_arg: crate::ln::msgs::UnsignedNodeAnnouncement) -> NodeAnnouncement {
	NodeAnnouncement { inner: Box::into_raw(Box::new(nativeNodeAnnouncement {
		signature: signature_arg.into_rust(),
		contents: *unsafe { Box::from_raw(contents_arg.take_inner()) },
	})), is_owned: true }
}
impl Clone for NodeAnnouncement {
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
pub(crate) extern "C" fn NodeAnnouncement_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeNodeAnnouncement)).clone() })) as *mut c_void
}
#[no_mangle]
pub extern "C" fn NodeAnnouncement_clone(orig: &NodeAnnouncement) -> NodeAnnouncement {
	orig.clone()
}

use lightning::ln::msgs::UnsignedChannelAnnouncement as nativeUnsignedChannelAnnouncementImport;
type nativeUnsignedChannelAnnouncement = nativeUnsignedChannelAnnouncementImport;

/// The unsigned part of a channel_announcement
#[must_use]
#[repr(C)]
pub struct UnsignedChannelAnnouncement {
	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeUnsignedChannelAnnouncement,
	pub is_owned: bool,
}

impl Drop for UnsignedChannelAnnouncement {
	fn drop(&mut self) {
		if self.is_owned && !self.inner.is_null() {
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
#[no_mangle]
pub extern "C" fn UnsignedChannelAnnouncement_free(this_ptr: UnsignedChannelAnnouncement) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn UnsignedChannelAnnouncement_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeUnsignedChannelAnnouncement); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl UnsignedChannelAnnouncement {
	pub(crate) fn take_inner(mut self) -> *mut nativeUnsignedChannelAnnouncement {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}
/// The advertised channel features
#[no_mangle]
pub extern "C" fn UnsignedChannelAnnouncement_get_features(this_ptr: &UnsignedChannelAnnouncement) -> crate::ln::features::ChannelFeatures {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.features;
	crate::ln::features::ChannelFeatures { inner: unsafe { ( (&((*inner_val)) as *const _) as *mut _) }, is_owned: false }
}
/// The advertised channel features
#[no_mangle]
pub extern "C" fn UnsignedChannelAnnouncement_set_features(this_ptr: &mut UnsignedChannelAnnouncement, mut val: crate::ln::features::ChannelFeatures) {
	unsafe { &mut *this_ptr.inner }.features = *unsafe { Box::from_raw(val.take_inner()) };
}
/// The genesis hash of the blockchain where the channel is to be opened
#[no_mangle]
pub extern "C" fn UnsignedChannelAnnouncement_get_chain_hash(this_ptr: &UnsignedChannelAnnouncement) -> *const [u8; 32] {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.chain_hash;
	(*inner_val).as_inner()
}
/// The genesis hash of the blockchain where the channel is to be opened
#[no_mangle]
pub extern "C" fn UnsignedChannelAnnouncement_set_chain_hash(this_ptr: &mut UnsignedChannelAnnouncement, mut val: crate::c_types::ThirtyTwoBytes) {
	unsafe { &mut *this_ptr.inner }.chain_hash = ::bitcoin::hash_types::BlockHash::from_slice(&val.data[..]).unwrap();
}
/// The short channel ID
#[no_mangle]
pub extern "C" fn UnsignedChannelAnnouncement_get_short_channel_id(this_ptr: &UnsignedChannelAnnouncement) -> u64 {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.short_channel_id;
	(*inner_val)
}
/// The short channel ID
#[no_mangle]
pub extern "C" fn UnsignedChannelAnnouncement_set_short_channel_id(this_ptr: &mut UnsignedChannelAnnouncement, mut val: u64) {
	unsafe { &mut *this_ptr.inner }.short_channel_id = val;
}
/// One of the two node_ids which are endpoints of this channel
#[no_mangle]
pub extern "C" fn UnsignedChannelAnnouncement_get_node_id_1(this_ptr: &UnsignedChannelAnnouncement) -> crate::c_types::PublicKey {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.node_id_1;
	crate::c_types::PublicKey::from_rust(&(*inner_val))
}
/// One of the two node_ids which are endpoints of this channel
#[no_mangle]
pub extern "C" fn UnsignedChannelAnnouncement_set_node_id_1(this_ptr: &mut UnsignedChannelAnnouncement, mut val: crate::c_types::PublicKey) {
	unsafe { &mut *this_ptr.inner }.node_id_1 = val.into_rust();
}
/// The other of the two node_ids which are endpoints of this channel
#[no_mangle]
pub extern "C" fn UnsignedChannelAnnouncement_get_node_id_2(this_ptr: &UnsignedChannelAnnouncement) -> crate::c_types::PublicKey {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.node_id_2;
	crate::c_types::PublicKey::from_rust(&(*inner_val))
}
/// The other of the two node_ids which are endpoints of this channel
#[no_mangle]
pub extern "C" fn UnsignedChannelAnnouncement_set_node_id_2(this_ptr: &mut UnsignedChannelAnnouncement, mut val: crate::c_types::PublicKey) {
	unsafe { &mut *this_ptr.inner }.node_id_2 = val.into_rust();
}
/// The funding key for the first node
#[no_mangle]
pub extern "C" fn UnsignedChannelAnnouncement_get_bitcoin_key_1(this_ptr: &UnsignedChannelAnnouncement) -> crate::c_types::PublicKey {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.bitcoin_key_1;
	crate::c_types::PublicKey::from_rust(&(*inner_val))
}
/// The funding key for the first node
#[no_mangle]
pub extern "C" fn UnsignedChannelAnnouncement_set_bitcoin_key_1(this_ptr: &mut UnsignedChannelAnnouncement, mut val: crate::c_types::PublicKey) {
	unsafe { &mut *this_ptr.inner }.bitcoin_key_1 = val.into_rust();
}
/// The funding key for the second node
#[no_mangle]
pub extern "C" fn UnsignedChannelAnnouncement_get_bitcoin_key_2(this_ptr: &UnsignedChannelAnnouncement) -> crate::c_types::PublicKey {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.bitcoin_key_2;
	crate::c_types::PublicKey::from_rust(&(*inner_val))
}
/// The funding key for the second node
#[no_mangle]
pub extern "C" fn UnsignedChannelAnnouncement_set_bitcoin_key_2(this_ptr: &mut UnsignedChannelAnnouncement, mut val: crate::c_types::PublicKey) {
	unsafe { &mut *this_ptr.inner }.bitcoin_key_2 = val.into_rust();
}
impl Clone for UnsignedChannelAnnouncement {
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
pub(crate) extern "C" fn UnsignedChannelAnnouncement_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeUnsignedChannelAnnouncement)).clone() })) as *mut c_void
}
#[no_mangle]
pub extern "C" fn UnsignedChannelAnnouncement_clone(orig: &UnsignedChannelAnnouncement) -> UnsignedChannelAnnouncement {
	orig.clone()
}

use lightning::ln::msgs::ChannelAnnouncement as nativeChannelAnnouncementImport;
type nativeChannelAnnouncement = nativeChannelAnnouncementImport;

/// A channel_announcement message to be sent or received from a peer
#[must_use]
#[repr(C)]
pub struct ChannelAnnouncement {
	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeChannelAnnouncement,
	pub is_owned: bool,
}

impl Drop for ChannelAnnouncement {
	fn drop(&mut self) {
		if self.is_owned && !self.inner.is_null() {
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
#[no_mangle]
pub extern "C" fn ChannelAnnouncement_free(this_ptr: ChannelAnnouncement) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn ChannelAnnouncement_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeChannelAnnouncement); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl ChannelAnnouncement {
	pub(crate) fn take_inner(mut self) -> *mut nativeChannelAnnouncement {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}
/// Authentication of the announcement by the first public node
#[no_mangle]
pub extern "C" fn ChannelAnnouncement_get_node_signature_1(this_ptr: &ChannelAnnouncement) -> crate::c_types::Signature {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.node_signature_1;
	crate::c_types::Signature::from_rust(&(*inner_val))
}
/// Authentication of the announcement by the first public node
#[no_mangle]
pub extern "C" fn ChannelAnnouncement_set_node_signature_1(this_ptr: &mut ChannelAnnouncement, mut val: crate::c_types::Signature) {
	unsafe { &mut *this_ptr.inner }.node_signature_1 = val.into_rust();
}
/// Authentication of the announcement by the second public node
#[no_mangle]
pub extern "C" fn ChannelAnnouncement_get_node_signature_2(this_ptr: &ChannelAnnouncement) -> crate::c_types::Signature {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.node_signature_2;
	crate::c_types::Signature::from_rust(&(*inner_val))
}
/// Authentication of the announcement by the second public node
#[no_mangle]
pub extern "C" fn ChannelAnnouncement_set_node_signature_2(this_ptr: &mut ChannelAnnouncement, mut val: crate::c_types::Signature) {
	unsafe { &mut *this_ptr.inner }.node_signature_2 = val.into_rust();
}
/// Proof of funding UTXO ownership by the first public node
#[no_mangle]
pub extern "C" fn ChannelAnnouncement_get_bitcoin_signature_1(this_ptr: &ChannelAnnouncement) -> crate::c_types::Signature {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.bitcoin_signature_1;
	crate::c_types::Signature::from_rust(&(*inner_val))
}
/// Proof of funding UTXO ownership by the first public node
#[no_mangle]
pub extern "C" fn ChannelAnnouncement_set_bitcoin_signature_1(this_ptr: &mut ChannelAnnouncement, mut val: crate::c_types::Signature) {
	unsafe { &mut *this_ptr.inner }.bitcoin_signature_1 = val.into_rust();
}
/// Proof of funding UTXO ownership by the second public node
#[no_mangle]
pub extern "C" fn ChannelAnnouncement_get_bitcoin_signature_2(this_ptr: &ChannelAnnouncement) -> crate::c_types::Signature {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.bitcoin_signature_2;
	crate::c_types::Signature::from_rust(&(*inner_val))
}
/// Proof of funding UTXO ownership by the second public node
#[no_mangle]
pub extern "C" fn ChannelAnnouncement_set_bitcoin_signature_2(this_ptr: &mut ChannelAnnouncement, mut val: crate::c_types::Signature) {
	unsafe { &mut *this_ptr.inner }.bitcoin_signature_2 = val.into_rust();
}
/// The actual announcement
#[no_mangle]
pub extern "C" fn ChannelAnnouncement_get_contents(this_ptr: &ChannelAnnouncement) -> crate::ln::msgs::UnsignedChannelAnnouncement {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.contents;
	crate::ln::msgs::UnsignedChannelAnnouncement { inner: unsafe { ( (&((*inner_val)) as *const _) as *mut _) }, is_owned: false }
}
/// The actual announcement
#[no_mangle]
pub extern "C" fn ChannelAnnouncement_set_contents(this_ptr: &mut ChannelAnnouncement, mut val: crate::ln::msgs::UnsignedChannelAnnouncement) {
	unsafe { &mut *this_ptr.inner }.contents = *unsafe { Box::from_raw(val.take_inner()) };
}
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelAnnouncement_new(mut node_signature_1_arg: crate::c_types::Signature, mut node_signature_2_arg: crate::c_types::Signature, mut bitcoin_signature_1_arg: crate::c_types::Signature, mut bitcoin_signature_2_arg: crate::c_types::Signature, mut contents_arg: crate::ln::msgs::UnsignedChannelAnnouncement) -> ChannelAnnouncement {
	ChannelAnnouncement { inner: Box::into_raw(Box::new(nativeChannelAnnouncement {
		node_signature_1: node_signature_1_arg.into_rust(),
		node_signature_2: node_signature_2_arg.into_rust(),
		bitcoin_signature_1: bitcoin_signature_1_arg.into_rust(),
		bitcoin_signature_2: bitcoin_signature_2_arg.into_rust(),
		contents: *unsafe { Box::from_raw(contents_arg.take_inner()) },
	})), is_owned: true }
}
impl Clone for ChannelAnnouncement {
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
pub(crate) extern "C" fn ChannelAnnouncement_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeChannelAnnouncement)).clone() })) as *mut c_void
}
#[no_mangle]
pub extern "C" fn ChannelAnnouncement_clone(orig: &ChannelAnnouncement) -> ChannelAnnouncement {
	orig.clone()
}

use lightning::ln::msgs::UnsignedChannelUpdate as nativeUnsignedChannelUpdateImport;
type nativeUnsignedChannelUpdate = nativeUnsignedChannelUpdateImport;

/// The unsigned part of a channel_update
#[must_use]
#[repr(C)]
pub struct UnsignedChannelUpdate {
	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeUnsignedChannelUpdate,
	pub is_owned: bool,
}

impl Drop for UnsignedChannelUpdate {
	fn drop(&mut self) {
		if self.is_owned && !self.inner.is_null() {
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
#[no_mangle]
pub extern "C" fn UnsignedChannelUpdate_free(this_ptr: UnsignedChannelUpdate) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn UnsignedChannelUpdate_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeUnsignedChannelUpdate); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl UnsignedChannelUpdate {
	pub(crate) fn take_inner(mut self) -> *mut nativeUnsignedChannelUpdate {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}
/// The genesis hash of the blockchain where the channel is to be opened
#[no_mangle]
pub extern "C" fn UnsignedChannelUpdate_get_chain_hash(this_ptr: &UnsignedChannelUpdate) -> *const [u8; 32] {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.chain_hash;
	(*inner_val).as_inner()
}
/// The genesis hash of the blockchain where the channel is to be opened
#[no_mangle]
pub extern "C" fn UnsignedChannelUpdate_set_chain_hash(this_ptr: &mut UnsignedChannelUpdate, mut val: crate::c_types::ThirtyTwoBytes) {
	unsafe { &mut *this_ptr.inner }.chain_hash = ::bitcoin::hash_types::BlockHash::from_slice(&val.data[..]).unwrap();
}
/// The short channel ID
#[no_mangle]
pub extern "C" fn UnsignedChannelUpdate_get_short_channel_id(this_ptr: &UnsignedChannelUpdate) -> u64 {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.short_channel_id;
	(*inner_val)
}
/// The short channel ID
#[no_mangle]
pub extern "C" fn UnsignedChannelUpdate_set_short_channel_id(this_ptr: &mut UnsignedChannelUpdate, mut val: u64) {
	unsafe { &mut *this_ptr.inner }.short_channel_id = val;
}
/// A strictly monotonic announcement counter, with gaps allowed, specific to this channel
#[no_mangle]
pub extern "C" fn UnsignedChannelUpdate_get_timestamp(this_ptr: &UnsignedChannelUpdate) -> u32 {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.timestamp;
	(*inner_val)
}
/// A strictly monotonic announcement counter, with gaps allowed, specific to this channel
#[no_mangle]
pub extern "C" fn UnsignedChannelUpdate_set_timestamp(this_ptr: &mut UnsignedChannelUpdate, mut val: u32) {
	unsafe { &mut *this_ptr.inner }.timestamp = val;
}
/// Channel flags
#[no_mangle]
pub extern "C" fn UnsignedChannelUpdate_get_flags(this_ptr: &UnsignedChannelUpdate) -> u8 {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.flags;
	(*inner_val)
}
/// Channel flags
#[no_mangle]
pub extern "C" fn UnsignedChannelUpdate_set_flags(this_ptr: &mut UnsignedChannelUpdate, mut val: u8) {
	unsafe { &mut *this_ptr.inner }.flags = val;
}
/// The number of blocks to subtract from incoming HTLC cltv_expiry values
#[no_mangle]
pub extern "C" fn UnsignedChannelUpdate_get_cltv_expiry_delta(this_ptr: &UnsignedChannelUpdate) -> u16 {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.cltv_expiry_delta;
	(*inner_val)
}
/// The number of blocks to subtract from incoming HTLC cltv_expiry values
#[no_mangle]
pub extern "C" fn UnsignedChannelUpdate_set_cltv_expiry_delta(this_ptr: &mut UnsignedChannelUpdate, mut val: u16) {
	unsafe { &mut *this_ptr.inner }.cltv_expiry_delta = val;
}
/// The minimum HTLC size incoming to sender, in milli-satoshi
#[no_mangle]
pub extern "C" fn UnsignedChannelUpdate_get_htlc_minimum_msat(this_ptr: &UnsignedChannelUpdate) -> u64 {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.htlc_minimum_msat;
	(*inner_val)
}
/// The minimum HTLC size incoming to sender, in milli-satoshi
#[no_mangle]
pub extern "C" fn UnsignedChannelUpdate_set_htlc_minimum_msat(this_ptr: &mut UnsignedChannelUpdate, mut val: u64) {
	unsafe { &mut *this_ptr.inner }.htlc_minimum_msat = val;
}
/// The base HTLC fee charged by sender, in milli-satoshi
#[no_mangle]
pub extern "C" fn UnsignedChannelUpdate_get_fee_base_msat(this_ptr: &UnsignedChannelUpdate) -> u32 {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.fee_base_msat;
	(*inner_val)
}
/// The base HTLC fee charged by sender, in milli-satoshi
#[no_mangle]
pub extern "C" fn UnsignedChannelUpdate_set_fee_base_msat(this_ptr: &mut UnsignedChannelUpdate, mut val: u32) {
	unsafe { &mut *this_ptr.inner }.fee_base_msat = val;
}
/// The amount to fee multiplier, in micro-satoshi
#[no_mangle]
pub extern "C" fn UnsignedChannelUpdate_get_fee_proportional_millionths(this_ptr: &UnsignedChannelUpdate) -> u32 {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.fee_proportional_millionths;
	(*inner_val)
}
/// The amount to fee multiplier, in micro-satoshi
#[no_mangle]
pub extern "C" fn UnsignedChannelUpdate_set_fee_proportional_millionths(this_ptr: &mut UnsignedChannelUpdate, mut val: u32) {
	unsafe { &mut *this_ptr.inner }.fee_proportional_millionths = val;
}
impl Clone for UnsignedChannelUpdate {
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
pub(crate) extern "C" fn UnsignedChannelUpdate_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeUnsignedChannelUpdate)).clone() })) as *mut c_void
}
#[no_mangle]
pub extern "C" fn UnsignedChannelUpdate_clone(orig: &UnsignedChannelUpdate) -> UnsignedChannelUpdate {
	orig.clone()
}

use lightning::ln::msgs::ChannelUpdate as nativeChannelUpdateImport;
type nativeChannelUpdate = nativeChannelUpdateImport;

/// A channel_update message to be sent or received from a peer
#[must_use]
#[repr(C)]
pub struct ChannelUpdate {
	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeChannelUpdate,
	pub is_owned: bool,
}

impl Drop for ChannelUpdate {
	fn drop(&mut self) {
		if self.is_owned && !self.inner.is_null() {
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
#[no_mangle]
pub extern "C" fn ChannelUpdate_free(this_ptr: ChannelUpdate) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn ChannelUpdate_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeChannelUpdate); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl ChannelUpdate {
	pub(crate) fn take_inner(mut self) -> *mut nativeChannelUpdate {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}
/// A signature of the channel update
#[no_mangle]
pub extern "C" fn ChannelUpdate_get_signature(this_ptr: &ChannelUpdate) -> crate::c_types::Signature {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.signature;
	crate::c_types::Signature::from_rust(&(*inner_val))
}
/// A signature of the channel update
#[no_mangle]
pub extern "C" fn ChannelUpdate_set_signature(this_ptr: &mut ChannelUpdate, mut val: crate::c_types::Signature) {
	unsafe { &mut *this_ptr.inner }.signature = val.into_rust();
}
/// The actual channel update
#[no_mangle]
pub extern "C" fn ChannelUpdate_get_contents(this_ptr: &ChannelUpdate) -> crate::ln::msgs::UnsignedChannelUpdate {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.contents;
	crate::ln::msgs::UnsignedChannelUpdate { inner: unsafe { ( (&((*inner_val)) as *const _) as *mut _) }, is_owned: false }
}
/// The actual channel update
#[no_mangle]
pub extern "C" fn ChannelUpdate_set_contents(this_ptr: &mut ChannelUpdate, mut val: crate::ln::msgs::UnsignedChannelUpdate) {
	unsafe { &mut *this_ptr.inner }.contents = *unsafe { Box::from_raw(val.take_inner()) };
}
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelUpdate_new(mut signature_arg: crate::c_types::Signature, mut contents_arg: crate::ln::msgs::UnsignedChannelUpdate) -> ChannelUpdate {
	ChannelUpdate { inner: Box::into_raw(Box::new(nativeChannelUpdate {
		signature: signature_arg.into_rust(),
		contents: *unsafe { Box::from_raw(contents_arg.take_inner()) },
	})), is_owned: true }
}
impl Clone for ChannelUpdate {
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
pub(crate) extern "C" fn ChannelUpdate_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeChannelUpdate)).clone() })) as *mut c_void
}
#[no_mangle]
pub extern "C" fn ChannelUpdate_clone(orig: &ChannelUpdate) -> ChannelUpdate {
	orig.clone()
}

use lightning::ln::msgs::QueryChannelRange as nativeQueryChannelRangeImport;
type nativeQueryChannelRange = nativeQueryChannelRangeImport;

/// A query_channel_range message is used to query a peer for channel
/// UTXOs in a range of blocks. The recipient of a query makes a best
/// effort to reply to the query using one or more reply_channel_range
/// messages.
#[must_use]
#[repr(C)]
pub struct QueryChannelRange {
	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeQueryChannelRange,
	pub is_owned: bool,
}

impl Drop for QueryChannelRange {
	fn drop(&mut self) {
		if self.is_owned && !self.inner.is_null() {
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
#[no_mangle]
pub extern "C" fn QueryChannelRange_free(this_ptr: QueryChannelRange) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn QueryChannelRange_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeQueryChannelRange); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl QueryChannelRange {
	pub(crate) fn take_inner(mut self) -> *mut nativeQueryChannelRange {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}
/// The genesis hash of the blockchain being queried
#[no_mangle]
pub extern "C" fn QueryChannelRange_get_chain_hash(this_ptr: &QueryChannelRange) -> *const [u8; 32] {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.chain_hash;
	(*inner_val).as_inner()
}
/// The genesis hash of the blockchain being queried
#[no_mangle]
pub extern "C" fn QueryChannelRange_set_chain_hash(this_ptr: &mut QueryChannelRange, mut val: crate::c_types::ThirtyTwoBytes) {
	unsafe { &mut *this_ptr.inner }.chain_hash = ::bitcoin::hash_types::BlockHash::from_slice(&val.data[..]).unwrap();
}
/// The height of the first block for the channel UTXOs being queried
#[no_mangle]
pub extern "C" fn QueryChannelRange_get_first_blocknum(this_ptr: &QueryChannelRange) -> u32 {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.first_blocknum;
	(*inner_val)
}
/// The height of the first block for the channel UTXOs being queried
#[no_mangle]
pub extern "C" fn QueryChannelRange_set_first_blocknum(this_ptr: &mut QueryChannelRange, mut val: u32) {
	unsafe { &mut *this_ptr.inner }.first_blocknum = val;
}
/// The number of blocks to include in the query results
#[no_mangle]
pub extern "C" fn QueryChannelRange_get_number_of_blocks(this_ptr: &QueryChannelRange) -> u32 {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.number_of_blocks;
	(*inner_val)
}
/// The number of blocks to include in the query results
#[no_mangle]
pub extern "C" fn QueryChannelRange_set_number_of_blocks(this_ptr: &mut QueryChannelRange, mut val: u32) {
	unsafe { &mut *this_ptr.inner }.number_of_blocks = val;
}
#[must_use]
#[no_mangle]
pub extern "C" fn QueryChannelRange_new(mut chain_hash_arg: crate::c_types::ThirtyTwoBytes, mut first_blocknum_arg: u32, mut number_of_blocks_arg: u32) -> QueryChannelRange {
	QueryChannelRange { inner: Box::into_raw(Box::new(nativeQueryChannelRange {
		chain_hash: ::bitcoin::hash_types::BlockHash::from_slice(&chain_hash_arg.data[..]).unwrap(),
		first_blocknum: first_blocknum_arg,
		number_of_blocks: number_of_blocks_arg,
	})), is_owned: true }
}
impl Clone for QueryChannelRange {
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
pub(crate) extern "C" fn QueryChannelRange_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeQueryChannelRange)).clone() })) as *mut c_void
}
#[no_mangle]
pub extern "C" fn QueryChannelRange_clone(orig: &QueryChannelRange) -> QueryChannelRange {
	orig.clone()
}

use lightning::ln::msgs::ReplyChannelRange as nativeReplyChannelRangeImport;
type nativeReplyChannelRange = nativeReplyChannelRangeImport;

/// A reply_channel_range message is a reply to a query_channel_range
/// message. Multiple reply_channel_range messages can be sent in reply
/// to a single query_channel_range message. The query recipient makes a
/// best effort to respond based on their local network view which may
/// not be a perfect view of the network. The short_channel_ids in the
/// reply are encoded. We only support encoding_type=0 uncompressed
/// serialization and do not support encoding_type=1 zlib serialization.
#[must_use]
#[repr(C)]
pub struct ReplyChannelRange {
	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeReplyChannelRange,
	pub is_owned: bool,
}

impl Drop for ReplyChannelRange {
	fn drop(&mut self) {
		if self.is_owned && !self.inner.is_null() {
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
#[no_mangle]
pub extern "C" fn ReplyChannelRange_free(this_ptr: ReplyChannelRange) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn ReplyChannelRange_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeReplyChannelRange); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl ReplyChannelRange {
	pub(crate) fn take_inner(mut self) -> *mut nativeReplyChannelRange {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}
/// The genesis hash of the blockchain being queried
#[no_mangle]
pub extern "C" fn ReplyChannelRange_get_chain_hash(this_ptr: &ReplyChannelRange) -> *const [u8; 32] {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.chain_hash;
	(*inner_val).as_inner()
}
/// The genesis hash of the blockchain being queried
#[no_mangle]
pub extern "C" fn ReplyChannelRange_set_chain_hash(this_ptr: &mut ReplyChannelRange, mut val: crate::c_types::ThirtyTwoBytes) {
	unsafe { &mut *this_ptr.inner }.chain_hash = ::bitcoin::hash_types::BlockHash::from_slice(&val.data[..]).unwrap();
}
/// The height of the first block in the range of the reply
#[no_mangle]
pub extern "C" fn ReplyChannelRange_get_first_blocknum(this_ptr: &ReplyChannelRange) -> u32 {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.first_blocknum;
	(*inner_val)
}
/// The height of the first block in the range of the reply
#[no_mangle]
pub extern "C" fn ReplyChannelRange_set_first_blocknum(this_ptr: &mut ReplyChannelRange, mut val: u32) {
	unsafe { &mut *this_ptr.inner }.first_blocknum = val;
}
/// The number of blocks included in the range of the reply
#[no_mangle]
pub extern "C" fn ReplyChannelRange_get_number_of_blocks(this_ptr: &ReplyChannelRange) -> u32 {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.number_of_blocks;
	(*inner_val)
}
/// The number of blocks included in the range of the reply
#[no_mangle]
pub extern "C" fn ReplyChannelRange_set_number_of_blocks(this_ptr: &mut ReplyChannelRange, mut val: u32) {
	unsafe { &mut *this_ptr.inner }.number_of_blocks = val;
}
/// True when this is the final reply for a query
#[no_mangle]
pub extern "C" fn ReplyChannelRange_get_sync_complete(this_ptr: &ReplyChannelRange) -> bool {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.sync_complete;
	(*inner_val)
}
/// True when this is the final reply for a query
#[no_mangle]
pub extern "C" fn ReplyChannelRange_set_sync_complete(this_ptr: &mut ReplyChannelRange, mut val: bool) {
	unsafe { &mut *this_ptr.inner }.sync_complete = val;
}
/// The short_channel_ids in the channel range
#[no_mangle]
pub extern "C" fn ReplyChannelRange_set_short_channel_ids(this_ptr: &mut ReplyChannelRange, mut val: crate::c_types::derived::CVec_u64Z) {
	let mut local_val = Vec::new(); for mut item in val.into_rust().drain(..) { local_val.push( { item }); };
	unsafe { &mut *this_ptr.inner }.short_channel_ids = local_val;
}
#[must_use]
#[no_mangle]
pub extern "C" fn ReplyChannelRange_new(mut chain_hash_arg: crate::c_types::ThirtyTwoBytes, mut first_blocknum_arg: u32, mut number_of_blocks_arg: u32, mut sync_complete_arg: bool, mut short_channel_ids_arg: crate::c_types::derived::CVec_u64Z) -> ReplyChannelRange {
	let mut local_short_channel_ids_arg = Vec::new(); for mut item in short_channel_ids_arg.into_rust().drain(..) { local_short_channel_ids_arg.push( { item }); };
	ReplyChannelRange { inner: Box::into_raw(Box::new(nativeReplyChannelRange {
		chain_hash: ::bitcoin::hash_types::BlockHash::from_slice(&chain_hash_arg.data[..]).unwrap(),
		first_blocknum: first_blocknum_arg,
		number_of_blocks: number_of_blocks_arg,
		sync_complete: sync_complete_arg,
		short_channel_ids: local_short_channel_ids_arg,
	})), is_owned: true }
}
impl Clone for ReplyChannelRange {
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
pub(crate) extern "C" fn ReplyChannelRange_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeReplyChannelRange)).clone() })) as *mut c_void
}
#[no_mangle]
pub extern "C" fn ReplyChannelRange_clone(orig: &ReplyChannelRange) -> ReplyChannelRange {
	orig.clone()
}

use lightning::ln::msgs::QueryShortChannelIds as nativeQueryShortChannelIdsImport;
type nativeQueryShortChannelIds = nativeQueryShortChannelIdsImport;

/// A query_short_channel_ids message is used to query a peer for
/// routing gossip messages related to one or more short_channel_ids.
/// The query recipient will reply with the latest, if available,
/// channel_announcement, channel_update and node_announcement messages
/// it maintains for the requested short_channel_ids followed by a
/// reply_short_channel_ids_end message. The short_channel_ids sent in
/// this query are encoded. We only support encoding_type=0 uncompressed
/// serialization and do not support encoding_type=1 zlib serialization.
#[must_use]
#[repr(C)]
pub struct QueryShortChannelIds {
	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeQueryShortChannelIds,
	pub is_owned: bool,
}

impl Drop for QueryShortChannelIds {
	fn drop(&mut self) {
		if self.is_owned && !self.inner.is_null() {
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
#[no_mangle]
pub extern "C" fn QueryShortChannelIds_free(this_ptr: QueryShortChannelIds) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn QueryShortChannelIds_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeQueryShortChannelIds); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl QueryShortChannelIds {
	pub(crate) fn take_inner(mut self) -> *mut nativeQueryShortChannelIds {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}
/// The genesis hash of the blockchain being queried
#[no_mangle]
pub extern "C" fn QueryShortChannelIds_get_chain_hash(this_ptr: &QueryShortChannelIds) -> *const [u8; 32] {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.chain_hash;
	(*inner_val).as_inner()
}
/// The genesis hash of the blockchain being queried
#[no_mangle]
pub extern "C" fn QueryShortChannelIds_set_chain_hash(this_ptr: &mut QueryShortChannelIds, mut val: crate::c_types::ThirtyTwoBytes) {
	unsafe { &mut *this_ptr.inner }.chain_hash = ::bitcoin::hash_types::BlockHash::from_slice(&val.data[..]).unwrap();
}
/// The short_channel_ids that are being queried
#[no_mangle]
pub extern "C" fn QueryShortChannelIds_set_short_channel_ids(this_ptr: &mut QueryShortChannelIds, mut val: crate::c_types::derived::CVec_u64Z) {
	let mut local_val = Vec::new(); for mut item in val.into_rust().drain(..) { local_val.push( { item }); };
	unsafe { &mut *this_ptr.inner }.short_channel_ids = local_val;
}
#[must_use]
#[no_mangle]
pub extern "C" fn QueryShortChannelIds_new(mut chain_hash_arg: crate::c_types::ThirtyTwoBytes, mut short_channel_ids_arg: crate::c_types::derived::CVec_u64Z) -> QueryShortChannelIds {
	let mut local_short_channel_ids_arg = Vec::new(); for mut item in short_channel_ids_arg.into_rust().drain(..) { local_short_channel_ids_arg.push( { item }); };
	QueryShortChannelIds { inner: Box::into_raw(Box::new(nativeQueryShortChannelIds {
		chain_hash: ::bitcoin::hash_types::BlockHash::from_slice(&chain_hash_arg.data[..]).unwrap(),
		short_channel_ids: local_short_channel_ids_arg,
	})), is_owned: true }
}
impl Clone for QueryShortChannelIds {
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
pub(crate) extern "C" fn QueryShortChannelIds_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeQueryShortChannelIds)).clone() })) as *mut c_void
}
#[no_mangle]
pub extern "C" fn QueryShortChannelIds_clone(orig: &QueryShortChannelIds) -> QueryShortChannelIds {
	orig.clone()
}

use lightning::ln::msgs::ReplyShortChannelIdsEnd as nativeReplyShortChannelIdsEndImport;
type nativeReplyShortChannelIdsEnd = nativeReplyShortChannelIdsEndImport;

/// A reply_short_channel_ids_end message is sent as a reply to a
/// query_short_channel_ids message. The query recipient makes a best
/// effort to respond based on their local network view which may not be
/// a perfect view of the network.
#[must_use]
#[repr(C)]
pub struct ReplyShortChannelIdsEnd {
	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeReplyShortChannelIdsEnd,
	pub is_owned: bool,
}

impl Drop for ReplyShortChannelIdsEnd {
	fn drop(&mut self) {
		if self.is_owned && !self.inner.is_null() {
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
#[no_mangle]
pub extern "C" fn ReplyShortChannelIdsEnd_free(this_ptr: ReplyShortChannelIdsEnd) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn ReplyShortChannelIdsEnd_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeReplyShortChannelIdsEnd); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl ReplyShortChannelIdsEnd {
	pub(crate) fn take_inner(mut self) -> *mut nativeReplyShortChannelIdsEnd {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}
/// The genesis hash of the blockchain that was queried
#[no_mangle]
pub extern "C" fn ReplyShortChannelIdsEnd_get_chain_hash(this_ptr: &ReplyShortChannelIdsEnd) -> *const [u8; 32] {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.chain_hash;
	(*inner_val).as_inner()
}
/// The genesis hash of the blockchain that was queried
#[no_mangle]
pub extern "C" fn ReplyShortChannelIdsEnd_set_chain_hash(this_ptr: &mut ReplyShortChannelIdsEnd, mut val: crate::c_types::ThirtyTwoBytes) {
	unsafe { &mut *this_ptr.inner }.chain_hash = ::bitcoin::hash_types::BlockHash::from_slice(&val.data[..]).unwrap();
}
/// Indicates if the query recipient maintains up-to-date channel
/// information for the chain_hash
#[no_mangle]
pub extern "C" fn ReplyShortChannelIdsEnd_get_full_information(this_ptr: &ReplyShortChannelIdsEnd) -> bool {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.full_information;
	(*inner_val)
}
/// Indicates if the query recipient maintains up-to-date channel
/// information for the chain_hash
#[no_mangle]
pub extern "C" fn ReplyShortChannelIdsEnd_set_full_information(this_ptr: &mut ReplyShortChannelIdsEnd, mut val: bool) {
	unsafe { &mut *this_ptr.inner }.full_information = val;
}
#[must_use]
#[no_mangle]
pub extern "C" fn ReplyShortChannelIdsEnd_new(mut chain_hash_arg: crate::c_types::ThirtyTwoBytes, mut full_information_arg: bool) -> ReplyShortChannelIdsEnd {
	ReplyShortChannelIdsEnd { inner: Box::into_raw(Box::new(nativeReplyShortChannelIdsEnd {
		chain_hash: ::bitcoin::hash_types::BlockHash::from_slice(&chain_hash_arg.data[..]).unwrap(),
		full_information: full_information_arg,
	})), is_owned: true }
}
impl Clone for ReplyShortChannelIdsEnd {
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
pub(crate) extern "C" fn ReplyShortChannelIdsEnd_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeReplyShortChannelIdsEnd)).clone() })) as *mut c_void
}
#[no_mangle]
pub extern "C" fn ReplyShortChannelIdsEnd_clone(orig: &ReplyShortChannelIdsEnd) -> ReplyShortChannelIdsEnd {
	orig.clone()
}

use lightning::ln::msgs::GossipTimestampFilter as nativeGossipTimestampFilterImport;
type nativeGossipTimestampFilter = nativeGossipTimestampFilterImport;

/// A gossip_timestamp_filter message is used by a node to request
/// gossip relay for messages in the requested time range when the
/// gossip_queries feature has been negotiated.
#[must_use]
#[repr(C)]
pub struct GossipTimestampFilter {
	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeGossipTimestampFilter,
	pub is_owned: bool,
}

impl Drop for GossipTimestampFilter {
	fn drop(&mut self) {
		if self.is_owned && !self.inner.is_null() {
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
#[no_mangle]
pub extern "C" fn GossipTimestampFilter_free(this_ptr: GossipTimestampFilter) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn GossipTimestampFilter_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeGossipTimestampFilter); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl GossipTimestampFilter {
	pub(crate) fn take_inner(mut self) -> *mut nativeGossipTimestampFilter {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}
/// The genesis hash of the blockchain for channel and node information
#[no_mangle]
pub extern "C" fn GossipTimestampFilter_get_chain_hash(this_ptr: &GossipTimestampFilter) -> *const [u8; 32] {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.chain_hash;
	(*inner_val).as_inner()
}
/// The genesis hash of the blockchain for channel and node information
#[no_mangle]
pub extern "C" fn GossipTimestampFilter_set_chain_hash(this_ptr: &mut GossipTimestampFilter, mut val: crate::c_types::ThirtyTwoBytes) {
	unsafe { &mut *this_ptr.inner }.chain_hash = ::bitcoin::hash_types::BlockHash::from_slice(&val.data[..]).unwrap();
}
/// The starting unix timestamp
#[no_mangle]
pub extern "C" fn GossipTimestampFilter_get_first_timestamp(this_ptr: &GossipTimestampFilter) -> u32 {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.first_timestamp;
	(*inner_val)
}
/// The starting unix timestamp
#[no_mangle]
pub extern "C" fn GossipTimestampFilter_set_first_timestamp(this_ptr: &mut GossipTimestampFilter, mut val: u32) {
	unsafe { &mut *this_ptr.inner }.first_timestamp = val;
}
/// The range of information in seconds
#[no_mangle]
pub extern "C" fn GossipTimestampFilter_get_timestamp_range(this_ptr: &GossipTimestampFilter) -> u32 {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.timestamp_range;
	(*inner_val)
}
/// The range of information in seconds
#[no_mangle]
pub extern "C" fn GossipTimestampFilter_set_timestamp_range(this_ptr: &mut GossipTimestampFilter, mut val: u32) {
	unsafe { &mut *this_ptr.inner }.timestamp_range = val;
}
#[must_use]
#[no_mangle]
pub extern "C" fn GossipTimestampFilter_new(mut chain_hash_arg: crate::c_types::ThirtyTwoBytes, mut first_timestamp_arg: u32, mut timestamp_range_arg: u32) -> GossipTimestampFilter {
	GossipTimestampFilter { inner: Box::into_raw(Box::new(nativeGossipTimestampFilter {
		chain_hash: ::bitcoin::hash_types::BlockHash::from_slice(&chain_hash_arg.data[..]).unwrap(),
		first_timestamp: first_timestamp_arg,
		timestamp_range: timestamp_range_arg,
	})), is_owned: true }
}
impl Clone for GossipTimestampFilter {
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
pub(crate) extern "C" fn GossipTimestampFilter_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeGossipTimestampFilter)).clone() })) as *mut c_void
}
#[no_mangle]
pub extern "C" fn GossipTimestampFilter_clone(orig: &GossipTimestampFilter) -> GossipTimestampFilter {
	orig.clone()
}
/// Used to put an error message in a LightningError
#[must_use]
#[derive(Clone)]
#[repr(C)]
pub enum ErrorAction {
	/// The peer took some action which made us think they were useless. Disconnect them.
	DisconnectPeer {
		msg: crate::ln::msgs::ErrorMessage,
	},
	/// The peer did something harmless that we weren't able to process, just log and ignore
	IgnoreError,
	/// The peer did something incorrect. Tell them.
	SendErrorMessage {
		msg: crate::ln::msgs::ErrorMessage,
	},
}
use lightning::ln::msgs::ErrorAction as nativeErrorAction;
impl ErrorAction {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeErrorAction {
		match self {
			ErrorAction::DisconnectPeer {ref msg, } => {
				let mut msg_nonref = (*msg).clone();
				let mut local_msg_nonref = if msg_nonref.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(msg_nonref.take_inner()) } }) };
				nativeErrorAction::DisconnectPeer {
					msg: local_msg_nonref,
				}
			},
			ErrorAction::IgnoreError => nativeErrorAction::IgnoreError,
			ErrorAction::SendErrorMessage {ref msg, } => {
				let mut msg_nonref = (*msg).clone();
				nativeErrorAction::SendErrorMessage {
					msg: *unsafe { Box::from_raw(msg_nonref.take_inner()) },
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeErrorAction {
		match self {
			ErrorAction::DisconnectPeer {mut msg, } => {
				let mut local_msg = if msg.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(msg.take_inner()) } }) };
				nativeErrorAction::DisconnectPeer {
					msg: local_msg,
				}
			},
			ErrorAction::IgnoreError => nativeErrorAction::IgnoreError,
			ErrorAction::SendErrorMessage {mut msg, } => {
				nativeErrorAction::SendErrorMessage {
					msg: *unsafe { Box::from_raw(msg.take_inner()) },
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &nativeErrorAction) -> Self {
		match native {
			nativeErrorAction::DisconnectPeer {ref msg, } => {
				let mut msg_nonref = (*msg).clone();
				let mut local_msg_nonref = crate::ln::msgs::ErrorMessage { inner: if msg_nonref.is_none() { std::ptr::null_mut() } else {  { Box::into_raw(Box::new((msg_nonref.unwrap()))) } }, is_owned: true };
				ErrorAction::DisconnectPeer {
					msg: local_msg_nonref,
				}
			},
			nativeErrorAction::IgnoreError => ErrorAction::IgnoreError,
			nativeErrorAction::SendErrorMessage {ref msg, } => {
				let mut msg_nonref = (*msg).clone();
				ErrorAction::SendErrorMessage {
					msg: crate::ln::msgs::ErrorMessage { inner: Box::into_raw(Box::new(msg_nonref)), is_owned: true },
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeErrorAction) -> Self {
		match native {
			nativeErrorAction::DisconnectPeer {mut msg, } => {
				let mut local_msg = crate::ln::msgs::ErrorMessage { inner: if msg.is_none() { std::ptr::null_mut() } else {  { Box::into_raw(Box::new((msg.unwrap()))) } }, is_owned: true };
				ErrorAction::DisconnectPeer {
					msg: local_msg,
				}
			},
			nativeErrorAction::IgnoreError => ErrorAction::IgnoreError,
			nativeErrorAction::SendErrorMessage {mut msg, } => {
				ErrorAction::SendErrorMessage {
					msg: crate::ln::msgs::ErrorMessage { inner: Box::into_raw(Box::new(msg)), is_owned: true },
				}
			},
		}
	}
}
#[no_mangle]
pub extern "C" fn ErrorAction_free(this_ptr: ErrorAction) { }
#[no_mangle]
pub extern "C" fn ErrorAction_clone(orig: &ErrorAction) -> ErrorAction {
	orig.clone()
}

use lightning::ln::msgs::LightningError as nativeLightningErrorImport;
type nativeLightningError = nativeLightningErrorImport;

/// An Err type for failure to process messages.
#[must_use]
#[repr(C)]
pub struct LightningError {
	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeLightningError,
	pub is_owned: bool,
}

impl Drop for LightningError {
	fn drop(&mut self) {
		if self.is_owned && !self.inner.is_null() {
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
#[no_mangle]
pub extern "C" fn LightningError_free(this_ptr: LightningError) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn LightningError_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeLightningError); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl LightningError {
	pub(crate) fn take_inner(mut self) -> *mut nativeLightningError {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}
/// A human-readable message describing the error
#[no_mangle]
pub extern "C" fn LightningError_get_err(this_ptr: &LightningError) -> crate::c_types::Str {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.err;
	(*inner_val).as_str().into()
}
/// A human-readable message describing the error
#[no_mangle]
pub extern "C" fn LightningError_set_err(this_ptr: &mut LightningError, mut val: crate::c_types::derived::CVec_u8Z) {
	unsafe { &mut *this_ptr.inner }.err = String::from_utf8(val.into_rust()).unwrap();
}
/// The action which should be taken against the offending peer.
#[no_mangle]
pub extern "C" fn LightningError_get_action(this_ptr: &LightningError) -> crate::ln::msgs::ErrorAction {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.action;
	crate::ln::msgs::ErrorAction::from_native(&(*inner_val))
}
/// The action which should be taken against the offending peer.
#[no_mangle]
pub extern "C" fn LightningError_set_action(this_ptr: &mut LightningError, mut val: crate::ln::msgs::ErrorAction) {
	unsafe { &mut *this_ptr.inner }.action = val.into_native();
}
#[must_use]
#[no_mangle]
pub extern "C" fn LightningError_new(mut err_arg: crate::c_types::derived::CVec_u8Z, mut action_arg: crate::ln::msgs::ErrorAction) -> LightningError {
	LightningError { inner: Box::into_raw(Box::new(nativeLightningError {
		err: String::from_utf8(err_arg.into_rust()).unwrap(),
		action: action_arg.into_native(),
	})), is_owned: true }
}
impl Clone for LightningError {
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
pub(crate) extern "C" fn LightningError_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeLightningError)).clone() })) as *mut c_void
}
#[no_mangle]
pub extern "C" fn LightningError_clone(orig: &LightningError) -> LightningError {
	orig.clone()
}

use lightning::ln::msgs::CommitmentUpdate as nativeCommitmentUpdateImport;
type nativeCommitmentUpdate = nativeCommitmentUpdateImport;

/// Struct used to return values from revoke_and_ack messages, containing a bunch of commitment
/// transaction updates if they were pending.
#[must_use]
#[repr(C)]
pub struct CommitmentUpdate {
	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeCommitmentUpdate,
	pub is_owned: bool,
}

impl Drop for CommitmentUpdate {
	fn drop(&mut self) {
		if self.is_owned && !self.inner.is_null() {
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
#[no_mangle]
pub extern "C" fn CommitmentUpdate_free(this_ptr: CommitmentUpdate) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn CommitmentUpdate_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeCommitmentUpdate); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl CommitmentUpdate {
	pub(crate) fn take_inner(mut self) -> *mut nativeCommitmentUpdate {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}
/// update_add_htlc messages which should be sent
#[no_mangle]
pub extern "C" fn CommitmentUpdate_set_update_add_htlcs(this_ptr: &mut CommitmentUpdate, mut val: crate::c_types::derived::CVec_UpdateAddHTLCZ) {
	let mut local_val = Vec::new(); for mut item in val.into_rust().drain(..) { local_val.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
	unsafe { &mut *this_ptr.inner }.update_add_htlcs = local_val;
}
/// update_fulfill_htlc messages which should be sent
#[no_mangle]
pub extern "C" fn CommitmentUpdate_set_update_fulfill_htlcs(this_ptr: &mut CommitmentUpdate, mut val: crate::c_types::derived::CVec_UpdateFulfillHTLCZ) {
	let mut local_val = Vec::new(); for mut item in val.into_rust().drain(..) { local_val.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
	unsafe { &mut *this_ptr.inner }.update_fulfill_htlcs = local_val;
}
/// update_fail_htlc messages which should be sent
#[no_mangle]
pub extern "C" fn CommitmentUpdate_set_update_fail_htlcs(this_ptr: &mut CommitmentUpdate, mut val: crate::c_types::derived::CVec_UpdateFailHTLCZ) {
	let mut local_val = Vec::new(); for mut item in val.into_rust().drain(..) { local_val.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
	unsafe { &mut *this_ptr.inner }.update_fail_htlcs = local_val;
}
/// update_fail_malformed_htlc messages which should be sent
#[no_mangle]
pub extern "C" fn CommitmentUpdate_set_update_fail_malformed_htlcs(this_ptr: &mut CommitmentUpdate, mut val: crate::c_types::derived::CVec_UpdateFailMalformedHTLCZ) {
	let mut local_val = Vec::new(); for mut item in val.into_rust().drain(..) { local_val.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
	unsafe { &mut *this_ptr.inner }.update_fail_malformed_htlcs = local_val;
}
/// An update_fee message which should be sent
#[no_mangle]
pub extern "C" fn CommitmentUpdate_get_update_fee(this_ptr: &CommitmentUpdate) -> crate::ln::msgs::UpdateFee {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.update_fee;
	let mut local_inner_val = crate::ln::msgs::UpdateFee { inner: unsafe { (if inner_val.is_none() { std::ptr::null() } else {  { (inner_val.as_ref().unwrap()) } } as *const _) as *mut _ }, is_owned: false };
	local_inner_val
}
/// An update_fee message which should be sent
#[no_mangle]
pub extern "C" fn CommitmentUpdate_set_update_fee(this_ptr: &mut CommitmentUpdate, mut val: crate::ln::msgs::UpdateFee) {
	let mut local_val = if val.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(val.take_inner()) } }) };
	unsafe { &mut *this_ptr.inner }.update_fee = local_val;
}
/// Finally, the commitment_signed message which should be sent
#[no_mangle]
pub extern "C" fn CommitmentUpdate_get_commitment_signed(this_ptr: &CommitmentUpdate) -> crate::ln::msgs::CommitmentSigned {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.commitment_signed;
	crate::ln::msgs::CommitmentSigned { inner: unsafe { ( (&((*inner_val)) as *const _) as *mut _) }, is_owned: false }
}
/// Finally, the commitment_signed message which should be sent
#[no_mangle]
pub extern "C" fn CommitmentUpdate_set_commitment_signed(this_ptr: &mut CommitmentUpdate, mut val: crate::ln::msgs::CommitmentSigned) {
	unsafe { &mut *this_ptr.inner }.commitment_signed = *unsafe { Box::from_raw(val.take_inner()) };
}
#[must_use]
#[no_mangle]
pub extern "C" fn CommitmentUpdate_new(mut update_add_htlcs_arg: crate::c_types::derived::CVec_UpdateAddHTLCZ, mut update_fulfill_htlcs_arg: crate::c_types::derived::CVec_UpdateFulfillHTLCZ, mut update_fail_htlcs_arg: crate::c_types::derived::CVec_UpdateFailHTLCZ, mut update_fail_malformed_htlcs_arg: crate::c_types::derived::CVec_UpdateFailMalformedHTLCZ, mut update_fee_arg: crate::ln::msgs::UpdateFee, mut commitment_signed_arg: crate::ln::msgs::CommitmentSigned) -> CommitmentUpdate {
	let mut local_update_add_htlcs_arg = Vec::new(); for mut item in update_add_htlcs_arg.into_rust().drain(..) { local_update_add_htlcs_arg.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
	let mut local_update_fulfill_htlcs_arg = Vec::new(); for mut item in update_fulfill_htlcs_arg.into_rust().drain(..) { local_update_fulfill_htlcs_arg.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
	let mut local_update_fail_htlcs_arg = Vec::new(); for mut item in update_fail_htlcs_arg.into_rust().drain(..) { local_update_fail_htlcs_arg.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
	let mut local_update_fail_malformed_htlcs_arg = Vec::new(); for mut item in update_fail_malformed_htlcs_arg.into_rust().drain(..) { local_update_fail_malformed_htlcs_arg.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
	let mut local_update_fee_arg = if update_fee_arg.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(update_fee_arg.take_inner()) } }) };
	CommitmentUpdate { inner: Box::into_raw(Box::new(nativeCommitmentUpdate {
		update_add_htlcs: local_update_add_htlcs_arg,
		update_fulfill_htlcs: local_update_fulfill_htlcs_arg,
		update_fail_htlcs: local_update_fail_htlcs_arg,
		update_fail_malformed_htlcs: local_update_fail_malformed_htlcs_arg,
		update_fee: local_update_fee_arg,
		commitment_signed: *unsafe { Box::from_raw(commitment_signed_arg.take_inner()) },
	})), is_owned: true }
}
impl Clone for CommitmentUpdate {
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
pub(crate) extern "C" fn CommitmentUpdate_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeCommitmentUpdate)).clone() })) as *mut c_void
}
#[no_mangle]
pub extern "C" fn CommitmentUpdate_clone(orig: &CommitmentUpdate) -> CommitmentUpdate {
	orig.clone()
}
/// The information we received from a peer along the route of a payment we originated. This is
/// returned by ChannelMessageHandler::handle_update_fail_htlc to be passed into
/// RoutingMessageHandler::handle_htlc_fail_channel_update to update our network map.
#[must_use]
#[derive(Clone)]
#[repr(C)]
pub enum HTLCFailChannelUpdate {
	/// We received an error which included a full ChannelUpdate message.
	ChannelUpdateMessage {
		msg: crate::ln::msgs::ChannelUpdate,
	},
	/// We received an error which indicated only that a channel has been closed
	ChannelClosed {
		short_channel_id: u64,
		is_permanent: bool,
	},
	/// We received an error which indicated only that a node has failed
	NodeFailure {
		node_id: crate::c_types::PublicKey,
		is_permanent: bool,
	},
}
use lightning::ln::msgs::HTLCFailChannelUpdate as nativeHTLCFailChannelUpdate;
impl HTLCFailChannelUpdate {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeHTLCFailChannelUpdate {
		match self {
			HTLCFailChannelUpdate::ChannelUpdateMessage {ref msg, } => {
				let mut msg_nonref = (*msg).clone();
				nativeHTLCFailChannelUpdate::ChannelUpdateMessage {
					msg: *unsafe { Box::from_raw(msg_nonref.take_inner()) },
				}
			},
			HTLCFailChannelUpdate::ChannelClosed {ref short_channel_id, ref is_permanent, } => {
				let mut short_channel_id_nonref = (*short_channel_id).clone();
				let mut is_permanent_nonref = (*is_permanent).clone();
				nativeHTLCFailChannelUpdate::ChannelClosed {
					short_channel_id: short_channel_id_nonref,
					is_permanent: is_permanent_nonref,
				}
			},
			HTLCFailChannelUpdate::NodeFailure {ref node_id, ref is_permanent, } => {
				let mut node_id_nonref = (*node_id).clone();
				let mut is_permanent_nonref = (*is_permanent).clone();
				nativeHTLCFailChannelUpdate::NodeFailure {
					node_id: node_id_nonref.into_rust(),
					is_permanent: is_permanent_nonref,
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeHTLCFailChannelUpdate {
		match self {
			HTLCFailChannelUpdate::ChannelUpdateMessage {mut msg, } => {
				nativeHTLCFailChannelUpdate::ChannelUpdateMessage {
					msg: *unsafe { Box::from_raw(msg.take_inner()) },
				}
			},
			HTLCFailChannelUpdate::ChannelClosed {mut short_channel_id, mut is_permanent, } => {
				nativeHTLCFailChannelUpdate::ChannelClosed {
					short_channel_id: short_channel_id,
					is_permanent: is_permanent,
				}
			},
			HTLCFailChannelUpdate::NodeFailure {mut node_id, mut is_permanent, } => {
				nativeHTLCFailChannelUpdate::NodeFailure {
					node_id: node_id.into_rust(),
					is_permanent: is_permanent,
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &nativeHTLCFailChannelUpdate) -> Self {
		match native {
			nativeHTLCFailChannelUpdate::ChannelUpdateMessage {ref msg, } => {
				let mut msg_nonref = (*msg).clone();
				HTLCFailChannelUpdate::ChannelUpdateMessage {
					msg: crate::ln::msgs::ChannelUpdate { inner: Box::into_raw(Box::new(msg_nonref)), is_owned: true },
				}
			},
			nativeHTLCFailChannelUpdate::ChannelClosed {ref short_channel_id, ref is_permanent, } => {
				let mut short_channel_id_nonref = (*short_channel_id).clone();
				let mut is_permanent_nonref = (*is_permanent).clone();
				HTLCFailChannelUpdate::ChannelClosed {
					short_channel_id: short_channel_id_nonref,
					is_permanent: is_permanent_nonref,
				}
			},
			nativeHTLCFailChannelUpdate::NodeFailure {ref node_id, ref is_permanent, } => {
				let mut node_id_nonref = (*node_id).clone();
				let mut is_permanent_nonref = (*is_permanent).clone();
				HTLCFailChannelUpdate::NodeFailure {
					node_id: crate::c_types::PublicKey::from_rust(&node_id_nonref),
					is_permanent: is_permanent_nonref,
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeHTLCFailChannelUpdate) -> Self {
		match native {
			nativeHTLCFailChannelUpdate::ChannelUpdateMessage {mut msg, } => {
				HTLCFailChannelUpdate::ChannelUpdateMessage {
					msg: crate::ln::msgs::ChannelUpdate { inner: Box::into_raw(Box::new(msg)), is_owned: true },
				}
			},
			nativeHTLCFailChannelUpdate::ChannelClosed {mut short_channel_id, mut is_permanent, } => {
				HTLCFailChannelUpdate::ChannelClosed {
					short_channel_id: short_channel_id,
					is_permanent: is_permanent,
				}
			},
			nativeHTLCFailChannelUpdate::NodeFailure {mut node_id, mut is_permanent, } => {
				HTLCFailChannelUpdate::NodeFailure {
					node_id: crate::c_types::PublicKey::from_rust(&node_id),
					is_permanent: is_permanent,
				}
			},
		}
	}
}
#[no_mangle]
pub extern "C" fn HTLCFailChannelUpdate_free(this_ptr: HTLCFailChannelUpdate) { }
#[no_mangle]
pub extern "C" fn HTLCFailChannelUpdate_clone(orig: &HTLCFailChannelUpdate) -> HTLCFailChannelUpdate {
	orig.clone()
}
/// A trait to describe an object which can receive channel messages.
///
/// Messages MAY be called in parallel when they originate from different their_node_ids, however
/// they MUST NOT be called in parallel when the two calls have the same their_node_id.
#[repr(C)]
pub struct ChannelMessageHandler {
	pub this_arg: *mut c_void,
	/// Handle an incoming open_channel message from the given peer.
	pub handle_open_channel: extern "C" fn (this_arg: *const c_void, their_node_id: crate::c_types::PublicKey, their_features: crate::ln::features::InitFeatures, msg: &crate::ln::msgs::OpenChannel),
	/// Handle an incoming accept_channel message from the given peer.
	pub handle_accept_channel: extern "C" fn (this_arg: *const c_void, their_node_id: crate::c_types::PublicKey, their_features: crate::ln::features::InitFeatures, msg: &crate::ln::msgs::AcceptChannel),
	/// Handle an incoming funding_created message from the given peer.
	pub handle_funding_created: extern "C" fn (this_arg: *const c_void, their_node_id: crate::c_types::PublicKey, msg: &crate::ln::msgs::FundingCreated),
	/// Handle an incoming funding_signed message from the given peer.
	pub handle_funding_signed: extern "C" fn (this_arg: *const c_void, their_node_id: crate::c_types::PublicKey, msg: &crate::ln::msgs::FundingSigned),
	/// Handle an incoming funding_locked message from the given peer.
	pub handle_funding_locked: extern "C" fn (this_arg: *const c_void, their_node_id: crate::c_types::PublicKey, msg: &crate::ln::msgs::FundingLocked),
	/// Handle an incoming shutdown message from the given peer.
	pub handle_shutdown: extern "C" fn (this_arg: *const c_void, their_node_id: crate::c_types::PublicKey, msg: &crate::ln::msgs::Shutdown),
	/// Handle an incoming closing_signed message from the given peer.
	pub handle_closing_signed: extern "C" fn (this_arg: *const c_void, their_node_id: crate::c_types::PublicKey, msg: &crate::ln::msgs::ClosingSigned),
	/// Handle an incoming update_add_htlc message from the given peer.
	pub handle_update_add_htlc: extern "C" fn (this_arg: *const c_void, their_node_id: crate::c_types::PublicKey, msg: &crate::ln::msgs::UpdateAddHTLC),
	/// Handle an incoming update_fulfill_htlc message from the given peer.
	pub handle_update_fulfill_htlc: extern "C" fn (this_arg: *const c_void, their_node_id: crate::c_types::PublicKey, msg: &crate::ln::msgs::UpdateFulfillHTLC),
	/// Handle an incoming update_fail_htlc message from the given peer.
	pub handle_update_fail_htlc: extern "C" fn (this_arg: *const c_void, their_node_id: crate::c_types::PublicKey, msg: &crate::ln::msgs::UpdateFailHTLC),
	/// Handle an incoming update_fail_malformed_htlc message from the given peer.
	pub handle_update_fail_malformed_htlc: extern "C" fn (this_arg: *const c_void, their_node_id: crate::c_types::PublicKey, msg: &crate::ln::msgs::UpdateFailMalformedHTLC),
	/// Handle an incoming commitment_signed message from the given peer.
	pub handle_commitment_signed: extern "C" fn (this_arg: *const c_void, their_node_id: crate::c_types::PublicKey, msg: &crate::ln::msgs::CommitmentSigned),
	/// Handle an incoming revoke_and_ack message from the given peer.
	pub handle_revoke_and_ack: extern "C" fn (this_arg: *const c_void, their_node_id: crate::c_types::PublicKey, msg: &crate::ln::msgs::RevokeAndACK),
	/// Handle an incoming update_fee message from the given peer.
	pub handle_update_fee: extern "C" fn (this_arg: *const c_void, their_node_id: crate::c_types::PublicKey, msg: &crate::ln::msgs::UpdateFee),
	/// Handle an incoming announcement_signatures message from the given peer.
	pub handle_announcement_signatures: extern "C" fn (this_arg: *const c_void, their_node_id: crate::c_types::PublicKey, msg: &crate::ln::msgs::AnnouncementSignatures),
	/// Indicates a connection to the peer failed/an existing connection was lost. If no connection
	/// is believed to be possible in the future (eg they're sending us messages we don't
	/// understand or indicate they require unknown feature bits), no_connection_possible is set
	/// and any outstanding channels should be failed.
	pub peer_disconnected: extern "C" fn (this_arg: *const c_void, their_node_id: crate::c_types::PublicKey, no_connection_possible: bool),
	/// Handle a peer reconnecting, possibly generating channel_reestablish message(s).
	pub peer_connected: extern "C" fn (this_arg: *const c_void, their_node_id: crate::c_types::PublicKey, msg: &crate::ln::msgs::Init),
	/// Handle an incoming channel_reestablish message from the given peer.
	pub handle_channel_reestablish: extern "C" fn (this_arg: *const c_void, their_node_id: crate::c_types::PublicKey, msg: &crate::ln::msgs::ChannelReestablish),
	/// Handle an incoming error message from the given peer.
	pub handle_error: extern "C" fn (this_arg: *const c_void, their_node_id: crate::c_types::PublicKey, msg: &crate::ln::msgs::ErrorMessage),
	pub MessageSendEventsProvider: crate::util::events::MessageSendEventsProvider,
	pub free: Option<extern "C" fn(this_arg: *mut c_void)>,
}
impl lightning::util::events::MessageSendEventsProvider for ChannelMessageHandler {
	fn get_and_clear_pending_msg_events(&self) -> Vec<lightning::util::events::MessageSendEvent> {
		<crate::util::events::MessageSendEventsProvider as lightning::util::events::MessageSendEventsProvider>::get_and_clear_pending_msg_events(&self.MessageSendEventsProvider)
	}
}
unsafe impl Send for ChannelMessageHandler {}
unsafe impl Sync for ChannelMessageHandler {}

use lightning::ln::msgs::ChannelMessageHandler as rustChannelMessageHandler;
impl rustChannelMessageHandler for ChannelMessageHandler {
	fn handle_open_channel(&self, their_node_id: &bitcoin::secp256k1::key::PublicKey, their_features: lightning::ln::features::InitFeatures, msg: &lightning::ln::msgs::OpenChannel) {
		(self.handle_open_channel)(self.this_arg, crate::c_types::PublicKey::from_rust(&their_node_id), crate::ln::features::InitFeatures { inner: Box::into_raw(Box::new(their_features)), is_owned: true }, &crate::ln::msgs::OpenChannel { inner: unsafe { (msg as *const _) as *mut _ }, is_owned: false })
	}
	fn handle_accept_channel(&self, their_node_id: &bitcoin::secp256k1::key::PublicKey, their_features: lightning::ln::features::InitFeatures, msg: &lightning::ln::msgs::AcceptChannel) {
		(self.handle_accept_channel)(self.this_arg, crate::c_types::PublicKey::from_rust(&their_node_id), crate::ln::features::InitFeatures { inner: Box::into_raw(Box::new(their_features)), is_owned: true }, &crate::ln::msgs::AcceptChannel { inner: unsafe { (msg as *const _) as *mut _ }, is_owned: false })
	}
	fn handle_funding_created(&self, their_node_id: &bitcoin::secp256k1::key::PublicKey, msg: &lightning::ln::msgs::FundingCreated) {
		(self.handle_funding_created)(self.this_arg, crate::c_types::PublicKey::from_rust(&their_node_id), &crate::ln::msgs::FundingCreated { inner: unsafe { (msg as *const _) as *mut _ }, is_owned: false })
	}
	fn handle_funding_signed(&self, their_node_id: &bitcoin::secp256k1::key::PublicKey, msg: &lightning::ln::msgs::FundingSigned) {
		(self.handle_funding_signed)(self.this_arg, crate::c_types::PublicKey::from_rust(&their_node_id), &crate::ln::msgs::FundingSigned { inner: unsafe { (msg as *const _) as *mut _ }, is_owned: false })
	}
	fn handle_funding_locked(&self, their_node_id: &bitcoin::secp256k1::key::PublicKey, msg: &lightning::ln::msgs::FundingLocked) {
		(self.handle_funding_locked)(self.this_arg, crate::c_types::PublicKey::from_rust(&their_node_id), &crate::ln::msgs::FundingLocked { inner: unsafe { (msg as *const _) as *mut _ }, is_owned: false })
	}
	fn handle_shutdown(&self, their_node_id: &bitcoin::secp256k1::key::PublicKey, msg: &lightning::ln::msgs::Shutdown) {
		(self.handle_shutdown)(self.this_arg, crate::c_types::PublicKey::from_rust(&their_node_id), &crate::ln::msgs::Shutdown { inner: unsafe { (msg as *const _) as *mut _ }, is_owned: false })
	}
	fn handle_closing_signed(&self, their_node_id: &bitcoin::secp256k1::key::PublicKey, msg: &lightning::ln::msgs::ClosingSigned) {
		(self.handle_closing_signed)(self.this_arg, crate::c_types::PublicKey::from_rust(&their_node_id), &crate::ln::msgs::ClosingSigned { inner: unsafe { (msg as *const _) as *mut _ }, is_owned: false })
	}
	fn handle_update_add_htlc(&self, their_node_id: &bitcoin::secp256k1::key::PublicKey, msg: &lightning::ln::msgs::UpdateAddHTLC) {
		(self.handle_update_add_htlc)(self.this_arg, crate::c_types::PublicKey::from_rust(&their_node_id), &crate::ln::msgs::UpdateAddHTLC { inner: unsafe { (msg as *const _) as *mut _ }, is_owned: false })
	}
	fn handle_update_fulfill_htlc(&self, their_node_id: &bitcoin::secp256k1::key::PublicKey, msg: &lightning::ln::msgs::UpdateFulfillHTLC) {
		(self.handle_update_fulfill_htlc)(self.this_arg, crate::c_types::PublicKey::from_rust(&their_node_id), &crate::ln::msgs::UpdateFulfillHTLC { inner: unsafe { (msg as *const _) as *mut _ }, is_owned: false })
	}
	fn handle_update_fail_htlc(&self, their_node_id: &bitcoin::secp256k1::key::PublicKey, msg: &lightning::ln::msgs::UpdateFailHTLC) {
		(self.handle_update_fail_htlc)(self.this_arg, crate::c_types::PublicKey::from_rust(&their_node_id), &crate::ln::msgs::UpdateFailHTLC { inner: unsafe { (msg as *const _) as *mut _ }, is_owned: false })
	}
	fn handle_update_fail_malformed_htlc(&self, their_node_id: &bitcoin::secp256k1::key::PublicKey, msg: &lightning::ln::msgs::UpdateFailMalformedHTLC) {
		(self.handle_update_fail_malformed_htlc)(self.this_arg, crate::c_types::PublicKey::from_rust(&their_node_id), &crate::ln::msgs::UpdateFailMalformedHTLC { inner: unsafe { (msg as *const _) as *mut _ }, is_owned: false })
	}
	fn handle_commitment_signed(&self, their_node_id: &bitcoin::secp256k1::key::PublicKey, msg: &lightning::ln::msgs::CommitmentSigned) {
		(self.handle_commitment_signed)(self.this_arg, crate::c_types::PublicKey::from_rust(&their_node_id), &crate::ln::msgs::CommitmentSigned { inner: unsafe { (msg as *const _) as *mut _ }, is_owned: false })
	}
	fn handle_revoke_and_ack(&self, their_node_id: &bitcoin::secp256k1::key::PublicKey, msg: &lightning::ln::msgs::RevokeAndACK) {
		(self.handle_revoke_and_ack)(self.this_arg, crate::c_types::PublicKey::from_rust(&their_node_id), &crate::ln::msgs::RevokeAndACK { inner: unsafe { (msg as *const _) as *mut _ }, is_owned: false })
	}
	fn handle_update_fee(&self, their_node_id: &bitcoin::secp256k1::key::PublicKey, msg: &lightning::ln::msgs::UpdateFee) {
		(self.handle_update_fee)(self.this_arg, crate::c_types::PublicKey::from_rust(&their_node_id), &crate::ln::msgs::UpdateFee { inner: unsafe { (msg as *const _) as *mut _ }, is_owned: false })
	}
	fn handle_announcement_signatures(&self, their_node_id: &bitcoin::secp256k1::key::PublicKey, msg: &lightning::ln::msgs::AnnouncementSignatures) {
		(self.handle_announcement_signatures)(self.this_arg, crate::c_types::PublicKey::from_rust(&their_node_id), &crate::ln::msgs::AnnouncementSignatures { inner: unsafe { (msg as *const _) as *mut _ }, is_owned: false })
	}
	fn peer_disconnected(&self, their_node_id: &bitcoin::secp256k1::key::PublicKey, no_connection_possible: bool) {
		(self.peer_disconnected)(self.this_arg, crate::c_types::PublicKey::from_rust(&their_node_id), no_connection_possible)
	}
	fn peer_connected(&self, their_node_id: &bitcoin::secp256k1::key::PublicKey, msg: &lightning::ln::msgs::Init) {
		(self.peer_connected)(self.this_arg, crate::c_types::PublicKey::from_rust(&their_node_id), &crate::ln::msgs::Init { inner: unsafe { (msg as *const _) as *mut _ }, is_owned: false })
	}
	fn handle_channel_reestablish(&self, their_node_id: &bitcoin::secp256k1::key::PublicKey, msg: &lightning::ln::msgs::ChannelReestablish) {
		(self.handle_channel_reestablish)(self.this_arg, crate::c_types::PublicKey::from_rust(&their_node_id), &crate::ln::msgs::ChannelReestablish { inner: unsafe { (msg as *const _) as *mut _ }, is_owned: false })
	}
	fn handle_error(&self, their_node_id: &bitcoin::secp256k1::key::PublicKey, msg: &lightning::ln::msgs::ErrorMessage) {
		(self.handle_error)(self.this_arg, crate::c_types::PublicKey::from_rust(&their_node_id), &crate::ln::msgs::ErrorMessage { inner: unsafe { (msg as *const _) as *mut _ }, is_owned: false })
	}
}

// We're essentially a pointer already, or at least a set of pointers, so allow us to be used
// directly as a Deref trait in higher-level structs:
impl std::ops::Deref for ChannelMessageHandler {
	type Target = Self;
	fn deref(&self) -> &Self {
		self
	}
}
/// Calls the free function if one is set
#[no_mangle]
pub extern "C" fn ChannelMessageHandler_free(this_ptr: ChannelMessageHandler) { }
impl Drop for ChannelMessageHandler {
	fn drop(&mut self) {
		if let Some(f) = self.free {
			f(self.this_arg);
		}
	}
}
/// A trait to describe an object which can receive routing messages.
///
/// # Implementor DoS Warnings
///
/// For `gossip_queries` messages there are potential DoS vectors when handling
/// inbound queries. Implementors using an on-disk network graph should be aware of
/// repeated disk I/O for queries accessing different parts of the network graph.
#[repr(C)]
pub struct RoutingMessageHandler {
	pub this_arg: *mut c_void,
	/// Handle an incoming node_announcement message, returning true if it should be forwarded on,
	/// false or returning an Err otherwise.
	#[must_use]
	pub handle_node_announcement: extern "C" fn (this_arg: *const c_void, msg: &crate::ln::msgs::NodeAnnouncement) -> crate::c_types::derived::CResult_boolLightningErrorZ,
	/// Handle a channel_announcement message, returning true if it should be forwarded on, false
	/// or returning an Err otherwise.
	#[must_use]
	pub handle_channel_announcement: extern "C" fn (this_arg: *const c_void, msg: &crate::ln::msgs::ChannelAnnouncement) -> crate::c_types::derived::CResult_boolLightningErrorZ,
	/// Handle an incoming channel_update message, returning true if it should be forwarded on,
	/// false or returning an Err otherwise.
	#[must_use]
	pub handle_channel_update: extern "C" fn (this_arg: *const c_void, msg: &crate::ln::msgs::ChannelUpdate) -> crate::c_types::derived::CResult_boolLightningErrorZ,
	/// Handle some updates to the route graph that we learned due to an outbound failed payment.
	pub handle_htlc_fail_channel_update: extern "C" fn (this_arg: *const c_void, update: &crate::ln::msgs::HTLCFailChannelUpdate),
	/// Gets a subset of the channel announcements and updates required to dump our routing table
	/// to a remote node, starting at the short_channel_id indicated by starting_point and
	/// including the batch_amount entries immediately higher in numerical value than starting_point.
	#[must_use]
	pub get_next_channel_announcements: extern "C" fn (this_arg: *const c_void, starting_point: u64, batch_amount: u8) -> crate::c_types::derived::CVec_C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZZ,
	/// Gets a subset of the node announcements required to dump our routing table to a remote node,
	/// starting at the node *after* the provided publickey and including batch_amount entries
	/// immediately higher (as defined by <PublicKey as Ord>::cmp) than starting_point.
	/// If None is provided for starting_point, we start at the first node.
	#[must_use]
	pub get_next_node_announcements: extern "C" fn (this_arg: *const c_void, starting_point: crate::c_types::PublicKey, batch_amount: u8) -> crate::c_types::derived::CVec_NodeAnnouncementZ,
	/// Called when a connection is established with a peer. This can be used to
	/// perform routing table synchronization using a strategy defined by the
	/// implementor.
	pub sync_routing_table: extern "C" fn (this_arg: *const c_void, their_node_id: crate::c_types::PublicKey, init: &crate::ln::msgs::Init),
	/// Handles the reply of a query we initiated to learn about channels
	/// for a given range of blocks. We can expect to receive one or more
	/// replies to a single query.
	#[must_use]
	pub handle_reply_channel_range: extern "C" fn (this_arg: *const c_void, their_node_id: crate::c_types::PublicKey, msg: crate::ln::msgs::ReplyChannelRange) -> crate::c_types::derived::CResult_NoneLightningErrorZ,
	/// Handles the reply of a query we initiated asking for routing gossip
	/// messages for a list of channels. We should receive this message when
	/// a node has completed its best effort to send us the pertaining routing
	/// gossip messages.
	#[must_use]
	pub handle_reply_short_channel_ids_end: extern "C" fn (this_arg: *const c_void, their_node_id: crate::c_types::PublicKey, msg: crate::ln::msgs::ReplyShortChannelIdsEnd) -> crate::c_types::derived::CResult_NoneLightningErrorZ,
	/// Handles when a peer asks us to send a list of short_channel_ids
	/// for the requested range of blocks.
	#[must_use]
	pub handle_query_channel_range: extern "C" fn (this_arg: *const c_void, their_node_id: crate::c_types::PublicKey, msg: crate::ln::msgs::QueryChannelRange) -> crate::c_types::derived::CResult_NoneLightningErrorZ,
	/// Handles when a peer asks us to send routing gossip messages for a
	/// list of short_channel_ids.
	#[must_use]
	pub handle_query_short_channel_ids: extern "C" fn (this_arg: *const c_void, their_node_id: crate::c_types::PublicKey, msg: crate::ln::msgs::QueryShortChannelIds) -> crate::c_types::derived::CResult_NoneLightningErrorZ,
	pub MessageSendEventsProvider: crate::util::events::MessageSendEventsProvider,
	pub free: Option<extern "C" fn(this_arg: *mut c_void)>,
}
unsafe impl Send for RoutingMessageHandler {}
unsafe impl Sync for RoutingMessageHandler {}
impl lightning::util::events::MessageSendEventsProvider for RoutingMessageHandler {
	fn get_and_clear_pending_msg_events(&self) -> Vec<lightning::util::events::MessageSendEvent> {
		<crate::util::events::MessageSendEventsProvider as lightning::util::events::MessageSendEventsProvider>::get_and_clear_pending_msg_events(&self.MessageSendEventsProvider)
	}
}

use lightning::ln::msgs::RoutingMessageHandler as rustRoutingMessageHandler;
impl rustRoutingMessageHandler for RoutingMessageHandler {
	fn handle_node_announcement(&self, msg: &lightning::ln::msgs::NodeAnnouncement) -> Result<bool, lightning::ln::msgs::LightningError> {
		let mut ret = (self.handle_node_announcement)(self.this_arg, &crate::ln::msgs::NodeAnnouncement { inner: unsafe { (msg as *const _) as *mut _ }, is_owned: false });
		let mut local_ret = match ret.result_ok { true => Ok( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) }) }), false => Err( { *unsafe { Box::from_raw((*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) }).take_inner()) } })};
		local_ret
	}
	fn handle_channel_announcement(&self, msg: &lightning::ln::msgs::ChannelAnnouncement) -> Result<bool, lightning::ln::msgs::LightningError> {
		let mut ret = (self.handle_channel_announcement)(self.this_arg, &crate::ln::msgs::ChannelAnnouncement { inner: unsafe { (msg as *const _) as *mut _ }, is_owned: false });
		let mut local_ret = match ret.result_ok { true => Ok( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) }) }), false => Err( { *unsafe { Box::from_raw((*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) }).take_inner()) } })};
		local_ret
	}
	fn handle_channel_update(&self, msg: &lightning::ln::msgs::ChannelUpdate) -> Result<bool, lightning::ln::msgs::LightningError> {
		let mut ret = (self.handle_channel_update)(self.this_arg, &crate::ln::msgs::ChannelUpdate { inner: unsafe { (msg as *const _) as *mut _ }, is_owned: false });
		let mut local_ret = match ret.result_ok { true => Ok( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) }) }), false => Err( { *unsafe { Box::from_raw((*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) }).take_inner()) } })};
		local_ret
	}
	fn handle_htlc_fail_channel_update(&self, update: &lightning::ln::msgs::HTLCFailChannelUpdate) {
		(self.handle_htlc_fail_channel_update)(self.this_arg, &crate::ln::msgs::HTLCFailChannelUpdate::from_native(&update))
	}
	fn get_next_channel_announcements(&self, starting_point: u64, batch_amount: u8) -> Vec<(lightning::ln::msgs::ChannelAnnouncement, Option<lightning::ln::msgs::ChannelUpdate>, Option<lightning::ln::msgs::ChannelUpdate>)> {
		let mut ret = (self.get_next_channel_announcements)(self.this_arg, starting_point, batch_amount);
		let mut local_ret = Vec::new(); for mut item in ret.into_rust().drain(..) { local_ret.push( { let (mut orig_ret_0_0, mut orig_ret_0_1, mut orig_ret_0_2) = item.to_rust(); let mut local_orig_ret_0_1 = if orig_ret_0_1.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(orig_ret_0_1.take_inner()) } }) }; let mut local_orig_ret_0_2 = if orig_ret_0_2.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(orig_ret_0_2.take_inner()) } }) }; let mut local_ret_0 = (*unsafe { Box::from_raw(orig_ret_0_0.take_inner()) }, local_orig_ret_0_1, local_orig_ret_0_2); local_ret_0 }); };
		local_ret
	}
	fn get_next_node_announcements(&self, starting_point: Option<&bitcoin::secp256k1::key::PublicKey>, batch_amount: u8) -> Vec<lightning::ln::msgs::NodeAnnouncement> {
		let mut local_starting_point = if starting_point.is_none() { crate::c_types::PublicKey::null() } else {  { crate::c_types::PublicKey::from_rust(&(starting_point.unwrap())) } };
		let mut ret = (self.get_next_node_announcements)(self.this_arg, local_starting_point, batch_amount);
		let mut local_ret = Vec::new(); for mut item in ret.into_rust().drain(..) { local_ret.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
		local_ret
	}
	fn sync_routing_table(&self, their_node_id: &bitcoin::secp256k1::key::PublicKey, init: &lightning::ln::msgs::Init) {
		(self.sync_routing_table)(self.this_arg, crate::c_types::PublicKey::from_rust(&their_node_id), &crate::ln::msgs::Init { inner: unsafe { (init as *const _) as *mut _ }, is_owned: false })
	}
	fn handle_reply_channel_range(&self, their_node_id: &bitcoin::secp256k1::key::PublicKey, msg: lightning::ln::msgs::ReplyChannelRange) -> Result<(), lightning::ln::msgs::LightningError> {
		let mut ret = (self.handle_reply_channel_range)(self.this_arg, crate::c_types::PublicKey::from_rust(&their_node_id), crate::ln::msgs::ReplyChannelRange { inner: Box::into_raw(Box::new(msg)), is_owned: true });
		let mut local_ret = match ret.result_ok { true => Ok( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) })*/ }), false => Err( { *unsafe { Box::from_raw((*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) }).take_inner()) } })};
		local_ret
	}
	fn handle_reply_short_channel_ids_end(&self, their_node_id: &bitcoin::secp256k1::key::PublicKey, msg: lightning::ln::msgs::ReplyShortChannelIdsEnd) -> Result<(), lightning::ln::msgs::LightningError> {
		let mut ret = (self.handle_reply_short_channel_ids_end)(self.this_arg, crate::c_types::PublicKey::from_rust(&their_node_id), crate::ln::msgs::ReplyShortChannelIdsEnd { inner: Box::into_raw(Box::new(msg)), is_owned: true });
		let mut local_ret = match ret.result_ok { true => Ok( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) })*/ }), false => Err( { *unsafe { Box::from_raw((*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) }).take_inner()) } })};
		local_ret
	}
	fn handle_query_channel_range(&self, their_node_id: &bitcoin::secp256k1::key::PublicKey, msg: lightning::ln::msgs::QueryChannelRange) -> Result<(), lightning::ln::msgs::LightningError> {
		let mut ret = (self.handle_query_channel_range)(self.this_arg, crate::c_types::PublicKey::from_rust(&their_node_id), crate::ln::msgs::QueryChannelRange { inner: Box::into_raw(Box::new(msg)), is_owned: true });
		let mut local_ret = match ret.result_ok { true => Ok( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) })*/ }), false => Err( { *unsafe { Box::from_raw((*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) }).take_inner()) } })};
		local_ret
	}
	fn handle_query_short_channel_ids(&self, their_node_id: &bitcoin::secp256k1::key::PublicKey, msg: lightning::ln::msgs::QueryShortChannelIds) -> Result<(), lightning::ln::msgs::LightningError> {
		let mut ret = (self.handle_query_short_channel_ids)(self.this_arg, crate::c_types::PublicKey::from_rust(&their_node_id), crate::ln::msgs::QueryShortChannelIds { inner: Box::into_raw(Box::new(msg)), is_owned: true });
		let mut local_ret = match ret.result_ok { true => Ok( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) })*/ }), false => Err( { *unsafe { Box::from_raw((*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) }).take_inner()) } })};
		local_ret
	}
}

// We're essentially a pointer already, or at least a set of pointers, so allow us to be used
// directly as a Deref trait in higher-level structs:
impl std::ops::Deref for RoutingMessageHandler {
	type Target = Self;
	fn deref(&self) -> &Self {
		self
	}
}
/// Calls the free function if one is set
#[no_mangle]
pub extern "C" fn RoutingMessageHandler_free(this_ptr: RoutingMessageHandler) { }
impl Drop for RoutingMessageHandler {
	fn drop(&mut self) {
		if let Some(f) = self.free {
			f(self.this_arg);
		}
	}
}
#[no_mangle]
pub extern "C" fn AcceptChannel_write(obj: &AcceptChannel) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*unsafe { &*obj }.inner })
}
#[no_mangle]
pub(crate) extern "C" fn AcceptChannel_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeAcceptChannel) })
}
#[no_mangle]
pub extern "C" fn AcceptChannel_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_AcceptChannelDecodeErrorZ {
	let res = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::ln::msgs::AcceptChannel { inner: Box::into_raw(Box::new(o)), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::ln::msgs::DecodeError { inner: Box::into_raw(Box::new(e)), is_owned: true } }).into() };
	local_res
}
#[no_mangle]
pub extern "C" fn AnnouncementSignatures_write(obj: &AnnouncementSignatures) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*unsafe { &*obj }.inner })
}
#[no_mangle]
pub(crate) extern "C" fn AnnouncementSignatures_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeAnnouncementSignatures) })
}
#[no_mangle]
pub extern "C" fn AnnouncementSignatures_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_AnnouncementSignaturesDecodeErrorZ {
	let res = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::ln::msgs::AnnouncementSignatures { inner: Box::into_raw(Box::new(o)), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::ln::msgs::DecodeError { inner: Box::into_raw(Box::new(e)), is_owned: true } }).into() };
	local_res
}
#[no_mangle]
pub extern "C" fn ChannelReestablish_write(obj: &ChannelReestablish) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*unsafe { &*obj }.inner })
}
#[no_mangle]
pub(crate) extern "C" fn ChannelReestablish_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeChannelReestablish) })
}
#[no_mangle]
pub extern "C" fn ChannelReestablish_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_ChannelReestablishDecodeErrorZ {
	let res = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::ln::msgs::ChannelReestablish { inner: Box::into_raw(Box::new(o)), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::ln::msgs::DecodeError { inner: Box::into_raw(Box::new(e)), is_owned: true } }).into() };
	local_res
}
#[no_mangle]
pub extern "C" fn ClosingSigned_write(obj: &ClosingSigned) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*unsafe { &*obj }.inner })
}
#[no_mangle]
pub(crate) extern "C" fn ClosingSigned_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeClosingSigned) })
}
#[no_mangle]
pub extern "C" fn ClosingSigned_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_ClosingSignedDecodeErrorZ {
	let res = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::ln::msgs::ClosingSigned { inner: Box::into_raw(Box::new(o)), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::ln::msgs::DecodeError { inner: Box::into_raw(Box::new(e)), is_owned: true } }).into() };
	local_res
}
#[no_mangle]
pub extern "C" fn CommitmentSigned_write(obj: &CommitmentSigned) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*unsafe { &*obj }.inner })
}
#[no_mangle]
pub(crate) extern "C" fn CommitmentSigned_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeCommitmentSigned) })
}
#[no_mangle]
pub extern "C" fn CommitmentSigned_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_CommitmentSignedDecodeErrorZ {
	let res = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::ln::msgs::CommitmentSigned { inner: Box::into_raw(Box::new(o)), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::ln::msgs::DecodeError { inner: Box::into_raw(Box::new(e)), is_owned: true } }).into() };
	local_res
}
#[no_mangle]
pub extern "C" fn FundingCreated_write(obj: &FundingCreated) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*unsafe { &*obj }.inner })
}
#[no_mangle]
pub(crate) extern "C" fn FundingCreated_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeFundingCreated) })
}
#[no_mangle]
pub extern "C" fn FundingCreated_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_FundingCreatedDecodeErrorZ {
	let res = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::ln::msgs::FundingCreated { inner: Box::into_raw(Box::new(o)), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::ln::msgs::DecodeError { inner: Box::into_raw(Box::new(e)), is_owned: true } }).into() };
	local_res
}
#[no_mangle]
pub extern "C" fn FundingSigned_write(obj: &FundingSigned) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*unsafe { &*obj }.inner })
}
#[no_mangle]
pub(crate) extern "C" fn FundingSigned_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeFundingSigned) })
}
#[no_mangle]
pub extern "C" fn FundingSigned_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_FundingSignedDecodeErrorZ {
	let res = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::ln::msgs::FundingSigned { inner: Box::into_raw(Box::new(o)), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::ln::msgs::DecodeError { inner: Box::into_raw(Box::new(e)), is_owned: true } }).into() };
	local_res
}
#[no_mangle]
pub extern "C" fn FundingLocked_write(obj: &FundingLocked) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*unsafe { &*obj }.inner })
}
#[no_mangle]
pub(crate) extern "C" fn FundingLocked_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeFundingLocked) })
}
#[no_mangle]
pub extern "C" fn FundingLocked_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_FundingLockedDecodeErrorZ {
	let res = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::ln::msgs::FundingLocked { inner: Box::into_raw(Box::new(o)), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::ln::msgs::DecodeError { inner: Box::into_raw(Box::new(e)), is_owned: true } }).into() };
	local_res
}
#[no_mangle]
pub extern "C" fn Init_write(obj: &Init) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*unsafe { &*obj }.inner })
}
#[no_mangle]
pub(crate) extern "C" fn Init_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeInit) })
}
#[no_mangle]
pub extern "C" fn Init_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_InitDecodeErrorZ {
	let res = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::ln::msgs::Init { inner: Box::into_raw(Box::new(o)), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::ln::msgs::DecodeError { inner: Box::into_raw(Box::new(e)), is_owned: true } }).into() };
	local_res
}
#[no_mangle]
pub extern "C" fn OpenChannel_write(obj: &OpenChannel) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*unsafe { &*obj }.inner })
}
#[no_mangle]
pub(crate) extern "C" fn OpenChannel_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeOpenChannel) })
}
#[no_mangle]
pub extern "C" fn OpenChannel_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_OpenChannelDecodeErrorZ {
	let res = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::ln::msgs::OpenChannel { inner: Box::into_raw(Box::new(o)), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::ln::msgs::DecodeError { inner: Box::into_raw(Box::new(e)), is_owned: true } }).into() };
	local_res
}
#[no_mangle]
pub extern "C" fn RevokeAndACK_write(obj: &RevokeAndACK) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*unsafe { &*obj }.inner })
}
#[no_mangle]
pub(crate) extern "C" fn RevokeAndACK_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeRevokeAndACK) })
}
#[no_mangle]
pub extern "C" fn RevokeAndACK_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_RevokeAndACKDecodeErrorZ {
	let res = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::ln::msgs::RevokeAndACK { inner: Box::into_raw(Box::new(o)), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::ln::msgs::DecodeError { inner: Box::into_raw(Box::new(e)), is_owned: true } }).into() };
	local_res
}
#[no_mangle]
pub extern "C" fn Shutdown_write(obj: &Shutdown) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*unsafe { &*obj }.inner })
}
#[no_mangle]
pub(crate) extern "C" fn Shutdown_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeShutdown) })
}
#[no_mangle]
pub extern "C" fn Shutdown_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_ShutdownDecodeErrorZ {
	let res = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::ln::msgs::Shutdown { inner: Box::into_raw(Box::new(o)), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::ln::msgs::DecodeError { inner: Box::into_raw(Box::new(e)), is_owned: true } }).into() };
	local_res
}
#[no_mangle]
pub extern "C" fn UpdateFailHTLC_write(obj: &UpdateFailHTLC) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*unsafe { &*obj }.inner })
}
#[no_mangle]
pub(crate) extern "C" fn UpdateFailHTLC_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeUpdateFailHTLC) })
}
#[no_mangle]
pub extern "C" fn UpdateFailHTLC_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_UpdateFailHTLCDecodeErrorZ {
	let res = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::ln::msgs::UpdateFailHTLC { inner: Box::into_raw(Box::new(o)), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::ln::msgs::DecodeError { inner: Box::into_raw(Box::new(e)), is_owned: true } }).into() };
	local_res
}
#[no_mangle]
pub extern "C" fn UpdateFailMalformedHTLC_write(obj: &UpdateFailMalformedHTLC) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*unsafe { &*obj }.inner })
}
#[no_mangle]
pub(crate) extern "C" fn UpdateFailMalformedHTLC_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeUpdateFailMalformedHTLC) })
}
#[no_mangle]
pub extern "C" fn UpdateFailMalformedHTLC_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_UpdateFailMalformedHTLCDecodeErrorZ {
	let res = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::ln::msgs::UpdateFailMalformedHTLC { inner: Box::into_raw(Box::new(o)), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::ln::msgs::DecodeError { inner: Box::into_raw(Box::new(e)), is_owned: true } }).into() };
	local_res
}
#[no_mangle]
pub extern "C" fn UpdateFee_write(obj: &UpdateFee) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*unsafe { &*obj }.inner })
}
#[no_mangle]
pub(crate) extern "C" fn UpdateFee_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeUpdateFee) })
}
#[no_mangle]
pub extern "C" fn UpdateFee_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_UpdateFeeDecodeErrorZ {
	let res = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::ln::msgs::UpdateFee { inner: Box::into_raw(Box::new(o)), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::ln::msgs::DecodeError { inner: Box::into_raw(Box::new(e)), is_owned: true } }).into() };
	local_res
}
#[no_mangle]
pub extern "C" fn UpdateFulfillHTLC_write(obj: &UpdateFulfillHTLC) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*unsafe { &*obj }.inner })
}
#[no_mangle]
pub(crate) extern "C" fn UpdateFulfillHTLC_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeUpdateFulfillHTLC) })
}
#[no_mangle]
pub extern "C" fn UpdateFulfillHTLC_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_UpdateFulfillHTLCDecodeErrorZ {
	let res = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::ln::msgs::UpdateFulfillHTLC { inner: Box::into_raw(Box::new(o)), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::ln::msgs::DecodeError { inner: Box::into_raw(Box::new(e)), is_owned: true } }).into() };
	local_res
}
#[no_mangle]
pub extern "C" fn UpdateAddHTLC_write(obj: &UpdateAddHTLC) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*unsafe { &*obj }.inner })
}
#[no_mangle]
pub(crate) extern "C" fn UpdateAddHTLC_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeUpdateAddHTLC) })
}
#[no_mangle]
pub extern "C" fn UpdateAddHTLC_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_UpdateAddHTLCDecodeErrorZ {
	let res = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::ln::msgs::UpdateAddHTLC { inner: Box::into_raw(Box::new(o)), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::ln::msgs::DecodeError { inner: Box::into_raw(Box::new(e)), is_owned: true } }).into() };
	local_res
}
#[no_mangle]
pub extern "C" fn Ping_write(obj: &Ping) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*unsafe { &*obj }.inner })
}
#[no_mangle]
pub(crate) extern "C" fn Ping_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativePing) })
}
#[no_mangle]
pub extern "C" fn Ping_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_PingDecodeErrorZ {
	let res = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::ln::msgs::Ping { inner: Box::into_raw(Box::new(o)), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::ln::msgs::DecodeError { inner: Box::into_raw(Box::new(e)), is_owned: true } }).into() };
	local_res
}
#[no_mangle]
pub extern "C" fn Pong_write(obj: &Pong) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*unsafe { &*obj }.inner })
}
#[no_mangle]
pub(crate) extern "C" fn Pong_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativePong) })
}
#[no_mangle]
pub extern "C" fn Pong_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_PongDecodeErrorZ {
	let res = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::ln::msgs::Pong { inner: Box::into_raw(Box::new(o)), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::ln::msgs::DecodeError { inner: Box::into_raw(Box::new(e)), is_owned: true } }).into() };
	local_res
}
#[no_mangle]
pub extern "C" fn UnsignedChannelAnnouncement_write(obj: &UnsignedChannelAnnouncement) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*unsafe { &*obj }.inner })
}
#[no_mangle]
pub(crate) extern "C" fn UnsignedChannelAnnouncement_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeUnsignedChannelAnnouncement) })
}
#[no_mangle]
pub extern "C" fn UnsignedChannelAnnouncement_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_UnsignedChannelAnnouncementDecodeErrorZ {
	let res = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::ln::msgs::UnsignedChannelAnnouncement { inner: Box::into_raw(Box::new(o)), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::ln::msgs::DecodeError { inner: Box::into_raw(Box::new(e)), is_owned: true } }).into() };
	local_res
}
#[no_mangle]
pub extern "C" fn ChannelAnnouncement_write(obj: &ChannelAnnouncement) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*unsafe { &*obj }.inner })
}
#[no_mangle]
pub(crate) extern "C" fn ChannelAnnouncement_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeChannelAnnouncement) })
}
#[no_mangle]
pub extern "C" fn ChannelAnnouncement_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_ChannelAnnouncementDecodeErrorZ {
	let res = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::ln::msgs::ChannelAnnouncement { inner: Box::into_raw(Box::new(o)), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::ln::msgs::DecodeError { inner: Box::into_raw(Box::new(e)), is_owned: true } }).into() };
	local_res
}
#[no_mangle]
pub extern "C" fn UnsignedChannelUpdate_write(obj: &UnsignedChannelUpdate) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*unsafe { &*obj }.inner })
}
#[no_mangle]
pub(crate) extern "C" fn UnsignedChannelUpdate_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeUnsignedChannelUpdate) })
}
#[no_mangle]
pub extern "C" fn UnsignedChannelUpdate_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_UnsignedChannelUpdateDecodeErrorZ {
	let res = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::ln::msgs::UnsignedChannelUpdate { inner: Box::into_raw(Box::new(o)), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::ln::msgs::DecodeError { inner: Box::into_raw(Box::new(e)), is_owned: true } }).into() };
	local_res
}
#[no_mangle]
pub extern "C" fn ChannelUpdate_write(obj: &ChannelUpdate) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*unsafe { &*obj }.inner })
}
#[no_mangle]
pub(crate) extern "C" fn ChannelUpdate_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeChannelUpdate) })
}
#[no_mangle]
pub extern "C" fn ChannelUpdate_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_ChannelUpdateDecodeErrorZ {
	let res = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::ln::msgs::ChannelUpdate { inner: Box::into_raw(Box::new(o)), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::ln::msgs::DecodeError { inner: Box::into_raw(Box::new(e)), is_owned: true } }).into() };
	local_res
}
#[no_mangle]
pub extern "C" fn ErrorMessage_write(obj: &ErrorMessage) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*unsafe { &*obj }.inner })
}
#[no_mangle]
pub(crate) extern "C" fn ErrorMessage_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeErrorMessage) })
}
#[no_mangle]
pub extern "C" fn ErrorMessage_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_ErrorMessageDecodeErrorZ {
	let res = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::ln::msgs::ErrorMessage { inner: Box::into_raw(Box::new(o)), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::ln::msgs::DecodeError { inner: Box::into_raw(Box::new(e)), is_owned: true } }).into() };
	local_res
}
#[no_mangle]
pub extern "C" fn UnsignedNodeAnnouncement_write(obj: &UnsignedNodeAnnouncement) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*unsafe { &*obj }.inner })
}
#[no_mangle]
pub(crate) extern "C" fn UnsignedNodeAnnouncement_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeUnsignedNodeAnnouncement) })
}
#[no_mangle]
pub extern "C" fn UnsignedNodeAnnouncement_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_UnsignedNodeAnnouncementDecodeErrorZ {
	let res = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::ln::msgs::UnsignedNodeAnnouncement { inner: Box::into_raw(Box::new(o)), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::ln::msgs::DecodeError { inner: Box::into_raw(Box::new(e)), is_owned: true } }).into() };
	local_res
}
#[no_mangle]
pub extern "C" fn NodeAnnouncement_write(obj: &NodeAnnouncement) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*unsafe { &*obj }.inner })
}
#[no_mangle]
pub(crate) extern "C" fn NodeAnnouncement_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeNodeAnnouncement) })
}
#[no_mangle]
pub extern "C" fn NodeAnnouncement_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_NodeAnnouncementDecodeErrorZ {
	let res = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::ln::msgs::NodeAnnouncement { inner: Box::into_raw(Box::new(o)), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::ln::msgs::DecodeError { inner: Box::into_raw(Box::new(e)), is_owned: true } }).into() };
	local_res
}
#[no_mangle]
pub extern "C" fn QueryShortChannelIds_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_QueryShortChannelIdsDecodeErrorZ {
	let res = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::ln::msgs::QueryShortChannelIds { inner: Box::into_raw(Box::new(o)), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::ln::msgs::DecodeError { inner: Box::into_raw(Box::new(e)), is_owned: true } }).into() };
	local_res
}
#[no_mangle]
pub extern "C" fn QueryShortChannelIds_write(obj: &QueryShortChannelIds) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*unsafe { &*obj }.inner })
}
#[no_mangle]
pub(crate) extern "C" fn QueryShortChannelIds_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeQueryShortChannelIds) })
}
#[no_mangle]
pub extern "C" fn ReplyShortChannelIdsEnd_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_ReplyShortChannelIdsEndDecodeErrorZ {
	let res = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::ln::msgs::ReplyShortChannelIdsEnd { inner: Box::into_raw(Box::new(o)), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::ln::msgs::DecodeError { inner: Box::into_raw(Box::new(e)), is_owned: true } }).into() };
	local_res
}
#[no_mangle]
pub extern "C" fn ReplyShortChannelIdsEnd_write(obj: &ReplyShortChannelIdsEnd) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*unsafe { &*obj }.inner })
}
#[no_mangle]
pub(crate) extern "C" fn ReplyShortChannelIdsEnd_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeReplyShortChannelIdsEnd) })
}
#[no_mangle]
pub extern "C" fn QueryChannelRange_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_QueryChannelRangeDecodeErrorZ {
	let res = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::ln::msgs::QueryChannelRange { inner: Box::into_raw(Box::new(o)), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::ln::msgs::DecodeError { inner: Box::into_raw(Box::new(e)), is_owned: true } }).into() };
	local_res
}
#[no_mangle]
pub extern "C" fn QueryChannelRange_write(obj: &QueryChannelRange) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*unsafe { &*obj }.inner })
}
#[no_mangle]
pub(crate) extern "C" fn QueryChannelRange_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeQueryChannelRange) })
}
#[no_mangle]
pub extern "C" fn ReplyChannelRange_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_ReplyChannelRangeDecodeErrorZ {
	let res = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::ln::msgs::ReplyChannelRange { inner: Box::into_raw(Box::new(o)), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::ln::msgs::DecodeError { inner: Box::into_raw(Box::new(e)), is_owned: true } }).into() };
	local_res
}
#[no_mangle]
pub extern "C" fn ReplyChannelRange_write(obj: &ReplyChannelRange) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*unsafe { &*obj }.inner })
}
#[no_mangle]
pub(crate) extern "C" fn ReplyChannelRange_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeReplyChannelRange) })
}
#[no_mangle]
pub extern "C" fn GossipTimestampFilter_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_GossipTimestampFilterDecodeErrorZ {
	let res = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::ln::msgs::GossipTimestampFilter { inner: Box::into_raw(Box::new(o)), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::ln::msgs::DecodeError { inner: Box::into_raw(Box::new(e)), is_owned: true } }).into() };
	local_res
}
#[no_mangle]
pub extern "C" fn GossipTimestampFilter_write(obj: &GossipTimestampFilter) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*unsafe { &*obj }.inner })
}
#[no_mangle]
pub(crate) extern "C" fn GossipTimestampFilter_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeGossipTimestampFilter) })
}
