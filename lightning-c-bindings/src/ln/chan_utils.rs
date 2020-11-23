//! Various utilities for building scripts and deriving keys related to channels. These are
//! largely of interest for those implementing chain::keysinterface::ChannelKeys message signing
//! by hand.

use std::ffi::c_void;
use bitcoin::hashes::Hash;
use crate::c_types::*;

/// Build the commitment secret from the seed and the commitment number
#[no_mangle]
pub extern "C" fn build_commitment_secret(commitment_seed: *const [u8; 32], mut idx: u64) -> crate::c_types::ThirtyTwoBytes {
	let mut ret = lightning::ln::chan_utils::build_commitment_secret(unsafe { &*commitment_seed}, idx);
	crate::c_types::ThirtyTwoBytes { data: ret }
}

/// Derives a per-commitment-transaction private key (eg an htlc key or delayed_payment key)
/// from the base secret and the per_commitment_point.
///
/// Note that this is infallible iff we trust that at least one of the two input keys are randomly
/// generated (ie our own).
#[no_mangle]
pub extern "C" fn derive_private_key(mut per_commitment_point: crate::c_types::PublicKey, base_secret: *const [u8; 32]) -> crate::c_types::derived::CResult_SecretKeySecpErrorZ {
	let mut ret = lightning::ln::chan_utils::derive_private_key(&bitcoin::secp256k1::Secp256k1::new(), &per_commitment_point.into_rust(), &::bitcoin::secp256k1::key::SecretKey::from_slice(&unsafe { *base_secret}[..]).unwrap());
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::c_types::SecretKey::from_rust(o) }), Err(mut e) => crate::c_types::CResultTempl::err( { crate::c_types::Secp256k1Error::from_rust(e) }) };
	local_ret
}

/// Derives a per-commitment-transaction public key (eg an htlc key or a delayed_payment key)
/// from the base point and the per_commitment_key. This is the public equivalent of
/// derive_private_key - using only public keys to derive a public key instead of private keys.
///
/// Note that this is infallible iff we trust that at least one of the two input keys are randomly
/// generated (ie our own).
#[no_mangle]
pub extern "C" fn derive_public_key(mut per_commitment_point: crate::c_types::PublicKey, mut base_point: crate::c_types::PublicKey) -> crate::c_types::derived::CResult_PublicKeySecpErrorZ {
	let mut ret = lightning::ln::chan_utils::derive_public_key(&bitcoin::secp256k1::Secp256k1::new(), &per_commitment_point.into_rust(), &base_point.into_rust());
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::c_types::PublicKey::from_rust(&o) }), Err(mut e) => crate::c_types::CResultTempl::err( { crate::c_types::Secp256k1Error::from_rust(e) }) };
	local_ret
}

/// Derives a per-commitment-transaction revocation key from its constituent parts.
///
/// Only the cheating participant owns a valid witness to propagate a revoked 
/// commitment transaction, thus per_commitment_secret always come from cheater
/// and revocation_base_secret always come from punisher, which is the broadcaster
/// of the transaction spending with this key knowledge.
///
/// Note that this is infallible iff we trust that at least one of the two input keys are randomly
/// generated (ie our own).
#[no_mangle]
pub extern "C" fn derive_private_revocation_key(per_commitment_secret: *const [u8; 32], countersignatory_revocation_base_secret: *const [u8; 32]) -> crate::c_types::derived::CResult_SecretKeySecpErrorZ {
	let mut ret = lightning::ln::chan_utils::derive_private_revocation_key(&bitcoin::secp256k1::Secp256k1::new(), &::bitcoin::secp256k1::key::SecretKey::from_slice(&unsafe { *per_commitment_secret}[..]).unwrap(), &::bitcoin::secp256k1::key::SecretKey::from_slice(&unsafe { *countersignatory_revocation_base_secret}[..]).unwrap());
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::c_types::SecretKey::from_rust(o) }), Err(mut e) => crate::c_types::CResultTempl::err( { crate::c_types::Secp256k1Error::from_rust(e) }) };
	local_ret
}

/// Derives a per-commitment-transaction revocation public key from its constituent parts. This is
/// the public equivalend of derive_private_revocation_key - using only public keys to derive a
/// public key instead of private keys.
///
/// Only the cheating participant owns a valid witness to propagate a revoked 
/// commitment transaction, thus per_commitment_point always come from cheater
/// and revocation_base_point always come from punisher, which is the broadcaster
/// of the transaction spending with this key knowledge.
///
/// Note that this is infallible iff we trust that at least one of the two input keys are randomly
/// generated (ie our own).
#[no_mangle]
pub extern "C" fn derive_public_revocation_key(mut per_commitment_point: crate::c_types::PublicKey, mut countersignatory_revocation_base_point: crate::c_types::PublicKey) -> crate::c_types::derived::CResult_PublicKeySecpErrorZ {
	let mut ret = lightning::ln::chan_utils::derive_public_revocation_key(&bitcoin::secp256k1::Secp256k1::new(), &per_commitment_point.into_rust(), &countersignatory_revocation_base_point.into_rust());
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::c_types::PublicKey::from_rust(&o) }), Err(mut e) => crate::c_types::CResultTempl::err( { crate::c_types::Secp256k1Error::from_rust(e) }) };
	local_ret
}


use lightning::ln::chan_utils::TxCreationKeys as nativeTxCreationKeysImport;
type nativeTxCreationKeys = nativeTxCreationKeysImport;

/// The set of public keys which are used in the creation of one commitment transaction.
/// These are derived from the channel base keys and per-commitment data.
///
/// A broadcaster key is provided from potential broadcaster of the computed transaction.
/// A countersignatory key is coming from a protocol participant unable to broadcast the
/// transaction.
///
/// These keys are assumed to be good, either because the code derived them from
/// channel basepoints via the new function, or they were obtained via
/// PreCalculatedTxCreationKeys.trust_key_derivation because we trusted the source of the
/// pre-calculated keys.
#[must_use]
#[repr(C)]
pub struct TxCreationKeys {
	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeTxCreationKeys,
	pub is_owned: bool,
}

impl Drop for TxCreationKeys {
	fn drop(&mut self) {
		if self.is_owned && !self.inner.is_null() {
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
#[no_mangle]
pub extern "C" fn TxCreationKeys_free(this_ptr: TxCreationKeys) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn TxCreationKeys_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeTxCreationKeys); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl TxCreationKeys {
	pub(crate) fn take_ptr(mut self) -> *mut nativeTxCreationKeys {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}
impl Clone for TxCreationKeys {
	fn clone(&self) -> Self {
		Self {
			inner: Box::into_raw(Box::new(unsafe { &*self.inner }.clone())),
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn TxCreationKeys_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeTxCreationKeys)).clone() })) as *mut c_void
}
#[no_mangle]
pub extern "C" fn TxCreationKeys_clone(orig: &TxCreationKeys) -> TxCreationKeys {
	TxCreationKeys { inner: Box::into_raw(Box::new(unsafe { &*orig.inner }.clone())), is_owned: true }
}
/// The broadcaster's per-commitment public key which was used to derive the other keys.
#[no_mangle]
pub extern "C" fn TxCreationKeys_get_per_commitment_point(this_ptr: &TxCreationKeys) -> crate::c_types::PublicKey {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.per_commitment_point;
	crate::c_types::PublicKey::from_rust(&(*inner_val))
}
/// The broadcaster's per-commitment public key which was used to derive the other keys.
#[no_mangle]
pub extern "C" fn TxCreationKeys_set_per_commitment_point(this_ptr: &mut TxCreationKeys, mut val: crate::c_types::PublicKey) {
	unsafe { &mut *this_ptr.inner }.per_commitment_point = val.into_rust();
}
/// The revocation key which is used to allow the broadcaster of the commitment
/// transaction to provide their counterparty the ability to punish them if they broadcast
/// an old state.
#[no_mangle]
pub extern "C" fn TxCreationKeys_get_revocation_key(this_ptr: &TxCreationKeys) -> crate::c_types::PublicKey {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.revocation_key;
	crate::c_types::PublicKey::from_rust(&(*inner_val))
}
/// The revocation key which is used to allow the broadcaster of the commitment
/// transaction to provide their counterparty the ability to punish them if they broadcast
/// an old state.
#[no_mangle]
pub extern "C" fn TxCreationKeys_set_revocation_key(this_ptr: &mut TxCreationKeys, mut val: crate::c_types::PublicKey) {
	unsafe { &mut *this_ptr.inner }.revocation_key = val.into_rust();
}
/// Broadcaster's HTLC Key
#[no_mangle]
pub extern "C" fn TxCreationKeys_get_broadcaster_htlc_key(this_ptr: &TxCreationKeys) -> crate::c_types::PublicKey {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.broadcaster_htlc_key;
	crate::c_types::PublicKey::from_rust(&(*inner_val))
}
/// Broadcaster's HTLC Key
#[no_mangle]
pub extern "C" fn TxCreationKeys_set_broadcaster_htlc_key(this_ptr: &mut TxCreationKeys, mut val: crate::c_types::PublicKey) {
	unsafe { &mut *this_ptr.inner }.broadcaster_htlc_key = val.into_rust();
}
/// Countersignatory's HTLC Key
#[no_mangle]
pub extern "C" fn TxCreationKeys_get_countersignatory_htlc_key(this_ptr: &TxCreationKeys) -> crate::c_types::PublicKey {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.countersignatory_htlc_key;
	crate::c_types::PublicKey::from_rust(&(*inner_val))
}
/// Countersignatory's HTLC Key
#[no_mangle]
pub extern "C" fn TxCreationKeys_set_countersignatory_htlc_key(this_ptr: &mut TxCreationKeys, mut val: crate::c_types::PublicKey) {
	unsafe { &mut *this_ptr.inner }.countersignatory_htlc_key = val.into_rust();
}
/// Broadcaster's Payment Key (which isn't allowed to be spent from for some delay)
#[no_mangle]
pub extern "C" fn TxCreationKeys_get_broadcaster_delayed_payment_key(this_ptr: &TxCreationKeys) -> crate::c_types::PublicKey {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.broadcaster_delayed_payment_key;
	crate::c_types::PublicKey::from_rust(&(*inner_val))
}
/// Broadcaster's Payment Key (which isn't allowed to be spent from for some delay)
#[no_mangle]
pub extern "C" fn TxCreationKeys_set_broadcaster_delayed_payment_key(this_ptr: &mut TxCreationKeys, mut val: crate::c_types::PublicKey) {
	unsafe { &mut *this_ptr.inner }.broadcaster_delayed_payment_key = val.into_rust();
}
#[must_use]
#[no_mangle]
pub extern "C" fn TxCreationKeys_new(mut per_commitment_point_arg: crate::c_types::PublicKey, mut revocation_key_arg: crate::c_types::PublicKey, mut broadcaster_htlc_key_arg: crate::c_types::PublicKey, mut countersignatory_htlc_key_arg: crate::c_types::PublicKey, mut broadcaster_delayed_payment_key_arg: crate::c_types::PublicKey) -> TxCreationKeys {
	TxCreationKeys { inner: Box::into_raw(Box::new(nativeTxCreationKeys {
		per_commitment_point: per_commitment_point_arg.into_rust(),
		revocation_key: revocation_key_arg.into_rust(),
		broadcaster_htlc_key: broadcaster_htlc_key_arg.into_rust(),
		countersignatory_htlc_key: countersignatory_htlc_key_arg.into_rust(),
		broadcaster_delayed_payment_key: broadcaster_delayed_payment_key_arg.into_rust(),
	})), is_owned: true }
}
#[no_mangle]
pub extern "C" fn TxCreationKeys_write(obj: *const TxCreationKeys) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &(*(*obj).inner) })
}
#[no_mangle]
pub extern "C" fn TxCreationKeys_read(ser: crate::c_types::u8slice) -> TxCreationKeys {
	if let Ok(res) = crate::c_types::deserialize_obj(ser) {
		TxCreationKeys { inner: Box::into_raw(Box::new(res)), is_owned: true }
	} else {
		TxCreationKeys { inner: std::ptr::null_mut(), is_owned: true }
	}
}

use lightning::ln::chan_utils::PreCalculatedTxCreationKeys as nativePreCalculatedTxCreationKeysImport;
type nativePreCalculatedTxCreationKeys = nativePreCalculatedTxCreationKeysImport;

/// The per-commitment point and a set of pre-calculated public keys used for transaction creation
/// in the signer.
/// The pre-calculated keys are an optimization, because ChannelKeys has enough
/// information to re-derive them.
#[must_use]
#[repr(C)]
pub struct PreCalculatedTxCreationKeys {
	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativePreCalculatedTxCreationKeys,
	pub is_owned: bool,
}

impl Drop for PreCalculatedTxCreationKeys {
	fn drop(&mut self) {
		if self.is_owned && !self.inner.is_null() {
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
#[no_mangle]
pub extern "C" fn PreCalculatedTxCreationKeys_free(this_ptr: PreCalculatedTxCreationKeys) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn PreCalculatedTxCreationKeys_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativePreCalculatedTxCreationKeys); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl PreCalculatedTxCreationKeys {
	pub(crate) fn take_ptr(mut self) -> *mut nativePreCalculatedTxCreationKeys {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}
impl Clone for PreCalculatedTxCreationKeys {
	fn clone(&self) -> Self {
		Self {
			inner: Box::into_raw(Box::new(unsafe { &*self.inner }.clone())),
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn PreCalculatedTxCreationKeys_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativePreCalculatedTxCreationKeys)).clone() })) as *mut c_void
}
#[no_mangle]
pub extern "C" fn PreCalculatedTxCreationKeys_clone(orig: &PreCalculatedTxCreationKeys) -> PreCalculatedTxCreationKeys {
	PreCalculatedTxCreationKeys { inner: Box::into_raw(Box::new(unsafe { &*orig.inner }.clone())), is_owned: true }
}
/// Create a new PreCalculatedTxCreationKeys from TxCreationKeys
#[must_use]
#[no_mangle]
pub extern "C" fn PreCalculatedTxCreationKeys_new(mut keys: crate::ln::chan_utils::TxCreationKeys) -> PreCalculatedTxCreationKeys {
	let mut ret = lightning::ln::chan_utils::PreCalculatedTxCreationKeys::new(*unsafe { Box::from_raw(keys.take_ptr()) });
	PreCalculatedTxCreationKeys { inner: Box::into_raw(Box::new(ret)), is_owned: true }
}

/// The pre-calculated transaction creation public keys.
/// An external validating signer should not trust these keys.
#[must_use]
#[no_mangle]
pub extern "C" fn PreCalculatedTxCreationKeys_trust_key_derivation(this_arg: &PreCalculatedTxCreationKeys) -> crate::ln::chan_utils::TxCreationKeys {
	let mut ret = unsafe { &*this_arg.inner }.trust_key_derivation();
	crate::ln::chan_utils::TxCreationKeys { inner: unsafe { ( (&(*ret) as *const _) as *mut _) }, is_owned: false }
}

/// The transaction per-commitment point
#[must_use]
#[no_mangle]
pub extern "C" fn PreCalculatedTxCreationKeys_per_commitment_point(this_arg: &PreCalculatedTxCreationKeys) -> crate::c_types::PublicKey {
	let mut ret = unsafe { &*this_arg.inner }.per_commitment_point();
	crate::c_types::PublicKey::from_rust(&*ret)
}


use lightning::ln::chan_utils::ChannelPublicKeys as nativeChannelPublicKeysImport;
type nativeChannelPublicKeys = nativeChannelPublicKeysImport;

/// One counterparty's public keys which do not change over the life of a channel.
#[must_use]
#[repr(C)]
pub struct ChannelPublicKeys {
	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeChannelPublicKeys,
	pub is_owned: bool,
}

impl Drop for ChannelPublicKeys {
	fn drop(&mut self) {
		if self.is_owned && !self.inner.is_null() {
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
#[no_mangle]
pub extern "C" fn ChannelPublicKeys_free(this_ptr: ChannelPublicKeys) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn ChannelPublicKeys_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeChannelPublicKeys); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl ChannelPublicKeys {
	pub(crate) fn take_ptr(mut self) -> *mut nativeChannelPublicKeys {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}
impl Clone for ChannelPublicKeys {
	fn clone(&self) -> Self {
		Self {
			inner: Box::into_raw(Box::new(unsafe { &*self.inner }.clone())),
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ChannelPublicKeys_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeChannelPublicKeys)).clone() })) as *mut c_void
}
#[no_mangle]
pub extern "C" fn ChannelPublicKeys_clone(orig: &ChannelPublicKeys) -> ChannelPublicKeys {
	ChannelPublicKeys { inner: Box::into_raw(Box::new(unsafe { &*orig.inner }.clone())), is_owned: true }
}
/// The public key which is used to sign all commitment transactions, as it appears in the
/// on-chain channel lock-in 2-of-2 multisig output.
#[no_mangle]
pub extern "C" fn ChannelPublicKeys_get_funding_pubkey(this_ptr: &ChannelPublicKeys) -> crate::c_types::PublicKey {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.funding_pubkey;
	crate::c_types::PublicKey::from_rust(&(*inner_val))
}
/// The public key which is used to sign all commitment transactions, as it appears in the
/// on-chain channel lock-in 2-of-2 multisig output.
#[no_mangle]
pub extern "C" fn ChannelPublicKeys_set_funding_pubkey(this_ptr: &mut ChannelPublicKeys, mut val: crate::c_types::PublicKey) {
	unsafe { &mut *this_ptr.inner }.funding_pubkey = val.into_rust();
}
/// The base point which is used (with derive_public_revocation_key) to derive per-commitment
/// revocation keys. This is combined with the per-commitment-secret generated by the
/// counterparty to create a secret which the counterparty can reveal to revoke previous
/// states.
#[no_mangle]
pub extern "C" fn ChannelPublicKeys_get_revocation_basepoint(this_ptr: &ChannelPublicKeys) -> crate::c_types::PublicKey {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.revocation_basepoint;
	crate::c_types::PublicKey::from_rust(&(*inner_val))
}
/// The base point which is used (with derive_public_revocation_key) to derive per-commitment
/// revocation keys. This is combined with the per-commitment-secret generated by the
/// counterparty to create a secret which the counterparty can reveal to revoke previous
/// states.
#[no_mangle]
pub extern "C" fn ChannelPublicKeys_set_revocation_basepoint(this_ptr: &mut ChannelPublicKeys, mut val: crate::c_types::PublicKey) {
	unsafe { &mut *this_ptr.inner }.revocation_basepoint = val.into_rust();
}
/// The public key on which the non-broadcaster (ie the countersignatory) receives an immediately
/// spendable primary channel balance on the broadcaster's commitment transaction. This key is
/// static across every commitment transaction.
#[no_mangle]
pub extern "C" fn ChannelPublicKeys_get_payment_point(this_ptr: &ChannelPublicKeys) -> crate::c_types::PublicKey {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.payment_point;
	crate::c_types::PublicKey::from_rust(&(*inner_val))
}
/// The public key on which the non-broadcaster (ie the countersignatory) receives an immediately
/// spendable primary channel balance on the broadcaster's commitment transaction. This key is
/// static across every commitment transaction.
#[no_mangle]
pub extern "C" fn ChannelPublicKeys_set_payment_point(this_ptr: &mut ChannelPublicKeys, mut val: crate::c_types::PublicKey) {
	unsafe { &mut *this_ptr.inner }.payment_point = val.into_rust();
}
/// The base point which is used (with derive_public_key) to derive a per-commitment payment
/// public key which receives non-HTLC-encumbered funds which are only available for spending
/// after some delay (or can be claimed via the revocation path).
#[no_mangle]
pub extern "C" fn ChannelPublicKeys_get_delayed_payment_basepoint(this_ptr: &ChannelPublicKeys) -> crate::c_types::PublicKey {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.delayed_payment_basepoint;
	crate::c_types::PublicKey::from_rust(&(*inner_val))
}
/// The base point which is used (with derive_public_key) to derive a per-commitment payment
/// public key which receives non-HTLC-encumbered funds which are only available for spending
/// after some delay (or can be claimed via the revocation path).
#[no_mangle]
pub extern "C" fn ChannelPublicKeys_set_delayed_payment_basepoint(this_ptr: &mut ChannelPublicKeys, mut val: crate::c_types::PublicKey) {
	unsafe { &mut *this_ptr.inner }.delayed_payment_basepoint = val.into_rust();
}
/// The base point which is used (with derive_public_key) to derive a per-commitment public key
/// which is used to encumber HTLC-in-flight outputs.
#[no_mangle]
pub extern "C" fn ChannelPublicKeys_get_htlc_basepoint(this_ptr: &ChannelPublicKeys) -> crate::c_types::PublicKey {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.htlc_basepoint;
	crate::c_types::PublicKey::from_rust(&(*inner_val))
}
/// The base point which is used (with derive_public_key) to derive a per-commitment public key
/// which is used to encumber HTLC-in-flight outputs.
#[no_mangle]
pub extern "C" fn ChannelPublicKeys_set_htlc_basepoint(this_ptr: &mut ChannelPublicKeys, mut val: crate::c_types::PublicKey) {
	unsafe { &mut *this_ptr.inner }.htlc_basepoint = val.into_rust();
}
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelPublicKeys_new(mut funding_pubkey_arg: crate::c_types::PublicKey, mut revocation_basepoint_arg: crate::c_types::PublicKey, mut payment_point_arg: crate::c_types::PublicKey, mut delayed_payment_basepoint_arg: crate::c_types::PublicKey, mut htlc_basepoint_arg: crate::c_types::PublicKey) -> ChannelPublicKeys {
	ChannelPublicKeys { inner: Box::into_raw(Box::new(nativeChannelPublicKeys {
		funding_pubkey: funding_pubkey_arg.into_rust(),
		revocation_basepoint: revocation_basepoint_arg.into_rust(),
		payment_point: payment_point_arg.into_rust(),
		delayed_payment_basepoint: delayed_payment_basepoint_arg.into_rust(),
		htlc_basepoint: htlc_basepoint_arg.into_rust(),
	})), is_owned: true }
}
#[no_mangle]
pub extern "C" fn ChannelPublicKeys_write(obj: *const ChannelPublicKeys) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &(*(*obj).inner) })
}
#[no_mangle]
pub extern "C" fn ChannelPublicKeys_read(ser: crate::c_types::u8slice) -> ChannelPublicKeys {
	if let Ok(res) = crate::c_types::deserialize_obj(ser) {
		ChannelPublicKeys { inner: Box::into_raw(Box::new(res)), is_owned: true }
	} else {
		ChannelPublicKeys { inner: std::ptr::null_mut(), is_owned: true }
	}
}
/// Create a new TxCreationKeys from channel base points and the per-commitment point
#[must_use]
#[no_mangle]
pub extern "C" fn TxCreationKeys_derive_new(mut per_commitment_point: crate::c_types::PublicKey, mut broadcaster_delayed_payment_base: crate::c_types::PublicKey, mut broadcaster_htlc_base: crate::c_types::PublicKey, mut countersignatory_revocation_base: crate::c_types::PublicKey, mut countersignatory_htlc_base: crate::c_types::PublicKey) -> crate::c_types::derived::CResult_TxCreationKeysSecpErrorZ {
	let mut ret = lightning::ln::chan_utils::TxCreationKeys::derive_new(&bitcoin::secp256k1::Secp256k1::new(), &per_commitment_point.into_rust(), &broadcaster_delayed_payment_base.into_rust(), &broadcaster_htlc_base.into_rust(), &countersignatory_revocation_base.into_rust(), &countersignatory_htlc_base.into_rust());
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::ln::chan_utils::TxCreationKeys { inner: Box::into_raw(Box::new(o)), is_owned: true } }), Err(mut e) => crate::c_types::CResultTempl::err( { crate::c_types::Secp256k1Error::from_rust(e) }) };
	local_ret
}

/// A script either spendable by the revocation
/// key or the broadcaster_delayed_payment_key and satisfying the relative-locktime OP_CSV constrain.
/// Encumbering a `to_holder` output on a commitment transaction or 2nd-stage HTLC transactions.
#[no_mangle]
pub extern "C" fn get_revokeable_redeemscript(mut revocation_key: crate::c_types::PublicKey, mut contest_delay: u16, mut broadcaster_delayed_payment_key: crate::c_types::PublicKey) -> crate::c_types::derived::CVec_u8Z {
	let mut ret = lightning::ln::chan_utils::get_revokeable_redeemscript(&revocation_key.into_rust(), contest_delay, &broadcaster_delayed_payment_key.into_rust());
	ret.into_bytes().into()
}


use lightning::ln::chan_utils::HTLCOutputInCommitment as nativeHTLCOutputInCommitmentImport;
type nativeHTLCOutputInCommitment = nativeHTLCOutputInCommitmentImport;

/// Information about an HTLC as it appears in a commitment transaction
#[must_use]
#[repr(C)]
pub struct HTLCOutputInCommitment {
	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeHTLCOutputInCommitment,
	pub is_owned: bool,
}

impl Drop for HTLCOutputInCommitment {
	fn drop(&mut self) {
		if self.is_owned && !self.inner.is_null() {
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
#[no_mangle]
pub extern "C" fn HTLCOutputInCommitment_free(this_ptr: HTLCOutputInCommitment) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn HTLCOutputInCommitment_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeHTLCOutputInCommitment); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl HTLCOutputInCommitment {
	pub(crate) fn take_ptr(mut self) -> *mut nativeHTLCOutputInCommitment {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}
impl Clone for HTLCOutputInCommitment {
	fn clone(&self) -> Self {
		Self {
			inner: Box::into_raw(Box::new(unsafe { &*self.inner }.clone())),
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn HTLCOutputInCommitment_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeHTLCOutputInCommitment)).clone() })) as *mut c_void
}
#[no_mangle]
pub extern "C" fn HTLCOutputInCommitment_clone(orig: &HTLCOutputInCommitment) -> HTLCOutputInCommitment {
	HTLCOutputInCommitment { inner: Box::into_raw(Box::new(unsafe { &*orig.inner }.clone())), is_owned: true }
}
/// Whether the HTLC was \"offered\" (ie outbound in relation to this commitment transaction).
/// Note that this is not the same as whether it is ountbound *from us*. To determine that you
/// need to compare this value to whether the commitment transaction in question is that of
/// the counterparty or our own.
#[no_mangle]
pub extern "C" fn HTLCOutputInCommitment_get_offered(this_ptr: &HTLCOutputInCommitment) -> bool {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.offered;
	(*inner_val)
}
/// Whether the HTLC was \"offered\" (ie outbound in relation to this commitment transaction).
/// Note that this is not the same as whether it is ountbound *from us*. To determine that you
/// need to compare this value to whether the commitment transaction in question is that of
/// the counterparty or our own.
#[no_mangle]
pub extern "C" fn HTLCOutputInCommitment_set_offered(this_ptr: &mut HTLCOutputInCommitment, mut val: bool) {
	unsafe { &mut *this_ptr.inner }.offered = val;
}
/// The value, in msat, of the HTLC. The value as it appears in the commitment transaction is
/// this divided by 1000.
#[no_mangle]
pub extern "C" fn HTLCOutputInCommitment_get_amount_msat(this_ptr: &HTLCOutputInCommitment) -> u64 {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.amount_msat;
	(*inner_val)
}
/// The value, in msat, of the HTLC. The value as it appears in the commitment transaction is
/// this divided by 1000.
#[no_mangle]
pub extern "C" fn HTLCOutputInCommitment_set_amount_msat(this_ptr: &mut HTLCOutputInCommitment, mut val: u64) {
	unsafe { &mut *this_ptr.inner }.amount_msat = val;
}
/// The CLTV lock-time at which this HTLC expires.
#[no_mangle]
pub extern "C" fn HTLCOutputInCommitment_get_cltv_expiry(this_ptr: &HTLCOutputInCommitment) -> u32 {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.cltv_expiry;
	(*inner_val)
}
/// The CLTV lock-time at which this HTLC expires.
#[no_mangle]
pub extern "C" fn HTLCOutputInCommitment_set_cltv_expiry(this_ptr: &mut HTLCOutputInCommitment, mut val: u32) {
	unsafe { &mut *this_ptr.inner }.cltv_expiry = val;
}
/// The hash of the preimage which unlocks this HTLC.
#[no_mangle]
pub extern "C" fn HTLCOutputInCommitment_get_payment_hash(this_ptr: &HTLCOutputInCommitment) -> *const [u8; 32] {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.payment_hash;
	&(*inner_val).0
}
/// The hash of the preimage which unlocks this HTLC.
#[no_mangle]
pub extern "C" fn HTLCOutputInCommitment_set_payment_hash(this_ptr: &mut HTLCOutputInCommitment, mut val: crate::c_types::ThirtyTwoBytes) {
	unsafe { &mut *this_ptr.inner }.payment_hash = ::lightning::ln::channelmanager::PaymentHash(val.data);
}
#[no_mangle]
pub extern "C" fn HTLCOutputInCommitment_write(obj: *const HTLCOutputInCommitment) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &(*(*obj).inner) })
}
#[no_mangle]
pub extern "C" fn HTLCOutputInCommitment_read(ser: crate::c_types::u8slice) -> HTLCOutputInCommitment {
	if let Ok(res) = crate::c_types::deserialize_obj(ser) {
		HTLCOutputInCommitment { inner: Box::into_raw(Box::new(res)), is_owned: true }
	} else {
		HTLCOutputInCommitment { inner: std::ptr::null_mut(), is_owned: true }
	}
}
/// Gets the witness redeemscript for an HTLC output in a commitment transaction. Note that htlc
/// does not need to have its previous_output_index filled.
#[no_mangle]
pub extern "C" fn get_htlc_redeemscript(htlc: &crate::ln::chan_utils::HTLCOutputInCommitment, keys: &crate::ln::chan_utils::TxCreationKeys) -> crate::c_types::derived::CVec_u8Z {
	let mut ret = lightning::ln::chan_utils::get_htlc_redeemscript(unsafe { &*htlc.inner }, unsafe { &*keys.inner });
	ret.into_bytes().into()
}

/// Gets the redeemscript for a funding output from the two funding public keys.
/// Note that the order of funding public keys does not matter.
#[no_mangle]
pub extern "C" fn make_funding_redeemscript(mut broadcaster: crate::c_types::PublicKey, mut countersignatory: crate::c_types::PublicKey) -> crate::c_types::derived::CVec_u8Z {
	let mut ret = lightning::ln::chan_utils::make_funding_redeemscript(&broadcaster.into_rust(), &countersignatory.into_rust());
	ret.into_bytes().into()
}

/// panics if htlc.transaction_output_index.is_none()!
#[no_mangle]
pub extern "C" fn build_htlc_transaction(prev_hash: *const [u8; 32], mut feerate_per_kw: u32, mut contest_delay: u16, htlc: &crate::ln::chan_utils::HTLCOutputInCommitment, mut broadcaster_delayed_payment_key: crate::c_types::PublicKey, mut revocation_key: crate::c_types::PublicKey) -> crate::c_types::Transaction {
	let mut ret = lightning::ln::chan_utils::build_htlc_transaction(&::bitcoin::hash_types::Txid::from_slice(&unsafe { &*prev_hash }[..]).unwrap(), feerate_per_kw, contest_delay, unsafe { &*htlc.inner }, &broadcaster_delayed_payment_key.into_rust(), &revocation_key.into_rust());
	let mut local_ret = ::bitcoin::consensus::encode::serialize(&ret);
	crate::c_types::Transaction::from_vec(local_ret)
}


use lightning::ln::chan_utils::HolderCommitmentTransaction as nativeHolderCommitmentTransactionImport;
type nativeHolderCommitmentTransaction = nativeHolderCommitmentTransactionImport;

/// We use this to track holder commitment transactions and put off signing them until we are ready
/// to broadcast. This class can be used inside a signer implementation to generate a signature
/// given the relevant secret key.
#[must_use]
#[repr(C)]
pub struct HolderCommitmentTransaction {
	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeHolderCommitmentTransaction,
	pub is_owned: bool,
}

impl Drop for HolderCommitmentTransaction {
	fn drop(&mut self) {
		if self.is_owned && !self.inner.is_null() {
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
#[no_mangle]
pub extern "C" fn HolderCommitmentTransaction_free(this_ptr: HolderCommitmentTransaction) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn HolderCommitmentTransaction_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeHolderCommitmentTransaction); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl HolderCommitmentTransaction {
	pub(crate) fn take_ptr(mut self) -> *mut nativeHolderCommitmentTransaction {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}
impl Clone for HolderCommitmentTransaction {
	fn clone(&self) -> Self {
		Self {
			inner: Box::into_raw(Box::new(unsafe { &*self.inner }.clone())),
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn HolderCommitmentTransaction_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeHolderCommitmentTransaction)).clone() })) as *mut c_void
}
#[no_mangle]
pub extern "C" fn HolderCommitmentTransaction_clone(orig: &HolderCommitmentTransaction) -> HolderCommitmentTransaction {
	HolderCommitmentTransaction { inner: Box::into_raw(Box::new(unsafe { &*orig.inner }.clone())), is_owned: true }
}
/// The commitment transaction itself, in unsigned form.
#[no_mangle]
pub extern "C" fn HolderCommitmentTransaction_get_unsigned_tx(this_ptr: &HolderCommitmentTransaction) -> crate::c_types::Transaction {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.unsigned_tx;
	let mut local_inner_val = ::bitcoin::consensus::encode::serialize(inner_val);
	crate::c_types::Transaction::from_vec(local_inner_val)
}
/// The commitment transaction itself, in unsigned form.
#[no_mangle]
pub extern "C" fn HolderCommitmentTransaction_set_unsigned_tx(this_ptr: &mut HolderCommitmentTransaction, mut val: crate::c_types::Transaction) {
	unsafe { &mut *this_ptr.inner }.unsigned_tx = val.into_bitcoin();
}
/// Our counterparty's signature for the transaction, above.
#[no_mangle]
pub extern "C" fn HolderCommitmentTransaction_get_counterparty_sig(this_ptr: &HolderCommitmentTransaction) -> crate::c_types::Signature {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.counterparty_sig;
	crate::c_types::Signature::from_rust(&(*inner_val))
}
/// Our counterparty's signature for the transaction, above.
#[no_mangle]
pub extern "C" fn HolderCommitmentTransaction_set_counterparty_sig(this_ptr: &mut HolderCommitmentTransaction, mut val: crate::c_types::Signature) {
	unsafe { &mut *this_ptr.inner }.counterparty_sig = val.into_rust();
}
/// The feerate paid per 1000-weight-unit in this commitment transaction. This value is
/// controlled by the channel initiator.
#[no_mangle]
pub extern "C" fn HolderCommitmentTransaction_get_feerate_per_kw(this_ptr: &HolderCommitmentTransaction) -> u32 {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.feerate_per_kw;
	(*inner_val)
}
/// The feerate paid per 1000-weight-unit in this commitment transaction. This value is
/// controlled by the channel initiator.
#[no_mangle]
pub extern "C" fn HolderCommitmentTransaction_set_feerate_per_kw(this_ptr: &mut HolderCommitmentTransaction, mut val: u32) {
	unsafe { &mut *this_ptr.inner }.feerate_per_kw = val;
}
/// The HTLCs and counterparty htlc signatures which were included in this commitment transaction.
///
/// Note that this includes all HTLCs, including ones which were considered dust and not
/// actually included in the transaction as it appears on-chain, but who's value is burned as
/// fees and not included in the to_holder or to_counterparty outputs.
///
/// The counterparty HTLC signatures in the second element will always be set for non-dust HTLCs, ie
/// those for which transaction_output_index.is_some().
#[no_mangle]
pub extern "C" fn HolderCommitmentTransaction_set_per_htlc(this_ptr: &mut HolderCommitmentTransaction, mut val: crate::c_types::derived::CVec_C2Tuple_HTLCOutputInCommitmentSignatureZZ) {
	let mut local_val = Vec::new(); for mut item in val.into_rust().drain(..) { local_val.push( { let (mut orig_val_0_0, mut orig_val_0_1) = item.to_rust(); let mut local_orig_val_0_1 = if orig_val_0_1.is_null() { None } else { Some( { orig_val_0_1.into_rust() }) }; let mut local_val_0 = (*unsafe { Box::from_raw(orig_val_0_0.take_ptr()) }, local_orig_val_0_1); local_val_0 }); };
	unsafe { &mut *this_ptr.inner }.per_htlc = local_val;
}
/// Generate a new HolderCommitmentTransaction based on a raw commitment transaction,
/// counterparty signature and both parties keys.
///
/// The unsigned transaction outputs must be consistent with htlc_data.  This function
/// only checks that the shape and amounts are consistent, but does not check the scriptPubkey.
#[must_use]
#[no_mangle]
pub extern "C" fn HolderCommitmentTransaction_new_missing_holder_sig(mut unsigned_tx: crate::c_types::Transaction, mut counterparty_sig: crate::c_types::Signature, mut holder_funding_key: crate::c_types::PublicKey, mut counterparty_funding_key: crate::c_types::PublicKey, mut keys: crate::ln::chan_utils::TxCreationKeys, mut feerate_per_kw: u32, mut htlc_data: crate::c_types::derived::CVec_C2Tuple_HTLCOutputInCommitmentSignatureZZ) -> crate::ln::chan_utils::HolderCommitmentTransaction {
	let mut local_htlc_data = Vec::new(); for mut item in htlc_data.into_rust().drain(..) { local_htlc_data.push( { let (mut orig_htlc_data_0_0, mut orig_htlc_data_0_1) = item.to_rust(); let mut local_orig_htlc_data_0_1 = if orig_htlc_data_0_1.is_null() { None } else { Some( { orig_htlc_data_0_1.into_rust() }) }; let mut local_htlc_data_0 = (*unsafe { Box::from_raw(orig_htlc_data_0_0.take_ptr()) }, local_orig_htlc_data_0_1); local_htlc_data_0 }); };
	let mut ret = lightning::ln::chan_utils::HolderCommitmentTransaction::new_missing_holder_sig(unsigned_tx.into_bitcoin(), counterparty_sig.into_rust(), &holder_funding_key.into_rust(), &counterparty_funding_key.into_rust(), *unsafe { Box::from_raw(keys.take_ptr()) }, feerate_per_kw, local_htlc_data);
	crate::ln::chan_utils::HolderCommitmentTransaction { inner: Box::into_raw(Box::new(ret)), is_owned: true }
}

/// The pre-calculated transaction creation public keys.
/// An external validating signer should not trust these keys.
#[must_use]
#[no_mangle]
pub extern "C" fn HolderCommitmentTransaction_trust_key_derivation(this_arg: &HolderCommitmentTransaction) -> crate::ln::chan_utils::TxCreationKeys {
	let mut ret = unsafe { &*this_arg.inner }.trust_key_derivation();
	crate::ln::chan_utils::TxCreationKeys { inner: unsafe { ( (&(*ret) as *const _) as *mut _) }, is_owned: false }
}

/// Get the txid of the holder commitment transaction contained in this
/// HolderCommitmentTransaction
#[must_use]
#[no_mangle]
pub extern "C" fn HolderCommitmentTransaction_txid(this_arg: &HolderCommitmentTransaction) -> crate::c_types::ThirtyTwoBytes {
	let mut ret = unsafe { &*this_arg.inner }.txid();
	crate::c_types::ThirtyTwoBytes { data: ret.into_inner() }
}

/// Gets holder signature for the contained commitment transaction given holder funding private key.
///
/// Funding key is your key included in the 2-2 funding_outpoint lock. Should be provided
/// by your ChannelKeys.
/// Funding redeemscript is script locking funding_outpoint. This is the mutlsig script
/// between your own funding key and your counterparty's. Currently, this is provided in
/// ChannelKeys::sign_holder_commitment() calls directly.
/// Channel value is amount locked in funding_outpoint.
#[must_use]
#[no_mangle]
pub extern "C" fn HolderCommitmentTransaction_get_holder_sig(this_arg: &HolderCommitmentTransaction, funding_key: *const [u8; 32], mut funding_redeemscript: crate::c_types::u8slice, mut channel_value_satoshis: u64) -> crate::c_types::Signature {
	let mut ret = unsafe { &*this_arg.inner }.get_holder_sig(&::bitcoin::secp256k1::key::SecretKey::from_slice(&unsafe { *funding_key}[..]).unwrap(), &::bitcoin::blockdata::script::Script::from(Vec::from(funding_redeemscript.to_slice())), channel_value_satoshis, &bitcoin::secp256k1::Secp256k1::new());
	crate::c_types::Signature::from_rust(&ret)
}

/// Get a signature for each HTLC which was included in the commitment transaction (ie for
/// which HTLCOutputInCommitment::transaction_output_index.is_some()).
///
/// The returned Vec has one entry for each HTLC, and in the same order. For HTLCs which were
/// considered dust and not included, a None entry exists, for all others a signature is
/// included.
#[must_use]
#[no_mangle]
pub extern "C" fn HolderCommitmentTransaction_get_htlc_sigs(this_arg: &HolderCommitmentTransaction, htlc_base_key: *const [u8; 32], mut counterparty_selected_contest_delay: u16) -> crate::c_types::derived::CResult_CVec_SignatureZNoneZ {
	let mut ret = unsafe { &*this_arg.inner }.get_htlc_sigs(&::bitcoin::secp256k1::key::SecretKey::from_slice(&unsafe { *htlc_base_key}[..]).unwrap(), counterparty_selected_contest_delay, &bitcoin::secp256k1::Secp256k1::new());
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { let mut local_ret_0 = Vec::new(); for item in o.drain(..) { local_ret_0.push( { let mut local_ret_0_0 = if item.is_none() { crate::c_types::Signature::null() } else {  { crate::c_types::Signature::from_rust(&(item.unwrap())) } }; local_ret_0_0 }); }; local_ret_0.into() }), Err(mut e) => crate::c_types::CResultTempl::err( { 0u8 /*e*/ }) };
	local_ret
}

#[no_mangle]
pub extern "C" fn HolderCommitmentTransaction_write(obj: *const HolderCommitmentTransaction) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &(*(*obj).inner) })
}
#[no_mangle]
pub extern "C" fn HolderCommitmentTransaction_read(ser: crate::c_types::u8slice) -> HolderCommitmentTransaction {
	if let Ok(res) = crate::c_types::deserialize_obj(ser) {
		HolderCommitmentTransaction { inner: Box::into_raw(Box::new(res)), is_owned: true }
	} else {
		HolderCommitmentTransaction { inner: std::ptr::null_mut(), is_owned: true }
	}
}
