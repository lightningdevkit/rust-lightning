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
/// CommitmentTransaction.trust().keys() because we trusted the source of the
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
	pub(crate) fn take_inner(mut self) -> *mut nativeTxCreationKeys {
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
pub extern "C" fn TxCreationKeys_write(obj: &TxCreationKeys) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &(*(*obj).inner) })
}
#[no_mangle]
pub(crate) extern "C" fn TxCreationKeys_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeTxCreationKeys) })
}
#[no_mangle]
pub extern "C" fn TxCreationKeys_read(ser: crate::c_types::u8slice) -> TxCreationKeys {
	if let Ok(res) = crate::c_types::deserialize_obj(ser) {
		TxCreationKeys { inner: Box::into_raw(Box::new(res)), is_owned: true }
	} else {
		TxCreationKeys { inner: std::ptr::null_mut(), is_owned: true }
	}
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
	pub(crate) fn take_inner(mut self) -> *mut nativeChannelPublicKeys {
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
pub extern "C" fn ChannelPublicKeys_write(obj: &ChannelPublicKeys) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &(*(*obj).inner) })
}
#[no_mangle]
pub(crate) extern "C" fn ChannelPublicKeys_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeChannelPublicKeys) })
}
#[no_mangle]
pub extern "C" fn ChannelPublicKeys_read(ser: crate::c_types::u8slice) -> ChannelPublicKeys {
	if let Ok(res) = crate::c_types::deserialize_obj(ser) {
		ChannelPublicKeys { inner: Box::into_raw(Box::new(res)), is_owned: true }
	} else {
		ChannelPublicKeys { inner: std::ptr::null_mut(), is_owned: true }
	}
}
/// Create per-state keys from channel base points and the per-commitment point.
/// Key set is asymmetric and can't be used as part of counter-signatory set of transactions.
#[must_use]
#[no_mangle]
pub extern "C" fn TxCreationKeys_derive_new(mut per_commitment_point: crate::c_types::PublicKey, mut broadcaster_delayed_payment_base: crate::c_types::PublicKey, mut broadcaster_htlc_base: crate::c_types::PublicKey, mut countersignatory_revocation_base: crate::c_types::PublicKey, mut countersignatory_htlc_base: crate::c_types::PublicKey) -> crate::c_types::derived::CResult_TxCreationKeysSecpErrorZ {
	let mut ret = lightning::ln::chan_utils::TxCreationKeys::derive_new(&bitcoin::secp256k1::Secp256k1::new(), &per_commitment_point.into_rust(), &broadcaster_delayed_payment_base.into_rust(), &broadcaster_htlc_base.into_rust(), &countersignatory_revocation_base.into_rust(), &countersignatory_htlc_base.into_rust());
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::ln::chan_utils::TxCreationKeys { inner: Box::into_raw(Box::new(o)), is_owned: true } }), Err(mut e) => crate::c_types::CResultTempl::err( { crate::c_types::Secp256k1Error::from_rust(e) }) };
	local_ret
}

/// Generate per-state keys from channel static keys.
/// Key set is asymmetric and can't be used as part of counter-signatory set of transactions.
#[must_use]
#[no_mangle]
pub extern "C" fn TxCreationKeys_from_channel_static_keys(mut per_commitment_point: crate::c_types::PublicKey, broadcaster_keys: &crate::ln::chan_utils::ChannelPublicKeys, countersignatory_keys: &crate::ln::chan_utils::ChannelPublicKeys) -> crate::c_types::derived::CResult_TxCreationKeysSecpErrorZ {
	let mut ret = lightning::ln::chan_utils::TxCreationKeys::from_channel_static_keys(&per_commitment_point.into_rust(), unsafe { &*broadcaster_keys.inner }, unsafe { &*countersignatory_keys.inner }, &bitcoin::secp256k1::Secp256k1::new());
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
	pub(crate) fn take_inner(mut self) -> *mut nativeHTLCOutputInCommitment {
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
pub extern "C" fn HTLCOutputInCommitment_write(obj: &HTLCOutputInCommitment) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &(*(*obj).inner) })
}
#[no_mangle]
pub(crate) extern "C" fn HTLCOutputInCommitment_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeHTLCOutputInCommitment) })
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


use lightning::ln::chan_utils::ChannelTransactionParameters as nativeChannelTransactionParametersImport;
type nativeChannelTransactionParameters = nativeChannelTransactionParametersImport;

/// Per-channel data used to build transactions in conjunction with the per-commitment data (CommitmentTransaction).
/// The fields are organized by holder/counterparty.
///
/// Normally, this is converted to the broadcaster/countersignatory-organized DirectedChannelTransactionParameters
/// before use, via the as_holder_broadcastable and as_counterparty_broadcastable functions.
#[must_use]
#[repr(C)]
pub struct ChannelTransactionParameters {
	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeChannelTransactionParameters,
	pub is_owned: bool,
}

impl Drop for ChannelTransactionParameters {
	fn drop(&mut self) {
		if self.is_owned && !self.inner.is_null() {
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
#[no_mangle]
pub extern "C" fn ChannelTransactionParameters_free(this_ptr: ChannelTransactionParameters) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn ChannelTransactionParameters_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeChannelTransactionParameters); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl ChannelTransactionParameters {
	pub(crate) fn take_inner(mut self) -> *mut nativeChannelTransactionParameters {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}
impl Clone for ChannelTransactionParameters {
	fn clone(&self) -> Self {
		Self {
			inner: Box::into_raw(Box::new(unsafe { &*self.inner }.clone())),
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ChannelTransactionParameters_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeChannelTransactionParameters)).clone() })) as *mut c_void
}
#[no_mangle]
pub extern "C" fn ChannelTransactionParameters_clone(orig: &ChannelTransactionParameters) -> ChannelTransactionParameters {
	ChannelTransactionParameters { inner: Box::into_raw(Box::new(unsafe { &*orig.inner }.clone())), is_owned: true }
}
/// Holder public keys
#[no_mangle]
pub extern "C" fn ChannelTransactionParameters_get_holder_pubkeys(this_ptr: &ChannelTransactionParameters) -> crate::ln::chan_utils::ChannelPublicKeys {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.holder_pubkeys;
	crate::ln::chan_utils::ChannelPublicKeys { inner: unsafe { ( (&((*inner_val)) as *const _) as *mut _) }, is_owned: false }
}
/// Holder public keys
#[no_mangle]
pub extern "C" fn ChannelTransactionParameters_set_holder_pubkeys(this_ptr: &mut ChannelTransactionParameters, mut val: crate::ln::chan_utils::ChannelPublicKeys) {
	unsafe { &mut *this_ptr.inner }.holder_pubkeys = *unsafe { Box::from_raw(val.take_inner()) };
}
/// The contest delay selected by the holder, which applies to counterparty-broadcast transactions
#[no_mangle]
pub extern "C" fn ChannelTransactionParameters_get_holder_selected_contest_delay(this_ptr: &ChannelTransactionParameters) -> u16 {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.holder_selected_contest_delay;
	(*inner_val)
}
/// The contest delay selected by the holder, which applies to counterparty-broadcast transactions
#[no_mangle]
pub extern "C" fn ChannelTransactionParameters_set_holder_selected_contest_delay(this_ptr: &mut ChannelTransactionParameters, mut val: u16) {
	unsafe { &mut *this_ptr.inner }.holder_selected_contest_delay = val;
}
/// Whether the holder is the initiator of this channel.
/// This is an input to the commitment number obscure factor computation.
#[no_mangle]
pub extern "C" fn ChannelTransactionParameters_get_is_outbound_from_holder(this_ptr: &ChannelTransactionParameters) -> bool {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.is_outbound_from_holder;
	(*inner_val)
}
/// Whether the holder is the initiator of this channel.
/// This is an input to the commitment number obscure factor computation.
#[no_mangle]
pub extern "C" fn ChannelTransactionParameters_set_is_outbound_from_holder(this_ptr: &mut ChannelTransactionParameters, mut val: bool) {
	unsafe { &mut *this_ptr.inner }.is_outbound_from_holder = val;
}
/// The late-bound counterparty channel transaction parameters.
/// These parameters are populated at the point in the protocol where the counterparty provides them.
#[no_mangle]
pub extern "C" fn ChannelTransactionParameters_get_counterparty_parameters(this_ptr: &ChannelTransactionParameters) -> crate::ln::chan_utils::CounterpartyChannelTransactionParameters {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.counterparty_parameters;
	let mut local_inner_val = crate::ln::chan_utils::CounterpartyChannelTransactionParameters { inner: unsafe { (if inner_val.is_none() { std::ptr::null() } else {  { (inner_val.as_ref().unwrap()) } } as *const _) as *mut _ }, is_owned: false };
	local_inner_val
}
/// The late-bound counterparty channel transaction parameters.
/// These parameters are populated at the point in the protocol where the counterparty provides them.
#[no_mangle]
pub extern "C" fn ChannelTransactionParameters_set_counterparty_parameters(this_ptr: &mut ChannelTransactionParameters, mut val: crate::ln::chan_utils::CounterpartyChannelTransactionParameters) {
	let mut local_val = if val.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(val.take_inner()) } }) };
	unsafe { &mut *this_ptr.inner }.counterparty_parameters = local_val;
}
/// The late-bound funding outpoint
#[no_mangle]
pub extern "C" fn ChannelTransactionParameters_get_funding_outpoint(this_ptr: &ChannelTransactionParameters) -> crate::chain::transaction::OutPoint {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.funding_outpoint;
	let mut local_inner_val = crate::chain::transaction::OutPoint { inner: unsafe { (if inner_val.is_none() { std::ptr::null() } else {  { (inner_val.as_ref().unwrap()) } } as *const _) as *mut _ }, is_owned: false };
	local_inner_val
}
/// The late-bound funding outpoint
#[no_mangle]
pub extern "C" fn ChannelTransactionParameters_set_funding_outpoint(this_ptr: &mut ChannelTransactionParameters, mut val: crate::chain::transaction::OutPoint) {
	let mut local_val = if val.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(val.take_inner()) } }) };
	unsafe { &mut *this_ptr.inner }.funding_outpoint = local_val;
}
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelTransactionParameters_new(mut holder_pubkeys_arg: crate::ln::chan_utils::ChannelPublicKeys, mut holder_selected_contest_delay_arg: u16, mut is_outbound_from_holder_arg: bool, mut counterparty_parameters_arg: crate::ln::chan_utils::CounterpartyChannelTransactionParameters, mut funding_outpoint_arg: crate::chain::transaction::OutPoint) -> ChannelTransactionParameters {
	let mut local_counterparty_parameters_arg = if counterparty_parameters_arg.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(counterparty_parameters_arg.take_inner()) } }) };
	let mut local_funding_outpoint_arg = if funding_outpoint_arg.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(funding_outpoint_arg.take_inner()) } }) };
	ChannelTransactionParameters { inner: Box::into_raw(Box::new(nativeChannelTransactionParameters {
		holder_pubkeys: *unsafe { Box::from_raw(holder_pubkeys_arg.take_inner()) },
		holder_selected_contest_delay: holder_selected_contest_delay_arg,
		is_outbound_from_holder: is_outbound_from_holder_arg,
		counterparty_parameters: local_counterparty_parameters_arg,
		funding_outpoint: local_funding_outpoint_arg,
	})), is_owned: true }
}

use lightning::ln::chan_utils::CounterpartyChannelTransactionParameters as nativeCounterpartyChannelTransactionParametersImport;
type nativeCounterpartyChannelTransactionParameters = nativeCounterpartyChannelTransactionParametersImport;

/// Late-bound per-channel counterparty data used to build transactions.
#[must_use]
#[repr(C)]
pub struct CounterpartyChannelTransactionParameters {
	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeCounterpartyChannelTransactionParameters,
	pub is_owned: bool,
}

impl Drop for CounterpartyChannelTransactionParameters {
	fn drop(&mut self) {
		if self.is_owned && !self.inner.is_null() {
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
#[no_mangle]
pub extern "C" fn CounterpartyChannelTransactionParameters_free(this_ptr: CounterpartyChannelTransactionParameters) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn CounterpartyChannelTransactionParameters_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeCounterpartyChannelTransactionParameters); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl CounterpartyChannelTransactionParameters {
	pub(crate) fn take_inner(mut self) -> *mut nativeCounterpartyChannelTransactionParameters {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}
impl Clone for CounterpartyChannelTransactionParameters {
	fn clone(&self) -> Self {
		Self {
			inner: Box::into_raw(Box::new(unsafe { &*self.inner }.clone())),
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn CounterpartyChannelTransactionParameters_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeCounterpartyChannelTransactionParameters)).clone() })) as *mut c_void
}
#[no_mangle]
pub extern "C" fn CounterpartyChannelTransactionParameters_clone(orig: &CounterpartyChannelTransactionParameters) -> CounterpartyChannelTransactionParameters {
	CounterpartyChannelTransactionParameters { inner: Box::into_raw(Box::new(unsafe { &*orig.inner }.clone())), is_owned: true }
}
/// Counter-party public keys
#[no_mangle]
pub extern "C" fn CounterpartyChannelTransactionParameters_get_pubkeys(this_ptr: &CounterpartyChannelTransactionParameters) -> crate::ln::chan_utils::ChannelPublicKeys {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.pubkeys;
	crate::ln::chan_utils::ChannelPublicKeys { inner: unsafe { ( (&((*inner_val)) as *const _) as *mut _) }, is_owned: false }
}
/// Counter-party public keys
#[no_mangle]
pub extern "C" fn CounterpartyChannelTransactionParameters_set_pubkeys(this_ptr: &mut CounterpartyChannelTransactionParameters, mut val: crate::ln::chan_utils::ChannelPublicKeys) {
	unsafe { &mut *this_ptr.inner }.pubkeys = *unsafe { Box::from_raw(val.take_inner()) };
}
/// The contest delay selected by the counterparty, which applies to holder-broadcast transactions
#[no_mangle]
pub extern "C" fn CounterpartyChannelTransactionParameters_get_selected_contest_delay(this_ptr: &CounterpartyChannelTransactionParameters) -> u16 {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.selected_contest_delay;
	(*inner_val)
}
/// The contest delay selected by the counterparty, which applies to holder-broadcast transactions
#[no_mangle]
pub extern "C" fn CounterpartyChannelTransactionParameters_set_selected_contest_delay(this_ptr: &mut CounterpartyChannelTransactionParameters, mut val: u16) {
	unsafe { &mut *this_ptr.inner }.selected_contest_delay = val;
}
#[must_use]
#[no_mangle]
pub extern "C" fn CounterpartyChannelTransactionParameters_new(mut pubkeys_arg: crate::ln::chan_utils::ChannelPublicKeys, mut selected_contest_delay_arg: u16) -> CounterpartyChannelTransactionParameters {
	CounterpartyChannelTransactionParameters { inner: Box::into_raw(Box::new(nativeCounterpartyChannelTransactionParameters {
		pubkeys: *unsafe { Box::from_raw(pubkeys_arg.take_inner()) },
		selected_contest_delay: selected_contest_delay_arg,
	})), is_owned: true }
}
/// Whether the late bound parameters are populated.
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelTransactionParameters_is_populated(this_arg: &ChannelTransactionParameters) -> bool {
	let mut ret = unsafe { &*this_arg.inner }.is_populated();
	ret
}

/// Convert the holder/counterparty parameters to broadcaster/countersignatory-organized parameters,
/// given that the holder is the broadcaster.
///
/// self.is_populated() must be true before calling this function.
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelTransactionParameters_as_holder_broadcastable(this_arg: &ChannelTransactionParameters) -> crate::ln::chan_utils::DirectedChannelTransactionParameters {
	let mut ret = unsafe { &*this_arg.inner }.as_holder_broadcastable();
	crate::ln::chan_utils::DirectedChannelTransactionParameters { inner: Box::into_raw(Box::new(ret)), is_owned: true }
}

/// Convert the holder/counterparty parameters to broadcaster/countersignatory-organized parameters,
/// given that the counterparty is the broadcaster.
///
/// self.is_populated() must be true before calling this function.
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelTransactionParameters_as_counterparty_broadcastable(this_arg: &ChannelTransactionParameters) -> crate::ln::chan_utils::DirectedChannelTransactionParameters {
	let mut ret = unsafe { &*this_arg.inner }.as_counterparty_broadcastable();
	crate::ln::chan_utils::DirectedChannelTransactionParameters { inner: Box::into_raw(Box::new(ret)), is_owned: true }
}

#[no_mangle]
pub extern "C" fn CounterpartyChannelTransactionParameters_write(obj: &CounterpartyChannelTransactionParameters) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &(*(*obj).inner) })
}
#[no_mangle]
pub(crate) extern "C" fn CounterpartyChannelTransactionParameters_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeCounterpartyChannelTransactionParameters) })
}
#[no_mangle]
pub extern "C" fn CounterpartyChannelTransactionParameters_read(ser: crate::c_types::u8slice) -> CounterpartyChannelTransactionParameters {
	if let Ok(res) = crate::c_types::deserialize_obj(ser) {
		CounterpartyChannelTransactionParameters { inner: Box::into_raw(Box::new(res)), is_owned: true }
	} else {
		CounterpartyChannelTransactionParameters { inner: std::ptr::null_mut(), is_owned: true }
	}
}
#[no_mangle]
pub extern "C" fn ChannelTransactionParameters_write(obj: &ChannelTransactionParameters) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &(*(*obj).inner) })
}
#[no_mangle]
pub(crate) extern "C" fn ChannelTransactionParameters_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeChannelTransactionParameters) })
}
#[no_mangle]
pub extern "C" fn ChannelTransactionParameters_read(ser: crate::c_types::u8slice) -> ChannelTransactionParameters {
	if let Ok(res) = crate::c_types::deserialize_obj(ser) {
		ChannelTransactionParameters { inner: Box::into_raw(Box::new(res)), is_owned: true }
	} else {
		ChannelTransactionParameters { inner: std::ptr::null_mut(), is_owned: true }
	}
}

use lightning::ln::chan_utils::DirectedChannelTransactionParameters as nativeDirectedChannelTransactionParametersImport;
type nativeDirectedChannelTransactionParameters = nativeDirectedChannelTransactionParametersImport<'static>;

/// Static channel fields used to build transactions given per-commitment fields, organized by
/// broadcaster/countersignatory.
///
/// This is derived from the holder/counterparty-organized ChannelTransactionParameters via the
/// as_holder_broadcastable and as_counterparty_broadcastable functions.
#[must_use]
#[repr(C)]
pub struct DirectedChannelTransactionParameters {
	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeDirectedChannelTransactionParameters,
	pub is_owned: bool,
}

impl Drop for DirectedChannelTransactionParameters {
	fn drop(&mut self) {
		if self.is_owned && !self.inner.is_null() {
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
#[no_mangle]
pub extern "C" fn DirectedChannelTransactionParameters_free(this_ptr: DirectedChannelTransactionParameters) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn DirectedChannelTransactionParameters_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeDirectedChannelTransactionParameters); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl DirectedChannelTransactionParameters {
	pub(crate) fn take_inner(mut self) -> *mut nativeDirectedChannelTransactionParameters {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}
/// Get the channel pubkeys for the broadcaster
#[must_use]
#[no_mangle]
pub extern "C" fn DirectedChannelTransactionParameters_broadcaster_pubkeys(this_arg: &DirectedChannelTransactionParameters) -> crate::ln::chan_utils::ChannelPublicKeys {
	let mut ret = unsafe { &*this_arg.inner }.broadcaster_pubkeys();
	crate::ln::chan_utils::ChannelPublicKeys { inner: unsafe { ( (&(*ret) as *const _) as *mut _) }, is_owned: false }
}

/// Get the channel pubkeys for the countersignatory
#[must_use]
#[no_mangle]
pub extern "C" fn DirectedChannelTransactionParameters_countersignatory_pubkeys(this_arg: &DirectedChannelTransactionParameters) -> crate::ln::chan_utils::ChannelPublicKeys {
	let mut ret = unsafe { &*this_arg.inner }.countersignatory_pubkeys();
	crate::ln::chan_utils::ChannelPublicKeys { inner: unsafe { ( (&(*ret) as *const _) as *mut _) }, is_owned: false }
}

/// Get the contest delay applicable to the transactions.
/// Note that the contest delay was selected by the countersignatory.
#[must_use]
#[no_mangle]
pub extern "C" fn DirectedChannelTransactionParameters_contest_delay(this_arg: &DirectedChannelTransactionParameters) -> u16 {
	let mut ret = unsafe { &*this_arg.inner }.contest_delay();
	ret
}

/// Whether the channel is outbound from the broadcaster.
///
/// The boolean representing the side that initiated the channel is
/// an input to the commitment number obscure factor computation.
#[must_use]
#[no_mangle]
pub extern "C" fn DirectedChannelTransactionParameters_is_outbound(this_arg: &DirectedChannelTransactionParameters) -> bool {
	let mut ret = unsafe { &*this_arg.inner }.is_outbound();
	ret
}

/// The funding outpoint
#[must_use]
#[no_mangle]
pub extern "C" fn DirectedChannelTransactionParameters_funding_outpoint(this_arg: &DirectedChannelTransactionParameters) -> crate::chain::transaction::OutPoint {
	let mut ret = unsafe { &*this_arg.inner }.funding_outpoint();
	crate::c_types::bitcoin_to_C_outpoint(ret)
}


use lightning::ln::chan_utils::HolderCommitmentTransaction as nativeHolderCommitmentTransactionImport;
type nativeHolderCommitmentTransaction = nativeHolderCommitmentTransactionImport;

/// Information needed to build and sign a holder's commitment transaction.
///
/// The transaction is only signed once we are ready to broadcast.
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
	pub(crate) fn take_inner(mut self) -> *mut nativeHolderCommitmentTransaction {
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
/// Our counterparty's signature for the transaction
#[no_mangle]
pub extern "C" fn HolderCommitmentTransaction_get_counterparty_sig(this_ptr: &HolderCommitmentTransaction) -> crate::c_types::Signature {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.counterparty_sig;
	crate::c_types::Signature::from_rust(&(*inner_val))
}
/// Our counterparty's signature for the transaction
#[no_mangle]
pub extern "C" fn HolderCommitmentTransaction_set_counterparty_sig(this_ptr: &mut HolderCommitmentTransaction, mut val: crate::c_types::Signature) {
	unsafe { &mut *this_ptr.inner }.counterparty_sig = val.into_rust();
}
/// All non-dust counterparty HTLC signatures, in the order they appear in the transaction
#[no_mangle]
pub extern "C" fn HolderCommitmentTransaction_set_counterparty_htlc_sigs(this_ptr: &mut HolderCommitmentTransaction, mut val: crate::c_types::derived::CVec_SignatureZ) {
	let mut local_val = Vec::new(); for mut item in val.into_rust().drain(..) { local_val.push( { item.into_rust() }); };
	unsafe { &mut *this_ptr.inner }.counterparty_htlc_sigs = local_val;
}
#[no_mangle]
pub extern "C" fn HolderCommitmentTransaction_write(obj: &HolderCommitmentTransaction) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &(*(*obj).inner) })
}
#[no_mangle]
pub(crate) extern "C" fn HolderCommitmentTransaction_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeHolderCommitmentTransaction) })
}
#[no_mangle]
pub extern "C" fn HolderCommitmentTransaction_read(ser: crate::c_types::u8slice) -> HolderCommitmentTransaction {
	if let Ok(res) = crate::c_types::deserialize_obj(ser) {
		HolderCommitmentTransaction { inner: Box::into_raw(Box::new(res)), is_owned: true }
	} else {
		HolderCommitmentTransaction { inner: std::ptr::null_mut(), is_owned: true }
	}
}
/// Create a new holder transaction with the given counterparty signatures.
/// The funding keys are used to figure out which signature should go first when building the transaction for broadcast.
#[must_use]
#[no_mangle]
pub extern "C" fn HolderCommitmentTransaction_new(mut commitment_tx: crate::ln::chan_utils::CommitmentTransaction, mut counterparty_sig: crate::c_types::Signature, mut counterparty_htlc_sigs: crate::c_types::derived::CVec_SignatureZ, mut holder_funding_key: crate::c_types::PublicKey, mut counterparty_funding_key: crate::c_types::PublicKey) -> HolderCommitmentTransaction {
	let mut local_counterparty_htlc_sigs = Vec::new(); for mut item in counterparty_htlc_sigs.into_rust().drain(..) { local_counterparty_htlc_sigs.push( { item.into_rust() }); };
	let mut ret = lightning::ln::chan_utils::HolderCommitmentTransaction::new(*unsafe { Box::from_raw(commitment_tx.take_inner()) }, counterparty_sig.into_rust(), local_counterparty_htlc_sigs, &holder_funding_key.into_rust(), &counterparty_funding_key.into_rust());
	HolderCommitmentTransaction { inner: Box::into_raw(Box::new(ret)), is_owned: true }
}


use lightning::ln::chan_utils::BuiltCommitmentTransaction as nativeBuiltCommitmentTransactionImport;
type nativeBuiltCommitmentTransaction = nativeBuiltCommitmentTransactionImport;

/// A pre-built Bitcoin commitment transaction and its txid.
#[must_use]
#[repr(C)]
pub struct BuiltCommitmentTransaction {
	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeBuiltCommitmentTransaction,
	pub is_owned: bool,
}

impl Drop for BuiltCommitmentTransaction {
	fn drop(&mut self) {
		if self.is_owned && !self.inner.is_null() {
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
#[no_mangle]
pub extern "C" fn BuiltCommitmentTransaction_free(this_ptr: BuiltCommitmentTransaction) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn BuiltCommitmentTransaction_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeBuiltCommitmentTransaction); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl BuiltCommitmentTransaction {
	pub(crate) fn take_inner(mut self) -> *mut nativeBuiltCommitmentTransaction {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}
impl Clone for BuiltCommitmentTransaction {
	fn clone(&self) -> Self {
		Self {
			inner: Box::into_raw(Box::new(unsafe { &*self.inner }.clone())),
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn BuiltCommitmentTransaction_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeBuiltCommitmentTransaction)).clone() })) as *mut c_void
}
#[no_mangle]
pub extern "C" fn BuiltCommitmentTransaction_clone(orig: &BuiltCommitmentTransaction) -> BuiltCommitmentTransaction {
	BuiltCommitmentTransaction { inner: Box::into_raw(Box::new(unsafe { &*orig.inner }.clone())), is_owned: true }
}
/// The commitment transaction
#[no_mangle]
pub extern "C" fn BuiltCommitmentTransaction_get_transaction(this_ptr: &BuiltCommitmentTransaction) -> crate::c_types::Transaction {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.transaction;
	let mut local_inner_val = ::bitcoin::consensus::encode::serialize(inner_val);
	crate::c_types::Transaction::from_vec(local_inner_val)
}
/// The commitment transaction
#[no_mangle]
pub extern "C" fn BuiltCommitmentTransaction_set_transaction(this_ptr: &mut BuiltCommitmentTransaction, mut val: crate::c_types::Transaction) {
	unsafe { &mut *this_ptr.inner }.transaction = val.into_bitcoin();
}
/// The txid for the commitment transaction.
///
/// This is provided as a performance optimization, instead of calling transaction.txid()
/// multiple times.
#[no_mangle]
pub extern "C" fn BuiltCommitmentTransaction_get_txid(this_ptr: &BuiltCommitmentTransaction) -> *const [u8; 32] {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.txid;
	(*inner_val).as_inner()
}
/// The txid for the commitment transaction.
///
/// This is provided as a performance optimization, instead of calling transaction.txid()
/// multiple times.
#[no_mangle]
pub extern "C" fn BuiltCommitmentTransaction_set_txid(this_ptr: &mut BuiltCommitmentTransaction, mut val: crate::c_types::ThirtyTwoBytes) {
	unsafe { &mut *this_ptr.inner }.txid = ::bitcoin::hash_types::Txid::from_slice(&val.data[..]).unwrap();
}
#[must_use]
#[no_mangle]
pub extern "C" fn BuiltCommitmentTransaction_new(mut transaction_arg: crate::c_types::Transaction, mut txid_arg: crate::c_types::ThirtyTwoBytes) -> BuiltCommitmentTransaction {
	BuiltCommitmentTransaction { inner: Box::into_raw(Box::new(nativeBuiltCommitmentTransaction {
		transaction: transaction_arg.into_bitcoin(),
		txid: ::bitcoin::hash_types::Txid::from_slice(&txid_arg.data[..]).unwrap(),
	})), is_owned: true }
}
#[no_mangle]
pub extern "C" fn BuiltCommitmentTransaction_write(obj: &BuiltCommitmentTransaction) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &(*(*obj).inner) })
}
#[no_mangle]
pub(crate) extern "C" fn BuiltCommitmentTransaction_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeBuiltCommitmentTransaction) })
}
#[no_mangle]
pub extern "C" fn BuiltCommitmentTransaction_read(ser: crate::c_types::u8slice) -> BuiltCommitmentTransaction {
	if let Ok(res) = crate::c_types::deserialize_obj(ser) {
		BuiltCommitmentTransaction { inner: Box::into_raw(Box::new(res)), is_owned: true }
	} else {
		BuiltCommitmentTransaction { inner: std::ptr::null_mut(), is_owned: true }
	}
}
/// Get the SIGHASH_ALL sighash value of the transaction.
///
/// This can be used to verify a signature.
#[must_use]
#[no_mangle]
pub extern "C" fn BuiltCommitmentTransaction_get_sighash_all(this_arg: &BuiltCommitmentTransaction, mut funding_redeemscript: crate::c_types::u8slice, mut channel_value_satoshis: u64) -> crate::c_types::ThirtyTwoBytes {
	let mut ret = unsafe { &*this_arg.inner }.get_sighash_all(&::bitcoin::blockdata::script::Script::from(Vec::from(funding_redeemscript.to_slice())), channel_value_satoshis);
	crate::c_types::ThirtyTwoBytes { data: ret.as_ref().clone() }
}

/// Sign a transaction, either because we are counter-signing the counterparty's transaction or
/// because we are about to broadcast a holder transaction.
#[must_use]
#[no_mangle]
pub extern "C" fn BuiltCommitmentTransaction_sign(this_arg: &BuiltCommitmentTransaction, funding_key: *const [u8; 32], mut funding_redeemscript: crate::c_types::u8slice, mut channel_value_satoshis: u64) -> crate::c_types::Signature {
	let mut ret = unsafe { &*this_arg.inner }.sign(&::bitcoin::secp256k1::key::SecretKey::from_slice(&unsafe { *funding_key}[..]).unwrap(), &::bitcoin::blockdata::script::Script::from(Vec::from(funding_redeemscript.to_slice())), channel_value_satoshis, &bitcoin::secp256k1::Secp256k1::new());
	crate::c_types::Signature::from_rust(&ret)
}


use lightning::ln::chan_utils::CommitmentTransaction as nativeCommitmentTransactionImport;
type nativeCommitmentTransaction = nativeCommitmentTransactionImport;

/// This class tracks the per-transaction information needed to build a commitment transaction and to
/// actually build it and sign.  It is used for holder transactions that we sign only when needed
/// and for transactions we sign for the counterparty.
///
/// This class can be used inside a signer implementation to generate a signature given the relevant
/// secret key.
#[must_use]
#[repr(C)]
pub struct CommitmentTransaction {
	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeCommitmentTransaction,
	pub is_owned: bool,
}

impl Drop for CommitmentTransaction {
	fn drop(&mut self) {
		if self.is_owned && !self.inner.is_null() {
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
#[no_mangle]
pub extern "C" fn CommitmentTransaction_free(this_ptr: CommitmentTransaction) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn CommitmentTransaction_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeCommitmentTransaction); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl CommitmentTransaction {
	pub(crate) fn take_inner(mut self) -> *mut nativeCommitmentTransaction {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}
impl Clone for CommitmentTransaction {
	fn clone(&self) -> Self {
		Self {
			inner: Box::into_raw(Box::new(unsafe { &*self.inner }.clone())),
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn CommitmentTransaction_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeCommitmentTransaction)).clone() })) as *mut c_void
}
#[no_mangle]
pub extern "C" fn CommitmentTransaction_clone(orig: &CommitmentTransaction) -> CommitmentTransaction {
	CommitmentTransaction { inner: Box::into_raw(Box::new(unsafe { &*orig.inner }.clone())), is_owned: true }
}
#[no_mangle]
pub extern "C" fn CommitmentTransaction_write(obj: &CommitmentTransaction) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &(*(*obj).inner) })
}
#[no_mangle]
pub(crate) extern "C" fn CommitmentTransaction_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeCommitmentTransaction) })
}
#[no_mangle]
pub extern "C" fn CommitmentTransaction_read(ser: crate::c_types::u8slice) -> CommitmentTransaction {
	if let Ok(res) = crate::c_types::deserialize_obj(ser) {
		CommitmentTransaction { inner: Box::into_raw(Box::new(res)), is_owned: true }
	} else {
		CommitmentTransaction { inner: std::ptr::null_mut(), is_owned: true }
	}
}
/// The backwards-counting commitment number
#[must_use]
#[no_mangle]
pub extern "C" fn CommitmentTransaction_commitment_number(this_arg: &CommitmentTransaction) -> u64 {
	let mut ret = unsafe { &*this_arg.inner }.commitment_number();
	ret
}

/// The value to be sent to the broadcaster
#[must_use]
#[no_mangle]
pub extern "C" fn CommitmentTransaction_to_broadcaster_value_sat(this_arg: &CommitmentTransaction) -> u64 {
	let mut ret = unsafe { &*this_arg.inner }.to_broadcaster_value_sat();
	ret
}

/// The value to be sent to the counterparty
#[must_use]
#[no_mangle]
pub extern "C" fn CommitmentTransaction_to_countersignatory_value_sat(this_arg: &CommitmentTransaction) -> u64 {
	let mut ret = unsafe { &*this_arg.inner }.to_countersignatory_value_sat();
	ret
}

/// The feerate paid per 1000-weight-unit in this commitment transaction.
#[must_use]
#[no_mangle]
pub extern "C" fn CommitmentTransaction_feerate_per_kw(this_arg: &CommitmentTransaction) -> u32 {
	let mut ret = unsafe { &*this_arg.inner }.feerate_per_kw();
	ret
}

/// Trust our pre-built transaction and derived transaction creation public keys.
///
/// Applies a wrapper which allows access to these fields.
///
/// This should only be used if you fully trust the builder of this object.  It should not
///\tbe used by an external signer - instead use the verify function.
#[must_use]
#[no_mangle]
pub extern "C" fn CommitmentTransaction_trust(this_arg: &CommitmentTransaction) -> crate::ln::chan_utils::TrustedCommitmentTransaction {
	let mut ret = unsafe { &*this_arg.inner }.trust();
	crate::ln::chan_utils::TrustedCommitmentTransaction { inner: Box::into_raw(Box::new(ret)), is_owned: true }
}

/// Verify our pre-built transaction and derived transaction creation public keys.
///
/// Applies a wrapper which allows access to these fields.
///
/// An external validating signer must call this method before signing
/// or using the built transaction.
#[must_use]
#[no_mangle]
pub extern "C" fn CommitmentTransaction_verify(this_arg: &CommitmentTransaction, channel_parameters: &crate::ln::chan_utils::DirectedChannelTransactionParameters, broadcaster_keys: &crate::ln::chan_utils::ChannelPublicKeys, countersignatory_keys: &crate::ln::chan_utils::ChannelPublicKeys) -> crate::c_types::derived::CResult_TrustedCommitmentTransactionNoneZ {
	let mut ret = unsafe { &*this_arg.inner }.verify(unsafe { &*channel_parameters.inner }, unsafe { &*broadcaster_keys.inner }, unsafe { &*countersignatory_keys.inner }, &bitcoin::secp256k1::Secp256k1::new());
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::ln::chan_utils::TrustedCommitmentTransaction { inner: Box::into_raw(Box::new(o)), is_owned: true } }), Err(mut e) => crate::c_types::CResultTempl::err( { 0u8 /*e*/ }) };
	local_ret
}


use lightning::ln::chan_utils::TrustedCommitmentTransaction as nativeTrustedCommitmentTransactionImport;
type nativeTrustedCommitmentTransaction = nativeTrustedCommitmentTransactionImport<'static>;

/// A wrapper on CommitmentTransaction indicating that the derived fields (the built bitcoin
/// transaction and the transaction creation keys) are trusted.
///
/// See trust() and verify() functions on CommitmentTransaction.
///
/// This structure implements Deref.
#[must_use]
#[repr(C)]
pub struct TrustedCommitmentTransaction {
	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeTrustedCommitmentTransaction,
	pub is_owned: bool,
}

impl Drop for TrustedCommitmentTransaction {
	fn drop(&mut self) {
		if self.is_owned && !self.inner.is_null() {
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
#[no_mangle]
pub extern "C" fn TrustedCommitmentTransaction_free(this_ptr: TrustedCommitmentTransaction) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn TrustedCommitmentTransaction_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeTrustedCommitmentTransaction); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl TrustedCommitmentTransaction {
	pub(crate) fn take_inner(mut self) -> *mut nativeTrustedCommitmentTransaction {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}
/// The transaction ID of the built Bitcoin transaction
#[must_use]
#[no_mangle]
pub extern "C" fn TrustedCommitmentTransaction_txid(this_arg: &TrustedCommitmentTransaction) -> crate::c_types::ThirtyTwoBytes {
	let mut ret = unsafe { &*this_arg.inner }.txid();
	crate::c_types::ThirtyTwoBytes { data: ret.into_inner() }
}

/// The pre-built Bitcoin commitment transaction
#[must_use]
#[no_mangle]
pub extern "C" fn TrustedCommitmentTransaction_built_transaction(this_arg: &TrustedCommitmentTransaction) -> crate::ln::chan_utils::BuiltCommitmentTransaction {
	let mut ret = unsafe { &*this_arg.inner }.built_transaction();
	crate::ln::chan_utils::BuiltCommitmentTransaction { inner: unsafe { ( (&(*ret) as *const _) as *mut _) }, is_owned: false }
}

/// The pre-calculated transaction creation public keys.
#[must_use]
#[no_mangle]
pub extern "C" fn TrustedCommitmentTransaction_keys(this_arg: &TrustedCommitmentTransaction) -> crate::ln::chan_utils::TxCreationKeys {
	let mut ret = unsafe { &*this_arg.inner }.keys();
	crate::ln::chan_utils::TxCreationKeys { inner: unsafe { ( (&(*ret) as *const _) as *mut _) }, is_owned: false }
}

/// Get a signature for each HTLC which was included in the commitment transaction (ie for
/// which HTLCOutputInCommitment::transaction_output_index.is_some()).
///
/// The returned Vec has one entry for each HTLC, and in the same order.
#[must_use]
#[no_mangle]
pub extern "C" fn TrustedCommitmentTransaction_get_htlc_sigs(this_arg: &TrustedCommitmentTransaction, htlc_base_key: *const [u8; 32], channel_parameters: &crate::ln::chan_utils::DirectedChannelTransactionParameters) -> crate::c_types::derived::CResult_CVec_SignatureZNoneZ {
	let mut ret = unsafe { &*this_arg.inner }.get_htlc_sigs(&::bitcoin::secp256k1::key::SecretKey::from_slice(&unsafe { *htlc_base_key}[..]).unwrap(), unsafe { &*channel_parameters.inner }, &bitcoin::secp256k1::Secp256k1::new());
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { let mut local_ret_0 = Vec::new(); for item in o.drain(..) { local_ret_0.push( { crate::c_types::Signature::from_rust(&item) }); }; local_ret_0.into() }), Err(mut e) => crate::c_types::CResultTempl::err( { 0u8 /*e*/ }) };
	local_ret
}

/// Get the transaction number obscure factor
#[no_mangle]
pub extern "C" fn get_commitment_transaction_number_obscure_factor(mut broadcaster_payment_basepoint: crate::c_types::PublicKey, mut countersignatory_payment_basepoint: crate::c_types::PublicKey, mut outbound_from_broadcaster: bool) -> u64 {
	let mut ret = lightning::ln::chan_utils::get_commitment_transaction_number_obscure_factor(&broadcaster_payment_basepoint.into_rust(), &countersignatory_payment_basepoint.into_rust(), outbound_from_broadcaster);
	ret
}

