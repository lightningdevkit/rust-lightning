//! Various user-configurable channel limits and settings which ChannelManager
//! applies for you.

use std::ffi::c_void;
use bitcoin::hashes::Hash;
use crate::c_types::*;


use lightning::util::config::ChannelHandshakeConfig as nativeChannelHandshakeConfigImport;
type nativeChannelHandshakeConfig = nativeChannelHandshakeConfigImport;

/// Configuration we set when applicable.
///
/// Default::default() provides sane defaults.
#[must_use]
#[repr(C)]
pub struct ChannelHandshakeConfig {
	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeChannelHandshakeConfig,
	pub is_owned: bool,
}

impl Drop for ChannelHandshakeConfig {
	fn drop(&mut self) {
		if self.is_owned && !self.inner.is_null() {
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
#[no_mangle]
pub extern "C" fn ChannelHandshakeConfig_free(this_ptr: ChannelHandshakeConfig) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn ChannelHandshakeConfig_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeChannelHandshakeConfig); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl ChannelHandshakeConfig {
	pub(crate) fn take_inner(mut self) -> *mut nativeChannelHandshakeConfig {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}
impl Clone for ChannelHandshakeConfig {
	fn clone(&self) -> Self {
		Self {
			inner: Box::into_raw(Box::new(unsafe { &*self.inner }.clone())),
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ChannelHandshakeConfig_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeChannelHandshakeConfig)).clone() })) as *mut c_void
}
#[no_mangle]
pub extern "C" fn ChannelHandshakeConfig_clone(orig: &ChannelHandshakeConfig) -> ChannelHandshakeConfig {
	ChannelHandshakeConfig { inner: Box::into_raw(Box::new(unsafe { &*orig.inner }.clone())), is_owned: true }
}
/// Confirmations we will wait for before considering the channel locked in.
/// Applied only for inbound channels (see ChannelHandshakeLimits::max_minimum_depth for the
/// equivalent limit applied to outbound channels).
///
/// Default value: 6.
#[no_mangle]
pub extern "C" fn ChannelHandshakeConfig_get_minimum_depth(this_ptr: &ChannelHandshakeConfig) -> u32 {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.minimum_depth;
	(*inner_val)
}
/// Confirmations we will wait for before considering the channel locked in.
/// Applied only for inbound channels (see ChannelHandshakeLimits::max_minimum_depth for the
/// equivalent limit applied to outbound channels).
///
/// Default value: 6.
#[no_mangle]
pub extern "C" fn ChannelHandshakeConfig_set_minimum_depth(this_ptr: &mut ChannelHandshakeConfig, mut val: u32) {
	unsafe { &mut *this_ptr.inner }.minimum_depth = val;
}
/// Set to the amount of time we require our counterparty to wait to claim their money.
///
/// It's one of the main parameter of our security model. We (or one of our watchtowers) MUST
/// be online to check for peer having broadcast a revoked transaction to steal our funds
/// at least once every our_to_self_delay blocks.
///
/// Meanwhile, asking for a too high delay, we bother peer to freeze funds for nothing in
/// case of an honest unilateral channel close, which implicitly decrease the economic value of
/// our channel.
///
/// Default value: BREAKDOWN_TIMEOUT (currently 144), we enforce it as a minimum at channel
/// opening so you can tweak config to ask for more security, not less.
#[no_mangle]
pub extern "C" fn ChannelHandshakeConfig_get_our_to_self_delay(this_ptr: &ChannelHandshakeConfig) -> u16 {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.our_to_self_delay;
	(*inner_val)
}
/// Set to the amount of time we require our counterparty to wait to claim their money.
///
/// It's one of the main parameter of our security model. We (or one of our watchtowers) MUST
/// be online to check for peer having broadcast a revoked transaction to steal our funds
/// at least once every our_to_self_delay blocks.
///
/// Meanwhile, asking for a too high delay, we bother peer to freeze funds for nothing in
/// case of an honest unilateral channel close, which implicitly decrease the economic value of
/// our channel.
///
/// Default value: BREAKDOWN_TIMEOUT (currently 144), we enforce it as a minimum at channel
/// opening so you can tweak config to ask for more security, not less.
#[no_mangle]
pub extern "C" fn ChannelHandshakeConfig_set_our_to_self_delay(this_ptr: &mut ChannelHandshakeConfig, mut val: u16) {
	unsafe { &mut *this_ptr.inner }.our_to_self_delay = val;
}
/// Set to the smallest value HTLC we will accept to process.
///
/// This value is sent to our counterparty on channel-open and we close the channel any time
/// our counterparty misbehaves by sending us an HTLC with a value smaller than this.
///
/// Default value: 1. If the value is less than 1, it is ignored and set to 1, as is required
/// by the protocol.
#[no_mangle]
pub extern "C" fn ChannelHandshakeConfig_get_our_htlc_minimum_msat(this_ptr: &ChannelHandshakeConfig) -> u64 {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.our_htlc_minimum_msat;
	(*inner_val)
}
/// Set to the smallest value HTLC we will accept to process.
///
/// This value is sent to our counterparty on channel-open and we close the channel any time
/// our counterparty misbehaves by sending us an HTLC with a value smaller than this.
///
/// Default value: 1. If the value is less than 1, it is ignored and set to 1, as is required
/// by the protocol.
#[no_mangle]
pub extern "C" fn ChannelHandshakeConfig_set_our_htlc_minimum_msat(this_ptr: &mut ChannelHandshakeConfig, mut val: u64) {
	unsafe { &mut *this_ptr.inner }.our_htlc_minimum_msat = val;
}
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelHandshakeConfig_new(mut minimum_depth_arg: u32, mut our_to_self_delay_arg: u16, mut our_htlc_minimum_msat_arg: u64) -> ChannelHandshakeConfig {
	ChannelHandshakeConfig { inner: Box::into_raw(Box::new(nativeChannelHandshakeConfig {
		minimum_depth: minimum_depth_arg,
		our_to_self_delay: our_to_self_delay_arg,
		our_htlc_minimum_msat: our_htlc_minimum_msat_arg,
	})), is_owned: true }
}
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelHandshakeConfig_default() -> ChannelHandshakeConfig {
	ChannelHandshakeConfig { inner: Box::into_raw(Box::new(Default::default())), is_owned: true }
}

use lightning::util::config::ChannelHandshakeLimits as nativeChannelHandshakeLimitsImport;
type nativeChannelHandshakeLimits = nativeChannelHandshakeLimitsImport;

/// Optional channel limits which are applied during channel creation.
///
/// These limits are only applied to our counterparty's limits, not our own.
///
/// Use 0/<type>::max_value() as appropriate to skip checking.
///
/// Provides sane defaults for most configurations.
///
/// Most additional limits are disabled except those with which specify a default in individual
/// field documentation. Note that this may result in barely-usable channels, but since they
/// are applied mostly only to incoming channels that's not much of a problem.
#[must_use]
#[repr(C)]
pub struct ChannelHandshakeLimits {
	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeChannelHandshakeLimits,
	pub is_owned: bool,
}

impl Drop for ChannelHandshakeLimits {
	fn drop(&mut self) {
		if self.is_owned && !self.inner.is_null() {
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
#[no_mangle]
pub extern "C" fn ChannelHandshakeLimits_free(this_ptr: ChannelHandshakeLimits) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn ChannelHandshakeLimits_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeChannelHandshakeLimits); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl ChannelHandshakeLimits {
	pub(crate) fn take_inner(mut self) -> *mut nativeChannelHandshakeLimits {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}
impl Clone for ChannelHandshakeLimits {
	fn clone(&self) -> Self {
		Self {
			inner: Box::into_raw(Box::new(unsafe { &*self.inner }.clone())),
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ChannelHandshakeLimits_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeChannelHandshakeLimits)).clone() })) as *mut c_void
}
#[no_mangle]
pub extern "C" fn ChannelHandshakeLimits_clone(orig: &ChannelHandshakeLimits) -> ChannelHandshakeLimits {
	ChannelHandshakeLimits { inner: Box::into_raw(Box::new(unsafe { &*orig.inner }.clone())), is_owned: true }
}
/// Minimum allowed satoshis when a channel is funded, this is supplied by the sender and so
/// only applies to inbound channels.
///
/// Default value: 0.
#[no_mangle]
pub extern "C" fn ChannelHandshakeLimits_get_min_funding_satoshis(this_ptr: &ChannelHandshakeLimits) -> u64 {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.min_funding_satoshis;
	(*inner_val)
}
/// Minimum allowed satoshis when a channel is funded, this is supplied by the sender and so
/// only applies to inbound channels.
///
/// Default value: 0.
#[no_mangle]
pub extern "C" fn ChannelHandshakeLimits_set_min_funding_satoshis(this_ptr: &mut ChannelHandshakeLimits, mut val: u64) {
	unsafe { &mut *this_ptr.inner }.min_funding_satoshis = val;
}
/// The remote node sets a limit on the minimum size of HTLCs we can send to them. This allows
/// you to limit the maximum minimum-size they can require.
///
/// Default value: u64::max_value.
#[no_mangle]
pub extern "C" fn ChannelHandshakeLimits_get_max_htlc_minimum_msat(this_ptr: &ChannelHandshakeLimits) -> u64 {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.max_htlc_minimum_msat;
	(*inner_val)
}
/// The remote node sets a limit on the minimum size of HTLCs we can send to them. This allows
/// you to limit the maximum minimum-size they can require.
///
/// Default value: u64::max_value.
#[no_mangle]
pub extern "C" fn ChannelHandshakeLimits_set_max_htlc_minimum_msat(this_ptr: &mut ChannelHandshakeLimits, mut val: u64) {
	unsafe { &mut *this_ptr.inner }.max_htlc_minimum_msat = val;
}
/// The remote node sets a limit on the maximum value of pending HTLCs to them at any given
/// time to limit their funds exposure to HTLCs. This allows you to set a minimum such value.
///
/// Default value: 0.
#[no_mangle]
pub extern "C" fn ChannelHandshakeLimits_get_min_max_htlc_value_in_flight_msat(this_ptr: &ChannelHandshakeLimits) -> u64 {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.min_max_htlc_value_in_flight_msat;
	(*inner_val)
}
/// The remote node sets a limit on the maximum value of pending HTLCs to them at any given
/// time to limit their funds exposure to HTLCs. This allows you to set a minimum such value.
///
/// Default value: 0.
#[no_mangle]
pub extern "C" fn ChannelHandshakeLimits_set_min_max_htlc_value_in_flight_msat(this_ptr: &mut ChannelHandshakeLimits, mut val: u64) {
	unsafe { &mut *this_ptr.inner }.min_max_htlc_value_in_flight_msat = val;
}
/// The remote node will require we keep a certain amount in direct payment to ourselves at all
/// time, ensuring that we are able to be punished if we broadcast an old state. This allows to
/// you limit the amount which we will have to keep to ourselves (and cannot use for HTLCs).
///
/// Default value: u64::max_value.
#[no_mangle]
pub extern "C" fn ChannelHandshakeLimits_get_max_channel_reserve_satoshis(this_ptr: &ChannelHandshakeLimits) -> u64 {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.max_channel_reserve_satoshis;
	(*inner_val)
}
/// The remote node will require we keep a certain amount in direct payment to ourselves at all
/// time, ensuring that we are able to be punished if we broadcast an old state. This allows to
/// you limit the amount which we will have to keep to ourselves (and cannot use for HTLCs).
///
/// Default value: u64::max_value.
#[no_mangle]
pub extern "C" fn ChannelHandshakeLimits_set_max_channel_reserve_satoshis(this_ptr: &mut ChannelHandshakeLimits, mut val: u64) {
	unsafe { &mut *this_ptr.inner }.max_channel_reserve_satoshis = val;
}
/// The remote node sets a limit on the maximum number of pending HTLCs to them at any given
/// time. This allows you to set a minimum such value.
///
/// Default value: 0.
#[no_mangle]
pub extern "C" fn ChannelHandshakeLimits_get_min_max_accepted_htlcs(this_ptr: &ChannelHandshakeLimits) -> u16 {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.min_max_accepted_htlcs;
	(*inner_val)
}
/// The remote node sets a limit on the maximum number of pending HTLCs to them at any given
/// time. This allows you to set a minimum such value.
///
/// Default value: 0.
#[no_mangle]
pub extern "C" fn ChannelHandshakeLimits_set_min_max_accepted_htlcs(this_ptr: &mut ChannelHandshakeLimits, mut val: u16) {
	unsafe { &mut *this_ptr.inner }.min_max_accepted_htlcs = val;
}
/// Outputs below a certain value will not be added to on-chain transactions. The dust value is
/// required to always be higher than this value so this only applies to HTLC outputs (and
/// potentially to-self outputs before any payments have been made).
/// Thus, HTLCs below this amount plus HTLC transaction fees are not enforceable on-chain.
/// This setting allows you to set a minimum dust limit for their commitment transactions,
/// reflecting the reality that tiny outputs are not considered standard transactions and will
/// not propagate through the Bitcoin network.
///
/// Default value: 546, the current dust limit on the Bitcoin network.
#[no_mangle]
pub extern "C" fn ChannelHandshakeLimits_get_min_dust_limit_satoshis(this_ptr: &ChannelHandshakeLimits) -> u64 {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.min_dust_limit_satoshis;
	(*inner_val)
}
/// Outputs below a certain value will not be added to on-chain transactions. The dust value is
/// required to always be higher than this value so this only applies to HTLC outputs (and
/// potentially to-self outputs before any payments have been made).
/// Thus, HTLCs below this amount plus HTLC transaction fees are not enforceable on-chain.
/// This setting allows you to set a minimum dust limit for their commitment transactions,
/// reflecting the reality that tiny outputs are not considered standard transactions and will
/// not propagate through the Bitcoin network.
///
/// Default value: 546, the current dust limit on the Bitcoin network.
#[no_mangle]
pub extern "C" fn ChannelHandshakeLimits_set_min_dust_limit_satoshis(this_ptr: &mut ChannelHandshakeLimits, mut val: u64) {
	unsafe { &mut *this_ptr.inner }.min_dust_limit_satoshis = val;
}
/// Maximum allowed threshold above which outputs will not be generated in their commitment
/// transactions.
/// HTLCs below this amount plus HTLC transaction fees are not enforceable on-chain.
///
/// Default value: u64::max_value.
#[no_mangle]
pub extern "C" fn ChannelHandshakeLimits_get_max_dust_limit_satoshis(this_ptr: &ChannelHandshakeLimits) -> u64 {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.max_dust_limit_satoshis;
	(*inner_val)
}
/// Maximum allowed threshold above which outputs will not be generated in their commitment
/// transactions.
/// HTLCs below this amount plus HTLC transaction fees are not enforceable on-chain.
///
/// Default value: u64::max_value.
#[no_mangle]
pub extern "C" fn ChannelHandshakeLimits_set_max_dust_limit_satoshis(this_ptr: &mut ChannelHandshakeLimits, mut val: u64) {
	unsafe { &mut *this_ptr.inner }.max_dust_limit_satoshis = val;
}
/// Before a channel is usable the funding transaction will need to be confirmed by at least a
/// certain number of blocks, specified by the node which is not the funder (as the funder can
/// assume they aren't going to double-spend themselves).
/// This config allows you to set a limit on the maximum amount of time to wait.
///
/// Default value: 144, or roughly one day and only applies to outbound channels.
#[no_mangle]
pub extern "C" fn ChannelHandshakeLimits_get_max_minimum_depth(this_ptr: &ChannelHandshakeLimits) -> u32 {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.max_minimum_depth;
	(*inner_val)
}
/// Before a channel is usable the funding transaction will need to be confirmed by at least a
/// certain number of blocks, specified by the node which is not the funder (as the funder can
/// assume they aren't going to double-spend themselves).
/// This config allows you to set a limit on the maximum amount of time to wait.
///
/// Default value: 144, or roughly one day and only applies to outbound channels.
#[no_mangle]
pub extern "C" fn ChannelHandshakeLimits_set_max_minimum_depth(this_ptr: &mut ChannelHandshakeLimits, mut val: u32) {
	unsafe { &mut *this_ptr.inner }.max_minimum_depth = val;
}
/// Set to force the incoming channel to match our announced channel preference in
/// ChannelConfig.
///
/// Default value: true, to make the default that no announced channels are possible (which is
/// appropriate for any nodes which are not online very reliably).
#[no_mangle]
pub extern "C" fn ChannelHandshakeLimits_get_force_announced_channel_preference(this_ptr: &ChannelHandshakeLimits) -> bool {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.force_announced_channel_preference;
	(*inner_val)
}
/// Set to force the incoming channel to match our announced channel preference in
/// ChannelConfig.
///
/// Default value: true, to make the default that no announced channels are possible (which is
/// appropriate for any nodes which are not online very reliably).
#[no_mangle]
pub extern "C" fn ChannelHandshakeLimits_set_force_announced_channel_preference(this_ptr: &mut ChannelHandshakeLimits, mut val: bool) {
	unsafe { &mut *this_ptr.inner }.force_announced_channel_preference = val;
}
/// Set to the amount of time we're willing to wait to claim money back to us.
///
/// Not checking this value would be a security issue, as our peer would be able to set it to
/// max relative lock-time (a year) and we would \"lose\" money as it would be locked for a long time.
///
/// Default value: MAX_LOCAL_BREAKDOWN_TIMEOUT (1008), which we also enforce as a maximum value
/// so you can tweak config to reduce the loss of having useless locked funds (if your peer accepts)
#[no_mangle]
pub extern "C" fn ChannelHandshakeLimits_get_their_to_self_delay(this_ptr: &ChannelHandshakeLimits) -> u16 {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.their_to_self_delay;
	(*inner_val)
}
/// Set to the amount of time we're willing to wait to claim money back to us.
///
/// Not checking this value would be a security issue, as our peer would be able to set it to
/// max relative lock-time (a year) and we would \"lose\" money as it would be locked for a long time.
///
/// Default value: MAX_LOCAL_BREAKDOWN_TIMEOUT (1008), which we also enforce as a maximum value
/// so you can tweak config to reduce the loss of having useless locked funds (if your peer accepts)
#[no_mangle]
pub extern "C" fn ChannelHandshakeLimits_set_their_to_self_delay(this_ptr: &mut ChannelHandshakeLimits, mut val: u16) {
	unsafe { &mut *this_ptr.inner }.their_to_self_delay = val;
}
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelHandshakeLimits_new(mut min_funding_satoshis_arg: u64, mut max_htlc_minimum_msat_arg: u64, mut min_max_htlc_value_in_flight_msat_arg: u64, mut max_channel_reserve_satoshis_arg: u64, mut min_max_accepted_htlcs_arg: u16, mut min_dust_limit_satoshis_arg: u64, mut max_dust_limit_satoshis_arg: u64, mut max_minimum_depth_arg: u32, mut force_announced_channel_preference_arg: bool, mut their_to_self_delay_arg: u16) -> ChannelHandshakeLimits {
	ChannelHandshakeLimits { inner: Box::into_raw(Box::new(nativeChannelHandshakeLimits {
		min_funding_satoshis: min_funding_satoshis_arg,
		max_htlc_minimum_msat: max_htlc_minimum_msat_arg,
		min_max_htlc_value_in_flight_msat: min_max_htlc_value_in_flight_msat_arg,
		max_channel_reserve_satoshis: max_channel_reserve_satoshis_arg,
		min_max_accepted_htlcs: min_max_accepted_htlcs_arg,
		min_dust_limit_satoshis: min_dust_limit_satoshis_arg,
		max_dust_limit_satoshis: max_dust_limit_satoshis_arg,
		max_minimum_depth: max_minimum_depth_arg,
		force_announced_channel_preference: force_announced_channel_preference_arg,
		their_to_self_delay: their_to_self_delay_arg,
	})), is_owned: true }
}
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelHandshakeLimits_default() -> ChannelHandshakeLimits {
	ChannelHandshakeLimits { inner: Box::into_raw(Box::new(Default::default())), is_owned: true }
}

use lightning::util::config::ChannelConfig as nativeChannelConfigImport;
type nativeChannelConfig = nativeChannelConfigImport;

/// Options which apply on a per-channel basis and may change at runtime or based on negotiation
/// with our counterparty.
#[must_use]
#[repr(C)]
pub struct ChannelConfig {
	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeChannelConfig,
	pub is_owned: bool,
}

impl Drop for ChannelConfig {
	fn drop(&mut self) {
		if self.is_owned && !self.inner.is_null() {
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
#[no_mangle]
pub extern "C" fn ChannelConfig_free(this_ptr: ChannelConfig) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn ChannelConfig_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeChannelConfig); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl ChannelConfig {
	pub(crate) fn take_inner(mut self) -> *mut nativeChannelConfig {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}
impl Clone for ChannelConfig {
	fn clone(&self) -> Self {
		Self {
			inner: Box::into_raw(Box::new(unsafe { &*self.inner }.clone())),
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ChannelConfig_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeChannelConfig)).clone() })) as *mut c_void
}
#[no_mangle]
pub extern "C" fn ChannelConfig_clone(orig: &ChannelConfig) -> ChannelConfig {
	ChannelConfig { inner: Box::into_raw(Box::new(unsafe { &*orig.inner }.clone())), is_owned: true }
}
/// Amount (in millionths of a satoshi) the channel will charge per transferred satoshi.
/// This may be allowed to change at runtime in a later update, however doing so must result in
/// update messages sent to notify all nodes of our updated relay fee.
///
/// Default value: 0.
#[no_mangle]
pub extern "C" fn ChannelConfig_get_fee_proportional_millionths(this_ptr: &ChannelConfig) -> u32 {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.fee_proportional_millionths;
	(*inner_val)
}
/// Amount (in millionths of a satoshi) the channel will charge per transferred satoshi.
/// This may be allowed to change at runtime in a later update, however doing so must result in
/// update messages sent to notify all nodes of our updated relay fee.
///
/// Default value: 0.
#[no_mangle]
pub extern "C" fn ChannelConfig_set_fee_proportional_millionths(this_ptr: &mut ChannelConfig, mut val: u32) {
	unsafe { &mut *this_ptr.inner }.fee_proportional_millionths = val;
}
/// Set to announce the channel publicly and notify all nodes that they can route via this
/// channel.
///
/// This should only be set to true for nodes which expect to be online reliably.
///
/// As the node which funds a channel picks this value this will only apply for new outbound
/// channels unless ChannelHandshakeLimits::force_announced_channel_preferences is set.
///
/// This cannot be changed after the initial channel handshake.
///
/// Default value: false.
#[no_mangle]
pub extern "C" fn ChannelConfig_get_announced_channel(this_ptr: &ChannelConfig) -> bool {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.announced_channel;
	(*inner_val)
}
/// Set to announce the channel publicly and notify all nodes that they can route via this
/// channel.
///
/// This should only be set to true for nodes which expect to be online reliably.
///
/// As the node which funds a channel picks this value this will only apply for new outbound
/// channels unless ChannelHandshakeLimits::force_announced_channel_preferences is set.
///
/// This cannot be changed after the initial channel handshake.
///
/// Default value: false.
#[no_mangle]
pub extern "C" fn ChannelConfig_set_announced_channel(this_ptr: &mut ChannelConfig, mut val: bool) {
	unsafe { &mut *this_ptr.inner }.announced_channel = val;
}
/// When set, we commit to an upfront shutdown_pubkey at channel open. If our counterparty
/// supports it, they will then enforce the mutual-close output to us matches what we provided
/// at intialization, preventing us from closing to an alternate pubkey.
///
/// This is set to true by default to provide a slight increase in security, though ultimately
/// any attacker who is able to take control of a channel can just as easily send the funds via
/// lightning payments, so we never require that our counterparties support this option.
///
/// This cannot be changed after a channel has been initialized.
///
/// Default value: true.
#[no_mangle]
pub extern "C" fn ChannelConfig_get_commit_upfront_shutdown_pubkey(this_ptr: &ChannelConfig) -> bool {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.commit_upfront_shutdown_pubkey;
	(*inner_val)
}
/// When set, we commit to an upfront shutdown_pubkey at channel open. If our counterparty
/// supports it, they will then enforce the mutual-close output to us matches what we provided
/// at intialization, preventing us from closing to an alternate pubkey.
///
/// This is set to true by default to provide a slight increase in security, though ultimately
/// any attacker who is able to take control of a channel can just as easily send the funds via
/// lightning payments, so we never require that our counterparties support this option.
///
/// This cannot be changed after a channel has been initialized.
///
/// Default value: true.
#[no_mangle]
pub extern "C" fn ChannelConfig_set_commit_upfront_shutdown_pubkey(this_ptr: &mut ChannelConfig, mut val: bool) {
	unsafe { &mut *this_ptr.inner }.commit_upfront_shutdown_pubkey = val;
}
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelConfig_new(mut fee_proportional_millionths_arg: u32, mut announced_channel_arg: bool, mut commit_upfront_shutdown_pubkey_arg: bool) -> ChannelConfig {
	ChannelConfig { inner: Box::into_raw(Box::new(nativeChannelConfig {
		fee_proportional_millionths: fee_proportional_millionths_arg,
		announced_channel: announced_channel_arg,
		commit_upfront_shutdown_pubkey: commit_upfront_shutdown_pubkey_arg,
	})), is_owned: true }
}
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelConfig_default() -> ChannelConfig {
	ChannelConfig { inner: Box::into_raw(Box::new(Default::default())), is_owned: true }
}
#[no_mangle]
pub extern "C" fn ChannelConfig_write(obj: &ChannelConfig) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &(*(*obj).inner) })
}
#[no_mangle]
pub(crate) extern "C" fn ChannelConfig_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeChannelConfig) })
}
#[no_mangle]
pub extern "C" fn ChannelConfig_read(ser: crate::c_types::u8slice) -> ChannelConfig {
	if let Ok(res) = crate::c_types::deserialize_obj(ser) {
		ChannelConfig { inner: Box::into_raw(Box::new(res)), is_owned: true }
	} else {
		ChannelConfig { inner: std::ptr::null_mut(), is_owned: true }
	}
}

use lightning::util::config::UserConfig as nativeUserConfigImport;
type nativeUserConfig = nativeUserConfigImport;

/// Top-level config which holds ChannelHandshakeLimits and ChannelConfig.
///
/// Default::default() provides sane defaults for most configurations
/// (but currently with 0 relay fees!)
#[must_use]
#[repr(C)]
pub struct UserConfig {
	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeUserConfig,
	pub is_owned: bool,
}

impl Drop for UserConfig {
	fn drop(&mut self) {
		if self.is_owned && !self.inner.is_null() {
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
#[no_mangle]
pub extern "C" fn UserConfig_free(this_ptr: UserConfig) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn UserConfig_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeUserConfig); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl UserConfig {
	pub(crate) fn take_inner(mut self) -> *mut nativeUserConfig {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}
impl Clone for UserConfig {
	fn clone(&self) -> Self {
		Self {
			inner: Box::into_raw(Box::new(unsafe { &*self.inner }.clone())),
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn UserConfig_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeUserConfig)).clone() })) as *mut c_void
}
#[no_mangle]
pub extern "C" fn UserConfig_clone(orig: &UserConfig) -> UserConfig {
	UserConfig { inner: Box::into_raw(Box::new(unsafe { &*orig.inner }.clone())), is_owned: true }
}
/// Channel config that we propose to our counterparty.
#[no_mangle]
pub extern "C" fn UserConfig_get_own_channel_config(this_ptr: &UserConfig) -> crate::util::config::ChannelHandshakeConfig {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.own_channel_config;
	crate::util::config::ChannelHandshakeConfig { inner: unsafe { ( (&((*inner_val)) as *const _) as *mut _) }, is_owned: false }
}
/// Channel config that we propose to our counterparty.
#[no_mangle]
pub extern "C" fn UserConfig_set_own_channel_config(this_ptr: &mut UserConfig, mut val: crate::util::config::ChannelHandshakeConfig) {
	unsafe { &mut *this_ptr.inner }.own_channel_config = *unsafe { Box::from_raw(val.take_inner()) };
}
/// Limits applied to our counterparty's proposed channel config settings.
#[no_mangle]
pub extern "C" fn UserConfig_get_peer_channel_config_limits(this_ptr: &UserConfig) -> crate::util::config::ChannelHandshakeLimits {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.peer_channel_config_limits;
	crate::util::config::ChannelHandshakeLimits { inner: unsafe { ( (&((*inner_val)) as *const _) as *mut _) }, is_owned: false }
}
/// Limits applied to our counterparty's proposed channel config settings.
#[no_mangle]
pub extern "C" fn UserConfig_set_peer_channel_config_limits(this_ptr: &mut UserConfig, mut val: crate::util::config::ChannelHandshakeLimits) {
	unsafe { &mut *this_ptr.inner }.peer_channel_config_limits = *unsafe { Box::from_raw(val.take_inner()) };
}
/// Channel config which affects behavior during channel lifetime.
#[no_mangle]
pub extern "C" fn UserConfig_get_channel_options(this_ptr: &UserConfig) -> crate::util::config::ChannelConfig {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.channel_options;
	crate::util::config::ChannelConfig { inner: unsafe { ( (&((*inner_val)) as *const _) as *mut _) }, is_owned: false }
}
/// Channel config which affects behavior during channel lifetime.
#[no_mangle]
pub extern "C" fn UserConfig_set_channel_options(this_ptr: &mut UserConfig, mut val: crate::util::config::ChannelConfig) {
	unsafe { &mut *this_ptr.inner }.channel_options = *unsafe { Box::from_raw(val.take_inner()) };
}
#[must_use]
#[no_mangle]
pub extern "C" fn UserConfig_new(mut own_channel_config_arg: crate::util::config::ChannelHandshakeConfig, mut peer_channel_config_limits_arg: crate::util::config::ChannelHandshakeLimits, mut channel_options_arg: crate::util::config::ChannelConfig) -> UserConfig {
	UserConfig { inner: Box::into_raw(Box::new(nativeUserConfig {
		own_channel_config: *unsafe { Box::from_raw(own_channel_config_arg.take_inner()) },
		peer_channel_config_limits: *unsafe { Box::from_raw(peer_channel_config_limits_arg.take_inner()) },
		channel_options: *unsafe { Box::from_raw(channel_options_arg.take_inner()) },
	})), is_owned: true }
}
#[must_use]
#[no_mangle]
pub extern "C" fn UserConfig_default() -> UserConfig {
	UserConfig { inner: Box::into_raw(Box::new(Default::default())), is_owned: true }
}
