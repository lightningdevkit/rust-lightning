//! Logic to connect off-chain channel management with on-chain transaction monitoring.
//!
//! [`ChainMonitor`] is an implementation of [`chain::Watch`] used both to process blocks and to
//! update [`ChannelMonitor`]s accordingly. If any on-chain events need further processing, it will
//! make those available as [`MonitorEvent`]s to be consumed.
//!
//! `ChainMonitor` is parameterized by an optional chain source, which must implement the
//! [`chain::Filter`] trait. This provides a mechanism to signal new relevant outputs back to light
//! clients, such that transactions spending those outputs are included in block data.
//!
//! `ChainMonitor` may be used directly to monitor channels locally or as a part of a distributed
//! setup to monitor channels remotely. In the latter case, a custom `chain::Watch` implementation
//! would be responsible for routing each update to a remote server and for retrieving monitor
//! events. The remote server would make use of `ChainMonitor` for block processing and for
//! servicing `ChannelMonitor` updates from the client.
//!
//! [`ChainMonitor`]: struct.ChainMonitor.html
//! [`chain::Filter`]: ../trait.Filter.html
//! [`chain::Watch`]: ../trait.Watch.html
//! [`ChannelMonitor`]: ../channelmonitor/struct.ChannelMonitor.html
//! [`MonitorEvent`]: ../channelmonitor/enum.MonitorEvent.html

use std::ffi::c_void;
use bitcoin::hashes::Hash;
use crate::c_types::*;


use lightning::chain::chainmonitor::ChainMonitor as nativeChainMonitorImport;
type nativeChainMonitor = nativeChainMonitorImport<crate::chain::keysinterface::ChannelKeys, crate::chain::Filter, crate::chain::chaininterface::BroadcasterInterface, crate::chain::chaininterface::FeeEstimator, crate::util::logger::Logger, crate::chain::channelmonitor::Persist>;

/// An implementation of [`chain::Watch`] for monitoring channels.
///
/// Connected and disconnected blocks must be provided to `ChainMonitor` as documented by
/// [`chain::Watch`]. May be used in conjunction with [`ChannelManager`] to monitor channels locally
/// or used independently to monitor channels remotely. See the [module-level documentation] for
/// details.
///
/// [`chain::Watch`]: ../trait.Watch.html
/// [`ChannelManager`]: ../../ln/channelmanager/struct.ChannelManager.html
/// [module-level documentation]: index.html
#[must_use]
#[repr(C)]
pub struct ChainMonitor {
	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeChainMonitor,
	pub is_owned: bool,
}

impl Drop for ChainMonitor {
	fn drop(&mut self) {
		if self.is_owned && !self.inner.is_null() {
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
#[no_mangle]
pub extern "C" fn ChainMonitor_free(this_ptr: ChainMonitor) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn ChainMonitor_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeChainMonitor); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl ChainMonitor {
	pub(crate) fn take_inner(mut self) -> *mut nativeChainMonitor {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}
/// Dispatches to per-channel monitors, which are responsible for updating their on-chain view
/// of a channel and reacting accordingly based on transactions in the connected block. See
/// [`ChannelMonitor::block_connected`] for details. Any HTLCs that were resolved on chain will
/// be returned by [`chain::Watch::release_pending_monitor_events`].
///
/// Calls back to [`chain::Filter`] if any monitor indicated new outputs to watch. Subsequent
/// calls must not exclude any transactions matching the new outputs nor any in-block
/// descendants of such transactions. It is not necessary to re-fetch the block to obtain
/// updated `txdata`.
///
/// [`ChannelMonitor::block_connected`]: ../channelmonitor/struct.ChannelMonitor.html#method.block_connected
/// [`chain::Watch::release_pending_monitor_events`]: ../trait.Watch.html#tymethod.release_pending_monitor_events
/// [`chain::Filter`]: ../trait.Filter.html
#[no_mangle]
pub extern "C" fn ChainMonitor_block_connected(this_arg: &ChainMonitor, header: *const [u8; 80], mut txdata: crate::c_types::derived::CVec_C2Tuple_usizeTransactionZZ, mut height: u32) {
	let mut local_txdata = Vec::new(); for mut item in txdata.into_rust().drain(..) { local_txdata.push( { let (mut orig_txdata_0_0, mut orig_txdata_0_1) = item.to_rust(); let mut local_txdata_0 = (orig_txdata_0_0, orig_txdata_0_1.into_bitcoin()); local_txdata_0 }); };
	unsafe { &*this_arg.inner }.block_connected(&::bitcoin::consensus::encode::deserialize(unsafe { &*header }).unwrap(), &local_txdata.iter().map(|(a, b)| (*a, b)).collect::<Vec<_>>()[..], height)
}

/// Dispatches to per-channel monitors, which are responsible for updating their on-chain view
/// of a channel based on the disconnected block. See [`ChannelMonitor::block_disconnected`] for
/// details.
///
/// [`ChannelMonitor::block_disconnected`]: ../channelmonitor/struct.ChannelMonitor.html#method.block_disconnected
#[no_mangle]
pub extern "C" fn ChainMonitor_block_disconnected(this_arg: &ChainMonitor, header: *const [u8; 80], mut disconnected_height: u32) {
	unsafe { &*this_arg.inner }.block_disconnected(&::bitcoin::consensus::encode::deserialize(unsafe { &*header }).unwrap(), disconnected_height)
}

/// Creates a new `ChainMonitor` used to watch on-chain activity pertaining to channels.
///
/// When an optional chain source implementing [`chain::Filter`] is provided, the chain monitor
/// will call back to it indicating transactions and outputs of interest. This allows clients to
/// pre-filter blocks or only fetch blocks matching a compact filter. Otherwise, clients may
/// always need to fetch full blocks absent another means for determining which blocks contain
/// transactions relevant to the watched channels.
///
/// [`chain::Filter`]: ../trait.Filter.html
#[must_use]
#[no_mangle]
pub extern "C" fn ChainMonitor_new(chain_source: *mut crate::chain::Filter, mut broadcaster: crate::chain::chaininterface::BroadcasterInterface, mut logger: crate::util::logger::Logger, mut feeest: crate::chain::chaininterface::FeeEstimator, mut persister: crate::chain::channelmonitor::Persist) -> ChainMonitor {
	let mut local_chain_source = if chain_source == std::ptr::null_mut() { None } else { Some( { unsafe { *Box::from_raw(chain_source) } }) };
	let mut ret = lightning::chain::chainmonitor::ChainMonitor::new(local_chain_source, broadcaster, logger, feeest, persister);
	ChainMonitor { inner: Box::into_raw(Box::new(ret)), is_owned: true }
}

impl From<nativeChainMonitor> for crate::chain::Watch {
	fn from(obj: nativeChainMonitor) -> Self {
		let mut rust_obj = ChainMonitor { inner: Box::into_raw(Box::new(obj)), is_owned: true };
		let mut ret = ChainMonitor_as_Watch(&rust_obj);
		// We want to free rust_obj when ret gets drop()'d, not rust_obj, so wipe rust_obj's pointer and set ret's free() fn
		rust_obj.inner = std::ptr::null_mut();
		ret.free = Some(ChainMonitor_free_void);
		ret
	}
}
#[no_mangle]
pub extern "C" fn ChainMonitor_as_Watch(this_arg: &ChainMonitor) -> crate::chain::Watch {
	crate::chain::Watch {
		this_arg: unsafe { (*this_arg).inner as *mut c_void },
		free: None,
		watch_channel: ChainMonitor_Watch_watch_channel,
		update_channel: ChainMonitor_Watch_update_channel,
		release_pending_monitor_events: ChainMonitor_Watch_release_pending_monitor_events,
	}
}
use lightning::chain::Watch as WatchTraitImport;
#[must_use]
extern "C" fn ChainMonitor_Watch_watch_channel(this_arg: *const c_void, mut funding_outpoint: crate::chain::transaction::OutPoint, mut monitor: crate::chain::channelmonitor::ChannelMonitor) -> crate::c_types::derived::CResult_NoneChannelMonitorUpdateErrZ {
	let mut ret = unsafe { &mut *(this_arg as *mut nativeChainMonitor) }.watch_channel(*unsafe { Box::from_raw(funding_outpoint.take_inner()) }, *unsafe { Box::from_raw(monitor.take_inner()) });
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { 0u8 /*o*/ }), Err(mut e) => crate::c_types::CResultTempl::err( { crate::chain::channelmonitor::ChannelMonitorUpdateErr::native_into(e) }) };
	local_ret
}
#[must_use]
extern "C" fn ChainMonitor_Watch_update_channel(this_arg: *const c_void, mut funding_txo: crate::chain::transaction::OutPoint, mut update: crate::chain::channelmonitor::ChannelMonitorUpdate) -> crate::c_types::derived::CResult_NoneChannelMonitorUpdateErrZ {
	let mut ret = unsafe { &mut *(this_arg as *mut nativeChainMonitor) }.update_channel(*unsafe { Box::from_raw(funding_txo.take_inner()) }, *unsafe { Box::from_raw(update.take_inner()) });
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { 0u8 /*o*/ }), Err(mut e) => crate::c_types::CResultTempl::err( { crate::chain::channelmonitor::ChannelMonitorUpdateErr::native_into(e) }) };
	local_ret
}
#[must_use]
extern "C" fn ChainMonitor_Watch_release_pending_monitor_events(this_arg: *const c_void) -> crate::c_types::derived::CVec_MonitorEventZ {
	let mut ret = unsafe { &mut *(this_arg as *mut nativeChainMonitor) }.release_pending_monitor_events();
	let mut local_ret = Vec::new(); for item in ret.drain(..) { local_ret.push( { crate::chain::channelmonitor::MonitorEvent { inner: Box::into_raw(Box::new(item)), is_owned: true } }); };
	local_ret.into()
}

impl From<nativeChainMonitor> for crate::util::events::EventsProvider {
	fn from(obj: nativeChainMonitor) -> Self {
		let mut rust_obj = ChainMonitor { inner: Box::into_raw(Box::new(obj)), is_owned: true };
		let mut ret = ChainMonitor_as_EventsProvider(&rust_obj);
		// We want to free rust_obj when ret gets drop()'d, not rust_obj, so wipe rust_obj's pointer and set ret's free() fn
		rust_obj.inner = std::ptr::null_mut();
		ret.free = Some(ChainMonitor_free_void);
		ret
	}
}
#[no_mangle]
pub extern "C" fn ChainMonitor_as_EventsProvider(this_arg: &ChainMonitor) -> crate::util::events::EventsProvider {
	crate::util::events::EventsProvider {
		this_arg: unsafe { (*this_arg).inner as *mut c_void },
		free: None,
		get_and_clear_pending_events: ChainMonitor_EventsProvider_get_and_clear_pending_events,
	}
}
use lightning::util::events::EventsProvider as EventsProviderTraitImport;
#[must_use]
extern "C" fn ChainMonitor_EventsProvider_get_and_clear_pending_events(this_arg: *const c_void) -> crate::c_types::derived::CVec_EventZ {
	let mut ret = unsafe { &mut *(this_arg as *mut nativeChainMonitor) }.get_and_clear_pending_events();
	let mut local_ret = Vec::new(); for item in ret.drain(..) { local_ret.push( { crate::util::events::Event::native_into(item) }); };
	local_ret.into()
}

