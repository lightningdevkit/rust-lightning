//! Traits and utility impls which allow other parts of rust-lightning to interact with the
//! blockchain.
//!
//! Includes traits for monitoring and receiving notifications of new blocks and block
//! disconnections, transaction broadcasting, and feerate information requests.

use std::ffi::c_void;
use bitcoin::hashes::Hash;
use crate::c_types::*;

/// Used to give chain error details upstream
#[must_use]
#[derive(Clone)]
#[repr(C)]
pub enum ChainError {
	/// Client doesn't support UTXO lookup (but the chain hash matches our genesis block hash)
	NotSupported,
	/// Chain isn't the one watched
	NotWatched,
	/// Tx doesn't exist or is unconfirmed
	UnknownTx,
}
use lightning::chain::chaininterface::ChainError as nativeChainError;
impl ChainError {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeChainError {
		match self {
			ChainError::NotSupported => nativeChainError::NotSupported,
			ChainError::NotWatched => nativeChainError::NotWatched,
			ChainError::UnknownTx => nativeChainError::UnknownTx,
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeChainError {
		match self {
			ChainError::NotSupported => nativeChainError::NotSupported,
			ChainError::NotWatched => nativeChainError::NotWatched,
			ChainError::UnknownTx => nativeChainError::UnknownTx,
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &nativeChainError) -> Self {
		match native {
			nativeChainError::NotSupported => ChainError::NotSupported,
			nativeChainError::NotWatched => ChainError::NotWatched,
			nativeChainError::UnknownTx => ChainError::UnknownTx,
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeChainError) -> Self {
		match native {
			nativeChainError::NotSupported => ChainError::NotSupported,
			nativeChainError::NotWatched => ChainError::NotWatched,
			nativeChainError::UnknownTx => ChainError::UnknownTx,
		}
	}
}
/// An interface to request notification of certain scripts as they appear the
/// chain.
///
/// Note that all of the functions implemented here *must* be reentrant-safe (obviously - they're
/// called from inside the library in response to ChainListener events, P2P events, or timer
/// events).
#[repr(C)]
pub struct ChainWatchInterface {
	pub this_arg: *mut c_void,
	/// Provides a txid/random-scriptPubKey-in-the-tx which much be watched for.
	pub install_watch_tx: extern "C" fn (this_arg: *const c_void, txid: *const [u8; 32], script_pub_key: crate::c_types::u8slice),
	/// Provides an outpoint which must be watched for, providing any transactions which spend the
	/// given outpoint.
	pub install_watch_outpoint: extern "C" fn (this_arg: *const c_void, outpoint: crate::c_types::derived::C2Tuple_Txidu32Z, out_script: crate::c_types::u8slice),
	/// Indicates that a listener needs to see all transactions.
	pub watch_all_txn: extern "C" fn (this_arg: *const c_void),
	/// Gets the script and value in satoshis for a given unspent transaction output given a
	/// short_channel_id (aka unspent_tx_output_identier). For BTC/tBTC channels the top three
	/// bytes are the block height, the next 3 the transaction index within the block, and the
	/// final two the output within the transaction.
	#[must_use]
	pub get_chain_utxo: extern "C" fn (this_arg: *const c_void, genesis_hash: crate::c_types::ThirtyTwoBytes, unspent_tx_output_identifier: u64) -> crate::c_types::derived::CResult_C2Tuple_Scriptu64ZChainErrorZ,
	/// Gets the list of transaction indices within a given block that the ChainWatchInterface is
	/// watching for.
	#[must_use]
	pub filter_block: extern "C" fn (this_arg: *const c_void, block: crate::c_types::u8slice) -> crate::c_types::derived::CVec_usizeZ,
	/// Returns a usize that changes when the ChainWatchInterface's watched data is modified.
	/// Users of `filter_block` should pre-save a copy of `reentered`'s return value and use it to
	/// determine whether they need to re-filter a given block.
	#[must_use]
	pub reentered: extern "C" fn (this_arg: *const c_void) -> usize,
	pub free: Option<extern "C" fn(this_arg: *mut c_void)>,
}
unsafe impl Sync for ChainWatchInterface {}
unsafe impl Send for ChainWatchInterface {}

use lightning::chain::chaininterface::ChainWatchInterface as rustChainWatchInterface;
impl rustChainWatchInterface for ChainWatchInterface {
	fn install_watch_tx(&self, txid: &bitcoin::hash_types::Txid, script_pub_key: &bitcoin::blockdata::script::Script) {
		(self.install_watch_tx)(self.this_arg, txid.as_inner(), crate::c_types::u8slice::from_slice(&script_pub_key[..]))
	}
	fn install_watch_outpoint(&self, outpoint: (bitcoin::hash_types::Txid, u32), out_script: &bitcoin::blockdata::script::Script) {
		let (mut orig_outpoint_0, mut orig_outpoint_1) = outpoint; let mut local_outpoint = (crate::c_types::ThirtyTwoBytes { data: orig_outpoint_0.into_inner() }, orig_outpoint_1).into();
		(self.install_watch_outpoint)(self.this_arg, local_outpoint, crate::c_types::u8slice::from_slice(&out_script[..]))
	}
	fn watch_all_txn(&self) {
		(self.watch_all_txn)(self.this_arg)
	}
	fn get_chain_utxo(&self, genesis_hash: bitcoin::hash_types::BlockHash, unspent_tx_output_identifier: u64) -> Result<(bitcoin::blockdata::script::Script, u64), lightning::chain::chaininterface::ChainError> {
		let mut ret = (self.get_chain_utxo)(self.this_arg, crate::c_types::ThirtyTwoBytes { data: genesis_hash.into_inner() }, unspent_tx_output_identifier);
		let mut local_ret = match ret.result_ok { true => Ok( { let (mut orig_ret_0_0, mut orig_ret_0_1) = (*unsafe { Box::from_raw(ret.contents.result.take_ptr()) }).to_rust(); let mut local_ret_0 = (::bitcoin::blockdata::script::Script::from(orig_ret_0_0.into_rust()), orig_ret_0_1); local_ret_0 }), false => Err( { (*unsafe { Box::from_raw(ret.contents.err.take_ptr()) }).into_native() })};
		local_ret
	}
	fn filter_block(&self, block: &bitcoin::blockdata::block::Block) -> Vec<usize> {
		let mut local_block = ::bitcoin::consensus::encode::serialize(block);
		let mut ret = (self.filter_block)(self.this_arg, crate::c_types::u8slice::from_slice(&local_block));
		let mut local_ret = Vec::new(); for mut item in ret.into_rust().drain(..) { local_ret.push( { item }); };
		local_ret
	}
	fn reentered(&self) -> usize {
		let mut ret = (self.reentered)(self.this_arg);
		ret
	}
}

// We're essentially a pointer already, or at least a set of pointers, so allow us to be used
// directly as a Deref trait in higher-level structs:
impl std::ops::Deref for ChainWatchInterface {
	type Target = Self;
	fn deref(&self) -> &Self {
		self
	}
}
/// Calls the free function if one is set
#[no_mangle]
pub extern "C" fn ChainWatchInterface_free(this_ptr: ChainWatchInterface) { }
impl Drop for ChainWatchInterface {
	fn drop(&mut self) {
		if let Some(f) = self.free {
			f(self.this_arg);
		}
	}
}
/// An interface to send a transaction to the Bitcoin network.
#[repr(C)]
pub struct BroadcasterInterface {
	pub this_arg: *mut c_void,
	/// Sends a transaction out to (hopefully) be mined.
	pub broadcast_transaction: extern "C" fn (this_arg: *const c_void, tx: crate::c_types::Transaction),
	pub free: Option<extern "C" fn(this_arg: *mut c_void)>,
}
unsafe impl Sync for BroadcasterInterface {}
unsafe impl Send for BroadcasterInterface {}

use lightning::chain::chaininterface::BroadcasterInterface as rustBroadcasterInterface;
impl rustBroadcasterInterface for BroadcasterInterface {
	fn broadcast_transaction(&self, tx: &bitcoin::blockdata::transaction::Transaction) {
		let mut local_tx = ::bitcoin::consensus::encode::serialize(tx);
		(self.broadcast_transaction)(self.this_arg, crate::c_types::Transaction::from_slice(&local_tx))
	}
}

// We're essentially a pointer already, or at least a set of pointers, so allow us to be used
// directly as a Deref trait in higher-level structs:
impl std::ops::Deref for BroadcasterInterface {
	type Target = Self;
	fn deref(&self) -> &Self {
		self
	}
}
/// Calls the free function if one is set
#[no_mangle]
pub extern "C" fn BroadcasterInterface_free(this_ptr: BroadcasterInterface) { }
impl Drop for BroadcasterInterface {
	fn drop(&mut self) {
		if let Some(f) = self.free {
			f(self.this_arg);
		}
	}
}
/// A trait indicating a desire to listen for events from the chain
#[repr(C)]
pub struct ChainListener {
	pub this_arg: *mut c_void,
	/// Notifies a listener that a block was connected.
	///
	/// The txn_matched array should be set to references to transactions which matched the
	/// relevant installed watch outpoints/txn, or the full set of transactions in the block.
	///
	/// Note that if txn_matched includes only matched transactions, and a new
	/// transaction/outpoint is watched during a block_connected call, the block *must* be
	/// re-scanned with the new transaction/outpoints and block_connected should be called
	/// again with the same header and (at least) the new transactions.
	///
	/// Note that if non-new transaction/outpoints are be registered during a call, a second call
	/// *must not* happen.
	///
	/// This also means those counting confirmations using block_connected callbacks should watch
	/// for duplicate headers and not count them towards confirmations!
	pub block_connected: extern "C" fn (this_arg: *const c_void, header: *const [u8; 80], height: u32, txn_matched: crate::c_types::derived::CVec_TransactionZ, indexes_of_txn_matched: crate::c_types::usizeslice),
	/// Notifies a listener that a block was disconnected.
	/// Unlike block_connected, this *must* never be called twice for the same disconnect event.
	/// Height must be the one of the block which was disconnected (not new height of the best chain)
	pub block_disconnected: extern "C" fn (this_arg: *const c_void, header: *const [u8; 80], disconnected_height: u32),
	pub free: Option<extern "C" fn(this_arg: *mut c_void)>,
}
unsafe impl Sync for ChainListener {}
unsafe impl Send for ChainListener {}

use lightning::chain::chaininterface::ChainListener as rustChainListener;
impl rustChainListener for ChainListener {
	fn block_connected(&self, header: &bitcoin::blockdata::block::BlockHeader, height: u32, txn_matched: &[&bitcoin::blockdata::transaction::Transaction], indexes_of_txn_matched: &[usize]) {
		let mut local_header = { let mut s = [0u8; 80]; s[..].copy_from_slice(&::bitcoin::consensus::encode::serialize(header)); s };
		let mut local_txn_matched = Vec::new(); for item in txn_matched.iter() { local_txn_matched.push( { let mut local_txn_matched_0 = ::bitcoin::consensus::encode::serialize(&**item); local_txn_matched_0.into() }); };
		let mut local_indexes_of_txn_matched = crate::c_types::usizeslice::from_slice(indexes_of_txn_matched);
		(self.block_connected)(self.this_arg, &local_header, height, local_txn_matched.into(), local_indexes_of_txn_matched)
	}
	fn block_disconnected(&self, header: &bitcoin::blockdata::block::BlockHeader, disconnected_height: u32) {
		let mut local_header = { let mut s = [0u8; 80]; s[..].copy_from_slice(&::bitcoin::consensus::encode::serialize(header)); s };
		(self.block_disconnected)(self.this_arg, &local_header, disconnected_height)
	}
}

// We're essentially a pointer already, or at least a set of pointers, so allow us to be used
// directly as a Deref trait in higher-level structs:
impl std::ops::Deref for ChainListener {
	type Target = Self;
	fn deref(&self) -> &Self {
		self
	}
}
/// Calls the free function if one is set
#[no_mangle]
pub extern "C" fn ChainListener_free(this_ptr: ChainListener) { }
impl Drop for ChainListener {
	fn drop(&mut self) {
		if let Some(f) = self.free {
			f(self.this_arg);
		}
	}
}
/// An enum that represents the speed at which we want a transaction to confirm used for feerate
/// estimation.
#[must_use]
#[derive(Clone)]
#[repr(C)]
pub enum ConfirmationTarget {
	/// We are happy with this transaction confirming slowly when feerate drops some.
	Background,
	/// We'd like this transaction to confirm without major delay, but 12-18 blocks is fine.
	Normal,
	/// We'd like this transaction to confirm in the next few blocks.
	HighPriority,
}
use lightning::chain::chaininterface::ConfirmationTarget as nativeConfirmationTarget;
impl ConfirmationTarget {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeConfirmationTarget {
		match self {
			ConfirmationTarget::Background => nativeConfirmationTarget::Background,
			ConfirmationTarget::Normal => nativeConfirmationTarget::Normal,
			ConfirmationTarget::HighPriority => nativeConfirmationTarget::HighPriority,
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeConfirmationTarget {
		match self {
			ConfirmationTarget::Background => nativeConfirmationTarget::Background,
			ConfirmationTarget::Normal => nativeConfirmationTarget::Normal,
			ConfirmationTarget::HighPriority => nativeConfirmationTarget::HighPriority,
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &nativeConfirmationTarget) -> Self {
		match native {
			nativeConfirmationTarget::Background => ConfirmationTarget::Background,
			nativeConfirmationTarget::Normal => ConfirmationTarget::Normal,
			nativeConfirmationTarget::HighPriority => ConfirmationTarget::HighPriority,
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeConfirmationTarget) -> Self {
		match native {
			nativeConfirmationTarget::Background => ConfirmationTarget::Background,
			nativeConfirmationTarget::Normal => ConfirmationTarget::Normal,
			nativeConfirmationTarget::HighPriority => ConfirmationTarget::HighPriority,
		}
	}
}
/// A trait which should be implemented to provide feerate information on a number of time
/// horizons.
///
/// Note that all of the functions implemented here *must* be reentrant-safe (obviously - they're
/// called from inside the library in response to ChainListener events, P2P events, or timer
/// events).
#[repr(C)]
pub struct FeeEstimator {
	pub this_arg: *mut c_void,
	/// Gets estimated satoshis of fee required per 1000 Weight-Units.
	///
	/// Must be no smaller than 253 (ie 1 satoshi-per-byte rounded up to ensure later round-downs
	/// don't put us below 1 satoshi-per-byte).
	///
	/// This translates to:
	///  * satoshis-per-byte * 250
	///  * ceil(satoshis-per-kbyte / 4)
	#[must_use]
	pub get_est_sat_per_1000_weight: extern "C" fn (this_arg: *const c_void, confirmation_target: crate::chain::chaininterface::ConfirmationTarget) -> u32,
	pub free: Option<extern "C" fn(this_arg: *mut c_void)>,
}
unsafe impl Sync for FeeEstimator {}
unsafe impl Send for FeeEstimator {}

use lightning::chain::chaininterface::FeeEstimator as rustFeeEstimator;
impl rustFeeEstimator for FeeEstimator {
	fn get_est_sat_per_1000_weight(&self, confirmation_target: lightning::chain::chaininterface::ConfirmationTarget) -> u32 {
		let mut ret = (self.get_est_sat_per_1000_weight)(self.this_arg, crate::chain::chaininterface::ConfirmationTarget::native_into(confirmation_target));
		ret
	}
}

// We're essentially a pointer already, or at least a set of pointers, so allow us to be used
// directly as a Deref trait in higher-level structs:
impl std::ops::Deref for FeeEstimator {
	type Target = Self;
	fn deref(&self) -> &Self {
		self
	}
}
/// Calls the free function if one is set
#[no_mangle]
pub extern "C" fn FeeEstimator_free(this_ptr: FeeEstimator) { }
impl Drop for FeeEstimator {
	fn drop(&mut self) {
		if let Some(f) = self.free {
			f(self.this_arg);
		}
	}
}

#[no_mangle]
pub static MIN_RELAY_FEE_SAT_PER_1000_WEIGHT: u64 = lightning::chain::chaininterface::MIN_RELAY_FEE_SAT_PER_1000_WEIGHT;

use lightning::chain::chaininterface::ChainWatchedUtil as nativeChainWatchedUtilImport;
type nativeChainWatchedUtil = nativeChainWatchedUtilImport;

/// Utility for tracking registered txn/outpoints and checking for matches
#[must_use]
#[repr(C)]
pub struct ChainWatchedUtil {
	/// Nearly everyhwere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeChainWatchedUtil,
	pub is_owned: bool,
}

impl Drop for ChainWatchedUtil {
	fn drop(&mut self) {
		if self.is_owned && !self.inner.is_null() {
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
#[no_mangle]
pub extern "C" fn ChainWatchedUtil_free(this_ptr: ChainWatchedUtil) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn ChainWatchedUtil_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeChainWatchedUtil); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl ChainWatchedUtil {
	pub(crate) fn take_ptr(mut self) -> *mut nativeChainWatchedUtil {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}
/// Constructs an empty (watches nothing) ChainWatchedUtil
#[must_use]
#[no_mangle]
pub extern "C" fn ChainWatchedUtil_new() -> ChainWatchedUtil {
	let mut ret = lightning::chain::chaininterface::ChainWatchedUtil::new();
	ChainWatchedUtil { inner: Box::into_raw(Box::new(ret)), is_owned: true }
}

/// Registers a tx for monitoring, returning true if it was a new tx and false if we'd already
/// been watching for it.
#[must_use]
#[no_mangle]
pub extern "C" fn ChainWatchedUtil_register_tx(this_arg: &mut ChainWatchedUtil, txid: *const [u8; 32], script_pub_key: crate::c_types::u8slice) -> bool {
	let mut ret = unsafe { &mut (*(this_arg.inner as *mut nativeChainWatchedUtil)) }.register_tx(&::bitcoin::hash_types::Txid::from_slice(&unsafe { &*txid }[..]).unwrap(), &::bitcoin::blockdata::script::Script::from(Vec::from(script_pub_key.to_slice())));
	ret
}

/// Registers an outpoint for monitoring, returning true if it was a new outpoint and false if
/// we'd already been watching for it
#[must_use]
#[no_mangle]
pub extern "C" fn ChainWatchedUtil_register_outpoint(this_arg: &mut ChainWatchedUtil, mut outpoint: crate::c_types::derived::C2Tuple_Txidu32Z, _script_pub_key: crate::c_types::u8slice) -> bool {
	let (mut orig_outpoint_0, mut orig_outpoint_1) = outpoint.to_rust(); let mut local_outpoint = (::bitcoin::hash_types::Txid::from_slice(&orig_outpoint_0.data[..]).unwrap(), orig_outpoint_1);
	let mut ret = unsafe { &mut (*(this_arg.inner as *mut nativeChainWatchedUtil)) }.register_outpoint(local_outpoint, &::bitcoin::blockdata::script::Script::from(Vec::from(_script_pub_key.to_slice())));
	ret
}

/// Sets us to match all transactions, returning true if this is a new setting and false if
/// we'd already been set to match everything.
#[must_use]
#[no_mangle]
pub extern "C" fn ChainWatchedUtil_watch_all(this_arg: &mut ChainWatchedUtil) -> bool {
	let mut ret = unsafe { &mut (*(this_arg.inner as *mut nativeChainWatchedUtil)) }.watch_all();
	ret
}

/// Checks if a given transaction matches the current filter.
#[must_use]
#[no_mangle]
pub extern "C" fn ChainWatchedUtil_does_match_tx(this_arg: &ChainWatchedUtil, tx: crate::c_types::Transaction) -> bool {
	let mut ret = unsafe { &*this_arg.inner }.does_match_tx(&tx.into_bitcoin());
	ret
}


use lightning::chain::chaininterface::BlockNotifier as nativeBlockNotifierImport;
type nativeBlockNotifier = nativeBlockNotifierImport<'static, crate::chain::chaininterface::ChainListener, crate::chain::chaininterface::ChainWatchInterface>;

/// Utility for notifying listeners about new blocks, and handling block rescans if new watch
/// data is registered.
///
/// Rather than using a plain BlockNotifier, it is preferable to use either a BlockNotifierArc
/// or a BlockNotifierRef for conciseness. See their documentation for more details, but essentially
/// you should default to using a BlockNotifierRef, and use a BlockNotifierArc instead when you
/// require ChainListeners with static lifetimes, such as when you're using lightning-net-tokio.
#[must_use]
#[repr(C)]
pub struct BlockNotifier {
	/// Nearly everyhwere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeBlockNotifier,
	pub is_owned: bool,
}

impl Drop for BlockNotifier {
	fn drop(&mut self) {
		if self.is_owned && !self.inner.is_null() {
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
#[no_mangle]
pub extern "C" fn BlockNotifier_free(this_ptr: BlockNotifier) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn BlockNotifier_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeBlockNotifier); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl BlockNotifier {
	pub(crate) fn take_ptr(mut self) -> *mut nativeBlockNotifier {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}
/// Constructs a new BlockNotifier without any listeners.
#[must_use]
#[no_mangle]
pub extern "C" fn BlockNotifier_new(mut chain_monitor: crate::chain::chaininterface::ChainWatchInterface) -> crate::chain::chaininterface::BlockNotifier {
	let mut ret = lightning::chain::chaininterface::BlockNotifier::new(chain_monitor);
	crate::chain::chaininterface::BlockNotifier { inner: Box::into_raw(Box::new(ret)), is_owned: true }
}

/// Register the given listener to receive events.
#[no_mangle]
pub extern "C" fn BlockNotifier_register_listener(this_arg: &BlockNotifier, mut listener: crate::chain::chaininterface::ChainListener) {
	unsafe { &*this_arg.inner }.register_listener(listener)
}

/// Notify listeners that a block was connected given a full, unfiltered block.
///
/// Handles re-scanning the block and calling block_connected again if listeners register new
/// watch data during the callbacks for you (see ChainListener::block_connected for more info).
#[no_mangle]
pub extern "C" fn BlockNotifier_block_connected(this_arg: &BlockNotifier, block: crate::c_types::u8slice, mut height: u32) {
	unsafe { &*this_arg.inner }.block_connected(&::bitcoin::consensus::encode::deserialize(block.to_slice()).unwrap(), height)
}

/// Notify listeners that a block was connected, given pre-filtered list of transactions in the
/// block which matched the filter (probably using does_match_tx).
///
/// Returns true if notified listeners registered additional watch data (implying that the
/// block must be re-scanned and this function called again prior to further block_connected
/// calls, see ChainListener::block_connected for more info).
#[must_use]
#[no_mangle]
pub extern "C" fn BlockNotifier_block_connected_checked(this_arg: &BlockNotifier, header: *const [u8; 80], mut height: u32, mut txn_matched: crate::c_types::derived::CVec_TransactionZ, mut indexes_of_txn_matched: crate::c_types::usizeslice) -> bool {
	let mut local_txn_matched = Vec::new(); for mut item in txn_matched.into_rust().drain(..) { local_txn_matched.push( { ::bitcoin::consensus::encode::deserialize(&item.into_rust()[..]).unwrap() }); };
	let mut ret = unsafe { &*this_arg.inner }.block_connected_checked(&::bitcoin::consensus::encode::deserialize(unsafe { &*header }).unwrap(), height, &local_txn_matched.iter().collect::<Vec<_>>()[..], indexes_of_txn_matched.to_slice());
	ret
}

/// Notify listeners that a block was disconnected.
#[no_mangle]
pub extern "C" fn BlockNotifier_block_disconnected(this_arg: &BlockNotifier, header: *const [u8; 80], mut disconnected_height: u32) {
	unsafe { &*this_arg.inner }.block_disconnected(&::bitcoin::consensus::encode::deserialize(unsafe { &*header }).unwrap(), disconnected_height)
}


use lightning::chain::chaininterface::ChainWatchInterfaceUtil as nativeChainWatchInterfaceUtilImport;
type nativeChainWatchInterfaceUtil = nativeChainWatchInterfaceUtilImport;

/// Utility to capture some common parts of ChainWatchInterface implementors.
///
/// Keeping a local copy of this in a ChainWatchInterface implementor is likely useful.
#[must_use]
#[repr(C)]
pub struct ChainWatchInterfaceUtil {
	/// Nearly everyhwere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeChainWatchInterfaceUtil,
	pub is_owned: bool,
}

impl Drop for ChainWatchInterfaceUtil {
	fn drop(&mut self) {
		if self.is_owned && !self.inner.is_null() {
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
#[no_mangle]
pub extern "C" fn ChainWatchInterfaceUtil_free(this_ptr: ChainWatchInterfaceUtil) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn ChainWatchInterfaceUtil_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeChainWatchInterfaceUtil); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl ChainWatchInterfaceUtil {
	pub(crate) fn take_ptr(mut self) -> *mut nativeChainWatchInterfaceUtil {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}
#[no_mangle]
pub extern "C" fn ChainWatchInterfaceUtil_as_ChainWatchInterface(this_arg: *const ChainWatchInterfaceUtil) -> crate::chain::chaininterface::ChainWatchInterface {
	crate::chain::chaininterface::ChainWatchInterface {
		this_arg: unsafe { (*this_arg).inner as *mut c_void },
		free: None,
		install_watch_tx: ChainWatchInterfaceUtil_ChainWatchInterface_install_watch_tx,
		install_watch_outpoint: ChainWatchInterfaceUtil_ChainWatchInterface_install_watch_outpoint,
		watch_all_txn: ChainWatchInterfaceUtil_ChainWatchInterface_watch_all_txn,
		get_chain_utxo: ChainWatchInterfaceUtil_ChainWatchInterface_get_chain_utxo,
		filter_block: ChainWatchInterfaceUtil_ChainWatchInterface_filter_block,
		reentered: ChainWatchInterfaceUtil_ChainWatchInterface_reentered,
	}
}
use lightning::chain::chaininterface::ChainWatchInterface as ChainWatchInterfaceTraitImport;
extern "C" fn ChainWatchInterfaceUtil_ChainWatchInterface_install_watch_tx(this_arg: *const c_void, txid: *const [u8; 32], script_pub_key: crate::c_types::u8slice) {
	unsafe { &mut *(this_arg as *mut nativeChainWatchInterfaceUtil) }.install_watch_tx(&::bitcoin::hash_types::Txid::from_slice(&unsafe { &*txid }[..]).unwrap(), &::bitcoin::blockdata::script::Script::from(Vec::from(script_pub_key.to_slice())))
}
extern "C" fn ChainWatchInterfaceUtil_ChainWatchInterface_install_watch_outpoint(this_arg: *const c_void, mut outpoint: crate::c_types::derived::C2Tuple_Txidu32Z, out_script: crate::c_types::u8slice) {
	let (mut orig_outpoint_0, mut orig_outpoint_1) = outpoint.to_rust(); let mut local_outpoint = (::bitcoin::hash_types::Txid::from_slice(&orig_outpoint_0.data[..]).unwrap(), orig_outpoint_1);
	unsafe { &mut *(this_arg as *mut nativeChainWatchInterfaceUtil) }.install_watch_outpoint(local_outpoint, &::bitcoin::blockdata::script::Script::from(Vec::from(out_script.to_slice())))
}
extern "C" fn ChainWatchInterfaceUtil_ChainWatchInterface_watch_all_txn(this_arg: *const c_void) {
	unsafe { &mut *(this_arg as *mut nativeChainWatchInterfaceUtil) }.watch_all_txn()
}
#[must_use]
extern "C" fn ChainWatchInterfaceUtil_ChainWatchInterface_get_chain_utxo(this_arg: *const c_void, mut genesis_hash: crate::c_types::ThirtyTwoBytes, mut _unspent_tx_output_identifier: u64) -> crate::c_types::derived::CResult_C2Tuple_Scriptu64ZChainErrorZ {
	let mut ret = unsafe { &mut *(this_arg as *mut nativeChainWatchInterfaceUtil) }.get_chain_utxo(::bitcoin::hash_types::BlockHash::from_slice(&genesis_hash.data[..]).unwrap(), _unspent_tx_output_identifier);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { let (mut orig_ret_0_0, mut orig_ret_0_1) = o; let mut local_ret_0 = (orig_ret_0_0.into_bytes().into(), orig_ret_0_1).into(); local_ret_0 }), Err(mut e) => crate::c_types::CResultTempl::err( { crate::chain::chaininterface::ChainError::native_into(e) }) };
	local_ret
}
#[must_use]
extern "C" fn ChainWatchInterfaceUtil_ChainWatchInterface_filter_block(this_arg: *const c_void, block: crate::c_types::u8slice) -> crate::c_types::derived::CVec_usizeZ {
	let mut ret = unsafe { &mut *(this_arg as *mut nativeChainWatchInterfaceUtil) }.filter_block(&::bitcoin::consensus::encode::deserialize(block.to_slice()).unwrap());
	let mut local_ret = Vec::new(); for item in ret.drain(..) { local_ret.push( { item }); };
	local_ret.into()
}
#[must_use]
extern "C" fn ChainWatchInterfaceUtil_ChainWatchInterface_reentered(this_arg: *const c_void) -> usize {
	let mut ret = unsafe { &mut *(this_arg as *mut nativeChainWatchInterfaceUtil) }.reentered();
	ret
}

/// Creates a new ChainWatchInterfaceUtil for the given network
#[must_use]
#[no_mangle]
pub extern "C" fn ChainWatchInterfaceUtil_new(mut network: crate::bitcoin::network::Network) -> crate::chain::chaininterface::ChainWatchInterfaceUtil {
	let mut ret = lightning::chain::chaininterface::ChainWatchInterfaceUtil::new(network.into_bitcoin());
	crate::chain::chaininterface::ChainWatchInterfaceUtil { inner: Box::into_raw(Box::new(ret)), is_owned: true }
}

/// Checks if a given transaction matches the current filter.
#[must_use]
#[no_mangle]
pub extern "C" fn ChainWatchInterfaceUtil_does_match_tx(this_arg: &ChainWatchInterfaceUtil, tx: crate::c_types::Transaction) -> bool {
	let mut ret = unsafe { &*this_arg.inner }.does_match_tx(&tx.into_bitcoin());
	ret
}

