use std::{
    io::Error,
    ffi::{CString},
    hash::{Hasher, Hash},
    ffi::CStr,
    ptr::NonNull
};

use bitcoin::hash_types::{BlockHash, Txid};
use bitcoin::{blockdata::transaction::Transaction, blockdata::script::Script, blockdata::block::Block, consensus::serialize as bitcoin_serialize, Network};
use bitcoin::secp256k1;

use lightning::{
    chain::chaininterface::{BroadcasterInterface, FeeEstimator, ConfirmationTarget, ChainWatchInterface, ChainError},
    util::logger::{Logger, Record, Level},
    util::ser::{Writer},
    ln::peer_handler::SocketDescriptor,
    ln::msgs::ErrorAction,
    chain::chaininterface::ChainWatchInterfaceUtil,
    ln::msgs::{ErrorMessage, RoutingMessageHandler, HTLCFailChannelUpdate, ChannelAnnouncement, NodeAnnouncement, LightningError, ChannelUpdate}
};

pub mod primitives;
use primitives::*;
use std::sync::Arc;

type Cstr = NonNull<i8>;

#[derive(PartialOrd, PartialEq, Eq, Ord, Debug, Copy, Clone)]
#[repr(u8)]
pub enum Bool { False = 0, True = 1 }
impl Bool {
    pub fn to_bool(&self) -> bool { *self == Bool::True }
}

impl From<bool> for Bool {
    fn from(v: bool) -> Self {
        if v { Bool::True } else { Bool::False }
    }
}

pub mod broadcaster_fn {
    use crate::adaptors::primitives::FFITransaction;
    pub type BroadcastTransactionPtr = extern "cdecl" fn(tx: *const FFITransaction);
}

#[repr(C)]
pub struct FFIBroadCaster {
  pub broadcast_transaction_ptr: broadcaster_fn::BroadcastTransactionPtr,
}

// these are necessary for `SimpleChannelManager` to have `ManyChannelMonitor` impl.
// TODO: we may need to use AtomicPtr type for inner func
unsafe_impl!("We don't mutate inner function pointer during execution" => impl Send for FFIBroadCaster {});
unsafe_impl!("We don't mutate inner function pointer during execution" => impl Sync for FFIBroadCaster {});

impl BroadcasterInterface for FFIBroadCaster {
    fn broadcast_transaction(&self, tx: &Transaction) {
        let v = bitcoin_serialize(tx);
        let ffi_tx = FFITransaction::from(v.as_slice());
        (self.broadcast_transaction_ptr)(&ffi_tx as *const FFITransaction)
    }
}

#[repr(C)]
pub enum FFIConfirmationTarget {
	/// We are happy with this transaction confirming slowly when feerate drops some.
	Background,
	/// We'd like this transaction to confirm without major delay, but 12-18 blocks is fine.
	Normal,
	/// We'd like this transaction to confirm in the next few blocks.
	HighPriority,
}

impl From<ConfirmationTarget> for FFIConfirmationTarget {
    fn from(target: ConfirmationTarget) -> FFIConfirmationTarget {
        match target {
            ConfirmationTarget::Background => FFIConfirmationTarget::Background,
            ConfirmationTarget::Normal => FFIConfirmationTarget::Normal,
            ConfirmationTarget::HighPriority => FFIConfirmationTarget::HighPriority,
        }
    }
}

pub mod fee_estimator_fn {
    use super::{FFIConfirmationTarget};
    pub type GetEstSatPer1000WeightPtr = extern "cdecl" fn (FFIConfirmationTarget) -> u32;
}

#[repr(C)]
#[derive(Clone)]
pub struct FFIFeeEstimator {
    pub get_est_sat_per_1000_weight_ptr: fee_estimator_fn::GetEstSatPer1000WeightPtr,
}

impl FeeEstimator for FFIFeeEstimator {
	fn get_est_sat_per_1000_weight(&self, confirmation_target: ConfirmationTarget) -> u32 {
        (self.get_est_sat_per_1000_weight_ptr)(confirmation_target.into())
    }
}
unsafe_impl!("We don't mutate inner function pointer during execution" => impl Send for FFIFeeEstimator {});
unsafe_impl!("We don't mutate inner function pointer during execution" => impl Sync for FFIFeeEstimator {});

#[repr(C)]
#[derive(Clone, Copy)]
pub enum FFINetwork {
    MainNet = 0,
    TestNet = 1,
    RegTest = 2,
}

impl FFINetwork {
    pub fn to_network(&self) -> bitcoin::network::constants::Network {
        match self {
            FFINetwork::MainNet => { bitcoin::network::constants::Network::Bitcoin },
            FFINetwork::TestNet => { bitcoin::network::constants::Network::Testnet },
            FFINetwork::RegTest => { bitcoin::network::constants::Network::Regtest },
        }
    }
}

#[derive(Debug)]
#[repr(C)]
pub enum FFILogLevel {
	///Designates logger being silent
	Off,
	/// Designates very serious errors
	Error,
	/// Designates hazardous situations
	Warn,
	/// Designates useful information
	Info,
	/// Designates lower priority information
	Debug,
	/// Designates very low priority, often extremely verbose, information
	Trace,
}

impl From<Level> for FFILogLevel {
    fn from(level: Level) -> FFILogLevel {
        match level {
            Level::Off => FFILogLevel::Off,
            Level::Error => FFILogLevel::Error,
            Level::Warn => FFILogLevel::Warn,
            Level::Info => FFILogLevel::Info,
            Level::Debug => FFILogLevel::Debug,
            Level::Trace => FFILogLevel::Trace
        }
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct FFILogRecord {
	/// The verbosity level of the message.
	pub level: FFILogLevel,
	/// The message body.
	pub args: Cstr,
	/// The module path of the message.
	pub module_path: Cstr,
	/// The source file containing the message.
	pub file: Cstr,
	/// The line containing the message.
	pub line: u32,
}

pub mod ffilogger_fn {
    use super::{FFILogRecord};
    pub type LogExtern = extern "cdecl" fn(record: *const FFILogRecord);
}

#[repr(C)]
pub struct FFILogger {
    pub log_ptr: ffilogger_fn::LogExtern,
}

impl Logger for FFILogger {
	fn log(&self, rec: &Record) {
        let args = CString::new(std::fmt::format(rec.args)).unwrap_or(CString::new("Record.args contains null char in the middle").unwrap());
        let module_path = CString::new(rec.module_path).unwrap_or(CString::new("Record.module_path contains null char in the middle").unwrap());
        let file = CString::new(rec.file).unwrap_or(CString::new("Record.file contains null char in the middle").unwrap());
        let ffi_record =
            FFILogRecord {
                level: rec.level.into(),
                args: NonNull::new(args.as_ptr() as *mut _).unwrap(),
                module_path: NonNull::new(module_path.as_ptr() as *mut _).unwrap(),
                file: NonNull::new(file.as_ptr() as *mut _).unwrap(),
                line: rec.line,
            };
        (self.log_ptr)(&ffi_record as *const _);
    }
}

pub mod chain_watch_interface_fn {
    use super::*;
    pub type InstallWatchTxPtr = extern "cdecl" fn(*const Bytes32, script_pub_key: *const FFIScript);
    pub type InstallWatchOutpointPtr = extern "cdecl" fn(outpoint: *const FFIOutPoint, out_script: *const FFIScript);
    pub type WatchAllTxnPtr = extern "cdecl" fn();
    pub type GetChainUtxoPtr = extern "cdecl" fn(genesis_hash: *const Bytes32, unspent_tx_output_identifier: u64, err: *mut FFIChainError, script_ptr: *mut u8, script_len: *mut usize, amount_satoshis: *mut u64);
    pub type FilterBlock = extern "cdecl" fn(block_ptr: *const u8, block_len: usize, matched_index_ptr: *mut usize, matched_inedx_len: *mut usize);
    pub type ReEntered = extern "cdecl" fn() -> usize;
}

#[repr(C)]
pub struct FFIChainWatchInterface {
    pub install_watch_tx_ptr: chain_watch_interface_fn::InstallWatchTxPtr,
    pub install_watch_outpoint_ptr: chain_watch_interface_fn::InstallWatchOutpointPtr,
    pub watch_all_txn_ptr: chain_watch_interface_fn::WatchAllTxnPtr,
    pub get_chain_utxo_ptr: chain_watch_interface_fn::GetChainUtxoPtr,
    pub filter_block_ptr: chain_watch_interface_fn::FilterBlock,
    pub reentered_ptr: chain_watch_interface_fn::ReEntered
}
impl FFIChainWatchInterface {
    pub fn new(
        install_watch_tx: chain_watch_interface_fn::InstallWatchTxPtr,
        install_watch_outpoint: chain_watch_interface_fn::InstallWatchOutpointPtr,
        watch_all_txn: chain_watch_interface_fn::WatchAllTxnPtr,
        get_chain_utxo: chain_watch_interface_fn::GetChainUtxoPtr,
        filter_block: chain_watch_interface_fn::FilterBlock,
        reentered: chain_watch_interface_fn::ReEntered,
        network: Network,
        logger: Arc<dyn Logger>
    ) -> FFIChainWatchInterface {
        FFIChainWatchInterface{
            install_watch_tx_ptr: install_watch_tx,
            install_watch_outpoint_ptr: install_watch_outpoint,
            watch_all_txn_ptr: watch_all_txn,
            get_chain_utxo_ptr: get_chain_utxo,
            filter_block_ptr: filter_block,
            reentered_ptr:reentered
        }
    }
}

impl ChainWatchInterface for FFIChainWatchInterface {
    fn install_watch_tx(&self, txid: &Txid, script_pub_key: &Script) {
        let spk_vec = bitcoin_serialize(script_pub_key);
        let ffi_spk = FFIScript::from(spk_vec.as_slice());
        let txid: Bytes32 = txid.clone().into();
        (self.install_watch_tx_ptr)(&txid as *const _, &ffi_spk as *const _)
    }
    fn install_watch_outpoint(&self, outpoint: (Txid, u32), out_script: &Script) {
        let txid: Bytes32 = outpoint.0.into();
        let ffi_outpoint = FFIOutPoint { txid: txid, index: outpoint.1 as u16 };
        let out_script_vec = bitcoin_serialize(out_script);
        let ffi_outscript = FFIScript::from(out_script_vec.as_slice());
        (self.install_watch_outpoint_ptr)(&ffi_outpoint as *const _, &ffi_outscript as *const _)
    }
    fn watch_all_txn(&self) {
        (self.watch_all_txn_ptr)()
    }
    fn get_chain_utxo(&self, genesis_hash: BlockHash, unspent_tx_output_identifier: u64) -> Result<(Script, u64), ChainError> {
        let err = std::ptr::null_mut();
        // the length can be anything as long as it is enough to put the scriptPubKey.
        // probably this is a bit overkill but who cares.
        let mut script = [0u8; 128];
        let script_len = std::ptr::null_mut();
        let amount_satoshis = std::ptr::null_mut();
        (self.get_chain_utxo_ptr)(&genesis_hash.into(), unspent_tx_output_identifier, err, script.as_mut_ptr(), script_len, amount_satoshis);
        if err.is_null() {
            let script_bytes: &[u8]  = unsafe_block!("We know the caller has set the value into the script_ptr, script_len" => &script[..(*script_len)]);
            let amount: u64 = unsafe_block!("We know the caller has set the value into the amount_satoshis" => *amount_satoshis);
            let s = bitcoin::consensus::deserialize(script_bytes).expect("Failed to parse scriptpubkey");
            Ok((s, amount))
        } else {
            let e = unsafe_block!("we know the error is not a null pointer" => (*err).clone());
            Err(e.into())
        }
    }

    fn filter_block<'a>(&self, block: &'a Block) -> Vec<usize> {
        let block_bytes = bitcoin_serialize(block);
        // the minimum weight for one tx is 440. So the max number of tx in one block is 9090.
        let mut matched_tx_index = [0; 9091];
        let mut matched_tx_index_len_ptr: &mut usize = &mut usize::MAX;
        (self.filter_block_ptr)(block_bytes.as_ptr(), block_bytes.len(), matched_tx_index.as_mut_ptr(), matched_tx_index_len_ptr as *mut _);
        if (matched_tx_index_len_ptr.clone() == usize::MAX) {
            panic!("FFI failure. the caller must set the actual serialized length of the tx-indexes in filter_block");
        }
        let mut matched_tx_indexes: &[usize] = unsafe_block!("We know the caller has set the value for serialized tx index" => &matched_tx_index[..(*matched_tx_index_len_ptr)]);
        matched_tx_indexes.to_vec()
    }

    fn reentered(&self) -> usize {
        (self.reentered_ptr)()
    }
}

pub mod socket_descriptor_fn {
    use super::FFIBytes;
    pub type SendData = extern "cdecl" fn (data: FFIBytes, resume_read: u8) -> usize;
    pub type DisconnectSocket = extern "cdecl" fn ();
}

#[repr(C)]
#[derive(Clone)]
pub struct FFISocketDescriptor {
    pub index: usize,
    pub send_data_ptr: socket_descriptor_fn::SendData,
    pub disconnect_socket_ptr: socket_descriptor_fn::DisconnectSocket,
}

impl PartialEq for FFISocketDescriptor {
    fn eq(&self, other: &Self) -> bool {
        self.index == other.index
    }
}
impl Eq for FFISocketDescriptor {}
impl Hash for FFISocketDescriptor {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.index.hash(state)
    }
}

impl SocketDescriptor for FFISocketDescriptor {
    fn send_data(&mut self, data: &[u8], resume_read: bool) -> usize {
        let r: FFIBytes = data.into();
        (self.send_data_ptr)(r, resume_read as u8)
    }

    fn disconnect_socket(&mut self) {
        (self.disconnect_socket_ptr)()
    }
}

#[repr(u8)]
#[derive(Debug,Clone)]
pub enum FFIErrorActionType {
    DisconnectPeer = 0u8,
    /// The peer did something harmless that we weren't able to process, just log and ignore
    IgnoreError,
    /// The peer did something incorrect. Tell them.
    SendErrorMessage,
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct FFIErrorMsg {
    pub channel_id: [u8; 32],
    pub data: Cstr,
}

impl From<FFIErrorMsg> for ErrorMessage {
    fn from(msg: FFIErrorMsg) -> Self {
        let data = unsafe_block!("We know pointer is non-null" => CStr::from_ptr(msg.data.as_ptr()) );
        ErrorMessage {
            data: data.to_str().unwrap().to_owned(),
            channel_id: msg.channel_id
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct FFIErrorAction {
    ty: FFIErrorActionType,
    payload: Option<*const FFIErrorMsg>
}

impl From<FFIErrorAction> for ErrorAction {
    fn from(x: FFIErrorAction) -> Self {
        match x.ty {
            FFIErrorActionType::DisconnectPeer => {
                ErrorAction::DisconnectPeer {
                    msg: x.payload.map(|msg| {
                        From::from(unsafe_block!("`from` conversion consumes x" => (*msg).clone()))
                    })
                }
            },
            FFIErrorActionType::IgnoreError => {
                ErrorAction::IgnoreError
            },
            FFIErrorActionType::SendErrorMessage => {
                match x.payload {
                    None => panic!(format!("Inconsistent enum {:?}", x)),
                    Some(msg) => {
                        let msg = unsafe_block!("`from` conversion consumes x" => (*msg).clone()).into();
                        ErrorAction::SendErrorMessage { msg }
                    }
                }
            }
        }
    }
}

#[derive(Clone)]
#[repr(C)]
pub struct FFILightningError {
    /// A human-readable message describing the error
    pub err: Cstr,
    /// The action which should be taken against the offending peer.
    pub action: FFIErrorAction,
}

impl From<FFILightningError> for LightningError {
    fn from(v: FFILightningError) -> Self {
        let err = unsafe_block!("We know error msg is non-null c string" => CStr::from_ptr(v.err.as_ptr()) );
        LightningError {
            err: err.to_str().unwrap(),
            action: v.action.into()
        }
    }
}

// --- routing stuff ---
/// TODO: enable to pass routing handler from outside.
pub mod routing_msg_descriptor_fn {
    use super::*;
    use crate::adaptors::primitives::Bytes33;

    /// Handle an incoming node_announcement message, returning true if it should be forwarded on,
    /// false or returning an Err otherwise.
    pub type HandleNodeAnnouncement = extern "cdecl" fn (msg: *const FFIBytes, error: *mut FFILightningError) -> Bool;
    /// Handle a channel_announcement message, returning true if it should be forwarded on, false
    /// or returning an Err otherwise.
    pub type HandleChannelAnnouncement = extern "cdecl" fn (msg: *const FFIBytes, error: *mut FFILightningError) -> Bool;
    /// Handle an incoming channel_update message, returning true if it should be forwarded on,
    /// false or returning an Err otherwise.
    pub type HandleChannelUpdate = extern "cdecl" fn (msg: *const FFIBytes, error: *mut FFILightningError) -> Bool;
    /// Handle some updates to the route graph that we learned due to an outbound failed payment.
    pub type HandleHTLCFailChannelUpdate = extern "cdecl" fn (update: *const FFIBytes);
    /// Gets a subset of the channel announcements and updates required to dump our routing table
    /// to a remote node, starting at the short_channel_id indicated by starting_point and
    /// including the batch_amount entries immediately higher in numerical value than starting_point.
    /// Return type is serialized `Vec<(ChannelAnnouncement, ChannelUpdate, ChannelUpdate)>`
    pub type GetNextChannelAnnouncements = extern "cdecl" fn (starting_point: u64, batch_amount: u8) -> FFIBytes;
    /// Gets a subset of the node announcements required to dump our routing table to a remote node,
    /// starting at the node *after* the provided publickey and including batch_amount entries
    /// immediately higher (as defined by <PublicKey as Ord>::cmp) than starting_point.
    /// If None is provided for starting_point, we start at the first node.
    /// Return type is binary serialized `Vec<NodeAnnouncement>` .
    pub type GetNextNodeAnnouncements = extern "cdecl" fn (starting_point: Option<*const Bytes33>, batch_amount: u8) -> FFIBytes;
    /// Returns whether a full sync should be requested from a peer.
    pub type ShouldRequestFullSync = extern "cdecl" fn (node_id: Bytes33) -> Bool;
}

pub struct FFIRoutingMsgHandler {
    pub handle_node_announcement_ptr: routing_msg_descriptor_fn::HandleNodeAnnouncement,
    pub handle_channel_announcement_ptr: routing_msg_descriptor_fn::HandleChannelAnnouncement,
    pub handle_channel_update_ptr: routing_msg_descriptor_fn::HandleChannelUpdate,
    pub handle_htlc_fail_channel_update_ptr: routing_msg_descriptor_fn::HandleHTLCFailChannelUpdate,
    pub get_next_channel_announcements_ptr: routing_msg_descriptor_fn::GetNextChannelAnnouncements,
    pub get_next_node_announcements_ptr: routing_msg_descriptor_fn::GetNextNodeAnnouncements,
    pub should_request_full_sync_ptr: routing_msg_descriptor_fn::ShouldRequestFullSync
}

pub struct VecWriter(pub Vec<u8>);
impl Writer for VecWriter {
    fn write_all(&mut self, buf: &[u8]) -> Result<(), Error> {
        self.0.extend_from_slice(buf);
        Ok(())
    }

    fn size_hint(&mut self, size: usize) {
        self.0.reserve_exact(size)
    }
}

impl RoutingMessageHandler for FFIRoutingMsgHandler {
    fn handle_node_announcement(&self, msg: &NodeAnnouncement) -> Result<bool, LightningError> {
        unimplemented!()
    }

    fn handle_channel_announcement(&self, msg: &ChannelAnnouncement) -> Result<bool, LightningError> {
        unimplemented!()
    }

    fn handle_channel_update(&self, msg: &ChannelUpdate) -> Result<bool, LightningError> {
        unimplemented!()
    }

    fn handle_htlc_fail_channel_update(&self, update: &HTLCFailChannelUpdate) {
        unimplemented!()
    }

    fn get_next_channel_announcements(&self, starting_point: u64, batch_amount: u8) -> Vec<(ChannelAnnouncement, Option<ChannelUpdate>, Option<ChannelUpdate>)> {
        unimplemented!()
    }

    fn get_next_node_announcements(&self, starting_point: Option<&secp256k1::PublicKey>, batch_amount: u8) -> Vec<NodeAnnouncement> {
        unimplemented!()
    }

    fn should_request_full_sync(&self, node_id: &secp256k1::PublicKey) -> bool {
        unimplemented!()
    }
}
