use crate::{
    error::FFIResult,
    handle::{Out, Ref, HandleShared},
    adaptors::{
        FFIBroadCaster,
        FFIFeeEstimator,
        FFILogger,
        FFIChainWatchInterface,
        chain_watch_interface_fn,
        ffilogger_fn,
        broadcaster_fn,
        fee_estimator_fn
    }
};
use lightning::{
    ln::channelmonitor::SimpleManyChannelMonitor,
    chain::{
        transaction::OutPoint,
        keysinterface::InMemoryChannelKeys
    }
};
use std::sync::Arc;
use crate::adaptors::primitives::{FFIOutPoint, Bytes33};

pub type FFIManyChannelMonitor = SimpleManyChannelMonitor<OutPoint, InMemoryChannelKeys, Arc<FFIBroadCaster>, Arc<FFIFeeEstimator>, Arc<FFILogger>, Arc<FFIChainWatchInterface>>;
pub type FFIManyChannelMonitorHandle<'a> = HandleShared<'a, FFIManyChannelMonitor>;


fn add_monitor_by_key(outpoint: FFIOutPoint, handle: FFIManyChannelMonitorHandle) -> FFIResult {
    unimplemented!()
}

ffi! {
    fn create_many_channel_monitor(
        install_watch_tx_ptr: Ref<chain_watch_interface_fn::InstallWatchTxPtr>,
        install_watch_outpoint_ptr: Ref<chain_watch_interface_fn::InstallWatchOutpointPtr>,
        watch_all_txn_ptr: Ref<chain_watch_interface_fn::WatchAllTxnPtr>,
        get_chain_utxo_ptr: Ref<chain_watch_interface_fn::GetChainUtxoPtr>,
        filter_block_ptr: Ref<chain_watch_interface_fn::FilterBlock>,
        reentered_ptr: Ref<chain_watch_interface_fn::ReEntered>,

        broadcast_transaction_ptr: Ref<broadcaster_fn::BroadcastTransactionPtr>,
        log_ptr: Ref<ffilogger_fn::LogExtern>,
        get_est_sat_per_1000_weight_ptr: Ref<fee_estimator_fn::GetEstSatPer1000WeightPtr>,
        handle: Out<FFIManyChannelMonitorHandle>) -> FFIResult {
        let install_watch_tx = unsafe_block!("function pointer lives as long as ChainWatchInterface and it points to valid data"  => install_watch_tx_ptr.as_ref());
        let install_watch_outpoint = unsafe_block!("function pointer lives as long as ChainWatchInterface and it points to valid data"  => install_watch_outpoint_ptr.as_ref());
        let watch_all_txn = unsafe_block!("function pointer lives as long as ChainWatchInterface and it points to valid data"  => watch_all_txn_ptr.as_ref());
        let get_chain_utxo = unsafe_block!("function pointer lives as long as ChainWatchInterface and it points to valid data"  => get_chain_utxo_ptr.as_ref());
        let filter_block = unsafe_block!("function pointer lives as long as ChainWatchInterface and it points to valid data"  => filter_block_ptr.as_ref());
        let reentered = unsafe_block!("function pointer lives as long as ChainWatchInterface and it points to valid data"  => reentered_ptr.as_ref());
        let chain_watch_interface =
            Arc::new(FFIChainWatchInterface::new(
                *install_watch_tx,
                *install_watch_outpoint,
                *watch_all_txn,
                *get_chain_utxo,
                *filter_block,
                *reentered,
            ));

        let log_ref = unsafe_block!("" => log_ptr.as_ref());
        let logger = Arc::new( FFILogger{ log_ptr: *log_ref } );

        let broadcast_ref = unsafe_block!("" => broadcast_transaction_ptr.as_ref());
        let tx_broadcaster = Arc::new(FFIBroadCaster { broadcast_transaction_ptr: *broadcast_ref });

        let fee_est_fn_ref = unsafe_block!("" => get_est_sat_per_1000_weight_ptr.as_ref());
        let fee_estimator = Arc::new(FFIFeeEstimator{ get_est_sat_per_1000_weight_ptr: *fee_est_fn_ref });

        let many_channel_monitor = SimpleManyChannelMonitor::new(chain_watch_interface, tx_broadcaster, logger, fee_estimator);
        unsafe_block!("We know the handle is not null by wrapper macro. And we know `Out` is writable" => handle.init(HandleShared::alloc(many_channel_monitor)));
        FFIResult::ok()
    }

    fn block_connected(
        block_ptr: Ref<u8>,
        block_len: usize,
        height: u32,
        handle: FFIManyChannelMonitorHandle
    ) -> FFIResult {
        let many_channel_monitor: &FFIManyChannelMonitor = handle.as_ref();
        let block_bytes = unsafe_block!("block_ptr points to valid buffer of block_len length" => block_ptr.as_bytes(block_len));
        let block = bitcoin::consensus::deserialize(block_bytes)?;
        many_channel_monitor.block_connected(&block, height);
        FFIResult::ok()
    }

    fn block_disconnected(
        block_header_ptr: Ref<u8>,
        block_header_len: usize,
        height: u32,
        handle: FFIBlockNotifierHandle
    ) -> FFIResult {
        let many_channel_monitor: &FFIManyChannelMonitor = handle.as_ref();
        let block_header_bytes: &[u8] = unsafe_block!("We know it points to valid buffer of specified length" => block_header_ptr.as_bytes(block_header_len));
        let block_header: BlockHeader = bitcoin::consensus::encode::deserialize(block_header_bytes)?;
        many_channel_monitor.block_disconnected(&block_header, height);
        FFIResult::ok()
    }


    fn release_many_channel_monitor(handle: FFIManyChannelMonitorHandle) -> FFIResult {
        unsafe_block!("The upstream caller guarantees the handle will not be accessed after being freed" => FFIManyChannelMonitorHandle::dealloc(handle, |mut _handle| {
            FFIResult::ok()
        }))
    }
}