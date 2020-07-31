use std::sync::Arc;

use bitcoin::hash_types::{BlockHash};

use lightning::{
    ln::channelmonitor::SimpleManyChannelMonitor,
    chain::{
        transaction::OutPoint,
        keysinterface::InMemoryChannelKeys
    },
    ln::channelmonitor::SimpleManyChannelMonitorReadArgs,
    util::ser::ReadableArgs
};

use crate::{
    error::FFIResult,
    handle::{Out, Ref, RefMut, HandleShared},
    adaptors::{
        FFIBroadCaster,
        FFIFeeEstimator,
        FFILogger,
        FFIChainWatchInterface,
        chain_watch_interface_fn,
        ffilogger_fn,
        broadcaster_fn,
        fee_estimator_fn
    },
    utils::into_fixed_buffer,
    adaptors::primitives::{FFIOutPoint}
};
use bitcoin::Block;

pub type FFIManyChannelMonitor = SimpleManyChannelMonitor<OutPoint, InMemoryChannelKeys, Arc<FFIBroadCaster>, Arc<FFIFeeEstimator>, Arc<FFILogger>, Arc<FFIChainWatchInterface>>;
pub type FFIManyChannelMonitorHandle = HandleShared<'static, FFIManyChannelMonitor>;

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

    fn serialize_many_channel_monitor(buf_out: Out<u8>, buf_len: usize, actual_len: Out<usize>, handle: FFIManyChannelMonitorHandle) -> FFIResult {
        let buf = unsafe_block!("The buffer lives as long as this function, the length is within the buffer and the buffer won't be read before initialization" => buf_out.as_uninit_bytes_mut(buf_len));
        let mut chan_mon = handle.as_ref();
        into_fixed_buffer(&mut chan_mon, buf, &mut actual_len)
    }

    fn deserialize_many_channel_monitor(input_buf_ptr: RefMut<u8>,
                                        input_buf_len: usize,
                                        install_watch_tx_ptr: Ref<chain_watch_interface_fn::InstallWatchTxPtr>,
                                        install_watch_outpoint_ptr: Ref<chain_watch_interface_fn::InstallWatchOutpointPtr>,
                                        watch_all_txn_ptr: Ref<chain_watch_interface_fn::WatchAllTxnPtr>,
                                        get_chain_utxo_ptr: Ref<chain_watch_interface_fn::GetChainUtxoPtr>,
                                        filter_block_ptr: Ref<chain_watch_interface_fn::FilterBlock>,
                                        reentered_ptr: Ref<chain_watch_interface_fn::ReEntered>,

                                        broadcast_transaction_ptr: Ref<broadcaster_fn::BroadcastTransactionPtr>,
                                        log_ptr: Ref<ffilogger_fn::LogExtern>,
                                        get_est_sat_per_1000_weight_ptr: Ref<fee_estimator_fn::GetEstSatPer1000WeightPtr>,

                                        output_buf_ptr: Out<u8>,
                                        output_buf_len: usize,
                                        output_actual_len: Out<usize>,

                                        handle: Out<FFIManyChannelMonitorHandle>) -> FFIResult
    {
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

        let broadcast_ref = unsafe_block!("" => broadcast_transaction_ptr.as_ref());
        let tx_broadcaster = Arc::new(FFIBroadCaster { broadcast_transaction_ptr: *broadcast_ref });

        let fee_est_fn_ref = unsafe_block!("" => get_est_sat_per_1000_weight_ptr.as_ref());
        let fee_estimator = Arc::new(FFIFeeEstimator{ get_est_sat_per_1000_weight_ptr: *fee_est_fn_ref });

        let log_ref = unsafe_block!("" => log_ptr.as_ref());
        let logger = Arc::new( FFILogger{ log_ptr: *log_ref } );

        let read_args = SimpleManyChannelMonitorReadArgs { fee_estimator, tx_broadcaster, logger, chain_watch_interface };
        let mut buf = unsafe_block!("The buffer lives as long as this function, the length is within the buffer and the buffer won't be read before initialization" => input_buf_ptr.as_bytes_mut(input_buf_len));
        let (hashes, many_channel_monitor): (Vec<(OutPoint, BlockHash)>, FFIManyChannelMonitor) = ReadableArgs::read(&mut ::std::io::Cursor::new(buf), read_args).unwrap();

        let output_buf = unsafe_block!("" => output_buf_ptr.as_uninit_bytes_mut(output_buf_len));
        into_fixed_buffer(&hashes, output_buf, &mut output_actual_len)?;
        unsafe_block!("We know the handle is not null by wrapper macro. And we know `Out` is writable" => handle.init(HandleShared::alloc(many_channel_monitor)));
        FFIResult::ok()
    }

    fn tell_block_connected_after_resume(
        block_ref: Ref<Block>,
        height: u32,
        key_ref: Ref<FFIOutPoint>,
        handle: FFIManyChannelMonitorHandle
    ) -> FFIResult {
        let block: &Block = unsafe_block!("" => block_ref.as_ref());
        let key: OutPoint = unsafe_block!("" => key_ref.as_ref()).clone().into();
        let chan_mon = handle.as_ref();
        chan_mon.tell_block_connected_after_resume(block, height, key)?;
        FFIResult::ok()
    }


    fn release_many_channel_monitor(handle: FFIManyChannelMonitorHandle) -> FFIResult {
        unsafe_block!("The upstream caller guarantees the handle will not be accessed after being freed" => FFIManyChannelMonitorHandle::dealloc(handle, |mut _handle| {
            FFIResult::ok()
        }))
    }
}