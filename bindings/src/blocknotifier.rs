use std::sync::Arc;
use lightning::chain::chaininterface::{BlockNotifier, ChainListener};
use crate::{
    HandleShared,
    FFIResult,
    Ref,
    Out,
    channelmanager::{FFIArcChannelManagerHandle, FFIArcChannelManager},
    adaptors::{chain_watch_interface_fn, FFIChainWatchInterface}
};
use bitcoin::BlockHeader;

type FFIBlockNotifier = BlockNotifier<'static, Arc<dyn ChainListener>, Arc<FFIChainWatchInterface>>;
type FFIBlockNotifierHandle<'a> = HandleShared<'a, FFIBlockNotifier>;

ffi! {

    fn create_block_notifier(
        install_watch_tx_ptr: Ref<chain_watch_interface_fn::InstallWatchTxPtr>,
        install_watch_outpoint_ptr: Ref<chain_watch_interface_fn::InstallWatchOutpointPtr>,
        watch_all_txn_ptr: Ref<chain_watch_interface_fn::WatchAllTxnPtr>,
        get_chain_utxo_ptr: Ref<chain_watch_interface_fn::GetChainUtxoPtr>,
        filter_block_ptr: Ref<chain_watch_interface_fn::FilterBlock>,
        reentered_ptr: Ref<chain_watch_interface_fn::ReEntered>,

        handle: Out<FFIBlockNotifierHandle>
    ) -> FFIResult {

        let install_watch_tx_ref = unsafe_block!("function pointer lives as long as ChainWatchInterface and it points to valid data"  => install_watch_tx_ptr.as_ref());
        let install_watch_outpoint_ref = unsafe_block!("function pointer lives as long as ChainWatchInterface and it points to valid data"  => install_watch_outpoint_ptr.as_ref());
        let watch_all_txn_ref = unsafe_block!("function pointer lives as long as ChainWatchInterface and it points to valid data"  => watch_all_txn_ptr.as_ref());
        let get_chain_utxo_ref = unsafe_block!("function pointer lives as long as ChainWatchInterface and it points to valid data"  => get_chain_utxo_ptr.as_ref());
        let filter_block_ref = unsafe_block!("function pointer lives as long as ChainWatchInterface and it points to valid data"  => filter_block_ptr.as_ref());
        let reentered_ref = unsafe_block!("function pointer lives as long as ChainWatchInterface and it points to valid data"  => reentered_ptr.as_ref());

        let chain_watch_interface_arc =
            Arc::new(FFIChainWatchInterface::new(
                *install_watch_tx_ref,
                *install_watch_outpoint_ref,
                *watch_all_txn_ref,
                *get_chain_utxo_ref,
                *filter_block_ref,
                *reentered_ref,
            ));
        let block_notifier = FFIBlockNotifier::new(chain_watch_interface_arc);
        unsafe_block!("We know handle is not null by wrapper macro. And we know `Out` is writable" => handle.init(HandleShared::alloc(block_notifier)));
        FFIResult::ok()
    }

    fn register_channel_manager(
        channel_manager: FFIArcChannelManagerHandle,
        handle: FFIBlockNotifierHandle
    ) -> FFIResult {
        let chan_man: Arc<FFIArcChannelManager> = unsafe_block!("We know the handle points to valid channel_manager" => channel_manager.as_arc());
        let block_notifier: &FFIBlockNotifier = handle.as_ref();
        block_notifier.register_listener(chan_man);
        FFIResult::ok()
    }

    fn unregister_channel_manager(
        channel_manager: FFIArcChannelManagerHandle,
        handle: FFIBlockNotifierHandle
    ) -> FFIResult {
        let chan_man: Arc<FFIArcChannelManager> = unsafe_block!("We know the handle points to valid channel_manager" => channel_manager.as_arc());
        let block_notifier: &FFIBlockNotifier = handle.as_ref();
        block_notifier.unregister_listener(chan_man);
        FFIResult::ok()
    }

    fn block_connected(
        block_ptr: Ref<u8>,
        block_len: usize,
        height: u32,
        handle: FFIBlockNotifierHandle) -> FFIResult {
        let block_notifier: &FFIBlockNotifier = handle.as_ref();
        let block_bytes = unsafe_block!("block_ptr points to valid buffer of block_len length" => block_ptr.as_bytes(block_len));
        let block = bitcoin::consensus::deserialize(block_bytes)?;
        block_notifier.block_connected(&block, height);
        FFIResult::ok()
    }

    fn block_disconnected(
        block_header_ptr: Ref<u8>,
        block_header_len: usize,
        height: u32,
        handle: FFIBlockNotifierHandle
    ) -> FFIResult {
        let block_notifier: &FFIBlockNotifier = handle.as_ref();

        let block_header_bytes: &[u8] = unsafe_block!("We know it points to valid buffer of specified length" => block_header_ptr.as_bytes(block_header_len));
        let block_header: BlockHeader = bitcoin::consensus::encode::deserialize(block_header_bytes)?;
        block_notifier.block_disconnected(&block_header, height);
        FFIResult::ok()
    }

    fn release_block_notifier(handle: FFIBlockNotifierHandle) -> FFIResult {
        unsafe_block!("The upstream caller guarantees the handle will not be accessed after being freed" => FFIBlockNotifierHandle::dealloc(handle, |mut handle| {
            // We keep reference to listeners from wrapper side (as a `SafeHandle`
            // to a `ChannelManager`) so that we can call methods
            // on it. So disposing it is their job. Not ours.
            std::mem::forget(handle.listeners);
            FFIResult::ok()
        }))
    }
}