use std::{
    sync::atomic::{AtomicUsize},
    convert::TryInto,
    sync::Arc,
};

use bitcoin::secp256k1;

use lightning::{
    ln::peer_handler::{PeerManager, MessageHandler},
    routing::network_graph::NetGraphMsgHandler,
    util::config::UserConfig,
    util::ser::Readable
};

use crate::{
    error::FFIResult,
    handle::{Out, Ref, HandleShared},
    adaptors::{
        *,
        primitives::{Bytes32, FFIBytes, Bytes33}
    },
    utils::into_fixed_buffer,
    channelmanager::{
        FFIArcChannelManagerHandle,
        FFIArcChannelManager
    }
};
use lightning::routing::network_graph::NetworkGraph;

type FFISimpleArcPeerManager = PeerManager<FFISocketDescriptor, &'static FFIArcChannelManager, Arc<NetGraphMsgHandler<Arc<FFIChainWatchInterface>, Arc<FFILogger>>>, Arc<FFILogger>>;
type FFIArcPeerManagerHandle = HandleShared<'static, FFISimpleArcPeerManager>;

lazy_static! {
    static ref SOCKET_DESC_INDEX: AtomicUsize = AtomicUsize::new(0);
}

fn construct_socket_desc (
    index: usize,
    send_data_ptr: Ref<socket_descriptor_fn::SendData>,
    disconnect_socket_ptr: Ref<socket_descriptor_fn::DisconnectSocket>,
) -> FFISocketDescriptor {
    let send_data_ref = unsafe_block!("" =>  send_data_ptr.as_ref());
    let disconnect_socket_ref = unsafe_block!("" =>  disconnect_socket_ptr.as_ref());
    let socket = FFISocketDescriptor { index, send_data_ptr: *send_data_ref, disconnect_socket_ptr: *disconnect_socket_ref };
    socket
}

fn create_peer_manager_inner(
    seed: Ref<Bytes32>,
    cfg: Ref<UserConfig>,
    chan_man: FFIArcChannelManagerHandle,
    install_watch_tx_ptr: Ref<chain_watch_interface_fn::InstallWatchTxPtr>,
    install_watch_outpoint_ptr: Ref<chain_watch_interface_fn::InstallWatchOutpointPtr>,
    watch_all_txn_ptr: Ref<chain_watch_interface_fn::WatchAllTxnPtr>,
    get_chain_utxo_ptr: Ref<chain_watch_interface_fn::GetChainUtxoPtr>,
    filter_block_ptr: Ref<chain_watch_interface_fn::FilterBlock>,
    reentered_ptr: Ref<chain_watch_interface_fn::ReEntered>,
    log_ptr: Ref<ffilogger_fn::LogExtern>,
    our_node_secret_ptr: Ref<Bytes32>,
    maybe_network_graph: Option<NetworkGraph>,
) -> FFISimpleArcPeerManager {
    let log_ref = unsafe_block!("" => log_ptr.as_ref());

    let our_node_secret: secp256k1::SecretKey =  {
        let o = unsafe_block!("" => our_node_secret_ptr.as_ref());
        o.clone().into()
    };
    let install_watch_tx_ref = unsafe_block!("function pointer lives as long as ChainWatchInterface and it points to valid data"  => install_watch_tx_ptr.as_ref());
    let install_watch_outpoint_ref = unsafe_block!("function pointer lives as long as ChainWatchInterface and it points to valid data"  => install_watch_outpoint_ptr.as_ref());
    let watch_all_txn_ref = unsafe_block!("function pointer lives as long as ChainWatchInterface and it points to valid data"  => watch_all_txn_ptr.as_ref());
    let get_chain_utxo_ref = unsafe_block!("function pointer lives as long as ChainWatchInterface and it points to valid data"  => get_chain_utxo_ptr.as_ref());
    let filter_block_ref = unsafe_block!("function pointer lives as long as ChainWatchInterface and it points to valid data"  => filter_block_ptr.as_ref());
    let reentered_ref = unsafe_block!("function pointer lives as long as ChainWatchInterface and it points to valid data"  => reentered_ptr.as_ref());

    let logger_arc = Arc::new(FFILogger { log_ptr: *log_ref });
    let chain_watch_interface_arc =
        Arc::new(FFIChainWatchInterface::new(
            *install_watch_tx_ref,
            *install_watch_outpoint_ref,
            *watch_all_txn_ref,
            *get_chain_utxo_ref,
            *filter_block_ref,
            *reentered_ref
        ));
    let route_handler =
        match maybe_network_graph {
            Some(network) => {
                NetGraphMsgHandler::from_net_graph(chain_watch_interface_arc, logger_arc.clone(), network)
            },
            None => {
                NetGraphMsgHandler::new(chain_watch_interface_arc, logger_arc.clone())
            },
        };
    let chan_man = chan_man.as_static_ref();
    let msg_handler =
        MessageHandler { chan_handler: chan_man, route_handler: Arc::new(route_handler) };

    let seed = unsafe_block!("It points to valid length buffer" => seed.as_ref());
    let peer_man =
        FFISimpleArcPeerManager::new(msg_handler, our_node_secret.clone(), &seed.bytes, logger_arc);
    peer_man
}

ffi! {
    fn create_peer_manager(
        seed: Ref<Bytes32>,
        cfg: Ref<UserConfig>,

        chan_man: FFIArcChannelManagerHandle,
        install_watch_tx_ptr: Ref<chain_watch_interface_fn::InstallWatchTxPtr>,
        install_watch_outpoint_ptr: Ref<chain_watch_interface_fn::InstallWatchOutpointPtr>,
        watch_all_txn_ptr: Ref<chain_watch_interface_fn::WatchAllTxnPtr>,
        get_chain_utxo_ptr: Ref<chain_watch_interface_fn::GetChainUtxoPtr>,
        filter_block_ptr: Ref<chain_watch_interface_fn::FilterBlock>,
        reentered_ptr: Ref<chain_watch_interface_fn::ReEntered>,

        log_ptr: Ref<ffilogger_fn::LogExtern>,

        our_node_secret_ptr: Ref<Bytes32>,
        handle: Out<FFIArcPeerManagerHandle>
    ) -> FFIResult {
        let peer_man =
            create_peer_manager_inner(
                seed,
                cfg,
                chan_man,
                install_watch_tx_ptr,
                install_watch_outpoint_ptr,
                watch_all_txn_ptr,
                get_chain_utxo_ptr,
                filter_block_ptr,
                reentered_ptr,
                log_ptr,
                our_node_secret_ptr,
                None
            );
        unsafe_block!("" => handle.init(FFIArcPeerManagerHandle::alloc(peer_man)));
        FFIResult::ok()
    }

    fn create_peer_manager_from_net_graph(
        seed: Ref<Bytes32>,
        cfg: Ref<UserConfig>,

        chan_man: FFIArcChannelManagerHandle,
        install_watch_tx_ptr: Ref<chain_watch_interface_fn::InstallWatchTxPtr>,
        install_watch_outpoint_ptr: Ref<chain_watch_interface_fn::InstallWatchOutpointPtr>,
        watch_all_txn_ptr: Ref<chain_watch_interface_fn::WatchAllTxnPtr>,
        get_chain_utxo_ptr: Ref<chain_watch_interface_fn::GetChainUtxoPtr>,
        filter_block_ptr: Ref<chain_watch_interface_fn::FilterBlock>,
        reentered_ptr: Ref<chain_watch_interface_fn::ReEntered>,

        log_ptr: Ref<ffilogger_fn::LogExtern>,

        our_node_secret_ptr: Ref<Bytes32>,
        network_graph_buf_ptr: Ref<u8>,
        network_graph_buf_len: usize,
        handle: Out<FFIArcPeerManagerHandle>
    ) -> FFIResult {
        let mut net_graph_buf = unsafe_block!("" => network_graph_buf_ptr.as_bytes(network_graph_buf_len));
        let net_graph: NetworkGraph = Readable::read(&mut net_graph_buf).unwrap();
        let peer_man =
            create_peer_manager_inner(
                seed,
                cfg,
                chan_man,
                install_watch_tx_ptr,
                install_watch_outpoint_ptr,
                watch_all_txn_ptr,
                get_chain_utxo_ptr,
                filter_block_ptr,
                reentered_ptr,
                log_ptr,
                our_node_secret_ptr,
                Some(net_graph),
            );
        unsafe_block!("" => handle.init(FFIArcPeerManagerHandle::alloc(peer_man)));
        FFIResult::ok()
    }
    fn new_inbound_connection(
        index: usize,
        send_data_ptr: Ref<socket_descriptor_fn::SendData>,
        disconnect_socket_ptr: Ref<socket_descriptor_fn::DisconnectSocket>,
        handle: FFIArcPeerManagerHandle
        ) -> FFIResult {
        let socket = construct_socket_desc(index, send_data_ptr, disconnect_socket_ptr);
        let peer_man: &FFISimpleArcPeerManager = handle.as_ref();
        peer_man.new_inbound_connection(socket)?;
        FFIResult::ok()
    }

    fn new_outbound_connection(
        index: usize,
        send_data_ptr: Ref<socket_descriptor_fn::SendData>,
        disconnect_socket_ptr: Ref<socket_descriptor_fn::DisconnectSocket>,
        their_node_id: Ref<Bytes33>,
        handle: FFIArcPeerManagerHandle,
        initial_send: Out<[u8; 50]>
    ) -> FFIResult {
        let socket = construct_socket_desc(index, send_data_ptr, disconnect_socket_ptr);
        let peer_man: &FFISimpleArcPeerManager = handle.as_ref();
        let their_node_id = unsafe_block!("" => their_node_id.as_ref());
        let their_node_id: secp256k1::PublicKey = their_node_id.clone().try_into()?;
        let act_one = peer_man.new_outbound_connection(their_node_id, socket)?;
        let mut return_value = [0u8; 50];
        return_value.copy_from_slice(act_one.as_slice());
        unsafe_block!("We know `initial_send` points to valid buffer" => initial_send.init(return_value));
        FFIResult::ok()
    }

    fn timer_tick_occured(handle: FFIArcPeerManagerHandle) -> FFIResult {
        let peer_man: &FFISimpleArcPeerManager = handle.as_ref();
        peer_man.timer_tick_occured();
        FFIResult::ok()
    }

    fn write_buffer_space_avail(
        index: usize,
        send_data_ptr: Ref<socket_descriptor_fn::SendData>,
        disconnect_socket_ptr: Ref<socket_descriptor_fn::DisconnectSocket>,
        handle: FFIArcPeerManagerHandle
    ) -> FFIResult {
        let mut socket = construct_socket_desc(index, send_data_ptr, disconnect_socket_ptr);
        let peer_man: &FFISimpleArcPeerManager = handle.as_ref();
        peer_man.write_buffer_space_avail(&mut socket)?;
        FFIResult::ok()
    }

    fn read_event(
        index: usize,
        send_data_ptr: Ref<socket_descriptor_fn::SendData>,
        disconnect_socket_ptr: Ref<socket_descriptor_fn::DisconnectSocket>,
        data_ref: Ref<FFIBytes>,
        should_pause_read: Out<Bool>,
        handle: FFIArcPeerManagerHandle
    ) -> FFIResult {
        let mut socket = construct_socket_desc(index, send_data_ptr, disconnect_socket_ptr);
        let peer_man: &FFISimpleArcPeerManager = handle.as_ref();
        let data = unsafe_block!("data lives as long as this function and it points to valid value" => data_ref.as_ref());
        let should_pause = peer_man.read_event(&mut socket, data.as_ref())?;
        unsafe_block!("We know it points to valid u8" => should_pause_read.init(if should_pause { Bool::True } else { Bool::False }));
        FFIResult::ok()
    }

    fn process_events(handle: FFIArcPeerManagerHandle) -> FFIResult {
        let peer_man: &FFISimpleArcPeerManager = handle.as_ref();
        peer_man.process_events();
        FFIResult::ok()
    }

    fn socket_disconnected(
        index: usize,
        send_data_ptr: Ref<socket_descriptor_fn::SendData>,
        disconnect_socket_ptr: Ref<socket_descriptor_fn::DisconnectSocket>,
        handle: FFIArcPeerManagerHandle) -> FFIResult {
        let mut socket = construct_socket_desc(index, send_data_ptr, disconnect_socket_ptr);
        let peer_man: &FFISimpleArcPeerManager = handle.as_ref();
        peer_man.socket_disconnected(&socket);
        FFIResult::ok()
    }

    fn get_peer_node_ids(buf_out: Out<u8>, buf_len: usize, actual_node_ids_len: Out<usize>, handle: FFIArcPeerManagerHandle) -> FFIResult {
        let buf = unsafe_block!("The buffer lives as long as `get_peer_node_ids`, the length is within the buffer and the buffer won't be read before initialization" => buf_out.as_uninit_bytes_mut(buf_len));
        let peer_man: &FFISimpleArcPeerManager = handle.as_ref();
        let mut node_ids = peer_man.get_peer_node_ids();
        into_fixed_buffer(&mut node_ids, buf, &mut actual_node_ids_len)
    }

    fn get_network_graph(buf_out: Out<u8>, buf_len: usize, actual_len: Out<usize>, handle: FFIArcPeerManagerHandle) -> FFIResult {
        let buf = unsafe_block!("The buffer lives as long as this function, the length is within the buffer and the buffer won't be read before initialization" => buf_out.as_uninit_bytes_mut(buf_len));
        let peer_man: &FFISimpleArcPeerManager = handle.as_ref();
        let mut graph = peer_man.message_handler.route_handler.network_graph.read().unwrap();
        into_fixed_buffer(&*graph, buf, &mut actual_len)
    }

    fn release_peer_manager(handle: FFIArcPeerManagerHandle) -> FFIResult {
        unsafe_block!("The upstream caller guarantees the handle will not be accessed after being freed" => FFIArcPeerManagerHandle::dealloc(handle, |mut handle| {
            // We keep reference to message_handler from wrapper side so that we can call methods
            // on it. So disposing it is their job. Not ours.
            std::mem::forget(handle.message_handler);
            FFIResult::ok()
        }))
    }
}
