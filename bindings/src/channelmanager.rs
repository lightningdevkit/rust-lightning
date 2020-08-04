use std::{
    convert::{TryInto},
    sync::Arc,
};

use bitcoin::{
    hash_types::BlockHash,
    secp256k1
};

use crate::{
    error::FFIResult,
    handle::{Out, Ref, HandleShared},
    adaptors::{
        primitives::{
            Bytes32,
            Bytes33,
            FFIRoute,
            FFIEvents,
            FFIOutPoint,
            FFIBytes
        },
        *
    },
    utils::into_fixed_buffer,
    channelmonitor::FFIManyChannelMonitor
};
use lightning::{
    routing::router::{RouteHint, get_route},
    util::{
        config::UserConfig,
        events::EventsProvider
    },
    ln::{
        channelmanager::{ChannelManager, PaymentHash},
    },
    chain::{
        keysinterface::{InMemoryChannelKeys},
        transaction::OutPoint
    },
    routing::router::Route,
    ln::channelmanager::{PaymentSecret, PaymentPreimage},
    util::ser::{Readable, ReadableArgs},
    ln::channelmanager::ChannelManagerReadArgs,
    routing::network_graph::NetworkGraph
};
use crate::channelmonitor::FFIManyChannelMonitorHandle;

pub type FFIArcChannelManager = ChannelManager<InMemoryChannelKeys, &'static FFIManyChannelMonitor, Arc<FFIBroadCaster>, Arc<FFIKeysInterface>, Arc<FFIFeeEstimator>, Arc<FFILogger>>;
pub type FFIArcChannelManagerHandle = HandleShared<'static, FFIArcChannelManager>;
pub type FFIChannelManagerReadArgs<'a> = ChannelManagerReadArgs<'a, Arc<InMemoryChannelKeys>, &'static FFIManyChannelMonitor, Arc<FFIBroadCaster>, Arc<FFIKeysInterface>, Arc<FFIFeeEstimator>, Arc<FFILogger>>;


fn fail_htlc_backwards_inner(payment_hash: Ref<Bytes32>, payment_secret: &Option<PaymentSecret>, handle: FFIArcChannelManagerHandle) -> Result<bool, FFIResult> {
    let chan_man: &FFIArcChannelManager = handle.as_ref();
    let payment_hash: &Bytes32 = unsafe_block!("" => payment_hash.as_ref());
    let payment_hash: PaymentHash = payment_hash.clone().try_into()?;
    Ok(chan_man.fail_htlc_backwards(&payment_hash, payment_secret))
}

fn create_channel_inner(their_network_key: Ref<Bytes33>, channel_value_satoshis: u64, push_msat: u64, user_id: u64, override_config: Option<UserConfig>, handle: FFIArcChannelManagerHandle) -> FFIResult {
    let chan_man: &FFIArcChannelManager = handle.as_ref();
    let their_network_key = unsafe_block!("We know it points to valid public key buffer" => their_network_key.as_ref()).clone().try_into()?;
    chan_man.create_channel(their_network_key, channel_value_satoshis, push_msat, user_id, override_config)?;
    FFIResult::ok()
}

fn claim_funds_inner(payment_preimage: Ref<Bytes32>, payment_secret: Option<PaymentSecret>, expected_amount: u64, handle: FFIArcChannelManagerHandle) -> bool {
    let chan_man: &FFIArcChannelManager = handle.as_ref();
    let payment_preimage: PaymentPreimage = unsafe_block!("" => payment_preimage.as_ref()).clone().into();

    chan_man.claim_funds(payment_preimage, &payment_secret, expected_amount)
}


fn send_payment_inner(handle: FFIArcChannelManagerHandle, route_ref: Ref<FFIRoute>, payment_hash_ref: Ref<Bytes32>, payment_secret: Option<PaymentSecret>) -> FFIResult {
    let chan_man: &FFIArcChannelManager = handle.as_ref();
    let route_ffi: &FFIRoute = unsafe_block!("We know it points to valid route data" => route_ref.as_ref());
    let payment_hash_ffi: &Bytes32 = unsafe_block!("We know it points to valid hash data" => payment_hash_ref.as_ref());
    let payment_hash: PaymentHash = payment_hash_ffi.clone().into();
    let route: Route = route_ffi.clone().try_into()?;
    chan_man.send_payment(&route, payment_hash, &payment_secret)?;
    FFIResult::ok()
}


fn get_route_and_send_payment_inner(
    graph_bytes_ptr: Ref<u8>,
    graph_bytes_len: usize,
    their_node_id: Ref<Bytes33>,
    last_hops_ref: Ref<FFIBytes>,
    final_value_msat: u64,
    final_cltv: u32,
    maybe_payment_secret: &Option<PaymentSecret>,
    payment_hash_ref: Ref<Bytes32>,
    chanman_handle: FFIArcChannelManagerHandle
) -> FFIResult {
    let chan_man: &FFIArcChannelManager = chanman_handle.as_ref();
    let their_node_id: secp256k1::PublicKey = unsafe_block!("" => their_node_id.as_ref()).clone().try_into()?;
    let hops = chan_man.list_usable_channels();
    let last_hops = unsafe_block!("data lives as long as this function and it points to valid value" => last_hops_ref.as_ref());
    let last_hops: Vec<RouteHint> = Readable::read(&mut last_hops.as_ref()).expect("Failed to deserialize last_hops");
    let our_node_id = chan_man.get_our_node_id();
    let mut graph_bytes = unsafe_block!("" => graph_bytes_ptr.as_bytes(graph_bytes_len));
    let graph: NetworkGraph = Readable::read(&mut graph_bytes).expect("Failed to decode graph");
    let mut route = get_route(&our_node_id, &graph, &their_node_id, Some(&hops), last_hops.as_ref(), final_value_msat, final_cltv, chan_man.logger.clone())?;
    if maybe_payment_secret.is_none()
    {
        route = Route { paths: route.paths[0..1].to_vec() }
    }
    let payment_hash: PaymentHash = unsafe_block!("We know it points to valid hash data" => payment_hash_ref.as_ref()).clone().into();
    chan_man.send_payment(&route, payment_hash, maybe_payment_secret)?;
    FFIResult::ok()
}

pub(crate) fn construct_channel_manager(
    ffi_network: FFINetwork,
    cfg: Ref<UserConfig>,

    install_watch_tx: &chain_watch_interface_fn::InstallWatchTxPtr,
    install_watch_outpoint: &chain_watch_interface_fn::InstallWatchOutpointPtr,
    watch_all_txn: &chain_watch_interface_fn::WatchAllTxnPtr,
    get_chain_utxo: &chain_watch_interface_fn::GetChainUtxoPtr,
    filter_block: &chain_watch_interface_fn::FilterBlock,
    reentered: &chain_watch_interface_fn::ReEntered,

    keys_interface: Arc<FFIKeysInterface>,

    broadcast_transaction_ptr: Ref<broadcaster_fn::BroadcastTransactionPtr>,
    log_ref: &ffilogger_fn::LogExtern,
    get_est_sat_per_1000_weight_ptr: Ref<fee_estimator_fn::GetEstSatPer1000WeightPtr>,
    cur_block_height: usize,
    monitor_handle: FFIManyChannelMonitorHandle
) -> FFIArcChannelManager {
    let network = ffi_network.to_network();

    let logger_arc = Arc::new( FFILogger{ log_ptr: *log_ref } );

    let chain_watch_interface_arc =
        Arc::new(FFIChainWatchInterface::new(
            *install_watch_tx,
            *install_watch_outpoint,
            *watch_all_txn,
            *get_chain_utxo,
            *filter_block,
            *reentered,
        ));

    let broadcast_ref = unsafe_block!("" => broadcast_transaction_ptr.as_ref());
    let broadcaster = Arc::new(FFIBroadCaster { broadcast_transaction_ptr: *broadcast_ref });

    let fee_est_fn_ref = unsafe_block!("" => get_est_sat_per_1000_weight_ptr.as_ref());
    let fee_est = FFIFeeEstimator{ get_est_sat_per_1000_weight_ptr: *fee_est_fn_ref };

    let cfg = unsafe_block!("" => cfg.as_ref());

    let monitor = monitor_handle.as_static_ref();

    ChannelManager::new(
        network,
        Arc::new(fee_est),
        monitor,
        broadcaster,
        logger_arc,
        keys_interface,
        cfg.clone(),
        cur_block_height
    )
}

ffi! {

    fn create_channel_manager(
        network_ref: Ref<FFINetwork>,
        cfg: Ref<UserConfig>,

        install_watch_tx_ptr: Ref<chain_watch_interface_fn::InstallWatchTxPtr>,
        install_watch_outpoint_ptr: Ref<chain_watch_interface_fn::InstallWatchOutpointPtr>,
        watch_all_txn_ptr: Ref<chain_watch_interface_fn::WatchAllTxnPtr>,
        get_chain_utxo_ptr: Ref<chain_watch_interface_fn::GetChainUtxoPtr>,
        filter_block_ptr: Ref<chain_watch_interface_fn::FilterBlock>,
        reentered_ptr: Ref<chain_watch_interface_fn::ReEntered>,

        get_node_secret_ptr: Ref<keys_interface_fn::GetNodeSecret>,
        get_destination_script_ptr: Ref<keys_interface_fn::GetDestinationScript>,
        get_shutdown_key_ptr: Ref<keys_interface_fn::GetShutdownPubKey>,
        get_channel_keys_ptr: Ref<keys_interface_fn::GetChannelKeys>,
        get_onion_rand_ptr: Ref<keys_interface_fn::GetOnionRand>,
        get_channel_id_ptr: Ref<keys_interface_fn::GetChannelId>,

        broadcast_transaction_ptr: Ref<broadcaster_fn::BroadcastTransactionPtr>,
        log_ptr: Ref<ffilogger_fn::LogExtern>,
        get_est_sat_per_1000_weight_ptr: Ref<fee_estimator_fn::GetEstSatPer1000WeightPtr>,
        cur_block_height: usize,
        monitor_handle: FFIManyChannelMonitorHandle,
        chan_man: Out<FFIArcChannelManagerHandle>
        ) -> FFIResult {

        let log_ref = unsafe_block!("" => log_ptr.as_ref());
        let network = unsafe_block!("" => *network_ref.as_ref());
        let install_watch_tx_ref = unsafe_block!("function pointer lives as long as ChainWatchInterface and it points to valid data"  => install_watch_tx_ptr.as_ref());
        let install_watch_outpoint_ref = unsafe_block!("function pointer lives as long as ChainWatchInterface and it points to valid data"  => install_watch_outpoint_ptr.as_ref());
        let watch_all_txn_ref = unsafe_block!("function pointer lives as long as ChainWatchInterface and it points to valid data"  => watch_all_txn_ptr.as_ref());
        let get_chain_utxo_ref = unsafe_block!("function pointer lives as long as ChainWatchInterface and it points to valid data"  => get_chain_utxo_ptr.as_ref());
        let filter_block_ref = unsafe_block!("function pointer lives as long as ChainWatchInterface and it points to valid data"  => filter_block_ptr.as_ref());
        let reentered_ref = unsafe_block!("function pointer lives as long as ChainWatchInterface and it points to valid data"  => reentered_ptr.as_ref());

        let get_node_secret_ref = unsafe_block!("function pointer lives as long as KeysInterface and it points to valid data" => get_node_secret_ptr.as_ref());
        let get_destination_script_ref = unsafe_block!("function pointer lives as long as KeysInterface and it points to valid data" => get_destination_script_ptr.as_ref());
        let get_shutdown_key_ref = unsafe_block!("function pointer lives as long as KeysInterface and it points to valid data" => get_shutdown_key_ptr.as_ref());
        let get_channel_keys_ref = unsafe_block!("function pointer lives as long as KeysInterface and it points to valid data" => get_channel_keys_ptr.as_ref());
        let get_onion_rand_ref = unsafe_block!("function pointer lives as long as KeysInterface and it points to valid data" => get_onion_rand_ptr.as_ref());
        let get_channel_id_ref = unsafe_block!("function pointer lives as long as KeysInterface and it points to valid data" => get_channel_id_ptr.as_ref());
        let keys_interface = FFIKeysInterface::new(
            *get_node_secret_ref,
            *get_destination_script_ref,
            *get_shutdown_key_ref,
            *get_channel_keys_ref,
            *get_onion_rand_ref,
            *get_channel_id_ref,
        );

        let chan_man_raw =
            construct_channel_manager(
                network,
                cfg,

                install_watch_tx_ref,
                install_watch_outpoint_ref,
                watch_all_txn_ref,
                get_chain_utxo_ref,
                filter_block_ref,
                reentered_ref,

                Arc::new(keys_interface),

                broadcast_transaction_ptr,
                log_ref,
                get_est_sat_per_1000_weight_ptr,
                cur_block_height,
                monitor_handle
            );
        unsafe_block!("We know chan_man is not null by wrapper macro. And we know `Out` is writable" => chan_man.init(HandleShared::alloc(chan_man_raw)));
        FFIResult::ok()
    }

    fn list_channels(buf_out: Out<u8>, buf_len: usize, actual_channels_len: Out<usize>, handle: FFIArcChannelManagerHandle) -> FFIResult {
        let buf = unsafe_block!("The buffer lives as long as this function, the length is within the buffer and the buffer won't be read before initialization" => buf_out.as_uninit_bytes_mut(buf_len));
        let chan_man: &FFIArcChannelManager = handle.as_ref();
        let mut channels = chan_man.list_channels();
        into_fixed_buffer(&mut channels, buf, &mut actual_channels_len)
    }

    fn create_channel(their_network_key: Ref<Bytes33>, channel_value_satoshis: u64, push_msat: u64, user_id: u64, handle: FFIArcChannelManagerHandle) -> FFIResult {
        create_channel_inner(their_network_key, channel_value_satoshis, push_msat, user_id, None, handle)
    }

    fn create_channel_with_custom_config(their_network_key: Ref<Bytes33>, channel_value_satoshis: u64, push_msat: u64, user_id: u64, override_config: Ref<UserConfig>, handle: FFIArcChannelManagerHandle) -> FFIResult {
        let override_config = unsafe_block!("We know it points to valid UserConfig" => override_config.as_ref());
        create_channel_inner(their_network_key, channel_value_satoshis, push_msat, user_id, Some(override_config.clone()), handle)
    }

    fn close_channel(channel_id: Ref<Bytes32>, handle: FFIArcChannelManagerHandle) -> FFIResult {
        let chan_man: &FFIArcChannelManager = handle.as_ref();
        let channel_id: &Bytes32 = unsafe_block!("We know it points to valid data and it lives as long as the function call" => channel_id.as_ref());
        chan_man.close_channel(&channel_id.bytes)?;
        FFIResult::ok()
    }

    fn force_close_channel(channel_id: Ref<Bytes32>, handle: FFIArcChannelManagerHandle) -> FFIResult {
        let chan_man: &FFIArcChannelManager = handle.as_ref();
        let channel_id = unsafe_block!("We know it points to valid data and it lives as long as the function call" => channel_id.as_ref());
        chan_man.force_close_channel(&channel_id.bytes);
        FFIResult::ok()
    }

    fn force_close_all_channels(handle: FFIArcChannelManagerHandle) -> FFIResult {
        let chan_man: &FFIArcChannelManager = handle.as_ref();
        chan_man.force_close_all_channels();
        FFIResult::ok()
    }

    fn send_payment(handle: FFIArcChannelManagerHandle, route_ref: Ref<FFIRoute>, payment_hash_ref: Ref<Bytes32>, payment_secret_ref: Ref<Bytes32>) -> FFIResult {
        let payment_secret: &Bytes32 = unsafe_block!("We know it points to valid payment_secret data or empty 32 bytes" => payment_secret_ref.as_ref());
        let maybe_secret = Some(payment_secret.clone().into());
        send_payment_inner(handle, route_ref, payment_hash_ref, maybe_secret)
    }

    fn send_payment_without_secret(handle: FFIArcChannelManagerHandle, route_ref: Ref<FFIRoute>, payment_hash_ref: Ref<Bytes32>) -> FFIResult {
        send_payment_inner(handle, route_ref, payment_hash_ref, None)
    }

    fn get_route_and_send_payment(
        graph_bytes_ptr: Ref<u8>,
        graph_bytes_len: usize,
        their_node_id: Ref<Bytes33>,
        last_hops_ref: Ref<FFIBytes>,
        final_value_msat: u64,
        final_cltv: u32,
        payment_secret_ref: Ref<Bytes32>,
        payment_hash: Ref<Bytes32>,
        chanman_handle: FFIArcChannelManagerHandle
    ) -> FFIResult {
        let payment_secret = unsafe_block!("" => payment_secret_ref.as_ref()).clone().into();
        get_route_and_send_payment_inner(graph_bytes_ptr, graph_bytes_len, their_node_id, last_hops_ref, final_value_msat, final_cltv, &Some(payment_secret), payment_hash, chanman_handle)
    }

    fn get_route_and_send_payment_without_secret(
        graph_bytes_ptr: Ref<u8>,
        graph_bytes_len: usize,
        their_node_id: Ref<Bytes33>,
        last_hops_ref: Ref<FFIBytes>,
        final_value_msat: u64,
        final_cltv: u32,
        payment_hash: Ref<Bytes32>,
        chanman_handle: FFIArcChannelManagerHandle
    ) -> FFIResult {
        get_route_and_send_payment_inner(graph_bytes_ptr, graph_bytes_len, their_node_id, last_hops_ref, final_value_msat, final_cltv, &None, payment_hash, chanman_handle)
    }

    fn funding_transaction_generated(temporary_channel_id: Ref<Bytes32>, funding_txo: FFIOutPoint, handle: FFIArcChannelManagerHandle) -> FFIResult {
        let chan_man: &FFIArcChannelManager = handle.as_ref();
        let temporary_channel_id: &Bytes32 = unsafe_block!("data lives as long as this function and it points to a valid value" => temporary_channel_id.as_ref());
        let funding_txo: OutPoint = funding_txo.try_into()?;
        chan_man.funding_transaction_generated(&temporary_channel_id.bytes, funding_txo);
        FFIResult::ok()
    }

    fn process_pending_htlc_forwards(handle: FFIArcChannelManagerHandle) -> FFIResult {
        let chan_man: &FFIArcChannelManager = handle.as_ref();
        chan_man.process_pending_htlc_forwards();
        FFIResult::ok()
    }

    fn timer_chan_freshness_every_min(handle: FFIArcChannelManagerHandle) -> FFIResult {
        let chan_man: &FFIArcChannelManager = handle.as_ref();
        chan_man.timer_chan_freshness_every_min();
        FFIResult::ok()
    }

    fn fail_htlc_backwards(payment_hash: Ref<Bytes32>, payment_secret: Ref<Bytes32>, handle: FFIArcChannelManagerHandle, result: Out<Bool>) -> FFIResult {
        let payment_secret: &Bytes32 = unsafe_block!("it points to valid data and lives as long as the function call" => payment_secret.as_ref());
        let payment_secret: PaymentSecret = payment_secret.clone().into();
        let payment_secret: Option<PaymentSecret> = Some(payment_secret);
        let r = fail_htlc_backwards_inner(payment_hash, &payment_secret, handle)?;
        unsafe_block!("We know out parameter is writable" => result.init(r.into()));
        FFIResult::ok()
    }

    fn fail_htlc_backwards_without_secret(payment_hash: Ref<Bytes32>, handle: FFIArcChannelManagerHandle, result: Out<Bool>) -> FFIResult {
        let r = fail_htlc_backwards_inner(payment_hash, &None, handle)?;
        unsafe_block!("We know out parameter is writable" => result.init(r.into()));
        FFIResult::ok()
    }

    fn claim_funds(payment_preimage: Ref<Bytes32>, payment_secret: Ref<Bytes32>, expected_amount: u64, handle: FFIArcChannelManagerHandle, result: Out<Bool>) -> FFIResult {
        let payment_secret: &Bytes32 = unsafe_block!("" => payment_secret.as_ref());
        let payment_secret: Option<PaymentSecret> = Some(payment_secret.clone().into());
        let r = claim_funds_inner(payment_preimage, payment_secret, expected_amount, handle);
        unsafe_block!("We know out parameter is writable" => result.init(r.into()));
        FFIResult::ok()
    }

    fn claim_funds_without_secret(payment_preimage: Ref<Bytes32>, expected_amount: u64, handle: FFIArcChannelManagerHandle, result: Out<Bool>) -> FFIResult {
        let r = claim_funds_inner(payment_preimage, None, expected_amount, handle);
        unsafe_block!("We know out parameter is writable" => result.init(r.into()));
        FFIResult::ok()
    }

    fn update_fee(channel_id: Ref<[u8; 32]>, feerate_per_kw: u32, handle: FFIArcChannelManagerHandle) -> FFIResult {
        let chan_man: &FFIArcChannelManager = handle.as_ref();
        let channel_id: &[u8;32] = unsafe_block!("" => channel_id.as_ref());
        chan_man.update_fee(channel_id.clone(), feerate_per_kw)?;
        FFIResult::ok()
    }

    fn get_and_clear_pending_events(handle: FFIArcChannelManagerHandle, buf_out: Out<u8>, buf_len: usize, actual_channels_len: Out<usize>) -> FFIResult {
        let buf = unsafe_block!("The buffer lives as long as this function, the length is within the buffer and the buffer won't be read before initialization" => buf_out.as_uninit_bytes_mut(buf_len));
        let chan_man: &FFIArcChannelManager = handle.as_ref();
        let mut e = FFIEvents{ events: chan_man.get_and_clear_pending_events() };
        into_fixed_buffer(&mut e, buf, &mut actual_channels_len)
    }

    fn serialize_channel_manager(buf_out: Out<u8>, buf_len: usize, actual_len: Out<usize>, handle: FFIArcChannelManagerHandle) -> FFIResult {
        let buf = unsafe_block!("The buffer lives as long as this function, the length is within the buffer and the buffer won't be read before initialization" => buf_out.as_uninit_bytes_mut(buf_len));
        let mut chan_man: &FFIArcChannelManager = handle.as_ref();
        into_fixed_buffer(&mut chan_man, buf, &mut actual_len)
    }

    fn deserialize_channel_manager(buf_ptr: Ref<u8>, buf_len: usize,
                                   cfg: Ref<UserConfig>,

                                   install_watch_tx_ptr: Ref<chain_watch_interface_fn::InstallWatchTxPtr>,
                                   install_watch_outpoint_ptr: Ref<chain_watch_interface_fn::InstallWatchOutpointPtr>,
                                   watch_all_txn_ptr: Ref<chain_watch_interface_fn::WatchAllTxnPtr>,
                                   get_chain_utxo_ptr: Ref<chain_watch_interface_fn::GetChainUtxoPtr>,
                                   filter_block_ptr: Ref<chain_watch_interface_fn::FilterBlock>,
                                   reentered_ptr: Ref<chain_watch_interface_fn::ReEntered>,

                                   get_node_secret_ptr: Ref<keys_interface_fn::GetNodeSecret>,
                                   get_destination_script_ptr: Ref<keys_interface_fn::GetDestinationScript>,
                                   get_shutdown_key_ptr: Ref<keys_interface_fn::GetShutdownPubKey>,
                                   get_channel_keys_ptr: Ref<keys_interface_fn::GetChannelKeys>,
                                   get_onion_rand_ptr: Ref<keys_interface_fn::GetOnionRand>,
                                   get_channel_id_ptr: Ref<keys_interface_fn::GetChannelId>,

                                   broadcast_transaction_ptr: Ref<broadcaster_fn::BroadcastTransactionPtr>,
                                   log_ptr: Ref<ffilogger_fn::LogExtern>,
                                   get_est_sat_per_1000_weight_ptr: Ref<fee_estimator_fn::GetEstSatPer1000WeightPtr>,
                                   monitor_handle: FFIManyChannelMonitorHandle,

                                    output_buf_ptr: Out<u8>,
                                    output_buf_len: usize,
                                    output_actual_len: Out<usize>,

                                   handle: Out<FFIArcChannelManagerHandle>) -> FFIResult {

        // TODO: use macro?
        let log_ref = unsafe_block!("" => log_ptr.as_ref());
        let install_watch_tx = unsafe_block!("function pointer lives as long as ChainWatchInterface and it points to valid data"  => install_watch_tx_ptr.as_ref());
        let install_watch_outpoint = unsafe_block!("function pointer lives as long as ChainWatchInterface and it points to valid data"  => install_watch_outpoint_ptr.as_ref());
        let watch_all_txn = unsafe_block!("function pointer lives as long as ChainWatchInterface and it points to valid data"  => watch_all_txn_ptr.as_ref());
        let get_chain_utxo = unsafe_block!("function pointer lives as long as ChainWatchInterface and it points to valid data"  => get_chain_utxo_ptr.as_ref());
        let filter_block = unsafe_block!("function pointer lives as long as ChainWatchInterface and it points to valid data"  => filter_block_ptr.as_ref());
        let reentered = unsafe_block!("function pointer lives as long as ChainWatchInterface and it points to valid data"  => reentered_ptr.as_ref());

        let get_node_secret_ref = unsafe_block!("function pointer lives as long as KeysInterface and it points to valid data" => get_node_secret_ptr.as_ref());
        let get_destination_script_ref = unsafe_block!("function pointer lives as long as KeysInterface and it points to valid data" => get_destination_script_ptr.as_ref());
        let get_shutdown_key_ref = unsafe_block!("function pointer lives as long as KeysInterface and it points to valid data" => get_shutdown_key_ptr.as_ref());
        let get_channel_keys_ref = unsafe_block!("function pointer lives as long as KeysInterface and it points to valid data" => get_channel_keys_ptr.as_ref());
        let get_onion_rand_ref = unsafe_block!("function pointer lives as long as KeysInterface and it points to valid data" => get_onion_rand_ptr.as_ref());
        let get_channel_id_ref = unsafe_block!("function pointer lives as long as KeysInterface and it points to valid data" => get_channel_id_ptr.as_ref());
        let keys_manager = Arc::new(FFIKeysInterface::new(
            *get_node_secret_ref,
            *get_destination_script_ref,
            *get_shutdown_key_ref,
            *get_channel_keys_ref,
            *get_onion_rand_ref,
            *get_channel_id_ref,
        ));

        let logger = Arc::new( FFILogger{ log_ptr: *log_ref } );

        let chain_watch_interface_arc =
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

        let default_config = unsafe_block!("" => cfg.as_ref());
        let mut buf = unsafe_block!("The buffer lives as long as this function. And its length is buf_len" => buf_ptr.as_bytes(buf_len));
        let monitor = monitor_handle.as_static_ref();
        let readable_args = ChannelManagerReadArgs {
            keys_manager,
            fee_estimator,
            monitor,
            tx_broadcaster,
            logger,
            default_config: default_config.clone(),
            channel_monitors: &mut Default::default()
        };
        let (hash, chan_man): (BlockHash, FFIArcChannelManager) = ReadableArgs::read(&mut buf, readable_args).unwrap();

        let output_buf = unsafe_block!("" => output_buf_ptr.as_uninit_bytes_mut(output_buf_len));
        into_fixed_buffer(&hash, output_buf, &mut output_actual_len)?;

        unsafe_block!("We know chan_man is not null by wrapper macro. And we know `Out` is writable" => handle.init(HandleShared::alloc(chan_man)));
        FFIResult::ok()
    }

    fn release_ffi_channel_manager(handle: FFIArcChannelManagerHandle) -> FFIResult {
        unsafe_block!("The upstream caller guarantees the handle will not be accessed after being freed" => FFIArcChannelManagerHandle::dealloc(handle, |mut _handle| {
            FFIResult::ok()
        }))
    }

}

