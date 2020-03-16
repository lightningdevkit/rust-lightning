use std::{
    convert::{TryInto},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH}
};

use bitcoin::secp256k1;
use lightning::{
    util::{
        config::UserConfig,
        events::EventsProvider
    },
    ln::{
        channelmanager::{ChannelManager, PaymentHash},
        channelmonitor::SimpleManyChannelMonitor
    },
    chain::{
        keysinterface::{KeysManager, InMemoryChannelKeys},
        transaction::OutPoint
    },
    routing::router::Route,
};

use crate::{
    error::FFIResult,
    handle::{Out, Ref, HandleShared},
    adaptors::{
        primitives::{
            PublicKey,
            FFISha256dHash,
            FFIRoute,
            FFIEvents,
            FFISecret,
            FFIOutPoint
        },
        *,
    }
};
use lightning::ln::channelmanager::{PaymentSecret, PaymentPreimage};

pub type FFIManyChannelMonitor = SimpleManyChannelMonitor<OutPoint, InMemoryChannelKeys, Arc<FFIBroadCaster>, Arc<FFIFeeEstimator>, Arc<FFILogger>, Arc<FFIChainWatchInterface>>;
pub type FFIArcChannelManager = ChannelManager<InMemoryChannelKeys, Arc<FFIManyChannelMonitor>, Arc<FFIBroadCaster>, Arc<KeysManager>, Arc<FFIFeeEstimator>, Arc<FFILogger>>;
pub type FFIArcChannelManagerHandle<'a> = HandleShared<'a, FFIArcChannelManager>;

fn fail_htlc_backwards_inner(payment_hash: Ref<FFISha256dHash>, payment_secret: &Option<PaymentSecret>, handle: FFIArcChannelManagerHandle) -> Result<bool, FFIResult> {
    let chan_man: &FFIArcChannelManager = unsafe_block!("We know handle points to valid channel_manager" => handle.as_ref());
    let payment_hash: &FFISha256dHash = unsafe_block!("" => payment_hash.as_ref());
    let payment_hash: PaymentHash = payment_hash.clone().try_into()?;
    Ok(chan_man.fail_htlc_backwards(&payment_hash, payment_secret))
}

fn create_channel_inner(their_network_key: PublicKey, channel_value_satoshis: u64, push_msat: u64, user_id: u64, override_config: Option<UserConfig>, handle: FFIArcChannelManagerHandle) -> FFIResult {
    let chan_man: &FFIArcChannelManager = unsafe_block!("We know handle points to valid channel_manager" => handle.as_ref());
    let their_network_key = their_network_key.try_into()?;
    chan_man.create_channel(their_network_key, channel_value_satoshis, push_msat, user_id, override_config)?;
    FFIResult::ok()
}

fn claim_funds_inner(payment_preimage: Ref<[u8; 32]>, payment_secret: Option<PaymentSecret>, expected_amount: u64, handle: FFIArcChannelManagerHandle) -> bool {
    let chan_man: &FFIArcChannelManager = unsafe_block!("We know handle points to valid channel_manager" => handle.as_ref());
    let payment_preimage: &[u8;32] = unsafe_block!("" => payment_preimage.as_ref());
    let payment_preimage = PaymentPreimage(payment_preimage.clone());

    chan_man.claim_funds(payment_preimage, &payment_secret, expected_amount)
}


pub(crate) fn construct_channel_manager(
    seed_ptr: Ref<u8>,
    seed_len: usize,
    ffi_network: FFINetwork,
    cfg: Ref<UserConfig>,

    install_watch_tx: &chain_watch_interface_fn::InstallWatchTxPtr,
    install_watch_outpoint: &chain_watch_interface_fn::InstallWatchOutpointPtr,
    watch_all_txn: &chain_watch_interface_fn::WatchAllTxnPtr,
    get_chain_utxo: &chain_watch_interface_fn::GetChainUtxoPtr,

    broadcast_transaction_ptr: Ref<broadcaster_fn::BroadcastTransactionPtr>,
    log_ref: &ffilogger_fn::LogExtern,
    get_est_sat_per_1000_weight_ptr: Ref<fee_estimator_fn::GetEstSatPer1000WeightPtr>,
    cur_block_height: usize,

) -> Result<FFIArcChannelManager, secp256k1::Error> {
    let seed_slice = unsafe_block!("The seed lives as long as `create_channel_manager` and the length is within the seed" => seed_ptr.as_bytes(seed_len));
    let network = ffi_network.to_network();
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    let mut seed: [u8; 32] = Default::default();
    seed.copy_from_slice(seed_slice);

    let logger_arc = Arc::new( FFILogger{ log_ptr: *log_ref } );

    let chain_watch_interface_arc =
        Arc::new(FFIChainWatchInterface::new(
             *install_watch_tx,
            *install_watch_outpoint,
            *watch_all_txn,
            *get_chain_utxo,
                network,
            logger_arc.clone()
        ));

    let broadcast_ref = unsafe_block!("" => broadcast_transaction_ptr.as_ref());
    let broadcaster = Arc::new(FFIBroadCaster { broadcast_transaction_ptr: *broadcast_ref });

    let fee_est_fn_ref = unsafe_block!("" => get_est_sat_per_1000_weight_ptr.as_ref());
    let fee_est = FFIFeeEstimator{ get_est_sat_per_1000_weight_ptr: *fee_est_fn_ref };

    let keyman = Arc::new(KeysManager::new(&seed, network, now.as_secs(), now.subsec_nanos()));
    let cfg = unsafe_block!("" => cfg.as_ref());

    let monitor =
        Arc::new(FFIManyChannelMonitor::new(chain_watch_interface_arc, broadcaster.clone(), logger_arc.clone(), Arc::new(fee_est.clone())));

    ChannelManager::new(
        network,
        Arc::new(fee_est),
        monitor,
        broadcaster,
        logger_arc,
        keyman,
        cfg.clone(),
        cur_block_height
    )
}

ffi! {

    fn create_channel_manager(
        seed_ptr: Ref<u8>,
        seed_len: usize,
        network_ref: Ref<FFINetwork>,
        cfg: Ref<UserConfig>,

        install_watch_tx_ptr: Ref<chain_watch_interface_fn::InstallWatchTxPtr>,
        install_watch_outpoint_ptr: Ref<chain_watch_interface_fn::InstallWatchOutpointPtr>,
        watch_all_txn_ptr: Ref<chain_watch_interface_fn::WatchAllTxnPtr>,
        get_chain_utxo_ptr: Ref<chain_watch_interface_fn::GetChainUtxoPtr>,

        broadcast_transaction_ptr: Ref<broadcaster_fn::BroadcastTransactionPtr>,
        log_ptr: Ref<ffilogger_fn::LogExtern>,
        get_est_sat_per_1000_weight_ptr: Ref<fee_estimator_fn::GetEstSatPer1000WeightPtr>,
        cur_block_height: usize,
        chan_man: Out<FFIArcChannelManagerHandle>) -> FFIResult {
        if (seed_len != 32) {
            return FFIResult::invalid_data_length();
        }
        let log_ref = unsafe_block!("" => log_ptr.as_ref());
        let network = unsafe_block!("" => *network_ref.as_ref());
        let install_watch_tx_ref = unsafe_block!("function pointer lives as long as ChainWatchInterface and it points to valid data"  => install_watch_tx_ptr.as_ref());
        let install_watch_outpoint_ref = unsafe_block!("function pointer lives as long as ChainWatchInterface and it points to valid data"  => install_watch_outpoint_ptr.as_ref());
        let watch_all_txn_ref = unsafe_block!("function pointer lives as long as ChainWatchInterface and it points to valid data"  => watch_all_txn_ptr.as_ref());
        let get_chain_utxo_ref = unsafe_block!("function pointer lives as long as ChainWatchInterface and it points to valid data"  => get_chain_utxo_ptr.as_ref());
        let chan_man_raw =
            construct_channel_manager(
                seed_ptr,
                seed_len,
                network,
                cfg,
                install_watch_tx_ref,
                install_watch_outpoint_ref,
                watch_all_txn_ref,
                get_chain_utxo_ref,

                broadcast_transaction_ptr,
                log_ref,
                get_est_sat_per_1000_weight_ptr,
                cur_block_height,
            )?;
        unsafe_block!("We know chan_man is not null by wrapper macro. And we know `Out` is writable" => chan_man.init(HandleShared::alloc(chan_man_raw)));
        FFIResult::ok()
    }

    fn create_channel(their_network_key: PublicKey, channel_value_satoshis: u64, push_msat: u64, user_id: u64, handle: FFIArcChannelManagerHandle) -> FFIResult {
        create_channel_inner(their_network_key, channel_value_satoshis, push_msat, user_id, None, handle)
    }

    fn create_channel_with_custom_config(their_network_key: PublicKey, channel_value_satoshis: u64, push_msat: u64, user_id: u64, override_config: Ref<UserConfig>, handle: FFIArcChannelManagerHandle) -> FFIResult {
        let override_config = unsafe_block!("We know it points to valid UserConfig" => override_config.as_ref());
        create_channel_inner(their_network_key, channel_value_satoshis, push_msat, user_id, Some(override_config.clone()), handle)
    }

    fn close_channel(channel_id: Ref<[u8; 32]>, handle: FFIArcChannelManagerHandle) -> FFIResult {
        let chan_man: &FFIArcChannelManager = unsafe_block!("We know handle points to valid channel_manager" => handle.as_ref());
        let channel_id: &[u8; 32] = unsafe_block!("We know it points to valid data and it lives as long as the function call" => channel_id.as_ref());
        chan_man.close_channel(channel_id)?;
        FFIResult::ok()
    }

    fn force_close_channel(channel_id: Ref<[u8; 32]>, handle: FFIArcChannelManagerHandle) -> FFIResult {
        let chan_man: &FFIArcChannelManager = unsafe_block!("We know handle points to valid channel_manager" => handle.as_ref());
        let channel_id: &[u8; 32] = unsafe_block!("We know it points to valid data and it lives as long as the function call" => channel_id.as_ref());
        chan_man.force_close_channel(channel_id);
        FFIResult::ok()
    }

    fn force_close_all_channels(handle: FFIArcChannelManagerHandle) -> FFIResult {
        let chan_man: &FFIArcChannelManager = unsafe_block!("We know handle points to valid channel_manager" => handle.as_ref());
        chan_man.force_close_all_channels();
        FFIResult::ok()
    }

    fn process_pending_htlc_forwards(handle: FFIArcChannelManagerHandle) -> FFIResult {
        let chan_man: &FFIArcChannelManager = unsafe_block!("We know handle points to valid channel_manager" => handle.as_ref());
        chan_man.process_pending_htlc_forwards();
        FFIResult::ok()
    }

    fn timer_chan_freshness_every_min(handle: FFIArcChannelManagerHandle) -> FFIResult {
        let chan_man: &FFIArcChannelManager = unsafe_block!("We know handle points to valid channel_manager" => handle.as_ref());
        chan_man.timer_chan_freshness_every_min();
        FFIResult::ok()
    }

    fn fail_htlc_backwards(payment_hash: Ref<FFISha256dHash>, payment_secret: Ref<FFISecret>, handle: FFIArcChannelManagerHandle, result: Out<Bool>) -> FFIResult {
        let payment_secret: &FFISecret = unsafe_block!("it points to valid data and lives as long as the function call" => payment_secret.as_ref());
        let payment_secret: Option<PaymentSecret> = Some(payment_secret.clone().try_into()?);
        let r = fail_htlc_backwards_inner(payment_hash, &payment_secret, handle)?;
        unsafe_block!("We know out parameter is writable" => result.init(r.into()));
        FFIResult::ok()
    }

    fn fail_htlc_backwards_without_secret(payment_hash: Ref<FFISha256dHash>, handle: FFIArcChannelManagerHandle, result: Out<Bool>) -> FFIResult {
        let r = fail_htlc_backwards_inner(payment_hash, &None, handle)?;
        unsafe_block!("We know out parameter is writable" => result.init(r.into()));
        FFIResult::ok()
    }

    fn send_payment(handle: FFIArcChannelManagerHandle, route_ref: Ref<FFIRoute>, payment_hash_ref: Ref<FFISha256dHash>, payment_secret_ref: Ref<FFISecret>) -> FFIResult {
        let chan_man: &FFIArcChannelManager = unsafe_block!("We know handle points to valid channel_manager" => handle.as_ref());
        let route_ffi: &FFIRoute = unsafe_block!("We know it points to valid route data" => route_ref.as_ref());
        let payment_hash_ffi: &FFISha256dHash = unsafe_block!("We know it points to valid hash data" => payment_hash_ref.as_ref());
        let payment_hash: PaymentHash = payment_hash_ffi.clone().try_into()?;
        let payment_secret: &FFISecret = unsafe_block!("We know it points to valid payment_secret data or empty 32 bytes" => payment_secret_ref.as_ref());
        let maybe_secret = if payment_secret.as_ref().is_empty() { None } else { Some(payment_secret.clone().try_into()?) };
        let route: Route = route_ffi.clone().try_into()?;
        chan_man.send_payment(&route, payment_hash, &maybe_secret)?;
        FFIResult::ok()
    }

    fn funding_transaction_generated(temporary_channel_id: Ref<[u8;32]>, funding_txo: FFIOutPoint, handle: FFIArcChannelManagerHandle) -> FFIResult { let chan_man: &FFIArcChannelManager = unsafe_block!("We know handle points to a valid channel_manager" => handle.as_ref());
        let temporary_channel_id: &[u8; 32] = unsafe_block!("data lives as long as this function and it points to a valid value" => temporary_channel_id.as_ref());
        let funding_txo: OutPoint = funding_txo.try_into()?;
        chan_man.funding_transaction_generated(temporary_channel_id, funding_txo);
        FFIResult::ok()
    }

    fn claim_funds(payment_preimage: Ref<[u8; 32]>, payment_secret: Ref<[u8; 32]>, expected_amount: u64, handle: FFIArcChannelManagerHandle, result: Out<Bool>) -> FFIResult {
        let payment_secret: &[u8;32] = unsafe_block!("" => payment_secret.as_ref());
        let payment_secret: Option<PaymentSecret> = Some(PaymentSecret(payment_secret.clone()));
        let r = claim_funds_inner(payment_preimage, payment_secret, expected_amount, handle);
        unsafe_block!("We know out parameter is writable" => result.init(r.into()));
        FFIResult::ok()
    }

    fn update_fee(channel_id: Ref<[u8; 32]>, feerate_per_kw: u64, handle: FFIArcChannelManagerHandle) -> FFIResult {
        let chan_man: &FFIArcChannelManager = unsafe_block!("We know handle points to valid channel_manager" => handle.as_ref());
        let channel_id: &[u8;32] = unsafe_block!("" => channel_id.as_ref());
        chan_man.update_fee(channel_id.clone(), feerate_per_kw)?;
        FFIResult::ok()
    }

    fn get_and_clear_pending_events(handle: FFIArcChannelManagerHandle, events: Out<FFIEvents>) -> FFIResult {
        let chan_man: &FFIArcChannelManager = unsafe_block!("We know handle points to valid channel_manager" => handle.as_ref());
        let e = chan_man.get_and_clear_pending_events().try_into()?;
        unsafe_block!("We know out parameter is writable" => events.init(e));
        FFIResult::ok()
    }

    fn release_ffi_channel_manager(handle: FFIArcChannelManagerHandle) -> FFIResult {
        unsafe_block!("The upstream caller guarantees the handle will not be accessed after being freed" => FFIArcChannelManagerHandle::dealloc(handle, |mut handle| {
            FFIResult::ok()
        }))
    }
}

