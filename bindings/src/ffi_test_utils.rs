use crate::error::FFIResult;
use lightning::util::events::Event;
use lightning::chain::transaction::OutPoint;
use bitcoin::hash_types::Txid;
use hex;
use crate::adaptors::primitives::FFIEvents;
use crate::utils::into_fixed_buffer;
use crate::Out;
use lightning::ln::channelmanager::{PaymentHash, PaymentSecret, PaymentPreimage};
use bitcoin_hashes::core::time::Duration;
use lightning::chain::keysinterface::SpendableOutputDescriptor;
use bitcoin::TxOut;


// These tests should be used for asserting that the wrapper can receive expected items from rust.
ffi! {
    fn ffi_test_error() -> FFIResult {
        use std::io;

        FFIResult::internal_error().context(io::Error::new(io::ErrorKind::Other, "A test error."))
    }

    fn ffi_test_ok() -> FFIResult {
        FFIResult::ok()
    }

    fn test_event_serialization(buf_out: Out<u8>, buf_len: usize, actual_len: Out<usize>) -> FFIResult {
        let mut events =  Vec::with_capacity(5);

        let txid = bitcoin::consensus::deserialize(&hex::decode("4141414141414141414141414141414141414141414141414141414141414142").unwrap()).unwrap();
        let funding_txo = OutPoint{ txid, index: 1};
        let user_channel_id = 1111;
        events.push(Event::FundingBroadcastSafe {funding_txo, user_channel_id} );

        let payment_hash = PaymentHash([2;32]);
        let payment_secret = Some(PaymentSecret([3; 32]));
        let amt = 50000;
        events.push(Event::PaymentReceived {payment_secret, payment_hash, amt});


        let payment_preimage = PaymentPreimage([4;32]);
        events.push(Event::PaymentSent {payment_preimage});

        let payment_hash = PaymentHash([5;32]);
        let rejected_by_dest = true;
        events.push(Event::PaymentFailed {payment_hash, rejected_by_dest});

        let time_forwardable = Duration::from_millis(100);
        events.push(Event::PendingHTLCsForwardable {time_forwardable});

        // expected txid for this tx is "1e8a6ed582813120a85e1dfed1249f1a32f530ba4b3fbabf4047cfbc1faea28c"
        let tx: bitcoin::blockdata::transaction::Transaction = bitcoin::consensus::deserialize(&hex::decode("02000000000101b7ab83b98315c8e44e92aef50e2f43e3e21b1ca3a6299cbe72fa78caed5b49140000000000feffffff026c5f042a0100000016001438ce449f272f685f24c9d741444bc5224a62749ea086010000000000220020debbba2af4c4f581437a66e3e8d839e883f9c2ec8c7a12d002aba7317170284002473044022006f1e5f46202752b2ac41ce524f88c95f51d97adf39f5b120ae2576329b7bb1802202ecdad16893b28deeb5886db76dc52b8ccbfc02a185c6e159b30f4c86bf922a801210333218b9a0778cd13c3bc2d8eb73962cb4f4b4528ef359f120aa961c39a8bdb66d2000000").unwrap()).unwrap();
        let outpoint = bitcoin::blockdata::transaction::OutPoint::new(tx.txid(), 1);
        let output = TxOut {value: 255, script_pubkey: bitcoin::blockdata::script::Script::new() };
        let static_output = SpendableOutputDescriptor::StaticOutput {outpoint, output: output.clone()};

        let per_commitment_point = bitcoin::secp256k1::key::PublicKey::from_slice(&hex::decode("02aca35d6de21baefaf65db590611fabd42ed4d52683c36caff58761d309314f65").unwrap()).unwrap();
        let remote_revocation_pubkey = bitcoin::secp256k1::key::PublicKey::from_slice(&hex::decode("02812cb18bf5c19374b34419095a09aa0b0d5559a24ce0ef558845230b0a096161").unwrap()).unwrap();
        let dynamic_output_p2wsh = SpendableOutputDescriptor::DynamicOutputP2WSH {
            outpoint,
            per_commitment_point,
            to_self_delay: 144,
            key_derivation_params: (3, 4),
            output,
            remote_revocation_pubkey
        };
        let outputs = vec![static_output, dynamic_output_p2wsh];
        events.push(Event::SpendableOutputs {outputs});

        let mut e = FFIEvents{ events };
        let buf = unsafe_block!("The buffer lives as long as this function, the length is within the buffer and the buffer won't be read before initialization" => buf_out.as_uninit_bytes_mut(buf_len));
        into_fixed_buffer(&mut e, buf, &mut actual_len)
    }

}
