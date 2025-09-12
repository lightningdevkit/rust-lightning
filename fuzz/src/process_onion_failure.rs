use std::sync::Arc;

use bitcoin::{
	key::Secp256k1,
	secp256k1::{PublicKey, SecretKey},
};
use lightning::{
	blinded_path::BlindedHop,
	ln::{
		channelmanager::{HTLCSource, PaymentId},
		msgs::OnionErrorPacket,
	},
	routing::router::{BlindedTail, Path, RouteHop, TrampolineHop},
	types::features::{ChannelFeatures, NodeFeatures},
	util::logger::Logger,
};

// Imports that need to be added manually
use crate::utils::test_logger::{self};

/// Actual fuzz test, method signature and name are fixed
fn do_test<Out: test_logger::Output>(data: &[u8], out: Out) {
	let mut read_pos = 0;
	macro_rules! get_slice {
		($len: expr) => {{
			let slice_len = $len as usize;
			if data.len() < read_pos + slice_len {
				return;
			}
			read_pos += slice_len;
			&data[read_pos - slice_len..read_pos]
		}};
	}

	macro_rules! get_u16 {
		() => {
			match get_slice!(2).try_into() {
				Ok(val) => u16::from_be_bytes(val),
				Err(_) => return,
			}
		};
	}

	macro_rules! get_bool {
		() => {
			get_slice!(1)[0] & 1 != 0
		};
	}

	fn usize_to_32_bytes(input: usize) -> [u8; 32] {
		let mut bytes = [0u8; 32];
		let input_bytes = input.to_be_bytes();
		bytes[..input_bytes.len()].copy_from_slice(&input_bytes);
		bytes
	}

	fn usize_to_pubkey(input: usize) -> PublicKey {
		let bytes = usize_to_32_bytes(1 + input);

		let secp_ctx = Secp256k1::new();
		let secret_key = SecretKey::from_slice(&bytes).unwrap();
		secret_key.public_key(&secp_ctx)
	}

	let secp_ctx = Secp256k1::new();
	let logger: Arc<dyn Logger> = Arc::new(test_logger::TestLogger::new("".to_owned(), out));

	let session_priv = SecretKey::from_slice(&usize_to_32_bytes(213127)).unwrap();
	let payment_id = PaymentId(usize_to_32_bytes(232299));

	let mut hops = Vec::<RouteHop>::new();
	let hop_count = get_slice!(1)[0] as usize % 30;
	for i in 0..hop_count {
		hops.push(RouteHop {
			pubkey: usize_to_pubkey(i),
			node_features: NodeFeatures::empty(),
			short_channel_id: i as u64,
			channel_features: ChannelFeatures::empty(),
			fee_msat: 0,
			cltv_expiry_delta: 0,
			maybe_announced_channel: false,
		});
	}

	let blinded_tail = if get_bool!() {
		let mut trampoline_hops = Vec::<TrampolineHop>::new();
		let trampoline_hop_count = get_slice!(1)[0] as usize % 30;
		for i in 0..trampoline_hop_count {
			trampoline_hops.push(TrampolineHop {
				pubkey: usize_to_pubkey(1000 + i),
				node_features: NodeFeatures::empty(),
				fee_msat: 0,
				cltv_expiry_delta: 0,
			});
		}
		let mut blinded_hops = Vec::<BlindedHop>::new();
		let blinded_hop_count = get_slice!(1)[0] as usize % 30;
		for i in 0..blinded_hop_count {
			blinded_hops.push(BlindedHop {
				blinded_node_id: usize_to_pubkey(2000 + i),
				encrypted_payload: get_slice!(get_u16!()).to_vec(),
			});
		}
		Some(BlindedTail {
			trampoline_hops,
			hops: blinded_hops,
			blinding_point: usize_to_pubkey(64354334),
			excess_final_cltv_expiry_delta: 0,
			final_value_msat: 0,
		})
	} else {
		None
	};

	let path = Path { hops, blinded_tail };

	let htlc_source = HTLCSource::OutboundRoute {
		path: path.clone(),
		session_priv,
		first_hop_htlc_msat: 0,
		payment_id,
		bolt12_invoice: None,
		hold_htlc: None,
	};

	let failure_len = get_u16!();
	let failure_data = get_slice!(failure_len);

	let attribution_data = if get_bool!() {
		Some(lightning::ln::AttributionData {
			hold_times: get_slice!(80).try_into().unwrap(),
			hmacs: get_slice!(840).try_into().unwrap(),
		})
	} else {
		None
	};
	let encrypted_packet =
		OnionErrorPacket { data: failure_data.into(), attribution_data: attribution_data.clone() };
	lightning::ln::process_onion_failure(&secp_ctx, &logger, &htlc_source, encrypted_packet);

	if let Some(attribution_data) = attribution_data {
		lightning::ln::decode_fulfill_attribution_data(
			&secp_ctx,
			&logger,
			&path,
			&session_priv,
			attribution_data,
		);
	}
}

/// Method that needs to be added manually, {name}_test
pub fn process_onion_failure_test<Out: test_logger::Output>(data: &[u8], out: Out) {
	do_test(data, out);
}

/// Method that needs to be added manually, {name}_run
#[no_mangle]
pub extern "C" fn process_onion_failure_run(data: *const u8, datalen: usize) {
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) }, test_logger::DevNull {});
}
