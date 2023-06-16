// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Utilities for testing BOLT 12 Offers interfaces

use bitcoin::secp256k1::{KeyPair, Message, PublicKey, Secp256k1, SecretKey};
use bitcoin::secp256k1::schnorr::Signature;
use core::convert::Infallible;
use core::time::Duration;
use crate::blinded_path::{BlindedHop, BlindedPath};
use crate::sign::EntropySource;
use crate::ln::PaymentHash;
use crate::ln::features::BlindedHopFeatures;
use crate::offers::invoice::BlindedPayInfo;

pub(super) fn payer_keys() -> KeyPair {
	let secp_ctx = Secp256k1::new();
	KeyPair::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[42; 32]).unwrap())
}

pub(super) fn payer_sign(digest: &Message) -> Result<Signature, Infallible> {
	let secp_ctx = Secp256k1::new();
	let keys = KeyPair::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[42; 32]).unwrap());
	Ok(secp_ctx.sign_schnorr_no_aux_rand(digest, &keys))
}

pub(super) fn payer_pubkey() -> PublicKey {
	payer_keys().public_key()
}

pub(super) fn recipient_keys() -> KeyPair {
	let secp_ctx = Secp256k1::new();
	KeyPair::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[43; 32]).unwrap())
}

pub(super) fn recipient_sign(digest: &Message) -> Result<Signature, Infallible> {
	let secp_ctx = Secp256k1::new();
	let keys = KeyPair::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[43; 32]).unwrap());
	Ok(secp_ctx.sign_schnorr_no_aux_rand(digest, &keys))
}

pub(super) fn recipient_pubkey() -> PublicKey {
	recipient_keys().public_key()
}

pub(super) fn pubkey(byte: u8) -> PublicKey {
	let secp_ctx = Secp256k1::new();
	PublicKey::from_secret_key(&secp_ctx, &privkey(byte))
}

pub(super) fn privkey(byte: u8) -> SecretKey {
	SecretKey::from_slice(&[byte; 32]).unwrap()
}

pub(super) fn payment_paths() -> Vec<(BlindedPayInfo, BlindedPath)> {
	let paths = vec![
		BlindedPath {
			introduction_node_id: pubkey(40),
			blinding_point: pubkey(41),
			blinded_hops: vec![
				BlindedHop { blinded_node_id: pubkey(43), encrypted_payload: vec![0; 43] },
				BlindedHop { blinded_node_id: pubkey(44), encrypted_payload: vec![0; 44] },
			],
		},
		BlindedPath {
			introduction_node_id: pubkey(40),
			blinding_point: pubkey(41),
			blinded_hops: vec![
				BlindedHop { blinded_node_id: pubkey(45), encrypted_payload: vec![0; 45] },
				BlindedHop { blinded_node_id: pubkey(46), encrypted_payload: vec![0; 46] },
			],
		},
	];

	let payinfo = vec![
		BlindedPayInfo {
			fee_base_msat: 1,
			fee_proportional_millionths: 1_000,
			cltv_expiry_delta: 42,
			htlc_minimum_msat: 100,
			htlc_maximum_msat: 1_000_000_000_000,
			features: BlindedHopFeatures::empty(),
		},
		BlindedPayInfo {
			fee_base_msat: 1,
			fee_proportional_millionths: 1_000,
			cltv_expiry_delta: 42,
			htlc_minimum_msat: 100,
			htlc_maximum_msat: 1_000_000_000_000,
			features: BlindedHopFeatures::empty(),
		},
	];

	payinfo.into_iter().zip(paths.into_iter()).collect()
}

pub(super) fn payment_hash() -> PaymentHash {
	PaymentHash([42; 32])
}

pub(super) fn now() -> Duration {
	std::time::SystemTime::now()
		.duration_since(std::time::SystemTime::UNIX_EPOCH)
		.expect("SystemTime::now() should come after SystemTime::UNIX_EPOCH")
}

pub(super) struct FixedEntropy;

impl EntropySource for FixedEntropy {
	fn get_secure_random_bytes(&self) -> [u8; 32] {
		[42; 32]
	}
}
