// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Utilities for testing BOLT 12 Offers interfaces

use bitcoin::secp256k1::{Keypair, PublicKey, Secp256k1, SecretKey};
use bitcoin::secp256k1::schnorr::Signature;

use core::time::Duration;
use crate::blinded_path::BlindedHop;
use crate::blinded_path::payment::{BlindedPayInfo, BlindedPaymentPath};
use crate::sign::EntropySource;
use crate::ln::types::PaymentHash;
use crate::ln::features::BlindedHopFeatures;
use crate::offers::merkle::TaggedHash;

#[allow(unused_imports)]
use crate::prelude::*;

pub(crate) fn fail_sign<T: AsRef<TaggedHash>>(_message: &T) -> Result<Signature, ()> {
	Err(())
}

pub(crate) fn payer_keys() -> Keypair {
	let secp_ctx = Secp256k1::new();
	Keypair::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[42; 32]).unwrap())
}

pub(crate) fn payer_sign<T: AsRef<TaggedHash>>(message: &T) -> Result<Signature, ()> {
	let secp_ctx = Secp256k1::new();
	let keys = Keypair::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[42; 32]).unwrap());
	Ok(secp_ctx.sign_schnorr_no_aux_rand(message.as_ref().as_digest(), &keys))
}

pub(crate) fn payer_pubkey() -> PublicKey {
	payer_keys().public_key()
}

pub(crate) fn recipient_keys() -> Keypair {
	let secp_ctx = Secp256k1::new();
	Keypair::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[43; 32]).unwrap())
}

pub(crate) fn recipient_sign<T: AsRef<TaggedHash>>(message: &T) -> Result<Signature, ()> {
	let secp_ctx = Secp256k1::new();
	let keys = Keypair::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[43; 32]).unwrap());
	Ok(secp_ctx.sign_schnorr_no_aux_rand(message.as_ref().as_digest(), &keys))
}

pub(crate) fn recipient_pubkey() -> PublicKey {
	recipient_keys().public_key()
}

pub(super) fn pubkey(byte: u8) -> PublicKey {
	let secp_ctx = Secp256k1::new();
	PublicKey::from_secret_key(&secp_ctx, &privkey(byte))
}

pub(super) fn privkey(byte: u8) -> SecretKey {
	SecretKey::from_slice(&[byte; 32]).unwrap()
}

pub(crate) fn payment_paths() -> Vec<BlindedPaymentPath> {
	vec![
		BlindedPaymentPath::from_raw(
			pubkey(40), pubkey(41),
			vec![
				BlindedHop { blinded_node_id: pubkey(43), encrypted_payload: vec![0; 43] },
				BlindedHop { blinded_node_id: pubkey(44), encrypted_payload: vec![0; 44] },
			],
			BlindedPayInfo {
				fee_base_msat: 1,
				fee_proportional_millionths: 1_000,
				cltv_expiry_delta: 42,
				htlc_minimum_msat: 100,
				htlc_maximum_msat: 1_000_000_000_000,
				features: BlindedHopFeatures::empty(),
			},
		),
		BlindedPaymentPath::from_raw(
			pubkey(40), pubkey(41),
			vec![
				BlindedHop { blinded_node_id: pubkey(45), encrypted_payload: vec![0; 45] },
				BlindedHop { blinded_node_id: pubkey(46), encrypted_payload: vec![0; 46] },
			],
			BlindedPayInfo {
				fee_base_msat: 1,
				fee_proportional_millionths: 1_000,
				cltv_expiry_delta: 42,
				htlc_minimum_msat: 100,
				htlc_maximum_msat: 1_000_000_000_000,
				features: BlindedHopFeatures::empty(),
			},
		),
	]
}

pub(crate) fn payment_hash() -> PaymentHash {
	PaymentHash([42; 32])
}

pub(crate) fn now() -> Duration {
	std::time::SystemTime::now()
		.duration_since(std::time::SystemTime::UNIX_EPOCH)
		.expect("SystemTime::now() should come after SystemTime::UNIX_EPOCH")
}

pub(crate) struct FixedEntropy;

impl EntropySource for FixedEntropy {
	fn get_secure_random_bytes(&self) -> [u8; 32] {
		[42; 32]
	}
}
