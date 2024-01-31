// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Onion message utility methods live here.

use bitcoin::hashes::hmac::{Hmac, HmacEngine};
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::{Hash, HashEngine};
use bitcoin::secp256k1::ecdh::SharedSecret;
use bitcoin::secp256k1::{self, PublicKey, Scalar, Secp256k1, SecretKey};

use super::{BlindedHop, BlindedPath};
use crate::crypto::streams::ChaChaPolyWriteAdapter;
use crate::ln::msgs::DecodeError;
use crate::ln::onion_utils;
use crate::onion_message::messenger::Destination;
use crate::util::ser::{Readable, Writeable};

use crate::io;
use crate::prelude::*;

// TODO: DRY with onion_utils::construct_onion_keys_callback
#[inline]
pub(crate) fn construct_keys_callback<'a, T, I, F>(
	secp_ctx: &Secp256k1<T>, unblinded_path: I, destination: Option<Destination>,
	session_priv: &SecretKey, mut callback: F,
) -> Result<(), secp256k1::Error>
where
	T: secp256k1::Signing + secp256k1::Verification,
	I: Iterator<Item = &'a PublicKey>,
	F: FnMut(PublicKey, SharedSecret, PublicKey, [u8; 32], Option<PublicKey>, Option<Vec<u8>>),
{
	let mut msg_blinding_point_priv = session_priv.clone();
	let mut msg_blinding_point = PublicKey::from_secret_key(secp_ctx, &msg_blinding_point_priv);
	let mut onion_packet_pubkey_priv = msg_blinding_point_priv.clone();
	let mut onion_packet_pubkey = msg_blinding_point.clone();

	macro_rules! build_keys {
		($pk: expr, $blinded: expr, $encrypted_payload: expr) => {{
			let encrypted_data_ss = SharedSecret::new(&$pk, &msg_blinding_point_priv);

			let blinded_hop_pk = if $blinded {
				$pk
			} else {
				let hop_pk_blinding_factor = {
					let mut hmac = HmacEngine::<Sha256>::new(b"blinded_node_id");
					hmac.input(encrypted_data_ss.as_ref());
					Hmac::from_engine(hmac).to_byte_array()
				};
				$pk.mul_tweak(secp_ctx, &Scalar::from_be_bytes(hop_pk_blinding_factor).unwrap())?
			};
			let onion_packet_ss = SharedSecret::new(&blinded_hop_pk, &onion_packet_pubkey_priv);

			let rho = onion_utils::gen_rho_from_shared_secret(encrypted_data_ss.as_ref());
			let unblinded_pk_opt = if $blinded { None } else { Some($pk) };
			callback(
				blinded_hop_pk,
				onion_packet_ss,
				onion_packet_pubkey,
				rho,
				unblinded_pk_opt,
				$encrypted_payload,
			);
			(encrypted_data_ss, onion_packet_ss)
		}};
	}

	macro_rules! build_keys_in_loop {
		($pk: expr, $blinded: expr, $encrypted_payload: expr) => {
			let (encrypted_data_ss, onion_packet_ss) =
				build_keys!($pk, $blinded, $encrypted_payload);

			let msg_blinding_point_blinding_factor = {
				let mut sha = Sha256::engine();
				sha.input(&msg_blinding_point.serialize()[..]);
				sha.input(encrypted_data_ss.as_ref());
				Sha256::from_engine(sha).to_byte_array()
			};

			msg_blinding_point_priv = msg_blinding_point_priv
				.mul_tweak(&Scalar::from_be_bytes(msg_blinding_point_blinding_factor).unwrap())?;
			msg_blinding_point = PublicKey::from_secret_key(secp_ctx, &msg_blinding_point_priv);

			let onion_packet_pubkey_blinding_factor = {
				let mut sha = Sha256::engine();
				sha.input(&onion_packet_pubkey.serialize()[..]);
				sha.input(onion_packet_ss.as_ref());
				Sha256::from_engine(sha).to_byte_array()
			};
			onion_packet_pubkey_priv = onion_packet_pubkey_priv
				.mul_tweak(&Scalar::from_be_bytes(onion_packet_pubkey_blinding_factor).unwrap())?;
			onion_packet_pubkey = PublicKey::from_secret_key(secp_ctx, &onion_packet_pubkey_priv);
		};
	}

	for pk in unblinded_path {
		build_keys_in_loop!(*pk, false, None);
	}
	if let Some(dest) = destination {
		match dest {
			Destination::Node(pk) => {
				build_keys!(pk, false, None);
			},
			Destination::BlindedPath(BlindedPath { blinded_hops, .. }) => {
				for hop in blinded_hops {
					build_keys_in_loop!(hop.blinded_node_id, true, Some(hop.encrypted_payload));
				}
			},
		}
	}
	Ok(())
}

// Panics if `unblinded_tlvs` length is less than `unblinded_pks` length
pub(super) fn construct_blinded_hops<'a, T, I1, I2>(
	secp_ctx: &Secp256k1<T>, unblinded_pks: I1, mut unblinded_tlvs: I2, session_priv: &SecretKey,
) -> Result<Vec<BlindedHop>, secp256k1::Error>
where
	T: secp256k1::Signing + secp256k1::Verification,
	I1: Iterator<Item = &'a PublicKey>,
	I2: Iterator,
	I2::Item: Writeable,
{
	let mut blinded_hops = Vec::with_capacity(unblinded_pks.size_hint().0);
	construct_keys_callback(
		secp_ctx,
		unblinded_pks,
		None,
		session_priv,
		|blinded_node_id, _, _, encrypted_payload_rho, _, _| {
			blinded_hops.push(BlindedHop {
				blinded_node_id,
				encrypted_payload: encrypt_payload(
					unblinded_tlvs.next().unwrap(),
					encrypted_payload_rho,
				),
			});
		},
	)?;
	Ok(blinded_hops)
}

/// Encrypt TLV payload to be used as a [`crate::blinded_path::BlindedHop::encrypted_payload`].
fn encrypt_payload<P: Writeable>(payload: P, encrypted_tlvs_rho: [u8; 32]) -> Vec<u8> {
	let write_adapter = ChaChaPolyWriteAdapter::new(encrypted_tlvs_rho, &payload);
	write_adapter.encode()
}

/// Blinded path encrypted payloads may be padded to ensure they are equal length.
///
/// Reads padding to the end, ignoring what's read.
pub(crate) struct Padding {}
impl Readable for Padding {
	#[inline]
	fn read<R: io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
		loop {
			let mut buf = [0; 8192];
			if reader.read(&mut buf[..])? == 0 {
				break;
			}
		}
		Ok(Self {})
	}
}
