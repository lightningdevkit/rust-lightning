// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Onion message utility methods live here.

use bitcoin::hashes::{Hash, HashEngine};
use bitcoin::hashes::hmac::{Hmac, HmacEngine};
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::secp256k1::{self, PublicKey, Secp256k1, SecretKey, Scalar};
use bitcoin::secp256k1::ecdh::SharedSecret;

use ln::onion_utils;
use super::blinded_route::BlindedRoute;
use super::messenger::Destination;

use prelude::*;

// TODO: DRY with onion_utils::construct_onion_keys_callback
#[inline]
pub(super) fn construct_keys_callback<T: secp256k1::Signing + secp256k1::Verification,
	FType: FnMut(PublicKey, SharedSecret, PublicKey, [u8; 32], Option<PublicKey>, Option<Vec<u8>>)>(
	secp_ctx: &Secp256k1<T>, unblinded_path: &[PublicKey], destination: Option<Destination>,
	session_priv: &SecretKey, mut callback: FType
) -> Result<(), secp256k1::Error> {
	let mut msg_blinding_point_priv = session_priv.clone();
	let mut msg_blinding_point = PublicKey::from_secret_key(secp_ctx, &msg_blinding_point_priv);
	let mut onion_packet_pubkey_priv = msg_blinding_point_priv.clone();
	let mut onion_packet_pubkey = msg_blinding_point.clone();

	macro_rules! build_keys {
		($pk: expr, $blinded: expr, $encrypted_payload: expr) => {{
			let encrypted_data_ss = SharedSecret::new(&$pk, &msg_blinding_point_priv);

			let blinded_hop_pk = if $blinded { $pk } else {
				let hop_pk_blinding_factor = {
					let mut hmac = HmacEngine::<Sha256>::new(b"blinded_node_id");
					hmac.input(encrypted_data_ss.as_ref());
					Hmac::from_engine(hmac).into_inner()
				};
				$pk.mul_tweak(secp_ctx, &Scalar::from_be_bytes(hop_pk_blinding_factor).unwrap())?
			};
			let onion_packet_ss = SharedSecret::new(&blinded_hop_pk, &onion_packet_pubkey_priv);

			let rho = onion_utils::gen_rho_from_shared_secret(encrypted_data_ss.as_ref());
			let unblinded_pk_opt = if $blinded { None } else { Some($pk) };
			callback(blinded_hop_pk, onion_packet_ss, onion_packet_pubkey, rho, unblinded_pk_opt, $encrypted_payload);
			(encrypted_data_ss, onion_packet_ss)
		}}
	}

	macro_rules! build_keys_in_loop {
		($pk: expr, $blinded: expr, $encrypted_payload: expr) => {
			let (encrypted_data_ss, onion_packet_ss) = build_keys!($pk, $blinded, $encrypted_payload);

			let msg_blinding_point_blinding_factor = {
				let mut sha = Sha256::engine();
				sha.input(&msg_blinding_point.serialize()[..]);
				sha.input(encrypted_data_ss.as_ref());
				Sha256::from_engine(sha).into_inner()
			};

			msg_blinding_point_priv = msg_blinding_point_priv.mul_tweak(&Scalar::from_be_bytes(msg_blinding_point_blinding_factor).unwrap())?;
			msg_blinding_point = PublicKey::from_secret_key(secp_ctx, &msg_blinding_point_priv);

			let onion_packet_pubkey_blinding_factor = {
				let mut sha = Sha256::engine();
				sha.input(&onion_packet_pubkey.serialize()[..]);
				sha.input(onion_packet_ss.as_ref());
				Sha256::from_engine(sha).into_inner()
			};
			onion_packet_pubkey_priv = onion_packet_pubkey_priv.mul_tweak(&Scalar::from_be_bytes(onion_packet_pubkey_blinding_factor).unwrap())?;
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
			Destination::BlindedRoute(BlindedRoute { blinded_hops, .. }) => {
				for hop in blinded_hops {
					build_keys_in_loop!(hop.blinded_node_id, true, Some(hop.encrypted_payload));
				}
			},
		}
	}
	Ok(())
}

/// Calculates the length of a Control TLV payload, based on the payload content.
#[macro_export]
macro_rules! get_control_tlv_length {
	($has_path_id: expr) => {{ // ReceiveControlTlvs
		get_control_tlv_length!(false, false, $has_path_id, 0, 0)
	}};
	($has_next_node_id: expr, $has_next_blinding_override: expr) => {{ // ForwardControlTlvs
		get_control_tlv_length!($has_next_node_id, $has_next_blinding_override, false, 0, 0)
	}};
	($has_next_node_id: expr, $has_next_blinding_override: expr, $has_path_id: expr, $tag_prefix_length: expr, $tag_length: expr) => {{
		// tag_prefix_length and tag_length refer to custom types in ControlTlvs, not the be
		// confused with the onion message tag.
		let mut res = 0;

		macro_rules! add_length {
			($should_add_len: expr, $prefix_len: expr, $content_len: expr) => {
				if $should_add_len {
					res += $prefix_len;
					res += $content_len;
				}
			}
		}

		add_length!($has_next_node_id, 2, 33);
		add_length!($has_next_blinding_override, 2, 33);
		add_length!($has_path_id, 2, 32);
		add_length!($tag_length > 0, $tag_prefix_length, $tag_length);

		res
	}}

	/*
	TODO:

	Also add support for payment_onion ControlTlvs also consisting of:

	payment_relay:
	2 bytes prefix
	2 bytes for cltv_expiry_delta
	4 bytes for fee_proportional_millionths
	0-4 bytes for fee_base_msat (tu32)

	payment_constraints:
	2 bytes prefix
	4 bytes max_cltv_expiry
	0-8 bytes htlc_minimum_msat (tu64)

	allowed_features:
	- If IS payment onion AND has NO known allowed_features:
	  2 bytes prefix only
	- If IS payment onion AND HAS known allowed_features:
	  2 bytes prefix
	  X bytes of allowed_features
	*/
}