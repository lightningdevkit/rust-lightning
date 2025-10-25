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

use super::message::BlindedMessagePath;
use super::{BlindedHop, BlindedPath};
use crate::crypto::streams::{chachapoly_encrypt_with_swapped_aad, ChaChaPolyWriteAdapter};
use crate::io;
use crate::ln::onion_utils;
use crate::onion_message::messenger::Destination;
use crate::sign::ReceiveAuthKey;
use crate::util::ser::{Writeable, Writer};

use core::borrow::Borrow;

#[allow(unused_imports)]
use crate::prelude::*;

// TODO: DRY with onion_utils::construct_onion_keys_callback
macro_rules! build_keys_helper {
	($session_priv: ident, $secp_ctx: ident, $callback: ident) => {
		let mut msg_blinding_point_priv = $session_priv.clone();
		let mut msg_blinding_point =
			PublicKey::from_secret_key($secp_ctx, &msg_blinding_point_priv);
		let mut onion_packet_pubkey_priv = msg_blinding_point_priv.clone();
		let mut onion_packet_pubkey = msg_blinding_point.clone();

		macro_rules! build_keys {
			($hop: expr, $blinded: expr, $encrypted_payload: expr) => {{
				let pk = *$hop.borrow();
				let encrypted_data_ss = SharedSecret::new(&pk, &msg_blinding_point_priv);

				let blinded_hop_pk = if $blinded {
					pk
				} else {
					let hop_pk_blinding_factor = {
						let mut hmac = HmacEngine::<Sha256>::new(b"blinded_node_id");
						hmac.input(encrypted_data_ss.as_ref());
						Hmac::from_engine(hmac).to_byte_array()
					};
					pk.mul_tweak($secp_ctx, &Scalar::from_be_bytes(hop_pk_blinding_factor).unwrap())
						.expect("RNG is busted")
				};
				let onion_packet_ss = SharedSecret::new(&blinded_hop_pk, &onion_packet_pubkey_priv);

				let rho = onion_utils::gen_rho_from_shared_secret(encrypted_data_ss.as_ref());
				let unblinded_hop_opt = if $blinded { None } else { Some($hop) };
				$callback(
					blinded_hop_pk,
					onion_packet_ss,
					onion_packet_pubkey,
					rho,
					unblinded_hop_opt,
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
					.mul_tweak(&Scalar::from_be_bytes(msg_blinding_point_blinding_factor).unwrap())
					.expect("RNG is busted");
				msg_blinding_point =
					PublicKey::from_secret_key($secp_ctx, &msg_blinding_point_priv);

				let onion_packet_pubkey_blinding_factor = {
					let mut sha = Sha256::engine();
					sha.input(&onion_packet_pubkey.serialize()[..]);
					sha.input(onion_packet_ss.as_ref());
					Sha256::from_engine(sha).to_byte_array()
				};
				onion_packet_pubkey_priv = onion_packet_pubkey_priv
					.mul_tweak(&Scalar::from_be_bytes(onion_packet_pubkey_blinding_factor).unwrap())
					.expect("RNG is busted");
				onion_packet_pubkey =
					PublicKey::from_secret_key($secp_ctx, &onion_packet_pubkey_priv);
			};
		}
	};
}

pub(crate) fn construct_keys_for_onion_message<'a, T, I, F>(
	secp_ctx: &Secp256k1<T>, unblinded_path: I, destination: Destination, session_priv: &SecretKey,
	mut callback: F,
) where
	T: secp256k1::Signing + secp256k1::Verification,
	I: Iterator<Item = PublicKey>,
	F: FnMut(SharedSecret, PublicKey, [u8; 32], Option<PublicKey>, Option<Vec<u8>>),
{
	let mut callback_wrapper =
		|_, ss, pk, encrypted_payload_rho, unblinded_hop_data, encrypted_payload| {
			callback(ss, pk, encrypted_payload_rho, unblinded_hop_data, encrypted_payload);
		};
	build_keys_helper!(session_priv, secp_ctx, callback_wrapper);

	for pk in unblinded_path {
		build_keys_in_loop!(pk, false, None);
	}
	match destination {
		Destination::Node(pk) => {
			build_keys!(pk, false, None);
		},
		Destination::BlindedPath(BlindedMessagePath(BlindedPath { blinded_hops, .. })) => {
			for hop in blinded_hops {
				build_keys_in_loop!(hop.blinded_node_id, true, Some(hop.encrypted_payload));
			}
		},
	}
}

fn construct_keys_for_blinded_path<'a, T, I, F, H>(
	secp_ctx: &Secp256k1<T>, unblinded_path: I, session_priv: &SecretKey, mut callback: F,
) where
	T: secp256k1::Signing + secp256k1::Verification,
	H: Borrow<PublicKey>,
	I: Iterator<Item = H>,
	F: FnMut(PublicKey, SharedSecret, PublicKey, [u8; 32], Option<H>, Option<Vec<u8>>),
{
	build_keys_helper!(session_priv, secp_ctx, callback);

	for pk in unblinded_path {
		build_keys_in_loop!(pk, false, None);
	}
}

struct PublicKeyWithTlvs<W: Writeable> {
	pubkey: PublicKey,
	hop_recv_key: Option<ReceiveAuthKey>,
	tlvs: W,
}

impl<W: Writeable> Borrow<PublicKey> for PublicKeyWithTlvs<W> {
	fn borrow(&self) -> &PublicKey {
		&self.pubkey
	}
}

pub(crate) fn construct_blinded_hops<'a, T, I, W>(
	secp_ctx: &Secp256k1<T>, unblinded_path: I, session_priv: &SecretKey,
) -> Vec<BlindedHop>
where
	T: secp256k1::Signing + secp256k1::Verification,
	I: Iterator<Item = ((PublicKey, Option<ReceiveAuthKey>), W)>,
	W: Writeable,
{
	let mut blinded_hops = Vec::with_capacity(unblinded_path.size_hint().0);
	construct_keys_for_blinded_path(
		secp_ctx,
		unblinded_path.map(|((pubkey, hop_recv_key), tlvs)| PublicKeyWithTlvs {
			pubkey,
			hop_recv_key,
			tlvs,
		}),
		session_priv,
		|blinded_node_id, _, _, encrypted_payload_rho, unblinded_hop_data, _| {
			let hop_data = unblinded_hop_data.unwrap();
			blinded_hops.push(BlindedHop {
				blinded_node_id,
				encrypted_payload: encrypt_payload(
					hop_data.tlvs,
					encrypted_payload_rho,
					hop_data.hop_recv_key,
				),
			});
		},
	);
	blinded_hops
}

/// Encrypt TLV payload to be used as a [`crate::blinded_path::BlindedHop::encrypted_payload`].
fn encrypt_payload<P: Writeable>(
	payload: P, encrypted_tlvs_rho: [u8; 32], hop_recv_key: Option<ReceiveAuthKey>,
) -> Vec<u8> {
	if let Some(hop_recv_key) = hop_recv_key {
		chachapoly_encrypt_with_swapped_aad(payload.encode(), encrypted_tlvs_rho, hop_recv_key.0)
	} else {
		let write_adapter = ChaChaPolyWriteAdapter::new(encrypted_tlvs_rho, &payload);
		write_adapter.encode()
	}
}

/// A data structure used exclusively to pad blinded path payloads, ensuring they are of
/// equal length. Padding is written at Type 1 for compatibility with the lightning specification.
///
/// For more details, see the [BOLTs Specification - Encrypted Recipient Data](https://github.com/lightning/bolts/blob/8707471dbc23245fb4d84c5f5babac1197f1583e/04-onion-routing.md#inside-encrypted_recipient_data-encrypted_data_tlv).
pub(crate) struct BlindedPathPadding {
	length: usize,
}

impl BlindedPathPadding {
	/// Creates a new [`BlindedPathPadding`] instance with a specified size.
	/// Use this method when defining the padding size before writing
	/// an encrypted payload.
	pub fn new(length: usize) -> Self {
		Self { length }
	}
}

impl Writeable for BlindedPathPadding {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		const BUFFER_SIZE: usize = 1024;
		let buffer = [0u8; BUFFER_SIZE];

		let mut remaining = self.length;
		loop {
			let to_write = core::cmp::min(remaining, BUFFER_SIZE);
			writer.write_all(&buffer[..to_write])?;
			remaining -= to_write;
			if remaining == 0 {
				break;
			}
		}
		Ok(())
	}
}

/// Padding storage requires two extra bytes:
/// - One byte for the type.
/// - One byte for the padding length.
/// This constant accounts for that overhead.
const TLV_OVERHEAD: usize = 2;

/// A generic struct that applies padding to blinded path TLVs, rounding their size off to `round_off`
pub(crate) struct BlindedPathWithPadding<T: Writeable> {
	pub(crate) tlvs: T,
	pub(crate) round_off: usize,
}

impl<T: Writeable> Writeable for BlindedPathWithPadding<T> {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		let tlv_length = self.tlvs.serialized_length();
		let total_length = tlv_length + TLV_OVERHEAD;

		let padding_length = total_length.div_ceil(self.round_off) * self.round_off - total_length;

		let padding = Some(BlindedPathPadding::new(padding_length));

		encode_tlv_stream!(writer, {
			(1, padding, option),
		});

		self.tlvs.write(writer)
	}
}

#[cfg(test)]
/// Verifies whether all hops in the blinded path follow the expected padding scheme.
///
/// In the padded encoding scheme, each hop's encrypted payload is expected to be of the form:
/// `n * padding_round_off + extra`, where:
/// - `padding_round_off` is the fixed block size to which unencrypted payloads are padded.
/// - `n` is a positive integer (n ≥ 1).
/// - `extra` is the fixed overhead added during encryption (assumed uniform across hops).
///
/// This function infers the `extra` from the first hop, and checks that all other hops conform
/// to the same pattern.
///
/// # Returns
/// - `true` if all hop payloads are padded correctly.
/// - `false` if padding is incorrectly applied or intentionally absent (e.g., in compact paths).
pub fn is_padded(hops: &[BlindedHop], padding_round_off: usize) -> bool {
	let first_hop = hops.first().expect("BlindedPath must have at least one hop");
	let first_len = first_hop.encrypted_payload.len();

	// Early rejection: if the first hop is too small, it can't be correctly padded.
	if first_len <= padding_round_off {
		return false;
	}

	let extra = first_len % padding_round_off;

	// Helper to check if a hop follows the padding pattern
	let is_hop_padded = |hop: &BlindedHop| {
		let len = hop.encrypted_payload.len();
		len > extra && (len - extra) % padding_round_off == 0
	};

	// All hops must follow the same padding structure AND
	// all hops except the final one must have the same length as the first
	// to ensure proper masking.
	hops.iter().all(is_hop_padded)
		&& hops
			.iter()
			.take(hops.len().saturating_sub(1))
			.all(|hop| hop.encrypted_payload.len() == first_len)
}
