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
use crate::crypto::streams::ChaChaPolyWriteAdapter;
use crate::io;
use crate::ln::onion_utils;
use crate::onion_message::messenger::Destination;
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
					pk.mul_tweak(
						$secp_ctx,
						&Scalar::from_be_bytes(hop_pk_blinding_factor).unwrap(),
					)?
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

				msg_blinding_point_priv = msg_blinding_point_priv.mul_tweak(
					&Scalar::from_be_bytes(msg_blinding_point_blinding_factor).unwrap(),
				)?;
				msg_blinding_point =
					PublicKey::from_secret_key($secp_ctx, &msg_blinding_point_priv);

				let onion_packet_pubkey_blinding_factor = {
					let mut sha = Sha256::engine();
					sha.input(&onion_packet_pubkey.serialize()[..]);
					sha.input(onion_packet_ss.as_ref());
					Sha256::from_engine(sha).to_byte_array()
				};
				onion_packet_pubkey_priv = onion_packet_pubkey_priv.mul_tweak(
					&Scalar::from_be_bytes(onion_packet_pubkey_blinding_factor).unwrap(),
				)?;
				onion_packet_pubkey =
					PublicKey::from_secret_key($secp_ctx, &onion_packet_pubkey_priv);
			};
		}
	};
}

#[inline]
pub(crate) fn construct_keys_for_onion_message<'a, T, I, F>(
	secp_ctx: &Secp256k1<T>, unblinded_path: I, destination: Destination, session_priv: &SecretKey,
	mut callback: F,
) -> Result<(), secp256k1::Error>
where
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
	Ok(())
}

#[inline]
pub(super) fn construct_keys_for_blinded_path<'a, T, I, F, H>(
	secp_ctx: &Secp256k1<T>, unblinded_path: I, session_priv: &SecretKey, mut callback: F,
) -> Result<(), secp256k1::Error>
where
	T: secp256k1::Signing + secp256k1::Verification,
	H: Borrow<PublicKey>,
	I: Iterator<Item = H>,
	F: FnMut(PublicKey, SharedSecret, PublicKey, [u8; 32], Option<H>, Option<Vec<u8>>),
{
	build_keys_helper!(session_priv, secp_ctx, callback);

	for pk in unblinded_path {
		build_keys_in_loop!(pk, false, None);
	}
	Ok(())
}

struct PublicKeyWithTlvs<W: Writeable> {
	pubkey: PublicKey,
	tlvs: W,
}

impl<W: Writeable> Borrow<PublicKey> for PublicKeyWithTlvs<W> {
	fn borrow(&self) -> &PublicKey {
		&self.pubkey
	}
}

pub(crate) fn construct_blinded_hops<'a, T, I, W>(
	secp_ctx: &Secp256k1<T>, unblinded_path: I, session_priv: &SecretKey,
) -> Result<Vec<BlindedHop>, secp256k1::Error>
where
	T: secp256k1::Signing + secp256k1::Verification,
	I: Iterator<Item = (PublicKey, W)>,
	W: Writeable,
{
	let mut blinded_hops = Vec::with_capacity(unblinded_path.size_hint().0);
	construct_keys_for_blinded_path(
		secp_ctx,
		unblinded_path.map(|(pubkey, tlvs)| PublicKeyWithTlvs { pubkey, tlvs }),
		session_priv,
		|blinded_node_id, _, _, encrypted_payload_rho, unblinded_hop_data, _| {
			blinded_hops.push(BlindedHop {
				blinded_node_id,
				encrypted_payload: encrypt_payload(
					unblinded_hop_data.unwrap().tlvs,
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

		let padding_length =
			(total_length + self.round_off - 1) / self.round_off * self.round_off - total_length;

		let padding = Some(BlindedPathPadding::new(padding_length));

		encode_tlv_stream!(writer, {
			(1, padding, option),
		});

		self.tlvs.write(writer)
	}
}

#[cfg(test)]
/// Checks if all the packets in the blinded path are properly padded.
pub fn is_padded(hops: &[BlindedHop], padding_round_off: usize) -> bool {
	let first_hop = hops.first().expect("BlindedPath must have at least one hop");
	let first_payload_size = first_hop.encrypted_payload.len();

	// The unencrypted payload data is padded before getting encrypted.
	// Assuming the first payload is padded properly, get the extra data length.
	let extra_length = first_payload_size % padding_round_off;
	hops.iter().all(|hop| {
		// Check that every packet is padded to the round off length subtracting the extra length.
		(hop.encrypted_payload.len() - extra_length) % padding_round_off == 0
	})
}
