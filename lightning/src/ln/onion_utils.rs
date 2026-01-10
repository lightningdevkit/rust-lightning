// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Low-level onion manipulation logic and fields

use super::msgs::OnionErrorPacket;
use crate::blinded_path::BlindedHop;
use crate::crypto::chacha20::ChaCha20;
use crate::crypto::streams::ChaChaReader;
use crate::events::HTLCHandlingFailureReason;
use crate::ln::channel::TOTAL_BITCOIN_SUPPLY_SATOSHIS;
use crate::ln::channelmanager::{HTLCSource, RecipientOnionFields};
use crate::ln::msgs::{self, DecodeError};
use crate::offers::invoice_request::InvoiceRequest;
use crate::routing::gossip::NetworkUpdate;
use crate::routing::router::{BlindedTail, Path, RouteHop, RouteParameters, TrampolineHop};
use crate::sign::{NodeSigner, Recipient};
use crate::types::features::{ChannelFeatures, NodeFeatures};
use crate::types::payment::{PaymentHash, PaymentPreimage};
use crate::util::errors::APIError;
use crate::util::logger::Logger;
use crate::util::ser::{
	LengthCalculatingWriter, Readable, ReadableArgs, VecWriter, Writeable, Writer,
};

use bitcoin::hashes::cmp::fixed_time_eq;
use bitcoin::hashes::hmac::{Hmac, HmacEngine};
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::{Hash, HashEngine};

use bitcoin::secp256k1;
use bitcoin::secp256k1::ecdh::SharedSecret;
use bitcoin::secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};

use crate::io::{Cursor, Read};
use core::ops::Deref;

#[allow(unused_imports)]
use crate::prelude::*;

const DEFAULT_MIN_FAILURE_PACKET_LEN: usize = 256;

/// The unit size of the hold time. This is used to reduce the hold time resolution to improve privacy.
pub(crate) const HOLD_TIME_UNIT_MILLIS: u128 = 100;

pub(crate) struct OnionKeys {
	#[cfg(test)]
	pub(crate) shared_secret: SharedSecret,
	#[cfg(test)]
	pub(crate) blinding_factor: [u8; 32],
	pub(crate) ephemeral_pubkey: PublicKey,
	pub(crate) rho: [u8; 32],
	pub(crate) mu: [u8; 32],
}

#[inline]
pub(crate) fn gen_rho_from_shared_secret(shared_secret: &[u8]) -> [u8; 32] {
	assert_eq!(shared_secret.len(), 32);
	let mut hmac = HmacEngine::<Sha256>::new(b"rho");
	hmac.input(&shared_secret);
	Hmac::from_engine(hmac).to_byte_array()
}

#[inline]
pub(crate) fn gen_rho_mu_from_shared_secret(shared_secret: &[u8]) -> ([u8; 32], [u8; 32]) {
	assert_eq!(shared_secret.len(), 32);
	let mut engine_rho = HmacEngine::<Sha256>::new(b"rho");
	engine_rho.input(&shared_secret);
	let hmac_rho = Hmac::from_engine(engine_rho).to_byte_array();

	let mut engine_mu = HmacEngine::<Sha256>::new(b"mu");
	engine_mu.input(&shared_secret);
	let hmac_mu = Hmac::from_engine(engine_mu).to_byte_array();

	(hmac_rho, hmac_mu)
}

#[inline]
pub(super) fn gen_um_from_shared_secret(shared_secret: &[u8]) -> [u8; 32] {
	assert_eq!(shared_secret.len(), 32);
	let mut hmac = HmacEngine::<Sha256>::new(b"um");
	hmac.input(&shared_secret);
	Hmac::from_engine(hmac).to_byte_array()
}

#[inline]
pub(super) fn gen_ammag_from_shared_secret(shared_secret: &[u8]) -> [u8; 32] {
	assert_eq!(shared_secret.len(), 32);
	let mut hmac = HmacEngine::<Sha256>::new(b"ammag");
	hmac.input(&shared_secret);
	Hmac::from_engine(hmac).to_byte_array()
}

#[inline]
pub(super) fn gen_ammagext_from_shared_secret(shared_secret: &[u8]) -> [u8; 32] {
	assert_eq!(shared_secret.len(), 32);
	let mut hmac = HmacEngine::<Sha256>::new(b"ammagext");
	hmac.input(&shared_secret);
	Hmac::from_engine(hmac).to_byte_array()
}

#[cfg(test)]
#[inline]
pub(super) fn gen_pad_from_shared_secret(shared_secret: &[u8]) -> [u8; 32] {
	assert_eq!(shared_secret.len(), 32);
	let mut hmac = HmacEngine::<Sha256>::new(b"pad");
	hmac.input(&shared_secret);
	Hmac::from_engine(hmac).to_byte_array()
}

/// Calculates a pubkey for the next hop, such as the next hop's packet pubkey or blinding point.
pub(crate) fn next_hop_pubkey<T: secp256k1::Verification>(
	secp_ctx: &Secp256k1<T>, curr_pubkey: PublicKey, shared_secret: &[u8],
) -> Result<PublicKey, secp256k1::Error> {
	let blinding_factor = {
		let mut sha = Sha256::engine();
		sha.input(&curr_pubkey.serialize()[..]);
		sha.input(shared_secret);
		Sha256::from_engine(sha).to_byte_array()
	};

	curr_pubkey.mul_tweak(secp_ctx, &Scalar::from_be_bytes(blinding_factor).unwrap())
}

trait HopInfo {
	fn node_pubkey(&self) -> &PublicKey;
}

trait PathHop {
	type HopId;
	fn hop_id(&self) -> Self::HopId;
	fn fee_msat(&self) -> u64;
	fn cltv_expiry_delta(&self) -> u32;
}

impl HopInfo for RouteHop {
	fn node_pubkey(&self) -> &PublicKey {
		&self.pubkey
	}
}

impl<'a> PathHop for &'a RouteHop {
	type HopId = u64; // scid

	fn hop_id(&self) -> Self::HopId {
		self.short_channel_id
	}

	fn fee_msat(&self) -> u64 {
		self.fee_msat
	}

	fn cltv_expiry_delta(&self) -> u32 {
		self.cltv_expiry_delta
	}
}

impl HopInfo for TrampolineHop {
	fn node_pubkey(&self) -> &PublicKey {
		&self.pubkey
	}
}

impl<'a> PathHop for &'a TrampolineHop {
	type HopId = PublicKey;

	fn hop_id(&self) -> Self::HopId {
		self.pubkey
	}

	fn fee_msat(&self) -> u64 {
		self.fee_msat
	}

	fn cltv_expiry_delta(&self) -> u32 {
		self.cltv_expiry_delta
	}
}

trait OnionPayload<'a, 'b> {
	type PathHopForId: PathHop + 'b;
	type ReceiveType: OnionPayload<'a, 'b>;
	fn new_forward(
		hop_id: <<Self as OnionPayload<'a, 'b>>::PathHopForId as PathHop>::HopId,
		amt_to_forward: u64, outgoing_cltv_value: u32,
	) -> Self;
	fn new_receive(
		recipient_onion: &'a RecipientOnionFields, keysend_preimage: Option<PaymentPreimage>,
		sender_intended_htlc_amt_msat: u64, total_msat: u64, cltv_expiry_height: u32,
	) -> Result<Self::ReceiveType, APIError>;
	fn new_blinded_forward(
		encrypted_tlvs: &'a Vec<u8>, intro_node_blinding_point: Option<PublicKey>,
	) -> Self;
	fn new_blinded_receive(
		sender_intended_htlc_amt_msat: u64, total_msat: u64, cltv_expiry_height: u32,
		encrypted_tlvs: &'a Vec<u8>, intro_node_blinding_point: Option<PublicKey>,
		keysend_preimage: Option<PaymentPreimage>, invoice_request: Option<&'a InvoiceRequest>,
		custom_tlvs: &'a Vec<(u64, Vec<u8>)>,
	) -> Self;
	fn new_trampoline_entry(
		total_msat: u64, amt_to_forward: u64, outgoing_cltv_value: u32,
		recipient_onion: &'a RecipientOnionFields, packet: msgs::TrampolineOnionPacket,
	) -> Result<Self::ReceiveType, APIError>;
}
impl<'a, 'b> OnionPayload<'a, 'b> for msgs::OutboundOnionPayload<'a> {
	type PathHopForId = &'b RouteHop;
	type ReceiveType = msgs::OutboundOnionPayload<'a>;
	fn new_forward(short_channel_id: u64, amt_to_forward: u64, outgoing_cltv_value: u32) -> Self {
		Self::Forward { short_channel_id, amt_to_forward, outgoing_cltv_value }
	}
	fn new_receive(
		recipient_onion: &'a RecipientOnionFields, keysend_preimage: Option<PaymentPreimage>,
		sender_intended_htlc_amt_msat: u64, total_msat: u64, cltv_expiry_height: u32,
	) -> Result<Self::ReceiveType, APIError> {
		Ok(Self::Receive {
			payment_data: recipient_onion
				.payment_secret
				.map(|payment_secret| msgs::FinalOnionHopData { payment_secret, total_msat }),
			payment_metadata: recipient_onion.payment_metadata.as_ref(),
			keysend_preimage,
			custom_tlvs: &recipient_onion.custom_tlvs,
			sender_intended_htlc_amt_msat,
			cltv_expiry_height,
		})
	}
	fn new_blinded_forward(
		encrypted_tlvs: &'a Vec<u8>, intro_node_blinding_point: Option<PublicKey>,
	) -> Self {
		Self::BlindedForward { encrypted_tlvs, intro_node_blinding_point }
	}
	fn new_blinded_receive(
		sender_intended_htlc_amt_msat: u64, total_msat: u64, cltv_expiry_height: u32,
		encrypted_tlvs: &'a Vec<u8>, intro_node_blinding_point: Option<PublicKey>,
		keysend_preimage: Option<PaymentPreimage>, invoice_request: Option<&'a InvoiceRequest>,
		custom_tlvs: &'a Vec<(u64, Vec<u8>)>,
	) -> Self {
		Self::BlindedReceive {
			sender_intended_htlc_amt_msat,
			total_msat,
			cltv_expiry_height,
			encrypted_tlvs,
			intro_node_blinding_point,
			keysend_preimage,
			invoice_request,
			custom_tlvs,
		}
	}

	fn new_trampoline_entry(
		total_msat: u64, amt_to_forward: u64, outgoing_cltv_value: u32,
		recipient_onion: &'a RecipientOnionFields, packet: msgs::TrampolineOnionPacket,
	) -> Result<Self, APIError> {
		Ok(Self::TrampolineEntrypoint {
			amt_to_forward,
			outgoing_cltv_value,
			multipath_trampoline_data: recipient_onion
				.payment_secret
				.map(|payment_secret| msgs::FinalOnionHopData { payment_secret, total_msat }),
			trampoline_packet: packet,
		})
	}
}
impl<'a, 'b> OnionPayload<'a, 'b> for msgs::OutboundTrampolinePayload<'a> {
	type PathHopForId = &'b TrampolineHop;
	type ReceiveType = msgs::OutboundTrampolinePayload<'a>;
	fn new_forward(
		outgoing_node_id: PublicKey, amt_to_forward: u64, outgoing_cltv_value: u32,
	) -> Self {
		Self::Forward { outgoing_node_id, amt_to_forward, outgoing_cltv_value }
	}
	fn new_receive(
		_recipient_onion: &'a RecipientOnionFields, _keysend_preimage: Option<PaymentPreimage>,
		_sender_intended_htlc_amt_msat: u64, _total_msat: u64, _cltv_expiry_height: u32,
	) -> Result<Self::ReceiveType, APIError> {
		Err(APIError::InvalidRoute {
			err: "Unblinded receiving is not supported for Trampoline!".to_string(),
		})
	}
	fn new_blinded_forward(
		encrypted_tlvs: &'a Vec<u8>, intro_node_blinding_point: Option<PublicKey>,
	) -> Self {
		Self::BlindedForward { encrypted_tlvs, intro_node_blinding_point }
	}
	fn new_blinded_receive(
		sender_intended_htlc_amt_msat: u64, total_msat: u64, cltv_expiry_height: u32,
		encrypted_tlvs: &'a Vec<u8>, intro_node_blinding_point: Option<PublicKey>,
		keysend_preimage: Option<PaymentPreimage>, _invoice_request: Option<&'a InvoiceRequest>,
		custom_tlvs: &'a Vec<(u64, Vec<u8>)>,
	) -> Self {
		Self::BlindedReceive {
			sender_intended_htlc_amt_msat,
			total_msat,
			cltv_expiry_height,
			encrypted_tlvs,
			intro_node_blinding_point,
			keysend_preimage,
			custom_tlvs,
		}
	}

	fn new_trampoline_entry(
		_total_msat: u64, _amt_to_forward: u64, _outgoing_cltv_value: u32,
		_recipient_onion: &'a RecipientOnionFields, _packet: msgs::TrampolineOnionPacket,
	) -> Result<Self::ReceiveType, APIError> {
		Err(APIError::InvalidRoute {
			err: "Trampoline onions cannot contain Trampoline entrypoints!".to_string(),
		})
	}
}

fn construct_onion_keys_generic<'a, T, H>(
	secp_ctx: &'a Secp256k1<T>, hops: &'a [H], blinded_tail: Option<&'a BlindedTail>,
	session_priv: &SecretKey,
) -> impl Iterator<Item = (SharedSecret, [u8; 32], PublicKey, Option<&'a H>, usize)> + 'a
where
	T: secp256k1::Signing,
	H: HopInfo,
{
	let mut blinded_priv = session_priv.clone();
	let mut blinded_pub = PublicKey::from_secret_key(secp_ctx, &blinded_priv);

	let unblinded_hops = hops.iter().map(|h| (h.node_pubkey(), Some(h)));
	let blinded_pubkeys = blinded_tail
		.map(|t| t.hops.iter())
		.unwrap_or([].iter())
		.skip(1) // Skip the intro node because it's included in the unblinded hops
		.map(|h| (&h.blinded_node_id, None));

	unblinded_hops.chain(blinded_pubkeys).enumerate().map(move |(idx, (pubkey, route_hop_opt))| {
		let shared_secret = SharedSecret::new(pubkey, &blinded_priv);

		let mut sha = Sha256::engine();
		sha.input(&blinded_pub.serialize()[..]);
		sha.input(shared_secret.as_ref());
		let blinding_factor = Sha256::from_engine(sha).to_byte_array();

		let ephemeral_pubkey = blinded_pub;

		blinded_priv = blinded_priv
			.mul_tweak(&Scalar::from_be_bytes(blinding_factor).expect("You broke SHA-256"))
			.expect("Blinding are never invalid as we picked the starting private key randomly");
		blinded_pub = PublicKey::from_secret_key(secp_ctx, &blinded_priv);

		(shared_secret, blinding_factor, ephemeral_pubkey, route_hop_opt, idx)
	})
}

// can only fail if an intermediary hop has an invalid public key or session_priv is invalid
pub(super) fn construct_onion_keys<T: secp256k1::Signing>(
	secp_ctx: &Secp256k1<T>, path: &Path, session_priv: &SecretKey,
) -> Vec<OnionKeys> {
	let mut res = Vec::with_capacity(path.hops.len());

	let blinded_tail = path.blinded_tail.as_ref().and_then(|t| {
		if !t.trampoline_hops.is_empty() {
			return None;
		}
		Some(t)
	});
	let iter = construct_onion_keys_generic(secp_ctx, &path.hops, blinded_tail, session_priv);
	for (shared_secret, _blinding_factor, ephemeral_pubkey, _, _) in iter {
		let (rho, mu) = gen_rho_mu_from_shared_secret(shared_secret.as_ref());

		res.push(OnionKeys {
			#[cfg(test)]
			shared_secret,
			#[cfg(test)]
			blinding_factor: _blinding_factor,
			ephemeral_pubkey,
			rho,
			mu,
		});
	}

	res
}

// can only fail if an intermediary hop has an invalid public key or session_priv is invalid
pub(super) fn construct_trampoline_onion_keys<T: secp256k1::Signing>(
	secp_ctx: &Secp256k1<T>, blinded_tail: &BlindedTail, session_priv: &SecretKey,
) -> Vec<OnionKeys> {
	let mut res = Vec::with_capacity(blinded_tail.trampoline_hops.len());

	let hops = &blinded_tail.trampoline_hops;
	let iter = construct_onion_keys_generic(secp_ctx, &hops, Some(blinded_tail), session_priv);
	for (shared_secret, _blinding_factor, ephemeral_pubkey, _, _) in iter {
		let (rho, mu) = gen_rho_mu_from_shared_secret(shared_secret.as_ref());

		res.push(OnionKeys {
			#[cfg(test)]
			shared_secret,
			#[cfg(test)]
			blinding_factor: _blinding_factor,
			ephemeral_pubkey,
			rho,
			mu,
		});
	}

	res
}

pub(super) fn build_trampoline_onion_payloads<'a>(
	blinded_tail: &'a BlindedTail, total_msat: u64, recipient_onion: &'a RecipientOnionFields,
	starting_htlc_offset: u32, keysend_preimage: &Option<PaymentPreimage>,
) -> Result<(Vec<msgs::OutboundTrampolinePayload<'a>>, u64, u32), APIError> {
	let mut res: Vec<msgs::OutboundTrampolinePayload> =
		Vec::with_capacity(blinded_tail.trampoline_hops.len() + blinded_tail.hops.len());
	let blinded_tail_with_hop_iter = BlindedTailDetails::DirectEntry {
		hops: blinded_tail.hops.iter(),
		blinding_point: blinded_tail.blinding_point,
		final_value_msat: blinded_tail.final_value_msat,
		excess_final_cltv_expiry_delta: blinded_tail.excess_final_cltv_expiry_delta,
	};

	let (value_msat, cltv) = build_onion_payloads_callback(
		blinded_tail.trampoline_hops.iter(),
		Some(blinded_tail_with_hop_iter),
		total_msat,
		recipient_onion,
		starting_htlc_offset,
		keysend_preimage,
		None,
		|action, payload| match action {
			PayloadCallbackAction::PushBack => res.push(payload),
			PayloadCallbackAction::PushFront => res.insert(0, payload),
		},
	)?;
	Ok((res, value_msat, cltv))
}

/// returns the hop data, as well as the first-hop value_msat and CLTV value we should send.
pub(super) fn build_onion_payloads<'a>(
	path: &'a Path, total_msat: u64, recipient_onion: &'a RecipientOnionFields,
	starting_htlc_offset: u32, keysend_preimage: &Option<PaymentPreimage>,
	invoice_request: Option<&'a InvoiceRequest>,
	trampoline_packet: Option<msgs::TrampolineOnionPacket>,
) -> Result<(Vec<msgs::OutboundOnionPayload<'a>>, u64, u32), APIError> {
	let mut res: Vec<msgs::OutboundOnionPayload> = Vec::with_capacity(
		path.hops.len() + path.blinded_tail.as_ref().map_or(0, |t| t.hops.len()),
	);

	// When Trampoline hops are present, they are presumed to follow the non-Trampoline hops, which
	// means that the blinded path needs not be appended to the regular hops, and is only included
	// among the Trampoline onion payloads.
	let blinded_tail_with_hop_iter = path.blinded_tail.as_ref().map(|bt| {
		if let Some(trampoline_packet) = trampoline_packet {
			return BlindedTailDetails::TrampolineEntry {
				trampoline_packet,
				final_value_msat: bt.final_value_msat,
			};
		}
		BlindedTailDetails::DirectEntry {
			hops: bt.hops.iter(),
			blinding_point: bt.blinding_point,
			final_value_msat: bt.final_value_msat,
			excess_final_cltv_expiry_delta: bt.excess_final_cltv_expiry_delta,
		}
	});

	let (value_msat, cltv) = build_onion_payloads_callback(
		path.hops.iter(),
		blinded_tail_with_hop_iter,
		total_msat,
		recipient_onion,
		starting_htlc_offset,
		keysend_preimage,
		invoice_request,
		|action, payload| match action {
			PayloadCallbackAction::PushBack => res.push(payload),
			PayloadCallbackAction::PushFront => res.insert(0, payload),
		},
	)?;
	Ok((res, value_msat, cltv))
}

enum BlindedTailDetails<'a, I: Iterator<Item = &'a BlindedHop>> {
	DirectEntry {
		hops: I,
		blinding_point: PublicKey,
		final_value_msat: u64,
		excess_final_cltv_expiry_delta: u32,
	},
	TrampolineEntry {
		trampoline_packet: msgs::TrampolineOnionPacket,
		final_value_msat: u64,
	},
}

enum PayloadCallbackAction {
	PushBack,
	PushFront,
}
fn build_onion_payloads_callback<'a, 'b, H, B, F, OP>(
	hops: H, mut blinded_tail: Option<BlindedTailDetails<'a, B>>, total_msat: u64,
	recipient_onion: &'a RecipientOnionFields, starting_htlc_offset: u32,
	keysend_preimage: &Option<PaymentPreimage>, invoice_request: Option<&'a InvoiceRequest>,
	mut callback: F,
) -> Result<(u64, u32), APIError>
where
	H: DoubleEndedIterator<Item = OP::PathHopForId>,
	B: ExactSizeIterator<Item = &'a BlindedHop>,
	F: FnMut(PayloadCallbackAction, OP),
	OP: OnionPayload<'a, 'b, ReceiveType = OP>,
{
	let mut cur_value_msat = 0u64;
	let mut cur_cltv = starting_htlc_offset;
	let mut last_hop_id = None;

	for (idx, hop) in hops.rev().enumerate() {
		// First hop gets special values so that it can check, on receipt, that everything is
		// exactly as it should be (and the next hop isn't trying to probe to find out if we're
		// the intended recipient).
		let value_msat = if cur_value_msat == 0 { hop.fee_msat() } else { cur_value_msat };
		let cltv = if cur_cltv == starting_htlc_offset {
			hop.cltv_expiry_delta().saturating_add(starting_htlc_offset)
		} else {
			cur_cltv
		};
		if idx == 0 {
			match blinded_tail.take() {
				Some(BlindedTailDetails::DirectEntry {
					blinding_point,
					hops,
					final_value_msat,
					excess_final_cltv_expiry_delta,
					..
				}) => {
					let mut blinding_point = Some(blinding_point);
					let hops_len = hops.len();
					for (i, blinded_hop) in hops.enumerate() {
						if i == hops_len - 1 {
							cur_value_msat += final_value_msat;
							callback(
								PayloadCallbackAction::PushBack,
								OP::new_blinded_receive(
									final_value_msat,
									total_msat,
									cur_cltv + excess_final_cltv_expiry_delta,
									&blinded_hop.encrypted_payload,
									blinding_point.take(),
									*keysend_preimage,
									invoice_request,
									&recipient_onion.custom_tlvs,
								),
							);
						} else {
							callback(
								PayloadCallbackAction::PushBack,
								OP::new_blinded_forward(
									&blinded_hop.encrypted_payload,
									blinding_point.take(),
								),
							);
						}
					}
				},
				Some(BlindedTailDetails::TrampolineEntry {
					trampoline_packet,
					final_value_msat,
				}) => {
					cur_value_msat += final_value_msat;
					callback(
						PayloadCallbackAction::PushBack,
						OP::new_trampoline_entry(
							total_msat,
							final_value_msat + hop.fee_msat(),
							cur_cltv,
							&recipient_onion,
							trampoline_packet,
						)?,
					);
				},
				None => {
					callback(
						PayloadCallbackAction::PushBack,
						OP::new_receive(
							&recipient_onion,
							*keysend_preimage,
							value_msat,
							total_msat,
							cltv,
						)?,
					);
				},
			}
		} else {
			let payload = OP::new_forward(
				last_hop_id.ok_or(APIError::InvalidRoute {
					err: "Next hop ID must be known for non-final hops".to_string(),
				})?,
				value_msat,
				cltv,
			);
			callback(PayloadCallbackAction::PushFront, payload);
		}
		cur_value_msat += hop.fee_msat();
		if cur_value_msat >= 21000000 * 100000000 * 1000 {
			return Err(APIError::InvalidRoute { err: "Channel fees overflowed?".to_owned() });
		}
		cur_cltv = cur_cltv.saturating_add(hop.cltv_expiry_delta() as u32);
		if cur_cltv >= 500000000 {
			return Err(APIError::InvalidRoute { err: "Channel CLTV overflowed?".to_owned() });
		}
		last_hop_id = Some(hop.hop_id());
	}
	Ok((cur_value_msat, cur_cltv))
}

pub(crate) const MIN_FINAL_VALUE_ESTIMATE_WITH_OVERPAY: u64 = 100_000_000;

pub(crate) fn set_max_path_length(
	route_params: &mut RouteParameters, recipient_onion: &RecipientOnionFields,
	keysend_preimage: Option<PaymentPreimage>, invoice_request: Option<&InvoiceRequest>,
	best_block_height: u32,
) -> Result<(), ()> {
	const PAYLOAD_HMAC_LEN: usize = 32;
	let unblinded_intermed_payload_len = msgs::OutboundOnionPayload::Forward {
		short_channel_id: 42,
		amt_to_forward: TOTAL_BITCOIN_SUPPLY_SATOSHIS,
		outgoing_cltv_value: route_params.payment_params.max_total_cltv_expiry_delta,
	}
	.serialized_length()
	.saturating_add(PAYLOAD_HMAC_LEN);

	const OVERPAY_ESTIMATE_MULTIPLER: u64 = 3;
	let final_value_msat_with_overpay_buffer = route_params
		.final_value_msat
		.saturating_mul(OVERPAY_ESTIMATE_MULTIPLER)
		.clamp(MIN_FINAL_VALUE_ESTIMATE_WITH_OVERPAY, 0x1000_0000);

	let blinded_tail_opt = route_params
		.payment_params
		.payee
		.blinded_route_hints()
		.iter()
		.max_by_key(|path| path.inner_blinded_path().serialized_length())
		.map(|largest_path| BlindedTailDetails::DirectEntry {
			hops: largest_path.blinded_hops().iter(),
			blinding_point: largest_path.blinding_point(),
			final_value_msat: final_value_msat_with_overpay_buffer,
			excess_final_cltv_expiry_delta: 0,
		});

	let cltv_expiry_delta =
		core::cmp::min(route_params.payment_params.max_total_cltv_expiry_delta, 0x1000_0000);
	let unblinded_route_hop = RouteHop {
		pubkey: PublicKey::from_slice(&[2; 33]).unwrap(),
		node_features: NodeFeatures::empty(),
		short_channel_id: 42,
		channel_features: ChannelFeatures::empty(),
		fee_msat: final_value_msat_with_overpay_buffer,
		cltv_expiry_delta,
		maybe_announced_channel: false,
	};
	let mut num_reserved_bytes: usize = 0;
	let build_payloads_res = build_onion_payloads_callback(
		core::iter::once(&unblinded_route_hop),
		blinded_tail_opt,
		final_value_msat_with_overpay_buffer,
		&recipient_onion,
		best_block_height,
		&keysend_preimage,
		invoice_request,
		|_, payload: msgs::OutboundOnionPayload| {
			num_reserved_bytes = num_reserved_bytes
				.saturating_add(payload.serialized_length())
				.saturating_add(PAYLOAD_HMAC_LEN);
		},
	);
	debug_assert!(build_payloads_res.is_ok());

	let max_path_length = 1300usize
		.checked_sub(num_reserved_bytes)
		.map(|p| p / unblinded_intermed_payload_len)
		.and_then(|l| u8::try_from(l.saturating_add(1)).ok())
		.ok_or(())?;

	route_params.payment_params.max_path_length =
		core::cmp::min(max_path_length, route_params.payment_params.max_path_length);
	Ok(())
}

/// Length of the onion data packet. Before TLV-based onions this was 20 65-byte hops, though now
/// the hops can be of variable length.
pub(crate) const ONION_DATA_LEN: usize = 20 * 65;

#[inline]
fn shift_slice_right(arr: &mut [u8], amt: usize) {
	for i in (amt..arr.len()).rev() {
		arr[i] = arr[i - amt];
	}
	for i in 0..amt {
		arr[i] = 0;
	}
}

pub(super) fn construct_onion_packet(
	payloads: Vec<msgs::OutboundOnionPayload>, onion_keys: Vec<OnionKeys>, prng_seed: [u8; 32],
	associated_data: &PaymentHash,
) -> Result<msgs::OnionPacket, ()> {
	let mut packet_data = [0; ONION_DATA_LEN];

	let mut chacha = ChaCha20::new(&prng_seed, &[0; 8]);
	chacha.process(&[0; ONION_DATA_LEN], &mut packet_data);

	debug_assert_eq!(payloads.len(), onion_keys.len(), "Payloads and keys must have equal lengths");

	let packet = FixedSizeOnionPacket(packet_data);
	construct_onion_packet_with_init_noise::<_, _>(
		payloads,
		onion_keys,
		packet,
		Some(associated_data),
	)
}

pub(super) fn construct_trampoline_onion_packet(
	payloads: Vec<msgs::OutboundTrampolinePayload>, onion_keys: Vec<OnionKeys>,
	prng_seed: [u8; 32], associated_data: &PaymentHash, length: Option<u16>,
) -> Result<msgs::TrampolineOnionPacket, ()> {
	let minimum_packet_length = payloads.iter().map(|p| p.serialized_length() + 32).sum();

	debug_assert!(
		minimum_packet_length < ONION_DATA_LEN,
		"Trampoline onion packet must be smaller than outer onion"
	);
	if minimum_packet_length >= ONION_DATA_LEN {
		return Err(());
	}

	let packet_length = length.map(|l| usize::from(l)).unwrap_or(minimum_packet_length);
	debug_assert!(
		packet_length >= minimum_packet_length,
		"Packet length cannot be smaller than the payloads require."
	);
	if packet_length < minimum_packet_length {
		return Err(());
	}

	let mut packet_data = vec![0u8; packet_length];
	let mut chacha = ChaCha20::new(&prng_seed, &[0; 8]);
	chacha.process_in_place(&mut packet_data);

	construct_onion_packet_with_init_noise::<_, _>(
		payloads,
		onion_keys,
		packet_data,
		Some(associated_data),
	)
}

#[cfg(test)]
/// Used in testing to write bogus `BogusOnionHopData` as well as `RawOnionHopData`, which is
/// otherwise not representable in `msgs::OnionHopData`.
pub(super) fn construct_onion_packet_with_writable_hopdata<HD: Writeable>(
	payloads: Vec<HD>, onion_keys: Vec<OnionKeys>, prng_seed: [u8; 32],
	associated_data: &PaymentHash,
) -> Result<msgs::OnionPacket, ()> {
	let mut packet_data = [0; ONION_DATA_LEN];

	let mut chacha = ChaCha20::new(&prng_seed, &[0; 8]);
	chacha.process(&[0; ONION_DATA_LEN], &mut packet_data);

	let packet = FixedSizeOnionPacket(packet_data);
	construct_onion_packet_with_init_noise::<_, _>(
		payloads,
		onion_keys,
		packet,
		Some(associated_data),
	)
}

/// Since onion message packets and onion payment packets have different lengths but are otherwise
/// identical, we use this trait to allow `construct_onion_packet_with_init_noise` to return either
/// type.
pub(crate) trait Packet {
	type Data: AsMut<[u8]>;
	fn new(pubkey: PublicKey, hop_data: Self::Data, hmac: [u8; 32]) -> Self;
}

// Needed for rustc versions older than 1.47 to avoid E0277: "arrays only have std trait
// implementations for lengths 0..=32".
pub(crate) struct FixedSizeOnionPacket(pub(crate) [u8; ONION_DATA_LEN]);

impl AsMut<[u8]> for FixedSizeOnionPacket {
	fn as_mut(&mut self) -> &mut [u8] {
		&mut self.0
	}
}

pub(crate) fn payloads_serialized_length<HD: Writeable>(payloads: &Vec<HD>) -> usize {
	payloads.iter().map(|p| p.serialized_length() + 32 /* HMAC */).sum()
}

pub(crate) fn construct_onion_message_packet<HD: Writeable, P: Packet<Data = Vec<u8>>>(
	payloads: Vec<HD>, onion_keys: Vec<OnionKeys>, prng_seed: [u8; 32], packet_data_len: usize,
) -> Result<P, ()> {
	let mut packet_data = vec![0; packet_data_len];

	let mut chacha = ChaCha20::new(&prng_seed, &[0; 8]);
	chacha.process_in_place(&mut packet_data);

	construct_onion_packet_with_init_noise::<_, _>(payloads, onion_keys, packet_data, None)
}

fn construct_onion_packet_with_init_noise<HD: Writeable, P: Packet>(
	mut payloads: Vec<HD>, onion_keys: Vec<OnionKeys>, mut packet_data: P::Data,
	associated_data: Option<&PaymentHash>,
) -> Result<P, ()> {
	let filler = {
		let packet_data = packet_data.as_mut();
		const ONION_HOP_DATA_LEN: usize = 65; // We may decrease this eventually after TLV is common
		let mut res = Vec::with_capacity(ONION_HOP_DATA_LEN * (payloads.len() - 1));

		let mut pos = 0;
		for (i, (payload, keys)) in payloads.iter().zip(onion_keys.iter()).enumerate() {
			let mut chacha = ChaCha20::new(&keys.rho, &[0u8; 8]);
			// TODO: Batch this.
			for _ in 0..(packet_data.len() - pos) {
				let mut dummy = [0; 1];
				chacha.process_in_place(&mut dummy); // We don't have a seek function :(
			}

			let mut payload_len = LengthCalculatingWriter(0);
			payload.write(&mut payload_len).expect("Failed to calculate length");
			pos += payload_len.0 + 32;
			if pos > packet_data.len() {
				return Err(());
			}

			if i == payloads.len() - 1 {
				break;
			}

			res.resize(pos, 0u8);
			chacha.process_in_place(&mut res);
		}
		res
	};

	let mut hmac_res = [0; 32];
	for (i, (payload, keys)) in payloads.iter_mut().zip(onion_keys.iter()).rev().enumerate() {
		let mut payload_len = LengthCalculatingWriter(0);
		payload.write(&mut payload_len).expect("Failed to calculate length");

		let packet_data = packet_data.as_mut();
		shift_slice_right(packet_data, payload_len.0 + 32);
		packet_data[0..payload_len.0].copy_from_slice(&payload.encode()[..]);
		packet_data[payload_len.0..(payload_len.0 + 32)].copy_from_slice(&hmac_res);

		let mut chacha = ChaCha20::new(&keys.rho, &[0u8; 8]);
		chacha.process_in_place(packet_data);

		if i == 0 {
			let stop_index = packet_data.len();
			let start_index = stop_index.checked_sub(filler.len()).ok_or(())?;
			packet_data[start_index..stop_index].copy_from_slice(&filler[..]);
		}

		let mut hmac = HmacEngine::<Sha256>::new(&keys.mu);
		hmac.input(packet_data);
		if let Some(associated_data) = associated_data {
			hmac.input(&associated_data.0[..]);
		}
		hmac_res = Hmac::from_engine(hmac).to_byte_array();
	}

	Ok(P::new(onion_keys.first().unwrap().ephemeral_pubkey, packet_data, hmac_res))
}

/// Encrypts/decrypts a failure packet.
fn crypt_failure_packet(shared_secret: &[u8], packet: &mut OnionErrorPacket) {
	let ammag = gen_ammag_from_shared_secret(&shared_secret);
	let mut chacha = ChaCha20::new(&ammag, &[0u8; 8]);
	chacha.process_in_place(&mut packet.data);

	if let Some(ref mut attribution_data) = packet.attribution_data {
		attribution_data.crypt(shared_secret);
	}
}

#[cfg(test)]
pub(super) fn test_crypt_failure_packet(shared_secret: &[u8], packet: &mut OnionErrorPacket) {
	crypt_failure_packet(shared_secret, packet)
}

fn build_unencrypted_failure_packet(
	shared_secret: &[u8], failure_reason: LocalHTLCFailureReason, failure_data: &[u8],
	hold_time: u32, min_packet_len: usize,
) -> OnionErrorPacket {
	assert_eq!(shared_secret.len(), 32);
	assert!(failure_data.len() <= 64531);

	// Failure len is 2 bytes type plus the data.
	let failure_len = 2 + failure_data.len();

	// The remaining length is the padding.
	let pad_len = min_packet_len.saturating_sub(failure_len);

	// Total len is a 32 bytes HMAC, 2 bytes failure len, failure, 2 bytes pad len and pad.
	let total_len = 32 + 2 + failure_len + 2 + pad_len;

	let mut writer = VecWriter(Vec::with_capacity(total_len));

	// Reserve space for the HMAC.
	writer.0.extend_from_slice(&[0; 32]);

	// Write failure len, type and data.
	(failure_len as u16).write(&mut writer).unwrap();
	failure_reason.failure_code().write(&mut writer).unwrap();
	writer.0.extend_from_slice(&failure_data[..]);

	// Write pad len and resize to match padding.
	(pad_len as u16).write(&mut writer).unwrap();
	writer.0.resize(total_len, 0);

	// Calculate and store HMAC.
	let um = gen_um_from_shared_secret(&shared_secret);
	let mut hmac = HmacEngine::<Sha256>::new(&um);
	hmac.input(&writer.0[32..]);
	let hmac = Hmac::from_engine(hmac).to_byte_array();
	writer.0[..32].copy_from_slice(&hmac);

	// Prepare attribution data.
	let mut packet = OnionErrorPacket { data: writer.0, attribution_data: None };
	update_attribution_data(&mut packet, shared_secret, hold_time);

	packet
}

fn update_attribution_data(
	onion_error_packet: &mut OnionErrorPacket, shared_secret: &[u8], hold_time: u32,
) {
	// If there's no attribution data yet, we still add our hold times and HMACs to potentially give the sender
	// attribution data for the partial path. In order for this to work, all upstream nodes need to support attributable
	// failures.
	let attribution_data =
		onion_error_packet.attribution_data.get_or_insert(AttributionData::new());

	attribution_data.update(&onion_error_packet.data, shared_secret, hold_time);
}

pub(super) fn build_failure_packet(
	shared_secret: &[u8], failure_reason: LocalHTLCFailureReason, failure_data: &[u8],
	hold_time: u32,
) -> OnionErrorPacket {
	let mut onion_error_packet = build_unencrypted_failure_packet(
		shared_secret,
		failure_reason,
		failure_data,
		hold_time,
		DEFAULT_MIN_FAILURE_PACKET_LEN,
	);

	crypt_failure_packet(shared_secret, &mut onion_error_packet);

	onion_error_packet
}

mod fuzzy_onion_utils {
	use super::*;

	pub struct DecodedOnionFailure {
		pub(crate) network_update: Option<NetworkUpdate>,
		pub(crate) short_channel_id: Option<u64>,
		pub(crate) payment_failed_permanently: bool,
		pub(crate) failed_within_blinded_path: bool,
		#[allow(dead_code)]
		pub(crate) hold_times: Vec<u32>,
		#[cfg(any(test, feature = "_test_utils"))]
		pub(crate) onion_error_code: Option<LocalHTLCFailureReason>,
		#[cfg(any(test, feature = "_test_utils"))]
		pub(crate) onion_error_data: Option<Vec<u8>>,
		#[cfg(test)]
		pub(crate) attribution_failed_channel: Option<u64>,
	}

	pub fn process_onion_failure<T: secp256k1::Signing, L: Deref>(
		secp_ctx: &Secp256k1<T>, logger: &L, htlc_source: &HTLCSource,
		encrypted_packet: OnionErrorPacket,
	) -> DecodedOnionFailure
	where
		L::Target: Logger,
	{
		let (path, session_priv) = match htlc_source {
			HTLCSource::OutboundRoute { ref path, ref session_priv, .. } => (path, session_priv),
			_ => unreachable!(),
		};

		process_onion_failure_inner(secp_ctx, logger, path, &session_priv, None, encrypted_packet)
	}

	/// Decodes the attribution data that we got back from upstream on a payment we sent.
	pub fn decode_fulfill_attribution_data<T: secp256k1::Signing, L: Deref>(
		secp_ctx: &Secp256k1<T>, logger: &L, path: &Path, outer_session_priv: &SecretKey,
		mut attribution_data: AttributionData,
	) -> Vec<u32>
	where
		L::Target: Logger,
	{
		let mut hold_times = Vec::new();

		// Only consider hops in the regular path for attribution data. Blinded path attribution data isn't accessible.
		let shared_secrets =
			construct_onion_keys_generic(secp_ctx, &path.hops, None, outer_session_priv)
				.map(|(shared_secret, _, _, _, _)| shared_secret);

		// Path length can reach 27 hops, but attribution data can only be conveyed back to the sender from the first 20
		// hops. Determine the number of hops to be used for attribution data.
		let attributable_hop_count = usize::min(path.hops.len(), MAX_HOPS);

		for (route_hop_idx, shared_secret) in
			shared_secrets.enumerate().take(attributable_hop_count)
		{
			attribution_data.crypt(shared_secret.as_ref());

			// Calculate position relative to the last attributable hop. The last attributable hop is at position 0. We need
			// to look at the chain of HMACs that does include all data up to the last attributable hop. Hold times beyond
			// the last attributable hop will not be available.
			let position = attributable_hop_count - route_hop_idx - 1;
			let res = attribution_data.verify(&Vec::new(), shared_secret.as_ref(), position);
			match res {
				Ok(hold_time) => {
					hold_times.push(hold_time);

					// Shift attribution data to prepare for processing the next hop.
					attribution_data.shift_left();
				},
				Err(()) => {
					// We will hit this if there is a node on the path that does not support fulfill attribution data.
					log_debug!(
						logger,
						"Invalid fulfill HMAC in attribution data for node at pos {}",
						route_hop_idx
					);

					break;
				},
			}
		}

		hold_times
	}
}
#[cfg(fuzzing)]
pub use self::fuzzy_onion_utils::*;
#[cfg(not(fuzzing))]
pub(crate) use self::fuzzy_onion_utils::*;

/// Process failure we got back from upstream on a payment we sent (implying htlc_source is an
/// OutboundRoute).
fn process_onion_failure_inner<T: secp256k1::Signing, L: Deref>(
	secp_ctx: &Secp256k1<T>, logger: &L, path: &Path, session_priv: &SecretKey,
	trampoline_session_priv_override: Option<SecretKey>, mut encrypted_packet: OnionErrorPacket,
) -> DecodedOnionFailure
where
	L::Target: Logger,
{
	// Check that there is at least enough data for an hmac, otherwise none of the checking that we may do makes sense.
	// Also prevent slice out of bounds further down.
	if encrypted_packet.data.len() < 32 {
		log_warn!(
			logger,
			"Non-attributable failure encountered on route {}",
			path.hops.iter().map(|h| h.pubkey.to_string()).collect::<Vec<_>>().join("->")
		);

		// Signal that we failed permanently. Without a valid hmac, we can't identify the failing node and we can't
		// apply a penalty. Therefore there is nothing more we can do other than failing the payment.
		return DecodedOnionFailure {
			network_update: None,
			short_channel_id: None,
			payment_failed_permanently: true,
			failed_within_blinded_path: false,
			hold_times: Vec::new(),
			#[cfg(any(test, feature = "_test_utils"))]
			onion_error_code: None,
			#[cfg(any(test, feature = "_test_utils"))]
			onion_error_data: None,
			#[cfg(test)]
			attribution_failed_channel: None,
		};
	}

	// Learnings from the HTLC failure to inform future payment retries and scoring.
	struct FailureLearnings {
		network_update: Option<NetworkUpdate>,
		short_channel_id: Option<u64>,
		payment_failed_permanently: bool,
		failed_within_blinded_path: bool,
	}
	let mut res: Option<FailureLearnings> = None;
	let mut _error_code_ret = None;
	let mut _error_packet_ret = None;
	let mut is_from_final_non_blinded_node = false;
	let mut hop_hold_times: Vec<u32> = Vec::new();

	enum ErrorHop<'a> {
		RouteHop(&'a RouteHop),
		TrampolineHop(&'a TrampolineHop),
	}

	impl<'a> ErrorHop<'a> {
		fn pubkey(&self) -> &PublicKey {
			match self {
				ErrorHop::RouteHop(rh) => rh.node_pubkey(),
				ErrorHop::TrampolineHop(th) => th.node_pubkey(),
			}
		}

		fn short_channel_id(&self) -> Option<u64> {
			match self {
				ErrorHop::RouteHop(rh) => Some(rh.short_channel_id),
				ErrorHop::TrampolineHop(_) => None,
			}
		}
	}

	let num_blinded_hops = path.blinded_tail.as_ref().map_or(0, |bt| bt.hops.len());

	// if we have Trampoline hops, the blinded hops are part of the inner Trampoline onion
	let nontrampoline_bt =
		if path.has_trampoline_hops() { None } else { path.blinded_tail.as_ref() };
	let nontrampolines =
		construct_onion_keys_generic(secp_ctx, &path.hops, nontrampoline_bt, session_priv).map(
			|(shared_secret, _, _, route_hop_option, _)| {
				(route_hop_option.map(|rh| ErrorHop::RouteHop(rh)), shared_secret)
			},
		);

	let trampolines = if path.has_trampoline_hops() {
		// Trampoline hops are part of the blinded tail, so this can never panic
		let blinded_tail = path.blinded_tail.as_ref();
		let hops = &blinded_tail.unwrap().trampoline_hops;
		let trampoline_session_priv = trampoline_session_priv_override
			.unwrap_or_else(|| compute_trampoline_session_priv(session_priv));
		Some(
			construct_onion_keys_generic(secp_ctx, hops, blinded_tail, &trampoline_session_priv)
				.map(|(shared_secret, _, _, route_hop_option, _)| {
					(
						route_hop_option.map(|tram_hop| ErrorHop::TrampolineHop(tram_hop)),
						shared_secret,
					)
				}),
		)
	} else {
		None
	};

	// In the best case, paths can be up to 27 hops. But attribution data can only be conveyed back to the sender from
	// the first 20 hops. Determine the number of hops to be used for attribution data.
	let attributable_hop_count = usize::min(path.hops.len(), MAX_HOPS);

	// Keep track of the first hop for which the attribution data failed to check out.
	let mut attribution_failed_channel = None;

	// Handle packed channel/node updates for passing back for the route handler
	let mut iter = nontrampolines.chain(trampolines.into_iter().flatten()).enumerate().peekable();
	while let Some((route_hop_idx, (route_hop_option, shared_secret))) = iter.next() {
		let route_hop = match route_hop_option.as_ref() {
			Some(hop) => hop,
			None => {
				// Got an error from within a blinded route.
				_error_code_ret = Some(LocalHTLCFailureReason::InvalidOnionBlinding);
				_error_packet_ret = Some(vec![0; 32]);
				res = Some(FailureLearnings {
					network_update: None,
					short_channel_id: None,
					payment_failed_permanently: false,
					failed_within_blinded_path: true,
				});
				break;
			},
		};

		// The failing hop includes either the inbound channel to the recipient or the outbound channel
		// from the current hop (i.e., the next hop's inbound channel).
		// For 1-hop blinded paths, the final `ErrorHop` entry is the recipient.
		// In our case that means that if we're on the last iteration, and there is no more than one
		// blinded hop, the current iteration references the last non-blinded hop.
		let next_hop = iter.peek();
		is_from_final_non_blinded_node = next_hop.is_none() && num_blinded_hops <= 1;
		let failing_route_hop = if is_from_final_non_blinded_node {
			route_hop
		} else {
			match next_hop {
				Some((_, (Some(hop), _))) => hop,
				_ => {
					// The failing hop is within a multi-hop blinded path.
					#[cfg(not(test))]
					{
						_error_code_ret = Some(LocalHTLCFailureReason::InvalidOnionBlinding);
						_error_packet_ret = Some(vec![0; 32]);
					}
					#[cfg(test)]
					{
						// Actually parse the onion error data in tests so we can check that blinded hops fail
						// back correctly.
						crypt_failure_packet(shared_secret.as_ref(), &mut encrypted_packet);
						let err_packet = msgs::DecodedOnionErrorPacket::read(&mut Cursor::new(
							&encrypted_packet.data,
						))
						.unwrap();
						_error_code_ret = Some(
							u16::from_be_bytes(
								err_packet.failuremsg.get(0..2).unwrap().try_into().unwrap(),
							)
							.into(),
						);
						_error_packet_ret = Some(err_packet.failuremsg[2..].to_vec());
					}

					res = Some(FailureLearnings {
						network_update: None,
						short_channel_id: None,
						payment_failed_permanently: false,
						failed_within_blinded_path: true,
					});
					break;
				},
			}
		};

		crypt_failure_packet(shared_secret.as_ref(), &mut encrypted_packet);

		let um = gen_um_from_shared_secret(shared_secret.as_ref());

		// Only check attribution when an attribution data failure has not yet occurred.
		if attribution_failed_channel.is_none() {
			// Check attr error HMACs if present.
			if let Some(ref mut attribution_data) = encrypted_packet.attribution_data {
				// Only consider hops in the regular path for attribution data. Failures in a blinded path are not
				// attributable.
				if route_hop_idx < attributable_hop_count {
					// Calculate position relative to the last attributable hop. The last attributable hop is at
					// position 0. The failure node does not need to come from the last attributable hop, but we need to
					// look at the chain of HMACs that does include all data up to the last attributable hop. For a more
					// nearby failure, the verified HMACs will include some zero padding data. Failures beyond the last
					// attributable hop will not be attributable.
					let position = attributable_hop_count - route_hop_idx - 1;
					let res = attribution_data.verify(
						&encrypted_packet.data,
						shared_secret.as_ref(),
						position,
					);
					match res {
						Ok(hold_time) => {
							hop_hold_times.push(hold_time);

							log_debug!(
								logger,
								"Htlc hold time at pos {}: {} ms",
								route_hop_idx,
								(hold_time as u128) * HOLD_TIME_UNIT_MILLIS
							);

							// Shift attribution data to prepare for processing the next hop.
							attribution_data.shift_left();
						},
						Err(()) => {
							// Store the failing hop, but continue processing the failure for the remaining hops. During the
							// upgrade period, it may happen that nodes along the way drop attribution data. If the legacy
							// failure is still valid, it should be processed normally.
							attribution_failed_channel = route_hop.short_channel_id();

							log_debug!(
								logger,
								"Invalid failure HMAC in attribution data for node at pos {}",
								route_hop_idx
							);
						},
					}
				}
			} else {
				// When no attribution data is provided at all, blame the first hop when the failing node turns out to
				// be unindentifiable.
				attribution_failed_channel = route_hop.short_channel_id();
			}
		}

		// Check legacy HMAC.
		let mut hmac = HmacEngine::<Sha256>::new(&um);
		hmac.input(&encrypted_packet.data[32..]);

		if &Hmac::from_engine(hmac).to_byte_array() != &encrypted_packet.data[..32] {
			continue;
		}

		let err_packet =
			match msgs::DecodedOnionErrorPacket::read(&mut Cursor::new(&encrypted_packet.data)) {
				Ok(p) => p,
				Err(_) => {
					log_warn!(logger, "Unreadable failure from {}", route_hop.pubkey());

					let network_update = Some(NetworkUpdate::NodeFailure {
						node_id: *route_hop.pubkey(),
						is_permanent: true,
					});
					let short_channel_id = route_hop.short_channel_id();
					res = Some(FailureLearnings {
						network_update,
						short_channel_id,
						payment_failed_permanently: is_from_final_non_blinded_node,
						failed_within_blinded_path: false,
					});
					break;
				},
			};

		let error_code_slice = match err_packet.failuremsg.get(0..2) {
			Some(s) => s,
			None => {
				// Useless packet that we can't use but it passed HMAC, so it definitely came from the peer
				// in question
				log_warn!(logger, "Missing error code in failure from {}", route_hop.pubkey());

				let network_update = Some(NetworkUpdate::NodeFailure {
					node_id: *route_hop.pubkey(),
					is_permanent: true,
				});
				let short_channel_id = route_hop.short_channel_id();
				res = Some(FailureLearnings {
					network_update,
					short_channel_id,
					payment_failed_permanently: is_from_final_non_blinded_node,
					failed_within_blinded_path: false,
				});
				break;
			},
		};

		let error_code = u16::from_be_bytes(error_code_slice.try_into().expect("len is 2")).into();
		_error_code_ret = Some(error_code);
		_error_packet_ret = Some(err_packet.failuremsg[2..].to_vec());

		let (debug_field, debug_field_size) = error_code.get_onion_debug_field();

		// indicate that payment parameter has failed and no need to update Route object
		let payment_failed = error_code.is_recipient_failure() && is_from_final_non_blinded_node;

		let mut network_update = None;
		let mut short_channel_id = None;

		if error_code.is_badonion() {
			// If the error code has the BADONION bit set, always blame the channel from the node
			// "originating" the error to its next hop. The "originator" is ultimately actually claiming
			// that its counterparty is the one who is failing the HTLC.
			// If the "originator" here isn't lying we should really mark the next-hop node as failed
			// entirely, but we can't be confident in that, as it would allow any node to get us to
			// completely ban one of its counterparties. Instead, we simply remove the channel in
			// question.
			if let ErrorHop::RouteHop(failing_route_hop) = failing_route_hop {
				network_update = Some(NetworkUpdate::ChannelFailure {
					short_channel_id: failing_route_hop.short_channel_id,
					is_permanent: true,
				});
			}
		} else if error_code.is_node() {
			network_update = Some(NetworkUpdate::NodeFailure {
				node_id: *route_hop.pubkey(),
				is_permanent: error_code.is_permanent(),
			});
			short_channel_id = route_hop.short_channel_id();
		} else if error_code.is_permanent() {
			if !payment_failed {
				if let ErrorHop::RouteHop(failing_route_hop) = failing_route_hop {
					network_update = Some(NetworkUpdate::ChannelFailure {
						short_channel_id: failing_route_hop.short_channel_id,
						is_permanent: true,
					});
				}
				short_channel_id = failing_route_hop.short_channel_id();
			}
		} else if error_code.is_temporary() {
			if let Some(update_len_slice) =
				err_packet.failuremsg.get(debug_field_size + 2..debug_field_size + 4)
			{
				let update_len =
					u16::from_be_bytes(update_len_slice.try_into().expect("len is 2")) as usize;
				if err_packet
					.failuremsg
					.get(debug_field_size + 4..debug_field_size + 4 + update_len)
					.is_some()
				{
					if let ErrorHop::RouteHop(failing_route_hop) = failing_route_hop {
						network_update = Some(NetworkUpdate::ChannelFailure {
							short_channel_id: failing_route_hop.short_channel_id,
							is_permanent: false,
						});
					}
					short_channel_id = failing_route_hop.short_channel_id();
				}
			}
			if network_update.is_none() {
				// They provided an UPDATE which was obviously bogus, not worth
				// trying to relay through them anymore.
				network_update = Some(NetworkUpdate::NodeFailure {
					node_id: *route_hop.pubkey(),
					is_permanent: true,
				});
			}
			if short_channel_id.is_none() {
				short_channel_id = route_hop.short_channel_id();
			}
		} else if payment_failed {
			// Only blame the hop when a value in the HTLC doesn't match the corresponding value in the
			// onion.
			short_channel_id = match error_code {
				LocalHTLCFailureReason::FinalIncorrectCLTVExpiry
				| LocalHTLCFailureReason::FinalIncorrectHTLCAmount => route_hop.short_channel_id(),
				_ => None,
			};
		} else {
			// We can't understand their error messages and they failed to forward...they probably can't
			// understand our forwards so it's really not worth trying any further.
			network_update = Some(NetworkUpdate::NodeFailure {
				node_id: *route_hop.pubkey(),
				is_permanent: true,
			});
			short_channel_id = route_hop.short_channel_id()
		}

		res = Some(FailureLearnings {
			network_update,
			short_channel_id,
			payment_failed_permanently: error_code.is_permanent() && is_from_final_non_blinded_node,
			failed_within_blinded_path: false,
		});

		if debug_field_size > 0 && err_packet.failuremsg.len() >= 4 + debug_field_size {
			log_info!(
				logger,
				"Onion Error[from {}: {:?}({:#x}) {}({})]",
				route_hop.pubkey(),
				error_code,
				error_code.failure_code(),
				debug_field,
				log_bytes!(&err_packet.failuremsg[4..4 + debug_field_size]),
			);
		} else {
			log_info!(
				logger,
				"Onion Error[from {}: {:?}({:#x})]",
				route_hop.pubkey(),
				error_code,
				error_code.failure_code(),
			);
		}

		break;
	}

	if let Some(FailureLearnings {
		network_update,
		short_channel_id,
		payment_failed_permanently,
		failed_within_blinded_path,
	}) = res
	{
		DecodedOnionFailure {
			network_update,
			short_channel_id,
			payment_failed_permanently,
			failed_within_blinded_path,
			hold_times: hop_hold_times,
			#[cfg(any(test, feature = "_test_utils"))]
			onion_error_code: _error_code_ret,
			#[cfg(any(test, feature = "_test_utils"))]
			onion_error_data: _error_packet_ret,
			#[cfg(test)]
			attribution_failed_channel,
		}
	} else {
		// only not set either packet unparseable or hmac does not match with any
		// payment not retryable only when garbage is from the final node
		log_warn!(
			logger,
			"Non-attributable failure encountered on route {}. Attributation data failed for channel {}",
			path.hops.iter().map(|h| h.pubkey.to_string()).collect::<Vec<_>>().join("->"),
			attribution_failed_channel.unwrap_or_default(),
		);

		DecodedOnionFailure {
			network_update: None,
			short_channel_id: None,
			payment_failed_permanently: is_from_final_non_blinded_node,
			failed_within_blinded_path: false,
			hold_times: hop_hold_times,
			#[cfg(any(test, feature = "_test_utils"))]
			onion_error_code: None,
			#[cfg(any(test, feature = "_test_utils"))]
			onion_error_data: None,
			#[cfg(test)]
			attribution_failed_channel,
		}
	}
}

const BADONION: u16 = 0x8000;
const PERM: u16 = 0x4000;
const NODE: u16 = 0x2000;
const UPDATE: u16 = 0x1000;

/// The reason that a HTLC was failed by the local node. These errors either represent direct,
/// human-readable mappings of BOLT04 error codes or provide additional information that would
/// otherwise be erased by the BOLT04 error code.
///
/// For example:
/// [`Self::FeeInsufficient`] is a direct representation of its underlying BOLT04 error code.
/// [`Self::PrivateChannelForward`] provides additional information that is not provided by its
///  BOLT04 error code.
//
// Note that variants that directly represent BOLT04 error codes must implement conversion from u16
// values using [`impl_from_u16_for_htlc_reason`]
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub enum LocalHTLCFailureReason {
	/// There has been a temporary processing failure on the node which may resolve on retry.
	TemporaryNodeFailure,
	/// These has been a permanent processing failure on the node which will not resolve on retry.
	PermanentNodeFailure,
	/// The HTLC does not implement a feature that is required by our node.
	///
	/// The sender may have outdated gossip, or a bug in its implementation.
	RequiredNodeFeature,
	/// The onion version specified by the HTLC packet is unknown to our node.
	InvalidOnionVersion,
	/// The integrity of the HTLC packet cannot be verified because it has an invalid HMAC.
	InvalidOnionHMAC,
	/// The onion packet has an invalid ephemeral key, so the HTLC cannot be processed.
	InvalidOnionKey,
	/// A temporary forwarding error has occurred which may resolve on retry.
	TemporaryChannelFailure,
	/// A permanent forwarding error has occurred which will not resolve on retry.
	PermanentChannelFailure,
	/// The HTLC does not implement a feature that is required by our channel for processing.
	RequiredChannelFeature,
	/// The HTLC's target outgoing channel that is not known to our node.
	UnknownNextPeer,
	/// The HTLC amount is below our advertised htlc_minimum_msat.
	///
	/// The sender may have outdated gossip, or a bug in its implementation.
	AmountBelowMinimum,
	/// The HTLC does not pay sufficient fees.
	///
	/// The sender may have outdated gossip, or a bug in its implementation.
	FeeInsufficient,
	/// The HTLC does not meet the cltv_expiry_delta advertised by our node, set by
	/// [`ChannelConfig::cltv_expiry_delta`].
	///
	/// The sender may have outdated gossip, or a bug in its implementation.
	///
	/// [`ChannelConfig::cltv_expiry_delta`]: crate::util::config::ChannelConfig::cltv_expiry_delta
	IncorrectCLTVExpiry,
	/// The HTLC expires too close to the current block height to be safely processed.
	CLTVExpiryTooSoon,
	/// A payment was made to our node that either had incorrect payment information, or was
	/// unknown to us.
	IncorrectPaymentDetails,
	/// The HTLC's expiry is less than the expiry height specified by the sender.
	///
	/// The forwarding node has either tampered with this value, or the sending node has an
	/// old best block height.
	FinalIncorrectCLTVExpiry,
	/// The HTLC's amount is less than the amount specified by the sender.
	///
	/// The forwarding node has tampered with this value, or has a bug in its implementation.
	FinalIncorrectHTLCAmount,
	/// The HTLC couldn't be forwarded because the channel counterparty has been offline for some
	/// time.
	ChannelDisabled,
	/// The HTLC expires too far in the future, so it is rejected to avoid the worst-case outcome
	/// of funds being held for extended periods of time.
	///
	// Limit set by [`crate::ln::channelmanager::CLTV_FAR_FAR_AWAY`].
	CLTVExpiryTooFar,
	/// The HTLC payload contained in the onion packet could not be understood by our node.
	InvalidOnionPayload,
	/// The total amount for a multi-part payment did not arrive in time, so the HTLCs partially
	/// paying the amount were canceled.
	MPPTimeout,
	/// Our node was selected as part of a blinded path, but the packet we received was not
	/// properly constructed, or had incorrect values for the blinded path.
	///
	/// This may happen if the forwarding node tamperd with the HTLC or the sender or recipient
	/// implementations have a bug.
	InvalidOnionBlinding,
	/// UnknownFailureCode represents BOLT04 failure codes that we are not familiar with. We will
	/// encounter this if:
	/// - A peer sends us a new failure code that LDK has not yet been upgraded to understand.
	/// - We read a deprecated failure code from disk that LDK no longer uses.
	///
	/// See <https://github.com/lightning/bolts/blob/master/04-onion-routing.md#returning-errors>
	/// for latest defined error codes.
	UnknownFailureCode {
		/// The bolt 04 failure code.
		code: u16,
	},
	/// A HTLC forward was failed back rather than forwarded on the proposed outgoing channel
	/// because its expiry is too close to the current block height to leave time to safely claim
	/// it on chain if the channel force closes.
	ForwardExpiryBuffer,
	/// The HTLC was failed because it has invalid trampoline forwarding information.
	InvalidTrampolineForward,
	/// A HTLC receive was failed back rather than claimed because its expiry is too close to
	/// the current block height to leave time to safely claim it on chain if the channel force
	/// closes.
	PaymentClaimBuffer,
	/// The HTLC was failed because accepting it would push our commitment's total amount of dust
	/// HTLCs over the limit that we allow to be burned to miner fees if the channel closed while
	/// they are unresolved.
	DustLimitHolder,
	/// The HTLC was failed because accepting it would push our counterparty's total amount of
	/// dust (small) HTLCs over the limit that we allow to be burned to miner fees if the channel
	/// closes while they are unresolved.
	DustLimitCounterparty,
	/// The HTLC was failed because it would drop the remote party's channel balance such that it
	/// cannot cover the fees it is required to pay at various fee rates. This buffer is maintained
	/// so that channels can always maintain reasonable fee rates.
	FeeSpikeBuffer,
	/// The HTLC that requested to be forwarded over a private channel was rejected to prevent
	/// revealing the existence of the channel.
	PrivateChannelForward,
	/// The HTLC was failed because it made a request to forward over the real channel ID of a
	/// channel that implements `option_scid_alias` which is a privacy feature to prevent the
	/// real channel ID from being known.
	RealSCIDForward,
	/// The HTLC was rejected because our channel has not yet reached sufficient depth to be used.
	ChannelNotReady,
	/// A keysend payment with a preimage that did not match the HTLC has was rejected.
	InvalidKeysendPreimage,
	/// The HTLC was failed because it had an invalid trampoline payload.
	InvalidTrampolinePayload,
	/// A payment was rejected because it did not include the correct payment secret from an
	/// invoice.
	PaymentSecretRequired,
	/// The HTLC was failed because its expiry is too close to the current block height, and we
	/// expect that it will immediately be failed back by our downstream peer.
	OutgoingCLTVTooSoon,
	/// The HTLC was failed because it was pending on a channel which is now in the process of
	/// being closed.
	ChannelClosed,
	/// The HTLC was failed back because its expiry height was reached and funds were timed out
	/// on chain.
	OnChainTimeout,
	/// The HTLC was failed because zero amount HTLCs are not allowed.
	ZeroAmount,
	/// The HTLC was failed because its amount is less than the smallest HTLC that the channel
	/// can currently accept.
	///
	/// This may occur because the HTLC is smaller than the counterparty's advertised minimum
	/// accepted HTLC size, or if we have reached our maximum total dust HTLC exposure.
	HTLCMinimum,
	/// The HTLC was failed because its amount is more than then largest HTLC that the channel
	/// can currently accept.
	///
	/// This may occur because the outbound channel has insufficient liquidity to forward the HTLC,
	/// we have reached the counterparty's in-flight limits, or the HTLC exceeds our advertised
	/// maximum accepted HTLC size.
	HTLCMaximum,
	/// The HTLC was failed because our remote peer is offline.
	PeerOffline,
	/// The HTLC was failed because the channel balance was overdrawn.
	ChannelBalanceOverdrawn,
	/// We have been unable to forward a payment to the next Trampoline node but may be able to
	/// do it later.
	TemporaryTrampolineFailure,
	/// The amount or CLTV expiry were insufficient to route the payment to the next Trampoline.
	TrampolineFeeOrExpiryInsufficient,
	/// The specified next Trampoline node cannot be reached from our node.
	UnknownNextTrampoline,
}

impl LocalHTLCFailureReason {
	pub(super) fn failure_code(&self) -> u16 {
		match self {
			Self::TemporaryNodeFailure | Self::ForwardExpiryBuffer => NODE | 2,
			Self::PermanentNodeFailure => PERM | NODE | 2,
			Self::RequiredNodeFeature | Self::PaymentSecretRequired => PERM | NODE | 3,
			Self::InvalidOnionVersion => BADONION | PERM | 4,
			Self::InvalidOnionHMAC => BADONION | PERM | 5,
			Self::InvalidOnionKey => BADONION | PERM | 6,
			Self::TemporaryChannelFailure
			| Self::DustLimitHolder
			| Self::DustLimitCounterparty
			| Self::FeeSpikeBuffer
			| Self::ChannelNotReady
			| Self::ZeroAmount
			| Self::HTLCMinimum
			| Self::HTLCMaximum
			| Self::PeerOffline
			| Self::ChannelBalanceOverdrawn => UPDATE | 7,
			Self::PermanentChannelFailure | Self::ChannelClosed | Self::OnChainTimeout => PERM | 8,
			Self::RequiredChannelFeature => PERM | 9,
			Self::UnknownNextPeer
			| Self::PrivateChannelForward
			| Self::RealSCIDForward
			| Self::InvalidTrampolineForward => PERM | 10,
			Self::AmountBelowMinimum => UPDATE | 11,
			Self::FeeInsufficient => UPDATE | 12,
			Self::IncorrectCLTVExpiry => UPDATE | 13,
			Self::CLTVExpiryTooSoon | Self::OutgoingCLTVTooSoon => UPDATE | 14,
			Self::IncorrectPaymentDetails
			| Self::PaymentClaimBuffer
			| Self::InvalidKeysendPreimage => PERM | 15,
			Self::FinalIncorrectCLTVExpiry => 18,
			Self::FinalIncorrectHTLCAmount => 19,
			Self::ChannelDisabled => UPDATE | 20,
			Self::CLTVExpiryTooFar => 21,
			Self::InvalidOnionPayload | Self::InvalidTrampolinePayload => PERM | 22,
			Self::MPPTimeout => 23,
			Self::InvalidOnionBlinding => BADONION | PERM | 24,
			Self::TemporaryTrampolineFailure => NODE | 25,
			Self::TrampolineFeeOrExpiryInsufficient => NODE | 26,
			Self::UnknownNextTrampoline => PERM | 27,
			Self::UnknownFailureCode { code } => *code,
		}
	}

	/// Returns the name of an error's data field and its expected length.
	fn get_onion_debug_field(&self) -> (&'static str, usize) {
		match self {
			Self::InvalidOnionVersion | Self::InvalidOnionHMAC | Self::InvalidOnionKey => {
				("sha256_of_onion", 32)
			},
			Self::AmountBelowMinimum | Self::FeeInsufficient => ("htlc_msat", 8),
			Self::IncorrectCLTVExpiry | Self::FinalIncorrectCLTVExpiry => ("cltv_expiry", 4),
			Self::FinalIncorrectHTLCAmount => ("incoming_htlc_msat", 8),
			Self::ChannelDisabled => ("flags", 2),
			_ => ("", 0),
		}
	}

	pub(super) fn is_temporary(&self) -> bool {
		self.failure_code() & UPDATE == UPDATE
	}

	pub(super) fn is_permanent(&self) -> bool {
		self.failure_code() & PERM == PERM
	}

	fn is_badonion(&self) -> bool {
		self.failure_code() & BADONION == BADONION
	}

	fn is_node(&self) -> bool {
		self.failure_code() & NODE == NODE
	}

	/// Returns true if the failure is only sent by the final recipient. Note that this function
	/// only checks [`LocalHTLCFailureReason`] variants that represent bolt 04 errors directly,
	/// as it's intended to analyze errors we've received as a sender.
	fn is_recipient_failure(&self) -> bool {
		self.failure_code() == LocalHTLCFailureReason::IncorrectPaymentDetails.failure_code()
			|| *self == LocalHTLCFailureReason::FinalIncorrectCLTVExpiry
			|| *self == LocalHTLCFailureReason::FinalIncorrectHTLCAmount
			|| *self == LocalHTLCFailureReason::MPPTimeout
	}
}

macro_rules! impl_from_u16_for_htlc_reason {
    ($enum:ident, [$($variant:ident),* $(,)?]) => {
        impl From<u16> for $enum {
            fn from(value: u16) -> Self {
                $(
                    if value == $enum::$variant.failure_code() {
                        return $enum::$variant;
                    }
                )*
                $enum::UnknownFailureCode { code: value }
            }
        }
    };
}

// Error codes that represent BOLT04 error codes must be included here.
impl_from_u16_for_htlc_reason!(
	LocalHTLCFailureReason,
	[
		TemporaryNodeFailure,
		PermanentNodeFailure,
		RequiredNodeFeature,
		InvalidOnionVersion,
		InvalidOnionHMAC,
		InvalidOnionKey,
		TemporaryChannelFailure,
		PermanentChannelFailure,
		RequiredChannelFeature,
		UnknownNextPeer,
		AmountBelowMinimum,
		FeeInsufficient,
		IncorrectCLTVExpiry,
		CLTVExpiryTooSoon,
		IncorrectPaymentDetails,
		FinalIncorrectCLTVExpiry,
		FinalIncorrectHTLCAmount,
		ChannelDisabled,
		CLTVExpiryTooFar,
		InvalidOnionPayload,
		MPPTimeout,
		InvalidOnionBlinding,
		TemporaryTrampolineFailure,
		TrampolineFeeOrExpiryInsufficient,
		UnknownNextTrampoline,
	]
);

macro_rules! ser_failure_reasons {
	($(($idx: expr, $name: ident)),*) => {
		impl Readable for LocalHTLCFailureReason {
			fn read<R: Read>(r: &mut R) -> Result<LocalHTLCFailureReason, DecodeError> {
				let code: u16 = Readable::read(r)?;
				let reason: u8 = Readable::read(r)?;
				read_tlv_fields!(r, {});
				match reason {
					$($idx => Ok(LocalHTLCFailureReason::$name),)*
					_ => Ok(code.into()),
				}
			}
		}
		impl Writeable for LocalHTLCFailureReason {
			fn write<W: Writer>(&self, writer: &mut W) -> Result<(), bitcoin::io::Error> {
				self.failure_code().write(writer)?;
				let reason: u8 = match self {
					$(LocalHTLCFailureReason::$name => $idx,)*
					LocalHTLCFailureReason::UnknownFailureCode { .. } => 0xff,
				};
				reason.write(writer)?;
				write_tlv_fields!(writer, {});
				Ok(())
			}
		}
	}
}

ser_failure_reasons!(
	(1, TemporaryNodeFailure),
	(2, PermanentNodeFailure),
	(3, RequiredNodeFeature),
	(4, InvalidOnionVersion),
	(5, InvalidOnionHMAC),
	(6, InvalidOnionKey),
	(7, TemporaryChannelFailure),
	(8, PermanentChannelFailure),
	(9, RequiredChannelFeature),
	(10, UnknownNextPeer),
	(11, AmountBelowMinimum),
	(12, FeeInsufficient),
	(13, IncorrectCLTVExpiry),
	(14, CLTVExpiryTooSoon),
	(15, IncorrectPaymentDetails),
	(16, FinalIncorrectCLTVExpiry),
	(17, FinalIncorrectHTLCAmount),
	(18, ChannelDisabled),
	(19, CLTVExpiryTooFar),
	(20, InvalidOnionPayload),
	(21, MPPTimeout),
	(22, InvalidOnionBlinding),
	(23, ForwardExpiryBuffer),
	(24, InvalidTrampolineForward),
	(25, PaymentClaimBuffer),
	(26, DustLimitHolder),
	(27, DustLimitCounterparty),
	(28, FeeSpikeBuffer),
	(29, PrivateChannelForward),
	(30, RealSCIDForward),
	(31, ChannelNotReady),
	(32, InvalidKeysendPreimage),
	(33, InvalidTrampolinePayload),
	(34, PaymentSecretRequired),
	(35, OutgoingCLTVTooSoon),
	(36, ChannelClosed),
	(37, OnChainTimeout),
	(38, ZeroAmount),
	(39, HTLCMinimum),
	(40, HTLCMaximum),
	(41, PeerOffline),
	(42, ChannelBalanceOverdrawn),
	(43, TemporaryTrampolineFailure),
	(44, TrampolineFeeOrExpiryInsufficient),
	(45, UnknownNextTrampoline)
);

impl From<&HTLCFailReason> for HTLCHandlingFailureReason {
	fn from(value: &HTLCFailReason) -> Self {
		match value.0 {
			HTLCFailReasonRepr::LightningError { .. } => HTLCHandlingFailureReason::Downstream,
			HTLCFailReasonRepr::Reason { failure_reason, .. } => {
				HTLCHandlingFailureReason::Local { reason: failure_reason }
			},
		}
	}
}

#[derive(Clone)] // See Channel::revoke_and_ack for why, tl;dr: Rust bug
#[cfg_attr(test, derive(PartialEq))]
pub(super) struct HTLCFailReason(HTLCFailReasonRepr);

#[derive(Clone)] // See Channel::revoke_and_ack for why, tl;dr: Rust bug
#[cfg_attr(test, derive(PartialEq))]
enum HTLCFailReasonRepr {
	LightningError { err: msgs::OnionErrorPacket, hold_time: Option<u32> },
	Reason { data: Vec<u8>, failure_reason: LocalHTLCFailureReason },
}

impl HTLCFailReason {
	pub fn set_hold_time(&mut self, hold_time: u32) {
		match self.0 {
			HTLCFailReasonRepr::LightningError { hold_time: ref mut current_hold_time, .. } => {
				*current_hold_time = Some(hold_time);
			},
			_ => {},
		}
	}
}

impl core::fmt::Debug for HTLCFailReason {
	fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
		match self.0 {
			HTLCFailReasonRepr::Reason { ref failure_reason, .. } => {
				write!(
					f,
					"HTLC failure {:?} error code {}",
					failure_reason,
					failure_reason.failure_code()
				)
			},
			HTLCFailReasonRepr::LightningError { .. } => {
				write!(f, "pre-built LightningError")
			},
		}
	}
}

impl Writeable for HTLCFailReason {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), crate::io::Error> {
		self.0.write(writer)
	}
}
impl Readable for HTLCFailReason {
	fn read<R: Read>(reader: &mut R) -> Result<Self, msgs::DecodeError> {
		Ok(Self(Readable::read(reader)?))
	}
}

impl_writeable_tlv_based_enum!(HTLCFailReasonRepr,
	(0, LightningError) => {
		(0, data, (legacy, Vec<u8>, |us|
			if let &HTLCFailReasonRepr::LightningError { err: msgs::OnionErrorPacket { ref data, .. }, .. } = us {
				Some(data)
			} else {
				None
			})
		),
		(1, attribution_data, (legacy, AttributionData, |us|
			if let &HTLCFailReasonRepr::LightningError { err: msgs::OnionErrorPacket { ref attribution_data, .. }, .. } = us {
				attribution_data.as_ref()
			} else {
				None
			})
		),
		(3, hold_time, option),
		(_unused, err, (static_value, msgs::OnionErrorPacket { data: data.ok_or(DecodeError::InvalidValue)?, attribution_data })),
	},
	(1, Reason) => {
		(0, _failure_code, (legacy, u16,
			|r: &HTLCFailReasonRepr| match r {
				HTLCFailReasonRepr::LightningError{ .. } => None,
				HTLCFailReasonRepr::Reason{ failure_reason, .. } => Some(failure_reason.failure_code())
			})),
		// failure_code was required, and is replaced by reason in 0.2 so any time we do not have a
		// reason available failure_code will be Some and can be expressed as a reason.
		(1, failure_reason, (default_value, LocalHTLCFailureReason::from(_failure_code.ok_or(DecodeError::InvalidValue)?))),
		(2, data, required_vec),
	},
);

impl HTLCFailReason {
	pub(super) fn reason(failure_reason: LocalHTLCFailureReason, data: Vec<u8>) -> Self {
		match failure_reason {
			LocalHTLCFailureReason::TemporaryNodeFailure
			| LocalHTLCFailureReason::ForwardExpiryBuffer => debug_assert!(data.is_empty()),
			LocalHTLCFailureReason::PermanentNodeFailure => debug_assert!(data.is_empty()),
			LocalHTLCFailureReason::RequiredNodeFeature
			| LocalHTLCFailureReason::PaymentSecretRequired => debug_assert!(data.is_empty()),
			LocalHTLCFailureReason::InvalidOnionVersion => debug_assert_eq!(data.len(), 32),
			LocalHTLCFailureReason::InvalidOnionHMAC => debug_assert_eq!(data.len(), 32),
			LocalHTLCFailureReason::InvalidOnionKey => debug_assert_eq!(data.len(), 32),
			LocalHTLCFailureReason::TemporaryChannelFailure
			| LocalHTLCFailureReason::DustLimitHolder
			| LocalHTLCFailureReason::DustLimitCounterparty
			| LocalHTLCFailureReason::FeeSpikeBuffer
			| LocalHTLCFailureReason::ChannelNotReady
			| LocalHTLCFailureReason::ZeroAmount
			| LocalHTLCFailureReason::HTLCMinimum
			| LocalHTLCFailureReason::HTLCMaximum
			| LocalHTLCFailureReason::PeerOffline
			| LocalHTLCFailureReason::ChannelBalanceOverdrawn => {
				debug_assert_eq!(
					data.len() - 2,
					u16::from_be_bytes(data[0..2].try_into().unwrap()) as usize
				)
			},
			LocalHTLCFailureReason::PermanentChannelFailure
			| LocalHTLCFailureReason::OnChainTimeout
			| LocalHTLCFailureReason::ChannelClosed => debug_assert!(data.is_empty()),
			LocalHTLCFailureReason::RequiredChannelFeature => debug_assert!(data.is_empty()),
			LocalHTLCFailureReason::UnknownNextPeer
			| LocalHTLCFailureReason::PrivateChannelForward
			| LocalHTLCFailureReason::RealSCIDForward
			| LocalHTLCFailureReason::InvalidTrampolineForward => debug_assert!(data.is_empty()),
			LocalHTLCFailureReason::AmountBelowMinimum => debug_assert_eq!(
				data.len() - 2 - 8,
				u16::from_be_bytes(data[8..10].try_into().unwrap()) as usize
			),
			LocalHTLCFailureReason::FeeInsufficient => debug_assert_eq!(
				data.len() - 2 - 8,
				u16::from_be_bytes(data[8..10].try_into().unwrap()) as usize
			),
			LocalHTLCFailureReason::IncorrectCLTVExpiry => debug_assert_eq!(
				data.len() - 2 - 4,
				u16::from_be_bytes(data[4..6].try_into().unwrap()) as usize
			),
			LocalHTLCFailureReason::CLTVExpiryTooSoon
			| LocalHTLCFailureReason::OutgoingCLTVTooSoon => debug_assert_eq!(
				data.len() - 2,
				u16::from_be_bytes(data[0..2].try_into().unwrap()) as usize
			),
			LocalHTLCFailureReason::IncorrectPaymentDetails
			| LocalHTLCFailureReason::PaymentClaimBuffer
			| LocalHTLCFailureReason::InvalidKeysendPreimage => debug_assert_eq!(data.len(), 12),
			LocalHTLCFailureReason::FinalIncorrectCLTVExpiry => debug_assert_eq!(data.len(), 4),
			LocalHTLCFailureReason::FinalIncorrectHTLCAmount => debug_assert_eq!(data.len(), 8),
			LocalHTLCFailureReason::ChannelDisabled => debug_assert_eq!(
				data.len() - 2 - 2,
				u16::from_be_bytes(data[2..4].try_into().unwrap()) as usize
			),
			LocalHTLCFailureReason::CLTVExpiryTooFar => debug_assert!(data.is_empty()),
			LocalHTLCFailureReason::InvalidOnionPayload
			| LocalHTLCFailureReason::InvalidTrampolinePayload => debug_assert!(data.len() <= 11),
			LocalHTLCFailureReason::MPPTimeout => debug_assert!(data.is_empty()),
			LocalHTLCFailureReason::InvalidOnionBlinding => debug_assert_eq!(data.len(), 32),
			LocalHTLCFailureReason::UnknownFailureCode { code } => {
				// We set some bogus BADONION failure codes in tests, so allow unknown BADONION.
				if code & BADONION == 0 {
					debug_assert!(false, "Unknown failure code: {}", code)
				}
			},
			LocalHTLCFailureReason::TemporaryTrampolineFailure => debug_assert!(data.is_empty()),
			LocalHTLCFailureReason::TrampolineFeeOrExpiryInsufficient => {
				debug_assert_eq!(data.len(), 10)
			},
			LocalHTLCFailureReason::UnknownNextTrampoline => debug_assert!(data.is_empty()),
		}

		Self(HTLCFailReasonRepr::Reason { data, failure_reason })
	}

	pub(super) fn from_failure_code(failure_reason: LocalHTLCFailureReason) -> Self {
		Self::reason(failure_reason, Vec::new())
	}

	pub(super) fn from_msg(msg: &msgs::UpdateFailHTLC) -> Self {
		Self(HTLCFailReasonRepr::LightningError {
			err: OnionErrorPacket {
				data: msg.reason.clone(),
				attribution_data: msg.attribution_data.clone(),
			},
			hold_time: None,
		})
	}

	/// Encrypted a failure packet using a shared secret.
	///
	/// For phantom nodes or inner Trampoline onions, a secondary_shared_secret can be passed, which
	/// will be used to encrypt the failure packet before applying the outer encryption step using
	/// incoming_packet_shared_secret.
	pub(super) fn get_encrypted_failure_packet(
		&self, incoming_packet_shared_secret: &[u8; 32], secondary_shared_secret: &Option<[u8; 32]>,
	) -> msgs::OnionErrorPacket {
		match self.0 {
			HTLCFailReasonRepr::Reason { ref data, ref failure_reason } => {
				// Final hop always reports zero hold time.
				let hold_time: u32 = 0;

				if let Some(secondary_shared_secret) = secondary_shared_secret {
					// Phantom hop always reports zero hold time too.
					let mut packet = build_failure_packet(
						secondary_shared_secret,
						*failure_reason,
						&data[..],
						hold_time,
					);

					process_failure_packet(&mut packet, incoming_packet_shared_secret, hold_time);
					crypt_failure_packet(incoming_packet_shared_secret, &mut packet);

					packet
				} else {
					build_failure_packet(
						incoming_packet_shared_secret,
						*failure_reason,
						&data[..],
						hold_time,
					)
				}
			},
			HTLCFailReasonRepr::LightningError { ref err, hold_time } => {
				let mut err = err.clone();
				let hold_time = hold_time.unwrap_or(0);

				process_failure_packet(&mut err, incoming_packet_shared_secret, hold_time);
				crypt_failure_packet(incoming_packet_shared_secret, &mut err);

				err
			},
		}
	}

	pub(super) fn decode_onion_failure<T: secp256k1::Signing, L: Deref>(
		&self, secp_ctx: &Secp256k1<T>, logger: &L, htlc_source: &HTLCSource,
	) -> DecodedOnionFailure
	where
		L::Target: Logger,
	{
		match self.0 {
			HTLCFailReasonRepr::LightningError { ref err, .. } => {
				process_onion_failure(secp_ctx, logger, &htlc_source, err.clone())
			},
			#[allow(unused)]
			HTLCFailReasonRepr::Reason { ref data, ref failure_reason } => {
				// we get a fail_malformed_htlc from the first hop
				// TODO: We'd like to generate a NetworkUpdate for temporary
				// failures here, but that would be insufficient as find_route
				// generally ignores its view of our own channels as we provide them via
				// ChannelDetails.
				if let &HTLCSource::OutboundRoute { ref path, .. } = htlc_source {
					DecodedOnionFailure {
						network_update: None,
						payment_failed_permanently: false,
						short_channel_id: Some(path.hops[0].short_channel_id),
						failed_within_blinded_path: false,
						hold_times: Vec::new(),
						#[cfg(any(test, feature = "_test_utils"))]
						onion_error_code: Some(*failure_reason),
						#[cfg(any(test, feature = "_test_utils"))]
						onion_error_data: Some(data.clone()),
						#[cfg(test)]
						attribution_failed_channel: None,
					}
				} else {
					unreachable!();
				}
			},
		}
	}
}

/// Allows `decode_next_hop` to return the next hop packet bytes for either payments or onion
/// message forwards.
pub(crate) trait NextPacketBytes: AsMut<[u8]> {
	fn new(len: usize) -> Self;
}

impl NextPacketBytes for FixedSizeOnionPacket {
	fn new(_len: usize) -> Self {
		Self([0 as u8; ONION_DATA_LEN])
	}
}

impl NextPacketBytes for Vec<u8> {
	fn new(len: usize) -> Self {
		vec![0 as u8; len]
	}
}

/// Data decrypted from a payment's onion payload.
pub(crate) enum Hop {
	/// This onion payload needs to be forwarded to a next-hop.
	Forward {
		/// Onion payload data used in forwarding the payment.
		next_hop_data: msgs::InboundOnionForwardPayload,
		/// Shared secret that was used to decrypt next_hop_data.
		shared_secret: SharedSecret,
		/// HMAC of the next hop's onion packet.
		next_hop_hmac: [u8; 32],
		/// Bytes of the onion packet we're forwarding.
		new_packet_bytes: [u8; ONION_DATA_LEN],
	},
	/// This onion was received via Trampoline, and needs to be forwarded to a subsequent Trampoline
	/// node.
	TrampolineForward {
		#[allow(unused)]
		outer_hop_data: msgs::InboundTrampolineEntrypointPayload,
		outer_shared_secret: SharedSecret,
		incoming_trampoline_public_key: PublicKey,
		trampoline_shared_secret: SharedSecret,
		next_trampoline_hop_data: msgs::InboundTrampolineForwardPayload,
		next_trampoline_hop_hmac: [u8; 32],
		new_trampoline_packet_bytes: Vec<u8>,
	},
	/// This onion was received via Trampoline, and needs to be forwarded to a subsequent Trampoline
	/// node.
	TrampolineBlindedForward {
		outer_hop_data: msgs::InboundTrampolineEntrypointPayload,
		outer_shared_secret: SharedSecret,
		#[allow(unused)]
		incoming_trampoline_public_key: PublicKey,
		trampoline_shared_secret: SharedSecret,
		next_trampoline_hop_data: msgs::InboundTrampolineBlindedForwardPayload,
		next_trampoline_hop_hmac: [u8; 32],
		new_trampoline_packet_bytes: Vec<u8>,
	},
	/// This onion payload needs to be forwarded to a next-hop.
	BlindedForward {
		/// Onion payload data used in forwarding the payment.
		next_hop_data: msgs::InboundOnionBlindedForwardPayload,
		/// Shared secret that was used to decrypt next_hop_data.
		shared_secret: SharedSecret,
		/// HMAC of the next hop's onion packet.
		next_hop_hmac: [u8; 32],
		/// Bytes of the onion packet we're forwarding.
		new_packet_bytes: [u8; ONION_DATA_LEN],
	},
	/// This onion payload was for us, not for forwarding to a next-hop. Contains information for
	/// verifying the incoming payment.
	Receive {
		/// Onion payload data used to receive our payment.
		hop_data: msgs::InboundOnionReceivePayload,
		/// Shared secret that was used to decrypt hop_data.
		shared_secret: SharedSecret,
	},
	/// This onion payload was for us, not for forwarding to a next-hop. Contains information for
	/// verifying the incoming payment.
	BlindedReceive {
		/// Onion payload data used to receive our payment.
		hop_data: msgs::InboundOnionBlindedReceivePayload,
		/// Shared secret that was used to decrypt hop_data.
		shared_secret: SharedSecret,
	},
	/// This onion payload was for us, not for forwarding to a next-hop, and it was sent to us via
	/// Trampoline. Contains information for verifying the incoming payment.
	TrampolineReceive {
		#[allow(unused)]
		outer_hop_data: msgs::InboundTrampolineEntrypointPayload,
		outer_shared_secret: SharedSecret,
		trampoline_hop_data: msgs::InboundOnionReceivePayload,
		trampoline_shared_secret: SharedSecret,
	},
	/// This onion payload was for us, not for forwarding to a next-hop, and it was sent to us via
	/// Trampoline. Contains information for verifying the incoming payment.
	TrampolineBlindedReceive {
		#[allow(unused)]
		outer_hop_data: msgs::InboundTrampolineEntrypointPayload,
		outer_shared_secret: SharedSecret,
		trampoline_hop_data: msgs::InboundOnionBlindedReceivePayload,
		trampoline_shared_secret: SharedSecret,
	},
}

impl Hop {
	pub(crate) fn is_intro_node_blinded_forward(&self) -> bool {
		match self {
			Self::BlindedForward {
				next_hop_data:
					msgs::InboundOnionBlindedForwardPayload {
						intro_node_blinding_point: Some(_), ..
					},
				..
			} => true,
			_ => false,
		}
	}

	pub(crate) fn shared_secret(&self) -> &SharedSecret {
		match self {
			Hop::Forward { shared_secret, .. } => shared_secret,
			Hop::BlindedForward { shared_secret, .. } => shared_secret,
			Hop::TrampolineForward { outer_shared_secret, .. } => outer_shared_secret,
			Hop::TrampolineBlindedForward { outer_shared_secret, .. } => outer_shared_secret,
			Hop::Receive { shared_secret, .. } => shared_secret,
			Hop::BlindedReceive { shared_secret, .. } => shared_secret,
			Hop::TrampolineReceive { outer_shared_secret, .. } => outer_shared_secret,
			Hop::TrampolineBlindedReceive { outer_shared_secret, .. } => outer_shared_secret,
		}
	}
}

/// Error returned when we fail to decode the onion packet.
#[derive(Debug)]
pub(crate) enum OnionDecodeErr {
	/// The HMAC of the onion packet did not match the hop data.
	Malformed { err_msg: &'static str, reason: LocalHTLCFailureReason },
	/// We failed to decode the onion payload.
	///
	/// If the payload we failed to decode belonged to a Trampoline onion, following the successful
	/// decoding of the outer onion, the trampoline_shared_secret field should be set.
	Relay {
		err_msg: &'static str,
		reason: LocalHTLCFailureReason,
		shared_secret: SharedSecret,
		trampoline_shared_secret: Option<SharedSecret>,
	},
}

pub(crate) fn decode_next_payment_hop<NS: Deref>(
	recipient: Recipient, hop_pubkey: &PublicKey, hop_data: &[u8], hmac_bytes: [u8; 32],
	payment_hash: PaymentHash, blinding_point: Option<PublicKey>, node_signer: NS,
) -> Result<Hop, OnionDecodeErr>
where
	NS::Target: NodeSigner,
{
	let blinded_node_id_tweak = blinding_point.map(|bp| {
		let blinded_tlvs_ss = node_signer.ecdh(recipient, &bp, None).unwrap().secret_bytes();
		let mut hmac = HmacEngine::<Sha256>::new(b"blinded_node_id");
		hmac.input(blinded_tlvs_ss.as_ref());
		Scalar::from_be_bytes(Hmac::from_engine(hmac).to_byte_array()).unwrap()
	});
	let shared_secret =
		node_signer.ecdh(recipient, hop_pubkey, blinded_node_id_tweak.as_ref()).unwrap();

	let decoded_hop: Result<(msgs::InboundOnionPayload, Option<_>), _> = decode_next_hop(
		shared_secret.secret_bytes(),
		hop_data,
		hmac_bytes,
		Some(payment_hash),
		(blinding_point, &(*node_signer)),
	);
	match decoded_hop {
		Ok((next_hop_data, Some((next_hop_hmac, FixedSizeOnionPacket(new_packet_bytes))))) => {
			match next_hop_data {
				msgs::InboundOnionPayload::Forward(next_hop_data) => Ok(Hop::Forward {
					shared_secret,
					next_hop_data,
					next_hop_hmac,
					new_packet_bytes,
				}),
				msgs::InboundOnionPayload::BlindedForward(next_hop_data) => {
					Ok(Hop::BlindedForward {
						shared_secret,
						next_hop_data,
						next_hop_hmac,
						new_packet_bytes,
					})
				},
				_ => {
					if blinding_point.is_some() {
						return Err(OnionDecodeErr::Malformed {
							err_msg:
								"Final Node OnionHopData provided for us as an intermediary node",
							reason: LocalHTLCFailureReason::InvalidOnionBlinding,
						});
					}
					Err(OnionDecodeErr::Relay {
						err_msg: "Final Node OnionHopData provided for us as an intermediary node",
						reason: LocalHTLCFailureReason::InvalidOnionPayload,
						shared_secret,
						trampoline_shared_secret: None,
					})
				},
			}
		},
		Ok((next_hop_data, None)) => match next_hop_data {
			msgs::InboundOnionPayload::Receive(hop_data) => {
				Ok(Hop::Receive { shared_secret, hop_data })
			},
			msgs::InboundOnionPayload::BlindedReceive(hop_data) => {
				Ok(Hop::BlindedReceive { shared_secret, hop_data })
			},
			msgs::InboundOnionPayload::TrampolineEntrypoint(hop_data) => {
				let incoming_trampoline_public_key = hop_data.trampoline_packet.public_key;
				let trampoline_blinded_node_id_tweak = hop_data.current_path_key.map(|bp| {
					let blinded_tlvs_ss =
						node_signer.ecdh(recipient, &bp, None).unwrap().secret_bytes();
					let mut hmac = HmacEngine::<Sha256>::new(b"blinded_node_id");
					hmac.input(blinded_tlvs_ss.as_ref());
					Scalar::from_be_bytes(Hmac::from_engine(hmac).to_byte_array()).unwrap()
				});
				let trampoline_shared_secret = node_signer
					.ecdh(
						recipient,
						&incoming_trampoline_public_key,
						trampoline_blinded_node_id_tweak.as_ref(),
					)
					.unwrap()
					.secret_bytes();
				let decoded_trampoline_hop: Result<
					(msgs::InboundTrampolinePayload, Option<([u8; 32], Vec<u8>)>),
					_,
				> = decode_next_hop(
					trampoline_shared_secret,
					&hop_data.trampoline_packet.hop_data,
					hop_data.trampoline_packet.hmac,
					Some(payment_hash),
					(blinding_point, node_signer),
				);
				match decoded_trampoline_hop {
					Ok((
						msgs::InboundTrampolinePayload::Forward(trampoline_hop_data),
						Some((next_trampoline_hop_hmac, new_trampoline_packet_bytes)),
					)) => Ok(Hop::TrampolineForward {
						outer_hop_data: hop_data,
						outer_shared_secret: shared_secret,
						incoming_trampoline_public_key,
						trampoline_shared_secret: SharedSecret::from_bytes(
							trampoline_shared_secret,
						),
						next_trampoline_hop_data: trampoline_hop_data,
						next_trampoline_hop_hmac,
						new_trampoline_packet_bytes,
					}),
					Ok((
						msgs::InboundTrampolinePayload::BlindedForward(trampoline_hop_data),
						Some((next_trampoline_hop_hmac, new_trampoline_packet_bytes)),
					)) => Ok(Hop::TrampolineBlindedForward {
						outer_hop_data: hop_data,
						outer_shared_secret: shared_secret,
						incoming_trampoline_public_key,
						trampoline_shared_secret: SharedSecret::from_bytes(
							trampoline_shared_secret,
						),
						next_trampoline_hop_data: trampoline_hop_data,
						next_trampoline_hop_hmac,
						new_trampoline_packet_bytes,
					}),
					Ok((msgs::InboundTrampolinePayload::Receive(trampoline_hop_data), None)) => {
						Ok(Hop::TrampolineReceive {
							outer_hop_data: hop_data,
							outer_shared_secret: shared_secret,
							trampoline_hop_data,
							trampoline_shared_secret: SharedSecret::from_bytes(
								trampoline_shared_secret,
							),
						})
					},
					Ok((
						msgs::InboundTrampolinePayload::BlindedReceive(trampoline_hop_data),
						None,
					)) => Ok(Hop::TrampolineBlindedReceive {
						outer_hop_data: hop_data,
						outer_shared_secret: shared_secret,
						trampoline_hop_data,
						trampoline_shared_secret: SharedSecret::from_bytes(
							trampoline_shared_secret,
						),
					}),
					Ok((msgs::InboundTrampolinePayload::BlindedForward(hop_data), None)) => {
						if hop_data.intro_node_blinding_point.is_some() {
							return Err(OnionDecodeErr::Relay {
								err_msg: "Non-final intro node Trampoline onion data provided to us as last hop",
								reason: LocalHTLCFailureReason::InvalidOnionPayload,
								shared_secret,
								trampoline_shared_secret: Some(SharedSecret::from_bytes(
									trampoline_shared_secret,
								)),
							});
						}
						Err(OnionDecodeErr::Malformed {
							err_msg: "Non-final Trampoline onion data provided to us as last hop",
							reason: LocalHTLCFailureReason::InvalidOnionBlinding,
						})
					},
					Ok((msgs::InboundTrampolinePayload::BlindedReceive(hop_data), Some(_))) => {
						if hop_data.intro_node_blinding_point.is_some() {
							return Err(OnionDecodeErr::Relay {
								err_msg: "Final Trampoline intro node onion data provided to us as intermediate hop",
								reason: LocalHTLCFailureReason::InvalidTrampolinePayload,
								shared_secret,
								trampoline_shared_secret: Some(SharedSecret::from_bytes(
									trampoline_shared_secret,
								)),
							});
						}
						Err(OnionDecodeErr::Malformed {
							err_msg:
								"Final Trampoline onion data provided to us as intermediate hop",
							reason: LocalHTLCFailureReason::InvalidOnionBlinding,
						})
					},
					Ok((msgs::InboundTrampolinePayload::Forward(_), None)) => {
						Err(OnionDecodeErr::Relay {
							err_msg: "Non-final Trampoline onion data provided to us as last hop",
							reason: LocalHTLCFailureReason::InvalidTrampolinePayload,
							shared_secret,
							trampoline_shared_secret: Some(SharedSecret::from_bytes(
								trampoline_shared_secret,
							)),
						})
					},
					Ok((msgs::InboundTrampolinePayload::Receive(_), Some(_))) => {
						Err(OnionDecodeErr::Relay {
							err_msg:
								"Final Trampoline onion data provided to us as intermediate hop",
							reason: LocalHTLCFailureReason::InvalidTrampolinePayload,
							shared_secret,
							trampoline_shared_secret: Some(SharedSecret::from_bytes(
								trampoline_shared_secret,
							)),
						})
					},
					Err(e) => Err(e),
				}
			},
			_ => {
				if blinding_point.is_some() {
					return Err(OnionDecodeErr::Malformed {
						err_msg: "Intermediate Node OnionHopData provided for us as a final node",
						reason: LocalHTLCFailureReason::InvalidOnionBlinding,
					});
				}
				Err(OnionDecodeErr::Relay {
					err_msg: "Intermediate Node OnionHopData provided for us as a final node",
					reason: LocalHTLCFailureReason::InvalidOnionPayload,
					shared_secret,
					trampoline_shared_secret: None,
				})
			},
		},
		Err(e) => Err(e),
	}
}

/// Build a payment onion, returning the first hop msat and cltv values as well.
///
/// `cur_block_height` should be set to the best known block height + 1.
pub fn create_payment_onion<T: secp256k1::Signing>(
	secp_ctx: &Secp256k1<T>, path: &Path, session_priv: &SecretKey, total_msat: u64,
	recipient_onion: &RecipientOnionFields, cur_block_height: u32, payment_hash: &PaymentHash,
	keysend_preimage: &Option<PaymentPreimage>, invoice_request: Option<&InvoiceRequest>,
	prng_seed: [u8; 32],
) -> Result<(msgs::OnionPacket, u64, u32), APIError> {
	create_payment_onion_internal(
		secp_ctx,
		path,
		session_priv,
		total_msat,
		recipient_onion,
		cur_block_height,
		payment_hash,
		keysend_preimage,
		invoice_request,
		prng_seed,
		None,
		None,
	)
}

pub(super) fn compute_trampoline_session_priv(outer_onion_session_priv: &SecretKey) -> SecretKey {
	// When creating the inner trampoline onion, we set the session priv to the hash of the outer
	// onion session priv.
	let session_priv_hash = Sha256::hash(&outer_onion_session_priv.secret_bytes()).to_byte_array();
	SecretKey::from_slice(&session_priv_hash[..]).expect("You broke SHA-256!")
}

/// Build a payment onion, returning the first hop msat and cltv values as well.
/// `cur_block_height` should be set to the best known block height + 1.
pub(crate) fn create_payment_onion_internal<T: secp256k1::Signing>(
	secp_ctx: &Secp256k1<T>, path: &Path, session_priv: &SecretKey, total_msat: u64,
	recipient_onion: &RecipientOnionFields, cur_block_height: u32, payment_hash: &PaymentHash,
	keysend_preimage: &Option<PaymentPreimage>, invoice_request: Option<&InvoiceRequest>,
	prng_seed: [u8; 32], trampoline_session_priv_override: Option<SecretKey>,
	trampoline_prng_seed_override: Option<[u8; 32]>,
) -> Result<(msgs::OnionPacket, u64, u32), APIError> {
	let mut outer_total_msat = total_msat;
	let mut outer_starting_htlc_offset = cur_block_height;
	let mut trampoline_packet_option = None;

	if let Some(blinded_tail) = &path.blinded_tail {
		if !blinded_tail.trampoline_hops.is_empty() {
			let trampoline_payloads;
			(trampoline_payloads, outer_total_msat, outer_starting_htlc_offset) =
				build_trampoline_onion_payloads(
					&blinded_tail,
					total_msat,
					recipient_onion,
					cur_block_height,
					keysend_preimage,
				)?;

			let trampoline_session_priv = trampoline_session_priv_override
				.unwrap_or_else(|| compute_trampoline_session_priv(session_priv));
			let trampoline_prng_seed = trampoline_prng_seed_override.unwrap_or(prng_seed);
			let onion_keys =
				construct_trampoline_onion_keys(&secp_ctx, &blinded_tail, &trampoline_session_priv);
			let trampoline_packet = construct_trampoline_onion_packet(
				trampoline_payloads,
				onion_keys,
				trampoline_prng_seed,
				payment_hash,
				// TODO: specify a fixed size for privacy in future spec upgrade
				None,
			)
			.map_err(|_| APIError::InvalidRoute {
				err: "Route size too large considering onion data".to_owned(),
			})?;

			trampoline_packet_option = Some(trampoline_packet);
		}
	}

	let (onion_payloads, htlc_msat, htlc_cltv) = build_onion_payloads(
		&path,
		outer_total_msat,
		recipient_onion,
		outer_starting_htlc_offset,
		keysend_preimage,
		invoice_request,
		trampoline_packet_option,
	)?;

	let onion_keys = construct_onion_keys(&secp_ctx, &path, session_priv);
	let onion_packet = construct_onion_packet(onion_payloads, onion_keys, prng_seed, payment_hash)
		.map_err(|_| APIError::InvalidRoute {
			err: "Route size too large considering onion data".to_owned(),
		})?;
	Ok((onion_packet, htlc_msat, htlc_cltv))
}

pub(crate) fn decode_next_untagged_hop<T, R: ReadableArgs<T>, N: NextPacketBytes>(
	shared_secret: [u8; 32], hop_data: &[u8], hmac_bytes: [u8; 32], read_args: T,
) -> Result<(R, Option<([u8; 32], N)>), OnionDecodeErr> {
	decode_next_hop(shared_secret, hop_data, hmac_bytes, None, read_args)
}

fn decode_next_hop<T, R: ReadableArgs<T>, N: NextPacketBytes>(
	shared_secret: [u8; 32], hop_data: &[u8], hmac_bytes: [u8; 32],
	payment_hash: Option<PaymentHash>, read_args: T,
) -> Result<(R, Option<([u8; 32], N)>), OnionDecodeErr> {
	let (rho, mu) = gen_rho_mu_from_shared_secret(&shared_secret);
	let mut hmac = HmacEngine::<Sha256>::new(&mu);
	hmac.input(hop_data);
	if let Some(tag) = payment_hash {
		hmac.input(&tag.0[..]);
	}
	if !fixed_time_eq(&Hmac::from_engine(hmac).to_byte_array(), &hmac_bytes) {
		return Err(OnionDecodeErr::Malformed {
			err_msg: "HMAC Check failed",
			reason: LocalHTLCFailureReason::InvalidOnionHMAC,
		});
	}

	let mut chacha = ChaCha20::new(&rho, &[0u8; 8]);
	let mut chacha_stream = ChaChaReader { chacha: &mut chacha, read: Cursor::new(&hop_data[..]) };
	match R::read(&mut chacha_stream, read_args) {
		Err(err) => {
			let reason = match err {
				// Unknown version
				msgs::DecodeError::UnknownVersion => LocalHTLCFailureReason::InvalidOnionVersion,
				// invalid_onion_payload
				msgs::DecodeError::UnknownRequiredFeature
				| msgs::DecodeError::InvalidValue
				| msgs::DecodeError::ShortRead => LocalHTLCFailureReason::InvalidOnionPayload,
				// Should never happen
				_ => LocalHTLCFailureReason::TemporaryNodeFailure,
			};
			return Err(OnionDecodeErr::Relay {
				err_msg: "Unable to decode our hop data",
				reason,
				shared_secret: SharedSecret::from_bytes(shared_secret),
				trampoline_shared_secret: None,
			});
		},
		Ok(msg) => {
			let mut hmac = [0; 32];
			if let Err(_) = chacha_stream.read_exact(&mut hmac[..]) {
				return Err(OnionDecodeErr::Relay {
					err_msg: "Unable to decode our hop data",
					reason: LocalHTLCFailureReason::InvalidOnionPayload,
					shared_secret: SharedSecret::from_bytes(shared_secret),
					trampoline_shared_secret: None,
				});
			}
			if hmac == [0; 32] {
				#[cfg(test)]
				{
					if chacha_stream.read.position() < hop_data.len() as u64 - 64 {
						// In tests, make sure that the initial onion packet data is, at least, non-0.
						// We could do some fancy randomness test here, but, ehh, whatever.
						// This checks for the issue where you can calculate the path length given the
						// onion data as all the path entries that the originator sent will be here
						// as-is (and were originally 0s).
						// Of course reverse path calculation is still pretty easy given naive routing
						// algorithms, but this fixes the most-obvious case.
						let mut next_bytes = [0; 32];
						chacha_stream.read_exact(&mut next_bytes).unwrap();
						assert_ne!(next_bytes[..], [0; 32][..]);
						chacha_stream.read_exact(&mut next_bytes).unwrap();
						assert_ne!(next_bytes[..], [0; 32][..]);
					}
				}
				return Ok((msg, None)); // We are the final destination for this packet
			} else {
				let mut new_packet_bytes = N::new(hop_data.len());
				let read_pos = hop_data.len() - chacha_stream.read.position() as usize;
				chacha_stream.read_exact(&mut new_packet_bytes.as_mut()[..read_pos]).unwrap();
				#[cfg(debug_assertions)]
				{
					// Check two things:
					// a) that the behavior of our stream here will return Ok(0) even if the TLV
					//    read above emptied out our buffer and the unwrap() wont needlessly panic
					// b) that we didn't somehow magically end up with extra data.
					let mut t = [0; 1];
					debug_assert!(chacha_stream.read(&mut t).unwrap() == 0);
				}
				// Once we've emptied the set of bytes our peer gave us, encrypt 0 bytes until we
				// fill the onion hop data we'll forward to our next-hop peer.
				chacha_stream.chacha.process_in_place(&mut new_packet_bytes.as_mut()[read_pos..]);
				return Ok((msg, Some((hmac, new_packet_bytes)))); // This packet needs forwarding
			}
		},
	}
}

pub(crate) const HOLD_TIME_LEN: usize = 4;
pub(crate) const MAX_HOPS: usize = 20;
pub(crate) const HMAC_LEN: usize = 4;

// Define the number of HMACs in the attributable data block. For the first node, there are 20 HMACs, and then for every
// subsequent node, the number of HMACs decreases by 1. 20 + 19 + 18 + ... + 1 = 20 * 21 / 2 = 210.
pub(crate) const HMAC_COUNT: usize = MAX_HOPS * (MAX_HOPS + 1) / 2;

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
/// Attribution data allows the sender of an HTLC to identify which hop failed an HTLC robustly,
/// preventing earlier hops from corrupting the HTLC failure information (or at least allowing the
/// sender to identify the earliest hop which corrupted HTLC failure information).
///
/// Additionally, it allows a sender to identify how long each hop along a path held an HTLC, with
/// 100ms granularity.
pub struct AttributionData {
	hold_times: [u8; MAX_HOPS * HOLD_TIME_LEN],
	hmacs: [u8; HMAC_LEN * HMAC_COUNT],
}

impl AttributionData {
	pub(crate) fn new() -> Self {
		Self { hold_times: [0; MAX_HOPS * HOLD_TIME_LEN], hmacs: [0; HMAC_LEN * HMAC_COUNT] }
	}
}

impl_writeable!(AttributionData, {
	hold_times,
	hmacs
});

impl AttributionData {
	/// Encrypts or decrypts the attribution data using the provided shared secret.
	pub(crate) fn crypt(&mut self, shared_secret: &[u8]) {
		let ammagext = gen_ammagext_from_shared_secret(&shared_secret);
		let mut chacha = ChaCha20::new(&ammagext, &[0u8; 8]);
		chacha.process_in_place(&mut self.hold_times);
		chacha.process_in_place(&mut self.hmacs);
	}

	/// Adds the current node's HMACs for all possible positions to this packet.
	pub(crate) fn add_hmacs(&mut self, shared_secret: &[u8], message: &[u8]) {
		let um: [u8; 32] = gen_um_from_shared_secret(&shared_secret);

		// Iterate over all possible positions that this hop could be on the path. An intermediate node does not have this
		// information, so it is up to the sender to verify the HMAC that corresponds to the actual position.
		for hmac_idx in 0..MAX_HOPS {
			// Calculate position relative to the final node. The final node is at position 0.
			let position: usize = MAX_HOPS - hmac_idx - 1;

			// The HMAC covers the original message and - for the assumed position - all the hold times and downstream
			// HMACs. As position decreases, fewer downstream HMACs are included.
			let mut hmac_engine = HmacEngine::<Sha256>::new(&um);
			hmac_engine.input(&message);
			hmac_engine.input(&self.hold_times[..(position + 1) * HOLD_TIME_LEN]);
			self.write_downstream_hmacs(position, &mut hmac_engine);

			let full_hmac = Hmac::from_engine(hmac_engine).to_byte_array();

			// Truncate the HMAC to save space. A low-probability collision acceptable here because the consequence is just
			// a pathfinding penalty.
			let hmac = &full_hmac[..HMAC_LEN];

			// Store the new HMAC.
			self.get_hmac_mut(hmac_idx).copy_from_slice(hmac);
		}
	}

	/// Writes the HMACs corresponding to the given position that have been added already by downstream hops. Position is
	/// relative to the final node. The final node is at position 0.
	pub(crate) fn write_downstream_hmacs(&self, position: usize, w: &mut HmacEngine<Sha256>) {
		// Set the index to the first downstream HMAC that we need to include. Note that we skip the first MAX_HOPS HMACs
		// because this is space reserved for the HMACs that we are producing for the current node.
		let mut hmac_idx = MAX_HOPS + MAX_HOPS - position - 1;

		// For every hop between the assumed position of this node and the final node, add the corresponding HMAC.
		for j in 0..position {
			w.input(self.get_hmac(hmac_idx));

			// HMAC block size gets smaller the closer we get to the (assumed) final hop.
			let block_size = MAX_HOPS - j - 1;

			// Move to the next HMAC in the block of the next downstream hop.
			hmac_idx += block_size;
		}
	}

	/// Verifies the attribution data of a failure packet for the given position in the path. If the HMAC checks out, the
	/// reported hold time is returned. If the HMAC does not match, an error is returned.
	fn verify(&self, message: &[u8], shared_secret: &[u8], position: usize) -> Result<u32, ()> {
		// Calculate the expected HMAC.
		let um = gen_um_from_shared_secret(shared_secret);
		let mut hmac = HmacEngine::<Sha256>::new(&um);
		hmac.input(&message);
		hmac.input(&self.hold_times[..(position + 1) * HOLD_TIME_LEN]);
		self.write_downstream_hmacs(position, &mut hmac);
		let expected_hmac = &Hmac::from_engine(hmac).to_byte_array()[..HMAC_LEN];

		// Compare with the actual HMAC.
		let hmac_idx = MAX_HOPS - position - 1;
		let actual_hmac = self.get_hmac(hmac_idx);
		if !fixed_time_eq(expected_hmac, actual_hmac) {
			return Err(());
		}

		// The HMAC checks out and the hold time can be extracted and returned;
		let hold_time: u32 = u32::from_be_bytes(self.get_hold_time_bytes(0).try_into().unwrap());

		Ok(hold_time)
	}

	/// Shifts hold times and HMACs to the left, taking into account HMAC pruning. This is the inverse operation of what
	/// hops do when back-propagating the failure.
	fn shift_left(&mut self) {
		// Shift hold times left.
		self.hold_times.copy_within(HOLD_TIME_LEN.., 0);

		// Shift HMACs left.
		let mut src_idx = MAX_HOPS;
		let mut dest_idx = 1;
		let mut copy_len = MAX_HOPS - 1;

		for _ in 0..MAX_HOPS - 1 {
			self.hmacs.copy_within(
				src_idx * HMAC_LEN..(src_idx + copy_len) * HMAC_LEN,
				dest_idx * HMAC_LEN,
			);

			src_idx += copy_len;
			dest_idx += copy_len + 1;
			copy_len -= 1;
		}
	}

	/// Shifts hold times and HMACS to the right, taking into account HMAC pruning. Intermediate nodes do this to create
	/// space for prepending their own hold time and HMACs.
	fn shift_right(&mut self) {
		// Shift hold times right. This will free up HOLD_TIME_LEN bytes at the beginning of the array.
		self.hold_times.copy_within(..(MAX_HOPS - 1) * HOLD_TIME_LEN, HOLD_TIME_LEN);

		// Shift HMACs right. Go backwards through the HMACs to prevent overwriting. This will free up MAX_HOPS slots at
		// the beginning of the array.
		let mut src_idx = HMAC_COUNT - 2;
		let mut dest_idx = HMAC_COUNT - 1;
		let mut copy_len = 1;

		for i in 0..MAX_HOPS - 1 {
			self.hmacs.copy_within(
				src_idx * HMAC_LEN..(src_idx + copy_len) * HMAC_LEN,
				dest_idx * HMAC_LEN,
			);

			// Break at last iteration to prevent underflow when updating indices.
			if i == MAX_HOPS - 2 {
				break;
			}

			copy_len += 1;
			src_idx -= copy_len + 1;
			dest_idx -= copy_len;
		}
	}

	fn get_hmac(&self, idx: usize) -> &[u8] {
		&self.hmacs[idx * HMAC_LEN..(idx + 1) * HMAC_LEN]
	}

	fn get_hmac_mut(&mut self, idx: usize) -> &mut [u8] {
		&mut self.hmacs[idx * HMAC_LEN..(idx + 1) * HMAC_LEN]
	}

	fn get_hold_time_bytes(&self, idx: usize) -> &[u8] {
		&self.hold_times[idx * HOLD_TIME_LEN..(idx + 1) * HOLD_TIME_LEN]
	}

	fn update(&mut self, message: &[u8], shared_secret: &[u8], hold_time: u32) {
		let hold_time_bytes: [u8; 4] = hold_time.to_be_bytes();
		self.hold_times[..HOLD_TIME_LEN].copy_from_slice(&hold_time_bytes);
		self.add_hmacs(shared_secret, message);
	}
}

/// Updates the attribution data for an intermediate node.
fn process_failure_packet(
	onion_error: &mut OnionErrorPacket, shared_secret: &[u8], hold_time: u32,
) {
	// Process received attribution data if present.
	if let Some(ref mut attribution_data) = onion_error.attribution_data {
		attribution_data.shift_right();
	}

	// Add this node's attribution data.
	update_attribution_data(onion_error, shared_secret, hold_time);
}

/// Updates fulfill attribution data with the given hold time for an intermediate or final node. If no downstream
/// attribution data is passed in, a new `AttributionData` field is instantiated. It is needless to say that in that
/// case the sender won't receive any hold times from nodes downstream of the current node.
pub(crate) fn process_fulfill_attribution_data(
	attribution_data: Option<AttributionData>, shared_secret: &[u8], hold_time: u32,
) -> AttributionData {
	let mut attribution_data =
		attribution_data.map_or(AttributionData::new(), |mut attribution_data| {
			// Shift the existing attribution data to the right to make space for the new hold time and HMACs.
			attribution_data.shift_right();

			attribution_data
		});

	// Add this node's hold time and HMACs. We pass in an empty message because there is no (failure) message in the
	// fulfill case.
	attribution_data.update(&[], &shared_secret, hold_time);
	attribution_data.crypt(&shared_secret);

	attribution_data
}

#[cfg(test)]
mod tests {
	use core::iter;
	use std::sync::Arc;

	use crate::io;
	use crate::ln::channelmanager::PaymentId;
	use crate::ln::msgs::{self, UpdateFailHTLC};
	use crate::ln::types::ChannelId;
	use crate::routing::router::{Path, PaymentParameters, Route, RouteHop};
	use crate::types::features::{ChannelFeatures, NodeFeatures};
	use crate::types::payment::PaymentHash;
	use crate::util::ser::{VecWriter, Writeable, Writer};

	#[allow(unused_imports)]
	use crate::prelude::*;
	use crate::util::test_utils::TestLogger;

	use super::*;
	use bitcoin::hex::{DisplayHex, FromHex};
	use bitcoin::secp256k1::Secp256k1;
	use bitcoin::secp256k1::{PublicKey, SecretKey};
	use types::features::Features;

	fn get_test_session_key() -> SecretKey {
		let hex = "4141414141414141414141414141414141414141414141414141414141414141";
		SecretKey::from_slice(&<Vec<u8>>::from_hex(hex).unwrap()[..]).unwrap()
	}

	fn build_test_path() -> Path {
		Path {
			hops: vec![
				RouteHop {
					pubkey: PublicKey::from_slice(
						&<Vec<u8>>::from_hex(
							"02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619",
						)
						.unwrap()[..],
					)
					.unwrap(),
					channel_features: ChannelFeatures::empty(),
					node_features: NodeFeatures::empty(),
					short_channel_id: 0,
					fee_msat: 0,
					cltv_expiry_delta: 0,
					maybe_announced_channel: true, // We fill in the payloads manually instead of generating them from RouteHops.
				},
				RouteHop {
					pubkey: PublicKey::from_slice(
						&<Vec<u8>>::from_hex(
							"0324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c",
						)
						.unwrap()[..],
					)
					.unwrap(),
					channel_features: ChannelFeatures::empty(),
					node_features: NodeFeatures::empty(),
					short_channel_id: 1,
					fee_msat: 0,
					cltv_expiry_delta: 0,
					maybe_announced_channel: true, // We fill in the payloads manually instead of generating them from RouteHops.
				},
				RouteHop {
					pubkey: PublicKey::from_slice(
						&<Vec<u8>>::from_hex(
							"027f31ebc5462c1fdce1b737ecff52d37d75dea43ce11c74d25aa297165faa2007",
						)
						.unwrap()[..],
					)
					.unwrap(),
					channel_features: ChannelFeatures::empty(),
					node_features: NodeFeatures::empty(),
					short_channel_id: 2,
					fee_msat: 0,
					cltv_expiry_delta: 0,
					maybe_announced_channel: true, // We fill in the payloads manually instead of generating them from RouteHops.
				},
				RouteHop {
					pubkey: PublicKey::from_slice(
						&<Vec<u8>>::from_hex(
							"032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991",
						)
						.unwrap()[..],
					)
					.unwrap(),
					channel_features: ChannelFeatures::empty(),
					node_features: NodeFeatures::empty(),
					short_channel_id: 3,
					fee_msat: 0,
					cltv_expiry_delta: 0,
					maybe_announced_channel: true, // We fill in the payloads manually instead of generating them from RouteHops.
				},
				RouteHop {
					pubkey: PublicKey::from_slice(
						&<Vec<u8>>::from_hex(
							"02edabbd16b41c8371b92ef2f04c1185b4f03b6dcd52ba9b78d9d7c89c8f221145",
						)
						.unwrap()[..],
					)
					.unwrap(),
					channel_features: ChannelFeatures::empty(),
					node_features: NodeFeatures::empty(),
					short_channel_id: 4,
					fee_msat: 0,
					cltv_expiry_delta: 0,
					maybe_announced_channel: true, // We fill in the payloads manually instead of generating them from RouteHops.
				},
			],
			blinded_tail: None,
		}
	}

	fn build_test_onion_keys() -> Vec<OnionKeys> {
		// Keys from BOLT 4, used in both test vector tests
		let secp_ctx = Secp256k1::new();

		let path = build_test_path();
		let route = Route { paths: vec![path], route_params: None };

		let onion_keys =
			super::construct_onion_keys(&secp_ctx, &route.paths[0], &get_test_session_key());
		assert_eq!(onion_keys.len(), route.paths[0].hops.len());
		onion_keys
	}

	#[test]
	fn onion_vectors() {
		let onion_keys = build_test_onion_keys();

		// Test generation of ephemeral keys and secrets. These values used to be part of the BOLT4
		// test vectors, but have since been removed. We keep them as they provide test coverage.
		let hex = "53eb63ea8a3fec3b3cd433b85cd62a4b145e1dda09391b348c4e1cd36a03ea66";
		assert_eq!(
			onion_keys[0].shared_secret.secret_bytes(),
			<Vec<u8>>::from_hex(hex).unwrap()[..]
		);

		let hex = "2ec2e5da605776054187180343287683aa6a51b4b1c04d6dd49c45d8cffb3c36";
		assert_eq!(onion_keys[0].blinding_factor[..], <Vec<u8>>::from_hex(hex).unwrap()[..]);

		let hex = "02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619";
		assert_eq!(
			onion_keys[0].ephemeral_pubkey.serialize()[..],
			<Vec<u8>>::from_hex(hex).unwrap()[..]
		);

		let hex = "ce496ec94def95aadd4bec15cdb41a740c9f2b62347c4917325fcc6fb0453986";
		assert_eq!(onion_keys[0].rho, <Vec<u8>>::from_hex(hex).unwrap()[..]);

		let hex = "b57061dc6d0a2b9f261ac410c8b26d64ac5506cbba30267a649c28c179400eba";
		assert_eq!(onion_keys[0].mu, <Vec<u8>>::from_hex(hex).unwrap()[..]);

		let hex = "a6519e98832a0b179f62123b3567c106db99ee37bef036e783263602f3488fae";
		assert_eq!(
			onion_keys[1].shared_secret.secret_bytes(),
			<Vec<u8>>::from_hex(hex).unwrap()[..]
		);

		let hex = "bf66c28bc22e598cfd574a1931a2bafbca09163df2261e6d0056b2610dab938f";
		assert_eq!(onion_keys[1].blinding_factor[..], <Vec<u8>>::from_hex(hex).unwrap()[..]);

		let hex = "028f9438bfbf7feac2e108d677e3a82da596be706cc1cf342b75c7b7e22bf4e6e2";
		assert_eq!(
			onion_keys[1].ephemeral_pubkey.serialize()[..],
			<Vec<u8>>::from_hex(hex).unwrap()[..]
		);

		let hex = "450ffcabc6449094918ebe13d4f03e433d20a3d28a768203337bc40b6e4b2c59";
		assert_eq!(onion_keys[1].rho, <Vec<u8>>::from_hex(hex).unwrap()[..]);

		let hex = "05ed2b4a3fb023c2ff5dd6ed4b9b6ea7383f5cfe9d59c11d121ec2c81ca2eea9";
		assert_eq!(onion_keys[1].mu, <Vec<u8>>::from_hex(hex).unwrap()[..]);

		let hex = "3a6b412548762f0dbccce5c7ae7bb8147d1caf9b5471c34120b30bc9c04891cc";
		assert_eq!(
			onion_keys[2].shared_secret.secret_bytes(),
			<Vec<u8>>::from_hex(hex).unwrap()[..]
		);

		let hex = "a1f2dadd184eb1627049673f18c6325814384facdee5bfd935d9cb031a1698a5";
		assert_eq!(onion_keys[2].blinding_factor[..], <Vec<u8>>::from_hex(hex).unwrap()[..]);

		let hex = "03bfd8225241ea71cd0843db7709f4c222f62ff2d4516fd38b39914ab6b83e0da0";
		assert_eq!(
			onion_keys[2].ephemeral_pubkey.serialize()[..],
			<Vec<u8>>::from_hex(hex).unwrap()[..]
		);

		let hex = "11bf5c4f960239cb37833936aa3d02cea82c0f39fd35f566109c41f9eac8deea";
		assert_eq!(onion_keys[2].rho, <Vec<u8>>::from_hex(hex).unwrap()[..]);

		let hex = "caafe2820fa00eb2eeb78695ae452eba38f5a53ed6d53518c5c6edf76f3f5b78";
		assert_eq!(onion_keys[2].mu, <Vec<u8>>::from_hex(hex).unwrap()[..]);

		let hex = "21e13c2d7cfe7e18836df50872466117a295783ab8aab0e7ecc8c725503ad02d";
		assert_eq!(
			onion_keys[3].shared_secret.secret_bytes(),
			<Vec<u8>>::from_hex(hex).unwrap()[..]
		);

		let hex = "7cfe0b699f35525029ae0fa437c69d0f20f7ed4e3916133f9cacbb13c82ff262";
		assert_eq!(onion_keys[3].blinding_factor[..], <Vec<u8>>::from_hex(hex).unwrap()[..]);

		let hex = "031dde6926381289671300239ea8e57ffaf9bebd05b9a5b95beaf07af05cd43595";
		assert_eq!(
			onion_keys[3].ephemeral_pubkey.serialize()[..],
			<Vec<u8>>::from_hex(hex).unwrap()[..]
		);

		let hex = "cbe784ab745c13ff5cffc2fbe3e84424aa0fd669b8ead4ee562901a4a4e89e9e";
		assert_eq!(onion_keys[3].rho, <Vec<u8>>::from_hex(hex).unwrap()[..]);

		let hex = "5052aa1b3d9f0655a0932e50d42f0c9ba0705142c25d225515c45f47c0036ee9";
		assert_eq!(onion_keys[3].mu, <Vec<u8>>::from_hex(hex).unwrap()[..]);

		let hex = "b5756b9b542727dbafc6765a49488b023a725d631af688fc031217e90770c328";
		assert_eq!(
			onion_keys[4].shared_secret.secret_bytes(),
			<Vec<u8>>::from_hex(hex).unwrap()[..]
		);

		let hex = "c96e00dddaf57e7edcd4fb5954be5b65b09f17cb6d20651b4e90315be5779205";
		assert_eq!(onion_keys[4].blinding_factor[..], <Vec<u8>>::from_hex(hex).unwrap()[..]);

		let hex = "03a214ebd875aab6ddfd77f22c5e7311d7f77f17a169e599f157bbcdae8bf071f4";
		assert_eq!(
			onion_keys[4].ephemeral_pubkey.serialize()[..],
			<Vec<u8>>::from_hex(hex).unwrap()[..]
		);

		let hex = "034e18b8cc718e8af6339106e706c52d8df89e2b1f7e9142d996acf88df8799b";
		assert_eq!(onion_keys[4].rho, <Vec<u8>>::from_hex(hex).unwrap()[..]);

		let hex = "8e45e5c61c2b24cb6382444db6698727afb063adecd72aada233d4bf273d975a";
		assert_eq!(onion_keys[4].mu, <Vec<u8>>::from_hex(hex).unwrap()[..]);

		// Packet creation test vectors from BOLT 4 (see
		// https://github.com/lightning/bolts/blob/16973e2b857e853308cafd59e42fa830d75b1642/bolt04/onion-test.json).
		// Note that we represent the test vector payloads 2 and 5 through RawOnionHopData::data
		// with raw hex instead of our in-memory enums, as the payloads contains custom types, and
		// we have no way of representing that with our enums.
		let payloads = vec!(
			RawOnionHopData::new(msgs::OutboundOnionPayload::Forward {
				short_channel_id: 1,
				amt_to_forward: 15000,
				outgoing_cltv_value: 1500,
			}),
			/*
			The second payload is represented by raw hex as it contains custom type data. Content:
			1. length "52" (payload_length 82).

			The first part of the payload has the `NonFinalNode` format, with content as follows:
			2. amt_to_forward "020236b0"
			   02 (type amt_to_forward) 02 (length 2) 36b0 (value 14000)
			3. outgoing_cltv_value "04020578"
			   04 (type outgoing_cltv_value) 02 (length 2) 0578 (value 1400)
			4. short_channel_id "06080000000000000002"
			   06 (type short_channel_id) 08 (length 8) 0000000000000002 (value 2)

			The rest of the payload is custom type data:
			5. custom_record "fd02013c0102030405060708090a0b0c0d0e0f0102030405060708090a0b0c0d0e0f0102030405060708090a0b0c0d0e0f0102030405060708090a0b0c0d0e0f"
			*/
			RawOnionHopData {
				data: <Vec<u8>>::from_hex("52020236b00402057806080000000000000002fd02013c0102030405060708090a0b0c0d0e0f0102030405060708090a0b0c0d0e0f0102030405060708090a0b0c0d0e0f0102030405060708090a0b0c0d0e0f").unwrap(),
			},
			RawOnionHopData::new(msgs::OutboundOnionPayload::Forward {
				short_channel_id: 3,
				amt_to_forward: 12500,
				outgoing_cltv_value: 1250,
			}),
			RawOnionHopData::new(msgs::OutboundOnionPayload::Forward {
				short_channel_id: 4,
				amt_to_forward: 10000,
				outgoing_cltv_value: 1000,
			}),
			/*
			The fifth payload is represented by raw hex as it contains custom type data. Content:
			1. length "fd0110" (payload_length 272).

			The first part of the payload has the `FinalNode` format, with content as follows:
			1. amt_to_forward "02022710"
			   02 (type amt_to_forward) 02 (length 2) 2710 (value 10000)
			2. outgoing_cltv_value "040203e8"
			   04 (type outgoing_cltv_value) 02 (length 2) 03e8 (value 1000)
			3. payment_data "082224a33562c54507a9334e79f0dc4f17d407e6d7c61f0e2f3d0d38599502f617042710"
			   08 (type short_channel_id) 22 (length 34) 24a33562c54507a9334e79f0dc4f17d407e6d7c61f0e2f3d0d38599502f61704 (payment_secret) 2710 (total_msat value 10000)

			The rest of the payload is custom type data:
			4. custom_record "fd012de02a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a"
			*/
			RawOnionHopData {
				data: <Vec<u8>>::from_hex("fd011002022710040203e8082224a33562c54507a9334e79f0dc4f17d407e6d7c61f0e2f3d0d38599502f617042710fd012de02a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a").unwrap(),
			},
		);

		// Verify that the serialized OnionHopDataFormat::NonFinalNode tlv payloads matches the test vectors
		let mut w = VecWriter(Vec::new());
		payloads[0].write(&mut w).unwrap();
		let hop_1_serialized_payload = w.0;
		let hex = "1202023a98040205dc06080000000000000001";
		let expected_serialized_hop_1_payload = &<Vec<u8>>::from_hex(hex).unwrap()[..];
		assert_eq!(hop_1_serialized_payload, expected_serialized_hop_1_payload);

		w = VecWriter(Vec::new());
		payloads[2].write(&mut w).unwrap();
		let hop_3_serialized_payload = w.0;
		let hex = "12020230d4040204e206080000000000000003";
		let expected_serialized_hop_3_payload = &<Vec<u8>>::from_hex(hex).unwrap()[..];
		assert_eq!(hop_3_serialized_payload, expected_serialized_hop_3_payload);

		w = VecWriter(Vec::new());
		payloads[3].write(&mut w).unwrap();
		let hop_4_serialized_payload = w.0;
		let hex = "1202022710040203e806080000000000000004";
		let expected_serialized_hop_4_payload = &<Vec<u8>>::from_hex(hex).unwrap()[..];
		assert_eq!(hop_4_serialized_payload, expected_serialized_hop_4_payload);

		let pad_keytype_seed =
			super::gen_pad_from_shared_secret(&get_test_session_key().secret_bytes());

		let packet: msgs::OnionPacket = super::construct_onion_packet_with_writable_hopdata::<_>(
			payloads,
			onion_keys,
			pad_keytype_seed,
			&PaymentHash([0x42; 32]),
		)
		.unwrap();

		let hex = "0002EEC7245D6B7D2CCB30380BFBE2A3648CD7A942653F5AA340EDCEA1F283686619F7F3416A5AA36DC7EEB3EC6D421E9615471AB870A33AC07FA5D5A51DF0A8823AABE3FEA3F90D387529D4F72837F9E687230371CCD8D263072206DBED0234F6505E21E282ABD8C0E4F5B9FF8042800BBAB065036EADD0149B37F27DDE664725A49866E052E809D2B0198AB9610FAA656BBF4EC516763A59F8F42C171B179166BA38958D4F51B39B3E98706E2D14A2DAFD6A5DF808093ABFCA5AEAACA16EDED5DB7D21FB0294DD1A163EDF0FB445D5C8D7D688D6DD9C541762BF5A5123BF9939D957FE648416E88F1B0928BFA034982B22548E1A4D922690EECF546275AFB233ACF4323974680779F1A964CFE687456035CC0FBA8A5428430B390F0057B6D1FE9A8875BFA89693EEB838CE59F09D207A503EE6F6299C92D6361BC335FCBF9B5CD44747AADCE2CE6069CFDC3D671DAEF9F8AE590CF93D957C9E873E9A1BC62D9640DC8FC39C14902D49A1C80239B6C5B7FD91D05878CBF5FFC7DB2569F47C43D6C0D27C438ABFF276E87364DEB8858A37E5A62C446AF95D8B786EAF0B5FCF78D98B41496794F8DCAAC4EEF34B2ACFB94C7E8C32A9E9866A8FA0B6F2A06F00A1CCDE569F97EEC05C803BA7500ACC96691D8898D73D8E6A47B8F43C3D5DE74458D20EDA61474C426359677001FBD75A74D7D5DB6CB4FEB83122F133206203E4E2D293F838BF8C8B3A29ACB321315100B87E80E0EDB272EE80FDA944E3FB6084ED4D7F7C7D21C69D9DA43D31A90B70693F9B0CC3EAC74C11AB8FF655905688916CFA4EF0BD04135F2E50B7C689A21D04E8E981E74C6058188B9B1F9DFC3EEC6838E9FFBCF22CE738D8A177C19318DFFEF090CEE67E12DE1A3E2A39F61247547BA5257489CBC11D7D91ED34617FCC42F7A9DA2E3CF31A94A210A1018143173913C38F60E62B24BF0D7518F38B5BAB3E6A1F8AEB35E31D6442C8ABB5178EFC892D2E787D79C6AD9E2FC271792983FA9955AC4D1D84A36C024071BC6E431B625519D556AF38185601F70E29035EA6A09C8B676C9D88CF7E05E0F17098B584C4168735940263F940033A220F40BE4C85344128B14BEB9E75696DB37014107801A59B13E89CD9D2258C169D523BE6D31552C44C82FF4BB18EC9F099F3BF0E5B1BB2BA9A87D7E26F98D294927B600B5529C47E04D98956677CBCEE8FA2B60F49776D8B8C367465B7C626DA53700684FB6C918EAD0EAB8360E4F60EDD25B4F43816A75ECF70F909301825B512469F8389D79402311D8AECB7B3EF8599E79485A4388D87744D899F7C47EE644361E17040A7958C8911BE6F463AB6A9B2AFACD688EC55EF517B38F1339EFC54487232798BB25522FF4572FF68567FE830F92F7B8113EFCE3E98C3FFFBAEDCE4FD8B50E41DA97C0C08E423A72689CC68E68F752A5E3A9003E64E35C957CA2E1C48BB6F64B05F56B70B575AD2F278D57850A7AD568C24A4D32A3D74B29F03DC125488BC7C637DA582357F40B0A52D16B3B40BB2C2315D03360BC24209E20972C200566BCF3BBE5C5B0AEDD83132A8A4D5B4242BA370B6D67D9B67EB01052D132C7866B9CB502E44796D9D356E4E3CB47CC527322CD24976FE7C9257A2864151A38E568EF7A79F10D6EF27CC04CE382347A2488B1F404FDBF407FE1CA1C9D0D5649E34800E25E18951C98CAE9F43555EEF65FEE1EA8F15828807366C3B612CD5753BF9FB8FCED08855F742CDDD6F765F74254F03186683D646E6F09AC2805586C7CF11998357CAFC5DF3F285329366F475130C928B2DCEBA4AA383758E7A9D20705C4BB9DB619E2992F608A1BA65DB254BB389468741D0502E2588AEB54390AC600C19AF5C8E61383FC1BEBE0029E4474051E4EF908828DB9CCA13277EF65DB3FD47CCC2179126AAEFB627719F421E20";
		assert_eq!(packet.encode(), <Vec<u8>>::from_hex(hex).unwrap());
	}

	#[test]
	fn test_attributable_failure_packet_onion_mutations() {
		// Define the length of the (legacy) failure message field in the test.
		const FAILURE_MESSAGE_LEN: usize = 1060;

		for mutating_node in 0..5 {
			let attribution_data_mutations = (0..HOLD_TIME_LEN * MAX_HOPS)
				.map(AttributionDataMutationType::HoldTimes)
				.chain((0..HMAC_LEN * HMAC_COUNT).map(AttributionDataMutationType::Hmacs));

			let failure_mutations = (0..FAILURE_MESSAGE_LEN).map(MutationType::FailureMessage);

			for mutation_type in failure_mutations
				.chain(attribution_data_mutations.map(MutationType::AttributionData))
				.chain(iter::once(MutationType::DropAttributionData))
			{
				// If the mutation is in the attribution data and not in the failure message itself, the invalid
				// attribution data should be ignored and the failure should still surface.
				let failure_ok = matches!(mutation_type, MutationType::DropAttributionData)
					|| matches!(mutation_type, MutationType::AttributionData(_));

				let mutation = Mutation { node: mutating_node, mutation_type };
				let decrypted_failure =
					test_attributable_failure_packet_onion_with_mutation(Some(mutation));

				if failure_ok {
					assert_eq!(
						decrypted_failure.onion_error_code,
						Some(LocalHTLCFailureReason::IncorrectPaymentDetails)
					);
					continue;
				}

				// Currently attribution data isn't used yet to identify the failing node, because this would hinder the
				// upgrade path.
				assert!(decrypted_failure.short_channel_id.is_none());

				// Assert that attribution data is interpreted correctly via a test-only field.
				assert!(decrypted_failure.attribution_failed_channel == Some(mutating_node as u64));

				assert_eq!(decrypted_failure.hold_times, [5, 4, 3, 2, 1][..mutating_node]);
			}
		}
	}

	#[test]
	fn test_attributable_failure_packet_onion_happy() {
		let decrypted_failure = test_attributable_failure_packet_onion_with_mutation(None);
		assert_eq!(
			decrypted_failure.onion_error_code,
			Some(LocalHTLCFailureReason::IncorrectPaymentDetails)
		);
		assert_eq!(decrypted_failure.hold_times, [5, 4, 3, 2, 1]);
	}

	enum AttributionDataMutationType {
		HoldTimes(usize),
		Hmacs(usize),
	}

	enum MutationType {
		FailureMessage(usize),
		AttributionData(AttributionDataMutationType),
		DropAttributionData,
	}

	struct Mutation {
		node: usize,
		mutation_type: MutationType,
	}

	fn test_attributable_failure_packet_onion_with_mutation(
		mutation: Option<Mutation>,
	) -> DecodedOnionFailure {
		struct ExpectedMessage<'a> {
			message: &'a str,
			attribution_data: &'a str,
		}

		impl<'a> ExpectedMessage<'a> {
			fn assert_eq(&self, actual: &OnionErrorPacket) {
				assert_eq!(actual.data.to_lower_hex_string(), self.message);

				let (expected_hold_times, expected_hmacs) =
					self.attribution_data.split_at(MAX_HOPS * HOLD_TIME_LEN * 2);
				assert_eq!(
					actual.attribution_data.as_ref().unwrap().hold_times.to_lower_hex_string(),
					expected_hold_times
				);
				assert_eq!(
					actual.attribution_data.as_ref().unwrap().hmacs.to_lower_hex_string(),
					expected_hmacs
				);
			}
		}

		const FAILURE_DATA: &str = "0000000000000064000c3500fd84d1fd012c808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080";
		const EXPECTED_MESSAGES: [ExpectedMessage; 5] = [
			ExpectedMessage {
				message: "146e94a9086dbbed6a0ab6932d00c118a7195dbf69b7d7a12b0e6956fc54b5e0a989f165b5f12fd45edd73a5b0c48630ff5be69500d3d82a29c0803f0a0679a6a073c33a6fb8250090a3152eba3f11a85184fa87b67f1b0354d6f48e3b342e332a17b7710f342f342a87cf32eccdf0afc2160808d58abb5e5840d2c760c538e63a6f841970f97d2e6fe5b8739dc45e2f7f5f532f227bcc2988ab0f9cc6d3f12909cd5842c37bc8c7608475a5ebbe10626d5ecc1f3388ad5f645167b44a4d166f87863fe34918cea25c18059b4c4d9cb414b59f6bc50c1cea749c80c43e2344f5d23159122ed4ab9722503b212016470d9610b46c35dbeebaf2e342e09770b38392a803bc9d2e7c8d6d384ffcbeb74943fe3f64afb2a543a6683c7db3088441c531eeb4647518cb41992f8954f1269fb969630944928c2d2b45593731b5da0c4e70d04a0a57afe4af42e99912fbb4f8883a5ecb9cb29b883cb6bfa0f4db2279ff8c6d2b56a232f55ba28fe7dfa70a9ab0433a085388f25cce8d53de6a2fbd7546377d6ede9027ad173ba1f95767461a3689ef405ab608a21086165c64b02c1782b04a6dba2361a7784603069124e12f2f6dcb1ec7612a4fbf94c0e14631a2bef6190c3d5f35e0c4b32aa85201f449d830fd8f782ec758b0910428e3ec3ca1dba3b6c7d89f69e1ee1b9df3dfbbf6d361e1463886b38d52e8f43b73a3bd48c6f36f5897f514b93364a31d49d1d506340b1315883d425cb36f4ea553430d538fd6f3596d4afc518db2f317dd051abc0d4bfb0a7870c3db70f19fe78d6604bbf088fcb4613f54e67b038277fedcd9680eb97bdffc3be1ab2cbcbafd625b8a7ac34d8c190f98d3064ecd3b95b8895157c6a37f31ef4de094b2cb9dbf8ff1f419ba0ecacb1bb13df0253b826bec2ccca1e745dd3b3e7cc6277ce284d649e7b8285727735ff4ef6cca6c18e2714f4e2a1ac67b25213d3bb49763b3b94e7ebf72507b71fb2fe0329666477ee7cb7ebd6b88ad5add8b217188b1ca0fa13de1ec09cc674346875105be6e0e0d6c8928eb0df23c39a639e04e4aedf535c4e093f08b2c905a14f25c0c0fe47a5a1535ab9eae0d9d67bdd79de13a08d59ee05385c7ea4af1ad3248e61dd22f8990e9e99897d653dd7b1b1433a6d464ea9f74e377f2d8ce99ba7dbc753297644234d25ecb5bd528e2e2082824681299ac30c05354baaa9c3967d86d7c07736f87fc0f63e5036d47235d7ae12178ced3ae36ee5919c093a02579e4fc9edad2c446c656c790704bfc8e2c491a42500aa1d75c8d4921ce29b753f883e17c79b09ea324f1f32ddf1f3284cd70e847b09d90f6718c42e5c94484cc9cbb0df659d255630a3f5a27e7d5dd14fa6b974d1719aa98f01a20fb4b7b1c77b42d57fab3c724339d459ee4a1c6b5d3bd4e08624c786a257872acc9ad3ff62222f2265a658d9f2a007229a5293b67ec91c84c4b4407c228434bad8a815ca9b256c776bd2c9f",
				attribution_data: "d77d0711b5f71d1d1be56bd88b3bb7ebc1792bb739ea7ebc1bc3b031b8bc2df3a50e25aeb99f47d7f7ab39e24187d3f4df9c4333463b053832ee9ac07274a5261b8b2a01fc09ce9ea7cd04d7b585dfb8cf5958e3f3f2a4365d1ec0df1d83c6a6221b5b7d1ff30156a2289a1d3ee559e7c7256bda444bb8e046f860e00b3a59a85e1e1a43de215fd5e6bf646a5deab97b1912c934e31b1cfd344764d6ca7e14ea7b3f2a951aba907c964c0f5d19a44e6d1d7279637321fa598adde927b3087d238f8b426ecde500d318617cdb7a56e6ce3520fc95be41a549973764e4dc483853ecc313947709f1b5199cb077d46e701fa633e11d3e13b03e9212c115ca6fa004b2f3dd912814693b705a561a06da54cdf603677a3abecdc22c7358c2de3cef771b366a568150aeecc86ad1990bb0f4e2865933b03ea0df87901bff467908273dc6cea31cbab0e2b8d398d10b001058c259ed221b7b55762f4c7e49c8c11a45a107b7a2c605c26dc5b0b10d719b1c844670102b2b6a36c43fe4753a78a483fc39166ae28420f112d50c10ee64ca69569a2f690712905236b7c2cb7ac8954f02922d2d918c56d42649261593c47b14b324a65038c3c5be8d3c403ce0c8f19299b1664bf077d7cf1636c4fb9685a8e58b7029fd0939fa07925a60bed339b23f973293598f595e75c8f9d455d7cebe4b5e23357c8bd47d66d6628b39427e37e0aecbabf46c11be6771f7136e108a143ae9bafba0fc47a51b6c7deef4cba54bae906398ee3162a41f2191ca386b628bde7e1dd63d1611aa01a95c456df337c763cb8c3a81a6013aa633739d8cd554c688102211725e6adad165adc1bcd429d020c51b4b25d2117e8bb27eb0cc7020f9070d4ad19ac31a76ebdf5f9246646aeadbfb9a3f1d75bd8237961e786302516a1a781780e8b73f58dc06f307e58bd0eb1d8f5c9111f01312974c1dc777a6a2d3834d8a2a40014e9818d0685cb3919f6b3b788ddc640b0ff9b1854d7098c7dd6f35196e902b26709640bc87935a3914869a807e8339281e9cedaaca99474c3e7bdd35050bb998ab4546f9900904e0e39135e861ff7862049269701081ebce32e4cca992c6967ff0fd239e38233eaf614af31e186635e9439ec5884d798f9174da6ff569d68ed5c092b78bd3f880f5e88a7a8ab36789e1b57b035fb6c32a6358f51f83e4e5f46220bcad072943df8bd9541a61b7dae8f30fa3dd5fb39b1fd9a0b8e802552b78d4ec306ecee15bfe6da14b29ba6d19ce5be4dd478bca74a52429cd5309d404655c3dec85c252"
			},
			ExpectedMessage {
				message: "7512354d6a26781d25e65539772ba049b7ed7c530bf75ab7ef80cf974b978a07a1c3dabc61940011585323f70fa98cfa1d4c868da30b1f751e44a72d9b3f79809c8c51c9f0843daa8fe83587844fedeacb7348362003b31922cbb4d6169b2087b6f8d192d9cfe5363254cd1fde24641bde9e422f170c3eb146f194c48a459ae2889d706dc654235fa9dd20307ea54091d09970bf956c067a3bcc05af03c41e01af949a131533778bf6ee3b546caf2eabe9d53d0fb2e8cc952b7e0f5326a69ed2e58e088729a1d85971c6b2e129a5643f3ac43da031e655b27081f10543262cf9d72d6f64d5d96387ac0d43da3e3a03da0c309af121dcf3e99192efa754eab6960c256ffd4c546208e292e0ab9894e3605db098dc16b40f17c320aa4a0e42fc8b105c22f08c9bc6537182c24e32062c6cd6d7ec7062a0c2c2ecdae1588c82185cdc61d874ee916a7873ac54cddf929354f307e870011704a0e9fbc5c7802d6140134028aca0e78a7e2f3d9e5c7e49e20c3a56b624bfea51196ec9e88e4e56be38ff56031369f45f1e03be826d44a182f270c153ee0d9f8cf9f1f4132f33974e37c7887d5b857365c873cb218cbf20d4be3abdb2a2011b14add0a5672e01e5845421cf6dd6faca1f2f443757aae575c53ab797c2227ecdab03882bbbf4599318cefafa72fa0c9a0f5a51d13c9d0e5d25bfcfb0154ed25895260a9df8743ac188714a3f16960e6e2ff663c08bffda41743d50960ea2f28cda0bc3bd4a180e297b5b41c700b674cb31d99c7f2a1445e121e772984abff2bbe3f42d757ceeda3d03fb1ffe710aecabda21d738b1f4620e757e57b123dbc3c4aa5d9617dfa72f4a12d788ca596af14bea583f502f16fdc13a5e739afb0715424af2767049f6b9aa107f69c5da0e85f6d8c5e46507e14616d5d0b797c3dea8b74a1b12d4e47ba7f57f09d515f6c7314543f78b5e85329d50c5f96ee2f55bbe0df742b4003b24ccbd4598a64413ee4807dc7f2a9c0b92424e4ae1b418a3cdf02ea4da5c3b12139348aa7022cc8272a3a1714ee3e4ae111cffd1bdfd62c503c80bdf27b2feaea0d5ab8fe00f9cec66e570b00fd24b4a2ed9a5f6384f148a4d6325110a41ca5659ebc5b98721d298a52819b6fb150f273383f1c5754d320be428941922da790e17f482989c365c078f7f3ae100965e1b38c052041165295157e1a7c5b7a57671b842d4d85a7d971323ad1f45e17a16c4656d889fc75c12fc3d8033f598306196e29571e414281c5da19c12605f48347ad5b4648e371757cbe1c40adb93052af1d6110cfbf611af5c8fc682b7e2ade3bfca8b5c7717d19fc9f97964ba6025aebbc91a6671e259949dcf40984342118de1f6b514a7786bd4f6598ffbe1604cef476b2a4cb1343db608aca09d1d38fc23e98ee9c65e7f6023a8d1e61fd4f34f753454bd8e858c8ad6be6403edc599c220e03ca917db765980ac781e758179cd93983e9c1e769e4241d47c",
				attribution_data: "1571e10db7f8aa9f8e7e99caaf9c892e106c817df1d8e3b7b0e39d1c48f631e473e17e205489dd7b3c634cac3be0825cbf01418cd46e83c24b8d9c207742db9a0f0e5bcd888086498159f08080ba7bf36dee297079eb841391ccd3096da76461e314863b6412efe0ffe228d51c6097db10d3edb2e50ea679820613bfe9db11ba02920ab4c1f2a79890d997f1fc022f3ab78f0029cc6de0c90be74d55f4a99bf77a50e20f8d076fe61776190a61d2f41c408871c0279309cba3b60fcdc7efc4a0e90b47cb4a418fc78f362ecc7f15ebbce9f854c09c7be300ebc1a40a69d4c7cb7a19779b6905e82bec221a709c1dab8cbdcde7b527aca3f54bde651aa9f3f2178829cee3f1c0b9292758a40cc63bd998fcd0d3ed4bdcaf1023267b8f8e44130a63ad15f76145936552381eabb6d684c0a3af6ba8efcf207cebaea5b7acdbb63f8e7221102409d10c23f0514dc9f4d0efb2264161a193a999a23e992632710580a0d320f676d367b9190721194514457761af05207cdab2b6328b1b3767eacb36a7ef4f7bd2e16762d13df188e0898b7410f62459458712a44bf594ae662fd89eb300abb6952ff8ad40164f2bcd7f86db5c7650b654b79046de55d51aa8061ce35f867a3e8f5bf98ad920be827101c64fb871d86e53a4b3c0455bfac5784168218aa72cbee86d9c750a9fa63c363a8b43d7bf4b2762516706a306f0aa3be1ec788b5e13f8b24837e53ac414f211e11c7a093cd9653dfa5fba4e377c79adfa5e841e2ddb6afc054fc715c05ddc6c8fc3e1ee3406e1ffceb2df77dc2f02652614d1bfcfaddebaa53ba919c7051034e2c7b7cfaabdf89f26e7f8e3f956d205dfab747ad0cb505b85b54a68439621b25832cbc2898919d0cd7c0a64cfd235388982dd4dd68240cb668f57e1d2619a656ed326f8c92357ee0d9acead3c20008bc5f04ca8059b55d77861c6d04dfc57cfba57315075acbe1451c96cf28e1e328e142890248d18f53b5d3513ce574dea7156cf596fdb3d909095ec287651f9cf1bcdc791c5938a5dd9b47e84c004d24ab3ae74492c7e8dcc1da15f65324be2672947ec82074cac8ce2b925bc555facbbf1b55d63ea6fbea6a785c97d4caf2e1dad9551b7f66c31caae5ebc7c0047e892f201308fcf452c588be0e63d89152113d87bf0dbd01603b4cdc7f0b724b0714a9851887a01f709408882e18230fe810b9fafa58a666654576d8eba3005f07221f55a6193815a672e5db56204053bc4286fa3db38250396309fd28011b5708a26a2d76c4a333b69b6bfd272fb"
			},
			ExpectedMessage {
				message: "145bc1c63058f7204abbd2320d422e69fb1b3801a14312f81e5e29e6b5f4774cfed8a25241d3dfb7466e749c1b3261559e49090853612e07bd669dfb5f4c54162fa504138dabd6ebcf0db8017840c35f12a2cfb84f89cc7c8959a6d51815b1d2c5136cedec2e4106bb5f2af9a21bd0a02c40b44ded6e6a90a145850614fb1b0eef2a03389f3f2693bc8a755630fc81fff1d87a147052863a71ad5aebe8770537f333e07d841761ec448257f948540d8f26b1d5b66f86e073746106dfdbb86ac9475acf59d95ece037fba360670d924dce53aaa74262711e62a8fc9eb70cd8618fbedae22853d3053c7f10b1a6f75369d7f73c419baa7dbf9f1fc5895362dcc8b6bd60cca4943ef7143956c91992119bccbe1666a20b7de8a2ff30a46112b53a6bb79b763903ecbd1f1f74952fb1d8eb0950c504df31fe702679c23b463f82a921a2c931500ab08e686cffb2d87258d254fb17843959cccd265a57ba26c740f0f231bb76df932b50c12c10be90174b37d454a3f8b284c849e86578a6182c4a7b2e47dd57d44730a1be9fec4ad07287a397e28dce4fda57e9cdfdb2eb5afdf0d38ef19d982341d18d07a556bb16c1416f480a396f278373b8fd9897023a4ac506e65cf4c306377730f9c8ca63cf47565240b59c4861e52f1dab84d938e96fb31820064d534aca05fd3d2600834fe4caea98f2a748eb8f200af77bd9fbf46141952b9ddda66ef0ebea17ea1e7bb5bce65b6e71554c56dd0d4e14f4cf74c77a150776bf31e7419756c71e7421dc22efe9cf01de9e19fc8808d5b525431b944400db121a77994518d6025711cb25a18774068bba7faaa16d8f65c91bec8768848333156dcb4a08dfbbd9fef392da3e4de13d4d74e83a7d6e46cfe530ee7a6f711e2caf8ad5461ba8177b2ef0a518baf9058ff9156e6aa7b08d938bd8d1485a787809d7b4c8aed97be880708470cd2b2cdf8e2f13428cc4b04ef1f2acbc9562f3693b948d0aa94b0e6113cafa684f8e4a67dc431dfb835726874bef1de36f273f52ee694ec46b0700f77f8538067642a552968e866a72a3f2031ad116663ac17b172b446c5bc705b84777363a9a3fdc6443c07b2f4ef58858122168d4ebbaee920cefc312e1cea870ed6e15eec046ab2073bbf08b0a3366f55cfc6ad4681a12ab0946534e7b6f90ea8992d530ec3daa6b523b3cf03101c60cadd914f30dec932c1ef4341b5a8efac3c921e203574cfe0f1f83433fddb8ccfd273f7c3cab7bc27efe3bb61fdccd5146f1185364b9b621e7fb2b74b51f5ee6be72ab6ff46a6359dc2c855e61469724c1dbeb273df9d2e1c1fb74891239c0019dc12d5c7535f7238f963b761d7102b585372cf021b64c4fc85bfb3161e59d2e298bba44cfd34d6859d9dba9dc6271e5047d525468c814f2ae438474b0a977273036da1a2292f88fcfb89574a6bdca1185b40f8aa54026d5926725f99ef028da1be892e3586361efe15f4a148ff1bc9",
				attribution_data: "34e34397b8621ec2f2b54dbe6c14073e267324cd60b152bce76aec8729a6ddefb61bc263be4b57bd592aae604a32bea69afe6ef4a6b573c26b17d69381ec1fc9b5aa769d148f2f1f8b5377a73840bb6dc641f68e356323d766fff0aaca5039fe7fc27038195844951a97d5a5b26698a4ca1e9cd4bca1fcca0aac5fee91b18977d2ad0e399ba159733fc98f6e96898ebc39bf0028c9c81619233bab6fad0328aa183a635fac20437fa6e00e899b2527c3697a8ab7342e42d55a679b176ab76671fcd480a9894cb897fa6af0a45b917a162bed6c491972403185df7235502f7ada65769d1bfb12d29f10e25b0d3cc08bbf6de8481ac5c04df32b4533b4f764c2aefb7333202645a629fb16e4a208e9045dc36830759c852b31dd613d8b2b10bbead1ed4eb60c85e8a4517deba5ab53e39867c83c26802beee2ee545bdd713208751added5fc0eb2bc89a5aa2decb18ee37dac39f22a33b60cc1a369d24de9f3d2d8b63c039e248806de4e36a47c7a0aed30edd30c3d62debdf1ad82bf7aedd7edec413850d91c261e12beec7ad1586a9ad25b2db62c58ca17119d61dcc4f3e5c4520c42a8e384a45d8659b338b3a08f9e123a1d3781f5fc97564ccff2c1d97f06fa0150cfa1e20eacabefb0c339ec109336d207cc63d9170752fc58314c43e6d4a528fd0975afa85f3aa186ff1b6b8cb12c97ed4ace295b0ef5f075f0217665b8bb180246b87982d10f43c9866b22878106f5214e99188781180478b07764a5e12876ddcb709e0a0a8dd42cf004c695c6fc1669a6fd0e4a1ca54b024d0d80eac492a9e5036501f36fb25b72a054189294955830e43c18e55668337c8c6733abb09fc2d4ade18d5a853a2b82f7b4d77151a64985004f1d9218f2945b63c56fdebd1e96a2a7e49fa70acb4c39873947b83c191c10e9a8f40f60f3ad5a2be47145c22ea59ed3f5f4e61cb069e875fb67142d281d784bf925cc286eacc2c43e94d08da4924b83e58dbf2e43fa625bdd620eba6d9ce960ff17d14ed1f2dbee7d08eceb540fdc75ff06dabc767267658fad8ce99e2a3236e46d2deedcb51c3c6f81589357edebac9772a70b3d910d83cd1b9ce6534a011e9fa557b891a23b5d88afcc0d9856c6dabeab25eea55e9a248182229e4927f268fe5431672fcce52f434ca3d27d1a2136bae5770bb36920df12fbc01d0e8165610efa04794f414c1417f1d4059435c5385bfe2de83ce0e238d6fd2dbd3c0487c69843298577bfa480fe2a16ab2a0e4bc712cd8b5a14871cda61c993b6835303d9043d7689a"
			},
			ExpectedMessage {
				message: "1b4b09a935ce7af95b336baae307f2b400e3a7e808d9b4cf421cc4b3955620acb69dcdb656128dae8857adbd4e6b37fbb1be9c1f2f02e61e9e59a630c4c77cf383cb37b07413aa4de2f2fbf5b40ae40a91a8f4c6d74aeacef1bb1be4ecbc26ec2c824d2bc45db4b9098e732a769788f1cff3f5b41b0d25c132d40dc5ad045ef0043b15332ca3c5a09de2cdb17455a0f82a8f20da08346282823dab062cdbd2111e238528141d69de13de6d83994fbc711e3e269df63a12d3a4177c5c149150eb4dc2f589cd8acabcddba14dec3b0dada12d663b36176cd3c257c5460bab93981ad99f58660efa9b31d7e63b39915329695b3fa60e0a3bdb93e7e29a54ca6a8f360d3848866198f9c3da3ba958e7730847fe1e6478ce8597848d3412b4ae48b06e05ba9a104e648f6eaf183226b5f63ed2e68f77f7e38711b393766a6fab7921b03eba82b5d7cb78e34dc961948d6161eadd7cf5d95d9c56df2ff5faa6ccf85eacdc9ff2fc3abafe41c365a5bd14fd486d6b5e2f24199319e7813e02e798877ffe31a70ae2398d9e31b9e3727e6c1a3c0d995c67d37bb6e72e9660aaaa9232670f382add2edd468927e3303b6142672546997fe105583e7c5a3c4c2b599731308b5416e6c9a3f3ba55b181ad0439d3535356108b059f2cb8742eed7a58d4eba9fe79eaa77c34b12aff1abdaea93197aabd0e74cb271269ca464b3b06aef1d6573df5e1224179616036b368677f26479376681b772d3760e871d99efd34cca5cd6beca95190d967da820b21e5bec60082ea46d776b0517488c84f26d12873912d1f68fafd67bcf4c298e43cfa754959780682a2db0f75f95f0598c0d04fd014c50e4beb86a9e37d95f2bba7e5065ae052dc306555bca203d104c44a538b438c9762de299e1c4ad30d5b4a6460a76484661fc907682af202cd69b9a4473813b2fdc1142f1403a49b7e69a650b7cde9ff133997dcc6d43f049ecac5fce097a21e2bce49c810346426585e3a5a18569b4cddd5ff6bdec66d0b69fcbc5ab3b137b34cc8aefb8b850a764df0e685c81c326611d901c392a519866e132bbb73234f6a358ba284fbafb21aa3605cacbaf9d0c901390a98b7a7dac9d4f0b405f7291c88b2ff45874241c90ac6c5fc895a440453c344d3a365cb929f9c91b9e39cb98b142444aae03a6ae8284c77eb04b0a163813d4c21883df3c0f398f47bf127b5525f222107a2d8fe55289f0cfd3f4bbad6c5387b0594ef8a966afc9e804ccaf75fe39f35c6446f7ee076d433f2f8a44dba1515acc78e589fa8c71b0a006fe14feebd51d0e0aa4e51110d16759eee86192eee90b34432130f387e0ccd2ee71023f1f641cddb571c690107e08f592039fe36d81336a421e89378f351e633932a2f5f697d25b620ffb8e84bb6478e9bd229bf3b164b48d754ae97bd23f319e3c56b3bcdaaeb3bd7fc02ec02066b324cb72a09b6b43dec1097f49d69d3c138ce6f1a6402898baf7568c",
				attribution_data: "74a4ea61339463642a2182758871b2ea724f31f531aa98d80f1c3043febca41d5ee52e8b1e127e61719a0d078db8909748d57839e58424b91f063c4fbc8a221bef261140e66a9b596ca6d420a973ad54fef30646ae53ccf0855b61f291a81e0ec6dc0f6bf69f0ca0e5889b7e23f577ba67d2a7d6a2aa91264ab9b20630ed52f8ed56cc10a869807cd1a4c2cd802d8433fee5685d6a04edb0bff248a480b93b01904bed3bb31705d1ecb7332004290cc0cd9cc2f7907cf9db28eec02985301668f53fbc28c3e095c8f3a6cd8cab28e5e442fd9ba608b8b12e098731bbfda755393bd403c62289093b40390b2bae337fc87d2606ca028311d73a9ffbdffef56020c735ada30f54e577c6a9ec515ae2739290609503404b118d7494499ecf0457d75015bb60a16288a4959d74cf5ac5d8d6c113de39f748a418d2a7083b90c9c0a09a49149fd1f2d2cde4412e5aa2421eca6fd4f6fe6b2c362ff37d1a0608c931c7ca3b8fefcfd4c44ef9c38357a0767b14f83cb49bd1989fb3f8e2ab202ac98bd8439790764a40bf309ea2205c1632610956495720030a25dc7118e0c868fdfa78c3e9ecce58215579a0581b3bafdb7dbbe53be9e904567fdc0ce1236aab5d22f1ebc18997e3ea83d362d891e04c5785fd5238326f767bce499209f8db211a50e1402160486e98e7235cf397dbb9ae19fd9b79ef589c821c6f99f28be33452405a003b33f4540fe0a41dfcc286f4d7cc10b70552ba7850869abadcd4bb7f256823face853633d6e2a999ac9fcd259c71d08e266db5d744e1909a62c0db673745ad9585949d108ab96640d2bc27fb4acac7fa8b170a30055a5ede90e004df9a44bdc29aeb4a6bec1e85dde1de6aaf01c6a5d12405d0bec22f49026cb23264f8c04b8401d3c2ab6f2e109948b6193b3bec27adfe19fb8afb8a92364d6fc5b219e8737d583e7ff3a4bcb75d53edda3bf3f52896ac36d8a877ad9f296ea6c045603fc62ac4ae41272bde85ef7c3b3fd3538aacfd5b025fefbe277c2906821ecb20e6f75ea479fa3280f9100fb0089203455c56b6bc775e5c2f0f58c63edd63fa3eec0b40da4b276d0d41da2ec0ead865a98d12bc694e23d8eaadd2b4d0ee88e9570c88fb878930f492e036d27998d593e47763927ff7eb80b188864a3846dd2238f7f95f4090ed399ae95deaeb37abca1cf37c397cc12189affb42dca46b4ff6988eb8c060691d155302d448f50ff70a794d97c0408f8cee9385d6a71fa412e36edcb22dbf433db9db4779f27b682ee17fc05e70c8e794b9f7f6d1"
			},
			ExpectedMessage {
				message: "2dd2f49c1f5af0fcad371d96e8cddbdcd5096dc309c1d4e110f955926506b3c03b44c192896f45610741c85ed4074212537e0c118d472ff3a559ae244acd9d783c65977765c5d4e00b723d00f12475aafaafff7b31c1be5a589e6e25f8da2959107206dd42bbcb43438129ce6cce2b6b4ae63edc76b876136ca5ea6cd1c6a04ca86eca143d15e53ccdc9e23953e49dc2f87bb11e5238cd6536e57387225b8fff3bf5f3e686fd08458ffe0211b87d64770db9353500af9b122828a006da754cf979738b4374e146ea79dd93656170b89c98c5f2299d6e9c0410c826c721950c780486cd6d5b7130380d7eaff994a8503a8fef3270ce94889fe996da66ed121741987010f785494415ca991b2e8b39ef2df6bde98efd2aec7d251b2772485194c8368451ad49c2354f9d30d95367bde316fec6cbdddc7dc0d25e99d3075e13d3de0822669861dafcd29de74eac48b64411987285491f98d78584d0c2a163b7221ea796f9e8671b2bb91e38ef5e18aaf32c6c02f2fb690358872a1ed28166172631a82c2568d23238017188ebbd48944a147f6cdb3690d5f88e51371cb70adf1fa02afe4ed8b581afc8bcc5104922843a55d52acde09bc9d2b71a663e178788280f3c3eae127d21b0b95777976b3eb17be40a702c244d0e5f833ff49dae6403ff44b131e66df8b88e33ab0a58e379f2c34bf5113c66b9ea8241fc7aa2b1fa53cf4ed3cdd91d407730c66fb039ef3a36d4050dde37d34e80bcfe02a48a6b14ae28227b1627b5ad07608a7763a531f2ffc96dff850e8c583461831b19feffc783bc1beab6301f647e9617d14c92c4b1d63f5147ccda56a35df8ca4806b8884c4aa3c3cc6a174fdc2232404822569c01aba686c1df5eecc059ba97e9688c8b16b70f0d24eacfdba15db1c71f72af1b2af85bd168f0b0800483f115eeccd9b02adf03bdd4a88eab03e43ce342877af2b61f9d3d85497cd1c6b96674f3d4f07f635bb26add1e36835e321d70263b1c04234e222124dad30ffb9f2a138e3ef453442df1af7e566890aedee568093aa922dd62db188aa8361c55503f8e2c2e6ba93de744b55c15260f15ec8e69bb01048ca1fa7bbbd26975bde80930a5b95054688a0ea73af0353cc84b997626a987cc06a517e18f91e02908829d4f4efc011b9867bd9bfe04c5f94e4b9261d30cc39982eb7b250f12aee2a4cce0484ff34eebba89bc6e35bd48d3968e4ca2d77527212017e202141900152f2fd8af0ac3aa456aae13276a13b9b9492a9a636e18244654b3245f07b20eb76b8e1cea8c55e5427f08a63a16b0a633af67c8e48ef8e53519041c9138176eb14b8782c6c2ee76146b8490b97978ee73cd0104e12f483be5a4af414404618e9f6633c55dda6f22252cb793d3d16fae4f0e1431434e7acc8fa2c009d4f6e345ade172313d558a4e61b4377e31b8ed4e28f7cd13a7fe3f72a409bc3bdabfe0ba47a6d861e21f64d2fac706dab18b3e546df4",
				attribution_data: "84986c936d26bfd3bb2d34d3ec62cfdb63e0032fdb3d9d75f3e5d456f73dffa7e35aab1db4f1bd3b98ff585caf004f656c51037a3f4e810d275f3f6aea0c8e3a125ebee5f374b6440bcb9bb2955ebf706f42be9999a62ed49c7a81fc73c0b4a16419fd6d334532f40bf179dd19afec21bd8519d5e6ebc3802501ef373bc378eee1f14a6fc5fab5b697c91ce31d5922199d1b0ad5ee12176aacafc7c81d54bc5b8fb7e63f3bfd40a3b6e21f985340cbd1c124c7f85f0369d1aa86ebc66def417107a7861131c8bcd73e8946f4fb54bfac87a2dc15bd7af642f32ae583646141e8875ef81ec9083d7e32d5f135131eab7a43803360434100ff67087762bbe3d6afe2034f5746b8c50e0c3c20dd62a4c174c38b1df7365dccebc7f24f19406649fbf48981448abe5c858bbd4bef6eb983ae7a23e9309fb33b5e7c0522554e88ca04b1d65fc190947dead8c0ccd32932976537d869b5ca53ed4945bccafab2a014ea4cbdc6b0250b25be66ba0afff2ff19c0058c68344fd1b9c472567147525b13b1bc27563e61310110935cf89fda0e34d0575e2389d57bdf2869398ca2965f64a6f04e1d1c2edf2082b97054264a47824dd1a9691c27902b39d57ae4a94dd6481954a9bd1b5cff4ab29ca221fa2bf9b28a362c9661206f896fc7cec563fb80aa5eaccb26c09fa4ef7a981e63028a9c4dac12f82ccb5bea090d56bbb1a4c431e315d9a169299224a8dbd099fb67ea61dfc604edf8a18ee742550b636836bb552dabb28820221bf8546331f32b0c143c1c89310c4fa2e1e0e895ce1a1eb0f43278fdb528131a3e32bfffe0c6de9006418f5309cba773ca38b6ad8507cc59445ccc0257506ebc16a4c01d4cd97e03fcf7a2049fea0db28447858f73b8e9fe98b391b136c9dc510288630a1f0af93b26a8891b857bfe4b818af99a1e011e6dbaa53982d29cf74ae7dffef45545279f19931708ed3eede5e82280eab908e8eb80abff3f1f023ab66869297b40da8496861dc455ac3abe1efa8a6f9e2c4eda48025d43a486a3f26f269743eaa30d6f0e1f48db6287751358a41f5b07aee0f098862e3493731fe2697acce734f004907c6f11eef189424fee52cd30ad708707eaf2e441f52bcf3d0c5440c1742458653c0c8a27b5ade784d9e09c8b47f1671901a29360e7e5e94946b9c75752a1a8d599d2a3e14ac81b84d42115cd688c8383a64fc6e7e1dc5568bb4837358ebe63207a4067af66b2027ad2ce8fb7ae3a452d40723a51fdf9f9c9913e8029a222cf81d12ad41e58860d75deb6de30ad"
			}
		];

		let failure_data = <Vec<u8>>::from_hex(FAILURE_DATA).unwrap();

		let onion_keys = build_test_onion_keys();
		let mut onion_error = super::build_unencrypted_failure_packet(
			onion_keys[4].shared_secret.as_ref(),
			LocalHTLCFailureReason::IncorrectPaymentDetails,
			&failure_data,
			1,
			1024,
		);

		let logger: Arc<TestLogger> = Arc::new(TestLogger::new());

		super::crypt_failure_packet(onion_keys[4].shared_secret.as_ref(), &mut onion_error);
		EXPECTED_MESSAGES[0].assert_eq(&onion_error);

		let mut mutated = false;
		let mutate_packet = |packet: &mut OnionErrorPacket, mutation_type: &MutationType| {
			match mutation_type {
				MutationType::FailureMessage(i) => {
					// Mutate legacy failure message.
					packet.data[*i] ^= 1;
				},
				MutationType::AttributionData(AttributionDataMutationType::HoldTimes(i)) => {
					// Mutate hold times.
					packet.attribution_data.as_mut().unwrap().hold_times[*i] ^= 1;
				},
				MutationType::AttributionData(AttributionDataMutationType::Hmacs(i)) => {
					// Mutate hold times.
					packet.attribution_data.as_mut().unwrap().hmacs[*i] ^= 1;
				},
				MutationType::DropAttributionData => {
					// Drop attribution data completely. This simulates a node that does not support the feature.
					packet.attribution_data = None;
				},
			}
		};

		if let Some(Mutation { node, ref mutation_type }) = mutation {
			if node == 4 {
				mutate_packet(&mut onion_error, mutation_type);
				mutated = true;
			}
		}

		for idx in (0..4).rev() {
			let shared_secret = onion_keys[idx].shared_secret.as_ref();
			let hold_time = (5 - idx) as u32;
			process_failure_packet(&mut onion_error, shared_secret, hold_time);
			super::crypt_failure_packet(shared_secret, &mut onion_error);

			if let Some(Mutation { node, ref mutation_type }) = mutation {
				if node == idx {
					mutate_packet(&mut onion_error, mutation_type);
					mutated = true;
				}
			}

			if !mutated {
				let expected_messages = &EXPECTED_MESSAGES[4 - idx];
				expected_messages.assert_eq(&onion_error);
			}
		}

		let ctx_full = Secp256k1::new();
		let path = build_test_path();
		let htlc_source = HTLCSource::OutboundRoute {
			path,
			session_priv: get_test_session_key(),
			first_hop_htlc_msat: 0,
			payment_id: PaymentId([1; 32]),
			bolt12_invoice: None,
		};

		process_onion_failure(&ctx_full, &logger, &htlc_source, onion_error)
	}

	/// Tests that the hold times and HMACs in the attribution data are matching the specification test vector and that
	/// decoding yields the expected values.
	#[test]
	fn test_success_hold_times() {
		fn assert_data(actual: &AttributionData, expected: &str) {
			let (expected_hold_times, expected_hmacs) =
				expected.split_at(MAX_HOPS * HOLD_TIME_LEN * 2);

			println!(
				"{}{}",
				actual.hold_times.to_lower_hex_string(),
				actual.hmacs.to_lower_hex_string()
			);

			assert_eq!(actual.hold_times.to_lower_hex_string(), expected_hold_times);
			assert_eq!(actual.hmacs.to_lower_hex_string(), expected_hmacs);
		}

		// The test vector from BOLT #4.
		const EXPECTED_MESSAGES: [&str; 5] = [
			"d77d0711b5f71d1d1be56bd88b3bb7ebc1792bb739ea7ebc1bc3b031b8bc2df3a50e25aeb99f47d7f7ab39e24187d3f4df9c4333463b053832ee9ac07274a5261b8b2a01fc09ce9ea7cd04d7b585dfb83299fb6570d71f793c1fcac0ef498766952c8c6840efa02a567d558a3cf6822b12476324b9b9efa03e5f8f26f81fa93daac46cbf00c98e69b6747cf69caaa2a71b025bd18830c4c54cd08f598cfde6197b3f2a951aba907c964c0f5d19a44e6d1d7279637321fa598adde927b3087d238f8b426ecde500d318617cdb7a56e6ce3520fc95be41a549973764e4dc483853ecc313947709f1b5199cb077d46e701fa633e11d3e13b03e9212c115ca6fa004b2f3dd912814693b705a561a06da54cdf603677a3abecdc22c7358c2de3cef771b366a568150aeecc86ad1990bb0f4e2865933b03ea0df87901bff467908273dc6cea31cbab0e2b8d398d10b001058c259ed221b7b55762f4c7e49c8c11a45a107b7a2c605c26dc5b0b10d719b1c844670102b2b6a36c43fe4753a78a483fc39166ae28420f112d50c10ee64ca69569a2f690712905236b7c2cb7ac8954f02922d2d918c56d42649261593c47b14b324a65038c3c5be8d3c403ce0c8f19299b1664bf077d7cf1636c4fb9685a8e58b7029fd0939fa07925a60bed339b23f973293598f595e75c8f9d455d7cebe4b5e23357c8bd47d66d6628b39427e37e0aecbabf46c11be6771f7136e108a143ae9bafba0fc47a51b6c7deef4cba54bae906398ee3162a41f2191ca386b628bde7e1dd63d1611aa01a95c456df337c763cb8c3a81a6013aa633739d8cd554c688102211725e6adad165adc1bcd429d020c51b4b25d2117e8bb27eb0cc7020f9070d4ad19ac31a76ebdf5f9246646aeadbfb9a3f1d75bd8237961e786302516a1a781780e8b73f58dc06f307e58bd0eb1d8f5c9111f01312974c1dc777a6a2d3834d8a2a40014e9818d0685cb3919f6b3b788ddc640b0ff9b1854d7098c7dd6f35196e902b26709640bc87935a3914869a807e8339281e9cedaaca99474c3e7bdd35050bb998ab4546f9900904e0e39135e861ff7862049269701081ebce32e4cca992c6967ff0fd239e38233eaf614af31e186635e9439ec5884d798f9174da6ff569d68ed5c092b78bd3f880f5e88a7a8ab36789e1b57b035fb6c32a6358f51f83e4e5f46220bcad072943df8bd9541a61b7dae8f30fa3dd5fb39b1fd9a0b8e802552b78d4ec306ecee15bfe6da14b29ba6d19ce5be4dd478bca74a52429cd5309d404655c3dec85c252",
			"1571e10db7f8aa9f8e7e99caaf9c892e106c817df1d8e3b7b0e39d1c48f631e473e17e205489dd7b3c634cac3be0825cbf01418cd46e83c24b8d9c207742db9a0f0e5bcd888086498159f08080ba7bf3ea029c0b493227c4e75a90f70340d9e21f00979fc7e4fb2078477c1a457ba242ed54b313e590b13a2a13bfeed753dab133c78059f460075b2594b4c31c50f31076f8f1a0f7ad0530d0fadaf2d86e505ff9755940ec0665f9e5bc58cad6e523091f94d0bcd3c6c65ca1a5d401128dcc5e14f9108b32e660017c13de598bcf9d403710857cccb0fb9c2a81bfd66bc4552e1132afa3119203a4aaa1e8839c1dab8cbdcde7b527aca3f54bde651aa9f3f2178829cee3f1c0b9292758a40cc63bd998fcd0d3ed4bdcaf1023267b8f8e44130a63ad15f76145936552381eabb6d684c0a3af6ba8efcf207cebaea5b7acdbb63f8e7221102409d10c23f0514dc9f4d0efb2264161a193a999a23e992632710580a0d320f676d367b9190721194514457761af05207cdab2b6328b1b3767eacb36a7ef4f7bd2e16762d13df188e0898b7410f62459458712a44bf594ae662fd89eb300abb6952ff8ad40164f2bcd7f86db5c7650b654b79046de55d51aa8061ce35f867a3e8f5bf98ad920be827101c64fb871d86e53a4b3c0455bfac5784168218aa72cbee86d9c750a9fa63c363a8b43d7bf4b2762516706a306f0aa3be1ec788b5e13f8b24837e53ac414f211e11c7a093cd9653dfa5fba4e377c79adfa5e841e2ddb6afc054fc715c05ddc6c8fc3e1ee3406e1ffceb2df77dc2f02652614d1bfcfaddebaa53ba919c7051034e2c7b7cfaabdf89f26e7f8e3f956d205dfab747ad0cb505b85b54a68439621b25832cbc2898919d0cd7c0a64cfd235388982dd4dd68240cb668f57e1d2619a656ed326f8c92357ee0d9acead3c20008bc5f04ca8059b55d77861c6d04dfc57cfba57315075acbe1451c96cf28e1e328e142890248d18f53b5d3513ce574dea7156cf596fdb3d909095ec287651f9cf1bcdc791c5938a5dd9b47e84c004d24ab3ae74492c7e8dcc1da15f65324be2672947ec82074cac8ce2b925bc555facbbf1b55d63ea6fbea6a785c97d4caf2e1dad9551b7f66c31caae5ebc7c0047e892f201308fcf452c588be0e63d89152113d87bf0dbd01603b4cdc7f0b724b0714a9851887a01f709408882e18230fe810b9fafa58a666654576d8eba3005f07221f55a6193815a672e5db56204053bc4286fa3db38250396309fd28011b5708a26a2d76c4a333b69b6bfd272fb",
			"34e34397b8621ec2f2b54dbe6c14073e267324cd60b152bce76aec8729a6ddefb61bc263be4b57bd592aae604a32bea69afe6ef4a6b573c26b17d69381ec1fc9b5aa769d148f2f1f8b5377a73840bb6dffc324ded0d1c00dc0c99e3dbc13273b2f89510af6410b525dd8836208abbbaae12753ae2276fa0ca49950374f94e187bf65cefcdd9dd9142074edc4bd0052d0eb027cb1ab6182497f9a10f9fe800b3228e3c088dab60081c807b30a67313667ca8c9e77b38b161a037cae8e973038d0fc4a97ea215914c6c4e23baf6ac4f0fb1e7fcc8aac3f6303658dae1f91588b535eb678e2200f45383c2590a55dc181a09f2209da72f79ae6745992c803310d39f960e8ecf327aed706e4b3e2704eeb9b304dc0e0685f5dcd0389ec377bdba37610ad556a0e957a413a56339dd3c40817214bced5802beee2ee545bdd713208751added5fc0eb2bc89a5aa2decb18ee37dac39f22a33b60cc1a369d24de9f3d2d8b63c039e248806de4e36a47c7a0aed30edd30c3d62debdf1ad82bf7aedd7edec413850d91c261e12beec7ad1586a9ad25b2db62c58ca17119d61dcc4f3e5c4520c42a8e384a45d8659b338b3a08f9e123a1d3781f5fc97564ccff2c1d97f06fa0150cfa1e20eacabefb0c339ec109336d207cc63d9170752fc58314c43e6d4a528fd0975afa85f3aa186ff1b6b8cb12c97ed4ace295b0ef5f075f0217665b8bb180246b87982d10f43c9866b22878106f5214e99188781180478b07764a5e12876ddcb709e0a0a8dd42cf004c695c6fc1669a6fd0e4a1ca54b024d0d80eac492a9e5036501f36fb25b72a054189294955830e43c18e55668337c8c6733abb09fc2d4ade18d5a853a2b82f7b4d77151a64985004f1d9218f2945b63c56fdebd1e96a2a7e49fa70acb4c39873947b83c191c10e9a8f40f60f3ad5a2be47145c22ea59ed3f5f4e61cb069e875fb67142d281d784bf925cc286eacc2c43e94d08da4924b83e58dbf2e43fa625bdd620eba6d9ce960ff17d14ed1f2dbee7d08eceb540fdc75ff06dabc767267658fad8ce99e2a3236e46d2deedcb51c3c6f81589357edebac9772a70b3d910d83cd1b9ce6534a011e9fa557b891a23b5d88afcc0d9856c6dabeab25eea55e9a248182229e4927f268fe5431672fcce52f434ca3d27d1a2136bae5770bb36920df12fbc01d0e8165610efa04794f414c1417f1d4059435c5385bfe2de83ce0e238d6fd2dbd3c0487c69843298577bfa480fe2a16ab2a0e4bc712cd8b5a14871cda61c993b6835303d9043d7689a",
			"74a4ea61339463642a2182758871b2ea724f31f531aa98d80f1c3043febca41d5ee52e8b1e127e61719a0d078db8909748d57839e58424b91f063c4fbc8a221bef261140e66a9b596ca6d420a973ad5431adfa8280a7355462fe50d4cac15cdfbd7a535c4b72a0b6d7d8a64cff3f719ff9b8be28036826342dc3bf3781efc70063d1e6fc79dff86334ae0564a5ab87bd61f8446465ef6713f8c4ef9d0200ebb375f90ee115216b469af42de554622df222858d30d733af1c9223e327ae09d9126be8baee6dd59a112d83a57cc6e0252104c11bc11705d384220eedd72f1a29a0597d97967e28b2ad13ba28b3d8a53c3613c1bb49fe9700739969ef1f795034ef9e2e983af2d3bbd6c637fb12f2f7dfc3aee85e08711e9b604106e95d7a4974e5b047674a6015792dae5d913681d84f71edd415910582e5d86590df2ecfd561dc6e1cdb08d3e10901312326a45fb0498a177319389809c6ba07a76cfad621e07b9af097730e94df92fbd311b2cb5da32c80ab5f14971b6d40f8e2ab202ac98bd8439790764a40bf309ea2205c1632610956495720030a25dc7118e0c868fdfa78c3e9ecce58215579a0581b3bafdb7dbbe53be9e904567fdc0ce1236aab5d22f1ebc18997e3ea83d362d891e04c5785fd5238326f767bce499209f8db211a50e1402160486e98e7235cf397dbb9ae19fd9b79ef589c821c6f99f28be33452405a003b33f4540fe0a41dfcc286f4d7cc10b70552ba7850869abadcd4bb7f256823face853633d6e2a999ac9fcd259c71d08e266db5d744e1909a62c0db673745ad9585949d108ab96640d2bc27fb4acac7fa8b170a30055a5ede90e004df9a44bdc29aeb4a6bec1e85dde1de6aaf01c6a5d12405d0bec22f49026cb23264f8c04b8401d3c2ab6f2e109948b6193b3bec27adfe19fb8afb8a92364d6fc5b219e8737d583e7ff3a4bcb75d53edda3bf3f52896ac36d8a877ad9f296ea6c045603fc62ac4ae41272bde85ef7c3b3fd3538aacfd5b025fefbe277c2906821ecb20e6f75ea479fa3280f9100fb0089203455c56b6bc775e5c2f0f58c63edd63fa3eec0b40da4b276d0d41da2ec0ead865a98d12bc694e23d8eaadd2b4d0ee88e9570c88fb878930f492e036d27998d593e47763927ff7eb80b188864a3846dd2238f7f95f4090ed399ae95deaeb37abca1cf37c397cc12189affb42dca46b4ff6988eb8c060691d155302d448f50ff70a794d97c0408f8cee9385d6a71fa412e36edcb22dbf433db9db4779f27b682ee17fc05e70c8e794b9f7f6d1",
			"84986c936d26bfd3bb2d34d3ec62cfdb63e0032fdb3d9d75f3e5d456f73dffa7e35aab1db4f1bd3b98ff585caf004f656c51037a3f4e810d275f3f6aea0c8e3a125ebee5f374b6440bcb9bb2955ebf70c06d64090f9f6cf098200305f7f4305ba9e1350a0c3f7dab4ccf35b8399b9650d8e363bf83d3a0a09706433f0adae6562eb338b21ea6f21329b3775905e59187c325c9cbf589f5da5e915d9e5ad1d21aa1431f9bdc587185ed8b5d4928e697e67cc96bee6d5354e3764cede3f385588fa665310356b2b1e68f8bd30c75d395405614a40a587031ebd6ace60dfb7c6dd188b572bd8e3e9a47b06c2187b528c5ed35c32da5130a21cd881138a5fcac806858ce6c596d810a7492eb261bcc91cead1dae75075b950c2e81cecf7e5fdb2b51df005d285803201ce914dfbf3218383829a0caa8f15486dd801133f1ed7edec436730b0ec98f48732547927229ac80269fcdc5e4f4db264274e940178732b429f9f0e582c559f994a7cdfb76c93ffc39de91ff936316726cc561a6520d47b2cd487299a96322dadc463ef06127fc63902ff9cc4f265e2fbd9de3fa5e48b7b51aa0850580ef9f3b5ebb60c6c3216c5a75a93e82936113d9cad57ae4a94dd6481954a9bd1b5cff4ab29ca221fa2bf9b28a362c9661206f896fc7cec563fb80aa5eaccb26c09fa4ef7a981e63028a9c4dac12f82ccb5bea090d56bbb1a4c431e315d9a169299224a8dbd099fb67ea61dfc604edf8a18ee742550b636836bb552dabb28820221bf8546331f32b0c143c1c89310c4fa2e1e0e895ce1a1eb0f43278fdb528131a3e32bfffe0c6de9006418f5309cba773ca38b6ad8507cc59445ccc0257506ebc16a4c01d4cd97e03fcf7a2049fea0db28447858f73b8e9fe98b391b136c9dc510288630a1f0af93b26a8891b857bfe4b818af99a1e011e6dbaa53982d29cf74ae7dffef45545279f19931708ed3eede5e82280eab908e8eb80abff3f1f023ab66869297b40da8496861dc455ac3abe1efa8a6f9e2c4eda48025d43a486a3f26f269743eaa30d6f0e1f48db6287751358a41f5b07aee0f098862e3493731fe2697acce734f004907c6f11eef189424fee52cd30ad708707eaf2e441f52bcf3d0c5440c1742458653c0c8a27b5ade784d9e09c8b47f1671901a29360e7e5e94946b9c75752a1a8d599d2a3e14ac81b84d42115cd688c8383a64fc6e7e1dc5568bb4837358ebe63207a4067af66b2027ad2ce8fb7ae3a452d40723a51fdf9f9c9913e8029a222cf81d12ad41e58860d75deb6de30ad",
		];

		let onion_keys = build_test_onion_keys();

		let mut attribution_data = AttributionData::new();
		attribution_data.update(&[], onion_keys[4].shared_secret.as_ref(), 1);

		let logger: Arc<TestLogger> = Arc::new(TestLogger::new());

		attribution_data.crypt(onion_keys[4].shared_secret.as_ref());

		assert_data(&attribution_data, EXPECTED_MESSAGES[0]);

		for idx in (0..4).rev() {
			let shared_secret = onion_keys[idx].shared_secret.as_ref();
			let hold_time = (5 - idx) as u32;

			attribution_data.shift_right();
			attribution_data.update(&[], shared_secret, hold_time);
			attribution_data.crypt(shared_secret);

			assert_data(&attribution_data, EXPECTED_MESSAGES[4 - idx]);
		}

		let ctx_full = Secp256k1::new();
		let path = build_test_path();
		let hold_times = decode_fulfill_attribution_data(
			&ctx_full,
			&logger,
			&path,
			&get_test_session_key(),
			attribution_data.clone(),
		);

		assert_eq!(hold_times, [5, 4, 3, 2, 1])
	}

	fn build_trampoline_test_path() -> Path {
		Path {
			hops: vec![
				// Bob
				RouteHop {
					pubkey: PublicKey::from_slice(&<Vec<u8>>::from_hex("0324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c").unwrap()).unwrap(),
					node_features: NodeFeatures::empty(),
					short_channel_id: 0,
					channel_features: ChannelFeatures::empty(),
					fee_msat: 3_000,
					cltv_expiry_delta: 24,
					maybe_announced_channel: false,
				},

				// Carol
				RouteHop {
					pubkey: PublicKey::from_slice(&<Vec<u8>>::from_hex("027f31ebc5462c1fdce1b737ecff52d37d75dea43ce11c74d25aa297165faa2007").unwrap()).unwrap(),
					node_features: NodeFeatures::empty(),
					short_channel_id: (572330 << 40) + (42 << 16) + 2821,
					channel_features: ChannelFeatures::empty(),
					fee_msat: 153_000,
					cltv_expiry_delta: 0,
					maybe_announced_channel: false,
				},
			],
			blinded_tail: Some(BlindedTail {
				trampoline_hops: vec![
					// Carol's pubkey
					TrampolineHop {
						pubkey: PublicKey::from_slice(&<Vec<u8>>::from_hex("027f31ebc5462c1fdce1b737ecff52d37d75dea43ce11c74d25aa297165faa2007").unwrap()).unwrap(),
						node_features: Features::empty(),
						fee_msat: 2_500,
						cltv_expiry_delta: 24,
					},

					// Dave's pubkey
					TrampolineHop {
						pubkey: PublicKey::from_slice(&<Vec<u8>>::from_hex("02edabbd16b41c8371b92ef2f04c1185b4f03b6dcd52ba9b78d9d7c89c8f221145").unwrap()).unwrap(),
						node_features: Features::empty(),
						fee_msat: 2_500,
						cltv_expiry_delta: 24,
					},

					// Emily's pubkey
					TrampolineHop {
						pubkey: PublicKey::from_slice(&<Vec<u8>>::from_hex("032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991").unwrap()).unwrap(),
						node_features: Features::empty(),
						fee_msat: 150_500,
						cltv_expiry_delta: 36,
					},
				],

				// Dummy blinded hop (because LDK doesn't allow unblinded Trampoline receives)
				hops: vec![
					// Emily's dummy blinded node id
					BlindedHop {
						blinded_node_id: PublicKey::from_slice(&<Vec<u8>>::from_hex("0295d40514096a8be54859e7dfe947b376eaafea8afe5cb4eb2c13ff857ed0b4be").unwrap()).unwrap(),
						encrypted_payload: vec![],
					}
				],
				blinding_point: PublicKey::from_slice(&<Vec<u8>>::from_hex("02988face71e92c345a068f740191fd8e53be14f0bb957ef730d3c5f76087b960e").unwrap()).unwrap(),
				excess_final_cltv_expiry_delta: 0,
				final_value_msat: 150_000_000,
			}),
		}
	}

	#[test]
	fn test_trampoline_onion_error_cryptography() {
		// TODO(arik): check intermediate hops' perspectives once we have implemented forwarding

		let secp_ctx = Secp256k1::new();
		let logger: Arc<TestLogger> = Arc::new(TestLogger::new());
		let dummy_amt_msat = 150_000_000;

		{
			// test vector per https://github.com/lightning/bolts/blob/079f761bf68caa48544bd6bf0a29591d43425b0b/bolt04/trampoline-onion-error-test.json
			// all dummy values
			let trampoline_session_priv = SecretKey::from_slice(&[3; 32]).unwrap();
			let outer_session_priv = SecretKey::from_slice(&[4; 32]).unwrap();

			let error_packet_hex = "f8941a320b8fde4ad7b9b920c69cbf334114737497d93059d77e591eaa78d6334d3e2aeefcb0cc83402eaaf91d07d695cd895d9cad1018abdaf7d2a49d7657b1612729db7f393f0bb62b25afaaaa326d72a9214666025385033f2ec4605dcf1507467b5726d806da180ea224a7d8631cd31b0bdd08eead8bfe14fc8c7475e17768b1321b54dd4294aecc96da391efe0ca5bd267a45ee085c85a60cf9a9ac152fa4795fff8700a3ea4f848817f5e6943e855ab2e86f6929c9e885d8b20c49b14d2512c59ed21f10bd38691110b0d82c00d9fa48a20f10c7550358724c6e8e2b966e56a0aadf458695b273768062fa7c6e60eb72d4cdc67bf525c194e4a17fdcaa0e9d80480b586bf113f14eea530b6728a1c53fe5cee092e24a90f21f4b764015e7ed5e23";
			let error_packet = OnionErrorPacket {
				data: <Vec<u8>>::from_hex(error_packet_hex).unwrap(),
				attribution_data: None,
			};
			let decrypted_failure = process_onion_failure_inner(
				&secp_ctx,
				&logger,
				&build_trampoline_test_path(),
				&outer_session_priv,
				Some(trampoline_session_priv),
				error_packet,
			);
			assert_eq!(
				decrypted_failure.onion_error_code,
				Some(LocalHTLCFailureReason::IncorrectPaymentDetails),
			);
		}

		{
			// shared secret cryptography sanity tests
			let session_priv = get_test_session_key();
			let path = build_trampoline_test_path();
			let outer_onion_keys = construct_onion_keys(&Secp256k1::new(), &path, &session_priv);

			let trampoline_session_priv = compute_trampoline_session_priv(&session_priv);
			let trampoline_onion_keys = construct_trampoline_onion_keys(
				&secp_ctx,
				&path.blinded_tail.as_ref().unwrap(),
				&trampoline_session_priv,
			);

			let htlc_source = HTLCSource::OutboundRoute {
				path,
				session_priv,
				first_hop_htlc_msat: dummy_amt_msat,
				payment_id: PaymentId([1; 32]),
				bolt12_invoice: None,
			};

			{
				// Ensure error decryption works without the Trampoline hops having been hit.
				let error_code = LocalHTLCFailureReason::TemporaryNodeFailure;
				let mut first_hop_error_packet = build_unencrypted_failure_packet(
					outer_onion_keys[0].shared_secret.as_ref(),
					error_code,
					&[0; 0],
					0,
					DEFAULT_MIN_FAILURE_PACKET_LEN,
				);

				crypt_failure_packet(
					outer_onion_keys[0].shared_secret.as_ref(),
					&mut first_hop_error_packet,
				);

				let decrypted_failure =
					process_onion_failure(&secp_ctx, &logger, &htlc_source, first_hop_error_packet);
				assert_eq!(decrypted_failure.onion_error_code, Some(error_code));
			};

			{
				// Ensure error decryption works from the first Trampoline hop, but at the outer onion.
				let error_code = 0x2003.into();
				let mut trampoline_outer_hop_error_packet = build_unencrypted_failure_packet(
					outer_onion_keys[1].shared_secret.as_ref(),
					error_code,
					&[0; 0],
					0,
					DEFAULT_MIN_FAILURE_PACKET_LEN,
				);
				trampoline_outer_hop_error_packet.attribution_data = None;

				crypt_failure_packet(
					outer_onion_keys[1].shared_secret.as_ref(),
					&mut trampoline_outer_hop_error_packet,
				);

				crypt_failure_packet(
					outer_onion_keys[0].shared_secret.as_ref(),
					&mut trampoline_outer_hop_error_packet,
				);

				let decrypted_failure = process_onion_failure(
					&secp_ctx,
					&logger,
					&htlc_source,
					trampoline_outer_hop_error_packet,
				);
				assert_eq!(decrypted_failure.onion_error_code, Some(error_code));
			};

			{
				// Ensure error decryption works from the Trampoline inner onion.
				let error_code = 0x2004.into();
				let mut trampoline_inner_hop_error_packet = build_unencrypted_failure_packet(
					trampoline_onion_keys[0].shared_secret.as_ref(),
					error_code,
					&[0; 0],
					0,
					DEFAULT_MIN_FAILURE_PACKET_LEN,
				);
				trampoline_inner_hop_error_packet.attribution_data = None;

				crypt_failure_packet(
					trampoline_onion_keys[0].shared_secret.as_ref(),
					&mut trampoline_inner_hop_error_packet,
				);

				crypt_failure_packet(
					outer_onion_keys[1].shared_secret.as_ref(),
					&mut trampoline_inner_hop_error_packet,
				);

				crypt_failure_packet(
					outer_onion_keys[0].shared_secret.as_ref(),
					&mut trampoline_inner_hop_error_packet,
				);

				let decrypted_failure = process_onion_failure(
					&secp_ctx,
					&logger,
					&htlc_source,
					trampoline_inner_hop_error_packet,
				);
				assert_eq!(decrypted_failure.onion_error_code, Some(error_code));
			}

			{
				// Ensure error decryption works from a later hop in the Trampoline inner onion.
				let error_code = 0x2005.into();
				let mut trampoline_second_hop_error_packet = build_unencrypted_failure_packet(
					trampoline_onion_keys[1].shared_secret.as_ref(),
					error_code,
					&[0; 0],
					0,
					DEFAULT_MIN_FAILURE_PACKET_LEN,
				);
				trampoline_second_hop_error_packet.attribution_data = None;

				crypt_failure_packet(
					trampoline_onion_keys[1].shared_secret.as_ref(),
					&mut trampoline_second_hop_error_packet,
				);

				crypt_failure_packet(
					trampoline_onion_keys[0].shared_secret.as_ref(),
					&mut trampoline_second_hop_error_packet,
				);

				crypt_failure_packet(
					outer_onion_keys[1].shared_secret.as_ref(),
					&mut trampoline_second_hop_error_packet,
				);

				crypt_failure_packet(
					outer_onion_keys[0].shared_secret.as_ref(),
					&mut trampoline_second_hop_error_packet,
				);

				let decrypted_failure = process_onion_failure(
					&secp_ctx,
					&logger,
					&htlc_source,
					trampoline_second_hop_error_packet,
				);
				assert_eq!(decrypted_failure.onion_error_code, Some(error_code));
			}
		}
	}

	#[test]
	fn test_non_attributable_failure_packet_onion() {
		// Create a failure packet with bogus data.
		let packet = vec![1u8; 292];
		let onion_error_packet =
			OnionErrorPacket { data: packet, attribution_data: Some(AttributionData::new()) };

		// With attributable failures, it should still be possible to identify the failing node.
		let logger: TestLogger = TestLogger::new();
		let decrypted_failure = test_failure_attribution(&logger, onion_error_packet);
		assert_eq!(decrypted_failure.attribution_failed_channel, Some(0));
	}

	#[test]
	fn test_long_route_attributable_failure() {
		// Test a long route that exceeds the reach of attribution data.

		let secp_ctx = Secp256k1::new();
		const LEGACY_MAX_HOPS: usize = 27;

		// Construct a route with 27 hops.
		let mut hops = Vec::new();
		for i in 0..LEGACY_MAX_HOPS {
			let mut secret_bytes = [0; 32];
			secret_bytes[0] = (i + 1) as u8;
			let secret_key = SecretKey::from_slice(&secret_bytes).unwrap();
			let pubkey = secret_key.public_key(&secp_ctx);

			hops.push(RouteHop {
				pubkey,
				channel_features: ChannelFeatures::empty(),
				node_features: NodeFeatures::empty(),
				short_channel_id: i as u64,
				fee_msat: 0,
				cltv_expiry_delta: 0,
				maybe_announced_channel: true,
			});
		}
		let path = Path { hops, blinded_tail: None };

		// Calculate shared secrets.
		let session_key = get_test_session_key();
		let onion_keys: Vec<_> =
			construct_onion_keys_generic(&secp_ctx, &path.hops, None, &session_key)
				.map(|(key, ..)| key)
				.collect();

		// Construct the htlc source.
		let logger = TestLogger::new();
		let htlc_source = HTLCSource::OutboundRoute {
			path,
			session_priv: session_key,
			first_hop_htlc_msat: 0,
			payment_id: PaymentId([1; 32]),
			bolt12_invoice: None,
		};

		// Iterate over all possible failure positions and check that the cases that can be attributed are.
		for failure_pos in 0..LEGACY_MAX_HOPS {
			// Create a failure packet with bogus data.
			let packet = vec![1u8; 292];
			let mut onion_error =
				OnionErrorPacket { data: packet, attribution_data: Some(AttributionData::new()) };

			// Apply the processing that the preceding hops would apply.
			for i in (0..failure_pos).rev() {
				let shared_secret = onion_keys[i].secret_bytes();
				process_failure_packet(&mut onion_error, &shared_secret, 0);
				super::crypt_failure_packet(&shared_secret, &mut onion_error);
			}

			// Decrypt the failure.
			let decrypted_failure =
				process_onion_failure(&secp_ctx, &&logger, &htlc_source, onion_error);

			// Expect attribution up to hop 20.
			let expected_failed_chan =
				if failure_pos < MAX_HOPS { Some(failure_pos as u64) } else { None };
			assert_eq!(decrypted_failure.attribution_failed_channel, expected_failed_chan);
		}
	}

	#[test]
	fn test_unreadable_failure_packet_onion() {
		// Create a failure packet with a valid hmac but unreadable failure message.
		let onion_keys: Vec<OnionKeys> = build_test_onion_keys();
		let shared_secret = onion_keys[0].shared_secret.as_ref();
		let um = gen_um_from_shared_secret(&shared_secret);

		// The failure message is a single 0 byte.
		let mut packet = [0u8; 33];

		let mut hmac = HmacEngine::<Sha256>::new(&um);
		hmac.input(&packet[32..]);
		let hmac = Hmac::from_engine(hmac).to_byte_array();
		packet[..32].copy_from_slice(&hmac);

		let mut onion_error_packet = OnionErrorPacket {
			data: packet.to_vec(),
			attribution_data: Some(AttributionData::new()),
		};
		onion_error_packet
			.attribution_data
			.as_mut()
			.unwrap()
			.add_hmacs(shared_secret, &onion_error_packet.data);
		crypt_failure_packet(shared_secret, &mut onion_error_packet);

		// For the unreadable failure, it is still expected that the failing channel can be identified.
		let logger: TestLogger = TestLogger::new();
		let decrypted_failure = test_failure_attribution(&logger, onion_error_packet);
		assert_eq!(decrypted_failure.short_channel_id, Some(0));

		logger.assert_log_contains("lightning::ln::onion_utils", "Unreadable failure", 1);
	}

	#[test]
	fn test_missing_error_code() {
		// Create a failure packet with a valid hmac and structure, but no error code.
		let onion_keys: Vec<OnionKeys> = build_test_onion_keys();
		let shared_secret = onion_keys[0].shared_secret.as_ref();
		let um = gen_um_from_shared_secret(&shared_secret);

		let failuremsg = vec![1];
		let pad = Vec::new();
		let mut packet = msgs::DecodedOnionErrorPacket { hmac: [0; 32], failuremsg, pad };

		let mut hmac = HmacEngine::<Sha256>::new(&um);
		hmac.input(&packet.encode()[32..]);
		packet.hmac = Hmac::from_engine(hmac).to_byte_array();

		let mut onion_error_packet = OnionErrorPacket {
			data: packet.encode(),
			attribution_data: Some(AttributionData::new()),
		};
		onion_error_packet
			.attribution_data
			.as_mut()
			.unwrap()
			.add_hmacs(shared_secret, &onion_error_packet.data);
		crypt_failure_packet(shared_secret, &mut onion_error_packet);

		let logger = TestLogger::new();
		let decrypted_failure = test_failure_attribution(&logger, onion_error_packet);
		assert_eq!(decrypted_failure.short_channel_id, Some(0));

		logger.assert_log_contains(
			"lightning::ln::onion_utils",
			"Missing error code in failure",
			1,
		);
	}

	fn test_failure_attribution(
		logger: &TestLogger, packet: OnionErrorPacket,
	) -> DecodedOnionFailure {
		let ctx_full = Secp256k1::new();
		let path = build_test_path();
		let htlc_source = HTLCSource::OutboundRoute {
			path,
			session_priv: get_test_session_key(),
			first_hop_htlc_msat: 0,
			payment_id: PaymentId([1; 32]),
			bolt12_invoice: None,
		};

		let decrypted_failure = process_onion_failure(&ctx_full, &logger, &htlc_source, packet);

		decrypted_failure
	}

	struct RawOnionHopData {
		data: Vec<u8>,
	}
	impl RawOnionHopData {
		fn new(orig: msgs::OutboundOnionPayload) -> Self {
			Self { data: orig.encode() }
		}
	}
	impl Writeable for RawOnionHopData {
		fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
			writer.write_all(&self.data[..])
		}
	}

	#[test]
	fn max_length_with_no_cltv_limit() {
		// While users generally shouldn't do this, we shouldn't overflow when
		// `max_total_cltv_expiry_delta` is `u32::MAX`.
		let recipient = PublicKey::from_slice(&[2; 33]).unwrap();
		let mut route_params = RouteParameters {
			payment_params: PaymentParameters::for_keysend(recipient, u32::MAX, true),
			final_value_msat: u64::MAX,
			max_total_routing_fee_msat: Some(u64::MAX),
		};
		route_params.payment_params.max_total_cltv_expiry_delta = u32::MAX;
		let recipient_onion = RecipientOnionFields::spontaneous_empty();
		set_max_path_length(&mut route_params, &recipient_onion, None, None, 42).unwrap();
	}

	#[test]
	fn test_failure_packet_max_size() {
		// Create a failure message of the maximum size of 65535 bytes. It is composed of:
		// - 32 bytes channel id
		// - 8 bytes htlc id
		// - 2 bytes reason length
		//    - 32 bytes of hmac
		//    - 2 bytes of failure type
		//    - 2 bytes of failure length
		//    - 64531 bytes of failure data
		//    - 2 bytes of pad len (0)
		// - 1 byte attribution data tlv type
		// - 3 bytes attribution data tlv length
		//    - 80 bytes of attribution data hold times
		//    - 840 bytes of attribution data hmacs
		let failure_data = vec![0; 64531];

		let shared_secret = [0; 32];
		let onion_error = super::build_unencrypted_failure_packet(
			&shared_secret,
			LocalHTLCFailureReason::TemporaryNodeFailure,
			&failure_data,
			0,
			DEFAULT_MIN_FAILURE_PACKET_LEN,
		);

		let msg = UpdateFailHTLC {
			channel_id: ChannelId([0; 32]),
			htlc_id: 0,
			reason: onion_error.data,
			attribution_data: onion_error.attribution_data,
		};

		let mut buffer = Vec::new();
		msg.write(&mut buffer).unwrap();

		assert_eq!(buffer.len(), 65535);
	}
}
