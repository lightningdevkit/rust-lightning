// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

use super::msgs::OnionErrorPacket;
use crate::blinded_path::BlindedHop;
use crate::crypto::chacha20::ChaCha20;
use crate::crypto::streams::ChaChaReader;
use crate::ln::channel::TOTAL_BITCOIN_SUPPLY_SATOSHIS;
use crate::ln::channelmanager::{HTLCSource, RecipientOnionFields};
use crate::ln::msgs;
use crate::offers::invoice_request::InvoiceRequest;
use crate::routing::gossip::NetworkUpdate;
use crate::routing::router::{BlindedTail, Path, RouteHop, RouteParameters, TrampolineHop};
use crate::sign::{NodeSigner, Recipient};
use crate::types::features::{ChannelFeatures, NodeFeatures};
use crate::types::payment::{PaymentHash, PaymentPreimage};
use crate::util::errors::{self, APIError};
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

#[inline]
fn construct_onion_keys_generic_callback<'a, T, H, FType>(
	secp_ctx: &Secp256k1<T>, hops: &'a [H], blinded_tail: Option<&BlindedTail>,
	session_priv: &SecretKey, mut callback: FType,
) -> Result<(), secp256k1::Error>
where
	T: secp256k1::Signing,
	H: HopInfo,
	FType: FnMut(SharedSecret, [u8; 32], PublicKey, Option<&'a H>, usize),
{
	let mut blinded_priv = session_priv.clone();
	let mut blinded_pub = PublicKey::from_secret_key(secp_ctx, &blinded_priv);

	let unblinded_hops_iter = hops.iter().map(|h| (h.node_pubkey(), Some(h)));
	let blinded_pks_iter = blinded_tail
		.map(|t| t.hops.iter())
		.unwrap_or([].iter())
		.skip(1) // Skip the intro node because it's included in the unblinded hops
		.map(|h| (&h.blinded_node_id, None));

	for (idx, (pubkey, route_hop_opt)) in unblinded_hops_iter.chain(blinded_pks_iter).enumerate() {
		let shared_secret = SharedSecret::new(pubkey, &blinded_priv);

		let mut sha = Sha256::engine();
		sha.input(&blinded_pub.serialize()[..]);
		sha.input(shared_secret.as_ref());
		let blinding_factor = Sha256::from_engine(sha).to_byte_array();

		let ephemeral_pubkey = blinded_pub;

		blinded_priv = blinded_priv.mul_tweak(&Scalar::from_be_bytes(blinding_factor).unwrap())?;
		blinded_pub = PublicKey::from_secret_key(secp_ctx, &blinded_priv);

		callback(shared_secret, blinding_factor, ephemeral_pubkey, route_hop_opt, idx);
	}

	Ok(())
}

// can only fail if an intermediary hop has an invalid public key or session_priv is invalid
pub(super) fn construct_onion_keys<T: secp256k1::Signing>(
	secp_ctx: &Secp256k1<T>, path: &Path, session_priv: &SecretKey,
) -> Result<Vec<OnionKeys>, secp256k1::Error> {
	let mut res = Vec::with_capacity(path.hops.len());

	let blinded_tail = path.blinded_tail.as_ref().and_then(|t| {
		if !t.trampoline_hops.is_empty() {
			return None;
		}
		Some(t)
	});
	construct_onion_keys_generic_callback(
		secp_ctx,
		&path.hops,
		blinded_tail,
		session_priv,
		|shared_secret, _blinding_factor, ephemeral_pubkey, _, _| {
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
		},
	)?;

	Ok(res)
}

// can only fail if an intermediary hop has an invalid public key or session_priv is invalid
pub(super) fn construct_trampoline_onion_keys<T: secp256k1::Signing>(
	secp_ctx: &Secp256k1<T>, blinded_tail: &BlindedTail, session_priv: &SecretKey,
) -> Result<Vec<OnionKeys>, secp256k1::Error> {
	let mut res = Vec::with_capacity(blinded_tail.trampoline_hops.len());

	construct_onion_keys_generic_callback(
		secp_ctx,
		&blinded_tail.trampoline_hops,
		Some(blinded_tail),
		session_priv,
		|shared_secret, _blinding_factor, ephemeral_pubkey, _, _| {
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
		},
	)?;

	Ok(res)
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

pub(super) const INVALID_ONION_BLINDING: u16 = 0x8000 | 0x4000 | 24;

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
	process_chacha(&ammag, &mut packet.data);
}

#[cfg(test)]
pub(super) fn test_crypt_failure_packet(shared_secret: &[u8], packet: &mut OnionErrorPacket) {
	crypt_failure_packet(shared_secret, packet)
}

fn process_chacha(key: &[u8; 32], packet: &mut [u8]) {
	let mut chacha = ChaCha20::new(key, &[0u8; 8]);
	chacha.process_in_place(packet);
}

fn build_unencrypted_failure_packet(
	shared_secret: &[u8], failure_type: u16, failure_data: &[u8], min_packet_len: usize,
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
	failure_type.write(&mut writer).unwrap();
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

	OnionErrorPacket { data: writer.0, attribution_data: None }
}

pub(super) fn build_failure_packet(
	shared_secret: &[u8], failure_type: u16, failure_data: &[u8],
) -> OnionErrorPacket {
	let mut onion_error_packet = build_unencrypted_failure_packet(
		shared_secret,
		failure_type,
		failure_data,
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
		#[cfg(any(test, feature = "_test_utils"))]
		pub(crate) onion_error_code: Option<u16>,
		#[cfg(any(test, feature = "_test_utils"))]
		pub(crate) onion_error_data: Option<Vec<u8>>,
	}
}
#[cfg(fuzzing)]
pub use self::fuzzy_onion_utils::*;
#[cfg(not(fuzzing))]
pub(crate) use self::fuzzy_onion_utils::*;

pub fn process_onion_failure<T: secp256k1::Signing, L: Deref>(
	secp_ctx: &Secp256k1<T>, logger: &L, htlc_source: &HTLCSource,
	encrypted_packet: OnionErrorPacket,
) -> DecodedOnionFailure
where
	L::Target: Logger,
{
	let (path, primary_session_priv) = match htlc_source {
		HTLCSource::OutboundRoute { ref path, ref session_priv, .. } => (path, session_priv),
		_ => unreachable!(),
	};

	if path.has_trampoline_hops() {
		// If we have Trampoline hops, the outer onion session_priv is a hash of the inner one.
		let session_priv_hash = Sha256::hash(&primary_session_priv.secret_bytes()).to_byte_array();
		let outer_session_priv =
			SecretKey::from_slice(&session_priv_hash[..]).expect("You broke SHA-256!");
		process_onion_failure_inner(
			secp_ctx,
			logger,
			path,
			&outer_session_priv,
			Some(primary_session_priv),
			encrypted_packet,
		)
	} else {
		process_onion_failure_inner(
			secp_ctx,
			logger,
			path,
			primary_session_priv,
			None,
			encrypted_packet,
		)
	}
}

/// Process failure we got back from upstream on a payment we sent (implying htlc_source is an
/// OutboundRoute).
#[inline]
pub(super) fn process_onion_failure_inner<T: secp256k1::Signing, L: Deref>(
	secp_ctx: &Secp256k1<T>, logger: &L, path: &Path, outer_session_priv: &SecretKey,
	inner_session_priv: Option<&SecretKey>, mut encrypted_packet: OnionErrorPacket,
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
			#[cfg(any(test, feature = "_test_utils"))]
			onion_error_code: None,
			#[cfg(any(test, feature = "_test_utils"))]
			onion_error_data: None,
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

	const BADONION: u16 = 0x8000;
	const PERM: u16 = 0x4000;
	const NODE: u16 = 0x2000;
	const UPDATE: u16 = 0x1000;

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

	let (num_blinded_hops, num_trampoline_hops) =
		path.blinded_tail.as_ref().map_or((0, 0), |bt| (bt.hops.len(), bt.trampoline_hops.len()));

	// We are first collecting all the unblinded `RouteHop`s inside `onion_keys`. Then, if applicable,
	// we will add all the `TrampolineHop`s, and finally, the blinded hops.
	let mut onion_keys =
		Vec::with_capacity(path.hops.len() + num_trampoline_hops + num_blinded_hops);

	construct_onion_keys_generic_callback(
		secp_ctx,
		&path.hops,
		// if we have Trampoline hops, the blinded hops are part of the inner Trampoline onion
		if path.has_trampoline_hops() { None } else { path.blinded_tail.as_ref() },
		outer_session_priv,
		|shared_secret, _, _, route_hop_option: Option<&RouteHop>, _| {
			onion_keys.push((route_hop_option.map(|rh| ErrorHop::RouteHop(rh)), shared_secret))
		},
	)
	.expect("Route we used spontaneously grew invalid keys in the middle of it?");

	if path.has_trampoline_hops() {
		construct_onion_keys_generic_callback(
			secp_ctx,
			// Trampoline hops are part of the blinded tail, so this can never panic
			&path.blinded_tail.as_ref().unwrap().trampoline_hops,
			path.blinded_tail.as_ref(),
			inner_session_priv.expect("Trampoline hops always have an inner session priv"),
			|shared_secret, _, _, trampoline_hop_option: Option<&TrampolineHop>, _| {
				onion_keys.push((
					trampoline_hop_option.map(|th| ErrorHop::TrampolineHop(th)),
					shared_secret,
				))
			},
		)
		.expect("Route we used spontaneously grew invalid keys in the middle of it?");
	}

	// Handle packed channel/node updates for passing back for the route handler
	let mut iterator = onion_keys.into_iter().peekable();
	while let Some((route_hop_option, shared_secret)) = iterator.next() {
		let route_hop = match route_hop_option.as_ref() {
			Some(hop) => hop,
			None => {
				// Got an error from within a blinded route.
				_error_code_ret = Some(BADONION | PERM | 24); // invalid_onion_blinding
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
		let next_hop = iterator.peek();
		is_from_final_non_blinded_node = next_hop.is_none() && num_blinded_hops <= 1;
		let failing_route_hop = if is_from_final_non_blinded_node {
			route_hop
		} else {
			match next_hop {
				Some((Some(hop), _)) => hop,
				_ => {
					// The failing hop is within a multi-hop blinded path.
					#[cfg(not(test))]
					{
						_error_code_ret = Some(BADONION | PERM | 24); // invalid_onion_blinding
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
						_error_code_ret = Some(u16::from_be_bytes(
							err_packet.failuremsg.get(0..2).unwrap().try_into().unwrap(),
						));
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

		let error_code = u16::from_be_bytes(error_code_slice.try_into().expect("len is 2"));
		_error_code_ret = Some(error_code);
		_error_packet_ret = Some(err_packet.failuremsg[2..].to_vec());

		let (debug_field, debug_field_size) = errors::get_onion_debug_field(error_code);

		// indicate that payment parameter has failed and no need to update Route object
		let payment_failed = match error_code & 0xff {
			15 | 16 | 17 | 18 | 19 | 23 => true,
			_ => false,
		} && is_from_final_non_blinded_node; // PERM bit observed below even if this error is from the intermediate nodes

		let mut network_update = None;
		let mut short_channel_id = None;

		if error_code & BADONION == BADONION {
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
		} else if error_code & NODE == NODE {
			let is_permanent = error_code & PERM == PERM;
			network_update =
				Some(NetworkUpdate::NodeFailure { node_id: *route_hop.pubkey(), is_permanent });
			short_channel_id = route_hop.short_channel_id();
		} else if error_code & PERM == PERM {
			if !payment_failed {
				if let ErrorHop::RouteHop(failing_route_hop) = failing_route_hop {
					network_update = Some(NetworkUpdate::ChannelFailure {
						short_channel_id: failing_route_hop.short_channel_id,
						is_permanent: true,
					});
				}
				short_channel_id = failing_route_hop.short_channel_id();
			}
		} else if error_code & UPDATE == UPDATE {
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
			short_channel_id = match error_code & 0xff {
				18 | 19 => route_hop.short_channel_id(),
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
			payment_failed_permanently: error_code & PERM == PERM && is_from_final_non_blinded_node,
			failed_within_blinded_path: false,
		});

		let (description, title) = errors::get_onion_error_description(error_code);
		if debug_field_size > 0 && err_packet.failuremsg.len() >= 4 + debug_field_size {
			log_info!(
				logger,
				"Onion Error[from {}: {}({:#x}) {}({})] {}",
				route_hop.pubkey(),
				title,
				error_code,
				debug_field,
				log_bytes!(&err_packet.failuremsg[4..4 + debug_field_size]),
				description
			);
		} else {
			log_info!(
				logger,
				"Onion Error[from {}: {}({:#x})] {}",
				route_hop.pubkey(),
				title,
				error_code,
				description
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
			#[cfg(any(test, feature = "_test_utils"))]
			onion_error_code: _error_code_ret,
			#[cfg(any(test, feature = "_test_utils"))]
			onion_error_data: _error_packet_ret,
		}
	} else {
		// only not set either packet unparseable or hmac does not match with any
		// payment not retryable only when garbage is from the final node
		log_warn!(
			logger,
			"Non-attributable failure encountered on route {}",
			path.hops.iter().map(|h| h.pubkey.to_string()).collect::<Vec<_>>().join("->")
		);

		DecodedOnionFailure {
			network_update: None,
			short_channel_id: None,
			payment_failed_permanently: is_from_final_non_blinded_node,
			failed_within_blinded_path: false,
			#[cfg(any(test, feature = "_test_utils"))]
			onion_error_code: None,
			#[cfg(any(test, feature = "_test_utils"))]
			onion_error_data: None,
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
	Reason { failure_code: u16, data: Vec<u8> },
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
			HTLCFailReasonRepr::Reason { ref failure_code, .. } => {
				write!(f, "HTLC error code {}", failure_code)
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
		(0, failure_code, required),
		(2, data, required_vec),
	},
);

impl HTLCFailReason {
	#[rustfmt::skip]
	pub(super) fn reason(failure_code: u16, data: Vec<u8>) -> Self {
		const BADONION: u16 = 0x8000;
		const PERM: u16 = 0x4000;
		const NODE: u16 = 0x2000;
		const UPDATE: u16 = 0x1000;

		     if failure_code == 1  | PERM { debug_assert!(data.is_empty()) }
		else if failure_code == 2  | NODE { debug_assert!(data.is_empty()) }
		else if failure_code == 2  | PERM | NODE { debug_assert!(data.is_empty()) }
		else if failure_code == 3  | PERM | NODE { debug_assert!(data.is_empty()) }
		else if failure_code == 4  | BADONION | PERM { debug_assert_eq!(data.len(), 32) }
		else if failure_code == 5  | BADONION | PERM { debug_assert_eq!(data.len(), 32) }
		else if failure_code == 6  | BADONION | PERM { debug_assert_eq!(data.len(), 32) }
		else if failure_code == 7  | UPDATE {
			debug_assert_eq!(data.len() - 2, u16::from_be_bytes(data[0..2].try_into().unwrap()) as usize) }
		else if failure_code == 8  | PERM { debug_assert!(data.is_empty()) }
		else if failure_code == 9  | PERM { debug_assert!(data.is_empty()) }
		else if failure_code == 10 | PERM { debug_assert!(data.is_empty()) }
		else if failure_code == 11 | UPDATE {
			debug_assert_eq!(data.len() - 2 - 8, u16::from_be_bytes(data[8..10].try_into().unwrap()) as usize) }
		else if failure_code == 12 | UPDATE {
			debug_assert_eq!(data.len() - 2 - 8, u16::from_be_bytes(data[8..10].try_into().unwrap()) as usize) }
		else if failure_code == 13 | UPDATE {
			debug_assert_eq!(data.len() - 2 - 4, u16::from_be_bytes(data[4..6].try_into().unwrap()) as usize) }
		else if failure_code == 14 | UPDATE {
			debug_assert_eq!(data.len() - 2, u16::from_be_bytes(data[0..2].try_into().unwrap()) as usize) }
		else if failure_code == 15 | PERM { debug_assert_eq!(data.len(), 12) }
		else if failure_code == 18 { debug_assert_eq!(data.len(), 4) }
		else if failure_code == 19 { debug_assert_eq!(data.len(), 8) }
		else if failure_code == 20 | UPDATE {
			debug_assert_eq!(data.len() - 2 - 2, u16::from_be_bytes(data[2..4].try_into().unwrap()) as usize) }
		else if failure_code == 21 { debug_assert!(data.is_empty()) }
		else if failure_code == 22 | PERM { debug_assert!(data.len() <= 11) }
		else if failure_code == 23 { debug_assert!(data.is_empty()) }
		else if failure_code & BADONION != 0 {
			// We set some bogus BADONION failure codes in test, so ignore unknown ones.
		}
		else { debug_assert!(false, "Unknown failure code: {}", failure_code) }

		Self(HTLCFailReasonRepr::Reason { failure_code, data })
	}

	pub(super) fn from_failure_code(failure_code: u16) -> Self {
		Self::reason(failure_code, Vec::new())
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
			HTLCFailReasonRepr::Reason { ref failure_code, ref data } => {
				if let Some(secondary_shared_secret) = secondary_shared_secret {
					let mut packet =
						build_failure_packet(secondary_shared_secret, *failure_code, &data[..]);

					crypt_failure_packet(incoming_packet_shared_secret, &mut packet);

					packet
				} else {
					build_failure_packet(incoming_packet_shared_secret, *failure_code, &data[..])
				}
			},
			HTLCFailReasonRepr::LightningError { ref err, .. } => {
				let mut err = err.clone();

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
			HTLCFailReasonRepr::Reason { ref failure_code, ref data, .. } => {
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
						#[cfg(any(test, feature = "_test_utils"))]
						onion_error_code: Some(*failure_code),
						#[cfg(any(test, feature = "_test_utils"))]
						onion_error_data: Some(data.clone()),
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
		#[allow(unused)]
		trampoline_shared_secret: SharedSecret,
	},
	/// This onion payload was for us, not for forwarding to a next-hop, and it was sent to us via
	/// Trampoline. Contains information for verifying the incoming payment.
	TrampolineBlindedReceive {
		#[allow(unused)]
		outer_hop_data: msgs::InboundTrampolineEntrypointPayload,
		outer_shared_secret: SharedSecret,
		trampoline_hop_data: msgs::InboundOnionBlindedReceivePayload,
		#[allow(unused)]
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
	Malformed { err_msg: &'static str, err_code: u16 },
	/// We failed to decode the onion payload.
	///
	/// If the payload we failed to decode belonged to a Trampoline onion, following the successful
	/// decoding of the outer onion, the trampoline_shared_secret field should be set.
	Relay {
		err_msg: &'static str,
		err_code: u16,
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
							err_code: INVALID_ONION_BLINDING,
						});
					}
					Err(OnionDecodeErr::Relay {
						err_msg: "Final Node OnionHopData provided for us as an intermediary node",
						err_code: 0x4000 | 22,
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
								err_code: INVALID_ONION_BLINDING,
								shared_secret,
								trampoline_shared_secret: Some(SharedSecret::from_bytes(
									trampoline_shared_secret,
								)),
							});
						}
						Err(OnionDecodeErr::Malformed {
							err_msg: "Non-final Trampoline onion data provided to us as last hop",
							err_code: INVALID_ONION_BLINDING,
						})
					},
					Ok((msgs::InboundTrampolinePayload::BlindedReceive(hop_data), Some(_))) => {
						if hop_data.intro_node_blinding_point.is_some() {
							return Err(OnionDecodeErr::Relay {
								err_msg: "Final Trampoline intro node onion data provided to us as intermediate hop",
								err_code: 0x4000 | 22,
								shared_secret,
								trampoline_shared_secret: Some(SharedSecret::from_bytes(
									trampoline_shared_secret,
								)),
							});
						}
						Err(OnionDecodeErr::Malformed {
							err_msg:
								"Final Trampoline onion data provided to us as intermediate hop",
							err_code: INVALID_ONION_BLINDING,
						})
					},
					Ok((msgs::InboundTrampolinePayload::Forward(_), None)) => {
						Err(OnionDecodeErr::Relay {
							err_msg: "Non-final Trampoline onion data provided to us as last hop",
							err_code: 0x4000 | 22,
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
							err_code: 0x4000 | 22,
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
						err_code: INVALID_ONION_BLINDING,
					});
				}
				Err(OnionDecodeErr::Relay {
					err_msg: "Intermediate Node OnionHopData provided for us as a final node",
					err_code: 0x4000 | 22,
					shared_secret,
					trampoline_shared_secret: None,
				})
			},
		},
		Err(e) => Err(e),
	}
}

/// Build a payment onion, returning the first hop msat and cltv values as well.
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

/// Build a payment onion, returning the first hop msat and cltv values as well.
/// `cur_block_height` should be set to the best known block height + 1.
pub(crate) fn create_payment_onion_internal<T: secp256k1::Signing>(
	secp_ctx: &Secp256k1<T>, path: &Path, session_priv: &SecretKey, total_msat: u64,
	recipient_onion: &RecipientOnionFields, cur_block_height: u32, payment_hash: &PaymentHash,
	keysend_preimage: &Option<PaymentPreimage>, invoice_request: Option<&InvoiceRequest>,
	prng_seed: [u8; 32], secondary_session_priv: Option<SecretKey>,
	secondary_prng_seed: Option<[u8; 32]>,
) -> Result<(msgs::OnionPacket, u64, u32), APIError> {
	let mut outer_total_msat = total_msat;
	let mut outer_starting_htlc_offset = cur_block_height;
	let mut outer_session_priv_override = None;
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

			let onion_keys =
				construct_trampoline_onion_keys(&secp_ctx, &blinded_tail, &session_priv).map_err(
					|_| APIError::InvalidRoute {
						err: "Pubkey along hop was maliciously selected".to_owned(),
					},
				)?;
			let trampoline_packet = construct_trampoline_onion_packet(
				trampoline_payloads,
				onion_keys,
				prng_seed,
				payment_hash,
				// TODO: specify a fixed size for privacy in future spec upgrade
				None,
			)
			.map_err(|_| APIError::InvalidRoute {
				err: "Route size too large considering onion data".to_owned(),
			})?;

			trampoline_packet_option = Some(trampoline_packet);

			outer_session_priv_override = Some(secondary_session_priv.unwrap_or_else(|| {
				let session_priv_hash = Sha256::hash(&session_priv.secret_bytes()).to_byte_array();
				SecretKey::from_slice(&session_priv_hash[..]).expect("You broke SHA-256!")
			}));
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

	let outer_session_priv = outer_session_priv_override.as_ref().unwrap_or(session_priv);
	let onion_keys = construct_onion_keys(&secp_ctx, &path, outer_session_priv).map_err(|_| {
		APIError::InvalidRoute { err: "Pubkey along hop was maliciously selected".to_owned() }
	})?;
	let outer_onion_prng_seed = secondary_prng_seed.unwrap_or(prng_seed);
	let onion_packet =
		construct_onion_packet(onion_payloads, onion_keys, outer_onion_prng_seed, payment_hash)
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
			err_code: 0x8000 | 0x4000 | 5,
		});
	}

	let mut chacha = ChaCha20::new(&rho, &[0u8; 8]);
	let mut chacha_stream = ChaChaReader { chacha: &mut chacha, read: Cursor::new(&hop_data[..]) };
	match R::read(&mut chacha_stream, read_args) {
		Err(err) => {
			let error_code = match err {
				// Unknown realm byte
				msgs::DecodeError::UnknownVersion => 0x4000 | 1,
				// invalid_onion_payload
				msgs::DecodeError::UnknownRequiredFeature
				| msgs::DecodeError::InvalidValue
				| msgs::DecodeError::ShortRead => 0x4000 | 22,
				// Should never happen
				_ => 0x2000 | 2,
			};
			return Err(OnionDecodeErr::Relay {
				err_msg: "Unable to decode our hop data",
				err_code: error_code,
				shared_secret: SharedSecret::from_bytes(shared_secret),
				trampoline_shared_secret: None,
			});
		},
		Ok(msg) => {
			let mut hmac = [0; 32];
			if let Err(_) = chacha_stream.read_exact(&mut hmac[..]) {
				return Err(OnionDecodeErr::Relay {
					err_msg: "Unable to decode our hop data",
					err_code: 0x4000 | 22,
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

pub const HOLD_TIME_LEN: usize = 4;
pub const MAX_HOPS: usize = 20;
pub const HMAC_LEN: usize = 4;

// Define the number of HMACs in the attributable data block. For the first node, there are 20 HMACs, and then for every
// subsequent node, the number of HMACs decreases by 1. 20 + 19 + 18 + ... + 1 = 20 * 21 / 2 = 210.
pub const HMAC_COUNT: usize = MAX_HOPS * (MAX_HOPS + 1) / 2;

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct AttributionData {
	pub hold_times: [u8; MAX_HOPS * HOLD_TIME_LEN],
	pub hmacs: [u8; HMAC_LEN * HMAC_COUNT],
}

impl AttributionData {
	pub fn new() -> Self {
		Self { hold_times: [0; MAX_HOPS * HOLD_TIME_LEN], hmacs: [0; HMAC_LEN * HMAC_COUNT] }
	}
}

impl_writeable!(AttributionData, {
	hold_times,
	hmacs
});

#[cfg(test)]
mod tests {
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
	use bitcoin::hex::FromHex;
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
			super::construct_onion_keys(&secp_ctx, &route.paths[0], &get_test_session_key())
				.unwrap();
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
	fn test_failure_packet_onion() {
		// Returning Errors test vectors from BOLT 4

		let onion_keys = build_test_onion_keys();
		let mut onion_error = super::build_unencrypted_failure_packet(
			onion_keys[4].shared_secret.as_ref(),
			0x2002,
			&[0; 0],
			DEFAULT_MIN_FAILURE_PACKET_LEN,
		);
		let hex = "4c2fc8bc08510334b6833ad9c3e79cd1b52ae59dfe5c2a4b23ead50f09f7ee0b0002200200fe0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
		assert_eq!(onion_error.data, <Vec<u8>>::from_hex(hex).unwrap());

		super::crypt_failure_packet(onion_keys[4].shared_secret.as_ref(), &mut onion_error);
		let hex = "a5e6bd0c74cb347f10cce367f949098f2457d14c046fd8a22cb96efb30b0fdcda8cb9168b50f2fd45edd73c1b0c8b33002df376801ff58aaa94000bf8a86f92620f343baef38a580102395ae3abf9128d1047a0736ff9b83d456740ebbb4aeb3aa9737f18fb4afb4aa074fb26c4d702f42968888550a3bded8c05247e045b866baef0499f079fdaeef6538f31d44deafffdfd3afa2fb4ca9082b8f1c465371a9894dd8c243fb4847e004f5256b3e90e2edde4c9fb3082ddfe4d1e734cacd96ef0706bf63c9984e22dc98851bcccd1c3494351feb458c9c6af41c0044bea3c47552b1d992ae542b17a2d0bba1a096c78d169034ecb55b6e3a7263c26017f033031228833c1daefc0dedb8cf7c3e37c9c37ebfe42f3225c326e8bcfd338804c145b16e34e4";
		assert_eq!(onion_error.data, <Vec<u8>>::from_hex(hex).unwrap());

		super::crypt_failure_packet(onion_keys[3].shared_secret.as_ref(), &mut onion_error);
		let hex = "c49a1ce81680f78f5f2000cda36268de34a3f0a0662f55b4e837c83a8773c22aa081bab1616a0011585323930fa5b9fae0c85770a2279ff59ec427ad1bbff9001c0cd1497004bd2a0f68b50704cf6d6a4bf3c8b6a0833399a24b3456961ba00736785112594f65b6b2d44d9f5ea4e49b5e1ec2af978cbe31c67114440ac51a62081df0ed46d4a3df295da0b0fe25c0115019f03f15ec86fabb4c852f83449e812f141a9395b3f70b766ebbd4ec2fae2b6955bd8f32684c15abfe8fd3a6261e52650e8807a92158d9f1463261a925e4bfba44bd20b166d532f0017185c3a6ac7957adefe45559e3072c8dc35abeba835a8cb01a71a15c736911126f27d46a36168ca5ef7dccd4e2886212602b181463e0dd30185c96348f9743a02aca8ec27c0b90dca270";
		assert_eq!(onion_error.data, <Vec<u8>>::from_hex(hex).unwrap());

		super::crypt_failure_packet(onion_keys[2].shared_secret.as_ref(), &mut onion_error);
		let hex = "a5d3e8634cfe78b2307d87c6d90be6fe7855b4f2cc9b1dfb19e92e4b79103f61ff9ac25f412ddfb7466e74f81b3e545563cdd8f5524dae873de61d7bdfccd496af2584930d2b566b4f8d3881f8c043df92224f38cf094cfc09d92655989531524593ec6d6caec1863bdfaa79229b5020acc034cd6deeea1021c50586947b9b8e6faa83b81fbfa6133c0af5d6b07c017f7158fa94f0d206baf12dda6b68f785b773b360fd0497e16cc402d779c8d48d0fa6315536ef0660f3f4e1865f5b38ea49c7da4fd959de4e83ff3ab686f059a45c65ba2af4a6a79166aa0f496bf04d06987b6d2ea205bdb0d347718b9aeff5b61dfff344993a275b79717cd815b6ad4c0beb568c4ac9c36ff1c315ec1119a1993c4b61e6eaa0375e0aaf738ac691abd3263bf937e3";
		assert_eq!(onion_error.data, <Vec<u8>>::from_hex(hex).unwrap());

		super::crypt_failure_packet(onion_keys[1].shared_secret.as_ref(), &mut onion_error);
		let hex = "aac3200c4968f56b21f53e5e374e3a2383ad2b1b6501bbcc45abc31e59b26881b7dfadbb56ec8dae8857add94e6702fb4c3a4de22e2e669e1ed926b04447fc73034bb730f4932acd62727b75348a648a1128744657ca6a4e713b9b646c3ca66cac02cdab44dd3439890ef3aaf61708714f7375349b8da541b2548d452d84de7084bb95b3ac2345201d624d31f4d52078aa0fa05a88b4e20202bd2b86ac5b52919ea305a8949de95e935eed0319cf3cf19ebea61d76ba92532497fcdc9411d06bcd4275094d0a4a3c5d3a945e43305a5a9256e333e1f64dbca5fcd4e03a39b9012d197506e06f29339dfee3331995b21615337ae060233d39befea925cc262873e0530408e6990f1cbd233a150ef7b004ff6166c70c68d9f8c853c1abca640b8660db2921";
		assert_eq!(onion_error.data, <Vec<u8>>::from_hex(hex).unwrap());

		super::crypt_failure_packet(onion_keys[0].shared_secret.as_ref(), &mut onion_error);
		let hex = "9c5add3963fc7f6ed7f148623c84134b5647e1306419dbe2174e523fa9e2fbed3a06a19f899145610741c83ad40b7712aefaddec8c6baf7325d92ea4ca4d1df8bce517f7e54554608bf2bd8071a4f52a7a2f7ffbb1413edad81eeea5785aa9d990f2865dc23b4bc3c301a94eec4eabebca66be5cf638f693ec256aec514620cc28ee4a94bd9565bc4d4962b9d3641d4278fb319ed2b84de5b665f307a2db0f7fbb757366067d88c50f7e829138fde4f78d39b5b5802f1b92a8a820865af5cc79f9f30bc3f461c66af95d13e5e1f0381c184572a91dee1c849048a647a1158cf884064deddbf1b0b88dfe2f791428d0ba0f6fb2f04e14081f69165ae66d9297c118f0907705c9c4954a199bae0bb96fad763d690e7daa6cfda59ba7f2c8d11448b604d12d";
		assert_eq!(onion_error.data, <Vec<u8>>::from_hex(hex).unwrap());

		let logger: Arc<TestLogger> = Arc::new(TestLogger::new());
		let ctx_full = Secp256k1::new();
		let path = build_test_path();
		let htlc_source = HTLCSource::OutboundRoute {
			path,
			session_priv: get_test_session_key(),
			first_hop_htlc_msat: 0,
			payment_id: PaymentId([1; 32]),
		};

		// Assert that the original failure can be retrieved and that all hmacs check out.
		let decrypted_failure =
			process_onion_failure(&ctx_full, &logger, &htlc_source, onion_error);
		assert_eq!(decrypted_failure.onion_error_code, Some(0x2002));
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
				Some(&trampoline_session_priv),
				error_packet,
			);
			assert_eq!(decrypted_failure.onion_error_code, Some(0x400f));
		}

		{
			// shared secret cryptography sanity tests
			let session_priv = get_test_session_key();
			let path = build_trampoline_test_path();

			let trampoline_onion_keys = construct_trampoline_onion_keys(
				&secp_ctx,
				&path.blinded_tail.as_ref().unwrap(),
				&session_priv,
			)
			.unwrap();

			let outer_onion_keys = {
				let session_priv_hash = Sha256::hash(&session_priv.secret_bytes()).to_byte_array();
				let outer_session_priv = SecretKey::from_slice(&session_priv_hash[..]).unwrap();
				construct_onion_keys(&Secp256k1::new(), &path, &outer_session_priv).unwrap()
			};

			let htlc_source = HTLCSource::OutboundRoute {
				path,
				session_priv,
				first_hop_htlc_msat: dummy_amt_msat,
				payment_id: PaymentId([1; 32]),
			};

			{
				// Ensure error decryption works without the Trampoline hops having been hit.
				let error_code = 0x2002;
				let mut first_hop_error_packet = build_unencrypted_failure_packet(
					outer_onion_keys[0].shared_secret.as_ref(),
					error_code,
					&[0; 0],
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
				let error_code = 0x2003;
				let mut trampoline_outer_hop_error_packet = build_unencrypted_failure_packet(
					outer_onion_keys[1].shared_secret.as_ref(),
					error_code,
					&[0; 0],
					DEFAULT_MIN_FAILURE_PACKET_LEN,
				);

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
				let error_code = 0x2004;
				let mut trampoline_inner_hop_error_packet = build_unencrypted_failure_packet(
					trampoline_onion_keys[0].shared_secret.as_ref(),
					error_code,
					&[0; 0],
					DEFAULT_MIN_FAILURE_PACKET_LEN,
				);

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
				let error_code = 0x2005;
				let mut trampoline_second_hop_error_packet = build_unencrypted_failure_packet(
					trampoline_onion_keys[1].shared_secret.as_ref(),
					error_code,
					&[0; 0],
					DEFAULT_MIN_FAILURE_PACKET_LEN,
				);

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
		let onion_error_packet = OnionErrorPacket { data: packet, attribution_data: None };

		// In the current protocol, it is unfortunately not possible to identify the failure source.
		let logger: TestLogger = TestLogger::new();
		let decrypted_failure = test_failure_attribution(&logger, onion_error_packet);
		assert_eq!(decrypted_failure.short_channel_id, None);

		logger.assert_log_contains(
			"lightning::ln::onion_utils",
			"Non-attributable failure encountered",
			1,
		);
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

		let mut onion_error_packet =
			OnionErrorPacket { data: packet.to_vec(), attribution_data: None };
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

		let mut onion_error_packet =
			OnionErrorPacket { data: packet.encode(), attribution_data: None };
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
			0x2002,
			&failure_data,
			DEFAULT_MIN_FAILURE_PACKET_LEN,
		);

		let msg = UpdateFailHTLC {
			channel_id: ChannelId([0; 32]),
			htlc_id: 0,
			reason: onion_error.data,
			attribution_data: Some(AttributionData {
				hold_times: [0; MAX_HOPS * HOLD_TIME_LEN],
				hmacs: [0; HMAC_LEN * HMAC_COUNT],
			}),
		};

		let mut buffer = Vec::new();
		msg.write(&mut buffer).unwrap();

		assert_eq!(buffer.len(), 65535);
	}
}
