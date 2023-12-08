//! Utilities to decode payment onions and do contextless validation of incoming payments.
//!
//! Primarily features [`peel_payment_onion`], which allows the decoding of an onion statelessly
//! and can be used to predict whether we'd accept a payment.

use bitcoin::hashes::Hash;
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::secp256k1::{self, Secp256k1, PublicKey};

use crate::blinded_path;
use crate::blinded_path::payment::{PaymentConstraints, PaymentRelay};
use crate::chain::channelmonitor::{HTLC_FAIL_BACK_BUFFER, LATENCY_GRACE_PERIOD_BLOCKS};
use crate::ln::PaymentHash;
use crate::ln::channelmanager::{BlindedForward, CLTV_FAR_FAR_AWAY, HTLCFailureMsg, MIN_CLTV_EXPIRY_DELTA, PendingHTLCInfo, PendingHTLCRouting};
use crate::ln::features::BlindedHopFeatures;
use crate::ln::msgs;
use crate::ln::onion_utils;
use crate::ln::onion_utils::{HTLCFailReason, INVALID_ONION_BLINDING};
use crate::sign::{NodeSigner, Recipient};
use crate::util::logger::Logger;

use crate::prelude::*;
use core::ops::Deref;

/// Invalid inbound onion payment.
#[derive(Debug)]
pub struct InboundOnionErr {
	/// BOLT 4 error code.
	pub err_code: u16,
	/// Data attached to this error.
	pub err_data: Vec<u8>,
	/// Error message text.
	pub msg: &'static str,
}

fn check_blinded_forward(
	inbound_amt_msat: u64, inbound_cltv_expiry: u32, payment_relay: &PaymentRelay,
	payment_constraints: &PaymentConstraints, features: &BlindedHopFeatures
) -> Result<(u64, u32), ()> {
	let amt_to_forward = blinded_path::payment::amt_to_forward_msat(
		inbound_amt_msat, payment_relay
	).ok_or(())?;
	let outgoing_cltv_value = inbound_cltv_expiry.checked_sub(
		payment_relay.cltv_expiry_delta as u32
	).ok_or(())?;
	if inbound_amt_msat < payment_constraints.htlc_minimum_msat ||
		outgoing_cltv_value > payment_constraints.max_cltv_expiry
		{ return Err(()) }
	if features.requires_unknown_bits_from(&BlindedHopFeatures::empty()) { return Err(()) }
	Ok((amt_to_forward, outgoing_cltv_value))
}

pub(super) fn create_fwd_pending_htlc_info(
	msg: &msgs::UpdateAddHTLC, hop_data: msgs::InboundOnionPayload, hop_hmac: [u8; 32],
	new_packet_bytes: [u8; onion_utils::ONION_DATA_LEN], shared_secret: [u8; 32],
	next_packet_pubkey_opt: Option<Result<PublicKey, secp256k1::Error>>
) -> Result<PendingHTLCInfo, InboundOnionErr> {
	debug_assert!(next_packet_pubkey_opt.is_some());
	let outgoing_packet = msgs::OnionPacket {
		version: 0,
		public_key: next_packet_pubkey_opt.unwrap_or(Err(secp256k1::Error::InvalidPublicKey)),
		hop_data: new_packet_bytes,
		hmac: hop_hmac,
	};

	let (
		short_channel_id, amt_to_forward, outgoing_cltv_value, inbound_blinding_point
	) = match hop_data {
		msgs::InboundOnionPayload::Forward { short_channel_id, amt_to_forward, outgoing_cltv_value } =>
			(short_channel_id, amt_to_forward, outgoing_cltv_value, None),
		msgs::InboundOnionPayload::BlindedForward {
			short_channel_id, payment_relay, payment_constraints, intro_node_blinding_point, features,
		} => {
			let (amt_to_forward, outgoing_cltv_value) = check_blinded_forward(
				msg.amount_msat, msg.cltv_expiry, &payment_relay, &payment_constraints, &features
			).map_err(|()| {
				// We should be returning malformed here if `msg.blinding_point` is set, but this is
				// unreachable right now since we checked it in `decode_update_add_htlc_onion`.
				InboundOnionErr {
					msg: "Underflow calculating outbound amount or cltv value for blinded forward",
					err_code: INVALID_ONION_BLINDING,
					err_data: vec![0; 32],
				}
			})?;
			(short_channel_id, amt_to_forward, outgoing_cltv_value, Some(intro_node_blinding_point))
		},
		msgs::InboundOnionPayload::Receive { .. } | msgs::InboundOnionPayload::BlindedReceive { .. } =>
			return Err(InboundOnionErr {
				msg: "Final Node OnionHopData provided for us as an intermediary node",
				err_code: 0x4000 | 22,
				err_data: Vec::new(),
			}),
	};

	Ok(PendingHTLCInfo {
		routing: PendingHTLCRouting::Forward {
			onion_packet: outgoing_packet,
			short_channel_id,
			blinded: inbound_blinding_point.map(|bp| BlindedForward { inbound_blinding_point: bp }),
		},
		payment_hash: msg.payment_hash,
		incoming_shared_secret: shared_secret,
		incoming_amt_msat: Some(msg.amount_msat),
		outgoing_amt_msat: amt_to_forward,
		outgoing_cltv_value,
		skimmed_fee_msat: None,
	})
}

pub(super) fn create_recv_pending_htlc_info(
	hop_data: msgs::InboundOnionPayload, shared_secret: [u8; 32], payment_hash: PaymentHash,
	amt_msat: u64, cltv_expiry: u32, phantom_shared_secret: Option<[u8; 32]>, allow_underpay: bool,
	counterparty_skimmed_fee_msat: Option<u64>, current_height: u32, accept_mpp_keysend: bool,
) -> Result<PendingHTLCInfo, InboundOnionErr> {
	let (payment_data, keysend_preimage, custom_tlvs, onion_amt_msat, outgoing_cltv_value, payment_metadata) = match hop_data {
		msgs::InboundOnionPayload::Receive {
			payment_data, keysend_preimage, custom_tlvs, amt_msat, outgoing_cltv_value, payment_metadata, ..
		} =>
			(payment_data, keysend_preimage, custom_tlvs, amt_msat, outgoing_cltv_value, payment_metadata),
		msgs::InboundOnionPayload::BlindedReceive {
			amt_msat, total_msat, outgoing_cltv_value, payment_secret, ..
		} => {
			let payment_data = msgs::FinalOnionHopData { payment_secret, total_msat };
			(Some(payment_data), None, Vec::new(), amt_msat, outgoing_cltv_value, None)
		}
		msgs::InboundOnionPayload::Forward { .. } => {
			return Err(InboundOnionErr {
				err_code: 0x4000|22,
				err_data: Vec::new(),
				msg: "Got non final data with an HMAC of 0",
			})
		},
		msgs::InboundOnionPayload::BlindedForward { .. } => {
			return Err(InboundOnionErr {
				err_code: INVALID_ONION_BLINDING,
				err_data: vec![0; 32],
				msg: "Got blinded non final data with an HMAC of 0",
			})
		}
	};
	// final_incorrect_cltv_expiry
	if outgoing_cltv_value > cltv_expiry {
		return Err(InboundOnionErr {
			msg: "Upstream node set CLTV to less than the CLTV set by the sender",
			err_code: 18,
			err_data: cltv_expiry.to_be_bytes().to_vec()
		})
	}
	// final_expiry_too_soon
	// We have to have some headroom to broadcast on chain if we have the preimage, so make sure
	// we have at least HTLC_FAIL_BACK_BUFFER blocks to go.
	//
	// Also, ensure that, in the case of an unknown preimage for the received payment hash, our
	// payment logic has enough time to fail the HTLC backward before our onchain logic triggers a
	// channel closure (see HTLC_FAIL_BACK_BUFFER rationale).
	if cltv_expiry <= current_height + HTLC_FAIL_BACK_BUFFER + 1 {
		let mut err_data = Vec::with_capacity(12);
		err_data.extend_from_slice(&amt_msat.to_be_bytes());
		err_data.extend_from_slice(&current_height.to_be_bytes());
		return Err(InboundOnionErr {
			err_code: 0x4000 | 15, err_data,
			msg: "The final CLTV expiry is too soon to handle",
		});
	}
	if (!allow_underpay && onion_amt_msat > amt_msat) ||
		(allow_underpay && onion_amt_msat >
		 amt_msat.saturating_add(counterparty_skimmed_fee_msat.unwrap_or(0)))
	{
		return Err(InboundOnionErr {
			err_code: 19,
			err_data: amt_msat.to_be_bytes().to_vec(),
			msg: "Upstream node sent less than we were supposed to receive in payment",
		});
	}

	let routing = if let Some(payment_preimage) = keysend_preimage {
		// We need to check that the sender knows the keysend preimage before processing this
		// payment further. Otherwise, an intermediary routing hop forwarding non-keysend-HTLC X
		// could discover the final destination of X, by probing the adjacent nodes on the route
		// with a keysend payment of identical payment hash to X and observing the processing
		// time discrepancies due to a hash collision with X.
		let hashed_preimage = PaymentHash(Sha256::hash(&payment_preimage.0).to_byte_array());
		if hashed_preimage != payment_hash {
			return Err(InboundOnionErr {
				err_code: 0x4000|22,
				err_data: Vec::new(),
				msg: "Payment preimage didn't match payment hash",
			});
		}
		if !accept_mpp_keysend && payment_data.is_some() {
			return Err(InboundOnionErr {
				err_code: 0x4000|22,
				err_data: Vec::new(),
				msg: "We don't support MPP keysend payments",
			});
		}
		PendingHTLCRouting::ReceiveKeysend {
			payment_data,
			payment_preimage,
			payment_metadata,
			incoming_cltv_expiry: outgoing_cltv_value,
			custom_tlvs,
		}
	} else if let Some(data) = payment_data {
		PendingHTLCRouting::Receive {
			payment_data: data,
			payment_metadata,
			incoming_cltv_expiry: outgoing_cltv_value,
			phantom_shared_secret,
			custom_tlvs,
		}
	} else {
		return Err(InboundOnionErr {
			err_code: 0x4000|0x2000|3,
			err_data: Vec::new(),
			msg: "We require payment_secrets",
		});
	};
	Ok(PendingHTLCInfo {
		routing,
		payment_hash,
		incoming_shared_secret: shared_secret,
		incoming_amt_msat: Some(amt_msat),
		outgoing_amt_msat: onion_amt_msat,
		outgoing_cltv_value,
		skimmed_fee_msat: counterparty_skimmed_fee_msat,
	})
}

/// Peel one layer off an incoming onion, returning a [`PendingHTLCInfo`] that contains information
/// about the intended next-hop for the HTLC.
///
/// This does all the relevant context-free checks that LDK requires for payment relay or
/// acceptance. If the payment is to be received, and the amount matches the expected amount for
/// a given invoice, this indicates the [`msgs::UpdateAddHTLC`], once fully committed in the
/// channel, will generate an [`Event::PaymentClaimable`].
///
/// [`Event::PaymentClaimable`]: crate::events::Event::PaymentClaimable
pub fn peel_payment_onion<NS: Deref, L: Deref, T: secp256k1::Verification>(
	msg: &msgs::UpdateAddHTLC, node_signer: &NS, logger: &L, secp_ctx: &Secp256k1<T>,
	cur_height: u32, accept_mpp_keysend: bool, allow_skimmed_fees: bool,
) -> Result<PendingHTLCInfo, InboundOnionErr>
where
	NS::Target: NodeSigner,
	L::Target: Logger,
{
	let (hop, shared_secret, next_packet_details_opt) =
		decode_incoming_update_add_htlc_onion(msg, node_signer, logger, secp_ctx
	).map_err(|e| {
		let (err_code, err_data) = match e {
			HTLCFailureMsg::Malformed(m) => (m.failure_code, Vec::new()),
			HTLCFailureMsg::Relay(r) => (0x4000 | 22, r.reason.data),
		};
		let msg = "Failed to decode update add htlc onion";
		InboundOnionErr { msg, err_code, err_data }
	})?;
	Ok(match hop {
		onion_utils::Hop::Forward { next_hop_data, next_hop_hmac, new_packet_bytes } => {
			let NextPacketDetails {
				next_packet_pubkey, outgoing_amt_msat: _, outgoing_scid: _, outgoing_cltv_value
			} = match next_packet_details_opt {
				Some(next_packet_details) => next_packet_details,
				// Forward should always include the next hop details
				None => return Err(InboundOnionErr {
					msg: "Failed to decode update add htlc onion",
					err_code: 0x4000 | 22,
					err_data: Vec::new(),
				}),
			};

			if let Err((err_msg, code)) = check_incoming_htlc_cltv(
				cur_height, outgoing_cltv_value, msg.cltv_expiry
			) {
				return Err(InboundOnionErr {
					msg: err_msg,
					err_code: code,
					err_data: Vec::new(),
				});
			}

			// TODO: If this is potentially a phantom payment we should decode the phantom payment
			// onion here and check it.

			create_fwd_pending_htlc_info(
				msg, next_hop_data, next_hop_hmac, new_packet_bytes, shared_secret,
				Some(next_packet_pubkey)
			)?
		},
		onion_utils::Hop::Receive(received_data) => {
			create_recv_pending_htlc_info(
				received_data, shared_secret, msg.payment_hash, msg.amount_msat, msg.cltv_expiry,
				None, allow_skimmed_fees, msg.skimmed_fee_msat, cur_height, accept_mpp_keysend,
			)?
		}
	})
}

pub(super) struct NextPacketDetails {
	pub(super) next_packet_pubkey: Result<PublicKey, secp256k1::Error>,
	pub(super) outgoing_scid: u64,
	pub(super) outgoing_amt_msat: u64,
	pub(super) outgoing_cltv_value: u32,
}

pub(super) fn decode_incoming_update_add_htlc_onion<NS: Deref, L: Deref, T: secp256k1::Verification>(
	msg: &msgs::UpdateAddHTLC, node_signer: &NS, logger: &L, secp_ctx: &Secp256k1<T>,
) -> Result<(onion_utils::Hop, [u8; 32], Option<NextPacketDetails>), HTLCFailureMsg>
where
	NS::Target: NodeSigner,
	L::Target: Logger,
{
	macro_rules! return_malformed_err {
		($msg: expr, $err_code: expr) => {
			{
				log_info!(logger, "Failed to accept/forward incoming HTLC: {}", $msg);
				return Err(HTLCFailureMsg::Malformed(msgs::UpdateFailMalformedHTLC {
					channel_id: msg.channel_id,
					htlc_id: msg.htlc_id,
					sha256_of_onion: Sha256::hash(&msg.onion_routing_packet.hop_data).to_byte_array(),
					failure_code: $err_code,
				}));
			}
		}
	}

	if let Err(_) = msg.onion_routing_packet.public_key {
		return_malformed_err!("invalid ephemeral pubkey", 0x8000 | 0x4000 | 6);
	}

	let shared_secret = node_signer.ecdh(
		Recipient::Node, &msg.onion_routing_packet.public_key.unwrap(), None
	).unwrap().secret_bytes();

	if msg.onion_routing_packet.version != 0 {
		//TODO: Spec doesn't indicate if we should only hash hop_data here (and in other
		//sha256_of_onion error data packets), or the entire onion_routing_packet. Either way,
		//the hash doesn't really serve any purpose - in the case of hashing all data, the
		//receiving node would have to brute force to figure out which version was put in the
		//packet by the node that send us the message, in the case of hashing the hop_data, the
		//node knows the HMAC matched, so they already know what is there...
		return_malformed_err!("Unknown onion packet version", 0x8000 | 0x4000 | 4);
	}
	macro_rules! return_err {
		($msg: expr, $err_code: expr, $data: expr) => {
			{
				log_info!(logger, "Failed to accept/forward incoming HTLC: {}", $msg);
				return Err(HTLCFailureMsg::Relay(msgs::UpdateFailHTLC {
					channel_id: msg.channel_id,
					htlc_id: msg.htlc_id,
					reason: HTLCFailReason::reason($err_code, $data.to_vec())
						.get_encrypted_failure_packet(&shared_secret, &None),
				}));
			}
		}
	}

	let next_hop = match onion_utils::decode_next_payment_hop(
		shared_secret, &msg.onion_routing_packet.hop_data[..], msg.onion_routing_packet.hmac,
		msg.payment_hash, node_signer
	) {
		Ok(res) => res,
		Err(onion_utils::OnionDecodeErr::Malformed { err_msg, err_code }) => {
			return_malformed_err!(err_msg, err_code);
		},
		Err(onion_utils::OnionDecodeErr::Relay { err_msg, err_code }) => {
			return_err!(err_msg, err_code, &[0; 0]);
		},
	};

	let next_packet_details = match next_hop {
		onion_utils::Hop::Forward {
			next_hop_data: msgs::InboundOnionPayload::Forward {
				short_channel_id, amt_to_forward, outgoing_cltv_value
			}, ..
		} => {
			let next_packet_pubkey = onion_utils::next_hop_pubkey(secp_ctx,
				msg.onion_routing_packet.public_key.unwrap(), &shared_secret);
			NextPacketDetails {
				next_packet_pubkey, outgoing_scid: short_channel_id,
				outgoing_amt_msat: amt_to_forward, outgoing_cltv_value
			}
		},
		onion_utils::Hop::Forward {
			next_hop_data: msgs::InboundOnionPayload::BlindedForward {
				short_channel_id, ref payment_relay, ref payment_constraints, ref features, ..
			}, ..
		} => {
			let (amt_to_forward, outgoing_cltv_value) = match check_blinded_forward(
				msg.amount_msat, msg.cltv_expiry, &payment_relay, &payment_constraints, &features
			) {
				Ok((amt, cltv)) => (amt, cltv),
				Err(()) => {
					return_err!("Underflow calculating outbound amount or cltv value for blinded forward",
						INVALID_ONION_BLINDING, &[0; 32]);
				}
			};
			let next_packet_pubkey = onion_utils::next_hop_pubkey(&secp_ctx,
				msg.onion_routing_packet.public_key.unwrap(), &shared_secret);
			NextPacketDetails {
				next_packet_pubkey, outgoing_scid: short_channel_id, outgoing_amt_msat: amt_to_forward,
				outgoing_cltv_value
			}
		},
		onion_utils::Hop::Receive { .. } => return Ok((next_hop, shared_secret, None)),
		onion_utils::Hop::Forward { next_hop_data: msgs::InboundOnionPayload::Receive { .. }, .. } |
			onion_utils::Hop::Forward { next_hop_data: msgs::InboundOnionPayload::BlindedReceive { .. }, .. } =>
		{
			return_err!("Final Node OnionHopData provided for us as an intermediary node", 0x4000 | 22, &[0; 0]);
		}
	};

	Ok((next_hop, shared_secret, Some(next_packet_details)))
}

pub(super) fn check_incoming_htlc_cltv(
	cur_height: u32, outgoing_cltv_value: u32, cltv_expiry: u32
) -> Result<(), (&'static str, u16)> {
	if (cltv_expiry as u64) < (outgoing_cltv_value) as u64 + MIN_CLTV_EXPIRY_DELTA as u64 {
		return Err((
			"Forwarding node has tampered with the intended HTLC values or origin node has an obsolete cltv_expiry_delta",
			0x1000 | 13, // incorrect_cltv_expiry
		));
	}
	// Theoretically, channel counterparty shouldn't send us a HTLC expiring now,
	// but we want to be robust wrt to counterparty packet sanitization (see
	// HTLC_FAIL_BACK_BUFFER rationale).
	if cltv_expiry <= cur_height + HTLC_FAIL_BACK_BUFFER as u32 { // expiry_too_soon
		return Err(("CLTV expiry is too close", 0x1000 | 14));
	}
	if cltv_expiry > cur_height + CLTV_FAR_FAR_AWAY as u32 { // expiry_too_far
		return Err(("CLTV expiry is too far in the future", 21));
	}
	// If the HTLC expires ~now, don't bother trying to forward it to our
	// counterparty. They should fail it anyway, but we don't want to bother with
	// the round-trips or risk them deciding they definitely want the HTLC and
	// force-closing to ensure they get it if we're offline.
	// We previously had a much more aggressive check here which tried to ensure
	// our counterparty receives an HTLC which has *our* risk threshold met on it,
	// but there is no need to do that, and since we're a bit conservative with our
	// risk threshold it just results in failing to forward payments.
	if (outgoing_cltv_value) as u64 <= (cur_height + LATENCY_GRACE_PERIOD_BLOCKS) as u64 {
		return Err(("Outgoing CLTV value is too soon", 0x1000 | 14));
	}

	Ok(())
}

#[cfg(test)]
mod tests {
	use bitcoin::hashes::Hash;
	use bitcoin::hashes::sha256::Hash as Sha256;
	use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
	use crate::ln::{PaymentPreimage, PaymentHash, PaymentSecret};
	use crate::ln::ChannelId;
	use crate::ln::channelmanager::RecipientOnionFields;
	use crate::ln::features::{ChannelFeatures, NodeFeatures};
	use crate::ln::msgs;
	use crate::ln::onion_utils::create_payment_onion;
	use crate::routing::router::{Path, RouteHop};
	use crate::util::test_utils;

	#[test]
	fn fail_construct_onion_on_too_big_payloads() {
		// Ensure that if we call `construct_onion_packet` and friends where payloads are too large for
		// the allotted packet length, we'll fail to construct. Previously, senders would happily
		// construct invalid packets by array-shifting the final node's HMAC out of the packet when
		// adding an intermediate onion layer, causing the receiver to error with "final payload
		// provided for us as an intermediate node."
		let secp_ctx = Secp256k1::new();
		let bob = crate::sign::KeysManager::new(&[2; 32], 42, 42);
		let bob_pk = PublicKey::from_secret_key(&secp_ctx, &bob.get_node_secret_key());
		let charlie = crate::sign::KeysManager::new(&[3; 32], 42, 42);
		let charlie_pk = PublicKey::from_secret_key(&secp_ctx, &charlie.get_node_secret_key());

		let (
			session_priv, total_amt_msat, cur_height, mut recipient_onion, keysend_preimage, payment_hash,
			prng_seed, hops, ..
		) = payment_onion_args(bob_pk, charlie_pk);

		// Ensure the onion will not fit all the payloads by adding a large custom TLV.
		recipient_onion.custom_tlvs.push((13377331, vec![0; 1156]));

		let path = Path { hops, blinded_tail: None, };
		let onion_keys = super::onion_utils::construct_onion_keys(&secp_ctx, &path, &session_priv).unwrap();
		let (onion_payloads, ..) = super::onion_utils::build_onion_payloads(
			&path, total_amt_msat, recipient_onion, cur_height + 1, &Some(keysend_preimage)
		).unwrap();

		assert!(super::onion_utils::construct_onion_packet(
				onion_payloads, onion_keys, prng_seed, &payment_hash
		).is_err());
	}

	#[test]
	fn test_peel_payment_onion() {
		use super::*;
		let secp_ctx = Secp256k1::new();

		let bob = crate::sign::KeysManager::new(&[2; 32], 42, 42);
		let bob_pk = PublicKey::from_secret_key(&secp_ctx, &bob.get_node_secret_key());
		let charlie = crate::sign::KeysManager::new(&[3; 32], 42, 42);
		let charlie_pk = PublicKey::from_secret_key(&secp_ctx, &charlie.get_node_secret_key());

		let (session_priv, total_amt_msat, cur_height, recipient_onion, preimage, payment_hash,
			prng_seed, hops, recipient_amount, pay_secret) = payment_onion_args(bob_pk, charlie_pk);

		let path = Path {
			hops: hops,
			blinded_tail: None,
		};

		let (onion, amount_msat, cltv_expiry) = create_payment_onion(
			&secp_ctx, &path, &session_priv, total_amt_msat, recipient_onion, cur_height,
			&payment_hash, &Some(preimage), prng_seed
		).unwrap();

		let msg = make_update_add_msg(amount_msat, cltv_expiry, payment_hash, onion);
		let logger = test_utils::TestLogger::with_id("bob".to_string());

		let peeled = peel_payment_onion(&msg, &&bob, &&logger, &secp_ctx, cur_height, true, false)
			.map_err(|e| e.msg).unwrap();

		let next_onion = match peeled.routing {
			PendingHTLCRouting::Forward { onion_packet, .. } => {
				onion_packet
			},
			_ => panic!("expected a forwarded onion"),
		};

		let msg2 = make_update_add_msg(amount_msat, cltv_expiry, payment_hash, next_onion);
		let peeled2 = peel_payment_onion(&msg2, &&charlie, &&logger, &secp_ctx, cur_height, true, false)
			.map_err(|e| e.msg).unwrap();

		match peeled2.routing {
			PendingHTLCRouting::ReceiveKeysend { payment_preimage, payment_data, incoming_cltv_expiry, .. } => {
				assert_eq!(payment_preimage, preimage);
				assert_eq!(peeled2.outgoing_amt_msat, recipient_amount);
				assert_eq!(incoming_cltv_expiry, peeled2.outgoing_cltv_value);
				let msgs::FinalOnionHopData{total_msat, payment_secret} = payment_data.unwrap();
				assert_eq!(total_msat, total_amt_msat);
				assert_eq!(payment_secret, pay_secret);
			},
			_ => panic!("expected a received keysend"),
		};
	}

	fn make_update_add_msg(
		amount_msat: u64, cltv_expiry: u32, payment_hash: PaymentHash,
		onion_routing_packet: msgs::OnionPacket
	) -> msgs::UpdateAddHTLC {
		msgs::UpdateAddHTLC {
			channel_id: ChannelId::from_bytes([0; 32]),
			htlc_id: 0,
			amount_msat,
			cltv_expiry,
			payment_hash,
			onion_routing_packet,
			skimmed_fee_msat: None,
			blinding_point: None,
		}
	}

	fn payment_onion_args(hop_pk: PublicKey, recipient_pk: PublicKey) -> (
		SecretKey, u64, u32, RecipientOnionFields, PaymentPreimage, PaymentHash, [u8; 32],
		Vec<RouteHop>, u64, PaymentSecret,
	) {
		let session_priv_bytes = [42; 32];
		let session_priv = SecretKey::from_slice(&session_priv_bytes).unwrap();
		let total_amt_msat = 1000;
		let cur_height = 1000;
		let pay_secret = PaymentSecret([99; 32]);
		let recipient_onion = RecipientOnionFields::secret_only(pay_secret);
		let preimage_bytes = [43; 32];
		let preimage = PaymentPreimage(preimage_bytes);
		let rhash_bytes = Sha256::hash(&preimage_bytes).to_byte_array();
		let payment_hash = PaymentHash(rhash_bytes);
		let prng_seed = [44; 32];

		// make a route alice -> bob -> charlie
		let hop_fee = 1;
		let recipient_amount = total_amt_msat - hop_fee;
		let hops = vec![
			RouteHop {
				pubkey: hop_pk,
				fee_msat: hop_fee,
				cltv_expiry_delta: 42,
				short_channel_id: 1,
				node_features: NodeFeatures::empty(),
				channel_features: ChannelFeatures::empty(),
				maybe_announced_channel: false,
			},
			RouteHop {
				pubkey: recipient_pk,
				fee_msat: recipient_amount,
				cltv_expiry_delta: 42,
				short_channel_id: 2,
				node_features: NodeFeatures::empty(),
				channel_features: ChannelFeatures::empty(),
				maybe_announced_channel: false,
			}
		];

		(session_priv, total_amt_msat, cur_height, recipient_onion, preimage, payment_hash,
			prng_seed, hops, recipient_amount, pay_secret)
	}

}
