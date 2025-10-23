//! Utilities to decode payment onions and do contextless validation of incoming payments.
//!
//! Primarily features [`peel_payment_onion`], which allows the decoding of an onion statelessly
//! and can be used to predict whether we'd accept a payment.

use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::ecdh::SharedSecret;
use bitcoin::secp256k1::{self, PublicKey, Secp256k1};

use crate::blinded_path;
use crate::blinded_path::payment::{PaymentConstraints, PaymentRelay};
use crate::chain::channelmonitor::{HTLC_FAIL_BACK_BUFFER, LATENCY_GRACE_PERIOD_BLOCKS};
use crate::ln::channelmanager::{
	BlindedFailure, BlindedForward, HTLCFailureMsg, PendingHTLCInfo, PendingHTLCRouting,
	CLTV_FAR_FAR_AWAY, MIN_CLTV_EXPIRY_DELTA,
};
use crate::ln::msgs;
use crate::ln::onion_utils;
use crate::ln::onion_utils::{HTLCFailReason, LocalHTLCFailureReason, ONION_DATA_LEN};
use crate::sign::{NodeSigner, Recipient};
use crate::types::features::BlindedHopFeatures;
use crate::types::payment::PaymentHash;
use crate::util::logger::Logger;

#[allow(unused_imports)]
use crate::prelude::*;

use core::ops::Deref;

/// Invalid inbound onion payment.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct InboundHTLCErr {
	/// BOLT 4 error code.
	pub reason: LocalHTLCFailureReason,
	/// Data attached to this error.
	pub err_data: Vec<u8>,
	/// Error message text.
	pub msg: &'static str,
}

/// Writes payment data for invalid or unknown payment error code.
pub(super) fn invalid_payment_err_data(amt_msat: u64, current_height: u32) -> Vec<u8> {
	let mut err_data = Vec::with_capacity(12);
	err_data.extend_from_slice(&amt_msat.to_be_bytes());
	err_data.extend_from_slice(&current_height.to_be_bytes());
	err_data
}

#[rustfmt::skip]
fn check_blinded_payment_constraints(
	amt_msat: u64, cltv_expiry: u32, constraints: &PaymentConstraints
) -> Result<(), ()> {
	if amt_msat < constraints.htlc_minimum_msat ||
		cltv_expiry > constraints.max_cltv_expiry
	{ return Err(()) }
	Ok(())
}

#[rustfmt::skip]
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
	check_blinded_payment_constraints(inbound_amt_msat, outgoing_cltv_value, payment_constraints)?;

	if features.requires_unknown_bits_from(&BlindedHopFeatures::empty()) { return Err(()) }
	Ok((amt_to_forward, outgoing_cltv_value))
}

fn check_trampoline_payment_constraints(
	outer_hop_data: &msgs::InboundTrampolineEntrypointPayload, trampoline_cltv_value: u32,
	trampoline_amount: u64,
) -> Result<(), InboundHTLCErr> {
	if outer_hop_data.outgoing_cltv_value < trampoline_cltv_value {
		return Err(InboundHTLCErr {
			reason: LocalHTLCFailureReason::FinalIncorrectCLTVExpiry,
			err_data: outer_hop_data.outgoing_cltv_value.to_be_bytes().to_vec(),
			msg: "Trampoline onion's CLTV value exceeded the outer onion's",
		});
	}
	let outgoing_amount = outer_hop_data
		.multipath_trampoline_data
		.as_ref()
		.map_or(outer_hop_data.amt_to_forward, |mtd| mtd.total_msat);
	if outgoing_amount < trampoline_amount {
		return Err(InboundHTLCErr {
			reason: LocalHTLCFailureReason::FinalIncorrectHTLCAmount,
			err_data: outgoing_amount.to_be_bytes().to_vec(),
			msg: "Trampoline onion's amt value exceeded the outer onion's",
		});
	}

	Ok(())
}

enum RoutingInfo {
	Direct {
		short_channel_id: u64,
		new_packet_bytes: [u8; ONION_DATA_LEN],
		next_hop_hmac: [u8; 32],
	},
	Trampoline {
		next_trampoline: PublicKey,
		// Trampoline onions are currently variable length
		new_packet_bytes: Vec<u8>,
		next_hop_hmac: [u8; 32],
		shared_secret: SharedSecret,
		current_path_key: Option<PublicKey>,
	},
}

#[rustfmt::skip]
pub(super) fn create_fwd_pending_htlc_info(
	msg: &msgs::UpdateAddHTLC, hop_data: onion_utils::Hop, shared_secret: [u8; 32],
	next_packet_pubkey_opt: Option<Result<PublicKey, secp256k1::Error>>
) -> Result<PendingHTLCInfo, InboundHTLCErr> {
	debug_assert!(next_packet_pubkey_opt.is_some());

	let (
		routing_info, amt_to_forward, outgoing_cltv_value, intro_node_blinding_point,
		next_blinding_override
	) = match hop_data {
		onion_utils::Hop::Forward { next_hop_data: msgs::InboundOnionForwardPayload {
			short_channel_id, amt_to_forward, outgoing_cltv_value
		}, new_packet_bytes, next_hop_hmac, .. } =>
			(RoutingInfo::Direct { short_channel_id, new_packet_bytes, next_hop_hmac }, amt_to_forward, outgoing_cltv_value, None, None),
		onion_utils::Hop::BlindedForward { next_hop_data: msgs::InboundOnionBlindedForwardPayload {
			short_channel_id, payment_relay, payment_constraints, intro_node_blinding_point, features,
			next_blinding_override,
		}, new_packet_bytes, next_hop_hmac, .. } => {
			let (amt_to_forward, outgoing_cltv_value) = check_blinded_forward(
				msg.amount_msat, msg.cltv_expiry, &payment_relay, &payment_constraints, &features
			).map_err(|()| {
				// We should be returning malformed here if `msg.blinding_point` is set, but this is
				// unreachable right now since we checked it in `decode_update_add_htlc_onion`.
				InboundHTLCErr {
					msg: "Underflow calculating outbound amount or cltv value for blinded forward",
					reason: LocalHTLCFailureReason::InvalidOnionBlinding,
					err_data: vec![0; 32],
				}
			})?;
			(RoutingInfo::Direct { short_channel_id, new_packet_bytes, next_hop_hmac }, amt_to_forward, outgoing_cltv_value, intro_node_blinding_point,
				next_blinding_override)
		},
		onion_utils::Hop::Receive { .. } | onion_utils::Hop::BlindedReceive { .. } =>
			return Err(InboundHTLCErr {
				msg: "Final Node OnionHopData provided for us as an intermediary node",
				reason: LocalHTLCFailureReason::InvalidOnionPayload,
				err_data: Vec::new(),
			}),
		onion_utils::Hop::TrampolineReceive { .. } | onion_utils::Hop::TrampolineBlindedReceive { .. } =>
			return Err(InboundHTLCErr {
				msg: "Final Node OnionHopData provided for us as an intermediary node",
				reason: LocalHTLCFailureReason::InvalidOnionPayload,
				err_data: Vec::new(),
			}),
		onion_utils::Hop::TrampolineForward { next_trampoline_hop_data, next_trampoline_hop_hmac, new_trampoline_packet_bytes, trampoline_shared_secret, .. } => {
			(
				RoutingInfo::Trampoline {
					next_trampoline: next_trampoline_hop_data.next_trampoline,
					new_packet_bytes: new_trampoline_packet_bytes,
					next_hop_hmac: next_trampoline_hop_hmac,
					shared_secret: trampoline_shared_secret,
					current_path_key: None
				},
				next_trampoline_hop_data.amt_to_forward,
				next_trampoline_hop_data.outgoing_cltv_value,
				None,
				None
			)
		},
		onion_utils::Hop::TrampolineBlindedForward { outer_hop_data, next_trampoline_hop_data, next_trampoline_hop_hmac, new_trampoline_packet_bytes, trampoline_shared_secret, .. } => {
			let (amt_to_forward, outgoing_cltv_value) = check_blinded_forward(
				msg.amount_msat, msg.cltv_expiry, &next_trampoline_hop_data.payment_relay, &next_trampoline_hop_data.payment_constraints, &next_trampoline_hop_data.features
			).map_err(|()| {
				// We should be returning malformed here if `msg.blinding_point` is set, but this is
				// unreachable right now since we checked it in `decode_update_add_htlc_onion`.
				InboundHTLCErr {
					msg: "Underflow calculating outbound amount or cltv value for blinded forward",
					reason: LocalHTLCFailureReason::InvalidOnionBlinding,
					err_data: vec![0; 32],
				}
			})?;
			(
				RoutingInfo::Trampoline {
					next_trampoline: next_trampoline_hop_data.next_trampoline,
					new_packet_bytes: new_trampoline_packet_bytes,
					next_hop_hmac: next_trampoline_hop_hmac,
					shared_secret: trampoline_shared_secret,
					current_path_key: outer_hop_data.current_path_key
				},
				amt_to_forward,
				outgoing_cltv_value,
				next_trampoline_hop_data.intro_node_blinding_point,
				next_trampoline_hop_data.next_blinding_override
			)
		},
	};

	let routing = match routing_info {
		RoutingInfo::Direct { short_channel_id, new_packet_bytes, next_hop_hmac } => {
			let outgoing_packet = msgs::OnionPacket {
				version: 0,
				public_key: next_packet_pubkey_opt.unwrap_or(Err(secp256k1::Error::InvalidPublicKey)),
				hop_data: new_packet_bytes,
				hmac: next_hop_hmac,
			};
			PendingHTLCRouting::Forward {
				onion_packet: outgoing_packet,
				short_channel_id,
				incoming_cltv_expiry: Some(msg.cltv_expiry),
				hold_htlc: msg.hold_htlc,
				blinded: intro_node_blinding_point.or(msg.blinding_point)
					.map(|bp| BlindedForward {
						inbound_blinding_point: bp,
						next_blinding_override,
						failure: intro_node_blinding_point
							.map(|_| BlindedFailure::FromIntroductionNode)
							.unwrap_or(BlindedFailure::FromBlindedNode),
					}),
			}
		}
		RoutingInfo::Trampoline { next_trampoline, new_packet_bytes, next_hop_hmac, shared_secret, current_path_key } => {
			let next_trampoline_packet_pubkey = match next_packet_pubkey_opt {
				Some(Ok(pubkey)) => pubkey,
				_ => return Err(InboundHTLCErr {
					msg: "Missing next Trampoline hop pubkey from intermediate Trampoline forwarding data",
					reason: LocalHTLCFailureReason::InvalidTrampolinePayload,
					err_data: Vec::new(),
				}),
			};
			let outgoing_packet = msgs::TrampolineOnionPacket {
				version: 0,
				public_key: next_trampoline_packet_pubkey,
				hop_data: new_packet_bytes,
				hmac: next_hop_hmac,
			};
			PendingHTLCRouting::TrampolineForward {
				incoming_shared_secret: shared_secret.secret_bytes(),
				onion_packet: outgoing_packet,
				node_id: next_trampoline,
				incoming_cltv_expiry: msg.cltv_expiry,
				blinded: intro_node_blinding_point.or(current_path_key)
					.map(|bp| BlindedForward {
						inbound_blinding_point: bp,
						next_blinding_override,
						failure: intro_node_blinding_point
							.map(|_| BlindedFailure::FromIntroductionNode)
							.unwrap_or(BlindedFailure::FromBlindedNode),
					})
			}
		}
	};

	Ok(PendingHTLCInfo {
		routing,
		payment_hash: msg.payment_hash,
		incoming_shared_secret: shared_secret,
		incoming_amt_msat: Some(msg.amount_msat),
		outgoing_amt_msat: amt_to_forward,
		outgoing_cltv_value,
		skimmed_fee_msat: None,
	})
}

#[rustfmt::skip]
pub(super) fn create_recv_pending_htlc_info(
	hop_data: onion_utils::Hop, shared_secret: [u8; 32], payment_hash: PaymentHash,
	amt_msat: u64, cltv_expiry: u32, phantom_shared_secret: Option<[u8; 32]>, allow_underpay: bool,
	counterparty_skimmed_fee_msat: Option<u64>, current_height: u32
) -> Result<PendingHTLCInfo, InboundHTLCErr> {
	let (
		payment_data, keysend_preimage, custom_tlvs, onion_amt_msat, onion_cltv_expiry,
		payment_metadata, payment_context, requires_blinded_error, has_recipient_created_payment_secret,
		invoice_request, trampoline_shared_secret,
	) = match hop_data {
		onion_utils::Hop::Receive { hop_data: msgs::InboundOnionReceivePayload {
			payment_data, keysend_preimage, custom_tlvs, sender_intended_htlc_amt_msat,
			cltv_expiry_height, payment_metadata, ..
		}, .. } =>
			(payment_data, keysend_preimage, custom_tlvs, sender_intended_htlc_amt_msat,
			 cltv_expiry_height, payment_metadata, None, false, keysend_preimage.is_none(), None, None),
		onion_utils::Hop::BlindedReceive { hop_data: msgs::InboundOnionBlindedReceivePayload {
			sender_intended_htlc_amt_msat, total_msat, cltv_expiry_height, payment_secret,
			intro_node_blinding_point, payment_constraints, payment_context, keysend_preimage,
			custom_tlvs, invoice_request
		}, .. } => {
			check_blinded_payment_constraints(
				sender_intended_htlc_amt_msat, cltv_expiry, &payment_constraints
			)
				.map_err(|()| {
					InboundHTLCErr {
						reason: LocalHTLCFailureReason::InvalidOnionBlinding,
						err_data: vec![0; 32],
						msg: "Amount or cltv_expiry violated blinded payment constraints",
					}
				})?;
			let payment_data = msgs::FinalOnionHopData { payment_secret, total_msat };
			(Some(payment_data), keysend_preimage, custom_tlvs,
			 sender_intended_htlc_amt_msat, cltv_expiry_height, None, Some(payment_context),
			 intro_node_blinding_point.is_none(), true, invoice_request, None)
		}
		onion_utils::Hop::TrampolineReceive {
			ref outer_hop_data,
			trampoline_shared_secret,
			trampoline_hop_data: msgs::InboundOnionReceivePayload {
				payment_data, keysend_preimage, custom_tlvs, sender_intended_htlc_amt_msat,
				cltv_expiry_height, payment_metadata, ..
			}, ..
		} => {
			check_trampoline_payment_constraints(outer_hop_data, cltv_expiry_height, sender_intended_htlc_amt_msat)?;
			(payment_data, keysend_preimage, custom_tlvs, sender_intended_htlc_amt_msat,
				cltv_expiry_height, payment_metadata, None, false, keysend_preimage.is_none(), None, Some(trampoline_shared_secret.secret_bytes()))
		},
		onion_utils::Hop::TrampolineBlindedReceive {
			trampoline_shared_secret,
			ref outer_hop_data,
			trampoline_hop_data: msgs::InboundOnionBlindedReceivePayload {
				sender_intended_htlc_amt_msat, total_msat, cltv_expiry_height, payment_secret,
				intro_node_blinding_point, payment_constraints, payment_context, keysend_preimage,
				custom_tlvs, invoice_request
			}, ..
		} => {
			check_blinded_payment_constraints(
				sender_intended_htlc_amt_msat, cltv_expiry, &payment_constraints,
			)
				.map_err(|()| {
					InboundHTLCErr {
						reason: LocalHTLCFailureReason::InvalidOnionBlinding,
						err_data: vec![0; 32],
						msg: "Amount or cltv_expiry violated blinded payment constraints within Trampoline onion",
					}
				})?;
			let payment_data = msgs::FinalOnionHopData { payment_secret, total_msat };
			check_trampoline_payment_constraints(outer_hop_data, cltv_expiry_height, sender_intended_htlc_amt_msat).map_err(|e| {
				InboundHTLCErr {
					reason: LocalHTLCFailureReason::InvalidOnionBlinding,
					err_data: vec![0; 32],
					msg: e.msg,
				}
			})?;
			(Some(payment_data), keysend_preimage, custom_tlvs,
				sender_intended_htlc_amt_msat, cltv_expiry_height, None, Some(payment_context),
				intro_node_blinding_point.is_none(), true, invoice_request, Some(trampoline_shared_secret.secret_bytes()))
		},
		onion_utils::Hop::Forward { .. } => {
			return Err(InboundHTLCErr {
				reason: LocalHTLCFailureReason::InvalidOnionPayload,
				err_data: Vec::new(),
				msg: "Got non final data with an HMAC of 0",
			})
		},
		onion_utils::Hop::BlindedForward { .. } => {
			return Err(InboundHTLCErr {
				reason: LocalHTLCFailureReason::InvalidOnionBlinding,
				err_data: vec![0; 32],
				msg: "Got blinded non final data with an HMAC of 0",
			})
		},
		onion_utils::Hop::TrampolineForward { .. } | onion_utils::Hop::TrampolineBlindedForward { .. } => {
			return Err(InboundHTLCErr {
				reason: LocalHTLCFailureReason::InvalidOnionPayload,
				err_data: Vec::new(),
				msg: "Got Trampoline non final data with an HMAC of 0",
			})
		},
	};
	// final_incorrect_cltv_expiry
	if onion_cltv_expiry > cltv_expiry {
		return Err(InboundHTLCErr {
			msg: "Upstream node set CLTV to less than the CLTV set by the sender",
			reason: LocalHTLCFailureReason::FinalIncorrectCLTVExpiry,
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
		return Err(InboundHTLCErr {
			reason: LocalHTLCFailureReason::PaymentClaimBuffer,
			err_data: invalid_payment_err_data(amt_msat, current_height),
			msg: "The final CLTV expiry is too soon to handle",
		});
	}
	if (!allow_underpay && onion_amt_msat > amt_msat) ||
		(allow_underpay && onion_amt_msat >
		 amt_msat.saturating_add(counterparty_skimmed_fee_msat.unwrap_or(0)))
	{
		return Err(InboundHTLCErr {
			reason: LocalHTLCFailureReason::FinalIncorrectHTLCAmount,
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
			return Err(InboundHTLCErr {
				reason: LocalHTLCFailureReason::InvalidKeysendPreimage,
				err_data: invalid_payment_err_data(amt_msat, current_height),
				msg: "Payment preimage didn't match payment hash",
			});
		}
		PendingHTLCRouting::ReceiveKeysend {
			payment_data,
			payment_preimage,
			payment_metadata,
			incoming_cltv_expiry: onion_cltv_expiry,
			custom_tlvs,
			requires_blinded_error,
			has_recipient_created_payment_secret,
			payment_context,
			invoice_request,
		}
	} else if let Some(data) = payment_data {
		PendingHTLCRouting::Receive {
			payment_data: data,
			payment_metadata,
			payment_context,
			incoming_cltv_expiry: onion_cltv_expiry,
			phantom_shared_secret,
			trampoline_shared_secret,
			custom_tlvs,
			requires_blinded_error,
		}
	} else {
		return Err(InboundHTLCErr {
			reason: LocalHTLCFailureReason::PaymentSecretRequired,
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
		outgoing_cltv_value: onion_cltv_expiry,
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
#[rustfmt::skip]
pub fn peel_payment_onion<NS: Deref, L: Deref, T: secp256k1::Verification>(
	msg: &msgs::UpdateAddHTLC, node_signer: NS, logger: L, secp_ctx: &Secp256k1<T>,
	cur_height: u32, allow_skimmed_fees: bool,
) -> Result<PendingHTLCInfo, InboundHTLCErr>
where
	NS::Target: NodeSigner,
	L::Target: Logger,
{
	let (hop, next_packet_details_opt) =
		decode_incoming_update_add_htlc_onion(msg, node_signer, logger, secp_ctx
	).map_err(|(msg, failure_reason)| {
		let (reason, err_data) = match msg {
			HTLCFailureMsg::Malformed(_) => (failure_reason, Vec::new()),
			HTLCFailureMsg::Relay(r) => (LocalHTLCFailureReason::InvalidOnionPayload, r.reason),
		};
		let msg = "Failed to decode update add htlc onion";
		InboundHTLCErr { msg, reason, err_data }
	})?;
	Ok(match hop {
		onion_utils::Hop::Forward { shared_secret, .. } |
		onion_utils::Hop::BlindedForward { shared_secret, .. } => {
			let NextPacketDetails {
				next_packet_pubkey, outgoing_amt_msat: _, outgoing_connector: _, outgoing_cltv_value
			} = match next_packet_details_opt {
				Some(next_packet_details) => next_packet_details,
				// Forward should always include the next hop details
				None => return Err(InboundHTLCErr {
					msg: "Failed to decode update add htlc onion",
					reason: LocalHTLCFailureReason::InvalidOnionPayload,
					err_data: Vec::new(),
				}),
			};

			if let Err(reason) = check_incoming_htlc_cltv(
				cur_height, outgoing_cltv_value, msg.cltv_expiry,
			) {
				return Err(InboundHTLCErr {
					msg: "incoming cltv check failed",
					reason,
					err_data: Vec::new(),
				});
			}

			// TODO: If this is potentially a phantom payment we should decode the phantom payment
			// onion here and check it.
			create_fwd_pending_htlc_info(msg, hop, shared_secret.secret_bytes(), Some(next_packet_pubkey))?
		},
		_ => {
			let shared_secret = hop.shared_secret().secret_bytes();
			create_recv_pending_htlc_info(
				hop, shared_secret, msg.payment_hash, msg.amount_msat, msg.cltv_expiry,
				None, allow_skimmed_fees, msg.skimmed_fee_msat, cur_height,
			)?
		}
	})
}

pub(super) enum HopConnector {
	// scid-based routing
	ShortChannelId(u64),
	// Trampoline-based routing
	#[allow(unused)]
	Trampoline(PublicKey),
}

pub(super) struct NextPacketDetails {
	pub(super) next_packet_pubkey: Result<PublicKey, secp256k1::Error>,
	pub(super) outgoing_connector: HopConnector,
	pub(super) outgoing_amt_msat: u64,
	pub(super) outgoing_cltv_value: u32,
}

#[rustfmt::skip]
pub(super) fn decode_incoming_update_add_htlc_onion<NS: Deref, L: Deref, T: secp256k1::Verification>(
	msg: &msgs::UpdateAddHTLC, node_signer: NS, logger: L, secp_ctx: &Secp256k1<T>,
) -> Result<(onion_utils::Hop, Option<NextPacketDetails>), (HTLCFailureMsg, LocalHTLCFailureReason)>
where
	NS::Target: NodeSigner,
	L::Target: Logger,
{
	let encode_malformed_error = |message: &str, failure_reason: LocalHTLCFailureReason| {
		log_info!(logger, "Failed to accept/forward incoming HTLC: {}", message);
		let (sha256_of_onion, failure_reason) = if msg.blinding_point.is_some() || failure_reason == LocalHTLCFailureReason::InvalidOnionBlinding {
			([0; 32], LocalHTLCFailureReason::InvalidOnionBlinding)
		} else {
			(Sha256::hash(&msg.onion_routing_packet.hop_data).to_byte_array(), failure_reason)
		};
		return Err((HTLCFailureMsg::Malformed(msgs::UpdateFailMalformedHTLC {
			channel_id: msg.channel_id,
			htlc_id: msg.htlc_id,
			sha256_of_onion,
			failure_code: failure_reason.failure_code(),
		}), failure_reason));
	};

	if let Err(_) = msg.onion_routing_packet.public_key {
		return encode_malformed_error("invalid ephemeral pubkey", LocalHTLCFailureReason::InvalidOnionKey);
	}

	if msg.onion_routing_packet.version != 0 {
		//TODO: Spec doesn't indicate if we should only hash hop_data here (and in other
		//sha256_of_onion error data packets), or the entire onion_routing_packet. Either way,
		//the hash doesn't really serve any purpose - in the case of hashing all data, the
		//receiving node would have to brute force to figure out which version was put in the
		//packet by the node that send us the message, in the case of hashing the hop_data, the
		//node knows the HMAC matched, so they already know what is there...
		return encode_malformed_error("Unknown onion packet version", LocalHTLCFailureReason::InvalidOnionVersion)
	}

	let encode_relay_error = |message: &str, reason: LocalHTLCFailureReason, shared_secret: [u8; 32], trampoline_shared_secret: Option<[u8; 32]>, data: &[u8]| {
		if msg.blinding_point.is_some() {
			return encode_malformed_error(message, LocalHTLCFailureReason::InvalidOnionBlinding)
		}

		log_info!(logger, "Failed to accept/forward incoming HTLC: {}", message);
		let failure = HTLCFailReason::reason(reason, data.to_vec())
			.get_encrypted_failure_packet(&shared_secret, &trampoline_shared_secret);
		return Err((HTLCFailureMsg::Relay(msgs::UpdateFailHTLC {
			channel_id: msg.channel_id,
			htlc_id: msg.htlc_id,
			reason: failure.data,
			attribution_data: failure.attribution_data,
		}), reason));
	};

	let next_hop = match onion_utils::decode_next_payment_hop(
		Recipient::Node, &msg.onion_routing_packet.public_key.unwrap(), &msg.onion_routing_packet.hop_data[..], msg.onion_routing_packet.hmac,
		msg.payment_hash, msg.blinding_point, node_signer
	) {
		Ok(res) => res,
		Err(onion_utils::OnionDecodeErr::Malformed { err_msg, reason }) => {
			return encode_malformed_error(err_msg, reason);
		},
		Err(onion_utils::OnionDecodeErr::Relay { err_msg, reason, shared_secret, trampoline_shared_secret }) => {
			return encode_relay_error(err_msg, reason, shared_secret.secret_bytes(), trampoline_shared_secret.map(|tss| tss.secret_bytes()), &[0; 0]);
		},
	};

	let next_packet_details = match next_hop {
		onion_utils::Hop::Forward { next_hop_data: msgs::InboundOnionForwardPayload { short_channel_id, amt_to_forward, outgoing_cltv_value }, shared_secret, .. } => {
			let next_packet_pubkey = onion_utils::next_hop_pubkey(secp_ctx,
				msg.onion_routing_packet.public_key.unwrap(), &shared_secret.secret_bytes());
			Some(NextPacketDetails {
				next_packet_pubkey, outgoing_connector: HopConnector::ShortChannelId(short_channel_id),
				outgoing_amt_msat: amt_to_forward, outgoing_cltv_value
			})
		}
		onion_utils::Hop::BlindedForward { next_hop_data: msgs::InboundOnionBlindedForwardPayload { short_channel_id, ref payment_relay, ref payment_constraints, ref features, .. }, shared_secret, .. } => {
			let (amt_to_forward, outgoing_cltv_value) = match check_blinded_forward(
				msg.amount_msat, msg.cltv_expiry, &payment_relay, &payment_constraints, &features
			) {
				Ok((amt, cltv)) => (amt, cltv),
				Err(()) => {
					return encode_relay_error("Underflow calculating outbound amount or cltv value for blinded forward",
						LocalHTLCFailureReason::InvalidOnionBlinding, shared_secret.secret_bytes(), None, &[0; 32]);
				}
			};
			let next_packet_pubkey = onion_utils::next_hop_pubkey(&secp_ctx,
				msg.onion_routing_packet.public_key.unwrap(), &shared_secret.secret_bytes());
			Some(NextPacketDetails {
				next_packet_pubkey, outgoing_connector: HopConnector::ShortChannelId(short_channel_id), outgoing_amt_msat: amt_to_forward,
				outgoing_cltv_value
			})
		}
		onion_utils::Hop::TrampolineForward { next_trampoline_hop_data: msgs::InboundTrampolineForwardPayload { amt_to_forward, outgoing_cltv_value, next_trampoline }, trampoline_shared_secret, incoming_trampoline_public_key, .. } => {
			let next_trampoline_packet_pubkey = onion_utils::next_hop_pubkey(secp_ctx,
				incoming_trampoline_public_key, &trampoline_shared_secret.secret_bytes());
			Some(NextPacketDetails {
				next_packet_pubkey: next_trampoline_packet_pubkey,
				outgoing_connector: HopConnector::Trampoline(next_trampoline),
				outgoing_amt_msat: amt_to_forward,
				outgoing_cltv_value,
			})
		}
		onion_utils::Hop::TrampolineBlindedForward { next_trampoline_hop_data: msgs::InboundTrampolineBlindedForwardPayload { next_trampoline, ref payment_relay, ref payment_constraints, ref features, .. }, outer_shared_secret, trampoline_shared_secret, incoming_trampoline_public_key, .. } => {
			let (amt_to_forward, outgoing_cltv_value) = match check_blinded_forward(
				msg.amount_msat, msg.cltv_expiry, &payment_relay, &payment_constraints, &features
			) {
				Ok((amt, cltv)) => (amt, cltv),
				Err(()) => {
					return encode_relay_error("Underflow calculating outbound amount or cltv value for blinded trampoline forward",
						LocalHTLCFailureReason::InvalidOnionBlinding, outer_shared_secret.secret_bytes(), Some(trampoline_shared_secret.secret_bytes()), &[0; 32]);
				}
			};
			let next_trampoline_packet_pubkey = onion_utils::next_hop_pubkey(secp_ctx,
				incoming_trampoline_public_key, &trampoline_shared_secret.secret_bytes());
			Some(NextPacketDetails {
				next_packet_pubkey: next_trampoline_packet_pubkey,
				outgoing_connector: HopConnector::Trampoline(next_trampoline),
				outgoing_amt_msat: amt_to_forward,
				outgoing_cltv_value,
			})
		}
		_ => None
	};

	Ok((next_hop, next_packet_details))
}

pub(super) fn check_incoming_htlc_cltv(
	cur_height: u32, outgoing_cltv_value: u32, cltv_expiry: u32,
) -> Result<(), LocalHTLCFailureReason> {
	if (cltv_expiry as u64) < (outgoing_cltv_value) as u64 + MIN_CLTV_EXPIRY_DELTA as u64 {
		return Err(LocalHTLCFailureReason::IncorrectCLTVExpiry);
	}
	// Theoretically, channel counterparty shouldn't send us a HTLC expiring now,
	// but we want to be robust wrt to counterparty packet sanitization (see
	// HTLC_FAIL_BACK_BUFFER rationale).
	if cltv_expiry <= cur_height + HTLC_FAIL_BACK_BUFFER as u32 {
		return Err(LocalHTLCFailureReason::CLTVExpiryTooSoon);
	}
	if cltv_expiry > cur_height + CLTV_FAR_FAR_AWAY as u32 {
		return Err(LocalHTLCFailureReason::CLTVExpiryTooFar);
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
		return Err(LocalHTLCFailureReason::OutgoingCLTVTooSoon);
	}

	Ok(())
}

#[cfg(test)]
mod tests {
	use crate::ln::channelmanager::{RecipientOnionFields, MIN_CLTV_EXPIRY_DELTA};
	use crate::ln::functional_test_utils::TEST_FINAL_CLTV;
	use crate::ln::msgs;
	use crate::ln::onion_utils::create_payment_onion;
	use crate::ln::types::ChannelId;
	use crate::routing::router::{Path, RouteHop};
	use crate::types::features::{ChannelFeatures, NodeFeatures};
	use crate::types::payment::{PaymentHash, PaymentPreimage, PaymentSecret};
	use crate::util::test_utils;
	use bitcoin::hashes::sha256::Hash as Sha256;
	use bitcoin::hashes::Hash;
	use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};

	#[test]
	#[rustfmt::skip]
	fn fail_construct_onion_on_too_big_payloads() {
		// Ensure that if we call `construct_onion_packet` and friends where payloads are too large for
		// the allotted packet length, we'll fail to construct. Previously, senders would happily
		// construct invalid packets by array-shifting the final node's HMAC out of the packet when
		// adding an intermediate onion layer, causing the receiver to error with "final payload
		// provided for us as an intermediate node."
		let secp_ctx = Secp256k1::new();
		let bob = crate::sign::KeysManager::new(&[2; 32], 42, 42, true);
		let bob_pk = PublicKey::from_secret_key(&secp_ctx, &bob.get_node_secret_key());
		let charlie = crate::sign::KeysManager::new(&[3; 32], 42, 42, true);
		let charlie_pk = PublicKey::from_secret_key(&secp_ctx, &charlie.get_node_secret_key());

		let (
			session_priv, total_amt_msat, cur_height, mut recipient_onion, keysend_preimage, payment_hash,
			prng_seed, hops, ..
		) = payment_onion_args(bob_pk, charlie_pk);

		// Ensure the onion will not fit all the payloads by adding a large custom TLV.
		recipient_onion.custom_tlvs.push((13377331, vec![0; 1156]));

		let path = Path { hops, blinded_tail: None, };
		let onion_keys = super::onion_utils::construct_onion_keys(&secp_ctx, &path, &session_priv);
		let (onion_payloads, ..) = super::onion_utils::build_onion_payloads(
			&path, total_amt_msat, &recipient_onion, cur_height + 1, &Some(keysend_preimage), None, None
		).unwrap();

		assert!(super::onion_utils::construct_onion_packet(
				onion_payloads, onion_keys, prng_seed, &payment_hash
		).is_err());
	}

	#[test]
	#[rustfmt::skip]
	fn test_peel_payment_onion() {
		use super::*;
		let secp_ctx = Secp256k1::new();

		let bob = crate::sign::KeysManager::new(&[2; 32], 42, 42, true);
		let bob_pk = PublicKey::from_secret_key(&secp_ctx, &bob.get_node_secret_key());
		let charlie = crate::sign::KeysManager::new(&[3; 32], 42, 42, true);
		let charlie_pk = PublicKey::from_secret_key(&secp_ctx, &charlie.get_node_secret_key());

		let (session_priv, total_amt_msat, cur_height, recipient_onion, preimage, payment_hash,
			prng_seed, hops, recipient_amount, pay_secret) = payment_onion_args(bob_pk, charlie_pk);

		let path = Path {
			hops: hops,
			blinded_tail: None,
		};

		let (onion, amount_msat, cltv_expiry) = create_payment_onion(
			&secp_ctx, &path, &session_priv, total_amt_msat, &recipient_onion,
			cur_height, &payment_hash, &Some(preimage), None, prng_seed
		).unwrap();

		let msg = make_update_add_msg(amount_msat, cltv_expiry, payment_hash, onion);
		let logger = test_utils::TestLogger::with_id("bob".to_string());

		let peeled = peel_payment_onion(&msg, &bob, &logger, &secp_ctx, cur_height, false)
			.map_err(|e| e.msg).unwrap();

		let next_onion = match peeled.routing {
			PendingHTLCRouting::Forward { onion_packet, .. } => {
				onion_packet
			},
			_ => panic!("expected a forwarded onion"),
		};

		let msg2 = make_update_add_msg(amount_msat, cltv_expiry, payment_hash, next_onion);
		let peeled2 = peel_payment_onion(&msg2, &charlie, &logger, &secp_ctx, cur_height, false)
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
		onion_routing_packet: msgs::OnionPacket,
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
			hold_htlc: None,
			accountable: None,
		}
	}

	#[rustfmt::skip]
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
				cltv_expiry_delta: MIN_CLTV_EXPIRY_DELTA as u32,
				short_channel_id: 1,
				node_features: NodeFeatures::empty(),
				channel_features: ChannelFeatures::empty(),
				maybe_announced_channel: false,
			},
			RouteHop {
				pubkey: recipient_pk,
				fee_msat: recipient_amount,
				cltv_expiry_delta: TEST_FINAL_CLTV,
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
