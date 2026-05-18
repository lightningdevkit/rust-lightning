// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Tests for trampoline MPP accumulation and forwarding validation in
//! [`ChannelManager::handle_trampoline_htlc`].

use crate::chain::transaction::OutPoint;
use crate::events::HTLCHandlingFailureReason;
use crate::ln::channelmanager::{HTLCPreviousHopData, MppPart};
use crate::ln::functional_test_utils::*;
use crate::ln::msgs;
use crate::ln::onion_utils::LocalHTLCFailureReason;
use crate::ln::outbound_payment::{NextTrampolineHopInfo, RecipientOnionFields};
use crate::ln::types::ChannelId;
use crate::types::payment::{PaymentHash, PaymentSecret};

use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};

fn test_prev_hop_data(htlc_id: u64) -> HTLCPreviousHopData {
	HTLCPreviousHopData {
		prev_outbound_scid_alias: 0,
		user_channel_id: None,
		htlc_id,
		incoming_packet_shared_secret: [0; 32],
		phantom_shared_secret: None,
		trampoline_shared_secret: Some([0; 32]),
		blinded_failure: None,
		channel_id: ChannelId::from_bytes([0; 32]),
		outpoint: OutPoint { txid: bitcoin::Txid::all_zeros(), index: 0 },
		counterparty_node_id: None,
		cltv_expiry: None,
	}
}

fn test_trampoline_onion_packet() -> msgs::TrampolineOnionPacket {
	let secp = Secp256k1::new();
	let test_secret = SecretKey::from_slice(&[42; 32]).unwrap();
	msgs::TrampolineOnionPacket {
		version: 0,
		public_key: PublicKey::from_secret_key(&secp, &test_secret),
		hop_data: vec![0; 650],
		hmac: [0; 32],
	}
}

fn test_onion_fields(total_msat: u64) -> RecipientOnionFields {
	RecipientOnionFields {
		payment_secret: Some(PaymentSecret([0; 32])),
		total_mpp_amount_msat: total_msat,
		payment_metadata: None,
		custom_tlvs: Vec::new(),
	}
}

enum TrampolineMppValidationTestCase {
	FeeInsufficient,
	CltvInsufficient,
	TrampolineAmountExceedsReceived,
	TrampolineCLTVExceedsReceived,
	MismatchedPaymentSecret,
}

/// Sends two MPP parts through [`ChannelManager::handle_trampoline_htlc`], testing various MPP
/// validation steps with a base case that succeeds.
fn do_test_trampoline_mpp_validation(test_case: Option<TrampolineMppValidationTestCase>) {
	let update_add_value: u64 = 500_000; // Actual amount we received in update_add_htlc.
	let update_add_cltv: u32 = 500; // Actual CLTV we received in update_add_htlc.
	let sender_intended_incoming_value: u64 = 500_000; // Amount we expect for one HTLC, outer onion.
	let incoming_mpp_total: u64 = 1_000_000; // Total we expect to receive across MPP parts, outer onion.
	let mut next_trampoline_amount: u64 = 750_000; // Total next trampoline expects, inner onion.
	let mut next_trampoline_cltv: u32 = 100; // CLTV next trampoline expects, inner onion.

	// By default, set our forwarding fee and CLTV delta to exactly what we're being offered
	// for this trampoline forward, so that we can force failures by just adding one.
	let mut forwarding_fee_base_msat = incoming_mpp_total - next_trampoline_amount;
	let mut cltv_delta = update_add_cltv - next_trampoline_cltv;
	let mut mismatch_payment_secret = false;

	let expected = match test_case {
		Some(TrampolineMppValidationTestCase::FeeInsufficient) => {
			forwarding_fee_base_msat += 1;
			LocalHTLCFailureReason::TrampolineFeeOrExpiryInsufficient
		},
		Some(TrampolineMppValidationTestCase::CltvInsufficient) => {
			cltv_delta += 1;
			LocalHTLCFailureReason::TrampolineFeeOrExpiryInsufficient
		},
		Some(TrampolineMppValidationTestCase::TrampolineAmountExceedsReceived) => {
			next_trampoline_amount = incoming_mpp_total + 1;
			LocalHTLCFailureReason::TrampolineFeeOrExpiryInsufficient
		},
		Some(TrampolineMppValidationTestCase::TrampolineCLTVExceedsReceived) => {
			next_trampoline_cltv = update_add_cltv + 1;
			LocalHTLCFailureReason::TrampolineFeeOrExpiryInsufficient
		},
		Some(TrampolineMppValidationTestCase::MismatchedPaymentSecret) => {
			mismatch_payment_secret = true;
			LocalHTLCFailureReason::InvalidTrampolineForward
		},
		// We can't route to the next trampoline as they're unknown.
		None => LocalHTLCFailureReason::TemporaryTrampolineFailure,
	};

	let chanmon_cfgs = create_chanmon_cfgs(1);
	let node_cfgs = create_node_cfgs(1, &chanmon_cfgs);
	let mut cfg = test_default_channel_config();
	cfg.channel_config.forwarding_fee_base_msat = forwarding_fee_base_msat as u32;
	cfg.channel_config.forwarding_fee_proportional_millionths = 0;
	cfg.channel_config.cltv_expiry_delta = cltv_delta as u16;
	let node_chanmgrs = create_node_chanmgrs(1, &node_cfgs, &[Some(cfg)]);
	let nodes = create_network(1, &node_cfgs, &node_chanmgrs);

	let payment_hash = PaymentHash([1; 32]);

	let secp = Secp256k1::new();
	let test_secret = SecretKey::from_slice(&[2; 32]).unwrap();
	let next_trampoline = PublicKey::from_secret_key(&secp, &test_secret);
	let next_hop_info = NextTrampolineHopInfo {
		onion_packet: test_trampoline_onion_packet(),
		blinding_point: None,
		amount_msat: next_trampoline_amount,
		cltv_expiry_height: next_trampoline_cltv,
	};

	let htlc1 = MppPart::new(
		test_prev_hop_data(0),
		update_add_value,
		sender_intended_incoming_value,
		update_add_cltv,
	);
	assert!(nodes[0]
		.node
		.test_handle_trampoline_htlc(
			htlc1,
			test_onion_fields(incoming_mpp_total),
			payment_hash,
			next_hop_info.clone(),
			next_trampoline,
		)
		.is_ok());

	let htlc2 = MppPart::new(
		test_prev_hop_data(1),
		update_add_value,
		sender_intended_incoming_value,
		update_add_cltv,
	);
	let onion2 = if mismatch_payment_secret {
		RecipientOnionFields {
			payment_secret: Some(PaymentSecret([1; 32])),
			total_mpp_amount_msat: incoming_mpp_total,
			payment_metadata: None,
			custom_tlvs: Vec::new(),
		}
	} else {
		test_onion_fields(incoming_mpp_total)
	};
	let result = nodes[0].node.test_handle_trampoline_htlc(
		htlc2,
		onion2,
		payment_hash,
		next_hop_info,
		next_trampoline,
	);

	assert_eq!(
		HTLCHandlingFailureReason::from(&result.expect_err("expect trampoline failure").1),
		HTLCHandlingFailureReason::Local { reason: expected },
	);
}

#[test]
fn test_trampoline_mpp_validation() {
	do_test_trampoline_mpp_validation(Some(TrampolineMppValidationTestCase::FeeInsufficient));
	do_test_trampoline_mpp_validation(Some(TrampolineMppValidationTestCase::CltvInsufficient));
	do_test_trampoline_mpp_validation(Some(
		TrampolineMppValidationTestCase::TrampolineAmountExceedsReceived,
	));
	do_test_trampoline_mpp_validation(Some(
		TrampolineMppValidationTestCase::TrampolineCLTVExceedsReceived,
	));
	do_test_trampoline_mpp_validation(Some(
		TrampolineMppValidationTestCase::MismatchedPaymentSecret,
	));
	do_test_trampoline_mpp_validation(None);
}
