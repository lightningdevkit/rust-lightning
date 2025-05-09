// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Tests that test the creation of dual-funded channels in ChannelManager.

use {
	crate::{
		chain::chaininterface::{ConfirmationTarget, LowerBoundedFeeEstimator},
		events::{Event, InboundChannelFunds},
		ln::{
			chan_utils::{
				make_funding_redeemscript, ChannelPublicKeys, ChannelTransactionParameters,
				CounterpartyChannelTransactionParameters,
			},
			channel::PendingV2Channel,
			channel_keys::{DelayedPaymentBasepoint, HtlcBasepoint, RevocationBasepoint},
			functional_test_utils::*,
			funding::FundingTxInput,
			msgs::{
				BaseMessageHandler, ChannelMessageHandler, CommitmentSigned, MessageSendEvent,
				TxAddInput, TxAddOutput, TxComplete, TxSignatures,
			},
			types::ChannelId,
		},
		prelude::*,
		util::test_utils,
	},
	bitcoin::{
		hashes::Hash,
		key::{constants::SECRET_KEY_SIZE, Keypair, Secp256k1},
		secp256k1::Message,
		sighash::SighashCache,
		Amount, Witness,
	},
};

// Dual-funding: V2 Channel Establishment Tests
struct V2ChannelEstablishmentTestSession {
	initiator_funding_satoshis: u64,
	initiator_input_value_satoshis: u64,
	acceptor_funding_satoshis: u64,
	acceptor_input_value_satoshis: u64,
}

// TODO(dual_funding): Use real node and API for creating V2 channels as initiator when available,
// instead of manually constructing messages.
fn do_test_v2_channel_establishment(session: V2ChannelEstablishmentTestSession) {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let mut node_1_user_config = test_default_channel_config();
	node_1_user_config.enable_dual_funded_channels = true;
	node_1_user_config.manually_accept_inbound_channels = true;
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, Some(node_1_user_config)]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let logger_a = test_utils::TestLogger::with_id("node a".to_owned());

	let secp_ctx = Secp256k1::new();
	let initiator_external_keypair =
		Keypair::from_seckey_slice(&secp_ctx, &[2; SECRET_KEY_SIZE]).unwrap();
	let acceptor_external_keypair =
		Keypair::from_seckey_slice(&secp_ctx, &[3; SECRET_KEY_SIZE]).unwrap();

	// Create initiator funding input for the new channel along with its previous transaction.
	let initiator_funding_inputs: Vec<_> = create_dual_funding_utxos_with_prev_txs(
		&nodes[0],
		&[session.initiator_input_value_satoshis],
		&initiator_external_keypair.public_key(),
	);

	dbg!(&initiator_funding_inputs[0].utxo.output);

	// Create acceptor funding input for the new channel along with its previous transaction.
	let acceptor_funding_inputs: Vec<_> = if session.acceptor_input_value_satoshis == 0 {
		vec![]
	} else {
		create_dual_funding_utxos_with_prev_txs(
			&nodes[1],
			&[session.acceptor_input_value_satoshis],
			&acceptor_external_keypair.public_key(),
		)
	};
	if !acceptor_funding_inputs.is_empty() {
		dbg!(&acceptor_funding_inputs[0].utxo.output);
	}
	let acceptor_funding_inputs_count = acceptor_funding_inputs.len();

	// Alice creates a dual-funded channel as initiator.
	let initiator_funding_satoshis = session.initiator_funding_satoshis;
	let mut channel = PendingV2Channel::new_outbound(
		&LowerBoundedFeeEstimator(node_cfgs[0].fee_estimator),
		&nodes[0].node.entropy_source,
		&nodes[0].node.signer_provider,
		nodes[1].node.get_our_node_id(),
		&nodes[1].node.init_features(),
		initiator_funding_satoshis,
		initiator_funding_inputs.clone(),
		42, /* user_channel_id */
		&nodes[0].node.get_current_config(),
		nodes[0].best_block_info().1,
		nodes[0].node.create_and_insert_outbound_scid_alias_for_test(),
		ConfirmationTarget::NonAnchorChannelFee,
		&logger_a,
	)
	.unwrap();
	let open_channel_v2_msg = channel.get_open_channel_v2(nodes[0].chain_source.chain_hash);

	nodes[1].node.handle_open_channel_v2(nodes[0].node.get_our_node_id(), &open_channel_v2_msg);

	let events = nodes[1].node.get_and_clear_pending_events();
	let accept_channel_v2_msg = match &events[0] {
		Event::OpenChannelRequest {
			temporary_channel_id,
			counterparty_node_id,
			channel_negotiation_type,
			..
		} => {
			assert!(matches!(channel_negotiation_type, &InboundChannelFunds::DualFunded));
			nodes[1]
				.node
				.accept_inbound_channel_with_contribution(
					temporary_channel_id,
					counterparty_node_id,
					u128::MAX - 2,
					None,
					Amount::from_sat(session.acceptor_funding_satoshis),
					acceptor_funding_inputs.clone(),
					None,
				)
				.unwrap();
			get_event_msg!(
				nodes[1],
				MessageSendEvent::SendAcceptChannelV2,
				nodes[0].node.get_our_node_id()
			)
		},
		_ => panic!("Unexpected event"),
	};

	let channel_id = ChannelId::v2_from_revocation_basepoints(
		&RevocationBasepoint::from(accept_channel_v2_msg.common_fields.revocation_basepoint),
		&RevocationBasepoint::from(open_channel_v2_msg.common_fields.revocation_basepoint),
	);

	let FundingTxInput { sequence, prevtx, .. } = &initiator_funding_inputs[0];
	let tx_add_input_msg = TxAddInput {
		channel_id,
		serial_id: 2, // Even serial_id from initiator.
		prevtx: Some(prevtx.clone()),
		prevtx_out: 0,
		sequence: sequence.0,
		shared_input_txid: None,
	};
	let input_value = tx_add_input_msg.prevtx.as_ref().unwrap().output
		[tx_add_input_msg.prevtx_out as usize]
		.value;
	assert_eq!(input_value.to_sat(), session.initiator_input_value_satoshis);

	nodes[1].node.handle_tx_add_input(nodes[0].node.get_our_node_id(), &tx_add_input_msg);

	if acceptor_funding_inputs_count > 0 {
		let _tx_add_input_msg = get_event_msg!(
			nodes[1],
			MessageSendEvent::SendTxAddInput,
			nodes[0].node.get_our_node_id()
		);
	} else {
		let _tx_complete_msg = get_event_msg!(
			nodes[1],
			MessageSendEvent::SendTxComplete,
			nodes[0].node.get_our_node_id()
		);
	}

	let tx_add_output_msg = TxAddOutput {
		channel_id,
		serial_id: 4,
		sats: initiator_funding_satoshis.saturating_add(session.acceptor_funding_satoshis),
		script: make_funding_redeemscript(
			&open_channel_v2_msg.common_fields.funding_pubkey,
			&accept_channel_v2_msg.common_fields.funding_pubkey,
		)
		.to_p2wsh(),
	};
	nodes[1].node.handle_tx_add_output(nodes[0].node.get_our_node_id(), &tx_add_output_msg);

	let acceptor_change_value_satoshis =
		session.initiator_input_value_satoshis.saturating_sub(session.initiator_funding_satoshis);
	if acceptor_funding_inputs_count > 0
		&& acceptor_change_value_satoshis > accept_channel_v2_msg.common_fields.dust_limit_satoshis
	{
		println!("Change: {acceptor_change_value_satoshis} satoshis");
		let _tx_add_output_msg = get_event_msg!(
			nodes[1],
			MessageSendEvent::SendTxAddOutput,
			nodes[0].node.get_our_node_id()
		);
	} else {
		let _tx_complete_msg = get_event_msg!(
			nodes[1],
			MessageSendEvent::SendTxComplete,
			nodes[0].node.get_our_node_id()
		);
	}

	let tx_complete_msg = TxComplete { channel_id };

	nodes[1].node.handle_tx_complete(nodes[0].node.get_our_node_id(), &tx_complete_msg);
	let msg_events = nodes[1].node.get_and_clear_pending_msg_events();
	let update_htlcs_msg_event = if acceptor_funding_inputs_count > 0 {
		assert_eq!(msg_events.len(), 2);
		match msg_events[0] {
			MessageSendEvent::SendTxComplete { ref node_id, .. } => {
				assert_eq!(*node_id, nodes[0].node.get_our_node_id());
			},
			_ => panic!("Unexpected event"),
		};
		&msg_events[1]
	} else {
		assert_eq!(msg_events.len(), 1);
		&msg_events[0]
	};
	let _msg_commitment_signed_from_1 = match update_htlcs_msg_event {
		MessageSendEvent::UpdateHTLCs { node_id, channel_id: _, updates } => {
			assert_eq!(*node_id, nodes[0].node.get_our_node_id());
			updates.commitment_signed.clone()
		},
		_ => panic!("Unexpected event"),
	};

	let (funding_outpoint, channel_type_features) = {
		let per_peer_state = nodes[1].node.per_peer_state.read().unwrap();
		let peer_state =
			per_peer_state.get(&nodes[0].node.get_our_node_id()).unwrap().lock().unwrap();
		let channel_funding =
			peer_state.channel_by_id.get(&tx_complete_msg.channel_id).unwrap().funding();
		(channel_funding.get_funding_txo(), channel_funding.get_channel_type().clone())
	};

	channel.funding.channel_transaction_parameters = ChannelTransactionParameters {
		counterparty_parameters: Some(CounterpartyChannelTransactionParameters {
			pubkeys: ChannelPublicKeys {
				funding_pubkey: accept_channel_v2_msg.common_fields.funding_pubkey,
				revocation_basepoint: RevocationBasepoint(
					accept_channel_v2_msg.common_fields.revocation_basepoint,
				),
				payment_point: accept_channel_v2_msg.common_fields.payment_basepoint,
				delayed_payment_basepoint: DelayedPaymentBasepoint(
					accept_channel_v2_msg.common_fields.delayed_payment_basepoint,
				),
				htlc_basepoint: HtlcBasepoint(accept_channel_v2_msg.common_fields.htlc_basepoint),
			},
			selected_contest_delay: accept_channel_v2_msg.common_fields.to_self_delay,
		}),
		holder_pubkeys: ChannelPublicKeys {
			funding_pubkey: open_channel_v2_msg.common_fields.funding_pubkey,
			revocation_basepoint: RevocationBasepoint(
				open_channel_v2_msg.common_fields.revocation_basepoint,
			),
			payment_point: open_channel_v2_msg.common_fields.payment_basepoint,
			delayed_payment_basepoint: DelayedPaymentBasepoint(
				open_channel_v2_msg.common_fields.delayed_payment_basepoint,
			),
			htlc_basepoint: HtlcBasepoint(open_channel_v2_msg.common_fields.htlc_basepoint),
		},
		holder_selected_contest_delay: open_channel_v2_msg.common_fields.to_self_delay,
		is_outbound_from_holder: true,
		funding_outpoint,
		splice_parent_funding_txid: None,
		channel_type_features,
		channel_value_satoshis: initiator_funding_satoshis
			.saturating_add(session.acceptor_funding_satoshis),
	};

	let (signature, htlc_signatures) = channel
		.context
		.get_initial_counterparty_commitment_signatures_for_test(
			&mut channel.funding,
			&&logger_a,
			accept_channel_v2_msg.common_fields.first_per_commitment_point,
		)
		.unwrap();

	let msg_commitment_signed_from_0 = CommitmentSigned {
		channel_id,
		signature,
		htlc_signatures,
		funding_txid: None,
		#[cfg(taproot)]
		partial_signature_with_nonce: None,
	};

	chanmon_cfgs[1].persister.set_update_ret(crate::chain::ChannelMonitorUpdateStatus::InProgress);

	// Handle the initial commitment_signed exchange. Order is not important here.
	nodes[1]
		.node
		.handle_commitment_signed(nodes[0].node.get_our_node_id(), &msg_commitment_signed_from_0);
	check_added_monitors(&nodes[1], 1);

	// The funding transaction should not have been broadcast before persisting initial monitor has
	// been completed.
	assert_eq!(nodes[1].tx_broadcaster.txn_broadcast().len(), 0);

	// Complete the persistence of the monitor.
	let events = nodes[1].node.get_and_clear_pending_events();
	assert!(events.is_empty());
	nodes[1].chain_monitor.complete_sole_pending_chan_update(&channel_id);

	if acceptor_funding_inputs_count > 0 {
		let events = nodes[1].node.get_and_clear_pending_events();
		match &events[0] {
			Event::FundingTransactionReadyForSigning {
				counterparty_node_id,
				unsigned_transaction,
				..
			} => {
				assert_eq!(counterparty_node_id, &nodes[0].node.get_our_node_id());
				let mut transaction = unsigned_transaction.clone();
				let mut sighash_cache = SighashCache::new(unsigned_transaction);
				for (idx, input) in transaction.input.iter_mut().enumerate() {
					if input.previous_output.txid == acceptor_funding_inputs[0].utxo.outpoint.txid {
						let sighash = sighash_cache
							.p2wpkh_signature_hash(
								idx,
								&acceptor_funding_inputs[0].utxo.output.script_pubkey,
								acceptor_funding_inputs[0].utxo.output.value,
								bitcoin::EcdsaSighashType::All,
							)
							.unwrap();
						let msg = Message::from_digest(sighash.as_raw_hash().to_byte_array());

						let signature =
							secp_ctx.sign_ecdsa(&msg, &acceptor_external_keypair.secret_key());
						let mut witness = Witness::p2wpkh(
							&bitcoin::ecdsa::Signature::sighash_all(signature),
							&acceptor_external_keypair.public_key(),
						);
						input.witness = witness;
					}
				}
				nodes[1]
					.node
					.funding_transaction_signed(&channel_id, counterparty_node_id, transaction)
					.unwrap();
			},
			_ => panic!("Unexpected event"),
		};
	}

	if session.acceptor_input_value_satoshis < session.initiator_input_value_satoshis {
		let tx_signatures_msg = get_event_msg!(
			nodes[1],
			MessageSendEvent::SendTxSignatures,
			nodes[0].node.get_our_node_id()
		);

		assert_eq!(tx_signatures_msg.channel_id, channel_id);

		let mut witness = Witness::new();
		witness.push([0x0]);
		// Receive tx_signatures from channel initiator.
		nodes[1].node.handle_tx_signatures(
			nodes[0].node.get_our_node_id(),
			&TxSignatures {
				channel_id,
				tx_hash: funding_outpoint.unwrap().txid,
				witnesses: vec![witness],
				shared_input_signature: None,
			},
		);
	} else {
		let mut witness = Witness::new();
		witness.push([0x0]);
		// Receive tx_signatures from channel initiator.
		nodes[1].node.handle_tx_signatures(
			nodes[0].node.get_our_node_id(),
			&TxSignatures {
				channel_id,
				tx_hash: funding_outpoint.unwrap().txid,
				witnesses: vec![witness],
				shared_input_signature: None,
			},
		);

		let tx_signatures_msg = get_event_msg!(
			nodes[1],
			MessageSendEvent::SendTxSignatures,
			nodes[0].node.get_our_node_id()
		);

		assert_eq!(tx_signatures_msg.channel_id, channel_id);
	}

	let events = nodes[1].node.get_and_clear_pending_events();
	if acceptor_funding_inputs_count == 0 {
		assert_eq!(events.len(), 1);
		match events[0] {
			Event::ChannelPending { channel_id: chan_id, .. } => assert_eq!(chan_id, channel_id),
			_ => panic!("Unexpected event"),
		};
	}

	// For an inbound channel V2 channel the transaction should be broadcast once receiving a
	// tx_signature and applying local tx_signatures:
	let broadcasted_txs = nodes[1].tx_broadcaster.txn_broadcast();
	assert_eq!(broadcasted_txs.len(), 1);
}

#[test]
fn test_v2_channel_establishment() {
	// Initiator contributes inputs, acceptor does not.
	do_test_v2_channel_establishment(V2ChannelEstablishmentTestSession {
		initiator_funding_satoshis: 100_00,
		initiator_input_value_satoshis: 150_000,
		acceptor_funding_satoshis: 0,
		acceptor_input_value_satoshis: 0,
	});
	// Initiator contributes more input value than acceptor.
	do_test_v2_channel_establishment(V2ChannelEstablishmentTestSession {
		initiator_funding_satoshis: 100_00,
		initiator_input_value_satoshis: 150_000,
		acceptor_funding_satoshis: 50_00,
		acceptor_input_value_satoshis: 100_000,
	});
	// Initiator contributes less input value than acceptor.
	do_test_v2_channel_establishment(V2ChannelEstablishmentTestSession {
		initiator_funding_satoshis: 100_00,
		initiator_input_value_satoshis: 150_000,
		acceptor_funding_satoshis: 125_00,
		acceptor_input_value_satoshis: 200_000,
	});
	// Initiator contributes the same input value as acceptor.
	// nodes[0] node_id: 88ce8f35acfc...
	// nodes[1] node_id: 236cdaa42692...
	// Since nodes[1] has a node_id in earlier lexicographical order, it should send tx_signatures first.
	do_test_v2_channel_establishment(V2ChannelEstablishmentTestSession {
		initiator_funding_satoshis: 100_00,
		initiator_input_value_satoshis: 150_000,
		acceptor_funding_satoshis: 125_00,
		acceptor_input_value_satoshis: 150_000,
	});
}
