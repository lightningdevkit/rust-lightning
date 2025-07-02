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
	crate::chain::chaininterface::{ConfirmationTarget, LowerBoundedFeeEstimator},
	crate::events::Event,
	crate::ln::chan_utils::{
		make_funding_redeemscript, ChannelPublicKeys, ChannelTransactionParameters,
		CounterpartyChannelTransactionParameters,
	},
	crate::ln::channel::PendingV2Channel,
	crate::ln::channel_keys::{DelayedPaymentBasepoint, HtlcBasepoint, RevocationBasepoint},
	crate::ln::functional_test_utils::*,
	crate::ln::msgs::{BaseMessageHandler, ChannelMessageHandler, MessageSendEvent},
	crate::ln::msgs::{CommitmentSigned, TxAddInput, TxAddOutput, TxComplete, TxSignatures},
	crate::ln::types::ChannelId,
	crate::prelude::*,
	crate::util::ser::TransactionU16LenLimited,
	crate::util::test_utils,
	bitcoin::Witness,
};

// Dual-funding: V2 Channel Establishment Tests
struct V2ChannelEstablishmentTestSession {
	funding_input_sats: u64,
	initiator_input_value_satoshis: u64,
}

// TODO(dual_funding): Use real node and API for creating V2 channels as initiator when available,
// instead of manually constructing messages.
fn do_test_v2_channel_establishment(session: V2ChannelEstablishmentTestSession) {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let mut node_1_user_config = test_default_channel_config();
	node_1_user_config.enable_dual_funded_channels = true;
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, Some(node_1_user_config)]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let logger_a = test_utils::TestLogger::with_id("node a".to_owned());

	// Create a funding input for the new channel along with its previous transaction.
	let initiator_funding_inputs: Vec<_> = create_dual_funding_utxos_with_prev_txs(
		&nodes[0],
		&[session.initiator_input_value_satoshis],
	)
	.into_iter()
	.map(|(txin, tx, _)| (txin, TransactionU16LenLimited::new(tx).unwrap()))
	.collect();

	// Alice creates a dual-funded channel as initiator.
	let funding_satoshis = session.funding_input_sats;
	let mut channel = PendingV2Channel::new_outbound(
		&LowerBoundedFeeEstimator(node_cfgs[0].fee_estimator),
		&nodes[0].node.entropy_source,
		&nodes[0].node.signer_provider,
		nodes[1].node.get_our_node_id(),
		&nodes[1].node.init_features(),
		funding_satoshis,
		initiator_funding_inputs.clone(),
		42, /* user_channel_id */
		nodes[0].node.get_current_default_configuration(),
		nodes[0].best_block_info().1,
		nodes[0].node.create_and_insert_outbound_scid_alias_for_test(),
		ConfirmationTarget::NonAnchorChannelFee,
		&logger_a,
	)
	.unwrap();
	let open_channel_v2_msg = channel.get_open_channel_v2(nodes[0].chain_source.chain_hash);

	nodes[1].node.handle_open_channel_v2(nodes[0].node.get_our_node_id(), &open_channel_v2_msg);

	let accept_channel_v2_msg = get_event_msg!(
		nodes[1],
		MessageSendEvent::SendAcceptChannelV2,
		nodes[0].node.get_our_node_id()
	);
	let channel_id = ChannelId::v2_from_revocation_basepoints(
		&RevocationBasepoint::from(accept_channel_v2_msg.common_fields.revocation_basepoint),
		&RevocationBasepoint::from(open_channel_v2_msg.common_fields.revocation_basepoint),
	);

	let tx_add_input_msg = TxAddInput {
		channel_id,
		serial_id: 2, // Even serial_id from initiator.
		prevtx: Some(initiator_funding_inputs[0].1.clone()),
		prevtx_out: 0,
		sequence: initiator_funding_inputs[0].0.sequence.0,
		shared_input_txid: None,
	};
	let input_value = tx_add_input_msg.prevtx.as_ref().unwrap().as_transaction().output
		[tx_add_input_msg.prevtx_out as usize]
		.value;
	assert_eq!(input_value.to_sat(), session.initiator_input_value_satoshis);

	nodes[1].node.handle_tx_add_input(nodes[0].node.get_our_node_id(), &tx_add_input_msg);

	let _tx_complete_msg =
		get_event_msg!(nodes[1], MessageSendEvent::SendTxComplete, nodes[0].node.get_our_node_id());

	let tx_add_output_msg = TxAddOutput {
		channel_id,
		serial_id: 4,
		sats: funding_satoshis,
		script: make_funding_redeemscript(
			&open_channel_v2_msg.common_fields.funding_pubkey,
			&accept_channel_v2_msg.common_fields.funding_pubkey,
		)
		.to_p2wsh(),
	};
	nodes[1].node.handle_tx_add_output(nodes[0].node.get_our_node_id(), &tx_add_output_msg);

	let _tx_complete_msg =
		get_event_msg!(nodes[1], MessageSendEvent::SendTxComplete, nodes[0].node.get_our_node_id());

	let tx_complete_msg = TxComplete { channel_id };

	nodes[1].node.handle_tx_complete(nodes[0].node.get_our_node_id(), &tx_complete_msg);
	let msg_events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(msg_events.len(), 1);
	let _msg_commitment_signed_from_1 = match msg_events[0] {
		MessageSendEvent::UpdateHTLCs { ref node_id, channel_id: _, ref updates } => {
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
		channel_value_satoshis: funding_satoshis,
	};

	let msg_commitment_signed_from_0 = CommitmentSigned {
		channel_id,
		signature: channel
			.context
			.get_initial_counterparty_commitment_signature_for_test(
				&mut channel.funding,
				&&logger_a,
				accept_channel_v2_msg.common_fields.first_per_commitment_point,
			)
			.unwrap(),
		htlc_signatures: vec![],
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
	assert_eq!(nodes[1].node.get_and_clear_pending_events().len(), 0);

	// Complete the persistence of the monitor.
	let events = nodes[1].node.get_and_clear_pending_events();
	assert!(events.is_empty());
	nodes[1].chain_monitor.complete_sole_pending_chan_update(&channel_id);

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

	let events = nodes[1].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		Event::ChannelPending { channel_id: chan_id, .. } => assert_eq!(chan_id, channel_id),
		_ => panic!("Unexpected event"),
	};

	// For an inbound channel V2 channel the transaction should be broadcast once receiving a
	// tx_signature and applying local tx_signatures:
	let broadcasted_txs = nodes[1].tx_broadcaster.txn_broadcast();
	assert_eq!(broadcasted_txs.len(), 1);
}

#[test]
fn test_v2_channel_establishment() {
	do_test_v2_channel_establishment(V2ChannelEstablishmentTestSession {
		funding_input_sats: 100_00,
		initiator_input_value_satoshis: 150_000,
	});
}
