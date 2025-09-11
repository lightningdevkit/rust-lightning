// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

use crate::chain::chaininterface::FEERATE_FLOOR_SATS_PER_KW;
use crate::chain::channelmonitor::{ANTI_REORG_DELAY, LATENCY_GRACE_PERIOD_BLOCKS};
use crate::events::bump_transaction::sync::WalletSourceSync;
use crate::events::{ClosureReason, Event, HTLCHandlingFailureType};
use crate::ln::chan_utils;
use crate::ln::functional_test_utils::*;
use crate::ln::funding::{FundingTxInput, SpliceContribution};
use crate::ln::msgs::{self, BaseMessageHandler, ChannelMessageHandler, MessageSendEvent};
use crate::ln::types::ChannelId;
use crate::util::errors::APIError;

use bitcoin::{Amount, OutPoint as BitcoinOutPoint, ScriptBuf, Transaction, TxOut};

#[test]
fn test_v1_splice_in_negative_insufficient_inputs() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let (_, _, channel_id, _) =
		create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100_000, 0);

	// Amount being added to the channel through the splice-in
	let splice_in_sats = 20_000;

	// Create additional inputs, but insufficient
	let extra_splice_funding_input_sats = splice_in_sats - 1;
	let funding_inputs =
		create_dual_funding_utxos_with_prev_txs(&nodes[0], &[extra_splice_funding_input_sats]);

	let contribution = SpliceContribution::SpliceIn {
		value: Amount::from_sat(splice_in_sats),
		inputs: funding_inputs,
		change_script: None,
	};

	// Initiate splice-in, with insufficient input contribution
	let res = nodes[0].node.splice_channel(
		&channel_id,
		&nodes[1].node.get_our_node_id(),
		contribution,
		1024, // funding_feerate_per_kw,
		None, // locktime
	);
	match res {
		Err(APIError::APIMisuseError { err }) => {
			assert!(err.contains("Need more inputs"))
		},
		_ => panic!("Wrong error {:?}", res.err().unwrap()),
	}
}

fn complete_interactive_funding_negotiation<'a, 'b, 'c, 'd>(
	initiator: &'a Node<'b, 'c, 'd>, acceptor: &'a Node<'b, 'c, 'd>, channel_id: ChannelId,
	initiator_contribution: SpliceContribution, new_funding_script: ScriptBuf,
) -> msgs::CommitmentSigned {
	let node_id_initiator = initiator.node.get_our_node_id();
	let node_id_acceptor = acceptor.node.get_our_node_id();

	let funding_outpoint = initiator
		.node
		.list_channels()
		.iter()
		.find(|channel| {
			channel.counterparty.node_id == node_id_acceptor && channel.channel_id == channel_id
		})
		.map(|channel| channel.funding_txo.unwrap())
		.unwrap();
	let (initiator_inputs, initiator_outputs, initiator_change_script) =
		initiator_contribution.into_tx_parts();
	let mut expected_initiator_inputs = initiator_inputs
		.iter()
		.map(|input| input.utxo.outpoint)
		.chain(core::iter::once(funding_outpoint.into_bitcoin_outpoint()))
		.collect::<Vec<_>>();
	let mut expected_initiator_scripts = initiator_outputs
		.into_iter()
		.map(|output| output.script_pubkey)
		.chain(core::iter::once(new_funding_script))
		.chain(initiator_change_script.into_iter())
		.collect::<Vec<_>>();

	let mut acceptor_sent_tx_complete = false;
	loop {
		if !expected_initiator_inputs.is_empty() {
			let tx_add_input =
				get_event_msg!(initiator, MessageSendEvent::SendTxAddInput, node_id_acceptor);
			let input_prevout = BitcoinOutPoint {
				txid: tx_add_input
					.prevtx
					.as_ref()
					.map(|prevtx| prevtx.compute_txid())
					.or(tx_add_input.shared_input_txid)
					.unwrap(),
				vout: tx_add_input.prevtx_out,
			};
			expected_initiator_inputs.remove(
				expected_initiator_inputs.iter().position(|input| *input == input_prevout).unwrap(),
			);
			acceptor.node.handle_tx_add_input(node_id_initiator, &tx_add_input);
		} else if !expected_initiator_scripts.is_empty() {
			let tx_add_output =
				get_event_msg!(initiator, MessageSendEvent::SendTxAddOutput, node_id_acceptor);
			expected_initiator_scripts.remove(
				expected_initiator_scripts
					.iter()
					.position(|script| *script == tx_add_output.script)
					.unwrap(),
			);
			acceptor.node.handle_tx_add_output(node_id_initiator, &tx_add_output);
		} else {
			let mut msg_events = initiator.node.get_and_clear_pending_msg_events();
			assert_eq!(
				msg_events.len(),
				if acceptor_sent_tx_complete { 2 } else { 1 },
				"{msg_events:?}"
			);
			if let MessageSendEvent::SendTxComplete { ref msg, .. } = msg_events.remove(0) {
				acceptor.node.handle_tx_complete(node_id_initiator, msg);
			} else {
				panic!();
			}
			if acceptor_sent_tx_complete {
				if let MessageSendEvent::UpdateHTLCs { mut updates, .. } = msg_events.remove(0) {
					return updates.commitment_signed.remove(0);
				}
				panic!();
			}
		}

		let mut msg_events = acceptor.node.get_and_clear_pending_msg_events();
		assert_eq!(msg_events.len(), 1, "{msg_events:?}");
		if let MessageSendEvent::SendTxComplete { ref msg, .. } = msg_events.remove(0) {
			initiator.node.handle_tx_complete(node_id_acceptor, msg);
		} else {
			panic!();
		}
		acceptor_sent_tx_complete = true;
	}
}

fn sign_interactive_funding_transaction<'a, 'b, 'c, 'd>(
	initiator: &'a Node<'b, 'c, 'd>, acceptor: &'a Node<'b, 'c, 'd>,
	initial_commit_sig_for_acceptor: msgs::CommitmentSigned,
) {
	let node_id_initiator = initiator.node.get_our_node_id();
	let node_id_acceptor = acceptor.node.get_our_node_id();

	assert!(initiator.node.get_and_clear_pending_msg_events().is_empty());
	acceptor.node.handle_commitment_signed(node_id_initiator, &initial_commit_sig_for_acceptor);

	let mut msg_events = acceptor.node.get_and_clear_pending_msg_events();
	assert_eq!(msg_events.len(), 2, "{msg_events:?}");
	if let MessageSendEvent::UpdateHTLCs { mut updates, .. } = msg_events.remove(0) {
		let commitment_signed = updates.commitment_signed.remove(0);
		initiator.node.handle_commitment_signed(node_id_acceptor, &commitment_signed);
	} else {
		panic!();
	}
	if let MessageSendEvent::SendTxSignatures { ref msg, .. } = msg_events.remove(0) {
		initiator.node.handle_tx_signatures(node_id_acceptor, msg);
	} else {
		panic!();
	}

	let event = get_event!(initiator, Event::FundingTransactionReadyForSigning);
	if let Event::FundingTransactionReadyForSigning {
		channel_id,
		counterparty_node_id,
		unsigned_transaction,
		..
	} = event
	{
		let partially_signed_tx = initiator.wallet_source.sign_tx(unsigned_transaction).unwrap();
		initiator
			.node
			.funding_transaction_signed(&channel_id, &counterparty_node_id, partially_signed_tx)
			.unwrap();
	}
	let tx_signatures =
		get_event_msg!(initiator, MessageSendEvent::SendTxSignatures, node_id_acceptor);
	acceptor.node.handle_tx_signatures(node_id_initiator, &tx_signatures);

	check_added_monitors(&initiator, 1);
	check_added_monitors(&acceptor, 1);
}

fn splice_channel<'a, 'b, 'c, 'd>(
	initiator: &'a Node<'b, 'c, 'd>, acceptor: &'a Node<'b, 'c, 'd>, channel_id: ChannelId,
	initiator_contribution: SpliceContribution,
) -> Transaction {
	let node_id_initiator = initiator.node.get_our_node_id();
	let node_id_acceptor = acceptor.node.get_our_node_id();

	initiator
		.node
		.splice_channel(
			&channel_id,
			&node_id_acceptor,
			initiator_contribution.clone(),
			FEERATE_FLOOR_SATS_PER_KW,
			None,
		)
		.unwrap();

	let stfu_init = get_event_msg!(initiator, MessageSendEvent::SendStfu, node_id_acceptor);
	acceptor.node.handle_stfu(node_id_initiator, &stfu_init);
	let stfu_ack = get_event_msg!(acceptor, MessageSendEvent::SendStfu, node_id_initiator);
	initiator.node.handle_stfu(node_id_acceptor, &stfu_ack);

	let splice_init = get_event_msg!(initiator, MessageSendEvent::SendSpliceInit, node_id_acceptor);
	acceptor.node.handle_splice_init(node_id_initiator, &splice_init);
	let splice_ack = get_event_msg!(acceptor, MessageSendEvent::SendSpliceAck, node_id_initiator);
	initiator.node.handle_splice_ack(node_id_acceptor, &splice_ack);

	let new_funding_script = chan_utils::make_funding_redeemscript(
		&splice_init.funding_pubkey,
		&splice_ack.funding_pubkey,
	)
	.to_p2wsh();

	let initial_commit_sig_for_acceptor = complete_interactive_funding_negotiation(
		initiator,
		acceptor,
		channel_id,
		initiator_contribution,
		new_funding_script,
	);
	sign_interactive_funding_transaction(initiator, acceptor, initial_commit_sig_for_acceptor);

	let splice_tx = {
		let mut initiator_txn = initiator.tx_broadcaster.txn_broadcast();
		assert_eq!(initiator_txn.len(), 1);
		let acceptor_txn = acceptor.tx_broadcaster.txn_broadcast();
		assert_eq!(initiator_txn, acceptor_txn);
		initiator_txn.remove(0)
	};
	splice_tx
}

fn lock_splice_after_blocks<'a, 'b, 'c, 'd>(
	node_a: &'a Node<'b, 'c, 'd>, node_b: &'a Node<'b, 'c, 'd>, channel_id: ChannelId,
	num_blocks: u32,
) {
	let (prev_funding_outpoint, prev_funding_script) = node_a
		.chain_monitor
		.chain_monitor
		.get_monitor(channel_id)
		.map(|monitor| (monitor.get_funding_txo(), monitor.get_funding_script()))
		.unwrap();

	connect_blocks(node_a, num_blocks);
	connect_blocks(node_b, num_blocks);

	let node_id_a = node_a.node.get_our_node_id();
	let node_id_b = node_b.node.get_our_node_id();

	let splice_locked_a = get_event_msg!(node_a, MessageSendEvent::SendSpliceLocked, node_id_b);
	node_b.node.handle_splice_locked(node_id_a, &splice_locked_a);

	let mut msg_events = node_b.node.get_and_clear_pending_msg_events();
	assert_eq!(msg_events.len(), 2, "{msg_events:?}");
	if let MessageSendEvent::SendSpliceLocked { msg, .. } = msg_events.remove(0) {
		node_a.node.handle_splice_locked(node_id_b, &msg);
	} else {
		panic!();
	}
	if let MessageSendEvent::SendAnnouncementSignatures { msg, .. } = msg_events.remove(0) {
		node_a.node.handle_announcement_signatures(node_id_b, &msg);
	} else {
		panic!();
	}

	expect_channel_ready_event(&node_a, &node_id_b);
	check_added_monitors(&node_a, 1);
	expect_channel_ready_event(&node_b, &node_id_a);
	check_added_monitors(&node_b, 1);

	let mut msg_events = node_a.node.get_and_clear_pending_msg_events();
	assert_eq!(msg_events.len(), 2, "{msg_events:?}");
	if let MessageSendEvent::SendAnnouncementSignatures { msg, .. } = msg_events.remove(0) {
		node_b.node.handle_announcement_signatures(node_id_a, &msg);
	} else {
		panic!();
	}
	if let MessageSendEvent::BroadcastChannelAnnouncement { .. } = msg_events.remove(0) {
	} else {
		panic!();
	}

	let mut msg_events = node_b.node.get_and_clear_pending_msg_events();
	assert_eq!(msg_events.len(), 1, "{msg_events:?}");
	if let MessageSendEvent::BroadcastChannelAnnouncement { .. } = msg_events.remove(0) {
	} else {
		panic!();
	}

	// Remove the corresponding outputs and transactions the chain source is watching.
	node_a
		.chain_source
		.remove_watched_txn_and_outputs(prev_funding_outpoint, prev_funding_script.clone());
	node_b.chain_source.remove_watched_txn_and_outputs(prev_funding_outpoint, prev_funding_script);
}

#[test]
fn test_splice_in() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let mut config = test_default_channel_config();
	config.channel_handshake_config.max_inbound_htlc_value_in_flight_percent_of_channel = 100;
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, Some(config)]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let initial_channel_value_sat = 100_000;
	let (_, _, channel_id, _) =
		create_announced_chan_between_nodes_with_value(&nodes, 0, 1, initial_channel_value_sat, 0);

	let _ = send_payment(&nodes[0], &[&nodes[1]], 100_000);

	let coinbase_tx1 = provide_anchor_reserves(&nodes);
	let coinbase_tx2 = provide_anchor_reserves(&nodes);
	let initiator_contribution = SpliceContribution::SpliceIn {
		value: Amount::from_sat(initial_channel_value_sat * 2),
		inputs: vec![
			FundingTxInput::new_p2wpkh(coinbase_tx1, 0).unwrap(),
			FundingTxInput::new_p2wpkh(coinbase_tx2, 0).unwrap(),
		],
		change_script: Some(nodes[0].wallet_source.get_change_script().unwrap()),
	};

	let splice_tx = splice_channel(&nodes[0], &nodes[1], channel_id, initiator_contribution);
	mine_transaction(&nodes[0], &splice_tx);
	mine_transaction(&nodes[1], &splice_tx);

	let htlc_limit_msat = nodes[0].node.list_channels()[0].next_outbound_htlc_limit_msat;
	assert!(htlc_limit_msat < initial_channel_value_sat * 1000);
	let _ = send_payment(&nodes[0], &[&nodes[1]], htlc_limit_msat);

	lock_splice_after_blocks(&nodes[0], &nodes[1], channel_id, ANTI_REORG_DELAY - 1);

	let htlc_limit_msat = nodes[0].node.list_channels()[0].next_outbound_htlc_limit_msat;
	assert!(htlc_limit_msat > initial_channel_value_sat);
	let _ = send_payment(&nodes[0], &[&nodes[1]], htlc_limit_msat);
}

#[test]
fn test_splice_out() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let mut config = test_default_channel_config();
	config.channel_handshake_config.max_inbound_htlc_value_in_flight_percent_of_channel = 100;
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, Some(config)]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let initial_channel_value_sat = 100_000;
	let (_, _, channel_id, _) =
		create_announced_chan_between_nodes_with_value(&nodes, 0, 1, initial_channel_value_sat, 0);

	let _ = send_payment(&nodes[0], &[&nodes[1]], 100_000);

	let initiator_contribution = SpliceContribution::SpliceOut {
		outputs: vec![
			TxOut {
				value: Amount::from_sat(initial_channel_value_sat / 4),
				script_pubkey: nodes[0].wallet_source.get_change_script().unwrap(),
			},
			TxOut {
				value: Amount::from_sat(initial_channel_value_sat / 4),
				script_pubkey: nodes[1].wallet_source.get_change_script().unwrap(),
			},
		],
	};

	let splice_tx = splice_channel(&nodes[0], &nodes[1], channel_id, initiator_contribution);
	mine_transaction(&nodes[0], &splice_tx);
	mine_transaction(&nodes[1], &splice_tx);

	let htlc_limit_msat = nodes[0].node.list_channels()[0].next_outbound_htlc_limit_msat;
	assert!(htlc_limit_msat < initial_channel_value_sat / 2 * 1000);
	let _ = send_payment(&nodes[0], &[&nodes[1]], htlc_limit_msat);

	lock_splice_after_blocks(&nodes[0], &nodes[1], channel_id, ANTI_REORG_DELAY - 1);

	let htlc_limit_msat = nodes[0].node.list_channels()[0].next_outbound_htlc_limit_msat;
	assert!(htlc_limit_msat < initial_channel_value_sat / 2 * 1000);
	let _ = send_payment(&nodes[0], &[&nodes[1]], htlc_limit_msat);
}

#[derive(PartialEq)]
enum SpliceStatus {
	Unconfirmed,
	Confirmed,
	Locked,
}

#[test]
fn test_splice_commitment_broadcast() {
	do_test_splice_commitment_broadcast(SpliceStatus::Unconfirmed, false);
	do_test_splice_commitment_broadcast(SpliceStatus::Unconfirmed, true);
	do_test_splice_commitment_broadcast(SpliceStatus::Confirmed, false);
	do_test_splice_commitment_broadcast(SpliceStatus::Confirmed, true);
	do_test_splice_commitment_broadcast(SpliceStatus::Locked, false);
	do_test_splice_commitment_broadcast(SpliceStatus::Locked, true);
}

fn do_test_splice_commitment_broadcast(splice_status: SpliceStatus, claim_htlcs: bool) {
	// Tests that we're able to enforce HTLCs onchain during the different stages of a splice.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let config = test_default_anchors_channel_config();
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[Some(config.clone()), Some(config)]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_id_0 = nodes[0].node.get_our_node_id();
	let node_id_1 = nodes[1].node.get_our_node_id();

	let initial_channel_capacity = 100_000;
	let (_, _, channel_id, initial_funding_tx) =
		create_announced_chan_between_nodes_with_value(&nodes, 0, 1, initial_channel_capacity, 0);

	let coinbase_tx = provide_anchor_reserves(&nodes);

	// We want to have two HTLCs pending to make sure we can claim those sent before and after a
	// splice negotiation.
	let payment_amount = 1_000_000;
	let (preimage1, payment_hash1, ..) = route_payment(&nodes[0], &[&nodes[1]], payment_amount);
	let splice_in_amount = initial_channel_capacity / 2;
	let initiator_contribution = SpliceContribution::SpliceIn {
		value: Amount::from_sat(splice_in_amount),
		inputs: vec![FundingTxInput::new_p2wpkh(coinbase_tx.clone(), 0).unwrap()],
		change_script: Some(nodes[0].wallet_source.get_change_script().unwrap()),
	};
	let splice_tx = splice_channel(&nodes[0], &nodes[1], channel_id, initiator_contribution);
	let (preimage2, payment_hash2, ..) = route_payment(&nodes[0], &[&nodes[1]], payment_amount);
	let htlc_expiry = nodes[0].best_block_info().1 + TEST_FINAL_CLTV + LATENCY_GRACE_PERIOD_BLOCKS;

	if splice_status == SpliceStatus::Confirmed || splice_status == SpliceStatus::Locked {
		mine_transaction(&nodes[0], &splice_tx);
		mine_transaction(&nodes[1], &splice_tx);
	}
	if splice_status == SpliceStatus::Locked {
		lock_splice_after_blocks(&nodes[0], &nodes[1], channel_id, ANTI_REORG_DELAY - 1);
	}

	if claim_htlcs {
		// Claim both HTLCs, but don't do anything with the update message sent since we want to
		// resolve the HTLCs onchain instead with a single transaction (thanks to anchors).
		nodes[1].node.claim_funds(preimage1);
		expect_payment_claimed!(&nodes[1], payment_hash1, payment_amount);
		nodes[1].node.claim_funds(preimage2);
		expect_payment_claimed!(&nodes[1], payment_hash2, payment_amount);
		check_added_monitors(&nodes[1], 2);
		let _ = get_htlc_update_msgs(&nodes[1], &node_id_0);
	}

	// Force close the channel. This should broadcast the appropriate commitment transaction based
	// on the currently confirmed funding.
	nodes[0]
		.node
		.force_close_broadcasting_latest_txn(&channel_id, &node_id_1, "test".to_owned())
		.unwrap();
	handle_bump_events(&nodes[0], true, 0);
	let commitment_tx = {
		let mut txn = nodes[0].tx_broadcaster.txn_broadcast();
		assert_eq!(txn.len(), 1);
		let commitment_tx = txn.remove(0);
		match splice_status {
			SpliceStatus::Unconfirmed => check_spends!(&commitment_tx, &initial_funding_tx),
			SpliceStatus::Confirmed | SpliceStatus::Locked => {
				check_spends!(&commitment_tx, &splice_tx)
			},
		}
		commitment_tx
	};

	mine_transaction(&nodes[0], &commitment_tx);
	mine_transaction(&nodes[1], &commitment_tx);

	let closure_reason = ClosureReason::HolderForceClosed {
		broadcasted_latest_txn: Some(true),
		message: "test".to_owned(),
	};
	let closed_channel_capacity = if splice_status == SpliceStatus::Locked {
		initial_channel_capacity + splice_in_amount
	} else {
		initial_channel_capacity
	};
	check_closed_event(&nodes[0], 1, closure_reason, false, &[node_id_1], closed_channel_capacity);
	check_closed_broadcast(&nodes[0], 1, true);
	check_added_monitors(&nodes[0], 1);

	let closure_reason = ClosureReason::CommitmentTxConfirmed;
	check_closed_event(&nodes[1], 1, closure_reason, false, &[node_id_0], closed_channel_capacity);
	check_closed_broadcast(&nodes[1], 1, true);
	check_added_monitors(&nodes[1], 1);

	if !claim_htlcs {
		// If we're supposed to time out the HTLCs, mine enough blocks until the expiration.
		connect_blocks(&nodes[0], htlc_expiry - nodes[0].best_block_info().1);
		connect_blocks(&nodes[1], htlc_expiry - nodes[1].best_block_info().1);
		expect_htlc_handling_failed_destinations!(
			nodes[1].node.get_and_clear_pending_events(),
			&[
				HTLCHandlingFailureType::Receive { payment_hash: payment_hash1 },
				HTLCHandlingFailureType::Receive { payment_hash: payment_hash2 }
			]
		);
	}

	// We should see either an aggregated HTLC timeout or success transaction spending the valid
	// commitment transaction we mined earlier.
	let htlc_claim_tx = if claim_htlcs {
		let mut txn = nodes[1].tx_broadcaster.txn_broadcast();
		assert_eq!(txn.len(), 1);
		let htlc_success_tx = txn.remove(0);
		assert_eq!(htlc_success_tx.input.len(), 2);
		check_spends!(&htlc_success_tx, &commitment_tx);
		htlc_success_tx
	} else {
		handle_bump_htlc_event(&nodes[0], 1);
		let mut txn = nodes[0].tx_broadcaster.txn_broadcast();
		assert_eq!(txn.len(), 1);
		let htlc_timeout_tx = txn.remove(0);
		// The inputs spent correspond to the fee bump input and the two HTLCs from the commitment
		// transaction.
		assert_eq!(htlc_timeout_tx.input.len(), 3);
		let tx_with_fee_bump_utxo =
			if splice_status == SpliceStatus::Unconfirmed { &coinbase_tx } else { &splice_tx };
		check_spends!(&htlc_timeout_tx, &commitment_tx, tx_with_fee_bump_utxo);
		htlc_timeout_tx
	};

	mine_transaction(&nodes[0], &htlc_claim_tx);
	mine_transaction(&nodes[1], &htlc_claim_tx);
	connect_blocks(&nodes[0], ANTI_REORG_DELAY - 1);
	connect_blocks(&nodes[1], ANTI_REORG_DELAY - 1);

	let events = nodes[0].node.get_and_clear_pending_events();
	if claim_htlcs {
		assert_eq!(events.iter().filter(|e| matches!(e, Event::PaymentSent { .. })).count(), 2);
		assert_eq!(
			events.iter().filter(|e| matches!(e, Event::PaymentPathSuccessful { .. })).count(),
			2
		);
	} else {
		assert_eq!(events.iter().filter(|e| matches!(e, Event::PaymentFailed { .. })).count(), 2,);
		assert_eq!(
			events.iter().filter(|e| matches!(e, Event::PaymentPathFailed { .. })).count(),
			2
		);
	}
	check_added_monitors(&nodes[0], 2); // Two `ReleasePaymentComplete` monitor updates
}
