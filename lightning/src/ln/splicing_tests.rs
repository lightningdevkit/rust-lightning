// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

use crate::ln::functional_test_utils::*;
use crate::ln::funding::SpliceContribution;
use crate::ln::msgs::{BaseMessageHandler, ChannelMessageHandler, MessageSendEvent};
use crate::util::errors::APIError;

use bitcoin::Amount;

/// Splicing test, simple splice-in flow. Starts with opening a V1 channel first.
/// Builds on test_channel_open_simple()
#[test]
fn test_v1_splice_in() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	// Initiator and Acceptor nodes
	let initiator_node_index = 0;
	let acceptor_node_index = 1;
	let initiator_node = &nodes[initiator_node_index];
	let acceptor_node = &nodes[acceptor_node_index];
	let initiator_node_id = initiator_node.node.get_our_node_id();
	let acceptor_node_id = acceptor_node.node.get_our_node_id();

	let channel_value_sat = 100_000;
	let channel_reserve_amnt_sat = 1_000;
	let expect_outputs_in_reverse = true;

	let (_, _, channel_id, _) = create_announced_chan_between_nodes_with_value(
		&nodes,
		initiator_node_index,
		acceptor_node_index,
		channel_value_sat,
		0, // push_msat,
	);

	let expected_funded_channel_id =
		"ae3367da2c13bc1ceb86bf56418f62828f7ce9d6bfb15a46af5ba1f1ed8b124f";
	assert_eq!(channel_id.to_string(), expected_funded_channel_id);

	let expected_initiator_funding_key =
		"020abf01c18d5a2543124a12150d698ebf3a8e17df9993521151a49e115678ceea";
	let expected_acceptor_funding_key =
		"036b47248c628fca98159f30f6b03a6cf0be0c4808cff17c75dc855fe94a244766";

	// ==== Channel is now ready for normal operation

	// Expected balances
	let mut exp_balance1 = 1000 * channel_value_sat;
	let mut _exp_balance2 = 0;

	// === Start of Splicing

	// Amount being added to the channel through the splice-in
	let splice_in_sats = 20_000;
	let post_splice_channel_value = channel_value_sat + splice_in_sats;
	let funding_feerate_per_kw = 1024;

	// Create additional inputs
	let extra_splice_funding_input_sats = 35_000;
	let funding_inputs = create_dual_funding_utxos_with_prev_txs(
		&initiator_node,
		&[extra_splice_funding_input_sats],
	);

	let contribution = SpliceContribution::SpliceIn {
		value: Amount::from_sat(splice_in_sats),
		inputs: funding_inputs,
		change_script: None,
	};

	// Initiate splice-in
	let _res = initiator_node
		.node
		.splice_channel(
			&channel_id,
			&acceptor_node.node.get_our_node_id(),
			contribution,
			funding_feerate_per_kw,
			None, // locktime
		)
		.unwrap();

	let init_stfu = get_event_msg!(initiator_node, MessageSendEvent::SendStfu, acceptor_node_id);
	acceptor_node.node.handle_stfu(initiator_node_id, &init_stfu);

	let ack_stfu = get_event_msg!(acceptor_node, MessageSendEvent::SendStfu, initiator_node_id);
	initiator_node.node.handle_stfu(acceptor_node_id, &ack_stfu);

	// Extract the splice_init message
	let splice_init_msg =
		get_event_msg!(initiator_node, MessageSendEvent::SendSpliceInit, acceptor_node_id);
	assert_eq!(splice_init_msg.funding_contribution_satoshis, splice_in_sats as i64);
	assert_eq!(splice_init_msg.funding_feerate_per_kw, funding_feerate_per_kw);
	assert_eq!(splice_init_msg.funding_pubkey.to_string(), expected_initiator_funding_key);
	assert!(splice_init_msg.require_confirmed_inputs.is_none());

	let _res = acceptor_node
		.node
		.handle_splice_init(initiator_node.node.get_our_node_id(), &splice_init_msg);
	// Extract the splice_ack message
	let splice_ack_msg = get_event_msg!(
		acceptor_node,
		MessageSendEvent::SendSpliceAck,
		initiator_node.node.get_our_node_id()
	);
	assert_eq!(splice_ack_msg.funding_contribution_satoshis, 0);
	assert_eq!(splice_ack_msg.funding_pubkey.to_string(), expected_acceptor_funding_key);
	assert!(splice_ack_msg.require_confirmed_inputs.is_none());

	// still pre-splice channel: capacity not updated, channel usable, and funding tx set
	assert_eq!(acceptor_node.node.list_channels().len(), 1);
	{
		let channel = &acceptor_node.node.list_channels()[0];
		assert_eq!(channel.channel_id.to_string(), expected_funded_channel_id);
		assert!(channel.is_usable);
		assert!(channel.is_channel_ready);
		assert_eq!(channel.channel_value_satoshis, channel_value_sat);
		assert_eq!(channel.outbound_capacity_msat, 0);
		assert!(channel.funding_txo.is_some());
		assert!(channel.confirmations.unwrap() > 0);
	}

	let _res = initiator_node
		.node
		.handle_splice_ack(acceptor_node.node.get_our_node_id(), &splice_ack_msg);

	// still pre-splice channel: capacity not updated, channel usable, and funding tx set
	assert_eq!(initiator_node.node.list_channels().len(), 1);
	{
		let channel = &initiator_node.node.list_channels()[0];
		assert_eq!(channel.channel_id.to_string(), expected_funded_channel_id);
		assert!(channel.is_usable);
		assert!(channel.is_channel_ready);
		assert_eq!(channel.channel_value_satoshis, channel_value_sat);
		assert_eq!(channel.outbound_capacity_msat, exp_balance1 - 1000 * channel_reserve_amnt_sat);
		assert!(channel.funding_txo.is_some());
		assert!(channel.confirmations.unwrap() > 0);
	}

	// exp_balance1 += 1000 * splice_in_sats; // increase in balance

	// Negotiate transaction inputs and outputs

	// First input
	let tx_add_input_msg = get_event_msg!(
		&initiator_node,
		MessageSendEvent::SendTxAddInput,
		acceptor_node.node.get_our_node_id()
	);
	// check which input is this (order is non-deterministic), based on the presense of prevtx
	let inputs_seen_in_reverse = tx_add_input_msg.prevtx.is_some();
	if !inputs_seen_in_reverse {
		// Input is the revious funding input
		assert_eq!(tx_add_input_msg.prevtx, None);
		assert_eq!(
			tx_add_input_msg.shared_input_txid.unwrap().to_string(),
			"4f128bedf1a15baf465ab1bfd6e97c8f82628f4156bf86eb1cbc132cda6733ae"
		);
	} else {
		// Input is the extra input
		let prevtx_value = tx_add_input_msg.prevtx.as_ref().unwrap().output
			[tx_add_input_msg.prevtx_out as usize]
			.value
			.to_sat();
		assert_eq!(prevtx_value, extra_splice_funding_input_sats);
		assert_eq!(tx_add_input_msg.shared_input_txid, None);
	}

	let _res = acceptor_node
		.node
		.handle_tx_add_input(initiator_node.node.get_our_node_id(), &tx_add_input_msg);
	let tx_complete_msg = get_event_msg!(
		acceptor_node,
		MessageSendEvent::SendTxComplete,
		initiator_node.node.get_our_node_id()
	);

	let _res = initiator_node
		.node
		.handle_tx_complete(acceptor_node.node.get_our_node_id(), &tx_complete_msg);
	// Second input
	let tx_add_input2_msg = get_event_msg!(
		&initiator_node,
		MessageSendEvent::SendTxAddInput,
		acceptor_node.node.get_our_node_id()
	);
	if !inputs_seen_in_reverse {
		// Input is the extra input
		let prevtx_value = tx_add_input2_msg.prevtx.as_ref().unwrap().output
			[tx_add_input2_msg.prevtx_out as usize]
			.value
			.to_sat();
		assert_eq!(prevtx_value, extra_splice_funding_input_sats);
		assert_eq!(tx_add_input2_msg.shared_input_txid, None);
	} else {
		// Input is the revious funding input
		assert_eq!(tx_add_input2_msg.prevtx, None);
		assert_eq!(
			tx_add_input2_msg.shared_input_txid.unwrap().to_string(),
			"4f128bedf1a15baf465ab1bfd6e97c8f82628f4156bf86eb1cbc132cda6733ae"
		);
	}

	let _res = acceptor_node
		.node
		.handle_tx_add_input(initiator_node.node.get_our_node_id(), &tx_add_input2_msg);
	let tx_complete_msg = get_event_msg!(
		acceptor_node,
		MessageSendEvent::SendTxComplete,
		initiator_node.node.get_our_node_id()
	);

	let _res = initiator_node
		.node
		.handle_tx_complete(acceptor_node.node.get_our_node_id(), &tx_complete_msg);

	// TxAddOutput for the change output
	let tx_add_output_msg = get_event_msg!(
		&initiator_node,
		MessageSendEvent::SendTxAddOutput,
		acceptor_node.node.get_our_node_id()
	);
	if !expect_outputs_in_reverse {
		assert!(tx_add_output_msg.script.is_p2wsh());
		assert_eq!(tx_add_output_msg.sats, post_splice_channel_value);
	} else {
		assert!(tx_add_output_msg.script.is_p2wpkh());
		assert_eq!(tx_add_output_msg.sats, 13979); // extra_splice_funding_input_sats - splice_in_sats
	}

	let _res = acceptor_node
		.node
		.handle_tx_add_output(initiator_node.node.get_our_node_id(), &tx_add_output_msg);
	let tx_complete_msg = get_event_msg!(
		&acceptor_node,
		MessageSendEvent::SendTxComplete,
		initiator_node.node.get_our_node_id()
	);

	let _res = initiator_node
		.node
		.handle_tx_complete(acceptor_node.node.get_our_node_id(), &tx_complete_msg);
	// TxAddOutput for the splice funding
	let tx_add_output2_msg = get_event_msg!(
		&initiator_node,
		MessageSendEvent::SendTxAddOutput,
		acceptor_node.node.get_our_node_id()
	);
	if !expect_outputs_in_reverse {
		assert!(tx_add_output2_msg.script.is_p2wpkh());
		assert_eq!(tx_add_output2_msg.sats, 14146); // extra_splice_funding_input_sats - splice_in_sats
	} else {
		assert!(tx_add_output2_msg.script.is_p2wsh());
		assert_eq!(tx_add_output2_msg.sats, post_splice_channel_value);
	}

	let _res = acceptor_node
		.node
		.handle_tx_add_output(initiator_node.node.get_our_node_id(), &tx_add_output2_msg);
	let _tx_complete_msg = get_event_msg!(
		acceptor_node,
		MessageSendEvent::SendTxComplete,
		initiator_node.node.get_our_node_id()
	);

	// TODO(splicing) This is the last tx_complete, which triggers the commitment flow, which is not yet fully implemented
	let _res = initiator_node
		.node
		.handle_tx_complete(acceptor_node.node.get_our_node_id(), &tx_complete_msg);
	let events = initiator_node.node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		MessageSendEvent::SendTxAbort { .. } => {},
		_ => panic!("Unexpected event {:?}", events[0]),
	}

	// TODO(splicing): Continue with commitment flow, new tx confirmation, and shutdown
}

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
