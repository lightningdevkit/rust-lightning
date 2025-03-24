// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

use crate::ln::functional_test_utils::*;
use crate::ln::msgs::{BaseMessageHandler, ChannelMessageHandler, MessageSendEvent};
use crate::util::errors::APIError;

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

	let channel_value_sat = 100_000;
	let channel_reserve_amnt_sat = 1_000;

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
		"03c21e841cbc0b48197d060c71e116c185fa0ac281b7d0aa5924f535154437ca3b";
	let expected_acceptor_funding_key =
		"039481c28b904cbe12681e79937373fc76245c1b29871028ae60ba3152162c319b";

	// ==== Channel is now ready for normal operation

	// === Start of Splicing

	// Amount being added to the channel through the splice-in
	let splice_in_sats = 20_000;
	let funding_feerate_per_kw = 1024;

	// Create additional inputs
	let extra_splice_funding_input_sats = 35_000;
	let funding_inputs = create_dual_funding_utxos_with_prev_txs(
		&initiator_node,
		&[extra_splice_funding_input_sats],
	);
	// Initiate splice-in
	let _res = initiator_node
		.node
		.splice_channel(
			&channel_id,
			&acceptor_node.node.get_our_node_id(),
			splice_in_sats as i64,
			funding_inputs,
			funding_feerate_per_kw,
			None, // locktime
		)
		.unwrap();
	// Extract the splice_init message
	let splice_init_msg = get_event_msg!(
		initiator_node,
		MessageSendEvent::SendSpliceInit,
		acceptor_node.node.get_our_node_id()
	);
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
		assert_eq!(
			channel.outbound_capacity_msat,
			1000 * (channel_value_sat - channel_reserve_amnt_sat)
		);
		assert!(channel.funding_txo.is_some());
		assert!(channel.confirmations.unwrap() > 0);
	}

	let _error_msg = get_err_msg(initiator_node, &acceptor_node.node.get_our_node_id());

	// TODO(splicing): continue with splice transaction negotiation

	// === Close channel, cooperatively
	initiator_node.node.close_channel(&channel_id, &acceptor_node.node.get_our_node_id()).unwrap();
	let node0_shutdown_message = get_event_msg!(
		initiator_node,
		MessageSendEvent::SendShutdown,
		acceptor_node.node.get_our_node_id()
	);
	acceptor_node
		.node
		.handle_shutdown(initiator_node.node.get_our_node_id(), &node0_shutdown_message);
	let nodes_1_shutdown = get_event_msg!(
		acceptor_node,
		MessageSendEvent::SendShutdown,
		initiator_node.node.get_our_node_id()
	);
	initiator_node.node.handle_shutdown(acceptor_node.node.get_our_node_id(), &nodes_1_shutdown);
	let _ = get_event_msg!(
		initiator_node,
		MessageSendEvent::SendClosingSigned,
		acceptor_node.node.get_our_node_id()
	);
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

	// Initiate splice-in, with insufficient input contribution
	let res = nodes[0].node.splice_channel(
		&channel_id,
		&nodes[1].node.get_our_node_id(),
		splice_in_sats as i64,
		funding_inputs,
		1024, // funding_feerate_per_kw,
		None, // locktime
	);
	match res {
		Err(APIError::APIMisuseError { err }) => {
			assert!(err.contains("Insufficient inputs for splicing"))
		},
		_ => panic!("Wrong error {:?}", res.err().unwrap()),
	}
}
