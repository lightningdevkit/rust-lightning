// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Tests that test standing up a network of ChannelManagers, creating channels, sending
//! payments/messages between them, and often checking the resulting ChannelMonitors are able to
//! claim outputs on-chain.

use crate::events::{Event, MessageSendEvent, MessageSendEventsProvider};
use crate::ln::functional_test_utils::*;
use crate::ln::msgs::ChannelMessageHandler;
use crate::util::config::{ChannelHandshakeConfig, UserConfig};

/// Splicing test, simple splice-in flow. Starts with opening a V1 channel first.
/// Builds on test_channel_open_simple()
#[test]
fn test_v1_splice_in() {
	// Set up a network of 2 nodes
	let cfg = UserConfig {
		channel_handshake_config: ChannelHandshakeConfig { ..Default::default() },
		..Default::default()
	};
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[Some(cfg), None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	// Initiator and Acceptor nodes
	let initiator_node_index = 0;
	let acceptor_node_index = 1;
	let initiator_node = &nodes[initiator_node_index];
	let acceptor_node = &nodes[acceptor_node_index];

	// Instantiate channel parameters where we push the maximum msats given our funding satoshis
	let channel_value_sat = 100_000; // same as funding satoshis
	let push_msat = 0;
	let channel_reserve_amnt_sat = 1_000;

	let expected_funded_channel_id =
		"ae3367da2c13bc1ceb86bf56418f62828f7ce9d6bfb15a46af5ba1f1ed8b124f";

	// Have initiator_node initiate a channel to acceptor_node with aforementioned parameters
	let channel_id_temp1 = initiator_node
		.node
		.create_channel(
			acceptor_node.node.get_our_node_id(),
			channel_value_sat,
			push_msat,
			42,
			None,
			None,
		)
		.unwrap();

	// Extract the channel open message from initiator_node to acceptor_node
	let open_channel_message = get_event_msg!(
		initiator_node,
		MessageSendEvent::SendOpenChannel,
		acceptor_node.node.get_our_node_id()
	);
	let expected_initiator_funding_key =
		"03c21e841cbc0b48197d060c71e116c185fa0ac281b7d0aa5924f535154437ca3b";
	assert_eq!(
		open_channel_message.common_fields.funding_pubkey.to_string(),
		expected_initiator_funding_key
	);

	let _res = acceptor_node
		.node
		.handle_open_channel(initiator_node.node.get_our_node_id(), &open_channel_message.clone());
	// Extract the accept channel message from acceptor_node to initiator_node
	let accept_channel_message = get_event_msg!(
		acceptor_node,
		MessageSendEvent::SendAcceptChannel,
		initiator_node.node.get_our_node_id()
	);
	let expected_acceptor_funding_key =
		"039481c28b904cbe12681e79937373fc76245c1b29871028ae60ba3152162c319b";
	assert_eq!(
		accept_channel_message.common_fields.funding_pubkey.to_string(),
		expected_acceptor_funding_key
	);

	let _res = initiator_node.node.handle_accept_channel(
		acceptor_node.node.get_our_node_id(),
		&accept_channel_message.clone(),
	);
	// Note: FundingGenerationReady emitted, checked and used below
	let (_channel_id_temp2, funding_tx, _funding_output) = create_funding_transaction(
		&initiator_node,
		&acceptor_node.node.get_our_node_id(),
		channel_value_sat,
		42,
	);

	// Funding transation created, provide it
	let _res = initiator_node
		.node
		.funding_transaction_generated(
			channel_id_temp1,
			acceptor_node.node.get_our_node_id(),
			funding_tx.clone(),
		)
		.unwrap();

	let funding_created_message = get_event_msg!(
		initiator_node,
		MessageSendEvent::SendFundingCreated,
		acceptor_node.node.get_our_node_id()
	);

	let _res = acceptor_node
		.node
		.handle_funding_created(initiator_node.node.get_our_node_id(), &funding_created_message);

	assert_eq!(initiator_node.node.list_channels().len(), 1);
	{
		let channel = &initiator_node.node.list_channels()[0];
		assert!(!channel.is_channel_ready);
	}
	// do checks on the acceptor node as well (capacity, etc.)
	assert_eq!(acceptor_node.node.list_channels().len(), 1);
	{
		let channel = &acceptor_node.node.list_channels()[0];
		assert!(!channel.is_channel_ready);
	}

	let funding_signed_message = get_event_msg!(
		acceptor_node,
		MessageSendEvent::SendFundingSigned,
		initiator_node.node.get_our_node_id()
	);
	let _res = initiator_node
		.node
		.handle_funding_signed(acceptor_node.node.get_our_node_id(), &funding_signed_message);
	// Take new channel ID
	let channel_id2 = funding_signed_message.channel_id;
	assert_eq!(channel_id2.to_string(), expected_funded_channel_id);

	// Check that funding transaction has been broadcasted
	assert_eq!(
		chanmon_cfgs[initiator_node_index].tx_broadcaster.txn_broadcasted.lock().unwrap().len(),
		1
	);
	let broadcasted_funding_tx =
		chanmon_cfgs[initiator_node_index].tx_broadcaster.txn_broadcasted.lock().unwrap()[0]
			.clone();

	check_added_monitors!(initiator_node, 1);
	let _ev = get_event!(initiator_node, Event::ChannelPending);
	check_added_monitors!(acceptor_node, 1);
	let _ev = get_event!(acceptor_node, Event::ChannelPending);

	// Simulate confirmation of the funding tx
	confirm_transaction(&initiator_node, &broadcasted_funding_tx);
	let channel_ready_message = get_event_msg!(
		initiator_node,
		MessageSendEvent::SendChannelReady,
		acceptor_node.node.get_our_node_id()
	);

	confirm_transaction(&acceptor_node, &broadcasted_funding_tx);
	let channel_ready_message2 = get_event_msg!(
		acceptor_node,
		MessageSendEvent::SendChannelReady,
		initiator_node.node.get_our_node_id()
	);

	let _res = acceptor_node
		.node
		.handle_channel_ready(initiator_node.node.get_our_node_id(), &channel_ready_message);
	let _ev = get_event!(acceptor_node, Event::ChannelReady);
	let _channel_update = get_event_msg!(
		acceptor_node,
		MessageSendEvent::SendChannelUpdate,
		initiator_node.node.get_our_node_id()
	);

	let _res = initiator_node
		.node
		.handle_channel_ready(acceptor_node.node.get_our_node_id(), &channel_ready_message2);
	let _ev = get_event!(initiator_node, Event::ChannelReady);
	let _channel_update = get_event_msg!(
		initiator_node,
		MessageSendEvent::SendChannelUpdate,
		acceptor_node.node.get_our_node_id()
	);

	// check channel capacity and other parameters
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
		assert_eq!(channel.funding_txo.unwrap().txid, funding_tx.compute_txid());
		assert_eq!(channel.confirmations.unwrap(), 10);
	}
	// do checks on the acceptor node as well (capacity, etc.)
	assert_eq!(acceptor_node.node.list_channels().len(), 1);
	{
		let channel = &acceptor_node.node.list_channels()[0];
		assert_eq!(channel.channel_id.to_string(), expected_funded_channel_id);
		assert!(channel.is_usable);
		assert!(channel.is_channel_ready);
		assert_eq!(channel.channel_value_satoshis, channel_value_sat);
		assert_eq!(channel.outbound_capacity_msat, 0);
		assert_eq!(channel.funding_txo.unwrap().txid, funding_tx.compute_txid());
		assert_eq!(channel.confirmations.unwrap(), 10);
	}

	// ==== Channel is now ready for normal operation

	// === Start of Splicing
	println!("Start of Splicing ..., channel_id {}", channel_id2);

	// Amount being added to the channel through the splice-in
	let splice_in_sats: u64 = 20000;
	let funding_feerate_per_kw = 1024; // TODO
	let locktime = 0; // TODO

	// Create additional inputs
	let extra_splice_funding_input_sats = 35_000;
	let (funding_inputs, total_weight) = create_dual_funding_utxos_with_prev_txs(
		&initiator_node,
		&[extra_splice_funding_input_sats],
	);
	// Initiate splice-in (on initiator_node)
	let _res = initiator_node
		.node
		.splice_channel(
			&channel_id2,
			&acceptor_node.node.get_our_node_id(),
			splice_in_sats as i64,
			funding_inputs,
			total_weight,
			funding_feerate_per_kw,
			locktime,
		)
		.unwrap();
	// Extract the splice message from node0 to node1
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
	// Extract the splice_ack message from node1 to node0
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
	initiator_node.node.close_channel(&channel_id2, &acceptor_node.node.get_our_node_id()).unwrap();
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
