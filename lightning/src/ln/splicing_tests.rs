// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

#![cfg_attr(not(test), allow(unused_imports))]

use crate::chain::chaininterface::FEERATE_FLOOR_SATS_PER_KW;
use crate::chain::channelmonitor::{ANTI_REORG_DELAY, LATENCY_GRACE_PERIOD_BLOCKS};
use crate::chain::transaction::OutPoint;
use crate::chain::ChannelMonitorUpdateStatus;
use crate::events::bump_transaction::sync::WalletSourceSync;
use crate::events::{ClosureReason, Event, FundingInfo, HTLCHandlingFailureType};
use crate::ln::chan_utils;
use crate::ln::channel::CHANNEL_ANNOUNCEMENT_PROPAGATION_DELAY;
use crate::ln::channelmanager::{PaymentId, RecipientOnionFields, BREAKDOWN_TIMEOUT};
use crate::ln::functional_test_utils::*;
use crate::ln::funding::{FundingTxInput, SpliceContribution};
use crate::ln::msgs::{self, BaseMessageHandler, ChannelMessageHandler, MessageSendEvent};
use crate::ln::types::ChannelId;
use crate::routing::router::{PaymentParameters, RouteParameters};
use crate::util::errors::APIError;
use crate::util::ser::Writeable;
use crate::util::test_channel_signer::SignerOp;

use bitcoin::secp256k1::PublicKey;
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

pub fn negotiate_splice_tx<'a, 'b, 'c, 'd>(
	initiator: &'a Node<'b, 'c, 'd>, acceptor: &'a Node<'b, 'c, 'd>, channel_id: ChannelId,
	initiator_contribution: SpliceContribution,
) -> msgs::CommitmentSigned {
	let new_funding_script =
		complete_splice_handshake(initiator, acceptor, channel_id, initiator_contribution.clone());
	complete_interactive_funding_negotiation(
		initiator,
		acceptor,
		channel_id,
		initiator_contribution,
		new_funding_script,
	)
}

pub fn complete_splice_handshake<'a, 'b, 'c, 'd>(
	initiator: &'a Node<'b, 'c, 'd>, acceptor: &'a Node<'b, 'c, 'd>, channel_id: ChannelId,
	initiator_contribution: SpliceContribution,
) -> ScriptBuf {
	let node_id_initiator = initiator.node.get_our_node_id();
	let node_id_acceptor = acceptor.node.get_our_node_id();

	initiator
		.node
		.splice_channel(
			&channel_id,
			&node_id_acceptor,
			initiator_contribution,
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

	new_funding_script
}

pub fn complete_interactive_funding_negotiation<'a, 'b, 'c, 'd>(
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

pub fn sign_interactive_funding_tx<'a, 'b, 'c, 'd>(
	initiator: &'a Node<'b, 'c, 'd>, acceptor: &'a Node<'b, 'c, 'd>,
	initial_commit_sig_for_acceptor: msgs::CommitmentSigned, is_0conf: bool,
) -> (Transaction, Option<(msgs::SpliceLocked, PublicKey)>) {
	let node_id_initiator = initiator.node.get_our_node_id();
	let node_id_acceptor = acceptor.node.get_our_node_id();

	assert!(initiator.node.get_and_clear_pending_msg_events().is_empty());
	acceptor.node.handle_commitment_signed(node_id_initiator, &initial_commit_sig_for_acceptor);

	let msg_events = acceptor.node.get_and_clear_pending_msg_events();
	assert_eq!(msg_events.len(), 2, "{msg_events:?}");
	if let MessageSendEvent::UpdateHTLCs { ref updates, .. } = &msg_events[0] {
		let commitment_signed = &updates.commitment_signed[0];
		initiator.node.handle_commitment_signed(node_id_acceptor, commitment_signed);
	} else {
		panic!();
	}
	if let MessageSendEvent::SendTxSignatures { ref msg, .. } = &msg_events[1] {
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
	let mut msg_events = initiator.node.get_and_clear_pending_msg_events();
	assert_eq!(msg_events.len(), if is_0conf { 2 } else { 1 }, "{msg_events:?}");
	if let MessageSendEvent::SendTxSignatures { ref msg, .. } = &msg_events[0] {
		acceptor.node.handle_tx_signatures(node_id_initiator, msg);
	} else {
		panic!();
	}
	let splice_locked = if is_0conf {
		if let MessageSendEvent::SendSpliceLocked { msg, .. } = msg_events.remove(1) {
			Some((msg, node_id_acceptor))
		} else {
			panic!();
		}
	} else {
		None
	};

	check_added_monitors(&initiator, 1);
	check_added_monitors(&acceptor, 1);

	let tx = {
		let mut initiator_txn = initiator.tx_broadcaster.txn_broadcast();
		assert_eq!(initiator_txn.len(), 1);
		let acceptor_txn = acceptor.tx_broadcaster.txn_broadcast();
		assert_eq!(initiator_txn, acceptor_txn,);
		initiator_txn.remove(0)
	};
	(tx, splice_locked)
}

pub fn splice_channel<'a, 'b, 'c, 'd>(
	initiator: &'a Node<'b, 'c, 'd>, acceptor: &'a Node<'b, 'c, 'd>, channel_id: ChannelId,
	initiator_contribution: SpliceContribution,
) -> Transaction {
	let node_id_initiator = initiator.node.get_our_node_id();
	let node_id_acceptor = acceptor.node.get_our_node_id();

	let new_funding_script =
		complete_splice_handshake(initiator, acceptor, channel_id, initiator_contribution.clone());

	let initial_commit_sig_for_acceptor = complete_interactive_funding_negotiation(
		initiator,
		acceptor,
		channel_id,
		initiator_contribution,
		new_funding_script,
	);
	let (splice_tx, splice_locked) =
		sign_interactive_funding_tx(initiator, acceptor, initial_commit_sig_for_acceptor, false);
	assert!(splice_locked.is_none());

	expect_splice_pending_event(initiator, &node_id_acceptor);
	expect_splice_pending_event(acceptor, &node_id_initiator);

	splice_tx
}

pub fn lock_splice_after_blocks<'a, 'b, 'c, 'd>(
	node_a: &'a Node<'b, 'c, 'd>, node_b: &'a Node<'b, 'c, 'd>, num_blocks: u32,
) {
	connect_blocks(node_a, num_blocks);
	connect_blocks(node_b, num_blocks);

	let node_id_b = node_b.node.get_our_node_id();
	let splice_locked_for_node_b =
		get_event_msg!(node_a, MessageSendEvent::SendSpliceLocked, node_id_b);
	lock_splice(node_a, node_b, &splice_locked_for_node_b, false);
}

pub fn lock_splice<'a, 'b, 'c, 'd>(
	node_a: &'a Node<'b, 'c, 'd>, node_b: &'a Node<'b, 'c, 'd>,
	splice_locked_for_node_b: &msgs::SpliceLocked, is_0conf: bool,
) {
	let (prev_funding_outpoint, prev_funding_script) = node_a
		.chain_monitor
		.chain_monitor
		.get_monitor(splice_locked_for_node_b.channel_id)
		.map(|monitor| (monitor.get_funding_txo(), monitor.get_funding_script()))
		.unwrap();

	let node_id_a = node_a.node.get_our_node_id();
	let node_id_b = node_b.node.get_our_node_id();

	node_b.node.handle_splice_locked(node_id_a, splice_locked_for_node_b);

	let mut msg_events = node_b.node.get_and_clear_pending_msg_events();
	assert_eq!(msg_events.len(), if is_0conf { 1 } else { 2 }, "{msg_events:?}");
	if let MessageSendEvent::SendSpliceLocked { msg, .. } = msg_events.remove(0) {
		node_a.node.handle_splice_locked(node_id_b, &msg);
	} else {
		panic!();
	}
	if !is_0conf {
		if let MessageSendEvent::SendAnnouncementSignatures { msg, .. } = msg_events.remove(0) {
			node_a.node.handle_announcement_signatures(node_id_b, &msg);
		} else {
			panic!();
		}
	}

	expect_channel_ready_event(&node_a, &node_id_b);
	check_added_monitors(&node_a, 1);
	expect_channel_ready_event(&node_b, &node_id_a);
	check_added_monitors(&node_b, 1);

	if !is_0conf {
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
	}

	// Remove the corresponding outputs and transactions the chain source is watching for the
	// old funding as it is no longer being tracked.
	node_a
		.chain_source
		.remove_watched_txn_and_outputs(prev_funding_outpoint, prev_funding_script.clone());
	node_b.chain_source.remove_watched_txn_and_outputs(prev_funding_outpoint, prev_funding_script);
}

#[test]
fn test_splice_state_reset_on_disconnect() {
	do_test_splice_state_reset_on_disconnect(false);
	do_test_splice_state_reset_on_disconnect(true);
}

#[cfg(test)]
fn do_test_splice_state_reset_on_disconnect(reload: bool) {
	// Tests that we're able to forget our pending splice state after a disconnect such that we can
	// retry later.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let (persister_0a, persister_0b, persister_0c, persister_1a, persister_1b, persister_1c);
	let (
		chain_monitor_0a,
		chain_monitor_0b,
		chain_monitor_0c,
		chain_monitor_1a,
		chain_monitor_1b,
		chain_monitor_1c,
	);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let (node_0a, node_0b, node_0c, node_1a, node_1b, node_1c);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_id_0 = nodes[0].node.get_our_node_id();
	let node_id_1 = nodes[1].node.get_our_node_id();

	let (_, _, channel_id, _) =
		create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100_000, 50_000_000);

	let contribution = SpliceContribution::SpliceOut {
		outputs: vec![TxOut {
			value: Amount::from_sat(1_000),
			script_pubkey: nodes[0].wallet_source.get_change_script().unwrap(),
		}],
	};
	nodes[0]
		.node
		.splice_channel(
			&channel_id,
			&node_id_1,
			contribution.clone(),
			FEERATE_FLOOR_SATS_PER_KW,
			None,
		)
		.unwrap();

	// Attempt a splice negotiation that only goes up to receiving `splice_init`. Reconnecting
	// should implicitly abort the negotiation and reset the splice state such that we're able to
	// retry another splice later.
	let stfu = get_event_msg!(nodes[0], MessageSendEvent::SendStfu, node_id_1);
	nodes[1].node.handle_stfu(node_id_0, &stfu);
	let stfu = get_event_msg!(nodes[1], MessageSendEvent::SendStfu, node_id_0);
	nodes[0].node.handle_stfu(node_id_1, &stfu);

	let splice_init = get_event_msg!(nodes[0], MessageSendEvent::SendSpliceInit, node_id_1);
	nodes[1].node.handle_splice_init(node_id_0, &splice_init);
	let _ = get_event_msg!(nodes[1], MessageSendEvent::SendSpliceAck, node_id_0);

	if reload {
		let encoded_monitor_0 = get_monitor!(nodes[0], channel_id).encode();
		reload_node!(
			nodes[0],
			&nodes[0].node.encode(),
			&[&encoded_monitor_0],
			persister_0a,
			chain_monitor_0a,
			node_0a
		);
		let encoded_monitor_1 = get_monitor!(nodes[1], channel_id).encode();
		reload_node!(
			nodes[1],
			&nodes[1].node.encode(),
			&[&encoded_monitor_1],
			persister_1a,
			chain_monitor_1a,
			node_1a
		);
	} else {
		nodes[0].node.peer_disconnected(node_id_1);
		nodes[1].node.peer_disconnected(node_id_0);
	}

	let _event = get_event!(nodes[0], Event::SpliceFailed);

	let mut reconnect_args = ReconnectArgs::new(&nodes[0], &nodes[1]);
	reconnect_args.send_channel_ready = (true, true);
	reconnect_args.send_announcement_sigs = (true, true);
	reconnect_nodes(reconnect_args);

	nodes[0]
		.node
		.splice_channel(
			&channel_id,
			&node_id_1,
			contribution.clone(),
			FEERATE_FLOOR_SATS_PER_KW,
			None,
		)
		.unwrap();

	// Attempt a splice negotiation that ends mid-construction of the funding transaction.
	// Reconnecting should implicitly abort the negotiation and reset the splice state such that
	// we're able to retry another splice later.
	let stfu = get_event_msg!(nodes[0], MessageSendEvent::SendStfu, node_id_1);
	nodes[1].node.handle_stfu(node_id_0, &stfu);
	let stfu = get_event_msg!(nodes[1], MessageSendEvent::SendStfu, node_id_0);
	nodes[0].node.handle_stfu(node_id_1, &stfu);

	let splice_init = get_event_msg!(nodes[0], MessageSendEvent::SendSpliceInit, node_id_1);
	nodes[1].node.handle_splice_init(node_id_0, &splice_init);
	let splice_ack = get_event_msg!(nodes[1], MessageSendEvent::SendSpliceAck, node_id_0);
	nodes[0].node.handle_splice_ack(node_id_1, &splice_ack);

	let tx_add_input = get_event_msg!(nodes[0], MessageSendEvent::SendTxAddInput, node_id_1);
	nodes[1].node.handle_tx_add_input(node_id_0, &tx_add_input);
	let _ = get_event_msg!(nodes[1], MessageSendEvent::SendTxComplete, node_id_0);

	if reload {
		let encoded_monitor_0 = get_monitor!(nodes[0], channel_id).encode();
		reload_node!(
			nodes[0],
			&nodes[0].node.encode(),
			&[&encoded_monitor_0],
			persister_0b,
			chain_monitor_0b,
			node_0b
		);
		let encoded_monitor_1 = get_monitor!(nodes[1], channel_id).encode();
		reload_node!(
			nodes[1],
			&nodes[1].node.encode(),
			&[&encoded_monitor_1],
			persister_1b,
			chain_monitor_1b,
			node_1b
		);
	} else {
		nodes[0].node.peer_disconnected(node_id_1);
		nodes[1].node.peer_disconnected(node_id_0);
	}

	let _event = get_event!(nodes[0], Event::SpliceFailed);

	let mut reconnect_args = ReconnectArgs::new(&nodes[0], &nodes[1]);
	reconnect_args.send_channel_ready = (true, true);
	reconnect_args.send_announcement_sigs = (true, true);
	reconnect_nodes(reconnect_args);

	// Attempt a splice negotiation that completes, (i.e. `tx_signatures` are exchanged). Reconnecting
	// should not abort the negotiation or reset the splice state.
	let splice_tx = splice_channel(&nodes[0], &nodes[1], channel_id, contribution);

	if reload {
		let encoded_monitor_0 = get_monitor!(nodes[0], channel_id).encode();
		reload_node!(
			nodes[0],
			&nodes[0].node.encode(),
			&[&encoded_monitor_0],
			persister_0c,
			chain_monitor_0c,
			node_0c
		);
		let encoded_monitor_1 = get_monitor!(nodes[1], channel_id).encode();
		reload_node!(
			nodes[1],
			&nodes[1].node.encode(),
			&[&encoded_monitor_1],
			persister_1c,
			chain_monitor_1c,
			node_1c
		);
	} else {
		nodes[0].node.peer_disconnected(node_id_1);
		nodes[1].node.peer_disconnected(node_id_0);
	}

	let mut reconnect_args = ReconnectArgs::new(&nodes[0], &nodes[1]);
	reconnect_args.send_announcement_sigs = (true, true);
	reconnect_nodes(reconnect_args);

	mine_transaction(&nodes[0], &splice_tx);
	mine_transaction(&nodes[1], &splice_tx);
	lock_splice_after_blocks(&nodes[0], &nodes[1], ANTI_REORG_DELAY - 1);
}

#[test]
fn test_config_reject_inbound_splices() {
	// Tests that nodes with `reject_inbound_splices` properly reject inbound splices but still
	// allow outbound ones.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let mut config = test_default_channel_config();
	config.reject_inbound_splices = true;
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, Some(config)]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_id_0 = nodes[0].node.get_our_node_id();
	let node_id_1 = nodes[1].node.get_our_node_id();

	let (_, _, channel_id, _) =
		create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100_000, 50_000_000);

	let contribution = SpliceContribution::SpliceOut {
		outputs: vec![TxOut {
			value: Amount::from_sat(1_000),
			script_pubkey: nodes[0].wallet_source.get_change_script().unwrap(),
		}],
	};
	nodes[0]
		.node
		.splice_channel(
			&channel_id,
			&node_id_1,
			contribution.clone(),
			FEERATE_FLOOR_SATS_PER_KW,
			None,
		)
		.unwrap();

	let stfu = get_event_msg!(nodes[0], MessageSendEvent::SendStfu, node_id_1);
	nodes[1].node.handle_stfu(node_id_0, &stfu);
	let stfu = get_event_msg!(nodes[1], MessageSendEvent::SendStfu, node_id_0);
	nodes[0].node.handle_stfu(node_id_1, &stfu);

	let splice_init = get_event_msg!(nodes[0], MessageSendEvent::SendSpliceInit, node_id_1);
	nodes[1].node.handle_splice_init(node_id_0, &splice_init);

	let msg_events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(msg_events.len(), 1);
	if let MessageSendEvent::HandleError { action, .. } = &msg_events[0] {
		assert!(matches!(action, msgs::ErrorAction::DisconnectPeerWithWarning { .. }));
	} else {
		panic!("Expected MessageSendEvent::HandleError");
	}

	nodes[0].node.peer_disconnected(node_id_1);
	nodes[1].node.peer_disconnected(node_id_0);

	let _event = get_event!(nodes[0], Event::SpliceFailed);

	let mut reconnect_args = ReconnectArgs::new(&nodes[0], &nodes[1]);
	reconnect_args.send_channel_ready = (true, true);
	reconnect_args.send_announcement_sigs = (true, true);
	reconnect_nodes(reconnect_args);

	let _ = splice_channel(&nodes[1], &nodes[0], channel_id, contribution);
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

	lock_splice_after_blocks(&nodes[0], &nodes[1], ANTI_REORG_DELAY - 1);

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

	lock_splice_after_blocks(&nodes[0], &nodes[1], ANTI_REORG_DELAY - 1);

	let htlc_limit_msat = nodes[0].node.list_channels()[0].next_outbound_htlc_limit_msat;
	assert!(htlc_limit_msat < initial_channel_value_sat / 2 * 1000);
	let _ = send_payment(&nodes[0], &[&nodes[1]], htlc_limit_msat);
}

#[cfg(test)]
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

#[cfg(test)]
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
		lock_splice_after_blocks(&nodes[0], &nodes[1], ANTI_REORG_DELAY - 1);
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

	// When the splice never confirms and we see a commitment transaction broadcast and confirm for
	// the current funding instead, we should expect to see an `Event::DiscardFunding` for the
	// splice transaction.
	if splice_status == SpliceStatus::Unconfirmed {
		// Remove the corresponding outputs and transactions the chain source is watching for the
		// splice as it is no longer being tracked.
		connect_blocks(&nodes[0], BREAKDOWN_TIMEOUT as u32);
		let (vout, txout) = splice_tx
			.output
			.iter()
			.enumerate()
			.find(|(_, output)| output.script_pubkey.is_p2wsh())
			.unwrap();
		let funding_outpoint = OutPoint { txid: splice_tx.compute_txid(), index: vout as u16 };
		nodes[0]
			.chain_source
			.remove_watched_txn_and_outputs(funding_outpoint, txout.script_pubkey.clone());
		nodes[1]
			.chain_source
			.remove_watched_txn_and_outputs(funding_outpoint, txout.script_pubkey.clone());

		// `SpendableOutputs` events are also included here, but we don't care for them.
		let events = nodes[0].chain_monitor.chain_monitor.get_and_clear_pending_events();
		assert_eq!(events.len(), if claim_htlcs { 2 } else { 4 }, "{events:?}");
		if let Event::DiscardFunding { funding_info, .. } = &events[0] {
			assert_eq!(*funding_info, FundingInfo::OutPoint { outpoint: funding_outpoint });
		} else {
			panic!();
		}
		let events = nodes[1].chain_monitor.chain_monitor.get_and_clear_pending_events();
		assert_eq!(events.len(), if claim_htlcs { 2 } else { 1 }, "{events:?}");
		if let Event::DiscardFunding { funding_info, .. } = &events[0] {
			assert_eq!(*funding_info, FundingInfo::OutPoint { outpoint: funding_outpoint });
		} else {
			panic!();
		}
	}
}

#[test]
fn test_splice_reestablish() {
	do_test_splice_reestablish(false, false);
	do_test_splice_reestablish(false, true);
	do_test_splice_reestablish(true, false);
	do_test_splice_reestablish(true, true);
}

#[cfg(test)]
fn do_test_splice_reestablish(reload: bool, async_monitor_update: bool) {
	// Test that we're able to reestablish the channel succesfully throughout the lifecycle of a splice.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let (persister_0a, persister_0b, persister_1a, persister_1b);
	let (chain_monitor_0a, chain_monitor_0b, chain_monitor_1a, chain_monitor_1b);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let (node_0a, node_0b, node_1a, node_1b);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_id_0 = nodes[0].node.get_our_node_id();
	let node_id_1 = nodes[1].node.get_our_node_id();

	let initial_channel_value_sat = 100_000;
	let (_, _, channel_id, _) =
		create_announced_chan_between_nodes_with_value(&nodes, 0, 1, initial_channel_value_sat, 0);

	let prev_funding_outpoint = get_monitor!(nodes[0], channel_id).get_funding_txo();
	let prev_funding_script = get_monitor!(nodes[0], channel_id).get_funding_script();

	// Keep a pending HTLC throughout the reestablish flow to make sure we can handle them.
	route_payment(&nodes[0], &[&nodes[1]], 1_000_000);

	// Negotiate the splice up until the nodes exchange `tx_complete`.
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
	let initial_commit_sig_for_acceptor =
		negotiate_splice_tx(&nodes[0], &nodes[1], channel_id, initiator_contribution);
	assert_eq!(initial_commit_sig_for_acceptor.htlc_signatures.len(), 1);
	let initial_commit_sig_for_initiator = get_htlc_update_msgs!(&nodes[1], node_id_0);
	assert_eq!(initial_commit_sig_for_initiator.commitment_signed.len(), 1);
	assert_eq!(initial_commit_sig_for_initiator.commitment_signed[0].htlc_signatures.len(), 1);

	macro_rules! reconnect_nodes {
		($f: expr) => {
			nodes[0].node.peer_disconnected(node_id_1);
			nodes[1].node.peer_disconnected(node_id_0);
			let mut reconnect_args = ReconnectArgs::new(&nodes[0], &nodes[1]);
			$f(&mut reconnect_args);
			reconnect_nodes(reconnect_args);
		};
	}

	// Reestablishing now should force both nodes to retransmit their initial `commitment_signed`
	// message as they were never delivered.
	if reload {
		let encoded_monitor_0 = get_monitor!(nodes[0], channel_id).encode();
		reload_node!(
			nodes[0],
			nodes[0].node.encode(),
			&[&encoded_monitor_0],
			persister_0a,
			chain_monitor_0a,
			node_0a
		);
		let encoded_monitor_1 = get_monitor!(nodes[1], channel_id).encode();
		reload_node!(
			nodes[1],
			nodes[1].node.encode(),
			&[&encoded_monitor_1],
			persister_1a,
			chain_monitor_1a,
			node_1a
		);
		if async_monitor_update {
			persister_0a.set_update_ret(ChannelMonitorUpdateStatus::InProgress);
			persister_1a.set_update_ret(ChannelMonitorUpdateStatus::InProgress);
		}
	} else {
		nodes[0].node.peer_disconnected(node_id_1);
		nodes[1].node.peer_disconnected(node_id_0);
		if async_monitor_update {
			chanmon_cfgs[0].persister.set_update_ret(ChannelMonitorUpdateStatus::InProgress);
			chanmon_cfgs[1].persister.set_update_ret(ChannelMonitorUpdateStatus::InProgress);
		}
	}

	let mut reconnect_args = ReconnectArgs::new(&nodes[0], &nodes[1]);
	reconnect_args.send_interactive_tx_commit_sig = (true, true);
	reconnect_nodes(reconnect_args);

	// The `commitment_signed` messages were delivered in the reestablishment, so we should expect
	// to see a `RenegotiatedFunding` monitor update on both nodes.
	check_added_monitors(&nodes[0], 1);
	check_added_monitors(&nodes[1], 1);

	if async_monitor_update {
		// Reconnecting again should result in no messages/events being generated as the monitor
		// update is pending.
		reconnect_nodes!(|_| {});
		assert!(nodes[0].node.get_and_clear_pending_events().is_empty());
		assert!(nodes[1].node.get_and_clear_pending_events().is_empty());
		assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
		assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
		nodes[0].chain_monitor.complete_sole_pending_chan_update(&channel_id);
		nodes[1].chain_monitor.complete_sole_pending_chan_update(&channel_id);
		chanmon_cfgs[0].persister.set_update_ret(ChannelMonitorUpdateStatus::Completed);
		chanmon_cfgs[1].persister.set_update_ret(ChannelMonitorUpdateStatus::Completed);
	}

	// Node 0 should have a signing event to handle since they had a contribution in the splice.
	// Node 1 won't and will immediately send `tx_signatures`.
	let _ = get_event!(nodes[0], Event::FundingTransactionReadyForSigning);
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	assert!(nodes[1].node.get_and_clear_pending_events().is_empty());
	let _ = get_event_msg!(nodes[1], MessageSendEvent::SendTxSignatures, node_id_0);

	// Reconnecting now should force node 1 to retransmit their `tx_signatures` since it was never
	// delivered. Node 0 still hasn't called back with `funding_transaction_signed`, so its
	// `tx_signatures` is not ready yet.
	reconnect_nodes!(|reconnect_args: &mut ReconnectArgs| {
		reconnect_args.send_interactive_tx_sigs = (true, false);
	});
	let _ = get_event!(nodes[0], Event::FundingTransactionReadyForSigning);

	// Reconnect again to make sure node 1 doesn't retransmit `tx_signatures` unnecessarily as it
	// was delivered in the previous reestablishment.
	reconnect_nodes!(|_| {});

	// Have node 0 sign, we should see its `tx_signatures` go out.
	let event = get_event!(nodes[0], Event::FundingTransactionReadyForSigning);
	if let Event::FundingTransactionReadyForSigning { unsigned_transaction, .. } = event {
		let tx = nodes[0].wallet_source.sign_tx(unsigned_transaction).unwrap();
		nodes[0].node.funding_transaction_signed(&channel_id, &node_id_1, tx).unwrap();
	}
	let _ = get_event_msg!(nodes[0], MessageSendEvent::SendTxSignatures, node_id_1);
	expect_splice_pending_event(&nodes[0], &node_id_1);

	// Reconnect to make sure node 0 retransmits its `tx_signatures` as it was never delivered.
	reconnect_nodes!(|reconnect_args: &mut ReconnectArgs| {
		reconnect_args.send_interactive_tx_sigs = (false, true);
	});
	expect_splice_pending_event(&nodes[1], &node_id_0);

	// Reestablish the channel again to make sure node 0 doesn't retransmit `tx_signatures`
	// unnecessarily as it was delivered in the previous reestablishment.
	if reload {
		let encoded_monitor_0 = get_monitor!(nodes[0], channel_id).encode();
		reload_node!(
			nodes[0],
			nodes[0].node.encode(),
			&[&encoded_monitor_0],
			persister_0b,
			chain_monitor_0b,
			node_0b
		);
		let encoded_monitor_1 = get_monitor!(nodes[1], channel_id).encode();
		reload_node!(
			nodes[1],
			nodes[1].node.encode(),
			&[&encoded_monitor_1],
			persister_1b,
			chain_monitor_1b,
			node_1b
		);
	} else {
		nodes[0].node.peer_disconnected(node_id_1);
		nodes[1].node.peer_disconnected(node_id_0);
	}
	reconnect_nodes(ReconnectArgs::new(&nodes[0], &nodes[1]));

	// The channel should no longer be quiescent with `tx_signatures` exchanged. We should expect to
	// see the splice transaction broadcast.
	let splice_tx = {
		let mut txn_0 = nodes[0].tx_broadcaster.txn_broadcast();
		assert_eq!(txn_0.len(), 1);
		let txn_1 = nodes[1].tx_broadcaster.txn_broadcast();
		assert_eq!(txn_0, txn_1);
		txn_0.remove(0)
	};

	// Make sure we can still send payments.
	send_payment(&nodes[0], &[&nodes[1]], 1_000_000);

	// Lock in the splice on node 0. We should see its `splice_locked` sent.
	confirm_transaction(&nodes[0], &splice_tx);
	let _ = get_event_msg!(nodes[0], MessageSendEvent::SendSpliceLocked, node_id_1);

	// Confirm the splice but with one less confirmation than required on node 1. Its
	// `splice_locked` should no be sent yet.
	mine_transaction(&nodes[1], &splice_tx);
	connect_blocks(&nodes[1], ANTI_REORG_DELAY - 2);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	// Reconnect the nodes. Node 1 should assume node 0's `splice_locked` via
	// `ChannelReestablish::my_current_funding_locked`.
	reconnect_nodes!(|_| {});

	if async_monitor_update {
		chanmon_cfgs[0].persister.set_update_ret(ChannelMonitorUpdateStatus::InProgress);
		chanmon_cfgs[1].persister.set_update_ret(ChannelMonitorUpdateStatus::InProgress);
	}

	// Mine the remaining block on node 1 for the splice to be locked. Since `splice_locked` has now
	// been exchanged on node 1, we should see its `announcement_signatures` sent as well, and the
	// `RenegotiatedFundingLocked` monitor update.
	connect_blocks(&nodes[1], 1);
	check_added_monitors(&nodes[1], 1);
	let mut msg_events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(msg_events.len(), 2, "{msg_events:?}");
	if let MessageSendEvent::SendSpliceLocked { .. } = msg_events.remove(0) {
	} else {
		panic!()
	}
	if let MessageSendEvent::SendAnnouncementSignatures { .. } = msg_events.remove(0) {
	} else {
		panic!()
	}
	expect_channel_ready_event(&nodes[1], &node_id_0);

	// Reconnect the nodes to ensure node 1 retransmits its `splice_locked` (implicitly via
	// `my_current_funding_locked`) and `announcement_signatures` to node 0.
	reconnect_nodes!(|reconnect_args: &mut ReconnectArgs| {
		reconnect_args.expect_renegotiated_funding_locked_monitor_update = (true, false);
		reconnect_args.send_announcement_sigs = (true, true);
	});
	expect_channel_ready_event(&nodes[0], &node_id_1);

	if async_monitor_update {
		nodes[0].chain_monitor.complete_sole_pending_chan_update(&channel_id);
		nodes[1].chain_monitor.complete_sole_pending_chan_update(&channel_id);
		chanmon_cfgs[0].persister.set_update_ret(ChannelMonitorUpdateStatus::Completed);
		chanmon_cfgs[1].persister.set_update_ret(ChannelMonitorUpdateStatus::Completed);
	}

	// We shouldn't have any further events or messages to process.
	assert!(nodes[0].node.get_and_clear_pending_events().is_empty());
	assert!(nodes[1].node.get_and_clear_pending_events().is_empty());
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	// Make sure we can still send payments.
	send_payment(&nodes[0], &[&nodes[1]], 1_000_000);

	// Remove the previous funding info the chain source was watching to avoid failing the
	// end-of-test sanity checks.
	nodes[0]
		.chain_source
		.remove_watched_txn_and_outputs(prev_funding_outpoint, prev_funding_script.clone());
	nodes[1]
		.chain_source
		.remove_watched_txn_and_outputs(prev_funding_outpoint, prev_funding_script);
}

#[test]
fn test_propose_splice_while_disconnected() {
	do_test_propose_splice_while_disconnected(false, false);
	do_test_propose_splice_while_disconnected(false, true);
	do_test_propose_splice_while_disconnected(true, false);
	do_test_propose_splice_while_disconnected(true, true);
}

#[cfg(test)]
fn do_test_propose_splice_while_disconnected(reload: bool, use_0conf: bool) {
	// Test that both nodes are able to propose a splice while the counterparty is disconnected, and
	// whoever doesn't go first due to the quiescence tie-breaker, will retry their splice after the
	// first one becomes locked.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let (persister_0a, persister_0b, persister_1a, persister_1b);
	let (chain_monitor_0a, chain_monitor_0b, chain_monitor_1a, chain_monitor_1b);
	let mut config = test_default_channel_config();
	if use_0conf {
		config.manually_accept_inbound_channels = true;
		config.channel_handshake_limits.trust_own_funding_0conf = true;
	}
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[Some(config.clone()), Some(config)]);
	let (node_0a, node_0b, node_1a, node_1b);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_id_0 = nodes[0].node.get_our_node_id();
	let node_id_1 = nodes[1].node.get_our_node_id();

	let initial_channel_value_sat = 1_000_000;
	let push_msat = initial_channel_value_sat / 2 * 1000;
	let channel_id = if use_0conf {
		let (funding_tx, channel_id) = open_zero_conf_channel_with_value(
			&nodes[0],
			&nodes[1],
			None,
			initial_channel_value_sat,
			push_msat,
		);
		mine_transaction(&nodes[0], &funding_tx);
		mine_transaction(&nodes[1], &funding_tx);
		channel_id
	} else {
		let (_, _, channel_id, _) = create_announced_chan_between_nodes_with_value(
			&nodes,
			0,
			1,
			initial_channel_value_sat,
			push_msat,
		);
		channel_id
	};

	// Start with the nodes disconnected, and have each one attempt a splice.
	nodes[0].node.peer_disconnected(node_id_1);
	nodes[1].node.peer_disconnected(node_id_0);

	let splice_out_sat = initial_channel_value_sat / 4;
	let node_0_contribution = SpliceContribution::SpliceOut {
		outputs: vec![TxOut {
			value: Amount::from_sat(splice_out_sat),
			script_pubkey: nodes[0].wallet_source.get_change_script().unwrap(),
		}],
	};
	nodes[0]
		.node
		.splice_channel(
			&channel_id,
			&node_id_1,
			node_0_contribution.clone(),
			FEERATE_FLOOR_SATS_PER_KW,
			None,
		)
		.unwrap();
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());

	let node_1_contribution = SpliceContribution::SpliceOut {
		outputs: vec![TxOut {
			value: Amount::from_sat(splice_out_sat),
			script_pubkey: nodes[1].wallet_source.get_change_script().unwrap(),
		}],
	};
	nodes[1]
		.node
		.splice_channel(
			&channel_id,
			&node_id_0,
			node_1_contribution.clone(),
			FEERATE_FLOOR_SATS_PER_KW,
			None,
		)
		.unwrap();
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	if reload {
		let encoded_monitor_0 = get_monitor!(nodes[0], channel_id).encode();
		reload_node!(
			nodes[0],
			nodes[0].node.encode(),
			&[&encoded_monitor_0],
			persister_0a,
			chain_monitor_0a,
			node_0a
		);
		let encoded_monitor_1 = get_monitor!(nodes[1], channel_id).encode();
		reload_node!(
			nodes[1],
			nodes[1].node.encode(),
			&[&encoded_monitor_1],
			persister_1a,
			chain_monitor_1a,
			node_1a
		);
	}

	// Reconnect the nodes. Both nodes should attempt quiescence as the initiator, but only one will
	// be it via the tie-breaker.
	let mut reconnect_args = ReconnectArgs::new(&nodes[0], &nodes[1]);
	reconnect_args.send_channel_ready = (true, true);
	if !use_0conf {
		reconnect_args.send_announcement_sigs = (true, true);
	}
	reconnect_args.send_stfu = (true, true);
	reconnect_nodes(reconnect_args);
	let splice_init = get_event_msg!(nodes[0], MessageSendEvent::SendSpliceInit, node_id_1);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	let (prev_funding_outpoint, prev_funding_script) = nodes[0]
		.chain_monitor
		.chain_monitor
		.get_monitor(channel_id)
		.map(|monitor| (monitor.get_funding_txo(), monitor.get_funding_script()))
		.unwrap();

	// Negotiate the first splice to completion.
	let initial_commit_sig = {
		nodes[1].node.handle_splice_init(node_id_0, &splice_init);
		let splice_ack = get_event_msg!(nodes[1], MessageSendEvent::SendSpliceAck, node_id_0);
		nodes[0].node.handle_splice_ack(node_id_1, &splice_ack);
		let new_funding_script = chan_utils::make_funding_redeemscript(
			&splice_init.funding_pubkey,
			&splice_ack.funding_pubkey,
		)
		.to_p2wsh();
		complete_interactive_funding_negotiation(
			&nodes[0],
			&nodes[1],
			channel_id,
			node_0_contribution,
			new_funding_script,
		)
	};
	let (splice_tx, splice_locked) =
		sign_interactive_funding_tx(&nodes[0], &nodes[1], initial_commit_sig, use_0conf);
	expect_splice_pending_event(&nodes[0], &node_id_1);
	expect_splice_pending_event(&nodes[1], &node_id_0);

	let splice_locked = if use_0conf {
		let (splice_locked, for_node_id) = splice_locked.unwrap();
		assert_eq!(for_node_id, node_id_1);
		splice_locked
	} else {
		assert!(splice_locked.is_none());

		mine_transaction(&nodes[0], &splice_tx);
		mine_transaction(&nodes[1], &splice_tx);

		// Mine enough blocks for the first splice to become locked.
		connect_blocks(&nodes[0], ANTI_REORG_DELAY - 1);
		connect_blocks(&nodes[1], ANTI_REORG_DELAY - 1);

		get_event_msg!(nodes[0], MessageSendEvent::SendSpliceLocked, node_id_1)
	};
	nodes[1].node.handle_splice_locked(node_id_0, &splice_locked);

	// We should see the node which lost the tie-breaker attempt their splice now by first
	// negotiating quiescence, but their `stfu` won't be sent until after another reconnection.
	let msg_events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(msg_events.len(), if use_0conf { 2 } else { 3 }, "{msg_events:?}");
	if let MessageSendEvent::SendSpliceLocked { ref msg, .. } = &msg_events[0] {
		nodes[0].node.handle_splice_locked(node_id_1, msg);
		if use_0conf {
			// TODO(splicing): Revisit splice transaction rebroadcasts.
			let txn_0 = nodes[0].tx_broadcaster.txn_broadcast();
			assert_eq!(txn_0.len(), 1);
			assert_eq!(&txn_0[0], &splice_tx);
			mine_transaction(&nodes[0], &splice_tx);
			mine_transaction(&nodes[1], &splice_tx);
		}
	} else {
		panic!("Unexpected event {:?}", &msg_events[0]);
	}
	if !use_0conf {
		if let MessageSendEvent::SendAnnouncementSignatures { ref msg, .. } = &msg_events[1] {
			nodes[0].node.handle_announcement_signatures(node_id_1, msg);
		} else {
			panic!("Unexpected event {:?}", &msg_events[1]);
		}
	}
	assert!(matches!(
		&msg_events[if use_0conf { 1 } else { 2 }],
		MessageSendEvent::SendStfu { .. }
	));

	let msg_events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(msg_events.len(), if use_0conf { 0 } else { 2 }, "{msg_events:?}");
	if !use_0conf {
		if let MessageSendEvent::SendAnnouncementSignatures { ref msg, .. } = &msg_events[0] {
			nodes[1].node.handle_announcement_signatures(node_id_0, msg);
		} else {
			panic!("Unexpected event {:?}", &msg_events[1]);
		}
		assert!(matches!(&msg_events[1], MessageSendEvent::BroadcastChannelAnnouncement { .. }));
	}

	let msg_events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(msg_events.len(), if use_0conf { 0 } else { 1 }, "{msg_events:?}");
	if !use_0conf {
		assert!(matches!(&msg_events[0], MessageSendEvent::BroadcastChannelAnnouncement { .. }));
	}

	expect_channel_ready_event(&nodes[0], &node_id_1);
	check_added_monitors(&nodes[0], 1);
	expect_channel_ready_event(&nodes[1], &node_id_0);
	check_added_monitors(&nodes[1], 1);

	// Remove the corresponding outputs and transactions the chain source is watching for the
	// old funding as it is no longer being tracked.
	nodes[0]
		.chain_source
		.remove_watched_txn_and_outputs(prev_funding_outpoint, prev_funding_script.clone());
	nodes[1]
		.chain_source
		.remove_watched_txn_and_outputs(prev_funding_outpoint, prev_funding_script);

	// Reconnect the nodes. This should trigger the node which lost the tie-breaker to resend `stfu`
	// for their splice attempt.
	if reload {
		let encoded_monitor_0 = get_monitor!(nodes[0], channel_id).encode();
		reload_node!(
			nodes[0],
			nodes[0].node.encode(),
			&[&encoded_monitor_0],
			persister_0b,
			chain_monitor_0b,
			node_0b
		);
		let encoded_monitor_1 = get_monitor!(nodes[1], channel_id).encode();
		reload_node!(
			nodes[1],
			nodes[1].node.encode(),
			&[&encoded_monitor_1],
			persister_1b,
			chain_monitor_1b,
			node_1b
		);
	} else {
		nodes[0].node.peer_disconnected(node_id_1);
		nodes[1].node.peer_disconnected(node_id_0);
	}
	let mut reconnect_args = ReconnectArgs::new(&nodes[0], &nodes[1]);
	if !use_0conf {
		reconnect_args.send_announcement_sigs = (true, true);
	}
	reconnect_args.send_stfu = (true, false);
	reconnect_nodes(reconnect_args);

	// Drive the second splice to completion.
	let msg_events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(msg_events.len(), 1, "{msg_events:?}");
	if let MessageSendEvent::SendStfu { ref msg, .. } = msg_events[0] {
		nodes[1].node.handle_stfu(node_id_0, msg);
	} else {
		panic!("Unexpected event {:?}", &msg_events[0]);
	}

	let splice_init = get_event_msg!(nodes[1], MessageSendEvent::SendSpliceInit, node_id_0);
	let initial_commit_sig = {
		nodes[0].node.handle_splice_init(node_id_1, &splice_init);
		let splice_ack = get_event_msg!(nodes[0], MessageSendEvent::SendSpliceAck, node_id_1);
		nodes[1].node.handle_splice_ack(node_id_0, &splice_ack);
		let new_funding_script = chan_utils::make_funding_redeemscript(
			&splice_init.funding_pubkey,
			&splice_ack.funding_pubkey,
		)
		.to_p2wsh();
		complete_interactive_funding_negotiation(
			&nodes[1],
			&nodes[0],
			channel_id,
			node_1_contribution,
			new_funding_script,
		)
	};
	let (splice_tx, splice_locked) =
		sign_interactive_funding_tx(&nodes[1], &nodes[0], initial_commit_sig, use_0conf);
	expect_splice_pending_event(&nodes[0], &node_id_1);
	expect_splice_pending_event(&nodes[1], &node_id_0);

	if use_0conf {
		let (splice_locked, for_node_id) = splice_locked.unwrap();
		assert_eq!(for_node_id, node_id_0);
		lock_splice(&nodes[1], &nodes[0], &splice_locked, true);
	} else {
		assert!(splice_locked.is_none());
		mine_transaction(&nodes[0], &splice_tx);
		mine_transaction(&nodes[1], &splice_tx);
		lock_splice_after_blocks(&nodes[1], &nodes[0], ANTI_REORG_DELAY - 1);
	}

	// Sanity check that we can still make a test payment.
	send_payment(&nodes[0], &[&nodes[1]], 1_000_000);
}

#[test]
fn disconnect_on_unexpected_interactive_tx_message() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let config = test_default_anchors_channel_config();
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[Some(config.clone()), Some(config)]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let initiator = &nodes[0];
	let acceptor = &nodes[1];

	let _node_id_initiator = initiator.node.get_our_node_id();
	let node_id_acceptor = acceptor.node.get_our_node_id();

	let initial_channel_capacity = 100_000;
	let (_, _, channel_id, _) =
		create_announced_chan_between_nodes_with_value(&nodes, 0, 1, initial_channel_capacity, 0);

	let coinbase_tx = provide_anchor_reserves(&nodes);
	let splice_in_amount = initial_channel_capacity / 2;
	let contribution = SpliceContribution::SpliceIn {
		value: Amount::from_sat(splice_in_amount),
		inputs: vec![FundingTxInput::new_p2wpkh(coinbase_tx, 0).unwrap()],
		change_script: Some(nodes[0].wallet_source.get_change_script().unwrap()),
	};

	// Complete interactive-tx construction, but fail by having the acceptor send a duplicate
	// tx_complete instead of commitment_signed.
	let _ = negotiate_splice_tx(initiator, acceptor, channel_id, contribution.clone());

	let mut msg_events = acceptor.node.get_and_clear_pending_msg_events();
	assert_eq!(msg_events.len(), 1);
	assert!(matches!(msg_events.remove(0), MessageSendEvent::UpdateHTLCs { .. }));

	let tx_complete = msgs::TxComplete { channel_id };
	initiator.node.handle_tx_complete(node_id_acceptor, &tx_complete);

	let _warning = get_warning_msg(initiator, &node_id_acceptor);
}

#[test]
fn fail_splice_on_interactive_tx_error() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let config = test_default_anchors_channel_config();
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[Some(config.clone()), Some(config)]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let initiator = &nodes[0];
	let acceptor = &nodes[1];

	let node_id_initiator = initiator.node.get_our_node_id();
	let node_id_acceptor = acceptor.node.get_our_node_id();

	let initial_channel_capacity = 100_000;
	let (_, _, channel_id, _) =
		create_announced_chan_between_nodes_with_value(&nodes, 0, 1, initial_channel_capacity, 0);

	let coinbase_tx = provide_anchor_reserves(&nodes);
	let splice_in_amount = initial_channel_capacity / 2;
	let contribution = SpliceContribution::SpliceIn {
		value: Amount::from_sat(splice_in_amount),
		inputs: vec![FundingTxInput::new_p2wpkh(coinbase_tx, 0).unwrap()],
		change_script: Some(nodes[0].wallet_source.get_change_script().unwrap()),
	};

	// Fail during interactive-tx construction by having the acceptor echo back tx_add_input instead
	// of sending tx_complete. The failure occurs because the serial id will have the wrong parity.
	let _ = complete_splice_handshake(initiator, acceptor, channel_id, contribution.clone());

	let tx_add_input =
		get_event_msg!(initiator, MessageSendEvent::SendTxAddInput, node_id_acceptor);
	acceptor.node.handle_tx_add_input(node_id_initiator, &tx_add_input);

	let _tx_complete =
		get_event_msg!(acceptor, MessageSendEvent::SendTxComplete, node_id_initiator);
	initiator.node.handle_tx_add_input(node_id_acceptor, &tx_add_input);

	let event = get_event!(initiator, Event::SpliceFailed);
	match event {
		Event::SpliceFailed { contributed_inputs, .. } => {
			assert_eq!(contributed_inputs.len(), 1);
			assert_eq!(contributed_inputs[0], contribution.inputs()[0].outpoint());
		},
		_ => panic!("Expected Event::SpliceFailed"),
	}

	let tx_abort = get_event_msg!(initiator, MessageSendEvent::SendTxAbort, node_id_acceptor);
	acceptor.node.handle_tx_abort(node_id_initiator, &tx_abort);

	let tx_abort = get_event_msg!(acceptor, MessageSendEvent::SendTxAbort, node_id_initiator);
	initiator.node.handle_tx_abort(node_id_acceptor, &tx_abort);

	// Fail signing the commitment transaction, which prevents the initiator from sending
	// tx_complete.
	initiator.disable_channel_signer_op(
		&node_id_acceptor,
		&channel_id,
		SignerOp::SignCounterpartyCommitment,
	);
	let _ = complete_splice_handshake(initiator, acceptor, channel_id, contribution.clone());

	let tx_add_input =
		get_event_msg!(initiator, MessageSendEvent::SendTxAddInput, node_id_acceptor);
	acceptor.node.handle_tx_add_input(node_id_initiator, &tx_add_input);

	let tx_complete = get_event_msg!(acceptor, MessageSendEvent::SendTxComplete, node_id_initiator);
	initiator.node.handle_tx_complete(node_id_acceptor, &tx_complete);

	let tx_add_input =
		get_event_msg!(initiator, MessageSendEvent::SendTxAddInput, node_id_acceptor);
	acceptor.node.handle_tx_add_input(node_id_initiator, &tx_add_input);

	let tx_complete = get_event_msg!(acceptor, MessageSendEvent::SendTxComplete, node_id_initiator);
	initiator.node.handle_tx_complete(node_id_acceptor, &tx_complete);

	let tx_add_output =
		get_event_msg!(initiator, MessageSendEvent::SendTxAddOutput, node_id_acceptor);
	acceptor.node.handle_tx_add_output(node_id_initiator, &tx_add_output);

	let tx_complete = get_event_msg!(acceptor, MessageSendEvent::SendTxComplete, node_id_initiator);
	initiator.node.handle_tx_complete(node_id_acceptor, &tx_complete);

	let tx_add_output =
		get_event_msg!(initiator, MessageSendEvent::SendTxAddOutput, node_id_acceptor);
	acceptor.node.handle_tx_add_output(node_id_initiator, &tx_add_output);

	let tx_complete = get_event_msg!(acceptor, MessageSendEvent::SendTxComplete, node_id_initiator);
	initiator.node.handle_tx_complete(node_id_acceptor, &tx_complete);

	let event = get_event!(initiator, Event::SpliceFailed);
	match event {
		Event::SpliceFailed { contributed_inputs, .. } => {
			assert_eq!(contributed_inputs.len(), 1);
			assert_eq!(contributed_inputs[0], contribution.inputs()[0].outpoint());
		},
		_ => panic!("Expected Event::SpliceFailed"),
	}

	let tx_abort = get_event_msg!(initiator, MessageSendEvent::SendTxAbort, node_id_acceptor);
	acceptor.node.handle_tx_abort(node_id_initiator, &tx_abort);

	let tx_abort = get_event_msg!(acceptor, MessageSendEvent::SendTxAbort, node_id_initiator);
	initiator.node.handle_tx_abort(node_id_acceptor, &tx_abort);
}

#[test]
fn fail_splice_on_tx_abort() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let config = test_default_anchors_channel_config();
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[Some(config.clone()), Some(config)]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let initiator = &nodes[0];
	let acceptor = &nodes[1];

	let node_id_initiator = initiator.node.get_our_node_id();
	let node_id_acceptor = acceptor.node.get_our_node_id();

	let initial_channel_capacity = 100_000;
	let (_, _, channel_id, _) =
		create_announced_chan_between_nodes_with_value(&nodes, 0, 1, initial_channel_capacity, 0);

	let coinbase_tx = provide_anchor_reserves(&nodes);
	let splice_in_amount = initial_channel_capacity / 2;
	let contribution = SpliceContribution::SpliceIn {
		value: Amount::from_sat(splice_in_amount),
		inputs: vec![FundingTxInput::new_p2wpkh(coinbase_tx, 0).unwrap()],
		change_script: Some(nodes[0].wallet_source.get_change_script().unwrap()),
	};

	// Fail during interactive-tx construction by having the acceptor send tx_abort instead of
	// tx_complete.
	let _ = complete_splice_handshake(initiator, acceptor, channel_id, contribution.clone());

	let tx_add_input =
		get_event_msg!(initiator, MessageSendEvent::SendTxAddInput, node_id_acceptor);
	acceptor.node.handle_tx_add_input(node_id_initiator, &tx_add_input);

	let _tx_complete =
		get_event_msg!(acceptor, MessageSendEvent::SendTxComplete, node_id_initiator);

	acceptor.node.abandon_splice(&channel_id, &node_id_initiator).unwrap();
	let tx_abort = get_event_msg!(acceptor, MessageSendEvent::SendTxAbort, node_id_initiator);
	initiator.node.handle_tx_abort(node_id_acceptor, &tx_abort);

	let event = get_event!(initiator, Event::SpliceFailed);
	match event {
		Event::SpliceFailed { contributed_inputs, .. } => {
			assert_eq!(contributed_inputs.len(), 1);
			assert_eq!(contributed_inputs[0], contribution.inputs()[0].outpoint());
		},
		_ => panic!("Expected Event::SpliceFailed"),
	}

	let tx_abort = get_event_msg!(initiator, MessageSendEvent::SendTxAbort, node_id_acceptor);
	acceptor.node.handle_tx_abort(node_id_initiator, &tx_abort);
}

#[test]
fn fail_splice_on_channel_close() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let config = test_default_anchors_channel_config();
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[Some(config.clone()), Some(config)]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let initiator = &nodes[0];
	let acceptor = &nodes[1];

	let _node_id_initiator = initiator.node.get_our_node_id();
	let node_id_acceptor = acceptor.node.get_our_node_id();

	let initial_channel_capacity = 100_000;
	let (_, _, channel_id, _) =
		create_announced_chan_between_nodes_with_value(&nodes, 0, 1, initial_channel_capacity, 0);

	let coinbase_tx = provide_anchor_reserves(&nodes);
	let splice_in_amount = initial_channel_capacity / 2;
	let contribution = SpliceContribution::SpliceIn {
		value: Amount::from_sat(splice_in_amount),
		inputs: vec![FundingTxInput::new_p2wpkh(coinbase_tx, 0).unwrap()],
		change_script: Some(nodes[0].wallet_source.get_change_script().unwrap()),
	};

	// Close the channel before completion of interactive-tx construction.
	let _ = complete_splice_handshake(initiator, acceptor, channel_id, contribution.clone());
	let _tx_add_input =
		get_event_msg!(initiator, MessageSendEvent::SendTxAddInput, node_id_acceptor);

	initiator
		.node
		.force_close_broadcasting_latest_txn(&channel_id, &node_id_acceptor, "test".to_owned())
		.unwrap();
	handle_bump_events(initiator, true, 0);
	check_closed_events(
		&nodes[0],
		&[ExpectedCloseEvent {
			channel_id: Some(channel_id),
			discard_funding: false,
			splice_failed: true,
			channel_funding_txo: None,
			user_channel_id: Some(42),
			..Default::default()
		}],
	);
	check_closed_broadcast(&nodes[0], 1, true);
	check_added_monitors(&nodes[0], 1);
}

#[test]
fn fail_quiescent_action_on_channel_close() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let config = test_default_anchors_channel_config();
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[Some(config.clone()), Some(config)]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let initiator = &nodes[0];
	let acceptor = &nodes[1];

	let _node_id_initiator = initiator.node.get_our_node_id();
	let node_id_acceptor = acceptor.node.get_our_node_id();

	let initial_channel_capacity = 100_000;
	let (_, _, channel_id, _) =
		create_announced_chan_between_nodes_with_value(&nodes, 0, 1, initial_channel_capacity, 0);

	let coinbase_tx = provide_anchor_reserves(&nodes);
	let splice_in_amount = initial_channel_capacity / 2;
	let contribution = SpliceContribution::SpliceIn {
		value: Amount::from_sat(splice_in_amount),
		inputs: vec![FundingTxInput::new_p2wpkh(coinbase_tx, 0).unwrap()],
		change_script: Some(nodes[0].wallet_source.get_change_script().unwrap()),
	};

	// Close the channel before completion of STFU handshake.
	initiator
		.node
		.splice_channel(
			&channel_id,
			&node_id_acceptor,
			contribution,
			FEERATE_FLOOR_SATS_PER_KW,
			None,
		)
		.unwrap();

	let _stfu_init = get_event_msg!(initiator, MessageSendEvent::SendStfu, node_id_acceptor);

	initiator
		.node
		.force_close_broadcasting_latest_txn(&channel_id, &node_id_acceptor, "test".to_owned())
		.unwrap();
	handle_bump_events(initiator, true, 0);
	check_closed_events(
		&nodes[0],
		&[ExpectedCloseEvent {
			channel_id: Some(channel_id),
			discard_funding: false,
			splice_failed: true,
			channel_funding_txo: None,
			user_channel_id: Some(42),
			..Default::default()
		}],
	);
	check_closed_broadcast(&nodes[0], 1, true);
	check_added_monitors(&nodes[0], 1);
}

#[cfg(test)]
fn do_test_splice_with_inflight_htlc_forward_and_resolution(expire_scid_pre_forward: bool) {
	// Test that we are still able to forward and resolve HTLCs while the original SCIDs contained
	// in the onion packets have now changed due channel splices becoming locked.
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let mut config = test_default_channel_config();
	config.channel_config.cltv_expiry_delta = CHANNEL_ANNOUNCEMENT_PROPAGATION_DELAY as u16 * 2;
	let node_chanmgrs = create_node_chanmgrs(
		3,
		&node_cfgs,
		&[Some(config.clone()), Some(config.clone()), Some(config)],
	);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	let node_id_0 = nodes[0].node.get_our_node_id();
	let node_id_1 = nodes[1].node.get_our_node_id();
	let node_id_2 = nodes[2].node.get_our_node_id();

	let (_, _, channel_id_0_1, _) = create_announced_chan_between_nodes(&nodes, 0, 1);
	let (chan_upd_1_2, _, channel_id_1_2, _) = create_announced_chan_between_nodes(&nodes, 1, 2);

	let node_max_height =
		nodes.iter().map(|node| node.blocks.lock().unwrap().len()).max().unwrap() as u32;
	connect_blocks(&nodes[0], node_max_height - nodes[0].best_block_info().1);
	connect_blocks(&nodes[1], node_max_height - nodes[1].best_block_info().1);
	connect_blocks(&nodes[2], node_max_height - nodes[2].best_block_info().1);

	// Send an outbound HTLC from node 0 to 2.
	let payment_amount = 1_000_000;
	let payment_params =
		PaymentParameters::from_node_id(node_id_2, CHANNEL_ANNOUNCEMENT_PROPAGATION_DELAY * 2)
			.with_bolt11_features(nodes[2].node.bolt11_invoice_features())
			.unwrap();
	let route_params =
		RouteParameters::from_payment_params_and_value(payment_params, payment_amount);
	let route = get_route(&nodes[0], &route_params).unwrap();
	let (_, payment_hash, payment_secret) =
		get_payment_preimage_hash(&nodes[2], Some(payment_amount), None);
	let onion = RecipientOnionFields::secret_only(payment_secret);
	let id = PaymentId(payment_hash.0);
	nodes[0].node.send_payment_with_route(route.clone(), payment_hash, onion, id).unwrap();
	check_added_monitors(&nodes[0], 1);

	// Node 1 should now have a pending HTLC to forward to 2.
	let update_add_0_1 = get_htlc_update_msgs(&nodes[0], &node_id_1);
	nodes[1].node.handle_update_add_htlc(node_id_0, &update_add_0_1.update_add_htlcs[0]);
	commitment_signed_dance!(nodes[1], nodes[0], update_add_0_1.commitment_signed, false);
	assert!(nodes[1].node.needs_pending_htlc_processing());

	// Splice both channels, lock them, and connect enough blocks to trigger the legacy SCID pruning
	// logic while the HTLC is still pending.
	let contribution = SpliceContribution::SpliceOut {
		outputs: vec![TxOut {
			value: Amount::from_sat(1_000),
			script_pubkey: nodes[0].wallet_source.get_change_script().unwrap(),
		}],
	};
	let splice_tx_0_1 = splice_channel(&nodes[0], &nodes[1], channel_id_0_1, contribution);
	for node in &nodes {
		mine_transaction(node, &splice_tx_0_1);
	}

	let contribution = SpliceContribution::SpliceOut {
		outputs: vec![TxOut {
			value: Amount::from_sat(1_000),
			script_pubkey: nodes[1].wallet_source.get_change_script().unwrap(),
		}],
	};
	let splice_tx_1_2 = splice_channel(&nodes[1], &nodes[2], channel_id_1_2, contribution);
	for node in &nodes {
		mine_transaction(node, &splice_tx_1_2);
	}

	for node in &nodes {
		connect_blocks(node, ANTI_REORG_DELAY - 2);
	}
	let splice_locked = get_event_msg!(nodes[0], MessageSendEvent::SendSpliceLocked, node_id_1);
	lock_splice(&nodes[0], &nodes[1], &splice_locked, false);

	for node in &nodes {
		connect_blocks(node, 1);
	}
	let splice_locked = get_event_msg!(nodes[1], MessageSendEvent::SendSpliceLocked, node_id_2);
	lock_splice(&nodes[1], &nodes[2], &splice_locked, false);

	if expire_scid_pre_forward {
		for node in &nodes {
			connect_blocks(node, CHANNEL_ANNOUNCEMENT_PROPAGATION_DELAY);
		}

		// Now attempt to forward the HTLC from node 1 to 2 which will fail because the SCID is no
		// longer stored and has expired. Obviously this is somewhat of an absurd case - not
		// forwarding for `CHANNEL_ANNOUNCEMENT_PROPAGATION_DELAY` blocks is kinda nuts.
		let fail_type = HTLCHandlingFailureType::InvalidForward {
			requested_forward_scid: chan_upd_1_2.contents.short_channel_id,
		};
		expect_htlc_forwarding_fails(&nodes[1], &[fail_type]);
		check_added_monitors(&nodes[1], 1);
		let update_fail_1_0 = get_htlc_update_msgs(&nodes[1], &node_id_0);
		nodes[0].node.handle_update_fail_htlc(node_id_1, &update_fail_1_0.update_fail_htlcs[0]);
		commitment_signed_dance!(nodes[0], nodes[1], update_fail_1_0.commitment_signed, false);

		let conditions = PaymentFailedConditions::new();
		expect_payment_failed_conditions(&nodes[0], payment_hash, false, conditions);
	} else {
		// Now attempt to forward the HTLC from node 1 to 2.
		nodes[1].node.process_pending_htlc_forwards();
		check_added_monitors(&nodes[1], 1);
		let update_add_1_2 = get_htlc_update_msgs(&nodes[1], &node_id_2);
		nodes[2].node.handle_update_add_htlc(node_id_1, &update_add_1_2.update_add_htlcs[0]);
		commitment_signed_dance!(nodes[2], nodes[1], update_add_1_2.commitment_signed, false);
		assert!(nodes[2].node.needs_pending_htlc_processing());

		// Node 2 should see the claimable payment. Fail it back to make sure we also handle the SCID
		// change on the way back.
		nodes[2].node.process_pending_htlc_forwards();
		expect_payment_claimable!(&nodes[2], payment_hash, payment_secret, payment_amount);
		nodes[2].node.fail_htlc_backwards(&payment_hash);
		let fail_type = HTLCHandlingFailureType::Receive { payment_hash };
		expect_and_process_pending_htlcs_and_htlc_handling_failed(&nodes[2], &[fail_type]);
		check_added_monitors(&nodes[2], 1);

		let update_fail_1_2 = get_htlc_update_msgs(&nodes[2], &node_id_1);
		nodes[1].node.handle_update_fail_htlc(node_id_2, &update_fail_1_2.update_fail_htlcs[0]);
		commitment_signed_dance!(nodes[1], nodes[2], update_fail_1_2.commitment_signed, false);
		let fail_type = HTLCHandlingFailureType::Forward {
			node_id: Some(node_id_2),
			channel_id: channel_id_1_2,
		};
		expect_and_process_pending_htlcs_and_htlc_handling_failed(&nodes[1], &[fail_type]);
		check_added_monitors(&nodes[1], 1);

		let update_fail_0_1 = get_htlc_update_msgs(&nodes[1], &node_id_0);
		nodes[0].node.handle_update_fail_htlc(node_id_1, &update_fail_0_1.update_fail_htlcs[0]);
		commitment_signed_dance!(nodes[0], nodes[1], update_fail_0_1.commitment_signed, false);

		let conditions = PaymentFailedConditions::new();
		expect_payment_failed_conditions(&nodes[0], payment_hash, true, conditions);
	}
}

#[test]
fn test_splice_with_inflight_htlc_forward_and_resolution() {
	do_test_splice_with_inflight_htlc_forward_and_resolution(true);
	do_test_splice_with_inflight_htlc_forward_and_resolution(false);
}
