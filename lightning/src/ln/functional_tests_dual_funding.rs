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
use crate::ln::ChannelId;
use crate::ln::channel::ChannelPhase;
use crate::ln::functional_test_utils::*;
use crate::ln::msgs::ChannelMessageHandler;
use crate::util::ser::Writeable;
use crate::util::config::{ChannelHandshakeConfig, UserConfig};
use crate::prelude::*;
use crate::chain::chaininterface::{ConfirmationTarget, FeeEstimator};

use bitcoin::{Transaction, TxOut, Witness};
use bitcoin::blockdata::opcodes;
use bitcoin::blockdata::script::{Builder, ScriptBuf};
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};

use hex::DisplayHex;
use core::default::Default;


// Create a 2-of-2 multisig redeem script. Return the script, and the two keys in the order they appear in the script.
fn create_multisig_redeem_script(key1: &PublicKey, key2: &PublicKey) -> (ScriptBuf, PublicKey, PublicKey) {
	let (smaller_key, larger_key) = if key1.serialize() < key2.serialize() {
		(key1, key2)
	} else {
		(key2, key1)
	};
	let script = Builder::new()
		.push_opcode(opcodes::all::OP_PUSHNUM_2)
		.push_slice(&smaller_key.serialize())
		.push_slice(&larger_key.serialize())
		.push_opcode(opcodes::all::OP_PUSHNUM_2)
		.push_opcode(opcodes::all::OP_CHECKMULTISIG)
		.into_script();
	(script, smaller_key.clone(), larger_key.clone())
}

// Create an output script for a 2-of-2 multisig.
fn create_multisig_output_script(key1: &PublicKey, key2: &PublicKey) -> ScriptBuf {
	let (redeem_script, _k1, _k2) = create_multisig_redeem_script(key1, key2);
	Builder::new()
		.push_opcode(opcodes::all::OP_PUSHBYTES_0)
		.push_slice(&AsRef::<[u8; 32]>::as_ref(&redeem_script.wscript_hash()))
		.into_script()
}

// Verify a 2-of-2 multisig output script.
fn verify_multisig_output_script(script: &ScriptBuf, exp_key_1: &PublicKey, exp_key_2: &PublicKey) {
	let exp_script = create_multisig_output_script(exp_key_1, exp_key_2);
	assert_eq!(script.to_hex_string(), exp_script.to_hex_string());
}

// Get the funding key of a node towards another node
fn get_funding_key(node: &Node, counterparty_node: &Node, channel_id: &ChannelId) -> PublicKey {
	let per_peer_state = node.node.per_peer_state.read().unwrap();
	let chan_lock = per_peer_state.get(&counterparty_node.node.get_our_node_id()).unwrap().lock().unwrap();
	let local_chan = chan_lock.channel_by_id.get(&channel_id).map(
		|phase| match phase {
			ChannelPhase::Funded(chan) => Some(chan),
			ChannelPhase::FundingV2(chans) => chans.get_funded_channel(),
			_ => None,
		}
	).flatten().unwrap();
	local_chan.get_signer().as_ref().pubkeys().funding_pubkey
}

/// Verify the funding output of a funding tx
fn verify_funding_output(funding_txo: &TxOut, funding_key_1: &PublicKey, funding_key_2: &PublicKey) {
	let act_script = &funding_txo.script_pubkey;
	verify_multisig_output_script(&act_script, funding_key_1, funding_key_2);
}

/// Do checks on a funding tx
fn verify_funding_tx(funding_tx: &Transaction, value: u64, funding_key_1: &PublicKey, funding_key_2: &PublicKey) {
	// find the output with the given value
	let mut funding_output_opt: Option<&TxOut> = None;
	for o in &funding_tx.output {
		if o.value == value {
			funding_output_opt = Some(o);
		}
	}
	if funding_output_opt.is_none() {
		panic!("Funding output not found, no output with value {}", value);
	}
	verify_funding_output(funding_output_opt.unwrap(), funding_key_1, funding_key_2)
}

/// End-to-end V2 open channel flow, with close, and verification checks.
/// The steps are mostly on ChannelManager level.
#[test]
fn test_channel_open_v2_and_close() {
	// Set up a network of 2 nodes
	let cfg = UserConfig {
		channel_handshake_config: ChannelHandshakeConfig {
			announced_channel: true,
			..Default::default()
		},
		..Default::default()
	};
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, Some(cfg)]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	// Initiator and Acceptor nodes. Order matters, we want the case when initiator pubkey is larger.
	let initiator_node_index = 0;
	let acceptor_node_index = 1;
	let initiator_node = &nodes[initiator_node_index];
	let acceptor_node = &nodes[acceptor_node_index];

	// Instantiate channel parameters where we push the maximum msats given our funding satoshis
	let channel_value_sat = 100000; // same as funding satoshis

	let expected_temporary_channel_id = "b1a3942f261316385476c86d7f454062ceb06d2e37675f08c2fac76b8c3ddc5e";
	let expected_funded_channel_id = "0df1425050bb045209e23459ebb5f9c8f6f219dafb85e2ec59d5fe841f1c4463";

	let extra_funding_input_sats = channel_value_sat + 35_000;
	let custom_input_secret_key = SecretKey::from_slice(&[2; 32]).unwrap();
	let funding_inputs = vec![create_custom_dual_funding_input_with_pubkey(&initiator_node, extra_funding_input_sats, &PublicKey::from_secret_key(&Secp256k1::new(), &custom_input_secret_key))];
	// Have node0 initiate a channel to node1 with aforementioned parameters
	let channel_id_temp1 = initiator_node.node.create_dual_funded_channel(acceptor_node.node.get_our_node_id(), channel_value_sat, funding_inputs, None, 42, None).unwrap();
	assert_eq!(channel_id_temp1.to_string(), expected_temporary_channel_id);

	// Extract the channel open message from node0 to node1
	let open_channel2_message = get_event_msg!(initiator_node, MessageSendEvent::SendOpenChannelV2, acceptor_node.node.get_our_node_id());
	assert_eq!(initiator_node.node.list_channels().len(), 1);

	let _res = acceptor_node.node.handle_open_channel_v2(&initiator_node.node.get_our_node_id(), &open_channel2_message.clone());
	// Extract the accept channel message from node1 to node0
	let accept_channel2_message = get_event_msg!(acceptor_node, MessageSendEvent::SendAcceptChannelV2, initiator_node.node.get_our_node_id());
	assert_eq!(accept_channel2_message.common_fields.temporary_channel_id.to_string(), expected_temporary_channel_id);

	let _res = initiator_node.node.handle_accept_channel_v2(&acceptor_node.node.get_our_node_id(), &accept_channel2_message.clone());

	// Note: FundingInputsContributionReady event is no longer used
	// Note: contribute_funding_inputs() call is no longer used

	// let events = acceptor_node.node.get_and_clear_pending_events();
	// println!("acceptor_node events: {}", events.len());
	// assert_eq!(events.len(), 0);

	// initiator_node will generate a TxAddInput message to kickstart the interactive transaction construction protocol
	let tx_add_input_msg = get_event_msg!(&initiator_node, MessageSendEvent::SendTxAddInput, acceptor_node.node.get_our_node_id());

	let _res = acceptor_node.node.handle_tx_add_input(&initiator_node.node.get_our_node_id(), &tx_add_input_msg);
	let tx_complete_msg = get_event_msg!(acceptor_node, MessageSendEvent::SendTxComplete, initiator_node.node.get_our_node_id());

	let _res = initiator_node.node.handle_tx_complete(&acceptor_node.node.get_our_node_id(), &tx_complete_msg);

	// First output, the funding tx
	let tx_add_output_msg = get_event_msg!(&initiator_node, MessageSendEvent::SendTxAddOutput, acceptor_node.node.get_our_node_id());
	assert!(tx_add_output_msg.script.is_v0_p2wsh());
	assert_eq!(tx_add_output_msg.sats, channel_value_sat); 

	let _res = acceptor_node.node.handle_tx_add_output(&initiator_node.node.get_our_node_id(), &tx_add_output_msg);
	let tx_complete_msg = get_event_msg!(&acceptor_node, MessageSendEvent::SendTxComplete, initiator_node.node.get_our_node_id());

	let _res = initiator_node.node.handle_tx_complete(&acceptor_node.node.get_our_node_id(), &tx_complete_msg);
	let tx_add_output_msg = get_event_msg!(&initiator_node, MessageSendEvent::SendTxAddOutput, acceptor_node.node.get_our_node_id());
	// Second output, change
	let _actual_change_output = tx_add_output_msg.sats;
	assert!(tx_add_output_msg.script.is_v0_p2wpkh());

	let _res = acceptor_node.node.handle_tx_add_output(&initiator_node.node.get_our_node_id(), &tx_add_output_msg);
	let tx_complete_msg = get_event_msg!(acceptor_node, MessageSendEvent::SendTxComplete, initiator_node.node.get_our_node_id());

	let _res = initiator_node.node.handle_tx_complete(&acceptor_node.node.get_our_node_id(), &tx_complete_msg);
	let msg_events = initiator_node.node.get_and_clear_pending_msg_events();
	assert_eq!(msg_events.len(), 2);
	let tx_complete_msg = match msg_events[0] {
		MessageSendEvent::SendTxComplete { ref node_id, ref msg } => {
			assert_eq!(*node_id, acceptor_node.node.get_our_node_id());
			(*msg).clone()
		},
		_ => panic!("Unexpected event"),
	};
	let msg_commitment_signed_from_0 = match msg_events[1] {
		MessageSendEvent::UpdateHTLCs { ref node_id, ref updates } => {
			assert_eq!(*node_id, acceptor_node.node.get_our_node_id());
			updates.commitment_signed.clone()
		},
		_ => panic!("Unexpected event"),
	};
	let channel_id1 = if let Event::FundingTransactionReadyForSigning {
		channel_id,
		counterparty_node_id,
		mut unsigned_transaction,
		..
	} = get_event!(initiator_node, Event::FundingTransactionReadyForSigning) {
		assert_eq!(channel_id.to_string(), expected_funded_channel_id);
		assert_eq!(counterparty_node_id, acceptor_node.node.get_our_node_id());

		// placeholder signature
		let mut witness = Witness::new();
		witness.push([7; 72]);
		unsigned_transaction.input[0].witness = witness;

		let _res = initiator_node.node.funding_transaction_signed(&channel_id, &counterparty_node_id, unsigned_transaction).unwrap();
		channel_id
	} else { panic!(); };

	let _res = acceptor_node.node.handle_tx_complete(&initiator_node.node.get_our_node_id(), &tx_complete_msg);
	let msg_events = acceptor_node.node.get_and_clear_pending_msg_events();
	// First messsage is commitment_signed, second is tx_signatures (see below for more)
	assert_eq!(msg_events.len(), 1);
	let msg_commitment_signed_from_1 = match msg_events[0] {
		MessageSendEvent::UpdateHTLCs { ref node_id, ref updates } => {
			assert_eq!(*node_id, initiator_node.node.get_our_node_id());
			updates.commitment_signed.clone()
		},
		_ => panic!("Unexpected event {:?}", msg_events[0]),
	};

	// Handle the initial commitment_signed exchange. Order is not important here.
	acceptor_node.node.handle_commitment_signed(&initiator_node.node.get_our_node_id(), &msg_commitment_signed_from_0);
	initiator_node.node.handle_commitment_signed(&acceptor_node.node.get_our_node_id(), &msg_commitment_signed_from_1);
	check_added_monitors(&initiator_node, 1);
	check_added_monitors(&acceptor_node, 1);

	// The initiator is the only party that contributed any inputs so they should definitely be the one to send tx_signatures
	// only after receiving tx_signatures from the non-initiator in this case.
	let msg_events = initiator_node.node.get_and_clear_pending_msg_events();
	assert!(msg_events.is_empty());
	let tx_signatures_from_1 = get_event_msg!(acceptor_node, MessageSendEvent::SendTxSignatures, initiator_node.node.get_our_node_id());

	let _res = initiator_node.node.handle_tx_signatures(&acceptor_node.node.get_our_node_id(), &tx_signatures_from_1);
	let events_0 = initiator_node.node.get_and_clear_pending_events();
	assert_eq!(events_0.len(), 1);
	match events_0[0] {
		Event::ChannelPending{ ref channel_id, ref counterparty_node_id, ref is_splice, .. } => {
			assert_eq!(channel_id.to_string(), expected_funded_channel_id);
			assert_eq!(*counterparty_node_id, acceptor_node.node.get_our_node_id());
			assert!(!is_splice);
		},
		_ => panic!("Unexpected event"),
	}
	let tx_signatures_from_0 = get_event_msg!(initiator_node, MessageSendEvent::SendTxSignatures, acceptor_node.node.get_our_node_id());
	let _res = acceptor_node.node.handle_tx_signatures(&initiator_node.node.get_our_node_id(), &tx_signatures_from_0);
	let events_1 = acceptor_node.node.get_and_clear_pending_events();
	assert_eq!(events_1.len(), 1);
	match events_1[0] {
		Event::ChannelPending{ ref channel_id, ref counterparty_node_id, ref is_splice, .. } => {
			assert_eq!(channel_id.to_string(), expected_funded_channel_id);
			assert_eq!(*counterparty_node_id, initiator_node.node.get_our_node_id());
			assert!(!is_splice);
		},
		_ => panic!("Unexpected event"),
	}

	// Check that funding transaction has been broadcasted
	assert_eq!(chanmon_cfgs[initiator_node_index].tx_broadcaster.txn_broadcasted.lock().unwrap().len(), 1);
	let broadcasted_funding_tx = chanmon_cfgs[initiator_node_index].tx_broadcaster.txn_broadcasted.lock().unwrap()[0].clone();
	let expected_funding_tx = "020000000001019c76affec45612929f824230eacc67dc7b3db1072c39d0e62f4f557a34e141fc000000000000000000021c88000000000000160014d5a9aa98b89acc215fc3d23d6fec0ad59ca3665fa08601000000000022002034c0cc0ad0dd5fe61dcf7ef58f995e3d34f8dbd24aa2a6fae68fefe102bf025c014807070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070700000000";
	assert_eq!(broadcasted_funding_tx.encode().len(), 201);
	assert_eq!(&broadcasted_funding_tx.encode().as_hex().to_string(), expected_funding_tx);
	// Check that funding transaction has been broadcasted on the acceptor side as well
	assert_eq!(chanmon_cfgs[acceptor_node_index].tx_broadcaster.txn_broadcasted.lock().unwrap().len(), 1);
	let broadcasted_funding_tx_acc = chanmon_cfgs[acceptor_node_index].tx_broadcaster.txn_broadcasted.lock().unwrap()[0].clone();
	assert_eq!(broadcasted_funding_tx_acc.encode().len(), 201);
	assert_eq!(&broadcasted_funding_tx_acc.encode().as_hex().to_string(), expected_funding_tx);

	// check fees
	let total_input = extra_funding_input_sats;
	assert_eq!(broadcasted_funding_tx.output.len(), 2);
	let total_output = broadcasted_funding_tx.output[0].value + broadcasted_funding_tx.output[1].value;
	assert!(total_input > total_output);
	let fee = total_input - total_output;
	let target_fee_rate = chanmon_cfgs[0].fee_estimator.get_est_sat_per_1000_weight(ConfirmationTarget::NonAnchorChannelFee); // target is irrelevant
	assert_eq!(target_fee_rate, 253);
	assert_eq!(broadcasted_funding_tx.weight().to_wu(), 576);
	let expected_minimum_fee = (broadcasted_funding_tx.weight().to_wu() as f64 * target_fee_rate as f64 / 1000 as f64).ceil() as u64;
	let expected_maximum_fee = expected_minimum_fee * 3;
	assert!(fee >= expected_minimum_fee);
	assert!(fee <= expected_maximum_fee);

	// Simulate confirmation of the funding tx
	confirm_transaction(&initiator_node, &broadcasted_funding_tx);
	let channel_ready_message = get_event_msg!(initiator_node, MessageSendEvent::SendChannelReady, acceptor_node.node.get_our_node_id());

	confirm_transaction(&acceptor_node, &broadcasted_funding_tx);
	let channel_ready_message2 = get_event_msg!(acceptor_node, MessageSendEvent::SendChannelReady, initiator_node.node.get_our_node_id());

	let _res = acceptor_node.node.handle_channel_ready(&initiator_node.node.get_our_node_id(), &channel_ready_message);
	let _ev = get_event!(acceptor_node, Event::ChannelReady);
	let _announcement_signatures = get_event_msg!(acceptor_node, MessageSendEvent::SendAnnouncementSignatures, initiator_node.node.get_our_node_id());

	let _res = initiator_node.node.handle_channel_ready(&acceptor_node.node.get_our_node_id(), &channel_ready_message2);
	let _ev = get_event!(initiator_node, Event::ChannelReady);
	let _announcement_signatures = get_event_msg!(initiator_node, MessageSendEvent::SendAnnouncementSignatures, acceptor_node.node.get_our_node_id());

	// check channel capacity and other parameters
	assert_eq!(initiator_node.node.list_channels().len(), 1);
	let channel = &initiator_node.node.list_channels()[0];
	{
		assert_eq!(channel.channel_id.to_string(), expected_funded_channel_id);
		assert!(channel.is_usable);
		assert!(channel.is_channel_ready);
		assert_eq!(channel.channel_value_satoshis, channel_value_sat);
		assert_eq!(channel.balance_msat, 1000 * channel_value_sat);
		assert_eq!(channel.confirmations.unwrap(), 10);
	}
	// do checks on the acceptor node as well (capacity, etc.)
	assert_eq!(acceptor_node.node.list_channels().len(), 1);
	{
		let channel = &acceptor_node.node.list_channels()[0];
		assert_eq!(channel.channel_id.to_string(), expected_funded_channel_id);
		assert!(channel.is_usable);
		assert!(channel.is_channel_ready);
		assert_eq!(channel.balance_msat, 0);
		assert_eq!(channel.confirmations.unwrap(), 10);
	}

	// Verify the funding transaction
	let initiator_funding_key = get_funding_key(&initiator_node, &acceptor_node, &channel_id1);
	let acceptor_funding_key = get_funding_key(&acceptor_node, &initiator_node, &channel_id1);

	verify_funding_tx(&broadcasted_funding_tx, channel_value_sat, &initiator_funding_key, &acceptor_funding_key);

	// Channel is ready now for normal operation

	// close channel, cooperatively
	initiator_node.node.close_channel(&channel_id1, &acceptor_node.node.get_our_node_id()).unwrap();
	let node0_shutdown_message = get_event_msg!(initiator_node, MessageSendEvent::SendShutdown, acceptor_node.node.get_our_node_id());
	acceptor_node.node.handle_shutdown(&initiator_node.node.get_our_node_id(), &node0_shutdown_message);
	let nodes_1_shutdown = get_event_msg!(acceptor_node, MessageSendEvent::SendShutdown, initiator_node.node.get_our_node_id());
	initiator_node.node.handle_shutdown(&acceptor_node.node.get_our_node_id(), &nodes_1_shutdown);
	let _ = get_event_msg!(initiator_node, MessageSendEvent::SendClosingSigned, acceptor_node.node.get_our_node_id());
}

fn do_v2_channel_establishment_with_rbf(which_tx_to_confirm: u8) {
	// Set up a network of 2 nodes
	let cfg = UserConfig {
		channel_handshake_config: ChannelHandshakeConfig {
			announced_channel: true,
			..Default::default()
		},
		..Default::default()
	};
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, Some(cfg)]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	// Initiator and Acceptor nodes. Order matters, we want the case when initiator pubkey is larger.
	let initiator_node_index = 0;
	let acceptor_node_index = 1;
	let initiator_node = &nodes[initiator_node_index];
	let acceptor_node = &nodes[acceptor_node_index];

	// Instantiate channel parameters where we push the maximum msats given our funding satoshis
	let channel_value_sat = 100000; // same as funding satoshis

	let expected_temporary_channel_id = "b1a3942f261316385476c86d7f454062ceb06d2e37675f08c2fac76b8c3ddc5e";
	let expected_funded_channel_id = "0df1425050bb045209e23459ebb5f9c8f6f219dafb85e2ec59d5fe841f1c4463";

	let extra_funding_input_sats = channel_value_sat + 35_000;
	let custom_input_secret_key = SecretKey::from_slice(&[2; 32]).unwrap();
	let funding_inputs = vec![create_custom_dual_funding_input_with_pubkey(&initiator_node, extra_funding_input_sats, &PublicKey::from_secret_key(&Secp256k1::new(), &custom_input_secret_key))];
	// Have node0 initiate a channel to node1 with aforementioned parameters
	let channel_id_temp1 = initiator_node.node.create_dual_funded_channel(
		acceptor_node.node.get_our_node_id(), channel_value_sat, funding_inputs.clone(),
		Some(ConfirmationTarget::AnchorChannelFee), 42, None,
	).unwrap();
	assert_eq!(channel_id_temp1.to_string(), expected_temporary_channel_id);

	// Extract the channel open message from node0 to node1
	let open_channel_v2_msg = get_event_msg!(initiator_node, MessageSendEvent::SendOpenChannelV2, acceptor_node.node.get_our_node_id());
	assert_eq!(initiator_node.node.list_channels().len(), 1);
	assert_eq!(initiator_node.node.list_channels()[0].channel_id.to_string(), expected_temporary_channel_id);

	let _res = acceptor_node.node.handle_open_channel_v2(&initiator_node.node.get_our_node_id(), &open_channel_v2_msg);
	// Extract the accept channel message from node1 to node0
	let accept_channel2_message = get_event_msg!(acceptor_node, MessageSendEvent::SendAcceptChannelV2, initiator_node.node.get_our_node_id());
	assert_eq!(accept_channel2_message.common_fields.temporary_channel_id.to_string(), expected_temporary_channel_id);
	assert_eq!(acceptor_node.node.list_channels().len(), 1);

	let _res = initiator_node.node.handle_accept_channel_v2(&acceptor_node.node.get_our_node_id(), &accept_channel2_message);

	// Note: FundingInputsContributionReady event is no longer used
	// Note: contribute_funding_inputs() call is no longer used

	// let events = acceptor_node.node.get_and_clear_pending_events();
	// println!("acceptor_node events: {}", events.len());
	// assert_eq!(events.len(), 0);

	// initiator_node will generate a TxAddInput message to kickstart the interactive transaction construction protocol
	let tx_add_input_msg = get_event_msg!(&initiator_node, MessageSendEvent::SendTxAddInput, acceptor_node.node.get_our_node_id());

	let input_value = tx_add_input_msg.prevtx.as_transaction().output[tx_add_input_msg.prevtx_out as usize].value;
	assert_eq!(input_value, extra_funding_input_sats);

	let _res = acceptor_node.node.handle_tx_add_input(&initiator_node.node.get_our_node_id(), &tx_add_input_msg);

	let tx_complete_msg = get_event_msg!(acceptor_node, MessageSendEvent::SendTxComplete, initiator_node.node.get_our_node_id());
	assert_eq!(tx_complete_msg.channel_id.to_string(), expected_funded_channel_id);

	let _res = initiator_node.node.handle_tx_complete(&acceptor_node.node.get_our_node_id(), &tx_complete_msg);

	// First output, the funding tx
	let tx_add_output_msg = get_event_msg!(&initiator_node, MessageSendEvent::SendTxAddOutput, acceptor_node.node.get_our_node_id());

	let _res = acceptor_node.node.handle_tx_add_output(&initiator_node.node.get_our_node_id(), &tx_add_output_msg);
	let tx_complete_msg = get_event_msg!(acceptor_node, MessageSendEvent::SendTxComplete, initiator_node.node.get_our_node_id());

	let _res = initiator_node.node.handle_tx_complete(&acceptor_node.node.get_our_node_id(), &tx_complete_msg);

	let tx_add_output_msg = get_event_msg!(&initiator_node, MessageSendEvent::SendTxAddOutput, acceptor_node.node.get_our_node_id());
	// Second output, change
	let _actual_change_output = tx_add_output_msg.sats;
	assert!(tx_add_output_msg.script.is_v0_p2wpkh());

	let _res = acceptor_node.node.handle_tx_add_output(&initiator_node.node.get_our_node_id(), &tx_add_output_msg);
	let tx_complete_msg = get_event_msg!(acceptor_node, MessageSendEvent::SendTxComplete, initiator_node.node.get_our_node_id());

	let _res = initiator_node.node.handle_tx_complete(&acceptor_node.node.get_our_node_id(), &tx_complete_msg);
	let msg_events = initiator_node.node.get_and_clear_pending_msg_events();
	assert_eq!(msg_events.len(), 2);
	let tx_complete_msg = match msg_events[0] {
		MessageSendEvent::SendTxComplete { ref node_id, ref msg } => {
			assert_eq!(*node_id, acceptor_node.node.get_our_node_id());
			(*msg).clone()
		},
		_ => panic!("Unexpected event"),
	};
	let msg_commitment_signed_from_0 = match msg_events[1] {
		MessageSendEvent::UpdateHTLCs { ref node_id, ref updates } => {
			assert_eq!(*node_id, acceptor_node.node.get_our_node_id());
			updates.commitment_signed.clone()
		},
		_ => panic!("Unexpected event"),
	};
	let channel_id1 = if let Event::FundingTransactionReadyForSigning {
		channel_id,
		counterparty_node_id,
		mut unsigned_transaction,
		..
	} = get_event!(initiator_node, Event::FundingTransactionReadyForSigning) {
		assert_eq!(channel_id.to_string(), expected_funded_channel_id);
		assert_eq!(counterparty_node_id, acceptor_node.node.get_our_node_id());

		// placeholder signature
		let mut witness = Witness::new();
		witness.push([7; 72]);
		unsigned_transaction.input[0].witness = witness;

		let _res = initiator_node.node.funding_transaction_signed(&channel_id, &counterparty_node_id, unsigned_transaction).unwrap();
		channel_id
	} else { panic!(); };

	let _res = acceptor_node.node.handle_tx_complete(&initiator_node.node.get_our_node_id(), &tx_complete_msg);
	let msg_events = acceptor_node.node.get_and_clear_pending_msg_events();
	assert_eq!(msg_events.len(), 1);
	let msg_commitment_signed_from_1 = match msg_events[0] {
		MessageSendEvent::UpdateHTLCs { ref node_id, ref updates } => {
			assert_eq!(*node_id, initiator_node.node.get_our_node_id());
			updates.commitment_signed.clone()
		},
		_ => panic!("Unexpected event {:?}", msg_events[0]),
	};
	// Handle the initial commitment_signed exchange. Order is not important here.
	acceptor_node.node.handle_commitment_signed(&initiator_node.node.get_our_node_id(), &msg_commitment_signed_from_0);
	initiator_node.node.handle_commitment_signed(&acceptor_node.node.get_our_node_id(), &msg_commitment_signed_from_1);
	check_added_monitors(&initiator_node, 1);
	check_added_monitors(&acceptor_node, 1);
	let tx_signatures_exchange = |first: usize, second: usize| {
		let msg_events = nodes[second].node.get_and_clear_pending_msg_events();
		assert!(msg_events.is_empty());
		let tx_signatures_from_first = get_event_msg!(nodes[first], MessageSendEvent::SendTxSignatures, nodes[second].node.get_our_node_id());
		nodes[second].node.handle_tx_signatures(&nodes[first].node.get_our_node_id(), &tx_signatures_from_first);
		let events_0 = nodes[second].node.get_and_clear_pending_events();
		assert_eq!(events_0.len(), 1);
		match events_0[0] {
			Event::ChannelPending{ ref counterparty_node_id, .. } => {
				assert_eq!(*counterparty_node_id, nodes[first].node.get_our_node_id());
			},
			_ => panic!("Unexpected event"),
		}
		let tx_signatures_from_second = get_event_msg!(nodes[second], MessageSendEvent::SendTxSignatures, nodes[first].node.get_our_node_id());
		nodes[first].node.handle_tx_signatures(&nodes[second].node.get_our_node_id(), &tx_signatures_from_second);
		let events_1 = nodes[first].node.get_and_clear_pending_events();
		assert_eq!(events_1.len(), 1);
		match events_1[0] {
			Event::ChannelPending{ ref counterparty_node_id, .. } => {
				assert_eq!(*counterparty_node_id, nodes[second].node.get_our_node_id());
			},
			_ => panic!("Unexpected event"),
		}
	};
	tx_signatures_exchange(1, 0);
	let tx_1 = {
		let tx_0 = &initiator_node.tx_broadcaster.txn_broadcasted.lock().unwrap()[0];
		let tx_1 = &acceptor_node.tx_broadcaster.txn_broadcasted.lock().unwrap()[0];
		assert_eq!(tx_0, tx_1);
		tx_0.clone()
	};
	let expected_tx1_id = "951459a816fd3e1105bd8b623b004c5fdf640e82c306f473b50c42097610dcdf";
	assert_eq!(tx_1.txid().to_string(), expected_tx1_id);

	println!("Start RBF");

	// Initiator sends an RBF
	let rbf_2nd_feerate = 506;
	let extra_funding_input_sats_2 = channel_value_sat + 36_000;
	let funding_inputs_2 = vec![create_custom_dual_funding_input_with_pubkey(&initiator_node, extra_funding_input_sats_2, &PublicKey::from_secret_key(&Secp256k1::new(), &custom_input_secret_key))];

	let res_channel_id = initiator_node.node.rbf_on_pending_v2_channel_open(
		acceptor_node.node.get_our_node_id(),
		channel_id1,
		funding_inputs_2,
		rbf_2nd_feerate,
		0,
	).unwrap();
	assert_eq!(res_channel_id.to_string(), expected_funded_channel_id);

	let rbf_msg = get_event_msg!(initiator_node, MessageSendEvent::SendTxInitRbf, acceptor_node.node.get_our_node_id());
	assert_eq!(initiator_node.node.list_channels().len(), 1);

	// handle init_rbf on acceptor side
	let _res = acceptor_node.node.handle_tx_init_rbf(&initiator_node.node.get_our_node_id(), &rbf_msg);
	let ack_rbf_msg = get_event_msg!(acceptor_node, MessageSendEvent::SendTxAckRbf, initiator_node.node.get_our_node_id());
	assert_eq!(acceptor_node.node.list_channels().len(), 1);

	// handle ack_rbf on initator side
	let _res = initiator_node.node.handle_tx_ack_rbf(&acceptor_node.node.get_our_node_id(), &ack_rbf_msg);

	let tx_add_input_msg = get_event_msg!(&initiator_node, MessageSendEvent::SendTxAddInput, acceptor_node.node.get_our_node_id());
	let input_value = tx_add_input_msg.prevtx.as_transaction().output[tx_add_input_msg.prevtx_out as usize].value;
	assert_eq!(input_value, extra_funding_input_sats_2);

	acceptor_node.node.handle_tx_add_input(&initiator_node.node.get_our_node_id(), &tx_add_input_msg);

	let tx_complete_msg = get_event_msg!(acceptor_node, MessageSendEvent::SendTxComplete, initiator_node.node.get_our_node_id());
	assert_eq!(tx_complete_msg.channel_id.to_string(), expected_funded_channel_id);

	initiator_node.node.handle_tx_complete(&acceptor_node.node.get_our_node_id(), &tx_complete_msg);

	let tx_add_output_msg = get_event_msg!(&initiator_node, MessageSendEvent::SendTxAddOutput, acceptor_node.node.get_our_node_id());
	acceptor_node.node.handle_tx_add_output(&initiator_node.node.get_our_node_id(), &tx_add_output_msg);

	let tx_complete_msg = get_event_msg!(acceptor_node, MessageSendEvent::SendTxComplete, initiator_node.node.get_our_node_id());
	initiator_node.node.handle_tx_complete(&acceptor_node.node.get_our_node_id(), &tx_complete_msg);

	let msg_events = initiator_node.node.get_and_clear_pending_msg_events();
	assert_eq!(msg_events.len(), 2);
	let tx_complete_msg = match msg_events[0] {
		MessageSendEvent::SendTxComplete { ref node_id, ref msg } => {
			assert_eq!(*node_id, acceptor_node.node.get_our_node_id());
			(*msg).clone()
		},
		_ => panic!("Unexpected event"),
	};
	let msg_commitment_signed_from_0 = match msg_events[1] {
		MessageSendEvent::UpdateHTLCs { ref node_id, ref updates } => {
			assert_eq!(*node_id, acceptor_node.node.get_our_node_id());
			updates.commitment_signed.clone()
		},
		_ => panic!("Unexpected event"),
	};
	if let Event::FundingTransactionReadyForSigning {
		channel_id,
		counterparty_node_id,
		mut unsigned_transaction,
		..
	} = get_event!(initiator_node, Event::FundingTransactionReadyForSigning) {
		assert_eq!(counterparty_node_id, acceptor_node.node.get_our_node_id());
		assert_eq!(channel_id.to_string(), expected_funded_channel_id);

		// placeholder signature
		let mut witness = Witness::new();
		witness.push([7; 72]);
		unsigned_transaction.input[0].witness = witness;

		initiator_node.node.funding_transaction_signed(&channel_id, &counterparty_node_id, unsigned_transaction).unwrap();
	} else { panic!(); }

	acceptor_node.node.handle_tx_complete(&initiator_node.node.get_our_node_id(), &tx_complete_msg);
	let msg_events = acceptor_node.node.get_and_clear_pending_msg_events();
	assert_eq!(msg_events.len(), 1);
	let msg_commitment_signed_from_1 = match msg_events[0] {
		MessageSendEvent::UpdateHTLCs { ref node_id, ref updates } => {
			assert_eq!(*node_id, initiator_node.node.get_our_node_id());
			updates.commitment_signed.clone()
		},
		_ => panic!("Unexpected event"),
	};

	// Handle the initial commitment_signed exchange. Order is not important here.
	acceptor_node.node.handle_commitment_signed(&initiator_node.node.get_our_node_id(), &msg_commitment_signed_from_0);
	initiator_node.node.handle_commitment_signed(&acceptor_node.node.get_our_node_id(), &msg_commitment_signed_from_1);
	check_added_monitors(&initiator_node, 1);
	check_added_monitors(&acceptor_node, 1);

	let tx_signatures_exchange = |first: usize, second: usize| {
		let msg_events = nodes[second].node.get_and_clear_pending_msg_events();
		assert!(msg_events.is_empty());
		let tx_signatures_from_first = get_event_msg!(nodes[first], MessageSendEvent::SendTxSignatures, nodes[second].node.get_our_node_id());

		nodes[second].node.handle_tx_signatures(&nodes[first].node.get_our_node_id(), &tx_signatures_from_first);
		let events_0 = nodes[second].node.get_and_clear_pending_events();
		assert_eq!(events_0.len(), 1);
		match events_0[0] {
			Event::ChannelPending{ ref counterparty_node_id, .. } => {
				assert_eq!(*counterparty_node_id, nodes[first].node.get_our_node_id());
			},
			_ => panic!("Unexpected event"),
		}
		let tx_signatures_from_second = get_event_msg!(nodes[second], MessageSendEvent::SendTxSignatures, nodes[first].node.get_our_node_id());
		nodes[first].node.handle_tx_signatures(&nodes[second].node.get_our_node_id(), &tx_signatures_from_second);
		let events_1 = nodes[first].node.get_and_clear_pending_events();
		assert_eq!(events_1.len(), 1);
		match events_1[0] {
			Event::ChannelPending{ ref counterparty_node_id, .. } => {
				assert_eq!(*counterparty_node_id, nodes[second].node.get_our_node_id());
			},
			_ => panic!("Unexpected event"),
		}
	};
	tx_signatures_exchange(1, 0);

	let tx_2 = {
		let tx_0 = &initiator_node.tx_broadcaster.txn_broadcasted.lock().unwrap()[1];
		let tx_1 = &acceptor_node.tx_broadcaster.txn_broadcasted.lock().unwrap()[1];
		assert_eq!(tx_0, tx_1);
		tx_0.clone()
	};
	let expected_tx2_id = "7166c11ccdaef23c8670ee4ac83fc35d9015b3895e36dd8e6b4ee64b33c09ace";
	assert_eq!(tx_2.txid().to_string(), expected_tx2_id);


	// Confirm tx
	let tx_to_confirm = match which_tx_to_confirm {
		1 => tx_1,
		2 | _ => tx_2,
	};

	// Simulate confirmation of the funding tx
	confirm_transaction(&initiator_node, &tx_to_confirm);
	let channel_ready_message = get_event_msg!(initiator_node, MessageSendEvent::SendChannelReady, acceptor_node.node.get_our_node_id());

	confirm_transaction(&acceptor_node, &tx_to_confirm);
	let channel_ready_message2 = get_event_msg!(acceptor_node, MessageSendEvent::SendChannelReady, initiator_node.node.get_our_node_id());

	let _res = acceptor_node.node.handle_channel_ready(&initiator_node.node.get_our_node_id(), &channel_ready_message);
	let _ev = get_event!(acceptor_node, Event::ChannelReady);
	let _announcement_signatures = get_event_msg!(acceptor_node, MessageSendEvent::SendAnnouncementSignatures, initiator_node.node.get_our_node_id());

	let _res = initiator_node.node.handle_channel_ready(&acceptor_node.node.get_our_node_id(), &channel_ready_message2);
	let _ev = get_event!(initiator_node, Event::ChannelReady);
	let _announcement_signatures = get_event_msg!(initiator_node, MessageSendEvent::SendAnnouncementSignatures, acceptor_node.node.get_our_node_id());

	// check channel capacity and other parameters
	assert_eq!(initiator_node.node.list_channels().len(), 1);
	let channel = &initiator_node.node.list_channels()[0];
	{
		assert_eq!(channel.channel_id.to_string(), expected_funded_channel_id);
		assert!(channel.is_usable);
		assert!(channel.is_channel_ready);
		assert_eq!(channel.channel_value_satoshis, channel_value_sat);
		assert_eq!(channel.balance_msat, 1000 * channel_value_sat);
		assert_eq!(channel.confirmations.unwrap(), 10);
	}
	// do checks on the acceptor node as well (capacity, etc.)
	assert_eq!(acceptor_node.node.list_channels().len(), 1);
	{
		let channel = &acceptor_node.node.list_channels()[0];
		assert_eq!(channel.channel_id.to_string(), expected_funded_channel_id);
		assert!(channel.is_usable);
		assert!(channel.is_channel_ready);
		assert_eq!(channel.balance_msat, 0);
		assert_eq!(channel.confirmations.unwrap(), 10);
	}

	// Channel is ready now for normal operation

	// close channel, cooperatively
	initiator_node.node.close_channel(&channel_id1, &acceptor_node.node.get_our_node_id()).unwrap();
	let node0_shutdown_message = get_event_msg!(initiator_node, MessageSendEvent::SendShutdown, acceptor_node.node.get_our_node_id());
	acceptor_node.node.handle_shutdown(&initiator_node.node.get_our_node_id(), &node0_shutdown_message);
	let nodes_1_shutdown = get_event_msg!(acceptor_node, MessageSendEvent::SendShutdown, initiator_node.node.get_our_node_id());
	initiator_node.node.handle_shutdown(&acceptor_node.node.get_our_node_id(), &nodes_1_shutdown);
	let _ = get_event_msg!(initiator_node, MessageSendEvent::SendClosingSigned, acceptor_node.node.get_our_node_id());
}

#[test]
fn test_v2_channel_establishment_with_rbf_conf_1st() {
	do_v2_channel_establishment_with_rbf(1);
}

#[test]
fn test_v2_channel_establishment_with_rbf_conf_2nd() {
	do_v2_channel_establishment_with_rbf(2);
}
