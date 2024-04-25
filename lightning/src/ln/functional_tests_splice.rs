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
use bitcoin::hash_types::Txid;
use bitcoin::secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use bitcoin::secp256k1::ecdsa::Signature;
use bitcoin::sighash::{EcdsaSighashType, SighashCache};

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

// Verify a 2-of-2 multisig redeem script. Return the same keys, but in the order as they appear in the script
fn verify_multisig_redeem_script(script: &Vec<u8>, exp_key_1: &PublicKey, exp_key_2: &PublicKey)  -> (PublicKey, PublicKey) {
	let (exp_script,exp_smaller_key, exp_larger_key) = create_multisig_redeem_script(exp_key_1, exp_key_2);
	assert_eq!(script.as_hex().to_string(), exp_script.as_bytes().as_hex().to_string());
	(exp_smaller_key, exp_larger_key)
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
		|phase| if let ChannelPhase::Funded(chan) = phase { Some(chan) } else { None }
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

/// Simple end-to-end open channel flow, with close, and verification checks.
/// The steps are mostly on ChannelManager level.
#[test]
fn test_channel_open_and_close() {
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
	let initiator_node = &nodes[initiator_node_index];
	let acceptor_node = &nodes[1];

	// Instantiate channel parameters where we push the maximum msats given our funding satoshis
	let channel_value_sat = 100000; // same as funding satoshis
	let push_msat = 0;

	let expected_temporary_channel_id = "2f64bdc25fb91c69b6f15b6fc10b32eb773471e433681dc956d9267a4dda8c2b";
	let expected_funded_channel_id = "74c52ab4f11296d62b66a6dba9513b04a3e7fb5a09a30cee22fce7294ab55b7e";

	// Have node0 initiate a channel to node1 with aforementioned parameters
	let channel_id_temp1 = initiator_node.node.create_channel(acceptor_node.node.get_our_node_id(), channel_value_sat, push_msat, 42, None, None).unwrap();
	assert_eq!(channel_id_temp1.to_string(), expected_temporary_channel_id);

	// Extract the channel open message from node0 to node1
	let open_channel_message = get_event_msg!(initiator_node, MessageSendEvent::SendOpenChannel, acceptor_node.node.get_our_node_id());

	let _res = acceptor_node.node.handle_open_channel(&initiator_node.node.get_our_node_id(), &open_channel_message.clone());
	// Extract the accept channel message from node1 to node0
	let accept_channel_message = get_event_msg!(acceptor_node, MessageSendEvent::SendAcceptChannel, initiator_node.node.get_our_node_id());
	let _res = initiator_node.node.handle_accept_channel(&acceptor_node.node.get_our_node_id(), &accept_channel_message.clone());
	// Note: FundingGenerationReady emitted, checked and used below
	let (channel_id_temp2, funding_tx, _funding_output) = create_funding_transaction(&initiator_node, &acceptor_node.node.get_our_node_id(), channel_value_sat, 42);
	assert_eq!(channel_id_temp2.to_string(), expected_temporary_channel_id);
	assert_eq!(funding_tx.encode().len(), 55);
	let expected_funding_tx = "0000000000010001a08601000000000022002034c0cc0ad0dd5fe61dcf7ef58f995e3d34f8dbd24aa2a6fae68fefe102bf025c00000000";
	assert_eq!(&funding_tx.encode().as_hex().to_string(), expected_funding_tx);

	// Funding transation created, provide it
	let _res = initiator_node.node.funding_transaction_generated(&channel_id_temp1, &acceptor_node.node.get_our_node_id(), funding_tx.clone()).unwrap();

	let funding_created_message = get_event_msg!(initiator_node, MessageSendEvent::SendFundingCreated, acceptor_node.node.get_our_node_id());
	assert_eq!(funding_created_message.temporary_channel_id.to_string(), expected_temporary_channel_id);

	let _res = acceptor_node.node.handle_funding_created(&initiator_node.node.get_our_node_id(), &funding_created_message);

	let funding_signed_message = get_event_msg!(acceptor_node, MessageSendEvent::SendFundingSigned, initiator_node.node.get_our_node_id());
	let _res = initiator_node.node.handle_funding_signed(&acceptor_node.node.get_our_node_id(), &funding_signed_message);
	// Take new channel ID
	let channel_id2 = funding_signed_message.channel_id;
	assert_eq!(channel_id2.to_string(), expected_funded_channel_id);

	// Check that funding transaction has been broadcasted
	assert_eq!(chanmon_cfgs[initiator_node_index].tx_broadcaster.txn_broadcasted.lock().unwrap().len(), 1);
	let broadcasted_funding_tx = chanmon_cfgs[initiator_node_index].tx_broadcaster.txn_broadcasted.lock().unwrap()[0].clone();
	assert_eq!(broadcasted_funding_tx.encode().len(), 55);
	assert_eq!(broadcasted_funding_tx.txid(), funding_tx.txid());
	assert_eq!(broadcasted_funding_tx.encode(), funding_tx.encode());
	assert_eq!(&broadcasted_funding_tx.encode().as_hex().to_string(), expected_funding_tx);
	// // Check that funding transaction has been broadcasted on the acceptor side too
	// assert_eq!(chanmon_cfgs[acceptor_node_index].tx_broadcaster.txn_broadcasted.lock().unwrap().len(), 1);
	// let broadcasted_funding_tx_acc = chanmon_cfgs[acceptor_node_index].tx_broadcaster.txn_broadcasted.lock().unwrap()[0].clone();
	// assert_eq!(broadcasted_funding_tx_acc.encode().len(), 55);
	// assert_eq!(broadcasted_funding_tx_acc.txid(), funding_tx.txid());
	// assert_eq!(&broadcasted_funding_tx_acc.encode().as_hex().to_string(), expected_funding_tx);

	check_added_monitors!(initiator_node, 1);
	let _ev = get_event!(initiator_node, Event::ChannelPending);
	check_added_monitors!(acceptor_node, 1);
	let _ev = get_event!(acceptor_node, Event::ChannelPending);

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
		assert_eq!(channel.funding_txo.unwrap().txid, funding_tx.txid());
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
		assert_eq!(channel.balance_msat, 0);
		assert_eq!(channel.funding_txo.unwrap().txid, funding_tx.txid());
		assert_eq!(channel.confirmations.unwrap(), 10);
	}

	// Verify the funding transaction
	let initiator_funding_key = get_funding_key(&initiator_node, &acceptor_node, &channel.channel_id);
	let acceptor_funding_key = get_funding_key(&acceptor_node, &initiator_node, &channel.channel_id);

	verify_funding_tx(&broadcasted_funding_tx, channel_value_sat, &initiator_funding_key, &acceptor_funding_key);

	// Channel is ready now for normal operation

	// close channel, cooperatively
	initiator_node.node.close_channel(&channel_id2, &acceptor_node.node.get_our_node_id()).unwrap();
	let node0_shutdown_message = get_event_msg!(initiator_node, MessageSendEvent::SendShutdown, acceptor_node.node.get_our_node_id());
	acceptor_node.node.handle_shutdown(&initiator_node.node.get_our_node_id(), &node0_shutdown_message);
	let nodes_1_shutdown = get_event_msg!(acceptor_node, MessageSendEvent::SendShutdown, initiator_node.node.get_our_node_id());
	initiator_node.node.handle_shutdown(&acceptor_node.node.get_our_node_id(), &nodes_1_shutdown);
	let _ = get_event_msg!(initiator_node, MessageSendEvent::SendClosingSigned, acceptor_node.node.get_our_node_id());
}

/// End-to-end V2 open channel flow, with close, and verification checks.
/// The steps are mostly on ChannelManager level.
#[cfg(any(dual_funding, splicing))]
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

	// Have node0 initiate a channel to node1 with aforementioned parameters
	let channel_id_temp1 = initiator_node.node.create_dual_funded_channel(acceptor_node.node.get_our_node_id(), channel_value_sat, None, 42, None).unwrap();
	assert_eq!(channel_id_temp1.to_string(), expected_temporary_channel_id);

	// Extract the channel open message from node0 to node1
	let open_channel2_message = get_event_msg!(initiator_node, MessageSendEvent::SendOpenChannelV2, acceptor_node.node.get_our_node_id());
	assert_eq!(initiator_node.node.list_channels().len(), 1);

	let _res = acceptor_node.node.handle_open_channel_v2(&initiator_node.node.get_our_node_id(), &open_channel2_message.clone());
	// Extract the accept channel message from node1 to node0
	let accept_channel2_message = get_event_msg!(acceptor_node, MessageSendEvent::SendAcceptChannelV2, initiator_node.node.get_our_node_id());
	assert_eq!(accept_channel2_message.common_fields.temporary_channel_id.to_string(), expected_temporary_channel_id);

	let _res = initiator_node.node.handle_accept_channel_v2(&acceptor_node.node.get_our_node_id(), &accept_channel2_message.clone());

	// Note: FundingInputsContributionReady emitted
	let events = initiator_node.node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	let channel_id1 = match events[0] {
		Event::FundingInputsContributionReady { channel_id, counterparty_node_id, .. } => {
			// Here we have the final channel_id now
			assert_eq!(channel_id.to_string(), expected_funded_channel_id);
			assert_eq!(counterparty_node_id, acceptor_node.node.get_our_node_id());
			channel_id
		}
		_ => panic!("FundingInputsContributionReady event missing {:?}", events[0]),
	};

	let extra_funding_input_sats = channel_value_sat + 35_000;
	let custom_input_secret_key = SecretKey::from_slice(&[2; 32]).unwrap();
	let funding_inputs = vec![create_custom_dual_funding_input_with_pubkey(&initiator_node, extra_funding_input_sats, &PublicKey::from_secret_key(&Secp256k1::new(), &custom_input_secret_key))];
	let _res = initiator_node.node.contribute_funding_inputs(&channel_id1, &acceptor_node.node.get_our_node_id(), funding_inputs).unwrap();

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
		assert_eq!(channel_id.to_string(), expected_funded_channel_id);
		assert_eq!(counterparty_node_id, acceptor_node.node.get_our_node_id());

		// placeholder signature
		let mut witness = Witness::new();
		witness.push([7; 72]);
		unsigned_transaction.input[0].witness = witness;

		let _res = initiator_node.node.funding_transaction_signed(&channel_id1, &counterparty_node_id, unsigned_transaction).unwrap();
	} else { panic!(); }

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
	let tx_signatures_from_1 = get_event_msg!(acceptor_node, MessageSendEvent::SendTxSignatures, nodes[0].node.get_our_node_id());

	let _res = initiator_node.node.handle_tx_signatures(&acceptor_node.node.get_our_node_id(), &tx_signatures_from_1);
	let events_0 = initiator_node.node.get_and_clear_pending_events();
	assert_eq!(events_0.len(), 1);
	match events_0[0] {
		Event::ChannelPending{ ref counterparty_node_id, .. } => {
			assert_eq!(*counterparty_node_id, acceptor_node.node.get_our_node_id());
		},
		_ => panic!("Unexpected event"),
	}
	let tx_signatures_from_0 = get_event_msg!(initiator_node, MessageSendEvent::SendTxSignatures, nodes[1].node.get_our_node_id());
	let _res = acceptor_node.node.handle_tx_signatures(&initiator_node.node.get_our_node_id(), &tx_signatures_from_0);
	let events_1 = acceptor_node.node.get_and_clear_pending_events();
	assert_eq!(events_1.len(), 1);
	match events_1[0] {
		Event::ChannelPending{ ref channel_id, ref counterparty_node_id, .. } => {
			assert_eq!(channel_id.to_string(), expected_funded_channel_id);
			assert_eq!(*counterparty_node_id, initiator_node.node.get_our_node_id());
		},
		_ => panic!("Unexpected event"),
	}

	// Check that funding transaction has been broadcasted
	assert_eq!(chanmon_cfgs[initiator_node_index].tx_broadcaster.txn_broadcasted.lock().unwrap().len(), 1);
	let broadcasted_funding_tx = chanmon_cfgs[initiator_node_index].tx_broadcaster.txn_broadcasted.lock().unwrap()[0].clone();
	let expected_funding_tx = "020000000001019c76affec45612929f824230eacc67dc7b3db1072c39d0e62f4f557a34e141fc000000000000000000022588000000000000160014d5a9aa98b89acc215fc3d23d6fec0ad59ca3665fa08601000000000022002034c0cc0ad0dd5fe61dcf7ef58f995e3d34f8dbd24aa2a6fae68fefe102bf025c014807070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070700000000";
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

fn verify_signature(msg: &Vec<u8>, sig: &Vec<u8>, pubkey: &PublicKey) -> Result<(), String> {
	let m = Message::from_slice(&msg).unwrap();
	let s = Signature::from_der(&sig).unwrap();
	let ctx = Secp256k1::new();
	match ctx.verify_ecdsa(&m, &s, &pubkey) {
		Ok(_) => Ok(()),
		Err(e) => Err(format!("Signature verification failed! err {}  msg {}  sig {}  pk {}", e, &msg.as_hex(), &sig.as_hex(), &pubkey.serialize().as_hex())),
	}
}

/// #SPLICING
/// Verify the previous funding input on a splicing funding transaction
fn verify_splice_funding_input(splice_tx: &Transaction, prev_funding_txid: &Txid, prev_funding_value: u64, funding_key_1: &PublicKey, funding_key_2: &PublicKey) {
	// check that the previous funding tx is an input
	let mut prev_fund_input_idx: Option<usize> = None;
	for idx in 0..splice_tx.input.len() {
		if splice_tx.input[idx].previous_output.txid == *prev_funding_txid {
			prev_fund_input_idx = Some(idx);
		}
	}
	if prev_fund_input_idx.is_none() {
		panic!("Splice tx should contain the pervious funding tx as input! {} {}", prev_funding_txid, splice_tx.encode().as_hex());
	}
	let prev_fund_input = &splice_tx.input[prev_fund_input_idx.unwrap()];
	let witness = &prev_fund_input.witness.to_vec();
	let witness_count = witness.len();
	let expected_witness_count = 4;
	if witness_count != expected_witness_count {
		panic!("Prev funding tx input should have {} witness elements! {} {}", expected_witness_count, witness_count, prev_fund_input_idx.unwrap());
	}
	if witness[0].len() != 0 {
		panic!("First multisig witness should be empty! {}", witness[0].len());
	}
	// check witness 1&2, signatures
	let wit1_sig = &witness[1];
	let wit2_sig = &witness[2];
	if wit1_sig.len() < 70 || wit1_sig.len() > 72 || wit2_sig.len() < 70 || wit2_sig.len() > 72 {
		panic!("Witness entries 2&3 should be signatures! {} {}", wit1_sig.as_hex(), wit2_sig.as_hex());
	}
	if wit1_sig[wit1_sig.len()-1] != 1 || wit2_sig[wit2_sig.len()-1] != 1 {
		panic!("Witness entries 2&3 should be signatures with SIGHASHALL! {} {}", wit1_sig.as_hex(), wit2_sig.as_hex());
	}
	let (script_key1, script_key2) = verify_multisig_redeem_script(&witness[3], funding_key_1, funding_key_2);
	let redeemscript = ScriptBuf::from(witness[3].to_vec());
	// check signatures, sigs are in same order as keys
	let sighash = &SighashCache::new(splice_tx).segwit_signature_hash(prev_fund_input_idx.unwrap(), &redeemscript, prev_funding_value, EcdsaSighashType::All).unwrap()[..].to_vec();
	let sig1 = wit1_sig[0..(wit1_sig.len()-1)].to_vec();
	let sig2 = wit2_sig[0..(wit2_sig.len()-1)].to_vec();
	if let Err(e1) = verify_signature(sighash, &sig1, &script_key1) {
		panic!("Sig 1 check fails {}", e1);
	}
	if let Err(e2) = verify_signature(sighash, &sig2, &script_key2) {
		panic!("Sig 2 check fails {}", e2);
	}
}

/// #SPLICING
/// Do checks on a splice funding tx
fn verify_splice_funding_tx(splice_tx: &Transaction, prev_funding_txid: &Txid, funding_value: u64, prev_funding_value: u64, funding_key_1: &PublicKey, funding_key_2: &PublicKey) {
	verify_splice_funding_input(splice_tx, prev_funding_txid, prev_funding_value, funding_key_1, funding_key_2);
	verify_funding_tx(splice_tx, funding_value, funding_key_1, funding_key_2);
}

/// #SPLICING Builds on test_channel_open_simple()
/// Splicing test, simple splice-in flow. Starts with opening a V1 channel first.
#[test]
fn test_v1_splice_in() {
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

	// Initiator and Acceptor nodes
	let initiator_node_index = 1;
	let initiator_node = &nodes[initiator_node_index];
	let acceptor_node = &nodes[0];

	// Instantiate channel parameters where we push the maximum msats given our funding satoshis
	let channel_value_sat = 100000; // same as funding satoshis
	let push_msat = 0;

	let expected_funded_channel_id = "c95d1eb6f3d0c5c74a398a6e9c2c0721afde1e30d23a70867362e9d6d8d04281";

	// Have node0 initiate a channel to node1 with aforementioned parameters
	let channel_id_temp1 = initiator_node.node.create_channel(acceptor_node.node.get_our_node_id(), channel_value_sat, push_msat, 42, None, None).unwrap();

	// Extract the channel open message from node0 to node1
	let open_channel_message = get_event_msg!(initiator_node, MessageSendEvent::SendOpenChannel, acceptor_node.node.get_our_node_id());

	let _res = acceptor_node.node.handle_open_channel(&initiator_node.node.get_our_node_id(), &open_channel_message.clone());
	// Extract the accept channel message from node1 to node0
	let accept_channel_message = get_event_msg!(acceptor_node, MessageSendEvent::SendAcceptChannel, initiator_node.node.get_our_node_id());
	let _res = initiator_node.node.handle_accept_channel(&acceptor_node.node.get_our_node_id(), &accept_channel_message.clone());
	// Note: FundingGenerationReady emitted, checked and used below
	let (_channel_id_temp2, funding_tx, _funding_output) = create_funding_transaction(&initiator_node, &acceptor_node.node.get_our_node_id(), channel_value_sat, 42);

	// Funding transation created, provide it
	let _res = initiator_node.node.funding_transaction_generated(&channel_id_temp1, &acceptor_node.node.get_our_node_id(), funding_tx.clone()).unwrap();

	let funding_created_message = get_event_msg!(initiator_node, MessageSendEvent::SendFundingCreated, acceptor_node.node.get_our_node_id());

	let _res = acceptor_node.node.handle_funding_created(&initiator_node.node.get_our_node_id(), &funding_created_message);

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

	let funding_signed_message = get_event_msg!(acceptor_node, MessageSendEvent::SendFundingSigned, initiator_node.node.get_our_node_id());
	let _res = initiator_node.node.handle_funding_signed(&acceptor_node.node.get_our_node_id(), &funding_signed_message);
	// Take new channel ID
	let channel_id2 = funding_signed_message.channel_id;
	assert_eq!(channel_id2.to_string(), expected_funded_channel_id);

	// Check that funding transaction has been broadcasted
	assert_eq!(chanmon_cfgs[initiator_node_index].tx_broadcaster.txn_broadcasted.lock().unwrap().len(), 1);
	let broadcasted_funding_tx = chanmon_cfgs[initiator_node_index].tx_broadcaster.txn_broadcasted.lock().unwrap()[0].clone();

	check_added_monitors!(initiator_node, 1);
	let _ev = get_event!(initiator_node, Event::ChannelPending);
	check_added_monitors!(acceptor_node, 1);
	let _ev = get_event!(acceptor_node, Event::ChannelPending);

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
	{
		let channel = &initiator_node.node.list_channels()[0];
		assert!(channel.is_channel_ready);
		assert_eq!(channel.channel_value_satoshis, channel_value_sat);
		assert_eq!(channel.balance_msat, 1000 * channel_value_sat);
		assert_eq!(channel.funding_txo.unwrap().txid, funding_tx.txid());
		assert_eq!(channel.confirmations.unwrap(), 10);
	}
	// do checks on the acceptor node as well (capacity, etc.)
	assert_eq!(acceptor_node.node.list_channels().len(), 1);
	{
		let channel = &acceptor_node.node.list_channels()[0];
		assert!(channel.is_channel_ready);
		assert_eq!(channel.channel_value_satoshis, channel_value_sat);
		assert_eq!(channel.balance_msat, 0);
		assert_eq!(channel.funding_txo.unwrap().txid, funding_tx.txid());
		assert_eq!(channel.confirmations.unwrap(), 10);
	}

	// ==== Channel is now ready for normal operation

	// === Start of Splicing
	println!("Start of Splicing ..., channel_id {}", channel_id2);

	// Amount being added to the channel through the splice-in
	let splice_in_sats: u64 = 20000;
	let _post_splice_channel_value = channel_value_sat + splice_in_sats;
	let funding_feerate_perkw = 1024; // TODO
	let locktime = 0; // TODO

	// Initiate splice-in (on node0)
	let res_error = initiator_node.node.splice_channel(&channel_id2, &acceptor_node.node.get_our_node_id(), splice_in_sats as i64, funding_feerate_perkw, locktime);
	assert!(res_error.is_err());
	assert_eq!(format!("{:?}", res_error.err().unwrap())[..53].to_string(), "Misuse error: Channel ID would change during splicing".to_string());

	// no change
	assert_eq!(initiator_node.node.list_channels().len(), 1);
	{
		let channel = &initiator_node.node.list_channels()[0];
		assert!(channel.is_channel_ready);
		assert_eq!(channel.channel_value_satoshis, channel_value_sat);
		assert_eq!(channel.balance_msat, 1000 * channel_value_sat);
		assert_eq!(channel.funding_txo.unwrap().txid, funding_tx.txid());
	}

	// === End of Splicing
	
	// === Close channel, cooperatively
	initiator_node.node.close_channel(&channel_id2, &acceptor_node.node.get_our_node_id()).unwrap();
	let node0_shutdown_message = get_event_msg!(initiator_node, MessageSendEvent::SendShutdown, acceptor_node.node.get_our_node_id());
	acceptor_node.node.handle_shutdown(&initiator_node.node.get_our_node_id(), &node0_shutdown_message);
	let nodes_1_shutdown = get_event_msg!(acceptor_node, MessageSendEvent::SendShutdown, initiator_node.node.get_our_node_id());
	initiator_node.node.handle_shutdown(&acceptor_node.node.get_our_node_id(), &nodes_1_shutdown);
	let _ = get_event_msg!(initiator_node, MessageSendEvent::SendClosingSigned, acceptor_node.node.get_our_node_id());
}

// TODO: Test with 2nd splice (open, splice, splice)

/// #SPLICING Builds on test_channel_open_v2_and_close()
/// Splicing test, simple splice-in flow. Starts with opening a V2 channel first.
/// The steps are mostly on ChannelManager level.
#[test]
fn test_v2_splice_in() {
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

	// Have node0 initiate a channel to node1 with aforementioned parameters
	let channel_id_temp1 = initiator_node.node.create_dual_funded_channel(acceptor_node.node.get_our_node_id(), channel_value_sat, None, 42, None).unwrap();
	assert_eq!(channel_id_temp1.to_string(), expected_temporary_channel_id);

	// Extract the channel open message from node0 to node1
	let open_channel2_message = get_event_msg!(initiator_node, MessageSendEvent::SendOpenChannelV2, acceptor_node.node.get_our_node_id());
	assert_eq!(initiator_node.node.list_channels().len(), 1);

	let _res = acceptor_node.node.handle_open_channel_v2(&initiator_node.node.get_our_node_id(), &open_channel2_message.clone());
	// Extract the accept channel message from node1 to node0
	let accept_channel2_message = get_event_msg!(acceptor_node, MessageSendEvent::SendAcceptChannelV2, initiator_node.node.get_our_node_id());
	assert_eq!(accept_channel2_message.common_fields.temporary_channel_id.to_string(), expected_temporary_channel_id);

	let _res = initiator_node.node.handle_accept_channel_v2(&acceptor_node.node.get_our_node_id(), &accept_channel2_message.clone());

	// Note: FundingInputsContributionReady emitted
	let events = initiator_node.node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	let channel_id1 = match events[0] {
		Event::FundingInputsContributionReady { channel_id, .. } => { 
			// Here we have the final channel_id now
			assert_eq!(channel_id.to_string(), expected_funded_channel_id);
			channel_id
		}
		_ => panic!("FundingInputsContributionReady event missing {:?}", events[0]),
	};

	let extra_funding_input_sats = channel_value_sat + 35_000;
	let custom_input_secret_key = SecretKey::from_slice(&[2; 32]).unwrap();
	let custom_input_pubkey = PublicKey::from_secret_key(&Secp256k1::new(), &custom_input_secret_key);
	let funding_inputs = vec![create_custom_dual_funding_input_with_pubkey(&initiator_node, extra_funding_input_sats, &custom_input_pubkey)];
	let _res = initiator_node.node.contribute_funding_inputs(&channel_id1, &acceptor_node.node.get_our_node_id(), funding_inputs).unwrap();

	// initiator_node will generate a TxAddInput message to kickstart the interactive transaction construction protocol
	let tx_add_input_msg = get_event_msg!(&initiator_node, MessageSendEvent::SendTxAddInput, acceptor_node.node.get_our_node_id());

	let _res = acceptor_node.node.handle_tx_add_input(&initiator_node.node.get_our_node_id(), &tx_add_input_msg);
	let tx_complete_msg = get_event_msg!(acceptor_node, MessageSendEvent::SendTxComplete, initiator_node.node.get_our_node_id());

	let _res = initiator_node.node.handle_tx_complete(&acceptor_node.node.get_our_node_id(), &tx_complete_msg);

	// First output, the new funding tx
	let tx_add_output_msg = get_event_msg!(&initiator_node, MessageSendEvent::SendTxAddOutput, acceptor_node.node.get_our_node_id());
	assert_eq!(tx_add_output_msg.sats, channel_value_sat);

	let _res = acceptor_node.node.handle_tx_add_output(&initiator_node.node.get_our_node_id(), &tx_add_output_msg);
	let tx_complete_msg = get_event_msg!(&acceptor_node, MessageSendEvent::SendTxComplete, initiator_node.node.get_our_node_id());

	// Second output, change
	let _res = initiator_node.node.handle_tx_complete(&acceptor_node.node.get_our_node_id(), &tx_complete_msg);
	let tx_add_output2_msg = get_event_msg!(&initiator_node, MessageSendEvent::SendTxAddOutput, acceptor_node.node.get_our_node_id());

	let _res = acceptor_node.node.handle_tx_add_output(&initiator_node.node.get_our_node_id(), &tx_add_output2_msg);
	let tx_complete_msg = get_event_msg!(acceptor_node, MessageSendEvent::SendTxComplete, initiator_node.node.get_our_node_id());

	initiator_node.node.handle_tx_complete(&acceptor_node.node.get_our_node_id(), &tx_complete_msg);
	let msg_events = initiator_node.node.get_and_clear_pending_msg_events();
	assert_eq!(msg_events.len(), 2);
	assert_event_type!(msg_events[0], MessageSendEvent::SendTxComplete);
	assert_event_type!(msg_events[1], MessageSendEvent::UpdateHTLCs);
	let msg_commitment_signed_from_0 = match msg_events[1] {
		MessageSendEvent::UpdateHTLCs { ref updates, .. } => {
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
		assert_eq!(channel_id.to_string(), expected_funded_channel_id);
		let mut witness = Witness::new();
		witness.push(vec![0]);
		unsigned_transaction.input[0].witness = witness;
		let _res = initiator_node.node.funding_transaction_signed(&channel_id1, &counterparty_node_id, unsigned_transaction).unwrap();
	} else { panic!(); }

	let _res = acceptor_node.node.handle_tx_complete(&initiator_node.node.get_our_node_id(), &tx_complete_msg);
	let msg_events = acceptor_node.node.get_and_clear_pending_msg_events();
	// First messsage is commitment_signed, second is tx_signatures (see below for more)
	assert_eq!(msg_events.len(), 1);
	let msg_commitment_signed_from_1 = match msg_events[0] {
		MessageSendEvent::UpdateHTLCs { ref updates, .. } => {
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
	get_event!(initiator_node, Event::ChannelPending);
	let tx_signatures_from_0 = get_event_msg!(initiator_node, MessageSendEvent::SendTxSignatures, acceptor_node.node.get_our_node_id());
	let _res = acceptor_node.node.handle_tx_signatures(&initiator_node.node.get_our_node_id(), &tx_signatures_from_0);
	get_event!(acceptor_node, Event::ChannelPending);

	// Check that funding transaction has been broadcasted
	assert_eq!(chanmon_cfgs[initiator_node_index].tx_broadcaster.txn_broadcasted.lock().unwrap().len(), 1);
	let broadcasted_funding_tx = chanmon_cfgs[initiator_node_index].tx_broadcaster.txn_broadcasted.lock().unwrap()[0].clone();
	assert_eq!(broadcasted_funding_tx.encode().len(), 130);
	assert_eq!(broadcasted_funding_tx.txid().to_string(), "684be2e5a50020f27a6d4d2802e1c9d9ca5e6b64f6098075ec873e04f62a70ee");

	// Simulate confirmation of the funding tx
	confirm_transaction(&initiator_node, &broadcasted_funding_tx);
	let channel_ready_message1 = get_event_msg!(initiator_node, MessageSendEvent::SendChannelReady, acceptor_node.node.get_our_node_id());

	confirm_transaction(&acceptor_node, &broadcasted_funding_tx);
	let channel_ready_message2 = get_event_msg!(acceptor_node, MessageSendEvent::SendChannelReady, initiator_node.node.get_our_node_id());

	let _res = acceptor_node.node.handle_channel_ready(&initiator_node.node.get_our_node_id(), &channel_ready_message1);
	let _ev = get_event!(acceptor_node, Event::ChannelReady);
	let _announcement_signatures2 = get_event_msg!(acceptor_node, MessageSendEvent::SendAnnouncementSignatures, initiator_node.node.get_our_node_id());

	let _res = initiator_node.node.handle_channel_ready(&acceptor_node.node.get_our_node_id(), &channel_ready_message2);
	let _ev = get_event!(initiator_node, Event::ChannelReady);
	let _announcement_signatures1 = get_event_msg!(initiator_node, MessageSendEvent::SendAnnouncementSignatures, acceptor_node.node.get_our_node_id());

	// let (announcement1, update1, update2) = create_chan_between_nodes_with_value_b(&initiator_node, &acceptor_node, &(channel_ready_message1, announcement_signatures1));
	// `update_nodes_with_chan_announce`(&nodes, initiator_node_index, acceptor_node_index, &announcement1, &update1, &update2);

	// check channel capacity and other parameters
	assert_eq!(initiator_node.node.list_channels().len(), 1);
	{
		let channel = &initiator_node.node.list_channels()[0];
		assert_eq!(channel.channel_id.to_string(), expected_funded_channel_id);
		assert!(channel.is_usable);
		assert!(channel.is_channel_ready);
		assert_eq!(channel.channel_value_satoshis, channel_value_sat);
		assert_eq!(channel.balance_msat, 1000 * channel_value_sat);
		assert_eq!(channel.confirmations.unwrap(), 10);
		assert!(channel.funding_txo.is_some());
	}
	// do checks on the acceptor node as well (capacity, etc.)
	assert_eq!(acceptor_node.node.list_channels().len(), 1);
	{
		let channel = &acceptor_node.node.list_channels()[0];
		assert_eq!(channel.channel_id.to_string(), expected_funded_channel_id);
		assert!(channel.is_usable);
		assert!(channel.is_channel_ready);
		assert_eq!(channel.channel_value_satoshis, channel_value_sat);
		assert_eq!(channel.balance_msat, 0);
		assert_eq!(channel.confirmations.unwrap(), 10);
		assert!(channel.funding_txo.is_some());
	}

	// === Channel is now ready for normal operation

	// === Start of Splicing
	println!("Start of Splicing ..., channel_id {}", channel_id1);

	// Amount being added to the channel through the splice-in
	let splice_in_sats: u64 = 20000;
	let post_splice_channel_value = channel_value_sat + splice_in_sats;
	let funding_feerate_perkw = 1024; // TODO
	let locktime = 0; // TODO

	// Initiate splice-in (on node0)
	let _res = initiator_node.node.splice_channel(&channel_id1, &acceptor_node.node.get_our_node_id(), splice_in_sats as i64, funding_feerate_perkw, locktime).unwrap();
	// Extract the splice message from node0 to node1
	let splice_msg = get_event_msg!(initiator_node, MessageSendEvent::SendSplice, acceptor_node.node.get_our_node_id());

	let _res = acceptor_node.node.handle_splice(&initiator_node.node.get_our_node_id(), &splice_msg);
	// Extract the splice_ack message from node1 to node0
	let splice_ack_msg = get_event_msg!(acceptor_node, MessageSendEvent::SendSpliceAck, initiator_node.node.get_our_node_id());

	// check that capacity has been updated, channel is not usable, and funding tx is unset
	assert_eq!(acceptor_node.node.list_channels().len(), 1);
	{
		let channel = &acceptor_node.node.list_channels()[0];
		assert_eq!(channel.channel_id.to_string(), expected_funded_channel_id);
		assert!(!channel.is_usable);
		assert!(!channel.is_channel_ready);
		assert_eq!(channel.channel_value_satoshis, post_splice_channel_value);
		assert_eq!(channel.balance_msat, 0);
		assert!(channel.funding_txo.is_none());
		assert_eq!(channel.confirmations.unwrap(), 0);
	}

	let _res = initiator_node.node.handle_splice_ack(&acceptor_node.node.get_our_node_id(), &splice_ack_msg);

	// Note: SpliceAckedInputsContributionReady emitted
	let events = initiator_node.node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		Event::SpliceAckedInputsContributionReady { channel_id, pre_channel_value_satoshis, post_channel_value_satoshis, holder_funding_satoshis, counterparty_funding_satoshis, .. } => {
			assert_eq!(channel_id.to_string(), expected_funded_channel_id);
			assert_eq!(pre_channel_value_satoshis, channel_value_sat);
			assert_eq!(post_channel_value_satoshis, post_splice_channel_value);
			assert_eq!(holder_funding_satoshis, post_splice_channel_value - channel_value_sat);
			assert_eq!(counterparty_funding_satoshis, 0);
		},
		_ => panic!("SpliceAckedInputsContributionReady event missing {:?}", events[0]),
	};

	// check that capacity has been updated, channel is not usable, and funding tx is unset
	assert_eq!(initiator_node.node.list_channels().len(), 1);
	{
		let channel = &initiator_node.node.list_channels()[0];
		assert_eq!(channel.channel_id.to_string(), expected_funded_channel_id);
		assert!(!channel.is_usable);
		assert!(!channel.is_channel_ready);
		assert_eq!(channel.channel_value_satoshis, post_splice_channel_value);
		assert_eq!(channel.balance_msat, 1000 * post_splice_channel_value);
		assert!(channel.funding_txo.is_none());
		assert_eq!(channel.confirmations.unwrap(), 0);
	}
	
	let extra_splice_funding_input_sats = 35_000;
	let funding_inputs = vec![create_custom_dual_funding_input_with_pubkey(&initiator_node, extra_splice_funding_input_sats, &custom_input_pubkey)];

	let _res = initiator_node.node.contribute_funding_inputs(&channel_id1, &acceptor_node.node.get_our_node_id(), funding_inputs).unwrap();

	// Initiator_node will generate first TxAddInput message
	let tx_add_input_msg = get_event_msg!(&initiator_node, MessageSendEvent::SendTxAddInput, acceptor_node.node.get_our_node_id());
	assert_eq!(tx_add_input_msg.prevtx.0.output[tx_add_input_msg.prevtx_out as usize].value, extra_splice_funding_input_sats);

	let _res = acceptor_node.node.handle_tx_add_input(&initiator_node.node.get_our_node_id(), &tx_add_input_msg);
	let tx_complete_msg = get_event_msg!(acceptor_node, MessageSendEvent::SendTxComplete, initiator_node.node.get_our_node_id());

	let _res = initiator_node.node.handle_tx_complete(&acceptor_node.node.get_our_node_id(), &tx_complete_msg);
	// second TxAddInput message for the second input
	let tx_add_input2_msg = get_event_msg!(&initiator_node, MessageSendEvent::SendTxAddInput, acceptor_node.node.get_our_node_id());
	assert_eq!(tx_add_input2_msg.prevtx.0.output[tx_add_input2_msg.prevtx_out as usize].value, channel_value_sat);

	let _res = acceptor_node.node.handle_tx_add_input(&initiator_node.node.get_our_node_id(), &tx_add_input2_msg);
	let tx_complete_msg = get_event_msg!(acceptor_node, MessageSendEvent::SendTxComplete, initiator_node.node.get_our_node_id());

	let _res = initiator_node.node.handle_tx_complete(&acceptor_node.node.get_our_node_id(), &tx_complete_msg);

	// First TxAddOutput is for the change output
	let tx_add_output_msg = get_event_msg!(&initiator_node, MessageSendEvent::SendTxAddOutput, acceptor_node.node.get_our_node_id());
	assert!(tx_add_output_msg.script.is_v0_p2wpkh());
	assert_eq!(tx_add_output_msg.sats, 14167); // extra_splice_input_sats - splice_in_sats - fee

	let _res = acceptor_node.node.handle_tx_add_output(&initiator_node.node.get_our_node_id(), &tx_add_output_msg);
	let tx_complete_msg = get_event_msg!(&acceptor_node, MessageSendEvent::SendTxComplete, initiator_node.node.get_our_node_id());

	let _res = initiator_node.node.handle_tx_complete(&acceptor_node.node.get_our_node_id(), &tx_complete_msg);
	// TxAddOutput for the splice funding
	let tx_add_output2_msg = get_event_msg!(&initiator_node, MessageSendEvent::SendTxAddOutput, acceptor_node.node.get_our_node_id());
	// Check we get the channel funding output.
	assert!(tx_add_output2_msg.script.is_v0_p2wsh());
	assert_eq!(tx_add_output2_msg.sats, post_splice_channel_value);
	
	let _res = acceptor_node.node.handle_tx_add_output(&initiator_node.node.get_our_node_id(), &tx_add_output2_msg);
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
	if let Event::FundingTransactionReadyForSigning {
		channel_id,
		counterparty_node_id,
		mut unsigned_transaction,
		..
	} = get_event!(initiator_node, Event::FundingTransactionReadyForSigning) {
		assert_eq!(channel_id.to_string(), expected_funded_channel_id);
		assert_eq!(counterparty_node_id, acceptor_node.node.get_our_node_id());
		assert_eq!(unsigned_transaction.input.len(), 2);
		// This is the previous funding tx input, already signed (partially)
		assert_eq!(unsigned_transaction.input[0].witness.len(), 4);
		// This is the extra input, not yet signed
		assert_eq!(unsigned_transaction.input[1].witness.len(), 0);

		// Placeholder for signature on the contributed input
		let mut witness1 = Witness::new();
		witness1.push(vec![0]);
		unsigned_transaction.input[1].witness = witness1;

		let _res = initiator_node.node.funding_transaction_signed(&channel_id, &counterparty_node_id, unsigned_transaction).unwrap();
	} else { panic!(); }

	let expected_splice_funding_txid = "e8b39faf45fb520bfe1fca16d394446814080761c0f536cb6184cc2af95d2848";
	// check new funding tx
	assert_eq!(initiator_node.node.list_channels().len(), 1);
	{
		let channel = &initiator_node.node.list_channels()[0];
		assert!(!channel.is_channel_ready);
		assert_eq!(channel.channel_value_satoshis, post_splice_channel_value);
		assert_eq!(channel.funding_txo.unwrap().txid.to_string(), expected_splice_funding_txid);
		assert_eq!(channel.confirmations.unwrap(), 0);
	}

	let _res = acceptor_node.node.handle_tx_complete(&initiator_node.node.get_our_node_id(), &tx_complete_msg);
	let msg_events = acceptor_node.node.get_and_clear_pending_msg_events();
	// First messsage is commitment_signed, second is tx_signatures (see below for more)
	assert_eq!(msg_events.len(), 1);
	let msg_commitment_signed_from_1 = match msg_events[0] {
		MessageSendEvent::UpdateHTLCs { ref node_id, ref updates } => {
			assert_eq!(*node_id, initiator_node.node.get_our_node_id());
			let res = updates.commitment_signed.clone();
			res
		},
		_ => panic!("Unexpected event {:?}", msg_events[0]),
	};

	// check new funding tx (acceptor side)
	assert_eq!(acceptor_node.node.list_channels().len(), 1);
	{
		let channel = &acceptor_node.node.list_channels()[0];
		assert!(!channel.is_channel_ready);
		assert_eq!(channel.channel_value_satoshis, post_splice_channel_value);
		assert_eq!(channel.funding_txo.unwrap().txid.to_string(), expected_splice_funding_txid);
		assert_eq!(channel.confirmations.unwrap(), 0);
	}

	// Handle the initial commitment_signed exchange. Order is not important here.
	let _res = acceptor_node.node.handle_commitment_signed(&initiator_node.node.get_our_node_id(), &msg_commitment_signed_from_0);
	let _res = initiator_node.node.handle_commitment_signed(&acceptor_node.node.get_our_node_id(), &msg_commitment_signed_from_1);
	check_added_monitors(&initiator_node, 1);
	check_added_monitors(&acceptor_node, 1);

	// The initiator is the only party that contributed any inputs so they should definitely be the one to send tx_signatures
	// only after receiving tx_signatures from the non-initiator in this case.
	let msg_events = initiator_node.node.get_and_clear_pending_msg_events();
	assert!(msg_events.is_empty());
	let msg_events = acceptor_node.node.get_and_clear_pending_msg_events();
	assert_eq!(msg_events.len(), 1);
	let tx_signatures_1 = match msg_events[0] {
		MessageSendEvent::SendTxSignatures { ref node_id, ref msg } => {
			assert_eq!(*node_id, initiator_node.node.get_our_node_id());
			// Here we only get the signature for the shared input
			assert_eq!(msg.witnesses.len(), 0);
			assert!(msg.funding_outpoint_sig.is_some());
			msg
		},
		_ => panic!("Unexpected event {:?}", msg_events[0]),
	};

	let _res = initiator_node.node.handle_tx_signatures(&acceptor_node.node.get_our_node_id(), &tx_signatures_1);
	let events_0 = initiator_node.node.get_and_clear_pending_events();
	assert_eq!(events_0.len(), 0);
	let msg_events = initiator_node.node.get_and_clear_pending_msg_events();
	assert_eq!(msg_events.len(), 1);
	let tx_signatures_0 = match msg_events[0] {
		MessageSendEvent::SendTxSignatures { ref node_id, ref msg } => {
			assert_eq!(*node_id, acceptor_node.node.get_our_node_id());
			// Here we get the witnesses for the two inputs:
			// - the custom input, and
			// - the previous funding tx, also in the tlvs
			assert_eq!(msg.witnesses.len(), 2);
			assert_eq!(msg.witnesses[0].len(), 4);
			assert_eq!(msg.witnesses[1].len(), 1);
			assert!(msg.funding_outpoint_sig.is_some());
			msg
		},
		_ => panic!("Unexpected event {:?}", msg_events[0]),
	};
	let _res = acceptor_node.node.handle_tx_signatures(&initiator_node.node.get_our_node_id(), &tx_signatures_0);

	let events_1 = acceptor_node.node.get_and_clear_pending_events();
	assert_eq!(events_1.len(), 0);

	// Check that funding transaction has been broadcasted
	assert_eq!(chanmon_cfgs[initiator_node_index].tx_broadcaster.txn_broadcasted.lock().unwrap().len(), 2);
	let broadcasted_splice_tx = chanmon_cfgs[initiator_node_index].tx_broadcaster.txn_broadcasted.lock().unwrap()[1].clone();
	let expected_funding_tx = "02000000000102ee702af6043e87ec758009f6646b5ecad9c9e102284d6d7af22000a5e5e24b68010000000000000000a29ca934f2f9e07815e35099881dc8c0de1847ce0f00154de3d66c0133384b7900000000000000000002c0d401000000000022002034c0cc0ad0dd5fe61dcf7ef58f995e3d34f8dbd24aa2a6fae68fefe102bf025c5737000000000000160014d5a9aa98b89acc215fc3d23d6fec0ad59ca3665f040047304402200133d8eb11f22c92e8be02c3513fce6d16d2aefa40779d487cdc6e97b4d24a3602206a3caf951836e2399e1b67f761e8e7360b961ad6fac00ac4bfdcabd7e4de823101473044022035ba0e32aaddebea4bb2386fe7aaada3bb4f33c7bf2f8e15bd372659f15717ff02206d9f7f17cb27cdc1d2d181110e685d54f9c826bdbc1ec39ac29f47527f896324014752210307a78def56cba9fc4db22a25928181de538ee59ba1a475ae113af7790acd0db32103c21e841cbc0b48197d060c71e116c185fa0ac281b7d0aa5924f535154437ca3b52ae01010000000000";
	assert_eq!(broadcasted_splice_tx.encode().len(), 389);
	assert_eq!(broadcasted_splice_tx.encode().as_hex().to_string(), expected_funding_tx);
	let initiator_funding_key = get_funding_key(&initiator_node, &acceptor_node, &channel_id1);
	let acceptor_funding_key = get_funding_key(&acceptor_node, &initiator_node, &channel_id1);
	verify_splice_funding_tx(&broadcasted_splice_tx, &broadcasted_funding_tx.txid(), post_splice_channel_value, channel_value_sat, &initiator_funding_key, &acceptor_funding_key);

	// Check that funding transaction has been broadcasted on acceptor side as well
	assert_eq!(chanmon_cfgs[acceptor_node_index].tx_broadcaster.txn_broadcasted.lock().unwrap().len(), 2);
	let broadcasted_splice_tx_acc = chanmon_cfgs[acceptor_node_index].tx_broadcaster.txn_broadcasted.lock().unwrap()[1].clone();
	assert_eq!(broadcasted_splice_tx_acc.encode().len(), 389);
	assert_eq!(broadcasted_splice_tx_acc.encode().as_hex().to_string(), expected_funding_tx);

	// check fees
	let total_input = channel_value_sat + extra_splice_funding_input_sats;
	assert_eq!(broadcasted_splice_tx.output.len(), 2);
	let total_output = broadcasted_splice_tx.output[0].value + broadcasted_splice_tx.output[1].value;
	assert!(total_input > total_output);
	let fee = total_input - total_output;
	let target_fee_rate = chanmon_cfgs[0].fee_estimator.get_est_sat_per_1000_weight(ConfirmationTarget::NonAnchorChannelFee); // target is irrelevant
	assert_eq!(target_fee_rate, 253);
	assert_eq!(broadcasted_splice_tx.weight().to_wu(), 887);
	let expected_minimum_fee = (broadcasted_splice_tx.weight().to_wu() as f64 * target_fee_rate as f64 / 1000 as f64).ceil() as u64;
	let expected_maximum_fee = expected_minimum_fee * 5;  // TODO lower tolerance, e.g. 3
	assert!(fee >= expected_minimum_fee);
	assert!(fee <= expected_maximum_fee);

	// Simulate confirmation of the funding tx
	confirm_transaction(&initiator_node, &broadcasted_splice_tx);
	let channel_ready_message = get_event_msg!(initiator_node, MessageSendEvent::SendChannelReady, acceptor_node.node.get_our_node_id());

	confirm_transaction(&acceptor_node, &broadcasted_splice_tx);
	let channel_ready_message2 = get_event_msg!(acceptor_node, MessageSendEvent::SendChannelReady, initiator_node.node.get_our_node_id());

	let _res = acceptor_node.node.handle_channel_ready(&initiator_node.node.get_our_node_id(), &channel_ready_message);
	// let _ev = get_event!(acceptor_node, Event::ChannelReady);
	let events_0 = acceptor_node.node.get_and_clear_pending_events();
	assert_eq!(events_0.len(), 0);
	let _channel_update = get_event_msg!(acceptor_node, MessageSendEvent::SendChannelUpdate, initiator_node.node.get_our_node_id());
	// let _announcement_signatures2 = get_event_msg!(acceptor_node, MessageSendEvent::SendAnnouncementSignatures, initiator_node.node.get_our_node_id());

	let _res = initiator_node.node.handle_channel_ready(&acceptor_node.node.get_our_node_id(), &channel_ready_message2);
	// let _ev = get_event!(initiator_node, Event::ChannelReady);
	let events_0 = initiator_node.node.get_and_clear_pending_events();
	assert_eq!(events_0.len(), 0);
	let _channel_update = get_event_msg!(initiator_node, MessageSendEvent::SendChannelUpdate, acceptor_node.node.get_our_node_id());
	// let _announcement_signatures1 = get_event_msg!(initiator_node, MessageSendEvent::SendAnnouncementSignatures, acceptor_node.node.get_our_node_id());

	// check new channel capacity and other parameters
	assert_eq!(initiator_node.node.list_channels().len(), 1);
	{
		let channel = &initiator_node.node.list_channels()[0];
		assert_eq!(channel.channel_id.to_string(), expected_funded_channel_id);
		assert!(channel.is_channel_ready);
		assert_eq!(channel.channel_value_satoshis, post_splice_channel_value);
		assert_eq!(channel.balance_msat, 1000 * post_splice_channel_value);
		assert_eq!(channel.funding_txo.unwrap().txid, broadcasted_splice_tx_acc.txid());
		assert_eq!(channel.confirmations.unwrap(), 10);
	}

	// do the checks on acceptor side as well
	assert_eq!(acceptor_node.node.list_channels().len(), 1);
	{
		let channel = &acceptor_node.node.list_channels()[0];
		assert_eq!(channel.channel_id.to_string(), expected_funded_channel_id);
		assert!(channel.is_channel_ready);
		assert_eq!(channel.channel_value_satoshis, post_splice_channel_value);
		assert_eq!(channel.balance_msat, 0);
		assert_eq!(channel.funding_txo.unwrap().txid, broadcasted_splice_tx_acc.txid());
		assert_eq!(channel.confirmations.unwrap(), 10);
	}

	// === End of Splicing

	// === Close channel, cooperatively
	initiator_node.node.close_channel(&channel_id1, &acceptor_node.node.get_our_node_id()).unwrap();
	let node0_shutdown_message = get_event_msg!(initiator_node, MessageSendEvent::SendShutdown, acceptor_node.node.get_our_node_id());
	acceptor_node.node.handle_shutdown(&initiator_node.node.get_our_node_id(), &node0_shutdown_message);
	let nodes_1_shutdown = get_event_msg!(acceptor_node, MessageSendEvent::SendShutdown, initiator_node.node.get_our_node_id());
	initiator_node.node.handle_shutdown(&acceptor_node.node.get_our_node_id(), &nodes_1_shutdown);
	let _ = get_event_msg!(initiator_node, MessageSendEvent::SendClosingSigned, acceptor_node.node.get_our_node_id());
}

/// #SPLICING Builds on test_channel_open_v2_and_close()
/// Splicing test, simple splice-in flow. Starts with opening a V2 channel first.
/// The steps are mostly on ChannelManager level.
#[ignore]
#[test]
fn test_v2_payment_splice_in_payment() {
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

	// Have node0 initiate a channel to node1 with aforementioned parameters
	let channel_id_temp1 = initiator_node.node.create_dual_funded_channel(acceptor_node.node.get_our_node_id(), channel_value_sat, None, 42, None).unwrap();
	assert_eq!(channel_id_temp1.to_string(), expected_temporary_channel_id);

	// Extract the channel open message from node0 to node1
	let open_channel2_message = get_event_msg!(initiator_node, MessageSendEvent::SendOpenChannelV2, acceptor_node.node.get_our_node_id());
	assert_eq!(initiator_node.node.list_channels().len(), 1);

	let _res = acceptor_node.node.handle_open_channel_v2(&initiator_node.node.get_our_node_id(), &open_channel2_message.clone());
	// Extract the accept channel message from node1 to node0
	let accept_channel2_message = get_event_msg!(acceptor_node, MessageSendEvent::SendAcceptChannelV2, initiator_node.node.get_our_node_id());
	assert_eq!(accept_channel2_message.common_fields.temporary_channel_id.to_string(), expected_temporary_channel_id);

	let _res = initiator_node.node.handle_accept_channel_v2(&acceptor_node.node.get_our_node_id(), &accept_channel2_message.clone());

	// Note: FundingInputsContributionReady emitted
	let events = initiator_node.node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	let channel_id1 = match events[0] {
		Event::FundingInputsContributionReady { channel_id, .. } => { 
			// Here we have the final channel_id now
			assert_eq!(channel_id.to_string(), expected_funded_channel_id);
			channel_id
		}
		_ => panic!("FundingInputsContributionReady event missing {:?}", events[0]),
	};

	let extra_funding_input_sats = channel_value_sat + 35_000;
	let custom_input_secret_key = SecretKey::from_slice(&[2; 32]).unwrap();
	let custom_input_pubkey = PublicKey::from_secret_key(&Secp256k1::new(), &custom_input_secret_key);
	let funding_inputs = vec![create_custom_dual_funding_input_with_pubkey(&initiator_node, extra_funding_input_sats, &custom_input_pubkey)];
	let _res = initiator_node.node.contribute_funding_inputs(&channel_id1, &acceptor_node.node.get_our_node_id(), funding_inputs).unwrap();

	// initiator_node will generate a TxAddInput message to kickstart the interactive transaction construction protocol
	let tx_add_input_msg = get_event_msg!(&initiator_node, MessageSendEvent::SendTxAddInput, acceptor_node.node.get_our_node_id());

	let _res = acceptor_node.node.handle_tx_add_input(&initiator_node.node.get_our_node_id(), &tx_add_input_msg);
	let tx_complete_msg = get_event_msg!(acceptor_node, MessageSendEvent::SendTxComplete, initiator_node.node.get_our_node_id());

	let _res = initiator_node.node.handle_tx_complete(&acceptor_node.node.get_our_node_id(), &tx_complete_msg);

	// First output we send is the change output.
	let tx_add_output_msg = get_event_msg!(&initiator_node, MessageSendEvent::SendTxAddOutput, acceptor_node.node.get_our_node_id());

	let _res = acceptor_node.node.handle_tx_add_output(&initiator_node.node.get_our_node_id(), &tx_add_output_msg);
	let tx_complete_msg = get_event_msg!(&acceptor_node, MessageSendEvent::SendTxComplete, initiator_node.node.get_our_node_id());

	let _res = initiator_node.node.handle_tx_complete(&acceptor_node.node.get_our_node_id(), &tx_complete_msg);
	let tx_add_output_msg = get_event_msg!(&initiator_node, MessageSendEvent::SendTxAddOutput, acceptor_node.node.get_our_node_id());
	assert_eq!(tx_add_output_msg.sats, channel_value_sat);

	let _res = acceptor_node.node.handle_tx_add_output(&initiator_node.node.get_our_node_id(), &tx_add_output_msg);
	let tx_complete_msg = get_event_msg!(acceptor_node, MessageSendEvent::SendTxComplete, initiator_node.node.get_our_node_id());

	initiator_node.node.handle_tx_complete(&acceptor_node.node.get_our_node_id(), &tx_complete_msg);
	let msg_events = initiator_node.node.get_and_clear_pending_msg_events();
	assert_eq!(msg_events.len(), 2);
	assert_event_type!(msg_events[0], MessageSendEvent::SendTxComplete);
	assert_event_type!(msg_events[1], MessageSendEvent::UpdateHTLCs);
	let msg_commitment_signed_from_0 = match msg_events[1] {
		MessageSendEvent::UpdateHTLCs { ref updates, .. } => {
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
		assert_eq!(channel_id.to_string(), expected_funded_channel_id);
		let mut witness = Witness::new();
		witness.push(vec![0]);
		unsigned_transaction.input[0].witness = witness;
		let _res = initiator_node.node.funding_transaction_signed(&channel_id1, &counterparty_node_id, unsigned_transaction).unwrap();
	} else { panic!(); }

	let _res = acceptor_node.node.handle_tx_complete(&initiator_node.node.get_our_node_id(), &tx_complete_msg);
	let msg_events = acceptor_node.node.get_and_clear_pending_msg_events();
	// First messsage is commitment_signed, second is tx_signatures (see below for more)
	assert_eq!(msg_events.len(), 1);
	let msg_commitment_signed_from_1 = match msg_events[0] {
		MessageSendEvent::UpdateHTLCs { ref updates, .. } => {
			updates.commitment_signed.clone()
		},
		_ => panic!("Unexpected event"),
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
	get_event!(initiator_node, Event::ChannelPending);
	let tx_signatures_from_0 = get_event_msg!(initiator_node, MessageSendEvent::SendTxSignatures, acceptor_node.node.get_our_node_id());
	let _res = acceptor_node.node.handle_tx_signatures(&initiator_node.node.get_our_node_id(), &tx_signatures_from_0);
	get_event!(acceptor_node, Event::ChannelPending);

	// Check that funding transaction has been broadcasted
	assert_eq!(chanmon_cfgs[initiator_node_index].tx_broadcaster.txn_broadcasted.lock().unwrap().len(), 1);
	let broadcasted_funding_tx = chanmon_cfgs[initiator_node_index].tx_broadcaster.txn_broadcasted.lock().unwrap()[0].clone();
	assert_eq!(broadcasted_funding_tx.encode().len(), 130);
	assert_eq!(broadcasted_funding_tx.txid().to_string(), "6d895eaa56b6c8d896e45d9f54744ac5c075f3e961ae376546e167ec75dbd7be");

	// Simulate confirmation of the funding tx
	confirm_transaction(&initiator_node, &broadcasted_funding_tx);
	let channel_ready_message1 = get_event_msg!(initiator_node, MessageSendEvent::SendChannelReady, acceptor_node.node.get_our_node_id());

	confirm_transaction(&acceptor_node, &broadcasted_funding_tx);
	let channel_ready_message2 = get_event_msg!(acceptor_node, MessageSendEvent::SendChannelReady, initiator_node.node.get_our_node_id());

	let _res = acceptor_node.node.handle_channel_ready(&initiator_node.node.get_our_node_id(), &channel_ready_message1);
	let _ev = get_event!(acceptor_node, Event::ChannelReady);
	let _announcement_signatures2 = get_event_msg!(acceptor_node, MessageSendEvent::SendAnnouncementSignatures, initiator_node.node.get_our_node_id());

	let _res = initiator_node.node.handle_channel_ready(&acceptor_node.node.get_our_node_id(), &channel_ready_message2);
	let _ev = get_event!(initiator_node, Event::ChannelReady);
	let _announcement_signatures1 = get_event_msg!(initiator_node, MessageSendEvent::SendAnnouncementSignatures, acceptor_node.node.get_our_node_id());

	// let (announcement1, update1, update2) = create_chan_between_nodes_with_value_b(&initiator_node, &acceptor_node, &(channel_ready_message1, announcement_signatures1));
	// `update_nodes_with_chan_announce`(&nodes, initiator_node_index, acceptor_node_index, &announcement1, &update1, &update2);

	// check channel capacity and other parameters
	assert_eq!(initiator_node.node.list_channels().len(), 1);
	{
		let channel = &initiator_node.node.list_channels()[0];
		assert_eq!(channel.channel_id.to_string(), expected_funded_channel_id);
		assert!(channel.is_usable);
		assert!(channel.is_channel_ready);
		assert_eq!(channel.channel_value_satoshis, channel_value_sat);
		assert_eq!(channel.balance_msat, 1000 * channel_value_sat);
		assert_eq!(channel.confirmations.unwrap(), 10);
		assert!(channel.funding_txo.is_some());
	}
	// do checks on the acceptor node as well (capacity, etc.)
	assert_eq!(acceptor_node.node.list_channels().len(), 1);
	{
		let channel = &acceptor_node.node.list_channels()[0];
		assert_eq!(channel.channel_id.to_string(), expected_funded_channel_id);
		assert!(channel.is_usable);
		assert!(channel.is_channel_ready);
		assert_eq!(channel.channel_value_satoshis, channel_value_sat);
		assert_eq!(channel.balance_msat, 0);
		assert_eq!(channel.confirmations.unwrap(), 10);
		assert!(channel.funding_txo.is_some());
	}

	// === Channel is now ready for normal operation

	// === Send a payment
	let payment1_amount_msat = 6001_000;

	let _payment_res = send_payment(&initiator_node, &[acceptor_node], payment1_amount_msat);

	assert_eq!(initiator_node.node.list_channels().len(), 1);
	{
		let channel = &initiator_node.node.list_channels()[0];
		assert!(channel.is_usable);
		assert!(channel.is_channel_ready);
		assert_eq!(channel.channel_value_satoshis, channel_value_sat);
		assert_eq!(channel.balance_msat, 1000 * channel_value_sat - payment1_amount_msat);
		assert!(channel.funding_txo.is_some());
	}
	assert_eq!(acceptor_node.node.list_channels().len(), 1);
	{
		let channel = &acceptor_node.node.list_channels()[0];
		assert!(channel.is_usable);
		assert!(channel.is_channel_ready);
		assert_eq!(channel.channel_value_satoshis, channel_value_sat);
		assert_eq!(channel.balance_msat, payment1_amount_msat);
		assert!(channel.funding_txo.is_some());
	}

	// === Start of Splicing
	println!("Start of Splicing ..., channel_id {}", channel_id1);

	// Amount being added to the channel through the splice-in
	let splice_in_sats: u64 = 20000;
	let post_splice_channel_value = channel_value_sat + splice_in_sats;
	let funding_feerate_perkw = 1024; // TODO
	let locktime = 0; // TODO

	// Initiate splice-in (on node0)
	let _res = initiator_node.node.splice_channel(&channel_id1, &acceptor_node.node.get_our_node_id(), splice_in_sats as i64, funding_feerate_perkw, locktime).unwrap();
	// Extract the splice message from node0 to node1
	let splice_msg = get_event_msg!(initiator_node, MessageSendEvent::SendSplice, acceptor_node.node.get_our_node_id());

	let _res = acceptor_node.node.handle_splice(&initiator_node.node.get_our_node_id(), &splice_msg);
	// Extract the splice_ack message from node1 to node0
	let splice_ack_msg = get_event_msg!(acceptor_node, MessageSendEvent::SendSpliceAck, initiator_node.node.get_our_node_id());

	// check that capacity has been updated, channel is not usable, and funding tx is unset
	assert_eq!(acceptor_node.node.list_channels().len(), 1);
	{
		let channel = &acceptor_node.node.list_channels()[0];
		assert_eq!(channel.channel_id.to_string(), expected_funded_channel_id);
		assert!(!channel.is_usable);
		assert!(!channel.is_channel_ready);
		assert_eq!(channel.channel_value_satoshis, post_splice_channel_value);
		assert_eq!(channel.balance_msat, payment1_amount_msat);
		assert!(channel.funding_txo.is_none());
		assert_eq!(channel.confirmations.unwrap(), 0);
	}

	let _res = initiator_node.node.handle_splice_ack(&acceptor_node.node.get_our_node_id(), &splice_ack_msg);

	// Note: SpliceAckedInputsContributionReady emitted
	let events = initiator_node.node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		Event::SpliceAckedInputsContributionReady { channel_id, pre_channel_value_satoshis, post_channel_value_satoshis, holder_funding_satoshis, counterparty_funding_satoshis, .. } => {
			assert_eq!(channel_id.to_string(), expected_funded_channel_id);
			assert_eq!(pre_channel_value_satoshis, channel_value_sat);
			assert_eq!(post_channel_value_satoshis, post_splice_channel_value);
			assert_eq!(holder_funding_satoshis, post_splice_channel_value);
			assert_eq!(counterparty_funding_satoshis, 0);
		},
		_ => panic!("SpliceAckedInputsContributionReady event missing {:?}", events[0]),
	};

	// check that capacity has been updated, channel is not usable, and funding tx is unset
	assert_eq!(initiator_node.node.list_channels().len(), 1);
	{
		let channel = &initiator_node.node.list_channels()[0];
		assert_eq!(channel.channel_id.to_string(), expected_funded_channel_id);
		assert!(!channel.is_usable);
		assert!(!channel.is_channel_ready);
		assert_eq!(channel.channel_value_satoshis, post_splice_channel_value);
		assert_eq!(channel.balance_msat, 1000 * post_splice_channel_value - payment1_amount_msat);
		assert!(channel.funding_txo.is_none());
		assert_eq!(channel.confirmations.unwrap(), 0);
	}
	
	let extra_splice_funding_input_sats = 35_000;
	let funding_inputs = vec![create_custom_dual_funding_input_with_pubkey(&initiator_node, extra_splice_funding_input_sats, &custom_input_pubkey)];

	let _res = initiator_node.node.contribute_funding_inputs(&channel_id1, &acceptor_node.node.get_our_node_id(), funding_inputs).unwrap();

	// Initiator_node will generate first TxAddInput message
	let tx_add_input_msg = get_event_msg!(&initiator_node, MessageSendEvent::SendTxAddInput, acceptor_node.node.get_our_node_id());
	assert_eq!(tx_add_input_msg.prevtx.0.output[tx_add_input_msg.prevtx_out as usize].value, channel_value_sat);

	let _res = acceptor_node.node.handle_tx_add_input(&initiator_node.node.get_our_node_id(), &tx_add_input_msg);
	let tx_complete_msg = get_event_msg!(acceptor_node, MessageSendEvent::SendTxComplete, initiator_node.node.get_our_node_id());

	let _res = initiator_node.node.handle_tx_complete(&acceptor_node.node.get_our_node_id(), &tx_complete_msg);
	// second TxAddInput message for the second input
	let tx_add_input2_msg = get_event_msg!(&initiator_node, MessageSendEvent::SendTxAddInput, acceptor_node.node.get_our_node_id());
	assert_eq!(tx_add_input2_msg.prevtx.0.output[tx_add_input2_msg.prevtx_out as usize].value, extra_splice_funding_input_sats);

	let _res = acceptor_node.node.handle_tx_add_input(&initiator_node.node.get_our_node_id(), &tx_add_input2_msg);
	let tx_complete_msg = get_event_msg!(acceptor_node, MessageSendEvent::SendTxComplete, initiator_node.node.get_our_node_id());

	let _res = initiator_node.node.handle_tx_complete(&acceptor_node.node.get_our_node_id(), &tx_complete_msg);

	// First TxAddOutput is for the change output
	let tx_add_output_msg = get_event_msg!(&initiator_node, MessageSendEvent::SendTxAddOutput, acceptor_node.node.get_our_node_id());
	assert!(tx_add_output_msg.script.is_v0_p2wpkh());
	assert_eq!(tx_add_output_msg.sats, 14314); // extra_splice_input_sats - splice_in_sats - fee

	let _res = acceptor_node.node.handle_tx_add_output(&initiator_node.node.get_our_node_id(), &tx_add_output_msg);
	let tx_complete_msg = get_event_msg!(&acceptor_node, MessageSendEvent::SendTxComplete, initiator_node.node.get_our_node_id());

	let _res = initiator_node.node.handle_tx_complete(&acceptor_node.node.get_our_node_id(), &tx_complete_msg);
	// TxAddOutput for the splice funding
	let tx_add_output2_msg = get_event_msg!(&initiator_node, MessageSendEvent::SendTxAddOutput, acceptor_node.node.get_our_node_id());
	// Check we get the channel funding output.
	assert!(tx_add_output2_msg.script.is_v0_p2wsh());
	assert_eq!(tx_add_output2_msg.sats, post_splice_channel_value);
	
	let _res = acceptor_node.node.handle_tx_add_output(&initiator_node.node.get_our_node_id(), &tx_add_output2_msg);
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
	if let Event::FundingTransactionReadyForSigning {
		channel_id,
		counterparty_node_id,
		mut unsigned_transaction,
		..
	} = get_event!(initiator_node, Event::FundingTransactionReadyForSigning) {
		assert_eq!(channel_id.to_string(), expected_funded_channel_id);
		assert_eq!(counterparty_node_id, acceptor_node.node.get_our_node_id());
		assert_eq!(unsigned_transaction.input.len(), 2);
		// This is the previous funding tx input, already signed (partially)
		assert_eq!(unsigned_transaction.input[0].witness.len(), 4);
		// This is the extra input, not yet signed
		assert_eq!(unsigned_transaction.input[1].witness.len(), 0);

		// Placeholder for signature on the contributed input
		let mut witness1 = Witness::new();
		witness1.push(vec![0]);
		unsigned_transaction.input[1].witness = witness1;

		let _res = initiator_node.node.funding_transaction_signed(&channel_id, &counterparty_node_id, unsigned_transaction).unwrap();
	} else { panic!(); }

	let expected_splice_funding_txid = "039ce00c0a71623b15f7906882a225b4fdc763548c5caf9f71ff7c5bebfe16a4";
	// check new funding tx
	assert_eq!(initiator_node.node.list_channels().len(), 1);
	{
		let channel = &initiator_node.node.list_channels()[0];
		assert!(!channel.is_channel_ready);
		assert_eq!(channel.channel_value_satoshis, post_splice_channel_value);
		assert_eq!(channel.funding_txo.unwrap().txid.to_string(), expected_splice_funding_txid);
		assert_eq!(channel.confirmations.unwrap(), 0);
	}

	let _res = acceptor_node.node.handle_tx_complete(&initiator_node.node.get_our_node_id(), &tx_complete_msg);
	let msg_events = acceptor_node.node.get_and_clear_pending_msg_events();
	// First messsage is commitment_signed, second is tx_signatures (see below for more)
	assert_eq!(msg_events.len(), 1);
	let msg_commitment_signed_from_1 = match msg_events[0] {
		MessageSendEvent::UpdateHTLCs { ref node_id, ref updates } => {
			assert_eq!(*node_id, initiator_node.node.get_our_node_id());
			let res = updates.commitment_signed.clone();
			res
		},
		_ => panic!("Unexpected event {:?}", msg_events[0]),
	};

	// check new funding tx (acceptor side)
	assert_eq!(acceptor_node.node.list_channels().len(), 1);
	{
		let channel = &acceptor_node.node.list_channels()[0];
		assert!(!channel.is_channel_ready);
		assert_eq!(channel.channel_value_satoshis, post_splice_channel_value);
		assert_eq!(channel.funding_txo.unwrap().txid.to_string(), expected_splice_funding_txid);
		assert_eq!(channel.confirmations.unwrap(), 0);
	}

	// Handle the initial commitment_signed exchange. Order is not important here.
	let _res = acceptor_node.node.handle_commitment_signed(&initiator_node.node.get_our_node_id(), &msg_commitment_signed_from_0);
	let _res = initiator_node.node.handle_commitment_signed(&acceptor_node.node.get_our_node_id(), &msg_commitment_signed_from_1);
	check_added_monitors(&initiator_node, 1);
	check_added_monitors(&acceptor_node, 1);

	// The initiator is the only party that contributed any inputs so they should definitely be the one to send tx_signatures
	// only after receiving tx_signatures from the non-initiator in this case.
	let msg_events = initiator_node.node.get_and_clear_pending_msg_events();
	assert!(msg_events.is_empty());
	let msg_events = acceptor_node.node.get_and_clear_pending_msg_events();
	assert_eq!(msg_events.len(), 1);
	let tx_signatures_1 = match msg_events[0] {
		MessageSendEvent::SendTxSignatures { ref node_id, ref msg } => {
			assert_eq!(*node_id, initiator_node.node.get_our_node_id());
			// Here we only get the signature for the shared input
			assert_eq!(msg.witnesses.len(), 0);
			assert!(msg.funding_outpoint_sig.is_some());
			msg
		},
		_ => panic!("Unexpected event {:?}", msg_events[0]),
	};

	let _res = initiator_node.node.handle_tx_signatures(&acceptor_node.node.get_our_node_id(), &tx_signatures_1);
	let events_0 = initiator_node.node.get_and_clear_pending_events();
	assert_eq!(events_0.len(), 0);
	let msg_events = initiator_node.node.get_and_clear_pending_msg_events();
	assert_eq!(msg_events.len(), 1);
	let tx_signatures_0 = match msg_events[0] {
		MessageSendEvent::SendTxSignatures { ref node_id, ref msg } => {
			assert_eq!(*node_id, acceptor_node.node.get_our_node_id());
			// Here we get the witnesses for the two inputs:
			// - the custom input, and
			// - the previous funding tx, also in the tlvs
			assert_eq!(msg.witnesses.len(), 2);
			assert_eq!(msg.witnesses[0].len(), 4);
			assert_eq!(msg.witnesses[1].len(), 1);
			assert!(msg.funding_outpoint_sig.is_some());
			msg
		},
		_ => panic!("Unexpected event {:?}", msg_events[0]),
	};
	let _res = acceptor_node.node.handle_tx_signatures(&initiator_node.node.get_our_node_id(), &tx_signatures_0);

	let events_1 = acceptor_node.node.get_and_clear_pending_events();
	assert_eq!(events_1.len(), 0);

	// Check that funding transaction has been broadcasted
	assert_eq!(chanmon_cfgs[initiator_node_index].tx_broadcaster.txn_broadcasted.lock().unwrap().len(), 2);
	let broadcasted_splice_tx = chanmon_cfgs[initiator_node_index].tx_broadcaster.txn_broadcasted.lock().unwrap()[1].clone();
	let expected_funding_tx = "02000000000102bed7db75ec67e1466537ae61e9f375c0c54a74549f5de496d8c8b656aa5e896d010000000000000000a29ca934f2f9e07815e35099881dc8c0de1847ce0f00154de3d66c0133384b7900000000000000000002c0d4010000000000220020203e7308dfff4f1923d21ca23f45545965d1f6b44ea0e2184c5db4d649a61c3aea37000000000000160014d5a9aa98b89acc215fc3d23d6fec0ad59ca3665f040047304402205c607d85347d9f22874500df846f27132ba0cc63cdb758a9cbecfc995bedc3780220200750390185cf03b34896dad01cd885208f0e1105c4cf88145f6342ab2fbe740147304402207325b2cd0eebe00df23f84487ccb5395b6983b35c6206b7aa3f2f47b6f22e449022039b1d3a8d4446f2a466e4f6883eb70b9d805ae5b8ddb7d2e6247c39a75fd411c01475221026a2a07ee436cc6745aed846a76275f66ed16a469706aca3aa581f20b85d85396210307a78def56cba9fc4db22a25928181de538ee59ba1a475ae113af7790acd0db352ae01010000000000";
	assert_eq!(broadcasted_splice_tx.encode().len(), 389);
	assert_eq!(broadcasted_splice_tx.encode().as_hex().to_string(), expected_funding_tx);
	let initiator_funding_key = get_funding_key(&initiator_node, &acceptor_node, &channel_id1);
	let acceptor_funding_key = get_funding_key(&acceptor_node, &initiator_node, &channel_id1);
	verify_splice_funding_tx(&broadcasted_splice_tx, &broadcasted_funding_tx.txid(), post_splice_channel_value, channel_value_sat, &initiator_funding_key, &acceptor_funding_key);

	// Check that funding transaction has been broadcasted on acceptor side as well
	assert_eq!(chanmon_cfgs[acceptor_node_index].tx_broadcaster.txn_broadcasted.lock().unwrap().len(), 2);
	let broadcasted_splice_tx_acc = chanmon_cfgs[acceptor_node_index].tx_broadcaster.txn_broadcasted.lock().unwrap()[1].clone();
	assert_eq!(broadcasted_splice_tx_acc.encode().len(), 389);
	assert_eq!(broadcasted_splice_tx_acc.encode().as_hex().to_string(), expected_funding_tx);

	// Simulate confirmation of the funding tx
	confirm_transaction(&initiator_node, &broadcasted_splice_tx);
	let channel_ready_message = get_event_msg!(initiator_node, MessageSendEvent::SendChannelReady, acceptor_node.node.get_our_node_id());

	confirm_transaction(&acceptor_node, &broadcasted_splice_tx);
	let channel_ready_message2 = get_event_msg!(acceptor_node, MessageSendEvent::SendChannelReady, initiator_node.node.get_our_node_id());

	let _res = acceptor_node.node.handle_channel_ready(&initiator_node.node.get_our_node_id(), &channel_ready_message);
	// let _ev = get_event!(acceptor_node, Event::ChannelReady);
	let events_0 = acceptor_node.node.get_and_clear_pending_events();
	assert_eq!(events_0.len(), 0);
	let _channel_update = get_event_msg!(acceptor_node, MessageSendEvent::SendChannelUpdate, initiator_node.node.get_our_node_id());
	// let announcement_signatures2 = get_event_msg!(acceptor_node, MessageSendEvent::SendAnnouncementSignatures, initiator_node.node.get_our_node_id());

	let _res = initiator_node.node.handle_channel_ready(&acceptor_node.node.get_our_node_id(), &channel_ready_message2);
	// let _ev = get_event!(initiator_node, Event::ChannelReady);
	let events_0 = initiator_node.node.get_and_clear_pending_events();
	assert_eq!(events_0.len(), 0);
	let _channel_update = get_event_msg!(initiator_node, MessageSendEvent::SendChannelUpdate, acceptor_node.node.get_our_node_id());
	// let announcement_signatures1 = get_event_msg!(initiator_node, MessageSendEvent::SendAnnouncementSignatures, acceptor_node.node.get_our_node_id());

	// check new channel capacity and other parameters
	assert_eq!(initiator_node.node.list_channels().len(), 1);
	{
		let channel = &initiator_node.node.list_channels()[0];
		assert_eq!(channel.channel_id.to_string(), expected_funded_channel_id);
		assert!(channel.is_channel_ready);
		assert_eq!(channel.channel_value_satoshis, post_splice_channel_value);
		assert_eq!(channel.balance_msat, 1000 * post_splice_channel_value - payment1_amount_msat);
		assert_eq!(channel.funding_txo.unwrap().txid, broadcasted_splice_tx_acc.txid());
		assert_eq!(channel.confirmations.unwrap(), 10);
	}

	// do the checks on acceptor side as well
	assert_eq!(acceptor_node.node.list_channels().len(), 1);
	{
		let channel = &acceptor_node.node.list_channels()[0];
		assert_eq!(channel.channel_id.to_string(), expected_funded_channel_id);
		assert!(channel.is_channel_ready);
		assert_eq!(channel.channel_value_satoshis, post_splice_channel_value);
		assert_eq!(channel.balance_msat, payment1_amount_msat);
		assert_eq!(channel.funding_txo.unwrap().txid, broadcasted_splice_tx_acc.txid());
		assert_eq!(channel.confirmations.unwrap(), 10);
	}

	// === End of Splicing

	// === Send another payment
	let payment2_amount_msat = 3002_000;

	let _payment_res = send_payment(&initiator_node, &[acceptor_node], payment2_amount_msat);

	// check changed balances
	assert_eq!(initiator_node.node.list_channels().len(), 1);
	{
		let channel = &initiator_node.node.list_channels()[0];
		assert_eq!(channel.channel_value_satoshis, channel_value_sat);
		assert_eq!(channel.balance_msat, 1000 * channel_value_sat - payment1_amount_msat - payment2_amount_msat);
	}
	// do checks on the acceptor node as well
	assert_eq!(acceptor_node.node.list_channels().len(), 1);
	{
		let channel = &acceptor_node.node.list_channels()[0];
		assert_eq!(channel.channel_value_satoshis, channel_value_sat);
		assert_eq!(channel.balance_msat, payment1_amount_msat + payment2_amount_msat);
	}

	// === Close channel, cooperatively
	initiator_node.node.close_channel(&channel_id1, &acceptor_node.node.get_our_node_id()).unwrap();
	let node0_shutdown_message = get_event_msg!(initiator_node, MessageSendEvent::SendShutdown, acceptor_node.node.get_our_node_id());
	acceptor_node.node.handle_shutdown(&initiator_node.node.get_our_node_id(), &node0_shutdown_message);
	let nodes_1_shutdown = get_event_msg!(acceptor_node, MessageSendEvent::SendShutdown, initiator_node.node.get_our_node_id());
	initiator_node.node.handle_shutdown(&acceptor_node.node.get_our_node_id(), &nodes_1_shutdown);
	let _ = get_event_msg!(initiator_node, MessageSendEvent::SendClosingSigned, acceptor_node.node.get_our_node_id());
}
