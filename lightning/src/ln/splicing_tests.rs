// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

#![cfg_attr(not(test), allow(unused_imports))]

use crate::chain::chaininterface::{TransactionType, FEERATE_FLOOR_SATS_PER_KW};
use crate::chain::channelmonitor::{ANTI_REORG_DELAY, LATENCY_GRACE_PERIOD_BLOCKS};
use crate::chain::transaction::OutPoint;
use crate::chain::ChannelMonitorUpdateStatus;
use crate::events::{ClosureReason, Event, FundingInfo, HTLCHandlingFailureType};
use crate::ln::chan_utils;
use crate::ln::channel::CHANNEL_ANNOUNCEMENT_PROPAGATION_DELAY;
use crate::ln::channelmanager::{provided_init_features, PaymentId, BREAKDOWN_TIMEOUT};
use crate::ln::functional_test_utils::*;
use crate::ln::funding::FundingContribution;
use crate::ln::msgs::{self, BaseMessageHandler, ChannelMessageHandler, MessageSendEvent};
use crate::ln::outbound_payment::RecipientOnionFields;
use crate::ln::types::ChannelId;
use crate::routing::router::{PaymentParameters, RouteParameters};
use crate::util::errors::APIError;
use crate::util::ser::Writeable;
use crate::util::wallet_utils::{
	CoinSelection, CoinSelectionSourceSync, ConfirmedUtxo, Input, WalletSourceSync, WalletSync,
};

use crate::sync::Arc;

use bitcoin::hashes::Hash;
use bitcoin::secp256k1::ecdsa::Signature;
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use bitcoin::transaction::Version;
use bitcoin::{
	Amount, FeeRate, OutPoint as BitcoinOutPoint, Psbt, ScriptBuf, Transaction, TxOut, WPubkeyHash,
};

#[test]
fn test_splicing_not_supported_api_error() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let mut features = provided_init_features(&test_default_channel_config());
	features.clear_splicing();
	*node_cfgs[0].override_init_features.borrow_mut() = Some(features);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_id_0 = nodes[0].node.get_our_node_id();
	let node_id_1 = nodes[1].node.get_our_node_id();

	let (_, _, channel_id, _) = create_announced_chan_between_nodes(&nodes, 0, 1);

	let feerate = FeeRate::from_sat_per_kwu(FEERATE_FLOOR_SATS_PER_KW as u64);
	let res = nodes[1].node.splice_channel(&channel_id, &node_id_0, feerate);
	match res {
		Err(APIError::ChannelUnavailable { err }) => {
			assert!(err.contains("Peer does not support splicing"))
		},
		_ => panic!("Wrong error {:?}", res.err().unwrap()),
	}

	nodes[0].node.peer_disconnected(node_id_1);
	nodes[1].node.peer_disconnected(node_id_0);

	let mut features = nodes[0].node.init_features();
	features.set_splicing_optional();
	features.clear_quiescence();
	*nodes[0].override_init_features.borrow_mut() = Some(features);

	let mut reconnect_args = ReconnectArgs::new(&nodes[0], &nodes[1]);
	reconnect_args.send_channel_ready = (true, true);
	reconnect_args.send_announcement_sigs = (true, true);
	reconnect_nodes(reconnect_args);

	let res = nodes[1].node.splice_channel(&channel_id, &node_id_0, feerate);
	match res {
		Err(APIError::ChannelUnavailable { err }) => {
			assert!(err.contains("Peer does not support quiescence, a splicing prerequisite"))
		},
		_ => panic!("Wrong error {:?}", res.err().unwrap()),
	}
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
	let splice_in_value = Amount::from_sat(20_000);

	// Create additional inputs, but insufficient
	let extra_splice_funding_input = splice_in_value - Amount::ONE_SAT;

	provide_utxo_reserves(&nodes, 1, extra_splice_funding_input);

	let feerate = FeeRate::from_sat_per_kwu(1024);

	// Initiate splice-in, with insufficient input contribution
	let funding_template = nodes[0]
		.node
		.splice_channel(&channel_id, &nodes[1].node.get_our_node_id(), feerate)
		.unwrap();

	let wallet = WalletSync::new(Arc::clone(&nodes[0].wallet_source), nodes[0].logger);
	assert!(funding_template.splice_in_sync(splice_in_value, &wallet).is_err());
}

/// A mock wallet that returns a pre-configured [`CoinSelection`] with a single input and change
/// output. Used to test edge cases where the input value is tight relative to the fee estimate.
struct TightBudgetWallet {
	utxo_value: Amount,
	change_value: Amount,
}

impl CoinSelectionSourceSync for TightBudgetWallet {
	fn select_confirmed_utxos(
		&self, _claim_id: Option<crate::chain::ClaimId>, _must_spend: Vec<Input>,
		_must_pay_to: &[TxOut], _target_feerate_sat_per_1000_weight: u32, _max_tx_weight: u64,
	) -> Result<CoinSelection, ()> {
		let prevout = TxOut {
			value: self.utxo_value,
			script_pubkey: ScriptBuf::new_p2wpkh(&WPubkeyHash::all_zeros()),
		};
		let prevtx = Transaction {
			input: vec![],
			output: vec![prevout],
			version: Version::TWO,
			lock_time: bitcoin::absolute::LockTime::ZERO,
		};
		let utxo = ConfirmedUtxo::new_p2wpkh(prevtx, 0).unwrap();

		let change_output = TxOut {
			value: self.change_value,
			script_pubkey: ScriptBuf::new_p2wpkh(&WPubkeyHash::all_zeros()),
		};

		Ok(CoinSelection { confirmed_utxos: vec![utxo], change_output: Some(change_output) })
	}

	fn sign_psbt(&self, _psbt: Psbt) -> Result<Transaction, ()> {
		unreachable!("should not reach signing")
	}
}

#[test]
fn test_validate_accounts_for_change_output_weight() {
	// Demonstrates that estimated_fee includes the change output's weight when building a
	// FundingContribution. A mock wallet returns a single input whose value is between
	// estimated_fee_without_change (1736/1740 sats) and estimated_fee_with_change (1984/1988
	// sats) above value_added. The validate() check correctly catches that the inputs are
	// insufficient when the change output weight is included. Without accounting for the change
	// output weight, the check would incorrectly pass.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let (_, _, channel_id, _) =
		create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100_000, 0);

	let feerate = FeeRate::from_sat_per_kwu(2000);
	let funding_template = nodes[0]
		.node
		.splice_channel(&channel_id, &nodes[1].node.get_our_node_id(), feerate)
		.unwrap();

	// Input value = value_added + 1800: above 1736/1740 (fee without change), below 1984/1988
	// (fee with change).
	let value_added = Amount::from_sat(20_000);
	let wallet = TightBudgetWallet {
		utxo_value: value_added + Amount::from_sat(1800),
		change_value: Amount::from_sat(1000),
	};
	let contribution = funding_template.splice_in_sync(value_added, &wallet).unwrap();

	assert!(contribution.change_output().is_some());
	assert!(contribution.validate().is_err());
}

pub fn negotiate_splice_tx<'a, 'b, 'c, 'd>(
	initiator: &'a Node<'b, 'c, 'd>, acceptor: &'a Node<'b, 'c, 'd>, channel_id: ChannelId,
	funding_contribution: FundingContribution,
) {
	let new_funding_script = complete_splice_handshake(initiator, acceptor);

	complete_interactive_funding_negotiation(
		initiator,
		acceptor,
		channel_id,
		funding_contribution,
		new_funding_script,
	);
}

pub fn initiate_splice_in<'a, 'b, 'c, 'd>(
	initiator: &'a Node<'b, 'c, 'd>, acceptor: &'a Node<'b, 'c, 'd>, channel_id: ChannelId,
	value_added: Amount,
) -> FundingContribution {
	do_initiate_splice_in(initiator, acceptor, channel_id, value_added)
}

pub fn do_initiate_splice_in<'a, 'b, 'c, 'd>(
	initiator: &'a Node<'b, 'c, 'd>, acceptor: &'a Node<'b, 'c, 'd>, channel_id: ChannelId,
	value_added: Amount,
) -> FundingContribution {
	let node_id_acceptor = acceptor.node.get_our_node_id();
	let feerate = FeeRate::from_sat_per_kwu(FEERATE_FLOOR_SATS_PER_KW as u64);
	let funding_template =
		initiator.node.splice_channel(&channel_id, &node_id_acceptor, feerate).unwrap();
	let wallet = WalletSync::new(Arc::clone(&initiator.wallet_source), initiator.logger);
	let funding_contribution = funding_template.splice_in_sync(value_added, &wallet).unwrap();
	initiator
		.node
		.funding_contributed(&channel_id, &node_id_acceptor, funding_contribution.clone(), None)
		.unwrap();
	funding_contribution
}

pub fn initiate_splice_out<'a, 'b, 'c, 'd>(
	initiator: &'a Node<'b, 'c, 'd>, acceptor: &'a Node<'b, 'c, 'd>, channel_id: ChannelId,
	outputs: Vec<TxOut>,
) -> FundingContribution {
	let node_id_acceptor = acceptor.node.get_our_node_id();
	let feerate = FeeRate::from_sat_per_kwu(FEERATE_FLOOR_SATS_PER_KW as u64);
	let funding_template =
		initiator.node.splice_channel(&channel_id, &node_id_acceptor, feerate).unwrap();
	let wallet = WalletSync::new(Arc::clone(&initiator.wallet_source), initiator.logger);
	let funding_contribution = funding_template.splice_out_sync(outputs, &wallet).unwrap();
	initiator
		.node
		.funding_contributed(&channel_id, &node_id_acceptor, funding_contribution.clone(), None)
		.unwrap();
	funding_contribution
}

pub fn initiate_splice_in_and_out<'a, 'b, 'c, 'd>(
	initiator: &'a Node<'b, 'c, 'd>, acceptor: &'a Node<'b, 'c, 'd>, channel_id: ChannelId,
	value_added: Amount, outputs: Vec<TxOut>,
) -> FundingContribution {
	do_initiate_splice_in_and_out(initiator, acceptor, channel_id, value_added, outputs)
}

pub fn do_initiate_splice_in_and_out<'a, 'b, 'c, 'd>(
	initiator: &'a Node<'b, 'c, 'd>, acceptor: &'a Node<'b, 'c, 'd>, channel_id: ChannelId,
	value_added: Amount, outputs: Vec<TxOut>,
) -> FundingContribution {
	let node_id_acceptor = acceptor.node.get_our_node_id();
	let feerate = FeeRate::from_sat_per_kwu(FEERATE_FLOOR_SATS_PER_KW as u64);
	let funding_template =
		initiator.node.splice_channel(&channel_id, &node_id_acceptor, feerate).unwrap();
	let wallet = WalletSync::new(Arc::clone(&initiator.wallet_source), initiator.logger);
	let funding_contribution =
		funding_template.splice_in_and_out_sync(value_added, outputs, &wallet).unwrap();
	initiator
		.node
		.funding_contributed(&channel_id, &node_id_acceptor, funding_contribution.clone(), None)
		.unwrap();
	funding_contribution
}

pub fn complete_splice_handshake<'a, 'b, 'c, 'd>(
	initiator: &'a Node<'b, 'c, 'd>, acceptor: &'a Node<'b, 'c, 'd>,
) -> ScriptBuf {
	let node_id_initiator = initiator.node.get_our_node_id();
	let node_id_acceptor = acceptor.node.get_our_node_id();

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
	initiator_contribution: FundingContribution, new_funding_script: ScriptBuf,
) {
	complete_interactive_funding_negotiation_for_both(
		initiator,
		acceptor,
		channel_id,
		initiator_contribution,
		None,
		new_funding_script,
	);
}

pub fn complete_interactive_funding_negotiation_for_both<'a, 'b, 'c, 'd>(
	initiator: &'a Node<'b, 'c, 'd>, acceptor: &'a Node<'b, 'c, 'd>, channel_id: ChannelId,
	initiator_contribution: FundingContribution,
	acceptor_contribution: Option<FundingContribution>, new_funding_script: ScriptBuf,
) {
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
	let (initiator_inputs, initiator_outputs) = initiator_contribution.into_tx_parts();
	let mut expected_initiator_inputs = initiator_inputs
		.iter()
		.map(|input| input.utxo.outpoint)
		.chain(core::iter::once(funding_outpoint.into_bitcoin_outpoint()))
		.collect::<Vec<_>>();
	let mut expected_initiator_scripts = initiator_outputs
		.into_iter()
		.map(|output| output.script_pubkey)
		.chain(core::iter::once(new_funding_script))
		.collect::<Vec<_>>();

	let (mut expected_acceptor_inputs, mut expected_acceptor_scripts) =
		if let Some(acceptor_contribution) = acceptor_contribution {
			let (acceptor_inputs, acceptor_outputs) = acceptor_contribution.into_tx_parts();
			let expected_acceptor_inputs =
				acceptor_inputs.iter().map(|input| input.utxo.outpoint).collect::<Vec<_>>();
			let expected_acceptor_scripts =
				acceptor_outputs.into_iter().map(|output| output.script_pubkey).collect::<Vec<_>>();
			(expected_acceptor_inputs, expected_acceptor_scripts)
		} else {
			(Vec::new(), Vec::new())
		};

	let mut initiator_sent_tx_complete;
	let mut acceptor_sent_tx_complete = false;
	loop {
		// Initiator's turn: send TxAddInput, TxAddOutput, or TxComplete
		let msg_events = initiator.node.get_and_clear_pending_msg_events();
		assert_eq!(msg_events.len(), 1, "{msg_events:?}");
		match &msg_events[0] {
			MessageSendEvent::SendTxAddInput { msg, .. } => {
				let input_prevout = BitcoinOutPoint {
					txid: msg
						.prevtx
						.as_ref()
						.map(|prevtx| prevtx.compute_txid())
						.or(msg.shared_input_txid)
						.unwrap(),
					vout: msg.prevtx_out,
				};
				expected_initiator_inputs.remove(
					expected_initiator_inputs
						.iter()
						.position(|input| *input == input_prevout)
						.unwrap(),
				);
				acceptor.node.handle_tx_add_input(node_id_initiator, msg);
				initiator_sent_tx_complete = false;
			},
			MessageSendEvent::SendTxAddOutput { msg, .. } => {
				expected_initiator_scripts.remove(
					expected_initiator_scripts
						.iter()
						.position(|script| *script == msg.script)
						.unwrap(),
				);
				acceptor.node.handle_tx_add_output(node_id_initiator, msg);
				initiator_sent_tx_complete = false;
			},
			MessageSendEvent::SendTxComplete { msg, .. } => {
				acceptor.node.handle_tx_complete(node_id_initiator, msg);
				initiator_sent_tx_complete = true;
				if acceptor_sent_tx_complete {
					break;
				}
			},
			_ => panic!("Unexpected message event: {:?}", msg_events[0]),
		}

		// Acceptor's turn: send TxAddInput, TxAddOutput, or TxComplete
		let msg_events = acceptor.node.get_and_clear_pending_msg_events();
		assert_eq!(msg_events.len(), 1, "{msg_events:?}");
		match &msg_events[0] {
			MessageSendEvent::SendTxAddInput { msg, .. } => {
				let input_prevout = BitcoinOutPoint {
					txid: msg
						.prevtx
						.as_ref()
						.map(|prevtx| prevtx.compute_txid())
						.or(msg.shared_input_txid)
						.unwrap(),
					vout: msg.prevtx_out,
				};
				expected_acceptor_inputs.remove(
					expected_acceptor_inputs
						.iter()
						.position(|input| *input == input_prevout)
						.unwrap(),
				);
				initiator.node.handle_tx_add_input(node_id_acceptor, msg);
				acceptor_sent_tx_complete = false;
			},
			MessageSendEvent::SendTxAddOutput { msg, .. } => {
				expected_acceptor_scripts.remove(
					expected_acceptor_scripts
						.iter()
						.position(|script| *script == msg.script)
						.unwrap(),
				);
				initiator.node.handle_tx_add_output(node_id_acceptor, msg);
				acceptor_sent_tx_complete = false;
			},
			MessageSendEvent::SendTxComplete { msg, .. } => {
				initiator.node.handle_tx_complete(node_id_acceptor, msg);
				acceptor_sent_tx_complete = true;
				if initiator_sent_tx_complete {
					break;
				}
			},
			_ => panic!("Unexpected message event: {:?}", msg_events[0]),
		}
	}

	assert!(expected_initiator_inputs.is_empty(), "Not all initiator inputs were sent");
	assert!(expected_initiator_scripts.is_empty(), "Not all initiator outputs were sent");
	assert!(expected_acceptor_inputs.is_empty(), "Not all acceptor inputs were sent");
	assert!(expected_acceptor_scripts.is_empty(), "Not all acceptor outputs were sent");
}

pub fn sign_interactive_funding_tx<'a, 'b, 'c, 'd>(
	initiator: &'a Node<'b, 'c, 'd>, acceptor: &'a Node<'b, 'c, 'd>, is_0conf: bool,
) -> (Transaction, Option<(msgs::SpliceLocked, PublicKey)>) {
	sign_interactive_funding_tx_with_acceptor_contribution(initiator, acceptor, is_0conf, false)
}

pub fn sign_interactive_funding_tx_with_acceptor_contribution<'a, 'b, 'c, 'd>(
	initiator: &'a Node<'b, 'c, 'd>, acceptor: &'a Node<'b, 'c, 'd>, is_0conf: bool,
	acceptor_has_contribution: bool,
) -> (Transaction, Option<(msgs::SpliceLocked, PublicKey)>) {
	let node_id_initiator = initiator.node.get_our_node_id();
	let node_id_acceptor = acceptor.node.get_our_node_id();

	assert!(initiator.node.get_and_clear_pending_msg_events().is_empty());

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
	} else {
		panic!();
	}

	let msg_events = initiator.node.get_and_clear_pending_msg_events();
	assert_eq!(msg_events.len(), 1, "{msg_events:?}");
	let initial_commit_sig_for_acceptor =
		if let MessageSendEvent::UpdateHTLCs { ref updates, .. } = &msg_events[0] {
			updates.commitment_signed[0].clone()
		} else {
			panic!();
		};
	acceptor.node.handle_commitment_signed(node_id_initiator, &initial_commit_sig_for_acceptor);

	if acceptor_has_contribution {
		// When the acceptor contributed inputs, it needs to sign as well. The counterparty's
		// commitment_signed is buffered until the acceptor signs.
		assert!(acceptor.node.get_and_clear_pending_msg_events().is_empty());

		let event = get_event!(acceptor, Event::FundingTransactionReadyForSigning);
		if let Event::FundingTransactionReadyForSigning {
			channel_id,
			counterparty_node_id,
			unsigned_transaction,
			..
		} = event
		{
			let partially_signed_tx = acceptor.wallet_source.sign_tx(unsigned_transaction).unwrap();
			acceptor
				.node
				.funding_transaction_signed(&channel_id, &counterparty_node_id, partially_signed_tx)
				.unwrap();
		} else {
			panic!();
		}
	}

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
		let mut initiator_txn = initiator.tx_broadcaster.txn_broadcast_with_types();
		assert_eq!(initiator_txn.len(), 1);
		let mut acceptor_txn = acceptor.tx_broadcaster.txn_broadcast_with_types();
		assert_eq!(acceptor_txn.len(), 1);
		// Compare transactions only (not types, as counterparty_node_id differs per perspective)
		assert_eq!(initiator_txn[0].0, acceptor_txn[0].0);
		let (tx, initiator_tx_type) = initiator_txn.remove(0);
		let (_, acceptor_tx_type) = acceptor_txn.remove(0);
		// Verify transaction types are Splice for both nodes
		assert!(
			matches!(initiator_tx_type, TransactionType::Splice { .. }),
			"Expected TransactionType::Splice, got {:?}",
			initiator_tx_type
		);
		assert!(
			matches!(acceptor_tx_type, TransactionType::Splice { .. }),
			"Expected TransactionType::Splice, got {:?}",
			acceptor_tx_type
		);
		tx
	};
	(tx, splice_locked)
}

pub fn splice_channel<'a, 'b, 'c, 'd>(
	initiator: &'a Node<'b, 'c, 'd>, acceptor: &'a Node<'b, 'c, 'd>, channel_id: ChannelId,
	funding_contribution: FundingContribution,
) -> (Transaction, ScriptBuf) {
	let node_id_initiator = initiator.node.get_our_node_id();
	let node_id_acceptor = acceptor.node.get_our_node_id();

	let new_funding_script = complete_splice_handshake(initiator, acceptor);

	complete_interactive_funding_negotiation(
		initiator,
		acceptor,
		channel_id,
		funding_contribution,
		new_funding_script.clone(),
	);
	let (splice_tx, splice_locked) = sign_interactive_funding_tx(initiator, acceptor, false);
	assert!(splice_locked.is_none());

	expect_splice_pending_event(initiator, &node_id_acceptor);
	expect_splice_pending_event(acceptor, &node_id_initiator);

	(splice_tx, new_funding_script)
}

pub fn lock_splice_after_blocks<'a, 'b, 'c, 'd>(
	node_a: &'a Node<'b, 'c, 'd>, node_b: &'a Node<'b, 'c, 'd>, num_blocks: u32,
) -> Option<MessageSendEvent> {
	connect_blocks(node_a, num_blocks);
	connect_blocks(node_b, num_blocks);

	let node_id_b = node_b.node.get_our_node_id();
	let splice_locked_for_node_b =
		get_event_msg!(node_a, MessageSendEvent::SendSpliceLocked, node_id_b);
	lock_splice(node_a, node_b, &splice_locked_for_node_b, false)
}

pub fn lock_splice<'a, 'b, 'c, 'd>(
	node_a: &'a Node<'b, 'c, 'd>, node_b: &'a Node<'b, 'c, 'd>,
	splice_locked_for_node_b: &msgs::SpliceLocked, is_0conf: bool,
) -> Option<MessageSendEvent> {
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

	// If the acceptor had a pending QuiescentAction, return the stfu message so that it can be used
	// for the next splice attempt.
	let node_b_stfu = msg_events
		.last()
		.filter(|event| matches!(event, MessageSendEvent::SendStfu { .. }))
		.is_some()
		.then(|| msg_events.pop().unwrap());

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

	node_b_stfu
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
	let (
		persister_0a,
		persister_0b,
		persister_0c,
		persister_0d,
		persister_1a,
		persister_1b,
		persister_1c,
		persister_1d,
	);
	let (
		chain_monitor_0a,
		chain_monitor_0b,
		chain_monitor_0c,
		chain_monitor_0d,
		chain_monitor_1a,
		chain_monitor_1b,
		chain_monitor_1c,
		chain_monitor_1d,
	);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let (node_0a, node_0b, node_0c, node_0d, node_1a, node_1b, node_1c, node_1d);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_id_0 = nodes[0].node.get_our_node_id();
	let node_id_1 = nodes[1].node.get_our_node_id();

	let (_, _, channel_id, _) =
		create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100_000, 50_000_000);

	let outputs = vec![TxOut {
		value: Amount::from_sat(1_000),
		script_pubkey: nodes[0].wallet_source.get_change_script().unwrap(),
	}];
	let funding_contribution =
		initiate_splice_out(&nodes[0], &nodes[1], channel_id, outputs.clone());

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

	expect_splice_failed_events(&nodes[0], &channel_id, funding_contribution);

	let mut reconnect_args = ReconnectArgs::new(&nodes[0], &nodes[1]);
	reconnect_args.send_channel_ready = (true, true);
	reconnect_args.send_announcement_sigs = (true, true);
	reconnect_nodes(reconnect_args);

	let funding_contribution =
		initiate_splice_out(&nodes[0], &nodes[1], channel_id, outputs.clone());

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

	expect_splice_failed_events(&nodes[0], &channel_id, funding_contribution);

	let mut reconnect_args = ReconnectArgs::new(&nodes[0], &nodes[1]);
	reconnect_args.send_channel_ready = (true, true);
	reconnect_args.send_announcement_sigs = (true, true);
	reconnect_nodes(reconnect_args);

	let funding_contribution =
		initiate_splice_out(&nodes[0], &nodes[1], channel_id, outputs.clone());

	// Attempt a splice negotiation that ends before the initial `commitment_signed` messages are
	// exchanged. The node missing the other's `commitment_signed` upon reconnecting should
	// implicitly abort the negotiation and reset the splice state such that we're able to retry
	// another splice later.
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
	let tx_complete = get_event_msg!(nodes[1], MessageSendEvent::SendTxComplete, node_id_0);
	nodes[0].node.handle_tx_complete(node_id_1, &tx_complete);

	let tx_add_output = get_event_msg!(nodes[0], MessageSendEvent::SendTxAddOutput, node_id_1);
	nodes[1].node.handle_tx_add_output(node_id_0, &tx_add_output);
	let tx_complete = get_event_msg!(nodes[1], MessageSendEvent::SendTxComplete, node_id_0);
	nodes[0].node.handle_tx_complete(node_id_1, &tx_complete);

	let tx_add_output = get_event_msg!(nodes[0], MessageSendEvent::SendTxAddOutput, node_id_1);
	nodes[1].node.handle_tx_add_output(node_id_0, &tx_add_output);
	let tx_complete = get_event_msg!(nodes[1], MessageSendEvent::SendTxComplete, node_id_0);
	nodes[0].node.handle_tx_complete(node_id_1, &tx_complete);

	let msg_events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(msg_events.len(), 1);
	if let MessageSendEvent::SendTxComplete { .. } = &msg_events[0] {
	} else {
		panic!("Unexpected event");
	}

	let _event = get_event!(nodes[0], Event::FundingTransactionReadyForSigning);

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
		// We should have another signing event generated upon reload as they're not persisted.
		let _ = get_event!(nodes[0], Event::FundingTransactionReadyForSigning);
	} else {
		nodes[0].node.peer_disconnected(node_id_1);
		nodes[1].node.peer_disconnected(node_id_0);
	}

	let mut reconnect_args = ReconnectArgs::new(&nodes[0], &nodes[1]);
	reconnect_args.send_channel_ready = (true, false);
	reconnect_args.send_announcement_sigs = (true, true);
	reconnect_args.send_tx_abort = (true, false);
	reconnect_nodes(reconnect_args);

	let tx_abort = get_event_msg!(nodes[0], MessageSendEvent::SendTxAbort, node_id_1);
	nodes[1].node.handle_tx_abort(node_id_0, &tx_abort);
	expect_splice_failed_events(&nodes[0], &channel_id, funding_contribution);

	// Attempt a splice negotiation that completes, (i.e. `tx_signatures` are exchanged). Reconnecting
	// should not abort the negotiation or reset the splice state.
	let funding_contribution = initiate_splice_out(&nodes[0], &nodes[1], channel_id, outputs);
	let (splice_tx, _) = splice_channel(&nodes[0], &nodes[1], channel_id, funding_contribution);

	if reload {
		let encoded_monitor_0 = get_monitor!(nodes[0], channel_id).encode();
		reload_node!(
			nodes[0],
			&nodes[0].node.encode(),
			&[&encoded_monitor_0],
			persister_0d,
			chain_monitor_0d,
			node_0d
		);
		let encoded_monitor_1 = get_monitor!(nodes[1], channel_id).encode();
		reload_node!(
			nodes[1],
			&nodes[1].node.encode(),
			&[&encoded_monitor_1],
			persister_1d,
			chain_monitor_1d,
			node_1d
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

	let outputs = vec![TxOut {
		value: Amount::from_sat(1_000),
		script_pubkey: nodes[0].wallet_source.get_change_script().unwrap(),
	}];
	let funding_contribution =
		initiate_splice_out(&nodes[0], &nodes[1], channel_id, outputs.clone());

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

	expect_splice_failed_events(&nodes[0], &channel_id, funding_contribution);

	let mut reconnect_args = ReconnectArgs::new(&nodes[0], &nodes[1]);
	reconnect_args.send_channel_ready = (true, true);
	reconnect_args.send_announcement_sigs = (true, true);
	reconnect_nodes(reconnect_args);

	let funding_contribution = initiate_splice_out(&nodes[1], &nodes[0], channel_id, outputs);
	let _ = splice_channel(&nodes[1], &nodes[0], channel_id, funding_contribution);
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

	let added_value = Amount::from_sat(initial_channel_value_sat * 2);
	let utxo_value = added_value * 3 / 4;
	let fees = Amount::from_sat(322);

	provide_utxo_reserves(&nodes, 2, utxo_value);

	let funding_contribution = do_initiate_splice_in(&nodes[0], &nodes[1], channel_id, added_value);

	let (splice_tx, new_funding_script) =
		splice_channel(&nodes[0], &nodes[1], channel_id, funding_contribution);
	let expected_change = utxo_value * 2 - added_value - fees;
	assert_eq!(
		splice_tx
			.output
			.iter()
			.find(|txout| txout.script_pubkey != new_funding_script)
			.unwrap()
			.value,
		expected_change,
	);

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

	let outputs = vec![
		TxOut {
			value: Amount::from_sat(initial_channel_value_sat / 4),
			script_pubkey: nodes[0].wallet_source.get_change_script().unwrap(),
		},
		TxOut {
			value: Amount::from_sat(initial_channel_value_sat / 4),
			script_pubkey: nodes[1].wallet_source.get_change_script().unwrap(),
		},
	];
	let funding_contribution = initiate_splice_out(&nodes[0], &nodes[1], channel_id, outputs);

	let (splice_tx, _) = splice_channel(&nodes[0], &nodes[1], channel_id, funding_contribution);
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

#[test]
fn test_splice_in_and_out() {
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

	// Contribute a net negative value, with fees taken from the contributed inputs and the
	// remaining value sent to change
	let htlc_limit_msat = nodes[0].node.list_channels()[0].next_outbound_htlc_limit_msat;
	let added_value = Amount::from_sat(htlc_limit_msat / 1000);
	let removed_value = added_value * 2;
	let utxo_value = added_value * 3 / 4;
	let fees = if cfg!(feature = "grind_signatures") {
		Amount::from_sat(385)
	} else {
		Amount::from_sat(385)
	};

	assert!(htlc_limit_msat > initial_channel_value_sat / 2 * 1000);

	provide_utxo_reserves(&nodes, 2, utxo_value);

	let outputs = vec![
		TxOut {
			value: removed_value / 2,
			script_pubkey: nodes[0].wallet_source.get_change_script().unwrap(),
		},
		TxOut {
			value: removed_value / 2,
			script_pubkey: nodes[1].wallet_source.get_change_script().unwrap(),
		},
	];
	let funding_contribution =
		do_initiate_splice_in_and_out(&nodes[0], &nodes[1], channel_id, added_value, outputs);

	let (splice_tx, new_funding_script) =
		splice_channel(&nodes[0], &nodes[1], channel_id, funding_contribution);
	let expected_change = utxo_value * 2 - added_value - fees;
	assert_eq!(
		splice_tx
			.output
			.iter()
			.filter(|txout| txout.value != removed_value / 2)
			.find(|txout| txout.script_pubkey != new_funding_script)
			.unwrap()
			.value,
		expected_change,
	);

	mine_transaction(&nodes[0], &splice_tx);
	mine_transaction(&nodes[1], &splice_tx);

	let htlc_limit_msat = nodes[0].node.list_channels()[0].next_outbound_htlc_limit_msat;
	assert!(htlc_limit_msat < added_value.to_sat() * 1000);
	let _ = send_payment(&nodes[0], &[&nodes[1]], htlc_limit_msat);

	lock_splice_after_blocks(&nodes[0], &nodes[1], ANTI_REORG_DELAY - 1);

	let htlc_limit_msat = nodes[0].node.list_channels()[0].next_outbound_htlc_limit_msat;
	assert!(htlc_limit_msat < added_value.to_sat() * 1000);
	let _ = send_payment(&nodes[0], &[&nodes[1]], htlc_limit_msat);

	// Contribute a net positive value, with fees taken from the contributed inputs and the
	// remaining value sent to change
	let added_value = Amount::from_sat(initial_channel_value_sat * 2);
	let removed_value = added_value / 2;
	let utxo_value = added_value * 3 / 4;
	let fees = if cfg!(feature = "grind_signatures") {
		Amount::from_sat(385)
	} else {
		Amount::from_sat(385)
	};

	// Clear UTXOs so that the change output from the previous splice isn't considered
	nodes[0].wallet_source.clear_utxos();

	provide_utxo_reserves(&nodes, 2, utxo_value);

	let outputs = vec![
		TxOut {
			value: removed_value / 2,
			script_pubkey: nodes[0].wallet_source.get_change_script().unwrap(),
		},
		TxOut {
			value: removed_value / 2,
			script_pubkey: nodes[1].wallet_source.get_change_script().unwrap(),
		},
	];
	let funding_contribution =
		do_initiate_splice_in_and_out(&nodes[0], &nodes[1], channel_id, added_value, outputs);

	let (splice_tx, new_funding_script) =
		splice_channel(&nodes[0], &nodes[1], channel_id, funding_contribution);
	let expected_change = utxo_value * 2 - added_value - fees;
	assert_eq!(
		splice_tx
			.output
			.iter()
			.filter(|txout| txout.value != removed_value / 2)
			.find(|txout| txout.script_pubkey != new_funding_script)
			.unwrap()
			.value,
		expected_change,
	);

	mine_transaction(&nodes[0], &splice_tx);
	mine_transaction(&nodes[1], &splice_tx);

	let htlc_limit_msat = nodes[0].node.list_channels()[0].next_outbound_htlc_limit_msat;
	assert_eq!(htlc_limit_msat, 0);

	lock_splice_after_blocks(&nodes[0], &nodes[1], ANTI_REORG_DELAY - 1);

	let htlc_limit_msat = nodes[0].node.list_channels()[0].next_outbound_htlc_limit_msat;
	assert!(htlc_limit_msat > initial_channel_value_sat / 2 * 1000);
	let _ = send_payment(&nodes[0], &[&nodes[1]], htlc_limit_msat);
}

#[test]
fn test_fails_initiating_concurrent_splices() {
	fails_initiating_concurrent_splices(true);
	fails_initiating_concurrent_splices(false);
}

#[cfg(test)]
fn fails_initiating_concurrent_splices(reconnect: bool) {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let config = test_default_channel_config();
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, Some(config)]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let initial_channel_value_sat = 100_000;
	let (_, _, channel_id, _) =
		create_announced_chan_between_nodes_with_value(&nodes, 0, 1, initial_channel_value_sat, 0);
	let node_0_id = nodes[0].node.get_our_node_id();
	let node_1_id = nodes[1].node.get_our_node_id();

	send_payment(&nodes[0], &[&nodes[1]], 1_000);
	provide_utxo_reserves(&nodes, 2, Amount::ONE_BTC);

	let outputs = vec![TxOut {
		value: Amount::from_sat(initial_channel_value_sat / 4),
		script_pubkey: nodes[0].wallet_source.get_change_script().unwrap(),
	}];
	let feerate = FeeRate::from_sat_per_kwu(FEERATE_FLOOR_SATS_PER_KW as u64);

	let funding_template = nodes[0].node.splice_channel(&channel_id, &node_1_id, feerate).unwrap();
	let wallet = WalletSync::new(Arc::clone(&nodes[0].wallet_source), nodes[0].logger);
	let funding_contribution = funding_template.splice_out_sync(outputs.clone(), &wallet).unwrap();
	nodes[0]
		.node
		.funding_contributed(&channel_id, &node_1_id, funding_contribution.clone(), None)
		.unwrap();

	assert_eq!(
		nodes[0].node.splice_channel(&channel_id, &node_1_id, feerate),
		Err(APIError::APIMisuseError {
			err: format!(
				"Channel {} cannot be spliced as one is waiting to be negotiated",
				channel_id
			),
		}),
	);

	let new_funding_script = complete_splice_handshake(&nodes[0], &nodes[1]);

	assert_eq!(
		nodes[0].node.splice_channel(&channel_id, &node_1_id, feerate),
		Err(APIError::APIMisuseError {
			err: format!(
				"Channel {} cannot be spliced as one is currently being negotiated",
				channel_id
			),
		}),
	);

	// The acceptor can enqueue a quiescent action while the current splice is pending.
	let added_value = Amount::from_sat(initial_channel_value_sat);
	let acceptor_template = nodes[1].node.splice_channel(&channel_id, &node_0_id, feerate).unwrap();
	let acceptor_wallet = WalletSync::new(Arc::clone(&nodes[1].wallet_source), nodes[1].logger);
	let acceptor_contribution =
		acceptor_template.splice_in_sync(added_value, &acceptor_wallet).unwrap();
	nodes[1]
		.node
		.funding_contributed(&channel_id, &node_0_id, acceptor_contribution, None)
		.unwrap();

	complete_interactive_funding_negotiation(
		&nodes[0],
		&nodes[1],
		channel_id,
		funding_contribution,
		new_funding_script,
	);

	assert_eq!(
		nodes[0].node.splice_channel(&channel_id, &node_1_id, feerate),
		Err(APIError::APIMisuseError {
			err: format!(
				"Channel {} cannot be spliced as one is currently being negotiated",
				channel_id
			),
		}),
	);

	let (splice_tx, splice_locked) = sign_interactive_funding_tx(&nodes[0], &nodes[1], false);
	assert!(splice_locked.is_none());

	expect_splice_pending_event(&nodes[0], &node_1_id);
	expect_splice_pending_event(&nodes[1], &node_0_id);

	// Now that the splice is pending, another splice may be initiated, but we must wait until
	// the `splice_locked` exchange to send the initiator `stfu`.
	assert!(nodes[0].node.splice_channel(&channel_id, &node_1_id, feerate).is_ok());

	if reconnect {
		nodes[0].node.peer_disconnected(node_1_id);
		nodes[1].node.peer_disconnected(node_0_id);
		reconnect_nodes(ReconnectArgs::new(&nodes[0], &nodes[1]));
	}

	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	mine_transaction(&nodes[0], &splice_tx);
	mine_transaction(&nodes[1], &splice_tx);
	let stfu = lock_splice_after_blocks(&nodes[0], &nodes[1], ANTI_REORG_DELAY - 1);

	assert!(
		matches!(stfu, Some(MessageSendEvent::SendStfu { node_id, .. }) if node_id == node_0_id)
	);
}

#[test]
fn test_initiating_splice_holds_stfu_with_pending_splice() {
	// Test that we don't send stfu too early for a new splice while we're already pending one.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let config = test_default_channel_config();
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, Some(config)]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_0_id = nodes[0].node.get_our_node_id();
	provide_utxo_reserves(&nodes, 2, Amount::ONE_BTC);

	let initial_channel_value_sat = 100_000;
	let (_, _, channel_id, _) =
		create_announced_chan_between_nodes_with_value(&nodes, 0, 1, initial_channel_value_sat, 0);

	// Have both nodes attempt a splice, but only node 0 will call back and negotiate the splice.
	let value_added = Amount::from_sat(10_000);
	let funding_contribution_0 = initiate_splice_in(&nodes[0], &nodes[1], channel_id, value_added);

	let feerate = FeeRate::from_sat_per_kwu(FEERATE_FLOOR_SATS_PER_KW as u64);
	let funding_template = nodes[1].node.splice_channel(&channel_id, &node_0_id, feerate).unwrap();

	let (splice_tx, _) = splice_channel(&nodes[0], &nodes[1], channel_id, funding_contribution_0);

	// With the splice negotiated, have node 1 call back. This will queue the quiescent action, but
	// it shouldn't send stfu yet as there's a pending splice.
	let wallet = WalletSync::new(Arc::clone(&nodes[1].wallet_source), &nodes[1].logger);
	let funding_contribution = funding_template.splice_in_sync(value_added, &wallet).unwrap();
	nodes[1]
		.node
		.funding_contributed(&channel_id, &node_0_id, funding_contribution.clone(), None)
		.unwrap();
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	mine_transaction(&nodes[0], &splice_tx);
	mine_transaction(&nodes[1], &splice_tx);
	let stfu = lock_splice_after_blocks(&nodes[0], &nodes[1], 5);
	assert!(
		matches!(stfu, Some(MessageSendEvent::SendStfu { node_id, .. }) if node_id == node_0_id)
	);
}

#[test]
fn test_splice_both_contribute_tiebreak() {
	// Same feerate: the acceptor's change increases because is_initiator=false has lower weight.
	do_test_splice_both_contribute_tiebreak(None, None);
}

#[test]
fn test_splice_tiebreak_higher_feerate() {
	// Node 0 (winner) uses a higher feerate than node 1 (loser). Node 1's change output is
	// adjusted (reduced) to accommodate the higher feerate. Negotiation succeeds.
	let floor = FEERATE_FLOOR_SATS_PER_KW as u64;
	do_test_splice_both_contribute_tiebreak(
		Some(FeeRate::from_sat_per_kwu(floor * 3)),
		Some(FeeRate::from_sat_per_kwu(floor)),
	);
}

#[test]
fn test_splice_tiebreak_lower_feerate() {
	// Node 0 (winner) uses a lower feerate than node 1 (loser). Node 1's change output increases
	// because the acceptor's fair fee decreases. Negotiation succeeds.
	let floor = FEERATE_FLOOR_SATS_PER_KW as u64;
	do_test_splice_both_contribute_tiebreak(
		Some(FeeRate::from_sat_per_kwu(floor)),
		Some(FeeRate::from_sat_per_kwu(floor * 3)),
	);
}

/// Runs the splice tie-breaker test with optional per-node feerates.
/// If `node_0_feerate` or `node_1_feerate` is None, both use the same default feerate.
#[cfg(test)]
fn do_test_splice_both_contribute_tiebreak(
	node_0_feerate: Option<FeeRate>, node_1_feerate: Option<FeeRate>,
) {
	// Both nodes call splice_channel + splice_in_sync + funding_contributed, both send STFU,
	// one wins the quiescence tie-break (node 0, the outbound channel funder). The loser
	// (node 1) becomes the acceptor and its stored QuiescentAction is consumed by the
	// splice_init handler, contributing its inputs/outputs to the splice transaction.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_id_0 = nodes[0].node.get_our_node_id();
	let node_id_1 = nodes[1].node.get_our_node_id();

	let initial_channel_value_sat = 100_000;
	let (_, _, channel_id, _) =
		create_announced_chan_between_nodes_with_value(&nodes, 0, 1, initial_channel_value_sat, 0);

	let added_value = Amount::from_sat(50_000);
	provide_utxo_reserves(&nodes, 2, Amount::from_sat(100_000));

	let default_feerate = FeeRate::from_sat_per_kwu(FEERATE_FLOOR_SATS_PER_KW as u64);
	let feerate_0 = node_0_feerate.unwrap_or(default_feerate);
	let feerate_1 = node_1_feerate.unwrap_or(default_feerate);

	// Node 0 calls splice_channel + splice_in_sync + funding_contributed at feerate_0.
	let funding_template_0 =
		nodes[0].node.splice_channel(&channel_id, &node_id_1, feerate_0).unwrap();
	let wallet_0 = WalletSync::new(Arc::clone(&nodes[0].wallet_source), nodes[0].logger);
	let node_0_funding_contribution =
		funding_template_0.splice_in_sync(added_value, &wallet_0).unwrap();
	nodes[0]
		.node
		.funding_contributed(&channel_id, &node_id_1, node_0_funding_contribution.clone(), None)
		.unwrap();

	// Node 1 calls splice_channel + splice_in_sync + funding_contributed at feerate_1.
	let funding_template_1 =
		nodes[1].node.splice_channel(&channel_id, &node_id_0, feerate_1).unwrap();
	let wallet_1 = WalletSync::new(Arc::clone(&nodes[1].wallet_source), nodes[1].logger);
	let node_1_funding_contribution =
		funding_template_1.splice_in_sync(added_value, &wallet_1).unwrap();
	nodes[1]
		.node
		.funding_contributed(&channel_id, &node_id_0, node_1_funding_contribution.clone(), None)
		.unwrap();

	// Capture change output values before the tiebreak.
	let node_0_change = node_0_funding_contribution
		.change_output()
		.expect("splice-in should have a change output")
		.clone();
	let node_1_change = node_1_funding_contribution
		.change_output()
		.expect("splice-in should have a change output")
		.clone();

	// Both nodes emit STFU.
	let stfu_0 = get_event_msg!(nodes[0], MessageSendEvent::SendStfu, node_id_1);
	assert!(stfu_0.initiator);
	let stfu_1 = get_event_msg!(nodes[1], MessageSendEvent::SendStfu, node_id_0);
	assert!(stfu_1.initiator);

	// Tie-break: node 1 handles node 0's STFU first — node 1 loses (not the outbound funder).
	nodes[1].node.handle_stfu(node_id_0, &stfu_0);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	// Node 0 handles node 1's STFU — node 0 wins (outbound funder), sends SpliceInit.
	nodes[0].node.handle_stfu(node_id_1, &stfu_1);

	let splice_init = get_event_msg!(nodes[0], MessageSendEvent::SendSpliceInit, node_id_1);

	// Node 1 handles SpliceInit — its contribution is adjusted for node 0's feerate as acceptor,
	// then sends SpliceAck with its contribution.
	nodes[1].node.handle_splice_init(node_id_0, &splice_init);
	let splice_ack = get_event_msg!(nodes[1], MessageSendEvent::SendSpliceAck, node_id_0);
	assert_ne!(
		splice_ack.funding_contribution_satoshis, 0,
		"Acceptor should contribute to the splice"
	);

	// Node 0 handles SpliceAck — starts interactive tx construction.
	nodes[0].node.handle_splice_ack(node_id_1, &splice_ack);

	// Compute the new funding script from the splice pubkeys.
	let new_funding_script = chan_utils::make_funding_redeemscript(
		&splice_init.funding_pubkey,
		&splice_ack.funding_pubkey,
	)
	.to_p2wsh();

	// Complete interactive funding negotiation with both parties' inputs/outputs.
	complete_interactive_funding_negotiation_for_both(
		&nodes[0],
		&nodes[1],
		channel_id,
		node_0_funding_contribution,
		Some(node_1_funding_contribution),
		new_funding_script,
	);

	// Sign (acceptor has contribution) and broadcast.
	let (tx, splice_locked) =
		sign_interactive_funding_tx_with_acceptor_contribution(&nodes[0], &nodes[1], false, true);
	assert!(splice_locked.is_none());

	// The initiator's change output should remain unchanged (no feerate adjustment).
	let initiator_change_in_tx = tx
		.output
		.iter()
		.find(|o| o.script_pubkey == node_0_change.script_pubkey)
		.expect("Initiator's change output should be in the splice transaction");
	assert_eq!(
		initiator_change_in_tx.value, node_0_change.value,
		"Initiator's change output should remain unchanged",
	);

	// The acceptor's change output should be adjusted based on the feerate difference.
	let acceptor_change_in_tx = tx
		.output
		.iter()
		.find(|o| o.script_pubkey == node_1_change.script_pubkey)
		.expect("Acceptor's change output should be in the splice transaction");
	if feerate_0 <= feerate_1 {
		// Initiator's feerate <= acceptor's original: the acceptor's change increases because
		// is_initiator=false has lower weight, and the feerate is the same or lower.
		assert!(
			acceptor_change_in_tx.value > node_1_change.value,
			"Acceptor's change should increase when initiator feerate ({}) <= acceptor feerate \
			 ({}): adjusted {} vs original {}",
			feerate_0.to_sat_per_kwu(),
			feerate_1.to_sat_per_kwu(),
			acceptor_change_in_tx.value,
			node_1_change.value,
		);
	} else {
		// Initiator's feerate > acceptor's original: the higher feerate more than compensates
		// for the lower weight, so the acceptor's change decreases.
		assert!(
			acceptor_change_in_tx.value < node_1_change.value,
			"Acceptor's change should decrease when initiator feerate ({}) > acceptor feerate \
			 ({}): adjusted {} vs original {}",
			feerate_0.to_sat_per_kwu(),
			feerate_1.to_sat_per_kwu(),
			acceptor_change_in_tx.value,
			node_1_change.value,
		);
	}

	expect_splice_pending_event(&nodes[0], &node_id_1);
	expect_splice_pending_event(&nodes[1], &node_id_0);

	mine_transaction(&nodes[0], &tx);
	mine_transaction(&nodes[1], &tx);

	lock_splice_after_blocks(&nodes[0], &nodes[1], ANTI_REORG_DELAY - 1);
}

#[test]
fn test_splice_tiebreak_feerate_too_high() {
	// Node 0 (winner) uses a feerate high enough that node 1's (loser) contribution cannot
	// cover the fees. Node 1 proceeds without its contribution (QuiescentAction is preserved
	// for a future splice). The splice completes with only node 0's inputs/outputs.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_id_0 = nodes[0].node.get_our_node_id();
	let node_id_1 = nodes[1].node.get_our_node_id();

	let initial_channel_value_sat = 100_000;
	let (_, _, channel_id, _) =
		create_announced_chan_between_nodes_with_value(&nodes, 0, 1, initial_channel_value_sat, 0);

	provide_utxo_reserves(&nodes, 2, Amount::from_sat(100_000));

	// Node 0 uses a high feerate (20,000 sat/kwu). Node 1 uses the floor feerate but
	// splices in a large amount (95,000 sats from a 100,000 sat UTXO), leaving very little
	// change/fee budget. Node 1's budget (~5,000 sats) can't cover the acceptor's fair fee
	// at 20,000 sat/kwu, so adjust_for_feerate fails.
	let high_feerate = FeeRate::from_sat_per_kwu(20_000);
	let floor_feerate = FeeRate::from_sat_per_kwu(FEERATE_FLOOR_SATS_PER_KW as u64);
	let node_0_added_value = Amount::from_sat(50_000);
	let node_1_added_value = Amount::from_sat(95_000);

	// Node 0: high feerate, moderate splice-in.
	let funding_template_0 =
		nodes[0].node.splice_channel(&channel_id, &node_id_1, high_feerate).unwrap();
	let wallet_0 = WalletSync::new(Arc::clone(&nodes[0].wallet_source), nodes[0].logger);
	let node_0_funding_contribution =
		funding_template_0.splice_in_sync(node_0_added_value, &wallet_0).unwrap();
	nodes[0]
		.node
		.funding_contributed(&channel_id, &node_id_1, node_0_funding_contribution.clone(), None)
		.unwrap();

	// Node 1: floor feerate, tight budget (95,000 from 100,000 sat UTXO).
	let funding_template_1 =
		nodes[1].node.splice_channel(&channel_id, &node_id_0, floor_feerate).unwrap();
	let wallet_1 = WalletSync::new(Arc::clone(&nodes[1].wallet_source), nodes[1].logger);
	let node_1_funding_contribution =
		funding_template_1.splice_in_sync(node_1_added_value, &wallet_1).unwrap();
	nodes[1]
		.node
		.funding_contributed(&channel_id, &node_id_0, node_1_funding_contribution.clone(), None)
		.unwrap();

	// Both emit STFU.
	let stfu_0 = get_event_msg!(nodes[0], MessageSendEvent::SendStfu, node_id_1);
	let stfu_1 = get_event_msg!(nodes[1], MessageSendEvent::SendStfu, node_id_0);

	// Tie-break: node 0 wins.
	nodes[1].node.handle_stfu(node_id_0, &stfu_0);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	nodes[0].node.handle_stfu(node_id_1, &stfu_1);

	// Node 0 sends SpliceInit at 20,000 sat/kwu.
	let splice_init = get_event_msg!(nodes[0], MessageSendEvent::SendSpliceInit, node_id_1);

	// Node 1 handles SpliceInit — adjust_for_feerate fails because node 1's contribution
	// can't cover fees at 20,000 sat/kwu. Node 1 proceeds without its contribution.
	nodes[1].node.handle_splice_init(node_id_0, &splice_init);
	let splice_ack = get_event_msg!(nodes[1], MessageSendEvent::SendSpliceAck, node_id_0);
	assert_eq!(
		splice_ack.funding_contribution_satoshis, 0,
		"Acceptor should not contribute when feerate adjustment fails"
	);

	// Node 0 handles SpliceAck — starts interactive tx construction.
	nodes[0].node.handle_splice_ack(node_id_1, &splice_ack);

	let new_funding_script = chan_utils::make_funding_redeemscript(
		&splice_init.funding_pubkey,
		&splice_ack.funding_pubkey,
	)
	.to_p2wsh();

	// Complete with only node 0's contribution.
	complete_interactive_funding_negotiation_for_both(
		&nodes[0],
		&nodes[1],
		channel_id,
		node_0_funding_contribution,
		None,
		new_funding_script,
	);

	// Sign (no acceptor contribution) and broadcast.
	let (tx, splice_locked) =
		sign_interactive_funding_tx_with_acceptor_contribution(&nodes[0], &nodes[1], false, false);
	assert!(splice_locked.is_none());

	expect_splice_pending_event(&nodes[0], &node_id_1);
	expect_splice_pending_event(&nodes[1], &node_id_0);

	mine_transaction(&nodes[0], &tx);
	mine_transaction(&nodes[1], &tx);

	// After splice_locked, node 1's preserved QuiescentAction triggers STFU.
	let node_1_stfu = lock_splice_after_blocks(&nodes[0], &nodes[1], ANTI_REORG_DELAY - 1);
	let stfu_1 = if let Some(MessageSendEvent::SendStfu { msg, .. }) = node_1_stfu {
		assert!(msg.initiator);
		msg
	} else {
		panic!("Expected SendStfu from node 1 after splice_locked");
	};

	// === Part 2: Node 1 retries as initiator ===

	// Node 0 receives node 1's STFU and responds with its own STFU.
	nodes[0].node.handle_stfu(node_id_1, &stfu_1);
	let stfu_0 = get_event_msg!(nodes[0], MessageSendEvent::SendStfu, node_id_1);

	// Node 1 receives STFU → quiescence established → node 1 is the initiator → sends SpliceInit.
	nodes[1].node.handle_stfu(node_id_0, &stfu_0);
	let splice_init = get_event_msg!(nodes[1], MessageSendEvent::SendSpliceInit, node_id_0);

	// Node 0 handles SpliceInit → sends SpliceAck.
	nodes[0].node.handle_splice_init(node_id_1, &splice_init);
	let splice_ack = get_event_msg!(nodes[0], MessageSendEvent::SendSpliceAck, node_id_1);

	// Node 1 handles SpliceAck → starts interactive tx construction.
	nodes[1].node.handle_splice_ack(node_id_0, &splice_ack);

	let new_funding_script_2 = chan_utils::make_funding_redeemscript(
		&splice_init.funding_pubkey,
		&splice_ack.funding_pubkey,
	)
	.to_p2wsh();

	// Complete interactive funding negotiation with node 1 as initiator (only node 1 contributes).
	complete_interactive_funding_negotiation(
		&nodes[1],
		&nodes[0],
		channel_id,
		node_1_funding_contribution,
		new_funding_script_2,
	);

	// Sign (no acceptor contribution) and broadcast.
	let (new_splice_tx, splice_locked) = sign_interactive_funding_tx(&nodes[1], &nodes[0], false);
	assert!(splice_locked.is_none());

	expect_splice_pending_event(&nodes[1], &node_id_0);
	expect_splice_pending_event(&nodes[0], &node_id_1);

	mine_transaction(&nodes[1], &new_splice_tx);
	mine_transaction(&nodes[0], &new_splice_tx);

	lock_splice_after_blocks(&nodes[1], &nodes[0], ANTI_REORG_DELAY - 1);
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
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_id_0 = nodes[0].node.get_our_node_id();
	let node_id_1 = nodes[1].node.get_our_node_id();

	let initial_channel_capacity = 100_000;
	let (_, _, channel_id, initial_funding_tx) =
		create_announced_chan_between_nodes_with_value(&nodes, 0, 1, initial_channel_capacity, 0);

	let coinbase_tx = provide_utxo_reserves(&nodes, 1, Amount::ONE_BTC);

	// We want to have two HTLCs pending to make sure we can claim those sent before and after a
	// splice negotiation.
	let payment_amount = 1_000_000;
	let (preimage1, payment_hash1, ..) = route_payment(&nodes[0], &[&nodes[1]], payment_amount);

	let splice_in_amount = initial_channel_capacity / 2;
	let initiator_contribution =
		do_initiate_splice_in(&nodes[0], &nodes[1], channel_id, Amount::from_sat(splice_in_amount));
	let (splice_tx, _) = splice_channel(&nodes[0], &nodes[1], channel_id, initiator_contribution);
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
	check_closed_event(&nodes[0], 1, closure_reason, &[node_id_1], closed_channel_capacity);
	check_closed_broadcast(&nodes[0], 1, true);
	check_added_monitors(&nodes[0], 1);

	let closure_reason = ClosureReason::CommitmentTxConfirmed;
	check_closed_event(&nodes[1], 1, closure_reason, &[node_id_0], closed_channel_capacity);
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
	let outputs = vec![
		TxOut {
			value: Amount::from_sat(initial_channel_value_sat / 4),
			script_pubkey: nodes[0].wallet_source.get_change_script().unwrap(),
		},
		TxOut {
			value: Amount::from_sat(initial_channel_value_sat / 4),
			script_pubkey: nodes[1].wallet_source.get_change_script().unwrap(),
		},
	];
	let initiator_contribution = initiate_splice_out(&nodes[0], &nodes[1], channel_id, outputs);
	negotiate_splice_tx(&nodes[0], &nodes[1], channel_id, initiator_contribution);

	// Node 0 should have a signing event to handle since they had a contribution in the splice.
	// Node 1 won't and will immediately try to send their initial `commitment_signed`.
	let signing_event = get_event!(nodes[0], Event::FundingTransactionReadyForSigning);
	assert!(nodes[1].node.get_and_clear_pending_events().is_empty());

	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	let _ = get_htlc_update_msgs(&nodes[1], &node_id_0);

	// Disconnect them, and handle the signing event on the initiator side.
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
		// We should have another signing event generated upon reload as they're not persisted.
		let _ = get_event!(nodes[0], Event::FundingTransactionReadyForSigning);
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

	if let Event::FundingTransactionReadyForSigning { unsigned_transaction, .. } = signing_event {
		let tx = nodes[0].wallet_source.sign_tx(unsigned_transaction).unwrap();
		nodes[0].node.funding_transaction_signed(&channel_id, &node_id_1, tx).unwrap();
	}

	// Since they're not connected, no messages should be sent.
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	// Reestablishing now should force both nodes to retransmit their initial `commitment_signed`
	// message as they were never delivered.
	let mut reconnect_args = ReconnectArgs::new(&nodes[0], &nodes[1]);
	reconnect_args.send_interactive_tx_commit_sig = (true, true);
	reconnect_nodes(reconnect_args);

	// The `commitment_signed` messages were delivered in the reestablishment, so we should expect
	// to see a `RenegotiatedFunding` monitor update on both nodes.
	check_added_monitors(&nodes[0], 1);
	check_added_monitors(&nodes[1], 1);

	macro_rules! reconnect_nodes {
		($f: expr) => {
			nodes[0].node.peer_disconnected(node_id_1);
			nodes[1].node.peer_disconnected(node_id_0);
			let mut reconnect_args = ReconnectArgs::new(&nodes[0], &nodes[1]);
			$f(&mut reconnect_args);
			reconnect_nodes(reconnect_args);
		};
	}

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

	// Both nodes should have their `tx_signatures` ready after completing the monitor update, but
	// node 0 has to wait for node 1 to send theirs first.
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	let _ = get_event_msg!(nodes[1], MessageSendEvent::SendTxSignatures, node_id_0);

	// Reconnecting now should force node 1 to retransmit their `tx_signatures` since it was never
	// delivered. Node 0 still hasn't called back with `funding_transaction_signed`, so its
	// `tx_signatures` is not ready yet.
	reconnect_nodes!(|reconnect_args: &mut ReconnectArgs| {
		reconnect_args.send_interactive_tx_sigs = (true, false);
	});
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
	do_test_propose_splice_while_disconnected(false);
	do_test_propose_splice_while_disconnected(true);
}

#[cfg(test)]
fn do_test_propose_splice_while_disconnected(use_0conf: bool) {
	// Test that both nodes are able to propose a splice while the counterparty is disconnected, and
	// whoever doesn't go first due to the quiescence tie-breaker, will have their contribution
	// merged into the counterparty-initiated splice.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let mut config = test_default_channel_config();
	if use_0conf {
		config.channel_handshake_limits.trust_own_funding_0conf = true;
	}
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[Some(config.clone()), Some(config)]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

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
	let node_0_outputs = vec![TxOut {
		value: Amount::from_sat(splice_out_sat),
		script_pubkey: nodes[0].wallet_source.get_change_script().unwrap(),
	}];
	let node_0_funding_contribution =
		initiate_splice_out(&nodes[0], &nodes[1], channel_id, node_0_outputs);

	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());

	let node_1_outputs = vec![TxOut {
		value: Amount::from_sat(splice_out_sat),
		script_pubkey: nodes[1].wallet_source.get_change_script().unwrap(),
	}];
	let node_1_funding_contribution =
		initiate_splice_out(&nodes[1], &nodes[0], channel_id, node_1_outputs);

	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

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

	// Negotiate the splice to completion. Node 1's quiescent action should be consumed by
	// splice_init, so both contributions are merged into a single splice.
	nodes[1].node.handle_splice_init(node_id_0, &splice_init);
	let splice_ack = get_event_msg!(nodes[1], MessageSendEvent::SendSpliceAck, node_id_0);
	assert_ne!(splice_ack.funding_contribution_satoshis, 0);
	nodes[0].node.handle_splice_ack(node_id_1, &splice_ack);
	let new_funding_script = chan_utils::make_funding_redeemscript(
		&splice_init.funding_pubkey,
		&splice_ack.funding_pubkey,
	)
	.to_p2wsh();
	complete_interactive_funding_negotiation_for_both(
		&nodes[0],
		&nodes[1],
		channel_id,
		node_0_funding_contribution,
		Some(node_1_funding_contribution),
		new_funding_script,
	);
	let (splice_tx, splice_locked) = sign_interactive_funding_tx_with_acceptor_contribution(
		&nodes[0], &nodes[1], use_0conf, true,
	);
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

		// Mine enough blocks for the splice to become locked.
		connect_blocks(&nodes[0], ANTI_REORG_DELAY - 1);
		connect_blocks(&nodes[1], ANTI_REORG_DELAY - 1);

		get_event_msg!(nodes[0], MessageSendEvent::SendSpliceLocked, node_id_1)
	};
	nodes[1].node.handle_splice_locked(node_id_0, &splice_locked);

	// Node 1's quiescent action was consumed, so it should NOT send stfu.
	let msg_events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(msg_events.len(), if use_0conf { 1 } else { 2 }, "{msg_events:?}");
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

	// Sanity check that we can still make a test payment.
	send_payment(&nodes[0], &[&nodes[1]], 1_000_000);
}

#[test]
fn disconnect_on_unexpected_interactive_tx_message() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let initiator = &nodes[0];
	let acceptor = &nodes[1];

	let node_id_initiator = initiator.node.get_our_node_id();
	let node_id_acceptor = acceptor.node.get_our_node_id();

	let initial_channel_capacity = 100_000;
	let (_, _, channel_id, _) =
		create_announced_chan_between_nodes_with_value(&nodes, 0, 1, initial_channel_capacity, 0);

	provide_utxo_reserves(&nodes, 1, Amount::ONE_BTC);

	let splice_in_amount = initial_channel_capacity / 2;
	let contribution =
		initiate_splice_in(initiator, acceptor, channel_id, Amount::from_sat(splice_in_amount));

	// Complete interactive-tx construction, but fail by having the acceptor send a duplicate
	// tx_complete instead of commitment_signed.
	negotiate_splice_tx(initiator, acceptor, channel_id, contribution);

	let _ = get_event!(initiator, Event::FundingTransactionReadyForSigning);
	let _ = get_htlc_update_msgs(acceptor, &node_id_initiator);

	let tx_complete = msgs::TxComplete { channel_id };
	initiator.node.handle_tx_complete(node_id_acceptor, &tx_complete);

	let _warning = get_warning_msg(initiator, &node_id_acceptor);
}

#[test]
fn fail_splice_on_interactive_tx_error() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let initiator = &nodes[0];
	let acceptor = &nodes[1];

	let node_id_initiator = initiator.node.get_our_node_id();
	let node_id_acceptor = acceptor.node.get_our_node_id();

	let initial_channel_capacity = 100_000;
	let (_, _, channel_id, _) =
		create_announced_chan_between_nodes_with_value(&nodes, 0, 1, initial_channel_capacity, 0);

	provide_utxo_reserves(&nodes, 1, Amount::ONE_BTC);

	let splice_in_amount = initial_channel_capacity / 2;

	// Fail during interactive-tx construction by having the acceptor echo back tx_add_input instead
	// of sending tx_complete. The failure occurs because the serial id will have the wrong parity.
	let funding_contribution =
		initiate_splice_in(initiator, acceptor, channel_id, Amount::from_sat(splice_in_amount));
	let _ = complete_splice_handshake(initiator, acceptor);

	// Queue an outgoing HTLC to the holding cell. It should be freed once we exit quiescence.
	let (route, payment_hash, _payment_preimage, payment_secret) =
		get_route_and_payment_hash!(initiator, acceptor, 1_000_000);
	let onion = RecipientOnionFields::secret_only(payment_secret, 1_000_000);
	let payment_id = PaymentId(payment_hash.0);
	initiator.node.send_payment_with_route(route, payment_hash, onion, payment_id).unwrap();

	let tx_add_input =
		get_event_msg!(initiator, MessageSendEvent::SendTxAddInput, node_id_acceptor);
	acceptor.node.handle_tx_add_input(node_id_initiator, &tx_add_input);

	let _tx_complete =
		get_event_msg!(acceptor, MessageSendEvent::SendTxComplete, node_id_initiator);
	initiator.node.handle_tx_add_input(node_id_acceptor, &tx_add_input);

	expect_splice_failed_events(initiator, &channel_id, funding_contribution);

	// We exit quiescence upon sending `tx_abort`, so we should see the holding cell be immediately
	// freed.
	let msg_events = initiator.node.get_and_clear_pending_msg_events();
	assert_eq!(msg_events.len(), 2, "{msg_events:?}");
	let tx_abort = if let MessageSendEvent::SendTxAbort { msg, .. } = &msg_events[0] {
		msg
	} else {
		panic!("Unexpected event {:?}", msg_events[0]);
	};
	let update = if let MessageSendEvent::UpdateHTLCs { updates, .. } = &msg_events[1] {
		updates
	} else {
		panic!("Unexpected event {:?}", msg_events[1]);
	};
	check_added_monitors(initiator, 1);

	acceptor.node.handle_tx_abort(node_id_initiator, tx_abort);
	let tx_abort = get_event_msg!(acceptor, MessageSendEvent::SendTxAbort, node_id_initiator);
	initiator.node.handle_tx_abort(node_id_acceptor, &tx_abort);

	acceptor.node.handle_update_add_htlc(node_id_initiator, &update.update_add_htlcs[0]);
	do_commitment_signed_dance(acceptor, initiator, &update.commitment_signed, false, false);
}

#[test]
fn fail_splice_on_tx_abort() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let initiator = &nodes[0];
	let acceptor = &nodes[1];

	let node_id_initiator = initiator.node.get_our_node_id();
	let node_id_acceptor = acceptor.node.get_our_node_id();

	let initial_channel_capacity = 100_000;
	let (_, _, channel_id, _) =
		create_announced_chan_between_nodes_with_value(&nodes, 0, 1, initial_channel_capacity, 0);

	provide_utxo_reserves(&nodes, 1, Amount::ONE_BTC);

	let splice_in_amount = initial_channel_capacity / 2;

	// Fail during interactive-tx construction by having the acceptor send tx_abort instead of
	// tx_complete.
	let funding_contribution =
		initiate_splice_in(initiator, acceptor, channel_id, Amount::from_sat(splice_in_amount));
	let _ = complete_splice_handshake(initiator, acceptor);

	// Queue an outgoing HTLC to the holding cell. It should be freed once we exit quiescence.
	let (route, payment_hash, _payment_preimage, payment_secret) =
		get_route_and_payment_hash!(initiator, acceptor, 1_000_000);
	let onion = RecipientOnionFields::secret_only(payment_secret, 1_000_000);
	let payment_id = PaymentId(payment_hash.0);
	initiator.node.send_payment_with_route(route, payment_hash, onion, payment_id).unwrap();

	let tx_add_input =
		get_event_msg!(initiator, MessageSendEvent::SendTxAddInput, node_id_acceptor);
	acceptor.node.handle_tx_add_input(node_id_initiator, &tx_add_input);

	let _tx_complete =
		get_event_msg!(acceptor, MessageSendEvent::SendTxComplete, node_id_initiator);

	acceptor.node.abandon_splice(&channel_id, &node_id_initiator).unwrap();
	let tx_abort = get_event_msg!(acceptor, MessageSendEvent::SendTxAbort, node_id_initiator);
	initiator.node.handle_tx_abort(node_id_acceptor, &tx_abort);

	expect_splice_failed_events(initiator, &channel_id, funding_contribution);

	// We exit quiescence upon receiving `tx_abort`, so we should see our `tx_abort` echo and the
	// holding cell be immediately freed.
	let msg_events = initiator.node.get_and_clear_pending_msg_events();
	assert_eq!(msg_events.len(), 2, "{msg_events:?}");
	check_added_monitors(initiator, 1);
	if let MessageSendEvent::SendTxAbort { msg, .. } = &msg_events[0] {
		acceptor.node.handle_tx_abort(node_id_initiator, msg);
	} else {
		panic!("Unexpected event {:?}", msg_events[0]);
	};
	if let MessageSendEvent::UpdateHTLCs { updates, .. } = &msg_events[1] {
		acceptor.node.handle_update_add_htlc(node_id_initiator, &updates.update_add_htlcs[0]);
		do_commitment_signed_dance(acceptor, initiator, &updates.commitment_signed, false, false);
	} else {
		panic!("Unexpected event {:?}", msg_events[1]);
	};
}

#[test]
fn fail_splice_on_tx_complete_error() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let config = test_default_channel_config();
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[Some(config.clone()), Some(config)]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let initiator = &nodes[1];
	let acceptor = &nodes[0];

	let node_id_initiator = initiator.node.get_our_node_id();
	let node_id_acceptor = acceptor.node.get_our_node_id();

	let (_, _, channel_id, _) =
		create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100_000, 50_000_000);

	let outputs = vec![TxOut {
		value: Amount::from_sat(1_000),
		script_pubkey: acceptor.wallet_source.get_change_script().unwrap(),
	}];
	let funding_contribution = initiate_splice_out(initiator, acceptor, channel_id, outputs);
	let _ = complete_splice_handshake(initiator, acceptor);

	// Queue an outgoing HTLC to the holding cell. It should be freed once we exit quiescence.
	let (route, payment_hash, _payment_preimage, payment_secret) =
		get_route_and_payment_hash!(initiator, acceptor, 1_000_000);
	let onion = RecipientOnionFields::secret_only(payment_secret, 1_000_000);
	let payment_id = PaymentId(payment_hash.0);
	acceptor.node.send_payment_with_route(route, payment_hash, onion, payment_id).unwrap();

	let tx_add_input =
		get_event_msg!(initiator, MessageSendEvent::SendTxAddInput, node_id_acceptor);
	acceptor.node.handle_tx_add_input(node_id_initiator, &tx_add_input);
	let tx_complete = get_event_msg!(acceptor, MessageSendEvent::SendTxComplete, node_id_initiator);
	initiator.node.handle_tx_complete(node_id_acceptor, &tx_complete);

	// Tamper the shared funding output such that the acceptor fails upon `tx_complete`.
	let mut tx_add_output =
		get_event_msg!(initiator, MessageSendEvent::SendTxAddOutput, node_id_acceptor);
	if tx_add_output.script.is_p2wsh() {
		tx_add_output.sats *= 2;
	}
	acceptor.node.handle_tx_add_output(node_id_initiator, &tx_add_output);
	let tx_complete = get_event_msg!(acceptor, MessageSendEvent::SendTxComplete, node_id_initiator);
	initiator.node.handle_tx_complete(node_id_acceptor, &tx_complete);

	let mut tx_add_output =
		get_event_msg!(initiator, MessageSendEvent::SendTxAddOutput, node_id_acceptor);
	if tx_add_output.script.is_p2wsh() {
		tx_add_output.sats *= 2;
	}
	acceptor.node.handle_tx_add_output(node_id_initiator, &tx_add_output);
	let tx_complete = get_event_msg!(acceptor, MessageSendEvent::SendTxComplete, node_id_initiator);
	initiator.node.handle_tx_complete(node_id_acceptor, &tx_complete);

	let _ = get_event!(initiator, Event::FundingTransactionReadyForSigning);
	let tx_complete = get_event_msg!(initiator, MessageSendEvent::SendTxComplete, node_id_acceptor);
	acceptor.node.handle_tx_complete(node_id_initiator, &tx_complete);

	let msg_events = acceptor.node.get_and_clear_pending_msg_events();
	assert_eq!(msg_events.len(), 2, "{msg_events:?}");
	check_added_monitors(acceptor, 1);
	let tx_abort = if let MessageSendEvent::SendTxAbort { msg, .. } = &msg_events[0] {
		msg
	} else {
		panic!("Unexpected event {:?}", msg_events[0]);
	};
	let update = if let MessageSendEvent::UpdateHTLCs { updates, .. } = &msg_events[1] {
		updates
	} else {
		panic!("Unexpected event {:?}", msg_events[1]);
	};

	initiator.node.handle_tx_abort(node_id_acceptor, tx_abort);
	expect_splice_failed_events(initiator, &channel_id, funding_contribution);

	let tx_abort = get_event_msg!(initiator, MessageSendEvent::SendTxAbort, node_id_acceptor);
	acceptor.node.handle_tx_abort(node_id_initiator, &tx_abort);

	initiator.node.handle_update_add_htlc(node_id_acceptor, &update.update_add_htlcs[0]);
	do_commitment_signed_dance(initiator, acceptor, &update.commitment_signed, false, false);
}

#[test]
fn free_holding_cell_on_tx_signatures_quiescence_exit() {
	// Test that if there's an update in the holding cell while we're quiescent, that it gets freed
	// upon exiting quiescence via the `tx_signatures` exchange.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let config = test_default_channel_config();
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[Some(config.clone()), Some(config)]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let initiator = &nodes[0];
	let acceptor = &nodes[1];
	let node_id_initiator = initiator.node.get_our_node_id();
	let node_id_acceptor = acceptor.node.get_our_node_id();

	let (_, _, channel_id, _) =
		create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100_000, 0);

	let outputs = vec![TxOut {
		value: Amount::from_sat(1_000),
		script_pubkey: initiator.wallet_source.get_change_script().unwrap(),
	}];
	let contribution = initiate_splice_out(initiator, acceptor, channel_id, outputs);
	negotiate_splice_tx(initiator, acceptor, channel_id, contribution);

	// Queue an outgoing HTLC to the holding cell. It should be freed once we exit quiescence.
	let (route, payment_hash, _payment_preimage, payment_secret) =
		get_route_and_payment_hash!(initiator, acceptor, 1_000_000);
	let onion = RecipientOnionFields::secret_only(payment_secret, 1_000_000);
	let payment_id = PaymentId(payment_hash.0);
	initiator.node.send_payment_with_route(route, payment_hash, onion, payment_id).unwrap();
	assert!(initiator.node.get_and_clear_pending_msg_events().is_empty());

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
	} else {
		unreachable!();
	}

	let update = get_htlc_update_msgs(initiator, &node_id_acceptor);
	acceptor.node.handle_commitment_signed(node_id_initiator, &update.commitment_signed[0]);
	check_added_monitors(&acceptor, 1);

	let msg_events = acceptor.node.get_and_clear_pending_msg_events();
	assert_eq!(msg_events.len(), 2, "{msg_events:?}");
	if let MessageSendEvent::UpdateHTLCs { ref updates, .. } = &msg_events[0] {
		let commitment_signed = &updates.commitment_signed[0];
		initiator.node.handle_commitment_signed(node_id_acceptor, commitment_signed);
		check_added_monitors(&initiator, 1);
	} else {
		panic!("Unexpected event {:?}", &msg_events[0]);
	}
	if let MessageSendEvent::SendTxSignatures { ref msg, .. } = &msg_events[1] {
		initiator.node.handle_tx_signatures(node_id_acceptor, msg);
	} else {
		panic!("Unexpected event {:?}", &msg_events[1]);
	}

	// With `tx_signatures` exchanged, we've exited quiescence and should now see the outgoing HTLC
	// update be sent.
	let msg_events = initiator.node.get_and_clear_pending_msg_events();
	assert_eq!(msg_events.len(), 2, "{msg_events:?}");
	check_added_monitors(initiator, 1); // Outgoing HTLC monitor update
	if let MessageSendEvent::SendTxSignatures { ref msg, .. } = &msg_events[0] {
		acceptor.node.handle_tx_signatures(node_id_initiator, msg);
	} else {
		panic!("Unexpected event {:?}", &msg_events[0]);
	}
	if let MessageSendEvent::UpdateHTLCs { updates, .. } = &msg_events[1] {
		acceptor.node.handle_update_add_htlc(node_id_initiator, &updates.update_add_htlcs[0]);
		do_commitment_signed_dance(acceptor, initiator, &updates.commitment_signed, false, false);
	} else {
		panic!("Unexpected event {:?}", &msg_events[1]);
	}

	expect_splice_pending_event(initiator, &node_id_acceptor);
	expect_splice_pending_event(acceptor, &node_id_initiator);
}

#[test]
fn fail_splice_on_channel_close() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let initiator = &nodes[0];
	let acceptor = &nodes[1];

	let _node_id_initiator = initiator.node.get_our_node_id();
	let node_id_acceptor = acceptor.node.get_our_node_id();

	let initial_channel_capacity = 100_000;
	let (_, _, channel_id, _) =
		create_announced_chan_between_nodes_with_value(&nodes, 0, 1, initial_channel_capacity, 0);

	provide_utxo_reserves(&nodes, 1, Amount::ONE_BTC);

	let splice_in_amount = initial_channel_capacity / 2;

	// Close the channel before completion of interactive-tx construction.
	let _ = initiate_splice_in(initiator, acceptor, channel_id, Amount::from_sat(splice_in_amount));
	let _ = complete_splice_handshake(initiator, acceptor);
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
			discard_funding: true,
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
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let initiator = &nodes[0];
	let acceptor = &nodes[1];

	let _node_id_initiator = initiator.node.get_our_node_id();
	let node_id_acceptor = acceptor.node.get_our_node_id();

	let initial_channel_capacity = 100_000;
	let (_, _, channel_id, _) =
		create_announced_chan_between_nodes_with_value(&nodes, 0, 1, initial_channel_capacity, 0);

	let splice_in_amount = initial_channel_capacity / 2;

	provide_utxo_reserves(&nodes, 1, Amount::ONE_BTC);

	// Close the channel before completion of STFU handshake.
	let _ = initiate_splice_in(initiator, acceptor, channel_id, Amount::from_sat(splice_in_amount));

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
			discard_funding: true,
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
fn abandon_splice_quiescent_action_on_shutdown() {
	do_abandon_splice_quiescent_action_on_shutdown(true);
	do_abandon_splice_quiescent_action_on_shutdown(false);
}

#[cfg(test)]
fn do_abandon_splice_quiescent_action_on_shutdown(local_shutdown: bool) {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	provide_utxo_reserves(&nodes, 1, Amount::ONE_BTC);

	let node_id_0 = nodes[0].node.get_our_node_id();
	let node_id_1 = nodes[1].node.get_our_node_id();

	let initial_channel_capacity = 100_000;
	let (_, _, channel_id, _) =
		create_announced_chan_between_nodes_with_value(&nodes, 0, 1, initial_channel_capacity, 0);

	// Since we cannot close after having sent `stfu`, send an HTLC so that when we attempt to
	// splice, the `stfu` message is held back.
	let payment_amount = 1_000_000;
	let (route, payment_hash, _payment_preimage, payment_secret) =
		get_route_and_payment_hash!(&nodes[0], &nodes[1], payment_amount);
	let onion = RecipientOnionFields::secret_only(payment_secret, payment_amount);
	let payment_id = PaymentId(payment_hash.0);
	nodes[0].node.send_payment_with_route(route, payment_hash, onion, payment_id).unwrap();
	let update = get_htlc_update_msgs(&nodes[0], &node_id_1);
	check_added_monitors(&nodes[0], 1);

	nodes[1].node.handle_update_add_htlc(node_id_0, &update.update_add_htlcs[0]);
	nodes[1].node.handle_commitment_signed(node_id_0, &update.commitment_signed[0]);
	check_added_monitors(&nodes[1], 1);
	let (revoke_and_ack, _) = get_revoke_commit_msgs(&nodes[1], &node_id_0);

	nodes[0].node.handle_revoke_and_ack(node_id_1, &revoke_and_ack);
	check_added_monitors(&nodes[0], 1);

	// Attempt the splice. `stfu` should not go out yet as the state machine is pending.
	let splice_in_amount = initial_channel_capacity / 2;
	let funding_contribution =
		initiate_splice_in(&nodes[0], &nodes[1], channel_id, Amount::from_sat(splice_in_amount));
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());

	// Close the channel. We should see a `SpliceFailed` event for the pending splice
	// `QuiescentAction`.
	let (closer_node, closee_node) =
		if local_shutdown { (&nodes[0], &nodes[1]) } else { (&nodes[1], &nodes[0]) };
	let closer_node_id = closer_node.node.get_our_node_id();
	let closee_node_id = closee_node.node.get_our_node_id();

	closer_node.node.close_channel(&channel_id, &closee_node_id).unwrap();
	let shutdown = get_event_msg!(closer_node, MessageSendEvent::SendShutdown, closee_node_id);
	closee_node.node.handle_shutdown(closer_node_id, &shutdown);

	expect_splice_failed_events(&nodes[0], &channel_id, funding_contribution);
	let _ = get_event_msg!(closee_node, MessageSendEvent::SendShutdown, closer_node_id);
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
	let onion = RecipientOnionFields::secret_only(payment_secret, payment_amount);
	let id = PaymentId(payment_hash.0);
	nodes[0].node.send_payment_with_route(route.clone(), payment_hash, onion, id).unwrap();
	check_added_monitors(&nodes[0], 1);

	// Node 1 should now have a pending HTLC to forward to 2.
	let update_add_0_1 = get_htlc_update_msgs(&nodes[0], &node_id_1);
	nodes[1].node.handle_update_add_htlc(node_id_0, &update_add_0_1.update_add_htlcs[0]);
	let commitment = &update_add_0_1.commitment_signed;
	do_commitment_signed_dance(&nodes[1], &nodes[0], commitment, false, false);
	assert!(nodes[1].node.needs_pending_htlc_processing());

	// Splice both channels, lock them, and connect enough blocks to trigger the legacy SCID pruning
	// logic while the HTLC is still pending.
	let outputs_0_1 = vec![TxOut {
		value: Amount::from_sat(1_000),
		script_pubkey: nodes[0].wallet_source.get_change_script().unwrap(),
	}];
	let contribution = initiate_splice_out(&nodes[0], &nodes[1], channel_id_0_1, outputs_0_1);
	let (splice_tx_0_1, _) = splice_channel(&nodes[0], &nodes[1], channel_id_0_1, contribution);
	for node in &nodes {
		mine_transaction(node, &splice_tx_0_1);
	}

	let outputs_1_2 = vec![TxOut {
		value: Amount::from_sat(1_000),
		script_pubkey: nodes[1].wallet_source.get_change_script().unwrap(),
	}];
	let contribution = initiate_splice_out(&nodes[1], &nodes[2], channel_id_1_2, outputs_1_2);
	let (splice_tx_1_2, _) = splice_channel(&nodes[1], &nodes[2], channel_id_1_2, contribution);
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
		let commitment = &update_fail_1_0.commitment_signed;
		do_commitment_signed_dance(&nodes[0], &nodes[1], commitment, false, false);

		let conditions = PaymentFailedConditions::new();
		expect_payment_failed_conditions(&nodes[0], payment_hash, false, conditions);
	} else {
		// Now attempt to forward the HTLC from node 1 to 2.
		nodes[1].node.process_pending_htlc_forwards();
		check_added_monitors(&nodes[1], 1);
		let update_add_1_2 = get_htlc_update_msgs(&nodes[1], &node_id_2);
		nodes[2].node.handle_update_add_htlc(node_id_1, &update_add_1_2.update_add_htlcs[0]);
		let commitment = &update_add_1_2.commitment_signed;
		do_commitment_signed_dance(&nodes[2], &nodes[1], commitment, false, false);
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
		let commitment = &update_fail_1_2.commitment_signed;
		do_commitment_signed_dance(&nodes[1], &nodes[2], commitment, false, false);
		let fail_type = HTLCHandlingFailureType::Forward {
			node_id: Some(node_id_2),
			channel_id: channel_id_1_2,
		};
		expect_and_process_pending_htlcs_and_htlc_handling_failed(&nodes[1], &[fail_type]);
		check_added_monitors(&nodes[1], 1);

		let update_fail_0_1 = get_htlc_update_msgs(&nodes[1], &node_id_0);
		nodes[0].node.handle_update_fail_htlc(node_id_1, &update_fail_0_1.update_fail_htlcs[0]);
		let commitment = &update_fail_0_1.commitment_signed;
		do_commitment_signed_dance(&nodes[0], &nodes[1], commitment, false, false);

		let conditions = PaymentFailedConditions::new();
		expect_payment_failed_conditions(&nodes[0], payment_hash, true, conditions);
	}
}

#[test]
fn test_splice_with_inflight_htlc_forward_and_resolution() {
	do_test_splice_with_inflight_htlc_forward_and_resolution(true);
	do_test_splice_with_inflight_htlc_forward_and_resolution(false);
}

#[test]
fn test_splice_buffer_commitment_signed_until_funding_tx_signed() {
	// Test that when the counterparty sends their initial `commitment_signed` before the user has
	// called `funding_transaction_signed`, we buffer the message and process it at the end of
	// `funding_transaction_signed`. This allows the user to cancel the splice negotiation if
	// desired without having queued an irreversible monitor update.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_id_0 = nodes[0].node.get_our_node_id();
	let node_id_1 = nodes[1].node.get_our_node_id();

	let initial_channel_value_sat = 100_000;
	let (_, _, channel_id, _) =
		create_announced_chan_between_nodes_with_value(&nodes, 0, 1, initial_channel_value_sat, 0);

	// Negotiate a splice-out where only the initiator (node 0) has a contribution.
	// This means node 1 will send their commitment_signed immediately after tx_complete.
	let outputs = vec![TxOut {
		value: Amount::from_sat(1_000),
		script_pubkey: nodes[0].wallet_source.get_change_script().unwrap(),
	}];
	let initiator_contribution = initiate_splice_out(&nodes[0], &nodes[1], channel_id, outputs);
	negotiate_splice_tx(&nodes[0], &nodes[1], channel_id, initiator_contribution);

	// Node 0 (initiator with contribution) should have a signing event to handle.
	let signing_event = get_event!(nodes[0], Event::FundingTransactionReadyForSigning);

	// Node 1 (acceptor with no contribution) won't have a signing event and will immediately
	// send their initial commitment_signed.
	assert!(nodes[1].node.get_and_clear_pending_events().is_empty());
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	let acceptor_commit_sig = get_htlc_update_msgs(&nodes[1], &node_id_0);

	// Deliver the acceptor's commitment_signed to the initiator BEFORE the initiator has called
	// funding_transaction_signed. The message should be buffered, not processed.
	nodes[0].node.handle_commitment_signed(node_id_1, &acceptor_commit_sig.commitment_signed[0]);

	// No monitor update should have happened since the message is buffered.
	check_added_monitors(&nodes[0], 0);
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());

	// Now handle the signing event and call `funding_transaction_signed`.
	if let Event::FundingTransactionReadyForSigning {
		channel_id: event_channel_id,
		counterparty_node_id,
		unsigned_transaction,
		..
	} = signing_event
	{
		assert_eq!(event_channel_id, channel_id);
		assert_eq!(counterparty_node_id, node_id_1);

		let partially_signed_tx = nodes[0].wallet_source.sign_tx(unsigned_transaction).unwrap();
		nodes[0]
			.node
			.funding_transaction_signed(&channel_id, &node_id_1, partially_signed_tx)
			.unwrap();
	} else {
		panic!("Expected FundingTransactionReadyForSigning event");
	}

	// After funding_transaction_signed:
	// 1. The initiator should send their commitment_signed
	// 2. The buffered commitment_signed from the acceptor should be processed (monitor update)
	let msg_events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(msg_events.len(), 1, "{msg_events:?}");
	let initiator_commit_sig =
		if let MessageSendEvent::UpdateHTLCs { ref updates, .. } = &msg_events[0] {
			updates.commitment_signed[0].clone()
		} else {
			panic!("Expected UpdateHTLCs message");
		};

	// The buffered commitment_signed should have been processed, resulting in a monitor update.
	check_added_monitors(&nodes[0], 1);

	// Complete the rest of the flow normally.
	nodes[1].node.handle_commitment_signed(node_id_0, &initiator_commit_sig);
	let msg_events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(msg_events.len(), 1, "{msg_events:?}");
	if let MessageSendEvent::SendTxSignatures { ref msg, .. } = &msg_events[0] {
		nodes[0].node.handle_tx_signatures(node_id_1, msg);
	} else {
		panic!("Expected SendTxSignatures message");
	}
	check_added_monitors(&nodes[1], 1);

	let msg_events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(msg_events.len(), 1, "{msg_events:?}");
	if let MessageSendEvent::SendTxSignatures { ref msg, .. } = &msg_events[0] {
		nodes[1].node.handle_tx_signatures(node_id_0, msg);
	} else {
		panic!("Expected SendTxSignatures message");
	}

	expect_splice_pending_event(&nodes[0], &node_id_1);
	expect_splice_pending_event(&nodes[1], &node_id_0);

	// Both nodes should broadcast the splice transaction.
	let splice_tx = {
		let mut txn_0 = nodes[0].tx_broadcaster.txn_broadcast();
		assert_eq!(txn_0.len(), 1);
		let txn_1 = nodes[1].tx_broadcaster.txn_broadcast();
		assert_eq!(txn_0, txn_1);
		txn_0.remove(0)
	};

	// Verify the channel is operational by sending a payment.
	send_payment(&nodes[0], &[&nodes[1]], 1_000_000);

	// Lock the splice by confirming the transaction.
	mine_transaction(&nodes[0], &splice_tx);
	mine_transaction(&nodes[1], &splice_tx);
	lock_splice_after_blocks(&nodes[0], &nodes[1], ANTI_REORG_DELAY - 1);

	// Verify the channel is still operational by sending another payment.
	send_payment(&nodes[0], &[&nodes[1]], 1_000_000);
}

#[test]
fn test_splice_buffer_invalid_commitment_signed_closes_channel() {
	// Test that when the counterparty sends an invalid `commitment_signed` (with a bad signature)
	// before the user has called `funding_transaction_signed`, the channel is closed with an error
	// when `ChannelManager::funding_transaction_signed` processes the buffered message.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_id_0 = nodes[0].node.get_our_node_id();
	let node_id_1 = nodes[1].node.get_our_node_id();

	let initial_channel_value_sat = 100_000;
	let (_, _, channel_id, _) =
		create_announced_chan_between_nodes_with_value(&nodes, 0, 1, initial_channel_value_sat, 0);

	// Negotiate a splice-out where only the initiator (node 0) has a contribution.
	// This means node 1 will send their commitment_signed immediately after tx_complete.
	let outputs = vec![TxOut {
		value: Amount::from_sat(1_000),
		script_pubkey: nodes[0].wallet_source.get_change_script().unwrap(),
	}];
	let initiator_contribution = initiate_splice_out(&nodes[0], &nodes[1], channel_id, outputs);
	negotiate_splice_tx(&nodes[0], &nodes[1], channel_id, initiator_contribution);

	// Node 0 (initiator with contribution) should have a signing event to handle.
	let signing_event = get_event!(nodes[0], Event::FundingTransactionReadyForSigning);

	// Node 1 (acceptor with no contribution) won't have a signing event and will immediately
	// send their initial commitment_signed.
	assert!(nodes[1].node.get_and_clear_pending_events().is_empty());
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	let mut acceptor_commit_sig = get_htlc_update_msgs(&nodes[1], &node_id_0);

	// Invalidate the signature by modifying one byte. This will cause signature verification
	// to fail when the buffered message is processed.
	let original_sig = acceptor_commit_sig.commitment_signed[0].signature;
	let mut sig_bytes = original_sig.serialize_compact();
	sig_bytes[0] ^= 0x01; // Flip a bit to corrupt the signature
	acceptor_commit_sig.commitment_signed[0].signature =
		Signature::from_compact(&sig_bytes).unwrap();

	// Deliver the acceptor's invalid commitment_signed to the initiator BEFORE the initiator has
	// called funding_transaction_signed. The message should be buffered, not processed.
	nodes[0].node.handle_commitment_signed(node_id_1, &acceptor_commit_sig.commitment_signed[0]);

	// No monitor update should have happened since the message is buffered.
	check_added_monitors(&nodes[0], 0);
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());

	// Now handle the signing event and call `funding_transaction_signed`.
	// This should process the buffered invalid commitment_signed and close the channel.
	if let Event::FundingTransactionReadyForSigning {
		channel_id: event_channel_id,
		counterparty_node_id,
		unsigned_transaction,
		..
	} = signing_event
	{
		assert_eq!(event_channel_id, channel_id);
		assert_eq!(counterparty_node_id, node_id_1);

		let partially_signed_tx = nodes[0].wallet_source.sign_tx(unsigned_transaction).unwrap();
		nodes[0]
			.node
			.funding_transaction_signed(&channel_id, &node_id_1, partially_signed_tx)
			.unwrap();
	} else {
		panic!("Expected FundingTransactionReadyForSigning event");
	}

	// After funding_transaction_signed:
	// 1. The initiator sends its commitment_signed (UpdateHTLCs message).
	// 2. The buffered invalid commitment_signed from the acceptor is processed, causing the
	//    channel to close due to the invalid signature.
	// We expect 3 message events: UpdateHTLCs, BroadcastChannelUpdate, and HandleError.
	let msg_events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(msg_events.len(), 3, "{msg_events:?}");
	match &msg_events[0] {
		MessageSendEvent::UpdateHTLCs { ref updates, .. } => {
			assert!(!updates.commitment_signed.is_empty());
		},
		_ => panic!("Expected UpdateHTLCs message, got {:?}", msg_events[0]),
	}
	match &msg_events[1] {
		MessageSendEvent::HandleError {
			action: msgs::ErrorAction::SendErrorMessage { ref msg },
			..
		} => {
			assert!(msg.data.contains("Invalid commitment tx signature from peer"));
		},
		_ => panic!("Expected HandleError with SendErrorMessage, got {:?}", msg_events[1]),
	}
	match &msg_events[2] {
		MessageSendEvent::BroadcastChannelUpdate { ref msg, .. } => {
			assert_eq!(msg.contents.channel_flags & 2, 2);
		},
		_ => panic!("Expected BroadcastChannelUpdate, got {:?}", msg_events[2]),
	}

	let err = "Invalid commitment tx signature from peer".to_owned();
	let reason = ClosureReason::ProcessingError { err };
	check_closed_events(
		&nodes[0],
		&[ExpectedCloseEvent::from_id_reason(channel_id, false, reason)],
	);
	check_added_monitors(&nodes[0], 1);
}

#[test]
fn test_splice_balance_falls_below_reserve() {
	// Test that we're able to proceed with a splice where the acceptor does not contribute
	// anything, but the initiator does, resulting in an increased channel reserve that the
	// counterparty does not meet but is still valid.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let mut config = test_default_channel_config();
	config.channel_handshake_config.max_inbound_htlc_value_in_flight_percent_of_channel = 100;
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[Some(config.clone()), Some(config)]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let initial_channel_value_sat = 100_000;
	// Push 10k sat to node 1 so it has balance to send HTLCs back.
	let push_msat = 10_000_000;
	let (_, _, channel_id, _) = create_announced_chan_between_nodes_with_value(
		&nodes,
		0,
		1,
		initial_channel_value_sat,
		push_msat,
	);

	let _ = provide_anchor_reserves(&nodes);

	// Create bidirectional pending HTLCs (routed but not claimed).
	// Outbound HTLC from node 0 to node 1.
	let (preimage_0_to_1, _hash_0_to_1, ..) = route_payment(&nodes[0], &[&nodes[1]], 1_000_000);
	// Large inbound HTLC from node 1 to node 0, bringing node 1's remaining balance down to
	// 2000 sat. The old reserve (1% of 100k) is 1000 sat so this is still above reserve.
	let (preimage_1_to_0, _hash_1_to_0, ..) = route_payment(&nodes[1], &[&nodes[0]], 8_000_000);

	// Splice-in 200k sat. The new channel value becomes 300k sat, raising the reserve to 3000
	// sat. Node 1's remaining 2000 sat is now below the new reserve.
	let initiator_contribution =
		initiate_splice_in(&nodes[0], &nodes[1], channel_id, Amount::from_sat(200_000));
	let (splice_tx, _) = splice_channel(&nodes[0], &nodes[1], channel_id, initiator_contribution);

	// Confirm and lock the splice.
	mine_transaction(&nodes[0], &splice_tx);
	mine_transaction(&nodes[1], &splice_tx);
	lock_splice_after_blocks(&nodes[0], &nodes[1], ANTI_REORG_DELAY - 1);

	// Claim both pending HTLCs to verify the channel is fully functional after the splice.
	claim_payment(&nodes[0], &[&nodes[1]], preimage_0_to_1);
	claim_payment(&nodes[1], &[&nodes[0]], preimage_1_to_0);

	// Final sanity check: send a payment using the new spliced capacity.
	let _ = send_payment(&nodes[0], &[&nodes[1]], 1_000_000);
}

#[test]
fn test_funding_contributed_counterparty_not_found() {
	// Tests that calling funding_contributed with an unknown counterparty_node_id returns
	// ChannelUnavailable and emits a DiscardFunding event.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_id_1 = nodes[1].node.get_our_node_id();

	let (_, _, channel_id, _) =
		create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100_000, 50_000_000);

	let splice_in_amount = Amount::from_sat(20_000);
	provide_utxo_reserves(&nodes, 1, splice_in_amount * 2);

	let feerate = FeeRate::from_sat_per_kwu(FEERATE_FLOOR_SATS_PER_KW as u64);
	let funding_template = nodes[0].node.splice_channel(&channel_id, &node_id_1, feerate).unwrap();
	let wallet = WalletSync::new(Arc::clone(&nodes[0].wallet_source), nodes[0].logger);
	let funding_contribution = funding_template.splice_in_sync(splice_in_amount, &wallet).unwrap();

	// Use a fake/unknown public key as counterparty
	let fake_node_id =
		PublicKey::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&[42; 32]).unwrap());

	assert_eq!(
		nodes[0].node.funding_contributed(
			&channel_id,
			&fake_node_id,
			funding_contribution.clone(),
			None
		),
		Err(APIError::no_such_peer(&fake_node_id)),
	);

	expect_discard_funding_event(&nodes[0], &channel_id, funding_contribution);
}

#[test]
fn test_funding_contributed_channel_not_found() {
	// Tests that calling funding_contributed with an unknown channel_id returns
	// ChannelUnavailable and emits a DiscardFunding event.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_id_1 = nodes[1].node.get_our_node_id();

	let (_, _, channel_id, _) =
		create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100_000, 50_000_000);

	let splice_in_amount = Amount::from_sat(20_000);
	provide_utxo_reserves(&nodes, 1, splice_in_amount * 2);

	let feerate = FeeRate::from_sat_per_kwu(FEERATE_FLOOR_SATS_PER_KW as u64);
	let funding_template = nodes[0].node.splice_channel(&channel_id, &node_id_1, feerate).unwrap();
	let wallet = WalletSync::new(Arc::clone(&nodes[0].wallet_source), nodes[0].logger);
	let funding_contribution = funding_template.splice_in_sync(splice_in_amount, &wallet).unwrap();

	// Use a random/unknown channel_id
	let fake_channel_id = ChannelId::from_bytes([42; 32]);

	assert_eq!(
		nodes[0].node.funding_contributed(
			&fake_channel_id,
			&node_id_1,
			funding_contribution.clone(),
			None
		),
		Err(APIError::no_such_channel_for_peer(&fake_channel_id, &node_id_1)),
	);

	expect_discard_funding_event(&nodes[0], &fake_channel_id, funding_contribution);
}

#[test]
fn test_funding_contributed_splice_already_pending() {
	// Tests that calling funding_contributed when there's already a pending splice
	// contribution returns Err(APIMisuseError) and emits a DiscardFunding event containing only the
	// inputs/outputs that are NOT already in the existing contribution.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_id_1 = nodes[1].node.get_our_node_id();

	let (_, _, channel_id, _) =
		create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100_000, 0);

	let splice_in_amount = Amount::from_sat(20_000);
	provide_utxo_reserves(&nodes, 2, splice_in_amount * 2);

	// Use splice_in_and_out with an output so we can test output filtering
	let first_splice_out = TxOut {
		value: Amount::from_sat(5_000),
		script_pubkey: ScriptBuf::new_p2wpkh(&WPubkeyHash::from_raw_hash(Hash::all_zeros())),
	};
	let feerate = FeeRate::from_sat_per_kwu(FEERATE_FLOOR_SATS_PER_KW as u64);
	let funding_template = nodes[0].node.splice_channel(&channel_id, &node_id_1, feerate).unwrap();
	let wallet = WalletSync::new(Arc::clone(&nodes[0].wallet_source), nodes[0].logger);
	let first_contribution = funding_template
		.splice_in_and_out_sync(splice_in_amount, vec![first_splice_out.clone()], &wallet)
		.unwrap();

	// Initiate a second splice with a DIFFERENT output to test that different outputs
	// are included in DiscardFunding (not filtered out)
	let second_splice_out = TxOut {
		value: Amount::from_sat(6_000), // Different amount
		script_pubkey: ScriptBuf::new_p2wpkh(&WPubkeyHash::from_raw_hash(Hash::all_zeros())),
	};

	// Clear UTXOs and add a LARGER one for the second contribution to ensure
	// the change output will be different from the first contribution's change
	//
	// FIXME: Should we actually not consider the change value given DiscardFunding is meant to
	// reclaim the change script pubkey? But that means for other cases we'd need to track which
	// output is for change later in the pipeline.
	nodes[0].wallet_source.clear_utxos();
	provide_utxo_reserves(&nodes, 1, splice_in_amount * 3);

	let funding_template = nodes[0].node.splice_channel(&channel_id, &node_id_1, feerate).unwrap();
	let wallet = WalletSync::new(Arc::clone(&nodes[0].wallet_source), nodes[0].logger);
	let second_contribution = funding_template
		.splice_in_and_out_sync(splice_in_amount, vec![second_splice_out.clone()], &wallet)
		.unwrap();

	// First funding_contributed - this sets up the quiescent action
	nodes[0].node.funding_contributed(&channel_id, &node_id_1, first_contribution, None).unwrap();

	// Drain the pending stfu message
	let _ = get_event_msg!(nodes[0], MessageSendEvent::SendStfu, node_id_1);

	// Second funding_contributed with a different contribution - this should trigger
	// DiscardFunding because there's already a pending quiescent action (splice contribution).
	// Only inputs/outputs NOT in the existing contribution should be discarded.
	let (expected_inputs, expected_outputs) =
		second_contribution.clone().into_contributed_inputs_and_outputs();

	// Returns Err(APIMisuseError) and emits DiscardFunding for the non-duplicate parts of the second contribution
	assert_eq!(
		nodes[0].node.funding_contributed(&channel_id, &node_id_1, second_contribution, None),
		Err(APIError::APIMisuseError {
			err: format!("Channel {} already has a pending funding contribution", channel_id),
		})
	);

	// The second contribution has different outputs (second_splice_out differs from first_splice_out),
	// so those outputs should NOT be filtered out - they should appear in DiscardFunding.
	let events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	match &events[0] {
		Event::DiscardFunding { channel_id: event_channel_id, funding_info } => {
			assert_eq!(event_channel_id, &channel_id);
			if let FundingInfo::Contribution { inputs, outputs } = funding_info {
				// The input is different, so it should be in the discard event
				assert_eq!(*inputs, expected_inputs);
				// The splice-out output is different (6000 vs 5000), so it should be in discard event
				assert!(expected_outputs.contains(&second_splice_out));
				assert!(!expected_outputs.contains(&first_splice_out));
				// The different outputs should NOT be filtered out
				assert_eq!(*outputs, expected_outputs);
			} else {
				panic!("Expected FundingInfo::Contribution");
			}
		},
		_ => panic!("Expected DiscardFunding event"),
	}
}

#[test]
fn test_funding_contributed_duplicate_contribution_no_event() {
	// Tests that calling funding_contributed with the exact same contribution twice
	// returns Err(APIMisuseError) and emits no events on the second call (DoNothing path).
	// This tests the case where all inputs/outputs in the second contribution
	// are already present in the existing contribution.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_id_1 = nodes[1].node.get_our_node_id();

	let (_, _, channel_id, _) =
		create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100_000, 0);

	let splice_in_amount = Amount::from_sat(20_000);
	provide_utxo_reserves(&nodes, 1, splice_in_amount * 2);

	let feerate = FeeRate::from_sat_per_kwu(FEERATE_FLOOR_SATS_PER_KW as u64);
	let funding_template = nodes[0].node.splice_channel(&channel_id, &node_id_1, feerate).unwrap();
	let wallet = WalletSync::new(Arc::clone(&nodes[0].wallet_source), nodes[0].logger);
	let contribution = funding_template.splice_in_sync(splice_in_amount, &wallet).unwrap();

	// First funding_contributed - this sets up the quiescent action
	nodes[0].node.funding_contributed(&channel_id, &node_id_1, contribution.clone(), None).unwrap();

	// Drain the pending stfu message
	let _ = get_event_msg!(nodes[0], MessageSendEvent::SendStfu, node_id_1);

	// Second funding_contributed with the SAME contribution (same inputs/outputs)
	// This should trigger the DoNothing path because all inputs/outputs are duplicates.
	// Returns Err(APIMisuseError) and emits NO events.
	assert_eq!(
		nodes[0].node.funding_contributed(&channel_id, &node_id_1, contribution, None),
		Err(APIError::APIMisuseError {
			err: format!("Duplicate funding contribution for channel {}", channel_id),
		})
	);

	// Verify no events were emitted - the duplicate contribution is silently ignored
	let events = nodes[0].node.get_and_clear_pending_events();
	assert!(events.is_empty(), "Expected no events for duplicate contribution, got {:?}", events);
}

#[test]
fn test_funding_contributed_active_funding_negotiation() {
	do_test_funding_contributed_active_funding_negotiation(0); // AwaitingAck
	do_test_funding_contributed_active_funding_negotiation(1); // ConstructingTransaction
	do_test_funding_contributed_active_funding_negotiation(2); // AwaitingSignatures
}

#[cfg(test)]
fn do_test_funding_contributed_active_funding_negotiation(state: u8) {
	// Tests that calling funding_contributed when a splice is already being actively negotiated
	// (pending_splice.funding_negotiation exists and is_initiator()) returns Err(APIMisuseError)
	// and emits SpliceFailed + DiscardFunding events for non-duplicate contributions, or
	// returns Err(APIMisuseError) with no events for duplicate contributions.
	//
	// State 0: AwaitingAck (splice_init sent, splice_ack not yet received)
	// State 1: ConstructingTransaction (splice handshake complete, interactive TX in progress)
	// State 2: AwaitingSignatures (interactive TX complete, awaiting signing)
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_id_0 = nodes[0].node.get_our_node_id();
	let node_id_1 = nodes[1].node.get_our_node_id();

	let (_, _, channel_id, _) =
		create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100_000, 0);

	let splice_in_amount = Amount::from_sat(20_000);
	provide_utxo_reserves(&nodes, 2, splice_in_amount * 2);

	// Build first contribution
	let feerate = FeeRate::from_sat_per_kwu(FEERATE_FLOOR_SATS_PER_KW as u64);
	let funding_template = nodes[0].node.splice_channel(&channel_id, &node_id_1, feerate).unwrap();
	let wallet = WalletSync::new(Arc::clone(&nodes[0].wallet_source), nodes[0].logger);
	let first_contribution = funding_template.splice_in_sync(splice_in_amount, &wallet).unwrap();

	// Build second contribution with different UTXOs so inputs/outputs don't overlap
	nodes[0].wallet_source.clear_utxos();
	provide_utxo_reserves(&nodes, 1, splice_in_amount * 3);

	let funding_template = nodes[0].node.splice_channel(&channel_id, &node_id_1, feerate).unwrap();
	let wallet = WalletSync::new(Arc::clone(&nodes[0].wallet_source), nodes[0].logger);
	let second_contribution = funding_template.splice_in_sync(splice_in_amount, &wallet).unwrap();

	// First funding_contributed - sets up the quiescent action and queues STFU
	nodes[0]
		.node
		.funding_contributed(&channel_id, &node_id_1, first_contribution.clone(), None)
		.unwrap();

	// Complete the STFU exchange. This consumes the quiescent_action and creates
	// FundingNegotiation::AwaitingAck with splice_init queued.
	let stfu_init = get_event_msg!(nodes[0], MessageSendEvent::SendStfu, node_id_1);
	nodes[1].node.handle_stfu(node_id_0, &stfu_init);
	let stfu_ack = get_event_msg!(nodes[1], MessageSendEvent::SendStfu, node_id_0);
	nodes[0].node.handle_stfu(node_id_1, &stfu_ack);

	// Drain the splice_init from the initiator's pending message events
	let splice_init = get_event_msg!(nodes[0], MessageSendEvent::SendSpliceInit, node_id_1);

	if state >= 1 {
		// Process splice_init/ack to move to ConstructingTransaction
		nodes[1].node.handle_splice_init(node_id_0, &splice_init);
		let splice_ack = get_event_msg!(nodes[1], MessageSendEvent::SendSpliceAck, node_id_0);
		nodes[0].node.handle_splice_ack(node_id_1, &splice_ack);

		if state == 2 {
			// Complete interactive TX negotiation to move to AwaitingSignatures
			let new_funding_script = chan_utils::make_funding_redeemscript(
				&splice_init.funding_pubkey,
				&splice_ack.funding_pubkey,
			)
			.to_p2wsh();

			complete_interactive_funding_negotiation(
				&nodes[0],
				&nodes[1],
				channel_id,
				first_contribution.clone(),
				new_funding_script,
			);

			// Drain the FundingTransactionReadyForSigning event from the initiator
			let _ = get_event!(nodes[0], Event::FundingTransactionReadyForSigning);
		}
	}

	// Call funding_contributed with a different contribution (non-overlapping inputs/outputs).
	// This hits the funding_negotiation path and returns DiscardFunding.
	let (expected_inputs, expected_outputs) =
		second_contribution.clone().into_contributed_inputs_and_outputs();
	assert_eq!(
		nodes[0].node.funding_contributed(&channel_id, &node_id_1, second_contribution, None),
		Err(APIError::APIMisuseError {
			err: format!("Channel {} already has a pending funding contribution", channel_id),
		})
	);

	// Assert DiscardFunding event with the non-duplicate inputs/outputs
	let events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1, "{events:?}");
	match &events[0] {
		Event::DiscardFunding { channel_id: event_channel_id, funding_info } => {
			assert_eq!(*event_channel_id, channel_id);
			if let FundingInfo::Contribution { inputs, outputs } = funding_info {
				assert_eq!(*inputs, expected_inputs);
				assert_eq!(*outputs, expected_outputs);
			} else {
				panic!("Expected FundingInfo::Contribution");
			}
		},
		_ => panic!("Expected DiscardFunding event, got {:?}", events[1]),
	}

	// Also test the DoNothing path: call funding_contributed with the same contribution
	// as the existing negotiation. All inputs/outputs are duplicates, so no events.
	assert_eq!(
		nodes[0].node.funding_contributed(&channel_id, &node_id_1, first_contribution, None),
		Err(APIError::APIMisuseError {
			err: format!("Duplicate funding contribution for channel {}", channel_id),
		})
	);

	let events = nodes[0].node.get_and_clear_pending_events();
	assert!(events.is_empty(), "Expected no events for duplicate contribution, got {:?}", events);

	// Cleanup: drain leftover message events from the in-progress splice negotiation
	if state == 1 {
		// Initiator has its first interactive TX message queued after handle_splice_ack
		let msg_events = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(msg_events.len(), 1, "{msg_events:?}");
		assert!(matches!(msg_events[0], MessageSendEvent::SendTxAddInput { .. }));
	}
	if state == 2 {
		// Acceptor (no contribution) auto-signed and sent commitment_signed
		let msg_events = nodes[1].node.get_and_clear_pending_msg_events();
		assert_eq!(msg_events.len(), 1, "{msg_events:?}");
		assert!(matches!(msg_events[0], MessageSendEvent::UpdateHTLCs { .. }));
	}
}

#[test]
fn test_funding_contributed_channel_shutdown() {
	// Tests that calling funding_contributed after initiating channel shutdown returns Err(APIMisuseError)
	// and emits both SpliceFailed and DiscardFunding events. The channel is no longer usable
	// after shutdown is initiated, so quiescence cannot be proposed.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_id_1 = nodes[1].node.get_our_node_id();

	let (_, _, channel_id, _) =
		create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100_000, 0);

	let splice_in_amount = Amount::from_sat(20_000);
	provide_utxo_reserves(&nodes, 1, splice_in_amount * 2);

	let feerate = FeeRate::from_sat_per_kwu(FEERATE_FLOOR_SATS_PER_KW as u64);
	let funding_template = nodes[0].node.splice_channel(&channel_id, &node_id_1, feerate).unwrap();
	let wallet = WalletSync::new(Arc::clone(&nodes[0].wallet_source), nodes[0].logger);
	let funding_contribution = funding_template.splice_in_sync(splice_in_amount, &wallet).unwrap();

	// Initiate channel shutdown - this makes is_usable() return false
	nodes[0].node.close_channel(&channel_id, &node_id_1).unwrap();

	// Drain the pending shutdown message
	let _ = get_event_msg!(nodes[0], MessageSendEvent::SendShutdown, node_id_1);

	// Now call funding_contributed - this should trigger FailSplice because
	// propose_quiescence() will fail when is_usable() returns false.
	// Returns Err(APIMisuseError) and emits both SpliceFailed and DiscardFunding.
	assert_eq!(
		nodes[0].node.funding_contributed(
			&channel_id,
			&node_id_1,
			funding_contribution.clone(),
			None
		),
		Err(APIError::APIMisuseError {
			err: format!("Channel {} cannot accept funding contribution", channel_id),
		})
	);

	expect_splice_failed_events(&nodes[0], &channel_id, funding_contribution);
}

#[test]
fn test_funding_contributed_unfunded_channel() {
	// Tests that calling funding_contributed on an unfunded channel returns APIMisuseError
	// and emits a DiscardFunding event. The channel exists but is not yet funded.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_id_1 = nodes[1].node.get_our_node_id();

	// Create a funded channel for the splice operation
	let (_, _, funded_channel_id, _) =
		create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100_000, 0);

	// Create an unfunded channel (after open/accept but before funding tx)
	let unfunded_channel_id = exchange_open_accept_chan(&nodes[0], &nodes[1], 50_000, 0);

	// Drain the FundingGenerationReady event for the unfunded channel
	let _ = get_event!(nodes[0], Event::FundingGenerationReady);

	let splice_in_amount = Amount::from_sat(20_000);
	provide_utxo_reserves(&nodes, 1, splice_in_amount * 2);

	let feerate = FeeRate::from_sat_per_kwu(FEERATE_FLOOR_SATS_PER_KW as u64);
	let funding_template =
		nodes[0].node.splice_channel(&funded_channel_id, &node_id_1, feerate).unwrap();
	let wallet = WalletSync::new(Arc::clone(&nodes[0].wallet_source), nodes[0].logger);
	let funding_contribution = funding_template.splice_in_sync(splice_in_amount, &wallet).unwrap();

	// Call funding_contributed with the unfunded channel's ID instead of the funded one.
	// Returns APIMisuseError because the channel is not funded.
	assert_eq!(
		nodes[0].node.funding_contributed(
			&unfunded_channel_id,
			&node_id_1,
			funding_contribution.clone(),
			None
		),
		Err(APIError::APIMisuseError {
			err: format!(
				"Channel with id {} not expecting funding contribution",
				unfunded_channel_id
			),
		})
	);

	expect_discard_funding_event(&nodes[0], &unfunded_channel_id, funding_contribution);
}

// Helper to re-enter quiescence between two nodes where node_a is the initiator.
// Returns after both sides are quiescent (no splice_init is generated since we use DoNothing).
fn reenter_quiescence<'a, 'b, 'c>(
	node_a: &Node<'a, 'b, 'c>, node_b: &Node<'a, 'b, 'c>, channel_id: &ChannelId,
) {
	let node_id_a = node_a.node.get_our_node_id();
	let node_id_b = node_b.node.get_our_node_id();

	node_a.node.maybe_propose_quiescence(&node_id_b, channel_id).unwrap();
	let stfu_a = get_event_msg!(node_a, MessageSendEvent::SendStfu, node_id_b);
	node_b.node.handle_stfu(node_id_a, &stfu_a);
	let stfu_b = get_event_msg!(node_b, MessageSendEvent::SendStfu, node_id_a);
	node_a.node.handle_stfu(node_id_b, &stfu_b);
}

#[test]
fn test_splice_rbf_acceptor_basic() {
	// Test the full end-to-end flow for RBF of a pending splice transaction.
	// Complete a splice-in, then use rbf_channel API to initiate an RBF attempt
	// with a higher feerate, going through the full tx_init_rbf → tx_ack_rbf →
	// interactive TX → signing → mining → splice_locked flow.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_id_0 = nodes[0].node.get_our_node_id();
	let node_id_1 = nodes[1].node.get_our_node_id();

	let initial_channel_value_sat = 100_000;
	let (_, _, channel_id, _) =
		create_announced_chan_between_nodes_with_value(&nodes, 0, 1, initial_channel_value_sat, 0);

	let added_value = Amount::from_sat(50_000);
	provide_utxo_reserves(&nodes, 2, added_value * 2);

	// Step 1: Complete a splice-in from node 0.
	let funding_contribution = do_initiate_splice_in(&nodes[0], &nodes[1], channel_id, added_value);
	// Save the pre-splice funding outpoint before splice_channel modifies the monitor.
	let original_funding_outpoint = nodes[0]
		.chain_monitor
		.chain_monitor
		.get_monitor(channel_id)
		.map(|monitor| (monitor.get_funding_txo(), monitor.get_funding_script()))
		.unwrap();

	let (first_splice_tx, new_funding_script) =
		splice_channel(&nodes[0], &nodes[1], channel_id, funding_contribution);

	// Step 2: Provide more UTXO reserves for the RBF attempt.
	provide_utxo_reserves(&nodes, 2, added_value * 2);

	// Step 3: Use rbf_channel API to initiate the RBF.
	// Original feerate was FEERATE_FLOOR_SATS_PER_KW (253). 253 * 25 / 24 = 263.54, so 264 works.
	let rbf_feerate_sat_per_kwu = (FEERATE_FLOOR_SATS_PER_KW as u64 * 25 + 23) / 24; // ceil(253*25/24) = 264
	let rbf_feerate = FeeRate::from_sat_per_kwu(rbf_feerate_sat_per_kwu);
	let funding_template = nodes[0].node.rbf_channel(&channel_id, &node_id_1, rbf_feerate).unwrap();
	let wallet = WalletSync::new(Arc::clone(&nodes[0].wallet_source), nodes[0].logger);
	let funding_contribution = funding_template.splice_in_sync(added_value, &wallet).unwrap();

	// Step 4: funding_contributed stores QuiescentAction::Splice and proposes quiescence.
	nodes[0]
		.node
		.funding_contributed(&channel_id, &node_id_1, funding_contribution.clone(), None)
		.unwrap();

	// Step 5: STFU exchange.
	let stfu_a = get_event_msg!(nodes[0], MessageSendEvent::SendStfu, node_id_1);
	nodes[1].node.handle_stfu(node_id_0, &stfu_a);
	let stfu_b = get_event_msg!(nodes[1], MessageSendEvent::SendStfu, node_id_0);
	nodes[0].node.handle_stfu(node_id_1, &stfu_b);

	// Step 6: Node 0 sends tx_init_rbf (not splice_init, since pending_splice exists).
	let tx_init_rbf = get_event_msg!(nodes[0], MessageSendEvent::SendTxInitRbf, node_id_1);
	assert_eq!(tx_init_rbf.channel_id, channel_id);
	assert_eq!(tx_init_rbf.feerate_sat_per_1000_weight, rbf_feerate_sat_per_kwu as u32);

	// Step 7: Node 1 handles tx_init_rbf → responds with tx_ack_rbf.
	nodes[1].node.handle_tx_init_rbf(node_id_0, &tx_init_rbf);
	let tx_ack_rbf = get_event_msg!(nodes[1], MessageSendEvent::SendTxAckRbf, node_id_0);
	assert_eq!(tx_ack_rbf.channel_id, channel_id);

	// Step 8: Node 0 handles tx_ack_rbf → starts interactive TX construction.
	nodes[0].node.handle_tx_ack_rbf(node_id_1, &tx_ack_rbf);

	// Step 9: Complete interactive funding negotiation.
	complete_interactive_funding_negotiation(
		&nodes[0],
		&nodes[1],
		channel_id,
		funding_contribution,
		new_funding_script.clone(),
	);

	// Step 10: Sign and broadcast.
	let (rbf_tx, splice_locked) = sign_interactive_funding_tx(&nodes[0], &nodes[1], false);
	assert!(splice_locked.is_none());

	expect_splice_pending_event(&nodes[0], &node_id_1);
	expect_splice_pending_event(&nodes[1], &node_id_0);

	// Step 11: Mine and lock.
	mine_transaction(&nodes[0], &rbf_tx);
	mine_transaction(&nodes[1], &rbf_tx);

	// Lock the RBF splice. We can't use lock_splice_after_blocks directly because the splice
	// promotion generates DiscardFunding events for the old (replaced) splice candidate.
	connect_blocks(&nodes[0], ANTI_REORG_DELAY - 1);
	connect_blocks(&nodes[1], ANTI_REORG_DELAY - 1);

	let splice_locked_b = get_event_msg!(nodes[0], MessageSendEvent::SendSpliceLocked, node_id_1);
	nodes[1].node.handle_splice_locked(node_id_0, &splice_locked_b);

	let mut msg_events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(msg_events.len(), 2, "{msg_events:?}");
	let splice_locked_a =
		if let MessageSendEvent::SendSpliceLocked { msg, .. } = msg_events.remove(0) {
			msg
		} else {
			panic!("Expected SendSpliceLocked, got {:?}", msg_events[0]);
		};
	let announcement_sigs_b =
		if let MessageSendEvent::SendAnnouncementSignatures { msg, .. } = msg_events.remove(0) {
			msg
		} else {
			panic!("Expected SendAnnouncementSignatures");
		};
	nodes[0].node.handle_splice_locked(node_id_1, &splice_locked_a);
	nodes[0].node.handle_announcement_signatures(node_id_1, &announcement_sigs_b);

	// Expect ChannelReady + DiscardFunding for the old splice candidate on both nodes.
	let events_a = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events_a.len(), 2, "{events_a:?}");
	assert!(matches!(events_a[0], Event::ChannelReady { .. }));
	assert!(matches!(events_a[1], Event::DiscardFunding { .. }));
	check_added_monitors(&nodes[0], 1);

	let events_b = nodes[1].node.get_and_clear_pending_events();
	assert_eq!(events_b.len(), 2, "{events_b:?}");
	assert!(matches!(events_b[0], Event::ChannelReady { .. }));
	assert!(matches!(events_b[1], Event::DiscardFunding { .. }));
	check_added_monitors(&nodes[1], 1);

	// Complete the announcement exchange.
	let mut msg_events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(msg_events.len(), 2, "{msg_events:?}");
	if let MessageSendEvent::SendAnnouncementSignatures { msg, .. } = msg_events.remove(0) {
		nodes[1].node.handle_announcement_signatures(node_id_0, &msg);
	} else {
		panic!("Expected SendAnnouncementSignatures");
	}
	assert!(matches!(msg_events.remove(0), MessageSendEvent::BroadcastChannelAnnouncement { .. }));

	let mut msg_events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(msg_events.len(), 1, "{msg_events:?}");
	assert!(matches!(msg_events.remove(0), MessageSendEvent::BroadcastChannelAnnouncement { .. }));

	// Clean up old watched outpoints from the chain source.
	// The original channel's funding outpoint and the first (replaced) splice's funding outpoint
	// are still being watched but are no longer tracked by the deserialized monitor.
	let (orig_outpoint, orig_script) = original_funding_outpoint;
	let first_splice_funding_idx =
		first_splice_tx.output.iter().position(|o| o.script_pubkey == new_funding_script).unwrap();
	let first_splice_outpoint =
		OutPoint { txid: first_splice_tx.compute_txid(), index: first_splice_funding_idx as u16 };
	for node in &nodes {
		node.chain_source.remove_watched_txn_and_outputs(orig_outpoint, orig_script.clone());
		node.chain_source
			.remove_watched_txn_and_outputs(first_splice_outpoint, new_funding_script.clone());
	}
}

#[test]
fn test_splice_rbf_insufficient_feerate() {
	// Test that rbf_channel rejects a feerate that doesn't satisfy the 25/24 rule, and that the
	// acceptor also rejects tx_init_rbf with an insufficient feerate from a misbehaving peer.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_id_0 = nodes[0].node.get_our_node_id();
	let node_id_1 = nodes[1].node.get_our_node_id();

	let initial_channel_value_sat = 100_000;
	let (_, _, channel_id, _) =
		create_announced_chan_between_nodes_with_value(&nodes, 0, 1, initial_channel_value_sat, 0);

	let added_value = Amount::from_sat(50_000);
	provide_utxo_reserves(&nodes, 2, added_value * 2);

	// Complete a splice-in.
	let funding_contribution = do_initiate_splice_in(&nodes[0], &nodes[1], channel_id, added_value);
	let (_splice_tx, _new_funding_script) =
		splice_channel(&nodes[0], &nodes[1], channel_id, funding_contribution);

	// Initiator-side: rbf_channel rejects an insufficient feerate.
	// Original feerate was 253. Using exactly 253 should fail since 253 * 24 < 253 * 25.
	let same_feerate = FeeRate::from_sat_per_kwu(FEERATE_FLOOR_SATS_PER_KW as u64);
	let err = nodes[0].node.rbf_channel(&channel_id, &node_id_1, same_feerate).unwrap_err();
	assert_eq!(
		err,
		APIError::APIMisuseError {
			err: format!(
				"Channel {} RBF feerate {} is less than 25/24 of the previous feerate {}",
				channel_id, FEERATE_FLOOR_SATS_PER_KW, FEERATE_FLOOR_SATS_PER_KW,
			),
		}
	);

	// Acceptor-side: tx_init_rbf with an insufficient feerate is also rejected.
	reenter_quiescence(&nodes[0], &nodes[1], &channel_id);

	let tx_init_rbf = msgs::TxInitRbf {
		channel_id,
		locktime: 0,
		feerate_sat_per_1000_weight: FEERATE_FLOOR_SATS_PER_KW,
		funding_output_contribution: Some(added_value.to_sat() as i64),
	};

	nodes[1].node.handle_tx_init_rbf(node_id_0, &tx_init_rbf);

	let msg_events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(msg_events.len(), 1);
	match &msg_events[0] {
		MessageSendEvent::HandleError { action, .. } => {
			assert_eq!(
				*action,
				msgs::ErrorAction::DisconnectPeerWithWarning {
					msg: msgs::WarningMessage {
						channel_id,
						data: format!(
							"Channel {} RBF feerate {} is less than 25/24 of the previous feerate {}",
							channel_id, FEERATE_FLOOR_SATS_PER_KW, FEERATE_FLOOR_SATS_PER_KW,
						),
					},
				}
			);
		},
		_ => panic!("Expected HandleError, got {:?}", msg_events[0]),
	}
}

#[test]
fn test_splice_rbf_no_pending_splice() {
	// Test that tx_init_rbf is rejected when there is no pending splice to RBF.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_id_0 = nodes[0].node.get_our_node_id();

	let initial_channel_value_sat = 100_000;
	let (_, _, channel_id, _) =
		create_announced_chan_between_nodes_with_value(&nodes, 0, 1, initial_channel_value_sat, 0);

	// Re-enter quiescence without having done a splice.
	reenter_quiescence(&nodes[0], &nodes[1], &channel_id);

	let tx_init_rbf = msgs::TxInitRbf {
		channel_id,
		locktime: 0,
		feerate_sat_per_1000_weight: 500,
		funding_output_contribution: Some(50_000),
	};

	nodes[1].node.handle_tx_init_rbf(node_id_0, &tx_init_rbf);

	let msg_events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(msg_events.len(), 1);
	match &msg_events[0] {
		MessageSendEvent::HandleError { action, .. } => {
			assert_eq!(
				*action,
				msgs::ErrorAction::DisconnectPeerWithWarning {
					msg: msgs::WarningMessage {
						channel_id,
						data: format!("Channel {} has no pending splice to RBF", channel_id),
					},
				}
			);
		},
		_ => panic!("Expected HandleError, got {:?}", msg_events[0]),
	}
}

#[test]
fn test_splice_rbf_active_negotiation() {
	// Test that tx_init_rbf is rejected when a funding negotiation is already in progress.
	// Start a splice but don't complete interactive TX construction, then send tx_init_rbf.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_id_0 = nodes[0].node.get_our_node_id();

	let initial_channel_value_sat = 100_000;
	let (_, _, channel_id, _) =
		create_announced_chan_between_nodes_with_value(&nodes, 0, 1, initial_channel_value_sat, 0);

	let added_value = Amount::from_sat(50_000);
	provide_utxo_reserves(&nodes, 2, added_value * 2);

	// Initiate a splice but only complete the handshake (STFU + splice_init/ack),
	// leaving interactive TX construction in progress.
	let _funding_contribution =
		do_initiate_splice_in(&nodes[0], &nodes[1], channel_id, added_value);
	let _new_funding_script = complete_splice_handshake(&nodes[0], &nodes[1]);

	// Now the acceptor (node 1) has a funding_negotiation in progress (ConstructingTransaction).
	// Sending tx_init_rbf should be rejected.
	let tx_init_rbf = msgs::TxInitRbf {
		channel_id,
		locktime: 0,
		feerate_sat_per_1000_weight: 500,
		funding_output_contribution: Some(added_value.to_sat() as i64),
	};

	nodes[1].node.handle_tx_init_rbf(node_id_0, &tx_init_rbf);

	let msg_events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(msg_events.len(), 1);
	match &msg_events[0] {
		MessageSendEvent::HandleError { action, .. } => {
			assert_eq!(
				*action,
				msgs::ErrorAction::DisconnectPeerWithWarning {
					msg: msgs::WarningMessage {
						channel_id,
						data: format!(
							"Channel {} already has a funding negotiation in progress",
							channel_id,
						),
					},
				}
			);
		},
		_ => panic!("Expected HandleError, got {:?}", msg_events[0]),
	}

	// Clear the initiator's pending interactive TX messages from the incomplete splice handshake.
	nodes[0].node.get_and_clear_pending_msg_events();
}

#[test]
fn test_splice_rbf_not_quiescence_initiator() {
	// Test that tx_init_rbf is rejected when the sender is not the quiescence initiator.
	// Node 1 initiates quiescence, so only node 1 should be allowed to send tx_init_rbf.
	// Node 0 sending tx_init_rbf should be rejected.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_id_0 = nodes[0].node.get_our_node_id();
	let node_id_1 = nodes[1].node.get_our_node_id();

	let initial_channel_value_sat = 100_000;
	let (_, _, channel_id, _) =
		create_announced_chan_between_nodes_with_value(&nodes, 0, 1, initial_channel_value_sat, 0);

	let added_value = Amount::from_sat(50_000);
	provide_utxo_reserves(&nodes, 2, added_value * 2);

	// Complete a splice-in from node 0.
	let funding_contribution = do_initiate_splice_in(&nodes[0], &nodes[1], channel_id, added_value);
	let (_splice_tx, _new_funding_script) =
		splice_channel(&nodes[0], &nodes[1], channel_id, funding_contribution);

	// Re-enter quiescence with node 1 as the initiator (not node 0).
	nodes[1].node.maybe_propose_quiescence(&node_id_0, &channel_id).unwrap();
	let stfu_b = get_event_msg!(nodes[1], MessageSendEvent::SendStfu, node_id_0);
	nodes[0].node.handle_stfu(node_id_1, &stfu_b);
	let stfu_a = get_event_msg!(nodes[0], MessageSendEvent::SendStfu, node_id_1);
	nodes[1].node.handle_stfu(node_id_0, &stfu_a);

	// Node 0 sends tx_init_rbf, but node 1 is the quiescence initiator, so node 0 should be
	// rejected.
	let tx_init_rbf = msgs::TxInitRbf {
		channel_id,
		locktime: 0,
		feerate_sat_per_1000_weight: 500,
		funding_output_contribution: Some(added_value.to_sat() as i64),
	};

	nodes[1].node.handle_tx_init_rbf(node_id_0, &tx_init_rbf);

	let msg_events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(msg_events.len(), 1);
	match &msg_events[0] {
		MessageSendEvent::HandleError { action, .. } => {
			assert_eq!(
				*action,
				msgs::ErrorAction::DisconnectPeerWithWarning {
					msg: msgs::WarningMessage {
						channel_id,
						data: "Counterparty sent tx_init_rbf but is not the quiescence initiator"
							.to_owned(),
					},
				}
			);
		},
		_ => panic!("Expected HandleError, got {:?}", msg_events[0]),
	}
}

#[test]
fn test_splice_rbf_after_splice_locked() {
	// Test that tx_init_rbf is rejected when the counterparty has already sent splice_locked.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_id_0 = nodes[0].node.get_our_node_id();
	let node_id_1 = nodes[1].node.get_our_node_id();

	let initial_channel_value_sat = 100_000;
	let (_, _, channel_id, _) =
		create_announced_chan_between_nodes_with_value(&nodes, 0, 1, initial_channel_value_sat, 0);

	let added_value = Amount::from_sat(50_000);
	provide_utxo_reserves(&nodes, 2, added_value * 2);

	// Complete a splice-in from node 0.
	let funding_contribution = do_initiate_splice_in(&nodes[0], &nodes[1], channel_id, added_value);
	let (splice_tx, _new_funding_script) =
		splice_channel(&nodes[0], &nodes[1], channel_id, funding_contribution);

	// Mine the splice tx on both nodes.
	mine_transaction(&nodes[0], &splice_tx);
	mine_transaction(&nodes[1], &splice_tx);

	// Connect enough blocks on node 0 only so it sends splice_locked.
	connect_blocks(&nodes[0], ANTI_REORG_DELAY - 1);

	let splice_locked = get_event_msg!(nodes[0], MessageSendEvent::SendSpliceLocked, node_id_1);

	// Deliver splice_locked to node 1. Since node 1 hasn't confirmed enough blocks,
	// it won't send its own splice_locked back, but it will set received_funding_txid.
	nodes[1].node.handle_splice_locked(node_id_0, &splice_locked);

	// Node 1 shouldn't have any messages to send (no splice_locked since it hasn't confirmed).
	let msg_events = nodes[1].node.get_and_clear_pending_msg_events();
	assert!(msg_events.is_empty(), "Expected no messages, got {:?}", msg_events);

	// Re-enter quiescence (node 0 initiates).
	reenter_quiescence(&nodes[0], &nodes[1], &channel_id);

	// Node 0 sends tx_init_rbf, but node 0 already sent splice_locked, so it should be rejected.
	let tx_init_rbf = msgs::TxInitRbf {
		channel_id,
		locktime: 0,
		feerate_sat_per_1000_weight: 500,
		funding_output_contribution: Some(added_value.to_sat() as i64),
	};

	nodes[1].node.handle_tx_init_rbf(node_id_0, &tx_init_rbf);

	let msg_events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(msg_events.len(), 1);
	match &msg_events[0] {
		MessageSendEvent::HandleError { action, .. } => {
			assert_eq!(
				*action,
				msgs::ErrorAction::DisconnectPeerWithWarning {
					msg: msgs::WarningMessage {
						channel_id,
						data: format!(
							"Channel {} counterparty already sent splice_locked, cannot RBF",
							channel_id,
						),
					},
				}
			);
		},
		_ => panic!("Expected HandleError, got {:?}", msg_events[0]),
	}
}

#[test]
fn test_splice_rbf_zeroconf_rejected() {
	// Test that tx_init_rbf is rejected when option_zeroconf is negotiated.
	// The zero-conf check happens before the pending_splice check, so we don't need to complete
	// a splice — just enter quiescence and send tx_init_rbf.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let mut config = test_default_channel_config();
	config.channel_handshake_limits.trust_own_funding_0conf = true;
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[Some(config.clone()), Some(config)]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_id_0 = nodes[0].node.get_our_node_id();

	let initial_channel_value_sat = 100_000;
	let (funding_tx, channel_id) =
		open_zero_conf_channel_with_value(&nodes[0], &nodes[1], None, initial_channel_value_sat, 0);
	mine_transaction(&nodes[0], &funding_tx);
	mine_transaction(&nodes[1], &funding_tx);

	// Enter quiescence (node 0 initiates).
	reenter_quiescence(&nodes[0], &nodes[1], &channel_id);

	// Node 0 sends tx_init_rbf, but the channel has option_zeroconf, so it should be rejected.
	let tx_init_rbf = msgs::TxInitRbf {
		channel_id,
		locktime: 0,
		feerate_sat_per_1000_weight: 500,
		funding_output_contribution: Some(50_000),
	};

	nodes[1].node.handle_tx_init_rbf(node_id_0, &tx_init_rbf);

	let msg_events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(msg_events.len(), 1);
	match &msg_events[0] {
		MessageSendEvent::HandleError { action, .. } => {
			assert_eq!(
				*action,
				msgs::ErrorAction::DisconnectPeerWithWarning {
					msg: msgs::WarningMessage {
						channel_id,
						data: format!(
							"Channel {} has option_zeroconf, cannot RBF splice",
							channel_id,
						),
					},
				}
			);
		},
		_ => panic!("Expected HandleError, got {:?}", msg_events[0]),
	}
}

#[test]
fn test_splice_rbf_both_contribute_tiebreak() {
	do_test_splice_rbf_both_contribute_tiebreak(None, None);
}

#[test]
fn test_splice_rbf_tiebreak_higher_feerate() {
	// Node 0 (winner) uses a higher feerate than node 1 (loser). Node 1's change output is
	// adjusted (reduced) to accommodate the higher feerate. Negotiation succeeds.
	let min_rbf_feerate = (FEERATE_FLOOR_SATS_PER_KW as u64 * 25 + 23) / 24;
	do_test_splice_rbf_both_contribute_tiebreak(
		Some(FeeRate::from_sat_per_kwu(min_rbf_feerate * 3)),
		Some(FeeRate::from_sat_per_kwu(min_rbf_feerate)),
	);
}

#[test]
fn test_splice_rbf_tiebreak_lower_feerate() {
	// Node 0 (winner) uses a lower feerate than node 1 (loser). Node 1's change output increases
	// because the acceptor's fair fee decreases. Negotiation succeeds.
	let min_rbf_feerate = (FEERATE_FLOOR_SATS_PER_KW as u64 * 25 + 23) / 24;
	do_test_splice_rbf_both_contribute_tiebreak(
		Some(FeeRate::from_sat_per_kwu(min_rbf_feerate)),
		Some(FeeRate::from_sat_per_kwu(min_rbf_feerate * 3)),
	);
}

/// Runs the tie-breaker test with optional per-node feerates.
/// If `node_0_feerate` or `node_1_feerate` is None, both use the same default RBF feerate.
fn do_test_splice_rbf_both_contribute_tiebreak(
	node_0_feerate: Option<FeeRate>, node_1_feerate: Option<FeeRate>,
) {
	// Test where both parties call rbf_channel + funding_contributed, both send STFU, one wins
	// the quiescence tie-break (node 0, the outbound channel funder). The loser (node 1) becomes
	// the acceptor and its stored QuiescentAction::Splice is consumed by the tx_init_rbf handler,
	// contributing its inputs/outputs to the RBF transaction.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_id_0 = nodes[0].node.get_our_node_id();
	let node_id_1 = nodes[1].node.get_our_node_id();

	let initial_channel_value_sat = 100_000;
	let (_, _, channel_id, _) =
		create_announced_chan_between_nodes_with_value(&nodes, 0, 1, initial_channel_value_sat, 0);

	let added_value = Amount::from_sat(50_000);
	provide_utxo_reserves(&nodes, 2, added_value * 2);

	// Step 1: Complete an initial splice-in from node 0.
	let funding_contribution = do_initiate_splice_in(&nodes[0], &nodes[1], channel_id, added_value);
	let original_funding_outpoint = nodes[0]
		.chain_monitor
		.chain_monitor
		.get_monitor(channel_id)
		.map(|monitor| (monitor.get_funding_txo(), monitor.get_funding_script()))
		.unwrap();
	let (first_splice_tx, new_funding_script) =
		splice_channel(&nodes[0], &nodes[1], channel_id, funding_contribution);

	// Step 2: Provide more UTXOs for both nodes' RBF attempts.
	provide_utxo_reserves(&nodes, 2, added_value * 2);

	// Step 3: Both nodes initiate RBF, possibly at different feerates.
	let default_rbf_feerate_sat_per_kwu = (FEERATE_FLOOR_SATS_PER_KW as u64 * 25 + 23) / 24;
	let default_rbf_feerate = FeeRate::from_sat_per_kwu(default_rbf_feerate_sat_per_kwu);
	let rbf_feerate_0 = node_0_feerate.unwrap_or(default_rbf_feerate);
	let rbf_feerate_1 = node_1_feerate.unwrap_or(default_rbf_feerate);

	// Node 0 calls rbf_channel + funding_contributed.
	let funding_template_0 =
		nodes[0].node.rbf_channel(&channel_id, &node_id_1, rbf_feerate_0).unwrap();
	let wallet_0 = WalletSync::new(Arc::clone(&nodes[0].wallet_source), nodes[0].logger);
	let node_0_funding_contribution =
		funding_template_0.splice_in_sync(added_value, &wallet_0).unwrap();
	nodes[0]
		.node
		.funding_contributed(&channel_id, &node_id_1, node_0_funding_contribution.clone(), None)
		.unwrap();

	// Node 1 calls rbf_channel + funding_contributed.
	let funding_template_1 =
		nodes[1].node.rbf_channel(&channel_id, &node_id_0, rbf_feerate_1).unwrap();
	let wallet_1 = WalletSync::new(Arc::clone(&nodes[1].wallet_source), nodes[1].logger);
	let node_1_funding_contribution =
		funding_template_1.splice_in_sync(added_value, &wallet_1).unwrap();
	nodes[1]
		.node
		.funding_contributed(&channel_id, &node_id_0, node_1_funding_contribution.clone(), None)
		.unwrap();

	// Capture change output values before the tiebreak.
	let node_0_change = node_0_funding_contribution
		.change_output()
		.expect("splice-in should have a change output")
		.clone();
	let node_1_change = node_1_funding_contribution
		.change_output()
		.expect("splice-in should have a change output")
		.clone();

	// Step 4: Both nodes sent STFU (both have awaiting_quiescence set).
	let stfu_0 = get_event_msg!(nodes[0], MessageSendEvent::SendStfu, node_id_1);
	assert!(stfu_0.initiator);
	let stfu_1 = get_event_msg!(nodes[1], MessageSendEvent::SendStfu, node_id_0);
	assert!(stfu_1.initiator);

	// Step 5: Exchange STFUs. Node 0 is the outbound channel funder and wins the tie-break.
	// Node 1 handles node 0's STFU first — it already sent its own STFU (local_stfu_sent is set),
	// so this goes through the tie-break path. Node 1 loses (is_outbound = false) and becomes the
	// acceptor. Its quiescent_action is preserved for the tx_init_rbf handler.
	nodes[1].node.handle_stfu(node_id_0, &stfu_0);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	// Node 0 handles node 1's STFU — it already sent its own STFU, so tie-break again.
	// Node 0 wins (is_outbound = true), consumes its quiescent_action, and sends tx_init_rbf.
	nodes[0].node.handle_stfu(node_id_1, &stfu_1);

	// Step 6: Node 0 sends tx_init_rbf.
	let tx_init_rbf = get_event_msg!(nodes[0], MessageSendEvent::SendTxInitRbf, node_id_1);
	assert_eq!(tx_init_rbf.channel_id, channel_id);
	assert_eq!(tx_init_rbf.feerate_sat_per_1000_weight, rbf_feerate_0.to_sat_per_kwu() as u32);

	// Step 7: Node 1 handles tx_init_rbf — its quiescent_action is consumed, providing its
	// inputs/outputs (adjusted for node 0's feerate). Responds with tx_ack_rbf.
	nodes[1].node.handle_tx_init_rbf(node_id_0, &tx_init_rbf);
	let tx_ack_rbf = get_event_msg!(nodes[1], MessageSendEvent::SendTxAckRbf, node_id_0);
	assert_eq!(tx_ack_rbf.channel_id, channel_id);
	assert!(
		tx_ack_rbf.funding_output_contribution.is_some(),
		"Acceptor should contribute to the RBF splice"
	);

	// Step 8: Node 0 handles tx_ack_rbf.
	nodes[0].node.handle_tx_ack_rbf(node_id_1, &tx_ack_rbf);

	// Step 9: Complete interactive funding negotiation with both parties' inputs/outputs.
	complete_interactive_funding_negotiation_for_both(
		&nodes[0],
		&nodes[1],
		channel_id,
		node_0_funding_contribution,
		Some(node_1_funding_contribution),
		new_funding_script.clone(),
	);

	// Step 10: Sign (acceptor has contribution) and broadcast.
	let (rbf_tx, splice_locked) =
		sign_interactive_funding_tx_with_acceptor_contribution(&nodes[0], &nodes[1], false, true);
	assert!(splice_locked.is_none());

	// The initiator's change output should remain unchanged (no feerate adjustment).
	let initiator_change_in_tx = rbf_tx
		.output
		.iter()
		.find(|o| o.script_pubkey == node_0_change.script_pubkey)
		.expect("Initiator's change output should be in the RBF transaction");
	assert_eq!(
		initiator_change_in_tx.value, node_0_change.value,
		"Initiator's change output should remain unchanged",
	);

	// The acceptor's change output should be adjusted based on the feerate difference.
	let acceptor_change_in_tx = rbf_tx
		.output
		.iter()
		.find(|o| o.script_pubkey == node_1_change.script_pubkey)
		.expect("Acceptor's change output should be in the RBF transaction");
	if rbf_feerate_0 <= rbf_feerate_1 {
		// Initiator's feerate <= acceptor's original: the acceptor's change increases because
		// is_initiator=false has lower weight, and the feerate is the same or lower.
		assert!(
			acceptor_change_in_tx.value > node_1_change.value,
			"Acceptor's change should increase when initiator feerate ({}) <= acceptor feerate \
			 ({}): adjusted {} vs original {}",
			rbf_feerate_0.to_sat_per_kwu(),
			rbf_feerate_1.to_sat_per_kwu(),
			acceptor_change_in_tx.value,
			node_1_change.value,
		);
	} else {
		// Initiator's feerate > acceptor's original: the higher feerate more than compensates
		// for the lower weight, so the acceptor's change decreases.
		assert!(
			acceptor_change_in_tx.value < node_1_change.value,
			"Acceptor's change should decrease when initiator feerate ({}) > acceptor feerate \
			 ({}): adjusted {} vs original {}",
			rbf_feerate_0.to_sat_per_kwu(),
			rbf_feerate_1.to_sat_per_kwu(),
			acceptor_change_in_tx.value,
			node_1_change.value,
		);
	}

	expect_splice_pending_event(&nodes[0], &node_id_1);
	expect_splice_pending_event(&nodes[1], &node_id_0);

	// Step 11: Mine and lock.
	mine_transaction(&nodes[0], &rbf_tx);
	mine_transaction(&nodes[1], &rbf_tx);

	connect_blocks(&nodes[0], ANTI_REORG_DELAY - 1);
	connect_blocks(&nodes[1], ANTI_REORG_DELAY - 1);

	let splice_locked_b = get_event_msg!(nodes[0], MessageSendEvent::SendSpliceLocked, node_id_1);
	nodes[1].node.handle_splice_locked(node_id_0, &splice_locked_b);

	let mut msg_events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(msg_events.len(), 2, "{msg_events:?}");
	let splice_locked_a =
		if let MessageSendEvent::SendSpliceLocked { msg, .. } = msg_events.remove(0) {
			msg
		} else {
			panic!("Expected SendSpliceLocked, got {:?}", msg_events[0]);
		};
	let announcement_sigs_b =
		if let MessageSendEvent::SendAnnouncementSignatures { msg, .. } = msg_events.remove(0) {
			msg
		} else {
			panic!("Expected SendAnnouncementSignatures");
		};
	nodes[0].node.handle_splice_locked(node_id_1, &splice_locked_a);
	nodes[0].node.handle_announcement_signatures(node_id_1, &announcement_sigs_b);

	// Expect ChannelReady + DiscardFunding for the old splice candidate on both nodes.
	let events_a = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events_a.len(), 2, "{events_a:?}");
	assert!(matches!(events_a[0], Event::ChannelReady { .. }));
	assert!(matches!(events_a[1], Event::DiscardFunding { .. }));
	check_added_monitors(&nodes[0], 1);

	let events_b = nodes[1].node.get_and_clear_pending_events();
	assert_eq!(events_b.len(), 2, "{events_b:?}");
	assert!(matches!(events_b[0], Event::ChannelReady { .. }));
	assert!(matches!(events_b[1], Event::DiscardFunding { .. }));
	check_added_monitors(&nodes[1], 1);

	// Complete the announcement exchange.
	let mut msg_events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(msg_events.len(), 2, "{msg_events:?}");
	if let MessageSendEvent::SendAnnouncementSignatures { msg, .. } = msg_events.remove(0) {
		nodes[1].node.handle_announcement_signatures(node_id_0, &msg);
	} else {
		panic!("Expected SendAnnouncementSignatures");
	}
	assert!(matches!(msg_events.remove(0), MessageSendEvent::BroadcastChannelAnnouncement { .. }));

	let mut msg_events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(msg_events.len(), 1, "{msg_events:?}");
	assert!(matches!(msg_events.remove(0), MessageSendEvent::BroadcastChannelAnnouncement { .. }));

	// Clean up old watched outpoints from the chain source.
	let (orig_outpoint, orig_script) = original_funding_outpoint;
	let first_splice_funding_idx =
		first_splice_tx.output.iter().position(|o| o.script_pubkey == new_funding_script).unwrap();
	let first_splice_outpoint =
		OutPoint { txid: first_splice_tx.compute_txid(), index: first_splice_funding_idx as u16 };
	for node in &nodes {
		node.chain_source.remove_watched_txn_and_outputs(orig_outpoint, orig_script.clone());
		node.chain_source
			.remove_watched_txn_and_outputs(first_splice_outpoint, new_funding_script.clone());
	}
}

#[test]
fn test_splice_rbf_tiebreak_feerate_too_high() {
	// Node 0 (winner) uses a feerate high enough that node 1's (loser) contribution cannot
	// cover the fees. Node 1 proceeds without its contribution (QuiescentAction is preserved
	// for a future splice). The RBF completes with only node 0's inputs/outputs.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_id_0 = nodes[0].node.get_our_node_id();
	let node_id_1 = nodes[1].node.get_our_node_id();

	let initial_channel_value_sat = 100_000;
	let (_, _, channel_id, _) =
		create_announced_chan_between_nodes_with_value(&nodes, 0, 1, initial_channel_value_sat, 0);

	let added_value = Amount::from_sat(50_000);
	provide_utxo_reserves(&nodes, 2, added_value * 2);

	// Complete an initial splice-in from node 0.
	let funding_contribution = do_initiate_splice_in(&nodes[0], &nodes[1], channel_id, added_value);
	let original_funding_outpoint = nodes[0]
		.chain_monitor
		.chain_monitor
		.get_monitor(channel_id)
		.map(|monitor| (monitor.get_funding_txo(), monitor.get_funding_script()))
		.unwrap();
	let (first_splice_tx, new_funding_script) =
		splice_channel(&nodes[0], &nodes[1], channel_id, funding_contribution);

	// Provide more UTXOs for both nodes' RBF attempts.
	provide_utxo_reserves(&nodes, 2, added_value * 2);

	// Node 0 uses a high feerate (20,000 sat/kwu). Node 1 uses the minimum RBF feerate but
	// splices in a large amount (95,000 sats from a 100,000 sat UTXO), leaving very little
	// change/fee budget. Node 1's budget (~5,000 sats) can't cover the acceptor's fair fee
	// at 20,000 sat/kwu (~5,440 sats without change output), so adjust_for_feerate fails.
	let high_feerate = FeeRate::from_sat_per_kwu(20_000);
	let min_rbf_feerate_sat_per_kwu = (FEERATE_FLOOR_SATS_PER_KW as u64 * 25 + 23) / 24;
	let min_rbf_feerate = FeeRate::from_sat_per_kwu(min_rbf_feerate_sat_per_kwu);

	let node_1_added_value = Amount::from_sat(95_000);

	let funding_template_0 =
		nodes[0].node.rbf_channel(&channel_id, &node_id_1, high_feerate).unwrap();
	let wallet_0 = WalletSync::new(Arc::clone(&nodes[0].wallet_source), nodes[0].logger);
	let node_0_funding_contribution =
		funding_template_0.splice_in_sync(added_value, &wallet_0).unwrap();
	nodes[0]
		.node
		.funding_contributed(&channel_id, &node_id_1, node_0_funding_contribution.clone(), None)
		.unwrap();

	let funding_template_1 =
		nodes[1].node.rbf_channel(&channel_id, &node_id_0, min_rbf_feerate).unwrap();
	let wallet_1 = WalletSync::new(Arc::clone(&nodes[1].wallet_source), nodes[1].logger);
	let node_1_funding_contribution =
		funding_template_1.splice_in_sync(node_1_added_value, &wallet_1).unwrap();
	nodes[1]
		.node
		.funding_contributed(&channel_id, &node_id_0, node_1_funding_contribution.clone(), None)
		.unwrap();

	// Both sent STFU.
	let stfu_0 = get_event_msg!(nodes[0], MessageSendEvent::SendStfu, node_id_1);
	let stfu_1 = get_event_msg!(nodes[1], MessageSendEvent::SendStfu, node_id_0);

	// Tie-break: node 0 wins.
	nodes[1].node.handle_stfu(node_id_0, &stfu_0);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	nodes[0].node.handle_stfu(node_id_1, &stfu_1);

	// Node 0 sends tx_init_rbf at 20,000 sat/kwu.
	let tx_init_rbf = get_event_msg!(nodes[0], MessageSendEvent::SendTxInitRbf, node_id_1);
	assert_eq!(tx_init_rbf.feerate_sat_per_1000_weight, high_feerate.to_sat_per_kwu() as u32);

	// Node 1 handles tx_init_rbf — adjust_for_feerate fails because node 1's contribution
	// can't cover fees at 20,000 sat/kwu. Node 1 proceeds without its contribution.
	nodes[1].node.handle_tx_init_rbf(node_id_0, &tx_init_rbf);
	let tx_ack_rbf = get_event_msg!(nodes[1], MessageSendEvent::SendTxAckRbf, node_id_0);
	assert_eq!(tx_ack_rbf.channel_id, channel_id);
	assert!(
		tx_ack_rbf.funding_output_contribution.is_none(),
		"Acceptor should not contribute when feerate adjustment fails"
	);

	// Node 0 handles tx_ack_rbf.
	nodes[0].node.handle_tx_ack_rbf(node_id_1, &tx_ack_rbf);

	// Complete interactive funding negotiation with only node 0's contribution.
	complete_interactive_funding_negotiation_for_both(
		&nodes[0],
		&nodes[1],
		channel_id,
		node_0_funding_contribution,
		None,
		new_funding_script.clone(),
	);

	// Sign (acceptor has no contribution) and broadcast.
	let (rbf_tx, splice_locked) =
		sign_interactive_funding_tx_with_acceptor_contribution(&nodes[0], &nodes[1], false, false);
	assert!(splice_locked.is_none());

	expect_splice_pending_event(&nodes[0], &node_id_1);
	expect_splice_pending_event(&nodes[1], &node_id_0);

	// Mine and lock.
	mine_transaction(&nodes[0], &rbf_tx);
	mine_transaction(&nodes[1], &rbf_tx);

	connect_blocks(&nodes[0], ANTI_REORG_DELAY - 1);
	connect_blocks(&nodes[1], ANTI_REORG_DELAY - 1);

	let splice_locked_b = get_event_msg!(nodes[0], MessageSendEvent::SendSpliceLocked, node_id_1);
	nodes[1].node.handle_splice_locked(node_id_0, &splice_locked_b);

	// Node 1's QuiescentAction was preserved, so after splice_locked it re-initiates
	// quiescence to retry its contribution in a future splice.
	let mut msg_events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(msg_events.len(), 3, "{msg_events:?}");
	let splice_locked_a =
		if let MessageSendEvent::SendSpliceLocked { msg, .. } = msg_events.remove(0) {
			msg
		} else {
			panic!("Expected SendSpliceLocked, got {:?}", msg_events[0]);
		};
	let announcement_sigs_b =
		if let MessageSendEvent::SendAnnouncementSignatures { msg, .. } = msg_events.remove(0) {
			msg
		} else {
			panic!("Expected SendAnnouncementSignatures");
		};
	let stfu_1 = if let MessageSendEvent::SendStfu { msg, .. } = msg_events.remove(0) {
		msg
	} else {
		panic!("Expected SendStfu, got {:?}", msg_events[0]);
	};
	assert!(stfu_1.initiator);

	nodes[0].node.handle_splice_locked(node_id_1, &splice_locked_a);
	nodes[0].node.handle_announcement_signatures(node_id_1, &announcement_sigs_b);

	// Expect ChannelReady + DiscardFunding for the old splice candidate on both nodes.
	let events_a = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events_a.len(), 2, "{events_a:?}");
	assert!(matches!(events_a[0], Event::ChannelReady { .. }));
	assert!(matches!(events_a[1], Event::DiscardFunding { .. }));
	check_added_monitors(&nodes[0], 1);

	let events_b = nodes[1].node.get_and_clear_pending_events();
	assert_eq!(events_b.len(), 2, "{events_b:?}");
	assert!(matches!(events_b[0], Event::ChannelReady { .. }));
	assert!(matches!(events_b[1], Event::DiscardFunding { .. }));
	check_added_monitors(&nodes[1], 1);

	// Complete the announcement exchange.
	let mut msg_events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(msg_events.len(), 2, "{msg_events:?}");
	if let MessageSendEvent::SendAnnouncementSignatures { msg, .. } = msg_events.remove(0) {
		nodes[1].node.handle_announcement_signatures(node_id_0, &msg);
	} else {
		panic!("Expected SendAnnouncementSignatures");
	}
	assert!(matches!(msg_events.remove(0), MessageSendEvent::BroadcastChannelAnnouncement { .. }));

	let mut msg_events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(msg_events.len(), 1, "{msg_events:?}");
	assert!(matches!(msg_events.remove(0), MessageSendEvent::BroadcastChannelAnnouncement { .. }));

	// Clean up old watched outpoints.
	let (orig_outpoint, orig_script) = original_funding_outpoint;
	let first_splice_funding_idx =
		first_splice_tx.output.iter().position(|o| o.script_pubkey == new_funding_script).unwrap();
	let first_splice_outpoint =
		OutPoint { txid: first_splice_tx.compute_txid(), index: first_splice_funding_idx as u16 };
	for node in &nodes {
		node.chain_source.remove_watched_txn_and_outputs(orig_outpoint, orig_script.clone());
		node.chain_source
			.remove_watched_txn_and_outputs(first_splice_outpoint, new_funding_script.clone());
	}

	// === Part 2: Node 1's preserved QuiescentAction leads to a new splice ===
	//
	// After splice_locked, pending_splice is None. So when stfu() consumes the QuiescentAction,
	// it sends SpliceInit (not TxInitRbf), starting a brand new splice.

	// Node 0 receives node 1's STFU and responds with its own STFU.
	nodes[0].node.handle_stfu(node_id_1, &stfu_1);
	let stfu_0 = get_event_msg!(nodes[0], MessageSendEvent::SendStfu, node_id_1);

	// Node 1 receives STFU → quiescence established → node 1 is the initiator → sends SpliceInit.
	nodes[1].node.handle_stfu(node_id_0, &stfu_0);
	let splice_init = get_event_msg!(nodes[1], MessageSendEvent::SendSpliceInit, node_id_0);

	// Node 0 handles SpliceInit → sends SpliceAck.
	nodes[0].node.handle_splice_init(node_id_1, &splice_init);
	let splice_ack = get_event_msg!(nodes[0], MessageSendEvent::SendSpliceAck, node_id_1);

	// Node 1 handles SpliceAck → starts interactive tx construction.
	nodes[1].node.handle_splice_ack(node_id_0, &splice_ack);

	// Compute the new funding script from the splice pubkeys.
	let new_funding_script_2 = chan_utils::make_funding_redeemscript(
		&splice_init.funding_pubkey,
		&splice_ack.funding_pubkey,
	)
	.to_p2wsh();

	// Complete interactive funding negotiation with node 1 as initiator (only node 1 contributes).
	complete_interactive_funding_negotiation(
		&nodes[1],
		&nodes[0],
		channel_id,
		node_1_funding_contribution,
		new_funding_script_2,
	);

	// Sign (no acceptor contribution) and broadcast.
	let (new_splice_tx, splice_locked) = sign_interactive_funding_tx(&nodes[1], &nodes[0], false);
	assert!(splice_locked.is_none());

	expect_splice_pending_event(&nodes[1], &node_id_0);
	expect_splice_pending_event(&nodes[0], &node_id_1);

	// Mine and lock.
	mine_transaction(&nodes[1], &new_splice_tx);
	mine_transaction(&nodes[0], &new_splice_tx);

	lock_splice_after_blocks(&nodes[1], &nodes[0], ANTI_REORG_DELAY - 1);
}

#[test]
fn test_splice_rbf_acceptor_recontributes() {
	// When the counterparty RBFs a splice and we have no pending QuiescentAction,
	// our prior contribution should be automatically re-used. This tests the scenario:
	// 1. Both nodes contribute to a splice (tiebreak: node 0 wins).
	// 2. Only node 0 initiates an RBF — node 1 has no QuiescentAction.
	// 3. Node 1 should re-contribute its prior inputs/outputs via our_prior_contribution.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_id_0 = nodes[0].node.get_our_node_id();
	let node_id_1 = nodes[1].node.get_our_node_id();

	let initial_channel_value_sat = 100_000;
	let (_, _, channel_id, _) =
		create_announced_chan_between_nodes_with_value(&nodes, 0, 1, initial_channel_value_sat, 0);

	let added_value = Amount::from_sat(50_000);
	provide_utxo_reserves(&nodes, 2, Amount::from_sat(100_000));

	// Step 1: Both nodes initiate a splice at floor feerate.
	let feerate = FeeRate::from_sat_per_kwu(FEERATE_FLOOR_SATS_PER_KW as u64);

	let funding_template_0 =
		nodes[0].node.splice_channel(&channel_id, &node_id_1, feerate).unwrap();
	let wallet_0 = WalletSync::new(Arc::clone(&nodes[0].wallet_source), nodes[0].logger);
	let node_0_funding_contribution =
		funding_template_0.splice_in_sync(added_value, &wallet_0).unwrap();
	nodes[0]
		.node
		.funding_contributed(&channel_id, &node_id_1, node_0_funding_contribution.clone(), None)
		.unwrap();

	let funding_template_1 =
		nodes[1].node.splice_channel(&channel_id, &node_id_0, feerate).unwrap();
	let wallet_1 = WalletSync::new(Arc::clone(&nodes[1].wallet_source), nodes[1].logger);
	let node_1_funding_contribution =
		funding_template_1.splice_in_sync(added_value, &wallet_1).unwrap();
	nodes[1]
		.node
		.funding_contributed(&channel_id, &node_id_0, node_1_funding_contribution.clone(), None)
		.unwrap();

	// Step 2: Both send STFU; tiebreak: node 0 wins.
	let stfu_0 = get_event_msg!(nodes[0], MessageSendEvent::SendStfu, node_id_1);
	let stfu_1 = get_event_msg!(nodes[1], MessageSendEvent::SendStfu, node_id_0);

	nodes[1].node.handle_stfu(node_id_0, &stfu_0);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	nodes[0].node.handle_stfu(node_id_1, &stfu_1);

	// Step 3: Node 0 sends SpliceInit, node 1 handles as acceptor (QuiescentAction consumed).
	let splice_init = get_event_msg!(nodes[0], MessageSendEvent::SendSpliceInit, node_id_1);
	nodes[1].node.handle_splice_init(node_id_0, &splice_init);
	let splice_ack = get_event_msg!(nodes[1], MessageSendEvent::SendSpliceAck, node_id_0);
	assert_ne!(splice_ack.funding_contribution_satoshis, 0);
	nodes[0].node.handle_splice_ack(node_id_1, &splice_ack);

	let new_funding_script = chan_utils::make_funding_redeemscript(
		&splice_init.funding_pubkey,
		&splice_ack.funding_pubkey,
	)
	.to_p2wsh();

	// Complete interactive funding with both contributions.
	complete_interactive_funding_negotiation_for_both(
		&nodes[0],
		&nodes[1],
		channel_id,
		node_0_funding_contribution,
		Some(node_1_funding_contribution.clone()),
		new_funding_script.clone(),
	);

	let (first_splice_tx, splice_locked) =
		sign_interactive_funding_tx_with_acceptor_contribution(&nodes[0], &nodes[1], false, true);
	assert!(splice_locked.is_none());

	let original_funding_outpoint = nodes[0]
		.chain_monitor
		.chain_monitor
		.get_monitor(channel_id)
		.map(|monitor| (monitor.get_funding_txo(), monitor.get_funding_script()))
		.unwrap();

	expect_splice_pending_event(&nodes[0], &node_id_1);
	expect_splice_pending_event(&nodes[1], &node_id_0);

	// Step 4: Provide new UTXOs for node 0's RBF (node 1 does NOT initiate RBF).
	provide_utxo_reserves(&nodes, 2, added_value * 2);

	// Step 5: Only node 0 calls rbf_channel + funding_contributed.
	let rbf_feerate_sat_per_kwu = (FEERATE_FLOOR_SATS_PER_KW as u64 * 25 + 23) / 24;
	let rbf_feerate = FeeRate::from_sat_per_kwu(rbf_feerate_sat_per_kwu);
	let funding_template = nodes[0].node.rbf_channel(&channel_id, &node_id_1, rbf_feerate).unwrap();
	let wallet = WalletSync::new(Arc::clone(&nodes[0].wallet_source), nodes[0].logger);
	let rbf_funding_contribution = funding_template.splice_in_sync(added_value, &wallet).unwrap();
	nodes[0]
		.node
		.funding_contributed(&channel_id, &node_id_1, rbf_funding_contribution.clone(), None)
		.unwrap();

	// Step 6: STFU exchange — node 0 initiates, node 1 responds (no QuiescentAction).
	let stfu_a = get_event_msg!(nodes[0], MessageSendEvent::SendStfu, node_id_1);
	nodes[1].node.handle_stfu(node_id_0, &stfu_a);
	let stfu_b = get_event_msg!(nodes[1], MessageSendEvent::SendStfu, node_id_0);
	nodes[0].node.handle_stfu(node_id_1, &stfu_b);

	// Step 7: Node 0 sends tx_init_rbf.
	let tx_init_rbf = get_event_msg!(nodes[0], MessageSendEvent::SendTxInitRbf, node_id_1);
	assert_eq!(tx_init_rbf.channel_id, channel_id);
	assert_eq!(tx_init_rbf.feerate_sat_per_1000_weight, rbf_feerate_sat_per_kwu as u32);

	// Step 8: Node 1 handles tx_init_rbf — should use our_prior_contribution.
	nodes[1].node.handle_tx_init_rbf(node_id_0, &tx_init_rbf);
	let tx_ack_rbf = get_event_msg!(nodes[1], MessageSendEvent::SendTxAckRbf, node_id_0);
	assert_eq!(tx_ack_rbf.channel_id, channel_id);
	assert!(
		tx_ack_rbf.funding_output_contribution.is_some(),
		"Acceptor should re-contribute via our_prior_contribution"
	);

	// Step 9: Node 0 handles tx_ack_rbf.
	nodes[0].node.handle_tx_ack_rbf(node_id_1, &tx_ack_rbf);

	// Step 10: Complete interactive funding with both contributions.
	// Node 1's prior contribution is re-used — pass a clone for matching.
	complete_interactive_funding_negotiation_for_both(
		&nodes[0],
		&nodes[1],
		channel_id,
		rbf_funding_contribution,
		Some(node_1_funding_contribution),
		new_funding_script.clone(),
	);

	// Step 11: Sign (acceptor has contribution) and broadcast.
	let (rbf_tx, splice_locked) =
		sign_interactive_funding_tx_with_acceptor_contribution(&nodes[0], &nodes[1], false, true);
	assert!(splice_locked.is_none());

	expect_splice_pending_event(&nodes[0], &node_id_1);
	expect_splice_pending_event(&nodes[1], &node_id_0);

	// Step 12: Mine and lock.
	mine_transaction(&nodes[0], &rbf_tx);
	mine_transaction(&nodes[1], &rbf_tx);

	connect_blocks(&nodes[0], ANTI_REORG_DELAY - 1);
	connect_blocks(&nodes[1], ANTI_REORG_DELAY - 1);

	let splice_locked_b = get_event_msg!(nodes[0], MessageSendEvent::SendSpliceLocked, node_id_1);
	nodes[1].node.handle_splice_locked(node_id_0, &splice_locked_b);

	let mut msg_events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(msg_events.len(), 2, "{msg_events:?}");
	let splice_locked_a =
		if let MessageSendEvent::SendSpliceLocked { msg, .. } = msg_events.remove(0) {
			msg
		} else {
			panic!("Expected SendSpliceLocked, got {:?}", msg_events[0]);
		};
	let announcement_sigs_b =
		if let MessageSendEvent::SendAnnouncementSignatures { msg, .. } = msg_events.remove(0) {
			msg
		} else {
			panic!("Expected SendAnnouncementSignatures");
		};
	nodes[0].node.handle_splice_locked(node_id_1, &splice_locked_a);
	nodes[0].node.handle_announcement_signatures(node_id_1, &announcement_sigs_b);

	let events_a = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events_a.len(), 2, "{events_a:?}");
	assert!(matches!(events_a[0], Event::ChannelReady { .. }));
	assert!(matches!(events_a[1], Event::DiscardFunding { .. }));
	check_added_monitors(&nodes[0], 1);

	let events_b = nodes[1].node.get_and_clear_pending_events();
	assert_eq!(events_b.len(), 2, "{events_b:?}");
	assert!(matches!(events_b[0], Event::ChannelReady { .. }));
	assert!(matches!(events_b[1], Event::DiscardFunding { .. }));
	check_added_monitors(&nodes[1], 1);

	let mut msg_events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(msg_events.len(), 2, "{msg_events:?}");
	if let MessageSendEvent::SendAnnouncementSignatures { msg, .. } = msg_events.remove(0) {
		nodes[1].node.handle_announcement_signatures(node_id_0, &msg);
	} else {
		panic!("Expected SendAnnouncementSignatures");
	}
	assert!(matches!(msg_events.remove(0), MessageSendEvent::BroadcastChannelAnnouncement { .. }));

	let mut msg_events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(msg_events.len(), 1, "{msg_events:?}");
	assert!(matches!(msg_events.remove(0), MessageSendEvent::BroadcastChannelAnnouncement { .. }));

	// Clean up old watched outpoints.
	let (orig_outpoint, orig_script) = original_funding_outpoint;
	let first_splice_funding_idx =
		first_splice_tx.output.iter().position(|o| o.script_pubkey == new_funding_script).unwrap();
	let first_splice_outpoint =
		OutPoint { txid: first_splice_tx.compute_txid(), index: first_splice_funding_idx as u16 };
	for node in &nodes {
		node.chain_source.remove_watched_txn_and_outputs(orig_outpoint, orig_script.clone());
		node.chain_source
			.remove_watched_txn_and_outputs(first_splice_outpoint, new_funding_script.clone());
	}
}

#[test]
fn test_splice_rbf_recontributes_feerate_too_high() {
	// When the counterparty RBFs at a feerate too high for our prior contribution,
	// we should reject the RBF rather than proceeding without our contribution.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_id_0 = nodes[0].node.get_our_node_id();
	let node_id_1 = nodes[1].node.get_our_node_id();

	let initial_channel_value_sat = 100_000;
	let (_, _, channel_id, _) =
		create_announced_chan_between_nodes_with_value(&nodes, 0, 1, initial_channel_value_sat, 0);

	provide_utxo_reserves(&nodes, 2, Amount::from_sat(100_000));

	// Step 1: Both nodes initiate a splice. Node 0 at floor feerate, node 1 splices in 95k
	// from a 100k UTXO (tight budget: ~5k for change/fees).
	let floor_feerate = FeeRate::from_sat_per_kwu(FEERATE_FLOOR_SATS_PER_KW as u64);

	let funding_template_0 =
		nodes[0].node.splice_channel(&channel_id, &node_id_1, floor_feerate).unwrap();
	let wallet_0 = WalletSync::new(Arc::clone(&nodes[0].wallet_source), nodes[0].logger);
	let node_0_funding_contribution =
		funding_template_0.splice_in_sync(Amount::from_sat(50_000), &wallet_0).unwrap();
	nodes[0]
		.node
		.funding_contributed(&channel_id, &node_id_1, node_0_funding_contribution.clone(), None)
		.unwrap();

	let node_1_added_value = Amount::from_sat(95_000);
	let funding_template_1 =
		nodes[1].node.splice_channel(&channel_id, &node_id_0, floor_feerate).unwrap();
	let wallet_1 = WalletSync::new(Arc::clone(&nodes[1].wallet_source), nodes[1].logger);
	let node_1_funding_contribution =
		funding_template_1.splice_in_sync(node_1_added_value, &wallet_1).unwrap();
	nodes[1]
		.node
		.funding_contributed(&channel_id, &node_id_0, node_1_funding_contribution.clone(), None)
		.unwrap();

	// Step 2: Both send STFU; tiebreak: node 0 wins.
	let stfu_0 = get_event_msg!(nodes[0], MessageSendEvent::SendStfu, node_id_1);
	let stfu_1 = get_event_msg!(nodes[1], MessageSendEvent::SendStfu, node_id_0);

	nodes[1].node.handle_stfu(node_id_0, &stfu_0);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	nodes[0].node.handle_stfu(node_id_1, &stfu_1);

	// Step 3: Complete the initial splice with both contributing.
	let splice_init = get_event_msg!(nodes[0], MessageSendEvent::SendSpliceInit, node_id_1);
	nodes[1].node.handle_splice_init(node_id_0, &splice_init);
	let splice_ack = get_event_msg!(nodes[1], MessageSendEvent::SendSpliceAck, node_id_0);
	assert_ne!(splice_ack.funding_contribution_satoshis, 0);
	nodes[0].node.handle_splice_ack(node_id_1, &splice_ack);

	let new_funding_script = chan_utils::make_funding_redeemscript(
		&splice_init.funding_pubkey,
		&splice_ack.funding_pubkey,
	)
	.to_p2wsh();

	complete_interactive_funding_negotiation_for_both(
		&nodes[0],
		&nodes[1],
		channel_id,
		node_0_funding_contribution,
		Some(node_1_funding_contribution),
		new_funding_script.clone(),
	);

	let (_first_splice_tx, splice_locked) =
		sign_interactive_funding_tx_with_acceptor_contribution(&nodes[0], &nodes[1], false, true);
	assert!(splice_locked.is_none());

	expect_splice_pending_event(&nodes[0], &node_id_1);
	expect_splice_pending_event(&nodes[1], &node_id_0);

	// Step 4: Provide new UTXOs. Node 0 initiates RBF at 20,000 sat/kwu.
	provide_utxo_reserves(&nodes, 2, Amount::from_sat(100_000));

	let high_feerate = FeeRate::from_sat_per_kwu(20_000);
	let funding_template =
		nodes[0].node.rbf_channel(&channel_id, &node_id_1, high_feerate).unwrap();
	let wallet = WalletSync::new(Arc::clone(&nodes[0].wallet_source), nodes[0].logger);
	let rbf_funding_contribution =
		funding_template.splice_in_sync(Amount::from_sat(50_000), &wallet).unwrap();
	nodes[0]
		.node
		.funding_contributed(&channel_id, &node_id_1, rbf_funding_contribution.clone(), None)
		.unwrap();

	// Step 5: STFU exchange.
	let stfu_a = get_event_msg!(nodes[0], MessageSendEvent::SendStfu, node_id_1);
	nodes[1].node.handle_stfu(node_id_0, &stfu_a);
	let stfu_b = get_event_msg!(nodes[1], MessageSendEvent::SendStfu, node_id_0);
	nodes[0].node.handle_stfu(node_id_1, &stfu_b);

	// Step 6: Node 0 sends tx_init_rbf at 20,000 sat/kwu.
	let tx_init_rbf = get_event_msg!(nodes[0], MessageSendEvent::SendTxInitRbf, node_id_1);
	assert_eq!(tx_init_rbf.feerate_sat_per_1000_weight, high_feerate.to_sat_per_kwu() as u32);

	// Step 7: Node 1's prior contribution (95k from 100k UTXO) can't cover fees at 20k sat/kwu.
	// Should reject with WarnAndDisconnect rather than proceeding without contribution.
	nodes[1].node.handle_tx_init_rbf(node_id_0, &tx_init_rbf);

	let msg_events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(msg_events.len(), 1, "{msg_events:?}");
	match &msg_events[0] {
		MessageSendEvent::HandleError {
			action: msgs::ErrorAction::DisconnectPeerWithWarning { msg },
			..
		} => {
			assert!(
				msg.data.contains("cannot accommodate RBF feerate"),
				"Unexpected warning: {}",
				msg.data
			);
		},
		other => panic!("Expected HandleError/DisconnectPeerWithWarning, got {:?}", other),
	}
}

#[test]
fn test_splice_rbf_sequential() {
	// Three consecutive RBF rounds on the same splice (initial → RBF #1 → RBF #2).
	// Node 0 is the quiescence initiator; node 1 is the acceptor with no contribution.
	// Verifies:
	// - Each round satisfies the 25/24 feerate rule
	// - DiscardFunding events reference the correct txids from previous rounds
	// - The final RBF can be mined and splice_locked successfully
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_id_0 = nodes[0].node.get_our_node_id();
	let node_id_1 = nodes[1].node.get_our_node_id();

	let initial_channel_value_sat = 100_000;
	let (_, _, channel_id, _) =
		create_announced_chan_between_nodes_with_value(&nodes, 0, 1, initial_channel_value_sat, 0);

	let added_value = Amount::from_sat(50_000);
	provide_utxo_reserves(&nodes, 2, added_value * 2);

	// Save the pre-splice funding outpoint.
	let original_funding_outpoint = nodes[0]
		.chain_monitor
		.chain_monitor
		.get_monitor(channel_id)
		.map(|monitor| (monitor.get_funding_txo(), monitor.get_funding_script()))
		.unwrap();

	// --- Round 0: Initial splice-in from node 0 at floor feerate (253). ---
	let funding_contribution = do_initiate_splice_in(&nodes[0], &nodes[1], channel_id, added_value);
	let (splice_tx_0, new_funding_script) =
		splice_channel(&nodes[0], &nodes[1], channel_id, funding_contribution);

	// Feerate progression: 253 → ceil(253*25/24) = 264 → ceil(264*25/24) = 275
	let feerate_1_sat_per_kwu = (FEERATE_FLOOR_SATS_PER_KW as u64 * 25 + 23) / 24; // 264
	let feerate_2_sat_per_kwu = (feerate_1_sat_per_kwu * 25 + 23) / 24; // 275

	// --- Round 1: RBF #1 at feerate 264. ---
	provide_utxo_reserves(&nodes, 2, added_value * 2);

	let rbf_feerate_1 = FeeRate::from_sat_per_kwu(feerate_1_sat_per_kwu);
	let funding_template =
		nodes[0].node.rbf_channel(&channel_id, &node_id_1, rbf_feerate_1).unwrap();
	let wallet = WalletSync::new(Arc::clone(&nodes[0].wallet_source), nodes[0].logger);
	let funding_contribution_1 = funding_template.splice_in_sync(added_value, &wallet).unwrap();
	nodes[0]
		.node
		.funding_contributed(&channel_id, &node_id_1, funding_contribution_1.clone(), None)
		.unwrap();

	let stfu_a = get_event_msg!(nodes[0], MessageSendEvent::SendStfu, node_id_1);
	nodes[1].node.handle_stfu(node_id_0, &stfu_a);
	let stfu_b = get_event_msg!(nodes[1], MessageSendEvent::SendStfu, node_id_0);
	nodes[0].node.handle_stfu(node_id_1, &stfu_b);

	let tx_init_rbf = get_event_msg!(nodes[0], MessageSendEvent::SendTxInitRbf, node_id_1);
	assert_eq!(tx_init_rbf.feerate_sat_per_1000_weight, feerate_1_sat_per_kwu as u32);
	nodes[1].node.handle_tx_init_rbf(node_id_0, &tx_init_rbf);
	let tx_ack_rbf = get_event_msg!(nodes[1], MessageSendEvent::SendTxAckRbf, node_id_0);
	nodes[0].node.handle_tx_ack_rbf(node_id_1, &tx_ack_rbf);

	complete_interactive_funding_negotiation(
		&nodes[0],
		&nodes[1],
		channel_id,
		funding_contribution_1,
		new_funding_script.clone(),
	);
	let (splice_tx_1, splice_locked) = sign_interactive_funding_tx(&nodes[0], &nodes[1], false);
	assert!(splice_locked.is_none());
	expect_splice_pending_event(&nodes[0], &node_id_1);
	expect_splice_pending_event(&nodes[1], &node_id_0);

	// --- Round 2: RBF #2 at feerate 275. ---
	provide_utxo_reserves(&nodes, 2, added_value * 2);

	let rbf_feerate_2 = FeeRate::from_sat_per_kwu(feerate_2_sat_per_kwu);
	let funding_template =
		nodes[0].node.rbf_channel(&channel_id, &node_id_1, rbf_feerate_2).unwrap();
	let wallet = WalletSync::new(Arc::clone(&nodes[0].wallet_source), nodes[0].logger);
	let funding_contribution_2 = funding_template.splice_in_sync(added_value, &wallet).unwrap();
	nodes[0]
		.node
		.funding_contributed(&channel_id, &node_id_1, funding_contribution_2.clone(), None)
		.unwrap();

	let stfu_a = get_event_msg!(nodes[0], MessageSendEvent::SendStfu, node_id_1);
	nodes[1].node.handle_stfu(node_id_0, &stfu_a);
	let stfu_b = get_event_msg!(nodes[1], MessageSendEvent::SendStfu, node_id_0);
	nodes[0].node.handle_stfu(node_id_1, &stfu_b);

	let tx_init_rbf = get_event_msg!(nodes[0], MessageSendEvent::SendTxInitRbf, node_id_1);
	assert_eq!(tx_init_rbf.feerate_sat_per_1000_weight, feerate_2_sat_per_kwu as u32);
	nodes[1].node.handle_tx_init_rbf(node_id_0, &tx_init_rbf);
	let tx_ack_rbf = get_event_msg!(nodes[1], MessageSendEvent::SendTxAckRbf, node_id_0);
	nodes[0].node.handle_tx_ack_rbf(node_id_1, &tx_ack_rbf);

	complete_interactive_funding_negotiation(
		&nodes[0],
		&nodes[1],
		channel_id,
		funding_contribution_2,
		new_funding_script.clone(),
	);
	let (rbf_tx_final, splice_locked) = sign_interactive_funding_tx(&nodes[0], &nodes[1], false);
	assert!(splice_locked.is_none());
	expect_splice_pending_event(&nodes[0], &node_id_1);
	expect_splice_pending_event(&nodes[1], &node_id_0);

	// --- Mine and lock the final RBF. ---
	mine_transaction(&nodes[0], &rbf_tx_final);
	mine_transaction(&nodes[1], &rbf_tx_final);

	connect_blocks(&nodes[0], ANTI_REORG_DELAY - 1);
	connect_blocks(&nodes[1], ANTI_REORG_DELAY - 1);

	let splice_locked_b = get_event_msg!(nodes[0], MessageSendEvent::SendSpliceLocked, node_id_1);
	nodes[1].node.handle_splice_locked(node_id_0, &splice_locked_b);

	let mut msg_events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(msg_events.len(), 2, "{msg_events:?}");
	let splice_locked_a =
		if let MessageSendEvent::SendSpliceLocked { msg, .. } = msg_events.remove(0) {
			msg
		} else {
			panic!("Expected SendSpliceLocked, got {:?}", msg_events[0]);
		};
	let announcement_sigs_b =
		if let MessageSendEvent::SendAnnouncementSignatures { msg, .. } = msg_events.remove(0) {
			msg
		} else {
			panic!("Expected SendAnnouncementSignatures");
		};
	nodes[0].node.handle_splice_locked(node_id_1, &splice_locked_a);
	nodes[0].node.handle_announcement_signatures(node_id_1, &announcement_sigs_b);

	// --- Verify DiscardFunding events for both replaced candidates. ---
	let splice_tx_0_txid = splice_tx_0.compute_txid();
	let splice_tx_1_txid = splice_tx_1.compute_txid();

	// Node 0 (initiator): ChannelReady + 2 DiscardFunding.
	let events_a = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events_a.len(), 3, "{events_a:?}");
	assert!(matches!(events_a[0], Event::ChannelReady { .. }));
	let discard_txids_a: Vec<_> = events_a[1..]
		.iter()
		.map(|e| match e {
			Event::DiscardFunding { funding_info: FundingInfo::Tx { transaction }, .. } => {
				transaction.compute_txid()
			},
			Event::DiscardFunding { funding_info: FundingInfo::OutPoint { outpoint }, .. } => {
				outpoint.txid
			},
			other => panic!("Expected DiscardFunding, got {:?}", other),
		})
		.collect();
	assert!(discard_txids_a.contains(&splice_tx_0_txid), "Missing discard for initial splice");
	assert!(discard_txids_a.contains(&splice_tx_1_txid), "Missing discard for RBF #1");
	check_added_monitors(&nodes[0], 1);

	// Node 1 (acceptor): ChannelReady + 2 DiscardFunding.
	let events_b = nodes[1].node.get_and_clear_pending_events();
	assert_eq!(events_b.len(), 3, "{events_b:?}");
	assert!(matches!(events_b[0], Event::ChannelReady { .. }));
	let discard_txids_b: Vec<_> = events_b[1..]
		.iter()
		.map(|e| match e {
			Event::DiscardFunding { funding_info: FundingInfo::Tx { transaction }, .. } => {
				transaction.compute_txid()
			},
			Event::DiscardFunding { funding_info: FundingInfo::OutPoint { outpoint }, .. } => {
				outpoint.txid
			},
			other => panic!("Expected DiscardFunding, got {:?}", other),
		})
		.collect();
	assert!(discard_txids_b.contains(&splice_tx_0_txid), "Missing discard for initial splice");
	assert!(discard_txids_b.contains(&splice_tx_1_txid), "Missing discard for RBF #1");
	check_added_monitors(&nodes[1], 1);

	// Complete the announcement exchange.
	let mut msg_events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(msg_events.len(), 2, "{msg_events:?}");
	if let MessageSendEvent::SendAnnouncementSignatures { msg, .. } = msg_events.remove(0) {
		nodes[1].node.handle_announcement_signatures(node_id_0, &msg);
	} else {
		panic!("Expected SendAnnouncementSignatures");
	}
	assert!(matches!(msg_events.remove(0), MessageSendEvent::BroadcastChannelAnnouncement { .. }));

	let mut msg_events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(msg_events.len(), 1, "{msg_events:?}");
	assert!(matches!(msg_events.remove(0), MessageSendEvent::BroadcastChannelAnnouncement { .. }));

	// Clean up old watched outpoints.
	let (orig_outpoint, orig_script) = original_funding_outpoint;
	let splice_funding_idx = |tx: &Transaction| {
		tx.output.iter().position(|o| o.script_pubkey == new_funding_script).unwrap()
	};
	let outpoint_0 =
		OutPoint { txid: splice_tx_0_txid, index: splice_funding_idx(&splice_tx_0) as u16 };
	let outpoint_1 =
		OutPoint { txid: splice_tx_1_txid, index: splice_funding_idx(&splice_tx_1) as u16 };
	for node in &nodes {
		node.chain_source.remove_watched_txn_and_outputs(orig_outpoint, orig_script.clone());
		node.chain_source.remove_watched_txn_and_outputs(outpoint_0, new_funding_script.clone());
		node.chain_source.remove_watched_txn_and_outputs(outpoint_1, new_funding_script.clone());
	}
}
