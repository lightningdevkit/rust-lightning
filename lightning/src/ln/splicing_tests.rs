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
use crate::ln::channel::{
	CHANNEL_ANNOUNCEMENT_PROPAGATION_DELAY, FEE_SPIKE_BUFFER_FEE_INCREASE_MULTIPLE,
};
use crate::ln::channelmanager::{provided_init_features, PaymentId, BREAKDOWN_TIMEOUT};
use crate::ln::functional_test_utils::*;
use crate::ln::funding::FundingContribution;
use crate::ln::msgs::{self, BaseMessageHandler, ChannelMessageHandler, MessageSendEvent};
use crate::ln::outbound_payment::RecipientOnionFields;
use crate::ln::types::ChannelId;
use crate::routing::router::{PaymentParameters, RouteParameters};
use crate::types::features::ChannelTypeFeatures;
use crate::util::config::UserConfig;
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
	Amount, FeeRate, OutPoint as BitcoinOutPoint, Psbt, ScriptBuf, Transaction, TxOut, Txid,
	WPubkeyHash,
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

	let res = nodes[1].node.splice_channel(&channel_id, &node_id_0);
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

	let res = nodes[1].node.splice_channel(&channel_id, &node_id_0);
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
	let funding_template =
		nodes[0].node.splice_channel(&channel_id, &nodes[1].node.get_our_node_id()).unwrap();

	let wallet = WalletSync::new(Arc::clone(&nodes[0].wallet_source), nodes[0].logger);
	assert!(funding_template
		.splice_in_sync(splice_in_value, feerate, FeeRate::MAX, &wallet)
		.is_err());
}

/// A mock wallet that returns a pre-configured [`CoinSelection`] with a single input and change
/// output. Used to test edge cases where the input value is tight relative to the fee estimate.
#[cfg(test)]
struct TightBudgetWallet {
	utxo_value: Amount,
	change_value: Amount,
}

#[cfg(test)]
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
	let floor_feerate = FeeRate::from_sat_per_kwu(FEERATE_FLOOR_SATS_PER_KW as u64);
	let funding_template = initiator.node.splice_channel(&channel_id, &node_id_acceptor).unwrap();
	let feerate = funding_template.min_rbf_feerate().unwrap_or(floor_feerate);
	let wallet = WalletSync::new(Arc::clone(&initiator.wallet_source), initiator.logger);
	let funding_contribution =
		funding_template.splice_in_sync(value_added, feerate, FeeRate::MAX, &wallet).unwrap();
	initiator
		.node
		.funding_contributed(&channel_id, &node_id_acceptor, funding_contribution.clone(), None)
		.unwrap();
	funding_contribution
}

pub fn do_initiate_rbf_splice_in<'a, 'b, 'c, 'd>(
	node: &'a Node<'b, 'c, 'd>, counterparty: &'a Node<'b, 'c, 'd>, channel_id: ChannelId,
	value_added: Amount, feerate: FeeRate,
) -> FundingContribution {
	let node_id_counterparty = counterparty.node.get_our_node_id();
	let funding_template = node.node.splice_channel(&channel_id, &node_id_counterparty).unwrap();
	let wallet = WalletSync::new(Arc::clone(&node.wallet_source), node.logger);
	let funding_contribution =
		funding_template.splice_in_sync(value_added, feerate, FeeRate::MAX, &wallet).unwrap();
	node.node
		.funding_contributed(&channel_id, &node_id_counterparty, funding_contribution.clone(), None)
		.unwrap();
	funding_contribution
}

pub fn do_initiate_rbf_splice_in_and_out<'a, 'b, 'c, 'd>(
	node: &'a Node<'b, 'c, 'd>, counterparty: &'a Node<'b, 'c, 'd>, channel_id: ChannelId,
	value_added: Amount, outputs: Vec<TxOut>, feerate: FeeRate,
) -> FundingContribution {
	let node_id_counterparty = counterparty.node.get_our_node_id();
	let funding_template = node.node.splice_channel(&channel_id, &node_id_counterparty).unwrap();
	let wallet = WalletSync::new(Arc::clone(&node.wallet_source), node.logger);
	let funding_contribution = funding_template
		.splice_in_and_out_sync(value_added, outputs, feerate, FeeRate::MAX, &wallet)
		.unwrap();
	node.node
		.funding_contributed(&channel_id, &node_id_counterparty, funding_contribution.clone(), None)
		.unwrap();
	funding_contribution
}

pub fn initiate_splice_out<'a, 'b, 'c, 'd>(
	initiator: &'a Node<'b, 'c, 'd>, acceptor: &'a Node<'b, 'c, 'd>, channel_id: ChannelId,
	outputs: Vec<TxOut>,
) -> Result<FundingContribution, APIError> {
	let node_id_acceptor = acceptor.node.get_our_node_id();
	let floor_feerate = FeeRate::from_sat_per_kwu(FEERATE_FLOOR_SATS_PER_KW as u64);
	let funding_template = initiator.node.splice_channel(&channel_id, &node_id_acceptor).unwrap();
	let feerate = funding_template.min_rbf_feerate().unwrap_or(floor_feerate);
	let funding_contribution = funding_template.splice_out(outputs, feerate, FeeRate::MAX).unwrap();
	match initiator.node.funding_contributed(
		&channel_id,
		&node_id_acceptor,
		funding_contribution.clone(),
		None,
	) {
		Ok(()) => Ok(funding_contribution),
		Err(e) => {
			expect_splice_failed_events(initiator, &channel_id, funding_contribution);
			Err(e)
		},
	}
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
	let floor_feerate = FeeRate::from_sat_per_kwu(FEERATE_FLOOR_SATS_PER_KW as u64);
	let funding_template = initiator.node.splice_channel(&channel_id, &node_id_acceptor).unwrap();
	let feerate = funding_template.min_rbf_feerate().unwrap_or(floor_feerate);
	let wallet = WalletSync::new(Arc::clone(&initiator.wallet_source), initiator.logger);
	let funding_contribution = funding_template
		.splice_in_and_out_sync(value_added, outputs, feerate, FeeRate::MAX, &wallet)
		.unwrap();
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

pub fn complete_rbf_handshake<'a, 'b, 'c, 'd>(
	initiator: &'a Node<'b, 'c, 'd>, acceptor: &'a Node<'b, 'c, 'd>,
) -> msgs::TxAckRbf {
	let node_id_initiator = initiator.node.get_our_node_id();
	let node_id_acceptor = acceptor.node.get_our_node_id();

	let stfu_init = get_event_msg!(initiator, MessageSendEvent::SendStfu, node_id_acceptor);
	acceptor.node.handle_stfu(node_id_initiator, &stfu_init);
	let stfu_ack = get_event_msg!(acceptor, MessageSendEvent::SendStfu, node_id_initiator);
	initiator.node.handle_stfu(node_id_acceptor, &stfu_ack);

	let tx_init_rbf = get_event_msg!(initiator, MessageSendEvent::SendTxInitRbf, node_id_acceptor);
	acceptor.node.handle_tx_init_rbf(node_id_initiator, &tx_init_rbf);
	let tx_ack_rbf = get_event_msg!(acceptor, MessageSendEvent::SendTxAckRbf, node_id_initiator);
	initiator.node.handle_tx_ack_rbf(node_id_acceptor, &tx_ack_rbf);

	tx_ack_rbf
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
		0,
		new_funding_script,
	);
}

pub fn complete_interactive_funding_negotiation_for_both<'a, 'b, 'c, 'd>(
	initiator: &'a Node<'b, 'c, 'd>, acceptor: &'a Node<'b, 'c, 'd>, channel_id: ChannelId,
	initiator_contribution: FundingContribution,
	acceptor_contribution: Option<FundingContribution>, acceptor_funding_satoshis: i64,
	new_funding_script: ScriptBuf,
) {
	let node_id_initiator = initiator.node.get_our_node_id();
	let node_id_acceptor = acceptor.node.get_our_node_id();

	let (funding_outpoint, channel_value_satoshis) = initiator
		.node
		.list_channels()
		.iter()
		.find(|channel| {
			channel.counterparty.node_id == node_id_acceptor && channel.channel_id == channel_id
		})
		.map(|channel| (channel.funding_txo.unwrap(), channel.channel_value_satoshis))
		.unwrap();
	let new_channel_value = Amount::from_sat(
		channel_value_satoshis
			.checked_add_signed(initiator_contribution.net_value().to_sat())
			.unwrap()
			.checked_add_signed(acceptor_funding_satoshis)
			.unwrap(),
	);
	let (initiator_funding_tx_inputs, mut expected_initiator_outputs) =
		initiator_contribution.into_tx_parts();
	let mut expected_initiator_inputs = initiator_funding_tx_inputs
		.iter()
		.map(|input| input.utxo.outpoint)
		.chain(core::iter::once(funding_outpoint.into_bitcoin_outpoint()))
		.collect::<Vec<_>>();
	expected_initiator_outputs
		.push(TxOut { script_pubkey: new_funding_script, value: new_channel_value });

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
				expected_initiator_outputs.remove(
					expected_initiator_outputs
						.iter()
						.position(|output| {
							*output.script_pubkey == msg.script && output.value.to_sat() == msg.sats
						})
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
	assert!(expected_initiator_outputs.is_empty(), "Not all initiator outputs were sent");
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
	lock_splice(node_a, node_b, &splice_locked_for_node_b, false, &[])
}

pub fn lock_splice<'a, 'b, 'c, 'd>(
	node_a: &'a Node<'b, 'c, 'd>, node_b: &'a Node<'b, 'c, 'd>,
	splice_locked_for_node_b: &msgs::SpliceLocked, is_0conf: bool, expected_discard_txids: &[Txid],
) -> Option<MessageSendEvent> {
	let prev_funding_txid = node_a
		.chain_monitor
		.chain_monitor
		.get_monitor(splice_locked_for_node_b.channel_id)
		.map(|monitor| monitor.get_funding_txo().txid)
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

	let mut all_discard_txids = Vec::new();
	let expected_num_events = 1 + expected_discard_txids.len();
	for node in [node_a, node_b] {
		let events = node.node.get_and_clear_pending_events();
		assert_eq!(events.len(), expected_num_events, "{events:?}");
		assert!(matches!(events[0], Event::ChannelReady { .. }));
		let discard_txids: Vec<_> = events[1..]
			.iter()
			.map(|e| match e {
				Event::DiscardFunding { funding_info: FundingInfo::Tx { transaction }, .. } => {
					transaction.compute_txid()
				},
				Event::DiscardFunding {
					funding_info: FundingInfo::OutPoint { outpoint }, ..
				} => outpoint.txid,
				other => panic!("Expected DiscardFunding, got {:?}", other),
			})
			.collect();
		for txid in expected_discard_txids {
			assert!(discard_txids.contains(txid), "Missing DiscardFunding for txid {}", txid);
		}
		if all_discard_txids.is_empty() {
			all_discard_txids = discard_txids;
		}
		check_added_monitors(node, 1);
	}

	let mut node_a_stfu = None;
	if !is_0conf {
		let mut msg_events = node_a.node.get_and_clear_pending_msg_events();

		// If node_a had a pending QuiescentAction, filter out the stfu message.
		node_a_stfu = msg_events
			.iter()
			.position(|event| matches!(event, MessageSendEvent::SendStfu { .. }))
			.map(|i| msg_events.remove(i));

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
	for node in [node_a, node_b] {
		node.chain_source.remove_watched_by_txid(prev_funding_txid);
		for txid in &all_discard_txids {
			node.chain_source.remove_watched_by_txid(*txid);
		}
	}

	node_a_stfu.or(node_b_stfu)
}

pub fn lock_rbf_splice_after_blocks<'a, 'b, 'c, 'd>(
	node_a: &'a Node<'b, 'c, 'd>, node_b: &'a Node<'b, 'c, 'd>, tx: &Transaction, num_blocks: u32,
	expected_discard_txids: &[Txid],
) -> Option<MessageSendEvent> {
	mine_transaction(node_a, tx);
	mine_transaction(node_b, tx);

	connect_blocks(node_a, num_blocks);
	connect_blocks(node_b, num_blocks);

	let node_id_b = node_b.node.get_our_node_id();
	let splice_locked_for_node_b =
		get_event_msg!(node_a, MessageSendEvent::SendSpliceLocked, node_id_b);
	lock_splice(node_a, node_b, &splice_locked_for_node_b, false, expected_discard_txids)
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
		initiate_splice_out(&nodes[0], &nodes[1], channel_id, outputs.clone()).unwrap();

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
		initiate_splice_out(&nodes[0], &nodes[1], channel_id, outputs.clone()).unwrap();

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
		initiate_splice_out(&nodes[0], &nodes[1], channel_id, outputs.clone()).unwrap();

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
	let funding_contribution =
		initiate_splice_out(&nodes[0], &nodes[1], channel_id, outputs).unwrap();
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
		initiate_splice_out(&nodes[0], &nodes[1], channel_id, outputs.clone()).unwrap();

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

	let funding_contribution =
		initiate_splice_out(&nodes[1], &nodes[0], channel_id, outputs).unwrap();
	let _ = splice_channel(&nodes[1], &nodes[0], channel_id, funding_contribution);
}

#[test]
fn test_splice_in() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let mut config = test_default_channel_config();
	config.channel_handshake_config.announced_channel_max_inbound_htlc_value_in_flight_percentage =
		100;
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
	config.channel_handshake_config.announced_channel_max_inbound_htlc_value_in_flight_percentage =
		100;
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
	let funding_contribution =
		initiate_splice_out(&nodes[0], &nodes[1], channel_id, outputs).unwrap();

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
	config.channel_handshake_config.announced_channel_max_inbound_htlc_value_in_flight_percentage =
		100;
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

	let funding_template = nodes[0].node.splice_channel(&channel_id, &node_1_id).unwrap();
	let funding_contribution =
		funding_template.splice_out(outputs.clone(), feerate, FeeRate::MAX).unwrap();
	nodes[0]
		.node
		.funding_contributed(&channel_id, &node_1_id, funding_contribution.clone(), None)
		.unwrap();

	assert_eq!(
		nodes[0].node.splice_channel(&channel_id, &node_1_id),
		Err(APIError::APIMisuseError {
			err: format!(
				"Channel {} cannot be spliced as one is waiting to be negotiated",
				channel_id
			),
		}),
	);

	let new_funding_script = complete_splice_handshake(&nodes[0], &nodes[1]);

	assert_eq!(
		nodes[0].node.splice_channel(&channel_id, &node_1_id),
		Err(APIError::APIMisuseError {
			err: format!(
				"Channel {} cannot be spliced as one is currently being negotiated",
				channel_id
			),
		}),
	);

	complete_interactive_funding_negotiation(
		&nodes[0],
		&nodes[1],
		channel_id,
		funding_contribution,
		new_funding_script,
	);

	assert_eq!(
		nodes[0].node.splice_channel(&channel_id, &node_1_id),
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

	// Now that the splice is pending, another splice may be initiated.
	assert!(nodes[0].node.splice_channel(&channel_id, &node_1_id).is_ok());

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
	// Node 0 had called splice_channel (line above) but never funding_contributed, so no stfu
	// is expected from node 0 at this point.
	assert!(stfu.is_none());
}

#[test]
fn test_initiating_splice_holds_stfu_with_pending_splice() {
	// Test that a splice can be completed and locked successfully.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	provide_utxo_reserves(&nodes, 2, Amount::ONE_BTC);

	let initial_channel_value_sat = 100_000;
	let (_, _, channel_id, _) =
		create_announced_chan_between_nodes_with_value(&nodes, 0, 1, initial_channel_value_sat, 0);

	// Node 0 initiates a splice, completing the full flow.
	let value_added = Amount::from_sat(10_000);
	let funding_contribution_0 = initiate_splice_in(&nodes[0], &nodes[1], channel_id, value_added);
	let (splice_tx, _) = splice_channel(&nodes[0], &nodes[1], channel_id, funding_contribution_0);

	// Mine and lock the splice.
	mine_transaction(&nodes[0], &splice_tx);
	mine_transaction(&nodes[1], &splice_tx);
	let stfu = lock_splice_after_blocks(&nodes[0], &nodes[1], 5);
	assert!(stfu.is_none());
}

#[test]
fn test_splice_both_contribute_tiebreak() {
	// Same feerate: the acceptor's change increases because is_initiator=false has lower weight.
	let feerate = FeeRate::from_sat_per_kwu(FEERATE_FLOOR_SATS_PER_KW as u64);
	do_test_splice_tiebreak(feerate, feerate, Amount::from_sat(50_000), true);
}

#[test]
fn test_splice_tiebreak_higher_feerate() {
	// Node 0 (winner) uses a higher feerate than node 1 (loser). Node 1's change output is
	// adjusted (reduced) to accommodate the higher feerate. Negotiation succeeds.
	let feerate = FEERATE_FLOOR_SATS_PER_KW as u64;
	do_test_splice_tiebreak(
		FeeRate::from_sat_per_kwu(feerate * 3),
		FeeRate::from_sat_per_kwu(feerate),
		Amount::from_sat(50_000),
		true,
	);
}

#[test]
fn test_splice_tiebreak_lower_feerate() {
	// Node 0 (winner) uses a lower feerate than node 1 (loser). Since the initiator's feerate
	// is below node 1's minimum, node 1 proceeds without contribution and retries as initiator.
	let feerate = FEERATE_FLOOR_SATS_PER_KW as u64;
	do_test_splice_tiebreak(
		FeeRate::from_sat_per_kwu(feerate),
		FeeRate::from_sat_per_kwu(feerate * 3),
		Amount::from_sat(50_000),
		false,
	);
}

#[test]
fn test_splice_tiebreak_feerate_too_high() {
	// Node 0 (winner) uses a high feerate (20,000 sat/kwu). Node 1 splices in 95,000 sats from
	// a 100,000 sat UTXO, leaving too little budget for fees. Node 1 proceeds without its
	// contribution and retries as initiator.
	let feerate = FEERATE_FLOOR_SATS_PER_KW as u64;
	do_test_splice_tiebreak(
		FeeRate::from_sat_per_kwu(20_000),
		FeeRate::from_sat_per_kwu(feerate),
		Amount::from_sat(95_000),
		false,
	);
}

/// Runs the splice tie-breaker test with the given per-node feerates and node 1's splice value.
///
/// Both nodes call splice_channel + splice_in_sync + funding_contributed, both send STFU,
/// node 0 wins the tie-break. If `expect_acceptor_contributes` is true, node 1 contributes
/// to the splice; otherwise, node 1 proceeds without contribution and retries as initiator.
#[cfg(test)]
fn do_test_splice_tiebreak(
	node_0_feerate: FeeRate, node_1_feerate: FeeRate, node_1_splice_value: Amount,
	expect_acceptor_contributes: bool,
) {
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

	// Node 0 calls splice_channel + splice_in_sync + funding_contributed.
	let funding_template_0 = nodes[0].node.splice_channel(&channel_id, &node_id_1).unwrap();
	let wallet_0 = WalletSync::new(Arc::clone(&nodes[0].wallet_source), nodes[0].logger);
	let node_0_funding_contribution = funding_template_0
		.splice_in_sync(added_value, node_0_feerate, FeeRate::MAX, &wallet_0)
		.unwrap();
	nodes[0]
		.node
		.funding_contributed(&channel_id, &node_id_1, node_0_funding_contribution.clone(), None)
		.unwrap();

	// Node 1 calls splice_channel + splice_in_sync + funding_contributed.
	let funding_template_1 = nodes[1].node.splice_channel(&channel_id, &node_id_0).unwrap();
	let wallet_1 = WalletSync::new(Arc::clone(&nodes[1].wallet_source), nodes[1].logger);
	let node_1_funding_contribution = funding_template_1
		.splice_in_sync(node_1_splice_value, node_1_feerate, FeeRate::MAX, &wallet_1)
		.unwrap();
	nodes[1]
		.node
		.funding_contributed(&channel_id, &node_id_0, node_1_funding_contribution.clone(), None)
		.unwrap();

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

	// Node 1 handles SpliceInit — whether it contributes depends on feerate/budget constraints.
	nodes[1].node.handle_splice_init(node_id_0, &splice_init);
	let splice_ack = get_event_msg!(nodes[1], MessageSendEvent::SendSpliceAck, node_id_0);
	let acceptor_contributes = splice_ack.funding_contribution_satoshis != 0;
	assert_eq!(
		acceptor_contributes, expect_acceptor_contributes,
		"Expected acceptor contribution: {}, got: {}",
		expect_acceptor_contributes, acceptor_contributes,
	);

	// Node 0 handles SpliceAck — starts interactive tx construction.
	nodes[0].node.handle_splice_ack(node_id_1, &splice_ack);

	// Compute the new funding script from the splice pubkeys.
	let new_funding_script = chan_utils::make_funding_redeemscript(
		&splice_init.funding_pubkey,
		&splice_ack.funding_pubkey,
	)
	.to_p2wsh();

	if acceptor_contributes {
		// Capture change output values for assertions.
		let node_0_change = node_0_funding_contribution
			.change_output()
			.expect("splice-in should have a change output")
			.clone();
		let node_1_change = node_1_funding_contribution
			.change_output()
			.expect("splice-in should have a change output")
			.clone();

		// Complete interactive funding negotiation with both parties' inputs/outputs.
		complete_interactive_funding_negotiation_for_both(
			&nodes[0],
			&nodes[1],
			channel_id,
			node_0_funding_contribution,
			Some(node_1_funding_contribution),
			splice_ack.funding_contribution_satoshis,
			new_funding_script,
		);

		// Sign (acceptor has contribution) and broadcast.
		let (tx, splice_locked) = sign_interactive_funding_tx_with_acceptor_contribution(
			&nodes[0], &nodes[1], false, true,
		);
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
		if node_0_feerate <= node_1_feerate {
			// Initiator's feerate <= acceptor's original: the acceptor's change increases because
			// is_initiator=false has lower weight, and the feerate is the same or lower.
			assert!(
				acceptor_change_in_tx.value > node_1_change.value,
				"Acceptor's change should increase when initiator feerate ({}) <= acceptor \
				 feerate ({}): adjusted {} vs original {}",
				node_0_feerate.to_sat_per_kwu(),
				node_1_feerate.to_sat_per_kwu(),
				acceptor_change_in_tx.value,
				node_1_change.value,
			);
		} else {
			// Initiator's feerate > acceptor's original: the higher feerate more than compensates
			// for the lower weight, so the acceptor's change decreases.
			assert!(
				acceptor_change_in_tx.value < node_1_change.value,
				"Acceptor's change should decrease when initiator feerate ({}) > acceptor \
				 feerate ({}): adjusted {} vs original {}",
				node_0_feerate.to_sat_per_kwu(),
				node_1_feerate.to_sat_per_kwu(),
				acceptor_change_in_tx.value,
				node_1_change.value,
			);
		}

		expect_splice_pending_event(&nodes[0], &node_id_1);
		expect_splice_pending_event(&nodes[1], &node_id_0);

		mine_transaction(&nodes[0], &tx);
		mine_transaction(&nodes[1], &tx);

		lock_splice_after_blocks(&nodes[0], &nodes[1], ANTI_REORG_DELAY - 1);
	} else {
		// Acceptor does not contribute — complete with only node 0's inputs/outputs.
		complete_interactive_funding_negotiation_for_both(
			&nodes[0],
			&nodes[1],
			channel_id,
			node_0_funding_contribution,
			None,
			0,
			new_funding_script,
		);

		// Sign (no acceptor contribution) and broadcast.
		let (tx, splice_locked) = sign_interactive_funding_tx_with_acceptor_contribution(
			&nodes[0], &nodes[1], false, false,
		);
		assert!(splice_locked.is_none());

		expect_splice_pending_event(&nodes[0], &node_id_1);
		expect_splice_pending_event(&nodes[1], &node_id_0);

		mine_transaction(&nodes[0], &tx);
		mine_transaction(&nodes[1], &tx);

		// After splice_locked, node 1's preserved QuiescentAction triggers STFU for retry.
		let node_1_stfu = lock_splice_after_blocks(&nodes[0], &nodes[1], ANTI_REORG_DELAY - 1);
		let stfu_1 = if let Some(MessageSendEvent::SendStfu { msg, .. }) = node_1_stfu {
			assert!(msg.initiator);
			msg
		} else {
			panic!("Expected SendStfu from node 1 after splice_locked");
		};

		// === Part 2: Node 1 retries as initiator at its preferred feerate ===
		// TODO(splicing): Node 1 should retry contribution via RBF above instead

		nodes[0].node.handle_stfu(node_id_1, &stfu_1);
		let stfu_0 = get_event_msg!(nodes[0], MessageSendEvent::SendStfu, node_id_1);

		nodes[1].node.handle_stfu(node_id_0, &stfu_0);
		let splice_init = get_event_msg!(nodes[1], MessageSendEvent::SendSpliceInit, node_id_0);

		nodes[0].node.handle_splice_init(node_id_1, &splice_init);
		let splice_ack = get_event_msg!(nodes[0], MessageSendEvent::SendSpliceAck, node_id_1);

		nodes[1].node.handle_splice_ack(node_id_0, &splice_ack);

		let new_funding_script_2 = chan_utils::make_funding_redeemscript(
			&splice_init.funding_pubkey,
			&splice_ack.funding_pubkey,
		)
		.to_p2wsh();

		complete_interactive_funding_negotiation(
			&nodes[1],
			&nodes[0],
			channel_id,
			node_1_funding_contribution,
			new_funding_script_2,
		);

		let (new_splice_tx, splice_locked) =
			sign_interactive_funding_tx(&nodes[1], &nodes[0], false);
		assert!(splice_locked.is_none());

		expect_splice_pending_event(&nodes[1], &node_id_0);
		expect_splice_pending_event(&nodes[0], &node_id_1);

		mine_transaction(&nodes[1], &new_splice_tx);
		mine_transaction(&nodes[0], &new_splice_tx);

		lock_splice_after_blocks(&nodes[1], &nodes[0], ANTI_REORG_DELAY - 1);
	}
}

#[test]
fn test_splice_tiebreak_feerate_too_high_rejected() {
	// Node 0 (winner) proposes a feerate far above node 1's (loser) max_feerate, and node 1's
	// fair fee at that feerate exceeds its budget. This triggers FeeRateAdjustmentError::TooHigh,
	// causing node 1 to reject with tx_abort.
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

	// Node 0 uses an extremely high feerate (100,000 sat/kwu). Node 1 uses the floor feerate
	// with a moderate splice-in (50,000 sats from a 100,000 sat UTXO) and a low max_feerate
	// (3,000 sat/kwu). The target (100k) far exceeds node 1's max (3k), and the fair fee at
	// 100k exceeds node 1's budget, triggering TooHigh.
	let high_feerate = FeeRate::from_sat_per_kwu(100_000);
	let floor_feerate = FeeRate::from_sat_per_kwu(FEERATE_FLOOR_SATS_PER_KW as u64);
	let node_0_added_value = Amount::from_sat(50_000);
	let node_1_added_value = Amount::from_sat(50_000);
	let node_1_max_feerate = FeeRate::from_sat_per_kwu(3_000);

	// Node 0: very high feerate, moderate splice-in.
	let funding_template_0 = nodes[0].node.splice_channel(&channel_id, &node_id_1).unwrap();
	let wallet_0 = WalletSync::new(Arc::clone(&nodes[0].wallet_source), nodes[0].logger);
	let node_0_funding_contribution = funding_template_0
		.splice_in_sync(node_0_added_value, high_feerate, FeeRate::MAX, &wallet_0)
		.unwrap();
	nodes[0]
		.node
		.funding_contributed(&channel_id, &node_id_1, node_0_funding_contribution.clone(), None)
		.unwrap();

	// Node 1: floor feerate, moderate splice-in, low max_feerate.
	let funding_template_1 = nodes[1].node.splice_channel(&channel_id, &node_id_0).unwrap();
	let wallet_1 = WalletSync::new(Arc::clone(&nodes[1].wallet_source), nodes[1].logger);
	let node_1_funding_contribution = funding_template_1
		.splice_in_sync(node_1_added_value, floor_feerate, node_1_max_feerate, &wallet_1)
		.unwrap();
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

	// Node 0 sends SpliceInit at 100,000 sat/kwu.
	let splice_init = get_event_msg!(nodes[0], MessageSendEvent::SendSpliceInit, node_id_1);

	// Node 1 handles SpliceInit — TooHigh: target (100k) >> max (3k) and fair fee > budget.
	nodes[1].node.handle_splice_init(node_id_0, &splice_init);

	let tx_abort = get_event_msg!(nodes[1], MessageSendEvent::SendTxAbort, node_id_0);
	assert_eq!(tx_abort.channel_id, channel_id);
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
	let (splice_tx, _) =
		splice_channel(&nodes[0], &nodes[1], channel_id, initiator_contribution.clone());
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
		initial_channel_capacity + initiator_contribution.net_value().to_sat() as u64
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
	let initiator_contribution =
		initiate_splice_out(&nodes[0], &nodes[1], channel_id, outputs).unwrap();
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
		initiate_splice_out(&nodes[0], &nodes[1], channel_id, node_0_outputs).unwrap();

	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());

	let node_1_outputs = vec![TxOut {
		value: Amount::from_sat(splice_out_sat),
		script_pubkey: nodes[1].wallet_source.get_change_script().unwrap(),
	}];
	let node_1_funding_contribution =
		initiate_splice_out(&nodes[1], &nodes[0], channel_id, node_1_outputs).unwrap();

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
		splice_ack.funding_contribution_satoshis,
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
	let funding_contribution =
		initiate_splice_out(initiator, acceptor, channel_id, outputs).unwrap();
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
	let contribution = initiate_splice_out(initiator, acceptor, channel_id, outputs).unwrap();
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
	do_abandon_splice_quiescent_action_on_shutdown(true, false);
	do_abandon_splice_quiescent_action_on_shutdown(false, false);
	do_abandon_splice_quiescent_action_on_shutdown(true, true);
	do_abandon_splice_quiescent_action_on_shutdown(false, true);
}

#[cfg(test)]
fn do_abandon_splice_quiescent_action_on_shutdown(local_shutdown: bool, pending_splice: bool) {
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

	// When testing with a prior pending splice, complete splice A first so that
	// `quiescent_action_into_error` filters against `pending_splice.contributed_inputs/outputs`.
	if pending_splice {
		let funding_contribution = do_initiate_splice_in(
			&nodes[0],
			&nodes[1],
			channel_id,
			Amount::from_sat(initial_channel_capacity / 2),
		);
		let (_splice_tx, _new_funding_script) =
			splice_channel(&nodes[0], &nodes[1], channel_id, funding_contribution);
	}

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
	// After a splice, commitment_signed messages are batched across funding scopes.
	nodes[1].node.handle_commitment_signed_batch_test(node_id_0, &update.commitment_signed);
	check_added_monitors(&nodes[1], 1);
	let (revoke_and_ack, _) = get_revoke_commit_msgs(&nodes[1], &node_id_0);

	nodes[0].node.handle_revoke_and_ack(node_id_1, &revoke_and_ack);
	check_added_monitors(&nodes[0], 1);

	// Attempt the splice. `stfu` should not go out yet as the state machine is pending.
	// When there's a prior splice, include a splice-out output with a different script_pubkey
	// so the test can verify selective filtering: the change output (same script_pubkey as
	// the prior splice) is filtered, while the splice-out output (different script_pubkey)
	// survives.
	let splice_in_amount =
		if pending_splice { initial_channel_capacity / 4 } else { initial_channel_capacity / 2 };
	let splice_out_output = if pending_splice {
		let script_pubkey = nodes[1].wallet_source.get_change_script().unwrap();
		Some(TxOut { value: Amount::from_sat(1_000), script_pubkey })
	} else {
		None
	};
	let funding_contribution = if let Some(ref output) = splice_out_output {
		initiate_splice_in_and_out(
			&nodes[0],
			&nodes[1],
			channel_id,
			Amount::from_sat(splice_in_amount),
			vec![output.clone()],
		)
	} else {
		initiate_splice_in(&nodes[0], &nodes[1], channel_id, Amount::from_sat(splice_in_amount))
	};
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

	if pending_splice {
		// With a prior pending splice, contributions are filtered against committed inputs/outputs.
		let events = nodes[0].node.get_and_clear_pending_events();
		assert_eq!(events.len(), 2, "{events:?}");
		match &events[0] {
			Event::SpliceFailed { channel_id: cid, .. } => {
				assert_eq!(*cid, channel_id);
			},
			other => panic!("Expected SpliceFailed, got {:?}", other),
		}
		match &events[1] {
			Event::DiscardFunding {
				funding_info: FundingInfo::Contribution { inputs, outputs },
				..
			} => {
				// The UTXO was filtered: it's still committed to the prior splice.
				assert!(inputs.is_empty(), "Expected empty inputs (filtered), got {:?}", inputs);
				// The change output was filtered (same script_pubkey as the prior splice's
				// change output), but the splice-out output survives (different script_pubkey).
				let expected_outputs: Vec<_> = splice_out_output.into_iter().collect();
				assert_eq!(*outputs, expected_outputs);
			},
			other => panic!("Expected DiscardFunding with Contribution, got {:?}", other),
		}
	} else {
		expect_splice_failed_events(&nodes[0], &channel_id, funding_contribution);
	}
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
	let contribution =
		initiate_splice_out(&nodes[0], &nodes[1], channel_id_0_1, outputs_0_1).unwrap();
	let (splice_tx_0_1, _) = splice_channel(&nodes[0], &nodes[1], channel_id_0_1, contribution);
	for node in &nodes {
		mine_transaction(node, &splice_tx_0_1);
	}

	let outputs_1_2 = vec![TxOut {
		value: Amount::from_sat(1_000),
		script_pubkey: nodes[1].wallet_source.get_change_script().unwrap(),
	}];
	let contribution =
		initiate_splice_out(&nodes[1], &nodes[2], channel_id_1_2, outputs_1_2).unwrap();
	let (splice_tx_1_2, _) = splice_channel(&nodes[1], &nodes[2], channel_id_1_2, contribution);
	for node in &nodes {
		mine_transaction(node, &splice_tx_1_2);
	}

	for node in &nodes {
		connect_blocks(node, ANTI_REORG_DELAY - 2);
	}
	let splice_locked = get_event_msg!(nodes[0], MessageSendEvent::SendSpliceLocked, node_id_1);
	lock_splice(&nodes[0], &nodes[1], &splice_locked, false, &[]);

	for node in &nodes {
		connect_blocks(node, 1);
	}
	let splice_locked = get_event_msg!(nodes[1], MessageSendEvent::SendSpliceLocked, node_id_2);
	lock_splice(&nodes[1], &nodes[2], &splice_locked, false, &[]);

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
	let initiator_contribution =
		initiate_splice_out(&nodes[0], &nodes[1], channel_id, outputs).unwrap();
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
	let initiator_contribution =
		initiate_splice_out(&nodes[0], &nodes[1], channel_id, outputs).unwrap();
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
fn test_splice_waits_for_initial_commitment_monitor_update_before_releasing_tx_signatures() {
	do_splice_waits_for_initial_commitment_monitor_update_before_releasing_tx_signatures(false);
	do_splice_waits_for_initial_commitment_monitor_update_before_releasing_tx_signatures(true);
}

#[cfg(test)]
fn do_splice_waits_for_initial_commitment_monitor_update_before_releasing_tx_signatures(
	complete_update_while_disconnected: bool,
) {
	// Test that if processing the counterparty's initial `commitment_signed` returns
	// `ChannelMonitorUpdateStatus::InProgress`, we do not release our `tx_signatures` when their
	// `tx_signatures` is received. We should only release ours once the monitor update completes.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_id_0 = nodes[0].node.get_our_node_id();
	let node_id_1 = nodes[1].node.get_our_node_id();

	let (_, _, channel_id, _) =
		create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100_000, 0);

	let outputs = vec![TxOut {
		value: Amount::from_sat(1_000),
		script_pubkey: nodes[0].wallet_source.get_change_script().unwrap(),
	}];
	let initiator_contribution =
		initiate_splice_out(&nodes[0], &nodes[1], channel_id, outputs).unwrap();
	negotiate_splice_tx(&nodes[0], &nodes[1], channel_id, initiator_contribution);

	let signing_event = get_event!(nodes[0], Event::FundingTransactionReadyForSigning);
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

	let initiator_commit_sig = get_htlc_update_msgs(&nodes[0], &node_id_1);
	nodes[1].node.handle_commitment_signed(node_id_0, &initiator_commit_sig.commitment_signed[0]);
	check_added_monitors(&nodes[1], 1);

	// Leave the monitor update for node 0's processing of the initial `commitment_signed` pending.
	chanmon_cfgs[0].persister.set_update_ret(ChannelMonitorUpdateStatus::InProgress);

	let msg_events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(msg_events.len(), 2, "{msg_events:?}");
	let counterparty_commit_sig =
		if let MessageSendEvent::UpdateHTLCs { ref updates, .. } = &msg_events[0] {
			updates.commitment_signed[0].clone()
		} else {
			panic!("Expected UpdateHTLCs message");
		};
	let counterparty_tx_signatures =
		if let MessageSendEvent::SendTxSignatures { ref msg, .. } = &msg_events[1] {
			msg.clone()
		} else {
			panic!("Expected SendTxSignatures message");
		};

	nodes[0].node.handle_commitment_signed(node_id_1, &counterparty_commit_sig);
	check_added_monitors(&nodes[0], 1);
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());

	nodes[0].node.handle_tx_signatures(node_id_1, &counterparty_tx_signatures);

	// We should not send our `tx_signatures` while the monitor update is still in progress.
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());

	// Reestablishing before the monitor update completes should still not release `tx_signatures`.
	nodes[0].node.peer_disconnected(node_id_1);
	nodes[1].node.peer_disconnected(node_id_0);
	let mut reconnect_args = ReconnectArgs::new(&nodes[0], &nodes[1]);
	reconnect_args.send_announcement_sigs = (true, true);
	reconnect_nodes(reconnect_args);
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	if complete_update_while_disconnected {
		nodes[0].node.peer_disconnected(node_id_1);
		nodes[1].node.peer_disconnected(node_id_0);
	}

	nodes[0].chain_monitor.complete_sole_pending_chan_update(&channel_id);
	chanmon_cfgs[0].persister.set_update_ret(ChannelMonitorUpdateStatus::Completed);

	if !complete_update_while_disconnected {
		let initiator_tx_signatures =
			get_event_msg!(nodes[0], MessageSendEvent::SendTxSignatures, node_id_1);
		nodes[1].node.handle_tx_signatures(node_id_0, &initiator_tx_signatures);
	}

	expect_splice_pending_event(&nodes[0], &node_id_1);
	if !complete_update_while_disconnected {
		expect_splice_pending_event(&nodes[1], &node_id_0);
	}
}

#[test]
fn test_splice_balance_falls_below_reserve() {
	// Test that we're able to proceed with a splice where the acceptor does not contribute
	// anything, but the initiator does, resulting in an increased channel reserve that the
	// counterparty does not meet but is still valid.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let mut config = test_default_channel_config();
	config.channel_handshake_config.announced_channel_max_inbound_htlc_value_in_flight_percentage =
		100;
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
	let funding_template = nodes[0].node.splice_channel(&channel_id, &node_id_1).unwrap();
	let wallet = WalletSync::new(Arc::clone(&nodes[0].wallet_source), nodes[0].logger);
	let funding_contribution =
		funding_template.splice_in_sync(splice_in_amount, feerate, FeeRate::MAX, &wallet).unwrap();

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
	let funding_template = nodes[0].node.splice_channel(&channel_id, &node_id_1).unwrap();
	let wallet = WalletSync::new(Arc::clone(&nodes[0].wallet_source), nodes[0].logger);
	let funding_contribution =
		funding_template.splice_in_sync(splice_in_amount, feerate, FeeRate::MAX, &wallet).unwrap();

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
	let funding_template = nodes[0].node.splice_channel(&channel_id, &node_id_1).unwrap();
	let wallet = WalletSync::new(Arc::clone(&nodes[0].wallet_source), nodes[0].logger);
	let first_contribution = funding_template
		.splice_in_and_out_sync(
			splice_in_amount,
			vec![first_splice_out.clone()],
			feerate,
			FeeRate::MAX,
			&wallet,
		)
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

	let funding_template = nodes[0].node.splice_channel(&channel_id, &node_id_1).unwrap();
	let wallet = WalletSync::new(Arc::clone(&nodes[0].wallet_source), nodes[0].logger);
	let second_contribution = funding_template
		.splice_in_and_out_sync(
			splice_in_amount,
			vec![second_splice_out.clone()],
			feerate,
			FeeRate::MAX,
			&wallet,
		)
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
	let funding_template = nodes[0].node.splice_channel(&channel_id, &node_id_1).unwrap();
	let wallet = WalletSync::new(Arc::clone(&nodes[0].wallet_source), nodes[0].logger);
	let contribution =
		funding_template.splice_in_sync(splice_in_amount, feerate, FeeRate::MAX, &wallet).unwrap();

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
	let funding_template = nodes[0].node.splice_channel(&channel_id, &node_id_1).unwrap();
	let wallet = WalletSync::new(Arc::clone(&nodes[0].wallet_source), nodes[0].logger);
	let first_contribution =
		funding_template.splice_in_sync(splice_in_amount, feerate, FeeRate::MAX, &wallet).unwrap();

	// Build second contribution with different UTXOs so inputs/outputs don't overlap
	nodes[0].wallet_source.clear_utxos();
	provide_utxo_reserves(&nodes, 1, splice_in_amount * 3);

	let funding_template = nodes[0].node.splice_channel(&channel_id, &node_id_1).unwrap();
	let wallet = WalletSync::new(Arc::clone(&nodes[0].wallet_source), nodes[0].logger);
	let second_contribution =
		funding_template.splice_in_sync(splice_in_amount, feerate, FeeRate::MAX, &wallet).unwrap();

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
	let funding_template = nodes[0].node.splice_channel(&channel_id, &node_id_1).unwrap();
	let wallet = WalletSync::new(Arc::clone(&nodes[0].wallet_source), nodes[0].logger);
	let funding_contribution =
		funding_template.splice_in_sync(splice_in_amount, feerate, FeeRate::MAX, &wallet).unwrap();

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
	let funding_template = nodes[0].node.splice_channel(&funded_channel_id, &node_id_1).unwrap();
	let wallet = WalletSync::new(Arc::clone(&nodes[0].wallet_source), nodes[0].logger);
	let funding_contribution =
		funding_template.splice_in_sync(splice_in_amount, feerate, FeeRate::MAX, &wallet).unwrap();

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

#[test]
fn test_splice_pending_htlcs() {
	let mut config = test_default_channel_config();
	config.channel_handshake_config.announced_channel_max_inbound_htlc_value_in_flight_percentage =
		100;
	config.channel_handshake_config.negotiate_anchors_zero_fee_htlc_tx = false;
	config.channel_handshake_config.negotiate_anchor_zero_fee_commitments = false;
	do_test_splice_pending_htlcs(config);

	let mut config = test_default_channel_config();
	config.channel_handshake_config.announced_channel_max_inbound_htlc_value_in_flight_percentage =
		100;
	config.channel_handshake_config.negotiate_anchors_zero_fee_htlc_tx = true;
	config.channel_handshake_config.negotiate_anchor_zero_fee_commitments = false;
	do_test_splice_pending_htlcs(config);

	let mut config = test_default_channel_config();
	config.channel_handshake_config.announced_channel_max_inbound_htlc_value_in_flight_percentage =
		100;
	config.channel_handshake_config.negotiate_anchors_zero_fee_htlc_tx = false;
	config.channel_handshake_config.negotiate_anchor_zero_fee_commitments = true;
	do_test_splice_pending_htlcs(config);
}

#[cfg(test)]
fn do_test_splice_pending_htlcs(config: UserConfig) {
	// Test balance checks for inbound and outbound splice-outs while there are pending HTLCs in the channel.
	// The channel fundee requests unaffordable splice-outs in the first section, while the channel funder does so
	// in the second section.
	let anchors_features = ChannelTypeFeatures::anchors_zero_htlc_fee_and_dependencies();
	let initial_channel_value = Amount::from_sat(100_000);
	let push_amount = Amount::from_sat(10_000);

	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[Some(config.clone()), Some(config)]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_id_0 = nodes[0].node.get_our_node_id();
	let node_id_1 = nodes[1].node.get_our_node_id();

	let (_, _, channel_id, _) = create_announced_chan_between_nodes_with_value(
		&nodes,
		0,
		1,
		initial_channel_value.to_sat(),
		push_amount.to_sat() * 1000,
	);

	let details = &nodes[0].node.list_channels()[0];
	let channel_type = details.channel_type.clone().unwrap();
	let feerate_per_kw = details.feerate_sat_per_1000_weight.unwrap();
	let spike_multiple = if channel_type == ChannelTypeFeatures::only_static_remote_key() {
		FEE_SPIKE_BUFFER_FEE_INCREASE_MULTIPLE as u32
	} else {
		1
	};
	let spiked_feerate = spike_multiple * feerate_per_kw;

	// Place some pending HTLCs in the channel, in both directions.
	let (preimage_1_to_0_a, _hash_1_to_0, ..) = route_payment(&nodes[1], &[&nodes[0]], 2_000_000);
	let (preimage_1_to_0_b, _hash_1_to_0, ..) = route_payment(&nodes[1], &[&nodes[0]], 2_000_000);
	let (preimage_1_to_0_c, _hash_1_to_0, ..) = route_payment(&nodes[1], &[&nodes[0]], 2_000_000);
	let (preimage_0_to_1_a, _hash_0_to_1, ..) = route_payment(&nodes[0], &[&nodes[1]], 40_000_000);
	let (preimage_0_to_1_b, _hash_0_to_1, ..) = route_payment(&nodes[0], &[&nodes[1]], 40_000_000);

	let splice_out_dance = |initiator: usize,
	                        acceptor: usize,
	                        // We will setup the channel such that splicing out an additional satoshi
	                        // overdraws the initiator's balance.
	                        splice_out: Amount,
	                        splice_out_incl_fees: Amount,
	                        post_splice_reserve: Amount|
	 -> FundingContribution {
		let initiator = &nodes[initiator];
		let acceptor = &nodes[acceptor];
		let node_id_initiator = initiator.node.get_our_node_id();
		let node_id_acceptor = acceptor.node.get_our_node_id();

		// 1) Check that splicing out an additional satoshi fails validation on the sender's side.

		let script_pubkey = initiator.wallet_source.get_change_script().unwrap();
		let outputs = vec![TxOut { value: splice_out + Amount::ONE_SAT, script_pubkey }];
		let error = initiate_splice_out(initiator, acceptor, channel_id, outputs).unwrap_err();
		let cannot_accept_contribution =
			format!("Channel {} cannot accept funding contribution", channel_id);
		assert_eq!(error, APIError::APIMisuseError { err: cannot_accept_contribution });
		let cannot_be_funded = format!(
			"Channel {} cannot be funded: Channel {} cannot be spliced out; our post-splice channel balance {} is smaller than their selected v2 reserve {}",
			channel_id, channel_id, post_splice_reserve - Amount::ONE_SAT, post_splice_reserve
		);
		initiator.logger.assert_log("lightning::ln::channel", cannot_be_funded, 1);

		// 2) Check that splicing out with the additional satoshi removed passes validation on the sender's side.

		let script_pubkey = initiator.wallet_source.get_change_script().unwrap();
		let outputs = vec![TxOut { value: splice_out, script_pubkey }];
		let contribution =
			initiate_splice_out(initiator, acceptor, channel_id, outputs.clone()).unwrap();
		assert_eq!(contribution.net_value(), -splice_out_incl_fees.to_signed().unwrap());

		let stfu_init = get_event_msg!(initiator, MessageSendEvent::SendStfu, node_id_acceptor);
		acceptor.node.handle_stfu(node_id_initiator, &stfu_init);
		let stfu_ack = get_event_msg!(acceptor, MessageSendEvent::SendStfu, node_id_initiator);
		initiator.node.handle_stfu(node_id_acceptor, &stfu_ack);

		// 3) Overwrite the splice-out message to add an additional satoshi to the splice-out, and check that it fails
		// validation on the receiver's side.

		let mut splice_init =
			get_event_msg!(initiator, MessageSendEvent::SendSpliceInit, node_id_acceptor);
		splice_init.funding_contribution_satoshis -= 1;
		acceptor.node.handle_splice_init(node_id_initiator, &splice_init);

		let msg = get_warning_msg(acceptor, &node_id_initiator);
		assert_eq!(msg.channel_id, channel_id);
		let cannot_be_spliced_out = format!(
			"Channel {} cannot be spliced out; their post-splice channel balance {} is smaller than our selected v2 reserve {}",
			channel_id, post_splice_reserve - Amount::ONE_SAT, post_splice_reserve
		);
		assert_eq!(msg.data, cannot_be_spliced_out);

		acceptor.node.peer_disconnected(node_id_initiator);
		initiator.node.peer_disconnected(node_id_acceptor);

		let reconnect_args = ReconnectArgs::new(initiator, acceptor);
		reconnect_nodes(reconnect_args);

		expect_splice_failed_events(initiator, &channel_id, contribution);

		// 4) Try again with the additional satoshi removed from the splice-out message, and check that it passes
		// validation on the receiver's side.

		let contribution = initiate_splice_out(initiator, acceptor, channel_id, outputs).unwrap();
		assert_eq!(contribution.net_value(), -splice_out_incl_fees.to_signed().unwrap());

		contribution
	};

	let (preimage_1_to_0_d, node_1_splice_out_incl_fees) = {
		// 0) Set the channel up such that if node 1 splices out an additional satoshi over the `splice_out`
		// value, it overdraws its reserve.

		let debit_htlcs = Amount::from_sat(2_000 * 3);
		let balance = push_amount - debit_htlcs;
		let estimated_fees = Amount::from_sat(183);
		let splice_out = Amount::from_sat(1000);
		let splice_out_incl_fees = splice_out + estimated_fees;
		let post_splice_reserve = (initial_channel_value - splice_out_incl_fees) / 100;
		let pre_splice_balance = post_splice_reserve + splice_out_incl_fees;
		let amount_msat = (balance - pre_splice_balance).to_sat() * 1000;
		let (preimage_1_to_0_d, ..) = route_payment(&nodes[1], &[&nodes[0]], amount_msat);

		let contribution =
			splice_out_dance(1, 0, splice_out, splice_out_incl_fees, post_splice_reserve);
		let _new_funding_script = complete_splice_handshake(&nodes[1], &nodes[0]);

		// Don't complete the splice, leave node 1's balance untouched such that its
		// `next_outbound_htlc_limit_msat` is exactly equal to its pre-splice balance - its pre-splice reserve.
		nodes[0].node.peer_disconnected(node_id_1);
		nodes[1].node.peer_disconnected(node_id_0);
		let reconnect_args = ReconnectArgs::new(&nodes[0], &nodes[1]);
		reconnect_nodes(reconnect_args);
		expect_splice_failed_events(&nodes[1], &channel_id, contribution);
		let details = &nodes[1].node.list_channels()[0];
		let expected_outbound_htlc_max =
			(pre_splice_balance.to_sat() - details.unspendable_punishment_reserve.unwrap()) * 1000;
		assert_eq!(details.next_outbound_htlc_limit_msat, expected_outbound_htlc_max);

		// At the end of the show, we'll claim the HTLC we used to setup the channel's balances above so we
		// return its preimage.
		// We'll also send a HTLC with the exact remaining amount available in the channel, which will match
		// the balance we were about to splice out here.
		(preimage_1_to_0_d, splice_out_incl_fees)
	};

	let preimage_0_to_1_d = {
		// 0) Set the channel up such that if node 0 splices out an additional satoshi over the `splice_out`
		// value, it overdraws its reserve.

		let debit_htlcs = Amount::from_sat(40_000 * 2);
		let debit_anchors =
			if channel_type == anchors_features { Amount::from_sat(330 * 2) } else { Amount::ZERO };
		let balance = initial_channel_value - push_amount - debit_htlcs - debit_anchors;
		let estimated_fees = Amount::from_sat(183);
		let splice_out = Amount::from_sat(1000);
		let splice_out_incl_fees = splice_out + estimated_fees;
		let post_splice_reserve = (initial_channel_value - splice_out_incl_fees) / 100;
		// The 6 HTLCs we sent previously, the HTLC we send just below, and the fee spike buffer HTLC.
		let htlc_count = 6 + 1 + 1;
		let commit_tx_fee = Amount::from_sat(chan_utils::commit_tx_fee_sat(
			spiked_feerate,
			htlc_count,
			&channel_type,
		));
		let pre_splice_balance = post_splice_reserve + commit_tx_fee + splice_out_incl_fees;
		let amount_msat = (balance - pre_splice_balance).to_sat() * 1000;
		let (preimage_0_to_1_d, ..) = route_payment(&nodes[0], &[&nodes[1]], amount_msat);

		// Now actually follow through on the splice.
		let contribution =
			splice_out_dance(0, 1, splice_out, splice_out_incl_fees, post_splice_reserve);
		let (splice_tx, _) = splice_channel(&nodes[0], &nodes[1], channel_id, contribution);

		// The funder's balance has exactly its reserve plus the fee for an inbound non-dust HTLC,
		// so its `next_outbound_htlc_limit_msat` is exactly 0. We'll send that last inbound non-dust HTLC
		// across further below to close the circle.
		assert_eq!(nodes[0].node.list_channels()[0].next_outbound_htlc_limit_msat, 0);

		// Confirm and lock the splice.
		mine_transaction(&nodes[0], &splice_tx);
		mine_transaction(&nodes[1], &splice_tx);
		lock_splice_after_blocks(&nodes[0], &nodes[1], ANTI_REORG_DELAY - 1);

		// Node 0 has now spliced the channel, so even though node 1 has not done anything, the max-size HTLC node 1
		// can send is now its pre-splice balance - its post-splice reserve. This matches the balance it was about to
		// splice out above, but never did.
		let outbound_htlc_max = nodes[1].node.list_channels()[0].next_outbound_htlc_limit_msat;
		assert_eq!(outbound_htlc_max, node_1_splice_out_incl_fees.to_sat() * 1000);

		// Send the last max-size non-dust HTLC in the channel.
		let _ = send_payment(&nodes[1], &[&nodes[0]], node_1_splice_out_incl_fees.to_sat() * 1000);

		// Node 1 is exactly at the V2 channel reserve, given that we just sent node 1's entire available balance
		// across.
		assert_eq!(nodes[1].node.list_channels()[0].next_outbound_htlc_limit_msat, 0);

		// Node 0's balance is its previous balance (ie the previous reserved fee) + the HTLC it just claimed
		// - the new reserved fee (the channel reserves cancel out).
		let previous_balance = chan_utils::commit_tx_fee_sat(spiked_feerate, 8, &channel_type);
		let claimed_htlc = node_1_splice_out_incl_fees.to_sat();
		let commit_tx_fee = chan_utils::commit_tx_fee_sat(spiked_feerate, 9, &channel_type);
		let new_balance = previous_balance + claimed_htlc - commit_tx_fee;
		let outbound_htlc_max = nodes[0].node.list_channels()[0].next_outbound_htlc_limit_msat;
		assert_eq!(outbound_htlc_max, new_balance * 1000);

		// Return the preimage of the HTLC used to setup the balances so we can claim the HTLC below.
		preimage_0_to_1_d
	};

	// Clean up the channel.
	claim_payment(&nodes[1], &[&nodes[0]], preimage_1_to_0_a);
	claim_payment(&nodes[1], &[&nodes[0]], preimage_1_to_0_b);
	claim_payment(&nodes[1], &[&nodes[0]], preimage_1_to_0_c);

	claim_payment(&nodes[1], &[&nodes[0]], preimage_1_to_0_d);

	claim_payment(&nodes[0], &[&nodes[1]], preimage_0_to_1_a);
	claim_payment(&nodes[0], &[&nodes[1]], preimage_0_to_1_b);

	claim_payment(&nodes[0], &[&nodes[1]], preimage_0_to_1_d);

	// Check that the channel is still operational.
	let _ = send_payment(&nodes[0], &[&nodes[1]], 2_000 * 1000);
	let _ = send_payment(&nodes[1], &[&nodes[0]], 2_000 * 1000);
}

// Returns after both sides are quiescent (no splice_init is generated since we use DoNothing).
pub fn reenter_quiescence<'a, 'b, 'c>(
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
fn test_splice_acceptor_disconnect_emits_events() {
	// When both nodes contribute to a splice and the negotiation fails due to disconnect,
	// both the initiator and acceptor should receive SpliceFailed + DiscardFunding events
	// so each can reclaim their UTXOs.
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
	provide_utxo_reserves(&nodes, 1, added_value * 2);

	// Both nodes initiate splice-in (tiebreak: node 0 wins).
	let node_0_funding_contribution =
		do_initiate_splice_in(&nodes[0], &nodes[1], channel_id, added_value);
	let _node_1_funding_contribution =
		do_initiate_splice_in(&nodes[1], &nodes[0], channel_id, added_value);

	let stfu_0 = get_event_msg!(nodes[0], MessageSendEvent::SendStfu, node_id_1);
	let stfu_1 = get_event_msg!(nodes[1], MessageSendEvent::SendStfu, node_id_0);
	nodes[1].node.handle_stfu(node_id_0, &stfu_0);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	nodes[0].node.handle_stfu(node_id_1, &stfu_1);

	let splice_init = get_event_msg!(nodes[0], MessageSendEvent::SendSpliceInit, node_id_1);
	nodes[1].node.handle_splice_init(node_id_0, &splice_init);
	let splice_ack = get_event_msg!(nodes[1], MessageSendEvent::SendSpliceAck, node_id_0);
	assert_ne!(splice_ack.funding_contribution_satoshis, 0);
	nodes[0].node.handle_splice_ack(node_id_1, &splice_ack);

	// Disconnect mid-interactive-TX negotiation.
	nodes[0].node.peer_disconnected(node_id_1);
	nodes[1].node.peer_disconnected(node_id_0);

	// The initiator should get SpliceFailed + DiscardFunding.
	expect_splice_failed_events(&nodes[0], &channel_id, node_0_funding_contribution);

	// The acceptor should also get SpliceFailed + DiscardFunding with its contributions
	// so it can reclaim its UTXOs. The contribution is feerate-adjusted by handle_splice_init,
	// so we check for non-empty inputs/outputs rather than exact values.
	let events = nodes[1].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 2, "{events:?}");
	match &events[0] {
		Event::SpliceFailed { channel_id: cid, .. } => assert_eq!(*cid, channel_id),
		other => panic!("Expected SpliceFailed, got {:?}", other),
	}
	match &events[1] {
		Event::DiscardFunding {
			funding_info: FundingInfo::Contribution { inputs, outputs },
			..
		} => {
			assert!(!inputs.is_empty(), "Expected acceptor inputs, got empty");
			assert!(!outputs.is_empty(), "Expected acceptor outputs, got empty");
		},
		other => panic!("Expected DiscardFunding with Contribution, got {:?}", other),
	}

	// Reconnect and verify the channel is still operational.
	let mut reconnect_args = ReconnectArgs::new(&nodes[0], &nodes[1]);
	reconnect_args.send_channel_ready = (true, true);
	reconnect_args.send_announcement_sigs = (true, true);
	reconnect_nodes(reconnect_args);
}

#[test]
fn test_splice_rbf_acceptor_basic() {
	// Test the full end-to-end flow for RBF of a pending splice transaction.
	// Complete a splice-in, then use splice_channel API to initiate an RBF attempt
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

	let (first_splice_tx, new_funding_script) =
		splice_channel(&nodes[0], &nodes[1], channel_id, funding_contribution);

	// Step 2: Provide more UTXO reserves for the RBF attempt.
	provide_utxo_reserves(&nodes, 2, added_value * 2);

	// Step 3: Use splice_channel API to initiate the RBF.
	// Original feerate was FEERATE_FLOOR_SATS_PER_KW (253). 253 + 25 = 278.
	let rbf_feerate_sat_per_kwu = FEERATE_FLOOR_SATS_PER_KW as u64 + 25;
	let rbf_feerate = FeeRate::from_sat_per_kwu(rbf_feerate_sat_per_kwu);
	let funding_contribution =
		do_initiate_rbf_splice_in(&nodes[0], &nodes[1], channel_id, added_value, rbf_feerate);

	// Steps 4-8: STFU exchange → tx_init_rbf → tx_ack_rbf.
	complete_rbf_handshake(&nodes[0], &nodes[1]);

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

	// Step 11: Mine, lock, and verify DiscardFunding for the replaced splice candidate.
	lock_rbf_splice_after_blocks(
		&nodes[0],
		&nodes[1],
		&rbf_tx,
		ANTI_REORG_DELAY - 1,
		&[first_splice_tx.compute_txid()],
	);
}

#[test]
fn test_splice_rbf_at_high_feerate() {
	// Test that min_rbf_feerate satisfies the spec's 25/24 rule at high feerates (above 600
	// sat/kwu, where a flat +25 increment alone would be insufficient).
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

	// Step 1: Complete a splice-in at floor feerate.
	let funding_contribution = do_initiate_splice_in(&nodes[0], &nodes[1], channel_id, added_value);
	let (_first_splice_tx, new_funding_script) =
		splice_channel(&nodes[0], &nodes[1], channel_id, funding_contribution);

	// Step 2: RBF to a high feerate (1000 sat/kwu, well above the 600 crossover point).
	provide_utxo_reserves(&nodes, 2, added_value * 2);
	let high_feerate = FeeRate::from_sat_per_kwu(1000);
	let contribution =
		do_initiate_rbf_splice_in(&nodes[0], &nodes[1], channel_id, added_value, high_feerate);
	complete_rbf_handshake(&nodes[0], &nodes[1]);
	complete_interactive_funding_negotiation(
		&nodes[0],
		&nodes[1],
		channel_id,
		contribution,
		new_funding_script.clone(),
	);
	let (_, splice_locked) = sign_interactive_funding_tx(&nodes[0], &nodes[1], false);
	assert!(splice_locked.is_none());
	expect_splice_pending_event(&nodes[0], &node_id_1);
	expect_splice_pending_event(&nodes[1], &node_id_0);

	// Step 3: RBF again using the template's min_rbf_feerate. The counterparty must accept it.
	provide_utxo_reserves(&nodes, 2, added_value * 2);
	let rbf_feerate = {
		let funding_template = nodes[0].node.splice_channel(&channel_id, &node_id_1).unwrap();
		funding_template.min_rbf_feerate().unwrap()
	};
	let contribution =
		do_initiate_rbf_splice_in(&nodes[0], &nodes[1], channel_id, added_value, rbf_feerate);
	complete_rbf_handshake(&nodes[0], &nodes[1]);
	complete_interactive_funding_negotiation(
		&nodes[0],
		&nodes[1],
		channel_id,
		contribution,
		new_funding_script,
	);
	let (_, splice_locked) = sign_interactive_funding_tx(&nodes[0], &nodes[1], false);
	assert!(splice_locked.is_none());
	expect_splice_pending_event(&nodes[0], &node_id_1);
	expect_splice_pending_event(&nodes[1], &node_id_0);
}

#[test]
fn test_splice_rbf_insufficient_feerate() {
	// Test that splice_in_sync rejects a feerate that doesn't satisfy the +25 sat/kwu rule, and that the
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

	// Initiator-side: splice_in_sync rejects an insufficient feerate.
	// Original feerate was 253. Using exactly 253 should fail since 253 * 24 < 253 * 25.
	let same_feerate = FeeRate::from_sat_per_kwu(FEERATE_FLOOR_SATS_PER_KW as u64);
	let funding_template = nodes[0].node.splice_channel(&channel_id, &node_id_1).unwrap();

	// Verify that the template exposes the RBF floor.
	let min_rbf_feerate = funding_template.min_rbf_feerate().unwrap();
	let expected_floor = FeeRate::from_sat_per_kwu(FEERATE_FLOOR_SATS_PER_KW as u64 + 25);
	assert_eq!(min_rbf_feerate, expected_floor);

	let wallet = WalletSync::new(Arc::clone(&nodes[0].wallet_source), nodes[0].logger);
	assert!(funding_template
		.splice_in_sync(added_value, same_feerate, FeeRate::MAX, &wallet)
		.is_err());

	// Verify that the floor feerate succeeds.
	let funding_template = nodes[0].node.splice_channel(&channel_id, &node_id_1).unwrap();
	assert!(funding_template
		.splice_in_sync(added_value, min_rbf_feerate, FeeRate::MAX, &wallet)
		.is_ok());

	// Acceptor-side: tx_init_rbf with an insufficient feerate is also rejected.
	reenter_quiescence(&nodes[0], &nodes[1], &channel_id);

	let tx_init_rbf = msgs::TxInitRbf {
		channel_id,
		locktime: 0,
		feerate_sat_per_1000_weight: FEERATE_FLOOR_SATS_PER_KW,
		funding_output_contribution: Some(added_value.to_sat() as i64),
	};

	nodes[1].node.handle_tx_init_rbf(node_id_0, &tx_init_rbf);

	let tx_abort = get_event_msg!(nodes[1], MessageSendEvent::SendTxAbort, node_id_0);
	assert_eq!(tx_abort.channel_id, channel_id);

	// Acceptor-side: a counterparty feerate that satisfies the spec's 25/24 rule (264) is
	// accepted, even though our own RBF floor (+25 sat/kwu = 278) is higher.
	// After tx_abort the channel remains quiescent, so no need to re-enter quiescence.
	nodes[0].node.handle_tx_abort(node_id_1, &tx_abort);

	let rbf_feerate_25_24 = ((FEERATE_FLOOR_SATS_PER_KW as u64) * 25).div_ceil(24) as u32;
	let tx_init_rbf = msgs::TxInitRbf {
		channel_id,
		locktime: 0,
		feerate_sat_per_1000_weight: rbf_feerate_25_24,
		funding_output_contribution: Some(added_value.to_sat() as i64),
	};

	nodes[1].node.handle_tx_init_rbf(node_id_0, &tx_init_rbf);
	let _tx_ack_rbf = get_event_msg!(nodes[1], MessageSendEvent::SendTxAckRbf, node_id_0);
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

	let tx_abort = get_event_msg!(nodes[1], MessageSendEvent::SendTxAbort, node_id_0);
	assert_eq!(tx_abort.channel_id, channel_id);

	// Clear the initiator's pending interactive TX messages from the incomplete splice handshake.
	nodes[0].node.get_and_clear_pending_msg_events();
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
fn test_splice_zeroconf_no_rbf_feerate() {
	// Test that splice_channel returns a FundingTemplate with min_rbf_feerate = None for a
	// zero-conf channel, even when a splice negotiation is in progress.
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

	let added_value = Amount::from_sat(50_000);
	provide_utxo_reserves(&nodes, 1, added_value * 2);

	// Initiate a splice (node 0) and complete the handshake so a funding negotiation is in
	// progress.
	let _funding_contribution =
		do_initiate_splice_in(&nodes[0], &nodes[1], channel_id, added_value);
	let _new_funding_script = complete_splice_handshake(&nodes[0], &nodes[1]);

	// The acceptor (node 1) calling splice_channel should return no RBF feerate since
	// zero-conf channels cannot RBF.
	let funding_template = nodes[1].node.splice_channel(&channel_id, &node_id_0).unwrap();
	assert!(funding_template.min_rbf_feerate().is_none());

	// Drain pending interactive tx messages from the splice handshake.
	nodes[0].node.get_and_clear_pending_msg_events();
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
						data: format!("Channel {} has option_zeroconf, cannot RBF", channel_id,),
					},
				}
			);
		},
		_ => panic!("Expected HandleError, got {:?}", msg_events[0]),
	}
}

#[test]
fn test_splice_rbf_not_quiescence_initiator() {
	// Test that tx_init_rbf from the non-quiescence-initiator is rejected because the
	// quiescence initiator's RBF flow has already set funding_negotiation to AwaitingAck.
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

	// Provide more UTXO reserves for the RBF attempt.
	provide_utxo_reserves(&nodes, 2, added_value * 2);

	// Initiate RBF from node 0 (quiescence initiator).
	let rbf_feerate_sat_per_kwu = FEERATE_FLOOR_SATS_PER_KW as u64 + 25;
	let rbf_feerate = FeeRate::from_sat_per_kwu(rbf_feerate_sat_per_kwu);
	let _funding_contribution =
		do_initiate_rbf_splice_in(&nodes[0], &nodes[1], channel_id, added_value, rbf_feerate);

	// STFU exchange: node 0 initiates quiescence.
	let stfu_init = get_event_msg!(nodes[0], MessageSendEvent::SendStfu, node_id_1);
	nodes[1].node.handle_stfu(node_id_0, &stfu_init);
	let stfu_ack = get_event_msg!(nodes[1], MessageSendEvent::SendStfu, node_id_0);
	nodes[0].node.handle_stfu(node_id_1, &stfu_ack);

	// Node 0 sends tx_init_rbf as the quiescence initiator — grab and discard.
	let _tx_init_rbf = get_event_msg!(nodes[0], MessageSendEvent::SendTxInitRbf, node_id_1);

	// Now craft a competing tx_init_rbf from node 1 (the non-initiator).
	let tx_init_rbf = msgs::TxInitRbf {
		channel_id,
		locktime: 0,
		feerate_sat_per_1000_weight: 500,
		funding_output_contribution: Some(added_value.to_sat() as i64),
	};

	nodes[0].node.handle_tx_init_rbf(node_id_1, &tx_init_rbf);

	let tx_abort = get_event_msg!(nodes[0], MessageSendEvent::SendTxAbort, node_id_1);
	assert_eq!(tx_abort.channel_id, channel_id);
}

#[test]
fn test_splice_rbf_both_contribute_tiebreak() {
	let min_rbf_feerate = FEERATE_FLOOR_SATS_PER_KW as u64 + 25;
	let feerate = FeeRate::from_sat_per_kwu(min_rbf_feerate);
	let added_value = Amount::from_sat(50_000);
	do_test_splice_rbf_tiebreak(feerate, feerate, added_value, true);
}

#[test]
fn test_splice_rbf_tiebreak_higher_feerate() {
	// Node 0 (winner) uses a higher feerate than node 1 (loser). Node 1's change output is
	// adjusted (reduced) to accommodate the higher feerate. Negotiation succeeds.
	let min_rbf_feerate = FEERATE_FLOOR_SATS_PER_KW as u64 + 25;
	do_test_splice_rbf_tiebreak(
		FeeRate::from_sat_per_kwu(min_rbf_feerate * 3),
		FeeRate::from_sat_per_kwu(min_rbf_feerate),
		Amount::from_sat(50_000),
		true,
	);
}

#[test]
fn test_splice_rbf_tiebreak_lower_feerate() {
	// Node 0 (winner) uses a lower feerate than node 1 (loser). Since the initiator's feerate
	// is below node 1's minimum, node 1 proceeds without contribution and will retry via a new
	// splice at its preferred feerate after the RBF locks.
	let min_rbf_feerate = FEERATE_FLOOR_SATS_PER_KW as u64 + 25;
	do_test_splice_rbf_tiebreak(
		FeeRate::from_sat_per_kwu(min_rbf_feerate),
		FeeRate::from_sat_per_kwu(min_rbf_feerate * 3),
		Amount::from_sat(50_000),
		false,
	);
}

#[test]
fn test_splice_rbf_tiebreak_feerate_too_high() {
	// Node 0 (winner) uses a feerate high enough that node 1's (loser) contribution cannot
	// cover the fees. Node 1 proceeds without its contribution (QuiescentAction is preserved
	// for a future splice). The RBF completes with only node 0's inputs/outputs.
	let min_rbf_feerate = FEERATE_FLOOR_SATS_PER_KW as u64 + 25;
	do_test_splice_rbf_tiebreak(
		FeeRate::from_sat_per_kwu(20_000),
		FeeRate::from_sat_per_kwu(min_rbf_feerate),
		Amount::from_sat(95_000),
		false,
	);
}

/// Runs the tie-breaker test with the given per-node feerates and node 1's splice value.
///
/// Both nodes call `splice_channel` + `funding_contributed`, both send STFU, and node 0 (the outbound
/// channel funder) wins the quiescence tie-break. The loser (node 1) becomes the acceptor. Whether
/// node 1 contributes to the RBF transaction depends on the feerate and budget constraints.
///
/// `expect_acceptor_contributes` asserts the expected outcome: whether node 1's `tx_ack_rbf`
/// includes a funding output contribution.
pub fn do_test_splice_rbf_tiebreak(
	rbf_feerate_0: FeeRate, rbf_feerate_1: FeeRate, node_1_splice_value: Amount,
	expect_acceptor_contributes: bool,
) {
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
	let (first_splice_tx, new_funding_script) =
		splice_channel(&nodes[0], &nodes[1], channel_id, funding_contribution);

	// Provide more UTXOs for both nodes' RBF attempts.
	provide_utxo_reserves(&nodes, 2, added_value * 2);

	// Node 0 calls splice_channel + funding_contributed.
	let node_0_funding_contribution =
		do_initiate_rbf_splice_in(&nodes[0], &nodes[1], channel_id, added_value, rbf_feerate_0);

	// Node 1 calls splice_channel + funding_contributed.
	let node_1_funding_contribution = do_initiate_rbf_splice_in(
		&nodes[1],
		&nodes[0],
		channel_id,
		node_1_splice_value,
		rbf_feerate_1,
	);

	// Both nodes sent STFU (both have awaiting_quiescence set).
	let stfu_0 = get_event_msg!(nodes[0], MessageSendEvent::SendStfu, node_id_1);
	assert!(stfu_0.initiator);
	let stfu_1 = get_event_msg!(nodes[1], MessageSendEvent::SendStfu, node_id_0);
	assert!(stfu_1.initiator);

	// Exchange STFUs. Node 0 is the outbound channel funder and wins the tie-break.
	// Node 1 handles node 0's STFU first — it already sent its own STFU (local_stfu_sent is set),
	// so this goes through the tie-break path. Node 1 loses (is_outbound = false) and becomes the
	// acceptor. Its quiescent_action is preserved for the tx_init_rbf handler.
	nodes[1].node.handle_stfu(node_id_0, &stfu_0);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	// Node 0 handles node 1's STFU — it already sent its own STFU, so tie-break again.
	// Node 0 wins (is_outbound = true), consumes its quiescent_action, and sends tx_init_rbf.
	nodes[0].node.handle_stfu(node_id_1, &stfu_1);

	// Node 0 sends tx_init_rbf.
	let tx_init_rbf = get_event_msg!(nodes[0], MessageSendEvent::SendTxInitRbf, node_id_1);
	assert_eq!(tx_init_rbf.channel_id, channel_id);
	assert_eq!(tx_init_rbf.feerate_sat_per_1000_weight, rbf_feerate_0.to_sat_per_kwu() as u32);

	// Node 1 handles tx_init_rbf — its quiescent_action is consumed, adjusting its contribution
	// for node 0's feerate. Whether it contributes depends on the feerate and budget constraints.
	nodes[1].node.handle_tx_init_rbf(node_id_0, &tx_init_rbf);
	let tx_ack_rbf = get_event_msg!(nodes[1], MessageSendEvent::SendTxAckRbf, node_id_0);
	assert_eq!(tx_ack_rbf.channel_id, channel_id);

	// Node 0 handles tx_ack_rbf.
	let acceptor_contributes = tx_ack_rbf.funding_output_contribution.is_some();
	assert_eq!(
		acceptor_contributes, expect_acceptor_contributes,
		"Expected acceptor contribution: {}, got: {}",
		expect_acceptor_contributes, acceptor_contributes,
	);
	nodes[0].node.handle_tx_ack_rbf(node_id_1, &tx_ack_rbf);

	if acceptor_contributes {
		// Capture change output values for assertions.
		let node_0_change = node_0_funding_contribution
			.change_output()
			.expect("splice-in should have a change output")
			.clone();
		let node_1_change = node_1_funding_contribution
			.change_output()
			.expect("splice-in should have a change output")
			.clone();

		// Complete interactive funding negotiation with both parties' inputs/outputs.
		complete_interactive_funding_negotiation_for_both(
			&nodes[0],
			&nodes[1],
			channel_id,
			node_0_funding_contribution,
			Some(node_1_funding_contribution),
			tx_ack_rbf.funding_output_contribution.unwrap(),
			new_funding_script.clone(),
		);

		// Sign (acceptor has contribution) and broadcast.
		let (rbf_tx, splice_locked) = sign_interactive_funding_tx_with_acceptor_contribution(
			&nodes[0], &nodes[1], false, true,
		);
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
				"Acceptor's change should increase when initiator feerate ({}) <= acceptor \
				 feerate ({}): adjusted {} vs original {}",
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
				"Acceptor's change should decrease when initiator feerate ({}) > acceptor \
				 feerate ({}): adjusted {} vs original {}",
				rbf_feerate_0.to_sat_per_kwu(),
				rbf_feerate_1.to_sat_per_kwu(),
				acceptor_change_in_tx.value,
				node_1_change.value,
			);
		}

		expect_splice_pending_event(&nodes[0], &node_id_1);
		expect_splice_pending_event(&nodes[1], &node_id_0);

		// Mine, lock, and verify DiscardFunding for the replaced splice candidate.
		lock_rbf_splice_after_blocks(
			&nodes[0],
			&nodes[1],
			&rbf_tx,
			ANTI_REORG_DELAY - 1,
			&[first_splice_tx.compute_txid()],
		);
	} else {
		// Acceptor does not contribute — complete with only node 0's inputs/outputs.
		complete_interactive_funding_negotiation_for_both(
			&nodes[0],
			&nodes[1],
			channel_id,
			node_0_funding_contribution,
			None,
			0,
			new_funding_script.clone(),
		);

		// Sign (acceptor has no contribution) and broadcast.
		let (rbf_tx, splice_locked) = sign_interactive_funding_tx_with_acceptor_contribution(
			&nodes[0], &nodes[1], false, false,
		);
		assert!(splice_locked.is_none());

		expect_splice_pending_event(&nodes[0], &node_id_1);
		expect_splice_pending_event(&nodes[1], &node_id_0);

		// Mine, lock, and verify DiscardFunding for the replaced splice candidate.
		// Node 1's QuiescentAction was preserved, so after splice_locked it re-initiates
		// quiescence to retry its contribution in a future splice.
		let node_b_stfu = lock_rbf_splice_after_blocks(
			&nodes[0],
			&nodes[1],
			&rbf_tx,
			ANTI_REORG_DELAY - 1,
			&[first_splice_tx.compute_txid()],
		);
		let stfu_1 = if let Some(MessageSendEvent::SendStfu { msg, .. }) = node_b_stfu {
			msg
		} else {
			panic!("Expected SendStfu from node 1");
		};
		assert!(stfu_1.initiator);

		// === Part 2: Node 1's preserved QuiescentAction leads to a new splice ===
		//
		// After splice_locked, pending_splice is None. So when stfu() consumes the
		// QuiescentAction, it sends SpliceInit (not TxInitRbf), starting a brand new splice.

		// Node 0 receives node 1's STFU and responds with its own STFU.
		nodes[0].node.handle_stfu(node_id_1, &stfu_1);
		let stfu_0 = get_event_msg!(nodes[0], MessageSendEvent::SendStfu, node_id_1);

		// Node 1 receives STFU → quiescence established → node 1 is the initiator →
		// sends SpliceInit.
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

		// Complete interactive funding negotiation with node 1 as initiator (only node 1
		// contributes).
		complete_interactive_funding_negotiation(
			&nodes[1],
			&nodes[0],
			channel_id,
			node_1_funding_contribution,
			new_funding_script_2,
		);

		// Sign (no acceptor contribution) and broadcast.
		let (new_splice_tx, splice_locked) =
			sign_interactive_funding_tx(&nodes[1], &nodes[0], false);
		assert!(splice_locked.is_none());

		expect_splice_pending_event(&nodes[1], &node_id_0);
		expect_splice_pending_event(&nodes[0], &node_id_1);

		// Mine and lock.
		mine_transaction(&nodes[1], &new_splice_tx);
		mine_transaction(&nodes[0], &new_splice_tx);

		lock_splice_after_blocks(&nodes[1], &nodes[0], ANTI_REORG_DELAY - 1);
	}
}

#[test]
fn test_splice_rbf_tiebreak_feerate_too_high_rejected() {
	// Node 0 (winner) proposes an RBF feerate far above node 1's (loser) max_feerate, and
	// node 1's fair fee at that feerate exceeds its budget. This triggers
	// FeeRateAdjustmentError::TooHigh in the queued contribution path, causing node 1 to
	// reject with tx_abort.
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
	let (_first_splice_tx, _new_funding_script) =
		splice_channel(&nodes[0], &nodes[1], channel_id, funding_contribution);

	// Provide more UTXOs for both nodes' RBF attempts.
	provide_utxo_reserves(&nodes, 2, added_value * 2);

	// Node 0 uses an extremely high feerate (100,000 sat/kwu). Node 1 uses the minimum RBF
	// feerate with a moderate splice-in (50,000 sats) and a low max_feerate (3,000 sat/kwu).
	// The target (100k) far exceeds node 1's max (3k), and the fair fee at 100k exceeds
	// node 1's budget, triggering TooHigh.
	let high_feerate = FeeRate::from_sat_per_kwu(100_000);
	let min_rbf_feerate_sat_per_kwu = FEERATE_FLOOR_SATS_PER_KW as u64 + 25;
	let min_rbf_feerate = FeeRate::from_sat_per_kwu(min_rbf_feerate_sat_per_kwu);
	let node_1_max_feerate = FeeRate::from_sat_per_kwu(3_000);

	let funding_template_0 = nodes[0].node.splice_channel(&channel_id, &node_id_1).unwrap();
	let wallet_0 = WalletSync::new(Arc::clone(&nodes[0].wallet_source), nodes[0].logger);
	let node_0_funding_contribution = funding_template_0
		.splice_in_sync(added_value, high_feerate, FeeRate::MAX, &wallet_0)
		.unwrap();
	nodes[0]
		.node
		.funding_contributed(&channel_id, &node_id_1, node_0_funding_contribution.clone(), None)
		.unwrap();

	let funding_template_1 = nodes[1].node.splice_channel(&channel_id, &node_id_0).unwrap();
	let wallet_1 = WalletSync::new(Arc::clone(&nodes[1].wallet_source), nodes[1].logger);
	let node_1_funding_contribution = funding_template_1
		.splice_in_sync(added_value, min_rbf_feerate, node_1_max_feerate, &wallet_1)
		.unwrap();
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

	// Node 0 sends tx_init_rbf at 100,000 sat/kwu.
	let tx_init_rbf = get_event_msg!(nodes[0], MessageSendEvent::SendTxInitRbf, node_id_1);
	assert_eq!(tx_init_rbf.feerate_sat_per_1000_weight, high_feerate.to_sat_per_kwu() as u32);

	// Node 1 handles tx_init_rbf — TooHigh: target (100k) >> max (3k) and fair fee > budget.
	nodes[1].node.handle_tx_init_rbf(node_id_0, &tx_init_rbf);

	let tx_abort = get_event_msg!(nodes[1], MessageSendEvent::SendTxAbort, node_id_0);
	assert_eq!(tx_abort.channel_id, channel_id);
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

	let funding_template_0 = nodes[0].node.splice_channel(&channel_id, &node_id_1).unwrap();
	let wallet_0 = WalletSync::new(Arc::clone(&nodes[0].wallet_source), nodes[0].logger);
	let node_0_funding_contribution =
		funding_template_0.splice_in_sync(added_value, feerate, FeeRate::MAX, &wallet_0).unwrap();
	nodes[0]
		.node
		.funding_contributed(&channel_id, &node_id_1, node_0_funding_contribution.clone(), None)
		.unwrap();

	let funding_template_1 = nodes[1].node.splice_channel(&channel_id, &node_id_0).unwrap();
	let wallet_1 = WalletSync::new(Arc::clone(&nodes[1].wallet_source), nodes[1].logger);
	let node_1_funding_contribution =
		funding_template_1.splice_in_sync(added_value, feerate, FeeRate::MAX, &wallet_1).unwrap();
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
		splice_ack.funding_contribution_satoshis,
		new_funding_script.clone(),
	);

	let (first_splice_tx, splice_locked) =
		sign_interactive_funding_tx_with_acceptor_contribution(&nodes[0], &nodes[1], false, true);
	assert!(splice_locked.is_none());

	expect_splice_pending_event(&nodes[0], &node_id_1);
	expect_splice_pending_event(&nodes[1], &node_id_0);

	// Step 4: Provide new UTXOs for node 0's RBF (node 1 does NOT initiate RBF).
	provide_utxo_reserves(&nodes, 2, added_value * 2);

	// Step 5: Only node 0 calls splice_channel + funding_contributed.
	let rbf_feerate_sat_per_kwu = FEERATE_FLOOR_SATS_PER_KW as u64 + 25;
	let rbf_feerate = FeeRate::from_sat_per_kwu(rbf_feerate_sat_per_kwu);
	let rbf_funding_contribution =
		do_initiate_rbf_splice_in(&nodes[0], &nodes[1], channel_id, added_value, rbf_feerate);

	// Steps 6-9: STFU exchange → tx_init_rbf → tx_ack_rbf.
	// Node 1 should re-contribute via our_prior_contribution.
	let tx_ack_rbf = complete_rbf_handshake(&nodes[0], &nodes[1]);
	assert!(
		tx_ack_rbf.funding_output_contribution.is_some(),
		"Acceptor should re-contribute via our_prior_contribution"
	);

	// Step 10: Complete interactive funding with both contributions.
	// Node 1's prior contribution is re-used — pass a clone for matching.
	complete_interactive_funding_negotiation_for_both(
		&nodes[0],
		&nodes[1],
		channel_id,
		rbf_funding_contribution,
		Some(node_1_funding_contribution),
		tx_ack_rbf.funding_output_contribution.unwrap(),
		new_funding_script.clone(),
	);

	// Step 11: Sign (acceptor has contribution) and broadcast.
	let (rbf_tx, splice_locked) =
		sign_interactive_funding_tx_with_acceptor_contribution(&nodes[0], &nodes[1], false, true);
	assert!(splice_locked.is_none());

	expect_splice_pending_event(&nodes[0], &node_id_1);
	expect_splice_pending_event(&nodes[1], &node_id_0);

	// Step 12: Mine, lock, and verify DiscardFunding for the replaced splice candidate.
	lock_rbf_splice_after_blocks(
		&nodes[0],
		&nodes[1],
		&rbf_tx,
		ANTI_REORG_DELAY - 1,
		&[first_splice_tx.compute_txid()],
	);
}

#[test]
fn test_splice_rbf_after_counterparty_rbf_aborted() {
	// When a counterparty-initiated RBF is aborted, the acceptor's prior contribution is
	// restored to the original feerate (before adjustment). Initiating our own RBF afterward
	// uses this restored contribution.
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

	let funding_template_0 = nodes[0].node.splice_channel(&channel_id, &node_id_1).unwrap();
	let wallet_0 = WalletSync::new(Arc::clone(&nodes[0].wallet_source), nodes[0].logger);
	let node_0_funding_contribution =
		funding_template_0.splice_in_sync(added_value, feerate, FeeRate::MAX, &wallet_0).unwrap();
	nodes[0]
		.node
		.funding_contributed(&channel_id, &node_id_1, node_0_funding_contribution.clone(), None)
		.unwrap();

	let funding_template_1 = nodes[1].node.splice_channel(&channel_id, &node_id_0).unwrap();
	let wallet_1 = WalletSync::new(Arc::clone(&nodes[1].wallet_source), nodes[1].logger);
	let node_1_funding_contribution =
		funding_template_1.splice_in_sync(added_value, feerate, FeeRate::MAX, &wallet_1).unwrap();
	nodes[1]
		.node
		.funding_contributed(&channel_id, &node_id_0, node_1_funding_contribution.clone(), None)
		.unwrap();

	// Step 2: Tiebreak — node 0 wins, both contribute to initial splice.
	let stfu_0 = get_event_msg!(nodes[0], MessageSendEvent::SendStfu, node_id_1);
	let stfu_1 = get_event_msg!(nodes[1], MessageSendEvent::SendStfu, node_id_0);

	nodes[1].node.handle_stfu(node_id_0, &stfu_0);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	nodes[0].node.handle_stfu(node_id_1, &stfu_1);

	let splice_init = get_event_msg!(nodes[0], MessageSendEvent::SendSpliceInit, node_id_1);
	nodes[1].node.handle_splice_init(node_id_0, &splice_init);
	let splice_ack = get_event_msg!(nodes[1], MessageSendEvent::SendSpliceAck, node_id_0);
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
		splice_ack.funding_contribution_satoshis,
		new_funding_script,
	);

	let (_first_splice_tx, splice_locked) =
		sign_interactive_funding_tx_with_acceptor_contribution(&nodes[0], &nodes[1], false, true);
	assert!(splice_locked.is_none());

	expect_splice_pending_event(&nodes[0], &node_id_1);
	expect_splice_pending_event(&nodes[1], &node_id_0);

	// Step 3: Node 0 initiates RBF. Node 1 has no QuiescentAction, so its prior contribution
	// is adjusted to the RBF feerate via for_acceptor_at_feerate.
	provide_utxo_reserves(&nodes, 2, added_value * 2);

	let rbf_feerate = FeeRate::from_sat_per_kwu(FEERATE_FLOOR_SATS_PER_KW as u64 + 25);
	let _rbf_funding_contribution =
		do_initiate_rbf_splice_in(&nodes[0], &nodes[1], channel_id, added_value, rbf_feerate);

	let tx_ack_rbf = complete_rbf_handshake(&nodes[0], &nodes[1]);
	assert!(tx_ack_rbf.funding_output_contribution.is_some());

	// Step 4: Abort the RBF. Node 0 sends tx_abort; node 1's prior contribution is restored
	// to the original feerate (the RBF round's adjusted entry is popped from contributions).
	// Drain node 0's pending TxAddInput from the interactive tx negotiation start.
	nodes[0].node.get_and_clear_pending_msg_events();

	let tx_abort = msgs::TxAbort { channel_id, data: vec![] };
	nodes[1].node.handle_tx_abort(node_id_0, &tx_abort);

	let msg_events = nodes[1].node.get_and_clear_pending_msg_events();
	assert!(!msg_events.is_empty());
	let tx_abort_echo = match &msg_events[0] {
		MessageSendEvent::SendTxAbort { msg, .. } => msg.clone(),
		other => panic!("Expected SendTxAbort, got {:?}", other),
	};

	nodes[0].node.handle_tx_abort(node_id_1, &tx_abort_echo);
	nodes[0].node.get_and_clear_pending_msg_events();
	nodes[0].node.get_and_clear_pending_events();
	nodes[1].node.get_and_clear_pending_events();

	// Step 5: Node 1 initiates its own RBF via splice_channel → rbf_sync.
	// The prior contribution's feerate is restored to the original floor feerate, not the
	// RBF-adjusted feerate.
	provide_utxo_reserves(&nodes, 2, added_value * 2);

	let funding_template = nodes[1].node.splice_channel(&channel_id, &node_id_0).unwrap();
	assert!(funding_template.min_rbf_feerate().is_some());
	assert_eq!(
		funding_template.prior_contribution().unwrap().feerate(),
		feerate,
		"Prior contribution should have the original feerate, not the RBF-adjusted one",
	);

	let wallet = WalletSync::new(Arc::clone(&nodes[1].wallet_source), nodes[1].logger);
	let rbf_contribution = funding_template.rbf_sync(FeeRate::MAX, &wallet);
	assert!(rbf_contribution.is_ok());
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

	let funding_template_0 = nodes[0].node.splice_channel(&channel_id, &node_id_1).unwrap();
	let wallet_0 = WalletSync::new(Arc::clone(&nodes[0].wallet_source), nodes[0].logger);
	let node_0_funding_contribution = funding_template_0
		.splice_in_sync(Amount::from_sat(50_000), floor_feerate, FeeRate::MAX, &wallet_0)
		.unwrap();
	nodes[0]
		.node
		.funding_contributed(&channel_id, &node_id_1, node_0_funding_contribution.clone(), None)
		.unwrap();

	let node_1_added_value = Amount::from_sat(95_000);
	let funding_template_1 = nodes[1].node.splice_channel(&channel_id, &node_id_0).unwrap();
	let wallet_1 = WalletSync::new(Arc::clone(&nodes[1].wallet_source), nodes[1].logger);
	let node_1_funding_contribution = funding_template_1
		.splice_in_sync(node_1_added_value, floor_feerate, FeeRate::MAX, &wallet_1)
		.unwrap();
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
		splice_ack.funding_contribution_satoshis,
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
	let funding_template = nodes[0].node.splice_channel(&channel_id, &node_id_1).unwrap();
	let wallet = WalletSync::new(Arc::clone(&nodes[0].wallet_source), nodes[0].logger);
	let rbf_funding_contribution = funding_template
		.splice_in_sync(Amount::from_sat(50_000), high_feerate, FeeRate::MAX, &wallet)
		.unwrap();
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
	// Should reject with tx_abort rather than proceeding without contribution.
	nodes[1].node.handle_tx_init_rbf(node_id_0, &tx_init_rbf);

	let tx_abort = get_event_msg!(nodes[1], MessageSendEvent::SendTxAbort, node_id_0);
	assert_eq!(tx_abort.channel_id, channel_id);
}

#[test]
fn test_splice_rbf_sequential() {
	// Three consecutive RBF rounds on the same splice (initial → RBF #1 → RBF #2).
	// Node 0 is the quiescence initiator; node 1 is the acceptor with no contribution.
	// Verifies:
	// - Each round satisfies the +25 sat/kwu feerate rule
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

	// --- Round 0: Initial splice-in from node 0 at floor feerate (253). ---
	let funding_contribution = do_initiate_splice_in(&nodes[0], &nodes[1], channel_id, added_value);
	let (splice_tx_0, new_funding_script) =
		splice_channel(&nodes[0], &nodes[1], channel_id, funding_contribution);

	// Feerate progression: 253 → 253+25 = 278 → 278+25 = 303
	let feerate_1_sat_per_kwu = FEERATE_FLOOR_SATS_PER_KW as u64 + 25; // 278
	let feerate_2_sat_per_kwu = feerate_1_sat_per_kwu + 25;

	// --- Round 1: RBF #1 at feerate 278. ---
	provide_utxo_reserves(&nodes, 2, added_value * 2);

	let rbf_feerate_1 = FeeRate::from_sat_per_kwu(feerate_1_sat_per_kwu);
	let funding_contribution_1 =
		do_initiate_rbf_splice_in(&nodes[0], &nodes[1], channel_id, added_value, rbf_feerate_1);
	complete_rbf_handshake(&nodes[0], &nodes[1]);

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

	// --- Round 2: RBF #2 at feerate 303. ---
	provide_utxo_reserves(&nodes, 2, added_value * 2);

	let rbf_feerate_2 = FeeRate::from_sat_per_kwu(feerate_2_sat_per_kwu);
	let funding_contribution_2 =
		do_initiate_rbf_splice_in(&nodes[0], &nodes[1], channel_id, added_value, rbf_feerate_2);
	complete_rbf_handshake(&nodes[0], &nodes[1]);

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

	// --- Mine and lock the final RBF, verifying DiscardFunding for both replaced candidates. ---
	let splice_tx_0_txid = splice_tx_0.compute_txid();
	let splice_tx_1_txid = splice_tx_1.compute_txid();
	lock_rbf_splice_after_blocks(
		&nodes[0],
		&nodes[1],
		&rbf_tx_final,
		ANTI_REORG_DELAY - 1,
		&[splice_tx_0_txid, splice_tx_1_txid],
	);
}

#[test]
fn test_splice_rbf_acceptor_contributes_then_disconnects() {
	// When both nodes contribute to a splice and the initiator RBFs (with the acceptor
	// re-contributing via prior contribution), disconnecting mid-interactive-TX should emit
	// SpliceFailed + DiscardFunding for both nodes so each can reclaim their UTXOs.
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

	// --- Round 0: Both nodes initiate splice-in (tiebreak: node 0 wins). ---
	let node_0_funding_contribution =
		do_initiate_splice_in(&nodes[0], &nodes[1], channel_id, added_value);
	let node_1_funding_contribution =
		do_initiate_splice_in(&nodes[1], &nodes[0], channel_id, added_value);

	let stfu_0 = get_event_msg!(nodes[0], MessageSendEvent::SendStfu, node_id_1);
	let stfu_1 = get_event_msg!(nodes[1], MessageSendEvent::SendStfu, node_id_0);
	nodes[1].node.handle_stfu(node_id_0, &stfu_0);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	nodes[0].node.handle_stfu(node_id_1, &stfu_1);

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
		Some(node_1_funding_contribution.clone()),
		splice_ack.funding_contribution_satoshis,
		new_funding_script.clone(),
	);

	let (_first_splice_tx, splice_locked) =
		sign_interactive_funding_tx_with_acceptor_contribution(&nodes[0], &nodes[1], false, true);
	assert!(splice_locked.is_none());

	expect_splice_pending_event(&nodes[0], &node_id_1);
	expect_splice_pending_event(&nodes[1], &node_id_0);

	// --- Round 1: Node 0 initiates RBF; node 1 re-contributes via prior. ---
	provide_utxo_reserves(&nodes, 2, added_value * 2);

	let rbf_feerate_sat_per_kwu = FEERATE_FLOOR_SATS_PER_KW as u64 + 25;
	let rbf_feerate = FeeRate::from_sat_per_kwu(rbf_feerate_sat_per_kwu);
	let _rbf_funding_contribution =
		do_initiate_rbf_splice_in(&nodes[0], &nodes[1], channel_id, added_value, rbf_feerate);

	let tx_ack_rbf = complete_rbf_handshake(&nodes[0], &nodes[1]);
	assert!(
		tx_ack_rbf.funding_output_contribution.is_some(),
		"Acceptor should re-contribute via prior contribution"
	);

	// Disconnect mid-interactive-TX negotiation.
	nodes[0].node.peer_disconnected(node_id_1);
	nodes[1].node.peer_disconnected(node_id_0);

	// The initiator should get SpliceFailed + DiscardFunding.
	let events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 2, "{events:?}");
	match &events[0] {
		Event::SpliceFailed { channel_id: cid, .. } => assert_eq!(*cid, channel_id),
		other => panic!("Expected SpliceFailed, got {:?}", other),
	}
	match &events[1] {
		Event::DiscardFunding { funding_info: FundingInfo::Contribution { .. }, .. } => {},
		other => panic!("Expected DiscardFunding with Contribution, got {:?}", other),
	}

	// The acceptor re-contributed the same UTXOs as round 0 (via prior contribution
	// adjustment). Since those UTXOs are still committed to round 0's splice, they are
	// filtered from the DiscardFunding event. With all inputs/outputs filtered, no events
	// are emitted for the acceptor.
	let events = nodes[1].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 0, "{events:?}");

	// Reconnect.
	let mut reconnect_args = ReconnectArgs::new(&nodes[0], &nodes[1]);
	reconnect_args.send_announcement_sigs = (true, true);
	reconnect_nodes(reconnect_args);
}

#[test]
fn test_splice_rbf_disconnect_filters_prior_contributions() {
	// When disconnecting during an RBF round that reuses the same UTXOs as a prior round,
	// the SpliceFundingFailed event should filter out inputs/outputs still committed to the prior
	// round. This exercises the `reset_pending_splice_state` → `maybe_create_splice_funding_failed`
	// macro path.
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
	// Provide exactly 1 UTXO per node so coin selection is deterministic.
	provide_utxo_reserves(&nodes, 1, added_value * 2);

	// --- Round 0: Initial splice-in at floor feerate (253). ---
	let funding_contribution = do_initiate_splice_in(&nodes[0], &nodes[1], channel_id, added_value);
	let (_splice_tx_0, _new_funding_script) =
		splice_channel(&nodes[0], &nodes[1], channel_id, funding_contribution);

	// --- Round 1: RBF at higher feerate without providing new UTXOs. ---
	// The wallet reselects the same UTXO since the splice tx hasn't been mined.
	// Include a splice-out output with a different script_pubkey so the test can verify
	// selective filtering: the change output (same script_pubkey as round 0) is filtered,
	// while the splice-out output (different script_pubkey) survives.
	let feerate_1_sat_per_kwu = FEERATE_FLOOR_SATS_PER_KW as u64 + 25;
	let rbf_feerate = FeeRate::from_sat_per_kwu(feerate_1_sat_per_kwu);
	let splice_out_output = TxOut {
		value: Amount::from_sat(1_000),
		script_pubkey: nodes[1].wallet_source.get_change_script().unwrap(),
	};
	let _funding_contribution_1 = do_initiate_rbf_splice_in_and_out(
		&nodes[0],
		&nodes[1],
		channel_id,
		added_value,
		vec![splice_out_output.clone()],
		rbf_feerate,
	);

	// STFU exchange + RBF handshake to start interactive TX.
	complete_rbf_handshake(&nodes[0], &nodes[1]);

	// Disconnect mid-negotiation. Stale interactive TX messages are cleared by peer_disconnected.
	nodes[0].node.peer_disconnected(node_id_1);
	nodes[1].node.peer_disconnected(node_id_0);

	// The initiator should get SpliceFailed + DiscardFunding with filtered contributions.
	let events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 2, "{events:?}");
	match &events[0] {
		Event::SpliceFailed { channel_id: cid, .. } => {
			assert_eq!(*cid, channel_id);
		},
		other => panic!("Expected SpliceFailed, got {:?}", other),
	}
	match &events[1] {
		Event::DiscardFunding {
			funding_info: FundingInfo::Contribution { inputs, outputs },
			..
		} => {
			// The UTXO was filtered out: it's still committed to round 0's splice.
			assert!(inputs.is_empty(), "Expected empty inputs (filtered), got {:?}", inputs);
			// The change output was filtered (same script_pubkey as round 0's change output),
			// but the splice-out output survives (different script_pubkey).
			assert_eq!(*outputs, vec![splice_out_output.clone()]);
		},
		other => panic!("Expected DiscardFunding with Contribution, got {:?}", other),
	}

	// Reconnect. After a completed splice, channel_ready is not re-sent.
	let mut reconnect_args = ReconnectArgs::new(&nodes[0], &nodes[1]);
	reconnect_args.send_announcement_sigs = (true, true);
	reconnect_nodes(reconnect_args);

	// --- Round 2: RBF at the same feerate as the failed round 1 (278). ---
	// This should succeed because the failed round never updated the feerate floor, which
	// remains at round 0's rate (253), and 278 >= 253 + 25.
	provide_utxo_reserves(&nodes, 1, added_value * 2);

	let rbf_feerate_2 = FeeRate::from_sat_per_kwu(feerate_1_sat_per_kwu);
	let _funding_contribution_2 =
		do_initiate_rbf_splice_in(&nodes[0], &nodes[1], channel_id, added_value, rbf_feerate_2);
	complete_rbf_handshake(&nodes[0], &nodes[1]);

	// Disconnect again to clean up the in-progress interactive TX negotiation.
	nodes[0].node.peer_disconnected(node_id_1);
	nodes[1].node.peer_disconnected(node_id_0);

	let events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 2, "{events:?}");
	match &events[0] {
		Event::SpliceFailed { channel_id: cid, .. } => assert_eq!(*cid, channel_id),
		other => panic!("Expected SpliceFailed, got {:?}", other),
	}
	match &events[1] {
		Event::DiscardFunding { .. } => {},
		other => panic!("Expected DiscardFunding, got {:?}", other),
	}

	let mut reconnect_args = ReconnectArgs::new(&nodes[0], &nodes[1]);
	reconnect_args.send_announcement_sigs = (true, true);
	reconnect_nodes(reconnect_args);
}

#[test]
fn test_splice_channel_with_pending_splice_includes_rbf_floor() {
	// Test that splice_channel includes the RBF floor when a pending splice exists with
	// negotiated candidates.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_id_1 = nodes[1].node.get_our_node_id();

	let initial_channel_value_sat = 100_000;
	let (_, _, channel_id, _) =
		create_announced_chan_between_nodes_with_value(&nodes, 0, 1, initial_channel_value_sat, 0);

	let added_value = Amount::from_sat(50_000);
	provide_utxo_reserves(&nodes, 2, added_value * 2);

	// Fresh splice — no pending splice, so no prior contribution or minimum RBF feerate.
	{
		let template = nodes[0].node.splice_channel(&channel_id, &node_id_1).unwrap();
		assert!(template.min_rbf_feerate().is_none());
		assert!(template.prior_contribution().is_none());
	}

	// Complete a splice-in at floor feerate.
	let funding_contribution = do_initiate_splice_in(&nodes[0], &nodes[1], channel_id, added_value);
	let (_splice_tx, _) = splice_channel(&nodes[0], &nodes[1], channel_id, funding_contribution);

	// Call splice_channel again — the pending splice should cause min_rbf_feerate to be set
	// and the prior contribution to be available.
	let funding_template = nodes[0].node.splice_channel(&channel_id, &node_id_1).unwrap();
	let expected_floor = FeeRate::from_sat_per_kwu(FEERATE_FLOOR_SATS_PER_KW as u64 + 25);
	assert_eq!(funding_template.min_rbf_feerate(), Some(expected_floor));
	assert!(funding_template.prior_contribution().is_some());

	// rbf_sync returns the Adjusted prior contribution directly.
	let wallet = WalletSync::new(Arc::clone(&nodes[0].wallet_source), nodes[0].logger);
	assert!(funding_template.rbf_sync(FeeRate::MAX, &wallet).is_ok());
}

#[test]
fn test_funding_contributed_adjusts_feerate_for_rbf() {
	// Test that funding_contributed adjusts the contribution's feerate to the minimum RBF feerate
	// when a pending splice appears between splice_channel and funding_contributed.
	//
	// Node 0 calls splice_channel (no pending splice → min_rbf_feerate = None) and builds a
	// contribution at floor feerate. Node 1 then initiates and completes a splice. When node 0
	// calls funding_contributed, the contribution is adjusted to the minimum RBF feerate and STFU
	// is sent immediately.
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
	provide_utxo_reserves(&nodes, 4, added_value * 2);

	// Node 0 calls splice_channel before any pending splice exists.
	let floor_feerate = FeeRate::from_sat_per_kwu(FEERATE_FLOOR_SATS_PER_KW as u64);
	let funding_template = nodes[0].node.splice_channel(&channel_id, &node_id_1).unwrap();
	assert!(funding_template.min_rbf_feerate().is_none());

	// Build contribution at floor feerate with high max_feerate to allow adjustment.
	let wallet = WalletSync::new(Arc::clone(&nodes[0].wallet_source), nodes[0].logger);
	let contribution =
		funding_template.splice_in_sync(added_value, floor_feerate, FeeRate::MAX, &wallet).unwrap();

	// Node 1 initiates and completes a splice, creating pending_splice with negotiated candidates.
	let node_1_contribution = do_initiate_splice_in(&nodes[1], &nodes[0], channel_id, added_value);
	let (_first_splice_tx, _new_funding_script) =
		splice_channel(&nodes[1], &nodes[0], channel_id, node_1_contribution);

	// Node 0 calls funding_contributed. The contribution's feerate (floor) is below the RBF
	// floor (floor + 25 sat/kwu), but funding_contributed adjusts it upward.
	nodes[0].node.funding_contributed(&channel_id, &node_id_1, contribution.clone(), None).unwrap();

	// STFU should be sent immediately (the adjusted feerate satisfies the RBF check).
	let stfu = get_event_msg!(nodes[0], MessageSendEvent::SendStfu, node_id_1);
	nodes[1].node.handle_stfu(node_id_0, &stfu);
	let stfu_resp = get_event_msg!(nodes[1], MessageSendEvent::SendStfu, node_id_0);
	nodes[0].node.handle_stfu(node_id_1, &stfu_resp);

	// Verify the RBF handshake proceeds.
	let tx_init_rbf = get_event_msg!(nodes[0], MessageSendEvent::SendTxInitRbf, node_id_1);
	let rbf_feerate = FeeRate::from_sat_per_kwu(tx_init_rbf.feerate_sat_per_1000_weight as u64);
	let expected_floor = FeeRate::from_sat_per_kwu(FEERATE_FLOOR_SATS_PER_KW as u64 + 25);
	assert!(rbf_feerate >= expected_floor);
}

#[test]
fn test_funding_contributed_rbf_adjustment_exceeds_max_feerate() {
	// Test that when the minimum RBF feerate exceeds max_feerate, the adjustment in
	// funding_contributed fails gracefully and the contribution keeps its original feerate. The
	// splice still proceeds (STFU is sent) and the RBF negotiation handles the feerate mismatch.
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
	provide_utxo_reserves(&nodes, 4, added_value * 2);

	// Node 0 calls splice_channel and builds contribution with max_feerate = floor_feerate.
	// This means the minimum RBF feerate (floor + 25 sat/kwu) will exceed max_feerate, preventing adjustment.
	let floor_feerate = FeeRate::from_sat_per_kwu(FEERATE_FLOOR_SATS_PER_KW as u64);
	let funding_template = nodes[0].node.splice_channel(&channel_id, &node_id_1).unwrap();
	let wallet = WalletSync::new(Arc::clone(&nodes[0].wallet_source), nodes[0].logger);
	let contribution = funding_template
		.splice_in_sync(added_value, floor_feerate, floor_feerate, &wallet)
		.unwrap();

	// Node 1 initiates and completes a splice.
	let node_1_contribution = do_initiate_splice_in(&nodes[1], &nodes[0], channel_id, added_value);
	let (_splice_tx, _) = splice_channel(&nodes[1], &nodes[0], channel_id, node_1_contribution);

	// Node 0 calls funding_contributed. The adjustment fails (minimum RBF feerate > max_feerate),
	// but funding_contributed still succeeds — the contribution keeps its original feerate.
	nodes[0].node.funding_contributed(&channel_id, &node_id_1, contribution, None).unwrap();

	// STFU is NOT sent — the feerate is below the minimum RBF feerate so try_send_stfu delays.
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());

	// Mine and lock the pending splice → pending_splice is cleared.
	mine_transaction(&nodes[0], &_splice_tx);
	mine_transaction(&nodes[1], &_splice_tx);
	let stfu = lock_splice_after_blocks(&nodes[0], &nodes[1], ANTI_REORG_DELAY - 1);

	// STFU is sent during lock — the splice proceeds as a fresh splice (not RBF).
	let stfu = match stfu {
		Some(MessageSendEvent::SendStfu { msg, .. }) => {
			assert!(msg.initiator);
			msg
		},
		other => panic!("Expected SendStfu, got {:?}", other),
	};

	// Complete the fresh splice and verify it uses the original floor feerate.
	nodes[1].node.handle_stfu(node_id_0, &stfu);
	let stfu_resp = get_event_msg!(nodes[1], MessageSendEvent::SendStfu, node_id_0);
	nodes[0].node.handle_stfu(node_id_1, &stfu_resp);

	let splice_init = get_event_msg!(nodes[0], MessageSendEvent::SendSpliceInit, node_id_1);
	assert_eq!(splice_init.funding_feerate_per_kw, FEERATE_FLOOR_SATS_PER_KW);
}

#[test]
fn test_funding_contributed_rbf_adjustment_insufficient_budget() {
	// Test that when the change output can't absorb the fee increase needed for the minimum RBF feerate
	// (even though max_feerate allows it), the adjustment fails gracefully and the splice
	// proceeds with the original feerate.
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
	provide_utxo_reserves(&nodes, 4, added_value * 2);

	// Node 0 calls splice_channel before any pending splice exists.
	let floor_feerate = FeeRate::from_sat_per_kwu(FEERATE_FLOOR_SATS_PER_KW as u64);
	let funding_template = nodes[0].node.splice_channel(&channel_id, &node_id_1).unwrap();

	// Build node 0's contribution at floor feerate with a tight budget.
	let wallet = TightBudgetWallet {
		utxo_value: added_value + Amount::from_sat(3000),
		change_value: Amount::from_sat(300),
	};
	let contribution =
		funding_template.splice_in_sync(added_value, floor_feerate, FeeRate::MAX, &wallet).unwrap();

	// Node 1 initiates a splice at a HIGH feerate (10,000 sat/kwu). The minimum RBF feerate will be
	// max(10,000 + 25, ceil(10,000 * 25/24)) = 10,417 sat/kwu — far above what node 0's tight
	// budget can handle.
	let high_feerate = FeeRate::from_sat_per_kwu(10_000);
	let node_1_template = nodes[1].node.splice_channel(&channel_id, &node_id_0).unwrap();
	let node_1_wallet = WalletSync::new(Arc::clone(&nodes[1].wallet_source), nodes[1].logger);
	let node_1_contribution = node_1_template
		.splice_in_sync(added_value, high_feerate, FeeRate::MAX, &node_1_wallet)
		.unwrap();
	nodes[1]
		.node
		.funding_contributed(&channel_id, &node_id_0, node_1_contribution.clone(), None)
		.unwrap();
	let (_splice_tx, _) = splice_channel(&nodes[1], &nodes[0], channel_id, node_1_contribution);

	// Node 0 calls funding_contributed. Adjustment fails (insufficient fee buffer), so the
	// contribution keeps its original feerate.
	nodes[0].node.funding_contributed(&channel_id, &node_id_1, contribution, None).unwrap();

	// STFU is NOT sent — the feerate is below the minimum RBF feerate so try_send_stfu delays.
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());

	// Mine and lock the pending splice → pending_splice is cleared.
	mine_transaction(&nodes[0], &_splice_tx);
	mine_transaction(&nodes[1], &_splice_tx);
	let stfu = lock_splice_after_blocks(&nodes[0], &nodes[1], ANTI_REORG_DELAY - 1);

	// STFU is sent during lock — the splice proceeds as a fresh splice (not RBF).
	let stfu = match stfu {
		Some(MessageSendEvent::SendStfu { msg, .. }) => {
			assert!(msg.initiator);
			msg
		},
		other => panic!("Expected SendStfu, got {:?}", other),
	};

	// Complete the fresh splice and verify it uses the original floor feerate.
	nodes[1].node.handle_stfu(node_id_0, &stfu);
	let stfu_resp = get_event_msg!(nodes[1], MessageSendEvent::SendStfu, node_id_0);
	nodes[0].node.handle_stfu(node_id_1, &stfu_resp);

	let splice_init = get_event_msg!(nodes[0], MessageSendEvent::SendSpliceInit, node_id_1);
	assert_eq!(splice_init.funding_feerate_per_kw, FEERATE_FLOOR_SATS_PER_KW);
}

#[test]
fn test_prior_contribution_unadjusted_when_max_feerate_too_low() {
	// Test that rbf_sync re-runs coin selection when the prior contribution's max_feerate is
	// too low to accommodate the minimum RBF feerate.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_id_1 = nodes[1].node.get_our_node_id();

	let initial_channel_value_sat = 100_000;
	let (_, _, channel_id, _) =
		create_announced_chan_between_nodes_with_value(&nodes, 0, 1, initial_channel_value_sat, 0);

	let added_value = Amount::from_sat(50_000);
	provide_utxo_reserves(&nodes, 2, added_value * 2);

	// Complete a splice with max_feerate = floor_feerate. This means the prior contribution
	// stored in pending_splice.contributions will have a tight max_feerate.
	let floor_feerate = FeeRate::from_sat_per_kwu(FEERATE_FLOOR_SATS_PER_KW as u64);
	let funding_template = nodes[0].node.splice_channel(&channel_id, &node_id_1).unwrap();
	let wallet = WalletSync::new(Arc::clone(&nodes[0].wallet_source), nodes[0].logger);
	let funding_contribution = funding_template
		.splice_in_sync(added_value, floor_feerate, floor_feerate, &wallet)
		.unwrap();
	nodes[0]
		.node
		.funding_contributed(&channel_id, &node_id_1, funding_contribution.clone(), None)
		.unwrap();
	let (_splice_tx, _) = splice_channel(&nodes[0], &nodes[1], channel_id, funding_contribution);

	// Call splice_channel again — the minimum RBF feerate (floor + 25 sat/kwu) exceeds the prior
	// contribution's max_feerate (floor), so adjustment fails. rbf_sync re-runs coin selection
	// with the caller's max_feerate.
	let funding_template = nodes[0].node.splice_channel(&channel_id, &node_id_1).unwrap();
	assert!(funding_template.min_rbf_feerate().is_some());
	assert!(funding_template.prior_contribution().is_some());
	let wallet = WalletSync::new(Arc::clone(&nodes[0].wallet_source), nodes[0].logger);
	assert!(funding_template.rbf_sync(FeeRate::MAX, &wallet).is_ok());
}

#[test]
fn test_splice_channel_during_negotiation_includes_rbf_feerate() {
	// Test that splice_channel returns min_rbf_feerate derived from the in-progress
	// negotiation's feerate when the acceptor calls it during active negotiation.
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

	// Node 1 initiates a splice. Perform stfu exchange and splice_init handling, which creates
	// a pending_splice with funding_negotiation on node 0 (the acceptor).
	let _funding_contribution =
		do_initiate_splice_in(&nodes[1], &nodes[0], channel_id, added_value);
	let stfu_init = get_event_msg!(nodes[1], MessageSendEvent::SendStfu, node_id_0);
	nodes[0].node.handle_stfu(node_id_1, &stfu_init);
	let stfu_ack = get_event_msg!(nodes[0], MessageSendEvent::SendStfu, node_id_1);
	nodes[1].node.handle_stfu(node_id_0, &stfu_ack);

	let splice_init = get_event_msg!(nodes[1], MessageSendEvent::SendSpliceInit, node_id_0);
	nodes[0].node.handle_splice_init(node_id_1, &splice_init);
	let _splice_ack = get_event_msg!(nodes[0], MessageSendEvent::SendSpliceAck, node_id_1);

	// Node 0 (acceptor) calls splice_channel while the negotiation is in progress.
	// min_rbf_feerate should be derived from the in-progress negotiation's feerate.
	let template = nodes[0].node.splice_channel(&channel_id, &node_id_1).unwrap();
	let expected_floor = FeeRate::from_sat_per_kwu(FEERATE_FLOOR_SATS_PER_KW as u64 + 25);
	assert_eq!(template.min_rbf_feerate(), Some(expected_floor));

	// No prior contribution since there are no negotiated candidates yet. rbf_sync runs
	// fee-bump-only coin selection.
	assert!(template.prior_contribution().is_none());
	let wallet = WalletSync::new(Arc::clone(&nodes[0].wallet_source), nodes[0].logger);
	assert!(template.rbf_sync(FeeRate::MAX, &wallet).is_ok());
}

#[test]
fn test_rbf_sync_returns_err_when_no_min_rbf_feerate() {
	// Test that rbf_sync returns Err(()) when there is no pending splice (min_rbf_feerate is
	// None), indicating this is not an RBF scenario.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_id_1 = nodes[1].node.get_our_node_id();

	let initial_channel_value_sat = 100_000;
	let (_, _, channel_id, _) =
		create_announced_chan_between_nodes_with_value(&nodes, 0, 1, initial_channel_value_sat, 0);

	let added_value = Amount::from_sat(50_000);
	provide_utxo_reserves(&nodes, 2, added_value * 2);

	// Fresh splice — no pending splice, so min_rbf_feerate is None.
	let template = nodes[0].node.splice_channel(&channel_id, &node_id_1).unwrap();
	assert!(template.min_rbf_feerate().is_none());
	assert!(template.prior_contribution().is_none());

	let wallet = WalletSync::new(Arc::clone(&nodes[0].wallet_source), nodes[0].logger);
	assert!(matches!(
		template.rbf_sync(FeeRate::MAX, &wallet),
		Err(crate::ln::funding::FundingContributionError::NotRbfScenario),
	));
}

#[test]
fn test_rbf_sync_returns_err_when_max_feerate_below_min_rbf() {
	// Test that rbf_sync returns Err when the caller's max_feerate is below the minimum
	// RBF feerate.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_id_1 = nodes[1].node.get_our_node_id();

	let initial_channel_value_sat = 100_000;
	let (_, _, channel_id, _) =
		create_announced_chan_between_nodes_with_value(&nodes, 0, 1, initial_channel_value_sat, 0);

	let added_value = Amount::from_sat(50_000);
	provide_utxo_reserves(&nodes, 2, added_value * 2);

	// Complete a splice to create a pending splice.
	let funding_contribution = do_initiate_splice_in(&nodes[0], &nodes[1], channel_id, added_value);
	let (_splice_tx, _) = splice_channel(&nodes[0], &nodes[1], channel_id, funding_contribution);

	// Call splice_channel again to get the RBF template.
	let funding_template = nodes[0].node.splice_channel(&channel_id, &node_id_1).unwrap();
	let min_rbf_feerate = funding_template.min_rbf_feerate().unwrap();

	// Use a max_feerate that is 1 sat/kwu below the minimum RBF feerate.
	let too_low_feerate =
		FeeRate::from_sat_per_kwu(min_rbf_feerate.to_sat_per_kwu().saturating_sub(1));
	let wallet = WalletSync::new(Arc::clone(&nodes[0].wallet_source), nodes[0].logger);
	assert!(matches!(
		funding_template.rbf_sync(too_low_feerate, &wallet),
		Err(crate::ln::funding::FundingContributionError::FeeRateExceedsMaximum { .. }),
	));
}

#[test]
fn test_splice_revalidation_at_quiescence() {
	// When an outbound HTLC is committed between funding_contributed and quiescence, the
	// holder's balance decreases. If the splice-out was marginal at funding_contributed time,
	// the re-validation at quiescence should fail and emit SpliceFailed + DiscardFunding.
	//
	// Flow:
	// 1. Send payment #1 (update_add + CS) → node 0 awaits RAA
	// 2. funding_contributed with splice-out → passes, stfu delayed (awaiting RAA)
	// 3. Process node 1's RAA → node 0 free to send
	// 4. Send payment #2 (update_add + CS) → balance reduced
	// 5. Process node 1's CS → node 0 sends RAA, stfu delayed (payment #2 pending)
	// 6. Complete payment #2's exchange → stfu fires
	// 7. stfu exchange → quiescence → re-validation fails
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let mut config = test_default_channel_config();
	config.channel_handshake_config.announced_channel_max_inbound_htlc_value_in_flight_percentage =
		100;
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[Some(config.clone()), Some(config)]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_id_0 = nodes[0].node.get_our_node_id();
	let node_id_1 = nodes[1].node.get_our_node_id();

	let initial_channel_value_sat = 100_000;
	let (_, _, channel_id, _) =
		create_announced_chan_between_nodes_with_value(&nodes, 0, 1, initial_channel_value_sat, 0);

	let _ = provide_anchor_reserves(&nodes);

	// Step 1: Send payment #1 (update_add + CS). Node 0 awaits RAA.
	let payment_1_msat = 20_000_000;
	let (route_1, payment_hash_1, _, payment_secret_1) =
		get_route_and_payment_hash!(nodes[0], nodes[1], payment_1_msat);
	nodes[0]
		.node
		.send_payment_with_route(
			route_1,
			payment_hash_1,
			RecipientOnionFields::secret_only(payment_secret_1, payment_1_msat),
			PaymentId(payment_hash_1.0),
		)
		.unwrap();
	check_added_monitors(&nodes[0], 1);
	let payment_1_msgs = nodes[0].node.get_and_clear_pending_msg_events();

	// Step 2: funding_contributed with splice-out. Passes because the balance floor only
	// includes payment #1. stfu is delayed — awaiting RAA.
	let outputs = vec![TxOut {
		value: Amount::from_sat(70_000),
		script_pubkey: nodes[0].wallet_source.get_change_script().unwrap(),
	}];

	let feerate = FeeRate::from_sat_per_kwu(FEERATE_FLOOR_SATS_PER_KW as u64);
	let funding_template = nodes[0].node.splice_channel(&channel_id, &node_id_1).unwrap();
	let contribution = funding_template.splice_out(outputs, feerate, FeeRate::MAX).unwrap();

	nodes[0].node.funding_contributed(&channel_id, &node_id_1, contribution.clone(), None).unwrap();
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty(), "stfu should be delayed");

	// Step 3: Deliver payment #1 to node 1 and process RAA.
	let payment_1_event = SendEvent::from_event(payment_1_msgs.into_iter().next().unwrap());
	nodes[1].node.handle_update_add_htlc(node_id_0, &payment_1_event.msgs[0]);
	nodes[1].node.handle_commitment_signed_batch_test(node_id_0, &payment_1_event.commitment_msg);
	check_added_monitors(&nodes[1], 1);
	let (raa, cs) = get_revoke_commit_msgs(&nodes[1], &node_id_0);

	// Process node 1's RAA. After this, node 0 is free to send new HTLCs.
	nodes[0].node.handle_revoke_and_ack(node_id_1, &raa);
	check_added_monitors(&nodes[0], 1);

	// Step 4: Send payment #2 in the window between RAA and CS processing.
	let payment_2_msat = 20_000_000;
	let (route_2, payment_hash_2, _, payment_secret_2) =
		get_route_and_payment_hash!(nodes[0], nodes[1], payment_2_msat);
	nodes[0]
		.node
		.send_payment_with_route(
			route_2,
			payment_hash_2,
			RecipientOnionFields::secret_only(payment_secret_2, payment_2_msat),
			PaymentId(payment_hash_2.0),
		)
		.unwrap();
	check_added_monitors(&nodes[0], 1);
	let payment_2_msgs = nodes[0].node.get_and_clear_pending_msg_events();

	// Step 5: Process node 1's CS. Node 0 sends RAA but stfu is delayed (payment #2 pending).
	nodes[0].node.handle_commitment_signed_batch_test(node_id_1, &cs);
	check_added_monitors(&nodes[0], 1);
	let raa_0 = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, node_id_1);
	nodes[1].node.handle_revoke_and_ack(node_id_0, &raa_0);
	check_added_monitors(&nodes[1], 1);

	// Step 6: Complete payment #2's commitment exchange. stfu fires afterward.
	let payment_2_event = SendEvent::from_event(payment_2_msgs.into_iter().next().unwrap());
	nodes[1].node.handle_update_add_htlc(node_id_0, &payment_2_event.msgs[0]);
	nodes[1].node.handle_commitment_signed_batch_test(node_id_0, &payment_2_event.commitment_msg);
	check_added_monitors(&nodes[1], 1);
	let (raa_1b, cs_1b) = get_revoke_commit_msgs(&nodes[1], &node_id_0);
	nodes[0].node.handle_revoke_and_ack(node_id_1, &raa_1b);
	check_added_monitors(&nodes[0], 1);
	nodes[0].node.handle_commitment_signed_batch_test(node_id_1, &cs_1b);
	check_added_monitors(&nodes[0], 1);

	// RAA and stfu sent together.
	let msg_events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(msg_events.len(), 2, "{msg_events:?}");
	let raa_0b = match &msg_events[0] {
		MessageSendEvent::SendRevokeAndACK { msg, .. } => msg.clone(),
		other => panic!("Expected SendRevokeAndACK, got {:?}", other),
	};
	let stfu_0 = match &msg_events[1] {
		MessageSendEvent::SendStfu { msg, .. } => msg.clone(),
		other => panic!("Expected SendStfu, got {:?}", other),
	};

	nodes[1].node.handle_revoke_and_ack(node_id_0, &raa_0b);
	check_added_monitors(&nodes[1], 1);

	// Step 7: stfu exchange → quiescence → re-validation fails → disconnect.
	nodes[1].node.handle_stfu(node_id_0, &stfu_0);
	let stfu_1 = get_event_msg!(nodes[1], MessageSendEvent::SendStfu, node_id_0);
	nodes[0].node.handle_stfu(node_id_1, &stfu_1);

	// handle_stfu returns WarnAndDisconnect (triggering disconnect) alongside the
	// QuiescentError containing the failed contribution's events.
	let msg_events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(msg_events.len(), 1, "{msg_events:?}");
	assert!(matches!(msg_events[0], MessageSendEvent::HandleError { .. }));

	expect_splice_failed_events(&nodes[0], &channel_id, contribution);
}

#[test]
fn test_splice_rbf_rejects_low_feerate_after_several_attempts() {
	// After several RBF attempts, the counterparty's RBF feerate must be high enough to
	// confirm (per the fee estimator). Early attempts at low feerates are accepted, but
	// once the threshold is crossed and the fee estimator expects a higher feerate, the
	// attempt is rejected.
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

	// Round 0: Initial splice-in at floor feerate (253).
	let funding_contribution = do_initiate_splice_in(&nodes[0], &nodes[1], channel_id, added_value);
	let (_, new_funding_script) =
		splice_channel(&nodes[0], &nodes[1], channel_id, funding_contribution);

	// Bump the fee estimator on node 1 (the RBF receiver) early so the feerate check
	// would reject once the threshold is crossed.
	let high_feerate = 10_000;
	*chanmon_cfgs[1].fee_estimator.sat_per_kw.lock().unwrap() = high_feerate;

	// Rounds 1-10: RBF at minimum bump. Accepted (at or below threshold).
	let mut prev_feerate = FEERATE_FLOOR_SATS_PER_KW as u64;
	for _ in 0..10 {
		let feerate = prev_feerate + 25;
		provide_utxo_reserves(&nodes, 2, added_value * 2);
		let rbf_feerate = FeeRate::from_sat_per_kwu(feerate);
		let contribution =
			do_initiate_rbf_splice_in(&nodes[0], &nodes[1], channel_id, added_value, rbf_feerate);
		complete_rbf_handshake(&nodes[0], &nodes[1]);
		complete_interactive_funding_negotiation(
			&nodes[0],
			&nodes[1],
			channel_id,
			contribution,
			new_funding_script.clone(),
		);
		let (_, splice_locked) = sign_interactive_funding_tx(&nodes[0], &nodes[1], false);
		assert!(splice_locked.is_none());
		expect_splice_pending_event(&nodes[0], &node_id_1);
		expect_splice_pending_event(&nodes[1], &node_id_0);
		prev_feerate = feerate;
	}

	// Round 11: RBF at minimum bump. Should be rejected because feerate < fee estimator.
	let next_feerate = prev_feerate + 25;
	provide_utxo_reserves(&nodes, 2, added_value * 2);
	let rbf_feerate = FeeRate::from_sat_per_kwu(next_feerate);
	let _contribution =
		do_initiate_rbf_splice_in(&nodes[0], &nodes[1], channel_id, added_value, rbf_feerate);
	let stfu_0 = get_event_msg!(nodes[0], MessageSendEvent::SendStfu, node_id_1);
	nodes[1].node.handle_stfu(node_id_0, &stfu_0);
	let stfu_1 = get_event_msg!(nodes[1], MessageSendEvent::SendStfu, node_id_0);
	nodes[0].node.handle_stfu(node_id_1, &stfu_1);

	// Node 0 sends tx_init_rbf. Node 1 rejects the low feerate after the threshold.
	let tx_init_rbf = get_event_msg!(nodes[0], MessageSendEvent::SendTxInitRbf, node_id_1);
	nodes[1].node.handle_tx_init_rbf(node_id_0, &tx_init_rbf);
	get_event_msg!(nodes[1], MessageSendEvent::SendTxAbort, node_id_0);
}

#[test]
fn test_splice_rbf_rejects_own_low_feerate_after_several_attempts() {
	// Same as test_splice_rbf_rejects_low_feerate_after_several_attempts, but for our own
	// initiated RBF. The spec requires: "MUST set a high enough feerate to ensure quick
	// confirmation." After several attempts, funding_contributed should reject our contribution
	// if the feerate is below the fee estimator's target.
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

	// Round 0: Initial splice-in at floor feerate (253).
	let funding_contribution = do_initiate_splice_in(&nodes[0], &nodes[1], channel_id, added_value);
	let (_, new_funding_script) =
		splice_channel(&nodes[0], &nodes[1], channel_id, funding_contribution);

	// Bump node 0's fee estimator early so the feerate check would reject once the
	// threshold is crossed.
	let high_feerate = 10_000;
	*chanmon_cfgs[0].fee_estimator.sat_per_kw.lock().unwrap() = high_feerate;

	// Rounds 1-10: RBF at minimum bump. Accepted (at or below threshold).
	let mut prev_feerate = FEERATE_FLOOR_SATS_PER_KW as u64;
	for _ in 0..10 {
		let feerate = prev_feerate + 25;
		provide_utxo_reserves(&nodes, 2, added_value * 2);
		let rbf_feerate = FeeRate::from_sat_per_kwu(feerate);
		let contribution =
			do_initiate_rbf_splice_in(&nodes[0], &nodes[1], channel_id, added_value, rbf_feerate);
		complete_rbf_handshake(&nodes[0], &nodes[1]);
		complete_interactive_funding_negotiation(
			&nodes[0],
			&nodes[1],
			channel_id,
			contribution,
			new_funding_script.clone(),
		);
		let (_, splice_locked) = sign_interactive_funding_tx(&nodes[0], &nodes[1], false);
		assert!(splice_locked.is_none());
		expect_splice_pending_event(&nodes[0], &node_id_1);
		expect_splice_pending_event(&nodes[1], &node_id_0);
		prev_feerate = feerate;
	}

	// Round 11: Our own RBF at minimum bump. funding_contributed should reject it.
	let next_feerate = prev_feerate + 25;
	provide_utxo_reserves(&nodes, 2, added_value * 2);
	let rbf_feerate = FeeRate::from_sat_per_kwu(next_feerate);
	let funding_template = nodes[0].node.splice_channel(&channel_id, &node_id_1).unwrap();
	let wallet = WalletSync::new(Arc::clone(&nodes[0].wallet_source), nodes[0].logger);
	let contribution =
		funding_template.splice_in_sync(added_value, rbf_feerate, FeeRate::MAX, &wallet).unwrap();

	let result = nodes[0].node.funding_contributed(&channel_id, &node_id_1, contribution, None);
	assert!(result.is_err(), "Expected rejection for low feerate: {:?}", result);

	// SpliceFailed is emitted. DiscardFunding is not emitted because all inputs/outputs
	// are filtered out (same UTXOs reused for RBF, still committed to the prior splice tx).
	let events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1, "{events:?}");
	match &events[0] {
		Event::SpliceFailed { channel_id: cid, .. } => assert_eq!(*cid, channel_id),
		other => panic!("Expected SpliceFailed, got {:?}", other),
	}
}
