// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Tests which test upgrading from previous versions of LDK or downgrading to previous versions of
//! LDK.

use lightning_0_1::commitment_signed_dance as commitment_signed_dance_0_1;
use lightning_0_1::events::ClosureReason as ClosureReason_0_1;
use lightning_0_1::expect_pending_htlcs_forwardable_ignore as expect_pending_htlcs_forwardable_ignore_0_1;
use lightning_0_1::get_monitor as get_monitor_0_1;
use lightning_0_1::ln::channelmanager::PaymentId as PaymentId_0_1;
use lightning_0_1::ln::channelmanager::RecipientOnionFields as RecipientOnionFields_0_1;
use lightning_0_1::ln::functional_test_utils as lightning_0_1_utils;
use lightning_0_1::ln::msgs::ChannelMessageHandler as _;
use lightning_0_1::routing::router as router_0_1;
use lightning_0_1::util::ser::Writeable as _;

use lightning::chain::channelmonitor::{ANTI_REORG_DELAY, HTLC_FAIL_BACK_BUFFER};
use lightning::events::bump_transaction::sync::WalletSourceSync;
use lightning::events::{ClosureReason, Event, HTLCHandlingFailureType};
use lightning::ln::functional_test_utils::*;
use lightning::ln::funding::SpliceContribution;
use lightning::ln::msgs::BaseMessageHandler as _;
use lightning::ln::msgs::ChannelMessageHandler as _;
use lightning::ln::msgs::MessageSendEvent;
use lightning::ln::splicing_tests::*;
use lightning::ln::types::ChannelId;
use lightning::sign::OutputSpender;

use lightning_types::payment::{PaymentHash, PaymentPreimage, PaymentSecret};

use bitcoin::script::Builder;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{opcodes, Amount, TxOut};

use std::sync::Arc;

#[test]
fn simple_upgrade() {
	// Tests a simple case of upgrading from LDK 0.1 with a pending payment
	let (node_a_ser, node_b_ser, mon_a_ser, mon_b_ser, preimage);
	{
		let chanmon_cfgs = lightning_0_1_utils::create_chanmon_cfgs(2);
		let node_cfgs = lightning_0_1_utils::create_node_cfgs(2, &chanmon_cfgs);
		let node_chanmgrs = lightning_0_1_utils::create_node_chanmgrs(2, &node_cfgs, &[None, None]);
		let nodes = lightning_0_1_utils::create_network(2, &node_cfgs, &node_chanmgrs);

		let chan_id = lightning_0_1_utils::create_announced_chan_between_nodes(&nodes, 0, 1).2;

		let payment_preimage =
			lightning_0_1_utils::route_payment(&nodes[0], &[&nodes[1]], 1_000_000);
		preimage = PaymentPreimage(payment_preimage.0 .0);

		node_a_ser = nodes[0].node.encode();
		node_b_ser = nodes[1].node.encode();
		mon_a_ser = get_monitor_0_1!(nodes[0], chan_id).encode();
		mon_b_ser = get_monitor_0_1!(nodes[1], chan_id).encode();
	}

	// Create a dummy node to reload over with the 0.1 state

	let mut chanmon_cfgs = create_chanmon_cfgs(2);

	// Our TestChannelSigner will fail as we're jumping ahead, so disable its state-based checks
	chanmon_cfgs[0].keys_manager.disable_all_state_policy_checks = true;
	chanmon_cfgs[1].keys_manager.disable_all_state_policy_checks = true;

	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let (persister_a, persister_b, chain_mon_a, chain_mon_b);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let (node_a, node_b);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let config = test_default_channel_config();
	let a_mons = &[&mon_a_ser[..]];
	reload_node!(nodes[0], config.clone(), &node_a_ser, a_mons, persister_a, chain_mon_a, node_a);
	reload_node!(nodes[1], config, &node_b_ser, &[&mon_b_ser], persister_b, chain_mon_b, node_b);

	reconnect_nodes(ReconnectArgs::new(&nodes[0], &nodes[1]));

	claim_payment(&nodes[0], &[&nodes[1]], preimage);
}

#[test]
fn test_0_1_legacy_remote_key_derivation() {
	// Test that a channel opened with a v1/legacy `remote_key` derivation will be properly spent
	// even after upgrading and opting into the new v2 derivation for new channels.
	let (node_a_ser, node_b_ser, mon_a_ser, mon_b_ser, commitment_tx, channel_id);
	let node_a_blocks;
	{
		let chanmon_cfgs = lightning_0_1_utils::create_chanmon_cfgs(2);
		let node_cfgs = lightning_0_1_utils::create_node_cfgs(2, &chanmon_cfgs);
		let node_chanmgrs = lightning_0_1_utils::create_node_chanmgrs(2, &node_cfgs, &[None, None]);
		let nodes = lightning_0_1_utils::create_network(2, &node_cfgs, &node_chanmgrs);

		let node_a_id = nodes[0].node.get_our_node_id();

		let chan_id = lightning_0_1_utils::create_announced_chan_between_nodes(&nodes, 0, 1).2;
		channel_id = chan_id.0;

		let err = "".to_owned();
		nodes[1].node.force_close_broadcasting_latest_txn(&chan_id, &node_a_id, err).unwrap();
		commitment_tx = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().split_off(0);
		assert_eq!(commitment_tx.len(), 1);

		lightning_0_1_utils::check_added_monitors(&nodes[1], 1);
		let reason = ClosureReason_0_1::HolderForceClosed { broadcasted_latest_txn: Some(true) };
		lightning_0_1_utils::check_closed_event(&nodes[1], 1, reason, false, &[node_a_id], 100000);
		lightning_0_1_utils::check_closed_broadcast(&nodes[1], 1, true);

		node_a_ser = nodes[0].node.encode();
		node_b_ser = nodes[1].node.encode();
		mon_a_ser = get_monitor_0_1!(nodes[0], chan_id).encode();
		mon_b_ser = get_monitor_0_1!(nodes[1], chan_id).encode();

		node_a_blocks = Arc::clone(&nodes[0].blocks);
	}

	// Create a dummy node to reload over with the 0.1 state
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let (persister_a, persister_b, chain_mon_a, chain_mon_b);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let (node_a, node_b);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let config = test_default_channel_config();
	let a_mons = &[&mon_a_ser[..]];
	reload_node!(nodes[0], config.clone(), &node_a_ser, a_mons, persister_a, chain_mon_a, node_a);
	reload_node!(nodes[1], config, &node_b_ser, &[&mon_b_ser], persister_b, chain_mon_b, node_b);

	nodes[0].blocks = node_a_blocks;

	let node_b_id = nodes[1].node.get_our_node_id();

	mine_transaction(&nodes[0], &commitment_tx[0]);
	let reason = ClosureReason::CommitmentTxConfirmed;
	check_closed_event(&nodes[0], 1, reason, false, &[node_b_id], 100_000);
	check_added_monitors(&nodes[0], 1);
	check_closed_broadcast(&nodes[0], 1, false);

	connect_blocks(&nodes[0], ANTI_REORG_DELAY - 1);
	let mut spendable_event = nodes[0].chain_monitor.chain_monitor.get_and_clear_pending_events();
	assert_eq!(spendable_event.len(), 1);
	if let Event::SpendableOutputs { outputs, channel_id: ev_id } = spendable_event.pop().unwrap() {
		assert_eq!(ev_id.unwrap().0, channel_id);
		assert_eq!(outputs.len(), 1);
		let spk = Builder::new().push_opcode(opcodes::all::OP_RETURN).into_script();
		let spend_tx = nodes[0]
			.keys_manager
			.backing
			.spend_spendable_outputs(&[&outputs[0]], Vec::new(), spk, 253, None, &Secp256k1::new())
			.unwrap();
		check_spends!(spend_tx, commitment_tx[0]);
	} else {
		panic!("Wrong event");
	}
}

fn do_test_0_1_htlc_forward_after_splice(fail_htlc: bool) {
	// Test what happens if an HTLC set to be forwarded in 0.1 is forwarded after the inbound
	// channel is spliced. In the initial splice code, this could have led to a dangling HTLC if
	// the HTLC is failed as the backwards-failure would use the channel's original SCID which is
	// no longer valid.
	// In some later splice code, this also failed because the `KeysManager` would have tried to
	// rotate the `to_remote` key, which we aren't able to do in the splicing protocol.
	let (node_a_ser, node_b_ser, node_c_ser, mon_a_1_ser, mon_b_1_ser, mon_b_2_ser, mon_c_1_ser);
	let (node_a_id, node_b_id, node_c_id);
	let (chan_id_bytes_a, chan_id_bytes_b);
	let (payment_secret_bytes, payment_hash_bytes, payment_preimage_bytes);
	let (node_a_blocks, node_b_blocks, node_c_blocks);

	const EXTRA_BLOCKS_BEFORE_FAIL: u32 = 145;

	{
		let chanmon_cfgs = lightning_0_1_utils::create_chanmon_cfgs(3);
		let node_cfgs = lightning_0_1_utils::create_node_cfgs(3, &chanmon_cfgs);
		let node_chanmgrs =
			lightning_0_1_utils::create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
		let nodes = lightning_0_1_utils::create_network(3, &node_cfgs, &node_chanmgrs);

		node_a_id = nodes[0].node.get_our_node_id();
		node_b_id = nodes[1].node.get_our_node_id();
		node_c_id = nodes[2].node.get_our_node_id();
		let chan_id_a = lightning_0_1_utils::create_announced_chan_between_nodes_with_value(
			&nodes, 0, 1, 10_000_000, 0,
		)
		.2;
		chan_id_bytes_a = chan_id_a.0;

		let chan_id_b = lightning_0_1_utils::create_announced_chan_between_nodes_with_value(
			&nodes, 1, 2, 50_000, 0,
		)
		.2;
		chan_id_bytes_b = chan_id_b.0;

		// Ensure all nodes are at the same initial height.
		let node_max_height = nodes.iter().map(|node| node.best_block_info().1).max().unwrap();
		for node in &nodes {
			let blocks_to_mine = node_max_height - node.best_block_info().1;
			if blocks_to_mine > 0 {
				lightning_0_1_utils::connect_blocks(node, blocks_to_mine);
			}
		}

		let (preimage, hash, secret) =
			lightning_0_1_utils::get_payment_preimage_hash(&nodes[2], Some(1_000_000), None);
		payment_preimage_bytes = preimage.0;
		payment_hash_bytes = hash.0;
		payment_secret_bytes = secret.0;

		let pay_params = router_0_1::PaymentParameters::from_node_id(
			node_c_id,
			lightning_0_1_utils::TEST_FINAL_CLTV,
		)
		.with_bolt11_features(nodes[2].node.bolt11_invoice_features())
		.unwrap();

		let route_params =
			router_0_1::RouteParameters::from_payment_params_and_value(pay_params, 1_000_000);
		let mut route = lightning_0_1_utils::get_route(&nodes[0], &route_params).unwrap();
		route.paths[0].hops[1].cltv_expiry_delta =
			EXTRA_BLOCKS_BEFORE_FAIL + HTLC_FAIL_BACK_BUFFER + 1;
		if fail_htlc {
			// Pay more than the channel's value (and probably not enough fee)
			route.paths[0].hops[1].fee_msat = 50_000_000;
		}

		let onion = RecipientOnionFields_0_1::secret_only(secret);
		let id = PaymentId_0_1(hash.0);
		nodes[0].node.send_payment_with_route(route, hash, onion, id).unwrap();

		lightning_0_1_utils::check_added_monitors(&nodes[0], 1);
		let send_event = lightning_0_1_utils::SendEvent::from_node(&nodes[0]);

		nodes[1].node.handle_update_add_htlc(node_a_id, &send_event.msgs[0]);
		commitment_signed_dance_0_1!(nodes[1], nodes[0], send_event.commitment_msg, false);
		expect_pending_htlcs_forwardable_ignore_0_1!(nodes[1]);

		// We now have an HTLC pending in node B's forwarding queue with the original channel's
		// SCID as the source.
		// We now upgrade to 0.2 and splice before forwarding that HTLC...
		node_a_ser = nodes[0].node.encode();
		node_b_ser = nodes[1].node.encode();
		node_c_ser = nodes[2].node.encode();
		mon_a_1_ser = get_monitor_0_1!(nodes[0], chan_id_a).encode();
		mon_b_1_ser = get_monitor_0_1!(nodes[1], chan_id_a).encode();
		mon_b_2_ser = get_monitor_0_1!(nodes[1], chan_id_b).encode();
		mon_c_1_ser = get_monitor_0_1!(nodes[2], chan_id_b).encode();

		node_a_blocks = Arc::clone(&nodes[0].blocks);
		node_b_blocks = Arc::clone(&nodes[1].blocks);
		node_c_blocks = Arc::clone(&nodes[2].blocks);
	}

	// Create a dummy node to reload over with the 0.1 state
	let mut chanmon_cfgs = create_chanmon_cfgs(3);

	// Our TestChannelSigner will fail as we're jumping ahead, so disable its state-based checks
	chanmon_cfgs[0].keys_manager.disable_all_state_policy_checks = true;
	chanmon_cfgs[1].keys_manager.disable_all_state_policy_checks = true;
	chanmon_cfgs[2].keys_manager.disable_all_state_policy_checks = true;

	chanmon_cfgs[0].tx_broadcaster.blocks = node_a_blocks;
	chanmon_cfgs[1].tx_broadcaster.blocks = node_b_blocks;
	chanmon_cfgs[2].tx_broadcaster.blocks = node_c_blocks;

	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let (persister_a, persister_b, persister_c, chain_mon_a, chain_mon_b, chain_mon_c);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let (node_a, node_b, node_c);
	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	let config = test_default_channel_config();
	let a_mons = &[&mon_a_1_ser[..]];
	reload_node!(nodes[0], config.clone(), &node_a_ser, a_mons, persister_a, chain_mon_a, node_a);
	let b_mons = &[&mon_b_1_ser[..], &mon_b_2_ser[..]];
	reload_node!(nodes[1], config.clone(), &node_b_ser, b_mons, persister_b, chain_mon_b, node_b);
	let c_mons = &[&mon_c_1_ser[..]];
	reload_node!(nodes[2], config, &node_c_ser, c_mons, persister_c, chain_mon_c, node_c);

	reconnect_nodes(ReconnectArgs::new(&nodes[0], &nodes[1]));
	let mut reconnect_b_c_args = ReconnectArgs::new(&nodes[1], &nodes[2]);
	reconnect_b_c_args.send_channel_ready = (true, true);
	reconnect_b_c_args.send_announcement_sigs = (true, true);
	reconnect_nodes(reconnect_b_c_args);

	let contribution = SpliceContribution::SpliceOut {
		outputs: vec![TxOut {
			value: Amount::from_sat(1_000),
			script_pubkey: nodes[0].wallet_source.get_change_script().unwrap(),
		}],
	};
	let splice_tx = splice_channel(&nodes[0], &nodes[1], ChannelId(chan_id_bytes_a), contribution);
	for node in nodes.iter() {
		mine_transaction(node, &splice_tx);
		connect_blocks(node, ANTI_REORG_DELAY - 1);
	}

	let splice_locked = get_event_msg!(nodes[0], MessageSendEvent::SendSpliceLocked, node_b_id);
	lock_splice(&nodes[0], &nodes[1], &splice_locked, false);

	for node in nodes.iter() {
		connect_blocks(node, EXTRA_BLOCKS_BEFORE_FAIL - ANTI_REORG_DELAY);
	}

	// Now release the HTLC to be failed back to node A
	nodes[1].node.process_pending_htlc_forwards();

	let pay_secret = PaymentSecret(payment_secret_bytes);
	let pay_hash = PaymentHash(payment_hash_bytes);
	let pay_preimage = PaymentPreimage(payment_preimage_bytes);

	if fail_htlc {
		let failure = HTLCHandlingFailureType::Forward {
			node_id: Some(node_c_id),
			channel_id: ChannelId(chan_id_bytes_b),
		};
		expect_and_process_pending_htlcs_and_htlc_handling_failed(&nodes[1], &[failure]);
		check_added_monitors(&nodes[1], 1);

		let updates = get_htlc_update_msgs(&nodes[1], &node_a_id);
		nodes[0].node.handle_update_fail_htlc(node_b_id, &updates.update_fail_htlcs[0]);
		commitment_signed_dance!(nodes[0], nodes[1], updates.commitment_signed, false);
		let conditions = PaymentFailedConditions::new();
		expect_payment_failed_conditions(&nodes[0], pay_hash, false, conditions);
	} else {
		check_added_monitors(&nodes[1], 1);
		let forward_event = SendEvent::from_node(&nodes[1]);
		nodes[2].node.handle_update_add_htlc(node_b_id, &forward_event.msgs[0]);
		commitment_signed_dance!(nodes[2], nodes[1], forward_event.commitment_msg, false);

		expect_and_process_pending_htlcs(&nodes[2], false);
		expect_payment_claimable!(nodes[2], pay_hash, pay_secret, 1_000_000);
		claim_payment(&nodes[0], &[&nodes[1], &nodes[2]], pay_preimage);
	}
}

#[test]
fn test_0_1_htlc_forward_after_splice() {
	do_test_0_1_htlc_forward_after_splice(true);
	do_test_0_1_htlc_forward_after_splice(false);
}
