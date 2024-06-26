// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Further functional tests which test blockchain reorganizations.

use crate::chain::chaininterface::LowerBoundedFeeEstimator;
use crate::chain::channelmonitor::{ANTI_REORG_DELAY, LATENCY_GRACE_PERIOD_BLOCKS};
use crate::chain::transaction::OutPoint;
use crate::chain::Confirm;
use crate::events::{Event, MessageSendEventsProvider, ClosureReason, HTLCDestination, MessageSendEvent};
use crate::ln::msgs::{ChannelMessageHandler, Init};
use crate::ln::types::ChannelId;
use crate::sign::OutputSpender;
use crate::util::test_utils;
use crate::util::ser::Writeable;
use crate::util::string::UntrustedString;

use bitcoin::script::Builder;
use bitcoin::opcodes;
use bitcoin::secp256k1::Secp256k1;

use crate::prelude::*;

use crate::ln::functional_test_utils::*;

fn do_test_onchain_htlc_reorg(local_commitment: bool, claim: bool) {
	// Our on-chain HTLC-claim learning has a few properties worth testing:
	//  * If an upstream HTLC is claimed with a preimage (both against our own commitment
	//    transaction our counterparty's), we claim it backwards immediately.
	//  * If an upstream HTLC is claimed with a timeout, we delay ANTI_REORG_DELAY before failing
	//    it backwards to ensure our counterparty can't claim with a preimage in a reorg.
	//
	// Here we test both properties in any combination based on the two bools passed in as
	// arguments.
	//
	// If local_commitment is set, we first broadcast a local commitment containing an offered HTLC
	// and an HTLC-Timeout tx, otherwise we broadcast a remote commitment containing a received
	// HTLC and a local HTLC-Timeout tx spending it.
	//
	// We then either allow these transactions to confirm (if !claim) or we wait until one block
	// before they otherwise would and reorg them out, confirming an HTLC-Success tx instead.
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	create_announced_chan_between_nodes(&nodes, 0, 1);
	let chan_2 = create_announced_chan_between_nodes(&nodes, 1, 2);

	// Make sure all nodes are at the same starting height
	connect_blocks(&nodes[0], 2*CHAN_CONFIRM_DEPTH + 1 - nodes[0].best_block_info().1);
	connect_blocks(&nodes[1], 2*CHAN_CONFIRM_DEPTH + 1 - nodes[1].best_block_info().1);
	connect_blocks(&nodes[2], 2*CHAN_CONFIRM_DEPTH + 1 - nodes[2].best_block_info().1);

	let (our_payment_preimage, our_payment_hash, ..) = route_payment(&nodes[0], &[&nodes[1], &nodes[2]], 1_000_000);

	// Provide preimage to node 2 by claiming payment
	nodes[2].node.claim_funds(our_payment_preimage);
	expect_payment_claimed!(nodes[2], our_payment_hash, 1_000_000);
	check_added_monitors!(nodes[2], 1);
	get_htlc_update_msgs!(nodes[2], nodes[1].node.get_our_node_id());

	let claim_txn = if local_commitment {
		// Broadcast node 1 commitment txn to broadcast the HTLC-Timeout
		let node_1_commitment_txn = get_local_commitment_txn!(nodes[1], chan_2.2);
		assert_eq!(node_1_commitment_txn.len(), 2); // 1 local commitment tx, 1 Outbound HTLC-Timeout
		assert_eq!(node_1_commitment_txn[0].output.len(), 2); // to-self and Offered HTLC (to-remote/to-node-3 is dust)
		check_spends!(node_1_commitment_txn[0], chan_2.3);
		check_spends!(node_1_commitment_txn[1], node_1_commitment_txn[0]);

		// Give node 2 node 1's transactions and get its response (claiming the HTLC instead).
		connect_block(&nodes[2], &create_dummy_block(nodes[2].best_block_hash(), 42, node_1_commitment_txn.clone()));
		check_added_monitors!(nodes[2], 1);
		check_closed_broadcast!(nodes[2], true); // We should get a BroadcastChannelUpdate (and *only* a BroadcstChannelUpdate)
		check_closed_event!(nodes[2], 1, ClosureReason::CommitmentTxConfirmed, [nodes[1].node.get_our_node_id()], 100000);
		let node_2_commitment_txn = nodes[2].tx_broadcaster.txn_broadcasted.lock().unwrap().split_off(0);
		assert_eq!(node_2_commitment_txn.len(), 1); // ChannelMonitor: 1 offered HTLC-Claim
		check_spends!(node_2_commitment_txn[0], node_1_commitment_txn[0]);

		// Make sure node 1's height is the same as the !local_commitment case
		connect_blocks(&nodes[1], 1);
		// Confirm node 1's commitment txn (and HTLC-Timeout) on node 1
		connect_block(&nodes[1], &create_dummy_block(nodes[1].best_block_hash(), 42, node_1_commitment_txn.clone()));

		// ...but return node 1's commitment tx in case claim is set and we're preparing to reorg
		vec![node_1_commitment_txn[0].clone(), node_2_commitment_txn[0].clone()]
	} else {
		// Broadcast node 2 commitment txn
		let mut node_2_commitment_txn = get_local_commitment_txn!(nodes[2], chan_2.2);
		assert_eq!(node_2_commitment_txn.len(), 2); // 1 local commitment tx, 1 Received HTLC-Claim
		assert_eq!(node_2_commitment_txn[0].output.len(), 2); // to-remote and Received HTLC (to-self is dust)
		check_spends!(node_2_commitment_txn[0], chan_2.3);
		check_spends!(node_2_commitment_txn[1], node_2_commitment_txn[0]);

		// Give node 1 node 2's commitment transaction and get its response (timing the HTLC out)
		mine_transaction(&nodes[1], &node_2_commitment_txn[0]);
		connect_blocks(&nodes[1], TEST_FINAL_CLTV); // Confirm blocks until the HTLC expires
		let node_1_commitment_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().clone();
		assert_eq!(node_1_commitment_txn.len(), 1); // ChannelMonitor: 1 offered HTLC-Timeout
		check_spends!(node_1_commitment_txn[0], node_2_commitment_txn[0]);

		// Confirm node 1's HTLC-Timeout on node 1
		mine_transaction(&nodes[1], &node_1_commitment_txn[0]);
		// ...but return node 2's commitment tx (and claim) in case claim is set and we're preparing to reorg
		vec![node_2_commitment_txn.pop().unwrap()]
	};
	check_added_monitors!(nodes[1], 1);
	check_closed_broadcast!(nodes[1], true); // We should get a BroadcastChannelUpdate (and *only* a BroadcstChannelUpdate)
	check_closed_event!(nodes[1], 1, ClosureReason::CommitmentTxConfirmed, [nodes[2].node.get_our_node_id()], 100000);
	// Connect ANTI_REORG_DELAY - 2 blocks, giving us a confirmation count of ANTI_REORG_DELAY - 1.
	connect_blocks(&nodes[1], ANTI_REORG_DELAY - 2);
	check_added_monitors!(nodes[1], 0);
	assert_eq!(nodes[1].node.get_and_clear_pending_events().len(), 0);

	if claim {
		// Disconnect Node 1's HTLC-Timeout which was connected above
		disconnect_blocks(&nodes[1], ANTI_REORG_DELAY - 1);

		connect_block(&nodes[1], &create_dummy_block(nodes[1].best_block_hash(), 42, claim_txn));

		// ChannelManager only polls chain::Watch::release_pending_monitor_events when we
		// probe it for events, so we probe non-message events here (which should just be the
		// PaymentForwarded event).
		expect_payment_forwarded!(nodes[1], nodes[0], nodes[2], Some(1000), true, true);
	} else {
		// Confirm the timeout tx and check that we fail the HTLC backwards
		connect_block(&nodes[1], &create_dummy_block(nodes[1].best_block_hash(), 42, Vec::new()));
		expect_pending_htlcs_forwardable_and_htlc_handling_failed!(nodes[1], vec![HTLCDestination::NextHopChannel { node_id: Some(nodes[2].node.get_our_node_id()), channel_id: chan_2.2 }]);
	}

	check_added_monitors!(nodes[1], 1);
	// Which should result in an immediate claim/fail of the HTLC:
	let htlc_updates = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	if claim {
		assert_eq!(htlc_updates.update_fulfill_htlcs.len(), 1);
		nodes[0].node.handle_update_fulfill_htlc(&nodes[1].node.get_our_node_id(), &htlc_updates.update_fulfill_htlcs[0]);
	} else {
		assert_eq!(htlc_updates.update_fail_htlcs.len(), 1);
		nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &htlc_updates.update_fail_htlcs[0]);
	}
	commitment_signed_dance!(nodes[0], nodes[1], htlc_updates.commitment_signed, false, true);
	if claim {
		expect_payment_sent!(nodes[0], our_payment_preimage);
	} else {
		expect_payment_failed_with_update!(nodes[0], our_payment_hash, false, chan_2.0.contents.short_channel_id, true);
	}
}

#[test]
fn test_onchain_htlc_claim_reorg_local_commitment() {
	do_test_onchain_htlc_reorg(true, true);
}
#[test]
fn test_onchain_htlc_timeout_delay_local_commitment() {
	do_test_onchain_htlc_reorg(true, false);
}
#[test]
fn test_onchain_htlc_claim_reorg_remote_commitment() {
	do_test_onchain_htlc_reorg(false, true);
}
#[test]
fn test_onchain_htlc_timeout_delay_remote_commitment() {
	do_test_onchain_htlc_reorg(false, false);
}

#[test]
fn test_counterparty_revoked_reorg() {
	// Test what happens when a revoked counterparty transaction is broadcast but then reorg'd out
	// of the main chain. Specifically, HTLCs in the latest commitment transaction which are not
	// included in the revoked commitment transaction should not be considered failed, and should
	// still be claim-from-able after the reorg.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 500_000_000);

	// Get the initial commitment transaction for broadcast, before any HTLCs are added at all.
	let revoked_local_txn = get_local_commitment_txn!(nodes[0], chan.2);
	assert_eq!(revoked_local_txn.len(), 1);

	// Now add two HTLCs in each direction, one dust and one not.
	route_payment(&nodes[0], &[&nodes[1]], 5_000_000);
	route_payment(&nodes[0], &[&nodes[1]], 5_000);
	let (payment_preimage_3, payment_hash_3, ..) = route_payment(&nodes[1], &[&nodes[0]], 4_000_000);
	let payment_hash_4 = route_payment(&nodes[1], &[&nodes[0]], 4_000).1;

	nodes[0].node.claim_funds(payment_preimage_3);
	let _ = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	check_added_monitors!(nodes[0], 1);
	expect_payment_claimed!(nodes[0], payment_hash_3, 4_000_000);

	let mut unrevoked_local_txn = get_local_commitment_txn!(nodes[0], chan.2);
	assert_eq!(unrevoked_local_txn.len(), 3); // commitment + 2 HTLC txn
	// Sort the unrevoked transactions in reverse order, ie commitment tx, then HTLC 1 then HTLC 3
	unrevoked_local_txn.sort_unstable_by_key(|tx| 1_000_000 - tx.output.iter().map(|outp| outp.value.to_sat()).sum::<u64>());

	// Now mine A's old commitment transaction, which should close the channel, but take no action
	// on any of the HTLCs, at least until we get six confirmations (which we won't get).
	mine_transaction(&nodes[1], &revoked_local_txn[0]);
	check_added_monitors!(nodes[1], 1);
	check_closed_event!(nodes[1], 1, ClosureReason::CommitmentTxConfirmed, [nodes[0].node.get_our_node_id()], 1000000);
	check_closed_broadcast!(nodes[1], true);

	// Connect up to one block before the revoked transaction would be considered final, then do a
	// reorg that disconnects the full chain and goes up to the height at which the revoked
	// transaction would be final.
	let theoretical_conf_height = nodes[1].best_block_info().1 + ANTI_REORG_DELAY - 1;
	connect_blocks(&nodes[1], ANTI_REORG_DELAY - 2);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	assert!(nodes[1].node.get_and_clear_pending_events().is_empty());

	disconnect_all_blocks(&nodes[1]);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	assert!(nodes[1].node.get_and_clear_pending_events().is_empty());

	connect_blocks(&nodes[1], theoretical_conf_height);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	assert!(nodes[1].node.get_and_clear_pending_events().is_empty());

	// Now connect A's latest commitment transaction instead and resolve the HTLCs
	mine_transaction(&nodes[1], &unrevoked_local_txn[0]);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	assert!(nodes[1].node.get_and_clear_pending_events().is_empty());

	// Connect the HTLC claim transaction for HTLC 3
	mine_transaction(&nodes[1], &unrevoked_local_txn[2]);
	expect_payment_sent(&nodes[1], payment_preimage_3, None, true, false);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	// Connect blocks to confirm the unrevoked commitment transaction
	connect_blocks(&nodes[1], ANTI_REORG_DELAY - 2);
	expect_payment_failed!(nodes[1], payment_hash_4, false);
}

fn do_test_unconf_chan(reload_node: bool, reorg_after_reload: bool, use_funding_unconfirmed: bool, connect_style: ConnectStyle) {
	// After creating a chan between nodes, we disconnect all blocks previously seen to force a
	// channel close on nodes[0] side. We also use this to provide very basic testing of logic
	// around freeing background events which store monitor updates during block_[dis]connected.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let persister;
	let new_chain_monitor;

	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes_0_deserialized;

	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	*nodes[0].connect_style.borrow_mut() = connect_style;

	let chan_conf_height = core::cmp::max(nodes[0].best_block_info().1 + 1, nodes[1].best_block_info().1 + 1);
	let chan = create_announced_chan_between_nodes(&nodes, 0, 1);

	{
		let per_peer_state = nodes[0].node.per_peer_state.read().unwrap();
		let peer_state = per_peer_state.get(&nodes[1].node.get_our_node_id()).unwrap().lock().unwrap();
		assert_eq!(peer_state.channel_by_id.len(), 1);
		assert_eq!(nodes[0].node.short_to_chan_info.read().unwrap().len(), 2);
	}

	assert_eq!(nodes[0].node.list_channels()[0].confirmations, Some(10));
	assert_eq!(nodes[1].node.list_channels()[0].confirmations, Some(10));

	if !reorg_after_reload {
		if use_funding_unconfirmed {
			let relevant_txids = nodes[0].node.get_relevant_txids();
			assert_eq!(relevant_txids.len(), 1);
			let block_hash_opt = relevant_txids[0].2;
			let expected_hash = nodes[0].get_block_header(chan_conf_height).block_hash();
			assert_eq!(relevant_txids[0].1, chan_conf_height);
			assert_eq!(block_hash_opt, Some(expected_hash));
			let txid = relevant_txids[0].0;
			assert_eq!(txid, chan.3.txid());
			nodes[0].node.transaction_unconfirmed(&txid);
			assert_eq!(nodes[0].node.list_usable_channels().len(), 0);
		} else if connect_style == ConnectStyle::FullBlockViaListen {
			disconnect_blocks(&nodes[0], CHAN_CONFIRM_DEPTH - 1);
			assert_eq!(nodes[0].node.list_usable_channels().len(), 1);
			assert_eq!(nodes[0].node.list_channels()[0].confirmations, Some(1));
			disconnect_blocks(&nodes[0], 1);
			assert_eq!(nodes[0].node.list_usable_channels().len(), 0);
		} else {
			disconnect_all_blocks(&nodes[0]);
			assert_eq!(nodes[0].node.list_usable_channels().len(), 0);
		}

		let relevant_txids = nodes[0].node.get_relevant_txids();
		assert_eq!(relevant_txids.len(), 0);

		{
			let per_peer_state = nodes[0].node.per_peer_state.read().unwrap();
			let peer_state = per_peer_state.get(&nodes[1].node.get_our_node_id()).unwrap().lock().unwrap();
			assert_eq!(peer_state.channel_by_id.len(), 0);
			assert_eq!(nodes[0].node.short_to_chan_info.read().unwrap().len(), 0);
		}
	}

	if reload_node {
		// Since we currently have a background event pending, it's good to test that we survive a
		// serialization roundtrip. Further, this tests the somewhat awkward edge-case of dropping
		// the Channel object from the ChannelManager, but still having a monitor event pending for
		// it when we go to deserialize, and then use the ChannelManager.
		let nodes_0_serialized = nodes[0].node.encode();
		let chan_0_monitor_serialized = get_monitor!(nodes[0], chan.2).encode();

		reload_node!(nodes[0], *nodes[0].node.get_current_default_configuration(), &nodes_0_serialized, &[&chan_0_monitor_serialized], persister, new_chain_monitor, nodes_0_deserialized);
		assert!(nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().is_empty());
	}

	if reorg_after_reload {
		if use_funding_unconfirmed {
			let relevant_txids = nodes[0].node.get_relevant_txids();
			assert_eq!(relevant_txids.len(), 1);
			let block_hash_opt = relevant_txids[0].2;
			let expected_hash = nodes[0].get_block_header(chan_conf_height).block_hash();
			assert_eq!(chan_conf_height, relevant_txids[0].1);
			assert_eq!(block_hash_opt, Some(expected_hash));
			let txid = relevant_txids[0].0;
			assert_eq!(txid, chan.3.txid());
			nodes[0].node.transaction_unconfirmed(&txid);
			assert_eq!(nodes[0].node.list_channels().len(), 0);
		} else if connect_style == ConnectStyle::FullBlockViaListen {
			disconnect_blocks(&nodes[0], CHAN_CONFIRM_DEPTH - 1);
			assert_eq!(nodes[0].node.list_channels().len(), 1);
			assert_eq!(nodes[0].node.list_channels()[0].confirmations, Some(1));
			disconnect_blocks(&nodes[0], 1);
			assert_eq!(nodes[0].node.list_usable_channels().len(), 0);
		} else {
			disconnect_all_blocks(&nodes[0]);
			assert_eq!(nodes[0].node.list_usable_channels().len(), 0);
		}

		let relevant_txids = nodes[0].node.get_relevant_txids();
		assert_eq!(relevant_txids.len(), 0);

		{
			let per_peer_state = nodes[0].node.per_peer_state.read().unwrap();
			let peer_state = per_peer_state.get(&nodes[1].node.get_our_node_id()).unwrap().lock().unwrap();
			assert_eq!(peer_state.channel_by_id.len(), 0);
			assert_eq!(nodes[0].node.short_to_chan_info.read().unwrap().len(), 0);
		}
	}
	// With expect_channel_force_closed set the TestChainMonitor will enforce that the next update
	// is a ChannelForcClosed on the right channel with should_broadcast set.
	*nodes[0].chain_monitor.expect_channel_force_closed.lock().unwrap() = Some((chan.2, true));
	nodes[0].node.test_process_background_events(); // Required to free the pending background monitor update
	check_added_monitors!(nodes[0], 1);
	let expected_err = "Funding transaction was un-confirmed. Locked at 6 confs, now have 0 confs.";
	if reorg_after_reload || !reload_node {
		handle_announce_close_broadcast_events(&nodes, 0, 1, true, "Channel closed because of an exception: Funding transaction was un-confirmed. Locked at 6 confs, now have 0 confs.");
		check_added_monitors!(nodes[1], 1);
		check_closed_event!(nodes[1], 1, ClosureReason::CounterpartyForceClosed { peer_msg: UntrustedString(format!("Channel closed because of an exception: {}", expected_err)) }
			, [nodes[0].node.get_our_node_id()], 100000);
	}

	check_closed_event!(nodes[0], 1, ClosureReason::ProcessingError { err: expected_err.to_owned() },
		[nodes[1].node.get_our_node_id()], 100000);
	assert_eq!(nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().len(), 1);
	nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().clear();

	// Now check that we can create a new channel
	if reload_node && nodes[0].node.per_peer_state.read().unwrap().len() == 0 {
		// If we dropped the channel before reloading the node, nodes[1] was also dropped from
		// nodes[0] storage, and hence not connected again on startup. We therefore need to
		// reconnect to the node before attempting to create a new channel.
		nodes[0].node.peer_connected(&nodes[1].node.get_our_node_id(), &Init {
			features: nodes[1].node.init_features(), networks: None, remote_network_address: None
		}, true).unwrap();
	}
	create_announced_chan_between_nodes(&nodes, 0, 1);
	send_payment(&nodes[0], &[&nodes[1]], 8000000);
}

#[test]
fn test_unconf_chan() {
	do_test_unconf_chan(true, true, false, ConnectStyle::BestBlockFirstSkippingBlocks);
	do_test_unconf_chan(false, true, false, ConnectStyle::BestBlockFirstSkippingBlocks);
	do_test_unconf_chan(true, false, false, ConnectStyle::BestBlockFirstSkippingBlocks);
	do_test_unconf_chan(false, false, false, ConnectStyle::BestBlockFirstSkippingBlocks);

	do_test_unconf_chan(true, true, false, ConnectStyle::BestBlockFirstReorgsOnlyTip);
	do_test_unconf_chan(false, true, false, ConnectStyle::BestBlockFirstReorgsOnlyTip);
	do_test_unconf_chan(true, false, false, ConnectStyle::BestBlockFirstReorgsOnlyTip);
	do_test_unconf_chan(false, false, false, ConnectStyle::BestBlockFirstReorgsOnlyTip);
}

#[test]
fn test_unconf_chan_via_listen() {
	do_test_unconf_chan(true, true, false, ConnectStyle::FullBlockViaListen);
	do_test_unconf_chan(false, true, false, ConnectStyle::FullBlockViaListen);
	do_test_unconf_chan(true, false, false, ConnectStyle::FullBlockViaListen);
	do_test_unconf_chan(false, false, false, ConnectStyle::FullBlockViaListen);
}

#[test]
fn test_unconf_chan_via_funding_unconfirmed() {
	do_test_unconf_chan(true, true, true, ConnectStyle::BestBlockFirstSkippingBlocks);
	do_test_unconf_chan(false, true, true, ConnectStyle::BestBlockFirstSkippingBlocks);
	do_test_unconf_chan(true, false, true, ConnectStyle::BestBlockFirstSkippingBlocks);
	do_test_unconf_chan(false, false, true, ConnectStyle::BestBlockFirstSkippingBlocks);

	do_test_unconf_chan(true, true, true, ConnectStyle::BestBlockFirstReorgsOnlyTip);
	do_test_unconf_chan(false, true, true, ConnectStyle::BestBlockFirstReorgsOnlyTip);
	do_test_unconf_chan(true, false, true, ConnectStyle::BestBlockFirstReorgsOnlyTip);
	do_test_unconf_chan(false, false, true, ConnectStyle::BestBlockFirstReorgsOnlyTip);

	do_test_unconf_chan(true, true, true, ConnectStyle::FullBlockViaListen);
	do_test_unconf_chan(false, true, true, ConnectStyle::FullBlockViaListen);
	do_test_unconf_chan(true, false, true, ConnectStyle::FullBlockViaListen);
	do_test_unconf_chan(false, false, true, ConnectStyle::FullBlockViaListen);
}

#[test]
fn test_set_outpoints_partial_claiming() {
	// - remote party claim tx, new bump tx
	// - disconnect remote claiming tx, new bump
	// - disconnect tx, see no tx anymore
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1000000, 59000000);
	let (payment_preimage_1, payment_hash_1, ..) = route_payment(&nodes[1], &[&nodes[0]], 3_000_000);
	let (payment_preimage_2, payment_hash_2, ..) = route_payment(&nodes[1], &[&nodes[0]], 3_000_000);

	// Remote commitment txn with 4 outputs: to_local, to_remote, 2 outgoing HTLC
	let remote_txn = get_local_commitment_txn!(nodes[1], chan.2);
	assert_eq!(remote_txn.len(), 3);
	assert_eq!(remote_txn[0].output.len(), 4);
	assert_eq!(remote_txn[0].input.len(), 1);
	assert_eq!(remote_txn[0].input[0].previous_output.txid, chan.3.txid());
	check_spends!(remote_txn[1], remote_txn[0]);
	check_spends!(remote_txn[2], remote_txn[0]);

	// Connect blocks on node A to advance height towards TEST_FINAL_CLTV
	// Provide node A with both preimage
	nodes[0].node.claim_funds(payment_preimage_1);
	expect_payment_claimed!(nodes[0], payment_hash_1, 3_000_000);
	nodes[0].node.claim_funds(payment_preimage_2);
	expect_payment_claimed!(nodes[0], payment_hash_2, 3_000_000);
	check_added_monitors!(nodes[0], 2);
	nodes[0].node.get_and_clear_pending_msg_events();

	// Connect blocks on node A commitment transaction
	mine_transaction(&nodes[0], &remote_txn[0]);
	check_closed_broadcast!(nodes[0], true);
	check_closed_event!(nodes[0], 1, ClosureReason::CommitmentTxConfirmed, [nodes[1].node.get_our_node_id()], 1000000);
	check_added_monitors!(nodes[0], 1);
	// Verify node A broadcast tx claiming both HTLCs
	{
		let mut node_txn = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap();
		// ChannelMonitor: claim tx
		assert_eq!(node_txn.len(), 1);
		check_spends!(node_txn[0], remote_txn[0]);
		assert_eq!(node_txn[0].input.len(), 2);
		node_txn.clear();
	}

	// Connect blocks on node B
	connect_blocks(&nodes[1], TEST_FINAL_CLTV + LATENCY_GRACE_PERIOD_BLOCKS + 1);
	check_closed_broadcast!(nodes[1], true);
	check_closed_event!(nodes[1], 1, ClosureReason::HTLCsTimedOut, [nodes[0].node.get_our_node_id()], 1000000);
	check_added_monitors!(nodes[1], 1);
	// Verify node B broadcast 2 HTLC-timeout txn
	let partial_claim_tx = {
		let mut node_txn = nodes[1].tx_broadcaster.unique_txn_broadcast();
		assert_eq!(node_txn.len(), 3);
		check_spends!(node_txn[0], chan.3);
		check_spends!(node_txn[1], node_txn[0]);
		check_spends!(node_txn[2], node_txn[0]);
		assert_eq!(node_txn[1].input.len(), 1);
		assert_eq!(node_txn[2].input.len(), 1);
		assert_ne!(node_txn[1].input[0].previous_output, node_txn[2].input[0].previous_output);
		node_txn.remove(1)
	};

	// Broadcast partial claim on node A, should regenerate a claiming tx with HTLC dropped
	mine_transaction(&nodes[0], &partial_claim_tx);
	{
		let mut node_txn = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap();
		assert_eq!(node_txn.len(), 1);
		check_spends!(node_txn[0], remote_txn[0]);
		assert_eq!(node_txn[0].input.len(), 1); //dropped HTLC
		node_txn.clear();
	}
	nodes[0].node.get_and_clear_pending_msg_events();

	// Disconnect last block on node A, should regenerate a claiming tx with HTLC dropped
	disconnect_blocks(&nodes[0], 1);
	{
		let mut node_txn = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap();
		assert_eq!(node_txn.len(), 1);
		check_spends!(node_txn[0], remote_txn[0]);
		assert_eq!(node_txn[0].input.len(), 2); //resurrected HTLC
		node_txn.clear();
	}

	//// Disconnect one more block and then reconnect multiple no transaction should be generated
	disconnect_blocks(&nodes[0], 1);
	connect_blocks(&nodes[0], 15);
	{
		let mut node_txn = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap();
		assert_eq!(node_txn.len(), 0);
		node_txn.clear();
	}
}

fn do_test_to_remote_after_local_detection(style: ConnectStyle) {
	// In previous code, detection of to_remote outputs in a counterparty commitment transaction
	// was dependent on whether a local commitment transaction had been seen on-chain previously.
	// This resulted in some edge cases around not being able to generate a SpendableOutput event
	// after a reorg.
	//
	// Here, we test this by first confirming one set of commitment transactions, then
	// disconnecting them and reconnecting another. We then confirm them and check that the correct
	// SpendableOutput event is generated.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	*nodes[0].connect_style.borrow_mut() = style;
	*nodes[1].connect_style.borrow_mut() = style;

	let (_, _, chan_id, funding_tx) =
		create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 100_000_000);
	let funding_outpoint = OutPoint { txid: funding_tx.txid(), index: 0 };
	assert_eq!(ChannelId::v1_from_funding_outpoint(funding_outpoint), chan_id);

	let remote_txn_a = get_local_commitment_txn!(nodes[0], chan_id);
	let remote_txn_b = get_local_commitment_txn!(nodes[1], chan_id);

	mine_transaction(&nodes[0], &remote_txn_a[0]);
	mine_transaction(&nodes[1], &remote_txn_a[0]);

	assert!(nodes[0].node.list_channels().is_empty());
	check_closed_broadcast!(nodes[0], true);
	check_added_monitors!(nodes[0], 1);
	check_closed_event!(nodes[0], 1, ClosureReason::CommitmentTxConfirmed, [nodes[1].node.get_our_node_id()], 1000000);
	assert!(nodes[1].node.list_channels().is_empty());
	check_closed_broadcast!(nodes[1], true);
	check_added_monitors!(nodes[1], 1);
	check_closed_event!(nodes[1], 1, ClosureReason::CommitmentTxConfirmed, [nodes[0].node.get_our_node_id()], 1000000);

	assert!(nodes[0].chain_monitor.chain_monitor.get_and_clear_pending_events().is_empty());
	assert!(nodes[1].chain_monitor.chain_monitor.get_and_clear_pending_events().is_empty());

	disconnect_blocks(&nodes[0], 1);
	disconnect_blocks(&nodes[1], 1);

	assert!(nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().is_empty());
	assert!(nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().is_empty());
	assert!(nodes[0].chain_monitor.chain_monitor.get_and_clear_pending_events().is_empty());
	assert!(nodes[1].chain_monitor.chain_monitor.get_and_clear_pending_events().is_empty());

	connect_blocks(&nodes[0], ANTI_REORG_DELAY - 1);
	connect_blocks(&nodes[1], ANTI_REORG_DELAY - 1);

	assert!(nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().is_empty());
	assert!(nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().is_empty());
	assert!(nodes[0].chain_monitor.chain_monitor.get_and_clear_pending_events().is_empty());
	assert!(nodes[1].chain_monitor.chain_monitor.get_and_clear_pending_events().is_empty());

	mine_transaction(&nodes[0], &remote_txn_b[0]);
	mine_transaction(&nodes[1], &remote_txn_b[0]);

	assert!(nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().is_empty());
	assert!(nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().is_empty());
	assert!(nodes[0].chain_monitor.chain_monitor.get_and_clear_pending_events().is_empty());
	assert!(nodes[1].chain_monitor.chain_monitor.get_and_clear_pending_events().is_empty());

	connect_blocks(&nodes[0], ANTI_REORG_DELAY - 1);
	connect_blocks(&nodes[1], ANTI_REORG_DELAY - 1);

	let mut node_a_spendable = nodes[0].chain_monitor.chain_monitor.get_and_clear_pending_events();
	assert_eq!(node_a_spendable.len(), 1);
	if let Event::SpendableOutputs { outputs, channel_id } = node_a_spendable.pop().unwrap() {
		assert_eq!(outputs.len(), 1);
		assert_eq!(channel_id, Some(chan_id));
		let spend_tx = nodes[0].keys_manager.backing.spend_spendable_outputs(&[&outputs[0]], Vec::new(),
			Builder::new().push_opcode(opcodes::all::OP_RETURN).into_script(), 253, None, &Secp256k1::new()).unwrap();
		check_spends!(spend_tx, remote_txn_b[0]);
	}

	// nodes[1] is waiting for the to_self_delay to expire, which is many more than
	// ANTI_REORG_DELAY. Instead, walk it back and confirm the original remote_txn_a commitment
	// again and check that nodes[1] generates a similar spendable output.
	// Technically a reorg of ANTI_REORG_DELAY violates our assumptions, so this is undefined by
	// our API spec, but we currently handle this correctly and there's little reason we shouldn't
	// in the future.
	assert!(nodes[1].chain_monitor.chain_monitor.get_and_clear_pending_events().is_empty());
	disconnect_blocks(&nodes[1], ANTI_REORG_DELAY);
	mine_transaction(&nodes[1], &remote_txn_a[0]);
	connect_blocks(&nodes[1], ANTI_REORG_DELAY - 1);

	let mut node_b_spendable = nodes[1].chain_monitor.chain_monitor.get_and_clear_pending_events();
	assert_eq!(node_b_spendable.len(), 1);
	if let Event::SpendableOutputs { outputs, channel_id } = node_b_spendable.pop().unwrap() {
		assert_eq!(outputs.len(), 1);
		assert_eq!(channel_id, Some(chan_id));
		let spend_tx = nodes[1].keys_manager.backing.spend_spendable_outputs(&[&outputs[0]], Vec::new(),
			Builder::new().push_opcode(opcodes::all::OP_RETURN).into_script(), 253, None, &Secp256k1::new()).unwrap();
		check_spends!(spend_tx, remote_txn_a[0]);
	}
}

#[test]
fn test_to_remote_after_local_detection() {
	do_test_to_remote_after_local_detection(ConnectStyle::BestBlockFirst);
	do_test_to_remote_after_local_detection(ConnectStyle::BestBlockFirstSkippingBlocks);
	do_test_to_remote_after_local_detection(ConnectStyle::BestBlockFirstReorgsOnlyTip);
	do_test_to_remote_after_local_detection(ConnectStyle::TransactionsFirst);
	do_test_to_remote_after_local_detection(ConnectStyle::TransactionsFirstSkippingBlocks);
	do_test_to_remote_after_local_detection(ConnectStyle::TransactionsFirstReorgsOnlyTip);
	do_test_to_remote_after_local_detection(ConnectStyle::FullBlockViaListen);
}

#[test]
fn test_htlc_preimage_claim_holder_commitment_after_counterparty_commitment_reorg() {
	// We detect a counterparty commitment confirm onchain, followed by a reorg and a confirmation
	// of a holder commitment. Then, if we learn of the preimage for an HTLC in both commitments,
	// test that we only claim the currently confirmed commitment.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let (_, _, chan_id, funding_tx) = create_announced_chan_between_nodes(&nodes, 0, 1);

	// Route an HTLC which we will claim onchain with the preimage.
	let (payment_preimage, payment_hash, ..) = route_payment(&nodes[0], &[&nodes[1]], 1_000_000);
	let error_message = "Channel force-closed";

	// Force close with the latest counterparty commitment, confirm it, and reorg it with the latest
	// holder commitment.
	nodes[0].node.force_close_broadcasting_latest_txn(&chan_id, &nodes[1].node.get_our_node_id(), error_message.to_string()).unwrap();
	check_closed_broadcast(&nodes[0], 1, true);
	check_added_monitors(&nodes[0], 1);
	check_closed_event(&nodes[0], 1, ClosureReason::HolderForceClosed { broadcasted_latest_txn: Some(true) }, false, &[nodes[1].node.get_our_node_id()], 100000);

	nodes[1].node.force_close_broadcasting_latest_txn(&chan_id, &nodes[0].node.get_our_node_id(), error_message.to_string()).unwrap();
	check_closed_broadcast(&nodes[1], 1, true);
	check_added_monitors(&nodes[1], 1);
	check_closed_event(&nodes[1], 1, ClosureReason::HolderForceClosed { broadcasted_latest_txn: Some(true) }, false, &[nodes[0].node.get_our_node_id()], 100000);

	let mut txn = nodes[0].tx_broadcaster.txn_broadcast();
	assert_eq!(txn.len(), 1);
	let commitment_tx_a = txn.pop().unwrap();
	check_spends!(commitment_tx_a, funding_tx);

	let mut txn = nodes[1].tx_broadcaster.txn_broadcast();
	assert_eq!(txn.len(), 1);
	let commitment_tx_b = txn.pop().unwrap();
	check_spends!(commitment_tx_b, funding_tx);

	mine_transaction(&nodes[0], &commitment_tx_a);
	mine_transaction(&nodes[1], &commitment_tx_a);

	disconnect_blocks(&nodes[0], 1);
	disconnect_blocks(&nodes[1], 1);

	mine_transaction(&nodes[0], &commitment_tx_b);
	mine_transaction(&nodes[1], &commitment_tx_b);
	if nodes[1].connect_style.borrow().updates_best_block_first() {
		let _ = nodes[1].tx_broadcaster.txn_broadcast();
	}

	// Provide the preimage now, such that we only claim from the holder commitment (since it's
	// currently confirmed) and not the counterparty's.
	get_monitor!(nodes[1], chan_id).provide_payment_preimage(
		&payment_hash, &payment_preimage, &nodes[1].tx_broadcaster,
		&LowerBoundedFeeEstimator(nodes[1].fee_estimator), &nodes[1].logger
	);

	let mut txn = nodes[1].tx_broadcaster.txn_broadcast();
	assert_eq!(txn.len(), 1);
	let htlc_success_tx = txn.pop().unwrap();
	check_spends!(htlc_success_tx, commitment_tx_b);
}

#[test]
fn test_htlc_preimage_claim_prev_counterparty_commitment_after_current_counterparty_commitment_reorg() {
	// We detect a counterparty commitment confirm onchain, followed by a reorg and a
	// confirmation of the previous (still unrevoked) counterparty commitment. Then, if we learn
	// of the preimage for an HTLC in both commitments, test that we only claim the currently
	// confirmed commitment.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let (_, _, chan_id, funding_tx) = create_announced_chan_between_nodes(&nodes, 0, 1);

	// Route an HTLC which we will claim onchain with the preimage.
	let (payment_preimage, payment_hash, ..) = route_payment(&nodes[0], &[&nodes[1]], 1_000_000);

	// Obtain the current commitment, which will become the previous after a fee update.
	let prev_commitment_a = &get_local_commitment_txn!(nodes[0], chan_id)[0];

	*nodes[0].fee_estimator.sat_per_kw.lock().unwrap() *= 4;
	nodes[0].node.timer_tick_occurred();
	check_added_monitors(&nodes[0], 1);
	let mut msg_events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(msg_events.len(), 1);
	let (update_fee, commit_sig) = if let MessageSendEvent::UpdateHTLCs { node_id, mut updates } = msg_events.pop().unwrap() {
		assert_eq!(node_id, nodes[1].node.get_our_node_id());
		(updates.update_fee.take().unwrap(), updates.commitment_signed)
	} else {
		panic!("Unexpected message send event");
	};

	// Handle the fee update on the other side, but don't send the last RAA such that the previous
	// commitment is still valid (unrevoked).
	nodes[1].node().handle_update_fee(&nodes[0].node.get_our_node_id(), &update_fee);
	let _last_revoke_and_ack = commitment_signed_dance!(nodes[1], nodes[0], commit_sig, false, true, false, true);
	let error_message = "Channel force-closed";

	// Force close with the latest commitment, confirm it, and reorg it with the previous commitment.
	nodes[0].node.force_close_broadcasting_latest_txn(&chan_id, &nodes[1].node.get_our_node_id(), error_message.to_string()).unwrap();
	check_closed_broadcast(&nodes[0], 1, true);
	check_added_monitors(&nodes[0], 1);
	check_closed_event(&nodes[0], 1, ClosureReason::HolderForceClosed { broadcasted_latest_txn: Some(true) }, false, &[nodes[1].node.get_our_node_id()], 100000);

	let mut txn = nodes[0].tx_broadcaster.txn_broadcast();
	assert_eq!(txn.len(), 1);
	let current_commitment_a = txn.pop().unwrap();
	assert_ne!(current_commitment_a.txid(), prev_commitment_a.txid());
	check_spends!(current_commitment_a, funding_tx);

	mine_transaction(&nodes[0], &current_commitment_a);
	mine_transaction(&nodes[1], &current_commitment_a);

	check_closed_broadcast(&nodes[1], 1, true);
	check_added_monitors(&nodes[1], 1);
	check_closed_event(&nodes[1], 1, ClosureReason::CommitmentTxConfirmed, false, &[nodes[0].node.get_our_node_id()], 100000);

	disconnect_blocks(&nodes[0], 1);
	disconnect_blocks(&nodes[1], 1);

	mine_transaction(&nodes[0], &prev_commitment_a);
	mine_transaction(&nodes[1], &prev_commitment_a);

	// Provide the preimage now, such that we only claim from the previous commitment (since it's
	// currently confirmed) and not the latest.
	get_monitor!(nodes[1], chan_id).provide_payment_preimage(
		&payment_hash, &payment_preimage, &nodes[1].tx_broadcaster,
		&LowerBoundedFeeEstimator(nodes[1].fee_estimator), &nodes[1].logger
	);

	let mut txn = nodes[1].tx_broadcaster.txn_broadcast();
	assert_eq!(txn.len(), 1);
	let htlc_preimage_tx = txn.pop().unwrap();
	check_spends!(htlc_preimage_tx, prev_commitment_a);
	// Make sure it was indeed a preimage claim and not a revocation claim since the previous
	// commitment (still unrevoked) is the currently confirmed closing transaction.
	assert_eq!(htlc_preimage_tx.input[0].witness.second_to_last().unwrap(), &payment_preimage.0[..]);
}

fn do_test_retries_own_commitment_broadcast_after_reorg(anchors: bool, revoked_counterparty_commitment: bool) {
	// Tests that a node will retry broadcasting its own commitment after seeing a confirmed
	// counterparty commitment be reorged out.
	let mut chanmon_cfgs = create_chanmon_cfgs(2);
	if revoked_counterparty_commitment {
		chanmon_cfgs[1].keys_manager.disable_revocation_policy_check = true;
	}
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let mut config = test_default_channel_config();
	if anchors {
		config.channel_handshake_config.negotiate_anchors_zero_fee_htlc_tx = true;
		config.manually_accept_inbound_channels = true;
	}
	let persister;
	let new_chain_monitor;
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[Some(config), Some(config)]);
	let nodes_1_deserialized;
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let (_, _, chan_id, funding_tx) = create_announced_chan_between_nodes(&nodes, 0, 1);

	// Route a payment so we have an HTLC to claim as well.
	let _ = route_payment(&nodes[0], &[&nodes[1]], 1_000_000);
	let error_message = "Channel force-closed";

	if revoked_counterparty_commitment {
		// Trigger a fee update such that we advance the state. We will have B broadcast its state
		// without the fee update.
		let serialized_node = nodes[1].node.encode();
		let serialized_monitor = get_monitor!(nodes[1], chan_id).encode();

		*chanmon_cfgs[0].fee_estimator.sat_per_kw.lock().unwrap() += 1;
		nodes[0].node.timer_tick_occurred();
		check_added_monitors!(nodes[0], 1);

		let fee_update = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
		nodes[1].node.handle_update_fee(&nodes[0].node.get_our_node_id(), &fee_update.update_fee.unwrap());
		commitment_signed_dance!(nodes[1], nodes[0], fee_update.commitment_signed, false);

		reload_node!(
			nodes[1], config, &serialized_node, &[&serialized_monitor], persister, new_chain_monitor, nodes_1_deserialized
		);
	}

	// Connect blocks until the HTLC expiry is met, prompting a commitment broadcast by A.
	connect_blocks(&nodes[0], TEST_FINAL_CLTV + LATENCY_GRACE_PERIOD_BLOCKS + 1);
	check_closed_broadcast(&nodes[0], 1, true);
	check_added_monitors(&nodes[0], 1);
	check_closed_event(&nodes[0], 1, ClosureReason::HTLCsTimedOut, false, &[nodes[1].node.get_our_node_id()], 100_000);

	{
		let mut txn = nodes[0].tx_broadcaster.txn_broadcast();
		if anchors {
			assert_eq!(txn.len(), 1);
			let commitment_tx_a = txn.pop().unwrap();
			check_spends!(commitment_tx_a, funding_tx);
		} else {
			assert_eq!(txn.len(), 2);
			let htlc_tx_a = txn.pop().unwrap();
			let commitment_tx_a = txn.pop().unwrap();
			check_spends!(commitment_tx_a, funding_tx);
			check_spends!(htlc_tx_a, commitment_tx_a);
		}
	};

	// B will also broadcast its own commitment.
	nodes[1].node.force_close_broadcasting_latest_txn(&chan_id, &nodes[0].node.get_our_node_id(), error_message.to_string()).unwrap();
	check_closed_broadcast(&nodes[1], 1, true);
	check_added_monitors(&nodes[1], 1);
	check_closed_event(&nodes[1], 1, ClosureReason::HolderForceClosed { broadcasted_latest_txn: Some(true) }, false, &[nodes[0].node.get_our_node_id()], 100_000);

	let commitment_b = {
		let mut txn = nodes[1].tx_broadcaster.txn_broadcast();
		assert_eq!(txn.len(), 1);
		let tx = txn.pop().unwrap();
		check_spends!(tx, funding_tx);
		tx
	};

	// Confirm B's commitment, A should now broadcast an HTLC timeout for commitment B.
	mine_transaction(&nodes[0], &commitment_b);
	{
		let mut txn = nodes[0].tx_broadcaster.txn_broadcast();
		if nodes[0].connect_style.borrow().updates_best_block_first() {
			// `commitment_a` and `htlc_timeout_a` are rebroadcast because the best block was
			// updated prior to seeing `commitment_b`.
			assert_eq!(txn.len(), if anchors { 2 } else { 3 });
			check_spends!(txn.last().unwrap(), commitment_b);
		} else {
			assert_eq!(txn.len(), 1);
			check_spends!(txn[0], commitment_b);
		}
	}

	// Disconnect the block, allowing A to retry its own commitment. Note that we connect two
	// blocks, one to get us back to the original height, and another to retry our pending claims.
	disconnect_blocks(&nodes[0], 1);
	connect_blocks(&nodes[0], 2);
	{
		let mut txn = nodes[0].tx_broadcaster.unique_txn_broadcast();
		if anchors {
			assert_eq!(txn.len(), 1);
			check_spends!(txn[0], funding_tx);
		} else {
			assert_eq!(txn.len(), 2);
			check_spends!(txn[0], txn[1]); // HTLC timeout A
			check_spends!(txn[1], funding_tx); // Commitment A
			assert_ne!(txn[1].txid(), commitment_b.txid());
		}
	}
}

#[test]
fn test_retries_own_commitment_broadcast_after_reorg() {
	do_test_retries_own_commitment_broadcast_after_reorg(false, false);
	do_test_retries_own_commitment_broadcast_after_reorg(false, true);
	do_test_retries_own_commitment_broadcast_after_reorg(true, false);
	do_test_retries_own_commitment_broadcast_after_reorg(true, true);
}
