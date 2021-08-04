// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Further functional tests which test blockchain reorganizations.

use chain::channelmonitor::{ANTI_REORG_DELAY, ChannelMonitor};
use chain::transaction::OutPoint;
use chain::{Confirm, Watch};
use ln::channelmanager::{ChannelManager, ChannelManagerReadArgs};
use ln::features::InitFeatures;
use ln::msgs::{ChannelMessageHandler, ErrorAction, HTLCFailChannelUpdate};
use util::enforcing_trait_impls::EnforcingSigner;
use util::events::{Event, MessageSendEvent, MessageSendEventsProvider};
use util::test_utils;
use util::ser::{ReadableArgs, Writeable};

use bitcoin::blockdata::block::{Block, BlockHeader};
use bitcoin::blockdata::script::Builder;
use bitcoin::blockdata::opcodes;
use bitcoin::hash_types::BlockHash;
use bitcoin::secp256k1::Secp256k1;

use prelude::*;
use core::mem;

use ln::functional_test_utils::*;

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

	create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());
	let chan_2 = create_announced_chan_between_nodes(&nodes, 1, 2, InitFeatures::known(), InitFeatures::known());

	// Make sure all nodes are at the same starting height
	connect_blocks(&nodes[0], 2*CHAN_CONFIRM_DEPTH + 1 - nodes[0].best_block_info().1);
	connect_blocks(&nodes[1], 2*CHAN_CONFIRM_DEPTH + 1 - nodes[1].best_block_info().1);
	connect_blocks(&nodes[2], 2*CHAN_CONFIRM_DEPTH + 1 - nodes[2].best_block_info().1);

	let (our_payment_preimage, our_payment_hash, _) = route_payment(&nodes[0], &[&nodes[1], &nodes[2]], 1000000);

	// Provide preimage to node 2 by claiming payment
	nodes[2].node.claim_funds(our_payment_preimage);
	check_added_monitors!(nodes[2], 1);
	get_htlc_update_msgs!(nodes[2], nodes[1].node.get_our_node_id());

	let mut header = BlockHeader { version: 0x2000_0000, prev_blockhash: nodes[2].best_block_hash(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
	let claim_txn = if local_commitment {
		// Broadcast node 1 commitment txn to broadcast the HTLC-Timeout
		let node_1_commitment_txn = get_local_commitment_txn!(nodes[1], chan_2.2);
		assert_eq!(node_1_commitment_txn.len(), 2); // 1 local commitment tx, 1 Outbound HTLC-Timeout
		assert_eq!(node_1_commitment_txn[0].output.len(), 2); // to-self and Offered HTLC (to-remote/to-node-3 is dust)
		check_spends!(node_1_commitment_txn[0], chan_2.3);
		check_spends!(node_1_commitment_txn[1], node_1_commitment_txn[0]);

		// Give node 2 node 1's transactions and get its response (claiming the HTLC instead).
		connect_block(&nodes[2], &Block { header, txdata: node_1_commitment_txn.clone() });
		check_added_monitors!(nodes[2], 1);
		check_closed_broadcast!(nodes[2], true); // We should get a BroadcastChannelUpdate (and *only* a BroadcstChannelUpdate)
		let node_2_commitment_txn = nodes[2].tx_broadcaster.txn_broadcasted.lock().unwrap();
		assert_eq!(node_2_commitment_txn.len(), 3); // ChannelMonitor: 1 offered HTLC-Claim, ChannelManger: 1 local commitment tx, 1 Received HTLC-Claim
		assert_eq!(node_2_commitment_txn[1].output.len(), 2); // to-remote and Received HTLC (to-self is dust)
		check_spends!(node_2_commitment_txn[1], chan_2.3);
		check_spends!(node_2_commitment_txn[2], node_2_commitment_txn[1]);
		check_spends!(node_2_commitment_txn[0], node_1_commitment_txn[0]);

		// Make sure node 1's height is the same as the !local_commitment case
		connect_blocks(&nodes[1], 1);
		// Confirm node 1's commitment txn (and HTLC-Timeout) on node 1
		header.prev_blockhash = nodes[1].best_block_hash();
		connect_block(&nodes[1], &Block { header, txdata: node_1_commitment_txn.clone() });

		// ...but return node 1's commitment tx in case claim is set and we're preparing to reorg
		vec![node_1_commitment_txn[0].clone(), node_2_commitment_txn[0].clone()]
	} else {
		// Broadcast node 2 commitment txn
		let node_2_commitment_txn = get_local_commitment_txn!(nodes[2], chan_2.2);
		assert_eq!(node_2_commitment_txn.len(), 2); // 1 local commitment tx, 1 Received HTLC-Claim
		assert_eq!(node_2_commitment_txn[0].output.len(), 2); // to-remote and Received HTLC (to-self is dust)
		check_spends!(node_2_commitment_txn[0], chan_2.3);
		check_spends!(node_2_commitment_txn[1], node_2_commitment_txn[0]);

		// Give node 1 node 2's commitment transaction and get its response (timing the HTLC out)
		mine_transaction(&nodes[1], &node_2_commitment_txn[0]);
		connect_blocks(&nodes[1], TEST_FINAL_CLTV - 1); // Confirm blocks until the HTLC expires
		let node_1_commitment_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().clone();
		assert_eq!(node_1_commitment_txn.len(), 2); // ChannelMonitor: 1 offered HTLC-Timeout, ChannelManger: 1 local commitment tx
		assert_eq!(node_1_commitment_txn[0].output.len(), 2); // to-local and Offered HTLC (to-remote is dust)
		check_spends!(node_1_commitment_txn[0], chan_2.3);
		check_spends!(node_1_commitment_txn[1], node_2_commitment_txn[0]);

		// Confirm node 2's commitment txn (and node 1's HTLC-Timeout) on node 1
		header.prev_blockhash = nodes[1].best_block_hash();
		let block = Block { header, txdata: vec![node_2_commitment_txn[0].clone(), node_1_commitment_txn[1].clone()] };
		connect_block(&nodes[1], &block);
		// ...but return node 2's commitment tx (and claim) in case claim is set and we're preparing to reorg
		node_2_commitment_txn
	};
	check_added_monitors!(nodes[1], 1);
	check_closed_broadcast!(nodes[1], true); // We should get a BroadcastChannelUpdate (and *only* a BroadcstChannelUpdate)
	// Connect ANTI_REORG_DELAY - 2 blocks, giving us a confirmation count of ANTI_REORG_DELAY - 1.
	connect_blocks(&nodes[1], ANTI_REORG_DELAY - 2);
	check_added_monitors!(nodes[1], 0);
	assert_eq!(nodes[1].node.get_and_clear_pending_events().len(), 0);

	if claim {
		disconnect_blocks(&nodes[1], ANTI_REORG_DELAY - 2);

		let block = Block {
			header: BlockHeader { version: 0x20000000, prev_blockhash: nodes[1].best_block_hash(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 },
			txdata: claim_txn,
		};
		connect_block(&nodes[1], &block);

		// ChannelManager only polls chain::Watch::release_pending_monitor_events when we
		// probe it for events, so we probe non-message events here (which should still end up empty):
		assert_eq!(nodes[1].node.get_and_clear_pending_events().len(), 0);
	} else {
		// Confirm the timeout tx and check that we fail the HTLC backwards
		let block = Block {
			header: BlockHeader { version: 0x20000000, prev_blockhash: nodes[1].best_block_hash(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 },
			txdata: vec![],
		};
		connect_block(&nodes[1], &block);
		expect_pending_htlcs_forwardable!(nodes[1]);
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
		let events = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		if let MessageSendEvent::PaymentFailureNetworkUpdate { update: HTLCFailChannelUpdate::ChannelClosed { ref is_permanent, .. } } = events[0] {
			assert!(is_permanent);
		} else { panic!("Unexpected event!"); }
		expect_payment_failed!(nodes[0], our_payment_hash, false);
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

fn do_test_unconf_chan(reload_node: bool, reorg_after_reload: bool, use_funding_unconfirmed: bool, connect_style: ConnectStyle) {
	// After creating a chan between nodes, we disconnect all blocks previously seen to force a
	// channel close on nodes[0] side. We also use this to provide very basic testing of logic
	// around freeing background events which store monitor updates during block_[dis]connected.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let persister: test_utils::TestPersister;
	let new_chain_monitor: test_utils::TestChainMonitor;
	let nodes_0_deserialized: ChannelManager<EnforcingSigner, &test_utils::TestChainMonitor, &test_utils::TestBroadcaster, &test_utils::TestKeysInterface, &test_utils::TestFeeEstimator, &test_utils::TestLogger>;
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	*nodes[0].connect_style.borrow_mut() = connect_style;

	let chan = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());

	let channel_state = nodes[0].node.channel_state.lock().unwrap();
	assert_eq!(channel_state.by_id.len(), 1);
	assert_eq!(channel_state.short_to_id.len(), 1);
	mem::drop(channel_state);

	if !reorg_after_reload {
		if use_funding_unconfirmed {
			let relevant_txids = nodes[0].node.get_relevant_txids();
			assert_eq!(&relevant_txids[..], &[chan.3.txid()]);
			nodes[0].node.transaction_unconfirmed(&relevant_txids[0]);
		} else {
			disconnect_all_blocks(&nodes[0]);
		}
		if connect_style == ConnectStyle::FullBlockViaListen && !use_funding_unconfirmed {
			handle_announce_close_broadcast_events(&nodes, 0, 1, true, "Funding transaction was un-confirmed. Locked at 6 confs, now have 2 confs.");
		} else {
			handle_announce_close_broadcast_events(&nodes, 0, 1, true, "Funding transaction was un-confirmed. Locked at 6 confs, now have 0 confs.");
		}
		check_added_monitors!(nodes[1], 1);
		{
			let channel_state = nodes[0].node.channel_state.lock().unwrap();
			assert_eq!(channel_state.by_id.len(), 0);
			assert_eq!(channel_state.short_to_id.len(), 0);
		}
	}

	if reload_node {
		// Since we currently have a background event pending, it's good to test that we survive a
		// serialization roundtrip. Further, this tests the somewhat awkward edge-case of dropping
		// the Channel object from the ChannelManager, but still having a monitor event pending for
		// it when we go to deserialize, and then use the ChannelManager.
		let nodes_0_serialized = nodes[0].node.encode();
		let mut chan_0_monitor_serialized = test_utils::TestVecWriter(Vec::new());
		nodes[0].chain_monitor.chain_monitor.monitors.read().unwrap().iter().next().unwrap().1.write(&mut chan_0_monitor_serialized).unwrap();

		persister = test_utils::TestPersister::new();
		let keys_manager = &chanmon_cfgs[0].keys_manager;
		new_chain_monitor = test_utils::TestChainMonitor::new(Some(nodes[0].chain_source), nodes[0].tx_broadcaster.clone(), nodes[0].logger, node_cfgs[0].fee_estimator, &persister, keys_manager);
		nodes[0].chain_monitor = &new_chain_monitor;
		let mut chan_0_monitor_read = &chan_0_monitor_serialized.0[..];
		let (_, mut chan_0_monitor) = <(BlockHash, ChannelMonitor<EnforcingSigner>)>::read(
			&mut chan_0_monitor_read, keys_manager).unwrap();
		assert!(chan_0_monitor_read.is_empty());

		let mut nodes_0_read = &nodes_0_serialized[..];
		nodes_0_deserialized = {
			let mut channel_monitors = HashMap::new();
			channel_monitors.insert(chan_0_monitor.get_funding_txo().0, &mut chan_0_monitor);
			<(BlockHash, ChannelManager<EnforcingSigner, &test_utils::TestChainMonitor, &test_utils::TestBroadcaster,
			  &test_utils::TestKeysInterface, &test_utils::TestFeeEstimator, &test_utils::TestLogger>)>::read(
				&mut nodes_0_read, ChannelManagerReadArgs {
					default_config: *nodes[0].node.get_current_default_configuration(),
					keys_manager,
					fee_estimator: node_cfgs[0].fee_estimator,
					chain_monitor: nodes[0].chain_monitor,
					tx_broadcaster: nodes[0].tx_broadcaster.clone(),
					logger: nodes[0].logger,
					channel_monitors,
			}).unwrap().1
		};
		nodes[0].node = &nodes_0_deserialized;
		assert!(nodes_0_read.is_empty());
		if !reorg_after_reload {
			// If the channel is already closed when we reload the node, we'll broadcast a closing
			// transaction via the ChannelMonitor which is missing a corresponding channel.
			assert_eq!(nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().len(), 1);
			nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().clear();
		}

		nodes[0].chain_monitor.watch_channel(chan_0_monitor.get_funding_txo().0.clone(), chan_0_monitor).unwrap();
		check_added_monitors!(nodes[0], 1);
	}

	if reorg_after_reload {
		if use_funding_unconfirmed {
			let relevant_txids = nodes[0].node.get_relevant_txids();
			assert_eq!(&relevant_txids[..], &[chan.3.txid()]);
			nodes[0].node.transaction_unconfirmed(&relevant_txids[0]);
		} else {
			disconnect_all_blocks(&nodes[0]);
		}
		if connect_style == ConnectStyle::FullBlockViaListen && !use_funding_unconfirmed {
			handle_announce_close_broadcast_events(&nodes, 0, 1, true, "Funding transaction was un-confirmed. Locked at 6 confs, now have 2 confs.");
		} else {
			handle_announce_close_broadcast_events(&nodes, 0, 1, true, "Funding transaction was un-confirmed. Locked at 6 confs, now have 0 confs.");
		}
		check_added_monitors!(nodes[1], 1);
		{
			let channel_state = nodes[0].node.channel_state.lock().unwrap();
			assert_eq!(channel_state.by_id.len(), 0);
			assert_eq!(channel_state.short_to_id.len(), 0);
		}
	}
	// With expect_channel_force_closed set the TestChainMonitor will enforce that the next update
	// is a ChannelForcClosed on the right channel with should_broadcast set.
	*nodes[0].chain_monitor.expect_channel_force_closed.lock().unwrap() = Some((chan.2, true));
	nodes[0].node.test_process_background_events(); // Required to free the pending background monitor update
	check_added_monitors!(nodes[0], 1);
	assert_eq!(nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().len(), 1);
	nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().clear();

	// Now check that we can create a new channel
	create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());
	send_payment(&nodes[0], &[&nodes[1]], 8000000);
}

#[test]
fn test_unconf_chan() {
	do_test_unconf_chan(true, true, false, ConnectStyle::BestBlockFirstSkippingBlocks);
	do_test_unconf_chan(false, true, false, ConnectStyle::BestBlockFirstSkippingBlocks);
	do_test_unconf_chan(true, false, false, ConnectStyle::BestBlockFirstSkippingBlocks);
	do_test_unconf_chan(false, false, false, ConnectStyle::BestBlockFirstSkippingBlocks);
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

	let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1000000, 59000000, InitFeatures::known(), InitFeatures::known());
	let payment_preimage_1 = route_payment(&nodes[1], &vec!(&nodes[0])[..], 3_000_000).0;
	let payment_preimage_2 = route_payment(&nodes[1], &vec!(&nodes[0])[..], 3_000_000).0;

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
	nodes[0].node.claim_funds(payment_preimage_2);
	check_added_monitors!(nodes[0], 2);
	nodes[0].node.get_and_clear_pending_events();
	nodes[0].node.get_and_clear_pending_msg_events();

	// Connect blocks on node A commitment transaction
	mine_transaction(&nodes[0], &remote_txn[0]);
	check_closed_broadcast!(nodes[0], true);
	check_added_monitors!(nodes[0], 1);
	// Verify node A broadcast tx claiming both HTLCs
	{
		let mut node_txn = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap();
		// ChannelMonitor: claim tx, ChannelManager: local commitment tx + HTLC-Success*2
		assert_eq!(node_txn.len(), 4);
		check_spends!(node_txn[0], remote_txn[0]);
		check_spends!(node_txn[1], chan.3);
		check_spends!(node_txn[2], node_txn[1]);
		check_spends!(node_txn[3], node_txn[1]);
		assert_eq!(node_txn[0].input.len(), 2);
		node_txn.clear();
	}

	// Connect blocks on node B
	connect_blocks(&nodes[1], 135);
	check_closed_broadcast!(nodes[1], true);
	check_added_monitors!(nodes[1], 1);
	// Verify node B broadcast 2 HTLC-timeout txn
	let partial_claim_tx = {
		let node_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap();
		assert_eq!(node_txn.len(), 3);
		check_spends!(node_txn[1], node_txn[0]);
		check_spends!(node_txn[2], node_txn[0]);
		assert_eq!(node_txn[1].input.len(), 1);
		assert_eq!(node_txn[2].input.len(), 1);
		node_txn[1].clone()
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
		create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 100_000_000, InitFeatures::known(), InitFeatures::known());
	let funding_outpoint = OutPoint { txid: funding_tx.txid(), index: 0 };
	assert_eq!(funding_outpoint.to_channel_id(), chan_id);

	let remote_txn_a = get_local_commitment_txn!(nodes[0], chan_id);
	let remote_txn_b = get_local_commitment_txn!(nodes[1], chan_id);

	mine_transaction(&nodes[0], &remote_txn_a[0]);
	mine_transaction(&nodes[1], &remote_txn_a[0]);

	assert!(nodes[0].node.list_channels().is_empty());
	check_closed_broadcast!(nodes[0], true);
	check_added_monitors!(nodes[0], 1);
	assert!(nodes[1].node.list_channels().is_empty());
	check_closed_broadcast!(nodes[1], true);
	check_added_monitors!(nodes[1], 1);

	// Drop transactions broadcasted in response to the first commitment transaction (we have good
	// test coverage of these things already elsewhere).
	assert_eq!(nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().split_off(0).len(), 1);
	assert_eq!(nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().split_off(0).len(), 1);

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
	if let Event::SpendableOutputs { outputs } = node_a_spendable.pop().unwrap() {
		assert_eq!(outputs.len(), 1);
		let spend_tx = nodes[0].keys_manager.backing.spend_spendable_outputs(&[&outputs[0]], Vec::new(),
			Builder::new().push_opcode(opcodes::all::OP_RETURN).into_script(), 253, &Secp256k1::new()).unwrap();
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
	if let Event::SpendableOutputs { outputs } = node_b_spendable.pop().unwrap() {
		assert_eq!(outputs.len(), 1);
		let spend_tx = nodes[1].keys_manager.backing.spend_spendable_outputs(&[&outputs[0]], Vec::new(),
			Builder::new().push_opcode(opcodes::all::OP_RETURN).into_script(), 253, &Secp256k1::new()).unwrap();
		check_spends!(spend_tx, remote_txn_a[0]);
	}
}

#[test]
fn test_to_remote_after_local_detection() {
	do_test_to_remote_after_local_detection(ConnectStyle::BestBlockFirst);
	do_test_to_remote_after_local_detection(ConnectStyle::BestBlockFirstSkippingBlocks);
	do_test_to_remote_after_local_detection(ConnectStyle::TransactionsFirst);
	do_test_to_remote_after_local_detection(ConnectStyle::TransactionsFirstSkippingBlocks);
	do_test_to_remote_after_local_detection(ConnectStyle::FullBlockViaListen);
}
