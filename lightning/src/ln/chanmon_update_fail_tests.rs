// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Functional tests which test the correct handling of ChannelMonitorUpdateErr returns from
//! monitor updates.
//! There are a bunch of these as their handling is relatively error-prone so they are split out
//! here. See also the chanmon_fail_consistency fuzz test.

use bitcoin::blockdata::block::{Block, BlockHeader};
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::hash_types::BlockHash;
use bitcoin::network::constants::Network;
use chain::channelmonitor::ChannelMonitor;
use chain::transaction::OutPoint;
use chain::{ChannelMonitorUpdateErr, Listen, Watch};
use ln::channelmanager::{ChannelManager, ChannelManagerReadArgs, RAACommitmentOrder, PaymentSendFailure};
use ln::channel::AnnouncementSigsState;
use ln::features::InitFeatures;
use ln::msgs;
use ln::msgs::{ChannelMessageHandler, RoutingMessageHandler};
use util::config::UserConfig;
use util::enforcing_trait_impls::EnforcingSigner;
use util::events::{Event, MessageSendEvent, MessageSendEventsProvider, PaymentPurpose, ClosureReason};
use util::errors::APIError;
use util::ser::{ReadableArgs, Writeable};
use util::test_utils::TestBroadcaster;

use ln::functional_test_utils::*;

use util::test_utils;

use io;
use prelude::*;
use sync::{Arc, Mutex};

#[test]
fn test_simple_monitor_permanent_update_fail() {
	// Test that we handle a simple permanent monitor update failure
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());

	let (route, payment_hash_1, _, payment_secret_1) = get_route_and_payment_hash!(&nodes[0], nodes[1], 1000000);
	chanmon_cfgs[0].persister.set_update_ret(Err(ChannelMonitorUpdateErr::PermanentFailure));
	unwrap_send_err!(nodes[0].node.send_payment(&route, payment_hash_1, &Some(payment_secret_1)), true, APIError::ChannelUnavailable {..}, {});
	check_added_monitors!(nodes[0], 2);

	let events_1 = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events_1.len(), 2);
	match events_1[0] {
		MessageSendEvent::BroadcastChannelUpdate { .. } => {},
		_ => panic!("Unexpected event"),
	};
	match events_1[1] {
		MessageSendEvent::HandleError { node_id, .. } => assert_eq!(node_id, nodes[1].node.get_our_node_id()),
		_ => panic!("Unexpected event"),
	};

	// TODO: Once we hit the chain with the failure transaction we should check that we get a
	// PaymentPathFailed event

	assert_eq!(nodes[0].node.list_channels().len(), 0);
	check_closed_event!(nodes[0], 1, ClosureReason::ProcessingError { err: "ChannelMonitor storage failure".to_string() });
}

#[test]
fn test_monitor_and_persister_update_fail() {
	// Test that if both updating the `ChannelMonitor` and persisting the updated
	// `ChannelMonitor` fail, then the failure from updating the `ChannelMonitor`
	// one that gets returned.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	// Create some initial channel
	let chan = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());
	let outpoint = OutPoint { txid: chan.3.txid(), index: 0 };

	// Rebalance the network to generate htlc in the two directions
	send_payment(&nodes[0], &vec!(&nodes[1])[..], 10_000_000);

	// Route an HTLC from node 0 to node 1 (but don't settle)
	let preimage = route_payment(&nodes[0], &vec!(&nodes[1])[..], 9_000_000).0;

	// Make a copy of the ChainMonitor so we can capture the error it returns on a
	// bogus update. Note that if instead we updated the nodes[0]'s ChainMonitor
	// directly, the node would fail to be `Drop`'d at the end because its
	// ChannelManager and ChainMonitor would be out of sync.
	let chain_source = test_utils::TestChainSource::new(Network::Testnet);
	let logger = test_utils::TestLogger::with_id(format!("node {}", 0));
	let persister = test_utils::TestPersister::new();
	let tx_broadcaster = TestBroadcaster {
		txn_broadcasted: Mutex::new(Vec::new()),
		// Because we will connect a block at height 200 below, we need the TestBroadcaster to know
		// that we are at height 200 so that it doesn't think we're violating the time lock
		// requirements of transactions broadcasted at that point.
		blocks: Arc::new(Mutex::new(vec![(genesis_block(Network::Testnet).header, 200); 200])),
	};
	let chain_mon = {
		let monitor = nodes[0].chain_monitor.chain_monitor.get_monitor(outpoint).unwrap();
		let mut w = test_utils::TestVecWriter(Vec::new());
		monitor.write(&mut w).unwrap();
		let new_monitor = <(BlockHash, ChannelMonitor<EnforcingSigner>)>::read(
			&mut io::Cursor::new(&w.0), &test_utils::OnlyReadsKeysInterface {}).unwrap().1;
		assert!(new_monitor == *monitor);
		let chain_mon = test_utils::TestChainMonitor::new(Some(&chain_source), &tx_broadcaster, &logger, &chanmon_cfgs[0].fee_estimator, &persister, &node_cfgs[0].keys_manager);
		assert!(chain_mon.watch_channel(outpoint, new_monitor).is_ok());
		chain_mon
	};
	let header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
	chain_mon.chain_monitor.block_connected(&Block { header, txdata: vec![] }, 200);

	// Set the persister's return value to be a TemporaryFailure.
	persister.set_update_ret(Err(ChannelMonitorUpdateErr::TemporaryFailure));

	// Try to update ChannelMonitor
	assert!(nodes[1].node.claim_funds(preimage));
	check_added_monitors!(nodes[1], 1);
	let updates = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	assert_eq!(updates.update_fulfill_htlcs.len(), 1);
	nodes[0].node.handle_update_fulfill_htlc(&nodes[1].node.get_our_node_id(), &updates.update_fulfill_htlcs[0]);
	if let Some(ref mut channel) = nodes[0].node.channel_state.lock().unwrap().by_id.get_mut(&chan.2) {
		if let Ok((_, _, update)) = channel.commitment_signed(&updates.commitment_signed, &node_cfgs[0].logger) {
			// Check that even though the persister is returning a TemporaryFailure,
			// because the update is bogus, ultimately the error that's returned
			// should be a PermanentFailure.
			if let Err(ChannelMonitorUpdateErr::PermanentFailure) = chain_mon.chain_monitor.update_channel(outpoint, update.clone()) {} else { panic!("Expected monitor error to be permanent"); }
			logger.assert_log_regex("lightning::chain::chainmonitor".to_string(), regex::Regex::new("Failed to persist ChannelMonitor update for channel [0-9a-f]*: TemporaryFailure").unwrap(), 1);
			if let Ok(_) = nodes[0].chain_monitor.update_channel(outpoint, update) {} else { assert!(false); }
		} else { assert!(false); }
	} else { assert!(false); };

	check_added_monitors!(nodes[0], 1);
	let events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
}

fn do_test_simple_monitor_temporary_update_fail(disconnect: bool) {
	// Test that we can recover from a simple temporary monitor update failure optionally with
	// a disconnect in between
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let channel_id = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known()).2;

	let (route, payment_hash_1, payment_preimage_1, payment_secret_1) = get_route_and_payment_hash!(&nodes[0], nodes[1], 1000000);

	chanmon_cfgs[0].persister.set_update_ret(Err(ChannelMonitorUpdateErr::TemporaryFailure));

	{
		unwrap_send_err!(nodes[0].node.send_payment(&route, payment_hash_1, &Some(payment_secret_1)), false, APIError::MonitorUpdateFailed, {});
		check_added_monitors!(nodes[0], 1);
	}

	assert!(nodes[0].node.get_and_clear_pending_events().is_empty());
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	assert_eq!(nodes[0].node.list_channels().len(), 1);

	if disconnect {
		nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id(), false);
		nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);
		reconnect_nodes(&nodes[0], &nodes[1], (true, true), (0, 0), (0, 0), (0, 0), (0, 0), (0, 0), (false, false));
	}

	chanmon_cfgs[0].persister.set_update_ret(Ok(()));
	let (outpoint, latest_update, _) = nodes[0].chain_monitor.latest_monitor_update_id.lock().unwrap().get(&channel_id).unwrap().clone();
	nodes[0].chain_monitor.chain_monitor.force_channel_monitor_updated(outpoint, latest_update);
	check_added_monitors!(nodes[0], 0);

	let mut events_2 = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events_2.len(), 1);
	let payment_event = SendEvent::from_event(events_2.pop().unwrap());
	assert_eq!(payment_event.node_id, nodes[1].node.get_our_node_id());
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &payment_event.msgs[0]);
	commitment_signed_dance!(nodes[1], nodes[0], payment_event.commitment_msg, false);

	expect_pending_htlcs_forwardable!(nodes[1]);

	let events_3 = nodes[1].node.get_and_clear_pending_events();
	assert_eq!(events_3.len(), 1);
	match events_3[0] {
		Event::PaymentReceived { ref payment_hash, ref purpose, amt } => {
			assert_eq!(payment_hash_1, *payment_hash);
			assert_eq!(amt, 1000000);
			match &purpose {
				PaymentPurpose::InvoicePayment { payment_preimage, payment_secret, .. } => {
					assert!(payment_preimage.is_none());
					assert_eq!(payment_secret_1, *payment_secret);
				},
				_ => panic!("expected PaymentPurpose::InvoicePayment")
			}
		},
		_ => panic!("Unexpected event"),
	}

	claim_payment(&nodes[0], &[&nodes[1]], payment_preimage_1);

	// Now set it to failed again...
	let (route, payment_hash_2, _, payment_secret_2) = get_route_and_payment_hash!(&nodes[0], nodes[1], 1000000);
	{
		chanmon_cfgs[0].persister.set_update_ret(Err(ChannelMonitorUpdateErr::TemporaryFailure));
		unwrap_send_err!(nodes[0].node.send_payment(&route, payment_hash_2, &Some(payment_secret_2)), false, APIError::MonitorUpdateFailed, {});
		check_added_monitors!(nodes[0], 1);
	}

	assert!(nodes[0].node.get_and_clear_pending_events().is_empty());
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	assert_eq!(nodes[0].node.list_channels().len(), 1);

	if disconnect {
		nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id(), false);
		nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);
		reconnect_nodes(&nodes[0], &nodes[1], (false, false), (0, 0), (0, 0), (0, 0), (0, 0), (0, 0), (false, false));
	}

	// ...and make sure we can force-close a frozen channel
	nodes[0].node.force_close_channel(&channel_id).unwrap();
	check_added_monitors!(nodes[0], 1);
	check_closed_broadcast!(nodes[0], true);

	// TODO: Once we hit the chain with the failure transaction we should check that we get a
	// PaymentPathFailed event

	assert_eq!(nodes[0].node.list_channels().len(), 0);
	check_closed_event!(nodes[0], 1, ClosureReason::HolderForceClosed);
}

#[test]
fn test_simple_monitor_temporary_update_fail() {
	do_test_simple_monitor_temporary_update_fail(false);
	do_test_simple_monitor_temporary_update_fail(true);
}

fn do_test_monitor_temporary_update_fail(disconnect_count: usize) {
	let disconnect_flags = 8 | 16;

	// Test that we can recover from a temporary monitor update failure with some in-flight
	// HTLCs going on at the same time potentially with some disconnection thrown in.
	// * First we route a payment, then get a temporary monitor update failure when trying to
	//   route a second payment. We then claim the first payment.
	// * If disconnect_count is set, we will disconnect at this point (which is likely as
	//   TemporaryFailure likely indicates net disconnect which resulted in failing to update
	//   the ChannelMonitor on a watchtower).
	// * If !(disconnect_count & 16) we deliver a update_fulfill_htlc/CS for the first payment
	//   immediately, otherwise we wait disconnect and deliver them via the reconnect
	//   channel_reestablish processing (ie disconnect_count & 16 makes no sense if
	//   disconnect_count & !disconnect_flags is 0).
	// * We then update the channel monitor, reconnecting if disconnect_count is set and walk
	//   through message sending, potentially disconnect/reconnecting multiple times based on
	//   disconnect_count, to get the update_fulfill_htlc through.
	// * We then walk through more message exchanges to get the original update_add_htlc
	//   through, swapping message ordering based on disconnect_count & 8 and optionally
	//   disconnect/reconnecting based on disconnect_count.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let channel_id = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known()).2;

	let (payment_preimage_1, payment_hash_1, _) = route_payment(&nodes[0], &[&nodes[1]], 1000000);

	// Now try to send a second payment which will fail to send
	let (route, payment_hash_2, payment_preimage_2, payment_secret_2) = get_route_and_payment_hash!(nodes[0], nodes[1], 1000000);
	{
		chanmon_cfgs[0].persister.set_update_ret(Err(ChannelMonitorUpdateErr::TemporaryFailure));
		unwrap_send_err!(nodes[0].node.send_payment(&route, payment_hash_2, &Some(payment_secret_2)), false, APIError::MonitorUpdateFailed, {});
		check_added_monitors!(nodes[0], 1);
	}

	assert!(nodes[0].node.get_and_clear_pending_events().is_empty());
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	assert_eq!(nodes[0].node.list_channels().len(), 1);

	// Claim the previous payment, which will result in a update_fulfill_htlc/CS from nodes[1]
	// but nodes[0] won't respond since it is frozen.
	assert!(nodes[1].node.claim_funds(payment_preimage_1));
	check_added_monitors!(nodes[1], 1);
	let events_2 = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(events_2.len(), 1);
	let (bs_initial_fulfill, bs_initial_commitment_signed) = match events_2[0] {
		MessageSendEvent::UpdateHTLCs { ref node_id, updates: msgs::CommitmentUpdate { ref update_add_htlcs, ref update_fulfill_htlcs, ref update_fail_htlcs, ref update_fail_malformed_htlcs, ref update_fee, ref commitment_signed } } => {
			assert_eq!(*node_id, nodes[0].node.get_our_node_id());
			assert!(update_add_htlcs.is_empty());
			assert_eq!(update_fulfill_htlcs.len(), 1);
			assert!(update_fail_htlcs.is_empty());
			assert!(update_fail_malformed_htlcs.is_empty());
			assert!(update_fee.is_none());

			if (disconnect_count & 16) == 0 {
				nodes[0].node.handle_update_fulfill_htlc(&nodes[1].node.get_our_node_id(), &update_fulfill_htlcs[0]);
				let events_3 = nodes[0].node.get_and_clear_pending_events();
				assert_eq!(events_3.len(), 1);
				match events_3[0] {
					Event::PaymentSent { ref payment_preimage, ref payment_hash, .. } => {
						assert_eq!(*payment_preimage, payment_preimage_1);
						assert_eq!(*payment_hash, payment_hash_1);
					},
					_ => panic!("Unexpected event"),
				}

				nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), commitment_signed);
				check_added_monitors!(nodes[0], 1);
				assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
				nodes[0].logger.assert_log("lightning::ln::channelmanager".to_string(), "Previous monitor update failure prevented generation of RAA".to_string(), 1);
			}

			(update_fulfill_htlcs[0].clone(), commitment_signed.clone())
		},
		_ => panic!("Unexpected event"),
	};

	if disconnect_count & !disconnect_flags > 0 {
		nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id(), false);
		nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);
	}

	// Now fix monitor updating...
	chanmon_cfgs[0].persister.set_update_ret(Ok(()));
	let (outpoint, latest_update, _) = nodes[0].chain_monitor.latest_monitor_update_id.lock().unwrap().get(&channel_id).unwrap().clone();
	nodes[0].chain_monitor.chain_monitor.force_channel_monitor_updated(outpoint, latest_update);
	check_added_monitors!(nodes[0], 0);

	macro_rules! disconnect_reconnect_peers { () => { {
		nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id(), false);
		nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);

		nodes[0].node.peer_connected(&nodes[1].node.get_our_node_id(), &msgs::Init { features: InitFeatures::empty() });
		let reestablish_1 = get_chan_reestablish_msgs!(nodes[0], nodes[1]);
		assert_eq!(reestablish_1.len(), 1);
		nodes[1].node.peer_connected(&nodes[0].node.get_our_node_id(), &msgs::Init { features: InitFeatures::empty() });
		let reestablish_2 = get_chan_reestablish_msgs!(nodes[1], nodes[0]);
		assert_eq!(reestablish_2.len(), 1);

		nodes[0].node.handle_channel_reestablish(&nodes[1].node.get_our_node_id(), &reestablish_2[0]);
		let as_resp = handle_chan_reestablish_msgs!(nodes[0], nodes[1]);
		nodes[1].node.handle_channel_reestablish(&nodes[0].node.get_our_node_id(), &reestablish_1[0]);
		let bs_resp = handle_chan_reestablish_msgs!(nodes[1], nodes[0]);

		assert!(as_resp.0.is_none());
		assert!(bs_resp.0.is_none());

		(reestablish_1, reestablish_2, as_resp, bs_resp)
	} } }

	let (payment_event, initial_revoke_and_ack) = if disconnect_count & !disconnect_flags > 0 {
		assert!(nodes[0].node.get_and_clear_pending_events().is_empty());
		assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());

		nodes[0].node.peer_connected(&nodes[1].node.get_our_node_id(), &msgs::Init { features: InitFeatures::empty() });
		let reestablish_1 = get_chan_reestablish_msgs!(nodes[0], nodes[1]);
		assert_eq!(reestablish_1.len(), 1);
		nodes[1].node.peer_connected(&nodes[0].node.get_our_node_id(), &msgs::Init { features: InitFeatures::empty() });
		let reestablish_2 = get_chan_reestablish_msgs!(nodes[1], nodes[0]);
		assert_eq!(reestablish_2.len(), 1);

		nodes[0].node.handle_channel_reestablish(&nodes[1].node.get_our_node_id(), &reestablish_2[0]);
		check_added_monitors!(nodes[0], 0);
		let mut as_resp = handle_chan_reestablish_msgs!(nodes[0], nodes[1]);
		nodes[1].node.handle_channel_reestablish(&nodes[0].node.get_our_node_id(), &reestablish_1[0]);
		check_added_monitors!(nodes[1], 0);
		let mut bs_resp = handle_chan_reestablish_msgs!(nodes[1], nodes[0]);

		assert!(as_resp.0.is_none());
		assert!(bs_resp.0.is_none());

		assert!(bs_resp.1.is_none());
		if (disconnect_count & 16) == 0 {
			assert!(bs_resp.2.is_none());

			assert!(as_resp.1.is_some());
			assert!(as_resp.2.is_some());
			assert!(as_resp.3 == RAACommitmentOrder::CommitmentFirst);
		} else {
			assert!(bs_resp.2.as_ref().unwrap().update_add_htlcs.is_empty());
			assert!(bs_resp.2.as_ref().unwrap().update_fail_htlcs.is_empty());
			assert!(bs_resp.2.as_ref().unwrap().update_fail_malformed_htlcs.is_empty());
			assert!(bs_resp.2.as_ref().unwrap().update_fee.is_none());
			assert!(bs_resp.2.as_ref().unwrap().update_fulfill_htlcs == vec![bs_initial_fulfill]);
			assert!(bs_resp.2.as_ref().unwrap().commitment_signed == bs_initial_commitment_signed);

			assert!(as_resp.1.is_none());

			nodes[0].node.handle_update_fulfill_htlc(&nodes[1].node.get_our_node_id(), &bs_resp.2.as_ref().unwrap().update_fulfill_htlcs[0]);
			let events_3 = nodes[0].node.get_and_clear_pending_events();
			assert_eq!(events_3.len(), 1);
			match events_3[0] {
				Event::PaymentSent { ref payment_preimage, ref payment_hash, .. } => {
					assert_eq!(*payment_preimage, payment_preimage_1);
					assert_eq!(*payment_hash, payment_hash_1);
				},
				_ => panic!("Unexpected event"),
			}

			nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &bs_resp.2.as_ref().unwrap().commitment_signed);
			let as_resp_raa = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());
			// No commitment_signed so get_event_msg's assert(len == 1) passes
			check_added_monitors!(nodes[0], 1);

			as_resp.1 = Some(as_resp_raa);
			bs_resp.2 = None;
		}

		if disconnect_count & !disconnect_flags > 1 {
			let (second_reestablish_1, second_reestablish_2, second_as_resp, second_bs_resp) = disconnect_reconnect_peers!();

			if (disconnect_count & 16) == 0 {
				assert!(reestablish_1 == second_reestablish_1);
				assert!(reestablish_2 == second_reestablish_2);
			}
			assert!(as_resp == second_as_resp);
			assert!(bs_resp == second_bs_resp);
		}

		(SendEvent::from_commitment_update(nodes[1].node.get_our_node_id(), as_resp.2.unwrap()), as_resp.1.unwrap())
	} else {
		let mut events_4 = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(events_4.len(), 2);
		(SendEvent::from_event(events_4.remove(0)), match events_4[0] {
			MessageSendEvent::SendRevokeAndACK { ref node_id, ref msg } => {
				assert_eq!(*node_id, nodes[1].node.get_our_node_id());
				msg.clone()
			},
			_ => panic!("Unexpected event"),
		})
	};

	assert_eq!(payment_event.node_id, nodes[1].node.get_our_node_id());

	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &payment_event.msgs[0]);
	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &payment_event.commitment_msg);
	let bs_revoke_and_ack = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, nodes[0].node.get_our_node_id());
	// nodes[1] is awaiting an RAA from nodes[0] still so get_event_msg's assert(len == 1) passes
	check_added_monitors!(nodes[1], 1);

	if disconnect_count & !disconnect_flags > 2 {
		let (_, _, as_resp, bs_resp) = disconnect_reconnect_peers!();

		assert!(as_resp.1.unwrap() == initial_revoke_and_ack);
		assert!(bs_resp.1.unwrap() == bs_revoke_and_ack);

		assert!(as_resp.2.is_none());
		assert!(bs_resp.2.is_none());
	}

	let as_commitment_update;
	let bs_second_commitment_update;

	macro_rules! handle_bs_raa { () => {
		nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_revoke_and_ack);
		as_commitment_update = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
		assert!(as_commitment_update.update_add_htlcs.is_empty());
		assert!(as_commitment_update.update_fulfill_htlcs.is_empty());
		assert!(as_commitment_update.update_fail_htlcs.is_empty());
		assert!(as_commitment_update.update_fail_malformed_htlcs.is_empty());
		assert!(as_commitment_update.update_fee.is_none());
		check_added_monitors!(nodes[0], 1);
	} }

	macro_rules! handle_initial_raa { () => {
		nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &initial_revoke_and_ack);
		bs_second_commitment_update = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
		assert!(bs_second_commitment_update.update_add_htlcs.is_empty());
		assert!(bs_second_commitment_update.update_fulfill_htlcs.is_empty());
		assert!(bs_second_commitment_update.update_fail_htlcs.is_empty());
		assert!(bs_second_commitment_update.update_fail_malformed_htlcs.is_empty());
		assert!(bs_second_commitment_update.update_fee.is_none());
		check_added_monitors!(nodes[1], 1);
	} }

	if (disconnect_count & 8) == 0 {
		handle_bs_raa!();

		if disconnect_count & !disconnect_flags > 3 {
			let (_, _, as_resp, bs_resp) = disconnect_reconnect_peers!();

			assert!(as_resp.1.unwrap() == initial_revoke_and_ack);
			assert!(bs_resp.1.is_none());

			assert!(as_resp.2.unwrap() == as_commitment_update);
			assert!(bs_resp.2.is_none());

			assert!(as_resp.3 == RAACommitmentOrder::RevokeAndACKFirst);
		}

		handle_initial_raa!();

		if disconnect_count & !disconnect_flags > 4 {
			let (_, _, as_resp, bs_resp) = disconnect_reconnect_peers!();

			assert!(as_resp.1.is_none());
			assert!(bs_resp.1.is_none());

			assert!(as_resp.2.unwrap() == as_commitment_update);
			assert!(bs_resp.2.unwrap() == bs_second_commitment_update);
		}
	} else {
		handle_initial_raa!();

		if disconnect_count & !disconnect_flags > 3 {
			let (_, _, as_resp, bs_resp) = disconnect_reconnect_peers!();

			assert!(as_resp.1.is_none());
			assert!(bs_resp.1.unwrap() == bs_revoke_and_ack);

			assert!(as_resp.2.is_none());
			assert!(bs_resp.2.unwrap() == bs_second_commitment_update);

			assert!(bs_resp.3 == RAACommitmentOrder::RevokeAndACKFirst);
		}

		handle_bs_raa!();

		if disconnect_count & !disconnect_flags > 4 {
			let (_, _, as_resp, bs_resp) = disconnect_reconnect_peers!();

			assert!(as_resp.1.is_none());
			assert!(bs_resp.1.is_none());

			assert!(as_resp.2.unwrap() == as_commitment_update);
			assert!(bs_resp.2.unwrap() == bs_second_commitment_update);
		}
	}

	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &bs_second_commitment_update.commitment_signed);
	let as_revoke_and_ack = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());
	// No commitment_signed so get_event_msg's assert(len == 1) passes
	check_added_monitors!(nodes[0], 1);

	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &as_commitment_update.commitment_signed);
	let bs_second_revoke_and_ack = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, nodes[0].node.get_our_node_id());
	// No commitment_signed so get_event_msg's assert(len == 1) passes
	check_added_monitors!(nodes[1], 1);

	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &as_revoke_and_ack);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	check_added_monitors!(nodes[1], 1);

	nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_second_revoke_and_ack);
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	check_added_monitors!(nodes[0], 1);
	expect_payment_path_successful!(nodes[0]);

	expect_pending_htlcs_forwardable!(nodes[1]);

	let events_5 = nodes[1].node.get_and_clear_pending_events();
	assert_eq!(events_5.len(), 1);
	match events_5[0] {
		Event::PaymentReceived { ref payment_hash, ref purpose, amt } => {
			assert_eq!(payment_hash_2, *payment_hash);
			assert_eq!(amt, 1000000);
			match &purpose {
				PaymentPurpose::InvoicePayment { payment_preimage, payment_secret, .. } => {
					assert!(payment_preimage.is_none());
					assert_eq!(payment_secret_2, *payment_secret);
				},
				_ => panic!("expected PaymentPurpose::InvoicePayment")
			}
		},
		_ => panic!("Unexpected event"),
	}

	claim_payment(&nodes[0], &[&nodes[1]], payment_preimage_2);
}

#[test]
fn test_monitor_temporary_update_fail_a() {
	do_test_monitor_temporary_update_fail(0);
	do_test_monitor_temporary_update_fail(1);
	do_test_monitor_temporary_update_fail(2);
	do_test_monitor_temporary_update_fail(3);
	do_test_monitor_temporary_update_fail(4);
	do_test_monitor_temporary_update_fail(5);
}

#[test]
fn test_monitor_temporary_update_fail_b() {
	do_test_monitor_temporary_update_fail(2 | 8);
	do_test_monitor_temporary_update_fail(3 | 8);
	do_test_monitor_temporary_update_fail(4 | 8);
	do_test_monitor_temporary_update_fail(5 | 8);
}

#[test]
fn test_monitor_temporary_update_fail_c() {
	do_test_monitor_temporary_update_fail(1 | 16);
	do_test_monitor_temporary_update_fail(2 | 16);
	do_test_monitor_temporary_update_fail(3 | 16);
	do_test_monitor_temporary_update_fail(2 | 8 | 16);
	do_test_monitor_temporary_update_fail(3 | 8 | 16);
}

#[test]
fn test_monitor_update_fail_cs() {
	// Tests handling of a monitor update failure when processing an incoming commitment_signed
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let channel_id = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known()).2;

	let (route, our_payment_hash, payment_preimage, our_payment_secret) = get_route_and_payment_hash!(nodes[0], nodes[1], 1000000);
	{
		nodes[0].node.send_payment(&route, our_payment_hash, &Some(our_payment_secret)).unwrap();
		check_added_monitors!(nodes[0], 1);
	}

	let send_event = SendEvent::from_event(nodes[0].node.get_and_clear_pending_msg_events().remove(0));
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &send_event.msgs[0]);

	chanmon_cfgs[1].persister.set_update_ret(Err(ChannelMonitorUpdateErr::TemporaryFailure));
	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &send_event.commitment_msg);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	nodes[1].logger.assert_log("lightning::ln::channelmanager".to_string(), "Failed to update ChannelMonitor".to_string(), 1);
	check_added_monitors!(nodes[1], 1);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	chanmon_cfgs[1].persister.set_update_ret(Ok(()));
	let (outpoint, latest_update, _) = nodes[1].chain_monitor.latest_monitor_update_id.lock().unwrap().get(&channel_id).unwrap().clone();
	nodes[1].chain_monitor.chain_monitor.force_channel_monitor_updated(outpoint, latest_update);
	check_added_monitors!(nodes[1], 0);
	let responses = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(responses.len(), 2);

	match responses[0] {
		MessageSendEvent::SendRevokeAndACK { ref msg, ref node_id } => {
			assert_eq!(*node_id, nodes[0].node.get_our_node_id());
			nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &msg);
			check_added_monitors!(nodes[0], 1);
		},
		_ => panic!("Unexpected event"),
	}
	match responses[1] {
		MessageSendEvent::UpdateHTLCs { ref updates, ref node_id } => {
			assert!(updates.update_add_htlcs.is_empty());
			assert!(updates.update_fulfill_htlcs.is_empty());
			assert!(updates.update_fail_htlcs.is_empty());
			assert!(updates.update_fail_malformed_htlcs.is_empty());
			assert!(updates.update_fee.is_none());
			assert_eq!(*node_id, nodes[0].node.get_our_node_id());

			chanmon_cfgs[0].persister.set_update_ret(Err(ChannelMonitorUpdateErr::TemporaryFailure));
			nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &updates.commitment_signed);
			assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
			nodes[0].logger.assert_log("lightning::ln::channelmanager".to_string(), "Failed to update ChannelMonitor".to_string(), 1);
			check_added_monitors!(nodes[0], 1);
			assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
		},
		_ => panic!("Unexpected event"),
	}

	chanmon_cfgs[0].persister.set_update_ret(Ok(()));
	let (outpoint, latest_update, _) = nodes[0].chain_monitor.latest_monitor_update_id.lock().unwrap().get(&channel_id).unwrap().clone();
	nodes[0].chain_monitor.chain_monitor.force_channel_monitor_updated(outpoint, latest_update);
	check_added_monitors!(nodes[0], 0);

	let final_raa = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());
	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &final_raa);
	check_added_monitors!(nodes[1], 1);

	expect_pending_htlcs_forwardable!(nodes[1]);

	let events = nodes[1].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		Event::PaymentReceived { payment_hash, ref purpose, amt } => {
			assert_eq!(payment_hash, our_payment_hash);
			assert_eq!(amt, 1000000);
			match &purpose {
				PaymentPurpose::InvoicePayment { payment_preimage, payment_secret, .. } => {
					assert!(payment_preimage.is_none());
					assert_eq!(our_payment_secret, *payment_secret);
				},
				_ => panic!("expected PaymentPurpose::InvoicePayment")
			}
		},
		_ => panic!("Unexpected event"),
	};

	claim_payment(&nodes[0], &[&nodes[1]], payment_preimage);
}

#[test]
fn test_monitor_update_fail_no_rebroadcast() {
	// Tests handling of a monitor update failure when no message rebroadcasting on
	// channel_monitor_updated() is required. Backported from chanmon_fail_consistency
	// fuzz tests.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let channel_id = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known()).2;

	let (route, our_payment_hash, payment_preimage_1, payment_secret_1) = get_route_and_payment_hash!(nodes[0], nodes[1], 1000000);
	{
		nodes[0].node.send_payment(&route, our_payment_hash, &Some(payment_secret_1)).unwrap();
		check_added_monitors!(nodes[0], 1);
	}

	let send_event = SendEvent::from_event(nodes[0].node.get_and_clear_pending_msg_events().remove(0));
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &send_event.msgs[0]);
	let bs_raa = commitment_signed_dance!(nodes[1], nodes[0], send_event.commitment_msg, false, true, false, true);

	chanmon_cfgs[1].persister.set_update_ret(Err(ChannelMonitorUpdateErr::TemporaryFailure));
	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &bs_raa);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	nodes[1].logger.assert_log("lightning::ln::channelmanager".to_string(), "Failed to update ChannelMonitor".to_string(), 1);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	assert!(nodes[1].node.get_and_clear_pending_events().is_empty());
	check_added_monitors!(nodes[1], 1);

	chanmon_cfgs[1].persister.set_update_ret(Ok(()));
	let (outpoint, latest_update, _) = nodes[1].chain_monitor.latest_monitor_update_id.lock().unwrap().get(&channel_id).unwrap().clone();
	nodes[1].chain_monitor.chain_monitor.force_channel_monitor_updated(outpoint, latest_update);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	check_added_monitors!(nodes[1], 0);
	expect_pending_htlcs_forwardable!(nodes[1]);

	let events = nodes[1].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		Event::PaymentReceived { payment_hash, .. } => {
			assert_eq!(payment_hash, our_payment_hash);
		},
		_ => panic!("Unexpected event"),
	}

	claim_payment(&nodes[0], &[&nodes[1]], payment_preimage_1);
}

#[test]
fn test_monitor_update_raa_while_paused() {
	// Tests handling of an RAA while monitor updating has already been marked failed.
	// Backported from chanmon_fail_consistency fuzz tests as this used to be broken.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let channel_id = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known()).2;

	send_payment(&nodes[0], &[&nodes[1]], 5000000);
	let (route, our_payment_hash_1, payment_preimage_1, our_payment_secret_1) = get_route_and_payment_hash!(nodes[0], nodes[1], 1000000);
	{
		nodes[0].node.send_payment(&route, our_payment_hash_1, &Some(our_payment_secret_1)).unwrap();
		check_added_monitors!(nodes[0], 1);
	}
	let send_event_1 = SendEvent::from_event(nodes[0].node.get_and_clear_pending_msg_events().remove(0));

	let (route, our_payment_hash_2, payment_preimage_2, our_payment_secret_2) = get_route_and_payment_hash!(nodes[1], nodes[0], 1000000);
	{
		nodes[1].node.send_payment(&route, our_payment_hash_2, &Some(our_payment_secret_2)).unwrap();
		check_added_monitors!(nodes[1], 1);
	}
	let send_event_2 = SendEvent::from_event(nodes[1].node.get_and_clear_pending_msg_events().remove(0));

	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &send_event_1.msgs[0]);
	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &send_event_1.commitment_msg);
	check_added_monitors!(nodes[1], 1);
	let bs_raa = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, nodes[0].node.get_our_node_id());

	chanmon_cfgs[0].persister.set_update_ret(Err(ChannelMonitorUpdateErr::TemporaryFailure));
	nodes[0].node.handle_update_add_htlc(&nodes[1].node.get_our_node_id(), &send_event_2.msgs[0]);
	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &send_event_2.commitment_msg);
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	nodes[0].logger.assert_log("lightning::ln::channelmanager".to_string(), "Failed to update ChannelMonitor".to_string(), 1);
	check_added_monitors!(nodes[0], 1);

	nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_raa);
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	nodes[0].logger.assert_log("lightning::ln::channelmanager".to_string(), "Previous monitor update failure prevented responses to RAA".to_string(), 1);
	check_added_monitors!(nodes[0], 1);

	chanmon_cfgs[0].persister.set_update_ret(Ok(()));
	let (outpoint, latest_update, _) = nodes[0].chain_monitor.latest_monitor_update_id.lock().unwrap().get(&channel_id).unwrap().clone();
	nodes[0].chain_monitor.chain_monitor.force_channel_monitor_updated(outpoint, latest_update);
	check_added_monitors!(nodes[0], 0);

	let as_update_raa = get_revoke_commit_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &as_update_raa.0);
	check_added_monitors!(nodes[1], 1);
	let bs_cs = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());

	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &as_update_raa.1);
	check_added_monitors!(nodes[1], 1);
	let bs_second_raa = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, nodes[0].node.get_our_node_id());

	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &bs_cs.commitment_signed);
	check_added_monitors!(nodes[0], 1);
	let as_second_raa = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());

	nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_second_raa);
	check_added_monitors!(nodes[0], 1);
	expect_pending_htlcs_forwardable!(nodes[0]);
	expect_payment_received!(nodes[0], our_payment_hash_2, our_payment_secret_2, 1000000);

	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &as_second_raa);
	check_added_monitors!(nodes[1], 1);
	expect_pending_htlcs_forwardable!(nodes[1]);
	expect_payment_received!(nodes[1], our_payment_hash_1, our_payment_secret_1, 1000000);

	claim_payment(&nodes[0], &[&nodes[1]], payment_preimage_1);
	claim_payment(&nodes[1], &[&nodes[0]], payment_preimage_2);
}

fn do_test_monitor_update_fail_raa(test_ignore_second_cs: bool) {
	// Tests handling of a monitor update failure when processing an incoming RAA
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());
	let chan_2 = create_announced_chan_between_nodes(&nodes, 1, 2, InitFeatures::known(), InitFeatures::known());

	// Rebalance a bit so that we can send backwards from 2 to 1.
	send_payment(&nodes[0], &[&nodes[1], &nodes[2]], 5000000);

	// Route a first payment that we'll fail backwards
	let (_, payment_hash_1, _) = route_payment(&nodes[0], &[&nodes[1], &nodes[2]], 1000000);

	// Fail the payment backwards, failing the monitor update on nodes[1]'s receipt of the RAA
	assert!(nodes[2].node.fail_htlc_backwards(&payment_hash_1));
	expect_pending_htlcs_forwardable!(nodes[2]);
	check_added_monitors!(nodes[2], 1);

	let updates = get_htlc_update_msgs!(nodes[2], nodes[1].node.get_our_node_id());
	assert!(updates.update_add_htlcs.is_empty());
	assert!(updates.update_fulfill_htlcs.is_empty());
	assert_eq!(updates.update_fail_htlcs.len(), 1);
	assert!(updates.update_fail_malformed_htlcs.is_empty());
	assert!(updates.update_fee.is_none());
	nodes[1].node.handle_update_fail_htlc(&nodes[2].node.get_our_node_id(), &updates.update_fail_htlcs[0]);

	let bs_revoke_and_ack = commitment_signed_dance!(nodes[1], nodes[2], updates.commitment_signed, false, true, false, true);
	check_added_monitors!(nodes[0], 0);

	// While the second channel is AwaitingRAA, forward a second payment to get it into the
	// holding cell.
	let (route, payment_hash_2, payment_preimage_2, payment_secret_2) = get_route_and_payment_hash!(nodes[0], nodes[2], 1000000);
	{
		nodes[0].node.send_payment(&route, payment_hash_2, &Some(payment_secret_2)).unwrap();
		check_added_monitors!(nodes[0], 1);
	}

	let mut send_event = SendEvent::from_event(nodes[0].node.get_and_clear_pending_msg_events().remove(0));
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &send_event.msgs[0]);
	commitment_signed_dance!(nodes[1], nodes[0], send_event.commitment_msg, false);

	expect_pending_htlcs_forwardable!(nodes[1]);
	check_added_monitors!(nodes[1], 0);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	// Now fail monitor updating.
	chanmon_cfgs[1].persister.set_update_ret(Err(ChannelMonitorUpdateErr::TemporaryFailure));
	nodes[1].node.handle_revoke_and_ack(&nodes[2].node.get_our_node_id(), &bs_revoke_and_ack);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	nodes[1].logger.assert_log("lightning::ln::channelmanager".to_string(), "Failed to update ChannelMonitor".to_string(), 1);
	assert!(nodes[1].node.get_and_clear_pending_events().is_empty());
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	check_added_monitors!(nodes[1], 1);

	// Forward a third payment which will also be added to the holding cell, despite the channel
	// being paused waiting a monitor update.
	let (route, payment_hash_3, _, payment_secret_3) = get_route_and_payment_hash!(nodes[0], nodes[2], 1000000);
	{
		nodes[0].node.send_payment(&route, payment_hash_3, &Some(payment_secret_3)).unwrap();
		check_added_monitors!(nodes[0], 1);
	}

	chanmon_cfgs[1].persister.set_update_ret(Ok(())); // We succeed in updating the monitor for the first channel
	send_event = SendEvent::from_event(nodes[0].node.get_and_clear_pending_msg_events().remove(0));
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &send_event.msgs[0]);
	commitment_signed_dance!(nodes[1], nodes[0], send_event.commitment_msg, false, true);
	check_added_monitors!(nodes[1], 0);

	// Call forward_pending_htlcs and check that the new HTLC was simply added to the holding cell
	// and not forwarded.
	expect_pending_htlcs_forwardable!(nodes[1]);
	check_added_monitors!(nodes[1], 0);
	assert!(nodes[1].node.get_and_clear_pending_events().is_empty());

	let (payment_preimage_4, payment_hash_4) = if test_ignore_second_cs {
		// Try to route another payment backwards from 2 to make sure 1 holds off on responding
		let (route, payment_hash_4, payment_preimage_4, payment_secret_4) = get_route_and_payment_hash!(nodes[2], nodes[0], 1000000);
		nodes[2].node.send_payment(&route, payment_hash_4, &Some(payment_secret_4)).unwrap();
		check_added_monitors!(nodes[2], 1);

		send_event = SendEvent::from_event(nodes[2].node.get_and_clear_pending_msg_events().remove(0));
		nodes[1].node.handle_update_add_htlc(&nodes[2].node.get_our_node_id(), &send_event.msgs[0]);
		nodes[1].node.handle_commitment_signed(&nodes[2].node.get_our_node_id(), &send_event.commitment_msg);
		check_added_monitors!(nodes[1], 1);
		assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
		nodes[1].logger.assert_log("lightning::ln::channelmanager".to_string(), "Previous monitor update failure prevented generation of RAA".to_string(), 1);
		assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
		(Some(payment_preimage_4), Some(payment_hash_4))
	} else { (None, None) };

	// Restore monitor updating, ensuring we immediately get a fail-back update and a
	// update_add update.
	chanmon_cfgs[1].persister.set_update_ret(Ok(()));
	let (outpoint, latest_update, _) = nodes[1].chain_monitor.latest_monitor_update_id.lock().unwrap().get(&chan_2.2).unwrap().clone();
	nodes[1].chain_monitor.chain_monitor.force_channel_monitor_updated(outpoint, latest_update);
	check_added_monitors!(nodes[1], 0);
	expect_pending_htlcs_forwardable!(nodes[1]);
	check_added_monitors!(nodes[1], 1);

	let mut events_3 = nodes[1].node.get_and_clear_pending_msg_events();
	if test_ignore_second_cs {
		assert_eq!(events_3.len(), 3);
	} else {
		assert_eq!(events_3.len(), 2);
	}

	// Note that the ordering of the events for different nodes is non-prescriptive, though the
	// ordering of the two events that both go to nodes[2] have to stay in the same order.
	let messages_a = match events_3.pop().unwrap() {
		MessageSendEvent::UpdateHTLCs { node_id, mut updates } => {
			assert_eq!(node_id, nodes[0].node.get_our_node_id());
			assert!(updates.update_fulfill_htlcs.is_empty());
			assert_eq!(updates.update_fail_htlcs.len(), 1);
			assert!(updates.update_fail_malformed_htlcs.is_empty());
			assert!(updates.update_add_htlcs.is_empty());
			assert!(updates.update_fee.is_none());
			(updates.update_fail_htlcs.remove(0), updates.commitment_signed)
		},
		_ => panic!("Unexpected event type!"),
	};
	let raa = if test_ignore_second_cs {
		match events_3.remove(1) {
			MessageSendEvent::SendRevokeAndACK { node_id, msg } => {
				assert_eq!(node_id, nodes[2].node.get_our_node_id());
				Some(msg.clone())
			},
			_ => panic!("Unexpected event"),
		}
	} else { None };
	let send_event_b = SendEvent::from_event(events_3.remove(0));
	assert_eq!(send_event_b.node_id, nodes[2].node.get_our_node_id());

	// Now deliver the new messages...

	nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &messages_a.0);
	commitment_signed_dance!(nodes[0], nodes[1], messages_a.1, false);
	expect_payment_failed!(nodes[0], payment_hash_1, true);

	nodes[2].node.handle_update_add_htlc(&nodes[1].node.get_our_node_id(), &send_event_b.msgs[0]);
	let as_cs;
	if test_ignore_second_cs {
		nodes[2].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &send_event_b.commitment_msg);
		check_added_monitors!(nodes[2], 1);
		let bs_revoke_and_ack = get_event_msg!(nodes[2], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());
		nodes[2].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &raa.unwrap());
		check_added_monitors!(nodes[2], 1);
		let bs_cs = get_htlc_update_msgs!(nodes[2], nodes[1].node.get_our_node_id());
		assert!(bs_cs.update_add_htlcs.is_empty());
		assert!(bs_cs.update_fail_htlcs.is_empty());
		assert!(bs_cs.update_fail_malformed_htlcs.is_empty());
		assert!(bs_cs.update_fulfill_htlcs.is_empty());
		assert!(bs_cs.update_fee.is_none());

		nodes[1].node.handle_revoke_and_ack(&nodes[2].node.get_our_node_id(), &bs_revoke_and_ack);
		check_added_monitors!(nodes[1], 1);
		as_cs = get_htlc_update_msgs!(nodes[1], nodes[2].node.get_our_node_id());

		nodes[1].node.handle_commitment_signed(&nodes[2].node.get_our_node_id(), &bs_cs.commitment_signed);
		check_added_monitors!(nodes[1], 1);
	} else {
		nodes[2].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &send_event_b.commitment_msg);
		check_added_monitors!(nodes[2], 1);

		let bs_revoke_and_commit = nodes[2].node.get_and_clear_pending_msg_events();
		assert_eq!(bs_revoke_and_commit.len(), 2);
		match bs_revoke_and_commit[0] {
			MessageSendEvent::SendRevokeAndACK { ref node_id, ref msg } => {
				assert_eq!(*node_id, nodes[1].node.get_our_node_id());
				nodes[1].node.handle_revoke_and_ack(&nodes[2].node.get_our_node_id(), &msg);
				check_added_monitors!(nodes[1], 1);
			},
			_ => panic!("Unexpected event"),
		}

		as_cs = get_htlc_update_msgs!(nodes[1], nodes[2].node.get_our_node_id());

		match bs_revoke_and_commit[1] {
			MessageSendEvent::UpdateHTLCs { ref node_id, ref updates } => {
				assert_eq!(*node_id, nodes[1].node.get_our_node_id());
				assert!(updates.update_add_htlcs.is_empty());
				assert!(updates.update_fail_htlcs.is_empty());
				assert!(updates.update_fail_malformed_htlcs.is_empty());
				assert!(updates.update_fulfill_htlcs.is_empty());
				assert!(updates.update_fee.is_none());
				nodes[1].node.handle_commitment_signed(&nodes[2].node.get_our_node_id(), &updates.commitment_signed);
				check_added_monitors!(nodes[1], 1);
			},
			_ => panic!("Unexpected event"),
		}
	}

	assert_eq!(as_cs.update_add_htlcs.len(), 1);
	assert!(as_cs.update_fail_htlcs.is_empty());
	assert!(as_cs.update_fail_malformed_htlcs.is_empty());
	assert!(as_cs.update_fulfill_htlcs.is_empty());
	assert!(as_cs.update_fee.is_none());
	let as_raa = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, nodes[2].node.get_our_node_id());


	nodes[2].node.handle_update_add_htlc(&nodes[1].node.get_our_node_id(), &as_cs.update_add_htlcs[0]);
	nodes[2].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &as_cs.commitment_signed);
	check_added_monitors!(nodes[2], 1);
	let bs_second_raa = get_event_msg!(nodes[2], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());

	nodes[2].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &as_raa);
	check_added_monitors!(nodes[2], 1);
	let bs_second_cs = get_htlc_update_msgs!(nodes[2], nodes[1].node.get_our_node_id());

	nodes[1].node.handle_revoke_and_ack(&nodes[2].node.get_our_node_id(), &bs_second_raa);
	check_added_monitors!(nodes[1], 1);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	nodes[1].node.handle_commitment_signed(&nodes[2].node.get_our_node_id(), &bs_second_cs.commitment_signed);
	check_added_monitors!(nodes[1], 1);
	let as_second_raa = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, nodes[2].node.get_our_node_id());

	nodes[2].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &as_second_raa);
	check_added_monitors!(nodes[2], 1);
	assert!(nodes[2].node.get_and_clear_pending_msg_events().is_empty());

	expect_pending_htlcs_forwardable!(nodes[2]);

	let events_6 = nodes[2].node.get_and_clear_pending_events();
	assert_eq!(events_6.len(), 2);
	match events_6[0] {
		Event::PaymentReceived { payment_hash, .. } => { assert_eq!(payment_hash, payment_hash_2); },
		_ => panic!("Unexpected event"),
	};
	match events_6[1] {
		Event::PaymentReceived { payment_hash, .. } => { assert_eq!(payment_hash, payment_hash_3); },
		_ => panic!("Unexpected event"),
	};

	if test_ignore_second_cs {
		expect_pending_htlcs_forwardable!(nodes[1]);
		check_added_monitors!(nodes[1], 1);

		send_event = SendEvent::from_node(&nodes[1]);
		assert_eq!(send_event.node_id, nodes[0].node.get_our_node_id());
		assert_eq!(send_event.msgs.len(), 1);
		nodes[0].node.handle_update_add_htlc(&nodes[1].node.get_our_node_id(), &send_event.msgs[0]);
		commitment_signed_dance!(nodes[0], nodes[1], send_event.commitment_msg, false);

		expect_pending_htlcs_forwardable!(nodes[0]);

		let events_9 = nodes[0].node.get_and_clear_pending_events();
		assert_eq!(events_9.len(), 1);
		match events_9[0] {
			Event::PaymentReceived { payment_hash, .. } => assert_eq!(payment_hash, payment_hash_4.unwrap()),
			_ => panic!("Unexpected event"),
		};
		claim_payment(&nodes[2], &[&nodes[1], &nodes[0]], payment_preimage_4.unwrap());
	}

	claim_payment(&nodes[0], &[&nodes[1], &nodes[2]], payment_preimage_2);
}

#[test]
fn test_monitor_update_fail_raa() {
	do_test_monitor_update_fail_raa(false);
	do_test_monitor_update_fail_raa(true);
}

#[test]
fn test_monitor_update_fail_reestablish() {
	// Simple test for message retransmission after monitor update failure on
	// channel_reestablish generating a monitor update (which comes from freeing holding cell
	// HTLCs).
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());
	create_announced_chan_between_nodes(&nodes, 1, 2, InitFeatures::known(), InitFeatures::known());

	let (payment_preimage, _, _) = route_payment(&nodes[0], &[&nodes[1], &nodes[2]], 1000000);

	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);
	nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id(), false);

	assert!(nodes[2].node.claim_funds(payment_preimage));
	check_added_monitors!(nodes[2], 1);
	let mut updates = get_htlc_update_msgs!(nodes[2], nodes[1].node.get_our_node_id());
	assert!(updates.update_add_htlcs.is_empty());
	assert!(updates.update_fail_htlcs.is_empty());
	assert!(updates.update_fail_malformed_htlcs.is_empty());
	assert!(updates.update_fee.is_none());
	assert_eq!(updates.update_fulfill_htlcs.len(), 1);
	nodes[1].node.handle_update_fulfill_htlc(&nodes[2].node.get_our_node_id(), &updates.update_fulfill_htlcs[0]);
	expect_payment_forwarded!(nodes[1], Some(1000), false);
	check_added_monitors!(nodes[1], 1);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	commitment_signed_dance!(nodes[1], nodes[2], updates.commitment_signed, false);

	chanmon_cfgs[1].persister.set_update_ret(Err(ChannelMonitorUpdateErr::TemporaryFailure));
	nodes[0].node.peer_connected(&nodes[1].node.get_our_node_id(), &msgs::Init { features: InitFeatures::empty() });
	nodes[1].node.peer_connected(&nodes[0].node.get_our_node_id(), &msgs::Init { features: InitFeatures::empty() });

	let as_reestablish = get_event_msg!(nodes[0], MessageSendEvent::SendChannelReestablish, nodes[1].node.get_our_node_id());
	let bs_reestablish = get_event_msg!(nodes[1], MessageSendEvent::SendChannelReestablish, nodes[0].node.get_our_node_id());

	nodes[0].node.handle_channel_reestablish(&nodes[1].node.get_our_node_id(), &bs_reestablish);

	nodes[1].node.handle_channel_reestablish(&nodes[0].node.get_our_node_id(), &as_reestablish);
	assert_eq!(
		get_event_msg!(nodes[0], MessageSendEvent::SendChannelUpdate, nodes[1].node.get_our_node_id())
			.contents.flags & 2, 0); // The "disabled" bit should be unset as we just reconnected

	nodes[1].logger.assert_log("lightning::ln::channelmanager".to_string(), "Failed to update ChannelMonitor".to_string(), 1);
	check_added_monitors!(nodes[1], 1);

	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);
	nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id(), false);

	nodes[0].node.peer_connected(&nodes[1].node.get_our_node_id(), &msgs::Init { features: InitFeatures::empty() });
	nodes[1].node.peer_connected(&nodes[0].node.get_our_node_id(), &msgs::Init { features: InitFeatures::empty() });

	assert!(as_reestablish == get_event_msg!(nodes[0], MessageSendEvent::SendChannelReestablish, nodes[1].node.get_our_node_id()));
	assert!(bs_reestablish == get_event_msg!(nodes[1], MessageSendEvent::SendChannelReestablish, nodes[0].node.get_our_node_id()));

	nodes[0].node.handle_channel_reestablish(&nodes[1].node.get_our_node_id(), &bs_reestablish);
	assert_eq!(
		get_event_msg!(nodes[0], MessageSendEvent::SendChannelUpdate, nodes[1].node.get_our_node_id())
			.contents.flags & 2, 0); // The "disabled" bit should be unset as we just reconnected

	nodes[1].node.handle_channel_reestablish(&nodes[0].node.get_our_node_id(), &as_reestablish);
	check_added_monitors!(nodes[1], 0);
	assert_eq!(
		get_event_msg!(nodes[1], MessageSendEvent::SendChannelUpdate, nodes[0].node.get_our_node_id())
			.contents.flags & 2, 0); // The "disabled" bit should be unset as we just reconnected

	chanmon_cfgs[1].persister.set_update_ret(Ok(()));
	let (outpoint, latest_update, _) = nodes[1].chain_monitor.latest_monitor_update_id.lock().unwrap().get(&chan_1.2).unwrap().clone();
	nodes[1].chain_monitor.chain_monitor.force_channel_monitor_updated(outpoint, latest_update);
	check_added_monitors!(nodes[1], 0);

	updates = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	assert!(updates.update_add_htlcs.is_empty());
	assert!(updates.update_fail_htlcs.is_empty());
	assert!(updates.update_fail_malformed_htlcs.is_empty());
	assert!(updates.update_fee.is_none());
	assert_eq!(updates.update_fulfill_htlcs.len(), 1);
	nodes[0].node.handle_update_fulfill_htlc(&nodes[1].node.get_our_node_id(), &updates.update_fulfill_htlcs[0]);
	commitment_signed_dance!(nodes[0], nodes[1], updates.commitment_signed, false);
	expect_payment_sent!(nodes[0], payment_preimage);
}

#[test]
fn raa_no_response_awaiting_raa_state() {
	// This is a rather convoluted test which ensures that if handling of an RAA does not happen
	// due to a previous monitor update failure, we still set AwaitingRemoteRevoke on the channel
	// in question (assuming it intends to respond with a CS after monitor updating is restored).
	// Backported from chanmon_fail_consistency fuzz tests as this used to be broken.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let channel_id = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known()).2;

	let (route, payment_hash_1, payment_preimage_1, payment_secret_1) = get_route_and_payment_hash!(nodes[0], nodes[1], 1000000);
	let (payment_preimage_2, payment_hash_2, payment_secret_2) = get_payment_preimage_hash!(nodes[1]);
	let (payment_preimage_3, payment_hash_3, payment_secret_3) = get_payment_preimage_hash!(nodes[1]);

	// Queue up two payments - one will be delivered right away, one immediately goes into the
	// holding cell as nodes[0] is AwaitingRAA. Ultimately this allows us to deliver an RAA
	// immediately after a CS. By setting failing the monitor update failure from the CS (which
	// requires only an RAA response due to AwaitingRAA) we can deliver the RAA and require the CS
	// generation during RAA while in monitor-update-failed state.
	{
		nodes[0].node.send_payment(&route, payment_hash_1, &Some(payment_secret_1)).unwrap();
		check_added_monitors!(nodes[0], 1);
		nodes[0].node.send_payment(&route, payment_hash_2, &Some(payment_secret_2)).unwrap();
		check_added_monitors!(nodes[0], 0);
	}

	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let payment_event = SendEvent::from_event(events.pop().unwrap());
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &payment_event.msgs[0]);
	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &payment_event.commitment_msg);
	check_added_monitors!(nodes[1], 1);

	let bs_responses = get_revoke_commit_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_responses.0);
	check_added_monitors!(nodes[0], 1);
	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let payment_event = SendEvent::from_event(events.pop().unwrap());

	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &bs_responses.1);
	check_added_monitors!(nodes[0], 1);
	let as_raa = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());

	// Now we have a CS queued up which adds a new HTLC (which will need a RAA/CS response from
	// nodes[1]) followed by an RAA. Fail the monitor updating prior to the CS, deliver the RAA,
	// then restore channel monitor updates.
	chanmon_cfgs[1].persister.set_update_ret(Err(ChannelMonitorUpdateErr::TemporaryFailure));
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &payment_event.msgs[0]);
	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &payment_event.commitment_msg);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	nodes[1].logger.assert_log("lightning::ln::channelmanager".to_string(), "Failed to update ChannelMonitor".to_string(), 1);
	check_added_monitors!(nodes[1], 1);

	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &as_raa);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	nodes[1].logger.assert_log("lightning::ln::channelmanager".to_string(), "Previous monitor update failure prevented responses to RAA".to_string(), 1);
	check_added_monitors!(nodes[1], 1);

	chanmon_cfgs[1].persister.set_update_ret(Ok(()));
	let (outpoint, latest_update, _) = nodes[1].chain_monitor.latest_monitor_update_id.lock().unwrap().get(&channel_id).unwrap().clone();
	nodes[1].chain_monitor.chain_monitor.force_channel_monitor_updated(outpoint, latest_update);
	// nodes[1] should be AwaitingRAA here!
	check_added_monitors!(nodes[1], 0);
	let bs_responses = get_revoke_commit_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	expect_pending_htlcs_forwardable!(nodes[1]);
	expect_payment_received!(nodes[1], payment_hash_1, payment_secret_1, 1000000);

	// We send a third payment here, which is somewhat of a redundant test, but the
	// chanmon_fail_consistency test required it to actually find the bug (by seeing out-of-sync
	// commitment transaction states) whereas here we can explicitly check for it.
	{
		nodes[0].node.send_payment(&route, payment_hash_3, &Some(payment_secret_3)).unwrap();
		check_added_monitors!(nodes[0], 0);
		assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	}
	nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_responses.0);
	check_added_monitors!(nodes[0], 1);
	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let payment_event = SendEvent::from_event(events.pop().unwrap());

	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &bs_responses.1);
	check_added_monitors!(nodes[0], 1);
	let as_raa = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());

	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &payment_event.msgs[0]);
	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &payment_event.commitment_msg);
	check_added_monitors!(nodes[1], 1);
	let bs_raa = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, nodes[0].node.get_our_node_id());

	// Finally deliver the RAA to nodes[1] which results in a CS response to the last update
	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &as_raa);
	check_added_monitors!(nodes[1], 1);
	expect_pending_htlcs_forwardable!(nodes[1]);
	expect_payment_received!(nodes[1], payment_hash_2, payment_secret_2, 1000000);
	let bs_update = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());

	nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_raa);
	check_added_monitors!(nodes[0], 1);

	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &bs_update.commitment_signed);
	check_added_monitors!(nodes[0], 1);
	let as_raa = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());

	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &as_raa);
	check_added_monitors!(nodes[1], 1);
	expect_pending_htlcs_forwardable!(nodes[1]);
	expect_payment_received!(nodes[1], payment_hash_3, payment_secret_3, 1000000);

	claim_payment(&nodes[0], &[&nodes[1]], payment_preimage_1);
	claim_payment(&nodes[0], &[&nodes[1]], payment_preimage_2);
	claim_payment(&nodes[0], &[&nodes[1]], payment_preimage_3);
}

#[test]
fn claim_while_disconnected_monitor_update_fail() {
	// Test for claiming a payment while disconnected and then having the resulting
	// channel-update-generated monitor update fail. This kind of thing isn't a particularly
	// contrived case for nodes with network instability.
	// Backported from chanmon_fail_consistency fuzz tests as an unmerged version of the handling
	// code introduced a regression in this test (specifically, this caught a removal of the
	// channel_reestablish handling ensuring the order was sensical given the messages used).
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let channel_id = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known()).2;

	// Forward a payment for B to claim
	let (payment_preimage_1, _, _) = route_payment(&nodes[0], &[&nodes[1]], 1000000);

	nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id(), false);
	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);

	assert!(nodes[1].node.claim_funds(payment_preimage_1));
	check_added_monitors!(nodes[1], 1);

	nodes[0].node.peer_connected(&nodes[1].node.get_our_node_id(), &msgs::Init { features: InitFeatures::empty() });
	nodes[1].node.peer_connected(&nodes[0].node.get_our_node_id(), &msgs::Init { features: InitFeatures::empty() });

	let as_reconnect = get_event_msg!(nodes[0], MessageSendEvent::SendChannelReestablish, nodes[1].node.get_our_node_id());
	let bs_reconnect = get_event_msg!(nodes[1], MessageSendEvent::SendChannelReestablish, nodes[0].node.get_our_node_id());

	nodes[0].node.handle_channel_reestablish(&nodes[1].node.get_our_node_id(), &bs_reconnect);
	let _as_channel_update = get_event_msg!(nodes[0], MessageSendEvent::SendChannelUpdate, nodes[1].node.get_our_node_id());

	// Now deliver a's reestablish, freeing the claim from the holding cell, but fail the monitor
	// update.
	chanmon_cfgs[1].persister.set_update_ret(Err(ChannelMonitorUpdateErr::TemporaryFailure));

	nodes[1].node.handle_channel_reestablish(&nodes[0].node.get_our_node_id(), &as_reconnect);
	let _bs_channel_update = get_event_msg!(nodes[1], MessageSendEvent::SendChannelUpdate, nodes[0].node.get_our_node_id());
	nodes[1].logger.assert_log("lightning::ln::channelmanager".to_string(), "Failed to update ChannelMonitor".to_string(), 1);
	check_added_monitors!(nodes[1], 1);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	// Send a second payment from A to B, resulting in a commitment update that gets swallowed with
	// the monitor still failed
	let (route, payment_hash_2, payment_preimage_2, payment_secret_2) = get_route_and_payment_hash!(nodes[0], nodes[1], 1000000);
	{
		nodes[0].node.send_payment(&route, payment_hash_2, &Some(payment_secret_2)).unwrap();
		check_added_monitors!(nodes[0], 1);
	}

	let as_updates = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &as_updates.update_add_htlcs[0]);
	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &as_updates.commitment_signed);
	check_added_monitors!(nodes[1], 1);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	nodes[1].logger.assert_log("lightning::ln::channelmanager".to_string(), "Previous monitor update failure prevented generation of RAA".to_string(), 1);
	// Note that nodes[1] not updating monitor here is OK - it wont take action on the new HTLC
	// until we've channel_monitor_update'd and updated for the new commitment transaction.

	// Now un-fail the monitor, which will result in B sending its original commitment update,
	// receiving the commitment update from A, and the resulting commitment dances.
	chanmon_cfgs[1].persister.set_update_ret(Ok(()));
	let (outpoint, latest_update, _) = nodes[1].chain_monitor.latest_monitor_update_id.lock().unwrap().get(&channel_id).unwrap().clone();
	nodes[1].chain_monitor.chain_monitor.force_channel_monitor_updated(outpoint, latest_update);
	check_added_monitors!(nodes[1], 0);

	let bs_msgs = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(bs_msgs.len(), 2);

	match bs_msgs[0] {
		MessageSendEvent::UpdateHTLCs { ref node_id, ref updates } => {
			assert_eq!(*node_id, nodes[0].node.get_our_node_id());
			nodes[0].node.handle_update_fulfill_htlc(&nodes[1].node.get_our_node_id(), &updates.update_fulfill_htlcs[0]);
			nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &updates.commitment_signed);
			check_added_monitors!(nodes[0], 1);

			let as_raa = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());
			nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &as_raa);
			check_added_monitors!(nodes[1], 1);
		},
		_ => panic!("Unexpected event"),
	}

	match bs_msgs[1] {
		MessageSendEvent::SendRevokeAndACK { ref node_id, ref msg } => {
			assert_eq!(*node_id, nodes[0].node.get_our_node_id());
			nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), msg);
			check_added_monitors!(nodes[0], 1);
		},
		_ => panic!("Unexpected event"),
	}

	let as_commitment = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());

	let bs_commitment = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &bs_commitment.commitment_signed);
	check_added_monitors!(nodes[0], 1);
	let as_raa = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());

	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &as_commitment.commitment_signed);
	check_added_monitors!(nodes[1], 1);
	let bs_raa = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, nodes[0].node.get_our_node_id());
	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &as_raa);
	check_added_monitors!(nodes[1], 1);

	expect_pending_htlcs_forwardable!(nodes[1]);
	expect_payment_received!(nodes[1], payment_hash_2, payment_secret_2, 1000000);

	nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_raa);
	check_added_monitors!(nodes[0], 1);
	expect_payment_sent!(nodes[0], payment_preimage_1);

	claim_payment(&nodes[0], &[&nodes[1]], payment_preimage_2);
}

#[test]
fn monitor_failed_no_reestablish_response() {
	// Test for receiving a channel_reestablish after a monitor update failure resulted in no
	// response to a commitment_signed.
	// Backported from chanmon_fail_consistency fuzz tests as it caught a long-standing
	// debug_assert!() failure in channel_reestablish handling.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let channel_id = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known()).2;
	{
		let mut lock;
		get_channel_ref!(nodes[0], lock, channel_id).announcement_sigs_state = AnnouncementSigsState::PeerReceived;
		get_channel_ref!(nodes[1], lock, channel_id).announcement_sigs_state = AnnouncementSigsState::PeerReceived;
	}

	// Route the payment and deliver the initial commitment_signed (with a monitor update failure
	// on receipt).
	let (route, payment_hash_1, payment_preimage_1, payment_secret_1) = get_route_and_payment_hash!(nodes[0], nodes[1], 1000000);
	{
		nodes[0].node.send_payment(&route, payment_hash_1, &Some(payment_secret_1)).unwrap();
		check_added_monitors!(nodes[0], 1);
	}

	chanmon_cfgs[1].persister.set_update_ret(Err(ChannelMonitorUpdateErr::TemporaryFailure));
	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let payment_event = SendEvent::from_event(events.pop().unwrap());
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &payment_event.msgs[0]);
	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &payment_event.commitment_msg);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	nodes[1].logger.assert_log("lightning::ln::channelmanager".to_string(), "Failed to update ChannelMonitor".to_string(), 1);
	check_added_monitors!(nodes[1], 1);

	// Now disconnect and immediately reconnect, delivering the channel_reestablish while nodes[1]
	// is still failing to update monitors.
	nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id(), false);
	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);

	nodes[0].node.peer_connected(&nodes[1].node.get_our_node_id(), &msgs::Init { features: InitFeatures::empty() });
	nodes[1].node.peer_connected(&nodes[0].node.get_our_node_id(), &msgs::Init { features: InitFeatures::empty() });

	let as_reconnect = get_event_msg!(nodes[0], MessageSendEvent::SendChannelReestablish, nodes[1].node.get_our_node_id());
	let bs_reconnect = get_event_msg!(nodes[1], MessageSendEvent::SendChannelReestablish, nodes[0].node.get_our_node_id());

	nodes[1].node.handle_channel_reestablish(&nodes[0].node.get_our_node_id(), &as_reconnect);
	let _bs_channel_update = get_event_msg!(nodes[1], MessageSendEvent::SendChannelUpdate, nodes[0].node.get_our_node_id());
	nodes[0].node.handle_channel_reestablish(&nodes[1].node.get_our_node_id(), &bs_reconnect);
	let _as_channel_update = get_event_msg!(nodes[0], MessageSendEvent::SendChannelUpdate, nodes[1].node.get_our_node_id());

	chanmon_cfgs[1].persister.set_update_ret(Ok(()));
	let (outpoint, latest_update, _) = nodes[1].chain_monitor.latest_monitor_update_id.lock().unwrap().get(&channel_id).unwrap().clone();
	nodes[1].chain_monitor.chain_monitor.force_channel_monitor_updated(outpoint, latest_update);
	check_added_monitors!(nodes[1], 0);
	let bs_responses = get_revoke_commit_msgs!(nodes[1], nodes[0].node.get_our_node_id());

	nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_responses.0);
	check_added_monitors!(nodes[0], 1);
	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &bs_responses.1);
	check_added_monitors!(nodes[0], 1);

	let as_raa = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());
	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &as_raa);
	check_added_monitors!(nodes[1], 1);

	expect_pending_htlcs_forwardable!(nodes[1]);
	expect_payment_received!(nodes[1], payment_hash_1, payment_secret_1, 1000000);

	claim_payment(&nodes[0], &[&nodes[1]], payment_preimage_1);
}

#[test]
fn first_message_on_recv_ordering() {
	// Test that if the initial generator of a monitor-update-frozen state doesn't generate
	// messages, we're willing to flip the order of response messages if neccessary in resposne to
	// a commitment_signed which needs to send an RAA first.
	// At a high level, our goal is to fail monitor updating in response to an RAA which needs no
	// response and then handle a CS while in the failed state, requiring an RAA followed by a CS
	// response. To do this, we start routing two payments, with the final RAA for the first being
	// delivered while B is in AwaitingRAA, hence when we deliver the CS for the second B will
	// have no pending response but will want to send a RAA/CS (with the updates for the second
	// payment applied).
	// Backported from chanmon_fail_consistency fuzz tests as it caught a bug here.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let channel_id = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known()).2;

	// Route the first payment outbound, holding the last RAA for B until we are set up so that we
	// can deliver it and fail the monitor update.
	let (route, payment_hash_1, payment_preimage_1, payment_secret_1) = get_route_and_payment_hash!(nodes[0], nodes[1], 1000000);
	{
		nodes[0].node.send_payment(&route, payment_hash_1, &Some(payment_secret_1)).unwrap();
		check_added_monitors!(nodes[0], 1);
	}

	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let payment_event = SendEvent::from_event(events.pop().unwrap());
	assert_eq!(payment_event.node_id, nodes[1].node.get_our_node_id());
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &payment_event.msgs[0]);
	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &payment_event.commitment_msg);
	check_added_monitors!(nodes[1], 1);
	let bs_responses = get_revoke_commit_msgs!(nodes[1], nodes[0].node.get_our_node_id());

	nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_responses.0);
	check_added_monitors!(nodes[0], 1);
	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &bs_responses.1);
	check_added_monitors!(nodes[0], 1);

	let as_raa = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());

	// Route the second payment, generating an update_add_htlc/commitment_signed
	let (route, payment_hash_2, payment_preimage_2, payment_secret_2) = get_route_and_payment_hash!(nodes[0], nodes[1], 1000000);
	{
		nodes[0].node.send_payment(&route, payment_hash_2, &Some(payment_secret_2)).unwrap();
		check_added_monitors!(nodes[0], 1);
	}
	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let payment_event = SendEvent::from_event(events.pop().unwrap());
	assert_eq!(payment_event.node_id, nodes[1].node.get_our_node_id());

	chanmon_cfgs[1].persister.set_update_ret(Err(ChannelMonitorUpdateErr::TemporaryFailure));

	// Deliver the final RAA for the first payment, which does not require a response. RAAs
	// generally require a commitment_signed, so the fact that we're expecting an opposite response
	// to the next message also tests resetting the delivery order.
	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &as_raa);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	nodes[1].logger.assert_log("lightning::ln::channelmanager".to_string(), "Failed to update ChannelMonitor".to_string(), 1);
	check_added_monitors!(nodes[1], 1);

	// Now deliver the update_add_htlc/commitment_signed for the second payment, which does need an
	// RAA/CS response, which should be generated when we call channel_monitor_update (with the
	// appropriate HTLC acceptance).
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &payment_event.msgs[0]);
	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &payment_event.commitment_msg);
	check_added_monitors!(nodes[1], 1);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	nodes[1].logger.assert_log("lightning::ln::channelmanager".to_string(), "Previous monitor update failure prevented generation of RAA".to_string(), 1);

	chanmon_cfgs[1].persister.set_update_ret(Ok(()));
	let (outpoint, latest_update, _) = nodes[1].chain_monitor.latest_monitor_update_id.lock().unwrap().get(&channel_id).unwrap().clone();
	nodes[1].chain_monitor.chain_monitor.force_channel_monitor_updated(outpoint, latest_update);
	check_added_monitors!(nodes[1], 0);

	expect_pending_htlcs_forwardable!(nodes[1]);
	expect_payment_received!(nodes[1], payment_hash_1, payment_secret_1, 1000000);

	let bs_responses = get_revoke_commit_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_responses.0);
	check_added_monitors!(nodes[0], 1);
	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &bs_responses.1);
	check_added_monitors!(nodes[0], 1);

	let as_raa = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());
	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &as_raa);
	check_added_monitors!(nodes[1], 1);

	expect_pending_htlcs_forwardable!(nodes[1]);
	expect_payment_received!(nodes[1], payment_hash_2, payment_secret_2, 1000000);

	claim_payment(&nodes[0], &[&nodes[1]], payment_preimage_1);
	claim_payment(&nodes[0], &[&nodes[1]], payment_preimage_2);
}

#[test]
fn test_monitor_update_fail_claim() {
	// Basic test for monitor update failures when processing claim_funds calls.
	// We set up a simple 3-node network, sending a payment from A to B and failing B's monitor
	// update to claim the payment. We then send two payments C->B->A, which are held at B.
	// Finally, we restore the channel monitor updating and claim the payment on B, forwarding
	// the payments from C onwards to A.
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());
	create_announced_chan_between_nodes(&nodes, 1, 2, InitFeatures::known(), InitFeatures::known());

	// Rebalance a bit so that we can send backwards from 3 to 2.
	send_payment(&nodes[0], &[&nodes[1], &nodes[2]], 5000000);

	let (payment_preimage_1, _, _) = route_payment(&nodes[0], &[&nodes[1]], 1000000);

	chanmon_cfgs[1].persister.set_update_ret(Err(ChannelMonitorUpdateErr::TemporaryFailure));
	assert!(nodes[1].node.claim_funds(payment_preimage_1));
	nodes[1].logger.assert_log("lightning::ln::channelmanager".to_string(), "Temporary failure claiming HTLC, treating as success: Failed to update ChannelMonitor".to_string(), 1);
	check_added_monitors!(nodes[1], 1);

	// Note that at this point there is a pending commitment transaction update for A being held by
	// B. Even when we go to send the payment from C through B to A, B will not update this
	// already-signed commitment transaction and will instead wait for it to resolve before
	// forwarding the payment onwards.

	let (route, payment_hash_2, _, payment_secret_2) = get_route_and_payment_hash!(nodes[2], nodes[0], 1_000_000);
	{
		nodes[2].node.send_payment(&route, payment_hash_2, &Some(payment_secret_2)).unwrap();
		check_added_monitors!(nodes[2], 1);
	}

	// Successfully update the monitor on the 1<->2 channel, but the 0<->1 channel should still be
	// paused, so forward shouldn't succeed until we call channel_monitor_updated().
	chanmon_cfgs[1].persister.set_update_ret(Ok(()));

	let mut events = nodes[2].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let payment_event = SendEvent::from_event(events.pop().unwrap());
	nodes[1].node.handle_update_add_htlc(&nodes[2].node.get_our_node_id(), &payment_event.msgs[0]);
	let events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 0);
	commitment_signed_dance!(nodes[1], nodes[2], payment_event.commitment_msg, false, true);

	let (_, payment_hash_3, payment_secret_3) = get_payment_preimage_hash!(nodes[0]);
	nodes[2].node.send_payment(&route, payment_hash_3, &Some(payment_secret_3)).unwrap();
	check_added_monitors!(nodes[2], 1);

	let mut events = nodes[2].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let payment_event = SendEvent::from_event(events.pop().unwrap());
	nodes[1].node.handle_update_add_htlc(&nodes[2].node.get_our_node_id(), &payment_event.msgs[0]);
	let events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 0);
	commitment_signed_dance!(nodes[1], nodes[2], payment_event.commitment_msg, false, true);

	// Now restore monitor updating on the 0<->1 channel and claim the funds on B.
	let (outpoint, latest_update, _) = nodes[1].chain_monitor.latest_monitor_update_id.lock().unwrap().get(&chan_1.2).unwrap().clone();
	nodes[1].chain_monitor.chain_monitor.force_channel_monitor_updated(outpoint, latest_update);
	check_added_monitors!(nodes[1], 0);

	let bs_fulfill_update = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	nodes[0].node.handle_update_fulfill_htlc(&nodes[1].node.get_our_node_id(), &bs_fulfill_update.update_fulfill_htlcs[0]);
	commitment_signed_dance!(nodes[0], nodes[1], bs_fulfill_update.commitment_signed, false);
	expect_payment_sent!(nodes[0], payment_preimage_1);

	// Get the payment forwards, note that they were batched into one commitment update.
	expect_pending_htlcs_forwardable!(nodes[1]);
	check_added_monitors!(nodes[1], 1);
	let bs_forward_update = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	nodes[0].node.handle_update_add_htlc(&nodes[1].node.get_our_node_id(), &bs_forward_update.update_add_htlcs[0]);
	nodes[0].node.handle_update_add_htlc(&nodes[1].node.get_our_node_id(), &bs_forward_update.update_add_htlcs[1]);
	commitment_signed_dance!(nodes[0], nodes[1], bs_forward_update.commitment_signed, false);
	expect_pending_htlcs_forwardable!(nodes[0]);

	let events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 2);
	match events[0] {
		Event::PaymentReceived { ref payment_hash, ref purpose, amt } => {
			assert_eq!(payment_hash_2, *payment_hash);
			assert_eq!(1_000_000, amt);
			match &purpose {
				PaymentPurpose::InvoicePayment { payment_preimage, payment_secret, .. } => {
					assert!(payment_preimage.is_none());
					assert_eq!(payment_secret_2, *payment_secret);
				},
				_ => panic!("expected PaymentPurpose::InvoicePayment")
			}
		},
		_ => panic!("Unexpected event"),
	}
	match events[1] {
		Event::PaymentReceived { ref payment_hash, ref purpose, amt } => {
			assert_eq!(payment_hash_3, *payment_hash);
			assert_eq!(1_000_000, amt);
			match &purpose {
				PaymentPurpose::InvoicePayment { payment_preimage, payment_secret, .. } => {
					assert!(payment_preimage.is_none());
					assert_eq!(payment_secret_3, *payment_secret);
				},
				_ => panic!("expected PaymentPurpose::InvoicePayment")
			}
		},
		_ => panic!("Unexpected event"),
	}
}

#[test]
fn test_monitor_update_on_pending_forwards() {
	// Basic test for monitor update failures when processing pending HTLC fail/add forwards.
	// We do this with a simple 3-node network, sending a payment from A to C and one from C to A.
	// The payment from A to C will be failed by C and pending a back-fail to A, while the payment
	// from C to A will be pending a forward to A.
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());
	create_announced_chan_between_nodes(&nodes, 1, 2, InitFeatures::known(), InitFeatures::known());

	// Rebalance a bit so that we can send backwards from 3 to 1.
	send_payment(&nodes[0], &[&nodes[1], &nodes[2]], 5000000);

	let (_, payment_hash_1, _) = route_payment(&nodes[0], &[&nodes[1], &nodes[2]], 1000000);
	assert!(nodes[2].node.fail_htlc_backwards(&payment_hash_1));
	expect_pending_htlcs_forwardable!(nodes[2]);
	check_added_monitors!(nodes[2], 1);

	let cs_fail_update = get_htlc_update_msgs!(nodes[2], nodes[1].node.get_our_node_id());
	nodes[1].node.handle_update_fail_htlc(&nodes[2].node.get_our_node_id(), &cs_fail_update.update_fail_htlcs[0]);
	commitment_signed_dance!(nodes[1], nodes[2], cs_fail_update.commitment_signed, true, true);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	let (route, payment_hash_2, payment_preimage_2, payment_secret_2) = get_route_and_payment_hash!(nodes[2], nodes[0], 1000000);
	{
		nodes[2].node.send_payment(&route, payment_hash_2, &Some(payment_secret_2)).unwrap();
		check_added_monitors!(nodes[2], 1);
	}

	let mut events = nodes[2].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let payment_event = SendEvent::from_event(events.pop().unwrap());
	nodes[1].node.handle_update_add_htlc(&nodes[2].node.get_our_node_id(), &payment_event.msgs[0]);
	commitment_signed_dance!(nodes[1], nodes[2], payment_event.commitment_msg, false);

	chanmon_cfgs[1].persister.set_update_ret(Err(ChannelMonitorUpdateErr::TemporaryFailure));
	expect_pending_htlcs_forwardable!(nodes[1]);
	check_added_monitors!(nodes[1], 1);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	nodes[1].logger.assert_log("lightning::ln::channelmanager".to_string(), "Failed to update ChannelMonitor".to_string(), 1);

	chanmon_cfgs[1].persister.set_update_ret(Ok(()));
	let (outpoint, latest_update, _) = nodes[1].chain_monitor.latest_monitor_update_id.lock().unwrap().get(&chan_1.2).unwrap().clone();
	nodes[1].chain_monitor.chain_monitor.force_channel_monitor_updated(outpoint, latest_update);
	check_added_monitors!(nodes[1], 0);

	let bs_updates = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &bs_updates.update_fail_htlcs[0]);
	nodes[0].node.handle_update_add_htlc(&nodes[1].node.get_our_node_id(), &bs_updates.update_add_htlcs[0]);
	commitment_signed_dance!(nodes[0], nodes[1], bs_updates.commitment_signed, false, true);

	let events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 2);
	if let Event::PaymentPathFailed { payment_hash, rejected_by_dest, .. } = events[0] {
		assert_eq!(payment_hash, payment_hash_1);
		assert!(rejected_by_dest);
	} else { panic!("Unexpected event!"); }
	match events[1] {
		Event::PendingHTLCsForwardable { .. } => { },
		_ => panic!("Unexpected event"),
	};
	nodes[0].node.process_pending_htlc_forwards();
	expect_payment_received!(nodes[0], payment_hash_2, payment_secret_2, 1000000);

	claim_payment(&nodes[2], &[&nodes[1], &nodes[0]], payment_preimage_2);
}

#[test]
fn monitor_update_claim_fail_no_response() {
	// Test for claim_funds resulting in both a monitor update failure and no message response (due
	// to channel being AwaitingRAA).
	// Backported from chanmon_fail_consistency fuzz tests as an unmerged version of the handling
	// code was broken.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let channel_id = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known()).2;

	// Forward a payment for B to claim
	let (payment_preimage_1, _, _) = route_payment(&nodes[0], &[&nodes[1]], 1000000);

	// Now start forwarding a second payment, skipping the last RAA so B is in AwaitingRAA
	let (route, payment_hash_2, payment_preimage_2, payment_secret_2) = get_route_and_payment_hash!(nodes[0], nodes[1], 1000000);
	{
		nodes[0].node.send_payment(&route, payment_hash_2, &Some(payment_secret_2)).unwrap();
		check_added_monitors!(nodes[0], 1);
	}

	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let payment_event = SendEvent::from_event(events.pop().unwrap());
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &payment_event.msgs[0]);
	let as_raa = commitment_signed_dance!(nodes[1], nodes[0], payment_event.commitment_msg, false, true, false, true);

	chanmon_cfgs[1].persister.set_update_ret(Err(ChannelMonitorUpdateErr::TemporaryFailure));
	assert!(nodes[1].node.claim_funds(payment_preimage_1));
	check_added_monitors!(nodes[1], 1);
	let events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 0);
	nodes[1].logger.assert_log("lightning::ln::channelmanager".to_string(), "Temporary failure claiming HTLC, treating as success: Failed to update ChannelMonitor".to_string(), 1);

	chanmon_cfgs[1].persister.set_update_ret(Ok(()));
	let (outpoint, latest_update, _) = nodes[1].chain_monitor.latest_monitor_update_id.lock().unwrap().get(&channel_id).unwrap().clone();
	nodes[1].chain_monitor.chain_monitor.force_channel_monitor_updated(outpoint, latest_update);
	check_added_monitors!(nodes[1], 0);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &as_raa);
	check_added_monitors!(nodes[1], 1);
	expect_pending_htlcs_forwardable!(nodes[1]);
	expect_payment_received!(nodes[1], payment_hash_2, payment_secret_2, 1000000);

	let bs_updates = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	nodes[0].node.handle_update_fulfill_htlc(&nodes[1].node.get_our_node_id(), &bs_updates.update_fulfill_htlcs[0]);
	commitment_signed_dance!(nodes[0], nodes[1], bs_updates.commitment_signed, false);
	expect_payment_sent!(nodes[0], payment_preimage_1);

	claim_payment(&nodes[0], &[&nodes[1]], payment_preimage_2);
}

// restore_b_before_conf has no meaning if !confirm_a_first
// restore_b_before_lock has no meaning if confirm_a_first
fn do_during_funding_monitor_fail(confirm_a_first: bool, restore_b_before_conf: bool, restore_b_before_lock: bool) {
	// Test that if the monitor update generated by funding_transaction_generated fails we continue
	// the channel setup happily after the update is restored.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	nodes[0].node.create_channel(nodes[1].node.get_our_node_id(), 100000, 10001, 43, None).unwrap();
	nodes[1].node.handle_open_channel(&nodes[0].node.get_our_node_id(), InitFeatures::known(), &get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, nodes[1].node.get_our_node_id()));
	nodes[0].node.handle_accept_channel(&nodes[1].node.get_our_node_id(), InitFeatures::known(), &get_event_msg!(nodes[1], MessageSendEvent::SendAcceptChannel, nodes[0].node.get_our_node_id()));

	let (temporary_channel_id, funding_tx, funding_output) = create_funding_transaction(&nodes[0], 100000, 43);

	nodes[0].node.funding_transaction_generated(&temporary_channel_id, funding_tx.clone()).unwrap();
	check_added_monitors!(nodes[0], 0);

	chanmon_cfgs[1].persister.set_update_ret(Err(ChannelMonitorUpdateErr::TemporaryFailure));
	let funding_created_msg = get_event_msg!(nodes[0], MessageSendEvent::SendFundingCreated, nodes[1].node.get_our_node_id());
	let channel_id = OutPoint { txid: funding_created_msg.funding_txid, index: funding_created_msg.funding_output_index }.to_channel_id();
	nodes[1].node.handle_funding_created(&nodes[0].node.get_our_node_id(), &funding_created_msg);
	check_added_monitors!(nodes[1], 1);

	chanmon_cfgs[0].persister.set_update_ret(Err(ChannelMonitorUpdateErr::TemporaryFailure));
	nodes[0].node.handle_funding_signed(&nodes[1].node.get_our_node_id(), &get_event_msg!(nodes[1], MessageSendEvent::SendFundingSigned, nodes[0].node.get_our_node_id()));
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	nodes[0].logger.assert_log("lightning::ln::channelmanager".to_string(), "Failed to update ChannelMonitor".to_string(), 1);
	check_added_monitors!(nodes[0], 1);
	assert!(nodes[0].node.get_and_clear_pending_events().is_empty());
	chanmon_cfgs[0].persister.set_update_ret(Ok(()));
	let (outpoint, latest_update, _) = nodes[0].chain_monitor.latest_monitor_update_id.lock().unwrap().get(&channel_id).unwrap().clone();
	nodes[0].chain_monitor.chain_monitor.force_channel_monitor_updated(outpoint, latest_update);
	check_added_monitors!(nodes[0], 0);

	let events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 0);
	assert_eq!(nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().len(), 1);
	assert_eq!(nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().split_off(0)[0].txid(), funding_output.txid);

	if confirm_a_first {
		confirm_transaction(&nodes[0], &funding_tx);
		nodes[1].node.handle_funding_locked(&nodes[0].node.get_our_node_id(), &get_event_msg!(nodes[0], MessageSendEvent::SendFundingLocked, nodes[1].node.get_our_node_id()));
		assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
		assert!(nodes[1].node.get_and_clear_pending_events().is_empty());
	} else {
		assert!(!restore_b_before_conf);
		confirm_transaction(&nodes[1], &funding_tx);
		assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	}

	// Make sure nodes[1] isn't stupid enough to re-send the FundingLocked on reconnect
	nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id(), false);
	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);
	reconnect_nodes(&nodes[0], &nodes[1], (false, confirm_a_first), (0, 0), (0, 0), (0, 0), (0, 0), (0, 0), (false, false));
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	if !restore_b_before_conf {
		confirm_transaction(&nodes[1], &funding_tx);
		assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
		assert!(nodes[1].node.get_and_clear_pending_events().is_empty());
	}
	if !confirm_a_first && !restore_b_before_lock {
		confirm_transaction(&nodes[0], &funding_tx);
		nodes[1].node.handle_funding_locked(&nodes[0].node.get_our_node_id(), &get_event_msg!(nodes[0], MessageSendEvent::SendFundingLocked, nodes[1].node.get_our_node_id()));
		assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
		assert!(nodes[1].node.get_and_clear_pending_events().is_empty());
	}

	chanmon_cfgs[1].persister.set_update_ret(Ok(()));
	let (outpoint, latest_update, _) = nodes[1].chain_monitor.latest_monitor_update_id.lock().unwrap().get(&channel_id).unwrap().clone();
	nodes[1].chain_monitor.chain_monitor.force_channel_monitor_updated(outpoint, latest_update);
	check_added_monitors!(nodes[1], 0);

	let (channel_id, (announcement, as_update, bs_update)) = if !confirm_a_first {
		if !restore_b_before_lock {
			let (funding_locked, channel_id) = create_chan_between_nodes_with_value_confirm_second(&nodes[0], &nodes[1]);
			(channel_id, create_chan_between_nodes_with_value_b(&nodes[1], &nodes[0], &funding_locked))
		} else {
			nodes[0].node.handle_funding_locked(&nodes[1].node.get_our_node_id(), &get_event_msg!(nodes[1], MessageSendEvent::SendFundingLocked, nodes[0].node.get_our_node_id()));
			confirm_transaction(&nodes[0], &funding_tx);
			let (funding_locked, channel_id) = create_chan_between_nodes_with_value_confirm_second(&nodes[1], &nodes[0]);
			(channel_id, create_chan_between_nodes_with_value_b(&nodes[0], &nodes[1], &funding_locked))
		}
	} else {
		if restore_b_before_conf {
			assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
			assert!(nodes[1].node.get_and_clear_pending_events().is_empty());
			confirm_transaction(&nodes[1], &funding_tx);
		}
		let (funding_locked, channel_id) = create_chan_between_nodes_with_value_confirm_second(&nodes[0], &nodes[1]);
		(channel_id, create_chan_between_nodes_with_value_b(&nodes[1], &nodes[0], &funding_locked))
	};
	for node in nodes.iter() {
		assert!(node.net_graph_msg_handler.handle_channel_announcement(&announcement).unwrap());
		node.net_graph_msg_handler.handle_channel_update(&as_update).unwrap();
		node.net_graph_msg_handler.handle_channel_update(&bs_update).unwrap();
	}

	send_payment(&nodes[0], &[&nodes[1]], 8000000);
	close_channel(&nodes[0], &nodes[1], &channel_id, funding_tx, true);
	check_closed_event!(nodes[0], 1, ClosureReason::CooperativeClosure);
	check_closed_event!(nodes[1], 1, ClosureReason::CooperativeClosure);
}

#[test]
fn during_funding_monitor_fail() {
	do_during_funding_monitor_fail(true, true, false);
	do_during_funding_monitor_fail(true, false, false);
	do_during_funding_monitor_fail(false, false, false);
	do_during_funding_monitor_fail(false, false, true);
}

#[test]
fn test_path_paused_mpp() {
	// Simple test of sending a multi-part payment where one path is currently blocked awaiting
	// monitor update
	let chanmon_cfgs = create_chanmon_cfgs(4);
	let node_cfgs = create_node_cfgs(4, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(4, &node_cfgs, &[None, None, None, None]);
	let mut nodes = create_network(4, &node_cfgs, &node_chanmgrs);

	let chan_1_id = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known()).0.contents.short_channel_id;
	let (chan_2_ann, _, chan_2_id, _) = create_announced_chan_between_nodes(&nodes, 0, 2, InitFeatures::known(), InitFeatures::known());
	let chan_3_id = create_announced_chan_between_nodes(&nodes, 1, 3, InitFeatures::known(), InitFeatures::known()).0.contents.short_channel_id;
	let chan_4_id = create_announced_chan_between_nodes(&nodes, 2, 3, InitFeatures::known(), InitFeatures::known()).0.contents.short_channel_id;

	let (mut route, payment_hash, payment_preimage, payment_secret) = get_route_and_payment_hash!(&nodes[0], nodes[3], 100000);

	// Set us up to take multiple routes, one 0 -> 1 -> 3 and one 0 -> 2 -> 3:
	let path = route.paths[0].clone();
	route.paths.push(path);
	route.paths[0][0].pubkey = nodes[1].node.get_our_node_id();
	route.paths[0][0].short_channel_id = chan_1_id;
	route.paths[0][1].short_channel_id = chan_3_id;
	route.paths[1][0].pubkey = nodes[2].node.get_our_node_id();
	route.paths[1][0].short_channel_id = chan_2_ann.contents.short_channel_id;
	route.paths[1][1].short_channel_id = chan_4_id;

	// Set it so that the first monitor update (for the path 0 -> 1 -> 3) succeeds, but the second
	// (for the path 0 -> 2 -> 3) fails.
	chanmon_cfgs[0].persister.set_update_ret(Ok(()));
	chanmon_cfgs[0].persister.set_next_update_ret(Some(Err(ChannelMonitorUpdateErr::TemporaryFailure)));

	// Now check that we get the right return value, indicating that the first path succeeded but
	// the second got a MonitorUpdateFailed err. This implies PaymentSendFailure::PartialFailure as
	// some paths succeeded, preventing retry.
	if let Err(PaymentSendFailure::PartialFailure { results, ..}) = nodes[0].node.send_payment(&route, payment_hash, &Some(payment_secret)) {
		assert_eq!(results.len(), 2);
		if let Ok(()) = results[0] {} else { panic!(); }
		if let Err(APIError::MonitorUpdateFailed) = results[1] {} else { panic!(); }
	} else { panic!(); }
	check_added_monitors!(nodes[0], 2);
	chanmon_cfgs[0].persister.set_update_ret(Ok(()));

	// Pass the first HTLC of the payment along to nodes[3].
	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	pass_along_path(&nodes[0], &[&nodes[1], &nodes[3]], 0, payment_hash.clone(), Some(payment_secret), events.pop().unwrap(), false, None);

	// And check that, after we successfully update the monitor for chan_2 we can pass the second
	// HTLC along to nodes[3] and claim the whole payment back to nodes[0].
	let (outpoint, latest_update, _) = nodes[0].chain_monitor.latest_monitor_update_id.lock().unwrap().get(&chan_2_id).unwrap().clone();
	nodes[0].chain_monitor.chain_monitor.force_channel_monitor_updated(outpoint, latest_update);
	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	pass_along_path(&nodes[0], &[&nodes[2], &nodes[3]], 200_000, payment_hash.clone(), Some(payment_secret), events.pop().unwrap(), true, None);

	claim_payment_along_route(&nodes[0], &[&[&nodes[1], &nodes[3]], &[&nodes[2], &nodes[3]]], false, payment_preimage);
}

#[test]
fn test_pending_update_fee_ack_on_reconnect() {
	// In early versions of our automated fee update patch, nodes did not correctly use the
	// previous channel feerate after sending an undelivered revoke_and_ack when re-sending an
	// undelivered commitment_signed.
	//
	// B sends A new HTLC + CS, not delivered
	// A sends B update_fee + CS
	// B receives the CS and sends RAA, previously causing B to lock in the new feerate
	// reconnect
	// B resends initial CS, using the original fee

	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());
	send_payment(&nodes[0], &[&nodes[1]], 100_000_00);

	let (route, payment_hash, payment_preimage, payment_secret) = get_route_and_payment_hash!(&nodes[1], nodes[0], 1_000_000);
	nodes[1].node.send_payment(&route, payment_hash, &Some(payment_secret)).unwrap();
	check_added_monitors!(nodes[1], 1);
	let bs_initial_send_msgs = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	// bs_initial_send_msgs are not delivered until they are re-generated after reconnect

	{
		let mut feerate_lock = chanmon_cfgs[0].fee_estimator.sat_per_kw.lock().unwrap();
		*feerate_lock *= 2;
	}
	nodes[0].node.timer_tick_occurred();
	check_added_monitors!(nodes[0], 1);
	let as_update_fee_msgs = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	assert!(as_update_fee_msgs.update_fee.is_some());

	nodes[1].node.handle_update_fee(&nodes[0].node.get_our_node_id(), as_update_fee_msgs.update_fee.as_ref().unwrap());
	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &as_update_fee_msgs.commitment_signed);
	check_added_monitors!(nodes[1], 1);
	let bs_first_raa = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, nodes[0].node.get_our_node_id());
	// bs_first_raa is not delivered until it is re-generated after reconnect

	nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id(), false);
	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);

	nodes[0].node.peer_connected(&nodes[1].node.get_our_node_id(), &msgs::Init { features: InitFeatures::known() });
	let as_connect_msg = get_event_msg!(nodes[0], MessageSendEvent::SendChannelReestablish, nodes[1].node.get_our_node_id());
	nodes[1].node.peer_connected(&nodes[0].node.get_our_node_id(), &msgs::Init { features: InitFeatures::known() });
	let bs_connect_msg = get_event_msg!(nodes[1], MessageSendEvent::SendChannelReestablish, nodes[0].node.get_our_node_id());

	nodes[1].node.handle_channel_reestablish(&nodes[0].node.get_our_node_id(), &as_connect_msg);
	let bs_resend_msgs = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(bs_resend_msgs.len(), 3);
	if let MessageSendEvent::UpdateHTLCs { ref updates, .. } = bs_resend_msgs[0] {
		assert_eq!(*updates, bs_initial_send_msgs);
	} else { panic!(); }
	if let MessageSendEvent::SendRevokeAndACK { ref msg, .. } = bs_resend_msgs[1] {
		assert_eq!(*msg, bs_first_raa);
	} else { panic!(); }
	if let MessageSendEvent::SendChannelUpdate { .. } = bs_resend_msgs[2] { } else { panic!(); }

	nodes[0].node.handle_channel_reestablish(&nodes[1].node.get_our_node_id(), &bs_connect_msg);
	get_event_msg!(nodes[0], MessageSendEvent::SendChannelUpdate, nodes[1].node.get_our_node_id());

	nodes[0].node.handle_update_add_htlc(&nodes[1].node.get_our_node_id(), &bs_initial_send_msgs.update_add_htlcs[0]);
	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &bs_initial_send_msgs.commitment_signed);
	check_added_monitors!(nodes[0], 1);
	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id()));
	check_added_monitors!(nodes[1], 1);
	let bs_second_cs = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id()).commitment_signed;

	nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_first_raa);
	check_added_monitors!(nodes[0], 1);
	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id()).commitment_signed);
	check_added_monitors!(nodes[1], 1);
	let bs_third_raa = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, nodes[0].node.get_our_node_id());

	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &bs_second_cs);
	check_added_monitors!(nodes[0], 1);
	nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_third_raa);
	check_added_monitors!(nodes[0], 1);

	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id()));
	check_added_monitors!(nodes[1], 1);

	expect_pending_htlcs_forwardable!(nodes[0]);
	expect_payment_received!(nodes[0], payment_hash, payment_secret, 1_000_000);

	claim_payment(&nodes[1], &[&nodes[0]], payment_preimage);
}

fn do_update_fee_resend_test(deliver_update: bool, parallel_updates: bool) {
	// In early versions we did not handle resending of update_fee on reconnect correctly. The
	// chanmon_consistency fuzz target, of course, immediately found it, but we test a few cases
	// explicitly here.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());
	send_payment(&nodes[0], &[&nodes[1]], 1000);

	{
		let mut feerate_lock = chanmon_cfgs[0].fee_estimator.sat_per_kw.lock().unwrap();
		*feerate_lock += 20;
	}
	nodes[0].node.timer_tick_occurred();
	check_added_monitors!(nodes[0], 1);
	let update_msgs = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	assert!(update_msgs.update_fee.is_some());
	if deliver_update {
		nodes[1].node.handle_update_fee(&nodes[0].node.get_our_node_id(), update_msgs.update_fee.as_ref().unwrap());
	}

	if parallel_updates {
		{
			let mut feerate_lock = chanmon_cfgs[0].fee_estimator.sat_per_kw.lock().unwrap();
			*feerate_lock += 20;
		}
		nodes[0].node.timer_tick_occurred();
		assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	}

	nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id(), false);
	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);

	nodes[0].node.peer_connected(&nodes[1].node.get_our_node_id(), &msgs::Init { features: InitFeatures::known() });
	let as_connect_msg = get_event_msg!(nodes[0], MessageSendEvent::SendChannelReestablish, nodes[1].node.get_our_node_id());
	nodes[1].node.peer_connected(&nodes[0].node.get_our_node_id(), &msgs::Init { features: InitFeatures::known() });
	let bs_connect_msg = get_event_msg!(nodes[1], MessageSendEvent::SendChannelReestablish, nodes[0].node.get_our_node_id());

	nodes[1].node.handle_channel_reestablish(&nodes[0].node.get_our_node_id(), &as_connect_msg);
	get_event_msg!(nodes[1], MessageSendEvent::SendChannelUpdate, nodes[0].node.get_our_node_id());
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	nodes[0].node.handle_channel_reestablish(&nodes[1].node.get_our_node_id(), &bs_connect_msg);
	let mut as_reconnect_msgs = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(as_reconnect_msgs.len(), 2);
	if let MessageSendEvent::SendChannelUpdate { .. } = as_reconnect_msgs.pop().unwrap() {} else { panic!(); }
	let update_msgs = if let MessageSendEvent::UpdateHTLCs { updates, .. } = as_reconnect_msgs.pop().unwrap()
		{ updates } else { panic!(); };
	assert!(update_msgs.update_fee.is_some());
	nodes[1].node.handle_update_fee(&nodes[0].node.get_our_node_id(), update_msgs.update_fee.as_ref().unwrap());
	if parallel_updates {
		nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &update_msgs.commitment_signed);
		check_added_monitors!(nodes[1], 1);
		let (bs_first_raa, bs_first_cs) = get_revoke_commit_msgs!(nodes[1], nodes[0].node.get_our_node_id());
		nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_first_raa);
		check_added_monitors!(nodes[0], 1);
		let as_second_update = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());

		nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &bs_first_cs);
		check_added_monitors!(nodes[0], 1);
		let as_first_raa = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());

		nodes[1].node.handle_update_fee(&nodes[0].node.get_our_node_id(), as_second_update.update_fee.as_ref().unwrap());
		nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &as_second_update.commitment_signed);
		check_added_monitors!(nodes[1], 1);
		let bs_second_raa = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, nodes[0].node.get_our_node_id());

		nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &as_first_raa);
		let bs_second_cs = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
		check_added_monitors!(nodes[1], 1);

		nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_second_raa);
		check_added_monitors!(nodes[0], 1);

		nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &bs_second_cs.commitment_signed);
		check_added_monitors!(nodes[0], 1);
		let as_second_raa = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());

		nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &as_second_raa);
		check_added_monitors!(nodes[1], 1);
	} else {
		commitment_signed_dance!(nodes[1], nodes[0], update_msgs.commitment_signed, false);
	}

	send_payment(&nodes[0], &[&nodes[1]], 1000);
}
#[test]
fn update_fee_resend_test() {
	do_update_fee_resend_test(false, false);
	do_update_fee_resend_test(true, false);
	do_update_fee_resend_test(false, true);
	do_update_fee_resend_test(true, true);
}

fn do_channel_holding_cell_serialize(disconnect: bool, reload_a: bool) {
	// Tests that, when we serialize a channel with AddHTLC entries in the holding cell, we
	// properly free them on reconnect. We previously failed such HTLCs upon serialization, but
	// that behavior was both somewhat unexpected and also broken (there was a debug assertion
	// which failed in such a case).
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let persister: test_utils::TestPersister;
	let new_chain_monitor: test_utils::TestChainMonitor;
	let nodes_0_deserialized: ChannelManager<EnforcingSigner, &test_utils::TestChainMonitor, &test_utils::TestBroadcaster, &test_utils::TestKeysInterface, &test_utils::TestFeeEstimator, &test_utils::TestLogger>;
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let chan_id = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 15_000_000, 7_000_000_000, InitFeatures::known(), InitFeatures::known()).2;
	let (route, payment_hash_1, payment_preimage_1, payment_secret_1) = get_route_and_payment_hash!(&nodes[0], nodes[1], 100000);
	let (payment_preimage_2, payment_hash_2, payment_secret_2) = get_payment_preimage_hash!(&nodes[1]);

	// Do a really complicated dance to get an HTLC into the holding cell, with MonitorUpdateFailed
	// set but AwaitingRemoteRevoke unset. When this test was written, any attempts to send an HTLC
	// while MonitorUpdateFailed is set are immediately failed-backwards. Thus, the only way to get
	// an AddHTLC into the holding cell is to add it while AwaitingRemoteRevoke is set but
	// MonitorUpdateFailed is unset, and then swap the flags.
	//
	// We do this by:
	//  a) routing a payment from node B to node A,
	//  b) sending a payment from node A to node B without delivering any of the generated messages,
	//     putting node A in AwaitingRemoteRevoke,
	//  c) sending a second payment from node A to node B, which is immediately placed in the
	//     holding cell,
	//  d) claiming the first payment from B, allowing us to fail the monitor update which occurs
	//     when we try to persist the payment preimage,
	//  e) delivering A's commitment_signed from (b) and the resulting B revoke_and_ack message,
	//     clearing AwaitingRemoteRevoke on node A.
	//
	// Note that because, at the end, MonitorUpdateFailed is still set, the HTLC generated in (c)
	// will not be freed from the holding cell.
	let (payment_preimage_0, _, _) = route_payment(&nodes[1], &[&nodes[0]], 100000);

	nodes[0].node.send_payment(&route, payment_hash_1, &Some(payment_secret_1)).unwrap();
	check_added_monitors!(nodes[0], 1);
	let send = SendEvent::from_node(&nodes[0]);
	assert_eq!(send.msgs.len(), 1);

	nodes[0].node.send_payment(&route, payment_hash_2, &Some(payment_secret_2)).unwrap();
	check_added_monitors!(nodes[0], 0);

	chanmon_cfgs[0].persister.set_update_ret(Err(ChannelMonitorUpdateErr::TemporaryFailure));
	assert!(nodes[0].node.claim_funds(payment_preimage_0));
	check_added_monitors!(nodes[0], 1);

	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &send.msgs[0]);
	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &send.commitment_msg);
	check_added_monitors!(nodes[1], 1);

	let (raa, cs) = get_revoke_commit_msgs!(nodes[1], nodes[0].node.get_our_node_id());

	nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &raa);
	check_added_monitors!(nodes[0], 1);

	if disconnect {
		// Optionally reload nodes[0] entirely through a serialization roundtrip, otherwise just
		// disconnect the peers. Note that the fuzzer originally found this issue because
		// deserializing a ChannelManager in this state causes an assertion failure.
		if reload_a {
			let nodes_0_serialized = nodes[0].node.encode();
			let mut chan_0_monitor_serialized = test_utils::TestVecWriter(Vec::new());
			get_monitor!(nodes[0], chan_id).write(&mut chan_0_monitor_serialized).unwrap();

			persister = test_utils::TestPersister::new();
			let keys_manager = &chanmon_cfgs[0].keys_manager;
			new_chain_monitor = test_utils::TestChainMonitor::new(Some(nodes[0].chain_source), nodes[0].tx_broadcaster.clone(), nodes[0].logger, node_cfgs[0].fee_estimator, &persister, keys_manager);
			nodes[0].chain_monitor = &new_chain_monitor;
			let mut chan_0_monitor_read = &chan_0_monitor_serialized.0[..];
			let (_, mut chan_0_monitor) = <(BlockHash, ChannelMonitor<EnforcingSigner>)>::read(
				&mut chan_0_monitor_read, keys_manager).unwrap();
			assert!(chan_0_monitor_read.is_empty());

			let mut nodes_0_read = &nodes_0_serialized[..];
			let config = UserConfig::default();
			nodes_0_deserialized = {
				let mut channel_monitors = HashMap::new();
				channel_monitors.insert(chan_0_monitor.get_funding_txo().0, &mut chan_0_monitor);
				<(BlockHash, ChannelManager<EnforcingSigner, &test_utils::TestChainMonitor, &test_utils::TestBroadcaster, &test_utils::TestKeysInterface, &test_utils::TestFeeEstimator, &test_utils::TestLogger>)>::read(&mut nodes_0_read, ChannelManagerReadArgs {
					default_config: config,
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

			nodes[0].chain_monitor.watch_channel(chan_0_monitor.get_funding_txo().0.clone(), chan_0_monitor).unwrap();
			check_added_monitors!(nodes[0], 1);
		} else {
			nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id(), false);
		}
		nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);

		// Now reconnect the two
		nodes[0].node.peer_connected(&nodes[1].node.get_our_node_id(), &msgs::Init { features: InitFeatures::empty() });
		let reestablish_1 = get_chan_reestablish_msgs!(nodes[0], nodes[1]);
		assert_eq!(reestablish_1.len(), 1);
		nodes[1].node.peer_connected(&nodes[0].node.get_our_node_id(), &msgs::Init { features: InitFeatures::empty() });
		let reestablish_2 = get_chan_reestablish_msgs!(nodes[1], nodes[0]);
		assert_eq!(reestablish_2.len(), 1);

		nodes[1].node.handle_channel_reestablish(&nodes[0].node.get_our_node_id(), &reestablish_1[0]);
		let resp_1 = handle_chan_reestablish_msgs!(nodes[1], nodes[0]);
		check_added_monitors!(nodes[1], 0);

		nodes[0].node.handle_channel_reestablish(&nodes[1].node.get_our_node_id(), &reestablish_2[0]);
		let resp_0 = handle_chan_reestablish_msgs!(nodes[0], nodes[1]);

		assert!(resp_0.0.is_none());
		assert!(resp_0.1.is_none());
		assert!(resp_0.2.is_none());
		assert!(resp_1.0.is_none());
		assert!(resp_1.1.is_none());

		// Check that the freshly-generated cs is equal to the original (which we will deliver in a
		// moment).
		if let Some(pending_cs) = resp_1.2 {
			assert!(pending_cs.update_add_htlcs.is_empty());
			assert!(pending_cs.update_fail_htlcs.is_empty());
			assert!(pending_cs.update_fulfill_htlcs.is_empty());
			assert_eq!(pending_cs.commitment_signed, cs);
		} else { panic!(); }

		// There should be no monitor updates as we are still pending awaiting a failed one.
		check_added_monitors!(nodes[0], 0);
		check_added_monitors!(nodes[1], 0);
	}

	// If we finish updating the monitor, we should free the holding cell right away (this did
	// not occur prior to #756).
	chanmon_cfgs[0].persister.set_update_ret(Ok(()));
	let (funding_txo, mon_id, _) = nodes[0].chain_monitor.latest_monitor_update_id.lock().unwrap().get(&chan_id).unwrap().clone();
	nodes[0].chain_monitor.chain_monitor.force_channel_monitor_updated(funding_txo, mon_id);

	// New outbound messages should be generated immediately upon a call to
	// get_and_clear_pending_msg_events (but not before).
	check_added_monitors!(nodes[0], 0);
	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	check_added_monitors!(nodes[0], 1);
	assert_eq!(events.len(), 1);

	// Deliver the pending in-flight CS
	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &cs);
	check_added_monitors!(nodes[0], 1);

	let commitment_msg = match events.pop().unwrap() {
		MessageSendEvent::UpdateHTLCs { node_id, updates } => {
			assert_eq!(node_id, nodes[1].node.get_our_node_id());
			assert!(updates.update_fail_htlcs.is_empty());
			assert!(updates.update_fail_malformed_htlcs.is_empty());
			assert!(updates.update_fee.is_none());
			assert_eq!(updates.update_fulfill_htlcs.len(), 1);
			nodes[1].node.handle_update_fulfill_htlc(&nodes[0].node.get_our_node_id(), &updates.update_fulfill_htlcs[0]);
			expect_payment_sent_without_paths!(nodes[1], payment_preimage_0);
			assert_eq!(updates.update_add_htlcs.len(), 1);
			nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &updates.update_add_htlcs[0]);
			updates.commitment_signed
		},
		_ => panic!("Unexpected event type!"),
	};

	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &commitment_msg);
	check_added_monitors!(nodes[1], 1);

	let as_revoke_and_ack = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());
	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &as_revoke_and_ack);
	expect_pending_htlcs_forwardable!(nodes[1]);
	expect_payment_received!(nodes[1], payment_hash_1, payment_secret_1, 100000);
	check_added_monitors!(nodes[1], 1);

	commitment_signed_dance!(nodes[1], nodes[0], (), false, true, false);

	let events = nodes[1].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 2);
	match events[0] {
		Event::PendingHTLCsForwardable { .. } => { },
		_ => panic!("Unexpected event"),
	};
	match events[1] {
		Event::PaymentPathSuccessful { .. } => { },
		_ => panic!("Unexpected event"),
	};

	nodes[1].node.process_pending_htlc_forwards();
	expect_payment_received!(nodes[1], payment_hash_2, payment_secret_2, 100000);

	claim_payment(&nodes[0], &[&nodes[1]], payment_preimage_1);
	claim_payment(&nodes[0], &[&nodes[1]], payment_preimage_2);
}
#[test]
fn channel_holding_cell_serialize() {
	do_channel_holding_cell_serialize(true, true);
	do_channel_holding_cell_serialize(true, false);
	do_channel_holding_cell_serialize(false, true); // last arg doesn't matter
}

#[derive(PartialEq)]
enum HTLCStatusAtDupClaim {
	Received,
	HoldingCell,
	Cleared,
}
fn do_test_reconnect_dup_htlc_claims(htlc_status: HTLCStatusAtDupClaim, second_fails: bool) {
	// When receiving an update_fulfill_htlc message, we immediately forward the claim backwards
	// along the payment path before waiting for a full commitment_signed dance. This is great, but
	// can cause duplicative claims if a node sends an update_fulfill_htlc message, disconnects,
	// reconnects, and then has to re-send its update_fulfill_htlc message again.
	// In previous code, we didn't handle the double-claim correctly, spuriously closing the
	// channel on which the inbound HTLC was received.
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());
	let chan_2 = create_announced_chan_between_nodes(&nodes, 1, 2, InitFeatures::known(), InitFeatures::known()).2;

	let (payment_preimage, payment_hash, _) = route_payment(&nodes[0], &[&nodes[1], &nodes[2]], 100_000);

	let mut as_raa = None;
	if htlc_status == HTLCStatusAtDupClaim::HoldingCell {
		// In order to get the HTLC claim into the holding cell at nodes[1], we need nodes[1] to be
		// awaiting a remote revoke_and_ack from nodes[0].
		let (route, second_payment_hash, _, second_payment_secret) = get_route_and_payment_hash!(nodes[0], nodes[1], 100_000);
		nodes[0].node.send_payment(&route, second_payment_hash, &Some(second_payment_secret)).unwrap();
		check_added_monitors!(nodes[0], 1);

		let send_event = SendEvent::from_event(nodes[0].node.get_and_clear_pending_msg_events().remove(0));
		nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &send_event.msgs[0]);
		nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &send_event.commitment_msg);
		check_added_monitors!(nodes[1], 1);

		let (bs_raa, bs_cs) = get_revoke_commit_msgs!(nodes[1], nodes[0].node.get_our_node_id());
		nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_raa);
		check_added_monitors!(nodes[0], 1);
		nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &bs_cs);
		check_added_monitors!(nodes[0], 1);

		as_raa = Some(get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id()));
	}

	let fulfill_msg = msgs::UpdateFulfillHTLC {
		channel_id: chan_2,
		htlc_id: 0,
		payment_preimage,
	};
	if second_fails {
		assert!(nodes[2].node.fail_htlc_backwards(&payment_hash));
		expect_pending_htlcs_forwardable!(nodes[2]);
		check_added_monitors!(nodes[2], 1);
		get_htlc_update_msgs!(nodes[2], nodes[1].node.get_our_node_id());
	} else {
		assert!(nodes[2].node.claim_funds(payment_preimage));
		check_added_monitors!(nodes[2], 1);
		let cs_updates = get_htlc_update_msgs!(nodes[2], nodes[1].node.get_our_node_id());
		assert_eq!(cs_updates.update_fulfill_htlcs.len(), 1);
		// Check that the message we're about to deliver matches the one generated:
		assert_eq!(fulfill_msg, cs_updates.update_fulfill_htlcs[0]);
	}
	nodes[1].node.handle_update_fulfill_htlc(&nodes[2].node.get_our_node_id(), &fulfill_msg);
	expect_payment_forwarded!(nodes[1], Some(1000), false);
	check_added_monitors!(nodes[1], 1);

	let mut bs_updates = None;
	if htlc_status != HTLCStatusAtDupClaim::HoldingCell {
		bs_updates = Some(get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id()));
		assert_eq!(bs_updates.as_ref().unwrap().update_fulfill_htlcs.len(), 1);
		nodes[0].node.handle_update_fulfill_htlc(&nodes[1].node.get_our_node_id(), &bs_updates.as_ref().unwrap().update_fulfill_htlcs[0]);
		expect_payment_sent_without_paths!(nodes[0], payment_preimage);
		if htlc_status == HTLCStatusAtDupClaim::Cleared {
			commitment_signed_dance!(nodes[0], nodes[1], &bs_updates.as_ref().unwrap().commitment_signed, false);
			expect_payment_path_successful!(nodes[0]);
		}
	} else {
		assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	}

	nodes[1].node.peer_disconnected(&nodes[2].node.get_our_node_id(), false);
	nodes[2].node.peer_disconnected(&nodes[1].node.get_our_node_id(), false);

	if second_fails {
		reconnect_nodes(&nodes[1], &nodes[2], (false, false), (0, 0), (0, 0), (1, 0), (0, 0), (0, 0), (false, false));
		expect_pending_htlcs_forwardable!(nodes[1]);
	} else {
		reconnect_nodes(&nodes[1], &nodes[2], (false, false), (0, 0), (1, 0), (0, 0), (0, 0), (0, 0), (false, false));
	}

	if htlc_status == HTLCStatusAtDupClaim::HoldingCell {
		nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &as_raa.unwrap());
		check_added_monitors!(nodes[1], 1);
		expect_pending_htlcs_forwardable_ignore!(nodes[1]); // We finally receive the second payment, but don't claim it

		bs_updates = Some(get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id()));
		assert_eq!(bs_updates.as_ref().unwrap().update_fulfill_htlcs.len(), 1);
		nodes[0].node.handle_update_fulfill_htlc(&nodes[1].node.get_our_node_id(), &bs_updates.as_ref().unwrap().update_fulfill_htlcs[0]);
		expect_payment_sent_without_paths!(nodes[0], payment_preimage);
	}
	if htlc_status != HTLCStatusAtDupClaim::Cleared {
		commitment_signed_dance!(nodes[0], nodes[1], &bs_updates.as_ref().unwrap().commitment_signed, false);
		expect_payment_path_successful!(nodes[0]);
	}
}

#[test]
fn test_reconnect_dup_htlc_claims() {
	do_test_reconnect_dup_htlc_claims(HTLCStatusAtDupClaim::Received, false);
	do_test_reconnect_dup_htlc_claims(HTLCStatusAtDupClaim::HoldingCell, false);
	do_test_reconnect_dup_htlc_claims(HTLCStatusAtDupClaim::Cleared, false);
	do_test_reconnect_dup_htlc_claims(HTLCStatusAtDupClaim::Received, true);
	do_test_reconnect_dup_htlc_claims(HTLCStatusAtDupClaim::HoldingCell, true);
	do_test_reconnect_dup_htlc_claims(HTLCStatusAtDupClaim::Cleared, true);
}

#[test]
fn test_temporary_error_during_shutdown() {
	// Test that temporary failures when updating the monitor's shutdown script delay cooperative
	// close.
	let mut config = test_default_channel_config();
	config.channel_options.commit_upfront_shutdown_pubkey = false;

	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[Some(config), Some(config)]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let (_, _, channel_id, funding_tx) = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());

	chanmon_cfgs[0].persister.set_update_ret(Err(ChannelMonitorUpdateErr::TemporaryFailure));
	chanmon_cfgs[1].persister.set_update_ret(Err(ChannelMonitorUpdateErr::TemporaryFailure));

	nodes[0].node.close_channel(&channel_id).unwrap();
	nodes[1].node.handle_shutdown(&nodes[0].node.get_our_node_id(), &InitFeatures::known(), &get_event_msg!(nodes[0], MessageSendEvent::SendShutdown, nodes[1].node.get_our_node_id()));
	check_added_monitors!(nodes[1], 1);

	nodes[0].node.handle_shutdown(&nodes[1].node.get_our_node_id(), &InitFeatures::known(), &get_event_msg!(nodes[1], MessageSendEvent::SendShutdown, nodes[0].node.get_our_node_id()));
	check_added_monitors!(nodes[0], 1);

	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());

	chanmon_cfgs[0].persister.set_update_ret(Ok(()));
	chanmon_cfgs[1].persister.set_update_ret(Ok(()));

	let (outpoint, latest_update, _) = nodes[0].chain_monitor.latest_monitor_update_id.lock().unwrap().get(&channel_id).unwrap().clone();
	nodes[0].chain_monitor.chain_monitor.force_channel_monitor_updated(outpoint, latest_update);
	nodes[1].node.handle_closing_signed(&nodes[0].node.get_our_node_id(), &get_event_msg!(nodes[0], MessageSendEvent::SendClosingSigned, nodes[1].node.get_our_node_id()));

	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	chanmon_cfgs[1].persister.set_update_ret(Ok(()));
	let (outpoint, latest_update, _) = nodes[1].chain_monitor.latest_monitor_update_id.lock().unwrap().get(&channel_id).unwrap().clone();
	nodes[1].chain_monitor.chain_monitor.force_channel_monitor_updated(outpoint, latest_update);

	nodes[0].node.handle_closing_signed(&nodes[1].node.get_our_node_id(), &get_event_msg!(nodes[1], MessageSendEvent::SendClosingSigned, nodes[0].node.get_our_node_id()));
	let (_, closing_signed_a) = get_closing_signed_broadcast!(nodes[0].node, nodes[1].node.get_our_node_id());
	let txn_a = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().split_off(0);

	nodes[1].node.handle_closing_signed(&nodes[0].node.get_our_node_id(), &closing_signed_a.unwrap());
	let (_, none_b) = get_closing_signed_broadcast!(nodes[1].node, nodes[0].node.get_our_node_id());
	assert!(none_b.is_none());
	let txn_b = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().split_off(0);

	assert_eq!(txn_a, txn_b);
	assert_eq!(txn_a.len(), 1);
	check_spends!(txn_a[0], funding_tx);
	check_closed_event!(nodes[1], 1, ClosureReason::CooperativeClosure);
	check_closed_event!(nodes[0], 1, ClosureReason::CooperativeClosure);
}

#[test]
fn test_permanent_error_during_sending_shutdown() {
	// Test that permanent failures when updating the monitor's shutdown script result in a force
	// close when initiating a cooperative close.
	let mut config = test_default_channel_config();
	config.channel_options.commit_upfront_shutdown_pubkey = false;

	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[Some(config), None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let channel_id = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known()).2;
	chanmon_cfgs[0].persister.set_update_ret(Err(ChannelMonitorUpdateErr::PermanentFailure));

	assert!(nodes[0].node.close_channel(&channel_id).is_ok());
	check_closed_broadcast!(nodes[0], true);
	check_added_monitors!(nodes[0], 2);
	check_closed_event!(nodes[0], 1, ClosureReason::ProcessingError { err: "ChannelMonitor storage failure".to_string() });
}

#[test]
fn test_permanent_error_during_handling_shutdown() {
	// Test that permanent failures when updating the monitor's shutdown script result in a force
	// close when handling a cooperative close.
	let mut config = test_default_channel_config();
	config.channel_options.commit_upfront_shutdown_pubkey = false;

	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, Some(config)]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let channel_id = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known()).2;
	chanmon_cfgs[1].persister.set_update_ret(Err(ChannelMonitorUpdateErr::PermanentFailure));

	assert!(nodes[0].node.close_channel(&channel_id).is_ok());
	let shutdown = get_event_msg!(nodes[0], MessageSendEvent::SendShutdown, nodes[1].node.get_our_node_id());
	nodes[1].node.handle_shutdown(&nodes[0].node.get_our_node_id(), &InitFeatures::known(), &shutdown);
	check_closed_broadcast!(nodes[1], true);
	check_added_monitors!(nodes[1], 2);
	check_closed_event!(nodes[1], 1, ClosureReason::ProcessingError { err: "ChannelMonitor storage failure".to_string() });
}

#[test]
fn double_temp_error() {
	// Test that it's OK to have multiple `ChainMonitor::update_channel` calls fail in a row.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let (_, _, channel_id, _) = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());

	let (payment_preimage_1, _, _) = route_payment(&nodes[0], &[&nodes[1]], 1000000);
	let (payment_preimage_2, _, _) = route_payment(&nodes[0], &[&nodes[1]], 1000000);

	chanmon_cfgs[1].persister.set_update_ret(Err(ChannelMonitorUpdateErr::TemporaryFailure));
	// `claim_funds` results in a ChannelMonitorUpdate.
	assert!(nodes[1].node.claim_funds(payment_preimage_1));
	check_added_monitors!(nodes[1], 1);
	let (funding_tx, latest_update_1, _) = nodes[1].chain_monitor.latest_monitor_update_id.lock().unwrap().get(&channel_id).unwrap().clone();

	chanmon_cfgs[1].persister.set_update_ret(Err(ChannelMonitorUpdateErr::TemporaryFailure));
	// Previously, this would've panicked due to a double-call to `Channel::monitor_update_failed`,
	// which had some asserts that prevented it from being called twice.
	assert!(nodes[1].node.claim_funds(payment_preimage_2));
	check_added_monitors!(nodes[1], 1);
	chanmon_cfgs[1].persister.set_update_ret(Ok(()));

	let (_, latest_update_2, _) = nodes[1].chain_monitor.latest_monitor_update_id.lock().unwrap().get(&channel_id).unwrap().clone();
	nodes[1].chain_monitor.chain_monitor.force_channel_monitor_updated(funding_tx, latest_update_1);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	check_added_monitors!(nodes[1], 0);
	nodes[1].chain_monitor.chain_monitor.force_channel_monitor_updated(funding_tx, latest_update_2);

	// Complete the first HTLC.
	let events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let (update_fulfill_1, commitment_signed_b1, node_id) = {
		match &events[0] {
			&MessageSendEvent::UpdateHTLCs { ref node_id, updates: msgs::CommitmentUpdate { ref update_add_htlcs, ref update_fulfill_htlcs, ref update_fail_htlcs, ref update_fail_malformed_htlcs, ref update_fee, ref commitment_signed } } => {
				assert!(update_add_htlcs.is_empty());
				assert_eq!(update_fulfill_htlcs.len(), 1);
				assert!(update_fail_htlcs.is_empty());
				assert!(update_fail_malformed_htlcs.is_empty());
				assert!(update_fee.is_none());
				(update_fulfill_htlcs[0].clone(), commitment_signed.clone(), node_id.clone())
			},
			_ => panic!("Unexpected event"),
		}
	};
	assert_eq!(node_id, nodes[0].node.get_our_node_id());
	nodes[0].node.handle_update_fulfill_htlc(&nodes[1].node.get_our_node_id(), &update_fulfill_1);
	check_added_monitors!(nodes[0], 0);
	expect_payment_sent_without_paths!(nodes[0], payment_preimage_1);
	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &commitment_signed_b1);
	check_added_monitors!(nodes[0], 1);
	nodes[0].node.process_pending_htlc_forwards();
	let (raa_a1, commitment_signed_a1) = get_revoke_commit_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	check_added_monitors!(nodes[1], 0);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &raa_a1);
	check_added_monitors!(nodes[1], 1);
	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &commitment_signed_a1);
	check_added_monitors!(nodes[1], 1);

	// Complete the second HTLC.
	let ((update_fulfill_2, commitment_signed_b2), raa_b2) = {
		let events = nodes[1].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 2);
		(match &events[0] {
			MessageSendEvent::UpdateHTLCs { node_id, updates } => {
				assert_eq!(*node_id, nodes[0].node.get_our_node_id());
				assert!(updates.update_add_htlcs.is_empty());
				assert!(updates.update_fail_htlcs.is_empty());
				assert!(updates.update_fail_malformed_htlcs.is_empty());
				assert!(updates.update_fee.is_none());
				assert_eq!(updates.update_fulfill_htlcs.len(), 1);
				(updates.update_fulfill_htlcs[0].clone(), updates.commitment_signed.clone())
			},
			_ => panic!("Unexpected event"),
		},
		 match events[1] {
			 MessageSendEvent::SendRevokeAndACK { ref node_id, ref msg } => {
				 assert_eq!(*node_id, nodes[0].node.get_our_node_id());
				 (*msg).clone()
			 },
			 _ => panic!("Unexpected event"),
		 })
	};
	nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &raa_b2);
	check_added_monitors!(nodes[0], 1);
	expect_payment_path_successful!(nodes[0]);

	nodes[0].node.handle_update_fulfill_htlc(&nodes[1].node.get_our_node_id(), &update_fulfill_2);
	check_added_monitors!(nodes[0], 0);
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	commitment_signed_dance!(nodes[0], nodes[1], commitment_signed_b2, false);
	expect_payment_sent!(nodes[0], payment_preimage_2);
}
