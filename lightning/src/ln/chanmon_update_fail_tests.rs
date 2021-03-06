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

use bitcoin::blockdata::block::BlockHeader;
use bitcoin::hash_types::BlockHash;
use bitcoin::network::constants::Network;
use chain::channelmonitor::{ChannelMonitor, ChannelMonitorUpdateErr};
use chain::transaction::OutPoint;
use chain::Watch;
use ln::channelmanager::{RAACommitmentOrder, PaymentPreimage, PaymentHash, PaymentSecret, PaymentSendFailure};
use ln::features::InitFeatures;
use ln::msgs;
use ln::msgs::{ChannelMessageHandler, ErrorAction, RoutingMessageHandler};
use routing::router::get_route;
use util::enforcing_trait_impls::EnforcingSigner;
use util::events::{Event, EventsProvider, MessageSendEvent, MessageSendEventsProvider};
use util::errors::APIError;
use util::ser::{ReadableArgs, Writeable};

use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::Hash;

use ln::functional_test_utils::*;

use util::test_utils;

// If persister_fail is true, we have the persister return a PermanentFailure
// instead of the higher-level ChainMonitor.
fn do_test_simple_monitor_permanent_update_fail(persister_fail: bool) {
	// Test that we handle a simple permanent monitor update failure
	let mut chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());
	let logger = test_utils::TestLogger::new();

	let (_, payment_hash_1) = get_payment_preimage_hash!(&nodes[0]);

	match persister_fail {
		true => chanmon_cfgs[0].persister.set_update_ret(Err(ChannelMonitorUpdateErr::PermanentFailure)),
		false => *nodes[0].chain_monitor.update_ret.lock().unwrap() = Some(Err(ChannelMonitorUpdateErr::PermanentFailure))
	}
	let net_graph_msg_handler = &nodes[0].net_graph_msg_handler;
	let route = get_route(&nodes[0].node.get_our_node_id(), &net_graph_msg_handler.network_graph.read().unwrap(), &nodes[1].node.get_our_node_id(), None, &Vec::new(), 1000000, TEST_FINAL_CLTV, &logger).unwrap();
	unwrap_send_err!(nodes[0].node.send_payment(&route, payment_hash_1, &None), true, APIError::ChannelUnavailable {..}, {});
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
	// PaymentFailed event

	assert_eq!(nodes[0].node.list_channels().len(), 0);
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
	send_payment(&nodes[0], &vec!(&nodes[1])[..], 10_000_000, 10_000_000);

	// Route an HTLC from node 0 to node 1 (but don't settle)
	let preimage = route_payment(&nodes[0], &vec!(&nodes[1])[..], 9_000_000).0;

	// Make a copy of the ChainMonitor so we can capture the error it returns on a
	// bogus update. Note that if instead we updated the nodes[0]'s ChainMonitor
	// directly, the node would fail to be `Drop`'d at the end because its
	// ChannelManager and ChainMonitor would be out of sync.
	let chain_source = test_utils::TestChainSource::new(Network::Testnet);
	let logger = test_utils::TestLogger::with_id(format!("node {}", 0));
	let persister = test_utils::TestPersister::new();
	let chain_mon = {
		let monitors = nodes[0].chain_monitor.chain_monitor.monitors.read().unwrap();
		let monitor = monitors.get(&outpoint).unwrap();
		let mut w = test_utils::TestVecWriter(Vec::new());
		monitor.write(&mut w).unwrap();
		let new_monitor = <(BlockHash, ChannelMonitor<EnforcingSigner>)>::read(
			&mut ::std::io::Cursor::new(&w.0), &test_utils::OnlyReadsKeysInterface {}).unwrap().1;
		assert!(new_monitor == *monitor);
		let chain_mon = test_utils::TestChainMonitor::new(Some(&chain_source), &chanmon_cfgs[0].tx_broadcaster, &logger, &chanmon_cfgs[0].fee_estimator, &persister, &node_cfgs[0].keys_manager);
		assert!(chain_mon.watch_channel(outpoint, new_monitor).is_ok());
		chain_mon
	};
	let header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
	chain_mon.chain_monitor.block_connected(&header, &[], 200);

	// Set the persister's return value to be a TemporaryFailure.
	persister.set_update_ret(Err(ChannelMonitorUpdateErr::TemporaryFailure));

	// Try to update ChannelMonitor
	assert!(nodes[1].node.claim_funds(preimage, &None, 9_000_000));
	check_added_monitors!(nodes[1], 1);
	let updates = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	assert_eq!(updates.update_fulfill_htlcs.len(), 1);
	nodes[0].node.handle_update_fulfill_htlc(&nodes[1].node.get_our_node_id(), &updates.update_fulfill_htlcs[0]);
	if let Some(ref mut channel) = nodes[0].node.channel_state.lock().unwrap().by_id.get_mut(&chan.2) {
		if let Ok((_, _, _, update)) = channel.commitment_signed(&updates.commitment_signed, &node_cfgs[0].fee_estimator, &node_cfgs[0].logger) {
			// Check that even though the persister is returning a TemporaryFailure,
			// because the update is bogus, ultimately the error that's returned
			// should be a PermanentFailure.
			if let Err(ChannelMonitorUpdateErr::PermanentFailure) = chain_mon.chain_monitor.update_channel(outpoint, update.clone()) {} else { panic!("Expected monitor error to be permanent"); }
			logger.assert_log_contains("lightning::chain::chainmonitor".to_string(), "Failed to persist channel monitor update: TemporaryFailure".to_string(), 1);
			if let Ok(_) = nodes[0].chain_monitor.update_channel(outpoint, update) {} else { assert!(false); }
		} else { assert!(false); }
	} else { assert!(false); };

	check_added_monitors!(nodes[0], 1);
	let events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
}

#[test]
fn test_simple_monitor_permanent_update_fail() {
	do_test_simple_monitor_permanent_update_fail(false);

	// Test behavior when the persister returns a PermanentFailure.
	do_test_simple_monitor_permanent_update_fail(true);
}

// If persister_fail is true, we have the persister return a TemporaryFailure instead of the
// higher-level ChainMonitor.
fn do_test_simple_monitor_temporary_update_fail(disconnect: bool, persister_fail: bool) {
	// Test that we can recover from a simple temporary monitor update failure optionally with
	// a disconnect in between
	let mut chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let channel_id = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known()).2;
	let logger = test_utils::TestLogger::new();

	let (payment_preimage_1, payment_hash_1) = get_payment_preimage_hash!(&nodes[0]);

	match persister_fail {
		true => chanmon_cfgs[0].persister.set_update_ret(Err(ChannelMonitorUpdateErr::TemporaryFailure)),
		false => *nodes[0].chain_monitor.update_ret.lock().unwrap() = Some(Err(ChannelMonitorUpdateErr::TemporaryFailure))
	}

	{
		let net_graph_msg_handler = &nodes[0].net_graph_msg_handler;
		let route = get_route(&nodes[0].node.get_our_node_id(), &net_graph_msg_handler.network_graph.read().unwrap(), &nodes[1].node.get_our_node_id(), None, &Vec::new(), 1000000, TEST_FINAL_CLTV, &logger).unwrap();
		unwrap_send_err!(nodes[0].node.send_payment(&route, payment_hash_1, &None), false, APIError::MonitorUpdateFailed, {});
		check_added_monitors!(nodes[0], 1);
	}

	assert!(nodes[0].node.get_and_clear_pending_events().is_empty());
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	assert_eq!(nodes[0].node.list_channels().len(), 1);

	if disconnect {
		nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id(), false);
		nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);
		reconnect_nodes(&nodes[0], &nodes[1], (true, true), (0, 0), (0, 0), (0, 0), (0, 0), (false, false));
	}

	match persister_fail {
		true => chanmon_cfgs[0].persister.set_update_ret(Ok(())),
		false => *nodes[0].chain_monitor.update_ret.lock().unwrap() = Some(Ok(()))
	}
	let (outpoint, latest_update) = nodes[0].chain_monitor.latest_monitor_update_id.lock().unwrap().get(&channel_id).unwrap().clone();
	nodes[0].node.channel_monitor_updated(&outpoint, latest_update);
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
		Event::PaymentReceived { ref payment_hash, ref payment_secret, amt } => {
			assert_eq!(payment_hash_1, *payment_hash);
			assert_eq!(*payment_secret, None);
			assert_eq!(amt, 1000000);
		},
		_ => panic!("Unexpected event"),
	}

	claim_payment(&nodes[0], &[&nodes[1]], payment_preimage_1, 1_000_000);

	// Now set it to failed again...
	let (_, payment_hash_2) = get_payment_preimage_hash!(&nodes[0]);
	{
		match persister_fail {
			true => chanmon_cfgs[0].persister.set_update_ret(Err(ChannelMonitorUpdateErr::TemporaryFailure)),
			false => *nodes[0].chain_monitor.update_ret.lock().unwrap() = Some(Err(ChannelMonitorUpdateErr::TemporaryFailure))
		}
		let net_graph_msg_handler = &nodes[0].net_graph_msg_handler;
		let route = get_route(&nodes[0].node.get_our_node_id(), &net_graph_msg_handler.network_graph.read().unwrap(), &nodes[1].node.get_our_node_id(), None, &Vec::new(), 1000000, TEST_FINAL_CLTV, &logger).unwrap();
		unwrap_send_err!(nodes[0].node.send_payment(&route, payment_hash_2, &None), false, APIError::MonitorUpdateFailed, {});
		check_added_monitors!(nodes[0], 1);
	}

	assert!(nodes[0].node.get_and_clear_pending_events().is_empty());
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	assert_eq!(nodes[0].node.list_channels().len(), 1);

	if disconnect {
		nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id(), false);
		nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);
		reconnect_nodes(&nodes[0], &nodes[1], (false, false), (0, 0), (0, 0), (0, 0), (0, 0), (false, false));
	}

	// ...and make sure we can force-close a frozen channel
	nodes[0].node.force_close_channel(&channel_id).unwrap();
	check_added_monitors!(nodes[0], 1);
	check_closed_broadcast!(nodes[0], false);

	// TODO: Once we hit the chain with the failure transaction we should check that we get a
	// PaymentFailed event

	assert_eq!(nodes[0].node.list_channels().len(), 0);
}

#[test]
fn test_simple_monitor_temporary_update_fail() {
	do_test_simple_monitor_temporary_update_fail(false, false);
	do_test_simple_monitor_temporary_update_fail(true, false);

	// Test behavior when the persister returns a TemporaryFailure.
	do_test_simple_monitor_temporary_update_fail(false, true);
	do_test_simple_monitor_temporary_update_fail(true, true);
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
	let logger = test_utils::TestLogger::new();

	let (payment_preimage_1, _) = route_payment(&nodes[0], &[&nodes[1]], 1000000);

	// Now try to send a second payment which will fail to send
	let (payment_preimage_2, payment_hash_2) = get_payment_preimage_hash!(nodes[0]);
	{
		*nodes[0].chain_monitor.update_ret.lock().unwrap() = Some(Err(ChannelMonitorUpdateErr::TemporaryFailure));
		let net_graph_msg_handler = &nodes[0].net_graph_msg_handler;
		let route = get_route(&nodes[0].node.get_our_node_id(), &net_graph_msg_handler.network_graph.read().unwrap(), &nodes[1].node.get_our_node_id(), None, &Vec::new(), 1000000, TEST_FINAL_CLTV, &logger).unwrap();
		unwrap_send_err!(nodes[0].node.send_payment(&route, payment_hash_2, &None), false, APIError::MonitorUpdateFailed, {});
		check_added_monitors!(nodes[0], 1);
	}

	assert!(nodes[0].node.get_and_clear_pending_events().is_empty());
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	assert_eq!(nodes[0].node.list_channels().len(), 1);

	// Claim the previous payment, which will result in a update_fulfill_htlc/CS from nodes[1]
	// but nodes[0] won't respond since it is frozen.
	assert!(nodes[1].node.claim_funds(payment_preimage_1, &None, 1_000_000));
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
					Event::PaymentSent { ref payment_preimage } => {
						assert_eq!(*payment_preimage, payment_preimage_1);
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
	*nodes[0].chain_monitor.update_ret.lock().unwrap() = Some(Ok(()));
	let (outpoint, latest_update) = nodes[0].chain_monitor.latest_monitor_update_id.lock().unwrap().get(&channel_id).unwrap().clone();
	nodes[0].node.channel_monitor_updated(&outpoint, latest_update);
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
				Event::PaymentSent { ref payment_preimage } => {
					assert_eq!(*payment_preimage, payment_preimage_1);
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

	expect_pending_htlcs_forwardable!(nodes[1]);

	let events_5 = nodes[1].node.get_and_clear_pending_events();
	assert_eq!(events_5.len(), 1);
	match events_5[0] {
		Event::PaymentReceived { ref payment_hash, ref payment_secret, amt } => {
			assert_eq!(payment_hash_2, *payment_hash);
			assert_eq!(*payment_secret, None);
			assert_eq!(amt, 1000000);
		},
		_ => panic!("Unexpected event"),
	}

	claim_payment(&nodes[0], &[&nodes[1]], payment_preimage_2, 1_000_000);
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
	let logger = test_utils::TestLogger::new();

	let (payment_preimage, our_payment_hash) = get_payment_preimage_hash!(nodes[0]);
	{
		let net_graph_msg_handler = &nodes[0].net_graph_msg_handler;
		let route = get_route(&nodes[0].node.get_our_node_id(), &net_graph_msg_handler.network_graph.read().unwrap(), &nodes[1].node.get_our_node_id(), None, &Vec::new(), 1000000, TEST_FINAL_CLTV, &logger).unwrap();
		nodes[0].node.send_payment(&route, our_payment_hash, &None).unwrap();
		check_added_monitors!(nodes[0], 1);
	}

	let send_event = SendEvent::from_event(nodes[0].node.get_and_clear_pending_msg_events().remove(0));
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &send_event.msgs[0]);

	*nodes[1].chain_monitor.update_ret.lock().unwrap() = Some(Err(ChannelMonitorUpdateErr::TemporaryFailure));
	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &send_event.commitment_msg);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	nodes[1].logger.assert_log("lightning::ln::channelmanager".to_string(), "Failed to update ChannelMonitor".to_string(), 1);
	check_added_monitors!(nodes[1], 1);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	*nodes[1].chain_monitor.update_ret.lock().unwrap() = Some(Ok(()));
	let (outpoint, latest_update) = nodes[1].chain_monitor.latest_monitor_update_id.lock().unwrap().get(&channel_id).unwrap().clone();
	nodes[1].node.channel_monitor_updated(&outpoint, latest_update);
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

			*nodes[0].chain_monitor.update_ret.lock().unwrap() = Some(Err(ChannelMonitorUpdateErr::TemporaryFailure));
			nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &updates.commitment_signed);
			assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
			nodes[0].logger.assert_log("lightning::ln::channelmanager".to_string(), "Failed to update ChannelMonitor".to_string(), 1);
			check_added_monitors!(nodes[0], 1);
			assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
		},
		_ => panic!("Unexpected event"),
	}

	*nodes[0].chain_monitor.update_ret.lock().unwrap() = Some(Ok(()));
	let (outpoint, latest_update) = nodes[0].chain_monitor.latest_monitor_update_id.lock().unwrap().get(&channel_id).unwrap().clone();
	nodes[0].node.channel_monitor_updated(&outpoint, latest_update);
	check_added_monitors!(nodes[0], 0);

	let final_raa = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());
	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &final_raa);
	check_added_monitors!(nodes[1], 1);

	expect_pending_htlcs_forwardable!(nodes[1]);

	let events = nodes[1].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		Event::PaymentReceived { payment_hash, payment_secret, amt } => {
			assert_eq!(payment_hash, our_payment_hash);
			assert_eq!(payment_secret, None);
			assert_eq!(amt, 1000000);
		},
		_ => panic!("Unexpected event"),
	};

	claim_payment(&nodes[0], &[&nodes[1]], payment_preimage, 1_000_000);
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
	let logger = test_utils::TestLogger::new();

	let (payment_preimage_1, our_payment_hash) = get_payment_preimage_hash!(nodes[0]);
	{
		let net_graph_msg_handler = &nodes[0].net_graph_msg_handler;
		let route = get_route(&nodes[0].node.get_our_node_id(), &net_graph_msg_handler.network_graph.read().unwrap(), &nodes[1].node.get_our_node_id(), None, &Vec::new(), 1000000, TEST_FINAL_CLTV, &logger).unwrap();
		nodes[0].node.send_payment(&route, our_payment_hash, &None).unwrap();
		check_added_monitors!(nodes[0], 1);
	}

	let send_event = SendEvent::from_event(nodes[0].node.get_and_clear_pending_msg_events().remove(0));
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &send_event.msgs[0]);
	let bs_raa = commitment_signed_dance!(nodes[1], nodes[0], send_event.commitment_msg, false, true, false, true);

	*nodes[1].chain_monitor.update_ret.lock().unwrap() = Some(Err(ChannelMonitorUpdateErr::TemporaryFailure));
	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &bs_raa);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	nodes[1].logger.assert_log("lightning::ln::channelmanager".to_string(), "Failed to update ChannelMonitor".to_string(), 1);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	assert!(nodes[1].node.get_and_clear_pending_events().is_empty());
	check_added_monitors!(nodes[1], 1);

	*nodes[1].chain_monitor.update_ret.lock().unwrap() = Some(Ok(()));
	let (outpoint, latest_update) = nodes[1].chain_monitor.latest_monitor_update_id.lock().unwrap().get(&channel_id).unwrap().clone();
	nodes[1].node.channel_monitor_updated(&outpoint, latest_update);
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

	claim_payment(&nodes[0], &[&nodes[1]], payment_preimage_1, 1_000_000);
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
	let logger = test_utils::TestLogger::new();

	send_payment(&nodes[0], &[&nodes[1]], 5000000, 5_000_000);
	let (payment_preimage_1, our_payment_hash_1) = get_payment_preimage_hash!(nodes[0]);
	{
		let net_graph_msg_handler = &nodes[0].net_graph_msg_handler;
		let route = get_route(&nodes[0].node.get_our_node_id(), &net_graph_msg_handler.network_graph.read().unwrap(), &nodes[1].node.get_our_node_id(), None, &Vec::new(), 1000000, TEST_FINAL_CLTV, &logger).unwrap();
		nodes[0].node.send_payment(&route, our_payment_hash_1, &None).unwrap();
		check_added_monitors!(nodes[0], 1);
	}
	let send_event_1 = SendEvent::from_event(nodes[0].node.get_and_clear_pending_msg_events().remove(0));

	let (payment_preimage_2, our_payment_hash_2) = get_payment_preimage_hash!(nodes[0]);
	{
		let net_graph_msg_handler = &nodes[1].net_graph_msg_handler;
		let route = get_route(&nodes[1].node.get_our_node_id(), &net_graph_msg_handler.network_graph.read().unwrap(), &nodes[0].node.get_our_node_id(), None, &Vec::new(), 1000000, TEST_FINAL_CLTV, &logger).unwrap();
		nodes[1].node.send_payment(&route, our_payment_hash_2, &None).unwrap();
		check_added_monitors!(nodes[1], 1);
	}
	let send_event_2 = SendEvent::from_event(nodes[1].node.get_and_clear_pending_msg_events().remove(0));

	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &send_event_1.msgs[0]);
	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &send_event_1.commitment_msg);
	check_added_monitors!(nodes[1], 1);
	let bs_raa = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, nodes[0].node.get_our_node_id());

	*nodes[0].chain_monitor.update_ret.lock().unwrap() = Some(Err(ChannelMonitorUpdateErr::TemporaryFailure));
	nodes[0].node.handle_update_add_htlc(&nodes[1].node.get_our_node_id(), &send_event_2.msgs[0]);
	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &send_event_2.commitment_msg);
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	nodes[0].logger.assert_log("lightning::ln::channelmanager".to_string(), "Failed to update ChannelMonitor".to_string(), 1);
	check_added_monitors!(nodes[0], 1);

	nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_raa);
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	nodes[0].logger.assert_log("lightning::ln::channelmanager".to_string(), "Previous monitor update failure prevented responses to RAA".to_string(), 1);
	check_added_monitors!(nodes[0], 1);

	*nodes[0].chain_monitor.update_ret.lock().unwrap() = Some(Ok(()));
	let (outpoint, latest_update) = nodes[0].chain_monitor.latest_monitor_update_id.lock().unwrap().get(&channel_id).unwrap().clone();
	nodes[0].node.channel_monitor_updated(&outpoint, latest_update);
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
	expect_payment_received!(nodes[0], our_payment_hash_2, 1000000);

	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &as_second_raa);
	check_added_monitors!(nodes[1], 1);
	expect_pending_htlcs_forwardable!(nodes[1]);
	expect_payment_received!(nodes[1], our_payment_hash_1, 1000000);

	claim_payment(&nodes[0], &[&nodes[1]], payment_preimage_1, 1_000_000);
	claim_payment(&nodes[1], &[&nodes[0]], payment_preimage_2, 1_000_000);
}

fn do_test_monitor_update_fail_raa(test_ignore_second_cs: bool) {
	// Tests handling of a monitor update failure when processing an incoming RAA
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());
	let chan_2 = create_announced_chan_between_nodes(&nodes, 1, 2, InitFeatures::known(), InitFeatures::known());
	let logger = test_utils::TestLogger::new();

	// Rebalance a bit so that we can send backwards from 2 to 1.
	send_payment(&nodes[0], &[&nodes[1], &nodes[2]], 5000000, 5_000_000);

	// Route a first payment that we'll fail backwards
	let (_, payment_hash_1) = route_payment(&nodes[0], &[&nodes[1], &nodes[2]], 1000000);

	// Fail the payment backwards, failing the monitor update on nodes[1]'s receipt of the RAA
	assert!(nodes[2].node.fail_htlc_backwards(&payment_hash_1, &None));
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
	let (payment_preimage_2, payment_hash_2) = get_payment_preimage_hash!(nodes[0]);
	{
		let net_graph_msg_handler = &nodes[0].net_graph_msg_handler;
		let route = get_route(&nodes[0].node.get_our_node_id(), &net_graph_msg_handler.network_graph.read().unwrap(), &nodes[2].node.get_our_node_id(), None, &Vec::new(), 1000000, TEST_FINAL_CLTV, &logger).unwrap();
		nodes[0].node.send_payment(&route, payment_hash_2, &None).unwrap();
		check_added_monitors!(nodes[0], 1);
	}

	let mut send_event = SendEvent::from_event(nodes[0].node.get_and_clear_pending_msg_events().remove(0));
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &send_event.msgs[0]);
	commitment_signed_dance!(nodes[1], nodes[0], send_event.commitment_msg, false);

	expect_pending_htlcs_forwardable!(nodes[1]);
	check_added_monitors!(nodes[1], 0);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	// Now fail monitor updating.
	*nodes[1].chain_monitor.update_ret.lock().unwrap() = Some(Err(ChannelMonitorUpdateErr::TemporaryFailure));
	nodes[1].node.handle_revoke_and_ack(&nodes[2].node.get_our_node_id(), &bs_revoke_and_ack);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	nodes[1].logger.assert_log("lightning::ln::channelmanager".to_string(), "Failed to update ChannelMonitor".to_string(), 1);
	assert!(nodes[1].node.get_and_clear_pending_events().is_empty());
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	check_added_monitors!(nodes[1], 1);

	// Attempt to forward a third payment but fail due to the second channel being unavailable
	// for forwarding.
	let (_, payment_hash_3) = get_payment_preimage_hash!(nodes[0]);
	{
		let net_graph_msg_handler = &nodes[0].net_graph_msg_handler;
		let route = get_route(&nodes[0].node.get_our_node_id(), &net_graph_msg_handler.network_graph.read().unwrap(), &nodes[2].node.get_our_node_id(), None, &Vec::new(), 1000000, TEST_FINAL_CLTV, &logger).unwrap();
		nodes[0].node.send_payment(&route, payment_hash_3, &None).unwrap();
		check_added_monitors!(nodes[0], 1);
	}

	*nodes[1].chain_monitor.update_ret.lock().unwrap() = Some(Ok(())); // We succeed in updating the monitor for the first channel
	send_event = SendEvent::from_event(nodes[0].node.get_and_clear_pending_msg_events().remove(0));
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &send_event.msgs[0]);
	commitment_signed_dance!(nodes[1], nodes[0], send_event.commitment_msg, false, true);
	check_added_monitors!(nodes[1], 0);

	let mut events_2 = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(events_2.len(), 1);
	match events_2.remove(0) {
		MessageSendEvent::UpdateHTLCs { node_id, updates } => {
			assert_eq!(node_id, nodes[0].node.get_our_node_id());
			assert!(updates.update_fulfill_htlcs.is_empty());
			assert_eq!(updates.update_fail_htlcs.len(), 1);
			assert!(updates.update_fail_malformed_htlcs.is_empty());
			assert!(updates.update_add_htlcs.is_empty());
			assert!(updates.update_fee.is_none());

			nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &updates.update_fail_htlcs[0]);
			commitment_signed_dance!(nodes[0], nodes[1], updates.commitment_signed, false, true);

			let msg_events = nodes[0].node.get_and_clear_pending_msg_events();
			assert_eq!(msg_events.len(), 1);
			match msg_events[0] {
				MessageSendEvent::PaymentFailureNetworkUpdate { update: msgs::HTLCFailChannelUpdate::ChannelUpdateMessage { ref msg }} => {
					assert_eq!(msg.contents.short_channel_id, chan_2.0.contents.short_channel_id);
					assert_eq!(msg.contents.flags & 2, 2); // temp disabled
				},
				_ => panic!("Unexpected event"),
			}

			let events = nodes[0].node.get_and_clear_pending_events();
			assert_eq!(events.len(), 1);
			if let Event::PaymentFailed { payment_hash, rejected_by_dest, .. } = events[0] {
				assert_eq!(payment_hash, payment_hash_3);
				assert!(!rejected_by_dest);
			} else { panic!("Unexpected event!"); }
		},
		_ => panic!("Unexpected event type!"),
	};

	let (payment_preimage_4, payment_hash_4) = if test_ignore_second_cs {
		// Try to route another payment backwards from 2 to make sure 1 holds off on responding
		let (payment_preimage_4, payment_hash_4) = get_payment_preimage_hash!(nodes[0]);
		let net_graph_msg_handler = &nodes[2].net_graph_msg_handler;
		let route = get_route(&nodes[2].node.get_our_node_id(), &net_graph_msg_handler.network_graph.read().unwrap(), &nodes[0].node.get_our_node_id(), None, &Vec::new(), 1000000, TEST_FINAL_CLTV, &logger).unwrap();
		nodes[2].node.send_payment(&route, payment_hash_4, &None).unwrap();
		check_added_monitors!(nodes[2], 1);

		send_event = SendEvent::from_event(nodes[2].node.get_and_clear_pending_msg_events().remove(0));
		nodes[1].node.handle_update_add_htlc(&nodes[2].node.get_our_node_id(), &send_event.msgs[0]);
		nodes[1].node.handle_commitment_signed(&nodes[2].node.get_our_node_id(), &send_event.commitment_msg);
		check_added_monitors!(nodes[1], 1);
		assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
		nodes[1].logger.assert_log("lightning::ln::channelmanager".to_string(), "Previous monitor update failure prevented generation of RAA".to_string(), 1);
		assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
		assert!(nodes[1].node.get_and_clear_pending_events().is_empty());
		(Some(payment_preimage_4), Some(payment_hash_4))
	} else { (None, None) };

	// Restore monitor updating, ensuring we immediately get a fail-back update and a
	// update_add update.
	*nodes[1].chain_monitor.update_ret.lock().unwrap() = Some(Ok(()));
	let (outpoint, latest_update) = nodes[1].chain_monitor.latest_monitor_update_id.lock().unwrap().get(&chan_2.2).unwrap().clone();
	nodes[1].node.channel_monitor_updated(&outpoint, latest_update);
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
	let events_4 = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events_4.len(), 1);
	if let Event::PaymentFailed { payment_hash, rejected_by_dest, .. } = events_4[0] {
		assert_eq!(payment_hash, payment_hash_1);
		assert!(rejected_by_dest);
	} else { panic!("Unexpected event!"); }

	nodes[2].node.handle_update_add_htlc(&nodes[1].node.get_our_node_id(), &send_event_b.msgs[0]);
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
		let as_cs = get_htlc_update_msgs!(nodes[1], nodes[2].node.get_our_node_id());
		assert!(as_cs.update_add_htlcs.is_empty());
		assert!(as_cs.update_fail_htlcs.is_empty());
		assert!(as_cs.update_fail_malformed_htlcs.is_empty());
		assert!(as_cs.update_fulfill_htlcs.is_empty());
		assert!(as_cs.update_fee.is_none());

		nodes[1].node.handle_commitment_signed(&nodes[2].node.get_our_node_id(), &bs_cs.commitment_signed);
		check_added_monitors!(nodes[1], 1);
		let as_raa = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, nodes[2].node.get_our_node_id());

		nodes[2].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &as_cs.commitment_signed);
		check_added_monitors!(nodes[2], 1);
		let bs_second_raa = get_event_msg!(nodes[2], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());

		nodes[2].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &as_raa);
		check_added_monitors!(nodes[2], 1);
		assert!(nodes[2].node.get_and_clear_pending_msg_events().is_empty());

		nodes[1].node.handle_revoke_and_ack(&nodes[2].node.get_our_node_id(), &bs_second_raa);
		check_added_monitors!(nodes[1], 1);
		assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	} else {
		commitment_signed_dance!(nodes[2], nodes[1], send_event_b.commitment_msg, false);
	}

	expect_pending_htlcs_forwardable!(nodes[2]);

	let events_6 = nodes[2].node.get_and_clear_pending_events();
	assert_eq!(events_6.len(), 1);
	match events_6[0] {
		Event::PaymentReceived { payment_hash, .. } => { assert_eq!(payment_hash, payment_hash_2); },
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
		claim_payment(&nodes[2], &[&nodes[1], &nodes[0]], payment_preimage_4.unwrap(), 1_000_000);
	}

	claim_payment(&nodes[0], &[&nodes[1], &nodes[2]], payment_preimage_2, 1_000_000);
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

	let (our_payment_preimage, _) = route_payment(&nodes[0], &[&nodes[1], &nodes[2]], 1000000);

	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);
	nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id(), false);

	assert!(nodes[2].node.claim_funds(our_payment_preimage, &None, 1_000_000));
	check_added_monitors!(nodes[2], 1);
	let mut updates = get_htlc_update_msgs!(nodes[2], nodes[1].node.get_our_node_id());
	assert!(updates.update_add_htlcs.is_empty());
	assert!(updates.update_fail_htlcs.is_empty());
	assert!(updates.update_fail_malformed_htlcs.is_empty());
	assert!(updates.update_fee.is_none());
	assert_eq!(updates.update_fulfill_htlcs.len(), 1);
	nodes[1].node.handle_update_fulfill_htlc(&nodes[2].node.get_our_node_id(), &updates.update_fulfill_htlcs[0]);
	check_added_monitors!(nodes[1], 1);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	commitment_signed_dance!(nodes[1], nodes[2], updates.commitment_signed, false);

	*nodes[1].chain_monitor.update_ret.lock().unwrap() = Some(Err(ChannelMonitorUpdateErr::TemporaryFailure));
	nodes[0].node.peer_connected(&nodes[1].node.get_our_node_id(), &msgs::Init { features: InitFeatures::empty() });
	nodes[1].node.peer_connected(&nodes[0].node.get_our_node_id(), &msgs::Init { features: InitFeatures::empty() });

	let as_reestablish = get_event_msg!(nodes[0], MessageSendEvent::SendChannelReestablish, nodes[1].node.get_our_node_id());
	let bs_reestablish = get_event_msg!(nodes[1], MessageSendEvent::SendChannelReestablish, nodes[0].node.get_our_node_id());

	nodes[0].node.handle_channel_reestablish(&nodes[1].node.get_our_node_id(), &bs_reestablish);

	nodes[1].node.handle_channel_reestablish(&nodes[0].node.get_our_node_id(), &as_reestablish);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	nodes[1].logger.assert_log("lightning::ln::channelmanager".to_string(), "Failed to update ChannelMonitor".to_string(), 1);
	check_added_monitors!(nodes[1], 1);

	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);
	nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id(), false);

	nodes[0].node.peer_connected(&nodes[1].node.get_our_node_id(), &msgs::Init { features: InitFeatures::empty() });
	nodes[1].node.peer_connected(&nodes[0].node.get_our_node_id(), &msgs::Init { features: InitFeatures::empty() });

	assert!(as_reestablish == get_event_msg!(nodes[0], MessageSendEvent::SendChannelReestablish, nodes[1].node.get_our_node_id()));
	assert!(bs_reestablish == get_event_msg!(nodes[1], MessageSendEvent::SendChannelReestablish, nodes[0].node.get_our_node_id()));

	nodes[0].node.handle_channel_reestablish(&nodes[1].node.get_our_node_id(), &bs_reestablish);

	nodes[1].node.handle_channel_reestablish(&nodes[0].node.get_our_node_id(), &as_reestablish);
	check_added_monitors!(nodes[1], 0);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	*nodes[1].chain_monitor.update_ret.lock().unwrap() = Some(Ok(()));
	let (outpoint, latest_update) = nodes[1].chain_monitor.latest_monitor_update_id.lock().unwrap().get(&chan_1.2).unwrap().clone();
	nodes[1].node.channel_monitor_updated(&outpoint, latest_update);
	check_added_monitors!(nodes[1], 0);

	updates = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	assert!(updates.update_add_htlcs.is_empty());
	assert!(updates.update_fail_htlcs.is_empty());
	assert!(updates.update_fail_malformed_htlcs.is_empty());
	assert!(updates.update_fee.is_none());
	assert_eq!(updates.update_fulfill_htlcs.len(), 1);
	nodes[0].node.handle_update_fulfill_htlc(&nodes[1].node.get_our_node_id(), &updates.update_fulfill_htlcs[0]);
	commitment_signed_dance!(nodes[0], nodes[1], updates.commitment_signed, false);

	let events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		Event::PaymentSent { payment_preimage, .. } => assert_eq!(payment_preimage, our_payment_preimage),
		_ => panic!("Unexpected event"),
	}
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
	let logger = test_utils::TestLogger::new();

	let (payment_preimage_1, payment_hash_1) = get_payment_preimage_hash!(nodes[0]);
	let (payment_preimage_2, payment_hash_2) = get_payment_preimage_hash!(nodes[0]);
	let (payment_preimage_3, payment_hash_3) = get_payment_preimage_hash!(nodes[0]);

	// Queue up two payments - one will be delivered right away, one immediately goes into the
	// holding cell as nodes[0] is AwaitingRAA. Ultimately this allows us to deliver an RAA
	// immediately after a CS. By setting failing the monitor update failure from the CS (which
	// requires only an RAA response due to AwaitingRAA) we can deliver the RAA and require the CS
	// generation during RAA while in monitor-update-failed state.
	{
		let net_graph_msg_handler = &nodes[0].net_graph_msg_handler;
		let route = get_route(&nodes[0].node.get_our_node_id(), &net_graph_msg_handler.network_graph.read().unwrap(), &nodes[1].node.get_our_node_id(), None, &Vec::new(), 1000000, TEST_FINAL_CLTV, &logger).unwrap();
		nodes[0].node.send_payment(&route, payment_hash_1, &None).unwrap();
		check_added_monitors!(nodes[0], 1);
		nodes[0].node.send_payment(&route, payment_hash_2, &None).unwrap();
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
	*nodes[1].chain_monitor.update_ret.lock().unwrap() = Some(Err(ChannelMonitorUpdateErr::TemporaryFailure));
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &payment_event.msgs[0]);
	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &payment_event.commitment_msg);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	nodes[1].logger.assert_log("lightning::ln::channelmanager".to_string(), "Failed to update ChannelMonitor".to_string(), 1);
	check_added_monitors!(nodes[1], 1);

	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &as_raa);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	nodes[1].logger.assert_log("lightning::ln::channelmanager".to_string(), "Previous monitor update failure prevented responses to RAA".to_string(), 1);
	check_added_monitors!(nodes[1], 1);

	*nodes[1].chain_monitor.update_ret.lock().unwrap() = Some(Ok(()));
	let (outpoint, latest_update) = nodes[1].chain_monitor.latest_monitor_update_id.lock().unwrap().get(&channel_id).unwrap().clone();
	nodes[1].node.channel_monitor_updated(&outpoint, latest_update);
	// nodes[1] should be AwaitingRAA here!
	check_added_monitors!(nodes[1], 0);
	let bs_responses = get_revoke_commit_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	expect_pending_htlcs_forwardable!(nodes[1]);
	expect_payment_received!(nodes[1], payment_hash_1, 1000000);

	// We send a third payment here, which is somewhat of a redundant test, but the
	// chanmon_fail_consistency test required it to actually find the bug (by seeing out-of-sync
	// commitment transaction states) whereas here we can explicitly check for it.
	{
		let net_graph_msg_handler = &nodes[0].net_graph_msg_handler;
		let route = get_route(&nodes[0].node.get_our_node_id(), &net_graph_msg_handler.network_graph.read().unwrap(), &nodes[1].node.get_our_node_id(), None, &Vec::new(), 1000000, TEST_FINAL_CLTV, &logger).unwrap();
		nodes[0].node.send_payment(&route, payment_hash_3, &None).unwrap();
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
	expect_payment_received!(nodes[1], payment_hash_2, 1000000);
	let bs_update = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());

	nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_raa);
	check_added_monitors!(nodes[0], 1);

	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &bs_update.commitment_signed);
	check_added_monitors!(nodes[0], 1);
	let as_raa = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());

	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &as_raa);
	check_added_monitors!(nodes[1], 1);
	expect_pending_htlcs_forwardable!(nodes[1]);
	expect_payment_received!(nodes[1], payment_hash_3, 1000000);

	claim_payment(&nodes[0], &[&nodes[1]], payment_preimage_1, 1_000_000);
	claim_payment(&nodes[0], &[&nodes[1]], payment_preimage_2, 1_000_000);
	claim_payment(&nodes[0], &[&nodes[1]], payment_preimage_3, 1_000_000);
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
	let logger = test_utils::TestLogger::new();

	// Forward a payment for B to claim
	let (payment_preimage_1, _) = route_payment(&nodes[0], &[&nodes[1]], 1000000);

	nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id(), false);
	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);

	assert!(nodes[1].node.claim_funds(payment_preimage_1, &None, 1_000_000));
	check_added_monitors!(nodes[1], 1);

	nodes[0].node.peer_connected(&nodes[1].node.get_our_node_id(), &msgs::Init { features: InitFeatures::empty() });
	nodes[1].node.peer_connected(&nodes[0].node.get_our_node_id(), &msgs::Init { features: InitFeatures::empty() });

	let as_reconnect = get_event_msg!(nodes[0], MessageSendEvent::SendChannelReestablish, nodes[1].node.get_our_node_id());
	let bs_reconnect = get_event_msg!(nodes[1], MessageSendEvent::SendChannelReestablish, nodes[0].node.get_our_node_id());

	nodes[0].node.handle_channel_reestablish(&nodes[1].node.get_our_node_id(), &bs_reconnect);
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());

	// Now deliver a's reestablish, freeing the claim from the holding cell, but fail the monitor
	// update.
	*nodes[1].chain_monitor.update_ret.lock().unwrap() = Some(Err(ChannelMonitorUpdateErr::TemporaryFailure));

	nodes[1].node.handle_channel_reestablish(&nodes[0].node.get_our_node_id(), &as_reconnect);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	nodes[1].logger.assert_log("lightning::ln::channelmanager".to_string(), "Failed to update ChannelMonitor".to_string(), 1);
	check_added_monitors!(nodes[1], 1);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	// Send a second payment from A to B, resulting in a commitment update that gets swallowed with
	// the monitor still failed
	let (payment_preimage_2, payment_hash_2) = get_payment_preimage_hash!(nodes[0]);
	{
		let net_graph_msg_handler = &nodes[0].net_graph_msg_handler;
		let route = get_route(&nodes[0].node.get_our_node_id(), &net_graph_msg_handler.network_graph.read().unwrap(), &nodes[1].node.get_our_node_id(), None, &Vec::new(), 1000000, TEST_FINAL_CLTV, &logger).unwrap();
		nodes[0].node.send_payment(&route, payment_hash_2, &None).unwrap();
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
	*nodes[1].chain_monitor.update_ret.lock().unwrap() = Some(Ok(()));
	let (outpoint, latest_update) = nodes[1].chain_monitor.latest_monitor_update_id.lock().unwrap().get(&channel_id).unwrap().clone();
	nodes[1].node.channel_monitor_updated(&outpoint, latest_update);
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
	expect_payment_received!(nodes[1], payment_hash_2, 1000000);

	nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_raa);
	check_added_monitors!(nodes[0], 1);

	let events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		Event::PaymentSent { ref payment_preimage } => {
			assert_eq!(*payment_preimage, payment_preimage_1);
		},
		_ => panic!("Unexpected event"),
	}

	claim_payment(&nodes[0], &[&nodes[1]], payment_preimage_2, 1_000_000);
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
	let logger = test_utils::TestLogger::new();

	// Route the payment and deliver the initial commitment_signed (with a monitor update failure
	// on receipt).
	let (payment_preimage_1, payment_hash_1) = get_payment_preimage_hash!(nodes[0]);
	{
		let net_graph_msg_handler = &nodes[0].net_graph_msg_handler;
		let route = get_route(&nodes[0].node.get_our_node_id(), &net_graph_msg_handler.network_graph.read().unwrap(), &nodes[1].node.get_our_node_id(), None, &Vec::new(), 1000000, TEST_FINAL_CLTV, &logger).unwrap();
		nodes[0].node.send_payment(&route, payment_hash_1, &None).unwrap();
		check_added_monitors!(nodes[0], 1);
	}

	*nodes[1].chain_monitor.update_ret.lock().unwrap() = Some(Err(ChannelMonitorUpdateErr::TemporaryFailure));
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
	nodes[0].node.handle_channel_reestablish(&nodes[1].node.get_our_node_id(), &bs_reconnect);

	*nodes[1].chain_monitor.update_ret.lock().unwrap() = Some(Ok(()));
	let (outpoint, latest_update) = nodes[1].chain_monitor.latest_monitor_update_id.lock().unwrap().get(&channel_id).unwrap().clone();
	nodes[1].node.channel_monitor_updated(&outpoint, latest_update);
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
	expect_payment_received!(nodes[1], payment_hash_1, 1000000);

	claim_payment(&nodes[0], &[&nodes[1]], payment_preimage_1, 1_000_000);
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
	let logger = test_utils::TestLogger::new();

	// Route the first payment outbound, holding the last RAA for B until we are set up so that we
	// can deliver it and fail the monitor update.
	let (payment_preimage_1, payment_hash_1) = get_payment_preimage_hash!(nodes[0]);
	{
		let net_graph_msg_handler = &nodes[0].net_graph_msg_handler;
		let route = get_route(&nodes[0].node.get_our_node_id(), &net_graph_msg_handler.network_graph.read().unwrap(), &nodes[1].node.get_our_node_id(), None, &Vec::new(), 1000000, TEST_FINAL_CLTV, &logger).unwrap();
		nodes[0].node.send_payment(&route, payment_hash_1, &None).unwrap();
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
	let (payment_preimage_2, payment_hash_2) = get_payment_preimage_hash!(nodes[0]);
	{
		let net_graph_msg_handler = &nodes[0].net_graph_msg_handler;
		let route = get_route(&nodes[0].node.get_our_node_id(), &net_graph_msg_handler.network_graph.read().unwrap(), &nodes[1].node.get_our_node_id(), None, &Vec::new(), 1000000, TEST_FINAL_CLTV, &logger).unwrap();
		nodes[0].node.send_payment(&route, payment_hash_2, &None).unwrap();
		check_added_monitors!(nodes[0], 1);
	}
	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let payment_event = SendEvent::from_event(events.pop().unwrap());
	assert_eq!(payment_event.node_id, nodes[1].node.get_our_node_id());

	*nodes[1].chain_monitor.update_ret.lock().unwrap() = Some(Err(ChannelMonitorUpdateErr::TemporaryFailure));

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

	*nodes[1].chain_monitor.update_ret.lock().unwrap() = Some(Ok(()));
	let (outpoint, latest_update) = nodes[1].chain_monitor.latest_monitor_update_id.lock().unwrap().get(&channel_id).unwrap().clone();
	nodes[1].node.channel_monitor_updated(&outpoint, latest_update);
	check_added_monitors!(nodes[1], 0);

	expect_pending_htlcs_forwardable!(nodes[1]);
	expect_payment_received!(nodes[1], payment_hash_1, 1000000);

	let bs_responses = get_revoke_commit_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_responses.0);
	check_added_monitors!(nodes[0], 1);
	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &bs_responses.1);
	check_added_monitors!(nodes[0], 1);

	let as_raa = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());
	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &as_raa);
	check_added_monitors!(nodes[1], 1);

	expect_pending_htlcs_forwardable!(nodes[1]);
	expect_payment_received!(nodes[1], payment_hash_2, 1000000);

	claim_payment(&nodes[0], &[&nodes[1]], payment_preimage_1, 1_000_000);
	claim_payment(&nodes[0], &[&nodes[1]], payment_preimage_2, 1_000_000);
}

#[test]
fn test_monitor_update_fail_claim() {
	// Basic test for monitor update failures when processing claim_funds calls.
	// We set up a simple 3-node network, sending a payment from A to B and failing B's monitor
	// update to claim the payment. We then send a payment C->B->A, making the forward of this
	// payment from B to A fail due to the paused channel. Finally, we restore the channel monitor
	// updating and claim the payment on B.
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());
	create_announced_chan_between_nodes(&nodes, 1, 2, InitFeatures::known(), InitFeatures::known());
	let logger = test_utils::TestLogger::new();

	// Rebalance a bit so that we can send backwards from 3 to 2.
	send_payment(&nodes[0], &[&nodes[1], &nodes[2]], 5000000, 5_000_000);

	let (payment_preimage_1, _) = route_payment(&nodes[0], &[&nodes[1]], 1000000);

	*nodes[1].chain_monitor.update_ret.lock().unwrap() = Some(Err(ChannelMonitorUpdateErr::TemporaryFailure));
	assert!(nodes[1].node.claim_funds(payment_preimage_1, &None, 1_000_000));
	check_added_monitors!(nodes[1], 1);

	let (_, payment_hash_2) = get_payment_preimage_hash!(nodes[0]);
	{
		let net_graph_msg_handler = &nodes[2].net_graph_msg_handler;
		let route = get_route(&nodes[2].node.get_our_node_id(), &net_graph_msg_handler.network_graph.read().unwrap(), &nodes[0].node.get_our_node_id(), None, &Vec::new(), 1000000, TEST_FINAL_CLTV, &logger).unwrap();
		nodes[2].node.send_payment(&route, payment_hash_2, &None).unwrap();
		check_added_monitors!(nodes[2], 1);
	}

	// Successfully update the monitor on the 1<->2 channel, but the 0<->1 channel should still be
	// paused, so forward shouldn't succeed until we call channel_monitor_updated().
	*nodes[1].chain_monitor.update_ret.lock().unwrap() = Some(Ok(()));

	let mut events = nodes[2].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let payment_event = SendEvent::from_event(events.pop().unwrap());
	nodes[1].node.handle_update_add_htlc(&nodes[2].node.get_our_node_id(), &payment_event.msgs[0]);
	let events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 0);
	nodes[1].logger.assert_log("lightning::ln::channelmanager".to_string(), "Temporary failure claiming HTLC, treating as success: Failed to update ChannelMonitor".to_string(), 1);
	commitment_signed_dance!(nodes[1], nodes[2], payment_event.commitment_msg, false, true);

	let bs_fail_update = get_htlc_update_msgs!(nodes[1], nodes[2].node.get_our_node_id());
	nodes[2].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &bs_fail_update.update_fail_htlcs[0]);
	commitment_signed_dance!(nodes[2], nodes[1], bs_fail_update.commitment_signed, false, true);

	let msg_events = nodes[2].node.get_and_clear_pending_msg_events();
	assert_eq!(msg_events.len(), 1);
	match msg_events[0] {
		MessageSendEvent::PaymentFailureNetworkUpdate { update: msgs::HTLCFailChannelUpdate::ChannelUpdateMessage { ref msg }} => {
			assert_eq!(msg.contents.short_channel_id, chan_1.0.contents.short_channel_id);
			assert_eq!(msg.contents.flags & 2, 2); // temp disabled
		},
		_ => panic!("Unexpected event"),
	}

	let events = nodes[2].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	if let Event::PaymentFailed { payment_hash, rejected_by_dest, .. } = events[0] {
		assert_eq!(payment_hash, payment_hash_2);
		assert!(!rejected_by_dest);
	} else { panic!("Unexpected event!"); }

	// Now restore monitor updating on the 0<->1 channel and claim the funds on B.
	let (outpoint, latest_update) = nodes[1].chain_monitor.latest_monitor_update_id.lock().unwrap().get(&chan_1.2).unwrap().clone();
	nodes[1].node.channel_monitor_updated(&outpoint, latest_update);
	check_added_monitors!(nodes[1], 0);

	let bs_fulfill_update = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	nodes[0].node.handle_update_fulfill_htlc(&nodes[1].node.get_our_node_id(), &bs_fulfill_update.update_fulfill_htlcs[0]);
	commitment_signed_dance!(nodes[0], nodes[1], bs_fulfill_update.commitment_signed, false);

	let events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	if let Event::PaymentSent { payment_preimage, .. } = events[0] {
		assert_eq!(payment_preimage, payment_preimage_1);
	} else { panic!("Unexpected event!"); }
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
	let logger = test_utils::TestLogger::new();

	// Rebalance a bit so that we can send backwards from 3 to 1.
	send_payment(&nodes[0], &[&nodes[1], &nodes[2]], 5000000, 5_000_000);

	let (_, payment_hash_1) = route_payment(&nodes[0], &[&nodes[1], &nodes[2]], 1000000);
	assert!(nodes[2].node.fail_htlc_backwards(&payment_hash_1, &None));
	expect_pending_htlcs_forwardable!(nodes[2]);
	check_added_monitors!(nodes[2], 1);

	let cs_fail_update = get_htlc_update_msgs!(nodes[2], nodes[1].node.get_our_node_id());
	nodes[1].node.handle_update_fail_htlc(&nodes[2].node.get_our_node_id(), &cs_fail_update.update_fail_htlcs[0]);
	commitment_signed_dance!(nodes[1], nodes[2], cs_fail_update.commitment_signed, true, true);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	let (payment_preimage_2, payment_hash_2) = get_payment_preimage_hash!(nodes[0]);
	{
		let net_graph_msg_handler = &nodes[2].net_graph_msg_handler;
		let route = get_route(&nodes[2].node.get_our_node_id(), &net_graph_msg_handler.network_graph.read().unwrap(), &nodes[0].node.get_our_node_id(), None, &Vec::new(), 1000000, TEST_FINAL_CLTV, &logger).unwrap();
		nodes[2].node.send_payment(&route, payment_hash_2, &None).unwrap();
		check_added_monitors!(nodes[2], 1);
	}

	let mut events = nodes[2].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let payment_event = SendEvent::from_event(events.pop().unwrap());
	nodes[1].node.handle_update_add_htlc(&nodes[2].node.get_our_node_id(), &payment_event.msgs[0]);
	commitment_signed_dance!(nodes[1], nodes[2], payment_event.commitment_msg, false);

	*nodes[1].chain_monitor.update_ret.lock().unwrap() = Some(Err(ChannelMonitorUpdateErr::TemporaryFailure));
	expect_pending_htlcs_forwardable!(nodes[1]);
	check_added_monitors!(nodes[1], 1);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	nodes[1].logger.assert_log("lightning::ln::channelmanager".to_string(), "Failed to update ChannelMonitor".to_string(), 1);

	*nodes[1].chain_monitor.update_ret.lock().unwrap() = Some(Ok(()));
	let (outpoint, latest_update) = nodes[1].chain_monitor.latest_monitor_update_id.lock().unwrap().get(&chan_1.2).unwrap().clone();
	nodes[1].node.channel_monitor_updated(&outpoint, latest_update);
	check_added_monitors!(nodes[1], 0);

	let bs_updates = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &bs_updates.update_fail_htlcs[0]);
	nodes[0].node.handle_update_add_htlc(&nodes[1].node.get_our_node_id(), &bs_updates.update_add_htlcs[0]);
	commitment_signed_dance!(nodes[0], nodes[1], bs_updates.commitment_signed, false, true);

	let events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 2);
	if let Event::PaymentFailed { payment_hash, rejected_by_dest, .. } = events[0] {
		assert_eq!(payment_hash, payment_hash_1);
		assert!(rejected_by_dest);
	} else { panic!("Unexpected event!"); }
	match events[1] {
		Event::PendingHTLCsForwardable { .. } => { },
		_ => panic!("Unexpected event"),
	};
	nodes[0].node.process_pending_htlc_forwards();
	expect_payment_received!(nodes[0], payment_hash_2, 1000000);

	claim_payment(&nodes[2], &[&nodes[1], &nodes[0]], payment_preimage_2, 1_000_000);
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
	let logger = test_utils::TestLogger::new();

	// Forward a payment for B to claim
	let (payment_preimage_1, _) = route_payment(&nodes[0], &[&nodes[1]], 1000000);

	// Now start forwarding a second payment, skipping the last RAA so B is in AwaitingRAA
	let (payment_preimage_2, payment_hash_2) = get_payment_preimage_hash!(nodes[0]);
	{
		let net_graph_msg_handler = &nodes[0].net_graph_msg_handler;
		let route = get_route(&nodes[0].node.get_our_node_id(), &net_graph_msg_handler.network_graph.read().unwrap(), &nodes[1].node.get_our_node_id(), None, &Vec::new(), 1000000, TEST_FINAL_CLTV, &logger).unwrap();
		nodes[0].node.send_payment(&route, payment_hash_2, &None).unwrap();
		check_added_monitors!(nodes[0], 1);
	}

	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let payment_event = SendEvent::from_event(events.pop().unwrap());
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &payment_event.msgs[0]);
	let as_raa = commitment_signed_dance!(nodes[1], nodes[0], payment_event.commitment_msg, false, true, false, true);

	*nodes[1].chain_monitor.update_ret.lock().unwrap() = Some(Err(ChannelMonitorUpdateErr::TemporaryFailure));
	assert!(nodes[1].node.claim_funds(payment_preimage_1, &None, 1_000_000));
	check_added_monitors!(nodes[1], 1);
	let events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 0);
	nodes[1].logger.assert_log("lightning::ln::channelmanager".to_string(), "Temporary failure claiming HTLC, treating as success: Failed to update ChannelMonitor".to_string(), 1);

	*nodes[1].chain_monitor.update_ret.lock().unwrap() = Some(Ok(()));
	let (outpoint, latest_update) = nodes[1].chain_monitor.latest_monitor_update_id.lock().unwrap().get(&channel_id).unwrap().clone();
	nodes[1].node.channel_monitor_updated(&outpoint, latest_update);
	check_added_monitors!(nodes[1], 0);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &as_raa);
	check_added_monitors!(nodes[1], 1);
	expect_pending_htlcs_forwardable!(nodes[1]);
	expect_payment_received!(nodes[1], payment_hash_2, 1000000);

	let bs_updates = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	nodes[0].node.handle_update_fulfill_htlc(&nodes[1].node.get_our_node_id(), &bs_updates.update_fulfill_htlcs[0]);
	commitment_signed_dance!(nodes[0], nodes[1], bs_updates.commitment_signed, false);

	let events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		Event::PaymentSent { ref payment_preimage } => {
			assert_eq!(*payment_preimage, payment_preimage_1);
		},
		_ => panic!("Unexpected event"),
	}

	claim_payment(&nodes[0], &[&nodes[1]], payment_preimage_2, 1_000_000);
}

// confirm_a_first and restore_b_before_conf are wholly unrelated to earlier bools and
// restore_b_before_conf has no meaning if !confirm_a_first
fn do_during_funding_monitor_fail(confirm_a_first: bool, restore_b_before_conf: bool) {
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

	nodes[0].node.funding_transaction_generated(&temporary_channel_id, funding_output);
	check_added_monitors!(nodes[0], 0);

	*nodes[1].chain_monitor.update_ret.lock().unwrap() = Some(Err(ChannelMonitorUpdateErr::TemporaryFailure));
	let funding_created_msg = get_event_msg!(nodes[0], MessageSendEvent::SendFundingCreated, nodes[1].node.get_our_node_id());
	let channel_id = OutPoint { txid: funding_created_msg.funding_txid, index: funding_created_msg.funding_output_index }.to_channel_id();
	nodes[1].node.handle_funding_created(&nodes[0].node.get_our_node_id(), &funding_created_msg);
	check_added_monitors!(nodes[1], 1);

	*nodes[0].chain_monitor.update_ret.lock().unwrap() = Some(Err(ChannelMonitorUpdateErr::TemporaryFailure));
	nodes[0].node.handle_funding_signed(&nodes[1].node.get_our_node_id(), &get_event_msg!(nodes[1], MessageSendEvent::SendFundingSigned, nodes[0].node.get_our_node_id()));
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	nodes[0].logger.assert_log("lightning::ln::channelmanager".to_string(), "Failed to update ChannelMonitor".to_string(), 1);
	check_added_monitors!(nodes[0], 1);
	assert!(nodes[0].node.get_and_clear_pending_events().is_empty());
	*nodes[0].chain_monitor.update_ret.lock().unwrap() = Some(Ok(()));
	let (outpoint, latest_update) = nodes[0].chain_monitor.latest_monitor_update_id.lock().unwrap().get(&channel_id).unwrap().clone();
	nodes[0].node.channel_monitor_updated(&outpoint, latest_update);
	check_added_monitors!(nodes[0], 0);

	let events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		Event::FundingBroadcastSafe { ref funding_txo, user_channel_id } => {
			assert_eq!(user_channel_id, 43);
			assert_eq!(*funding_txo, funding_output);
		},
		_ => panic!("Unexpected event"),
	};

	if confirm_a_first {
		confirm_transaction(&nodes[0], &funding_tx);
		nodes[1].node.handle_funding_locked(&nodes[0].node.get_our_node_id(), &get_event_msg!(nodes[0], MessageSendEvent::SendFundingLocked, nodes[1].node.get_our_node_id()));
	} else {
		assert!(!restore_b_before_conf);
		confirm_transaction(&nodes[1], &funding_tx);
		assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	}

	// Make sure nodes[1] isn't stupid enough to re-send the FundingLocked on reconnect
	nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id(), false);
	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);
	reconnect_nodes(&nodes[0], &nodes[1], (false, confirm_a_first), (0, 0), (0, 0), (0, 0), (0, 0), (false, false));
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	if !restore_b_before_conf {
		confirm_transaction(&nodes[1], &funding_tx);
		assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
		assert!(nodes[1].node.get_and_clear_pending_events().is_empty());
	}

	*nodes[1].chain_monitor.update_ret.lock().unwrap() = Some(Ok(()));
	let (outpoint, latest_update) = nodes[1].chain_monitor.latest_monitor_update_id.lock().unwrap().get(&channel_id).unwrap().clone();
	nodes[1].node.channel_monitor_updated(&outpoint, latest_update);
	check_added_monitors!(nodes[1], 0);

	let (channel_id, (announcement, as_update, bs_update)) = if !confirm_a_first {
		nodes[0].node.handle_funding_locked(&nodes[1].node.get_our_node_id(), &get_event_msg!(nodes[1], MessageSendEvent::SendFundingLocked, nodes[0].node.get_our_node_id()));

		confirm_transaction(&nodes[0], &funding_tx);
		let (funding_locked, channel_id) = create_chan_between_nodes_with_value_confirm_second(&nodes[1], &nodes[0]);
		(channel_id, create_chan_between_nodes_with_value_b(&nodes[0], &nodes[1], &funding_locked))
	} else {
		if restore_b_before_conf {
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

	send_payment(&nodes[0], &[&nodes[1]], 8000000, 8_000_000);
	close_channel(&nodes[0], &nodes[1], &channel_id, funding_tx, true);
}

#[test]
fn during_funding_monitor_fail() {
	do_during_funding_monitor_fail(true, true);
	do_during_funding_monitor_fail(true, false);
	do_during_funding_monitor_fail(false, false);
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
	let logger = test_utils::TestLogger::new();

	let (payment_preimage, payment_hash) = get_payment_preimage_hash!(&nodes[0]);
	let payment_secret = PaymentSecret([0xdb; 32]);
	let mut route = get_route(&nodes[0].node.get_our_node_id(), &nodes[0].net_graph_msg_handler.network_graph.read().unwrap(), &nodes[3].node.get_our_node_id(), None, &[], 100000, TEST_FINAL_CLTV, &logger).unwrap();

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
	*nodes[0].chain_monitor.update_ret.lock().unwrap() = Some(Ok(()));
	*nodes[0].chain_monitor.next_update_ret.lock().unwrap() = Some(Err(ChannelMonitorUpdateErr::TemporaryFailure));

	// Now check that we get the right return value, indicating that the first path succeeded but
	// the second got a MonitorUpdateFailed err. This implies PaymentSendFailure::PartialFailure as
	// some paths succeeded, preventing retry.
	if let Err(PaymentSendFailure::PartialFailure(results)) = nodes[0].node.send_payment(&route, payment_hash, &Some(payment_secret)) {
		assert_eq!(results.len(), 2);
		if let Ok(()) = results[0] {} else { panic!(); }
		if let Err(APIError::MonitorUpdateFailed) = results[1] {} else { panic!(); }
	} else { panic!(); }
	check_added_monitors!(nodes[0], 2);
	*nodes[0].chain_monitor.update_ret.lock().unwrap() = Some(Ok(()));

	// Pass the first HTLC of the payment along to nodes[3].
	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	pass_along_path(&nodes[0], &[&nodes[1], &nodes[3]], 0, payment_hash.clone(), Some(payment_secret), events.pop().unwrap(), false);

	// And check that, after we successfully update the monitor for chan_2 we can pass the second
	// HTLC along to nodes[3] and claim the whole payment back to nodes[0].
	let (outpoint, latest_update) = nodes[0].chain_monitor.latest_monitor_update_id.lock().unwrap().get(&chan_2_id).unwrap().clone();
	nodes[0].node.channel_monitor_updated(&outpoint, latest_update);
	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	pass_along_path(&nodes[0], &[&nodes[2], &nodes[3]], 200_000, payment_hash.clone(), Some(payment_secret), events.pop().unwrap(), true);

	claim_payment_along_route_with_secret(&nodes[0], &[&[&nodes[1], &nodes[3]], &[&nodes[2], &nodes[3]]], false, payment_preimage, Some(payment_secret), 200_000);
}
