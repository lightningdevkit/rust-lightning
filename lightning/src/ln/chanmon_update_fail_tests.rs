// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Functional tests which test the correct handling of ChannelMonitorUpdateStatus returns from
//! monitor updates.
//! There are a bunch of these as their handling is relatively error-prone so they are split out
//! here. See also the chanmon_fail_consistency fuzz test.

use crate::chain::chaininterface::LowerBoundedFeeEstimator;
use crate::chain::chainmonitor::ChainMonitor;
use crate::chain::channelmonitor::{ChannelMonitor, MonitorEvent, ANTI_REORG_DELAY};
use crate::chain::transaction::OutPoint;
use crate::chain::{ChannelMonitorUpdateStatus, Listen, Watch};
use crate::events::{ClosureReason, Event, HTLCHandlingFailureType, PaymentPurpose};
use crate::ln::channel::AnnouncementSigsState;
use crate::ln::channelmanager::{PaymentId, RAACommitmentOrder, RecipientOnionFields, Retry};
use crate::ln::msgs;
use crate::ln::msgs::{
	BaseMessageHandler, ChannelMessageHandler, MessageSendEvent, RoutingMessageHandler,
};
use crate::ln::types::ChannelId;
use crate::routing::router::{PaymentParameters, RouteParameters};
use crate::sign::NodeSigner;
use crate::util::native_async::FutureQueue;
use crate::util::persist::{
	MonitorName, MonitorUpdatingPersisterAsync, CHANNEL_MONITOR_PERSISTENCE_PRIMARY_NAMESPACE,
	CHANNEL_MONITOR_PERSISTENCE_SECONDARY_NAMESPACE,
	CHANNEL_MONITOR_UPDATE_PERSISTENCE_PRIMARY_NAMESPACE,
};
use crate::util::ser::{ReadableArgs, Writeable};
use crate::util::test_channel_signer::TestChannelSigner;
use crate::util::test_utils::TestBroadcaster;
use bitcoin::constants::genesis_block;
use bitcoin::hash_types::BlockHash;
use bitcoin::network::Network;

use crate::ln::functional_test_utils::*;

use crate::util::test_utils;

use crate::prelude::*;
use crate::sync::{Arc, Mutex};
use bitcoin::hashes::Hash;

fn get_latest_mon_update_id<'a, 'b, 'c>(
	node: &Node<'a, 'b, 'c>, channel_id: ChannelId,
) -> (u64, u64) {
	let monitor_id_state = node.chain_monitor.latest_monitor_update_id.lock().unwrap();
	monitor_id_state.get(&channel_id).unwrap().clone()
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

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	// Create some initial channel
	let chan = create_announced_chan_between_nodes(&nodes, 0, 1);

	// Rebalance the network to generate htlc in the two directions
	send_payment(&nodes[0], &[&nodes[1]], 10_000_000);

	// Route an HTLC from node 0 to node 1 (but don't settle)
	let (preimage, payment_hash, ..) = route_payment(&nodes[0], &[&nodes[1]], 9_000_000);

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
		blocks: Arc::new(Mutex::new(vec![(genesis_block(Network::Testnet), 200); 200])),
	};
	let chain_mon = {
		let new_monitor = {
			let monitor = nodes[0].chain_monitor.chain_monitor.get_monitor(chan.2).unwrap();
			let (_, new_monitor) = <(BlockHash, ChannelMonitor<TestChannelSigner>)>::read(
				&mut &monitor.encode()[..],
				(nodes[0].keys_manager, nodes[0].keys_manager),
			)
			.unwrap();
			assert!(new_monitor == *monitor);
			new_monitor
		};
		let chain_mon = test_utils::TestChainMonitor::new(
			Some(&chain_source),
			&tx_broadcaster,
			&logger,
			&chanmon_cfgs[0].fee_estimator,
			&persister,
			&node_cfgs[0].keys_manager,
		);
		assert_eq!(
			chain_mon.watch_channel(chan.2, new_monitor),
			Ok(ChannelMonitorUpdateStatus::Completed)
		);
		chain_mon
	};
	chain_mon
		.chain_monitor
		.block_connected(&create_dummy_block(BlockHash::all_zeros(), 42, Vec::new()), 200);

	// Try to update ChannelMonitor
	nodes[1].node.claim_funds(preimage);
	expect_payment_claimed!(nodes[1], payment_hash, 9_000_000);
	check_added_monitors(&nodes[1], 1);

	let mut updates = get_htlc_update_msgs(&nodes[1], &node_a_id);
	assert_eq!(updates.update_fulfill_htlcs.len(), 1);
	nodes[0].node.handle_update_fulfill_htlc(node_b_id, updates.update_fulfill_htlcs.remove(0));

	{
		let mut per_peer_lock;
		let mut peer_state_lock;
		let chan_opt = get_channel_ref!(nodes[0], nodes[1], per_peer_lock, peer_state_lock, chan.2);
		if let Some(channel) = chan_opt.as_funded_mut() {
			assert_eq!(updates.commitment_signed.len(), 1);
			let feeest = LowerBoundedFeeEstimator::new(&chanmon_cfgs[0].fee_estimator);
			if let Ok(Some(update)) = channel.commitment_signed(
				&updates.commitment_signed[0],
				&feeest,
				&node_cfgs[0].logger,
			) {
				// Check that the persister returns InProgress (and will never actually complete)
				// as the monitor update errors.
				if let ChannelMonitorUpdateStatus::InProgress =
					chain_mon.chain_monitor.update_channel(chan.2, &update)
				{
				} else {
					panic!("Expected monitor paused");
				}
				logger.assert_log_regex(
					"lightning::chain::chainmonitor",
					regex::Regex::new("Failed to update ChannelMonitor").unwrap(),
					1,
				);

				// Apply the monitor update to the original ChainMonitor, ensuring the
				// ChannelManager and ChannelMonitor aren't out of sync.
				assert_eq!(
					nodes[0].chain_monitor.update_channel(chan.2, &update),
					ChannelMonitorUpdateStatus::Completed
				);
			} else {
				assert!(false);
			}
		} else {
			assert!(false);
		}
	}

	check_added_monitors(&nodes[0], 1);
	expect_payment_sent(&nodes[0], preimage, None, false, false);
}

fn do_test_simple_monitor_temporary_update_fail(disconnect: bool) {
	// Test that we can recover from a simple temporary monitor update failure optionally with
	// a disconnect in between
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	let channel_id = create_announced_chan_between_nodes(&nodes, 0, 1).2;
	let user_channel_id = nodes[1].node.list_channels()[0].user_channel_id;

	let (route, payment_hash_1, payment_preimage_1, payment_secret_1) =
		get_route_and_payment_hash!(&nodes[0], nodes[1], 1000000);

	chanmon_cfgs[0].persister.set_update_ret(ChannelMonitorUpdateStatus::InProgress);

	let onion = RecipientOnionFields::secret_only(payment_secret_1);
	let id = PaymentId(payment_hash_1.0);
	nodes[0].node.send_payment_with_route(route, payment_hash_1, onion, id).unwrap();
	check_added_monitors(&nodes[0], 1);

	assert!(nodes[0].node.get_and_clear_pending_events().is_empty());
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	assert_eq!(nodes[0].node.list_channels().len(), 1);

	if disconnect {
		nodes[0].node.peer_disconnected(node_b_id);
		nodes[1].node.peer_disconnected(node_a_id);
		let mut reconnect_args = ReconnectArgs::new(&nodes[0], &nodes[1]);
		reconnect_args.send_channel_ready = (true, true);
		reconnect_args.send_announcement_sigs = (true, true);
		reconnect_nodes(reconnect_args);
	}

	chanmon_cfgs[0].persister.set_update_ret(ChannelMonitorUpdateStatus::Completed);
	let (latest_update, _) = get_latest_mon_update_id(&nodes[0], channel_id);
	nodes[0].chain_monitor.chain_monitor.force_channel_monitor_updated(channel_id, latest_update);
	check_added_monitors(&nodes[0], 0);

	let mut events_2 = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events_2.len(), 1);
	let payment_event = SendEvent::from_event(events_2.pop().unwrap());
	assert_eq!(payment_event.node_id, node_b_id);
	nodes[1].node.handle_update_add_htlc(node_a_id, &payment_event.msgs[0]);
	do_commitment_signed_dance(&nodes[1], &nodes[0], &payment_event.commitment_msg, false, false);

	expect_and_process_pending_htlcs(&nodes[1], false);

	let events_3 = nodes[1].node.get_and_clear_pending_events();
	assert_eq!(events_3.len(), 1);
	match events_3[0] {
		Event::PaymentClaimable {
			ref payment_hash,
			ref purpose,
			amount_msat,
			receiver_node_id,
			ref receiving_channel_ids,
			..
		} => {
			assert_eq!(payment_hash_1, *payment_hash);
			assert_eq!(amount_msat, 1_000_000);
			assert_eq!(receiver_node_id.unwrap(), node_b_id);
			assert_eq!(*receiving_channel_ids, &[(channel_id, Some(user_channel_id))]);
			match &purpose {
				PaymentPurpose::Bolt11InvoicePayment {
					payment_preimage, payment_secret, ..
				} => {
					assert!(payment_preimage.is_none());
					assert_eq!(payment_secret_1, *payment_secret);
				},
				_ => panic!("expected PaymentPurpose::Bolt11InvoicePayment"),
			}
		},
		_ => panic!("Unexpected event"),
	}

	claim_payment(&nodes[0], &[&nodes[1]], payment_preimage_1);

	// Now set it to failed again...
	let (route, payment_hash_2, _, payment_secret_2) =
		get_route_and_payment_hash!(&nodes[0], nodes[1], 1000000);
	chanmon_cfgs[0].persister.set_update_ret(ChannelMonitorUpdateStatus::InProgress);

	let onion = RecipientOnionFields::secret_only(payment_secret_2);
	let id = PaymentId(payment_hash_2.0);
	nodes[0].node.send_payment_with_route(route, payment_hash_2, onion, id).unwrap();
	check_added_monitors(&nodes[0], 1);

	assert!(nodes[0].node.get_and_clear_pending_events().is_empty());
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	assert_eq!(nodes[0].node.list_channels().len(), 1);

	if disconnect {
		nodes[0].node.peer_disconnected(node_b_id);
		nodes[1].node.peer_disconnected(node_a_id);
		reconnect_nodes(ReconnectArgs::new(&nodes[0], &nodes[1]));
	}

	// ...and make sure we can force-close a frozen channel
	let message = "Channel force-closed".to_owned();
	let reason = ClosureReason::HolderForceClosed {
		broadcasted_latest_txn: Some(true),
		message: message.clone(),
	};
	nodes[0].node.force_close_broadcasting_latest_txn(&channel_id, &node_b_id, message).unwrap();
	check_added_monitors(&nodes[0], 1);
	check_closed_broadcast!(nodes[0], true);

	// TODO: Once we hit the chain with the failure transaction we should check that we get a
	// PaymentPathFailed event

	assert_eq!(nodes[0].node.list_channels().len(), 0);
	check_closed_event(&nodes[0], 1, reason, &[node_b_id], 100000);
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
	//   InProgress likely indicates net disconnect which resulted in failing to update the
	//   ChannelMonitor on a watchtower).
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

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	let channel_id = create_announced_chan_between_nodes(&nodes, 0, 1).2;
	let user_channel_id = nodes[1].node.list_channels()[0].user_channel_id;

	let (payment_preimage_1, payment_hash_1, ..) =
		route_payment(&nodes[0], &[&nodes[1]], 1_000_000);

	// Now try to send a second payment which will fail to send
	let (route, payment_hash_2, payment_preimage_2, payment_secret_2) =
		get_route_and_payment_hash!(nodes[0], nodes[1], 1000000);
	chanmon_cfgs[0].persister.set_update_ret(ChannelMonitorUpdateStatus::InProgress);
	let onion = RecipientOnionFields::secret_only(payment_secret_2);
	let id = PaymentId(payment_hash_2.0);
	nodes[0].node.send_payment_with_route(route, payment_hash_2, onion, id).unwrap();
	check_added_monitors(&nodes[0], 1);

	assert!(nodes[0].node.get_and_clear_pending_events().is_empty());
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	assert_eq!(nodes[0].node.list_channels().len(), 1);

	// Claim the previous payment, which will result in a update_fulfill_htlc/CS from nodes[1]
	// but nodes[0] won't respond since it is frozen.
	nodes[1].node.claim_funds(payment_preimage_1);
	check_added_monitors(&nodes[1], 1);
	expect_payment_claimed!(nodes[1], payment_hash_1, 1_000_000);

	let events_2 = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(events_2.len(), 1);
	let (bs_initial_fulfill, bs_initial_commitment_signed) = match events_2[0] {
		MessageSendEvent::UpdateHTLCs {
			ref node_id,
			channel_id: _,
			updates:
				msgs::CommitmentUpdate {
					ref update_add_htlcs,
					ref update_fulfill_htlcs,
					ref update_fail_htlcs,
					ref update_fail_malformed_htlcs,
					ref update_fee,
					ref commitment_signed,
				},
		} => {
			assert_eq!(*node_id, node_a_id);
			assert!(update_add_htlcs.is_empty());
			assert_eq!(update_fulfill_htlcs.len(), 1);
			assert!(update_fail_htlcs.is_empty());
			assert!(update_fail_malformed_htlcs.is_empty());
			assert!(update_fee.is_none());

			if (disconnect_count & 16) == 0 {
				let fulfill_msg = update_fulfill_htlcs[0].clone();
				nodes[0].node.handle_update_fulfill_htlc(node_b_id, fulfill_msg);
				let events_3 = nodes[0].node.get_and_clear_pending_events();
				assert_eq!(events_3.len(), 1);
				match events_3[0] {
					Event::PaymentSent { ref payment_preimage, ref payment_hash, .. } => {
						assert_eq!(*payment_preimage, payment_preimage_1);
						assert_eq!(*payment_hash, payment_hash_1);
					},
					_ => panic!("Unexpected event"),
				}

				nodes[0].node.handle_commitment_signed_batch_test(node_b_id, commitment_signed);
				check_added_monitors(&nodes[0], 1);
				assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
			}

			(update_fulfill_htlcs[0].clone(), commitment_signed.clone())
		},
		_ => panic!("Unexpected event"),
	};

	if disconnect_count & !disconnect_flags > 0 {
		nodes[0].node.peer_disconnected(node_b_id);
		nodes[1].node.peer_disconnected(node_a_id);
	}

	// Now fix monitor updating...
	chanmon_cfgs[0].persister.set_update_ret(ChannelMonitorUpdateStatus::Completed);
	let (latest_update, _) = get_latest_mon_update_id(&nodes[0], channel_id);
	nodes[0].chain_monitor.chain_monitor.force_channel_monitor_updated(channel_id, latest_update);
	check_added_monitors(&nodes[0], 0);

	macro_rules! disconnect_reconnect_peers {
		() => {{
			nodes[0].node.peer_disconnected(node_b_id);
			nodes[1].node.peer_disconnected(node_a_id);

			let init_msg = msgs::Init {
				features: nodes[1].node.init_features(),
				networks: None,
				remote_network_address: None,
			};

			nodes[0].node.peer_connected(node_b_id, &init_msg, true).unwrap();
			let reestablish_1 = get_chan_reestablish_msgs!(nodes[0], nodes[1]);
			assert_eq!(reestablish_1.len(), 1);
			nodes[1].node.peer_connected(node_a_id, &init_msg, false).unwrap();
			let reestablish_2 = get_chan_reestablish_msgs!(nodes[1], nodes[0]);
			assert_eq!(reestablish_2.len(), 1);

			nodes[0].node.handle_channel_reestablish(node_b_id, &reestablish_2[0]);
			let as_resp = handle_chan_reestablish_msgs!(nodes[0], nodes[1]);
			nodes[1].node.handle_channel_reestablish(node_a_id, &reestablish_1[0]);
			let bs_resp = handle_chan_reestablish_msgs!(nodes[1], nodes[0]);

			assert!(as_resp.0.is_none());
			assert!(bs_resp.0.is_none());

			(reestablish_1, reestablish_2, as_resp, bs_resp)
		}};
	}

	let (payment_event, initial_revoke_and_ack) = if disconnect_count & !disconnect_flags > 0 {
		assert!(nodes[0].node.get_and_clear_pending_events().is_empty());
		assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());

		let init_msg = msgs::Init {
			features: nodes[1].node.init_features(),
			networks: None,
			remote_network_address: None,
		};
		nodes[0].node.peer_connected(node_b_id, &init_msg, true).unwrap();
		let reestablish_1 = get_chan_reestablish_msgs!(nodes[0], nodes[1]);
		assert_eq!(reestablish_1.len(), 1);
		nodes[1].node.peer_connected(node_a_id, &init_msg, false).unwrap();
		let reestablish_2 = get_chan_reestablish_msgs!(nodes[1], nodes[0]);
		assert_eq!(reestablish_2.len(), 1);

		nodes[0].node.handle_channel_reestablish(node_b_id, &reestablish_2[0]);
		check_added_monitors(&nodes[0], 0);
		let mut as_resp = handle_chan_reestablish_msgs!(nodes[0], nodes[1]);
		nodes[1].node.handle_channel_reestablish(node_a_id, &reestablish_1[0]);
		check_added_monitors(&nodes[1], 0);
		let mut bs_resp = handle_chan_reestablish_msgs!(nodes[1], nodes[0]);

		assert!(as_resp.0.is_none());
		assert!(bs_resp.0.is_none());

		assert!(bs_resp.1.is_none());
		if (disconnect_count & 16) == 0 {
			assert!(bs_resp.2.is_none());

			assert!(as_resp.1.is_some());
			assert!(as_resp.2.is_some());
			assert_eq!(as_resp.3, RAACommitmentOrder::CommitmentFirst);
		} else {
			assert!(bs_resp.2.as_ref().unwrap().update_add_htlcs.is_empty());
			assert!(bs_resp.2.as_ref().unwrap().update_fail_htlcs.is_empty());
			assert!(bs_resp.2.as_ref().unwrap().update_fail_malformed_htlcs.is_empty());
			assert!(bs_resp.2.as_ref().unwrap().update_fee.is_none());
			assert_eq!(bs_resp.2.as_ref().unwrap().update_fulfill_htlcs, [bs_initial_fulfill]);
			assert_eq!(bs_resp.2.as_ref().unwrap().commitment_signed, bs_initial_commitment_signed);

			assert!(as_resp.1.is_none());

			nodes[0].node.handle_update_fulfill_htlc(
				node_b_id,
				bs_resp.2.as_ref().unwrap().update_fulfill_htlcs[0].clone(),
			);
			let events_3 = nodes[0].node.get_and_clear_pending_events();
			assert_eq!(events_3.len(), 1);
			match events_3[0] {
				Event::PaymentSent { ref payment_preimage, ref payment_hash, .. } => {
					assert_eq!(*payment_preimage, payment_preimage_1);
					assert_eq!(*payment_hash, payment_hash_1);
				},
				_ => panic!("Unexpected event"),
			}

			nodes[0].node.handle_commitment_signed_batch_test(
				node_b_id,
				&bs_resp.2.as_ref().unwrap().commitment_signed,
			);
			let as_resp_raa =
				get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, node_b_id);
			// No commitment_signed so get_event_msg's assert(len == 1) passes
			check_added_monitors(&nodes[0], 1);

			as_resp.1 = Some(as_resp_raa);
			bs_resp.2 = None;
		}

		if disconnect_count & !disconnect_flags > 1 {
			let (second_reestablish_1, second_reestablish_2, second_as_resp, second_bs_resp) =
				disconnect_reconnect_peers!();

			if (disconnect_count & 16) == 0 {
				assert_eq!(reestablish_1, second_reestablish_1);
				assert_eq!(reestablish_2, second_reestablish_2);
			}
			assert_eq!(as_resp, second_as_resp);
			assert_eq!(bs_resp, second_bs_resp);
		}

		(
			SendEvent::from_commitment_update(node_b_id, channel_id, as_resp.2.unwrap()),
			as_resp.1.unwrap(),
		)
	} else {
		let mut events_4 = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(events_4.len(), 2);
		(
			SendEvent::from_event(events_4.remove(0)),
			match events_4[0] {
				MessageSendEvent::SendRevokeAndACK { ref node_id, ref msg } => {
					assert_eq!(*node_id, node_b_id);
					msg.clone()
				},
				_ => panic!("Unexpected event"),
			},
		)
	};

	assert_eq!(payment_event.node_id, node_b_id);

	nodes[1].node.handle_update_add_htlc(node_a_id, &payment_event.msgs[0]);
	nodes[1].node.handle_commitment_signed_batch_test(node_a_id, &payment_event.commitment_msg);
	let bs_revoke_and_ack = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, node_a_id);
	// nodes[1] is awaiting an RAA from nodes[0] still so get_event_msg's assert(len == 1) passes
	check_added_monitors(&nodes[1], 1);

	if disconnect_count & !disconnect_flags > 2 {
		let (_, _, as_resp, bs_resp) = disconnect_reconnect_peers!();

		assert_eq!(as_resp.1.unwrap(), initial_revoke_and_ack);
		assert_eq!(bs_resp.1.unwrap(), bs_revoke_and_ack);

		assert!(as_resp.2.is_none());
		assert!(bs_resp.2.is_none());
	}

	let as_commitment_update;
	let bs_second_commitment_update;

	macro_rules! handle_bs_raa {
		() => {
			nodes[0].node.handle_revoke_and_ack(node_b_id, &bs_revoke_and_ack);
			as_commitment_update = get_htlc_update_msgs(&nodes[0], &node_b_id);
			assert!(as_commitment_update.update_add_htlcs.is_empty());
			assert!(as_commitment_update.update_fulfill_htlcs.is_empty());
			assert!(as_commitment_update.update_fail_htlcs.is_empty());
			assert!(as_commitment_update.update_fail_malformed_htlcs.is_empty());
			assert!(as_commitment_update.update_fee.is_none());
			check_added_monitors(&nodes[0], 1);
		};
	}

	macro_rules! handle_initial_raa {
		() => {
			nodes[1].node.handle_revoke_and_ack(node_a_id, &initial_revoke_and_ack);
			bs_second_commitment_update = get_htlc_update_msgs(&nodes[1], &node_a_id);
			assert!(bs_second_commitment_update.update_add_htlcs.is_empty());
			assert!(bs_second_commitment_update.update_fulfill_htlcs.is_empty());
			assert!(bs_second_commitment_update.update_fail_htlcs.is_empty());
			assert!(bs_second_commitment_update.update_fail_malformed_htlcs.is_empty());
			assert!(bs_second_commitment_update.update_fee.is_none());
			check_added_monitors(&nodes[1], 1);
		};
	}

	if (disconnect_count & 8) == 0 {
		handle_bs_raa!();

		if disconnect_count & !disconnect_flags > 3 {
			let (_, _, as_resp, bs_resp) = disconnect_reconnect_peers!();

			assert_eq!(as_resp.1.unwrap(), initial_revoke_and_ack);
			assert!(bs_resp.1.is_none());

			assert_eq!(as_resp.2.unwrap(), as_commitment_update);
			assert!(bs_resp.2.is_none());

			assert_eq!(as_resp.3, RAACommitmentOrder::RevokeAndACKFirst);
		}

		handle_initial_raa!();

		if disconnect_count & !disconnect_flags > 4 {
			let (_, _, as_resp, bs_resp) = disconnect_reconnect_peers!();

			assert!(as_resp.1.is_none());
			assert!(bs_resp.1.is_none());

			assert_eq!(as_resp.2.unwrap(), as_commitment_update);
			assert_eq!(bs_resp.2.unwrap(), bs_second_commitment_update);
		}
	} else {
		handle_initial_raa!();

		if disconnect_count & !disconnect_flags > 3 {
			let (_, _, as_resp, bs_resp) = disconnect_reconnect_peers!();

			assert!(as_resp.1.is_none());
			assert_eq!(bs_resp.1.unwrap(), bs_revoke_and_ack);

			assert!(as_resp.2.is_none());
			assert_eq!(bs_resp.2.unwrap(), bs_second_commitment_update);

			assert_eq!(bs_resp.3, RAACommitmentOrder::RevokeAndACKFirst);
		}

		handle_bs_raa!();

		if disconnect_count & !disconnect_flags > 4 {
			let (_, _, as_resp, bs_resp) = disconnect_reconnect_peers!();

			assert!(as_resp.1.is_none());
			assert!(bs_resp.1.is_none());

			assert_eq!(as_resp.2.unwrap(), as_commitment_update);
			assert_eq!(bs_resp.2.unwrap(), bs_second_commitment_update);
		}
	}

	nodes[0].node.handle_commitment_signed_batch_test(
		node_b_id,
		&bs_second_commitment_update.commitment_signed,
	);
	let as_revoke_and_ack = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, node_b_id);
	// No commitment_signed so get_event_msg's assert(len == 1) passes
	check_added_monitors(&nodes[0], 1);

	nodes[1]
		.node
		.handle_commitment_signed_batch_test(node_a_id, &as_commitment_update.commitment_signed);
	let bs_second_revoke_and_ack =
		get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, node_a_id);
	// No commitment_signed so get_event_msg's assert(len == 1) passes
	check_added_monitors(&nodes[1], 1);

	nodes[1].node.handle_revoke_and_ack(node_a_id, &as_revoke_and_ack);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	check_added_monitors(&nodes[1], 1);

	nodes[0].node.handle_revoke_and_ack(node_b_id, &bs_second_revoke_and_ack);
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	check_added_monitors(&nodes[0], 1);
	expect_payment_path_successful!(nodes[0]);

	expect_and_process_pending_htlcs(&nodes[1], false);

	let events_5 = nodes[1].node.get_and_clear_pending_events();
	assert_eq!(events_5.len(), 1);
	match events_5[0] {
		Event::PaymentClaimable {
			ref payment_hash,
			ref purpose,
			amount_msat,
			receiver_node_id,
			ref receiving_channel_ids,
			..
		} => {
			assert_eq!(payment_hash_2, *payment_hash);
			assert_eq!(amount_msat, 1_000_000);
			assert_eq!(receiver_node_id.unwrap(), node_b_id);
			assert_eq!(*receiving_channel_ids, [(channel_id, Some(user_channel_id))]);
			match &purpose {
				PaymentPurpose::Bolt11InvoicePayment {
					payment_preimage, payment_secret, ..
				} => {
					assert!(payment_preimage.is_none());
					assert_eq!(payment_secret_2, *payment_secret);
				},
				_ => panic!("expected PaymentPurpose::Bolt11InvoicePayment"),
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

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	let channel_id = create_announced_chan_between_nodes(&nodes, 0, 1).2;
	let user_channel_id = nodes[1].node.list_channels()[0].user_channel_id;

	let (route, our_payment_hash, payment_preimage, our_payment_secret) =
		get_route_and_payment_hash!(nodes[0], nodes[1], 1000000);
	let onion = RecipientOnionFields::secret_only(our_payment_secret);
	let id = PaymentId(our_payment_hash.0);
	nodes[0].node.send_payment_with_route(route, our_payment_hash, onion, id).unwrap();
	check_added_monitors(&nodes[0], 1);

	let send_event =
		SendEvent::from_event(nodes[0].node.get_and_clear_pending_msg_events().remove(0));
	nodes[1].node.handle_update_add_htlc(node_a_id, &send_event.msgs[0]);

	chanmon_cfgs[1].persister.set_update_ret(ChannelMonitorUpdateStatus::InProgress);
	nodes[1].node.handle_commitment_signed_batch_test(node_a_id, &send_event.commitment_msg);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	check_added_monitors(&nodes[1], 1);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	chanmon_cfgs[1].persister.set_update_ret(ChannelMonitorUpdateStatus::Completed);
	let (latest_update, _) = get_latest_mon_update_id(&nodes[1], channel_id);
	nodes[1].chain_monitor.chain_monitor.force_channel_monitor_updated(channel_id, latest_update);
	check_added_monitors(&nodes[1], 0);
	let responses = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(responses.len(), 2);

	match responses[0] {
		MessageSendEvent::SendRevokeAndACK { ref msg, ref node_id } => {
			assert_eq!(*node_id, node_a_id);
			nodes[0].node.handle_revoke_and_ack(node_b_id, &msg);
			check_added_monitors(&nodes[0], 1);
		},
		_ => panic!("Unexpected event"),
	}
	match responses[1] {
		MessageSendEvent::UpdateHTLCs { ref updates, ref node_id, channel_id: _ } => {
			assert!(updates.update_add_htlcs.is_empty());
			assert!(updates.update_fulfill_htlcs.is_empty());
			assert!(updates.update_fail_htlcs.is_empty());
			assert!(updates.update_fail_malformed_htlcs.is_empty());
			assert!(updates.update_fee.is_none());
			assert_eq!(*node_id, node_a_id);

			chanmon_cfgs[0].persister.set_update_ret(ChannelMonitorUpdateStatus::InProgress);
			nodes[0]
				.node
				.handle_commitment_signed_batch_test(node_b_id, &updates.commitment_signed);
			assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
			check_added_monitors(&nodes[0], 1);
			assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
		},
		_ => panic!("Unexpected event"),
	}

	chanmon_cfgs[0].persister.set_update_ret(ChannelMonitorUpdateStatus::Completed);
	let (latest_update, _) = get_latest_mon_update_id(&nodes[0], channel_id);
	nodes[0].chain_monitor.chain_monitor.force_channel_monitor_updated(channel_id, latest_update);
	check_added_monitors(&nodes[0], 0);

	let final_raa = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, node_b_id);
	nodes[1].node.handle_revoke_and_ack(node_a_id, &final_raa);
	check_added_monitors(&nodes[1], 1);

	expect_and_process_pending_htlcs(&nodes[1], false);

	let events = nodes[1].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		Event::PaymentClaimable {
			payment_hash,
			ref purpose,
			amount_msat,
			receiver_node_id,
			ref receiving_channel_ids,
			..
		} => {
			assert_eq!(payment_hash, our_payment_hash);
			assert_eq!(amount_msat, 1_000_000);
			assert_eq!(receiver_node_id.unwrap(), node_b_id);
			assert_eq!(*receiving_channel_ids, [(channel_id, Some(user_channel_id))]);
			match &purpose {
				PaymentPurpose::Bolt11InvoicePayment {
					payment_preimage, payment_secret, ..
				} => {
					assert!(payment_preimage.is_none());
					assert_eq!(our_payment_secret, *payment_secret);
				},
				_ => panic!("expected PaymentPurpose::Bolt11InvoicePayment"),
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

	let node_a_id = nodes[0].node.get_our_node_id();

	let channel_id = create_announced_chan_between_nodes(&nodes, 0, 1).2;

	let (route, our_payment_hash, payment_preimage_1, payment_secret_1) =
		get_route_and_payment_hash!(nodes[0], nodes[1], 1000000);
	let onion = RecipientOnionFields::secret_only(payment_secret_1);
	let id = PaymentId(our_payment_hash.0);
	nodes[0].node.send_payment_with_route(route, our_payment_hash, onion, id).unwrap();
	check_added_monitors(&nodes[0], 1);

	let send_event =
		SendEvent::from_event(nodes[0].node.get_and_clear_pending_msg_events().remove(0));
	nodes[1].node.handle_update_add_htlc(node_a_id, &send_event.msgs[0]);
	let commitment = send_event.commitment_msg;
	let bs_raa = commitment_signed_dance_return_raa(&nodes[1], &nodes[0], &commitment, false);

	chanmon_cfgs[1].persister.set_update_ret(ChannelMonitorUpdateStatus::InProgress);
	nodes[1].node.handle_revoke_and_ack(node_a_id, &bs_raa);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	assert!(nodes[1].node.get_and_clear_pending_events().is_empty());
	check_added_monitors(&nodes[1], 1);

	chanmon_cfgs[1].persister.set_update_ret(ChannelMonitorUpdateStatus::Completed);
	let (latest_update, _) = get_latest_mon_update_id(&nodes[1], channel_id);
	nodes[1].chain_monitor.chain_monitor.force_channel_monitor_updated(channel_id, latest_update);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	check_added_monitors(&nodes[1], 0);
	expect_and_process_pending_htlcs(&nodes[1], false);

	let events = nodes[1].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		Event::PaymentClaimable { payment_hash, .. } => {
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

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	let channel_id = create_announced_chan_between_nodes(&nodes, 0, 1).2;

	send_payment(&nodes[0], &[&nodes[1]], 5000000);
	let (route, our_payment_hash_1, payment_preimage_1, our_payment_secret_1) =
		get_route_and_payment_hash!(nodes[0], nodes[1], 1000000);
	let onion = RecipientOnionFields::secret_only(our_payment_secret_1);
	let id = PaymentId(our_payment_hash_1.0);
	nodes[0].node.send_payment_with_route(route, our_payment_hash_1, onion, id).unwrap();

	check_added_monitors(&nodes[0], 1);
	let send_event_1 =
		SendEvent::from_event(nodes[0].node.get_and_clear_pending_msg_events().remove(0));

	let (route, our_payment_hash_2, payment_preimage_2, our_payment_secret_2) =
		get_route_and_payment_hash!(nodes[1], nodes[0], 1000000);
	let onion_2 = RecipientOnionFields::secret_only(our_payment_secret_2);
	let id_2 = PaymentId(our_payment_hash_2.0);
	nodes[1].node.send_payment_with_route(route, our_payment_hash_2, onion_2, id_2).unwrap();

	check_added_monitors(&nodes[1], 1);
	let send_event_2 =
		SendEvent::from_event(nodes[1].node.get_and_clear_pending_msg_events().remove(0));

	nodes[1].node.handle_update_add_htlc(node_a_id, &send_event_1.msgs[0]);
	nodes[1].node.handle_commitment_signed_batch_test(node_a_id, &send_event_1.commitment_msg);
	check_added_monitors(&nodes[1], 1);
	let bs_raa = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, node_a_id);

	chanmon_cfgs[0].persister.set_update_ret(ChannelMonitorUpdateStatus::InProgress);
	chanmon_cfgs[0].persister.set_update_ret(ChannelMonitorUpdateStatus::InProgress);
	nodes[0].node.handle_update_add_htlc(node_b_id, &send_event_2.msgs[0]);
	nodes[0].node.handle_commitment_signed_batch_test(node_b_id, &send_event_2.commitment_msg);
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	check_added_monitors(&nodes[0], 1);
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());

	nodes[0].node.handle_revoke_and_ack(node_b_id, &bs_raa);
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	check_added_monitors(&nodes[0], 1);

	let (latest_update, _) = get_latest_mon_update_id(&nodes[0], channel_id);
	nodes[0].chain_monitor.chain_monitor.force_channel_monitor_updated(channel_id, latest_update);
	check_added_monitors(&nodes[0], 0);

	let as_update_raa = get_revoke_commit_msgs(&nodes[0], &node_b_id);
	nodes[1].node.handle_revoke_and_ack(node_a_id, &as_update_raa.0);
	check_added_monitors(&nodes[1], 1);
	let bs_cs = get_htlc_update_msgs(&nodes[1], &node_a_id);

	nodes[1].node.handle_commitment_signed_batch_test(node_a_id, &as_update_raa.1);
	check_added_monitors(&nodes[1], 1);
	let bs_second_raa = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, node_a_id);

	nodes[0].node.handle_commitment_signed_batch_test(node_b_id, &bs_cs.commitment_signed);
	check_added_monitors(&nodes[0], 1);
	let as_second_raa = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, node_b_id);

	nodes[0].node.handle_revoke_and_ack(node_b_id, &bs_second_raa);
	check_added_monitors(&nodes[0], 1);
	expect_and_process_pending_htlcs(&nodes[0], false);
	expect_payment_claimable!(nodes[0], our_payment_hash_2, our_payment_secret_2, 1000000);

	nodes[1].node.handle_revoke_and_ack(node_a_id, &as_second_raa);
	check_added_monitors(&nodes[1], 1);
	expect_and_process_pending_htlcs(&nodes[1], false);
	expect_payment_claimable!(nodes[1], our_payment_hash_1, our_payment_secret_1, 1000000);

	claim_payment(&nodes[0], &[&nodes[1]], payment_preimage_1);
	claim_payment(&nodes[1], &[&nodes[0]], payment_preimage_2);
}

fn do_test_monitor_update_fail_raa(test_ignore_second_cs: bool) {
	// Tests handling of a monitor update failure when processing an incoming RAA
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();
	let node_c_id = nodes[2].node.get_our_node_id();

	create_announced_chan_between_nodes(&nodes, 0, 1);
	let chan_2 = create_announced_chan_between_nodes(&nodes, 1, 2);

	// Rebalance a bit so that we can send backwards from 2 to 1.
	send_payment(&nodes[0], &[&nodes[1], &nodes[2]], 5000000);

	// Route a first payment that we'll fail backwards
	let (_, payment_hash_1, ..) = route_payment(&nodes[0], &[&nodes[1], &nodes[2]], 1000000);

	// Fail the payment backwards, failing the monitor update on nodes[1]'s receipt of the RAA
	nodes[2].node.fail_htlc_backwards(&payment_hash_1);
	expect_and_process_pending_htlcs_and_htlc_handling_failed(
		&nodes[2],
		&[HTLCHandlingFailureType::Receive { payment_hash: payment_hash_1 }],
	);
	check_added_monitors(&nodes[2], 1);

	let updates = get_htlc_update_msgs(&nodes[2], &node_b_id);
	assert!(updates.update_add_htlcs.is_empty());
	assert!(updates.update_fulfill_htlcs.is_empty());
	assert_eq!(updates.update_fail_htlcs.len(), 1);
	assert!(updates.update_fail_malformed_htlcs.is_empty());
	assert!(updates.update_fee.is_none());
	nodes[1].node.handle_update_fail_htlc(node_c_id, &updates.update_fail_htlcs[0]);

	let commitment = updates.commitment_signed;
	let bs_revoke_and_ack =
		commitment_signed_dance_return_raa(&nodes[1], &nodes[2], &commitment, false);
	check_added_monitors(&nodes[0], 0);

	// While the second channel is AwaitingRAA, forward a second payment to get it into the
	// holding cell.
	let (route, payment_hash_2, payment_preimage_2, payment_secret_2) =
		get_route_and_payment_hash!(nodes[0], nodes[2], 1000000);
	let onion_2 = RecipientOnionFields::secret_only(payment_secret_2);
	let id_2 = PaymentId(payment_hash_2.0);
	nodes[0].node.send_payment_with_route(route, payment_hash_2, onion_2, id_2).unwrap();
	check_added_monitors(&nodes[0], 1);

	let mut send_event =
		SendEvent::from_event(nodes[0].node.get_and_clear_pending_msg_events().remove(0));
	nodes[1].node.handle_update_add_htlc(node_a_id, &send_event.msgs[0]);
	do_commitment_signed_dance(&nodes[1], &nodes[0], &send_event.commitment_msg, false, false);

	expect_and_process_pending_htlcs(&nodes[1], false);
	check_added_monitors(&nodes[1], 0);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	// Now fail monitor updating.
	chanmon_cfgs[1].persister.set_update_ret(ChannelMonitorUpdateStatus::InProgress);
	nodes[1].node.handle_revoke_and_ack(node_c_id, &bs_revoke_and_ack);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	assert!(nodes[1].node.get_and_clear_pending_events().is_empty());
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	check_added_monitors(&nodes[1], 1);

	// Forward a third payment which will also be added to the holding cell, despite the channel
	// being paused waiting a monitor update.
	let (route, payment_hash_3, _, payment_secret_3) =
		get_route_and_payment_hash!(nodes[0], nodes[2], 1000000);
	let onion_3 = RecipientOnionFields::secret_only(payment_secret_3);
	let id_3 = PaymentId(payment_hash_3.0);
	nodes[0].node.send_payment_with_route(route, payment_hash_3, onion_3, id_3).unwrap();
	check_added_monitors(&nodes[0], 1);

	chanmon_cfgs[1].persister.set_update_ret(ChannelMonitorUpdateStatus::Completed); // We succeed in updating the monitor for the first channel
	send_event = SendEvent::from_event(nodes[0].node.get_and_clear_pending_msg_events().remove(0));
	nodes[1].node.handle_update_add_htlc(node_a_id, &send_event.msgs[0]);
	do_commitment_signed_dance(&nodes[1], &nodes[0], &send_event.commitment_msg, false, true);
	check_added_monitors(&nodes[1], 0);

	// Call forward_pending_htlcs and check that the new HTLC was simply added to the holding cell
	// and not forwarded.
	expect_and_process_pending_htlcs(&nodes[1], false);
	check_added_monitors(&nodes[1], 0);
	assert!(nodes[1].node.get_and_clear_pending_events().is_empty());

	let (payment_preimage_4, payment_hash_4) = if test_ignore_second_cs {
		// Try to route another payment backwards from 2 to make sure 1 holds off on responding
		let (route, payment_hash_4, payment_preimage_4, payment_secret_4) =
			get_route_and_payment_hash!(nodes[2], nodes[0], 1000000);
		let onion_4 = RecipientOnionFields::secret_only(payment_secret_4);
		let id_4 = PaymentId(payment_hash_4.0);
		nodes[2].node.send_payment_with_route(route, payment_hash_4, onion_4, id_4).unwrap();
		check_added_monitors(&nodes[2], 1);

		send_event =
			SendEvent::from_event(nodes[2].node.get_and_clear_pending_msg_events().remove(0));
		nodes[1].node.handle_update_add_htlc(node_c_id, &send_event.msgs[0]);
		nodes[1].node.handle_commitment_signed_batch_test(node_c_id, &send_event.commitment_msg);
		check_added_monitors(&nodes[1], 1);
		assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
		(Some(payment_preimage_4), Some(payment_hash_4))
	} else {
		(None, None)
	};

	// Restore monitor updating, ensuring we immediately get a fail-back update and a
	// update_add update.
	chanmon_cfgs[1].persister.set_update_ret(ChannelMonitorUpdateStatus::Completed);
	let (latest_update, _) = get_latest_mon_update_id(&nodes[1], chan_2.2);
	nodes[1].chain_monitor.chain_monitor.force_channel_monitor_updated(chan_2.2, latest_update);
	check_added_monitors(&nodes[1], 0);
	expect_and_process_pending_htlcs_and_htlc_handling_failed(
		&nodes[1],
		&[HTLCHandlingFailureType::Forward { node_id: Some(node_c_id), channel_id: chan_2.2 }],
	);
	check_added_monitors(&nodes[1], 1);

	let mut events_3 = nodes[1].node.get_and_clear_pending_msg_events();
	if test_ignore_second_cs {
		assert_eq!(events_3.len(), 3);
	} else {
		assert_eq!(events_3.len(), 2);
	}

	// Note that the ordering of the events for different nodes is non-prescriptive, though the
	// ordering of the two events that both go to nodes[2] have to stay in the same order.
	let nodes_0_event = remove_first_msg_event_to_node(&node_a_id, &mut events_3);
	let messages_a = match nodes_0_event {
		MessageSendEvent::UpdateHTLCs { node_id, mut updates, channel_id: _ } => {
			assert_eq!(node_id, node_a_id);
			assert!(updates.update_fulfill_htlcs.is_empty());
			assert_eq!(updates.update_fail_htlcs.len(), 1);
			assert!(updates.update_fail_malformed_htlcs.is_empty());
			assert!(updates.update_add_htlcs.is_empty());
			assert!(updates.update_fee.is_none());
			(updates.update_fail_htlcs.remove(0), updates.commitment_signed)
		},
		_ => panic!("Unexpected event type!"),
	};

	let nodes_2_event = remove_first_msg_event_to_node(&node_c_id, &mut events_3);
	let send_event_b = SendEvent::from_event(nodes_2_event);
	assert_eq!(send_event_b.node_id, node_c_id);

	let raa = if test_ignore_second_cs {
		let nodes_2_event = remove_first_msg_event_to_node(&node_c_id, &mut events_3);
		match nodes_2_event {
			MessageSendEvent::SendRevokeAndACK { node_id, msg } => {
				assert_eq!(node_id, node_c_id);
				Some(msg.clone())
			},
			_ => panic!("Unexpected event"),
		}
	} else {
		None
	};

	// Now deliver the new messages...

	nodes[0].node.handle_update_fail_htlc(node_b_id, &messages_a.0);
	do_commitment_signed_dance(&nodes[0], &nodes[1], &messages_a.1, false, false);
	expect_payment_failed!(nodes[0], payment_hash_1, true);

	nodes[2].node.handle_update_add_htlc(node_b_id, &send_event_b.msgs[0]);
	let as_cs;
	if test_ignore_second_cs {
		nodes[2].node.handle_commitment_signed_batch_test(node_b_id, &send_event_b.commitment_msg);
		check_added_monitors(&nodes[2], 1);
		let bs_revoke_and_ack =
			get_event_msg!(nodes[2], MessageSendEvent::SendRevokeAndACK, node_b_id);
		nodes[2].node.handle_revoke_and_ack(node_b_id, &raa.unwrap());
		check_added_monitors(&nodes[2], 1);
		let bs_cs = get_htlc_update_msgs(&nodes[2], &node_b_id);
		assert!(bs_cs.update_add_htlcs.is_empty());
		assert!(bs_cs.update_fail_htlcs.is_empty());
		assert!(bs_cs.update_fail_malformed_htlcs.is_empty());
		assert!(bs_cs.update_fulfill_htlcs.is_empty());
		assert!(bs_cs.update_fee.is_none());

		nodes[1].node.handle_revoke_and_ack(node_c_id, &bs_revoke_and_ack);
		check_added_monitors(&nodes[1], 1);
		as_cs = get_htlc_update_msgs(&nodes[1], &node_c_id);

		nodes[1].node.handle_commitment_signed_batch_test(node_c_id, &bs_cs.commitment_signed);
		check_added_monitors(&nodes[1], 1);
	} else {
		nodes[2].node.handle_commitment_signed_batch_test(node_b_id, &send_event_b.commitment_msg);
		check_added_monitors(&nodes[2], 1);

		let bs_revoke_and_commit = nodes[2].node.get_and_clear_pending_msg_events();
		// As both messages are for nodes[1], they're in order.
		assert_eq!(bs_revoke_and_commit.len(), 2);
		match bs_revoke_and_commit[0] {
			MessageSendEvent::SendRevokeAndACK { ref node_id, ref msg } => {
				assert_eq!(*node_id, node_b_id);
				nodes[1].node.handle_revoke_and_ack(node_c_id, &msg);
				check_added_monitors(&nodes[1], 1);
			},
			_ => panic!("Unexpected event"),
		}

		as_cs = get_htlc_update_msgs(&nodes[1], &node_c_id);

		match bs_revoke_and_commit[1] {
			MessageSendEvent::UpdateHTLCs { ref node_id, channel_id: _, ref updates } => {
				assert_eq!(*node_id, node_b_id);
				assert!(updates.update_add_htlcs.is_empty());
				assert!(updates.update_fail_htlcs.is_empty());
				assert!(updates.update_fail_malformed_htlcs.is_empty());
				assert!(updates.update_fulfill_htlcs.is_empty());
				assert!(updates.update_fee.is_none());
				nodes[1]
					.node
					.handle_commitment_signed_batch_test(node_c_id, &updates.commitment_signed);
				check_added_monitors(&nodes[1], 1);
			},
			_ => panic!("Unexpected event"),
		}
	}

	assert_eq!(as_cs.update_add_htlcs.len(), 1);
	assert!(as_cs.update_fail_htlcs.is_empty());
	assert!(as_cs.update_fail_malformed_htlcs.is_empty());
	assert!(as_cs.update_fulfill_htlcs.is_empty());
	assert!(as_cs.update_fee.is_none());
	let as_raa = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, node_c_id);

	nodes[2].node.handle_update_add_htlc(node_b_id, &as_cs.update_add_htlcs[0]);
	nodes[2].node.handle_commitment_signed_batch_test(node_b_id, &as_cs.commitment_signed);
	check_added_monitors(&nodes[2], 1);
	let bs_second_raa = get_event_msg!(nodes[2], MessageSendEvent::SendRevokeAndACK, node_b_id);

	nodes[2].node.handle_revoke_and_ack(node_b_id, &as_raa);
	check_added_monitors(&nodes[2], 1);
	let bs_second_cs = get_htlc_update_msgs(&nodes[2], &node_b_id);

	nodes[1].node.handle_revoke_and_ack(node_c_id, &bs_second_raa);
	check_added_monitors(&nodes[1], 1);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	nodes[1].node.handle_commitment_signed_batch_test(node_c_id, &bs_second_cs.commitment_signed);
	check_added_monitors(&nodes[1], 1);
	let as_second_raa = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, node_c_id);

	nodes[2].node.handle_revoke_and_ack(node_b_id, &as_second_raa);
	check_added_monitors(&nodes[2], 1);
	assert!(nodes[2].node.get_and_clear_pending_msg_events().is_empty());

	expect_and_process_pending_htlcs(&nodes[2], false);

	let events_6 = nodes[2].node.get_and_clear_pending_events();
	assert_eq!(events_6.len(), 2);
	match events_6[0] {
		Event::PaymentClaimable { payment_hash, .. } => {
			assert_eq!(payment_hash, payment_hash_2);
		},
		_ => panic!("Unexpected event"),
	};
	match events_6[1] {
		Event::PaymentClaimable { payment_hash, .. } => {
			assert_eq!(payment_hash, payment_hash_3);
		},
		_ => panic!("Unexpected event"),
	};

	if test_ignore_second_cs {
		expect_and_process_pending_htlcs(&nodes[1], false);
		check_added_monitors(&nodes[1], 1);

		send_event = SendEvent::from_node(&nodes[1]);
		assert_eq!(send_event.node_id, node_a_id);
		assert_eq!(send_event.msgs.len(), 1);
		nodes[0].node.handle_update_add_htlc(node_b_id, &send_event.msgs[0]);
		do_commitment_signed_dance(&nodes[0], &nodes[1], &send_event.commitment_msg, false, false);

		expect_and_process_pending_htlcs(&nodes[0], false);

		let events_9 = nodes[0].node.get_and_clear_pending_events();
		assert_eq!(events_9.len(), 1);
		match events_9[0] {
			Event::PaymentClaimable { payment_hash, .. } => {
				assert_eq!(payment_hash, payment_hash_4.unwrap())
			},
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

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();
	let node_c_id = nodes[2].node.get_our_node_id();

	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1);
	create_announced_chan_between_nodes(&nodes, 1, 2);

	let (payment_preimage, payment_hash, ..) =
		route_payment(&nodes[0], &[&nodes[1], &nodes[2]], 1_000_000);

	nodes[1].node.peer_disconnected(node_a_id);
	nodes[0].node.peer_disconnected(node_b_id);

	nodes[2].node.claim_funds(payment_preimage);
	check_added_monitors(&nodes[2], 1);
	expect_payment_claimed!(nodes[2], payment_hash, 1_000_000);

	let mut updates = get_htlc_update_msgs(&nodes[2], &node_b_id);
	assert!(updates.update_add_htlcs.is_empty());
	assert!(updates.update_fail_htlcs.is_empty());
	assert!(updates.update_fail_malformed_htlcs.is_empty());
	assert!(updates.update_fee.is_none());
	assert_eq!(updates.update_fulfill_htlcs.len(), 1);
	nodes[1].node.handle_update_fulfill_htlc(node_c_id, updates.update_fulfill_htlcs.remove(0));
	expect_payment_forwarded!(nodes[1], nodes[0], nodes[2], Some(1000), false, false);
	check_added_monitors(&nodes[1], 1);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	do_commitment_signed_dance(&nodes[1], &nodes[2], &updates.commitment_signed, false, false);

	chanmon_cfgs[1].persister.set_update_ret(ChannelMonitorUpdateStatus::InProgress);
	let init_msg = msgs::Init {
		features: nodes[1].node.init_features(),
		networks: None,
		remote_network_address: None,
	};
	nodes[0].node.peer_connected(node_b_id, &init_msg, true).unwrap();
	nodes[1].node.peer_connected(node_a_id, &init_msg, false).unwrap();

	let as_reestablish = get_chan_reestablish_msgs!(nodes[0], nodes[1]).pop().unwrap();
	let bs_reestablish = get_chan_reestablish_msgs!(nodes[1], nodes[0]).pop().unwrap();

	nodes[0].node.handle_channel_reestablish(node_b_id, &bs_reestablish);

	nodes[1].node.handle_channel_reestablish(node_a_id, &as_reestablish);

	// The "disabled" bit should be unset as we just reconnected
	let as_channel_upd = get_event_msg!(nodes[0], MessageSendEvent::SendChannelUpdate, node_b_id);
	assert_eq!(as_channel_upd.contents.channel_flags & 2, 0);

	nodes[1].node.get_and_clear_pending_msg_events(); // Free the holding cell
	check_added_monitors(&nodes[1], 1);

	nodes[1].node.peer_disconnected(node_a_id);
	nodes[0].node.peer_disconnected(node_b_id);

	nodes[0].node.peer_connected(node_b_id, &init_msg, true).unwrap();
	nodes[1].node.peer_connected(node_a_id, &init_msg, false).unwrap();

	assert_eq!(get_chan_reestablish_msgs!(nodes[0], nodes[1]).pop().unwrap(), as_reestablish);
	assert_eq!(get_chan_reestablish_msgs!(nodes[1], nodes[0]).pop().unwrap(), bs_reestablish);

	nodes[0].node.handle_channel_reestablish(node_b_id, &bs_reestablish);

	// The "disabled" bit should be unset as we just reconnected
	let as_channel_upd = get_event_msg!(nodes[0], MessageSendEvent::SendChannelUpdate, node_b_id);
	assert_eq!(as_channel_upd.contents.channel_flags & 2, 0);

	nodes[1].node.handle_channel_reestablish(node_a_id, &as_reestablish);
	check_added_monitors(&nodes[1], 0);

	// The "disabled" bit should be unset as we just reconnected
	let bs_channel_upd = get_event_msg!(nodes[1], MessageSendEvent::SendChannelUpdate, node_a_id);
	assert_eq!(bs_channel_upd.contents.channel_flags & 2, 0);

	chanmon_cfgs[1].persister.set_update_ret(ChannelMonitorUpdateStatus::Completed);
	let (latest_update, _) = get_latest_mon_update_id(&nodes[1], chan_1.2);
	nodes[1].chain_monitor.chain_monitor.force_channel_monitor_updated(chan_1.2, latest_update);
	check_added_monitors(&nodes[1], 0);

	updates = get_htlc_update_msgs(&nodes[1], &node_a_id);
	assert!(updates.update_add_htlcs.is_empty());
	assert!(updates.update_fail_htlcs.is_empty());
	assert!(updates.update_fail_malformed_htlcs.is_empty());
	assert!(updates.update_fee.is_none());
	assert_eq!(updates.update_fulfill_htlcs.len(), 1);
	nodes[0].node.handle_update_fulfill_htlc(node_b_id, updates.update_fulfill_htlcs.remove(0));
	do_commitment_signed_dance(&nodes[0], &nodes[1], &updates.commitment_signed, false, false);
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

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	let channel_id = create_announced_chan_between_nodes(&nodes, 0, 1).2;

	let (route, payment_hash_1, payment_preimage_1, payment_secret_1) =
		get_route_and_payment_hash!(nodes[0], nodes[1], 1000000);
	let (payment_preimage_2, payment_hash_2, payment_secret_2) =
		get_payment_preimage_hash!(nodes[1]);
	let (payment_preimage_3, payment_hash_3, payment_secret_3) =
		get_payment_preimage_hash!(nodes[1]);

	// Queue up two payments - one will be delivered right away, one immediately goes into the
	// holding cell as nodes[0] is AwaitingRAA. Ultimately this allows us to deliver an RAA
	// immediately after a CS. By setting failing the monitor update failure from the CS (which
	// requires only an RAA response due to AwaitingRAA) we can deliver the RAA and require the CS
	// generation during RAA while in monitor-update-failed state.
	let onion_1 = RecipientOnionFields::secret_only(payment_secret_1);
	let id_1 = PaymentId(payment_hash_1.0);
	nodes[0].node.send_payment_with_route(route.clone(), payment_hash_1, onion_1, id_1).unwrap();
	check_added_monitors(&nodes[0], 1);
	let onion_2 = RecipientOnionFields::secret_only(payment_secret_2);
	let id_2 = PaymentId(payment_hash_2.0);
	nodes[0].node.send_payment_with_route(route.clone(), payment_hash_2, onion_2, id_2).unwrap();
	check_added_monitors(&nodes[0], 0);

	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let payment_event = SendEvent::from_event(events.pop().unwrap());
	nodes[1].node.handle_update_add_htlc(node_a_id, &payment_event.msgs[0]);
	nodes[1].node.handle_commitment_signed_batch_test(node_a_id, &payment_event.commitment_msg);
	check_added_monitors(&nodes[1], 1);

	let bs_responses = get_revoke_commit_msgs(&nodes[1], &node_a_id);
	nodes[0].node.handle_revoke_and_ack(node_b_id, &bs_responses.0);
	check_added_monitors(&nodes[0], 1);
	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let payment_event = SendEvent::from_event(events.pop().unwrap());

	nodes[0].node.handle_commitment_signed_batch_test(node_b_id, &bs_responses.1);
	check_added_monitors(&nodes[0], 1);
	let as_raa = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, node_b_id);

	// Now we have a CS queued up which adds a new HTLC (which will need a RAA/CS response from
	// nodes[1]) followed by an RAA. Fail the monitor updating prior to the CS, deliver the RAA,
	// then restore channel monitor updates.
	chanmon_cfgs[1].persister.set_update_ret(ChannelMonitorUpdateStatus::InProgress);
	chanmon_cfgs[1].persister.set_update_ret(ChannelMonitorUpdateStatus::InProgress);
	nodes[1].node.handle_update_add_htlc(node_a_id, &payment_event.msgs[0]);
	nodes[1].node.handle_commitment_signed_batch_test(node_a_id, &payment_event.commitment_msg);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	check_added_monitors(&nodes[1], 1);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	nodes[1].node.handle_revoke_and_ack(node_a_id, &as_raa);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	check_added_monitors(&nodes[1], 1);

	let (latest_update, _) = get_latest_mon_update_id(&nodes[1], channel_id);
	nodes[1].chain_monitor.chain_monitor.force_channel_monitor_updated(channel_id, latest_update);
	// nodes[1] should be AwaitingRAA here!
	check_added_monitors(&nodes[1], 0);
	let bs_responses = get_revoke_commit_msgs(&nodes[1], &node_a_id);
	expect_and_process_pending_htlcs(&nodes[1], false);
	expect_payment_claimable!(nodes[1], payment_hash_1, payment_secret_1, 1000000);

	// We send a third payment here, which is somewhat of a redundant test, but the
	// chanmon_fail_consistency test required it to actually find the bug (by seeing out-of-sync
	// commitment transaction states) whereas here we can explicitly check for it.
	let onion_3 = RecipientOnionFields::secret_only(payment_secret_3);
	let id_3 = PaymentId(payment_hash_3.0);
	nodes[0].node.send_payment_with_route(route, payment_hash_3, onion_3, id_3).unwrap();
	check_added_monitors(&nodes[0], 0);
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	nodes[0].node.handle_revoke_and_ack(node_b_id, &bs_responses.0);
	check_added_monitors(&nodes[0], 1);
	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let payment_event = SendEvent::from_event(events.pop().unwrap());

	nodes[0].node.handle_commitment_signed_batch_test(node_b_id, &bs_responses.1);
	check_added_monitors(&nodes[0], 1);
	let as_raa = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, node_b_id);

	nodes[1].node.handle_update_add_htlc(node_a_id, &payment_event.msgs[0]);
	nodes[1].node.handle_commitment_signed_batch_test(node_a_id, &payment_event.commitment_msg);
	check_added_monitors(&nodes[1], 1);
	let bs_raa = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, node_a_id);

	// Finally deliver the RAA to nodes[1] which results in a CS response to the last update
	nodes[1].node.handle_revoke_and_ack(node_a_id, &as_raa);
	check_added_monitors(&nodes[1], 1);
	expect_and_process_pending_htlcs(&nodes[1], false);
	expect_payment_claimable!(nodes[1], payment_hash_2, payment_secret_2, 1000000);
	let bs_update = get_htlc_update_msgs(&nodes[1], &node_a_id);

	nodes[0].node.handle_revoke_and_ack(node_b_id, &bs_raa);
	check_added_monitors(&nodes[0], 1);

	nodes[0].node.handle_commitment_signed_batch_test(node_b_id, &bs_update.commitment_signed);
	check_added_monitors(&nodes[0], 1);
	let as_raa = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, node_b_id);

	nodes[1].node.handle_revoke_and_ack(node_a_id, &as_raa);
	check_added_monitors(&nodes[1], 1);
	expect_and_process_pending_htlcs(&nodes[1], false);
	expect_payment_claimable!(nodes[1], payment_hash_3, payment_secret_3, 1000000);

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

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	let channel_id = create_announced_chan_between_nodes(&nodes, 0, 1).2;

	// Forward a payment for B to claim
	let (payment_preimage_1, payment_hash_1, ..) =
		route_payment(&nodes[0], &[&nodes[1]], 1_000_000);

	nodes[0].node.peer_disconnected(node_b_id);
	nodes[1].node.peer_disconnected(node_a_id);

	nodes[1].node.claim_funds(payment_preimage_1);
	check_added_monitors(&nodes[1], 1);
	expect_payment_claimed!(nodes[1], payment_hash_1, 1_000_000);

	let init_msg = msgs::Init {
		features: nodes[1].node.init_features(),
		networks: None,
		remote_network_address: None,
	};
	nodes[0].node.peer_connected(node_b_id, &init_msg, true).unwrap();
	nodes[1].node.peer_connected(node_a_id, &init_msg, false).unwrap();

	let as_reconnect = get_chan_reestablish_msgs!(nodes[0], nodes[1]).pop().unwrap();
	let bs_reconnect = get_chan_reestablish_msgs!(nodes[1], nodes[0]).pop().unwrap();

	nodes[0].node.handle_channel_reestablish(node_b_id, &bs_reconnect);
	let _as_channel_update =
		get_event_msg!(nodes[0], MessageSendEvent::SendChannelUpdate, node_b_id);

	// Now deliver a's reestablish, freeing the claim from the holding cell, but fail the monitor
	// update.
	chanmon_cfgs[1].persister.set_update_ret(ChannelMonitorUpdateStatus::InProgress);

	nodes[1].node.handle_channel_reestablish(node_a_id, &as_reconnect);
	let _bs_channel_update =
		get_event_msg!(nodes[1], MessageSendEvent::SendChannelUpdate, node_a_id);
	check_added_monitors(&nodes[1], 1);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	// Send a second payment from A to B, resulting in a commitment update that gets swallowed with
	// the monitor still failed
	let (route, payment_hash_2, payment_preimage_2, payment_secret_2) =
		get_route_and_payment_hash!(nodes[0], nodes[1], 1000000);
	let onion_2 = RecipientOnionFields::secret_only(payment_secret_2);
	let id_2 = PaymentId(payment_hash_2.0);
	nodes[0].node.send_payment_with_route(route, payment_hash_2, onion_2, id_2).unwrap();
	check_added_monitors(&nodes[0], 1);

	let as_updates = get_htlc_update_msgs(&nodes[0], &node_b_id);
	nodes[1].node.handle_update_add_htlc(node_a_id, &as_updates.update_add_htlcs[0]);
	nodes[1].node.handle_commitment_signed_batch_test(node_a_id, &as_updates.commitment_signed);
	check_added_monitors(&nodes[1], 1);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	// Note that nodes[1] not updating monitor here is OK - it wont take action on the new HTLC
	// until we've channel_monitor_update'd and updated for the new commitment transaction.

	// Now un-fail the monitor, which will result in B sending its original commitment update,
	// receiving the commitment update from A, and the resulting commitment dances.
	chanmon_cfgs[1].persister.set_update_ret(ChannelMonitorUpdateStatus::Completed);
	let (latest_update, _) = get_latest_mon_update_id(&nodes[1], channel_id);
	nodes[1].chain_monitor.chain_monitor.force_channel_monitor_updated(channel_id, latest_update);
	check_added_monitors(&nodes[1], 0);

	let mut bs_msgs = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(bs_msgs.len(), 2);

	match bs_msgs.remove(0) {
		MessageSendEvent::UpdateHTLCs { node_id, channel_id: _, mut updates } => {
			assert_eq!(node_id, node_a_id);
			let update_fulfill = updates.update_fulfill_htlcs.remove(0);
			nodes[0].node.handle_update_fulfill_htlc(node_b_id, update_fulfill);
			expect_payment_sent(&nodes[0], payment_preimage_1, None, false, false);
			nodes[0]
				.node
				.handle_commitment_signed_batch_test(node_b_id, &updates.commitment_signed);
			check_added_monitors(&nodes[0], 1);

			let as_raa = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, node_b_id);
			nodes[1].node.handle_revoke_and_ack(node_a_id, &as_raa);
			check_added_monitors(&nodes[1], 1);
		},
		_ => panic!("Unexpected event"),
	}

	match bs_msgs[0] {
		MessageSendEvent::SendRevokeAndACK { ref node_id, ref msg } => {
			assert_eq!(*node_id, node_a_id);
			nodes[0].node.handle_revoke_and_ack(node_b_id, msg);
			check_added_monitors(&nodes[0], 1);
		},
		_ => panic!("Unexpected event"),
	}

	let as_commitment = get_htlc_update_msgs(&nodes[0], &node_b_id);

	let bs_commitment = get_htlc_update_msgs(&nodes[1], &node_a_id);
	nodes[0].node.handle_commitment_signed_batch_test(node_b_id, &bs_commitment.commitment_signed);
	check_added_monitors(&nodes[0], 1);
	let as_raa = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, node_b_id);

	nodes[1].node.handle_commitment_signed_batch_test(node_a_id, &as_commitment.commitment_signed);
	check_added_monitors(&nodes[1], 1);
	let bs_raa = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, node_a_id);
	nodes[1].node.handle_revoke_and_ack(node_a_id, &as_raa);
	check_added_monitors(&nodes[1], 1);

	expect_and_process_pending_htlcs(&nodes[1], false);
	expect_payment_claimable!(nodes[1], payment_hash_2, payment_secret_2, 1000000);

	nodes[0].node.handle_revoke_and_ack(node_b_id, &bs_raa);
	check_added_monitors(&nodes[0], 1);
	expect_payment_path_successful!(nodes[0]);

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

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	let channel_id = create_announced_chan_between_nodes(&nodes, 0, 1).2;
	{
		let mut per_peer_lock;
		let mut peer_state_lock;
		get_channel_ref!(nodes[0], nodes[1], per_peer_lock, peer_state_lock, channel_id)
			.context_mut()
			.announcement_sigs_state = AnnouncementSigsState::PeerReceived;
	}
	{
		let mut per_peer_lock;
		let mut peer_state_lock;
		get_channel_ref!(nodes[1], nodes[0], per_peer_lock, peer_state_lock, channel_id)
			.context_mut()
			.announcement_sigs_state = AnnouncementSigsState::PeerReceived;
	}

	// Route the payment and deliver the initial commitment_signed (with a monitor update failure
	// on receipt).
	let (route, payment_hash_1, payment_preimage_1, payment_secret_1) =
		get_route_and_payment_hash!(nodes[0], nodes[1], 1000000);
	let onion = RecipientOnionFields::secret_only(payment_secret_1);
	let id = PaymentId(payment_hash_1.0);
	nodes[0].node.send_payment_with_route(route, payment_hash_1, onion, id).unwrap();
	check_added_monitors(&nodes[0], 1);

	chanmon_cfgs[1].persister.set_update_ret(ChannelMonitorUpdateStatus::InProgress);
	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let payment_event = SendEvent::from_event(events.pop().unwrap());
	nodes[1].node.handle_update_add_htlc(node_a_id, &payment_event.msgs[0]);
	nodes[1].node.handle_commitment_signed_batch_test(node_a_id, &payment_event.commitment_msg);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	check_added_monitors(&nodes[1], 1);

	// Now disconnect and immediately reconnect, delivering the channel_reestablish while nodes[1]
	// is still failing to update monitors.
	nodes[0].node.peer_disconnected(node_b_id);
	nodes[1].node.peer_disconnected(node_a_id);

	let init_msg = msgs::Init {
		features: nodes[1].node.init_features(),
		networks: None,
		remote_network_address: None,
	};
	nodes[0].node.peer_connected(node_b_id, &init_msg, true).unwrap();
	nodes[1].node.peer_connected(node_a_id, &init_msg, false).unwrap();

	let as_reconnect = get_chan_reestablish_msgs!(nodes[0], nodes[1]).pop().unwrap();
	let bs_reconnect = get_chan_reestablish_msgs!(nodes[1], nodes[0]).pop().unwrap();

	nodes[1].node.handle_channel_reestablish(node_a_id, &as_reconnect);
	let _bs_channel_update =
		get_event_msg!(nodes[1], MessageSendEvent::SendChannelUpdate, node_a_id);
	nodes[0].node.handle_channel_reestablish(node_b_id, &bs_reconnect);
	let _as_channel_update =
		get_event_msg!(nodes[0], MessageSendEvent::SendChannelUpdate, node_b_id);

	chanmon_cfgs[1].persister.set_update_ret(ChannelMonitorUpdateStatus::Completed);
	let (latest_update, _) = get_latest_mon_update_id(&nodes[1], channel_id);
	nodes[1].chain_monitor.chain_monitor.force_channel_monitor_updated(channel_id, latest_update);
	check_added_monitors(&nodes[1], 0);
	let bs_responses = get_revoke_commit_msgs(&nodes[1], &node_a_id);

	nodes[0].node.handle_revoke_and_ack(node_b_id, &bs_responses.0);
	check_added_monitors(&nodes[0], 1);
	nodes[0].node.handle_commitment_signed_batch_test(node_b_id, &bs_responses.1);
	check_added_monitors(&nodes[0], 1);

	let as_raa = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, node_b_id);
	nodes[1].node.handle_revoke_and_ack(node_a_id, &as_raa);
	check_added_monitors(&nodes[1], 1);

	expect_and_process_pending_htlcs(&nodes[1], false);
	expect_payment_claimable!(nodes[1], payment_hash_1, payment_secret_1, 1000000);

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

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	let channel_id = create_announced_chan_between_nodes(&nodes, 0, 1).2;

	// Route the first payment outbound, holding the last RAA for B until we are set up so that we
	// can deliver it and fail the monitor update.
	let (route, payment_hash_1, payment_preimage_1, payment_secret_1) =
		get_route_and_payment_hash!(nodes[0], nodes[1], 1000000);
	let onion_1 = RecipientOnionFields::secret_only(payment_secret_1);
	let id_1 = PaymentId(payment_hash_1.0);
	nodes[0].node.send_payment_with_route(route, payment_hash_1, onion_1, id_1).unwrap();
	check_added_monitors(&nodes[0], 1);

	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let payment_event = SendEvent::from_event(events.pop().unwrap());
	assert_eq!(payment_event.node_id, node_b_id);
	nodes[1].node.handle_update_add_htlc(node_a_id, &payment_event.msgs[0]);
	nodes[1].node.handle_commitment_signed_batch_test(node_a_id, &payment_event.commitment_msg);
	check_added_monitors(&nodes[1], 1);
	let bs_responses = get_revoke_commit_msgs(&nodes[1], &node_a_id);

	nodes[0].node.handle_revoke_and_ack(node_b_id, &bs_responses.0);
	check_added_monitors(&nodes[0], 1);
	nodes[0].node.handle_commitment_signed_batch_test(node_b_id, &bs_responses.1);
	check_added_monitors(&nodes[0], 1);

	let as_raa = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, node_b_id);

	// Route the second payment, generating an update_add_htlc/commitment_signed
	let (route, payment_hash_2, payment_preimage_2, payment_secret_2) =
		get_route_and_payment_hash!(nodes[0], nodes[1], 1000000);
	let onion_2 = RecipientOnionFields::secret_only(payment_secret_2);
	let id_2 = PaymentId(payment_hash_2.0);
	nodes[0].node.send_payment_with_route(route, payment_hash_2, onion_2, id_2).unwrap();

	check_added_monitors(&nodes[0], 1);
	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let payment_event = SendEvent::from_event(events.pop().unwrap());
	assert_eq!(payment_event.node_id, node_b_id);

	chanmon_cfgs[1].persister.set_update_ret(ChannelMonitorUpdateStatus::InProgress);

	// Deliver the final RAA for the first payment, which does not require a response. RAAs
	// generally require a commitment_signed, so the fact that we're expecting an opposite response
	// to the next message also tests resetting the delivery order.
	nodes[1].node.handle_revoke_and_ack(node_a_id, &as_raa);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	check_added_monitors(&nodes[1], 1);

	// Now deliver the update_add_htlc/commitment_signed for the second payment, which does need an
	// RAA/CS response, which should be generated when we call channel_monitor_update (with the
	// appropriate HTLC acceptance).
	nodes[1].node.handle_update_add_htlc(node_a_id, &payment_event.msgs[0]);
	nodes[1].node.handle_commitment_signed_batch_test(node_a_id, &payment_event.commitment_msg);
	check_added_monitors(&nodes[1], 1);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	chanmon_cfgs[1].persister.set_update_ret(ChannelMonitorUpdateStatus::Completed);
	let (latest_update, _) = get_latest_mon_update_id(&nodes[1], channel_id);
	nodes[1].chain_monitor.chain_monitor.force_channel_monitor_updated(channel_id, latest_update);
	check_added_monitors(&nodes[1], 0);

	assert!(nodes[1].node.get_and_clear_pending_events().is_empty());
	expect_and_process_pending_htlcs(&nodes[1], false);
	expect_payment_claimable!(nodes[1], payment_hash_1, payment_secret_1, 1000000);

	let bs_responses = get_revoke_commit_msgs(&nodes[1], &node_a_id);
	nodes[0].node.handle_revoke_and_ack(node_b_id, &bs_responses.0);
	check_added_monitors(&nodes[0], 1);
	nodes[0].node.handle_commitment_signed_batch_test(node_b_id, &bs_responses.1);
	check_added_monitors(&nodes[0], 1);

	let as_raa = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, node_b_id);
	nodes[1].node.handle_revoke_and_ack(node_a_id, &as_raa);
	check_added_monitors(&nodes[1], 1);

	expect_and_process_pending_htlcs(&nodes[1], false);
	expect_payment_claimable!(nodes[1], payment_hash_2, payment_secret_2, 1000000);

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

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();
	let node_c_id = nodes[2].node.get_our_node_id();

	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1);
	create_announced_chan_between_nodes(&nodes, 1, 2);

	// Rebalance a bit so that we can send backwards from 3 to 2.
	send_payment(&nodes[0], &[&nodes[1], &nodes[2]], 5000000);

	let (payment_preimage_1, payment_hash_1, ..) =
		route_payment(&nodes[0], &[&nodes[1]], 1_000_000);

	chanmon_cfgs[1].persister.set_update_ret(ChannelMonitorUpdateStatus::InProgress);
	// As long as the preimage isn't on-chain, we shouldn't expose the `PaymentClaimed` event to
	// users nor send the preimage to peers in the new commitment update.
	nodes[1].node.claim_funds(payment_preimage_1);
	assert!(nodes[1].node.get_and_clear_pending_events().is_empty());
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	check_added_monitors(&nodes[1], 1);

	// Note that at this point there is a pending commitment transaction update for A being held by
	// B. Even when we go to send the payment from C through B to A, B will not update this
	// already-signed commitment transaction and will instead wait for it to resolve before
	// forwarding the payment onwards.

	let (route, payment_hash_2, _, payment_secret_2) =
		get_route_and_payment_hash!(nodes[2], nodes[0], 1_000_000);
	let onion_2 = RecipientOnionFields::secret_only(payment_secret_2);
	let id_2 = PaymentId(payment_hash_2.0);
	nodes[2].node.send_payment_with_route(route.clone(), payment_hash_2, onion_2, id_2).unwrap();
	check_added_monitors(&nodes[2], 1);

	// Successfully update the monitor on the 1<->2 channel, but the 0<->1 channel should still be
	// paused, so forward shouldn't succeed until we call channel_monitor_updated().
	chanmon_cfgs[1].persister.set_update_ret(ChannelMonitorUpdateStatus::Completed);

	let mut events = nodes[2].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let payment_event = SendEvent::from_event(events.pop().unwrap());
	nodes[1].node.handle_update_add_htlc(node_c_id, &payment_event.msgs[0]);
	let events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 0);
	do_commitment_signed_dance(&nodes[1], &nodes[2], &payment_event.commitment_msg, false, true);
	expect_htlc_failure_conditions(nodes[1].node.get_and_clear_pending_events(), &[]);

	let (_, payment_hash_3, payment_secret_3) = get_payment_preimage_hash!(nodes[0]);
	let id_3 = PaymentId(payment_hash_3.0);
	let onion_3 = RecipientOnionFields::secret_only(payment_secret_3);
	nodes[2].node.send_payment_with_route(route, payment_hash_3, onion_3, id_3).unwrap();
	check_added_monitors(&nodes[2], 1);

	let mut events = nodes[2].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let payment_event = SendEvent::from_event(events.pop().unwrap());
	nodes[1].node.handle_update_add_htlc(node_c_id, &payment_event.msgs[0]);
	let events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 0);
	do_commitment_signed_dance(&nodes[1], &nodes[2], &payment_event.commitment_msg, false, true);

	// Now restore monitor updating on the 0<->1 channel and claim the funds on B.
	let channel_id = chan_1.2;
	let (latest_update, _) = get_latest_mon_update_id(&nodes[1], channel_id);
	nodes[1].chain_monitor.chain_monitor.force_channel_monitor_updated(channel_id, latest_update);
	expect_payment_claimed!(nodes[1], payment_hash_1, 1_000_000);
	check_added_monitors(&nodes[1], 0);

	let mut bs_fulfill = get_htlc_update_msgs(&nodes[1], &node_a_id);
	nodes[0].node.handle_update_fulfill_htlc(node_b_id, bs_fulfill.update_fulfill_htlcs.remove(0));
	do_commitment_signed_dance(&nodes[0], &nodes[1], &bs_fulfill.commitment_signed, false, false);
	expect_payment_sent!(nodes[0], payment_preimage_1);

	// Get the payment forwards, note that they were batched into one commitment update.
	nodes[1].node.process_pending_htlc_forwards();
	check_added_monitors(&nodes[1], 1);
	let bs_forward_update = get_htlc_update_msgs(&nodes[1], &node_a_id);
	nodes[0].node.handle_update_add_htlc(node_b_id, &bs_forward_update.update_add_htlcs[0]);
	nodes[0].node.handle_update_add_htlc(node_b_id, &bs_forward_update.update_add_htlcs[1]);
	let commitment = &bs_forward_update.commitment_signed;
	do_commitment_signed_dance(&nodes[0], &nodes[1], commitment, false, false);
	expect_and_process_pending_htlcs(&nodes[0], false);

	let events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 2);
	match events[0] {
		Event::PaymentClaimable {
			ref payment_hash,
			ref purpose,
			amount_msat,
			receiver_node_id,
			ref receiving_channel_ids,
			..
		} => {
			assert_eq!(payment_hash_2, *payment_hash);
			assert_eq!(1_000_000, amount_msat);
			assert_eq!(receiver_node_id.unwrap(), node_a_id);
			assert_eq!(*receiving_channel_ids.last().unwrap(), (channel_id, Some(42)));
			match &purpose {
				PaymentPurpose::Bolt11InvoicePayment {
					payment_preimage, payment_secret, ..
				} => {
					assert!(payment_preimage.is_none());
					assert_eq!(payment_secret_2, *payment_secret);
				},
				_ => panic!("expected PaymentPurpose::Bolt11InvoicePayment"),
			}
		},
		_ => panic!("Unexpected event"),
	}
	match events[1] {
		Event::PaymentClaimable {
			ref payment_hash,
			ref purpose,
			amount_msat,
			receiver_node_id,
			ref receiving_channel_ids,
			..
		} => {
			assert_eq!(payment_hash_3, *payment_hash);
			assert_eq!(1_000_000, amount_msat);
			assert_eq!(receiver_node_id.unwrap(), node_a_id);
			assert_eq!(*receiving_channel_ids, [(channel_id, Some(42))]);
			match &purpose {
				PaymentPurpose::Bolt11InvoicePayment {
					payment_preimage, payment_secret, ..
				} => {
					assert!(payment_preimage.is_none());
					assert_eq!(payment_secret_3, *payment_secret);
				},
				_ => panic!("expected PaymentPurpose::Bolt11InvoicePayment"),
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

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();
	let node_c_id = nodes[2].node.get_our_node_id();

	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1);
	let chan_2 = create_announced_chan_between_nodes(&nodes, 1, 2);

	// Rebalance a bit so that we can send backwards from 3 to 1.
	send_payment(&nodes[0], &[&nodes[1], &nodes[2]], 5000000);

	let (_, payment_hash_1, ..) = route_payment(&nodes[0], &[&nodes[1], &nodes[2]], 1000000);
	nodes[2].node.fail_htlc_backwards(&payment_hash_1);
	expect_and_process_pending_htlcs_and_htlc_handling_failed(
		&nodes[2],
		&[HTLCHandlingFailureType::Receive { payment_hash: payment_hash_1 }],
	);
	check_added_monitors(&nodes[2], 1);

	let cs_fail_update = get_htlc_update_msgs(&nodes[2], &node_b_id);
	nodes[1].node.handle_update_fail_htlc(node_c_id, &cs_fail_update.update_fail_htlcs[0]);
	do_commitment_signed_dance(&nodes[1], &nodes[2], &cs_fail_update.commitment_signed, true, true);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	let (route, payment_hash_2, payment_preimage_2, payment_secret_2) =
		get_route_and_payment_hash!(nodes[2], nodes[0], 1000000);
	let onion = RecipientOnionFields::secret_only(payment_secret_2);
	let id = PaymentId(payment_hash_2.0);
	nodes[2].node.send_payment_with_route(route, payment_hash_2, onion, id).unwrap();
	check_added_monitors(&nodes[2], 1);

	let mut events = nodes[2].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let payment_event = SendEvent::from_event(events.pop().unwrap());
	nodes[1].node.handle_update_add_htlc(node_c_id, &payment_event.msgs[0]);
	do_commitment_signed_dance(&nodes[1], &nodes[2], &payment_event.commitment_msg, false, false);

	chanmon_cfgs[1].persister.set_update_ret(ChannelMonitorUpdateStatus::InProgress);
	expect_and_process_pending_htlcs_and_htlc_handling_failed(
		&nodes[1],
		&[HTLCHandlingFailureType::Forward { node_id: Some(node_c_id), channel_id: chan_2.2 }],
	);
	check_added_monitors(&nodes[1], 1);

	chanmon_cfgs[1].persister.set_update_ret(ChannelMonitorUpdateStatus::Completed);
	let (latest_update, _) = get_latest_mon_update_id(&nodes[1], chan_1.2);
	nodes[1].chain_monitor.chain_monitor.force_channel_monitor_updated(chan_1.2, latest_update);
	check_added_monitors(&nodes[1], 0);

	let bs_updates = get_htlc_update_msgs(&nodes[1], &node_a_id);
	nodes[0].node.handle_update_fail_htlc(node_b_id, &bs_updates.update_fail_htlcs[0]);
	nodes[0].node.handle_update_add_htlc(node_b_id, &bs_updates.update_add_htlcs[0]);
	do_commitment_signed_dance(&nodes[0], &nodes[1], &bs_updates.commitment_signed, false, true);

	let events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 2);
	if let Event::PaymentPathFailed { payment_hash, payment_failed_permanently, .. } = events[0] {
		assert_eq!(payment_hash, payment_hash_1);
		assert!(payment_failed_permanently);
	} else {
		panic!("Unexpected event!");
	}
	match events[1] {
		Event::PaymentFailed { payment_hash, .. } => {
			assert_eq!(payment_hash, Some(payment_hash_1));
		},
		_ => panic!("Unexpected event"),
	}
	nodes[0].node.process_pending_htlc_forwards();
	expect_payment_claimable!(nodes[0], payment_hash_2, payment_secret_2, 1000000);

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

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	let channel_id = create_announced_chan_between_nodes(&nodes, 0, 1).2;

	// Forward a payment for B to claim
	let (payment_preimage_1, payment_hash_1, ..) =
		route_payment(&nodes[0], &[&nodes[1]], 1_000_000);

	// Now start forwarding a second payment, skipping the last RAA so B is in AwaitingRAA
	let (route, payment_hash_2, payment_preimage_2, payment_secret_2) =
		get_route_and_payment_hash!(nodes[0], nodes[1], 1000000);
	let onion = RecipientOnionFields::secret_only(payment_secret_2);
	let id = PaymentId(payment_hash_2.0);
	nodes[0].node.send_payment_with_route(route, payment_hash_2, onion, id).unwrap();
	check_added_monitors(&nodes[0], 1);

	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let payment_event = SendEvent::from_event(events.pop().unwrap());
	nodes[1].node.handle_update_add_htlc(node_a_id, &payment_event.msgs[0]);
	let commitment = payment_event.commitment_msg;
	let as_raa = commitment_signed_dance_return_raa(&nodes[1], &nodes[0], &commitment, false);

	chanmon_cfgs[1].persister.set_update_ret(ChannelMonitorUpdateStatus::InProgress);
	nodes[1].node.claim_funds(payment_preimage_1);
	check_added_monitors(&nodes[1], 1);

	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	chanmon_cfgs[1].persister.set_update_ret(ChannelMonitorUpdateStatus::Completed);
	let (latest_update, _) = get_latest_mon_update_id(&nodes[1], channel_id);
	nodes[1].chain_monitor.chain_monitor.force_channel_monitor_updated(channel_id, latest_update);
	expect_payment_claimed!(nodes[1], payment_hash_1, 1_000_000);
	check_added_monitors(&nodes[1], 0);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	nodes[1].node.handle_revoke_and_ack(node_a_id, &as_raa);
	check_added_monitors(&nodes[1], 1);
	expect_and_process_pending_htlcs(&nodes[1], false);
	expect_payment_claimable!(nodes[1], payment_hash_2, payment_secret_2, 1000000);

	let mut bs_updates = get_htlc_update_msgs(&nodes[1], &node_a_id);
	nodes[0].node.handle_update_fulfill_htlc(node_b_id, bs_updates.update_fulfill_htlcs.remove(0));
	do_commitment_signed_dance(&nodes[0], &nodes[1], &bs_updates.commitment_signed, false, false);
	expect_payment_sent!(nodes[0], payment_preimage_1);

	claim_payment(&nodes[0], &[&nodes[1]], payment_preimage_2);
}

// restore_b_before_conf has no meaning if !confirm_a_first
// restore_b_before_lock has no meaning if confirm_a_first
fn do_during_funding_monitor_fail(
	confirm_a_first: bool, restore_b_before_conf: bool, restore_b_before_lock: bool,
) {
	// Test that if the monitor update generated by funding_transaction_generated fails we continue
	// the channel setup happily after the update is restored.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	nodes[0].node.create_channel(node_b_id, 100000, 10001, 43, None, None).unwrap();
	let open_channel_msg = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, node_b_id);
	handle_and_accept_open_channel(&nodes[1], node_a_id, &open_channel_msg);
	nodes[0].node.handle_accept_channel(
		node_b_id,
		&get_event_msg!(nodes[1], MessageSendEvent::SendAcceptChannel, node_a_id),
	);

	let (temporary_channel_id, funding_tx, funding_output) =
		create_funding_transaction(&nodes[0], &node_b_id, 100000, 43);

	nodes[0]
		.node
		.funding_transaction_generated(temporary_channel_id, node_b_id, funding_tx.clone())
		.unwrap();
	check_added_monitors(&nodes[0], 0);

	chanmon_cfgs[1].persister.set_update_ret(ChannelMonitorUpdateStatus::InProgress);
	let funding_created_msg =
		get_event_msg!(nodes[0], MessageSendEvent::SendFundingCreated, node_b_id);
	let channel_id = ChannelId::v1_from_funding_txid(
		funding_created_msg.funding_txid.as_byte_array(),
		funding_created_msg.funding_output_index,
	);
	nodes[1].node.handle_funding_created(node_a_id, &funding_created_msg);
	check_added_monitors(&nodes[1], 1);

	chanmon_cfgs[0].persister.set_update_ret(ChannelMonitorUpdateStatus::InProgress);
	nodes[0].node.handle_funding_signed(
		node_b_id,
		&get_event_msg!(nodes[1], MessageSendEvent::SendFundingSigned, node_a_id),
	);
	check_added_monitors(&nodes[0], 1);
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	assert!(nodes[0].node.get_and_clear_pending_events().is_empty());
	chanmon_cfgs[0].persister.set_update_ret(ChannelMonitorUpdateStatus::Completed);
	let (latest_update, _) = get_latest_mon_update_id(&nodes[0], channel_id);
	nodes[0].chain_monitor.chain_monitor.force_channel_monitor_updated(channel_id, latest_update);
	check_added_monitors(&nodes[0], 0);
	expect_channel_pending_event(&nodes[0], &node_b_id);

	let events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 0);
	assert_eq!(nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().len(), 1);
	assert_eq!(
		nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().split_off(0)[0].compute_txid(),
		funding_output.txid
	);

	if confirm_a_first {
		confirm_transaction(&nodes[0], &funding_tx);
		nodes[1].node.handle_channel_ready(
			node_a_id,
			&get_event_msg!(nodes[0], MessageSendEvent::SendChannelReady, node_b_id),
		);
		assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
		assert!(nodes[1].node.get_and_clear_pending_events().is_empty());
	} else {
		assert!(!restore_b_before_conf);
		confirm_transaction(&nodes[1], &funding_tx);
		assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	}

	// Make sure nodes[1] isn't stupid enough to re-send the ChannelReady on reconnect
	nodes[0].node.peer_disconnected(node_b_id);
	nodes[1].node.peer_disconnected(node_a_id);
	let mut reconnect_args = ReconnectArgs::new(&nodes[0], &nodes[1]);
	reconnect_args.send_channel_ready.1 = confirm_a_first;
	reconnect_nodes(reconnect_args);

	// But we want to re-emit ChannelPending
	expect_channel_pending_event(&nodes[1], &node_a_id);
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	if !restore_b_before_conf {
		confirm_transaction(&nodes[1], &funding_tx);
		assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
		assert!(nodes[1].node.get_and_clear_pending_events().is_empty());
	}
	if !confirm_a_first && !restore_b_before_lock {
		confirm_transaction(&nodes[0], &funding_tx);
		nodes[1].node.handle_channel_ready(
			node_a_id,
			&get_event_msg!(nodes[0], MessageSendEvent::SendChannelReady, node_b_id),
		);
		assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
		assert!(nodes[1].node.get_and_clear_pending_events().is_empty());
	}

	chanmon_cfgs[1].persister.set_update_ret(ChannelMonitorUpdateStatus::Completed);
	let (latest_update, _) = get_latest_mon_update_id(&nodes[1], channel_id);
	nodes[1].chain_monitor.chain_monitor.force_channel_monitor_updated(channel_id, latest_update);
	check_added_monitors(&nodes[1], 0);

	let (channel_id, (announcement, as_update, bs_update)) = if !confirm_a_first {
		if !restore_b_before_lock {
			let (channel_ready, channel_id) =
				create_chan_between_nodes_with_value_confirm_second(&nodes[0], &nodes[1]);
			(
				channel_id,
				create_chan_between_nodes_with_value_b(&nodes[1], &nodes[0], &channel_ready),
			)
		} else {
			nodes[0].node.handle_channel_ready(
				node_b_id,
				&get_event_msg!(nodes[1], MessageSendEvent::SendChannelReady, node_a_id),
			);
			confirm_transaction(&nodes[0], &funding_tx);
			let (channel_ready, channel_id) =
				create_chan_between_nodes_with_value_confirm_second(&nodes[1], &nodes[0]);
			(
				channel_id,
				create_chan_between_nodes_with_value_b(&nodes[0], &nodes[1], &channel_ready),
			)
		}
	} else {
		if restore_b_before_conf {
			assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
			assert!(nodes[1].node.get_and_clear_pending_events().is_empty());
			confirm_transaction(&nodes[1], &funding_tx);
		}
		let (channel_ready, channel_id) =
			create_chan_between_nodes_with_value_confirm_second(&nodes[0], &nodes[1]);
		(channel_id, create_chan_between_nodes_with_value_b(&nodes[1], &nodes[0], &channel_ready))
	};
	for (i, node) in nodes.iter().enumerate() {
		let counterparty_node_id = nodes[(i + 1) % 2].node.get_our_node_id();
		assert!(node
			.gossip_sync
			.handle_channel_announcement(Some(counterparty_node_id), &announcement)
			.unwrap());
		node.gossip_sync.handle_channel_update(Some(counterparty_node_id), &as_update).unwrap();
		node.gossip_sync.handle_channel_update(Some(counterparty_node_id), &bs_update).unwrap();
	}

	if !restore_b_before_lock {
		expect_channel_ready_event(&nodes[1], &node_a_id);
	} else {
		expect_channel_ready_event(&nodes[0], &node_b_id);
	}

	send_payment(&nodes[0], &[&nodes[1]], 8000000);
	close_channel(&nodes[0], &nodes[1], &channel_id, funding_tx, true);
	let reason_a = ClosureReason::CounterpartyInitiatedCooperativeClosure;
	check_closed_event(&nodes[0], 1, reason_a, &[node_b_id], 100000);
	let reason_b = ClosureReason::LocallyInitiatedCooperativeClosure;
	check_closed_event(&nodes[1], 1, reason_b, &[node_a_id], 100000);
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

	let node_b_id = nodes[1].node.get_our_node_id();
	let node_c_id = nodes[2].node.get_our_node_id();

	let chan_1_id = create_announced_chan_between_nodes(&nodes, 0, 1).0.contents.short_channel_id;
	let (chan_2_ann, _, chan_2_id, _) = create_announced_chan_between_nodes(&nodes, 0, 2);
	let chan_3_id = create_announced_chan_between_nodes(&nodes, 1, 3).0.contents.short_channel_id;
	let chan_4_id = create_announced_chan_between_nodes(&nodes, 2, 3).0.contents.short_channel_id;

	let (mut route, payment_hash, payment_preimage, payment_secret) =
		get_route_and_payment_hash!(&nodes[0], nodes[3], 100000);

	// Set us up to take multiple routes, one 0 -> 1 -> 3 and one 0 -> 2 -> 3:
	let path = route.paths[0].clone();
	route.paths.push(path);
	route.paths[0].hops[0].pubkey = node_b_id;
	route.paths[0].hops[0].short_channel_id = chan_1_id;
	route.paths[0].hops[1].short_channel_id = chan_3_id;
	route.paths[1].hops[0].pubkey = node_c_id;
	route.paths[1].hops[0].short_channel_id = chan_2_ann.contents.short_channel_id;
	route.paths[1].hops[1].short_channel_id = chan_4_id;

	// Set it so that the first monitor update (for the path 0 -> 1 -> 3) succeeds, but the second
	// (for the path 0 -> 2 -> 3) fails.
	chanmon_cfgs[0].persister.set_update_ret(ChannelMonitorUpdateStatus::Completed);
	chanmon_cfgs[0].persister.set_update_ret(ChannelMonitorUpdateStatus::InProgress);

	// The first path should have succeeded with the second getting a MonitorUpdateInProgress err.
	let onion = RecipientOnionFields::secret_only(payment_secret);
	let id = PaymentId(payment_hash.0);
	nodes[0].node.send_payment_with_route(route, payment_hash, onion, id).unwrap();
	check_added_monitors(&nodes[0], 2);
	chanmon_cfgs[0].persister.set_update_ret(ChannelMonitorUpdateStatus::Completed);

	// Pass the first HTLC of the payment along to nodes[3].
	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let path_1 = &[&nodes[1], &nodes[3]];
	let ev = events.pop().unwrap();
	pass_along_path(&nodes[0], path_1, 0, payment_hash, Some(payment_secret), ev, false, None);

	// And check that, after we successfully update the monitor for chan_2 we can pass the second
	// HTLC along to nodes[3] and claim the whole payment back to nodes[0].
	let (latest_update, _) = get_latest_mon_update_id(&nodes[0], chan_2_id);
	nodes[0].chain_monitor.chain_monitor.force_channel_monitor_updated(chan_2_id, latest_update);

	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let path_2 = &[&nodes[2], &nodes[3]];
	let ev = events.pop().unwrap();
	pass_along_path(&nodes[0], path_2, 200_000, payment_hash, Some(payment_secret), ev, true, None);

	claim_payment_along_route(ClaimAlongRouteArgs::new(
		&nodes[0],
		&[path_1, path_2],
		payment_preimage,
	));
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

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	create_announced_chan_between_nodes(&nodes, 0, 1);
	send_payment(&nodes[0], &[&nodes[1]], 100_000_00);

	let (route, payment_hash, payment_preimage, payment_secret) =
		get_route_and_payment_hash!(&nodes[1], nodes[0], 1_000_000);
	let onion = RecipientOnionFields::secret_only(payment_secret);
	let id = PaymentId(payment_hash.0);
	nodes[1].node.send_payment_with_route(route, payment_hash, onion, id).unwrap();
	check_added_monitors(&nodes[1], 1);
	let bs_initial_send_msgs = get_htlc_update_msgs(&nodes[1], &node_a_id);
	// bs_initial_send_msgs are not delivered until they are re-generated after reconnect

	{
		let mut feerate_lock = chanmon_cfgs[0].fee_estimator.sat_per_kw.lock().unwrap();
		*feerate_lock *= 2;
	}
	nodes[0].node.timer_tick_occurred();
	check_added_monitors(&nodes[0], 1);
	let as_update_fee_msgs = get_htlc_update_msgs(&nodes[0], &node_b_id);
	assert!(as_update_fee_msgs.update_fee.is_some());

	nodes[1].node.handle_update_fee(node_a_id, as_update_fee_msgs.update_fee.as_ref().unwrap());
	nodes[1]
		.node
		.handle_commitment_signed_batch_test(node_a_id, &as_update_fee_msgs.commitment_signed);
	check_added_monitors(&nodes[1], 1);
	let bs_first_raa = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, node_a_id);
	// bs_first_raa is not delivered until it is re-generated after reconnect

	nodes[0].node.peer_disconnected(node_b_id);
	nodes[1].node.peer_disconnected(node_a_id);

	let init_msg = msgs::Init {
		features: nodes[1].node.init_features(),
		networks: None,
		remote_network_address: None,
	};
	nodes[0].node.peer_connected(node_b_id, &init_msg, true).unwrap();
	let as_connect_msg = get_chan_reestablish_msgs!(nodes[0], nodes[1]).pop().unwrap();
	nodes[1].node.peer_connected(node_a_id, &init_msg, false).unwrap();
	let bs_connect_msg = get_chan_reestablish_msgs!(nodes[1], nodes[0]).pop().unwrap();

	nodes[1].node.handle_channel_reestablish(node_a_id, &as_connect_msg);
	let bs_resend_msgs = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(bs_resend_msgs.len(), 3);
	if let MessageSendEvent::UpdateHTLCs { ref updates, .. } = bs_resend_msgs[0] {
		assert_eq!(*updates, bs_initial_send_msgs);
	} else {
		panic!();
	}
	if let MessageSendEvent::SendRevokeAndACK { ref msg, .. } = bs_resend_msgs[1] {
		assert_eq!(*msg, bs_first_raa);
	} else {
		panic!();
	}
	if let MessageSendEvent::SendChannelUpdate { .. } = bs_resend_msgs[2] {
	} else {
		panic!();
	}

	nodes[0].node.handle_channel_reestablish(node_b_id, &bs_connect_msg);
	get_event_msg!(nodes[0], MessageSendEvent::SendChannelUpdate, node_b_id);

	nodes[0].node.handle_update_add_htlc(node_b_id, &bs_initial_send_msgs.update_add_htlcs[0]);
	nodes[0]
		.node
		.handle_commitment_signed_batch_test(node_b_id, &bs_initial_send_msgs.commitment_signed);
	check_added_monitors(&nodes[0], 1);
	nodes[1].node.handle_revoke_and_ack(
		node_a_id,
		&get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, node_b_id),
	);
	check_added_monitors(&nodes[1], 1);
	let bs_second_cs = get_htlc_update_msgs(&nodes[1], &node_a_id).commitment_signed;

	nodes[0].node.handle_revoke_and_ack(node_b_id, &bs_first_raa);
	check_added_monitors(&nodes[0], 1);
	nodes[1].node.handle_commitment_signed_batch_test(
		node_a_id,
		&get_htlc_update_msgs(&nodes[0], &node_b_id).commitment_signed,
	);
	check_added_monitors(&nodes[1], 1);
	let bs_third_raa = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, node_a_id);

	nodes[0].node.handle_commitment_signed_batch_test(node_b_id, &bs_second_cs);
	check_added_monitors(&nodes[0], 1);
	nodes[0].node.handle_revoke_and_ack(node_b_id, &bs_third_raa);
	check_added_monitors(&nodes[0], 1);

	nodes[1].node.handle_revoke_and_ack(
		node_a_id,
		&get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, node_b_id),
	);
	check_added_monitors(&nodes[1], 1);

	expect_and_process_pending_htlcs(&nodes[0], false);
	expect_payment_claimable!(nodes[0], payment_hash, payment_secret, 1_000_000);

	claim_payment(&nodes[1], &[&nodes[0]], payment_preimage);
}

#[test]
fn test_fail_htlc_on_broadcast_after_claim() {
	// In an earlier version of 7e78fa660cec8a73286c94c1073ee588140e7a01 we'd also fail the inbound
	// channel backwards if we received an HTLC failure after a HTLC fulfillment. Here we test a
	// specific case of that by having the HTLC failure come from the ChannelMonitor after a dust
	// HTLC was not included in a confirmed commitment transaction.
	//
	// We first forward a payment, then claim it with an update_fulfill_htlc message, closing the
	// channel immediately before commitment occurs. After the commitment transaction reaches
	// ANTI_REORG_DELAY confirmations, will will try to fail the HTLC which was already fulfilled.
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();
	let node_c_id = nodes[2].node.get_our_node_id();

	create_announced_chan_between_nodes(&nodes, 0, 1);
	let chan_id_2 = create_announced_chan_between_nodes(&nodes, 1, 2).2;

	let (payment_preimage, payment_hash, ..) =
		route_payment(&nodes[0], &[&nodes[1], &nodes[2]], 2000);

	let bs_txn = get_local_commitment_txn!(nodes[2], chan_id_2);
	assert_eq!(bs_txn.len(), 1);

	nodes[2].node.claim_funds(payment_preimage);
	check_added_monitors(&nodes[2], 1);
	expect_payment_claimed!(nodes[2], payment_hash, 2000);

	let mut cs_updates = get_htlc_update_msgs(&nodes[2], &node_b_id);
	nodes[1].node.handle_update_fulfill_htlc(node_c_id, cs_updates.update_fulfill_htlcs.remove(0));
	let mut bs_updates = get_htlc_update_msgs(&nodes[1], &node_a_id);
	check_added_monitors(&nodes[1], 1);
	expect_payment_forwarded!(nodes[1], nodes[0], nodes[2], Some(1000), false, false);

	mine_transaction(&nodes[1], &bs_txn[0]);
	let reason = ClosureReason::CommitmentTxConfirmed;
	check_closed_event(&nodes[1], 1, reason, &[node_c_id], 100000);
	check_closed_broadcast!(nodes[1], true);
	connect_blocks(&nodes[1], ANTI_REORG_DELAY - 1);
	check_added_monitors(&nodes[1], 1);
	expect_and_process_pending_htlcs_and_htlc_handling_failed(
		&nodes[1],
		&[HTLCHandlingFailureType::Forward { node_id: Some(node_c_id), channel_id: chan_id_2 }],
	);

	nodes[0].node.handle_update_fulfill_htlc(node_b_id, bs_updates.update_fulfill_htlcs.remove(0));
	expect_payment_sent(&nodes[0], payment_preimage, None, false, false);
	do_commitment_signed_dance(&nodes[0], &nodes[1], &bs_updates.commitment_signed, true, true);
	expect_payment_path_successful!(nodes[0]);
}

fn do_update_fee_resend_test(deliver_update: bool, parallel_updates: bool) {
	// In early versions we did not handle resending of update_fee on reconnect correctly. The
	// chanmon_consistency fuzz target, of course, immediately found it, but we test a few cases
	// explicitly here.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	create_announced_chan_between_nodes(&nodes, 0, 1);
	send_payment(&nodes[0], &[&nodes[1]], 1000);

	{
		let mut feerate_lock = chanmon_cfgs[0].fee_estimator.sat_per_kw.lock().unwrap();
		*feerate_lock += 20;
	}
	nodes[0].node.timer_tick_occurred();
	check_added_monitors(&nodes[0], 1);
	let update_msgs = get_htlc_update_msgs(&nodes[0], &node_b_id);
	assert!(update_msgs.update_fee.is_some());
	if deliver_update {
		nodes[1].node.handle_update_fee(node_a_id, update_msgs.update_fee.as_ref().unwrap());
	}

	if parallel_updates {
		{
			let mut feerate_lock = chanmon_cfgs[0].fee_estimator.sat_per_kw.lock().unwrap();
			*feerate_lock += 20;
		}
		nodes[0].node.timer_tick_occurred();
		assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	}

	nodes[0].node.peer_disconnected(node_b_id);
	nodes[1].node.peer_disconnected(node_a_id);

	let init_msg = msgs::Init {
		features: nodes[1].node.init_features(),
		networks: None,
		remote_network_address: None,
	};
	nodes[0].node.peer_connected(node_b_id, &init_msg, true).unwrap();
	let as_connect_msg = get_chan_reestablish_msgs!(nodes[0], nodes[1]).pop().unwrap();
	nodes[1].node.peer_connected(node_a_id, &init_msg, false).unwrap();
	let bs_connect_msg = get_chan_reestablish_msgs!(nodes[1], nodes[0]).pop().unwrap();

	nodes[1].node.handle_channel_reestablish(node_a_id, &as_connect_msg);
	get_event_msg!(nodes[1], MessageSendEvent::SendChannelUpdate, node_a_id);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	nodes[0].node.handle_channel_reestablish(node_b_id, &bs_connect_msg);
	let mut as_reconnect_msgs = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(as_reconnect_msgs.len(), 2);
	if let MessageSendEvent::SendChannelUpdate { .. } = as_reconnect_msgs.pop().unwrap() {
	} else {
		panic!();
	}
	let update_msgs =
		if let MessageSendEvent::UpdateHTLCs { updates, .. } = as_reconnect_msgs.pop().unwrap() {
			updates
		} else {
			panic!();
		};
	assert!(update_msgs.update_fee.is_some());
	nodes[1].node.handle_update_fee(node_a_id, update_msgs.update_fee.as_ref().unwrap());
	if parallel_updates {
		nodes[1]
			.node
			.handle_commitment_signed_batch_test(node_a_id, &update_msgs.commitment_signed);
		check_added_monitors(&nodes[1], 1);
		let (bs_first_raa, bs_first_cs) = get_revoke_commit_msgs(&nodes[1], &node_a_id);
		nodes[0].node.handle_revoke_and_ack(node_b_id, &bs_first_raa);
		check_added_monitors(&nodes[0], 1);
		let as_second_update = get_htlc_update_msgs(&nodes[0], &node_b_id);

		nodes[0].node.handle_commitment_signed_batch_test(node_b_id, &bs_first_cs);
		check_added_monitors(&nodes[0], 1);
		let as_first_raa = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, node_b_id);

		nodes[1].node.handle_update_fee(node_a_id, as_second_update.update_fee.as_ref().unwrap());
		nodes[1]
			.node
			.handle_commitment_signed_batch_test(node_a_id, &as_second_update.commitment_signed);
		check_added_monitors(&nodes[1], 1);
		let bs_second_raa = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, node_a_id);

		nodes[1].node.handle_revoke_and_ack(node_a_id, &as_first_raa);
		let bs_second_cs = get_htlc_update_msgs(&nodes[1], &node_a_id);
		check_added_monitors(&nodes[1], 1);

		nodes[0].node.handle_revoke_and_ack(node_b_id, &bs_second_raa);
		check_added_monitors(&nodes[0], 1);

		nodes[0]
			.node
			.handle_commitment_signed_batch_test(node_b_id, &bs_second_cs.commitment_signed);
		check_added_monitors(&nodes[0], 1);
		let as_second_raa = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, node_b_id);

		nodes[1].node.handle_revoke_and_ack(node_a_id, &as_second_raa);
		check_added_monitors(&nodes[1], 1);
	} else {
		let commitment = &update_msgs.commitment_signed;
		do_commitment_signed_dance(&nodes[1], &nodes[0], commitment, false, false);
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
	let persister;
	let new_chain_mon;
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes_0_reload;
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	let chan_id =
		create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 15_000_000, 7_000_000_000).2;
	let (route, payment_hash_1, payment_preimage_1, payment_secret_1) =
		get_route_and_payment_hash!(&nodes[0], nodes[1], 100000);
	let (payment_preimage_2, payment_hash_2, payment_secret_2) =
		get_payment_preimage_hash!(&nodes[1]);

	// Do a really complicated dance to get an HTLC into the holding cell, with
	// MonitorUpdateInProgress set but AwaitingRemoteRevoke unset. When this test was written, any
	// attempts to send an HTLC while MonitorUpdateInProgress is set are immediately
	// failed-backwards. Thus, the only way to get an AddHTLC into the holding cell is to add it
	// while AwaitingRemoteRevoke is set but MonitorUpdateInProgress is unset, and then swap the
	// flags.
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
	// Note that because, at the end, MonitorUpdateInProgress is still set, the HTLC generated in
	// (c) will not be freed from the holding cell.
	let (payment_preimage_0, payment_hash_0, ..) = route_payment(&nodes[1], &[&nodes[0]], 100_000);

	let onion_1 = RecipientOnionFields::secret_only(payment_secret_1);
	let id_1 = PaymentId(payment_hash_1.0);
	nodes[0].node.send_payment_with_route(route.clone(), payment_hash_1, onion_1, id_1).unwrap();
	check_added_monitors(&nodes[0], 1);
	let send = SendEvent::from_node(&nodes[0]);
	assert_eq!(send.msgs.len(), 1);

	let onion_2 = RecipientOnionFields::secret_only(payment_secret_2);
	let id_2 = PaymentId(payment_hash_2.0);
	nodes[0].node.send_payment_with_route(route, payment_hash_2, onion_2, id_2).unwrap();
	check_added_monitors(&nodes[0], 0);

	let chan_0_monitor_serialized = get_monitor!(nodes[0], chan_id).encode();
	chanmon_cfgs[0].persister.set_update_ret(ChannelMonitorUpdateStatus::InProgress);
	chanmon_cfgs[0].persister.set_update_ret(ChannelMonitorUpdateStatus::InProgress);
	nodes[0].node.claim_funds(payment_preimage_0);
	check_added_monitors(&nodes[0], 1);

	nodes[1].node.handle_update_add_htlc(node_a_id, &send.msgs[0]);
	nodes[1].node.handle_commitment_signed_batch_test(node_a_id, &send.commitment_msg);
	check_added_monitors(&nodes[1], 1);

	let (raa, cs) = get_revoke_commit_msgs(&nodes[1], &node_a_id);

	nodes[0].node.handle_revoke_and_ack(node_b_id, &raa);
	check_added_monitors(&nodes[0], 1);

	if disconnect {
		// Optionally reload nodes[0] entirely through a serialization roundtrip, otherwise just
		// disconnect the peers. Note that the fuzzer originally found this issue because
		// deserializing a ChannelManager in this state causes an assertion failure.
		if reload_a {
			let node_ser = nodes[0].node.encode();
			let mons = &[&chan_0_monitor_serialized[..]];
			reload_node!(nodes[0], &node_ser, mons, persister, new_chain_mon, nodes_0_reload);
			persister.set_update_ret(ChannelMonitorUpdateStatus::InProgress);
			persister.set_update_ret(ChannelMonitorUpdateStatus::InProgress);
		} else {
			nodes[0].node.peer_disconnected(node_b_id);
		}
		nodes[1].node.peer_disconnected(node_a_id);

		// Now reconnect the two
		let init_msg = msgs::Init {
			features: nodes[1].node.init_features(),
			networks: None,
			remote_network_address: None,
		};
		nodes[0].node.peer_connected(node_b_id, &init_msg, true).unwrap();
		let reestablish_1 = get_chan_reestablish_msgs!(nodes[0], nodes[1]);
		assert_eq!(reestablish_1.len(), 1);
		nodes[1].node.peer_connected(node_a_id, &init_msg, false).unwrap();
		let reestablish_2 = get_chan_reestablish_msgs!(nodes[1], nodes[0]);
		assert_eq!(reestablish_2.len(), 1);

		nodes[1].node.handle_channel_reestablish(node_a_id, &reestablish_1[0]);
		let resp_1 = handle_chan_reestablish_msgs!(nodes[1], nodes[0]);
		check_added_monitors(&nodes[1], 0);

		nodes[0].node.handle_channel_reestablish(node_b_id, &reestablish_2[0]);
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
		} else {
			panic!();
		}

		if reload_a {
			// The two pending monitor updates were replayed (but are still pending).
			check_added_monitors(&nodes[0], 2);
		} else {
			// There should be no monitor updates as we are still pending awaiting a failed one.
			check_added_monitors(&nodes[0], 0);
		}
		check_added_monitors(&nodes[1], 0);
	}

	// If we finish updating the monitor, we should free the holding cell right away (this did
	// not occur prior to #756). This should result in a new monitor update.
	chanmon_cfgs[0].persister.set_update_ret(ChannelMonitorUpdateStatus::Completed);
	let (mon_id, _) = get_latest_mon_update_id(&nodes[0], chan_id);
	nodes[0].chain_monitor.chain_monitor.force_channel_monitor_updated(chan_id, mon_id);
	expect_payment_claimed!(nodes[0], payment_hash_0, 100_000);
	check_added_monitors(&nodes[0], 1);
	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);

	// Deliver the pending in-flight CS
	nodes[0].node.handle_commitment_signed_batch_test(node_b_id, &cs);
	check_added_monitors(&nodes[0], 1);

	let commitment_msg = match events.pop().unwrap() {
		MessageSendEvent::UpdateHTLCs { node_id, channel_id: _, mut updates } => {
			assert_eq!(node_id, node_b_id);
			assert!(updates.update_fail_htlcs.is_empty());
			assert!(updates.update_fail_malformed_htlcs.is_empty());
			assert!(updates.update_fee.is_none());
			assert_eq!(updates.update_fulfill_htlcs.len(), 1);
			let update_fulfill = updates.update_fulfill_htlcs.remove(0);
			nodes[1].node.handle_update_fulfill_htlc(node_a_id, update_fulfill);
			expect_payment_sent(&nodes[1], payment_preimage_0, None, false, false);
			assert_eq!(updates.update_add_htlcs.len(), 1);
			nodes[1].node.handle_update_add_htlc(node_a_id, &updates.update_add_htlcs[0]);
			updates.commitment_signed
		},
		_ => panic!("Unexpected event type!"),
	};

	nodes[1].node.handle_commitment_signed_batch_test(node_a_id, &commitment_msg);
	check_added_monitors(&nodes[1], 1);

	let as_revoke_and_ack = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, node_b_id);
	nodes[1].node.handle_revoke_and_ack(node_a_id, &as_revoke_and_ack);
	expect_and_process_pending_htlcs(&nodes[1], false);
	expect_payment_claimable!(nodes[1], payment_hash_1, payment_secret_1, 100000);
	check_added_monitors(&nodes[1], 1);

	assert!(commitment_signed_dance_through_cp_raa(&nodes[1], &nodes[0], false, false).is_none());
	let events = nodes[1].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		Event::PaymentPathSuccessful { .. } => {},
		_ => panic!("Unexpected event"),
	};

	nodes[1].node.process_pending_htlc_forwards();
	expect_payment_claimable!(nodes[1], payment_hash_2, payment_secret_2, 100000);

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

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();
	let node_c_id = nodes[2].node.get_our_node_id();

	create_announced_chan_between_nodes(&nodes, 0, 1);
	let chan_id_2 = create_announced_chan_between_nodes(&nodes, 1, 2).2;

	let (payment_preimage, payment_hash, ..) =
		route_payment(&nodes[0], &[&nodes[1], &nodes[2]], 100_000);

	let mut as_raa = None;
	if htlc_status == HTLCStatusAtDupClaim::HoldingCell {
		// In order to get the HTLC claim into the holding cell at nodes[1], we need nodes[1] to be
		// awaiting a remote revoke_and_ack from nodes[0].
		let (route, second_payment_hash, _, second_payment_secret) =
			get_route_and_payment_hash!(nodes[0], nodes[1], 100_000);
		let onion_2 = RecipientOnionFields::secret_only(second_payment_secret);
		let id_2 = PaymentId(second_payment_hash.0);
		nodes[0].node.send_payment_with_route(route, second_payment_hash, onion_2, id_2).unwrap();
		check_added_monitors(&nodes[0], 1);

		let send_event =
			SendEvent::from_event(nodes[0].node.get_and_clear_pending_msg_events().remove(0));
		nodes[1].node.handle_update_add_htlc(node_a_id, &send_event.msgs[0]);
		nodes[1].node.handle_commitment_signed_batch_test(node_a_id, &send_event.commitment_msg);
		check_added_monitors(&nodes[1], 1);

		let (bs_raa, bs_cs) = get_revoke_commit_msgs(&nodes[1], &node_a_id);
		nodes[0].node.handle_revoke_and_ack(node_b_id, &bs_raa);
		check_added_monitors(&nodes[0], 1);
		nodes[0].node.handle_commitment_signed_batch_test(node_b_id, &bs_cs);
		check_added_monitors(&nodes[0], 1);

		as_raa = Some(get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, node_b_id));
	}

	let mut fulfill_msg = msgs::UpdateFulfillHTLC {
		channel_id: chan_id_2,
		htlc_id: 0,
		payment_preimage,
		attribution_data: None,
	};
	if second_fails {
		nodes[2].node.fail_htlc_backwards(&payment_hash);
		expect_and_process_pending_htlcs_and_htlc_handling_failed(
			&nodes[2],
			&[HTLCHandlingFailureType::Receive { payment_hash }],
		);
		check_added_monitors(&nodes[2], 1);
		get_htlc_update_msgs(&nodes[2], &node_b_id);
	// Note that we don't populate fulfill_msg.attribution_data here, which will lead to hold times being
	// unavailable.
	} else {
		nodes[2].node.claim_funds(payment_preimage);
		check_added_monitors(&nodes[2], 1);
		expect_payment_claimed!(nodes[2], payment_hash, 100_000);

		let cs_updates = get_htlc_update_msgs(&nodes[2], &node_b_id);
		assert_eq!(cs_updates.update_fulfill_htlcs.len(), 1);

		// Check that the message we're about to deliver matches the one generated. Ignore attribution data.
		assert_eq!(fulfill_msg.channel_id, cs_updates.update_fulfill_htlcs[0].channel_id);
		assert_eq!(fulfill_msg.htlc_id, cs_updates.update_fulfill_htlcs[0].htlc_id);
		assert_eq!(
			fulfill_msg.payment_preimage,
			cs_updates.update_fulfill_htlcs[0].payment_preimage
		);
		fulfill_msg.attribution_data = cs_updates.update_fulfill_htlcs[0].attribution_data.clone();
	}
	nodes[1].node.handle_update_fulfill_htlc(node_c_id, fulfill_msg);
	expect_payment_forwarded!(nodes[1], nodes[0], nodes[2], Some(1000), false, false);
	check_added_monitors(&nodes[1], 1);

	let mut bs_updates = None;
	if htlc_status != HTLCStatusAtDupClaim::HoldingCell {
		bs_updates = Some(get_htlc_update_msgs(&nodes[1], &node_a_id));
		assert_eq!(bs_updates.as_ref().unwrap().update_fulfill_htlcs.len(), 1);
		nodes[0].node.handle_update_fulfill_htlc(
			node_b_id,
			bs_updates.as_mut().unwrap().update_fulfill_htlcs.remove(0),
		);
		expect_payment_sent(&nodes[0], payment_preimage, None, false, false);
		if htlc_status == HTLCStatusAtDupClaim::Cleared {
			let commitment = &bs_updates.as_ref().unwrap().commitment_signed;
			do_commitment_signed_dance(&nodes[0], &nodes[1], commitment, false, false);
			expect_payment_path_successful!(nodes[0]);
		}
	} else {
		assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	}

	nodes[1].node.peer_disconnected(node_c_id);
	nodes[2].node.peer_disconnected(node_b_id);

	if second_fails {
		let mut reconnect_args = ReconnectArgs::new(&nodes[1], &nodes[2]);
		reconnect_args.pending_htlc_fails.0 = 1;
		reconnect_nodes(reconnect_args);
		expect_and_process_pending_htlcs_and_htlc_handling_failed(
			&nodes[1],
			&[HTLCHandlingFailureType::Forward { node_id: Some(node_c_id), channel_id: chan_id_2 }],
		);
	} else {
		let mut reconnect_args = ReconnectArgs::new(&nodes[1], &nodes[2]);
		reconnect_args.pending_htlc_claims.0 = 1;
		reconnect_nodes(reconnect_args);
	}

	if htlc_status == HTLCStatusAtDupClaim::HoldingCell {
		nodes[1].node.handle_revoke_and_ack(node_a_id, &as_raa.unwrap());
		check_added_monitors(&nodes[1], 1);
		expect_htlc_failure_conditions(nodes[1].node.get_and_clear_pending_events(), &[]); // We finally receive the second payment, but don't claim it

		bs_updates = Some(get_htlc_update_msgs(&nodes[1], &node_a_id));
		assert_eq!(bs_updates.as_ref().unwrap().update_fulfill_htlcs.len(), 1);
		nodes[0].node.handle_update_fulfill_htlc(
			node_b_id,
			bs_updates.as_mut().unwrap().update_fulfill_htlcs.remove(0),
		);
		expect_payment_sent(&nodes[0], payment_preimage, None, false, false);
	}
	if htlc_status != HTLCStatusAtDupClaim::Cleared {
		let commitment = &bs_updates.as_ref().unwrap().commitment_signed;
		do_commitment_signed_dance(&nodes[0], &nodes[1], commitment, false, false);
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
	config.channel_handshake_config.commit_upfront_shutdown_pubkey = false;

	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[Some(config.clone()), Some(config)]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	let (_, _, channel_id, funding_tx) = create_announced_chan_between_nodes(&nodes, 0, 1);

	chanmon_cfgs[0].persister.set_update_ret(ChannelMonitorUpdateStatus::InProgress);
	chanmon_cfgs[1].persister.set_update_ret(ChannelMonitorUpdateStatus::InProgress);

	nodes[0].node.close_channel(&channel_id, &node_b_id).unwrap();
	nodes[1].node.handle_shutdown(
		node_a_id,
		&get_event_msg!(nodes[0], MessageSendEvent::SendShutdown, node_b_id),
	);
	check_added_monitors(&nodes[1], 1);

	nodes[0].node.handle_shutdown(
		node_b_id,
		&get_event_msg!(nodes[1], MessageSendEvent::SendShutdown, node_a_id),
	);
	check_added_monitors(&nodes[0], 1);

	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());

	chanmon_cfgs[0].persister.set_update_ret(ChannelMonitorUpdateStatus::Completed);
	chanmon_cfgs[1].persister.set_update_ret(ChannelMonitorUpdateStatus::Completed);

	let (latest_update, _) = get_latest_mon_update_id(&nodes[0], channel_id);
	nodes[0].chain_monitor.chain_monitor.force_channel_monitor_updated(channel_id, latest_update);
	nodes[1].node.handle_closing_signed(
		node_a_id,
		&get_event_msg!(nodes[0], MessageSendEvent::SendClosingSigned, node_b_id),
	);

	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	chanmon_cfgs[1].persister.set_update_ret(ChannelMonitorUpdateStatus::Completed);
	let (latest_update, _) = get_latest_mon_update_id(&nodes[1], channel_id);
	nodes[1].chain_monitor.chain_monitor.force_channel_monitor_updated(channel_id, latest_update);

	nodes[0].node.handle_closing_signed(
		node_b_id,
		&get_event_msg!(nodes[1], MessageSendEvent::SendClosingSigned, node_a_id),
	);
	let (_, closing_signed_a) = get_closing_signed_broadcast!(nodes[0].node, node_b_id);
	let txn_a = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().split_off(0);

	nodes[1].node.handle_closing_signed(node_a_id, &closing_signed_a.unwrap());
	let (_, none_b) = get_closing_signed_broadcast!(nodes[1].node, node_a_id);
	assert!(none_b.is_none());
	let txn_b = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().split_off(0);

	assert_eq!(txn_a, txn_b);
	assert_eq!(txn_a.len(), 1);
	check_spends!(txn_a[0], funding_tx);
	let reason_b = ClosureReason::CounterpartyInitiatedCooperativeClosure;
	check_closed_event(&nodes[1], 1, reason_b, &[node_a_id], 100000);
	let reason_a = ClosureReason::LocallyInitiatedCooperativeClosure;
	check_closed_event(&nodes[0], 1, reason_a, &[node_b_id], 100000);
}

#[test]
fn double_temp_error() {
	// Test that it's OK to have multiple `ChainMonitor::update_channel` calls fail in a row.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	let (_, _, channel_id, _) = create_announced_chan_between_nodes(&nodes, 0, 1);

	let (payment_preimage_1, payment_hash_1, ..) =
		route_payment(&nodes[0], &[&nodes[1]], 1_000_000);
	let (payment_preimage_2, payment_hash_2, ..) =
		route_payment(&nodes[0], &[&nodes[1]], 1_000_000);

	chanmon_cfgs[1].persister.set_update_ret(ChannelMonitorUpdateStatus::InProgress);
	// `claim_funds` results in a ChannelMonitorUpdate.
	nodes[1].node.claim_funds(payment_preimage_1);
	check_added_monitors(&nodes[1], 1);
	let (latest_update_1, _) = get_latest_mon_update_id(&nodes[1], channel_id);

	chanmon_cfgs[1].persister.set_update_ret(ChannelMonitorUpdateStatus::InProgress);
	// Previously, this would've panicked due to a double-call to `Channel::monitor_update_failed`,
	// which had some asserts that prevented it from being called twice.
	nodes[1].node.claim_funds(payment_preimage_2);
	check_added_monitors(&nodes[1], 1);
	chanmon_cfgs[1].persister.set_update_ret(ChannelMonitorUpdateStatus::Completed);

	let (latest_update_2, _) = get_latest_mon_update_id(&nodes[1], channel_id);
	nodes[1].chain_monitor.chain_monitor.force_channel_monitor_updated(channel_id, latest_update_1);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	check_added_monitors(&nodes[1], 0);
	nodes[1].chain_monitor.chain_monitor.force_channel_monitor_updated(channel_id, latest_update_2);

	// Complete the first HTLC. Note that as a side-effect we handle the monitor update completions
	// and get both PaymentClaimed events at once.
	let msg_events = nodes[1].node.get_and_clear_pending_msg_events();

	let events = nodes[1].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 2);
	match events[0] {
		Event::PaymentClaimed { amount_msat: 1_000_000, payment_hash, .. } => {
			assert_eq!(payment_hash, payment_hash_1)
		},
		_ => panic!("Unexpected Event: {:?}", events[0]),
	}
	match events[1] {
		Event::PaymentClaimed { amount_msat: 1_000_000, payment_hash, .. } => {
			assert_eq!(payment_hash, payment_hash_2)
		},
		_ => panic!("Unexpected Event: {:?}", events[1]),
	}

	assert_eq!(msg_events.len(), 1);
	let (update_fulfill_1, commitment_signed_b1, node_id) = {
		match &msg_events[0] {
			&MessageSendEvent::UpdateHTLCs {
				ref node_id,
				channel_id: _,
				updates:
					msgs::CommitmentUpdate {
						ref update_add_htlcs,
						ref update_fulfill_htlcs,
						ref update_fail_htlcs,
						ref update_fail_malformed_htlcs,
						ref update_fee,
						ref commitment_signed,
					},
			} => {
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
	assert_eq!(node_id, node_a_id);
	nodes[0].node.handle_update_fulfill_htlc(node_b_id, update_fulfill_1);
	check_added_monitors(&nodes[0], 0);
	expect_payment_sent(&nodes[0], payment_preimage_1, None, false, false);
	nodes[0].node.handle_commitment_signed_batch_test(node_b_id, &commitment_signed_b1);
	check_added_monitors(&nodes[0], 1);
	nodes[0].node.process_pending_htlc_forwards();
	let (raa_a1, commitment_signed_a1) = get_revoke_commit_msgs(&nodes[0], &node_b_id);
	check_added_monitors(&nodes[1], 0);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	nodes[1].node.handle_revoke_and_ack(node_a_id, &raa_a1);
	check_added_monitors(&nodes[1], 1);
	nodes[1].node.handle_commitment_signed_batch_test(node_a_id, &commitment_signed_a1);
	check_added_monitors(&nodes[1], 1);

	// Complete the second HTLC.
	let ((update_fulfill_2, commitment_signed_b2), raa_b2) = {
		let events = nodes[1].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 2);
		(
			match &events[0] {
				MessageSendEvent::UpdateHTLCs { node_id, channel_id: _, updates } => {
					assert_eq!(*node_id, node_a_id);
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
					assert_eq!(*node_id, node_a_id);
					(*msg).clone()
				},
				_ => panic!("Unexpected event"),
			},
		)
	};
	nodes[0].node.handle_revoke_and_ack(node_b_id, &raa_b2);
	check_added_monitors(&nodes[0], 1);
	expect_payment_path_successful!(nodes[0]);

	nodes[0].node.handle_update_fulfill_htlc(node_b_id, update_fulfill_2);
	check_added_monitors(&nodes[0], 0);
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	do_commitment_signed_dance(&nodes[0], &nodes[1], &commitment_signed_b2, false, false);
	expect_payment_sent!(nodes[0], payment_preimage_2);
}

fn do_test_outbound_reload_without_init_mon(use_0conf: bool) {
	// Test that if the monitor update generated in funding_signed is stored async and we restart
	// with the latest ChannelManager but the ChannelMonitor persistence never completed we happily
	// drop the channel and move on.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);

	let persister;
	let new_chain_monitor;

	let mut chan_config = test_default_channel_config();
	chan_config.channel_handshake_limits.trust_own_funding_0conf = true;

	let node_chanmgrs =
		create_node_chanmgrs(2, &node_cfgs, &[Some(chan_config.clone()), Some(chan_config)]);
	let node_a_reload;

	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	nodes[0].node.create_channel(node_b_id, 100000, 10001, 43, None, None).unwrap();
	nodes[1].node.handle_open_channel(
		node_a_id,
		&get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, node_b_id),
	);

	let events = nodes[1].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		Event::OpenChannelRequest { temporary_channel_id: chan_id, .. } => {
			if use_0conf {
				nodes[1]
					.node
					.accept_inbound_channel_from_trusted_peer_0conf(&chan_id, &node_a_id, 0, None)
					.unwrap();
			} else {
				nodes[1].node.accept_inbound_channel(&chan_id, &node_a_id, 0, None).unwrap();
			}
		},
		_ => panic!("Unexpected event"),
	};

	nodes[0].node.handle_accept_channel(
		node_b_id,
		&get_event_msg!(nodes[1], MessageSendEvent::SendAcceptChannel, node_a_id),
	);

	let (temporary_channel_id, funding_tx, ..) =
		create_funding_transaction(&nodes[0], &node_b_id, 100000, 43);

	nodes[0]
		.node
		.funding_transaction_generated(temporary_channel_id, node_b_id, funding_tx.clone())
		.unwrap();
	check_added_monitors(&nodes[0], 0);

	let funding_created_msg =
		get_event_msg!(nodes[0], MessageSendEvent::SendFundingCreated, node_b_id);
	nodes[1].node.handle_funding_created(node_a_id, &funding_created_msg);
	check_added_monitors(&nodes[1], 1);
	expect_channel_pending_event(&nodes[1], &node_a_id);

	let bs_signed_locked = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(bs_signed_locked.len(), if use_0conf { 2 } else { 1 });
	match &bs_signed_locked[0] {
		MessageSendEvent::SendFundingSigned { msg, .. } => {
			chanmon_cfgs[0].persister.set_update_ret(ChannelMonitorUpdateStatus::InProgress);

			nodes[0].node.handle_funding_signed(node_b_id, &msg);
			check_added_monitors(&nodes[0], 1);
		},
		_ => panic!("Unexpected event"),
	}
	if use_0conf {
		match &bs_signed_locked[1] {
			MessageSendEvent::SendChannelReady { msg, .. } => {
				nodes[0].node.handle_channel_ready(node_b_id, &msg);
			},
			_ => panic!("Unexpected event"),
		}
	}

	assert!(nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().is_empty());
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	assert!(nodes[0].node.get_and_clear_pending_events().is_empty());

	// nodes[0] is now waiting on the first ChannelMonitor persistence to complete in order to
	// broadcast the funding transaction. If nodes[0] restarts at this point with the
	// ChannelMonitor lost, we should simply discard the channel.

	// The test framework checks that watched_txn/outputs match the monitor set, which they will
	// not, so we have to clear them here.
	nodes[0].chain_source.watched_txn.lock().unwrap().clear();
	nodes[0].chain_source.watched_outputs.lock().unwrap().clear();

	let node_a_ser = nodes[0].node.encode();
	reload_node!(nodes[0], &node_a_ser, &[], persister, new_chain_monitor, node_a_reload);
	check_closed_event(&nodes[0], 1, ClosureReason::DisconnectedPeer, &[node_b_id], 100000);
	assert!(nodes[0].node.list_channels().is_empty());
}

#[test]
fn test_outbound_reload_without_init_mon() {
	do_test_outbound_reload_without_init_mon(true);
	do_test_outbound_reload_without_init_mon(false);
}

fn do_test_inbound_reload_without_init_mon(use_0conf: bool, lock_commitment: bool) {
	// Test that if the monitor update generated by funding_transaction_generated is stored async
	// and we restart with the latest ChannelManager but the ChannelMonitor persistence never
	// completed we happily drop the channel and move on.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);

	let persister;
	let new_chain_monitor;

	let mut chan_config = test_default_channel_config();
	chan_config.channel_handshake_limits.trust_own_funding_0conf = true;

	let node_chanmgrs =
		create_node_chanmgrs(2, &node_cfgs, &[Some(chan_config.clone()), Some(chan_config)]);
	let node_b_reload;

	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	nodes[0].node.create_channel(node_b_id, 100000, 10001, 43, None, None).unwrap();
	nodes[1].node.handle_open_channel(
		node_a_id,
		&get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, node_b_id),
	);

	let events = nodes[1].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		Event::OpenChannelRequest { temporary_channel_id: chan_id, .. } => {
			if use_0conf {
				nodes[1]
					.node
					.accept_inbound_channel_from_trusted_peer_0conf(&chan_id, &node_a_id, 0, None)
					.unwrap();
			} else {
				nodes[1].node.accept_inbound_channel(&chan_id, &node_a_id, 0, None).unwrap();
			}
		},
		_ => panic!("Unexpected event"),
	};

	nodes[0].node.handle_accept_channel(
		node_b_id,
		&get_event_msg!(nodes[1], MessageSendEvent::SendAcceptChannel, node_a_id),
	);

	let (temporary_channel_id, funding_tx, ..) =
		create_funding_transaction(&nodes[0], &node_b_id, 100000, 43);

	nodes[0]
		.node
		.funding_transaction_generated(temporary_channel_id, node_b_id, funding_tx.clone())
		.unwrap();
	check_added_monitors(&nodes[0], 0);

	let funding_created_msg =
		get_event_msg!(nodes[0], MessageSendEvent::SendFundingCreated, node_b_id);
	chanmon_cfgs[1].persister.set_update_ret(ChannelMonitorUpdateStatus::InProgress);
	nodes[1].node.handle_funding_created(node_a_id, &funding_created_msg);
	check_added_monitors(&nodes[1], 1);

	// nodes[1] happily sends its funding_signed even though its awaiting the persistence of the
	// initial ChannelMonitor, but it will decline to send its channel_ready even if the funding
	// transaction is confirmed.
	let funding_signed_msg =
		get_event_msg!(nodes[1], MessageSendEvent::SendFundingSigned, node_a_id);

	nodes[0].node.handle_funding_signed(node_b_id, &funding_signed_msg);
	check_added_monitors(&nodes[0], 1);
	expect_channel_pending_event(&nodes[0], &node_b_id);

	let as_funding_tx = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().split_off(0);
	if lock_commitment {
		confirm_transaction(&nodes[0], &as_funding_tx[0]);
		confirm_transaction(&nodes[1], &as_funding_tx[0]);
	}
	if use_0conf || lock_commitment {
		let as_ready = get_event_msg!(nodes[0], MessageSendEvent::SendChannelReady, node_b_id);
		nodes[1].node.handle_channel_ready(node_a_id, &as_ready);
	}
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	// nodes[1] is now waiting on the first ChannelMonitor persistence to complete in order to
	// move the channel to ready (or is waiting on the funding transaction to confirm). If nodes[1]
	// restarts at this point with the ChannelMonitor lost, we should simply discard the channel.

	// The test framework checks that watched_txn/outputs match the monitor set, which they will
	// not, so we have to clear them here.
	nodes[1].chain_source.watched_txn.lock().unwrap().clear();
	nodes[1].chain_source.watched_outputs.lock().unwrap().clear();

	let node_b_ser = nodes[1].node.encode();
	reload_node!(nodes[1], &node_b_ser, &[], persister, new_chain_monitor, node_b_reload);

	check_closed_event(&nodes[1], 1, ClosureReason::DisconnectedPeer, &[node_a_id], 100000);
	assert!(nodes[1].node.list_channels().is_empty());
}

#[test]
fn test_inbound_reload_without_init_mon() {
	do_test_inbound_reload_without_init_mon(true, true);
	do_test_inbound_reload_without_init_mon(true, false);
	do_test_inbound_reload_without_init_mon(false, true);
	do_test_inbound_reload_without_init_mon(false, false);
}

#[derive(PartialEq, Eq)]
enum BlockedUpdateComplMode {
	Async,
	AtReload,
	Sync,
}

fn do_test_blocked_chan_preimage_release(completion_mode: BlockedUpdateComplMode) {
	// Test that even if a channel's `ChannelMonitorUpdate` flow is blocked waiting on an event to
	// be handled HTLC preimage `ChannelMonitorUpdate`s will still go out.
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let persister;
	let new_chain_mon;
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let nodes_1_reload;
	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();
	let node_c_id = nodes[2].node.get_our_node_id();

	let chan_id_1 = create_announced_chan_between_nodes(&nodes, 0, 1).2;
	let chan_id_2 = create_announced_chan_between_nodes(&nodes, 1, 2).2;

	send_payment(&nodes[0], &[&nodes[1], &nodes[2]], 5_000_000);

	// Tee up two payments in opposite directions across nodes[1], one it sent to generate a
	// PaymentSent event and one it forwards.
	let (payment_preimage_1, payment_hash_1, ..) =
		route_payment(&nodes[1], &[&nodes[2]], 1_000_000);
	let (payment_preimage_2, payment_hash_2, ..) =
		route_payment(&nodes[2], &[&nodes[1], &nodes[0]], 1_000_000);

	// Claim the first payment to get a `PaymentSent` event (but don't handle it yet).
	nodes[2].node.claim_funds(payment_preimage_1);
	check_added_monitors(&nodes[2], 1);
	expect_payment_claimed!(nodes[2], payment_hash_1, 1_000_000);

	let mut cs_htlc_fulfill = get_htlc_update_msgs(&nodes[2], &node_b_id);
	nodes[1]
		.node
		.handle_update_fulfill_htlc(node_c_id, cs_htlc_fulfill.update_fulfill_htlcs.remove(0));
	let commitment = cs_htlc_fulfill.commitment_signed;
	do_commitment_signed_dance(&nodes[1], &nodes[2], &commitment, false, false);
	check_added_monitors(&nodes[1], 0);

	// Now claim the second payment on nodes[0], which will ultimately result in nodes[1] trying to
	// claim an HTLC on its channel with nodes[2], but that channel is blocked on the above
	// `PaymentSent` event.
	nodes[0].node.claim_funds(payment_preimage_2);
	check_added_monitors(&nodes[0], 1);
	expect_payment_claimed!(nodes[0], payment_hash_2, 1_000_000);

	let mut as_htlc_fulfill = get_htlc_update_msgs(&nodes[0], &node_b_id);
	if completion_mode != BlockedUpdateComplMode::Sync {
		// We use to incorrectly handle monitor update completion in cases where we completed a
		// monitor update async or after reload. We test both based on the `completion_mode`.
		chanmon_cfgs[1].persister.set_update_ret(ChannelMonitorUpdateStatus::InProgress);
	}
	nodes[1]
		.node
		.handle_update_fulfill_htlc(node_a_id, as_htlc_fulfill.update_fulfill_htlcs.remove(0));
	check_added_monitors(&nodes[1], 1); // We generate only a preimage monitor update
	assert!(get_monitor!(nodes[1], chan_id_2).get_stored_preimages().contains_key(&payment_hash_2));
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	if completion_mode == BlockedUpdateComplMode::AtReload {
		let node_ser = nodes[1].node.encode();
		let chan_mon_0 = get_monitor!(nodes[1], chan_id_1).encode();
		let chan_mon_1 = get_monitor!(nodes[1], chan_id_2).encode();

		let mons = &[&chan_mon_0[..], &chan_mon_1[..]];
		reload_node!(nodes[1], &node_ser, mons, persister, new_chain_mon, nodes_1_reload);

		nodes[0].node.peer_disconnected(node_b_id);
		nodes[2].node.peer_disconnected(node_b_id);

		let mut a_b_reconnect = ReconnectArgs::new(&nodes[0], &nodes[1]);
		a_b_reconnect.pending_htlc_claims.1 = 1;
		// Note that we will expect no final RAA monitor update in
		// `commitment_signed_dance_through_cp_raa` during the reconnect, matching the below case.
		reconnect_nodes(a_b_reconnect);
		reconnect_nodes(ReconnectArgs::new(&nodes[2], &nodes[1]));
	} else if completion_mode == BlockedUpdateComplMode::Async {
		let (latest_update, _) = get_latest_mon_update_id(&nodes[1], chan_id_2);
		nodes[1]
			.chain_monitor
			.chain_monitor
			.channel_monitor_updated(chan_id_2, latest_update)
			.unwrap();
	}

	// Finish the CS dance between nodes[0] and nodes[1]. Note that until the event handling, the
	// update_fulfill_htlc + CS is held, even though the preimage is already on disk for the
	// channel.
	// Note that when completing as a side effect of a reload we completed the CS dance in
	// `reconnect_nodes` above.
	if completion_mode != BlockedUpdateComplMode::AtReload {
		nodes[1]
			.node
			.handle_commitment_signed_batch_test(node_a_id, &as_htlc_fulfill.commitment_signed);
		check_added_monitors(&nodes[1], 1);
		let (a, raa) = do_main_commitment_signed_dance(&nodes[1], &nodes[0], false);
		assert!(a.is_none());

		nodes[1].node.handle_revoke_and_ack(node_a_id, &raa);
		check_added_monitors(&nodes[1], 1);
		assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	}

	let events = nodes[1].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 3, "{events:?}");
	if let Event::PaymentSent { .. } = events[0] {
	} else {
		panic!();
	}
	if let Event::PaymentPathSuccessful { .. } = events[2] {
	} else {
		panic!();
	}
	if let Event::PaymentForwarded { .. } = events[1] {
	} else {
		panic!();
	}

	// The event processing should release the last RAA update.
	// It should also generate the next update for nodes[2].
	check_added_monitors(&nodes[1], 2);
	let mut bs_htlc_fulfill = get_htlc_update_msgs(&nodes[1], &node_c_id);
	check_added_monitors(&nodes[1], 0);

	nodes[2]
		.node
		.handle_update_fulfill_htlc(node_b_id, bs_htlc_fulfill.update_fulfill_htlcs.remove(0));
	let commitment = bs_htlc_fulfill.commitment_signed;
	do_commitment_signed_dance(&nodes[2], &nodes[1], &commitment, false, false);
	expect_payment_sent(&nodes[2], payment_preimage_2, None, true, true);
}

#[test]
fn test_blocked_chan_preimage_release() {
	do_test_blocked_chan_preimage_release(BlockedUpdateComplMode::AtReload);
	do_test_blocked_chan_preimage_release(BlockedUpdateComplMode::Sync);
	do_test_blocked_chan_preimage_release(BlockedUpdateComplMode::Async);
}

fn do_test_inverted_mon_completion_order(
	with_latest_manager: bool, complete_bc_commitment_dance: bool,
) {
	// When we forward a payment and receive `update_fulfill_htlc`+`commitment_signed` messages
	// from the downstream channel, we immediately claim the HTLC on the upstream channel, before
	// even doing a `commitment_signed` dance on the downstream channel. This implies that our
	// `ChannelMonitorUpdate`s are generated in the right order - first we ensure we'll get our
	// money, then we write the update that resolves the downstream node claiming their money. This
	// is safe as long as `ChannelMonitorUpdate`s complete in the order in which they are
	// generated, but of course this may not be the case. For asynchronous update writes, we have
	// to ensure monitor updates can block each other, preventing the inversion all together.
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);

	let persister;
	let chain_mon;
	let node_b_reload;

	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();
	let node_c_id = nodes[2].node.get_our_node_id();

	let chan_id_ab = create_announced_chan_between_nodes(&nodes, 0, 1).2;
	let chan_id_bc = create_announced_chan_between_nodes(&nodes, 1, 2).2;

	// Route a payment from A, through B, to C, then claim it on C. Once we pass B the
	// `update_fulfill_htlc` we have a monitor update for both of B's channels. We complete the one
	// on the B<->C channel but leave the A<->B monitor update pending, then reload B.
	let (payment_preimage, payment_hash, ..) =
		route_payment(&nodes[0], &[&nodes[1], &nodes[2]], 100_000);

	let mon_ab = get_monitor!(nodes[1], chan_id_ab).encode();
	let mut manager_b = Vec::new();
	if !with_latest_manager {
		manager_b = nodes[1].node.encode();
	}

	nodes[2].node.claim_funds(payment_preimage);
	check_added_monitors(&nodes[2], 1);
	expect_payment_claimed!(nodes[2], payment_hash, 100_000);

	chanmon_cfgs[1].persister.set_update_ret(ChannelMonitorUpdateStatus::InProgress);
	let mut cs_updates = get_htlc_update_msgs(&nodes[2], &node_b_id);
	nodes[1].node.handle_update_fulfill_htlc(node_c_id, cs_updates.update_fulfill_htlcs.remove(0));

	// B generates a new monitor update for the A <-> B channel, but doesn't send the new messages
	// for it since the monitor update is marked in-progress.
	check_added_monitors(&nodes[1], 1);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	// Now step the Commitment Signed Dance between B and C forward a bit (or fully), ensuring we
	// won't get the preimage when the nodes reconnect and we have to get it from the
	// ChannelMonitor.
	nodes[1].node.handle_commitment_signed_batch_test(node_c_id, &cs_updates.commitment_signed);
	check_added_monitors(&nodes[1], 1);
	if complete_bc_commitment_dance {
		let (bs_revoke_and_ack, bs_commitment_signed) =
			get_revoke_commit_msgs(&nodes[1], &node_c_id);
		nodes[2].node.handle_revoke_and_ack(node_b_id, &bs_revoke_and_ack);
		check_added_monitors(&nodes[2], 1);
		nodes[2].node.handle_commitment_signed_batch_test(node_b_id, &bs_commitment_signed);
		check_added_monitors(&nodes[2], 1);
		let cs_raa = get_event_msg!(nodes[2], MessageSendEvent::SendRevokeAndACK, node_b_id);

		// At this point node B still hasn't persisted the `ChannelMonitorUpdate` with the
		// preimage in the A <-> B channel, which will prevent it from persisting the
		// `ChannelMonitorUpdate` for the B<->C channel here to avoid "losing" the preimage.
		nodes[1].node.handle_revoke_and_ack(node_c_id, &cs_raa);
		check_added_monitors(&nodes[1], 0);
		assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	}

	// Now reload node B
	if with_latest_manager {
		manager_b = nodes[1].node.encode();
	}

	let mon_bc = get_monitor!(nodes[1], chan_id_bc).encode();
	reload_node!(nodes[1], &manager_b, &[&mon_ab, &mon_bc], persister, chain_mon, node_b_reload);

	nodes[0].node.peer_disconnected(node_b_id);
	nodes[2].node.peer_disconnected(node_b_id);

	if with_latest_manager {
		// If we used the latest ChannelManager to reload from, we should have both channels still
		// live. The B <-> C channel's final RAA ChannelMonitorUpdate must still be blocked as
		// before - the ChannelMonitorUpdate for the A <-> B channel hasn't completed.
		// When we call `timer_tick_occurred` we will get that monitor update back, which we'll
		// complete after reconnecting to our peers.
		persister.set_update_ret(ChannelMonitorUpdateStatus::InProgress);
		nodes[1].node.timer_tick_occurred();
		check_added_monitors(&nodes[1], 1);
		assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

		// Now reconnect B to both A and C. If the B <-> C commitment signed dance wasn't run to
		// the end go ahead and do that, though the
		// `pending_responding_commitment_signed_dup_monitor` in `reconnect_args` indicates that we
		// expect to *not* receive the final RAA ChannelMonitorUpdate.
		if complete_bc_commitment_dance {
			reconnect_nodes(ReconnectArgs::new(&nodes[1], &nodes[2]));
		} else {
			let mut reconnect_args = ReconnectArgs::new(&nodes[1], &nodes[2]);
			reconnect_args.pending_responding_commitment_signed.1 = true;
			reconnect_args.pending_responding_commitment_signed_dup_monitor.1 = true;
			reconnect_args.pending_raa = (false, true);
			reconnect_nodes(reconnect_args);
		}

		reconnect_nodes(ReconnectArgs::new(&nodes[0], &nodes[1]));

		// (Finally) complete the A <-> B ChannelMonitorUpdate, ensuring the preimage is durably on
		// disk in the proper ChannelMonitor, unblocking the B <-> C ChannelMonitor updating
		// process.
		let (_, ab_update_id) = get_latest_mon_update_id(&nodes[1], chan_id_ab);
		nodes[1]
			.chain_monitor
			.chain_monitor
			.channel_monitor_updated(chan_id_ab, ab_update_id)
			.unwrap();

	// When we fetch B's HTLC update messages next (now that the ChannelMonitorUpdate has
	// completed), it will also release the final RAA ChannelMonitorUpdate on the B <-> C
	// channel.
	} else {
		// If the ChannelManager used in the reload was stale, check that the B <-> C channel was
		// closed.
		//
		// Note that this will also process the ChannelMonitorUpdates which were queued up when we
		// reloaded the ChannelManager. This will re-emit the A<->B preimage as well as the B<->C
		// force-closure ChannelMonitorUpdate. Once the A<->B preimage update completes, the claim
		// commitment update will be allowed to go out.
		check_added_monitors(&nodes[1], 0);
		persister.set_update_ret(ChannelMonitorUpdateStatus::InProgress);
		persister.set_update_ret(ChannelMonitorUpdateStatus::InProgress);
		let reason = ClosureReason::OutdatedChannelManager;
		check_closed_event(&nodes[1], 1, reason, &[node_c_id], 100_000);
		check_added_monitors(&nodes[1], 2);

		nodes[1].node.timer_tick_occurred();
		check_added_monitors(&nodes[1], 0);

		// Don't bother to reconnect B to C - that channel has been closed. We don't need to
		// exchange any messages here even though there's a pending commitment update because the
		// ChannelMonitorUpdate hasn't yet completed.
		reconnect_nodes(ReconnectArgs::new(&nodes[0], &nodes[1]));

		let (_, ab_update_id) = get_latest_mon_update_id(&nodes[1], chan_id_ab);
		nodes[1]
			.chain_monitor
			.chain_monitor
			.channel_monitor_updated(chan_id_ab, ab_update_id)
			.unwrap();

		// The ChannelMonitorUpdate which was completed prior to the reconnect only contained the
		// preimage (as it was a replay of the original ChannelMonitorUpdate from before we
		// restarted). When we go to fetch the commitment transaction updates we'll poll the
		// ChannelMonitorUpdate completion, then generate (and complete) a new ChannelMonitorUpdate
		// with the actual commitment transaction, which will allow us to fulfill the HTLC with
		// node A.
	}

	let mut bs_updates = get_htlc_update_msgs(&nodes[1], &node_a_id);
	check_added_monitors(&nodes[1], 1);

	nodes[0].node.handle_update_fulfill_htlc(node_b_id, bs_updates.update_fulfill_htlcs.remove(0));
	do_commitment_signed_dance(&nodes[0], &nodes[1], &bs_updates.commitment_signed, false, false);

	expect_payment_forwarded!(
		nodes[1],
		&nodes[0],
		&nodes[2],
		Some(1_000),
		false,
		!with_latest_manager
	);

	// Finally, check that the payment was, ultimately, seen as sent by node A.
	expect_payment_sent(&nodes[0], payment_preimage, None, true, true);
}

#[test]
fn test_inverted_mon_completion_order() {
	do_test_inverted_mon_completion_order(true, true);
	do_test_inverted_mon_completion_order(true, false);
	do_test_inverted_mon_completion_order(false, true);
	do_test_inverted_mon_completion_order(false, false);
}

fn do_test_durable_preimages_on_closed_channel(
	close_chans_before_reload: bool, close_only_a: bool, hold_post_reload_mon_update: bool,
) {
	// Test that we can apply a `ChannelMonitorUpdate` with a payment preimage even if the channel
	// is force-closed between when we generate the update on reload and when we go to handle the
	// update or prior to generating the update at all.

	if !close_chans_before_reload && close_only_a {
		// If we're not closing, it makes no sense to "only close A"
		panic!();
	}

	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);

	let persister;
	let chain_mon;
	let node_b_reload;

	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();
	let node_c_id = nodes[2].node.get_our_node_id();

	let chan_id_ab = create_announced_chan_between_nodes(&nodes, 0, 1).2;
	let chan_id_bc = create_announced_chan_between_nodes(&nodes, 1, 2).2;

	// Route a payment from A, through B, to C, then claim it on C. Once we pass B the
	// `update_fulfill_htlc` we have a monitor update for both of B's channels. We complete the one
	// on the B<->C channel but leave the A<->B monitor update pending, then reload B.
	let (payment_preimage, payment_hash, ..) =
		route_payment(&nodes[0], &[&nodes[1], &nodes[2]], 1_000_000);

	let mon_ab = get_monitor!(nodes[1], chan_id_ab).encode();

	nodes[2].node.claim_funds(payment_preimage);
	check_added_monitors(&nodes[2], 1);
	expect_payment_claimed!(nodes[2], payment_hash, 1_000_000);

	chanmon_cfgs[1].persister.set_update_ret(ChannelMonitorUpdateStatus::InProgress);
	let mut cs_updates = get_htlc_update_msgs(&nodes[2], &node_b_id);
	nodes[1].node.handle_update_fulfill_htlc(node_c_id, cs_updates.update_fulfill_htlcs.remove(0));

	// B generates a new monitor update for the A <-> B channel, but doesn't send the new messages
	// for it since the monitor update is marked in-progress.
	check_added_monitors(&nodes[1], 1);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	// Now step the Commitment Signed Dance between B and C forward a bit, ensuring we won't get
	// the preimage when the nodes reconnect, at which point we have to ensure we get it from the
	// ChannelMonitor.
	nodes[1].node.handle_commitment_signed_batch_test(node_c_id, &cs_updates.commitment_signed);
	check_added_monitors(&nodes[1], 1);
	let _ = get_revoke_commit_msgs(&nodes[1], &node_c_id);

	let mon_bc = get_monitor!(nodes[1], chan_id_bc).encode();

	if close_chans_before_reload {
		if !close_only_a {
			chanmon_cfgs[1].persister.set_update_ret(ChannelMonitorUpdateStatus::InProgress);
			let message = "Channel force-closed".to_owned();
			nodes[1]
				.node
				.force_close_broadcasting_latest_txn(&chan_id_bc, &node_c_id, message.clone())
				.unwrap();
			check_closed_broadcast(&nodes[1], 1, true);
			let reason =
				ClosureReason::HolderForceClosed { broadcasted_latest_txn: Some(true), message };
			check_closed_event(&nodes[1], 1, reason, &[node_c_id], 100000);
		}

		chanmon_cfgs[1].persister.set_update_ret(ChannelMonitorUpdateStatus::InProgress);
		let message = "Channel force-closed".to_owned();
		nodes[1]
			.node
			.force_close_broadcasting_latest_txn(&chan_id_ab, &node_a_id, message.clone())
			.unwrap();
		check_closed_broadcast(&nodes[1], 1, true);
		let reason =
			ClosureReason::HolderForceClosed { broadcasted_latest_txn: Some(true), message };
		check_closed_event(&nodes[1], 1, reason, &[node_a_id], 100000);
	}

	// Now reload node B
	let manager_b = nodes[1].node.encode();
	reload_node!(nodes[1], &manager_b, &[&mon_ab, &mon_bc], persister, chain_mon, node_b_reload);

	nodes[0].node.peer_disconnected(node_b_id);
	nodes[2].node.peer_disconnected(node_b_id);

	if close_chans_before_reload {
		// If the channels were already closed, B will rebroadcast its closing transactions here.
		let bs_close_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().split_off(0);
		if close_only_a {
			assert_eq!(bs_close_txn.len(), 2);
		} else {
			assert_eq!(bs_close_txn.len(), 3);
		}
	}

	let err_msg = "Channel force-closed".to_owned();
	let reason = ClosureReason::HolderForceClosed {
		broadcasted_latest_txn: Some(true),
		message: err_msg.clone(),
	};
	nodes[0].node.force_close_broadcasting_latest_txn(&chan_id_ab, &node_b_id, err_msg).unwrap();
	check_closed_event(&nodes[0], 1, reason, &[node_b_id], 100000);
	check_added_monitors(&nodes[0], 1);
	let as_closing_tx = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().split_off(0);
	assert_eq!(as_closing_tx.len(), 1);

	// In order to give A's closing transaction to B without processing background events first,
	// use the _without_consistency_checks utility method. This is similar to connecting blocks
	// during startup prior to the node being full initialized.
	mine_transaction_without_consistency_checks(&nodes[1], &as_closing_tx[0]);

	// After a timer tick a payment preimage ChannelMonitorUpdate is applied to the A<->B
	// ChannelMonitor (possible twice), even though the channel has since been closed.
	check_added_monitors(&nodes[1], 0);
	let mons_added = if close_chans_before_reload {
		if !close_only_a {
			4
		} else {
			3
		}
	} else {
		2
	};
	if hold_post_reload_mon_update {
		for _ in 0..mons_added {
			persister.set_update_ret(ChannelMonitorUpdateStatus::InProgress);
		}
	}
	if !close_chans_before_reload {
		check_closed_broadcast(&nodes[1], 1, false);
		let reason = ClosureReason::CommitmentTxConfirmed;
		check_closed_event(&nodes[1], 1, reason, &[node_a_id], 100000);
	}
	nodes[1].node.timer_tick_occurred();
	check_added_monitors(&nodes[1], mons_added);

	// Finally, check that B created a payment preimage transaction and close out the payment.
	let bs_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().split_off(0);
	assert_eq!(bs_txn.len(), if close_chans_before_reload && !close_only_a { 2 } else { 1 });
	let bs_preimage_tx = bs_txn
		.iter()
		.find(|tx| tx.input[0].previous_output.txid == as_closing_tx[0].compute_txid())
		.unwrap();
	check_spends!(bs_preimage_tx, as_closing_tx[0]);

	mine_transactions(&nodes[0], &[&as_closing_tx[0], bs_preimage_tx]);
	check_closed_broadcast(&nodes[0], 1, false);
	expect_payment_sent(&nodes[0], payment_preimage, None, true, true);

	if !close_chans_before_reload || close_only_a {
		// Make sure the B<->C channel is still alive and well by sending a payment over it.
		let mut reconnect_args = ReconnectArgs::new(&nodes[1], &nodes[2]);
		reconnect_args.pending_responding_commitment_signed.1 = true;
		// The B<->C `ChannelMonitorUpdate` shouldn't be allowed to complete, which is the
		// equivalent to the responding `commitment_signed` being a duplicate for node B, thus we
		// need to set the `pending_responding_commitment_signed_dup` flag.
		reconnect_args.pending_responding_commitment_signed_dup_monitor.1 = true;
		reconnect_args.pending_raa.1 = true;

		reconnect_nodes(reconnect_args);
	}

	// Once the blocked `ChannelMonitorUpdate` *finally* completes, the pending
	// `PaymentForwarded` event will finally be released.
	let (_, ab_update_id) = get_latest_mon_update_id(&nodes[1], chan_id_ab);
	nodes[1].chain_monitor.chain_monitor.force_channel_monitor_updated(chan_id_ab, ab_update_id);

	// If the A<->B channel was closed before we reload, we'll replay the claim against it on
	// reload, causing the `PaymentForwarded` event to get replayed.
	let evs = nodes[1].node.get_and_clear_pending_events();
	assert_eq!(evs.len(), if close_chans_before_reload { 2 } else { 1 });
	for ev in evs {
		if let Event::PaymentForwarded { .. } = ev {
		} else {
			panic!();
		}
	}

	if !close_chans_before_reload || close_only_a {
		// Once we call `process_pending_events` the final `ChannelMonitor` for the B<->C channel
		// will fly, removing the payment preimage from it.
		check_added_monitors(&nodes[1], 1);
		assert!(nodes[1].node.get_and_clear_pending_events().is_empty());
		send_payment(&nodes[1], &[&nodes[2]], 100_000);
	}
}

#[test]
fn test_durable_preimages_on_closed_channel() {
	do_test_durable_preimages_on_closed_channel(true, true, true);
	do_test_durable_preimages_on_closed_channel(true, true, false);
	do_test_durable_preimages_on_closed_channel(true, false, true);
	do_test_durable_preimages_on_closed_channel(true, false, false);
	do_test_durable_preimages_on_closed_channel(false, false, true);
	do_test_durable_preimages_on_closed_channel(false, false, false);
}

fn do_test_reload_mon_update_completion_actions(close_during_reload: bool) {
	// Test that if a `ChannelMonitorUpdate` completes but a `ChannelManager` isn't serialized
	// before restart we run the monitor update completion action on startup.
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);

	let persister;
	let chain_mon;
	let node_b_reload;

	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	let node_b_id = nodes[1].node.get_our_node_id();
	let node_c_id = nodes[2].node.get_our_node_id();

	let chan_id_ab = create_announced_chan_between_nodes(&nodes, 0, 1).2;
	let chan_id_bc = create_announced_chan_between_nodes(&nodes, 1, 2).2;

	// Route a payment from A, through B, to C, then claim it on C. Once we pass B the
	// `update_fulfill_htlc`+`commitment_signed` we have a monitor update for both of B's channels.
	// We complete the commitment signed dance on the B<->C channel but leave the A<->B monitor
	// update pending, then reload B. At that point, the final monitor update on the B<->C channel
	// is still pending because it can't fly until the preimage is persisted on the A<->B monitor.
	let (payment_preimage, payment_hash, ..) =
		route_payment(&nodes[0], &[&nodes[1], &nodes[2]], 1_000_000);

	nodes[2].node.claim_funds(payment_preimage);
	check_added_monitors(&nodes[2], 1);
	expect_payment_claimed!(nodes[2], payment_hash, 1_000_000);

	chanmon_cfgs[1].persister.set_update_ret(ChannelMonitorUpdateStatus::InProgress);
	let mut cs_updates = get_htlc_update_msgs(&nodes[2], &node_b_id);
	nodes[1].node.handle_update_fulfill_htlc(node_c_id, cs_updates.update_fulfill_htlcs.remove(0));

	// B generates a new monitor update for the A <-> B channel, but doesn't send the new messages
	// for it since the monitor update is marked in-progress.
	check_added_monitors(&nodes[1], 1);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	// Now step the Commitment Signed Dance between B and C and check that after the final RAA B
	// doesn't let the preimage-removing monitor update fly.
	nodes[1].node.handle_commitment_signed_batch_test(node_c_id, &cs_updates.commitment_signed);
	check_added_monitors(&nodes[1], 1);
	let (bs_raa, bs_cs) = get_revoke_commit_msgs(&nodes[1], &node_c_id);

	nodes[2].node.handle_revoke_and_ack(node_b_id, &bs_raa);
	check_added_monitors(&nodes[2], 1);
	nodes[2].node.handle_commitment_signed_batch_test(node_b_id, &bs_cs);
	check_added_monitors(&nodes[2], 1);

	let cs_final_raa = get_event_msg!(nodes[2], MessageSendEvent::SendRevokeAndACK, node_b_id);
	nodes[1].node.handle_revoke_and_ack(node_c_id, &cs_final_raa);
	check_added_monitors(&nodes[1], 0);

	// Finally, reload node B and check that after we call `process_pending_events` once we realize
	// we've completed the A<->B preimage-including monitor update and so can release the B<->C
	// preimage-removing monitor update.
	let mon_ab = get_monitor!(nodes[1], chan_id_ab).encode();
	let mon_bc = get_monitor!(nodes[1], chan_id_bc).encode();
	let manager_b = nodes[1].node.encode();
	reload_node!(nodes[1], &manager_b, &[&mon_ab, &mon_bc], persister, chain_mon, node_b_reload);

	let msg = "Channel force-closed".to_owned();
	if close_during_reload {
		// Test that we still free the B<->C channel if the A<->B channel closed while we reloaded
		// (as learned about during the on-reload block connection).
		let reason = ClosureReason::HolderForceClosed {
			broadcasted_latest_txn: Some(true),
			message: msg.clone(),
		};
		nodes[0].node.force_close_broadcasting_latest_txn(&chan_id_ab, &node_b_id, msg).unwrap();
		check_added_monitors(&nodes[0], 1);
		check_closed_broadcast!(nodes[0], true);
		check_closed_event(&nodes[0], 1, reason, &[node_b_id], 100_000);
		let as_closing_tx = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().split_off(0);
		mine_transaction_without_consistency_checks(&nodes[1], &as_closing_tx[0]);
	}

	let (_, bc_update_id) = get_latest_mon_update_id(&nodes[1], chan_id_bc);
	let mut events = nodes[1].node.get_and_clear_pending_events();
	assert_eq!(events.len(), if close_during_reload { 2 } else { 1 });
	expect_payment_forwarded(
		events.remove(0),
		&nodes[1],
		&nodes[0],
		&nodes[2],
		Some(1000),
		None,
		close_during_reload,
		false,
		false,
	);
	if close_during_reload {
		match events[0] {
			Event::ChannelClosed { .. } => {},
			_ => panic!(),
		}
		check_closed_broadcast(&nodes[1], 1, false);
	}

	// Once we run event processing the monitor should free, check that it was indeed the B<->C
	// channel which was updated.
	check_added_monitors(&nodes[1], if close_during_reload { 2 } else { 1 });
	let (_, post_ev_bc_update_id) = get_latest_mon_update_id(&nodes[1], chan_id_bc);
	assert!(bc_update_id != post_ev_bc_update_id);

	// Finally, check that there's nothing left to do on B<->C reconnect and the channel operates
	// fine.
	nodes[2].node.peer_disconnected(node_b_id);
	reconnect_nodes(ReconnectArgs::new(&nodes[1], &nodes[2]));
	send_payment(&nodes[1], &[&nodes[2]], 100_000);
}

#[test]
fn test_reload_mon_update_completion_actions() {
	do_test_reload_mon_update_completion_actions(true);
	do_test_reload_mon_update_completion_actions(false);
}

fn do_test_glacial_peer_cant_hang(hold_chan_a: bool) {
	// Test that if a peer manages to send an `update_fulfill_htlc` message without a
	// `commitment_signed`, disconnects, then replays the `update_fulfill_htlc` message it doesn't
	// result in a channel hang. This was previously broken as the `DuplicateClaim` case wasn't
	// handled when claiming an HTLC and handling wasn't added when completion actions were added
	// (which must always complete at some point).
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);

	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();
	let node_c_id = nodes[2].node.get_our_node_id();

	let chan_id_ab = create_announced_chan_between_nodes(&nodes, 0, 1).2;
	let _chan_id_bc = create_announced_chan_between_nodes(&nodes, 1, 2).2;

	// Route a payment from A, through B, to C, then claim it on C. Replay the
	// `update_fulfill_htlc` twice on B to check that B doesn't hang.
	let (payment_preimage, payment_hash, ..) =
		route_payment(&nodes[0], &[&nodes[1], &nodes[2]], 1_000_000);

	nodes[2].node.claim_funds(payment_preimage);
	check_added_monitors(&nodes[2], 1);
	expect_payment_claimed!(nodes[2], payment_hash, 1_000_000);

	let mut cs_updates = get_htlc_update_msgs(&nodes[2], &node_b_id);
	if hold_chan_a {
		// The first update will be on the A <-> B channel, which we optionally allow to complete.
		chanmon_cfgs[1].persister.set_update_ret(ChannelMonitorUpdateStatus::InProgress);
	}
	nodes[1].node.handle_update_fulfill_htlc(node_c_id, cs_updates.update_fulfill_htlcs.remove(0));
	check_added_monitors(&nodes[1], 1);

	if !hold_chan_a {
		let mut bs_updates = get_htlc_update_msgs(&nodes[1], &node_a_id);
		let mut update_fulfill = bs_updates.update_fulfill_htlcs.remove(0);
		nodes[0].node.handle_update_fulfill_htlc(node_b_id, update_fulfill);
		let commitment = &bs_updates.commitment_signed;
		do_commitment_signed_dance(&nodes[0], &nodes[1], commitment, false, false);
		expect_payment_sent!(&nodes[0], payment_preimage);
	}

	nodes[1].node.peer_disconnected(node_c_id);
	nodes[2].node.peer_disconnected(node_b_id);

	let mut reconnect = ReconnectArgs::new(&nodes[1], &nodes[2]);
	reconnect.pending_htlc_claims = (1, 0);
	reconnect_nodes(reconnect);

	if !hold_chan_a {
		expect_payment_forwarded!(nodes[1], nodes[0], nodes[2], Some(1000), false, false);
		send_payment(&nodes[0], &[&nodes[1], &nodes[2]], 100_000);
	} else {
		assert!(nodes[1].node.get_and_clear_pending_events().is_empty());
		assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

		let (route, payment_hash_2, payment_preimage_2, payment_secret_2) =
			get_route_and_payment_hash!(&nodes[1], nodes[2], 1_000_000);

		// With the A<->B preimage persistence not yet complete, the B<->C channel is stuck
		// waiting.
		let onion_2 = RecipientOnionFields::secret_only(payment_secret_2);
		let id_2 = PaymentId(payment_hash_2.0);
		nodes[1].node.send_payment_with_route(route, payment_hash_2, onion_2, id_2).unwrap();
		check_added_monitors(&nodes[1], 0);

		assert!(nodes[1].node.get_and_clear_pending_events().is_empty());
		assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

		// ...but once we complete the A<->B channel preimage persistence, the B<->C channel
		// unlocks and we send both peers commitment updates.
		let (ab_update_id, _) = get_latest_mon_update_id(&nodes[1], chan_id_ab);
		assert!(nodes[1]
			.chain_monitor
			.chain_monitor
			.channel_monitor_updated(chan_id_ab, ab_update_id)
			.is_ok());

		let mut msg_events = nodes[1].node.get_and_clear_pending_msg_events();
		assert_eq!(msg_events.len(), 2);
		check_added_monitors(&nodes[1], 2);

		let mut c_update = msg_events
			.iter()
			.filter(
				|ev| matches!(ev, MessageSendEvent::UpdateHTLCs { node_id, .. } if *node_id == node_c_id),
			)
			.cloned()
			.collect::<Vec<_>>();
		let a_filtermap = |ev| {
			if let MessageSendEvent::UpdateHTLCs { node_id, channel_id: _, updates } = ev {
				if node_id == node_a_id {
					Some(updates)
				} else {
					None
				}
			} else {
				None
			}
		};
		let a_update = msg_events.drain(..).filter_map(|ev| a_filtermap(ev)).collect::<Vec<_>>();

		assert_eq!(a_update.len(), 1);
		assert_eq!(c_update.len(), 1);

		let update_fulfill = a_update[0].update_fulfill_htlcs[0].clone();
		nodes[0].node.handle_update_fulfill_htlc(node_b_id, update_fulfill);
		let commitment = &a_update[0].commitment_signed;
		do_commitment_signed_dance(&nodes[0], &nodes[1], commitment, false, false);
		expect_payment_sent(&nodes[0], payment_preimage, None, true, true);
		expect_payment_forwarded!(nodes[1], nodes[0], nodes[2], Some(1000), false, false);

		pass_along_path(
			&nodes[1],
			&[&nodes[2]],
			1_000_000,
			payment_hash_2,
			Some(payment_secret_2),
			c_update.pop().unwrap(),
			true,
			None,
		);
		claim_payment(&nodes[1], &[&nodes[2]], payment_preimage_2);
	}
}

#[test]
fn test_glacial_peer_cant_hang() {
	do_test_glacial_peer_cant_hang(false);
	do_test_glacial_peer_cant_hang(true);
}

fn do_test_partial_claim_mon_update_compl_actions(reload_a: bool, reload_b: bool) {
	// Test that if we have an MPP claim that we ensure the preimage for the claim is retained in
	// all the `ChannelMonitor`s until the preimage reaches every `ChannelMonitor` for a channel
	// which was a part of the MPP.
	let chanmon_cfgs = create_chanmon_cfgs(4);
	let node_cfgs = create_node_cfgs(4, &chanmon_cfgs);

	let (persister, persister_2, persister_3);
	let (new_chain_mon, new_chain_mon_2, new_chain_mon_3);
	let (nodes_3_reload, nodes_3_reload_2, nodes_3_reload_3);

	let node_chanmgrs = create_node_chanmgrs(4, &node_cfgs, &[None, None, None, None]);
	let mut nodes = create_network(4, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();
	let node_c_id = nodes[2].node.get_our_node_id();
	let node_d_id = nodes[3].node.get_our_node_id();

	let chan_1_scid = create_announced_chan_between_nodes(&nodes, 0, 1).0.contents.short_channel_id;
	let chan_2_scid = create_announced_chan_between_nodes(&nodes, 0, 2).0.contents.short_channel_id;
	let (chan_3_update, _, chan_3_id, ..) = create_announced_chan_between_nodes(&nodes, 1, 3);
	let chan_3_scid = chan_3_update.contents.short_channel_id;
	let (chan_4_update, _, chan_4_id, ..) = create_announced_chan_between_nodes(&nodes, 2, 3);
	let chan_4_scid = chan_4_update.contents.short_channel_id;

	let (mut route, payment_hash, preimage, payment_secret) =
		get_route_and_payment_hash!(&nodes[0], nodes[3], 100000);
	let path = route.paths[0].clone();
	route.paths.push(path);
	route.paths[0].hops[0].pubkey = node_b_id;
	route.paths[0].hops[0].short_channel_id = chan_1_scid;
	route.paths[0].hops[1].short_channel_id = chan_3_scid;
	route.paths[1].hops[0].pubkey = node_c_id;
	route.paths[1].hops[0].short_channel_id = chan_2_scid;
	route.paths[1].hops[1].short_channel_id = chan_4_scid;
	let paths = &[&[&nodes[1], &nodes[3]][..], &[&nodes[2], &nodes[3]][..]];
	send_along_route_with_secret(&nodes[0], route, paths, 200_000, payment_hash, payment_secret);

	// Store the monitor for channel 4 without the preimage to use on reload
	let chan_4_monitor_serialized = get_monitor!(nodes[3], chan_4_id).encode();
	// Claim along both paths, but only complete one of the two monitor updates.
	chanmon_cfgs[3].persister.set_update_ret(ChannelMonitorUpdateStatus::InProgress);
	chanmon_cfgs[3].persister.set_update_ret(ChannelMonitorUpdateStatus::InProgress);
	nodes[3].node.claim_funds(preimage);
	assert_eq!(nodes[3].node.get_and_clear_pending_msg_events(), Vec::new());
	assert_eq!(nodes[3].node.get_and_clear_pending_events(), Vec::new());
	check_added_monitors(&nodes[3], 2);

	// Complete the 1<->3 monitor update and play the commitment_signed dance forward until it
	// blocks.
	nodes[3].chain_monitor.complete_sole_pending_chan_update(&chan_3_id);
	let payment_claimed = nodes[3].node.get_and_clear_pending_events();
	assert_eq!(payment_claimed.len(), 1, "{payment_claimed:?}");
	if let Event::PaymentClaimed { payment_hash: ev_hash, .. } = &payment_claimed[0] {
		assert_eq!(*ev_hash, payment_hash);
	} else {
		panic!("{payment_claimed:?}");
	}
	let mut updates = get_htlc_update_msgs(&nodes[3], &node_b_id);

	nodes[1].node.handle_update_fulfill_htlc(node_d_id, updates.update_fulfill_htlcs.remove(0));
	check_added_monitors(&nodes[1], 1);
	expect_payment_forwarded!(nodes[1], nodes[0], nodes[3], Some(1000), false, false);
	let _bs_updates_for_a = get_htlc_update_msgs(&nodes[1], &node_a_id);

	nodes[1].node.handle_commitment_signed_batch_test(node_d_id, &updates.commitment_signed);
	check_added_monitors(&nodes[1], 1);
	let (bs_raa, bs_cs) = get_revoke_commit_msgs(&nodes[1], &node_d_id);

	nodes[3].node.handle_revoke_and_ack(node_b_id, &bs_raa);
	check_added_monitors(&nodes[3], 0);

	nodes[3].node.handle_commitment_signed_batch_test(node_b_id, &bs_cs);
	check_added_monitors(&nodes[3], 0);
	assert!(nodes[3].node.get_and_clear_pending_msg_events().is_empty());

	if reload_a {
		// After a reload (with the monitor not yet fully updated), the RAA should still be blocked
		// waiting until the monitor update completes.
		let node_ser = nodes[3].node.encode();
		let chan_3_monitor_serialized = get_monitor!(nodes[3], chan_3_id).encode();
		let mons = &[&chan_3_monitor_serialized[..], &chan_4_monitor_serialized[..]];
		reload_node!(nodes[3], &node_ser, mons, persister, new_chain_mon, nodes_3_reload);
		// The final update to channel 4 should be replayed.
		persister.set_update_ret(ChannelMonitorUpdateStatus::InProgress);
		assert!(nodes[3].node.get_and_clear_pending_msg_events().is_empty());
		check_added_monitors(&nodes[3], 1);

		// Because the HTLCs aren't yet cleared, the PaymentClaimed event will be replayed on
		// restart.
		let second_payment_claimed = nodes[3].node.get_and_clear_pending_events();
		assert_eq!(payment_claimed, second_payment_claimed);

		nodes[1].node.peer_disconnected(node_d_id);
		nodes[2].node.peer_disconnected(node_d_id);
		reconnect_nodes(ReconnectArgs::new(&nodes[1], &nodes[3]));
		reconnect_nodes(ReconnectArgs::new(&nodes[2], &nodes[3]));

		assert!(nodes[3].node.get_and_clear_pending_msg_events().is_empty());
	}

	// Now double-check that the preimage is still in the 1<->3 channel and complete the pending
	// monitor update, allowing node 3 to claim the payment on the 2<->3 channel. This also
	// unblocks the 1<->3 channel, allowing node 3 to release the two blocked monitor updates and
	// respond to the final commitment_signed.
	assert!(get_monitor!(nodes[3], chan_3_id).get_stored_preimages().contains_key(&payment_hash));
	assert!(nodes[3].node.get_and_clear_pending_events().is_empty());

	nodes[3].chain_monitor.complete_sole_pending_chan_update(&chan_4_id);
	let mut ds_msgs = nodes[3].node.get_and_clear_pending_msg_events();
	assert_eq!(ds_msgs.len(), 2, "{ds_msgs:?}");
	check_added_monitors(&nodes[3], 2);

	match remove_first_msg_event_to_node(&node_b_id, &mut ds_msgs) {
		MessageSendEvent::SendRevokeAndACK { msg, .. } => {
			nodes[1].node.handle_revoke_and_ack(node_d_id, &msg);
			check_added_monitors(&nodes[1], 1);
		},
		_ => panic!(),
	}

	match remove_first_msg_event_to_node(&node_c_id, &mut ds_msgs) {
		MessageSendEvent::UpdateHTLCs { mut updates, .. } => {
			let update_fulfill = updates.update_fulfill_htlcs.remove(0);
			nodes[2].node.handle_update_fulfill_htlc(node_d_id, update_fulfill);
			check_added_monitors(&nodes[2], 1);
			expect_payment_forwarded!(nodes[2], nodes[0], nodes[3], Some(1000), false, false);
			let _cs_updates_for_a = get_htlc_update_msgs(&nodes[2], &node_a_id);

			nodes[2]
				.node
				.handle_commitment_signed_batch_test(node_d_id, &updates.commitment_signed);
			check_added_monitors(&nodes[2], 1);
		},
		_ => panic!(),
	}

	let (cs_raa, cs_cs) = get_revoke_commit_msgs(&nodes[2], &node_d_id);

	nodes[3].node.handle_revoke_and_ack(node_c_id, &cs_raa);
	check_added_monitors(&nodes[3], 1);

	nodes[3].node.handle_commitment_signed_batch_test(node_c_id, &cs_cs);
	check_added_monitors(&nodes[3], 1);

	let ds_raa = get_event_msg!(nodes[3], MessageSendEvent::SendRevokeAndACK, node_c_id);
	nodes[2].node.handle_revoke_and_ack(node_d_id, &ds_raa);
	check_added_monitors(&nodes[2], 1);

	// Our current `ChannelMonitor`s store preimages one RAA longer than they need to. That's nice
	// for safety, but means we have to send one more payment here to wipe the preimage.
	assert!(get_monitor!(nodes[3], chan_3_id).get_stored_preimages().contains_key(&payment_hash));
	assert!(get_monitor!(nodes[3], chan_4_id).get_stored_preimages().contains_key(&payment_hash));

	if reload_b {
		// Ensure that the channel pause logic doesn't accidentally get restarted after a second
		// reload once the HTLCs for the first payment have been removed and the monitors
		// completed.
		let node_ser = nodes[3].node.encode();
		let chan_3_monitor_serialized = get_monitor!(nodes[3], chan_3_id).encode();
		let chan_4_monitor_serialized = get_monitor!(nodes[3], chan_4_id).encode();
		let mons = &[&chan_3_monitor_serialized[..], &chan_4_monitor_serialized[..]];
		reload_node!(nodes[3], &node_ser, mons, persister_2, new_chain_mon_2, nodes_3_reload_2);
		check_added_monitors(&nodes[3], 0);

		nodes[1].node.peer_disconnected(node_d_id);
		nodes[2].node.peer_disconnected(node_d_id);
		reconnect_nodes(ReconnectArgs::new(&nodes[1], &nodes[3]));
		reconnect_nodes(ReconnectArgs::new(&nodes[2], &nodes[3]));

		assert!(nodes[3].node.get_and_clear_pending_msg_events().is_empty());

		// Because the HTLCs aren't yet cleared, the PaymentClaimed event will be replayed on
		// restart.
		let third_payment_claimed = nodes[3].node.get_and_clear_pending_events();
		assert_eq!(payment_claimed, third_payment_claimed);
	}

	send_payment(&nodes[1], &[&nodes[3]], 100_000);
	assert!(!get_monitor!(nodes[3], chan_3_id).get_stored_preimages().contains_key(&payment_hash));

	if reload_b {
		// Ensure that the channel pause logic doesn't accidentally get restarted after a second
		// reload once the HTLCs for the first payment have been removed and the monitors
		// completed, even if only one of the two monitors still knows about the first payment.
		let node_ser = nodes[3].node.encode();
		let chan_3_monitor_serialized = get_monitor!(nodes[3], chan_3_id).encode();
		let chan_4_monitor_serialized = get_monitor!(nodes[3], chan_4_id).encode();
		let mons = &[&chan_3_monitor_serialized[..], &chan_4_monitor_serialized[..]];
		reload_node!(nodes[3], &node_ser, mons, persister_3, new_chain_mon_3, nodes_3_reload_3);
		check_added_monitors(&nodes[3], 0);

		nodes[1].node.peer_disconnected(node_d_id);
		nodes[2].node.peer_disconnected(node_d_id);
		reconnect_nodes(ReconnectArgs::new(&nodes[1], &nodes[3]));
		reconnect_nodes(ReconnectArgs::new(&nodes[2], &nodes[3]));

		assert!(nodes[3].node.get_and_clear_pending_msg_events().is_empty());

		// Because the HTLCs aren't yet cleared, the PaymentClaimed events for both payments will
		// be replayed on restart.
		// Use this as an opportunity to check the payment_ids are unique.
		let mut events = nodes[3].node.get_and_clear_pending_events();
		assert_eq!(events.len(), 2);
		events.retain(|ev| *ev != payment_claimed[0]);
		assert_eq!(events.len(), 1);
		if let Event::PaymentClaimed { payment_id: original_payment_id, .. } = &payment_claimed[0] {
			assert!(original_payment_id.is_some());
			if let Event::PaymentClaimed { amount_msat, payment_id, .. } = &events[0] {
				assert!(payment_id.is_some());
				assert_ne!(original_payment_id, payment_id);
				assert_eq!(*amount_msat, 100_000);
			} else {
				panic!("{events:?}");
			}
		} else {
			panic!("{events:?}");
		}

		send_payment(&nodes[1], &[&nodes[3]], 100_000);
	}

	send_payment(&nodes[2], &[&nodes[3]], 100_000);
	assert!(!get_monitor!(nodes[3], chan_4_id).get_stored_preimages().contains_key(&payment_hash));
}

#[test]
fn test_partial_claim_mon_update_compl_actions() {
	do_test_partial_claim_mon_update_compl_actions(true, true);
	do_test_partial_claim_mon_update_compl_actions(true, false);
	do_test_partial_claim_mon_update_compl_actions(false, true);
	do_test_partial_claim_mon_update_compl_actions(false, false);
}

#[test]
fn test_claim_to_closed_channel_blocks_forwarded_preimage_removal() {
	// One of the last features for async persistence we implemented was the correct blocking of
	// RAA(s) which remove a preimage from an outbound channel for a forwarded payment until the
	// preimage write makes it durably to the closed inbound channel.
	// This tests that behavior.
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();
	let node_c_id = nodes[2].node.get_our_node_id();

	// First open channels, route a payment, and force-close the first hop.
	let chan_a =
		create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 500_000_000);
	let chan_b =
		create_announced_chan_between_nodes_with_value(&nodes, 1, 2, 1_000_000, 500_000_000);

	let (payment_preimage, payment_hash, ..) =
		route_payment(&nodes[0], &[&nodes[1], &nodes[2]], 1_000_000);

	let message = "Channel force-closed".to_owned();
	nodes[0]
		.node
		.force_close_broadcasting_latest_txn(&chan_a.2, &node_b_id, message.clone())
		.unwrap();
	check_added_monitors(&nodes[0], 1);
	let a_reason = ClosureReason::HolderForceClosed { broadcasted_latest_txn: Some(true), message };
	check_closed_event(&nodes[0], 1, a_reason, &[node_b_id], 1000000);
	check_closed_broadcast!(nodes[0], true);

	let as_commit_tx = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().split_off(0);
	assert_eq!(as_commit_tx.len(), 1);

	mine_transaction(&nodes[1], &as_commit_tx[0]);
	check_closed_broadcast!(nodes[1], true);
	check_added_monitors(&nodes[1], 1);
	let b_reason = ClosureReason::CommitmentTxConfirmed;
	check_closed_event(&nodes[1], 1, b_reason, &[node_a_id], 1000000);

	// Now that B has a pending forwarded payment across it with the inbound edge on-chain, claim
	// the payment on C and give B the preimage for it.
	nodes[2].node.claim_funds(payment_preimage);
	check_added_monitors(&nodes[2], 1);
	expect_payment_claimed!(nodes[2], payment_hash, 1_000_000);

	let mut updates = get_htlc_update_msgs(&nodes[2], &node_b_id);
	chanmon_cfgs[1].persister.set_update_ret(ChannelMonitorUpdateStatus::InProgress);
	nodes[1].node.handle_update_fulfill_htlc(node_c_id, updates.update_fulfill_htlcs.remove(0));
	check_added_monitors(&nodes[1], 1);
	do_commitment_signed_dance(&nodes[1], &nodes[2], &updates.commitment_signed, false, false);

	// At this point nodes[1] has the preimage and is waiting for the `ChannelMonitorUpdate` for
	// channel A to hit disk. Until it does so, it shouldn't ever let the preimage dissapear from
	// channel B's `ChannelMonitor`
	assert!(get_monitor!(nodes[1], chan_b.2)
		.get_all_current_outbound_htlcs()
		.iter()
		.any(|(_, (_, preimage))| *preimage == Some(payment_preimage)));

	// Once we complete the `ChannelMonitorUpdate` on channel A, and the `ChannelManager` processes
	// background events (via `get_and_clear_pending_msg_events`), the final `ChannelMonitorUpdate`
	// will fly and we'll drop the preimage from channel B's `ChannelMonitor`. We'll also release
	// the `Event::PaymentForwarded`.
	check_added_monitors(&nodes[1], 0);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	assert!(nodes[1].node.get_and_clear_pending_events().is_empty());

	nodes[1].chain_monitor.complete_sole_pending_chan_update(&chan_a.2);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	check_added_monitors(&nodes[1], 1);
	assert!(!get_monitor!(nodes[1], chan_b.2)
		.get_all_current_outbound_htlcs()
		.iter()
		.any(|(_, (_, preimage))| *preimage == Some(payment_preimage)));
	expect_payment_forwarded!(nodes[1], nodes[0], nodes[2], None, true, false);
}

#[test]
fn test_claim_to_closed_channel_blocks_claimed_event() {
	// One of the last features for async persistence we implemented was the correct blocking of
	// event(s) until the preimage for a claimed HTLC is durably on disk in a ChannelMonitor for a
	// closed channel.
	// This tests that behavior.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	// First open channels, route a payment, and force-close the first hop.
	let chan_a =
		create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 500_000_000);

	let (payment_preimage, payment_hash, ..) = route_payment(&nodes[0], &[&nodes[1]], 1_000_000);

	let message = "Channel force-closed".to_owned();
	nodes[0]
		.node
		.force_close_broadcasting_latest_txn(&chan_a.2, &node_b_id, message.clone())
		.unwrap();
	check_added_monitors(&nodes[0], 1);
	let a_reason = ClosureReason::HolderForceClosed { broadcasted_latest_txn: Some(true), message };
	check_closed_event(&nodes[0], 1, a_reason, &[node_b_id], 1000000);
	check_closed_broadcast!(nodes[0], true);

	let as_commit_tx = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().split_off(0);
	assert_eq!(as_commit_tx.len(), 1);

	mine_transaction(&nodes[1], &as_commit_tx[0]);
	check_closed_broadcast!(nodes[1], true);
	check_added_monitors(&nodes[1], 1);
	let b_reason = ClosureReason::CommitmentTxConfirmed;
	check_closed_event(&nodes[1], 1, b_reason, &[node_a_id], 1000000);

	// Now that B has a pending payment with the inbound HTLC on a closed channel, claim the
	// payment on disk, but don't let the `ChannelMonitorUpdate` complete. This should prevent the
	// `Event::PaymentClaimed` from being generated.
	chanmon_cfgs[1].persister.set_update_ret(ChannelMonitorUpdateStatus::InProgress);
	nodes[1].node.claim_funds(payment_preimage);
	check_added_monitors(&nodes[1], 1);
	assert!(nodes[1].node.get_and_clear_pending_events().is_empty());

	// Once we complete the `ChannelMonitorUpdate` the `Event::PaymentClaimed` will become
	// available.
	nodes[1].chain_monitor.complete_sole_pending_chan_update(&chan_a.2);
	expect_payment_claimed!(nodes[1], payment_hash, 1_000_000);
}

#[test]
#[cfg(all(feature = "std", not(target_os = "windows")))]
fn test_single_channel_multiple_mpp() {
	use std::sync::atomic::{AtomicBool, Ordering};

	// Test what happens when we attempt to claim an MPP with many parts that came to us through
	// the same channel with a synchronous persistence interface which has very high latency.
	//
	// Previously, if a `revoke_and_ack` came in while we were still running in
	// `ChannelManager::claim_payment` we'd end up hanging waiting to apply a
	// `ChannelMonitorUpdate` until after it completed. See the commit which introduced this test
	// for more info.
	let chanmon_cfgs = create_chanmon_cfgs(9);
	let node_cfgs = create_node_cfgs(9, &chanmon_cfgs);
	let configs = [None, None, None, None, None, None, None, None, None];
	let node_chanmgrs = create_node_chanmgrs(9, &node_cfgs, &configs);
	let mut nodes = create_network(9, &node_cfgs, &node_chanmgrs);

	let node_b_id = nodes[1].node.get_our_node_id();
	let node_c_id = nodes[2].node.get_our_node_id();
	let node_d_id = nodes[3].node.get_our_node_id();
	let node_e_id = nodes[4].node.get_our_node_id();
	let node_f_id = nodes[5].node.get_our_node_id();
	let node_g_id = nodes[6].node.get_our_node_id();
	let node_h_id = nodes[7].node.get_our_node_id();
	let node_i_id = nodes[8].node.get_our_node_id();

	// Send an MPP payment in six parts along the path shown from top to bottom
	//        0
	//   1 2 3 4 5 6
	//        7
	//        8
	//
	// We can in theory reproduce this issue with fewer channels/HTLCs, but getting this test
	// robust is rather challenging. We rely on having the main test thread wait on locks held in
	// the background `claim_funds` thread and unlocking when the `claim_funds` thread completes a
	// single `ChannelMonitorUpdate`.
	// This thread calls `get_and_clear_pending_msg_events()` and `handle_revoke_and_ack()`, both
	// of which require `ChannelManager` locks, but we have to make sure this thread gets a chance
	// to be blocked on the mutexes before we let the background thread wake `claim_funds` so that
	// the mutex can switch to this main thread.
	// This relies on our locks being fair, but also on our threads getting runtime during the test
	// run, which can be pretty competitive. Thus we do a dumb dance to be as conservative as
	// possible - we have a background thread which completes a `ChannelMonitorUpdate` (by sending
	// into the `write_blocker` mpsc) but it doesn't run until a mpsc channel sends from this main
	// thread to the background thread, and then we let it sleep a while before we send the
	// `ChannelMonitorUpdate` unblocker.
	// Further, we give ourselves two chances each time, needing 4 HTLCs just to unlock our two
	// `ChannelManager` calls. We then need a few remaining HTLCs to actually trigger the bug, so
	// we use 6 HTLCs.
	// Finaly, we do not run this test on Winblowz because it, somehow, in 2025, does not implement
	// actual preemptive multitasking and thinks that cooperative multitasking somehow is
	// acceptable in the 21st century, let alone a quarter of the way into it.
	const MAX_THREAD_INIT_TIME: std::time::Duration = std::time::Duration::from_secs(1);

	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100_000, 0);
	create_announced_chan_between_nodes_with_value(&nodes, 0, 2, 100_000, 0);
	create_announced_chan_between_nodes_with_value(&nodes, 0, 3, 100_000, 0);
	create_announced_chan_between_nodes_with_value(&nodes, 0, 4, 100_000, 0);
	create_announced_chan_between_nodes_with_value(&nodes, 0, 5, 100_000, 0);
	create_announced_chan_between_nodes_with_value(&nodes, 0, 6, 100_000, 0);

	create_announced_chan_between_nodes_with_value(&nodes, 1, 7, 100_000, 0);
	create_announced_chan_between_nodes_with_value(&nodes, 2, 7, 100_000, 0);
	create_announced_chan_between_nodes_with_value(&nodes, 3, 7, 100_000, 0);
	create_announced_chan_between_nodes_with_value(&nodes, 4, 7, 100_000, 0);
	create_announced_chan_between_nodes_with_value(&nodes, 5, 7, 100_000, 0);
	create_announced_chan_between_nodes_with_value(&nodes, 6, 7, 100_000, 0);
	create_announced_chan_between_nodes_with_value(&nodes, 7, 8, 1_000_000, 0);

	let (mut route, payment_hash, payment_preimage, payment_secret) =
		get_route_and_payment_hash!(&nodes[0], nodes[8], 50_000_000);

	send_along_route_with_secret(
		&nodes[0],
		route,
		&[
			&[&nodes[1], &nodes[7], &nodes[8]],
			&[&nodes[2], &nodes[7], &nodes[8]],
			&[&nodes[3], &nodes[7], &nodes[8]],
			&[&nodes[4], &nodes[7], &nodes[8]],
			&[&nodes[5], &nodes[7], &nodes[8]],
			&[&nodes[6], &nodes[7], &nodes[8]],
		],
		50_000_000,
		payment_hash,
		payment_secret,
	);

	let (do_a_write, blocker) = std::sync::mpsc::sync_channel(0);
	*nodes[8].chain_monitor.write_blocker.lock().unwrap() = Some(blocker);

	// Until we have std::thread::scoped we have to unsafe { turn off the borrow checker }.
	// We do this by casting a pointer to a `TestChannelManager` to a pointer to a
	// `TestChannelManager` with different (in this case 'static) lifetime.
	// This is even suggested in the second example at
	// https://doc.rust-lang.org/std/mem/fn.transmute.html#examples
	let claim_node: &'static TestChannelManager<'static, 'static> =
		unsafe { std::mem::transmute(nodes[8].node as &TestChannelManager) };
	let thrd = std::thread::spawn(move || {
		// Initiate the claim in a background thread as it will immediately block waiting on the
		// `write_blocker` we set above.
		claim_node.claim_funds(payment_preimage);
	});

	// First unlock one monitor so that we have a pending
	// `update_fulfill_htlc`/`commitment_signed` pair to pass to our counterparty.
	do_a_write.send(()).unwrap();

	let event_node: &'static TestChannelManager<'static, 'static> =
		unsafe { std::mem::transmute(nodes[8].node as &TestChannelManager) };
	let thrd_event = std::thread::spawn(move || {
		let mut have_event = false;
		while !have_event {
			let mut events = event_node.get_and_clear_pending_events();
			assert!(events.len() == 1 || events.len() == 0);
			if events.len() == 1 {
				if let Event::PaymentClaimed { .. } = events[0] {
				} else {
					panic!("Unexpected event {events:?}");
				}
				have_event = true;
			}
		}
	});

	// Then fetch the `update_fulfill_htlc`/`commitment_signed`. Note that the
	// `get_and_clear_pending_msg_events` will immediately hang trying to take a peer lock which
	// `claim_funds` is holding. Thus, we release a second write after a small sleep in the
	// background to give `claim_funds` a chance to step forward, unblocking
	// `get_and_clear_pending_msg_events`.
	let do_a_write_background = do_a_write.clone();
	let block_thrd2 = AtomicBool::new(true);
	let block_thrd2_read: &'static AtomicBool = unsafe { std::mem::transmute(&block_thrd2) };
	let thrd2 = std::thread::spawn(move || {
		while block_thrd2_read.load(Ordering::Acquire) {
			std::thread::yield_now();
		}
		std::thread::sleep(MAX_THREAD_INIT_TIME);
		do_a_write_background.send(()).unwrap();
		std::thread::sleep(MAX_THREAD_INIT_TIME);
		do_a_write_background.send(()).unwrap();
	});
	block_thrd2.store(false, Ordering::Release);
	let mut first_updates = get_htlc_update_msgs(&nodes[8], &node_h_id);

	// Thread 2 could unblock first, or it could get blocked waiting on us to process a
	// `PaymentClaimed` event. Either way, wait until both have finished.
	thrd2.join().unwrap();
	thrd_event.join().unwrap();

	// Disconnect node 6 from all its peers so it doesn't bother to fail the HTLCs back
	nodes[7].node.peer_disconnected(node_b_id);
	nodes[7].node.peer_disconnected(node_c_id);
	nodes[7].node.peer_disconnected(node_d_id);
	nodes[7].node.peer_disconnected(node_e_id);
	nodes[7].node.peer_disconnected(node_f_id);
	nodes[7].node.peer_disconnected(node_g_id);

	let first_update_fulfill = first_updates.update_fulfill_htlcs.remove(0);
	nodes[7].node.handle_update_fulfill_htlc(node_i_id, first_update_fulfill);
	check_added_monitors(&nodes[7], 1);
	expect_payment_forwarded!(nodes[7], nodes[1], nodes[8], Some(1000), false, false);
	nodes[7].node.handle_commitment_signed_batch_test(node_i_id, &first_updates.commitment_signed);
	check_added_monitors(&nodes[7], 1);
	let (raa, cs) = get_revoke_commit_msgs(&nodes[7], &node_i_id);

	// Now, handle the `revoke_and_ack` from node 5. Note that `claim_funds` is still blocked on
	// our peer lock, so we have to release a write to let it process.
	// After this call completes, the channel previously would be locked up and should not be able
	// to make further progress.
	let do_a_write_background = do_a_write.clone();
	let block_thrd3 = AtomicBool::new(true);
	let block_thrd3_read: &'static AtomicBool = unsafe { std::mem::transmute(&block_thrd3) };
	let thrd3 = std::thread::spawn(move || {
		while block_thrd3_read.load(Ordering::Acquire) {
			std::thread::yield_now();
		}
		std::thread::sleep(MAX_THREAD_INIT_TIME);
		do_a_write_background.send(()).unwrap();
		std::thread::sleep(MAX_THREAD_INIT_TIME);
		do_a_write_background.send(()).unwrap();
	});
	block_thrd3.store(false, Ordering::Release);
	nodes[8].node.handle_revoke_and_ack(node_h_id, &raa);
	thrd3.join().unwrap();
	assert!(!thrd.is_finished());

	let thrd4 = std::thread::spawn(move || {
		do_a_write.send(()).unwrap();
		do_a_write.send(()).unwrap();
	});

	thrd4.join().unwrap();
	thrd.join().unwrap();

	// At the end, we should have 7 ChannelMonitorUpdates - 6 for HTLC claims, and one for the
	// above `revoke_and_ack`.
	check_added_monitors(&nodes[8], 7);

	// Now drive everything to the end, at least as far as node 7 is concerned...
	*nodes[8].chain_monitor.write_blocker.lock().unwrap() = None;
	nodes[8].node.handle_commitment_signed_batch_test(node_h_id, &cs);
	check_added_monitors(&nodes[8], 1);

	let (mut updates, raa) = get_updates_and_revoke(&nodes[8], &node_h_id);

	nodes[7].node.handle_update_fulfill_htlc(node_i_id, updates.update_fulfill_htlcs.remove(0));
	expect_payment_forwarded!(nodes[7], nodes[2], nodes[8], Some(1000), false, false);
	nodes[7].node.handle_update_fulfill_htlc(node_i_id, updates.update_fulfill_htlcs.remove(0));
	expect_payment_forwarded!(nodes[7], nodes[3], nodes[8], Some(1000), false, false);
	let mut next_source = 4;
	if let Some(update) = updates.update_fulfill_htlcs.get(0) {
		nodes[7].node.handle_update_fulfill_htlc(node_i_id, update.clone());
		expect_payment_forwarded!(nodes[7], nodes[4], nodes[8], Some(1000), false, false);
		next_source += 1;
	}

	nodes[7].node.handle_commitment_signed_batch_test(node_i_id, &updates.commitment_signed);
	nodes[7].node.handle_revoke_and_ack(node_i_id, &raa);
	if updates.update_fulfill_htlcs.get(0).is_some() {
		check_added_monitors(&nodes[7], 5);
	} else {
		check_added_monitors(&nodes[7], 4);
	}

	let (raa, cs) = get_revoke_commit_msgs(&nodes[7], &node_i_id);

	nodes[8].node.handle_revoke_and_ack(node_h_id, &raa);
	nodes[8].node.handle_commitment_signed_batch_test(node_h_id, &cs);
	check_added_monitors(&nodes[8], 2);

	let (mut updates, raa) = get_updates_and_revoke(&nodes[8], &node_h_id);

	nodes[7].node.handle_update_fulfill_htlc(node_i_id, updates.update_fulfill_htlcs.remove(0));
	expect_payment_forwarded!(nodes[7], nodes[next_source], nodes[8], Some(1000), false, false);
	next_source += 1;
	nodes[7].node.handle_update_fulfill_htlc(node_i_id, updates.update_fulfill_htlcs.remove(0));
	expect_payment_forwarded!(nodes[7], nodes[next_source], nodes[8], Some(1000), false, false);
	next_source += 1;
	if let Some(update) = updates.update_fulfill_htlcs.get(0) {
		nodes[7].node.handle_update_fulfill_htlc(node_i_id, update.clone());
		expect_payment_forwarded!(nodes[7], nodes[next_source], nodes[8], Some(1000), false, false);
	}

	nodes[7].node.handle_commitment_signed_batch_test(node_i_id, &updates.commitment_signed);
	nodes[7].node.handle_revoke_and_ack(node_i_id, &raa);
	if updates.update_fulfill_htlcs.get(0).is_some() {
		check_added_monitors(&nodes[7], 5);
	} else {
		check_added_monitors(&nodes[7], 4);
	}

	let (raa, cs) = get_revoke_commit_msgs(&nodes[7], &node_i_id);
	nodes[8].node.handle_revoke_and_ack(node_h_id, &raa);
	nodes[8].node.handle_commitment_signed_batch_test(node_h_id, &cs);
	check_added_monitors(&nodes[8], 2);

	let raa = get_event_msg!(nodes[8], MessageSendEvent::SendRevokeAndACK, node_h_id);
	nodes[7].node.handle_revoke_and_ack(node_i_id, &raa);
	check_added_monitors(&nodes[7], 1);
}

#[test]
fn native_async_persist() {
	// Test ChainMonitor::new_async_beta and the backing MonitorUpdatingPersisterAsync.
	//
	// Because our test utils aren't really set up for such utils, we simply test them directly,
	// first spinning up some nodes to create a `ChannelMonitor` and some `ChannelMonitorUpdate`s
	// we can apply.
	let (monitor, updates);
	let mut chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let (_, _, chan_id, funding_tx) = create_announced_chan_between_nodes(&nodes, 0, 1);

	monitor = get_monitor!(nodes[0], chan_id).clone();
	send_payment(&nodes[0], &[&nodes[1]], 1_000_000);
	let mon_updates =
		nodes[0].chain_monitor.monitor_updates.lock().unwrap().remove(&chan_id).unwrap();
	updates = mon_updates.into_iter().collect::<Vec<_>>();
	assert!(updates.len() >= 4, "The test below needs at least four updates");

	core::mem::drop(nodes);
	core::mem::drop(node_chanmgrs);
	core::mem::drop(node_cfgs);

	let node_0_utils = chanmon_cfgs.remove(0);
	let (logger, keys_manager, tx_broadcaster, fee_estimator) = (
		node_0_utils.logger,
		node_0_utils.keys_manager,
		node_0_utils.tx_broadcaster,
		node_0_utils.fee_estimator,
	);

	// Now that we have some updates, build a new ChainMonitor with a backing async KVStore.
	let logger = Arc::new(logger);
	let keys_manager = Arc::new(keys_manager);
	let tx_broadcaster = Arc::new(tx_broadcaster);
	let fee_estimator = Arc::new(fee_estimator);

	let kv_store = Arc::new(test_utils::TestStore::new(false));
	let persist_futures = Arc::new(FutureQueue::new());
	let native_async_persister = MonitorUpdatingPersisterAsync::new(
		Arc::clone(&kv_store),
		Arc::clone(&persist_futures),
		Arc::clone(&logger),
		42,
		Arc::clone(&keys_manager),
		Arc::clone(&keys_manager),
		Arc::clone(&tx_broadcaster),
		Arc::clone(&fee_estimator),
	);
	let chain_source = test_utils::TestChainSource::new(Network::Testnet);
	let async_chain_monitor = ChainMonitor::new_async_beta(
		Some(&chain_source),
		tx_broadcaster,
		logger,
		fee_estimator,
		native_async_persister,
		Arc::clone(&keys_manager),
		keys_manager.get_peer_storage_key(),
	);

	// Write the initial ChannelMonitor async, testing primarily that the `MonitorEvent::Completed`
	// isn't returned until the write is completed (via `complete_all_async_writes`) and the future
	// is `poll`ed (which a background spawn should do automatically in production, but which is
	// needed to get the future completion through to the `ChainMonitor`).
	let write_status = async_chain_monitor.watch_channel(chan_id, monitor).unwrap();
	assert_eq!(write_status, ChannelMonitorUpdateStatus::InProgress);

	// The write will remain pending until we call `complete_all_async_writes`, below.
	assert_eq!(persist_futures.pending_futures(), 1);
	persist_futures.poll_futures();
	assert_eq!(persist_futures.pending_futures(), 1);

	let funding_txo = OutPoint { txid: funding_tx.compute_txid(), index: 0 };
	let key = MonitorName::V1Channel(funding_txo).to_string();
	let pending_writes = kv_store.list_pending_async_writes(
		CHANNEL_MONITOR_PERSISTENCE_PRIMARY_NAMESPACE,
		CHANNEL_MONITOR_PERSISTENCE_SECONDARY_NAMESPACE,
		&key,
	);
	assert_eq!(pending_writes.len(), 1);

	// Once we complete the future, the write will still be pending until the future gets `poll`ed.
	kv_store.complete_all_async_writes();
	assert_eq!(persist_futures.pending_futures(), 1);
	assert_eq!(async_chain_monitor.release_pending_monitor_events().len(), 0);

	assert_eq!(persist_futures.pending_futures(), 1);
	persist_futures.poll_futures();
	assert_eq!(persist_futures.pending_futures(), 0);

	let completed_persist = async_chain_monitor.release_pending_monitor_events();
	assert_eq!(completed_persist.len(), 1);
	assert_eq!(completed_persist[0].2.len(), 1);
	assert!(matches!(completed_persist[0].2[0], MonitorEvent::Completed { .. }));

	// Now test two async `ChannelMonitorUpdate`s in flight at once, completing them in-order but
	// separately.
	let update_status = async_chain_monitor.update_channel(chan_id, &updates[0]);
	assert_eq!(update_status, ChannelMonitorUpdateStatus::InProgress);

	let update_status = async_chain_monitor.update_channel(chan_id, &updates[1]);
	assert_eq!(update_status, ChannelMonitorUpdateStatus::InProgress);

	persist_futures.poll_futures();
	assert_eq!(async_chain_monitor.release_pending_monitor_events().len(), 0);

	let pending_writes = kv_store.list_pending_async_writes(
		CHANNEL_MONITOR_UPDATE_PERSISTENCE_PRIMARY_NAMESPACE,
		&key,
		"1",
	);
	assert_eq!(pending_writes.len(), 1);
	let pending_writes = kv_store.list_pending_async_writes(
		CHANNEL_MONITOR_UPDATE_PERSISTENCE_PRIMARY_NAMESPACE,
		&key,
		"2",
	);
	assert_eq!(pending_writes.len(), 1);

	kv_store.complete_async_writes_through(
		CHANNEL_MONITOR_UPDATE_PERSISTENCE_PRIMARY_NAMESPACE,
		&key,
		"1",
		usize::MAX,
	);
	persist_futures.poll_futures();
	// While the `ChainMonitor` could return a `MonitorEvent::Completed` here, it currently
	// doesn't. If that ever changes we should validate that the `Completed` event has the correct
	// `monitor_update_id` (1).
	assert!(async_chain_monitor.release_pending_monitor_events().is_empty());

	kv_store.complete_async_writes_through(
		CHANNEL_MONITOR_UPDATE_PERSISTENCE_PRIMARY_NAMESPACE,
		&key,
		"2",
		usize::MAX,
	);
	persist_futures.poll_futures();
	let completed_persist = async_chain_monitor.release_pending_monitor_events();
	assert_eq!(completed_persist.len(), 1);
	assert_eq!(completed_persist[0].2.len(), 1);
	assert!(matches!(completed_persist[0].2[0], MonitorEvent::Completed { .. }));

	// Finally, test two async `ChanelMonitorUpdate`s in flight at once, completing them
	// out-of-order and ensuring that no `MonitorEvent::Completed` is generated until they are both
	// completed (and that it marks both as completed when it is generated).
	let update_status = async_chain_monitor.update_channel(chan_id, &updates[2]);
	assert_eq!(update_status, ChannelMonitorUpdateStatus::InProgress);

	let update_status = async_chain_monitor.update_channel(chan_id, &updates[3]);
	assert_eq!(update_status, ChannelMonitorUpdateStatus::InProgress);

	persist_futures.poll_futures();
	assert_eq!(async_chain_monitor.release_pending_monitor_events().len(), 0);

	let pending_writes = kv_store.list_pending_async_writes(
		CHANNEL_MONITOR_UPDATE_PERSISTENCE_PRIMARY_NAMESPACE,
		&key,
		"3",
	);
	assert_eq!(pending_writes.len(), 1);
	let pending_writes = kv_store.list_pending_async_writes(
		CHANNEL_MONITOR_UPDATE_PERSISTENCE_PRIMARY_NAMESPACE,
		&key,
		"4",
	);
	assert_eq!(pending_writes.len(), 1);

	kv_store.complete_async_writes_through(
		CHANNEL_MONITOR_UPDATE_PERSISTENCE_PRIMARY_NAMESPACE,
		&key,
		"4",
		usize::MAX,
	);
	persist_futures.poll_futures();
	assert_eq!(async_chain_monitor.release_pending_monitor_events().len(), 0);

	kv_store.complete_async_writes_through(
		CHANNEL_MONITOR_UPDATE_PERSISTENCE_PRIMARY_NAMESPACE,
		&key,
		"3",
		usize::MAX,
	);
	persist_futures.poll_futures();
	let completed_persist = async_chain_monitor.release_pending_monitor_events();
	assert_eq!(completed_persist.len(), 1);
	assert_eq!(completed_persist[0].2.len(), 1);
	if let MonitorEvent::Completed { monitor_update_id, .. } = &completed_persist[0].2[0] {
		assert_eq!(*monitor_update_id, 4);
	} else {
		panic!();
	}
}

#[test]
fn test_mpp_claim_to_holding_cell() {
	// Previously, if an MPP payment was claimed while one channel was AwaitingRAA (causing the
	// HTLC claim to go into the holding cell), and the RAA came in before the async monitor
	// update with the preimage completed, the channel could hang waiting on itself.
	// This tests that behavior.
	let chanmon_cfgs = create_chanmon_cfgs(4);
	let node_cfgs = create_node_cfgs(4, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(4, &node_cfgs, &[None, None, None, None]);
	let nodes = create_network(4, &node_cfgs, &node_chanmgrs);

	let node_b_id = nodes[1].node.get_our_node_id();
	let node_c_id = nodes[2].node.get_our_node_id();
	let node_d_id = nodes[3].node.get_our_node_id();

	// First open channels in a diamond and deliver the MPP payment.
	let chan_1_scid = create_announced_chan_between_nodes(&nodes, 0, 1).0.contents.short_channel_id;
	let chan_2_scid = create_announced_chan_between_nodes(&nodes, 0, 2).0.contents.short_channel_id;
	let (chan_3_update, _, chan_3_id, ..) = create_announced_chan_between_nodes(&nodes, 1, 3);
	let chan_3_scid = chan_3_update.contents.short_channel_id;
	let (chan_4_update, _, chan_4_id, ..) = create_announced_chan_between_nodes(&nodes, 2, 3);
	let chan_4_scid = chan_4_update.contents.short_channel_id;

	let (mut route, paymnt_hash_1, preimage_1, payment_secret) =
		get_route_and_payment_hash!(&nodes[0], nodes[3], 500_000);
	let path = route.paths[0].clone();
	route.paths.push(path);
	route.paths[0].hops[0].pubkey = node_b_id;
	route.paths[0].hops[0].short_channel_id = chan_1_scid;
	route.paths[0].hops[1].short_channel_id = chan_3_scid;
	route.paths[0].hops[1].fee_msat = 250_000;
	route.paths[1].hops[0].pubkey = node_c_id;
	route.paths[1].hops[0].short_channel_id = chan_2_scid;
	route.paths[1].hops[1].short_channel_id = chan_4_scid;
	route.paths[1].hops[1].fee_msat = 250_000;
	let paths = &[&[&nodes[1], &nodes[3]][..], &[&nodes[2], &nodes[3]][..]];
	send_along_route_with_secret(&nodes[0], route, paths, 500_000, paymnt_hash_1, payment_secret);

	// Put the C <-> D channel into AwaitingRaa
	let (preimage_2, paymnt_hash_2, payment_secret_2) = get_payment_preimage_hash!(nodes[3]);
	let onion = RecipientOnionFields::secret_only(payment_secret_2);
	let id = PaymentId([42; 32]);
	let pay_params = PaymentParameters::from_node_id(node_d_id, TEST_FINAL_CLTV);
	let route_params = RouteParameters::from_payment_params_and_value(pay_params, 400_000);
	nodes[2].node.send_payment(paymnt_hash_2, onion, id, route_params, Retry::Attempts(0)).unwrap();
	check_added_monitors(&nodes[2], 1);

	let mut payment_event = SendEvent::from_node(&nodes[2]);
	nodes[3].node.handle_update_add_htlc(node_c_id, &payment_event.msgs[0]);
	nodes[3].node.handle_commitment_signed_batch_test(node_c_id, &payment_event.commitment_msg);
	check_added_monitors(&nodes[3], 1);

	let (raa, cs) = get_revoke_commit_msgs(&nodes[3], &node_c_id);
	nodes[2].node.handle_revoke_and_ack(node_d_id, &raa);
	check_added_monitors(&nodes[2], 1);

	nodes[2].node.handle_commitment_signed_batch_test(node_d_id, &cs);
	check_added_monitors(&nodes[2], 1);

	let cs_raa = get_event_msg!(nodes[2], MessageSendEvent::SendRevokeAndACK, node_d_id);

	// Now claim the payment, completing both channel monitor updates async
	// In the current code, the C <-> D channel happens to be the `durable_preimage_channel`,
	// improving coverage somewhat but it isn't strictly critical to the test.
	chanmon_cfgs[3].persister.set_update_ret(ChannelMonitorUpdateStatus::InProgress);
	chanmon_cfgs[3].persister.set_update_ret(ChannelMonitorUpdateStatus::InProgress);
	nodes[3].node.claim_funds(preimage_1);
	check_added_monitors(&nodes[3], 2);

	// Complete the B <-> D monitor update, freeing the first fulfill.
	let (latest_id, _) = get_latest_mon_update_id(&nodes[3], chan_3_id);
	nodes[3].chain_monitor.chain_monitor.channel_monitor_updated(chan_3_id, latest_id).unwrap();
	let mut b_claim = get_htlc_update_msgs(&nodes[3], &node_b_id);

	// When we deliver the pre-claim RAA, node D will shove the monitor update into the blocked
	// state since we have a pending MPP payment which is blocking RAA monitor updates.
	nodes[3].node.handle_revoke_and_ack(node_c_id, &cs_raa);
	check_added_monitors(&nodes[3], 0);

	// Finally, complete the C <-> D monitor update. Previously, this unlock failed to be processed
	// due to the existence of the blocked RAA update above.
	let (latest_id, _) = get_latest_mon_update_id(&nodes[3], chan_4_id);
	nodes[3].chain_monitor.chain_monitor.channel_monitor_updated(chan_4_id, latest_id).unwrap();
	// Once we process monitor events (in this case by checking for the `PaymentClaimed` event, the
	// RAA monitor update blocked above will be released.
	// At the same time, the RAA monitor update completion will allow the C <-> D channel to
	// generate its fulfill update.
	expect_payment_claimed!(nodes[3], paymnt_hash_1, 500_000);
	check_added_monitors(&nodes[3], 2);
	let mut c_claim = get_htlc_update_msgs(&nodes[3], &node_c_id);
	check_added_monitors(&nodes[3], 0);

	// Finally, clear all the pending payments.
	let path = [&[&nodes[1], &nodes[3]][..], &[&nodes[2], &nodes[3]][..]];
	let mut args = ClaimAlongRouteArgs::new(&nodes[0], &path[..], preimage_1);
	let b_claim_msgs = (b_claim.update_fulfill_htlcs.pop().unwrap(), b_claim.commitment_signed);
	let c_claim_msgs = (c_claim.update_fulfill_htlcs.pop().unwrap(), c_claim.commitment_signed);
	let claims = vec![(b_claim_msgs, node_b_id), (c_claim_msgs, node_c_id)];
	pass_claimed_payment_along_route_from_ev(250_000, claims, args);

	expect_payment_sent(&nodes[0], preimage_1, None, true, true);

	expect_and_process_pending_htlcs(&nodes[3], false);
	expect_payment_claimable!(nodes[3], paymnt_hash_2, payment_secret_2, 400_000);
	claim_payment(&nodes[2], &[&nodes[3]], preimage_2);
}
