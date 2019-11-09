//! Functional tests which test the correct handling of ChannelMonitorUpdateErr returns from
//! monitor updates.
//! There are a bunch of these as their handling is relatively error-prone so they are split out
//! here. See also the chanmon_fail_consistency fuzz test.

use ln::channelmanager::{RAACommitmentOrder, PaymentPreimage, PaymentHash};
use ln::channelmonitor::ChannelMonitorUpdateErr;
use ln::msgs;
use ln::msgs::ChannelMessageHandler;
use util::events::{Event, EventsProvider, MessageSendEvent, MessageSendEventsProvider};
use util::errors::APIError;

use bitcoin_hashes::sha256::Hash as Sha256;
use bitcoin_hashes::Hash;

use std::time::Instant;

use ln::functional_test_utils::*;

#[test]
fn test_simple_monitor_permanent_update_fail() {
	// Test that we handle a simple permanent monitor update failure
	let mut nodes = create_network(2);
	create_announced_chan_between_nodes(&nodes, 0, 1);

	let route = nodes[0].router.get_route(&nodes[1].node.get_our_node_id(), None, &Vec::new(), 1000000, TEST_FINAL_CLTV).unwrap();
	let (_, payment_hash_1) = get_payment_preimage_hash!(nodes[0]);

	*nodes[0].chan_monitor.update_ret.lock().unwrap() = Err(ChannelMonitorUpdateErr::PermanentFailure);
	if let Err(APIError::ChannelUnavailable {..}) = nodes[0].node.send_payment(route, payment_hash_1) {} else { panic!(); }
	check_added_monitors!(nodes[0], 1);

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

fn do_test_simple_monitor_temporary_update_fail(disconnect: bool) {
	// Test that we can recover from a simple temporary monitor update failure optionally with
	// a disconnect in between
	let mut nodes = create_network(2);
	create_announced_chan_between_nodes(&nodes, 0, 1);

	let route = nodes[0].router.get_route(&nodes[1].node.get_our_node_id(), None, &Vec::new(), 1000000, TEST_FINAL_CLTV).unwrap();
	let (payment_preimage_1, payment_hash_1) = get_payment_preimage_hash!(nodes[0]);

	*nodes[0].chan_monitor.update_ret.lock().unwrap() = Err(ChannelMonitorUpdateErr::TemporaryFailure);
	if let Err(APIError::MonitorUpdateFailed) = nodes[0].node.send_payment(route.clone(), payment_hash_1) {} else { panic!(); }
	check_added_monitors!(nodes[0], 1);

	assert!(nodes[0].node.get_and_clear_pending_events().is_empty());
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	assert_eq!(nodes[0].node.list_channels().len(), 1);

	if disconnect {
		nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id(), false);
		nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);
		reconnect_nodes(&nodes[0], &nodes[1], (true, true), (0, 0), (0, 0), (0, 0), (0, 0), (false, false));
	}

	*nodes[0].chan_monitor.update_ret.lock().unwrap() = Ok(());
	nodes[0].node.test_restore_channel_monitor();
	check_added_monitors!(nodes[0], 1);

	let mut events_2 = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events_2.len(), 1);
	let payment_event = SendEvent::from_event(events_2.pop().unwrap());
	assert_eq!(payment_event.node_id, nodes[1].node.get_our_node_id());
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &payment_event.msgs[0]).unwrap();
	commitment_signed_dance!(nodes[1], nodes[0], payment_event.commitment_msg, false);

	expect_pending_htlcs_forwardable!(nodes[1]);

	let events_3 = nodes[1].node.get_and_clear_pending_events();
	assert_eq!(events_3.len(), 1);
	match events_3[0] {
		Event::PaymentReceived { ref payment_hash, amt } => {
			assert_eq!(payment_hash_1, *payment_hash);
			assert_eq!(amt, 1000000);
		},
		_ => panic!("Unexpected event"),
	}

	claim_payment(&nodes[0], &[&nodes[1]], payment_preimage_1);

	// Now set it to failed again...
	let (_, payment_hash_2) = get_payment_preimage_hash!(nodes[0]);
	*nodes[0].chan_monitor.update_ret.lock().unwrap() = Err(ChannelMonitorUpdateErr::TemporaryFailure);
	if let Err(APIError::MonitorUpdateFailed) = nodes[0].node.send_payment(route, payment_hash_2) {} else { panic!(); }
	check_added_monitors!(nodes[0], 1);

	assert!(nodes[0].node.get_and_clear_pending_events().is_empty());
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	assert_eq!(nodes[0].node.list_channels().len(), 1);

	if disconnect {
		nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id(), false);
		nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);
		reconnect_nodes(&nodes[0], &nodes[1], (false, false), (0, 0), (0, 0), (0, 0), (0, 0), (false, false));
	}

	// ...and make sure we can force-close a TemporaryFailure channel with a PermanentFailure
	*nodes[0].chan_monitor.update_ret.lock().unwrap() = Err(ChannelMonitorUpdateErr::PermanentFailure);
	nodes[0].node.test_restore_channel_monitor();
	check_added_monitors!(nodes[0], 1);
	check_closed_broadcast!(nodes[0]);

	// TODO: Once we hit the chain with the failure transaction we should check that we get a
	// PaymentFailed event

	assert_eq!(nodes[0].node.list_channels().len(), 0);
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
	let mut nodes = create_network(2);
	create_announced_chan_between_nodes(&nodes, 0, 1);

	let (payment_preimage_1, _) = route_payment(&nodes[0], &[&nodes[1]], 1000000);

	// Now try to send a second payment which will fail to send
	let route = nodes[0].router.get_route(&nodes[1].node.get_our_node_id(), None, &Vec::new(), 1000000, TEST_FINAL_CLTV).unwrap();
	let (payment_preimage_2, payment_hash_2) = get_payment_preimage_hash!(nodes[0]);

	*nodes[0].chan_monitor.update_ret.lock().unwrap() = Err(ChannelMonitorUpdateErr::TemporaryFailure);
	if let Err(APIError::MonitorUpdateFailed) = nodes[0].node.send_payment(route.clone(), payment_hash_2) {} else { panic!(); }
	check_added_monitors!(nodes[0], 1);

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
				nodes[0].node.handle_update_fulfill_htlc(&nodes[1].node.get_our_node_id(), &update_fulfill_htlcs[0]).unwrap();
				let events_3 = nodes[0].node.get_and_clear_pending_events();
				assert_eq!(events_3.len(), 1);
				match events_3[0] {
					Event::PaymentSent { ref payment_preimage } => {
						assert_eq!(*payment_preimage, payment_preimage_1);
					},
					_ => panic!("Unexpected event"),
				}

				if let Err(msgs::HandleError{err, action: Some(msgs::ErrorAction::IgnoreError) }) = nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), commitment_signed) {
					assert_eq!(err, "Previous monitor update failure prevented generation of RAA");
				} else { panic!(); }
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
	*nodes[0].chan_monitor.update_ret.lock().unwrap() = Ok(());
	nodes[0].node.test_restore_channel_monitor();
	check_added_monitors!(nodes[0], 1);

	macro_rules! disconnect_reconnect_peers { () => { {
		nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id(), false);
		nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);

		nodes[0].node.peer_connected(&nodes[1].node.get_our_node_id());
		let reestablish_1 = get_chan_reestablish_msgs!(nodes[0], nodes[1]);
		assert_eq!(reestablish_1.len(), 1);
		nodes[1].node.peer_connected(&nodes[0].node.get_our_node_id());
		let reestablish_2 = get_chan_reestablish_msgs!(nodes[1], nodes[0]);
		assert_eq!(reestablish_2.len(), 1);

		nodes[0].node.handle_channel_reestablish(&nodes[1].node.get_our_node_id(), &reestablish_2[0]).unwrap();
		let as_resp = handle_chan_reestablish_msgs!(nodes[0], nodes[1]);
		nodes[1].node.handle_channel_reestablish(&nodes[0].node.get_our_node_id(), &reestablish_1[0]).unwrap();
		let bs_resp = handle_chan_reestablish_msgs!(nodes[1], nodes[0]);

		assert!(as_resp.0.is_none());
		assert!(bs_resp.0.is_none());

		(reestablish_1, reestablish_2, as_resp, bs_resp)
	} } }

	let (payment_event, initial_revoke_and_ack) = if disconnect_count & !disconnect_flags > 0 {
		assert!(nodes[0].node.get_and_clear_pending_events().is_empty());
		assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());

		nodes[0].node.peer_connected(&nodes[1].node.get_our_node_id());
		let reestablish_1 = get_chan_reestablish_msgs!(nodes[0], nodes[1]);
		assert_eq!(reestablish_1.len(), 1);
		nodes[1].node.peer_connected(&nodes[0].node.get_our_node_id());
		let reestablish_2 = get_chan_reestablish_msgs!(nodes[1], nodes[0]);
		assert_eq!(reestablish_2.len(), 1);

		nodes[0].node.handle_channel_reestablish(&nodes[1].node.get_our_node_id(), &reestablish_2[0]).unwrap();
		check_added_monitors!(nodes[0], 0);
		let mut as_resp = handle_chan_reestablish_msgs!(nodes[0], nodes[1]);
		nodes[1].node.handle_channel_reestablish(&nodes[0].node.get_our_node_id(), &reestablish_1[0]).unwrap();
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

			nodes[0].node.handle_update_fulfill_htlc(&nodes[1].node.get_our_node_id(), &bs_resp.2.as_ref().unwrap().update_fulfill_htlcs[0]).unwrap();
			let events_3 = nodes[0].node.get_and_clear_pending_events();
			assert_eq!(events_3.len(), 1);
			match events_3[0] {
				Event::PaymentSent { ref payment_preimage } => {
					assert_eq!(*payment_preimage, payment_preimage_1);
				},
				_ => panic!("Unexpected event"),
			}

			nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &bs_resp.2.as_ref().unwrap().commitment_signed).unwrap();
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

	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &payment_event.msgs[0]).unwrap();
	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &payment_event.commitment_msg).unwrap();
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
		nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_revoke_and_ack).unwrap();
		as_commitment_update = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
		assert!(as_commitment_update.update_add_htlcs.is_empty());
		assert!(as_commitment_update.update_fulfill_htlcs.is_empty());
		assert!(as_commitment_update.update_fail_htlcs.is_empty());
		assert!(as_commitment_update.update_fail_malformed_htlcs.is_empty());
		assert!(as_commitment_update.update_fee.is_none());
		check_added_monitors!(nodes[0], 1);
	} }

	macro_rules! handle_initial_raa { () => {
		nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &initial_revoke_and_ack).unwrap();
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

	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &bs_second_commitment_update.commitment_signed).unwrap();
	let as_revoke_and_ack = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());
	// No commitment_signed so get_event_msg's assert(len == 1) passes
	check_added_monitors!(nodes[0], 1);

	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &as_commitment_update.commitment_signed).unwrap();
	let bs_second_revoke_and_ack = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, nodes[0].node.get_our_node_id());
	// No commitment_signed so get_event_msg's assert(len == 1) passes
	check_added_monitors!(nodes[1], 1);

	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &as_revoke_and_ack).unwrap();
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	check_added_monitors!(nodes[1], 1);

	nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_second_revoke_and_ack).unwrap();
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	check_added_monitors!(nodes[0], 1);

	expect_pending_htlcs_forwardable!(nodes[1]);

	let events_5 = nodes[1].node.get_and_clear_pending_events();
	assert_eq!(events_5.len(), 1);
	match events_5[0] {
		Event::PaymentReceived { ref payment_hash, amt } => {
			assert_eq!(payment_hash_2, *payment_hash);
			assert_eq!(amt, 1000000);
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
	let mut nodes = create_network(2);
	create_announced_chan_between_nodes(&nodes, 0, 1);

	let route = nodes[0].router.get_route(&nodes[1].node.get_our_node_id(), None, &Vec::new(), 1000000, TEST_FINAL_CLTV).unwrap();
	let (payment_preimage, our_payment_hash) = get_payment_preimage_hash!(nodes[0]);
	nodes[0].node.send_payment(route, our_payment_hash).unwrap();
	check_added_monitors!(nodes[0], 1);

	let send_event = SendEvent::from_event(nodes[0].node.get_and_clear_pending_msg_events().remove(0));
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &send_event.msgs[0]).unwrap();

	*nodes[1].chan_monitor.update_ret.lock().unwrap() = Err(ChannelMonitorUpdateErr::TemporaryFailure);
	if let msgs::HandleError { err, action: Some(msgs::ErrorAction::IgnoreError) } = nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &send_event.commitment_msg).unwrap_err() {
		assert_eq!(err, "Failed to update ChannelMonitor");
	} else { panic!(); }
	check_added_monitors!(nodes[1], 1);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	*nodes[1].chan_monitor.update_ret.lock().unwrap() = Ok(());
	nodes[1].node.test_restore_channel_monitor();
	check_added_monitors!(nodes[1], 1);
	let responses = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(responses.len(), 2);

	match responses[0] {
		MessageSendEvent::SendRevokeAndACK { ref msg, ref node_id } => {
			assert_eq!(*node_id, nodes[0].node.get_our_node_id());
			nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &msg).unwrap();
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

			*nodes[0].chan_monitor.update_ret.lock().unwrap() = Err(ChannelMonitorUpdateErr::TemporaryFailure);
			if let msgs::HandleError { err, action: Some(msgs::ErrorAction::IgnoreError) } = nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &updates.commitment_signed).unwrap_err() {
				assert_eq!(err, "Failed to update ChannelMonitor");
			} else { panic!(); }
			check_added_monitors!(nodes[0], 1);
			assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
		},
		_ => panic!("Unexpected event"),
	}

	*nodes[0].chan_monitor.update_ret.lock().unwrap() = Ok(());
	nodes[0].node.test_restore_channel_monitor();
	check_added_monitors!(nodes[0], 1);

	let final_raa = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());
	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &final_raa).unwrap();
	check_added_monitors!(nodes[1], 1);

	expect_pending_htlcs_forwardable!(nodes[1]);

	let events = nodes[1].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		Event::PaymentReceived { payment_hash, amt } => {
			assert_eq!(payment_hash, our_payment_hash);
			assert_eq!(amt, 1000000);
		},
		_ => panic!("Unexpected event"),
	};

	claim_payment(&nodes[0], &[&nodes[1]], payment_preimage);
}

#[test]
fn test_monitor_update_fail_no_rebroadcast() {
	// Tests handling of a monitor update failure when no message rebroadcasting on
	// test_restore_channel_monitor() is required. Backported from
	// chanmon_fail_consistency fuzz tests.
	let mut nodes = create_network(2);
	create_announced_chan_between_nodes(&nodes, 0, 1);

	let route = nodes[0].router.get_route(&nodes[1].node.get_our_node_id(), None, &Vec::new(), 1000000, TEST_FINAL_CLTV).unwrap();
	let (payment_preimage_1, our_payment_hash) = get_payment_preimage_hash!(nodes[0]);
	nodes[0].node.send_payment(route, our_payment_hash).unwrap();
	check_added_monitors!(nodes[0], 1);

	let send_event = SendEvent::from_event(nodes[0].node.get_and_clear_pending_msg_events().remove(0));
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &send_event.msgs[0]).unwrap();
	let bs_raa = commitment_signed_dance!(nodes[1], nodes[0], send_event.commitment_msg, false, true, false, true);

	*nodes[1].chan_monitor.update_ret.lock().unwrap() = Err(ChannelMonitorUpdateErr::TemporaryFailure);
	if let msgs::HandleError { err, action: Some(msgs::ErrorAction::IgnoreError) } = nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &bs_raa).unwrap_err() {
		assert_eq!(err, "Failed to update ChannelMonitor");
	} else { panic!(); }
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	assert!(nodes[1].node.get_and_clear_pending_events().is_empty());
	check_added_monitors!(nodes[1], 1);

	*nodes[1].chan_monitor.update_ret.lock().unwrap() = Ok(());
	nodes[1].node.test_restore_channel_monitor();
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	check_added_monitors!(nodes[1], 1);
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
	let mut nodes = create_network(2);
	create_announced_chan_between_nodes(&nodes, 0, 1);

	send_payment(&nodes[0], &[&nodes[1]], 5000000);

	let route = nodes[0].router.get_route(&nodes[1].node.get_our_node_id(), None, &Vec::new(), 1000000, TEST_FINAL_CLTV).unwrap();
	let (payment_preimage_1, our_payment_hash_1) = get_payment_preimage_hash!(nodes[0]);
	nodes[0].node.send_payment(route, our_payment_hash_1).unwrap();
	check_added_monitors!(nodes[0], 1);
	let send_event_1 = SendEvent::from_event(nodes[0].node.get_and_clear_pending_msg_events().remove(0));

	let route = nodes[1].router.get_route(&nodes[0].node.get_our_node_id(), None, &Vec::new(), 1000000, TEST_FINAL_CLTV).unwrap();
	let (payment_preimage_2, our_payment_hash_2) = get_payment_preimage_hash!(nodes[0]);
	nodes[1].node.send_payment(route, our_payment_hash_2).unwrap();
	check_added_monitors!(nodes[1], 1);
	let send_event_2 = SendEvent::from_event(nodes[1].node.get_and_clear_pending_msg_events().remove(0));

	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &send_event_1.msgs[0]).unwrap();
	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &send_event_1.commitment_msg).unwrap();
	check_added_monitors!(nodes[1], 1);
	let bs_raa = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, nodes[0].node.get_our_node_id());

	*nodes[0].chan_monitor.update_ret.lock().unwrap() = Err(ChannelMonitorUpdateErr::TemporaryFailure);
	nodes[0].node.handle_update_add_htlc(&nodes[1].node.get_our_node_id(), &send_event_2.msgs[0]).unwrap();
	if let msgs::HandleError { err, action: Some(msgs::ErrorAction::IgnoreError) } = nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &send_event_2.commitment_msg).unwrap_err() {
		assert_eq!(err, "Failed to update ChannelMonitor");
	} else { panic!(); }
	check_added_monitors!(nodes[0], 1);

	if let msgs::HandleError { err, action: Some(msgs::ErrorAction::IgnoreError) } = nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_raa).unwrap_err() {
		assert_eq!(err, "Previous monitor update failure prevented responses to RAA");
	} else { panic!(); }
	check_added_monitors!(nodes[0], 1);

	*nodes[0].chan_monitor.update_ret.lock().unwrap() = Ok(());
	nodes[0].node.test_restore_channel_monitor();
	check_added_monitors!(nodes[0], 1);

	let as_update_raa = get_revoke_commit_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &as_update_raa.0).unwrap();
	check_added_monitors!(nodes[1], 1);
	let bs_cs = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());

	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &as_update_raa.1).unwrap();
	check_added_monitors!(nodes[1], 1);
	let bs_second_raa = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, nodes[0].node.get_our_node_id());

	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &bs_cs.commitment_signed).unwrap();
	check_added_monitors!(nodes[0], 1);
	let as_second_raa = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());

	nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_second_raa).unwrap();
	check_added_monitors!(nodes[0], 1);
	expect_pending_htlcs_forwardable!(nodes[0]);
	expect_payment_received!(nodes[0], our_payment_hash_2, 1000000);

	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &as_second_raa).unwrap();
	check_added_monitors!(nodes[1], 1);
	expect_pending_htlcs_forwardable!(nodes[1]);
	expect_payment_received!(nodes[1], our_payment_hash_1, 1000000);

	claim_payment(&nodes[0], &[&nodes[1]], payment_preimage_1);
	claim_payment(&nodes[1], &[&nodes[0]], payment_preimage_2);
}

fn do_test_monitor_update_fail_raa(test_ignore_second_cs: bool) {
	// Tests handling of a monitor update failure when processing an incoming RAA
	let mut nodes = create_network(3);
	create_announced_chan_between_nodes(&nodes, 0, 1);
	let chan_2 = create_announced_chan_between_nodes(&nodes, 1, 2);

	// Rebalance a bit so that we can send backwards from 2 to 1.
	send_payment(&nodes[0], &[&nodes[1], &nodes[2]], 5000000);

	// Route a first payment that we'll fail backwards
	let (_, payment_hash_1) = route_payment(&nodes[0], &[&nodes[1], &nodes[2]], 1000000);

	// Fail the payment backwards, failing the monitor update on nodes[1]'s receipt of the RAA
	assert!(nodes[2].node.fail_htlc_backwards(&payment_hash_1, 0));
	expect_pending_htlcs_forwardable!(nodes[2]);
	check_added_monitors!(nodes[2], 1);

	let updates = get_htlc_update_msgs!(nodes[2], nodes[1].node.get_our_node_id());
	assert!(updates.update_add_htlcs.is_empty());
	assert!(updates.update_fulfill_htlcs.is_empty());
	assert_eq!(updates.update_fail_htlcs.len(), 1);
	assert!(updates.update_fail_malformed_htlcs.is_empty());
	assert!(updates.update_fee.is_none());
	nodes[1].node.handle_update_fail_htlc(&nodes[2].node.get_our_node_id(), &updates.update_fail_htlcs[0]).unwrap();

	let bs_revoke_and_ack = commitment_signed_dance!(nodes[1], nodes[2], updates.commitment_signed, false, true, false, true);
	check_added_monitors!(nodes[0], 0);

	// While the second channel is AwaitingRAA, forward a second payment to get it into the
	// holding cell.
	let (payment_preimage_2, payment_hash_2) = get_payment_preimage_hash!(nodes[0]);
	let route = nodes[0].router.get_route(&nodes[2].node.get_our_node_id(), None, &Vec::new(), 1000000, TEST_FINAL_CLTV).unwrap();
	nodes[0].node.send_payment(route, payment_hash_2).unwrap();
	check_added_monitors!(nodes[0], 1);

	let mut send_event = SendEvent::from_event(nodes[0].node.get_and_clear_pending_msg_events().remove(0));
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &send_event.msgs[0]).unwrap();
	commitment_signed_dance!(nodes[1], nodes[0], send_event.commitment_msg, false);

	expect_pending_htlcs_forwardable!(nodes[1]);
	check_added_monitors!(nodes[1], 0);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	// Now fail monitor updating.
	*nodes[1].chan_monitor.update_ret.lock().unwrap() = Err(ChannelMonitorUpdateErr::TemporaryFailure);
	if let msgs::HandleError { err, action: Some(msgs::ErrorAction::IgnoreError) } = nodes[1].node.handle_revoke_and_ack(&nodes[2].node.get_our_node_id(), &bs_revoke_and_ack).unwrap_err() {
		assert_eq!(err, "Failed to update ChannelMonitor");
	} else { panic!(); }
	assert!(nodes[1].node.get_and_clear_pending_events().is_empty());
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	check_added_monitors!(nodes[1], 1);

	// Attempt to forward a third payment but fail due to the second channel being unavailable
	// for forwarding.

	let (_, payment_hash_3) = get_payment_preimage_hash!(nodes[0]);
	let route = nodes[0].router.get_route(&nodes[2].node.get_our_node_id(), None, &Vec::new(), 1000000, TEST_FINAL_CLTV).unwrap();
	nodes[0].node.send_payment(route, payment_hash_3).unwrap();
	check_added_monitors!(nodes[0], 1);

	*nodes[1].chan_monitor.update_ret.lock().unwrap() = Ok(()); // We succeed in updating the monitor for the first channel
	send_event = SendEvent::from_event(nodes[0].node.get_and_clear_pending_msg_events().remove(0));
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &send_event.msgs[0]).unwrap();
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

			nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &updates.update_fail_htlcs[0]).unwrap();
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
		let route = nodes[2].router.get_route(&nodes[0].node.get_our_node_id(), None, &Vec::new(), 1000000, TEST_FINAL_CLTV).unwrap();
		nodes[2].node.send_payment(route, payment_hash_4).unwrap();
		check_added_monitors!(nodes[2], 1);

		send_event = SendEvent::from_event(nodes[2].node.get_and_clear_pending_msg_events().remove(0));
		nodes[1].node.handle_update_add_htlc(&nodes[2].node.get_our_node_id(), &send_event.msgs[0]).unwrap();
		if let Err(msgs::HandleError{err, action: Some(msgs::ErrorAction::IgnoreError) }) = nodes[1].node.handle_commitment_signed(&nodes[2].node.get_our_node_id(), &send_event.commitment_msg) {
			assert_eq!(err, "Previous monitor update failure prevented generation of RAA");
		} else { panic!(); }
		assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
		assert!(nodes[1].node.get_and_clear_pending_events().is_empty());
		(Some(payment_preimage_4), Some(payment_hash_4))
	} else { (None, None) };

	// Restore monitor updating, ensuring we immediately get a fail-back update and a
	// update_add update.
	*nodes[1].chan_monitor.update_ret.lock().unwrap() = Ok(());
	nodes[1].node.test_restore_channel_monitor();
	check_added_monitors!(nodes[1], 1);
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

	nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &messages_a.0).unwrap();
	commitment_signed_dance!(nodes[0], nodes[1], messages_a.1, false);
	let events_4 = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events_4.len(), 1);
	if let Event::PaymentFailed { payment_hash, rejected_by_dest, .. } = events_4[0] {
		assert_eq!(payment_hash, payment_hash_1);
		assert!(rejected_by_dest);
	} else { panic!("Unexpected event!"); }

	nodes[2].node.handle_update_add_htlc(&nodes[1].node.get_our_node_id(), &send_event_b.msgs[0]).unwrap();
	if test_ignore_second_cs {
		nodes[2].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &send_event_b.commitment_msg).unwrap();
		check_added_monitors!(nodes[2], 1);
		let bs_revoke_and_ack = get_event_msg!(nodes[2], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());
		nodes[2].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &raa.unwrap()).unwrap();
		check_added_monitors!(nodes[2], 1);
		let bs_cs = get_htlc_update_msgs!(nodes[2], nodes[1].node.get_our_node_id());
		assert!(bs_cs.update_add_htlcs.is_empty());
		assert!(bs_cs.update_fail_htlcs.is_empty());
		assert!(bs_cs.update_fail_malformed_htlcs.is_empty());
		assert!(bs_cs.update_fulfill_htlcs.is_empty());
		assert!(bs_cs.update_fee.is_none());

		nodes[1].node.handle_revoke_and_ack(&nodes[2].node.get_our_node_id(), &bs_revoke_and_ack).unwrap();
		check_added_monitors!(nodes[1], 1);
		let as_cs = get_htlc_update_msgs!(nodes[1], nodes[2].node.get_our_node_id());
		assert!(as_cs.update_add_htlcs.is_empty());
		assert!(as_cs.update_fail_htlcs.is_empty());
		assert!(as_cs.update_fail_malformed_htlcs.is_empty());
		assert!(as_cs.update_fulfill_htlcs.is_empty());
		assert!(as_cs.update_fee.is_none());

		nodes[1].node.handle_commitment_signed(&nodes[2].node.get_our_node_id(), &bs_cs.commitment_signed).unwrap();
		check_added_monitors!(nodes[1], 1);
		let as_raa = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, nodes[2].node.get_our_node_id());

		nodes[2].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &as_cs.commitment_signed).unwrap();
		check_added_monitors!(nodes[2], 1);
		let bs_second_raa = get_event_msg!(nodes[2], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());

		nodes[2].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &as_raa).unwrap();
		check_added_monitors!(nodes[2], 1);
		assert!(nodes[2].node.get_and_clear_pending_msg_events().is_empty());

		nodes[1].node.handle_revoke_and_ack(&nodes[2].node.get_our_node_id(), &bs_second_raa).unwrap();
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
		nodes[0].node.handle_update_add_htlc(&nodes[1].node.get_our_node_id(), &send_event.msgs[0]).unwrap();
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
	let mut nodes = create_network(3);
	create_announced_chan_between_nodes(&nodes, 0, 1);
	create_announced_chan_between_nodes(&nodes, 1, 2);

	let (our_payment_preimage, _) = route_payment(&nodes[0], &[&nodes[1], &nodes[2]], 1000000);

	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);
	nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id(), false);

	assert!(nodes[2].node.claim_funds(our_payment_preimage));
	check_added_monitors!(nodes[2], 1);
	let mut updates = get_htlc_update_msgs!(nodes[2], nodes[1].node.get_our_node_id());
	assert!(updates.update_add_htlcs.is_empty());
	assert!(updates.update_fail_htlcs.is_empty());
	assert!(updates.update_fail_malformed_htlcs.is_empty());
	assert!(updates.update_fee.is_none());
	assert_eq!(updates.update_fulfill_htlcs.len(), 1);
	nodes[1].node.handle_update_fulfill_htlc(&nodes[2].node.get_our_node_id(), &updates.update_fulfill_htlcs[0]).unwrap();
	check_added_monitors!(nodes[1], 1);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	commitment_signed_dance!(nodes[1], nodes[2], updates.commitment_signed, false);

	*nodes[1].chan_monitor.update_ret.lock().unwrap() = Err(ChannelMonitorUpdateErr::TemporaryFailure);
	nodes[0].node.peer_connected(&nodes[1].node.get_our_node_id());
	nodes[1].node.peer_connected(&nodes[0].node.get_our_node_id());

	let as_reestablish = get_event_msg!(nodes[0], MessageSendEvent::SendChannelReestablish, nodes[1].node.get_our_node_id());
	let bs_reestablish = get_event_msg!(nodes[1], MessageSendEvent::SendChannelReestablish, nodes[0].node.get_our_node_id());

	nodes[0].node.handle_channel_reestablish(&nodes[1].node.get_our_node_id(), &bs_reestablish).unwrap();

	if let msgs::HandleError { err, action: Some(msgs::ErrorAction::IgnoreError) } = nodes[1].node.handle_channel_reestablish(&nodes[0].node.get_our_node_id(), &as_reestablish).unwrap_err() {
		assert_eq!(err, "Failed to update ChannelMonitor");
	} else { panic!(); }
	check_added_monitors!(nodes[1], 1);

	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);
	nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id(), false);

	nodes[0].node.peer_connected(&nodes[1].node.get_our_node_id());
	nodes[1].node.peer_connected(&nodes[0].node.get_our_node_id());

	assert!(as_reestablish == get_event_msg!(nodes[0], MessageSendEvent::SendChannelReestablish, nodes[1].node.get_our_node_id()));
	assert!(bs_reestablish == get_event_msg!(nodes[1], MessageSendEvent::SendChannelReestablish, nodes[0].node.get_our_node_id()));

	nodes[0].node.handle_channel_reestablish(&nodes[1].node.get_our_node_id(), &bs_reestablish).unwrap();

	nodes[1].node.handle_channel_reestablish(&nodes[0].node.get_our_node_id(), &as_reestablish).unwrap();
	check_added_monitors!(nodes[1], 0);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	*nodes[1].chan_monitor.update_ret.lock().unwrap() = Ok(());
	nodes[1].node.test_restore_channel_monitor();
	check_added_monitors!(nodes[1], 1);

	updates = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	assert!(updates.update_add_htlcs.is_empty());
	assert!(updates.update_fail_htlcs.is_empty());
	assert!(updates.update_fail_malformed_htlcs.is_empty());
	assert!(updates.update_fee.is_none());
	assert_eq!(updates.update_fulfill_htlcs.len(), 1);
	nodes[0].node.handle_update_fulfill_htlc(&nodes[1].node.get_our_node_id(), &updates.update_fulfill_htlcs[0]).unwrap();
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
	let mut nodes = create_network(2);
	create_announced_chan_between_nodes(&nodes, 0, 1);

	let route = nodes[0].router.get_route(&nodes[1].node.get_our_node_id(), None, &Vec::new(), 1000000, TEST_FINAL_CLTV).unwrap();
	let (payment_preimage_1, payment_hash_1) = get_payment_preimage_hash!(nodes[0]);
	let (payment_preimage_2, payment_hash_2) = get_payment_preimage_hash!(nodes[0]);
	let (payment_preimage_3, payment_hash_3) = get_payment_preimage_hash!(nodes[0]);

	// Queue up two payments - one will be delivered right away, one immediately goes into the
	// holding cell as nodes[0] is AwaitingRAA. Ultimately this allows us to deliver an RAA
	// immediately after a CS. By setting failing the monitor update failure from the CS (which
	// requires only an RAA response due to AwaitingRAA) we can deliver the RAA and require the CS
	// generation during RAA while in monitor-update-failed state.
	nodes[0].node.send_payment(route.clone(), payment_hash_1).unwrap();
	check_added_monitors!(nodes[0], 1);
	nodes[0].node.send_payment(route.clone(), payment_hash_2).unwrap();
	check_added_monitors!(nodes[0], 0);

	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let payment_event = SendEvent::from_event(events.pop().unwrap());
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &payment_event.msgs[0]).unwrap();
	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &payment_event.commitment_msg).unwrap();
	check_added_monitors!(nodes[1], 1);

	let bs_responses = get_revoke_commit_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_responses.0).unwrap();
	check_added_monitors!(nodes[0], 1);
	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let payment_event = SendEvent::from_event(events.pop().unwrap());

	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &bs_responses.1).unwrap();
	check_added_monitors!(nodes[0], 1);
	let as_raa = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());

	// Now we have a CS queued up which adds a new HTLC (which will need a RAA/CS response from
	// nodes[1]) followed by an RAA. Fail the monitor updating prior to the CS, deliver the RAA,
	// then restore channel monitor updates.
	*nodes[1].chan_monitor.update_ret.lock().unwrap() = Err(ChannelMonitorUpdateErr::TemporaryFailure);
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &payment_event.msgs[0]).unwrap();
	if let msgs::HandleError { err, action: Some(msgs::ErrorAction::IgnoreError) } = nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &payment_event.commitment_msg).unwrap_err() {
		assert_eq!(err, "Failed to update ChannelMonitor");
	} else { panic!(); }
	check_added_monitors!(nodes[1], 1);

	if let msgs::HandleError { err, action: Some(msgs::ErrorAction::IgnoreError) } = nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &as_raa).unwrap_err() {
		assert_eq!(err, "Previous monitor update failure prevented responses to RAA");
	} else { panic!(); }
	check_added_monitors!(nodes[1], 1);

	*nodes[1].chan_monitor.update_ret.lock().unwrap() = Ok(());
	nodes[1].node.test_restore_channel_monitor();
	// nodes[1] should be AwaitingRAA here!
	check_added_monitors!(nodes[1], 1);
	let bs_responses = get_revoke_commit_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	expect_pending_htlcs_forwardable!(nodes[1]);
	expect_payment_received!(nodes[1], payment_hash_1, 1000000);

	// We send a third payment here, which is somewhat of a redundant test, but the
	// chanmon_fail_consistency test required it to actually find the bug (by seeing out-of-sync
	// commitment transaction states) whereas here we can explicitly check for it.
	nodes[0].node.send_payment(route.clone(), payment_hash_3).unwrap();
	check_added_monitors!(nodes[0], 0);
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());

	nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_responses.0).unwrap();
	check_added_monitors!(nodes[0], 1);
	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let payment_event = SendEvent::from_event(events.pop().unwrap());

	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &bs_responses.1).unwrap();
	check_added_monitors!(nodes[0], 1);
	let as_raa = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());

	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &payment_event.msgs[0]).unwrap();
	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &payment_event.commitment_msg).unwrap();
	check_added_monitors!(nodes[1], 1);
	let bs_raa = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, nodes[0].node.get_our_node_id());

	// Finally deliver the RAA to nodes[1] which results in a CS response to the last update
	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &as_raa).unwrap();
	check_added_monitors!(nodes[1], 1);
	expect_pending_htlcs_forwardable!(nodes[1]);
	expect_payment_received!(nodes[1], payment_hash_2, 1000000);
	let bs_update = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());

	nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_raa).unwrap();
	check_added_monitors!(nodes[0], 1);

	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &bs_update.commitment_signed).unwrap();
	check_added_monitors!(nodes[0], 1);
	let as_raa = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());

	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &as_raa).unwrap();
	check_added_monitors!(nodes[1], 1);
	expect_pending_htlcs_forwardable!(nodes[1]);
	expect_payment_received!(nodes[1], payment_hash_3, 1000000);

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
	let mut nodes = create_network(2);
	create_announced_chan_between_nodes(&nodes, 0, 1);

	// Forward a payment for B to claim
	let (payment_preimage_1, _) = route_payment(&nodes[0], &[&nodes[1]], 1000000);

	nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id(), false);
	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);

	assert!(nodes[1].node.claim_funds(payment_preimage_1));
	check_added_monitors!(nodes[1], 1);

	nodes[0].node.peer_connected(&nodes[1].node.get_our_node_id());
	nodes[1].node.peer_connected(&nodes[0].node.get_our_node_id());

	let as_reconnect = get_event_msg!(nodes[0], MessageSendEvent::SendChannelReestablish, nodes[1].node.get_our_node_id());
	let bs_reconnect = get_event_msg!(nodes[1], MessageSendEvent::SendChannelReestablish, nodes[0].node.get_our_node_id());

	nodes[0].node.handle_channel_reestablish(&nodes[1].node.get_our_node_id(), &bs_reconnect).unwrap();
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());

	// Now deliver a's reestablish, freeing the claim from the holding cell, but fail the monitor
	// update.
	*nodes[1].chan_monitor.update_ret.lock().unwrap() = Err(ChannelMonitorUpdateErr::TemporaryFailure);

	if let msgs::HandleError { err, action: Some(msgs::ErrorAction::IgnoreError) } = nodes[1].node.handle_channel_reestablish(&nodes[0].node.get_our_node_id(), &as_reconnect).unwrap_err() {
		assert_eq!(err, "Failed to update ChannelMonitor");
	} else { panic!(); }
	check_added_monitors!(nodes[1], 1);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	// Send a second payment from A to B, resulting in a commitment update that gets swallowed with
	// the monitor still failed
	let route = nodes[0].router.get_route(&nodes[1].node.get_our_node_id(), None, &Vec::new(), 1000000, TEST_FINAL_CLTV).unwrap();
	let (payment_preimage_2, payment_hash_2) = get_payment_preimage_hash!(nodes[0]);
	nodes[0].node.send_payment(route, payment_hash_2).unwrap();
	check_added_monitors!(nodes[0], 1);

	let as_updates = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &as_updates.update_add_htlcs[0]).unwrap();
	if let msgs::HandleError { err, action: Some(msgs::ErrorAction::IgnoreError) } = nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &as_updates.commitment_signed).unwrap_err() {
		assert_eq!(err, "Previous monitor update failure prevented generation of RAA");
	} else { panic!(); }
	// Note that nodes[1] not updating monitor here is OK - it wont take action on the new HTLC
	// until we've test_restore_channel_monitor'd and updated for the new commitment transaction.

	// Now un-fail the monitor, which will result in B sending its original commitment update,
	// receiving the commitment update from A, and the resulting commitment dances.
	*nodes[1].chan_monitor.update_ret.lock().unwrap() = Ok(());
	nodes[1].node.test_restore_channel_monitor();
	check_added_monitors!(nodes[1], 1);

	let bs_msgs = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(bs_msgs.len(), 2);

	match bs_msgs[0] {
		MessageSendEvent::UpdateHTLCs { ref node_id, ref updates } => {
			assert_eq!(*node_id, nodes[0].node.get_our_node_id());
			nodes[0].node.handle_update_fulfill_htlc(&nodes[1].node.get_our_node_id(), &updates.update_fulfill_htlcs[0]).unwrap();
			nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &updates.commitment_signed).unwrap();
			check_added_monitors!(nodes[0], 1);

			let as_raa = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());
			nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &as_raa).unwrap();
			check_added_monitors!(nodes[1], 1);
		},
		_ => panic!("Unexpected event"),
	}

	match bs_msgs[1] {
		MessageSendEvent::SendRevokeAndACK { ref node_id, ref msg } => {
			assert_eq!(*node_id, nodes[0].node.get_our_node_id());
			nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), msg).unwrap();
			check_added_monitors!(nodes[0], 1);
		},
		_ => panic!("Unexpected event"),
	}

	let as_commitment = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());

	let bs_commitment = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &bs_commitment.commitment_signed).unwrap();
	check_added_monitors!(nodes[0], 1);
	let as_raa = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());

	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &as_commitment.commitment_signed).unwrap();
	check_added_monitors!(nodes[1], 1);
	let bs_raa = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, nodes[0].node.get_our_node_id());
	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &as_raa).unwrap();
	check_added_monitors!(nodes[1], 1);

	expect_pending_htlcs_forwardable!(nodes[1]);
	expect_payment_received!(nodes[1], payment_hash_2, 1000000);

	nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_raa).unwrap();
	check_added_monitors!(nodes[0], 1);

	let events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		Event::PaymentSent { ref payment_preimage } => {
			assert_eq!(*payment_preimage, payment_preimage_1);
		},
		_ => panic!("Unexpected event"),
	}

	claim_payment(&nodes[0], &[&nodes[1]], payment_preimage_2);
}

#[test]
fn monitor_failed_no_reestablish_response() {
	// Test for receiving a channel_reestablish after a monitor update failure resulted in no
	// response to a commitment_signed.
	// Backported from chanmon_fail_consistency fuzz tests as it caught a long-standing
	// debug_assert!() failure in channel_reestablish handling.
	let mut nodes = create_network(2);
	create_announced_chan_between_nodes(&nodes, 0, 1);

	// Route the payment and deliver the initial commitment_signed (with a monitor update failure
	// on receipt).
	let route = nodes[0].router.get_route(&nodes[1].node.get_our_node_id(), None, &Vec::new(), 1000000, TEST_FINAL_CLTV).unwrap();
	let (payment_preimage_1, payment_hash_1) = get_payment_preimage_hash!(nodes[0]);
	nodes[0].node.send_payment(route, payment_hash_1).unwrap();
	check_added_monitors!(nodes[0], 1);

	*nodes[1].chan_monitor.update_ret.lock().unwrap() = Err(ChannelMonitorUpdateErr::TemporaryFailure);
	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let payment_event = SendEvent::from_event(events.pop().unwrap());
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &payment_event.msgs[0]).unwrap();
	if let msgs::HandleError { err, action: Some(msgs::ErrorAction::IgnoreError) } = nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &payment_event.commitment_msg).unwrap_err() {
		assert_eq!(err, "Failed to update ChannelMonitor");
	} else { panic!(); }
	check_added_monitors!(nodes[1], 1);

	// Now disconnect and immediately reconnect, delivering the channel_reestablish while nodes[1]
	// is still failing to update monitors.
	nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id(), false);
	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);

	nodes[0].node.peer_connected(&nodes[1].node.get_our_node_id());
	nodes[1].node.peer_connected(&nodes[0].node.get_our_node_id());

	let as_reconnect = get_event_msg!(nodes[0], MessageSendEvent::SendChannelReestablish, nodes[1].node.get_our_node_id());
	let bs_reconnect = get_event_msg!(nodes[1], MessageSendEvent::SendChannelReestablish, nodes[0].node.get_our_node_id());

	nodes[1].node.handle_channel_reestablish(&nodes[0].node.get_our_node_id(), &as_reconnect).unwrap();
	nodes[0].node.handle_channel_reestablish(&nodes[1].node.get_our_node_id(), &bs_reconnect).unwrap();

	*nodes[1].chan_monitor.update_ret.lock().unwrap() = Ok(());
	nodes[1].node.test_restore_channel_monitor();
	check_added_monitors!(nodes[1], 1);
	let bs_responses = get_revoke_commit_msgs!(nodes[1], nodes[0].node.get_our_node_id());

	nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_responses.0).unwrap();
	check_added_monitors!(nodes[0], 1);
	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &bs_responses.1).unwrap();
	check_added_monitors!(nodes[0], 1);

	let as_raa = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());
	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &as_raa).unwrap();
	check_added_monitors!(nodes[1], 1);

	expect_pending_htlcs_forwardable!(nodes[1]);
	expect_payment_received!(nodes[1], payment_hash_1, 1000000);

	claim_payment(&nodes[0], &[&nodes[1]], payment_preimage_1);
}
