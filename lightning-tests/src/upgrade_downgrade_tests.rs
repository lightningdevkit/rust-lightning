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

use lightning_0_1::get_monitor as get_monitor_0_1;
use lightning_0_1::ln::functional_test_utils as lightning_0_1_utils;
use lightning_0_1::util::ser::Writeable as _;

use lightning_0_0_125::chain::ChannelMonitorUpdateStatus as ChannelMonitorUpdateStatus_0_0_125;
use lightning_0_0_125::check_added_monitors as check_added_monitors_0_0_125;
use lightning_0_0_125::events::ClosureReason as ClosureReason_0_0_125;
use lightning_0_0_125::expect_payment_claimed as expect_payment_claimed_0_0_125;
use lightning_0_0_125::get_htlc_update_msgs as get_htlc_update_msgs_0_0_125;
use lightning_0_0_125::get_monitor as get_monitor_0_0_125;
use lightning_0_0_125::get_revoke_commit_msgs as get_revoke_commit_msgs_0_0_125;
use lightning_0_0_125::ln::channelmanager::PaymentId as PaymentId_0_0_125;
use lightning_0_0_125::ln::channelmanager::RecipientOnionFields as RecipientOnionFields_0_0_125;
use lightning_0_0_125::ln::functional_test_utils as lightning_0_0_125_utils;
use lightning_0_0_125::ln::msgs::ChannelMessageHandler as _;
use lightning_0_0_125::routing::router as router_0_0_125;
use lightning_0_0_125::util::ser::Writeable as _;

use lightning::ln::functional_test_utils::*;

use lightning_types::payment::PaymentPreimage;

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
fn test_125_dangling_post_update_actions() {
	// Tests a failure of upgrading from 0.0.125 to 0.1 when there's a dangling
	// `MonitorUpdateCompletionAction` due to the bug fixed in
	// 93b4479e472e6767af5df90fecdcdfb79074e260.
	let (node_d_ser, mon_ser);
	{
		// First, we get RAA-source monitor updates held by using async persistence (note that this
		// issue was first identified as a consequence of the bug fixed in
		// 93b4479e472e6767af5df90fecdcdfb79074e260 but in order to replicate that bug we need a
		// complicated multi-threaded race that is not deterministic, thus we "cheat" here by using
		// async persistence). We do this by simply claiming an MPP payment and not completing the
		// second channel's `ChannelMonitorUpdate`, blocking RAA `ChannelMonitorUpdate`s from the
		// first (which is ultimately a very similar bug to the one fixed in 93b4479e472e6767af5df).
		//
		// Then, we claim a second payment on the channel, which ultimately doesn't have its
		// `ChannelMonitorUpdate` completion handled due to the presence of the blocked
		// `ChannelMonitorUpdate`. The claim also generates a post-update completion action, but
		// the `ChannelMonitorUpdate` isn't queued due to the RAA-update block.
		let chanmon_cfgs = lightning_0_0_125_utils::create_chanmon_cfgs(4);
		let node_cfgs = lightning_0_0_125_utils::create_node_cfgs(4, &chanmon_cfgs);
		let node_chanmgrs =
			lightning_0_0_125_utils::create_node_chanmgrs(4, &node_cfgs, &[None, None, None, None]);
		let nodes = lightning_0_0_125_utils::create_network(4, &node_cfgs, &node_chanmgrs);

		let node_b_id = nodes[1].node.get_our_node_id();
		let node_d_id = nodes[3].node.get_our_node_id();

		lightning_0_0_125_utils::create_announced_chan_between_nodes_with_value(
			&nodes, 0, 1, 100_000, 0,
		);
		lightning_0_0_125_utils::create_announced_chan_between_nodes_with_value(
			&nodes, 0, 2, 100_000, 0,
		);
		let chan_id_1_3 = lightning_0_0_125_utils::create_announced_chan_between_nodes_with_value(
			&nodes, 1, 3, 100_000, 0,
		)
		.2;
		let chan_id_2_3 = lightning_0_0_125_utils::create_announced_chan_between_nodes_with_value(
			&nodes, 2, 3, 100_000, 0,
		)
		.2;

		let (preimage, hash, secret) =
			lightning_0_0_125_utils::get_payment_preimage_hash(&nodes[3], Some(15_000_000), None);

		let pay_params = router_0_0_125::PaymentParameters::from_node_id(
			node_d_id,
			lightning_0_0_125_utils::TEST_FINAL_CLTV,
		)
		.with_bolt11_features(nodes[3].node.bolt11_invoice_features())
		.unwrap();

		let route_params =
			router_0_0_125::RouteParameters::from_payment_params_and_value(pay_params, 15_000_000);
		let route = lightning_0_0_125_utils::get_route(&nodes[0], &route_params).unwrap();

		let onion = RecipientOnionFields_0_0_125::secret_only(secret);
		let id = PaymentId_0_0_125(hash.0);
		nodes[0].node.send_payment_with_route(route, hash, onion, id).unwrap();

		check_added_monitors_0_0_125!(nodes[0], 2);
		let paths = &[&[&nodes[1], &nodes[3]][..], &[&nodes[2], &nodes[3]]];
		lightning_0_0_125_utils::pass_along_route(&nodes[0], paths, 15_000_000, hash, secret);

		let preimage_2 = lightning_0_0_125_utils::route_payment(&nodes[1], &[&nodes[3]], 100_000).0;

		chanmon_cfgs[3].persister.set_update_ret(ChannelMonitorUpdateStatus_0_0_125::InProgress);
		chanmon_cfgs[3].persister.set_update_ret(ChannelMonitorUpdateStatus_0_0_125::InProgress);
		nodes[3].node.claim_funds(preimage);
		check_added_monitors_0_0_125!(nodes[3], 2);

		let (outpoint, update_id, _) = {
			let latest_monitors = nodes[3].chain_monitor.latest_monitor_update_id.lock().unwrap();
			latest_monitors.get(&chan_id_1_3).unwrap().clone()
		};
		nodes[3].chain_monitor.chain_monitor.channel_monitor_updated(outpoint, update_id).unwrap();
		expect_payment_claimed_0_0_125!(nodes[3], hash, 15_000_000);

		let ds_fulfill = get_htlc_update_msgs_0_0_125!(nodes[3], node_b_id);
		// Due to an unrelated test bug in 0.0.125, we have to leave the `ChannelMonitorUpdate` for
		// the previous node un-completed or we will panic when dropping the `Node`.
		chanmon_cfgs[1].persister.set_update_ret(ChannelMonitorUpdateStatus_0_0_125::InProgress);
		nodes[1].node.handle_update_fulfill_htlc(&node_d_id, &ds_fulfill.update_fulfill_htlcs[0]);
		check_added_monitors_0_0_125!(nodes[1], 1);

		nodes[1].node.handle_commitment_signed(&node_d_id, &ds_fulfill.commitment_signed);
		check_added_monitors_0_0_125!(nodes[1], 1);

		// The `ChannelMonitorUpdate` generated by the RAA from node B to node D will be blocked.
		let (bs_raa, _) = get_revoke_commit_msgs_0_0_125!(nodes[1], node_d_id);
		nodes[3].node.handle_revoke_and_ack(&node_b_id, &bs_raa);
		check_added_monitors_0_0_125!(nodes[3], 0);

		// Now that there is a blocked update in the B <-> D channel, we can claim the second
		// payment across it, which, while it will generate a `ChannelMonitorUpdate`, will not
		// complete its post-update actions.
		nodes[3].node.claim_funds(preimage_2);
		check_added_monitors_0_0_125!(nodes[3], 1);

		// Finally, we set up the failure by force-closing the channel in question, ensuring that
		// 0.1 will not create a per-peer state for node B.
		let err = "Force Closing Channel".to_owned();
		nodes[3].node.force_close_without_broadcasting_txn(&chan_id_1_3, &node_b_id, err).unwrap();
		let reason =
			ClosureReason_0_0_125::HolderForceClosed { broadcasted_latest_txn: Some(false) };
		let peers = &[node_b_id];
		lightning_0_0_125_utils::check_closed_event(&nodes[3], 1, reason, false, peers, 100_000);
		lightning_0_0_125_utils::check_closed_broadcast(&nodes[3], 1, true);
		check_added_monitors_0_0_125!(nodes[3], 1);

		node_d_ser = nodes[3].node.encode();
		mon_ser = get_monitor_0_0_125!(nodes[3], chan_id_2_3).encode();
	}

	// Create a dummy node to reload over with the 0.0.125 state

	let mut chanmon_cfgs = create_chanmon_cfgs(4);

	// Our TestChannelSigner will fail as we're jumping ahead, so disable its state-based checks
	chanmon_cfgs[0].keys_manager.disable_all_state_policy_checks = true;
	chanmon_cfgs[1].keys_manager.disable_all_state_policy_checks = true;
	chanmon_cfgs[2].keys_manager.disable_all_state_policy_checks = true;
	chanmon_cfgs[3].keys_manager.disable_all_state_policy_checks = true;

	let node_cfgs = create_node_cfgs(4, &chanmon_cfgs);
	let (persister, chain_mon);
	let node_chanmgrs = create_node_chanmgrs(4, &node_cfgs, &[None, None, None, None]);
	let node;
	let mut nodes = create_network(4, &node_cfgs, &node_chanmgrs);

	// Finally, reload the node in the latest LDK. This previously failed.
	let config = test_default_channel_config();
	reload_node!(nodes[3], config, &node_d_ser, &[&mon_ser], persister, chain_mon, node);
}
